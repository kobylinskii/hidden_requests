#!/usr/bin/env python3
"""Forced activation of hidden HTTP requests via Frida."""

import json, sys, os, argparse, re, urllib.request
from pathlib import Path

try:
    from slice import load_apk
except ImportError:
    load_apk = None

_STAGE_KINDS = {0: "call_retrofit", 1: "invoke", 2: "trigger_entry"}
_REQUIRED = ("key", "stage", "overrides", "fields", "args", "trigger", "rationale")

def validate_plan(plan, member_exists):
    """Проблемы плана; пусто = валиден. member_exists(cls,kind,name,sig)->bool."""
    probs = []
    if not isinstance(plan, dict):
        return ["план не объект JSON"]
    for k in _REQUIRED:
        if k not in plan:
            probs.append(f"нет обязательного поля {k}")
    if probs:
        return probs

    # Guard stage: must be int
    st = plan["stage"]
    if not isinstance(st, int):
        probs.append(f"stage не целое: {st!r}")
        st = None  # skip stage/trigger-kind checks
    elif st not in _STAGE_KINDS:
        probs.append(f"stage={st!r} не из {sorted(_STAGE_KINDS)}")

    # Guard trigger: must be dict, use .get() for keys
    trig = plan.get("trigger")
    if trig is not None and not isinstance(trig, dict):
        probs.append("trigger не объект")
        trig = None
    if trig is None:
        trig = {}
    if st is not None and st in _STAGE_KINDS and trig.get("kind") != _STAGE_KINDS[st]:
        probs.append(f"trigger.kind={trig.get('kind')!r} не соответствует stage={st}")

    # Guard overrides: must be list
    overrides = plan.get("overrides")
    if not isinstance(overrides, list):
        probs.append(f"overrides не список: {overrides!r}")
        overrides = []
    for ov in overrides:
        if not isinstance(ov, dict):
            probs.append(f"override не объект: {ov!r}")
            continue
        cls = ov.get("cls")
        method = ov.get("method")
        sig = ov.get("sig")
        if cls is None or method is None or sig is None:
            probs.append(f"override без ключей cls/method/sig: {ov!r}")
            continue
        if not all(isinstance(v, str) for v in (cls, method, sig)):
            probs.append(f"override: cls/method/sig не строки: {ov!r}")
            continue
        if not member_exists(cls, "method", method, sig):
            probs.append(f"override: нет метода {cls}->{method}{sig}")

    # Guard fields: must be list
    fields = plan.get("fields")
    if not isinstance(fields, list):
        probs.append(f"fields не список: {fields!r}")
        fields = []
    for fl in fields:
        if not isinstance(fl, dict):
            probs.append(f"field не объект: {fl!r}")
            continue
        cls = fl.get("cls")
        name = fl.get("name")
        sig = fl.get("sig")
        if cls is None or name is None or sig is None:
            probs.append(f"field без ключей cls/name/sig: {fl!r}")
            continue
        if not all(isinstance(v, str) for v in (cls, name, sig)):
            probs.append(f"field: cls/name/sig не строки: {fl!r}")
            continue
        if not member_exists(cls, "field", name, sig):
            probs.append(f"field: нет поля {cls}->{name} {sig}")

    # Guard args: must be list (no validation of contents required)
    args = plan.get("args")
    if not isinstance(args, list):
        probs.append(f"args не список: {args!r}")

    # Guard trigger method (for invoke/trigger_entry)
    if trig.get("kind") in ("invoke", "trigger_entry"):
        tcls = trig.get("cls")
        tmethod = trig.get("method")
        tsig = trig.get("sig")
        if tcls is None or tmethod is None or tsig is None:
            probs.append(f"trigger без ключей cls/method/sig: {trig!r}")
        elif not all(isinstance(v, str) for v in (tcls, tmethod, tsig)):
            probs.append(f"trigger: cls/method/sig не строки: {trig!r}")
        else:
            if not member_exists(tcls, "method", tmethod, tsig):
                probs.append(f"trigger: нет метода {tcls}->{tmethod}{tsig}")

    return probs

_NOISE_NOTES = {"coroutine_state_machine", "framework"}

def real_guards(rec):
    """Стражи среза без шумовых (coroutine state machine, framework-утиль
    типа Kotlin Intrinsics) — то, что реально нужно обойти/подделать."""
    return [g for g in rec.get("guards", [])
            if not (_NOISE_NOTES & set(g.get("notes", [])))]


def method_smali(dx, cls, method):
    """fqcn + имя метода -> smali-текст (строки 'mnemonic operand').
    Пусто, если класс/метод не найден или у метода нет кода (внешнее
    объявление/abstract — как и в slice.frame_of)."""
    ca = dx.classes.get("L" + cls.replace(".", "/") + ";")
    if ca is None:
        return ""
    out = []
    for ma in ca.get_methods():
        if ma.name != method:
            continue
        m = ma.get_method()
        code = m.get_code() if m is not None and hasattr(m, "get_code") else None
        if code is None:
            continue
        for ins in code.get_bc().get_instructions():
            out.append(f"{ins.get_name()} {ins.get_output()}")
        break
    return "\n".join(out)


_STAGE_DOC = {
    0: "Ступень 0 — call_retrofit: прямой вызов скрытого Retrofit-метода, стражи игнорируются, аргументы по провенанс-стратегии.",
    1: "Ступень 1 — invoke: вызвать ближайший call_site, заглушив реальные стражи на пути; приложение само строит реальные аргументы.",
    2: "Ступень 2 — trigger_entry: дёрнуть UI-фронтир, заглушив все реальные стражи пути.",
}
_SCHEMA_DOC = '''Выдай СТРОГО один JSON-объект, без markdown-забора, без текста вокруг:
{"key": str, "stage": 0|1|2,
 "overrides": [{"cls","method","sig","ret"}],   // заглушить return метода-стража
 "fields":    [{"cls","name","sig","value","instance"?}],
 "args":      [{"index", "value"}],
 "trigger":   {"kind": "call_retrofit"|"invoke"|"trigger_entry", "cls","method","sig","suspend"?},
 "raw_js":    null,
 "rationale": str}  // по-русски: почему эти значения ведут к вызову
value — примитив JSON либо: {"$new":"cls","args":[...]} | {"$choose":"cls"} (живой инстанс из кучи, предпочтительно ради реальных параметров) | {"$enum":"cls.FIELD"} | {"$null":"cls"}.
kind обязан соответствовать stage: 0->call_retrofit, 1->invoke, 2->trigger_entry.'''

def build_prompt(rec, stage, smali):
    """Срез (запись из out/<pkg>.slice.jsonl) + ступень + smali нужных
    кадров -> текст промпта для LLM. Шумовые стражи (coroutine/framework)
    отфильтрованы через real_guards — LLM видит только то, что реально
    нужно обойти."""
    rg = real_guards(rec)
    ctx = {"key": rec["key"], "cls": rec["cls"], "method": rec["method"],
           "stage": stage,
           "call_sites": rec.get("call_sites", []),
           "real_guards": rg, "args": rec.get("args", []),
           "frontier": rec.get("frontier"), "activation_cost": rec.get("activation_cost")}
    smali_txt = "\n\n".join(f"### smali {k}\n{v}" for k, v in smali.items() if v)
    return (
        "Ты генерируешь план принудительной активации скрытого HTTP-запроса Android-приложения "
        "на стенде исследователя. Главная цель — чтобы запрос ушёл С РЕАЛЬНЫМИ ПАРАМЕТРАМИ "
        "(значения, которые приложение подставило бы само), поэтому предпочитай $choose и прогон "
        "через логику приложения, а не синтетические болванки.\n\n"
        f"{_STAGE_DOC[stage]}\n\n"
        f"Срез скрытого вызова (JSON):\n{json.dumps(ctx, ensure_ascii=False, indent=2)}\n\n"
        f"Декомпиляция (smali) нужных кадров:\n{smali_txt}\n\n"
        f"Контракт вывода:\n{_SCHEMA_DOC}\n\n"
        f'Сейчас сгенерируй план для stage={stage}. Поле "stage" в ответе должно быть {stage}.'
    )


def parse_plan(text):
    """Срезает markdown-забор, парсит JSON из текста. ValueError на мусоре."""
    t = text.strip()
    m = re.search(r"```(?:json)?\s*(.*?)```", t, re.S)
    if m:
        t = m.group(1).strip()
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        a, b = t.find("{"), t.rfind("}")
        if 0 <= a < b:
            try:
                return json.loads(t[a:b + 1])
            except json.JSONDecodeError:
                pass
    raise ValueError(f"LLM вернул неразбираемый план: {text[:200]!r}")


def _urllib_transport(url, headers, body):
    """HTTP POST через stdlib urllib."""
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read().decode("utf-8")


def generate_plan(prompt, backend="openai", *, transport=None, manual_path=None):
    """Генерирует план через LLM (openai) или читает вручную (manual)."""
    if backend == "manual":
        src = Path(manual_path) if manual_path else None
        if not src or not src.exists():
            raise SystemExit(f"manual-бэкенд: нет файла с планом {manual_path!r}.\n"
                             f"Вставьте ответ LLM в этот файл и повторите.")
        return parse_plan(src.read_text(encoding="utf-8"))
    url = os.environ.get("LLM_BASE_URL", "https://openrouter.ai/api/v1/chat/completions")
    model = os.environ.get("LLM_MODEL", "deepseek/deepseek-chat-v3-0324:free")
    key = os.environ.get("LLM_API_KEY")
    if not key:
        raise SystemExit("нет LLM_API_KEY в окружении (или используйте --backend manual)")
    body = json.dumps({"model": model, "temperature": 0,
                       "messages": [{"role": "user", "content": prompt}]}).encode("utf-8")
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    try:
        raw = (transport or _urllib_transport)(url, headers, body)
    except Exception as e:
        raise RuntimeError(f"LLM transport failed ({model} @ {url}): {e}") from e
    try:
        content = json.loads(raw)["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as e:
        raise RuntimeError(f"LLM response unparsable: {e}; raw={raw[:200]!r}") from e
    return parse_plan(content)


def dex_member_exists(dx):
    """member_exists поверх androguard dx. Сверяет имя И сигнатуру (R8-перегрузки)."""
    def me(cls, kind, name, sig):
        ca = dx.classes.get("L" + cls.replace(".", "/") + ";")
        if ca is None:
            return False
        if kind == "method":
            for ma in ca.get_methods():
                m = ma.get_method()
                if m is None:
                    continue
                # Use canonical getters for androguard compatibility
                if m.get_name() == name and m.get_descriptor() == sig:
                    return True
            return False
        if kind == "field":
            for f in ca.get_fields():
                ef = f.get_field()
                if ef is None:
                    continue
                # Use canonical getters for androguard compatibility
                if ef.get_name() == name and ef.get_descriptor() == sig:
                    return True
            return False
        return False
    return me


def _retrofit_hit(payload, key):
    """True if a hook.js NDJSON event is a Retrofit proxy call of the target key."""
    return payload.get("t") == "retrofit" and f"{payload.get('cls')}->{payload.get('m')}" == key


def run_key(rec, stages, run_stage):
    """Ступенчатая петля по одному скрытому вызову: пробует stages по порядку,
    останавливается на первой ступени с real_params==True (уровень б).
    Исключение run_stage не роняет петлю — фиксируется и пробуется следующая ступень."""
    out = {"key": rec["key"], "reached": False, "activated_real": False,
           "min_stage": None, "stages": []}
    for stage in stages:
        try:
            r = run_stage(rec, stage)
        except Exception as e:
            r = {"stage": stage, "valid": False, "exceptions": [str(e)],
                 "fired": False, "real_params": False, "request": None}
        out["stages"].append(r)
        if r.get("fired"):
            out["reached"] = True
        if r.get("real_params"):
            out["activated_real"] = True
            out["min_stage"] = stage
            break
    return out


HERE = Path(__file__).resolve().parent


def activate_on_device(dx, pkg, backend, wait_t, manual_path=None):
    """Возвращает run_stage(rec, stage), замкнутый на пакет и одну Frida-сессию.
    import frida/trace здесь, а не на верху модуля — offline-пути (--selfcheck
    без --apk, --dry-run) должны работать без установленного frida."""
    import frida, time, trace
    me = dex_member_exists(dx)
    device = trace.pick_device(None)

    def run_stage(rec, stage):
        prompt = build_prompt(rec, stage, {rec["cls"] + "->" + rec["method"]:
                                           method_smali(dx, rec["cls"], rec["method"])})
        plan = generate_plan(prompt, backend=backend, manual_path=manual_path)
        probs = validate_plan(plan, me)
        if probs:
            return {"stage": stage, "valid": False, "exceptions": probs,
                    "fired": False, "real_params": False, "request": None, "plan": plan}
        pid = device.spawn([pkg])
        session = None
        seen = {"hit": False}

        def _on_hook_msg(message, data):
            if message.get("type") == "send":
                if _retrofit_hit(message.get("payload") or {}, rec["key"]):
                    seen["hit"] = True

        # Приложения с анти-frida само-завершаются через секунды после старта:
        # сессия/скрипт умирают в окне ожидания, и тогда ЛЮБОЙ exports-вызов
        # кидает "script has been destroyed". Поэтому каждый device-вызов — под
        # своим guard'ом, а fired берём из асинхронного seen["hit"] (его ставит
        # хендлер hook.js, когда наш форс-вызов дёргает Proxy.invoke) — он валиден,
        # даже если приложение умерло до snapshot. _SETTLE даёт Retrofit построить
        # прокси до arm (иначе call_retrofit не найдёт инстанс). Пилот-правка, §15.
        res, snap, exc = {}, None, []
        _SETTLE = 1.0
        try:
            session = device.attach(pid)
            # prelude.js ПЕРВЫМ: глушит само-завершение приложения при детекте frida
            # (TNT зовёт System.exit/killProcess и умирает за ~0.5с без него).
            prelude = session.create_script((HERE / "prelude.js").read_text(encoding="utf-8"))
            prelude.load()
            hook_script = session.create_script((HERE / "hook.js").read_text(encoding="utf-8"))
            hook_script.on("message", _on_hook_msg)
            hook_script.load()
            agent = session.create_script((HERE / "activate.js").read_text(encoding="utf-8"))
            agent.load()
            device.resume(pid)
            time.sleep(_SETTLE)
            try: agent.exports_sync.capture_on(rec["key"])
            except Exception as e: exc.append("capture_on: " + str(e))
            try: res = agent.exports_sync.arm(json.dumps(plan))
            except Exception as e: exc.append("arm: " + str(e))
            time.sleep(wait_t)
            try: snap = agent.exports_sync.snapshot()
            except Exception as e: exc.append("snapshot: " + str(e))
        except Exception as e:
            exc.append("session: " + str(e))
        finally:
            if session is not None:
                try: session.detach()
                except Exception: pass
            try: device.kill(pid)
            except Exception: pass
        # fired — ключ-точный оракул из hook.js (Proxy.invoke по cls->method).
        # snap — advisory-артефакт; строгая привязка к key — доработка пилотной фазы.
        fired = seen["hit"]
        real = fired and _params_real(plan, snap)
        exc = (res.get("exceptions", []) if isinstance(res, dict) else []) + exc
        return {"stage": stage, "valid": True, "exceptions": exc,
                "fired": fired, "real_params": real, "request": snap, "plan": plan}

    return run_stage


def _params_real(plan, snap):
    """Уровень (б): хоть один аргумент не синтетический ($choose/прогон) И запрос непуст.
    Порог (spec §15, открытый вопрос): нет args через $new/примитив-болванку."""
    if not snap or not snap.get("url"):
        return False
    synth = any(isinstance(a.get("value"), (int, float, str, bool)) or
                (isinstance(a.get("value"), dict) and "$new" in a["value"])
                for a in plan.get("args", []))
    return not synth or bool(plan.get("trigger", {}).get("kind") in ("invoke", "trigger_entry"))


def report(results):
    """HTTP-аналог Таблицы IV ICSE 2025: распределение ключей по минимальной
    ступени уровня (б) {0,1,2,none} + уровень (а) отдельно + оговорка о
    несопоставимости с RQ3 (активити vs сетевые вызовы, другой стенд)."""
    n = len(results)
    reached = sum(r["reached"] for r in results)
    real = sum(r["activated_real"] for r in results)
    from collections import Counter
    dist = Counter(r["min_stage"] for r in results if r["activated_real"])
    none = n - real
    L = [f"Всего ключей: {n}",
         f"(а) достижим (запрос ушёл, параметры любые): {reached}/{n}",
         f"(б) активирован с реальными параметрами:     {real}/{n}",
         "",
         "HTTP-аналог Таблицы IV — минимальная ступень уровня (б):",
         f"  ступень 0 (прямой вызов):          {dist.get(0,0)}",
         f"  ступень 1 (вызывающий + стражи):   {dist.get(1,0)}",
         f"  ступень 2 (UI-фронтир):            {dist.get(2,0)}",
         f"  не активирован (нужна продвинутая техника/сервер): {none}",
         "",
         "Оговорка: сравнение с RQ3/Таблицей IV ICSE 2025 — качественное; "
         "метрики несопоставимы напрямую (активити vs сетевые вызовы, другой стенд).",]
    return "\n".join(L)


def _check_validate_plan():
    # фейковый DEX: класс A с методом m(()Z) и полем c (I)
    present = {("A", "method", "m", "()Z"), ("A", "field", "c", "I")}
    me = lambda cls, kind, name, sig: (cls, kind, name, sig) in present

    good = {"key": "A->m", "stage": 1,
            "overrides": [{"cls": "A", "method": "m", "sig": "()Z", "ret": False}],
            "fields": [{"cls": "A", "name": "c", "sig": "I", "value": 1}],
            "args": [], "trigger": {"kind": "invoke", "cls": "A", "method": "m", "sig": "()Z"},
            "raw_js": None, "rationale": "x"}
    assert validate_plan(good, me) == [], validate_plan(good, me)

    # отсутствует обязательное поле stage
    bad = dict(good); bad.pop("stage")
    assert any("stage" in p for p in validate_plan(bad, me))

    # перегрузка: тот же метод, другая сигнатура -> не существует
    ov = {**good, "overrides": [{"cls": "A", "method": "m", "sig": "(I)Z", "ret": False}]}
    probs = validate_plan(ov, me)
    assert any("(I)Z" in p for p in probs), probs

    # несуществующий класс в trigger
    nc = {**good, "trigger": {"kind": "invoke", "cls": "Z", "method": "m", "sig": "()Z"}}
    assert any("Z->m" in p for p in validate_plan(nc, me))

    # Malformed shapes: trust boundary robustness
    # stage is unhashable (list)
    bad_stage_list = {**good, "stage": [1]}
    probs = validate_plan(bad_stage_list, me)
    assert len(probs) > 0 and not any(isinstance(p, Exception) for p in probs), probs
    assert any("stage" in p for p in probs), probs

    # stage is not int (dict)
    bad_stage_dict = {**good, "stage": {"val": 1}}
    probs = validate_plan(bad_stage_dict, me)
    assert len(probs) > 0, probs
    assert any("stage" in p for p in probs), probs

    # overrides is None
    bad_ov_none = {**good, "overrides": None}
    probs = validate_plan(bad_ov_none, me)
    assert len(probs) > 0, probs

    # overrides is string
    bad_ov_str = {**good, "overrides": "not a list"}
    probs = validate_plan(bad_ov_str, me)
    assert len(probs) > 0, probs

    # override item missing "sig" key
    bad_ov_item = {**good, "overrides": [{"cls": "A", "method": "m", "ret": False}]}
    probs = validate_plan(bad_ov_item, me)
    assert len(probs) > 0, probs
    assert any("sig" in p for p in probs), probs

    # fields is None
    bad_fields_none = {**good, "fields": None}
    probs = validate_plan(bad_fields_none, me)
    assert len(probs) > 0, probs

    # field item missing "name" key
    bad_field_item = {**good, "fields": [{"cls": "A", "sig": "I", "value": 1}]}
    probs = validate_plan(bad_field_item, me)
    assert len(probs) > 0, probs
    assert any("name" in p for p in probs), probs

    # trigger is string (truthy non-dict)
    bad_trigger_str = {**good, "trigger": "invoke"}
    probs = validate_plan(bad_trigger_str, me)
    assert len(probs) > 0, probs
    assert any("trigger" in p for p in probs), probs

    # args is not a list
    bad_args = {**good, "args": "not a list"}
    probs = validate_plan(bad_args, me)
    assert len(probs) > 0, probs
    assert any("args" in p for p in probs), probs

    # trigger dict missing "cls" key
    bad_trigger_keys = {**good, "trigger": {"kind": "invoke", "method": "m", "sig": "()Z"}}
    probs = validate_plan(bad_trigger_keys, me)
    assert len(probs) > 0, probs
    assert any("cls" in p or "trigger" in p for p in probs), probs

    # override cls is wrong-typed (int, not str) -> problem, not AttributeError
    bad_ov_type = {**good, "overrides": [{"cls": 123, "method": "m", "sig": "()Z"}]}
    probs = validate_plan(bad_ov_type, me)   # не должно бросать AttributeError
    assert len(probs) > 0, probs

    print("  validate_plan ok")


def _check_retrofit_hit():
    assert _retrofit_hit({"t": "retrofit", "cls": "p.A", "m": "m"}, "p.A->m")
    assert not _retrofit_hit({"t": "retrofit", "cls": "p.A", "m": "n"}, "p.A->m")
    assert not _retrofit_hit({"t": "http", "url": "/x"}, "p.A->m")
    print("  retrofit_hit ok")


def _check_dex_member_exists(dx):
    """Test dex_member_exists against real androguard dx.
    Pick one concrete method and one field, verify canonical identity."""
    me = dex_member_exists(dx)

    # Find first method in DEX to use as test case
    found_method = False
    for class_desc, ca in dx.classes.items():
        for ma in ca.get_methods():
            # Get canonical identity via androguard getters
            m = ma.get_method()
            if m is None:
                continue
            canonical_name = m.get_name()
            canonical_desc = m.get_descriptor()
            # Extract class name from dict key
            class_name = class_desc[1:-1].replace("/", ".") if class_desc.startswith("L") and class_desc.endswith(";") else class_desc
            # Test: method exists with canonical signature
            assert me(class_name, "method", canonical_name, canonical_desc), \
                f"Method {class_name}.{canonical_name}{canonical_desc} should exist"
            # Test: method doesn't exist with tweaked signature
            tweaked = canonical_desc + "X" if canonical_desc else "(X)"
            assert not me(class_name, "method", canonical_name, tweaked), \
                f"Tweaked signature {tweaked} should not exist"
            found_method = True
            break
        if found_method:
            break

    assert found_method, "No methods found in DEX for testing"

    # Find first field in DEX to use as test case
    found_field = False
    for class_desc, ca in dx.classes.items():
        for fa in ca.get_fields():
            # Get canonical identity via androguard getters
            f = fa.get_field()
            if f is None:
                continue
            canonical_name = f.get_name()
            canonical_desc = f.get_descriptor()
            # Extract class name from dict key
            class_name = class_desc[1:-1].replace("/", ".") if class_desc.startswith("L") and class_desc.endswith(";") else class_desc
            # Test: field exists with canonical signature
            assert me(class_name, "field", canonical_name, canonical_desc), \
                f"Field {class_name}.{canonical_name}:{canonical_desc} should exist"
            # Test: field doesn't exist with tweaked signature
            tweaked = canonical_desc + "X" if canonical_desc else "X"
            assert not me(class_name, "field", canonical_name, tweaked), \
                f"Tweaked field signature {tweaked} should not exist"
            found_field = True
            break
        if found_field:
            break

    assert found_field, "No fields found in DEX for testing"

    print("  dex_member_exists ok")


def _check_real_guards():
    rec = {"guards": [
        {"frame": "A->m", "opcode": "if-nez", "operand": {"source_kind": "invoke",
         "detail": "Lp/S;->isX()Z"}, "notes": []},
        {"frame": "B->invokeSuspend", "opcode": "if-eqz", "operand": {"source_kind": "field",
         "detail": "Lp/B;->A I"}, "notes": ["coroutine_state_machine"]},
        {"frame": "C->k", "opcode": "if-nez", "operand": {"source_kind": "invoke",
         "detail": "Lkotlin/jvm/internal/Intrinsics;->areEqual"}, "notes": ["framework"]},
    ]}
    rg = real_guards(rec)
    assert len(rg) == 1 and rg[0]["frame"] == "A->m", rg
    print("  real_guards ok")


def _check_build_prompt():
    rec = {"key": "p.IAcc->upd", "cls": "p.IAcc", "method": "upd",
           "call_sites": [{"caller": "p.Mgr->enable", "offset": 28}],
           "guards": [{"frame": "p.Mgr->enable", "opcode": "if-nez",
                       "operand": {"source_kind": "invoke", "detail": "Lp/S;->isX()Z"},
                       "notes": []},
                      {"frame": "b->invokeSuspend", "opcode": "if-eqz",
                       "operand": {"source_kind": "field", "detail": "Lb;->A I"},
                       "notes": ["coroutine_state_machine"]}],
           "args": [{"index": 0, "source_kind": "unknown", "detail": None}],
           "frontier": "ui.Btn->onClick", "activation_cost": 1}
    p = build_prompt(rec, stage=1, smali={"p.Mgr->enable": "0x0 invoke ..."})
    assert "p.IAcc->upd" in p
    assert "isX()Z" in p                      # реальный страж в промпте
    assert "coroutine_state_machine" not in p # шумовой отфильтрован
    assert '"stage": 1' in p or '"stage":1' in p
    assert "call_retrofit" in p and "invoke" in p and "trigger_entry" in p  # схема ступеней
    print("  build_prompt ok")


def _check_method_smali(dx):
    """method_smali на реальном DEX: найти метод с кодом, проверить, что
    выход непустой и похож на smali-строки 'mnemonic operand'."""
    found = None
    for class_desc, ca in dx.classes.items():
        cls = class_desc[1:-1].replace("/", ".") if class_desc.startswith("L") and class_desc.endswith(";") else class_desc
        for ma in ca.get_methods():
            txt = method_smali(dx, cls, ma.name)
            if txt:
                found = (cls, ma.name, txt)
                break
        if found:
            break
    assert found is not None, "не нашлось ни одного метода с кодом в DEX"
    cls, method, txt = found
    assert isinstance(txt, str) and txt.strip(), txt
    lines = txt.splitlines()
    assert any(len(line.split(" ", 1)) == 2 and line.split(" ", 1)[0] for line in lines), \
        f"нет строки вида 'mnemonic operand' в smali {cls}->{method}:\n{txt}"
    print("  method_smali ok")


def _check_parse_plan():
    assert parse_plan('{"a":1}') == {"a": 1}
    assert parse_plan('```json\n{"a":1}\n```') == {"a": 1}       # забор срезан
    assert parse_plan('бла\n{"a": 1}\nбла') == {"a": 1}          # JSON среди текста
    try:
        parse_plan("не json вовсе"); assert False
    except ValueError:
        pass
    print("  parse_plan ok")

def _check_generate_plan():
    captured = {}
    def fake_transport(url, headers, body):
        captured["url"] = url
        captured["headers"] = headers
        captured["body"] = json.loads(body)
        return json.dumps({"choices": [{"message": {"content": '{"stage": 0}'}}]})
    os.environ["LLM_API_KEY"] = "k"
    os.environ["LLM_MODEL"] = "m"
    os.environ["LLM_BASE_URL"] = "https://x/v1/chat/completions"
    plan = generate_plan("PROMPT", backend="openai", transport=fake_transport)
    assert plan == {"stage": 0}
    assert captured["body"]["model"] == "m"
    assert captured["body"]["messages"][0]["content"] == "PROMPT"
    assert captured["headers"]["Authorization"] == "Bearer k"
    assert captured["headers"]["Content-Type"] == "application/json"

    # transport failure (e.g. 429) surfaces as a labeled RuntimeError, not a bare HTTPError
    def boom(*a):
        raise urllib.error.HTTPError("https://x", 429, "Too Many Requests", {}, None)
    try:
        generate_plan("PROMPT", backend="openai", transport=boom)
        assert False, "expected RuntimeError"
    except RuntimeError as e:
        msg = str(e).lower()
        assert "transport" in msg or "llm" in msg, msg
    print("  generate_plan ok")


def _check_staging():
    rec = {"key": "p.A->m", "cls": "p.A", "method": "m"}
    # fired на ступени 0, но параметры синтетические; реальные — только на ступени 1
    def fake_run(rec, stage):
        return {"stage": stage, "valid": True, "exceptions": [],
                "fired": stage in (0, 1),
                "real_params": stage == 1,
                "request": {"url": "/x"} if stage in (0, 1) else None}
    out = run_key(rec, stages=(0, 1, 2), run_stage=fake_run)
    assert out["reached"] is True                 # уровень (а): ушло на ст.0
    assert out["activated_real"] is True          # уровень (б)
    assert out["min_stage"] == 1                  # минимальная ступень уровня (б)
    assert len(out["stages"]) == 2                # 2 остановил не пробовали

    # исключение ступени не роняет петлю (Review Focus: suspend/Continuation)
    def boom(rec, stage):
        if stage == 0: raise RuntimeError("frida boom")
        return {"stage": stage, "valid": True, "exceptions": [], "fired": True,
                "real_params": True, "request": {"url": "/y"}}
    out2 = run_key(rec, stages=(0, 1), run_stage=boom)
    assert out2["activated_real"] is True and out2["min_stage"] == 1
    assert "frida boom" in out2["stages"][0]["exceptions"][0]
    print("  staging ok")


def _check_report():
    results = [
        {"key": "a", "reached": True, "activated_real": True, "min_stage": 0},
        {"key": "b", "reached": True, "activated_real": True, "min_stage": 1},
        {"key": "c", "reached": True, "activated_real": False, "min_stage": None},
    ]
    txt = report(results)
    assert "ступень 0" in txt and "ступень 1" in txt
    assert "достижим" in txt                    # уровень (а) отдельно
    assert "RQ3" in txt and "несопостав" in txt.lower()  # оговорка
    print("  report ok")


def _selfcheck(apk=None):
    _check_validate_plan()
    _check_retrofit_hit()
    _check_real_guards()
    _check_build_prompt()
    _check_parse_plan()
    _check_generate_plan()
    _check_staging()
    _check_report()
    if apk is not None:
        if load_apk is None:
            raise RuntimeError("slice module not available; cannot test with real APK")
        apk_obj, dx = load_apk(apk)
        _check_dex_member_exists(dx)
        _check_method_smali(dx)
    print("все проверки activate.py прошли")


def main():
    ap = argparse.ArgumentParser(description="Принудительная активация скрытых запросов")
    ap.add_argument("--slice", type=Path, help="out/<pkg>.slice.jsonl")
    ap.add_argument("--apk", type=Path)
    ap.add_argument("--keys", nargs="*", help="подмножество ключей; по умолч. activation_exact")
    ap.add_argument("--backend", default="openai", choices=["openai", "manual"])
    ap.add_argument("--manual-plan", type=Path, help="файл с планом для --backend manual")
    ap.add_argument("--wait", type=float, default=5.0, help="окно ожидания сетевого события, сек")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--dry-run", action="store_true", help="prompt+plan+validate без устройства")
    ap.add_argument("--selfcheck", action="store_true")
    args = ap.parse_args()
    if args.selfcheck:
        _selfcheck(apk=args.apk)
        return
    if not (args.slice and args.apk):
        ap.error("нужны --slice и --apk")
    recs = [json.loads(l) for l in args.slice.read_text(encoding="utf-8").splitlines() if l.strip()]
    recs = [r for r in recs if r.get("key")]
    if args.keys:
        recs = [r for r in recs if r["key"] in set(args.keys)]
    else:
        recs = [r for r in recs if r.get("activation_exact")]
    apk_obj, dx = load_apk(args.apk)
    results = []
    if args.dry_run:
        me = dex_member_exists(dx)
        for r in recs:
            prompt = build_prompt(r, 0, {r["cls"] + "->" + r["method"]:
                                         method_smali(dx, r["cls"], r["method"])})
            plan = generate_plan(prompt, backend=args.backend, manual_path=args.manual_plan)
            print(f"[{r['key']}] проблемы плана: {validate_plan(plan, me) or 'нет'}")
        return
    run_stage = activate_on_device(dx, apk_obj.get_package(), args.backend, args.wait, args.manual_plan)
    for r in recs:
        results.append(run_key(r, stages=(0, 1, 2), run_stage=run_stage))
    txt = report(results)
    print(txt)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        args.out.with_suffix(".report.txt").write_text(txt, encoding="utf-8")


if __name__ == "__main__":
    main()
