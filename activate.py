#!/usr/bin/env python3
"""Forced activation of hidden HTTP requests via Frida."""

import json, sys, os, argparse, re, urllib.request
from pathlib import Path

try:
    from slice import load_apk
except ImportError:
    load_apk = None


def _package_of(apk_path):
    """Имя пакета из манифеста APK — быстрый парс (без тяжёлого androguard
    Analysis на 138MB), чтобы знать пакет для spawn, не загружая dx."""
    from loguru import logger
    logger.remove()
    from androguard.core.apk import APK
    return APK(str(apk_path)).get_package()

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
        if sig != "*" and not member_exists(cls, "method", method, sig):
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
        if sig != "*" and not member_exists(cls, "field", name, sig):
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
        elif tsig != "*" and not member_exists(tcls, "method", tmethod, tsig):
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


def generate_plan(prompt, backend="openai", *, transport=None, manual_path=None,
                  max_retries=4, _backoff=None):
    """Генерирует план через LLM (openai) или читает вручную (manual).
    На бесплатном tier (OpenRouter) жёсткие rate-limit'ы — ретрай с бэкоффом на
    любой сбой транспорта (429/5xx/сеть), max_retries попыток сверх первой."""
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
                       "max_tokens": int(os.environ.get("LLM_MAX_TOKENS", "2000")),
                       "messages": [{"role": "user", "content": prompt}]}).encode("utf-8")
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    import time as _t
    backoff = _backoff or (lambda n: _t.sleep(min(3 * (2 ** n), 30)))
    raw, last = None, None
    for attempt in range(max_retries + 1):
        try:
            raw = (transport or _urllib_transport)(url, headers, body)
            last = None
            break
        except Exception as e:
            last = e
            if attempt < max_retries:
                backoff(attempt)
    if last is not None:
        raise RuntimeError(f"LLM transport failed ({model} @ {url}) после "
                           f"{max_retries + 1} попыток: {last}") from last
    try:
        content = json.loads(raw)["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as e:
        raise RuntimeError(f"LLM response unparsable: {e}; raw={raw[:200]!r}") from e
    if not isinstance(content, str) or not content.strip():
        raise RuntimeError(f"LLM вернул пустой content ({content!r}; raw={raw[:200]!r})")
    return parse_plan(content)


# --- Механический генератор планов (без LLM) ------------------------------
# Прогон всех ключей без LLM-ключа: детерминированные планы по ступеням.
# stage 0 — прямой вызов Retrofit-метода (zero-arg + авто-Continuation для suspend);
# stage 1 — invoke ближайшего call_site + эвристический форс реальных стражей;
# stage 2 — trigger_entry фронтира + форс всех стражей. Триггеры/оверрайды
# name-based (sig="*") — сигнатур в срезе нет, overloadBySig берёт единств.
# перегрузку. Эвристика стражей («успех»: boolean->true, объект->null) груба:
# надёжный выбор ветви требует LLM/анализа кода, поэтому stage 1-2 — best-effort.

def _split(k):
    i = k.rsplit("->", 1)
    return (i[0], i[1]) if len(i) == 2 else (k, "")

def _guard_overrides(rec):
    out, seen = [], set()
    for g in real_guards(rec):
        op = g.get("operand") or {}
        if op.get("source_kind") != "invoke":
            continue
        m = re.match(r"^L([^;]+);->([^(]+)\(.*\)(.+)$", op.get("detail") or "")
        if not m:
            continue
        cls = m.group(1).replace("/", "."); meth = m.group(2); ret = m.group(3)
        if cls + "->" + meth in seen:
            continue
        seen.add(cls + "->" + meth)
        if ret == "Z":
            val = True
        elif ret.startswith("L") or ret.startswith("["):
            val = {"$null": "x"}
        else:
            continue
        out.append({"cls": cls, "method": meth, "sig": "*", "ret": val})
    return out

def _arg_val(t, recipes, depth=2):
    """JVM-дескриптор типа параметра -> значение для плана. String -> "",
    массив -> null (грубо), примитив -> дефолт. Объект: если в recipes есть
    рецепт постройки (slice.py arg_recipes) и глубина не исчерпана — строим
    $new по конструктору, рекурсивно синтезируя его аргументы; иначе $default
    (activate.js в рантайме даст enum->values()[0] / прочий объект->null).
    Объектные DTO транзиентны (в куче их нет), поэтому $new, а не $choose."""
    if t == "Ljava/lang/String;":
        return ""
    if t.startswith("["):
        return {"$null": "x"}
    if t.startswith("L"):
        fq = t[1:-1].replace("/", ".")
        r = recipes.get(t)
        if r and depth > 0:
            pts = r["ctor"]
            return {"$new": fq, "sig": "(" + "".join(pts) + ")V",
                    "args": [_arg_val(p, recipes, depth - 1) for p in pts]}
        return {"$default": fq}
    return {"Z": False, "F": 0.0, "D": 0.0}.get(t, 0)

def _fq(desc):
    return desc[1:-1].replace("/", ".") if desc.startswith("L") and desc.endswith(";") else desc

def _sig_param_types(sig):
    m = re.search(r"\(([^)]*)\)", sig or "")
    if not m:
        return []
    s, out, i = m.group(1), [], 0
    while i < len(s):
        arr = ""
        while i < len(s) and s[i] == "[":
            arr += "["; i += 1
        if i >= len(s):
            break
        c = s[i]
        if c == "L":
            e = s.index(";", i); out.append(arr + s[i:e + 1]); i = e + 1
        else:
            out.append(arr + c); i += 1
    return out

def _prov_val(prov, recipes, ftype):
    """Значение аргумента из провенанса slice (статический продюсер), с откатом
    на рецепт-болванку _arg_val(ftype) — чтобы пустой продюсер (холодный старт,
    нет живого инстанса) не рушил уровень (а). field -> $field (поле живого
    owner); invoke -> $invoke (метод живого owner, его args — болванки по
    сигнатуре); new+ctor_args -> $new, каждое поле из своего провенанса."""
    dflt = _arg_val(ftype, recipes)
    if not prov:
        return dflt
    k, d = prov.get("source_kind"), prov.get("detail")
    if k == "field" and d and "->" in d:
        owner, rest = d.split("->", 1)
        fv = {"$field": _fq(owner), "name": rest.split()[0], "else": dflt}
        if ftype.startswith("L"):      # #2: нужный тип значения поля
            fv["expect"] = _fq(ftype)
        return fv
    if k == "invoke" and d and "->" in d:
        owner, rest = d.split("->", 1)
        m = re.match(r"([^(]+)(\([^)]*\)\S*)", rest)
        if m:
            return {"$invoke": _fq(owner), "method": m.group(1), "sig": m.group(2),
                    "args": [_arg_val(p, recipes) for p in _sig_param_types(m.group(2))],
                    "else": dflt}
    if k == "new" and prov.get("ctor_args") is not None and ftype.startswith("L"):
        r = recipes.get(ftype)
        if r:
            pts, ca = r["ctor"], prov["ctor_args"]
            return {"$new": _fq(ftype), "sig": "(" + "".join(pts) + ")V",
                    "args": [_prov_val(ca[i] if i < len(ca) else None, recipes, pts[i])
                             for i in range(len(pts))]}
    return dflt

def _args_from_types(rec):
    recipes = rec.get("arg_recipes", {})
    prov = {a["index"]: a for a in (rec.get("args") or [])}
    return [{"index": i, "value": _prov_val(prov.get(i), recipes, t)}
            for i, t in enumerate(rec.get("arg_types", []))]


def _stub_val(ftype):
    """Заглушка на user-input лист (param/unknown): маркер $stub с типом —
    coerce даст НЕПУСТОЕ значение нужного типа (синтетика, НЕ app-данные; тир
    (в) synthesized). LLM-наполнитель — отдельным флагом поверх (follow-up)."""
    return {"$stub": _fq(ftype) if ftype.startswith("L") else ftype}

def _src_val(src, recipes, ftype):
    """Рекурсивное дерево источника (slice.arg_sources) -> значение плана.
    const->литерал; field->$field; invoke->$invoke с РЕКУРСИВНО собранными
    аргументами продюсера; new->$new с рекурсивными ctor-полями; param/unknown/
    capped/instanceof -> $stub (user-input). Так «дёргаем продюсеров рекурсивно,
    пока не упрёмся в пользовательский ввод», где ставим заглушку."""
    if not isinstance(src, dict):
        return _arg_val(ftype, recipes)
    k = src.get("k")
    if k == "const":
        v = src.get("value")
        return v if isinstance(v, (str, int, float, bool)) else _stub_val(ftype)
    if k == "field" and src.get("detail") and "->" in src["detail"]:
        owner, rest = src["detail"].split("->", 1)
        fv = {"$field": _fq(owner), "name": rest.split()[0], "else": _stub_val(ftype)}
        if ftype.startswith("L"):      # #2: нужный тип значения поля
            fv["expect"] = _fq(ftype)
        return fv
    if k == "invoke" and src.get("detail") and "->" in src["detail"]:
        owner, rest = src["detail"].split("->", 1)
        m = re.match(r"([^(]+)(\([^)]*\)\S*)", rest)
        if m:
            meth, sig = m.group(1), m.group(2)
            pts = _sig_param_types(sig)
            sa = src.get("args") or []
            args = [_src_val(sa[i], recipes, pts[i]) if i < len(sa) else _stub_val(pts[i])
                    for i in range(len(pts))]
            return {"$invoke": _fq(owner), "method": meth, "sig": sig, "args": args,
                    "else": _stub_val(ftype)}
    if k == "new" and src.get("type"):
        t = src["type"]; r = recipes.get(t)
        if r:
            pts = r["ctor"]; ca = src.get("ctor_args") or []
            args = [_src_val(ca[i], recipes, pts[i]) if i < len(ca) else _stub_val(pts[i])
                    for i in range(len(pts))]
            return {"$new": _fq(t), "sig": "(" + "".join(pts) + ")V", "args": args}
    return _stub_val(ftype)  # param / unknown / capped / instanceof / нерезолвнутое

def _args_from_sources(rec):
    """Рекурсивный вариант (флаг --recurse-args): аргументы из arg_sources."""
    recipes = rec.get("arg_recipes", {})
    src = {a["index"]: a.get("source") for a in (rec.get("arg_sources") or [])}
    return [{"index": i, "value": _src_val(src.get(i), recipes, t)}
            for i, t in enumerate(rec.get("arg_types", []))]

def _plan_has_stub(v):
    """Есть ли $stub как ПЕРВИЧНОЕ значение плана (рекурсивно) — признак тира
    (в) synthesized (user-input заглушен). Ветка `else` (фолбэк $field/$invoke)
    игнорируется: упал ли продюсер в заглушку — факт рантайма, ловится оффлайн
    по телу (маркер 'stub'), а не по плану (иначе каждый $field с else-stub
    ложно метился бы synthesized)."""
    if isinstance(v, dict):
        if "$stub" in v:
            return True
        return any(_plan_has_stub(val) for key, val in v.items() if key != "else")
    if isinstance(v, list):
        return any(_plan_has_stub(x) for x in v)
    return False

def make_plan(rec, stage, recurse_args=False):
    cls, method, key = rec["cls"], rec["method"], rec["key"]
    p = {"key": key, "stage": stage, "overrides": [], "fields": [], "args": [],
         "raw_js": None, "rationale": ""}
    if stage == 0:
        p["trigger"] = {"kind": "call_retrofit", "cls": cls, "method": method, "sig": "*"}
        p["args"] = _args_from_sources(rec) if recurse_args else _args_from_types(rec)
        p["rationale"] = ("mech stage0: прямой вызов Retrofit-метода, args "
                          + ("рекурсивно из arg_sources +$stub на user-input" if recurse_args
                             else "по типам/провенансу (+авто-Continuation)"))
    elif stage == 1:
        cs = rec.get("call_sites") or []
        ccls, cm = _split(cs[0]["caller"]) if cs else (cls, method)
        p["trigger"] = {"kind": "invoke", "cls": ccls, "method": cm, "sig": "*"}
        p["overrides"] = _guard_overrides(rec)
        p["rationale"] = "mech stage1: invoke ближайшего call_site + форс стражей (эвристика)"
    else:
        fcls, fm = _split(rec.get("frontier") or "")
        if not fm:
            fcls, fm = cls, method
        p["trigger"] = {"kind": "trigger_entry", "cls": fcls, "method": fm, "sig": "*"}
        p["overrides"] = _guard_overrides(rec)
        p["rationale"] = "mech stage2: trigger_entry фронтира + форс всех стражей (эвристика)"
    return p


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


def _agent(name):
    """Путь к Frida-агенту: скомпилированный build/<name> (frida 17 — bundle с
    frida-java-bridge, т.к. frida 17 убрал глобал Java), иначе исходник (frida 16/arm)."""
    b = HERE / "build" / name
    return b if b.exists() else HERE / name


def _pidof(device, pkg):
    import subprocess
    r = subprocess.run(["adb", "-s", device.id, "shell", "pidof", pkg],
                       capture_output=True, text=True)
    p = (r.stdout or "").split()
    return int(p[0]) if p else None

def _ensure_warm(device, pkg, tries=3):
    """#1 re-warm (attach-режим): вернуть pid тёплого процесса; если упал —
    перезапустить через LAUNCHER (логин на диске переживает рестарт) и подождать
    инициализацию. None — поднять не удалось."""
    import subprocess, time as _t
    pid = _pidof(device, pkg)
    if pid is not None:
        return pid
    for _ in range(tries):
        subprocess.run(["adb", "-s", device.id, "shell", "monkey", "-p", pkg,
                        "-c", "android.intent.category.LAUNCHER", "1"],
                       capture_output=True, text=True)
        _t.sleep(12)
        pid = _pidof(device, pkg)
        if pid is not None:
            _t.sleep(4)   # дать инициализироваться (DI/сессия)
            return pid
    return None

def activate_on_device(dx_provider, pkg, backend, wait_t, manual_path=None, paths=None, skip_dx=False, plans=None, recurse_args=False, attach=False):
    """Возвращает run_stage(rec, stage), замкнутый на пакет и одну Frida-сессию.
    dx_provider() лениво отдаёт androguard dx (загрузка 138MB APK ~130с) — зовётся
    только когда dx реально нужен (валидация overrides/fields, smali для openai-
    промпта). Для manual call_retrofit dx не нужен → APK не грузится (иначе прогон
    упирается в тяжёлую androguard-загрузку).
    import frida/trace здесь, а не на верху модуля — offline-пути должны работать
    без установленного frida."""
    import frida, time, trace, signal
    _me = {}
    def me(cls, kind, name, sig):
        if skip_dx:                              # без DEX-валидации (кривой член упадёт на устройстве)
            return True
        if "f" not in _me:
            _me["f"] = dex_member_exists(dx_provider())
        return _me["f"](cls, kind, name, sig)
    device = trace.pick_device(None)

    def run_stage(rec, stage):
        if backend == "plans":
            plan = (plans or {}).get(rec["key"])  # готовый план на ключ (напр. от субагента)
            if not isinstance(plan, dict) or plan.get("stage") != stage:
                return {"stage": stage, "valid": False, "exceptions": ["нет плана для этой ступени"],
                        "fired": False, "real_params": False, "request": None, "plan": plan}
        elif backend == "mech":
            plan = make_plan(rec, stage, recurse_args)  # детерминированно из среза, без dx/LLM
        else:
            # manual и skip_dx игнорируют dx/smali (не грузим тяжёлый androguard);
            # у openai smali синка обычно пуст (интерфейс) — главный сигнал в срезе.
            if backend == "manual":
                prompt = ""
            elif skip_dx:
                prompt = build_prompt(rec, stage, {})
            else:
                prompt = build_prompt(rec, stage, {rec["cls"] + "->" + rec["method"]:
                                                   method_smali(dx_provider(), rec["cls"], rec["method"])})
            plan = generate_plan(prompt, backend=backend, manual_path=manual_path)
        probs = validate_plan(plan, me)
        if probs:
            return {"stage": stage, "valid": False, "exceptions": probs,
                    "fired": False, "real_params": False, "request": None, "plan": plan}
        session = pid = None
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
        # _SETTLE даёт Retrofit построить прокси ДО arm, и служит ОКНОМ HARVEST
        # (б2b): залогиненное приложение на старте рефрешит токен, грузит профиль/
        # устройства — реальные значения попадают в harvest-пул агента ещё до
        # форс-вызова, и patchForced наполняет ими пустые поля. §4.8.
        _SETTLE = 4.0
        # Таймаут на ключ: на свопящем эмуляторе device.spawn/attach иногда виснет
        # намертво (во frida нет таймаута) — SIGALRM в главном потоке прерывает
        # зависший вызов, ключ помечается timeout и прогон идёт дальше (пилот-правка).
        def _on_timeout(sig, frm):
            raise TimeoutError("per-key timeout (spawn/attach завис)")
        _old_h = signal.signal(signal.SIGALRM, _on_timeout)
        signal.alarm(int(wait_t) + 45 + int(_SETTLE))
        try:
            # attach-режим (warm-state, План А): подключиться к УЖЕ запущенному и
            # пролистанному процессу (живая сессия/токены/id в куче → $field/
            # liveReceiver читают РЕАЛЬНЫЕ значения) и НЕ убивать его между ключами.
            # spawn-режим: холодный старт (пустая сессия). attach пропускает ранний
            # Proxy.newProxyInstance-хук, но mintProxy создаёт свой прокси (хук ловит
            # его) — stage-0 call_retrofit работает.
            if attach:
                # #1 re-warm: процесс мог упасть под форсом предыдущего ключа —
                # перезапускаем (логин переживает рестарт, он на диске) и ждём.
                pid = _ensure_warm(device, pkg)
                if pid is None:
                    raise RuntimeError(f"attach: процесс {pkg} не поднялся после re-warm")
                session = device.attach(pid)
            else:
                pid = device.spawn([pkg])
                session = device.attach(pid)
            # ТОЛЬКО activate.js: он сам кэширует прокси, несёт key-exact оракул
            # (эмитит {t:'retrofit',cls,m}) и снимает запрос. hook.js НЕ грузим —
            # двойной хук Proxy.newProxyInstance (hook.js+activate.js) рекурсивно
            # роняет приложение на этом ART. Оракул слушаем на самом activate.js.
            agent = session.create_script(_agent("activate.js").read_text(encoding="utf-8"))
            agent.on("message", _on_hook_msg)
            agent.load()
            if not attach:
                device.resume(pid)
            time.sleep(1.0 if attach else _SETTLE)
            try: agent.exports_sync.capture_on(rec["key"], (paths or {}).get(rec["key"], ""))
            except Exception as e: exc.append("capture_on: " + str(e))
            try: res = agent.exports_sync.arm(json.dumps(plan))
            except Exception as e: exc.append("arm: " + str(e))
            time.sleep(wait_t)
            try: snap = agent.exports_sync.snapshot()
            except Exception as e: exc.append("snapshot: " + str(e))
        except Exception as e:
            exc.append("session: " + str(e))
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, _old_h)
            if session is not None:
                try: session.detach()
                except Exception: pass
            if pid is not None and not attach:   # attach: НЕ убивать — процесс должен остаться тёплым
                try: device.kill(pid)
                except Exception: pass
        # fired — ключ-точный оракул из hook.js (Proxy.invoke по cls->method).
        # snap — advisory-артефакт; строгая привязка к key — доработка пилотной фазы.
        fired = seen["hit"]
        real = fired and _params_real(plan, snap, rec)
        exc = (res.get("exceptions", []) if isinstance(res, dict) else []) + exc
        return {"stage": stage, "valid": True, "exceptions": exc,
                "fired": fired, "real_params": real, "request": snap, "plan": plan}

    return run_stage


def _has_real_data(url, body):
    """В запросе есть хоть один непустой РЕАЛЬНЫЙ лист данных: непустой query-
    параметр или непустое строковое/ненулевое числовое поле JSON-тела. Пустые
    строки, false, 0 и пустые контейнеры — не данные (наши болванки / пустой
    продюсер)."""
    from urllib.parse import urlparse, parse_qsl
    for _, v in parse_qsl(urlparse(url or "").query, keep_blank_values=True):
        if v.strip():
            return True
    if body and body.strip().startswith("{"):
        try:
            obj = json.loads(body)
        except Exception:
            return False
        def walk(o):
            if isinstance(o, dict):
                return any(walk(x) for x in o.values())
            if isinstance(o, list):
                return any(walk(x) for x in o)
            if isinstance(o, bool):
                return False
            if isinstance(o, str):
                return o.strip() != ""
            if isinstance(o, (int, float)):
                return o != 0
            return False
        return walk(obj)
    return False


def _params_real(plan, snap, rec=None):
    """Уровень (б1): запрос СОБРАН ПРИЛОЖЕНИЕМ С РЕАЛЬНЫМИ ДАННЫМИ. Метрика по
    ФАКТУ снимка, не по плану: $field/$invoke в плане «не болванка», но продюсер
    в рантайме мог вернуть пусто / откатиться на болванку — поэтому доверяем
    только наблюдаемому запросу. matched обязателен (url содержит ожидаемый
    endpoint — НАШ форс-вызов, не попутный трафик; поллюция с hint '/' отсечена
    ещё в activate.js). none-тир (нет семантических аргументов) — запрос
    полностью определён методом, app-built при matched. data-тир — нужен хотя бы
    один непустой реальный лист в query/теле, иначе продюсер был пуст = уровень
    (а). data_cost берём из среза (rec); без rec — выводим из плана (none =
    нет args)."""
    if not snap or not snap.get("url") or not snap.get("matched"):
        return False
    # $stub в плане = user-input заглушен нами → тир (в) synthesized, НЕ app-built
    if any(_plan_has_stub(a.get("value")) for a in plan.get("args", [])):
        return False
    data_cost = (rec or {}).get("data_cost")
    if data_cost is None:
        data_cost = "none" if not plan.get("args") else "object"
    if data_cost == "none":
        return True
    return _has_real_data(snap.get("url", ""), snap.get("body", ""))


def _check_params_real():
    # none-тир (нет семантических args) matched — app-built по методу (б1)
    none_rec = {"data_cost": "none"}
    assert _params_real({"args": []}, {"url": "/x", "matched": True}, none_rec)
    assert _params_real({"args": []}, {"url": "/x", "matched": True})  # без rec: none из пустых args
    # data-тир: matched, но тело/параметры ПУСТЫ (продюсер пуст / откат на болванку) — НЕ б1
    obj_rec = {"data_cost": "object"}
    assert not _params_real({"args": [{"index": 0, "value": {"$field": "p.S", "name": "C"}}]},
                            {"url": "/x", "matched": True, "body": '{"a":"","b":false,"c":0}'}, obj_rec)
    # data-тир с реальными данными в теле — б1
    assert _params_real({"args": [{"index": 0, "value": {"$field": "p.S", "name": "C"}}]},
                        {"url": "/x", "matched": True, "body": '{"a":"val"}'}, obj_rec)
    # data-тир с реальным query-параметром — б1
    assert _params_real({"args": [{"index": 0}]}, {"url": "/x?code=123", "matched": True}, obj_rec)
    # пустой query (?code=) — не данные
    assert not _params_real({"args": [{"index": 0}]}, {"url": "/x?code=", "matched": True}, obj_rec)
    # снимок НЕ matched (попутный трафик / поллюция hint='/') — не б1
    assert not _params_real({"args": []}, {"url": "/x", "matched": False}, none_rec)
    # пустой снимок — не б1
    assert not _params_real({"args": []}, None, none_rec)
    assert not _params_real({"args": []}, {"url": "", "matched": True}, none_rec)
    # _has_real_data: вложенность, пустые листья
    assert _has_real_data("/x", '{"a":{"b":"z"}}') and not _has_real_data("/x", '{"a":{"b":""}}')
    print("  params_real ok")


def _best_snap(r):
    """Представительный снимок ключа: matched приоритетно, иначе первый с url."""
    snap = None
    for s in r.get("stages", []):
        rq = s.get("request") or {}
        if rq.get("url"):
            if rq.get("matched"):
                return rq
            if snap is None:
                snap = rq
    return snap


def _honest_level(r):
    """Честный уровень ключа ПО ФАКТУ снимка (не по плану): ('б1'|'в'|'а', snap,
    stage). matched-снимок (url содержит endpoint; hint '/' отсечён в activate.js)
    + реальные непустые данные в query/теле → 'б1' app-built. Те же данные, но с
    нашей заглушкой ($stub в плане / маркер "stub" в теле) → 'в' synthesized.
    Иначе (не matched / тело пусто) → 'а'."""
    msnap = mstage = mplan = None
    first = None
    for s in r.get("stages", []):
        rq = s.get("request") or {}
        if not rq.get("url"):
            continue
        if first is None:
            first = rq
        if rq.get("matched"):
            msnap, mstage, mplan = rq, s.get("stage"), (s.get("plan") or {})
            break
    if msnap is None:
        return ("а", first, None)
    url, body = msnap.get("url", "") or "", msnap.get("body", "") or ""
    if not _has_real_data(url, body):
        return ("а", msnap, mstage)
    synth = _has_stub_marker(url, body) or any(_plan_has_stub(a.get("value"))
                                               for a in (mplan or {}).get("args", []))
    return ("в" if synth else "б1", msnap, mstage)


def _has_stub_marker(url, body):
    """В снимке есть наша $stub-заглушка: маркер "stub" в JSON-теле ИЛИ значение
    query-параметра == 'stub' (GET кладёт заглушку в URL, не в тело)."""
    if body and '"stub"' in body:
        return True
    from urllib.parse import urlparse, parse_qsl
    return any(v == "stub" for _, v in parse_qsl(urlparse(url or "").query, keep_blank_values=True))


def report(results):
    """HTTP-аналог Таблицы IV ICSE 2025. ЧЕСТНАЯ метрика по факту снимка:
    (а) достижим / (б1) app-built с реальными данными / (в) synthesized (тело
    наполнено нашими заглушками). Распределение (б1) по минимальной ступени +
    оговорка о несопоставимости с RQ3."""
    from collections import Counter
    n = len(results)
    reached = sum(r.get("reached") for r in results)
    lvl = {r["key"]: _honest_level(r) for r in results}
    b1 = sum(1 for v in lvl.values() if v[0] == "б1")
    synth = sum(1 for v in lvl.values() if v[0] == "в")
    dist = Counter(v[2] for v in lvl.values() if v[0] == "б1")
    L = [f"Всего ключей: {n}",
         f"(а) достижим (запрос ушёл, параметры любые):              {reached}/{n}",
         f"(б1) app-built с РЕАЛЬНЫМИ данными (matched, без заглушек): {b1}/{n}",
         f"(в)  synthesized (тело наполнено нашими $stub-заглушками):  {synth}/{n}",
         "",
         "HTTP-аналог Таблицы IV — минимальная ступень уровня (б1):",
         f"  ступень 0 (прямой вызов):          {dist.get(0,0)}",
         f"  ступень 1 (вызывающий + стражи):   {dist.get(1,0)}",
         f"  ступень 2 (UI-фронтир):            {dist.get(2,0)}",
         f"  без реальных данных (болванка/synthesized/недостижим): {n - b1}",
         "",
         "Оговорка: сравнение с RQ3/Таблицей IV ICSE 2025 — качественное; "
         "метрики несопоставимы напрямую (активити vs сетевые вызовы, другой стенд).",]
    # Дамп сформированных запросов (артефакт для ВКР): [а]=пусто/болванка,
    # [б1]=реальные app-данные, [в]=наполнено нашими заглушками.
    dump = []
    for r in results:
        level, snap, _ = lvl[r["key"]]
        if not snap:
            continue
        body = snap.get("body")
        body = "" if body is None else (" body=" + str(body)[:120])
        src = snap.get("source")
        src = f" [{src}]" if src else ""
        dump.append(f"  [{level}]{src} {r['key'].split('->')[-1]}: "
                    f"{snap.get('method','?')} {snap.get('url','')}{body}")
    if dump:
        L += ["", "Сформированные запросы ([а]=пусто/болванка / [б1]=реальные app-данные / "
              "[в]=наполнено заглушками):"] + dump
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
        generate_plan("PROMPT", backend="openai", transport=boom, max_retries=0)
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


def _check_arg_synth():
    # object-арг с рецептом -> $new по конструктору: примитив->дефолт,
    # String->"", вложенный объект с рецептом -> вложенный $new, объект без
    # рецепта/enum -> $default.
    recipes = {"Lp/Dto;": {"ctor": ["Ljava/lang/String;", "I", "Lp/Inner;", "Lp/Mode;"]},
               "Lp/Inner;": {"ctor": ["Z"]}}
    rec = {"arg_types": ["Lp/Dto;", "J", "Ljava/lang/String;", "[I"],
           "arg_recipes": recipes}
    args = [a["value"] for a in _args_from_types(rec)]
    dto = args[0]
    assert dto["$new"] == "p.Dto" and dto["sig"] == "(Ljava/lang/String;ILp/Inner;Lp/Mode;)V"
    assert dto["args"][0] == "" and dto["args"][1] == 0           # String->"", int->0
    assert dto["args"][2]["$new"] == "p.Inner"                   # вложенный DTO с рецептом
    assert dto["args"][2]["args"] == [False]                     # его boolean->false
    assert dto["args"][3] == {"$default": "p.Mode"}              # enum без рецепта -> $default
    assert args[1] == 0 and args[2] == "" and args[3] == {"$null": "x"}  # long/String/массив
    # исчерпание глубины: объект на 3-м уровне -> $default, не бесконечная рекурсия
    deep = {"Lp/A;": {"ctor": ["Lp/B;"]}, "Lp/B;": {"ctor": ["Lp/C;"]},
            "Lp/C;": {"ctor": ["Lp/D;"]}, "Lp/D;": {"ctor": ["I"]}}
    v = _arg_val("Lp/A;", deep)   # A(depth2)->B(1)->C(0): C уже $default, не раскрыт
    assert v["args"][0]["$new"] == "p.B" and v["args"][0]["args"][0] == {"$default": "p.C"}, v
    # провенанс (статический продюсер): field->$field, invoke->$invoke, new+ctor->$new по полям
    recp = {"Lp/Dto;": {"ctor": ["Ljava/lang/String;"]}}
    rf = {"arg_types": ["Lp/Dto;"], "arg_recipes": recp,
          "args": [{"index": 0, "source_kind": "field", "detail": "Lp/Store;->C Ljava/lang/Object;"}]}
    a0 = _args_from_types(rf)[0]["value"]
    assert a0["$field"] == "p.Store" and a0["name"] == "C" and "else" in a0, a0
    ri = {"arg_types": ["Lp/Dto;"], "arg_recipes": recp,
          "args": [{"index": 0, "source_kind": "invoke",
                    "detail": "Lp/M;->map(Ljava/lang/String;)Lp/Dto;"}]}
    a1 = _args_from_types(ri)[0]["value"]
    assert a1["$invoke"] == "p.M" and a1["method"] == "map" and a1["args"] == [""], a1
    rn = {"arg_types": ["Lp/Dto;"], "arg_recipes": recp,
          "args": [{"index": 0, "source_kind": "new", "detail": "Lp/Dto;",
                    "ctor_args": [{"index": 0, "source_kind": "field",
                                   "detail": "Lp/S;->t Ljava/lang/String;"}]}]}
    a2 = _args_from_types(rn)[0]["value"]
    assert a2["$new"] == "p.Dto" and a2["args"][0]["$field"] == "p.S", a2
    # рекурсивный arg_sources: new -> invoke(продюсер) -> param-лист = $stub
    rs = {"arg_types": ["Lp/Dto;"], "arg_recipes": {"Lp/Dto;": {"ctor": ["Lp/X;"]}},
          "arg_sources": [{"index": 0, "source": {"k": "new", "type": "Lp/Dto;",
              "ctor_args": [{"k": "invoke", "detail": "Lp/F;->mk(Ljava/lang/String;)Lp/X;",
                             "args": [{"k": "param", "index": 1}]}]}}]}
    a3 = _args_from_sources(rs)[0]["value"]
    assert a3["$new"] == "p.Dto", a3
    assert a3["args"][0]["$invoke"] == "p.F" and a3["args"][0]["method"] == "mk", a3
    assert a3["args"][0]["args"][0] == {"$stub": "java.lang.String"}, a3   # user-input лист
    assert _plan_has_stub(a3) and not _plan_has_stub({"$field": "p.S", "name": "C"})
    # field-лист без $stub — app-built, не synthesized
    rf2 = {"arg_types": ["Ljava/lang/String;"], "arg_recipes": {},
           "arg_sources": [{"index": 0, "source": {"k": "field", "detail": "Lp/S;->t Ljava/lang/String;"}}]}
    assert not _plan_has_stub(_args_from_sources(rf2)[0]["value"])
    print("  arg_synth ok")


def _check_report():
    def st(stage, url, body, matched, plan_args):
        return {"stage": stage, "request": {"url": url, "body": body, "matched": matched,
                                            "method": "POST"},
                "plan": {"args": plan_args}}
    results = [
        # б1: matched, реальные данные, без заглушек
        {"key": "a", "reached": True, "stages": [st(0, "/x?id=42", None, True, [])]},
        # в: matched, реальные данные, но тело из заглушки
        {"key": "b", "reached": True, "stages": [st(0, "/y", '{"id":"stub"}', True,
                                                     [{"value": {"$stub": "java.lang.String"}}])]},
        # а: matched, но тело пустое
        {"key": "c", "reached": True, "stages": [st(0, "/z", '{"ids":[]}', True, [])]},
        # а: не matched
        {"key": "d", "reached": False, "stages": [st(0, "/w", None, False, [])]},
    ]
    txt = report(results)
    levels = {k: _honest_level(r)[0] for k, r in zip("abcd", results)}
    assert levels == {"a": "б1", "b": "в", "c": "а", "d": "а"}, levels
    assert "(б1) app-built с РЕАЛЬНЫМИ данными" in txt and "synthesized" in txt
    assert "ступень 0" in txt and "RQ3" in txt and "несопостав" in txt.lower()
    print("  report ok")


def _selfcheck(apk=None):
    _check_validate_plan()
    _check_retrofit_hit()
    _check_real_guards()
    _check_build_prompt()
    _check_parse_plan()
    _check_generate_plan()
    _check_staging()
    _check_arg_synth()
    _check_params_real()
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
    ap.add_argument("--package", help="пакет для spawn (по умолчанию — из манифеста APK)")
    ap.add_argument("--keys", nargs="*", help="подмножество ключей; по умолч. activation_exact")
    ap.add_argument("--keys-file", type=Path, help="файл со списком ключей (по одному в строке)")
    ap.add_argument("--skip-dx", action="store_true",
                    help="не грузить androguard dx: пустой smali в промпте + пропуск DEX-валидации "
                         "(кривой член падает на устройстве). Для openai на тяжёлом/свопящем APK.")
    ap.add_argument("--backend", default="openai", choices=["openai", "manual", "mech", "plans"],
                    help="openai=LLM, manual=один план из файла, mech=механический без LLM, "
                         "plans=готовые планы на ключ из --plans-file (напр. от субагента)")
    ap.add_argument("--plans-file", type=Path, help="JSON {ключ: план} для --backend plans")
    ap.add_argument("--manual-plan", type=Path, help="файл с планом для --backend manual")
    ap.add_argument("--hidden", type=Path, help="out/<pkg>.hidden.jsonl — карта ключ→путь для привязки снимка")
    ap.add_argument("--wait", type=float, default=5.0, help="окно ожидания сетевого события, сек")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--attach", action="store_true",
                    help="warm-state (План А): attach к УЖЕ запущенному+пролистанному процессу, не spawn и не kill — $field/liveReceiver читают реальные сессионные данные")
    ap.add_argument("--recurse-args", action="store_true",
                    help="stage0: аргументы рекурсивно из arg_sources, $stub на user-input листьях (тир synthesized)")
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
    keyset = set(args.keys or [])
    if args.keys_file and args.keys_file.exists():
        keyset |= {k.strip() for k in args.keys_file.read_text(encoding="utf-8").splitlines() if k.strip()}
    if keyset:
        recs = [r for r in recs if r["key"] in keyset]
    else:
        recs = [r for r in recs if r.get("activation_exact")]
    results = []
    dxbox = {}
    def dx_provider():
        if "dx" not in dxbox:
            dxbox["dx"] = load_apk(args.apk)[1]
        return dxbox["dx"]
    if args.dry_run:
        me = dex_member_exists(dx_provider())
        for r in recs:
            prompt = build_prompt(r, 0, {r["cls"] + "->" + r["method"]:
                                         method_smali(dx_provider(), r["cls"], r["method"])})
            plan = generate_plan(prompt, backend=args.backend, manual_path=args.manual_plan)
            print(f"[{r['key']}] проблемы плана: {validate_plan(plan, me) or 'нет'}")
        return
    pkg = args.package or _package_of(args.apk)
    paths = {}
    if args.hidden and args.hidden.exists():
        for l in args.hidden.read_text(encoding="utf-8").splitlines():
            if not l.strip():
                continue
            h = json.loads(l)
            if h.get("status") == "hidden" and h.get("path"):
                paths.setdefault(h["key"], h["path"])
    plans = {}
    if args.plans_file and args.plans_file.exists():
        plans = json.loads(args.plans_file.read_text(encoding="utf-8"))
    run_stage = activate_on_device(dx_provider, pkg, args.backend, args.wait, args.manual_plan,
                                   paths, args.skip_dx, plans, args.recurse_args, args.attach)
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
