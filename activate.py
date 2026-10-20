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

def _sig_ret_type(sig):
    """Тип возврата из дескриптора метода '(...)ret' — для типизированной
    заглушки else у $invoke (иначе Object-заглушка ломает подбор перегрузки)."""
    i = (sig or "").rfind(")")
    return sig[i + 1:] if (0 <= i < len(sig) - 1) else ""

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
    if k == "phi":
        # значение из ≥2 веток (slice._phi_source): берём первую альтернативу,
        # дающую НЕ-$stub (реальную) ветку; иначе первую. Инструменту достаточно
        # одного валидного значения.
        best = None
        for a in (src.get("alts") or []):
            v = _src_val(a, recipes, ftype)
            if best is None:
                best = v
            if not (isinstance(v, dict) and "$stub" in v):
                return v
        return best if best is not None else _stub_val(ftype)
    if k == "const":
        v = src.get("value")
        # const-class (литерал класса): JacksonJsoner.getFieldsParameter(Model.class)
        # и подобные рефлексивные продюсеры принимают java.lang.Class — передаём
        # НАСТОЯЩИЙ класс, иначе $stub ломает продюсер (ivi: fields=stub → 400).
        if ftype == "Ljava/lang/Class;" and isinstance(v, str) and v.startswith("L") and v.endswith(";"):
            return {"$class": _fq(v)}
        if ftype.startswith(("L", "[")):
            # Объектный слот. Валиден только строковый литерал для String/
            # CharSequence/Object. Числовой const (const/4 v,#0) в объектный регистр —
            # это загрузка NULL, а не число; отдать его числом ломает подбор
            # перегрузки (регрессия catalogFeedsCardgroup: 0 прилетал на
            # java.lang.String → "argument types do not match"). По типу несовместимо
            # → типизированная болванка (как было до phi: unknown→$stub, вызов шёл).
            if isinstance(v, str) and not isinstance(v, bool) and ftype in (
                    "Ljava/lang/String;", "Ljava/lang/CharSequence;", "Ljava/lang/Object;"):
                return v
            return _stub_val(ftype)
        # Примитивный слот: скаляр как есть.
        return v if isinstance(v, (str, int, float, bool)) else _stub_val(ftype)
    if k == "field" and src.get("detail") and "->" in src["detail"]:
        owner, rest = src["detail"].split("->", 1)
        if _fq(owner).startswith("java."):   # генерик java.*-owner — см. $invoke ниже
            return _stub_val(ftype)
        # else-заглушка — типа СЛОТА (ftype), а НЕ объявленного типа поля: поле
        # континуации часто объявлено java.lang.Object (generic-слот), а аргументу
        # нужен String — Object-заглушка сломала бы подбор (feedsCardgroupInfo).
        fv = {"$field": _fq(owner), "name": rest.split()[0], "else": _stub_val(ftype)}
        if ftype.startswith("L"):      # #2: нужный тип значения поля
            fv["expect"] = _fq(ftype)
        return fv
    if k == "invoke" and src.get("detail") and "->" in src["detail"]:
        owner, rest = src["detail"].split("->", 1)
        # Генерик java.*-owner (java.util.List/Map, java.lang.Object, ...) как
        # продюсер бессмыслен: coerce делает Java.choose по ВСЕЙ куче нужного типа
        # (миллионы List/String) — повисает и всё равно даёт случайный объект.
        # Реальный продюсер — всегда app-класс. → типизированная болванка слота.
        # (getRestrictionsSchedule: arg = List.get(field) → зависал на Java.choose.)
        if _fq(owner).startswith("java."):
            return _stub_val(ftype)
        m = re.match(r"([^(]+)(\([^)]*\)\S*)", rest)
        if m:
            meth, sig = m.group(1), m.group(2)
            pts = _sig_param_types(sig)
            sa = src.get("args") or []
            args = [_src_val(sa[i], recipes, pts[i]) if i < len(sa) else _stub_val(pts[i])
                    for i in range(len(pts))]
            # else-заглушка (продюсер пуст/мёртв) — БОЛЕЕ КОНКРЕТНЫЙ из {тип
            # параметра ftype, тип возврата ret}: если ftype конкретен (String) —
            # берём его (getRestrictionsSchedule: List.get()->Object на String-
            # параметре; Object-заглушка ломала подбор перегрузки → не вызывался);
            # если ftype генерик (Object), а ret конкретен — берём ret (registerSmart).
            ret = _sig_ret_type(sig)
            _GEN = ("Ljava/lang/Object;", "")
            if ftype.startswith(("L", "[")) and ftype not in _GEN:
                else_t = ftype
            elif ret.startswith(("L", "[")) and ret not in _GEN:
                else_t = ret
            else:
                else_t = ret or ftype
            return {"$invoke": _fq(owner), "method": meth, "sig": sig, "args": args,
                    "else": _stub_val(else_t)}
    if k == "new" and src.get("type"):
        t = src["type"]; r = recipes.get(t); ca = src.get("ctor_args") or []
        # Конструктор из arg_sources (реальный, что использовал вызывающий) ценен,
        # когда его ctor_args РАЗРЕШЕНЫ в продюсеры (invoke/field/const/new) — тогда
        # зовём getDeviceModel/getOsVersion/... и получаем реальные данные
        # (registerSmart). Но если ctor_args — unknown/param, мы не знаем их типов:
        # Object-заглушки ломают подбор перегрузки конструктора (frida: «argument
        # types do not match») → ключ вообще не вызывается. Поэтому:
        if ca and r and len(r["ctor"]) == len(ca):
            # длины совпали с рецептом → есть типы → sig + типизированные заглушки
            pts = r["ctor"]
            args = [_src_val(ca[i], recipes, pts[i]) for i in range(len(ca))]
            return {"$new": _fq(t), "sig": "(" + "".join(pts) + ")V", "args": args}
        if ca and all(c.get("k") in ("invoke", "field", "const", "new") for c in ca):
            # типов нет (рецепт иной длины), но все ctor_args — конкретные продюсеры:
            # их значения корректно типизированы, frida подберёт перегрузку по ним
            args = [_src_val(c, recipes, "Ljava/lang/Object;") for c in ca]
            return {"$new": _fq(t), "args": args}
        # иначе (ctor_args с unknown/param или их нет) — рецепт: безопасно вызывается
        if r:
            pts = r["ctor"]
            args = [_src_val(None, recipes, p) for p in pts]
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
        # [в]/[а]-matched уже снят на этой ступени: верхние ступени тело не улучшат
        # (синтетика не станет реальнее) и лишь рискуют уронить приложение — выходим.
        if (r.get("request") or {}).get("matched"):
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

def _wait_past_splash(device, pkg, timeout=60):
    """Ждать, пока приложение выйдет из SplashActivity (ранний старт: деоптимизация
    vdex + сплеш). Attach+форс в этот момент нестабилен для frida-java-bridge
    ('script has been destroyed' — процесс гибнет на arm). Готово, когда resumed-
    активность принадлежит pkg и это НЕ *Splash*. Возврат мгновенный, если уже
    на основном экране. False — таймаут (всё равно продолжаем, лучше чем висеть)."""
    import subprocess, time as _t, re as _re
    deadline = _t.time() + timeout
    pat = _re.compile(r"ResumedActivity.*?" + _re.escape(pkg) + r"/(\S+)")
    while _t.time() < deadline:
        r = subprocess.run(["adb", "-s", device.id, "shell", "dumpsys", "activity", "activities"],
                           capture_output=True, text=True)
        m = pat.search(r.stdout or "")
        if m and "splash" not in m.group(1).lower():
            return True
        _t.sleep(2)
    return False

def _ensure_running(device, pkg, tries=3, non_interactive=False, report=None):
    """attach-режим без перезапуска: вернуть pid ЖИВОГО процесса — между ключами
    приложение НЕ перезапускается, куча переиспользуется. Если процесс УПАЛ
    (форс сломал приложение) — поднять СВЕЖИМ (force-stop + LAUNCHER) и, если
    это интерактивный терминал, ПОПРОСИТЬ пользователя заново залогиниться и
    ввести пинкод (чтобы сессия восстановилась, а не терялась после краша), затем
    по Enter продолжить. Не-TTY (фон) — просто ждём инициализацию. None — не
    удалось поднять."""
    import subprocess, time as _t
    # Устройство офлайн (Genymotion подвис/ушёл) — force-stop/monkey по мёртвой VM
    # бессмысленны и УСУГУБЛЯЮТ фриз; пробуем мягко переподключить, не оживает —
    # сдаёмся быстро (None), чтобы не грид-фейлить 100 ключей по дохлой VM.
    def _online():
        r = subprocess.run(["adb", "devices"], capture_output=True, text=True)
        return any(device.id in ln and ln.split()[-1] == "device"
                   for ln in (r.stdout or "").splitlines() if ln.split())
    if not _online():
        for _ in range(5):
            subprocess.run(["adb", "disconnect", device.id], capture_output=True, text=True)
            subprocess.run(["adb", "connect", device.id], capture_output=True, text=True)
            _t.sleep(3)
            if _online():
                break
        else:
            return None   # VM мертва — ручной рестарт (adb не оживляет фриз)
    pid = _pidof(device, pkg)
    if pid is not None:
        # Уже запущен — но мог быть только что поднят (scan.sh шаг 6) и висеть на
        # сплеше/деоптимизации: форс в этот момент роняет сессию. Ждём основной
        # экран (мгновенно, если уже на нём).
        _wait_past_splash(device, pkg)
        return pid                               # нашли живой процесс — не перезапускали
    if report is not None:
        report["relaunched"] = True              # дальше — поднимаем свежим (cold после краха)
    interactive = bool(getattr(sys.stdin, "isatty", lambda: False)())
    for _ in range(tries):
        subprocess.run(["adb", "-s", device.id, "shell", "am", "force-stop", pkg],
                       capture_output=True, text=True)
        subprocess.run(["adb", "-s", device.id, "shell", "monkey", "-p", pkg,
                        "-c", "android.intent.category.LAUNCHER", "1"],
                       capture_output=True, text=True)
        _t.sleep(12)
        pid = _pidof(device, pkg)
        if pid is None:
            continue
        if interactive and not non_interactive:
            # приложение сломалось форсом и перезапущено — сессия/пинкод потеряны;
            # просим пользователя восстановить вручную, чтобы дальше ловить данные.
            try:
                input(f"\n[!] приложение {pkg} сломалось форс-вызовом и перезапущено.\n"
                      f"    Залогинься заново и введи пинкод в эмуляторе, затем нажми Enter "
                      f"для продолжения скана (Ctrl-C — прервать): ")
            except (EOFError, KeyboardInterrupt):
                pass
            pid = _pidof(device, pkg) or pid   # мог пересоздаться за время логина
        else:
            # Не-интерактив (Docker/CI): человека не ждём, но ждём выхода из сплеша/
            # деоптимизации — иначе attach+arm на раннем старте роняет сессию
            # ('script has been destroyed'). sleep 12 мало (unquickening vdex дольше).
            _wait_past_splash(device, pkg)
            _t.sleep(4)   # добор на DI/стабилизацию
        return pid
    return None

def activate_on_device(dx_provider, pkg, backend, wait_t, manual_path=None, paths=None, skip_dx=False, plans=None, recurse_args=False, attach=False, non_interactive=False, seed_path=None):
    """Возвращает namespace(run_key, preflight), замкнутый на пакет и Frida-сессию.
    dx_provider() лениво отдаёт androguard dx (загрузка 138MB APK ~130с) — зовётся
    только когда dx реально нужен (валидация overrides/fields, smali для openai-
    промпта). Для manual call_retrofit dx не нужен → APK не грузится (иначе прогон
    упирается в тяжёлую androguard-загрузку).
    import frida/trace здесь, а не на верху модуля — offline-пути должны работать
    без установленного frida."""
    import frida, time, trace, signal
    # Карта параметров из шага сбора (trace.py --params): листья name/val/url.
    # Сеется в pool агента ОДИН раз после загрузки (дополняет пассивный harvest).
    seed_items = []
    if seed_path and Path(seed_path).exists():
        for line in Path(seed_path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try: seed_items.append(json.loads(line))
                except Exception: pass
        print(f"[seed] карта параметров: {len(seed_items)} записей из {seed_path}", file=sys.stderr)
    _me = {}
    def me(cls, kind, name, sig):
        if skip_dx:                              # без DEX-валидации (кривой член упадёт на устройстве)
            return True
        if "f" not in _me:
            _me["f"] = dex_member_exists(dx_provider())
        return _me["f"](cls, kind, name, sig)
    device = trace.pick_device(None)
    import threading, types
    # _SETTLE даёт Retrofit построить прокси ДО arm (иначе call_retrofit не найдёт
    # инстанс) и служит ОКНОМ HARVEST (б2b): залогиненное приложение на старте
    # рефрешит токен, грузит профиль/устройства — реальные значения попадают в
    # harvest-пул агента ещё до форс-вызова, и patchForced наполняет ими поля. §4.8.
    _SETTLE = 4.0

    def _plan_for(rec, stage):
        """План ступени (offline, без устройства) + список проблем валидации."""
        if backend == "plans":
            plan = (plans or {}).get(rec["key"])  # готовый план на ключ (напр. от субагента)
            if not isinstance(plan, dict) or plan.get("stage") != stage:
                return plan, ["нет плана для этой ступени"]
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
        return plan, validate_plan(plan, me)

    def _open(pid, on_message):
        """attach+load+settle ОДИН раз. attach: к уже поднятому pid; spawn: холодный
        старт. Возвращает (session, pid, agent). ТОЛЬКО activate.js: он кэширует
        прокси, несёт key-exact оракул ({t:'retrofit',cls,m}) и снимает запрос;
        hook.js НЕ грузим — двойной хук Proxy.newProxyInstance роняет приложение."""
        if attach:
            # Гонка: форс уронил приложение, _ensure_running вернул pid, но процесс
            # исчез к моменту attach (frida.ProcessNotFoundError). Переподнимаем и
            # повторяем — иначе одна такая гонка роняет ВЕСЬ прогон (было на ключе 14).
            session = None
            for _ in range(3):
                try:
                    session = device.attach(pid); break
                except frida.ProcessNotFoundError:
                    pid = _ensure_running(device, pkg, non_interactive=non_interactive)
                    if pid is None:
                        raise
            if session is None:
                session = device.attach(pid)   # последняя попытка (пробросит реальную ошибку)
        else:
            pid = device.spawn([pkg])
            session = device.attach(pid)
        agent = session.create_script(_agent("activate.js").read_text(encoding="utf-8"))
        if on_message:
            agent.on("message", on_message)
        agent.load()
        if seed_items:
            try:
                n = agent.exports_sync.seed_pool(seed_items)
                print(f"[seed] засеяно в pool: {n}", file=sys.stderr)
            except Exception as e:
                print(f"[seed] seedPool не удался: {e}", file=sys.stderr)
        if not attach:
            device.resume(pid)
        time.sleep(_SETTLE)   # иначе okhttp/build-хук не успевает встать (проверено)
        return session, pid, agent

    def preflight():
        """Case 1: доступен ли сам Retrofit? stage-0 mintProxies минтит прокси ТОЛЬКО
        через retrofit2.Retrofit.create() (имя класса захардкожено в agent). Если R8
        обфусцировал библиотеку Retrofit (dodo: retrofit2.Retrofit → retrofit2.z/f0/
        ..., класс под этим именем не грузится), create() недостижим и ни один ключ
        не выстрелит. Проверяем ОДНИМ дешёвым probe'ом (без перебора ключей — он
        же и вис в прошлой версии) и падаем ДО молотьбы всего среза. Ключи dodo —
        сами по себе Retrofit-интерфейсы (аннотация @retrofit2.http.o), так что
        проверять isInterface бессмысленно; решает именно доступность Retrofit."""
        pid = _ensure_running(device, pkg, non_interactive=non_interactive) if attach else None
        if attach and pid is None:
            raise RuntimeError(f"preflight: процесс {pkg} не поднялся")
        session = None
        try:
            session, pid, agent = _open(pid, None)
            info = json.loads(agent.exports_sync.retrofit_probe())
        except frida.ProcessNotFoundError as e:
            # Устойчивая гонка attach на старте — preflight лишь оптимизация (fail-fast
            # на обфускации Retrofit). Не роняем прогон: цикл ключей сам покажет.
            print(f"[preflight] пропущен (гонка attach: {e})", file=sys.stderr)
            return
        finally:
            if session is not None:
                try: session.detach()
                except Exception: pass
            if pid is not None and not attach:
                try: device.kill(pid)
                except Exception: pass
        if not info.get("loadable"):
            raise RuntimeError(
                f"приложение {pkg}: класс retrofit2.Retrofit не загружается под этим "
                f"именем — библиотека Retrofit обфусцирована R8 (имена вида retrofit2.z/"
                f"f0/g0). stage-0 call_retrofit минтит прокси только через "
                f"retrofit2.Retrofit.create() → форс не выстрелит ни на одном ключе. "
                f"Деобфускация имени Retrofit-класса (heap-поиск по сигнатуре create()) "
                f"— отдельная задача.")
        return info

    def run_key_dev(rec, stages):
        """Одна Frida-сессия НА КЛЮЧ: attach+load агента ОДИН раз, затем arm всех
        ступеней на этом же скрипте (было: re-attach+re-load 741-КБ бандла на
        КАЖДУЮ ступень — 3× накладных). Семантику петли (перебор ступеней, break
        на real, терпимость к исключениям) переиспользуем из run_key."""
        stages = tuple(stages)
        session = pid = agent = None
        seen = {"hit": False, "req": None, "resp": None}

        def _on_hook_msg(message, data):
            # fired — асинхронный ключ-точный оракул (его ставит хендлер, когда
            # форс-вызов дёргает Proxy.invoke нужного cls->method); валиден даже
            # если приложение умерло до snapshot.
            if message.get("type") == "send":
                p = message.get("payload") or {}
                if _retrofit_hit(p, rec["key"]):
                    seen["hit"] = True
                # push-захват matched-запроса: приходит из captureRequest СРАЗУ при
                # снятии, спасает запрос, если процесс умрёт до snapshot()-RPC.
                if p.get("t") == "captured":
                    h = p.get("hit") or {}
                    if h.get("matched") and h.get("key") == rec["key"]:
                        seen["req"] = h
                # push-захват ОТВЕТА сервера на форс (оракул: статус + тело ошибки),
                # спасает ответ, если процесс умрёт до snapshot()-RPC.
                if p.get("t") == "captured_response" and p.get("key") == rec["key"]:
                    seen["resp"] = p.get("resp")

        # WATCHDOG-ПОТОК (не SIGALRM!): форс-вызов может заблокировать frida-RPC
        # (метод ушёл в бесконечный/блокирующий вызов) — синхронный arm() не
        # вернётся, а SIGALRM бессилен (Python не прерывает нативный frida-вызов).
        # По таймауту поток ПРИБИВАЕТ процесс → заблокированный RPC падает →
        # главный поток разблокируется. Бюджет масштабируем на число ступеней.
        _timedout = {"v": False}
        def _watchdog():
            _timedout["v"] = True
            # 1) убить процесс → заблокированный RPC падает (VM жива, завис только app).
            killed = False
            try:
                if pid is not None: device.kill(pid); killed = True
            except Exception: pass
            # 2) device.kill упал → устройство могло флапнуть в offline: переподключить
            # adb и повторить (оживляет флап, НЕ оживляет жёсткий фриз VM).
            if not killed and pid is not None:
                import subprocess as _sp
                _sp.run(["adb", "connect", device.id], capture_output=True, text=True)
                try: device.kill(pid)
                except Exception: pass
            # 3) detach тоже рвёт зависший arm()-RPC ('script destroyed'). ЖЁСТКИЙ фриз
            # VM посреди RPC здесь не лечится (device недостижим) — на этот случай
            # нужен ВНЕШНИЙ таймаут процесса (драйвер: subprocess timeout), не watchdog.
            try:
                if session is not None: session.detach()
            except Exception: pass
        _wd = threading.Timer(len(stages) * int(wait_t) + 45 + int(_SETTLE), _watchdog)

        # _ensure_running ДО watchdog: он может ждать ввода человека (логин+пинкод
        # после краха, если не non_interactive) неопределённо долго.
        _er = {}
        if attach:
            pid = _ensure_running(device, pkg, non_interactive=non_interactive, report=_er)
        setup_exc = []
        try:
            if attach and pid is None:
                raise RuntimeError(f"attach: процесс {pkg} не поднялся")
            _wd.start()                 # теперь таймаут накрывает attach/load/arm/snapshot
            session, pid, agent = _open(pid, _on_hook_msg)
        except Exception as e:
            setup_exc.append("session: " + str(e))

        def arm_stage(rec, stage):
            plan, probs = _plan_for(rec, stage)
            if probs:
                return {"stage": stage, "valid": False, "exceptions": probs,
                        "fired": False, "real_params": False, "request": None, "plan": plan}
            if agent is None:
                return {"stage": stage, "valid": False, "exceptions": setup_exc or ["нет сессии"],
                        "fired": False, "real_params": False, "request": None, "plan": plan}
            seen["hit"] = False   # оракул на ступень (captureOn чистит cap.hits — нет утечки снимка)
            seen["req"] = None    # push-захват на ступень
            res, snap, exc = {}, None, []
            try: agent.exports_sync.capture_on(rec["key"], (paths or {}).get(rec["key"], ""))
            except Exception as e: exc.append("capture_on: " + str(e))
            try: res = agent.exports_sync.arm(json.dumps(plan))
            except Exception as e: exc.append("arm: " + str(e))
            time.sleep(wait_t)
            try: snap = agent.exports_sync.snapshot()
            except Exception as e: exc.append("snapshot: " + str(e))
            fired = seen["hit"]
            # snapshot потерян (процесс умер до RPC), но push-захват успел — берём его
            if snap is None and seen["req"] is not None:
                snap = seen["req"]
            # ответ сервера-оракул: из snapshot или из push (если процесс умер)
            if snap is not None and not snap.get("response") and seen["resp"]:
                snap["response"] = seen["resp"]
            real = fired and _params_real(plan, snap, rec)
            exc = (res.get("exceptions", []) if isinstance(res, dict) else []) + exc
            if _timedout["v"]:
                exc.append("per-key timeout — форс завис, процесс прибит")
            return {"stage": stage, "valid": True, "exceptions": exc,
                    "fired": fired, "real_params": real, "request": snap, "plan": plan}

        try:
            out = run_key(rec, stages, arm_stage)
        finally:
            _wd.cancel()
            if session is not None:
                try: session.detach()
                except Exception: pass
            # attach: НЕ убивать — процесс переиспользуется между ключами (если его
            # не прибил watchdog); spawn: всегда убить холодный процесс.
            if pid is not None and not attach:
                try: device.kill(pid)
                except Exception: pass
        if _timedout["v"]:
            out["timeout"] = True
        if _er.get("relaunched"):
            # приложение было поднято свежим (после краха/первого ключа) → этот ключ
            # прогнан на ХОЛОДНОЙ куче; warm/логин-состояние потеряно (методологич.
            # неоднородность: холодный старт ⇒ часть feature-Retrofit'ов не создана).
            out["cold_after_crash"] = True
        return out

    return types.SimpleNamespace(run_key=run_key_dev, preflight=preflight)


def _has_real_data(url, body):
    """В запросе есть хоть один непустой РЕАЛЬНЫЙ лист данных: непустой query-
    параметр или непустое строковое/ненулевое числовое поле JSON-тела. Пустые
    строки, false, 0 и пустые контейнеры — не данные (наши болванки / пустой
    продюсер)."""
    from urllib.parse import urlparse, parse_qsl
    for _, v in parse_qsl(urlparse(url or "").query, keep_blank_values=True):
        if v.strip():
            return True
    if body and not body.strip().startswith("{") and "=" in body:
        # form-urlencoded тело (a=stub&b=stub) — частый не-JSON формат (ivi AuthApi)
        for _, v in parse_qsl(body, keep_blank_values=True):
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
    # Заглушка УЦЕЛЕЛА в запросе (не затёрта harvest) → тир (в), НЕ app-built.
    # Смотрим на факт снимка, а не на план: harvest-наполненное поле = реальное.
    if _has_stub_marker(snap.get("url", ""), snap.get("body", "")):
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
    # РЕГРЕССИЯ: план нёс $stub, но harvest затёр его реальным → тело без "stub" = б1
    # (раньше plan-stub ложно метил synth и прятал единственный harvest-win).
    assert _params_real({"args": [{"index": 0, "value": {"$stub": "Ljava/lang/String;"}}]},
                        {"url": "/x", "matched": True, "body": '{"code":"1111"}'}, obj_rec)
    # уцелевшая заглушка в теле → НЕ б1
    assert not _params_real({"args": [{"index": 0}]},
                            {"url": "/x", "matched": True, "body": '{"code":"stub"}'}, obj_rec)
    # path-параметр stub (/streams/stub) ловится маркером; реальный id — нет
    assert _has_stub_marker("/app/v1/download/streams/stub", "")
    assert not _has_stub_marker("/app/v1/download/streams/12345", "{}")
    print("  params_real ok")


def _honest_level(r):
    """Честный уровень ключа ПО ФАКТУ снимка (не по плану): ('б1'|'в'|'а', snap,
    stage). matched-снимок (url содержит endpoint; hint '/' отсечён в activate.js)
    + реальные непустые данные в query/теле → 'б1' app-built. Те же данные, но с
    нашей заглушкой ($stub в плане / маркер "stub" в теле) → 'в' synthesized.
    Иначе (не matched / тело пусто) → 'а'."""
    msnap = mstage = mplan = None
    for s in r.get("stages", []):
        rq = s.get("request") or {}
        if rq.get("url") and rq.get("matched"):
            msnap, mstage, mplan = rq, s.get("stage"), (s.get("plan") or {})
            break
    # НЕ matched снимок = чужой фоновый трафик, не наш форс-вызов: не выдаём его
    # за тело ключа (иначе отчёт лжёт — ivi приписывал pyrus/gettickets 22 ключам).
    if msnap is None:
        return ("а", None, None)
    url, body = msnap.get("url", "") or "", msnap.get("body", "") or ""
    if not _has_real_data(url, body):
        return ("а", msnap, mstage)
    # synth — ПО ФАКТУ запроса: уцелела ли наша заглушка. Поле, наполненное harvest
    # из карты/стора (←traffic/←store), заглушку в запросе затирает → это РЕАЛЬНЫЕ
    # данные (б1), а не synth, даже если план содержал $stub (иначе метрика прячет
    # ровно то, ради чего harvest и делался).
    synth = _has_stub_marker(url, body)
    return ("в" if synth else "б1", msnap, mstage)


def _has_stub_marker(url, body):
    """В ФАКТИЧЕСКОМ запросе уцелела наша $stub-заглушка: маркер "stub" в JSON-теле,
    или значение query-параметра == 'stub', или path-сегмент == 'stub' (GET с
    path-параметром: /streams/stub, /pop-up/stub), или form-поле == 'stub'. Если
    harvest заменил заглушку реальным значением — "stub" в запросе не останется, и
    это уже не synthesized (ключевой признак тира: смотрим на провод, не на план)."""
    if body and '"stub"' in body:
        return True
    from urllib.parse import urlparse, parse_qsl
    u = urlparse(url or "")
    if any(seg == "stub" for seg in u.path.split("/")):     # path-параметр: /streams/stub
        return True
    if any(v == "stub" for _, v in parse_qsl(u.query, keep_blank_values=True)):
        return True
    # form-urlencoded тело: значение параметра == 'stub' (наша $stub-String)
    if body and not body.strip().startswith("{") and "=" in body:
        return any(v == "stub" for _, v in parse_qsl(body, keep_blank_values=True))
    return False


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
    # matched = у ключа есть снимок с совпавшим endpoint (запрос РЕАЛЬНО ушёл на
    # нужный URL). Считаем по факту снимка, а НЕ как b1+synth: тело может быть
    # бинарным (protobuf/gRPC pivi-эндпоинты ivi) или пустым — запрос всё равно ушёл.
    def _matched(r):
        return any((s.get("request") or {}).get("matched") for s in r.get("stages", []))
    wire = sum(1 for r in results if _matched(r))
    def _filled_any(r, mark):
        return any(mark in f
                   for s in r.get("stages", []) for f in ((s.get("request") or {}).get("filled") or []))
    store_n = sum(1 for r in results if _filled_any(r, "←store:"))     # T3 сессия/uid/device
    traffic_n = sum(1 for r in results if _filled_any(r, "←traffic:"))  # T4 карта трафика
    # ЭТАП 1: почему ключ дошёл до Retrofit, но НЕ ушёл на провод. Классифицируем
    # по строкам исключений (бакеты — что чинить, чтобы поднять число отправленных).
    def _why_not_sent(r):
        blob = " ".join(e for s in r.get("stages", []) for e in (s.get("exceptions") or []))
        if "argument types do not match" in blob:               return "overload (типы аргументов не совпали)"
        if ("CoroutineSingletons" in blob or "ExecutorCallbackCall" in blob
                or "Continuation" in blob):                      return "suspend/Call не исполнен"
        if ("Unable to create" in blob or "converter" in blob
                or "ServiceMethod" in blob):                     return "Retrofit converter"
        if "NullPointer" in blob or "checkNotNull" in blob:      return "NPE (null в non-null)"
        if "script has been destroyed" in blob:                 return "краш процесса"
        if r.get("timeout"):                                     return "таймаут (форс завис)"
        return "без исключения / прочее"
    not_sent = [r for r in results if r.get("reached") and not _matched(r)]
    why = Counter(_why_not_sent(r) for r in not_sent)
    # ОРАКУЛ: ответ сервера на форс-вызов. accepted = 2xx (сервер принял тело как
    # валидное); rejected = 4xx/5xx (чаще всего называет недостающий/невалидный
    # параметр). Это и есть «качество активации» — не «сформировали», а «приняли».
    def _resp(r):
        for s in r.get("stages", []):
            rq = s.get("request") or {}
            if rq.get("matched") and rq.get("response"):
                return rq["response"]
        return None
    resps = [(r["key"].split("->")[-1], _resp(r)) for r in results if _resp(r)]
    L = [f"Всего скрытых запросов (ключей): {n}",
         "",
         "══ ЭТАП 1 — ДОСТАВКА (сколько доведено до бэкенда; заглушки допустимы) ══",
         f"  ушло на провод (matched):       {wire}/{n}",
         f"  дошло до Retrofit, но НЕ ушло:   {len(not_sent)}/{n}" + ("  — причины:" if why else ""),]
    for name, c in why.most_common():
        L.append(f"       {c:>3}  {name}")
    L += [f"  не дошло до Retrofit:            {n - reached}/{n}",
         "",
         "══ ЭТАП 2 — РЕАЛИЗАЦИЯ (из ушедших — с какими данными) ══",
         f"  (б1) реальные данные на проводе:  {b1}/{wire}",
         f"  (в)  уцелела заглушка ($stub):    {synth}/{wire}",
         f"  (а)  тело пустое/бинарное:        {wire - b1 - synth}/{wire}",
         "  источник реальных (наполнено ≥1 поле; T0–T2 без маркера — считаем остатком):",
         f"       T4 harvest (карта трафика):  {traffic_n}",
         f"       T3 стор (сессия/uid/device): {store_n}",
         "",
         f"ОТВЕТ СЕРВЕРА снят (сырая улика, толкует человек/агент): {len(resps)}/{wire}",
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
    if resps:
        rd = [f"  [{x.get('status')}] {k}: {(x.get('body') or '')[:160]}" for k, x in resps]
        L += ["", "ОТВЕТЫ СЕРВЕРА (сырая улика — status + тело, без механического вердикта):"] + rd
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
    # phi: берём первую НЕ-$stub ветку (реальную), игнорируя stub-альтернативу
    rp = {"arg_types": ["Ljava/lang/String;"], "arg_recipes": {},
          "arg_sources": [{"index": 0, "source": {"k": "phi", "alts": [
              {"k": "param", "index": 1},                 # user-input ветка -> $stub
              {"k": "const", "value": "real"}]}}]}         # реальная ветка -> берём её
    assert _args_from_sources(rp)[0]["value"] == "real", _args_from_sources(rp)[0]["value"]
    # phi из одних stub-веток -> $stub (нечего взять)
    rp2 = {"arg_types": ["Ljava/lang/String;"], "arg_recipes": {},
           "arg_sources": [{"index": 0, "source": {"k": "phi", "alts": [
               {"k": "param", "index": 1}, {"k": "unknown", "reason": "op:x"}]}}]}
    assert _args_from_sources(rp2)[0]["value"] == {"$stub": "java.lang.String"}, _args_from_sources(rp2)[0]["value"]
    # const 0 в ОБЪЕКТНЫЙ слот = null-загрузка (const/4 v,#0) -> типизированная
    # болванка, НЕ целое 0 (регрессия catalogFeedsCardgroup: 0 на java.lang.String
    # ломал подбор перегрузки → запрос не уходил)
    rc0 = {"arg_types": ["Ljava/lang/String;"], "arg_recipes": {},
           "arg_sources": [{"index": 0, "source": {"k": "const", "value": 0}}]}
    assert _args_from_sources(rc0)[0]["value"] == {"$stub": "java.lang.String"}, _args_from_sources(rc0)[0]["value"]
    # const-string в String-слот -> литерал; const int в примитивный слот -> как есть
    rc1 = {"arg_types": ["Ljava/lang/String;"], "arg_recipes": {},
           "arg_sources": [{"index": 0, "source": {"k": "const", "value": "x"}}]}
    assert _args_from_sources(rc1)[0]["value"] == "x"
    rc2 = {"arg_types": ["I"], "arg_recipes": {},
           "arg_sources": [{"index": 0, "source": {"k": "const", "value": 5}}]}
    assert _args_from_sources(rc2)[0]["value"] == 5
    # const-class литерал в слот java.lang.Class → $class (ivi getFieldsParameter)
    rc3 = {"arg_types": ["Ljava/lang/Class;"], "arg_recipes": {},
           "arg_sources": [{"index": 0, "source": {"k": "const", "value": "Lru/ivi/models/Broadcast;"}}]}
    assert _args_from_sources(rc3)[0]["value"] == {"$class": "ru.ivi.models.Broadcast"}, \
        _args_from_sources(rc3)[0]["value"]
    # тот же литерал в String-слот НЕ class-ифицируется ($class только в Class-контексте)
    rc4 = {"arg_types": ["Ljava/lang/String;"], "arg_recipes": {},
           "arg_sources": [{"index": 0, "source": {"k": "const", "value": "Lru/ivi/models/Broadcast;"}}]}
    v4 = _args_from_sources(rc4)[0]["value"]
    assert not (isinstance(v4, dict) and "$class" in v4), v4
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
    assert "(б1) реальные данные на проводе:  1/3" in txt and "уцелела заглушка" in txt
    assert "ушло на провод (matched):       3/4" in txt           # a,b,c matched; d — нет
    assert "не дошло до Retrofit:            1/4" in txt           # d не reached
    assert "ЭТАП 1" in txt and "ЭТАП 2" in txt
    assert "RQ3" in txt and "несопостав" in txt.lower()
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
    ap.add_argument("--all-reached", action="store_true",
                    help="активировать ВСЕ достижимые скрытые ключи (сканер), а не только "
                         "activation_exact — ступень 0 зовёт метод напрямую, точный путь не нужен")
    ap.add_argument("--seed", type=Path,
                    help="карта параметров из trace.py (--params): листья трафика для "
                         "наполнения скрытых запросов реальными значениями вместо $stub")
    ap.add_argument("--recurse-args", action="store_true",
                    help="stage0: аргументы рекурсивно из arg_sources, $stub на user-input листьях (тир synthesized)")
    ap.add_argument("--stages", default="0,1,2",
                    help="ступени форса через запятую (0=прямой Retrofit, 1=invoke "
                         "вызывающего, 2=frontier). Ступени 1/2 исполняют код приложения "
                         "и могут ронять процесс — для устойчивого скана reachability "
                         "ставь --stages 0")
    ap.add_argument("--non-interactive", action="store_true",
                    help="после краха форсом не ждать логина человека (Docker/CI): "
                         "поднять приложение свежим и продолжить")
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
    elif args.all_reached:
        # сканер: ступень 0 (call_retrofit) минтит прокси и зовёт метод напрямую —
        # работает для ЛЮБОГО достижимого ключа, не только activation_exact.
        recs = [r for r in recs if r.get("reached")]
    else:
        # research-подвыборка: только ключи с точным минимальным путём (Таблица IV).
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
                # Обрезаем путь до первого path-параметра {slug}/{id}: литерал
                # "{slug}" в реальном URL не встретится, и matched был бы ложно
                # False, хотя запрос пойман (напр. /uma-api/.../cardgroup_info/{slug}
                # → префикс /uma-api/.../cardgroup_info/ матчит реальный .../stub).
                paths.setdefault(h["key"], h["path"].split("{", 1)[0])
    plans = {}
    if args.plans_file and args.plans_file.exists():
        plans = json.loads(args.plans_file.read_text(encoding="utf-8"))
    runner = activate_on_device(dx_provider, pkg, args.backend, args.wait, args.manual_plan,
                                paths, args.skip_dx, plans, args.recurse_args, args.attach,
                                args.non_interactive, args.seed)
    total = len(recs)
    print(f"[активация] ключей к вызову: {total}", file=sys.stderr)
    # Case-1: mech/stage-0 (call_retrofit) минтит прокси через retrofit2.Retrofit.
    # Если библиотека Retrofit обфусцирована (dodo), форс не выстрелит ни на одном
    # ключе — падаем ДО молотьбы всего среза с понятной ошибкой.
    if args.backend == "mech":
        runner.preflight()
    _mark = {"б1": "реальные app-данные", "в": "наполнено заглушками", "а": "достижим (тело пусто/болванка)"}
    # Инкрементальная запись: результат по каждому ключу дописываем в .jsonl сразу
    # и флашим. Внешний обрыв (SIGTERM/docker stop/закрытая вкладка — активация
    # всех ключей идёт ~30 мин) НЕ стирает весь прогон: в .jsonl остаётся всё, что
    # успели, отчёт пересобираем из него. _finalize закрывает файл и пишет отчёт.
    outf = None
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        outf = args.out.open("w", encoding="utf-8")

    def _finalize():
        if outf and not outf.closed:
            try: outf.flush(); outf.close()
            except Exception: pass
        txt = report(results)
        if args.out:
            try: args.out.with_suffix(".report.txt").write_text(txt, encoding="utf-8")
            except Exception: pass
        return txt

    # По SIGTERM/SIGINT: сохранить частичный отчёт и выйти (os._exit, без frida-
    # teardown — тот может висеть). .jsonl уже дописан по ключам, так что данные
    # целы даже если сигнал пришёл во время нативного frida-RPC (обработчик тогда
    # отработает только по его возврату — но терять уже нечего).
    import signal
    def _on_signal(signum, _frame):
        sys.stderr.write(f"\n[активация] сигнал {signum} — сохраняю частичный результат "
                         f"({len(results)}/{total}) и выхожу\n")
        _finalize()
        os._exit(128 + signum)
    for _s in (signal.SIGTERM, signal.SIGINT):
        try: signal.signal(_s, _on_signal)
        except Exception: pass

    _stages = tuple(int(x) for x in str(args.stages).split(",") if x.strip() != "")
    for i, r in enumerate(recs, 1):
        try:
            res = runner.run_key(r, _stages)
        except Exception as e:
            # Изоляция ключа: катастрофа внутри run_key_dev (напр. _ensure_running
            # до внутреннего try, флап adb → ValueError в _pidof) НЕ должна ронять
            # весь прогон — синтезируем запись-ошибку и идём дальше (jsonl цел).
            res = {"key": r["key"], "reached": False, "activated_real": False,
                   "min_stage": None, "stages": [{"stage": _stages[0] if _stages else 0,
                   "valid": False, "exceptions": [f"run_key fatal: {e}"],
                   "fired": False, "real_params": False, "request": None}]}
        results.append(res)
        if outf:
            outf.write(json.dumps(res, ensure_ascii=False) + "\n"); outf.flush()
        fired = any(s.get("fired") for s in res.get("stages", []))
        lvl = _honest_level(res)[0]
        print(f"  [{i}/{total}] {r['key'].split('->')[-1]}: "
              f"{'вызван' if fired else 'НЕ вызван'}"
              f"{' / ' + _mark.get(lvl, '') if fired else ''}", file=sys.stderr)
    txt = _finalize()
    print(txt)


if __name__ == "__main__":
    main()
