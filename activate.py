#!/usr/bin/env python3
"""Forced activation of hidden HTTP requests via Frida."""

import json, sys, os, argparse
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

    print("  validate_plan ok")


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


def _selfcheck(apk=None):
    _check_validate_plan()
    _check_real_guards()
    _check_build_prompt()
    if apk is not None:
        if load_apk is None:
            raise RuntimeError("slice module not available; cannot test with real APK")
        apk_obj, dx = load_apk(apk)
        _check_dex_member_exists(dx)
        _check_method_smali(dx)
    print("все проверки activate.py прошли")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selfcheck", action="store_true")
    ap.add_argument("--apk", help="APK path for DEX-gated tests (slow, ~130s)")
    args = ap.parse_args()
    if args.selfcheck:
        _selfcheck(apk=args.apk)


if __name__ == "__main__":
    main()
