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


def _selfcheck(apk=None):
    _check_validate_plan()
    if apk is not None:
        if load_apk is None:
            raise RuntimeError("slice module not available; cannot test with real APK")
        apk_obj, dx = load_apk(apk)
        _check_dex_member_exists(dx)
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
