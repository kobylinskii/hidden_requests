#!/usr/bin/env python3
"""Forced activation of hidden HTTP requests via Frida."""

import json, sys, os, argparse
from pathlib import Path

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
    st = plan["stage"]
    if st not in _STAGE_KINDS:
        probs.append(f"stage={st!r} не из {sorted(_STAGE_KINDS)}")
    trig = plan.get("trigger") or {}
    if st in _STAGE_KINDS and trig.get("kind") != _STAGE_KINDS[st]:
        probs.append(f"trigger.kind={trig.get('kind')!r} не соответствует stage={st}")
    for ov in plan["overrides"]:
        if not member_exists(ov["cls"], "method", ov["method"], ov["sig"]):
            probs.append(f"override: нет метода {ov['cls']}->{ov['method']}{ov['sig']}")
    for fl in plan["fields"]:
        if not member_exists(fl["cls"], "field", fl["name"], fl["sig"]):
            probs.append(f"field: нет поля {fl['cls']}->{fl['name']} {fl['sig']}")
    if trig.get("kind") in ("invoke", "trigger_entry"):
        if not member_exists(trig["cls"], "method", trig["method"], trig["sig"]):
            probs.append(f"trigger: нет метода {trig['cls']}->{trig['method']}{trig['sig']}")
    return probs

def dex_member_exists(dx):
    """member_exists поверх androguard dx. Сверяет имя И сигнатуру (R8-перегрузки)."""
    def me(cls, kind, name, sig):
        ca = dx.classes.get("L" + cls.replace(".", "/") + ";")
        if ca is None:
            return False
        if kind == "method":
            for ma in ca.get_methods():
                if ma.name == name and ma.descriptor.replace(" ", "") == sig.replace(" ", ""):
                    return True
            return False
        if kind == "field":
            for f in ca.get_fields():
                ef = f.get_field()
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
    print("  validate_plan ok")


def _selfcheck():
    _check_validate_plan()
    print("все проверки activate.py прошли")


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--selfcheck", action="store_true")
    args = ap.parse_args()
    if args.selfcheck:
        _selfcheck()


if __name__ == "__main__":
    main()
