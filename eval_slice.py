#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Оценка точности слайсера против ручной разметки (ground truth, RQ2).

1) pick_sample печатает N ключей для ручного разбора в JADX;
2) разметку кладём в truth.json: {key: [[kind, detail], ...]};
3) score сравнивает с slice.jsonl и печатает precision/recall.
"""
import argparse
import json
import random
from pathlib import Path


def pick_sample(keys, n=18, seed=42):
    """Детерминированная подвыборка ключей (без повторов, отсортирована)."""
    r = random.Random(seed)
    return sorted(r.sample(keys, min(n, len(keys))))


def _guards_of(rec):
    """Запись slice.jsonl -> множество стражей (source_kind, detail).

    Ruling-H (eval-сторона): считаем ТОЛЬКО реальные стражи — с пустым
    notes. Coroutine state-machine стражи (notes=["coroutine_state_machine"])
    исключены, как и в headline guard_count самой записи (Task 5) — иначе
    скоринг против этого шума обессмысливает precision/recall.
    """
    return {
        (g["operand"]["source_kind"], g["operand"]["detail"])
        for g in rec.get("guards", [])
        if not g["notes"]
    }


def score(pred, truth):
    """pred/truth: {key: set[(source_kind, detail)]} -> tp/fp/fn/precision/recall."""
    tp = fp = fn = 0
    for k in truth:
        p, t = pred.get(k, set()), truth[k]
        tp += len(p & t)
        fp += len(p - t)
        fn += len(t - p)
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": prec, "recall": rec}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--slice", type=Path, help="slice.jsonl для оценки")
    ap.add_argument("--truth", type=Path, help="ручная разметка truth.json")
    ap.add_argument("--hidden", type=Path, help="hidden.jsonl (формат diff.py) для --pick")
    ap.add_argument("--pick", action="store_true", help="напечатать выборку ключей для разметки")
    ap.add_argument("--selfcheck", action="store_true")
    a = ap.parse_args()
    if a.selfcheck:
        _check_scorer()
        print("selfcheck ok")
        return
    if a.pick:
        import slice as sl  # sibling module (запуск из new/)
        for k in pick_sample(sl.load_hidden(a.hidden)):
            print(k)
        return
    pred = {}
    for line in a.slice.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        pred[r["key"]] = _guards_of(r)
    truth = {k: {tuple(x) for x in v} for k, v in json.loads(a.truth.read_text(encoding="utf-8")).items()}
    print(json.dumps(score(pred, truth), indent=2, ensure_ascii=False))


def _check_scorer():
    pred = {"a->x": {("invoke", "S->isLoggedIn()Z")}, "b->y": set()}
    truth = {"a->x": {("invoke", "S->isLoggedIn()Z"), ("field", "F->on")}, "b->y": set()}
    s = score(pred, truth)
    assert s["tp"] == 1 and s["fn"] == 1 and s["fp"] == 0
    assert abs(s["recall"] - 0.5) < 1e-9 and s["precision"] == 1.0
    # _guards_of: coroutine-флагованный страж не должен попасть в pred-множество
    # (Ruling-H eval-сторона) — только запись с notes=[] считается реальной.
    rec = {
        "guards": [
            {"operand": {"source_kind": "invoke", "detail": "S->isLoggedIn()Z"}, "notes": []},
            {"operand": {"source_kind": "field", "detail": "TT->z I"}, "notes": ["coroutine_state_machine"]},
        ]
    }
    assert _guards_of(rec) == {("invoke", "S->isLoggedIn()Z")}
    print("  scorer ok")


if __name__ == "__main__":
    main()
