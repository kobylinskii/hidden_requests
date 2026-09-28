#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Статический обратный срез скрытых HTTP-запросов.

Для каждого ключа `fqcn->method` из hidden.jsonl: call-sites (XREF), обратный
межпроцедурный обход до фронтира, управляющие стражи на пути и источники
аргументов. Гибрид androguard + networkx; алгоритмика отделена от androguard и
проверяется на синтетике (--selfcheck). Дизайн: docs/.../2026-09-28-...-design.md
"""
import argparse
import json
import re
import sys
from collections import namedtuple
from pathlib import Path

from loguru import logger
logger.remove()  # androguard DEBUG-флуд — до его импорта
import networkx as nx

Insn = namedtuple("Insn", "op out args")


def _kind_of(ins):
    """Категория источника по мнемонике инструкции. Префиксное сравнение (не
    exact-match): Task 3 положит в op СЫРУЮ мнемонику androguard
    (ins.get_name()), а у Dalvik куча суффиксных вариантов одной операции
    (const/4, const-string, iget-object, move-result-object, ...)."""
    if ins.op.startswith("const"):
        return ("const", ins.args[0] if ins.args else None)
    if ins.op.startswith(("iget", "sget")):
        return ("field", ins.args[0] if ins.args else None)
    if ins.op.startswith("move-result"):
        return ("invoke", ins.args[0] if ins.args else None)
    return ("unknown", None)


def classify_operand(cfg, block, use_pos, reg, params):
    """Обратный def-use по reg от use_pos внутри block, затем в единственного
    предшественника. >=2 предшественников без локального def -> unknown, кроме
    параметров (они доминируют все блоки). ponytail: глубина один хоп."""
    b, start, seen = block, use_pos - 1, set()
    while True:
        insns = cfg.nodes[b]["insns"]
        for i in range(min(start, len(insns) - 1), -1, -1):
            if insns[i].out == reg:
                return _kind_of(insns[i])
        if b in seen:
            return ("param", params[reg]) if reg in params else ("unknown", None)
        seen.add(b)
        preds = list(cfg.predecessors(b))
        if len(preds) == 1:
            b = preds[0]
            start = len(cfg.nodes[b]["insns"]) - 1
            continue
        return ("param", params[reg]) if reg in params else ("unknown", None)


def post_idom(cfg, exit_node):
    """Непосредственные пост-доминаторы = idom на реверснутом CFG с корнем exit.
    Узлы, не достигающие exit (бесконечные циклы), сначала соединяются с ним —
    иначе immediate_dominators их не покроет. ponytail: fallback-ребро, не полный
    разбор неприводимых циклов."""
    g = cfg.copy()
    reach = nx.ancestors(g, exit_node) | {exit_node}
    for n in list(g.nodes):
        if n not in reach:
            g.add_edge(n, exit_node)
    return nx.immediate_dominators(g.reverse(copy=True), exit_node)


def control_deps(cfg, criterion, exit_node):
    """Транзитивный набор (ветвление, ведущий-преемник), от которых criterion
    управляемо зависим (Ferrante-Ottenstein-Warren, замкнуто транзитивно)."""
    ipdom = post_idom(cfg, exit_node)

    def direct(node):
        out = []
        for a in cfg.nodes:
            succ = list(cfg.successors(a))
            if len(succ) < 2:
                continue
            stop = ipdom.get(a)
            for b in succ:
                n, seen = b, []
                while n is not None and n != stop:
                    seen.append(n)
                    n = ipdom.get(n)
                if node in seen:
                    out.append((a, b))
        return out

    # result — set из (branch, taken), не dict по branch: узел может быть
    # зависим сразу от НЕСКОЛЬКИХ рёбер одного switch/when-ветвления (3+
    # successors) — это разные прямые зависимости, а не альтернативы друг друга.
    result, work, seen_branches = set(), [criterion], set()
    while work:
        cur = work.pop()
        for a, b in direct(cur):
            result.add((a, b))
            if a not in seen_branches:
                seen_branches.add(a)
                work.append(a)
    return list(result)


def _check_control_deps():
    import networkx as nx
    # прямая линия: стражей нет
    g = nx.DiGraph([("A", "X")])
    assert control_deps(g, "A", "X") == []

    # ромб: A(if)->{B,C}, B->M, C->M, M->X ; B зависим от A, M — нет
    g = nx.DiGraph([("A","B"),("A","C"),("B","M"),("C","M"),("M","X")])
    assert control_deps(g, "B", "X") == [("A","B")]
    assert control_deps(g, "M", "X") == []

    # вложенность: A(if)->{B,C}; B->D(if)->{E,F}; E->H;F->H;C->H;H->X
    g = nx.DiGraph([("A","B"),("A","C"),("B","D"),("D","E"),("D","F"),
                    ("E","H"),("F","H"),("C","H"),("H","X")])
    deps = dict(control_deps(g, "E", "X"))
    assert deps == {"A": "B", "D": "E"}, deps  # транзитивно: E<-D<-A

    # петля без выхода к X у тела: не падает, тело зависимо от условия петли
    g = nx.DiGraph([("E","L"),("L","BODY"),("L","AFTER"),("BODY","L"),("AFTER","X")])
    deps = dict(control_deps(g, "BODY", "X"))
    assert deps == {"L": "BODY"}, deps

    # switch/when: A(3 ветви)->{B,C,D}; B->M,C->M (сходятся до ipdom(A)), D->Z
    # напрямую; M зависим от ОБОИХ рёбер (A,B) и (A,C), но не от (A,D)
    g = nx.DiGraph([("A","B"),("A","C"),("A","D"),("B","M"),("C","M"),
                    ("M","Z"),("D","Z"),("Z","X")])
    got = set(control_deps(g, "M", "X"))
    assert got == {("A","B"),("A","C")}, got
    print("  control_deps ok")


def _check_classify_operand():
    import networkx as nx

    def one_block(insns, params=None):
        g = nx.DiGraph(); g.add_node("B", insns=insns)
        return g, "B", params or {}

    # const
    g,b,p = one_block([Insn("const","v0",(1,)), Insn("other",None,())])
    assert classify_operand(g,b,1,"v0",p) == ("const",1)
    # поле (фича-флаг)
    g,b,p = one_block([Insn("iget","v0",("Foo->enabled",)), Insn("other",None,())])
    assert classify_operand(g,b,1,"v0",p) == ("field","Foo->enabled")
    # возврат метода (move-result несёт сигнатуру callee, спаренную адаптером)
    g,b,p = one_block([Insn("move-result","v0",("Bar->isLoggedIn()Z",)), Insn("other",None,())])
    assert classify_operand(g,b,1,"v0",p) == ("invoke","Bar->isLoggedIn()Z")
    # параметр: нет записи, reg — параметр
    g,b,p = one_block([Insn("other",None,())], params={"p1":0})
    assert classify_operand(g,b,0,"p1",p) == ("param",0)
    # phi-подобное: два предшественника пишут v0, локально нет def, не параметр
    g = nx.DiGraph()
    g.add_node("P1", insns=[Insn("const","v0",(1,))])
    g.add_node("P2", insns=[Insn("const","v0",(2,))])
    g.add_node("B",  insns=[Insn("other",None,())])
    g.add_edge("P1","B"); g.add_edge("P2","B")
    assert classify_operand(g,"B",0,"v0",{}) == ("unknown",None)
    print("  classify_operand ok")


def _selfcheck():
    _check_control_deps()
    _check_classify_operand()
    print("selfcheck ok")


if __name__ == "__main__":
    if "--selfcheck" in sys.argv:
        _selfcheck()
        sys.exit(0)
