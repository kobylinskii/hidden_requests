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
from pathlib import Path

from loguru import logger
logger.remove()  # androguard DEBUG-флуд — до его импорта
import networkx as nx


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


def _selfcheck():
    _check_control_deps()
    print("selfcheck ok")


if __name__ == "__main__":
    if "--selfcheck" in sys.argv:
        _selfcheck()
        sys.exit(0)
