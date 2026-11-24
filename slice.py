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
from bisect import bisect_right
from collections import Counter, deque, namedtuple
from functools import lru_cache
from pathlib import Path

from loguru import logger
logger.remove()  # androguard DEBUG-флуд — до его импорта
import networkx as nx
from androguard.misc import AnalyzeAPK
from androguard.core.dex.dex_types import Operand

Insn = namedtuple("Insn", "op out args")
CALL_EDGE_EVIDENCE = frozenset({"dex_xref", "resolved_dispatch", "cha", "coroutine_resume",
                                "coroutine_launch", "allocation_xref"})


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
    if ins.op.startswith("new-instance"):  # инлайн-конструкция DTO — продюсер полей в <init>
        return ("new", ins.args[0] if ins.args else None)
    if ins.op == "instance-of":  # `if (r is Result.Error)` — сигнал Server/Error handling
        return ("instanceof", ins.args[0] if ins.args else None)
    return ("unknown", None)


def classify_operand(cfg, block, use_pos, reg, params):
    """Trace register moves and unambiguous definitions back from a use."""
    seen = set()
    while (block, use_pos, reg) not in seen:
        seen.add((block, use_pos, reg))
        definition, reason, _ = _def_insn(cfg, block, use_pos, reg)
        if definition is None:
            if reason == "no_pred" and reg in params:
                return "param", params[reg]
            break
        block, use_pos, ins = definition
        if ins.op.startswith(("move-result", "move-exception")) or not ins.op.startswith("move") or not ins.args:
            return _kind_of(ins)
        reg = ins.args[0]
    return "unknown", None


def post_idom(cfg, exit_node):
    """Непосредственные пост-доминаторы = idom на реверснутом CFG с корнем exit.
    Узлы, не достигающие exit (бесконечные циклы), сначала соединяются с ним —
    иначе immediate_dominators их не покроет. ponytail: fallback-ребро, не полный
    разбор неприводимых циклов."""
    g = cfg
    reach = nx.ancestors(cfg, exit_node) | {exit_node}
    if len(reach) != len(cfg):
        g = cfg.copy()
        g.add_edges_from((n, exit_node) for n in cfg if n not in reach)
    return nx.immediate_dominators(g.reverse(copy=False), exit_node)


def _direct_control_deps(cfg, exit_node):
    """Index direct dependencies once for all call sites in the method."""
    ipdom = post_idom(cfg, exit_node)
    direct = {}
    for a in cfg:
        if cfg.out_degree(a) < 2:
            continue
        for b in cfg.successors(a):
            n = b
            while n != ipdom[a] and n != exit_node:
                direct.setdefault(n, []).append((a, b))
                n = ipdom[n]
    return direct


def _control_closure(direct, criterion):
    # result — set из (branch, taken), не dict по branch: узел может быть
    # зависим сразу от НЕСКОЛЬКИХ рёбер одного switch/when-ветвления (3+
    # successors) — это разные прямые зависимости, а не альтернативы друг друга.
    result, work, seen_branches = set(), [criterion], set()
    while work:
        cur = work.pop()
        for a, b in direct.get(cur, ()):
            result.add((a, b))
            if a not in seen_branches:
                seen_branches.add(a)
                work.append(a)
    return list(result)


def control_deps(cfg, criterion, exit_node):
    """Transitive control dependencies for a CFG with an explicit exit."""
    return _control_closure(_direct_control_deps(cfg, exit_node), criterion)


def _guard_distances(weight, children, sink, *,
                    cha_uncertain=frozenset(), allocation_uncertain=frozenset(), missing_frames=(), routes=None):
    """Compute distances under the optimistic, allocation-tolerant and strict models.

    A stopped suffix can omit nonnegative weights upstream. A complete path
    additionally requires a recognized callback, resolved frames and direct
    caller edges all the way to the sink.
    """
    import heapq

    parents = {}
    for parent, targets in children.items():
        for target in targets:
            parents.setdefault(target, []).append(parent)

    def distances(blocked=None):
        dist = {sink: 0}
        next_frame = {}
        queue = [(0, 0, sink)]
        order = 0
        while queue:
            cost, _, node = heapq.heappop(queue)
            if cost != dist[node] or (blocked is not None and node in blocked):
                continue
            for parent in parents.get(node, ()):
                if blocked is not None and parent in missing_frames:
                    continue
                candidate = cost + weight.get(parent, 0)
                if candidate < dist.get(parent, float("inf")):
                    dist[parent] = candidate
                    next_frame[parent] = node
                    order += 1
                    heapq.heappush(queue, (candidate, order, parent))
        return dist, next_frame

    optimistic = distances()
    modulo = distances(cha_uncertain) if cha_uncertain or missing_frames else optimistic
    verified = distances(cha_uncertain | allocation_uncertain) if allocation_uncertain else modulo
    models = optimistic, modulo, verified
    if routes is not None:
        routes.extend(next_frame for _, next_frame in models)
    return tuple(dist for dist, _ in models)


def _guard_costs(distances, tops, frontier):
    optimistic, modulo, verified = distances
    lower = min((optimistic[n] for n in tops if n in optimistic), default=None)
    complete = min((verified[n] for n in frontier if n in verified), default=None)
    complete_modulo = min((modulo[n] for n in frontier if n in modulo), default=None)
    exact = complete is not None and complete == lower
    return lower, exact, complete, complete_modulo


def min_path_guards(weight, children, tops, frontier, sink, **options):
    return _guard_costs(_guard_distances(weight, children, sink, **options), tops, frontier)


def _check_cha():
    # фейковая иерархия: C extends B implements I; I.m и B.n объявлены.
    # xref проверяем через cha_caller_sites: вызывающий I.m() должен подтянуться
    # к C.m() (полиморфный invoke-interface), которого в прямом xref C.m() нет.
    class FMA:
        def __init__(self, name, desc, cls, callers=()):
            self.name, self.descriptor, self.class_name = name, desc, cls
            self._callers = callers
        def get_xref_from(self):
            return [(None, cma, off) for cma, off in self._callers]
        def get_method(self):
            return None
        def get_access_flags_string(self):
            return "public"
    class FCA:
        def __init__(self, ext, impl, methods, external=False):
            self.extends, self.implements, self._m, self._ext = ext, impl, methods, external
        def is_external(self): return self._ext
        def get_methods(self): return self._m
    caller = FMA("onCreate", "()V", "LA;")
    i_m = FMA("m", "()V", "LI;", callers=[(caller, 10)])      # вызывающий висит на I.m()
    c_m = FMA("m", "()V", "LC;")                               # у реализации прямого xref нет
    dx = type("DX", (), {})()
    dx.classes = {"LA;": FCA("Landroid/app/Service;", [], [caller]),
                  "LI;": FCA(None, [], [i_m], external=False),
                  "LB;": FCA("Ljava/lang/Object;", [], []),
                  "LC;": FCA("LB;", ["LI;"], [c_m])}
    def find_method(owner, name, desc):
        ca = dx.classes.get(owner)
        return next((m for m in ca.get_methods() if (m.name, m.descriptor) == (name, desc)), None) if ca else None
    dx.get_method_analysis_by_name = find_method
    _cha_supers.cache_clear()
    assert set(_cha_supers(dx, "LC;")) == {"LB;", "LI;"}, _cha_supers(dx, "LC;")
    sites, used, reason = cha_caller_sites(dx, c_m)
    assert reason is None
    assert used and (caller, 10) in sites, (sites, used)
    # у метода с прямым xref и без супертипов CHA ничего не добавляет
    _cha_supers.cache_clear()
    sites2, used2, reason = cha_caller_sites(dx, i_m)
    assert reason is None
    assert used2 is False and (caller, 10) in sites2, (sites2, used2)
    _caller_evidence.cache_clear()
    i_m._callers = [(caller, off) for off in range(_CHA_FANIN_CAP + 1)]
    assert cha_caller_sites(dx, c_m) == ([], False, "fanin_capped")

    hidden = FMA("post", "()V", "LApi;", callers=[(c_m, 4)])
    dx.classes["LApi;"] = FCA(None, [], [hidden])
    walk = backward_frames(dx, "Api", "post")
    assert walk["dead_end_nodes"] == {(id(c_m), 4)}
    assert walk["stop_reasons"] == {(id(c_m), 4): "fanin_capped"}
    leaf = FMA("save", "()V", "LB;")
    hidden._callers = [(c_m, 4), (leaf, 2)]
    notes = slice_key(dx, "Api->post")["notes"]
    assert {"dead_end", "dead_end:fanin_capped", "dead_end:no_callers"} <= set(notes)
    hidden._callers = [(c_m, 4)]
    _caller_evidence.cache_clear()
    i_m._callers = []
    assert cha_caller_sites(dx, c_m) == ([], False, "no_callers")
    c_m.name = "invoke"
    dx.classes["LC;"].get_xref_new_instance = lambda: [(caller, 8)]
    walk = backward_frames(dx, "Api", "post")
    assert walk["frontier_nodes"] == {(id(caller), 8)}
    assert not walk["dead_ends"] and not walk["stop_reasons"]
    print("  cha ok")


def _check_min_path():
    sink = "H"
    # ромб: вход E -> {A,B} -> C -> H; A несёт 2 стража, B — 0, C — 1.
    # дешёвый путь E-B-C-H = 0+0+1 = 1 страж.
    weight = {"E": 0, "A": 2, "B": 0, "C": 1, sink: 0}
    children = {"E": {"A", "B"}, "A": {"C"}, "B": {"C"}, "C": {sink}}
    assert min_path_guards(weight, children, {"E"}, {"E"}, sink) == (1, True, 1, 1)

    # оборванный путь дешевле фронтира: frontier F (1 страж) -> C(1) -> H,
    # dead_end D (0) -> C(1) -> H. Настоящий UI-путь = 2, но через D может быть 1
    # -> нижняя граница 1, лучший завершённый путь 2.
    weight = {"F": 1, "D": 0, "C": 1, sink: 0}
    children = {"F": {"C"}, "D": {"C"}, "C": {sink}}
    assert min_path_guards(weight, children, {"F", "D"}, {"F"}, sink) == (1, False, 2, 2)

    # ни один фронтир не дотянулся: только dead_end D(2)->C(1)->H -> нижняя оценка 3
    assert min_path_guards({"D": 2, "C": 1, sink: 0},
                           {"D": {"C"}, "C": {sink}}, {"D"}, set(), sink) == (3, False, None, None)

    # цикл в графе вызовов не зацикливает и не удешевляет: A<->B, A->H, оба по 1
    assert min_path_guards({"A": 1, "B": 1, sink: 0},
                           {"A": {"B", sink}, "B": {"A"}}, {"B"}, {"B"}, sink) == (2, True, 2, 2)
    weights = {"F": 0, "A": 1, "B": 0}
    edges = {"F": {"A"}, "A": {"B"}, "B": {sink}}
    opts = (weights, edges, {"F", "A"}, {"F"}, sink)
    assert min_path_guards(*opts, allocation_uncertain={"A"}) == (1, False, None, 1)
    assert min_path_guards(*opts, cha_uncertain={"B"}) == (1, False, None, None)
    assert min_path_guards(*opts, cha_uncertain={"B"}, allocation_uncertain={"A"}) == (1, False, None, None)
    print("  min_path ok")


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
    # new-instance -> ("new", type): инлайн-конструкция DTO
    g,b,p = one_block([Insn("new-instance","v0",("Lp/Dto;",)), Insn("other",None,())])
    assert classify_operand(g,b,1,"v0",p) == ("new","Lp/Dto;")
    print("  classify_operand ok")


def _check_ctor_args():
    """Статический продюсер полей: из инлайн-<init> DTO вытягиваются источники
    каждого ctor-аргумента (кто порождает поле тела запроса)."""
    import networkx as nx
    insns = [
        Insn("new-instance", "v0", ("Lp/Dto;",)),
        Insn("const", "v1", ("promo",)),                       # поле 0: литерал
        Insn("iget", "v2", ("Lp/Store;->token Ljava/lang/String;",)),  # поле 1: из поля-стора
        Insn("invoke-direct", None,
             ("Lp/Dto;-><init>(Ljava/lang/String;Ljava/lang/String;)V", "v0", "v1", "v2")),
        Insn("invoke-interface", None, ("Lp/Api;->send(Lp/Dto;)V", "v9", "v0")),
    ]
    g = nx.DiGraph(); g.add_node("B", insns=insns)
    fr = {"cfg": g, "params": {}}
    ca = _ctor_args_of(fr, "B", 4, "v0", "Lp/Dto;")
    assert ca == [{"index": 0, "source_kind": "const", "detail": "promo"},
                  {"index": 1, "source_kind": "field", "detail": "Lp/Store;->token Ljava/lang/String;"}], ca
    # РЕКУРСИЯ: поле DTO = результат вызова продюсера, чей аргумент — const →
    # дерево new → invoke(args=[const]); поле 1 — param (user-input лист)
    insns2 = [
        Insn("new-instance", "v0", ("Lp/Dto;",)),
        Insn("const", "v3", ("seed",)),
        Insn("invoke-static", None, ("Lp/F;->mk(Ljava/lang/String;)Lp/X;", "v3")),
        Insn("move-result", "v1", ("Lp/F;->mk(Ljava/lang/String;)Lp/X;",)),  # поле0 = mk(seed)
        Insn("invoke-direct", None, ("Lp/Dto;-><init>(Lp/X;Ljava/lang/String;)V", "v0", "v1", "p5")),
        Insn("invoke-interface", None, ("Lp/Api;->send(Lp/Dto;)V", "v9", "v0")),
    ]
    g2 = nx.DiGraph(); g2.add_node("B", insns=insns2)
    fr2 = {"cfg": g2, "params": {"p5": 1}}
    t = _resolve_source(fr2, "B", 5, "v0")
    assert t["k"] == "new" and t["type"] == "Lp/Dto;", t
    assert t["ctor_args"][0] == {"k": "invoke", "detail": "Lp/F;->mk(Ljava/lang/String;)Lp/X;",
                                 "args": [{"k": "const", "value": "seed"}]}, t["ctor_args"][0]
    assert t["ctor_args"][1] == {"k": "param", "index": 1}, t["ctor_args"][1]  # user-input лист
    print("  ctor_args ok")


def _check_alias():
    """Алиас-трекинг: аргумент, пришедший через move-object (копия регистра) или
    check-cast (приведение на месте), раскручивается до исходного продюсера, а не
    теряется в unknown."""
    import networkx as nx
    insns = [
        Insn("const", "v2", ("tok",)),                       # v2 = "tok"
        Insn("move-object", "v0", ("v2",)),                  # v0 = v2 (АЛИАС копии)
        Insn("invoke-static", None, ("Lp/F;->mk()Lp/X;",)),
        Insn("move-result", "v3", ("Lp/F;->mk()Lp/X;",)),    # v3 = mk()
        Insn("check-cast", None, ("v3",)),                   # (X) v3 — прозрачно (out=None)
        Insn("invoke-interface", None,
             ("Lp/Api;->send(Ljava/lang/String;Lp/X;)V", "v9", "v0", "v3")),
    ]
    g = nx.DiGraph(); g.add_node("B", insns=insns)
    fr = {"cfg": g, "params": {}}
    # arg через move-object → раскрутка до литерала (без фикса было unknown)
    assert _resolve_source(fr, "B", 5, "v0") == {"k": "const", "value": "tok"}, \
        _resolve_source(fr, "B", 5, "v0")
    # arg через check-cast → раскрутка до вызова-продюсера (cast прозрачен)
    t = _resolve_source(fr, "B", 5, "v3")
    assert t["k"] == "invoke" and t["detail"] == "Lp/F;->mk()Lp/X;", t
    # цепочка move→move→const тоже доходит до листа (сквозной def-use)
    insns2 = [
        Insn("const", "v5", ("deep",)),
        Insn("move-object", "v4", ("v5",)),
        Insn("move-object", "v1", ("v4",)),
        Insn("invoke-interface", None, ("Lp/Api;->p(Ljava/lang/String;)V", "v9", "v1")),
    ]
    g2 = nx.DiGraph(); g2.add_node("B", insns=insns2)
    assert _resolve_source({"cfg": g2, "params": {}}, "B", 3, "v1") == {"k": "const", "value": "deep"}
    print("  alias ok")


def _check_phi():
    """phi-раскрутка: reg, определённый в разных ветках (merge ≥2 предшественников),
    собирается в phi-узел с альтернативами; сходящиеся ветки схлопываются в один лист."""
    import networkx as nx
    # ромб: A (ветвление) → T|F (разные const в v0) → M (использование в вызове)
    def diamond(tval, fval):
        g = nx.DiGraph()
        g.add_node("A", insns=[Insn("if-eqz", None, ("v9",))])
        g.add_node("T", insns=[Insn("const", "v0", (tval,))])
        g.add_node("F", insns=[Insn("const", "v0", (fval,))])
        g.add_node("M", insns=[Insn("invoke-interface", None,
                                    ("Lp/Api;->send(Ljava/lang/String;)V", "v9", "v0"))])
        g.add_edge("A", "T"); g.add_edge("A", "F"); g.add_edge("T", "M"); g.add_edge("F", "M")
        return {"cfg": g, "params": {}}
    # расходящиеся ветки → phi с двумя альтернативами
    t = _resolve_source(diamond("x", "y"), "M", 0, "v0")
    assert t["k"] == "phi", t
    assert {a["value"] for a in t["alts"]} == {"x", "y"}, t
    # сходящиеся ветки (одно значение) → схлопывается в один const-лист, не phi
    t2 = _resolve_source(diamond("same", "same"), "M", 0, "v0")
    assert t2 == {"k": "const", "value": "same"}, t2
    print("  phi ok")


#  Task 3: слой androguard — загрузка APK, XREF call-sites, нормализация CFG.
#
#  Discovery (Step 1, на реальном методе DownloadsApiRepository->
#  disallowDeviceDownload, androguard 4.1.4) зафиксировал форму операндов
#  Instruction.get_operands() — список тюплов:
#    - регистр:  (Operand.REGISTER, N)               напр. (REGISTER, 0) -> v0
#    - литерал:  (Operand.LITERAL, value)             напр. const/4, const/high16
#    - offset:   (Operand.OFFSET, value)              напр. if-eqz, goto (не регистр)
#    - constant-pool ссылка: 3-тюпл (kind, index, human_str), kind — это
#      Operand.KIND(256)+смещение: 256=METH, 257=STRING, 258=FIELD, 259=TYPE;
#      human_str — то, что нужно класть в Insn.args (сигнатура/имя поля/строка).
#  get_output() — просто человекочитаемая строка того же самого, не парсится.
#  move-result* всегда идёт СРАЗУ за своим invoke* в пределах ОДНОГО базового
#  блока (Dalvik ABI/верификатор) — сигнатура берётся из операнда invoke*,
#  запомненного при проходе по инструкциям блока.
#  DEXBasicBlock.childs — список (last_idx, target_idx, target_block|None);
#  чтобы отличить fallthrough от branch, сравниваем start целевого блока с
#  end текущего (совпадает -> fallthrough, иначе -> branch/jump).


def load_apk(path):
    """Путь к APK -> (APK, Analysis dx). Долгая операция (~130с на 130MB
    multi-dex APK) — вызывать один раз и переиспользовать оба объекта.
    APK нужен для идентичности сборки в отчёте (пакет/versionName/
    versionCode из манифеста, который androguard и так уже распарсил
    внутри AnalyzeAPK — второй проход по APK не нужен)."""
    apk, _, dx = AnalyzeAPK(str(path))
    return apk, dx


def _fqcn(descriptor):
    """'Lpkg/Cls;' -> 'pkg.Cls'."""
    return descriptor[1:-1].replace("/", ".") if descriptor.startswith("L") else descriptor


def method_key(ma):
    """MethodAnalysis -> 'fqcn->name'."""
    return f"{_fqcn(ma.class_name)}->{ma.name}"


def _declarations(dx, cls, method, descriptor):
    ca = dx.classes.get("L" + cls.replace(".", "/") + ";")
    wanted = descriptor.replace(" ", "") if descriptor is not None else None
    return [ma for ma in (ca.get_methods() if ca else ()) if ma.name == method
            and (wanted is None or ma.descriptor.replace(" ", "") == wanted)]


def resolve_call_sites(dx, cls, method, descriptor=None):
    """Все вызовы cls->method по XREF. Внешние методы не отсеиваются — метод
    может быть интерфейсным объявлением (у него самого нет кода, но есть
    xref_from от вызывающих через invoke-interface). Пусто, если метод не
    найден или XREF пуст (не ошибка)."""
    # Прямой lookup по dx.classes, не dx.find_methods: тот гоняет regex по ВСЕМ
    # классам APK на каждый вызов, а обход зовёт резолв на каждый кадр.
    sites = []
    for ma in _declarations(dx, cls, method, descriptor):
        for xf in ma.get_xref_from():
            caller_ma, off = xf[1], xf[-1]
            sites.append({"caller": method_key(caller_ma),
                          "caller_ma": caller_ma, "offset": off})
    return sorted(sites, key=lambda s: _site_order((s["caller_ma"], s["offset"])))


_CHA_FANIN_CAP = 16      # больше вызывающих у полиморфного метода -> общий интерфейс, не граница
_FRAME_BUDGET = 4000     # потолок кадров на ключ: гарантия завершения при взрывном fan-in
_EDGE_BUDGET = 4 * _FRAME_BUDGET  # прямые ссылки на запрос сохраняются отдельно
# Лимит глубины пути. Проверено на TNT: углубление НЕ помогает покрытию. При
# limit=12 точных ключей стало меньше (29->27), шум стражей вырос в 5-13x, а
# dead_end 100->115 — глубже обход лишь проходит больше промежуточных кадров и
# упирается в общие DI/clean-arch интерфейсы (их CHA режет по _CHA_FANIN_CAP), не
# доходя до UI; заодно более дешёвые оборванные top'ы демотируют бывшие точные
# ключи. Ограничитель покрытия здесь архитектурный (shared-interface routing), не
# глубина — его пробил бы points-to/RTA (whole-app, отвергнут в дизайне §2.1/§11),
# а не CHA. limit=6 даёт лучший баланс точность/шум.
_DEPTH_LIMIT = 6


@lru_cache(maxsize=4096)
def _cha_supers(dx, class_desc):
    """Транзитивные супертипы класса (extends + implements), существующие в APK
    (внешние/Object отбрасываются). Кэш — обход зовёт на каждый кадр, иерархия
    у класса фиксирована."""
    pending = [class_desc]
    seen = {class_desc, "Ljava/lang/Object;"}
    out = []
    while pending:
        ca = dx.classes.get(pending.pop())
        if ca is None or ca.is_external():
            continue
        for s in (ca.extends, *ca.implements):
            if s and s not in seen:
                seen.add(s)
                out.append(s)
                pending.append(s)
    return tuple(out)


def _allocation_origin(cfg, block, pos, register):
    """Resolve one in-method allocation through unambiguous object-register moves."""
    for _ in range(12):
        definition, _, _ = _def_insn(cfg, block, pos, register)
        if definition is None:
            return None
        block, pos, ins = definition
        if ins.op == "new-instance" and ins.args[0]:
            return block, pos, ins.args[0]
        if not ins.op.startswith("move-object") or not ins.args:
            return None
        register = ins.args[0]
    return None


@lru_cache(maxsize=4096)
def _virtual_implementation(dx, owner, name, descriptor):
    seen = set()
    while owner and owner not in seen:
        seen.add(owner)
        cls = dx.classes.get(owner)
        if cls is None or cls.is_external():
            return None
        for method in cls.get_methods():
            if method.name != name or method.descriptor.replace(" ", "") != descriptor:
                continue
            flags = set(method.get_access_flags_string().split())
            if not flags & {"private", "static"}:
                return method if "abstract" not in flags else None
        owner = cls.extends
    return None


@lru_cache(maxsize=16384)
def _call_site_dispatch(dx, caller, offset):
    """Return whether a decoded call is virtual and the exact target if locally resolved."""
    from parameter_slice import layout

    method = caller.get_method()
    if method is None or not hasattr(method, "get_code") or method.get_code() is None:
        return None, None
    basic = caller.get_basic_blocks().get_basic_block(offset)
    if basic is None:
        return None, None
    cursor = basic.get_start()
    for raw in basic.get_instructions():
        if cursor == offset:
            if not raw.get_name().startswith(("invoke-interface", "invoke-virtual")):
                return False, None
            break
        cursor += raw.get_length()
    else:
        return None, None
    frame = layout(caller)
    if not frame or offset not in frame[3]:
        return True, None
    cfg, _, _, positions = frame
    block, pos = positions[offset]
    inv = cfg.nodes[block]["insns"][pos]
    if not inv.op.startswith(("invoke-interface", "invoke-virtual")):
        return False, None
    if len(inv.args) < 2 or not inv.args[0]:
        return True, None
    origin = _allocation_origin(cfg, block, pos, inv.args[1])
    if origin is None:
        return True, None
    owner, _, signature_text = inv.args[0].replace(" ", "").partition("->")
    name, sep, descriptor = signature_text.partition("(")
    receiver = origin[2]
    if sep and (receiver == owner or owner in _cha_supers(dx, receiver)):
        return True, _virtual_implementation(dx, receiver, name, sep + descriptor)
    return True, None


def _xref_sites(method):
    return [(caller, offset) for _, caller, offset in method.get_xref_from()]


def _site_order(site):
    caller, offset = site
    return caller.class_name, caller.name, caller.descriptor, offset


@lru_cache(maxsize=4096)
def _caller_evidence(dx, method, excluded_caller=None):
    """Find resolved callers first. Retain the existing bound on speculative CHA."""
    direct = sorted({site for site in _xref_sites(method) if site[0] is not excluded_caller}, key=_site_order)
    certain, possible = [], []
    final_method = "final" in method.get_access_flags_string().split()
    for site in direct:
        virtual, target = _call_site_dispatch(dx, *site)
        if target is method or (target is None and (not virtual or final_method)):
            certain.append(site)
        elif target is None:
            possible.append(site)

    seen = set(direct)
    truncated = False
    for owner in _cha_supers(dx, method.class_name):
        parent = dx.get_method_analysis_by_name(owner, method.name, method.descriptor)
        if parent is None:
            continue
        for site in sorted(_xref_sites(parent), key=_site_order):
            if site in seen or site[0] is excluded_caller:
                continue
            if len(seen) - len(direct) >= _FRAME_BUDGET:
                truncated = True
                break
            seen.add(site)
            virtual, target = _call_site_dispatch(dx, *site)
            if target is method:
                certain.append(site)
            elif target is None and virtual is not False:
                possible.append(site)
        if truncated:
            break
    if certain:
        return tuple(certain), False, "unexamined_dispatch" if possible or truncated else None
    if len(possible) > _CHA_FANIN_CAP or truncated:
        return (), False, "fanin_capped"
    return (tuple(possible), True, None) if possible else ((), False, "no_callers")


def cha_caller_sites(dx, ma):
    """Return caller sites, whether they rely on CHA, and the stopping reason."""
    sites, used_cha, reason = _caller_evidence(dx, ma)
    return list(sites), used_cha, reason


def _reg(operand):
    """Операнд-регистр -> 'vN', иначе None."""
    return f"v{operand[1]}" if operand[0] == Operand.REGISTER else None


def _kindstr(operand):
    """3-тюпл constant-pool ссылки (kind, index, human_str) -> human_str."""
    return operand[2] if len(operand) == 3 else None


def _norm(instructions):
    """Список androguard Instruction (один базовый блок) -> список Insn.
    op — СЫРАЯ мнемоника (Ruling-A: ins.get_name(), без сведения к категории —
    _kind_of сопоставляет её по префиксу). Раскладка out/args — по форме,
    зафиксированной в discovery (см. комментарий выше):
      move-result*  -> out=dst; args=(сигнатура_callee,) — сигнатура взята из
                        ПРЕДЫДУЩЕЙ invoke*-инструкции этого же блока.
      if-*/*-switch -> out=None; args=тестируемые регистры (нет записи).
      const*        -> out=dst; args=(значение,) — литерал ИЛИ строка/тип
                        (const-string/const-class тоже "const*").
      iget*/sget*   -> out=dst; args=(имя_поля,).
      *put*         -> out=None (aput/iput/sput пишут в поле/массив, не в
                        регистр); args=(имя_поля,) если есть constant-pool
                        ссылка, иначе регистры как есть.
      invoke*       -> out=None; args=(сигнатура_callee,) + регистры-аргументы
                        в порядке вызова (первый — receiver для virtual/
                        interface/direct). ponytail: /range-варианты вызовов
                        не встретились в discovery — форма их операндов не
                        проверена; если Task 4/5 упрутся в /range, перепроверить.
      goto/return/throw -> out=None.
      иначе (move-object, check-cast, instance-of, арифметика,
      move-exception, new-instance, aget, ...) -> общий случай: out = первый
      регистр-операнд (приёмник), args = остальные регистры. Приведение типа
      использует исходный регистр, а move сохраняет регистр-источник.
    """
    out = []
    prev_invoke_sig = None
    for ins in instructions:
        op = ins.get_name()
        operands = ins.get_operands()
        regs = [_reg(o) for o in operands if o[0] == Operand.REGISTER]
        # move-result потребляет prev_invoke_sig; invoke устанавливает его для
        # СЛЕДУЮЩЕЙ инструкции; любая другая инструкция между ними невозможна
        # по Dalvik ABI, но на всякий случай сбрасываем его для всех прочих —
        # не тянуть чужую сигнатуру издалека.
        if op.startswith("move-result"):
            out.append(Insn(op, regs[0] if regs else None,
                             (prev_invoke_sig,) if prev_invoke_sig else ()))
            prev_invoke_sig = None
        elif op.startswith("invoke"):
            prev_invoke_sig = next((_kindstr(o) for o in operands if len(o) == 3), None)
            out.append(Insn(op, None, (prev_invoke_sig,) + tuple(regs)))
        elif op.startswith("if-") or op.endswith("-switch"):
            prev_invoke_sig = None
            out.append(Insn(op, None, tuple(regs)))
        elif op.startswith("const"):
            prev_invoke_sig = None
            lit = next((o[1] for o in operands if o[0] == Operand.LITERAL), None)
            s = next((_kindstr(o) for o in operands if len(o) == 3), None)
            out.append(Insn(op, regs[0] if regs else None, (s if s is not None else lit,)))
        elif op.startswith(("iget", "sget")):
            prev_invoke_sig = None
            field = next((_kindstr(o) for o in operands if len(o) == 3), None)
            out.append(Insn(op, regs[0] if regs else None, (field,)))
        elif op.startswith("new-instance"):
            # new-instance vDst, Type — тип в constant-pool-операнде (len==3),
            # приёмник — единственный регистр. Нужен для резолва ctor-продюсера.
            prev_invoke_sig = None
            typ = next((_kindstr(o) for o in operands if len(o) == 3), None)
            out.append(Insn(op, regs[0] if regs else None, (typ,)))
        elif "put" in op:
            prev_invoke_sig = None
            field = next((_kindstr(o) for o in operands if len(o) == 3), None)
            out.append(Insn(op, None, (field,) if field is not None else tuple(regs)))
        elif op.startswith("goto") or op.startswith("return") or op == "throw" or op == "nop":
            prev_invoke_sig = None
            out.append(Insn(op, None, tuple(regs)))
        elif op in ("monitor-enter", "monitor-exit", "fill-array-data", "check-cast"):
            # единственный регистр-операнд здесь — ЧИСТОЕ использование (lock-
            # объект / ссылка на массив / check-cast — приведение на месте, def-use
            # идёт сквозь него к исходному значению), не def; в общий else не класть.
            prev_invoke_sig = None
            out.append(Insn(op, None, tuple(regs)))
        elif op == "instance-of":
            prev_invoke_sig = None
            typ = next((_kindstr(o) for o in operands if len(o) == 3), None)
            out.append(Insn(op, regs[0] if regs else None, (typ,)))
        else:
            prev_invoke_sig = None
            out.append(Insn(op, regs[0] if regs else None, tuple(regs[1:])))
    return out


def _params(m):
    """EncodedMethod -> {'vN': индекс}. androguard's get_information()['params']
    отдаёт ТОЛЬКО явные параметры дескриптора (без this) — Dalvik ABI кладёт
    их в ПОСЛЕДНИЕ N регистров кадра, а this (если метод не static) — сразу
    перед первым явным параметром (each_params_by_register). this
    восстанавливается вручную по этому смещению и получает индекс 0.
    ponytail: wide-параметры (D/J) занимают 2 регистра, но params отдаёт
    только СТАРТОВЫЙ per androguard — старший регистр пары в map не попадает;
    для boolean/int-флагов (типичный guard) не актуально, апгрейд — раскрыть
    пару по typ, если Task 4/5 упрутся в double/long параметр."""
    code = m.get_code()
    if code is None:
        return {}
    info = m.get_information()
    params = info.get("params", [])
    result, idx = {}, 0
    if "static" not in m.get_access_flags_string():
        this_reg = (params[0][0] - 1) if params else (code.get_registers_size() - 1)
        result[f"v{this_reg}"] = idx
        idx += 1
    for reg, _typ in params:
        result[f"v{reg}"] = idx
        idx += 1
    return result


@lru_cache(maxsize=4096)
def frame_of(ma):
    """MethodAnalysis -> {cfg, params, block_at}. None, если у метода нет
    кода (интерфейс/внешний объявление — ExternalMethod без get_code вовсе,
    либо abstract-метод в самом APK, у которого get_code() is None).
    cfg: nx.DiGraph, id узла = bb.get_name(); атрибуты узла: insns
    (list[Insn]), start/end (смещения code units). Рёбра помечены kind=
    branch|fallthrough (см. комментарий над _norm)."""
    m = ma.get_method()
    code = m.get_code() if m is not None and hasattr(m, "get_code") else None
    if code is None:
        return None
    cfg = nx.DiGraph()
    bbs = list(ma.get_basic_blocks().get())
    handlers = set()
    for bb in bbs:
        raw = list(bb.get_instructions())
        start, end = bb.get_start(), bb.get_end()
        cfg.add_node(bb.get_name(), insns=_norm(raw), start=start, end=end)
        exception = bb.get_exception_analysis()
        if exception is not None:
            handlers.update(handler.get_name() for _, _, handler in exception.exceptions if handler is not None)
        if raw and (raw[-1].get_name().startswith("if-") or raw[-1].get_name().endswith("-switch")):
            cond = raw[-1]
            offset = end - cond.get_length()
            outcomes = {end: [{"kind": "fallthrough"}]}
            if cond.get_name().startswith("if-"):
                outcomes.setdefault(offset + 2 * cond.get_ref_off(), []).append({"kind": "taken"})
            else:
                outcomes[end] = [{"kind": "default"}]
                payload = bb.get_special_ins(offset)
                if payload is not None:
                    for key, target in zip(payload.get_keys(), payload.get_targets()):
                        outcomes.setdefault(offset + 2 * target, []).append({"kind": "case", "value": key})
            cfg.nodes[bb.get_name()].update(branch_offset=offset, outcomes=outcomes)
    for bb in bbs:
        end = bb.get_end()
        for (_last_idx, _tgt_idx, tbb) in bb.childs:
            if tbb is None:
                continue
            kind = "fallthrough" if tbb.get_start() == end else "branch"
            cfg.add_edge(bb.get_name(), tbb.get_name(), kind=kind)
    params = _params(m)
    blocks = sorted(cfg.nodes, key=lambda n: cfg.nodes[n]["start"])
    starts = [cfg.nodes[n]["start"] for n in blocks]

    def block_at(off):
        idx = bisect_right(starts, off) - 1
        if idx >= 0 and off < cfg.nodes[blocks[idx]]["end"]:
            return blocks[idx]
        return None

    normal_blocks = nx.descendants(cfg, blocks[0]) | {blocks[0]} if blocks else set()
    handler_blocks = handlers.union(*(nx.descendants(cfg, handler) for handler in handlers))
    return {"cfg": cfg, "params": params, "block_at": block_at, "normal_blocks": normal_blocks,
            "handler_blocks": handler_blocks}


def _check_androguard(dx):
    cs = resolve_call_sites(dx, "gpm.tnt_premier.features.downloads.impl.data.network.DownloadsApi",
                            "disallowDeviceDownload")
    assert cs, "call-site not found — XREF сломан"
    assert any(c["caller"].endswith("DownloadsApiRepository->disallowDeviceDownload") for c in cs), cs
    # пустой XREF для несуществующего ключа
    assert resolve_call_sites(dx, "no.such.Class", "nope") == []
    # frame_of даёт непустой cfg у метода с кодом
    fr = frame_of(cs[0]["caller_ma"])
    assert fr is not None and fr["cfg"].number_of_nodes() >= 1
    print("  androguard ok")

    w = backward_frames(dx, "gpm.tnt_premier.features.downloads.impl.data.network.DownloadsApi",
                        "disallowDeviceDownload")
    assert w["reached"] and w["call_sites"], w
    assert len(w["frames"]) >= 1, w
    # Ruling-E: лимит — per-path глубина, не общий потолок на frames; общее
    # число кадров естественно ограничено visited-дедупом по (key, offset).
    # Санити-порог на runaway — доказывает, что дедуп реально работает и
    # обход не взрывается комбинаторно на графе с высоким fan-in.
    assert len(w["frames"]) < _FRAME_BUDGET + 1, w
    # regression-guard против отката к глобальному капу на frames (round-1
    # review, Finding 1): у отвергнутого global-cap варианта здесь было бы
    # ровно limit кадров — >=1 и <budget это не ловят, а >6 ловит.
    assert len(w["frames"]) > 6, w
    assert w["depth"] <= _DEPTH_LIMIT, w   # per-path лимит глубины реально соблюдён
    # цикл в графе вызовов не зациклил обход (дошли до сюда — visited работает)
    print("  backward_frames ok")


_ACTIVITY = "Landroid/app/Activity;"
_FRAGMENTS = ("Landroid/app/Fragment;", "Landroidx/fragment/app/Fragment;")
_SERVICE = "Landroid/app/Service;"
_LIFECYCLE_OWNERS = (_ACTIVITY, *_FRAGMENTS)
# TODO: Resolve Compose callback registration (LaunchedEffect and
# rememberCoroutineScope) before treating these runtime edges as UI entries.
_CALLBACK_OWNERS = {
    ("onCreate", "(Landroid/os/Bundle;)V"): _LIFECYCLE_OWNERS,
    ("onStart", "()V"): _LIFECYCLE_OWNERS,
    ("onResume", "()V"): _LIFECYCLE_OWNERS,
    ("onPause", "()V"): _LIFECYCLE_OWNERS,
    ("onStop", "()V"): _LIFECYCLE_OWNERS,
    ("onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V"): _FRAGMENTS,
    ("onCreateView", "(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;"
                     "Landroid/os/Bundle;)Landroid/view/View;"): _FRAGMENTS,
    ("onClick", "(Landroid/view/View;)V"): ("Landroid/view/View$OnClickListener;",),
    ("onCreate", "()V"): (_SERVICE, "Landroid/app/Application;"),
    ("onCreate", "()Z"): ("Landroid/content/ContentProvider;",),
    ("onBind", "(Landroid/content/Intent;)Landroid/os/IBinder;"): (_SERVICE,),
    ("onStartCommand", "(Landroid/content/Intent;II)I"): (_SERVICE,),
    ("onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V"):
        ("Landroid/content/BroadcastReceiver;",),
    ("onHandleWork", "(Landroid/content/Intent;)V"): ("Landroidx/core/app/JobIntentService;",),
    ("doWork", "()Landroidx/work/ListenableWorker$Result;"): ("Landroidx/work/Worker;",),
}


_VIEWMODEL_CONSTRUCTORS = {
    "()V": ("Landroidx/lifecycle/ViewModel;",),
    "(Landroid/app/Application;)V": ("Landroidx/lifecycle/AndroidViewModel;",),
}


def _is_viewmodel_candidate(dx, method):
    if method.name != "<init>":
        return False
    owners = _VIEWMODEL_CONSTRUCTORS.get(method.descriptor.replace(" ", ""), ())
    return bool(owners and set(owners).intersection(_cha_supers(dx, method.class_name)))


def _is_compose_candidate(dx, method):
    class_name = method.class_name
    leaf = class_name.rsplit("/", 1)[-1]
    if "ComposableSingletons" in leaf:
        return True
    if "$lambda" not in leaf:
        return False
    from body_data import annotations, dex_class

    owner = dex_class(dx, class_name.split("$lambda", 1)[0] + ";")
    return owner is not None and any(
        "Landroidx/compose/runtime/Composable;" in tags for tags in annotations(owner)[0].values())


def is_plumbing(key, ma):
    """Kotlin-машинерия, которую нужно проходить насквозь при обратном
    обходе (не считать семантическим кадром): $default-перегрузки со
    значениями по умолчанию, access$-мостики для private-полей из
    вложенных классов, $$inlined$/$$special$ классы (inline-функции),
    invokeSuspend классов-континуаций и create/invoke СИНТЕТИЧЕСКИХ
    лямбда-классов (компилятор Kotlin их так называет).

    Ruling-F (round-1 review, Finding 2): create/invoke — узкий сигнал, не
    широкий, как у invokeSuspend. '$' в простом имени класса матчит ЛЮБОЙ
    вложенный класс (Dagger Foo$Factory.create(), ViewModelProvider.
    Factory.create(), обычный Function1.invoke()) — такие create/invoke
    ошибочно считались бы плумбингом и роняли guard-несущие кадры (та же
    проблема, с которой борется Ruling-E). create/invoke — плумбинг только
    при явном классе Continuation ЛИБО синтетическом лямбда-классе (последний
    $-сегмент — цифры, напр. Foo$bar$1), не для обычных Factory/Function."""
    name = key.rsplit("->", 1)[-1]
    cls = getattr(ma, "class_name", "")
    if name.endswith("$default") or name.startswith("access$"):
        return True
    if "$$inlined$" in cls or "$$special$" in cls:
        return True
    # class_name — сырой JVM-дескриптор ('La/b/C$run$1;'), простое имя
    # снимается по '/' и trailing ';' (иначе последний $-сегмент — "1;",
    # isdigit() ложно фейлится на обычной цифровой лямбде).
    simple = cls.rsplit("/", 1)[-1].rstrip(";")
    if name == "invokeSuspend" and ("Continuation" in cls or "$" in simple):
        return True
    # ponytail: эвристика по имени — create/invoke считаем плумбингом только для
    # корутинной машинерии (Continuation) либо синтетического лямбда-класса
    # (последний $-сегмент — цифры, напр. Foo$bar$1), не для обычных Factory/Function.
    # Точность плумбинга валидируется в Task 7 против ground truth.
    if name in ("create", "invoke") and (
            "Continuation" in cls
            or ("$" in simple and simple.rsplit("$", 1)[-1].isdigit())):
        return True
    return False


_VIEW = "Landroid/view/View;"
_CLICK_LISTENER = "Landroid/view/View$OnClickListener;"
_CLICK_REGISTRATION = "setOnClickListener(" + _CLICK_LISTENER + ")V"


@lru_cache(maxsize=4096)
def _has_click_registration(dx, owner):
    from parameter_slice import layout

    clazz = dx.classes.get(owner)
    for caller, offset in clazz.get_xref_new_instance() if clazz else ():
        frame = layout(caller)
        if not frame or offset not in frame[3]:
            continue
        cfg, _, _, positions = frame
        alloc_block, alloc_pos = positions[offset]
        for block, data in cfg.nodes(data=True):
            for pos, ins in enumerate(data["insns"]):
                if not ins.op.startswith(("invoke-virtual", "invoke-super")) or len(ins.args) != 3:
                    continue
                receiver, _, member = (ins.args[0] or "").replace(" ", "").partition("->")
                if member != _CLICK_REGISTRATION:
                    continue
                if receiver != _VIEW and _VIEW not in _cha_supers(dx, receiver):
                    continue
                if _allocation_origin(cfg, block, pos, ins.args[2]) == (alloc_block, alloc_pos, owner):
                    return True
    return False


def _frontier_kind(dx, ma):
    """Recognize modelled UI and background entry points separately."""
    owners = _CALLBACK_OWNERS.get((ma.name, ma.descriptor.replace(" ", "")))
    if not owners:
        return None
    flags = set(ma.get_access_flags_string().split())
    if not flags.intersection({"public", "protected"}) or flags.intersection({"static", "abstract", "private"}):
        return None
    hierarchy = (ma.class_name, *_cha_supers(dx, ma.class_name))
    if not any(owner in hierarchy for owner in owners):
        return None
    if ma.name == "onClick":
        return "ui" if _has_click_registration(dx, ma.class_name) else None
    return "ui" if any(owner in hierarchy for owner in _LIFECYCLE_OWNERS) else "background"


def is_frontier(dx, ma):
    return _frontier_kind(dx, ma) is not None


def manifest_entry_classes(apk):
    """Collect component names from manifest export declarations and intent filters."""
    ns = "{http://schemas.android.com/apk/res/android}"
    out = set()
    try:
        root = apk.get_android_manifest_xml()
    except Exception:
        return out
    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for el in root.iter(tag):
            name = el.get(ns + "name")
            if not name:
                continue
            exp = el.get(ns + "exported")
            if exp == "true" or (exp is None and el.find("intent-filter") is not None):
                out.add(name if name[0] != "." else apk.get_package() + name)
    return out


SINK = ("__sink__",)  # синтетический узел скрытого вызова в графе кадров (§7.1)


def _integer_source(cfg, block, pos, register):
    definition, reason, _ = _def_insn(cfg, block, pos, register)
    if definition is None:
        return "parameter" if reason == "no_pred" else "unknown", register
    _, _, ins = definition
    if ins.op in ("const/4", "const/16", "const", "const/high16") and type(ins.args[0]) is int:
        return "literal", ins.args[0]
    return "unknown", None


def _allocation_selector(dx, method, offset):
    """Find an immutable integer selector and an explicit arm reaching the criterion."""
    from body_data import raw_blocks, registers
    from parameter_slice import layout

    layout_data = layout(method)
    if not layout_data:
        return None
    cfg, params, offsets, positions = layout_data
    located = positions.get(offset)
    entry = next(iter(cfg), None)
    if not located or entry is None:
        return None
    insns = cfg.nodes[entry]["insns"]
    if not insns:
        return None
    pos = len(insns) - 1
    branch = insns[pos]
    branch_offset = offsets[entry, pos]
    raw = raw_blocks(method)[branch_offset]
    fallthrough = branch_offset + raw.get_length()
    if branch.op.endswith("-switch"):
        payload = raw_blocks(method).get(branch_offset + 2 * raw.get_ref_off())
        if payload is None or not hasattr(payload, "get_targets"):
            return None
        labels = {value: branch_offset + 2 * target
                  for value, target in zip(payload.get_values(), payload.get_targets())}
        default = fallthrough
        operands = [(branch.args[0], None)]
    elif branch.op in ("if-eqz", "if-nez", "if-eq", "if-ne"):
        destination = branch_offset + 2 * raw.get_ref_off()
        equal_branch = branch.op.startswith("if-eq")
        targets = (destination, fallthrough) if equal_branch else (fallthrough, destination)
        operands = [(branch.args[0], None)] if branch.op.endswith("z") else [
            (branch.args[0], branch.args[1]), (branch.args[1], branch.args[0])]
    else:
        return None

    criterion = located[0]
    can_reach = nx.ancestors(cfg, criterion) | {criterion}
    successors = {cfg.nodes[n]["start"]: n for n in cfg.successors(entry)}
    found = []
    for reg, compared in operands:
        definition, _, _ = _def_insn(cfg, entry, pos, reg)
        if not definition or definition[0] != entry or definition[2].op != "iget":
            continue
        _, read_pos, read = definition
        field = read.args[0]
        field_owner, _, field_tail = field.partition("->")
        name, _, typ = field_tail.partition(" ")
        if field_owner != method.class_name or typ != "I" or name == "label":
            continue
        raw_read = raw_blocks(method)[offsets[entry, read_pos]]
        _, receiver = registers(raw_read)
        if params.get(receiver, (None,))[0] != -1 or _def_insn(cfg, entry, read_pos, receiver)[0]:
            continue
        owner = dx.classes[field_owner].get_vm_class()
        if not any(f.get_name() == name and f.get_descriptor() == "I" and f.get_access_flags() & 0x10
                   for f in owner.get_fields()):
            continue
        if not branch.op.endswith("-switch"):
            kind, label = ("literal", 0) if compared is None else _integer_source(cfg, entry, pos, compared)
            if kind != "literal":
                continue
            labels, default = {label: targets[0]}, targets[1]
        if default not in successors or successors[default] in can_reach:
            continue
        if any(target not in successors for target in labels.values()):
            continue
        values = {value for value, target in labels.items() if successors[target] in can_reach}
        if values:
            found.append((field, values))
    return found[0] if len(found) == 1 else None


def _allocation_selector_value(dx, caller, offset, field):
    from body_data import arguments, raw_blocks, registers
    from parameter_slice import layout

    layout_data = layout(caller)
    instruction = raw_blocks(caller).get(offset)
    if not layout_data or instruction is None or instruction.get_name() != "new-instance":
        return None
    cfg, _, _, positions = layout_data
    if offset not in positions:
        return None
    block, pos = positions[offset]
    insns = cfg.nodes[block]["insns"]
    allocated = insns[pos].out
    owner = field.partition("->")[0]
    for at, inv in enumerate(insns[pos + 1:], pos + 1):
        if inv.out == allocated:
            return None
        if (inv.op.startswith("invoke-direct") and len(inv.args) >= 2
                and inv.args[1] == allocated and (inv.args[0] or "").startswith(owner + "-><init>(")):
            break
    else:
        return None
    desc = inv.args[0].partition("-><init>")[2]
    ctor = next((m for m in dx.classes[owner].get_methods()
                 if m.name == "<init>" and m.descriptor.replace(" ", "") == desc.replace(" ", "")), None)
    ctor_data = layout(ctor) if ctor is not None else None
    if not ctor_data:
        return None
    graph, parameters, offsets, _ = ctor_data
    if len(graph) != 1:
        return None
    node = next(iter(graph))
    code = graph.nodes[node]["insns"]
    writes = [i for i, ins in enumerate(code) if ins.op == "iput" and ins.args == (field,)]
    if len(writes) != 1:
        return None
    write, = writes
    value, receiver = registers(raw_blocks(ctor)[offsets[node, write]])
    if parameters.get(receiver, (None,))[0] != -1 or _def_insn(graph, node, write, receiver)[0]:
        return None
    kind, source = _integer_source(graph, node, write, value)
    if kind == "literal":
        return source
    index, typ = parameters.get(source, (-1, None))
    if kind != "parameter" or index < 0 or typ != "I":
        return None
    argument = list(arguments(inv.args[2:], _param_types(desc)))[index]
    kind, value = _integer_source(cfg, block, at, argument)
    return value if kind == "literal" else None


def _allocation_callers(dx, method, offset):
    cls = dx.classes.get(method.class_name)
    sites = list(cls.get_xref_new_instance()) if cls else []
    if len(sites) < 2:
        return sites
    selector = _allocation_selector(dx, method, offset)
    if selector is None:
        return sites
    field, accepted = selector
    narrowed = []
    for caller, position in sites:
        value = _allocation_selector_value(dx, caller, position, field)
        if value is None or value in accepted:
            narrowed.append((caller, position))
    return narrowed or sites


def backward_frames(dx, cls, method, limit=_DEPTH_LIMIT, *, descriptor=None):
    """Обратный межпроцедурный обход от call-site'ов cls->method вверх по
    графу вызовов до известного UI/lifecycle-колбэка или лимита глубины.
    Плумбинг (is_plumbing) проходится насквозь — не попадает в frames и не
    тратит бюджет глубины (вверх от него идём с ТЕМ ЖЕ depth), но его узел
    сохраняется в графе. Циклы (рекурсия, coroutine resume через себя
    же) гасятся visited-множеством по (метод, offset) — один и тот же
    call-site не обрабатывается дважды, что гарантирует терминацию на
    конечном графе вызовов.

    Ruling-E: limit — бюджет глубины ОДНОГО пути (как ICSE-обход
    startActivity->onCreate), а не общий потолок на len(frames).

    §7.1: обход строит граф кадров для минимума по путям. node = (id(ma), off)
    (совпадает с ключом visited). edges — рёбра ВНИЗ к скрытому вызову
    (родитель-вызывающий -> потомок-вызываемый); у исходных call-site'ов
    потомок — SINK. Рёбра пишутся в момент ОБНАРУЖЕНИЯ (push), до дедупа, иначе
    fan-in терялся бы. frontier_nodes / dead_end_nodes / capped_nodes —
    максимальные кадры (входы обхода); plumbing_nodes — узлы-плумбинг
    (семантические стражи в них учитываются наравне с другими кадрами)."""
    from coroutine_paths import launched_lambda_sites, resumed_method

    sites = resolve_call_sites(dx, cls, method, descriptor)
    if not sites:
        return {"reached": False, "call_sites": [], "frames": [],
                "frontier": None, "depth": 0, "plumbing_skipped": [],
                "depth_capped": False, "dead_ends": [], "edges": [], "cha_used": False,
                "sites_by_node": {}, "edge_kinds": {}, "budget_nodes": set(), "dispatch_capped": set(),
                "budget_hit": False, "uncertain_callers": set(), "cha_uncertain": set(), "allocation_uncertain": set(),
                "unexamined_dispatch": set(),
                "allocation_used": False, "coroutine_resume_edges": 0, "coroutine_launch_edges": 0,
                "frontier_nodes": set(), "entry_nodes": {}, "dead_end_nodes": set(),
                "capped_nodes": set(), "plumbing_nodes": set(), "stop_reasons": {},
                "first_uncertain_depth": {}, "viewmodel_candidate": False, "compose_dead_end": False}
    stop_reasons = {}
    first_uncertain_depth = {}
    frames, skipped, frontier, dead_ends = [], [], None, []
    edges = []
    frontier_nodes, dead_end_nodes, capped_nodes, plumbing_nodes = set(), set(), set(), set()
    entry_nodes = {}
    visited = set()
    cha_used = False
    cha_uncertain, allocation_uncertain = set(), set()
    unexamined_dispatch = set()
    allocation_used = False
    viewmodel_candidate = compose_dead_end = False
    budget_hit = False
    max_depth = 0
    depth_capped = False  # True, если ХОТЬ ОДИН путь упёрся в limit (OR по путям)
    nid = lambda ma, o: (id(ma), o)
    sites_by_node = {nid(s["caller_ma"], s["offset"]): s["caller_ma"] for s in sites}
    edge_kinds = {(node, SINK): {"dex_xref"} for node in sites_by_node}
    budget_nodes, dispatch_capped = set(), set()
    scheduled_edges = 0
    # Очередь: (child_node, caller_ma, offset, depth, evidence). Depth путевой.
    # child_node — узел, который этот кадр вызывает ВНИЗ к скрытому вызову.
    # 0-1 BFS (спека §5.2), не DFS: при visited-дедупе DFS мог впервые прийти в
    # кадр по длинному пути, упереться в limit и отбросить короткий путь к нему.
    queue = deque((SINK, s["caller_ma"], s["offset"], 0, ("dex_xref",)) for s in sites)
    while queue:
        child_node, caller_ma, off, depth, evidence = queue.popleft()
        node = nid(caller_ma, off)
        sites_by_node[node] = caller_ma
        edge_kinds.setdefault((node, child_node), set()).update(evidence)
        ckey = method_key(caller_ma)
        edges.append((node, child_node))  # ребро вниз к скрытому вызову (до дедупа)
        # дедуп по самому методу, не по имени: у R8 перегрузки a(I)/a(J) — разные
        # методы с одним ключом, склейка давала ложный fan-in (выброс 528 стражей)
        if (caller_ma, off) in visited:
            continue
        visited.add((caller_ma, off))
        if len(visited) > _FRAME_BUDGET:
            # взрывной fan-in (общий интерфейс проскочил потолок): обход не
            # должен виснуть — обрываем, ключ честно помечается budget_hit
            budget_hit = True
            budget_nodes.add(node)
            for pending_child, ma, offset, _, kinds in queue:
                pending = nid(ma, offset)
                if pending_child == SINK or pending in sites_by_node:
                    edge_kinds.setdefault((pending, pending_child), set()).update(kinds)
                else:
                    # The caller was discovered, but its frame did not fit the budget.
                    budget_nodes.add(pending_child)
            budget_nodes.update(n for n, ma in sites_by_node.items() if (ma, n[1]) not in visited)
            break
        hop = depth
        viewmodel_candidate |= _is_viewmodel_candidate(dx, caller_ma)
        resumed = resumed_method(dx, caller_ma, off)
        plumbing = resumed is not None or is_plumbing(ckey, caller_ma)
        if plumbing:
            skipped.append(ckey)
            plumbing_nodes.add(node)
            # плумбинг не тратит бюджет глубины — depth дальше вверх тот же
        else:
            frames.append({"key": ckey, "ma": caller_ma, "node": node, "offset": off})
            max_depth = max(max_depth, depth + 1)
            kind = _frontier_kind(dx, caller_ma)
            if kind:
                frontier = ckey
                frontier_nodes.add(node)
                entry_nodes[node] = kind
                continue  # путь дошёл до фронтира — выше по нему не поднимаемся
            depth += 1
            if depth >= limit:
                depth_capped = True
                capped_nodes.add(node)
                continue  # этот путь упёрся в лимит глубины
        if resumed is not None:
            ups, used, reason = _caller_evidence(dx, resumed, caller_ma)
        else:
            ups, used, reason = cha_caller_sites(dx, caller_ma)
        if reason == "fanin_capped":
            dispatch_capped.add(node)
        launches, incomplete = launched_lambda_sites(dx, caller_ma, off)
        caller_kinds = {}
        if not (used and launches):
            for ma, offset in ups:
                virtual, _ = _call_site_dispatch(dx, ma, offset)
                kinds = ["cha" if used else "resolved_dispatch" if virtual else "dex_xref"]
                if resumed is not None:
                    kinds.append("coroutine_resume")
                caller_kinds[ma, offset] = kinds
        if launches:
            for site in launches:
                caller_kinds.setdefault(site, []).append("coroutine_launch")
            if incomplete or used or reason in ("fanin_capped", "unexamined_dispatch"):
                unexamined_dispatch.add(node)
            known = [] if used else ups
            ups = sorted(set(known) | set(launches), key=_site_order)
            used = False
        cha_used = cha_used or used
        if used:
            cha_uncertain.add(node)
        elif reason == "unexamined_dispatch":
            unexamined_dispatch.add(node)
        if not ups and resumed is None and caller_ma.name in _COROUTINE_FRAME_METHODS:
            # invoke/invokeSuspend/create лямбды зовёт рантайм через интерфейс
            # (Function*/Continuation) — XREF пуст. Точка активации лямбды — место
            # её создания (new-instance): ViewModel/фрагмент, где вызван launch {}.
            # Для слитых классов исключаем только доказанно чужие ветки.
            ups = _allocation_callers(dx, caller_ma, off)
            if ups:
                allocation_uncertain.add(node)
                allocation_used = True
                ups = sorted(set(ups), key=_site_order)
                caller_kinds = {site: ["allocation_xref"] for site in ups}
        if not ups:
            stop_reasons[node] = reason
            dead_ends.append(ckey)  # путь оборван не на фронтире: стражи выше не видны
            dead_end_nodes.add(node)
            compose_dead_end |= _is_compose_candidate(dx, caller_ma)
        if used or node in allocation_uncertain or not ups:
            first_uncertain_depth[node] = hop
        push = queue.appendleft if plumbing else queue.append  # плумбинг: та же глубина
        remaining_edges = _EDGE_BUDGET - scheduled_edges
        if len(ups) > remaining_edges:
            budget_hit = True
            budget_nodes.add(node)
        for ma, o in ups[:remaining_edges]:
            push((node, ma, o, depth, caller_kinds[ma, o]))
            scheduled_edges += 1
    return {"reached": True, "call_sites": sites, "frames": frames,
            "frontier": frontier, "depth": max_depth,
            "plumbing_skipped": skipped, "depth_capped": depth_capped,
            "dead_ends": dead_ends, "edges": edges, "cha_used": cha_used,
            "sites_by_node": sites_by_node, "edge_kinds": edge_kinds, "budget_nodes": budget_nodes,
            "dispatch_capped": dispatch_capped,
            "uncertain_callers": cha_uncertain | allocation_uncertain, "unexamined_dispatch": unexamined_dispatch,
            "cha_uncertain": cha_uncertain, "allocation_uncertain": allocation_uncertain,
            "allocation_used": allocation_used,
            "coroutine_resume_edges": sum("coroutine_resume" in kinds for kinds in edge_kinds.values()),
            "coroutine_launch_edges": sum("coroutine_launch" in kinds for kinds in edge_kinds.values()),
            "budget_hit": budget_hit,
            "frontier_nodes": frontier_nodes, "entry_nodes": entry_nodes, "dead_end_nodes": dead_end_nodes,
            "capped_nodes": capped_nodes, "plumbing_nodes": plumbing_nodes, "stop_reasons": stop_reasons,
            "first_uncertain_depth": first_uncertain_depth,
            "viewmodel_candidate": viewmodel_candidate, "compose_dead_end": compose_dead_end}


def _check_walk_predicates():
    class FakeMA:  # достаточно для предикатов — только class_name
        def __init__(self, cls): self.class_name = cls
    assert is_plumbing("a.b.C->postDeviceUpdate$default", FakeMA("La/b/C;"))
    assert is_plumbing("a.b.C$$inlined$x->invoke", FakeMA("La/b/C$$inlined$x;"))
    assert not is_plumbing("a.b.C->postDeviceUpdate", FakeMA("La/b/C;"))
    # Ruling-F: create/invoke на ОБЫЧНОМ вложенном классе (Dagger Factory,
    # ViewModelProvider.Factory, произвольный Function1) — НЕ плумбинг,
    # только широкое '$' в простом имени этого больше не ловит.
    assert not is_plumbing("a.b.C$Factory->create", FakeMA("La/b/C$Factory;"))
    # синтетический лямбда-класс (последний $-сегмент — цифры) — плумбинг.
    assert is_plumbing("a.b.C$run$1->invoke", FakeMA("La/b/C$run$1;"))
    print("  walk_predicates ok")


def guards_of_frame(fr, criterion_offset):
    """Стражи одного кадра для критерия (call-site offset в нём): узлы
    ветвления, от которых блок-критерий транзитивно control-dependent
    (Task 1), с классификацией тестируемого операнда (Task 2).

    Ruling-G: инструкция-ветвление ищется по PREFIX/SUFFIX сырой мнемоники
    (op.startswith("if") или op.endswith("-switch")), НЕ по членству в
    фиксированном наборе _IF_OPS — так _norm (Task 3) и пометила ветвления:
    if-*/*-switch имеют out=None, тестируемый регистр(ы) в args. Если cond не
    найден (не должно происходить для настоящего ветвления, но не падать) —
    ярлык "branch", операнд unknown."""
    cfg = fr["cfg"]
    crit = fr["block_at"](criterion_offset)
    if crit is None:
        return []
    if "control_deps" not in fr:
        exit_node = "__exit__"
        g = cfg.copy()
        g.add_node(exit_node)
        g.add_edges_from((n, exit_node) for n in cfg if cfg.out_degree(n) == 0)
        fr["control_deps"] = _direct_control_deps(g, exit_node)
    guards = []
    for branch, taken in sorted(_control_closure(fr["control_deps"], crit)):
        branch_data = cfg.nodes[branch]
        insns = branch_data["insns"]
        cond = next((i for i in reversed(insns)
                     if i.op.startswith("if") or i.op.endswith("-switch")), None)
        opcode = cond.op if cond else "branch"
        # спека §5.6 — каждый операнд. У if-eq/if-lt/... два регистра; источник
        # стража — неконстантная сторона (`if (cfg.mode == 2)`: константа справа
        # или слева), иначе первый операнд.
        cands = [classify_operand(cfg, branch, len(insns) - 1, r, fr["params"])
                 for r in (cond.args if cond else ())]
        kind, detail = next((c for c in cands if c[0] not in ("const", "unknown")),
                            cands[0] if cands else ("unknown", None))
        operand = {"source_kind": kind, "detail": detail}
        operands = [{"register": reg, "source_kind": source, "detail": value}
                    for reg, (source, value) in zip(cond.args if cond else (), cands)]
        if opcode.startswith("if-") and opcode.endswith("z"):
            operands.append({"source_kind": "const", "detail": 0})
        # дескрипторы полей/типов, читаемых в самом блоке ветвления: нужны для
        # распознавания метки корутины `if ((label & MIN_INT) != 0)`, где
        # операнд — результат and-int (unknown), а само поле-метку читает iget.
        block_refs = [i.args[0] for i in insns
                      if i.op.startswith(("iget", "sget", "instance-of"))
                      and i.args and i.args[0]]
        guards.append({"frame": None, "opcode": opcode, "sense": f"->{taken}",
                       "branch_block": branch, "branch_offset": branch_data.get("branch_offset"),
                       "target_offset": cfg.nodes[taken].get("start"),
                       "outcomes": branch_data.get("outcomes", {}).get(cfg.nodes[taken].get("start"), []),
                       "operand": operand, "operands": operands, "notes": [], "_block_refs": block_refs})
    return guards


def _check_guard_operand():
    # if-eq v0, v1 с константой в ПЕРВОМ операнде: источник стража — поле во втором
    g = nx.DiGraph()
    g.add_node("A", insns=[Insn("const/4", "v0", (2,)), Insn("iget", "v1", ("Lc/Cfg;->mode I",)),
                           Insn("if-eq", None, ("v0", "v1"))])
    g.add_node("B", insns=[Insn("invoke-interface", None, ("Lx/Api;->m()V",))])
    g.add_node("C", insns=[Insn("return-void", None, ())])
    g.add_edges_from([("A", "B"), ("A", "C"), ("B", "C")])
    gs = guards_of_frame({"cfg": g, "params": {}, "block_at": lambda off: "B"}, 0)
    assert [x["operand"] for x in gs] == [{"source_kind": "field", "detail": "Lc/Cfg;->mode I"}], gs
    print("  guard_operand ok")


def _find_invoke(insns, cls, method):
    """Ищет в списке Insn блока invoke*-инструкцию скрытого вызова cls->method
    по сигнатуре callee (args[0] инструкции — человекочитаемая строка вида
    'Lpkg/Cls;->name(...)Rtype', см. _norm/_kindstr). Сначала точное
    совпадение владельца+имени, иначе — первое совпадение по одному имени
    (перегрузки не различаем, как весь пайплайн). None, если не нашли."""
    desc = "L" + cls.replace(".", "/") + ";->" + method + "("
    name_pat = "->" + method + "("
    fallback = None
    for i, ins in enumerate(insns):
        if not ins.op.startswith("invoke") or not ins.args or not ins.args[0]:
            continue
        sig = ins.args[0]
        if sig.startswith(desc):
            return i, ins
        if fallback is None and name_pat in sig:
            fallback = (i, ins)
    return fallback


def args_of_call(fr, offset, cls, method):
    """Происхождение фактических аргументов скрытого вызова (спека §5.7) —
    тот же классификатор источника (classify_operand), что и для guard-
    операндов, по регистрам-аргументам invoke-инструкции. Receiver (первый
    регистр у virtual/interface/super/direct invoke) индекс не получает —
    индексируются только явные аргументы метода, как в сигнатуре вызова;
    invoke-static регистры все явные, receiver нет. [] при любом сбое
    резолва (нет кадра/блока/инструкции) — не падать (Review Focus)."""
    block = fr["block_at"](offset)
    if block is None:
        return []
    insns = fr["cfg"].nodes[block]["insns"]
    found = _find_invoke(insns, cls, method)
    if found is None:
        return []
    use_pos, ins = found
    regs = list(ins.args[1:])
    if regs and not ins.op.startswith("invoke-static"):
        regs = regs[1:]  # receiver — не аргумент метода
    if regs and "Lkotlin/coroutines/Continuation;)" in ins.args[0]:
        regs = regs[:-1]  # continuation suspend-вызова — не данные запроса
    out = []
    for idx, reg in enumerate(regs):
        kind, detail = classify_operand(fr["cfg"], block, use_pos, reg, fr["params"])
        entry = {"index": idx, "source_kind": kind, "detail": detail}
        # Статический продюсер полей: если аргумент — инлайн-сконструированный
        # DTO (new-instance), дорезолвить провенанс каждого его ctor-аргумента —
        # это источники полей тела запроса (кто порождает code/id/token/…).
        if kind == "new" and detail:
            ca = _ctor_args_of(fr, block, use_pos, reg, detail)
            if ca:
                entry["ctor_args"] = ca
        out.append(entry)
    return out


def _def_insn(cfg, block, use_pos, reg):
    """Инструкция-определение reg (обратный def-use один хоп, как classify_operand).
    Возвращает ((block, idx, Insn), 'found') либо (None, причина): 'merge' (>=2
    предшественника — phi/слияние, def неоднозначен), 'no_pred' (0 предшественников
    — вход метода: параметр или не определён), 'cycle' (петля блоков)."""
    b, start, seen = block, use_pos - 1, set()
    while True:
        insns = cfg.nodes[b]["insns"]
        for i in range(min(start, len(insns) - 1), -1, -1):
            if insns[i].out == reg:
                return (b, i, insns[i]), "found", None
        if b in seen:
            return None, "cycle", None
        seen.add(b)
        preds = list(cfg.predecessors(b))
        if len(preds) == 1:
            b = preds[0]; start = len(cfg.nodes[b]["insns"]) - 1; continue
        # merge: def неоднозначен (≥2 предш.) — отдаём merge-блок для phi-раскрутки.
        return None, ("merge" if len(preds) >= 2 else "no_pred"), (b if len(preds) >= 2 else None)


def _resolve_source(fr, block, use_pos, reg, depth=3, seen=None):
    """РЕКУРСИВНОЕ дерево происхождения значения в reg (статический продюсер до
    листьев). Раскрывает new-instance (→ctor-аргументы), move-result (→вызов-
    продюсер и ЕГО аргументы), iget/const. Листья: const / field (чтение живого)
    / invoke (вызов живого продюсера) / param (ПОЛЬЗОВАТЕЛЬСКИЙ ВВОД или вход
    метода — здесь ставится заглушка) / unknown / capped (предел глубины). Обход
    интрапроцедурный (тело вызывающего) — продюсер в чужом методе становится
    листом invoke, его аргументы синтезируются/стопаются на уровне make_plan."""
    seen = seen or set()
    loc, why, mb = _def_insn(fr["cfg"], block, use_pos, reg)
    if loc is None:
        if reg in fr["params"]:
            return {"k": "param", "index": fr["params"][reg]}
        if why == "merge":
            return _phi_source(fr, mb, reg, depth, seen)   # def из ≥2 веток
        return {"k": "unknown", "reason": why}   # no_pred / cycle
    b, idx, ins = loc
    key = (b, idx, reg)
    if depth <= 0 or key in seen:
        return {"k": "capped"}
    seen = seen | {key}
    op = ins.op
    if op.startswith("const"):
        return {"k": "const", "value": ins.args[0] if ins.args else None}
    if op.startswith(("iget", "sget")):
        return {"k": "field", "detail": ins.args[0] if ins.args else None}
    if op.startswith("new-instance"):
        # <init> идёт ПОСЛЕ new-instance, до точки использования — сканируем от
        # use_pos назад (как _ctor_args_of), не от позиции самого new-instance.
        return {"k": "new", "type": ins.args[0] if ins.args else None,
                "ctor_args": _ctor_sources(fr, block, use_pos, reg, ins.args[0], depth - 1, seen)}
    if op.startswith("move-result"):
        if idx - 1 >= 0:
            inv = fr["cfg"].nodes[b]["insns"][idx - 1]
            if inv.op.startswith("invoke"):
                return _invoke_source(fr, b, idx - 1, inv, depth - 1, seen)
        return {"k": "invoke", "detail": ins.args[0] if ins.args else None, "args": []}
    if op.startswith("move") and op != "move-exception":
        # move / move-object(/from16//16) — алиас-копия регистра: значение берём из
        # регистра-источника (сквозной def-use), не теряем трассу. move-result выше,
        # move-exception — пойманное исключение (не алиас). depth НЕ тратим: копия
        # не продюсерский хоп, цикл ловит seen. (check-cast прозрачен и так — out=None
        # в _norm, _def_insn идёт мимо него к доcast-определению.)
        return _resolve_source(fr, b, idx, ins.args[0], depth, seen) if ins.args else {"k": "unknown", "reason": "move_noargs"}
    if op == "instance-of":
        return {"k": "instanceof", "detail": ins.args[0] if ins.args else None}
    return {"k": "unknown", "reason": "op:" + op}


def _phi_source(fr, merge_block, reg, depth, seen):
    """phi-раскрутка: reg определён в ≥2 ветках, сходящихся в merge_block. Резолвим
    def reg от КОНЦА каждого предшественника и собираем различные деревья-источники.
    Один уникальный → он и есть; несколько → {k:phi, alts:[...]} (консьюмер _src_val
    берёт первую не-stub ветку — инструменту достаточно одного валидного значения).
    depth тратится (ветка — реальный хоп резолва), mkey в seen ловит петли (loop-
    carried phi, где предшественник ведёт обратно в merge)."""
    mkey = ("phi", merge_block, reg)
    if depth <= 0 or mkey in seen:
        return {"k": "capped"}
    seen = seen | {mkey}
    alts, seen_json = [], set()
    for p in fr["cfg"].predecessors(merge_block):
        insns = fr["cfg"].nodes[p]["insns"]
        t = _resolve_source(fr, p, len(insns), reg, depth - 1, seen)
        j = json.dumps(t, sort_keys=True, ensure_ascii=False)
        if j not in seen_json:
            seen_json.add(j); alts.append(t)
    if not alts:
        return {"k": "unknown", "reason": "merge_nopreds"}
    return alts[0] if len(alts) == 1 else {"k": "phi", "alts": alts}


def _invoke_source(fr, b, pos, inv, depth, seen):
    """Вызов-продюсер (move-result-инструкция): сигнатура + РЕКУРСИВНО источники
    его фактических аргументов (receiver и continuation отброшены)."""
    sig = inv.args[0]
    regs = list(inv.args[1:])
    if regs and not inv.op.startswith("invoke-static"):
        regs = regs[1:]  # receiver — не аргумент
    if regs and sig and "Lkotlin/coroutines/Continuation;)" in sig:
        regs = regs[:-1]
    return {"k": "invoke", "detail": sig,
            "args": [_resolve_source(fr, b, pos, r, depth, seen) for r in regs]}


def _ctor_sources(fr, block, use_pos, dto_reg, dto_type, depth, seen):
    """Как _ctor_args_of, но каждый ctor-аргумент — РЕКУРСИВНОЕ дерево источника."""
    b, start, seen2 = block, use_pos, set()
    while True:
        insns = fr["cfg"].nodes[b]["insns"]
        for i in range(min(start, len(insns) - 1), -1, -1):
            ins = insns[i]
            if (ins.op.startswith("invoke") and ins.args and ins.args[0]
                    and "-><init>(" in ins.args[0] and dto_type and dto_type in ins.args[0]
                    and len(ins.args) > 1 and ins.args[1] == dto_reg):
                return [_resolve_source(fr, b, i, r, depth, seen) for r in ins.args[2:]]
        if b in seen2:
            return []
        seen2.add(b)
        preds = list(fr["cfg"].predecessors(b))
        if len(preds) != 1:
            return []
        b = preds[0]; start = len(fr["cfg"].nodes[b]["insns"]) - 1


def arg_sources_of_call(fr, offset, cls, method, depth=3):
    """Рекурсивные деревья происхождения фактических аргументов скрытого вызова
    (расширение args_of_call до листьев — продюсеры продюсеров до user-input)."""
    block = fr["block_at"](offset)
    if block is None:
        return []
    insns = fr["cfg"].nodes[block]["insns"]
    found = _find_invoke(insns, cls, method)
    if found is None:
        return []
    use_pos, ins = found
    regs = list(ins.args[1:])
    if regs and not ins.op.startswith("invoke-static"):
        regs = regs[1:]
    if regs and "Lkotlin/coroutines/Continuation;)" in ins.args[0]:
        regs = regs[:-1]
    return [{"index": i, "source": _resolve_source(fr, block, use_pos, r, depth)}
            for i, r in enumerate(regs)]


def _is_concrete_source(s):
    """Источник несёт конкретное значение/продюсера (не голый вход метода).
    Подъём через $default-мост заменяет param только на такой — иначе
    типизированный $stub лучше null из `const null`-дефолта вызывающего."""
    k = s.get("k")
    if k in ("new", "invoke", "field"):
        return True
    if k == "const":
        return s.get("value") not in (None, 0, "0")
    if k == "phi":
        return any(_is_concrete_source(a) for a in s.get("alts", []))
    return False


def _climb_default_bridge(dx, bridge_ma, srcs):
    """Kotlin `name$default`-мост форвардит СВОИ параметры в скрытый вызов →
    каждый проброшенный аргумент вырождается в {k:param}. Реальные литералы —
    у вызывающего МОСТ (кладёт их в invoke name$default перед mask+marker).
    Один хоп вверх к первому НЕ-синтетическому вызывающему: param-источник
    заменяем источником соответствующего фактического аргумента $default, если
    тот конкретен (монотонно — только апгрейд param→значение). $default
    статический: факт.арг[0]=owner, семантический форвард-индекс i ↔ i+1.
    ponytail: один хоп, первый вызывающий — не points-to; глубже уводит в
    shared-interface routing (см. _DEPTH_LIMIT)."""
    bcls = _fqcn(bridge_ma.class_name)
    sites = [s for s in resolve_call_sites(dx, bcls, bridge_ma.name)
             if not s["caller"].split("->")[-1].endswith("$default")]
    if not sites:
        return srcs
    cfr = frame_of(sites[0]["caller_ma"])
    if cfr is None:
        return srcs
    by_idx = {c["index"]: c["source"]
              for c in arg_sources_of_call(cfr, sites[0]["offset"], bcls, bridge_ma.name)}
    out = []
    for s in srcs:
        src = s["source"]
        if src.get("k") == "param":
            up = by_idx.get(s["index"] + 1)   # +1: факт.арг[0] моста = owner
            if up and _is_concrete_source(up):
                src = up
        out.append({"index": s["index"], "source": src})
    return out


def _ctor_args_of(fr, block, use_pos, dto_reg, dto_type):
    """Провенанс фактических ctor-аргументов инлайн-DTO (статический продюсер
    полей тела запроса). Ищет invoke-direct <dto_type>-><init> на регистре
    dto_reg (в блоке и по цепочке единственных предшественников назад от
    use_pos) и классифицирует каждый ctor-аргумент тем же classify_operand.
    [] если <init> не найден (DTO собран не тривиально / построен фабрикой)."""
    b, start, seen = block, use_pos, set()
    while True:
        insns = fr["cfg"].nodes[b]["insns"]
        for i in range(min(start, len(insns) - 1), -1, -1):
            ins = insns[i]
            if (ins.op.startswith("invoke") and ins.args and ins.args[0]
                    and "-><init>(" in ins.args[0] and dto_type in ins.args[0]
                    and len(ins.args) > 1 and ins.args[1] == dto_reg):
                out = []
                for idx, reg in enumerate(ins.args[2:]):  # args[1]=receiver(dto_reg)
                    k, d = classify_operand(fr["cfg"], b, i, reg, fr["params"])
                    out.append({"index": idx, "source_kind": k, "detail": d})
                return out
        if b in seen:
            return []
        seen.add(b)
        preds = list(fr["cfg"].predecessors(b))
        if len(preds) != 1:
            return []
        b = preds[0]
        start = len(fr["cfg"].nodes[b]["insns"]) - 1


_COROUTINE_FRAME_METHODS = {"invokeSuspend", "invoke", "create"}


def _is_coroutine_state_guard(guard):
    """Ruling-H (fix round 1, §5.3): страж — диспетчер state-machine корутины
    (label/захваченный локал continuation), а не реальный activation guard,
    если ОБА условия верны:
      - рамка страж — invokeSuspend/invoke/create (машинерия Kotlin-continuation/
        лямбды; матчим по ИМЕНИ метода, не по классу — класс может быть
        обфусцирован, имя метода переживает обфускацию);
      - тестируемый операнд — field, и владелец поля (класс перед '->' в
        detail вида 'Lpkg/Cls;->name TYPE') совпадает с классом самой рамки
        (self-field, не поле/вызов ДРУГОГО объекта).
    Реальные guards (auth-проверка, feature-флаг) — invoke/field на ЧУЖОМ
    объекте и остаются посчитанными.

    ponytail: эвристика помечает self-field стражи в continuation-кадрах
    (label + захваченные локалы); может пере-пометить настоящий guard на
    захваченном локале и не пометить state, спрятанное не в self-field —
    точность меряется в Task 7 (§8) на ground truth. Заодно компенсирует то,
    что is_plumbing не ловит обфусцированные continuation-классы — такие
    кадры здесь не отбрасываются молча, а помечаются с прозрачностью."""
    frame_cls, _, frame_method = guard["frame"].partition("->")
    if frame_method not in _COROUTINE_FRAME_METHODS:
        return False
    op = guard["operand"]
    if op["source_kind"] != "field" or not op["detail"] or "->" not in op["detail"]:
        return False
    owner_desc = op["detail"].split("->", 1)[0]
    return _fqcn(owner_desc) == frame_cls


@lru_cache(maxsize=4096)
def _is_continuation_class(dx, desc):
    """Класс-континуация suspend-функции: есть invokeSuspend (переопределение
    BaseContinuationImpl — имя переживает R8, в отличие от имени класса)."""
    ca = dx.classes.get(desc)
    return ca is not None and any(m.name == "invokeSuspend" for m in ca.get_methods())


def _reads_continuation(dx, guard):
    """Пролог стейт-машины внутри самой suspend-функции: `cont instanceof K`,
    чтение `K.label` (у R8 — `K->E I`) и знаковая проверка метки
    `if ((label & MIN_INT) != 0)`. Владелец поля — класс континуации, а не
    класс кадра, поэтому _is_coroutine_state_guard его не видит."""
    op = guard["operand"]
    if op["source_kind"] in ("field", "instanceof") and op["detail"]:
        if _is_continuation_class(dx, str(op["detail"]).partition("->")[0]):
            return True
    # знаковая проверка метки: тестируемый регистр — результат and-int (unknown),
    # но само поле-метку читает iget в том же блоке ветвления.
    if op["source_kind"] == "unknown":
        return any(_is_continuation_class(dx, str(d).partition("->")[0])
                   for d in guard.get("_block_refs", ()))
    return False


# ponytail: грубый, но консервативный список — точность валидируется в Task 7
# §8 на ground truth; апгрейд — расширять по факту false negative/positive.
_FRAMEWORK_OWNER_PREFIXES = ("android.", "androidx.", "java.", "kotlin.", "kotlinx.", "io.ktor.")
_FRAMEWORK_MEMBER_NAMES = {"ordinal", "areEqual", "checkNotNull", "checkNotNullParameter"}


def _is_framework_guard(guard):
    """Страж — фреймворк/компилятор-сгенерированный, не активационный (round-2
    review): операнд invoke/field, чей владелец — android/androidx/java/
    kotlin/kotlinx (Intrinsics сюда уже попадает — kotlin.jvm.internal.*),
    ЛИБО имя метода/поля — известная compiler-generated проверка. ordinal
    матчится по имени члена, а не по владельцу: enum в байткоде вызывает
    ordinal() на СВОЁМ классе (Lpkg/MyEnum;->ordinal()I), не java.lang.Enum."""
    op = guard["operand"]
    if op["source_kind"] not in ("invoke", "field", "instanceof") or not op["detail"]:
        return False
    owner_desc, _, rest = op["detail"].partition("->")
    if _fqcn(owner_desc).startswith(_FRAMEWORK_OWNER_PREFIXES):
        return True
    m = re.match(r"[^\s(]+", rest)
    return bool(m) and m.group() in _FRAMEWORK_MEMBER_NAMES


_PRIM = set("ZBSCIJFD")
_CONT = "Lkotlin/coroutines/Continuation;"

def _param_types(desc):
    """JVM-дескриптор метода '(...)ret' -> список дескрипторов параметров
    ['Ljava/lang/String;','I','[Z',...]. Пусто, если нет скобок."""
    m = re.search(r"\(([^)]*)\)", desc or "")
    if not m:
        return []
    s, out, i = m.group(1).replace(" ", ""), [], 0
    while i < len(s):
        arr = ""
        while i < len(s) and s[i] == "[":
            arr += "["; i += 1
        c = s[i]
        if c == "L":
            e = s.index(";", i)
            out.append(arr + s[i:e + 1]); i = e + 1
        else:
            out.append(arr + c); i += 1
    return out

def _hidden_desc(dx, cls, method):
    """Дескриптор скрытого Retrofit-метода cls->method (первая перегрузка)."""
    ca = dx.classes.get("L" + cls.replace(".", "/") + ";")
    if ca is None:
        return None
    for ma in ca.get_methods():
        if ma.name == method:
            return ma.descriptor
    return None

def _data_cost(sem_types):
    """Тир стоимости ДАННЫХ для активации (HTTP-аналог Таблицы IV RQ3): по
    семантическим аргументам (Continuation уже убран). none / primitive / object."""
    if not sem_types:
        return "none"
    return "primitive" if all(t[0] in _PRIM for t in sem_types) else "object"


_MARKER = "DefaultConstructorMarker"

def _is_enum(ca):
    """Класс — enum (конструировать нельзя, у activate.js $default возьмёт
    values()[0])."""
    sup = getattr(ca, "extends", None)
    if sup and "Enum;" in str(sup):
        return True
    return any(m.name == "values" for m in ca.get_methods())

def _ctor_params(ca):
    """Параметры «строительного» конструктора: среди <init> берём с наименьшим
    числом параметров, исключая синтетический Kotlin-дефолтный (…, int,
    DefaultConstructorMarker). None -> подходящего конструктора нет."""
    best = None
    for ma in ca.get_methods():
        if ma.name != "<init>":
            continue
        pts = _param_types(ma.descriptor)
        if any(_MARKER in t for t in pts):
            continue
        if best is None or len(pts) < len(best):
            best = pts
    return best

def _arg_recipes(dx, arg_types, depth=2):
    """Рецепты постройки объектных аргументов DTO: {jvm-тип: {"ctor": [типы
    параметров]}}. Рекурсия на объектных параметрах конструктора до depth
    уровней. String / enum / framework-классы / классы без конструктора НЕ
    пишутся — на них make_plan даст $default (пустая строка / values()[0] /
    null). Источник — androguard dx (уже загружен в срезе)."""
    recipes, seen = {}, set()
    def visit(t, d):
        if d < 0 or not t.startswith("L") or t in seen:
            return
        seen.add(t)
        if t == "Ljava/lang/String;" or _fqcn(t).startswith(_FRAMEWORK_OWNER_PREFIXES):
            return
        ca = dx.classes.get(t)
        if ca is None or _is_enum(ca):
            return
        pts = _ctor_params(ca)
        if pts is None:
            return
        recipes[t] = {"ctor": pts}
        for p in pts:
            visit(p, d - 1)
    for t in arg_types:
        visit(t, depth)
    return recipes


def _counts_as_guard(guard):
    return not guard["notes"] or guard["notes"] == ["third_party_sdk"]


def frame_guard_count(guards):
    return len({guard["branch_block"] for guard in guards if _counts_as_guard(guard)})


def _call_graph(walk, node_ids, guards, stops, frame_notes):
    frames = []
    for node in node_ids:
        method = walk["sites_by_node"][node]
        frames.append({"method": method_key(method), "descriptor": method.descriptor.replace(" ", ""),
                       "offset": node[1], "entry": walk["entry_nodes"].get(node),
                       "plumbing": node in walk["plumbing_nodes"], "stops": sorted(stops.get(node, ())),
                       "notes": frame_notes.get(node, []), "guards": guards.get(node, [])})
    edges = [{"from": node_ids[parent], "to": None if child == SINK else node_ids[child], "evidence": sorted(kinds)}
             for (parent, child), kinds in walk["edge_kinds"].items()]
    edges.sort(key=lambda edge: (edge["from"], -1 if edge["to"] is None else edge["to"]))
    return {"frames": frames, "edges": edges}


def _path_witness(candidates, distances, routes, node_ids, evidence):
    start = min((node for node in candidates if node in distances),
                key=lambda node: (distances[node], node_ids[node]), default=None)
    if start is None:
        return None
    frames, node = [], start
    while node != SINK:
        frames.append(node_ids[node])
        node = routes[node]
    return {"evidence": evidence, "frames": frames, "guard_count": distances[start]}


def slice_key(dx, key, *, descriptor=None, include_arguments=True, package=None):
    """Полная запись среза для одного ключа (схема спеки §4): обход вверх
    (Task 4) до фронтира/лимита, на каждом семантическом кадре — стражи
    (guards_of_frame). Кадр без кода (frame_of -> None, напр. внешнее/
    abstract-объявление) не роняет обход — помечается inconclusive и
    пропускается (Review Focus). Конвейер передаёт include_arguments=False,
    поскольку отдельно строит срез аргументов по DEX-дескриптору."""
    cls, _, method = key.partition("->")
    w = backward_frames(dx, cls, method, descriptor=descriptor)
    rec = {"key": key, "cls": cls, "method": method,
           "reached": w["reached"],
           "call_sites": [{"caller": s["caller"], "offset": s["offset"]} for s in w["call_sites"]],
           "call_graph": {"frames": [], "edges": []}, "witnesses": {},
           "guards": [], "guard_count": 0, "guard_count_coroutine": 0,
           "guard_count_framework": 0, "guard_count_third_party_sdk": 0, "activation_cost": None,
           "activation_exact": False, "best_known_complete_cost": None, "args": [],
           "activation_cost_modulo_allocation": None, "activation_exact_modulo_allocation": False,
           "first_uncertain_hop": min(w["first_uncertain_depth"].values(), default=None),
           "frontier": w["frontier"], "depth": w["depth"],
           "entry_evidence": {"ui": "not_found", "background": "not_found"},
           "coroutine_resume_edges": w["coroutine_resume_edges"], "coroutine_launch_edges": w["coroutine_launch_edges"],
           "plumbing_skipped": w["plumbing_skipped"], "inconclusive": False,
           "arg_types": [], "suspend": False, "data_cost": "none",
           "arg_recipes": {}, "notes": []}
    # Типы аргументов скрытого метода — собираем ВО ВРЕМЯ среза (dx уже загружен),
    # чтобы activate.py синтезировал args по типам без отдельной androguard-загрузки.
    # Continuation у suspend убираем из семантических — рантайм досылает его сам.
    # рецепты постройки объектных DTO-аргументов (тир object Таблицы IV): они
    # транзиентны, в куче их нет ($choose пусто) — activate.py строит их $new.
    if include_arguments:
        _pt = _param_types(descriptor or _hidden_desc(dx, cls, method))
        rec["suspend"] = bool(_pt) and _pt[-1] == _CONT
        rec["arg_types"] = [t for t in _pt if t != _CONT]
        rec["data_cost"] = _data_cost(rec["arg_types"])
        rec["arg_recipes"] = _arg_recipes(dx, rec["arg_types"])
    if not w["reached"]:
        # BFScan печатает JADX-алиасы имён (обфускация): такого класса/метода в DEX
        # нет вовсе — это артефакт статики, а не категория No caller
        known = bool(_declarations(dx, cls, method, descriptor))
        rec["notes"].append("no_caller" if known else "key_not_in_dex")
        return rec
    all_guards, seen, guard_instructions, weight = [], set(), {}, {}
    frame_guards, frame_notes = {}, {}
    missing_frames, offset_misses, disconnected_frames, exception_frames = set(), set(), set(), set()
    analyzed_nodes = {f["node"] for f in w["frames"]} | w["plumbing_nodes"]
    node_ids = {node: index for index, node in enumerate(sorted(
        w["sites_by_node"], key=lambda node: _site_order((w["sites_by_node"][node], node[1]))))}
    for node in node_ids:
        if node not in analyzed_nodes:
            continue
        ma = w["sites_by_node"][node]
        frame_key = method_key(ma)
        fr = frame_of(ma)
        if fr is None:
            missing_frames.add(node)
            continue
        block = fr["block_at"](node[1])
        if block is None:
            offset_misses.add(node)
            print(f"[предупреждение] {key}: unexpected_offset_miss; {frame_key} offset={node[1]}",
                  file=sys.stderr)
            continue
        handler_blocks = fr.get("handler_blocks", ())
        if handler_blocks:
            frame_notes[node] = ["exception_handlers_unmodeled"]
        if "normal_blocks" in fr and block not in fr["normal_blocks"]:
            disconnected_frames.add(node)
            continue
        if block in handler_blocks:
            exception_frames.add(node)
            continue
        frame_guards[node] = guards_of_frame(fr, node[1])
        for g in frame_guards[node]:
            g["frame"] = frame_key
            # флаги coroutine/framework взаимоисключающи (elif) — одним проходом,
            # чтобы вес кадра для минимума по путям (§7.1) считался по уже
            # очищенным стражам.
            if _is_coroutine_state_guard(g) or _reads_continuation(dx, g):
                g["notes"] = ["coroutine_state_machine"]
            elif (_is_framework_guard(g) or g["frame"].startswith(_FRAMEWORK_OWNER_PREFIXES)
                  # switch по enum: `aget ordinal` из $EnumSwitchMapping$ — таблица,
                  # сгенерированная компилятором, а не гейт приложения (§7.3)
                  or any("$EnumSwitchMapping$" in str(d) for d in g.get("_block_refs", ()))):
                g["notes"] = ["framework"]
            elif package and not g["frame"].startswith(package + "."):
                # Package boundaries also include first-party modules and relocated classes.
                g["notes"] = ["third_party_sdk"]
            g.pop("_block_refs", None)  # служебное, не в выход
            instruction = (node[0], g["branch_block"])
            guard_instructions.setdefault(instruction, g)
            sig = (*instruction, g["sense"])
            if sig not in seen:
                seen.add(sig)
                all_guards.append(g)
        weight[node] = frame_guard_count(frame_guards[node])
    unverified_frames = missing_frames | offset_misses | disconnected_frames | exception_frames
    rec["inconclusive"] = bool(unverified_frames)
    rec["guards"] = all_guards
    # Ruling-H: union guard_count — ВЕРХНЯЯ оценка (все стражи всех путей);
    # headline-метрика стоимости активации — activation_cost (минимум по путям).
    unique_guards = guard_instructions.values()
    rec["guard_count"] = sum(_counts_as_guard(g) for g in unique_guards)
    rec["guard_count_coroutine"] = sum("coroutine_state_machine" in g["notes"] for g in unique_guards)
    rec["guard_count_framework"] = sum("framework" in g["notes"] for g in unique_guards)
    rec["guard_count_third_party_sdk"] = sum("third_party_sdk" in g["notes"] for g in unique_guards)
    # §7.1: минимум реальных стражей по путям UI-вход -> скрытый вызов.
    children = {}
    for parent, child in sorted(w["edge_kinds"], key=lambda edge: node_ids[edge[0]]):
        children.setdefault(parent, set()).add(child)
    tops = (w["frontier_nodes"] | w["dead_end_nodes"] | w["capped_nodes"]
            | w["uncertain_callers"] | w["unexamined_dispatch"] | unverified_frames)
    if w["budget_hit"]:
        # An unprocessed initial site may have no guards at all.
        tops.add(SINK)
    routes = []
    distances = _guard_distances(
        weight, children, SINK, cha_uncertain=w["cha_uncertain"],
        allocation_uncertain=w["allocation_uncertain"], missing_frames=unverified_frames, routes=routes)
    cost, exact, complete, modulo = _guard_costs(distances, tops, w["frontier_nodes"])
    for reachable, evidence in zip(distances, ("possible", "modulo_allocation", "resolved")):
        for node, kind in w["entry_nodes"].items():
            if node in reachable:
                rec["entry_evidence"][kind] = evidence
    stops = {node: {reason} for node, reason in w["stop_reasons"].items()}
    for nodes, reason in ((w["capped_nodes"], "depth_cap"), (w["budget_nodes"], "budget_hit"),
                          (w["dispatch_capped"], "fanin_capped"),
                          (w["unexamined_dispatch"], "unexamined_dispatch"),
                          (missing_frames, "missing_frame"), (offset_misses, "unexpected_offset_miss"),
                          (disconnected_frames, "unreachable_from_method_entry"),
                          (exception_frames, "exception_flow_unresolved")):
        for node in nodes:
            stops.setdefault(node, set()).add(reason)
    if not stops and not w["entry_nodes"]:
        for node in children:
            if SINK in children[node]:
                stops[node] = {"no_entry_in_graph"}
    rec["call_graph"] = _call_graph(w, node_ids, frame_guards, stops, frame_notes)
    for reachable, path, evidence in zip(distances, routes, ("possible", "modulo_allocation", "resolved")):
        for kind, status in rec["entry_evidence"].items():
            if status == evidence:
                candidates = (node for node, entry_kind in w["entry_nodes"].items() if entry_kind == kind)
                rec["witnesses"][kind] = _path_witness(candidates, reachable, path, node_ids, evidence)
    partial = _path_witness(stops, distances[0], routes[0], node_ids, "partial")
    if partial is not None:
        rec["witnesses"]["partial"] = partial
    rec["activation_cost_modulo_allocation"] = modulo
    rec["activation_exact_modulo_allocation"] = modulo is not None and modulo == cost and not w["budget_hit"]
    if rec["activation_exact_modulo_allocation"] and not exact:
        rec["notes"].append("allocation_certified")
    rec["activation_cost"], rec["activation_exact"] = cost, exact and not w["budget_hit"]
    rec["best_known_complete_cost"] = complete
    if missing_frames:
        rec["notes"].append("missing_frame")
    if offset_misses:
        rec["notes"].append("unexpected_offset_miss")
    if disconnected_frames:
        rec["notes"].append("unreachable_from_method_entry")
    if exception_frames:
        rec["notes"].append("exception_flow_unresolved")
    if cost is None:
        # ни один top (фронтир/dead_end/depth_cap) не дотянулся до скрытого вызова:
        # все пути обрываются на плумбинге — стоимость активации не определена
        rec["notes"].append("no_semantic_entry")
    # round-2 review Fix 1: происхождение аргументов скрытого вызова (спека
    # §5.7) — по ПЕРВОМУ call-site (данных-ось не требует нескольких путей,
    # как guard-сторона; симметрично её простоте).
    first = w["call_sites"][0]
    fr0 = frame_of(first["caller_ma"]) if include_arguments else None
    if fr0 is not None:
        rec["args"] = args_of_call(fr0, first["offset"], cls, method)
        asrc = arg_sources_of_call(fr0, first["offset"], cls, method)
        # $default-мост форвардит свои параметры → проброшенные аргументы = param;
        # один хоп вверх к реальному вызывающему моста поднимает литералы (§5.7).
        if first["caller_ma"].name.endswith("$default") and any(
                s["source"].get("k") == "param" for s in asrc):
            asrc = _climb_default_bridge(dx, first["caller_ma"], asrc)
        rec["arg_sources"] = asrc
    if w["depth_capped"]:
        rec["notes"].append("depth_cap")
    if w["dead_ends"]:
        rec["notes"].append("dead_end")
        reasons = {w["stop_reasons"][node] for node in w["dead_end_nodes"]}
        rec["notes"].extend(f"dead_end:{reason}" for reason in sorted(reasons))
    if w["cha_used"]:
        # хотя бы один вызывающий найден по CHA (полиморфный вызов) — путь, а
        # значит и activation_cost, возможно over-approximated (§7.2)
        rec["notes"].append("cha")
    if w["allocation_used"]:
        rec["notes"].append("allocation_xref")
    if w["viewmodel_candidate"]:
        rec["notes"].append("viewmodel_constructor_candidate")
    if w["compose_dead_end"]:
        rec["notes"].append("possible_compose_dead_end")
    if w["unexamined_dispatch"]:
        rec["notes"].append("unexamined_dispatch")
    if w["budget_hit"]:
        # обход упёрся в потолок кадров (взрывной fan-in) — граф неполон,
        # activation_cost ненадёжен; ключ честно помечается
        rec["notes"].append("budget_hit")
    return rec


def run(dx, keys):
    """Срез по списку ключей -> список записей (порядок сохраняется)."""
    return [slice_key(dx, k) for k in keys]


def _check_slice_key(dx):
    rec = slice_key(dx, "gpm.tnt_premier.features.downloads.impl.data.network.DownloadsApi->disallowDeviceDownload")
    assert "unexpected_offset_miss" not in rec["notes"], rec["notes"]
    assert rec["reached"] is True
    assert rec["cls"].endswith("DownloadsApi") and rec["method"] == "disallowDeviceDownload"
    assert isinstance(rec["guards"], list)
    assert (rec["guard_count"] + rec["guard_count_coroutine"] + rec["guard_count_framework"]
            <= len(rec["guards"]))
    assert set(("reached", "call_sites", "guards", "args", "frontier", "inconclusive",
                "guard_count_coroutine", "guard_count_framework",
                "activation_cost", "activation_exact")) <= set(rec)
    assert all("notes" in g for g in rec["guards"])
    # §7.1: минимум по путям не больше объединения (union) — верхней оценки
    assert rec["activation_cost"] is None or rec["activation_cost"] <= rec["guard_count"], rec
    # Ruling-H (fix round 1): известный кейс несёт coroutine state-machine
    # стражи (continuation TT->invokeSuspend/invoke, self-field label) —
    # они помечены и НЕ входят в headline guard_count; регрессия отката
    # флага (guard_count == len(guards)) здесь бы провалила assert.
    assert rec["guard_count_coroutine"] > 0, rec
    assert rec["guard_count"] < len(rec["guards"]), rec
    # ключ-форвардер без стражей: guard_count 0, не падение (Review Focus)
    assert rec["guard_count"] >= 0
    # round-2 review Fix 1: известный кейс имеет явные аргументы на первом
    # call-site — args должен быть непустым и нести схему {index,source_kind,detail}.
    assert rec["args"], rec
    assert set(("index", "source_kind", "detail")) <= set(rec["args"][0])
    # тир object: disallowDeviceDownload принимает request-body DTO → для него
    # собран рецепт постройки (ctor с типами параметров), не пустой.
    assert rec["data_cost"] == "object", rec["arg_types"]
    assert rec["arg_recipes"], rec["arg_types"]
    assert all("ctor" in v and isinstance(v["ctor"], list)
               for v in rec["arg_recipes"].values()), rec["arg_recipes"]
    print("  slice_key ok")


def load_hidden(path, *, include_caveats=True):
    """Read unique hidden keys in catalog order, with an optional confidence filter."""
    keys, seen = [], set()
    with Path(path).open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            status = row.get("status")
            if status in ("observed", "meta"):
                continue
            if status not in ("hidden", "not_observed"):
                print(f"[предупреждение] {path}:{number}: пропущен неизвестный статус {status!r}",
                      file=sys.stderr)
                continue
            if not include_caveats and row.get("confidence_caveats") != []:
                continue
            key = row["key"]
            if key not in seen:
                seen.add(key)
                keys.append(key)
    return keys


def report(records, meta=None):
    """records (из run()) -> человекочитаемый отчёт: шапка (totals),
    распределение guard_count (сырьё для Таблицы IV), топ источников
    стражей, построчный листинг.

    Ruling-H: guard_count в записи уже "чистый" (coroutine state-machine
    стражи исключены Task 5) — распределение использует его как есть. Топ
    источников ДОПОЛНИТЕЛЬНО фильтрует по guard["notes"]: без этого
    self-поля state-machine (label, захваченный continuation), которые не
    входят в guard_count, всё равно засоряли бы список источников их
    отдельным проходом по guards[]. Общее число флагованных стражей
    показывается отдельной строкой — шум виден, но не смешан с headline-
    метрикой."""
    lines = []
    w = lines.append
    if meta:
        w(f"Приложение: {meta.get('package')} versionName={meta.get('versionName')} "
          f"versionCode={meta.get('versionCode')}")
    if meta and "status" in meta and "build" in meta:
        w(f"Сборка: {meta['build']} | Статус артефакта: {meta['status']}")
    total = len(records)
    w(f"Записей среза: {total}. Распределения ниже рассчитаны по записям среза.")
    reached = sum(r["reached"] for r in records)
    not_in_dex = sum(1 for r in records if "key_not_in_dex" in r["notes"])
    unresolved = sum(1 for r in records if r.get("analysis_scope") == "unresolved")
    no_caller = total - reached - not_in_dex - unresolved
    dead = sum(1 for r in records if "dead_end" in r["notes"])
    inconcl = sum(1 for r in records if r.get("inconclusive"))
    coroutine_total = sum(r.get("guard_count_coroutine", 0) for r in records)
    framework_total = sum(r.get("guard_count_framework", 0) for r in records)
    w(f"Всего ключей: {len({r['key'] for r in records})} | reached: {reached} | no_caller: {no_caller} | "
      f"key_not_in_dex: {not_in_dex} | inconclusive: {inconcl}")
    if any("entry_evidence" in r for r in records):
        for kind, label in (("ui", "Точки входа UI"), ("background", "Фоновые точки входа")):
            states = Counter(r.get("entry_evidence", {}).get(kind, "not_found") for r in records)
            summary = ", ".join(f"{state}={states[state]}"
                                for state in ("resolved", "modulo_allocation", "possible", "not_found"))
            w(f"{label}: {summary}")
    if any("coroutine_resume_edges" in r for r in records):
        resumed = sum(r.get("coroutine_resume_edges", 0) > 0 for r in records)
        launched = sum(r.get("coroutine_launch_edges", 0) > 0 for r in records)
        w(f"Объявления со связью через возобновление suspend-функции: {resumed}")
        w(f"Объявления с локально установленным запуском корутины: {launched}")
    if unresolved:
        w(f"DEX-дескриптор не разрешён: {unresolved}")
    w(f"Обход оборван не на фронтире (dead_end, стражи выше пути не видны): {dead}")
    compose_ends = sum("possible_compose_dead_end" in r["notes"] for r in records)
    candidates = sum("viewmodel_constructor_candidate" in r["notes"] for r in records)
    compose_fraction = compose_ends / dead if dead else 0
    w(f"Тупики с возможным участием Compose: {compose_ends}/{dead} ({compose_fraction:.1%})")
    w(f"Срезы с конструктором ViewModel на пути: {candidates}/{total}")
    for reason in ("fanin_capped", "no_callers"):
        keys = {r["key"] for r in records if "dead_end:" + reason in r["notes"]}
        w(f"  dead_end:{reason}: {len(keys)} уникальных ключей")
    w("Подгруппы dead_end могут пересекаться и не суммируются.")
    w(f"Стражи state-machine корутин (флагованы, исключены из guard_count и топа источников): {coroutine_total}")
    w(f"Стражи фреймворка/компилятора (флагованы, исключены из guard_count и топа источников): {framework_total}")
    sdk_total = sum(r.get("guard_count_third_party_sdk", 0) for r in records)
    w(f"Стражи вне пакета приложения (third_party_sdk, учитываются в guard_count): {sdk_total}")
    hops = Counter(r["first_uncertain_hop"] for r in records if r.get("first_uncertain_hop") is not None)
    w("Распределение глубины первой неопределённости пути:")
    for hop, count in sorted(hops.items()):
        w(f"  {hop}: {count}")
    dist = Counter(min(r["guard_count"], 4) for r in records if r["reached"])
    w("Распределение guard_count — объединение стражей на исследованных путях:")
    for k in range(5):
        label = "4+" if k == 4 else str(k)
        w(f"  {label} стражей: {dist.get(k, 0)}")
    # §7.1: минимум по путям — стоимость активации. Таблица IV строится ТОЛЬКО по
    # ключам с activation_exact (путь дошёл до UI-входа); остальные — нижняя оценка.
    exact = [r for r in records if r["reached"] and r.get("activation_exact")]
    modulo = [r for r in records if r.get("activation_exact_modulo_allocation") and not r.get("activation_exact")]
    lower = [r for r in records if r["reached"] and not r.get("activation_exact")
             and not r.get("activation_exact_modulo_allocation") and r.get("activation_cost") is not None]
    adist = Counter(min(r["activation_cost"], 4) for r in exact)
    w(f"Точный минимум по статической модели до колбэка: {len(exact)} записей")
    for k in range(5):
        label = "4+" if k == 4 else str(k)
        w(f"  {label} стражей: {adist.get(k, 0)}")
    w(f"Нижняя оценка (точный минимум до входа не установлен): {len(lower)} записей")
    undet = [r for r in records if r.get("activation_cost") is None]
    w(f"Стоимость не определена: {len(undet)} записей, из них без найденного места вызова: "
      f"{sum(not r['reached'] and r.get('analysis_scope') != 'unresolved' for r in undet)}")
    # Стоимость ДАННЫХ (HTTP-аналог тиров «+Data support» RQ3): по типам аргументов
    # скрытого метода. none=нет аргументов (активируется прямым вызовом), primitive=
    # только примитивы (дефолты), object=есть объектные арги (нужен живой инстанс/синтез).
    if any("data_cost" in r for r in records):
        dc = Counter(r.get("data_cost", "none") for r in records if r["reached"])
        susp = sum(1 for r in records if r["reached"] and r.get("suspend"))
        w(f"Стоимость данных (типы аргументов скрытого метода): "
          f"none(без аргументов): {dc.get('none', 0)} | "
          f"primitive(только примитивы): {dc.get('primitive', 0)} | "
          f"object(есть объектные): {dc.get('object', 0)} | из них suspend: {susp}")
    src = Counter(g["operand"]["detail"] for r in records for g in r.get("guards", ())
                  if _counts_as_guard(g) and g["operand"]["source_kind"] in ("invoke", "field", "instanceof")
                  and g["operand"]["detail"])
    if src:
        w("Топ источников стражей:")
    for name, n in src.most_common(15):
        w(f"  {n:3d}  {name}")
    w("")
    sections = [
        ("Точная оценка (exact)", exact),
        ("Точная оценка с точностью до создания лямбды (exact_modulo_allocation)", modulo),
        ("Нижняя оценка (lower)", lower),
        ("Неопределённая стоимость (undet)", undet),
    ]
    for title, group in sections:
        w(f"{title} — {len(group)}")
        for r in group:
            tag = "HIDDEN" if r["reached"] else "NO-CALLER"
            if r.get("status") == "observed":
                tag = "OBSERVED"
            if r.get("analysis_scope") == "unresolved":
                tag = "UNRESOLVED"
            ac = r.get("activation_cost")
            acs = (f"{ac}{'' if r.get('activation_exact') else '+'}" if ac is not None else "?")
            frontier = f"frontier={r['frontier']} " if "frontier" in r else ""
            name = r["key"] + (r.get("descriptor") or "")
            declaration = f"declaration_id={r['declaration_id']} " if "declaration_id" in r else ""
            best = r.get("best_known_complete_cost")
            best_text = str(best) if best is not None else "?"
            alloc_cost = r.get("activation_cost_modulo_allocation")
            alloc_text = f" activation_cost_modulo_allocation={alloc_cost}" if alloc_cost is not None else ""
            evidence = r.get("entry_evidence")
            entry_text = f" ui={evidence['ui']} background={evidence['background']}" if evidence else ""
            w(f"[{tag}] {name}  {declaration}activation_cost={acs} best_known_complete_cost={best_text}{alloc_text} "
              f"guard_count(union)={r['guard_count']} "
              f"{frontier}notes={r['notes']}{entry_text}")
            for kind, witness in r.get("witnesses", {}).items():
                frames = [r["call_graph"]["frames"][i] for i in witness["frames"]]
                route = " → ".join(f"{f['method']}{f['descriptor']}@{f['offset']}" for f in frames)
                stop = f" stop={','.join(frames[0]['stops'])}" if kind == "partial" else ""
                w(f"    {kind} ({witness['evidence']}, стражей {witness['guard_count']}{stop}) {route} → {name}")
            for g in r.get("guards", ()):
                o = g["operand"]
                flag = f" [{','.join(g['notes'])}]" if g["notes"] else ""
                w(f"    {g['opcode']} {g['sense']}  <- {o['source_kind']}:{o['detail']}  @{g['frame']}{flag}")
        w("")
    return "\n".join(lines)


def _check_report():
    recs = [
        {"key": "a->x", "cls": "a", "method": "x", "reached": True,
         "call_sites": [{"caller": "c->x", "offset": 1}],
         "guards": [
             {"frame": "c->x", "opcode": "if-eqz", "sense": "->true",
              "operand": {"source_kind": "invoke", "detail": "S->isLoggedIn()Z"}, "notes": []},
             # coroutine-флагованный self-field guard — не должен попасть в топ источников
             {"frame": "T->invokeSuspend", "opcode": "if-eqz", "sense": "->false",
              "operand": {"source_kind": "field", "detail": "T->label I"},
              "notes": ["coroutine_state_machine"]},
             # round-2 review Fix 2: framework-флагованный guard — тоже не в топ
             {"frame": "c->x", "opcode": "if-eqz", "sense": "->true",
              "operand": {"source_kind": "invoke",
                          "detail": "Lkotlin/jvm/internal/Intrinsics;->areEqual(Ljava/lang/Object;Ljava/lang/Object;)Z"},
              "notes": ["framework"]},
         ],
         "guard_count": 1, "guard_count_coroutine": 1, "guard_count_framework": 1, "args": [],
         "frontier": "F->onCreate", "depth": 2, "plumbing_skipped": [],
         "inconclusive": False, "notes": []},
        {"key": "b->y", "cls": "b", "method": "y", "reached": False,
         "call_sites": [], "guards": [], "guard_count": 0, "guard_count_coroutine": 0,
         "guard_count_framework": 0, "args": [], "frontier": None, "depth": 0,
         "plumbing_skipped": [], "inconclusive": False, "notes": ["no_caller"]},
    ]
    txt = report(recs)
    assert "guard_count" in txt and "no_caller" in txt.lower()
    assert "1 стражей: 1" in txt  # распределение: один reached-ключ с 1 стражем
    # fix round 1: meta (пакет/версия) должна попасть в шапку — паритет сборки
    # со static+dynamic, как в diff.py (Spec §4)
    meta = {"package": "p", "versionName": "1.0", "versionCode": "42"}
    txt_meta = report(recs, meta=meta)
    assert "Приложение: p versionName=1.0 versionCode=42" in txt_meta
    # Ruling-H / round-2 Fix 2: топ источников — реальный guard входит,
    # coroutine- и framework-флагованные — нет
    top_section = txt.split("Топ источников")[1].split("\n\n")[0]
    assert "S->isLoggedIn()Z" in top_section
    assert "T->label" not in top_section
    assert "Intrinsics" not in top_section
    # построчный листинг НЕ скрывает флагованные стражи — просто помечает их
    # (прозрачность, не молчаливое отбрасывание)
    assert "T->label" in txt and "[coroutine_state_machine]" in txt
    assert "[framework]" in txt
    # общее число флагованных стражей каждого вида видно отдельной строкой
    assert "Стражи state-machine корутин" in txt and "1" in txt.split("корутин")[1].split("\n")[0]
    assert "Стражи фреймворка/компилятора" in txt and "1" in txt.split("компилятора")[1].split("\n")[0]
    both = dict(recs[0], notes=["dead_end", "dead_end:fanin_capped", "dead_end:no_callers"])
    grouped = report([dict(both, declaration_id=1), dict(both, declaration_id=2), recs[1]])
    assert "Всего ключей: 2" in grouped
    assert all(f"dead_end:{r}: 1 уникальных ключей" in grouped for r in ("fanin_capped", "no_callers"))
    assert grouped.count("[HIDDEN] a->x") == 2
    assert grouped.index("(exact)") < grouped.index("(exact_modulo_allocation)") < grouped.index("(lower)") < grouped.index("(undet)")
    print("  report ok")


def _check_framework_guard():
    def g(kind, detail):
        return {"operand": {"source_kind": kind, "detail": detail}, "notes": []}
    # владелец — android/androidx/java/kotlin/kotlinx -> фреймворк
    assert _is_framework_guard(g("invoke", "Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;"))
    assert _is_framework_guard(g("invoke", "Landroidx/fragment/app/Fragment;->getView()Landroid/view/View;"))
    assert _is_framework_guard(g("invoke", "Ljava/lang/String;->length()I"))
    assert _is_framework_guard(g("invoke",
        "Lkotlin/jvm/internal/Intrinsics;->areEqual(Ljava/lang/Object;Ljava/lang/Object;)Z"))
    assert _is_framework_guard(g("invoke", "Lkotlinx/coroutines/JobKt;->Job()Lkotlinx/coroutines/Job;"))
    # enum ordinal на СВОЁМ (не android/kotlin) классе — матчим по имени члена
    assert _is_framework_guard(g("invoke", "Lcom/app/Status;->ordinal()I"))
    # обычный app-guard (auth/feature-флаг) — не фреймворк, остаётся в guard_count
    assert not _is_framework_guard(g("invoke", "Lcom/app/SessionManager;->isLoggedIn()Z"))
    assert not _is_framework_guard(g("field", "Lcom/app/Config;->featureX Z"))
    # пролог suspend-функции: label/instanceof класса-континуации (есть invokeSuspend)
    M = namedtuple("M", "name")
    C = namedtuple("C", "methods")
    C.get_methods = lambda self: self.methods
    dx = type("DX", (), {"classes": {"Lk70;": C([M("invokeSuspend")]), "Lcom/app/Cfg;": C([M("get")])}})()
    assert _reads_continuation(dx, g("field", "Lk70;->E I"))
    assert _reads_continuation(dx, g("instanceof", "Lk70;"))
    assert not _reads_continuation(dx, g("field", "Lcom/app/Cfg;->on Z"))
    # знаковая проверка метки: операнд unknown (результат and-int), но блок
    # читает поле-метку класса-континуации -> плумбинг
    sign = {"operand": {"source_kind": "unknown", "detail": None}, "notes": [],
            "_block_refs": ["Lk70;->E I"]}
    assert _reads_continuation(dx, sign)
    # тот же unknown, но блок читает поле обычного класса -> настоящий страж
    real = {"operand": {"source_kind": "unknown", "detail": None}, "notes": [],
            "_block_refs": ["Lcom/app/Cfg;->flag Z"]}
    assert not _reads_continuation(dx, real)
    print("  framework_guard ok")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hidden", type=Path, help="out/<pkg>.hidden.jsonl")
    ap.add_argument("--apk", type=Path, help="apk/<pkg>.apk (та же сборка)")
    ap.add_argument("--out", type=Path, help="куда сохранить slice.jsonl")
    ap.add_argument("--selfcheck", action="store_true")
    args = ap.parse_args()
    if args.selfcheck:
        _selfcheck(args.apk)
        return
    if not (args.hidden and args.apk):
        ap.error("нужны --hidden и --apk")
    keys = load_hidden(args.hidden)
    print(f"[срез] скрытых ключей: {len(keys)}; загрузка APK (androguard, ~1–2 мин)...",
          file=sys.stderr)
    apk_obj, dx = load_apk(args.apk)
    # Spec §4: паритет сборки со static+dynamic (как diff.py) — пакет/версия
    # из манифеста, который androguard уже распарсил внутри load_apk.
    meta = {"package": apk_obj.get_package(),
            "versionName": apk_obj.get_androidversion_name(),
            "versionCode": apk_obj.get_androidversion_code()}
    want = next((r.get("versionCode") for r in map(json.loads, filter(str.strip,
                 args.hidden.read_text(encoding="utf-8").splitlines()))
                 if r.get("status") == "meta"), None)
    if want and str(want) != str(meta["versionCode"]):
        sys.exit(f"error: {args.hidden} снят со сборки versionCode={want}, APK — "
                 f"{meta['versionCode']}: чужие ключи молча ушли бы в no_caller")
    print(f"[срез] APK загружен, строю срез по {len(keys)} ключам...", file=sys.stderr)
    records = []
    for i, k in enumerate(keys, 1):
        records.append(slice_key(dx, k, package=meta["package"]))
        print(f"  [{i}/{len(keys)}] {k.split('->')[-1]}", file=sys.stderr)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    txt = report(records, meta=meta)
    print(txt)
    if args.out:
        report_path = args.out.with_suffix(".report.txt")
        report_path.write_text(txt, encoding="utf-8")
        print(f"\n→ {args.out}\n→ {report_path}", file=sys.stderr)


def _selfcheck(apk=None):
    _check_cha()
    _check_min_path()
    _check_control_deps()
    _check_classify_operand()
    _check_ctor_args()
    _check_alias()
    _check_phi()
    _check_walk_predicates()
    _check_guard_operand()
    _check_framework_guard()
    _check_report()
    if apk:
        _, dx = load_apk(apk)  # APK-объект здесь не нужен, только dx
        _check_androguard(dx)  # уже принимает dx (Ruling-C: без повторной загрузки APK)
        _check_slice_key(dx)
    print("selfcheck ok")


if __name__ == "__main__":
    main()
