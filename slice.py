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
from collections import Counter, deque, namedtuple
from functools import lru_cache
from pathlib import Path

from loguru import logger
logger.remove()  # androguard DEBUG-флуд — до его импорта
import networkx as nx
from androguard.misc import AnalyzeAPK
from androguard.core.dex.dex_types import Operand

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
    if ins.op == "instance-of":  # `if (r is Result.Error)` — сигнал Server/Error handling
        return ("instanceof", ins.args[0] if ins.args else None)
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


def min_path_guards(weight, children, tops, frontier, sink):
    """Минимум реальных стражей на пути UI-вход -> скрытый вызов (открытый
    вопрос §7.1: стоимость активации = минимум по путям, а не объединение).

    weight:   node_id -> число реальных (не-флагованных) стражей кадра; у плумбинга 0.
    children: node_id -> множество node_id, которые кадр вызывает ВНИЗ к sink
              (у call-site'ов среди children есть sink; у sink детей нет).
    tops:     node_id максимальных кадров обхода (фронтир | dead_end | depth_cap).
    frontier: подмножество tops — настоящие UI/lifecycle/exported-входы.
    sink:     синтетический узел скрытого вызова, weight[sink] = 0.

    dist(n) = weight(n) + min(dist(c) for c in children(n)); dist(sink)=0.
    Веса неотрицательны -> задача шортест-пат: Дейкстра от sink по обратным
    рёбрам (итеративно, без рекурсии — граф кадров с CHA бывает глубже лимита
    стека Python; циклы Дейкстра обрабатывает естественно, не удешевляя путь).

    Возвращает (cost, exact):
      cost  — минимум по frontier-входам, дотянувшимся до sink; если таких нет —
              нижняя оценка по всем tops (путь оборван, выше могли быть ещё
              стражи); None, если ни один top не достигает sink.
      exact — True, если cost достигнут настоящим UI-входом И ни один оборванный
              top не дешевле (т.е. истинная стоимость не может быть ниже)."""
    import heapq
    INF = float("inf")
    parents = {}  # обратные рёбра: child -> множество его родителей (вызывающих)
    for p, cs in children.items():
        for c in cs:
            parents.setdefault(c, set()).add(p)
    dist = {sink: 0}
    pq, cnt = [(0, 0, sink)], 1  # cnt — тай-брейк, чтобы heap не сравнивал узлы
    while pq:
        d, _, n = heapq.heappop(pq)
        if d > dist.get(n, INF):
            continue
        for p in parents.get(n, ()):
            nd = weight.get(p, 0) + d
            if nd < dist.get(p, INF):
                dist[p] = nd
                heapq.heappush(pq, (nd, cnt, p)); cnt += 1

    fcost = min((dist.get(f, INF) for f in frontier), default=INF)
    tcost = min((dist.get(t, INF) for t in tops), default=INF)
    if fcost == INF:
        return (None if tcost == INF else tcost), False
    # fcost конечен: истинная стоимость через UI = fcost. exact, только если ни
    # один оборванный top не дешевле (иначе настоящий путь может быть короче).
    return fcost, (fcost <= tcost)


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
    class FCA:
        def __init__(self, ext, impl, methods, external=False):
            self.extends, self.implements, self._m, self._ext = ext, impl, methods, external
        def is_external(self): return self._ext
        def get_methods(self): return self._m
    caller = FMA("onCreate", "()V", "LA;")
    i_m = FMA("m", "()V", "LI;", callers=[(caller, 10)])      # вызывающий висит на I.m()
    c_m = FMA("m", "()V", "LC;")                               # у реализации прямого xref нет
    dx = type("DX", (), {})()
    dx.classes = {"LI;": FCA(None, [], [i_m], external=False),
                  "LB;": FCA("Ljava/lang/Object;", [], []),
                  "LC;": FCA("LB;", ["LI;"], [c_m])}
    _cha_supers.cache_clear()
    assert set(_cha_supers(dx, "LC;")) == {"LB;", "LI;"}, _cha_supers(dx, "LC;")
    sites, used = cha_caller_sites(dx, c_m)
    assert used and (caller, 10) in sites, (sites, used)
    # у метода с прямым xref и без супертипов CHA ничего не добавляет
    _cha_supers.cache_clear()
    sites2, used2 = cha_caller_sites(dx, i_m)
    assert used2 is False and (caller, 10) in sites2, (sites2, used2)
    print("  cha ok")


def _check_min_path():
    sink = "H"
    # ромб: вход E -> {A,B} -> C -> H; A несёт 2 стража, B — 0, C — 1.
    # дешёвый путь E-B-C-H = 0+0+1 = 1 страж.
    weight = {"E": 0, "A": 2, "B": 0, "C": 1, sink: 0}
    children = {"E": {"A", "B"}, "A": {"C"}, "B": {"C"}, "C": {sink}}
    cost, exact = min_path_guards(weight, children, {"E"}, {"E"}, sink)
    assert (cost, exact) == (1, True), (cost, exact)

    # оборванный путь дешевле фронтира: frontier F (1 страж) -> C(1) -> H,
    # dead_end D (0) -> C(1) -> H. Настоящий UI-путь = 2, но через D может быть 1
    # -> cost=2, exact=False (истинная стоимость может быть ниже).
    weight = {"F": 1, "D": 0, "C": 1, sink: 0}
    children = {"F": {"C"}, "D": {"C"}, "C": {sink}}
    cost, exact = min_path_guards(weight, children, {"F", "D"}, {"F"}, sink)
    assert (cost, exact) == (2, False), (cost, exact)

    # ни один фронтир не дотянулся: только dead_end D(2)->C(1)->H -> нижняя оценка 3
    cost, exact = min_path_guards({"D": 2, "C": 1, sink: 0},
                                  {"D": {"C"}, "C": {sink}}, {"D"}, set(), sink)
    assert (cost, exact) == (3, False), (cost, exact)

    # цикл в графе вызовов не зацикливает и не удешевляет: A<->B, A->H, оба по 1
    cost, exact = min_path_guards({"A": 1, "B": 1, sink: 0},
                                  {"A": {"B", sink}, "B": {"A"}}, {"B"}, {"B"}, sink)
    assert (cost, exact) == (2, True), (cost, exact)  # B->A->H = 1+1
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
    print("  classify_operand ok")


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


def resolve_call_sites(dx, cls, method):
    """Все вызовы cls->method по XREF. Внешние методы не отсеиваются — метод
    может быть интерфейсным объявлением (у него самого нет кода, но есть
    xref_from от вызывающих через invoke-interface). Пусто, если метод не
    найден или XREF пуст (не ошибка)."""
    # Прямой lookup по dx.classes, не dx.find_methods: тот гоняет regex по ВСЕМ
    # классам APK на каждый вызов, а обход зовёт резолв на каждый кадр.
    ca = dx.classes.get("L" + cls.replace(".", "/") + ";")
    sites = []
    for ma in (ca.get_methods() if ca else ()):
        if ma.name != method:
            continue
        for xf in ma.get_xref_from():
            caller_ma, off = xf[1], xf[-1]
            sites.append({"caller": method_key(caller_ma),
                          "caller_ma": caller_ma, "offset": off})
    return sites


_CHA_FANIN_CAP = 16      # больше вызывающих у полиморфного метода -> общий интерфейс, не граница
_FRAME_BUDGET = 4000     # потолок кадров на ключ: гарантия завершения при взрывном fan-in
# Лимит глубины пути. Проверено на TNT: углубление НЕ помогает покрытию. При
# limit=12 точных ключей стало меньше (29->27), шум стражей вырос в 5-13x, а
# dead_end 100->115 — глубже обход лишь проходит больше промежуточных кадров и
# упирается в общие DI/clean-arch интерфейсы (их CHA режет по _CHA_FANIN_CAP), не
# доходя до UI; заодно более дешёвые оборванные top'ы демотируют бывшие точные
# ключи. Ограничитель покрытия здесь архитектурный (shared-interface routing), не
# глубина — его пробил бы points-to/RTA (whole-app, отвергнут в дизайне §2.1/§11),
# а не CHA. limit=6 даёт лучший баланс точность/шум.
_DEPTH_LIMIT = 6


@lru_cache(maxsize=None)
def _cha_supers(dx, class_desc):
    """Транзитивные супертипы класса (extends + implements), существующие в APK
    (внешние/Object отбрасываются). Кэш — обход зовёт на каждый кадр, иерархия
    у класса фиксирована."""
    ca = dx.classes.get(class_desc)
    if ca is None or ca.is_external():
        return ()
    out = []
    supers = ([ca.extends] if ca.extends else []) + list(ca.implements)
    for s in supers:
        if not s or s == "Ljava/lang/Object;":
            continue
        out.append(s)
        out.extend(_cha_supers(dx, s))
    return tuple(dict.fromkeys(out))  # дедуп, порядок сохранён


def cha_caller_sites(dx, ma):
    """Вызывающие метода ma с учётом CHA (§7.2): помимо прямого xref_from самого
    ma — xref_from одноимённых (name+descriptor) объявлений в его супертипах.
    Полиморфный вызов `invoke-interface I.m()` / `invoke-super` виден в xref_from
    интерфейсного/родительского объявления I.m(), а НЕ реализации C.m() — без
    этого обход обрывался на реализации (dead_end).

    CHA полон по достижимости (ни один вызывающий не теряется), но
    over-approximation: вызывающие полиморфного I.m() приписываются ВСЕМ его
    реализациям, не только настоящей. Для min-по-путям (activation_cost) это
    смещение вниз — оговорено в методологии (docs/slice-methodology.md §7.2).

    CHA применяется ТОЛЬКО когда прямой xref пуст (реальный тупик) — именно там
    он нужен для покрытия. Применять его к кадрам, у которых вызывающие и так
    есть, значило бы тянуть вызывающих интерфейса для каждого кадра — fan-in
    взрывается, а стоимость смещается вниз сильнее.

    Потолок fan-in (`_CHA_FANIN_CAP`): если у супер-объявления БОЛЬШЕ потолка
    вызывающих — это общий/утилитный интерфейс (Repo-база, Function, use-case),
    не граница активации конкретного запроса. CHA для него бессмыслен
    (over-approximation на сотни мест) и взрывоопасен (каскадный fan-in не
    завершается) — кадр остаётся тупиком (честная нижняя оценка activation_cost).

    Возвращает (sites, used_cha): sites — список (caller_ma, offset);
    used_cha=True, если вызывающие найдены по CHA (прямой xref был пуст)."""
    direct = [(xf[1], xf[-1]) for xf in ma.get_xref_from()]
    if direct:
        return direct, False
    name, desc = ma.name, ma.descriptor
    seen, sites = set(), []
    for sdesc in _cha_supers(dx, ma.class_name):
        sca = dx.classes.get(sdesc)
        if sca is None:
            continue
        for sm in sca.get_methods():
            if sm.name == name and sm.descriptor == desc:
                for xf in sm.get_xref_from():
                    cma, off = xf[1], xf[-1]
                    if (cma, off) not in seen:
                        seen.add((cma, off))
                        sites.append((cma, off))
                        if len(sites) > _CHA_FANIN_CAP:
                            return [], False  # общий интерфейс — не граница, тупик
    return sites, bool(sites)


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
      регистр-операнд (приёмник), args = остальные регистры. ponytail:
      check-cast/move-object не трактуются как алиас исходного значения —
      после них classify_operand видит "unknown" вместо исходного источника;
      апгрейд — алиас-таблица в classify_operand, если понадобится точность.
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
    for bb in bbs:
        cfg.add_node(bb.get_name(), insns=_norm(list(bb.get_instructions())),
                     start=bb.get_start(), end=bb.get_end())
    for bb in bbs:
        end = bb.get_end()
        for (_last_idx, _tgt_idx, tbb) in bb.childs:
            if tbb is None:
                continue
            kind = "fallthrough" if tbb.get_start() == end else "branch"
            cfg.add_edge(bb.get_name(), tbb.get_name(), kind=kind)
    params = _params(m)

    def block_at(off):
        for n in cfg.nodes:
            if cfg.nodes[n]["start"] <= off < cfg.nodes[n]["end"]:
                return n
        return None

    return {"cfg": cfg, "params": params, "block_at": block_at}


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


_FRONTIER_NAMES = {"onCreate", "onStart", "onResume", "onPause", "onStop",
                   "onViewCreated", "onCreateView", "onClick", "onBind",
                   "onReceive", "onHandleWork", "doWork", "onStartCommand"}


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


def is_frontier(key, exported=()):
    """UI/lifecycle/entry-колбэк — точка, где обратный обход останавливается
    (дальше вверх — фреймворк, не наш код): имя метода из известного набора
    колбэков жизненного цикла/UI, класс из android./androidx. (сам фреймворк
    вызывает наш метод, выше в стеке ничего нашего нет), либо класс —
    exported-компонент манифеста (§7.2: альтернативная точка входа — deep link,
    виджет, вызов из другого приложения; выше по стеку наш код не идёт)."""
    cls, _, name = key.partition("->")
    if name in _FRONTIER_NAMES:
        return True
    if cls.startswith("android.") or cls.startswith("androidx."):
        return True
    return cls in exported


def manifest_entry_classes(apk):
    """FQCN exported-компонентов манифеста (activity/service/receiver/provider):
    android:exported="true" ЛИБО есть intent-filter при отсутствии exported
    (неявный exported до API 31). Это альтернативные точки входа (§7.2) —
    фронтир обратного обхода наравне с UI-колбэками."""
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


def backward_frames(dx, cls, method, limit=_DEPTH_LIMIT, exported=()):
    """Обратный межпроцедурный обход от call-site'ов cls->method вверх по
    графу вызовов до фронтира (UI/lifecycle/exported) или лимита глубины.
    Плумбинг (is_plumbing) проходится насквозь — не попадает в frames и не
    тратит бюджет глубины (вверх от него идём с ТЕМ ЖЕ depth), но обход через
    его вызывающих продолжается. Циклы (рекурсия, coroutine resume через себя
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
    (вес 0 в минимуме по путям)."""
    sites = resolve_call_sites(dx, cls, method)
    if not sites:
        return {"reached": False, "call_sites": [], "frames": [],
                "frontier": None, "depth": 0, "plumbing_skipped": [],
                "depth_capped": False, "dead_ends": [], "edges": [], "cha_used": False,
                "budget_hit": False, "frontier_nodes": set(), "dead_end_nodes": set(),
                "capped_nodes": set(), "plumbing_nodes": set()}
    frames, skipped, frontier, dead_ends = [], [], None, []
    edges = []
    frontier_nodes, dead_end_nodes, capped_nodes, plumbing_nodes = set(), set(), set(), set()
    visited = set()
    cha_used = False
    budget_hit = False
    max_depth = 0
    depth_capped = False  # True, если ХОТЬ ОДИН путь упёрся в limit (OR по путям)
    nid = lambda ma, o: (id(ma), o)
    # очередь: (child_node, caller_ma, offset, depth) — depth путевой (per-path);
    # child_node — узел, который этот кадр вызывает ВНИЗ к скрытому вызову.
    # 0-1 BFS (спека §5.2), не DFS: при visited-дедупе DFS мог впервые прийти в
    # кадр по длинному пути, упереться в limit и отбросить короткий путь к нему.
    queue = deque((SINK, s["caller_ma"], s["offset"], 0) for s in sites)
    while queue:
        child_node, caller_ma, off, depth = queue.popleft()
        node = nid(caller_ma, off)
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
            break
        plumbing = is_plumbing(ckey, caller_ma)
        if plumbing:
            skipped.append(ckey)
            plumbing_nodes.add(node)
            # плумбинг не тратит бюджет глубины — depth дальше вверх тот же
        else:
            frames.append({"key": ckey, "ma": caller_ma, "node": node, "offset": off})
            max_depth = max(max_depth, depth + 1)
            if is_frontier(ckey, exported):
                frontier = ckey
                frontier_nodes.add(node)
                continue  # путь дошёл до фронтира — выше по нему не поднимаемся
            depth += 1
            if depth >= limit:
                depth_capped = True
                capped_nodes.add(node)
                continue  # этот путь упёрся в лимит глубины
        # шаг вверх: кто вызывает именно этот метод (с CHA — §7.2)
        ups, used = cha_caller_sites(dx, caller_ma)
        cha_used = cha_used or used
        if not ups and caller_ma.name in _COROUTINE_FRAME_METHODS:
            # invoke/invokeSuspend/create лямбды зовёт рантайм через интерфейс
            # (Function*/Continuation) — XREF пуст. Точка активации лямбды — место
            # её создания (new-instance): ViewModel/фрагмент, где вызван launch {}.
            # ponytail: по имени метода; `operator fun invoke` без XREF у не-лямбды
            # тоже уйдёт к new-instance (обычно DI), а R8-слитый класс лямбд
            # (один класс + switch по id) даёт fan-in на все места создания —
            # апгрейд: проверять суперкласс и id слитой лямбды.
            ca = dx.classes.get(caller_ma.class_name)
            ups = list(ca.get_xref_new_instance()) if ca else []
        if not ups:
            dead_ends.append(ckey)  # путь оборван не на фронтире: стражи выше не видны
            if not plumbing:
                dead_end_nodes.add(node)
        push = queue.appendleft if plumbing else queue.append  # плумбинг: та же глубина
        for ma, o in ups:
            push((node, ma, o, depth))  # node — потомок (вниз к скрытому вызову) для вызывающего
    return {"reached": True, "call_sites": sites, "frames": frames,
            "frontier": frontier, "depth": max_depth,
            "plumbing_skipped": skipped, "depth_capped": depth_capped,
            "dead_ends": dead_ends, "edges": edges, "cha_used": cha_used,
            "budget_hit": budget_hit,
            "frontier_nodes": frontier_nodes, "dead_end_nodes": dead_end_nodes,
            "capped_nodes": capped_nodes, "plumbing_nodes": plumbing_nodes}


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
    assert is_frontier("androidx.fragment.app.Fragment->onViewCreated")
    assert is_frontier("a.b.MyActivity->onCreate")
    assert not is_frontier("a.b.SomeRepository->refresh")
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
    exit_node = "__exit__"
    g = cfg.copy()
    terminals = [n for n in cfg.nodes if cfg.out_degree(n) == 0]
    for n in terminals:
        g.add_edge(n, exit_node)
    if not terminals:  # ни одного терминала (см. post_idom) — синтетический fallback
        g.add_edge(list(cfg.nodes)[-1], exit_node)
    guards = []
    for (branch, taken) in control_deps(g, crit, exit_node):
        insns = cfg.nodes[branch]["insns"]
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
        # дескрипторы полей/типов, читаемых в самом блоке ветвления: нужны для
        # распознавания метки корутины `if ((label & MIN_INT) != 0)`, где
        # операнд — результат and-int (unknown), а само поле-метку читает iget.
        block_refs = [i.args[0] for i in insns
                      if i.op.startswith(("iget", "sget", "instance-of"))
                      and i.args and i.args[0]]
        guards.append({"frame": None, "opcode": opcode, "sense": f"->{taken}",
                       "operand": operand, "notes": [], "_block_refs": block_refs})
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
        out.append({"index": idx, "source_kind": kind, "detail": detail})
    return out


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


@lru_cache(maxsize=None)
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
_FRAMEWORK_OWNER_PREFIXES = ("android.", "androidx.", "java.", "kotlin.", "kotlinx.")
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


def slice_key(dx, key):
    """Полная запись среза для одного ключа (схема спеки §4): обход вверх
    (Task 4) до фронтира/лимита, на каждом семантическом кадре — стражи
    (guards_of_frame). Кадр без кода (frame_of -> None, напр. внешнее/
    abstract-объявление) не роняет обход — помечается inconclusive и
    пропускается (Review Focus)."""
    cls, _, method = key.partition("->")
    w = backward_frames(dx, cls, method, exported=getattr(dx, "_exported", ()))
    rec = {"key": key, "cls": cls, "method": method,
           "reached": w["reached"],
           "call_sites": [{"caller": s["caller"], "offset": s["offset"]} for s in w["call_sites"]],
           "guards": [], "guard_count": 0, "guard_count_coroutine": 0,
           "guard_count_framework": 0, "activation_cost": None,
           "activation_exact": False, "args": [],
           "frontier": w["frontier"], "depth": w["depth"],
           "plumbing_skipped": w["plumbing_skipped"], "inconclusive": False,
           "arg_types": [], "suspend": False, "data_cost": "none",
           "arg_recipes": {}, "notes": []}
    # Типы аргументов скрытого метода — собираем ВО ВРЕМЯ среза (dx уже загружен),
    # чтобы activate.py синтезировал args по типам без отдельной androguard-загрузки.
    # Continuation у suspend убираем из семантических — рантайм досылает его сам.
    _pt = _param_types(_hidden_desc(dx, cls, method))
    rec["suspend"] = bool(_pt) and _pt[-1] == _CONT
    rec["arg_types"] = [t for t in _pt if t != _CONT]
    rec["data_cost"] = _data_cost(rec["arg_types"])
    # рецепты постройки объектных DTO-аргументов (тир object Таблицы IV): они
    # транзиентны, в куче их нет ($choose пусто) — activate.py строит их $new.
    rec["arg_recipes"] = _arg_recipes(dx, rec["arg_types"])
    if not w["reached"]:
        # BFScan печатает JADX-алиасы имён (обфускация): такого класса/метода в DEX
        # нет вовсе — это артефакт статики, а не категория No caller
        ca = dx.classes.get("L" + cls.replace(".", "/") + ";")
        known = ca is not None and any(m.name == method for m in ca.get_methods())
        rec["notes"].append("no_caller" if known else "key_not_in_dex")
        return rec
    all_guards, seen, weight = [], set(), {}
    for f in w["frames"]:
        fr = frame_of(f["ma"])
        if fr is None:
            rec["inconclusive"] = True
            continue
        node_real = 0
        for g in guards_of_frame(fr, f["offset"]):
            g["frame"] = f["key"]
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
            g.pop("_block_refs", None)  # служебное, не в выход
            if not g["notes"]:
                node_real += 1  # вес кадра — его СОБСТВЕННЫЕ реальные стражи
            # для guards[]/union guard_count — межкадровый дедуп (одно условие на
            # нескольких call-site одного метода не задваивается); на вес кадра
            # (минимум по путям) дедуп НЕ влияет — там каждый узел считает своё.
            sig = (id(f["ma"]), g["opcode"], g["sense"], g["operand"]["source_kind"],
                   str(g["operand"]["detail"]))
            if sig not in seen:
                seen.add(sig)
                all_guards.append(g)
        weight[f["node"]] = node_real
    rec["guards"] = all_guards
    # Ruling-H: union guard_count — ВЕРХНЯЯ оценка (все стражи всех путей);
    # headline-метрика стоимости активации — activation_cost (минимум по путям).
    rec["guard_count"] = sum(1 for g in all_guards if not g["notes"])
    rec["guard_count_coroutine"] = sum(1 for g in all_guards if "coroutine_state_machine" in g["notes"])
    rec["guard_count_framework"] = sum(1 for g in all_guards if "framework" in g["notes"])
    # §7.1: минимум реальных стражей по путям UI-вход -> скрытый вызов.
    children = {}
    for parent, child in w["edges"]:
        children.setdefault(parent, set()).add(child)
    tops = w["frontier_nodes"] | w["dead_end_nodes"] | w["capped_nodes"]
    cost, exact = min_path_guards(weight, children, tops, w["frontier_nodes"], SINK)
    # обход оборван по бюджету -> граф неполон, в точную Таблицу IV не берём
    rec["activation_cost"], rec["activation_exact"] = cost, exact and not w["budget_hit"]
    if cost is None:
        # ни один top (фронтир/dead_end/depth_cap) не дотянулся до скрытого вызова:
        # все пути обрываются на плумбинге — стоимость активации не определена
        rec["notes"].append("no_semantic_entry")
    # round-2 review Fix 1: происхождение аргументов скрытого вызова (спека
    # §5.7) — по ПЕРВОМУ call-site (данных-ось не требует нескольких путей,
    # как guard-сторона; симметрично её простоте).
    first = w["call_sites"][0]
    fr0 = frame_of(first["caller_ma"])
    if fr0 is not None:
        rec["args"] = args_of_call(fr0, first["offset"], cls, method)
    if w["depth_capped"]:
        rec["notes"].append("depth_cap")
    if w["dead_ends"]:
        rec["notes"].append("dead_end")
    if w["cha_used"]:
        # хотя бы один вызывающий найден по CHA (полиморфный вызов) — путь, а
        # значит и activation_cost, возможно over-approximated (§7.2)
        rec["notes"].append("cha")
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
    assert rec["reached"] is True
    assert rec["cls"].endswith("DownloadsApi") and rec["method"] == "disallowDeviceDownload"
    assert isinstance(rec["guards"], list)
    assert (rec["guard_count"] + rec["guard_count_coroutine"] + rec["guard_count_framework"]
            == len(rec["guards"]))
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


def load_hidden(path):
    """out/<pkg>.hidden.jsonl (формат diff.py) -> список уникальных ключей со
    status=hidden, порядок первого появления. Дубли — перегрузки одного и
    того же класс->метод (diff.py схлопывает их по ключу на выходе, но не
    дедупит внутри файла), в срезе достаточно одной записи на ключ."""
    keys, seen = [], set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        if r.get("status") == "hidden" and r["key"] not in seen:
            seen.add(r["key"])
            keys.append(r["key"])
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
    total = len(records)
    reached = sum(r["reached"] for r in records)
    not_in_dex = sum(1 for r in records if "key_not_in_dex" in r["notes"])
    no_caller = sum(1 for r in records if not r["reached"]) - not_in_dex
    dead = sum(1 for r in records if "dead_end" in r["notes"])
    inconcl = sum(1 for r in records if r.get("inconclusive"))
    coroutine_total = sum(r.get("guard_count_coroutine", 0) for r in records)
    framework_total = sum(r.get("guard_count_framework", 0) for r in records)
    w(f"Всего ключей: {total} | reached: {reached} | no_caller: {no_caller} | "
      f"key_not_in_dex: {not_in_dex} | inconclusive: {inconcl}")
    w(f"Обход оборван не на фронтире (dead_end, стражи выше пути не видны): {dead}")
    w(f"Стражи state-machine корутин (флагованы, исключены из guard_count и топа источников): {coroutine_total}")
    w(f"Стражи фреймворка/компилятора (флагованы, исключены из guard_count и топа источников): {framework_total}")
    dist = Counter(min(r["guard_count"], 4) for r in records if r["reached"])
    w("Распределение guard_count — ВЕРХНЯЯ оценка, объединение стражей всех путей:")
    for k in range(5):
        label = "4+" if k == 4 else str(k)
        w(f"  {label} стражей: {dist.get(k, 0)}")
    # §7.1: минимум по путям — стоимость активации. Таблица IV строится ТОЛЬКО по
    # ключам с activation_exact (путь дошёл до UI-входа); остальные — нижняя оценка.
    exact = [r for r in records if r["reached"] and r.get("activation_exact")]
    lower = [r for r in records if r["reached"] and not r.get("activation_exact")
             and r.get("activation_cost") is not None]
    adist = Counter(min(r["activation_cost"], 4) for r in exact)
    w(f"Стоимость активации (минимум по путям), ТОЧНО (путь до UI-входа): {len(exact)} ключей — "
      f"это и есть Таблица IV:")
    for k in range(5):
        label = "4+" if k == 4 else str(k)
        w(f"  {label} стражей: {adist.get(k, 0)}")
    w(f"Нижняя оценка (обход не дошёл до UI-входа, истинная стоимость не меньше): {len(lower)} ключей")
    undet = sum(1 for r in records if r["reached"] and r.get("activation_cost") is None)
    w(f"Стоимость не определена (обход завершился только на плумбинге, нет семантического входа): {undet} ключей")
    # Стоимость ДАННЫХ (HTTP-аналог тиров «+Data support» RQ3): по типам аргументов
    # скрытого метода. none=нет аргументов (активируется прямым вызовом), primitive=
    # только примитивы (дефолты), object=есть объектные арги (нужен живой инстанс/синтез).
    dc = Counter(r.get("data_cost", "none") for r in records if r["reached"])
    susp = sum(1 for r in records if r["reached"] and r.get("suspend"))
    w(f"Стоимость данных (типы аргументов скрытого метода): "
      f"none(без аргументов): {dc.get('none', 0)} | "
      f"primitive(только примитивы): {dc.get('primitive', 0)} | "
      f"object(есть объектные): {dc.get('object', 0)} | из них suspend: {susp}")
    src = Counter(g["operand"]["detail"] for r in records for g in r["guards"]
                  if not g["notes"] and g["operand"]["source_kind"] in ("invoke", "field", "instanceof")
                  and g["operand"]["detail"])
    w("Топ источников стражей:")
    for name, n in src.most_common(15):
        w(f"  {n:3d}  {name}")
    w("")
    for r in records:
        tag = "HIDDEN" if r["reached"] else "NO-CALLER"
        ac = r.get("activation_cost")
        acs = (f"{ac}{'' if r.get('activation_exact') else '+'}" if ac is not None else "?")
        w(f"[{tag}] {r['key']}  activation_cost={acs} guard_count(union)={r['guard_count']} "
          f"frontier={r['frontier']} notes={r['notes']}")
        for g in r["guards"]:
            o = g["operand"]
            flag = f" [{','.join(g['notes'])}]" if g["notes"] else ""
            w(f"    {g['opcode']} {g['sense']}  <- {o['source_kind']}:{o['detail']}  @{g['frame']}{flag}")
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
    apk_obj, dx = load_apk(args.apk)
    dx._exported = manifest_entry_classes(apk_obj)  # §7.2: exported — фронтир обхода
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
    records = run(dx, keys)
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
