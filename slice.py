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
    """Путь к APK -> androguard Analysis (dx). Долгая операция (~130с на
    130MB multi-dex APK) — вызывать один раз и переиспользовать dx."""
    _, _, dx = AnalyzeAPK(str(path))
    return dx


def _fqcn(descriptor):
    """'Lpkg/Cls;' -> 'pkg.Cls'."""
    return descriptor[1:-1].replace("/", ".") if descriptor.startswith("L") else descriptor


def method_key(ma):
    """MethodAnalysis -> 'fqcn->name'."""
    return f"{_fqcn(ma.class_name)}->{ma.name}"


def resolve_call_sites(dx, cls, method):
    """Все вызовы cls->method по XREF. no_external=False — метод может быть
    интерфейсным объявлением (у него самого нет кода, но есть xref_from от
    реализаций/вызывающих через invoke-interface). Пусто, если метод не
    найден или XREF пуст (не ошибка)."""
    desc = "L" + cls.replace(".", "/") + ";"
    pat = "^" + re.escape(desc) + "$"
    mpat = "^" + re.escape(method) + "$"
    sites = []
    for ma in dx.find_methods(classname=pat, methodname=mpat, no_external=False):
        for xf in ma.get_xref_from():
            caller_ma, off = xf[1], xf[-1]
            sites.append({"caller": method_key(caller_ma),
                          "caller_ma": caller_ma, "offset": off})
    return sites


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


def _selfcheck(apk=None):
    _check_control_deps()
    _check_classify_operand()
    if apk:
        dx = load_apk(apk)
        _check_androguard(dx)
    print("selfcheck ok")


if __name__ == "__main__":
    if "--selfcheck" in sys.argv:
        apk = None
        if "--apk" in sys.argv:
            apk = sys.argv[sys.argv.index("--apk") + 1]
        _selfcheck(apk)
        sys.exit(0)
