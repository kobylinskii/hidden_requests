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
from collections import Counter, namedtuple
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
        elif op in ("monitor-enter", "monitor-exit", "fill-array-data"):
            # единственный регистр-операнд здесь — ЧИСТОЕ использование (lock-
            # объект / ссылка на массив), не def; в общий else не класть.
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

    w = backward_frames(dx, "gpm.tnt_premier.features.downloads.impl.data.network.DownloadsApi",
                        "disallowDeviceDownload")
    assert w["reached"] and w["call_sites"], w
    assert len(w["frames"]) >= 1, w
    # Ruling-E: лимит — per-path глубина, не общий потолок на frames; общее
    # число кадров естественно ограничено visited-дедупом по (key, offset).
    # Санити-порог на runaway — доказывает, что дедуп реально работает и
    # обход не взрывается комбинаторно на графе с высоким fan-in.
    assert len(w["frames"]) < 300, w
    # regression-guard против отката к глобальному капу на frames (round-1
    # review, Finding 1): у отвергнутого global-cap варианта здесь было бы
    # ровно 6 кадров — >=1 и <300 это не ловят, а >6 ловит.
    assert len(w["frames"]) > 6, w
    assert w["depth"] <= 6, w              # per-path лимит глубины реально соблюдён
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


def is_frontier(key):
    """UI/lifecycle/entry-колбэк — точка, где обратный обход останавливается
    (дальше вверх — фреймворк, не наш код): либо имя метода из известного
    набора колбэков жизненного цикла/UI, либо класс из android./androidx.
    (сам фреймворк вызывает наш метод, выше в стеке ничего нашего нет)."""
    cls, _, name = key.partition("->")
    if name in _FRONTIER_NAMES:
        return True
    return cls.startswith("android.") or cls.startswith("androidx.")


def backward_frames(dx, cls, method, limit=6):
    """Обратный межпроцедурный обход от call-site'ов cls->method вверх по
    графу вызовов до фронтира (UI/lifecycle) или лимита глубины. Плумбинг
    (is_plumbing) проходится насквозь — не попадает в frames и не тратит
    бюджет глубины (вверх от него идём с ТЕМ ЖЕ depth), но обход через его
    вызывающих продолжается. Циклы (рекурсия, coroutine resume через себя
    же) гасятся visited-множеством по (caller_key, offset) — один и тот же
    call-site не обрабатывается дважды, что гарантирует терминацию на
    конечном графе вызовов.

    Ruling-E: limit — бюджет глубины ОДНОГО пути (как ICSE-обход
    startActivity->onCreate), а не общий потолок на len(frames). При
    нескольких исходных call-site'ах или fan-in выше по графу каждый путь
    независимо идёт до своего фронтира/лимита; итоговый frames естественно
    ограничен только visited-дедупом по (key, offset), без искусственного
    общего капа."""
    sites = resolve_call_sites(dx, cls, method)
    if not sites:
        return {"reached": False, "call_sites": [], "frames": [],
                "frontier": None, "depth": 0, "plumbing_skipped": [],
                "depth_capped": False}
    frames, skipped, frontier = [], [], None
    visited = set()
    max_depth = 0
    depth_capped = False  # True, если ХОТЬ ОДИН путь упёрся в limit (OR по путям)
    # очередь: (callee_key, caller_ma, offset, depth) — depth путевой (per-path)
    queue = [(f"{cls}->{method}", s["caller_ma"], s["offset"], 0) for s in sites]
    while queue:
        callee_key, caller_ma, off, depth = queue.pop()
        ckey = method_key(caller_ma)
        if (ckey, off) in visited:
            continue
        visited.add((ckey, off))
        if is_plumbing(ckey, caller_ma):
            skipped.append(ckey)
            # плумбинг не тратит бюджет глубины — depth дальше вверх тот же
        else:
            frames.append({"key": ckey, "ma": caller_ma,
                           "callee_key": callee_key, "offset": off})
            max_depth = max(max_depth, depth + 1)
            if is_frontier(ckey):
                frontier = ckey
                continue  # путь дошёл до фронтира — выше по нему не поднимаемся
            depth += 1
            if depth >= limit:
                depth_capped = True
                continue  # этот путь упёрся в лимит глубины
        # шаг вверх: кто вызывает ckey
        pcls, _, pm = ckey.partition("->")
        for s in resolve_call_sites(dx, pcls, pm):
            queue.append((ckey, s["caller_ma"], s["offset"], depth))
    return {"reached": True, "call_sites": sites, "frames": frames,
            "frontier": frontier, "depth": max_depth,
            "plumbing_skipped": skipped, "depth_capped": depth_capped}


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
    if-*/*-switch имеют out=None, тестируемый регистр(ы) в args. Регистр —
    cond.args[0]; если cond не найден (не должно происходить для настоящего
    ветвления, но не падать) — ярлык "branch", операнд unknown."""
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
        reg = cond.args[0] if (cond and cond.args) else None
        operand = {"source_kind": "unknown", "detail": None}
        if reg is not None:
            kind, detail = classify_operand(cfg, branch, len(insns) - 1, reg, fr["params"])
            operand = {"source_kind": kind, "detail": detail}
        guards.append({"frame": None, "opcode": opcode,
                       "sense": f"->{taken}", "operand": operand, "notes": []})
    return guards


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


def slice_key(dx, key):
    """Полная запись среза для одного ключа (схема спеки §4): обход вверх
    (Task 4) до фронтира/лимита, на каждом семантическом кадре — стражи
    (guards_of_frame). Кадр без кода (frame_of -> None, напр. внешнее/
    abstract-объявление) не роняет обход — помечается inconclusive и
    пропускается (Review Focus)."""
    cls, _, method = key.partition("->")
    w = backward_frames(dx, cls, method)
    rec = {"key": key, "cls": cls, "method": method,
           "reached": w["reached"],
           "call_sites": [{"caller": s["caller"], "offset": s["offset"]} for s in w["call_sites"]],
           "guards": [], "guard_count": 0, "guard_count_coroutine": 0, "args": [],
           "frontier": w["frontier"], "depth": w["depth"],
           "plumbing_skipped": w["plumbing_skipped"], "inconclusive": False,
           "notes": []}
    if not w["reached"]:
        rec["notes"].append("no_caller")
        return rec
    all_guards = []
    for f in w["frames"]:
        fr = frame_of(f["ma"])
        if fr is None:
            rec["inconclusive"] = True
            continue
        gs = guards_of_frame(fr, f["offset"])
        for g in gs:
            g["frame"] = f["key"]
            if _is_coroutine_state_guard(g):
                g["notes"] = ["coroutine_state_machine"]
        all_guards.extend(gs)
    rec["guards"] = all_guards
    # Ruling-H: guard_count — только НЕ помеченные (headline-метрика); флаг —
    # отдельным счётчиком, guards[] несёт все, включая помеченные.
    rec["guard_count"] = sum(1 for g in all_guards if not g["notes"])
    rec["guard_count_coroutine"] = sum(1 for g in all_guards if g["notes"])
    if w["depth_capped"]:
        rec["notes"].append("depth_cap")
    return rec


def run(dx, keys):
    """Срез по списку ключей -> список записей (порядок сохраняется)."""
    return [slice_key(dx, k) for k in keys]


def _check_slice_key(dx):
    rec = slice_key(dx, "gpm.tnt_premier.features.downloads.impl.data.network.DownloadsApi->disallowDeviceDownload")
    assert rec["reached"] is True
    assert rec["cls"].endswith("DownloadsApi") and rec["method"] == "disallowDeviceDownload"
    assert isinstance(rec["guards"], list)
    assert rec["guard_count"] + rec["guard_count_coroutine"] == len(rec["guards"])
    assert set(("reached", "call_sites", "guards", "args", "frontier",
                "inconclusive", "guard_count_coroutine")) <= set(rec)
    assert all("notes" in g for g in rec["guards"])
    # Ruling-H (fix round 1): известный кейс несёт coroutine state-machine
    # стражи (continuation TT->invokeSuspend/invoke, self-field label) —
    # они помечены и НЕ входят в headline guard_count; регрессия отката
    # флага (guard_count == len(guards)) здесь бы провалила assert.
    assert rec["guard_count_coroutine"] > 0, rec
    assert rec["guard_count"] < len(rec["guards"]), rec
    # ключ-форвардер без стражей: guard_count 0, не падение (Review Focus)
    assert rec["guard_count"] >= 0
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
    no_caller = sum(1 for r in records if not r["reached"])
    inconcl = sum(1 for r in records if r.get("inconclusive"))
    coroutine_total = sum(r.get("guard_count_coroutine", 0) for r in records)
    w(f"Всего ключей: {total} | reached: {reached} | no_caller: {no_caller} | inconclusive: {inconcl}")
    w(f"Стражи state-machine корутин (флагованы, исключены из guard_count и топа источников): {coroutine_total}")
    dist = Counter(min(r["guard_count"], 4) for r in records if r["reached"])
    w("Распределение guard_count (сырьё для Таблицы IV):")
    for k in range(5):
        label = "4+" if k == 4 else str(k)
        w(f"  {label} стражей: {dist.get(k, 0)}")
    src = Counter(g["operand"]["detail"] for r in records for g in r["guards"]
                  if not g["notes"] and g["operand"]["source_kind"] in ("invoke", "field")
                  and g["operand"]["detail"])
    w("Топ источников стражей:")
    for name, n in src.most_common(15):
        w(f"  {n:3d}  {name}")
    w("")
    for r in records:
        tag = "HIDDEN" if r["reached"] else "NO-CALLER"
        w(f"[{tag}] {r['key']}  guards={r['guard_count']} frontier={r['frontier']} notes={r['notes']}")
        for g in r["guards"]:
            o = g["operand"]
            flag = " [coroutine]" if g["notes"] else ""
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
         ],
         "guard_count": 1, "guard_count_coroutine": 1, "args": [],
         "frontier": "F->onCreate", "depth": 2, "plumbing_skipped": [],
         "inconclusive": False, "notes": []},
        {"key": "b->y", "cls": "b", "method": "y", "reached": False,
         "call_sites": [], "guards": [], "guard_count": 0, "guard_count_coroutine": 0,
         "args": [], "frontier": None, "depth": 0, "plumbing_skipped": [],
         "inconclusive": False, "notes": ["no_caller"]},
    ]
    txt = report(recs)
    assert "guard_count" in txt and "no_caller" in txt.lower()
    assert "1 стражей: 1" in txt  # распределение: один reached-ключ с 1 стражем
    # fix round 1: meta (пакет/версия) должна попасть в шапку — паритет сборки
    # со static+dynamic, как в diff.py (Spec §4)
    meta = {"package": "p", "versionName": "1.0", "versionCode": "42"}
    txt_meta = report(recs, meta=meta)
    assert "Приложение: p versionName=1.0 versionCode=42" in txt_meta
    # Ruling-H: топ источников — реальный guard входит, coroutine-флагованный — нет
    top_section = txt.split("Топ источников")[1].split("\n\n")[0]
    assert "S->isLoggedIn()Z" in top_section
    assert "T->label" not in top_section
    # построчный листинг НЕ скрывает coroutine-флагованные стражи — просто
    # помечает их (прозрачность, не молчаливое отбрасывание)
    assert "T->label" in txt and "[coroutine]" in txt
    # общее число coroutine-флагованных стражей видно отдельной строкой
    assert "Стражи state-machine корутин" in txt and "1" in txt.split("корутин")[1].split("\n")[0]
    print("  report ok")


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
    records = run(dx, keys)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w", encoding="utf-8") as f:
            for r in records:
                # на всякий случай — рекорд и так не содержит ma (Task 5 кладёт
                # в call_sites/guards только {caller,offset}/операнды), но
                # страхуемся от нежелательных не-JSON полей при апгрейде схемы
                f.write(json.dumps({k: v for k, v in r.items() if k != "ma"},
                                   ensure_ascii=False) + "\n")
    # Spec §4: паритет сборки со static+dynamic (как diff.py) — пакет/версия
    # из манифеста, который androguard уже распарсил внутри load_apk (без
    # повторного полного прохода по APK).
    meta = {"package": apk_obj.get_package(),
            "versionName": apk_obj.get_androidversion_name(),
            "versionCode": apk_obj.get_androidversion_code()}
    txt = report(records, meta=meta)
    print(txt)
    if args.out:
        report_path = args.out.with_suffix(".report.txt")
        report_path.write_text(txt, encoding="utf-8")
        print(f"\n→ {args.out}\n→ {report_path}", file=sys.stderr)


def _selfcheck(apk=None):
    _check_control_deps()
    _check_classify_operand()
    _check_walk_predicates()
    _check_report()
    if apk:
        _, dx = load_apk(apk)  # APK-объект здесь не нужен, только dx
        _check_androguard(dx)  # уже принимает dx (Ruling-C: без повторной загрузки APK)
        _check_slice_key(dx)
    print("selfcheck ok")


if __name__ == "__main__":
    main()
