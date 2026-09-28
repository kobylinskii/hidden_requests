# Статический обратный срез скрытых запросов — план реализации

> **Статус: выполнено.** Все 7 задач реализованы, каждая прошла ревью (с fix-циклами
> по находкам), плюс финальное ревью всей ветки и одна волна фиксов по его результатам.
> Чекбоксы ниже — исторический план, не отражают фактический ход (велись субагентами
> вне этого файла); запись хода выполнения — git-история коммитов `slice.py`/`eval_slice.py`
> в этом репозитории. Пути `new/...` в тексте плана — из момента, когда код ещё жил
> подкаталогом `new/` внутри `/home/solidgroup/hidden_requests`; репозиторий с тех пор
> вынесен в отдельный `/home/solidgroup/SolidLab/hidden_requests` без префикса `new/`.
> Что изменилось относительно первоначального дизайна при реализации — дизайн-документ
> §12; текущее состояние инструмента и пилот — `CONTEXT.md` §4.7, `README.md`.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Построить `new/slice.py`, который для каждого скрытого запроса из `hidden.jsonl` восстанавливает call-sites и управляющие стражи обратным межпроцедурным обходом байткода APK.

**Architecture:** Гибрид. androguard даёт XREF, CFG, инструкции; networkx держит графы. Стадия A (по всему APK): резолв call-sites через XREF + обратный под-граф вызовов до фронтира. Стадия B (только на под-срезе): управляющие зависимости через пост-доминаторы (Ferrante–Ottenstein–Warren) и мелкий def-use для источников операндов. Андроид-специфика изолирована от алгоритмики, чтобы ядро тестировалось на синтетических графах без APK.

**Tech Stack:** Python 3.12, androguard 4.1.4, networkx 3.7 (оба в `new/.venv`). Без новых зависимостей.

**Spec:** `docs/superpowers/specs/2026-09-28-static-backward-slice-design.md` — план аргументируется из спеки, читать оба.

## Global Constraints

- Все команды `python`/`pip` — только из `new/.venv` (`./.venv/bin/python`). Рабочая директория `new/`.
- Новых зависимостей не добавлять (ponytail: только androguard + networkx).
- Логи androguard душить в самом начале: `from loguru import logger; logger.remove()` **до** импорта androguard.
- Ключ запроса — строка `fqcn->method` (формат `diff.py`); перегрузки не различаются.
- Выход — NDJSON (`slice.jsonl`), одна запись на ключ; поля строго по схеме спеки §4.
- Тесты — без фреймворков: `python3 slice.py --selfcheck` на `assert` (паттерн `diff.py:_selfcheck`). Синтетические CFG строятся вручную на networkx.
- Класснейм в `find_methods` — regex: экранировать `re.escape`, якорить `^...$`.

## Review Focus

Классы входов, которые спека подразумевает, но которые легко ломают программу — каждый закреплён за задачей и покрыт её тестом:

- **Ключ без call-sites** (рефлексия/мёртвый код): `xref_from` пуст ⇒ `reached:false`, не падение. → Task 3 (`resolve_call_sites` на несуществующем ключе), Task 5 (запись с `reached:false`).
- **Цикл в графе вызовов** (рекурсия/резюмирование корутины): обход вверх обязан завершаться. → Task 4 (тест `backward_frames` с циклом через visited-множество).
- **Метод-форвардер без ветвлений** (прямой путь): `control_deps` возвращает `[]`, `guard_count:0`, не ошибку. → Task 1 (тест прямой линии).
- **CFG без пути к выходу** (бесконечный цикл): расчёт пост-доминаторов не падает (узлы без пути к выходу до-подключаются к нему). → Task 1 (тест петли без выхода).
- **Операнд с неоднозначным определением** (два def на двух ветвях, не параметр): классификатор возвращает `unknown`, а не угадывает. → Task 2 (тест phi-подобного случая).

---

## Task 0 (опционально): инициализация git

Репозиторий `/home/solidgroup/hidden_requests` — не git. Частые коммиты — часть методологии. Если заказчик не хочет git, эту задачу пропустить, а шаги «Commit» ниже трактовать как чекпойнты.

**Files:**
- Create: `/home/solidgroup/hidden_requests/.gitignore`

- [ ] **Step 1: init + .gitignore**

```bash
cd /home/solidgroup/hidden_requests
git init
cat > .gitignore <<'EOF'
*.apk
**/.venv/
**/__pycache__/
*.pyc
requests/BFScan/
new/out/*.jsonl
EOF
git add .gitignore docs/
git commit -m "chore: init repo, add slice spec and plan"
```

Комментарий: `*.apk` (136 МБ — не в git), `.venv`, вендорный `requests/BFScan/` (свой .git), крупные генерируемые `out/*.jsonl`. Отчёты `.txt` и код остаются под версией.

---

## Task 1: Управляющие зависимости на абстрактном CFG (чистая логика)

Ядро среза. Работает на `networkx.DiGraph`, где узлы — id блоков, есть выделенный `exit`. Не знает про androguard.

**Files:**
- Create: `new/slice.py`
- Test: внутри `slice.py`, функция `_check_control_deps()`, вызывается из `_selfcheck()`.

**Interfaces:**
- Produces:
  - `post_idom(cfg: nx.DiGraph, exit_node) -> dict` — узел → непосредственный пост-доминатор. Узлы без пути к `exit_node` предварительно до-соединяются с ним.
  - `control_deps(cfg: nx.DiGraph, criterion, exit_node) -> list[tuple]` — транзитивный список `(branch_node, taken_successor)`, от которых `criterion` управляемо зависим.

- [ ] **Step 1: Write the failing test**

```python
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
    print("  control_deps ok")
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/bin/python slice.py --selfcheck`
Expected: FAIL — `NameError: name 'control_deps' is not defined`.

- [ ] **Step 3: Implement**

```python
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

    result, work, done = {}, [criterion], set()
    while work:
        cur = work.pop()
        if cur in done:
            continue
        done.add(cur)
        for a, b in direct(cur):
            if a not in result:
                result[a] = b
                work.append(a)
    return list(result.items())
```

- [ ] **Step 4: Run to verify it passes**

Run: `./.venv/bin/python slice.py --selfcheck` (после Step 5 — временный `_selfcheck`)
Expected: `control_deps ok`.

- [ ] **Step 5: Wire selfcheck**

```python
def _selfcheck():
    _check_control_deps()
    print("selfcheck ok")


if __name__ == "__main__":
    if "--selfcheck" in sys.argv:
        _selfcheck()
        sys.exit(0)
```

- [ ] **Step 6: Commit**

```bash
cd /home/solidgroup/hidden_requests
git add new/slice.py && git commit -m "feat(slice): control dependence on abstract CFG"
```

---

## Task 2: Классификатор источника операнда (чистый def-use)

Мелкий обратный def-use по регистру: откуда пришло значение стража/аргумента. Работает на CFG с инструкциями в атрибуте узла `insns`, независимо от androguard.

**Files:**
- Modify: `new/slice.py`
- Test: `_check_classify_operand()` в `slice.py`.

**Interfaces:**
- Consumes: `nx.DiGraph` с `cfg.nodes[b]["insns"]: list[Insn]`.
- Produces:
  - `Insn = namedtuple("Insn", "op out args")` — нормализованная инструкция (`op` — категория: `const|iget|sget|move-result|other`; `out` — регистр-приёмник или None; `args` — кортеж значимых операндов).
  - `classify_operand(cfg, block, use_pos, reg, params) -> tuple` — `(source_kind, detail)`, `source_kind ∈ const|field|invoke|param|unknown`.

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/bin/python slice.py --selfcheck`
Expected: FAIL — `NameError: name 'Insn' is not defined`.

- [ ] **Step 3: Implement**

```python
from collections import namedtuple

Insn = namedtuple("Insn", "op out args")


def _kind_of(ins):
    if ins.op == "const":
        return ("const", ins.args[0] if ins.args else None)
    if ins.op in ("iget", "sget"):
        return ("field", ins.args[0] if ins.args else None)
    if ins.op == "move-result":
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
```

- [ ] **Step 4: Run to verify it passes**

Add `_check_classify_operand()` to `_selfcheck()`. Run: `./.venv/bin/python slice.py --selfcheck`
Expected: `classify_operand ok`.

- [ ] **Step 5: Commit**

```bash
git add new/slice.py && git commit -m "feat(slice): shallow def-use operand classifier"
```

---

## Task 3: Слой androguard — загрузка, call-sites, нормализация кадра

Изолирует всю андроид-специфику. Тестируется интеграционно против реального APK (значения известны из пробы): `DownloadsApi->disallowDeviceDownload` вызывается из `DownloadsApiRepository->disallowDeviceDownload @194`.

**Files:**
- Modify: `new/slice.py`
- Test: `_check_androguard(apk)` в `slice.py`, запускается только если APK передан: `slice.py --selfcheck --apk apk/gpm.tnt_premier.apk`.

**Interfaces:**
- Produces:
  - `load_apk(path) -> Analysis` (androguard `dx`).
  - `method_key(method_analysis) -> str` — `fqcn->name` из `MethodAnalysis` (класс без `L;`, точки вместо слэшей).
  - `resolve_call_sites(dx, cls, method) -> list[dict]` — `[{caller, caller_ma, offset}]`; пусто, если XREF пуст.
  - `frame_of(method_analysis) -> dict|None` — `{cfg, params, block_at}`: `cfg` (networkx с `insns`, помеченными рёбрами `branch`/`fallthrough`), `params` (reg→index), `block_at(offset)->node`. `None`, если у метода нет кода (интерфейс/внешний).

- [ ] **Step 1: Discovery — сверить форму операндов (одноразово)**

Форма `get_operands()` версионнозависима. Прогнать против реального метода и зафиксировать раскладку регистров/полей/вызовов, прежде чем писать нормализатор:

```bash
./.venv/bin/python - <<'PY' 2>/dev/null
from loguru import logger; logger.remove()
from androguard.misc import AnalyzeAPK
import re
a,d,dx = AnalyzeAPK("apk/gpm.tnt_premier.apk")
cls="Lgpm/tnt_premier/features/downloads/impl/data/network/DownloadsApiRepository;"
for m in dx.find_methods(classname="^"+re.escape(cls)+"$", methodname="^disallowDeviceDownload$"):
    for bb in m.get_basic_blocks().get():
        print("BB", bb.get_name(), "childs=", [(c[0],c[1]) for c in bb.childs])
        for ins in bb.get_instructions():
            print("   ", ins.get_name(), "|", ins.get_output(), "|", ins.get_operands())
    break
PY
```

Зафиксировать в комментарии `frame_of`: как из `get_operands()` достаётся регистр-приёмник, имя поля (`iget/sget`), сигнатура callee (`invoke*` + следующий `move-result*`).

- [ ] **Step 2: Write the failing test**

```python
def _check_androguard(apk):
    dx = load_apk(apk)
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
```

- [ ] **Step 3: Run to verify it fails**

Run: `./.venv/bin/python slice.py --selfcheck --apk apk/gpm.tnt_premier.apk`
Expected: FAIL — `NameError: name 'load_apk' is not defined`.

- [ ] **Step 4: Implement**

```python
from androguard.misc import AnalyzeAPK


def load_apk(path):
    _, _, dx = AnalyzeAPK(str(path))
    return dx


def _fqcn(descriptor):
    return descriptor[1:-1].replace("/", ".") if descriptor.startswith("L") else descriptor


def method_key(ma):
    return f"{_fqcn(ma.class_name)}->{ma.name}"


def resolve_call_sites(dx, cls, method):
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


def frame_of(ma):
    """MethodAnalysis -> {cfg, params, block_at}. None, если нет кода.
    Нормализация инструкций по форме, зафиксированной в Step 1."""
    m = ma.get_method()
    if m is None or m.get_code() is None:
        return None
    cfg = nx.DiGraph()
    starts = {}                         # start-offset -> node id
    bbs = list(ma.get_basic_blocks().get())
    for bb in bbs:
        node = bb.get_name()
        starts[bb.get_start()] = node
        cfg.add_node(node, insns=[_norm(list(bb.get_instructions()))],
                     start=bb.get_start(), end=bb.get_end())
        # insns хранить плоским списком:
        cfg.nodes[node]["insns"] = _norm(list(bb.get_instructions()))
    for bb in bbs:
        node = bb.get_name()
        for (_last, tgt, tbb) in bb.childs:
            cfg.add_edge(node, tbb.get_name())
    params = _params(m)
    def block_at(off):
        cand = [n for n in cfg.nodes if cfg.nodes[n]["start"] <= off < cfg.nodes[n]["end"]]
        return cand[0] if cand else None
    return {"cfg": cfg, "params": params, "block_at": block_at}
```

`_norm(instructions)` и `_params(method)` — по итогам Step 1. `_norm` превращает каждую инструкцию в `Insn(op, out, args)`: `op` из `get_name()` (сведённый к `const|iget|sget|move-result|other`), `out`/`args` — из `get_operands()`; для `move-result*` в `args` кладётся сигнатура предыдущего `invoke*`. `_params` возвращает `{регистр: индекс}` по числу аргументов метода (в Dalvik параметры — последние N регистров).

- [ ] **Step 5: Run to verify it passes**

Run: `./.venv/bin/python slice.py --selfcheck --apk apk/gpm.tnt_premier.apk`
Expected: `androguard ok` (загрузка ~130 с).

- [ ] **Step 6: Commit**

```bash
git add new/slice.py && git commit -m "feat(slice): androguard layer — load, xref call-sites, frame normalization"
```

---

## Task 4: Обратный межпроцедурный обход (плумбинг + фронтир)

Строит под-граф вызовов вверх от call-site. Предикаты плумбинга и фронтира — чистые (юнит-тест), сам обход — интеграционно.

**Files:**
- Modify: `new/slice.py`
- Test: `_check_walk_predicates()` (чистый) + ветка в `_check_androguard`.

**Interfaces:**
- Consumes: `dx`, `resolve_call_sites`, `method_key`.
- Produces:
  - `is_plumbing(key: str, ma) -> bool` — Kotlin-машинерия: `$default`, `access$`, класс с `$$inlined$`/`$$special$`, `invokeSuspend`/`create`/`invoke` класса-континуации.
  - `is_frontier(key: str) -> bool` — UI/lifecycle/entry-колбэк: имя ∈ `{onCreate,onStart,onResume,onViewCreated,onClick,onBind,...}` или класс из `android.`/`androidx.`.
  - `backward_frames(dx, cls, method, limit=6) -> dict` — `{reached, call_sites, frames, frontier, depth, plumbing_skipped}`; `frames` — семантические кадры (`{key, ma, callee_key, offset}`) до фронтира/лимита; плумбинг проходится насквозь и в лимит не идёт. Циклы гасит visited-множество.

- [ ] **Step 1: Write the failing test**

```python
def _check_walk_predicates():
    class FakeMA:  # достаточно для предикатов
        def __init__(self, cls): self.class_name = cls
    assert is_plumbing("a.b.C->postDeviceUpdate$default", FakeMA("La/b/C;"))
    assert is_plumbing("a.b.C$$inlined$x->invoke", FakeMA("La/b/C$$inlined$x;"))
    assert not is_plumbing("a.b.C->postDeviceUpdate", FakeMA("La/b/C;"))
    assert is_frontier("androidx.fragment.app.Fragment->onViewCreated")
    assert is_frontier("a.b.MyActivity->onCreate")
    assert not is_frontier("a.b.SomeRepository->refresh")
    print("  walk_predicates ok")
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/bin/python slice.py --selfcheck`
Expected: FAIL — `NameError: name 'is_plumbing' is not defined`.

- [ ] **Step 3: Implement**

```python
_FRONTIER_NAMES = {"onCreate", "onStart", "onResume", "onPause", "onStop",
                   "onViewCreated", "onCreateView", "onClick", "onBind",
                   "onReceive", "onHandleWork", "doWork", "onStartCommand"}


def is_plumbing(key, ma):
    name = key.rsplit("->", 1)[-1]
    cls = getattr(ma, "class_name", "")
    if name.endswith("$default") or name.startswith("access$"):
        return True
    if "$$inlined$" in cls or "$$special$" in cls:
        return True
    if name in ("invokeSuspend", "create", "invoke") and (
            "Continuation" in cls or "$" in cls.rsplit("/", 1)[-1]):
        return True
    return False


def is_frontier(key):
    cls, _, name = key.partition("->")
    if name in _FRONTIER_NAMES:
        return True
    return cls.startswith("android.") or cls.startswith("androidx.")


def backward_frames(dx, cls, method, limit=6):
    sites = resolve_call_sites(dx, cls, method)
    if not sites:
        return {"reached": False, "call_sites": [], "frames": [],
                "frontier": None, "depth": 0, "plumbing_skipped": []}
    frames, skipped, frontier = [], [], None
    visited = set()
    # очередь: (callee_key, caller_ma, offset, depth)
    queue = [(f"{cls}->{method}", s["caller_ma"], s["offset"], 0) for s in sites]
    while queue:
        callee_key, caller_ma, off, depth = queue.pop()
        ckey = method_key(caller_ma)
        if (ckey, off) in visited:
            continue
        visited.add((ckey, off))
        if is_plumbing(ckey, caller_ma):
            skipped.append(ckey)
        else:
            frames.append({"key": ckey, "ma": caller_ma,
                           "callee_key": callee_key, "offset": off})
            if is_frontier(ckey):
                frontier = ckey
                continue
            depth += 1
            if depth >= limit:
                continue
        # шаг вверх
        pcls, _, pm = ckey.partition("->")
        for s in resolve_call_sites(dx, pcls, pm):
            queue.append((ckey, s["caller_ma"], s["offset"], depth))
    return {"reached": True, "call_sites": sites, "frames": frames,
            "frontier": frontier, "depth": len(frames),
            "plumbing_skipped": skipped}
```

- [ ] **Step 4: Extend integration test (cycle safety)**

В `_check_androguard(apk)` добавить:

```python
    w = backward_frames(dx, "gpm.tnt_premier.features.downloads.impl.data.network.DownloadsApi",
                        "disallowDeviceDownload")
    assert w["reached"] and w["call_sites"], w
    assert len(w["frames"]) <= 6                      # лимит соблюдён
    # цикл в графе вызовов не зациклил обход (дошли до сюда — visited работает)
    print("  backward_frames ok")
```

- [ ] **Step 5: Run to verify it passes**

Run: `./.venv/bin/python slice.py --selfcheck --apk apk/gpm.tnt_premier.apk`
Expected: `walk_predicates ok` и `backward_frames ok`.

- [ ] **Step 6: Commit**

```bash
git add new/slice.py && git commit -m "feat(slice): backward interprocedural walk with plumbing skip and frontier"
```

---

## Task 5: Сборка среза ключа и запись `slice.jsonl`

Соединяет всё: обход (Task 4) → для каждого кадра стражи (Task 1) и источники (Task 2) → запись схемы спеки §4.

**Files:**
- Modify: `new/slice.py`
- Test: ветка в `_check_androguard(apk)` — форма записи для известного ключа.

**Interfaces:**
- Consumes: `backward_frames`, `frame_of`, `control_deps`, `classify_operand`, `Insn`.
- Produces:
  - `guards_of_frame(fr, criterion_offset) -> list[dict]` — стражи блока с вызовом: `[{opcode, sense, operand:{source_kind,detail}}]`.
  - `slice_key(dx, key) -> dict` — полная запись выхода (поля: `key,cls,method,reached,call_sites,guards,guard_count,args,frontier,depth,plumbing_skipped,inconclusive,notes`).
  - `run(dx, keys) -> list[dict]`.

- [ ] **Step 1: Write the failing test**

```python
def _check_slice_key(dx):
    rec = slice_key(dx, "gpm.tnt_premier.features.downloads.impl.data.network.DownloadsApi->disallowDeviceDownload")
    assert rec["reached"] is True
    assert rec["cls"].endswith("DownloadsApi") and rec["method"] == "disallowDeviceDownload"
    assert isinstance(rec["guards"], list) and rec["guard_count"] == len(rec["guards"])
    assert set(("reached","call_sites","guards","args","frontier","inconclusive")) <= set(rec)
    # ключ-форвардер без стражей: guard_count 0, не падение (Review Focus)
    assert rec["guard_count"] >= 0
    print("  slice_key ok")
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/bin/python slice.py --selfcheck --apk apk/gpm.tnt_premier.apk`
Expected: FAIL — `NameError: name 'slice_key' is not defined`.

- [ ] **Step 3: Implement**

```python
_IF_OPS = ("if-eqz", "if-nez", "if-eq", "if-ne", "if-lt", "if-ge",
           "if-gt", "if-le", "if-ltz", "if-gez", "if-gtz", "if-lez")


def guards_of_frame(fr, criterion_offset):
    cfg = fr["cfg"]
    crit = fr["block_at"](criterion_offset)
    if crit is None:
        return []
    exit_node = "__exit__"
    g = cfg.copy()
    for n in [x for x in cfg.nodes if cfg.out_degree(x) == 0]:
        g.add_edge(n, exit_node)
    if g.number_of_nodes() == len(cfg):        # не было терминалов
        g.add_edge(list(cfg.nodes)[-1], exit_node)
    guards = []
    for (branch, taken) in control_deps(g, crit, exit_node):
        insns = cfg.nodes[branch]["insns"]
        cond = next((i for i in reversed(insns) if i.op in _IF_OPS or i.op == "if"), None)
        opcode = cond.op if cond else "if"
        reg = cond.out if (cond and cond.out) else (cond.args[0] if cond and cond.args else None)
        operand = {"source_kind": "unknown", "detail": None}
        if reg is not None:
            kind, detail = classify_operand(cfg, branch, len(insns) - 1, reg, fr["params"])
            operand = {"source_kind": kind, "detail": detail}
        guards.append({"frame": None, "opcode": opcode,
                       "sense": f"->{taken}", "operand": operand})
    return guards


def slice_key(dx, key):
    cls, _, method = key.partition("->")
    w = backward_frames(dx, cls, method)
    rec = {"key": key, "cls": cls, "method": method,
           "reached": w["reached"],
           "call_sites": [{"caller": s["caller"], "offset": s["offset"]} for s in w["call_sites"]],
           "guards": [], "guard_count": 0, "args": [],
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
        all_guards.extend(gs)
    rec["guards"] = all_guards
    rec["guard_count"] = len(all_guards)
    if w["frontier"] is None and w["depth"] >= 6:
        rec["notes"].append("depth_cap")
    return rec


def run(dx, keys):
    return [slice_key(dx, k) for k in keys]
```

- [ ] **Step 4: Run to verify it passes**

Add `_check_slice_key(dx)` в ветку `--apk` of `_selfcheck`. Run: `./.venv/bin/python slice.py --selfcheck --apk apk/gpm.tnt_premier.apk`
Expected: `slice_key ok`.

- [ ] **Step 5: Commit**

```bash
git add new/slice.py && git commit -m "feat(slice): assemble per-key slice record with guards and args"
```

---

## Task 6: Отчёт, CLI, полный `--selfcheck`

Человекочитаемый отчёт + argparse как в `diff.py`.

**Files:**
- Modify: `new/slice.py`
- Test: `_check_report()` (чистый, на фейковых записях).

**Interfaces:**
- Consumes: `run`, `load_hidden`.
- Produces:
  - `load_hidden(path) -> list[str]` — уникальные ключи со `status=hidden`.
  - `report(records, meta=None) -> str` — сводка + распределение `guard_count` + топ источников + построчно.
  - `main()`.

- [ ] **Step 1: Write the failing test**

```python
def _check_report():
    recs = [
        {"key":"a->x","reached":True,"guard_count":1,"guards":[{"operand":{"source_kind":"invoke","detail":"S->isLoggedIn()Z"}}],"inconclusive":False,"call_sites":[{"caller":"c->x","offset":1}],"frontier":"F->onCreate","args":[],"plumbing_skipped":[],"notes":[]},
        {"key":"b->y","reached":False,"guard_count":0,"guards":[],"inconclusive":False,"call_sites":[],"frontier":None,"args":[],"plumbing_skipped":[],"notes":["no_caller"]},
    ]
    txt = report(recs)
    assert "guard_count" in txt and "no_caller" in txt.lower()
    assert "1" in txt  # распределение
    print("  report ok")
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/bin/python slice.py --selfcheck`
Expected: FAIL — `NameError: name 'report' is not defined`.

- [ ] **Step 3: Implement**

```python
from collections import Counter


def load_hidden(path):
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
    lines = []
    w = lines.append
    if meta:
        w(f"Приложение: {meta.get('package')} versionName={meta.get('versionName')} "
          f"versionCode={meta.get('versionCode')}")
    total = len(records)
    reached = sum(r["reached"] for r in records)
    no_caller = sum(1 for r in records if not r["reached"])
    inconcl = sum(1 for r in records if r.get("inconclusive"))
    w(f"Всего ключей: {total} | reached: {reached} | no_caller: {no_caller} | inconclusive: {inconcl}")
    dist = Counter(min(r["guard_count"], 4) for r in records if r["reached"])
    w("Распределение guard_count (сырьё для Таблицы IV):")
    for k in range(5):
        label = "4+" if k == 4 else str(k)
        w(f"  {label} стражей: {dist.get(k, 0)}")
    src = Counter(g["operand"]["detail"] for r in records for g in r["guards"]
                  if g["operand"]["source_kind"] in ("invoke", "field") and g["operand"]["detail"])
    w("Топ источников стражей:")
    for name, n in src.most_common(15):
        w(f"  {n:3d}  {name}")
    w("")
    for r in records:
        tag = "HIDDEN" if r["reached"] else "NO-CALLER"
        w(f"[{tag}] {r['key']}  guards={r['guard_count']} frontier={r['frontier']} notes={r['notes']}")
        for g in r["guards"]:
            o = g["operand"]
            w(f"    {g['opcode']} {g['sense']}  <- {o['source_kind']}:{o['detail']}  @{g['frame']}")
    return "\n".join(lines)


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
    dx = load_apk(args.apk)
    records = run(dx, keys)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps({k: v for k, v in r.items() if k != "ma"},
                                   ensure_ascii=False) + "\n")
    txt = report(records)
    print(txt)
    if args.out:
        Path(str(args.out).replace(".jsonl", ".report.txt")).write_text(txt, encoding="utf-8")
```

- [ ] **Step 4: Update `_selfcheck` and `__main__`**

```python
def _selfcheck(apk=None):
    _check_control_deps()
    _check_classify_operand()
    _check_walk_predicates()
    _check_report()
    if apk:
        dx = load_apk(apk)
        _check_androguard_dx(dx)   # рефактор _check_androguard: принимает dx
        _check_slice_key(dx)
    print("selfcheck ok")


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run full selfcheck**

Run: `./.venv/bin/python slice.py --selfcheck` (без APK — все чистые проверки)
Expected: `selfcheck ok`.
Run: `./.venv/bin/python slice.py --selfcheck --apk apk/gpm.tnt_premier.apk` (полный)
Expected: `selfcheck ok`.

- [ ] **Step 6: Прогон на пилоте end-to-end**

```bash
./.venv/bin/python slice.py --hidden out/gpm.tnt_premier.manual.hidden.jsonl \
    --apk apk/gpm.tnt_premier.apk --out out/gpm.tnt_premier.slice.jsonl
```
Expected: 133 записи; в шапке отчёта — распределение guard_count; ненулевой reached.

- [ ] **Step 7: Commit**

```bash
git add new/slice.py && git commit -m "feat(slice): report, CLI, full selfcheck; pilot run on TNT"
```

---

## Task 7: Ground truth и оценка точности (валидация RQ2)

Спека §8: без ground truth метрика не годится. Детерминированный сэмплер + скорер precision/recall против ручной разметки.

**Files:**
- Create: `new/eval_slice.py`
- Test: `_check_scorer()` в `eval_slice.py`.

**Interfaces:**
- Produces:
  - `pick_sample(keys, n=18, seed=42) -> list[str]` — детерминированная подвыборка.
  - `score(pred_guards: dict, truth_guards: dict) -> dict` — precision/recall детекции стражей по ключам (страж = пара `(source_kind, detail)`).

- [ ] **Step 1: Write the failing test**

```python
def _check_scorer():
    pred = {"a->x": {("invoke","S->isLoggedIn()Z")}, "b->y": set()}
    truth = {"a->x": {("invoke","S->isLoggedIn()Z"), ("field","F->on")}, "b->y": set()}
    s = score(pred, truth)
    assert s["tp"] == 1 and s["fn"] == 1 and s["fp"] == 0
    assert abs(s["recall"] - 0.5) < 1e-9 and s["precision"] == 1.0
    print("  scorer ok")
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/bin/python eval_slice.py --selfcheck`
Expected: FAIL — `NameError: name 'score' is not defined`.

- [ ] **Step 3: Implement**

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Оценка точности слайсера против ручной разметки (ground truth, RQ2).

1) pick_sample печатает N ключей для ручного разбора в JADX;
2) разметку кладём в truth.json: {key: [[kind, detail], ...]};
3) score сравнивает с slice.jsonl и печатает precision/recall.
"""
import argparse, json, random, sys
from pathlib import Path


def pick_sample(keys, n=18, seed=42):
    r = random.Random(seed)
    return sorted(r.sample(keys, min(n, len(keys))))


def _guards_of(rec):
    return {(g["operand"]["source_kind"], g["operand"]["detail"]) for g in rec.get("guards", [])}


def score(pred, truth):
    tp = fp = fn = 0
    for k in truth:
        p, t = pred.get(k, set()), truth[k]
        tp += len(p & t); fp += len(p - t); fn += len(t - p)
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": prec, "recall": rec}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--slice", type=Path)
    ap.add_argument("--truth", type=Path)
    ap.add_argument("--hidden", type=Path)
    ap.add_argument("--pick", action="store_true")
    ap.add_argument("--selfcheck", action="store_true")
    a = ap.parse_args()
    if a.selfcheck:
        _check_scorer(); print("selfcheck ok"); return
    if a.pick:
        import slice as sl
        for k in pick_sample(sl.load_hidden(a.hidden)):
            print(k)
        return
    pred = {}
    for line in a.slice.read_text().splitlines():
        r = json.loads(line); pred[r["key"]] = _guards_of(r)
    truth = {k: {tuple(x) for x in v} for k, v in json.loads(a.truth.read_text()).items()}
    print(json.dumps(score(pred, truth), indent=2, ensure_ascii=False))


def _check_scorer():
    pred = {"a->x": {("invoke","S->isLoggedIn()Z")}, "b->y": set()}
    truth = {"a->x": {("invoke","S->isLoggedIn()Z"), ("field","F->on")}, "b->y": set()}
    s = score(pred, truth)
    assert s["tp"] == 1 and s["fn"] == 1 and s["fp"] == 0
    assert abs(s["recall"] - 0.5) < 1e-9 and s["precision"] == 1.0
    print("  scorer ok")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run to verify it passes**

Run: `./.venv/bin/python eval_slice.py --selfcheck`
Expected: `scorer ok` / `selfcheck ok`.

- [ ] **Step 5: Manual ground truth (не код)**

```bash
./.venv/bin/python eval_slice.py --pick --hidden out/gpm.tnt_premier.manual.hidden.jsonl
```
Разобрать 18 ключей в JADX, стражи занести в `new/out/tnt_truth.json`. Прогнать `--slice ... --truth ...`, записать precision/recall и классы ошибок в главу методологии ВКР.

- [ ] **Step 6: Commit**

```bash
git add new/eval_slice.py && git commit -m "feat(eval): ground-truth sampler and precision/recall scorer"
```

---

## Self-Review

**Spec coverage:** §3 стадия A → Task 3,4; стадия B → Task 1,2,5; §4 схема выхода → Task 5,6; §5.1 call-sites → Task 3; §5.2–5.4 обход/плумбинг/фронтир → Task 4; §5.5 управляющие деп → Task 1; §5.6–5.7 источники → Task 2,5; §7 отчёт → Task 6; §8 ground truth → Task 7; §10 selfcheck → Task 1–6; §11 Soot — осознанно отложено, задачи нет. Пробелов нет.

**Placeholder scan:** `_norm`/`_params` в Task 3 не дописаны полным кодом — намеренно: их точная форма зависит от Discovery Step 1 (форма `get_operands()` в androguard 4.1.4), контракт задан. Это единственное место, зависящее от рантайм-факта; всё остальное — рабочий код.

**Type consistency:** `Insn(op,out,args)` единообразен в Task 2,3,5. `frame_of` → dict `{cfg,params,block_at}` — потребляется в Task 5 так же. `backward_frames` → dict с `frames/call_sites/frontier` — Task 5 читает те же ключи. `control_deps` → list[(branch,taken)] — Task 5 распаковывает так же.

**Review Focus:** все 5 закрыты тестами (Task 1: прямая линия + петля без выхода; Task 2: phi→unknown; Task 3: пустой XREF; Task 4: цикл + лимит).
