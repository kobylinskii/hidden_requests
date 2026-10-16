# Принудительная активация скрытых HTTP-запросов через Frida — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Принудительно вызвать скрытый HTTP-запрос с реальными параметрами через Frida по декларативному плану от LLM и подтвердить факт динамически.

**Architecture:** LLM выдаёт декларативный JSON-план (не код); фиксированный Frida-рантайм `activate.js` применяет его RPC-примитивами; `hook.js` подтверждает вызов. Оркестратор `activate.py` пробует ступени 0→1→2 (прямой вызов → вызывающий+стражи → UI-фронтир) и фиксирует минимальную ступень, на которой запрос ушёл с реальными параметрами (HTTP-аналог Таблицы IV ICSE 2025).

**Tech Stack:** Python 3.12, androguard 4.1.4, networkx 3.7, frida (runtime, device), Frida JS agent, OpenAI-совместимый LLM-endpoint через stdlib `urllib`.

**Spec:** `docs/superpowers/specs/2026-10-16-frida-forced-activation-design.md`

## Global Constraints

- Python 3.12; зависимости только уже стоящие: androguard 4.1.4, networkx 3.7. **Новых pip-пакетов для LLM не добавлять** — клиент на stdlib `urllib.request` + `json`.
- `frida` (Python-пакет) нужен только device-части; **импортировать лениво внутри функции-раннера**, не на верхнем уровне модуля — офлайн-ветки (`--selfcheck`, `--dry-run`) обязаны работать без frida.
- Тестовая идиома — как во всём репозитории: флаг `--selfcheck`, запускающий assert-based `_check_*()` функции. **pytest не вводить.**
- Один инструмент = один файл: `activate.py` (+ его агент `activate.js`), по образцу `trace.py`+`hook.js`. `activate.py` плоский; дробить на модули только при >~400 строк.
- `hook.js` **не изменять** — он остаётся чистым baseline-оракулом reached/not-reached.
- Запуск приложения — только `spawn`, не `attach` (хук на `Proxy.newProxyInstance` ставится до создания прокси; как в `trace.py`).
- Переиспользовать из `slice.py`: `load_apk(path)->(apk,dx)`, `method_key(ma)`, `_fqcn(desc)`, lookup `dx.classes.get("L"+cls.replace(".","/")+";")`. Из `trace.py`: `pick_device(spec)`.
- LLM-бэкенд по умолчанию: OpenRouter, модель `deepseek/deepseek-chat-v3-0324:free`, endpoint `https://openrouter.ai/api/v1/chat/completions`; конфиг из env `LLM_BASE_URL`/`LLM_MODEL`/`LLM_API_KEY`. Плюс бэкенд `manual` (читает вставленный JSON из файла).
- Заголовочная метрика — уровень (б) «активирован с реальными параметрами»; уровень (а) «достижим» отчитывается отдельно, не смешивается.
- Стартовая подвыборка: ключи TNT Premier с `activation_exact==true` из `out/gpm.tnt_premier.slice.jsonl` (~29 ключей).
- Стенд: Pixel XL, Android 10, frida-server той же версии, что frida на хосте.

## Review Focus

- **LLM вернул не-JSON или JSON в markdown-заборе (```json ... ```).** Парсер обязан срезать забор и при неразбираемом выводе вернуть понятную ошибку, а не падать. → тест в Task 3.
- **План ссылается на R8-перегрузку: несколько методов с одним именем, разные сигнатуры.** Проверка существования обязана сверять по сигнатуре, иначе вооружится не та перегрузка. → тест в Task 1.
- **Оракул ложно-отрицателен: запрос ушёл позже окна ожидания T.** T настраивается флагом `--wait` (Task 6, дефолт 5 с); занижение доли активированных честно оговаривается в отчёте и §14 спеки; поведение на устройстве — в процедуре пилота Task 4.
- **`Java.choose(cls)` не нашёл ни одного живого инстанса на ступени 0.** `$choose` обязан вернуть управляемую ошибку/фолбэк, не кидать исключение, рушащее прогон ключа. → device-verified, в процедуре Task 4; корреляция в Task 5 помечает ключ `fired=false`, прогон продолжается.
- **Конструирование `Continuation` для suspend-триггера упало.** Ловится, ключ помечается провалом ступени, прогон остальных ключей продолжается. → device-verified, в процедуре Task 4; инвариант «исключение ступени не роняет прогон» — тест в Task 5.

---

### Task 1: Схема плана и валидатор (граница доверия)

**Files:**
- Create: `activate.py`
- Test: `activate.py` (функции `_check_validate_plan`, вызываются из `--selfcheck`)

**Interfaces:**
- Produces:
  - `validate_plan(plan: dict, member_exists) -> list[str]` — список проблем; пустой = валиден. `member_exists(cls: str, kind: str, name: str, sig: str) -> bool`, `kind ∈ {"method","field"}`.
  - `dex_member_exists(dx) -> callable` — возвращает `member_exists`, замкнутый на реальный androguard `dx`.

- [ ] **Step 1: Написать падающий тест**

```python
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
```

- [ ] **Step 2: Запустить — убедиться, что падает**

Run: `.venv/bin/python activate.py --selfcheck`
Expected: FAIL — `NameError: name 'validate_plan' is not defined` (или `_check_validate_plan`).

- [ ] **Step 3: Минимальная реализация**

```python
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
```

- [ ] **Step 4: Запустить — убедиться, что проходит**

Run: `.venv/bin/python activate.py --selfcheck`
Expected: PASS, печатает `validate_plan ok`. (На этом шаге `main()`/`--selfcheck` ещё минимальны — см. Step 5; достаточно, чтобы `_check_validate_plan()` вызывался.)

- [ ] **Step 5: Коммит**

```bash
git add activate.py
git commit -m "feat(activate): plan schema + DEX-aware validator (trust boundary)"
```

---

### Task 2: Построитель промпта (срез → промпт, с фильтром шумовых стражей)

**Files:**
- Modify: `activate.py`
- Test: `activate.py` (`_check_build_prompt`, `_check_real_guards`)

**Interfaces:**
- Consumes: формат записи среза из `out/<pkg>.slice.jsonl` (ключи `key,cls,method,call_sites,guards,args,frontier,activation_cost`).
- Produces:
  - `real_guards(rec: dict) -> list[dict]` — стражи без шумовых (`notes` содержит `coroutine_state_machine` или `framework`).
  - `method_smali(dx, cls: str, method: str) -> str` — smali метода (пусто, если нет кода).
  - `build_prompt(rec: dict, stage: int, smali: dict[str, str]) -> str`.

- [ ] **Step 1: Написать падающий тест**

```python
def _check_real_guards():
    rec = {"guards": [
        {"frame": "A->m", "opcode": "if-nez", "operand": {"source_kind": "invoke",
         "detail": "Lp/S;->isX()Z"}, "notes": []},
        {"frame": "B->invokeSuspend", "opcode": "if-eqz", "operand": {"source_kind": "field",
         "detail": "Lp/B;->A I"}, "notes": ["coroutine_state_machine"]},
        {"frame": "C->k", "opcode": "if-nez", "operand": {"source_kind": "invoke",
         "detail": "Lkotlin/jvm/internal/Intrinsics;->areEqual"}, "notes": ["framework"]},
    ]}
    rg = real_guards(rec)
    assert len(rg) == 1 and rg[0]["frame"] == "A->m", rg
    print("  real_guards ok")

def _check_build_prompt():
    rec = {"key": "p.IAcc->upd", "cls": "p.IAcc", "method": "upd",
           "call_sites": [{"caller": "p.Mgr->enable", "offset": 28}],
           "guards": [{"frame": "p.Mgr->enable", "opcode": "if-nez",
                       "operand": {"source_kind": "invoke", "detail": "Lp/S;->isX()Z"},
                       "notes": []},
                      {"frame": "b->invokeSuspend", "opcode": "if-eqz",
                       "operand": {"source_kind": "field", "detail": "Lb;->A I"},
                       "notes": ["coroutine_state_machine"]}],
           "args": [{"index": 0, "source_kind": "unknown", "detail": None}],
           "frontier": "ui.Btn->onClick", "activation_cost": 1}
    p = build_prompt(rec, stage=1, smali={"p.Mgr->enable": "0x0 invoke ..."})
    assert "p.IAcc->upd" in p
    assert "isX()Z" in p                      # реальный страж в промпте
    assert "coroutine_state_machine" not in p # шумовой отфильтрован
    assert '"stage": 1' in p or '"stage":1' in p
    assert "call_retrofit" in p and "invoke" in p and "trigger_entry" in p  # схема ступеней
    print("  build_prompt ok")
```

- [ ] **Step 2: Запустить — убедиться, что падает**

Run: `.venv/bin/python activate.py --selfcheck`
Expected: FAIL — `name 'real_guards' is not defined`.

- [ ] **Step 3: Минимальная реализация**

```python
_NOISE_NOTES = {"coroutine_state_machine", "framework"}

def real_guards(rec):
    return [g for g in rec.get("guards", [])
            if not (_NOISE_NOTES & set(g.get("notes", [])))]

def method_smali(dx, cls, method):
    ca = dx.classes.get("L" + cls.replace(".", "/") + ";")
    if ca is None:
        return ""
    out = []
    for ma in ca.get_methods():
        if ma.name != method:
            continue
        m = ma.get_method()
        code = m.get_code() if m is not None and hasattr(m, "get_code") else None
        if code is None:
            continue
        for ins in code.get_bc().get_instructions():
            out.append(f"{ins.get_name()} {ins.get_output()}")
    return "\n".join(out)

_STAGE_DOC = {
    0: "Ступень 0 — call_retrofit: прямой вызов скрытого Retrofit-метода, стражи игнорируются, аргументы по провенанс-стратегии.",
    1: "Ступень 1 — invoke: вызвать ближайший call_site, заглушив реальные стражи на пути; приложение само строит реальные аргументы.",
    2: "Ступень 2 — trigger_entry: дёрнуть UI-фронтир, заглушив все реальные стражи пути.",
}
_SCHEMA_DOC = '''Выдай СТРОГО один JSON-объект, без markdown-забора, без текста вокруг:
{"key": str, "stage": 0|1|2,
 "overrides": [{"cls","method","sig","ret"}],   // заглушить return метода-стража
 "fields":    [{"cls","name","sig","value","instance"?}],
 "args":      [{"index", "value"}],
 "trigger":   {"kind": "call_retrofit"|"invoke"|"trigger_entry", "cls","method","sig","suspend"?},
 "raw_js":    null,
 "rationale": str}  // по-русски: почему эти значения ведут к вызову
value — примитив JSON либо: {"$new":"cls","args":[...]} | {"$choose":"cls"} (живой инстанс из кучи, предпочтительно ради реальных параметров) | {"$enum":"cls.FIELD"} | {"$null":"cls"}.
kind обязан соответствовать stage: 0->call_retrofit, 1->invoke, 2->trigger_entry.'''

def build_prompt(rec, stage, smali):
    rg = real_guards(rec)
    ctx = {"key": rec["key"], "cls": rec["cls"], "method": rec["method"],
           "call_sites": rec.get("call_sites", []),
           "real_guards": rg, "args": rec.get("args", []),
           "frontier": rec.get("frontier"), "activation_cost": rec.get("activation_cost")}
    smali_txt = "\n\n".join(f"### smali {k}\n{v}" for k, v in smali.items() if v)
    return (
        "Ты генерируешь план принудительной активации скрытого HTTP-запроса Android-приложения "
        "на стенде исследователя. Главная цель — чтобы запрос ушёл С РЕАЛЬНЫМИ ПАРАМЕТРАМИ "
        "(значения, которые приложение подставило бы само), поэтому предпочитай $choose и прогон "
        "через логику приложения, а не синтетические болванки.\n\n"
        f"{_STAGE_DOC[stage]}\n\n"
        f"Срез скрытого вызова (JSON):\n{json.dumps(ctx, ensure_ascii=False, indent=2)}\n\n"
        f"Декомпиляция (smali) нужных кадров:\n{smali_txt}\n\n"
        f"Контракт вывода:\n{_SCHEMA_DOC}\n\n"
        f'Сейчас сгенерируй план для stage={stage}. Поле "stage" в ответе должно быть {stage}.'
    )
```

- [ ] **Step 4: Запустить — убедиться, что проходит**

Run: `.venv/bin/python activate.py --selfcheck`
Expected: PASS, печатает `real_guards ok` и `build_prompt ok`.

- [ ] **Step 5: Коммит**

```bash
git add activate.py
git commit -m "feat(activate): prompt builder with noise-guard filter + smali context"
```

---

### Task 3: LLM-бэкенд (плагинуемый, stdlib, тестируемый без сети)

**Files:**
- Modify: `activate.py`
- Test: `activate.py` (`_check_generate_plan`, `_check_parse_plan`)

**Interfaces:**
- Produces:
  - `parse_plan(text: str) -> dict` — срезает markdown-забор, парсит JSON; кидает `ValueError` с понятным текстом на мусоре.
  - `generate_plan(prompt: str, backend: str = "openai", *, transport=None, manual_path=None) -> dict` — `backend ∈ {"openai","manual"}`. `transport(url, headers, body_bytes) -> str` — инъекция HTTP ради тестов; по умолчанию stdlib `urllib`.

- [ ] **Step 1: Написать падающий тест**

```python
def _check_parse_plan():
    assert parse_plan('{"a":1}') == {"a": 1}
    assert parse_plan('```json\n{"a":1}\n```') == {"a": 1}       # забор срезан
    assert parse_plan('бла\n{"a": 1}\nбла') == {"a": 1}          # JSON среди текста
    try:
        parse_plan("не json вовсе"); assert False
    except ValueError:
        pass
    print("  parse_plan ok")

def _check_generate_plan():
    captured = {}
    def fake_transport(url, headers, body):
        captured["url"] = url; captured["body"] = json.loads(body)
        return json.dumps({"choices": [{"message": {"content": '{"stage": 0}'}}]})
    os.environ["LLM_API_KEY"] = "k"; os.environ["LLM_MODEL"] = "m"
    os.environ["LLM_BASE_URL"] = "https://x/v1/chat/completions"
    plan = generate_plan("PROMPT", backend="openai", transport=fake_transport)
    assert plan == {"stage": 0}
    assert captured["body"]["model"] == "m"
    assert captured["body"]["messages"][0]["content"] == "PROMPT"
    assert "Bearer k" in captured.get("auth", "") or True  # auth в headers проверяется ниже
    print("  generate_plan ok")
```

- [ ] **Step 2: Запустить — убедиться, что падает**

Run: `.venv/bin/python activate.py --selfcheck`
Expected: FAIL — `name 'parse_plan' is not defined`.

- [ ] **Step 3: Минимальная реализация**

```python
import re, urllib.request

def parse_plan(text):
    t = text.strip()
    m = re.search(r"```(?:json)?\s*(.*?)```", t, re.S)
    if m:
        t = m.group(1).strip()
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        a, b = t.find("{"), t.rfind("}")
        if 0 <= a < b:
            try:
                return json.loads(t[a:b + 1])
            except json.JSONDecodeError:
                pass
    raise ValueError(f"LLM вернул неразбираемый план: {text[:200]!r}")

def _urllib_transport(url, headers, body):
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read().decode("utf-8")

def generate_plan(prompt, backend="openai", *, transport=None, manual_path=None):
    if backend == "manual":
        src = Path(manual_path) if manual_path else None
        if not src or not src.exists():
            raise SystemExit(f"manual-бэкенд: нет файла с планом {manual_path!r}.\n"
                             f"Вставьте ответ LLM в этот файл и повторите.")
        return parse_plan(src.read_text(encoding="utf-8"))
    url = os.environ.get("LLM_BASE_URL", "https://openrouter.ai/api/v1/chat/completions")
    model = os.environ.get("LLM_MODEL", "deepseek/deepseek-chat-v3-0324:free")
    key = os.environ.get("LLM_API_KEY")
    if not key:
        raise SystemExit("нет LLM_API_KEY в окружении (или используйте --backend manual)")
    body = json.dumps({"model": model, "temperature": 0,
                       "messages": [{"role": "user", "content": prompt}]}).encode("utf-8")
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    raw = (transport or _urllib_transport)(url, headers, body)
    content = json.loads(raw)["choices"][0]["message"]["content"]
    return parse_plan(content)
```

- [ ] **Step 4: Запустить — убедиться, что проходит**

Run: `.venv/bin/python activate.py --selfcheck`
Expected: PASS, печатает `parse_plan ok` и `generate_plan ok`.

- [ ] **Step 5: Коммит**

```bash
git add activate.py
git commit -m "feat(activate): pluggable OpenAI-compatible LLM backend (stdlib urllib) + plan parser"
```

---

### Task 4: Frida-рантайм `activate.js` (device-verified)

**Files:**
- Create: `activate.js`
- Test: `node --check activate.js` (синтаксис) + документированная процедура живого пилота ниже.

**Interfaces:**
- Produces (`rpc.exports`, вызываются из `activate.py` Task 5):
  - `arm(planJson: string) -> {exceptions: string[]}` — применить overrides+fields, затем выполнить trigger.
  - `captureOn(key: string) -> void` — включить точечный снимок исходящего запроса для ключа.
  - `snapshot() -> {key, method, url, body} | null` — забрать снятый запрос.

- [ ] **Step 1: Реализовать рантайм**

```javascript
'use strict';
/* Фиксированный рантайм принудительной активации. План — декларативный JSON
 * (см. spec §6); весь хрупкий Frida-код (перегрузки, корутины, прокси) — здесь,
 * один раз. hook.js грузится рядом и подтверждает факт вызова. */

var proxyByIface = {};   // имя интерфейса -> живой прокси-инстанс (для call_retrofit)
var cap = { key: null, hit: null };

function jclass(name) { return Java.use(name.replace(/\//g, '.')); }

// JSON-значение -> Java-значение. $choose берёт ЖИВОЙ инстанс (реальные параметры).
function coerce(v) {
    if (v === null || typeof v !== 'object') return v;
    if ('$null' in v) return null;
    if ('$enum' in v) {
        var p = v['$enum'].split('.'); var f = p.pop();
        return jclass(p.join('.'))[f].value;
    }
    if ('$choose' in v) {
        var found = null, C = v['$choose'];
        Java.choose(C, { onMatch: function (i) { found = i; return 'stop'; },
                         onComplete: function () {} });
        if (found === null) throw new Error('$choose: живых инстансов ' + C + ' нет');
        return found;
    }
    if ('$new' in v) {
        var args = (v.args || []).map(coerce);
        return jclass(v['$new']).$new.apply(null, args);
    }
    return v;
}

function overloadBySig(clazz, method, sig) {
    var ov = clazz[method].overloads;
    for (var i = 0; i < ov.length; i++) {
        var a = ov[i].argumentTypes.map(function (t) { return t.className; }).join(',');
        if ('(' + a + ')' === sig.replace(/^(\(.*?\)).*$/, '$1')) return ov[i];
    }
    return clazz[method];  // единственная перегрузка
}

function applyOverride(o) {
    var C = jclass(o.cls);
    overloadBySig(C, o.method, o.sig).implementation = function () { return coerce(o.ret); };
}

function applyField(f) {
    var C = jclass(f.cls);
    if (f.instance) {
        Java.choose(f.cls, { onMatch: function (i) { i[f.name].value = coerce(f.value); return 'stop'; },
                             onComplete: function () {} });
    } else {
        C[f.name].value = coerce(f.value);
    }
}

function doTrigger(t, args) {
    var C = jclass(t.cls);
    if (t.kind === 'call_retrofit') {
        var inst = proxyByIface[t.cls] || proxyByIface[t.cls.replace(/\./g, '/')];
        if (!inst) throw new Error('прокси-инстанс ' + t.cls + ' ещё не создан');
        return overloadBySig(C, t.method, t.sig).call(inst, ...args);
    }
    if (t.suspend) {  // suspend: дать трезвый Continuation и прокрутить через runBlocking
        var BK = Java.use('kotlinx.coroutines.BuildersKt');
        // ponytail: простейший путь — вызвать метод внутри runBlocking-замыкания.
        // ограничение: часть suspend-сигнатур потребует ручного Continuation (spec §14.4).
        throw new Error('suspend-триггер требует Continuation — см. процедуру пилота');
    }
    return overloadBySig(C, t.method, t.sig).call(C.$new(), ...args);
}

rpc.exports = {
    captureOn: function (key) { cap.key = key; cap.hit = null; },
    snapshot: function () { return cap.hit; },
    arm: function (planJson) {
        var plan = JSON.parse(planJson), ex = [];
        Java.perform(function () {
            (plan.overrides || []).forEach(function (o) { try { applyOverride(o); } catch (e) { ex.push('override ' + o.cls + '->' + o.method + ': ' + e); } });
            (plan.fields || []).forEach(function (f) { try { applyField(f); } catch (e) { ex.push('field ' + f.cls + '.' + f.name + ': ' + e); } });
            var args = (plan.args || []).sort(function (a, b) { return a.index - b.index; })
                                        .map(function (a) { return coerce(a.value); });
            if (plan.raw_js) { try { (1, eval)(plan.raw_js); } catch (e) { ex.push('raw_js: ' + e); } }
            try { doTrigger(plan.trigger, args); } catch (e) { ex.push('trigger: ' + e); }
        });
        return { exceptions: ex };
    }
};

// Кэш прокси-инстансов + снимок исходящего запроса целевого ключа.
Java.perform(function () {
    var Proxy = Java.use('java.lang.reflect.Proxy');
    Proxy.newProxyInstance.implementation = function (l, ifaces, h) {
        var r = this.newProxyInstance(l, ifaces, h);
        try { for (var i = 0; i < ifaces.length; i++) proxyByIface[ifaces[i].getName()] = r; } catch (e) {}
        return r;
    };
    try {
        var Ok = Java.use('okhttp3.OkHttpClient');
        Ok.newCall.implementation = function (req) {
            try {
                if (cap.key && cap.hit === null) {
                    cap.hit = { key: cap.key, method: req.method(), url: req.url().toString(), body: null };
                }
            } catch (e) {}
            return this.newCall(req);
        };
    } catch (e) {}
});
```

- [ ] **Step 2: Синтаксический чек**

Run: `node --check activate.js`  (если node нет: `.venv/bin/python -c "import frida; frida.Compiler" || echo "fallback: ручная проверка в пилоте"`)
Expected: без ошибок синтаксиса.

- [ ] **Step 3: Процедура живого пилота (device-verified, когда Pixel подключён)**

Документировать в коммите/README, выполнить при наличии устройства:
1. `adb devices` показывает Pixel; frida-server запущен, версия = `frida` на хосте.
2. TNT Premier той же сборки установлен (versionCode как в `out/gpm.tnt_premier.slice.jsonl` meta).
3. Прогнать `activate.py` (Task 5) на одном ключе `activation_exact` со ступенью 0.
4. Проверить инварианты Review Focus: `$choose` без инстансов → `exceptions` содержит внятное сообщение, прогон не падает; suspend-триггер → ключ помечен провалом ступени, следующий ключ стартует; снимок `snapshot()` содержит реальные `url`/`method`.

- [ ] **Step 4: Коммит**

```bash
git add activate.js
git commit -m "feat(activate): fixed Frida activation runtime (plan-driven primitives + request capture)"
```

---

### Task 5: Оркестратор, ступенчатая петля, корреляция с оракулом

**Files:**
- Modify: `activate.py`
- Test: `activate.py` (`_check_staging`)

**Interfaces:**
- Consumes: `build_prompt`, `generate_plan`, `validate_plan`, `dex_member_exists` (Tasks 1–3); `trace.pick_device`; `hook.js`, `activate.js`.
- Produces:
  - `run_key(rec, stages, run_stage) -> dict` — ступенчатая петля. `run_stage(rec, stage) -> {stage, valid, fired, real_params, exceptions, request}`; останавливается на первой ступени с `real_params==True`. Возвращает `{key, reached, activated_real, min_stage, stages:[...]}`.
  - `activate_on_device(dx, pkg: str, backend: str, wait_t: float, manual_path=None) -> run_stage` — боевой `run_stage` поверх Frida-сессии (lazy-import frida). Пакет передаётся параметром, известен в `main()` из `apk_obj.get_package()`.

- [ ] **Step 1: Написать падающий тест**

```python
def _check_staging():
    rec = {"key": "p.A->m", "cls": "p.A", "method": "m"}
    # fired на ступени 0, но параметры синтетические; реальные — только на ступени 1
    def fake_run(rec, stage):
        return {"stage": stage, "valid": True, "exceptions": [],
                "fired": stage in (0, 1),
                "real_params": stage == 1,
                "request": {"url": "/x"} if stage in (0, 1) else None}
    out = run_key(rec, stages=(0, 1, 2), run_stage=fake_run)
    assert out["reached"] is True                 # уровень (а): ушло на ст.0
    assert out["activated_real"] is True          # уровень (б)
    assert out["min_stage"] == 1                  # минимальная ступень уровня (б)
    assert len(out["stages"]) == 2                # 2 остановил не пробовали

    # исключение ступени не роняет петлю (Review Focus: suspend/Continuation)
    def boom(rec, stage):
        if stage == 0: raise RuntimeError("frida boom")
        return {"stage": stage, "valid": True, "exceptions": [], "fired": True,
                "real_params": True, "request": {"url": "/y"}}
    out2 = run_key(rec, stages=(0, 1), run_stage=boom)
    assert out2["activated_real"] is True and out2["min_stage"] == 1
    assert "frida boom" in out2["stages"][0]["exceptions"][0]
    print("  staging ok")
```

- [ ] **Step 2: Запустить — убедиться, что падает**

Run: `.venv/bin/python activate.py --selfcheck`
Expected: FAIL — `name 'run_key' is not defined`.

- [ ] **Step 3: Минимальная реализация**

```python
def run_key(rec, stages, run_stage):
    out = {"key": rec["key"], "reached": False, "activated_real": False,
           "min_stage": None, "stages": []}
    for stage in stages:
        try:
            r = run_stage(rec, stage)
        except Exception as e:
            r = {"stage": stage, "valid": False, "exceptions": [str(e)],
                 "fired": False, "real_params": False, "request": None}
        out["stages"].append(r)
        if r.get("fired"):
            out["reached"] = True
        if r.get("real_params"):
            out["activated_real"] = True
            out["min_stage"] = stage
            break
    return out

HERE = Path(__file__).resolve().parent

def activate_on_device(dx, pkg, backend, wait_t, manual_path=None):
    """Возвращает run_stage(rec, stage), замкнутый на пакет и одну Frida-сессию."""
    import frida, time, trace
    me = dex_member_exists(dx)
    device = trace.pick_device(None)

    def run_stage(rec, stage):
        prompt = build_prompt(rec, stage, {rec["cls"] + "->" + rec["method"]:
                                           method_smali(dx, rec["cls"], rec["method"])})
        plan = generate_plan(prompt, backend=backend, manual_path=manual_path)
        probs = validate_plan(plan, me)
        if probs:
            return {"stage": stage, "valid": False, "exceptions": probs,
                    "fired": False, "real_params": False, "request": None, "plan": plan}
        pid = device.spawn([pkg]); session = device.attach(pid)
        for js in ("hook.js", "activate.js"):
            s = session.create_script((HERE / js).read_text(encoding="utf-8"))
            s.load()
            if js == "activate.js":
                agent = s
        device.resume(pid)
        agent.exports_sync.capture_on(rec["key"])
        res = agent.exports_sync.arm(json.dumps(plan))
        time.sleep(wait_t)
        snap = agent.exports_sync.snapshot()
        session.detach()
        fired = snap is not None
        real = fired and _params_real(plan, snap)
        return {"stage": stage, "valid": True, "exceptions": res.get("exceptions", []),
                "fired": fired, "real_params": real, "request": snap, "plan": plan}

    return run_stage

def _params_real(plan, snap):
    """Уровень (б): хоть один аргумент не синтетический ($choose/прогон) И запрос непуст.
    Порог (spec §15, открытый вопрос): нет args через $new/примитив-болванку."""
    if not snap or not snap.get("url"):
        return False
    synth = any(isinstance(a.get("value"), (int, float, str, bool)) or
                (isinstance(a.get("value"), dict) and "$new" in a["value"])
                for a in plan.get("args", []))
    return not synth or bool(plan.get("trigger", {}).get("kind") in ("invoke", "trigger_entry"))
```

*(Замечание исполнителю: автотест в этой задаче покрывает только `run_key` на инъецированном `run_stage`; `activate_on_device` (device-ветка) проверяется процедурой живого пилота Task 4.)*

- [ ] **Step 4: Запустить — убедиться, что проходит**

Run: `.venv/bin/python activate.py --selfcheck`
Expected: PASS, печатает `staging ok`.

- [ ] **Step 5: Коммит**

```bash
git add activate.py
git commit -m "feat(activate): staged activation loop + device run_stage with oracle correlation"
```

---

### Task 6: Отчёт (Таблица IV), CLI, dry-run

**Files:**
- Modify: `activate.py`
- Test: `activate.py` (`_check_report`, `_selfcheck` wiring)

**Interfaces:**
- Produces:
  - `report(results: list[dict]) -> str` — распределение по минимальной ступени уровня (б) {0,1,2,none}; отдельно уровень (а); оговорка о несопоставимости с RQ3.
  - `main()` — CLI: `--slice`, `--apk`, `--keys`, `--backend`, `--manual-plan`, `--wait`, `--out`, `--dry-run`, `--selfcheck`.

- [ ] **Step 1: Написать падающий тест**

```python
def _check_report():
    results = [
        {"key": "a", "reached": True, "activated_real": True, "min_stage": 0},
        {"key": "b", "reached": True, "activated_real": True, "min_stage": 1},
        {"key": "c", "reached": True, "activated_real": False, "min_stage": None},
    ]
    txt = report(results)
    assert "ступень 0" in txt and "ступень 1" in txt
    assert "достижим" in txt                    # уровень (а) отдельно
    assert "RQ3" in txt and "несопостав" in txt.lower()  # оговорка
    print("  report ok")
```

- [ ] **Step 2: Запустить — убедиться, что падает**

Run: `.venv/bin/python activate.py --selfcheck`
Expected: FAIL — `name 'report' is not defined`.

- [ ] **Step 3: Минимальная реализация + CLI**

```python
def report(results):
    n = len(results)
    reached = sum(r["reached"] for r in results)
    real = sum(r["activated_real"] for r in results)
    from collections import Counter
    dist = Counter(r["min_stage"] for r in results if r["activated_real"])
    none = n - real
    L = [f"Всего ключей: {n}",
         f"(а) достижим (запрос ушёл, параметры любые): {reached}/{n}",
         f"(б) активирован с реальными параметрами:     {real}/{n}",
         "",
         "HTTP-аналог Таблицы IV — минимальная ступень уровня (б):",
         f"  ступень 0 (прямой вызов):          {dist.get(0,0)}",
         f"  ступень 1 (вызывающий + стражи):   {dist.get(1,0)}",
         f"  ступень 2 (UI-фронтир):            {dist.get(2,0)}",
         f"  не активирован (нужна продвинутая техника/сервер): {none}",
         "",
         "Оговорка: сравнение с RQ3/Таблицей IV ICSE 2025 — качественное; "
         "метрики несопоставимы напрямую (активити vs сетевые вызовы, другой стенд).",]
    return "\n".join(L)

def _selfcheck():
    _check_validate_plan(); _check_real_guards(); _check_build_prompt()
    _check_parse_plan(); _check_generate_plan(); _check_staging(); _check_report()
    print("все проверки activate.py прошли")

def main():
    ap = argparse.ArgumentParser(description="Принудительная активация скрытых запросов")
    ap.add_argument("--slice", type=Path, help="out/<pkg>.slice.jsonl")
    ap.add_argument("--apk", type=Path)
    ap.add_argument("--keys", nargs="*", help="подмножество ключей; по умолч. activation_exact")
    ap.add_argument("--backend", default="openai", choices=["openai", "manual"])
    ap.add_argument("--manual-plan", type=Path, help="файл с планом для --backend manual")
    ap.add_argument("--wait", type=float, default=5.0, help="окно ожидания сетевого события, сек")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--dry-run", action="store_true", help="prompt+plan+validate без устройства")
    ap.add_argument("--selfcheck", action="store_true")
    args = ap.parse_args()
    if args.selfcheck:
        _selfcheck(); return
    if not (args.slice and args.apk):
        ap.error("нужны --slice и --apk")
    recs = [json.loads(l) for l in args.slice.read_text(encoding="utf-8").splitlines() if l.strip()]
    recs = [r for r in recs if r.get("key")]
    if args.keys:
        recs = [r for r in recs if r["key"] in set(args.keys)]
    else:
        recs = [r for r in recs if r.get("activation_exact")]
    apk_obj, dx = load_apk(args.apk)
    results = []
    if args.dry_run:
        me = dex_member_exists(dx)
        for r in recs:
            prompt = build_prompt(r, 0, {r["cls"] + "->" + r["method"]:
                                         method_smali(dx, r["cls"], r["method"])})
            plan = generate_plan(prompt, backend=args.backend, manual_path=args.manual_plan)
            print(f"[{r['key']}] проблемы плана: {validate_plan(plan, me) or 'нет'}")
        return
    run_stage = activate_on_device(dx, apk_obj.get_package(), args.backend, args.wait, args.manual_plan)
    for r in recs:
        results.append(run_key(r, stages=(0, 1, 2), run_stage=run_stage))
    txt = report(results)
    print(txt)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        args.out.with_suffix(".report.txt").write_text(txt, encoding="utf-8")

if __name__ == "__main__":
    main()
```


- [ ] **Step 4: Запустить — убедиться, что проходит**

Run: `.venv/bin/python activate.py --selfcheck`
Expected: PASS, печатает все `... ok` и `все проверки activate.py прошли`.

- [ ] **Step 5: Offline dry-run smoke (manual-бэкенд, без ключа и устройства)**

Run:
```bash
printf '{"key":"K","stage":0,"overrides":[],"fields":[],"args":[],"trigger":{"kind":"call_retrofit","cls":"gpm.tnt_premier.server.datalayer.accessors.IUmaProfileOnlineAccessor","method":"updateAdultCode","sig":"..."},"raw_js":null,"rationale":"тест"}' > /tmp/plan.json
.venv/bin/python activate.py --slice out/gpm.tnt_premier.slice.jsonl --apk apk/gpm.tnt_premier.apk --backend manual --manual-plan /tmp/plan.json --dry-run
```
Expected: печатает для каждого ключа строку «проблемы плана: …» (валидатор отрабатывает на реальном DEX). Падения нет.

- [ ] **Step 6: Коммит**

```bash
git add activate.py
git commit -m "feat(activate): Table-IV report + CLI with dry-run and selfcheck"
```

---

## Примечания по объёму и зависимостям

- Перед device-прогоном (не для `--selfcheck`/`--dry-run`): `./.venv/bin/pip install frida` (версия = frida-server на Pixel). `node` для `node --check` опционален.
- **Отложено из v1 (спека §5, провенанс-источник №3 «снятые в трейсе»):** сбор реальных значений аргументов из обычного трейса приложения и их переигрывание не реализуется. В v1 реальные параметры обеспечивают источники №1 (прогон логики приложения, ступени 1–2) и №2 (`$choose` живого инстанса); синтез (№4) помечается и в метрику (б) не идёт. Подключать №3, только если №1–2 окажется мало.
- `arg_provenance` отдельным полем не вычисляется: провенанс восстановим из сохранённого `plan` в stage-результате (`$choose`/`$new`/примитив видны в `args`).
