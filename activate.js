'use strict';
/* Фиксированный рантайм принудительной активации. План — декларативный JSON
 * (см. spec §6); весь хрупкий Frida-код (перегрузки, корутины, прокси) — здесь,
 * один раз. hook.js грузится рядом и подтверждает факт вызова. */

var proxyByIface = {};   // имя интерфейса -> живой прокси-инстанс (для call_retrofit)
var cap = { key: null, path: '', hits: [] };   // path — ожидаемый endpoint ключа
// Пул реальных значений (б2b), собранный ПАССИВНО из СОБСТВЕННОГО трафика
// приложения (залогинено → на старте рефрешит токен, грузит профиль/устройства
// с реальными значениями). Ключ — имя JSON-поля, значение — последнее непустое.
// App-agnostic: только имена полей, без знания классов приложения.
var harvest = {};

function jclass(name) { return Java.use(name.replace(/\//g, '.')); }

// #2: значение obj — инстанс типа fq (frida-имя класса/интерфейса)? Для выбора
// СЕМАНТИЧЕСКИ верного живого инстанса ($field/$choose), а не первого по типу поля.
function isType(obj, fq) {
    try { return jclass(fq).class.isInstance(obj); } catch (e) { return false; }
}

// Рекурсивно собрать непустые примитивные листья JSON в harvest по имени поля.
function recordHarvest(obj) {
    if (obj === null || typeof obj !== 'object') return;
    for (var k in obj) {
        var v = obj[k];
        if (v !== null && typeof v === 'object') { recordHarvest(v); }
        else if ((typeof v === 'string' && v !== '') ||
                 (typeof v === 'number' && v !== 0) || typeof v === 'boolean') {
            harvest[k] = v;   // последнее непустое — обычно самое свежее (напр. свежий токен)
        }
    }
}

// Наполнить пустые поля JSON-тела реальными значениями из harvest по имени поля.
// Возвращает {changed:bool, filled:[имена], obj} — app-agnostic подстановка.
function fillFromHarvest(obj, filled) {
    var changed = false;
    if (obj === null || typeof obj !== 'object') return changed;
    for (var k in obj) {
        var v = obj[k];
        if (v !== null && typeof v === 'object') {
            if (fillFromHarvest(v, filled)) changed = true;
        } else if (v === '' && typeof harvest[k] === 'string' && harvest[k] !== '') {
            obj[k] = harvest[k]; filled.push(k); changed = true;
        }
    }
    return changed;
}

// JSON-значение -> Java-значение. $choose берёт ЖИВОЙ инстанс (реальные параметры).
function coerce(v) {
    if (v === null || typeof v !== 'object') return v;
    if ('$null' in v) return null;
    if ('$enum' in v) {
        var p = v['$enum'].split('.'); var f = p.pop();
        return jclass(p.join('.'))[f].value;
    }
    if ('$choose' in v) {
        var found = null, C = v['$choose'], want0 = v.expect;
        Java.choose(C, { onMatch: function (i) {
            if (want0 && !isType(i, want0)) return;   // #2: не тот инстанс по типу
            found = i; return 'stop'; }, onComplete: function () {} });
        if (found === null) throw new Error('$choose: живых инстансов ' + C + ' нет');
        return found;
    }
    // $field/$invoke — значение из ЖИВОГО продюсера (статическая карта из slice):
    // читаем поле / зовём метод на живом инстансе owner. Один Java.use + Java.choose,
    // без скана кучи. null, если живого инстанса нет (холодный старт — ожидаемо).
    if ('$field' in v) {
        var fn = v.name, want = v.expect, got = null;
        if (v.static) { try { return jclass(v['$field'])[fn].value; } catch (e) {} }
        // #2: среди ВСЕХ живых инстансов owner берём тот, чьё поле непусто и
        // (если задан expect) нужного типа — иначе Java.choose брал первый
        // попавшийся (в removeProfile.id попадал каталожный объект вместо id).
        else Java.choose(v['$field'], { onMatch: function (i) {
            var val; try { val = i[fn].value; } catch (e) { return; }
            if (val === null || val === undefined) return;
            if (want && !isType(val, want)) return;
            got = val; return 'stop'; },
            onComplete: function () {} });
        if (got !== null && got !== undefined) return got;
        return ('else' in v) ? coerce(v['else']) : null;   // продюсер пуст/не тот тип → болванка (а)
    }
    if ('$invoke' in v) {
        var iargs = (v.args || []).map(coerce), r = null, ok = false;
        Java.choose(v['$invoke'], { onMatch: function (i) {
            try { r = overloadBySig(i, v.method, v.sig).apply(i, iargs); ok = true; } catch (e) {}
            return 'stop'; }, onComplete: function () {} });
        if (ok && r !== null) return r;
        return ('else' in v) ? coerce(v['else']) : null;
    }
    // $stub — заглушка user-input листа (тир synthesized): НЕПУСТОЕ значение
    // нужного типа, чтобы поле попало в тело (но это синтетика, не app-данные).
    if ('$stub' in v) {
        var t = v['$stub'];
        if (t in _JVM_PRIM) t = _JVM_PRIM[t];   // JVM-дескриптор Z/I/J… -> frida-имя
        if (t === 'java.lang.String' || t === 'java.lang.CharSequence') return 'stub';
        if (t in _PRIM_DEFAULT) return (t === 'boolean') ? true : 1;   // непустое значение типа
        try {
            if (t in _BOXED) return jclass(t).valueOf(t === 'java.lang.Boolean' ? true : 1);
        } catch (e) {}
        return synthDefault(t);   // enum/коллекция/объект — как дефолт (непустой, если можем)
    }
    if ('$default' in v) return synthDefault(v['$default']);
    if ('$new' in v) {
        var C = jclass(v['$new']);
        // интерфейсный тип (DI-зависимость) — $new() кинул бы "cannot instantiate
        // an interface"; отдаём нативную Proxy-заглушку (app-agnostic).
        if (C.class.isInterface()) return ifaceStub(v['$new']);
        var args = (v.args || []).map(coerce);
        var ctor = v.sig ? pickOverload(C.$new, v.sig) : C.$new;
        // receiver конструктора — сам класс C (не null): иначе frida-java-bridge
        // теряет class-handle ($borrowClassHandle of null).
        return ctor.apply(C, args);
    }
    return v;
}

// Значение по умолчанию для типа, которого мы не строим рецептом (вложенный
// объект за пределами глубины, enum, класс без конструктора): примитив->дефолт,
// String->"", enum->первая константа (values()[0]), прочий объект->null (тело
// запроса всё равно формируется — нас интересует факт вызова, spec §14.4).
var _PRIM_DEFAULT = { boolean: false, byte: 0, short: 0, char: 0, int: 0,
                      long: 0, float: 0.0, double: 0.0 };
// JVM-дескриптор примитива -> frida-имя (slice кладёт в тип параметра дескриптор
// Z/I/J…, а _PRIM_DEFAULT/_BOXED оперируют полными именами).
var _JVM_PRIM = { Z: 'boolean', B: 'byte', S: 'short', C: 'char', I: 'int',
                  J: 'long', F: 'float', D: 'double' };
var _BOXED = { 'java.lang.Integer': 'int', 'java.lang.Long': 'long',
               'java.lang.Short': 'short', 'java.lang.Byte': 'byte',
               'java.lang.Character': 'char', 'java.lang.Boolean': 'boolean',
               'java.lang.Float': 'float', 'java.lang.Double': 'double' };
var _EMPTY = { 'java.util.List': 'emptyList', 'java.util.Collection': 'emptyList',
               'java.lang.Iterable': 'emptyList', 'java.util.Map': 'emptyMap',
               'java.util.Set': 'emptySet' };
function synthDefault(name) {
    if (name in _PRIM_DEFAULT) return _PRIM_DEFAULT[name];
    if (name === 'java.lang.String' || name === 'java.lang.CharSequence') return '';
    try {
        if (name in _BOXED) return jclass(name).valueOf(_PRIM_DEFAULT[_BOXED[name]]);
        if (name in _EMPTY) return jclass('java.util.Collections')[_EMPTY[name]]();
        var C = jclass(name);
        if (C.class.isInterface()) {            // интерфейс -> нативная Proxy-заглушка
            var s = ifaceStub(name);
            if (s !== null) return s;
        }
        if (typeof C.values === 'function') {   // enum -> первая константа
            var vs = C.values();
            if (vs && vs.length) return vs[0];
        }
        // Kotlin-параметры часто non-null (checkNotNullParameter кидает NPE на
        // null): даём no-arg инстанс (Object, ArrayList, HashMap, …), если есть
        // такой конструктор; иначе падаем в null ниже.
        try { return C.$new(); } catch (e) {}
    } catch (e) {}
    return null;
}

// Выбор перегрузки (метода или конструктора C.$new) по JVM-сигнатуре параметров.
function pickOverload(m, sig) {
    var want = sigArgClassNames(sig);
    var ov = m.overloads;
    for (var i = 0; i < ov.length; i++) {
        var a = ov[i].argumentTypes.map(function (t) { return t.className; });
        if (want !== null && a.length === want.length && a.join(',') === want.join(',')) return ov[i];
    }
    return m;
}

// Массивы отдаём в JNI/Class.getName()-форме ([I, [Ljava.lang.String;, [[I —
// именно так Frida кладёт их в argumentTypes[i].className); точный формат
// на разных Android/ART-версиях — pilot-verified на устройстве (spec §14.4).
function sigArgClassNames(sig) {
    var m = /^\(([^)]*)\)/.exec(sig);
    if (!m) return null;
    var s = m[1], out = [], i = 0;
    var prim = {Z:'boolean',B:'byte',S:'short',C:'char',I:'int',J:'long',F:'float',D:'double'};
    while (i < s.length) {
        var dims = 0;
        while (s[i] === '[') { dims++; i++; }
        var base;
        if (s[i] === 'L') {
            var e = s.indexOf(';', i);
            var cls = s.substring(i + 1, e).replace(/\//g, '.');
            i = e + 1;
            // array keeps the JNI L...; wrapper; a bare object type is unwrapped (Frida className)
            base = dims > 0 ? ('L' + cls + ';') : cls;
        } else {
            var c = s[i]; i++;
            // array keeps the primitive letter (I/Z/...); a bare primitive is its name
            base = dims > 0 ? c : (prim[c] || c);
        }
        var prefix = '';
        for (var d = 0; d < dims; d++) prefix += '[';
        out.push(prefix + base);
    }
    return out;
}

function overloadBySig(clazz, method, sig) {
    return pickOverload(clazz[method], sig);  // единственная перегрузка -> сам method
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

// Trivial Continuation для вызова Kotlin suspend-функций из Frida: большинство
// Retrofit-методов современного Kotlin-приложения — suspend (последний параметр
// kotlin.coroutines.Continuation). Нас интересует факт формирования/отправки
// запроса, не результат — resumeWith no-op (spec §14.4).
var _cont = null;
function makeContinuation() {
    if (_cont !== null) return _cont;
    var ctx = Java.use('kotlin.coroutines.EmptyCoroutineContext').INSTANCE.value;
    var Cont = Java.registerClass({
        name: 'frida.ActivationContinuation',
        implements: [Java.use('kotlin.coroutines.Continuation')],
        methods: {
            getContext: function () { return ctx; },
            resumeWith: function (result) { }
        }
    });
    _cont = Cont.$new();
    return _cont;
}

// Универсальная заглушка ПРОИЗВОЛЬНОГО интерфейса. DI-зависимости в конструкторах
// Requester-классов приходят интерфейсными типами; frida C.$new() на интерфейсе
// кидает "cannot instantiate an interface" и роняет весь форс-вызов (главный
// блокер на ivi: 99 падений). Строим JDK-нативным Proxy.newProxyInstance — он
// обслуживает ЛЮБОЙ интерфейс без перечисления методов (app-agnostic). Один общий
// InvocationHandler: примитивы->дефолт, объекты->null (зависимость обычно лишь
// сохраняется в поле; если её метод всё же дёрнут при сборке запроса — вернём
// дефолт, а вызывающий код уже в try/catch).
var _stubHandler = null, _ifaceStub = {};
function stubHandler() {
    if (_stubHandler !== null) return _stubHandler;
    var Boolean = Java.use('java.lang.Boolean'), Integer = Java.use('java.lang.Integer'),
        Long = Java.use('java.lang.Long'), Float = Java.use('java.lang.Float'),
        Double = Java.use('java.lang.Double');
    var H = Java.registerClass({
        name: 'frida.ActivationStub',
        implements: [Java.use('java.lang.reflect.InvocationHandler')],
        methods: { invoke: function (proxy, method, args) {
            var rt; try { rt = method.getReturnType().getName(); } catch (e) { return null; }
            switch (rt) {
                case 'boolean': return Boolean.valueOf(false);
                case 'int': return Integer.valueOf(0);
                case 'long': return Long.valueOf(0);
                case 'float': return Float.valueOf(0);
                case 'double': return Double.valueOf(0);
                default: return null;   // void/объект/прочие примитивы (редкие)
            }
        } }
    });
    _stubHandler = H.$new();
    return _stubHandler;
}
function ifaceStub(name) {
    if (name in _ifaceStub) return _ifaceStub[name];
    var out = null;
    try {
        var C = jclass(name);
        if (C.class.isInterface()) {
            var Proxy = Java.use('java.lang.reflect.Proxy');
            var ld = C.class.getClassLoader();
            if (ld === null) ld = Java.use('java.lang.ClassLoader').getSystemClassLoader();
            out = Java.retain(Proxy.newProxyInstance(
                ld, Java.array('java.lang.Class', [C.class]), stubHandler()));
        }
    } catch (e) {}
    _ifaceStub[name] = out;
    return out;
}

function argTypesOf(ov) {
    if (ov.argumentTypes) return ov.argumentTypes;
    if (ov.overloads && ov.overloads.length === 1) return ov.overloads[0].argumentTypes;
    return null;
}

// Вызвать перегрузку на receiver; если метод suspend (на один аргумент больше и
// последний — Continuation), а план его не передал, дослать наш Continuation.
function invokeOverload(ov, receiver, args) {
    var types = argTypesOf(ov);
    if (types && types.length === args.length + 1 &&
        types[types.length - 1].className === 'kotlin.coroutines.Continuation') {
        args = args.concat([makeContinuation()]);
    }
    return ov.call.apply(ov, [receiver].concat(args));
}

// Лениво-инициализируемый Retrofit-сервис: на холодном старте его прокси ещё
// нет (приложение создаёт сервис при открытии экрана фичи). Но сам Retrofit —
// долгоживущий синглтон, он ЕСТЬ в куче ($choose работает, в отличие от
// транзиентных DTO). Создаём прокси тем же публичным API, что и приложение —
// retrofit.create(InterfaceClass). create() внутри зовёт Proxy.newProxyInstance,
// наш хук регистрирует прокси в proxyByIface и вешает оракул на его handler.
function mintProxies(clsName) {
    // Прокси интерфейса от КАЖДОГО живого Retrofit-инстанса (у приложения их
    // несколько — разные baseUrl/конвертеры). create() не валидирует конвертер
    // (ошибка «Unable to create converter» всплывает позже при вызове метода),
    // поэтому возвращаем ВСЕ кандидаты, а doTrigger переберёт их: конвертер-
    // ошибка кидается ДО отправки запроса, так что неподходящие безопасно
    // пропускаются, а шлёт запрос только тот Retrofit, что реально обслужил.
    var iface;
    try { iface = jclass(clsName).class; } catch (e) { return []; }
    var rets = [];
    Java.choose('retrofit2.Retrofit', {
        onMatch: function (r) { try { rets.push(Java.retain(r)); } catch (e) {} },
        onComplete: function () {}
    });
    // Порядок кандидатов: основной API-хост приложения обслуживает НЕСКОЛЬКО
    // feature-Retrofit'ов, одиночный сторонний SDK (pyrus/аналитика) — один. Сперва
    // пробуем хосты с наибольшей частотой, чтобы форс уходил на реальный API, а не
    // в SDK (app-agnostic: без хардкода имён хостов). При равенстве — исходный порядок.
    var freq = {}, hostOf = rets.map(function (r) {
        var h = ''; try { h = r.baseUrl().host().toString(); } catch (e) {}
        freq[h] = (freq[h] || 0) + 1; return h;
    });
    var order = rets.map(function (_, i) { return i; })
                    .sort(function (a, b) { return (freq[hostOf[b]] || 0) - (freq[hostOf[a]] || 0); });
    var proxies = [];
    for (var k = 0; k < order.length; k++) {
        try {
            var p = rets[order[k]].create(iface);   // create() возвращает прокси; хук вешает оракул
            if (p) proxies.push(Java.retain(p));
        } catch (e) {}
    }
    return proxies;
}

function _isConverterError(e) {
    var s = String(e);
    return s.indexOf('Unable to create') !== -1 || s.indexOf('converter') !== -1 ||
           s.indexOf('ServiceMethod') !== -1 || s.indexOf('annotation') !== -1;
}

// Живой инстанс класса из кучи (уровень б1): вызывающие/ViewModel/UseCase —
// DI-синглтоны, они ЕСТЬ в куче (в отличие от транзиентных DTO). Живой receiver
// несёт реальное состояние приложения, поэтому его код собирает запрос с
// реальными значениями, а не с нашими болванками. null — живого нет.
function liveReceiver(clsName) {
    var found = null;
    try {
        Java.choose(clsName, {
            onMatch: function (i) { try { found = Java.retain(i); } catch (e) {} return 'stop'; },
            onComplete: function () {}
        });
    } catch (e) {}
    return found;
}

// ── Форс-отправка результата вызова ──────────────────────────────────────────
// Non-suspend Retrofit-методы возвращают Call/Observable/Single БЕЗ авто-отправки:
// пока нет execute()/subscribe(), okhttp-запрос не строится (ivi: reached>0, но
// matched=0). Форсим отправку по типу возврата (детект по имени реактивного класса
// — app-agnostic). Запрос уходит асинхронно (своим диспатчером / фоновым потоком),
// RPC-поток не блокируем; снимок берём после wait_t.
var _noopCb = null;
function noopCallback() {
    if (_noopCb !== null) return _noopCb;
    var C = Java.registerClass({
        name: 'frida.ActivationCallback',
        implements: [Java.use('retrofit2.Callback')],
        methods: { onResponse: function () {}, onFailure: function () {} }
    });
    _noopCb = C.$new();
    return _noopCb;
}
function safeUse(n) { try { return Java.use(n); } catch (e) { return null; } }
function isA(obj, n) { var C = safeUse(n); try { return C !== null && C.class.isInstance(obj); } catch (e) { return false; } }
function runAsync(fn) {
    try {
        var R = Java.registerClass({
            implements: [Java.use('java.lang.Runnable')],
            methods: { run: function () { try { fn(); } catch (e) {} } }
        });
        Java.use('java.lang.Thread').$new(R.$new()).start();
    } catch (e) { try { fn(); } catch (e2) {} }   // не вышло поднять поток — синхронно
}
var _RX = ['io.reactivex.Single', 'io.reactivex.Observable', 'io.reactivex.Completable',
           'io.reactivex.Maybe', 'io.reactivex.Flowable',
           'io.reactivex.rxjava3.core.Single', 'io.reactivex.rxjava3.core.Observable',
           'io.reactivex.rxjava3.core.Completable', 'io.reactivex.rxjava3.core.Maybe',
           'io.reactivex.rxjava3.core.Flowable', 'rx.Observable', 'rx.Single'];
function dispatchResult(r, ex) {
    if (r === null || r === undefined) return;
    var cn; try { cn = r.$className; } catch (e) { return; }
    ex.push('ret: ' + cn);                        // диагностика типа возврата
    if (isA(r, 'retrofit2.Call')) {               // Call → enqueue (async, не блокирует)
        try { Java.cast(r, Java.use('retrofit2.Call')).enqueue(noopCallback()); }
        catch (e) { ex.push('enqueue: ' + e); }
        return;
    }
    for (var i = 0; i < _RX.length; i++) {        // RxJava → subscribe() на фоновом потоке
        if (isA(r, _RX[i])) {
            var rr = Java.retain(r), cls = _RX[i];
            runAsync(function () { Java.cast(rr, Java.use(cls)).subscribe(); });
            return;
        }
    }
}

function doTrigger(t, args) {
    var C = jclass(t.cls);
    if (t.kind === 'call_retrofit') {
        // кандидаты: ранее зарегистрированный прокси + прокси от ВСЕХ Retrofit.
        var cands = [], seen = {};
        var cached = proxyByIface[t.cls] || proxyByIface[t.cls.replace(/\./g, '/')];
        if (cached) cands.push(cached);
        mintProxies(t.cls).forEach(function (p) { cands.push(p); });
        if (!cands.length) throw new Error('прокси-инстанс ' + t.cls + ' не создан (нет живого Retrofit?)');
        var ov = overloadBySig(C, t.method, t.sig), lastErr = null;
        for (var i = 0; i < cands.length; i++) {
            try {
                return invokeOverload(ov, cands[i], args);
            } catch (e) {
                lastErr = e;
                // конвертер/ServiceMethod не сработал на ЭТОМ Retrofit (запрос ещё
                // не ушёл) → пробуем следующий; иную ошибку (напр. наши args) не маскируем.
                if (_isConverterError(e)) continue;
                throw e;
            }
        }
        throw lastErr || new Error('ни один Retrofit не обслужил ' + t.cls);
    }
    // invoke / trigger_entry: живой вызывающий из кучи → его код сам собирает
    // реальный DTO (уровень б1); фолбэк на $new() (пустое состояние), если
    // живого инстанса нет.
    // фолбэк без живого инстанса: интерфейс (вызывающий — абстракция, кода нет)
    // → нативная Proxy-заглушка вместо C.$new() ("cannot instantiate an interface");
    // конкретный класс → пустой инстанс.
    var recv = liveReceiver(t.cls);
    if (recv === null) recv = C.class.isInterface() ? ifaceStub(t.cls) : C.$new();
    if (recv === null) throw new Error('нет приёмника для ' + t.cls);
    return invokeOverload(overloadBySig(C, t.method, t.sig), recv, args);
}

rpc.exports = {
    captureOn: function (key, pathHint) { cap.key = key; cap.path = pathHint || ''; cap.hits = []; },
    // Case-1 префлайт: доступен ли сам Retrofit? stage-0 mintProxies минтит прокси
    // ТОЛЬКО через retrofit2.Retrofit.create() (имя класса захардкожено). Если R8
    // обфусцировал саму библиотеку Retrofit (dodo: retrofit2.Retrofit → retrofit2.z/
    // f0/..., класс под этим именем не грузится), create() недостижим → ни один
    // ключ не выстрелит. loadable=false — верный (и постоянный) признак; instances
    // advisory (0 может быть и временно — холодный старт, фича не открыта).
    retrofitProbe: function () {
        var r = { loadable: false, instances: 0 };
        Java.perform(function () {
            try { jclass('retrofit2.Retrofit'); r.loadable = true; } catch (e) {}
            try { Java.choose('retrofit2.Retrofit', { onMatch: function () { r.instances++; }, onComplete: function () {} }); } catch (e) {}
        });
        return JSON.stringify(r);
    },
    baseUrls: function () {   // диагностика: baseUrl всех живых Retrofit-инстансов
        var out = [];
        Java.perform(function () {
            try { Java.choose('retrofit2.Retrofit', {
                onMatch: function (r) { try { out.push(r.baseUrl().toString()); } catch (e) {} },
                onComplete: function () {} }); } catch (e) {}
        });
        return JSON.stringify(out);
    },
    snapshot: function () {
        if (!cap.hits.length) return null;
        for (var i = 0; i < cap.hits.length; i++) if (cap.hits[i].matched) return cap.hits[i];
        // ни один не совпал с ожидаемым endpoint — это ЧУЖОЙ (фоновый) трафик
        // приложения, а не наш форс-вызов. Не отдаём его: иначе отчёт припишет
        // чужое тело имени ключа (ivi: pyrus/gettickets под 22 разными ключами).
        return null;
    },
    arm: function (planJson) {
        var plan = JSON.parse(planJson), ex = [];
        Java.perform(function () {
            (plan.overrides || []).forEach(function (o) { try { applyOverride(o); } catch (e) { ex.push('override ' + o.cls + '->' + o.method + ': ' + e); } });
            (plan.fields || []).forEach(function (f) { try { applyField(f); } catch (e) { ex.push('field ' + f.cls + '.' + f.name + ': ' + e); } });
            var args = [];
            try {
                args = (plan.args || []).sort(function (a, b) { return a.index - b.index; })
                                        .map(function (a) { return coerce(a.value); });
            } catch (e) { ex.push('args: ' + e); args = []; }
            if (plan.raw_js) { try { (1, eval)(plan.raw_js); } catch (e) { ex.push('raw_js: ' + e); } }
            var tr = null;
            try { tr = doTrigger(plan.trigger, args); } catch (e) { ex.push('trigger: ' + e); }
            try { dispatchResult(tr, ex); } catch (e) { ex.push('dispatch: ' + e); }
        });
        return { exceptions: ex };
    }
};

// Key-exact оракул: хук InvocationHandler.invoke эмитит {t:'retrofit',cls,m} на
// КАЖДЫЙ вызов Retrofit-метода (в т.ч. наш форс-вызов) — перенесён из hook.js
// внутрь activate.js, чтобы сессия активации грузила ОДИН скрипт (двойной хук
// Proxy.newProxyInstance из hook.js+activate.js рекурсивно роняет приложение).
var hookedHandlers = {};
function hookHandlerInvoke(name) {
    if (hookedHandlers[name]) return;
    hookedHandlers[name] = true;
    var H; try { H = Java.use(name); } catch (e) { return; }
    var ovs; try { ovs = H.invoke.overloads; } catch (e) { return; }
    ovs.forEach(function (o) {
        o.implementation = function (proxy, method, args) {
            try {
                if (method !== null) {
                    send({ t: 'retrofit', cls: method.getDeclaringClass().getName(), m: method.getName() });
                }
            } catch (e) {}
            return o.call(this, proxy, method, args);
        };
    });
}

// Кэш прокси-инстансов + оракул + снимок исходящего запроса целевого ключа.
Java.perform(function () {
    var Proxy = Java.use('java.lang.reflect.Proxy');
    Proxy.newProxyInstance.implementation = function (l, ifaces, h) {
        var r = this.newProxyInstance(l, ifaces, h);
        // Java.retain: иначе прокси-обёртка, взятая внутри хука, протухает к моменту
        // arm ("Wrapper is disposed") — нужна долгоживущая ссылка.
        try { var rr = Java.retain(r); for (var i = 0; i < ifaces.length; i++) proxyByIface[ifaces[i].getName()] = rr; } catch (e) {}
        try {
            var hc = h !== null ? h.$className : null;
            if (hc && hc !== 'libcore.reflect.AnnotationFactory') hookHandlerInvoke(hc);
        } catch (e) {}
        return r;
    };
    installOkHttpCapture(60);
});

// Снять okhttp3.Request в cap.hits (url+метод+тело, флаг matched по cap.path).
// source — откуда снято ('build' — сборка Retrofit-запроса, 'dispatch' — okhttp.newCall),
// чтобы в отчёте было видно, дошёл ли вызов до сети.
function bodyOf(req) {
    try {
        var rb = req.body();
        if (rb === null) return null;
        var Buffer = Java.use('okio.Buffer');
        var buf = Buffer.$new();
        rb.writeTo(buf);
        return buf.readUtf8();
    } catch (e) { return '<unreadable>'; }
}

function captureRequest(req, source, body, filled) {
    try {
        if (body === undefined) body = bodyOf(req);
        // harvest из ЛЮБОГО запроса (в т.ч. собственного трафика приложения)
        if (body && body.charAt(0) === '{') { try { recordHarvest(JSON.parse(body)); } catch (e) {} }
        if (!cap.key || cap.hits.length >= 10) return;
        var url = req.url().toString();
        // matched только при СОДЕРЖАТЕЛЬНОМ hint: path '/' (или пустой) совпал бы
        // с любым проходящим трафиком приложения → поллюция, не наш форс-вызов.
        var m = (cap.path && cap.path !== '/') ? (url.indexOf(cap.path) !== -1) : false;
        var hit = { key: cap.key, method: req.method(), url: url, body: body, source: source,
                    filled: filled || [], matched: m };
        cap.hits.push(hit);
        // PUSH-захват: эмитим matched-запрос СРАЗУ (не ждём snapshot()). Форс-вызов
        // часто роняет приложение ПОСЛЕ отправки запроса, но ДО snapshot-RPC → без
        // push 24 ключа ivi снимались в cap.hits, но терялись (процесс умер). Теперь
        // Python получает его из on_message в момент снятия.
        if (m) { try { send({ t: 'captured', hit: hit }); } catch (e) {} }
    } catch (e) {}
}

// Если req — НАШ форс-вызов (url совпал с ожидаемым endpoint ключа) и у него
// пустые поля, которые есть в harvest — построить новый Request с наполненным
// телом (б2b). App-agnostic: патч на уровне JSON, пересборка okhttp RequestBody.
function patchForced(req) {
    if (!cap.key || !cap.path) return { req: req };
    var url;
    try { url = req.url().toString(); } catch (e) { return { req: req }; }
    if (url.indexOf(cap.path) === -1) return { req: req };
    var body = bodyOf(req);
    if (!body || body.charAt(0) !== '{') return { req: req, body: body };
    var obj; try { obj = JSON.parse(body); } catch (e) { return { req: req, body: body }; }
    var filled = [];
    if (!fillFromHarvest(obj, filled)) return { req: req, body: body };
    try {
        var json = JSON.stringify(obj);
        var ct = req.body().contentType();   // сохранить media type
        var RequestBody = Java.use('okhttp3.RequestBody');
        var bytes = Java.use('java.lang.String').$new(json).getBytes('UTF-8');
        var nb;
        // okhttp менял сигнатуру RequestBody.create между версиями — пробуем обе.
        try { nb = RequestBody.create(ct, bytes); }
        catch (e) { nb = RequestBody.create(bytes, ct); }
        _inPatch = true;   // re-entrancy guard: .build() ниже — тот же хук
        var nr = req.newBuilder().method(req.method(), nb).build();
        _inPatch = false;
        return { req: nr, body: json, filled: filled };
    } catch (e) { _inPatch = false; return { req: req, body: body }; }
}
var _inPatch = false;

function installOkHttpCapture(attemptsLeft) {
    var ok = false;
    // Диспетч: okhttp3.OkHttpClient.newCall — запрос реально ушёл в сеть.
    try {
        var Ok = Java.use('okhttp3.OkHttpClient');
        Ok.newCall.implementation = function (req) {
            var p = patchForced(req);
            captureRequest(p.req, 'dispatch', p.body, p.filled);
            return this.newCall(p.req);
        };
        ok = true;
    } catch (e) {}
    // Сборка: okhttp3.Request$Builder.build() — Retrofit строит Request ЗДЕСЬ,
    // синхронно во время вызова, даже если suspend-корутина не дойдёт до
    // диспетча (наш trivial Continuation её не прокачивает). Ловим тело форс-
    // запроса, который иначе не виден (пробел захвата фазы б1), и наполняем его
    // реальными значениями из harvest (б2b).
    try {
        var RB = Java.use('okhttp3.Request$Builder');
        RB.build.implementation = function () {
            var r = this.build();
            if (_inPatch) return r;   // наша же пересборка внутри patchForced
            var p = patchForced(r);
            captureRequest(p.req, 'build', p.body, p.filled);
            return p.req;
        };
        ok = true;
    } catch (e) {}
    if (ok) return;
    if (attemptsLeft <= 0) return;
    setTimeout(function () { installOkHttpCapture(attemptsLeft - 1); }, 1000);
}
