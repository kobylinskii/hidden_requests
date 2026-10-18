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
        var found = null, C = v['$choose'];
        Java.choose(C, { onMatch: function (i) { found = i; return 'stop'; },
                         onComplete: function () {} });
        if (found === null) throw new Error('$choose: живых инстансов ' + C + ' нет');
        return found;
    }
    // $field/$invoke — значение из ЖИВОГО продюсера (статическая карта из slice):
    // читаем поле / зовём метод на живом инстансе owner. Один Java.use + Java.choose,
    // без скана кучи. null, если живого инстанса нет (холодный старт — ожидаемо).
    if ('$field' in v) {
        var fn = v.name, got = null, has = false;
        if (v.static) { try { return jclass(v['$field'])[fn].value; } catch (e) {} }
        else Java.choose(v['$field'], { onMatch: function (i) {
            try { got = i[fn].value; has = true; } catch (e) {} return 'stop'; },
            onComplete: function () {} });
        if (has && got !== null) return got;
        return ('else' in v) ? coerce(v['else']) : null;   // продюсер пуст → болванка (а)
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
        var args = (v.args || []).map(coerce);
        var C = jclass(v['$new']);
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
function mintProxy(clsName) {
    var iface;
    try { iface = jclass(clsName).class; } catch (e) { return null; }
    var rets = [];
    Java.choose('retrofit2.Retrofit', {
        onMatch: function (r) { try { rets.push(Java.retain(r)); } catch (e) {} },
        onComplete: function () {}
    });
    for (var i = 0; i < rets.length; i++) {
        // Любой Retrofit собирает прокси для интерфейса (create не валидирует
        // baseUrl); при нескольких хостах endpoint снимка — advisory.
        try { rets[i].create(iface); } catch (e) { continue; }
        var got = proxyByIface[clsName] || proxyByIface[clsName.replace(/\./g, '/')];
        if (got) return got;
    }
    return null;
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

function doTrigger(t, args) {
    var C = jclass(t.cls);
    if (t.kind === 'call_retrofit') {
        var inst = proxyByIface[t.cls] || proxyByIface[t.cls.replace(/\./g, '/')] || mintProxy(t.cls);
        if (!inst) throw new Error('прокси-инстанс ' + t.cls + ' ещё не создан и не удалось создать через retrofit.create (нет живого Retrofit?)');
        return invokeOverload(overloadBySig(C, t.method, t.sig), inst, args);
    }
    // invoke / trigger_entry: живой вызывающий из кучи → его код сам собирает
    // реальный DTO (уровень б1); фолбэк на $new() (пустое состояние), если
    // живого инстанса нет.
    var recv = liveReceiver(t.cls) || C.$new();
    return invokeOverload(overloadBySig(C, t.method, t.sig), recv, args);
}

rpc.exports = {
    captureOn: function (key, pathHint) { cap.key = key; cap.path = pathHint || ''; cap.hits = []; },
    snapshot: function () {
        if (!cap.hits.length) return null;
        for (var i = 0; i < cap.hits.length; i++) if (cap.hits[i].matched) return cap.hits[i];
        return cap.hits[0];   // ни один не совпал с ожидаемым путём — отдаём первый (advisory)
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
            try { doTrigger(plan.trigger, args); } catch (e) { ex.push('trigger: ' + e); }
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
        cap.hits.push({ key: cap.key, method: req.method(), url: url, body: body, source: source,
                        filled: filled || [], matched: m });
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
