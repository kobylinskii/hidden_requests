'use strict';
/* Фиксированный рантайм принудительной активации. План — декларативный JSON
 * (см. spec §6); весь хрупкий Frida-код (перегрузки, корутины, прокси) — здесь,
 * один раз. hook.js грузится рядом и подтверждает факт вызова. */

var proxyByIface = {};   // имя интерфейса -> живой прокси-инстанс (для call_retrofit)
var cap = { key: null, path: '', hits: [] };   // path — ожидаемый endpoint ключа

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

function doTrigger(t, args) {
    var C = jclass(t.cls);
    if (t.kind === 'call_retrofit') {
        var inst = proxyByIface[t.cls] || proxyByIface[t.cls.replace(/\./g, '/')] || mintProxy(t.cls);
        if (!inst) throw new Error('прокси-инстанс ' + t.cls + ' ещё не создан и не удалось создать через retrofit.create (нет живого Retrofit?)');
        return invokeOverload(overloadBySig(C, t.method, t.sig), inst, args);
    }
    return invokeOverload(overloadBySig(C, t.method, t.sig), C.$new(), args);
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

function installOkHttpCapture(attemptsLeft) {
    try {
        var Ok = Java.use('okhttp3.OkHttpClient');
        Ok.newCall.implementation = function (req) {
            try {
                if (cap.key && cap.hits.length < 10) {
                    var url = req.url().toString();
                    var body = null;
                    try {
                        var rb = req.body();
                        if (rb !== null) {
                            var Buffer = Java.use('okio.Buffer');
                            var buf = Buffer.$new();
                            rb.writeTo(buf);
                            body = buf.readUtf8();
                        }
                    } catch (e) { body = '<unreadable>'; }
                    cap.hits.push({ key: cap.key, method: req.method(), url: url, body: body,
                                    matched: cap.path ? (url.indexOf(cap.path) !== -1) : false });
                }
            } catch (e) {}
            return this.newCall(req);
        };
        return;
    } catch (e) {
        if (attemptsLeft <= 0) return;
        setTimeout(function () { installOkHttpCapture(attemptsLeft - 1); }, 1000);
    }
}
