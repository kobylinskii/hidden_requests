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

function sigArgClassNames(sig) {
    var m = /^\(([^)]*)\)/.exec(sig);
    if (!m) return null;
    var s = m[1], out = [], i = 0;
    var prim = {Z:'boolean',B:'byte',S:'short',C:'char',I:'int',J:'long',F:'float',D:'double'};
    while (i < s.length) {
        var arr = '';
        while (s[i] === '[') { arr += '[]'; i++; }
        var c = s[i];
        if (c === 'L') {
            var e = s.indexOf(';', i);
            out.push(s.substring(i + 1, e).replace(/\//g, '.') + arr);
            i = e + 1;
        } else { out.push((prim[c] || c) + arr); i++; }
    }
    return out;
}

function overloadBySig(clazz, method, sig) {
    var ov = clazz[method].overloads;
    var want = sigArgClassNames(sig);
    for (var i = 0; i < ov.length; i++) {
        var a = ov[i].argumentTypes.map(function (t) { return t.className; });
        if (want !== null && a.length === want.length && a.join(',') === want.join(',')) return ov[i];
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

// Кэш прокси-инстансов + снимок исходящего запроса целевого ключа.
Java.perform(function () {
    var Proxy = Java.use('java.lang.reflect.Proxy');
    Proxy.newProxyInstance.implementation = function (l, ifaces, h) {
        var r = this.newProxyInstance(l, ifaces, h);
        try { for (var i = 0; i < ifaces.length; i++) proxyByIface[ifaces[i].getName()] = r; } catch (e) {}
        return r;
    };
    installOkHttpCapture(60);
});

function installOkHttpCapture(attemptsLeft) {
    try {
        var Ok = Java.use('okhttp3.OkHttpClient');
        Ok.newCall.implementation = function (req) {
            try {
                if (cap.key && cap.hit === null) {
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
                    cap.hit = { key: cap.key, method: req.method(), url: req.url().toString(), body: body };
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
