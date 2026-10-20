'use strict';
/*
 * Агент Frida: фиксирует, какие сетевые вызовы приложение реально выполнило.
 *
 * Слой 1 (основной) — динамические прокси.
 *   Retrofit/Ktorfit строят реализацию API-интерфейса через java.lang.reflect.Proxy.
 *   Перехватываем Proxy.newProxyInstance, находим класс InvocationHandler'а и
 *   вешаемся на его invoke(proxy, Method, args). Method даёт
 *   getDeclaringClass().getName() + getName() — это ровно тот ключ
 *   `класс->метод`, который печатает BFScan. Сопоставление получается точным,
 *   без эвристик по URL.
 *
 *   Прокси не фильтруются по retrofit-аннотациям: приложение создаёт и другие
 *   динамические прокси, но их ключи просто не встретятся в статике. Отбор
 *   делает diff.py пересечением с ключами BFScan — лишние события безвредны.
 *
 * Слой 2 (вспомогательный) — OkHttp и HttpURLConnection.
 *   Даёт полный список URL, включая вызовы мимо Retrofit (сырой OkHttp, Ktor,
 *   WebView, аналитика). BFScan такие вызовы не извлекает, поэтому слой 2 —
 *   это оценка неполноты статического анализа, а не источник ключей.
 *
 * Рассчитано на приложения без обфускации: okhttp3 и retrofit2 доступны под
 * своими именами, имя метода в DEX совпадает с тем, что печатает BFScan.
 */

var MAX_EVENTS = 20000;          // предохранитель от переполнения канала
var sent = 0;
var dropped = 0;                 // сколько событий съел предел
var seenProxy = {};              // ключ класс->метод -> true
var seenHttp = {};               // verb + path -> true
var hookedHandlers = {};         // имя класса InvocationHandler -> true
var installed = [];              // что удалось повесить, для отчёта
var loggedInvokeError = false;

function emit(obj) {
    if (sent >= MAX_EVENTS) {
        // Отбрасывать молча нельзя: потерянное событие выглядит в отчёте как
        // скрытый запрос, то есть предел тихо завышает результат. Сообщаем один
        // раз (иначе зальём канал), счётчик уезжает в stats().
        dropped++;
        if (dropped === 1) {
            note('ПРЕДЕЛ MAX_EVENTS=' + MAX_EVENTS + ' достигнут, дальнейшие ' +
                 'события отбрасываются — отчёт будет занижен');
        }
        return;
    }
    sent++;
    obj.ts = Date.now();
    send(obj);
}

// Параметры карты — ОТДЕЛЬНЫЙ канал: свой предел и дедуп в агенте, чтобы поток
// листьев (тела+ответы) НЕ вытеснял http/retrofit (их ест только emit/sent →
// diff не занижается). Дедуп по (name,val) схлопывает повторы/поллинг в агенте.
var seenParam = {};
var paramSent = 0;
var PARAM_MAX = 50000;
function emitParam(name, val, url) {
    if (!name) return;
    // CDN/медиа-ссылки (постеры/логотипы) — не параметры слота: слот берёт
    // id/slug/токен, не абсолютный URL. Отсекаем — иначе уникальные URL каждого
    // постера забивают карту (path/slug-значения не начинаются с http, сохранятся).
    if (typeof val === 'string' && /^https?:\/\//i.test(val)) return;
    var k = name + '\u0000' + val;
    if (seenParam[k]) return;
    seenParam[k] = true;
    if (paramSent >= PARAM_MAX) return;      // свой предел — не трогает MAX_EVENTS
    paramSent++;
    send({ t: 'param', name: name, val: val, url: url, ts: Date.now() });
}

function note(msg) { send({ t: 'log', msg: String(msg) }); }

/* ---------- слой 1: динамические прокси (Retrofit/Ktorfit) ---------- */

function hookHandlerClass(name) {
    if (hookedHandlers[name]) return;
    hookedHandlers[name] = true;
    var Handler;
    try {
        Handler = Java.use(name);
    } catch (e) {
        note('не удалось открыть handler ' + name + ': ' + e);
        return;
    }
    var overloads;
    try {
        overloads = Handler.invoke.overloads;
    } catch (e) {
        return;                                  // invoke унаследован/отсутствует
    }
    overloads.forEach(function (ov) {
        ov.implementation = function (proxy, method, args) {
            try {
                if (method !== null) {
                    var cls = method.getDeclaringClass().getName();
                    var m = method.getName();
                    var key = cls + '->' + m;
                    if (!seenProxy[key]) {
                        seenProxy[key] = true;
                        emit({ t: 'retrofit', cls: cls, m: m, handler: name });
                    }
                }
            } catch (e) {
                if (!loggedInvokeError) { loggedInvokeError = true; note('invoke: ' + e); }
            }
            return ov.call(this, proxy, method, args);
        };
    });
    note('hooked InvocationHandler: ' + name);
}

function hookProxyFactory() {
    var Proxy = Java.use('java.lang.reflect.Proxy');
    Proxy.newProxyInstance.implementation = function (loader, interfaces, handler) {
        var result = this.newProxyInstance(loader, interfaces, handler);
        try {
            if (handler !== null) {
                // Именно $className, а не getClass().getName(): аргумент
                // приезжает как обёртка Frida, у которой Java-метода getClass()
                // нет — вызов молча падает в TypeError и съедает все прокси.
                var hc = handler.$className;
                // Аннотации Java тоже реализованы через Proxy; их обработчик
                // дёргается на каждое чтение атрибута и к сети отношения не имеет.
                if (hc && hc !== 'libcore.reflect.AnnotationFactory') {
                    hookHandlerClass(hc);
                }
            }
        } catch (e) { note('newProxyInstance: ' + e); }
        return result;
    };
    installed.push('java.lang.reflect.Proxy.newProxyInstance');
}


/* ---------- слой 2: OkHttp / HttpURLConnection ---------- */

var Log = null, Exc = null;

function stackTrace() {
    try {
        if (Log === null) { Log = Java.use('android.util.Log'); Exc = Java.use('java.lang.Exception'); }
        return Log.getStackTraceString(Exc.$new());
    } catch (e) { return ''; }
}

function recordHttp(verb, url) {
    if (!url) return;
    var path = String(url).split('?')[0];
    var key = verb + ' ' + path;
    if (seenHttp[key]) return;
    seenHttp[key] = true;
    var st = stackTrace();
    // Вызов считаем retrofit'овым, если в стеке есть кадр прокси или самой
    // библиотеки. При полной минификации retrofit2 признак пропадает — тогда
    // вызов попадёт в список «вне Retrofit», что в отчёте помечено как оценка.
    var viaRetrofit = st.indexOf('retrofit') !== -1 || st.indexOf('$Proxy') !== -1;
    emit({
        t: 'http', verb: verb, url: String(url),
        via_retrofit: viaRetrofit,
        stack: st.split('\n').slice(0, 12).join('\n')
    });
}

// КАРТА ПАРАМЕТРОВ (б2b): эмитим примитивные листья тел/URL/ответов как
// {t:'param', name, val, url}. Хост (trace.py) дедуплицирует в param-файл,
// которым activate.py сеет pool. Канонический сборщик/матчинг — в activate.js;
// здесь только компактный эмиттер (resource/shape считает activate.js.seedPool).
// ponytail: сырые тела НЕ шлём (мусорных запросов много) — только листья ≤256 симв.
function emitLeaves(obj, url) {
    if (obj === null || typeof obj !== 'object') return;
    for (var k in obj) {
        var v = obj[k];
        if (v !== null && typeof v === 'object') { emitLeaves(v, url); continue; }
        var ok = (typeof v === 'string' && v !== '' && v !== 'stub' && v.length <= 256) ||
                 (typeof v === 'number' && v !== 0) || typeof v === 'boolean';
        if (ok) emitParam(k, v, url);
    }
}
function reqBodyText(req) {
    try {
        var rb = req.body(); if (rb === null) return null;
        var B = Java.use('okio.Buffer'), buf = B.$new(); rb.writeTo(buf); return buf.readUtf8();
    } catch (e) { return null; }
}
function harvestReq(request, url) {
    try {
        var b = reqBodyText(request);
        if (b && b.charAt(0) === '{') { try { emitLeaves(JSON.parse(b), url); } catch (e) {} }
        var qs = String(url).split('?')[1];
        if (qs) qs.split('&').forEach(function (p) {
            var i = p.indexOf('='); if (i <= 0) return;
            try { emitParam(decodeURIComponent(p.slice(0, i)), decodeURIComponent(p.slice(i + 1)), url); }
            catch (e) {}
        });
        // id в пути (/streams/<num|hex>) — под частым именем слота 'id'
        String(url).split('?')[0].split('/').forEach(function (seg) {
            if (/^\d+$/.test(seg) || /^[0-9a-f]{16,}$/i.test(seg)) emitParam('id', seg, url);
        });
    } catch (e) {}
}

function hookOkHttp() {
    try {
        var Client = Java.use('okhttp3.OkHttpClient');
        Client.newCall.implementation = function (request) {
            try {
                var u = request.url().toString();
                recordHttp(request.method(), u);
                harvestReq(request, u);
            } catch (e) {}
            return this.newCall(request);
        };
        installed.push('okhttp3.OkHttpClient.newCall');
        // Ответы: id/slug реальных сущностей приходят В ОТВЕТЕ (напр. список
        // устройств для disallow-device). peekBody НЕ потребляет оригинал.
        try {
            var RespB = Java.use('okhttp3.Response$Builder');
            RespB.build.implementation = function () {
                var resp = this.build();
                try {
                    var ct = resp.header('Content-Type', '') || '';
                    if (ct.indexOf('json') !== -1) {
                        var txt = resp.peekBody(131072).string();
                        if (txt && (txt.charAt(0) === '{' || txt.charAt(0) === '['))
                            emitLeaves(JSON.parse(txt), resp.request().url().toString());
                    }
                } catch (e) {}
                return resp;
            };
            installed.push('okhttp3.Response$Builder.build');
        } catch (e) {}
        return true;
    } catch (e) {
        return false;      // класс ещё не загружен либо переименован R8
    }
}

// okhttp3 подгружается лениво, уже после старта процесса: на момент Java.perform
// его классов в VM нет и Java.use падает. Поэтому не один раз, а с повторами.
function hookOkHttpWithRetry(attemptsLeft) {
    if (hookOkHttp()) {
        note('okhttp3.OkHttpClient.newCall перехвачен');
        return;
    }
    if (attemptsLeft <= 0) {
        note('okhttp3.OkHttpClient так и не найден — либо переименован R8, ' +
             'либо приложение его не использует');
        return;
    }
    setTimeout(function () { hookOkHttpWithRetry(attemptsLeft - 1); }, 1000);
}

function hookUrlConnection() {
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function () {
            try {
                var u = this.toString();
                if (u.indexOf('http') === 0) recordHttp('GET?', u);
            } catch (e) {}
            return this.openConnection();
        };
        installed.push('java.net.URL.openConnection');
    } catch (e) {
        note('java.net.URL.openConnection не перехвачен: ' + e);
    }
}

/* ---------- старт ---------- */

Java.perform(function () {
    hookProxyFactory();
    hookUrlConnection();
    hookOkHttpWithRetry(60);     // ~60 с на ленивую инициализацию сетевого стека
    send({ t: 'ready', installed: installed });
});

rpc.exports = {
    // trace.py дёргает при завершении, чтобы забрать итоговую сводку
    stats: function () {
        return {
            proxy_keys: Object.keys(seenProxy).length,
            http_urls: Object.keys(seenHttp).length,
            handlers: Object.keys(hookedHandlers),
            installed: installed,
            events: sent,
            dropped: dropped
        };
    }
};
