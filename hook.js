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

function note(msg) { send({ t: 'log', msg: String(msg) }); }

/* ---------- слой 1: динамические прокси (Retrofit/Ktorfit) ---------- */

function dexType(type) {
    var name = String(type.getName());
    var primitives = {void: 'V', boolean: 'Z', byte: 'B', char: 'C', short: 'S',
        int: 'I', long: 'J', float: 'F', double: 'D'};
    return primitives[name] || (name[0] === '[' ? name : 'L' + name + ';').replace(/\./g, '/');
}

var coveredInterfaces = {};
function recordMethod(method, handler) {
    var cls = String(method.getDeclaringClass().getName());
    var m = String(method.getName());
    var args = method.getParameterTypes();
    var descriptor = '(';
    for (var i = 0; i < args.length; i++) descriptor += dexType(args[i]);
    descriptor += ')' + dexType(method.getReturnType());
    var key = cls + '->' + m + descriptor;
    if (!seenProxy[key]) {
        seenProxy[key] = true;
        emit({ t: 'retrofit', observation: 'method_call', cls: cls, m: m,
            descriptor: descriptor, handler: handler });
    }
    if (handler.indexOf('retrofit2.Retrofit$') === 0 && !coveredInterfaces[cls]) {
        coveredInterfaces[cls] = true;
        emit({ t: 'coverage', interface: cls });
    }
}

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
                if (method !== null) recordMethod(method, name);
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

function recordHttp(verb, url, observation) {
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
    var rec = {
        t: 'http', observation: observation, verb: verb, url: String(url),
        via_retrofit: viaRetrofit,
        stack: st.split('\n').slice(0, 12).join('\n')
    };
    emit(rec);
}

function hookOkHttpResponse() {
    try {
        var Builder = Java.use('okhttp3.Response$Builder');
        var build = Builder.build.overload();
        build.implementation = function () {
            var response = build.call(this);
            try {
                var request = response.request();
                var url = String(request.url().toString());
                var verb = String(request.method());
                var status = response.code();
                var key = 'response ' + verb + ' ' + url.split('?')[0] + ' ' + status;
                if (!seenHttp[key]) {
                    seenHttp[key] = true;
                    emit({ t: 'response', observation: 'response_created',
                        verb: verb, url: url, status: status });
                }
            } catch (e) {}
            return response;
        };
        installed.push('okhttp3.Response$Builder.build');
    } catch (e) {
        note('Перехват создания HTTP-ответа недоступен: ' + e);
    }
}

function hookOkHttp() {
    try {
        var Client = Java.use('okhttp3.OkHttpClient');
        Client.newCall.implementation = function (request) {
            try {
                var u = request.url().toString();
                recordHttp(request.method(), u, 'request_created');
            } catch (e) {}
            return this.newCall(request);
        };
        installed.push('okhttp3.OkHttpClient.newCall');
        hookOkHttpResponse();
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
                if (u.indexOf('http') === 0) recordHttp('GET?', u, 'connection_opened');
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
