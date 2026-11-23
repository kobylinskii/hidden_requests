'use strict';
/* Фиксированный рантайм принудительной активации. План — декларативный JSON
 * (см. spec §6); весь хрупкий Frida-код (перегрузки, корутины, прокси) — здесь,
 * один раз. hook.js грузится рядом и подтверждает факт вызова. */

var proxyByIface = {};   // имя интерфейса -> живой прокси-инстанс (для call_retrofit)
var cap = { key: null, path: '', hits: [], resp: null };   // path — ожидаемый endpoint; resp — ответ сервера на форс
// КАРТА ПАРАМЕТРОВ ПРИЛОЖЕНИЯ (б2b): реальные значения, НАБЛЮДЁННЫЕ в трафике
// (тела и URL запросов + тела ответов), для подстановки вместо $stub-заглушек.
// Структура: normName -> [ {val, key, resource, shape} ] — несколько кандидатов
// на имя, чтобы разрешать коллизии (`id` устройства vs шоу vs профиля). Три слоя:
//   (1) область видимости по РЕСУРСУ (сегмент пути) — свой домен не мешается с чужим;
//   (2) сигнатура ФОРМЫ (num/uuid/hex/jwt/slug/str) — отсев явно-чужого типа;
//   (3) остаточная неоднозначность → пометка [ambig:N] (окончательный арбитр — сервер).
// App-agnostic: только имена полей, сегменты пути и форма значения.
var pool = {};

function jclass(name) { return Java.use(name.replace(/\//g, '.')); }

// #2: значение obj — инстанс типа fq (frida-имя класса/интерфейса)? Для выбора
// СЕМАНТИЧЕСКИ верного живого инстанса ($field/$choose), а не первого по типу поля.
function isType(obj, fq) {
    try { return jclass(fq).class.isInstance(obj); } catch (e) { return false; }
}

// Слой 1: сегмент-ресурс из URL. /app/v1.1.3/download/disallow-device -> "download".
// Отбрасываем host, версии (vN/vN.N) и технические префиксы.
function resourceOf(url) {
    try {
        var p = String(url).replace(/^[a-z]+:\/\/[^/]+/i, '').split('?')[0];
        var segs = p.split('/').filter(function (s) {
            return s && !/^v\d+(\.\d+)*$/i.test(s) &&
                   ['app', 'api', 'catalog', 'uma-api', 'frontend'].indexOf(s.toLowerCase()) === -1;
        });
        return segs.length ? segs[0].toLowerCase() : '';
    } catch (e) { return ''; }
}

// Слой 2: сигнатура формы значения (грубый класс, без онтологии).
function shapeOf(v) {
    var s = String(v);
    if (/^\d+$/.test(s)) return 'num';
    if (/^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i.test(s)) return 'uuid';
    if (/^ey[A-Za-z0-9_-]+\./.test(s)) return 'jwt';
    if (/^[0-9a-f]{16,}$/i.test(s)) return 'hex';
    if (/^[a-z0-9]+(-[a-z0-9]+)+$/.test(s)) return 'slug';
    return 'str';
}

function _poolAdd(name, val, resource) {
    var nk = normKey(name);
    if (!nk || nk.length < 2) return;
    var sv = String(val);
    if (!sv.length || sv === 'stub') return;
    var arr = pool[nk] || (pool[nk] = []);
    for (var i = 0; i < arr.length; i++)
        if (arr[i].key === sv && arr[i].resource === resource) return;   // dedup
    if (arr.length < 40) arr.push({ val: val, key: sv, resource: resource, shape: shapeOf(sv) });
}

// Собрать непустые примитивные листья JSON (тела запроса/ответа) в карту под ресурсом.
function recordPool(obj, resource) {
    if (obj === null || typeof obj !== 'object') return;
    for (var k in obj) {
        var v = obj[k];
        if (v !== null && typeof v === 'object') recordPool(v, resource);
        else if ((typeof v === 'string' && v !== '' && v !== 'stub') ||
                 (typeof v === 'number' && v !== 0) || typeof v === 'boolean')
            _poolAdd(k, v, resource);
    }
}

// URL — тоже источник реальных сущностей: query-параметры (?cid=...) и id в пути
// (/streams/<id> → под именем `id`, частое имя слота). ponytail: path-id кладём
// только как `id`; именованные path-шаблоны {slug} восстановить из URL нельзя.
function recordUrl(url) {
    try {
        var res = resourceOf(url);
        var m = String(url).replace(/^[a-z]+:\/\/[^/]+/i, '');
        var qs = m.split('?')[1];
        if (qs) qs.split('&').forEach(function (p) {
            var i = p.indexOf('='); if (i < 0) return;
            try { _poolAdd(decodeURIComponent(p.slice(0, i)), decodeURIComponent(p.slice(i + 1)), res); }
            catch (e) {}
        });
        m.split('?')[0].split('/').filter(Boolean).forEach(function (seg) {
            var sh = shapeOf(seg);
            if (sh === 'num' || sh === 'uuid' || sh === 'hex') _poolAdd('id', seg, res);
        });
    } catch (e) {}
}

// ── Harvest из ПЕРСИСТЕНТНЫХ сторов (SharedPreferences/DataStore) ──────────────
// Реальные сессионные значения (token/uid/device_id) приложение хранит на диске и
// держит в куче ПОСЛЕ логина — в отличие от per-action DTO они НЕ транзиентны.
// Собираем все пары ключ→значение из живых сторов; матчим с пустыми полями запроса
// по НОРМАЛИЗОВАННОМУ имени (ключи prefs вроде `pref_session_data` не совпадают с
// полем `session` буквально, но совпадают после нормализации). App-agnostic:
// перечисляем стандартные Android/Jetpack-классы, без знания классов приложения.
var storeDump = {}, _storesDone = false;
function normKey(s) {               // pref_session_data → sessiondata; PREF_DEVICE_ID_…_FROM_SERVER → deviceid…
    return String(s).toLowerCase()
        .replace(/^pref[_.]?/, '').replace(/_from_server$/, '').replace(/[^a-z0-9]/g, '');
}
function _addStore(k, v) {
    if (k === null || k === undefined || v === null || v === undefined) return;
    var cls; try { cls = v.getClass().getName(); } catch (e) { cls = ''; }
    if (cls === 'java.lang.Boolean') return;        // флаги (shown-tip и т.п.) — не данные
    var vs; try { vs = v.toString(); } catch (e) { return; }
    if (!vs || !vs.length || vs === 'stub') return;
    // Не атомарное значение → не параметр слота: склейка с пробелами (okhttp
    // User-Agent-блоб лез в platform/deviceModel) или структура/дата в скобках
    // ([2026-10-20] лез в deviceName). Токены/id/slug пробелов и скобок не несут.
    if (/\s/.test(vs) || '[{('.indexOf(vs.charAt(0)) !== -1) return;
    var nk = normKey(k);
    if (nk && !(nk in storeDump)) storeDump[nk] = { val: vs, orig: String(k) };
}
function harvestStores() {
    // SharedPreferences (вкл. EncryptedSharedPreferences — getAll() отдаёт расшифрованное)
    ['android.app.SharedPreferencesImpl',
     'androidx.security.crypto.EncryptedSharedPreferences'].forEach(function (cn) {
        try { jclass(cn); } catch (e) { return; }
        Java.choose(cn, { onMatch: function (sp) {
            try { var all = sp.getAll(), it = all.keySet().iterator();
                while (it.hasNext()) { var key = it.next(); _addStore(key ? key.toString() : null, all.get(key)); }
            } catch (e) {}
        }, onComplete: function () {} });
    });
    // DataStore Preferences (best-effort: токен может быть здесь, напр. TNT refreshToken)
    ['androidx.datastore.preferences.core.MutablePreferences',
     'androidx.datastore.preferences.core.PreferencesMap'].forEach(function (cn) {
        try { jclass(cn); } catch (e) { return; }
        Java.choose(cn, { onMatch: function (p) {
            try { var m = p.asMap(), it = m.keySet().iterator();
                while (it.hasNext()) { var key = it.next();
                    var name; try { name = key.getName(); } catch (e) { name = key ? key.toString() : null; }
                    _addStore(name, m.get(key)); }
            } catch (e) {}
        }, onComplete: function () {} });
    });
}
function ensureStoreHarvest() { if (_storesDone) return; _storesDone = true; try { harvestStores(); } catch (e) {} }

// Fuzzy-поиск значения стора по имени поля запроса (нормализованное совпадение).
function storeFuzzy(fieldName) {
    var fn = normKey(fieldName);
    if (fn.length < 3) return null;                 // слишком короткое имя → шумный матч
    var best = null, bestLen = 0;
    for (var nk in storeDump) {
        if (nk === fn || nk.indexOf(fn) !== -1 || fn.indexOf(nk) !== -1) {
            var ov = Math.min(nk.length, fn.length);   // предпочитаем самое длинное пересечение
            if (ov > bestLen) { bestLen = ov; best = storeDump[nk]; }
        }
    }
    return best;                                    // {val, orig} | null
}

// Выбрать значение из карты под слот (имя поля, целевой ресурс) по слоям 1–3.
// Слой 1 (ресурс) — жёсткий: междоменный матч ЗАПРЕЩЁН (иначе ложный b1, напр.
// id шоу в слот устройства). Слой 2/3 — ранжирование и пометка неоднозначности.
function poolPick(fieldName, targetRes) {
    var fn = normKey(fieldName);
    if (fn.length < 2) return null;
    var cands = [];
    for (var nk in pool) {
        if (nk === fn || nk.indexOf(fn) !== -1 || fn.indexOf(nk) !== -1) {
            var ov = Math.min(nk.length, fn.length), exact = nk === fn;
            pool[nk].forEach(function (e) {
                if (e.resource === targetRes) cands.push({ e: e, ov: ov, exact: exact });
            });
        }
    }
    if (!cands.length) return null;                         // нет своего домена → не заполняем
    cands.sort(function (a, b) { return (b.exact - a.exact) || (b.ov - a.ov); });
    var vals = {}; cands.forEach(function (c) { vals[c.e.key] = 1; });
    return { val: cands[0].e.val, resource: targetRes, shape: cands[0].e.shape,
             ambig: Object.keys(vals).length };
}

// Наполнить пустые/заглушечные поля тела реальными значениями. Приоритет: карта
// параметров (трафик, со слоями) → fuzzy из персистентного стора (сессия/токен,
// без ресурса). filled помечает источник (артефакт ВКР). App-agnostic.
function fillFromHarvest(obj, filled, targetRes) {
    var changed = false;
    if (obj === null || typeof obj !== 'object') return changed;
    for (var k in obj) {
        var v = obj[k];
        if (v !== null && typeof v === 'object') {
            if (fillFromHarvest(v, filled, targetRes)) changed = true;
        } else if (v === '' || v === 'stub') {      // пустое ИЛИ наш $stub-плейсхолдер
            var p = poolPick(k, targetRes);
            if (p) {
                obj[k] = p.val; changed = true;
                filled.push(k + '←traffic:' + p.resource + '[' + p.shape + ']' +
                            (p.ambig > 1 ? '(ambig:' + p.ambig + ')' : ''));
            } else {
                var s = storeFuzzy(k);
                if (s) { obj[k] = s.val; filled.push(k + '←store:' + s.orig); changed = true; }
            }
        }
    }
    return changed;
}

// JSON-значение -> Java-значение. $choose берёт ЖИВОЙ инстанс (реальные параметры).
function coerce(v) {
    if (v === null || typeof v !== 'object') return v;
    if ('$null' in v) return null;
    if ('$class' in v) { return jclass(v['$class']).class; }   // java.lang.Class литерал
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
    if (name.charAt(0) === '[') {   // массив → ПУСТОЙ массив (иначе null → NPE "length of null array")
        var el = name.slice(1), prim = {Z:'boolean',B:'byte',S:'short',C:'char',I:'int',J:'long',F:'float',D:'double'};
        try {
            if (el in prim) return Java.array(prim[el], []);
            if (el.charAt(0) === 'L') return Java.array(el.slice(1, -1).replace(/\//g, '.'), []);
            if (el.charAt(0) === '[') return Java.array(el, []);   // многомерный
        } catch (e) {}
        return null;
    }
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
    if (want === null) return m;
    var ov = m.overloads, CONT = 'kotlin.coroutines.Continuation';
    // точное совпадение типов аргументов
    for (var i = 0; i < ov.length; i++) {
        var a = ov[i].argumentTypes.map(function (t) { return t.className; });
        if (a.length === want.length && a.join(',') === want.join(',')) return ov[i];
    }
    // suspend: реальная перегрузка = want + хвостовой Continuation (в срезе его нет).
    // invokeOverload дошлёт наш Continuation сам.
    for (var j = 0; j < ov.length; j++) {
        var b = ov[j].argumentTypes.map(function (t) { return t.className; });
        if (b.length === want.length + 1 && b[want.length] === CONT &&
            b.slice(0, want.length).join(',') === want.join(',')) return ov[j];
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

if (typeof rpc !== 'undefined') rpc.exports = {
    captureOn: function (key, pathHint) { cap.key = key; cap.path = pathHint || ''; cap.hits = []; cap.resp = null; },
    // Засеять карту параметров из трафика, собранного на шаге сбора (trace.py):
    // items = [{name, val, url}]. Ресурс/форму считаем здесь (resourceOf/_poolAdd),
    // чтобы не дублировать логику на хосте. Дополняет пассивный рантайм-harvest.
    seedPool: function (items) {
        var n = 0;
        (items || []).forEach(function (it) {
            try { _poolAdd(it.name, it.val, resourceOf(it.url || '')); n++; } catch (e) {}
        });
        return n;
    },
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
        for (var i = 0; i < cap.hits.length; i++) if (cap.hits[i].matched) {
            if (cap.resp) cap.hits[i].response = cap.resp;   // ответ сервера-оракул
            return cap.hits[i];
        }
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
if (typeof Java !== 'undefined') Java.perform(function () {
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
        var bytes = buf.readByteArray();
        if (bytes === null || bytes.length === 0) return (bytes === null) ? null : '';
        // текст или бинарь (protobuf)? доля печатных байт в начале
        var printable = 0, lim = Math.min(bytes.length, 512);
        for (var i = 0; i < lim; i++) {
            var c = bytes[i] & 0xff;
            if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 0xC0) printable++;
        }
        if (printable / lim > 0.85) return Java.use('java.lang.String').$new(bytes, 'UTF-8');
        // бинарное тело (protobuf) — base64-улика, не теряем (#3: видим блоб)
        var b64 = Java.use('android.util.Base64').encodeToString(bytes, 2); // NO_WRAP
        return '<proto ' + bytes.length + 'b b64:' + b64.slice(0, 160) + '>';
    } catch (e) { return '<unreadable>'; }
}

function captureRequest(req, source, body, filled) {
    try {
        if (body === undefined) body = bodyOf(req);
        var url = req.url().toString();
        // harvest из ЛЮБОГО запроса (в т.ч. собственного трафика приложения): тело + URL
        var res = resourceOf(url);
        if (body && body.charAt(0) === '{') { try { recordPool(JSON.parse(body), res); } catch (e) {} }
        recordUrl(url);
        if (!cap.key || cap.hits.length >= 10) return;
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
    if (!body) return { req: req, body: body };
    ensureStoreHarvest();                       // лениво снять персистентные сторы (один раз)
    // Тело бывает JSON ({...}) и form-urlencoded (a=stub&b=&c=x) — поддерживаем оба.
    var isJson = body.charAt(0) === '{';
    var obj, isForm = false;
    if (isJson) {
        try { obj = JSON.parse(body); } catch (e) { return { req: req, body: body }; }
    } else if (body.indexOf('=') !== -1) {
        isForm = true; obj = {};
        body.split('&').forEach(function (p) {
            var i = p.indexOf('='); if (i < 0) return;
            try { obj[decodeURIComponent(p.slice(0, i))] = decodeURIComponent(p.slice(i + 1)); }
            catch (e) { obj[p.slice(0, i)] = p.slice(i + 1); }
        });
    } else {
        return { req: req, body: body };
    }
    var filled = [];
    if (!fillFromHarvest(obj, filled, resourceOf(url))) return { req: req, body: body };
    try {
        var outBody;
        if (isForm) {
            var parts = [];
            for (var fk in obj) parts.push(encodeURIComponent(fk) + '=' + encodeURIComponent(obj[fk]));
            outBody = parts.join('&');
        } else {
            outBody = JSON.stringify(obj);
        }
        var ct = req.body().contentType();   // сохранить media type
        var RequestBody = Java.use('okhttp3.RequestBody');
        var bytes = Java.use('java.lang.String').$new(outBody).getBytes('UTF-8');
        var nb;
        // okhttp менял сигнатуру RequestBody.create между версиями — пробуем обе.
        try { nb = RequestBody.create(ct, bytes); }
        catch (e) { nb = RequestBody.create(bytes, ct); }
        _inPatch = true;   // re-entrancy guard: .build() ниже — тот же хук
        var nr = req.newBuilder().method(req.method(), nb).build();
        _inPatch = false;
        return { req: nr, body: outBody, filled: filled };
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
    // Ответы: окно для реальных сущностей (id/slug приходят В ОТВЕТЕ, напр. список
    // устройств для disallow-device). peekBody НЕ потребляет оригинал (окно для
    // приложения не ломается). ponytail: cap 128KB + только JSON — не парсим видео/бинарь.
    try {
        var RespB = Java.use('okhttp3.Response$Builder');
        RespB.build.implementation = function () {
            var resp = this.build();
            try {
                var rurl = resp.request().url().toString();
                var ct = resp.header('Content-Type', '') || '';
                var txt = (ct.indexOf('json') !== -1) ? resp.peekBody(131072).string() : null;
                if (txt && (txt.charAt(0) === '{' || txt.charAt(0) === '['))
                    recordPool(JSON.parse(txt), resourceOf(rurl));
                // Ответ на НАШ форс-вызов (url совпал с ожидаемым endpoint) — ОРАКУЛ:
                // статус + тело (сервер в теле называет недостающий/невалидный параметр).
                if (cap.key && cap.path && cap.path !== '/' && rurl.indexOf(cap.path) !== -1) {
                    var rb = txt;
                    if (rb === null) { try { rb = resp.peekBody(8192).string(); } catch (e2) { rb = null; } }
                    cap.resp = { status: resp.code(), url: rurl,
                                 body: rb ? String(rb).slice(0, 2000) : null };
                    try { send({ t: 'captured_response', key: cap.key, resp: cap.resp }); } catch (e3) {}
                }
            } catch (e) {}
            return resp;
        };
        ok = true;
    } catch (e) {}
    if (ok) return;
    if (attemptsLeft <= 0) return;
    setTimeout(function () { installOkHttpCapture(attemptsLeft - 1); }, 1000);
}

// ── Самопроверка чистой логики матчинга (node activate.js) ────────────────────
// Под frida Java определён → блок пропускается. Под node — гоняем слои 1–3.
if (typeof Java === 'undefined') {
    var _f = 0;
    function _eq(a, b, m) { if (a !== b) { _f++; console.log('FAIL ' + m + ': ' + JSON.stringify(a) + ' != ' + JSON.stringify(b)); } }
    // слой 1: ресурс
    _eq(resourceOf('https://premier.one/app/v1.1.3/download/disallow-device?x=1'), 'download', 'res-download');
    _eq(resourceOf('https://premier.one/catalog/v1/show/access?id=1'), 'show', 'res-show');
    _eq(resourceOf('https://premier.one/uma-api/feeds/397'), 'feeds', 'res-feeds');
    // слой 2: форма
    _eq(shapeOf('12345'), 'num', 'shape-num');
    _eq(shapeOf('ab12cd34-ef56-7890-ab12-cd34ef567890'), 'uuid', 'shape-uuid');
    _eq(shapeOf('little-portrait'), 'slug', 'shape-slug');
    _eq(shapeOf('eyJhbGc.payload'), 'jwt', 'shape-jwt');
    _eq(shapeOf('deadbeefdeadbeef'), 'hex', 'shape-hex');
    _eq(shapeOf('promo'), 'str', 'shape-str');
    // слои 1+3: коллизия имени `id` между ресурсами + ambig + запрет междоменного
    pool = {};
    _poolAdd('id', '777', 'download'); _poolAdd('id', '42', 'show');
    _eq((poolPick('id', 'download') || {}).val, '777', 'collision-download');   // не берёт id шоу
    _eq((poolPick('id', 'show') || {}).val, '42', 'collision-show');
    _eq(poolPick('id', 'profile'), null, 'cross-domain-forbidden');             // чужого домена нет → null
    _poolAdd('id', '778', 'download');                                          // 2 разных id в одном ресурсе
    _eq((poolPick('id', 'download') || {}).ambig, 2, 'ambig-count');
    console.log(_f === 0 ? 'activate.js match selfcheck ok' : ('activate.js selfcheck: ' + _f + ' FAIL'));
    if (_f) { if (typeof process !== 'undefined') process.exitCode = 1; }
}
