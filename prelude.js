'use strict';
/* Нейтрализация само-завершения при детекте Frida.
 *
 * Целевое приложение (TNT Premier) обнаруживает инструментарий и само-убивается
 * через ~0.5с после старта, вызывая Java-level exit/killProcess — окна для
 * форс-активации не остаётся (эмпирически: сессия умирала на 0.48с). Глушим эти
 * пути; грузится ПЕРВЫМ, до hook.js/activate.js и до resume, чтобы стабы встали
 * раньше, чем отработает детект.
 *
 * Ограничение: закрывает только Java-пути само-завершения. Если сборка перейдёт
 * на нативный _exit/abort/raise, понадобится Interceptor на libc (пилотная фаза).
 * Это обход анти-frida на СВОЁМ стенде ради измерения достижимости — не обход
 * защиты в проде. */
Java.perform(function () {
    function noop() { return 0; }
    try { Java.use('java.lang.System').exit.implementation = function (c) {}; } catch (e) {}
    try {
        var R = Java.use('java.lang.Runtime');
        R.exit.implementation = function (c) {};
        try { R.halt.implementation = function (c) {}; } catch (e) {}
    } catch (e) {}
    try { Java.use('android.os.Process').killProcess.implementation = noop; } catch (e) {}
});
