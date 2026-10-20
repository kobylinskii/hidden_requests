#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Запускает приложение под Frida с hook.js и пишет NDJSON реально выполненных
сетевых вызовов. Работает до Ctrl-C — всё это время исследуйте приложение
руками или GUI-роботом.

Если приложение падает или его убивает система, сессия перезапускается сама и
запись продолжается в тот же файл: исследование до насыщения идёт часами, и
терять его из-за одного краша нельзя.

    python3 trace.py --package gpm.tnt_premier
    python3 trace.py --package gpm.tnt_premier --append    # дописать ещё сессию

Требует frida-server на устройстве той же версии, что frida на хосте.
"""

import argparse
import json
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

import frida

HERE = Path(__file__).resolve().parent


def apk_version(package):
    """Версия установленного пакета. Статика и динамика обязаны быть сняты с
    одной сборки: после минификации имена методов у разных сборок разные, и
    сопоставление молча даёт 100% «скрытых» запросов."""
    try:
        out = subprocess.run(["adb", "shell", "dumpsys", "package", package],
                             capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return {}
    name = re.search(r"versionName=(\S+)", out)
    code = re.search(r"versionCode=(\d+)", out)
    return {"versionName": name.group(1) if name else None,
            "versionCode": code.group(1) if code else None}


def pick_device(spec):
    mgr = frida.get_device_manager()
    if spec:
        return mgr.get_device(spec, timeout=10)
    try:
        return frida.get_usb_device(timeout=5)
    except frida.InvalidArgumentError:
        pass
    # Эмуляторы, подключённые через adb (в т.ч. `adb connect 127.0.0.1:PORT`),
    # frida показывает как type == "usb". Псевдоустройства "socket" и "barebone"
    # тоже не local, но frida-server за ними нет — отбираем именно usb.
    for d in mgr.enumerate_devices():
        if d.type == "usb":
            return d
    sys.exit("error: устройство не найдено. Проверьте `adb devices` и frida-server.")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--package", required=True, help="например gpm.tnt_premier")
    ap.add_argument("--out", type=Path, help="по умолчанию out/<package>.dynamic.jsonl")
    ap.add_argument("--device", help="id устройства frida (по умолчанию — автоподбор)")
    ap.add_argument("--append", "-a", action="store_true",
                    help="дописать в существующий файл (несколько сессий)")
    ap.add_argument("--params", type=Path,
                    help="карта параметров (листья тел/URL/ответов) для activate.py --seed; "
                         "по умолч. out/<package>.params.jsonl")
    ap.add_argument("--max-restarts", type=int, default=10,
                    help="сколько раз поднимать упавшее приложение (0 — не поднимать)")
    ap.add_argument("--script", type=Path, default=None,
                    help="агент; по умолч. build/hook.js (frida 17, собран с "
                         "frida-java-bridge), иначе hook.js (frida 16/arm)")
    args = ap.parse_args()

    out = args.out or HERE / "out" / f"{args.package}.dynamic.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    fh = out.open("a" if args.append else "w", encoding="utf-8")
    # Карта параметров: компактный дедуп (name,val)->url. Мусорные запросы дают
    # листья, но они инертны — activate.py берёт значение только если у скрытого
    # слота совпали имя И ресурс. Копим в памяти, пишем один раз в конце.
    params_path = args.params or HERE / "out" / f"{args.package}.params.jsonl"
    params = {}
    PARAMS_CAP = 8000
    # frida 17 убрал глобал Java → грузим собранный build/hook.js (bundle с
    # frida-java-bridge); исходный hook.js падает "ReferenceError: Java is not defined".
    script_path = args.script or (HERE / "build" / "hook.js"
                                  if (HERE / "build" / "hook.js").exists() else HERE / "hook.js")
    script_src = script_path.read_text(encoding="utf-8")
    print(f"агент: {script_path.relative_to(HERE)}", file=sys.stderr)

    device = pick_device(args.device)
    print(f"устройство: {device.id} ({device.name})", file=sys.stderr)

    meta = {"t": "meta", "package": args.package, **apk_version(args.package)}
    print(f"версия: {meta.get('versionName')} (code {meta.get('versionCode')}) — "
          f"статику снимайте с этой же сборки", file=sys.stderr)
    fh.write(json.dumps(meta, ensure_ascii=False) + "\n")

    stop = {"now": False}
    state = {"session": None, "script": None, "restart": False, "restarts": 0}
    # Считаем уникальные ключи на хосте, а не в агенте: после перезапуска агент
    # поднимается с чистыми множествами и заново шлёт те же события.
    seen = {"retrofit": set(), "http": set()}
    limit_hit = {"yes": False}
    # Индикатор насыщения: время последнего НОВОГО уникального вызова — чтобы
    # видеть в терминале, когда новые запросы перестали появляться.
    progress = {"last_new": time.time()}

    def on_message(message, data):
        if message["type"] == "error":
            print(f"[agent error] {message.get('description')}", file=sys.stderr)
            return
        payload = message.get("payload") or {}
        kind = payload.get("t")
        if kind == "log":
            msg = payload.get("msg", "")
            if "MAX_EVENTS" in msg:
                limit_hit["yes"] = True
            print(f"[agent] {msg}", file=sys.stderr)
            return
        if kind == "ready":
            print(f"[agent] перехвачено: {', '.join(payload.get('installed') or [])}",
                  file=sys.stderr)
            return
        if kind == "param":
            # Карта параметров — отдельно, НЕ в dynamic.jsonl (иначе мусор и ломается
            # diff). Дедуп по (name,val), храним представительный url для ресурса.
            key = (payload.get("name"), str(payload.get("val")))
            if key[0] and key not in params and len(params) < PARAMS_CAP:
                params[key] = payload.get("url", "")
            return
        # NDJSON — честный журнал событий: после перезапуска повторы остаются,
        # diff.py работает множествами и на них не реагирует.
        fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
        fh.flush()
        if kind == "retrofit":
            key = f"{payload['cls']}->{payload['m']}"
            if key not in seen["retrofit"]:
                seen["retrofit"].add(key)
                progress["last_new"] = time.time()
                print(f"  + [retrofit] {key}  (всего {len(seen['retrofit'])})", file=sys.stderr)
        elif kind == "http":
            url = payload.get("url", "")
            if url and url not in seen["http"]:
                seen["http"].add(url)
                progress["last_new"] = time.time()
                print(f"  + [http] {url[:90]}  (всего {len(seen['http'])})", file=sys.stderr)

    def on_detached(reason, crash):
        # Колбэк приходит из потока frida — отсюда нельзя дёргать spawn/attach,
        # поэтому только выставляем флаг, а поднимает сессию основной цикл.
        if stop["now"] or reason == "application-requested":
            return
        print(f"\n[!] сессия отвалилась: {reason}", file=sys.stderr)
        state["restart"] = True

    def start():
        # Только spawn: Retrofit создаёт прокси рано, и при подключении к уже
        # запущенному процессу хук на newProxyInstance не увидит ни одного.
        pid = device.spawn([args.package])
        session = device.attach(pid)
        session.on("detached", on_detached)
        script = session.create_script(script_src)
        script.on("message", on_message)
        script.load()
        device.resume(pid)
        state["session"], state["script"] = session, script

    start()

    print(f"\nпишу в {out}\nисследуйте приложение; Ctrl-C — закончить\n", file=sys.stderr)
    signal.signal(signal.SIGINT, lambda *_: stop.__setitem__("now", True))
    HEARTBEAT = 15      # как часто печатать сводку, сек
    SATURATED = 60      # «без новых» дольше этого — считаем насыщением
    last_beat = time.time()
    try:
        while not stop["now"]:
            now = time.time()
            if now - last_beat >= HEARTBEAT:
                last_beat = now
                idle = int(now - progress["last_new"])
                hint = ("НАСЫЩЕНИЕ — можно Ctrl-C" if idle >= SATURATED
                        else "кликайте дальше")
                print(f"[сбор] retrofit: {len(seen['retrofit'])} | http: {len(seen['http'])} URL "
                      f"| {idle}с без новых — {hint}", file=sys.stderr)
            if state["restart"]:
                state["restart"] = False
                if state["restarts"] >= args.max_restarts:
                    print(f"[!] предел перезапусков ({args.max_restarts}) исчерпан, "
                          f"заканчиваю", file=sys.stderr)
                    break
                state["restarts"] += 1
                time.sleep(2)          # дать системе прибрать процесс
                try:
                    start()
                    print(f"[+] перезапуск {state['restarts']}/{args.max_restarts}, "
                          f"запись продолжается", file=sys.stderr)
                except Exception as e:
                    print(f"[!] поднять приложение не удалось: {e}", file=sys.stderr)
                    state["restart"] = True
                    time.sleep(3)
            time.sleep(0.3)
    finally:
        stats = {}
        try:
            stats = state["script"].exports_sync.stats()
        except Exception as e:
            print(f"\nстатистику агента забрать не удалось: {e}", file=sys.stderr)
        fh.close()
        try:
            if state["session"]:
                state["session"].detach()
        except Exception:
            pass

        if params:
            with params_path.open("w", encoding="utf-8") as pf:
                for (name, val), url in params.items():
                    pf.write(json.dumps({"name": name, "val": val, "url": url},
                                        ensure_ascii=False) + "\n")
            print(f"параметров в карте (name,val):  {len(params)} → {params_path}", file=sys.stderr)

        print(f"\nуникальных ключей класс->метод: {len(seen['retrofit'])}", file=sys.stderr)
        print(f"уникальных HTTP-URL:            {len(seen['http'])}", file=sys.stderr)
        if state["restarts"]:
            print(f"перезапусков приложения:        {state['restarts']}", file=sys.stderr)
        # stats() виден только по последней сессии, поэтому дополнительно
        # смотрим на флаг, взведённый сообщением агента в любой из сессий.
        if limit_hit["yes"] or stats.get("dropped"):
            print(f"\n[!] ВНИМАНИЕ: агент упёрся в MAX_EVENTS и отбрасывал события "
                  f"(в последней сессии — {stats.get('dropped', '?')}).\n"
                  f"    Отчёт будет ЗАНИЖЕН: потерянный вызов выглядит как скрытый "
                  f"запрос.\n    Поднимите MAX_EVENTS в hook.js и повторите прогон.",
                  file=sys.stderr)
        print(f"→ {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
