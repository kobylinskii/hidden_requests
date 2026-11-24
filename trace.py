#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Запускает приложение под Frida с hook.js и пишет NDJSON наблюдений за методами
Retrofit и HTTP-клиентом. Работает до Ctrl-C — всё это время исследуйте приложение
руками или GUI-роботом.

Если приложение падает или его убивает система, сессия перезапускается сама и
запись продолжается в тот же файл: исследование до насыщения идёт часами, и
терять его из-за одного краша нельзя.

    python3 trace.py --package gpm.tnt_premier
    python3 trace.py --package gpm.tnt_premier --append    # дописать ещё сессию

Требует frida-server на устройстве той же версии, что frida на хосте.
"""

import argparse
import hashlib
import io
import zipfile
import json
import re
import shlex
import signal
import subprocess
import sys
import time
from uuid import uuid4
from pathlib import Path

import frida

HERE = Path(__file__).resolve().parent
PARTIAL_SESSION_EXIT = 3  # scan.sh may consume the newly finalized partial session.


def apk_version(package, serial):
    """Версия установленного пакета. Статика и динамика обязаны быть сняты с
    одной сборки: после минификации имена методов у разных сборок разные, и
    сопоставление молча даёт 100% «скрытых» запросов."""
    try:
        out = subprocess.run(["adb", "-s", serial, "shell", "dumpsys", "package", package],
                             capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return {}
    name = re.search(r"versionName=(\S+)", out)
    code = re.search(r"versionCode=(\d+)", out)
    return {"versionName": name.group(1) if name else None,
            "versionCode": code.group(1) if code else None}


def installed_identity(package, serial):
    """Bind the base APK and verify configuration splits contain no DEX code."""
    adb = ["adb", "-s", serial]
    try:
        listing = subprocess.check_output([*adb, "shell", "pm", "path", package],
                                          text=True, timeout=20)
        paths = sorted(line.removeprefix("package:").strip() for line in listing.splitlines()
                       if line.startswith("package:"))
        if not paths:
            return None, []
        bases = [p for p in paths if p.endswith("/base.apk")]
        base = paths[0] if len(paths) == 1 else bases[0] if len(bases) == 1 else None
        if base is None:
            return None, []
        inventory = []
        for path in paths:
            digest = subprocess.check_output(
                [*adb, "shell", "sha256sum " + shlex.quote(path)], text=True, timeout=60).split()[0]
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                return None, []
            if path != base:
                data = subprocess.check_output([*adb, "exec-out", "cat", path], timeout=60)
                if hashlib.sha256(data).hexdigest() != digest:
                    return None, []
                with zipfile.ZipFile(io.BytesIO(data)) as split:
                    if any(name.lower().endswith(".dex") for name in split.namelist()):
                        return None, []
            inventory.append({"name": Path(path).name, "sha256": digest})
        build = next(item["sha256"] for item in inventory if item["name"] == Path(base).name)
        return build, inventory
    except (OSError, subprocess.SubprocessError, IndexError, zipfile.BadZipFile):
        return None, []


def installed_build(package, serial):
    return installed_identity(package, serial)[0]


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
    ap.add_argument("--max-restarts", type=int, default=10,
                    help="сколько раз поднимать упавшее приложение (0 — не поднимать)")
    ap.add_argument("--script", type=Path, default=None,
                    help="агент; по умолч. build/hook.js (frida 17, собран с "
                         "frida-java-bridge), иначе hook.js (frida 16/arm)")
    args = ap.parse_args()

    out = args.out or HERE / "out" / f"{args.package}.dynamic.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    # frida 17 убрал глобал Java → грузим собранный build/hook.js (bundle с
    # frida-java-bridge); исходный hook.js падает "ReferenceError: Java is not defined".
    script_path = args.script or (HERE / "build" / "hook.js"
                                  if (HERE / "build" / "hook.js").exists() else HERE / "hook.js")
    script_src = script_path.read_text(encoding="utf-8")
    print(f"агент: {script_path}", file=sys.stderr)

    device = pick_device(args.device)
    print(f"устройство: {device.id} ({device.name})", file=sys.stderr)

    build, installed_apks = installed_identity(args.package, device.id)
    session_id = uuid4().hex
    meta = {"t": "meta", "package": args.package, "build": build, "session": session_id,
            "installed_apks": installed_apks, **apk_version(args.package, device.id)}
    appending = args.append and out.exists() and out.stat().st_size > 0
    if appending:
        from request_pipeline import read_trace
        if not build or not read_trace(out, build)["complete"]:
            ap.error("к существующей трассе можно дописать только сеанс той же подтверждённой сборки")
    fh = out.open("a" if args.append else "w", encoding="utf-8", buffering=1)
    if appending:
        fh.write("\n")  # An existing valid end record may lack its final newline.
    fh.write(json.dumps(meta, ensure_ascii=False) + "\n")
    issues = set()
    if build is None:
        issues.add("installed_build_unverified")

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
            issues.add("agent_error")
            print(f"[agent error] {message.get('description')}", file=sys.stderr)
            return
        payload = message.get("payload") or {}
        kind = payload.get("t")
        if kind == "log":
            msg = payload.get("msg", "")
            if msg.startswith(("invoke:", "newProxyInstance:", "не удалось открыть handler")):
                issues.add("hook_error")
            if "MAX_EVENTS" in msg:
                limit_hit["yes"] = True
            print(f"[agent] {msg}", file=sys.stderr)
            return
        if kind == "ready":
            print(f"[agent] перехвачено: {', '.join(payload.get('installed') or [])}",
                  file=sys.stderr)
            return
        if kind == "param":  # старый агент из --script
            return
        # NDJSON — честный журнал событий: после перезапуска повторы остаются,
        # diff.py работает множествами и на них не реагирует.
        fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
        fh.flush()
        if (kind == "retrofit" and isinstance(payload.get("handler"), str)
                and payload["handler"].startswith("retrofit2.Retrofit$")
                and payload.get("observation", "method_call") == "method_call"):
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
        issues.add("unexpected_detach")
        state["restart"] = True

    def start():
        # Только spawn: Retrofit создаёт прокси рано, и при подключении к уже
        # запущенному процессу хук на newProxyInstance не увидит ни одного.
        pid = device.spawn([args.package])
        try:
            session = device.attach(pid)
        except Exception:
            device.kill(pid)
            raise
        state["session"], state["script"] = session, None
        session.on("detached", on_detached)
        script = session.create_script(script_src)
        script.on("message", on_message)
        script.load()
        device.resume(pid)
        state["script"] = script

    print(f"\nпишу в {out}\nисследуйте приложение; Ctrl-C — закончить\n", file=sys.stderr)
    signal.signal(signal.SIGINT, lambda *_: stop.__setitem__("now", True))
    HEARTBEAT = 15      # как часто печатать сводку, сек
    SATURATED = 60      # «без новых» дольше этого — считаем насыщением
    last_beat = time.time()
    try:
        start()
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
    except Exception as error:
        issues.add("collection_failed")
        print(f"[!] Ошибка сбора: {error}", file=sys.stderr)
    finally:
        stats = {}
        try:
            stats = state["script"].exports_sync.stats()
        except Exception as e:
            print(f"\nстатистику агента забрать не удалось: {e}", file=sys.stderr)
        finally:
            try:
                if state["session"]:
                    state["session"].detach()
            except Exception:
                issues.add("detach_failed")
        if not stop["now"]:
            issues.add("session_interrupted")
        if not stats:
            issues.add("final_stats_unavailable")
        if limit_hit["yes"] or stats.get("dropped"):
            issues.add("events_dropped")
        if build is not None and installed_identity(args.package, device.id) != (build, installed_apks):
            issues.add("installed_build_changed")
        fh.write(json.dumps({"t": "end", "session": session_id, "build": build,
                             "status": "partial" if issues else "complete",
                             "reasons": sorted(issues)}, ensure_ascii=False) + "\n")
        fh.close()

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

    if issues:
        print("Причины частичной трассы: " + ", ".join(sorted(issues)), file=sys.stderr)
        sys.exit(PARTIAL_SESSION_EXIT)


if __name__ == "__main__":
    main()
