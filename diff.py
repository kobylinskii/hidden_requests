#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Скрытые HTTP-запросы = статика (BFScan .md) − динамика (Frida).

Сопоставление точное, по ключу `класс->метод`. BFScan извлекает эндпоинты из
аннотаций Retrofit/Ktorfit, а Frida перехватывает вызов того же интерфейсного
метода через динамический прокси Retrofit и отдаёт объект Method. Никаких
эвристик по путям — в отличие от ~/hidden_requests/compare.py.

Рассчитано на приложения без обфускации: имя метода в DEX совпадает с тем, что
печатает BFScan, и этого достаточно для ключа.

    python3 diff.py --static apk/gpm.tnt_premier_methods.md \
                    --dynamic out/gpm.tnt_premier.dynamic.jsonl \
                    --out out/gpm.tnt_premier.hidden.jsonl
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

_METHOD = re.compile(r"^\*\*Method\*\*:\s*(.+?)->(.+?)\s*$")
_REQUEST = re.compile(r"^([A-Z]+)\s+(\S+)\s+HTTP/1\.1\s*$")


def parse_bfscan(md_path: Path) -> list:
    """Разбирает вывод BFScan. Формат: `**Method**: fqcn->name`, затем блок с
    сырым HTTP-запросом, первая строка которого `VERB /path?query HTTP/1.1`."""
    out, cls, name, source = [], None, None, None
    for line in md_path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = _METHOD.match(line)
        if m:
            cls, name, source = m.group(1), m.group(2), None
            continue
        if line.startswith("* ") and cls:
            source = line[2:].strip()
            continue
        r = _REQUEST.match(line)
        if r and cls:
            path, _, query = r.group(2).partition("?")
            out.append({
                "key": f"{cls}->{name}",
                "cls": cls,
                "method": name,
                "verb": r.group(1),
                "path": path,
                "query": query,
                "source": source,
            })
    return out


def load_dynamic(path: Path):
    """Читает NDJSON от hook.js. Возвращает (вызванные ключи, HTTP-события, meta)."""
    called, http, meta = set(), [], {}
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            print(f"warn: {path}:{n} не JSON, пропущено", file=sys.stderr)
            continue
        t = ev.get("t")
        if t == "retrofit":
            called.add(f"{ev['cls']}->{ev['m']}")
        elif t == "http":
            http.append(ev)
        elif t == "meta":
            meta = ev
    return called, http, meta


def report(static, called, http, meta=None, verbose=False):
    # Один ключ может давать несколько записей: перегрузки метода отличаются
    # набором query-параметров, но в рантайме неразличимы. Схлопываем по ключу.
    by_key = defaultdict(list)
    for s in static:
        by_key[s["key"]].append(s)

    hidden_keys = sorted(k for k in by_key if k not in called)
    found_keys = sorted(k for k in by_key if k in called)
    # Метод вызван, класс BFScan знает, а самой записи в статике нет.
    static_classes = {s["cls"] for s in static}
    missed_by_bfscan = sorted(k for k in called - set(by_key)
                              if k.rsplit("->", 1)[0] in static_classes)

    lines = []
    w = lines.append
    w("=" * 78)
    w("ОТЧЁТ О СКРЫТЫХ HTTP-ЗАПРОСАХ")
    w("=" * 78)
    if meta:
        w(f"Приложение: {meta.get('package')} "
          f"versionName={meta.get('versionName')} versionCode={meta.get('versionCode')}")
    w(f"Статических эндпоинтов (записей BFScan): {len(static)}")
    w(f"Уникальных ключей класс->метод:          {len(by_key)}")
    w(f"Вызвано в рантайме:                      {len(found_keys)}")
    pct = f" ({len(hidden_keys) / len(by_key) * 100:.1f}%)" if by_key else ""
    w(f"СКРЫТО (ни разу не вызвано):             {len(hidden_keys)}{pct}")
    w("")

    w("-" * 78)
    w(f"СКРЫТЫЕ ЗАПРОСЫ ({len(hidden_keys)})")
    w("-" * 78)
    for key in hidden_keys:
        recs = by_key[key]
        cls, _, method = key.partition("->")
        w(f"\n[HIDDEN] {cls}")
        w(f"         метод: {method}")
        for r in recs:
            q = f"?{r['query']}" if r["query"] else ""
            w(f"         {r['verb']} {r['path']}{q}")
        if len(recs) > 1:
            w(f"         ({len(recs)} перегрузок — в рантайме неразличимы)")

    if missed_by_bfscan:
        w("")
        w("-" * 78)
        w(f"ВЫЗВАНО, НО НЕТ В СТАТИКЕ ({len(missed_by_bfscan)})")
        w("  Класс BFScan знает, а этот его метод — нет: аннотацию он не разобрал.")
        w("-" * 78)
        for key in missed_by_bfscan:
            w(f"  {key}")

    non_retrofit = [e for e in http if not e.get("via_retrofit")]
    if non_retrofit:
        urls = sorted({e.get("url", "") for e in non_retrofit})
        w("")
        w("-" * 78)
        w(f"HTTP-ВЫЗОВЫ ВНЕ RETROFIT ({len(urls)} уникальных URL)")
        w("  Сырой OkHttp, Ktor, WebView, аналитика. BFScan извлекает только")
        w("  аннотации Retrofit/Ktorfit, поэтому это оценка неполноты статики.")
        w("-" * 78)
        for u in urls[: (None if verbose else 40)]:
            w(f"  {u}")
        if not verbose and len(urls) > 40:
            w(f"  ... ещё {len(urls) - 40}, полный список в --out")

    if verbose and found_keys:
        w("")
        w("-" * 78)
        w(f"НАЙДЕНО В ТРАФИКЕ ({len(found_keys)})")
        w("-" * 78)
        for key in found_keys:
            for r in by_key[key]:
                w(f"  [FOUND] {key}  {r['verb']} {r['path']}")

    return "\n".join(lines), hidden_keys, by_key, missed_by_bfscan, non_retrofit


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--static", required=True, type=Path, help="BFScan *_methods.md")
    ap.add_argument("--dynamic", required=True, type=Path, help="NDJSON от trace.py")
    ap.add_argument("--out", type=Path, help="куда сохранить hidden.jsonl")
    ap.add_argument("-v", "--verbose", action="store_true", help="печатать и FOUND")
    args = ap.parse_args()

    static = parse_bfscan(args.static)
    if not static:
        sys.exit(f"error: в {args.static} не найдено ни одной записи BFScan")
    called, http, meta = load_dynamic(args.dynamic)

    text, hidden_keys, by_key, missed, non_retrofit = report(
        static, called, http, meta, args.verbose)
    print(text)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w", encoding="utf-8") as f:
            if meta:  # версия сборки — slice.py сверит её с APK
                f.write(json.dumps({**meta, "status": "meta"}, ensure_ascii=False) + "\n")
            for key in hidden_keys:
                for r in by_key[key]:
                    f.write(json.dumps({**r, "status": "hidden"},
                                       ensure_ascii=False) + "\n")
            for key in missed:
                f.write(json.dumps({"key": key, "status": "not_in_static"},
                                   ensure_ascii=False) + "\n")
            for e in non_retrofit:
                f.write(json.dumps({**e, "status": "non_retrofit"},
                                   ensure_ascii=False) + "\n")
        print(f"\n→ {args.out}", file=sys.stderr)


def _selfcheck():
    """python3 diff.py --selfcheck"""
    import tempfile
    md = """**HTTP Methods**

**Method**: gpm.tnt_premier.DownloadsApi->getDownloadDevices

* Retrofit/Ktorfit Method
```
GET /app/v1.1.3/download/devices HTTP/1.1
Host: localhost
```

**Method**: ru.ivi.mapi.AuthApi->getUserInfo

* Retrofit/Ktorfit Method
```
GET /user/info/v5/?fields=value HTTP/1.1
```

**Method**: ru.ivi.mapi.AuthApi->getUserInfo

* Retrofit/Ktorfit Method
```
GET /user/info/v5/?key=value HTTP/1.1
```
"""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "m.md"
        p.write_text(md, encoding="utf-8")
        recs = parse_bfscan(p)
        assert len(recs) == 3, recs
        assert recs[0]["key"] == "gpm.tnt_premier.DownloadsApi->getDownloadDevices"
        assert recs[0]["path"] == "/app/v1.1.3/download/devices"
        assert recs[0]["query"] == ""
        assert recs[1]["key"] == recs[2]["key"]            # перегрузки схлопываются

        dyn = Path(d) / "d.jsonl"
        dyn.write_text(
            '{"t":"meta","package":"gpm.tnt_premier","versionCode":"11134093"}\n'
            '{"t":"retrofit","cls":"ru.ivi.mapi.AuthApi","m":"getUserInfo"}\n'
            '{"t":"retrofit","cls":"ru.ivi.mapi.AuthApi","m":"logout"}\n'
            '{"t":"retrofit","cls":"com.other.Unrelated","m":"ping"}\n'
            '{"t":"http","url":"https://cdn.example/a.png","via_retrofit":false}\n'
            '{"t":"http","url":"https://api.example/x","via_retrofit":true}\n',
            encoding="utf-8")
        called, http, meta = load_dynamic(dyn)
        assert meta["versionCode"] == "11134093"
        text, hidden, by_key, missed, non_rt = report(recs, called, http, meta)

        # вызван -> не скрыт; обе перегрузки закрываются одним вызовом
        assert hidden == ["gpm.tnt_premier.DownloadsApi->getDownloadDevices"], hidden
        # класс знаком, метода в статике нет
        assert missed == ["ru.ivi.mapi.AuthApi->logout"], missed
        # чужие прокси в отчёт не лезут
        assert "com.other.Unrelated->ping" not in text
        # в список «вне Retrofit» попадает только вызов без retrofit в стеке
        assert len(non_rt) == 1 and non_rt[0]["url"] == "https://cdn.example/a.png"
        assert "versionCode=11134093" in text

    print("selfcheck ok")


if __name__ == "__main__":
    if "--selfcheck" in sys.argv:
        _selfcheck()
    else:
        main()
