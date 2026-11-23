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


def reject_non_json_constant(value):
    raise ValueError(f"Недопустимое значение JSON: {value}")


def parse_bfscan(md_path: Path) -> list:
    """Разбирает вывод BFScan. Формат: `**Method**: fqcn->name`, затем блок с
    сырым HTTP-запросом, первая строка которого `VERB /path?query HTTP/1.1`."""
    out, cls, name, source = [], None, None, None
    body_lines = None

    def finish_body():
        headers, separator, body = "\n".join(body_lines).partition("\n\n")
        content_type = next((line.split(":", 1)[1].strip() for line in headers.splitlines()
                             if line.lower().startswith("content-type:")), None)
        example = {"content_type": content_type, "has_example": bool(separator and body.strip())}
        if example["has_example"]:
            example["body_text"] = body
            try:
                example["template"] = json.loads(body, parse_constant=reject_non_json_constant)
            except ValueError:
                example["template_text"] = body
        out[-1]["bfscan"] = example

    for line in md_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if body_lines is not None:
            if line.strip() == "```":
                finish_body()
                body_lines = None
            else:
                body_lines.append(line)
            continue
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
                "declaration_id": len(out) + 1,
                "key": f"{cls}->{name}",
                "cls": cls,
                "method": name,
                "verb": r.group(1),
                "path": path,
                "query": query,
                "source": source,
            })
            body_lines = [line]
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
            raise ValueError(f"{path}:{n}: повреждённая запись JSON") from None
        t = ev.get("t")
        if t == "retrofit":
            called.add(f"{ev['cls']}->{ev['m']}")
        elif t == "http":
            http.append(ev)
        elif t == "meta":
            if meta and (not ev.get("versionCode") or
                         ev.get("package") != meta.get("package") or
                         str(ev["versionCode"]) != str(meta.get("versionCode"))):
                raise ValueError(f"{path}:{n}: несовместимые метаданные сессий")
            meta = ev
    return called, http, meta


def report(static, called, http, meta=None, verbose=False):
    # Один ключ может давать несколько записей: перегрузки метода отличаются
    # набором query-параметров, но в рантайме неразличимы. Схлопываем по ключу.
    by_key = defaultdict(list)
    for s in static:
        by_key[s["key"]].append(s)

    hidden_keys = sorted(k for k in by_key if k not in called)
    found_keys = sorted(k for k in by_key if k in called and len(by_key[k]) == 1)
    ambiguous = sorted(k for k in by_key if k in called and len(by_key[k]) > 1)
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
    w(f"Вызов с неоднозначным объявлением: {len(ambiguous)}")
    w(f"Вызвано в рантайме:                      {len(found_keys)}")
    pct = f" ({len(hidden_keys) / len(by_key) * 100:.1f}%)" if by_key else ""
    w(f"СКРЫТО (ни разу не вызвано):             {len(hidden_keys)}{pct}")
    # hook.js слой 1 ловит только Retrofit/Ktorfit-вызовы через java.lang.reflect.Proxy.
    # Если в рантайме не перехвачено НИ ОДНОГО ключа, а статика непуста — прокси-хук,
    # вероятно, не сработал (Ktorfit с codegen-бэкендом строит вызовы без Proxy, либо
    # retrofit2 переименован R8). Тогда ВСЕ ключи ложно выглядят скрытыми.
    if by_key and not called:
        w("")
        w("[!] ВНИМАНИЕ: в рантайме не перехвачено ни одного ключа класс->метод, а в")
        w("    статике они есть. hook.js слой 1 вешается на Proxy.newProxyInstance —")
        w("    Ktorfit (codegen без Proxy) или переименованный R8 retrofit2 он не ловит,")
        w("    и тогда весь список «скрытых» — артефакт непойманного слоя, а не результат.")
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
        w(f"НАБЛЮДАЛСЯ ВЫЗОВ МЕТОДА ({len(found_keys)})")
        w("-" * 78)
        for key in found_keys:
            for r in by_key[key]:
                w(f"  [FOUND] {key}  {r['verb']} {r['path']}")

    return "\n".join(lines), hidden_keys, by_key, missed_by_bfscan, non_retrofit


def main():
    ap = argparse.ArgumentParser(description="Сравнить каталог BFScan с трассой той же сборки")
    ap.add_argument("--apk", type=Path, help="APK для проверки сборки и разрешения DEX-дескрипторов")
    ap.add_argument("--static", required=True, type=Path, help="BFScan *_methods.md")
    ap.add_argument("--dynamic", required=True, type=Path, help="NDJSON от trace.py")
    ap.add_argument("--out", type=Path, help="куда сохранить сравнение в JSONL")
    ap.add_argument("-v", "--verbose", action="store_true", help="показать все объявления")
    args = ap.parse_args()

    from collections import Counter
    from types import SimpleNamespace
    from request_artifacts import sha256, write_rows
    from request_pipeline import compare_artifacts, publish

    try:
        if args.apk:
            from slice import load_apk
            build = sha256(args.apk)
            _, dx = load_apk(args.apk)
            rows, complete = compare_artifacts(
                SimpleNamespace(catalog=args.static, trace=args.dynamic), build, dx)
            if args.out:
                publish(args.out, ({"build": build, **row} for row in rows), build, complete)
        else:
            # Old catalogs are still readable for diagnostics. They have no
            # verified relation to the observed Android build or DEX methods.
            rows = [{**row, "status": "insufficient_data", "reason": "apk_required_for_comparison"}
                    for row in parse_bfscan(args.static)]
            if args.out:
                write_rows(args.out, rows)
    except (OSError, ValueError) as error:
        ap.error(str(error))

    counts = Counter(row["status"] for row in rows)
    print("Сравнение: " + ", ".join(f"{status}={counts[status]}" for status in
                                    ("observed", "not_observed", "insufficient_data")))
    if args.verbose:
        for row in rows:
            print(f"{row['status']:18} {row['key']} {row['verb']} {row['path']}")


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
