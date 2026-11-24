"""Compare an APK catalog with passive observations and render candidate bodies."""

import argparse
import hashlib
import gc
from collections import Counter
import json
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from diff import parse_bfscan
from request_artifacts import catalog_metadata, sha256, write_rows, write_text


@contextmanager
def progress_stage(label):
    started = time.monotonic()
    stopped = threading.Event()

    def report():
        while not stopped.wait(10):
            print(f"[сканер] {label} — {time.monotonic() - started:.0f} с",
                  file=sys.stderr, flush=True)

    print(f"[сканер] {label}", file=sys.stderr, flush=True)
    worker = threading.Thread(target=report, daemon=True)
    worker.start()
    try:
        yield
    except BaseException:
        print(f"[сканер] Этап прерван: {label}", file=sys.stderr, flush=True)
        raise
    else:
        print(f"[сканер] Готово: {label} — {time.monotonic() - started:.1f} с",
              file=sys.stderr, flush=True)
    finally:
        stopped.set()
        worker.join()


def read_trace(path, build):
    methods, legacy_keys, interfaces = set(), set(), set()
    stream_methods, stream_legacy, stream_interfaces = set(), set(), set()
    ambiguous_methods, stream_ambiguous = set(), set()
    legacy_coverage, verified_owners = set(), set()
    session = None
    complete = True
    matched_build = False
    pending = False

    def finish_evidence(identity_verified=True):
        if identity_verified:
            methods.update(stream_methods)
            legacy_keys.update(stream_legacy)
            interfaces.update(stream_interfaces)
            # Old agents emitted bare coverage on a call. Corroborate its
            # interface with a method from a known Retrofit handler in this session.
            interfaces.update(legacy_coverage & verified_owners)
            ambiguous_methods.update(stream_ambiguous)
        stream_methods.clear()
        stream_legacy.clear()
        stream_interfaces.clear()
        stream_ambiguous.clear()
        legacy_coverage.clear()
        verified_owners.clear()

    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except ValueError:
                complete = False
                continue
            if not isinstance(event, dict):
                complete = False
                continue
            kind = event.get("t")
            if kind == "meta":
                complete &= not pending
                finish_evidence()
                session = event.get("session")
                pending = True
                matches = event.get("build") == build
                matched_build |= matches
                complete &= bool(session and matches)
            elif kind == "end":
                verified = (pending and event.get("session") == session
                            and ("build" not in event or event["build"] == build)
                            and "installed_build_changed" not in (event.get("reasons") or []))
                complete &= (verified
                             and event.get("status") == "complete")
                finish_evidence(verified)
                pending = False
            elif pending and matches:
                handler = event.get("handler")
                retrofit = isinstance(handler, str) and handler.startswith("retrofit2.Retrofit$")
                if kind == "retrofit" and isinstance(event.get("cls"), str) and isinstance(event.get("m"), str):
                    key = event["cls"] + "->" + event["m"]
                    descriptor = event.get("descriptor")
                    method_call = event.get("observation", "method_call") == "method_call"
                    if retrofit and method_call:
                        verified_owners.add(event["cls"])
                    if not isinstance(descriptor, str) or not descriptor:
                        stream_legacy.add(key)
                    elif retrofit and method_call:
                        stream_methods.add((key, descriptor))
                    else:
                        # Old agents deduplicated *all* handlers on the same
                        # signature. A local stub could mask a later genuine call.
                        stream_ambiguous.add((key, descriptor))
                elif kind == "coverage" and isinstance(event.get("interface"), str):
                    if retrofit:
                        stream_interfaces.add(event["interface"])
                    elif handler is None:
                        legacy_coverage.add(event["interface"])
            elif not pending:
                complete = False
    finish_evidence()
    return {"complete": complete and matched_build and not pending,
            "methods": methods, "legacy_keys": legacy_keys, "interfaces": interfaces,
            "ambiguous_methods": ambiguous_methods}


def compare(declarations, trace, catalog_complete):
    rows = []
    for entry in declarations:
        key, descriptor = entry["key"], entry.get("descriptor")
        observed = bool(descriptor) and (key, descriptor) in trace["methods"]
        caveats = []
        if not observed:
            if not descriptor:
                caveats.append("dex_identity_unresolved")
            if not catalog_complete or not trace["complete"]:
                caveats.append("artifact_incomplete_or_unverified")
            if (entry.get("framework") != "retrofit" or entry["cls"] not in trace["interfaces"]
                    or key in trace["legacy_keys"] or (key, descriptor) in trace.get("ambiguous_methods", ())):
                caveats.append("method_coverage_unverified")
        row = {**entry, "status": "observed" if observed else "not_observed",
               "confidence_caveats": caveats}
        row.pop("reason", None)
        rows.append(row)
    return rows


def load_artifact(path, build):
    try:
        meta = json.loads(catalog_metadata(path).read_text(encoding="utf-8"))
        valid = (isinstance(meta, dict) and meta.get("build") == build
                 and meta.get("catalog_sha256") == sha256(path))
    except (OSError, ValueError):
        return None
    return meta if valid else None


def read_checked_rows(path, build, expected_type=None):
    try:
        meta = json.loads(catalog_metadata(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(f"{path}: нет подтверждённых метаданных сборки") from error
    if not isinstance(meta, dict) or meta.get("build") != build:
        raise ValueError(f"{path}: нет подтверждённых метаданных сборки")
    kind = meta.get("artifact_type")
    if expected_type and kind is not None and kind != expected_type:
        raise ValueError(f"{path}: ожидался артефакт {expected_type}, получен {kind}")
    if expected_type and meta.get("status") not in ("complete", "partial"):
        raise ValueError(f"{path}: неизвестный статус артефакта")
    rows = []
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for line in stream:
            digest.update(line)
            if line.strip():
                row = json.loads(line)
                if not isinstance(row, dict) or row.get("build") != build:
                    raise ValueError(f"{path}: запись относится к другой сборке")
                rows.append(row)
    if digest.hexdigest() != meta.get("catalog_sha256"):
        raise ValueError(f"{path}: контрольная сумма не совпадает с метаданными")
    if expected_type and not rows and kind is None:
        raise ValueError(f"{path}: тип пустого артефакта не подтверждён")
    if expected_type == "hidden":
        ids = set()
        accepted = []
        for row in rows:
            status = row.get("status")
            if status not in ("observed", "not_observed"):
                print(f"[предупреждение] {path}: пропущен неизвестный статус {status!r} "
                      f"объявления {row.get('declaration_id')!r}", file=sys.stderr)
                continue
            descriptor = row.get("descriptor")
            caveats = row.get("confidence_caveats", [])
            if (type(row.get("declaration_id")) is not int or row["declaration_id"] in ids
                    or not all(isinstance(row.get(k), str) for k in ("cls", "method", "key", "verb", "path"))
                    or row["key"] != row["cls"] + "->" + row["method"]
                    or (descriptor is not None and not isinstance(descriptor, str))
                    or (status == "observed" and (not descriptor or caveats))
                    or not isinstance(caveats, list) or not all(isinstance(c, str) for c in caveats)):
                raise ValueError(f"{path}: некорректное объявление в списке сравнения")
            ids.add(row["declaration_id"])
            row.pop("reason", None)
            row["descriptor"] = descriptor or None
            row["confidence_caveats"] = caveats
            accepted.append(row)
        rows = accepted
    return rows, meta.get("status") == "complete"


def checked_rows(path, build):
    rows, _ = read_checked_rows(path, build)
    yield from rows


def publish(path, rows, build, complete, *, artifact_type=None, run_id=None):
    digest = write_rows(path, rows)
    metadata = {"build": build, "catalog_sha256": digest, "status": "complete" if complete else "partial"}
    if artifact_type:
        metadata.update(artifact_type=artifact_type, run_id=run_id)
    write_rows(catalog_metadata(path), [metadata])


def compare_artifacts(args, build, dx):
    from body_data import bind_declaration

    static = load_artifact(args.catalog, build)
    catalog_complete = bool(static and static.get("status") == "complete")
    if not args.catalog.is_file():
        raise ValueError(f"{args.catalog}: каталог BFScan отсутствует")
    declarations = [bind_declaration(dx, row) for row in parse_bfscan(args.catalog)]
    trace = (read_trace(args.trace, build) if args.trace.is_file() else
             {"complete": False, "methods": set(), "legacy_keys": set(), "interfaces": set()})
    return compare(declarations, trace, catalog_complete), catalog_complete and trace["complete"]



def bfscan_body_rows(compared):
    for row in compared:
        if row["status"] != "not_observed":
            continue
        example = row.get("bfscan") or {}
        body = example.get("body_text", example.get("template_text"))
        if body is None and "template" in example:
            # Older verified comparison artifacts stored only parsed JSON.
            body = json.dumps(example["template"], ensure_ascii=False)
        yield {**{k: row.get(k) for k in ("build", "declaration_id", "key", "descriptor",
                                          "verb", "path", "query")},
               "confidence_caveats": row.get("confidence_caveats", []),
               "source": "bfscan", "content_type": example.get("content_type"),
               "status": "example" if body is not None else "no_bfscan_example", "body": body}


def print_statistics(compared, bodies):
    counts = Counter(row["status"] for row in compared)
    total = len(compared)
    print(f"[статистика] Статических HTTP-объявлений: {total}; "
          f"уникальных класс->метод: {len({row['key'] for row in compared})}", file=sys.stderr, flush=True)
    for status, title in (("observed", "Наблюдались"), ("not_observed", "Скрытые в этой сессии")):
        amount = counts[status]
        percent = amount / total * 100 if total else 0
        print(f"[статистика] {title}: {amount} ({percent:.1f}%)", file=sys.stderr, flush=True)
    caveat_counts = Counter(c for row in bodies for c in set(row["confidence_caveats"]))
    clean = sum(not row["confidence_caveats"] for row in bodies)
    details = ", ".join(f"{c}={n}" for c, n in sorted(caveat_counts.items()))
    print(f"[статистика] Из {len(bodies)} скрытых без оговорок: {clean}; "
          f"с оговорками: {len(bodies) - clean}" + (f" ({details}; категории пересекаются)" if details else ""),
          file=sys.stderr, flush=True)
    with_body = sum(row["body"] is not None for row in bodies)
    print(f"[статистика] Скрытые с телом BFScan: {with_body}; "
          f"без примера тела: {len(bodies) - with_body}", file=sys.stderr, flush=True)
    verbs = Counter(row["verb"] for row in bodies)
    print("[статистика] Методы скрытых запросов: " +
          (", ".join(f"{verb}={count}" for verb, count in sorted(verbs.items())) or "0"),
          file=sys.stderr, flush=True)


GUARD_COUNTS = ("guard_count", "guard_count_coroutine", "guard_count_framework", "guard_count_third_party_sdk", "depth")
GUARD_FLAGS = ("reached", "activation_exact", "activation_exact_modulo_allocation", "inconclusive")
GUARD_COSTS = ("activation_cost", "best_known_complete_cost", "activation_cost_modulo_allocation")
GUARD_FIELDS = (*GUARD_COUNTS, *GUARD_FLAGS, *GUARD_COSTS, "first_uncertain_hop", "entry_evidence", "notes")


def read_guard_metrics(path, build, hidden):
    cached, complete = read_checked_rows(path, build, "reasons")
    remaining = {(r["declaration_id"], r["key"], r["descriptor"]) for r in hidden}
    metrics = {}
    for row in cached:
        identity = (row.get("declaration_id"), row.get("key"), row.get("descriptor"))
        if identity not in remaining:
            raise ValueError(f"{path}: состав скрытых объявлений отличается")
        remaining.remove(identity)
        scope = "dex_descriptor" if row.get("descriptor") else "unresolved"
        if row.get("analysis_scope") != scope or not all(k in row for k in (*GUARD_FIELDS, "call_site_count")):
            raise ValueError(f"{path}: несовместимый отчёт о стражах. Повторите анализ без REASONS_IN")
        entry = {k: row[k] for k in (*GUARD_FIELDS, "call_site_count")}
        counts = [entry[k] for k in (*GUARD_COUNTS, "call_site_count")]
        counts.extend(entry[k] for k in (*GUARD_COSTS, "first_uncertain_hop") if entry[k] is not None)
        valid_counts = all(type(n) is int and n >= 0 for n in counts)
        valid_flags = all(type(entry[k]) is bool for k in GUARD_FLAGS)
        notes = entry["notes"]
        valid_notes = isinstance(notes, list) and all(isinstance(t, str) for t in notes)
        evidence = entry["entry_evidence"]
        valid_evidence = (isinstance(evidence, dict) and evidence.keys() == {"ui", "background"}
                          and all(v in ("not_found", "possible", "modulo_allocation", "resolved")
                                  for v in evidence.values()))
        if not (valid_counts and valid_flags and valid_notes and valid_evidence):
            raise ValueError(f"{path}: неверные значения метрик стражей объявления {identity[0]}")
        lower, best, modulo = (entry[k] for k in GUARD_COSTS)
        if (entry["reached"] != bool(entry["call_site_count"])
                or (best is not None and (lower is None or lower > best))
                or (modulo is not None and (lower is None or lower > modulo))
                or (best is not None and (modulo is None or modulo > best))
                or (entry["activation_exact_modulo_allocation"] and (lower is None or lower != modulo))
                or (entry["activation_exact"] and not entry["activation_exact_modulo_allocation"])
                or (not entry["reached"] and lower is not None)
                or (entry["activation_exact"] and (lower is None or lower != best))):
            raise ValueError(f"{path}: противоречивые метрики стражей объявления {identity[0]}")
        signature = (row["key"], row["descriptor"])
        if signature in metrics and metrics[signature] != entry:
            raise ValueError(f"{path}: противоречащие оценки одного ключа")
        metrics[signature] = entry
    if remaining:
        raise ValueError(f"{path}: в отчёте отсутствуют скрытые объявления")
    return metrics, complete


def analyze_guards(args, build, complete, hidden, direct_sites, apk_obj, dx):
    from slice import report, slice_key

    metrics = {}
    unresolved = {**dict.fromkeys(GUARD_COUNTS, 0), **dict.fromkeys(GUARD_FLAGS, False),
                  "inconclusive": True, **dict.fromkeys((*GUARD_COSTS, "first_uncertain_hop")),
                  "notes": ["dex_identity_unresolved"], "call_site_count": 0,
                  "entry_evidence": {"ui": "not_found", "background": "not_found"}}
    if args.reasons_in:
        metrics, cache_complete = read_guard_metrics(args.reasons_in, build, hidden)
        complete = complete and cache_complete

    package = apk_obj.get_package()
    records = []
    key_count = len({(r["key"], r["descriptor"]) for r in hidden if r["descriptor"]})
    for row in hidden:
        key = row["key"]
        signature = (key, row["descriptor"])
        if row["descriptor"] and signature not in metrics:
            print(f"[стражи {len(metrics) + 1}/{key_count}] {key}", file=sys.stderr, flush=True)
            analysis = slice_key(dx, key, descriptor=row["descriptor"], include_arguments=False, package=package)
            metrics[signature] = {k: analysis[k] for k in GUARD_FIELDS}
            metrics[signature]["call_site_count"] = len(analysis["call_sites"])
        entry = metrics[signature] if row["descriptor"] else unresolved
        scope = "dex_descriptor" if row["descriptor"] else "unresolved"
        provenance = direct_sites[row["declaration_id"]]
        if provenance is not None and provenance != entry["reached"]:
            print(f"[предупреждение] {key} {row['descriptor']} (объявление {row['declaration_id']}): "
                  f"место вызова в срезе аргументов={provenance}, в анализе стражей={entry['reached']}. "
                  "Ветви анализа расходятся по одному DEX-дескриптору.",
                  file=sys.stderr, flush=True)
        records.append({**{k: row[k] for k in ("build", "declaration_id", "key", "descriptor")},
                        "analysis_scope": scope, "declaration_has_call_sites": provenance, **entry})

    meta = {"package": package, "versionName": apk_obj.get_androidversion_name(),
            "versionCode": apk_obj.get_androidversion_code(), "build": build,
            "status": "complete" if complete else "partial"}
    summary = report(records, meta=meta)
    publish(args.reasons, records, build, complete, artifact_type="reasons", run_id=args.run_id)
    write_text(args.reasons.with_suffix(".report.txt"), summary)


def report_bfscan(args, build):
    from slice import load_apk

    apk_obj = dx = None
    if args.comparison_in:
        with progress_stage("Проверка готового списка объявлений"):
            compared, complete = read_checked_rows(args.comparison_in, build, "hidden")
    else:
        if not (args.catalog and args.trace):
            raise ValueError("нужны --catalog и --trace либо --comparison-in")
        with progress_stage("Загрузка APK, разбор DEX и построение связей методов"):
            apk_obj, dx = load_apk(args.apk)
        with progress_stage("Сравнение BFScan с динамической трассой"):
            compared, complete = compare_artifacts(args, build, dx)
        for row in compared:
            row["build"] = build
    publish(args.comparison, compared, build, complete, artifact_type="hidden", run_id=args.run_id)
    records = list(bfscan_body_rows(compared))
    print_statistics(compared, records)
    publish(args.out, records, build, complete, artifact_type="bodies", run_id=args.run_id)
    for row in records:
        target = row["path"] + ("?" + row["query"] if row.get("query") else "")
        print(f"{row['verb']} {target}  [{row['key']}]")
        print(row["body"] if row["body"] is not None else "(в BFScan нет примера тела)")
        print()
    sys.stdout.flush()
    print(f"[сканер] Список и тела BFScan подготовлены. Скрытых объявлений: {len(records)}. "
          f"Статус прогона: {'complete' if complete else 'partial'}.", file=sys.stderr, flush=True)
    if args.request_slice:
        from body_data import request_slice

        hidden = [row for row in compared if row["status"] == "not_observed"]
        if hidden and dx is None:
            with progress_stage("Загрузка APK, разбор DEX и построение связей методов"):
                apk_obj, dx = load_apk(args.apk)
        direct_sites = {}

        def slices():
            total = len(hidden)
            counts = Counter()
            site_count = 0
            for index, row in enumerate(hidden, 1):
                print(f"[срез {index}/{total}] {row['key']}", file=sys.stderr, flush=True)
                result = request_slice(dx, row)
                direct_sites[row["declaration_id"]] = (None if result["status"] == "dex_method_unavailable"
                                                       else bool(result["call_sites"]))
                counts[result["status"]] += 1
                site_count += len(result["call_sites"])
                print(f"[срез {index}/{total}] Результат: {result['status']}; "
                      f"мест вызова: {len(result['call_sites'])}", file=sys.stderr, flush=True)
                yield {**{k: row[k] for k in ("build", "declaration_id", "key", "descriptor", "verb", "path")},
                       "body_argument": row.get("body_argument"), **result}
            print(f"[статистика] Срезов: {sum(counts.values())}; мест вызова: {site_count}; " +
                  (", ".join(f"{status}={count}" for status, count in sorted(counts.items())) or "0"),
                  file=sys.stderr, flush=True)

        with progress_stage(f"Обратные срезы для {len(hidden)} скрытых объявлений"):
            publish(args.request_slice, slices(), build, complete, artifact_type="request-slice", run_id=args.run_id)
        with progress_stage("Проверка готового отчёта о стражах" if args.reasons_in else
                            f"Анализ стражей для {len(hidden)} скрытых объявлений"):
            if apk_obj is None:  # Пустой готовый список: для шапки достаточно манифеста.
                from androguard.core.apk import APK
                apk_obj = APK(str(args.apk))
            analyze_guards(args, build, complete, hidden, direct_sites, apk_obj, dx)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("apk", "comparison", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("catalog", "trace", "comparison-in", "slice-in", "data-slice", "request-slice",
                 "reasons", "reasons-in"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--serializer", choices=("auto", "gson"), default="auto")
    args = parser.parse_args()
    if (args.reasons or args.reasons_in) and not args.request_slice:
        parser.error("--reasons и --reasons-in требуют --request-slice")
    if args.request_slice and not args.reasons:
        prefix = args.request_slice.stem.removesuffix(".request-slice")
        args.reasons = args.request_slice.with_name(prefix + ".reasons.jsonl")
    if args.request_slice and args.data_slice:
        parser.error("--request-slice используется в режиме отчёта BFScan")
    build = sha256(args.apk)
    try:
        if not args.data_slice:
            if args.slice_in:
                parser.error("--slice-in требует --data-slice")
            from report_publication import stage_reports
            with stage_reports(args) as staged:
                report_bfscan(staged, build)
            return
        from archivive.reconstruction import run
        run(args, build, parser)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
    print("[сканер] Обработка завершена, результаты сохранены.", file=sys.stderr, flush=True)
    # Androguard holds millions of cyclic references. After successful CLI
    # completion the OS releases this memory; skip its final cyclic GC pass.
    gc.freeze()
