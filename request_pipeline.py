"""Compare an APK catalog with passive observations and render candidate bodies."""

import argparse
import hashlib
from collections import Counter
import json
import sys
from pathlib import Path

from body_report import render_body
from diff import parse_bfscan
from request_artifacts import catalog_metadata, sha256, write_rows


def read_trace(path, build):
    methods, legacy_keys, interfaces = set(), set(), set()
    stream_methods, stream_legacy, stream_interfaces = set(), set(), set()
    session = None
    complete = True
    matched_build = False
    pending = False

    def finish_evidence(identity_verified=True):
        if identity_verified:
            methods.update(stream_methods)
            legacy_keys.update(stream_legacy)
            interfaces.update(stream_interfaces)
        stream_methods.clear()
        stream_legacy.clear()
        stream_interfaces.clear()

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
                if kind == "retrofit" and isinstance(event.get("cls"), str) and isinstance(event.get("m"), str):
                    key = event["cls"] + "->" + event["m"]
                    descriptor = event.get("descriptor")
                    if isinstance(descriptor, str):
                        stream_methods.add((key, descriptor))
                    else:
                        stream_legacy.add(key)
                elif kind == "coverage" and isinstance(event.get("interface"), str):
                    stream_interfaces.add(event["interface"])
            elif not pending:
                complete = False
    finish_evidence()
    return {"complete": complete and matched_build and not pending,
            "methods": methods, "legacy_keys": legacy_keys, "interfaces": interfaces}


def compare(declarations, trace, catalog_complete):
    rows = []
    for entry in declarations:
        key, descriptor = entry["key"], entry.get("descriptor")
        if descriptor and (key, descriptor) in trace["methods"]:
            status, reason = "observed", None
        elif not descriptor:
            status, reason = "insufficient_data", "dex_identity_unresolved"
        elif not catalog_complete or not trace["complete"]:
            status, reason = "insufficient_data", "artifact_incomplete_or_unverified"
        elif key in trace["legacy_keys"] or entry.get("framework") != "retrofit" or entry["cls"] not in trace["interfaces"]:
            status, reason = "insufficient_data", "method_coverage_unverified"
        else:
            status, reason = "not_observed", None
        rows.append({**entry, "status": status, "reason": reason})
    return rows


def load_artifact(path, build):
    try:
        meta = json.loads(catalog_metadata(path).read_text(encoding="utf-8"))
        valid = (isinstance(meta, dict) and meta.get("build") == build
                 and meta.get("catalog_sha256") == sha256(path))
    except (OSError, ValueError):
        return None
    return meta if valid else None


def read_checked_rows(path, build):
    try:
        meta = json.loads(catalog_metadata(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(f"{path}: нет подтверждённых метаданных сборки") from error
    if not isinstance(meta, dict) or meta.get("build") != build:
        raise ValueError(f"{path}: нет подтверждённых метаданных сборки")
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
    return rows, meta.get("status") == "complete"


def checked_rows(path, build):
    rows, _ = read_checked_rows(path, build)
    yield from rows


def publish(path, rows, build, complete):
    digest = write_rows(path, rows)
    write_rows(catalog_metadata(path), [{"build": build, "catalog_sha256": digest,
                                         "status": "complete" if complete else "partial"}])


def compare_artifacts(args, build, dx):
    from body_data import bind_declaration

    static = load_artifact(args.catalog, build)
    catalog_complete = bool(static and static.get("status") == "complete")
    if not args.catalog.is_file():
        raise ValueError(f"{args.catalog}: каталог BFScan отсутствует")
    declarations = [bind_declaration(dx, row) for row in parse_bfscan(args.catalog)]
    trace = (read_trace(args.trace, build) if args.trace.is_file() else
             {"complete": False, "methods": set(), "legacy_keys": set(), "interfaces": set()})
    if static:
        compared = compare(declarations, trace, catalog_complete)
    else:
        compared = [{**row, "status": "insufficient_data", "reason": "catalog_identity_unverified"}
                    for row in declarations]
    return compared, catalog_complete and trace["complete"]


def slice_bodies(compared, dx, build, serializer):
    from body_data import body_variants

    for row in compared:
        if row["status"] != "not_observed":
            continue
        identity = {k: row[k] for k in ("declaration_id", "key", "descriptor", "verb", "path")}
        yield {**identity, "build": build, "serializer": serializer, "bfscan": row.get("bfscan"),
               "body_argument": row.get("body_argument"), "variants": body_variants(dx, row, serializer)}


def field_writes(graph):
    nodes = {node["id"]: node for node in graph["nodes"]}
    for allocation in nodes.values():
        fields = {field["field"]: field for field in allocation.get("declared_fields", [])}
        for write in allocation.get("local_writes_and_calls", []):
            if "field" not in write:
                continue
            field = write["field"]
            name = field.partition("->")[2].partition(" ")[0]
            source = nodes.get(write["source"], {"kind": "unknown", "reason": "analysis_limit"})
            seen = set()
            while source["kind"] == "alias" and source["id"] not in seen:
                seen.add(source["id"])
                source = nodes.get(source["inputs"][0], {"kind": "unknown", "reason": "analysis_limit"})
            yield {"field": field, "allocation_node": allocation["id"], "offset": write["offset"],
                   "source_node": write["source"], "name_annotations": fields.get(name, {}).get("name_annotations", {}),
                   "source": source}


def body_rows(data_slices):
    for row in data_slices:
        rendered = []
        for variant in row["variants"]:
            value = render_body(variant["model"]) if "model" in variant else {
                "status": variant["status"], "reason": variant.get("reason"),
                "unknown_paths": [""] if variant["status"] in {"unsupported", "partial"} else [],
            }
            if isinstance(value.get("body"), dict) and isinstance((row.get("bfscan") or {}).get("template"), dict):
                actual = value["body"].keys()
                template = row["bfscan"]["template"].keys()
                value["template_fields"] = {"common": sorted(actual & template),
                                            "only_bfscan": sorted(template - actual),
                                            "only_dto": sorted(actual - template)}
            if "parameter_slice" in variant:
                value["parameter_slice"] = variant["parameter_slice"]
                value["field_writes"] = list(field_writes(variant["parameter_slice"]))
            rendered.append({**value, "call_sites": variant["call_sites"],
                             "guards": variant.get("guards", []),
                             "unresolved_guards": variant.get("unresolved_guards", [])})
        yield {**row, "variants": rendered}


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
               "source": "bfscan", "content_type": example.get("content_type"),
               "status": "example" if body is not None else "no_bfscan_example", "body": body}


def report_bfscan(args, build):
    from slice import load_apk

    dx = None
    if args.comparison_in:
        compared, complete = read_checked_rows(args.comparison_in, build)
    else:
        if not (args.catalog and args.trace):
            raise ValueError("нужны --catalog и --trace либо --comparison-in")
        _, dx = load_apk(args.apk)
        compared, complete = compare_artifacts(args, build, dx)
        for row in compared:
            row["build"] = build
    if not args.comparison_in or args.comparison_in.resolve() != args.comparison.resolve():
        publish(args.comparison, compared, build, complete)
    records = list(bfscan_body_rows(compared))
    publish(args.out, records, build, complete)
    if args.request_slice:
        from body_data import request_slice

        hidden = [row for row in compared if row["status"] == "not_observed"]
        if hidden and dx is None:
            _, dx = load_apk(args.apk)
        slices = ({**{k: row[k] for k in ("build", "declaration_id", "key", "descriptor", "verb", "path")},
                   "body_argument": row.get("body_argument"), **request_slice(dx, row)}
                  for row in hidden)
        publish(args.request_slice, slices, build, complete)
    for row in records:
        target = row["path"] + ("?" + row["query"] if row.get("query") else "")
        print(f"{row['verb']} {target}  [{row['key']}]")
        print(row["body"] if row["body"] is not None else "(в BFScan нет примера тела)")
        print()
    print(f"Скрытых объявлений: {len(records)}. Статус прогона: "
          f"{'complete' if complete else 'partial'}.", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("apk", "comparison", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("catalog", "trace", "comparison-in", "slice-in", "data-slice", "request-slice"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--serializer", choices=("auto", "gson"), default="auto")
    args = parser.parse_args()
    if args.request_slice and args.data_slice:
        parser.error("--request-slice используется в режиме отчёта BFScan")
    build = sha256(args.apk)
    try:
        if not args.data_slice:
            if args.slice_in:
                parser.error("--slice-in требует --data-slice")
            report_bfscan(args, build)
            return
        from body_data import known_serializer
        from slice import load_apk
        if args.slice_in:
            data_slices, complete = read_checked_rows(args.slice_in, build)
        else:
            if not args.comparison_in and not (args.catalog and args.trace):
                parser.error("передайте --catalog и --trace либо артефакт предыдущего этапа")
            _, dx = load_apk(args.apk)
            if args.comparison_in:
                compared, complete = read_checked_rows(args.comparison_in, build)
            else:
                compared, complete = compare_artifacts(args, build, dx)
            publish(args.comparison, ({"build": build, **row} for row in compared), build, complete)
            serializer = known_serializer(dx) if args.serializer == "auto" else args.serializer
            data_slices = list(slice_bodies(compared, dx, build, serializer))
            counts = Counter(row["status"] for row in compared)
            print("Сравнение: " + ", ".join(f"{status}={counts[status]}" for status in
                                            ("observed", "not_observed", "insufficient_data")))

        publish(args.data_slice, data_slices, build, complete)
        publish(args.out, body_rows(data_slices), build, complete)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
