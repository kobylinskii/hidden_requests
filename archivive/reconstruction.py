"""Historical JSON reconstruction, invoked by the optional legacy CLI flags."""
from archivive.body_report import render_body
def slice_bodies(compared, dx, build, serializer):
    from archivive.body_data import body_variants

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



def run(args, build, parser):
    from collections import Counter
    from request_pipeline import read_checked_rows, compare_artifacts, publish
    from archivive.body_data import known_serializer
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
