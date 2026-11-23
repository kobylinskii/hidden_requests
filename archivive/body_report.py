"""Схемы примеров тел BFScan для записей статического среза."""
import argparse
import json
from collections import defaultdict
from pathlib import Path
from tempfile import NamedTemporaryFile

from diff import _METHOD, _REQUEST


def render_body(model):
    """Render the proposed JSON and retain JSON Pointers for unknown values."""
    unknown_paths = []

    def render(node, path):
        kind = node["kind"]
        if kind == "unknown":
            unknown_paths.append(path)
            return None
        if kind == "value":
            return node["value"]
        if kind == "array":
            return [render(item, f"{path}/{index}") for index, item in enumerate(node["items"])]
        fields = {}
        for name, field in node["fields"].items():
            child = path + "/" + name.replace("~", "~0").replace("/", "~1")
            value = render(field, child)
            if field["kind"] != "unknown":
                fields[name] = value
        return fields

    body = render(model, "")
    result = {"status": "partial" if unknown_paths else "complete",
              "unknown_paths": unknown_paths}
    if model["kind"] != "unknown":
        result["body"] = body
    return result


def schema(value):
    if isinstance(value, dict):
        return {"type": "object", "properties": {key: schema(item) for key, item in value.items()}}
    if isinstance(value, list):
        variants = []
        for item in value:
            shape = schema(item)
            if shape not in variants:
                variants.append(shape)
        items = {} if not variants else variants[0] if len(variants) == 1 else {"anyOf": variants}
        return {"type": "array", "items": items}
    types = {str: "string", bool: "boolean", int: "integer", float: "number", type(None): "null"}
    return {"type": types[type(value)]}


def placeholder_body(value):
    """Build an example with the same JSON types and structure as the BFScan sample."""
    if isinstance(value, dict):
        return {key: placeholder_body(item) for key, item in value.items()}
    if isinstance(value, list):
        return [placeholder_body(item) for item in value]
    placeholders = {str: "<unknown>", bool: False, int: 0, float: 0.0, type(None): None}
    return placeholders[type(value)]


def declarations(path):
    by_key = defaultdict(list)
    key = None
    block = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() == "```":
            if block is None:
                block = []
                continue
            if key and block and _REQUEST.fullmatch(block[0]):
                headers, _, body = "\n".join(block).partition("\n\n")
                method, target, _ = block[0].split()
                row = {"verb": method, "target": target}
                content_type = next((line.partition(":")[2].strip().lower()
                                     for line in headers.splitlines()[1:]
                                     if line.lower().startswith("content-type:")), "")
                if not body.strip():
                    row["status"] = "no_example_body"
                elif content_type and "json" not in content_type:
                    row["status"] = "non_json"
                else:
                    try:
                        row["body"] = json.loads(body)
                        row["schema"] = schema(row["body"])
                        row["example_body"] = placeholder_body(row["body"])
                        row["example_source"] = "typed_placeholders_from_bfscan"
                        row["status"] = "example_schema"
                    except ValueError:
                        row["status"] = "unparsed"
                by_key[key].append(row)
            block = None
        elif block is not None:
            block.append(line)
        elif match := _METHOD.fullmatch(line):
            key = "->".join(match.groups())
    return by_key


def saved_attempts(path):
    """Индекс снимков одного явно выбранного прогона по ключу среза."""
    by_key = defaultdict(list)
    with path.open(encoding="utf-8") as records:
        for line_number, line in enumerate(records, 1):
            if not line.strip():
                continue
            record = json.loads(line)
            key = record.get("key")
            if not key:
                continue
            attempt = {"line": line_number, "method_reached": record.get("reached"), "stages": []}
            for stage in record.get("stages", []):
                request = stage.get("request") or {}
                entry = {"stage": stage.get("stage"), "method_reached": stage.get("fired"),
                         "snapshot_matched": False, "body_status": "no_matched_snapshot",
                         "response_observed": False,
                         "exception_count": len(stage.get("exceptions") or [])}
                if request.get("matched") and request.get("key", key) == key:
                    response = request.get("response") or {}
                    entry.update(snapshot_matched=True, capture_source=request.get("source"),
                                 response_observed=bool(response), http_status=response.get("status"))
                    raw = request.get("body")
                    if raw is None:
                        entry["body_status"] = "missing"
                    elif raw == "":
                        entry["body_status"] = "empty"
                    elif raw.startswith(("<unreadable>", "<proto ")):
                        entry["body_status"] = "capture_marker"
                    else:
                        try:
                            entry["body"] = json.loads(raw)
                            entry["body_status"] = "json"
                        except ValueError:
                            entry["body_status"] = "non_json_or_incomplete"
                attempt["stages"].append(entry)
            by_key[key].append(attempt)
    return by_key


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("--static", "--slice", "--out"):
        parser.add_argument(option, type=Path, required=True)
    parser.add_argument("--activation", type=Path, help="сохранённый журнал вызовов для этой сборки")
    args = parser.parse_args()
    attempts = saved_attempts(args.activation) if args.activation else {}
    catalog = declarations(args.static) if args.static.exists() else {}
    with args.slice.open(encoding="utf-8") as records, NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=args.out.parent, delete=False
    ) as output:
        temporary = Path(output.name)
        try:
            for line in records:
                if not line.strip():
                    continue
                record = json.loads(line)
                if "key" not in record:
                    continue
                variants = catalog.get(record["key"], [])
                result = {"key": record["key"], "call_sites": record.get("call_sites", []),
                          "status": "declared" if variants else "missing_declaration",
                          "variants": variants}
                if args.activation:
                    result["activation_log"] = args.activation.name
                    result["attempts"] = attempts.get(record["key"], [])
                output.write(json.dumps(result, ensure_ascii=False) + "\n")
            output.close()
            temporary.replace(args.out)
        finally:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
