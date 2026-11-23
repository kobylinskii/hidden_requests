"""Схемы примеров тел BFScan для записей статического среза."""
import argparse
import json
from collections import defaultdict
from pathlib import Path
from tempfile import NamedTemporaryFile

from diff import _METHOD, _REQUEST


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
                        row["schema"] = schema(json.loads(body))
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("--static", "--slice", "--out"):
        parser.add_argument(option, type=Path, required=True)
    args = parser.parse_args()
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
                output.write(json.dumps(result, ensure_ascii=False) + "\n")
            output.close()
            temporary.replace(args.out)
        finally:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
