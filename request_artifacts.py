"""Identities and atomic publication for independent scanner artifacts."""

import argparse
import hashlib
import json
from pathlib import Path
from tempfile import NamedTemporaryFile


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_rows(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with NamedTemporaryFile(dir=path.parent, mode="wb", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            for row in rows:
                line = (json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
                stream.write(line)
                digest.update(line)
            stream.close()
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    return digest.hexdigest()


def catalog_metadata(catalog):
    return catalog.with_name(catalog.name + ".meta.json")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("apk", type=Path)
    parser.add_argument("catalog", type=Path)
    parser.add_argument("status", choices=("complete", "partial"))
    args = parser.parse_args()
    write_rows(catalog_metadata(args.catalog), [{
        "build": sha256(args.apk),
        "catalog_sha256": sha256(args.catalog),
        "status": args.status,
    }])


if __name__ == "__main__":
    main()
