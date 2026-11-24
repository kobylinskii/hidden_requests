"""Identities and atomic publication for independent scanner artifacts."""

import argparse
import hashlib
import json
from pathlib import Path
from tempfile import NamedTemporaryFile


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _write_bytes(path, chunks):
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with NamedTemporaryFile(dir=path.parent, mode="wb", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            for chunk in chunks:
                stream.write(chunk)
                digest.update(chunk)
            stream.close()
            temporary.chmod(0o644)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    return digest.hexdigest()


def write_rows(path, rows):
    return _write_bytes(path, ((json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
                               for row in rows))


def write_text(path, text):
    _write_bytes(path, [text.encode("utf-8")])


def catalog_metadata(catalog):
    return catalog.with_name(catalog.name + ".meta.json")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("apk", type=Path)
    parser.add_argument("catalog", type=Path)
    parser.add_argument("status", choices=("complete", "partial"))
    parser.add_argument("--source", type=Path, help="publish the catalog from this staged file")
    parser.add_argument("--analysis-mode", choices=("whole_apk", "per_dex"))
    args = parser.parse_args()
    metadata = {"build": sha256(args.apk), "status": args.status}
    if args.source:
        with args.source.open("rb") as stream:
            metadata["catalog_sha256"] = _write_bytes(args.catalog, iter(lambda: stream.read(1024 * 1024), b""))
    else:
        metadata["catalog_sha256"] = sha256(args.catalog)
    if args.analysis_mode:
        metadata.update(analysis_mode=args.analysis_mode, limitations=[])
        if args.analysis_mode == "per_dex":
            metadata.update(status="partial", fallback_reason="whole_apk_oom",
                            limitations=["cross_dex_type_resolution", "apk_resources_unavailable"])
    write_rows(catalog_metadata(args.catalog), [metadata])


if __name__ == "__main__":
    main()
