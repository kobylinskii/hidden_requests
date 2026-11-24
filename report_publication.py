"""Publish related reports through one POSIX directory pointer."""
from argparse import Namespace
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import shutil
from uuid import uuid4

from request_artifacts import catalog_metadata, sha256, write_rows


def _point(link, target):
    temporary = link.with_name("." + uuid4().hex)
    try:
        temporary.symlink_to(target)
        temporary.replace(link)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def stage_reports(args):
    """Keep public filenames stable while staging a complete report generation."""
    outputs = {"comparison": "hidden.jsonl", "out": "bodies.jsonl"}
    if args.request_slice:
        outputs.update(request_slice="request-slice.jsonl", reasons="reasons.jsonl")
    paths = {}
    for field, filename in outputs.items():
        output = getattr(args, field)
        paths[filename] = output
        paths[filename + ".meta.json"] = catalog_metadata(output)
    if args.request_slice:
        paths["reasons.report.txt"] = args.reasons.with_suffix(".report.txt")
    prefix = args.comparison.stem.removesuffix(".hidden")
    paths["run.json"] = args.comparison.with_name(prefix + ".run.json")
    if len({path.resolve() for path in paths.values()}) != len(paths):
        raise ValueError("пути выходных отчётов пересекаются")

    protected_inputs = (args.apk, args.catalog, args.trace, args.comparison_in, args.reasons_in)
    for source in filter(None, protected_inputs):
        allowed = set()
        if source == args.comparison_in:
            allowed.update(("hidden.jsonl", "hidden.jsonl.meta.json"))
        if source == args.reasons_in:
            allowed.update(("reasons.jsonl", "reasons.jsonl.meta.json"))
        protected = {source.resolve(), catalog_metadata(source).resolve()}
        if any(name not in allowed and path.resolve() in protected for name, path in paths.items()):
            raise ValueError(f"входной файл совпадает с выходом другого этапа: {source}")

    store = args.comparison.parent / ("." + args.comparison.name + ".runs")
    store.mkdir(parents=True, exist_ok=True)
    current = store / "current"
    run_id = uuid4().hex
    stage = store / run_id
    stage.mkdir(mode=0o755)
    staged = Namespace(**vars(args))
    staged.run_id = run_id
    for field, filename in outputs.items():
        setattr(staged, field, stage / filename)
    try:
        yield staged
        manifest = {"run_id": run_id, "artifacts": {}}
        artifacts = manifest["artifacts"]
        for filename in outputs.values():
            metadata = json.loads(catalog_metadata(stage / filename).read_text(encoding="utf-8"))
            manifest["build"] = metadata["build"]
            artifacts[metadata["artifact_type"]] = {"file": os.path.relpath(paths[filename], args.comparison.parent),
                                                    "sha256": metadata["catalog_sha256"]}
        if args.request_slice:
            artifacts["report"] = {"file": os.path.relpath(paths["reasons.report.txt"], args.comparison.parent),
                                   "sha256": sha256(stage / "reasons.report.txt")}
        write_rows(stage / "run.json", [manifest])
        with (store / ".lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            previous = current.readlink() if current.is_symlink() else None
            if previous is not None and (len(previous.name) != 32 or previous != Path(previous.name)
                                         or any(c not in "0123456789abcdef" for c in previous.name)):
                raise ValueError(f"неизвестный каталог предыдущего прогона: {current}")
            # During conversion from ordinary files keep their original contents
            # visible until every public name points through the same switch.
            if previous is None and any(p.is_file() for p in paths.values()):
                previous = Path(uuid4().hex)
                backup = store / previous
                backup.mkdir()
                for filename, p in paths.items():
                    if p.is_file():
                        shutil.copy2(p, backup / filename)
                _point(current, previous)
            for filename, p in paths.items():
                p.parent.mkdir(exist_ok=True, parents=True)
                target = Path(os.path.relpath(current / filename, p.parent))
                if not p.is_symlink() or p.readlink() != target:
                    _point(p, target)
            _point(current, Path(run_id))
            if previous:
                shutil.rmtree(store / previous, ignore_errors=True)
    finally:
        if not current.is_symlink() or current.readlink() != Path(run_id):
            shutil.rmtree(stage, ignore_errors=True)
