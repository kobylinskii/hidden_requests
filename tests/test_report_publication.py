from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor
import json
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
import unittest
from unittest.mock import patch

from report_publication import stage_reports
from request_artifacts import catalog_metadata, sha256
from request_pipeline import main, publish


class PublicationTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.apk = self.root / "demo.apk"
        self.apk.write_bytes(b"demo")
        self.build = sha256(self.apk)
        self.hidden = self.root / "demo.hidden.jsonl"
        self.source = self.root / "previous.hidden.jsonl"
        self.row = dict(build=self.build, declaration_id=1, cls="demo.Api", method="get",
                        key="demo.Api->get", descriptor="()V", verb="GET", path="/item", status="observed")
        publish(self.source, [self.row], self.build, True)

    def run_report(self, *extra):
        args = ["pipeline", "--apk", str(self.apk), "--comparison-in", str(self.source),
                "--comparison", str(self.hidden), "--out", str(self.root / "demo.bodies.jsonl"),
                "--request-slice", str(self.root / "demo.request-slice.jsonl"), *map(str, extra)]
        with patch("sys.argv", args), patch("androguard.core.apk.APK") as apk, redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            apk.return_value.get_package.return_value = "demo"
            apk.return_value.get_androidversion_name.return_value = "1"
            apk.return_value.get_androidversion_code.return_value = "1"
            main()

    def test_bad_cache_preserves_entire_previous_generation(self):
        self.run_report()
        before = {p: p.read_bytes() for p in self.root.glob("demo.*") if p.is_file()}
        publish(self.source, [dict(self.row, declaration_id=2)], self.build, True)
        with self.assertRaises(SystemExit):
            self.run_report("--reasons-in", self.root / "absent")
        self.assertEqual({p: p.read_bytes() for p in before}, before)

    def test_reject_wrong_artifact_even_with_valid_hash_and_build(self):
        publish(self.source, [dict(self.row, status="no_bfscan_example")], self.build, True, artifact_type="bodies")
        with self.assertRaises(SystemExit):
            self.run_report()

    def test_old_unknown_status_is_skipped_with_warning(self):
        from request_pipeline import read_checked_rows
        publish(self.source, [self.row, dict(self.row, declaration_id=2, status="insufficient_data")],
                self.build, True, artifact_type="hidden")
        with redirect_stderr(StringIO()) as log:
            rows, complete = read_checked_rows(self.source, self.build, "hidden")
        self.assertTrue(complete)
        self.assertEqual([r["status"] for r in rows], ["observed"])
        self.assertIn("insufficient_data", log.getvalue())

    def test_metadata_identifies_kind_and_single_run(self):
        self.run_report()
        metas = [json.loads(catalog_metadata(self.root / f"demo.{kind}.jsonl").read_text())
                 for kind in ("hidden", "bodies", "request-slice", "reasons")]
        self.assertEqual(len({m.get("run_id") for m in metas if m.get("run_id")}), 1)
        self.assertEqual([m.get("artifact_type") for m in metas], ["hidden", "bodies", "request-slice", "reasons"])

    def test_concurrent_publications_expose_one_run(self):
        args = Namespace(apk=self.apk, comparison=self.hidden, out=self.root / "demo.bodies.jsonl",
                         request_slice=None, catalog=None, trace=None, comparison_in=None, reasons_in=None)
        ready = Barrier(2)

        def write(label):
            with stage_reports(args) as staged:
                for path, kind in ((staged.comparison, "hidden"), (staged.out, "bodies")):
                    publish(path, [{"label": label}], self.build, True, artifact_type=kind, run_id=staged.run_id)
                ready.wait(timeout=5)

        with ThreadPoolExecutor(max_workers=2) as workers:
            list(workers.map(write, ("a", "b")))
        manifest = json.loads((self.root / "demo.run.json").read_text())
        labels = set()
        for artifact in manifest["artifacts"].values():
            p = self.root / artifact["file"]
            self.assertEqual(json.loads(catalog_metadata(p).read_text())["run_id"], manifest["run_id"])
            self.assertEqual(sha256(p), artifact["sha256"])
            labels.add(json.loads(p.read_text())["label"])
        self.assertEqual(len(labels), 1)
