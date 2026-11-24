import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from archivive.body_report import render_body
from request_pipeline import compare, read_trace
from diff import parse_bfscan


class RequestPipelineTests(unittest.TestCase):
    def test_bfscan_keeps_duplicate_declarations_and_template(self):
        with TemporaryDirectory() as work:
            path = Path(work) / "methods.md"
            block = ('**Method**: demo.Api->send\n* Retrofit/Ktorfit Method\n'
                     '```\nPOST /send HTTP/1.1\nContent-Type: application/json\n\n{"id":0}\n```\n')
            path.write_text(block * 2)
            first, second = parse_bfscan(path)
        self.assertNotEqual(first["declaration_id"], second["declaration_id"])
        self.assertEqual(first["bfscan"]["template"], {"id": 0})

    def test_exact_observation_wins_and_hidden_caveats_accumulate(self):
        declarations = [
            {"key": "demo.Api->send", "descriptor": "(I)V", "cls": "demo.Api", "framework": "retrofit"},
            {"key": "demo.Api->send", "descriptor": "(Z)V", "cls": "demo.Api", "framework": "retrofit"},
            {"key": "demo.Api->send", "descriptor": None, "cls": "demo.Api", "framework": "ktorfit",
             "reason": "dex_identity_unresolved"},
        ]
        trace = {"complete": True, "methods": {("demo.Api->send", "(I)V")},
                 "legacy_keys": set(), "interfaces": {"demo.Api"}}
        complete = compare(declarations, trace, True)
        self.assertEqual([r["status"] for r in complete], ["observed", "not_observed", "not_observed"])
        self.assertEqual(complete[1]["confidence_caveats"], [])
        trace["complete"] = False
        trace["interfaces"].clear()
        partial = compare(declarations, trace, True)
        self.assertEqual([r["status"] for r in partial], ["observed", "not_observed", "not_observed"])
        self.assertEqual(partial[0]["confidence_caveats"], [])
        self.assertEqual(partial[1]["confidence_caveats"],
                         ["artifact_incomplete_or_unverified", "method_coverage_unverified"])
        self.assertEqual(partial[2]["confidence_caveats"],
                         ["dex_identity_unresolved", "artifact_incomplete_or_unverified",
                          "method_coverage_unverified"])
        self.assertTrue(all("reason" not in row for row in partial))

    def test_statistics_count_overlapping_caveats_outside_primary_totals(self):
        from contextlib import redirect_stderr
        from io import StringIO
        from request_pipeline import bfscan_body_rows, print_statistics

        base = {"key": "demo.Api->send", "verb": "POST", "status": "not_observed"}
        rows = [dict(base, confidence_caveats=[]),
                dict(base, confidence_caveats=["dex_identity_unresolved", "method_coverage_unverified"]),
                dict(base, status="observed", confidence_caveats=[])]
        stderr = StringIO()
        with redirect_stderr(stderr):
            print_statistics(rows, list(bfscan_body_rows(rows)))
        output = stderr.getvalue()
        self.assertIn("Наблюдались: 1 (33.3%)", output)
        self.assertIn("Скрытые в этой сессии: 2 (66.7%)", output)
        self.assertIn("без оговорок: 1; с оговорками: 1", output)
        self.assertIn("dex_identity_unresolved=1", output)
        self.assertIn("method_coverage_unverified=1", output)
        self.assertNotIn("Недостаточно данных", output)

    def test_eval_pick_excludes_caveats_by_default_and_warns_on_obsolete_status(self):
        import subprocess
        import sys
        from request_artifacts import write_rows

        with TemporaryDirectory() as work:
            path = Path(work) / "hidden.jsonl"
            write_rows(path, [
                {"key": "demo.Api->clean", "status": "not_observed", "confidence_caveats": []},
                {"key": "demo.Api->limited", "status": "not_observed",
                 "confidence_caveats": ["method_coverage_unverified"]},
                {"key": "demo.Api->old", "status": "insufficient_data"},
            ])
            cmd = [sys.executable, "eval_slice.py", "--pick", "--hidden", str(path)]
            default = subprocess.run(cmd, check=True, capture_output=True, text=True)
            wide = subprocess.run(cmd + ["--include-caveats"], check=True, capture_output=True, text=True)
            self.assertEqual(default.stdout.splitlines(), ["demo.Api->clean"])
            self.assertEqual(wide.stdout.splitlines(), ["demo.Api->clean", "demo.Api->limited"])
            self.assertIn("insufficient_data", default.stderr)

    def test_truncated_trace_keeps_positive_evidence(self):
        with TemporaryDirectory() as work:
            path = Path(work) / "trace"
            path.write_text('{"t":"meta","build":"sha","session":"id"}\n'
                            '{"t":"retrofit","cls":"demo.Api","m":"send","descriptor":"(I)V",'
                            '"handler":"retrofit2.Retrofit$1"}\n'
                            '{"t":')
            trace = read_trace(path, "sha")
        self.assertFalse(trace["complete"])
        self.assertIn(("demo.Api->send", "(I)V"), trace["methods"])

    def test_unknown_is_distinct_from_explicit_json_null(self):
        model = {"kind": "object", "fields": {
            "known": {"kind": "value", "value": None},
            "a/b": {"kind": "unknown"},
        }}
        result = render_body(model)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(json.loads(json.dumps(result["body"])), {"known": None})
        self.assertEqual(result["unknown_paths"], ["/a~1b"])

    def test_array_preserves_indexes_of_unknown_values(self):
        result = render_body({"kind": "array", "items": [
            {"kind": "unknown"}, {"kind": "value", "value": 2}]})
        self.assertEqual(result["body"], [None, 2])
        self.assertEqual(result["unknown_paths"], ["/0"])

    def test_parameter_slice_keeps_dto_write_and_typed_source(self):
        from archivive.reconstruction import body_rows
        graph = {"root": 1, "limit_hit": False, "nodes": [
            {"id": 1, "kind": "allocation", "type": "Lnotes/Query;",
             "declared_fields": [{"field": "term", "type": "Ljava/lang/String;",
                                  "name_annotations": {"Ldemo/JsonKey;": "query"}}],
             "local_writes_and_calls": [{"field": "Lnotes/Query;->term Ljava/lang/String;",
                                         "source": 2, "offset": 18}]},
            {"id": 2, "kind": "alias", "inputs": [3]},
            {"id": 3, "kind": "parameter", "type": "Ljava/lang/String;", "index": 1,
             "method": "Lnotes/Repo;->search(ILjava/lang/String;)V"},
        ]}
        variant = {"parameter_slice": graph, "status": "partial", "call_sites": []}
        report = next(body_rows([{"variants": [variant]}]))["variants"][0]
        self.assertEqual(report.get("field_writes"), [{
            "field": "Lnotes/Query;->term Ljava/lang/String;", "allocation_node": 1,
            "offset": 18, "source_node": 2, "name_annotations": {"Ldemo/JsonKey;": "query"},
            "source": graph["nodes"][2],
        }])

    def test_hidden_bfscan_output_preserves_body_text(self):
        from request_pipeline import bfscan_body_rows
        bodies = ['{ "id": 1 }', 'id=1&id=2', 'null', '']
        with TemporaryDirectory() as work:
            catalog = Path(work) / 'methods.md'
            catalog.write_text(''.join(
                f'**Method**: demo.Api->send\n```\nPOST /send HTTP/1.1\n\n{body}\n```\n'
                for body in bodies))
            rows = [dict(r, status='not_observed', confidence_caveats=['method_coverage_unverified'])
                    for r in parse_bfscan(catalog)]
        records = list(bfscan_body_rows(rows + [dict(rows[0], status='observed'),
                                                dict(rows[0], status='insufficient_data')]))
        self.assertEqual([r['body'] for r in records], bodies[:-1] + [None])
        self.assertEqual([r['declaration_id'] for r in records], [1, 2, 3, 4])
        self.assertEqual(records[0]['confidence_caveats'], ['method_coverage_unverified'])

    def test_verified_artifact_uses_digest_of_written_utf8_bytes(self):
        from request_pipeline import publish, read_checked_rows
        import hashlib

        with TemporaryDirectory() as work:
            path = Path(work) / 'comparison.jsonl'
            records = [{'build': 'sha', 'label': 'тело'}]
            publish(path, records, 'sha', False)
            metadata = json.loads(Path(str(path) + '.meta.json').read_text())
            self.assertEqual(metadata['catalog_sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(read_checked_rows(path, 'sha'), (records, False))
            with path.open('ab') as stream:
                stream.write(b'\n')
            with self.assertRaisesRegex(ValueError, 'сумма'):
                read_checked_rows(path, 'sha')
