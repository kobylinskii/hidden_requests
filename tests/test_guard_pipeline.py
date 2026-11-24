"""Integration of the offline pipeline with a locally compiled, network-free APK."""
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from request_artifacts import catalog_metadata, sha256, write_rows
from request_pipeline import main, publish, read_checked_rows

PACKAGE = "demo.local.notes"
OWNER = PACKAGE + ".Api"


def build_demo(directory):
    sdk = Path(os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
               or Path.home() / "Android/Sdk")
    jars = sorted(sdk.glob("platforms/android-*/android.jar"))
    bins = sorted(d for d in sdk.glob("build-tools/*") if (d / "aapt").is_file() and (d / "d8").is_file())
    if not (jars and bins and shutil.which("javac")):
        raise unittest.SkipTest("Android SDK (android.jar, aapt, d8) and javac required")
    android = jars[-1]
    manifest = directory / "AndroidManifest.xml"
    manifest.write_text(
        f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{PACKAGE}" '
        'android:versionName="1.0" android:versionCode="1"><application>'
        '<receiver android:name=".Entry" android:exported="true"/></application></manifest>')
    source = directory / "Api.java"
    source.write_text("""
package demo.local.notes;
import retrofit2.http.POST;
interface Api {
    @POST("/text") void save(String x);
    @POST("/number") void save(int x);
    @POST("/seen") void seen();
    @POST("/unused") void unused();
    @POST("/draft") void draft();
}
class Entry extends android.content.BroadcastReceiver {
    public void onReceive(android.content.Context c, android.content.Intent i) {}
    void route(Api api, boolean selected) { if (selected) api.save("sample"); }
}
class Draft { void store(Api api) { api.draft(); } }
""")
    annotation = directory / "POST.java"
    annotation.write_text("""
package retrofit2.http;
@java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
public @interface POST { String value(); }
""")
    subprocess.run(["javac", "--release", "8", "-classpath", android, "-d", directory, source, annotation],
                   check=True)
    classes = sorted(directory.rglob("*.class"))
    subprocess.run([bins[-1] / "d8", "--min-api", "21", "--lib", android, "--output", directory, *classes],
                   check=True)
    apk = directory / "demo.apk"
    subprocess.run([bins[-1] / "aapt", "package", "-M", manifest, "-I", android, "-F", apk], check=True)
    with ZipFile(apk, "a") as archive:
        archive.write(directory / "classes.dex", "classes.dex")
    return apk


def demo_inputs(directory, build):
    catalog = directory / (PACKAGE + "_methods.md")
    catalog.write_text("".join(
        f"**Method**: {OWNER}->{name}\n* Retrofit/Ktorfit Method\n```\nPOST /{path} HTTP/1.1\n\n```\n"
        for name, path in (("save", "text"), ("save", "number"), ("seen", "seen"),
                           ("unused", "unused"), ("draft", "draft"), ("save", "unknown"))))
    write_rows(catalog_metadata(catalog), [{"build": build, "catalog_sha256": sha256(catalog), "status": "complete"}])
    trace = directory / (PACKAGE + ".dynamic.jsonl")
    write_rows(trace, [{"t": "meta", "session": "fixture", "build": build},
                       {"t": "coverage", "interface": OWNER, "handler": "retrofit2.Retrofit$1"},
                       {"t": "retrofit", "cls": OWNER, "m": "seen", "descriptor": "()V", "handler": "retrofit2.Retrofit$1"},
                       {"t": "end", "session": "fixture", "build": build, "status": "complete"}])
    return catalog, trace


class GuardPipelineTest(unittest.TestCase):
    def test_offline_pipeline_and_cached_reasons(self):
        from slice import load_apk, slice_key

        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            directory = Path(tmp)
            apk = build_demo(directory)
            build = sha256(apk)
            catalog, trace = demo_inputs(directory, build)
            hidden = directory / "demo.hidden.jsonl"
            reasons = directory / "demo.reasons.jsonl"
            report = reasons.with_suffix(".report.txt")
            args = ["request_pipeline.py", "--apk", str(apk), "--comparison", str(hidden),
                    "--out", str(directory / "demo.bodies.jsonl"),
                    "--request-slice", str(directory / "demo.request-slice.jsonl")]
            with patch.object(sys, "argv", args + ["--catalog", str(catalog), "--trace", str(trace)]), \
                    patch("slice.load_apk", wraps=load_apk) as load, \
                    patch("slice.slice_key", wraps=slice_key) as analyze, \
                    patch("sys.stderr", new_callable=StringIO) as log:
                main()
            load.assert_called_once()
            self.assertEqual(analyze.call_count, 4)
            self.assertNotIn("[предупреждение]", log.getvalue())
            comparison, _ = read_checked_rows(hidden, build)
            self.assertEqual([r["status"] for r in comparison],
                             ["not_observed", "not_observed", "observed", "not_observed", "not_observed", "not_observed"])
            records, complete = read_checked_rows(reasons, build)
            self.assertTrue(complete)
            self.assertEqual([(r["declaration_id"], r["key"], r["descriptor"]) for r in records],
                             [(r["declaration_id"], r["key"], r["descriptor"]) for r in comparison
                              if r["status"] == "not_observed"])
            self.assertFalse(records[0]["activation_exact"])
            self.assertFalse(records[1]["reached"])
            self.assertIsNone(records[1]["activation_cost"])
            self.assertTrue(records[0]["reached"])
            self.assertTrue(records[0]["declaration_has_call_sites"])
            self.assertEqual(records[0]["coroutine_launch_edges"], 0)
            self.assertEqual(records[4]["coroutine_resume_edges"], 0)
            self.assertEqual(records[0]["entry_evidence"], {"ui": "not_found", "background": "not_found"})
            self.assertFalse(records[1]["declaration_has_call_sites"])
            self.assertEqual(records[0]["guard_count"], 1)
            self.assertEqual(records[0]["activation_cost"], 1)
            self.assertFalse(records[2]["reached"])
            self.assertIn("no_caller", records[2]["notes"])
            self.assertIn("dead_end:no_callers", records[3]["notes"])
            self.assertEqual(comparison[5]["confidence_caveats"],
                             ["dex_identity_unresolved", "method_coverage_unverified"])
            self.assertFalse(records[3]["activation_exact"])
            self.assertIsNone(records[4]["descriptor"])
            self.assertEqual(records[4]["analysis_scope"], "unresolved")
            self.assertIn("dex_identity_unresolved", records[4]["notes"])
            self.assertIsNone(records[4]["activation_cost"])
            self.assertEqual(records[4]["call_site_count"], 0)
            for path in (reasons, catalog_metadata(reasons), report):
                self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            summary = report.read_text()
            self.assertIn("versionName=1.0 versionCode=1", summary)
            self.assertIn("[UNRESOLVED]", summary)
            self.assertIn("Точки входа UI:", summary)
            self.assertIn("DEX-дескриптор не разрешён: 1", summary)
            for section in ("(exact) — 0", "(lower) — 2", "(undet) — 3"):
                self.assertIn(section, summary)
            cached_args = args + ["--comparison-in", str(hidden), "--reasons-in", str(reasons)]
            with patch.object(sys, "argv", cached_args), patch("slice.slice_key", side_effect=AssertionError):
                main()
            self.assertEqual(read_checked_rows(reasons, build), (records, True))
            self.assertEqual(report.read_text(), summary)
            publish(reasons, records[:-1], build, True)
            with patch.object(sys, "argv", cached_args), self.assertRaises(SystemExit):
                main()

    def test_partial_comparison_with_no_candidates_needs_no_dex(self):
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            directory = Path(tmp)
            apk = directory / "demo.apk"
            apk.write_bytes(b"test identity")
            build = sha256(apk)
            hidden = directory / "demo.hidden.jsonl"
            publish(hidden, [], build, False, artifact_type="hidden", run_id="fixture")
            args = ["request_pipeline.py", "--apk", str(apk), "--comparison", str(hidden),
                    "--comparison-in", str(hidden), "--out", str(directory / "demo.bodies.jsonl"),
                    "--request-slice", str(directory / "demo.request-slice.jsonl")]
            with patch.object(sys, "argv", args), patch("slice.load_apk", side_effect=AssertionError), \
                    patch("slice.slice_key", side_effect=AssertionError), patch("androguard.core.apk.APK") as manifest:
                manifest.return_value.get_package.return_value = PACKAGE
                main()
            manifest.assert_called_once_with(str(apk))
            reasons = directory / "demo.reasons.jsonl"
            self.assertEqual(read_checked_rows(reasons, build), ([], False))
            self.assertIn("Всего ключей: 0", reasons.with_suffix(".report.txt").read_text())
