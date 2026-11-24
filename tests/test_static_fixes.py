"""Offline regressions for static catalog collection, DEX binding, and operand slicing."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from zipfile import ZipFile

from body_data import bind_declaration, request_slice
from request_artifacts import catalog_metadata

ROOT = Path(__file__).resolve().parents[1]


class CatalogCollectionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)
        self.apk = self.work / "sample.apk"
        with ZipFile(self.apk, "w") as apk:
            apk.writestr("classes.dex", b"first")
            apk.writestr("classes2.dex", b"second")
        self.output = self.work / "result.md"
        self.jar = self.work / "scanner.jar"
        self.jar.touch()
        java = self.work / "java"
        java.write_text("""#!/bin/bash
input=$3
md="${input%.*}_methods.md"
case "$input" in
  *.apk)
    if [[ $SCENARIO == whole ]]; then
      printf 'whole\\r\\n{ "kept" : true }\\r\\n' > "$md"
      echo '[Fatal Error] resource.xml: XML parser error' >&2
    else
      echo incomplete > "$md"
      if [[ $SCENARIO == fatal ]]; then
        echo "ERROR Main - Error processing file $(basename "$input")" >&2
      else
        echo 'java.lang.OutOfMemoryError: Java heap space' >&2
      fi
    fi ;;
  *.dex)
    if [[ $SCENARIO == dex_fatal && $input == *classes2.dex ]]; then
      echo incomplete > "$md"
      echo "ERROR Main - Error processing file $(basename "$input")" >&2
    else
      cat "$input" > "$md"
      echo >> "$md"
    fi ;;
esac
""")
        java.chmod(0o755)

    def collect(self, scenario):
        result = subprocess.run(
            ["bash", ROOT / "bfscan.sh", self.apk, self.output],
            env={**os.environ, "PYTHON": sys.executable, "PATH": f"{self.work}:{os.environ['PATH']}",
                 "BFSCAN_JAR": str(self.jar), "SCENARIO": scenario},
            capture_output=True, text=True,
        )
        content = self.output.read_bytes()
        metadata = json.loads(catalog_metadata(self.output).read_bytes())
        self.assertEqual(metadata["catalog_sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(metadata["build"], hashlib.sha256(self.apk.read_bytes()).hexdigest())
        return result, content, metadata

    def test_whole_apk_preserves_full_catalog_and_isolates_scanner_files(self):
        sibling = self.apk.with_name("sample_methods.md")
        sibling.write_text("previous report")
        result, content, meta = self.collect("whole")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(content, b'whole\r\n{ "kept" : true }\r\n')
        self.assertEqual(sibling.read_text(), "previous report")
        self.assertEqual((meta["analysis_mode"], meta["status"]), ("whole_apk", "complete"))

    def test_oom_discards_truncated_output_and_marks_fallback_partial(self):
        result, content, meta = self.collect("oom")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(content, b"first\nsecond\n")
        self.assertEqual(meta["status"], "partial")
        self.assertEqual(meta["analysis_mode"], "per_dex")
        self.assertEqual(meta["fallback_reason"], "whole_apk_oom")
        self.assertIn("cross_dex_type_resolution", meta["limitations"])

    def test_fatal_log_with_zero_exit_does_not_retry_by_dex(self):
        result, content, meta = self.collect("fatal")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(content, b"")
        self.assertEqual((meta["analysis_mode"], meta["status"]), ("whole_apk", "partial"))

    def test_fallback_keeps_only_finished_dex_when_next_dex_fails(self):
        result, content, meta = self.collect("dex_fatal")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(content, b"first\n")
        self.assertEqual((meta["analysis_mode"], meta["status"]), ("per_dex", "partial"))


class DexEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from androguard.core.analysis.analysis import Analysis
        from androguard.core.dex import DEX

        sdk = Path(os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
                   or Path.home() / "Android/Sdk")
        bins = sorted(sdk.glob("build-tools/*/d8"))
        android = sorted(sdk.glob("platforms/android-*/android.jar"))
        if not (bins and android and shutil.which("javac")):
            raise unittest.SkipTest("Android SDK (android.jar, d8) and javac required")
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        work = Path(tmp.name)
        (work / "POST.java").write_text("""
package retrofit2.http;
@java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
public @interface POST { String value(); }
""")
        (work / "Api.java").write_text("""
package demo;
import retrofit2.http.POST;
interface Api {
    @POST("item?tag=a&tag=a&mode=on&empty=") void report(Body b);
    @POST("item?mode=off") void report(int n);
    @POST("item?lang=en") void both(int i);
    @POST("item?mode=on") void both(long l);
}
class Body { Body(long a, double b, int c) {} }
class Caller {
    native double convert(long j, double d);
    static native double compute(long j, int tail);
    void send(Api api, long j, int tail) {
        api.report(new Body(j, convert(j, compute(j, tail)), tail));
    }
}
""")
        subprocess.run(["javac", "--release", "8", "-d", work, work / "Api.java", work / "POST.java"],
                       check=True)
        subprocess.run([bins[-1], "--lib", android[-1], "--output", work,
                        *sorted(work.rglob("*.class"))], check=True)
        cls.dx = Analysis(DEX((work / "classes.dex").read_bytes()))
        cls.dx.create_xref()

    def bind(self, name, query):
        return bind_declaration(self.dx, {"cls": "demo.Api", "method": name, "verb": "POST",
                                          "path": "/item", "query": query})

    def test_fixed_query_allows_expansion_and_requires_each_repeated_pair(self):
        self.assertEqual(self.bind("report", "search=text&mode=on&empty=&tag=a&tag=a")["descriptor"],
                         "(Ldemo/Body;)V")
        for query in ("search=text&mode=on&empty=&tag=a", "mode=on&tag=a&tag=a",
                      "mode=other&empty=&tag=a&tag=a"):
            with self.subTest(query=query):
                self.assertIsNone(self.bind("report", query)["descriptor"])

    def test_query_matching_multiple_overloads_keeps_all_candidates(self):
        bound = self.bind("both", "extra=field&lang=en&mode=on")
        self.assertIsNone(bound["descriptor"])
        self.assertEqual(bound["descriptor_candidates"], ["(I)V", "(J)V"])

    def test_inner_invocations_trace_one_input_for_each_wide_value(self):
        row = self.bind("report", "tag=a&tag=a&mode=on&empty=")
        sites = request_slice(self.dx, row)["call_sites"]
        graph = sites[0]["arguments"][0]["slice"]
        nodes = {n["id"]: n for n in graph["nodes"]}

        def inputs(node):
            result = []
            for idx in node["inputs"]:
                child = nodes[idx]
                while child["kind"] == "alias":
                    child = nodes[child["inputs"][0]]
                result.append(child)
            return result

        ctor = nodes[graph["root"]]["local_writes_and_calls"][0]
        args = inputs(ctor)
        self.assertEqual([n["kind"] for n in args], ["parameter", "producer", "parameter"])
        self.assertEqual([args[0]["index"], args[2]["index"]], [1, 2])
        instance_args = inputs(args[1])
        self.assertEqual([n["kind"] for n in instance_args], ["receiver", "parameter", "producer"])
        static_args = inputs(instance_args[2])
        self.assertEqual([n["index"] for n in static_args], [1, 2])
