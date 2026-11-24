"""Regression on a DEX fixture shaped like an R8 lambda group."""
from pathlib import Path
import os
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

from androguard.core.analysis.analysis import Analysis
from androguard.core.dex import DEX

from slice import backward_frames


class AllocationDiscriminatorTest(unittest.TestCase):
    def test_switch_keeps_matching_and_unresolved_allocations(self):
        sdk = Path(os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
                   or Path.home() / "Android/Sdk")
        d8 = sorted(sdk.glob("build-tools/*/d8"))
        if not (d8 and shutil.which("javac")):
            self.skipTest("Android SDK and javac required")
        with TemporaryDirectory() as tmp:
            p = Path(tmp)
            source = p / "Merged.java"
            source.write_text("""
package demo;
class Merged {
    private final int id;
    Merged() { id = 0; }
    Merged(int value) { id = value; }
    void invoke(Api api) {
        switch (id) {
            case 0: api.other(); break;
            case 1: api.target(); break;
            case 2: api.other(); break;
            default: break;
        }
    }
}
interface Api { void target(); void other(); }
class Instances {
    Merged zero() { return new Merged(); }
    Merged one() { return new Merged(1); }
    Merged unknown(int n) { return new Merged(n); }
}
""")
            subprocess.run(["javac", "--release", "8", "-Xlint:-options", "-d", p, source], check=True)
            subprocess.run([d8[-1], "--output", p, *p.rglob("*.class")], check=True)
            dx = Analysis(DEX((p / "classes.dex").read_bytes()))
            dx.create_xref()
            walk = backward_frames(dx, "demo.Api", "target")
        self.assertTrue(walk["allocation_used"])
        frames = {f["key"] for f in walk["frames"]}
        self.assertIn("demo.Instances->one", frames)
        self.assertIn("demo.Instances->unknown", frames)
        self.assertNotIn("demo.Instances->zero", frames)
