"""Local DEX fixture for dispatch and Android View callback registration."""
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

from androguard.core.analysis.analysis import Analysis
from androguard.core.dex import DEX

from slice import cha_caller_sites, slice_key


class UiReachabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sdk = Path.home() / "Android/Sdk"
        d8 = sorted(sdk.glob("build-tools/*/d8"))
        android = sorted(sdk.glob("platforms/*/android.jar"))
        if not (d8 and android and shutil.which("javac")):
            raise unittest.SkipTest("Android SDK and javac required")
        temp = TemporaryDirectory()
        cls.addClassCleanup(temp.cleanup)
        path = Path(temp.name)
        source = path / "Fixture.java"
        source.write_text("""
package testlocal;
import android.view.View;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

class Sink {
    static void first() {}
    static void second() {}
    static void background() {}
}
interface Loader { void load(); }
final class Left implements Loader { public void load() { Sink.first(); } }
final class Right implements Loader { public void load() { Sink.second(); } }
class Screen {
    void attach(View view) {
        View.OnClickListener used = new Active();
        new Inactive();
        view.setOnClickListener(used);
    }
    void unknown(Loader loader) { loader.load(); }
}
final class Active implements View.OnClickListener {
    public void onClick(View view) { Loader loader = new Left(); loader.load(); }
}
final class Inactive implements View.OnClickListener {
    public void onClick(View view) { Loader loader = new Right(); loader.load(); }
}
class Receiver extends BroadcastReceiver {
    public void onReceive(Context c, Intent i) { Sink.background(); }
}
""")
        subprocess.run(["javac", "--release", "8", "-Xlint:-options", "-cp", android[-1],
                        "-d", path, source], check=True)
        subprocess.run([d8[-1], "--lib", android[-1], "--output", path, *path.rglob("*.class")], check=True)
        cls.dx = Analysis(DEX((path / "classes.dex").read_bytes()))
        cls.dx.create_xref()

    def analyze(self, name):
        return slice_key(self.dx, "testlocal.Sink->" + name, descriptor="()V", include_arguments=False)

    def test_local_receiver_discards_other_implementations(self):
        method = self.dx.get_method_analysis_by_name("Ltestlocal/Left;", "load", "()V")
        sites, used_cha, reason = cha_caller_sites(self.dx, method)
        self.assertEqual({item.class_name for item, _ in sites}, {"Ltestlocal/Active;"})
        self.assertFalse(used_cha)
        self.assertEqual(reason, "unexamined_dispatch")

    def test_only_registered_listener_serves_as_ui_entry(self):
        registered = self.analyze("first")
        unregistered = self.analyze("second")
        self.assertEqual(registered["entry_evidence"], {"ui": "resolved", "background": "not_found"})
        self.assertEqual(unregistered["entry_evidence"], {"ui": "not_found", "background": "not_found"})
        self.assertTrue(unregistered["reached"])

    def test_background_entry_is_not_counted_as_ui(self):
        result = self.analyze("background")
        self.assertEqual(result["entry_evidence"], {"ui": "not_found", "background": "resolved"})
