"""Exercises Kotlin coroutine bytecode shapes on a local, network-free DEX."""
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

from androguard.core.analysis.analysis import Analysis
from androguard.core.dex import DEX

from slice import slice_key


SOURCES = {
    "Continuation.java": "package kotlin.coroutines; public interface Continuation {}",
    "CoroutineContext.java": "package kotlin.coroutines; public interface CoroutineContext {}",
    "Function2.java": "package kotlin.jvm.functions; public interface Function2 {}",
    "ContinuationImpl.java": """
        package kotlin.coroutines.jvm.internal;
        public abstract class ContinuationImpl implements kotlin.coroutines.Continuation {
            protected abstract Object invokeSuspend(Object result);
        }
    """,
    "SuspendLambda.java": """
        package kotlin.coroutines.jvm.internal;
        public abstract class SuspendLambda extends ContinuationImpl implements kotlin.jvm.functions.Function2 {}
    """,
    "CoroutineScope.java": "package kotlinx.coroutines; public interface CoroutineScope {}",
    "CoroutineStart.java": "package kotlinx.coroutines; public enum CoroutineStart { DEFAULT, LAZY }",
    "Job.java": "package kotlinx.coroutines; public interface Job {}",
    "Deferred.java": "package kotlinx.coroutines; public interface Deferred {}",
    "BuildersKt.java": """
        package kotlinx.coroutines;
        import kotlin.coroutines.CoroutineContext;
        import kotlin.jvm.functions.Function2;
        public class BuildersKt {
            public static native Job launch(CoroutineScope scope, CoroutineContext context,
                                            CoroutineStart start, Function2 block);
            public static native Deferred async(CoroutineScope scope, CoroutineContext context,
                                                  CoroutineStart start, Function2 block);
            public static native Job launch$default(CoroutineScope scope, CoroutineContext context,
                                                    CoroutineStart start, Function2 block, int mask, Object marker);
        }
    """,
    "Screen.java": """
        package localdemo;
        import android.app.Activity;
        import android.os.Bundle;
        import kotlin.coroutines.Continuation;
        import kotlin.coroutines.CoroutineContext;
        import kotlin.coroutines.jvm.internal.*;
        import kotlinx.coroutines.*;

        class Sink {
            static void started() {}
            static void allocated() {}
            static void lazy() {}
            static void defaultStart() {}
            static void asyncStarted() {}
            static void resumed() {}
        }
        final class Started extends SuspendLambda {
            protected Object invokeSuspend(Object result) { Sink.started(); return null; }
        }
        final class Allocated extends SuspendLambda {
            protected Object invokeSuspend(Object result) { Sink.allocated(); return null; }
        }
        final class Lazy extends SuspendLambda {
            protected Object invokeSuspend(Object result) { Sink.lazy(); return null; }
        }
        final class DefaultStart extends SuspendLambda {
            protected Object invokeSuspend(Object result) { Sink.defaultStart(); return null; }
        }
        final class AsyncStarted extends SuspendLambda {
            protected Object invokeSuspend(Object result) { Sink.asyncStarted(); return null; }
        }
        final class State extends ContinuationImpl {
            protected Object invokeSuspend(Object result) { return Service.load(this); }
        }
        class Service {
            static Object load(Continuation state) {
                if (!(state instanceof State)) state = new State();
                Sink.resumed();
                return state;
            }
        }
        public class Screen extends Activity {
            final CoroutineScope scope = new CoroutineScope() {};
            final CoroutineContext context = new CoroutineContext() {};
            protected void onCreate(Bundle state) {
                BuildersKt.launch(scope, context, CoroutineStart.DEFAULT, new Started());
                new Started();
                new Allocated();
                BuildersKt.async(scope, context, CoroutineStart.DEFAULT, new AsyncStarted());
                BuildersKt.launch(scope, context, CoroutineStart.LAZY, new Lazy());
                BuildersKt.launch$default(scope, null, null, new DefaultStart(), 3, null);
                Service.load(null);
            }
        }
    """,
}


class CoroutineReachabilityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sdk = Path(os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
                   or Path.home() / "Android/Sdk")
        d8 = sorted(sdk.glob("build-tools/*/d8"))
        android = sorted(sdk.glob("platforms/*/android.jar"))
        if not (d8 and android and shutil.which("javac")):
            raise unittest.SkipTest("Android SDK and javac required")
        temp = TemporaryDirectory()
        cls.addClassCleanup(temp.cleanup)
        root = Path(temp.name)
        for name, code in SOURCES.items():
            (root / name).write_text(code)
        subprocess.run(["javac", "--release", "8", "-Xlint:-options", "-cp", android[-1],
                        "-d", root, *root.glob("*.java")], check=True)
        subprocess.run([d8[-1], "--lib", android[-1], "--output", root, *root.rglob("*.class")], check=True)
        cls.dx = Analysis(DEX((root / "classes.dex").read_bytes()))
        cls.dx.create_xref()

    def analyze(self, name):
        return slice_key(self.dx, "localdemo.Sink->" + name, descriptor="()V", include_arguments=False)

    def test_launch_of_known_instance_supplies_resolved_edge(self):
        for case in ("started", "defaultStart", "asyncStarted"):
            with self.subTest(case=case):
                rec = self.analyze(case)
                self.assertEqual(rec["entry_evidence"]["ui"], "resolved")
                self.assertEqual(rec["coroutine_launch_edges"], 1)

    def test_allocation_and_lazy_launch_remain_unverified(self):
        for case in ("allocated", "lazy"):
            with self.subTest(case=case):
                rec = self.analyze(case)
                self.assertEqual(rec["entry_evidence"]["ui"], "modulo_allocation")
                self.assertEqual(rec["coroutine_launch_edges"], 0)

    def test_resume_bridge_recovers_the_original_suspend_method(self):
        rec = self.analyze("resumed")
        self.assertEqual(rec["entry_evidence"]["ui"], "resolved")
        self.assertEqual(rec["coroutine_resume_edges"], 1)
