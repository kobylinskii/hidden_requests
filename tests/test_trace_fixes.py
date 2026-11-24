"""Regressions for passive trace attribution and collector failures."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from request_pipeline import compare, read_trace


ROOT = Path(__file__).resolve().parents[1]
HANDLER = "retrofit2.Retrofit$1"
OWNER = "demo.Api"


def trace_rows(*events):
    return [{"t": "meta", "session": "s", "build": "sha"}, *events,
            {"t": "end", "session": "s", "build": "sha", "status": "complete"}]


def classify(events, *descriptors):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "trace.jsonl"
        path.write_text("".join(json.dumps(e) + "\n" for e in trace_rows(*events)))
        trace = read_trace(path, "sha")
    rows = [{"key": OWNER + "->send", "cls": OWNER, "framework": "retrofit",
             "descriptor": descriptor} for descriptor in descriptors]
    return [row["status"] for row in compare(rows, trace, True)]


class TraceEvidenceTests(unittest.TestCase):
    def test_legacy_stub_could_have_suppressed_later_genuine_call(self):
        method = {"t": "retrofit", "cls": OWNER, "m": "send"}
        events = [{**method, "handler": "demo.Stub", "descriptor": "(I)V"},
                  {**method, "handler": HANDLER, "descriptor": "(Z)V"},
                  {"t": "coverage", "interface": OWNER}]
        self.assertEqual(classify(events, "(I)V", "(Z)V", "()V"),
                         ["insufficient_data", "observed", "not_observed"])

    def test_unattributed_legacy_event_and_coverage(self):
        events = [{"t": "retrofit", "cls": OWNER, "m": "send", "descriptor": "(I)V"},
                  {"t": "coverage", "interface": OWNER}]
        self.assertEqual(classify(events, "(I)V", "(Z)V"), ["insufficient_data"] * 2)

    def test_only_method_call_attributes_declaration(self):
        events = [{"t": "coverage", "interface": OWNER, "handler": HANDLER},
                  {"t": "http", "observation": "request_created", "url": "/send", "verb": "GET"},
                  {"t": "response", "observation": "response_created", "url": "/send", "status": 200},
                  {"t": "retrofit", "cls": OWNER, "m": "send", "descriptor": "(I)V",
                   "handler": HANDLER, "observation": "response_created"}]
        self.assertNotIn("observed", classify(events, "(I)V"))

    def test_coverage_belongs_to_instrumented_retrofit_interface(self):
        events = [{"t": "coverage", "interface": OWNER, "handler": "demo.Stub"},
                  {"t": "coverage", "interface": "demo.Other", "handler": HANDLER}]
        self.assertEqual(classify(events, "(I)V"), ["insufficient_data"])


@unittest.skipUnless(shutil.which("node"), "Node.js required for the passive agent fixture")
class AgentTests(unittest.TestCase):
    def test_factory_invocation_and_forwarding(self):
        fixture = """
const vm = require('node:vm'), fs = require('node:fs'), assert = require('node:assert/strict');
const events = [], types = ['java.lang.Object', 'java.lang.reflect.Method', '[Ljava.lang.Object;'];
const iface = { getName: () => 'demo.Api' };
const method = { getName: () => 'send', getDeclaringClass: () => iface,
    getParameterTypes: () => [{getName: () => 'int'}], getReturnType: () => ({getName: () => 'void'}) };
const service = {}, loader = {}, argv = [13], result = {};
const classes = {};
function handler(name) {
    const obj = { $className: name };
    const ov = { call(receiver, proxy, m, args) {
        assert.equal(receiver, obj); assert.equal(proxy, service); assert.equal(m, method);
        assert.equal(args, argv); return result;
    }};
    const extra = { call(receiver, ...args) {
        assert.equal(receiver, obj); assert.deepEqual(args, [19]); return 23;
    }};
    classes[name] = { class: {isInstance: h => h === obj}, invoke: { overloads: [ov, extra],
        overload(...args) { assert.deepEqual(args, types); return ov; } }};
    return {obj, ov, extra};
}
const stub = handler('demo.Stub'), real = handler('retrofit2.Retrofit$1');
const broken = handler('retrofit2.Retrofit$2');
classes[broken.obj.$className].invoke.overload = () => { throw Error('no standard overload'); };
classes[broken.obj.$className].invoke.overloads = [];
const proxy = {newProxyInstance(l, interfaces, h) { assert.equal(l, loader); return service; }};
classes['java.lang.reflect.Proxy'] = proxy;
const ctx = {rpc: {}, send: e => events.push(e), setTimeout() {},
    Java: {perform: fn => fn(), use: name => {
        if (!(name in classes)) throw Error('unavailable: ' + name);
        return classes[name];
    }}};
vm.runInNewContext(fs.readFileSync('hook.js', 'utf8'), ctx);
function create(h, interfaceClass) {
    assert.equal(proxy.newProxyInstance.implementation.call(proxy, loader, [interfaceClass], h.obj), service);
}
function call(h, ov, ...args) {
    return ov.implementation ? ov.implementation.call(h.obj, ...args) : ov.call(h.obj, ...args);
}
create(stub, iface);
assert.equal(call(stub, stub.ov, service, method, argv), result);
create(broken, {getName: () => 'demo.Unhooked'});
create(real, iface);
create(real, {getName: () => 'demo.Unused'});
assert.equal(call(real, real.ov, service, method, argv), result);
assert.equal(call(real, real.extra, 19), 23);
assert.deepEqual(events.filter(e => e.t === 'retrofit').map(e => [e.handler, e.descriptor, e.observation]),
    [['retrofit2.Retrofit$1', '(I)V', 'method_call']]);
assert.deepEqual(events.filter(e => e.t === 'coverage').map(e => [e.interface, e.handler]),
    [['demo.Api', 'retrofit2.Retrofit$1'], ['demo.Unused', 'retrofit2.Retrofit$1']]);
"""
        run = subprocess.run(["node", "-e", fixture], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_http_objects_are_observed_only_after_successful_construction(self):
        fixture = """
const vm = require('node:vm'), fs = require('node:fs'), assert = require('node:assert/strict');
const events = [], request = {url: () => 'https://local/item', method: () => 'GET'};
const response = {request: () => request, code: () => 200};
const successfulCall = {}, opened = {}, broken = Error('constructor failed');
let fails = true;
function maybeReturn(value) { if (fails) throw broken; return value; }
const client = {newCall: req => maybeReturn(successfulCall)};
const builder = {call: () => maybeReturn(response)};
const connection = {};
const url = {openConnection: Object.assign(() => maybeReturn(opened), {overload: () => connection}),
    toString: () => request.url()};
const classes = { 'java.lang.reflect.Proxy': {newProxyInstance: {}}, 'java.net.URL': url,
    'okhttp3.OkHttpClient': client, 'okhttp3.Response$Builder': {build: {overload: () => builder}},
    'android.util.Log': {getStackTraceString: () => 'at org.demo.$Proxy1.request(Proxy.java)'},
    'java.lang.Exception': {$new() {}} };
vm.runInNewContext(fs.readFileSync('hook.js', 'utf8'), {rpc: {}, send: e => events.push(e),
    Java: {perform: fn => fn(), use: name => classes[name]}});
const createCall = () => client.newCall.implementation.call(client, request);
const createResponse = () => builder.implementation.call(builder);
const openConnection = () => connection.implementation.call(url);
for (const action of [createCall, createResponse, openConnection]) assert.throws(action, err => err === broken);
assert.equal(events.filter(e => e.observation).length, 0);
fails = false;
assert.equal(createCall(), successfulCall);
assert.equal(openConnection(), opened);
assert.equal(createResponse(), response);
assert.deepEqual(events.filter(e => e.observation).map(e => [e.t, e.observation]),
    [['http', 'request_created'], ['http', 'connection_opened'], ['response', 'response_created']]);
assert.equal(events.find(e => e.observation === 'request_created').via_retrofit, false);
"""
        run = subprocess.run(["node", "-e", fixture], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)


class ScanAppendTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.directory = Path(tmp.name)
        self.apk = self.directory / "demo.apk"
        self.apk.touch()
        self.trace = self.directory / "demo.dynamic.jsonl"
        self.prior = "\n".join(json.dumps(e) for e in trace_rows()).encode()
        self.trace.write_bytes(self.prior)
        self.marker = self.directory / "pipeline_called"
        self.py = self.directory / "fake-python"
        self.py.write_text("""#!/usr/bin/env bash
case "$1" in
    -c) echo demo ;;
    */trace.py) shift; exec "$TRACE_PYTHON" -c '
import os
from types import SimpleNamespace
from unittest.mock import patch
import trace
device = SimpleNamespace(id="d", name="device")
with patch.object(trace, "pick_device", return_value=device), patch.object(trace, "installed_identity", return_value=(os.environ["TEST_BUILD"], [])), patch.object(trace, "apk_version", return_value={}):
    trace.main()
' "$@" ;;
    */request_pipeline.py) touch "$PIPELINE_CALLED" ;;
esac
""")
        adb = self.directory / "adb"
        adb.write_text("#!/bin/sh\necho package:/base.apk\n")
        self.py.chmod(0o755)
        adb.chmod(0o755)

    def run_scan(self, build):
        env = {**os.environ, "PATH": str(self.directory) + ":" + os.environ["PATH"],
               "PYTHON": str(self.py), "OUT_DIR": str(self.directory), "TRACE_APPEND": "1",
               "STATIC_IN": str(self.directory / "catalog"), "TEST_BUILD": build,
               "ADB_DEVICE": "d", "PIPELINE_CALLED": str(self.marker), "TRACE_PYTHON": sys.executable}
        return subprocess.run(["bash", ROOT / "scan.sh", self.apk], cwd=ROOT, capture_output=True,
                              text=True, env=env)

    def test_refused_append_preserves_complete_file_and_stops_scan(self):
        run = self.run_scan("different")
        self.assertNotEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.trace.read_bytes(), self.prior)
        self.assertFalse(self.marker.exists())

    def test_finalized_new_partial_session_is_available_to_the_scanner(self):
        # The test device passes identity checks but cannot spawn the application.
        run = self.run_scan("sha")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(self.marker.exists())
        events = [json.loads(line) for line in self.trace.read_text().splitlines() if line]
        self.assertEqual([e["t"] for e in events], ["meta", "end", "meta", "end"])
        self.assertEqual(events[-1]["status"], "partial")
        self.assertEqual(events[-1]["session"], events[-2]["session"])
        self.assertNotEqual(events[-1]["session"], events[0]["session"])
        self.assertFalse(read_trace(self.trace, "sha")["complete"])
