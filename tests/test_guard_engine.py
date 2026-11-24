"""Small DEX graph fixtures for the passive guard metrics."""
from contextlib import redirect_stderr
from io import StringIO
import unittest
from unittest.mock import patch

import networkx as nx

import slice as sl


class Method:
    def __init__(self, owner, name, descriptor="()V", callers=(), flags="public"):
        self.class_name, self.name, self.descriptor = owner, name, descriptor
        self.callers, self.flags = list(callers), flags

    def get_xref_from(self):
        return [(None, caller, offset) for caller, offset in self.callers]

    def get_method(self):
        return None

    def get_access_flags_string(self):
        return self.flags


class Class:
    def __init__(self, *methods, parent="Ljava/lang/Object;"):
        self.methods, self.extends, self.implements = methods, parent, []

    def get_methods(self):
        return self.methods

    def is_external(self):
        return False

    def get_xref_new_instance(self):
        return []


class Analysis:
    def __init__(self, **classes):
        self.classes = {"L" + name + ";": cls for name, cls in classes.items()}

    def get_method_analysis_by_name(self, owner, name, descriptor):
        ca = self.classes.get(owner)
        if ca:
            return next((m for m in ca.methods if (m.name, m.descriptor) == (name, descriptor)), None)


def frame():
    cfg = nx.DiGraph()
    cfg.add_node(0, insns=[sl.Insn("if-eqz", None, ("v0",))])
    cfg.add_node(1, insns=[])
    cfg.add_node(2, insns=[])
    cfg.add_edges_from([(0, 1), (0, 2), (1, 2)])
    return {"cfg": cfg, "params": {"v0": 0}, "block_at": lambda offset: offset if offset in cfg else None}


class GuardEngineTest(unittest.TestCase):
    def setUp(self):
        self.callback = Method("LEntry;", "onReceive", "(Landroid/content/Context; Landroid/content/Intent;)V")
        self.api = Method("LApi;", "record", "(I)V", [(self.callback, 1)])
        self.other = Method("LApi;", "record", "(J)V")
        self.dx = Analysis(Api=Class(self.api, self.other),
                           Entry=Class(self.callback, parent="Landroid/content/BroadcastReceiver;"))
        self.dx._exported = {"Entry"}

    def analyze(self, descriptor="(I)V"):
        return sl.slice_key(self.dx, "Api->record", descriptor=descriptor, include_arguments=False)

    def test_overload_filters_initial_sites_and_dex_membership(self):
        with patch.object(sl, "frame_of", return_value=frame()):
            self.assertEqual(self.analyze()["guard_count"], 1)
            self.assertFalse(self.analyze("(J)V")["reached"])
            self.assertEqual(self.analyze("(J)V")["notes"], ["no_caller"])
            self.assertEqual(self.analyze("(Z)V")["notes"], ["key_not_in_dex"])

    def test_frontier_requires_instance_signature_and_ancestor(self):
        bad = [Method("LEntry;", "route"), Method("LEntry;", "onReceive"),
               Method("LEntry;", "onReceive", self.callback.descriptor, flags="static public"),
               Method("LPlain;", "onReceive", self.callback.descriptor),
               Method("Landroidx/test/Helper;", "helper")]
        self.dx.classes["LPlain;"] = Class(bad[-2])
        self.dx.classes["Landroidx/test/Helper;"] = Class(bad[-1])
        with patch.object(sl, "frame_of", return_value=frame()):
            for method in bad:
                with self.subTest(method=method.name, owner=method.class_name, flags=method.flags):
                    self.api.callers = [(method, 1)]
                    result = self.analyze()
                    self.assertFalse(result["activation_exact"])
                    self.assertIsNone(result["best_known_complete_cost"])
            self.api.callers = [(self.callback, 1)]
            result = self.analyze()
            self.assertTrue(result["activation_exact"])
            self.assertEqual(result["best_known_complete_cost"], 1)

    def test_cheaper_truncated_suffix_is_lower_bound(self):
        leaf = Method("LPlain;", "partial")
        self.api.callers.append((leaf, 2))
        with patch.object(sl, "frame_of", return_value=frame()):
            result = self.analyze()
        self.assertEqual(result["activation_cost"], 0)
        self.assertFalse(result["activation_exact"])
        self.assertEqual(result["best_known_complete_cost"], 1)

    def test_missing_frame_and_missing_offset_never_certify_a_complete_path(self):
        for missing in (None, {"cfg": nx.DiGraph(), "params": {}, "block_at": lambda offset: None}):
            with (self.subTest(frame=missing), patch.object(sl, "frame_of", return_value=missing),
                  redirect_stderr(StringIO()) as log):
                result = self.analyze()
                self.assertTrue(result["inconclusive"])
                self.assertFalse(result["activation_exact"])
                self.assertIsNone(result["best_known_complete_cost"])
                if missing is None:
                    self.assertIn("missing_frame", result["notes"])
                    self.assertNotIn("unexpected_offset_miss", result["notes"])
                    self.assertEqual(log.getvalue(), "")
                else:
                    self.assertIn("unexpected_offset_miss", result["notes"])
                    self.assertNotIn("missing_frame", result["notes"])
                    self.assertIn("Api->record", log.getvalue())
                    self.assertIn("offset=1", log.getvalue())

    def test_cha_and_allocation_edges_cannot_certify_a_complete_path(self):
        for name in ("save", "invoke"):
            with self.subTest(name=name):
                method = Method("LImpl;", name)
                origin = Method("LBase;", name, callers=[(self.callback, 1)] if name == "save" else [])
                cls = Class(method, parent="LBase;")
                cls.get_xref_new_instance = lambda: [(self.callback, 1)]
                self.dx.classes.update({"LImpl;": cls, "LBase;": Class(origin)})
                self.api.callers = [(method, 2)]
                with patch.object(sl, "frame_of", return_value=frame()):
                    result = self.analyze()
                self.assertFalse(result["activation_exact"])
                self.assertEqual(result["activation_cost"], 0)
                self.assertIsNone(result["best_known_complete_cost"])

    def test_budget_keeps_lower_bound_for_unvisited_direct_site(self):
        leaf = Method("LPlain;", "partial")
        self.api.callers.append((leaf, 2))
        with patch.object(sl, "_FRAME_BUDGET", 1), patch.object(sl, "frame_of", return_value=frame()):
            result = self.analyze()
        self.assertIn("budget_hit", result["notes"])
        self.assertFalse(result["activation_exact"])
        self.assertEqual(result["activation_cost"], 0)
        self.assertEqual(result["best_known_complete_cost"], 1)

    def test_unexamined_supertype_callers_do_not_raise_the_lower_bound(self):
        impl = Method("LImpl;", "save", callers=[(self.callback, 1)])
        base = Method("LBase;", "save", callers=[(self.callback, 2)])
        self.dx.classes.update({"LImpl;": Class(impl, parent="LBase;"), "LBase;": Class(base)})
        self.api.callers = [(impl, 2)]
        with patch.object(sl, "frame_of", return_value=frame()):
            result = self.analyze()
        self.assertFalse(result["activation_exact"])
        self.assertEqual(result["activation_cost"], 0)
        self.assertEqual(result["best_known_complete_cost"], 1)

    def test_uncertain_alternative_does_not_hide_an_independent_complete_path(self):
        impl = Method("LImpl;", "save")
        base = Method("LBase;", "save", callers=[(self.callback, 2)])
        self.dx.classes.update({"LImpl;": Class(impl, parent="LBase;"), "LBase;": Class(base)})
        self.api.callers.append((impl, 2))
        with patch.object(sl, "frame_of", return_value=frame()):
            result = self.analyze()
        self.assertFalse(result["activation_exact"])
        self.assertEqual(result["activation_cost"], 0)
        self.assertEqual(result["best_known_complete_cost"], 1)

    def test_postdominators_reused_across_queries_with_distinct_criteria(self):
        fr = frame()
        with patch.object(sl, "post_idom", wraps=sl.post_idom) as post:
            self.assertEqual(len(sl.guards_of_frame(fr, 1)), 1)
            self.assertEqual(len(sl.guards_of_frame(fr, 2)), 0)
            self.assertEqual(len(sl.guards_of_frame(fr, 1)), 1)
            self.assertEqual(post.call_count, 1)

    def test_report_keeps_differently_analyzed_overloads(self):
        row = dict(key="Api->record", guard_count=1, notes=[], reached=True,
                   activation_exact=True, activation_cost=1, best_known_complete_cost=1)
        rows = [dict(row, descriptor="(I)V", declaration_id=1),
                dict(row, descriptor="(J)V", declaration_id=2, reached=False,
                     activation_exact=False, activation_cost=None, best_known_complete_cost=None, notes=["no_caller"])]
        report = sl.report(rows)
        for value in ("(I)V", "(J)V", "(exact) — 1", "(undet) — 1"):
            self.assertIn(value, report)

    def test_allocation_only_certification_distinguishes_cha(self):
        edges = {"entry": {"allocation"}, "allocation": {"cha"}, "cha": {"call"}}
        args = ({"allocation": 1}, edges, {"entry", "allocation"}, {"entry"}, "call")
        self.assertEqual(sl.min_path_guards(*args, allocation_uncertain={"allocation"}),
                         (1, False, None, 1))
        self.assertEqual(sl.min_path_guards(*args, cha_uncertain={"cha"}),
                         (1, False, None, None))
        self.assertEqual(sl.min_path_guards(*args, cha_uncertain={"cha"},
                                           allocation_uncertain={"allocation"}), (1, False, None, None))

    def test_first_uncertain_hop_counts_semantic_frames_before_current(self):
        first = Method("LImpl;", "read")
        above = Method("LImpl;", "load")
        first.callers = [(above, 2)]
        base = Method("LBase;", "load", callers=[(self.callback, 2)])
        self.dx.classes.update({"LImpl;": Class(first, above, parent="LBase;"), "LBase;": Class(base)})
        self.api.callers = [(first, 2)]
        with patch.object(sl, "frame_of", return_value=frame()):
            result = self.analyze()
        self.assertEqual(result["first_uncertain_hop"], 1)
        self.assertEqual(sl.backward_frames(self.dx, "Api", "record")["first_uncertain_depth"], {(id(above), 2): 1})

    def test_ktor_and_sdk_tags_preserve_sdk_weight(self):
        with patch.object(sl, "frame_of", return_value=frame()):
            result = sl.slice_key(self.dx, "Api->record", descriptor="(I)V",
                                  include_arguments=False, package="demo")
        self.assertEqual(result["guard_count_third_party_sdk"], 1)
        self.assertEqual(result["guard_count"], 1)
        self.assertEqual(result["activation_cost"], 1)
        self.assertEqual(result["guards"][0]["notes"], ["third_party_sdk"])
        ktor_guard = {"operand": {"source_kind": "instanceof", "detail": "Lio/ktor/http/OutgoingContent;"}}
        self.assertTrue(sl._is_framework_guard(ktor_guard))

    def test_viewmodel_candidate_keeps_searching_and_compose_dead_end_is_diagnostic(self):
        ctor = Method("LDemoViewModel;", "<init>")
        compose = Method("Ldemo/ComposableSingletons$ScreenKt;", "render")
        ctor.callers = [(compose, 1)]
        self.dx.classes[ctor.class_name] = Class(ctor, parent="Landroidx/lifecycle/ViewModel;")
        self.api.callers = [(ctor, 2)]
        with patch.object(sl, "frame_of", return_value=frame()):
            result = self.analyze()
        self.assertIn("viewmodel_constructor_candidate", result["notes"])
        self.assertIn("possible_compose_dead_end", result["notes"])
        self.assertFalse(result["activation_exact"])
        self.assertEqual(result["first_uncertain_hop"], 1)
