#!/usr/bin/env python3
"""
tests/test_chain_lb_nodes.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты LB-состава (выбор нод для балансировки) VLESS-каскада
(Режим B): chimera/modules/chain_nodes.py (_normalize_lb_nodes /
_lb_effective_nodes / _lb_selector_tags / _lb_nodes_summary /
_lb_selection_from_state / set_lb_nodes) + chimera/modules/
smart_balancer.py (_sb_lb_selection / _sb_probe_plan).

Зеркало тестов lb_exits AWG (test_awg_cascade_lb) и Mieru
(test_mieru_cascade_lb_exits): пусто = все, <2 валидных = фолбэк на
все, молчаливая одиночная нода запрещена, пиннинг ортогонален составу.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import chain_nodes as cn          # noqa: E402
from chimera.modules import smart_balancer as sb       # noqa: E402


NODES = [
    {"host": "fi.fleet-b.example", "port": 443, "sni": "fi.fleet-b.example"},
    {"host": "fleet-b.example",    "port": 443, "sni": "fleet-b.example"},
    {"host": "fleet-c.example",        "port": 443, "sni": "fleet-c.example"},
    {"host": "fleet-a.example",     "port": 443, "sni": "fleet-a.example"},
]
TAGS = ["chain-exit-1", "chain-exit-2", "chain-exit-3", "chain-exit-4"]


# ── _normalize_lb_nodes ──────────────────────────────────────────────────────

class TestNormalize(unittest.TestCase):

    def test_none_and_empty_mean_all(self):
        self.assertEqual(cn._normalize_lb_nodes(None, NODES), [])
        self.assertEqual(cn._normalize_lb_nodes([], NODES), [])

    def test_unknown_dropped_dup_dedup(self):
        self.assertEqual(
            cn._normalize_lb_nodes(
                ["fleet-c.example", "no.such.host", "fleet-c.example"], NODES),
            ["fleet-c.example"])

    def test_order_follows_chain_nodes(self):
        # ввод в обратном порядке — порядок по chain_nodes
        self.assertEqual(
            cn._normalize_lb_nodes(
                ["fleet-a.example", "fleet-c.example"], NODES),
            ["fleet-c.example", "fleet-a.example"])

    def test_case_insensitive_and_strip(self):
        self.assertEqual(
            cn._normalize_lb_nodes(["  FLEET-C.EXAMPLE "], NODES),
            ["fleet-c.example"])

    def test_empty_strings_ignored(self):
        self.assertEqual(cn._normalize_lb_nodes(["", "  ", None], NODES), [])


# ── _lb_effective_nodes ──────────────────────────────────────────────────────

class TestEffective(unittest.TestCase):

    def test_empty_selection_all(self):
        eff = cn._lb_effective_nodes(NODES, [])
        self.assertEqual(eff, NODES)
        self.assertIsNot(eff, NODES)      # копия, не тот же объект

    def test_none_selection_all(self):
        self.assertEqual(cn._lb_effective_nodes(NODES, None), NODES)

    def test_two_of_four(self):
        eff = cn._lb_effective_nodes(NODES, ["fleet-c.example",
                                             "fleet-a.example"])
        self.assertEqual([n["host"] for n in eff],
                         ["fleet-c.example", "fleet-a.example"])

    def test_single_valid_fallback_all(self):
        # <2 валидных — фолбэк на все (молчаливая одиночная нода запрещена)
        eff = cn._lb_effective_nodes(NODES, ["fleet-c.example"])
        self.assertEqual(eff, NODES)

    def test_all_unknown_fallback_all(self):
        eff = cn._lb_effective_nodes(NODES, ["a.xxx", "b.yyy"])
        self.assertEqual(eff, NODES)

    def test_three_of_four(self):
        # N-способность: тройка
        eff = cn._lb_effective_nodes(
            NODES, ["fi.fleet-b.example", "fleet-c.example",
                    "fleet-a.example"])
        self.assertEqual(len(eff), 3)

    def test_case_variants_selected(self):
        eff = cn._lb_effective_nodes(NODES, ["FLEET-C.EXAMPLE",
                                             "Fleet-A.Example"])
        self.assertEqual(len(eff), 2)


# ── _lb_selector_tags ────────────────────────────────────────────────────────

class TestSelectorTags(unittest.TestCase):

    def test_empty_selection_all_tags(self):
        self.assertEqual(cn._lb_selector_tags(TAGS, NODES, []),
                         TAGS)

    def test_subset_maps_to_tags(self):
        self.assertEqual(
            cn._lb_selector_tags(TAGS, NODES,
                                 ["fleet-a.example", "fleet-c.example"]),
            ["chain-exit-3", "chain-exit-4"])

    def test_invalid_selection_all_tags(self):
        # 1 валидный → фолбэк на все → все теги
        self.assertEqual(
            cn._lb_selector_tags(TAGS, NODES, ["fleet-c.example"]),
            TAGS)

    def test_length_mismatch_safe(self):
        # outbound_tags короче nodes (защита zip) — не падает
        self.assertEqual(
            cn._lb_selector_tags(TAGS[:2], NODES, []),
            TAGS[:2])


# ── _lb_nodes_summary ────────────────────────────────────────────────────────

class TestSummary(unittest.TestCase):

    def test_all(self):
        self.assertEqual(cn._lb_nodes_summary(NODES, []), "все (4)")

    def test_subset(self):
        self.assertEqual(
            cn._lb_nodes_summary(NODES, ["fleet-c.example",
                                         "fleet-a.example"]),
            "fleet-c.example, fleet-a.example (2 из 4)")

    def test_invalid_shows_all(self):
        self.assertEqual(cn._lb_nodes_summary(NODES, ["zzz"]),
                         "все (4)")

    def test_empty_fleet(self):
        self.assertEqual(cn._lb_nodes_summary([], []), "—")


# ── _lb_selection_from_state ─────────────────────────────────────────────────

class TestSelectionFromState(unittest.TestCase):

    def test_reads_state_file(self):
        with tempfile.TemporaryDirectory() as td:
            stf = Path(td) / "state.json"
            stf.write_text(json.dumps(
                {"chain_lb_nodes": ["fleet-c.example"]}))
            with patch.object(cn, "_CHAIN_STATE_FILE", stf):
                self.assertEqual(cn._lb_selection_from_state(None),
                                 ["fleet-c.example"])

    def test_missing_file_empty(self):
        with patch.object(cn, "_CHAIN_STATE_FILE",
                          Path("/nonexistent/state.json")):
            self.assertEqual(cn._lb_selection_from_state(None), [])

    def test_core_global_wins(self):
        class _Core:
            CHAIN_LB_NODES = ["a.ru"]
            STATE_FILE = Path("/nonexistent/state.json")
        self.assertEqual(cn._lb_selection_from_state(_Core), ["a.ru"])


# ── smart_balancer: _sb_lb_selection / _sb_probe_plan ────────────────────────

class TestSmartBalancerPlan(unittest.TestCase):

    def test_selection_none_when_empty(self):
        self.assertIsNone(sb._sb_lb_selection({}))
        self.assertIsNone(sb._sb_lb_selection({"chain_lb_nodes": []}))
        self.assertIsNone(sb._sb_lb_selection(None))

    def test_selection_lowered_set(self):
        self.assertEqual(
            sb._sb_lb_selection({"chain_lb_nodes": ["  FLEET-C.EXAMPLE "]}),
            {"fleet-c.example"})

    def test_non_list_is_none(self):
        self.assertIsNone(sb._sb_lb_selection({"chain_lb_nodes": "x"}))

    def test_plan_all_when_none(self):
        plan = sb._sb_probe_plan(NODES, None)
        self.assertEqual([i for i, _ in plan], [0, 1, 2, 3])

    def test_plan_subset_keeps_original_indices(self):
        plan = sb._sb_probe_plan(NODES, {"fleet-c.example",
                                         "fleet-a.example"})
        self.assertEqual([(i, n["host"]) for i, n in plan],
                         [(2, "fleet-c.example"),
                          (3, "fleet-a.example")])

    def test_plan_empty_when_no_known(self):
        self.assertEqual(sb._sb_probe_plan(NODES, {"zzz.io"}), [])


# ── set_lb_nodes: state + хирургический патч конфига (tmp-файлы) ─────────────

_LIVE_CFG = {
    "routing": {
        "balancers": [{
            "tag": "chain-balancer",
            "selector": ["chain-exit-1", "chain-exit-2",
                         "chain-exit-3", "chain-exit-4"],
            "strategy": {"type": "roundRobin"},
        }],
        "rules": [{"type": "field", "network": "tcp",
                   "balancerTag": "chain-balancer"}],
    },
    "observatory": {
        "subjectSelector": ["chain-exit-"],
        "probeUrl": "https://1.1.1.1/cdn-cgi/trace",
    },
    "outbounds": (
        [{"tag": f"chain-exit-{i+1}",
          "protocol": "vless",
          "settings": {"vnext": [{"address": nd["host"], "port": 443,
                                  "users": []}]}}
         for i, nd in enumerate(NODES)] +
        [{"tag": "direct", "protocol": "freedom"}]
    ),
}


class TestSetLbNodes(unittest.TestCase):

    def _setup(self, td):
        stf = Path(td) / "state.json"
        stf.write_text(json.dumps({"chain_nodes": NODES}))
        cfgf = Path(td) / "config.json"
        cfgf.write_text(json.dumps(_LIVE_CFG))
        return stf, cfgf

    def test_reject_lt2_known(self):
        with tempfile.TemporaryDirectory() as td:
            stf, cfgf = self._setup(td)
            with patch.object(cn, "_CHAIN_STATE_FILE", stf), \
                 patch.object(cn, "_CHAIN_CONFIG_FILE", cfgf):
                self.assertFalse(cn.set_lb_nodes(["fleet-c.example"],
                                                 restart=False))
            # state не изменился
            self.assertEqual(json.loads(stf.read_text()).get(
                "chain_lb_nodes"), None)

    def test_apply_subset_patches_selector(self):
        with tempfile.TemporaryDirectory() as td:
            stf, cfgf = self._setup(td)
            with patch.object(cn, "_CHAIN_STATE_FILE", stf), \
                 patch.object(cn, "_CHAIN_CONFIG_FILE", cfgf):
                self.assertTrue(cn.set_lb_nodes(
                    ["fleet-c.example", "fleet-a.example"],
                    restart=False))
            st = json.loads(stf.read_text())
            self.assertEqual(st["chain_lb_nodes"],
                             ["fleet-c.example", "fleet-a.example"])
            cfg = json.loads(cfgf.read_text())
            b = cfg["routing"]["balancers"][0]
            self.assertEqual(b["selector"],
                             ["chain-exit-3", "chain-exit-4"])
            # observatory.subjectSelector синхронизирован с selector
            self.assertEqual(cfg["observatory"]["subjectSelector"],
                             ["chain-exit-3", "chain-exit-4"])
            # outbounds — superset (невыбранные не удаляются)
            tags = [ob["tag"] for ob in cfg["outbounds"]
                    if ob["tag"].startswith("chain-exit")]
            self.assertEqual(tags, TAGS)

    def test_apply_resyncs_stale_smartbalancer_patch(self):
        # устаревший патч smart_balancer'а в чужом слоте снимается:
        # chain-exit-1 указывает на ru, хотя его хост по state — fi
        with tempfile.TemporaryDirectory() as td:
            stf, cfgf = self._setup(td)
            cfg = json.loads(cfgf.read_text())
            cfg["outbounds"][0]["settings"]["vnext"][0]["address"] = \
                "fleet-c.example"
            cfgf.write_text(json.dumps(cfg))
            with patch.object(cn, "_CHAIN_STATE_FILE", stf), \
                 patch.object(cn, "_CHAIN_CONFIG_FILE", cfgf):
                self.assertTrue(cn.set_lb_nodes(
                    ["fi.fleet-b.example", "fleet-c.example"],
                    restart=False))
            patched = json.loads(cfgf.read_text())
            by_tag = {ob["tag"]: ob for ob in patched["outbounds"]}
            # chain-exit-1 (fi) восстановлен на свой хост
            self.assertEqual(
                by_tag["chain-exit-1"]["settings"]["vnext"][0]["address"],
                "fi.fleet-b.example")
            # невыбранный chain-exit-2 НЕ тронут (остаётся как был)
            self.assertEqual(
                by_tag["chain-exit-2"]["settings"]["vnext"][0]["address"],
                "fleet-b.example")

    def test_apply_all_clears_selection(self):
        with tempfile.TemporaryDirectory() as td:
            stf, cfgf = self._setup(td)
            stf.write_text(json.dumps({
                "chain_nodes": NODES,
                "chain_lb_nodes": ["fleet-c.example"]}))
            with patch.object(cn, "_CHAIN_STATE_FILE", stf), \
                 patch.object(cn, "_CHAIN_CONFIG_FILE", cfgf):
                self.assertTrue(cn.set_lb_nodes(None, restart=False))
            st = json.loads(stf.read_text())
            self.assertEqual(st["chain_lb_nodes"], [])
            cfg = json.loads(cfgf.read_text())
            # пустой выбор → selector не сужается (все теги остаются)
            self.assertEqual(cfg["routing"]["balancers"][0]["selector"],
                             TAGS)

    def test_reject_when_fleet_lt2(self):
        with tempfile.TemporaryDirectory() as td:
            stf = Path(td) / "state.json"
            stf.write_text(json.dumps({"chain_nodes": NODES[:1]}))
            cfgf = Path(td) / "config.json"
            cfgf.write_text(json.dumps(_LIVE_CFG))
            with patch.object(cn, "_CHAIN_STATE_FILE", stf), \
                 patch.object(cn, "_CHAIN_CONFIG_FILE", cfgf):
                self.assertFalse(cn.set_lb_nodes(["x"], restart=False))

    def test_no_balancer_only_state(self):
        # pinned/одна нода: balancers нет — сохраняется только state
        with tempfile.TemporaryDirectory() as td:
            stf, cfgf = self._setup(td)
            cfg = json.loads(cfgf.read_text())
            del cfg["routing"]["balancers"]
            cfgf.write_text(json.dumps(cfg))
            with patch.object(cn, "_CHAIN_STATE_FILE", stf), \
                 patch.object(cn, "_CHAIN_CONFIG_FILE", cfgf):
                self.assertTrue(cn.set_lb_nodes(
                    ["fleet-c.example", "fleet-a.example"],
                    restart=False))
            st = json.loads(stf.read_text())
            self.assertEqual(len(st["chain_lb_nodes"]), 2)


# ── _sb_patch_xray_active_node: приоритет outbound'ов из selector ────────────

class TestPatchPriority(unittest.TestCase):

    def test_patches_first_selected_outbound(self):
        with tempfile.TemporaryDirectory() as td:
            cfgf = Path(td) / "config.json"
            cfg = json.loads(json.dumps(_LIVE_CFG))
            # состав = chain-exit-3/-4 → патчиться должен chain-exit-3
            cfg["routing"]["balancers"][0]["selector"] = \
                ["chain-exit-3", "chain-exit-4"]
            cfgf.write_text(json.dumps(cfg))
            with patch.object(sb, "_sb_get_xray_config_path",
                              return_value=cfgf):
                ok = sb._sb_patch_xray_active_node(
                    {"host": "new.example.org", "port": 443,
                     "uuid": "u1", "sni": "sni", "pubkey": "pk",
                     "short_id": "sid", "fp": "chrome"})
            self.assertTrue(ok)
            patched = json.loads(cfgf.read_text())
            by_tag = {ob["tag"]: ob for ob in patched["outbounds"]}
            self.assertEqual(
                by_tag["chain-exit-3"]["settings"]["vnext"][0]["address"],
                "new.example.org")
            # chain-exit-1 (вне состава) не тронут
            self.assertEqual(
                by_tag["chain-exit-1"]["settings"]["vnext"][0]["address"],
                "fi.fleet-b.example")


if __name__ == "__main__":
    unittest.main(verbosity=2)
