#!/usr/bin/env python3
"""
tests/test_hysteria2_balancer.py — _live_nodes, _weighted_random, _least_rtt,
_round_robin, _auto_adjust_weights
"""
from __future__ import annotations
import json
import sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

def _setup_core():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text(); g = {}
    with patch.object(Path, 'mkdir', lambda s,*a,**k: None), \
         patch.object(Path, 'touch', lambda s,*a,**k: None), \
         patch.object(Path, 'chmod', lambda s,*a,**k: None), \
         patch('os.chown', lambda *a,**k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types; m = types.ModuleType("chimera._core"); m.__dict__.update(g)
    sys.modules["chimera._core"] = m

class TestLiveNodes(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_filters_down(self):
        from chimera.modules.hysteria2_balancer import _live_nodes
        nodes = [{"status":"up"},{"status":"down"},{"status":"ok"}]
        live = _live_nodes(nodes)
        self.assertEqual(len(live), 2)
    def test_empty(self):
        from chimera.modules.hysteria2_balancer import _live_nodes
        self.assertEqual(_live_nodes([]), [])

class TestWeightedRandom(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_returns_none_when_empty(self):
        from chimera.modules.hysteria2_balancer import _weighted_random
        self.assertIsNone(_weighted_random([]))
    def test_returns_node(self):
        from chimera.modules.hysteria2_balancer import _weighted_random
        nodes = [{"weight":1.0,"status":"up"}]
        result = _weighted_random(nodes)
        self.assertIsNotNone(result)
    def test_clamps_zero_weight(self):
        from chimera.modules.hysteria2_balancer import _weighted_random
        nodes = [{"weight":0,"status":"up"},{"weight":0,"status":"up"}]
        result = _weighted_random(nodes)
        self.assertIsNotNone(result)

class TestLeastRtt(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_returns_none_when_empty(self):
        from chimera.modules.hysteria2_balancer import _least_rtt
        self.assertIsNone(_least_rtt([]))
    def test_returns_min_rtt(self):
        from chimera.modules.hysteria2_balancer import _least_rtt
        nodes = [{"metrics":{"rtt_ms":100}},{"metrics":{"rtt_ms":50}},{"metrics":{"rtt_ms":200}}]
        result = _least_rtt(nodes)
        self.assertEqual(result["metrics"]["rtt_ms"], 50)
    def test_ignores_zero_rtt(self):
        from chimera.modules.hysteria2_balancer import _least_rtt
        nodes = [{"metrics":{"rtt_ms":0}},{"metrics":{"rtt_ms":50}}]
        result = _least_rtt(nodes)
        self.assertEqual(result["metrics"]["rtt_ms"], 50)

class TestRoundRobin(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_returns_none_when_empty(self):
        from chimera.modules.hysteria2_balancer import _round_robin
        self.assertIsNone(_round_robin([], 0))
    def test_wraps_around(self):
        from chimera.modules.hysteria2_balancer import _round_robin
        nodes = [{"host":"a"},{"host":"b"},{"host":"c"}]
        self.assertEqual(_round_robin(nodes, 0)["host"], "a")
        self.assertEqual(_round_robin(nodes, 1)["host"], "b")
        self.assertEqual(_round_robin(nodes, 2)["host"], "c")
        self.assertEqual(_round_robin(nodes, 3)["host"], "a")

class TestAutoAdjustWeights(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_returns_list(self):
        from chimera.modules import hysteria2_balancer
        nodes = [{"ip":"1.1.1.1","metrics":{"rtt_ms":50,"loss_pct":0},"weight":1.0},
                 {"ip":"2.2.2.2","metrics":{"rtt_ms":100,"loss_pct":0},"weight":1.0}]
        with patch.object(hysteria2_balancer, "log_to_file"):
            result = hysteria2_balancer._auto_adjust_weights(nodes)
        self.assertEqual(len(result), 2)
        self.assertGreater(result[0]["weight"], result[1]["weight"])


# ══════════════════════════════════════════════════════════════════════════════
#  Волна-2 (11.11.2026): метки нод в h2_switch/h2_weights — канон node_identity
#  («alias · домен [IP](:порт)») вместо голого ip. Герметичность: state/DNS-кэш
#  node_identity на tmp, транспорт/health подменены, _tg_h2_event перехвачен.
# ══════════════════════════════════════════════════════════════════════════════

class _BalancerTmpBase(unittest.TestCase):
    def setUp(self):
        _setup_core()
        import time as _time
        from chimera.modules import hysteria2_balancer as bal
        from chimera.modules import node_identity as _ni
        self._bal = bal
        self._ni = _ni
        self._now = _time.time()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(self._rmtree)
        for p in (
            patch.object(_ni, "STATE_FILE", self.tmp / "state.json"),
            patch.object(_ni, "TG_FILE", self.tmp / "tg-absent.json"),
            patch.object(_ni, "DNS_CACHE_FILE", self.tmp / "node_dns_cache.json"),
            patch.object(_ni, "ALIASES_FILE", self.tmp / "aliases-absent.json"),
        ):
            p.start()
            self.addCleanup(p.stop)
        _ni._MEM.clear()
        self.addCleanup(_ni._MEM.clear)
        self.events: list[tuple] = []
        for p in (
            patch.object(bal, "_tg_h2_event",
                         lambda ev, detail="": self.events.append((ev, detail))),
            patch.object(bal, "_save_h2_state", lambda h2: None),
            patch.object(bal, "log_to_file", lambda *a, **k: None),
        ):
            p.start()
            self.addCleanup(p.stop)

    def _rmtree(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _fill_dns(self, host: str, ip: str):
        (self.tmp / "node_dns_cache.json").write_text(json.dumps(
            {host: {"ip": ip, "ts": self._now}}))
        self._ni._MEM.clear()


class TestSwitchEventLabel(_BalancerTmpBase):
    """run_once: h2_switch «Балансировщик → метка ноды»."""

    def test_switch_event_carries_label(self):
        from chimera.modules import hysteria2_balancer as bal
        self._fill_dns("node-h2b.example.com", "203.0.113.99")
        state = {
            "exit_nodes": [
                {"ip": "203.0.113.10", "ports": [443], "auth": "a",
                 "weight": 1.0, "status": "down",
                 "metrics": {"rtt_ms": 200, "loss_pct": 100.0}},
            ],
            "_active_node_ip": "203.0.113.10",
            "balancer": {"switch_threshold": 0.5},
        }
        best = {"ip": "node-h2b.example.com", "ports": [8443], "auth": "x",
                "name": "H2-B", "status": "active",
                "metrics": {"rtt_ms": 20, "loss_pct": 0.0}, "weight": 1.0}
        with patch.object(bal, "_load_h2_state", lambda: dict(state)), \
             patch("chimera.modules.hysteria2_health.h2_health_check_all",
                   return_value=state["exit_nodes"]), \
             patch.object(bal, "h2_balancer_select_node", return_value=best), \
             patch("chimera.modules.hysteria2_transport.h2_transport_apply",
                   return_value=True), \
             patch.object(bal, "info", lambda *a, **k: None):
            self.assertTrue(bal.h2_balancer_run_once())
        self.assertEqual([e for e, _ in self.events], ["h2_switch"])
        self.assertIn("Балансировщик → H2-B · node-h2b.example.com "
                      "[203.0.113.99]:8443", self.events[0][1])
        # голого ip в уведе больше нет
        self.assertNotIn("→ node-h2b.example.com:", self.events[0][1])


class TestWeightsEventLabel(_BalancerTmpBase):
    """_set_node_weight: h2_weights «Вес метка → W» вместо голого ip."""

    def test_manual_weight_event_carries_label(self):
        from chimera.modules import hysteria2_balancer as bal
        state = {"exit_nodes": [
            {"ip": "203.0.113.10", "ports": [443], "auth": "a",
             "weight": 1.0, "status": "active"},
        ]}
        inputs = iter(["1", "2.5", ""])
        with patch.object(bal, "_load_h2_state", lambda: dict(state)), \
             patch("builtins.input", side_effect=lambda p="": next(inputs)), \
             patch.object(bal, "success", lambda *a, **k: None):
            bal._set_node_weight()
        self.assertEqual([e for e, _ in self.events], ["h2_weights"])
        self.assertIn("Вес 203.0.113.10 → 2.5", self.events[0][1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
