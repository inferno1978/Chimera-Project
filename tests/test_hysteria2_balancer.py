#!/usr/bin/env python3
"""
tests/test_hysteria2_balancer.py — _live_nodes, _weighted_random, _least_rtt,
_round_robin, _auto_adjust_weights
"""
from __future__ import annotations
import sys, unittest
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

if __name__ == "__main__":
    unittest.main(verbosity=2)
