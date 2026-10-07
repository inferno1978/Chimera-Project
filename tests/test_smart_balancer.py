#!/usr/bin/env python3
"""
tests/test_smart_balancer.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/smart_balancer.py.

Покрывает:
  1. _compute_score — расчёт score (pure math)
  2. _is_quarantined — проверка карантина
  3. _quarantine_node — установка карантина
  4. _release_from_quarantine — снятие карантина
  5. _sb_load / _sb_save — JSON I/O
  6. _awg_guard_cron — проверка AWG-режима
  7. _probe_tcp_latency — TCP проверка (mocked socket)
  8. _sb_get_relay_hops — активные relay_hops из state.json
  9. _sb_relay_probe_target — цель зонда (via-aware, pure)
 10. _sb_native_balancer_selector_tags — selector живого chain-balancer
 11. run_once — сценарии: наблюдение при нативной ротации, классический
     патч без балансировщика, зонд релейной ноды в хоп
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core


class TestComputeScore(unittest.TestCase):
    """_compute_score — pure math."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _weights(self):
        return {"latency": 0.5, "bandwidth": 0.3, "load": 0.2}

    def test_perfect_metrics_returns_zero(self):
        """lat=0, bw=0, load=0 → все нормированные значения = 0 → score = 0.
        После фикса: lat=0 трактуется как идеальный пинг (0 falsy больше не
        подменяется на NORM_LAT_MS_WORST)."""
        from chimera.modules.smart_balancer import _compute_score
        score = _compute_score(0, 0, 0, self._weights())
        # w_lat*0 + w_bw*0 + w_ld*0 = 0.0
        self.assertEqual(score, 0.0)

    def test_zero_latency_not_treated_as_worst(self):
        """Regression: lat=0 (идеальный пинг) НЕ должен трактоваться как worst.
        Раньше `0 or NORM` = NORM из-за falsy-семантики 0.0 в Python.
        После фикса: `0 if 0 is not None else NORM` = 0 → lat_norm = 0."""
        from chimera.modules.smart_balancer import _compute_score
        perfect = _compute_score(0, 100, 100, self._weights())
        worst = _compute_score(2000, 100, 100, self._weights())  # lat=NORM_WORST
        self.assertLess(perfect, worst,
                        "lat=0 (идеальный пинг) должен давать МЕНЬШИЙ score, чем lat=NORM_WORST")

    def test_none_metrics_returns_one(self):
        """lat=None, bw=None, load=None → все берут NORM_*_WORST → score = 1.0.
        После фикса: load=None поддерживается (раньше падал с TypeError)."""
        from chimera.modules.smart_balancer import _compute_score
        score = _compute_score(None, None, None, self._weights())
        # w_lat*1 + w_bw*1 + w_ld*1 = 1.0
        self.assertAlmostEqual(score, 1.0, places=4)

    def test_none_load_treated_as_worst(self):
        """Regression: load=None → берётся NORM_LOAD_WORST (200) → load_norm=1.0.
        Раньше load=None падал с TypeError (не было `or NORM` fallback).
        После фикса: `load if load is not None else NORM_LOAD_WORST`."""
        from chimera.modules.smart_balancer import _compute_score
        score = _compute_score(None, None, None, self._weights())
        # load_norm = 1.0 → w_ld*1 = 0.2
        # но проще проверить через изолированный load=None vs load=200
        score_none = _compute_score(0, 0, None, self._weights())
        score_worst = _compute_score(0, 0, 200, self._weights())  # load=NORM_LOAD_WORST
        self.assertAlmostEqual(score_none, score_worst, places=4)
        # и это больше чем score при load=0
        score_zero = _compute_score(0, 0, 0, self._weights())
        self.assertGreater(score_none, score_zero)

    def test_high_latency_higher_score(self):
        from chimera.modules.smart_balancer import _compute_score
        low = _compute_score(10, 10, 10, self._weights())
        high = _compute_score(1000, 10, 10, self._weights())
        self.assertGreater(high, low)

    def test_clamps_to_one(self):
        """Метрики выше NORM → clamp на 1.0."""
        from chimera.modules.smart_balancer import _compute_score
        score = _compute_score(999999, 999999, 999999, self._weights())
        self.assertLessEqual(score, 1.0)

    def test_rounded_to_4_decimal_places(self):
        from chimera.modules.smart_balancer import _compute_score
        score = _compute_score(100, 200, 50, self._weights())
        # проверяем что не больше 4 знаков после запятой
        decimal_part = str(score).split(".")[1] if "." in str(score) else ""
        self.assertLessEqual(len(decimal_part), 4)


class TestIsQuarantined(unittest.TestCase):
    """_is_quarantined — pure."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_false_when_no_quarantine(self):
        from chimera.modules.smart_balancer import _is_quarantined
        self.assertFalse(_is_quarantined({}))

    def test_returns_false_when_quarantine_in_past(self):
        from chimera.modules.smart_balancer import _is_quarantined
        meta = {"quarantine_until": time.time() - 100}
        self.assertFalse(_is_quarantined(meta))

    def test_returns_true_when_quarantine_in_future(self):
        from chimera.modules.smart_balancer import _is_quarantined
        meta = {"quarantine_until": time.time() + 3600}
        self.assertTrue(_is_quarantined(meta))


class TestQuarantineNode(unittest.TestCase):
    """_quarantine_node — pure mutation."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_sets_quarantine_until(self):
        from chimera.modules.smart_balancer import _quarantine_node
        meta = {}
        now = time.time()
        with patch("time.time", return_value=now):
            _quarantine_node(meta, minutes=30)
        self.assertAlmostEqual(meta["quarantine_until"], now + 30 * 60, places=1)

    def test_sets_quarantine_until_str(self):
        from chimera.modules.smart_balancer import _quarantine_node
        meta = {}
        _quarantine_node(meta, minutes=30)
        self.assertIn("quarantine_until_str", meta)


class TestReleaseFromQuarantine(unittest.TestCase):
    """_release_from_quarantine — pure mutation."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_resets_quarantine_until(self):
        from chimera.modules.smart_balancer import _release_from_quarantine
        meta = {"quarantine_until": time.time() + 3600, "fails": 5}
        _release_from_quarantine(meta)
        self.assertEqual(meta["quarantine_until"], 0)
        self.assertEqual(meta["fails"], 0)

    def test_removes_quarantine_until_str(self):
        from chimera.modules.smart_balancer import _release_from_quarantine
        meta = {"quarantine_until_str": "2026-07-10 12:00", "fails": 3}
        _release_from_quarantine(meta)
        self.assertNotIn("quarantine_until_str", meta)


class TestSbLoadSave(unittest.TestCase):
    """_sb_load / _sb_save — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "sb.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.smart_balancer._SB_STATE_FILE",
                     self._state)

    def test_load_returns_default_when_no_file(self):
        from chimera.modules.smart_balancer import _sb_load
        with self._patch():
            state = _sb_load()
        self.assertFalse(state["enabled"])
        self.assertEqual(state["strategy"], "smart")
        self.assertEqual(state["active_node_idx"], -1)

    def test_load_returns_default_on_corrupt(self):
        from chimera.modules.smart_balancer import _sb_load
        self._state.write_text("{invalid")
        with self._patch():
            state = _sb_load()
        self.assertFalse(state["enabled"])

    def test_save_then_load(self):
        from chimera.modules.smart_balancer import _sb_load, _sb_save
        with self._patch():
            _sb_save({"enabled": True, "strategy": "leastping", "active_node_idx": 0})
            loaded = _sb_load()
        self.assertTrue(loaded["enabled"])
        self.assertEqual(loaded["strategy"], "leastping")

    def test_save_sets_chmod_600(self):
        import stat
        from chimera.modules.smart_balancer import _sb_save
        with self._patch():
            _sb_save({"enabled": False})
        mode = stat.S_IMODE(os.stat(self._state).st_mode)
        self.assertEqual(mode, 0o600)


class TestAwgGuardCron(unittest.TestCase):
    """_awg_guard_cron — проверка AWG-режима."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.smart_balancer._STATE_FILE",
                     self._state)

    def test_returns_false_when_no_state(self):
        from chimera.modules.smart_balancer import _awg_guard_cron
        with self._patch():
            self.assertFalse(_awg_guard_cron("test"))

    def test_returns_true_for_awg_mode_b(self):
        from chimera.modules.smart_balancer import _awg_guard_cron
        self._state.write_text(json.dumps({
            "awg_exit_enabled": True, "install_mode": "B",
        }))
        with self._patch():
            self.assertTrue(_awg_guard_cron("test"))

    def test_returns_false_for_non_awg(self):
        from chimera.modules.smart_balancer import _awg_guard_cron
        self._state.write_text(json.dumps({
            "awg_exit_enabled": False, "install_mode": "A",
        }))
        with self._patch():
            self.assertFalse(_awg_guard_cron("test"))

    def test_returns_false_for_awg_mode_not_b(self):
        from chimera.modules.smart_balancer import _awg_guard_cron
        self._state.write_text(json.dumps({
            "awg_exit_enabled": True, "install_mode": "A",
        }))
        with self._patch():
            self.assertFalse(_awg_guard_cron("test"))


class TestProbeTcpLatency(unittest.TestCase):
    """_probe_tcp_latency — TCP проверка (mocked socket).

    6b55d47 (prefer IPv4) переписал функцию с socket.create_connection на
    getaddrinfo + socket().connect(sockaddr) — старый мок create_connection
    перестал перехватывать что-либо, и тест зависел от сетевого окружения
    (в без-DNS контейнере getaddrinfo падал → inf → FAIL). Теперь мокаем
    актуальный API — детерминизм в любом окружении.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        import socket as _socket
        self._fake_addr = (_socket.AF_INET, _socket.SOCK_STREAM,
                           6, "", ("1.2.3.4", 443))

    def test_returns_positive_on_success(self):
        from chimera.modules.smart_balancer import _probe_tcp_latency
        with patch("socket.getaddrinfo", return_value=[self._fake_addr]), \
             patch("socket.socket") as mock_sock_cls:
            mock_sock_cls.return_value = MagicMock()
            result = _probe_tcp_latency("1.2.3.4", 443)
        self.assertGreaterEqual(result, 0)
        self.assertLess(result, float("inf"))
        # connect обязан идти через SOCKADDR (не через host:port повторно).
        inst = mock_sock_cls.return_value
        inst.connect.assert_called_once_with(("1.2.3.4", 443))

    def test_returns_inf_on_failure(self):
        from chimera.modules.smart_balancer import _probe_tcp_latency
        with patch("socket.getaddrinfo", return_value=[self._fake_addr]), \
             patch("socket.socket") as mock_sock_cls:
            mock_sock_cls.return_value = MagicMock()
            mock_sock_cls.return_value.connect.side_effect = OSError(
                "conn refused")
            result = _probe_tcp_latency("1.2.3.4", 443)
        self.assertEqual(result, float("inf"))

    def test_returns_inf_on_dns_failure(self):
        from chimera.modules.smart_balancer import _probe_tcp_latency
        with patch("socket.getaddrinfo",
                   side_effect=OSError("dns unreachable")):
            result = _probe_tcp_latency("nonexistent.invalid", 443)
        self.assertEqual(result, float("inf"))

    def test_prefers_ipv4_over_ipv6(self):
        """Регрессия 6b55d47: при наличии A и AAAA пробуем IPv4 первым."""
        import socket as _socket
        from chimera.modules.smart_balancer import _probe_tcp_latency
        addrs = [
            (_socket.AF_INET6, _socket.SOCK_STREAM, 6, "",
             ("2001:db8::1", 443, 0, 0)),
            (_socket.AF_INET, _socket.SOCK_STREAM, 6, "", ("1.2.3.4", 443)),
        ]
        with patch("socket.getaddrinfo", return_value=addrs), \
             patch("socket.socket") as mock_sock_cls:
            mock_sock_cls.return_value = MagicMock()
            result = _probe_tcp_latency("dual.example", 443)
        self.assertLess(result, float("inf"))
        # Первый созданный сокет — IPv4 (AF_INET).
        first_family = mock_sock_cls.call_args_list[0].args[0]
        self.assertEqual(first_family, _socket.AF_INET)


class TestSbGetRelayHops(unittest.TestCase):
    """_sb_get_relay_hops — активные relay_hops из state.json."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.smart_balancer._STATE_FILE",
                     self._state)

    def test_empty_when_no_state(self):
        from chimera.modules.smart_balancer import _sb_get_relay_hops
        with self._patch():
            self.assertEqual(_sb_get_relay_hops(), [])

    def test_returns_enabled_hops_only(self):
        from chimera.modules.smart_balancer import _sb_get_relay_hops
        self._state.write_text(json.dumps({"relay_hops": [
            {"tag": "hop-a", "host": "hop-a.example", "port": 443,
             "enabled": True},
            {"tag": "hop-b", "host": "hop-b.example", "port": 443,
             "enabled": False},
        ]}))
        with self._patch():
            hops = _sb_get_relay_hops()
        self.assertEqual(len(hops), 1)
        self.assertEqual(hops[0]["tag"], "hop-a")

    def test_enabled_defaults_true(self):
        from chimera.modules.smart_balancer import _sb_get_relay_hops
        self._state.write_text(json.dumps({"relay_hops": [
            {"tag": "hop-c", "host": "hop-c.example", "port": 8443},
        ]}))
        with self._patch():
            self.assertEqual(len(_sb_get_relay_hops()), 1)

    def test_garbage_state_returns_empty(self):
        from chimera.modules.smart_balancer import _sb_get_relay_hops
        self._state.write_text("{invalid")
        with self._patch():
            self.assertEqual(_sb_get_relay_hops(), [])


class TestSbRelayProbeTarget(unittest.TestCase):
    """_sb_relay_probe_target — цель зонда для ноды (pure)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._hops = [
            {"tag": "hop-a", "host": "hop-a.example", "port": 8443,
             "enabled": True},
            {"tag": "hop-b", "host": "hop-b.example", "port": 443,
             "enabled": False},
        ]

    def test_direct_node_without_via(self):
        from chimera.modules.smart_balancer import _sb_relay_probe_target
        self.assertEqual(
            _sb_relay_probe_target({"host": "n.example", "port": 443},
                                   self._hops),
            ("n.example", 443, ""))

    def test_relayed_node_probes_hop(self):
        from chimera.modules.smart_balancer import _sb_relay_probe_target
        self.assertEqual(
            _sb_relay_probe_target(
                {"host": "n.example", "port": 443, "via": "hop-a"},
                self._hops),
            ("hop-a.example", 8443, "hop-a"))

    def test_disabled_hop_falls_back_to_node(self):
        from chimera.modules.smart_balancer import _sb_relay_probe_target
        self.assertEqual(
            _sb_relay_probe_target(
                {"host": "n.example", "port": 443, "via": "hop-b"},
                self._hops),
            ("n.example", 443, ""))

    def test_unknown_via_falls_back_to_node(self):
        from chimera.modules.smart_balancer import _sb_relay_probe_target
        self.assertEqual(
            _sb_relay_probe_target(
                {"host": "n.example", "port": 443, "via": "nope"},
                self._hops),
            ("n.example", 443, ""))

    def test_missing_port_defaults_443(self):
        from chimera.modules.smart_balancer import _sb_relay_probe_target
        self.assertEqual(
            _sb_relay_probe_target({"host": "n2.example"}, []),
            ("n2.example", 443, ""))

    def test_none_node_is_safe(self):
        from chimera.modules.smart_balancer import _sb_relay_probe_target
        self.assertEqual(_sb_relay_probe_target(None, self._hops),
                         ("", 443, ""))


class TestSbNativeBalancerSelectorTags(unittest.TestCase):
    """_sb_native_balancer_selector_tags — selector живого конфига."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "config.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch(
            "chimera.modules.smart_balancer._sb_get_xray_config_path",
            lambda: self._cfg if self._cfg.exists() else None)

    def test_empty_when_no_config(self):
        from chimera.modules.smart_balancer import _sb_native_balancer_selector_tags
        with patch(
                "chimera.modules.smart_balancer._sb_get_xray_config_path",
                lambda: None):
            self.assertEqual(_sb_native_balancer_selector_tags(), [])

    def test_returns_selector_tags(self):
        from chimera.modules.smart_balancer import _sb_native_balancer_selector_tags
        self._cfg.write_text(json.dumps({"routing": {"balancers": [
            {"tag": "chain-balancer",
             "selector": ["chain-exit-1", "chain-exit-2"],
             "strategy": {"type": "roundRobin"}},
        ]}}))
        with self._patch():
            self.assertEqual(_sb_native_balancer_selector_tags(),
                             ["chain-exit-1", "chain-exit-2"])

    def test_empty_when_no_balancers_section(self):
        from chimera.modules.smart_balancer import _sb_native_balancer_selector_tags
        self._cfg.write_text(json.dumps({"routing": {}}))
        with self._patch():
            self.assertEqual(_sb_native_balancer_selector_tags(), [])

    def test_garbage_config_returns_empty(self):
        from chimera.modules.smart_balancer import _sb_native_balancer_selector_tags
        self._cfg.write_text("{invalid")
        with self._patch():
            self.assertEqual(_sb_native_balancer_selector_tags(), [])


class TestRunOnceObservationAndVia(unittest.TestCase):
    """run_once: сценарии via-aware зондирования и владения ротацией.

    1. Нативный chain-balancer (selector из 2 тегов) владеет ротацией
       при ПУСТОМ chain_lb_nodes («все ноды») — патч адреса НЕ вызывается
       (иначе один слот ротации перезаписывается «лучшей» нодой).
    2. Балансировщика нет — классический режим: патч вызывается
       (обратная совместимость для одной ноды / pinned).
    3. Релейная нода (via=<tag>) зондируется в свой хоп, не напрямую.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"   # installer state
        self._sb    = self._tmpdir / "sb.json"      # SB state
        self._cfg   = self._tmpdir / "config.json"  # xray config

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _alive(self):
        return {"alive": True, "lat_ms": 10.0, "bw_ms": 20.0, "load": 0}

    def _run(self, nodes, cfg_text=None):
        """Запускает run_once с моками; возвращает (mock_patch, mock_reload,
        probe_calls, saved_sb_state)."""
        import chimera.modules.smart_balancer as sbm
        self._state.write_text(json.dumps({
            "chain_nodes": nodes,
            "chain_lb_nodes": [],
        }))
        self._sb.write_text(json.dumps({
            "enabled": True, "strategy": "smart", "active_node_idx": -1,
        }))
        if cfg_text is not None:
            self._cfg.write_text(cfg_text)
        probe_calls = []

        def _fake_probe(host, port):
            probe_calls.append((host, port))
            return self._alive()

        with patch("chimera.modules.smart_balancer._STATE_FILE", self._state), \
             patch("chimera.modules.smart_balancer._SB_STATE_FILE", self._sb), \
             patch("chimera.modules.smart_balancer._sb_get_nodes_from_state",
                   return_value=nodes), \
             patch("chimera.modules.smart_balancer._sb_get_xray_config_path",
                   lambda: self._cfg if self._cfg.exists() else None), \
             patch("chimera.modules.smart_balancer._probe_node",
                   side_effect=_fake_probe), \
             patch("chimera.modules.smart_balancer._sb_patch_xray_active_node") as m_patch, \
             patch("chimera.modules.smart_balancer._sb_reload_xray") as m_reload, \
             patch("chimera.modules.smart_balancer._tg_notify_event"), \
             patch("chimera.modules.smart_balancer._sb_log"):
            sbm._smart_balancer_run_once()
        saved = json.loads(self._sb.read_text())
        return m_patch, m_reload, probe_calls, saved

    _CFG_BALANCER = json.dumps({"routing": {"balancers": [
        {"tag": "chain-balancer",
         "selector": ["chain-exit-1", "chain-exit-2"],
         "strategy": {"type": "roundRobin"}},
    ]}})

    def test_no_patch_when_native_balancer_owns_rotation(self):
        nodes = [{"host": "a.example", "port": 443},
                 {"host": "b.example", "port": 443}]
        m_patch, m_reload, calls, saved = self._run(
            nodes, cfg_text=self._CFG_BALANCER)
        m_patch.assert_not_called()
        m_reload.assert_not_called()
        # обе ноды пробились и заскорились (наблюдаемость жива)
        self.assertEqual(calls, [("a.example", 443), ("b.example", 443)])
        self.assertIn("a.example:443", saved["nodes_meta"])
        self.assertIn("b.example:443", saved["nodes_meta"])
        self.assertIsNotNone(saved["nodes_meta"]["a.example:443"]["last_score"])

    def test_patch_when_no_native_balancer(self):
        nodes = [{"host": "a.example", "port": 443},
                 {"host": "b.example", "port": 443}]
        m_patch, m_reload, calls, saved = self._run(
            nodes, cfg_text=None)   # конфига нет → балансировщика нет
        m_patch.assert_called_once()
        self.assertEqual(saved["active_node_idx"], 0)

    def test_relayed_node_probes_hop_not_directly(self):
        nodes = [{"host": "a.example", "port": 443},
                 {"host": "ee.example", "port": 443, "via": "hop-a"}]
        # hop-a включён и живёт на 8443; relay_hops пишем в state.json,
        # откуда их читает _sb_get_relay_hops() (через _STATE_FILE)
        import chimera.modules.smart_balancer as sbm
        self._state.write_text(json.dumps({
            "chain_nodes": nodes,
            "chain_lb_nodes": [],
            "relay_hops": [
                {"tag": "hop-a", "host": "hop-a.example", "port": 8443,
                 "enabled": True},
            ],
        }))
        self._sb.write_text(json.dumps({
            "enabled": True, "strategy": "smart", "active_node_idx": -1,
        }))
        probe_calls = []

        def _fake_probe(host, port):
            probe_calls.append((host, port))
            return self._alive()

        with patch("chimera.modules.smart_balancer._STATE_FILE", self._state), \
             patch("chimera.modules.smart_balancer._SB_STATE_FILE", self._sb), \
             patch("chimera.modules.smart_balancer._sb_get_nodes_from_state",
                   return_value=nodes), \
             patch("chimera.modules.smart_balancer._sb_get_xray_config_path",
                   lambda: None), \
             patch("chimera.modules.smart_balancer._probe_node",
                   side_effect=_fake_probe), \
             patch("chimera.modules.smart_balancer._sb_patch_xray_active_node"), \
             patch("chimera.modules.smart_balancer._sb_reload_xray"), \
             patch("chimera.modules.smart_balancer._tg_notify_event"), \
             patch("chimera.modules.smart_balancer._sb_log"):
            sbm._smart_balancer_run_once()

        # прямая нода — сама в себя, релейная — в свой хоп (не напрямую!)
        self.assertIn(("a.example", 443), probe_calls)
        self.assertIn(("hop-a.example", 8443), probe_calls)
        self.assertNotIn(("ee.example", 443), probe_calls)


class TestSbFailoverCandidates(unittest.TestCase):
    """_sb_failover_candidates — чистая выборка резервных хопов."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _hops(self):
        return [
            {"tag": "hop-a", "host": "hop-a.example", "port": 443,
             "enabled": True},
            {"tag": "hop-b", "host": "hop-b.example", "port": 443,
             "enabled": True},
            {"tag": "hop-c", "host": "hop-c.example", "port": 443,
             "enabled": False},
        ]

    def test_excludes_current_via(self):
        from chimera.modules.smart_balancer import _sb_failover_candidates
        node = {"host": "ee.example", "via": "hop-a"}
        tags = [h["tag"] for h in _sb_failover_candidates(node, self._hops())]
        self.assertEqual(tags, ["hop-b"])

    def test_no_via_returns_all_enabled(self):
        from chimera.modules.smart_balancer import _sb_failover_candidates
        node = {"host": "ee.example"}
        tags = [h["tag"] for h in _sb_failover_candidates(node, self._hops())]
        self.assertEqual(tags, ["hop-a", "hop-b"])

    def test_unknown_via_still_excluded(self):
        """via указывает на выключенный/несуществующий хоп — он не кандидат."""
        from chimera.modules.smart_balancer import _sb_failover_candidates
        node = {"host": "ee.example", "via": "hop-c"}
        tags = [h["tag"] for h in _sb_failover_candidates(node, self._hops())]
        self.assertEqual(tags, ["hop-a", "hop-b"])

    def test_none_safe(self):
        from chimera.modules.smart_balancer import _sb_failover_candidates
        self.assertEqual(_sb_failover_candidates(None, None), [])
        self.assertEqual(_sb_failover_candidates(None, self._hops()),
                         self._hops()[:2])


class TestRelayFailover(unittest.TestCase):
    """run_once + _sb_try_relay_failover: сценарии отказов релея.

    Основа: via-нода ee (via=hop-a) + два резервных хопа (hop-pl,
    hop-b). Зонд hop-a мёртв, nodes_meta предзаполнен fails —
    failover должен переключить via до карантина.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"
        self._sb    = self._tmpdir / "sb.json"
        self._cfg   = self._tmpdir / "config.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    _NODES = [
        {"host": "a.example", "port": 443},
        {"host": "ee.example", "port": 443, "via": "hop-a",
         "uuid": "00000000-0000-0000-0000-000000000001",
         "pubkey": "PUBKEY-EE", "shortid": "deadbeef", "sni": "ee.example"},
    ]
    _HOPS = [
        {"tag": "hop-a", "host": "hop-a.example", "port": 443,
         "enabled": True},
        {"tag": "hop-pl", "host": "hop-pl.example", "port": 443,
         "enabled": True},
        {"tag": "hop-b", "host": "hop-b.example", "port": 443,
         "enabled": True},
    ]
    _CFG_BALANCER = json.dumps({"routing": {"balancers": [
        {"tag": "chain-balancer",
         "selector": ["chain-exit-1", "chain-exit-2"],
         "strategy": {"type": "roundRobin"}},
    ]}})

    def _probe(self, host, port):
        """hop-a мёртв; все остальные цели живы."""
        if host == "hop-a.example":
            return {"alive": False, "lat_ms": None, "bw_ms": None,
                    "load": None}
        return {"alive": True, "lat_ms": 40.0, "bw_ms": 60.0, "load": 0}

    def _run(self, fails, fullpath, switch_ret=True, nodes=None):
        """run_once с моками failover-инфраструктуры.

        fullpath(node, hops) -> dict — мок _sb_fullpath_check.
        Возвращает (m_switch, m_tg, saved_sb_state, probe_calls)."""
        import copy
        import chimera.modules.smart_balancer as sbm
        # deepcopy: _sb_try_relay_failover мутирует node["via"] при
        # переключении — общий class-атрибут _NODES загрязнял бы
        # последующие тесты (ловушка порядка выполнения).
        nodes = (copy.deepcopy(nodes) if nodes is not None
                 else copy.deepcopy(self._NODES))
        hops = copy.deepcopy(self._HOPS)
        self._state.write_text(json.dumps({
            "chain_nodes": nodes,
            "chain_lb_nodes": [],
            "relay_hops": hops,
        }))
        self._sb.write_text(json.dumps({
            "enabled": True, "strategy": "smart", "active_node_idx": -1,
            "nodes_meta": {"ee.example:443": {
                "fails": fails, "quarantine_until": 0,
            }},
        }))
        self._cfg.write_text(self._CFG_BALANCER)
        probe_calls = []

        def _fake_probe(host, port):
            probe_calls.append((host, port))
            return self._probe(host, port)

        with patch("chimera.modules.smart_balancer._STATE_FILE", self._state), \
             patch("chimera.modules.smart_balancer._SB_STATE_FILE", self._sb), \
             patch("chimera.modules.smart_balancer._sb_get_nodes_from_state",
                   return_value=nodes), \
             patch("chimera.modules.smart_balancer._sb_get_xray_config_path",
                   lambda: self._cfg), \
             patch("chimera.modules.smart_balancer._probe_node",
                   side_effect=_fake_probe), \
             patch("chimera.modules.smart_balancer._sb_fullpath_check",
                   side_effect=fullpath) as m_fp, \
             patch("chimera.modules.smart_balancer._sb_switch_node_via",
                   return_value=switch_ret) as m_switch, \
             patch("chimera.modules.smart_balancer._sb_patch_xray_active_node"), \
             patch("chimera.modules.smart_balancer._sb_reload_xray"), \
             patch("chimera.modules.smart_balancer._tg_notify_event") as m_tg, \
             patch("chimera.modules.smart_balancer._sb_log"):
            sbm._smart_balancer_run_once()
        saved = json.loads(self._sb.read_text())
        return m_switch, m_tg, m_fp, saved, probe_calls

    def test_failover_switches_to_healthy_hop(self):
        """hop-a мёртв (fails 1→2): full-path текущего мёртв, hop-pl жив
        → via переключен на hop-pl, fails сброшен, TG отправлен."""
        def _fp(nd, hops):
            if nd.get("via") == "hop-a":
                return {"ok": False, "ms": 0, "detail": "цепочка мертва"}
            return {"ok": True, "ms": 150.0, "exit_ip": "198.51.100.10",
                    "detail": "цепочка жива"}
        m_switch, m_tg, m_fp, saved, calls = self._run(fails=1, fullpath=_fp)
        m_switch.assert_called_once_with("ee.example", "hop-pl")
        self.assertEqual(m_tg.call_args[0][0], "relay_failover")
        ee = saved["nodes_meta"]["ee.example:443"]
        self.assertEqual(ee["fails"], 0)
        self.assertIsNotNone(ee["last_score"])

    def test_failover_prefers_fastest_candidate(self):
        """Кандидаты сортируются по TCP-латентности: hop-b быстрее —
        переключаемся на него."""
        def _probe_fast_de(host, port):
            if host == "hop-a.example":
                return {"alive": False, "lat_ms": None, "bw_ms": None,
                        "load": None}
            if host == "hop-b.example":
                return {"alive": True, "lat_ms": 20.0, "bw_ms": 30.0,
                        "load": 0}
            return {"alive": True, "lat_ms": 90.0, "bw_ms": 120.0, "load": 0}

        import chimera.modules.smart_balancer as sbm
        import copy
        _nodes = copy.deepcopy(self._NODES)
        self._state.write_text(json.dumps({
            "chain_nodes": _nodes, "chain_lb_nodes": [],
            "relay_hops": self._HOPS,
        }))
        self._sb.write_text(json.dumps({
            "enabled": True, "strategy": "smart", "active_node_idx": -1,
            "nodes_meta": {"ee.example:443": {"fails": 1,
                                              "quarantine_until": 0}},
        }))
        self._cfg.write_text(self._CFG_BALANCER)

        def _fp(nd, hops):
            return ({"ok": True, "ms": 140.0, "exit_ip": "198.51.100.10",
                     "detail": "ok"} if nd.get("via") != "hop-a"
                    else {"ok": False, "ms": 0, "detail": "dead"})

        with patch("chimera.modules.smart_balancer._STATE_FILE", self._state), \
             patch("chimera.modules.smart_balancer._SB_STATE_FILE", self._sb), \
             patch("chimera.modules.smart_balancer._sb_get_nodes_from_state",
                   return_value=_nodes), \
             patch("chimera.modules.smart_balancer._sb_get_xray_config_path",
                   lambda: self._cfg), \
             patch("chimera.modules.smart_balancer._probe_node",
                   side_effect=_probe_fast_de), \
             patch("chimera.modules.smart_balancer._sb_fullpath_check",
                   side_effect=_fp), \
             patch("chimera.modules.smart_balancer._sb_switch_node_via",
                   return_value=True) as m_switch, \
             patch("chimera.modules.smart_balancer._sb_patch_xray_active_node"), \
             patch("chimera.modules.smart_balancer._sb_reload_xray"), \
             patch("chimera.modules.smart_balancer._tg_notify_event"), \
             patch("chimera.modules.smart_balancer._sb_log"):
            sbm._smart_balancer_run_once()
        m_switch.assert_called_once_with("ee.example", "hop-b")

    def test_failover_current_path_alive_no_switch(self):
        """Зонд дрогнул, но full-path текущего хопа жив (ложный негатив):
        без переключения, нода жива, fails сброшен."""
        def _fp(nd, hops):
            return {"ok": True, "ms": 151.0, "exit_ip": "198.51.100.10",
                    "detail": "цепочка жива"}
        m_switch, m_tg, m_fp, saved, calls = self._run(fails=1, fullpath=_fp)
        m_switch.assert_not_called()
        ee = saved["nodes_meta"]["ee.example:443"]
        self.assertEqual(ee["fails"], 0)
        self.assertIsNotNone(ee["last_score"])

    def test_failover_exhausted_goes_to_quarantine(self):
        """Все релеи мертвы: переключения нет, fails 2→3 → карантин."""
        def _fp(nd, hops):
            return {"ok": False, "ms": 0, "detail": "всё мертво"}
        m_switch, m_tg, m_fp, saved, calls = self._run(fails=2, fullpath=_fp)
        m_switch.assert_not_called()
        ee = saved["nodes_meta"]["ee.example:443"]
        self.assertGreater(ee.get("quarantine_until", 0), 0)
        self.assertEqual(ee["fails"], 3)

    def test_failover_not_triggered_on_first_fail(self):
        """Первый провал (fails 0→1) — гистерезис: full-path не дёргаем."""
        def _fp(nd, hops):
            raise AssertionError("full-path не должен вызываться при fails<2")
        m_switch, m_tg, m_fp, saved, calls = self._run(fails=0, fullpath=_fp)
        m_switch.assert_not_called()
        ee = saved["nodes_meta"]["ee.example:443"]
        self.assertEqual(ee["fails"], 1)

    def test_failover_skipped_for_direct_nodes(self):
        """Нода без via: failover не применяется даже после 2+ провалов."""
        def _fp(nd, hops):
            raise AssertionError("full-path не должен вызываться без via")
        nodes = [{"host": "plain.example", "port": 443}]
        import chimera.modules.smart_balancer as sbm
        self._state.write_text(json.dumps({
            "chain_nodes": nodes, "chain_lb_nodes": [],
            "relay_hops": self._HOPS,
        }))
        self._sb.write_text(json.dumps({
            "enabled": True, "strategy": "smart", "active_node_idx": -1,
            "nodes_meta": {"plain.example:443": {"fails": 2,
                                                 "quarantine_until": 0}},
        }))
        self._cfg.write_text(self._CFG_BALANCER)

        def _dead_probe(host, port):
            return {"alive": False, "lat_ms": None, "bw_ms": None,
                    "load": None}

        with patch("chimera.modules.smart_balancer._STATE_FILE", self._state), \
             patch("chimera.modules.smart_balancer._SB_STATE_FILE", self._sb), \
             patch("chimera.modules.smart_balancer._sb_get_nodes_from_state",
                   return_value=nodes), \
             patch("chimera.modules.smart_balancer._sb_get_xray_config_path",
                   lambda: self._cfg), \
             patch("chimera.modules.smart_balancer._probe_node",
                   side_effect=_dead_probe), \
             patch("chimera.modules.smart_balancer._sb_fullpath_check",
                   side_effect=_fp), \
             patch("chimera.modules.smart_balancer._sb_switch_node_via") as m_switch, \
             patch("chimera.modules.smart_balancer._sb_patch_xray_active_node"), \
             patch("chimera.modules.smart_balancer._sb_reload_xray"), \
             patch("chimera.modules.smart_balancer._tg_notify_event"), \
             patch("chimera.modules.smart_balancer._sb_log"):
            sbm._smart_balancer_run_once()
        m_switch.assert_not_called()
        ee = json.loads(self._sb.read_text())["nodes_meta"]["plain.example:443"]
        self.assertGreater(ee.get("quarantine_until", 0), 0)


class TestSbSwitchNodeVia(unittest.TestCase):
    """_sb_switch_node_via: state.json via + канонический rebuild."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"
        self._state.write_text(json.dumps({
            "chain_nodes": [
                {"host": "a.example", "port": 443},
                {"host": "ee.example", "port": 443, "via": "hop-a"},
            ],
        }))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_switch_updates_state_and_rebuilds(self):
        import chimera.modules.smart_balancer as sbm
        import chimera.modules.chain_relay as cr
        calls = {}
        with patch.object(cr, "_chain_nodes_from_state",
                          return_value=json.loads(
                              self._state.read_text())["chain_nodes"]), \
             patch.object(cr, "_save_chain_nodes_via",
                          side_effect=lambda nodes: calls.update(
                              saved=nodes) or True), \
             patch("chimera._core._load_state_into_globals",
                   lambda: calls.update(loaded=True)), \
             patch("chimera._core._rebuild_and_restart_xray",
                   lambda msg="": calls.update(rebuilt=msg) or None):
            ok = sbm._sb_switch_node_via("EE.example", "hop-pl")
        self.assertTrue(ok)
        self.assertTrue(calls.get("loaded"))
        self.assertIn("failover", calls.get("rebuilt", ""))
        ee = next(n for n in calls["saved"]
                  if n["host"] == "ee.example")
        self.assertEqual(ee["via"], "hop-pl")

    def test_unknown_host_returns_false(self):
        import chimera.modules.smart_balancer as sbm
        import chimera.modules.chain_relay as cr
        with patch.object(cr, "_chain_nodes_from_state",
                          return_value=json.loads(
                              self._state.read_text())["chain_nodes"]), \
             patch.object(cr, "_save_chain_nodes_via") as m_save, \
             patch("chimera._core._rebuild_and_restart_xray") as m_rebuild:
            ok = sbm._sb_switch_node_via("no-such.example", "hop-pl")
        self.assertFalse(ok)
        m_save.assert_not_called()
        m_rebuild.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
