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


if __name__ == "__main__":
    unittest.main(verbosity=2)
