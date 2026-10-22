#!/usr/bin/env python3
"""
tests/test_node_health_monitor.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/node_health_monitor.py.

Покрывает:
  1. _load_nodes — чтение chain_nodes из state
  2. _load_health_state / _save_health_state — JSON I/O
  3. is_monitor_installed — проверка cron+script
  4. _get_installed_interval — парсинг cron
  5. install/uninstall_health_monitor — file I/O
  6. _tcp_ping — TCP проверка (mocked socket)
"""
from __future__ import annotations

import json
import sys
import tempfile
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


class TestLoadNodes(unittest.TestCase):
    """_load_nodes — чтение chain_nodes из state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.node_health_monitor.STATE_FILE",
                     self._state)

    def test_returns_empty_when_no_file(self):
        from chimera.modules.node_health_monitor import _load_nodes
        with self._patch():
            self.assertEqual(_load_nodes(), [])

    def test_returns_empty_on_corrupt(self):
        from chimera.modules.node_health_monitor import _load_nodes
        self._state.write_text("{invalid")
        with self._patch():
            self.assertEqual(_load_nodes(), [])

    def test_returns_chain_nodes(self):
        from chimera.modules.node_health_monitor import _load_nodes
        self._state.write_text(json.dumps({
            "chain_nodes": [{"host": "1.1.1.1", "port": 443}],
        }))
        with self._patch():
            nodes = _load_nodes()
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["host"], "1.1.1.1")

    def test_returns_empty_when_no_chain_nodes(self):
        from chimera.modules.node_health_monitor import _load_nodes
        self._state.write_text(json.dumps({"other_key": "value"}))
        with self._patch():
            self.assertEqual(_load_nodes(), [])


class TestLoadSaveHealthState(unittest.TestCase):
    """_load_health_state / _save_health_state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._health = self._tmpdir / "health.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.node_health_monitor.HEALTH_STATE",
                     self._health)

    def test_load_returns_empty_when_no_file(self):
        from chimera.modules.node_health_monitor import _load_health_state
        with self._patch():
            self.assertEqual(_load_health_state(), {})

    def test_load_returns_empty_on_corrupt(self):
        from chimera.modules.node_health_monitor import _load_health_state
        self._health.write_text("{invalid")
        with self._patch():
            self.assertEqual(_load_health_state(), {})

    def test_save_then_load(self):
        from chimera.modules.node_health_monitor import (
            _load_health_state, _save_health_state,
        )
        data = {"node1": {"up": True, "ms": 10.5}}
        with self._patch():
            _save_health_state(data)
            loaded = _load_health_state()
        self.assertEqual(loaded, data)


class TestIsMonitorInstalled(unittest.TestCase):
    """is_monitor_installed — проверка cron+script."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cron = self._tmpdir / "cron"
        self._script = self._tmpdir / "script"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("chimera.modules.node_health_monitor.CRON_FILE", self._cron),
            patch("chimera.modules.node_health_monitor.CHECK_SCRIPT", self._script),
        )

    def test_returns_false_when_neither_exists(self):
        from chimera.modules.node_health_monitor import is_monitor_installed
        with self._patch()[0], self._patch()[1]:
            self.assertFalse(is_monitor_installed())

    def test_returns_false_when_only_cron(self):
        from chimera.modules.node_health_monitor import is_monitor_installed
        self._cron.write_text("x")
        with self._patch()[0], self._patch()[1]:
            self.assertFalse(is_monitor_installed())

    def test_returns_true_when_both_exist(self):
        from chimera.modules.node_health_monitor import is_monitor_installed
        self._cron.write_text("x")
        self._script.write_text("x")
        with self._patch()[0], self._patch()[1]:
            self.assertTrue(is_monitor_installed())


class TestGetInstalledInterval(unittest.TestCase):
    """_get_installed_interval — парсинг cron."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cron = self._tmpdir / "cron"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.node_health_monitor.CRON_FILE",
                     self._cron)

    def test_returns_default_when_no_file(self):
        from chimera.modules.node_health_monitor import (
            _get_installed_interval, DEFAULT_INTERVAL,
        )
        with self._patch():
            self.assertEqual(_get_installed_interval(), DEFAULT_INTERVAL)

    def test_parses_interval(self):
        from chimera.modules.node_health_monitor import _get_installed_interval
        self._cron.write_text("*/7 * * * * root /script\n")
        with self._patch():
            self.assertEqual(_get_installed_interval(), 7)

    def test_returns_default_when_no_pattern(self):
        from chimera.modules.node_health_monitor import (
            _get_installed_interval, DEFAULT_INTERVAL,
        )
        self._cron.write_text("@reboot root /script\n")
        with self._patch():
            self.assertEqual(_get_installed_interval(), DEFAULT_INTERVAL)


class TestInstallUninstall(unittest.TestCase):
    """install_health_monitor / uninstall_health_monitor — file I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cron = self._tmpdir / "cron"
        self._script = self._tmpdir / "script"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("chimera.modules.node_health_monitor.CRON_FILE", self._cron),
            patch("chimera.modules.node_health_monitor.CHECK_SCRIPT", self._script),
        )

    def test_install_creates_files(self):
        from chimera.modules.node_health_monitor import install_health_monitor
        with self._patch()[0], self._patch()[1]:
            ok, msg = install_health_monitor(interval=5)
        self.assertTrue(ok)
        self.assertTrue(self._cron.exists())
        self.assertTrue(self._script.exists())

    def test_install_cron_contains_interval(self):
        from chimera.modules.node_health_monitor import install_health_monitor
        with self._patch()[0], self._patch()[1]:
            install_health_monitor(interval=10)
        content = self._cron.read_text()
        self.assertIn("*/10", content)

    def test_uninstall_removes_files(self):
        from chimera.modules.node_health_monitor import (
            install_health_monitor, uninstall_health_monitor,
        )
        with self._patch()[0], self._patch()[1]:
            install_health_monitor()
            ok, _ = uninstall_health_monitor()
        self.assertTrue(ok)
        self.assertFalse(self._cron.exists())
        self.assertFalse(self._script.exists())

    def test_uninstall_succeeds_when_no_files(self):
        from chimera.modules.node_health_monitor import uninstall_health_monitor
        with self._patch()[0], self._patch()[1]:
            ok, _ = uninstall_health_monitor()
        self.assertTrue(ok)


class TestTcpPing(unittest.TestCase):
    """_tcp_ping — TCP проверка (mocked socket)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_true_on_success(self):
        from chimera.modules.node_health_monitor import _tcp_ping
        with patch("socket.gethostbyname", return_value="1.2.3.4"), \
             patch("socket.create_connection") as mock_conn:
            mock_conn.return_value = MagicMock()
            ok, ms = _tcp_ping("example.com", 443)
        self.assertTrue(ok)
        self.assertGreaterEqual(ms, 0)

    def test_returns_false_on_dns_failure(self):
        from chimera.modules.node_health_monitor import _tcp_ping
        with patch("socket.gethostbyname", side_effect=OSError("dns fail")):
            ok, ms = _tcp_ping("nonexistent.invalid", 443)
        self.assertFalse(ok)
        self.assertEqual(ms, 0.0)

    def test_returns_false_on_connection_failure(self):
        from chimera.modules.node_health_monitor import _tcp_ping
        with patch("socket.gethostbyname", return_value="1.2.3.4"), \
             patch("socket.create_connection", side_effect=OSError("conn refused")):
            ok, ms = _tcp_ping("1.2.3.4", 443)
        self.assertFalse(ok)
        self.assertEqual(ms, 0.0)


class TestDegradedReasons(unittest.TestCase):
    """Кейс окт.2026 №9: reason деградированного DOWN (DNS/v6-egress на
    exit — туннель жив) пишется в state/results/лог; TG говорит
    «деградировала», не «недоступна»; жёсткий DOWN — прежний текст."""

    def setUp(self):
        _setup_core_in_sysmodules()
        core = sys.modules["chimera._core"]
        self._tmp = tempfile.TemporaryDirectory()
        core.STATE_FILE = Path(self._tmp.name) / "state.json"
        core.STATE_FILE.write_text(json.dumps({
            "chain_nodes": [{"host": "nl.example.com", "port": 443,
                             "sni": "nl.example.com", "uuid": "u",
                             "pubkey": "p"}],
            "relay_hops": [],
        }))
        from chimera.modules import node_health_monitor as _nhm
        self._nhm = _nhm
        self._orig = (_nhm.STATE_FILE, _nhm.HEALTH_STATE, _nhm.HEALTH_LOG)
        _nhm.STATE_FILE = core.STATE_FILE
        _nhm.HEALTH_STATE = Path(self._tmp.name) / "node-health-state.json"
        _nhm.HEALTH_LOG = Path(self._tmp.name) / "xray-node-health.log"

    def tearDown(self):
        (self._nhm.STATE_FILE, self._nhm.HEALTH_STATE,
         self._nhm.HEALTH_LOG) = self._orig
        self._tmp.cleanup()

    def _run_check(self, probe_result, prev_state):
        import chimera.modules.chain_relay as cr
        nhm = self._nhm
        nhm.HEALTH_STATE.write_text(json.dumps(prev_state))
        sent = []
        orig_fp, orig_icmp, orig_tg = (cr.check_node_full_path,
                                       cr.icmp_rtt, nhm._tg_send)
        cr.check_node_full_path = lambda nd, **kw: probe_result
        cr.icmp_rtt = lambda host, **kw: {"ok": True, "avg": 60.5}
        nhm._tg_send = lambda msg: sent.append(msg) or True
        try:
            results = nhm.check_nodes_once()
        finally:
            (cr.check_node_full_path, cr.icmp_rtt,
             nhm._tg_send) = orig_fp, orig_icmp, orig_tg
        return results, sent

    def test_degraded_down_reason_everywhere(self):
        # была UP → стала DOWN с v6-egress: reason в results/state/лог,
        # TG — «деградирована ... туннель жив», НЕ «недоступна»
        results, sent = self._run_check(
            {"ok": False, "ms": 0.0, "infra": False,
             "reason": "v6-egress на exit",
             "detail": "нода и REALITY живы"},
            {"nl.example.com:443": {"up": True, "last_check": 1.0}})
        self.assertFalse(results[0]["up"])
        self.assertEqual(results[0]["reason"], "v6-egress на exit")
        st = json.loads(self._nhm.HEALTH_STATE.read_text())
        self.assertEqual(st["nl.example.com:443"]["reason"],
                         "v6-egress на exit")
        log = self._nhm.HEALTH_LOG.read_text()
        self.assertIn("v6-egress на exit", log)
        self.assertEqual(len(sent), 1)
        self.assertIn("деградирована", sent[0])
        self.assertIn("туннель жив", sent[0])
        self.assertNotIn("недоступна", sent[0])

    def test_hard_down_keeps_unavailable_wording(self):
        # жёсткий отказ (все пробы 000) — прежний красный текст
        results, sent = self._run_check(
            {"ok": False, "ms": 0.0, "infra": False,
             "reason": "нода не отвечает"},
            {"nl.example.com:443": {"up": True, "last_check": 1.0}})
        self.assertFalse(results[0]["up"])
        self.assertEqual(len(sent), 1)
        self.assertIn("недоступна", sent[0])
        self.assertNotIn("деградирована", sent[0])

    def test_up_node_has_empty_reason(self):
        results, sent = self._run_check(
            {"ok": True, "ms": 250.0, "infra": False, "reason": "нода жива"},
            {"nl.example.com:443": {"up": True, "last_check": 1.0}})
        self.assertTrue(results[0]["up"])
        self.assertEqual(results[0]["reason"], "")
        self.assertEqual(sent, [])     # статуса не менялся — TG нет

    def test_is_degraded_reason_helper(self):
        nhm = self._nhm
        self.assertTrue(nhm._is_degraded_reason("DNS на exit"))
        self.assertTrue(nhm._is_degraded_reason("v6-egress на exit"))
        self.assertFalse(nhm._is_degraded_reason("нода не отвечает"))
        self.assertFalse(nhm._is_degraded_reason(""))
        self.assertFalse(nhm._is_degraded_reason(None))


if __name__ == "__main__":
    unittest.main(verbosity=2)
