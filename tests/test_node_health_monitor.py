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


class TestProbeNode(unittest.TestCase):
    """probe_node (волна-5): выбор зонда зеркалит check_nodes_once.

    Мокание — прямой подстановой атрибутов модуля chain_relay (паттерн
    TestDegradedReasons._run_check): probe_node импортирует функции
    chain_relay локально внутри тела — подмена атрибутов модуля
    подхватывается при каждом вызове."""

    def setUp(self):
        _setup_core_in_sysmodules()
        import chimera.modules.chain_relay as cr
        from chimera.modules import node_health_monitor as nhm
        self.cr = cr
        self.nhm = nhm
        # оригиналы атрибутов chain_relay + nhm._tcp_ping — восстановить всё
        self._orig = (cr.check_via_node_full_path, cr.check_node_full_path,
                      cr.load_relay_hops, cr.hop_via_tag_for,
                      cr.node_has_reality_creds, nhm._tcp_ping)

    def tearDown(self):
        (self.cr.check_via_node_full_path, self.cr.check_node_full_path,
         self.cr.load_relay_hops, self.cr.hop_via_tag_for,
         self.cr.node_has_reality_creds, self.nhm._tcp_ping) = self._orig

    def test_via_active_hop_full_path(self):
        # via-нода с активным хопом → check_via_node_full_path (цепочка)
        calls = []
        self.cr.load_relay_hops = lambda: [{"tag": "hop1", "enabled": True}]
        self.cr.hop_via_tag_for = lambda nd, hops: "hop1"
        self.cr.check_via_node_full_path = (
            lambda nd, hops, **kw: calls.append(kw) or
            {"ok": True, "ms": 120.0, "infra": False})
        r = self.nhm.probe_node({"host": "nl.example.com", "port": 443,
                                 "via": "hop1"})
        self.assertEqual(r, {"up": True, "ms": 120.0, "reason": "",
                             "method": "via-full-path"})
        # HM-интересует только ok/не-ok — глубокая диагностика не нужна
        self.assertEqual(calls, [{"deep_diag": False, "curl_timeout": 8}])

    def test_via_active_hop_down_reason(self):
        # via-отказ с причиной → up=False, reason доезжает до вызывающего
        self.cr.load_relay_hops = lambda: [{"tag": "hop1", "enabled": True}]
        self.cr.hop_via_tag_for = lambda nd, hops: "hop1"
        self.cr.check_via_node_full_path = lambda nd, hops, **kw: (
            {"ok": False, "ms": 0.0, "infra": False,
             "reason": "нода не отвечает"})
        r = self.nhm.probe_node({"host": "nl.example.com", "port": 443,
                                 "via": "hop1"})
        self.assertFalse(r["up"])
        self.assertEqual(r["reason"], "нода не отвечает")
        self.assertEqual(r["method"], "via-full-path")

    def test_via_infra_falls_to_tcp(self):
        # сбой МЕХАНИЗМА зонда о ноде ничего не говорит — честный TCP;
        # прямая ветка не зовётся (via-infra → сразу TCP, зеркалит HM)
        self.cr.load_relay_hops = lambda: [{"tag": "hop1", "enabled": True}]
        self.cr.hop_via_tag_for = lambda nd, hops: "hop1"
        self.cr.check_via_node_full_path = lambda nd, hops, **kw: (
            {"ok": False, "ms": 0.0, "infra": True, "reason": "нет xray"})
        direct_calls = []
        self.cr.check_node_full_path = lambda nd, **kw: direct_calls.append(1)
        self.nhm._tcp_ping = lambda host, port, timeout=5: (True, 5.0)
        r = self.nhm.probe_node({"host": "nl.example.com", "port": 443,
                                 "via": "hop1"})
        self.assertTrue(r["up"])
        self.assertEqual(r["method"], "tcp")
        self.assertEqual(direct_calls, [])

    def test_via_hop_disabled_uses_direct_probe(self):
        # хоп выключен/удалён → нода ходит напрямую → прямой полный зонд
        self.cr.load_relay_hops = lambda: []
        self.cr.hop_via_tag_for = lambda nd, hops: ""
        self.cr.node_has_reality_creds = lambda nd: True
        self.cr.check_node_full_path = lambda nd, **kw: (
            {"ok": True, "ms": 50.0, "infra": False})
        r = self.nhm.probe_node({"host": "nl.example.com", "port": 443,
                                 "via": "hop1"})
        self.assertTrue(r["up"])
        self.assertEqual(r["method"], "direct-full-path")

    def test_via_import_error_falls_to_tcp(self):
        # chain_relay недоступен (None в sys.modules) → TCP без вердикта
        self.nhm._tcp_ping = lambda host, port, timeout=5: (False, 0.0)
        with patch.dict(sys.modules,
                        {"chimera.modules.chain_relay": None}):
            r = self.nhm.probe_node({"host": "nl.example.com", "port": 443,
                                     "via": "hop1"})
        self.assertFalse(r["up"])
        self.assertEqual(r["method"], "tcp")

    def test_direct_node_with_creds(self):
        # прямая нода с REALITY-ключами → check_node_full_path (не TCP)
        calls = []
        self.cr.node_has_reality_creds = lambda nd: True
        self.cr.check_node_full_path = (
            lambda nd, **kw: calls.append(kw) or
            {"ok": True, "ms": 77.0, "infra": False})
        r = self.nhm.probe_node({"host": "nl.example.com", "port": 443})
        self.assertTrue(r["up"])
        self.assertEqual(r["method"], "direct-full-path")
        # curl_timeout=8: мост поминутный, бюджет раунда ограничен
        self.assertEqual(calls, [{"curl_timeout": 8, "deep_diag": False}])

    def test_direct_node_degraded_reason(self):
        # деградированный отказ (кейс №9) — up=False с причиной
        self.cr.node_has_reality_creds = lambda nd: True
        self.cr.check_node_full_path = lambda nd, **kw: (
            {"ok": False, "ms": 0.0, "infra": False, "reason": "DNS на exit"})
        r = self.nhm.probe_node({"host": "nl.example.com", "port": 443})
        self.assertFalse(r["up"])
        self.assertEqual(r["reason"], "DNS на exit")
        self.assertEqual(r["method"], "direct-full-path")

    def test_direct_infra_falls_to_tcp(self):
        # сбой механизма прямого зонда → честный TCP-fallback
        self.cr.node_has_reality_creds = lambda nd: True
        self.cr.check_node_full_path = lambda nd, **kw: (
            {"ok": False, "ms": 0.0, "infra": True, "reason": "нет xray"})
        self.nhm._tcp_ping = lambda host, port, timeout=5: (True, 7.0)
        r = self.nhm.probe_node({"host": "nl.example.com", "port": 443})
        self.assertTrue(r["up"])
        self.assertEqual(r["method"], "tcp")

    def test_no_creds_tcp(self):
        # нода без клиентских REALITY-ключей → честная TCP-проба
        direct_calls = []
        self.cr.node_has_reality_creds = lambda nd: False
        self.cr.check_node_full_path = lambda nd, **kw: direct_calls.append(1)
        self.nhm._tcp_ping = lambda host, port, timeout=5: (True, 9.0)
        r = self.nhm.probe_node({"host": "nl.example.com", "port": 443})
        self.assertTrue(r["up"])
        self.assertEqual(r["method"], "tcp")
        self.assertEqual(direct_calls, [])

    def test_no_host(self):
        # нода без host — вердикта нет (method "none")
        r = self.nhm.probe_node({"host": ""})
        self.assertEqual(r, {"up": False, "ms": 0.0, "reason": "нет host",
                             "method": "none"})


class TestHmCheckCli(unittest.TestCase):
    """hm_check_cli (мост --hm-check, волна-5): stdout ровно "up"/"down",
    exit 0/1/2, stderr с причиной."""

    def setUp(self):
        _setup_core_in_sysmodules()
        import signal as _signal
        from chimera.modules import node_health_monitor as nhm
        self.nhm = nhm
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"
        self._orig = (nhm.STATE_FILE, nhm.probe_node, nhm._tcp_ping)
        nhm.STATE_FILE = self._state
        self._orig_sigterm = _signal.getsignal(_signal.SIGTERM)

    def tearDown(self):
        import signal as _signal
        import shutil
        self.nhm.STATE_FILE, self.nhm.probe_node, self.nhm._tcp_ping = (
            self._orig)
        _signal.signal(_signal.SIGTERM, self._orig_sigterm)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write_nodes(self, nodes):
        self._state.write_text(json.dumps({"chain_nodes": nodes}))

    def _run(self, target):
        import contextlib
        import io
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = self.nhm.hm_check_cli(target)
        return rc, out.getvalue(), err.getvalue()

    def test_up_prints_word_returns_zero(self):
        # нода найдена → probe_node; stdout — ровно "up", exit 0
        self._write_nodes([{"host": "n.example.com", "port": 443,
                            "uuid": "u", "pubkey": "p"}])
        seen = []
        self.nhm.probe_node = (
            lambda nd: seen.append(nd) or
            {"up": True, "ms": 90.0, "reason": "",
             "method": "direct-full-path"})
        rc, out, err = self._run("n.example.com:443")
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "up")
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["host"], "n.example.com")

    def test_down_stderr_reason(self):
        # down → stdout "down", exit 1, причина — на stderr
        self._write_nodes([{"host": "n.example.com", "port": 443,
                            "uuid": "u", "pubkey": "p"}])
        self.nhm.probe_node = lambda nd: (
            {"up": False, "ms": 0.0, "reason": "DNS на exit",
             "method": "direct-full-path"})
        rc, out, err = self._run("n.example.com:443")
        self.assertEqual(rc, 1)
        self.assertEqual(out.strip(), "down")
        self.assertIn("DNS на exit", err)

    def test_empty_target_usage(self):
        # пустой target (в т.ч. пробелы) → exit 2 (usage)
        rc, out, err = self._run("")
        self.assertEqual(rc, 2)
        rc, out, err = self._run("   ")
        self.assertEqual(rc, 2)

    def test_host_without_port_found(self):
        # host без :port — нода найдена по хосту (порт любой)
        self._write_nodes([{"host": "n.example.com", "port": 443,
                            "uuid": "u", "pubkey": "p"}])
        seen = []
        self.nhm.probe_node = (
            lambda nd: seen.append(nd) or
            {"up": True, "ms": 1.0, "reason": "",
             "method": "direct-full-path"})
        rc, out, err = self._run("n.example.com")
        self.assertEqual(rc, 0)
        self.assertEqual(len(seen), 1)

    def test_port_mismatch_tcp_fallback(self):
        # host найден, порт другой → нода не в chain_nodes → TCP-проба
        self._write_nodes([{"host": "n.example.com", "port": 443,
                            "uuid": "u", "pubkey": "p"}])
        self.nhm._tcp_ping = lambda host, port, timeout=5: (True, 3.0)
        rc, out, err = self._run("n.example.com:8443")
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "up")

    def test_unknown_node_tcp_down(self):
        # ноды нет в chain_nodes, TCP молчит → down + причина на stderr
        self._write_nodes([])
        self.nhm._tcp_ping = lambda host, port, timeout=5: (False, 0.0)
        rc, out, err = self._run("gone.example.com")
        self.assertEqual(rc, 1)
        self.assertEqual(out.strip(), "down")
        self.assertIn("chain_nodes", err)

    def test_sigterm_handler_installed(self):
        # bash `timeout` шлёт SIGTERM — гард ставится (не SIG_DFL)
        import signal as _signal
        self._write_nodes([{"host": "n.example.com", "port": 443,
                            "uuid": "u", "pubkey": "p"}])
        self.nhm.probe_node = lambda nd: (
            {"up": True, "ms": 1.0, "reason": "",
             "method": "direct-full-path"})
        self._run("n.example.com:443")
        self.assertIsNot(_signal.getsignal(_signal.SIGTERM),
                         _signal.SIG_DFL)


if __name__ == "__main__":
    unittest.main(verbosity=2)
