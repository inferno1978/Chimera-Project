#!/usr/bin/env python3
"""
tests/test_dpi_detector.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/dpi_detector.py.

Покрывает:
  1. _dpi_state_load — чтение JSON state
  2. _dpi_state_save — запись JSON state с chmod 0o600
  3. _dpi_run_once — анализ error.log (mocked _run, _autoban_*, _lookup_asn)
  4. _DPI_PATTERNS — соответствие regex ожидаемым строкам
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta
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


class TestDpiStateLoad(unittest.TestCase):
    """_dpi_state_load — JSON state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "dpi.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.dpi_detector._DPI_STATE_FILE",
                     self._state)

    def test_returns_defaults_when_no_file(self):
        from chimera.modules.dpi_detector import (
            _dpi_state_load, _DPI_THRESHOLD_DEFAULT, _DPI_WINDOW_DEFAULT,
        )
        with self._patch():
            cfg = _dpi_state_load()
        self.assertFalse(cfg["enabled"])
        self.assertEqual(cfg["threshold"], _DPI_THRESHOLD_DEFAULT)
        self.assertEqual(cfg["window_min"], _DPI_WINDOW_DEFAULT)
        self.assertIn("127.0.0.1", cfg["whitelist"])
        self.assertIn("::1", cfg["whitelist"])

    def test_returns_defaults_when_corrupt(self):
        from chimera.modules.dpi_detector import _dpi_state_load
        self._state.write_text("{invalid")
        with self._patch():
            cfg = _dpi_state_load()
        self.assertFalse(cfg["enabled"])

    def test_returns_state_when_valid(self):
        from chimera.modules.dpi_detector import _dpi_state_load
        self._state.write_text(json.dumps({
            "enabled": True, "threshold": 10, "window_min": 30,
            "whitelist": ["1.2.3.4"],
        }))
        with self._patch():
            cfg = _dpi_state_load()
        self.assertTrue(cfg["enabled"])
        self.assertEqual(cfg["threshold"], 10)
        self.assertIn("1.2.3.4", cfg["whitelist"])


class TestDpiStateSave(unittest.TestCase):
    """_dpi_state_save."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "dpi.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.dpi_detector._DPI_STATE_FILE",
                     self._state)

    def test_writes_json(self):
        from chimera.modules.dpi_detector import _dpi_state_save
        with self._patch():
            _dpi_state_save({"enabled": True, "threshold": 8})
        data = json.loads(self._state.read_text())
        self.assertTrue(data["enabled"])
        self.assertEqual(data["threshold"], 8)

    def test_sets_chmod_600(self):
        from chimera.modules.dpi_detector import _dpi_state_save
        with self._patch():
            _dpi_state_save({"enabled": False})
        mode = stat.S_IMODE(os.stat(self._state).st_mode)
        self.assertEqual(mode, 0o600)


class TestDpiPatterns(unittest.TestCase):
    """_DPI_PATTERNS — regex соответствуют ожидаемым строкам."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_patterns_count_at_least_5(self):
        from chimera.modules.dpi_detector import _DPI_PATTERNS
        self.assertGreaterEqual(len(_DPI_PATTERNS), 5)

    def test_pattern_matches_tls_no_sni(self):
        from chimera.modules.dpi_detector import _DPI_PATTERNS
        # первый паттерн — TLS без SNI
        pattern, desc, weight = _DPI_PATTERNS[0]
        self.assertTrue(pattern.search("TLS: no SNI from client"))
        self.assertTrue(pattern.search("missing SNI in handshake"))

    def test_reality_auth_fail_pattern(self):
        from chimera.modules.dpi_detector import _DPI_PATTERNS
        reality_pattern = None
        for p, d, w in _DPI_PATTERNS:
            if "REALITY" in d:
                reality_pattern = p
                break
        self.assertIsNotNone(reality_pattern)
        self.assertTrue(reality_pattern.search("short id mismatch"))
        self.assertTrue(reality_pattern.search("invalid public key"))

    def test_all_patterns_have_positive_weight(self):
        from chimera.modules.dpi_detector import _DPI_PATTERNS
        for pattern, desc, weight in _DPI_PATTERNS:
            with self.subTest(desc=desc):
                self.assertGreater(weight, 0)


class TestPinnedNodeLabels(unittest.TestCase):
    """_dpi_node_label — key_label-метки chain-нод (node_identity: алиас
    наблюдателя трафика + DNS из предзаполненного кэша — без getent;
    прод-файлы node_identity изолированы в tmp, паттерн 652e692)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._dns = self._tmpdir / "node_dns_cache.json"
        self._aliases = self._tmpdir / "exit_traffic_watcher.json"
        self._dns.write_text(json.dumps({
            "node-nl.example.com": {"ip": "203.0.113.40",
                                    "ts": time.time()}}))
        self._aliases.write_text(json.dumps({
            "aliases": {"node-nl.example.com:443": "NL",
                        "198.51.100.9:8443": "DE"}}))
        from chimera.modules import node_identity as _ni
        _ni._MEM.clear()
        for p in (patch.object(_ni, "DNS_CACHE_FILE", self._dns),
                  patch.object(_ni, "ALIASES_FILE", self._aliases)):
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(_ni._MEM.clear)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_domain_node_alias_and_ip(self):
        """Домен: алиас из watcher-aliases + [IP] из кэша; :443 не пишется."""
        from chimera.modules.dpi_detector import _dpi_node_label
        self.assertEqual(_dpi_node_label("node-nl.example.com", 443),
                         "NL · node-nl.example.com [203.0.113.40]")

    def test_ip_node_with_port(self):
        """IP-литерал + нестандартный порт: алиас + «IP:порт»."""
        from chimera.modules.dpi_detector import _dpi_node_label
        self.assertEqual(_dpi_node_label("198.51.100.9", 8443),
                         "DE · 198.51.100.9:8443")

    def test_ip_node_default_port_hidden(self):
        """IP-литерал без алиаса, порт 443 — голый IP (порт не пишется)."""
        from chimera.modules.dpi_detector import _dpi_node_label
        self.assertEqual(_dpi_node_label("198.51.100.9", 443),
                         "198.51.100.9")


class TestPinnedFallbackNotify(unittest.TestCase):
    """pinned-fallback/restore — TG-уведы с node_label-метками нод
    («NL · домен [IP]»); TCP-пробы/Xray-рестарт/TG — замоканы
    (герметичность, паттерн c3c1803)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"
        self._dns = self._tmpdir / "node_dns_cache.json"
        self._aliases = self._tmpdir / "exit_traffic_watcher.json"
        self._dns.write_text(json.dumps({
            "node-nl.example.com": {"ip": "203.0.113.40",
                                    "ts": time.time()},
            "node-de.example.com": {"ip": "192.0.2.20",
                                    "ts": time.time()}}))
        self._aliases.write_text(json.dumps({
            "aliases": {"node-nl.example.com:443": "NL",
                        "node-de.example.com:443": "DE"}}))
        from chimera.modules import node_identity as _ni
        _ni._MEM.clear()
        for p in (patch.object(_ni, "DNS_CACHE_FILE", self._dns),
                  patch.object(_ni, "ALIASES_FILE", self._aliases)):
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(_ni._MEM.clear)
        self._nodes = [
            {"host": "node-nl.example.com", "port": 443},
            {"host": "node-de.example.com", "port": 443},
        ]
        self._notified: list[tuple] = []

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _run(self, state, tcp_hosts):
        """Фаза pinned-чека с моками: tcp_hosts — хосты, отвечающие на
        TCP-пробу (остальные — connection refused)."""
        import socket as _sock
        from chimera.modules import dpi_detector as dd

        class _FakeConn:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_conn(addr, timeout=None):
            if addr[0] in tcp_hosts:
                return _FakeConn()
            raise ConnectionRefusedError(f"refused: {addr[0]}")

        self._state.write_text(json.dumps(state))
        # (_fallback_log — вложенная функция, не патчится; пишет в
        # /var/log/xray-auto-fallback.log best-effort, без сети/TG)
        with patch.object(dd, "_STATE_FILE", self._state), \
             patch.object(dd, "_tg_notify_event",
                          side_effect=lambda ev, d="":
                              self._notified.append((ev, d))), \
             patch.object(dd, "_set_chain_pinned_node_index", MagicMock()), \
             patch.object(dd, "_rebuild_and_restart_xray", MagicMock()), \
             patch.object(_sock, "create_connection", fake_conn):
            dd._pinned_node_check_and_fallback()

    def test_fallback_and_restore_labels(self):
        """Смерть pinned (NL) → fallback на DE: обе ноды в уведе —
        node_label-метками «алиас · домен [IP]» (не «#N (host)»);
        восстановление NL → возврат с меткой fallback-ноды."""
        st = {"chain_pinned_node_index": 0, "chain_nodes": self._nodes}
        self._run(st, tcp_hosts={"node-de.example.com"})
        self.assertEqual(len(self._notified), 1)
        ev, det = self._notified[0]
        self.assertEqual(ev, "xray_down")
        self.assertIn("NL · node-nl.example.com [203.0.113.40]", det)
        self.assertIn("DE · node-de.example.com [192.0.2.20]", det)
        self.assertNotIn("#1 (", det)
        # фаза A: оригинал (NL) поднялся → restore с fallback-ноды (DE)
        st2 = {"chain_pinned_node_index": 1,
               "_pinned_original_index": 0,
               "chain_nodes": self._nodes}
        self._run(st2, tcp_hosts={"node-nl.example.com"})
        self.assertEqual(len(self._notified), 2)
        ev2, det2 = self._notified[1]
        self.assertEqual(ev2, "xray_up")
        self.assertIn("NL · node-nl.example.com [203.0.113.40]", det2)
        self.assertIn("DE · node-de.example.com [192.0.2.20]", det2)

    def test_alive_pinned_no_notify(self):
        """Pinned жив — увед нет (проверка молча)."""
        st = {"chain_pinned_node_index": 0, "chain_nodes": self._nodes}
        self._run(st, tcp_hosts={"node-nl.example.com"})
        self.assertEqual(self._notified, [])


class TestDpiRunOnce(unittest.TestCase):
    """_dpi_run_once — анализ error.log (mocked)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._error_log = self._tmpdir / "error.log"
        self._access_log = self._tmpdir / "access.log"
        self._dpi_log = self._tmpdir / "dpi.log"
        self._dpi_state = self._tmpdir / "dpi_state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_line(self, ip: str, content: str, ts: datetime = None) -> str:
        if ts is None:
            ts = datetime.now()
        return f"{ts:%Y/%m/%d} {ts:%H:%M:%S} [{ip}] {content}"

    def test_returns_zero_when_no_error_log(self):
        from chimera.modules import dpi_detector
        # Патчим Path так, чтобы /var/log/xray/error.log не существовал
        original_path = Path

        def _fake_path(*args, **kwargs):
            p = original_path(*args, **kwargs)
            if str(p) == "/var/log/xray/error.log":
                # Возвращаем путь к несуществующему файлу
                return original_path("/tmp/nonexistent_error_log_xyz.log")
            return p

        mock_path = MagicMock(side_effect=_fake_path)
        for attr in ("exists", "read_text", "write_text", "stat", "parent",
                     "name", "mkdir", "chmod", "unlink", "open"):
            setattr(mock_path, attr, getattr(original_path, attr, None))

        with patch.object(dpi_detector, "_DPI_STATE_FILE", self._dpi_state), \
             patch.object(dpi_detector, "_dpi_state_load",
                          return_value={"enabled": True, "threshold": 6,
                                        "window_min": 15,
                                        "whitelist": ["127.0.0.1", "::1"]}), \
             patch.object(dpi_detector, "_autoban_load",
                          return_value={"banned": {}, "whitelist": []}), \
             patch.object(dpi_detector, "_autoban_save"), \
             patch.object(dpi_detector, "_autoban_get_chain_ips", return_value=[]), \
             patch.object(dpi_detector, "_pinned_node_check_and_fallback",
                          return_value=False), \
             patch.object(dpi_detector, "Path", mock_path):
            result = dpi_detector._dpi_run_once()
        self.assertEqual(result, 0)

    def test_bans_ip_when_score_exceeds_threshold(self):
        """REALITY auth fail (weight=4) × 2 = 8 > threshold 6 → бан."""
        from chimera.modules import dpi_detector
        # 2 строки с REALITY auth fail от одного IP
        now = datetime.now()
        lines = "\n".join([
            self._make_line("1.2.3.4", "REALITY auth fail: short id mismatch", now),
            self._make_line("1.2.3.4", "REALITY auth fail: invalid public key", now),
        ])
        self._error_log.write_text(lines)

        # Патчим Path только для /var/log/xray/error.log
        original_path = Path

        def _fake_path(*args, **kwargs):
            p = original_path(*args, **kwargs)
            if str(p) == "/var/log/xray/error.log":
                return self._error_log
            if str(p) == "/var/log/xray/access.log":
                return original_path("/tmp/nonexistent_access_log_xyz.json")
            return p

        mock_path = MagicMock(side_effect=_fake_path)
        for attr in ("exists", "read_text", "write_text", "stat", "parent",
                     "name", "mkdir", "chmod", "unlink", "open"):
            setattr(mock_path, attr, getattr(original_path, attr, None))

        with patch.object(dpi_detector, "_DPI_STATE_FILE", self._dpi_state), \
             patch.object(dpi_detector, "_DPI_LOG", self._dpi_log), \
             patch.object(dpi_detector, "_dpi_state_load",
                          return_value={"enabled": True, "threshold": 6,
                                        "window_min": 15,
                                        "whitelist": ["127.0.0.1", "::1"]}), \
             patch.object(dpi_detector, "_autoban_load",
                          return_value={"banned": {}, "whitelist": []}), \
             patch.object(dpi_detector, "_autoban_save") as mock_save, \
             patch.object(dpi_detector, "_autoban_get_chain_ips", return_value=[]), \
             patch.object(dpi_detector, "_lookup_asn",
                          return_value={"asn": "AS123"}), \
             patch.object(dpi_detector, "_ban_report_append"), \
             patch.object(dpi_detector, "_tg_notify_event"), \
             patch.object(dpi_detector, "_pinned_node_check_and_fallback",
                          return_value=False), \
             patch.object(dpi_detector, "_run") as mock_run, \
             patch.object(dpi_detector, "Path", mock_path):
            # ufw deny — успешно
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = dpi_detector._dpi_run_once()
        self.assertEqual(result, 1)
        # autoban_save должен был вызваться с IP в banned
        mock_save.assert_called()
        saved_data = mock_save.call_args.args[0]
        self.assertIn("1.2.3.4", saved_data["banned"])

    def test_skips_whitelisted_ip(self):
        """IP в whitelist — не банится даже при высоком score."""
        from chimera.modules import dpi_detector
        now = datetime.now()
        lines = "\n".join([
            self._make_line("127.0.0.1", "REALITY auth fail: short id mismatch", now),
            self._make_line("127.0.0.1", "REALITY auth fail: invalid public key", now),
        ])
        self._error_log.write_text(lines)

        original_path = Path

        def _fake_path(*args, **kwargs):
            p = original_path(*args, **kwargs)
            if str(p) == "/var/log/xray/error.log":
                return self._error_log
            if str(p) == "/var/log/xray/access.log":
                return original_path("/tmp/nonexistent_access_xyz.json")
            return p

        mock_path = MagicMock(side_effect=_fake_path)
        for attr in ("exists", "read_text", "write_text", "stat", "parent",
                     "name", "mkdir", "chmod", "unlink", "open"):
            setattr(mock_path, attr, getattr(original_path, attr, None))

        with patch.object(dpi_detector, "_DPI_STATE_FILE", self._dpi_state), \
             patch.object(dpi_detector, "_DPI_LOG", self._dpi_log), \
             patch.object(dpi_detector, "_dpi_state_load",
                          return_value={"enabled": True, "threshold": 6,
                                        "window_min": 15,
                                        "whitelist": ["127.0.0.1", "::1"]}), \
             patch.object(dpi_detector, "_autoban_load",
                          return_value={"banned": {}, "whitelist": []}), \
             patch.object(dpi_detector, "_autoban_save"), \
             patch.object(dpi_detector, "_autoban_get_chain_ips", return_value=[]), \
             patch.object(dpi_detector, "_pinned_node_check_and_fallback",
                          return_value=False), \
             patch.object(dpi_detector, "Path", mock_path):
            result = dpi_detector._dpi_run_once()
        self.assertEqual(result, 0)

    def test_skips_already_banned_ip(self):
        """IP уже в banned — не баним второй раз."""
        from chimera.modules import dpi_detector
        now = datetime.now()
        lines = "\n".join([
            self._make_line("9.9.9.9", "REALITY auth fail: short id mismatch", now),
            self._make_line("9.9.9.9", "REALITY auth fail: invalid public key", now),
        ])
        self._error_log.write_text(lines)

        original_path = Path

        def _fake_path(*args, **kwargs):
            p = original_path(*args, **kwargs)
            if str(p) == "/var/log/xray/error.log":
                return self._error_log
            if str(p) == "/var/log/xray/access.log":
                return original_path("/tmp/nonexistent_acc_xyz.json")
            return p

        mock_path = MagicMock(side_effect=_fake_path)
        for attr in ("exists", "read_text", "write_text", "stat", "parent",
                     "name", "mkdir", "chmod", "unlink", "open"):
            setattr(mock_path, attr, getattr(original_path, attr, None))

        with patch.object(dpi_detector, "_DPI_STATE_FILE", self._dpi_state), \
             patch.object(dpi_detector, "_DPI_LOG", self._dpi_log), \
             patch.object(dpi_detector, "_dpi_state_load",
                          return_value={"enabled": True, "threshold": 6,
                                        "window_min": 15,
                                        "whitelist": ["127.0.0.1", "::1"]}), \
             patch.object(dpi_detector, "_autoban_load",
                          return_value={"banned": {"9.9.9.9": {"count": 10}},
                                        "whitelist": []}), \
             patch.object(dpi_detector, "_autoban_save"), \
             patch.object(dpi_detector, "_autoban_get_chain_ips", return_value=[]), \
             patch.object(dpi_detector, "_pinned_node_check_and_fallback",
                          return_value=False), \
             patch.object(dpi_detector, "Path", mock_path):
            result = dpi_detector._dpi_run_once()
        self.assertEqual(result, 0)

    def test_filters_old_entries_by_window(self):
        """Записи старше window_min минут — игнорируются."""
        from chimera.modules import dpi_detector
        old_ts = datetime.now() - timedelta(hours=2)
        now = datetime.now()
        # Старая запись (должна быть отфильтрована) + свежая
        lines = "\n".join([
            self._make_line("1.2.3.4", "REALITY auth fail: short id mismatch", old_ts),
            self._make_line("1.2.3.4", "REALITY auth fail: invalid public key", now),
        ])
        self._error_log.write_text(lines)

        original_path = Path

        def _fake_path(*args, **kwargs):
            p = original_path(*args, **kwargs)
            if str(p) == "/var/log/xray/error.log":
                return self._error_log
            if str(p) == "/var/log/xray/access.log":
                return original_path("/tmp/nonexistent_acc_xyz2.json")
            return p

        mock_path = MagicMock(side_effect=_fake_path)
        for attr in ("exists", "read_text", "write_text", "stat", "parent",
                     "name", "mkdir", "chmod", "unlink", "open"):
            setattr(mock_path, attr, getattr(original_path, attr, None))

        with patch.object(dpi_detector, "_DPI_STATE_FILE", self._dpi_state), \
             patch.object(dpi_detector, "_DPI_LOG", self._dpi_log), \
             patch.object(dpi_detector, "_dpi_state_load",
                          return_value={"enabled": True, "threshold": 6,
                                        "window_min": 15,
                                        "whitelist": ["127.0.0.1", "::1"]}), \
             patch.object(dpi_detector, "_autoban_load",
                          return_value={"banned": {}, "whitelist": []}), \
             patch.object(dpi_detector, "_autoban_save"), \
             patch.object(dpi_detector, "_autoban_get_chain_ips", return_value=[]), \
             patch.object(dpi_detector, "_pinned_node_check_and_fallback",
                          return_value=False), \
             patch.object(dpi_detector, "Path", mock_path):
            result = dpi_detector._dpi_run_once()
        # только 1 fresh запись с weight=4 < threshold 6 → 0 банов
        self.assertEqual(result, 0)


class TestLogFunctions(unittest.TestCase):
    """info/success/warn/log_to_file."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._log = self._tmpdir / "install.log"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.dpi_detector._LOG_FILE", self._log)

    def test_log_to_file_writes_line(self):
        from chimera.modules.dpi_detector import log_to_file
        with self._patch():
            log_to_file("INFO", "test message")
        content = self._log.read_text()
        self.assertIn("INFO", content)
        self.assertIn("test message", content)

    def test_log_strips_ansi(self):
        """Лог-файл не должен содержать ANSI-кодов."""
        from chimera.modules.dpi_detector import log_to_file
        with self._patch():
            log_to_file("INFO", "\033[1;31mred text\033[0m")
        content = self._log.read_text()
        self.assertNotIn("\033[", content)
        self.assertIn("red text", content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
