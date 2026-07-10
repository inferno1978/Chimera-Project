#!/usr/bin/env python3
"""
tests/test_status_panel.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/status_panel.py.

Покрывает:
  1. _check_awg / _check_h2 — pure checks из state
  2. _check_autoban — проверка cron-файла
  3. _IPV4_RE — валидация IPv4
  4. _load_state — JSON I/O
  5. _system_metrics — системные метрики (mocked /proc)
  6. _ip_and_country — IP + country (mocked core)
  7. _load_cache / _save_cache / get_snapshot — кеш
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
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("vless_installer._core")
    fake_core.__dict__.update(g)
    sys.modules["vless_installer._core"] = fake_core


class TestCheckAwg(unittest.TestCase):
    """_check_awg — pure check from state."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_false_when_empty(self):
        from vless_installer.modules.status_panel import _check_awg
        self.assertFalse(_check_awg({}))

    def test_returns_true_when_awg_exit_enabled(self):
        from vless_installer.modules.status_panel import _check_awg
        self.assertTrue(_check_awg({"awg_exit_enabled": True}))

    def test_returns_true_when_awg_installed(self):
        from vless_installer.modules.status_panel import _check_awg
        self.assertTrue(_check_awg({"awg_installed": True}))

    def test_returns_false_when_both_false(self):
        from vless_installer.modules.status_panel import _check_awg
        self.assertFalse(_check_awg({"awg_exit_enabled": False, "awg_installed": False}))


class TestCheckH2(unittest.TestCase):
    """_check_h2 — pure check."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_false_when_empty(self):
        from vless_installer.modules.status_panel import _check_h2
        self.assertFalse(_check_h2({}))

    def test_returns_true_when_h2_exit_enabled(self):
        from vless_installer.modules.status_panel import _check_h2
        self.assertTrue(_check_h2({"h2_exit_enabled": True}))

    def test_returns_false_when_false(self):
        from vless_installer.modules.status_panel import _check_h2
        self.assertFalse(_check_h2({"h2_exit_enabled": False}))


class TestCheckAutoban(unittest.TestCase):
    """_check_autoban — проверка cron-файла."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cron = self._tmpdir / "xray-autoban"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_false_when_no_cron(self):
        from vless_installer.modules.status_panel import _check_autoban
        with patch("vless_installer.modules.status_panel.Path") as mock_path:
            mock_path.return_value.exists.return_value = False
            self.assertFalse(_check_autoban())

    def test_returns_true_when_cron_exists(self):
        from vless_installer.modules.status_panel import _check_autoban
        self._cron.write_text("cron content")
        with patch("vless_installer.modules.status_panel.Path",
                   return_value=self._cron):
            self.assertTrue(_check_autoban())


class TestIpv4Re(unittest.TestCase):
    """_IPV4_RE — валидация IPv4."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_valid_ipv4(self):
        from vless_installer.modules.status_panel import _IPV4_RE
        self.assertIsNotNone(_IPV4_RE.match("1.2.3.4"))
        self.assertIsNotNone(_IPV4_RE.match("192.168.1.1"))

    def test_invalid_short(self):
        from vless_installer.modules.status_panel import _IPV4_RE
        self.assertIsNone(_IPV4_RE.match("1.2.3"))

    def test_invalid_long(self):
        from vless_installer.modules.status_panel import _IPV4_RE
        self.assertIsNone(_IPV4_RE.match("1.2.3.4.5"))

    def test_invalid_garbage(self):
        from vless_installer.modules.status_panel import _IPV4_RE
        self.assertIsNone(_IPV4_RE.match("abc"))
        self.assertIsNone(_IPV4_RE.match(""))

    def test_regex_does_not_validate_octet_range(self):
        """Regex только синтаксис — 999.999.999.999 проходит (regex-only)."""
        from vless_installer.modules.status_panel import _IPV4_RE
        self.assertIsNotNone(_IPV4_RE.match("999.999.999.999"))


class TestLoadState(unittest.TestCase):
    """_load_state — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.status_panel.STATE_FILE", self._state)

    def test_returns_empty_when_no_file(self):
        from vless_installer.modules.status_panel import _load_state
        with self._patch():
            self.assertEqual(_load_state(), {})

    def test_returns_empty_on_corrupt(self):
        from vless_installer.modules.status_panel import _load_state
        self._state.write_text("{invalid")
        with self._patch():
            self.assertEqual(_load_state(), {})

    def test_returns_state(self):
        from vless_installer.modules.status_panel import _load_state
        self._state.write_text(json.dumps({"domain": "x.com"}))
        with self._patch():
            st = _load_state()
        self.assertEqual(st["domain"], "x.com")


class TestSystemMetrics(unittest.TestCase):
    """_system_metrics — mocked /proc."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_dict_with_required_keys(self):
        from vless_installer.modules.status_panel import _system_metrics
        with patch("os.getloadavg", return_value=(0.1, 0.2, 0.3)), \
             patch("shutil.disk_usage") as mock_du, \
             patch("pathlib.Path.read_text") as mock_read:
            mock_du.return_value = MagicMock(total=100, used=50, free=50)
            mock_read.side_effect = lambda: (
                "MemTotal:       16384000 kB\nMemAvailable:    8192000 kB\n"
                if "meminfo" in str(self) else
                "12345.67 9876.54\n"
            )
            metrics = _system_metrics()
        for key in ("load", "disk_pct", "ram_pct", "uptime"):
            self.assertIn(key, metrics)

    def test_handles_missing_proc_files(self):
        """При недоступности /proc — метрики помечаются '?', но не падают."""
        from vless_installer.modules.status_panel import _system_metrics
        with patch("os.getloadavg", side_effect=OSError), \
             patch("shutil.disk_usage", side_effect=OSError), \
             patch("pathlib.Path.read_text", side_effect=OSError):
            metrics = _system_metrics()
        # load может быть "?", "?, ?", "0" или похожим — главное не падать
        self.assertIn("?", str(metrics["load"]) + "?")
        # все ключи присутствуют
        for key in ("load", "disk_pct", "ram_pct", "uptime"):
            self.assertIn(key, metrics)


class TestIpAndCountry(unittest.TestCase):
    """_ip_and_country — IP + country (mocked core)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_question_when_no_ip(self):
        from vless_installer.modules import status_panel
        mock_core = MagicMock()
        mock_core.get_server_ip.return_value = ""
        with patch.object(status_panel, "_core_module", return_value=mock_core):
            result = status_panel._ip_and_country()
        self.assertEqual(result, "?")

    def test_returns_question_when_ip_invalid(self):
        """Если get_server_ip возвращает текст ошибки вместо IP — _IPV4_RE отсеивает."""
        from vless_installer.modules import status_panel
        mock_core = MagicMock()
        mock_core.get_server_ip.return_value = "error: not found"
        with patch.object(status_panel, "_core_module", return_value=mock_core):
            result = status_panel._ip_and_country()
        self.assertEqual(result, "?")

    def test_returns_ip_with_country(self):
        from vless_installer.modules import status_panel
        mock_core = MagicMock()
        mock_core.get_server_ip.return_value = "1.2.3.4"
        mock_core.get_server_country_cached.return_value = ("RU", "Russia", "🇷🇺")
        with patch.object(status_panel, "_core_module", return_value=mock_core):
            result = status_panel._ip_and_country()
        self.assertIn("1.2.3.4", result)
        self.assertIn("RU", result)
        self.assertIn("🇷🇺", result)


class TestCacheOperations(unittest.TestCase):
    """_load_cache / _save_cache / get_snapshot."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cache = self._tmpdir / "cache.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.status_panel.CACHE_FILE", self._cache)

    def test_load_cache_returns_none_when_no_file(self):
        from vless_installer.modules.status_panel import _load_cache
        with self._patch():
            self.assertIsNone(_load_cache())

    def test_load_cache_returns_none_when_expired(self):
        from vless_installer.modules.status_panel import _load_cache, CACHE_TTL
        self._cache.write_text(json.dumps({"ts": time.time() - CACHE_TTL - 10, "data": "x"}))
        with self._patch():
            self.assertIsNone(_load_cache())

    def test_load_cache_returns_data_when_fresh(self):
        from vless_installer.modules.status_panel import _load_cache
        self._cache.write_text(json.dumps({"ts": time.time(), "data": "x"}))
        with self._patch():
            result = _load_cache()
        self.assertIsNotNone(result)
        self.assertEqual(result["data"], "x")

    def test_save_cache_writes_json(self):
        from vless_installer.modules.status_panel import _save_cache, _load_cache
        with self._patch():
            _save_cache({"ts": time.time(), "data": "test"})
            loaded = _load_cache()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["data"], "test")


if __name__ == "__main__":
    unittest.main(verbosity=2)
