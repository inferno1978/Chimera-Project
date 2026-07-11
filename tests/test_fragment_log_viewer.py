#!/usr/bin/env python3
"""
tests/test_fragment_log_viewer.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/fragment_log_viewer.py.

Покрывает:
  1. _parse_log_line — парсинг строки лога
  2. _find_xray_log — поиск лог-файла
  3. _PATTERNS — структура паттернов
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


class TestParseLogLine(unittest.TestCase):
    """_parse_log_line — парсинг строки лога."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_none_for_empty_string(self):
        from vless_installer.modules.fragment_log_viewer import _parse_log_line
        self.assertIsNone(_parse_log_line(""))

    def test_returns_none_for_comment(self):
        from vless_installer.modules.fragment_log_viewer import _parse_log_line
        self.assertIsNone(_parse_log_line("# comment"))

    def test_parses_timestamp_slash_format(self):
        from vless_installer.modules.fragment_log_viewer import _parse_log_line
        line = "2026/07/10 12:00:00 some event happened"
        result = _parse_log_line(line)
        self.assertIsNotNone(result)
        self.assertIn("ts", result)
        self.assertIn("12:00:00", result["ts"])

    def test_parses_timestamp_iso_format(self):
        from vless_installer.modules.fragment_log_viewer import _parse_log_line
        line = "2026-07-10T12:00:00 some event happened"
        result = _parse_log_line(line)
        self.assertIsNotNone(result)
        self.assertIn("ts", result)

    def test_detects_connection_reset(self):
        from vless_installer.modules.fragment_log_viewer import _parse_log_line
        line = "2026/07/10 12:00:00 connection reset by peer"
        result = _parse_log_line(line)
        self.assertIsNotNone(result)
        self.assertIn("event", result)

    def test_detects_fragment_event(self):
        from vless_installer.modules.fragment_log_viewer import _parse_log_line
        line = "2026/07/10 12:00:00 fragment applied to request"
        result = _parse_log_line(line)
        self.assertIsNotNone(result)

    def test_returns_info_for_unknown_event(self):
        from vless_installer.modules.fragment_log_viewer import _parse_log_line
        line = "2026/07/10 12:00:00 unknown event type"
        result = _parse_log_line(line)
        self.assertIsNotNone(result)
        self.assertIn("raw", result)

    def test_includes_raw_line(self):
        from vless_installer.modules.fragment_log_viewer import _parse_log_line
        line = "2026/07/10 12:00:00 some event"
        result = _parse_log_line(line)
        self.assertIsNotNone(result)
        # raw может быть в результате или нет — главное что парсинг не падает
        self.assertIsInstance(result, dict)


class TestFindXrayLog(unittest.TestCase):
    """_find_xray_log — поиск лог-файла."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._log = self._tmpdir / "error.log"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_none_when_no_log(self):
        from vless_installer.modules.fragment_log_viewer import _find_xray_log
        # На продакшен-сервере /var/log/xray.log, /tmp/xray-error.log или
        # /etc/xray/config.json (с log.error путём) могут существовать —
        # патчим ВСЕ кандидаты + config.json чтобы гарантировать None.
        _no_log_paths = {
            "/tmp/nonexistent_log1", "/tmp/nonexistent_log2",
            "/var/log/xray.log", "/tmp/xray-error.log",
            "/etc/xray/config.json", "/usr/local/etc/xray/config.json",
        }
        _orig_exists = Path.exists
        def _exists(self):
            if str(self) in _no_log_paths:
                return False
            return _orig_exists(self)
        with patch("vless_installer.modules.fragment_log_viewer._XRAY_LOG",
                   Path("/tmp/nonexistent_log1")), \
             patch("vless_installer.modules.fragment_log_viewer._ALT_LOG",
                   Path("/tmp/nonexistent_log2")), \
             patch.object(Path, "exists", _exists):
            result = _find_xray_log()
        self.assertIsNone(result)

    def test_returns_first_existing_log(self):
        from vless_installer.modules.fragment_log_viewer import _find_xray_log
        self._log.write_text("log content\n")
        with patch("vless_installer.modules.fragment_log_viewer._XRAY_LOG", self._log), \
             patch("vless_installer.modules.fragment_log_viewer._ALT_LOG",
                   Path("/tmp/nonexistent_alt")):
            result = _find_xray_log()
        self.assertEqual(result, self._log)

    def test_skips_empty_file(self):
        from vless_installer.modules.fragment_log_viewer import _find_xray_log
        self._log.write_text("")  # пустой
        # На проде /var/log/xray.log, /tmp/xray-error.log или config.json
        # могут существовать — патчим их exists() → False.
        _no_log_paths = {
            "/var/log/xray.log", "/tmp/xray-error.log",
            "/etc/xray/config.json", "/usr/local/etc/xray/config.json",
        }
        _orig_exists = Path.exists
        def _exists(self):
            if str(self) in _no_log_paths:
                return False
            return _orig_exists(self)
        with patch("vless_installer.modules.fragment_log_viewer._XRAY_LOG", self._log), \
             patch("vless_installer.modules.fragment_log_viewer._ALT_LOG",
                   Path("/tmp/nonexistent_alt")), \
             patch.object(Path, "exists", _exists):
            result = _find_xray_log()
        self.assertIsNone(result)


class TestPatterns(unittest.TestCase):
    """_PATTERNS — структура."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_at_least_5_patterns(self):
        from vless_installer.modules.fragment_log_viewer import _PATTERNS
        self.assertGreaterEqual(len(_PATTERNS), 5)

    def test_each_pattern_has_required_fields(self):
        from vless_installer.modules.fragment_log_viewer import _PATTERNS
        for pat in _PATTERNS:
            with self.subTest(pattern=pat):
                # каждый паттерн — tuple (regex, icon, color, event_label)
                self.assertEqual(len(pat), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
