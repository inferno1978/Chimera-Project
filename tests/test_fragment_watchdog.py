#!/usr/bin/env python3
"""
tests/test_fragment_watchdog.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/fragment_watchdog.py.

Покрывает:
  1. _ESCALATION — структура пресетов
  2. _show_watchdog_log — чтение лога (mocked)
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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


class TestEscalation(unittest.TestCase):
    """_ESCALATION — структура пресетов."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_at_least_3_presets(self):
        from chimera.modules.fragment_watchdog import _ESCALATION
        self.assertGreaterEqual(len(_ESCALATION), 3)

    def test_each_preset_has_required_keys(self):
        from chimera.modules.fragment_watchdog import _ESCALATION
        for preset in _ESCALATION:
            with self.subTest(preset=preset.get("name")):
                self.assertIn("name", preset)
                self.assertIn("packets", preset)
                self.assertIn("length", preset)
                self.assertIn("interval", preset)


class TestShowWatchdogLog(unittest.TestCase):
    """_show_watchdog_log — чтение лога."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._log = self._tmpdir / "watchdog.log"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.fragment_watchdog._WATCHDOG_LOG", self._log)

    def test_shows_empty_message_when_no_file(self):
        import io
        from chimera.modules.fragment_watchdog import _show_watchdog_log
        buf = io.StringIO()
        with self._patch(), patch("sys.stdout", buf):
            _show_watchdog_log()
        output = buf.getvalue()
        self.assertIn("пуст", output.lower())

    def test_shows_log_lines(self):
        import io
        from chimera.modules.fragment_watchdog import _show_watchdog_log
        self._log.write_text(
            "[START] Watchdog started\n"
            "[SWITCH] Switched to aggressive\n"
            "[ALERT] Xray down\n"
        )
        buf = io.StringIO()
        with self._patch(), patch("sys.stdout", buf):
            _show_watchdog_log()
        output = buf.getvalue()
        self.assertIn("Watchdog started", output)
        self.assertIn("Switched", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
