#!/usr/bin/env python3
"""
tests/test_telemt_syn_limiter.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/telemt_syn_limiter.py.

Покрывает:
  1. _plain / _wlen — unicode helpers
  2. SynLimiterConfig — dataclass с дефолтами
  3. _load_state / _save_state — JSON I/O с фильтрацией ключей
  4. _get_telemt_port — чтение порта из TOML
  5. _PRESETS — структура пресетов
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


class TestPlain(unittest.TestCase):
    """_plain — strip ANSI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_plain_string_unchanged(self):
        from chimera.modules.telemt_syn_limiter import _plain
        self.assertEqual(_plain("hello"), "hello")

    def test_strips_ansi(self):
        from chimera.modules.telemt_syn_limiter import _plain
        self.assertEqual(_plain("\033[1;31mhi\033[0m"), "hi")


class TestWlen(unittest.TestCase):
    """_wlen — display width."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ascii(self):
        from chimera.modules.telemt_syn_limiter import _wlen
        self.assertEqual(_wlen("hello"), 5)

    def test_cjk_two_columns(self):
        from chimera.modules.telemt_syn_limiter import _wlen
        self.assertEqual(_wlen("中文"), 4)

    def test_emoji_two_columns(self):
        from chimera.modules.telemt_syn_limiter import _wlen
        self.assertEqual(_wlen("🛡️"), 2)  # shield + VS16

    def test_ansi_zero_width(self):
        from chimera.modules.telemt_syn_limiter import _wlen
        self.assertEqual(_wlen("\033[1mhi\033[0m"), 2)


class TestSynLimiterConfig(unittest.TestCase):
    """SynLimiterConfig — dataclass."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_defaults(self):
        from chimera.modules.telemt_syn_limiter import SynLimiterConfig
        cfg = SynLimiterConfig()
        self.assertFalse(cfg.enabled)
        self.assertEqual(cfg.port, 0)
        self.assertEqual(cfg.rate_per_sec, 1)
        self.assertEqual(cfg.burst, 1)
        self.assertEqual(cfg.htable_expire_ms, 60000)
        self.assertEqual(cfg.preset_name, "hard")


class TestLoadSaveState(unittest.TestCase):
    """_load_state / _save_state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "syn_limiter.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.telemt_syn_limiter._STATE_FILE",
                     self._state)

    def test_load_returns_default_when_no_file(self):
        from chimera.modules.telemt_syn_limiter import _load_state
        with self._patch():
            cfg = _load_state()
        self.assertFalse(cfg.enabled)
        self.assertEqual(cfg.preset_name, "hard")

    def test_load_returns_default_on_corrupt(self):
        from chimera.modules.telemt_syn_limiter import _load_state
        self._state.write_text("{invalid")
        with self._patch():
            cfg = _load_state()
        self.assertFalse(cfg.enabled)

    def test_load_filters_unknown_keys(self):
        """Лишние ключи игнорируются."""
        from chimera.modules.telemt_syn_limiter import _load_state
        self._state.write_text(json.dumps({
            "enabled": True, "port": 443, "rate_per_sec": 5,
            "burst": 10, "htable_expire_ms": 30000, "preset_name": "soft",
            "unknown_key": "ignored",
        }))
        with self._patch():
            cfg = _load_state()
        self.assertTrue(cfg.enabled)
        self.assertEqual(cfg.port, 443)
        self.assertEqual(cfg.rate_per_sec, 5)

    def test_save_then_load(self):
        from chimera.modules.telemt_syn_limiter import (
            _load_state, _save_state, SynLimiterConfig,
        )
        cfg = SynLimiterConfig(enabled=True, port=8443, rate_per_sec=10,
                                burst=20, htable_expire_ms=120000,
                                preset_name="medium")
        with self._patch():
            _save_state(cfg)
            loaded = _load_state()
        self.assertTrue(loaded.enabled)
        self.assertEqual(loaded.port, 8443)
        self.assertEqual(loaded.rate_per_sec, 10)


class TestGetTelemtPort(unittest.TestCase):
    """_get_telemt_port — чтение порта из TOML."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "telemt.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.telemt_syn_limiter._CONFIG_FILE",
                     self._cfg)

    def test_returns_zero_when_no_file(self):
        from chimera.modules.telemt_syn_limiter import _get_telemt_port
        with self._patch():
            self.assertEqual(_get_telemt_port(), 0)

    def test_returns_port(self):
        from chimera.modules.telemt_syn_limiter import _get_telemt_port
        self._cfg.write_text('port = 8443\n')
        with self._patch():
            self.assertEqual(_get_telemt_port(), 8443)

    def test_returns_zero_when_no_port(self):
        from chimera.modules.telemt_syn_limiter import _get_telemt_port
        self._cfg.write_text('other = "x"\n')
        with self._patch():
            self.assertEqual(_get_telemt_port(), 0)


class TestPresets(unittest.TestCase):
    """_PRESETS — структура."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_presets(self):
        from chimera.modules.telemt_syn_limiter import _PRESETS
        self.assertGreater(len(_PRESETS), 0)

    def test_each_preset_has_required_fields(self):
        """Структура: (preset_name, rate_per_sec, burst, label, detail, recommended)."""
        from chimera.modules.telemt_syn_limiter import _PRESETS
        for name, preset in _PRESETS.items():
            with self.subTest(preset=name):
                # preset — tuple из 6 элементов
                self.assertIsInstance(preset, tuple)
                self.assertEqual(len(preset), 6)
                # rate_per_sec и burst — положительные int
                self.assertGreater(preset[1], 0)  # rate_per_sec
                self.assertGreater(preset[2], 0)  # burst


if __name__ == "__main__":
    unittest.main(verbosity=2)
