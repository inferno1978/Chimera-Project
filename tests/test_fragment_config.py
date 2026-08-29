#!/usr/bin/env python3
"""
tests/test_fragment_config.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/fragment_config.py.

Покрывает:
  1. build_fragment_sockopt — генерация sockopt dict
  2. _validate_range_str — валидация диапазонов "3-7"
  3. _FRAGMENT_PRESETS — структура пресетов
  4. generate_fragment_client_config — генерация конфига (mocked state)
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


class TestBuildFragmentSockopt(unittest.TestCase):
    """build_fragment_sockopt — pure dict builder."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_dict_with_required_keys(self):
        from chimera.modules.fragment_config import build_fragment_sockopt
        s = build_fragment_sockopt()
        # TFO (tcpFastOpen) УБРАН из дефолта — инцидент 28.08.2026 (DPI
        # резал data-in-SYN). Проверяем что базовые поля на месте.
        for key in ("tcpKeepAliveInterval", "tcpKeepAliveIdle",
                     "tcpUserTimeout", "tcpCongestion", "fragment"):
            self.assertIn(key, s)
        self.assertNotIn("tcpFastOpen", s,
                         "TFO не должен быть в sockopt по умолчанию")

    def test_default_values(self):
        from chimera.modules.fragment_config import build_fragment_sockopt
        s = build_fragment_sockopt()
        self.assertNotIn("tcpFastOpen", s)
        self.assertEqual(s["tcpCongestion"], "bbr")
        self.assertEqual(s["fragment"]["packets"], "1-3")
        self.assertEqual(s["fragment"]["length"], "3-7")
        self.assertEqual(s["fragment"]["interval"], "10-20")

    def test_tfo_added_when_enabled(self):
        """При включённом TFO (override) поле tcpFastOpen появляется."""
        from chimera.modules import tfo_settings
        from chimera.modules.fragment_config import build_fragment_sockopt
        tfo_settings.set_tfo_override(True)
        try:
            s = build_fragment_sockopt()
            self.assertTrue(s.get("tcpFastOpen"))
        finally:
            tfo_settings.clear_tfo_override()

    def test_custom_values(self):
        from chimera.modules.fragment_config import build_fragment_sockopt
        s = build_fragment_sockopt(packets="5-10", length="100-200", interval="50-100")
        self.assertEqual(s["fragment"]["packets"], "5-10")
        self.assertEqual(s["fragment"]["length"], "100-200")
        self.assertEqual(s["fragment"]["interval"], "50-100")


class TestValidateRangeStr(unittest.TestCase):
    """_validate_range_str — валидатор диапазонов."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_single_number_valid(self):
        from chimera.modules.fragment_config import _validate_range_str
        self.assertTrue(_validate_range_str("3", "test"))
        self.assertTrue(_validate_range_str("10", "test"))

    def test_range_valid(self):
        from chimera.modules.fragment_config import _validate_range_str
        self.assertTrue(_validate_range_str("3-7", "test"))
        self.assertTrue(_validate_range_str("1-100", "test"))

    def test_zero_invalid(self):
        from chimera.modules.fragment_config import _validate_range_str
        self.assertFalse(_validate_range_str("0", "test"))
        self.assertFalse(_validate_range_str("0-5", "test"))

    def test_reversed_range_invalid(self):
        from chimera.modules.fragment_config import _validate_range_str
        self.assertFalse(_validate_range_str("7-3", "test"))

    def test_non_numeric_invalid(self):
        from chimera.modules.fragment_config import _validate_range_str
        self.assertFalse(_validate_range_str("abc", "test"))
        self.assertFalse(_validate_range_str("a-b", "test"))

    def test_three_parts_invalid(self):
        from chimera.modules.fragment_config import _validate_range_str
        self.assertFalse(_validate_range_str("3-7-9", "test"))

    def test_strips_whitespace(self):
        from chimera.modules.fragment_config import _validate_range_str
        self.assertTrue(_validate_range_str("  3-7  ", "test"))


class TestFragmentPresets(unittest.TestCase):
    """_FRAGMENT_PRESETS — структура."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_aggressive_balanced_light_custom(self):
        from chimera.modules.fragment_config import _FRAGMENT_PRESETS
        for name in ("aggressive", "balanced", "light", "custom"):
            self.assertIn(name, _FRAGMENT_PRESETS)

    def test_each_preset_has_required_keys(self):
        from chimera.modules.fragment_config import _FRAGMENT_PRESETS
        for name, preset in _FRAGMENT_PRESETS.items():
            with self.subTest(preset=name):
                for key in ("packets", "length", "interval", "desc"):
                    self.assertIn(key, preset)


class TestGenerateFragmentClientConfig(unittest.TestCase):
    """generate_fragment_client_config — генерация конфига."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"
        self._frag_dir = self._tmpdir / "fragment"
        self._frag_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("chimera.modules.fragment_config._STATE_FILE", self._state),
            patch("chimera.modules.fragment_config._FRAGMENT_DIR", self._frag_dir),
        )

    def test_returns_none_when_no_state(self):
        from chimera.modules.fragment_config import generate_fragment_client_config
        with self._patch()[0], self._patch()[1]:
            result = generate_fragment_client_config("1-3", "3-7", "10-20")
        self.assertIsNone(result)

    def test_returns_none_when_no_domain(self):
        from chimera.modules.fragment_config import generate_fragment_client_config
        self._state.write_text(json.dumps({"uuid": "abc"}))
        with self._patch()[0], self._patch()[1]:
            result = generate_fragment_client_config("1-3", "3-7", "10-20")
        self.assertIsNone(result)

    def test_returns_none_when_no_uuid(self):
        from chimera.modules.fragment_config import generate_fragment_client_config
        self._state.write_text(json.dumps({"domain": "x.com"}))
        with self._patch()[0], self._patch()[1]:
            result = generate_fragment_client_config("1-3", "3-7", "10-20")
        self.assertIsNone(result)

    def test_generates_reality_config(self):
        from chimera.modules.fragment_config import generate_fragment_client_config
        self._state.write_text(json.dumps({
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "reality",
            "reality_dest": "dest.example.com:443",
            "reality_pubkey": "PUBKEY",
            "reality_privkey": "PRIVKEY",
            "reality_shortid": "abcd1234",
        }))
        with self._patch()[0], self._patch()[1]:
            result = generate_fragment_client_config("1-3", "3-7", "10-20", label="test")
        self.assertIsNotNone(result)
        self.assertTrue(result.exists())
        content = result.read_text()
        self.assertIn("vpn.example.com", content)
        self.assertIn("test-uuid", content)

    def test_sanitizes_label(self):
        """label с пробелами и спецсимволами — санитизируется."""
        from chimera.modules.fragment_config import generate_fragment_client_config
        self._state.write_text(json.dumps({
            "domain": "x.com", "uuid": "u",
            "protocol_mode": "reality",
            "reality_dest": "d:443", "reality_pubkey": "p",
            "reality_privkey": "k", "reality_shortid": "s",
        }))
        with self._patch()[0], self._patch()[1]:
            result = generate_fragment_client_config("1-3", "3-7", "10-20",
                                                     label="test name!@#")
        self.assertIsNotNone(result)
        # имя файла должно содержать только alnum/-/_
        for c in result.name:
            self.assertTrue(c.isalnum() or c in "-_.")


if __name__ == "__main__":
    unittest.main(verbosity=2)
