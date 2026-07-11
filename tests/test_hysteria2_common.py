#!/usr/bin/env python3
"""
tests/test_hysteria2_common.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/hysteria2_common.py.

Покрывает:
  1. _h2_default_state — структура дефолтного state
  2. _is_ipv6 — определение IPv6
  3. _bracket — оборачивание IPv6 в […]
  4. _load_state / _save_state — JSON I/O
  5. _load_h2_state / _save_h2_state — подсекция hysteria2
  6. _ensure_h2_state — гарантирует наличие секции
  7. _h2_binary_exists — проверка бинарника
"""
from __future__ import annotations

import json
import os
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


class TestH2DefaultState(unittest.TestCase):
    """_h2_default_state — структура."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_dict(self):
        from vless_installer.modules.hysteria2_common import _h2_default_state
        st = _h2_default_state()
        self.assertIsInstance(st, dict)

    def test_has_required_top_level_keys(self):
        from vless_installer.modules.hysteria2_common import _h2_default_state
        st = _h2_default_state()
        for key in ("enabled", "transport_only", "exit_nodes", "cert",
                     "health_check", "firewall", "balancer", "auto_update"):
            self.assertIn(key, st, f"missing key: {key}")

    def test_enabled_is_false_by_default(self):
        from vless_installer.modules.hysteria2_common import _h2_default_state
        self.assertFalse(_h2_default_state()["enabled"])


class TestIsIpv6(unittest.TestCase):
    """_is_ipv6 — определение IPv6."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ipv4_returns_false(self):
        from vless_installer.modules.hysteria2_common import _is_ipv6
        self.assertFalse(_is_ipv6("1.2.3.4"))
        self.assertFalse(_is_ipv6("192.168.1.1"))

    def test_ipv6_returns_true(self):
        from vless_installer.modules.hysteria2_common import _is_ipv6
        self.assertTrue(_is_ipv6("::1"))
        self.assertTrue(_is_ipv6("2001:db8::1"))
        self.assertTrue(_is_ipv6("fd66:66:66::1"))

    def test_empty_returns_false(self):
        from vless_installer.modules.hysteria2_common import _is_ipv6
        self.assertFalse(_is_ipv6(""))


class TestBracket(unittest.TestCase):
    """_bracket — оборачивание IPv6 в […]."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ipv4_unchanged(self):
        from vless_installer.modules.hysteria2_common import _bracket
        self.assertEqual(_bracket("1.2.3.4"), "1.2.3.4")

    def test_ipv6_wrapped(self):
        from vless_installer.modules.hysteria2_common import _bracket
        self.assertEqual(_bracket("2001:db8::1"), "[2001:db8::1]")
        self.assertEqual(_bracket("::1"), "[::1]")

    def test_already_bracketed_unchanged(self):
        from vless_installer.modules.hysteria2_common import _bracket
        self.assertEqual(_bracket("[2001:db8::1]"), "[2001:db8::1]")


class TestLoadSaveState(unittest.TestCase):
    """_load_state / _save_state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.hysteria2_common.STATE_FILE", self._state)

    def test_load_returns_empty_when_no_file(self):
        from vless_installer.modules.hysteria2_common import _load_state
        with self._patch():
            self.assertEqual(_load_state(), {})

    def test_load_returns_empty_on_corrupt(self):
        from vless_installer.modules.hysteria2_common import _load_state
        self._state.write_text("{invalid")
        with self._patch():
            self.assertEqual(_load_state(), {})

    def test_load_returns_state(self):
        from vless_installer.modules.hysteria2_common import _load_state
        self._state.write_text(json.dumps({"hysteria2": {"enabled": True}}))
        with self._patch():
            st = _load_state()
        self.assertTrue(st["hysteria2"]["enabled"])

    def test_save_writes_json(self):
        from vless_installer.modules.hysteria2_common import _save_state, _load_state
        with self._patch():
            _save_state({"hysteria2": {"enabled": True}})
            loaded = _load_state()
        self.assertTrue(loaded["hysteria2"]["enabled"])


class TestLoadSaveH2State(unittest.TestCase):
    """_load_h2_state / _save_h2_state — подсекция hysteria2."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.hysteria2_common.STATE_FILE", self._state)

    def test_load_h2_returns_empty_when_no_section(self):
        from vless_installer.modules.hysteria2_common import _load_h2_state
        with self._patch():
            self.assertEqual(_load_h2_state(), {})

    def test_load_h2_returns_section(self):
        from vless_installer.modules.hysteria2_common import _load_h2_state
        self._state.write_text(json.dumps({"hysteria2": {"enabled": True, "port": 8443}}))
        with self._patch():
            h2 = _load_h2_state()
        self.assertTrue(h2["enabled"])
        self.assertEqual(h2["port"], 8443)

    def test_save_h2_preserves_other_keys(self):
        from vless_installer.modules.hysteria2_common import (
            _save_h2_state, _load_h2_state, _load_state,
        )
        self._state.write_text(json.dumps({"uuid": "abc", "domain": "x.com"}))
        with self._patch():
            _save_h2_state({"enabled": True})
            full = _load_state()
        self.assertEqual(full["uuid"], "abc")
        self.assertEqual(full["domain"], "x.com")
        self.assertTrue(full["hysteria2"]["enabled"])


class TestEnsureH2State(unittest.TestCase):
    """_ensure_h2_state — гарантирует наличие секции."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.hysteria2_common.STATE_FILE", self._state)

    def test_creates_default_when_missing(self):
        from vless_installer.modules.hysteria2_common import _ensure_h2_state
        with self._patch():
            h2 = _ensure_h2_state()
        self.assertIn("enabled", h2)
        # файл создан
        self.assertTrue(self._state.exists())

    def test_returns_existing_when_present(self):
        from vless_installer.modules.hysteria2_common import _ensure_h2_state
        self._state.write_text(json.dumps({"hysteria2": {"enabled": True, "custom": "x"}}))
        with self._patch():
            h2 = _ensure_h2_state()
        self.assertTrue(h2["enabled"])
        self.assertEqual(h2["custom"], "x")


class TestH2BinaryExists(unittest.TestCase):
    """_h2_binary_exists."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_false_when_no_binary(self):
        from vless_installer.modules.hysteria2_common import _h2_binary_exists
        with patch("vless_installer.modules.hysteria2_common.H2_BINARY",
                   Path("/tmp/nonexistent_h2_binary")):
            self.assertFalse(_h2_binary_exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
