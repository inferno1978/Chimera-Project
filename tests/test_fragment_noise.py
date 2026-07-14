#!/usr/bin/env python3
"""
tests/test_fragment_noise.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/fragment_noise.py.

Покрывает:
  1. build_noise_sockopt — генерация sockopt с noise
  2. build_singbox_noise_dial — генерация Sing-box dial
  3. _resolve_sni — выбор SNI
  4. _load_state — чтение state
  5. _NOISE_PRESETS — структура пресетов
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


class TestBuildNoiseSockopt(unittest.TestCase):
    """build_noise_sockopt — pure dict builder."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_dict_with_fragment_and_noise(self):
        from chimera.modules.fragment_noise import build_noise_sockopt
        s = build_noise_sockopt()
        self.assertIn("fragment", s)
        self.assertIn("noise", s)
        self.assertIsInstance(s["noise"], list)
        self.assertEqual(len(s["noise"]), 1)

    def test_default_noise_values(self):
        from chimera.modules.fragment_noise import build_noise_sockopt
        s = build_noise_sockopt()
        noise = s["noise"][0]
        self.assertEqual(noise["type"], "rand")
        self.assertEqual(noise["packet"], "20-50")
        self.assertEqual(noise["delay"], "10-20")

    def test_custom_noise_values(self):
        from chimera.modules.fragment_noise import build_noise_sockopt
        s = build_noise_sockopt(noise_packet="100-200", noise_delay="50-100")
        noise = s["noise"][0]
        self.assertEqual(noise["packet"], "100-200")
        self.assertEqual(noise["delay"], "50-100")

    def test_has_tcp_fast_open(self):
        from chimera.modules.fragment_noise import build_noise_sockopt
        s = build_noise_sockopt()
        self.assertTrue(s["tcpFastOpen"])


class TestBuildSingboxNoiseDial(unittest.TestCase):
    """build_singbox_noise_dial — pure dict builder."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_dict_with_required_keys(self):
        from chimera.modules.fragment_noise import build_singbox_noise_dial
        d = build_singbox_noise_dial("1-3", "3-7", "10-20", "20-50", "10-20")
        for key in ("tcp_fast_open", "fragment", "noise"):
            self.assertIn(key, d)

    def test_fragment_enabled(self):
        from chimera.modules.fragment_noise import build_singbox_noise_dial
        d = build_singbox_noise_dial("1-3", "3-7", "10-20", "20-50", "10-20")
        self.assertTrue(d["fragment"]["enabled"])
        self.assertEqual(d["fragment"]["size"], "3-7")
        self.assertEqual(d["fragment"]["sleep"], "10-20")

    def test_noise_enabled(self):
        from chimera.modules.fragment_noise import build_singbox_noise_dial
        d = build_singbox_noise_dial("1-3", "3-7", "10-20", "20-50", "10-20")
        self.assertTrue(d["noise"]["enabled"])
        self.assertEqual(d["noise"]["type"], "rand")
        self.assertEqual(d["noise"]["packet"], "20-50")


class TestResolveSni(unittest.TestCase):
    """_resolve_sni — выбор SNI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_domain_for_reality_without_awg(self):
        from chimera.modules.fragment_noise import _resolve_sni
        state = {"proto": "reality", "domain": "vpn.example.com"}
        self.assertEqual(_resolve_sni(state), "vpn.example.com")

    def test_returns_reality_dest_for_awg_reality_mode_b(self):
        from chimera.modules.fragment_noise import _resolve_sni
        state = {
            "proto": "reality", "awg_exit_enabled": True,
            "install_mode": "B", "reality_dest": "dest.example.com:443",
            "domain": "vpn.example.com",
        }
        self.assertEqual(_resolve_sni(state), "dest.example.com")

    def test_returns_domain_when_awg_but_mode_not_b(self):
        from chimera.modules.fragment_noise import _resolve_sni
        state = {
            "proto": "reality", "awg_exit_enabled": True,
            "install_mode": "A", "reality_dest": "dest:443",
            "domain": "vpn.example.com",
        }
        self.assertEqual(_resolve_sni(state), "vpn.example.com")

    def test_returns_domain_for_xhttp(self):
        from chimera.modules.fragment_noise import _resolve_sni
        state = {"proto": "xhttp", "domain": "vpn.example.com"}
        self.assertEqual(_resolve_sni(state), "vpn.example.com")


class TestLoadState(unittest.TestCase):
    """_load_state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.fragment_noise._STATE_FILE", self._state)

    def test_returns_none_when_no_file(self):
        from chimera.modules.fragment_noise import _load_state
        with self._patch():
            self.assertIsNone(_load_state())

    def test_returns_none_when_no_domain(self):
        from chimera.modules.fragment_noise import _load_state
        self._state.write_text(json.dumps({"uuid": "u"}))
        with self._patch():
            self.assertIsNone(_load_state())

    def test_returns_none_when_no_uuid(self):
        from chimera.modules.fragment_noise import _load_state
        self._state.write_text(json.dumps({"domain": "x.com"}))
        with self._patch():
            self.assertIsNone(_load_state())

    def test_returns_state_when_valid(self):
        from chimera.modules.fragment_noise import _load_state
        self._state.write_text(json.dumps({"domain": "x.com", "uuid": "u"}))
        with self._patch():
            st = _load_state()
        self.assertIsNotNone(st)
        self.assertEqual(st["domain"], "x.com")


class TestNoisePresets(unittest.TestCase):
    """_NOISE_PRESETS — структура."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_light_medium_aggressive(self):
        from chimera.modules.fragment_noise import _NOISE_PRESETS
        for name in ("light", "medium", "aggressive"):
            self.assertIn(name, _NOISE_PRESETS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
