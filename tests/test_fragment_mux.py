#!/usr/bin/env python3
"""
tests/test_fragment_mux.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/fragment_mux.py.

Покрывает:
  1. build_mux_outbound_patch — генерация mux dict для Xray
  2. build_singbox_multiplex — генерация multiplex dict для Sing-box
  3. _resolve_sni — выбор SNI
  4. _MUX_PRESETS / _SINGBOX_PROTOCOLS — структура
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


class TestBuildMuxOutboundPatch(unittest.TestCase):
    """build_mux_outbound_patch — pure dict builder."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_dict_with_required_keys(self):
        from vless_installer.modules.fragment_mux import build_mux_outbound_patch
        m = build_mux_outbound_patch()
        for key in ("enabled", "concurrency", "xudpConcurrency", "xudpProxyUDP443"):
            self.assertIn(key, m)

    def test_default_values(self):
        from vless_installer.modules.fragment_mux import build_mux_outbound_patch
        m = build_mux_outbound_patch()
        self.assertTrue(m["enabled"])
        self.assertEqual(m["concurrency"], 8)
        self.assertEqual(m["xudpConcurrency"], 16)
        self.assertEqual(m["xudpProxyUDP443"], "reject")

    def test_custom_values(self):
        from vless_installer.modules.fragment_mux import build_mux_outbound_patch
        m = build_mux_outbound_patch(concurrency=16, xudp=32)
        self.assertEqual(m["concurrency"], 16)
        self.assertEqual(m["xudpConcurrency"], 32)


class TestBuildSingboxMultiplex(unittest.TestCase):
    """build_singbox_multiplex — pure dict builder."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_dict_with_required_keys(self):
        from vless_installer.modules.fragment_mux import build_singbox_multiplex
        m = build_singbox_multiplex()
        for key in ("enabled", "protocol", "max_connections", "min_streams", "padding"):
            self.assertIn(key, m)

    def test_default_values(self):
        from vless_installer.modules.fragment_mux import build_singbox_multiplex
        m = build_singbox_multiplex()
        self.assertTrue(m["enabled"])
        self.assertEqual(m["protocol"], "h2mux")
        self.assertEqual(m["max_connections"], 4)
        self.assertEqual(m["min_streams"], 4)
        self.assertTrue(m["padding"])

    def test_custom_protocol(self):
        from vless_installer.modules.fragment_mux import build_singbox_multiplex
        m = build_singbox_multiplex(protocol="smux", max_connections=8, min_streams=2)
        self.assertEqual(m["protocol"], "smux")
        self.assertEqual(m["max_connections"], 8)
        self.assertEqual(m["min_streams"], 2)


class TestResolveSni(unittest.TestCase):
    """_resolve_sni — аналогичен fragment_noise."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_domain_for_reality_without_awg(self):
        from vless_installer.modules.fragment_mux import _resolve_sni
        state = {"proto": "reality", "domain": "vpn.example.com"}
        self.assertEqual(_resolve_sni(state), "vpn.example.com")

    def test_returns_reality_dest_for_awg_reality_mode_b(self):
        from vless_installer.modules.fragment_mux import _resolve_sni
        state = {
            "proto": "reality", "awg_exit_enabled": True,
            "install_mode": "B", "reality_dest": "dest.example.com:443",
            "domain": "vpn.example.com",
        }
        self.assertEqual(_resolve_sni(state), "dest.example.com")


class TestMuxPresets(unittest.TestCase):
    """_MUX_PRESETS / _SINGBOX_PROTOCOLS — структура."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_mux_presets_has_light_medium_heavy(self):
        from vless_installer.modules.fragment_mux import _MUX_PRESETS
        for name in ("light", "medium", "heavy"):
            self.assertIn(name, _MUX_PRESETS)

    def test_singbox_protocols_has_h2mux_smux_yamux(self):
        from vless_installer.modules.fragment_mux import _SINGBOX_PROTOCOLS
        for proto in ("h2mux", "smux", "yamux"):
            self.assertIn(proto, _SINGBOX_PROTOCOLS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
