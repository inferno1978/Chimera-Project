#!/usr/bin/env python3
"""
tests/test_fragment_mux.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/fragment_mux.py.

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


class TestBuildMuxOutboundPatch(unittest.TestCase):
    """build_mux_outbound_patch — pure dict builder."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_dict_with_required_keys(self):
        from chimera.modules.fragment_mux import build_mux_outbound_patch
        m = build_mux_outbound_patch()
        for key in ("enabled", "concurrency", "xudpConcurrency", "xudpProxyUDP443"):
            self.assertIn(key, m)

    def test_default_values(self):
        from chimera.modules.fragment_mux import build_mux_outbound_patch
        m = build_mux_outbound_patch()
        self.assertTrue(m["enabled"])
        self.assertEqual(m["concurrency"], 8)
        self.assertEqual(m["xudpConcurrency"], 16)
        self.assertEqual(m["xudpProxyUDP443"], "reject")

    def test_custom_values(self):
        from chimera.modules.fragment_mux import build_mux_outbound_patch
        m = build_mux_outbound_patch(concurrency=16, xudp=32)
        self.assertEqual(m["concurrency"], 16)
        self.assertEqual(m["xudpConcurrency"], 32)


class TestBuildSingboxMultiplex(unittest.TestCase):
    """build_singbox_multiplex — pure dict builder."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_dict_with_required_keys(self):
        from chimera.modules.fragment_mux import build_singbox_multiplex
        m = build_singbox_multiplex()
        for key in ("enabled", "protocol", "max_connections", "min_streams", "padding"):
            self.assertIn(key, m)

    def test_default_values(self):
        from chimera.modules.fragment_mux import build_singbox_multiplex
        m = build_singbox_multiplex()
        self.assertTrue(m["enabled"])
        self.assertEqual(m["protocol"], "h2mux")
        self.assertEqual(m["max_connections"], 4)
        self.assertEqual(m["min_streams"], 4)
        self.assertTrue(m["padding"])

    def test_custom_protocol(self):
        from chimera.modules.fragment_mux import build_singbox_multiplex
        m = build_singbox_multiplex(protocol="smux", max_connections=8, min_streams=2)
        self.assertEqual(m["protocol"], "smux")
        self.assertEqual(m["max_connections"], 8)
        self.assertEqual(m["min_streams"], 2)


class TestResolveSni(unittest.TestCase):
    """_resolve_sni — аналогичен fragment_noise."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_domain_for_reality_without_awg(self):
        from chimera.modules.fragment_mux import _resolve_sni
        state = {"proto": "reality", "domain": "vpn.example.com"}
        self.assertEqual(_resolve_sni(state), "vpn.example.com")

    def test_returns_reality_dest_for_awg_reality_mode_b(self):
        from chimera.modules.fragment_mux import _resolve_sni
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
        from chimera.modules.fragment_mux import _MUX_PRESETS
        for name in ("light", "medium", "heavy"):
            self.assertIn(name, _MUX_PRESETS)

    def test_singbox_protocols_has_h2mux_smux_yamux(self):
        from chimera.modules.fragment_mux import _SINGBOX_PROTOCOLS
        for proto in ("h2mux", "smux", "yamux"):
            self.assertIn(proto, _SINGBOX_PROTOCOLS)


class TestXhttpRealityBranches(unittest.TestCase):
    """xhttp_reality — транспорт xHTTP + REALITY TLS, БЕЗ flow."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._state = {
            "protocol_mode": "xhttp_reality",
            "domain": "vpn.example.com",
            "server_port": 443,
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
            "fingerprint": "chrome",
            "xhttp_path": "/xhttp",
            "xhttp_mode": "stream-up",
            "xtls_flow": "xtls-rprx-vision",
        }

    def test_resolve_sni_returns_reality_dest_for_awg_mode_b(self):
        from chimera.modules.fragment_mux import _resolve_sni
        state = {**self._state, "awg_exit_enabled": True,
                 "install_mode": "B", "reality_dest": "dest.example.com:443"}
        self.assertEqual(_resolve_sni(state), "dest.example.com")

    def test_resolve_sni_returns_domain_without_awg(self):
        from chimera.modules.fragment_mux import _resolve_sni
        self.assertEqual(_resolve_sni(self._state), "vpn.example.com")

    def test_xray_json_without_flow_and_with_reality(self):
        from chimera.modules.fragment_mux import _build_xray_mux_json
        cfg = _build_xray_mux_json(self._state, "1-3", "3-7", "10-20", 8, 16)
        ob = cfg["outbounds"][0]
        ss = ob["streamSettings"]
        # users БЕЗ flow — xhttp-транспорт несовместим с vision
        self.assertNotIn("flow", ob["settings"]["vnext"][0]["users"][0])
        self.assertEqual(ss["network"], "xhttp")
        self.assertEqual(ss["security"], "reality")
        self.assertEqual(ss["xhttpSettings"],
                         {"path": "/xhttp", "mode": "stream-up"})
        rs = ss["realitySettings"]
        self.assertFalse(rs["show"])
        self.assertEqual(rs["serverName"], "vpn.example.com")
        self.assertEqual(rs["publicKey"], "PUBKEY")
        self.assertEqual(rs["shortId"], "abcd1234")
        self.assertEqual(rs["spiderX"], "/")
        self.assertNotIn("tlsSettings", ss)
        # mux присутствует, fragment в sockopt
        self.assertTrue(ob["mux"]["enabled"])
        self.assertEqual(ss["sockopt"]["fragment"]["length"], "3-7")

    def test_singbox_json_transport_xhttp_tls_reality_no_flow(self):
        from chimera.modules.fragment_mux import _build_singbox_mux_json
        cfg = _build_singbox_mux_json(self._state, "1-3", "3-7", "10-20",
                                      "h2mux")
        ob = cfg["outbounds"][0]
        self.assertNotIn("flow", ob)
        self.assertEqual(ob["transport"],
                         {"type": "xhttp", "mode": "stream-up",
                          "path": "/xhttp"})
        self.assertEqual(ob["tls"]["server_name"], "vpn.example.com")
        self.assertTrue(ob["tls"]["utls"]["enabled"])
        self.assertTrue(ob["tls"]["reality"]["enabled"])
        self.assertEqual(ob["tls"]["reality"]["public_key"], "PUBKEY")
        self.assertTrue(ob["multiplex"]["enabled"])
        self.assertTrue(ob["fragment"]["enabled"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
