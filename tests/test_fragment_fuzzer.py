#!/usr/bin/env python3
"""
tests/test_fragment_fuzzer.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/fragment_fuzzer.py.

Покрывает:
  1. _build_test_client_config — xhttp_reality: xhttp + REALITY, БЕЗ flow
  2. _build_test_client_config — регрессия reality / xhttp
"""
from __future__ import annotations

import sys
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


class TestBuildTestClientConfigXhttpReality(unittest.TestCase):
    """_build_test_client_config — ветка xhttp_reality (Режим A)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._state = {
            "protocol_mode": "xhttp_reality",
            "domain": "vpn.example.com",
            "server_port": 443,
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
            "fingerprint": "firefox",
            "xhttp_path": "/xhttp",
            "xhttp_mode": "stream-up",
            "xtls_flow": "xtls-rprx-vision",
        }

    def _build(self, state=None):
        from chimera.modules.fragment_fuzzer import _build_test_client_config
        return _build_test_client_config(state or self._state,
                                         "1-3", "3-7", "10-20", 10900)

    def test_xhttp_reality_without_flow(self):
        cfg = self._build()
        ob = cfg["outbounds"][0]
        ss = ob["streamSettings"]
        # users БЕЗ flow — xhttp-транспорт несовместим с vision
        self.assertNotIn("flow", ob["settings"]["vnext"][0]["users"][0])
        self.assertEqual(ss["network"], "xhttp")
        self.assertEqual(ss["security"], "reality")
        self.assertEqual(ss["xhttpSettings"],
                         {"path": "/xhttp", "mode": "stream-up"})
        rs = ss["realitySettings"]
        # SNI по канону: без AWG — domain
        self.assertEqual(rs["serverName"], "vpn.example.com")
        self.assertEqual(rs["publicKey"], "PUBKEY")
        self.assertEqual(rs["shortId"], "abcd1234")
        self.assertEqual(rs["spiderX"], "/")
        self.assertNotIn("tlsSettings", ss)
        # фрагментация на месте (вся суть fuzzer'а)
        self.assertEqual(ss["sockopt"]["fragment"]["length"], "3-7")

    def test_xhttp_reality_awg_sni(self):
        """xhttp_reality + AWG Mode B: SNI = reality_dest (serverNames)."""
        state = {**self._state, "awg_exit_enabled": True,
                 "install_mode": "B", "reality_dest": "dest.example.com:443"}
        cfg = self._build(state)
        rs = cfg["outbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(rs["serverName"], "dest.example.com")

    def test_reality_regression(self):
        """Классический reality (Mode A): SNI = domain (canonical sni_hygiene).

        прежний тест ассертил баг — SNI брался из reality_dest даже
        БЕЗ Mode B/AWG, тогда как сервер в Mode A ждёт serverNames=[domain].
        Канонический рул (как в E2E-проверенной xhttp_reality ветке):
        Mode B + awg_exit_enabled + reality_dest → reality_dest, иначе domain.
        """
        cfg = self._build({**self._state, "protocol_mode": "reality",
                           "reality_dest": "dest.example.com:443"})
        ob = cfg["outbounds"][0]
        ss = ob["streamSettings"]
        self.assertEqual(ss["network"], "tcp")
        self.assertEqual(ss["security"], "reality")
        self.assertEqual(ob["settings"]["vnext"][0]["users"][0].get("flow"),
                         "xtls-rprx-vision")
        self.assertEqual(ss["realitySettings"]["serverName"],
                         "vpn.example.com")

    def test_reality_awg_mode_b_sni(self):
        """Классический reality + AWG Mode B: SNI = reality_dest."""
        cfg = self._build({**self._state, "protocol_mode": "reality",
                           "awg_exit_enabled": True, "install_mode": "B",
                           "reality_dest": "dest.example.com:443"})
        rs = cfg["outbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(rs["serverName"], "dest.example.com")

    def test_xhttp_regression(self):
        """xhttp (TLS, без REALITY): tlsSettings, нет realitySettings."""
        cfg = self._build({**self._state, "protocol_mode": "xhttp"})
        ob = cfg["outbounds"][0]
        ss = ob["streamSettings"]
        self.assertEqual(ss["security"], "tls")
        self.assertIn("tlsSettings", ss)
        self.assertNotIn("realitySettings", ss)


if __name__ == "__main__":
    unittest.main(verbosity=2)
