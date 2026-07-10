#!/usr/bin/env python3
"""
tests/test_fragment_link.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/fragment_link.py.

Покрывает:
  1. _resolve_sni — выбор SNI
  2. _gen_happ_link — генерация Happ URI
  3. _gen_incy_link — генерация Incy URI
  4. _gen_nekoray_link — генерация Nekoray URI
  5. _build_xray_client_json — генерация Xray клиентского конфига
  6. _build_singbox_json — генерация Sing-box конфига
  7. _load_state — чтение state
"""
from __future__ import annotations

import json
import sys
import tempfile
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


class TestResolveSni(unittest.TestCase):
    """_resolve_sni — выбор SNI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_domain_for_reality_without_awg(self):
        from vless_installer.modules.fragment_link import _resolve_sni
        state = {"protocol_mode": "reality", "domain": "vpn.example.com"}
        self.assertEqual(_resolve_sni(state), "vpn.example.com")

    def test_returns_reality_dest_for_awg_reality_mode_b(self):
        from vless_installer.modules.fragment_link import _resolve_sni
        state = {
            "protocol_mode": "reality", "awg_exit_enabled": True,
            "install_mode": "B", "reality_dest": "dest.example.com:443",
            "domain": "vpn.example.com",
        }
        self.assertEqual(_resolve_sni(state), "dest.example.com")

    def test_returns_domain_for_xhttp(self):
        from vless_installer.modules.fragment_link import _resolve_sni
        state = {"protocol_mode": "xhttp", "domain": "vpn.example.com"}
        self.assertEqual(_resolve_sni(state), "vpn.example.com")


class TestGenHappLink(unittest.TestCase):
    """_gen_happ_link — генерация Happ URI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_vless_uri_with_fragment(self):
        from vless_installer.modules.fragment_link import _gen_happ_link
        link = _gen_happ_link(
            host="1.2.3.4", uuid_str="uuid", pbk="PUBKEY", sid="abcd",
            sni="vpn.example.com", packets="1-3", length="3-7", interval="10-20",
        )
        self.assertTrue(link.startswith("vless://"))
        self.assertIn("fragment=", link)
        self.assertIn("Happ", link)

    def test_fragment_format_is_length_interval_packets(self):
        """Happ формат: fragment=length,interval,packets (URL-encoded)."""
        from vless_installer.modules.fragment_link import _gen_happ_link
        import urllib.parse
        link = _gen_happ_link(
            host="1.2.3.4", uuid_str="uuid", pbk="PUBKEY", sid="abcd",
            sni="vpn.example.com", packets="1-3", length="3-7", interval="10-20",
        )
        # извлекаем fragment= значение (до # label)
        query = link.split("#", 1)[0]
        frag_part = [p for p in query.split("&") if p.startswith("fragment=")][0]
        frag_val = urllib.parse.unquote(frag_part.split("=", 1)[1])
        self.assertEqual(frag_val, "3-7,10-20,1-3")

    def test_reality_includes_pbk_and_sid(self):
        from vless_installer.modules.fragment_link import _gen_happ_link
        link = _gen_happ_link(
            host="1.2.3.4", uuid_str="uuid", pbk="PUBKEY", sid="abcd",
            sni="vpn.example.com", packets="1-3", length="3-7", interval="10-20",
        )
        self.assertIn("pbk=PUBKEY", link)
        self.assertIn("sid=abcd", link)


class TestGenIncyLink(unittest.TestCase):
    """_gen_incy_link — генерация Incy URI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_vless_uri_with_fragment_length_and_interval(self):
        from vless_installer.modules.fragment_link import _gen_incy_link
        link = _gen_incy_link(
            host="1.2.3.4", uuid_str="uuid", pbk="PUBKEY", sid="abcd",
            sni="vpn.example.com", packets="1-3", length="3-7", interval="10-20",
        )
        self.assertTrue(link.startswith("vless://"))
        self.assertIn("fragmentLength=3-7", link)
        self.assertIn("fragmentInterval=10-20", link)
        self.assertIn("Incy", link)

    def test_does_not_include_packets_in_uri(self):
        """Incy не использует packets в URI — только length+interval."""
        from vless_installer.modules.fragment_link import _gen_incy_link
        link = _gen_incy_link(
            host="1.2.3.4", uuid_str="uuid", pbk="PUBKEY", sid="abcd",
            sni="vpn.example.com", packets="1-3", length="3-7", interval="10-20",
        )
        self.assertNotIn("fragmentPackets", link)


class TestGenNekorayLink(unittest.TestCase):
    """_gen_nekoray_link — генерация Nekoray URI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_vless_uri_with_fragment(self):
        from vless_installer.modules.fragment_link import _gen_nekoray_link
        link = _gen_nekoray_link(
            host="1.2.3.4", uuid_str="uuid", pbk="PUBKEY", sid="abcd",
            sni="vpn.example.com", packets="1-3", length="3-7", interval="10-20",
        )
        self.assertTrue(link.startswith("vless://"))
        self.assertIn("fragment=", link)
        self.assertIn("Neko", link)

    def test_fragment_format_is_packets_length_interval(self):
        """Nekoray формат: fragment=packets,length,interval (порядок важен!)."""
        from vless_installer.modules.fragment_link import _gen_nekoray_link
        import urllib.parse
        link = _gen_nekoray_link(
            host="1.2.3.4", uuid_str="uuid", pbk="PUBKEY", sid="abcd",
            sni="vpn.example.com", packets="1-3", length="3-7", interval="10-20",
        )
        query = link.split("#", 1)[0]
        frag_part = [p for p in query.split("&") if p.startswith("fragment=")][0]
        frag_val = urllib.parse.unquote(frag_part.split("=", 1)[1])
        self.assertEqual(frag_val, "1-3,3-7,10-20")


class TestBuildXrayClientJson(unittest.TestCase):
    """_build_xray_client_json — генерация Xray клиентского конфига."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _state(self):
        return {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd",
            "reality_dest": "dest:443",
            "fingerprint": "chrome",
            "server_port": 443,
        }

    def test_returns_dict_with_required_keys(self):
        from vless_installer.modules.fragment_link import _build_xray_client_json
        cfg = _build_xray_client_json(self._state(), "1-3", "3-7", "10-20")
        for key in ("log", "inbounds", "outbounds", "routing"):
            self.assertIn(key, cfg)

    def test_has_socks_and_http_inbounds(self):
        from vless_installer.modules.fragment_link import _build_xray_client_json
        cfg = _build_xray_client_json(self._state(), "1-3", "3-7", "10-20")
        protocols = [ib["protocol"] for ib in cfg["inbounds"]]
        self.assertIn("socks", protocols)
        self.assertIn("http", protocols)

    def test_has_proxy_direct_block_outbounds(self):
        from vless_installer.modules.fragment_link import _build_xray_client_json
        cfg = _build_xray_client_json(self._state(), "1-3", "3-7", "10-20")
        tags = [ob["tag"] for ob in cfg["outbounds"]]
        self.assertIn("proxy", tags)
        self.assertIn("direct", tags)
        self.assertIn("block", tags)

    def test_fragment_included_when_all_params_present(self):
        from vless_installer.modules.fragment_link import _build_xray_client_json
        cfg = _build_xray_client_json(self._state(), "1-3", "3-7", "10-20")
        proxy = [ob for ob in cfg["outbounds"] if ob["tag"] == "proxy"][0]
        self.assertIn("fragment", proxy.get("streamSettings", {}).get("sockopt", {}))

    def test_fragment_omitted_when_params_empty(self):
        from vless_installer.modules.fragment_link import _build_xray_client_json
        cfg = _build_xray_client_json(self._state(), "", "", "")
        proxy = [ob for ob in cfg["outbounds"] if ob["tag"] == "proxy"][0]
        sockopt = proxy.get("streamSettings", {}).get("sockopt", {})
        self.assertNotIn("fragment", sockopt)


class TestBuildSingboxJson(unittest.TestCase):
    """_build_singbox_json — генерация Sing-box конфига."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _state(self):
        return {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd",
            "reality_dest": "dest:443",
            "fingerprint": "chrome",
            "server_port": 443,
        }

    def test_returns_dict_with_required_keys(self):
        from vless_installer.modules.fragment_link import _build_singbox_json
        cfg = _build_singbox_json(self._state(), "1-3", "3-7", "10-20")
        for key in ("inbounds", "outbounds", "route"):
            self.assertIn(key, cfg)

    def test_has_socks_and_http_inbounds(self):
        from vless_installer.modules.fragment_link import _build_singbox_json
        cfg = _build_singbox_json(self._state(), "1-3", "3-7", "10-20")
        types = [ib["type"] for ib in cfg["inbounds"]]
        self.assertIn("socks", types)
        self.assertIn("http", types)

    def test_fragment_in_outbound_when_present(self):
        from vless_installer.modules.fragment_link import _build_singbox_json
        cfg = _build_singbox_json(self._state(), "1-3", "3-7", "10-20")
        proxy = cfg["outbounds"][0]
        # fragment может быть на верхнем уровне outbound или в dial_fields
        frag = proxy.get("fragment") or proxy.get("dial_fields", {}).get("fragment")
        self.assertIsNotNone(frag)
        self.assertTrue(frag["enabled"])

    def test_fragment_omitted_when_params_empty(self):
        from vless_installer.modules.fragment_link import _build_singbox_json
        cfg = _build_singbox_json(self._state(), "", "", "")
        proxy = cfg["outbounds"][0]
        frag = proxy.get("fragment") or proxy.get("dial_fields", {}).get("fragment")
        self.assertIsNone(frag)


class TestLoadState(unittest.TestCase):
    """_load_state — чтение state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.fragment_link._STATE_FILE", self._state)

    def test_returns_none_when_no_file(self):
        from vless_installer.modules.fragment_link import _load_state
        with self._patch():
            self.assertIsNone(_load_state())

    def test_returns_none_when_no_domain(self):
        from vless_installer.modules.fragment_link import _load_state
        self._state.write_text(json.dumps({"uuid": "u"}))
        with self._patch():
            self.assertIsNone(_load_state())

    def test_returns_state_when_valid(self):
        from vless_installer.modules.fragment_link import _load_state
        self._state.write_text(json.dumps({"domain": "x.com", "uuid": "u"}))
        with self._patch():
            st = _load_state()
        self.assertIsNotNone(st)
        self.assertEqual(st["domain"], "x.com")


if __name__ == "__main__":
    unittest.main(verbosity=2)
