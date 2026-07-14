#!/usr/bin/env python3
"""
tests/test_hysteria2_transport.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/hysteria2_transport.py.

Покрывает:
  1. _find_xray_config — поиск config.json
  2. _build_socks_outbound — pure dict builder
  3. _find_proxy_outbound_idx — поиск outbound по tag
  4. _find_catchall_rule — поиск catch-all routing rule
  5. _patch_routing_to_proxy — мутация routing
  6. _write_h2_client_config — генерация YAML (mocked write)
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


class TestFindXrayConfig(unittest.TestCase):
    """_find_xray_config."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_none_when_no_config(self):
        from chimera.modules import hysteria2_transport
        with patch.object(hysteria2_transport, "_XRAY_CONFIG",
                          Path("/tmp/nonexistent1")), \
             patch.object(hysteria2_transport, "_XRAY_CONFIG_ALT",
                          Path("/tmp/nonexistent2")):
            self.assertIsNone(hysteria2_transport._find_xray_config())

    def test_returns_alt_when_exists(self):
        from chimera.modules import hysteria2_transport
        alt = self._tmpdir / "config.json"
        alt.write_text("{}")
        with patch.object(hysteria2_transport, "_XRAY_CONFIG",
                          Path("/tmp/nonexistent1")), \
             patch.object(hysteria2_transport, "_XRAY_CONFIG_ALT", alt):
            self.assertEqual(hysteria2_transport._find_xray_config(), alt)


class TestBuildSocksOutbound(unittest.TestCase):
    """_build_socks_outbound — pure dict builder."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_dict_with_required_keys(self):
        from chimera.modules.hysteria2_transport import _build_socks_outbound
        ob = _build_socks_outbound()
        self.assertEqual(ob["protocol"], "socks")
        self.assertEqual(ob["tag"], "proxy")
        self.assertIn("settings", ob)
        self.assertIn("servers", ob["settings"])
        self.assertEqual(len(ob["settings"]["servers"]), 1)

    def test_custom_host_port_tag(self):
        from chimera.modules.hysteria2_transport import _build_socks_outbound
        ob = _build_socks_outbound(host="10.0.0.1", port=1080, tag="my-proxy")
        self.assertEqual(ob["tag"], "my-proxy")
        self.assertEqual(ob["settings"]["servers"][0]["address"], "10.0.0.1")
        self.assertEqual(ob["settings"]["servers"][0]["port"], 1080)


class TestFindProxyOutboundIdx(unittest.TestCase):
    """_find_proxy_outbound_idx — поиск outbound по tag."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_neg1_when_no_outbounds(self):
        from chimera.modules.hysteria2_transport import _find_proxy_outbound_idx
        self.assertEqual(_find_proxy_outbound_idx({}), -1)

    def test_returns_neg1_when_tag_not_found(self):
        from chimera.modules.hysteria2_transport import _find_proxy_outbound_idx
        cfg = {"outbounds": [{"tag": "other"}, {"tag": "another"}]}
        self.assertEqual(_find_proxy_outbound_idx(cfg), -1)

    def test_returns_index_when_found(self):
        from chimera.modules.hysteria2_transport import _find_proxy_outbound_idx
        cfg = {"outbounds": [{"tag": "direct"}, {"tag": "proxy"}, {"tag": "block"}]}
        self.assertEqual(_find_proxy_outbound_idx(cfg), 1)

    def test_custom_tag(self):
        from chimera.modules.hysteria2_transport import _find_proxy_outbound_idx
        cfg = {"outbounds": [{"tag": "x"}, {"tag": "my-tag"}]}
        self.assertEqual(_find_proxy_outbound_idx(cfg, "my-tag"), 1)


class TestFindCatchallRule(unittest.TestCase):
    """_find_catchall_rule — поиск catch-all routing rule."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_none_when_no_routing(self):
        from chimera.modules.hysteria2_transport import _find_catchall_rule
        self.assertIsNone(_find_catchall_rule({}))

    def test_returns_none_when_no_rules(self):
        from chimera.modules.hysteria2_transport import _find_catchall_rule
        cfg = {"routing": {"rules": []}}
        self.assertIsNone(_find_catchall_rule(cfg))

    def test_returns_none_when_all_rules_have_ip(self):
        from chimera.modules.hysteria2_transport import _find_catchall_rule
        cfg = {"routing": {"rules": [
            {"type": "field", "network": "tcp,udp", "ip": ["1.0.0.0/8"], "outboundTag": "proxy"},
        ]}}
        self.assertIsNone(_find_catchall_rule(cfg))

    def test_returns_none_when_block_rule(self):
        from chimera.modules.hysteria2_transport import _find_catchall_rule
        cfg = {"routing": {"rules": [
            {"type": "field", "network": "tcp,udp", "outboundTag": "BLOCK"},
        ]}}
        self.assertIsNone(_find_catchall_rule(cfg))

    def test_returns_rule_when_catchall(self):
        from chimera.modules.hysteria2_transport import _find_catchall_rule
        rule = {"type": "field", "network": "tcp,udp", "outboundTag": "proxy"}
        cfg = {"routing": {"rules": [rule]}}
        self.assertEqual(_find_catchall_rule(cfg), rule)


class TestPatchRoutingToProxy(unittest.TestCase):
    """_patch_routing_to_proxy — мутация routing."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_false_when_no_rule(self):
        from chimera.modules.hysteria2_transport import _patch_routing_to_proxy
        changed, prev = _patch_routing_to_proxy({})
        self.assertFalse(changed)
        self.assertEqual(prev, "")

    def test_returns_false_when_already_set(self):
        from chimera.modules.hysteria2_transport import _patch_routing_to_proxy
        cfg = {"routing": {"rules": [
            {"type": "field", "network": "tcp,udp", "outboundTag": "proxy"},
        ]}}
        changed, prev = _patch_routing_to_proxy(cfg)
        self.assertFalse(changed)
        self.assertEqual(prev, "proxy")

    def test_changes_outbound_tag(self):
        from chimera.modules.hysteria2_transport import _patch_routing_to_proxy
        cfg = {"routing": {"rules": [
            {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
        ]}}
        changed, prev = _patch_routing_to_proxy(cfg, "proxy")
        self.assertTrue(changed)
        self.assertEqual(prev, "direct")
        self.assertEqual(cfg["routing"]["rules"][0]["outboundTag"], "proxy")


class TestWriteH2ClientConfig(unittest.TestCase):
    """_write_h2_client_config — генерация YAML."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "h2_client.yml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.hysteria2_transport._H2_CLIENT_CONFIG",
                     self._cfg)

    def test_writes_yaml_with_ipv4(self):
        from chimera.modules.hysteria2_transport import _write_h2_client_config
        with self._patch():
            result = _write_h2_client_config("1.2.3.4", 8443, "password123")
        self.assertTrue(result)
        content = self._cfg.read_text()
        self.assertIn("1.2.3.4:8443", content)
        self.assertIn("password123", content)

    def test_writes_yaml_with_ipv6(self):
        from chimera.modules.hysteria2_transport import _write_h2_client_config
        with self._patch():
            result = _write_h2_client_config("2001:db8::1", 8443, "pass")
        self.assertTrue(result)
        content = self._cfg.read_text()
        # IPv6 оборачивается в […]
        self.assertIn("[2001:db8::1]:8443", content)

    def test_writes_insecure_when_no_cert(self):
        from chimera.modules.hysteria2_transport import _write_h2_client_config
        with self._patch():
            _write_h2_client_config("1.2.3.4", 8443, "pass")
        content = self._cfg.read_text()
        self.assertIn("insecure: true", content)

    def test_writes_cert_pin_when_provided(self):
        from chimera.modules.hysteria2_transport import _write_h2_client_config
        with self._patch():
            _write_h2_client_config("1.2.3.4", 8443, "pass",
                                     cert_sha256="AB:CD:EF:12:34", sni="vpn.example.com")
        content = self._cfg.read_text()
        self.assertIn("pinSHA256", content)
        # SHA нормализуется: lowercase, без двоеточий
        self.assertIn("abcdef1234", content)
        self.assertIn("vpn.example.com", content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
