#!/usr/bin/env python3
"""
tests/test_awg_standalone.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/awg_standalone.py.

Покрывает:
  1. awgs_build_server_conf — генерация awg0.conf (серверная сторона)
"""
from __future__ import annotations

import sys
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


def _default_params():
    return {
        "jc": 4, "jmin": 40, "jmax": 70,
        "s1": 0, "s2": 0, "s3": 0, "s4": 0,
        "h1": 1, "h2": 2, "h3": 3, "h4": 4,
        "i1": "", "i2": "", "i3": "", "i4": "", "i5": "",
    }


def _sample_peer(name="alice", **overrides):
    base = {
        "name": name,
        "client_pubkey": "CLIENT_PUBKEY",
        "client_ip": "10.66.66.2",
        "client_ipv6": "fd66:66:66::2",
        "preshared_key": "",
    }
    base.update(overrides)
    return base


class TestAwgsBuildServerConf(unittest.TestCase):
    """awgs_build_server_conf — генерация awg0.conf."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_minimal_config(self):
        from vless_installer.modules.awg_standalone import awgs_build_server_conf
        conf = awgs_build_server_conf(
            server_privkey="SERVER_PRIV",
            port=51820, subnet="10.66.66.0/24",
            subnet_v6="fd66:66:66::/64", mtu=1280,
            params=_default_params(),
        )
        self.assertIn("[Interface]", conf)
        self.assertIn("PrivateKey = SERVER_PRIV", conf)
        self.assertIn("ListenPort = 51820", conf)
        self.assertIn("MTU = 1280", conf)
        self.assertIn("Address = 10.66.66.1/24", conf)
        self.assertIn("Address = fd66:66:66::1/64", conf)

    def test_includes_awg_params(self):
        from vless_installer.modules.awg_standalone import awgs_build_server_conf
        conf = awgs_build_server_conf(
            server_privkey="PRIV", port=51820,
            subnet="10.66.66.0/24", subnet_v6="", mtu=1280,
            params=_default_params(),
        )
        self.assertIn("Jc = 4", conf)
        self.assertIn("Jmin = 40", conf)
        self.assertIn("Jmax = 70", conf)
        self.assertIn("H1 = 1", conf)
        self.assertIn("H4 = 4", conf)

    def test_omits_ipv6_when_empty(self):
        from vless_installer.modules.awg_standalone import awgs_build_server_conf
        conf = awgs_build_server_conf(
            server_privkey="PRIV", port=51820,
            subnet="10.66.66.0/24", subnet_v6="", mtu=1280,
            params=_default_params(),
        )
        # без IPv6 — только один Address (v4)
        self.assertEqual(conf.count("Address ="), 1)

    def test_includes_peers(self):
        from vless_installer.modules.awg_standalone import awgs_build_server_conf
        peers = [_sample_peer("alice"), _sample_peer("bob")]
        conf = awgs_build_server_conf(
            server_privkey="PRIV", port=51820,
            subnet="10.66.66.0/24", subnet_v6="", mtu=1280,
            params=_default_params(), peers=peers,
        )
        self.assertIn("[Peer]", conf)
        self.assertIn("CLIENT_PUBKEY", conf)
        self.assertIn("10.66.66.2", conf)

    def test_peer_with_preshared_key(self):
        from vless_installer.modules.awg_standalone import awgs_build_server_conf
        peers = [_sample_peer(preshared_key="PSK_KEY")]
        conf = awgs_build_server_conf(
            server_privkey="PRIV", port=51820,
            subnet="10.66.66.0/24", subnet_v6="", mtu=1280,
            params=_default_params(), peers=peers,
        )
        self.assertIn("PresharedKey = PSK_KEY", conf)

    def test_peer_without_preshared_key(self):
        from vless_installer.modules.awg_standalone import awgs_build_server_conf
        peers = [_sample_peer(preshared_key="")]
        conf = awgs_build_server_conf(
            server_privkey="PRIV", port=51820,
            subnet="10.66.66.0/24", subnet_v6="", mtu=1280,
            params=_default_params(), peers=peers,
        )
        self.assertNotIn("PresharedKey", conf)

    def test_i1_included_when_non_empty(self):
        from vless_installer.modules.awg_standalone import awgs_build_server_conf
        params = _default_params()
        params["i1"] = "deadbeef"
        conf = awgs_build_server_conf(
            server_privkey="PRIV", port=51820,
            subnet="10.66.66.0/24", subnet_v6="", mtu=1280,
            params=params,
        )
        self.assertIn("I1 = deadbeef", conf)

    def test_i1_omitted_when_empty(self):
        from vless_installer.modules.awg_standalone import awgs_build_server_conf
        conf = awgs_build_server_conf(
            server_privkey="PRIV", port=51820,
            subnet="10.66.66.0/24", subnet_v6="", mtu=1280,
            params=_default_params(),
        )
        self.assertNotIn("I1 =", conf)

    def test_cascade_entry_role(self):
        """cascade_role='entry' + cascade_peer → [Peer] для exit-VPS."""
        from vless_installer.modules.awg_standalone import awgs_build_server_conf
        cascade_peer = {
            "pubkey": "EXIT_PUBKEY",
            "preshared_key": "CASCADE_PSK",
        }
        conf = awgs_build_server_conf(
            server_privkey="PRIV", port=51820,
            subnet="10.66.66.0/24", subnet_v6="", mtu=1280,
            params=_default_params(),
            cascade_role="entry", cascade_peer=cascade_peer,
        )
        self.assertIn("[Peer]", conf)
        self.assertIn("EXIT_PUBKEY", conf)
        self.assertIn("CASCADE_PSK", conf)
        self.assertIn("AllowedIPs = 0.0.0.0/0", conf)
        self.assertIn("PersistentKeepalive = 25", conf)


if __name__ == "__main__":
    unittest.main(verbosity=2)
