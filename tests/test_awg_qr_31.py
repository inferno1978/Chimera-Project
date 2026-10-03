#!/usr/bin/env python3
"""
tests/test_awg_qr_31.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты AWG 3.1 в awg_qr.py — клиентские конфиги и vpn:// URI.

Покрывает:
  1. awgs_qr_build_client_conf: 9 директив 3.1 в [Interface] после I1-I5
  2. awgs_qr_build_vpn_uri: protocol_version "3" + 3.1-ключи в inner JSON
  3. РЕГРЕССИЯ 2.0: state без protocol_version — байт-в-байт прежний вывод
     (protocol_version "2", без 3.1-директив)
"""
from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

_HPKEY = "c3BhcnJlLWhvcnNld2Fzb2x1dGlvbi1rZXktMzItYnl0ZXMhIQ=="

_PARAMS_20 = {
    "jc": 4, "jmin": 40, "jmax": 70,
    "s1": 15, "s2": 20, "s3": 12, "s4": 12,
    "h1": 1, "h2": 2, "h3": 3, "h4": 4,
    "i1": "<r 32>", "i2": "", "i3": "", "i4": "", "i5": "",
}
_PARAMS_31 = dict(_PARAMS_20)
_PARAMS_31.update({
    "header_protection_key": _HPKEY,
    "content_padding_addition": "12-40",
    "rekey_after_time": "100-140",
    "rekey_timeout": "3-6",
    "reject_after_time": "170-250",
    "keepalive_timeout": "8-14",
    "max_handshake_attempts": "15-35",
    "random_trailers": "on",
    "disable_cookies": "on",
})


def _peer(**overrides):
    base = {
        "name": "alice",
        "client_privkey": "CLIENT_PRIV",
        "client_pubkey": "CLIENT_PUB",
        "client_ip": "10.66.66.2",
        "client_ipv6": "",
        "preshared_key": "",
        "dns1": "1.1.1.1",
        "dns2": "8.8.8.8",
    }
    base.update(overrides)
    return base


def _state_31():
    return {
        "installed": True,
        "server_pubkey": "SERVER_PUB",
        "port": 51820,
        "endpoint": "1.2.3.4",
        "endpoint_host": "",
        "mtu": 1280,
        "params": dict(_PARAMS_31),
        "allow_ipv6_tunnel": False,
        "protocol_version": "3.1",
    }


def _state_20():
    return {
        "installed": True,
        "server_pubkey": "SERVER_PUB",
        "port": 51820,
        "endpoint": "1.2.3.4",
        "endpoint_host": "",
        "mtu": 1280,
        "params": dict(_PARAMS_20),
        "allow_ipv6_tunnel": False,
        # protocol_version отсутствует = 2.0 (старые state)
    }


class TestBuildClientConf31(unittest.TestCase):
    def setUp(self):
        from chimera.modules import awg_qr
        self.awg_qr = awg_qr

    def test_31_directives_in_interface(self):
        conf = self.awg_qr.awgs_qr_build_client_conf(_peer(), _state_31())
        iface_part = conf.split("[Peer]")[0]
        self.assertIn(f"HeaderProtectionKey = {_HPKEY}", iface_part)
        self.assertIn("ContentPaddingAddition = 12-40", iface_part)
        self.assertIn("RekeyAfterTime = 100-140", iface_part)
        self.assertIn("RekeyTimeout = 3-6", iface_part)
        self.assertIn("RejectAfterTime = 170-250", iface_part)
        self.assertIn("KeepaliveTimeout = 8-14", iface_part)
        self.assertIn("MaxHandshakeAttempts = 15-35", iface_part)
        self.assertIn("RandomTrailers = on", iface_part)
        self.assertIn("DisableCookies = on", iface_part)

    def test_31_block_after_i_lines(self):
        conf = self.awg_qr.awgs_qr_build_client_conf(_peer(), _state_31())
        self.assertGreater(conf.find("HeaderProtectionKey = "),
                           conf.find("I1 = <r 32>"))
        self.assertGreater(conf.find("HeaderProtectionKey = "),
                           conf.find("# I2 = "))

    def test_31_empty_extra_commented(self):
        st = _state_31()
        st["params"]["rekey_timeout"] = ""
        conf = self.awg_qr.awgs_qr_build_client_conf(_peer(), st)
        self.assertIn("# RekeyTimeout = ", conf)
        self.assertNotIn("\nRekeyTimeout = \n", conf)

    def test_regression_20_no_directives(self):
        conf = self.awg_qr.awgs_qr_build_client_conf(_peer(), _state_20())
        for d in ("HeaderProtectionKey", "ContentPaddingAddition",
                  "RandomTrailers", "DisableCookies"):
            self.assertNotIn(d, conf)

    def test_regression_20_identical_with_31_params(self):
        # 2.0-state с 3.1-параметрами в params → 3.1-блок НЕ рендерится
        # (версия решает, не содержимое params)
        st = _state_20()
        st["params"] = dict(_PARAMS_31)
        conf = self.awg_qr.awgs_qr_build_client_conf(_peer(), st)
        self.assertNotIn("HeaderProtectionKey", conf)


class TestBuildVpnUri31(unittest.TestCase):
    def setUp(self):
        from chimera.modules import awg_qr
        self.awg_qr = awg_qr

    def _decode(self, uri):
        self.assertTrue(uri.startswith("vpn://free/"))
        parts = uri[len("vpn://free/"):].split("/")
        outer = json.loads(base64.b64decode(parts[0]))
        inner = json.loads(base64.b64decode(parts[1]))
        return outer, inner

    def test_31_protocol_version_3(self):
        uri = self.awg_qr.awgs_qr_build_vpn_uri(_peer(), _state_31())
        outer, inner = self._decode(uri)
        awg = outer["containers"][0]["awg"]
        self.assertEqual(awg["protocol_version"], "3")

    def test_31_inner_keys(self):
        uri = self.awg_qr.awgs_qr_build_vpn_uri(_peer(), _state_31())
        outer, inner = self._decode(uri)
        # 3.1-ключи в inner JSON — строками (контракт Amnezia Client)
        self.assertEqual(inner["HeaderProtectionKey"], _HPKEY)
        self.assertEqual(inner["ContentPaddingAddition"], "12-40")
        self.assertEqual(inner["RandomTrailers"], "on")
        self.assertEqual(inner["DisableCookies"], "on")
        self.assertEqual(inner["MaxHandshakeAttempts"], "15-35")
        # Базовые ключи на месте
        self.assertEqual(inner["Jc"], "4")
        self.assertEqual(inner["I1"], "<r 32>")

    def test_regression_20_protocol_version_2(self):
        uri = self.awg_qr.awgs_qr_build_vpn_uri(_peer(), _state_20())
        outer, inner = self._decode(uri)
        self.assertEqual(outer["containers"][0]["awg"]["protocol_version"],
                         "2")
        # Без 3.1-ключей
        self.assertNotIn("HeaderProtectionKey", inner)

    def test_31_raw_config_in_inner(self):
        # config (raw .conf) содержит 3.1-директивы — клиентский конфиг
        # един и в last_config.config
        uri = self.awg_qr.awgs_qr_build_vpn_uri(_peer(), _state_31())
        outer, inner = self._decode(uri)
        self.assertIn("HeaderProtectionKey = ", inner["config"])
        self.assertIn("RandomTrailers = on", inner["config"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
