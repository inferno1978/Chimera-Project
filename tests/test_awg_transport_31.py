#!/usr/bin/env python3
"""
tests/test_awg_transport_31.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты AWG 3.1 в awg_transport.py — Mode B (транспорт exit-ноды).

Покрывает:
  1. Все 4 генератора конфигов при AWG_PROTOCOL_VERSION="3.1" — 9 директив
     (_awg_server_conf_text, _awg_client_conf_text,
      _awg_server_conf_for_node, _awg_client_conf_for_node)
  2. _awg_build_31_lines — пустая строка при 2.0 (байт-в-байт регрессия)
  3. РЕГРЕССИЯ 2.0: mock-core без AWG_PROTOCOL_VERSION (MagicMock auto-attr)
     → 2.0-конфиг без 3.1-директив
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import awg_transport

_HPKEY = "bW9kZS1iLXRyYW5zcG9ydC1rZXktMzItYnl0ZXMhISEhIQ=="


def _mock_core(**overrides):
    """MagicMock-core со всеми AWG_* атрибутами Mode B."""
    core = MagicMock()
    core.AWG_SERVER_PRIVKEY = "SERVER_PRIV"
    core.AWG_CLIENT_PRIVKEY = "CLIENT_PRIV"
    core.AWG_SERVER_PUBKEY = "SERVER_PUB"
    core.AWG_CLIENT_PUBKEY = "CLIENT_PUB"
    core.AWG_PRESHARED_KEY = "PSK"
    core.AWG_EXIT_HOST = "1.2.3.4"
    core.AWG_EXIT_PORT = 51820
    core.AWG_CLIENT_LISTEN_PORT = 11100
    core.AWG_SERVER_IP = "10.66.66.1/32"
    core.AWG_SERVER_IPv6 = "fd66:66:66::1/128"
    core.AWG_CLIENT_IP = "10.66.66.2/32"
    core.AWG_CLIENT_IPv6 = "fd66:66:66::2/128"
    core.AWG_SUBNET = "10.66.66.0/24"
    core.AWG_SUBNET_V6 = "fd66:66:66::/64"
    core.AWG_MTU = 1280
    core.AWG_JC = 4
    core.AWG_JMIN = 40
    core.AWG_JMAX = 70
    core.AWG_S1 = 15
    core.AWG_S2 = 20
    core.AWG_S3 = 12
    core.AWG_S4 = 12
    core.AWG_H1 = 1
    core.AWG_H2 = 2
    core.AWG_H3 = 3
    core.AWG_H4 = 4
    core.AWG_I1 = "<r 32>"
    core.AWG_I2 = ""
    core.AWG_I3 = ""
    core.AWG_I4 = ""
    core.AWG_I5 = ""
    core.AWG_FWMARK = 1000
    core.AWG_ROUTE_TABLE = 1000
    core.AWG_INTERFACE = "awg0"
    for k, v in overrides.items():
        setattr(core, k, v)
    return core


def _core_31(**overrides):
    core = _mock_core(
        AWG_PROTOCOL_VERSION="3.1",
        AWG_HEADER_PROTECTION_KEY=_HPKEY,
        AWG_CONTENT_PADDING_ADDITION="12-40",
        AWG_REKEY_AFTER_TIME="100-140",
        AWG_REKEY_TIMEOUT="3-6",
        AWG_REJECT_AFTER_TIME="170-250",
        AWG_KEEPALIVE_TIMEOUT="8-14",
        AWG_MAX_HANDSHAKE_ATTEMPTS="15-35",
        AWG_RANDOM_TRAILERS="on",
        AWG_DISABLE_COOKIES="on",
    )
    for k, v in overrides.items():
        setattr(core, k, v)
    return core


def _node():
    return {
        "host": "1.2.3.4", "port": 51820, "pubkey": "NODE_PUB",
        "preshared_key": "PSK", "interface": "awg1",
        "client_ip": "10.66.1.2/32", "server_ip": "10.66.1.1/32",
        "client_ip_v6": "fd66:1::2/128", "server_ip_v6": "fd66:1::1/128",
        "subnet_v4": "10.66.1.0/24", "subnet_v6": "fd66:1::/48",
        "fwmark": 1001, "route_table": 1001, "status": "unknown",
        "last_check": "", "ssh_auth_method": "key",
    }


_DIRECTIVES_31 = ("HeaderProtectionKey", "ContentPaddingAddition",
                  "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
                  "KeepaliveTimeout", "MaxHandshakeAttempts",
                  "RandomTrailers", "DisableCookies")


class TestBuild31Lines(unittest.TestCase):
    def setUp(self):
        from chimera.modules import awg_transport
        self.awg_transport = awg_transport

    def test_empty_for_20(self):
        with patch.object(awg_transport, "_core_module",
                          return_value=_mock_core(AWG_PROTOCOL_VERSION="2.0")):
            self.assertEqual(awg_transport._awg_build_31_lines(), "")

    def test_empty_for_magicmock_core(self):
        # MagicMock auto-attr AWG_PROTOCOL_VERSION → не-строка → 2.0
        # (существующие тесты transport без нового атрибута)
        with patch.object(awg_transport, "_core_module",
                          return_value=MagicMock()):
            self.assertEqual(awg_transport._awg_build_31_lines(), "")

    def test_full_block_for_31(self):
        with patch.object(awg_transport, "_core_module",
                          return_value=_core_31()):
            block = awg_transport._awg_build_31_lines()
            self.assertIn(f"HeaderProtectionKey = {_HPKEY}", block)
            self.assertIn("RandomTrailers = on", block)
            self.assertIn("DisableCookies = on", block)
            # 9 строк
            self.assertEqual(len(block.splitlines()), 9)

    def test_empty_globals_commented(self):
        # Пустые 3.1-глобали → «# Key = » (правило v5.4.5)
        core = _core_31(AWG_REKEY_TIMEOUT="", AWG_RANDOM_TRAILERS="")
        with patch.object(awg_transport, "_core_module", return_value=core):
            block = awg_transport._awg_build_31_lines()
            self.assertIn("# RekeyTimeout = ", block)
            self.assertIn("# RandomTrailers = ", block)
            self.assertIn(f"HeaderProtectionKey = {_HPKEY}", block)


class TestAll4ConfGenerators31(unittest.TestCase):
    """Все 4 генератора Mode B: 3.1-блок при версии 3.1, отсутствие при 2.0."""

    def setUp(self):
        from chimera.modules import awg_transport
        self.awg_transport = awg_transport

    def _server_conf(self, core):
        with patch.object(self.awg_transport, "_core_module",
                          return_value=core):
            return self.awg_transport._awg_server_conf_text()

    def _client_conf(self, core):
        with patch.object(self.awg_transport, "_core_module",
                          return_value=core):
            return self.awg_transport._awg_client_conf_text()

    def _server_conf_node(self, core):
        with patch.object(self.awg_transport, "_core_module",
                          return_value=core):
            return self.awg_transport._awg_server_conf_for_node(_node())

    def _client_conf_node(self, core):
        with patch.object(self.awg_transport, "_core_module",
                          return_value=core):
            return self.awg_transport._awg_client_conf_for_node(_node())

    def test_server_conf_31(self):
        conf = self._server_conf(_core_31())
        for d in _DIRECTIVES_31:
            self.assertIn(d, conf, msg=d)
        # Блок после I-lines, до PostUp
        self.assertGreater(conf.find("HeaderProtectionKey = "),
                           conf.find("I1 = <r 32>"))
        self.assertLess(conf.find("HeaderProtectionKey = "),
                        conf.find("PostUp = "))

    def test_client_conf_31(self):
        conf = self._client_conf(_core_31())
        for d in _DIRECTIVES_31:
            self.assertIn(d, conf, msg=d)
        self.assertLess(conf.find("HeaderProtectionKey = "),
                        conf.find("[Peer]"))

    def test_server_conf_node_31(self):
        conf = self._server_conf_node(_core_31())
        for d in _DIRECTIVES_31:
            self.assertIn(d, conf, msg=d)

    def test_client_conf_node_31(self):
        conf = self._client_conf_node(_core_31())
        for d in _DIRECTIVES_31:
            self.assertIn(d, conf, msg=d)

    def test_regression_20_server_conf(self):
        conf = self._server_conf(_mock_core(AWG_PROTOCOL_VERSION="2.0"))
        for d in _DIRECTIVES_31:
            self.assertNotIn(d, conf, msg=d)

    def test_regression_20_client_conf(self):
        conf = self._client_conf(_mock_core(AWG_PROTOCOL_VERSION="2.0"))
        for d in _DIRECTIVES_31:
            self.assertNotIn(d, conf, msg=d)

    def test_regression_magicmock_core_no_31(self):
        # Существующие тесты дают MagicMock без AWG_PROTOCOL_VERSION —
        # auto-attr не строка → 2.0-путь (обратная совместимость моков)
        conf = self._server_conf(MagicMock())
        # H1 и т.п. будут MagicMock-значениями, но 3.1-директив быть не должно
        for d in _DIRECTIVES_31:
            self.assertNotIn(f"{d} = ", conf, msg=d)

    def test_all_4_functions_have_31_block_subtest(self):
        for name, fn in (
            ("server", self._server_conf),
            ("client", self._client_conf),
            ("server_node", self._server_conf_node),
            ("client_node", self._client_conf_node),
        ):
            with self.subTest(func=name):
                conf = fn(_core_31())
                self.assertIn(f"HeaderProtectionKey = {_HPKEY}", conf)
                self.assertIn("RandomTrailers = on", conf)
                self.assertIn("DisableCookies = on", conf)
                # Полный набор из 9 директив
                present = sum(1 for d in _DIRECTIVES_31 if f"{d} = " in conf)
                self.assertEqual(present, 9, msg=name)


class TestCoreStateKeys31(unittest.TestCase):
    """Глобали 3.1 существуют в _core.py с правильными дефолтами."""

    def test_globals_exist(self):
        core_path = _PROJECT_ROOT / "chimera" / "_core.py"
        src = core_path.read_text()
        for var in ("AWG_PROTOCOL_VERSION", "AWG_HEADER_PROTECTION_KEY",
                    "AWG_CONTENT_PADDING_ADDITION", "AWG_REKEY_AFTER_TIME",
                    "AWG_REKEY_TIMEOUT", "AWG_REJECT_AFTER_TIME",
                    "AWG_KEEPALIVE_TIMEOUT", "AWG_MAX_HANDSHAKE_ATTEMPTS",
                    "AWG_RANDOM_TRAILERS", "AWG_DISABLE_COOKIES"):
            self.assertIn(f"{var}", src, msg=var)
        # Дефолт версии — 2.0 (обратная совместимость)
        self.assertIn('AWG_PROTOCOL_VERSION: str = "2.0"', src)
        # State-ключи: save + load
        self.assertIn('"awg_protocol_version"', src)
        self.assertIn('"awg_header_protection_key"', src)
        self.assertIn('"awg_disable_cookies"', src)
        self.assertIn('"awg_random_trailers"', src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
