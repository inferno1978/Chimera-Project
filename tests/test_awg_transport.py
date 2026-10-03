#!/usr/bin/env python3
"""
tests/test_awg_transport.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/awg_transport.py.

Модуль использует _core_module() для доступа к globals — патчим через mock core.
Тестируем:
  1. awg_check_tool — проверка бинарника через shutil.which
  2. _awg_node_subnets — генерация сетевых параметров ноды
  3. _awg_node_from_globals — сборка ноды из globals
  4. _awg_load_nodes_from_state / _awg_save_nodes_to_state — JSON I/O
  5. _awg_client_conf_for_node — генерация клиентского конфига
  6. _awg_server_conf_for_node — генерация серверного конфига
  7. _awg_client_conf_text — генерация клиентского конфига из globals
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


def _mock_core(**overrides):
    """Создаёт mock core с AWG_* дефолтами + override'ами."""
    core = MagicMock()
    # Дефолты из _core.py
    core.AWG_SERVER_PRIVKEY = "SERVER_PRIV"
    core.AWG_SERVER_PUBKEY = "SERVER_PUB"
    core.AWG_CLIENT_PRIVKEY = "CLIENT_PRIV"
    core.AWG_CLIENT_PUBKEY = "CLIENT_PUB"
    core.AWG_PRESHARED_KEY = "PSK_KEY"
    core.AWG_EXIT_HOST = "1.2.3.4"
    core.AWG_EXIT_PORT = 51820
    core.AWG_SERVER_IP = "10.66.66.1/32"
    core.AWG_SERVER_IPv6 = "fd66:66:66::1/128"
    core.AWG_CLIENT_IP = "10.66.66.2/32"
    core.AWG_CLIENT_IPv6 = "fd66:66:66::2/128"
    core.AWG_CLIENT_LISTEN_PORT = 11100
    core.AWG_H1 = 1
    core.AWG_H2 = 2
    core.AWG_H3 = 3
    core.AWG_H4 = 4
    core.AWG_JC = 4
    core.AWG_JMIN = 40
    core.AWG_JMAX = 70
    core.AWG_S1 = 0
    core.AWG_S2 = 0
    #  S3/S4/I1-I5 — добавлены в mock для полного набора AWG 2.0
    core.AWG_S3 = 0
    core.AWG_S4 = 0
    core.AWG_I1 = ""
    core.AWG_I2 = ""
    core.AWG_I3 = ""
    core.AWG_I4 = ""
    core.AWG_I5 = ""
    core.AWG_OBFUSCATION_SOURCE = "default"
    core.AWG_MTU = 1280
    core.AWG_FWMARK = 1000
    core.AWG_INTERFACE = "awg0"
    core.AWG_ROUTE_TABLE = 1000
    core.AWG_SUBNET = "10.66.66.0/24"
    core.AWG_SUBNET_V6 = "fd66:66:66::/64"
    core.AWG_SSH_AUTH_METHOD = "key"
    core.AWG_ACTIVE_NODE_INDEX = 0
    core._AWG_SSH_CLIENT_IP = ""
    core.warn = MagicMock()
    core.log_to_file = MagicMock()
    for k, v in overrides.items():
        setattr(core, k, v)
    return core


class TestAwgCheckTool(unittest.TestCase):
    """awg_check_tool — shutil.which."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_true_when_binary_in_path(self):
        from chimera.modules import awg_transport
        with patch("shutil.which", return_value="/usr/bin/awg"), \
             patch.object(awg_transport, "_core_module", return_value=MagicMock()):
            self.assertTrue(awg_transport.awg_check_tool("awg"))

    def test_returns_false_when_binary_not_found(self):
        from chimera.modules import awg_transport
        with patch("shutil.which", return_value=None), \
             patch.object(awg_transport, "_core_module", return_value=MagicMock()):
            self.assertFalse(awg_transport.awg_check_tool("nonexistent"))


class TestAwgNodeSubnets(unittest.TestCase):
    """_awg_node_subnets — генерация сетевых параметров."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_node_0(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module",
                          return_value=_mock_core()):
            subnets = awg_transport._awg_node_subnets(0)
        self.assertEqual(subnets["interface"], "awg0")
        self.assertEqual(subnets["subnet_v4"], "10.66.0.0/24")
        self.assertEqual(subnets["client_ip"], "10.66.0.2/32")
        self.assertEqual(subnets["server_ip"], "10.66.0.1/32")
        self.assertEqual(subnets["subnet_v6"], "fd66:0::/48")
        self.assertEqual(subnets["fwmark"], 1000)
        self.assertEqual(subnets["route_table"], 1000)

    def test_node_5(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module",
                          return_value=_mock_core()):
            subnets = awg_transport._awg_node_subnets(5)
        self.assertEqual(subnets["interface"], "awg5")
        self.assertEqual(subnets["subnet_v4"], "10.66.5.0/24")
        self.assertEqual(subnets["subnet_v6"], "fd66:5::/48")
        self.assertEqual(subnets["fwmark"], 1005)
        self.assertEqual(subnets["route_table"], 1005)

    def test_has_all_required_keys(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module",
                          return_value=_mock_core()):
            subnets = awg_transport._awg_node_subnets(1)
        required = {
            "interface", "subnet_v4", "client_ip", "server_ip",
            "subnet_v6", "client_ip_v6", "server_ip_v6",
            "fwmark", "route_table",
        }
        self.assertEqual(set(subnets.keys()), required)


class TestAwgNodeFromGlobals(unittest.TestCase):
    """_awg_node_from_globals — сборка ноды из AWG_*."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_uses_globals_for_host_port(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module",
                          return_value=_mock_core(AWG_EXIT_HOST="5.6.7.8")):
            node = awg_transport._awg_node_from_globals(2)
        self.assertEqual(node["host"], "5.6.7.8")
        self.assertEqual(node["interface"], "awg2")
        self.assertEqual(node["client_ip"], "10.66.2.2/32")
        self.assertEqual(node["subnet_v6"], "fd66:2::/48")
        self.assertEqual(node["fwmark"], 1002)
        self.assertEqual(node["status"], "unknown")

    def test_default_ssh_auth_method_is_key(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module",
                          return_value=_mock_core()):
            node = awg_transport._awg_node_from_globals(0)
        self.assertEqual(node["ssh_auth_method"], "key")


class TestAwgLoadNodesFromState(unittest.TestCase):
    """_awg_load_nodes_from_state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_empty_when_no_file(self):
        from chimera.modules import awg_transport
        core = _mock_core()
        core.STATE_FILE = Path("/tmp/nonexistent_xyz_state.json")
        with patch.object(awg_transport, "_core_module", return_value=core):
            result = awg_transport._awg_load_nodes_from_state()
        self.assertEqual(result, [])

    def test_returns_nodes_from_state(self):
        from chimera.modules import awg_transport
        self._state.write_text(json.dumps({
            "awg_nodes": [{"host": "1.1.1.1"}, {"host": "2.2.2.2"}],
        }))
        core = _mock_core()
        core.STATE_FILE = self._state
        with patch.object(awg_transport, "_core_module", return_value=core):
            result = awg_transport._awg_load_nodes_from_state()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["host"], "1.1.1.1")

    def test_returns_empty_when_corrupt(self):
        from chimera.modules import awg_transport
        self._state.write_text("{invalid")
        core = _mock_core()
        core.STATE_FILE = self._state
        with patch.object(awg_transport, "_core_module", return_value=core):
            result = awg_transport._awg_load_nodes_from_state()
        self.assertEqual(result, [])

    def test_returns_empty_when_no_awg_nodes_key(self):
        from chimera.modules import awg_transport
        self._state.write_text(json.dumps({"other_key": "value"}))
        core = _mock_core()
        core.STATE_FILE = self._state
        with patch.object(awg_transport, "_core_module", return_value=core):
            result = awg_transport._awg_load_nodes_from_state()
        self.assertEqual(result, [])


class TestAwgSaveNodesToState(unittest.TestCase):
    """_awg_save_nodes_to_state — merge + filter ssh_password."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_filters_ssh_password_from_nodes(self):
        """ssh_password не должен попадать в state.json."""
        from chimera.modules import awg_transport
        self._state.write_text(json.dumps({"uuid": "abc"}))
        core = _mock_core()
        core.STATE_FILE = self._state
        nodes = [
            {"host": "1.1.1.1", "ssh_password": "secret"},
            {"host": "2.2.2.2", "ssh_password": "another"},
        ]
        with patch.object(awg_transport, "_core_module", return_value=core):
            awg_transport._awg_save_nodes_to_state(nodes)
        saved = json.loads(self._state.read_text())
        for n in saved["awg_nodes"]:
            self.assertNotIn("ssh_password", n)
        self.assertEqual(len(saved["awg_nodes"]), 2)
        # другие ключи сохранены
        self.assertEqual(saved["uuid"], "abc")

    def test_does_nothing_when_no_state_file(self):
        from chimera.modules import awg_transport
        core = _mock_core()
        core.STATE_FILE = Path("/tmp/nonexistent_xyz_state.json")
        with patch.object(awg_transport, "_core_module", return_value=core):
            # не должно бросать
            awg_transport._awg_save_nodes_to_state([{"host": "1.1.1.1"}])

    def test_writes_active_node_index(self):
        from chimera.modules import awg_transport
        self._state.write_text(json.dumps({}))
        core = _mock_core(AWG_ACTIVE_NODE_INDEX=3)
        core.STATE_FILE = self._state
        with patch.object(awg_transport, "_core_module", return_value=core):
            awg_transport._awg_save_nodes_to_state([{"host": "1.1.1.1"}])
        saved = json.loads(self._state.read_text())
        self.assertEqual(saved["awg_active_node_index"], 3)


class TestAwgClientConfForNode(unittest.TestCase):
    """_awg_client_conf_for_node — генерация клиентского конфига для ноды."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _node(self):
        return {
            "host": "5.6.7.8", "port": 51820,
            "client_ip": "10.66.5.2/32",
            "client_ip_v6": "fd66:5::2/128",
            "pubkey": "NODE_PUBKEY",
            "preshared_key": "NODE_PSK",
            "client_privkey": "NODE_PRIVKEY",
        }

    def test_includes_node_endpoint(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_for_node(self._node())
        self.assertIn("Endpoint = 5.6.7.8:51820", conf)

    def test_uses_node_keys_when_provided(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_for_node(self._node())
        self.assertIn("PrivateKey = NODE_PRIVKEY", conf)
        self.assertIn("PublicKey = NODE_PUBKEY", conf)
        self.assertIn("PresharedKey = NODE_PSK", conf)

    def test_falls_back_to_globals_when_node_keys_missing(self):
        from chimera.modules import awg_transport
        node = {
            "host": "5.6.7.8", "port": 51820,
            "client_ip": "10.66.5.2/32",
            "client_ip_v6": "fd66:5::2/128",
            # pubkey, preshared_key, client_privkey отсутствуют
        }
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_for_node(node)
        self.assertIn("PrivateKey = CLIENT_PRIV", conf)
        self.assertIn("PublicKey = SERVER_PUB", conf)
        self.assertIn("PresharedKey = PSK_KEY", conf)

    def test_includes_node_addresses(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_for_node(self._node())
        self.assertIn("10.66.5.2/32", conf)
        self.assertIn("fd66:5::2/128", conf)

    def test_includes_awg_params(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_for_node(self._node())
        self.assertIn("Jc = 4", conf)
        self.assertIn("Jmin = 40", conf)
        self.assertIn("Jmax = 70", conf)
        self.assertIn("H1 = 1", conf)
        self.assertIn("H4 = 4", conf)

    def test_includes_dns_and_table_off(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_for_node(self._node())
        self.assertIn("DNS = 1.1.1.1, 8.8.8.8, 2606:4700:4700::1111", conf)
        self.assertIn("Table = off", conf)

    def test_allowed_ips_all(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_for_node(self._node())
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", conf)

    def test_persistent_keepalive(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_for_node(self._node())
        self.assertIn("PersistentKeepalive = 25", conf)


class TestAwgServerConfForNode(unittest.TestCase):
    """_awg_server_conf_for_node — генерация серверного конфига."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _node(self):
        return {
            "interface": "awg5", "host": "5.6.7.8", "port": 51820,
            "client_ip": "10.66.5.2/32",
            "client_ip_v6": "fd66:5::2/128",
            "server_ip": "10.66.5.1/32",
            "server_ip_v6": "fd66:5::1/128",
            "server_privkey": "NODE_S_PRIV",
            "client_pubkey": "NODE_C_PUB",
        }

    def test_includes_interface_section(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_server_conf_for_node(self._node())
        self.assertIn("[Interface]", conf)
        self.assertIn("[Peer]", conf)

    def test_uses_node_server_privkey(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_server_conf_for_node(self._node())
        self.assertIn("PrivateKey = NODE_S_PRIV", conf)

    def test_uses_node_client_pubkey(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_server_conf_for_node(self._node())
        self.assertIn("PublicKey = NODE_C_PUB", conf)

    def test_includes_listen_port(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_server_conf_for_node(self._node())
        self.assertIn("ListenPort = 51820", conf)

    def test_includes_addresses(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_server_conf_for_node(self._node())
        self.assertIn("10.66.5.1/32", conf)
        self.assertIn("fd66:5::1/128", conf)
        self.assertIn("10.66.5.2/32", conf)
        self.assertIn("fd66:5::2/128", conf)

    def test_includes_awg_params(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_server_conf_for_node(self._node())
        self.assertIn("Jc = 4", conf)
        self.assertIn("Jmin = 40", conf)
        self.assertIn("Jmax = 70", conf)


class TestAwgClientConfText(unittest.TestCase):
    """_awg_client_conf_text — генерация клиентского конфига из globals."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_includes_interface_and_peer_sections(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_text()
        self.assertIn("[Interface]", conf)
        self.assertIn("[Peer]", conf)

    def test_includes_endpoint_from_globals(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_text()
        self.assertIn("Endpoint = 1.2.3.4:51820", conf)

    def test_includes_keys(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_text()
        self.assertIn("PrivateKey = CLIENT_PRIV", conf)
        self.assertIn("PublicKey = SERVER_PUB", conf)
        self.assertIn("PresharedKey = PSK_KEY", conf)

    def test_includes_awg_params(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_text()
        self.assertIn("Jc = 4", conf)
        self.assertIn("Jmin = 40", conf)
        self.assertIn("Jmax = 70", conf)
        self.assertIn("H1 = 1", conf)
        self.assertIn("H4 = 4", conf)

    def test_includes_dns_and_table_off(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_text()
        self.assertIn("DNS = 1.1.1.1, 8.8.8.8, 2606:4700:4700::1111", conf)
        self.assertIn("Table = off", conf)

    def test_allowed_ips_all(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_text()
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", conf)

    def test_persistent_keepalive(self):
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_text()
        self.assertIn("PersistentKeepalive = 25", conf)


# ============================================================================
#   — Тесты на полный набор параметров AWG 2.0 (S3/S4/I1-I5)
# ============================================================================
# Жалоба пользователя (Keenetic не может импортировать AWG-конфиг) —
# Cascade-режим генерил только 9 параметров (Jc/Jmin/Jmax/S1/S2/H1-H4),
# без S3/S4/I1-I5. Keenetic, видимо, парсер-строгий и падал на отсутствии I1.
#
# Тесты проверяют что все 4 Cascade-функции теперь пишут полный набор:
#   - _awg_server_conf_text()
#   - _awg_client_conf_text()
#   - _awg_client_conf_for_node(node)
#   - _awg_server_conf_for_node(node)

class TestCascadeFullParamsV4257(unittest.TestCase):
    """ все 4 Cascade-функции должны писать полный набор параметров
    AWG 2.0 — Jc/Jmin/Jmax/S1-S4/H1-H4/I1-I5 (16 штук).

    Раньше писались только 9 (Jc/Jmin/Jmax/S1/S2/H1-H4) — без S3/S4/I1-I5.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def _mock_node(self):
        """Минимальная нода для _awg_*_conf_for_node()."""
        return {
            "interface":      "awg0",
            "server_ip":      "10.66.66.1/32",
            "server_ip_v6":   "fd66:66:66::1/128",
            "client_ip":      "10.66.66.2/32",
            "client_ip_v6":   "fd66:66:66::2/128",
            "port":           51820,
            "host":           "1.2.3.4",
            "pubkey":         "SERVER_PUB",
            "preshared_key":  "PSK_KEY",
            "client_privkey": "CLIENT_PRIV",
            "server_privkey": "SERVER_PRIV",
            "client_pubkey":  "CLIENT_PUB",
            "fwmark":         1000,
            "route_table":    1000,
        }

    # ── _awg_server_conf_text ─────────────────────────────────────────────
    def test_server_conf_has_s3_s4(self):
        """_awg_server_conf_text пишет S3 и S4 (раньше не писались)."""
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_server_conf_text()
        self.assertIn("S3 = 0", conf, f"S3 отсутствует в server conf:\n{conf}")
        self.assertIn("S4 = 0", conf, f"S4 отсутствует в server conf:\n{conf}")

    def test_server_conf_writes_i1_when_set(self):
        """_awg_server_conf_text пишет I1 если он задан (непустой)."""
        from chimera.modules import awg_transport
        _i1_val = "aabbccdd" * 6  # 48 hex chars
        with patch.object(awg_transport, "_core_module",
                          return_value=_mock_core(AWG_I1=_i1_val)):
            conf = awg_transport._awg_server_conf_text()
        self.assertIn(f"I1 = {_i1_val}", conf,
                      f"I1 должен быть в conf когда задан, фактически:\n{conf}")

    def test_server_conf_writes_i_lines_commented(self):
        """v5.4: _awg_server_conf_text пишет пустые I1-I5 ЗАКОММЕНТИРОВАННЫМИ.

        См. test_empty_i1_to_i5_commented_ в test_awg_standalone.py.
        Коротко: старые amneziawg-tools падают на 'I2 = ' (пустая),
        но игнорируют '# I2 = '.
        """
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_server_conf_text()
        # Все 5 I-ключей должны быть ЗАКОММЕНТИРОВАНЫ (пустые)
        for key in ("I1", "I2", "I3", "I4", "I5"):
            self.assertIn(f"# {key} = ", conf,
                          f"# {key} = должен присутствовать (закомментирован) "
                          f"в server conf (v5.4)")

    def test_server_conf_writes_all_i_when_set(self):
        """_awg_server_conf_text пишет I1-I5 если все заданы."""
        from chimera.modules import awg_transport
        _vals = {"AWG_I1": "aa", "AWG_I2": "bb", "AWG_I3": "cc",
                 "AWG_I4": "dd", "AWG_I5": "ee"}
        with patch.object(awg_transport, "_core_module",
                          return_value=_mock_core(**_vals)):
            conf = awg_transport._awg_server_conf_text()
        for _k, _v in _vals.items():
            self.assertIn(f"{_k.replace('AWG_', '')} = {_v}", conf,
                          f"{_k} должен быть в conf, фактически:\n{conf}")

    # ── _awg_client_conf_text ─────────────────────────────────────────────
    def test_client_conf_has_s3_s4(self):
        """_awg_client_conf_text пишет S3 и S4."""
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_text()
        self.assertIn("S3 = 0", conf)
        self.assertIn("S4 = 0", conf)

    def test_client_conf_writes_i1_when_set(self):
        """_awg_client_conf_text пишет I1 если задан."""
        from chimera.modules import awg_transport
        _i1_val = "deadbeef" * 6
        with patch.object(awg_transport, "_core_module",
                          return_value=_mock_core(AWG_I1=_i1_val)):
            conf = awg_transport._awg_client_conf_text()
        self.assertIn(f"I1 = {_i1_val}", conf)

    def test_client_conf_writes_i_lines_commented_v545(self):
        """v5.4.5: _awg_client_conf_text комментирует ПУСТЫЕ I1-I5 (# I2 = ).

        E2E 2026-10-03: awg setconf (amneziawg-tools 2026 PPA) падает
        на голой пустой 'I2 = ' —"Line unrecognized: I2=".
        """
        from chimera.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_text()
        for key in ("I1", "I2", "I3", "I4", "I5"):
            self.assertIn(f"# {key} = ", conf,
                          f"# {key} = должен присутствовать (закомментирован) "
                          f"в client conf (v5.4.5)")
            self.assertNotIn(f"\n{key} = \n", conf,
                             f"голая пустая '{key} = ' НЕ должна быть "
                             f"в client conf (v5.4.5)")

    # ── _awg_client_conf_for_node ─────────────────────────────────────────
    def test_client_conf_for_node_has_s3_s4(self):
        """_awg_client_conf_for_node пишет S3 и S4."""
        from chimera.modules import awg_transport
        node = self._mock_node()
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_for_node(node)
        self.assertIn("S3 = 0", conf)
        self.assertIn("S4 = 0", conf)

    def test_client_conf_for_node_writes_i1_when_set(self):
        """_awg_client_conf_for_node пишет I1 если задан."""
        from chimera.modules import awg_transport
        node = self._mock_node()
        _i1_val = "cafebabe" * 6
        with patch.object(awg_transport, "_core_module",
                          return_value=_mock_core(AWG_I1=_i1_val)):
            conf = awg_transport._awg_client_conf_for_node(node)
        self.assertIn(f"I1 = {_i1_val}", conf)

    def test_client_conf_for_node_writes_i_lines_commented_v545(self):
        """v5.4.5: _awg_client_conf_for_node комментирует ПУСТЫЕ I1-I5 (# I2 = )."""
        from chimera.modules import awg_transport
        node = self._mock_node()
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_for_node(node)
        for key in ("I1", "I2", "I3", "I4", "I5"):
            self.assertIn(f"# {key} = ", conf,
                          f"# {key} = должен присутствовать (закомментирован) "
                          f"в client_conf_for_node (v5.4.5)")
            self.assertNotIn(f"\n{key} = \n", conf,
                             f"голая пустая '{key} = ' НЕ должна быть "
                             f"в client_conf_for_node (v5.4.5)")

    # ── _awg_server_conf_for_node ─────────────────────────────────────────
    def test_server_conf_for_node_has_s3_s4(self):
        """_awg_server_conf_for_node пишет S3 и S4."""
        from chimera.modules import awg_transport
        node = self._mock_node()
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_server_conf_for_node(node)
        self.assertIn("S3 = 0", conf)
        self.assertIn("S4 = 0", conf)

    def test_server_conf_for_node_writes_i1_when_set(self):
        """_awg_server_conf_for_node пишет I1 если задан."""
        from chimera.modules import awg_transport
        node = self._mock_node()
        _i1_val = "1234abcd" * 6
        with patch.object(awg_transport, "_core_module",
                          return_value=_mock_core(AWG_I1=_i1_val)):
            conf = awg_transport._awg_server_conf_for_node(node)
        self.assertIn(f"I1 = {_i1_val}", conf)

    def test_server_conf_for_node_writes_i_lines_commented(self):
        """v5.4: _awg_server_conf_for_node пишет пустые I1-I5 ЗАКОММЕНТИРОВАННЫМИ."""
        from chimera.modules import awg_transport
        node = self._mock_node()
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_server_conf_for_node(node)
        for key in ("I1", "I2", "I3", "I4", "I5"):
            self.assertIn(f"# {key} = ", conf,
                          f"# {key} = должен присутствовать (закомментирован) "
                          f"в server_conf_for_node (v5.4)")

    # ── Полный набор — regression на жалобу zvshka ────────────────────────
    def test_all_4_functions_have_full_param_set(self):
        """Все 4 Cascade-функции пишут ПОЛНЫЙ набор: Jc/Jmin/Jmax/S1-S4/H1-H4 + I1-I5.

        v5.4.5: ПУСТЫЕ I1-I5 комментируются ВЕЗДА (# I2 = ) — и на сервере,
        и на клиенте: Linux-клиентский awg-quick падает на голой пустой
        'I2 = ' (awg setconf, amneziawg-tools 2026 PPA). Проверяем что все
        16 параметров присутствуют в каждой функции.
        """
        from chimera.modules import awg_transport
        node = self._mock_node()
        # Все 4 функции
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            confs = [
                ("_awg_server_conf_text", awg_transport._awg_server_conf_text()),
                ("_awg_client_conf_text", awg_transport._awg_client_conf_text()),
                ("_awg_client_conf_for_node",
                 awg_transport._awg_client_conf_for_node(node)),
                ("_awg_server_conf_for_node",
                 awg_transport._awg_server_conf_for_node(node)),
            ]
        # 11 обязательных параметров (Jc/Jmin/Jmax/S1-S4/H1-H4) — без комментария
        required_uncommented = [
            "Jc = ", "Jmin = ", "Jmax = ",
            "S1 = ", "S2 = ", "S3 = ", "S4 = ",
            "H1 = ", "H2 = ", "H3 = ", "H4 = ",
        ]

        for fname, conf in confs:
            with self.subTest(func=fname):
                for param in required_uncommented:
                    self.assertIn(param, conf,
                                  f"{fname}: отсутствует '{param}' — "
                                  f"неполный набор AWG 2.0 (баг zvshka):\n{conf}")
                # v5.4.5: I1-I5 (пустые в дефолтном _mock_core)
                # комментируются ВЕЗДА — сервер и клиент
                for key in ("I1", "I2", "I3", "I4", "I5"):
                    self.assertIn(f"# {key} = ", conf,
                                  f"{fname}: # {key} = должен быть "
                                  f"(пустые комментируются, v5.4.5)")
                    self.assertNotIn(f"\n{key} = \n", conf,
                                     f"{fname}: голая пустая '{key} = ' НЕ должна "
                                     f"быть (awg setconf падает, v5.4.5)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
