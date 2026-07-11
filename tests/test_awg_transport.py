#!/usr/bin/env python3
"""
tests/test_awg_transport.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/awg_transport.py.

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
        from vless_installer.modules import awg_transport
        with patch("shutil.which", return_value="/usr/bin/awg"), \
             patch.object(awg_transport, "_core_module", return_value=MagicMock()):
            self.assertTrue(awg_transport.awg_check_tool("awg"))

    def test_returns_false_when_binary_not_found(self):
        from vless_installer.modules import awg_transport
        with patch("shutil.which", return_value=None), \
             patch.object(awg_transport, "_core_module", return_value=MagicMock()):
            self.assertFalse(awg_transport.awg_check_tool("nonexistent"))


class TestAwgNodeSubnets(unittest.TestCase):
    """_awg_node_subnets — генерация сетевых параметров."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_node_0(self):
        from vless_installer.modules import awg_transport
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
        from vless_installer.modules import awg_transport
        with patch.object(awg_transport, "_core_module",
                          return_value=_mock_core()):
            subnets = awg_transport._awg_node_subnets(5)
        self.assertEqual(subnets["interface"], "awg5")
        self.assertEqual(subnets["subnet_v4"], "10.66.5.0/24")
        self.assertEqual(subnets["subnet_v6"], "fd66:5::/48")
        self.assertEqual(subnets["fwmark"], 1005)
        self.assertEqual(subnets["route_table"], 1005)

    def test_has_all_required_keys(self):
        from vless_installer.modules import awg_transport
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
        from vless_installer.modules import awg_transport
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
        from vless_installer.modules import awg_transport
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
        from vless_installer.modules import awg_transport
        core = _mock_core()
        core.STATE_FILE = Path("/tmp/nonexistent_xyz_state.json")
        with patch.object(awg_transport, "_core_module", return_value=core):
            result = awg_transport._awg_load_nodes_from_state()
        self.assertEqual(result, [])

    def test_returns_nodes_from_state(self):
        from vless_installer.modules import awg_transport
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
        from vless_installer.modules import awg_transport
        self._state.write_text("{invalid")
        core = _mock_core()
        core.STATE_FILE = self._state
        with patch.object(awg_transport, "_core_module", return_value=core):
            result = awg_transport._awg_load_nodes_from_state()
        self.assertEqual(result, [])

    def test_returns_empty_when_no_awg_nodes_key(self):
        from vless_installer.modules import awg_transport
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
        from vless_installer.modules import awg_transport
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
        from vless_installer.modules import awg_transport
        core = _mock_core()
        core.STATE_FILE = Path("/tmp/nonexistent_xyz_state.json")
        with patch.object(awg_transport, "_core_module", return_value=core):
            # не должно бросать
            awg_transport._awg_save_nodes_to_state([{"host": "1.1.1.1"}])

    def test_writes_active_node_index(self):
        from vless_installer.modules import awg_transport
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
        from vless_installer.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_for_node(self._node())
        self.assertIn("Endpoint = 5.6.7.8:51820", conf)

    def test_uses_node_keys_when_provided(self):
        from vless_installer.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_for_node(self._node())
        self.assertIn("PrivateKey = NODE_PRIVKEY", conf)
        self.assertIn("PublicKey = NODE_PUBKEY", conf)
        self.assertIn("PresharedKey = NODE_PSK", conf)

    def test_falls_back_to_globals_when_node_keys_missing(self):
        from vless_installer.modules import awg_transport
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
        from vless_installer.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_for_node(self._node())
        self.assertIn("10.66.5.2/32", conf)
        self.assertIn("fd66:5::2/128", conf)

    def test_includes_awg_params(self):
        from vless_installer.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_for_node(self._node())
        self.assertIn("Jc = 4", conf)
        self.assertIn("Jmin = 40", conf)
        self.assertIn("Jmax = 70", conf)
        self.assertIn("H1 = 1", conf)
        self.assertIn("H4 = 4", conf)

    def test_includes_dns_and_table_off(self):
        from vless_installer.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_for_node(self._node())
        self.assertIn("DNS = 1.1.1.1, 8.8.8.8, 2606:4700:4700::1111", conf)
        self.assertIn("Table = off", conf)

    def test_allowed_ips_all(self):
        from vless_installer.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_for_node(self._node())
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", conf)

    def test_persistent_keepalive(self):
        from vless_installer.modules import awg_transport
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
        from vless_installer.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_server_conf_for_node(self._node())
        self.assertIn("[Interface]", conf)
        self.assertIn("[Peer]", conf)

    def test_uses_node_server_privkey(self):
        from vless_installer.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_server_conf_for_node(self._node())
        self.assertIn("PrivateKey = NODE_S_PRIV", conf)

    def test_uses_node_client_pubkey(self):
        from vless_installer.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_server_conf_for_node(self._node())
        self.assertIn("PublicKey = NODE_C_PUB", conf)

    def test_includes_listen_port(self):
        from vless_installer.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_server_conf_for_node(self._node())
        self.assertIn("ListenPort = 51820", conf)

    def test_includes_addresses(self):
        from vless_installer.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_server_conf_for_node(self._node())
        self.assertIn("10.66.5.1/32", conf)
        self.assertIn("fd66:5::1/128", conf)
        self.assertIn("10.66.5.2/32", conf)
        self.assertIn("fd66:5::2/128", conf)

    def test_includes_awg_params(self):
        from vless_installer.modules import awg_transport
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
        from vless_installer.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_text()
        self.assertIn("[Interface]", conf)
        self.assertIn("[Peer]", conf)

    def test_includes_endpoint_from_globals(self):
        from vless_installer.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_text()
        self.assertIn("Endpoint = 1.2.3.4:51820", conf)

    def test_includes_keys(self):
        from vless_installer.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_text()
        self.assertIn("PrivateKey = CLIENT_PRIV", conf)
        self.assertIn("PublicKey = SERVER_PUB", conf)
        self.assertIn("PresharedKey = PSK_KEY", conf)

    def test_includes_awg_params(self):
        from vless_installer.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_text()
        self.assertIn("Jc = 4", conf)
        self.assertIn("Jmin = 40", conf)
        self.assertIn("Jmax = 70", conf)
        self.assertIn("H1 = 1", conf)
        self.assertIn("H4 = 4", conf)

    def test_includes_dns_and_table_off(self):
        from vless_installer.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_text()
        self.assertIn("DNS = 1.1.1.1, 8.8.8.8, 2606:4700:4700::1111", conf)
        self.assertIn("Table = off", conf)

    def test_allowed_ips_all(self):
        from vless_installer.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_text()
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", conf)

    def test_persistent_keepalive(self):
        from vless_installer.modules import awg_transport
        with patch.object(awg_transport, "_core_module", return_value=_mock_core()):
            conf = awg_transport._awg_client_conf_text()
        self.assertIn("PersistentKeepalive = 25", conf)


if __name__ == "__main__":
    unittest.main(verbosity=2)
