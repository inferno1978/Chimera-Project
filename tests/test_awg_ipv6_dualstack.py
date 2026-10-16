#!/usr/bin/env python3
"""
tests/test_awg_ipv6_dualstack.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для IPv6-интеграции AWG.

Контекст: инцидент 2026-10-05 «Ютуб работает только с B4 на роутере» —
IPv4-only туннель при IPv6-сети клиента = AAAA-утечка мимо туннеля.
IPv6 default-on во всех режимах AWG.

Покрывает:
  1. awg_v6_ula_from_subnet      — derived per-node ULA (fd66:66:<okt3>::/64)
  2. awg_v6_host_from_v4         — v6-зеркало v4 host-id
  3. ip6tables_ensure            — идемпотентность v6-правил
  4. awgs_build_nat_helper_body  — v6-часть (NAT66) в helper-скрипте
  5. _awgs_cascade_build_awg1_conf(allow_ipv6=True) — Address v6 + ::/0
  6. _awgs_cascade_create_routing_script(subnet_v6=...) — v6-зеркало в скрипте
  7. awgs_build_server_conf      — peer AllowedIPs v6 (regression)
  8. awgs_qr_build_client_conf   — клиентский конфиг с v6 (regression)
  9. awgs_install сигнатура      — allow_ipv6_tunnel default True
 10. awgs_enable_ipv6            — upgrade-путь (state + пиры + v6)
"""
from __future__ import annotations

import inspect
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


# ============================================================================
#  1-2. ULA-деривация и v6-зеркало (чистые функции, без core)
# ============================================================================

class TestAwgV6UlaFromSubnet(unittest.TestCase):
    """awg_v6_ula_from_subnet — derived per-node ULA."""

    def test_default_subnet_maps_to_default_ula(self):
        from chimera.modules.awg_net_common import awg_v6_ula_from_subnet
        # Дефолт 10.66.66.0/24 → fd66:66:66::/64 (обратная совместимость
        # со старыми установками, где subnet_v6 был именно таким)
        self.assertEqual(awg_v6_ula_from_subnet("10.66.66.0/24"),
                         "fd66:66:66::/64")

    def test_user_subnets_get_per_node_ula(self):
        from chimera.modules.awg_net_common import awg_v6_ula_from_subnet
        # Реальные подсети живых нод юзера (инцидент 2026-10-05)
        self.assertEqual(awg_v6_ula_from_subnet("172.16.81.0/24"),
                         "fd66:66:81::/64")   # нода 45
        self.assertEqual(awg_v6_ula_from_subnet("172.16.82.0/24"),
                         "fd66:66:82::/64")   # нода 138
        self.assertEqual(awg_v6_ula_from_subnet("172.16.83.0/24"),
                         "fd66:66:83::/64")   # нода 91
        self.assertEqual(awg_v6_ula_from_subnet("172.16.91.0/24"),
                         "fd66:66:91::/64")   # каскадная (exit DE)

    def test_per_node_ula_unique_for_unique_v4(self):
        """Разные v4-подсети → разные ULA (анти-коллизия мульти-exit каскада)."""
        from chimera.modules.awg_net_common import awg_v6_ula_from_subnet
        ulas = {awg_v6_ula_from_subnet(f"172.16.{i}.0/24") for i in range(81, 95)}
        self.assertEqual(len(ulas), 14)

    def test_garbage_input_falls_back_to_default(self):
        from chimera.modules.awg_net_common import awg_v6_ula_from_subnet
        for bad in ("", "не-подсеть", "10.66", "10.66.66.256.0/24", None):
            self.assertEqual(awg_v6_ula_from_subnet(bad), "fd66:66:66::/64")


class TestAwgV6HostFromV4(unittest.TestCase):
    """awg_v6_host_from_v4 — v6-адрес зеркалит v4 host-id."""

    def test_mirror_host_id(self):
        from chimera.modules.awg_net_common import awg_v6_host_from_v4
        self.assertEqual(awg_v6_host_from_v4("172.16.82.2", "fd66:66:82::/64"),
                         "fd66:66:82::2")
        self.assertEqual(awg_v6_host_from_v4("172.16.82.17", "fd66:66:82::/64"),
                         "fd66:66:82::17")
        self.assertEqual(awg_v6_host_from_v4("172.16.91.3", "fd66:66:91::/64"),
                         "fd66:66:91::3")

    def test_accepts_cidr_and_plain(self):
        from chimera.modules.awg_net_common import awg_v6_host_from_v4
        self.assertEqual(awg_v6_host_from_v4("172.16.82.5/32", "fd66:66:82::/64"),
                         awg_v6_host_from_v4("172.16.82.5", "fd66:66:82::/64"))

    def test_garbage_returns_empty(self):
        from chimera.modules.awg_net_common import awg_v6_host_from_v4
        for bad_v4 in ("", "abc", None, "10.66"):
            self.assertEqual(awg_v6_host_from_v4(bad_v4, "fd66:66:82::/64"), "")
        self.assertEqual(awg_v6_host_from_v4("172.16.82.2", ""), "")


# ============================================================================
#  3. ip6tables_ensure
# ============================================================================

class TestIp6tablesEnsure(unittest.TestCase):
    """ip6tables_ensure — идемпотентное добавление v6-правил."""

    def test_calls_ip6tables_not_iptables(self):
        from chimera.modules import awg_net_common
        core = MagicMock()
        core._run.return_value = MagicMock(returncode=1)
        awg_net_common.ip6tables_ensure(
            core, ["-t", "nat", "-A", "POSTROUTING", "-o", "ens3",
                   "-j", "MASQUERADE"])
        first_call = core._run.call_args_list[0][0][0]
        self.assertEqual(first_call[0], "ip6tables")

    def test_skips_when_rule_exists(self):
        from chimera.modules import awg_net_common
        core = MagicMock()
        # -C check вернул 0 — правило уже есть
        core._run.return_value = MagicMock(returncode=0)
        awg_net_common.ip6tables_ensure(
            core, ["-A", "FORWARD", "-i", "awg0", "-j", "ACCEPT"])
        self.assertEqual(core._run.call_count, 1)  # только check, без -A


# ============================================================================
#  4. NAT-helper с v6-частью
# ============================================================================

class TestNatHelperV6(unittest.TestCase):
    """awgs_build_nat_helper_body с subnet_v6 — NAT66 в helper-скрипте."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_helper_contains_nat66_block(self):
        from chimera.modules.awg_standalone import awgs_build_nat_helper_body
        body = awgs_build_nat_helper_body(
            "172.16.82.0/24", "awg0", subnet_v6="fd66:66:82::/64")
        self.assertIn("ip6tables", body)
        self.assertIn("-s fd66:66:82::/64", body)
        self.assertIn("MASQUERADE", body)
        # обе секции — up (идемпотентный -C || -A) и down (-D || true)
        self.assertIn("ip6tables -t nat -C POSTROUTING -s fd66:66:82::/64 -o $WAN -j MASQUERADE", body)
        self.assertIn("ip6tables -t nat -D POSTROUTING -s fd66:66:82::/64 -o $WAN -j MASQUERADE 2>/dev/null || true", body)
        # v6-блок — во ВТОРОМ case (не сломал первый v4-case)
        self.assertEqual(body.count("case \"$CMD\" in"), 2)

    def test_helper_without_v6_has_no_ip6tables(self):
        from chimera.modules.awg_standalone import awgs_build_nat_helper_body
        body = awgs_build_nat_helper_body("172.16.82.0/24", "awg0", subnet_v6="")
        self.assertNotIn("ip6tables", body)

    def test_v4_part_untouched(self):
        from chimera.modules.awg_standalone import awgs_build_nat_helper_body
        v4_only = awgs_build_nat_helper_body("10.5.0.0/24", "awg0")
        with_v6 = awgs_build_nat_helper_body("10.5.0.0/24", "awg0",
                                             subnet_v6="fd66:66:5::/64")
        # v4-строки идентичны в обоих (v6 добавляется, не заменяет)
        v4_lines = [l for l in v4_only.splitlines()
                    if "iptables" in l and "ip6tables" not in l]
        for line in v4_lines:
            self.assertIn(line, with_v6)


# ============================================================================
#  5-6. Каскад: awg1.conf и routing-скрипт с v6
# ============================================================================

class TestCascadeAwg1V6(unittest.TestCase):
    """_awgs_cascade_build_awg1_conf(allow_ipv6=True) — v6 в awg1.conf."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.awg_state.AWGS_STATE_FILE", self._state)

    def test_v6_address_and_slash0_allowed_ips(self):
        from chimera.modules import awg_cascade
        self._state.write_text(json.dumps({"installed": True, "params": {}}))
        with self._patch():
            conf = awg_cascade._awgs_cascade_build_awg1_conf(
                exit_host="203.0.113.106", exit_port=52831,
                exit_pubkey="PUB", client_privkey="PRIV",
                psk="", exit_subnet="172.16.91.0/24",
                exit_peer_ip="172.16.91.3",
                allow_ipv6=True,
            )
        # v6-адрес — зеркало host-id v4 (.3 → ::3) в каскадной ULA
        self.assertIn("Address = fd66:66:91::3/128", conf)
        # AllowedIPs с ::/0
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", conf)
        # Table = off сохранён (SSH-lockout фикс не сломан)
        self.assertIn("Table = off", conf)

    def test_v6_off_byte_compatible(self):
        """allow_ipv6=False (default) — конфиг без v6 (старое поведение)."""
        from chimera.modules import awg_cascade
        self._state.write_text(json.dumps({"installed": True, "params": {}}))
        with self._patch():
            conf = awg_cascade._awgs_cascade_build_awg1_conf(
                exit_host="203.0.113.106", exit_port=52831,
                exit_pubkey="PUB", client_privkey="PRIV",
                psk="", exit_subnet="172.16.91.0/24",
                exit_peer_ip="172.16.91.3",
            )
        self.assertNotIn("::/0", conf)
        self.assertNotIn("fd66:", conf)
        self.assertIn("AllowedIPs = 0.0.0.0/0", conf)

    def test_explicit_peer_ipv6_overrides_mirror(self):
        from chimera.modules import awg_cascade
        self._state.write_text(json.dumps({"installed": True, "params": {}}))
        with self._patch():
            conf = awg_cascade._awgs_cascade_build_awg1_conf(
                exit_host="1.2.3.4", exit_port=51820,
                exit_pubkey="PUB", client_privkey="PRIV",
                psk="", exit_subnet="172.16.91.0/24",
                exit_peer_ip="172.16.91.3",
                allow_ipv6=True,
                exit_peer_ipv6="fd66:66:91::9",
            )
        self.assertIn("Address = fd66:66:91::9/128", conf)


class TestCascadeRoutingScriptV6(unittest.TestCase):
    """_awgs_cascade_create_routing_script(subnet_v6=...) — v6-зеркало."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._script = self._tmpdir / "awg-routing.sh"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("chimera.modules.awg_cascade.AWGS_CASCADE_DIR", self._tmpdir),
            patch("chimera.modules.awg_cascade.AWGS_ROUTING_SCRIPT", self._script),
        )

    def test_script_has_v6_block(self):
        from chimera.modules import awg_cascade
        with self._patch()[0], self._patch()[1]:
            awg_cascade._awgs_cascade_create_routing_script(
                "172.16.91.0/24", subnet_v6="fd66:66:91::/64")
        body = self._script.read_text()
        self.assertIn("ip6tables", body)
        self.assertIn("ip -6 route replace default dev awg1 table 2000", body)
        self.assertIn("ip -6 rule add fwmark", body)
        self.assertIn("net.ipv6.conf.all.forwarding=1", body)
        # v4-часть не тронута
        self.assertIn("ip route replace default via 172.16.91.1 dev awg1 table 2000", body)

    def test_script_without_v6_no_ip6tables(self):
        from chimera.modules import awg_cascade
        with self._patch()[0], self._patch()[1]:
            awg_cascade._awgs_cascade_create_routing_script(
                "172.16.91.0/24", subnet_v6="")
        self.assertNotIn("ip6tables", self._script.read_text())


# ============================================================================
#  7-8. Regression: серверный и клиентский конфиги с v6
# ============================================================================

class TestBuildServerConfPeerV6(unittest.TestCase):
    """awgs_build_server_conf — peer AllowedIPs v6 (regression, раньше)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_peer_v6_allowed_ips(self):
        from chimera.modules.awg_standalone import awgs_build_server_conf
        conf = awgs_build_server_conf(
            server_privkey="PRIV",
            port=45915,
            subnet="172.16.82.0/24",
            subnet_v6="fd66:66:82::/64",
            mtu=1280,
            params={},
            peers=[{"name": "user-main", "client_pubkey": "CPUB",
                    "client_ip": "172.16.82.2",
                    "client_ipv6": "fd66:66:82::2"}],
        )
        self.assertIn("Address = fd66:66:82::1/64", conf)
        self.assertIn("AllowedIPs = fd66:66:82::2/128", conf)


class TestClientConfV6(unittest.TestCase):
    """awgs_qr_build_client_conf — клиентский конфиг с v6 (regression)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_client_conf_v6_lines(self):
        from chimera.modules.awg_qr import awgs_qr_build_client_conf
        conf = awgs_qr_build_client_conf(
            peer={"client_privkey": "CPRIV", "client_ip": "172.16.82.2",
                  "client_ipv6": "fd66:66:82::2", "dns1": "1.1.1.1",
                  "dns2": "8.8.8.8"},
            server_state={"server_pubkey": "SPUB", "port": 45915,
                          "mtu": 1280, "allow_ipv6_tunnel": True,
                          "params": {}, "endpoint": "203.0.113.103"},
        )
        self.assertIn("Address = 172.16.82.2/32, fd66:66:82::2/128", conf)
        self.assertNotIn("Address = fd66:66:82::2/128\n", conf)
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", conf)


# ============================================================================
#  9. awgs_install сигнатура — default True
# ============================================================================

class TestInstallDefaultsV6(unittest.TestCase):
    """awgs_install: allow_ipv6_tunnel теперь True по умолчанию."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_default_allow_ipv6_true(self):
        from chimera.modules import awg_standalone
        sig = inspect.signature(awg_standalone.awgs_install)
        self.assertIs(sig.parameters["allow_ipv6_tunnel"].default, True)

    def test_default_subnet_v6_empty_derives_inside(self):
        from chimera.modules import awg_standalone
        sig = inspect.signature(awg_standalone.awgs_install)
        self.assertEqual(sig.parameters["subnet_v6"].default, "")


# ============================================================================
# 10. awgs_enable_ipv6 — upgrade существующей установки
# ============================================================================

class TestAwgsEnableIpv6(unittest.TestCase):
    """awgs_enable_ipv6 — upgrade-путь: state + v6 пирам-зеркалам."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _state_fixture(self) -> dict:
        return {
            "installed": True,
            "subnet": "172.16.82.0/24",
            "subnet_v6": "fd66:66:66::/64",   # старый дефолт → миграция
            "allow_ipv6_tunnel": False,
            "cascade_role": "entry",
            "cascade_subnet": "172.16.91.0/24",
            "peers": [
                {"name": "user-main", "client_ip": "172.16.82.2",
                 "client_ipv6": ""},
                {"name": "second", "client_ip": "172.16.82.5",
                 "client_ipv6": ""},
            ],
            "params": {},
        }

    def test_peers_get_mirror_v6_and_state_saved(self):
        from chimera.modules import awg_standalone
        self._state.write_text(json.dumps(self._state_fixture()))
        with patch("chimera.modules.awg_state.AWGS_STATE_FILE", self._state), \
             patch("chimera.modules.awg_peers.awg_peer_rebuild_conf",
                   return_value=True) as _rb, \
             patch("chimera.modules.awg_apply.awgs_apply_syncconf",
                   return_value=True), \
             patch("chimera.modules.awg_cascade.awgs_cascade_enable_ipv6",
                   return_value=True), \
             patch("chimera.modules.awg_qr.awgs_qr_export_peer",
                   side_effect=lambda p, show_terminal=True:
                       {"conf_path": Path("/tmp/x.conf")}):
            ok = awg_standalone.awgs_enable_ipv6()
        self.assertTrue(ok)
        state = json.loads(self._state.read_text())
        # state: v6 включён, подсеть мигрирована на per-node
        self.assertTrue(state["allow_ipv6_tunnel"])
        self.assertEqual(state["subnet_v6"], "fd66:66:82::/64")
        # пирам выданы зеркальные v6
        by_name = {p["name"]: p for p in state["peers"]}
        self.assertEqual(by_name["user-main"]["client_ipv6"], "fd66:66:82::2")
        self.assertEqual(by_name["second"]["client_ipv6"], "fd66:66:82::5")
        # rebuild конфига вызван
        _rb.assert_called_once()

    def test_standalone_role_uses_nat66(self):
        """cascade_role != entry → NAT66-ветка (setup_nat_and_routing)."""
        from chimera.modules import awg_standalone
        fixture = self._state_fixture()
        fixture["cascade_role"] = ""
        self._state.write_text(json.dumps(fixture))
        with patch("chimera.modules.awg_state.AWGS_STATE_FILE", self._state), \
             patch("chimera.modules.awg_peers.awg_peer_rebuild_conf",
                   return_value=True), \
             patch("chimera.modules.awg_apply.awgs_apply_syncconf",
                   return_value=True), \
             patch.object(awg_standalone, "awgs_setup_nat_and_routing",
                          wraps=lambda **kw: True) as _nat:
            ok = awg_standalone.awgs_enable_ipv6(regen_client_confs=False)
        self.assertTrue(ok)
        _nat.assert_called_once()
        self.assertEqual(_nat.call_args.kwargs.get("subnet_v6"), "fd66:66:82::/64")

    def test_not_installed_fails_cleanly(self):
        from chimera.modules import awg_standalone
        fixture = self._state_fixture()
        fixture["installed"] = False
        self._state.write_text(json.dumps(fixture))
        with patch("chimera.modules.awg_state.AWGS_STATE_FILE", self._state):
            ok = awg_standalone.awgs_enable_ipv6()
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)
