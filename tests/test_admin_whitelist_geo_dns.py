#!/usr/bin/env python3
"""
tests/test_admin_whitelist_geo_dns.py
───────────────────────────────────────────────────────────────────────────────
: регрессионные тесты двух инцидентов.

Инцидент №1 (блокировка входящих из РФ, меню G):
  Пункт «D» (Определить мой текущий IP автоматически) запрашивал api.ipify.org
  С САМОГО СЕРВЕРА → в whitelist попадал IP САМОГО СЕРВЕРА, а не IP
  администратора. На Entry-ноде в РФ администратор из РФ включал блокировку и
  терял доступ к порту Xray (клиент: «dial tcp <server>:443: i/o timeout»).
  Фикс: _detect_admin_ssh_ip() — IP источника текущей SSH-сессии
  ($SSH_CLIENT/$SSH_CONNECTION → who -m → ss), + авто-страховка в
  _ingress_enable().

Инцидент №2 (гео-зависимость DNS-стека):
  Entry-нода в РФ + bootstrap/fallback/netprobe 1.1.1.1:53/8.8.8.8:53 (душатся
  TSPU / заблокированы РКН) + server_names cloudflare/google → DNS black-hole.
  Фикс: Quad9 (9.9.9.9 / 149.112.112.112) + Яндекс в bootstrap DNSCrypt,
  quad9-dnscrypt-* в server_names, живой Quad9-fallback в dns_servers Xray.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

# _core-стаб (как в test_ingress_geoip.py) — модульам нужен chimera._core
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


_setup_core_in_sysmodules()


# ═════════════════════════════════════════════════════════════════════════════
#  Инцидент №1: детекция IP администратора (SSH-сессия)
# ═════════════════════════════════════════════════════════════════════════════
class TestDetectAdminSshIp(unittest.TestCase):
    """_detect_admin_ssh_ip — IP источника SSH-сессии, а не IP сервера."""

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in ("SSH_CLIENT", "SSH_CONNECTION")}
        os.environ.pop("SSH_CLIENT", None)
        os.environ.pop("SSH_CONNECTION", None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_ssh_client_env(self):
        from chimera.modules.ingress_geoip import _detect_admin_ssh_ip
        os.environ["SSH_CLIENT"] = "203.0.113.77 55123 22"
        self.assertEqual(_detect_admin_ssh_ip(), "203.0.113.77")

    def test_ssh_connection_env_fallback(self):
        from chimera.modules.ingress_geoip import _detect_admin_ssh_ip
        os.environ["SSH_CONNECTION"] = "198.51.100.9 40122 10.0.0.5 22"
        self.assertEqual(_detect_admin_ssh_ip(), "198.51.100.9")

    def test_ipv6_ssh_client(self):
        from chimera.modules.ingress_geoip import _detect_admin_ssh_ip
        os.environ["SSH_CLIENT"] = "2a00:1370:8194:1::42 55123 22"
        self.assertEqual(_detect_admin_ssh_ip(), "2a00:1370:8194:1::42")

    def test_env_priority_over_who(self):
        from chimera.modules import ingress_geoip
        os.environ["SSH_CLIENT"] = "203.0.113.77 55123 22"
        # даже если who -m вернул бы другой адрес — ENV приоритетнее
        with patch.object(ingress_geoip, "_run",
                          return_value=_FakeRun(0, "root pts/0 2026-01-01 10:00 (192.0.2.1)")):
            self.assertEqual(ingress_geoip._detect_admin_ssh_ip(), "203.0.113.77")

    def test_returns_empty_when_nothing_detected(self):
        from chimera.modules import ingress_geoip
        # локальная консоль: ENV пуст, who/ss недоступны
        with patch.object(ingress_geoip, "_run",
                          return_value=_FakeRun(1, "")):
            self.assertEqual(ingress_geoip._detect_admin_ssh_ip(), "")


class _FakeRun:
    """Заглушка subprocess.CompletedProcess."""

    def __init__(self, rc: int, out: str = "", err: str = ""):
        self.returncode = rc
        self.stdout = out
        self.stderr = err


class TestIngressEnableAutoWhitelist(unittest.TestCase):
    """_ingress_enable — авто-добавление IP SSH-сессии в whitelist."""

    def test_admin_ip_auto_added_to_state(self):
        from chimera.modules import ingress_geoip
        captured = {}

        def fake_save(data):
            captured.update(data)

        base_state = {"enabled": False, "port": 0, "whitelist": [],
                      "cidrs_v4": 0, "cidrs_v6": 0, "updated_at": "", "method": ""}

        with patch.object(ingress_geoip, "_ingress_iptables_available",
                          return_value=True), \
             patch.object(ingress_geoip, "_detect_admin_ssh_ip",
                          return_value="203.0.113.77"), \
             patch.object(ingress_geoip, "_server_own_ips",
                          return_value=["203.0.113.134"]), \
             patch.object(ingress_geoip, "_ingress_state_load",
                          return_value=dict(base_state)), \
             patch.object(ingress_geoip, "_ingress_state_save",
                          side_effect=fake_save), \
             patch.object(ingress_geoip, "check_ripe_file_age",
                          return_value=False):
            ingress_geoip._ingress_enable(443)

        # IP администратора сохранён в whitelist ДО любых правил блокировки
        self.assertIn("203.0.113.77", captured.get("whitelist", []))

    def test_server_own_ip_not_added(self):
        """IP самого сервера не должен попадать в whitelist (бесполезен)."""
        from chimera.modules import ingress_geoip
        captured = {}

        def fake_save(data):
            captured.update(data)

        base_state = {"enabled": False, "port": 0, "whitelist": [],
                      "cidrs_v4": 0, "cidrs_v6": 0, "updated_at": "", "method": ""}

        with patch.object(ingress_geoip, "_ingress_iptables_available",
                          return_value=True), \
             patch.object(ingress_geoip, "_detect_admin_ssh_ip",
                          return_value="203.0.113.134"), \
             patch.object(ingress_geoip, "_server_own_ips",
                          return_value=["203.0.113.134"]), \
             patch.object(ingress_geoip, "_ingress_state_load",
                          return_value=dict(base_state)), \
             patch.object(ingress_geoip, "_ingress_state_save",
                          side_effect=fake_save), \
             patch.object(ingress_geoip, "check_ripe_file_age",
                          return_value=False):
            ingress_geoip._ingress_enable(443)

        self.assertNotIn("203.0.113.134",
                         captured.get("whitelist", []))


# ═════════════════════════════════════════════════════════════════════════════
#  Инцидент №2: гео-резистентный DNS (Entry в РФ)
# ═════════════════════════════════════════════════════════════════════════════
class TestDnscryptGeoResilientDefaults(unittest.TestCase):
    """TOML DNSCrypt: quad9 в server_names; bootstrap/fallback/netprobe достижимы из РФ."""

    def setUp(self):
        self._src = (_PROJECT_ROOT / "chimera" / "modules" /
                     "dnscrypt_setup.py").read_text()

    def test_server_names_include_quad9_dnscrypt(self):
        # DNSCrypt-протокол Quad9 (порт 8443, без SNI) переживает DPI РФ
        self.assertIn("quad9-dnscrypt-ip4-nofilter-pri", self._src)
        self.assertIn("quad9-dnscrypt-ip6-nofilter-pri", self._src)

    def test_bootstrap_resolvers_rf_reachable(self):
        self.assertIn("bootstrap_resolvers = ['9.9.9.9:53', '77.88.8.8:53']",
                      self._src)

    def test_fallback_resolvers_rf_reachable(self):
        self.assertIn("fallback_resolvers = ['9.9.9.9:53', '77.88.8.8:53']",
                      self._src)

    def test_netprobe_not_cloudflare(self):
        # netprobe 1.1.1.1:53 в РФ душится → dnscrypt решал, что «сети нет»
        self.assertIn("netprobe_address = '9.9.9.9:53'", self._src)
        self.assertNotIn("netprobe_address = '1.1.1.1:53'", self._src)


class TestAghFallbackQuad9(unittest.TestCase):
    """AGH fallback_dns — параллельные DoH-апстримы вместо plain :53.

    Эволюция: plain-:53 (Quad9/1.1.1.1) душится из РФ → fallback
    переведён на DoH-список (cloudflare/adguard/dnsforge/doh.pub/
    google, upstream_mode: parallel — см. aghome_setup.AGH_FALLBACK_DNS).
    Тест обновлён вслед за дизайном: раньше ассертил Quad9 x2."""

    def test_fallback_dns_values(self):
        from chimera.modules.aghome_setup import AGH_FALLBACK_DNS
        # все записи — DoH (plain :53 душится из РФ)
        self.assertTrue(
            all(u.startswith("https://") and u.endswith("/dns-query")
                for u in AGH_FALLBACK_DNS),
            f"fallback must be DoH-only, got: {AGH_FALLBACK_DNS}")
        # несколько апстримов — параллельная устойчивость
        self.assertGreaterEqual(len(AGH_FALLBACK_DNS), 3)
        # plain-:53 в fallback больше не используется
        self.assertNotIn("1.1.1.1:53", AGH_FALLBACK_DNS)
        self.assertNotIn("9.9.9.9:53", AGH_FALLBACK_DNS)


class TestXrayDnsQuad9Fallback(unittest.TestCase):
    """dns_servers Xray — живой Quad9-fallback (skipFallback=False) во всех
    генераторах конфигов (Режим A + цепочка single/multi)."""

    _PATTERN = '"address": "9.9.9.9", "port": 53, "network": "udp", "skipFallback": False'

    def test_xray_install_has_quad9_fallback(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" /
               "xray_install.py").read_text()
        # agh-ветка + dnscrypt-ветка
        self.assertGreaterEqual(src.count(self._PATTERN), 2)

    def test_chain_nodes_has_quad9_fallback(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" /
               "chain_nodes.py").read_text()
        # 2 генератора (single-node + multi-node) × 2 ветки (agh + dnscrypt)
        self.assertGreaterEqual(src.count(self._PATTERN), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
