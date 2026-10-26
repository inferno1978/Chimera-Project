#!/usr/bin/env python3
"""
tests/test_domain_strategy.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/domain_strategy.py (смена domainStrategy
на живом config.json, меню «Настройки сети → 6»).

Ключевой регрессионный кейс (стенд 2026-10-26): сервер установлен «в режиме
IPv6», IPv6 на хостинге отвалился. Прежний код меню additionally портил
routing.domainStrategy (Use*-значение → Xray молча читает его как AsIs →
ip/geoip-правила перестают матчить домены) и не трогал dns.queryStrategy /
мёртвые IPv6-DNS. Проверяем новую семантику целиком.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules.domain_strategy import (  # noqa: E402
    V4_DNS_FALLBACK,
    _is_v6_address,
    apply_domain_strategy_to_config,
)


def _v6_mode_config() -> dict:
    """Конфиг «как сгенерил бы установщик при живом IPv6» (шаг 8 → UseIPv6v4)."""
    return {
        "log": {"loglevel": "warning"},
        "dns": {
            "servers": [
                {"address": "2a10:50c0::1:ff", "port": 53, "network": "udp", "skipFallback": False},
                {"address": "2a10:50c0::2:ff", "port": 53, "network": "udp", "skipFallback": False},
                {"address": "2606:4700:4700::1111", "port": 53, "network": "udp", "skipFallback": False},
                {"address": "2001:4860:4860::8888", "port": 53, "network": "udp", "skipFallback": True},
                {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": True},
                {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": True},
            ],
            "queryStrategy": "UseIPv6v4",
        },
        "inbounds": [{
            "tag": "inbound-vless", "port": 443, "listen": "::",
            "protocol": "vless",
        }],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct",
             "settings": {"domainStrategy": "UseIPv6v4"},
             "streamSettings": {"sockopt": {"mark": 51820}}},
            {"protocol": "blackhole", "tag": "BLOCK"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"},
                {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
            ],
        },
    }


class TestIsV6Address(unittest.TestCase):
    def test_v4_is_not_v6(self):
        self.assertFalse(_is_v6_address("1.1.1.1"))
        self.assertFalse(_is_v6_address("9.9.9.9"))

    def test_domain_is_not_v6(self):
        self.assertFalse(_is_v6_address("dns.google"))

    def test_url_is_not_v6(self):
        # Схемы содержат слэши — не матчатся v6-литералом (в конфигах
        # Химеры DNS-серверы-URL не встречаются, но защита от ложного
        # срабатывания нужна).
        self.assertFalse(_is_v6_address("https://1.1.1.1/dns-query"))
        self.assertFalse(_is_v6_address("udp://2a10:50c0::1:ff"))

    def test_v6_literals(self):
        self.assertTrue(_is_v6_address("2a10:50c0::1:ff"))
        self.assertTrue(_is_v6_address("2606:4700:4700::1111"))
        self.assertTrue(_is_v6_address("[2001:db8::1]:53"))

    def test_garbage(self):
        self.assertFalse(_is_v6_address(""))
        self.assertFalse(_is_v6_address(None))
        self.assertFalse(_is_v6_address(12345))


class TestSwitchToUseIPv4(unittest.TestCase):
    """Кейс «отвалился IPv6» — перевод живого конфига на UseIPv4."""

    def setUp(self):
        self.cfg = _v6_mode_config()

    def test_outbounds_patched(self):
        changes = apply_domain_strategy_to_config(self.cfg, "UseIPv4")
        ds = {ob["tag"]: ob["settings"]["domainStrategy"]
              for ob in self.cfg["outbounds"] if ob.get("protocol") == "freedom"}
        self.assertEqual(ds, {"direct": "UseIPv4"})
        self.assertTrue(any("direct" in c for c in changes))

    def test_routing_domain_strategy_untouched_regression(self):
        """ГЛАВНЫЙ регрессионный тест: routing.domainStrategy не портится."""
        before = copy.deepcopy(self.cfg["routing"])
        apply_domain_strategy_to_config(self.cfg, "UseIPv4")
        self.assertEqual(self.cfg["routing"], before)
        self.assertEqual(self.cfg["routing"]["domainStrategy"], "IPIfNonMatch")
        # правила не тронуты
        self.assertEqual(len(self.cfg["routing"]["rules"]), 2)

    def test_dns_query_strategy_patched(self):
        apply_domain_strategy_to_config(self.cfg, "UseIPv4")
        self.assertEqual(self.cfg["dns"]["queryStrategy"], "UseIPv4")

    def test_v6_dns_servers_removed_v4_kept(self):
        apply_domain_strategy_to_config(self.cfg, "UseIPv4")
        addrs = [s["address"] for s in self.cfg["dns"]["servers"]]
        self.assertEqual(addrs, ["1.1.1.1", "8.8.8.8"])
        # все серверы были skipFallback=True → первый должен стать primary
        self.assertFalse(self.cfg["dns"]["servers"][0]["skipFallback"])

    def test_stats_api_outbound_untouched(self):
        self.cfg["outbounds"].insert(0, {
            "protocol": "freedom", "tag": "xray-stats-api",
            "settings": {"domainStrategy": "UseIPv6v4"}})
        apply_domain_strategy_to_config(self.cfg, "UseIPv4")
        stats = next(ob for ob in self.cfg["outbounds"]
                     if ob["tag"] == "xray-stats-api")
        self.assertEqual(stats["settings"]["domainStrategy"], "UseIPv6v4")

    def test_outbound_without_settings_gets_one(self):
        self.cfg["outbounds"].insert(0, {"protocol": "freedom", "tag": "direct-local"})
        apply_domain_strategy_to_config(self.cfg, "UseIPv4")
        dl = next(ob for ob in self.cfg["outbounds"] if ob["tag"] == "direct-local")
        self.assertEqual(dl["settings"]["domainStrategy"], "UseIPv4")

    def test_idempotent(self):
        apply_domain_strategy_to_config(self.cfg, "UseIPv4")
        changes = apply_domain_strategy_to_config(self.cfg, "UseIPv4")
        self.assertEqual(changes, [])


class TestSwitchToUseIPv4AllV6Dns(unittest.TestCase):
    def test_fallback_substituted(self):
        cfg = _v6_mode_config()
        cfg["dns"]["servers"] = [
            {"address": "2a10:50c0::1:ff", "port": 53, "network": "udp", "skipFallback": False},
            {"address": "2606:4700:4700::1111", "port": 53, "network": "udp", "skipFallback": False},
        ]
        apply_domain_strategy_to_config(cfg, "UseIPv4")
        self.assertEqual(
            cfg["dns"]["servers"],
            [dict(s) for s in V4_DNS_FALLBACK])

    def test_string_servers_filtered(self):
        cfg = _v6_mode_config()
        cfg["dns"]["servers"] = ["2a10:50c0::1:ff", "1.1.1.1", "8.8.8.8"]
        apply_domain_strategy_to_config(cfg, "UseIPv4")
        self.assertEqual(cfg["dns"]["servers"], ["1.1.1.1", "8.8.8.8"])


class TestSwitchToUseIPv6v4(unittest.TestCase):
    """Обратное переключение (v6 починили) — DNS-серверы не трогаем."""

    def test_servers_untouched(self):
        cfg = _v6_mode_config()
        before = copy.deepcopy(cfg["dns"]["servers"])
        apply_domain_strategy_to_config(cfg, "UseIPv6v4")
        self.assertEqual(cfg["dns"]["servers"], before)

    def test_local_resolvers_survive_v4_switch(self):
        """AGH/dnscrypt-конфиг: локальные резолверы без двоеточий — не удаляются."""
        cfg = _v6_mode_config()
        cfg["dns"]["servers"] = [
            {"address": "127.0.0.1", "port": 53, "network": "udp", "skipFallback": False},
            {"address": "127.0.0.1", "port": 5300, "network": "udp", "skipFallback": False},
            {"address": "9.9.9.9", "port": 53, "network": "udp", "skipFallback": False},
            {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": True},
        ]
        before = copy.deepcopy(cfg["dns"]["servers"])
        apply_domain_strategy_to_config(cfg, "UseIPv4")
        self.assertEqual(cfg["dns"]["servers"], before)


class TestEdgeCases(unittest.TestCase):
    def test_no_dns_section(self):
        cfg = {"outbounds": [
            {"protocol": "freedom", "tag": "direct",
             "settings": {"domainStrategy": "UseIPv6v4"}}],
            "routing": {"domainStrategy": "IPIfNonMatch"}}
        changes = apply_domain_strategy_to_config(cfg, "UseIPv4")
        self.assertEqual(cfg["outbounds"][0]["settings"]["domainStrategy"], "UseIPv4")
        self.assertEqual(cfg["routing"]["domainStrategy"], "IPIfNonMatch")
        self.assertTrue(changes)

    def test_empty_outbounds(self):
        cfg = {"outbounds": [], "dns": {"queryStrategy": "UseIPv6v4"}}
        apply_domain_strategy_to_config(cfg, "UseIP")
        self.assertEqual(cfg["dns"]["queryStrategy"], "UseIP")

    def test_outbounds_none(self):
        cfg = {"outbounds": None}
        changes = apply_domain_strategy_to_config(cfg, "UseIPv4")
        self.assertEqual(changes, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
