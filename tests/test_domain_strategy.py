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


class TestDualWriteSockopt(unittest.TestCase):
    """Миграция freedom.settings.domainStrategy → sockopt.domainStrategy
    (deprecated в Xray 26.9.30+, будет удалён). Дуал-запись: оба поля с
    одинаковым значением — поведение идентично на любом ядре флота
    (≤26.7.x читает settings, 26.9.30+ читает sockopt, значения совпадают)."""

    def test_make_freedom_outbound_shape(self):
        from chimera.modules.domain_strategy import make_freedom_outbound
        ob = make_freedom_outbound("direct", "UseIPv6v4")
        self.assertEqual(ob["protocol"], "freedom")
        self.assertEqual(ob["tag"], "direct")
        self.assertEqual(ob["settings"]["domainStrategy"], "UseIPv6v4")
        self.assertEqual(
            ob["streamSettings"]["sockopt"]["domainStrategy"], "UseIPv6v4")
        # без mark — ключа mark нет
        self.assertNotIn("mark", ob["streamSettings"]["sockopt"])

    def test_make_freedom_outbound_with_mark(self):
        from chimera.modules.domain_strategy import make_freedom_outbound
        ob = make_freedom_outbound("direct", "UseIPv6v4", mark=51820)
        self.assertEqual(ob["streamSettings"]["sockopt"]["mark"], 51820)
        self.assertEqual(
            ob["streamSettings"]["sockopt"]["domainStrategy"], "UseIPv6v4")

    def test_make_freedom_outbound_send_through(self):
        from chimera.modules.domain_strategy import make_freedom_outbound
        ob = make_freedom_outbound("warp", "UseIPv4",
                                   send_through="172.16.0.2")
        self.assertEqual(ob["settings"]["sendThrough"], "172.16.0.2")
        self.assertEqual(ob["settings"]["domainStrategy"], "UseIPv4")
        self.assertEqual(
            ob["streamSettings"]["sockopt"]["domainStrategy"], "UseIPv4")

    def test_set_merges_existing_sockopt_keys(self):
        """AWG-mark / TFO в sockopt не затираются при патче стратегии."""
        from chimera.modules.domain_strategy import set_freedom_domain_strategy
        ob = {
            "protocol": "freedom", "tag": "direct",
            "settings": {"domainStrategy": "UseIPv6v4"},
            "streamSettings": {"sockopt": {
                "mark": 51820, "tcpFastOpen": True}},
        }
        self.assertTrue(set_freedom_domain_strategy(ob, "UseIPv4"))
        self.assertEqual(ob["streamSettings"]["sockopt"]["mark"], 51820)
        self.assertIs(ob["streamSettings"]["sockopt"]["tcpFastOpen"], True)
        self.assertEqual(ob["settings"]["domainStrategy"], "UseIPv4")
        self.assertEqual(
            ob["streamSettings"]["sockopt"]["domainStrategy"], "UseIPv4")

    def test_set_creates_sockopt_when_absent(self):
        from chimera.modules.domain_strategy import set_freedom_domain_strategy
        ob = {"protocol": "freedom", "tag": "direct-local",
              "settings": {"domainStrategy": "UseIPv4"}}
        set_freedom_domain_strategy(ob, "UseIPv4")
        self.assertEqual(
            ob["streamSettings"]["sockopt"]["domainStrategy"], "UseIPv4")

    def test_set_preserves_settings_send_through(self):
        from chimera.modules.domain_strategy import set_freedom_domain_strategy
        ob = {"protocol": "freedom", "tag": "warp",
              "settings": {"domainStrategy": "UseIPv6",
                           "sendThrough": "fd00::2"}}
        set_freedom_domain_strategy(ob, "UseIPv4")
        self.assertEqual(ob["settings"]["sendThrough"], "fd00::2")

    def test_apply_produces_dual_form(self):
        cfg = _v6_mode_config()
        apply_domain_strategy_to_config(cfg, "UseIPv4")
        direct = next(ob for ob in cfg["outbounds"] if ob["tag"] == "direct")
        self.assertEqual(direct["settings"]["domainStrategy"], "UseIPv4")
        self.assertEqual(
            direct["streamSettings"]["sockopt"]["domainStrategy"], "UseIPv4")
        # легаси-марка AWG не тронута (её в fixture нет — просто структура)
        self.assertIn("sockopt", direct["streamSettings"])

    def test_apply_awg_mark_preserved(self):
        """Инцидент-класс: патч стратегии на AWG-ноде не должен ронять fwmark."""
        cfg = _v6_mode_config()
        cfg["outbounds"][0]["streamSettings"] = {"sockopt": {"mark": 51820}}
        apply_domain_strategy_to_config(cfg, "UseIPv4")
        direct = cfg["outbounds"][0]
        self.assertEqual(direct["streamSettings"]["sockopt"]["mark"], 51820)
        self.assertEqual(
            direct["streamSettings"]["sockopt"]["domainStrategy"], "UseIPv4")

    def test_dual_write_idempotent(self):
        from chimera.modules.domain_strategy import (
            make_freedom_outbound, set_freedom_domain_strategy)
        ob = make_freedom_outbound("direct", "UseIPv6v4")
        self.assertFalse(set_freedom_domain_strategy(ob, "UseIPv6v4"))

    def test_set_ignores_non_freedom_and_stats(self):
        from chimera.modules.domain_strategy import set_freedom_domain_strategy
        vless = {"protocol": "vless", "tag": "chain-exit-0",
                 "settings": {"domainStrategy": "UseIPv6v4"}}
        self.assertFalse(set_freedom_domain_strategy(vless, "UseIPv4"))
        self.assertNotIn("streamSettings", vless)
        stats = {"protocol": "freedom", "tag": "xray-stats-api",
                 "settings": {"domainStrategy": "UseIPv6v4"}}
        self.assertFalse(set_freedom_domain_strategy(stats, "UseIPv4"))
        self.assertEqual(stats["settings"]["domainStrategy"], "UseIPv6v4")


class TestResolveOutboundStrategy(unittest.TestCase):
    """Резолвер стратегии для генераторов: выбор установки (state) имеет
    приоритет; пустой выбор — адаптив по живому IPv6; v6-стратегии без
    живого v6 деградируют до UseIPv4. Регрессия кейса 91.х: генератор
    хардкодил UseIPv6v4 при state UseIPv4."""

    def test_empty_prefers_v6_when_available(self):
        from chimera.modules.domain_strategy import resolve_outbound_strategy
        self.assertEqual(resolve_outbound_strategy("", True), "UseIPv6v4")

    def test_empty_v4_when_no_v6(self):
        from chimera.modules.domain_strategy import resolve_outbound_strategy
        self.assertEqual(resolve_outbound_strategy("", False), "UseIPv4")

    def test_state_use_ipv4_wins_even_with_v6(self):
        """ГЛАВНАЯ регрессия 91.х: state UseIPv4 + живой IPv6 → UseIPv4."""
        from chimera.modules.domain_strategy import resolve_outbound_strategy
        self.assertEqual(
            resolve_outbound_strategy("UseIPv4", True), "UseIPv4")

    def test_v6_strategy_degrades_without_v6(self):
        """«IPv6 отвалился после установки» → v6-first silently dangerous."""
        from chimera.modules.domain_strategy import resolve_outbound_strategy
        for pref in ("UseIPv6v4", "UseIPv4v6", "UseIPv6"):
            self.assertEqual(
                resolve_outbound_strategy(pref, False), "UseIPv4",
                f"{pref} без IPv6 должен деградировать до UseIPv4")

    def test_v6_strategy_kept_with_v6(self):
        from chimera.modules.domain_strategy import resolve_outbound_strategy
        self.assertEqual(
            resolve_outbound_strategy("UseIPv6v4", True), "UseIPv6v4")
        self.assertEqual(
            resolve_outbound_strategy("UseIPv4v6", True), "UseIPv4v6")

    def test_use_ip_passthrough(self):
        from chimera.modules.domain_strategy import resolve_outbound_strategy
        self.assertEqual(resolve_outbound_strategy("UseIP", True), "UseIP")
        self.assertEqual(resolve_outbound_strategy("UseIP", False), "UseIP")

    def test_use_ipv4_passthrough_no_v6(self):
        from chimera.modules.domain_strategy import resolve_outbound_strategy
        self.assertEqual(
            resolve_outbound_strategy("UseIPv4", False), "UseIPv4")

    def test_none_and_whitespace(self):
        from chimera.modules.domain_strategy import resolve_outbound_strategy
        self.assertEqual(resolve_outbound_strategy(None, True), "UseIPv6v4")
        self.assertEqual(
            resolve_outbound_strategy("  UseIPv4  ", True), "UseIPv4")
        self.assertEqual(resolve_outbound_strategy("   ", False), "UseIPv4")


class TestResolveExitNodeStrategy(unittest.TestCase):
    """Стратегия exit-конфигов, генерируемых с entry: IPv6-статус exit
    неизвестен → самоподстраивающийся v6-first/v4-fallback; явный UseIPv4
    из state entry («v4-only инфраструктура») уважается."""

    def test_empty_defaults_to_self_adapting(self):
        from chimera.modules.domain_strategy import resolve_exit_node_strategy
        self.assertEqual(resolve_exit_node_strategy(""), "UseIPv6v4")
        self.assertEqual(resolve_exit_node_strategy(None), "UseIPv6v4")

    def test_explicit_v4_respected(self):
        from chimera.modules.domain_strategy import resolve_exit_node_strategy
        self.assertEqual(
            resolve_exit_node_strategy("UseIPv4"), "UseIPv4")

    def test_v6_first_variants_collapse_to_self_adapting(self):
        from chimera.modules.domain_strategy import resolve_exit_node_strategy
        self.assertEqual(
            resolve_exit_node_strategy("UseIPv6v4"), "UseIPv6v4")
        self.assertEqual(
            resolve_exit_node_strategy("UseIPv4v6"), "UseIPv6v4")

    def test_use_ip_passthrough(self):
        from chimera.modules.domain_strategy import resolve_exit_node_strategy
        self.assertEqual(resolve_exit_node_strategy("UseIP"), "UseIP")
