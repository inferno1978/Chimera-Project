#!/usr/bin/env python3
"""
tests/test_subscription_multinode.py — тесты мульти-нодовых конфигов подписки.

Покрывает:
  • subscription_multinode.collect_nodes (entry + exits + mirrors)
  • multinode_status (авто: Mode B + chain_nodes; явный on/off)
  • build_mihomo_config (группы, ноды, правила, домены, YAML-санити)
  • build_singbox_config (selector/urltest/route.final, extra outbounds)
  • get_multinode_uris (vless:// exit-нод)
  • subscription._resolve_format ('clash')
  • subscription.build_subscription_body (exit-URI добавляются)
  • subscription.build_subscription_body_ios (exit-URI исключаются)
  • HTTP e2e: ?format=clash и ?format=singbox через реальный сервер

Запуск: python3 -m unittest tests.test_subscription_multinode -v
"""
from __future__ import annotations

import base64
import json
import sys
import tempfile
import types
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    """Загружает chimera._core через exec и регистрирует в sys.modules."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core


# ── Тестовые данные ────────────────────────────────────────────────────────
_TEST_USER = {
    "uuid": "11111111-2222-3333-4444-555555555555",
    "email": "multinode@test.online",
    "name": "multitester",
}

_TEST_STATE_MODE_B = {
    "domain": "entry.test.online",
    "server_port": 443,
    "protocol_mode": "reality",
    "public_key": "entry_pbk_123",
    "short_id": "aabbccdd",
    "fingerprint": "chrome",
    "xtls_flow": "xtls-rprx-vision",
    "install_mode": "B",
    "chain_nodes": [
        {
            "host": "1.2.3.4", "port": 443,
            "uuid": "exit-uuid-1", "pubkey": "exit_pbk_1",
            "shortid": "11111111", "sni": "exit1.example.com",
            "fp": "chrome", "proto": "reality",
        },
        {
            "host": "5.6.7.8", "port": 443,
            "uuid": "exit-uuid-2", "pubkey": "exit_pbk_2",
            "shortid": "22222222", "sni": "exit2.example.com",
            "fp": "chrome", "proto": "reality",
        },
    ],
}

_TEST_STATE_MODE_A = {
    "domain": "solo.test.online",
    "server_port": 443,
    "protocol_mode": "reality",
    "public_key": "solo_pbk",
    "short_id": "00000001",
    "fingerprint": "chrome",
    "xtls_flow": "xtls-rprx-vision",
    "install_mode": "A",
}


def _fake_vless_link(host, uuid_str, pbk, sid, domain, fp="chrome",
                     proto="reality", xhttp_path="/", xhttp_mode="stream-up",
                     port=443):
    return (f"vless://{uuid_str}@{host}:{port}?type=tcp&security=reality"
            f"&pbk={pbk}&sid={sid}&sni={domain}&fp={fp}#Chimera")


class TestMultinodeRegistry(unittest.TestCase):
    """Реестр нод + статус фичи."""

    @classmethod
    def setUpClass(cls):
        _setup_core()
        cls._tmpdir = Path(tempfile.mkdtemp())
        cls._state_file = cls._tmpdir / "state.json"
        cls._sub_conf = cls._tmpdir / "subscription.json"
        cls._mirrors = cls._tmpdir / "entry_mirrors.json"
        from chimera.modules import subscription_multinode as mn
        cls._mn = mn

    def _with_paths(self, state, sub_conf=None, mirrors=None):
        p_state = patch.object(self._mn, "_STATE_FILE", self._state_file)
        p_conf = patch.object(self._mn, "_SUB_CONF", self._sub_conf)
        p_mir = patch.object(self._mn, "_MIRRORS_FILE", self._mirrors)
        p_geo = patch.object(self._mn, "_geo_lookup", return_value="")
        self._state_file.write_text(json.dumps(state))
        self._sub_conf.write_text(json.dumps(sub_conf or {}))
        self._mirrors.write_text(json.dumps(mirrors or {"mirrors": []}))
        return p_state, p_conf, p_mir, p_geo

    def test_status_auto_mode_b_enabled(self):
        ps = self._with_paths(_TEST_STATE_MODE_B)
        with ps[0], ps[1], ps[2], ps[3]:
            st = self._mn.multinode_status()
            self.assertTrue(st["enabled"])
            self.assertFalse(st["explicit"])
            self.assertEqual(st["exit_count"], 2)

    def test_status_auto_mode_a_disabled(self):
        ps = self._with_paths(_TEST_STATE_MODE_A)
        with ps[0], ps[1], ps[2], ps[3]:
            st = self._mn.multinode_status()
            self.assertFalse(st["enabled"])
            self.assertEqual(st["exit_count"], 0)

    def test_status_explicit_off_overrides_mode_b(self):
        ps = self._with_paths(_TEST_STATE_MODE_B,
                              sub_conf={"multinode": {"enabled": False}})
        with ps[0], ps[1], ps[2], ps[3]:
            st = self._mn.multinode_status()
            self.assertFalse(st["enabled"])
            self.assertTrue(st["explicit"])

    def test_collect_nodes_structure(self):
        mirrors = {"mirrors": [{
            "id": "m1", "label": "EU-backup", "enabled": True,
            "host": "9.9.9.9", "port": 443, "sni": "mirror.example.com",
            "pbk": "mirror_pbk", "sid": "33333333", "fp": "chrome",
        }]}
        ps = self._with_paths(_TEST_STATE_MODE_B, mirrors=mirrors)
        with ps[0], ps[1], ps[2], ps[3]:
            reg = self._mn.collect_nodes(_TEST_USER)
            self.assertEqual(len(reg["exits"]), 2)
            self.assertIsNotNone(reg["entry"])
            self.assertEqual(len(reg["mirrors"]), 1)
            # Порядок all: exits первыми, entry, mirrors
            kinds = [n["kind"] for n in reg["all"]]
            self.assertEqual(kinds, ["exit", "exit", "entry_cascade", "mirror"])
            # Exit-ноды со своими UUID (chain-UUID)
            self.assertEqual(reg["exits"][0]["uuid"], "exit-uuid-1")
            self.assertEqual(reg["exits"][1]["uuid"], "exit-uuid-2")
            # Entry с UUID юзера
            self.assertEqual(reg["entry"]["uuid"], _TEST_USER["uuid"])
            # Mirror с UUID юзера
            self.assertEqual(reg["mirrors"][0]["uuid"], _TEST_USER["uuid"])
            # Имена уникальны
            names = [n["name"] for n in reg["all"]]
            self.assertEqual(len(names), len(set(names)))

    def test_collect_nodes_skips_incomplete_exit(self):
        state = json.loads(json.dumps(_TEST_STATE_MODE_B))
        state["chain_nodes"][1]["pubkey"] = ""  # неполная нода
        ps = self._with_paths(state)
        with ps[0], ps[1], ps[2], ps[3]:
            reg = self._mn.collect_nodes(_TEST_USER)
            self.assertEqual(len(reg["exits"]), 1)

    def test_legacy_chain_exit_format(self):
        state = {
            "domain": "entry.test.online", "install_mode": "B",
            "chain_exit_host": "1.2.3.4", "chain_exit_port": 443,
            "chain_exit_uuid": "legacy-uuid", "chain_exit_pubkey": "pbk",
            "chain_exit_shortid": "aa", "chain_exit_sni": "sni.example.com",
        }
        ps = self._with_paths(state)
        with ps[0], ps[1], ps[2], ps[3]:
            st = self._mn.multinode_status()
            self.assertTrue(st["enabled"])  # legacy-формат тоже активирует фичу
            reg = self._mn.collect_nodes(_TEST_USER)
            self.assertEqual(len(reg["exits"]), 1)
            self.assertEqual(reg["exits"][0]["uuid"], "legacy-uuid")


class TestMihomoConfig(unittest.TestCase):
    """Генератор mihomo/Clash Meta YAML."""

    @classmethod
    def setUpClass(cls):
        _setup_core()
        cls._tmpdir = Path(tempfile.mkdtemp())
        cls._state_file = cls._tmpdir / "state.json"
        cls._sub_conf = cls._tmpdir / "subscription.json"
        cls._mirrors = cls._tmpdir / "entry_mirrors.json"
        from chimera.modules import subscription_multinode as mn
        cls._mn = mn

    def _build(self, state):
        self._state_file.write_text(json.dumps(state))
        self._sub_conf.write_text(json.dumps({}))
        self._mirrors.write_text(json.dumps({"mirrors": []}))
        with patch.object(self._mn, "_STATE_FILE", self._state_file), \
             patch.object(self._mn, "_SUB_CONF", self._sub_conf), \
             patch.object(self._mn, "_MIRRORS_FILE", self._mirrors), \
             patch.object(self._mn, "_geo_lookup", return_value=""):
            return self._mn.build_mihomo_config(_TEST_USER)

    def test_mode_b_full_structure(self):
        cfg = self._build(_TEST_STATE_MODE_B)
        self.assertTrue(cfg)
        # Все ключевые секции эталонного конфига
        for section in ("profile:", "dns:", "tun:", "sniffer:", "proxies:",
                        "proxy-groups:", "rules:", "rule-providers:",
                        "geox-url:"):
            self.assertIn(section, cfg, f"missing section: {section}")
        # Группы эталона v9 (16: + RU-Auto, YouTube, авто-подгруппы)
        for group in ('"📍 Выбор ноды"', '"Proxy"', '"Auto"', '"Fallback"',
                      '"Balance-RR"', '"Balance-Hash"', '"Balance-Sticky"',
                      '"Balance-Weighted"', '"🇷🇺 RU-Auto"', '"YouTube"',
                      '"Streaming"', '"Streaming-Auto"', '"Telegram"',
                      '"Telegram-Auto"', '"AI"', '"AI-Auto"'):
            self.assertIn(group, cfg, f"missing group: {group}")
        # Ноды: 2 exit + entry
        self.assertIn("exit-uuid-1", cfg)
        self.assertIn("exit-uuid-2", cfg)
        self.assertIn(_TEST_USER["uuid"], cfg)
        # Reality-параметры exit-нод
        self.assertIn("exit_pbk_1", cfg)
        # RU-сплит и финальное правило
        self.assertIn("GEOIP,RU,DIRECT", cfg)
        self.assertIn("- MATCH,Proxy", cfg)
        self.assertIn("RULE-SET,ru-ripe-subnets,DIRECT", cfg)
        # QUIC-block YouTube
        self.assertIn("(DOMAIN-SUFFIX,googlevideo.com),(NETWORK,udp),(DST-PORT,443)", cfg)
        # Домены нод в DNS-фильтре
        self.assertIn("+.exit1.example.com", cfg)
        self.assertIn("+.entry.test.online", cfg)

        # ── Эталон v9: полный отказ от .dat ──
        self.assertIn("geodata-mode: false", cfg)
        self.assertNotIn("geodata-mode: true", cfg)
        self.assertNotIn("global-client-fingerprint", cfg)
        self.assertIn("etag-support: true", cfg)
        self.assertIn("find-process-mode: off", cfg)
        # mrs-провайдеры и rule-set-ссылки вместо GEOSITE/GEOIP
        self.assertIn("RULE-SET,category-ads-all,REJECT", cfg)
        self.assertIn('"rule-set:category-ads-all"', cfg)
        self.assertIn('"rule-set:cn-domains"', cfg)
        self.assertIn("category-ads-all.mrs", cfg)
        self.assertIn("RULE-SET,cncidr,DIRECT", cfg)
        self.assertIn("private.mrs", cfg)  # private.txt → mrs (без warnings)
        # .dat-эпоха в реальных правилах отсутствует
        rule_lines = [l for l in cfg.splitlines()
                      if l.strip().startswith("- ") and not l.lstrip().startswith("#")]
        for stale in ("GEOSITE,", "GEOIP,LAN", "GEOIP,CN"):
            self.assertFalse(any(stale in l for l in rule_lines),
                             f"stale rule {stale} в v9-конфиге")
        # ASN-рулинг (GeoLite2-ASN.mmdb)
        self.assertIn("IP-ASN,15169,YouTube", cfg)
        self.assertIn("IP-ASN,62041,Telegram", cfg)
        # Глобальный QUIC-блок перед MATCH
        self.assertIn("- AND,((NETWORK,udp),(DST-PORT,443)),REJECT", cfg)

        # ── Дашборд (эталон v9): zashboard + per-user secret ──
        self.assertIn("external-controller: 127.0.0.1:9097", cfg)
        self.assertIn("external-ui-name: zashboard", cfg)

        # ── DNS: AGH-эшелоны + Яндекс-бутстрап + loopback-listen ──
        self.assertIn("listen: 127.0.0.1:1053", cfg)
        self.assertIn("https://cdn.example:30443/dns-query", cfg)
        self.assertIn("https://dns.quad9.net/dns-query", cfg)
        self.assertIn("https://dns.adguard-dns.com/dns-query", cfg)
        self.assertIn("https://dns.yandex.ru/dns-query", cfg)
        self.assertIn("77.88.8.8", cfg)
        self.assertIn("geoip: false", cfg)  # fallback-filter v6

        # ── Защита доменов: exit → Proxy, RU-entry → DIRECT (hairpin-фикс v2) ──
        self.assertIn("DOMAIN-SUFFIX,exit1.example.com,Proxy", cfg)
        self.assertIn("DOMAIN-SUFFIX,entry.test.online,DIRECT", cfg)
        # jsdelivr-качалки → первая exit-нода (урок [Provider] EOF)
        self.assertIn("DOMAIN-SUFFIX,jsdelivr.net,", cfg)

        # Telegram: RU-каскад первым в группе (урок PL из эталона v8)
        self.assertIn(
            '- name: "Telegram"\n    type: select\n    proxies:\n      - "🇷🇺 RU-Auto"',
            cfg)

    def test_dashboard_secret_stable_per_user(self):
        """Secret дашборда детерминирован из UUID: одинаков между
        генерациями (не ломает ссылки панели при refresh подписки)."""
        import re as _re
        cfg1 = self._build(_TEST_STATE_MODE_B)
        cfg2 = self._build(_TEST_STATE_MODE_B)
        s1 = _re.findall(r'secret: "([0-9a-f]{16})"', cfg1)
        s2 = _re.findall(r'secret: "([0-9a-f]{16})"', cfg2)
        self.assertEqual(len(s1), 1)
        self.assertEqual(s1, s2)
        # не хардкод секрета эталона в генератор
        self.assertNotEqual(s1[0], "0f1e2d3c00000008")

    def test_yaml_sanity_quotes_and_indents(self):
        cfg = self._build(_TEST_STATE_MODE_B)
        lines = [l for l in cfg.splitlines()]
        # Сбалансированность двойных кавычек в каждой строке
        for i, line in enumerate(lines):
            if line.strip() and not line.strip().startswith("#"):
                self.assertEqual(
                    line.count('"') % 2, 0,
                    f"unbalanced quotes line {i}: {line}")
        # Каждый proxy name встречается и в proxies, и в группе Proxy
        import re
        names = re.findall(r'- name: "([^"]+)"\n    type: vless', cfg)
        self.assertEqual(len(names), 3)  # 2 exit + entry

    def test_mode_a_simplified(self):
        cfg = self._build(_TEST_STATE_MODE_A)
        self.assertTrue(cfg)
        self.assertIn('"Proxy"', cfg)
        self.assertNotIn('"Auto"', cfg)      # нет exit → нет авто-групп
        self.assertNotIn('"Balance-RR"', cfg)
        self.assertIn(_TEST_USER["uuid"], cfg)

    def test_no_nodes_returns_empty(self):
        cfg = self._build({"domain": "", "install_mode": "B"})
        self.assertEqual(cfg, "")


class TestSingboxConfig(unittest.TestCase):
    """Генератор мульти-нодового sing-box JSON."""

    @classmethod
    def setUpClass(cls):
        _setup_core()
        cls._tmpdir = Path(tempfile.mkdtemp())
        cls._state_file = cls._tmpdir / "state.json"
        cls._sub_conf = cls._tmpdir / "subscription.json"
        cls._mirrors = cls._tmpdir / "entry_mirrors.json"
        from chimera.modules import subscription_multinode as mn
        cls._mn = mn

    def _build(self, state, extra=None):
        self._state_file.write_text(json.dumps(state))
        self._sub_conf.write_text(json.dumps({}))
        self._mirrors.write_text(json.dumps({"mirrors": []}))
        with patch.object(self._mn, "_STATE_FILE", self._state_file), \
             patch.object(self._mn, "_SUB_CONF", self._sub_conf), \
             patch.object(self._mn, "_MIRRORS_FILE", self._mirrors), \
             patch.object(self._mn, "_geo_lookup", return_value=""):
            return self._mn.build_singbox_config(_TEST_USER, extra_outbounds=extra)

    def test_selector_and_urltest(self):
        raw = self._build(_TEST_STATE_MODE_B)
        cfg = json.loads(raw)
        tags = [ob.get("tag") for ob in cfg["outbounds"]]
        selector = next(ob for ob in cfg["outbounds"] if ob["type"] == "selector")
        urltest = next(ob for ob in cfg["outbounds"] if ob["type"] == "urltest")
        self.assertEqual(selector["tag"], self._mn.SELECTOR_TAG)
        self.assertEqual(urltest["tag"], "auto")
        # В селекторе: все ноды + auto
        self.assertIn("auto", selector["outbounds"])
        self.assertGreaterEqual(len(selector["outbounds"]), 4)
        # route.final → selector
        self.assertEqual(cfg["route"]["final"], self._mn.SELECTOR_TAG)
        # Все ноды как vless outbounds
        vless_obs = [ob for ob in cfg["outbounds"] if ob["type"] == "vless"]
        self.assertEqual(len(vless_obs), 3)
        # Служебные outbound'ы: direct — есть; block/dns-out УДАЛЕНЫ (v69:
        # legacy special outbounds = FATAL на старте sing-box 1.12.25+;
        # их роль выполняют route-actions reject/hijack-dns).
        self.assertIn("direct", tags)
        self.assertNotIn("block", tags)
        self.assertNotIn("dns-out", tags)
        # Reality у exit-нод
        exit1 = next(ob for ob in vless_obs if ob.get("uuid") == "exit-uuid-1")
        self.assertTrue(exit1["tls"]["reality"]["enabled"])
        self.assertEqual(exit1["tls"]["reality"]["public_key"], "exit_pbk_1")

    def test_extra_outbounds_in_selector(self):
        extra = [{"type": "trojan", "tag": "trojan-sat", "server": "x",
                  "server_port": 443, "password": "p"},
                 {"type": "direct", "tag": "direct"}]  # служебный — отфильтровать
        raw = self._build(_TEST_STATE_MODE_B, extra=extra)
        cfg = json.loads(raw)
        selector = next(ob for ob in cfg["outbounds"] if ob["type"] == "selector")
        self.assertIn("trojan-sat", selector["outbounds"])
        # direct не дублируется в селекторе (служебный отфильтрован)
        self.assertEqual(selector["outbounds"].count("direct"), 0)
        tags = [ob.get("tag") for ob in cfg["outbounds"]]
        self.assertEqual(tags.count("trojan-sat"), 1)

    def test_no_nodes_returns_empty(self):
        raw = self._build({"domain": ""})
        self.assertEqual(raw, "")


class TestMultinodeUris(unittest.TestCase):
    """vless:// exit-нод для base64-подписки."""

    @classmethod
    def setUpClass(cls):
        _setup_core()
        cls._tmpdir = Path(tempfile.mkdtemp())
        cls._state_file = cls._tmpdir / "state.json"
        cls._sub_conf = cls._tmpdir / "subscription.json"
        cls._mirrors = cls._tmpdir / "entry_mirrors.json"
        from chimera.modules import subscription_multinode as mn
        cls._mn = mn

    def test_uris_for_exits(self):
        self._state_file.write_text(json.dumps(_TEST_STATE_MODE_B))
        self._sub_conf.write_text(json.dumps({}))
        self._mirrors.write_text(json.dumps({"mirrors": []}))
        with patch.object(self._mn, "_STATE_FILE", self._state_file), \
             patch.object(self._mn, "_SUB_CONF", self._sub_conf), \
             patch.object(self._mn, "_MIRRORS_FILE", self._mirrors), \
             patch.object(self._mn, "_geo_lookup", return_value=""), \
             patch.object(self._mn, "_core_call",
                          side_effect=lambda fn, *a, **k: _fake_vless_link(*a, **k)):
            uris = self._mn.get_multinode_uris(_TEST_USER)
        self.assertEqual(len(uris), 2)
        for u in uris:
            self.assertTrue(u.startswith("vless://"))
            self.assertIn("#", u)  # fragment с именем ноды
        self.assertIn("exit-uuid-1", uris[0])
        self.assertIn("exit-uuid-2", uris[1])

    def test_disabled_returns_empty(self):
        self._state_file.write_text(json.dumps(_TEST_STATE_MODE_A))
        self._sub_conf.write_text(json.dumps({}))
        self._mirrors.write_text(json.dumps({"mirrors": []}))
        with patch.object(self._mn, "_STATE_FILE", self._state_file), \
             patch.object(self._mn, "_SUB_CONF", self._sub_conf), \
             patch.object(self._mn, "_MIRRORS_FILE", self._mirrors):
            uris = self._mn.get_multinode_uris(_TEST_USER)
        self.assertEqual(uris, [])


class TestSubscriptionIntegration(unittest.TestCase):
    """Интеграция с subscription.py: форматы, base64, iOS-исключение."""

    @classmethod
    def setUpClass(cls):
        _setup_core()
        cls._tmpdir = Path(tempfile.mkdtemp())
        cls._state_file = cls._tmpdir / "state.json"
        cls._sub_conf = cls._tmpdir / "subscription.json"
        cls._mirrors = cls._tmpdir / "entry_mirrors.json"
        from chimera.modules import subscription as sub
        from chimera.modules import subscription_multinode as mn
        cls._sub = sub
        cls._mn = mn

    def _patches(self, state, sub_conf=None):
        self._state_file.write_text(json.dumps(state))
        self._sub_conf.write_text(json.dumps(sub_conf or {}))
        self._mirrors.write_text(json.dumps({"mirrors": []}))
        core = sys.modules["chimera._core"]
        return [
            patch.object(self._sub, "_load_state", return_value=dict(state)),
            patch.object(self._sub, "_load_sub_conf",
                         return_value=json.loads(self._sub_conf.read_text())),
            patch.object(self._sub, "_load_all_users",
                         return_value=[_TEST_USER]),
            patch.object(self._sub, "_get_server_ip", return_value="1.1.1.1"),
            patch.object(self._sub, "is_hybrid_mieru_active", return_value=False),
            patch.object(self._sub, "_build_vless_uri",
                         return_value="vless://user-uuid@entry.test.online:443?security=reality"),
            patch.object(self._sub, "_build_mieru_uris", return_value=[]),
            patch.object(self._sub, "_build_naive_uris", return_value=[]),
            patch.object(self._sub, "_build_fptn_uris", return_value=[]),
            patch.object(self._sub, "_build_telemt_uri", return_value=None),
            patch.object(self._sub, "_collect_registry_uris", return_value=[]),
            patch.object(self._sub, "_collect_registry_json_outbounds",
                         return_value=[]),
            patch.object(self._mn, "_STATE_FILE", self._state_file),
            patch.object(self._mn, "_SUB_CONF", self._sub_conf),
            patch.object(self._mn, "_MIRRORS_FILE", self._mirrors),
            patch.object(self._mn, "_geo_lookup", return_value=""),
            patch.object(self._mn, "_core_call",
                         side_effect=lambda fn, *a, **k: _fake_vless_link(*a, **k)),
        ]

    def test_resolve_format_clash(self):
        cases = [
            ("clash", "", "clash"),
            ("mihomo", "", "clash"),
            ("meta", "", "clash"),
            ("", "ClashMeta/1.18.0", "clash"),
            ("", "FlClash/0.8 android", "clash"),
            ("", "mihomo/1.18", "clash"),
            ("", "v2rayNG/1.8", "base64"),
            ("singbox", "", "singbox"),
        ]
        for requested, ua, expected in cases:
            self.assertEqual(
                self._sub._resolve_format(requested, ua), expected,
                f"requested={requested!r} ua={ua!r}")

    def test_base64_body_includes_exit_uris(self):
        ps = self._patches(_TEST_STATE_MODE_B)
        with ps[0], ps[1], ps[2], ps[3], ps[4], ps[5], ps[6], ps[7], \
             ps[8], ps[9], ps[10], ps[11], ps[12], ps[13], ps[14], ps[15], ps[16]:
            body = self._sub.build_subscription_body(_TEST_USER)
        decoded = base64.b64decode(body).decode("utf-8")
        links = decoded.split("\n")
        vless_links = [l for l in links if l.startswith("vless://")]
        self.assertEqual(len(vless_links), 3)  # entry + 2 exit
        self.assertIn("exit-uuid-1", decoded)
        self.assertIn("exit-uuid-2", decoded)

    def test_ios_body_excludes_exit_uris(self):
        ps = self._patches(_TEST_STATE_MODE_B)
        # _resolve_ios_shadow_user читает реальный config.json Xray — в стене
        # его нет, подменяем на identity-функцию (та же семантика fallback).
        ps_shadow = patch.object(
            self._sub, "_resolve_ios_shadow_user",
            side_effect=lambda u: u)
        with ps[0], ps[1], ps[2], ps[3], ps[4], ps[5], ps[6], ps[7], \
             ps[8], ps[9], ps[10], ps[11], ps[12], ps[13], ps[14], ps[15], ps[16], \
             ps_shadow:
            body = self._sub.build_subscription_body_ios(_TEST_USER)
        decoded = base64.b64decode(body).decode("utf-8")
        self.assertNotIn("exit-uuid-1", decoded)
        self.assertNotIn("exit-uuid-2", decoded)

    def test_base64_body_mode_a_no_exit_uris(self):
        ps = self._patches(_TEST_STATE_MODE_A)
        with ps[0], ps[1], ps[2], ps[3], ps[4], ps[5], ps[6], ps[7], \
             ps[8], ps[9], ps[10], ps[11], ps[12], ps[13], ps[14], ps[15], ps[16]:
            body = self._sub.build_subscription_body(_TEST_USER)
        decoded = base64.b64decode(body).decode("utf-8")
        vless_links = [l for l in decoded.split("\n") if l.startswith("vless://")]
        self.assertEqual(len(vless_links), 1)  # только entry

    def test_multinode_disabled_by_explicit_conf(self):
        ps = self._patches(
            _TEST_STATE_MODE_B,
            sub_conf={"multinode": {"enabled": False}})
        with ps[0], ps[1], ps[2], ps[3], ps[4], ps[5], ps[6], ps[7], \
             ps[8], ps[9], ps[10], ps[11], ps[12], ps[13], ps[14], ps[15], ps[16]:
            body = self._sub.build_subscription_body(_TEST_USER)
        decoded = base64.b64decode(body).decode("utf-8")
        self.assertNotIn("exit-uuid-1", decoded)


class TestSubscriptionHttpE2E(unittest.TestCase):
    """HTTP-тесты ?format=clash / ?format=singbox через реальный сервер."""

    @classmethod
    def setUpClass(cls):
        _setup_core()
        cls._tmpdir = Path(tempfile.mkdtemp())
        cls._state_file = cls._tmpdir / "state.json"
        cls._sub_conf = cls._tmpdir / "subscription.json"
        cls._mirrors = cls._tmpdir / "entry_mirrors.json"
        from chimera.modules import subscription as sub
        from chimera.modules import subscription_multinode as mn
        cls._sub = sub
        cls._mn = mn
        # Токен для тестового юзера
        import hashlib, hmac, secrets
        pepper = "multinode_test_pepper"
        token = hmac.new(pepper.encode(), _TEST_USER["uuid"].encode(),
                         hashlib.sha256).hexdigest()[:24]
        cls._token = token
        cls._pepper = pepper

    def _start_server(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), self._sub._SubHandler)
        port = server.server_address[1]
        import threading
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, port, thread

    def _get(self, port, path, headers=None):
        from urllib.request import urlopen, Request
        from urllib.error import HTTPError
        req = Request(f"http://127.0.0.1:{port}{path}")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urlopen(req, timeout=10) as resp:
                return resp.status, resp.headers.get("Content-Type", ""), resp.read()
        except HTTPError as e:
            return e.code, e.headers.get("Content-Type", ""), e.read()

    def test_format_clash_and_singbox(self):
        self._state_file.write_text(json.dumps(_TEST_STATE_MODE_B))
        self._sub_conf.write_text(json.dumps({
            "pepper": self._pepper, "enabled": True,
            "listen_port": 0, "identity_map": {},
        }))
        self._mirrors.write_text(json.dumps({"mirrors": []}))

        patches = [
            patch.object(self._sub, "_load_state",
                         return_value=dict(_TEST_STATE_MODE_B)),
            patch.object(self._sub, "_load_sub_conf",
                         return_value=json.loads(self._sub_conf.read_text())),
            patch.object(self._sub, "_load_all_users",
                         return_value=[_TEST_USER]),
            patch.object(self._sub, "_get_server_ip", return_value="1.1.1.1"),
            patch.object(self._sub, "_build_vless_uri",
                         return_value="vless://user-uuid@entry.test.online:443?security=reality"),
            patch.object(self._sub, "_build_mieru_uris", return_value=[]),
            patch.object(self._sub, "_build_naive_uris", return_value=[]),
            patch.object(self._sub, "_build_fptn_uris", return_value=[]),
            patch.object(self._sub, "_build_telemt_uri", return_value=None),
            patch.object(self._sub, "_collect_registry_uris", return_value=[]),
            patch.object(self._sub, "_collect_registry_json_outbounds",
                         return_value=[]),
            patch.object(self._sub, "_build_userinfo_header", return_value=None),
            patch.object(self._mn, "_STATE_FILE", self._state_file),
            patch.object(self._mn, "_SUB_CONF", self._sub_conf),
            patch.object(self._mn, "_MIRRORS_FILE", self._mirrors),
            patch.object(self._mn, "_geo_lookup", return_value=""),
            patch.object(self._mn, "_core_call",
                         side_effect=lambda fn, *a, **k: _fake_vless_link(*a, **k)),
        ]
        server, port, thread = self._start_server()
        try:
            with patches[0], patches[1], patches[2], patches[3], patches[4], \
                 patches[5], patches[6], patches[7], patches[8], patches[9], \
                 patches[10], patches[11], patches[12], patches[13], patches[14], \
                 patches[15], patches[16]:
                # ?format=clash
                status, ctype, body = self._get(
                    port, f"/sub/{self._token}?format=clash")
                self.assertEqual(status, 200)
                self.assertIn("text/yaml", ctype)
                text = body.decode("utf-8")
                self.assertIn("proxy-groups:", text)
                self.assertIn('"📍 Выбор ноды"', text)
                self.assertIn("exit-uuid-1", text)

                # ?format=singbox — мульти-нодовый JSON
                status, ctype, body = self._get(
                    port, f"/sub/{self._token}?format=singbox")
                self.assertEqual(status, 200)
                self.assertIn("application/json", ctype)
                cfg = json.loads(body.decode("utf-8"))
                selector = next(ob for ob in cfg["outbounds"]
                                if ob["type"] == "selector")
                self.assertEqual(cfg["route"]["final"], selector["tag"])

                # UA-эвристика: ClashMeta → clash
                status, ctype, body = self._get(
                    port, f"/sub/{self._token}",
                    headers={"User-Agent": "ClashMeta/1.18.0"})
                self.assertEqual(status, 200)
                self.assertIn("text/yaml", ctype)

                # Дефолт — base64 (обратная совместимость)
                status, ctype, body = self._get(
                    port, f"/sub/{self._token}",
                    headers={"User-Agent": "v2rayNG/1.8.0"})
                self.assertEqual(status, 200)
                self.assertIn("text/plain", ctype)
                decoded = base64.b64decode(body).decode("utf-8")
                self.assertIn("exit-uuid-1", decoded)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


class TestPortalHelpers(unittest.TestCase):
    """get_portal_subscription_info / get_admin_subscription_info."""

    @classmethod
    def setUpClass(cls):
        _setup_core()
        cls._tmpdir = Path(tempfile.mkdtemp())
        cls._state_file = cls._tmpdir / "state.json"
        cls._sub_conf = cls._tmpdir / "subscription.json"
        cls._mirrors = cls._tmpdir / "entry_mirrors.json"
        cls._nginx_state = cls._tmpdir / "sub_nginx.json"
        from chimera.modules import subscription as sub
        from chimera.modules import subscription_multinode as mn
        cls._sub = sub
        cls._mn = mn

    def test_portal_info(self):
        import hashlib, hmac
        self._state_file.write_text(json.dumps(_TEST_STATE_MODE_B))
        pepper = "portal_pepper"
        self._sub_conf.write_text(json.dumps({
            "pepper": pepper, "enabled": True, "listen_port": 8443,
        }))
        self._mirrors.write_text(json.dumps({"mirrors": []}))
        token = hmac.new(pepper.encode(), _TEST_USER["uuid"].encode(),
                         hashlib.sha256).hexdigest()[:24]
        with patch.object(self._sub, "_STATE_FILE", self._state_file), \
             patch.object(self._sub, "_SUB_CONF", self._sub_conf), \
             patch.object(self._sub, "_load_state",
                          return_value=dict(_TEST_STATE_MODE_B)), \
             patch.object(self._sub, "_load_sub_conf",
                          return_value=json.loads(self._sub_conf.read_text())), \
             patch.object(self._sub, "_sub_nginx_status",
                          return_value={"enabled": False}), \
             patch.object(self._sub, "_get_server_ip", return_value="1.1.1.1"), \
             patch.object(self._sub, "_load_all_users",
                          return_value=[_TEST_USER]), \
             patch.object(self._mn, "_STATE_FILE", self._state_file), \
             patch.object(self._mn, "_SUB_CONF", self._sub_conf), \
             patch.object(self._mn, "_MIRRORS_FILE", self._mirrors), \
             patch.object(self._mn, "_geo_lookup", return_value=""):
            info = self._sub.get_portal_subscription_info(_TEST_USER)
        self.assertTrue(info["service_enabled"])
        self.assertEqual(info["base_url"], "https://entry.test.online:8443/sub")
        self.assertEqual(info["urls"]["base64"],
                         f"https://entry.test.online:8443/sub/{token}")
        self.assertIn("format=clash", info["urls"]["clash"])
        self.assertTrue(info["multinode"]["enabled"])
        self.assertEqual(len(info["multinode"]["nodes"]), 3)

    def test_admin_info(self):
        self._state_file.write_text(json.dumps(_TEST_STATE_MODE_B))
        self._sub_conf.write_text(json.dumps({"enabled": False}))
        self._mirrors.write_text(json.dumps({"mirrors": []}))
        with patch.object(self._sub, "_STATE_FILE", self._state_file), \
             patch.object(self._sub, "_SUB_CONF", self._sub_conf), \
             patch.object(self._sub, "_load_state",
                          return_value=dict(_TEST_STATE_MODE_B)), \
             patch.object(self._sub, "_load_sub_conf",
                          return_value=json.loads(self._sub_conf.read_text())), \
             patch.object(self._sub, "_sub_nginx_status",
                          return_value={"enabled": False}), \
             patch.object(self._sub, "_get_server_ip", return_value="1.1.1.1"), \
             patch.object(self._sub, "_load_all_users",
                          return_value=[_TEST_USER]), \
             patch.object(self._mn, "_STATE_FILE", self._state_file), \
             patch.object(self._mn, "_SUB_CONF", self._sub_conf), \
             patch.object(self._mn, "_MIRRORS_FILE", self._mirrors), \
             patch.object(self._mn, "_geo_lookup", return_value=""):
            info = self._sub.get_admin_subscription_info()
        self.assertFalse(info["service_enabled"])
        self.assertEqual(info["users"], [])  # выключена → без URL
        self.assertTrue(info["multinode"]["enabled"])  # статус фичи всё равно показываем


if __name__ == "__main__":
    unittest.main(verbosity=2)
