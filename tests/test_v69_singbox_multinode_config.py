#!/usr/bin/env python3
"""v69: регресс-тесты клиентского sing-box-конфига мульти-ноды (Режим B).

Первопричина инцидента «каскад не работает НИЧЕГО»: build_singbox_config()
генерировал конфиг, который НЕ ЗАПУСКАЛСЯ на актуальных sing-box:
  • legacy special outbounds (block/dns) — FATAL с 1.12.25+
  • легаси dns.fakeip.* — FATAL с 1.13+
  • легаси DNS-правило outbound:any — FATAL с 1.13+
  • detour у local-dns к пустому direct-outbound — FATAL на старте 1.13+
  • rule-set'ы geosite-ru / geoip-telegram / geoip-private — HTTP 404 (файлов
    не существует) — загрузка на старте падает, клиент мёртв
  • selector default = первый EXIT (из РФ недоступен) — весь трафик и DNS
    (detour remote-dns через selector) в i/o timeout
  • local-dns = AliDNS 223.5.5.5 (Китай) — таймауты из РФ

E2E-верификация: scripts/sim_mode_b_e2e.py (реальные бинарники Xray + sing-box
1.13.19, каскад клиент→entry→exit→интернет, delay-тест 35ms).
"""
import json
import sys
import unittest
import uuid as uuid_mod
from pathlib import Path
from unittest.mock import patch

PROJECT = Path("/home/z/my-project/chimera-latest")
sys.path.insert(0, str(PROJECT))


def _make_module():
    """Загружает subscription_multinode с фейковым _core (как тесты проекта)."""
    core_path = PROJECT / "chimera" / "_core.py"
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
    from chimera.modules import subscription_multinode as sm
    return sm, fake_core


USER_UUID = str(uuid_mod.uuid4())
EXIT_UUID = str(uuid_mod.uuid4())

STATE = {
    "install_mode": "B",
    "protocol_mode": "reality",
    "domain": "chimeraprodcdn.online",
    "server_port": 443,
    "public_key": "lVYClK-9CQnAfHvBPDUnAzfINyoyQ1ZxQtdiNuPE-zg",
    "short_id": "abcd1234",
    "xtls_flow": "xtls-rprx-vision",
    "fingerprint": "chrome",
    "awg_exit_enabled": False,
    "chain_nodes": [{
        "host": "45.136.223.10", "port": 443,
        "uuid": EXIT_UUID,
        "pubkey": "nhoMmkj4w_ncoYWahbhcXPEcyJfMhaEJq_TbT79gBFo",
        "shortid": "feedabcd",
        "sni": "cdn.jsdelivr.net", "fp": "chrome", "proto": "reality",
        "label": "NL-Exit-1",
    }],
}


class TestV69SingboxMultinodeConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sm, cls.fake_core = _make_module()
        cls.sm._load_state = lambda: dict(STATE)
        cls.sm._geo_lookup = lambda host: "NL"
        raw = cls.sm.build_singbox_config({"uuid": USER_UUID, "name": "t"})
        assert raw, "build_singbox_config вернул ''"
        cls.cfg = json.loads(raw)
        cls.ob_types = {o["tag"]: o["type"] for o in cls.cfg["outbounds"]}

    # ── 1. Легаси-конструкции, валившие старт sing-box ─────────────────────

    def test_no_legacy_special_outbounds(self):
        """block/dns outbounds выпилены (FATAL на 1.12.25+)."""
        self.assertNotIn("block", self.ob_types.values())
        self.assertNotIn("dns", self.ob_types.values())

    def test_no_legacy_fakeip_block(self):
        """Легаси dns.fakeip.* убран; диапазоны внутри сервера fakeip."""
        self.assertNotIn("fakeip", self.cfg["dns"])
        fp = [s for s in self.cfg["dns"]["servers"] if s["type"] == "fakeip"]
        self.assertEqual(len(fp), 1)
        self.assertEqual(fp[0]["inet4_range"], "198.18.0.0/15")
        self.assertEqual(fp[0]["inet6_range"], "fc00::/18")

    def test_no_deprecated_outbound_dns_rule(self):
        """Легаси-правило outbound:any выпилено (FATAL на 1.13+)."""
        for r in self.cfg["dns"]["rules"]:
            self.assertNotIn("outbound", r,
                             f"deprecated outbound-правило: {r}")

    def test_local_dns_no_detour(self):
        """detour к пустому direct-outbound у local-dns — FATAL на старте."""
        ld = [s for s in self.cfg["dns"]["servers"]
              if s.get("tag") == "local-dns"][0]
        self.assertNotIn("detour", ld)

    def test_route_default_domain_resolver(self):
        """route.default_domain_resolver задан (требование 1.12+)."""
        self.assertEqual(self.cfg["route"].get("default_domain_resolver"),
                         "local-dns")

    # ── 2. Rule-set'ы: существующие URL ────────────────────────────────────

    def test_ruleset_no_download_detour(self):
        for rs in self.cfg["route"]["rule_set"]:
            self.assertNotIn("download_detour", rs)

    def test_ruleset_tags_no_dead_names(self):
        tags = [rs["tag"] for rs in self.cfg["route"]["rule_set"]]
        self.assertNotIn("geosite-ru", tags)          # 404 в sing-geosite
        self.assertIn("geosite-category-ru", tags)

    def test_ruleset_urls_alive(self):
        """geoip-telegram/private — только в MetaCubeX (в sing-geoip их нет)."""
        urls = {rs["tag"]: rs["url"] for rs in self.cfg["route"]["rule_set"]}
        self.assertIn("MetaCubeX/meta-rules-dat", urls["geoip-telegram"])
        self.assertIn("MetaCubeX/meta-rules-dat", urls["geoip-private"])
        self.assertIn("SagerNet/sing-geoip@rule-set/geoip-ru.srs",
                      urls["geoip-ru"])
        self.assertIn("geosite-category-ru.srs", urls["geosite-category-ru"])
        # правила ссылаются только на объявленные rule_set-теги
        declared = set(tags for tags in urls)
        for r in self.cfg["route"]["rules"]:
            for rs in ([r["rule_set"]] if isinstance(r.get("rule_set"), str)
                       else r.get("rule_set", [])):
                self.assertIn(rs, declared)

    # ── 3. Каскадная маршрутизация ─────────────────────────────────────────

    def test_selector_default_is_entry(self):
        """Default селектора — ENTRY-каскад, а не первый exit (из РФ exit
        недоступен напрямую — дефолт «первый exit» валил весь трафик и DNS)."""
        sel = [o for o in self.cfg["outbounds"]
               if o.get("type") == "selector"
               and o["tag"] == "🎯 Chimera"][0]
        vless = [o for o in self.cfg["outbounds"] if o.get("type") == "vless"]
        entry_tags = [o["tag"] for o in vless
                      if o["server"] == STATE["domain"]]
        self.assertEqual(len(entry_tags), 1)
        self.assertEqual(sel["default"], entry_tags[0])

    def test_groups_include_entry(self):
        """Streaming/Telegram/AI: entry в группе и является default."""
        vless = [o for o in self.cfg["outbounds"] if o.get("type") == "vless"]
        entry_tag = [o["tag"] for o in vless
                     if o["server"] == STATE["domain"]][0]
        for tag in ("🎬 Streaming", "✈️ Telegram", "🤖 AI"):
            grp = [o for o in self.cfg["outbounds"]
                   if o.get("tag") == tag][0]
            self.assertIn(entry_tag, grp["outbounds"], f"{tag}: нет entry")
            self.assertEqual(grp["default"], entry_tag)

    # ── 4. DNS для РФ ──────────────────────────────────────────────────────

    def test_local_dns_is_yandex_not_alidns(self):
        ld = [s for s in self.cfg["dns"]["servers"]
              if s.get("tag") == "local-dns"][0]
        self.assertEqual(ld["server"], "77.88.8.8")

    def test_node_domains_guarded_from_fakeip(self):
        """Домены нод идут на реальный DNS ДО правила fakeip (иначе петля)."""
        rules = self.cfg["dns"]["rules"]
        guard = rules[0]
        self.assertEqual(guard.get("server"), "local-dns")
        self.assertIn("domain_suffix", guard)
        self.assertIn(STATE["domain"], guard["domain_suffix"])
        fakeip_rules = [i for i, r in enumerate(rules)
                        if r.get("server") == "fakeip-dns"]
        for i in fakeip_rules:
            self.assertGreater(i, 0)

    def test_vless_domain_outbounds_have_resolver(self):
        """Ноды с доменным адресом обязаны иметь domain_resolver (1.12+)."""
        for o in self.cfg["outbounds"]:
            if o.get("type") == "vless":
                srv = o.get("server", "")
                if srv and not srv[0].isdigit():
                    self.assertEqual(o.get("domain_resolver"), "local-dns",
                                     f"{o['tag']}: нет domain_resolver")

    # ── 5. TUN ─────────────────────────────────────────────────────────────

    def test_strict_route_disabled(self):
        """strict_route=False: WFP-правила на Windows рвут собственные dial
        sing-box (симптом: dial tcp <entry>:443 i/o timeout)."""
        tun = self.cfg["inbounds"][0]
        self.assertEqual(tun["type"], "tun")
        self.assertFalse(tun.get("strict_route"))
        self.assertTrue(tun.get("auto_route"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
