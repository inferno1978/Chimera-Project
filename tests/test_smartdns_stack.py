#!/usr/bin/env python3
"""
tests/test_smartdns_stack.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/smartdns_stack.py — компонентного слоя
SmartDNS-ноды (Python-порт bash-установщика smartdns-installer v3.0.0).

Покрывает:
  1. build_xray_base_config — bind по режиму (companion → второй IP,
     standalone → wildcard); dokodemo 8444/853 → loopback-терминаторы.
  2. build_routing_rules — порядок правил (dot-in → block; наши домены →
     nginx-local; GeoHide → direct-v4; private → block; fallback).
  3. nginx: full-конфиг (default_server) vs drop-in (bind_ip, БЕЗ
     default_server — сосуществование с vhost'ами Химеры в одном nginx);
     неймспейс smartdns_ для map/limit_req (нет коллизий с Химерой);
     секретные location'ы /auth/<SECRET> и /resolve/<SECRET>.
  4. ensure_stream_include — идемпотентный stream-хук (нет stream{} →
     добавить; есть без include → вставить; уже есть → no-op).
  5. parse_geohide_hosts — паритет awk-конвейера bash: нормализация,
     безусловные исключения (captive-portal/x.com), опции Google/Xbox,
     custom-allow/deny, generativelanguage всегда в списке.
  6. render_engine_domain_lists — hosts-файл + AGH dnsrewrite-правила.
  7. render_oxidns_config / render_agh_config — loopback 5353/8053,
     TLS off (терминация стека, не AGH).
  8. generate_cover_site — детерминизм по seed, различие между seed'ами.
  9. version_key — semver + release > pre-release (канон dpi_bypass).
  10. resolve_component_versions — фолбэк-теги без сети; oxidns только
      x86_64.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import smartdns_stack as st  # noqa: E402

CFG_COMPANION = {
    "mode": "companion", "bind_ip": "203.0.113.7",
    "engine": "oxidns", "domain": "example.com",
    "dot_host": "dot.example.com", "doh_path": "S" * 52,
    "server_ipv4": "203.0.113.7",
}
CFG_STANDALONE = {
    "mode": "standalone", "bind_ip": None, "engine": "oxidns",
    "domain": "example.com", "dot_host": "dot.example.com",
    "doh_path": "S" * 52, "server_ipv4": "198.51.100.2",
}


class TestXrayConfig(unittest.TestCase):
    def test_bind_companion_second_ip(self):
        cfg = st.build_xray_base_config(CFG_COMPANION)
        for ib in cfg["inbounds"]:
            self.assertEqual(ib["listen"], "203.0.113.7")

    def test_bind_standalone_wildcard(self):
        cfg = st.build_xray_base_config(CFG_STANDALONE)
        for ib in cfg["inbounds"]:
            self.assertEqual(ib["listen"], "0.0.0.0")

    def test_dokodemo_targets_loopback(self):
        cfg = st.build_xray_base_config(CFG_COMPANION)
        https_in, dot_in = cfg["inbounds"]
        self.assertEqual(https_in["port"], st.PORT_DOH)
        self.assertEqual(dot_in["port"], st.PORT_DOT)
        self.assertEqual(dot_in["settings"]["port"], st.PORT_DOTHERM)
        self.assertEqual(cfg["outbounds"][1]["settings"]["redirect"],
                         f"127.0.0.1:{st.PORT_STEALTH}")

    def test_routing_rules_order(self):
        r = st.build_routing_rules("example.com", "dot.example.com",
                                   ["a.com", "b.com"], "1.2.3.4")
        rules = r["routing"]["rules"]
        self.assertEqual(rules[0]["outboundTag"], "dot-backend")
        self.assertEqual(rules[1]["outboundTag"], "block")       # dot: прочее
        self.assertEqual(rules[2]["outboundTag"], "nginx-local")  # наши домены
        self.assertEqual(rules[3]["domain"], ["domain:a.com", "domain:b.com"])
        self.assertEqual(rules[3]["outboundTag"], "direct-v4")   # GeoHide
        self.assertIn("1.2.3.4", rules[4]["ip"])
        self.assertEqual(rules[-1]["outboundTag"], "nginx-local")  # fallback

    def test_routing_rules_ipv6_added(self):
        r = st.build_routing_rules("d.com", "dot.d.com", [], "1.2.3.4",
                                   "2001:db8::1")
        self.assertIn("2001:db8::1", r["routing"]["rules"][4]["ip"])


class TestNginx(unittest.TestCase):
    def test_full_conf_default_server(self):
        full = st._nginx_server_blocks(CFG_STANDALONE, dropin=False)
        self.assertIn("listen 80 default_server;", full)
        self.assertIn("listen 9443 ssl default_server;", full)
        self.assertIn("listen 127.0.0.1:9444 ssl proxy_protocol;", full)
        self.assertIn("location = /resolve/" + "S" * 52, full)
        self.assertIn("location = /auth/" + "S" * 52, full)

    def test_dropin_bind_ip_no_default_server(self):
        dropin = st._nginx_server_blocks(CFG_COMPANION, dropin=True)
        self.assertIn("listen 203.0.113.7:80;", dropin)
        self.assertIn("listen 203.0.113.7:9443 ssl;", dropin)
        self.assertNotIn("default_server", dropin)   # default — Химеры
        self.assertIn("listen 127.0.0.1:9444 ssl proxy_protocol;", dropin)

    def test_http_directives_namespaced(self):
        d = st._nginx_http_directives()
        for name in ("smartdns_doh_fmt", "smartdns_web_fmt",
                     "smartdns_doh", "smartdns_web", "smartdns_doh_get_ok",
                     "smartdns_web_auth_ok"):
            self.assertIn(name, d)
        # не задаём чужие имена (log http-контекста общий с Химерой)
        self.assertNotIn("doh_ratelimit:", d)
        self.assertNotIn("web_ratelimit:", d)

    def test_stream_dropin_loopback_only(self):
        s = st._nginx_stream_block()
        self.assertIn(f"listen 127.0.0.1:{st.PORT_DOTHERM} ssl;", s)
        self.assertNotIn("0.0.0.0", s)

    def test_ensure_stream_include_adds_block(self):
        t, changed = st.ensure_stream_include("events {}\nhttp {\n}\n")
        self.assertTrue(changed)
        self.assertIn("stream {", t)
        self.assertEqual(t.count("stream-conf.d"), 1)

    def test_ensure_stream_include_injects_into_existing(self):
        base = "events {}\nhttp {\n}\nstream {\n    # comment\n}\n"
        t, changed = st.ensure_stream_include(base)
        self.assertTrue(changed)
        self.assertIn("include /etc/nginx/stream-conf.d/*.conf;", t)
        # http-блок не тронут
        self.assertIn("http {\n}", t)

    def test_ensure_stream_include_idempotent(self):
        once, _ = st.ensure_stream_include("stream {\n}\n")
        twice, changed = st.ensure_stream_include(once)
        self.assertFalse(changed)
        self.assertEqual(once, twice)


class TestGeoHide(unittest.TestCase):
    HOSTS = (
        "# header\n"
        "1.2.3.4 foo.com bar.com\n"
        "*.baz.com\n"
        "qux.ru\n"
        "captive.apple.com\n"
        "connectivitycheck.gstatic.com\n"
        "msftconnecttest.com\n"
        "x.com\n"
        "meta.ai\n"
        "clients4.google.com\n"
        "googleapis.com\n"
        "xboxlive.com\n"
        "bad name!!\n"
    )

    def test_parse_defaults(self):
        doms = st.parse_geohide_hosts(self.HOSTS)
        self.assertIn("foo.com", doms)
        self.assertIn("baz.com", doms)      # *.baz.com → baz.com
        self.assertIn("qux.ru", doms)
        for gone in ("captive.apple.com", "connectivitycheck.gstatic.com",
                     "msftconnecttest.com", "x.com", "meta.ai",
                     "clients4.google.com", "googleapis.com", "xboxlive.com"):
            self.assertNotIn(gone, doms)
        self.assertIn("generativelanguage.googleapis.com", doms)

    def test_parse_google_and_xbox_options(self):
        doms = st.parse_geohide_hosts(self.HOSTS, exclude_google_sys=False,
                                      include_xbox_ipify=True)
        self.assertIn("googleapis.com", doms)
        self.assertIn("xboxlive.com", doms)
        # безусловные исключения остаются
        self.assertNotIn("x.com", doms)

    def test_parse_custom_allow_deny(self):
        doms = st.parse_geohide_hosts(self.HOSTS, custom_allow="my.site.org",
                                      custom_deny="foo.com")
        self.assertIn("my.site.org", doms)
        self.assertNotIn("foo.com", doms)

    def test_render_engine_lists(self):
        arts = st.render_engine_domain_lists(["a.com"], "5.6.7.8")
        self.assertEqual(arts["hosts"].strip(), "domain:a.com 5.6.7.8")
        self.assertIn("||a.com^$dnstype=A,dnsrewrite=NOERROR;A;5.6.7.8",
                      arts["agh_rules"])
        self.assertIn("||a.com^$dnstype=AAAA,dnsrewrite=NOERROR",
                      arts["agh_rules"])
        self.assertIn("||a.com^$dnstype=HTTPS|SVCB,dnsrewrite=NOERROR",
                      arts["agh_rules"])
        self.assertEqual(arts["count"], 1)


class TestEngineConfigs(unittest.TestCase):
    def test_oxidns_loopback_listeners(self):
        cfg = st.render_oxidns_config()
        self.assertIn(f'listen: "127.0.0.1:{st.PORT_ENGINE}"', cfg)
        self.assertIn(f'listen: "127.0.0.1:{st.PORT_DOHLOC}"', cfg)
        self.assertIn("/dns-query", cfg)
        self.assertNotIn("0.0.0.0", cfg)

    def test_agh_tls_off_loopback(self):
        cfg = st.render_agh_config("admin_x", "HASH", "example.com")
        self.assertIn(f"127.0.0.1:{st.PORT_DOHLOC}", cfg)
        self.assertIn(f"  port: {st.PORT_ENGINE}", cfg)
        self.assertIn("enabled: false", cfg)          # TLS терминирует стек
        self.assertIn("ag-smartdns-rules.txt", cfg)


class TestCoverSite(unittest.TestCase):
    def test_deterministic_by_seed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            with patch.object(st, "WEB_ROOT", Path(td)):
                st.generate_cover_site({"domain": "example.com"}, seed=42)
                h1 = (Path(td) / "index.html").read_text()
                st.generate_cover_site({"domain": "example.com"}, seed=42)
                self.assertEqual(h1, (Path(td) / "index.html").read_text())
                st.generate_cover_site({"domain": "example.com"}, seed=7)
                self.assertNotEqual(h1, (Path(td) / "index.html").read_text())

    def test_files_created(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            with patch.object(st, "WEB_ROOT", Path(td)):
                st.generate_cover_site({"domain": "Example.COM"}, seed=1)
                for f in ("index.html", "404.html", "favicon.svg",
                          "assets/style.css"):
                    self.assertTrue((Path(td) / f).exists(), f)
                html = (Path(td) / "index.html").read_text()
                self.assertIn("example.com", html)   # lowercase в контактах


class TestVersionsAndDownloads(unittest.TestCase):
    def test_version_key(self):
        self.assertGreater(st.version_key("v26.11.9"), st.version_key("v26.10.9"))
        self.assertGreater(st.version_key("1.7.1"), st.version_key("1.7.1rc1"))
        self.assertGreater(st.version_key("v0.107.62"), st.version_key("v0.107.61"))
        self.assertGreater(st.version_key("2.0"), st.version_key(""))
        self.assertEqual(st.version_key("v1.2.3"), st.version_key("1.2.3"))

    def test_resolve_versions_offline_fallback(self):
        v = st.resolve_component_versions(arch="x86_64", net_probe=False)
        self.assertEqual(v["xray"], st.XRAY_FALLBACK_TAG)
        self.assertEqual(v["oxidns"], st.OXIDNS_FALLBACK_TAG)
        self.assertEqual(v["agh"], st.AGH_FALLBACK_TAG)

    def test_resolve_versions_oxidns_not_x86(self):
        v = st.resolve_component_versions(arch="aarch64", net_probe=False)
        self.assertEqual(v["oxidns"], "")   # официальные сборки x86_64-only
        self.assertEqual(v["agh"], st.AGH_FALLBACK_TAG)

    def test_release_mirrors_only_release_family(self):
        urls = st._release_mirror_urls("XTLS", "Xray-core", "v1.2.3",
                                       "Xray-linux-64.zip")
        self.assertTrue(any(
            u.endswith("/releases/download/v1.2.3/Xray-linux-64.zip")
            for u in urls))
        # jsDelivr/raw/statically не раздают release-ассеты — их быть не должно
        for u in urls:
            self.assertNotIn("cdn.jsdelivr", u)
            self.assertNotIn("raw.githubusercontent", u)
            self.assertNotIn("statically", u)

    def test_geo_timers_use_chimera_pythonpath(self):
        gsvc, _gtmr, hsvc, _htmr = st._unit_geo_timers()
        for unit in (gsvc, hsvc):
            self.assertIn("PYTHONPATH=", unit)
            self.assertIn("-m chimera.modules.smartdns_stack", unit)


if __name__ == "__main__":
    unittest.main(verbosity=2)
