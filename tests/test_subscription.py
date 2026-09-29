#!/usr/bin/env python3
"""
tests/test_subscription.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/subscription.py.

Покрывает:
  1. _token_for — HMAC токен
  2. _make_tls_secret — генерация TLS-секрета
  3. _candidate_names — сбор кандидатов имён
  4. _resolve_sni — выбор SNI
  5. _build_userinfo_header — заголовок userinfo
  6. _unit_text — генерация systemd unit
  7. _gen_mieru_share_link — генерация mierus:// URL
  8. _load_sub_conf / _save_sub_conf — JSON I/O
  9. _ensure_pepper — генерация pepper
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
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


class TestTokenFor(unittest.TestCase):
    """_token_for — HMAC токен (pure)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_24_char_hex(self):
        from chimera.modules.subscription import _token_for
        token = _token_for("uuid-123", "pepper-123")
        self.assertEqual(len(token), 24)
        self.assertTrue(all(c in "0123456789abcdef" for c in token))

    def test_deterministic(self):
        """Одинаковые ввод → одинаковый токен."""
        from chimera.modules.subscription import _token_for
        t1 = _token_for("uuid-123", "pepper-123")
        t2 = _token_for("uuid-123", "pepper-123")
        self.assertEqual(t1, t2)

    def test_different_uuid_different_token(self):
        from chimera.modules.subscription import _token_for
        t1 = _token_for("uuid-1", "pepper")
        t2 = _token_for("uuid-2", "pepper")
        self.assertNotEqual(t1, t2)

    def test_different_pepper_different_token(self):
        from chimera.modules.subscription import _token_for
        t1 = _token_for("uuid", "pepper-1")
        t2 = _token_for("uuid", "pepper-2")
        self.assertNotEqual(t1, t2)

    def test_uses_hmac_sha256(self):
        """Проверка что используется именно HMAC-SHA256."""
        from chimera.modules.subscription import _token_for
        expected = hmac.new(
            b"pepper", b"uuid", hashlib.sha256
        ).hexdigest()[:24]
        self.assertEqual(_token_for("uuid", "pepper"), expected)


class TestMakeTlsSecret(unittest.TestCase):
    """_make_tls_secret — pure."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_ee_prefix(self):
        from chimera.modules.subscription import _make_tls_secret
        result = _make_tls_secret("base_secret", "example.com")
        self.assertTrue(result.startswith("ee"))

    def test_contains_base_secret(self):
        from chimera.modules.subscription import _make_tls_secret
        result = _make_tls_secret("mysecret", "example.com")
        self.assertIn("mysecret", result)

    def test_contains_hex_domain(self):
        from chimera.modules.subscription import _make_tls_secret
        result = _make_tls_secret("base", "example.com")
        # domain.encode().hex() должен присутствовать
        self.assertIn("example.com".encode().hex(), result)

    def test_deterministic(self):
        from chimera.modules.subscription import _make_tls_secret
        self.assertEqual(
            _make_tls_secret("base", "domain"),
            _make_tls_secret("base", "domain"),
        )


class TestCandidateNames(unittest.TestCase):
    """_candidate_names — pure."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_set(self):
        from chimera.modules.subscription import _candidate_names
        result = _candidate_names({"name": "alice", "email": "alice@x.com"})
        self.assertIsInstance(result, set)

    def test_includes_name_and_email_local_part(self):
        from chimera.modules.subscription import _candidate_names
        result = _candidate_names({
            "name": "alice", "email": "alice@example.com",
        })
        self.assertIn("alice", result)

    def test_lowercases(self):
        from chimera.modules.subscription import _candidate_names
        result = _candidate_names({"name": "ALICE", "email": "ALICE@Example.COM"})
        self.assertIn("alice", result)

    def test_empty_fields_excluded(self):
        from chimera.modules.subscription import _candidate_names
        result = _candidate_names({"name": "", "email": ""})
        self.assertNotIn("", result)


class TestResolveSni(unittest.TestCase):
    """_resolve_sni — выбор SNI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_domain_for_reality_without_awg(self):
        from chimera.modules.subscription import _resolve_sni
        state = {"proto": "reality", "domain": "vpn.example.com"}
        self.assertEqual(_resolve_sni(state), "vpn.example.com")

    def test_returns_reality_dest_for_awg_reality_mode_b(self):
        from chimera.modules.subscription import _resolve_sni
        state = {
            "proto": "reality", "awg_exit_enabled": True,
            "install_mode": "B", "reality_dest": "dest.example.com:443",
            "domain": "vpn.example.com",
        }
        self.assertEqual(_resolve_sni(state), "dest.example.com")

    def test_returns_reality_dest_for_awg_xhttp_reality_mode_b(self):
        """xhttp_reality наследует SNI-правило REALITY: Mode B + AWG → reality_dest."""
        from chimera.modules.subscription import _resolve_sni
        state = {
            "protocol_mode": "xhttp_reality", "awg_exit_enabled": True,
            "install_mode": "B", "reality_dest": "dest.example.com:443",
            "domain": "vpn.example.com",
        }
        self.assertEqual(_resolve_sni(state), "dest.example.com")

    def test_returns_domain_for_xhttp_reality_mode_a(self):
        """xhttp_reality без AWG (Mode A): SNI = собственный домен."""
        from chimera.modules.subscription import _resolve_sni
        state = {
            "protocol_mode": "xhttp_reality",
            "reality_dest": "dest.example.com:443",
            "install_mode": "A",
            "domain": "vpn.example.com",
        }
        self.assertEqual(_resolve_sni(state), "vpn.example.com")


class TestBuildUserinfoHeader(unittest.TestCase):
    """_build_userinfo_header — pure."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_none_when_no_email(self):
        from chimera.modules.subscription import _build_userinfo_header
        self.assertIsNone(_build_userinfo_header({"email": ""}))

    def test_returns_none_when_no_limit(self):
        from chimera.modules.subscription import _build_userinfo_header
        with patch("chimera.modules.subscription._load_traffic_limits",
                   return_value={}):
            result = _build_userinfo_header({"email": "alice@x.com"})
        self.assertIsNone(result)

    def test_returns_header_when_limit_set(self):
        from chimera.modules.subscription import _build_userinfo_header
        with patch("chimera.modules.subscription._load_traffic_limits",
                   return_value={"alice@x.com": {"limit_gb": 10}}):
            result = _build_userinfo_header({"email": "alice@x.com"})
        self.assertIsNotNone(result)
        self.assertIn("upload=", result)
        self.assertIn("download=", result)
        self.assertIn("total=", result)
        # 10 GB = 10 * 1024^3
        self.assertIn(str(10 * 1024 ** 3), result)


class TestUnitText(unittest.TestCase):
    """_unit_text — pure string builder."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_string_with_substitutions(self):
        from chimera.modules.subscription import _unit_text
        result = _unit_text("/usr/bin/python3", "/path/to/module.py", 8443)
        self.assertIn("/usr/bin/python3", result)
        self.assertIn("/path/to/module.py", result)
        self.assertIn("8443", result)

    def test_contains_restart_always(self):
        from chimera.modules.subscription import _unit_text
        result = _unit_text("/usr/bin/python3", "/path.py", 8443)
        self.assertIn("Restart=always", result)


class TestNginxSnippetText(unittest.TestCase):
    """_nginx_snippet_text — regression test for KeyError: ' listen 443 ssl; '.

    The nginx snippet template contains a COMMENT with the text
    `server { listen 443 ssl; ... }`. Python's str.format() interprets
    `{ listen 443 ssl; ... }` as a named placeholder and raises KeyError
    because no such argument is passed. The fix escapes literal braces
    as {{ }} in the template.

    This test ensures the template can be formatted for ANY port without
    raising KeyError — regression guard for the production bug where
    menu [1] crashed with:
        [ERR] Не удалось установить сервис: ' listen 443 ssl; '
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_does_not_raise_keyerror_for_port_8443(self):
        from chimera.modules.subscription import _nginx_snippet_text
        # Should not raise KeyError
        result = _nginx_snippet_text(8443)
        self.assertIn("proxy_pass https://127.0.0.1:8443", result)

    def test_does_not_raise_keyerror_for_arbitrary_port(self):
        from chimera.modules.subscription import _nginx_snippet_text
        # The user had listen_port=63876 in subscription.json
        result = _nginx_snippet_text(63876)
        self.assertIn("proxy_pass https://127.0.0.1:63876", result)

    def test_contains_location_sub_block(self):
        from chimera.modules.subscription import _nginx_snippet_text
        result = _nginx_snippet_text(8443)
        self.assertIn("location /sub/ {", result)
        self.assertIn("}", result)

    def test_comment_braces_are_literal_not_placeholders(self):
        """The comment `server { listen 443 ssl; ... }` must appear literally
        in the output — { and } must NOT be consumed by .format()."""
        from chimera.modules.subscription import _nginx_snippet_text
        result = _nginx_snippet_text(8443)
        self.assertIn("server { listen 443 ssl; ... }", result,
                      "literal braces in comment must survive .format()")


class TestGenMieruShareLink(unittest.TestCase):
    """_gen_mieru_share_link — pure URL builder."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_mierus_url(self):
        from chimera.modules.subscription import _gen_mieru_share_link
        result = _gen_mieru_share_link("1.2.3.4", 8443, "tcp", "user", "pass")
        self.assertTrue(result.startswith("mierus://"))

    def test_contains_credentials(self):
        from chimera.modules.subscription import _gen_mieru_share_link
        result = _gen_mieru_share_link("1.2.3.4", 8443, "tcp", "user", "pass")
        self.assertIn("user:pass", result)

    def test_contains_port_and_protocol(self):
        from chimera.modules.subscription import _gen_mieru_share_link
        result = _gen_mieru_share_link("1.2.3.4", 8443, "tcp", "user", "pass")
        self.assertIn("port=8443", result)
        self.assertIn("protocol=TCP", result)  # uppercase


class TestLoadSaveSubConf(unittest.TestCase):
    """_load_sub_conf / _save_sub_conf — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._conf = self._tmpdir / "sub_conf.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.subscription._SUB_CONF", self._conf)

    def test_load_returns_empty_when_no_file(self):
        from chimera.modules.subscription import _load_sub_conf
        with self._patch():
            self.assertEqual(_load_sub_conf(), {})

    def test_load_returns_empty_on_corrupt(self):
        from chimera.modules.subscription import _load_sub_conf
        self._conf.write_text("{invalid")
        with self._patch():
            self.assertEqual(_load_sub_conf(), {})

    def test_save_then_load(self):
        from chimera.modules.subscription import _load_sub_conf, _save_sub_conf
        with self._patch():
            _save_sub_conf({"pepper": "abc", "identity_map": {}})
            loaded = _load_sub_conf()
        self.assertEqual(loaded["pepper"], "abc")


class TestEnsurePepper(unittest.TestCase):
    """_ensure_pepper — генерация pepper."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._conf = self._tmpdir / "sub_conf.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.subscription._SUB_CONF", self._conf)

    def test_returns_existing_pepper(self):
        from chimera.modules.subscription import (
            _ensure_pepper, _load_sub_conf,
        )
        self._conf.write_text(json.dumps({"pepper": "existing"}))
        with self._patch():
            cfg = _load_sub_conf()
            result = _ensure_pepper(cfg)
        self.assertEqual(result, "existing")

    def test_generates_new_pepper_when_missing(self):
        from chimera.modules.subscription import _ensure_pepper
        with self._patch():
            result = _ensure_pepper({})
        self.assertGreater(len(result), 10)
        # pepper сохраняется в конфиг
        saved = json.loads(self._conf.read_text())
        self.assertEqual(saved["pepper"], result)

    def test_generated_pepper_is_hex(self):
        from chimera.modules.subscription import _ensure_pepper
        with self._patch():
            result = _ensure_pepper({})
        self.assertTrue(all(c in "0123456789abcdef" for c in result))


class TestMieruEndpoints(unittest.TestCase):
    """единый источник mieru-точек — домен из state в ссылках,
    BOTH → TCP и UDP отдельными точками, hybrid + standalone."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write(self, name, data):
        p = self._tmp / name
        p.write_text(json.dumps(data))
        return p

    def _user(self):
        return {"uuid": "uuid-1", "email": "john@x.com"}

    def test_hybrid_domain_in_links(self):
        """Домен из client_server_addr попадает в mierus://-ссылки
        подписки — IP больше не приоритетен."""
        from chimera.modules import subscription as sub
        hst = self._write("hybrid_st.json", {
            "transport": "both", "tcp_port": 443, "udp_port": 444,
            "client_server_addr": "chimeraprodcdn.online",
            "client_dns": "chimeravpn.online"})
        mcfg = self._write("mita.json", {"users": [{"name": "john", "password": "pw"}]})
        with patch.object(sub, "_HYBRID_STATE", hst), \
             patch.object(sub, "_MITA_HYBRID_CFG", mcfg), \
             patch.object(sub, "_MIERU_STATE", self._tmp / "nope.json"):
            links = sub._build_mieru_uris(self._user(), "138.124.255.238")
        self.assertEqual(len(links), 2)  # tcp и udp — ОБА транспорта
        for link in links:
            self.assertIn("@chimeraprodcdn.online", link)
            self.assertNotIn("138.124.255.238", link)
        protos = [l.split("protocol=")[1].split("&")[0] for l in links]
        self.assertEqual(sorted(protos), ["TCP", "UDP"])

    def test_hybrid_ip_fallback(self):
        """Нет client_server_addr — как раньше, IP (нулевая регрессия)."""
        from chimera.modules import subscription as sub
        hst = self._write("hybrid_st.json", {"tcp_port": 443, "udp_port": None})
        mcfg = self._write("mita.json", {"users": [{"name": "john", "password": "pw"}]})
        with patch.object(sub, "_HYBRID_STATE", hst), \
             patch.object(sub, "_MITA_HYBRID_CFG", mcfg), \
             patch.object(sub, "_MIERU_STATE", self._tmp / "nope.json"):
            links = sub._build_mieru_uris(self._user(), "138.124.255.238")
        self.assertEqual(len(links), 1)
        self.assertIn("@138.124.255.238", links[0])
        self.assertIn("protocol=TCP", links[0])

    def test_standalone_both_two_links(self):
        """Standalone BOTH → две ссылки (TCP и UDP), домен из state."""
        from chimera.modules import subscription as sub
        mst = self._write("mieru.json", {
            "installed": True, "port_start": 20000, "port_end": 20010,
            "protocol": "BOTH", "client_server_addr": "d.example",
            "users": [{"username": "john", "password": "pw"}]})
        with patch.object(sub, "_MIERU_STATE", mst), \
             patch.object(sub, "_HYBRID_STATE", self._tmp / "nope.json"), \
             patch.object(sub, "_MITA_HYBRID_CFG", self._tmp / "nope.json"):
            links = sub._build_mieru_uris(self._user(), "1.2.3.4")
        self.assertEqual(len(links), 2)
        protos = [l.split("protocol=")[1].split("&")[0] for l in links]
        self.assertEqual(sorted(protos), ["TCP", "UDP"])
        for link in links:
            self.assertIn("@d.example", link)
            self.assertIn("port=20000", link)

    def test_standalone_single_protocol_unchanged(self):
        """Регресс: одиночный протокол — одна ссылка (без BOTH)."""
        from chimera.modules import subscription as sub
        mst = self._write("mieru.json", {
            "installed": True, "port_start": 5353, "port_end": 5353,
            "protocol": "UDP",
            "users": [{"username": "john", "password": "pw"}]})
        with patch.object(sub, "_MIERU_STATE", mst), \
             patch.object(sub, "_HYBRID_STATE", self._tmp / "nope.json"), \
             patch.object(sub, "_MITA_HYBRID_CFG", self._tmp / "nope.json"):
            links = sub._build_mieru_uris(self._user(), "1.2.3.4")
        self.assertEqual(len(links), 1)
        self.assertIn("protocol=UDP", links[0])
        self.assertIn("port=5353", links[0])

    def test_endpoints_meta(self):
        """meta из _collect_mieru_json_outbounds: client_dns, домен, первый тег."""
        from chimera.modules import subscription as sub
        hst = self._write("hybrid_st.json", {
            "tcp_port": 443, "udp_port": 444,
            "client_server_addr": "chimeraprodcdn.online",
            "client_dns": "chimeravpn.online",
            "traffic_pattern_blob": "GgQIARAFIgIIAQ=="})
        mcfg = self._write("mita.json", {"users": [{"name": "john", "password": "pw"}]})
        with patch.object(sub, "_HYBRID_STATE", hst), \
             patch.object(sub, "_MITA_HYBRID_CFG", mcfg), \
             patch.object(sub, "_MIERU_STATE", self._tmp / "nope.json"):
            obs, meta = sub._collect_mieru_json_outbounds(self._user(), "1.2.3.4")
        self.assertEqual(len(obs), 2)
        self.assertEqual(meta["client_dns"], "chimeravpn.online")
        self.assertEqual(meta["server_domain"], "chimeraprodcdn.online")
        self.assertEqual(meta["first_tag"], "mieru-john")
        # теги уникальны, у второго — суффикс транспорта
        tags = [ob["tag"] for ob in obs]
        self.assertEqual(len(set(tags)), 2)
        self.assertEqual(tags, ["mieru-john", "mieru-john-udp"])
        for ob in obs:
            self.assertEqual(ob["server"], "chimeraprodcdn.online")
            self.assertEqual(ob["domain_resolver"], "local")
            self.assertEqual(ob["traffic_pattern"], "GgQIARAFIgIIAQ==")
            self.assertEqual(ob["multiplexing"], "MULTIPLEXING_HIGH")


class TestSingboxSubscription(unittest.TestCase):
    """nyamebox/nekobox (format=singbox) получают mieru-outbound'ы;
    VLESS исключается в hybrid-режиме; DNS-блок — только в чистом mieru."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write(self, name, data):
        p = self._tmp / name
        p.write_text(json.dumps(data))
        return p

    def _user(self):
        return {"uuid": "uuid-1", "email": "john@x.com"}

    def _hybrid_state(self, dns="chimeravpn.online", addr="chimeraprodcdn.online"):
        hst = self._write("hybrid_st.json", {
            "transport": "both", "tcp_port": 443, "udp_port": 444,
            "client_server_addr": addr, "client_dns": dns,
            "traffic_pattern_blob": "GgQIARAFIgIIAQ=="})
        mcfg = self._write("mita.json", {"users": [{"name": "john", "password": "pw"}]})
        return hst, mcfg

    def _build(self, hst, mcfg, mieru_state=None, vless_json=""):
        from chimera.modules import subscription as sub
        import chimera.modules.rest_api as rest_api
        with patch.object(sub, "_HYBRID_STATE", hst), \
             patch.object(sub, "_MITA_HYBRID_CFG", mcfg), \
             patch.object(sub, "_MIERU_STATE", mieru_state or (self._tmp / "nope.json")), \
             patch.object(sub, "_get_server_ip", return_value="138.124.255.238"), \
             patch.object(sub, "_load_state", return_value={}), \
             patch.object(sub, "_collect_registry_json_outbounds", return_value=[]), \
             patch.object(rest_api, "_generate_singbox_config", return_value=vless_json):
            return sub.build_subscription_singbox_config(self._user())

    def test_hybrid_mieru_outbounds_and_dns(self):
        """Hybrid-режим: mieru-outbound'ы на ОБА транспорта, домен,
        DNS-блок (AGH через туннель) — как в прежнем Karing-JSON."""
        hst, mcfg = self._hybrid_state()
        cfg = json.loads(self._build(hst, mcfg))
        mieru_obs = [ob for ob in cfg["outbounds"] if ob.get("type") == "mieru"]
        self.assertEqual(len(mieru_obs), 2)
        tags = [ob["tag"] for ob in mieru_obs]
        self.assertEqual(tags, ["mieru-john", "mieru-john-udp"])
        for ob in mieru_obs:
            self.assertEqual(ob["server"], "chimeraprodcdn.online")
            self.assertEqual(ob["domain_resolver"], "local")
            self.assertEqual(ob["traffic_pattern"], "GgQIARAFIgIIAQ==")
        # route.final — на первый mieru-outbound
        self.assertEqual(cfg["route"]["final"], "mieru-john")
        # DNS-секция: custom-dns через туннель + правила на домен сервера
        custom = cfg["dns"]["servers"][0]
        self.assertEqual(custom["tag"], "custom-dns")
        self.assertEqual(custom["address"], "chimeravpn.online")
        self.assertEqual(custom["detour"], "mieru-john")
        self.assertEqual(cfg["dns"]["rules"],
                         [{"domain": ["chimeraprodcdn.online"], "server": "local"}])

    def test_hybrid_vless_excluded(self):
        """Hybrid-режим: VLESS-outbound исключён (инбаунд — SOCKS-петля,
        мёртв снаружи) — паритет с base64-подпиской."""
        hst, mcfg = self._hybrid_state()
        fake_vless = json.dumps({
            "outbounds": [{"type": "vless", "tag": "vless-out",
                           "server": "138.124.255.238", "server_port": 443}]})
        cfg = json.loads(self._build(hst, mcfg, vless_json=fake_vless))
        types = [ob.get("type") for ob in cfg["outbounds"]]
        self.assertNotIn("vless", types)
        self.assertIn("mieru", types)

    def test_no_client_dns_no_dns_section(self):
        """client_dns не задан — dns-секции нет (нулевая регрессия для
        установок без DNS)."""
        hst, mcfg = self._hybrid_state(dns="")
        cfg = json.loads(self._build(hst, mcfg))
        self.assertNotIn("dns", cfg)
        self.assertEqual(len([ob for ob in cfg["outbounds"]
                              if ob.get("type") == "mieru"]), 2)

    def test_mixed_config_no_dns_block(self):
        """Standalone (VLESS+mieru вместе): mieru-outbound'ы есть, DNS-блока
        НЕТ — DNS через mieru ломал бы VLESS при падении mieru."""
        mst = self._write("mieru.json", {
            "installed": True, "port_start": 20000, "port_end": 20000,
            "protocol": "BOTH", "client_dns": "dns.example",
            "users": [{"username": "john", "password": "pw"}]})
        hst = self._tmp / "nope_hybrid.json"  # не существует → hybrid не активен
        mcfg = self._tmp / "nope_mita.json"
        fake_vless = json.dumps({
            "outbounds": [{"type": "vless", "tag": "vless-out",
                           "server": "1.2.3.4", "server_port": 443}]})
        cfg = json.loads(self._build(hst, mcfg, mieru_state=mst,
                                     vless_json=fake_vless))
        types = [ob.get("type") for ob in cfg["outbounds"]]
        self.assertEqual(types.count("vless"), 1)
        self.assertEqual(types.count("mieru"), 2)  # BOTH → TCP и UDP
        self.assertNotIn("dns", cfg)
        # VLESS остаётся первым (route.final не изменился — регресс-защита)
        self.assertEqual(cfg["route"]["final"], "vless-out")


if __name__ == "__main__":
    unittest.main(verbosity=2)
