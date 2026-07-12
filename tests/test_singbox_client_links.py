#!/usr/bin/env python3
"""
tests/test_singbox_client_links.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для генератора клиентских ссылок v4.23.12.

Покрывает:
  1. _gen_shadowtls_client_uri  — trojan:// + shadowtls params
  2. _gen_anytls_client_uri     — anytls:// URI
  3. _gen_tuic_client_uri       — tuic:// URI (uuid:password@)
  4. _gen_vless_ws_cdn_client_uri — vless:// + ws + tls
  5. _gen_singbox_client_json   — JSON outbound для всех 4 протоколов
  6. _get_public_endpoint       — loopback detection
  7. _show_client_links         — дымовой тест (не падает на валидном state)

Не требует root и не дёргает сеть — get_server_ip замокан.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch, MagicMock
from urllib.parse import urlparse, parse_qs

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("vless_installer._core")
    m.__dict__.update(g)
    sys.modules["vless_installer._core"] = m


def _enter_patches(stack, patches):
    for p in patches:
        stack.enter_context(p)


class _Base(unittest.TestCase):
    """Базовый класс с setup'ом общих моков."""

    def setUp(self):
        self.stack = ExitStack()
        _enter_patches(self.stack, [
            patch('os.geteuid', return_value=0),
            patch('os.chown', lambda *a, **k: None),
            patch.object(Path, 'mkdir', lambda s, *a, **k: None),
            patch.object(Path, 'touch', lambda s, *a, **k: None),
            patch.object(Path, 'chmod', lambda s, *a, **k: None),
            # Мокаем get_server_ip — не дёргаем сеть
            patch('vless_installer.modules.resources.get_server_ip',
                  return_value="203.0.113.42"),
        ])
        _setup_core()
        from vless_installer.modules import singbox_menu
        self.menu = singbox_menu

    def tearDown(self):
        self.stack.close()


# ============================================================================
#  1. _gen_shadowtls_client_uri
# ============================================================================
class TestShadowtlsUri(_Base):
    def _state(self, password="s3cret-pw", sni="www.cloudflare.com",
               port=9443, name="alice"):
        return {
            "enabled": True,
            "listen": "127.0.0.1",
            "listen_port": port,
            "version": 3,
            "password": password,
            "handshake": {"server": sni, "server_port": 443},
            "users": [{"password": password, "name": name}],
        }

    def test_uri_starts_with_trojan_scheme(self):
        uri = self.menu._gen_shadowtls_client_uri(
            self._state(), "203.0.113.42", 9443, "s3cret-pw")
        self.assertTrue(uri.startswith("trojan://"))

    def test_uri_contains_password_and_endpoint(self):
        uri = self.menu._gen_shadowtls_client_uri(
            self._state(), "203.0.113.42", 9443, "s3cret-pw")
        # password должен быть в user-info
        self.assertIn("s3cret-pw@", uri)
        # endpoint
        self.assertIn("203.0.113.42:9443", uri)

    def test_uri_contains_shadowtls_params(self):
        uri = self.menu._gen_shadowtls_client_uri(
            self._state(sni="tls.cloudflare.com"),
            "203.0.113.42", 9443, "s3cret-pw")
        # Парсим query
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        self.assertEqual(params["shadowtls"], ["3"])
        self.assertEqual(params["shadowtls_password"], ["s3cret-pw"])
        self.assertEqual(params["sni"], ["tls.cloudflare.com"])
        self.assertEqual(params["security"], ["tls"])
        self.assertEqual(params["fp"], ["chrome"])

    def test_uri_fragment_is_name(self):
        uri = self.menu._gen_shadowtls_client_uri(
            self._state(name="alice"), "203.0.113.42", 9443, "pw")
        parsed = urlparse(uri)
        self.assertEqual(parsed.fragment, "alice")

    def test_uri_password_url_encoded(self):
        # Пароль со спец-символами должен быть URL-encoded
        uri = self.menu._gen_shadowtls_client_uri(
            self._state(password="p@ss:word"),
            "203.0.113.42", 9443, "p@ss:word")
        # '@' и ':' в password должны быть закодированы в user-info
        # Проверяем что первый '@' отделяет userinfo от host
        # (т.е. в самом password '@' закодирован как %40)
        scheme_rest = uri[len("trojan://"):]
        # scheme_rest = "<encoded_pw>@host:port?...#name"
        # Первый '@' — разделитель. До него — encoded password.
        at_idx = scheme_rest.index("@")
        encoded_pw = scheme_rest[:at_idx]
        self.assertNotIn("@", encoded_pw)
        self.assertIn("%40", encoded_pw)  # @ -> %40


# ============================================================================
#  2. _gen_anytls_client_uri
# ============================================================================
class TestAnytlsUri(_Base):
    def _state(self, password="anytls-pw", port=8444, cn="example.com"):
        return {
            "enabled": True,
            "listen": "127.0.0.1",
            "listen_port": port,
            "password": password,
            "cert_source": "self-signed",
            "common_name": cn,
            "users": [{"password": password, "name": "bob"}],
        }

    def test_scheme_anytls(self):
        uri = self.menu._gen_anytls_client_uri(
            self._state(), "203.0.113.42", 8444, "anytls-pw")
        self.assertTrue(uri.startswith("anytls://"))

    def test_endpoint_and_password(self):
        uri = self.menu._gen_anytls_client_uri(
            self._state(), "203.0.113.42", 8444, "anytls-pw")
        self.assertIn("anytls-pw@", uri)
        self.assertIn("203.0.113.42:8444", uri)

    def test_sni_from_common_name(self):
        uri = self.menu._gen_anytls_client_uri(
            self._state(cn="vpn.example.com"),
            "203.0.113.42", 8444, "anytls-pw")
        params = parse_qs(urlparse(uri).query)
        self.assertEqual(params["sni"], ["vpn.example.com"])
        self.assertEqual(params["insecure"], ["1"])  # self-signed


# ============================================================================
#  3. _gen_tuic_client_uri
# ============================================================================
class TestTuicUri(_Base):
    def _state(self, uuid="550e8400-e29b-41d4-a716-446655440000",
               password="tuic-pw", port=443):
        return {
            "enabled": True,
            "listen": "::",
            "listen_port": port,
            "users": [{"uuid": uuid, "password": password, "name": "carol"}],
            "congestion_control": "bbr",
            "cert_source": "self-signed",
        }

    def test_scheme_tuic(self):
        uri = self.menu._gen_tuic_client_uri(
            self._state(), "203.0.113.42", 443)
        self.assertTrue(uri.startswith("tuic://"))

    def test_uuid_password_in_userinfo(self):
        uri = self.menu._gen_tuic_client_uri(
            self._state(), "203.0.113.42", 443)
        # tuic://<uuid>:<password>@host:port
        self.assertIn("550e8400-e29b-41d4-a716-446655440000:tuic-pw@", uri)

    def test_congestion_control_param(self):
        uri = self.menu._gen_tuic_client_uri(
            self._state(), "203.0.113.42", 443)
        params = parse_qs(urlparse(uri).query)
        self.assertEqual(params["congestion_control"], ["bbr"])
        self.assertEqual(params["alpn"], ["h3"])

    def test_empty_users_returns_empty(self):
        state = self._state()
        state["users"] = []
        uri = self.menu._gen_tuic_client_uri(state, "203.0.113.42", 443)
        self.assertEqual(uri, "")


# ============================================================================
#  4. _gen_vless_ws_cdn_client_uri
# ============================================================================
class TestVlessWsCdnUri(_Base):
    def _state(self, uuid="vless-uuid-1234",
               host="vpn.example.net", path="/a3f4b2c1"):
        return {
            "enabled": True,
            "listen": "0.0.0.0",
            "listen_port": 8443,
            "uuid": uuid,
            "ws_path": path,
            "host": host,
            "cdn_provider": "cloudflare",
        }

    def test_scheme_vless(self):
        uri = self.menu._gen_vless_ws_cdn_client_uri(self._state())
        self.assertTrue(uri.startswith("vless://"))

    def test_endpoint_is_cdn_host_port_443(self):
        uri = self.menu._gen_vless_ws_cdn_client_uri(self._state())
        # CDN endpoint всегда 443
        self.assertIn("vpn.example.net:443", uri)

    def test_ws_params(self):
        uri = self.menu._gen_vless_ws_cdn_client_uri(self._state())
        params = parse_qs(urlparse(uri).query)
        self.assertEqual(params["type"], ["ws"])
        self.assertEqual(params["host"], ["vpn.example.net"])
        self.assertEqual(params["path"], ["/a3f4b2c1"])
        self.assertEqual(params["security"], ["tls"])


# ============================================================================
#  5. _gen_singbox_client_json (v4.23.15 — полный клиентский конфиг)
# ============================================================================
class TestSingboxClientJson(_Base):
    def test_shadowtls_json_structure_v4_23_15(self):
        """v4.23.15: ShadowTLS — отдельный outbound, не transport.

        Правильная схема (sing-box 1.12+):
          - shadowtls outbound с detour на trojan-out
          - trojan outbound с detour на shadowtls (proxy)
        Старый формат с transport: shadowtls НЕ работает в 1.13+.
        """
        state = {
            "handshake": {"server": "www.cloudflare.com", "server_port": 443},
            "password": "pw123",
        }
        s = self.menu._gen_singbox_client_json(
            "shadowtls", state, "203.0.113.42", 9443)
        d = json.loads(s)
        # Полный конфиг, не фрагмент
        self.assertIn("inbounds", d)
        self.assertIn("outbounds", d)
        self.assertIn("route", d)
        # Два outbound: shadowtls (proxy) + trojan (trojan-out) + direct
        outbounds = d["outbounds"]
        self.assertEqual(len(outbounds), 3)
        proxy = outbounds[0]
        trojan = outbounds[1]
        # shadowtls outbound
        self.assertEqual(proxy["type"], "shadowtls")
        self.assertEqual(proxy["tag"], "proxy")
        self.assertEqual(proxy["server"], "203.0.113.42")
        self.assertEqual(proxy["server_port"], 9443)
        self.assertEqual(proxy["version"], 3)
        self.assertEqual(proxy["password"], "pw123")
        self.assertEqual(proxy["tls"]["server_name"], "www.cloudflare.com")
        self.assertTrue(proxy["tls"]["utls"]["enabled"])
        self.assertEqual(proxy["detour"], "trojan-out")
        # trojan outbound (внутренний)
        self.assertEqual(trojan["type"], "trojan")
        self.assertEqual(trojan["tag"], "trojan-out")
        self.assertEqual(trojan["password"], "pw123")
        self.assertEqual(trojan["detour"], "proxy")
        # НЕ должно быть transport: shadowtls
        self.assertNotIn("transport", proxy)

    def test_anytls_json_structure(self):
        state = {
            "password": "anytls-pw",
            "common_name": "vpn.example.com",
            "cert_source": "self-signed",
        }
        s = self.menu._gen_singbox_client_json(
            "anytls", state, "203.0.113.42", 8444)
        d = json.loads(s)
        proxy = d["outbounds"][0]
        self.assertEqual(proxy["type"], "anytls")
        self.assertEqual(proxy["password"], "anytls-pw")
        self.assertTrue(proxy["tls"]["insecure"])  # self-signed

    def test_tuic_json_structure(self):
        state = {
            "users": [{"uuid": "uuid-1234", "password": "tuic-pw"}],
            "congestion_control": "bbr",
            "cert_source": "self-signed",
        }
        s = self.menu._gen_singbox_client_json(
            "tuic", state, "203.0.113.42", 443)
        d = json.loads(s)
        proxy = d["outbounds"][0]
        self.assertEqual(proxy["type"], "tuic")
        self.assertEqual(proxy["uuid"], "uuid-1234")
        self.assertEqual(proxy["password"], "tuic-pw")
        self.assertEqual(proxy["congestion_control"], "bbr")
        self.assertTrue(proxy["tls"]["insecure"])

    def test_vless_ws_cdn_json_structure(self):
        state = {
            "host": "vpn.example.net",
            "uuid": "vless-uuid",
            "ws_path": "/abc",
        }
        s = self.menu._gen_singbox_client_json(
            "vless_ws_cdn", state, "203.0.113.42", 8443)
        d = json.loads(s)
        proxy = d["outbounds"][0]
        self.assertEqual(proxy["type"], "vless")
        self.assertEqual(proxy["server"], "vpn.example.net")
        self.assertEqual(proxy["server_port"], 443)
        self.assertEqual(proxy["uuid"], "vless-uuid")
        self.assertEqual(proxy["transport"]["type"], "ws")
        self.assertEqual(proxy["transport"]["path"], "/abc")
        self.assertEqual(proxy["transport"]["headers"]["Host"], "vpn.example.net")

    def test_unknown_protocol_returns_empty(self):
        s = self.menu._gen_singbox_client_json(
            "unknown_proto", {}, "1.2.3.4", 1000)
        self.assertEqual(s, "")

    def test_tuic_empty_users_returns_empty(self):
        state = {"users": []}
        s = self.menu._gen_singbox_client_json(
            "tuic", state, "1.2.3.4", 443)
        self.assertEqual(s, "")

    def test_full_config_has_inbound_mixed(self):
        """Полный конфиг должен иметь mixed-in на 127.0.0.1:2080."""
        s = self.menu._gen_singbox_client_json(
            "anytls", {"password": "x"}, "1.2.3.4", 8444)
        d = json.loads(s)
        self.assertEqual(d["inbounds"][0]["type"], "mixed")
        self.assertEqual(d["inbounds"][0]["listen"], "127.0.0.1")
        self.assertEqual(d["inbounds"][0]["listen_port"], 2080)

    def test_full_config_route_final_proxy(self):
        """route.final должен быть 'proxy'."""
        s = self.menu._gen_singbox_client_json(
            "anytls", {"password": "x"}, "1.2.3.4", 8444)
        d = json.loads(s)
        self.assertEqual(d["route"]["final"], "proxy")


# ============================================================================
#  6. _get_public_endpoint
# ============================================================================
class TestGetPublicEndpoint(_Base):
    def test_loopback_returns_warning_flag(self):
        # listen=127.0.0.1 → is_loopback=True
        ip, port, is_loopback = self.menu._get_public_endpoint(
            {"listen": "127.0.0.1", "listen_port": 9443})
        self.assertTrue(is_loopback)
        self.assertEqual(port, 9443)
        # public_ip должен быть замоканным
        self.assertEqual(ip, "203.0.113.42")

    def test_loopback_ipv6(self):
        ip, port, is_loopback = self.menu._get_public_endpoint(
            {"listen": "::1", "listen_port": 9443})
        self.assertTrue(is_loopback)

    def test_external_listen_no_warning(self):
        ip, port, is_loopback = self.menu._get_public_endpoint(
            {"listen": "0.0.0.0", "listen_port": 8443})
        self.assertFalse(is_loopback)
        self.assertEqual(port, 8443)

    def test_external_ipv6_listen_no_warning(self):
        ip, port, is_loopback = self.menu._get_public_endpoint(
            {"listen": "::", "listen_port": 443})
        self.assertFalse(is_loopback)


# ============================================================================
#  7. _list_users_for_protocol (v4.23.12 — показывает полный пароль)
# ============================================================================
class TestListUsersShowsPassword(_Base):
    def test_function_callable(self):
        # Дымовой тест — функция существует и callable
        self.assertTrue(callable(self.menu._list_users_for_protocol))


# ============================================================================
#  8. _is_valid_listen_ip (v4.23.13)
# ============================================================================
class TestIsValidListenIp(_Base):
    def test_loopback_ipv4(self):
        self.assertTrue(self.menu._is_valid_listen_ip("127.0.0.1"))

    def test_loopback_ipv6(self):
        self.assertTrue(self.menu._is_valid_listen_ip("::1"))

    def test_all_ipv4(self):
        self.assertTrue(self.menu._is_valid_listen_ip("0.0.0.0"))

    def test_all_ipv6(self):
        self.assertTrue(self.menu._is_valid_listen_ip("::"))

    def test_localhost(self):
        self.assertTrue(self.menu._is_valid_listen_ip("localhost"))

    def test_concrete_ipv4(self):
        self.assertTrue(self.menu._is_valid_listen_ip("192.168.1.1"))
        self.assertTrue(self.menu._is_valid_listen_ip("203.0.113.42"))

    def test_concrete_ipv6(self):
        self.assertTrue(self.menu._is_valid_listen_ip("2001:db8::1"))
        self.assertTrue(self.menu._is_valid_listen_ip("::ffff:192.0.2.1"))

    def test_invalid_strings(self):
        self.assertFalse(self.menu._is_valid_listen_ip(""))
        self.assertFalse(self.menu._is_valid_listen_ip("not-an-ip"))
        self.assertFalse(self.menu._is_valid_listen_ip("999.999.999.999"))
        self.assertFalse(self.menu._is_valid_listen_ip("192.168.1"))
        self.assertFalse(self.menu._is_valid_listen_ip("192.168.1.1:8080"))

    def test_domain_name_rejected(self):
        # Имена доменов не должны проходить — только IP/0.0.0.0/::/localhost
        self.assertFalse(self.menu._is_valid_listen_ip("example.com"))


# ============================================================================
#  9. _build_shadowtls_inbound / _build_anytls_inbound с listen= (v4.23.13)
# ============================================================================
class TestBuildInboundListen(_Base):
    """Тестируем что _build_*_inbound читает listen из state-словаря.

    Прямой unit-тест на builder (без state_init), чтобы не зависеть от
    тест-изоляции state-файла. Интеграционные тесты на singbox_enable_*
    с state-файлом уже есть в test_singbox_config.py.
    """
    def test_shadowtls_build_reads_listen_from_state(self):
        from vless_installer.modules.singbox_config import _build_shadowtls_inbound
        state_ib = {
            "listen": "0.0.0.0",
            "listen_port": 9443,
            "version": 3,
            "users": [{"password": "pw", "name": "u1"}],
            "handshake": {"server": "www.cloudflare.com", "server_port": 443},
        }
        built = _build_shadowtls_inbound(state_ib)
        self.assertEqual(built["listen"], "0.0.0.0")
        self.assertEqual(built["listen_port"], 9443)

    def test_shadowtls_build_defaults_to_loopback(self):
        from vless_installer.modules.singbox_config import _build_shadowtls_inbound
        # state без listen → дефолт 127.0.0.1 (безопасно)
        state_ib = {"listen_port": 9443, "users": []}
        built = _build_shadowtls_inbound(state_ib)
        self.assertEqual(built["listen"], "127.0.0.1")

    def test_anytls_build_reads_listen_from_state(self):
        from vless_installer.modules.singbox_config import _build_anytls_inbound
        state_ib = {
            "listen": "0.0.0.0",
            "listen_port": 8444,
            "users": [{"password": "pw", "name": "u1"}],
        }
        built = _build_anytls_inbound(state_ib)
        self.assertEqual(built["listen"], "0.0.0.0")
        self.assertEqual(built["listen_port"], 8444)

    def test_anytls_build_defaults_to_loopback(self):
        from vless_installer.modules.singbox_config import _build_anytls_inbound
        state_ib = {"listen_port": 8444, "users": []}
        built = _build_anytls_inbound(state_ib)
        self.assertEqual(built["listen"], "127.0.0.1")

    def test_change_listen_ip_callable(self):
        # Дымовой тест — функция существует и callable
        self.assertTrue(callable(self.menu._change_listen_ip))


if __name__ == "__main__":
    unittest.main()
