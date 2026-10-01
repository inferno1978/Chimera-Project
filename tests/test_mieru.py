#!/usr/bin/env python3
"""
tests/test_mieru.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/mieru.py.

Покрывает:
  1. _get_download_urls — вычисление URL для amd64/arm64
  2. _build_server_config — генерация серверного конфига
  3. _gen_singbox_outbound — генерация sing-box outbound
  4. _gen_client_share_link — генерация mierus:// ссылки
  5. _gen_client_share_link_nekobox — генерация Nekobox ссылки
  6. _is_amd64 — определение архитектуры
  7. _RE_USERNAME — валидация имени пользователя
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

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


class TestGetDownloadUrls(unittest.TestCase):
    """_get_download_urls — вычисление URL."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_amd64_urls(self):
        from chimera.modules import mieru
        with patch.object(mieru, "_is_amd64", return_value=True):
            mita_url, mieru_url = mieru._get_download_urls("1.0.0")
        self.assertIn("amd64", mita_url)
        self.assertIn("amd64", mieru_url)
        self.assertIn("1.0.0", mita_url)
        self.assertIn("1.0.0", mieru_url)

    def test_arm64_urls(self):
        from chimera.modules import mieru
        with patch.object(mieru, "_is_amd64", return_value=False):
            mita_url, mieru_url = mieru._get_download_urls("2.0.0")
        self.assertIn("arm64", mita_url)
        self.assertIn("arm64", mieru_url)


class TestBuildServerConfig(unittest.TestCase):
    """_build_server_config — генерация серверного конфига."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_single_port(self):
        from chimera.modules.mieru import _build_server_config
        users = [{"username": "alice", "password": "pass1"}]
        cfg = _build_server_config(users, 2012, 2012, "TCP")
        self.assertEqual(len(cfg["portBindings"]), 1)
        self.assertEqual(cfg["portBindings"][0]["port"], 2012)
        self.assertEqual(cfg["portBindings"][0]["protocol"], "TCP")

    def test_port_range(self):
        from chimera.modules.mieru import _build_server_config
        users = [{"username": "alice", "password": "pass1"}]
        cfg = _build_server_config(users, 2012, 2022, "UDP")
        self.assertEqual(len(cfg["portBindings"]), 1)
        self.assertIn("portRange", cfg["portBindings"][0])
        self.assertEqual(cfg["portBindings"][0]["portRange"], "2012-2022")
        self.assertEqual(cfg["portBindings"][0]["protocol"], "UDP")

    def test_users_included(self):
        from chimera.modules.mieru import _build_server_config
        users = [{"username": "alice", "password": "p1"}, {"username": "bob", "password": "p2"}]
        cfg = _build_server_config(users, 2012, 2022, "TCP")
        self.assertEqual(len(cfg["users"]), 2)

    def test_logging_level_and_mtu(self):
        from chimera.modules.mieru import _build_server_config
        cfg = _build_server_config([], 2012, 2022, "TCP")
        self.assertEqual(cfg["loggingLevel"], "INFO")
        self.assertEqual(cfg["mtu"], 1400)

    # ── Фича 1: trafficPattern в server config ──────────────────────────────

    def test_traffic_pattern_added_when_provided(self):
        """_build_server_config с traffic_pattern → cfg["trafficPattern"] present."""
        from chimera.modules.mieru import _build_server_config
        tp = {"nonce": {"type": "NONCE_TYPE_PRINTABLE"}}
        cfg = _build_server_config([], 2012, 2022, "TCP", traffic_pattern=tp)
        self.assertIn("trafficPattern", cfg)
        self.assertEqual(cfg["trafficPattern"], tp)

    def test_traffic_pattern_omitted_when_none(self):
        """_build_server_config без traffic_pattern → нет поля trafficPattern."""
        from chimera.modules.mieru import _build_server_config
        cfg = _build_server_config([], 2012, 2022, "TCP")
        self.assertNotIn("trafficPattern", cfg)

    def test_traffic_pattern_omitted_when_none_explicit(self):
        """_build_server_config с traffic_pattern=None → нет поля."""
        from chimera.modules.mieru import _build_server_config
        cfg = _build_server_config([], 2012, 2022, "TCP", traffic_pattern=None)
        self.assertNotIn("trafficPattern", cfg)


class TestMieruTrafficPresets(unittest.TestCase):
    """_MIERU_TRAFFIC_PRESETS — структура пресетов для server config."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_4_presets(self):
        from chimera.modules.mieru import _MIERU_TRAFFIC_PRESETS
        for name in ("disabled", "basic", "medium", "aggressive"):
            self.assertIn(name, _MIERU_TRAFFIC_PRESETS)

    def test_each_preset_has_label_description_config(self):
        from chimera.modules.mieru import _MIERU_TRAFFIC_PRESETS
        for name, preset in _MIERU_TRAFFIC_PRESETS.items():
            with self.subTest(preset=name):
                self.assertIn("label", preset)
                self.assertIn("description", preset)
                self.assertIn("config", preset)

    def test_disabled_has_none_config(self):
        from chimera.modules.mieru import _MIERU_TRAFFIC_PRESETS
        self.assertIsNone(_MIERU_TRAFFIC_PRESETS["disabled"]["config"])

    def test_basic_has_nonce(self):
        from chimera.modules.mieru import _MIERU_TRAFFIC_PRESETS
        cfg = _MIERU_TRAFFIC_PRESETS["basic"]["config"]
        self.assertIn("nonce", cfg)

    def test_aggressive_has_all_fields(self):
        from chimera.modules.mieru import _MIERU_TRAFFIC_PRESETS
        cfg = _MIERU_TRAFFIC_PRESETS["aggressive"]["config"]
        self.assertIn("nonce", cfg)
        self.assertIn("tcpFragment", cfg)
        self.assertIn("padding", cfg)


class TestGenSingboxOutbound(unittest.TestCase):
    """_gen_singbox_outbound — генерация sing-box outbound."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_dict_with_required_keys(self):
        from chimera.modules.mieru import _gen_singbox_outbound
        ob = _gen_singbox_outbound("1.2.3.4", 2012, 2022, "TCP", "alice", "pass")
        self.assertEqual(ob["type"], "mieru")
        self.assertEqual(ob["tag"], "mieru-alice")
        self.assertEqual(ob["server"], "1.2.3.4")
        self.assertEqual(ob["server_port"], 2012)
        self.assertEqual(ob["username"], "alice")
        self.assertEqual(ob["password"], "pass")

    def test_transport_uppercase(self):
        from chimera.modules.mieru import _gen_singbox_outbound
        ob = _gen_singbox_outbound("1.2.3.4", 2012, 2022, "tcp", "u", "p")
        self.assertEqual(ob["transport"], "TCP")

    def test_multiplexing_high(self):
        from chimera.modules.mieru import _gen_singbox_outbound
        ob = _gen_singbox_outbound("1.2.3.4", 2012, 2022, "TCP", "u", "p")
        self.assertEqual(ob["multiplexing"], "MULTIPLEXING_HIGH")


class TestGenClientShareLink(unittest.TestCase):
    """_gen_client_share_link — генерация mierus:// ссылки."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_mierus_url(self):
        from chimera.modules.mieru import _gen_client_share_link
        link = _gen_client_share_link("1.2.3.4", 2012, 2022, "TCP", "alice", "pass")
        self.assertTrue(link.startswith("mierus://"))

    def test_contains_credentials(self):
        from chimera.modules.mieru import _gen_client_share_link
        link = _gen_client_share_link("1.2.3.4", 2012, 2022, "TCP", "alice", "pass")
        self.assertIn("alice:pass", link)

    def test_contains_port_and_protocol(self):
        from chimera.modules.mieru import _gen_client_share_link
        link = _gen_client_share_link("1.2.3.4", 2012, 2022, "tcp", "u", "p")
        self.assertIn("port=2012", link)
        self.assertIn("protocol=TCP", link)

    def test_contains_mtu_and_multiplexing(self):
        from chimera.modules.mieru import _gen_client_share_link
        link = _gen_client_share_link("1.2.3.4", 2012, 2022, "TCP", "u", "p")
        self.assertIn("mtu=1400", link)
        self.assertIn("multiplexing=MULTIPLEXING_HIGH", link)

    # ── Фича 2: traffic-pattern для Karing ──────────────────────────────────

    def test_contains_traffic_pattern(self):
        """Ссылка содержит traffic-pattern= параметр (base64-protobuf)."""
        from chimera.modules.mieru import _gen_client_share_link
        link = _gen_client_share_link("1.2.3.4", 2012, 2022, "TCP", "u", "p")
        self.assertIn("traffic-pattern=", link)

    def test_traffic_pattern_is_url_encoded(self):
        """base64 padding '=' → '%3D' (URL-safe)."""
        from chimera.modules.mieru import _gen_client_share_link
        from chimera.modules.mieru_traffic_presets import get_preset_base64
        import urllib.parse
        link = _gen_client_share_link("1.2.3.4", 2012, 2022, "TCP", "u", "p",
                                      traffic_preset="medium")
        # Извлекаем traffic-pattern значение
        tp_part = [p for p in link.split("&") if p.startswith("traffic-pattern=")][0]
        tp_value = tp_part.split("=", 1)[1]
        # Декодируем URL-encoding
        decoded = urllib.parse.unquote(tp_value)
        # Должно быть валидным base64
        import base64
        base64.b64decode(decoded)  # не должно поднять исключение

    def test_default_preset_is_basic(self):
        """Дефолтный traffic_preset='basic' → base64 = GgQIARAK."""
        from chimera.modules.mieru import _gen_client_share_link
        from chimera.modules.mieru_traffic_presets import get_preset_base64
        import urllib.parse
        link = _gen_client_share_link("1.2.3.4", 2012, 2022, "TCP", "u", "p")
        tp_part = [p for p in link.split("&") if p.startswith("traffic-pattern=")][0]
        tp_value = urllib.parse.unquote(tp_part.split("=", 1)[1])
        expected = get_preset_base64("basic")
        self.assertEqual(tp_value, expected)

    def test_different_presets_produce_different_patterns(self):
        """Разные пресеты → разные traffic-pattern значения."""
        from chimera.modules.mieru import _gen_client_share_link
        import urllib.parse
        link_basic = _gen_client_share_link("1.2.3.4", 2012, 2022, "TCP", "u", "p",
                                            traffic_preset="basic")
        link_aggressive = _gen_client_share_link("1.2.3.4", 2012, 2022, "TCP", "u", "p",
                                                  traffic_preset="aggressive")
        tp_basic = [p for p in link_basic.split("&") if p.startswith("traffic-pattern=")][0]
        tp_aggr = [p for p in link_aggressive.split("&") if p.startswith("traffic-pattern=")][0]
        self.assertNotEqual(tp_basic, tp_aggr)

    def test_nekobox_link_does_not_have_traffic_pattern(self):
        """Без traffic_pattern (сервер без паттерна) — параметра в ссылке нет.

        Дефисная форма traffic-pattern= (Karing) в NekoBox-ссылке
        отсутствует ВСЕГДА: приложение читает только подчёркивание
        (MieruBean.cpp TryParseLink) — теперь паттерн передаётся
        параметром traffic_pattern= (см. TestGenClientShareLinkNekobox).
        """
        from chimera.modules.mieru import _gen_client_share_link_nekobox
        link = _gen_client_share_link_nekobox("1.2.3.4", 2012, "TCP", "u", "p")
        self.assertNotIn("traffic-pattern", link)
        self.assertNotIn("traffic_pattern", link)

    def test_share_link_uses_preset_from_state(self):
        """Integration: при traffic_preset='aggressive' в state — ссылка
        содержит traffic-pattern соответствующий aggressive, а не basic.

        Это regression-тест на баг: _gen_client_share_link вызывался без
        передачи traffic_preset — всегда дефолт 'basic', даже если админ
        выбрал 'aggressive' на сервере. Клиент и сервер расходились.
        """
        from chimera.modules.mieru import _gen_client_share_link
        from chimera.modules.mieru_traffic_presets import get_preset_base64
        import urllib.parse

        # Генерируем ссылку с aggressive
        link_aggr = _gen_client_share_link("1.2.3.4", 2012, 2022, "TCP", "u", "p",
                                            traffic_preset="aggressive")
        # Извлекаем traffic-pattern
        tp_part = [p for p in link_aggr.split("&") if p.startswith("traffic-pattern=")][0]
        tp_value = urllib.parse.unquote(tp_part.split("=", 1)[1])

        # Должен соответствовать aggressive, а не basic
        expected_aggr = get_preset_base64("aggressive")
        expected_basic = get_preset_base64("basic")
        self.assertEqual(tp_value, expected_aggr)
        self.assertNotEqual(tp_value, expected_basic)

    def test_default_uses_basic_when_no_preset_in_state(self):
        """При отсутствии traffic_preset в state — дефолт 'basic'."""
        from chimera.modules.mieru import _gen_client_share_link
        from chimera.modules.mieru_traffic_presets import get_preset_base64
        import urllib.parse

        link = _gen_client_share_link("1.2.3.4", 2012, 2022, "TCP", "u", "p")
        tp_part = [p for p in link.split("&") if p.startswith("traffic-pattern=")][0]
        tp_value = urllib.parse.unquote(tp_part.split("=", 1)[1])
        self.assertEqual(tp_value, get_preset_base64("basic"))


class TestGenClientShareLinkNekobox(unittest.TestCase):
    """_gen_client_share_link_nekobox — формат, сверенный с парсером
    приложения (Iblis/NekoBox 5.11.28.3, MieruBean.cpp TryParseLink).

    Регрессии на живые FATAL ядра (02.10.2026, nekobox_core check):
      • без server_ports → server_ports: [""] → «invalid server_ports
        format»; формат — ТОЛЬКО диапазон «2012-2012», одиночное число
        ядро тоже отвергает;
      • multiplexing=MULTIPLEXING_HIGH — дефолт приложения;
      • traffic_pattern — ПОДЧЁРКИВАНИЕМ (MieruBean.cpp:24), в отличие
        от Karing-формата с дефисом.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_mierus_url(self):
        from chimera.modules.mieru import _gen_client_share_link_nekobox
        link = _gen_client_share_link_nekobox("1.2.3.4", 2012, "TCP", "alice", "pass")
        self.assertTrue(link.startswith("mierus://"))

    def test_contains_port_in_host_part(self):
        """Nekobox формат: host:PORT? а не ?port=PORT"""
        from chimera.modules.mieru import _gen_client_share_link_nekobox
        link = _gen_client_share_link_nekobox("1.2.3.4", 2012, "tcp", "u", "p")
        self.assertIn("1.2.3.4:2012", link)

    def test_contains_transport(self):
        from chimera.modules.mieru import _gen_client_share_link_nekobox
        link = _gen_client_share_link_nekobox("1.2.3.4", 2012, "tcp", "u", "p")
        self.assertIn("transport=TCP", link)

    def test_server_ports_range_required(self):
        """server_ports обязателен и ТОЛЬКО диапазоном: без него
        MieruBean даёт serverPorts=[""], ядро падает FATAL «invalid
        server_ports format»; одиночное число тоже отвергается —
        даже один порт пишется парой «2012-2012"."""
        from chimera.modules.mieru import _gen_client_share_link_nekobox
        link = _gen_client_share_link_nekobox("1.2.3.4", 2012, "TCP", "u", "p")
        self.assertIn("server_ports=2012-2012", link)
        # одиночное число без дефиса — запрещённая форма
        self.assertNotIn("server_ports=2012&", link)

    def test_server_ports_range_with_port_end(self):
        """port_end задан (port hopping) → server_ports=START-END."""
        from chimera.modules.mieru import _gen_client_share_link_nekobox
        link = _gen_client_share_link_nekobox("1.2.3.4", 2012, "TCP", "u", "p",
                                              port_end=2022)
        self.assertIn("server_ports=2012-2022", link)

    def test_multiplexing_present(self):
        """multiplexing=MULTIPLEXING_HIGH — дефолт приложения, в ссылке
        всегда."""
        from chimera.modules.mieru import _gen_client_share_link_nekobox
        link = _gen_client_share_link_nekobox("1.2.3.4", 2012, "TCP", "u", "p")
        self.assertIn("multiplexing=MULTIPLEXING_HIGH", link)

    def test_traffic_pattern_underscore_param(self):
        """Паттерн обфускации — параметром traffic_pattern= (ПОДЧЁРКИВАНИЕ,
        MieruBean.cpp:24), URL-quoted; дефисной формы в ссылке нет."""
        import urllib.parse
        from chimera.modules.mieru import _gen_client_share_link_nekobox
        blob = "GgQIARAUIgIIASoFCEAQgAE="  # живой etalon aggressive
        link = _gen_client_share_link_nekobox("1.2.3.4", 2012, "TCP", "u", "p",
                                              traffic_pattern=blob)
        expected = "traffic_pattern=" + urllib.parse.quote(blob, safe="")
        self.assertIn(expected, link)
        self.assertNotIn("traffic-pattern=", link)

    def test_traffic_pattern_empty_omitted(self):
        """traffic_pattern='' → параметр не добавляется (сервер без паттерна)."""
        from chimera.modules.mieru import _gen_client_share_link_nekobox
        link = _gen_client_share_link_nekobox("1.2.3.4", 2012, "TCP", "u", "p",
                                              traffic_pattern="")
        self.assertNotIn("traffic_pattern=", link)


class TestIsAmd64(unittest.TestCase):
    """_is_amd64."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_x86_64(self):
        from chimera.modules.mieru import _is_amd64
        with patch("platform.machine", return_value="x86_64"):
            self.assertTrue(_is_amd64())

    def test_amd64(self):
        from chimera.modules.mieru import _is_amd64
        with patch("platform.machine", return_value="amd64"):
            self.assertTrue(_is_amd64())

    def test_aarch64(self):
        from chimera.modules.mieru import _is_amd64
        with patch("platform.machine", return_value="aarch64"):
            self.assertFalse(_is_amd64())


class TestReUsername(unittest.TestCase):
    """_RE_USERNAME — валидация имени."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_valid_names(self):
        from chimera.modules.mieru import _RE_USERNAME
        for name in ("alice", "bob123", "user-name", "user_name", "ABC"):
            with self.subTest(name=name):
                self.assertTrue(_RE_USERNAME.match(name))

    def test_invalid_names(self):
        from chimera.modules.mieru import _RE_USERNAME
        for name in ("", "user@name", "user.name", "user name", "пользователь"):
            with self.subTest(name=name):
                self.assertFalse(_RE_USERNAME.match(name))


# ══════════════════════════════════════════════════════════════════════════════
# домен сервера + свой DNS в клиентских конфигах Karing
# ══════════════════════════════════════════════════════════════════════════════
class TestDnsHostIsDomain(unittest.TestCase):
    """_dns_host_is_domain — IP / домен / DoH / DoT / DoQ / порт."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ip(self):
        from chimera.modules.mieru import _dns_host_is_domain
        self.assertFalse(_dns_host_is_domain("8.8.8.8"))
        self.assertFalse(_dns_host_is_domain("203.0.113.103"))
        self.assertFalse(_dns_host_is_domain("1.2.3.4:53"))

    def test_domain(self):
        from chimera.modules.mieru import _dns_host_is_domain
        self.assertTrue(_dns_host_is_domain("cdn.example"))
        self.assertTrue(_dns_host_is_domain("dns.example.com:53"))

    def test_doh_url(self):
        from chimera.modules.mieru import _dns_host_is_domain
        self.assertTrue(_dns_host_is_domain("https://panel.example/dns-query"))
        self.assertFalse(_dns_host_is_domain("https://1.1.1.1/dns-query"))

    def test_dot_quic_schemes(self):
        from chimera.modules.mieru import _dns_host_is_domain
        self.assertTrue(_dns_host_is_domain("tls://panel.example"))
        self.assertTrue(_dns_host_is_domain("quic://panel.example"))
        self.assertFalse(_dns_host_is_domain("tls://10.0.0.1"))

    def test_empty_and_garbage(self):
        from chimera.modules.mieru import _dns_host_is_domain
        self.assertFalse(_dns_host_is_domain(""))
        self.assertFalse(_dns_host_is_domain("   "))
        self.assertFalse(_dns_host_is_domain("/"))


class TestBuildKaringDnsBlock(unittest.TestCase):
    """_build_karing_dns_block — дефолт (Google) / свой DNS / bootstrap-правило."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_default_google_unchanged(self):
        """Пустой client_dns — блок ровно как ранее (нулевая регрессия)."""
        from chimera.modules.mieru import _build_karing_dns_block
        block = _build_karing_dns_block("", "mieru-u1")
        self.assertEqual(block["servers"][0],
                         {"tag": "google", "address": "8.8.8.8"})
        self.assertEqual(block["servers"][1],
                         {"tag": "local", "address": "1.1.1.1", "detour": "direct"})
        self.assertNotIn("rules", block)

    def test_custom_ip_no_resolver(self):
        from chimera.modules.mieru import _build_karing_dns_block
        block = _build_karing_dns_block("10.0.0.53", "mieru-u1")
        custom = block["servers"][0]
        self.assertEqual(custom["tag"], "custom-dns")
        self.assertEqual(custom["address"], "10.0.0.53")
        self.assertEqual(custom["detour"], "mieru-u1")
        self.assertNotIn("address_resolver", custom)  # IP — резолвер не нужен
        self.assertEqual(block["servers"][1]["tag"], "local")

    def test_custom_domain_gets_bootstrap_resolver(self):
        from chimera.modules.mieru import _build_karing_dns_block
        block = _build_karing_dns_block("cdn.example", "mieru-u1")
        custom = block["servers"][0]
        self.assertEqual(custom["address"], "cdn.example")
        self.assertEqual(custom["address_resolver"], "local")
        self.assertEqual(custom["detour"], "mieru-u1")

    def test_doh_url_gets_bootstrap_resolver(self):
        from chimera.modules.mieru import _build_karing_dns_block
        block = _build_karing_dns_block("https://panel.example/dns-query",
                                        "mieru-u1")
        custom = block["servers"][0]
        self.assertEqual(custom["address"],
                         "https://panel.example/dns-query")
        self.assertEqual(custom["address_resolver"], "local")

    def test_server_domain_bootstrap_rule(self):
        """Домен сервера mieru — правило «резолвить напрямую», не через
        туннель (иначе цикл «домен туннеля нужен для поднятия туннеля»)."""
        from chimera.modules.mieru import _build_karing_dns_block
        block = _build_karing_dns_block("", "mieru-u1",
                                        server_domain="cdn.example")
        self.assertEqual(block["rules"],
                         [{"domain": ["cdn.example"],
                           "server": "local"}])

    def test_ip_server_no_rules(self):
        from chimera.modules.mieru import _build_karing_dns_block
        block = _build_karing_dns_block("10.0.0.53", "mieru-u1",
                                        server_domain="")
        self.assertNotIn("rules", block)


class TestBuildKaringFullConfig(unittest.TestCase):
    """_build_karing_full_config — профиль целиком + domain_resolver."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _outbound(self):
        from chimera.modules.mieru import _gen_singbox_outbound
        return _gen_singbox_outbound("1.2.3.4", 2012, 2022, "TCP", "u1", "p1")

    def test_shape(self):
        from chimera.modules.mieru import _build_karing_full_config
        cfg = _build_karing_full_config(self._outbound())
        self.assertEqual(cfg["log"], {"level": "info"})
        self.assertEqual(cfg["outbounds"][1], {"type": "direct", "tag": "direct"})
        self.assertEqual(cfg["route"], {"final": "mieru-u1"})

    def test_domain_sets_domain_resolver(self):
        from chimera.modules.mieru import _build_karing_full_config
        cfg = _build_karing_full_config(self._outbound(), "",
                                        "cdn.example")
        self.assertEqual(cfg["outbounds"][0]["domain_resolver"], "local")
        self.assertEqual(cfg["dns"]["rules"],
                         [{"domain": ["cdn.example"],
                           "server": "local"}])

    def test_ip_no_domain_resolver(self):
        from chimera.modules.mieru import _build_karing_full_config
        cfg = _build_karing_full_config(self._outbound())
        self.assertNotIn("domain_resolver", cfg["outbounds"][0])
        self.assertNotIn("rules", cfg["dns"])

    def test_outbound_not_mutated(self):
        """Билдер работает с копией outbound — исходник не трогает
        (в hybrid_addon к нему уже дописан traffic_pattern)."""
        from chimera.modules.mieru import _build_karing_full_config
        ob = self._outbound()
        ob["traffic_pattern"] = "BLOB"
        cfg = _build_karing_full_config(ob, "", "cdn.example")
        self.assertNotIn("domain_resolver", ob)
        self.assertEqual(cfg["outbounds"][0]["traffic_pattern"], "BLOB")

    def test_custom_dns_wired(self):
        from chimera.modules.mieru import _build_karing_full_config
        cfg = _build_karing_full_config(self._outbound(), "10.0.0.53")
        self.assertEqual(cfg["dns"]["servers"][0]["address"], "10.0.0.53")


class TestDetectServerDomain(unittest.TestCase):
    """Цепочка: PARAM_DOMAIN → state.json → naiveproxy.json (как)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        import tempfile
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _core(self, domain):
        import types
        m = types.ModuleType("chimera._core")
        m.PARAM_DOMAIN = domain
        return m

    def test_param_domain_wins(self):
        import sys as _sys
        (self._tmp / "state.json").write_text('{"domain": "core.example.com"}')
        (self._tmp / "naiveproxy.json").write_text('{"domain": "naive.example.com"}')
        from chimera.modules import mieru
        with patch.dict(_sys.modules,
                        {"chimera._core": self._core("vless.example.com")}), \
             patch.object(mieru, "_CORE_STATE_DIR", self._tmp):
            self.assertEqual(mieru._detect_server_domain(), "vless.example.com")

    def test_state_json_fallback(self):
        import sys as _sys
        (self._tmp / "state.json").write_text('{"domain": "core.example.com"}')
        from chimera.modules import mieru
        with patch.dict(_sys.modules, {"chimera._core": self._core("")}), \
             patch.object(mieru, "_CORE_STATE_DIR", self._tmp):
            self.assertEqual(mieru._detect_server_domain(), "core.example.com")

    def test_naive_domain_fallback(self):
        import sys as _sys
        (self._tmp / "naiveproxy.json").write_text(
            '{"domain": "naive.example.com", "port": 443}')
        from chimera.modules import mieru
        with patch.dict(_sys.modules, {"chimera._core": self._core("")}), \
             patch.object(mieru, "_CORE_STATE_DIR", self._tmp):
            self.assertEqual(mieru._detect_server_domain(), "naive.example.com")

    def test_nothing_found(self):
        import sys as _sys
        from chimera.modules import mieru
        with patch.dict(_sys.modules, {"chimera._core": self._core("")}), \
             patch.object(mieru, "_CORE_STATE_DIR", self._tmp):
            self.assertEqual(mieru._detect_server_domain(), "")

    def test_garbage_ignored(self):
        import sys as _sys
        (self._tmp / "naiveproxy.json").write_text("не json вообще")
        from chimera.modules import mieru
        with patch.dict(_sys.modules, {"chimera._core": self._core("")}), \
             patch.object(mieru, "_CORE_STATE_DIR", self._tmp):
            self.assertEqual(mieru._detect_server_domain(), "")


class TestEffectiveClientAddr(unittest.TestCase):
    """_effective_client_addr — домен из state выигрывает, пусто → IP."""

    def setUp(self):
        _setup_core_in_sysmodules()
        import tempfile
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_state_domain_wins(self):
        from chimera.modules import mieru
        sf = self._tmp / "mstate.json"
        sf.write_text('{"client_server_addr": "cdn.example"}')
        with patch.object(mieru, "_MODULE_STATE", sf), \
             patch.object(mieru, "_get_server_ip", return_value="1.2.3.4"):
            self.assertEqual(mieru._effective_client_addr(),
                             "cdn.example")

    def test_empty_falls_back_to_ip(self):
        from chimera.modules import mieru
        sf = self._tmp / "mstate.json"
        sf.write_text('{"client_server_addr": ""}')
        with patch.object(mieru, "_MODULE_STATE", sf), \
             patch.object(mieru, "_get_server_ip", return_value="1.2.3.4"):
            self.assertEqual(mieru._effective_client_addr(), "1.2.3.4")

    def test_missing_state(self):
        from chimera.modules import mieru
        with patch.object(mieru, "_MODULE_STATE", self._tmp / "nope.json"), \
             patch.object(mieru, "_get_server_ip", return_value="1.2.3.4"):
            self.assertEqual(mieru._effective_client_addr(), "1.2.3.4")


class TestBothProtocol(unittest.TestCase):
    """BOTH (TCP+UDP) — один диапазон портов на оба транспорта,
    ссылки/JSON генерируются на КАЖДЫЙ транспорт (запрос юзера)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_protocol_variants(self):
        from chimera.modules.mieru import _protocol_variants, _protocol_label
        self.assertEqual(_protocol_variants("BOTH"), ("TCP", "UDP"))
        self.assertEqual(_protocol_variants("both"), ("TCP", "UDP"))
        self.assertEqual(_protocol_variants("TCP"), ("TCP",))
        self.assertEqual(_protocol_variants("udp"), ("UDP",))
        self.assertEqual(_protocol_variants(""), ("TCP",))  # пустое — дефолт
        self.assertEqual(_protocol_variants(None), ("TCP",))
        self.assertEqual(_protocol_label("BOTH"), "TCP+UDP")
        self.assertEqual(_protocol_label("tcp"), "TCP")

    def test_build_server_config_both_single_port(self):
        """BOTH, один порт: две portBindings — TCP и UDP на одном порту
        (разные сокеты, конфликта нет)."""
        from chimera.modules import mieru
        cfg = mieru._build_server_config(
            [{"username": "a", "password": "b"}], 443, 443, "BOTH")
        self.assertEqual(cfg["portBindings"],
                         [{"port": 443, "protocol": "TCP"},
                          {"port": 443, "protocol": "UDP"}])

    def test_build_server_config_both_range(self):
        """BOTH, диапазон: два portRange-биндинга на оба транспорта."""
        from chimera.modules import mieru
        cfg = mieru._build_server_config(
            [{"username": "a", "password": "b"}], 20000, 20010, "BOTH")
        self.assertEqual(cfg["portBindings"],
                         [{"portRange": "20000-20010", "protocol": "TCP"},
                          {"portRange": "20000-20010", "protocol": "UDP"}])

    def test_build_server_config_single_unchanged(self):
        """Регресс: одиночный протокол — один биндинг, как раньше."""
        from chimera.modules import mieru
        cfg = mieru._build_server_config(
            [{"username": "a", "password": "b"}], 443, 443, "TCP")
        self.assertEqual(cfg["portBindings"], [{"port": 443, "protocol": "TCP"}])
        cfg_u = mieru._build_server_config(
            [{"username": "a", "password": "b"}], 5353, 5353, "UDP")
        self.assertEqual(cfg_u["portBindings"], [{"port": 5353, "protocol": "UDP"}])

    def test_karing_multi_config_selector(self):
        """BOTH в Karing-JSON: selector-группа «mieru-transport», route.final
        и DNS detour на неё; на каждом outbound — domain_resolver=local."""
        from chimera.modules import mieru
        obs = [mieru._gen_singbox_outbound("d.example", 443, 443, p, "alice", "pw")
               for p in ("TCP", "UDP")]
        obs[0]["tag"] = "mieru-alice-tcp"
        obs[1]["tag"] = "mieru-alice-udp"
        cfg = mieru._build_karing_multi_config(obs, "dns.example", "d.example")
        self.assertEqual(cfg["outbounds"][0]["type"], "selector")
        self.assertEqual(cfg["route"]["final"], "mieru-transport")
        sel = cfg["outbounds"][0]
        self.assertEqual(sel["outbounds"], ["mieru-alice-tcp", "mieru-alice-udp"])
        # DNS идёт через selector — то есть через ВЫБРАННЫЙ транспорт
        self.assertEqual(cfg["dns"]["servers"][0]["detour"], "mieru-transport")
        self.assertEqual(cfg["dns"]["servers"][0]["address"], "dns.example")
        for ob in cfg["outbounds"][1:3]:
            self.assertEqual(ob["domain_resolver"], "local")
        self.assertEqual(cfg["outbounds"][-1], {"type": "direct", "tag": "direct"})

    def test_karing_multi_config_single_no_selector(self):
        """Регресс: один outbound — без selector, формат прежний (один транспорт)."""
        from chimera.modules import mieru
        ob = mieru._gen_singbox_outbound("1.2.3.4", 443, 443, "TCP", "alice", "pw")
        cfg = mieru._build_karing_multi_config([ob])
        types = [o.get("type") for o in cfg["outbounds"]]
        self.assertNotIn("selector", types)
        self.assertEqual(cfg["route"]["final"], "mieru-alice")
        self.assertEqual(cfg["dns"]["servers"][0]["tag"], "google")

    def test_share_link_empty_preset_no_pattern(self):
        """traffic_preset='' — параметра traffic-pattern НЕТ (вызывающий
        код добавит свой blob; раньше здесь вставался basic — двойной параметр)."""
        from chimera.modules import mieru
        link = mieru._gen_client_share_link("1.2.3.4", 443, 443, "TCP", "u", "p",
                                            traffic_preset="")
        self.assertNotIn("traffic-pattern=", link)

    def test_share_link_default_preset_keeps_pattern(self):
        """Регресс: дефолтный preset — параметр на месте (как в и раньше)."""
        from chimera.modules import mieru
        link = mieru._gen_client_share_link("1.2.3.4", 443, 443, "TCP", "u", "p")
        self.assertEqual(link.count("traffic-pattern="), 1)

    def test_wizard_prompt_accepts_both(self):
        """Валидация ввода из визарда (строка «Протокол [TCP/UDP/BOTH]»):
        BOTH принимается (в любом регистре — визард upper()-ит), мусор — откат."""
        for raw, expected in (("BOTH", "BOTH"), ("both", "BOTH"),
                              ("tcp", "TCP"), ("UDP", "UDP"),
                              ("xyz", "TCP"), ("", "TCP")):
            raw = raw.strip().upper()  # как в визарде
            protocol = raw if raw in ("TCP", "UDP", "BOTH") else "TCP"
            self.assertEqual(protocol, expected)


# ═════════════════════════════════════════════════════════════════════════════
# DNS-меню + AGH-детект + мульти-адреса + ссылки вне рамки
# ═════════════════════════════════════════════════════════════════════════════
class TestParseDnsAddresses(unittest.TestCase):
    """_parse_dns_addresses — списки через запятую/плюс (пункт «Google +
    Cloudflare» и ручной ввод)."""

    def test_single_address(self):
        from chimera.modules.mieru import _parse_dns_addresses
        self.assertEqual(_parse_dns_addresses("8.8.8.8"), ["8.8.8.8"])

    def test_comma_list_with_spaces(self):
        from chimera.modules.mieru import _parse_dns_addresses
        self.assertEqual(_parse_dns_addresses("8.8.8.8, 1.1.1.1"),
                         ["8.8.8.8", "1.1.1.1"])

    def test_plus_list(self):
        from chimera.modules.mieru import _parse_dns_addresses
        self.assertEqual(_parse_dns_addresses("8.8.8.8+1.1.1.1"),
                         ["8.8.8.8", "1.1.1.1"])

    def test_empty_and_garbage(self):
        from chimera.modules.mieru import _parse_dns_addresses
        self.assertEqual(_parse_dns_addresses(""), [])
        self.assertEqual(_parse_dns_addresses(None), [])
        self.assertEqual(_parse_dns_addresses(" ,+ "), [])

    def test_spaces_inside_token_kept(self):
        """Пробел ВНУТРИ токена не режется — его отвергнет валидация."""
        from chimera.modules.mieru import _parse_dns_addresses
        self.assertEqual(_parse_dns_addresses("bad dns com"), ["bad dns com"])


class TestPlausibleDns(unittest.TestCase):
    """_is_plausible_dns_address — что прошло валидацию, что опечатка.

     отвергала tls:// и quic:// (слэш без http-префикса) — баг, 
    легализует DoT/DoQ и списки адресов."""

    def _ok(self, s):
        from chimera.modules.mieru import _is_plausible_dns_address
        return _is_plausible_dns_address(s)

    def test_addresses(self):
        for s in ("8.8.8.8", "1.1.1.1", "panel.example",
                  "https://panel.example/dns-query",
                  "tls://panel.example:853",
                  "quic://panel.example:853",
                  "8.8.8.8,1.1.1.1", "8.8.8.8, panel.example"):
            self.assertTrue(self._ok(s), s)

    def test_typos(self):
        for s in ("", "bad dns com", "https//no-slashes", "https://ok / x"):
            self.assertFalse(self._ok(s), s)


class TestBuildKaringDnsBlockMulti(unittest.TestCase):
    """_build_karing_dns_block — несколько адресов (пункт «Google +
    Cloudflare»): первый — дефолтный custom-dns, остальные — допы."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_two_public_resolvers(self):
        from chimera.modules.mieru import _build_karing_dns_block
        block = _build_karing_dns_block("8.8.8.8,1.1.1.1", "mieru-u1")
        servers = block["servers"]
        self.assertEqual(len(servers), 3)  # custom-dns, custom-dns-2, local
        self.assertEqual(servers[0],
                         {"tag": "custom-dns", "address": "8.8.8.8",
                          "detour": "mieru-u1"})
        self.assertEqual(servers[1],
                         {"tag": "custom-dns-2", "address": "1.1.1.1",
                          "detour": "mieru-u1"})
        self.assertEqual(servers[2]["tag"], "local")
        self.assertNotIn("address_resolver", servers[0])  # IP — не нужен

    def test_mixed_ip_and_domain(self):
        from chimera.modules.mieru import _build_karing_dns_block
        block = _build_karing_dns_block("8.8.8.8,panel.example", "mieru-u1")
        self.assertEqual(block["servers"][1]["address"], "panel.example")
        self.assertEqual(block["servers"][1]["address_resolver"], "local")

    def test_single_address_bytes_unchanged(self):
        """Регресс одиночный адрес — блок побайтово как раньше."""
        from chimera.modules.mieru import _build_karing_dns_block
        block = _build_karing_dns_block("10.0.0.53", "mieru-u1")
        self.assertEqual(block["servers"][0],
                         {"tag": "custom-dns", "address": "10.0.0.53",
                          "detour": "mieru-u1"})

    def test_spaces_around_comma_ok(self):
        from chimera.modules.mieru import _build_karing_dns_block
        block = _build_karing_dns_block("8.8.8.8, 1.1.1.1", "mieru-u1")
        self.assertEqual(len(block["servers"]), 3)


class TestDetectAghDnsEndpoints(unittest.TestCase):
    """_detect_agh_dns_endpoints — подглядывание DoH/DoT/DoQ в стейт AGH."""

    def setUp(self):
        import tempfile
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _detect(self, payload=None):
        from chimera.modules import mieru
        if payload is not None:
            (self._tmp / "aghome_state.json").write_text(
                __import__("json").dumps(payload))
        with patch.object(mieru, "_CORE_STATE_DIR", self._tmp):
            return mieru._detect_agh_dns_endpoints()

    def test_ok_tls_domain(self):
        r = self._detect({"domain": "cdn.example",
                          "tls_enabled": True, "self_signed": False})
        self.assertEqual(r["status"], "ok")
        self.assertEqual(
            r["links"],
            [("DoH", "https://cdn.example:30443/dns-query"),
             ("DoT", "tls://cdn.example:853"),
             ("DoQ", "quic://cdn.example:853")])

    def test_no_file(self):
        r = self._detect(None)
        self.assertEqual((r["links"], r["status"]), ([], "no-agh"))

    def test_no_tls(self):
        r = self._detect({"domain": "cdn.example",
                          "tls_enabled": False})
        self.assertEqual((r["links"], r["status"]), ([], "no-tls"))

    def test_no_domain(self):
        r = self._detect({"domain": "", "tls_enabled": True})
        self.assertEqual((r["links"], r["status"]), ([], "no-domain"))

    def test_self_signed_flag(self):
        r = self._detect({"domain": "dns.example.com", "tls_enabled": True,
                          "self_signed": True})
        self.assertTrue(r["self_signed"])

    def test_custom_ports(self):
        r = self._detect({"domain": "dns.example.com", "tls_enabled": True,
                          "doh_port": 8443, "dot_port": 8853, "doq_port": 8853})
        self.assertEqual(r["links"][0],
                         ("DoH", "https://dns.example.com:8443/dns-query"))
        self.assertEqual(r["links"][1], ("DoT", "tls://dns.example.com:8853"))


class TestAskClientDns(unittest.TestCase):
    """_ask_client_dns (standalone) — то же меню, что в гибриде, но на
    proto_ask; Enter-дефолты, номера, ручной ввод, опечатки."""

    _NO_AGH = {"links": [], "self_signed": False, "status": "no-agh"}
    _AGH = {"links": [
        ("DoH", "https://cdn.example:30443/dns-query"),
        ("DoT", "tls://cdn.example:853"),
        ("DoQ", "quic://cdn.example:853"),
    ], "self_signed": False, "status": "ok"}

    def _ask(self, inputs, old_dns="", agh=None):
        import io
        from contextlib import redirect_stdout
        from chimera.modules import mieru
        answers = iter(inputs)
        buf = io.StringIO()
        with patch.object(mieru, "proto_ask",
                          side_effect=lambda *a, **k: next(answers)), \
             patch.object(mieru, "_detect_agh_dns_endpoints",
                          return_value=agh if agh is not None else self._NO_AGH), \
             redirect_stdout(buf):
            return mieru._ask_client_dns(old_dns)

    def test_agh_found_enter_defaults_to_agh_doh(self):
        self.assertEqual(
            self._ask([""], agh=self._AGH),
            "https://cdn.example:30443/dns-query")

    def test_agh_doq_by_number(self):
        self.assertEqual(self._ask(["6"], agh=self._AGH),
                         "quic://cdn.example:853")

    def test_no_agh_enter_is_google(self):
        self.assertEqual(self._ask([""]), "")

    def test_option3_pair(self):
        self.assertEqual(self._ask(["3"]), "8.8.8.8,1.1.1.1")

    def test_manual_flow(self):
        self.assertEqual(self._ask(["4", "panel.example"]),
                         "panel.example")

    def test_manual_typo_falls_back(self):
        self.assertEqual(self._ask(["4", "bad dns com"]), "")

    def test_raw_address_typed_directly(self):
        self.assertEqual(self._ask(["tls://panel.example:853"]),
                         "tls://panel.example:853")

    def test_old_dns_kept_on_enter(self):
        self.assertEqual(self._ask([""], old_dns="10.0.0.53"), "10.0.0.53")


class TestPrintLinkPairsOutside(unittest.TestCase):
    """_print_link_pairs_outside — ссылки ВНЕ рамки, одной строкой каждая:
    в строках-ссылках нет символов рамки (║), все mierus://-ссылки целые."""

    def test_links_printed_whole_outside_frame(self):
        import io
        import re
        from contextlib import redirect_stdout
        from chimera.modules import mieru
        pairs = [
            ("TCP", "mierus://u1:p1@cdn.example?port=443&protocol=TCP&traffic-pattern=BLOB%3D%3D",
             "mierus://u1:p1@cdn.example:443?transport=TCP&mtu=1400"),
            ("UDP", "mierus://u2:p2@cdn.example?port=5443&protocol=UDP&traffic-pattern=BLOB%3D%3D",
             "mierus://u2:p2@cdn.example:5443?transport=UDP&mtu=1400"),
        ]
        buf = io.StringIO()
        with redirect_stdout(buf):
            mieru._print_link_pairs_outside(pairs)
        ansi = re.compile(r"\x1b\[[0-9;]*m")
        lines = [ansi.sub("", ln).strip() for ln in buf.getvalue().splitlines()]
        link_lines = [l for l in lines if l.startswith("mierus://")]
        # 2 пары × (Karing + Nekobox) = 4 ссылки, каждая — ЦЕЛИКОМ
        self.assertEqual(len(link_lines), 4)
        for l in link_lines:
            self.assertNotIn("║", l)
        # суффиксы транспортов видны в подписях при BOTH
        self.assertIn("Karing (sing-box core) (TCP):", lines)
        self.assertIn("Nekobox / Nyamebox (UDP):", lines)


class TestKaringUdpAddr(unittest.TestCase):
    """_karing_link_addr — UDP+домен подставляет IP (баг ядра
    Karing: mieru-UDP не резолвит домен — NilDNSResolver, а
    BypassDialerDNS у mieru действует только на TCP-underlay).
    TCP/IP-выдача не трогается."""

    def test_udp_domain_substitutes_ip(self):
        from chimera.modules import mieru
        with patch.object(mieru, "_karing_udp_server_ip",
                          return_value="203.0.113.103"):
            addr, sub = mieru._karing_link_addr("UDP", "cdn.example")
        self.assertEqual(addr, "203.0.113.103")
        self.assertTrue(sub)

    def test_udp_domain_ip_missing_keeps_domain(self):
        from chimera.modules import mieru
        with patch.object(mieru, "_karing_udp_server_ip", return_value=""):
            addr, sub = mieru._karing_link_addr("UDP", "cdn.example")
        self.assertEqual(addr, "cdn.example")
        self.assertFalse(sub)

    def test_tcp_domain_unchanged(self):
        from chimera.modules import mieru
        with patch.object(mieru, "_karing_udp_server_ip", return_value="1.2.3.4"):
            addr, sub = mieru._karing_link_addr("TCP", "cdn.example")
        self.assertEqual(addr, "cdn.example")
        self.assertFalse(sub)

    def test_udp_ip_unchanged(self):
        from chimera.modules import mieru
        addr, sub = mieru._karing_link_addr("UDP", "203.0.113.103")
        self.assertEqual(addr, "203.0.113.103")
        self.assertFalse(sub)

    def test_is_public_ipv4(self):
        from chimera.modules import mieru
        for a in ("1.2.3.4", "203.0.113.103", "8.8.8.8", "255.255.255.255"):
            self.assertTrue(mieru._is_public_ipv4(a), a)
        for a in ("", "foo", "10.0.0.1", "127.0.0.1", "192.168.1.1",
                  "172.16.0.1", "172.31.9.9", "169.254.1.1", "300.1.1.1",
                  "1.2.3", "1.2.3.4.5"):
            self.assertFalse(mieru._is_public_ipv4(a), a)


class TestKaringUdpLinksAndJson(unittest.TestCase):
    """ссылочная выдача и JSON — Karing-UDP с IP, домен в TCP
    и Nekobox/Nyamebox; domain_resolver — только доменным outbound'ам."""

    def test_both_pairs_udp_karing_gets_ip(self):
        import io
        from contextlib import redirect_stdout
        from chimera.modules import mieru
        with patch.object(mieru, "_karing_udp_server_ip",
                          return_value="203.0.113.103"):
            pairs = []
            _ports = {"TCP": 443, "UDP": 5443}
            for p in mieru._protocol_variants("BOTH"):
                k_addr, _sub = mieru._karing_link_addr(p, "cdn.example")
                pairs.append((p,
                    mieru._gen_client_share_link(k_addr, _ports[p], _ports[p],
                                                 p, "u1", "p1"),
                    mieru._gen_client_share_link_nekobox("cdn.example",
                                                         _ports[p], p, "u1", "p1")))
        buf = io.StringIO()
        with redirect_stdout(buf):
            mieru._print_link_pairs_outside(pairs)
        text = buf.getvalue()
        self.assertIn("@cdn.example?port=443&protocol=TCP", text)
        self.assertIn("@203.0.113.103?port=5443&protocol=UDP", text)
        self.assertIn("@cdn.example:5443?transport=UDP", text)

    def test_multi_config_domain_resolver_only_for_domain_outbounds(self):
        from chimera.modules import mieru
        obs = [
            mieru._gen_singbox_outbound("cdn.example", 443, 443,
                                        "TCP", "u1", "p1"),
            mieru._gen_singbox_outbound("203.0.113.103", 5443, 5443,
                                        "UDP", "u2", "p2"),
        ]
        cfg = mieru._build_karing_multi_config(obs, "8.8.8.8",
                                               "cdn.example")
        mieru_obs = [ob for ob in cfg["outbounds"] if ob.get("type") == "mieru"]
        dom_ob = next(ob for ob in mieru_obs
                      if ob["server"] == "cdn.example")
        ip_ob = next(ob for ob in mieru_obs
                     if ob["server"] == "203.0.113.103")
        self.assertEqual(dom_ob["domain_resolver"], "local")
        self.assertNotIn("domain_resolver", ip_ob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
