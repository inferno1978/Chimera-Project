#!/usr/bin/env python3
"""
tests/test_chain_nodes.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/chain_nodes.py — управление exit-нодами
каскада (Режим B), генерация Xray-конфигов для Entry/Exit, мульти-нодовая
балансировка.

Покрывает:
  1. _nodes_from_state — нормализация state.json → список exit-нод
     (новый формат chain_nodes + legacy chain_exit_*).
  2. _make_exit_node_config — построение Xray-конфига для exit-ноды
     (xhttp, reality и xhttp_reality ветки).
  3. _speed_test_node_latency — форматирование latency (mocked socket).
  4. _speed_test_node_geo — парсинг JSON-ответа ip-api (mocked _run).
  5. _access_log_bytes_per_node — парсинг access.log, сопоставление тегов.
  6. РЕГРЕССИЯ: Mode B + PROTOCOL_MODE="xhttp" → inbound НЕ должен
     биндиться напрямую с tlsSettings на 0.0.0.0:443 — только через
     loopback (127.0.0.1:XHTTP_BACKEND_PORT) с Nginx-терминацией TLS.

Реального subprocess/systemctl/iptables/curl — нет, всё через mock.
Реальной записи в /var, /etc, /usr — нет, через tempfile + patch путей.
"""
from __future__ import annotations

import json
import socket
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Загружает _core.py через exec и регистрирует фейк в sys.modules.

    Патчит Path.mkdir/touch/chmod, os.chown, os.geteuid — чтобы код _core.py
    выполнялся без побочных эффектов на ФС и без требования root.
    Копируется из tests/test_health.py без изменений (эталонный паттерн).
    """
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core


# ══════════════════════════════════════════════════════════════════════════════
#  _nodes_from_state — нормализация state.json → список нод
# ══════════════════════════════════════════════════════════════════════════════
class TestNodesFromState(unittest.TestCase):
    """_nodes_from_state: новый формат + legacy + edge cases."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_new_format_chain_nodes_list(self):
        """Новый формат: state['chain_nodes'] = [...] — возвращает как есть."""
        from chimera.modules.chain_nodes import _nodes_from_state
        nodes = [
            {"host": "1.1.1.1", "port": 443, "uuid": "u1"},
            {"host": "2.2.2.2", "port": 8443, "uuid": "u2"},
        ]
        result = _nodes_from_state({"chain_nodes": nodes})
        self.assertEqual(result, nodes)

    def test_new_format_empty_list(self):
        """chain_nodes = [] — возвращает пустой список."""
        from chimera.modules.chain_nodes import _nodes_from_state
        self.assertEqual(_nodes_from_state({"chain_nodes": []}), [])

    def test_legacy_format_single_node(self):
        """Старый формат: chain_exit_host/port/uuid/... → список из одной ноды."""
        from chimera.modules.chain_nodes import _nodes_from_state
        state = {
            "chain_exit_host":    "exit.example.com",
            "chain_exit_port":    8443,
            "chain_exit_uuid":    "test-uuid",
            "chain_exit_pubkey":  "PUB_KEY",
            "chain_exit_shortid": "abcd1234",
            "chain_exit_sni":     "sni.example.com",
            "chain_exit_fp":      "firefox",
        }
        result = _nodes_from_state(state)
        self.assertEqual(len(result), 1)
        n = result[0]
        self.assertEqual(n["host"], "exit.example.com")
        self.assertEqual(n["port"], 8443)
        self.assertEqual(n["uuid"], "test-uuid")
        self.assertEqual(n["pubkey"], "PUB_KEY")
        self.assertEqual(n["shortid"], "abcd1234")
        self.assertEqual(n["sni"], "sni.example.com")
        self.assertEqual(n["fp"], "firefox")

    def test_legacy_format_default_fp_is_chrome(self):
        """В legacy-формате fp по умолчанию = 'chrome'."""
        from chimera.modules.chain_nodes import _nodes_from_state
        state = {"chain_exit_host": "h.example.com"}
        # port также по умолчанию 443
        result = _nodes_from_state(state)
        self.assertEqual(result[0]["fp"], "chrome")
        self.assertEqual(result[0]["port"], 443)

    def test_empty_state_returns_empty_list(self):
        """Пустой state — пустой список."""
        from chimera.modules.chain_nodes import _nodes_from_state
        self.assertEqual(_nodes_from_state({}), [])

    def test_legacy_host_empty_returns_empty(self):
        """legacy-формат, но host пустой — пустой список."""
        from chimera.modules.chain_nodes import _nodes_from_state
        self.assertEqual(_nodes_from_state({"chain_exit_host": ""}), [])

    def test_chain_nodes_null_falls_back_to_legacy(self):
        """chain_nodes=null + есть chain_exit_host → legacy fallback."""
        from chimera.modules.chain_nodes import _nodes_from_state
        state = {
            "chain_nodes": None,  # не list → fallback на legacy
            "chain_exit_host": "legacy.example.com",
            "chain_exit_port": 443,
        }
        result = _nodes_from_state(state)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["host"], "legacy.example.com")

    def test_chain_nodes_not_list_ignored(self):
        """chain_nodes — не list (например dict) → fallback на legacy."""
        from chimera.modules.chain_nodes import _nodes_from_state
        state = {
            "chain_nodes": {"host": "this is wrong type"},
            "chain_exit_host": "real.example.com",
        }
        result = _nodes_from_state(state)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["host"], "real.example.com")


# ══════════════════════════════════════════════════════════════════════════════
#  _make_exit_node_config — построение Xray-конфига для exit-ноды
# ══════════════════════════════════════════════════════════════════════════════
class TestMakeExitNodeConfig(unittest.TestCase):
    """_make_exit_node_config: построение Xray-конфига для exit-ноды."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()

    def test_xhttp_branch_builds_tls_inbound(self):
        """xhttp-нода: inbound с tlsSettings + сертификаты по sni."""
        from chimera.modules import chain_nodes
        # Патчим только две helpers из core — остальное берётся из fake_core.
        with patch.object(self._fake_core, "_build_exit_xhttp_settings",
                          return_value={"path": "/x", "mode": "stream-up"}), \
             patch.object(self._fake_core, "_build_sockopt",
                          return_value={"tcpFastOpen": True}):
            nd = {
                "proto": "xhttp",
                "port": 443,
                "uuid": "11111111-2222-3333-4444-555555555555",
                "sni":  "exit.example.com",
                "host": "1.2.3.4",
            }
            cfg = chain_nodes._make_exit_node_config(nd)

        # Inbound — VLESS+xhttp+TLS (для exit-ноды это корректно: TLS терминирует
        # сама exit-нода, на ней лежат сертификаты).
        inb = cfg["inbounds"][0]
        self.assertEqual(inb["protocol"], "vless")
        self.assertEqual(inb["listen"], "::")
        self.assertEqual(inb["port"], 443)
        ss = inb["streamSettings"]
        self.assertEqual(ss["network"], "xhttp")
        self.assertEqual(ss["security"], "tls")
        self.assertIn("tlsSettings", ss)
        certs = ss["tlsSettings"]["certificates"]
        self.assertEqual(len(certs), 1)
        self.assertIn("exit.example.com", certs[0]["certificateFile"])
        self.assertIn("exit.example.com", certs[0]["keyFile"])
        # xhttpSettings делегированы helper'у
        self.assertEqual(ss["xhttpSettings"]["path"], "/x")
        # Client-email = entry@chain
        self.assertEqual(inb["settings"]["clients"][0]["email"], "entry@chain")

    def test_reality_branch_builds_reality_inbound(self):
        """reality-нода: inbound с realitySettings + placeholder приватного ключа."""
        from chimera.modules import chain_nodes
        with patch.object(self._fake_core, "_build_exit_xhttp_settings",
                          return_value={}), \
             patch.object(self._fake_core, "_build_sockopt",
                          return_value={"tcpFastOpen": True}), \
             patch.object(self._fake_core, "XTLS_FLOW", "xtls-rprx-vision",
                          create=True):
            nd = {
                "proto": "reality",
                "port": 443,
                "uuid": "11111111-2222-3333-4444-555555555555",
                "sni":  "reality.exit.com",
                "pubkey":  "PUB",
                "shortid": "abcd1234",
                "host": "1.2.3.4",
            }
            cfg = chain_nodes._make_exit_node_config(nd)

        inb = cfg["inbounds"][0]
        self.assertEqual(inb["protocol"], "vless")
        ss = inb["streamSettings"]
        self.assertEqual(ss["security"], "reality")
        self.assertEqual(ss["network"], "tcp")
        self.assertIn("realitySettings", ss)
        rs = ss["realitySettings"]
        self.assertEqual(rs["publicKey"], "PUB")
        self.assertEqual(rs["shortIds"], ["abcd1234"])
        self.assertEqual(rs["serverNames"], ["reality.exit.com"])
        # Приватный ключ требует ручной вставки (явный placeholder в коде)
        self.assertIn("privateKey", rs)
        # Comment поясняет назначение конфига
        self.assertIn("REALITY", cfg["_comment"])

    def test_default_proto_is_reality(self):
        """Если в nd нет поля 'proto' — fallback на reality-ветку."""
        from chimera.modules import chain_nodes
        with patch.object(self._fake_core, "_build_exit_xhttp_settings",
                          return_value={}), \
             patch.object(self._fake_core, "_build_sockopt",
                          return_value={"tcpFastOpen": True}), \
             patch.object(self._fake_core, "XTLS_FLOW", "",
                          create=True):
            nd = {
                "port": 443,
                "uuid": "11111111-2222-3333-4444-555555555555",
                "sni":  "exit.example.com",
                "pubkey": "PUB",
                "shortid": "abcd1234",
            }
            cfg = chain_nodes._make_exit_node_config(nd)
        inb = cfg["inbounds"][0]
        self.assertEqual(inb["streamSettings"]["security"], "reality")

    def test_config_has_dns_and_routing_blocks(self):
        """Конфиг содержит DNS, outbounds (direct+BLOCK), routing с правилами."""
        from chimera.modules import chain_nodes
        with patch.object(self._fake_core, "_build_exit_xhttp_settings",
                          return_value={}), \
             patch.object(self._fake_core, "_build_sockopt",
                          return_value={}):
            nd = {
                "proto": "xhttp",
                "port": 443,
                "uuid": "u",
                "sni":  "exit.example.com",
                "host": "1.2.3.4",
            }
            cfg = chain_nodes._make_exit_node_config(nd)

        # DNS
        self.assertIn("dns", cfg)
        self.assertEqual(cfg["dns"]["queryStrategy"], "UseIPv6v4")
        # Outbounds
        tags = [ob["tag"] for ob in cfg["outbounds"]]
        self.assertIn("direct", tags)
        self.assertIn("BLOCK", tags)
        # Routing: BT → BLOCK, loopback → direct, tcp,udp → direct
        rules = cfg["routing"]["rules"]
        self.assertTrue(any(r.get("outboundTag") == "BLOCK"
                            and "bittorrent" in r.get("protocol", [])
                            for r in rules))
        self.assertTrue(any(r.get("outboundTag") == "direct"
                            and "127.0.0.1/32" in r.get("ip", [])
                            for r in rules))

    def test_xhttp_tcp_no_delay_inserted_when_enabled(self):
        """XHTTP_TCP_NO_DELAY=True → sockopt.tcpNoDelay=True в inbound."""
        from chimera.modules import chain_nodes
        with patch.object(self._fake_core, "_build_exit_xhttp_settings",
                          return_value={}), \
             patch.object(self._fake_core, "_build_sockopt",
                          return_value={}), \
             patch.object(self._fake_core, "XHTTP_TCP_NO_DELAY", True,
                          create=True):
            nd = {
                "proto": "xhttp",
                "port": 443,
                "uuid": "u",
                "sni":  "exit.example.com",
                "host": "1.2.3.4",
            }
            cfg = chain_nodes._make_exit_node_config(nd)
        sockopt = cfg["inbounds"][0]["streamSettings"]["sockopt"]
        self.assertTrue(sockopt.get("tcpNoDelay"))

    def test_xhttp_reality_branch_builds_xhttp_reality_inbound(self):
        """xhttp_reality-нода: inbound xhttp+reality — БЕЗ tlsSettings/LE и БЕЗ flow."""
        from chimera.modules import chain_nodes
        with patch.object(self._fake_core, "_build_exit_xhttp_settings",
                          return_value={"path": "/xhr", "mode": "stream-up"}), \
             patch.object(self._fake_core, "_build_sockopt",
                          return_value={}), \
             patch.object(self._fake_core, "XTLS_FLOW", "xtls-rprx-vision",
                          create=True):
            nd = {
                "proto": "xhttp_reality",
                "port": 8443,
                "uuid": "11111111-2222-3333-4444-555555555555",
                "sni":  "xhr.exit.com",
                "pubkey":  "PUB",
                "shortid": "abcd1234",
                "host": "1.2.3.4",
                "path": "/xhr",
                "xhttp_mode": "stream-up",
            }
            cfg = chain_nodes._make_exit_node_config(nd)

        inb = cfg["inbounds"][0]
        self.assertEqual(inb["tag"], "inbound-xhttp-reality")
        self.assertEqual(inb["port"], 8443)
        ss = inb["streamSettings"]
        # Транспорт xHTTP + REALITY TLS — LE-сертификат НЕ нужен
        self.assertEqual(ss["network"], "xhttp")
        self.assertEqual(ss["security"], "reality")
        self.assertNotIn("tlsSettings", ss)
        # Клиент БЕЗ flow — xHTTP-транспорт несовместим с xtls-rprx-vision
        client = inb["settings"]["clients"][0]
        self.assertEqual(client["id"], "11111111-2222-3333-4444-555555555555")
        self.assertEqual(client["email"], "entry@chain")
        self.assertNotIn("flow", client)
        # xhttpSettings делегированы helper'у
        self.assertEqual(ss["xhttpSettings"]["path"], "/xhr")
        # sockopt — стиль xhttp-ветки (keepalive/bbr)
        self.assertEqual(ss["sockopt"]["tcpCongestion"], "bbr")
        self.assertEqual(ss["sockopt"]["tcpKeepAliveInterval"], 15)
        # realitySettings — как в reality-ветке: placeholder приватного ключа
        rs = ss["realitySettings"]
        self.assertEqual(rs["publicKey"], "PUB")
        self.assertEqual(rs["shortIds"], ["abcd1234"])
        self.assertEqual(rs["serverNames"], ["xhr.exit.com"])
        self.assertEqual(rs["dest"], "xhr.exit.com:443")
        self.assertIn("privateKey", rs)
        # Гейт версий клиента присутствует явно (как в reality-ветке)
        self.assertIn("minClientVer", rs)
        # Comment ведёт к xray x25519 (приватный ключ REALITY нужен и тут)
        self.assertIn("xray x25519", cfg["_comment"])
        self.assertIn("xHTTP + REALITY", cfg["_comment"])


# ══════════════════════════════════════════════════════════════════════════════
#  _speed_test_node_latency — форматирование latency (mocked socket)
# ══════════════════════════════════════════════════════════════════════════════
class TestSpeedTestNodeLatency(unittest.TestCase):
    """_speed_test_node_latency: TCP-подключение mock'ается."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()

    def test_success_returns_ms(self):
        from chimera.modules import chain_nodes
        fake_sock = MagicMock()
        with patch("socket.gethostbyname", return_value="1.2.3.4"), \
             patch("socket.create_connection", return_value=fake_sock):
            result = chain_nodes._speed_test_node_latency("example.com", 443)
        self.assertIn("мс", result)
        fake_sock.close.assert_called_once()

    def test_timeout_returns_timeout_string(self):
        from chimera.modules import chain_nodes
        with patch("socket.gethostbyname", return_value="1.2.3.4"), \
             patch("socket.create_connection",
                   side_effect=socket.timeout("timed out")):
            result = chain_nodes._speed_test_node_latency("example.com", 443)
        self.assertIn("таймаут", result)

    def test_dns_failure_returns_error_string(self):
        from chimera.modules import chain_nodes
        with patch("socket.gethostbyname",
                   side_effect=socket.gaierror("DNS fail")):
            result = chain_nodes._speed_test_node_latency("nonexistent.invalid", 443)
        self.assertIn("ошибка", result)

    # ── via-ноды: полный зонд ЧЕРЕЗ ЦЕПОЧКУ (живой кейс окт.2026 №4:
    #    ee via hop-fi вечно «нода не отвечает» в [T] при живой цепи) ────

    _ND_VIA = {"host": "ee.example.com", "port": 443, "uuid": "uuid-x",
               "pubkey": "pbk-x", "shortid": "sid", "sni": "ee.example.com",
               "fp": "firefox", "proto": "reality", "via": "hop-fi"}

    def _patch_relay(self, **attrs):
        import chimera.modules.chain_relay as cr
        saved = {}
        for k, v in attrs.items():
            saved[k] = getattr(cr, k)
            setattr(cr, k, v)
        return saved

    def _restore_relay(self, saved):
        import chimera.modules.chain_relay as cr
        for k, v in saved.items():
            setattr(cr, k, v)

    def test_via_node_active_hop_chain_ok(self):
        """via-нода с активным хопом → зонд через цепочку, метка
        (via hop-fi) — НЕ прямой зонд (кейс №4). Короткий маркер
        «(via hop-fi)»: полный «(full-path via hop-fi)» + «· RTT …» не
        влезал в 78 колонок бокса [T] и рвался переносом (№6)."""
        from chimera.modules import chain_nodes
        calls = []

        def fake_via(nd, hops, **kw):
            calls.append("via")
            return {"ok": True, "ms": 171.5, "reason": "цепь жива",
                    "detail": "цепочка жива (hop-fi → exit)",
                    "infra": False}

        saved = self._patch_relay(
            check_via_node_full_path=fake_via,
            load_relay_hops=lambda: [],
            hop_via_tag_for=lambda nd, hops: "hop-fi")
        try:
            result = chain_nodes._speed_test_node_latency(
                "ee.example.com", 443, dict(self._ND_VIA))
        finally:
            self._restore_relay(saved)
        self.assertIn("(via hop-fi)", result)
        self.assertNotIn("(full-path via hop-fi)", result)
        self.assertIn("мс", result)
        self.assertEqual(calls, ["via"])

    def test_via_node_active_hop_chain_fail_honest(self):
        """Честный отказ цепочки → «недоступна (причина)», не TCP-маскировка."""
        from chimera.modules import chain_nodes
        saved = self._patch_relay(
            check_via_node_full_path=lambda nd, hops, **kw: {
                "ok": False, "ms": 0.0, "reason": "хоп->нода не доставляет",
                "infra": False},
            load_relay_hops=lambda: [],
            hop_via_tag_for=lambda nd, hops: "hop-fi")
        try:
            result = chain_nodes._speed_test_node_latency(
                "ee.example.com", 443, dict(self._ND_VIA))
        finally:
            self._restore_relay(saved)
        self.assertIn("недоступна", result)
        self.assertIn("хоп->нода не доставляет", result)

    def test_via_node_infra_falls_back_tcp(self):
        """Сбой МЕХАНИЗМА via-зонда → честный TCP-пинг (не ложный DOWN)."""
        from chimera.modules import chain_nodes
        fake_sock = MagicMock()
        saved = self._patch_relay(
            check_via_node_full_path=lambda nd, hops, **kw: {
                "ok": False, "ms": 0.0, "reason": "нет xray",
                "infra": True},
            load_relay_hops=lambda: [],
            hop_via_tag_for=lambda nd, hops: "hop-fi",
            check_node_full_path=lambda nd, **kw: {
                "ok": False, "ms": 0.0, "reason": "нет xray",
                "infra": True},
            node_has_reality_creds=lambda nd: True)
        try:
            with patch("socket.gethostbyname", return_value="1.2.3.4"), \
                 patch("socket.create_connection", return_value=fake_sock):
                result = chain_nodes._speed_test_node_latency(
                    "ee.example.com", 443, dict(self._ND_VIA))
        finally:
            self._restore_relay(saved)
        self.assertIn("мс", result)
        self.assertNotIn("full-path", result)
        self.assertNotIn("недоступна", result)

    def test_via_node_disabled_hop_direct_probe_with_note(self):
        """Хоп выключен → нода в проде прямая: прямой полный зонд
        + пометка «(via hop-fi выключен - напрямую)»."""
        from chimera.modules import chain_nodes
        calls = []

        def fake_fp(nd, **kw):
            calls.append("fp")
            return {"ok": True, "ms": 120.0, "infra": False}

        saved = self._patch_relay(
            load_relay_hops=lambda: [],
            hop_via_tag_for=lambda nd, hops: None,
            check_node_full_path=fake_fp,
            node_has_reality_creds=lambda nd: True)
        try:
            result = chain_nodes._speed_test_node_latency(
                "ee.example.com", 443, dict(self._ND_VIA))
        finally:
            self._restore_relay(saved)
        self.assertIn("full-path", result)
        self.assertIn("(via hop-fi выключен - напрямую)", result)
        self.assertEqual(calls, ["fp"])

    def test_via_node_disabled_hop_no_creds_tcp_with_note(self):
        """Хоп выключен, ключей нет → TCP-пинг с той же пометкой."""
        from chimera.modules import chain_nodes
        fake_sock = MagicMock()
        saved = self._patch_relay(
            load_relay_hops=lambda: [],
            hop_via_tag_for=lambda nd, hops: None,
            node_has_reality_creds=lambda nd: False)
        try:
            with patch("socket.gethostbyname", return_value="1.2.3.4"), \
                 patch("socket.create_connection", return_value=fake_sock):
                result = chain_nodes._speed_test_node_latency(
                    "ee.example.com", 443, dict(self._ND_VIA))
        finally:
            self._restore_relay(saved)
        self.assertIn("мс", result)
        self.assertIn("(via hop-fi выключен - напрямую)", result)
        self.assertNotIn("full-path", result)


# ══════════════════════════════════════════════════════════════════════════════
#  _speed_test_node_geo — парсинг ip-api.com (mocked _run)
# ══════════════════════════════════════════════════════════════════════════════
class TestSpeedTestNodeGeo(unittest.TestCase):
    """_speed_test_node_geo: парсинг JSON ответа ip-api (mocked)."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()

    def test_success_returns_geo_tuple(self):
        from chimera.modules import chain_nodes
        api_response = json.dumps({
            "status": "success",
            "country": "Germany",
            "countryCode": "DE",
            "city": "Frankfurt",
            "isp": "Hetzner",
            "query": "1.2.3.4",
        })
        with patch("socket.gethostbyname", return_value="1.2.3.4"), \
             patch.object(self._fake_core, "_run",
                          return_value=MagicMock(returncode=0,
                                                 stdout=api_response,
                                                 stderr="")):
            ip, cc, country, city, isp = chain_nodes._speed_test_node_geo("example.com")
        self.assertEqual(ip, "1.2.3.4")
        self.assertEqual(cc, "DE")
        self.assertEqual(country, "Germany")
        self.assertEqual(city, "Frankfurt")
        self.assertEqual(isp, "Hetzner")

    def test_failed_status_returns_unknown(self):
        from chimera.modules import chain_nodes
        api_response = json.dumps({"status": "fail", "query": "1.2.3.4"})
        with patch("socket.gethostbyname", return_value="1.2.3.4"), \
             patch.object(self._fake_core, "_run",
                          return_value=MagicMock(returncode=0,
                                                 stdout=api_response,
                                                 stderr="")):
            ip, cc, country, city, isp = chain_nodes._speed_test_node_geo("example.com")
        self.assertEqual(ip, "1.2.3.4")
        self.assertEqual(cc, "??")
        self.assertEqual(country, "неизвестно")

    def test_curl_failure_returns_unknown(self):
        from chimera.modules import chain_nodes
        with patch("socket.gethostbyname", return_value="1.2.3.4"), \
             patch.object(self._fake_core, "_run",
                          return_value=MagicMock(returncode=1,
                                                 stdout="",
                                                 stderr="connection refused")):
            ip, cc, country, city, isp = chain_nodes._speed_test_node_geo("example.com")
        self.assertEqual(ip, "1.2.3.4")
        self.assertEqual(cc, "??")

    def test_dns_failure_returns_host_as_ip(self):
        from chimera.modules import chain_nodes
        with patch("socket.gethostbyname",
                   side_effect=socket.gaierror("DNS fail")):
            ip, cc, country, city, isp = chain_nodes._speed_test_node_geo("nonexist.invalid")
        # При сбое DNS функция возвращает host как ip
        self.assertEqual(ip, "nonexist.invalid")
        self.assertEqual(cc, "??")


# ══════════════════════════════════════════════════════════════════════════════
#  _access_log_bytes_per_node — парсинг access.log
# ══════════════════════════════════════════════════════════════════════════════
class TestAccessLogBytesPerNode(unittest.TestCase):
    """_access_log_bytes_per_node: сопоставление тегов с нодами."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._log_path = Path(self._tmpdir) / "access.log"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_log(self, content: str):
        self._log_path.write_text(content)
        return patch.object(self._fake_core, "DIAG_ACCESS_LOG",
                            self._log_path, create=True)

    def test_empty_log_returns_zero_for_all_nodes(self):
        from chimera.modules import chain_nodes
        nodes = [{"host": "1.1.1.1"}, {"host": "2.2.2.2"}]
        with self._patch_log(""):
            result = chain_nodes._access_log_bytes_per_node(nodes)
        self.assertEqual(result, {"1.1.1.1": 0, "2.2.2.2": 0})

    def test_log_missing_returns_zero_for_all_nodes(self):
        from chimera.modules import chain_nodes
        nodes = [{"host": "1.1.1.1"}]
        with patch.object(self._fake_core, "DIAG_ACCESS_LOG",
                          Path("/tmp/nonexistent_log_xyz.log"), create=True):
            result = chain_nodes._access_log_bytes_per_node(nodes)
        self.assertEqual(result, {"1.1.1.1": 0})

    def test_chain_exit_tag_mapped_to_correct_node(self):
        """chain-exit-1 → nodes[0], chain-exit-2 → nodes[1]."""
        from chimera.modules import chain_nodes
        from datetime import datetime as _dt
        import time as _time
        nodes = [{"host": "1.1.1.1"}, {"host": "2.2.2.2"}]
        # Используем текущую дату/время, чтобы записи попадали в окно 24ч.
        now = _dt.fromtimestamp(_time.time()).strftime("%Y/%m/%d %H:%M:%S")
        log = (
            f"{now} "
            ">> chain-exit-1 | 100 200 |\n"
            f"{now} "
            ">> chain-exit-2 | 300 400 |\n"
        )
        with self._patch_log(log):
            result = chain_nodes._access_log_bytes_per_node(nodes)
        self.assertEqual(result["1.1.1.1"], 300)   # 100+200
        self.assertEqual(result["2.2.2.2"], 700)   # 300+400

    def test_balancer_tag_mapped_to_first_node(self):
        """Тег 'balancer' / 'chain-balancer' всегда уходит в nodes[0] (последняя запись выигрывает)."""
        from chimera.modules import chain_nodes
        from datetime import datetime as _dt
        import time as _time
        nodes = [{"host": "1.1.1.1"}, {"host": "2.2.2.2"}]
        now = _dt.fromtimestamp(_time.time()).strftime("%Y/%m/%d %H:%M:%S")
        log = (
            f"{now} "
            ">> balancer | 500 500 |\n"
        )
        with self._patch_log(log):
            result = chain_nodes._access_log_bytes_per_node(nodes)
        # balancer → nodes[0] (затем перезаписывается как nodes[-1] в цикле,
        # но так как nodes[0] == nodes[-1] для первого элемента, итоговый host —
        # nodes[-1]["host"]). Проверяем, что балансовый трафик не потерян.
        self.assertEqual(result["2.2.2.2"], 1000)

    def test_unknown_tag_ignored(self):
        """Тег, которого нет в tag_to_host — игнорируется."""
        from chimera.modules import chain_nodes
        nodes = [{"host": "1.1.1.1"}]
        log = (
            "2025/01/01 12:00:00 "
            ">> unknown-tag | 100 200 |\n"
        )
        with self._patch_log(log):
            result = chain_nodes._access_log_bytes_per_node(nodes)
        self.assertEqual(result["1.1.1.1"], 0)

    def test_old_entries_outside_window_ignored(self):
        """Записи старше hours — игнорируются."""
        from chimera.modules import chain_nodes
        import time as _time
        nodes = [{"host": "1.1.1.1"}]
        # Запись 48 часов назад — за окном по умолчанию 24 часа
        old_ts = _time.time() - 48 * 3600
        from datetime import datetime as _dt
        old_str = _dt.fromtimestamp(old_ts).strftime("%Y/%m/%d %H:%M:%S")
        log = (
            f"{old_str} "
            ">> chain-exit-1 | 9999 9999 |\n"
        )
        with self._patch_log(log):
            result = chain_nodes._access_log_bytes_per_node(nodes, hours=24)
        self.assertEqual(result["1.1.1.1"], 0)


# ══════════════════════════════════════════════════════════════════════════════
#  РЕГРЕССИЯ: Mode B + PROTOCOL_MODE="xhttp" → inbound НЕ должен
#  биндиться напрямую с tlsSettings на 0.0.0.0:443
#  (только через loopback/Nginx-терминацию)
# ══════════════════════════════════════════════════════════════════════════════
class TestChainEntryMultiXhttpRegression(unittest.TestCase):
    """
    Регрессия: при Mode B + PROTOCOL_MODE='xhttp' итоговый inbound
    НЕ должен биндиться напрямую с tlsSettings на 0.0.0.0:443.
    TLS терминируется Nginx, Xray слушает 127.0.0.1:XHTTP_BACKEND_PORT.
    """

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._config_dir = Path(self._tmpdir) / "xray"
        self._config_dir.mkdir(parents=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _prepare_fake_core(self, **overrides):
        """Заполняет fake_core нужными атрибутами для генерации entry-конфига."""
        c = self._fake_core
        # Хелперы — no-op / детерминированные заглушки
        c._assert_reality_dest_sane = lambda *a, **kw: None
        c._run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
        c._build_xhttp_settings = MagicMock(return_value=(
            {"path": "/xh", "mode": "stream-up"},   # xhttp_settings
            {"tcpFastOpen": True},                  # sockopt
        ))
        c._build_tls_settings_xhttp = MagicMock(return_value={
            "serverName": "test.example.com",
            "certificates": [],
        })
        c._build_sockopt = MagicMock(return_value={"tcpFastOpen": True})
        c._build_exit_xhttp_outbound_settings = MagicMock(return_value={
            "path": "/x", "mode": "stream-up"
        })
        c._xray_log_block = MagicMock(return_value={"loglevel": "info"})
        c._apply_stats_to_config = MagicMock()
        c._set_config_owner = MagicMock()
        c.build_split_tunnel_routing_rules = MagicMock(return_value=[])
        c.generate_xray_config = MagicMock()
        c.generate_xray_config_xhttp = MagicMock()
        c.info = MagicMock()
        c.warn = MagicMock()
        c.success = MagicMock()
        c.log_to_file = MagicMock()
        c._h2_reapply_transport_if_active = MagicMock()
        # Параметры по умолчанию для xhttp-режима
        c.PROTOCOL_MODE = "xhttp"
        c.PARAM_DOMAIN = "test.example.com"
        c.PARAM_UUID = "11111111-2222-3333-4444-555555555555"
        c.XTLS_FLOW = ""
        c.XHTTP_MODE = "stream-up"
        c.XHTTP_PATH = "/xh"
        c.XHTTP_BACKEND_PORT = 8443
        c.XHTTP_TCP_NO_DELAY = False
        c.XHTTP_ENABLE_SESSION_RESUMPTION = False
        c.AWG_EXIT_ENABLED = False
        c.H2_EXIT_ENABLED = False
        c.PARAM_REALITY_DEST = ""
        c.PARAM_SOCKET_PATH = "/var/run/xray/vless-reality.sock"
        c.PARAM_SPIDERX = "/"
        c.PARAM_PRIVATE_KEY = "PRIV"
        c.PARAM_PUBLIC_KEY = "PUB"
        c.PARAM_SHORTID = "abcd1234"
        c.SERVER_PORT = 443
        c.AWG_FWMARK = 1000
        c.SPLIT_TUNNEL_ENABLED = False
        c.IS_IPV6_AVAILABLE = False
        c.DNSCRYPT_LISTEN_PORT = 5300
        c.DNSCRYPT_LISTEN_ADDR = "127.0.0.1"
        c.DNSCRYPT_INSTALLED = False
        c.CHAIN_BALANCER_STRATEGY = "roundRobin"
        c.CHAIN_PINNED_NODE_INDEX = -1
        c.CONFIG_DIR = self._config_dir
        c.XRAY_BIN = "/usr/local/bin/xray"
        c.Any = object
        # Одна exit-нода xhttp
        c.CHAIN_NODES = [{
            "host":    "1.2.3.4",
            "port":    443,
            "uuid":    "exit-uuid-1234",
            "pubkey":  "EXIT_PUB",
            "shortid": "exit0123",
            "sni":     "exit.example.com",
            "fp":      "chrome",
            "proto":   "xhttp",
            "path":    "/x",
            "xhttp_mode": "stream-up",
        }]
        c.CHAIN_EXIT_HOST = ""
        c.CHAIN_EXIT_PORT = 443
        c.CHAIN_EXIT_UUID = ""
        c.CHAIN_EXIT_PUBKEY = ""
        c.CHAIN_EXIT_SHORTID = ""
        c.CHAIN_EXIT_SNI = ""
        c.CHAIN_EXIT_FP = "chrome"
        for k, v in overrides.items():
            setattr(c, k, v)

    def test_xhttp_inbound_uses_loopback_not_443(self):
        """
        Главный regression-тест: Mode B + xhttp → inbound слушает
        127.0.0.1:XHTTP_BACKEND_PORT (8443), НЕ 0.0.0.0:443.
        security='none', tlsSettings отсутствует.
        """
        from chimera.modules import chain_nodes
        self._prepare_fake_core()
        # /usr/local/etc/xray не должен существовать, чтобы skip symlink-блок
        with patch.object(Path, "exists",
                          lambda self: False if "usr/local/etc/xray" in str(self)
                          else Path.exists(self)):
            chain_nodes.generate_xray_config_chain_entry_multi()

        cfg_path = self._config_dir / "config.json"
        self.assertTrue(cfg_path.exists(),
                        "config.json должен быть создан в CONFIG_DIR")
        cfg = json.loads(cfg_path.read_text())
        self.assertTrue(cfg.get("inbounds"),
                        "В конфиге должен быть хотя бы один inbound")
        inb = cfg["inbounds"][0]
        # КЛЮЧЕВЫЕ ПРОВЕРКИ:
        # 1. listen — loopback, НЕ "::" / "0.0.0.0"
        self.assertEqual(inb["listen"], "127.0.0.1",
                         "inbound.listen должен быть 127.0.0.1 (loopback), "
                         "не '::' или '0.0.0.0' — TLS терминирует Nginx")
        # 2. port — XHTTP_BACKEND_PORT (8443), НЕ SERVER_PORT (443)
        self.assertEqual(inb["port"], 8443,
                         "inbound.port должен быть XHTTP_BACKEND_PORT (8443), "
                         "не SERVER_PORT (443) — Nginx проксирует на этот порт")
        # 3. security='none' — TLS терминирован Nginx
        ss = inb["streamSettings"]
        self.assertEqual(ss["security"], "none",
                         "streamSettings.security должен быть 'none' — "
                         "TLS терминирован Nginx, сертификаты не нужны")
        # 4. tlsSettings отсутствует — нет дублирующего TLS-терминатора
        self.assertNotIn("tlsSettings", ss,
                         "tlsSettings НЕ должен присутствовать в inbound — "
                         "это значит что Xray сам терминирует TLS на 0.0.0.0:443, "
                         "что является регрессией архитектуры Mode B + xhttp")
        # 5. network='xhttp'
        self.assertEqual(ss["network"], "xhttp")

    def test_xhttp_inbound_has_no_tls_certificates(self):
        """Доп. проверка: в inbound нет ссылок на сертификаты Let's Encrypt."""
        from chimera.modules import chain_nodes
        self._prepare_fake_core()
        with patch.object(Path, "exists",
                          lambda self: False if "usr/local/etc/xray" in str(self)
                          else Path.exists(self)):
            chain_nodes.generate_xray_config_chain_entry_multi()
        cfg = json.loads((self._config_dir / "config.json").read_text())
        inb_str = json.dumps(cfg["inbounds"][0])
        self.assertNotIn("letsencrypt", inb_str,
                         "Inbound не должен ссылаться на сертификаты Let's Encrypt")
        self.assertNotIn("certificateFile", inb_str,
                         "Inbound не должен содержать certificateFile")

    def test_reality_inbound_uses_socket_path_not_443(self):
        """
        Контраст: в reality-режиме inbound биндится на SERVER_PORT через
        Unix-сокет (PARAM_SOCKET_PATH) — это рабочая схема Nginx+Xray.
        Здесь проверяем что reality-ветка действительно использует socket.
        """
        from chimera.modules import chain_nodes
        self._prepare_fake_core(PROTOCOL_MODE="reality")
        with patch.object(Path, "exists",
                          lambda self: False if "usr/local/etc/xray" in str(self)
                          else Path.exists(self)):
            chain_nodes.generate_xray_config_chain_entry_multi()
        cfg = json.loads((self._config_dir / "config.json").read_text())
        inb = cfg["inbounds"][0]
        ss = inb["streamSettings"]
        # В reality-ветке: REALITY inbound с socket через Nginx
        self.assertEqual(ss["security"], "reality")
        # listen "::" — это норма для reality, так как Nginx терминирует TCP
        # и проксирует через Unix-сокет (xver=1, Proxy Protocol)
        self.assertIn("realitySettings", ss)

    def test_round_robin_single_node_no_balancer(self):
        """1 нода → balancers пустой, routing rule ссылается на chain-exit-1 напрямую."""
        from chimera.modules import chain_nodes
        self._prepare_fake_core()
        with patch.object(Path, "exists",
                          lambda self: False if "usr/local/etc/xray" in str(self)
                          else Path.exists(self)):
            chain_nodes.generate_xray_config_chain_entry_multi()
        cfg = json.loads((self._config_dir / "config.json").read_text())
        # balancers должен отсутствовать или быть пустым
        balancers = cfg.get("routing", {}).get("balancers", [])
        self.assertEqual(balancers, [])
        # FIX: catch-all теперь только TCP (VLESS REALITY не туннелирует UDP).
        # Проверяем что TCP-правило ссылается на chain-exit-1.
        rules = cfg["routing"]["rules"]
        tcp_rule = next((r for r in rules
                         if r.get("network") == "tcp"), None)
        self.assertIsNotNone(tcp_rule, "Должно быть TCP catch-all правило")
        self.assertEqual(tcp_rule["outboundTag"], "chain-exit-1")
        # Дополнительно: UDP-трафик должен блокироваться (VLESS TCP-only)
        udp_block_rule = next((r for r in rules
                                if r.get("network") == "udp"
                                and r.get("outboundTag") == "BLOCK"), None)
        self.assertIsNotNone(udp_block_rule,
                             "Должно быть правило блокировки UDP")
        # DNS (порт 53) → direct (резолвится через DNSCrypt на entry)
        dns_rule = next((r for r in rules
                         if r.get("port") == "53"), None)
        self.assertIsNotNone(dns_rule,
                             "Должно быть правило для DNS (порт 53)")
        # observatory не нужен для 1 ноды
        self.assertNotIn("observatory", cfg)

    def test_least_ping_strategy_with_multiple_nodes_uses_observatory(self):
        """3 ноды + leastPing → balancers + observatory с probeUrl."""
        from chimera.modules import chain_nodes
        self._prepare_fake_core(CHAIN_BALANCER_STRATEGY="leastPing")
        # Делаем 3 ноды
        self._fake_core.CHAIN_NODES = [
            {**self._fake_core.CHAIN_NODES[0], "host": f"10.0.0.{i}"}
            for i in range(1, 4)
        ]
        with patch.object(Path, "exists",
                          lambda self: False if "usr/local/etc/xray" in str(self)
                          else Path.exists(self)):
            chain_nodes.generate_xray_config_chain_entry_multi()
        cfg = json.loads((self._config_dir / "config.json").read_text())
        # balancers присутствует
        balancers = cfg["routing"].get("balancers", [])
        self.assertEqual(len(balancers), 1)
        self.assertEqual(balancers[0]["strategy"]["type"], "leastPing")
        # observatory присутствует
        self.assertIn("observatory", cfg)
        self.assertEqual(cfg["observatory"]["probeUrl"],
                         "https://1.1.1.1/cdn-cgi/trace")
        # FIX: catch-all теперь только TCP (VLESS REALITY не туннелирует UDP).
        # Проверяем что TCP-правило ссылается на balancerTag, не outboundTag.
        rules = cfg["routing"]["rules"]
        tcp_rule = next((r for r in rules
                         if r.get("network") == "tcp"), None)
        self.assertIsNotNone(tcp_rule, "Должно быть TCP catch-all правило")
        self.assertIn("balancerTag", tcp_rule)
        self.assertEqual(tcp_rule["balancerTag"], "chain-balancer")
        # Дополнительно: должны быть правила для блокировки UDP и DNS→direct
        udp_block_rule = next((r for r in rules
                                if r.get("network") == "udp"
                                and r.get("outboundTag") == "BLOCK"), None)
        self.assertIsNotNone(udp_block_rule,
                             "Должно быть правило блокировки UDP")
        dns_rule = next((r for r in rules
                         if r.get("port") == "53"), None)
        self.assertIsNotNone(dns_rule,
                             "Должно быть правило для DNS (порт 53)")


# ══════════════════════════════════════════════════════════════════════════════
# Mode B + PROTOCOL_MODE='xhttp_reality': entry-инбаунд xHTTP+REALITY
# (живой тест Mode A на DE 2026-09-29 прошёл; Mode B entry ранее проваливался
#  в else-ветку REALITY TCP — GAP, закрытый для каскада RU→DE)
# ══════════════════════════════════════════════════════════════════════════════
class TestChainEntryMultiXhttpRealityEntry(unittest.TestCase):
    """Mode B + xhttp_reality: inbound = xhttp+reality на SERVER_PORT
    (Xray владеет портом напрямую), clients БЕЗ flow, outbound к
    xhttp_reality-exit с transport=xhttp + REALITY TLS."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._config_dir = Path(self._tmpdir) / "xray"
        self._config_dir.mkdir(parents=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _prepare(self):
        c = self._fake_core
        c._assert_reality_dest_sane = lambda *a, **kw: None
        c._run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
        c._build_xhttp_settings = MagicMock(return_value=(
            {"path": "/7f78c7e5", "mode": "stream-up"},
            {"tcpFastOpen": True},
        ))
        c._build_tls_settings_xhttp = MagicMock(return_value={})
        c._build_sockopt = MagicMock(return_value={"tcpFastOpen": True})
        c._build_exit_xhttp_outbound_settings = MagicMock(return_value={
            "path": "/7f78c7e5", "mode": "stream-up"
        })
        c._xray_log_block = MagicMock(return_value={"loglevel": "info"})
        c._apply_stats_to_config = MagicMock()
        c._set_config_owner = MagicMock()
        c.build_split_tunnel_routing_rules = MagicMock(return_value=[])
        c.generate_xray_config = MagicMock()
        c.generate_xray_config_xhttp = MagicMock()
        c.info = MagicMock()
        c.warn = MagicMock()
        c.success = MagicMock()
        c.log_to_file = MagicMock()
        c._h2_reapply_transport_if_active = MagicMock()
        c.PROTOCOL_MODE = "xhttp_reality"
        c.PARAM_DOMAIN = "cdn2.example"
        c.PARAM_UUID = "11111111-2222-3333-4444-555555555555"
        c.XTLS_FLOW = ""
        c.XHTTP_MODE = "stream-up"
        c.XHTTP_PATH = "/7f78c7e5"
        c.XHTTP_BACKEND_PORT = 8443
        c.XHTTP_TCP_NO_DELAY = False
        c.XHTTP_ENABLE_SESSION_RESUMPTION = False
        c.AWG_EXIT_ENABLED = False
        c.H2_EXIT_ENABLED = False
        c.PARAM_REALITY_DEST = ""
        c.PARAM_SOCKET_PATH = "/dev/shm/4e3460f3.socket"
        c.PARAM_SPIDERX = "/1f9l8n"
        c.PARAM_PRIVATE_KEY = "PRIVKEY_XHR"
        c.PARAM_PUBLIC_KEY = "PUBKEY_XHR"
        c.PARAM_SHORTID = "db4eaf93"
        c.SERVER_PORT = 8443
        c.AWG_FWMARK = 1000
        c.SPLIT_TUNNEL_ENABLED = False
        c.IS_IPV6_AVAILABLE = False
        c.DNSCRYPT_LISTEN_PORT = 5300
        c.DNSCRYPT_LISTEN_ADDR = "127.0.0.1"
        c.DNSCRYPT_INSTALLED = False
        c.CHAIN_BALANCER_STRATEGY = "roundRobin"
        c.CHAIN_PINNED_NODE_INDEX = -1
        c.CONFIG_DIR = self._config_dir
        c.XRAY_BIN = "/usr/local/bin/xray"
        c.Any = object
        # Exit-нода = существующий DE xhttp_reality (Mode A, живой тест)
        c.CHAIN_NODES = [{
            "host":    "203.0.113.106",
            "port":    8443,
            "uuid":    "aa0024-0000-4000-8000-000000000024",
            "pubkey":  "DE_PUB",
            "shortid": "desid012",
            "sni":     "fleet-a.example",
            "fp":      "chrome",
            "proto":   "xhttp_reality",
            "path":    "/7f78c7e5",
            "xhttp_mode": "stream-up",
        }]
        c.CHAIN_EXIT_HOST = ""
        c.CHAIN_EXIT_PORT = 443
        c.CHAIN_EXIT_UUID = ""
        c.CHAIN_EXIT_PUBKEY = ""
        c.CHAIN_EXIT_SHORTID = ""
        c.CHAIN_EXIT_SNI = ""
        c.CHAIN_EXIT_FP = "chrome"

    def _generate(self):
        from chimera.modules import chain_nodes
        with patch.object(Path, "exists",
                          lambda self: False if "usr/local/etc/xray" in str(self)
                          else Path.exists(self)):
            chain_nodes.generate_xray_config_chain_entry_multi()
        return json.loads((self._config_dir / "config.json").read_text())

    def test_entry_inbound_xhttp_reality(self):
        """Entry-инбаунд: network=xhttp + security=reality на SERVER_PORT,
        REALITY dest=socket, serverNames=свой домен, clients БЕЗ flow."""
        self._prepare()
        cfg = self._generate()
        inb = cfg["inbounds"][0]
        ss = inb["streamSettings"]
        # Xray владеет портом напрямую (не loopback-схема Nginx!)
        self.assertEqual(inb["port"], 8443)
        self.assertEqual(inb["listen"], "::")
        # Транспорт + маскировка
        self.assertEqual(ss["network"], "xhttp",
                         "ГЛАВНАЯ ПРОВЕРКА GAP: до фикса xhttp_reality "
                         "проваливался в reality-ветку с network=tcp")
        self.assertEqual(ss["security"], "reality")
        self.assertIn("xhttpSettings", ss)
        self.assertNotIn("tlsSettings", ss,
                         "LE-сертификат не нужен — TLS терминирует REALITY")
        rs = ss["realitySettings"]
        self.assertEqual(rs["dest"], "/dev/shm/4e3460f3.socket")
        self.assertEqual(rs["serverNames"], ["cdn2.example"])
        self.assertEqual(rs["privateKey"], "PRIVKEY_XHR")
        self.assertEqual(rs["shortIds"], ["db4eaf93"])
        # clients БЕЗ flow (xhttp не поддерживает xtls-rprx-vision)
        for cl in inb["settings"]["clients"]:
            self.assertNotIn("flow", cl)

    def test_exit_outbound_xhttp_reality(self):
        """Outbound к DE-exit: network=xhttp + security=reality,
        xhttpSettings + realitySettings (serverName=SNI ноды)."""
        self._prepare()
        cfg = self._generate()
        ob = next(o for o in cfg["outbounds"]
                  if str(o.get("tag", "")).startswith("chain-exit-"))
        ss = ob["streamSettings"]
        self.assertEqual(ss["network"], "xhttp")
        self.assertEqual(ss["security"], "reality")
        self.assertIn("xhttpSettings", ss)
        self.assertEqual(ss["realitySettings"]["publicKey"], "DE_PUB")
        self.assertEqual(ss["realitySettings"]["serverName"],
                         "fleet-a.example")
        # пользователи outbound без flow
        for u in ob["settings"]["vnext"][0]["users"]:
            self.assertNotIn("flow", u)

    def test_routing_single_exit_no_balancer(self):
        """1 exit-нода → без balancer, TCP catch-all → chain-exit-1."""
        self._prepare()
        cfg = self._generate()
        self.assertEqual(cfg.get("routing", {}).get("balancers", []), [])
        tcp_rule = next((r for r in cfg["routing"]["rules"]
                         if r.get("network") == "tcp"), None)
        self.assertIsNotNone(tcp_rule)
        self.assertEqual(tcp_rule["outboundTag"], "chain-exit-1")


# ══════════════════════════════════════════════════════════════════════════════
# BUGFIX: регенерация конфига сохраняет юзеров (anti-EOF)
# ══════════════════════════════════════════════════════════════════════════════
class TestChainEntryMultiPreservesUsers(unittest.TestCase):
    """
    РЕГРЕССИЯ (реальный инцидент на VPS без IPv6):
    после установки AGH _regenerate_xray_config() перегенерировала
    /etc/xray/config.json с clients=[PARAM_UUID из state.json].
    state.json содержал dc1c190b-... (второй прогон промптов), а
    выданная клиентская ссылка — b707d8cc-... (users.json). UUID из
    ссылки выпал из конфига → xray рвал каждое соединение
    «invalid request user id» → сплошные EOF в клиенте.

    Фикс: clients собираются из _unified_load_users() (users.json +
    текущий конфиг) + PARAM_UUID. Ссылки, выданные ДО регенерации,
    обязаны оставаться валидными.
    """

    # UUID из клиентской ссылки (инцидент на panel.example)
    _LINK_UUID = "aa0025-0000-4000-8000-000000000025"
    # UUID, который попал в state.json (и раньше — единственный в clients)
    _STATE_UUID = "aa0026-0000-4000-8000-000000000026"

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._config_dir = Path(self._tmpdir) / "xray"
        self._config_dir.mkdir(parents=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _prepare(self, users: list | None = None):
        """fake_core из xhttp-регрессии, переведённый в reality-режим."""
        c = self._fake_core
        c._assert_reality_dest_sane = lambda *a, **kw: None
        c._run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
        c._build_xhttp_settings = MagicMock(return_value=(
            {"path": "/xh", "mode": "stream-up"}, {"tcpFastOpen": True}))
        c._build_tls_settings_xhttp = MagicMock(return_value={
            "serverName": "test.example.com", "certificates": []})
        c._build_sockopt = MagicMock(return_value={"tcpFastOpen": True})
        c._build_exit_xhttp_outbound_settings = MagicMock(return_value={
            "path": "/x", "mode": "stream-up"})
        c._xray_log_block = MagicMock(return_value={"loglevel": "info"})
        c._apply_stats_to_config = MagicMock()
        c._set_config_owner = MagicMock()
        c.build_split_tunnel_routing_rules = MagicMock(return_value=[])
        c.generate_xray_config = MagicMock()
        c.generate_xray_config_xhttp = MagicMock()
        c.info = MagicMock()
        c.warn = MagicMock()
        c.success = MagicMock()
        c.log_to_file = MagicMock()
        c._h2_reapply_transport_if_active = MagicMock()
        c.PROTOCOL_MODE = "reality"
        c.PARAM_DOMAIN = "test.example.com"
        c.PARAM_UUID = self._STATE_UUID          # state.json «правда»
        c.XTLS_FLOW = "xtls-rprx-vision"
        c.XHTTP_MODE = "stream-up"
        c.XHTTP_PATH = "/xh"
        c.XHTTP_BACKEND_PORT = 8443
        c.XHTTP_TCP_NO_DELAY = False
        c.XHTTP_ENABLE_SESSION_RESUMPTION = False
        c.AWG_EXIT_ENABLED = False
        c.H2_EXIT_ENABLED = False
        c.PARAM_REALITY_DEST = ""
        c.PARAM_SOCKET_PATH = "/var/run/xray/vless-reality.sock"
        c.PARAM_SPIDERX = "/"
        c.PARAM_PRIVATE_KEY = "PRIV"
        c.PARAM_PUBLIC_KEY = "PUB"
        c.PARAM_SHORTID = "abcd1234"
        c.SERVER_PORT = 443
        c.AWG_FWMARK = 1000
        c.SPLIT_TUNNEL_ENABLED = False
        c.IS_IPV6_AVAILABLE = False
        c.DNSCRYPT_LISTEN_PORT = 5300
        c.DNSCRYPT_LISTEN_ADDR = "127.0.0.1"
        c.DNSCRYPT_INSTALLED = False
        c.CHAIN_BALANCER_STRATEGY = "roundRobin"
        c.CHAIN_PINNED_NODE_INDEX = -1
        c.CONFIG_DIR = self._config_dir
        c.XRAY_BIN = "/usr/local/bin/xray"
        c.Any = object
        c.CHAIN_NODES = [{
            "host":    "1.2.3.4",
            "port":    443,
            "uuid":    "exit-uuid-1234",
            "pubkey":  "EXIT_PUB",
            "shortid": "exit0123",
            "sni":     "exit.example.com",
            "fp":      "chrome",
            "proto":   "reality",
        }]
        c.CHAIN_EXIT_HOST = ""
        c.CHAIN_EXIT_PORT = 443
        c.CHAIN_EXIT_UUID = ""
        c.CHAIN_EXIT_PUBKEY = ""
        c.CHAIN_EXIT_SHORTID = ""
        c.CHAIN_EXIT_SNI = ""
        c.CHAIN_EXIT_FP = "chrome"
        # users.json — юзер, чья ссылка выдана клиенту (источник ссылки)
        users_file = self._config_dir / "users.json"
        users_file.write_text(json.dumps(
            users if users is not None else [
                {"uuid": self._LINK_UUID, "email": "netwalker@xray",
                 "name": "netwalker", "created": "2026-08-20", "source": "B"},
            ]))
        c.USERS_FILE = users_file

    def _generate(self):
        from chimera.modules import chain_nodes
        # Паттерн «Path.exists(self)» внутри лямбды РЕКУРСИВЕН (Path.exists
        # уже заменён) — RecursionError молча гасится try/except фикса.
        # Захватываем оригинал ДО патча, как в test_users_manager.
        _skip = ("usr/local/etc/xray", "/etc/xray/config.json")
        _orig_exists = Path.exists

        def _exists(p):
            if any(s in str(p) for s in _skip):
                return False
            return _orig_exists(p)

        with patch.object(Path, "exists", _exists):
            chain_nodes.generate_xray_config_chain_entry_multi()
        return json.loads((self._config_dir / "config.json").read_text())

    def test_link_uuid_survives_regeneration(self):
        """UUID из выданной ссылки остаётся в clients после регенерации."""
        self._prepare()
        cfg = self._generate()
        clients = cfg["inbounds"][0]["settings"]["clients"]
        ids = [cl["id"] for cl in clients]
        self.assertIn(self._LINK_UUID, ids,
                      "UUID из клиентской ссылки обязан остаться в clients — "
                      "иначе клиент получает EOF «invalid request user id»")
        self.assertIn(self._STATE_UUID, ids,
                      "PARAM_UUID из state.json тоже должен присутствовать")
        self.assertEqual(len(ids), len(set(ids)), "Без дублей UUID")

    def test_clients_have_email_and_flow_in_reality(self):
        """REALITY-клиенты: email у всех, flow у всех."""
        self._prepare()
        cfg = self._generate()
        clients = cfg["inbounds"][0]["settings"]["clients"]
        self.assertGreaterEqual(len(clients), 2)
        for cl in clients:
            self.assertTrue(cl.get("email"), "email обязателен (дедуп xray)")
            self.assertEqual(cl.get("flow"), "xtls-rprx-vision")

    def test_fresh_install_single_param_uuid(self):
        """Fresh install (users.json пуст) → clients=[PARAM_UUID], как раньше."""
        self._prepare(users=[])
        cfg = self._generate()
        clients = cfg["inbounds"][0]["settings"]["clients"]
        self.assertEqual([cl["id"] for cl in clients], [self._STATE_UUID])


# ══════════════════════════════════════════════════════════════════════════════
#  _save_chain_nodes_to_state — запись нод обратно в state.json
# ══════════════════════════════════════════════════════════════════════════════
class TestSaveChainNodesToState(unittest.TestCase):
    """_save_chain_nodes_to_state: запись CHAIN_NODES в state.json."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._state_file = Path(self._tmpdir) / "state.json"
        self._state_file.write_text(json.dumps({"domain": "x.com"}))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_writes_chain_nodes_field(self):
        from chimera.modules import chain_nodes
        c = self._fake_core
        c.STATE_FILE = self._state_file
        c.CHAIN_NODES = [{"host": "h", "port": 443, "uuid": "u",
                          "pubkey": "p", "shortid": "s", "sni": "n", "fp": "chrome"}]
        c.CHAIN_BALANCER_STRATEGY = "roundRobin"
        c.CHAIN_PINNED_NODE_INDEX = -1
        c.warn = MagicMock()
        chain_nodes._save_chain_nodes_to_state()
        st = json.loads(self._state_file.read_text())
        self.assertIn("chain_nodes", st)
        self.assertEqual(st["chain_nodes"][0]["host"], "h")
        # Legacy-поля тоже обновляются
        self.assertEqual(st["chain_exit_host"], "h")
        self.assertEqual(st["chain_exit_port"], 443)

    def test_warns_when_state_missing(self):
        from chimera.modules import chain_nodes
        c = self._fake_core
        c.STATE_FILE = Path("/tmp/nonexistent_state_xyz.json")
        c.CHAIN_NODES = []
        c.warn = MagicMock()
        chain_nodes._save_chain_nodes_to_state()
        c.warn.assert_called()
        warn_msg = c.warn.call_args.args[0]
        self.assertIn("state.json", warn_msg)


# ══════════════════════════════════════════════════════════════════════════════
#  _resolve_host_fresh — DoH-резолв (Cloudflare/Google) + fallback
# ══════════════════════════════════════════════════════════════════════════════
class TestResolveHostFresh(unittest.TestCase):
    """_resolve_host_fresh: DoH через Cloudflare/Google + fallback на gethostbyname."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()

    def test_ipv4_passthrough(self):
        """Если host уже валидный IPv4 — возвращается как есть, без DoH."""
        from chimera.modules import chain_nodes
        # _run НЕ должен вызываться — патчим с side_effect AssertionError.
        with patch.object(self._fake_core, "_run",
                          side_effect=AssertionError("_run не должен вызываться")):
            result = chain_nodes._resolve_host_fresh("192.0.2.42")
        self.assertEqual(result, "192.0.2.42")

    def test_doh_cloudflare_success(self):
        """DoH через Cloudflare (1.1.1.1) отдал A-record — возвращается IP."""
        from chimera.modules import chain_nodes
        # Cloudflare JSON DoH: {"Status":0,"Answer":[{"name":"...","type":1,"data":"5.6.7.8"}]}
        cf_response = json.dumps({
            "Status": 0,
            "Answer": [{"name": "example.com", "type": 1, "TTL": 60, "data": "5.6.7.8"}],
        })
        mock_run = MagicMock(returncode=0, stdout=cf_response, stderr="")
        with patch.object(self._fake_core, "_run", return_value=mock_run), \
             patch("socket.gethostbyname",
                   side_effect=AssertionError(
                       "gethostbyname не должен вызываться при успешном DoH")):
            result = chain_nodes._resolve_host_fresh("example.com")
        self.assertEqual(result, "5.6.7.8")

    def test_doh_cloudflare_fails_google_succeeds(self):
        """Cloudflare недоступен → fallback на Google DoH (8.8.8.8)."""
        from chimera.modules import chain_nodes
        google_response = json.dumps({
            "Status": 0,
            "Answer": [{"name": "example.com", "type": 1, "TTL": 60, "data": "9.9.9.9"}],
        })
        # Первый вызов _run (Cloudflare) — ошибка; второй (Google) — успех.
        responses = [
            MagicMock(returncode=28, stdout="", stderr="timeout"),  # cf fail
            MagicMock(returncode=0,  stdout=google_response, stderr=""),  # google ok
        ]
        with patch.object(self._fake_core, "_run", side_effect=responses), \
             patch("socket.gethostbyname",
                   side_effect=AssertionError(
                       "gethostbyname не должен вызываться при успешном Google DoH")):
            result = chain_nodes._resolve_host_fresh("example.com")
        self.assertEqual(result, "9.9.9.9")

    def test_doh_returns_nxdomain_falls_back_to_gethostbyname(self):
        """DoH отдал NXDOMAIN (Status=3) → fallback на системный резолвер."""
        from chimera.modules import chain_nodes
        # NXDOMAIN от обоих провайдеров.
        nxdomain = json.dumps({"Status": 3, "Answer": []})
        mock_run = MagicMock(returncode=0, stdout=nxdomain, stderr="")
        with patch.object(self._fake_core, "_run", return_value=mock_run), \
             patch("socket.gethostbyname", return_value="203.0.113.7") as mock_ghbn:
            result = chain_nodes._resolve_host_fresh("cached.example.com")
        self.assertEqual(result, "203.0.113.7")
        mock_ghbn.assert_called_once_with("cached.example.com")

    def test_doh_returns_aaaa_ignored(self):
        """DoH-ответ с AAAA (type=28), но без A (type=1) → fallback на gethostbyname.

        _resolve_host_fresh возвращает только IPv4 (inet_aton), чтобы не ломать
        callers, ожидающих IPv4-строку.
        """
        from chimera.modules import chain_nodes
        aaaa_only = json.dumps({
            "Status": 0,
            "Answer": [{"name": "v6.example.com", "type": 28,
                        "TTL": 60, "data": "2a12::1"}],
        })
        mock_run = MagicMock(returncode=0, stdout=aaaa_only, stderr="")
        with patch.object(self._fake_core, "_run", return_value=mock_run), \
             patch("socket.gethostbyname", return_value="198.51.100.42"):
            result = chain_nodes._resolve_host_fresh("v6.example.com")
        self.assertEqual(result, "198.51.100.42")

    def test_all_doh_fail_falls_back_to_gethostbyname(self):
        """Все DoH-провайдеры недоступны (curl fail) → fallback на gethostbyname."""
        from chimera.modules import chain_nodes
        mock_run = MagicMock(returncode=6, stdout="", stderr="couldn't resolve host")
        with patch.object(self._fake_core, "_run", return_value=mock_run), \
             patch("socket.gethostbyname", return_value="203.0.113.99") as mock_ghbn:
            result = chain_nodes._resolve_host_fresh("example.com")
        self.assertEqual(result, "203.0.113.99")
        mock_ghbn.assert_called_once_with("example.com")

    def test_all_fail_returns_none(self):
        """DoH недоступен И gethostbyname падает → None."""
        from chimera.modules import chain_nodes
        mock_run = MagicMock(returncode=6, stdout="", stderr="")
        with patch.object(self._fake_core, "_run", return_value=mock_run), \
             patch("socket.gethostbyname",
                   side_effect=socket.gaierror("DNS fail")):
            result = chain_nodes._resolve_host_fresh("nonexistent.invalid")
        self.assertIsNone(result)


# ══════════════════════════════════════════════════════════════════════════════
#  _build_chain_routing_rules + _build_chain_sniffing — единые хелперы
#  для VLESS REALITY TCP каскада (FIX: раньше catch-all был tcp,udp → обрыв UDP)
# ══════════════════════════════════════════════════════════════════════════════
class TestChainRoutingRulesHelpers(unittest.TestCase):
    """_build_chain_routing_rules и _build_chain_sniffing — структура правил.

    FIX (commit): раньше catch-all было {"network": "tcp,udp", "outboundTag": "chain-exit"},
    что рвало UDP-трафик (VLESS REALITY TCP-only). Теперь:
      - DNS (порт 53) → direct
      - QUIC (UDP:443) → BLOCK (браузер откатится на TCP)
      - Весь остальной UDP → BLOCK
      - Только TCP → chain-exit / chain-balancer
    """

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()

    def test_build_chain_routing_rules_single_node_uses_outbound_tag(self):
        """Single-node: catch-all rule имеет outboundTag, не balancerTag."""
        from chimera.modules import chain_nodes
        rules = chain_nodes._build_chain_routing_rules("chain-exit-1")
        # Последнее правило — TCP catch-all
        tcp_rule = rules[-1]
        self.assertEqual(tcp_rule["network"], "tcp")
        self.assertEqual(tcp_rule["outboundTag"], "chain-exit-1")
        self.assertNotIn("balancerTag", tcp_rule)

    def test_build_chain_routing_rules_balancer_uses_balancer_tag(self):
        """Balancer mode: catch-all rule имеет balancerTag, не outboundTag."""
        from chimera.modules import chain_nodes
        rules = chain_nodes._build_chain_routing_rules("chain-balancer",
                                                        balancer=True)
        tcp_rule = rules[-1]
        self.assertEqual(tcp_rule["network"], "tcp")
        self.assertEqual(tcp_rule["balancerTag"], "chain-balancer")
        self.assertNotIn("outboundTag", tcp_rule)

    def test_build_chain_routing_rules_has_loopback_direct(self):
        """loopback (127.0.0.1/8, ::1/128) → direct — для DNSCrypt."""
        from chimera.modules import chain_nodes
        rules = chain_nodes._build_chain_routing_rules("chain-exit-1")
        loopback_rule = next(
            (r for r in rules
             if "127.0.0.1/8" in r.get("ip", [])),
            None
        )
        self.assertIsNotNone(loopback_rule)
        self.assertEqual(loopback_rule["outboundTag"], "direct")

    def test_build_chain_routing_rules_has_bittorrent_block(self):
        """bittorrent → BLOCK."""
        from chimera.modules import chain_nodes
        rules = chain_nodes._build_chain_routing_rules("chain-exit-1")
        bt_rule = next(
            (r for r in rules
             if "bittorrent" in r.get("protocol", [])),
            None
        )
        self.assertIsNotNone(bt_rule)
        self.assertEqual(bt_rule["outboundTag"], "BLOCK")

    def test_build_chain_routing_rules_dns_port_53_to_direct(self):
        """DNS (порт 53) → direct (резолвится через DNSCrypt на entry)."""
        from chimera.modules import chain_nodes
        rules = chain_nodes._build_chain_routing_rules("chain-exit-1")
        dns_rule = next(
            (r for r in rules if r.get("port") == "53"),
            None
        )
        self.assertIsNotNone(dns_rule)
        self.assertEqual(dns_rule["network"], "tcp,udp")
        self.assertEqual(dns_rule["outboundTag"], "direct")

    def test_build_chain_routing_rules_quic_443_udp_to_block(self):
        """QUIC (UDP:443) → BLOCK — браузер откатится на TCP/HTTP2."""
        from chimera.modules import chain_nodes
        rules = chain_nodes._build_chain_routing_rules("chain-exit-1")
        quic_rule = next(
            (r for r in rules
             if r.get("port") == "443" and r.get("network") == "udp"),
            None
        )
        self.assertIsNotNone(quic_rule)
        self.assertEqual(quic_rule["outboundTag"], "BLOCK")

    def test_build_chain_routing_rules_udp_all_to_block(self):
        """Весь остальной UDP → BLOCK (VLESS REALITY TCP-only)."""
        from chimera.modules import chain_nodes
        rules = chain_nodes._build_chain_routing_rules("chain-exit-1")
        udp_block_rule = next(
            (r for r in rules
             if r.get("network") == "udp"
             and r.get("outboundTag") == "BLOCK"
             and "port" not in r),
            None
        )
        self.assertIsNotNone(udp_block_rule)

    def test_build_chain_routing_rules_no_tcp_udp_catchall(self):
        """FIX: НЕ должно быть catch-all правила {network: 'tcp,udp'} без port.
        Старый баг: catch-all матчил весь UDP и рвал его (VLESS TCP-only).
        Теперь 'tcp,udp' разрешено ТОЛЬКО для конкретного порта (DNS:53).
        """
        from chimera.modules import chain_nodes
        rules = chain_nodes._build_chain_routing_rules("chain-exit-1")
        for r in rules:
            if r.get("network") == "tcp,udp":
                # Допустимо только с явным портом (например, DNS:53)
                self.assertIn("port", r,
                              f"Правило {r} не должно быть catch-all "
                              f"(tcp,udp без port) — это рвало UDP-трафик")

    def test_build_chain_routing_rules_order_loopback_first(self):
        """loopback → direct должно быть ПЕРВЫМ правилом (Xray резолвит
        через DNSCrypt на 127.0.0.1:5300, должен матчится раньше catch-all).
        """
        from chimera.modules import chain_nodes
        rules = chain_nodes._build_chain_routing_rules("chain-exit-1")
        self.assertIn("127.0.0.1/8", rules[0].get("ip", []))
        self.assertEqual(rules[0]["outboundTag"], "direct")

    def test_build_chain_routing_rules_order_tcp_catchall_last(self):
        """TCP catch-all должно быть ПОСЛЕДНИМ правилом (матчиться по умолчанию)."""
        from chimera.modules import chain_nodes
        rules = chain_nodes._build_chain_routing_rules("chain-exit-1")
        self.assertEqual(rules[-1]["network"], "tcp")

    def test_build_chain_sniffing_default(self):
        """sniffing без AWG: destOverride содержит http, tls, quic;
        metadataOnly=False (xray должен читать SNI/Host).
        """
        from chimera.modules import chain_nodes
        sn = chain_nodes._build_chain_sniffing(awg=False)
        self.assertTrue(sn["enabled"])
        self.assertIn("http", sn["destOverride"])
        self.assertIn("tls", sn["destOverride"])
        self.assertIn("quic", sn["destOverride"])
        self.assertFalse(sn["metadataOnly"])
        self.assertFalse(sn["routeOnly"])

    def test_build_chain_sniffing_awg(self):
        """sniffing с AWG: metadataOnly=True (routing через ядро)."""
        from chimera.modules import chain_nodes
        sn = chain_nodes._build_chain_sniffing(awg=True)
        self.assertTrue(sn["enabled"])
        self.assertIn("quic", sn["destOverride"])
        self.assertTrue(sn["metadataOnly"])


class TestLatencyDegradedWording(unittest.TestCase):
    """Кейс окт.2026 №9: отказ full-path с причиной «DNS на exit»/
    «v6-egress на exit» = нода ЖИВА (ICMP/туннель) → честное
    «деградация (причина)», НЕ «недоступна»; жёсткие причины — как раньше."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()

    _ND = {"host": "nl.example.com", "port": 443, "uuid": "uuid-x",
           "pubkey": "pbk-x", "shortid": "sid", "sni": "nl.example.com",
           "fp": "firefox", "proto": "reality"}

    def _patch_relay(self, **attrs):
        import chimera.modules.chain_relay as cr
        saved = {}
        for k, v in attrs.items():
            saved[k] = getattr(cr, k)
            setattr(cr, k, v)
        return saved

    def _restore_relay(self, saved):
        import chimera.modules.chain_relay as cr
        for k, v in saved.items():
            setattr(cr, k, v)

    def test_v6egress_reason_degradation_not_unavailable(self):
        from chimera.modules import chain_nodes
        saved = self._patch_relay(
            check_node_full_path=lambda nd, **kw: {
                "ok": False, "ms": 0.0, "reason": "v6-egress на exit",
                "infra": False},
            node_has_reality_creds=lambda nd: True)
        try:
            result = chain_nodes._speed_test_node_latency(
                "nl.example.com", 443, dict(self._ND))
        finally:
            self._restore_relay(saved)
        self.assertIn("деградация", result)
        self.assertIn("v6-egress на exit", result)
        self.assertNotIn("недоступна", result)

    def test_dns_reason_degradation_not_unavailable(self):
        from chimera.modules import chain_nodes
        saved = self._patch_relay(
            check_node_full_path=lambda nd, **kw: {
                "ok": False, "ms": 0.0, "reason": "DNS на exit",
                "infra": False},
            node_has_reality_creds=lambda nd: True)
        try:
            result = chain_nodes._speed_test_node_latency(
                "nl.example.com", 443, dict(self._ND))
        finally:
            self._restore_relay(saved)
        self.assertIn("деградация (DNS на exit)", result)
        self.assertNotIn("недоступна", result)

    def test_hard_reason_still_unavailable(self):
        from chimera.modules import chain_nodes
        saved = self._patch_relay(
            check_node_full_path=lambda nd, **kw: {
                "ok": False, "ms": 0.0, "reason": "нода не отвечает",
                "infra": False},
            node_has_reality_creds=lambda nd: True)
        try:
            result = chain_nodes._speed_test_node_latency(
                "nl.example.com", 443, dict(self._ND))
        finally:
            self._restore_relay(saved)
        self.assertIn("недоступна", result)
        self.assertNotIn("деградация", result)


# ═════════════════════════════════════════════════════════════════════════════
#  Кейс №10: пин на деградированную ноду (v6-egress) — здоровье в меню [P]
#  + v4-режим закрепления (DoH→direct, v6→BLOCK fast-fail)
# ═════════════════════════════════════════════════════════════════════════════
class TestPinV4RoutingRules(unittest.TestCase):
    """_build_chain_routing_rules(v4_pin=True): два правила перед catch-all."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()

    def test_v4_pin_inserts_doh_direct_and_v6_block_before_catchall(self):
        """v4_pin=True: DoH-резолверы → direct и ::/0 → BLOCK идут ПЕРЕД
        TCP catch-all (порядок важен: первый матч выигрывает)."""
        from chimera.modules import chain_nodes
        rules = chain_nodes._build_chain_routing_rules("chain-exit-1",
                                                       v4_pin=True)
        # catch-all — последний
        self.assertEqual(rules[-1]["network"], "tcp")
        self.assertEqual(rules[-1]["outboundTag"], "chain-exit-1")
        # предпоследнее — BLOCK ::/0 (v6 fast-fail)
        v6_block = rules[-2]
        self.assertEqual(v6_block.get("ip"), ["::/0"])
        self.assertEqual(v6_block.get("outboundTag"), "BLOCK")
        # перед ним — DoH-резолверы → direct
        doh = rules[-3]
        self.assertEqual(doh.get("outboundTag"), "direct")
        doms = doh.get("domain", [])
        self.assertIn("domain:cloudflare-dns.com", doms)
        self.assertIn("domain:dns.google", doms)
        self.assertIn("domain:dns.quad9.net", doms)
        # все домены с префиксом domain: (subdomain-match, как geosite-правила)
        self.assertTrue(all(d.startswith("domain:") for d in doms))

    def test_v4_pin_disabled_by_default_regression(self):
        """Регрессия: без флага — прежний список из 6 правил, никаких
        v4-правил (конфиги живых нод без флага байт-в-байт прежние)."""
        from chimera.modules import chain_nodes
        rules = chain_nodes._build_chain_routing_rules("chain-exit-1")
        self.assertEqual(len(rules), 6)
        for r in rules:
            self.assertNotIn("::/0", r.get("ip", []))
            self.assertNotIn("comment", r)
            self.assertNotIn("domain", r)

    def test_balancer_ignores_v4_pin(self):
        """Balancer-режим флаг игнорирует: v4-правил нет (не бывает
        «закреплённого v4» без закрепления)."""
        from chimera.modules import chain_nodes
        rules = chain_nodes._build_chain_routing_rules(
            "chain-balancer", balancer=True, v4_pin=True)
        self.assertEqual(rules[-1].get("balancerTag"), "chain-balancer")
        for r in rules:
            self.assertNotIn("::/0", r.get("ip", []))
            self.assertNotIn("domain", r)

    def test_v4_pin_port53_direct_precedes_v6_block(self):
        """Порядок: plain-DNS (порт 53) → direct идёт РАНЬШЕ BLOCK ::/0 —
        v6-DNS клиентов не должен съедать fast-fail (замер кейса №10)."""
        from chimera.modules import chain_nodes
        rules = chain_nodes._build_chain_routing_rules("chain-exit-2",
                                                       v4_pin=True)
        idx_port53 = next(i for i, r in enumerate(rules)
                          if r.get("port") == "53")
        idx_v6block = next(i for i, r in enumerate(rules)
                           if r.get("ip") == ["::/0"])
        self.assertLess(idx_port53, idx_v6block)


class TestPinV4State(unittest.TestCase):
    """Флаг chain_pinned_v4only: чтение/запись state.json, снятие пина."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        import tempfile
        from pathlib import Path as _P
        from chimera.modules import chain_nodes
        self._tmp = tempfile.mkdtemp()
        self._state_file = _P(self._tmp) / "state.json"
        self._orig = chain_nodes._CHAIN_STATE_FILE
        chain_nodes._CHAIN_STATE_FILE = self._state_file

    def tearDown(self):
        from chimera.modules import chain_nodes
        chain_nodes._CHAIN_STATE_FILE = self._orig

    def test_flag_roundtrip_and_clear(self):
        from chimera.modules import chain_nodes
        self.assertFalse(chain_nodes._chain_pinned_v4only())
        chain_nodes._pin_v4_set(True)
        self.assertTrue(chain_nodes._chain_pinned_v4only())
        # флаг ложится в существующий state.json, не затирая соседей
        st = json.loads(self._state_file.read_text())
        self.assertIs(st.get("chain_pinned_v4only"), True)
        st["chain_nodes"] = [{"host": "a.example"}]
        self._state_file.write_text(json.dumps(st))
        chain_nodes._pin_v4_set(True)
        st2 = json.loads(self._state_file.read_text())
        self.assertIs(st2.get("chain_pinned_v4only"), True)
        self.assertEqual(len(st2.get("chain_nodes", [])), 1)
        # снятие — ключ удаляется (не False-мусор)
        chain_nodes._pin_v4_set(False)
        st3 = json.loads(self._state_file.read_text())
        self.assertNotIn("chain_pinned_v4only", st3)
        self.assertFalse(chain_nodes._chain_pinned_v4only())

    def test_flag_corrupt_state_safe(self):
        """Битый state.json → False (не исключение)."""
        from chimera.modules import chain_nodes
        self._state_file.write_text("{broken json")
        self.assertFalse(chain_nodes._chain_pinned_v4only())


class TestPinHealthHints(unittest.TestCase):
    """_pin_health_hints: HM-вердикты + карантин + свежесть + нет данных."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        import tempfile
        import time
        from pathlib import Path as _P
        from chimera.modules import chain_nodes
        self._tmp = _P(tempfile.mkdtemp())
        self._now = time.time()
        self._hm = self._tmp / "hm.json"
        self._sb = self._tmp / "sb.json"
        self._orig_hm = chain_nodes._PIN_HM_STATE_FILE
        self._orig_sb = chain_nodes._PIN_SB_STATE_FILE
        chain_nodes._PIN_HM_STATE_FILE = self._hm
        chain_nodes._PIN_SB_STATE_FILE = self._sb

    def tearDown(self):
        from chimera.modules import chain_nodes
        chain_nodes._PIN_HM_STATE_FILE = self._orig_hm
        chain_nodes._PIN_SB_STATE_FILE = self._orig_sb

    def _nodes(self):
        return [{"host": "nl.example.com", "port": 443},
                {"host": "de.example.com", "port": 443},
                {"host": "fi.example.com", "port": 443},
                {"host": "ee.example.com", "port": 443}]

    def test_up_degr_down_quarantine_and_nodata(self):
        from chimera.modules import chain_nodes
        self._hm.write_text(json.dumps({
            "nl.example.com:443": {"up": False, "ms": 0.0,
                                   "reason": "v6-egress на exit",
                                   "last_check": self._now},
            "de.example.com:443": {"up": True, "ms": 157.4,
                                   "reason": "", "last_check": self._now},
            "fi.example.com:443": {"up": False, "ms": 0.0,
                                   "reason": "нода не отвечает",
                                   "last_check": self._now},
        }))
        self._sb.write_text(json.dumps({"nodes_meta": {
            "nl.example.com:443": {
                "fails": 3,
                "quarantine_until": self._now + 1200,
                "quarantine_until_str": "2026-10-22 20:45:50"},
        }}))
        hints = chain_nodes._pin_health_hints(self._nodes())
        nl = hints["nl.example.com:443"]
        self.assertIn("DEGR", nl)
        self.assertIn("v6-egress на exit", nl)
        self.assertIn("карантин до 20:45", nl)
        self.assertIn("UP 157мс", hints["de.example.com:443"])
        fi = hints["fi.example.com:443"]
        self.assertIn("DOWN", fi)
        self.assertIn("нода не отвечает", fi)
        self.assertNotIn("DEGR", fi)
        # нет данных ни в HM, ни в балансировщике — пустая подсказка
        self.assertEqual(hints["ee.example.com:443"], "")

    def test_stale_verdict_marked(self):
        """HM-вердикт старше 45 минут — помечается временем данных."""
        from chimera.modules import chain_nodes
        stale = self._now - 46 * 60
        self._hm.write_text(json.dumps({
            "nl.example.com:443": {"up": True, "ms": 100.0,
                                   "reason": "", "last_check": stale},
        }))
        self._sb.write_text("{}")
        hints = chain_nodes._pin_health_hints(self._nodes()[:1])
        self.assertIn("данные ", hints["nl.example.com:443"])

    def test_missing_files_all_empty(self):
        """Файлов нет — все подсказки пустые (меню не ломается)."""
        from chimera.modules import chain_nodes
        hints = chain_nodes._pin_health_hints(self._nodes())
        self.assertTrue(all(h == "" for h in hints.values()))
        self.assertEqual(len(hints), 4)


class TestPinProbeNode(unittest.TestCase):
    """_pin_probe_node: via-нода → зонд через цепочку, прямая → прямой."""

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()

    def _patch_relay(self, **attrs):
        import chimera.modules.chain_relay as cr
        saved = {}
        for k, v in attrs.items():
            saved[k] = getattr(cr, k)
            setattr(cr, k, v)
        return saved

    def _restore_relay(self, saved):
        import chimera.modules.chain_relay as cr
        for k, v in saved.items():
            setattr(cr, k, v)

    def test_via_node_uses_via_probe(self):
        from chimera.modules import chain_nodes
        calls = []

        def fake_via(nd, hops, **kw):
            calls.append("via")
            return {"ok": False, "ms": 0.0, "reason": "v6-egress на exit",
                    "detail": "туннель жив, AAAA умирают", "infra": False}

        def fake_direct(nd, **kw):
            calls.append("direct")
            return {"ok": True, "ms": 99.0, "reason": "", "infra": False}

        saved = self._patch_relay(
            check_via_node_full_path=fake_via,
            check_node_full_path=fake_direct,
            load_relay_hops=lambda: [{"tag": "hop-fi"}],
            hop_via_tag_for=lambda nd, hops: "hop-fi")
        try:
            verdict = chain_nodes._pin_probe_node(
                {"host": "ee.example.com", "port": 443, "via": "hop-fi"})
        finally:
            self._restore_relay(saved)
        self.assertEqual(calls, ["via"])
        self.assertEqual(verdict["reason"], "v6-egress на exit")

    def test_direct_node_uses_direct_probe(self):
        from chimera.modules import chain_nodes
        calls = []

        def fake_via(nd, hops, **kw):
            calls.append("via")
            return {"ok": True, "ms": 1.0, "reason": "", "infra": False}

        def fake_direct(nd, **kw):
            calls.append("direct")
            return {"ok": True, "ms": 98.5, "reason": "цепь жива",
                    "infra": False}

        saved = self._patch_relay(
            check_via_node_full_path=fake_via,
            check_node_full_path=fake_direct,
            load_relay_hops=lambda: [{"tag": "hop-fi"}],
            hop_via_tag_for=lambda nd, hops: None)
        try:
            verdict = chain_nodes._pin_probe_node(
                {"host": "nl.example.com", "port": 443})
        finally:
            self._restore_relay(saved)
        self.assertEqual(calls, ["direct"])
        self.assertTrue(verdict["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
