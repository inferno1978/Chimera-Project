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
     (xhttp и reality ветки).
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
#  BUGFIX (v53): регенерация конфига сохраняет юзеров (anti-EOF)
# ══════════════════════════════════════════════════════════════════════════════
class TestChainEntryMultiPreservesUsers(unittest.TestCase):
    """
    РЕГРЕССИЯ v53 (реальный инцидент на VPS без IPv6):
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

    # UUID из клиентской ссылки (инцидент на chimeravpn.online)
    _LINK_UUID = "b707d8cc-24de-4ac8-a402-4005ee9ebd9e"
    # UUID, который попал в state.json (и раньше — единственный в clients)
    _STATE_UUID = "dc1c190b-7fdc-4cfc-a227-1c7e4fb063a9"

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
