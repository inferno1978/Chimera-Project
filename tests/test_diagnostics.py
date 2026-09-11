#!/usr/bin/env python3
"""
tests/test_diagnostics.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/diagnostics.py.

Покрывает:
  1. _diag_fmt_bytes — форматирование байт
  2. _diag_sni_port — порт TLS-проверки SNI-цели
  3. _diag_make_counters — создание счётчиков
  4. _diag_chk — валидатор с счётчиками
  5. _diag_resolve_config — поиск и чтение config.json
"""
from __future__ import annotations

import json
import socket
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


class TestDiagFmtBytes(unittest.TestCase):
    """_diag_fmt_bytes — форматирование байт."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_zero(self):
        from chimera.modules.diagnostics import _diag_fmt_bytes
        self.assertEqual(_diag_fmt_bytes(0), "0 Б")

    def test_less_than_kib(self):
        from chimera.modules.diagnostics import _diag_fmt_bytes
        self.assertEqual(_diag_fmt_bytes(500), "500 Б")

    def test_kib(self):
        from chimera.modules.diagnostics import _diag_fmt_bytes
        self.assertEqual(_diag_fmt_bytes(1024), "1.0 КБ")

    def test_mib(self):
        from chimera.modules.diagnostics import _diag_fmt_bytes
        self.assertEqual(_diag_fmt_bytes(1024 ** 2), "1.0 МБ")

    def test_gib(self):
        from chimera.modules.diagnostics import _diag_fmt_bytes
        self.assertIn("ГБ", _diag_fmt_bytes(1024 ** 3))


class TestDiagSniPort(unittest.TestCase):
    """_diag_sni_port — порт TLS-проверки SNI-цели.

    Сценарий бага: server_port сменён на 9443, но шаг 6 проверки
    продолжал стучаться на хардкод-443 → ложный WARN «Не удалось
    получить сертификат».
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_own_domain_returns_server_port(self):
        from chimera.modules.diagnostics import _diag_sni_port
        self.assertEqual(
            _diag_sni_port("chimeraprodcdn.online", "chimeraprodcdn.online", 9443),
            9443)

    def test_own_domain_port_443_unchanged(self):
        from chimera.modules.diagnostics import _diag_sni_port
        self.assertEqual(
            _diag_sni_port("example.com", "example.com", 443), 443)

    def test_foreign_sni_returns_443(self):
        from chimera.modules.diagnostics import _diag_sni_port
        self.assertEqual(
            _diag_sni_port("www.cloudflare.com", "example.com", 9443), 443)

    def test_empty_domain_fallback_sni_returns_443(self):
        from chimera.modules.diagnostics import _diag_sni_port
        # домен не задан → _sni = www.google.com (fallback) → 443
        self.assertEqual(
            _diag_sni_port("www.google.com", "", 9443), 443)

    def test_empty_domain_own_sni_returns_443(self):
        from chimera.modules.diagnostics import _diag_sni_port
        # без домена нельзя понять свой/чужой SNI → безопасный 443
        self.assertEqual(
            _diag_sni_port("chimeraprodcdn.online", "", 9443), 443)

    def test_reality_sni_differs_from_domain_returns_443(self):
        from chimera.modules.diagnostics import _diag_sni_port
        # reality_sni (внешний камуфляж) ≠ домену → чужой → 443
        self.assertEqual(
            _diag_sni_port("camo.example.net", "example.com", 9443), 443)


class TestDiagMakeCounters(unittest.TestCase):
    """_diag_make_counters — создание счётчиков."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_list_of_four_zeros(self):
        from chimera.modules.diagnostics import _diag_make_counters
        counters = _diag_make_counters()
        self.assertEqual(counters, [0, 0, 0, 0])


class TestDiagChk(unittest.TestCase):
    """_diag_chk — валидатор с счётчиками."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _mock_core(self):
        core = MagicMock()
        core._box_wrap_msg = MagicMock()
        core._box_row = MagicMock()
        core._box_warn = MagicMock()
        core.CYAN = ""
        core.GREEN = ""
        core.RED = ""
        core.YELLOW = ""
        core.DIM = ""
        core.NC = ""
        core.BOLD = ""
        return core

    def test_returns_true_and_increments_passed(self):
        from chimera.modules import diagnostics
        counters = diagnostics._diag_make_counters()
        with patch.object(diagnostics, "_core_module", return_value=self._mock_core()), \
             patch.object(diagnostics, "_diag_ok") as mock_ok:
            result = diagnostics._diag_chk(counters, True, "ok", "fail")
        self.assertTrue(result)
        self.assertEqual(counters[0], 1)  # total
        self.assertEqual(counters[1], 1)  # passed
        mock_ok.assert_called_once_with("ok")

    def test_returns_false_and_increments_err(self):
        from chimera.modules import diagnostics
        counters = diagnostics._diag_make_counters()
        with patch.object(diagnostics, "_core_module", return_value=self._mock_core()), \
             patch.object(diagnostics, "_diag_err") as mock_err:
            result = diagnostics._diag_chk(counters, False, "ok", "fail")
        self.assertFalse(result)
        self.assertEqual(counters[0], 1)  # total
        self.assertEqual(counters[3], 1)  # err
        mock_err.assert_called_once_with("fail")

    def test_warn_increments_warn_not_err(self):
        from chimera.modules import diagnostics
        counters = diagnostics._diag_make_counters()
        with patch.object(diagnostics, "_core_module", return_value=self._mock_core()), \
             patch.object(diagnostics, "_diag_err") as mock_err:
            result = diagnostics._diag_chk(counters, False, "ok", "fail", is_warn=True)
        self.assertFalse(result)
        self.assertEqual(counters[2], 1)  # warn
        self.assertEqual(counters[3], 0)  # err not incremented
        mock_err.assert_not_called()


class TestDiagResolveConfig(unittest.TestCase):
    """_diag_resolve_config — поиск и чтение config.json."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "config.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _mock_core(self):
        core = MagicMock()
        core.DIAG_CONFIG_FILE = self._cfg
        core.DIAG_ALT_CONFIG_FILE = Path("/tmp/nonexistent_alt_cfg.json")
        core._box_wrap_msg = MagicMock()
        core._box_row = MagicMock()
        core.CYAN = ""
        core.DIM = ""
        core.NC = ""
        return core

    def test_returns_none_when_no_config(self):
        from chimera.modules import diagnostics
        core = self._mock_core()
        core.DIAG_CONFIG_FILE = Path("/tmp/nonexistent_main_cfg.json")
        with patch.object(diagnostics, "_core_module", return_value=core), \
             patch.object(diagnostics, "_diag_err"):
            path, cfg = diagnostics._diag_resolve_config()
        self.assertIsNone(path)
        self.assertEqual(cfg, {})

    def test_returns_config_when_valid(self):
        from chimera.modules import diagnostics
        self._cfg.write_text(json.dumps({"inbounds": []}))
        with patch.object(diagnostics, "_core_module", return_value=self._mock_core()):
            path, cfg = diagnostics._diag_resolve_config()
        self.assertIsNotNone(path)
        self.assertIn("inbounds", cfg)

    def test_returns_empty_on_corrupt(self):
        from chimera.modules import diagnostics
        self._cfg.write_text("{invalid json")
        with patch.object(diagnostics, "_core_module", return_value=self._mock_core()), \
             patch.object(diagnostics, "_diag_err"):
            path, cfg = diagnostics._diag_resolve_config()
        self.assertIsNotNone(path)
        self.assertEqual(cfg, {})


class TestDiagTcpProbe(unittest.TestCase):
    """_diag_tcp_probe — TCP-ping с перебором IPv4/IPv6 из getaddrinfo()."""

    def setUp(self):
        _setup_core_in_sysmodules()
        # По умолчанию DoH-резолв возвращает None → _diag_tcp_probe
        # уходит в fallback-ветку на socket.getaddrinfo() — это позволяет
        # старым тестам проверять логику перебора address family.
        # Тесты, проверяющие DoH-путь, переопределяют этот patch локально.
        patcher = patch("chimera.modules.chain_nodes._resolve_host_fresh",
                        return_value=None)
        self._doh_patcher = patcher
        self._doh_patcher.start()
        self.addCleanup(self._doh_patcher.stop)

    def _make_addrinfo(self, family, ip, port=443):
        """Хелпер: строит кортеж формата getaddrinfo."""
        if family == socket.AF_INET:
            sockaddr = (ip, port, 0, 0)
        else:
            sockaddr = (ip, port, 0, 0)
        return (family, socket.SOCK_STREAM, 6, "", sockaddr)

    def test_dns_fail_returns_false_with_detail(self):
        from chimera.modules import diagnostics
        with patch.object(diagnostics.socket, "getaddrinfo",
                          side_effect=socket.gaierror("Name or service not known")):
            alive, detail, lat = diagnostics._diag_tcp_probe("nonexistent.invalid", 443)
        self.assertFalse(alive)
        self.assertIn("DNS fail", detail)
        self.assertEqual(lat, -1)

    def test_dns_empty_returns_false(self):
        from chimera.modules import diagnostics
        with patch.object(diagnostics.socket, "getaddrinfo", return_value=[]):
            alive, detail, lat = diagnostics._diag_tcp_probe("example.com", 443)
        self.assertFalse(alive)
        self.assertEqual(detail, "DNS empty")
        self.assertEqual(lat, -1)

    def test_ipv4_only_success(self):
        """Классический кейс: домен резолвится в IPv4, коннект успешен."""
        from chimera.modules import diagnostics
        addrinfos = [self._make_addrinfo(socket.AF_INET, "1.2.3.4")]
        mock_sock = MagicMock()
        with patch.object(diagnostics.socket, "getaddrinfo", return_value=addrinfos), \
             patch.object(diagnostics.socket, "socket", return_value=mock_sock):
            alive, detail, lat = diagnostics._diag_tcp_probe("example.com", 443)
        self.assertTrue(alive)
        self.assertIn("IPv4", detail)
        self.assertIn("1.2.3.4", detail)
        self.assertGreaterEqual(lat, 0)  # latency должна быть неотрицательной
        mock_sock.connect.assert_called_once()
        mock_sock.close.assert_called_once()

    def test_ipv6_only_unreachable_on_ipv4_only_server(self):
        """Кейс totalshadows.online: только AAAA, на сервере нет IPv6 → 'Network is unreachable'."""
        from chimera.modules import diagnostics
        addrinfos = [self._make_addrinfo(socket.AF_INET6, "2a12:bec4:1460:443::2")]
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("Network is unreachable")
        with patch.object(diagnostics.socket, "getaddrinfo", return_value=addrinfos), \
             patch.object(diagnostics.socket, "socket", return_value=mock_sock):
            alive, detail, lat = diagnostics._diag_tcp_probe("totalshadows.online", 443)
        self.assertFalse(alive)
        self.assertIn("IPv6", detail)
        self.assertIn("unreachable", detail.lower())
        # Подсказка для diag-вывода: detail не должен содержать IPv4-успеха
        self.assertNotIn("IPv4", detail)
        self.assertEqual(lat, -1)

    def test_dualstack_ipv6_fails_ipv4_succeeds(self):
        """Dual-stack домен, IPv6 недоступен, IPv4 отвечает → нода жива."""
        from chimera.modules import diagnostics
        addrinfos = [
            self._make_addrinfo(socket.AF_INET6, "2a12::1"),
            self._make_addrinfo(socket.AF_INET, "1.2.3.4"),
        ]
        # Каждый вызов socket() возвращает новый mock — один для IPv6 (fail), один для IPv4 (ok)
        sock_v6 = MagicMock()
        sock_v6.connect.side_effect = OSError("Network is unreachable")
        sock_v4 = MagicMock()
        with patch.object(diagnostics.socket, "getaddrinfo", return_value=addrinfos), \
             patch.object(diagnostics.socket, "socket", side_effect=[sock_v6, sock_v4]):
            alive, detail, lat = diagnostics._diag_tcp_probe("dualstack.example.com", 443)
        self.assertTrue(alive)
        self.assertIn("IPv4", detail)
        self.assertIn("1.2.3.4", detail)
        self.assertGreaterEqual(lat, 0)

    def test_dualstack_both_fail(self):
        """Dual-stack домен, обе семьи упали → False, detail содержит обе ошибки."""
        from chimera.modules import diagnostics
        addrinfos = [
            self._make_addrinfo(socket.AF_INET6, "2a12::1"),
            self._make_addrinfo(socket.AF_INET, "1.2.3.4"),
        ]
        sock_v6 = MagicMock()
        sock_v6.connect.side_effect = OSError("Network is unreachable")
        sock_v4 = MagicMock()
        sock_v4.connect.side_effect = socket.timeout("timed out")
        with patch.object(diagnostics.socket, "getaddrinfo", return_value=addrinfos), \
             patch.object(diagnostics.socket, "socket", side_effect=[sock_v6, sock_v4]):
            alive, detail, lat = diagnostics._diag_tcp_probe("dualstack.example.com", 443)
        self.assertFalse(alive)
        self.assertIn("IPv6", detail)
        self.assertIn("IPv4", detail)
        self.assertIn("unreachable", detail.lower())
        self.assertIn("timeout", detail.lower())
        self.assertEqual(lat, -1)

    def test_timeout_10_seconds_passed_to_socket(self):
        """Проверка что timeout=10 доходит до socket.settimeout()."""
        from chimera.modules import diagnostics
        addrinfos = [self._make_addrinfo(socket.AF_INET, "1.2.3.4")]
        mock_sock = MagicMock()
        with patch.object(diagnostics.socket, "getaddrinfo", return_value=addrinfos), \
             patch.object(diagnostics.socket, "socket", return_value=mock_sock):
            diagnostics._diag_tcp_probe("example.com", 443, timeout=10)
        mock_sock.settimeout.assert_called_once_with(10)

    def test_dedup_duplicate_addrinfo_entries(self):
        """getaddrinfo часто возвращает дубликаты — должны быть дедуплицированы."""
        from chimera.modules import diagnostics
        # Тот же адрес дважды
        addrinfos = [
            self._make_addrinfo(socket.AF_INET, "1.2.3.4"),
            self._make_addrinfo(socket.AF_INET, "1.2.3.4"),
        ]
        mock_sock = MagicMock()
        with patch.object(diagnostics.socket, "getaddrinfo", return_value=addrinfos) as mock_gai, \
             patch.object(diagnostics.socket, "socket", return_value=mock_sock) as mock_socket_factory:
            diagnostics._diag_tcp_probe("example.com", 443)
        # Только ОДИН сокет создан — дубликат не вызывал второй коннект
        mock_socket_factory.assert_called_once()
        mock_sock.connect.assert_called_once()

    def test_doh_resolves_overrides_getaddrinfo(self):
        """DoH-резолв отдаёт АКТУАЛЬНЫЙ IP — getaddrinfo не должен вызываться.

        Симулирует кейс из баг-репорта: на сервере в /etc/hosts или в кэше
        systemd-resolved прописан СТАРЫЙ IP домена, но реальная A-запись в
        DNS-провайдере уже указывает на НОВЫЙ IP. DoH идёт напрямую к
        Cloudflare/Google, минуя локальный кэш, и возвращает НОВЫЙ IP.
        """
        from chimera.modules import diagnostics
        # DoH отдаёт НОВЫЙ IP
        with patch("chimera.modules.chain_nodes._resolve_host_fresh",
                   return_value="5.6.7.8"), \
             patch.object(diagnostics.socket, "getaddrinfo",
                          side_effect=AssertionError(
                              "getaddrinfo не должен вызываться при успешном DoH")) as mock_gai, \
             patch.object(diagnostics.socket, "socket") as mock_socket_factory:
            mock_sock = MagicMock()
            mock_socket_factory.return_value = mock_sock
            alive, detail, lat = diagnostics._diag_tcp_probe("example.com", 443)
        self.assertTrue(alive)
        self.assertIn("5.6.7.8", detail)
        self.assertIn("IPv4", detail)
        mock_gai.assert_not_called()
        mock_sock.connect.assert_called_once()
        # connect() вызван с НОВЫМ IP
        connected_to = mock_sock.connect.call_args[0][0]
        self.assertEqual(connected_to[0], "5.6.7.8")


if __name__ == "__main__":
    unittest.main(verbosity=2)
