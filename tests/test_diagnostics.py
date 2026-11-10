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
  6. _diag_dropin_danger_keys — разбор опасных директив drop-in'а
  7. _diag_check_xray_service — ветка drop-in'ов (штатный/безобидный/опасный)
  8. Волна-4 (заголовки конвейерных отправителей): отправка отчёта из
     меню — _tg_send_report_from_menu: конвейер tg_bot.tg_notify_event
     (НОВОЕ событие diag_report; шапка/фильтр/иконка от конвейера),
     фолбэк — прежний прямой curl (+ events-фильтр + шапка
     node_identity.server_header, фолбэк hostname); muted → молчит;
     длинный отчёт → sendDocument; суть (пункты диагностики) не меняется
"""
from __future__ import annotations

import io
import json
import socket
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
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
            _diag_sni_port("cdn.example", "cdn.example", 9443),
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
            _diag_sni_port("cdn.example", "", 9443), 443)

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
        """Кейс fleet-a.example: только AAAA, на сервере нет IPv6 → 'Network is unreachable'."""
        from chimera.modules import diagnostics
        addrinfos = [self._make_addrinfo(socket.AF_INET6, "2001:db8:1460:443::2")]
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("Network is unreachable")
        with patch.object(diagnostics.socket, "getaddrinfo", return_value=addrinfos), \
             patch.object(diagnostics.socket, "socket", return_value=mock_sock):
            alive, detail, lat = diagnostics._diag_tcp_probe("fleet-a.example", 443)
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


class TestDiagTopHostsAlignment(unittest.TestCase):
    """Шаг 8 «Топ хостов по маршрутизации» — выравнивание прогресс-баров.

    Сценарий бага: {host:<32} паддил только короткие хосты, но не усекал
    длинные — колонки count/%/бара «плясали» (googlevideo.com, 35 симв. —
    сдвиг вправо), а hosts длиннее ~38 симв. (nperf.net, 42) вылезали за
    ширину рамки и переносили бар на новую строку.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    @staticmethod
    def _log(host: str, port: str, tag: str) -> str:
        return (f"2026/10/07 10:00:00 [Info] proxy/vless/inbound: "
                f"connection accepted tcp:{host}:{port} "
                f"[inbound-vless -> {tag}]")

    def test_fit_host_pads_and_truncates(self):
        from chimera.modules.diagnostics import _diag_fit_host, _DIAG_HOST_COL_W
        # короткий — паддинг до ширины колонки
        padded = _diag_fit_host("i.ytimg.com")
        self.assertEqual(len(padded), _DIAG_HOST_COL_W)
        self.assertTrue(padded.startswith("i.ytimg.com"))
        # граничный (35 симв., googlevideo) — влезает целиком
        gv = "rr1---sn-pivhx-n8v6.googlevideo.com"
        self.assertEqual(_diag_fit_host(gv), f"{gv:<{_DIAG_HOST_COL_W}}")
        # длинный — ровно ширина колонки, усечение посередине,
        # доменная зона сохранена
        long_host = "fi-oneprovider-helsinki-01-1g-1.nperf.net"
        fitted = _diag_fit_host(long_host)
        self.assertEqual(len(fitted), _DIAG_HOST_COL_W)
        self.assertIn("…", fitted)
        self.assertTrue(fitted.endswith(long_host[-12:]))

    def test_fit_host_narrow_box(self):
        """Узкая рамка (min 64) — колонка сужается, строка не переносится."""
        from chimera.modules.diagnostics import _diag_fit_host
        long_host = "fi-oneprovider-helsinki-01-1g-1.nperf.net"
        fitted = _diag_fit_host(long_host, 22)
        self.assertEqual(len(fitted), 22)
        self.assertTrue(fitted.endswith(long_host[-12:]))

    def test_rows_bars_aligned_no_wrap(self):
        """Полный рендер топа: у всех строк бара одна стартовая колонка,
        бар ровно 20 символов (нет переносов за рамку), длинный хост
        усечён с сохранением доменной зоны."""
        import contextlib
        import io
        import os
        import re as _re
        from chimera.modules import diagnostics

        fake_core = sys.modules["chimera._core"]
        box_w = fake_core._BOX_W

        hosts = [
            ("149.154.175.50", "443", "chain-exit-3", 8),          # короткий IP
            ("fi-oneprovider-helsinki-01-1g-1.nperf.net", "443", "chain-exit-5", 5),  # 42 симв.
            ("speedtest.fi.senko.network", "8080", "chain-exit-4", 4),  # host:port
            ("rr1---sn-pivhx-n8v6.googlevideo.com", "443", "direct", 6),  # 35 симв.
            ("i.ytimg.com", "443", "direct", 3),                   # 11 симв.
        ]
        lines = []
        for host, port, tag, cnt in hosts:
            lines.extend([self._log(host, port, tag)] * cnt)

        with tempfile.NamedTemporaryFile("w", suffix=".log",
                                         delete=False) as f:
            f.write("\n".join(lines) + "\n")
            log_path = f.name
        self.addCleanup(os.unlink, log_path)

        old = fake_core.DIAG_ACCESS_LOG
        fake_core.DIAG_ACCESS_LOG = Path(log_path)
        self.addCleanup(setattr, fake_core, "DIAG_ACCESS_LOG", old)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            diagnostics._diag_top_hosts(n=10)
        out = _re.sub(r"\033\[[0-9;]*m", "", buf.getvalue())

        bar_lines = [l for l in out.splitlines() if ("▓" in l or "░" in l)]
        # все 5 хостов в топе (в обеих секциях)
        self.assertGreaterEqual(len(bar_lines), 5, out)
        # 1) бар ровно 20 символов в каждой строке → переносов нет
        for l in bar_lines:
            n_bar = len(l) - len(l.replace("▓", "").replace("░", ""))
            self.assertEqual(n_bar, 20, f"бар не 20 симв.: {l!r}")
        # 2) стартовая колонка бара одинакова у всех строк
        starts = {l.find("▓") if "▓" in l else l.find("░")
                  for l in bar_lines}
        self.assertEqual(len(starts), 1,
                         f"колонки бара разъехались: {starts}\n{out}")
        # 3) строки не вылезают за рамку (+2 на ║…║)
        for l in bar_lines:
            self.assertLessEqual(len(l), box_w + 2, l)
        # 4) длинный хост усечён «…», доменная зона видна
        self.assertTrue(any("…" in l and "nperf.net" in l
                            for l in bar_lines), out)
        # 5) короткий хост и граничный googlevideo отображаются целиком
        self.assertTrue(any("i.ytimg.com" in l for l in bar_lines), out)
        self.assertTrue(any("googlevideo.com" in l for l in bar_lines), out)


class TestFullpathNdFromOutbound(unittest.TestCase):
    """Реконструкция nd-dict для full-path проверки (шаг 5 мастера)
    из outbound прод-конфига с sockopt.dialerProxy.

    Регрессия: path/xhttp_mode раньше не реконструировались — чекер
    уходил на дефолты "/"+"stream-up" и для xhttp/xhttp_reality нод с
    кастомным path full-path проверка валилась ложно."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _ob(self, stream: dict) -> dict:
        return {
            "tag": "chain-exit-2",
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": "203.0.113.10", "port": 8443,
                "users": [{"id": "d34df00d-1111-2222-3333-444455556666",
                           "encryption": "none"}],
            }]},
            "streamSettings": stream,
        }

    def test_no_dialer_proxy_returns_none(self):
        from chimera.modules.diagnostics import _fullpath_nd_from_outbound
        ob = self._ob({"network": "tcp", "security": "reality",
                       "sockopt": {}, "realitySettings": {}})
        vn = ob["settings"]["vnext"][0]
        self.assertIsNone(_fullpath_nd_from_outbound(ob, vn))

    def test_no_dialer_proxy_direct_reconstruction_with_flag(self):
        """require_via=False: прямые outbound-ы реконструируются тоже
        (шаг 5: прямой REALITY-зонд вместо банящегося TCP-ping,
        кейс окт. 2026 №3)."""
        from chimera.modules.diagnostics import _fullpath_nd_from_outbound
        ob = self._ob({
            "network": "tcp", "security": "reality", "sockopt": {},
            "realitySettings": {
                "publicKey": "PUBKEY-DIRECT", "shortId": "abcd1234",
                "serverName": "nl.example.com", "fingerprint": "firefox",
            }})
        vn = ob["settings"]["vnext"][0]
        nd = _fullpath_nd_from_outbound(ob, vn, require_via=False)
        self.assertIsNotNone(nd)
        self.assertEqual(nd["host"], "203.0.113.10")   # address из vnext
        self.assertEqual(nd["pubkey"], "PUBKEY-DIRECT")
        self.assertEqual(nd["shortid"], "abcd1234")
        self.assertEqual(nd["sni"], "nl.example.com")  # serverName из REALITY
        self.assertEqual(nd["via"], "")

    def test_xhttp_reality_custom_path_mode(self):
        from chimera.modules.diagnostics import _fullpath_nd_from_outbound
        ob = self._ob({
            "network": "xhttp", "security": "reality",
            "sockopt": {"dialerProxy": "hop-eu", "tcpCongestion": "bbr"},
            "xhttpSettings": {"mode": "packet-up", "path": "/ab12cd34",
                              "extra": {}},
            "realitySettings": {
                "show": False, "fingerprint": "firefox",
                "serverName": "exit.example.com",
                "publicKey": "PBK-123", "shortId": "SID-456",
                "spiderX": "/"},
        })
        vn = ob["settings"]["vnext"][0]
        nd = _fullpath_nd_from_outbound(ob, vn)
        self.assertIsNotNone(nd)
        self.assertEqual(nd["proto"], "xhttp_reality")
        self.assertEqual(nd["path"], "/ab12cd34")       # НЕ дефолт "/"
        self.assertEqual(nd["xhttp_mode"], "packet-up")  # НЕ дефолт
        self.assertEqual(nd["via"], "hop-eu")
        self.assertEqual(nd["uuid"], "d34df00d-1111-2222-3333-444455556666")
        self.assertEqual(nd["pubkey"], "PBK-123")
        self.assertEqual(nd["shortid"], "SID-456")
        self.assertEqual(nd["sni"], "exit.example.com")
        self.assertEqual(nd["fp"], "firefox")
        self.assertEqual(nd["host"], "203.0.113.10")
        self.assertEqual(nd["port"], 8443)

    def test_reality_sni_from_server_names(self):
        from chimera.modules.diagnostics import _fullpath_nd_from_outbound
        ob = self._ob({
            "network": "tcp", "security": "reality",
            "sockopt": {"dialerProxy": "hop-eu"},
            "realitySettings": {
                "serverNames": ["sni.example.com"],
                "publicKey": "PBK", "shortIds": ["SID1", "SID2"],
                "fingerprint": "chrome"},
        })
        vn = ob["settings"]["vnext"][0]
        nd = _fullpath_nd_from_outbound(ob, vn)
        self.assertEqual(nd["proto"], "reality")
        self.assertEqual(nd["sni"], "sni.example.com")
        self.assertEqual(nd["shortid"], "SID1")          # первый из shortIds
        self.assertEqual(nd["flow"], "")                  # users без flow

    def test_reality_sni_from_server_name_string(self):
        """ГЛАВНЫЙ кейс шага 5: прод-outbound REALITY хранит serverName
        (строку), а не serverNames. Раньше SNI брался = host (IP) →
        REALITY-проба через цепочку валилась ложно для IP-хостов."""
        from chimera.modules.diagnostics import _fullpath_nd_from_outbound
        ob = self._ob({
            "network": "tcp", "security": "reality",
            "sockopt": {"dialerProxy": "hop-eu"},
            "realitySettings": {
                "serverName": "real-sni.example.com",
                "publicKey": "PBK", "shortId": "SID9",
                "fingerprint": "chrome"},
        })
        vn = ob["settings"]["vnext"][0]
        nd = _fullpath_nd_from_outbound(ob, vn)
        self.assertEqual(nd["sni"], "real-sni.example.com")  # НЕ 203.0.113.10
        self.assertEqual(nd["shortid"], "SID9")              # shortId-строка

    def test_xhttp_tls_sni_fp_from_tls_settings(self):
        from chimera.modules.diagnostics import _fullpath_nd_from_outbound
        ob = self._ob({
            "network": "xhttp", "security": "tls",
            "sockopt": {"dialerProxy": "hop-eu"},
            "xhttpSettings": {"mode": "stream-up", "path": "/xy9876"},
            "tlsSettings": {"serverName": "tls.example.com",
                            "fingerprint": "safari",
                            "alpn": ["h2", "http/1.1"]},
        })
        vn = ob["settings"]["vnext"][0]
        nd = _fullpath_nd_from_outbound(ob, vn)
        self.assertEqual(nd["proto"], "xhttp")
        self.assertEqual(nd["sni"], "tls.example.com")   # из tlsSettings
        self.assertEqual(nd["fp"], "safari")             # из tlsSettings
        self.assertEqual(nd["path"], "/xy9876")


class TestDiagRoutingLiveViaHop(unittest.TestCase):
    """Шаг 5 мастера («Тест маршрутизации») для via-нод (dialerProxy).

    Регрессия stale-config кейса: хоп выключен/удалён в state ПОСЛЕ
    последней сборки конфига → outbound всё ещё содержит dialerProxy.
    Раньше шаг 5 выдавал ERR «цепочка НЕ РАБОТАЕТ (via не найден/
    выключен)» и противоречил шагу 11 того же запуска («нода работает
    напрямую»). Теперь — WARN «пересоберите конфиг», full-path
    не вызывается (зеркалит шаг 11 / меню [T] / HM).
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    @staticmethod
    def _via_ob() -> dict:
        return {
            "tag": "chain-exit-2",
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": "203.0.113.10", "port": 8443,
                "users": [{"id": "d34df00d-1111-2222-3333-444455556666",
                           "encryption": "none"}],
            }]},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "sockopt": {"dialerProxy": "hop-eu"},
                "realitySettings": {
                    "serverName": "exit.example.com",
                    "publicKey": "PBK-123", "shortId": "SID-456",
                    "fingerprint": "chrome"},
            },
        }

    @staticmethod
    def _hop(enabled: bool) -> dict:
        return {
            "tag": "hop-eu", "host": "203.0.113.20", "port": 443,
            "uuid": "d34df00d-1111-2222-3333-444455556666",
            "pubkey": "RkFLRS1wYi1rZXk", "shortid": "0f1e2d3c4b5a6978",
            "sni": "fi.example.com", "fp": "chrome", "proto": "reality",
            "via": "", "enabled": enabled,
        }

    def _run(self, hops, chain_result=None):
        """_diag_check_routing_live с одним via-outbound.

        Возвращает (stdout, counters, fullpath_calls).
        """
        import chimera.modules.diagnostics as dg
        import chimera.modules.chain_relay as cr

        counters = dg._diag_make_counters()
        calls: list = []

        def _fake_fullpath(nd, hs, **kw):
            calls.append((nd, hs))
            return dict(chain_result) if chain_result else {
                "ok": False, "ms": 0.0, "detail": "не должен вызываться",
                "reason": "x", "legs": {}, "xray_tail": ""}

        out = io.StringIO()
        with redirect_stdout(out), \
             patch.object(cr, "load_relay_hops", lambda: hops), \
             patch.object(cr, "check_via_node_full_path", _fake_fullpath):
            dg._diag_check_routing_live(
                {"outbounds": [self._via_ob()]}, counters)
        return out.getvalue(), counters, calls

    def test_disabled_hop_warns_no_false_fail(self):
        """Хоп выключен, конфиг stale → WARN «пересоберите конфиг»,
        ERR-счётчик не растёт, full-path не вызывается."""
        out, counters, calls = self._run([self._hop(enabled=False)])
        self.assertEqual(calls, [],
                         "full-path не должен вызываться для выключенного хопа")
        self.assertIn("пересоберите конфиг", out)
        self.assertIn("hop-eu", out)
        # [total, passed, warnings, errors]: 1 проверка, 0 ошибок, 1 WARN
        self.assertEqual(counters, [1, 0, 1, 0])
        self.assertNotIn("НЕ РАБОТАЕТ", out)

    def test_enabled_hop_fullpath_ok(self):
        """Хоп активен → full-path вызывается с реконструированным nd
        и списком хопов; ok → «full-path OK», ошибок нет."""
        _h = self._hop(enabled=True)
        out, counters, calls = self._run(
            [_h],
            {"ok": True, "ms": 412.0, "exit_ip": "203.0.113.10",
             "speed_mbps": 0.0, "detail": "цепочка жива", "reason": "цепь жива",
             "legs": {}, "xray_tail": ""})
        self.assertEqual(len(calls), 1)
        nd, hs = calls[0]
        self.assertEqual(nd["via"], "hop-eu")          # реконструкция
        self.assertEqual(nd["sni"], "exit.example.com")
        self.assertEqual(nd["pubkey"], "PBK-123")
        self.assertIs(hs[0], _h)                       # хопы переданы как есть
        self.assertIn("full-path OK", out)
        self.assertIn("412", out)
        self.assertEqual(counters, [1, 1, 0, 0])

    def test_enabled_hop_fullpath_fail_is_err(self):
        """Хоп активен, цепь упала → честный ERR с деталью чекера."""
        out, counters, calls = self._run(
            [self._hop(enabled=True)],
            {"ok": False, "ms": 0.0, "exit_ip": "", "speed_mbps": 0.0,
             "detail": "хоп→нода недостижима (mini-client: нода не отвечает)",
             "reason": "хоп→нода недостижима", "legs": {}, "xray_tail": ""})
        self.assertEqual(len(calls), 1)
        self.assertIn("НЕ РАБОТАЕТ", out)
        self.assertIn("хоп→нода недостижима", out)
        self.assertEqual(counters, [1, 0, 0, 1])


class TestDiagRoutingDesyncHint(unittest.TestCase):
    """Шаг 5, прямой REALITY-зонд FAIL + рассинхрон outbound ↔ БД нод.

    Живой кейс окт.2026 №5: SmartBalancer патчнул chain-exit-1 вживую
    (shortId не обновился, via-ноде не поставился dialerProxy) → зонд
    честно FAIL на битом outbound, но сообщение «нода не отвечает»
    сбивало с толку при живой ноде ([T]/HM зелёные). Теперь при
    несовпадении кредов outbound со state.json chain_nodes добавляется
    подсказка «конфиг патчен без пересборки — пересоберите».
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    @staticmethod
    def _direct_ob(short_id="SID-DB"):
        """Прямой (без dialerProxy) REALITY-outbound chain-exit-1."""
        return {
            "tag": "chain-exit-1", "protocol": "vless",
            "settings": {"vnext": [{
                "address": "ee.example", "port": 443,
                "users": [{"id": "UUID-DB", "encryption": "none",
                           "flow": "xtls-rprx-vision"}],
            }]},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "sockopt": {},
                "realitySettings": {
                    "serverName": "ee.example", "publicKey": "PBK-DB",
                    "shortId": short_id, "fingerprint": "firefox"},
            },
        }

    _DB_NODE = {"host": "ee.example", "port": 443, "uuid": "UUID-DB",
                "pubkey": "PBK-DB", "shortid": "SID-DB",
                "sni": "ee.example"}

    def _run(self, ob, db_nodes):
        import chimera.modules.diagnostics as dg
        import chimera.modules.chain_relay as cr
        counters = dg._diag_make_counters()
        _fail = {"ok": False, "ms": 0.0, "exit_ip": "", "speed_mbps": 0.0,
                 "detail": "нода не отвечает (все HTTP-пробы 000): TCP "
                           "может принимать, но REALITY/маршрут не работает",
                 "reason": "нода не отвечает", "legs": {}, "xray_tail": ""}
        out = io.StringIO()
        with redirect_stdout(out), \
             patch.object(cr, "check_node_full_path",
                          lambda nd, **kw: dict(_fail)), \
             patch.object(cr, "_chain_nodes_from_state",
                          lambda: db_nodes):
            dg._diag_check_routing_live({"outbounds": [ob]}, counters)
        return out.getvalue(), counters

    def test_desync_shortid_hint(self):
        """Чужой shortId в outbound (патч балансера, кейс №5) →
        подсказка «креды ≠ state.json — пересоберите конфиг»."""
        ob = self._direct_ob(short_id="SID-OTHER")   # ← чужой shortId
        out, counters = self._run(ob, [self._DB_NODE])
        self.assertIn("REALITY-зонд FAIL", out)
        self.assertIn("≠ state.json", out)
        self.assertIn("пересоберите конфиг Xray", out)
        # reason уже вложен в detail — не дублируется
        self.assertNotIn("нода не отвечает (нода не отвечает", out)
        self.assertEqual(counters, [1, 0, 0, 1])

    def test_no_hint_when_creds_match(self):
        """Креды outbound = БД → честный FAIL БЕЗ подсказки (не шумим)."""
        ob = self._direct_ob()                        # shortId = SID-DB
        out, counters = self._run(ob, [self._DB_NODE])
        self.assertIn("REALITY-зонд FAIL", out)
        self.assertNotIn("state.json", out)
        self.assertEqual(counters, [1, 0, 0, 1])

    def test_no_db_node_for_outbound_hint(self):
        """Outbound не соответствует ни одной ноде БД (stale/патченый
        слот) → подсказка «не соответствует ни одной ноде»."""
        ob = self._direct_ob()
        out, counters = self._run(
            ob, [dict(self._DB_NODE, host="other.example")])
        self.assertIn("не соответствует ни одной ноде", out)
        self.assertIn("без пересборки", out)
        self.assertEqual(counters, [1, 0, 0, 1])

    def test_desync_hint_not_triggered_on_ok(self):
        """Зонд OK → без подсказки даже при рассинхроне (OK не шумим)."""
        import chimera.modules.diagnostics as dg
        import chimera.modules.chain_relay as cr
        counters = dg._diag_make_counters()
        _ok = {"ok": True, "ms": 150.0, "exit_ip": "", "speed_mbps": 0.0,
               "detail": "нода жива", "reason": "нода жива",
               "legs": {}, "xray_tail": ""}
        out = io.StringIO()
        with redirect_stdout(out), \
             patch.object(cr, "check_node_full_path",
                          lambda nd, **kw: dict(_ok)), \
             patch.object(cr, "_chain_nodes_from_state",
                          lambda: [self._DB_NODE]):
            dg._diag_check_routing_live(
                {"outbounds": [self._direct_ob(short_id="SID-OTHER")]},
                counters)
        self.assertIn("REALITY-зонд", out.getvalue())   # OK-ветка сработала
        self.assertNotIn("state.json", out.getvalue())  # подсказки нет на OK
        self.assertEqual(counters, [1, 1, 0, 0])


class TestDiagDropinDangerKeys(unittest.TestCase):
    """_diag_dropin_danger_keys — разбор опасных директив drop-in'а."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _keys(self, content: str) -> set:
        from chimera.modules.diagnostics import _diag_dropin_danger_keys
        return _diag_dropin_danger_keys(content)

    def test_harmless_environment_only(self):
        """Прод-контент chimera-server-frag.conf: только Environment= — безобиден."""
        content = "[Service]\nEnvironment=GODEBUG=multipathtcp=0\n"
        self.assertEqual(self._keys(content), set())

    def test_execstart_override_detected(self):
        content = "[Service]\nExecStart=/usr/local/bin/xray run -config /tmp/other.json\n"
        self.assertEqual(self._keys(content), {"execstart"})

    def test_execstartpost_with_plus_modifier(self):
        """Модификатор '+' стоит в значении — ключ всё равно ExecStartPost."""
        content = "[Service]\nExecStartPost=+/usr/local/bin/chimera-server-frag-restore\n"
        self.assertEqual(self._keys(content), {"execstartpost"})

    def test_comments_and_blank_lines_ignored(self):
        content = "# ExecStart=/bin/false\n; ExecStop=/bin/false\n\n[Service]\nEnvironment=A=b\n"
        self.assertEqual(self._keys(content), set())

    def test_case_insensitive_keys(self):
        content = "[Service]\nEXECSTART=/bin/false\n"
        self.assertEqual(self._keys(content), {"execstart"})

    def test_environmentfile_injection_point(self):
        content = "[Service]\nEnvironmentFile=/etc/xray.env\n"
        self.assertEqual(self._keys(content), {"environmentfile"})

    def test_empty_reset_value_still_counts(self):
        """Пустой 'ExecStart=' сбрасывает штатную команду — тоже опасно."""
        content = "[Service]\nExecStart=\n"
        self.assertEqual(self._keys(content), {"execstart"})

    def test_mixed_returns_only_dangerous(self):
        content = "[Service]\nEnvironment=GODEBUG=x\nRestart=on-failure\nExecStop=/bin/true\n"
        self.assertEqual(self._keys(content), {"execstop"})

    def test_bare_line_without_equals_ignored(self):
        content = "[Service]\nBareLine\nExecReload=/bin/true\n"
        self.assertEqual(self._keys(content), {"execreload"})


class TestDiagCheckXrayServiceDropins(unittest.TestCase):
    """_diag_check_xray_service — ветка drop-in'ов: штатный chimera-server-frag
    не флагуется (FP-регрессия), посторонний безобидный — WARN, с Exec* — ERR."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._dropin_dir = self._tmpdir / "xray.service.d"
        self._dropin_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _mock_core(self):
        core = MagicMock()
        for attr in ("_box_wrap_msg", "_box_top", "_box_row", "_box_warn"):
            setattr(core, attr, MagicMock())
        for attr in ("GREEN", "RED", "YELLOW", "CYAN", "DIM", "BOLD", "NC"):
            setattr(core, attr, "")
        return core

    def _run_check(self, dropin_files: dict) -> list:
        from chimera.modules import diagnostics
        for name, content in dropin_files.items():
            (self._dropin_dir / name).write_text(content)
        counters = diagnostics._diag_make_counters()
        active = MagicMock(stdout="active\n", returncode=0)
        enabled = MagicMock(stdout="enabled\n", returncode=0)
        with patch.object(diagnostics, "_core_module", return_value=self._mock_core()), \
             patch.object(diagnostics, "_diag_run", side_effect=[active, enabled]), \
             patch.object(diagnostics, "_XRAY_SERVICE_DROPIN_DIR", self._dropin_dir), \
             redirect_stdout(io.StringIO()):
            diagnostics._diag_check_xray_service(counters)
        return counters

    def test_known_frag_dropin_is_ok(self):
        """FP-регрессия: штатный chimera-server-frag.conf — ни ERR, ни WARN."""
        counters = self._run_check(
            {"chimera-server-frag.conf": "[Service]\nEnvironment=GODEBUG=multipathtcp=0\n"})
        self.assertEqual(counters, [2, 2, 0, 0])

    def test_unknown_harmless_dropin_warns_not_errors(self):
        counters = self._run_check(
            {"stranger-env.conf": "[Service]\nEnvironment=FOO=bar\n"})
        self.assertEqual(counters, [2, 2, 1, 0])

    def test_unknown_execstart_dropin_errors(self):
        counters = self._run_check(
            {"stranger.conf": "[Service]\nExecStart=/bin/false\n"})
        self.assertEqual(counters, [2, 2, 0, 1])

    def test_mixed_known_harmless_and_dangerous(self):
        counters = self._run_check({
            "chimera-server-frag.conf": "[Service]\nEnvironment=GODEBUG=multipathtcp=0\n",
            "env-tweak.conf": "[Service]\nEnvironment=NO_PROXY=*\n",
            "evil.conf": "[Service]\nExecStartPost=/usr/bin/reporter\n",
        })
        self.assertEqual(counters, [2, 2, 1, 1])

    def test_empty_dropin_dir_no_conflicts(self):
        counters = self._run_check({})
        self.assertEqual(counters, [2, 2, 0, 0])


# ══════════════════════════════════════════════════════════════════════════════
#  8. Волна-4: _tg_send_report_from_menu — конвейер diag_report + фолбэк
#  (паттерн герметичности test_hysteria2_common._H2TmpBase: node_identity и
#  telegram.json на tmp, транспорт (_diag_tg_run) подменён, боевой TG молчит)
# ══════════════════════════════════════════════════════════════════════════════

class TestTgSendReportWave4(unittest.TestCase):
    """_tg_send_report_from_menu (волна-4): основной путь — конвейер
    tg_bot.tg_notify_event с НОВЫМ событием diag_report (шапка/фильтр/
    иконка от конвейера); фолбэк — прежний прямой curl с events-фильтром
    (false → молчит) и шапкой server_header «имя · домен · IP» (фолбэк
    hostname). Суть отчёта (пункты диагностики) не меняется."""

    def setUp(self):
        import subprocess
        from chimera.modules import node_identity as _ni
        import chimera.modules.diagnostics as d_
        self.diag = d_
        self._ni = _ni
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(self._rmtree)
        self.calls: list = []
        self._cp = subprocess.CompletedProcess
        patches = [
            patch.object(d_, "DIAG_TG_CFG_FILE", self.tmp / "telegram.json"),
            # node_identity: прод-файлы НЕ протекают в тесты (герметичность
            # живых нод — паттерн 652e692/71605f2)
            patch.object(_ni, "STATE_FILE", self.tmp / "state.json"),
            patch.object(_ni, "TG_FILE", self.tmp / "telegram.json"),
            patch.object(_ni, "DNS_CACHE_FILE",
                         self.tmp / "node_dns_cache.json"),
            patch.object(_ni, "ALIASES_FILE", self.tmp / "aliases-absent.json"),
            # транспорт фолбэка (curl/hostname) — мок: боевых запросов нет
            patch.object(d_, "_diag_tg_run", side_effect=self._fake_run),
        ]
        _ni._MEM.clear()
        self.addCleanup(_ni._MEM.clear)
        (self.tmp / "node_dns_cache.json").write_text(json.dumps({}))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.report = self.tmp / "xray-diagnostic-test.txt"
        self.report.write_text("Шаг 1: unit tests ✔ PASS\n"
                               "Шаг 2: сервисы ✔ PASS\n", encoding="utf-8")

    def _rmtree(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _fake_run(self, args, timeout=20):
        self.calls.append(list(args))
        if list(args)[:1] == ["hostname"]:
            return self._cp(args, 0, stdout="testhost\n", stderr="")
        return self._cp(args, 0, stdout="200", stderr="")

    def _write_state(self, domain="node-ru1.example.com"):
        (self.tmp / "state.json").write_text(json.dumps({"domain": domain}))
        self._ni._MEM.clear()

    def _cfg(self, events=None, domain=None):
        if domain:
            self._write_state(domain)
        cfg = {"token": "TESTTOKEN", "chat_id": "12345",
               "server_name": "RU1", "server_ip": "203.0.113.10"}
        if events is not None:
            cfg["events"] = events
        return cfg

    def _force_fallback(self):
        """chimera.modules.tg_bot недоступен → curl-фолбэк (два рычага:
        sys.modules-None + атрибут пакета — attr побеждает, если tg_bot
        уже импортировался раньше в этом процессе)."""
        import chimera.modules as pkg
        for m in (patch.dict(sys.modules,
                             {"chimera.modules.tg_bot": None}),
                  patch.object(pkg, "tg_bot", None, create=True)):
            m.start()
            self.addCleanup(m.stop)

    def _curl_cmds(self):
        return [c for c in self.calls if c[:1] == ["curl"]]

    def _tg_text(self) -> str:
        cmds = [c for c in self._curl_cmds() if "sendMessage" in " ".join(c)]
        self.assertEqual(len(cmds), 1, f"ожидался один sendMessage: {cmds}")
        return next(a for a in cmds[0]
                    if str(a).startswith("text="))[len("text="):]

    # ── конвейерный путь (НОВОЕ событие diag_report) ───────────────

    def test_pipeline_sends_diag_report_event(self):
        """Основной путь — tg_bot.tg_notify_event("diag_report", суть):
        шапку/events-фильтр/иконку ставит конвейер; curl не тронут."""
        with patch("chimera.modules.tg_bot.tg_notify_event") as m_notify:
            res = self.diag._tg_send_report_from_menu(self.report,
                                                      self._cfg())
        self.assertTrue(res["ok"])
        self.assertEqual(res["via"], "pipeline")
        m_notify.assert_called_once()
        ev, detail = m_notify.call_args[0]
        self.assertEqual(ev, "diag_report")
        self.assertEqual(ev, self.diag.DIAG_REPORT_EVENT)
        self.assertIn("Диагностический отчёт", detail)
        self.assertIn("unit tests", detail)   # суть (пункты диагностики)
        self.assertEqual(self._curl_cmds(), [])
        self.assertEqual(res["file"], "")       # короткий отчёт — без файла

    def test_pipeline_report_body_html_escaped(self):
        """Тело отчёта экранируется под parse_mode=HTML (визуально идентично,
        суть не меняется) — иначе сырой <tag> ломал бы sendMessage (400)."""
        self.report.write_text("лог: <script>boom</script> & порт", encoding="utf-8")
        with patch("chimera.modules.tg_bot.tg_notify_event") as m_notify:
            self.diag._tg_send_report_from_menu(self.report, self._cfg())
        detail = m_notify.call_args[0][1]
        self.assertIn("&lt;script&gt;", detail)
        self.assertNotIn("<script>", detail)
        self.assertIn("&amp;", detail)

    def test_muted_when_event_disabled(self):
        """events.diag_report == false → молчит в ОБОИХ путях (конвейер
        вызывается нуле раз; меню честно покажет «заглушено»)."""
        with patch("chimera.modules.tg_bot.tg_notify_event") as m_notify:
            res = self.diag._tg_send_report_from_menu(
                self.report, self._cfg(events={"diag_report": False}))
        self.assertTrue(res["muted"])
        self.assertFalse(res["ok"])
        m_notify.assert_not_called()
        self.assertEqual(self._curl_cmds(), [])

    def test_no_config_http_status(self):
        cfg = self._cfg()
        cfg.pop("token")
        res = self.diag._tg_send_report_from_menu(self.report, cfg)
        self.assertFalse(res["ok"])
        self.assertEqual(res["http"], "no-config")

    def test_long_report_sends_full_file(self):
        """Отчёт >3800 символов → конвейер шлёт дайджест, полный файл —
        sendDocument'ом (как раньше; конвейер документы не шлёт)."""
        self.report.write_text("д" * 5000, encoding="utf-8")
        with patch("chimera.modules.tg_bot.tg_notify_event") as m_notify:
            res = self.diag._tg_send_report_from_menu(self.report,
                                                      self._cfg())
        self.assertTrue(res["ok"])
        self.assertEqual(res["file"], "sent")
        self.assertEqual(m_notify.call_args[0][0], "diag_report")
        send_doc = [c for c in self._curl_cmds()
                    if "sendDocument" in " ".join(c)]
        self.assertEqual(len(send_doc), 1)
        self.assertIn(f"document=@{self.report}", send_doc[0])
        self.assertLessEqual(len(m_notify.call_args[0][1]), 3860)

    # ── фолбэк (прежний прямой curl + каноничная шапка) ─────────────

    def test_fallback_header_canonical_server_header(self):
        """Фолбэк собирает канон «имя · домен · IP» + иконку + ts;
        parse_mode=HTML (формат как у конвейера)."""
        cfg = self._cfg(domain="node-ru1.example.com")
        self._force_fallback()
        res = self.diag._tg_send_report_from_menu(self.report, cfg)
        self.assertTrue(res["ok"])
        self.assertEqual(res["via"], "curl")
        self.assertEqual(res["http"], "200")
        text = self._tg_text()
        self.assertIn(
            "🩺 <b>[RU1 · node-ru1.example.com · 203.0.113.10]</b> "
            "Диагностический отчёт", text)
        self.assertIn("unit tests", text)
        self.assertIn("<i>", text)   # ts — как у конвейера
        self.assertIn("parse_mode=HTML", " ".join(self._curl_cmds()[0]))

    def test_fallback_header_hostname_when_node_identity_unavailable(self):
        """node_identity недоступен → фолбэк hostname, не бросает."""
        cfg = self._cfg(domain="node-ru1.example.com")
        self._force_fallback()
        with patch.dict(sys.modules,
                        {"chimera.modules.node_identity": None}):
            res = self.diag._tg_send_report_from_menu(self.report, cfg)
        self.assertTrue(res["ok"])
        self.assertIn("<b>[testhost]</b>", self._tg_text())

    def test_fallback_http_error_reported(self):
        """HTTP != 200 → честный статус для меню (ok=False, http=код)."""
        import subprocess
        cfg = self._cfg()
        self._force_fallback()
        with patch.object(self.diag, "_diag_tg_run",
                          return_value=subprocess.CompletedProcess(
                              [], 1, stdout="404", stderr="")):
            res = self.diag._tg_send_report_from_menu(self.report, cfg)
        self.assertFalse(res["ok"])
        self.assertEqual(res["http"], "404")

    # ── events-фильтр (чистый хелпер) и проводка меню ───────────────

    def test_event_enabled_matrix(self):
        """_diag_tg_event_enabled: нет файла/ключа → ВКЛ; false → выкл;
        битый json → ВКЛ (паттерн bandwidth_monitor._tg_event_enabled)."""
        f = self.tmp / "telegram.json"
        # нет файла → ВКЛ
        self.assertTrue(self.diag._diag_tg_event_enabled("diag_report"))
        f.write_text(json.dumps({}))
        self.assertTrue(self.diag._diag_tg_event_enabled("diag_report"))
        f.write_text(json.dumps({"events": {"diag_report": False}}))
        self.assertFalse(self.diag._diag_tg_event_enabled("diag_report"))
        self.assertTrue(self.diag._diag_tg_event_enabled("cert_expire"))
        f.write_text("{это не json")
        self.assertTrue(self.diag._diag_tg_event_enabled("diag_report"))
        # явный конфиг в аргументе важнее файла
        self.assertFalse(self.diag._diag_tg_event_enabled(
            "diag_report", {"events": {"diag_report": False}}))
        self.assertTrue(self.diag._diag_tg_event_enabled(""))

    def test_menu_block_wired_to_helper(self):
        """do_full_diagnostic шлёт отчёт только через хелпер (старый
        сырой curl-bot{token}/sendMessage из меню исчез)."""
        import inspect
        src = inspect.getsource(self.diag.do_full_diagnostic)
        self.assertIn("_tg_send_report_from_menu", src)
        self.assertNotIn("api.telegram.org", src)

    def test_menu_tg_config_file_survives_core_migration(self):
        """getattr(core, TG_CONFIG_FILE) исчез из _core при миграции —
        привязка падает на модульную копию DIAG_TG_CFG_FILE (фикс сироты
        миграции: пункт «Отправить в Telegram» навсегда показывал
        «не настроен»)."""
        import inspect
        src = inspect.getsource(self.diag.do_full_diagnostic)
        self.assertIn('getattr(core, "TG_CONFIG_FILE", None)', src)
        self.assertIn("DIAG_TG_CFG_FILE", src)

    def test_diag_report_key_and_icon_documented(self):
        """НОВЫЙ ключ волны-4: diag_report / иконка 🩺 (предложение для
        регистрации в tg_bot: icons + ev_keys/ev_labels меню [5]→[3])."""
        self.assertEqual(self.diag.DIAG_REPORT_EVENT, "diag_report")
        self.assertEqual(self.diag.DIAG_REPORT_ICON, "🩺")


if __name__ == "__main__":
    unittest.main(verbosity=2)
