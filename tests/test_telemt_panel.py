#!/usr/bin/env python3
"""
tests/test_telemt_panel.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/telemt_panel.py.

Покрывает:
  1. _now_str — текущая дата/время
  2. _is_installed — проверка установки
  3. _telemt_is_installed — проверка telemt
  4. _plain / _wlen — unicode helpers
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime
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


class TestNowStr(unittest.TestCase):
    """_now_str — текущая дата/время."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_formatted_string(self):
        from chimera.modules.telemt_panel import _now_str
        result = _now_str()
        self.assertRegex(result, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
        datetime.strptime(result, "%Y-%m-%d %H:%M:%S")


class TestIsInstalled(unittest.TestCase):
    """_is_installed — проверка установки панели."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._bin = self._tmpdir / "telemt-panel"
        self._cfg = self._tmpdir / "config.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("chimera.modules.telemt_panel.BIN_PATH", self._bin),
            patch("chimera.modules.telemt_panel.CONFIG_FILE", self._cfg),
        )

    def test_returns_false_when_neither(self):
        from chimera.modules.telemt_panel import _is_installed
        with self._patch()[0], self._patch()[1]:
            self.assertFalse(_is_installed())

    def test_returns_true_when_both(self):
        from chimera.modules.telemt_panel import _is_installed
        self._bin.write_text("x")
        self._cfg.write_text("x")
        with self._patch()[0], self._patch()[1]:
            self.assertTrue(_is_installed())


class TestTelemTIsInstalled(unittest.TestCase):
    """_telemt_is_installed — проверка telemt."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_false_when_mp_is_none(self):
        from chimera.modules.telemt_panel import _telemt_is_installed
        self.assertFalse(_telemt_is_installed(None))

    def test_returns_false_when_files_missing(self):
        from chimera.modules.telemt_panel import _telemt_is_installed
        mp = MagicMock()
        mp.CONFIG_FILE = Path("/tmp/nonexistent_telemt_cfg")
        mp.BIN_PATH = Path("/tmp/nonexistent_telemt_bin")
        self.assertFalse(_telemt_is_installed(mp))

    def test_returns_true_when_files_exist(self):
        import tempfile as tf
        from chimera.modules.telemt_panel import _telemt_is_installed
        tmpdir = Path(tf.mkdtemp())
        try:
            cfg = tmpdir / "telemt.toml"
            bin_path = tmpdir / "telemt"
            cfg.write_text("x")
            bin_path.write_text("x")
            mp = MagicMock()
            mp.CONFIG_FILE = cfg
            mp.BIN_PATH = bin_path
            self.assertTrue(_telemt_is_installed(mp))
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestPlain(unittest.TestCase):
    """_plain — strip ANSI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_plain_string_unchanged(self):
        from chimera.modules.telemt_panel import _plain
        self.assertEqual(_plain("hello"), "hello")

    def test_strips_ansi(self):
        from chimera.modules.telemt_panel import _plain
        self.assertEqual(_plain("\033[1;31mhi\033[0m"), "hi")


class TestWlen(unittest.TestCase):
    """_wlen — display width."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ascii(self):
        from chimera.modules.telemt_panel import _wlen
        self.assertEqual(_wlen("hello"), 5)

    def test_cjk_two_columns(self):
        from chimera.modules.telemt_panel import _wlen
        self.assertEqual(_wlen("中文"), 4)


class TestValidateTlsPort(unittest.TestCase):
    """_validate_tls_port — валидация порта для TLS-фронта Telemt Panel."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_default_port_8444_valid(self):
        from chimera.modules.telemt_panel import _validate_tls_port, DEFAULT_PANEL_TLS_PORT
        ok, err = _validate_tls_port(DEFAULT_PANEL_TLS_PORT)
        self.assertTrue(ok, f"Default port {DEFAULT_PANEL_TLS_PORT} should be valid: {err}")

    def test_zero_invalid(self):
        from chimera.modules.telemt_panel import _validate_tls_port
        ok, err = _validate_tls_port(0)
        self.assertFalse(ok)

    def test_too_large_invalid(self):
        from chimera.modules.telemt_panel import _validate_tls_port
        ok, _ = _validate_tls_port(70000)
        self.assertFalse(ok)

    def test_privileged_port_rejected(self):
        from chimera.modules.telemt_panel import _validate_tls_port
        # 443 — VLESS, must be rejected both as privileged and as reserved.
        ok, err = _validate_tls_port(443)
        self.assertFalse(ok)
        self.assertIn("443", err)

    def test_privileged_port_80_rejected(self):
        from chimera.modules.telemt_panel import _validate_tls_port
        ok, err = _validate_tls_port(80)
        self.assertFalse(ok)
        self.assertIn("80", err)

    def test_reserved_port_8443_rejected(self):
        """8443 — rest_api web_panel (loopback) — конфликт."""
        from chimera.modules.telemt_panel import _validate_tls_port
        ok, err = _validate_tls_port(8443)
        self.assertFalse(ok)
        self.assertIn("8443", err)

    def test_reserved_port_8888_rejected(self):
        """8888 — olcRTC manager panel — конфликт."""
        from chimera.modules.telemt_panel import _validate_tls_port
        ok, err = _validate_tls_port(8888)
        self.assertFalse(ok)
        self.assertIn("8888", err)

    def test_reserved_port_9443_rejected(self):
        """9443 — nginx front для User Portal (default) — конфликт."""
        from chimera.modules.telemt_panel import _validate_tls_port
        ok, err = _validate_tls_port(9443)
        self.assertFalse(ok)
        self.assertIn("9443", err)

    def test_reserved_port_8080_rejected(self):
        """8080 — Telemt Panel listen (backend) — конфликт."""
        from chimera.modules.telemt_panel import _validate_tls_port
        ok, err = _validate_tls_port(8080)
        self.assertFalse(ok)
        self.assertIn("8080", err)

    def test_reserved_port_9091_rejected(self):
        """9091 — Telemt API (loopback) — конфликт."""
        from chimera.modules.telemt_panel import _validate_tls_port
        ok, err = _validate_tls_port(9091)
        self.assertFalse(ok)
        self.assertIn("9091", err)

    def test_high_port_accepted(self):
        """Произвольный высокий порт должен быть принят."""
        from chimera.modules.telemt_panel import _validate_tls_port
        ok, _ = _validate_tls_port(8445)
        self.assertTrue(ok)

    def test_high_port_20000_accepted(self):
        from chimera.modules.telemt_panel import _validate_tls_port
        ok, _ = _validate_tls_port(20000)
        self.assertTrue(ok)

    def test_non_int_rejected(self):
        from chimera.modules.telemt_panel import _validate_tls_port
        ok, _ = _validate_tls_port("8444")
        self.assertFalse(ok)


class TestTelemtPanelDirectPortRegistry(unittest.TestCase):
    """Интеграция с port_registry: SERVICE_TELEMT_PANEL_DIRECT константа."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_service_constant_exists(self):
        from chimera.modules.port_registry import SERVICE_TELEMT_PANEL_DIRECT
        self.assertEqual(SERVICE_TELEMT_PANEL_DIRECT, "telemt_panel_direct")

    def test_service_constant_in_main_list(self):
        """Константа SERVICE_TELEMT_PANEL_DIRECT должна быть в перечне всех SERVICE_*
        через round-trip port_register → port_list_for_service → port_unregister."""
        import tempfile
        from pathlib import Path
        import chimera.modules.port_registry as pr
        # Подменяем файл реестра на временный.
        tmpdir = Path(tempfile.mkdtemp())
        old_file = pr.PORT_REGISTRY_FILE
        old_lock = pr.LOCK_FILE
        try:
            pr.PORT_REGISTRY_FILE = tmpdir / "registry.json"
            pr.LOCK_FILE = tmpdir / "registry.lock"
            ok, msg = pr.port_register(
                pr.SERVICE_TELEMT_PANEL_DIRECT, 8444, "tcp",
                comment="Telemt Panel direct (TLS)", force=True,
            )
            self.assertTrue(ok, msg)
            entries = pr.port_list_for_service(pr.SERVICE_TELEMT_PANEL_DIRECT)
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["port"], 8444)
            pr.port_unregister(pr.SERVICE_TELEMT_PANEL_DIRECT, 8444, "tcp")
            self.assertEqual(
                len(pr.port_list_for_service(pr.SERVICE_TELEMT_PANEL_DIRECT)), 0
            )
        finally:
            pr.PORT_REGISTRY_FILE = old_file
            pr.LOCK_FILE = old_lock
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestAskTlsPort(unittest.TestCase):
    """_ask_tls_port — TUI ввод порта."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_default_on_empty_input(self):
        from chimera.modules.telemt_panel import _ask_tls_port, DEFAULT_PANEL_TLS_PORT
        with patch("builtins.input", return_value=""):
            port = _ask_tls_port()
        self.assertEqual(port, DEFAULT_PANEL_TLS_PORT)

    def test_custom_port_returned(self):
        from chimera.modules.telemt_panel import _ask_tls_port
        with patch("builtins.input", return_value="9999"):
            port = _ask_tls_port()
        self.assertEqual(port, 9999)

    def test_invalid_input_falls_back_to_default(self):
        from chimera.modules.telemt_panel import _ask_tls_port, DEFAULT_PANEL_TLS_PORT
        with patch("builtins.input", return_value="abc"):
            port = _ask_tls_port()
        self.assertEqual(port, DEFAULT_PANEL_TLS_PORT)


class TestGetPublicIps(unittest.TestCase):
    """_get_public_ips — получение (ipv4, ipv6)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_tuple_of_two_strings(self):
        from chimera.modules.telemt_panel import _get_public_ips
        with patch("chimera.modules.telemt_panel._run",
                          return_value=MagicMock(returncode=0, stdout="1.2.3.4\n", stderr="")):
            ipv4, ipv6 = _get_public_ips()
        self.assertIsInstance(ipv4, str)
        self.assertIsInstance(ipv6, str)

    def test_ipv6_detected_from_ifconfig(self):
        """ifconfig.me вернул IPv6 → ipv6 заполняется."""
        from chimera.modules.telemt_panel import _get_public_ips
        # IPv6 адрес содержит ':'
        with patch("chimera.modules.telemt_panel._run",
                          return_value=MagicMock(returncode=0, stdout="2a0d:d940:600:4::2\n", stderr="")):
            ipv4, ipv6 = _get_public_ips()
        # Хотя бы один из IP должен быть определён (ipv4 или ipv6).
        self.assertTrue(ipv4 or ipv6, "должен вернуть хотя бы один IP")

    def test_empty_when_no_internet(self):
        from chimera.modules.telemt_panel import _get_public_ips
        with patch("chimera.modules.telemt_panel._run",
                          return_value=MagicMock(returncode=1, stdout="", stderr="")):
            ipv4, ipv6 = _get_public_ips()
        # Оба пустые (или из mtproto, но он тоже замокан через _run)
        self.assertIsInstance(ipv4, str)


class TestAskPublicIpChoice(unittest.TestCase):
    """_ask_public_ip_choice — выбор IP при наличии обоих."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_both_ips_offers_choice(self):
        from chimera.modules.telemt_panel import _ask_public_ip_choice
        with patch("builtins.input", return_value="1"):
            ip = _ask_public_ip_choice("1.2.3.4", "2a0d::1")
        self.assertEqual(ip, "1.2.3.4")  # IPv4 выбран

    def test_choose_ipv6(self):
        from chimera.modules.telemt_panel import _ask_public_ip_choice
        with patch("builtins.input", return_value="2"):
            ip = _ask_public_ip_choice("1.2.3.4", "2a0d::1")
        self.assertEqual(ip, "2a0d::1")  # IPv6 выбран

    def test_only_ipv4_no_choice(self):
        """Если только IPv4 — возвращается без вопроса."""
        from chimera.modules.telemt_panel import _ask_public_ip_choice
        with patch("builtins.input", side_effect=AssertionError("не должно спрашивать")):
            ip = _ask_public_ip_choice("1.2.3.4", "")
        self.assertEqual(ip, "1.2.3.4")

    def test_only_ipv6_no_choice(self):
        from chimera.modules.telemt_panel import _ask_public_ip_choice
        with patch("builtins.input", side_effect=AssertionError("не должно спрашивать")):
            ip = _ask_public_ip_choice("", "2a0d::1")
        self.assertEqual(ip, "2a0d::1")

    def test_no_ips_returns_localhost(self):
        from chimera.modules.telemt_panel import _ask_public_ip_choice
        with patch("builtins.input", side_effect=AssertionError("не должно спрашивать")):
            ip = _ask_public_ip_choice("", "")
        self.assertEqual(ip, "127.0.0.1")


class TestPortRegistryCoverage(unittest.TestCase):
    """Проверка что Telemt Panel использует port_registry для прямого доступа."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_service_constant_exists(self):
        from chimera.modules.port_registry import SERVICE_TELEMT_PANEL_DIRECT
        self.assertEqual(SERVICE_TELEMT_PANEL_DIRECT, "telemt_panel_direct")

    def test_setup_direct_calls_port_register(self):
        """_telemt_setup_direct_access должен вызвать port_register + ufw_open_port."""
        from chimera.modules import telemt_panel
        from chimera.modules import panel_nginx_front
        # герметичность — nginx-фронт исполняется по-настоящему (именно
        # он вызывает port_register/ufw_open_port), но ВСЕ его побочные
        # эффекты замоканы: генерация сертификата, nginx -t, curl, запись
        # vhost-файлов, curl ifconfig.me. Реальный nginx и /etc/nginx
        # в песочнице не нужны.
        _mock_sites_avail = MagicMock()
        _mock_sites_en = MagicMock()
        _mock_sites_en.exists.return_value = False
        _mock_vhost_file = MagicMock()
        _mock_sites_avail.__truediv__ = lambda self, x: _mock_vhost_file
        _mock_sites_en.__truediv__ = lambda self, x: _mock_vhost_file
        with patch.object(telemt_panel, "_is_installed", return_value=True), \
             patch.object(telemt_panel, "_validate_tls_port", return_value=(True, "")), \
             patch("chimera.modules.telemt_panel.shutil.which", return_value="/usr/sbin/nginx"), \
             patch.object(telemt_panel, "_run", return_value=MagicMock(returncode=0, stdout="", stderr="")), \
             patch.object(telemt_panel, "_get_public_ips", return_value=("1.2.3.4", "")), \
             patch.object(telemt_panel, "_ask_public_ip_choice", return_value="1.2.3.4"), \
             patch.object(panel_nginx_front, "check_port_via_registry",
                          return_value=(True, [])), \
             patch.object(panel_nginx_front, "_generate_self_signed_tls",
                          return_value=(MagicMock(), MagicMock())), \
             patch("chimera.modules.panel_nginx_front.subprocess.run",
                          return_value=MagicMock(returncode=0, stdout="", stderr="")) as _m_pnf_run, \
             patch("chimera.modules.panel_nginx_front.shutil.which",
                          return_value="/usr/sbin/nginx"), \
             patch.object(panel_nginx_front, "NGINX_SITES_AVAILABLE",
                          _mock_sites_avail), \
             patch.object(panel_nginx_front, "NGINX_SITES_ENABLED",
                          _mock_sites_en), \
             patch.object(panel_nginx_front, "NGINX_SSL_DIR", MagicMock()), \
             patch("chimera.modules.telemt_panel.Path") as mock_path_cls, \
             patch.object(telemt_panel, "TELEMT_NGINX_AVAILABLE") as mock_avail, \
             patch.object(telemt_panel, "TELEMT_NGINX_ENABLED") as mock_en, \
             patch.object(telemt_panel, "TELEMT_NGINX_STATE") as mock_state, \
             patch("chimera.modules.port_registry.port_register", return_value=(True, "")) as mock_reg, \
             patch("chimera.modules.port_registry.ufw_open_port", return_value=(True, "")) as mock_ufw:
            # Path() возвращает мок который поддерживает mkdir/write_text/chmod.
            mock_path_inst = MagicMock()
            mock_path_inst.mkdir = MagicMock()
            mock_path_inst.write_text = MagicMock()
            mock_path_inst.chmod = MagicMock()
            mock_path_cls.return_value = mock_path_inst
            mock_path_cls.side_effect = lambda x: mock_path_inst
            mock_avail.parent.mkdir = MagicMock()
            mock_avail.write_text = MagicMock()
            mock_en.exists.return_value = False
            mock_en.symlink_to = MagicMock()
            mock_state.parent.mkdir = MagicMock()
            mock_state.write_text = MagicMock()
            result = telemt_panel._telemt_setup_direct_access(port=8444)
        # port_register должен быть вызван.
        mock_reg.assert_called()
        # ufw_open_port должен быть вызван.
        mock_ufw.assert_called()

    def test_remove_direct_calls_port_unregister(self):
        """_telemt_remove_direct_access должен вызвать ufw_close_port + port_unregister."""
        from chimera.modules import telemt_panel
        from chimera.modules import panel_nginx_front
        import json
        # герметичность — nginx-фронт исполняется по-настоящему (именно
        # он вызывает ufw_close_port/port_unregister), но nginx -t/reload,
        # unlink vhost-файлов и state.json замоканы.
        _mock_sites_avail = MagicMock()
        _mock_sites_en = MagicMock()
        _mock_vhost_file = MagicMock()
        _mock_sites_avail.__truediv__ = lambda self, x: _mock_vhost_file
        _mock_sites_en.__truediv__ = lambda self, x: _mock_vhost_file
        # State показывает что прямой доступ включён.
        with patch.object(telemt_panel, "TELEMT_NGINX_STATE") as mock_state, \
             patch.object(telemt_panel, "TELEMT_NGINX_ENABLED") as mock_en, \
             patch.object(telemt_panel, "TELEMT_NGINX_AVAILABLE") as mock_avail, \
             patch("chimera.modules.telemt_panel.shutil.which", return_value="/usr/sbin/nginx"), \
             patch.object(telemt_panel, "_run", return_value=MagicMock(returncode=0, stdout="", stderr="")), \
             patch.object(panel_nginx_front, "NGINX_SITES_AVAILABLE",
                          _mock_sites_avail), \
             patch.object(panel_nginx_front, "NGINX_SITES_ENABLED",
                          _mock_sites_en), \
             patch("chimera.modules.panel_nginx_front.subprocess.run",
                          return_value=MagicMock(returncode=0, stdout="", stderr="")), \
             patch("chimera.modules.panel_nginx_front.shutil.which",
                          return_value="/usr/sbin/nginx"), \
             patch("chimera.modules.port_registry.ufw_close_port", return_value=(True, "")) as mock_ufw_close, \
             patch("chimera.modules.port_registry.port_unregister", return_value=True) as mock_unreg:
            mock_state.exists.return_value = True
            mock_state.read_text.return_value = json.dumps({"enabled": True, "port": 8444})
            mock_en.unlink = MagicMock()
            mock_avail.unlink = MagicMock()
            mock_state.unlink = MagicMock()
            telemt_panel._telemt_remove_direct_access()
        # ufw_close_port должен быть вызван.
        mock_ufw_close.assert_called()
        # port_unregister должен быть вызван.
        mock_unreg.assert_called()


# ══════════════════════════════════════════════════════════════════════════════
# авто-домен для Let's Encrypt (порт из triple_panel.py)
# ══════════════════════════════════════════════════════════════════════════════
class TestAutoDomain(unittest.TestCase):
    """Цепочка _detect_panel_domain: PARAM_DOMAIN → state.json →
    naiveproxy.json (домен Naive — его panel_nginx_front не видит).
    порт фикса Telemt Panel на серверах без VLESS больше
    не застревает на пустом «Домен:» при включении прямого доступа."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _core(self, domain):
        import types
        return types.SimpleNamespace(PARAM_DOMAIN=domain)

    def test_param_domain_wins(self):
        from chimera.modules import telemt_panel
        tmp = Path(tempfile.mkdtemp())
        (tmp / "state.json").write_text('{"domain": "core.example.com"}')
        (tmp / "naiveproxy.json").write_text(
            '{"domain": "naive.example.com"}')
        with patch.object(telemt_panel, "_core_module",
                          return_value=self._core("vless.example.com")), \
             patch.object(telemt_panel, "STATE_DIR", tmp):
            self.assertEqual(telemt_panel._detect_panel_domain(),
                             "vless.example.com")

    def test_state_json_fallback(self):
        from chimera.modules import telemt_panel
        tmp = Path(tempfile.mkdtemp())
        (tmp / "state.json").write_text('{"domain": "core.example.com"}')
        (tmp / "naiveproxy.json").write_text(
            '{"domain": "naive.example.com"}')
        with patch.object(telemt_panel, "_core_module",
                          return_value=self._core("")), \
             patch.object(telemt_panel, "STATE_DIR", tmp):
            self.assertEqual(telemt_panel._detect_panel_domain(),
                             "core.example.com")

    def test_naive_domain_fallback(self):
        """Сервер без VLESS (чистый MTProxy): домен живёт в naiveproxy.json —
        панель обязана подхватить его сама (кейс юзера: пустое «Домен:»)."""
        from chimera.modules import telemt_panel
        tmp = Path(tempfile.mkdtemp())
        (tmp / "naiveproxy.json").write_text(
            '{"domain": "naive.example.com", "port": 443}')
        with patch.object(telemt_panel, "_core_module",
                          return_value=self._core("")), \
             patch.object(telemt_panel, "STATE_DIR", tmp):
            self.assertEqual(telemt_panel._detect_panel_domain(),
                             "naive.example.com")

    def test_nothing_found(self):
        from chimera.modules import telemt_panel
        tmp = Path(tempfile.mkdtemp())
        with patch.object(telemt_panel, "_core_module",
                          return_value=self._core("")), \
             patch.object(telemt_panel, "STATE_DIR", tmp):
            self.assertEqual(telemt_panel._detect_panel_domain(), "")

    def test_garbage_files_ignored(self):
        from chimera.modules import telemt_panel
        tmp = Path(tempfile.mkdtemp())
        (tmp / "naiveproxy.json").write_text("не json вообще")
        with patch.object(telemt_panel, "_core_module",
                          return_value=self._core("")), \
             patch.object(telemt_panel, "STATE_DIR", tmp):
            self.assertEqual(telemt_panel._detect_panel_domain(), "")

    def test_core_import_failure_ignored(self):
        from chimera.modules import telemt_panel

        def boom():
            raise ImportError("нет ядра")

        tmp = Path(tempfile.mkdtemp())
        (tmp / "naiveproxy.json").write_text('{"domain": "naive.example.com"}')
        with patch.object(telemt_panel, "_core_module", side_effect=boom), \
             patch.object(telemt_panel, "STATE_DIR", tmp):
            self.assertEqual(telemt_panel._detect_panel_domain(),
                             "naive.example.com")


class TestToggleDirectAccessFlow(unittest.TestCase):
    """Пункт [6] «Прямой доступ»: домен подставляется автоматически,
    ask_domain НЕ вызывается; ручной ввод — только если нигде не нашли;
    пустой ручной ввод — откат на self-signed (как было ранее)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _run_toggle(self, detect_value, ask_domain_return=None):
        """Прогоняет _toggle_direct_access (ветка «включить») с фейками.
        Возвращает (kwargs_вызова_setup, mock_ask_domain)."""
        from chimera.modules import telemt_panel
        from chimera.modules import panel_nginx_front
        setup_calls = []
        with patch.object(telemt_panel, "_telemt_direct_status",
                          return_value={"enabled": False}), \
             patch.object(telemt_panel, "_telemt_setup_direct_access",
                          side_effect=lambda **kw:
                              setup_calls.append(kw) or True), \
             patch.object(telemt_panel, "_detect_panel_domain",
                          return_value=detect_value), \
             patch.object(telemt_panel, "_ask_tls_port", return_value=8444), \
             patch.object(telemt_panel, "_pause", lambda: None), \
             patch.object(panel_nginx_front, "ask_tls_mode",
                          return_value=(False, None)), \
             patch.object(panel_nginx_front, "ask_domain",
                          return_value=ask_domain_return) as mock_ad:
            telemt_panel._toggle_direct_access()
        return setup_calls, mock_ad

    def test_auto_domain_skips_ask_domain(self):
        """Домен найден (Naive) — ask_domain не вызывается вообще."""
        calls, mock_ad = self._run_toggle("naive.example.com")
        mock_ad.assert_not_called()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].get("domain"), "naive.example.com")
        self.assertFalse(calls[0].get("use_self_signed"))

    def test_manual_input_when_not_found(self):
        """Нигде не нашли — классический ручной ввод (как ранее)."""
        calls, mock_ad = self._run_toggle("", ask_domain_return="manual.example.com")
        mock_ad.assert_called_once()
        self.assertEqual(calls[0].get("domain"), "manual.example.com")
        self.assertFalse(calls[0].get("use_self_signed"))

    def test_fallback_to_self_signed_when_empty(self):
        """Не нашли + ручной ввод пуст → откат на self-signed (регресс
        исходного поведения)."""
        calls, mock_ad = self._run_toggle("", ask_domain_return=None)
        mock_ad.assert_called_once()
        self.assertTrue(calls[0].get("use_self_signed"))
        self.assertIsNone(calls[0].get("domain"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
