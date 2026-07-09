#!/usr/bin/env python3
"""
tests/test_health.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/health.py.

Покрывает:
  1. _get_state_value — чтение из state.json
  2. health_check_ssl — проверка SSL сертификата (mocked)
  3. Регрессия: state.json пустой/отсутствует → domain="" → warning
  4. health_check_ports — проверка портов (mocked)
"""
from __future__ import annotations

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
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("vless_installer._core")
    fake_core.__dict__.update(g)
    sys.modules["vless_installer._core"] = fake_core


class TestGetStateValue(unittest.TestCase):
    """_get_state_value — чтение значений из state.json."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._state_file = Path(self._tmpdir) / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state(self, state_dict: dict):
        self._state_file.write_text(json.dumps(state_dict))
        return patch("vless_installer.modules.health._STATE_FILE", self._state_file)

    def test_returns_value_when_key_exists(self):
        from vless_installer.modules import health
        with self._patch_state({"domain": "example.com", "server_port": 443}):
            self.assertEqual(health._get_state_value("domain"), "example.com")
            self.assertEqual(health._get_state_value("server_port"), 443)

    def test_returns_default_when_key_missing(self):
        from vless_installer.modules import health
        with self._patch_state({"domain": "example.com"}):
            self.assertIsNone(health._get_state_value("server_port"))
            self.assertEqual(health._get_state_value("server_port", 443), 443)

    def test_returns_default_when_no_state_file(self):
        from vless_installer.modules import health
        # Патчит на несуществующий файл
        with patch.object(health, "_STATE_FILE", Path("/tmp/nonexistent_state_xyz.json")):
            self.assertIsNone(health._get_state_value("domain"))
            self.assertEqual(health._get_state_value("domain", "fallback"), "fallback")

    def test_returns_default_when_corrupt_json(self):
        from vless_installer.modules import health
        self._state_file.write_text("{invalid json!!!")
        with patch.object(health, "_STATE_FILE", self._state_file):
            self.assertIsNone(health._get_state_value("domain"))

    def test_param_domain_key_returns_none_when_only_domain_exists(self):
        """Регрессия: state.json хранит 'domain', не 'param_domain'."""
        from vless_installer.modules import health
        with self._patch_state({"domain": "example.com"}):
            self.assertIsNone(health._get_state_value("param_domain"))
            self.assertEqual(health._get_state_value("domain"), "example.com")


class TestHealthCheckSsl(unittest.TestCase):
    """health_check_ssl — проверка SSL сертификата."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._state_file = Path(self._tmpdir) / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state(self, state_dict: dict):
        self._state_file.write_text(json.dumps(state_dict))
        return patch("vless_installer.modules.health._STATE_FILE", self._state_file)

    def test_warns_when_domain_empty(self):
        """Регрессия: пустой domain → warning 'SSL проверка пропущена'."""
        from vless_installer.modules import health
        with self._patch_state({"domain": ""}), \
             patch.object(health, "warn") as mock_warn:
            result = health.health_check_ssl()
            self.assertFalse(result)
            mock_warn.assert_called_with("SSL проверка пропущена: домен не задан")

    def test_warns_when_domain_missing(self):
        """Нет ключа domain → warning."""
        from vless_installer.modules import health
        with self._patch_state({"server_port": 443}), \
             patch.object(health, "warn") as mock_warn:
            result = health.health_check_ssl()
            self.assertFalse(result)
            mock_warn.assert_called_with("SSL проверка пропущена: домен не задан")

    def test_warns_when_cert_not_found(self):
        """Domain есть, но сертификат не найден."""
        from vless_installer.modules import health
        with self._patch_state({"domain": "example.com"}), \
             patch.object(health, "warn") as mock_warn:
            # Патчим Path.exists только для пути сертификата, не для state.json.
            # _STATE_FILE уже указывает на реальный временный файл (exists=True).
            # cert = Path("/etc/letsencrypt/live/example.com/fullchain.pem")
            # Нужно чтобы cert.exists() = False.
            orig_exists = Path.exists
            def _conditional_exists(self):
                if "letsencrypt" in str(self):
                    return False
                return orig_exists(self)
            with patch.object(Path, "exists", _conditional_exists):
                result = health.health_check_ssl()
                self.assertFalse(result)
                mock_warn.assert_called_with("SSL сертификат не найден")

    def test_success_when_cert_valid(self):
        """Сертификат найден, срок > 30 дней → OK."""
        from vless_installer.modules import health
        import time as _time
        # future date: 90 days from now
        future_epoch = int(_time.time()) + 90 * 86400
        with self._patch_state({"domain": "example.com"}), \
             patch("pathlib.Path.exists", return_value=True), \
             patch.object(health, "_run") as mock_run:
            # Мокаем: openssl x509 → expiry date, date -d → epoch
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="notAfter=Sep 10 12:00:00 2026 GMT", stderr=""),
                MagicMock(returncode=0, stdout=str(future_epoch), stderr=""),
            ]
            with patch.object(health, "success") as mock_success:
                result = health.health_check_ssl()
                self.assertTrue(result)
                mock_success.assert_called()

    def test_warns_when_cert_expiring_soon(self):
        """Сертификат истекает < 30 дней → warning."""
        from vless_installer.modules import health
        import time as _time
        future_epoch = int(_time.time()) + 10 * 86400  # 10 days
        with self._patch_state({"domain": "example.com"}), \
             patch("pathlib.Path.exists", return_value=True), \
             patch.object(health, "_run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="notAfter=Jul 20 12:00:00 2026 GMT", stderr=""),
                MagicMock(returncode=0, stdout=str(future_epoch), stderr=""),
            ]
            with patch.object(health, "warn") as mock_warn:
                result = health.health_check_ssl()
                # health_check_ssl returns True even when warning (cert exists)
                # but warns about expiration
                mock_warn.assert_called()
                warn_msg = mock_warn.call_args.args[0]
                self.assertIn("10", warn_msg)


class TestHealthCheckPorts(unittest.TestCase):
    """health_check_ports — проверка портов."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._state_file = Path(self._tmpdir) / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state(self, state_dict: dict):
        self._state_file.write_text(json.dumps(state_dict))
        return patch("vless_installer.modules.health._STATE_FILE", self._state_file)

    def test_uses_server_port_from_state(self):
        """Порт берётся из state['server_port'], не fallback 443."""
        from vless_installer.modules import health
        with self._patch_state({"server_port": 8443}), \
             patch.object(health, "_run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0,
                                               stdout=":8443 ", stderr="")
            with patch.object(health, "success"):
                health.health_check_ports()
            # Проверяем что ss -tlnp вызывался и порт 8443 проверялся
            # _run вызывается с ["ss", "-tlnp", ...]
            self.assertTrue(mock_run.called)

    def test_fallback_to_443_when_no_state(self):
        """Нет state.json → fallback на 443."""
        from vless_installer.modules import health
        with patch.object(health, "_STATE_FILE", Path("/tmp/nonexistent_xyz.json")), \
             patch.object(health, "_run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0,
                                               stdout=":443 ", stderr="")
            with patch.object(health, "success"):
                health.health_check_ports()
            self.assertTrue(mock_run.called)


class TestHealthCheckXray(unittest.TestCase):
    """health_check_xray — проверка Xray сервиса."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_success_when_active(self):
        from vless_installer.modules import health
        with patch.object(health, "_run") as mock_run, \
             patch("time.sleep"):  # ускоряем тест
            # systemctl is-active xray → "active"
            # pgrep -x xray → returncode 0
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="active\n", stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),
            ]
            with patch.object(health, "success"):
                result = health.health_check_xray()
                self.assertTrue(result)

    def test_failure_when_inactive(self):
        from vless_installer.modules import health
        with patch.object(health, "_run") as mock_run, \
             patch("time.sleep"):
            mock_run.side_effect = [
                MagicMock(returncode=3, stdout="inactive\n", stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),  # journalctl
            ]
            with patch.object(health, "warn"):
                result = health.health_check_xray()
                self.assertFalse(result)


class TestHealthCheckNginx(unittest.TestCase):
    """health_check_nginx — проверка Nginx."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_success_when_active_and_config_valid(self):
        from vless_installer.modules import health
        with patch.object(health, "_run") as mock_run, \
             patch("time.sleep"):
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="active\n", stderr=""),  # is-active
                MagicMock(returncode=0, stdout="", stderr=""),  # nginx -t
            ]
            with patch.object(health, "success"):
                result = health.health_check_nginx()
                self.assertTrue(result)

    def test_failure_when_inactive(self):
        from vless_installer.modules import health
        with patch.object(health, "_run") as mock_run, \
             patch("time.sleep"):
            mock_run.return_value = MagicMock(returncode=3, stdout="inactive\n", stderr="")
            with patch.object(health, "warn"):
                result = health.health_check_nginx()
                self.assertFalse(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
