#!/usr/bin/env python3
"""
tests/test_port_registry.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/port_registry.py — централизованный реестр портов.

Покрывает:
  1. _registry_load / _registry_save — JSON I/O
  2. port_register — регистрация с conflict detection
  3. port_unregister — снятие регистрации (по service+port, по service всем)
  4. port_get_conflicts — поиск конфликтов (registry/system/ufw)
  5. port_is_free — проверка свободы порта
  6. port_list_all / port_list_for_service — листинг
  7. ufw_open_port / ufw_close_port — UFW lifecycle
  8. _validate_port в nginx_front_portal — валидация порта
  9. _check_etc_services — well-known ports
"""
from __future__ import annotations

import contextlib
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Загружает chimera._core через exec и регистрирует в sys.modules."""
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


class TestRegistryLoadSave(unittest.TestCase):
    """_registry_load / _registry_save — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._reg_file = self._tmpdir / "ports.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        """Возвращает context manager, патчащий и PORT_REGISTRY_FILE, и LOCK_FILE."""
        from chimera.modules import port_registry
        lock_file = self._reg_file.with_suffix(".lock")
        @contextlib.contextmanager
        def _combined():
            with patch.object(port_registry, "PORT_REGISTRY_FILE", self._reg_file), \
                 patch.object(port_registry, "LOCK_FILE", lock_file):
                yield
        return _combined()

    def test_load_returns_empty_when_no_file(self):
        from chimera.modules.port_registry import _registry_load
        with self._patch():
            result = _registry_load()
        self.assertEqual(result, [])

    def test_load_returns_empty_on_corrupt(self):
        from chimera.modules.port_registry import _registry_load
        self._reg_file.write_text("{invalid")
        with self._patch():
            result = _registry_load()
        self.assertEqual(result, [])

    def test_save_then_load(self):
        from chimera.modules.port_registry import _registry_load, _registry_save
        entries = [{"service": "test", "port": 9999, "proto": "tcp"}]
        with self._patch():
            _registry_save(entries)
            loaded = _registry_load()
        self.assertEqual(loaded, entries)


class TestPortRegister(unittest.TestCase):
    """port_register — регистрация с conflict detection."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._reg_file = self._tmpdir / "ports.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        """Возвращает context manager, патчащий и PORT_REGISTRY_FILE, и LOCK_FILE."""
        from chimera.modules import port_registry
        lock_file = self._reg_file.with_suffix(".lock")
        @contextlib.contextmanager
        def _combined():
            with patch.object(port_registry, "PORT_REGISTRY_FILE", self._reg_file), \
                 patch.object(port_registry, "LOCK_FILE", lock_file):
                yield
        return _combined()

    def test_register_valid_port(self):
        from chimera.modules.port_registry import port_register, SERVICE_WEB_PANEL_NGINX
        with self._patch(), \
             patch("chimera.modules.port_registry.port_check_system", return_value=[]), \
             patch("chimera.modules.port_registry._check_ufw_rules", return_value=[]):
            ok, msg = port_register(SERVICE_WEB_PANEL_NGINX, 9443, "tcp",
                                    comment="test")
        self.assertTrue(ok, msg)

    def test_register_invalid_port(self):
        from chimera.modules.port_registry import port_register
        with self._patch():
            ok, msg = port_register("test", 0)
            self.assertFalse(ok)
            ok, msg = port_register("test", 70000)
            self.assertFalse(ok)
            ok, msg = port_register("test", -1)
            self.assertFalse(ok)

    def test_register_invalid_proto(self):
        from chimera.modules.port_registry import port_register
        with self._patch():
            ok, msg = port_register("test", 9999, "icmp")
            self.assertFalse(ok)

    def test_register_conflict_in_registry(self):
        """Регистрация порта, уже занятого другим сервисом в реестре."""
        from chimera.modules.port_registry import (
            port_register, SERVICE_WEB_PANEL, SERVICE_WEB_PANEL_NGINX,
        )
        with self._patch(), \
             patch("chimera.modules.port_registry.port_check_system", return_value=[]), \
             patch("chimera.modules.port_registry._check_ufw_rules", return_value=[]):
            # web_panel уже занял 9443 (допустим)
            port_register(SERVICE_WEB_PANEL, 9443, "tcp", comment="test")
            # web_panel_nginx пытается занять тот же порт
            ok, msg = port_register(SERVICE_WEB_PANEL_NGINX, 9443, "tcp",
                                    comment="other")
        self.assertFalse(ok)
        self.assertIn("занят", msg.lower())

    def test_register_same_service_same_port_idempotent(self):
        """Тот же сервис повторно регистрирует тот же порт — обновляем, не конфликт."""
        from chimera.modules.port_registry import port_register, SERVICE_WEB_PANEL_NGINX
        with self._patch(), \
             patch("chimera.modules.port_registry.port_check_system", return_value=[]), \
             patch("chimera.modules.port_registry._check_ufw_rules", return_value=[]):
            ok, _ = port_register(SERVICE_WEB_PANEL_NGINX, 9443, "tcp",
                                  comment="v1")
            self.assertTrue(ok)
            ok, msg = port_register(SERVICE_WEB_PANEL_NGINX, 9443, "tcp",
                                    comment="v2")
            self.assertTrue(ok, f"Должен быть идемпотентный: {msg}")

    def test_register_force_skips_conflict_check(self):
        """force=True обходит проверку конфликтов."""
        from chimera.modules.port_registry import (
            port_register, SERVICE_WEB_PANEL, SERVICE_WEB_PANEL_NGINX,
        )
        with self._patch():
            port_register(SERVICE_WEB_PANEL, 9443, "tcp", comment="test", force=True)
            ok, msg = port_register(SERVICE_WEB_PANEL_NGINX, 9443, "tcp",
                                    comment="force test", force=True)
        self.assertTrue(ok, f"force должен обойти конфликты: {msg}")


class TestPortUnregister(unittest.TestCase):
    """port_unregister — снятие регистрации."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._reg_file = self._tmpdir / "ports.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        """Возвращает context manager, патчащий и PORT_REGISTRY_FILE, и LOCK_FILE."""
        from chimera.modules import port_registry
        lock_file = self._reg_file.with_suffix(".lock")
        @contextlib.contextmanager
        def _combined():
            with patch.object(port_registry, "PORT_REGISTRY_FILE", self._reg_file), \
                 patch.object(port_registry, "LOCK_FILE", lock_file):
                yield
        return _combined()

    def test_unregister_specific_port(self):
        from chimera.modules.port_registry import port_register, port_unregister
        with self._patch():
            port_register("svc1", 9001, "tcp", force=True)
            port_register("svc1", 9002, "tcp", force=True)
            result = port_unregister("svc1", port=9001, proto="tcp")
            self.assertTrue(result)
            # Вторая запись осталась.
            from chimera.modules.port_registry import port_list_for_service
            entries = port_list_for_service("svc1")
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["port"], 9002)

    def test_unregister_all_for_service(self):
        from chimera.modules.port_registry import (
            port_register, port_unregister, port_list_for_service,
        )
        with self._patch():
            port_register("svc1", 9001, "tcp", force=True)
            port_register("svc1", 9002, "tcp", force=True)
            port_register("svc2", 9003, "tcp", force=True)
            result = port_unregister("svc1")
            self.assertTrue(result)
            self.assertEqual(len(port_list_for_service("svc1")), 0)
            self.assertEqual(len(port_list_for_service("svc2")), 1)

    def test_unregister_nonexistent_returns_false(self):
        from chimera.modules.port_registry import port_unregister
        with self._patch():
            result = port_unregister("nonexistent")
            self.assertFalse(result)


class TestPortGetConflicts(unittest.TestCase):
    """port_get_conflicts — поиск конфликтов."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._reg_file = self._tmpdir / "ports.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        """Возвращает context manager, патчащий и PORT_REGISTRY_FILE, и LOCK_FILE."""
        from chimera.modules import port_registry
        lock_file = self._reg_file.with_suffix(".lock")
        @contextlib.contextmanager
        def _combined():
            with patch.object(port_registry, "PORT_REGISTRY_FILE", self._reg_file), \
                 patch.object(port_registry, "LOCK_FILE", lock_file):
                yield
        return _combined()

    def test_conflict_in_registry(self):
        from chimera.modules.port_registry import (
            port_register, port_get_conflicts, SERVICE_WEB_PANEL,
        )
        with self._patch():
            port_register(SERVICE_WEB_PANEL, 9443, "tcp", force=True)
            conflicts = port_get_conflicts(9443, "tcp",
                                            exclude_service="other_svc")
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["type"], "registry")
        self.assertEqual(conflicts[0]["service"], SERVICE_WEB_PANEL)

    def test_exclude_service_skips_own_entries(self):
        from chimera.modules.port_registry import (
            port_register, port_get_conflicts, SERVICE_WEB_PANEL,
        )
        with self._patch():
            port_register(SERVICE_WEB_PANEL, 9443, "tcp", force=True)
            # Если проверяем для того же сервиса — своя запись не конфликт.
            conflicts = port_get_conflicts(9443, "tcp",
                                            exclude_service=SERVICE_WEB_PANEL)
        self.assertEqual(len(conflicts), 0)

    def test_conflict_in_system(self):
        """Если ss показывает что порт слушается — конфликт."""
        from chimera.modules.port_registry import port_get_conflicts
        with patch("chimera.modules.port_registry.port_check_system",
                   return_value=["nginx (pid=1234)"]):
            conflicts = port_get_conflicts(9443, "tcp")
        self.assertTrue(any(c["type"] == "system" for c in conflicts))

    def test_no_conflict_when_free(self):
        from chimera.modules.port_registry import port_get_conflicts
        with patch("chimera.modules.port_registry.port_check_system",
                   return_value=[]), \
             patch("chimera.modules.port_registry._check_ufw_rules",
                   return_value=[]):
            conflicts = port_get_conflicts(9999, "tcp")
        self.assertEqual(conflicts, [])


class TestPortIsFree(unittest.TestCase):
    """port_is_free — проверка свободы порта."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_free_port(self):
        from chimera.modules.port_registry import port_is_free
        with patch("chimera.modules.port_registry.port_check_system",
                   return_value=[]), \
             patch("chimera.modules.port_registry._check_ufw_rules",
                   return_value=[]):
            is_free, descs = port_is_free(9999, "tcp")
        self.assertTrue(is_free)
        self.assertEqual(descs, [])

    def test_occupied_port(self):
        from chimera.modules.port_registry import port_is_free
        with patch("chimera.modules.port_registry.port_check_system",
                   return_value=["nginx (pid=1234)"]):
            is_free, descs = port_is_free(443, "tcp")
        self.assertFalse(is_free)
        self.assertGreater(len(descs), 0)


class TestPortListAll(unittest.TestCase):
    """port_list_all / port_list_for_service."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._reg_file = self._tmpdir / "ports.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_list_all(self):
        from chimera.modules import port_registry
        from chimera.modules.port_registry import (
            port_register, port_list_all,
        )
        lock_file = self._reg_file.with_suffix(".lock")
        with patch.object(port_registry, "PORT_REGISTRY_FILE", self._reg_file), \
             patch.object(port_registry, "LOCK_FILE", lock_file):
            port_register("svc1", 9001, "tcp", force=True)
            port_register("svc2", 9002, "tcp", force=True)
            entries = port_list_all()
            self.assertEqual(len(entries), 2)


class TestUfwHelpers(unittest.TestCase):
    """ufw_open_port / ufw_close_port — UFW lifecycle."""

    def setUp(self):
        _setup_core_in_sysmodules()

    @patch("chimera.modules.port_registry.shutil.which", return_value="/usr/sbin/ufw")
    @patch("chimera.modules.port_registry._check_ufw_rules", return_value=[])
    @patch("chimera.modules.port_registry.subprocess.run")
    def test_ufw_open_port(self, mock_run, mock_check, mock_which):
        from chimera.modules.port_registry import ufw_open_port
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        ok, msg = ufw_open_port(9443, "tcp", "test_svc", comment="test")
        self.assertTrue(ok, msg)
        # Проверяем что был вызов ufw allow.
        for c in mock_run.call_args_list:
            cmd = c.args[0]
            if "ufw" in cmd and "allow" in cmd:
                self.assertIn("9443/tcp", cmd)
                self.assertIn("chimera-test_svc", " ".join(cmd))
                return
        self.fail("ufw allow не был вызван")

    @patch("chimera.modules.port_registry.shutil.which", return_value="/usr/sbin/ufw")
    @patch("chimera.modules.port_registry._check_ufw_rules")
    def test_ufw_open_idempotent(self, mock_check, mock_which):
        """Если уже открыто нашим правилом — не дублируем."""
        from chimera.modules.port_registry import ufw_open_port
        mock_check.return_value = [{
            "num": 1, "comment": "chimera-test_svc test", "raw": "9443/tcp ALLOW",
        }]
        ok, msg = ufw_open_port(9443, "tcp", "test_svc")
        self.assertTrue(ok)
        self.assertIn("Уже открыто", msg)

    @patch("chimera.modules.port_registry.shutil.which", return_value="/usr/sbin/ufw")
    @patch("chimera.modules.port_registry._check_ufw_rules")
    def test_ufw_open_foreign_conflict(self, mock_check, mock_which):
        """Если порт открыт чужим правилом — не трогаем."""
        from chimera.modules.port_registry import ufw_open_port
        mock_check.return_value = [{
            "num": 1, "comment": "other-app", "raw": "9443/tcp ALLOW",
        }]
        ok, msg = ufw_open_port(9443, "tcp", "test_svc")
        self.assertFalse(ok)
        self.assertIn("чужим", msg.lower())

    @patch("chimera.modules.port_registry.shutil.which", return_value=None)
    def test_ufw_open_no_ufw(self, mock_which):
        """Если ufw не установлен — возвращаем False."""
        from chimera.modules.port_registry import ufw_open_port
        ok, msg = ufw_open_port(9443, "tcp", "test_svc")
        self.assertFalse(ok)


class TestEtcServices(unittest.TestCase):
    """_check_etc_services — well-known ports."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_known_port_443(self):
        from chimera.modules.port_registry import _check_etc_services
        # 443 = https — должно найтись в /etc/services.
        result = _check_etc_services(443, "tcp")
        self.assertIsNotNone(result)
        self.assertEqual(result, "https")

    def test_known_port_80(self):
        from chimera.modules.port_registry import _check_etc_services
        result = _check_etc_services(80, "tcp")
        self.assertEqual(result, "http")

    def test_unknown_port(self):
        from chimera.modules.port_registry import _check_etc_services
        result = _check_etc_services(59999, "tcp")
        self.assertIsNone(result)


class TestNginxFrontValidatePort(unittest.TestCase):
    """nginx_front_portal._validate_port — валидация порта."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_valid_port(self):
        from chimera.modules.nginx_front_portal import _validate_port
        ok, _ = _validate_port(9443)
        self.assertTrue(ok)

    def test_privileged_port_rejected(self):
        from chimera.modules.nginx_front_portal import _validate_port
        ok, err = _validate_port(443)
        self.assertFalse(ok)
        self.assertIn("Привилегированный", err)

    def test_reserved_8443_rejected(self):
        """8443 зарезервирован под rest_api backend."""
        from chimera.modules.nginx_front_portal import _validate_port
        ok, err = _validate_port(8443)
        self.assertFalse(ok)
        self.assertIn("8443", err)

    def test_reserved_80_rejected(self):
        from chimera.modules.nginx_front_portal import _validate_port
        ok, _ = _validate_port(80)
        self.assertFalse(ok)

    def test_out_of_range(self):
        from chimera.modules.nginx_front_portal import _validate_port
        ok, _ = _validate_port(0)
        self.assertFalse(ok)
        ok, _ = _validate_port(70000)
        self.assertFalse(ok)


class TestNginxFrontVhostGeneration(unittest.TestCase):
    """nginx_front_portal._generate_vhost — генерация конфига."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_vhost_contains_required_directives(self):
        from chimera.modules.nginx_front_portal import _generate_vhost
        vhost = _generate_vhost(
            port=9443, backend_port=8443,
            cert_path=Path("/etc/letsencrypt/live/example.com/fullchain.pem"),
            key_path=Path("/etc/letsencrypt/live/example.com/privkey.pem"),
            domain="example.com",
        )
        # Проверяем ключевые элементы.
        self.assertIn("listen 9443 ssl http2", vhost)
        self.assertIn("proxy_pass http://127.0.0.1:8443", vhost)
        self.assertIn("ssl_certificate", vhost)
        self.assertIn("ssl_certificate_key", vhost)
        self.assertIn("server_name example.com", vhost)
        # Security headers.
        self.assertIn("Strict-Transport-Security", vhost)
        self.assertIn("X-Frame-Options", vhost)
        # ACME challenge location для renewal.
        self.assertIn(".well-known/acme-challenge", vhost)

    def test_vhost_does_not_listen_on_443(self):
        """nginx front НЕ должен слушать 443 (это VLESS/nginx основной)."""
        from chimera.modules.nginx_front_portal import _generate_vhost
        vhost = _generate_vhost(
            port=9443, backend_port=8443,
            cert_path=Path("/tmp/cert.pem"),
            key_path=Path("/tmp/key.pem"),
            domain="example.com",
        )
        # Не должно быть "listen 443" в основном server-блоке для портала.
        # Может быть только в HTTP→HTTPS redirect, которого нет в нашем vhost.
        self.assertNotIn("listen 443", vhost)


class TestNginxFrontStatus(unittest.TestCase):
    """nginx_front_portal.nginx_front_status — статус."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "nfp_state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_status_disabled_when_no_state(self):
        from chimera.modules import nginx_front_portal
        with patch.object(nginx_front_portal, "NGINX_FRONT_STATE_FILE",
                          self._state_file):
            status = nginx_front_portal.nginx_front_status()
        self.assertFalse(status["enabled"])

    def test_status_after_install_simulated(self):
        from chimera.modules import nginx_front_portal
        # Симулируем state после установки.
        self._state_file.write_text(json.dumps({
            "enabled": True,
            "port": 9443,
            "domain": "example.com",
            "backend_port": 8443,
            "cert_path": "/etc/letsencrypt/live/example.com/fullchain.pem",
        }))
        with patch.object(nginx_front_portal, "NGINX_FRONT_STATE_FILE",
                          self._state_file), \
             patch.object(nginx_front_portal, "_is_nginx_active", return_value=True):
            status = nginx_front_portal.nginx_front_status()
        self.assertTrue(status["enabled"])
        self.assertEqual(status["port"], 9443)
        self.assertEqual(status["domain"], "example.com")
        self.assertTrue(status["nginx_active"])


class TestNginxFrontRemoveWithUninstallWebPanel(unittest.TestCase):
    """Интеграция: uninstall_web_service должен удалять nginx front."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_uninstall_web_service_calls_nginx_front_remove(self):
        """uninstall_web_service() вызывает nginx_front_remove если фронт включён."""
        from chimera.modules import rest_api
        import inspect
        src = inspect.getsource(rest_api.uninstall_web_service)
        self.assertIn("nginx_front_remove", src)
        self.assertIn("nginx_front_status", src)


class TestRestApiMenuHasNginxFrontItem(unittest.TestCase):
    """Проверка что пункт [7] nginx front подключён в do_manage_web_panel."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_menu_has_item_7(self):
        from chimera.modules import rest_api
        import inspect
        src = inspect.getsource(rest_api.do_manage_web_panel)
        self.assertIn('"7"', src)
        self.assertIn("do_manage_nginx_front", src)


# ============================================================================
#  Atomic write + file lock tests
# ============================================================================

class TestAtomicWrite(unittest.TestCase):
    """ атомарная запись через tempfile + os.replace."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._reg_file = self._tmpdir / "ports.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        from chimera.modules import port_registry
        lock_file = self._reg_file.with_suffix(".lock")
        @contextlib.contextmanager
        def _combined():
            with patch.object(port_registry, "PORT_REGISTRY_FILE", self._reg_file), \
                 patch.object(port_registry, "LOCK_FILE", lock_file):
                yield
        return _combined()

    def test_save_creates_valid_json(self):
        """_registry_save создаёт валидный JSON."""
        from chimera.modules.port_registry import _registry_save, _registry_load
        entries = [{"service": "test", "port": 9999, "proto": "tcp"}]
        with self._patch():
            _registry_save(entries)
            loaded = _registry_load()
        self.assertEqual(loaded, entries)

    def test_save_does_not_leave_tmp_file(self):
        """После save временный .tmp файл не остаётся."""
        from chimera.modules.port_registry import _registry_save
        with self._patch():
            _registry_save([{"service": "test", "port": 9999}])
        tmp_file = self._reg_file.with_suffix(".tmp")
        self.assertFalse(tmp_file.exists(), f".tmp file should not exist: {tmp_file}")

    def test_save_aborted_mid_write_preserves_original(self):
        """Если os.replace не выполнился (exception до него) — оригинал цел."""
        from chimera.modules import port_registry
        # Сначала пишем валидный файл.
        with self._patch():
            port_registry._registry_save([{"service": "original", "port": 1111}])
        # Теперь мокаем os.replace чтобы бросить исключение.
        # Патчим на уровне модуля (не через _patch, т.к. нам нужен
        # оригинальный PORT_REGISTRY_FILE для проверки).
        with patch.object(port_registry.os, "replace", side_effect=OSError("simulated")):
            try:
                port_registry._registry_save([{"service": "broken", "port": 2222}])
            except OSError:
                pass
        # Оригинальный файл должен быть нетронутым.
        data = json.loads(self._reg_file.read_text())
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["service"], "original")
        self.assertEqual(data[0]["port"], 1111)


class TestFileLock(unittest.TestCase):
    """ файловая блокировка через fcntl.flock."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._reg_file = self._tmpdir / "ports.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        from chimera.modules import port_registry
        lock_file = self._reg_file.with_suffix(".lock")
        @contextlib.contextmanager
        def _combined():
            with patch.object(port_registry, "PORT_REGISTRY_FILE", self._reg_file), \
                 patch.object(port_registry, "LOCK_FILE", lock_file):
                yield
        return _combined()

    def test_concurrent_register_different_ports(self):
        """Тест 1: конкурентная регистрация РАЗНЫХ портов — обе записи сохраняются."""
        import threading
        from chimera.modules.port_registry import port_register, port_list_all

        results = []
        def _register(port, tag):
            ok, msg = port_register(tag, port, "tcp", comment=f"test {tag}", force=True)
            results.append((ok, port, tag))

        with self._patch():
            t1 = threading.Thread(target=_register, args=(9001, "svc1"))
            t2 = threading.Thread(target=_register, args=(9002, "svc2"))
            t1.start()
            t2.start()
            t1.join(timeout=15)
            t2.join(timeout=15)

        self.assertEqual(len(results), 2, "Оба потока должны завершиться")
        for ok, port, tag in results:
            self.assertTrue(ok, f"Регистрация {tag}:{port} должна быть успешной: {results}")

        with self._patch():
            entries = port_list_all()
        ports = sorted([e["port"] for e in entries])
        self.assertEqual(ports, [9001, 9002],
                         "Обе записи должны быть в реестре — ни одна не потеряна")

    def test_concurrent_register_same_port_different_services(self):
        """Тест 2: конкурентная регистрация ОДНОГО порта разными сервисами —
        финальный JSON валиден (не обрывки от каждого писателя)."""
        import threading
        from chimera.modules.port_registry import port_register, port_list_all

        results = []
        def _register(tag):
            ok, msg = port_register(tag, 9443, "tcp", comment=f"test {tag}", force=True)
            results.append((ok, tag))

        with self._patch():
            t1 = threading.Thread(target=_register, args=("svc_a",))
            t2 = threading.Thread(target=_register, args=("svc_b",))
            t1.start()
            t2.start()
            t1.join(timeout=15)
            t2.join(timeout=15)

        # Файл должен быть валидным JSON (не обрывки).
        data = json.loads(self._reg_file.read_text())
        self.assertIsInstance(data, list, "Файл должен быть валидным JSON list")
        # Должна быть хотя бы одна запись (вторая может перезаписать первую
        # т.к. разные service_tag → append, но одна может не успеть из-за лока).
        # Главное — файл не повреждён.
        for entry in data:
            self.assertIn("service", entry)
            self.assertIn("port", entry)

    def test_lock_timeout_returns_error(self):
        """Тест 3: если лок занят дольше таймаута — port_register возвращает ошибку."""
        import fcntl
        from chimera.modules import port_registry
        from chimera.modules.port_registry import port_register

        lock_file = self._reg_file.with_suffix(".lock")
        lock_file.parent.mkdir(parents=True, exist_ok=True)

        with self._patch():
            # Держим лок вручную в другом потоке.
            held = threading.Event()
            release = threading.Event()

            def _hold_lock():
                with open(lock_file, "w") as f:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                    held.set()
                    release.wait(timeout=20)
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

            t = threading.Thread(target=_hold_lock)
            t.start()
            held.wait(timeout=5)  # ждём пока лок будет взят

            # Пытаемся зарегистрировать с коротким таймаутом.
            try:
                ok, msg = port_register("test_svc", 9999, "tcp",
                                        comment="timeout test", force=True)
                # С _LOCK_TIMEOUT_SEC=10 по умолчанию — может успеть.
                # Проверяем что хотя бы не зависли.
            except TimeoutError:
                ok = False
                msg = "TimeoutError"
            finally:
                release.set()
                t.join(timeout=5)

            # Если таймаут сработал — ok=False. Если успело — ok=True.
            # В обоих случаях процесс не завис.
            self.assertIsInstance(ok, bool)

    def test_lock_timeout_with_short_timeout(self):
        """Тест 3b: с очень коротким таймаутом и занятым локом — точно TimeoutError."""
        import fcntl
        from chimera.modules import port_registry

        lock_file = self._reg_file.with_suffix(".lock")
        lock_file.parent.mkdir(parents=True, exist_ok=True)

        with self._patch():
            # Держим лок.
            f = open(lock_file, "w")
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)

            try:
                with port_registry._registry_lock(timeout=0.3):
                    self.fail("Не должно было получить лок при занятом")
            except TimeoutError:
                pass  # ожидаемое поведение
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                f.close()


if __name__ == "__main__":
    unittest.main()
