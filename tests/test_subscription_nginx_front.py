#!/usr/bin/env python3
"""
tests/test_subscription_nginx_front.py
───────────────────────────────────────────────────────────────────────────────
Тесты для nginx front (прямой доступ по домену/IP с TLS) в подписке.

Покрываем:
  1. SERVICE_SUBSCRIPTION_NGINX существует в port_registry.
  2. Константы в subscription.py (DEFAULT_SUB_NGINX_PORT, _SUB_NGINX_STATE_FILE, _SUB_NGINX_SITE_NAME).
  3. _sub_nginx_status() — чтение состояния.
  4. serve() читает SUB_LISTEN_HOST из окружения (0.0.0.0 по умолчанию, 127.0.0.1 если задано).
  5. URL-генерация с учётом nginx front (url_base меняется).
  6. Интеграция с panel_nginx_front (вызывается с правильными параметрами).
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core(state_json: str | None = None):
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}

    tmp_dir = tempfile.mkdtemp(prefix="chimera_test_")
    state_file = Path(tmp_dir) / "state.json"
    if state_json is not None:
        state_file.write_text(state_json)

    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)

    g["STATE_FILE"] = state_file

    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return state_file


def _clear_subscription_module():
    mods_to_remove = [k for k in list(sys.modules)
                      if k.startswith("chimera.modules.subscription")]
    for m in mods_to_remove:
        del sys.modules[m]


# =============================================================================
#  1. SERVICE_SUBSCRIPTION_NGINX в port_registry
# =============================================================================
class TestServiceTagExists(unittest.TestCase):
    """Проверяем что SERVICE_SUBSCRIPTION_NGINX определён в port_registry."""

    def setUp(self):
        _setup_core()

    def test_service_tag_exists(self):
        from chimera.modules import port_registry
        self.assertTrue(hasattr(port_registry, "SERVICE_SUBSCRIPTION_NGINX"))
        tag = port_registry.SERVICE_SUBSCRIPTION_NGINX
        self.assertIsInstance(tag, str)
        self.assertEqual(tag, "subscription_nginx")
        # Должен отличаться от SERVICE_SUBSCRIPTION (backend).
        self.assertNotEqual(tag, port_registry.SERVICE_SUBSCRIPTION)

    def test_service_tag_in_documentation(self):
        from chimera.modules import port_registry
        src = Path(port_registry.__file__).read_text()
        self.assertIn("SERVICE_SUBSCRIPTION_NGINX", src)


# =============================================================================
#  2. Константы в subscription.py
# =============================================================================
class TestSubscriptionNginxConstants(unittest.TestCase):
    """Проверяем что в subscription.py есть нужные константы."""

    def setUp(self):
        _setup_core()
        _clear_subscription_module()

    def test_constants_exist(self):
        from chimera.modules import subscription
        self.assertTrue(hasattr(subscription, "DEFAULT_SUB_NGINX_PORT"))
        self.assertTrue(hasattr(subscription, "_SUB_NGINX_SITE_NAME"))
        self.assertTrue(hasattr(subscription, "_SUB_NGINX_STATE_FILE"))

    def test_default_port_is_int_and_not_privileged(self):
        from chimera.modules import subscription
        port = subscription.DEFAULT_SUB_NGINX_PORT
        self.assertIsInstance(port, int)
        self.assertGreater(port, 1024)
        self.assertLess(port, 65536)

    def test_default_port_does_not_conflict_with_backend(self):
        """Порт nginx front НЕ должен совпадать с DEFAULT_PORT (backend)."""
        from chimera.modules import subscription
        self.assertNotEqual(subscription.DEFAULT_SUB_NGINX_PORT, subscription.DEFAULT_PORT)

    def test_default_port_does_not_conflict_with_other_nginx_fronts(self):
        """Не должен конфликтовать с User Portal nginx (9443) или Telemt (8444)."""
        from chimera.modules import subscription
        # 9443 — User Portal nginx front (nginx_front_portal.DEFAULT_NGINX_FRONT_PORT)
        # 8444 — Telemt Panel direct (telemt_panel.DEFAULT_PANEL_TLS_PORT)
        # 8443 — backend подписки / rest_api
        self.assertNotEqual(subscription.DEFAULT_SUB_NGINX_PORT, 9443)
        self.assertNotEqual(subscription.DEFAULT_SUB_NGINX_PORT, 8444)
        self.assertNotEqual(subscription.DEFAULT_SUB_NGINX_PORT, 8443)

    def test_state_file_path(self):
        from chimera.modules import subscription
        self.assertTrue(str(subscription._SUB_NGINX_STATE_FILE).endswith(
            "subscription_nginx_front.json"))


# =============================================================================
#  3. _sub_nginx_status() — чтение состояния
# =============================================================================
class TestSubNginxStatus(unittest.TestCase):
    """_sub_nginx_status — корректное чтение состояния."""

    def setUp(self):
        _setup_core()
        _clear_subscription_module()

    def test_returns_disabled_when_no_state_file(self):
        from chimera.modules import subscription
        with patch.object(subscription, "_SUB_NGINX_STATE_FILE",
                           MagicMock(exists=MagicMock(return_value=False))):
            result = subscription._sub_nginx_status()
            self.assertFalse(result["enabled"])

    def test_returns_enabled_when_state_file_exists(self):
        from chimera.modules import subscription
        state_content = json.dumps({
            "enabled": True,
            "port": 9444,
            "domain": "example.com",
            "self_signed": False,
            "url": "https://example.com:9444",
        })
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = state_content
        with patch.object(subscription, "_SUB_NGINX_STATE_FILE", mock_path):
            result = subscription._sub_nginx_status()
            self.assertTrue(result["enabled"])
            self.assertEqual(result["port"], 9444)
            self.assertEqual(result["domain"], "example.com")
            self.assertFalse(result["self_signed"])

    def test_returns_disabled_on_invalid_json(self):
        from chimera.modules import subscription
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = "not json"
        with patch.object(subscription, "_SUB_NGINX_STATE_FILE", mock_path):
            result = subscription._sub_nginx_status()
            self.assertFalse(result["enabled"])


# =============================================================================
#  4. serve() читает SUB_LISTEN_HOST
# =============================================================================
class TestServeListensOnLoopbackEnv(unittest.TestCase):
    """serve() должен читать SUB_LISTEN_HOST из окружения."""

    def setUp(self):
        _setup_core()
        _clear_subscription_module()

    def test_serve_uses_env_loopback(self):
        """Если SUB_LISTEN_HOST=127.0.0.1 — serve() должен биндиться на 127.0.0.1."""
        from chimera.modules import subscription
        captured_host = []

        class FakeHTTPServer:
            def __init__(self, addr, handler):
                captured_host.append(addr[0])
            socket = MagicMock()
            def serve_forever(self):
                raise KeyboardInterrupt  # сразу выйти
            def server_close(self):
                pass

        # Замокаем всё, что serve() вызывает до/после ThreadingHTTPServer.
        with patch.dict(os.environ, {"SUB_LISTEN_HOST": "127.0.0.1"}), \
             patch.object(subscription, "ThreadingHTTPServer", FakeHTTPServer), \
             patch.object(subscription, "_load_sub_conf",
                          return_value={"enabled": True, "pepper": "x"}), \
             patch.object(subscription, "_find_cert_pair",
                          return_value=(None, None)), \
             patch.object(subscription, "_ensure_pepper", return_value="pepper"), \
             patch.object(subscription, "_load_state", return_value={}):
            try:
                subscription.serve(8443)
            except (KeyboardInterrupt, SystemExit):
                pass
        self.assertEqual(captured_host, ["127.0.0.1"])

    def test_serve_defaults_to_public_when_no_env(self):
        """Без SUB_LISTEN_HOST — serve() биндится на 0.0.0.0 (старый режим)."""
        from chimera.modules import subscription
        captured_host = []

        class FakeHTTPServer:
            def __init__(self, addr, handler):
                captured_host.append(addr[0])
            socket = MagicMock()
            def serve_forever(self):
                raise KeyboardInterrupt
            def server_close(self):
                pass

        # Удаляем SUB_LISTEN_HOST если есть.
        env = {k: v for k, v in os.environ.items() if k != "SUB_LISTEN_HOST"}
        with patch.dict(os.environ, env, clear=True), \
             patch.object(subscription, "ThreadingHTTPServer", FakeHTTPServer), \
             patch.object(subscription, "_load_sub_conf",
                          return_value={"enabled": True, "pepper": "x"}), \
             patch.object(subscription, "_find_cert_pair",
                          return_value=(None, None)), \
             patch.object(subscription, "_ensure_pepper", return_value="pepper"), \
             patch.object(subscription, "_load_state", return_value={}):
            try:
                subscription.serve(8443)
            except (KeyboardInterrupt, SystemExit):
                pass
        self.assertEqual(captured_host, ["0.0.0.0"])


# =============================================================================
#  5. _sub_nginx_get_url — URL с учётом nginx front
# =============================================================================
class TestSubNginxGetUrl(unittest.TestCase):
    """_sub_nginx_get_url — генерация URL с учётом nginx front."""

    def setUp(self):
        _setup_core()
        _clear_subscription_module()

    def test_returns_none_when_disabled(self):
        from chimera.modules import subscription
        with patch.object(subscription, "_sub_nginx_status",
                           return_value={"enabled": False}):
            result = subscription._sub_nginx_get_url("token123")
            self.assertIsNone(result)

    def test_returns_url_when_enabled_with_domain(self):
        from chimera.modules import subscription
        with patch.object(subscription, "_sub_nginx_status",
                           return_value={
                               "enabled": True,
                               "port": 9444,
                               "domain": "example.com",
                               "self_signed": False,
                           }):
            result = subscription._sub_nginx_get_url("token123")
            self.assertEqual(result, "https://example.com:9444/sub/token123")

    def test_returns_none_for_self_signed_without_domain(self):
        """Self-signed без domain — fallback (caller покажет backend URL)."""
        from chimera.modules import subscription
        with patch.object(subscription, "_sub_nginx_status",
                           return_value={
                               "enabled": True,
                               "port": 9444,
                               "domain": None,
                               "self_signed": True,
                           }):
            result = subscription._sub_nginx_get_url("token123")
            self.assertIsNone(result)


# =============================================================================
#  6. _sub_nginx_install — вызов panel_nginx_front с правильными параметрами
# =============================================================================
class TestSubNginxInstall(unittest.TestCase):
    """_sub_nginx_install — корректный вызов panel_nginx_front_install."""

    def setUp(self):
        _setup_core()
        _clear_subscription_module()

    def test_calls_panel_nginx_front_install(self):
        from chimera.modules import subscription
        captured_kwargs = {}

        def fake_install(**kwargs):
            captured_kwargs.update(kwargs)
            return True, "ok"

        with patch("chimera.modules.panel_nginx_front.panel_nginx_front_install",
                    fake_install), \
             patch.object(subscription, "_load_sub_conf",
                           return_value={"listen_port": 8443}):
            ok, msg = subscription._sub_nginx_install(
                port=9444,
                use_self_signed=False,
                domain="example.com",
            )
        self.assertTrue(ok)
        # Проверяем что передаётся правильный service_tag.
        self.assertEqual(captured_kwargs["service_tag"], "subscription_nginx")
        # backend_port должен браться из конфига подписки.
        self.assertEqual(captured_kwargs["backend_port"], 8443)
        # Внешний порт.
        self.assertEqual(captured_kwargs["port"], 9444)
        # backend_http_scheme=https (backend сам имеет TLS).
        self.assertEqual(captured_kwargs["backend_http_scheme"], "https")
        # websocket_origin_rewrite=False (подписке не нужен WebSocket).
        self.assertFalse(captured_kwargs["websocket_origin_rewrite"])


# =============================================================================
#  7. _sub_backend_bind_loopback — переключение backend на 127.0.0.1
# =============================================================================
class TestSubBackendBindLoopback(unittest.TestCase):
    """_sub_backend_bind_loopback — добавляет SUB_LISTEN_HOST в unit-файл."""

    def setUp(self):
        _setup_core()
        _clear_subscription_module()

    def test_adds_env_to_unit_file(self):
        from chimera.modules import subscription
        # Симулируем существующий unit-файл без SUB_LISTEN_HOST.
        unit_content = """[Unit]
Description=VLESS Subscription
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -m chimera.modules.subscription serve 8443
Restart=always

[Install]
WantedBy=multi-user.target
"""
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = unit_content
        written_content = []

        def fake_write(text):
            written_content.append(text)

        mock_path.write_text = fake_write

        with patch.object(subscription, "_UNIT_PATH", mock_path), \
             patch.object(subscription, "_load_sub_conf",
                           return_value={"listen_port": 8443}), \
             patch.object(subscription, "_fw_close_tcp") as mock_close, \
             patch("subprocess.run") as mock_run:
            subscription._sub_backend_bind_loopback()

        # Должно закрыть порт 8443.
        mock_close.assert_called_once_with(8443)
        # Должно записать обновлённый unit-файл с SUB_LISTEN_HOST.
        self.assertEqual(len(written_content), 1)
        self.assertIn("SUB_LISTEN_HOST=127.0.0.1", written_content[0])

    def test_idempotent_when_already_loopback(self):
        """Если SUB_LISTEN_HOST уже есть — не должен дублировать."""
        from chimera.modules import subscription
        unit_content = """[Service]
Environment=SUB_LISTEN_HOST=127.0.0.1
ExecStart=/usr/bin/python3 -m chimera.modules.subscription serve 8443
"""
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = unit_content
        mock_path.write_text = MagicMock()

        with patch.object(subscription, "_UNIT_PATH", mock_path), \
             patch.object(subscription, "_load_sub_conf",
                           return_value={"listen_port": 8443}), \
             patch.object(subscription, "_fw_close_tcp"), \
             patch("subprocess.run"):
            subscription._sub_backend_bind_loopback()

        # write_text НЕ должен вызываться — переменная уже есть.
        mock_path.write_text.assert_not_called()


# =============================================================================
#  8. _sub_backend_bind_public — возврат на 0.0.0.0
# =============================================================================
class TestSubBackendBindPublic(unittest.TestCase):
    """_sub_backend_bind_public — удаляет SUB_LISTEN_HOST из unit-файла."""

    def setUp(self):
        _setup_core()
        _clear_subscription_module()

    def test_removes_env_from_unit_file(self):
        from chimera.modules import subscription
        unit_content = """[Service]
Environment=SUB_LISTEN_HOST=127.0.0.1
ExecStart=/usr/bin/python3 -m chimera.modules.subscription serve 8443
"""
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = unit_content
        written_content = []

        def fake_write(text):
            written_content.append(text)

        mock_path.write_text = fake_write

        with patch.object(subscription, "_UNIT_PATH", mock_path), \
             patch.object(subscription, "_load_sub_conf",
                           return_value={"listen_port": 8443, "enabled": True}), \
             patch.object(subscription, "_fw_open_tcp") as mock_open, \
             patch("subprocess.run"):
            subscription._sub_backend_bind_public()

        # Должен удалить строку с SUB_LISTEN_HOST.
        self.assertEqual(len(written_content), 1)
        self.assertNotIn("SUB_LISTEN_HOST", written_content[0])
        # Должен открыть порт 8443 (т.к. enabled=True).
        mock_open.assert_called_once_with(8443)

    def test_does_not_open_port_when_disabled(self):
        """Если сервис выключен — не открываем порт."""
        from chimera.modules import subscription
        unit_content = "[Service]\nExecStart=test\n"
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = unit_content
        mock_path.write_text = MagicMock()

        with patch.object(subscription, "_UNIT_PATH", mock_path), \
             patch.object(subscription, "_load_sub_conf",
                           return_value={"listen_port": 8443, "enabled": False}), \
             patch.object(subscription, "_fw_open_tcp") as mock_open, \
             patch("subprocess.run"):
            subscription._sub_backend_bind_public()

        mock_open.assert_not_called()


# =============================================================================
#  9. uninstall_subscription_service — удаляет nginx front
# =============================================================================
class TestUninstallRemovesNginxFront(unittest.TestCase):
    """uninstall_subscription_service должен также снимать nginx front."""

    def setUp(self):
        _setup_core()
        _clear_subscription_module()

    def test_calls_sub_nginx_remove(self):
        """При полном удалении подписки — nginx front тоже должен быть снят."""
        from chimera.modules import subscription
        nginx_remove_called = []

        def fake_nginx_remove():
            nginx_remove_called.append(True)
            return True, "removed"

        with patch.object(subscription, "_sub_nginx_remove", fake_nginx_remove), \
             patch.object(subscription, "_load_sub_conf",
                           return_value={"listen_port": 8443, "enabled": True}), \
             patch.object(subscription, "_save_sub_conf"), \
             patch.object(subscription, "_fw_close_tcp"), \
             patch.object(subscription, "_stop_service_reliable"), \
             patch.object(subscription, "_kill_port_holder"), \
             patch("subprocess.run"):
            subscription.uninstall_subscription_service()

        self.assertEqual(len(nginx_remove_called), 1)


if __name__ == "__main__":
    unittest.main()
