#!/usr/bin/env python3
"""
tests/test_b4_mcp_nginx.py
───────────────────────────────────────────────────────────────────────────────
Тесты MCP-проксирования b4 через nginx front (v72.2).

Контекст: b4 >= 1.80 поднял MCP-сервер (/api/mcp). MCP go-sdk
(StreamableHTTPHandler) требует, чтобы при loopback-бэкенде Host-заголовок
был loopback (DNS-rebinding защита) — иначе 403 «invalid Host header».
nginx front b4 (порт 9743) до v72.2 слал Host $host (домен) → все
стандартные MCP-клиенты получали 403.

Покрывает:
  1. _generate_vhost(mcp_proxy=True) — location /api/mcp с loopback-Host,
     SSE-стримингом (proxy_buffering off) и долгим read-timeout.
  2. _generate_vhost() по умолчанию — БЕЗ /api/mcp (не меняем чужие панели:
     telemt, user portal, subscription).
  3. panel_nginx_front_install(mcp_proxy=...) — параметр доезжает до
     _generate_vhost.
  4. dpi_bypass._b4_nginx_install / youtube_b4._b4_nginx_install —
     передают mcp_proxy=True.
  5. REST-авторизация b4: _b4_web_credentials (config.json),
     _b4_api_token (POST /api/login, кэш), _b4_rest_request (Bearer,
     перевыпуск при 401).
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
import types
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    """Загружает chimera._core через exec и регистрирует в sys.modules."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core


def _load_module(name: str):
    """Импортирует chimera.modules.<name> с подготовленным _core."""
    _setup_core()
    import importlib
    mod = importlib.import_module(f"chimera.modules.{name}")
    return mod


class TestGenerateVhostMcp(unittest.TestCase):
    """_generate_vhost: MCP-локация (v72.2)."""

    @classmethod
    def setUpClass(cls):
        cls.pnf = _load_module("panel_nginx_front")

    def _vhost(self, **kw) -> str:
        from pathlib import Path as P
        return self.pnf._generate_vhost(
            port=9743, backend_port=9700,
            cert_path=P("/etc/ssl/certs/chimera-b4.crt"),
            key_path=P("/etc/ssl/private/chimera-b4.key"),
            domain="example.com",
            panel_name_slug="chimera-b4",
            **kw)

    def test_mcp_proxy_true_generates_location(self):
        v = self._vhost(mcp_proxy=True)
        self.assertIn("location /api/mcp {", v)

    def test_mcp_location_has_loopback_host(self):
        v = self._vhost(mcp_proxy=True)
        # Host обязан быть loopback (go-sdk DNS-rebinding protection).
        self.assertIn("proxy_set_header Host 127.0.0.1:9700;", v)

    def test_mcp_location_sse_streaming(self):
        v = self._vhost(mcp_proxy=True)
        # SSE: без буферизации, долгий read-timeout (discovery идёт минутами).
        self.assertIn("proxy_buffering off;", v)
        self.assertIn("proxy_read_timeout 3600s;", v)

    def test_mcp_location_strips_origin(self):
        v = self._vhost(mcp_proxy=True)
        # mcpGate сверяет Origin с Host — стриппаем, чтобы браузерные
        # MCP-клиенты не ловили "origin not allowed".
        self.assertIn('proxy_set_header Origin "";', v)

    def test_mcp_location_passes_to_backend(self):
        v = self._vhost(mcp_proxy=True)
        self.assertIn("proxy_pass http://127.0.0.1:9700;", v)

    def test_mcp_location_before_root_location(self):
        v = self._vhost(mcp_proxy=True)
        # prefix-локация длиннее / выигрывает независимо от порядка,
        # но в конфиге MCP-блок должен идти первым (читабельность).
        self.assertLess(v.index("location /api/mcp {"), v.index("location / {"))
    def test_default_has_no_mcp_location(self):
        # КРИТИЧНО: чужие панели (telemt/user portal/subscription) не
        # должны получить /api/mcp — там нет MCP-сервера, а 404 от бэкенда
        # вместо UI-роута был бы багом. (Ищем с «{», чтобы не матчить
        # поясняющий комментарий в шаблоне.)
        v = self._vhost()
        self.assertNotIn("location /api/mcp {", v)
        self.assertNotIn("proxy_set_header Host 127.0.0.1:9700;", v)

    def test_websocket_rewrite_still_works_with_mcp(self):
        # Сочетание параметров не должно падать (хотя b4 его не использует).
        v = self._vhost(mcp_proxy=True, websocket_origin_rewrite=True)
        self.assertIn("location /api/mcp {", v)
        self.assertIn("proxy_set_header Host 127.0.0.1:9700;", v)


class TestB4NginxInstallPassesMcp(unittest.TestCase):
    """dpi_bypass / youtube_b4: _b4_nginx_install передаёт mcp_proxy=True."""

    def _check(self, modname: str):
        mod = _load_module(modname)
        captured = {}

        def fake_install(**kw):
            captured.update(kw)
            return True, "ok"

        with patch("chimera.modules.panel_nginx_front.panel_nginx_front_install",
                   side_effect=fake_install):
            ok, _ = mod._b4_nginx_install(9743, True, None)
        self.assertTrue(ok)
        self.assertTrue(captured.get("mcp_proxy"),
                        f"{modname}._b4_nginx_install должен передавать mcp_proxy=True")
        self.assertEqual(captured.get("backend_port"), 9700)
        # ufw deny 9700 — мокаем subprocess, чтобы не трогать реальный.
        self.assertEqual(captured.get("cert_name_slug"), "chimera-b4")

    def test_dpi_bypass(self):
        mod = _load_module("dpi_bypass")
        captured = {}
        with patch("chimera.modules.panel_nginx_front.panel_nginx_front_install",
                   side_effect=lambda **kw: (captured.update(kw), (True, "ok"))[1]), \
             patch.object(mod, "subprocess", MagicMock()):
            mod._b4_nginx_install(9743, True, None)
        self.assertTrue(captured.get("mcp_proxy"))
        self.assertEqual(captured.get("backend_port"), 9700)

    def test_youtube_b4(self):
        mod = _load_module("youtube_b4")
        captured = {}
        with patch("chimera.modules.panel_nginx_front.panel_nginx_front_install",
                   side_effect=lambda **kw: (captured.update(kw), (True, "ok"))[1]), \
             patch.object(mod, "subprocess", MagicMock()):
            mod._b4_nginx_install(9743, True, None)
        self.assertTrue(captured.get("mcp_proxy"))


class _FakeResponse(io.BytesIO):
    """urllib-совместимый response-объект."""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    @property
    def status(self):
        return 200


class TestB4RestAuth(unittest.TestCase):
    """REST-авторизация b4 (v72.2): логин → Bearer → 401-retry.

    Сценарий: администратор включил username/password в b4 Web UI —
    REST-запросы Chimera без токена получали бы 401 и импорт сетов
    откатывался бы на прямую запись config.json (конфликт с live-режимом
    b4). Теперь Chimera логинится и шлёт Bearer.
    """

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.config_file = self.tmpdir / "config.json"
        self.dpi = _load_module("dpi_bypass")
        self.dpi.B4_CONFIG_FILE = self.config_file
        # Сброс кэша токена между тестами.
        self.dpi._B4_API_TOKEN["value"] = None

    def _write_config(self, username="", password=""):
        self.config_file.write_text(json.dumps({
            "system": {"web_server": {
                "port": 9700, "username": username, "password": password}}}))

    def test_credentials_none_when_no_auth(self):
        self._write_config()
        self.assertIsNone(self.dpi._b4_web_credentials())

    def test_credentials_from_config(self):
        self._write_config(username="admin", password="secret")
        self.assertEqual(self.dpi._b4_web_credentials(), ("admin", "secret"))

    def test_token_none_when_no_auth(self):
        self._write_config()
        with patch.object(self.dpi, "_b4_web_port", return_value=9700), \
             patch.object(self.dpi, "_B4_REST_OPENER") as opener:
            self.assertIsNone(self.dpi._b4_api_token())
            opener.open.assert_not_called()

    def test_token_login_and_cache(self):
        self._write_config(username="admin", password="secret")
        opener = MagicMock()
        opener.open.return_value = _FakeResponse(b'{"token": "tok123"}')
        with patch.object(self.dpi, "_b4_web_port", return_value=9700), \
             patch.object(self.dpi, "_B4_REST_OPENER", opener):
            tok = self.dpi._b4_api_token()
            self.assertEqual(tok, "tok123")
            # Второй вызов — из кэша, без нового /api/login.
            self.assertEqual(self.dpi._b4_api_token(), "tok123")
            self.assertEqual(opener.open.call_count, 1)
            # Проверяем тело логина.
            req = opener.open.call_args[0][0]
            self.assertIn("/api/login", req.full_url)
            self.assertEqual(json.loads(req.data.decode()),
                             {"username": "admin", "password": "secret"})

    def test_rest_request_sends_bearer(self):
        self._write_config(username="admin", password="secret")
        opener = MagicMock()

        def _route(req, timeout=None):
            if "/api/login" in req.full_url:
                return _FakeResponse(b'{"token": "tok123"}')
            return _FakeResponse(b'[{"id": "s1"}]')

        opener.open.side_effect = _route
        with patch.object(self.dpi, "_b4_web_port", return_value=9700), \
             patch.object(self.dpi, "_B4_REST_OPENER", opener):
            status, body = self.dpi._b4_rest_request("GET", "/api/sets")
        self.assertEqual(status, 200)
        self.assertEqual(body, [{"id": "s1"}])
        req = opener.open.call_args[0][0]
        self.assertIn("/api/sets", req.full_url)
        self.assertEqual(req.get_header("Authorization"), "Bearer tok123")

    def test_rest_request_401_retry(self):
        """Протухший токен → перевыпуск → повтор → успех."""
        self._write_config(username="admin", password="secret")
        self.dpi._B4_API_TOKEN["value"] = "STALE"
        opener = MagicMock()
        err = urllib.error.HTTPError("url", 401, "Unauthorized",
                                     io.StringIO("x"), io.BytesIO(b"{}"))
        resp_ok = _FakeResponse(b'[{"id": "s2"}]')
        # 1-й вызов — 401, 2-й (логин) — токен, 3-й — успешный ответ.
        opener.open.side_effect = [err, _FakeResponse(b'{"token": "tokNEW"}'), resp_ok]
        with patch.object(self.dpi, "_b4_web_port", return_value=9700), \
             patch.object(self.dpi, "_B4_REST_OPENER", opener):
            status, body = self.dpi._b4_rest_request("GET", "/api/sets")
        self.assertEqual(status, 200)
        self.assertEqual(body, [{"id": "s2"}])
        self.assertEqual(self.dpi._B4_API_TOKEN["value"], "tokNEW")
        self.assertEqual(opener.open.call_count, 3)

    def test_rest_request_no_auth_header_without_credentials(self):
        self._write_config()
        opener = MagicMock()
        opener.open.return_value = _FakeResponse(b'[{"id": "s1"}]')
        with patch.object(self.dpi, "_b4_web_port", return_value=9700), \
             patch.object(self.dpi, "_B4_REST_OPENER", opener):
            status, _ = self.dpi._b4_rest_request("GET", "/api/sets")
        self.assertEqual(status, 200)
        self.assertEqual(opener.open.call_count, 1)  # без /api/login
        req = opener.open.call_args[0][0]
        self.assertIsNone(req.get_header("Authorization"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
