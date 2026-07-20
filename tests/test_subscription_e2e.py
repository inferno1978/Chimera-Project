#!/usr/bin/env python3
"""
tests/test_subscription_e2e.py
───────────────────────────────────────────────────────────────────────────────
Сквозные (end-to-end) тесты для HTTP-пути единой подписки.

Принцип: юнит-тесты чистых функций (_resolve_format, _filter_safe_links) НЕ
заменяют проверку точки их сборки внутри do_GET(). Эти тесты поднимают реальный
_SubHandler через ThreadingHTTPServer и делают настоящий HTTP GET-запрос —
чтобы поймать баги вроде AttributeError: 'bytes' has no attribute 'copy'
которые прячутся в связывающем коде и не видны через прямые вызовы внутренних
функций.

Покрытие:
  1. GET /sub/{valid_token} — 200, text/plain, валидный Base64.
  2. GET /sub/{valid_token}?format=safe — 200, Base64 без naive/mieru.
  3. GET /sub/{valid_token} с UA: Karing — 200, safe-фильтрованный.
  4. GET /sub/{valid_token}?format=singbox — 200, application/json, outbounds.
  5. GET /sub/{valid_token}/ios — 200, регрессия iOS-маршрута.
  6. GET /sub/{invalid_token} — 404 на всех форматах.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import types
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch, MagicMock
from urllib.request import urlopen, Request
from urllib.error import HTTPError

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


# Тестовые данные — валидный 24-hex token.
_TEST_TOKEN = "aabbccddeeff001122334455"
_TEST_USER = {
    "uuid": "test-uuid-1234",
    "email": "test@blackshadows.online",
    "name": "testuser",
    "portal_password": "testpass",
}
_TEST_STATE = {
    "domain": "test.blackshadows.online",
    "server_port": 443,
    "protocol_mode": "reality",
    "public_key": "test_pub_key",
    "short_id": "abcd1234",
    "uuid": "test-uuid-1234",
    "fingerprint": "chrome",
    "xtls_flow": "xtls-rprx-vision",
    "xhttp_path": "/",
    "install_mode": "A",
}


class TestSubscriptionE2E(unittest.TestCase):
    """Сквозные HTTP-тесты для единой подписки.

    Поднимает реальный ThreadingHTTPServer с _SubHandler на случайном порту,
    делает настоящие HTTP-запросы через urllib.
    """

    @classmethod
    def setUpClass(cls):
        _setup_core()
        # Подменяем state.json, users.json, subscription.json.
        cls._tmpdir = Path(tempfile.mkdtemp())
        cls._state_file = cls._tmpdir / "state.json"
        cls._users_file = cls._tmpdir / "users.json"
        cls._sub_conf = cls._tmpdir / "subscription.json"
        cls._state_file.write_text(json.dumps(_TEST_STATE))
        cls._users_file.write_text(json.dumps([_TEST_USER]))
        # subscription.json с pepper и валидным token.
        from chimera.modules import subscription
        # Вычисляем token = first 24 hex of HMAC(pepper, uuid).
        import hashlib, hmac
        pepper = "test_pepper_12345"
        token_raw = hmac.new(pepper.encode(), _TEST_USER["uuid"].encode(),
                            hashlib.sha256).hexdigest()
        cls._token = token_raw[:24]
        cls._sub_conf.write_text(json.dumps({
            "pepper": pepper,
            "enabled": True,
            "listen_port": 0,  # will be overridden
            "identity_map": {},
        }))

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls._tmpdir, ignore_errors=True)

    def _start_server(self):
        """Запускает HTTP-сервер на случайном порту, возвращает (server, port)."""
        from chimera.modules.subscription import _SubHandler
        server = ThreadingHTTPServer(("127.0.0.1", 0), _SubHandler)
        port = server.server_address[1]
        import threading
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, port, thread

    def _stop_server(self, server, thread):
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    def _make_request(self, port, path, headers=None):
        """Делает HTTP GET и возвращает (status, content_type, body_bytes)."""
        url = f"http://127.0.0.1:{port}{path}"
        req = Request(url)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        try:
            with urlopen(req, timeout=10) as resp:
                return resp.status, resp.headers.get("Content-Type", ""), resp.read()
        except HTTPError as e:
            return e.code, e.headers.get("Content-Type", ""), e.read()

    def _patch_all(self):
        """Возвращает список patch-объектов для всех внешних зависимостей."""
        from chimera.modules import subscription
        patches = [
            patch.object(subscription, "_load_state", return_value=dict(_TEST_STATE)),
            patch.object(subscription, "_load_sub_conf", return_value=json.loads(self._sub_conf.read_text())),
            patch.object(subscription, "_load_all_users", return_value=[_TEST_USER]),
            patch.object(subscription, "_get_server_ip", return_value="1.2.3.4"),
            patch.object(subscription, "is_hybrid_mieru_active", return_value=False),
            # build_subscription_body_ios calls _build_vless_uri which reads
            # config.json for shadow-user lookup — patch it to return a simple URI.
            patch.object(subscription, "_build_vless_uri",
                         return_value="vless://test-uuid@test.x.com:443?security=reality"),
        ]
        return patches

    # ── Тесты ─────────────────────────────────────────────────────────────

    def test_default_base64(self):
        """GET /sub/{token} — 200, text/plain, валидный Base64."""
        patches = self._patch_all()
        for p in patches:
            p.start()
        try:
            server, port, thread = self._start_server()
            try:
                status, ct, body = self._make_request(port, f"/sub/{self._token}")
                self.assertEqual(status, 200)
                self.assertIn("text/plain", ct)
                # Декодируем Base64 — должно работать без ошибок.
                decoded = base64.b64decode(body).decode("utf-8")
                self.assertIsInstance(decoded, str)
                # Должна быть хотя бы одна ссылка.
                self.assertGreater(len(decoded), 0)
            finally:
                self._stop_server(server, thread)
        finally:
            for p in patches:
                p.stop()

    def test_format_safe(self):
        """GET /sub/{token}?format=safe — 200, Base64 без naive/mieru."""
        patches = self._patch_all()
        for p in patches:
            p.start()
        try:
            server, port, thread = self._start_server()
            try:
                status, ct, body = self._make_request(
                    port, f"/sub/{self._token}?format=safe")
                self.assertEqual(status, 200)
                self.assertIn("text/plain", ct)
                # Декодируем Base64.
                decoded = base64.b64decode(body).decode("utf-8")
                links = decoded.split("\n")
                # Не должно быть naive+https:// или mierus://.
                for link in links:
                    self.assertFalse(
                        link.startswith("naive+https://"),
                        f"naive+https:// не должен быть в safe-подписке: {link}")
                    self.assertFalse(
                        link.startswith("mierus://"),
                        f"mierus:// не должен быть в safe-подписке: {link}")
            finally:
                self._stop_server(server, thread)
        finally:
            for p in patches:
                p.stop()

    def test_ua_karing_triggers_safe(self):
        """GET /sub/{token} с UA: Karing/2.0 — 200, safe-фильтрованный."""
        patches = self._patch_all()
        for p in patches:
            p.start()
        try:
            server, port, thread = self._start_server()
            try:
                status, ct, body = self._make_request(
                    port, f"/sub/{self._token}",
                    headers={"User-Agent": "Karing/2.0"})
                self.assertEqual(status, 200)
                decoded = base64.b64decode(body).decode("utf-8")
                for link in decoded.split("\n"):
                    self.assertFalse(link.startswith("naive+https://"))
                    self.assertFalse(link.startswith("mierus://"))
            finally:
                self._stop_server(server, thread)
        finally:
            for p in patches:
                p.stop()

    def test_format_singbox(self):
        """GET /sub/{token}?format=singbox — 200, application/json, outbounds."""
        patches = self._patch_all()
        for p in patches:
            p.start()
        try:
            server, port, thread = self._start_server()
            try:
                status, ct, body = self._make_request(
                    port, f"/sub/{self._token}?format=singbox")
                self.assertEqual(status, 200)
                self.assertIn("application/json", ct)
                # Должно парситься как JSON.
                config = json.loads(body)
                self.assertIsInstance(config, dict)
                self.assertIn("outbounds", config)
                self.assertGreater(len(config["outbounds"]), 0)
            finally:
                self._stop_server(server, thread)
        finally:
            for p in patches:
                p.stop()

    def test_ios_route_unchanged(self):
        """GET /sub/{token}/ios — 200, text/plain (регрессия)."""
        from chimera.modules import subscription
        # iOS route calls build_subscription_body_ios which has deep
        # dependencies (shadow-user lookup, ios_link_variant, etc.).
        # Patch it to return a simple valid Base64 body.
        import base64 as _b64
        fake_body = _b64.b64encode(b"vless://test-uuid@test.x.com:443")
        patches = self._patch_all()
        patches.append(patch.object(subscription, "build_subscription_body_ios",
                                    return_value=fake_body))
        for p in patches:
            p.start()
        try:
            server, port, thread = self._start_server()
            try:
                status, ct, body = self._make_request(
                    port, f"/sub/{self._token}/ios")
                self.assertEqual(status, 200)
                self.assertIn("text/plain", ct)
                # Должен декодироваться как Base64.
                decoded = base64.b64decode(body).decode("utf-8")
                self.assertIsInstance(decoded, str)
            finally:
                self._stop_server(server, thread)
        finally:
            for p in patches:
                p.stop()

    def test_invalid_token_returns_404(self):
        """GET /sub/{invalid} — 404 на всех форматах."""
        patches = self._patch_all()
        for p in patches:
            p.start()
        try:
            server, port, thread = self._start_server()
            try:
                # Обычный.
                status, _, _ = self._make_request(
                    port, "/sub/000000000000000000000000")
                self.assertEqual(status, 404)
                # format=safe.
                status, _, _ = self._make_request(
                    port, "/sub/000000000000000000000000?format=safe")
                self.assertEqual(status, 404)
                # format=singbox.
                status, _, _ = self._make_request(
                    port, "/sub/000000000000000000000000?format=singbox")
                self.assertEqual(status, 404)
            finally:
                self._stop_server(server, thread)
        finally:
            for p in patches:
                p.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
