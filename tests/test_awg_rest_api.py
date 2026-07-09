#!/usr/bin/env python3
"""
tests/test_awg_rest_api.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/awg_rest_api.py и интеграции с rest_api.

Покрывает:
  1. /api/awg/* отдают 404 если AWG не установлен (не 500).
  2. ADMIN endpoints требуют admin auth (без неё — 401).
  3. USER endpoints требуют user auth (без неё — 401).
  4. User НЕ может запросить чужой /api/awg/peers/{name}/config напрямую —
     это admin-only endpoint, отдаёт 401 без admin auth, а не 200.
  5. /api/awg/my-peer/config — только если owner_email совпадает.
  6. /api/awg/my-peer/regen — только если owner_email совпадает.
  7. Валидация имени пира: path traversal блокируется (../../etc/passwd и т.п.).
  8. owner_email не попадает в JSON-ответы вместе с client_privkey (приватные
     ключи никогда не отдаются в JSON).

Запуск:
  cd <repo-root>
  python3 -m pytest tests/test_awg_rest_api.py -v
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ── Подготовка пути для импорта ────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """
    Загружает _core.py через exec (как full_test.py) и регистрирует в
    sys.modules['vless_installer._core'], чтобы lazy-импорты в awg-модулях
    работали. Возвращает module object.
    """
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
    return fake_core, g


class _MockHandler:
    """
    Упрощённый mock _VLESSHandler для тестирования awg_rest_api хендлеров.
    Записывает send_response/send_header/end_headers/wfile.write вызовы.
    """
    def __init__(self, admin_authed=False, user=None):
        self._admin_authed = admin_authed
        self._user = user  # dict или None
        self.status = None
        self.headers = {}
        self.body = b""
        self._headers_sent = False

    # Auth methods (как в rest_api._VLESSHandler)
    def _check_admin_auth(self):
        return self._admin_authed

    def _require_admin(self, realm="Admin"):
        if not self._admin_authed:
            self._send_json({"error": "Unauthorized"}, 401)
            return False
        return True

    def _check_user_auth(self):
        return self._user

    def _require_user(self):
        if self._user is None:
            self._send_json({"error": "Unauthorized"}, 401)
            return None
        return self._user

    # Response methods
    def _send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.status = status
        self.headers["Content-Type"] = "application/json; charset=utf-8"
        self.headers["Content-Length"] = str(len(body))
        self.body = body

    def _send_404(self):
        self._send_json({"error": "Not found"}, 404)

    def send_response(self, status, *args, **kwargs):
        self.status = status

    def send_header(self, key, value):
        self.headers[key] = value

    def end_headers(self):
        self._headers_sent = True

    @property
    def wfile(self):
        writer = MagicMock()
        writer.write = lambda data: setattr(self, 'body', data if isinstance(data, bytes) else data.encode())
        return writer

    def _get_json_body(self):
        """Парсит self.body как JSON (для assert'ов)."""
        try:
            return json.loads(self.body)
        except Exception:
            return {}


class TestAWGRestAPIAwgNotInstalled(unittest.TestCase):
    """Все /api/awg/* отдают 404 если AWG не установлен."""

    def setUp(self):
        _setup_core_in_sysmodules()
        # Патчим awgs_state_is_installed → False
        self._patch1 = patch("vless_installer.modules.awg_rest_api._is_awg_installed", return_value=False)
        self._patch1.start()

    def tearDown(self):
        self._patch1.stop()

    def test_get_status_404_when_not_installed(self):
        from vless_installer.modules import awg_rest_api
        h = _MockHandler(admin_authed=True)
        awg_rest_api.awg_handle_get(h, "/api/awg/status", {})
        self.assertEqual(h.status, 404)

    def test_get_peers_404_when_not_installed(self):
        from vless_installer.modules import awg_rest_api
        h = _MockHandler(admin_authed=True)
        awg_rest_api.awg_handle_get(h, "/api/awg/peers", {})
        self.assertEqual(h.status, 404)

    def test_post_peer_404_when_not_installed(self):
        from vless_installer.modules import awg_rest_api
        h = _MockHandler(admin_authed=True)
        awg_rest_api.awg_handle_post(h, "/api/awg/peers", {"name": "test"})
        self.assertEqual(h.status, 404)

    def test_delete_peer_404_when_not_installed(self):
        from vless_installer.modules import awg_rest_api
        h = _MockHandler(admin_authed=True)
        awg_rest_api.awg_handle_delete(h, "/api/awg/peers/test")
        self.assertEqual(h.status, 404)

    def test_patch_peer_404_when_not_installed(self):
        from vless_installer.modules import awg_rest_api
        h = _MockHandler(admin_authed=True)
        awg_rest_api.awg_handle_patch(h, "/api/awg/peers/test", {"param": "dns1", "value": "1.1.1.1"})
        self.assertEqual(h.status, 404)

    def test_my_peer_404_when_not_installed(self):
        from vless_installer.modules import awg_rest_api
        h = _MockHandler(user={"email": "alice@example.com"})
        awg_rest_api.awg_handle_get(h, "/api/awg/my-peer", {})
        self.assertEqual(h.status, 404)


class TestAWGRestAPIAdminAuth(unittest.TestCase):
    """ADMIN endpoints требуют admin auth."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._patch1 = patch("vless_installer.modules.awg_rest_api._is_awg_installed", return_value=True)
        self._patch1.start()
        # Мокаем awgs_state_load / awgs_service_status чтобы не падало
        self._patch2 = patch("vless_installer.modules.awg_state.awgs_state_load",
                             return_value={"installed": True, "peers": [], "interface": "awg0"})
        self._patch2.start()
        self._patch3 = patch("vless_installer.modules.awg_state.awgs_state_is_installed", return_value=True)
        self._patch3.start()

    def tearDown(self):
        self._patch1.stop()
        self._patch2.stop()
        self._patch3.stop()

    def test_status_401_without_admin_auth(self):
        from vless_installer.modules import awg_rest_api
        h = _MockHandler(admin_authed=False)
        awg_rest_api.awg_handle_get(h, "/api/awg/status", {})
        self.assertEqual(h.status, 401)

    def test_peers_401_without_admin_auth(self):
        from vless_installer.modules import awg_rest_api
        h = _MockHandler(admin_authed=False)
        awg_rest_api.awg_handle_get(h, "/api/awg/peers", {})
        self.assertEqual(h.status, 401)

    def test_post_peer_401_without_admin_auth(self):
        from vless_installer.modules import awg_rest_api
        h = _MockHandler(admin_authed=False)
        awg_rest_api.awg_handle_post(h, "/api/awg/peers", {"name": "test"})
        self.assertEqual(h.status, 401)

    def test_delete_peer_401_without_admin_auth(self):
        from vless_installer.modules import awg_rest_api
        h = _MockHandler(admin_authed=False)
        awg_rest_api.awg_handle_delete(h, "/api/awg/peers/test")
        self.assertEqual(h.status, 401)

    def test_patch_peer_401_without_admin_auth(self):
        from vless_installer.modules import awg_rest_api
        h = _MockHandler(admin_authed=False)
        awg_rest_api.awg_handle_patch(h, "/api/awg/peers/test", {"param": "dns1", "value": "1.1.1.1"})
        self.assertEqual(h.status, 401)

    def test_peer_config_401_without_admin_auth(self):
        """User НЕ может запросить /api/awg/peers/{name}/config напрямую.

        Это admin-only endpoint. Без admin auth → 401 (не 200, не 403).
        Это и есть негативный кейс: user пытается достучаться до admin endpoint.
        """
        from vless_installer.modules import awg_rest_api
        h = _MockHandler(admin_authed=False)
        awg_rest_api.awg_handle_get(h, "/api/awg/peers/alice/config", {})
        self.assertEqual(h.status, 401)

    def test_peer_qr_401_without_admin_auth(self):
        from vless_installer.modules import awg_rest_api
        h = _MockHandler(admin_authed=False)
        awg_rest_api.awg_handle_get(h, "/api/awg/peers/alice/qr", {})
        self.assertEqual(h.status, 401)

    def test_stats_401_without_admin_auth(self):
        from vless_installer.modules import awg_rest_api
        h = _MockHandler(admin_authed=False)
        awg_rest_api.awg_handle_get(h, "/api/awg/stats", {})
        self.assertEqual(h.status, 401)


class TestAWGRestAPIStatsNoSecretLeak(unittest.TestCase):
    """Регрессионный тест: /api/awg/stats НЕ должен утекать секреты.

    До фикса этот endpoint возвращал "raw_dump": dump — необработанный вывод
    `awg show all dump`, формат которого:
      interface-строка: interface\t<server_privkey>\tport\t...
      peer-строка:      peer\t<pubkey>\t<psk>\tendpoint\tallowed_ips\thandshake\trx\ttx
    raw_dump содержал приватный ключ сервера (поле 1 interface-строки) и
    PSK каждого пира (поле 2 peer-строки) — прямая утечка боевых секретов
    через JSON API, нарушающая инвариант модуля ("приватные ключи никогда
    не попадают в JSON-ответы").

    Фикс: raw_dump полностью убран из ответа. Фронтенду он не нужен —
    там уже есть распарсенные "peers" со статистикой.

    Этот тест собирает fake dump с заведомо узнаваемыми значениями
    (SERVER_PRIVKEY_MUST_NOT_LEAK, PSK_MUST_NOT_LEAK) и проверяет что
    они НЕ встречаются нигде в JSON-ответе.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._patch1 = patch("vless_installer.modules.awg_rest_api._is_awg_installed",
                             return_value=True)
        self._patch1.start()

    def tearDown(self):
        self._patch1.stop()

    def _build_fake_dump_with_secrets(self):
        """
        Собирает fake `awg show all dump` с узнаваемыми секретами.

        Формат (tab-separated):
          interface\t<privkey>\t<port>\t...
          peer\t<pubkey>\t<psk>\t<endpoint>\t<allowed_ips>\t<handshake>\t<rx>\t<tx>

        ВАЖНО: используем заведомо узнаваемые строки-маркеры для секретов,
        чтобы assertNotIn однозначно ловил утечку.
        """
        return [
            # interface-строка: поле 1 = приватный ключ сервера
            "interface\tSERVER_PRIVKEY_MUST_NOT_LEAK\t51820\tawg0",
            # peer-строка: поле 2 = PSK пира
            "peer\talice_pubkey\tPSK_MUST_NOT_LEAK\t1.2.3.4:54321\t10.66.66.2/32\t1700000000\t1024\t2048",
        ]

    def test_stats_response_does_not_contain_server_privkey(self):
        """JSON-ответ /api/awg/stats не содержит server_privkey."""
        from vless_installer.modules import awg_rest_api
        fake_dump = self._build_fake_dump_with_secrets()
        # peers из state — нужны для матчинга по pubkey в _parse_peer_stats
        fake_peers = [{
            "name": "alice",
            "client_pubkey": "alice_pubkey",
            "client_privkey": "irrelevant",
            "client_ip": "10.66.66.2",
        }]
        with patch("vless_installer.modules.awg_apply.awgs_show_dump",
                   return_value=fake_dump), \
             patch("vless_installer.modules.awg_state.awgs_state_peers_get",
                   return_value=fake_peers):
            h = _MockHandler(admin_authed=True)
            awg_rest_api.awg_handle_get(h, "/api/awg/stats", {})
            self.assertEqual(h.status, 200)
            # Сериализуем весь ответ в строку и проверяем отсутствие секрета
            response_str = json.dumps(h._get_json_body(), ensure_ascii=False)
            self.assertNotIn("SERVER_PRIVKEY_MUST_NOT_LEAK", response_str,
                             "Приватный ключ сервера утёк в /api/awg/stats. "
                             "raw_dump должен быть убран из ответа.")

    def test_stats_response_does_not_contain_psk(self):
        """JSON-ответ /api/awg/stats не содержит PSK пира."""
        from vless_installer.modules import awg_rest_api
        fake_dump = self._build_fake_dump_with_secrets()
        fake_peers = [{
            "name": "alice",
            "client_pubkey": "alice_pubkey",
            "client_privkey": "irrelevant",
            "client_ip": "10.66.66.2",
        }]
        with patch("vless_installer.modules.awg_apply.awgs_show_dump",
                   return_value=fake_dump), \
             patch("vless_installer.modules.awg_state.awgs_state_peers_get",
                   return_value=fake_peers):
            h = _MockHandler(admin_authed=True)
            awg_rest_api.awg_handle_get(h, "/api/awg/stats", {})
            self.assertEqual(h.status, 200)
            response_str = json.dumps(h._get_json_body(), ensure_ascii=False)
            self.assertNotIn("PSK_MUST_NOT_LEAK", response_str,
                             "PSK пира утёк в /api/awg/stats. "
                             "raw_dump должен быть убран из ответа.")

    def test_stats_response_does_not_contain_raw_dump_key(self):
        """В JSON-ответе нет ключа 'raw_dump' вообще."""
        from vless_installer.modules import awg_rest_api
        fake_dump = self._build_fake_dump_with_secrets()
        fake_peers = [{
            "name": "alice",
            "client_pubkey": "alice_pubkey",
            "client_privkey": "irrelevant",
            "client_ip": "10.66.66.2",
        }]
        with patch("vless_installer.modules.awg_apply.awgs_show_dump",
                   return_value=fake_dump), \
             patch("vless_installer.modules.awg_state.awgs_state_peers_get",
                   return_value=fake_peers):
            h = _MockHandler(admin_authed=True)
            awg_rest_api.awg_handle_get(h, "/api/awg/stats", {})
            self.assertEqual(h.status, 200)
            data = h._get_json_body()
            self.assertNotIn("raw_dump", data,
                             "Ключ 'raw_dump' не должен присутствовать в ответе "
                             "/api/awg/stats — он содержит необработанный вывод "
                             "awg show dump с секретами.")

    def test_stats_response_contains_parsed_peers_without_secrets(self):
        """JSON-ответ содержит распарсенные peers со статистикой, но без секретов.

        Проверка что после фикса endpoint всё ещё отдаёт полезную статистику
        (rx_bytes, tx_bytes, handshake, endpoint) — просто без raw_dump.
        """
        from vless_installer.modules import awg_rest_api
        fake_dump = self._build_fake_dump_with_secrets()
        fake_peers = [{
            "name": "alice",
            "client_pubkey": "alice_pubkey",
            "client_privkey": "irrelevant",
            "client_ip": "10.66.66.2",
        }]
        with patch("vless_installer.modules.awg_apply.awgs_show_dump",
                   return_value=fake_dump), \
             patch("vless_installer.modules.awg_state.awgs_state_peers_get",
                   return_value=fake_peers):
            h = _MockHandler(admin_authed=True)
            awg_rest_api.awg_handle_get(h, "/api/awg/stats", {})
            self.assertEqual(h.status, 200)
            data = h._get_json_body()
            # peers должен быть в ответе
            self.assertIn("peers", data)
            self.assertEqual(len(data["peers"]), 1)
            peer_stat = data["peers"][0]
            self.assertEqual(peer_stat["name"], "alice")
            self.assertEqual(peer_stat["rx_bytes"], 1024)
            self.assertEqual(peer_stat["tx_bytes"], 2048)
            # Секретов быть не должно
            response_str = json.dumps(data, ensure_ascii=False)
            self.assertNotIn("SERVER_PRIVKEY_MUST_NOT_LEAK", response_str)
            self.assertNotIn("PSK_MUST_NOT_LEAK", response_str)

    def test_peers_endpoint_also_does_not_leak_secrets(self):
        """Дополнительно: /api/awg/peers тоже не утекает секреты из dump.

        /api/awg/peers парсит dump через _parse_peer_stats (который извлекает
        только rx/tx/handshake/endpoint), но проверим что raw dump не попадает
        в ответ случайно (например через debug-поле).
        """
        from vless_installer.modules import awg_rest_api
        fake_dump = self._build_fake_dump_with_secrets()
        fake_peers = [{
            "name": "alice",
            "client_pubkey": "alice_pubkey",
            "client_privkey": "irrelevant",
            "client_ip": "10.66.66.2",
            "owner_email": "",
            "expires_at": "",
        }]
        with patch("vless_installer.modules.awg_apply.awgs_show_dump",
                   return_value=fake_dump), \
             patch("vless_installer.modules.awg_state.awgs_state_peers_get",
                   return_value=fake_peers), \
             patch("vless_installer.modules.awg_state.awgs_state_ensure_peer_owner_field"):
            h = _MockHandler(admin_authed=True)
            awg_rest_api.awg_handle_get(h, "/api/awg/peers", {})
            self.assertEqual(h.status, 200)
            response_str = json.dumps(h._get_json_body(), ensure_ascii=False)
            self.assertNotIn("SERVER_PRIVKEY_MUST_NOT_LEAK", response_str,
                             "Приватный ключ сервера не должен утекать в /api/awg/peers")
            self.assertNotIn("PSK_MUST_NOT_LEAK", response_str,
                             "PSK не должен утекать в /api/awg/peers")


class TestAWGRestAPIPeerNameValidation(unittest.TestCase):
    """Валидация имени пира: path traversal блокируется."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._patch1 = patch("vless_installer.modules.awg_rest_api._is_awg_installed", return_value=True)
        self._patch1.start()

    def tearDown(self):
        self._patch1.stop()

    def test_path_traversal_in_config_blocked(self):
        """Имя пира с ../ не проходит валидацию → 400, не 500/200."""
        from vless_installer.modules import awg_rest_api
        h = _MockHandler(admin_authed=True)
        # path уже спарсен rest_api; хендлер получает имя из regex
        # Симулируем что regex в awg_rest_api matched "etc/passwd" (без ..)
        # но _validate_peer_name его отклонит
        awg_rest_api.awg_handle_get(h, "/api/awg/peers/..%2F..%2Fetc%2Fpasswd/config", {})
        # regex [^/]+ не сматчит %2F как /, но если он прошёл — валидация имени
        # должна дать 400
        # Если regex не сматчил — handler вернёт False (не наш путь) → status=None
        # В любом случае НЕ должно быть 200 или 500
        self.assertIn(h.status, (None, 400, 404))

    def test_invalid_peer_name_rejected(self):
        """Имя начинающееся с цифры отклоняется."""
        from vless_installer.modules import awg_rest_api
        # Проверяем напрямую _validate_peer_name
        self.assertFalse(awg_rest_api._validate_peer_name("123abc"))
        self.assertFalse(awg_rest_api._validate_peer_name(""))
        self.assertFalse(awg_rest_api._validate_peer_name("a" * 33))  # >32 символов
        self.assertFalse(awg_rest_api._validate_peer_name("test!"))
        self.assertFalse(awg_rest_api._validate_peer_name("test space"))
        # Валидные
        self.assertTrue(awg_rest_api._validate_peer_name("alice"))
        self.assertTrue(awg_rest_api._validate_peer_name("alice_01"))
        self.assertTrue(awg_rest_api._validate_peer_name("peer-1"))

    def test_path_traversal_name_rejected_by_validator(self):
        """Имена с / .. и т.п. не проходят _validate_peer_name."""
        from vless_installer.modules import awg_rest_api
        self.assertFalse(awg_rest_api._validate_peer_name("../etc/passwd"))
        self.assertFalse(awg_rest_api._validate_peer_name("a/b"))
        self.assertFalse(awg_rest_api._validate_peer_name(".."))
        self.assertFalse(awg_rest_api._validate_peer_name("."))


class TestAWGRestAPIUserEndpoints(unittest.TestCase):
    """USER endpoints — my-peer, my-peer/config, my-peer/qr, my-peer/regen."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._patch1 = patch("vless_installer.modules.awg_rest_api._is_awg_installed", return_value=True)
        self._patch1.start()

    def tearDown(self):
        self._patch1.stop()

    def test_my_peer_401_without_user_auth(self):
        from vless_installer.modules import awg_rest_api
        h = _MockHandler(user=None)
        awg_rest_api.awg_handle_get(h, "/api/awg/my-peer", {})
        self.assertEqual(h.status, 401)

    def test_my_peer_returns_null_when_no_peer(self):
        """Если у юзера нет привязанного пира — {"peer": null}, 200."""
        from vless_installer.modules import awg_rest_api
        with patch("vless_installer.modules.awg_state.awgs_state_find_peer_by_owner",
                   return_value=None):
            h = _MockHandler(user={"email": "alice@example.com"})
            awg_rest_api.awg_handle_get(h, "/api/awg/my-peer", {})
            self.assertEqual(h.status, 200)
            data = h._get_json_body()
            self.assertIsNone(data.get("peer"))

    def test_my_peer_config_404_when_no_peer(self):
        from vless_installer.modules import awg_rest_api
        with patch("vless_installer.modules.awg_state.awgs_state_find_peer_by_owner",
                   return_value=None):
            h = _MockHandler(user={"email": "alice@example.com"})
            awg_rest_api.awg_handle_get(h, "/api/awg/my-peer/config", {})
            self.assertEqual(h.status, 404)

    def test_my_peer_regen_404_when_no_peer(self):
        from vless_installer.modules import awg_rest_api
        with patch("vless_installer.modules.awg_state.awgs_state_find_peer_by_owner",
                   return_value=None):
            h = _MockHandler(user={"email": "alice@example.com"})
            awg_rest_api.awg_handle_post(h, "/api/awg/my-peer/regen", {})
            self.assertEqual(h.status, 404)

    def test_my_peer_returns_safe_peer_without_privkey(self):
        """my-peer отдаёт пира БЕЗ client_privkey И preshared_key (секреты не утекают)."""
        from vless_installer.modules import awg_rest_api
        fake_peer = {
            "name": "alice",
            "client_privkey": "SECRET_PRIVATE_KEY_MUST_NOT_LEAK",
            "preshared_key": "SECRET_PSK_MUST_NOT_LEAK",
            "client_pubkey": "pubkey123",
            "client_ip": "10.66.66.2",
            "owner_email": "alice@example.com",
            "expires_at": "",
        }
        with patch("vless_installer.modules.awg_state.awgs_state_find_peer_by_owner",
                   return_value=fake_peer), \
             patch("vless_installer.modules.awg_apply.awgs_show_dump", return_value=[]):
            h = _MockHandler(user={"email": "alice@example.com"})
            awg_rest_api.awg_handle_get(h, "/api/awg/my-peer", {})
            self.assertEqual(h.status, 200)
            data = h._get_json_body()
            peer = data.get("peer", {})
            self.assertNotIn("client_privkey", peer,
                             "Приватный ключ не должен попадать в JSON-ответ")
            self.assertNotIn("preshared_key", peer,
                             "PSK не должен попадать в JSON-ответ (регрессионный тест)")
            self.assertEqual(peer.get("name"), "alice")
            self.assertEqual(peer.get("client_pubkey"), "pubkey123")


class TestAWGRestAPISafePeerForJson(unittest.TestCase):
    """_safe_peer_for_json убирает приватные ключи и PSK."""

    def test_safe_peer_strips_client_privkey(self):
        from vless_installer.modules import awg_rest_api
        peer = {
            "name": "alice",
            "client_privkey": "SECRET",
            "client_pubkey": "pub",
            "client_ip": "10.66.66.2",
            "owner_email": "alice@example.com",
        }
        safe = awg_rest_api._safe_peer_for_json(peer)
        self.assertNotIn("client_privkey", safe)
        self.assertEqual(safe.get("client_pubkey"), "pub")
        self.assertEqual(safe.get("owner_email"), "alice@example.com")

    def test_safe_peer_strips_preshared_key(self):
        """preshared_key (PSK) НЕ должен попадать в JSON-ответы API.

        Регрессионный тест на баг из ревью: _safe_peer_for_json фильтровал
        только client_privkey, но PSK утекал в GET /api/awg/peers и
        /api/awg/my-peer. PSK — боевой секрет (дополнительный симметричный
        ключ для post-quantum resistance), утечка ослабляет туннель.
        """
        from vless_installer.modules import awg_rest_api
        peer = {
            "name": "alice",
            "client_privkey": "SECRET_PRIV",
            "client_pubkey": "pub",
            "preshared_key": "SECRET_PSK_MUST_NOT_LEAK",
            "client_ip": "10.66.66.2",
            "owner_email": "alice@example.com",
        }
        safe = awg_rest_api._safe_peer_for_json(peer)
        self.assertNotIn("client_privkey", safe,
                         "Приватный ключ не должен попадать в JSON")
        self.assertNotIn("preshared_key", safe,
                         "PSK не должен попадать в JSON (регрессионный тест)")
        # Остальные поля сохраняются
        self.assertEqual(safe.get("client_pubkey"), "pub")
        self.assertEqual(safe.get("owner_email"), "alice@example.com")
        self.assertEqual(safe.get("name"), "alice")

    def test_safe_peer_strips_server_privkey_if_present(self):
        """server_privkey (если бы оказался в peer) тоже фильтруется."""
        from vless_installer.modules import awg_rest_api
        peer = {
            "name": "alice",
            "server_privkey": "SERVER_SECRET",
            "client_pubkey": "pub",
        }
        safe = awg_rest_api._safe_peer_for_json(peer)
        self.assertNotIn("server_privkey", safe)

    def test_safe_peer_handles_empty(self):
        from vless_installer.modules import awg_rest_api
        self.assertEqual(awg_rest_api._safe_peer_for_json({}), {})
        self.assertEqual(awg_rest_api._safe_peer_for_json(None), {})


class TestAWGStateOwnerEmailMigration(unittest.TestCase):
    """Миграция: awgs_state_ensure_peer_owner_field добавляет owner_email."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ensure_owner_field_adds_missing(self):
        from vless_installer.modules import awg_state
        with patch("vless_installer.modules.awg_state.awgs_state_load",
                   return_value={"peers": [
                       {"name": "alice", "client_privkey": "x"},  # без owner_email
                       {"name": "bob", "owner_email": "bob@ex.com"},  # уже есть
                   ]}), \
             patch("vless_installer.modules.awg_state.awgs_state_save") as mock_save:
            awg_state.awgs_state_ensure_peer_owner_field()
            mock_save.assert_called_once()
            saved_state = mock_save.call_args.args[0]
            peers = saved_state["peers"]
            self.assertEqual(peers[0].get("owner_email"), "")
            self.assertEqual(peers[1].get("owner_email"), "bob@ex.com")

    def test_ensure_owner_field_idempotent_when_all_have_it(self):
        from vless_installer.modules import awg_state
        with patch("vless_installer.modules.awg_state.awgs_state_load",
                   return_value={"peers": [
                       {"name": "alice", "owner_email": "a@ex.com"},
                   ]}), \
             patch("vless_installer.modules.awg_state.awgs_state_save") as mock_save:
            awg_state.awgs_state_ensure_peer_owner_field()
            mock_save.assert_not_called()  # ничего не меняли — не сохраняем

    def test_find_peer_by_owner_returns_correct_peer(self):
        from vless_installer.modules import awg_state
        peers = [
            {"name": "alice", "owner_email": "alice@ex.com"},
            {"name": "bob", "owner_email": "bob@ex.com"},
            {"name": "tech", "owner_email": ""},  # технический
        ]
        with patch("vless_installer.modules.awg_state.awgs_state_peers_get",
                   return_value=peers):
            self.assertEqual(awg_state.awgs_state_find_peer_by_owner("alice@ex.com")["name"], "alice")
            self.assertEqual(awg_state.awgs_state_find_peer_by_owner("bob@ex.com")["name"], "bob")
            self.assertIsNone(awg_state.awgs_state_find_peer_by_owner("nobody@ex.com"))
            self.assertIsNone(awg_state.awgs_state_find_peer_by_owner(""))


class TestAWGPeerAddOwnerEmail(unittest.TestCase):
    """awg_peer_add принимает и сохраняет owner_email."""

    def setUp(self):
        _setup_core_in_sysmodules()
        # Мокаем все внешние вызовы awg_peer_add
        self._patches = [
            patch("vless_installer.modules.awg_peers.awgs_state_peer_find", return_value=None),
            patch("vless_installer.modules.awg_peers.awgs_generate_keys",
                  return_value=("priv", "pub")),
            patch("vless_installer.modules.awg_peers.awgs_state_next_ip",
                  return_value="10.66.66.5"),
            patch("vless_installer.modules.awg_peers.awgs_state_load",
                  return_value={"allow_ipv6_tunnel": False}),
            patch("vless_installer.modules.awg_peers.awgs_state_peer_add", return_value=True),
            patch("vless_installer.modules.awg_peers.awg_peer_rebuild_conf", return_value=True),
            patch("vless_installer.modules.awg_peers.awgs_qr_export_peer",
                  return_value={"conf_path": "/tmp/x.conf"}),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()

    def test_add_with_owner_email_saves_it(self):
        from vless_installer.modules import awg_peers
        ok = awg_peers.awg_peer_add(
            name="alice",
            expires="",
            psk=False,
            apply=False,
            save_state=True,
            show_qr=False,
            owner_email="alice@example.com",
        )
        self.assertTrue(ok)
        # Проверяем что awgs_state_peer_add получил пира с owner_email
        from vless_installer.modules import awg_peers
        peer_arg = awg_peers.awgs_state_peer_add.call_args.args[0]
        self.assertEqual(peer_arg.get("owner_email"), "alice@example.com")

    def test_add_without_owner_email_defaults_empty(self):
        from vless_installer.modules import awg_peers
        ok = awg_peers.awg_peer_add(
            name="tech",
            expires="",
            psk=False,
            apply=False,
            save_state=True,
            show_qr=False,
            # owner_email не передаём
        )
        self.assertTrue(ok)
        peer_arg = awg_peers.awgs_state_peer_add.call_args.args[0]
        self.assertEqual(peer_arg.get("owner_email"), "")

    def test_add_with_invalid_email_fails(self):
        from vless_installer.modules import awg_peers
        ok = awg_peers.awg_peer_add(
            name="bad",
            expires="",
            psk=False,
            apply=False,
            save_state=True,
            show_qr=False,
            owner_email="not-an-email",
        )
        self.assertFalse(ok)


class TestAWGPeerModifyOwnerEmail(unittest.TestCase):
    """awg_peer_modify поддерживает owner_email."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_modify_owner_email_valid(self):
        from vless_installer.modules import awg_peers
        with patch("vless_installer.modules.awg_peers.awgs_state_peer_find",
                   return_value={"name": "alice", "owner_email": ""}), \
             patch("vless_installer.modules.awg_peers.awgs_state_peer_update", return_value=True) as mock_up, \
             patch("vless_installer.modules.awg_peers.awgs_qr_export_peer"):
            ok = awg_peers.awg_peer_modify("alice", "owner_email", "alice@new.com")
            self.assertTrue(ok)
            mock_up.assert_called_once_with("alice", owner_email="alice@new.com")

    def test_modify_owner_email_empty_unbinds(self):
        from vless_installer.modules import awg_peers
        with patch("vless_installer.modules.awg_peers.awgs_state_peer_find",
                   return_value={"name": "alice", "owner_email": "old@ex.com"}), \
             patch("vless_installer.modules.awg_peers.awgs_state_peer_update", return_value=True) as mock_up, \
             patch("vless_installer.modules.awg_peers.awgs_qr_export_peer"):
            ok = awg_peers.awg_peer_modify("alice", "owner_email", "")
            self.assertTrue(ok)
            mock_up.assert_called_once_with("alice", owner_email="")

    def test_modify_owner_email_invalid_fails(self):
        from vless_installer.modules import awg_peers
        with patch("vless_installer.modules.awg_peers.awgs_state_peer_find",
                   return_value={"name": "alice", "owner_email": ""}), \
             patch("vless_installer.modules.awg_peers.awgs_state_peer_update") as mock_up:
            ok = awg_peers.awg_peer_modify("alice", "owner_email", "not-an-email")
            self.assertFalse(ok)
            mock_up.assert_not_called()


class TestValidateEmail(unittest.TestCase):
    """_validate_email: пустая строка допустима, невалидные — нет."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_email_valid(self):
        from vless_installer.modules import awg_peers
        self.assertTrue(awg_peers._validate_email(""))

    def test_valid_emails(self):
        from vless_installer.modules import awg_peers
        self.assertTrue(awg_peers._validate_email("alice@example.com"))
        self.assertTrue(awg_peers._validate_email("bob.user@sub.domain.org"))
        self.assertTrue(awg_peers._validate_email("user+tag@ex.com"))

    def test_invalid_emails(self):
        from vless_installer.modules import awg_peers
        self.assertFalse(awg_peers._validate_email("not-an-email"))
        self.assertFalse(awg_peers._validate_email("@example.com"))
        self.assertFalse(awg_peers._validate_email("user@"))
        self.assertFalse(awg_peers._validate_email("user@example"))  # без точки в домене
        self.assertFalse(awg_peers._validate_email("user name@example.com"))  # пробел


class TestUserCannotRegenOthersPeer(unittest.TestCase):
    """Негативный кейс: user пытается regen чужого пира через /api/awg/peers/{name}/regen."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._patch1 = patch("vless_installer.modules.awg_rest_api._is_awg_installed", return_value=True)
        self._patch1.start()

    def tearDown(self):
        self._patch1.stop()

    def test_user_regen_others_peer_returns_404(self):
        """User Alice пытается regen пира Bob (owner_email=bob@ex.com).
        Должно быть 404 (не раскрываем существование чужого пира), не 200."""
        from vless_installer.modules import awg_rest_api
        bob_peer = {"name": "bob", "owner_email": "bob@example.com"}
        with patch("vless_installer.modules.awg_state.awgs_state_peer_find",
                   return_value=bob_peer):
            # Alice authed as user, not admin
            h = _MockHandler(admin_authed=False, user={"email": "alice@example.com"})
            awg_rest_api.awg_handle_post(h, "/api/awg/peers/bob/regen", {})
            # Должно быть 404 (не 200, не 403 — не раскрываем существование)
            self.assertEqual(h.status, 404)

    def test_admin_regen_any_peer_ok(self):
        """Админ может regen любой пир."""
        from vless_installer.modules import awg_rest_api
        bob_peer = {"name": "bob", "owner_email": "bob@example.com"}
        with patch("vless_installer.modules.awg_state.awgs_state_peer_find",
                   return_value=bob_peer), \
             patch("vless_installer.modules.awg_peers.awg_peer_regen", return_value=True):
            h = _MockHandler(admin_authed=True)
            awg_rest_api.awg_handle_post(h, "/api/awg/peers/bob/regen", {})
            self.assertEqual(h.status, 200)
            data = h._get_json_body()
            self.assertEqual(data.get("status"), "regenerated")

    def test_user_regen_own_peer_ok(self):
        """User Alice может regen свой пир."""
        from vless_installer.modules import awg_rest_api
        alice_peer = {"name": "alice", "owner_email": "alice@example.com"}
        with patch("vless_installer.modules.awg_state.awgs_state_peer_find",
                   return_value=alice_peer), \
             patch("vless_installer.modules.awg_peers.awg_peer_regen", return_value=True):
            h = _MockHandler(admin_authed=False, user={"email": "alice@example.com"})
            awg_rest_api.awg_handle_post(h, "/api/awg/peers/alice/regen", {})
            self.assertEqual(h.status, 200)


class TestUserCannotAccessAdminEndpoints(unittest.TestCase):
    """Негативный кейс: user пытается DELETE/PATCH чужого пира (admin-only)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._patch1 = patch("vless_installer.modules.awg_rest_api._is_awg_installed", return_value=True)
        self._patch1.start()

    def tearDown(self):
        self._patch1.stop()

    def test_user_delete_peer_401(self):
        """DELETE /api/awg/peers/{name} — admin-only. User → 401."""
        from vless_installer.modules import awg_rest_api
        # _MockHandler с admin_authed=False но user=set — _require_admin вернёт 401
        h = _MockHandler(admin_authed=False, user={"email": "alice@example.com"})
        awg_rest_api.awg_handle_delete(h, "/api/awg/peers/alice")
        self.assertEqual(h.status, 401)

    def test_user_patch_peer_401(self):
        """PATCH /api/awg/peers/{name} — admin-only. User → 401."""
        from vless_installer.modules import awg_rest_api
        h = _MockHandler(admin_authed=False, user={"email": "alice@example.com"})
        awg_rest_api.awg_handle_patch(h, "/api/awg/peers/alice",
                                       {"param": "owner_email", "value": "hacker@ex.com"})
        self.assertEqual(h.status, 401)


class TestAWGQRPngChmod(unittest.TestCase):
    """П.2: PNG-файлы QR-кодов создаются с chmod 0o600.

    Регрессионный тест: раньше awgs_qr_save_png() не делал chmod, и PNG
    создавался с umask-правами (часто 0o644), что позволяло любому локальному
    юзеру на сервере прочитать приватный ключ + PSK (они закодированы в PNG
    как vpn:// URI). После начала отдачи PNG через REST API это стало
    подтверждённой боевой экспозицией.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_save_png_calls_chmod_600(self):
        """awgs_qr_save_png вызывает path.chmod(0o600) после успешной генерации."""
        import tempfile
        from vless_installer.modules import awg_qr
        from pathlib import Path
        with tempfile.TemporaryDirectory() as td:
            png_path = Path(td) / "test_qr.png"
            # Мокаем _core_module()._run чтобы qrencode "отработал" успешно
            mock_core = MagicMock()
            mock_core._run = MagicMock(
                return_value=MagicMock(returncode=0, stdout="", stderr="")
            )
            with patch.object(awg_qr, "_core_module", return_value=mock_core):
                # Создаём файл чтобы chmod не падал на несуществующем файле
                png_path.write_bytes(b"fake-png-content")
                ok = awg_qr.awgs_qr_save_png("test content", png_path)
            self.assertTrue(ok)
            # Проверяем права — должны быть 0o600
            import os, stat
            mode = stat.S_IMODE(os.stat(png_path).st_mode)
            self.assertEqual(mode, 0o600,
                             f"PNG должен иметь права 0o600, имеет {oct(mode)}")

    def test_save_png_no_chmod_on_failure(self):
        """При неудаче qrencode chmod не вызывается (файла нет)."""
        from vless_installer.modules import awg_qr
        from pathlib import Path
        mock_core = MagicMock()
        mock_core._run = MagicMock(
            return_value=MagicMock(returncode=1, stdout="", stderr="qrencode error")
        )
        with patch.object(awg_qr, "_core_module", return_value=mock_core):
            ok = awg_qr.awgs_qr_save_png("test", Path("/tmp/nonexistent_xyz.png"))
        self.assertFalse(ok)

    def test_save_client_conf_sets_dir_chmod_700(self):
        """awgs_qr_save_client_conf устанавливает AWGS_KEYS_DIR chmod 0o700."""
        import tempfile
        from vless_installer.modules import awg_qr
        from pathlib import Path
        with tempfile.TemporaryDirectory() as td:
            keys_dir = Path(td) / "keys"
            with patch.object(awg_qr, "AWGS_KEYS_DIR", keys_dir), \
                 patch.object(awg_qr, "_core_module",
                              return_value=MagicMock(log_to_file=MagicMock())):
                awg_qr.awgs_qr_save_client_conf(
                    {"name": "alice", "client_privkey": "k", "client_ip": "10.66.66.2"},
                    {"server_pubkey": "pk", "port": 51820, "endpoint": "1.2.3.4",
                     "params": {}, "mtu": 1280, "allow_ipv6_tunnel": False}
                )
            import os, stat
            dir_mode = stat.S_IMODE(os.stat(keys_dir).st_mode)
            self.assertEqual(dir_mode, 0o700,
                             f"AWGS_KEYS_DIR должен иметь права 0o700, имеет {oct(dir_mode)}")
            conf_path = keys_dir / "alice.conf"
            conf_mode = stat.S_IMODE(os.stat(conf_path).st_mode)
            self.assertEqual(conf_mode, 0o600,
                             f".conf должен иметь права 0o600, имеет {oct(conf_mode)}")


class TestAWGQRExportNoPrintInApiMode(unittest.TestCase):
    """П.3: awgs_qr_export_peer(show_terminal=False) не печатает QR в stdout.

    Регрессионный тест на серьёзный баг: при вызове из REST API
    /api/awg/.../qr функция дёргала awgs_qr_show_terminal(), которая делает
    print(r.stdout) — ANSI QR с vpn:// URI (приватный ключ + PSK). Под
    systemd это уходит в journal (journalctl -u vless-web), читаемый любым
    с доступом к journalctl. На каждый просмотр QR юзером приватный ключ
    буквально писался в системный лог.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_export_with_show_terminal_false_does_not_print(self):
        """show_terminal=False → awgs_qr_show_terminal НЕ вызывается."""
        from vless_installer.modules import awg_qr
        peer = {
            "name": "alice",
            "client_privkey": "SECRET",
            "client_pubkey": "pub",
            "client_ip": "10.66.66.2",
            "preshared_key": "PSK_SECRET",
        }
        server_state = {
            "server_pubkey": "srv_pub",
            "port": 51820,
            "endpoint": "1.2.3.4",
            "params": {},
            "mtu": 1280,
            "allow_ipv6_tunnel": False,
        }
        with patch.object(awg_qr, "_core_module",
                          return_value=MagicMock(log_to_file=MagicMock())), \
             patch("vless_installer.modules.awg_state.awgs_state_load",
                   return_value=server_state), \
             patch.object(awg_qr, "AWGS_KEYS_DIR",
                          Path("/tmp/test_awg_qr_keys")), \
             patch.object(awg_qr, "awgs_qr_show_terminal") as mock_show_term, \
             patch.object(awg_qr, "awgs_qr_save_png", return_value=True), \
             patch.object(awg_qr, "awgs_qr_save_client_conf",
                          return_value=Path("/tmp/test.conf")):
            awg_qr.awgs_qr_export_peer(peer, show_terminal=False)
            # awgs_qr_show_terminal НЕ должен вызываться в API-режиме
            mock_show_term.assert_not_called()

    def test_export_with_show_terminal_true_calls_show_terminal(self):
        """show_terminal=True (TUI-режим, default) → awgs_qr_show_terminal вызывается."""
        from vless_installer.modules import awg_qr
        peer = {
            "name": "alice",
            "client_privkey": "SECRET",
            "client_pubkey": "pub",
            "client_ip": "10.66.66.2",
        }
        server_state = {
            "server_pubkey": "srv_pub",
            "port": 51820,
            "endpoint": "1.2.3.4",
            "params": {},
            "mtu": 1280,
            "allow_ipv6_tunnel": False,
        }
        with patch.object(awg_qr, "_core_module",
                          return_value=MagicMock(log_to_file=MagicMock())), \
             patch("vless_installer.modules.awg_state.awgs_state_load",
                   return_value=server_state), \
             patch.object(awg_qr, "AWGS_KEYS_DIR",
                          Path("/tmp/test_awg_qr_keys")), \
             patch.object(awg_qr, "awgs_qr_show_terminal", return_value=True) as mock_show_term, \
             patch.object(awg_qr, "awgs_qr_save_png", return_value=True), \
             patch.object(awg_qr, "awgs_qr_save_client_conf",
                          return_value=Path("/tmp/test.conf")):
            awg_qr.awgs_qr_export_peer(peer, show_terminal=True)
            # awgs_qr_show_terminal ДОЛЖЕН вызываться в TUI-режиме
            mock_show_term.assert_called()

    def test_export_default_is_show_terminal_true(self):
        """Default (без аргумента) = TUI-режим (show_terminal=True) — обратная совместимость."""
        import inspect
        from vless_installer.modules import awg_qr
        sig = inspect.signature(awg_qr.awgs_qr_export_peer)
        self.assertIn("show_terminal", sig.parameters)
        self.assertEqual(sig.parameters["show_terminal"].default, True,
                         "Default show_terminal=True для обратной совместимости с TUI")

    def test_rest_api_qr_endpoint_uses_show_terminal_false(self):
        """REST API /api/awg/peers/{name}/qr передаёт show_terminal=False.

        Интеграционный тест: хендлер REST API не должен дёргать
        awgs_qr_show_terminal (иначе приватный ключ в journal).
        """
        from vless_installer.modules import awg_rest_api
        peer = {"name": "alice", "owner_email": "", "client_privkey": "k",
                "client_pubkey": "pub", "client_ip": "10.66.66.2"}
        with patch("vless_installer.modules.awg_rest_api._is_awg_installed",
                   return_value=True), \
             patch("vless_installer.modules.awg_state.awgs_state_peer_find",
                   return_value=peer), \
             patch("vless_installer.modules.awg_qr.awgs_qr_export_peer") as mock_export, \
             patch("vless_installer.modules.awg_constants.AWGS_KEYS_DIR",
                   Path("/tmp/test_awg_keys")), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_bytes", return_value=b"fake-png"):
            # Создаём mock handler с admin auth
            h = MagicMock()
            h._require_admin = MagicMock(return_value=True)
            h._send_json = MagicMock()
            h.send_response = MagicMock()
            h.send_header = MagicMock()
            h.end_headers = MagicMock()
            h.wfile = MagicMock()
            awg_rest_api.awg_handle_get(h, "/api/awg/peers/alice/qr", {})
            # Проверяем что awgs_qr_export_peer вызван с show_terminal=False
            mock_export.assert_called_once()
            call_kwargs = mock_export.call_args.kwargs
            self.assertIn("show_terminal", call_kwargs,
                          "Хендлер должен явно передавать show_terminal=False")
            self.assertFalse(call_kwargs["show_terminal"],
                             "show_terminal=False — иначе приватный ключ утекает в journal")

    def test_rest_api_my_peer_qr_uses_show_terminal_false(self):
        """REST API /api/awg/my-peer/qr передаёт show_terminal=False."""
        from vless_installer.modules import awg_rest_api
        peer = {"name": "alice", "owner_email": "alice@ex.com",
                "client_privkey": "k", "client_pubkey": "pub",
                "client_ip": "10.66.66.2"}
        with patch("vless_installer.modules.awg_rest_api._is_awg_installed",
                   return_value=True), \
             patch("vless_installer.modules.awg_state.awgs_state_find_peer_by_owner",
                   return_value=peer), \
             patch("vless_installer.modules.awg_qr.awgs_qr_export_peer") as mock_export, \
             patch("vless_installer.modules.awg_constants.AWGS_KEYS_DIR",
                   Path("/tmp/test_awg_keys")), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_bytes", return_value=b"fake-png"):
            h = MagicMock()
            h._require_user = MagicMock(return_value={"email": "alice@ex.com"})
            h._send_json = MagicMock()
            h.send_response = MagicMock()
            h.send_header = MagicMock()
            h.end_headers = MagicMock()
            h.wfile = MagicMock()
            awg_rest_api.awg_handle_get(h, "/api/awg/my-peer/qr", {})
            mock_export.assert_called_once()
            call_kwargs = mock_export.call_args.kwargs
            self.assertIn("show_terminal", call_kwargs)
            self.assertFalse(call_kwargs["show_terminal"],
                             "show_terminal=False для my-peer/qr — иначе ключ в journal")


class TestAWGQREndToEndChmod(unittest.TestCase):
    """E2E тест: GET /api/awg/peers/{name}/qr реально генерирует PNG с chmod 0o600.

    В отличие от TestAWGQRPngChmod (который тестирует awgs_qr_save_png изолированно)
    и TestAWGQRExportNoPrintInApiMode (который мокает awgs_qr_export_peer целиком),
    этот тест идёт через ВЕСЬ стек: awg_handle_get → awgs_qr_export_peer (реальный)
    → awgs_qr_save_png (реальный) → qrencode (замокан на уровне core._run, но с
    side-effect создания файла) → chmod (реальный на реальном файле).

    Цель: убедиться что end-to-end путь от HTTP-запроса до файла на диске
    создаёт PNG с правами 0o600, а не просто что какой-то изолированный вызов
    chmod работает.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp(prefix="awg_e2e_test_")
        self._keys_dir = Path(self._tmpdir) / "keys"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_mock_core_with_qrencode(self):
        """
        Создаёт mock core, где _run эмулирует qrencode:
          • `which qrencode` → returncode=0 (как будто установлен)
          • `qrencode -t PNG -o {path}` → создаёт реальный PNG-файл (fake bytes),
            returncode=0. Это позволяет chmod отработать на реальном файле.
          • `qrencode -t ANSIUTF8 -o -` → returncode=0, stdout пустой (не печатаем)
          • прочие вызовы → returncode=0
        """
        def _fake_run(args, **kwargs):
            # args — список аргументов команды
            if not args:
                return MagicMock(returncode=0, stdout="", stderr="")
            cmd = args[0]
            if cmd == "which" and len(args) > 1 and args[1] == "qrencode":
                return MagicMock(returncode=0, stdout="/usr/bin/qrencode", stderr="")
            if cmd == "qrencode":
                # qrencode -t PNG -o {path} — нужно создать файл
                if "-t" in args and "PNG" in args and "-o" in args:
                    try:
                        out_idx = args.index("-o")
                        out_path = args[out_idx + 1] if out_idx + 1 < len(args) else None
                        if out_path:
                            # Создаём реальный файл (fake PNG content)
                            Path(out_path).parent.mkdir(parents=True, exist_ok=True)
                            Path(out_path).write_bytes(b"\x89PNG\r\n\x1a\n fake PNG content")
                    except Exception:
                        pass
                    return MagicMock(returncode=0, stdout="", stderr="")
                # qrencode -t ANSIUTF8 -o - (для terminal) — возвращаем пустой stdout
                if "-t" in args and "ANSIUTF8" in args:
                    return MagicMock(returncode=0, stdout="", stderr="")
            # Прочие команды — успех
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_core = MagicMock()
        mock_core._run = MagicMock(side_effect=_fake_run)
        mock_core.log_to_file = MagicMock()
        mock_core.warn = MagicMock()
        mock_core.info = MagicMock()
        mock_core.CYAN = ""
        mock_core.NC = ""
        return mock_core

    def test_e2e_admin_qr_endpoint_creates_png_with_0600(self):
        """E2E: GET /api/awg/peers/{name}/qr → PNG файл с правами 0o600 на диске.

        Полный путь:
          awg_handle_get(/api/awg/peers/alice/qr)
            → _require_admin() (mocked: True)
            → awgs_qr_export_peer(peer, show_terminal=False)  [РЕАЛЬНЫЙ]
              → awgs_qr_save_client_conf  [РЕАЛЬНЫЙ, .conf создаётся]
              → awgs_qr_build_vpn_uri      [РЕАЛЬНЫЙ]
              → awgs_qr_show_terminal      [show_terminal=False → пропускается]
              → awgs_qr_save_png           [РЕАЛЬНЫЙ, qrencode замокан на core._run]
                → qrencode -t PNG -o ...   [side-effect: создаёт файл]
                → path.chmod(0o600)        [РЕАЛЬНЫЙ на реальном файле]
            → png_path.read_bytes() → HTTP 200
        """
        import os, stat
        from vless_installer.modules import awg_rest_api, awg_qr, awg_constants

        peer = {
            "name": "alice",
            "owner_email": "",
            "client_privkey": "SECRET_PRIV_KEY",
            "client_pubkey": "pubkey123",
            "client_ip": "10.66.66.2",
            "client_ipv6": "",
            "preshared_key": "SECRET_PSK",
            "dns1": "1.1.1.1",
            "dns2": "8.8.8.8",
        }
        server_state = {
            "server_pubkey": "server_pub",
            "port": 51820,
            "endpoint": "1.2.3.4",
            "endpoint_host": "",
            "params": {"jc": 4, "jmin": 40, "jmax": 70, "s1": 0, "s2": 0,
                       "s3": 0, "s4": 0, "h1": 1, "h2": 2, "h3": 3, "h4": 4,
                       "i1": "", "i2": "", "i3": "", "i4": "", "i5": ""},
            "mtu": 1280,
            "allow_ipv6_tunnel": False,
        }
        mock_core = self._make_mock_core_with_qrencode()

        with patch("vless_installer.modules.awg_rest_api._is_awg_installed",
                   return_value=True), \
             patch("vless_installer.modules.awg_state.awgs_state_peer_find",
                   return_value=peer), \
             patch("vless_installer.modules.awg_state.awgs_state_load",
                   return_value=server_state), \
             patch.object(awg_qr, "_core_module", return_value=mock_core), \
             patch.object(awg_qr, "AWGS_KEYS_DIR", self._keys_dir), \
             patch.object(awg_constants, "AWGS_KEYS_DIR", self._keys_dir):
            # Создаём mock handler с admin auth
            h = MagicMock()
            h._require_admin = MagicMock(return_value=True)
            h._send_json = MagicMock()
            h.send_response = MagicMock()
            h.send_header = MagicMock()
            h.end_headers = MagicMock()
            # wfile.write должен принять bytes
            written = []
            h.wfile = MagicMock()
            h.wfile.write = lambda data: written.append(data)

            awg_rest_api.awg_handle_get(h, "/api/awg/peers/alice/qr", {})

            # Проверяем что HTTP статус 200 (PNG отдан)
            self.assertEqual(h.send_response.call_args.args[0], 200,
                             "QR endpoint должен отдать 200")

            # Проверяем что PNG файл реально создан на диске
            png_path = self._keys_dir / "alice_qr.png"
            self.assertTrue(png_path.exists(),
                            f"PNG файл должен быть создан: {png_path}")

            # Проверяем права файла — должны быть 0o600
            mode = stat.S_IMODE(os.stat(png_path).st_mode)
            self.assertEqual(mode, 0o600,
                             f"PNG должен иметь права 0o600 (E2E), имеет {oct(mode)}. "
                             f"Без этого приватный ключ + PSK читаемы другими юзерами.")

            # Проверяем что PNG реально отдан в HTTP-ответе
            self.assertTrue(len(written) > 0, "PNG bytes должны быть записаны в wfile")
            self.assertTrue(isinstance(written[0], bytes))

            # Дополнительно: .conf файл тоже должен быть 0o600
            conf_path = self._keys_dir / "alice.conf"
            if conf_path.exists():
                conf_mode = stat.S_IMODE(os.stat(conf_path).st_mode)
                self.assertEqual(conf_mode, 0o600,
                                 f".conf должен иметь права 0o600, имеет {oct(conf_mode)}")

            # Дополнительно: AWGS_KEYS_DIR должен быть 0o700
            dir_mode = stat.S_IMODE(os.stat(self._keys_dir).st_mode)
            self.assertEqual(dir_mode, 0o700,
                             f"AWGS_KEYS_DIR должен иметь права 0o700, имеет {oct(dir_mode)}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
