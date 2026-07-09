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
        """my-peer отдаёт пира БЕЗ client_privkey (приватные ключи не утекают)."""
        from vless_installer.modules import awg_rest_api
        fake_peer = {
            "name": "alice",
            "client_privkey": "SECRET_PRIVATE_KEY_MUST_NOT_LEAK",
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
            self.assertEqual(peer.get("name"), "alice")
            self.assertEqual(peer.get("client_pubkey"), "pubkey123")


class TestAWGRestAPISafePeerForJson(unittest.TestCase):
    """_safe_peer_for_json убирает приватные ключи."""

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
