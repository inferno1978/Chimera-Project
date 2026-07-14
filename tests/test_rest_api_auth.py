#!/usr/bin/env python3
"""
tests/test_rest_api_auth.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для auth-функций из chimera/modules/rest_api.py
(класс _VLESSHandler).

Покрывает (только auth — НЕ пересекается с test_rest_api.py, который тестирует
генерацию конфигов):

  1. _check_admin_auth  — валидация Basic Auth admin (constant-time, defaults)
  2. _check_user_auth   — валидация Basic Auth user (по name/email + portal_password)
  3. _is_rate_limited   — sliding-window rate-limit (60с окно, 10 попыток, 30с reject)
  4. _record_auth_failure — запись timestamp'а в _AUTH_FAIL_LOG
  5. _require_admin     — composite gate: rate-limit → auth → 401/429
  6. _require_user      — composite gate: rate-limit → auth → 401/429

Реального subprocess/systemctl/iptables/curl — нет, всё через mock.
Реальной записи в /var, /etc, /usr — нет, через tempfile + patch путей.
"""
from __future__ import annotations

import base64
import json
import sys
import time
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Эталонный паттерн из tests/test_health.py."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core


def _basic_auth_header(user: str, password: str) -> str:
    """Возвращает строку заголовка Authorization: Basic ..."""
    creds = f"{user}:{password}"
    encoded = base64.b64encode(creds.encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"


def _make_handler(headers: dict = None, client_ip: str = "1.2.3.4"):
    """Создаёт stub _VLESSHandler с нужными атрибутами.

    Используем реальный класс-наследник _VLESSHandler (без вызова __init__
    BaseHTTPRequestHandler), чтобы методы _check_admin_auth/_is_rate_limited/
    _require_admin и т.д. работали как настоящие bound methods.
    """
    from chimera.modules.rest_api import _VLESSHandler

    class _StubHandler(_VLESSHandler):
        # Не вызываем BaseHTTPRequestHandler.__init__ — он требует сокет и
        # парсит заголовки из rfile. Нам нужна только имитация атрибутов.
        def __init__(self, headers_dict, client_ip):
            self.headers = headers_dict or {}
            self.client_address = (client_ip, 12345) if client_ip else None
            self.send_response = MagicMock()
            self.send_header = MagicMock()
            self.end_headers = MagicMock()
            self.wfile = MagicMock()

    return _StubHandler(headers, client_ip)


# ══════════════════════════════════════════════════════════════════════════════
#  _check_admin_auth — валидация Basic Auth admin
# ══════════════════════════════════════════════════════════════════════════════
class TestCheckAdminAuth(unittest.TestCase):
    """_check_admin_auth: сравнение с admin_user/admin_pass из web_config.json."""

    def setUp(self):
        _setup_core_in_sysmodules()
        # Очищаем rate-limit лог между тестами
        from chimera.modules import rest_api
        rest_api._AUTH_FAIL_LOG.clear()

    def test_returns_true_with_correct_credentials(self):
        from chimera.modules import rest_api
        h = _make_handler({
            "Authorization": _basic_auth_header("admin", "s3cret"),
        })
        with patch.object(rest_api, "_web_config_load",
                          return_value={"admin_user": "admin",
                                        "admin_pass": "s3cret"}):
            result = rest_api._VLESSHandler._check_admin_auth(h)
        self.assertTrue(result)

    def test_returns_false_with_wrong_password(self):
        from chimera.modules import rest_api
        h = _make_handler({
            "Authorization": _basic_auth_header("admin", "wrong"),
        })
        with patch.object(rest_api, "_web_config_load",
                          return_value={"admin_user": "admin",
                                        "admin_pass": "s3cret"}):
            result = rest_api._VLESSHandler._check_admin_auth(h)
        self.assertFalse(result)

    def test_returns_false_with_wrong_username(self):
        from chimera.modules import rest_api
        h = _make_handler({
            "Authorization": _basic_auth_header("root", "s3cret"),
        })
        with patch.object(rest_api, "_web_config_load",
                          return_value={"admin_user": "admin",
                                        "admin_pass": "s3cret"}):
            result = rest_api._VLESSHandler._check_admin_auth(h)
        self.assertFalse(result)

    def test_returns_false_when_no_auth_header(self):
        from chimera.modules import rest_api
        h = _make_handler({})
        with patch.object(rest_api, "_web_config_load",
                          return_value={"admin_user": "admin",
                                        "admin_pass": "s3cret"}):
            result = rest_api._VLESSHandler._check_admin_auth(h)
        self.assertFalse(result)

    def test_returns_false_when_not_basic_auth(self):
        """Bearer-токен не принимается."""
        from chimera.modules import rest_api
        h = _make_handler({"Authorization": "Bearer xyz123"})
        with patch.object(rest_api, "_web_config_load",
                          return_value={"admin_user": "admin",
                                        "admin_pass": "s3cret"}):
            result = rest_api._VLESSHandler._check_admin_auth(h)
        self.assertFalse(result)

    def test_returns_false_when_invalid_base64(self):
        from chimera.modules import rest_api
        h = _make_handler({"Authorization": "Basic !!!invalid_base64!!!"})
        with patch.object(rest_api, "_web_config_load",
                          return_value={"admin_user": "admin",
                                        "admin_pass": "s3cret"}):
            result = rest_api._VLESSHandler._check_admin_auth(h)
        self.assertFalse(result)

    def test_returns_false_when_admin_pass_empty(self):
        """Если admin_pass в конфиге пустой — отказ (даже при верных остальных полях)."""
        from chimera.modules import rest_api
        h = _make_handler({
            "Authorization": _basic_auth_header("admin", ""),
        })
        with patch.object(rest_api, "_web_config_load",
                          return_value={"admin_user": "admin",
                                        "admin_pass": ""}):
            result = rest_api._VLESSHandler._check_admin_auth(h)
        self.assertFalse(result)

    def test_returns_false_when_web_config_empty(self):
        """Пустой web_config → defaults: admin_user='admin', admin_pass='' → False."""
        from chimera.modules import rest_api
        h = _make_handler({
            "Authorization": _basic_auth_header("admin", ""),
        })
        with patch.object(rest_api, "_web_config_load", return_value={}):
            result = rest_api._VLESSHandler._check_admin_auth(h)
        self.assertFalse(result)

    def test_password_with_colon_partition_works(self):
        """Пароль с двоеточием — partition берёт только первое ':'."""
        from chimera.modules import rest_api
        # user='admin', password='pass:with:colons'
        h = _make_handler({
            "Authorization": _basic_auth_header("admin", "pass:with:colons"),
        })
        with patch.object(rest_api, "_web_config_load",
                          return_value={"admin_user": "admin",
                                        "admin_pass": "pass:with:colons"}):
            result = rest_api._VLESSHandler._check_admin_auth(h)
        self.assertTrue(result)

    def test_default_admin_user_is_admin(self):
        """Если в конфиге нет admin_user — default 'admin'."""
        from chimera.modules import rest_api
        h = _make_handler({
            "Authorization": _basic_auth_header("admin", "pass"),
        })
        # Конфиг без admin_user, но с admin_pass
        with patch.object(rest_api, "_web_config_load",
                          return_value={"admin_pass": "pass"}):
            result = rest_api._VLESSHandler._check_admin_auth(h)
        self.assertTrue(result)


# ══════════════════════════════════════════════════════════════════════════════
#  _check_user_auth — валидация Basic Auth user
# ══════════════════════════════════════════════════════════════════════════════
class TestCheckUserAuth(unittest.TestCase):
    """_check_user_auth: матч по name или email + portal_password."""

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import rest_api
        rest_api._AUTH_FAIL_LOG.clear()

    def test_returns_user_dict_when_matching_name(self):
        from chimera.modules import rest_api
        user = {"name": "alice", "email": "alice@example.com",
                "portal_password": "alice_pw", "uuid": "u1"}
        h = _make_handler({
            "Authorization": _basic_auth_header("alice", "alice_pw"),
        })
        with patch.object(rest_api, "_get_users", return_value=[user]):
            result = rest_api._VLESSHandler._check_user_auth(h)
        self.assertEqual(result, user)

    def test_returns_user_dict_when_matching_email(self):
        from chimera.modules import rest_api
        user = {"name": "alice", "email": "alice@example.com",
                "portal_password": "alice_pw", "uuid": "u1"}
        h = _make_handler({
            "Authorization": _basic_auth_header("alice@example.com", "alice_pw"),
        })
        with patch.object(rest_api, "_get_users", return_value=[user]):
            result = rest_api._VLESSHandler._check_user_auth(h)
        self.assertEqual(result, user)

    def test_returns_none_when_wrong_password(self):
        from chimera.modules import rest_api
        user = {"name": "alice", "email": "alice@example.com",
                "portal_password": "alice_pw", "uuid": "u1"}
        h = _make_handler({
            "Authorization": _basic_auth_header("alice", "wrong"),
        })
        with patch.object(rest_api, "_get_users", return_value=[user]):
            result = rest_api._VLESSHandler._check_user_auth(h)
        self.assertIsNone(result)

    def test_returns_none_when_user_not_found(self):
        from chimera.modules import rest_api
        h = _make_handler({
            "Authorization": _basic_auth_header("nobody", "pw"),
        })
        with patch.object(rest_api, "_get_users",
                          return_value=[{"name": "alice", "email": "a@x",
                                         "portal_password": "p"}]):
            result = rest_api._VLESSHandler._check_user_auth(h)
        self.assertIsNone(result)

    def test_returns_none_when_no_basic_header(self):
        from chimera.modules import rest_api
        h = _make_handler({})
        with patch.object(rest_api, "_get_users", return_value=[]):
            result = rest_api._VLESSHandler._check_user_auth(h)
        self.assertIsNone(result)

    def test_returns_none_when_invalid_base64(self):
        from chimera.modules import rest_api
        h = _make_handler({"Authorization": "Basic !!!invalid!!!"})
        with patch.object(rest_api, "_get_users", return_value=[]):
            result = rest_api._VLESSHandler._check_user_auth(h)
        self.assertIsNone(result)

    def test_returns_none_when_portal_password_empty(self):
        """Регрессия: пользователь найден, но portal_password пустой → None
        (раньше был fallback на uuid — убран намеренно)."""
        from chimera.modules import rest_api
        user = {"name": "alice", "email": "alice@example.com",
                "portal_password": "",  # пустой!
                "uuid": "u1"}
        h = _make_handler({
            "Authorization": _basic_auth_header("alice", ""),
        })
        with patch.object(rest_api, "_get_users", return_value=[user]):
            result = rest_api._VLESSHandler._check_user_auth(h)
        self.assertIsNone(result)

    def test_first_match_wins_when_duplicate_names(self):
        """Несколько пользователей с одним name — выигрывает первый."""
        from chimera.modules import rest_api
        u1 = {"name": "alice", "email": "alice1@x",
              "portal_password": "pw1", "uuid": "u1"}
        u2 = {"name": "alice", "email": "alice2@x",
              "portal_password": "pw2", "uuid": "u2"}
        h = _make_handler({
            "Authorization": _basic_auth_header("alice", "pw1"),
        })
        with patch.object(rest_api, "_get_users", return_value=[u1, u2]):
            result = rest_api._VLESSHandler._check_user_auth(h)
        self.assertEqual(result["uuid"], "u1")

    def test_password_with_colon_partition_works(self):
        """Пароль с двоеточием — partition берёт только первое ':'."""
        from chimera.modules import rest_api
        user = {"name": "alice", "email": "a@x",
                "portal_password": "pw:with:colons", "uuid": "u1"}
        h = _make_handler({
            "Authorization": _basic_auth_header("alice", "pw:with:colons"),
        })
        with patch.object(rest_api, "_get_users", return_value=[user]):
            result = rest_api._VLESSHandler._check_user_auth(h)
        self.assertEqual(result, user)


# ══════════════════════════════════════════════════════════════════════════════
#  _is_rate_limited — sliding-window rate-limit
# ══════════════════════════════════════════════════════════════════════════════
class TestIsRateLimited(unittest.TestCase):
    """_is_rate_limited: 10 попыток за 60с → блок на 30с от последней неудачи."""

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import rest_api
        rest_api._AUTH_FAIL_LOG.clear()

    def test_returns_false_when_log_empty(self):
        from chimera.modules import rest_api
        h = _make_handler(client_ip="1.1.1.1")
        self.assertFalse(rest_api._VLESSHandler._is_rate_limited(h))

    def test_returns_false_below_threshold(self):
        """9 попыток за 60с — НЕ rate-limited."""
        from chimera.modules import rest_api
        rest_api._AUTH_FAIL_LOG["1.1.1.1"] = [time.time() - i for i in range(9)]
        h = _make_handler(client_ip="1.1.1.1")
        self.assertFalse(rest_api._VLESSHandler._is_rate_limited(h))

    def test_returns_true_at_threshold(self):
        """10 попыток за 60с, последняя <30с назад → rate-limited."""
        from chimera.modules import rest_api
        now = time.time()
        rest_api._AUTH_FAIL_LOG["1.1.1.1"] = [now - i for i in range(10)]
        h = _make_handler(client_ip="1.1.1.1")
        self.assertTrue(rest_api._VLESSHandler._is_rate_limited(h))

    def test_returns_false_when_reject_window_expired(self):
        """10 попыток, но последняя >30с назад → НЕ rate-limited (отклон истёк)."""
        from chimera.modules import rest_api
        now = time.time()
        # 10 попыток в течение 60с, но последняя была 35с назад
        rest_api._AUTH_FAIL_LOG["1.1.1.1"] = [now - 35 - i for i in range(10)]
        h = _make_handler(client_ip="1.1.1.1")
        self.assertFalse(rest_api._VLESSHandler._is_rate_limited(h))

    def test_returns_false_when_attempts_outside_window(self):
        """Попытки старше 60с — выкидываются."""
        from chimera.modules import rest_api
        now = time.time()
        # 5 свежих + 5 старых (>60с) — должно остаться 5, не rate-limited
        rest_api._AUTH_FAIL_LOG["1.1.1.1"] = (
            [now - i for i in range(5)] +               # свежие
            [now - 70 - i for i in range(5)]            # старые
        )
        h = _make_handler(client_ip="1.1.1.1")
        self.assertFalse(rest_api._VLESSHandler._is_rate_limited(h))

    def test_rate_limit_isolated_by_ip(self):
        """10 попыток от IP '1.1.1.1' не блокируют IP '2.2.2.2'."""
        from chimera.modules import rest_api
        now = time.time()
        rest_api._AUTH_FAIL_LOG["1.1.1.1"] = [now - i for i in range(10)]
        h2 = _make_handler(client_ip="2.2.2.2")
        self.assertFalse(rest_api._VLESSHandler._is_rate_limited(h2))

    def test_unknown_ip_returns_question_mark(self):
        """client_address=None → IP становится '?' — отдельный bucket."""
        from chimera.modules import rest_api
        h = _make_handler(client_ip=None)
        # 10 попыток от '?'
        rest_api._AUTH_FAIL_LOG["?"] = [time.time() - i for i in range(10)]
        self.assertTrue(rest_api._VLESSHandler._is_rate_limited(h))


# ══════════════════════════════════════════════════════════════════════════════
#  _record_auth_failure — запись timestamp в лог
# ══════════════════════════════════════════════════════════════════════════════
class TestRecordAuthFailure(unittest.TestCase):
    """_record_auth_failure: append timestamp + cleanup старых."""

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import rest_api
        rest_api._AUTH_FAIL_LOG.clear()

    def test_appends_timestamp_to_log(self):
        from chimera.modules import rest_api
        h = _make_handler(client_ip="1.1.1.1")
        before = time.time()
        rest_api._VLESSHandler._record_auth_failure(h)
        after = time.time()
        self.assertIn("1.1.1.1", rest_api._AUTH_FAIL_LOG)
        self.assertEqual(len(rest_api._AUTH_FAIL_LOG["1.1.1.1"]), 1)
        ts = rest_api._AUTH_FAIL_LOG["1.1.1.1"][0]
        self.assertGreaterEqual(ts, before)
        self.assertLessEqual(ts, after)

    def test_multiple_appends_accumulate(self):
        from chimera.modules import rest_api
        h = _make_handler(client_ip="1.1.1.1")
        for _ in range(5):
            rest_api._VLESSHandler._record_auth_failure(h)
        self.assertEqual(len(rest_api._AUTH_FAIL_LOG["1.1.1.1"]), 5)

    def test_cleans_up_old_entries(self):
        """Записи старше AUTH_FAIL_WINDOW выкидываются при следующей записи."""
        from chimera.modules import rest_api
        rest_api._AUTH_FAIL_LOG["1.1.1.1"] = [time.time() - 100]  # 100с назад
        h = _make_handler(client_ip="1.1.1.1")
        rest_api._VLESSHandler._record_auth_failure(h)
        # Старая запись выкинута, осталась только новая
        self.assertEqual(len(rest_api._AUTH_FAIL_LOG["1.1.1.1"]), 1)

    def test_isolates_ips(self):
        from chimera.modules import rest_api
        h1 = _make_handler(client_ip="1.1.1.1")
        h2 = _make_handler(client_ip="2.2.2.2")
        rest_api._VLESSHandler._record_auth_failure(h1)
        rest_api._VLESSHandler._record_auth_failure(h2)
        self.assertIn("1.1.1.1", rest_api._AUTH_FAIL_LOG)
        self.assertIn("2.2.2.2", rest_api._AUTH_FAIL_LOG)
        self.assertEqual(len(rest_api._AUTH_FAIL_LOG["1.1.1.1"]), 1)
        self.assertEqual(len(rest_api._AUTH_FAIL_LOG["2.2.2.2"]), 1)


# ══════════════════════════════════════════════════════════════════════════════
#  _require_admin — composite gate (rate-limit → auth → 401/429)
# ══════════════════════════════════════════════════════════════════════════════
class TestRequireAdmin(unittest.TestCase):
    """_require_admin: success / rate-limited / auth-fail."""

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import rest_api
        rest_api._AUTH_FAIL_LOG.clear()

    def test_returns_true_when_auth_succeeds(self):
        from chimera.modules import rest_api
        h = _make_handler({
            "Authorization": _basic_auth_header("admin", "s3cret"),
        })
        with patch.object(rest_api, "_web_config_load",
                          return_value={"admin_user": "admin",
                                        "admin_pass": "s3cret"}):
            result = rest_api._VLESSHandler._require_admin(h)
        self.assertTrue(result)
        # Никаких HTTP-ответов не отправляется
        h.send_response.assert_not_called()
        h.wfile.write.assert_not_called()

    def test_returns_false_and_sends_401_when_auth_fails(self):
        from chimera.modules import rest_api
        h = _make_handler({
            "Authorization": _basic_auth_header("admin", "wrong"),
        })
        with patch.object(rest_api, "_web_config_load",
                          return_value={"admin_user": "admin",
                                        "admin_pass": "s3cret"}):
            result = rest_api._VLESSHandler._require_admin(h, realm="Admin Panel")
        self.assertFalse(result)
        # 401 отправлен
        h.send_response.assert_called_with(401)
        # Realm в заголовке
        realm_call = [c for c in h.send_header.call_args_list
                      if "WWW-Authenticate" in str(c)]
        self.assertTrue(realm_call, "WWW-Authenticate header должен быть отправлен")
        # Запись в rate-limit лог
        self.assertIn("1.2.3.4", rest_api._AUTH_FAIL_LOG)

    def test_returns_false_and_sends_429_when_rate_limited(self):
        """10 неудач → следующий запрос получает 429, _record_auth_failure НЕ вызывается."""
        from chimera.modules import rest_api
        rest_api._AUTH_FAIL_LOG["1.2.3.4"] = [time.time() - i for i in range(10)]
        h = _make_handler({
            "Authorization": _basic_auth_header("admin", "s3cret"),
        })
        with patch.object(rest_api, "_web_config_load",
                          return_value={"admin_user": "admin",
                                        "admin_pass": "s3cret"}):
            result = rest_api._VLESSHandler._require_admin(h)
        self.assertFalse(result)
        # 429 отправлен
        h.send_response.assert_called_with(429)
        # Retry-After header
        retry_call = [c for c in h.send_header.call_args_list
                      if "Retry-After" in str(c)]
        self.assertTrue(retry_call, "Retry-After header должен быть отправлен")
        # Счётчик не растёт во время 429-блокировки
        self.assertEqual(len(rest_api._AUTH_FAIL_LOG["1.2.3.4"]), 10)

    def test_default_realm_is_admin(self):
        from chimera.modules import rest_api
        h = _make_handler({})  # нет auth
        with patch.object(rest_api, "_web_config_load",
                          return_value={"admin_user": "admin",
                                        "admin_pass": "s3cret"}):
            rest_api._VLESSHandler._require_admin(h)
        # Realm по умолчанию = "Admin"
        realm_call = next(c for c in h.send_header.call_args_list
                          if "WWW-Authenticate" in str(c))
        self.assertIn("Admin", str(realm_call))


# ══════════════════════════════════════════════════════════════════════════════
#  _require_user — composite gate (rate-limit → auth → 401/429)
# ══════════════════════════════════════════════════════════════════════════════
class TestRequireUser(unittest.TestCase):
    """_require_user: success / rate-limited / auth-fail."""

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import rest_api
        rest_api._AUTH_FAIL_LOG.clear()

    def test_returns_user_dict_when_auth_succeeds(self):
        from chimera.modules import rest_api
        user = {"name": "alice", "email": "a@x",
                "portal_password": "pw", "uuid": "u1"}
        h = _make_handler({
            "Authorization": _basic_auth_header("alice", "pw"),
        })
        with patch.object(rest_api, "_get_users", return_value=[user]):
            result = rest_api._VLESSHandler._require_user(h)
        self.assertEqual(result, user)
        h.send_response.assert_not_called()

    def test_returns_none_and_sends_401_when_user_not_found(self):
        from chimera.modules import rest_api
        h = _make_handler({
            "Authorization": _basic_auth_header("nobody", "pw"),
        })
        with patch.object(rest_api, "_get_users", return_value=[]):
            result = rest_api._VLESSHandler._require_user(h)
        self.assertIsNone(result)
        h.send_response.assert_called_with(401)
        # Realm для user portal
        realm_call = next(c for c in h.send_header.call_args_list
                          if "WWW-Authenticate" in str(c))
        self.assertIn("User Portal", str(realm_call))
        self.assertIn("1.2.3.4", rest_api._AUTH_FAIL_LOG)

    def test_returns_none_and_sends_429_when_rate_limited(self):
        from chimera.modules import rest_api
        rest_api._AUTH_FAIL_LOG["1.2.3.4"] = [time.time() - i for i in range(10)]
        user = {"name": "alice", "email": "a@x",
                "portal_password": "pw", "uuid": "u1"}
        h = _make_handler({
            "Authorization": _basic_auth_header("alice", "pw"),
        })
        with patch.object(rest_api, "_get_users", return_value=[user]):
            result = rest_api._VLESSHandler._require_user(h)
        self.assertIsNone(result)
        h.send_response.assert_called_with(429)
        # Счётчик не растёт во время 429
        self.assertEqual(len(rest_api._AUTH_FAIL_LOG["1.2.3.4"]), 10)

    def test_returns_none_when_portal_password_empty(self):
        """Регрессия: пользователь найден, но portal_password='' → 401."""
        from chimera.modules import rest_api
        user = {"name": "alice", "email": "a@x",
                "portal_password": "", "uuid": "u1"}
        h = _make_handler({
            "Authorization": _basic_auth_header("alice", ""),
        })
        with patch.object(rest_api, "_get_users", return_value=[user]):
            result = rest_api._VLESSHandler._require_user(h)
        self.assertIsNone(result)
        h.send_response.assert_called_with(401)


# ══════════════════════════════════════════════════════════════════════════════
#  _send_401 / _send_429 — формирование HTTP-ответов
# ══════════════════════════════════════════════════════════════════════════════
class TestSendErrorResponses(unittest.TestCase):
    """_send_401 / _send_429: корректность HTTP-ответов."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_send_401_includes_www_authenticate_header(self):
        from chimera.modules import rest_api
        h = _make_handler()
        rest_api._VLESSHandler._send_401(h, realm="Test Realm")
        h.send_response.assert_called_with(401)
        # Проверяем, что был send_header с WWW-Authenticate и realm
        headers_sent = [str(c) for c in h.send_header.call_args_list]
        self.assertTrue(any("WWW-Authenticate" in h_str for h_str in headers_sent))
        self.assertTrue(any("Test Realm" in h_str for h_str in headers_sent))
        # Тело — JSON с ошибкой
        h.wfile.write.assert_called_once()
        body = h.wfile.write.call_args.args[0]
        self.assertIn(b"Unauthorized", body)

    def test_send_429_includes_retry_after_header(self):
        from chimera.modules import rest_api
        h = _make_handler()
        rest_api._VLESSHandler._send_429(h)
        h.send_response.assert_called_with(429)
        # Retry-After = AUTH_FAIL_REJECT (30)
        headers_sent = [str(c) for c in h.send_header.call_args_list]
        self.assertTrue(any("Retry-After" in h_str for h_str in headers_sent))
        self.assertTrue(any("30" in h_str for h_str in headers_sent))
        # Тело — JSON с ошибкой
        h.wfile.write.assert_called_once()
        body = h.wfile.write.call_args.args[0]
        self.assertIn(b"Too Many Requests", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
