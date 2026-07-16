#!/usr/bin/env python3
"""
tests/test_tg_client_bot.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/tg_client_bot.py.

Покрывает:
  1. Разбор /start токена (issue_invite_token → _consume_invite_token)
  2. Привязка TG user_id → UUID (bind_telegram_user, lookup_user_by_tg_id)
  3. Формирование ответа /status с разными состояниями:
     - активен
     - заблокирован по лимиту трафика
     - истёк TTL
     - нет подписки
     - отключён администратором
  4. _is_user_blocked — все ветки
  5. _ttl_is_expired / _ttl_expires_str
  6. _progress_bar / _format_bytes
  7. Генерация inner-скрипта: ast.parse валидность, наличие команд
  8. Конфиг / карта привязок: load / save / chmod 0o600
  9. Rate-limiting
  10. Безопасность: приватные ключи не попадают в ответы
"""
from __future__ import annotations

import ast
import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Создаёт фейковый chimera._core (как в test_tg_bot.py)."""
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


class TestInviteTokenLifecycle(unittest.TestCase):
    """issue_invite_token → _consume_invite_token: разбор /start токена."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_file = self._tmpdir / "tg_client_bot.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_cfg(self):
        return patch("chimera.modules.tg_client_bot._CLIENT_BOT_FILE", self._cfg_file)

    def test_issue_creates_unique_token(self):
        from chimera.modules import tg_client_bot
        with self._patch_cfg():
            t1 = tg_client_bot.issue_invite_token("alice@xray")
            t2 = tg_client_bot.issue_invite_token("bob@xray")
        self.assertNotEqual(t1, t2)
        self.assertGreaterEqual(len(t1), 16)

    def test_consume_returns_email_for_valid_token(self):
        from chimera.modules import tg_client_bot
        with self._patch_cfg():
            tok = tg_client_bot.issue_invite_token("alice@xray")
            email = tg_client_bot._consume_invite_token(tok)
        self.assertEqual(email, "alice@xray")

    def test_consume_returns_none_for_invalid_token(self):
        from chimera.modules import tg_client_bot
        with self._patch_cfg():
            self.assertIsNone(tg_client_bot._consume_invite_token("nonexistent"))

    def test_consume_returns_none_for_already_used_token(self):
        """Одноразовый токен — повторное использование невозможно."""
        from chimera.modules import tg_client_bot
        with self._patch_cfg():
            tok = tg_client_bot.issue_invite_token("alice@xray")
            first = tg_client_bot._consume_invite_token(tok)
            second = tg_client_bot._consume_invite_token(tok)
        self.assertEqual(first, "alice@xray")
        self.assertIsNone(second)

    def test_token_marked_used_after_consume(self):
        from chimera.modules import tg_client_bot
        with self._patch_cfg():
            tok = tg_client_bot.issue_invite_token("alice@xray")
            tg_client_bot._consume_invite_token(tok)
            cfg = tg_client_bot.client_bot_load()
        info = cfg["invite_tokens"][tok]
        self.assertTrue(info["used"])
        self.assertIn("used_at", info)


class TestBindTelegramUser(unittest.TestCase):
    """Привязка TG user_id → VLESS-пользователь."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._map_file = self._tmpdir / "map.json"
        self._users_file = self._tmpdir / "users.json"
        self._users_file.write_text(json.dumps([
            {"uuid": "uuid-alice", "email": "alice@xray", "name": "alice"},
            {"uuid": "uuid-bob",   "email": "bob@xray",   "name": "bob"},
        ]))
        # Создаём patch-объекты ОДИН раз — чтобы один и тот же объект
        # использовался в with... и start/stop
        self._p_map = patch("chimera.modules.tg_client_bot._CLIENT_MAP_FILE", self._map_file)
        self._p_users = patch("chimera.modules.tg_client_bot._USERS_FILE", self._users_file)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_bind_creates_entry(self):
        from chimera.modules import tg_client_bot
        with self._p_map, self._p_users:
            user = tg_client_bot.bind_telegram_user(111111, "alice@xray")
            self.assertIsNotNone(user)
            self.assertEqual(user["uuid"], "uuid-alice")
            data = tg_client_bot.client_map_load()
            self.assertIn("111111", data)
            self.assertEqual(data["111111"]["email"], "alice@xray")

    def test_bind_returns_none_for_unknown_email(self):
        from chimera.modules import tg_client_bot
        with self._p_map, self._p_users:
            user = tg_client_bot.bind_telegram_user(222222, "nobody@xray")
        self.assertIsNone(user)

    def test_bind_blocks_double_binding_email(self):
        """Один email не может быть привязан к двум TG-аккаунтам."""
        from chimera.modules import tg_client_bot
        with self._p_map, self._p_users:
            tg_client_bot.bind_telegram_user(111, "alice@xray")
            user2 = tg_client_bot.bind_telegram_user(222, "alice@xray")
        self.assertIsNone(user2)

    def test_bind_allows_rebind_same_tg(self):
        """Перепривязка того же TG-аккаунта на новый email разрешена."""
        from chimera.modules import tg_client_bot
        with self._p_map, self._p_users:
            tg_client_bot.bind_telegram_user(111, "alice@xray")
            user2 = tg_client_bot.bind_telegram_user(111, "bob@xray")
            self.assertIsNotNone(user2)
            data = tg_client_bot.client_map_load()
            self.assertEqual(data["111"]["email"], "bob@xray")

    def test_lookup_returns_user(self):
        from chimera.modules import tg_client_bot
        with self._p_map, self._p_users:
            tg_client_bot.bind_telegram_user(111, "alice@xray")
            user = tg_client_bot.lookup_user_by_tg_id(111)
        self.assertIsNotNone(user)
        self.assertEqual(user["email"], "alice@xray")

    def test_lookup_returns_none_for_unbound(self):
        from chimera.modules import tg_client_bot
        with self._p_map, self._p_users:
            user = tg_client_bot.lookup_user_by_tg_id(999999)
        self.assertIsNone(user)


class TestIsUserBlocked(unittest.TestCase):
    """_is_user_blocked — все ветки."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._users_file = self._tmpdir / "users.json"
        self._ttl_file   = self._tmpdir / "ttl.json"
        self._lim_file   = self._tmpdir / "limits.json"
        self._blk_file   = self._tmpdir / "blocked.json"
        self._users_file.write_text(json.dumps([
            {"uuid": "u1", "email": "alice@xray", "name": "alice"},
            {"uuid": "u2", "email": "dis@xray",   "name": "dis",   "disabled": True},
            {"uuid": "u3", "email": "blk@xray",   "name": "blk",   "blocked": True},
        ]))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return (
            patch("chimera.modules.tg_client_bot._USERS_FILE", self._users_file),
            patch("chimera.modules.tg_client_bot._TTL_FILE", self._ttl_file),
            patch("chimera.modules.tg_client_bot._LIMITS_FILE", self._lim_file),
            patch("chimera.modules.tg_client_bot._BLOCKED_FILE", self._blk_file),
        )

    def test_active_user_returns_false(self):
        from chimera.modules import tg_client_bot
        for p in self._patches():
            p.start()
        try:
            blocked, reason = tg_client_bot._is_user_blocked("alice@xray")
        finally:
            for p in self._patches():
                p.stop()
        self.assertFalse(blocked)
        self.assertEqual(reason, "")

    def test_disabled_user(self):
        from chimera.modules import tg_client_bot
        for p in self._patches():
            p.start()
        try:
            blocked, reason = tg_client_bot._is_user_blocked("dis@xray")
        finally:
            for p in self._patches():
                p.stop()
        self.assertTrue(blocked)
        self.assertEqual(reason, "disabled")

    def test_blocked_user(self):
        from chimera.modules import tg_client_bot
        for p in self._patches():
            p.start()
        try:
            blocked, reason = tg_client_bot._is_user_blocked("blk@xray")
        finally:
            for p in self._patches():
                p.stop()
        self.assertTrue(blocked)
        self.assertEqual(reason, "blocked")

    def test_ttl_expired_user(self):
        from chimera.modules import tg_client_bot
        self._ttl_file.write_text(json.dumps({
            "alice@xray": {
                "expires_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
            }
        }))
        for p in self._patches():
            p.start()
        try:
            blocked, reason = tg_client_bot._is_user_blocked("alice@xray")
        finally:
            for p in self._patches():
                p.stop()
        self.assertTrue(blocked)
        self.assertEqual(reason, "ttl_expired")

    def test_traffic_limit_user(self):
        from chimera.modules import tg_client_bot
        self._lim_file.write_text(json.dumps({
            "alice@xray": {"disabled": True, "limit_gb": 10}
        }))
        for p in self._patches():
            p.start()
        try:
            blocked, reason = tg_client_bot._is_user_blocked("alice@xray")
        finally:
            for p in self._patches():
                p.stop()
        self.assertTrue(blocked)
        self.assertEqual(reason, "traffic_limit")

    def test_no_user(self):
        from chimera.modules import tg_client_bot
        for p in self._patches():
            p.start()
        try:
            blocked, reason = tg_client_bot._is_user_blocked("ghost@xray")
        finally:
            for p in self._patches():
                p.stop()
        self.assertTrue(blocked)
        self.assertEqual(reason, "no_user")


class TestTtlHelpers(unittest.TestCase):
    """_ttl_is_expired / _ttl_expires_str."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_is_expired_true_for_past(self):
        from chimera.modules import tg_client_bot
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        self.assertTrue(tg_client_bot._ttl_is_expired(past))

    def test_is_expired_false_for_future(self):
        from chimera.modules import tg_client_bot
        future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        self.assertFalse(tg_client_bot._ttl_is_expired(future))

    def test_is_expired_false_for_empty(self):
        from chimera.modules import tg_client_bot
        self.assertFalse(tg_client_bot._ttl_is_expired(""))

    def test_is_expired_false_for_invalid(self):
        from chimera.modules import tg_client_bot
        self.assertFalse(tg_client_bot._ttl_is_expired("not-a-date"))

    def test_expires_str_for_future(self):
        from chimera.modules import tg_client_bot
        future = (datetime.now(timezone.utc) + timedelta(days=3, hours=5)).isoformat()
        s = tg_client_bot._ttl_expires_str(future)
        self.assertIn("д", s)
        self.assertIn("ч", s)

    def test_expires_str_for_past(self):
        from chimera.modules import tg_client_bot
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        self.assertEqual(tg_client_bot._ttl_expires_str(past), "ИСТЁК")

    def test_expires_str_for_empty(self):
        from chimera.modules import tg_client_bot
        self.assertEqual(tg_client_bot._ttl_expires_str(""), "бессрочно")


class TestFormatBytesAndProgressBar(unittest.TestCase):
    """_format_bytes / _progress_bar."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_format_bytes_units(self):
        from chimera.modules import tg_client_bot
        self.assertEqual(tg_client_bot._format_bytes(0), "0 B")
        self.assertEqual(tg_client_bot._format_bytes(512), "512 B")
        self.assertIn("KiB", tg_client_bot._format_bytes(2048))
        self.assertIn("MiB", tg_client_bot._format_bytes(5 * 1024**2))
        self.assertIn("GiB", tg_client_bot._format_bytes(3 * 1024**3))

    def test_progress_bar_zero(self):
        from chimera.modules import tg_client_bot
        bar = tg_client_bot._progress_bar(0)
        self.assertIn("0%", bar)
        self.assertIn("----------", bar)  # все 10 dashes

    def test_progress_bar_full(self):
        from chimera.modules import tg_client_bot
        bar = tg_client_bot._progress_bar(100)
        self.assertIn("100%", bar)
        self.assertIn("██████████", bar)  # все 10 filled

    def test_progress_bar_70(self):
        from chimera.modules import tg_client_bot
        bar = tg_client_bot._progress_bar(70)
        self.assertIn("70%", bar)
        # 7 filled + 3 dashes
        self.assertIn("███████", bar)
        self.assertIn("---", bar)

    def test_progress_bar_clamps_above_100(self):
        from chimera.modules import tg_client_bot
        bar = tg_client_bot._progress_bar(150)
        self.assertIn("100%", bar)


class TestStatusMessage(unittest.TestCase):
    """format_status_message — все состояния."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._map_file    = self._tmpdir / "map.json"
        self._users_file  = self._tmpdir / "users.json"
        self._ttl_file    = self._tmpdir / "ttl.json"
        self._lim_file    = self._tmpdir / "limits.json"
        self._blk_file    = self._tmpdir / "blocked.json"
        self._state_file  = self._tmpdir / "state.json"
        self._users_file.write_text(json.dumps([
            {"uuid": "u1", "email": "alice@xray", "name": "alice"},
        ]))
        self._state_file.write_text(json.dumps({
            "domain": "vpn.example.com",
            "uuid": "u1",
            "public_key": "PUB",
            "short_id": "abcd",
        }))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("chimera.modules.tg_client_bot._CLIENT_MAP_FILE", self._map_file),
            patch("chimera.modules.tg_client_bot._USERS_FILE", self._users_file),
            patch("chimera.modules.tg_client_bot._TTL_FILE", self._ttl_file),
            patch("chimera.modules.tg_client_bot._LIMITS_FILE", self._lim_file),
            patch("chimera.modules.tg_client_bot._BLOCKED_FILE", self._blk_file),
            patch("chimera.modules.tg_client_bot._STATE_FILE", self._state_file),
            # linkqr_lib использует свои собственные path-константы
            patch("chimera.modules.linkqr_lib._MAIN_STATE_FILE", self._state_file),
            patch("chimera.modules.linkqr_lib._USERS_FILE", self._users_file),
        ]

    def _start_patches(self):
        for p in self._patches():
            p.start()

    def _stop_patches(self):
        for p in self._patches():
            p.stop()

    def test_no_binding(self):
        from chimera.modules import tg_client_bot
        self._start_patches()
        try:
            msg = tg_client_bot.format_status_message(999999)
        finally:
            self._stop_patches()
        self.assertIn("не зарегистрированы", msg)

    def test_active_user_shows_traffic_and_ttl(self):
        from chimera.modules import tg_client_bot
        self._lim_file.write_text(json.dumps({
            "alice@xray": {"limit_gb": 50, "used_bytes": 35 * 1024**3, "disabled": False}
        }))
        self._ttl_file.write_text(json.dumps({
            "alice@xray": {
                "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
            }
        }))
        self._start_patches()
        try:
            tg_client_bot.bind_telegram_user(111, "alice@xray")
            msg = tg_client_bot.format_status_message(111)
        finally:
            self._stop_patches()
        self.assertIn("активна", msg)
        self.assertIn("Трафик:", msg)
        self.assertIn("GiB", msg)
        self.assertIn("Срок действия:", msg)
        # Не должен содержать приватные ключи
        self.assertNotIn("private_key", msg.lower())

    def test_blocked_by_traffic_limit(self):
        from chimera.modules import tg_client_bot
        self._lim_file.write_text(json.dumps({
            "alice@xray": {"limit_gb": 10, "used_bytes": 11 * 1024**3, "disabled": True}
        }))
        self._start_patches()
        try:
            tg_client_bot.bind_telegram_user(111, "alice@xray")
            msg = tg_client_bot.format_status_message(111)
        finally:
            self._stop_patches()
        self.assertIn("лимит", msg.lower())
        # Не должен показывать прогресс-бар активной подписки
        self.assertNotIn("█", msg)

    def test_blocked_by_ttl_expired(self):
        from chimera.modules import tg_client_bot
        self._ttl_file.write_text(json.dumps({
            "alice@xray": {
                "expires_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
            }
        }))
        self._start_patches()
        try:
            tg_client_bot.bind_telegram_user(111, "alice@xray")
            msg = tg_client_bot.format_status_message(111)
        finally:
            self._stop_patches()
        self.assertIn("истёк", msg.lower())

    def test_unlimited_traffic_shows_bezlimit(self):
        from chimera.modules import tg_client_bot
        # Без записи в limits_file — безлимит
        self._start_patches()
        try:
            tg_client_bot.bind_telegram_user(111, "alice@xray")
            msg = tg_client_bot.format_status_message(111)
        finally:
            self._stop_patches()
        self.assertIn("безлимит", msg.lower())


class TestConfigMessage(unittest.TestCase):
    """format_config_message — возвращает (text, list_of_keys)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._map_file    = self._tmpdir / "map.json"
        self._users_file  = self._tmpdir / "users.json"
        self._ttl_file    = self._tmpdir / "ttl.json"
        self._lim_file    = self._tmpdir / "limits.json"
        self._blk_file    = self._tmpdir / "blocked.json"
        self._state_file  = self._tmpdir / "state.json"
        self._users_file.write_text(json.dumps([
            {"uuid": "u1", "email": "alice@xray", "name": "alice"},
        ]))
        self._state_file.write_text(json.dumps({
            "domain": "vpn.example.com",
            "uuid": "u1",
            "public_key": "PUB",
            "short_id": "abcd",
        }))
        # Создаём patch-объекты один раз
        self._patches = [
            patch("chimera.modules.tg_client_bot._CLIENT_MAP_FILE", self._map_file),
            patch("chimera.modules.tg_client_bot._USERS_FILE", self._users_file),
            patch("chimera.modules.tg_client_bot._TTL_FILE", self._ttl_file),
            patch("chimera.modules.tg_client_bot._LIMITS_FILE", self._lim_file),
            patch("chimera.modules.tg_client_bot._BLOCKED_FILE", self._blk_file),
            patch("chimera.modules.tg_client_bot._STATE_FILE", self._state_file),
            # linkqr_lib использует свои собственные path-константы
            patch("chimera.modules.linkqr_lib._MAIN_STATE_FILE", self._state_file),
            patch("chimera.modules.linkqr_lib._USERS_FILE", self._users_file),
        ]

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_no_binding_returns_empty_keys(self):
        from chimera.modules import tg_client_bot
        for p in self._patches:
            p.start()
        try:
            text, keys = tg_client_bot.format_config_message(999999)
        finally:
            for p in self._patches:
                p.stop()
        self.assertIn("не зарегистрированы", text)
        self.assertEqual(keys, [])

    def test_active_user_returns_vless_key(self):
        from chimera.modules import tg_client_bot
        for p in self._patches:
            p.start()
        try:
            tg_client_bot.bind_telegram_user(111, "alice@xray")
            text, keys = tg_client_bot.format_config_message(111)
        finally:
            for p in self._patches:
                p.stop()
        self.assertIn("vless", keys)
        self.assertIn("vless://", text)
        # Приватный ключ сервера НЕ должен попасть в ответ
        self.assertNotIn("private_key", text)


class TestConfigAndMapSaveLoad(unittest.TestCase):
    """client_bot_load/save, client_map_load/save — JSON I/O + chmod 0o600."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_file = self._tmpdir / "tg_client_bot.json"
        self._map_file = self._tmpdir / "map.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_cfg_save_sets_chmod_600(self):
        import stat as stat_mod
        from chimera.modules import tg_client_bot
        with patch("chimera.modules.tg_client_bot._CLIENT_BOT_FILE", self._cfg_file):
            tg_client_bot.client_bot_save({"token": "secret", "admin_id": "111"})
            mode = stat_mod.filemode(self._cfg_file.stat().st_mode)
            # 0o600 = rw------- = "-rw-------"
            self.assertEqual(self._cfg_file.stat().st_mode & 0o777, 0o600)

    def test_cfg_load_returns_empty_when_no_file(self):
        from chimera.modules import tg_client_bot
        with patch("chimera.modules.tg_client_bot._CLIENT_BOT_FILE", self._cfg_file):
            self.assertEqual(tg_client_bot.client_bot_load(), {})

    def test_map_save_sets_chmod_600(self):
        from chimera.modules import tg_client_bot
        with patch("chimera.modules.tg_client_bot._CLIENT_MAP_FILE", self._map_file):
            tg_client_bot.client_map_save({"111": {"uuid": "u1", "email": "a@x"}})
            self.assertEqual(self._map_file.stat().st_mode & 0o777, 0o600)

    def test_map_load_returns_empty_when_no_file(self):
        from chimera.modules import tg_client_bot
        with patch("chimera.modules.tg_client_bot._CLIENT_MAP_FILE", self._map_file):
            self.assertEqual(tg_client_bot.client_map_load(), {})


class TestGeneratedScriptSyntax(unittest.TestCase):
    """_generate_client_bot_script — ast.parse валидность."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_script_is_valid_python(self):
        from chimera.modules import tg_client_bot
        cfg = {
            "token": "12345:ABC-DEF",
            "admin_id": "987654321",
            "rate_limit_seconds": 2,
        }
        script = tg_client_bot._generate_client_bot_script(cfg)
        # Должен парситься как валидный Python
        try:
            ast.parse(script)
        except SyntaxError as e:
            self.fail(f"Generated script has invalid syntax: {e}")

    def test_script_contains_all_commands(self):
        from chimera.modules import tg_client_bot
        cfg = {"token": "T", "admin_id": "A", "rate_limit_seconds": 2}
        script = tg_client_bot._generate_client_bot_script(cfg)
        for cmd in ["/start", "/config", "/qr", "/status", "/help"]:
            self.assertIn(f'"{cmd}"', script, f"Command {cmd} missing in generated script")
        for handler in ["handle_start", "handle_config", "handle_qr", "handle_status", "handle_help"]:
            self.assertIn(handler, script, f"Handler {handler} missing in generated script")

    def test_script_contains_rate_limiting(self):
        from chimera.modules import tg_client_bot
        cfg = {"token": "T", "admin_id": "A", "rate_limit_seconds": 5}
        script = tg_client_bot._generate_client_bot_script(cfg)
        self.assertIn("RATE_LIMIT_S = 5", script)
        self.assertIn("_rl_allow", script)

    def test_script_contains_callback_query_handler(self):
        """Inline-кнопки должны обрабатываться."""
        from chimera.modules import tg_client_bot
        cfg = {"token": "T", "admin_id": "A"}
        script = tg_client_bot._generate_client_bot_script(cfg)
        self.assertIn("callback_query", script)
        self.assertIn("answerCallbackQuery", script)

    def test_script_uses_token_safely(self):
        """Токен с спецсимволами должен безопасно вставляться."""
        from chimera.modules import tg_client_bot
        # Токен с кавычками и слэшами
        cfg = {"token": '12345:ABC"DEF\\GHI', "admin_id": "A"}
        script = tg_client_bot._generate_client_bot_script(cfg)
        try:
            ast.parse(script)
        except SyntaxError as e:
            self.fail(f"Script with special-char token has invalid syntax: {e}")


class TestSecurityNoSecretsInMessages(unittest.TestCase):
    """Приватные ключи / PSK не должны попадать в ответы бота."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._map_file    = self._tmpdir / "map.json"
        self._users_file  = self._tmpdir / "users.json"
        self._ttl_file    = self._tmpdir / "ttl.json"
        self._lim_file    = self._tmpdir / "limits.json"
        self._blk_file    = self._tmpdir / "blocked.json"
        self._state_file  = self._tmpdir / "state.json"
        self._users_file.write_text(json.dumps([
            {"uuid": "u1", "email": "alice@xray", "name": "alice"},
        ]))
        self._state_file.write_text(json.dumps({
            "domain": "vpn.example.com",
            "uuid": "u1",
            "public_key": "PUBLIC_KEY_OK",
            "private_key": "TOP_SECRET_PRIVATE_KEY_MUST_NOT_LEAK",
            "short_id": "abcd",
        }))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("chimera.modules.tg_client_bot._CLIENT_MAP_FILE", self._map_file),
            patch("chimera.modules.tg_client_bot._USERS_FILE", self._users_file),
            patch("chimera.modules.tg_client_bot._TTL_FILE", self._ttl_file),
            patch("chimera.modules.tg_client_bot._LIMITS_FILE", self._lim_file),
            patch("chimera.modules.tg_client_bot._BLOCKED_FILE", self._blk_file),
            patch("chimera.modules.tg_client_bot._STATE_FILE", self._state_file),
        ]

    def test_private_key_not_in_status(self):
        from chimera.modules import tg_client_bot
        for p in self._patches():
            p.start()
        try:
            tg_client_bot.bind_telegram_user(111, "alice@xray")
            msg = tg_client_bot.format_status_message(111)
        finally:
            for p in self._patches():
                p.stop()
        self.assertNotIn("TOP_SECRET_PRIVATE_KEY_MUST_NOT_LEAK", msg)

    def test_private_key_not_in_config(self):
        from chimera.modules import tg_client_bot
        for p in self._patches():
            p.start()
        try:
            tg_client_bot.bind_telegram_user(111, "alice@xray")
            text, _ = tg_client_bot.format_config_message(111)
        finally:
            for p in self._patches():
                p.stop()
        self.assertNotIn("TOP_SECRET_PRIVATE_KEY_MUST_NOT_LEAK", text)


class TestRateLimiting(unittest.TestCase):
    """Rate-limiting: встроен в generated inner-скрипт, не в outer."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_rate_limit_value_persisted_in_cfg(self):
        from chimera.modules import tg_client_bot
        cfg = {"token": "T", "admin_id": "A", "rate_limit_seconds": 5}
        script = tg_client_bot._generate_client_bot_script(cfg)
        self.assertIn("RATE_LIMIT_S = 5", script)

    def test_rate_limit_default_2_when_not_set(self):
        from chimera.modules import tg_client_bot
        cfg = {"token": "T", "admin_id": "A"}  # нет rate_limit_seconds
        script = tg_client_bot._generate_client_bot_script(cfg)
        self.assertIn("RATE_LIMIT_S = 2", script)


if __name__ == "__main__":
    unittest.main()
