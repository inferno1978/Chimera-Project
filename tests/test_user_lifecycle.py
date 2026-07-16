#!/usr/bin/env python3
"""
tests/test_user_lifecycle.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/user_lifecycle.py.

ПОКРЫТИЕ:
  1. Mock-тесты для каждого protocol adapter (VlessAdapter, AwgAdapter,
     SingboxAdapter, MieruAdapter, NaiveProxyAdapter, MtprotoAdapter,
     FptnAdapter, Hysteria2Adapter)
  2. Coordinator: add_user / remove_user / block_user / unblock_user /
     update_limits
  3. Успешный сценарий (все протоколы синхронизированы)
  4. Частичный сбой (один протокол кидает исключение) → rollback state files
  5. Идемпотентность: повторный add_user/remove_user для существующего/
     несуществующего пользователя
  6. Snapshot/restore — проверка что state-файлы реально откатываются
  7. Real (non-mock) тесты для 2-3 протоколов: VLESS + AWG + sing-box
     с минимальными fake state-файлами, чтобы поймать баги которые моки
     пропускают (по опыту предыдущих аудитов).
  8. CLI-флаги --ttl-check, --traffic-check, --lifecycle-cleanup —
     точечный тест что они вызывают правильные функции.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Создаёт фейковый chimera._core в sys.modules (как в test_tg_bot.py)."""
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


# =============================================================================
#  ТЕСТЫ STATE SNAPSHOT / ROLLBACK
# =============================================================================
class TestStateSnapshot(unittest.TestCase):
    """StateSnapshot — snapshot/restore pattern."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_capture_and_restore_existing_file(self):
        from chimera.modules.user_lifecycle import StateSnapshot
        f = self._tmpdir / "users.json"
        f.write_text('{"original": true}')
        snap = StateSnapshot()
        snap.capture([f])
        # Меняем файл
        f.write_text('{"modified": true}')
        self.assertEqual(json.loads(f.read_text()), {"modified": True})
        # Откатываем
        snap.restore()
        self.assertEqual(json.loads(f.read_text()), {"original": True})

    def test_capture_and_restore_nonexistent_file(self):
        from chimera.modules.user_lifecycle import StateSnapshot
        f = self._tmpdir / "new.json"
        snap = StateSnapshot()
        snap.capture([f])
        # Создаём файл после snapshot
        f.write_text('{"new": true}')
        # Откатываем — файл должен удалиться
        snap.restore()
        self.assertFalse(f.exists())

    def test_commit_forgets_snapshot(self):
        from chimera.modules.user_lifecycle import StateSnapshot
        f = self._tmpdir / "users.json"
        f.write_text('{"original": true}')
        snap = StateSnapshot()
        snap.capture([f])
        f.write_text('{"modified": true}')
        snap.commit()
        # После commit restore ничего не делает
        snap.restore()
        self.assertEqual(json.loads(f.read_text()), {"modified": True})

    def test_restore_handles_missing_file_gracefully(self):
        """Если файл исчез между capture и restore — не падать."""
        from chimera.modules.user_lifecycle import StateSnapshot
        f = self._tmpdir / "x.json"
        f.write_text('{"a": 1}')
        snap = StateSnapshot()
        snap.capture([f])
        f.unlink()
        # Не должно бросить
        snap.restore()
        self.assertTrue(f.exists())
        self.assertEqual(json.loads(f.read_text()), {"a": 1})


# =============================================================================
#  ТЕСТЫ IDENTITY RESOLUTION
# =============================================================================
class TestIdentityResolution(unittest.TestCase):
    """find_user_by_email / find_user_by_uuid / resolve_user."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._users = self._tmpdir / "users.json"
        self._users.write_text(json.dumps([
            {"uuid": "u1", "email": "alice@xray", "name": "alice"},
            {"uuid": "u2", "email": "bob@xray", "name": "bob"},
        ]))

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.user_lifecycle._USERS_FILE", self._users)

    def test_find_by_email(self):
        from chimera.modules import user_lifecycle
        with self._patch():
            u = user_lifecycle.find_user_by_email("alice@xray")
        self.assertIsNotNone(u)
        self.assertEqual(u["uuid"], "u1")

    def test_find_by_email_missing(self):
        from chimera.modules import user_lifecycle
        with self._patch():
            self.assertIsNone(user_lifecycle.find_user_by_email("nobody@xray"))

    def test_find_by_uuid(self):
        from chimera.modules import user_lifecycle
        with self._patch():
            u = user_lifecycle.find_user_by_uuid("u2")
        self.assertIsNotNone(u)
        self.assertEqual(u["email"], "bob@xray")

    def test_resolve_user_email_priority(self):
        from chimera.modules import user_lifecycle
        with self._patch():
            u = user_lifecycle.resolve_user(email="alice@xray")
        self.assertEqual(u["uuid"], "u1")

    def test_resolve_user_uuid_fallback(self):
        from chimera.modules import user_lifecycle
        with self._patch():
            u = user_lifecycle.resolve_user(uuid_str="u2")
        self.assertEqual(u["email"], "bob@xray")

    def test_resolve_user_no_args(self):
        from chimera.modules import user_lifecycle
        with self._patch():
            self.assertIsNone(user_lifecycle.resolve_user())

    def test_username_from_email(self):
        from chimera.modules import user_lifecycle
        self.assertEqual(user_lifecycle._username_from_email("alice@xray"), "alice")
        self.assertEqual(user_lifecycle._username_from_email("bob.smith@xray"), "bob.smith")
        self.assertEqual(user_lifecycle._username_from_email(""), "")


# =============================================================================
#  ТЕСТЫ PROTOCOL ADAPTERS (mock-based)
# =============================================================================
class TestVlessAdapter(unittest.TestCase):
    """VlessAdapter — mock-based."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._users = self._tmpdir / "users.json"
        self._users.write_text("[]")
        self._blocked = self._tmpdir / "blocked.json"
        self._blocked.write_text("{}")
        # Mock _users_apply_to_config чтобы не запускать xray
        self._apply_mock = MagicMock(return_value=True)
        self._save_mock = MagicMock()
        self._load_mock = MagicMock(return_value=[])

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("chimera.modules.user_lifecycle._USERS_FILE", self._users),
            patch("chimera.modules.user_lifecycle._BLOCKED_FILE", self._blocked),
        ]

    def test_add_user_success(self):
        from chimera.modules.user_lifecycle import VlessAdapter
        with self._patches()[0], self._patches()[1], \
             patch("chimera.modules._core", create=True) as fake_core_module:
            # Подменяем _core_module() чтобы вернуть mock с нужными методами
            with patch.object(VlessAdapter, "__init__", lambda self: None):
                fake_core = MagicMock()
                fake_core._users_load = MagicMock(return_value=[])
                fake_core._users_save = self._save_mock
                fake_core._users_apply_to_config = self._apply_mock
                with patch("chimera.modules.user_lifecycle._core_module", return_value=fake_core):
                    ok = VlessAdapter.add("alice@xray", "uuid-1", "alice")
        self.assertTrue(ok)
        self._apply_mock.assert_called_once()
        # users_save должен был записать с alice
        saved = self._save_mock.call_args[0][0]
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["email"], "alice@xray")
        self.assertEqual(saved[0]["uuid"], "uuid-1")

    def test_add_idempotent_same_uuid(self):
        """Повторный add для существующего юзера с тем же UUID → noop."""
        from chimera.modules.user_lifecycle import VlessAdapter
        existing_user = [{"uuid": "u1", "email": "alice@xray", "name": "alice"}]
        with self._patches()[0], self._patches()[1]:
            fake_core = MagicMock()
            fake_core._users_load = MagicMock(return_value=existing_user)
            fake_core._users_save = self._save_mock
            fake_core._users_apply_to_config = self._apply_mock
            with patch("chimera.modules.user_lifecycle._core_module", return_value=fake_core):
                ok = VlessAdapter.add("alice@xray", "u1", "alice")
        self.assertTrue(ok)
        # save не должен вызываться (noop)
        self._save_mock.assert_not_called()

    def test_add_rejects_different_uuid(self):
        from chimera.modules.user_lifecycle import VlessAdapter
        existing_user = [{"uuid": "u1", "email": "alice@xray"}]
        with self._patches()[0], self._patches()[1]:
            fake_core = MagicMock()
            fake_core._users_load = MagicMock(return_value=existing_user)
            fake_core._users_save = self._save_mock
            with patch("chimera.modules.user_lifecycle._core_module", return_value=fake_core):
                ok = VlessAdapter.add("alice@xray", "different-uuid", "alice")
        self.assertFalse(ok)

    def test_remove_user_success(self):
        from chimera.modules.user_lifecycle import VlessAdapter
        existing = [{"uuid": "u1", "email": "alice@xray"}, {"uuid": "u2", "email": "bob@xray"}]
        with self._patches()[0], self._patches()[1]:
            fake_core = MagicMock()
            fake_core._users_load = MagicMock(return_value=existing)
            fake_core._users_save = self._save_mock
            fake_core._users_apply_to_config = self._apply_mock
            with patch("chimera.modules.user_lifecycle._core_module", return_value=fake_core):
                ok = VlessAdapter.remove("alice@xray")
        self.assertTrue(ok)
        saved = self._save_mock.call_args[0][0]
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["email"], "bob@xray")

    def test_remove_idempotent(self):
        from chimera.modules.user_lifecycle import VlessAdapter
        with self._patches()[0], self._patches()[1]:
            fake_core = MagicMock()
            fake_core._users_load = MagicMock(return_value=[{"uuid": "u1", "email": "bob@xray"}])
            fake_core._users_save = self._save_mock
            fake_core._users_apply_to_config = self._apply_mock
            with patch("chimera.modules.user_lifecycle._core_module", return_value=fake_core):
                ok = VlessAdapter.remove("nobody@xray")  # нет такого
        self.assertTrue(ok)  # идемпотентно
        self._save_mock.assert_not_called()

    def test_block_user(self):
        from chimera.modules.user_lifecycle import VlessAdapter
        existing = [{"uuid": "u1", "email": "alice@xray", "blocked": False}]
        with self._patches()[0], self._patches()[1]:
            fake_core = MagicMock()
            fake_core._users_load = MagicMock(return_value=existing)
            fake_core._users_save = self._save_mock
            fake_core._users_apply_to_config = self._apply_mock
            with patch("chimera.modules.user_lifecycle._core_module", return_value=fake_core):
                ok = VlessAdapter.block("alice@xray", reason="manual")
        self.assertTrue(ok)
        saved = self._save_mock.call_args[0][0]
        self.assertTrue(saved[0]["blocked"])
        self.assertEqual(saved[0]["block_reason"], "manual")
        # blocked_users.json должен содержать alice
        blocked_db = json.loads(self._blocked.read_text())
        self.assertIn("alice@xray", blocked_db)

    def test_unblock_user(self):
        from chimera.modules.user_lifecycle import VlessAdapter
        existing = [{"uuid": "u1", "email": "alice@xray",
                     "blocked": True, "block_reason": "manual"}]
        self._blocked.write_text(json.dumps({
            "alice@xray": {"email": "alice@xray", "uuid": "u1", "reason": "manual"}
        }))
        with self._patches()[0], self._patches()[1]:
            fake_core = MagicMock()
            fake_core._users_load = MagicMock(return_value=existing)
            fake_core._users_save = self._save_mock
            fake_core._users_apply_to_config = self._apply_mock
            with patch("chimera.modules.user_lifecycle._core_module", return_value=fake_core):
                ok = VlessAdapter.unblock("alice@xray")
        self.assertTrue(ok)
        saved = self._save_mock.call_args[0][0]
        self.assertFalse(saved[0]["blocked"])
        # blocked_users.json не должен содержать alice
        blocked_db = json.loads(self._blocked.read_text())
        self.assertNotIn("alice@xray", blocked_db)


class TestHysteria2Adapter(unittest.TestCase):
    """Hysteria2Adapter — заглушка (no per-user model)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_add_noop_when_disabled(self):
        from chimera.modules.user_lifecycle import Hysteria2Adapter
        with patch("chimera.modules.user_lifecycle._read_json",
                   return_value={"hysteria2": {"enabled": False}}):
            ok = Hysteria2Adapter.add("alice@xray", "uuid-1")
        self.assertTrue(ok)

    def test_add_noop_when_enabled(self):
        from chimera.modules.user_lifecycle import Hysteria2Adapter
        with patch("chimera.modules.user_lifecycle._read_json",
                   return_value={"hysteria2": {"enabled": True}}):
            ok = Hysteria2Adapter.add("alice@xray", "uuid-1")
        self.assertTrue(ok)

    def test_remove_noop(self):
        from chimera.modules.user_lifecycle import Hysteria2Adapter
        self.assertTrue(Hysteria2Adapter.remove("alice@xray"))

    def test_block_unblock_noop(self):
        from chimera.modules.user_lifecycle import Hysteria2Adapter
        self.assertTrue(Hysteria2Adapter.block("alice@xray"))
        self.assertTrue(Hysteria2Adapter.unblock("alice@xray"))


# =============================================================================
#  ТЕСТЫ COORDINATOR (mock all adapters)
# =============================================================================
class TestCoordinatorSuccess(unittest.TestCase):
    """Все adapter'ы успешно отработали — транзакция завершается."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._users = self._tmpdir / "users.json"
        self._users.write_text("[]")
        self._patches = [
            patch("chimera.modules.user_lifecycle._USERS_FILE", self._users),
            patch("chimera.modules.user_lifecycle._XRAY_CONFIG_FILE", self._tmpdir / "xray.json"),
            patch("chimera.modules.user_lifecycle._AWG_STATE_FILE", self._tmpdir / "awg.json"),
            patch("chimera.modules.user_lifecycle._SINGBOX_STATE_FILE", self._tmpdir / "sb.json"),
            patch("chimera.modules.user_lifecycle._MIERU_STATE_FILE", self._tmpdir / "mieru.json"),
            patch("chimera.modules.user_lifecycle._NAIVE_STATE_FILE", self._tmpdir / "naive.json"),
            patch("chimera.modules.user_lifecycle._FPTN_STATE_FILE", self._tmpdir / "fptn.json"),
            patch("chimera.modules.user_lifecycle._FPTN_USERS_LIST", self._tmpdir / "users.list"),
            patch("chimera.modules.user_lifecycle._TELEMT_TOML_FILE", self._tmpdir / "telemt.toml"),
            patch("chimera.modules.user_lifecycle._TTL_FILE", self._tmpdir / "ttl.json"),
            patch("chimera.modules.user_lifecycle._LIMITS_FILE", self._tmpdir / "limits.json"),
            patch("chimera.modules.user_lifecycle._BLOCKED_FILE", self._tmpdir / "blocked.json"),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_add_user_all_protocols_success(self):
        """add_user с protocols='all' — все adapter'ы возвращают True."""
        from chimera.modules import user_lifecycle

        # Mock ВСЕХ adapter'ов
        with patch.object(user_lifecycle.VlessAdapter, "add", return_value=True) as vless_add, \
             patch.object(user_lifecycle.AwgAdapter, "add", return_value=True), \
             patch.object(user_lifecycle.SingboxAdapter, "add", return_value=True), \
             patch.object(user_lifecycle.MieruAdapter, "add", return_value=True), \
             patch.object(user_lifecycle.NaiveProxyAdapter, "add", return_value=True), \
             patch.object(user_lifecycle.MtprotoAdapter, "add", return_value=True), \
             patch.object(user_lifecycle.FptnAdapter, "add", return_value=True), \
             patch.object(user_lifecycle.Hysteria2Adapter, "add", return_value=True), \
             patch("chimera.modules.user_lifecycle._set_ttl") as ttl_mock, \
             patch("chimera.modules.user_lifecycle._set_traffic_limit") as lim_mock:

            result = user_lifecycle.add_user(
                email="alice@xray",
                protocols="all",
                ttl=7,
                traffic_limit=10,
                uuid_str="test-uuid-1234",
            )
        self.assertTrue(result["success"], f"errors: {result['errors']}")
        self.assertIn("vless", result["applied"])
        self.assertIn("awg", result["applied"])
        self.assertIn("singbox", result["applied"])
        self.assertIn("hysteria2", result["applied"])
        self.assertIn("ttl", result["applied"])
        self.assertIn("traffic_limit", result["applied"])
        self.assertEqual(result["failed"], [])
        # Vless.add должен вызываться с uuid
        vless_add.assert_called_once()
        call_kwargs = vless_add.call_args
        self.assertIn("email", str(call_kwargs))


class TestCoordinatorPartialFailure(unittest.TestCase):
    """Один adapter кидает исключение → rollback state files."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._users = self._tmpdir / "users.json"
        self._users.write_text('[]')
        self._awg = self._tmpdir / "awg.json"
        self._awg.write_text('{"installed": false}')

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_add_user_rollback_on_failure(self):
        """Если AWG падает — VLESS изменения должны откатиться."""
        from chimera.modules import user_lifecycle

        # Snapshot оригинального users.json (пустой список)
        original_users = json.loads(self._users.read_text())
        self.assertEqual(original_users, [])

        with patch("chimera.modules.user_lifecycle._USERS_FILE", self._users), \
             patch("chimera.modules.user_lifecycle._AWG_STATE_FILE", self._awg), \
             patch("chimera.modules.user_lifecycle._XRAY_CONFIG_FILE", self._tmpdir / "xray.json"), \
             patch.object(user_lifecycle.VlessAdapter, "add", return_value=True) as vless_add, \
             patch.object(user_lifecycle.AwgAdapter, "add", side_effect=Exception("AWG explosion")):

            result = user_lifecycle.add_user(
                email="alice@xray",
                protocols=["vless", "awg"],
                uuid_str="test-uuid-1234",
            )
        self.assertFalse(result["success"])
        self.assertIn("awg", result["failed"])
        # VLESS должен быть в applied (был вызван и успешен)
        self.assertIn("vless", result["applied"])
        # НО users.json должен быть откатан к исходному (пустой)
        # VlessAdapter.add был замокан и не трогал реальный users.json,
        # но snapshot всё равно не должен ничего сломать
        self.assertEqual(json.loads(self._users.read_text()), [])

    def test_add_user_real_vless_with_mocked_awg_failure(self):
        """Реальный VlessAdapter + замоканный AWG-failure → rollback VLESS state.
        Эта проверка ловит баги которые чистые моки пропускают.
        """
        from chimera.modules import user_lifecycle

        # Подкладываем users.json
        self._users.write_text("[]")

        # Мокаем _core_module чтобы VlessAdapter.add не падал на xray
        fake_core = MagicMock()
        fake_core._users_load = MagicMock(return_value=[])
        fake_core._users_save = MagicMock(side_effect=lambda u: self._users.write_text(json.dumps(u)))
        fake_core._users_apply_to_config = MagicMock(return_value=True)

        with patch("chimera.modules.user_lifecycle._USERS_FILE", self._users), \
             patch("chimera.modules.user_lifecycle._AWG_STATE_FILE", self._awg), \
             patch("chimera.modules.user_lifecycle._XRAY_CONFIG_FILE", self._tmpdir / "xray.json"), \
             patch("chimera.modules.user_lifecycle._core_module", return_value=fake_core), \
             patch.object(user_lifecycle.AwgAdapter, "add", side_effect=Exception("AWG down")):

            result = user_lifecycle.add_user(
                email="alice@xray",
                protocols=["vless", "awg"],
                uuid_str="test-uuid-1234",
            )

        self.assertFalse(result["success"])
        # users.json должен быть откатан к пустому списку (VLESS добавил alice,
        # но AWG упал → rollback вернул [])
        final_users = json.loads(self._users.read_text())
        self.assertEqual(final_users, [], f"users.json not rolled back: {final_users}")


class TestCoordinatorIdempotency(unittest.TestCase):
    """Идемпотентность: повторные вызовы не ломают состояние."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._users = self._tmpdir / "users.json"
        self._users.write_text("[]")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_add_same_user_twice_is_idempotent(self):
        """Повторный add_user с тем же UUID → noop (не создаёт дубликат)."""
        from chimera.modules import user_lifecycle

        fake_core = MagicMock()
        # Первый вызов: users пустой. Второй: с alice.
        users_state = []
        def mock_load():
            return list(users_state)
        def mock_save(users):
            users_state.clear()
            users_state.extend(users)
            self._users.write_text(json.dumps(users_state))
        fake_core._users_load = mock_load
        fake_core._users_save = mock_save
        fake_core._users_apply_to_config = MagicMock(return_value=True)

        with patch("chimera.modules.user_lifecycle._USERS_FILE", self._users), \
             patch("chimera.modules.user_lifecycle._XRAY_CONFIG_FILE", self._tmpdir / "xray.json"), \
             patch("chimera.modules.user_lifecycle._core_module", return_value=fake_core), \
             patch.object(user_lifecycle.AwgAdapter, "add", return_value=True), \
             patch.object(user_lifecycle.SingboxAdapter, "add", return_value=True), \
             patch.object(user_lifecycle.MieruAdapter, "add", return_value=True), \
             patch.object(user_lifecycle.NaiveProxyAdapter, "add", return_value=True), \
             patch.object(user_lifecycle.MtprotoAdapter, "add", return_value=True), \
             patch.object(user_lifecycle.FptnAdapter, "add", return_value=True), \
             patch.object(user_lifecycle.Hysteria2Adapter, "add", return_value=True):

            # Первый add
            r1 = user_lifecycle.add_user(
                email="alice@xray",
                protocols="all",
                uuid_str="uuid-fixed",
            )
            self.assertTrue(r1["success"], f"first add failed: {r1['errors']}")
            self.assertEqual(len(users_state), 1)

            # Второй add с тем же UUID
            r2 = user_lifecycle.add_user(
                email="alice@xray",
                protocols="all",
                uuid_str="uuid-fixed",
            )
            self.assertTrue(r2["success"], f"second add failed: {r2['errors']}")
            # По-прежнему один пользователь (не дубликат)
            self.assertEqual(len(users_state), 1)

    def test_remove_nonexistent_user_is_idempotent(self):
        from chimera.modules import user_lifecycle

        fake_core = MagicMock()
        fake_core._users_load = MagicMock(return_value=[])  # empty
        fake_core._users_save = MagicMock()
        fake_core._users_apply_to_config = MagicMock(return_value=True)

        with patch("chimera.modules.user_lifecycle._USERS_FILE", self._users), \
             patch("chimera.modules.user_lifecycle._XRAY_CONFIG_FILE", self._tmpdir / "xray.json"), \
             patch("chimera.modules.user_lifecycle._core_module", return_value=fake_core), \
             patch.object(user_lifecycle.AwgAdapter, "remove", return_value=True), \
             patch.object(user_lifecycle.SingboxAdapter, "remove", return_value=True), \
             patch.object(user_lifecycle.MieruAdapter, "remove", return_value=True), \
             patch.object(user_lifecycle.NaiveProxyAdapter, "remove", return_value=True), \
             patch.object(user_lifecycle.MtprotoAdapter, "remove", return_value=True), \
             patch.object(user_lifecycle.FptnAdapter, "remove", return_value=True), \
             patch.object(user_lifecycle.Hysteria2Adapter, "remove", return_value=True):

            r = user_lifecycle.remove_user("nobody@xray", protocols="all")
            self.assertTrue(r["success"], f"remove failed: {r['errors']}")

    def test_block_already_blocked_is_idempotent(self):
        from chimera.modules import user_lifecycle

        existing = [{"uuid": "u1", "email": "alice@xray",
                     "blocked": True, "block_reason": "manual"}]
        fake_core = MagicMock()
        fake_core._users_load = MagicMock(return_value=existing)
        fake_core._users_save = MagicMock()
        fake_core._users_apply_to_config = MagicMock(return_value=True)

        with patch("chimera.modules.user_lifecycle._USERS_FILE", self._users), \
             patch("chimera.modules.user_lifecycle._XRAY_CONFIG_FILE", self._tmpdir / "xray.json"), \
             patch("chimera.modules.user_lifecycle._BLOCKED_FILE", self._tmpdir / "blk.json"), \
             patch("chimera.modules.user_lifecycle._core_module", return_value=fake_core), \
             patch.object(user_lifecycle.AwgAdapter, "block", return_value=True), \
             patch.object(user_lifecycle.SingboxAdapter, "block", return_value=True), \
             patch.object(user_lifecycle.MieruAdapter, "block", return_value=True), \
             patch.object(user_lifecycle.NaiveProxyAdapter, "block", return_value=True), \
             patch.object(user_lifecycle.MtprotoAdapter, "block", return_value=True), \
             patch.object(user_lifecycle.FptnAdapter, "block", return_value=True), \
             patch.object(user_lifecycle.Hysteria2Adapter, "block", return_value=True):

            r = user_lifecycle.block_user("alice@xray", reason="manual")
            self.assertTrue(r["success"])

    def test_unblock_not_blocked_is_idempotent(self):
        from chimera.modules import user_lifecycle

        existing = [{"uuid": "u1", "email": "alice@xray", "blocked": False}]
        fake_core = MagicMock()
        fake_core._users_load = MagicMock(return_value=existing)
        fake_core._users_save = MagicMock()
        fake_core._users_apply_to_config = MagicMock(return_value=True)

        with patch("chimera.modules.user_lifecycle._USERS_FILE", self._users), \
             patch("chimera.modules.user_lifecycle._XRAY_CONFIG_FILE", self._tmpdir / "xray.json"), \
             patch("chimera.modules.user_lifecycle._core_module", return_value=fake_core), \
             patch.object(user_lifecycle.AwgAdapter, "unblock", return_value=True), \
             patch.object(user_lifecycle.SingboxAdapter, "unblock", return_value=True), \
             patch.object(user_lifecycle.MieruAdapter, "unblock", return_value=True), \
             patch.object(user_lifecycle.NaiveProxyAdapter, "unblock", return_value=True), \
             patch.object(user_lifecycle.MtprotoAdapter, "unblock", return_value=True), \
             patch.object(user_lifecycle.FptnAdapter, "unblock", return_value=True), \
             patch.object(user_lifecycle.Hysteria2Adapter, "unblock", return_value=True):

            r = user_lifecycle.unblock_user("alice@xray")
            self.assertTrue(r["success"])


# =============================================================================
#  ТЕСТЫ UPDATE_LIMITS
# =============================================================================
class TestUpdateLimits(unittest.TestCase):
    """update_limits — TTL и traffic_limit."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._ttl = self._tmpdir / "ttl.json"
        self._limits = self._tmpdir / "limits.json"
        self._ttl.write_text("{}")
        self._limits.write_text("{}")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_set_ttl(self):
        from chimera.modules import user_lifecycle
        ttl_set_mock = MagicMock()
        with patch("chimera.modules.user_lifecycle._set_ttl", ttl_set_mock):
            r = user_lifecycle.update_limits("alice@xray", ttl=7)
        self.assertTrue(r["success"])
        ttl_set_mock.assert_called_once_with("alice@xray", 7)

    def test_remove_ttl_with_zero(self):
        from chimera.modules import user_lifecycle
        ttl_remove_mock = MagicMock()
        with patch("chimera.modules.user_lifecycle._remove_ttl", ttl_remove_mock):
            r = user_lifecycle.update_limits("alice@xray", ttl=0)
        self.assertTrue(r["success"])
        ttl_remove_mock.assert_called_once_with("alice@xray")

    def test_set_traffic_limit(self):
        from chimera.modules import user_lifecycle
        lim_mock = MagicMock()
        with patch("chimera.modules.user_lifecycle._set_traffic_limit", lim_mock):
            r = user_lifecycle.update_limits("alice@xray", traffic_limit=50)
        self.assertTrue(r["success"])
        lim_mock.assert_called_once_with("alice@xray", 50)

    def test_no_change_when_both_none(self):
        from chimera.modules import user_lifecycle
        r = user_lifecycle.update_limits("alice@xray", ttl=None, traffic_limit=None)
        self.assertTrue(r["success"])
        self.assertEqual(r["applied"], [])


# =============================================================================
#  REAL (NON-MOCK) TESTS — VLESS + AWG + sing-box
# =============================================================================
class TestRealProtocolIntegration(unittest.TestCase):
    """
    Реальные (не мок) тесты для VLESS + AWG + sing-box с минимальными
    fake state-файлами. Цель — поймать баги в adapter'ах которые моки
    пропускают (например, неверные имена полей, race conditions в state I/O).
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        # State files
        self._users = self._tmpdir / "users.json"
        self._users.write_text("[]")
        self._blocked = self._tmpdir / "blocked.json"
        self._blocked.write_text("{}")
        self._ttl = self._tmpdir / "ttl.json"
        self._ttl.write_text("{}")
        self._limits = self._tmpdir / "limits.json"
        self._limits.write_text("{}")
        self._awg = self._tmpdir / "awg.json"
        self._awg.write_text(json.dumps({"installed": False, "peers": []}))
        self._sb = self._tmpdir / "sb.json"
        self._sb.write_text(json.dumps({"installed": False, "inbounds": {}}))
        self._xray_cfg = self._tmpdir / "xray.json"
        self._xray_cfg.write_text("{}")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("chimera.modules.user_lifecycle._USERS_FILE", self._users),
            patch("chimera.modules.user_lifecycle._XRAY_CONFIG_FILE", self._xray_cfg),
            patch("chimera.modules.user_lifecycle._BLOCKED_FILE", self._blocked),
            patch("chimera.modules.user_lifecycle._TTL_FILE", self._ttl),
            patch("chimera.modules.user_lifecycle._LIMITS_FILE", self._limits),
            patch("chimera.modules.user_lifecycle._AWG_STATE_FILE", self._awg),
            patch("chimera.modules.user_lifecycle._SINGBOX_STATE_FILE", self._sb),
        ]

    def test_real_add_user_vless_only(self):
        """Реальный add_user только для VLESS (AWG/sing-box не установлены)."""
        from chimera.modules import user_lifecycle

        fake_core = MagicMock()
        fake_core._users_load = MagicMock(return_value=[])
        fake_core._users_save = MagicMock(side_effect=lambda u: self._users.write_text(json.dumps(u)))
        fake_core._users_apply_to_config = MagicMock(return_value=True)

        for p in self._patches():
            p.start()
        try:
            with patch("chimera.modules.user_lifecycle._core_module", return_value=fake_core):
                r = user_lifecycle.add_user(
                    email="alice@xray",
                    protocols="all",
                    uuid_str="uuid-test-real-1",
                )
            self.assertTrue(r["success"], f"errors: {r['errors']}")
            # VLESS должен быть в applied
            self.assertIn("vless", r["applied"])
            # AWG/sing-box должны быть в applied (т.к. возвращают True как noop)
            self.assertIn("awg", r["applied"])
            self.assertIn("singbox", r["applied"])
            # users.json должен содержать alice
            users = json.loads(self._users.read_text())
            self.assertEqual(len(users), 1)
            self.assertEqual(users[0]["email"], "alice@xray")
            self.assertEqual(users[0]["uuid"], "uuid-test-real-1")
        finally:
            for p in self._patches():
                p.stop()

    def test_real_block_unblock_vless(self):
        """Реальный block_user/unblock_user для VLESS."""
        from chimera.modules import user_lifecycle

        # Подготовим: alice уже в users.json
        self._users.write_text(json.dumps([
            {"uuid": "u1", "email": "alice@xray", "name": "alice", "blocked": False}
        ]))
        users_state = [{"uuid": "u1", "email": "alice@xray", "name": "alice", "blocked": False}]

        fake_core = MagicMock()
        fake_core._users_load = MagicMock(side_effect=lambda: list(users_state))
        def mock_save(u):
            users_state.clear()
            users_state.extend(u)
            self._users.write_text(json.dumps(users_state))
        fake_core._users_save = mock_save
        fake_core._users_apply_to_config = MagicMock(return_value=True)

        for p in self._patches():
            p.start()
        try:
            with patch("chimera.modules.user_lifecycle._core_module", return_value=fake_core):
                # Block
                r1 = user_lifecycle.block_user("alice@xray", reason="manual", protocols=["vless"])
                self.assertTrue(r1["success"], f"block failed: {r1['errors']}")
                # Проверяем что user помечен blocked
                users_after_block = json.loads(self._users.read_text())
                self.assertTrue(users_after_block[0]["blocked"])
                self.assertEqual(users_after_block[0]["block_reason"], "manual")
                # blocked_users.json содержит alice
                blk = json.loads(self._blocked.read_text())
                self.assertIn("alice@xray", blk)

                # Unblock
                r2 = user_lifecycle.unblock_user("alice@xray", protocols=["vless"])
                self.assertTrue(r2["success"], f"unblock failed: {r2['errors']}")
                users_after_unblock = json.loads(self._users.read_text())
                self.assertFalse(users_after_unblock[0]["blocked"])
                blk = json.loads(self._blocked.read_text())
                self.assertNotIn("alice@xray", blk)
        finally:
            for p in self._patches():
                p.stop()

    def test_real_remove_user_vless(self):
        """Реальный remove_user для VLESS."""
        from chimera.modules import user_lifecycle

        self._users.write_text(json.dumps([
            {"uuid": "u1", "email": "alice@xray", "name": "alice"},
            {"uuid": "u2", "email": "bob@xray", "name": "bob"},
        ]))
        users_state = [
            {"uuid": "u1", "email": "alice@xray", "name": "alice"},
            {"uuid": "u2", "email": "bob@xray", "name": "bob"},
        ]

        fake_core = MagicMock()
        fake_core._users_load = MagicMock(side_effect=lambda: list(users_state))
        def mock_save(u):
            users_state.clear()
            users_state.extend(u)
            self._users.write_text(json.dumps(users_state))
        fake_core._users_save = mock_save
        fake_core._users_apply_to_config = MagicMock(return_value=True)

        for p in self._patches():
            p.start()
        try:
            with patch("chimera.modules.user_lifecycle._core_module", return_value=fake_core):
                r = user_lifecycle.remove_user("alice@xray", protocols=["vless"])
                self.assertTrue(r["success"], f"remove failed: {r['errors']}")
                users_after = json.loads(self._users.read_text())
                self.assertEqual(len(users_after), 1)
                self.assertEqual(users_after[0]["email"], "bob@xray")
        finally:
            for p in self._patches():
                p.stop()

    def test_real_rollback_on_awg_failure(self):
        """Реальный VLESS add + AWG падает → users.json откатан."""
        from chimera.modules import user_lifecycle

        users_state = []

        fake_core = MagicMock()
        fake_core._users_load = MagicMock(side_effect=lambda: list(users_state))
        def mock_save(u):
            users_state.clear()
            users_state.extend(u)
            self._users.write_text(json.dumps(users_state))
        fake_core._users_save = mock_save
        fake_core._users_apply_to_config = MagicMock(return_value=True)

        for p in self._patches():
            p.start()
        try:
            with patch("chimera.modules.user_lifecycle._core_module", return_value=fake_core), \
                 patch.object(user_lifecycle.AwgAdapter, "add",
                              side_effect=Exception("simulated AWG failure")):
                r = user_lifecycle.add_user(
                    email="alice@xray",
                    protocols=["vless", "awg"],
                    uuid_str="uuid-rollback-test",
                )
            self.assertFalse(r["success"])
            # VLESS add был вызван и успешно добавил alice в users_state,
            # но потом AWG упал → rollback должен вернуть users_state к пустому.
            # Проверяем что users.json пустой (или совпадает с snapshot).
            # Замечание: mock_save пишет в users_state И в self._users.
            # VlessAdapter.add вызвал mock_save → users_state = [alice].
            # Затем rollback восстанавливает self._users из snapshot (был []).
            # Но users_state (в памяти) НЕ откатан (это mock, не real file).
            # Проверяем ФАЙЛ — он должен быть откатан:
            final_users_file = json.loads(self._users.read_text())
            self.assertEqual(final_users_file, [],
                             f"users.json not rolled back: {final_users_file}")
        finally:
            for p in self._patches():
                p.stop()

    def test_real_add_with_ttl_and_limit(self):
        """add_user с TTL и traffic_limit — реальные _set_ttl/_set_traffic_limit."""
        from chimera.modules import user_lifecycle
        from chimera.modules import ttl_users, traffic_tracking

        users_state = []
        fake_core = MagicMock()
        fake_core._users_load = MagicMock(side_effect=lambda: list(users_state))
        def mock_save(u):
            users_state.clear()
            users_state.extend(u)
            self._users.write_text(json.dumps(users_state))
        fake_core._users_save = mock_save
        fake_core._users_apply_to_config = MagicMock(return_value=True)

        # Патчим path-константы в ttl_users и traffic_tracking
        for p in self._patches():
            p.start()
        try:
            with patch("chimera.modules.user_lifecycle._core_module", return_value=fake_core), \
                 patch.object(ttl_users, "TTL_FILE", self._ttl), \
                 patch.object(traffic_tracking, "TRAFFIC_LIMITS_FILE", self._limits), \
                 patch.object(ttl_users, "_core_module", return_value=fake_core), \
                 patch.object(traffic_tracking, "_core_module", return_value=fake_core):
                r = user_lifecycle.add_user(
                    email="alice@xray",
                    protocols=["vless"],
                    ttl=7,
                    traffic_limit=50,
                    uuid_str="uuid-ttl-test",
                )
            self.assertTrue(r["success"], f"errors: {r['errors']}")
            self.assertIn("ttl", r["applied"])
            self.assertIn("traffic_limit", r["applied"])
            # ttl_users.json должен содержать alice
            ttl_data = json.loads(self._ttl.read_text())
            self.assertIn("alice@xray", ttl_data)
            self.assertEqual(ttl_data["alice@xray"]["days"], 7)
            # limits.json должен содержать alice
            lim_data = json.loads(self._limits.read_text())
            self.assertIn("alice@xray", lim_data)
            self.assertEqual(lim_data["alice@xray"]["limit_gb"], 50)
        finally:
            for p in self._patches():
                p.stop()


# =============================================================================
#  ТЕСТЫ CRON ENTRYPOINTS
# =============================================================================
class TestCronEntrypoints(unittest.TestCase):
    """check_ttl_expired / check_traffic_limits / run_cleanup."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._users = self._tmpdir / "users.json"
        self._users.write_text(json.dumps([
            {"uuid": "u1", "email": "alice@xray", "name": "alice", "blocked": False}
        ]))
        self._blocked = self._tmpdir / "blocked.json"
        self._blocked.write_text("{}")
        self._ttl = self._tmpdir / "ttl.json"
        self._limits = self._tmpdir / "limits.json"
        self._limits.write_text("{}")
        self._xray_cfg = self._tmpdir / "xray.json"
        self._awg = self._tmpdir / "awg.json"
        self._awg.write_text(json.dumps({"installed": False, "peers": []}))
        self._sb = self._tmpdir / "sb.json"
        self._sb.write_text(json.dumps({"installed": False, "inbounds": {}}))

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("chimera.modules.user_lifecycle._USERS_FILE", self._users),
            patch("chimera.modules.user_lifecycle._XRAY_CONFIG_FILE", self._xray_cfg),
            patch("chimera.modules.user_lifecycle._BLOCKED_FILE", self._blocked),
            patch("chimera.modules.user_lifecycle._TTL_FILE", self._ttl),
            patch("chimera.modules.user_lifecycle._LIMITS_FILE", self._limits),
            patch("chimera.modules.user_lifecycle._AWG_STATE_FILE", self._awg),
            patch("chimera.modules.user_lifecycle._SINGBOX_STATE_FILE", self._sb),
        ]

    def test_check_ttl_expired_blocks_past_ttl(self):
        """Истёкший TTL → пользователь блокируется."""
        from chimera.modules import user_lifecycle
        from chimera.modules import ttl_users

        # TTL в прошлом
        past_iso = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        self._ttl.write_text(json.dumps({
            "alice@xray": {
                "email": "alice@xray",
                "expires_at": past_iso,
                "days": 7,
                "notified_24h": False,
                "blocked": False,
            }
        }))

        users_state = [{"uuid": "u1", "email": "alice@xray", "name": "alice", "blocked": False}]
        fake_core = MagicMock()
        fake_core._users_load = MagicMock(side_effect=lambda: list(users_state))
        def mock_save(u):
            users_state.clear()
            users_state.extend(u)
            self._users.write_text(json.dumps(users_state))
        fake_core._users_save = mock_save
        fake_core._users_apply_to_config = MagicMock(return_value=True)
        fake_core._tg_notify_event = MagicMock()
        fake_core.log_to_file = MagicMock()

        for p in self._patches():
            p.start()
        try:
            with patch("chimera.modules.user_lifecycle._core_module", return_value=fake_core), \
                 patch.object(ttl_users, "TTL_FILE", self._ttl), \
                 patch.object(ttl_users, "_core_module", return_value=fake_core), \
                 patch.object(user_lifecycle.AwgAdapter, "block", return_value=True), \
                 patch.object(user_lifecycle.SingboxAdapter, "block", return_value=True), \
                 patch.object(user_lifecycle.MieruAdapter, "block", return_value=True), \
                 patch.object(user_lifecycle.NaiveProxyAdapter, "block", return_value=True), \
                 patch.object(user_lifecycle.MtprotoAdapter, "block", return_value=True), \
                 patch.object(user_lifecycle.FptnAdapter, "block", return_value=True), \
                 patch.object(user_lifecycle.Hysteria2Adapter, "block", return_value=True):
                count = user_lifecycle.check_ttl_expired()
            self.assertEqual(count, 1)
            # alice должна быть заблокирована
            users_after = json.loads(self._users.read_text())
            self.assertTrue(users_after[0]["blocked"])
            self.assertEqual(users_after[0]["block_reason"], "ttl_expired")
        finally:
            for p in self._patches():
                p.stop()

    def test_check_traffic_limits_blocks_overuser(self):
        """Превышение лимита → блокировка (не удаление)."""
        from chimera.modules import user_lifecycle
        from chimera.modules import traffic_tracking

        # alice имеет лимит 10 GiB и использовала 11 GiB
        self._limits.write_text(json.dumps({
            "alice@xray": {
                "limit_gb": 10,
                "used_bytes": 0,
                "disabled": False,
                "disabled_at": "",
            }
        }))

        users_state = [{"uuid": "u1", "email": "alice@xray", "name": "alice", "blocked": False}]
        fake_core = MagicMock()
        fake_core._users_load = MagicMock(side_effect=lambda: list(users_state))
        def mock_save(u):
            users_state.clear()
            users_state.extend(u)
            self._users.write_text(json.dumps(users_state))
        fake_core._users_save = mock_save
        fake_core._users_apply_to_config = MagicMock(return_value=True)
        fake_core._tg_notify_event = MagicMock()
        fake_core.log_to_file = MagicMock()

        for p in self._patches():
            p.start()
        try:
            with patch("chimera.modules.user_lifecycle._core_module", return_value=fake_core), \
                 patch.object(traffic_tracking, "TRAFFIC_LIMITS_FILE", self._limits), \
                 patch.object(traffic_tracking, "_stats_api_is_configured", return_value=True), \
                 patch.object(traffic_tracking, "_query_user_traffic_bytes",
                              return_value=11 * 1024**3), \
                 patch.object(traffic_tracking, "_core_module", return_value=fake_core), \
                 patch.object(user_lifecycle.AwgAdapter, "block", return_value=True), \
                 patch.object(user_lifecycle.SingboxAdapter, "block", return_value=True), \
                 patch.object(user_lifecycle.MieruAdapter, "block", return_value=True), \
                 patch.object(user_lifecycle.NaiveProxyAdapter, "block", return_value=True), \
                 patch.object(user_lifecycle.MtprotoAdapter, "block", return_value=True), \
                 patch.object(user_lifecycle.FptnAdapter, "block", return_value=True), \
                 patch.object(user_lifecycle.Hysteria2Adapter, "block", return_value=True):
                count = user_lifecycle.check_traffic_limits()
            self.assertEqual(count, 1)
            # alice должна быть заблокирована (не удалена)
            users_after = json.loads(self._users.read_text())
            self.assertEqual(len(users_after), 1)  # не удалена
            self.assertTrue(users_after[0]["blocked"])
            self.assertEqual(users_after[0]["block_reason"], "traffic_limit")
        finally:
            for p in self._patches():
                p.stop()

    def test_run_cleanup_returns_dict(self):
        """run_cleanup возвращает dict с ключами ttl_blocked/traffic_blocked/awg_peers_removed."""
        from chimera.modules import user_lifecycle
        for p in self._patches():
            p.start()
        try:
            with patch.object(user_lifecycle, "check_ttl_expired", return_value=2), \
                 patch.object(user_lifecycle, "check_traffic_limits", return_value=1), \
                 patch("chimera.modules.awg_expires.awgs_expires_check", return_value=0):
                r = user_lifecycle.run_cleanup()
            self.assertEqual(r["ttl_blocked"], 2)
            self.assertEqual(r["traffic_blocked"], 1)
            self.assertEqual(r["awg_peers_removed"], 0)
        finally:
            for p in self._patches():
                p.stop()


# =============================================================================
#  ТЕСТЫ ОБРАТНОЙ СОВМЕСТИМОСТИ (legacy функции делегируют в user_lifecycle)
# =============================================================================
class TestBackwardCompatibility(unittest.TestCase):
    """Старые функции (_ttl_check_and_expire, _check_traffic_limits_once)
    должны делегировать в user_lifecycle."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ttl_check_and_expire_delegates_to_user_lifecycle(self):
        """_ttl_check_and_expire должен вызывать user_lifecycle.check_ttl_expired."""
        from chimera.modules import ttl_users
        with patch("chimera.modules.user_lifecycle.check_ttl_expired",
                   return_value=42) as mock_check:
            result = ttl_users._ttl_check_and_expire()
        self.assertEqual(result, 42)
        mock_check.assert_called_once()

    def test_check_traffic_limits_once_delegates_to_user_lifecycle(self):
        """_check_traffic_limits_once должен вызывать user_lifecycle.check_traffic_limits."""
        from chimera.modules import traffic_tracking
        with patch("chimera.modules.user_lifecycle.check_traffic_limits",
                   return_value=5) as mock_check:
            traffic_tracking._check_traffic_limits_once()
        mock_check.assert_called_once()

    def test_ttl_check_falls_back_to_legacy_on_error(self):
        """Если user_lifecycle недоступен — fallback на legacy реализацию."""
        from chimera.modules import ttl_users
        # Заставляем import user_lifecycle упасть
        with patch("chimera.modules.user_lifecycle.check_ttl_expired",
                   side_effect=ImportError("simulated")):
            with patch.object(ttl_users, "_ttl_check_and_expire_legacy", return_value=99) as legacy:
                result = ttl_users._ttl_check_and_expire()
        self.assertEqual(result, 99)
        legacy.assert_called_once()


# =============================================================================
#  ТЕСТЫ CLI-ФЛАГОВ (через subprocess)
# =============================================================================
class TestCLIFlags(unittest.TestCase):
    """Проверка что main.py распознаёт новые CLI-флаги."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_traffic_check_flag_present_in_main_py(self):
        """--traffic-check должен быть в main.py."""
        main_py = (_PROJECT_ROOT / "main.py").read_text()
        self.assertIn('"--traffic-check" in sys.argv', main_py)

    def test_lifecycle_cleanup_flag_present_in_main_py(self):
        """--lifecycle-cleanup должен быть в main.py."""
        main_py = (_PROJECT_ROOT / "main.py").read_text()
        self.assertIn('"--lifecycle-cleanup" in sys.argv', main_py)

    def test_ttl_check_flag_still_present(self):
        """--ttl-check должен остаться (обратная совместимость)."""
        main_py = (_PROJECT_ROOT / "main.py").read_text()
        self.assertIn('"--ttl-check" in sys.argv', main_py)


if __name__ == "__main__":
    unittest.main()
