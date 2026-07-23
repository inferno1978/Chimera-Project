#!/usr/bin/env python3
"""
tests/test_mtproto_limits.py
───────────────────────────────────────────────────────────────────────────────
Тесты для per-user лимитов Telemt (квота трафика + срок действия).

Покрывает:
  1. mtproto_set_limits — установка квоты + срока
  2. mtproto_set_limits — только квота, только срок, оба None
  3. mtproto_set_limits — несуществующий пользователь → False
  4. mtproto_set_limits — невалидный формат квоты/срока → False
  5. mtproto_get_limits — возвращает лимиты + used_bytes
  6. mtproto_remove_limits — удаляет лимиты
  7. mtproto_check_limits — истечение по сроку → удаляет
  8. mtproto_check_limits — превышение квоты → удаляет
  9. mtproto_check_limits — оба лимита безлимитны → не трогает
  10. Обратная совместимость — старый формат [access.users] (плоские строки)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import types
import unittest
from datetime import datetime, timezone, timedelta
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
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core


def _make_telemt_config(users: dict) -> str:
    """Создаёт минимальный telemt.toml с секцией [access.users]."""
    lines = [
        '[server]',
        'listen = "0.0.0.0:443"',
        '',
        '[access]',
        'replay_check_len = 65536',
        '',
        '[access.users]',
    ]
    for name, secret in users.items():
        lines.append(f'{name} = "{secret}"')
    lines.append('')
    lines.append('[general.links]')
    lines.append('show = [' + ', '.join(f'"{u}"' for u in users) + ']')
    return '\n'.join(lines) + '\n'


class TestMtprotoSetLimits(unittest.TestCase):
    """mtproto_set_limits — установка per-user лимитов."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._config_file = self._tmpdir / "telemt.toml"
        self._limits_file = self._tmpdir / "telemt_limits.json"
        _setup_core_in_sysmodules()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_mtproto(self):
        from chimera.modules import mtproto
        core = sys.modules["chimera._core"]
        return (
            patch.object(mtproto, "CONFIG_FILE", self._config_file),
            patch.object(mtproto, "LIMITS_FILE", self._limits_file),
            patch.object(mtproto, "_run", MagicMock()),
        )

    def test_set_quota_and_expiry(self):
        """Кейс 1: установка квоты + срока → True, лимиты записаны."""
        from chimera.modules import mtproto
        self._config_file.write_text(_make_telemt_config({"alice": "a" * 32}))
        with self._patch_mtproto()[0], self._patch_mtproto()[1], self._patch_mtproto()[2]:
            ok = mtproto.mtproto_set_limits("alice", "10G", "30d")
        self.assertTrue(ok)
        limits = json.loads(self._limits_file.read_text())
        self.assertEqual(limits["alice"]["quota_bytes"], 10737418240)
        self.assertIsNotNone(limits["alice"]["expires_at"])

    def test_set_quota_only(self):
        """Кейс 2a: только квота, срок бессрочный."""
        from chimera.modules import mtproto
        self._config_file.write_text(_make_telemt_config({"bob": "b" * 32}))
        with self._patch_mtproto()[0], self._patch_mtproto()[1], self._patch_mtproto()[2]:
            ok = mtproto.mtproto_set_limits("bob", "500MB", None)
        self.assertTrue(ok)
        limits = json.loads(self._limits_file.read_text())
        self.assertEqual(limits["bob"]["quota_bytes"], 500000000)
        self.assertIsNone(limits["bob"]["expires_at"])

    def test_set_expiry_only(self):
        """Кейс 2b: только срок, квота безлимитная."""
        from chimera.modules import mtproto
        self._config_file.write_text(_make_telemt_config({"carol": "c" * 32}))
        with self._patch_mtproto()[0], self._patch_mtproto()[1], self._patch_mtproto()[2]:
            ok = mtproto.mtproto_set_limits("carol", None, "12h")
        self.assertTrue(ok)
        limits = json.loads(self._limits_file.read_text())
        self.assertIsNone(limits["carol"]["quota_bytes"])
        self.assertIsNotNone(limits["carol"]["expires_at"])

    def test_set_both_none(self):
        """Кейс 2c: оба None → безлимит."""
        from chimera.modules import mtproto
        self._config_file.write_text(_make_telemt_config({"dave": "d" * 32}))
        with self._patch_mtproto()[0], self._patch_mtproto()[1], self._patch_mtproto()[2]:
            ok = mtproto.mtproto_set_limits("dave", None, None)
        self.assertTrue(ok)
        limits = json.loads(self._limits_file.read_text())
        self.assertIsNone(limits["dave"]["quota_bytes"])
        self.assertIsNone(limits["dave"]["expires_at"])

    def test_nonexistent_user_returns_false(self):
        """Кейс 3: несуществующий пользователь → False."""
        from chimera.modules import mtproto
        self._config_file.write_text(_make_telemt_config({"alice": "a" * 32}))
        with self._patch_mtproto()[0], self._patch_mtproto()[1], self._patch_mtproto()[2]:
            ok = mtproto.mtproto_set_limits("nonexistent", "10G", "30d")
        self.assertFalse(ok)

    def test_invalid_quota_returns_false(self):
        """Кейс 4a: невалидный формат квоты → False."""
        from chimera.modules import mtproto
        self._config_file.write_text(_make_telemt_config({"alice": "a" * 32}))
        with self._patch_mtproto()[0], self._patch_mtproto()[1], self._patch_mtproto()[2]:
            ok = mtproto.mtproto_set_limits("alice", "notabytes", "30d")
        self.assertFalse(ok)

    def test_invalid_expiry_returns_false(self):
        """Кейс 4b: невалидный формат срока → False."""
        from chimera.modules import mtproto
        self._config_file.write_text(_make_telemt_config({"alice": "a" * 32}))
        with self._patch_mtproto()[0], self._patch_mtproto()[1], self._patch_mtproto()[2]:
            ok = mtproto.mtproto_set_limits("alice", "10G", "notaduration")
        self.assertFalse(ok)


class TestMtprotoGetLimits(unittest.TestCase):
    """mtproto_get_limits — получение лимитов."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._config_file = self._tmpdir / "telemt.toml"
        self._limits_file = self._tmpdir / "telemt_limits.json"
        _setup_core_in_sysmodules()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_get_limits_returns_all_fields(self):
        """Кейс 5: get_limits возвращает quota_bytes, expires_at, used_bytes."""
        from chimera.modules import mtproto
        self._config_file.write_text(_make_telemt_config({"alice": "a" * 32}))
        self._limits_file.write_text(json.dumps({
            "alice": {"quota_bytes": 10737418240, "expires_at": "2026-12-31T00:00:00+00:00",
                      "max_connections": None}
        }))
        with patch.object(mtproto, "CONFIG_FILE", self._config_file), \
             patch.object(mtproto, "LIMITS_FILE", self._limits_file), \
             patch.object(mtproto, "_get_user_traffic_bytes", return_value=500000000), \
             patch.object(mtproto, "_run", MagicMock()):
            result = mtproto.mtproto_get_limits("alice")
        self.assertEqual(result["quota_bytes"], 10737418240)
        self.assertIsNotNone(result["expires_at"])
        self.assertEqual(result["used_bytes"], 500000000)
        self.assertIsNone(result["max_connections"])


class TestMtprotoRemoveLimits(unittest.TestCase):
    """mtproto_remove_limits — удаление лимитов."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._limits_file = self._tmpdir / "telemt_limits.json"
        _setup_core_in_sysmodules()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_remove_limits(self):
        """Кейс 6: remove_limits удаляет запись."""
        from chimera.modules import mtproto
        self._limits_file.write_text(json.dumps({
            "alice": {"quota_bytes": 1000, "expires_at": None, "max_connections": None}
        }))
        with patch.object(mtproto, "LIMITS_FILE", self._limits_file):
            ok = mtproto.mtproto_remove_limits("alice")
        self.assertTrue(ok)
        limits = json.loads(self._limits_file.read_text())
        self.assertNotIn("alice", limits)

    def test_remove_nonexistent_returns_false(self):
        """Удаление лимитов для пользователя без лимитов → False."""
        from chimera.modules import mtproto
        self._limits_file.write_text(json.dumps({}))
        with patch.object(mtproto, "LIMITS_FILE", self._limits_file):
            ok = mtproto.mtproto_remove_limits("nonexistent")
        self.assertFalse(ok)


class TestMtprotoCheckLimits(unittest.TestCase):
    """mtproto_check_limits — периодическая проверка."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._config_file = self._tmpdir / "telemt.toml"
        self._limits_file = self._tmpdir / "telemt_limits.json"
        _setup_core_in_sysmodules()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_all(self):
        from chimera.modules import mtproto
        return (
            patch.object(mtproto, "CONFIG_FILE", self._config_file),
            patch.object(mtproto, "LIMITS_FILE", self._limits_file),
            patch.object(mtproto, "_run", MagicMock()),
            patch.object(mtproto, "_save_users", MagicMock()),
            patch.object(mtproto, "_log_telemt", MagicMock()),
        )

    def test_expired_user_removed(self):
        """Кейс 7: истечение по сроку → пользователь удалён."""
        from chimera.modules import mtproto
        self._config_file.write_text(_make_telemt_config({"alice": "a" * 32, "bob": "b" * 32}))
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        self._limits_file.write_text(json.dumps({
            "alice": {"quota_bytes": None, "expires_at": past, "max_connections": None}
        }))
        with self._patch_all()[0], self._patch_all()[1], self._patch_all()[2], \
             self._patch_all()[3], self._patch_all()[4]:
            result = mtproto.mtproto_check_limits()
        self.assertEqual(result["expired"], 1)
        self.assertEqual(result["quota_exceeded"], 0)

    def test_quota_exceeded_user_removed(self):
        """Кейс 8: превышение квоты → пользователь удалён."""
        from chimera.modules import mtproto
        self._config_file.write_text(_make_telemt_config({"alice": "a" * 32, "bob": "b" * 32}))
        self._limits_file.write_text(json.dumps({
            "alice": {"quota_bytes": 1000, "expires_at": None, "max_connections": None}
        }))
        with self._patch_all()[0], self._patch_all()[1], self._patch_all()[2], \
             self._patch_all()[3], self._patch_all()[4], \
             patch.object(mtproto, "_get_user_traffic_bytes", return_value=2000):
            result = mtproto.mtproto_check_limits()
        self.assertEqual(result["expired"], 0)
        self.assertEqual(result["quota_exceeded"], 1)

    def test_unlimited_user_not_touched(self):
        """Кейс 9: оба лимита безлимитны → пользователь не трогается."""
        from chimera.modules import mtproto
        self._config_file.write_text(_make_telemt_config({"alice": "a" * 32}))
        self._limits_file.write_text(json.dumps({
            "alice": {"quota_bytes": None, "expires_at": None, "max_connections": None}
        }))
        with self._patch_all()[0], self._patch_all()[1], self._patch_all()[2], \
             self._patch_all()[3], self._patch_all()[4], \
             patch.object(mtproto, "_get_user_traffic_bytes", return_value=999999999):
            result = mtproto.mtproto_check_limits()
        self.assertEqual(result["expired"], 0)
        self.assertEqual(result["quota_exceeded"], 0)
        # Лимиты не удалены
        limits = json.loads(self._limits_file.read_text())
        self.assertIn("alice", limits)


class TestBackwardCompatOldUsersFormat(unittest.TestCase):
    """Кейс 10: обратная совместимость — старый формат [access.users] (плоские строки)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_old_format_plain_strings_still_loads(self):
        """Старый формат (плоские строки = секреты) должен читаться без ошибок."""
        from chimera.modules import mtproto
        tmpdir = Path(tempfile.mkdtemp())
        config_file = tmpdir / "telemt.toml"
        config_file.write_text(_make_telemt_config({"alice": "a" * 32, "bob": "b" * 32}))
        with patch.object(mtproto, "CONFIG_FILE", config_file):
            users = mtproto._load_users()
        self.assertEqual(len(users), 2)
        self.assertEqual(users["alice"], "a" * 32)
        self.assertEqual(users["bob"], "b" * 32)
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

    def test_old_format_with_limits_works(self):
        """Старый формат + новые лимиты в отдельном файле → работают вместе."""
        from chimera.modules import mtproto
        tmpdir = Path(tempfile.mkdtemp())
        config_file = tmpdir / "telemt.toml"
        limits_file = tmpdir / "telemt_limits.json"
        config_file.write_text(_make_telemt_config({"alice": "a" * 32}))
        limits_file.write_text(json.dumps({
            "alice": {"quota_bytes": 10737418240, "expires_at": None, "max_connections": None}
        }))
        with patch.object(mtproto, "CONFIG_FILE", config_file), \
             patch.object(mtproto, "LIMITS_FILE", limits_file), \
             patch.object(mtproto, "_run", MagicMock()):
            # set_limits с новой квотой
            ok = mtproto.mtproto_set_limits("alice", "20G", None)
            self.assertTrue(ok)
            limits = json.loads(limits_file.read_text())
            self.assertEqual(limits["alice"]["quota_bytes"], 21474836480)
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
