#!/usr/bin/env python3
"""
tests/test_access_control.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/access_control.py — master + OTP парольная защита.

Покрывает:
  1. init_master — установка master-пароля
  2. init_otp — создание OTP
  3. verify_access — master пароль → доступ без расхода OTP
  4. verify_access — OTP → доступ + ротация (старый протухает, новый создаётся)
  5. verify_access — неправильный пароль → отказ
  6. verify_access — использованный OTP → отказ
  7. get_current_otp — показать текущий OTP
  8. rotate_otp — принудительная ротация
  9. Backward compat — старый формат (без "master") → считается master
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


class TestAccessControl(unittest.TestCase):
    """Базовые тесты access_control."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._hash_file = self._tmpdir / "access.hash"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)


class TestInitMaster(TestAccessControl):
    """init_master — установка master-пароля."""

    def test_init_master_creates_file(self):
        from chimera.modules.access_control import init_master
        ok = init_master(self._hash_file, "SecretPass123!")
        self.assertTrue(ok)
        self.assertTrue(self._hash_file.exists())
        data = json.loads(self._hash_file.read_text())
        self.assertIn("master", data)
        self.assertIn("salt", data["master"])
        self.assertIn("hash", data["master"])
        self.assertEqual(data["master"]["algo"], "pbkdf2_sha256")
        self.assertEqual(data["master"]["iterations"], 600000)

    def test_init_master_empty_password(self):
        from chimera.modules.access_control import init_master
        ok = init_master(self._hash_file, "")
        self.assertFalse(ok)

    def test_init_master_preserves_existing_otp(self):
        """init_master не должен перезаписывать существующий OTP."""
        from chimera.modules.access_control import init_master, init_otp
        init_master(self._hash_file, "Master123!")
        otp = init_otp(self._hash_file)
        self.assertIsNotNone(otp)
        # Меняем master.
        init_master(self._hash_file, "NewMaster456!")
        # OTP должен остаться.
        data = json.loads(self._hash_file.read_text())
        self.assertIn("otp", data)
        self.assertEqual(data["otp"]["current_code"], otp)


class TestInitOtp(TestAccessControl):
    """init_otp — создание OTP."""

    def test_init_otp_creates_otp(self):
        from chimera.modules.access_control import init_master, init_otp
        init_master(self._hash_file, "Master123!")
        otp = init_otp(self._hash_file)
        self.assertIsNotNone(otp)
        self.assertEqual(len(otp), 8)
        data = json.loads(self._hash_file.read_text())
        self.assertIn("otp", data)
        self.assertFalse(data["otp"]["used"])

    def test_init_otp_idempotent_when_unused(self):
        """Если OTP не использован — init_otp возвращает тот же код."""
        from chimera.modules.access_control import init_master, init_otp
        init_master(self._hash_file, "Master123!")
        otp1 = init_otp(self._hash_file)
        otp2 = init_otp(self._hash_file)
        self.assertEqual(otp1, otp2)

    def test_init_otp_without_master(self):
        """init_otp без master — создаёт OTP."""
        from chimera.modules.access_control import init_otp
        otp = init_otp(self._hash_file)
        self.assertIsNotNone(otp)
        data = json.loads(self._hash_file.read_text())
        self.assertIn("otp", data)
        # master не должен быть создан автоматически.
        self.assertNotIn("master", data)


class TestVerifyAccess(TestAccessControl):
    """verify_access — проверка пароля."""

    def test_master_grants_access_without_otp_consumption(self):
        """Master-пароль → доступ, OTP не тратится."""
        from chimera.modules.access_control import (
            init_master, init_otp, verify_access,
        )
        init_master(self._hash_file, "Master123!")
        init_otp(self._hash_file)
        result = verify_access(self._hash_file, "Master123!")
        self.assertTrue(result.granted)
        self.assertTrue(result.is_master)
        self.assertFalse(result.otp_rotated)
        # OTP должен остаться неиспользованным.
        data = json.loads(self._hash_file.read_text())
        self.assertFalse(data["otp"]["used"])

    def test_otp_grants_access_and_rotates(self):
        """OTP → доступ, старый протухает, новый создаётся."""
        from chimera.modules.access_control import (
            init_master, init_otp, verify_access,
        )
        init_master(self._hash_file, "Master123!")
        otp = init_otp(self._hash_file)
        result = verify_access(self._hash_file, otp)
        self.assertTrue(result.granted)
        self.assertFalse(result.is_master)
        self.assertTrue(result.otp_rotated)
        self.assertTrue(result.new_otp)
        self.assertNotEqual(result.new_otp, otp)
        # Старый OTP должен быть использован (но заменён новым).
        data = json.loads(self._hash_file.read_text())
        self.assertFalse(data["otp"]["used"])  # новый не использован
        self.assertNotEqual(data["otp"]["current_code"], otp)  # новый код

    def test_wrong_password_denied(self):
        """Неправильный пароль → отказ."""
        from chimera.modules.access_control import (
            init_master, init_otp, verify_access,
        )
        init_master(self._hash_file, "Master123!")
        init_otp(self._hash_file)
        result = verify_access(self._hash_file, "WrongPass456!")
        self.assertFalse(result.granted)

    def test_used_otp_denied(self):
        """Использованный OTP → отказ."""
        from chimera.modules.access_control import (
            init_master, init_otp, verify_access, rotate_otp,
        )
        init_master(self._hash_file, "Master123!")
        otp1 = init_otp(self._hash_file)
        # Используем OTP.
        result = verify_access(self._hash_file, otp1)
        self.assertTrue(result.granted)
        new_otp = result.new_otp
        # Пытаемся использовать старый OTP — должен отказать.
        result2 = verify_access(self._hash_file, otp1)
        self.assertFalse(result2.granted)
        # Новый OTP должен работать.
        result3 = verify_access(self._hash_file, new_otp)
        self.assertTrue(result3.granted)

    def test_no_file_denied(self):
        """Нет файла → отказ."""
        from chimera.modules.access_control import verify_access
        result = verify_access(self._hash_file, "anything")
        self.assertFalse(result.granted)

    def test_empty_password_denied(self):
        """Пустой пароль → отказ."""
        from chimera.modules.access_control import (
            init_master, verify_access,
        )
        init_master(self._hash_file, "Master123!")
        result = verify_access(self._hash_file, "")
        self.assertFalse(result.granted)


class TestBackwardCompat(TestAccessControl):
    """Backward compat: старый формат (без "master") → считается master."""

    def test_old_format_treated_as_master(self):
        """Старый формат {salt, hash, iterations, algo} → master-пароль."""
        from chimera.modules.access_control import verify_access, _compute_hash
        import os
        salt = os.urandom(16)
        password = "OldMaster123!"
        old_data = {
            "salt": salt.hex(),
            "hash": _compute_hash(password, salt, 600000),
            "iterations": 600000,
            "algo": "pbkdf2_sha256",
        }
        self._hash_file.write_text(json.dumps(old_data))
        result = verify_access(self._hash_file, password)
        self.assertTrue(result.granted)
        self.assertTrue(result.is_master)

    def test_old_format_wrong_password_denied(self):
        """Старый формат + неправильный пароль → отказ."""
        from chimera.modules.access_control import verify_access, _compute_hash
        import os
        salt = os.urandom(16)
        old_data = {
            "salt": salt.hex(),
            "hash": _compute_hash("CorrectPass", salt, 600000),
            "iterations": 600000,
            "algo": "pbkdf2_sha256",
        }
        self._hash_file.write_text(json.dumps(old_data))
        result = verify_access(self._hash_file, "WrongPass")
        self.assertFalse(result.granted)


class TestGetCurrentOtp(TestAccessControl):
    """get_current_otp — показать текущий OTP."""

    def test_get_current_otp_when_unused(self):
        from chimera.modules.access_control import (
            init_master, init_otp, get_current_otp,
        )
        init_master(self._hash_file, "Master123!")
        otp = init_otp(self._hash_file)
        current = get_current_otp(self._hash_file)
        self.assertEqual(current, otp)

    def test_get_current_otp_returns_none_when_used(self):
        from chimera.modules.access_control import (
            init_master, init_otp, verify_access, get_current_otp,
        )
        init_master(self._hash_file, "Master123!")
        otp = init_otp(self._hash_file)
        verify_access(self._hash_file, otp)  # Использовали.
        # После ротации новый OTP должен быть доступен.
        new_otp = get_current_otp(self._hash_file)
        self.assertIsNotNone(new_otp)
        self.assertNotEqual(new_otp, otp)

    def test_get_current_otp_no_file(self):
        from chimera.modules.access_control import get_current_otp
        self.assertIsNone(get_current_otp(self._hash_file))


class TestRotateOtp(TestAccessControl):
    """rotate_otp — принудительная ротация."""

    def test_rotate_creates_new_otp(self):
        from chimera.modules.access_control import (
            init_master, init_otp, rotate_otp,
        )
        init_master(self._hash_file, "Master123!")
        otp1 = init_otp(self._hash_file)
        otp2 = rotate_otp(self._hash_file)
        self.assertIsNotNone(otp2)
        self.assertNotEqual(otp1, otp2)

    def test_rotate_makes_old_otp_invalid(self):
        from chimera.modules.access_control import (
            init_master, init_otp, rotate_otp, verify_access,
        )
        init_master(self._hash_file, "Master123!")
        otp1 = init_otp(self._hash_file)
        rotate_otp(self._hash_file)  # Принудительная ротация.
        # Старый OTP не должен работать.
        result = verify_access(self._hash_file, otp1)
        self.assertFalse(result.granted)


if __name__ == "__main__":
    unittest.main()
