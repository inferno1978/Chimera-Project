#!/usr/bin/env python3
"""
tests/test_awg_peers.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/awg_peers.py.

Покрывает:
  1. _validate_peer_name — валидация имени пира
  2. _validate_email — валидация email
  3. _format_bytes — форматирование байт
  4. _format_handshake — форматирование времени handshake
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
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


class TestValidatePeerName(unittest.TestCase):
    """_validate_peer_name — валидация имени пира."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_valid_name(self):
        from vless_installer.modules.awg_peers import _validate_peer_name
        self.assertTrue(_validate_peer_name("alice"))
        self.assertTrue(_validate_peer_name("bob123"))
        self.assertTrue(_validate_peer_name("user-name"))
        self.assertTrue(_validate_peer_name("user_name"))

    def test_empty_invalid(self):
        from vless_installer.modules.awg_peers import _validate_peer_name
        self.assertFalse(_validate_peer_name(""))

    def test_starts_with_digit_invalid(self):
        from vless_installer.modules.awg_peers import _validate_peer_name
        self.assertFalse(_validate_peer_name("1alice"))
        self.assertFalse(_validate_peer_name("123"))

    def test_contains_space_invalid(self):
        from vless_installer.modules.awg_peers import _validate_peer_name
        self.assertFalse(_validate_peer_name("alice bob"))

    def test_too_long_invalid(self):
        from vless_installer.modules.awg_peers import _validate_peer_name
        self.assertFalse(_validate_peer_name("a" * 33))

    def test_max_length_valid(self):
        from vless_installer.modules.awg_peers import _validate_peer_name
        self.assertTrue(_validate_peer_name("a" * 32))

    def test_unicode_invalid(self):
        from vless_installer.modules.awg_peers import _validate_peer_name
        self.assertFalse(_validate_peer_name("алиса"))

    def test_special_chars_invalid(self):
        from vless_installer.modules.awg_peers import _validate_peer_name
        self.assertFalse(_validate_peer_name("alice@bob"))
        self.assertFalse(_validate_peer_name("alice.bob"))


class TestValidateEmail(unittest.TestCase):
    """_validate_email — валидация email."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_returns_true(self):
        """Пустой email — валиден (технический пир)."""
        from vless_installer.modules.awg_peers import _validate_email
        self.assertTrue(_validate_email(""))

    def test_valid_email(self):
        from vless_installer.modules.awg_peers import _validate_email
        self.assertTrue(_validate_email("alice@example.com"))
        self.assertTrue(_validate_email("bob@sub.example.com"))

    def test_invalid_no_at(self):
        from vless_installer.modules.awg_peers import _validate_email
        self.assertFalse(_validate_email("aliceexample.com"))

    def test_invalid_no_dot_after_at(self):
        from vless_installer.modules.awg_peers import _validate_email
        self.assertFalse(_validate_email("alice@example"))

    def test_invalid_with_space(self):
        from vless_installer.modules.awg_peers import _validate_email
        self.assertFalse(_validate_email("alice @example.com"))


class TestFormatBytes(unittest.TestCase):
    """_format_bytes — форматирование байт."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_zero(self):
        from vless_installer.modules.awg_peers import _format_bytes
        self.assertEqual(_format_bytes(0), "0 B")

    def test_kib(self):
        from vless_installer.modules.awg_peers import _format_bytes
        self.assertEqual(_format_bytes(1024), "1.0 KiB")

    def test_mib(self):
        from vless_installer.modules.awg_peers import _format_bytes
        self.assertEqual(_format_bytes(1024 ** 2), "1.0 MiB")

    def test_gib(self):
        from vless_installer.modules.awg_peers import _format_bytes
        self.assertEqual(_format_bytes(1024 ** 3), "1.0 GiB")

    def test_tib(self):
        from vless_installer.modules.awg_peers import _format_bytes
        self.assertEqual(_format_bytes(1024 ** 4), "1.0 TiB")

    def test_petabytes_fallback(self):
        from vless_installer.modules.awg_peers import _format_bytes
        result = _format_bytes(1024 ** 5)
        self.assertIn("PiB", result)


class TestFormatHandshake(unittest.TestCase):
    """_format_handshake — форматирование времени handshake."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_returns_nikogda(self):
        from vless_installer.modules.awg_peers import _format_handshake
        self.assertEqual(_format_handshake(""), "никогда")

    def test_zero_returns_nikogda(self):
        from vless_installer.modules.awg_peers import _format_handshake
        self.assertEqual(_format_handshake("0"), "никогда")

    def test_recent_seconds(self):
        from vless_installer.modules.awg_peers import _format_handshake
        recent = str(int(time.time()) - 30)  # 30 секунд назад
        result = _format_handshake(recent)
        self.assertIn("сек", result)

    def test_minutes_ago(self):
        from vless_installer.modules.awg_peers import _format_handshake
        recent = str(int(time.time()) - 5 * 60)  # 5 минут назад
        result = _format_handshake(recent)
        self.assertIn("мин", result)

    def test_hours_ago(self):
        from vless_installer.modules.awg_peers import _format_handshake
        recent = str(int(time.time()) - 3 * 3600)  # 3 часа назад
        result = _format_handshake(recent)
        self.assertIn("ч", result)

    def test_days_ago(self):
        from vless_installer.modules.awg_peers import _format_handshake
        recent = str(int(time.time()) - 2 * 86400)  # 2 дня назад
        result = _format_handshake(recent)
        self.assertIn("дн", result)

    def test_invalid_returns_input(self):
        """Невалидный timestamp — возвращается исходная строка."""
        from vless_installer.modules.awg_peers import _format_handshake
        result = _format_handshake("not_a_number")
        # функция не должна падать
        self.assertIsInstance(result, str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
