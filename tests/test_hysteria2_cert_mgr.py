#!/usr/bin/env python3
"""
tests/test_hysteria2_cert_mgr.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/hysteria2_cert_mgr.py.

Покрывает:
  1. h2_cert_check — проверка сертификата (mocked openssl _run)
     - сертификат не существует → exists=False
     - openssl возвращает notAfter → парсинг двух форматов дат
     - openssl не возвращает notAfter → valid=False
     - days_left > 0 → valid=True
     - days_left < 0 → valid=False
  2. _check_if_need_renew — обёртка над h2_cert_check
"""
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("vless_installer._core")
    m.__dict__.update(g)
    sys.modules["vless_installer._core"] = m


class TestH2CertCheck(unittest.TestCase):
    """h2_cert_check — проверка сертификата."""

    def setUp(self):
        _setup_core()

    def test_returns_not_exists_when_no_file(self):
        """Сертификат не существует → exists=False."""
        from vless_installer.modules.hysteria2_cert_mgr import h2_cert_check
        with patch("pathlib.Path.exists", return_value=False):
            result = h2_cert_check("/tmp/nonexistent_cert.pem")
        self.assertFalse(result["exists"])
        self.assertFalse(result["valid"])
        self.assertEqual(result["days_left"], 0)

    def test_parses_single_space_date_format(self):
        """openssl возвращает 'Sep 28 12:00:00 2025 GMT' (одинарный пробел)."""
        from vless_installer.modules.hysteria2_cert_mgr import h2_cert_check
        future = (datetime.now(timezone.utc) + timedelta(days=90))
        date_str = future.strftime("%b %d %H:%M:%S %Y GMT")
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = f"notBefore=Jan  1 00:00:00 2025 GMT\nnotAfter={date_str}\n"
        mock_result.stderr = ""
        with patch("pathlib.Path.exists", return_value=True), \
             patch("vless_installer.modules.hysteria2_cert_mgr._run",
                   return_value=mock_result):
            result = h2_cert_check("/fake/cert.pem")
        self.assertTrue(result["exists"])
        self.assertTrue(result["valid"])
        self.assertGreater(result["days_left"], 80)

    def test_parses_double_space_date_format(self):
        """openssl возвращает 'Sep  8 12:00:00 2025 GMT' (двойной пробел для однозначных дней)."""
        from vless_installer.modules.hysteria2_cert_mgr import h2_cert_check
        future = (datetime.now(timezone.utc) + timedelta(days=60))
        day = future.day
        if day < 10:
            date_str = future.strftime(f"%b  {day} %H:%M:%S %Y GMT")
        else:
            date_str = future.strftime("%b %d %H:%M:%S %Y GMT")
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = f"notAfter={date_str}\n"
        mock_result.stderr = ""
        with patch("pathlib.Path.exists", return_value=True), \
             patch("vless_installer.modules.hysteria2_cert_mgr._run",
                   return_value=mock_result):
            result = h2_cert_check("/fake/cert.pem")
        self.assertTrue(result["exists"])
        self.assertTrue(result["valid"])

    def test_expired_cert_returns_valid_false(self):
        """Сертификат с датой в прошлом → valid=False, days_left < 0."""
        from vless_installer.modules.hysteria2_cert_mgr import h2_cert_check
        past = (datetime.now(timezone.utc) - timedelta(days=30))
        date_str = past.strftime("%b %d %H:%M:%S %Y GMT")
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = f"notAfter={date_str}\n"
        mock_result.stderr = ""
        with patch("pathlib.Path.exists", return_value=True), \
             patch("vless_installer.modules.hysteria2_cert_mgr._run",
                   return_value=mock_result):
            result = h2_cert_check("/fake/cert.pem")
        self.assertTrue(result["exists"])
        self.assertFalse(result["valid"])
        self.assertLess(result["days_left"], 0)

    def test_returns_invalid_when_no_notafter(self):
        """openssl не вернул notAfter → valid=False."""
        from vless_installer.modules.hysteria2_cert_mgr import h2_cert_check
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "some other line\n"
        mock_result.stderr = ""
        with patch("pathlib.Path.exists", return_value=True), \
             patch("vless_installer.modules.hysteria2_cert_mgr._run",
                   return_value=mock_result):
            result = h2_cert_check("/fake/cert.pem")
        self.assertTrue(result["exists"])
        self.assertFalse(result["valid"])

    def test_returns_error_dict_on_exception(self):
        """При исключении в openssl → error в результате."""
        from vless_installer.modules.hysteria2_cert_mgr import h2_cert_check
        with patch("pathlib.Path.exists", return_value=True), \
             patch("vless_installer.modules.hysteria2_cert_mgr._run",
                   side_effect=Exception("openssl crash")):
            result = h2_cert_check("/fake/cert.pem")
        self.assertTrue(result["exists"])
        self.assertFalse(result["valid"])
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
