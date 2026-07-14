#!/usr/bin/env python3
"""
tests/test_fail2ban_manager.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/fail2ban_manager.py.

Покрывает:
  1. _extract_int — извлечение числа из строки
  2. _f2b_today_ban_history — парсинг лога fail2ban
  3. _f2b_log_lines — чтение лог-файлов
  4. _f2b_read_conf / _f2b_conf_jails — чтение конфигурации
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, time
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
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


class TestExtractInt(unittest.TestCase):
    """_extract_int — извлечение числа из строки."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_extracts_number(self):
        from chimera.modules.fail2ban_manager import _extract_int
        self.assertEqual(_extract_int("Currently failed:  5"), 5)
        self.assertEqual(_extract_int("Total: 42"), 42)

    def test_returns_zero_when_no_number(self):
        from chimera.modules.fail2ban_manager import _extract_int
        self.assertEqual(_extract_int("no number here"), 0)

    def test_returns_zero_on_empty(self):
        from chimera.modules.fail2ban_manager import _extract_int
        self.assertEqual(_extract_int(""), 0)


class TestF2bTodayBanHistory(unittest.TestCase):
    """_f2b_today_ban_history — парсинг лога fail2ban."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._log = self._tmpdir / "fail2ban.log"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.fail2ban_manager._F2B_LOG", self._log)

    def _make_ban_line(self, ip: str, jail: str, dt: datetime) -> str:
        ts = dt.strftime("%Y-%m-%d %H:%M:%S,123")
        return f"{ts} fail2ban.actions [12345]: NOTICE [{jail}] Ban {ip}"

    def test_returns_empty_when_no_file(self):
        from chimera.modules.fail2ban_manager import _f2b_today_ban_history
        with self._patch():
            result = _f2b_today_ban_history()
        self.assertEqual(result, [])

    def test_parses_today_bans(self):
        from chimera.modules.fail2ban_manager import _f2b_today_ban_history
        now = datetime.now()
        self._log.write_text("\n".join([
            self._make_ban_line("1.2.3.4", "sshd", now),
            self._make_ban_line("5.6.7.8", "sshd", now),
        ]) + "\n")
        with self._patch():
            result = _f2b_today_ban_history()
        self.assertEqual(len(result), 2)

    def test_filters_old_bans(self):
        """Баны за прошлый день — отсекаются."""
        from chimera.modules.fail2ban_manager import _f2b_today_ban_history
        from datetime import timedelta
        old = datetime.now() - timedelta(days=2)
        self._log.write_text(self._make_ban_line("1.2.3.4", "sshd", old) + "\n")
        with self._patch():
            result = _f2b_today_ban_history()
        self.assertEqual(len(result), 0)

    def test_groups_by_ip_and_jail(self):
        """Несколько банов одного (ip,jail) — группируются."""
        from chimera.modules.fail2ban_manager import _f2b_today_ban_history
        now = datetime.now()
        lines = [
            self._make_ban_line("1.2.3.4", "sshd", now),
            self._make_ban_line("1.2.3.4", "sshd", now),
            self._make_ban_line("1.2.3.4", "sshd", now),
        ]
        self._log.write_text("\n".join(lines) + "\n")
        with self._patch():
            result = _f2b_today_ban_history()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["count"], 3)

    def test_separates_different_jails(self):
        from chimera.modules.fail2ban_manager import _f2b_today_ban_history
        now = datetime.now()
        self._log.write_text("\n".join([
            self._make_ban_line("1.2.3.4", "sshd", now),
            self._make_ban_line("1.2.3.4", "nginx", now),
        ]) + "\n")
        with self._patch():
            result = _f2b_today_ban_history()
        self.assertEqual(len(result), 2)


class TestF2bLogLines(unittest.TestCase):
    """_f2b_log_lines — чтение лог-файлов."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._log = self._tmpdir / "fail2ban.log"
        self._log1 = self._tmpdir / "fail2ban.log.1"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.fail2ban_manager._F2B_LOG", self._log)

    def test_returns_empty_when_no_file(self):
        from chimera.modules.fail2ban_manager import _f2b_log_lines
        with self._patch():
            self.assertEqual(_f2b_log_lines(), [])

    def test_reads_main_log(self):
        from chimera.modules.fail2ban_manager import _f2b_log_lines
        self._log.write_text("line1\nline2\n")
        with self._patch():
            result = _f2b_log_lines()
        self.assertEqual(len(result), 2)


class TestF2bConfJails(unittest.TestCase):
    """_f2b_conf_jails — чтение секций jail."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._conf = self._tmpdir / "jail.conf"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.fail2ban_manager._JAIL_LOCAL", self._conf)

    def test_returns_empty_when_no_file(self):
        from chimera.modules.fail2ban_manager import _f2b_conf_jails
        with self._patch():
            self.assertEqual(_f2b_conf_jails(), [])

    def test_returns_jail_names(self):
        from chimera.modules.fail2ban_manager import _f2b_conf_jails
        self._conf.write_text("[sshd]\nenabled = true\n\n[nginx]\nenabled = true\n")
        with self._patch():
            jails = _f2b_conf_jails()
        self.assertIn("sshd", jails)
        self.assertIn("nginx", jails)


if __name__ == "__main__":
    unittest.main(verbosity=2)
