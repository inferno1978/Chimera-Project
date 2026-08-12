#!/usr/bin/env python3
"""
tests/test_autoban.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/autoban.py.

Покрывает:
  1. _autoban_load / _autoban_save — JSON I/O с дефолтами
  2. _ban_report_append — добавление записи в отчёт
"""
from __future__ import annotations
import json, os, stat, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

def _setup_core():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text(); g = {}
    with patch.object(Path, 'mkdir', lambda s,*a,**k: None), \
         patch.object(Path, 'touch', lambda s,*a,**k: None), \
         patch.object(Path, 'chmod', lambda s,*a,**k: None), \
         patch('os.chown', lambda *a,**k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types; m = types.ModuleType("chimera._core"); m.__dict__.update(g)
    sys.modules["chimera._core"] = m

class TestAutobanLoadSave(unittest.TestCase):
    def setUp(self):
        _setup_core()
        self._tmp = Path(tempfile.mkdtemp())
        self._state = self._tmp / "autoban.json"
    def tearDown(self):
        import shutil; shutil.rmtree(self._tmp, ignore_errors=True)
    def _patch(self):
        return patch("chimera.modules.autoban._XRAY_BAN_STATE", self._state)
    def test_load_returns_defaults_when_no_file(self):
        from chimera.modules.autoban import _autoban_load
        with self._patch():
            data = _autoban_load()
        self.assertFalse(data["enabled"])
        self.assertIn("banned", data)
        self.assertIn("whitelist", data)
    def test_load_returns_defaults_on_corrupt(self):
        from chimera.modules.autoban import _autoban_load
        self._state.write_text("{invalid")
        with self._patch():
            data = _autoban_load()
        self.assertFalse(data["enabled"])
    def test_save_then_load(self):
        from chimera.modules.autoban import _autoban_load, _autoban_save
        with self._patch():
            _autoban_save({"enabled": True, "banned": {"1.2.3.4": {"count": 5}}})
            loaded = _autoban_load()
        self.assertTrue(loaded["enabled"])
        self.assertIn("1.2.3.4", loaded["banned"])
    def test_save_adds_ban_history(self):
        from chimera.modules.autoban import _autoban_load, _autoban_save
        with self._patch():
            _autoban_save({"enabled": True, "banned": {}})
            loaded = _autoban_load()
        self.assertIn("ban_history", loaded)
    def test_save_sets_chmod_600(self):
        from chimera.modules.autoban import _autoban_save
        with self._patch():
            _autoban_save({"enabled": False})
        mode = stat.S_IMODE(os.stat(self._state).st_mode)
        self.assertEqual(mode, 0o600)


class TestBanHistoryMigration(unittest.TestCase):
    """
    Регрессия: ранее cron-скрипт банил IP, но не добавлял запись
    в ban_history. Из-за этого у существующих инсталляций пункт меню
    [6] «История банов» показывал «История пуста» хотя banned-список
    был непустой. _autoban_load() теперь мигрирует banned → ban_history
    при первом открытии.
    """
    def setUp(self):
        _setup_core()
        self._tmp = Path(tempfile.mkdtemp())
        self._state = self._tmp / "autoban.json"
    def tearDown(self):
        import shutil; shutil.rmtree(self._tmp, ignore_errors=True)
    def _patch(self):
        return patch("chimera.modules.autoban._XRAY_BAN_STATE", self._state)

    def test_migrates_banned_to_history_when_history_empty(self):
        """Существующие баны (без истории) переносятся в ban_history."""
        from chimera.modules.autoban import _autoban_load, _autoban_save
        # Симулируем старый сломанный state: 3 бана, ban_history пуст
        with self._patch():
            _autoban_save({
                "enabled": True,
                "banned": {
                    "1.2.3.4": {"count": 10, "banned_at": "2026-08-02T14:10:00",
                                "reason": "10 TLS errors in 10min"},
                    "5.6.7.8": {"count": 15, "banned_at": "2026-08-03T08:55:00",
                                "reason": "15 TLS errors in 10min"},
                    "9.10.11.12": {"count": 64, "banned_at": "2026-08-09T18:40:00",
                                   "reason": "64 TLS errors in 10min"},
                },
                # ban_history не указан — старый формат
            })
            loaded = _autoban_load()
        # После миграции ban_history должен содержать 3 записи
        self.assertEqual(len(loaded["ban_history"]), 3)
        ips_in_history = {r["ip"] for r in loaded["ban_history"]}
        self.assertEqual(ips_in_history, {"1.2.3.4", "5.6.7.8", "9.10.11.12"})
        # banned-словарь не должен пострадать
        self.assertEqual(len(loaded["banned"]), 3)
        # unbanned_at должен быть None (они ещё активны)
        for rec in loaded["ban_history"]:
            self.assertIsNone(rec["unbanned_at"])

    def test_no_migration_when_history_already_present(self):
        """Если ban_history уже есть — миграция не трогает его."""
        from chimera.modules.autoban import _autoban_load, _autoban_save
        with self._patch():
            _autoban_save({
                "enabled": True,
                "banned": {"1.2.3.4": {"count": 10, "banned_at": "2026-08-02T14:10:00"}},
                "ban_history": [
                    {"ip": "9.9.9.9", "banned_at": "2026-01-01T00:00:00",
                     "unbanned_at": "2026-01-02T00:00:00", "count": 5, "reason": "old"}
                ],
            })
            loaded = _autoban_load()
        # История осталась как была — 1 запись, не 2
        self.assertEqual(len(loaded["ban_history"]), 1)
        self.assertEqual(loaded["ban_history"][0]["ip"], "9.9.9.9")

    def test_no_migration_when_banned_empty(self):
        """Если banned пуст — миграция не создаёт пустой ban_history."""
        from chimera.modules.autoban import _autoban_load, _autoban_save
        with self._patch():
            _autoban_save({"enabled": True, "banned": {}})
            loaded = _autoban_load()
        self.assertEqual(loaded["ban_history"], [])


class TestCronScriptWritesHistory(unittest.TestCase):
    """
    Регрессия: проверяем что встроенный Python-скрипт внутри
    _autoban_install_cron() содержит код добавления ban_history.
    Раньше он только инициализировал пустой список, но не append'ил.
    """
    def test_cron_script_contains_ban_history_append(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" / "autoban.py").read_text()
        # Извлекаем тело встроенного скрипта
        import re
        m = re.search(r'py_body = f"""(.*?)"""', src, re.DOTALL)
        self.assertIsNotNone(m, "py_body f-string не найден в исходнике")
        body = m.group(1)
        # Проверяем наличие ключевых маркеров фикса
        self.assertIn("cfg['ban_history'].append(", body,
                      "cron-скрипт не append'ит в ban_history — регрессия!")
        self.assertIn("'unbanned_at': None", body,
                      "cron-скрипт не задаёт unbanned_at=None в записях истории")
        self.assertIn("'banned_at':   _ban_ts", body,
                      "cron-скрипт не сохраняет banned_at в записях истории")

    def test_cron_script_truncates_history_at_500(self):
        """История не должна расти бесконечно — лимит 500 записей."""
        src = (_PROJECT_ROOT / "chimera" / "modules" / "autoban.py").read_text()
        import re
        m = re.search(r'py_body = f"""(.*?)"""', src, re.DOTALL)
        body = m.group(1)
        self.assertIn("len(cfg['ban_history']) > 500", body)
        self.assertIn("cfg['ban_history'][-500:]", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
