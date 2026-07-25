#!/usr/bin/env python3
"""
tests/test_system_deps.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/system_deps.py.

Покрывает:
  1. _CMD_TO_PKG — структура таблицы команд
  2. _smart_recover — сужение apt-get ветки: FileNotFoundError с filename,
     похожим на файл (.toml/.json/.service/.crt/...), НЕ вызывает
     "apt-get install", а печатает "ОШИБКА ФАЙЛОВОЙ СИСТЕМЫ" и возвращает
     False. Реальные отсутствующие команды (curl, xray, ...) — старая
     ветка apt-get install работает как раньше.
"""
from __future__ import annotations

import io
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("chimera._core")
    m.__dict__.update(g)
    sys.modules["chimera._core"] = m


class TestSystemDeps(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_cmd_to_pkg_has_common_commands(self):
        from chimera.modules.system_deps import _CMD_TO_PKG
        for cmd in ("curl", "wget", "tar"):
            self.assertIn(cmd, _CMD_TO_PKG)
    def test_cmd_to_pkg_values_are_tuples(self):
        from chimera.modules.system_deps import _CMD_TO_PKG
        for cmd, pkg in _CMD_TO_PKG.items():
            with self.subTest(cmd=cmd):
                self.assertIsInstance(pkg, (tuple, list))
                self.assertEqual(len(pkg), 2)


# =============================================================================
#  _smart_recover: сужение apt-get ветки для неродственных FileNotFoundError
# =============================================================================
class TestSmartRecoverFilesystemError(unittest.TestCase):
    """Проверяем, что _smart_recover() корректно отличает
    FileNotFoundError по отсутствующей команде (curl, xray, ...) от
    FileNotFoundError по отсутствующему файлу (telemt.toml, server.json,
    ...).

    До фикса: shutil.copy2 в do_export_config упал с FileNotFoundError
    (path=.../mita/server.json) — _smart_recover достал basename
    "server.json", не нашёл его в _CMD_TO_PKG, но всё равно показал
    "КОМАНДА НЕ НАЙДЕНА / apt-get install server.json" — бессмысленно.

    После фикса: для filename с расширением из _FILE_EXT_HINTS
    (.toml/.json/.txt/.service/.crt/.key/.yaml/...) — печатаем
    "ОШИБКА ФАЙЛОВОЙ СИСТЕМЫ", возвращаем False, НЕ предлагаем apt-get.
    """

    def setUp(self):
        _setup_core()

    def _run_smart_recover_capturing(self, exc: FileNotFoundError):
        """Запускает _smart_recover(exc) с захватом stdout.

        Возвращает (result_bool, stdout_text).
        Мокает input() чтобы избежать интерактивного промпта (если
        дело дойдёт до ветки apt-get install — что в наших тестах
        не должно случаться для file-system случая).
        """
        from chimera.modules.system_deps import _smart_recover
        buf = io.StringIO()
        with patch("builtins.input", return_value="S"):  # Skip если спросит
            with redirect_stdout(buf), redirect_stderr(buf):
                try:
                    result = _smart_recover(exc)
                except SystemExit:
                    result = False
        return result, buf.getvalue()

    # ── Тест 3: filename='telemt.toml' → False, FS error, NO apt-get ────────
    def test_filename_with_toml_extension_returns_false_no_apt_get(self):
        """FileNotFoundError с filename='telemt.toml' (не в _CMD_TO_PKG,
        имеет .toml расширение) → _smart_recover возвращает False,
        печатает 'ОШИБКА ФАЙЛОВОЙ СИСТЕМЫ', НЕ печатает 'apt-get install'.
        """
        exc = FileNotFoundError(2, "No such file or directory",
                                "/tmp/xray_export_xxx/telemt/telemt.toml")
        result, out = self._run_smart_recover_capturing(exc)

        self.assertFalse(result,
                         "expected False for file-system FileNotFoundError")
        self.assertIn("ОШИБКА ФАЙЛОВОЙ СИСТЕМЫ", out)
        self.assertIn("telemt.toml", out)
        self.assertIn("не связано с отсутствующим системным пакетом", out)
        # НЕ должно быть apt-get install для filename
        self.assertNotIn("apt-get install", out.lower(),
                         f"should NOT suggest apt-get install for a file, "
                         f"got: {out!r}")

    # ── Дополнительные случаи расширений ─────────────────────────────────────
    def test_filename_with_json_extension_returns_false_no_apt_get(self):
        exc = FileNotFoundError(2, "No such file or directory",
                                "/etc/mita/server.json")
        result, out = self._run_smart_recover_capturing(exc)
        self.assertFalse(result)
        self.assertIn("ОШИБКА ФАЙЛОВОЙ СИСТЕМЫ", out)
        self.assertNotIn("apt-get install", out.lower())

    def test_filename_with_service_extension_returns_false_no_apt_get(self):
        exc = FileNotFoundError(2, "No such file or directory",
                                "/etc/systemd/system/mita.service")
        result, out = self._run_smart_recover_capturing(exc)
        self.assertFalse(result)
        self.assertIn("ОШИБКА ФАЙЛОВОЙ СИСТЕМЫ", out)
        self.assertNotIn("apt-get install", out.lower())

    def test_filename_with_crt_extension_returns_false_no_apt_get(self):
        exc = FileNotFoundError(2, "No such file or directory",
                                "/etc/xray/hysteria.crt")
        result, out = self._run_smart_recover_capturing(exc)
        self.assertFalse(result)
        self.assertIn("ОШИБКА ФАЙЛОВОЙ СИСТЕМЫ", out)
        self.assertNotIn("apt-get install", out.lower())

    def test_filename_with_yaml_extension_returns_false_no_apt_get(self):
        exc = FileNotFoundError(2, "No such file or directory",
                                "/etc/hysteria/config.yaml")
        result, out = self._run_smart_recover_capturing(exc)
        self.assertFalse(result)
        self.assertIn("ОШИБКА ФАЙЛОВОЙ СИСТЕМЫ", out)
        self.assertNotIn("apt-get install", out.lower())

    # ── Тест 4: filename='curl' (из _CMD_TO_PKG) → старое поведение ──────────
    def test_filename_with_known_command_uses_old_apt_get_branch(self):
        """FileNotFoundError с filename='curl' (есть в _CMD_TO_PKG) →
        старая ветка apt-get install, печатаем 'КОМАНДА НЕ НАЙДЕНА',
        упоминаем пакет для установки. Поведение НЕ изменилось.
        """
        exc = FileNotFoundError(2, "No such file or directory", "curl")
        result, out = self._run_smart_recover_capturing(exc)

        # Не должно быть "ОШИБКА ФАЙЛОВОЙ СИСТЕМЫ" — это старая ветка
        self.assertNotIn("ОШИБКА ФАЙЛОВОЙ СИСТЕМЫ", out,
                         f"curl is a known system command, should use old "
                         f"apt-get branch, not FS-error branch. Got: {out!r}")
        # Должно быть "КОМАНДА НЕ НАЙДЕНА"
        self.assertIn("КОМАНДА НЕ НАЙДЕНА", out)
        # Должно упоминать пакет (curl → "curl" в apt)
        self.assertIn("curl", out)
        # Может быть или apt-get install (если предложено) или упоминание
        # пакета для установки. Главное — НЕ FS-error.
        # result может быть True (если input='A' и установка прошла) или
        # False (если 'S' skip). С 'S' в нашем mock — False.
        self.assertFalse(result, "with 'S' input, should return False (skip)")

    def test_filename_with_xray_command_uses_old_apt_get_branch(self):
        """Дополнительная проверка: filename='xray' — это НЕ в _CMD_TO_PKG,
        но это известный исполняемый файл проекта. Старая ветка должна
        сработать (через _find_pkg_for_missing_cmd → fallback apt-file
        lookup или просто "пакет неизвестен" + traceback). В любом случае
        это НЕ FS-error — нет расширения, не похож на файл.
        """
        exc = FileNotFoundError(2, "No such file or directory", "xray")
        result, out = self._run_smart_recover_capturing(exc)

        # xray не имеет расширения — не должен попасть в FS-error ветку
        self.assertNotIn("ОШИБКА ФАЙЛОВОЙ СИСТЕМЫ", out,
                         f"xray has no file extension, should use old "
                         f"command-not-found branch. Got: {out!r}")
        self.assertIn("КОМАНДА НЕ НАЙДЕНА", out)
        self.assertIn("xray", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
