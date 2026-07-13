#!/usr/bin/env python3
"""
tests/test_core_dynamic_version.py
───────────────────────────────────────────────────────────────────────────────
Тест динамической подстановки версии в vless_installer/_core.py.

Проверяет что _get_version() берёт версию из vless_installer.__version__,
а не из хардкода. Monkey-patch'ит __version__ на "9.9.9" и проверяет,
что баннер/лог/статус-бар реально подхватывают новое значение.

Аналогично паттерну honeypot.py (см. CHANGELOG: "хардкоженный v4.11 в
генерируемом конфиге заменён на динамическую вставку
vless_installer.__version__").
"""
from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Создаёт фейковый vless_installer._core (как в test_tg_bot.py).

    Возвращает (fake_core, globals_dict) — globals_dict это тот самый dict
    который был передан в exec() и стал __globals__ для всех функций.
    """
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
    return fake_core, g


class TestCoreDynamicVersion(unittest.TestCase):
    """Проверяет что _core.py берёт версию динамически из __version__."""

    def setUp(self):
        self._fake_core, self._core_globals = _setup_core_in_sysmodules()

    def test_get_version_returns_from_init(self):
        """_get_version() возвращает значение из vless_installer.__version__."""
        version = self._fake_core._get_version()
        # Должно совпадать с __version__ из __init__.py
        from vless_installer import __version__ as real_version
        self.assertEqual(version, real_version,
                         f"_get_version() should return {real_version!r}, got {version!r}")

    def test_get_version_caches_after_first_call(self):
        """_get_version() кэширует результат — второй вызов не делает импорт."""
        # Сбрасываем кэш В globals dict (не на fake_core — global в _get_version
        # ссылается на оригинальный exec'd dict, он же self._core_globals).
        self._core_globals["_CACHED_VERSION"] = "test-cached-value"
        v2 = self._fake_core._get_version()
        self.assertEqual(v2, "test-cached-value",
                         "Second call should return cached value, not re-import")

    def test_monkeypatch_version_propagates_to_get_version(self):
        """Monkey-patch __version__ на "9.9.9" → _get_version() возвращает "9.9.9".

        Сначала сбрасываем кэш (т.к. exec _core.py уже вызвал _get_version()
        при строке log_to_file), затем патчим __version__ и проверяем.
        """
        # Сбрасываем кэш в globals dict
        self._core_globals["_CACHED_VERSION"] = ""

        # Monkey-patch __version__
        import vless_installer
        original_version = vless_installer.__version__
        try:
            vless_installer.__version__ = "9.9.9"
            version = self._fake_core._get_version()
        finally:
            vless_installer.__version__ = original_version

        self.assertEqual(version, "9.9.9",
                         f"Expected '9.9.9' after monkey-patch, got {version!r}")

    def test_monkeypatch_version_propagates_to_banner(self):
        """Баннер (print_banner) подхватывает monkey-patched версию.

        print_banner() использует _get_version() в f-string для ASCII-баннера.
        Проверяем что "9.9.9" появляется в выводе.
        """
        # Сбрасываем кэш в globals dict
        self._core_globals["_CACHED_VERSION"] = ""

        # Monkey-patch __version__
        import vless_installer
        original_version = vless_installer.__version__
        try:
            vless_installer.__version__ = "9.9.9"
            # Захватываем stdout
            captured = io.StringIO()
            with redirect_stdout(captured):
                self._fake_core.print_banner()
        finally:
            vless_installer.__version__ = original_version

        output = captured.getvalue()
        self.assertIn("9.9.9", output,
                      f"Expected '9.9.9' in banner output, got:\n{output}")
        # Убеждаемся что старая версия НЕ появилась
        self.assertNotIn("4.25.0", output,
                         f"Old hardcoded version 4.25.0 should NOT appear in banner, "
                         f"got:\n{output}")

    def test_monkeypatch_version_propagates_to_main_menu(self):
        """Статус-бар главного меню подхватывает monkey-patched версию.

        main_menu() использует _get_version() в f-string для строки
        "VLESS Ultimate Installer v{version}".
        """
        # Сбрасываем кэш в globals dict
        self._core_globals["_CACHED_VERSION"] = ""

        # Monkey-patch __version__
        import vless_installer
        original_version = vless_installer.__version__
        try:
            vless_installer.__version__ = "9.9.9"

            # main_menu() — это бесконечный цикл с input(). Мокаем input
            # чтобы выйти после первой итерации.
            call_count = [0]
            def mock_input(prompt):
                call_count[0] += 1
                if call_count[0] == 1:
                    return "q"  # exit menu
                raise KeyboardInterrupt

            # Также мокаем os.system("clear") чтобы не засорять вывод
            with patch("builtins.input", side_effect=mock_input), \
                 patch("os.system"), \
                 patch("time.sleep"):
                # Захватываем stdout
                captured = io.StringIO()
                try:
                    with redirect_stdout(captured):
                        self._fake_core.main_menu()
                except (KeyboardInterrupt, SystemExit):
                    pass  # menu exit

        finally:
            vless_installer.__version__ = original_version

        output = captured.getvalue()
        self.assertIn("9.9.9", output,
                      f"Expected '9.9.9' in main_menu output, got:\n{output[:500]}")

    def test_no_hardcoded_version_in_core_py(self):
        """В _core.py не должно остаться хардкода '4.25.0' (кроме исторических
        комментариев про старые версии).

        Этот тест — regression guard: если кто-то снова впишет хардкод,
        тест поймает.
        """
        core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
        content = core_path.read_text()
        # Ищем "v4.25.0" или "4.25.0" в контексте версии проекта.
        # Допускаются исторические упоминания старых версий (v4.20.x, v4.23.x).
        # Но текущая версия (4.25.0) НЕ должна быть захардкожена.
        lines_with_current_version = [
            line.strip()
            for i, line in enumerate(content.splitlines(), 1)
            if "4.25.0" in line
        ]
        self.assertEqual(lines_with_current_version, [],
                         f"_core.py contains hardcoded '4.25.0' on lines: "
                         f"{lines_with_current_version}. Use _get_version() instead.")


if __name__ == "__main__":
    unittest.main()
