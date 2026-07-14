#!/usr/bin/env python3
"""
tests/test_core_dynamic_version.py
───────────────────────────────────────────────────────────────────────────────
Тест динамической подстановки версии в chimera/_core.py.

Проверяет что _get_version() берёт версию из chimera.__version__,
а не из хардкода. Monkey-patch'ит __version__ на "9.9.9" и проверяет,
что баннер/лог/статус-бар реально подхватывают новое значение.

Аналогично паттерну honeypot.py (см. CHANGELOG: "хардкоженный v4.11 в
генерируемом конфиге заменён на динамическую вставку
chimera.__version__").
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
    """Создаёт фейковый chimera._core (как в test_tg_bot.py).

    Возвращает (fake_core, globals_dict) — globals_dict это тот самый dict
    который был передан в exec() и стал __globals__ для всех функций.
    """
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
    return fake_core, g


class TestCoreDynamicVersion(unittest.TestCase):
    """Проверяет что _core.py берёт версию динамически из __version__."""

    def setUp(self):
        self._fake_core, self._core_globals = _setup_core_in_sysmodules()

    def test_get_version_returns_from_init(self):
        """_get_version() возвращает значение из chimera.__version__."""
        version = self._fake_core._get_version()
        # Должно совпадать с __version__ из __init__.py
        from chimera import __version__ as real_version
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
        import chimera
        original_version = chimera.__version__
        try:
            chimera.__version__ = "9.9.9"
            version = self._fake_core._get_version()
        finally:
            chimera.__version__ = original_version

        self.assertEqual(version, "9.9.9",
                         f"Expected '9.9.9' after monkey-patch, got {version!r}")

    def test_monkeypatch_version_propagates_to_banner(self):
        """Баннер (print_banner) подхватывает monkey-patched версию.

        print_banner() использует _get_version() в f-string для ASCII-баннера.
        Проверяем что "9.9.9" появляется в выводе, а оригинальная версия
        (прочитанная динамически из chimera.__version__ ДО monkey-patch)
        — НЕ появляется. Это защищает от регрессии: если баннер перестанет
        использовать _get_version() и вернётся к хардкоду, оригинальная
        версия останется в выводе даже после monkey-patch.
        """
        # Сбрасываем кэш в globals dict
        self._core_globals["_CACHED_VERSION"] = ""

        # Читаем оригинальную версию ДО monkey-patch — это значение НЕ должно
        # появиться в выводе после подмены на "9.9.9". Динамическое чтение,
        # не хардкод — при следующем бампе версии тест сам подтянется.
        import chimera
        original_version = chimera.__version__
        try:
            chimera.__version__ = "9.9.9"
            # Захватываем stdout
            captured = io.StringIO()
            with redirect_stdout(captured):
                self._fake_core.print_banner()
        finally:
            chimera.__version__ = original_version

        output = captured.getvalue()
        self.assertIn("9.9.9", output,
                      f"Expected '9.9.9' in banner output, got:\n{output}")
        # Убеждаемся что оригинальная версия НЕ появилась — если бы баннер
        # использовал хардкод вместо _get_version(), оригинал остался бы.
        self.assertNotIn(original_version, output,
                         f"Original version {original_version!r} should NOT appear "
                         f"in banner after monkey-patch to '9.9.9' — this would "
                         f"mean banner uses hardcoded version instead of "
                         f"_get_version(). Got:\n{output}")

    def test_main_menu_shows_current_version(self):
        """Регрессионный тест Т4 (патч версии 4.25.1): главное меню
        показывает ТЕКУЩУЮ версию проекта в строке баннера.

        main_menu() использует _get_version() в f-string для строки
        "Chimera Project v{version}". После бампа версии
        баннер должен показывать новое значение, а не старое и не "unknown".

        ВАЖНО: тест НЕ хардкодит "4.25.1" — читает текущую версию из
        chimera.__version__ и проверяет, что она появилась в выводе.
        При следующем бампе тест сам подтянется.
        """
        # Сбрасываем кэш — _core.py уже вызвал _get_version() при exec.
        self._core_globals["_CACHED_VERSION"] = ""

        from chimera import __version__ as current_version
        # main_menu() — бесконечный цикл с input(). Мокаем чтобы выйти.
        call_count = [0]
        def mock_input(prompt):
            call_count[0] += 1
            if call_count[0] == 1:
                return "q"
            raise KeyboardInterrupt

        with patch("builtins.input", side_effect=mock_input), \
             patch("os.system"), \
             patch("time.sleep"):
            captured = io.StringIO()
            try:
                with redirect_stdout(captured):
                    self._fake_core.main_menu()
            except (KeyboardInterrupt, SystemExit):
                pass

        output = captured.getvalue()
        self.assertIn(current_version, output,
                      f"Main menu banner should contain current version "
                      f"{current_version!r}, got:\n{output[:500]}")
        self.assertNotIn("unknown", output.lower(),
                         f"Banner should NOT show 'unknown' — means "
                         f"_get_version() failed to import __version__. "
                         f"Got:\n{output[:500]}")

    def test_monkeypatch_version_propagates_to_main_menu(self):
        """Статус-бар главного меню подхватывает monkey-patched версию.

        main_menu() использует _get_version() в f-string для строки
        "Chimera Project v{version}".
        """
        # Сбрасываем кэш в globals dict
        self._core_globals["_CACHED_VERSION"] = ""

        # Monkey-patch __version__
        import chimera
        original_version = chimera.__version__
        try:
            chimera.__version__ = "9.9.9"

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
            chimera.__version__ = original_version

        output = captured.getvalue()
        self.assertIn("9.9.9", output,
                      f"Expected '9.9.9' in main_menu output, got:\n{output[:500]}")

    def test_no_hardcoded_current_version_in_core_py(self):
        """В _core.py не должно остаться хардкода ТЕКУЩЕЙ версии проекта
        (кроме исторических комментариев про старые версии).

        Этот тест — regression guard: если кто-то снова впишет хардкод
        текущей версии вместо _get_version(), тест поймает.

        ВАЖНО: тест НЕ хардкодит конкретную версию (типа "X.Y.Z" —
        текущее значение). Он читает текущую версию из chimera.__version__
        в момент запуска и ищет её как литерал в _core.py. При следующем
        бампе версии тест сам подтянется — не нужно править тест руками.

        Допускаются исторические упоминания СТАРЫХ версий (v4.20.x, v4.23.x
        и т.д. в комментариях типа "# v4.23.8: ..." — это история, не хардкод
        текущей версии). Текущая версия в виде литерала запрещена — её
        единственное законное место в _core.py — это результат вызова
        _get_version(), который возвращает её из chimera.__version__.
        """
        import re
        core_path = _PROJECT_ROOT / "chimera" / "_core.py"
        content = core_path.read_text()

        # Динамически читаем текущую версию — НЕ хардкодим "4.25.x".
        from chimera import __version__ as current_version
        # Экранируем для regex (точки — это метасимволы).
        version_pattern = re.escape(current_version)

        lines_with_current_version = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            # Пропускаем комментарии и докстринги — там могут быть исторические
            # упоминания. Но в _core.py НЕТ активного кода с текущей версией
            # как литералом (всё через _get_version()).
            # Исторические упоминания старых версий (v4.20.x, v4.23.x) нас не
            # интересуют — мы ищем только CURRENT version.
            if re.search(version_pattern, line):
                lines_with_current_version.append((i, line.rstrip()))

        self.assertEqual(lines_with_current_version, [],
                         f"_core.py contains hardcoded current version "
                         f"{current_version!r} on lines: "
                         f"{lines_with_current_version}. "
                         f"Use _get_version() instead — version must come from "
                         f"chimera.__version__, not from a string literal.")


if __name__ == "__main__":
    unittest.main()
