#!/usr/bin/env python3
"""
tests/test_test_runner.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/test_runner.py.

Покрывает:
  1. TEST_GROUPS — структура групп
  2. _run_test_modules — запуск тестов
  3. _run_py_compile — проверка синтаксиса
  4. _format_report — форматирование отчёта
  5. run_tests_cli — CLI-интерфейс
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

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


class TestTestGroups(unittest.TestCase):
    """TEST_GROUPS — структура групп."""

    def setUp(self):
        _setup_core()

    def test_has_9_groups_plus_all(self):
        from vless_installer.modules.test_runner import TEST_GROUPS
        # Ключи '1'-'9' + 'A'
        for key in ("1", "2", "3", "4", "5", "6", "7", "8", "9", "A"):
            self.assertIn(key, TEST_GROUPS)

    def test_each_group_has_required_fields(self):
        from vless_installer.modules.test_runner import TEST_GROUPS
        for key, group in TEST_GROUPS.items():
            with self.subTest(group=key):
                self.assertIn("label", group)
                self.assertIn("description", group)
                self.assertIn("tests", group)
                self.assertIsInstance(group["tests"], list)
                self.assertGreater(len(group["tests"]), 0)

    def test_all_test_names_are_strings(self):
        from vless_installer.modules.test_runner import TEST_GROUPS
        for key, group in TEST_GROUPS.items():
            for name in group["tests"]:
                with self.subTest(group=key, test=name):
                    self.assertIsInstance(name, str)

    def test_no_duplicate_tests_across_groups(self):
        """Тест не должен встречаться в двух группах одновременно."""
        from vless_installer.modules.test_runner import TEST_GROUPS
        all_tests = []
        for group in TEST_GROUPS.values():
            all_tests.extend(group["tests"])
        self.assertEqual(len(all_tests), len(set(all_tests)),
                         "Duplicate test names found across groups")

    def test_all_test_files_exist(self):
        """Каждый тест в группах соответствует существующему файлу."""
        from vless_installer.modules.test_runner import TEST_GROUPS, _TESTS_DIR
        for key, group in TEST_GROUPS.items():
            for name in group["tests"]:
                test_file = _TESTS_DIR / f"test_{name}.py"
                with self.subTest(group=key, test=name):
                    self.assertTrue(test_file.exists(),
                                    f"test_{name}.py not found in tests/")


class TestRunTestModules(unittest.TestCase):
    """_run_test_modules — запуск тестов."""

    def setUp(self):
        _setup_core()

    def test_returns_correct_structure(self):
        from vless_installer.modules.test_runner import _run_test_modules
        stats = _run_test_modules(["awg_constants"])
        for key in ("found", "not_found", "tests_run", "failures",
                     "errors", "skipped", "expected_failures", "output",
                     "result_obj"):
            self.assertIn(key, stats)

    def test_runs_real_tests(self):
        from vless_installer.modules.test_runner import _run_test_modules
        stats = _run_test_modules(["awg_constants"])
        self.assertEqual(len(stats["found"]), 1)
        self.assertEqual(stats["not_found"], [])
        self.assertGreater(stats["tests_run"], 0)
        self.assertEqual(stats["failures"], 0)
        self.assertEqual(stats["errors"], 0)

    def test_handles_nonexistent_module(self):
        from vless_installer.modules.test_runner import _run_test_modules
        stats = _run_test_modules(["nonexistent_xyz"])
        self.assertEqual(stats["found"], [])
        self.assertEqual(stats["not_found"], ["nonexistent_xyz"])
        self.assertEqual(stats["tests_run"], 0)

    def test_mixed_existing_and_nonexistent(self):
        from vless_installer.modules.test_runner import _run_test_modules
        stats = _run_test_modules(["awg_constants", "nonexistent_xyz"])
        self.assertEqual(len(stats["found"]), 1)
        self.assertEqual(stats["not_found"], ["nonexistent_xyz"])
        self.assertGreater(stats["tests_run"], 0)


class TestRunPyCompile(unittest.TestCase):
    """_run_py_compile — проверка синтаксиса."""

    def setUp(self):
        _setup_core()

    def test_returns_tuple_of_three(self):
        from vless_installer.modules.test_runner import _run_py_compile
        result = _run_py_compile()
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 3)

    def test_finds_no_errors_in_project(self):
        from vless_installer.modules.test_runner import _run_py_compile
        ok, fail, errors = _run_py_compile()
        self.assertGreater(ok, 0)
        self.assertEqual(fail, 0)
        self.assertEqual(errors, [])


class TestFormatReport(unittest.TestCase):
    """_format_report — форматирование отчёта."""

    def setUp(self):
        _setup_core()

    def test_returns_string(self):
        from vless_installer.modules.test_runner import _format_report, _run_test_modules
        stats = _run_test_modules(["awg_constants"])
        report = _format_report("Test Group", stats, 1.5)
        self.assertIsInstance(report, str)
        self.assertIn("Test Group", report)
        self.assertIn("Tests run:", report)

    def test_includes_timestamp(self):
        from vless_installer.modules.test_runner import _format_report, _run_test_modules
        stats = _run_test_modules(["awg_constants"])
        report = _format_report("Test", stats, 0.1)
        self.assertIn("Timestamp:", report)

    def test_includes_duration(self):
        from vless_installer.modules.test_runner import _format_report, _run_test_modules
        stats = _run_test_modules(["awg_constants"])
        report = _format_report("Test", stats, 3.14)
        self.assertIn("3.1s", report)


class TestRunTestsCli(unittest.TestCase):
    """run_tests_cli — CLI-интерфейс."""

    def setUp(self):
        _setup_core()

    def test_returns_zero_on_success(self):
        from vless_installer.modules.test_runner import run_tests_cli
        exit_code = run_tests_cli("4")  # Mieru group
        self.assertEqual(exit_code, 0)

    def test_returns_nonzero_on_failure(self):
        from vless_installer.modules.test_runner import run_tests_cli
        # Несуществующая группа
        exit_code = run_tests_cli("nonexistent")
        self.assertEqual(exit_code, 1)

    def test_compile_returns_zero(self):
        from vless_installer.modules.test_runner import run_tests_cli
        exit_code = run_tests_cli("compile")
        self.assertEqual(exit_code, 0)

    def test_all_runs_without_crash(self):
        """run_tests_cli('all') не должен падать. Запускает ВСЕ 121 тест-модуль
        в одном сабпроцессе — может занять несколько минут.
        Пропускаем в обычном прогоне (mark with @unittest.skipIf через env var
        VLESS_RUN_SLOW_TESTS=1 чтобы включить)."""
        import os
        if not os.environ.get("VLESS_RUN_SLOW_TESTS"):
            self.skipTest("Медленный тест (запускает все 121 модуль). "
                          "Установите VLESS_RUN_SLOW_TESTS=1 чтобы выполнить.")
        from vless_installer.modules.test_runner import run_tests_cli
        # Не проверяем exit_code — могут быть expected failures
        # Главное — не падает
        exit_code = run_tests_cli("all")
        self.assertIn(exit_code, (0, 1))


# ══════════════════════════════════════════════════════════════════════════════
#  РЕГРЕССИЯ: sys.modules["vless_installer._core"] НЕ должен меняться
#  после прогона тестов из TUI-меню.
#
#  Баг (коммит 20101ea): test_runner.py запускал тесты in-process через
#  unittest.TestLoader. Каждый test-файл в setUp() делал
#      sys.modules["vless_installer._core"] = types.ModuleType(...)
#  БЕЗ tearDown. При запуске из живого TUI (тот же процесс что main_menu())
#  подмена оставалась навсегда — module-level state (PROGRESS,
#  INSTALL_START_TIME, TOTAL_RAM, BANNER) пересоздавался.
#
#  Фикс: тесты запускаются в ИЗОЛИРОВАННОМ САБПРОЦЕССЕ через
#  `sys.executable -m unittest ...`. Сабпроцесс имеет свой sys.modules —
#  любые подмены остаются в нём.
# ══════════════════════════════════════════════════════════════════════════════

class TestSysModulesIsolation(unittest.TestCase):
    """Регрессия: sys.modules['vless_installer._core'] должен остаться тем же
    объектом (is identity) после _run_test_modules().

    До фикса: тесты in-process подменяли sys.modules['vless_installer._core']
    в setUp() без tearDown — подмена оставалась навсегда в живом TUI.
    После фикса: тесты в сабпроцессе, родительский sys.modules не трогается.
    """

    def setUp(self):
        _setup_core()
        # Сохраняем reference на текущий _core модуль ДО прогона тестов
        import vless_installer._core as core_mod
        self._core_before = core_mod
        # Также сохраняем id() для надёжности
        self._core_id_before = id(sys.modules.get("vless_installer._core"))

    def test_core_module_identity_preserved_after_run(self):
        """КЛЮЧЕВОЙ ТЕСТ: sys.modules['vless_installer._core'] должен быть
        ТЕМ ЖЕ объектом (is) после _run_test_modules(), не новым."""
        from vless_installer.modules.test_runner import _run_test_modules

        # Запускаем группу тестов (awg_constants — маленькая и быстрая)
        stats = _run_test_modules(["awg_constants"])

        # Проверяем что прогон вообще состоялся
        self.assertGreater(stats["tests_run"], 0,
                           "Тесты должны были запуститься для проверки изоляции")

        # Получаем текущий _core модуль ПОСЛЕ прогона
        core_after = sys.modules.get("vless_installer._core")
        self.assertIsNotNone(core_after,
                             "sys.modules['vless_installer._core'] должен существовать")

        # КЛЮЧЕВАЯ ПРОВЕРКА: тот же объект (is identity)
        self.assertIs(core_after, self._core_before,
                      "sys.modules['vless_installer._core'] должен быть тем же объектом "
                      "после _run_test_modules(). Баг 20101ea: подмена в setUp() без tearDown.")

        # Двойная проверка через id()
        self.assertEqual(id(core_after), self._core_id_before,
                         "id() модуля не должен измениться")

    def test_core_module_identity_preserved_after_mieru_group(self):
        """Та же проверка для группы Mieru — эти тесты ТОЧНО делают
        sys.modules['vless_installer._core'] = ... в setUp (см. test_mieru.py).
        Если изоляция работает — родительский _core не изменится."""
        from vless_installer.modules.test_runner import _run_test_modules

        stats = _run_test_modules(["mieru"])

        # Эти тесты должны запуститься
        self.assertGreater(stats["tests_run"], 0)

        core_after = sys.modules.get("vless_installer._core")
        self.assertIs(core_after, self._core_before,
                      "Даже после группы Mieru (которая подменяет _core в setUp) "
                      "родительский _core должен остаться тем же объектом.")

    def test_core_module_identity_preserved_after_multiple_groups(self):
        """Проверка что несколько прогонов подряд не накапливают подмену."""
        from vless_installer.modules.test_runner import _run_test_modules

        # Прогоняем 3 разные группы подряд
        for group in (["awg_constants"], ["mieru"], ["text_width"]):
            _run_test_modules(group)

        core_after = sys.modules.get("vless_installer._core")
        self.assertIs(core_after, self._core_before,
                      "После 3 прогонов разных групп _core должен остаться тем же объектом")


class TestModuleLevelStateIsolation(unittest.TestCase):
    """Регрессия: module-level state _core (PROGRESS, INSTALL_START_TIME)
    не должен меняться после прогона тестов из TUI.

    До фикса: подмена sys.modules['vless_installer._core'] пересоздавала
    module-level state. PROGRESS = Progress() — новый синглтон,
    INSTALL_START_TIME = time.time() — новая временная метка.
    После фикса: сабпроцесс изолирован, родительский state не трогается.
    """

    def setUp(self):
        _setup_core()
        import vless_installer._core as core_mod
        # Сохраняем references на module-level state ДО прогона
        self._progress_before = core_mod.PROGRESS
        self._install_start_time_before = core_mod.INSTALL_START_TIME
        self._total_ram_before = core_mod.TOTAL_RAM
        self._total_cpu_before = core_mod.TOTAL_CPU
        self._banner_before = core_mod.BANNER

    def test_progress_singleton_unchanged(self):
        """PROGRESS (синглтон Progress()) не должен пересоздаваться."""
        from vless_installer.modules.test_runner import _run_test_modules
        _run_test_modules(["awg_constants"])

        import vless_installer._core as core_mod
        self.assertIs(core_mod.PROGRESS, self._progress_before,
                      "PROGRESS синглтон должен остаться тем же объектом. "
                      "Баг 20101ea: подмена _core пересоздавала PROGRESS.")

    def test_install_start_time_unchanged(self):
        """INSTALL_START_TIME = time.time() не должен меняться."""
        from vless_installer.modules.test_runner import _run_test_modules
        _run_test_modules(["awg_constants"])

        import vless_installer._core as core_mod
        self.assertEqual(core_mod.INSTALL_START_TIME, self._install_start_time_before,
                         "INSTALL_START_TIME не должен измениться после прогона тестов")

    def test_total_ram_unchanged(self):
        """TOTAL_RAM (реальный системный вызов) не должен пересчитываться."""
        from vless_installer.modules.test_runner import _run_test_modules
        _run_test_modules(["awg_constants"])

        import vless_installer._core as core_mod
        self.assertEqual(core_mod.TOTAL_RAM, self._total_ram_before,
                         "TOTAL_RAM не должен измениться")

    def test_total_cpu_unchanged(self):
        """TOTAL_CPU не должен пересчитываться."""
        from vless_installer.modules.test_runner import _run_test_modules
        _run_test_modules(["awg_constants"])

        import vless_installer._core as core_mod
        self.assertEqual(core_mod.TOTAL_CPU, self._total_cpu_before,
                         "TOTAL_CPU не должен измениться")

    def test_banner_unchanged(self):
        """BANNER (строка) не должен пересоздаваться."""
        from vless_installer.modules.test_runner import _run_test_modules
        _run_test_modules(["awg_constants"])

        import vless_installer._core as core_mod
        self.assertEqual(core_mod.BANNER, self._banner_before,
                         "BANNER не должен измениться")

    def test_all_state_unchanged_after_mieru_group(self):
        """Комплексная проверка после группы Mieru (которая точно подменяет
        _core в setUp) — ВСЕ module-level state должны остаться нетронутыми."""
        from vless_installer.modules.test_runner import _run_test_modules
        _run_test_modules(["mieru"])

        import vless_installer._core as core_mod
        self.assertIs(core_mod.PROGRESS, self._progress_before,
                      "PROGRESS не должен измениться после Mieru")
        self.assertEqual(core_mod.INSTALL_START_TIME, self._install_start_time_before,
                         "INSTALL_START_TIME не должен измениться после Mieru")
        self.assertEqual(core_mod.TOTAL_RAM, self._total_ram_before,
                         "TOTAL_RAM не должен измениться после Mieru")
        self.assertEqual(core_mod.TOTAL_CPU, self._total_cpu_before,
                         "TOTAL_CPU не должен измениться после Mieru")


class TestSubprocessIsolation(unittest.TestCase):
    """Дополнительные проверки того что тесты реально запускаются в
    сабпроцессе (а не in-process), и что сабпроцесс изолирован."""

    def setUp(self):
        _setup_core()

    def test_run_test_modules_returns_returncode(self):
        """_run_test_modules должен возвращать returncode сабпроцесса."""
        from vless_installer.modules.test_runner import _run_test_modules
        stats = _run_test_modules(["awg_constants"])
        self.assertIn("returncode", stats,
                      "stats dict должен содержать returncode сабпроцесса")
        # 0 = OK, 1 = failures/errors (unittest exit codes)
        self.assertIn(stats["returncode"], (0, 1),
                      "returncode должен быть 0 (OK) или 1 (failures)")

    def test_subprocess_does_not_inherit_test_state(self):
        """Если мы изменим sys.modules['vless_installer._core'] в родителе
        ДО вызова _run_test_modules, сабпроцесс НЕ должен это унаследовать
        (он стартует с чистого sys.path и собирает _core заново)."""
        import types
        # Подменяем _core в родительском процессе
        fake_core = types.ModuleType("vless_installer._core")
        fake_core.FAKE_MARKER = "parent_fake"
        original_core = sys.modules.get("vless_installer._core")
        sys.modules["vless_installer._core"] = fake_core

        try:
            from vless_installer.modules.test_runner import _run_test_modules
            # Запускаем тесты — сабпроцесс не должен унаследовать fake_core
            stats = _run_test_modules(["awg_constants"])
        finally:
            # Восстанавливаем оригинальный _core в родителе
            if original_core is not None:
                sys.modules["vless_installer._core"] = original_core

        # Тесты в сабпроцессе должны были запуститься (если бы они унаследовали
        # fake_core без реальных атрибутов, они бы упали с AttributeError)
        self.assertGreater(stats["tests_run"], 0,
                           "Сабпроцесс должен запустить тесты независимо от родительского sys.modules")
        self.assertEqual(stats["errors"], 0,
                         "Сабпроцесс не должен унаследовать сломанный _core из родителя")


if __name__ == "__main__":
    unittest.main(verbosity=2)
