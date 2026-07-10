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
        from vless_installer.modules.test_runner import run_tests_cli
        # Не проверяем exit_code — могут быть expected failures
        # Главное — не падает
        exit_code = run_tests_cli("all")
        self.assertIn(exit_code, (0, 1))


if __name__ == "__main__":
    unittest.main(verbosity=2)
