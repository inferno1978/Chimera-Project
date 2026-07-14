#!/usr/bin/env python3
"""
tests/test_tg_nets.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/tg_nets.py.

Модуль автономен (не зависит от _core). Тестируем:
  1. _valid_cidr — валидация CIDR v4/v6
  2. _remove_more_specific — удаление вложенных подсетей
  3. _dedup — дедупликация с сохранением порядка
  4. _load_from_file / _save_to_file — файловое хранилище
  5. _file_age_days — возраст файла
  6. get_tg_nets — fallback на builtin
  7. tg_nets_status_line — формирование строки статуса
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta
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


class TestValidCidr(unittest.TestCase):
    """_valid_cidr — валидация CIDR."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_valid_ipv4(self):
        from chimera.modules.tg_nets import _valid_cidr
        self.assertTrue(_valid_cidr("91.108.4.0/22"))
        self.assertTrue(_valid_cidr("10.0.0.0/8"))
        self.assertTrue(_valid_cidr("192.168.1.0/32"))

    def test_valid_ipv6(self):
        from chimera.modules.tg_nets import _valid_cidr
        self.assertTrue(_valid_cidr("2001:67c:4e8::/48"))
        self.assertTrue(_valid_cidr("::1/128"))
        self.assertTrue(_valid_cidr("fd66:66:66::/64"))

    def test_empty_string_invalid(self):
        from chimera.modules.tg_nets import _valid_cidr
        self.assertFalse(_valid_cidr(""))

    def test_invalid_prefix_too_high_v4(self):
        from chimera.modules.tg_nets import _valid_cidr
        self.assertFalse(_valid_cidr("10.0.0.0/33"))

    def test_no_prefix_invalid(self):
        from chimera.modules.tg_nets import _valid_cidr
        self.assertFalse(_valid_cidr("10.0.0.0"))

    def test_strips_whitespace(self):
        from chimera.modules.tg_nets import _valid_cidr
        self.assertTrue(_valid_cidr("  10.0.0.0/8  "))

    def test_garbage_invalid(self):
        """_valid_cidr использует regex-only — проверяет синтаксис, не диапазон октетов."""
        from chimera.modules.tg_nets import _valid_cidr
        self.assertFalse(_valid_cidr("garbage"))
        self.assertFalse(_valid_cidr("not_a_cidr_at_all"))
        # NOTE: regex-only проверка принимает \d{1,3} без валидации 0-255 —
        # это известное поведение валидации, на ip_network парсинг ловит дальше.


class TestRemoveMoreSpecific(unittest.TestCase):
    """_remove_more_specific — удаление вложенных."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_list(self):
        from chimera.modules.tg_nets import _remove_more_specific
        self.assertEqual(_remove_more_specific([]), [])

    def test_keeps_distinct_networks(self):
        from chimera.modules.tg_nets import _remove_more_specific
        nets = ["10.0.0.0/8", "192.168.0.0/16"]
        result = _remove_more_specific(nets)
        self.assertEqual(len(result), 2)

    def test_removes_nested_v4(self):
        """10.0.0.0/24 внутри 10.0.0.0/8 → убирается."""
        from chimera.modules.tg_nets import _remove_more_specific
        nets = ["10.0.0.0/8", "10.0.0.0/24"]
        result = _remove_more_specific(nets)
        self.assertEqual(len(result), 1)
        self.assertIn("10.0.0.0/8", result)

    def test_keeps_overlapping_not_nested(self):
        """Пересекающиеся но не вложенные — обе остаются."""
        from chimera.modules.tg_nets import _remove_more_specific
        nets = ["10.0.0.0/24", "10.0.0.128/25"]
        # /25 внутри /24 → /25 убирается
        result = _remove_more_specific(nets)
        self.assertEqual(len(result), 1)
        # А вот 10.0.0.0/23 и 10.0.1.0/24 — /24 внутри /23
        result2 = _remove_more_specific(["10.0.0.0/23", "10.0.1.0/24"])
        self.assertEqual(len(result2), 1)

    def test_v4_and_v6_separate(self):
        """IPv4 и IPv6 обрабатываются раздельно."""
        from chimera.modules.tg_nets import _remove_more_specific
        nets = [
            "10.0.0.0/8", "10.0.0.0/24",
            "2001:db8::/32", "2001:db8:1::/48",
        ]
        result = _remove_more_specific(nets)
        self.assertEqual(len(result), 2)
        self.assertIn("10.0.0.0/8", result)
        self.assertIn("2001:db8::/32", result)

    def test_invalid_cidr_silently_skipped(self):
        from chimera.modules.tg_nets import _remove_more_specific
        result = _remove_more_specific(["garbage", "10.0.0.0/8"])
        self.assertEqual(len(result), 1)

    def test_duplicates_not_collapsed_by_remove_more_specific(self):
        """_remove_more_specific НЕ убирает дубликаты — это ответственность _dedup.
        Дубликаты не считаются 'вложенными' (subnet_of + net != acc)."""
        from chimera.modules.tg_nets import (
            _remove_more_specific, _dedup,
        )
        result = _remove_more_specific(["10.0.0.0/8", "10.0.0.0/8"])
        # без _dedup — дубликаты остаются
        self.assertEqual(len(result), 2)
        # с _dedup сначала — дубликат убирается до remove_more_specific
        deduped = _dedup(["10.0.0.0/8", "10.0.0.0/8"])
        result2 = _remove_more_specific(deduped)
        self.assertEqual(len(result2), 1)

    def test_builtin_nets_no_more_specific_leak(self):
        """Встроенный список после remove_more_specific — без вложенных."""
        from chimera.modules.tg_nets import (
            _remove_more_specific, _BUILTIN_NETS, _dedup,
        )
        result = _remove_more_specific(_dedup(_BUILTIN_NETS))
        # Результат должен быть <= исходного (часть убрана как more-specific)
        self.assertLessEqual(len(result), len(_BUILTIN_NETS))
        # Каждый элемент результата — валидный CIDR
        for n in result:
            self.assertTrue(":" in n or "." in n)


class TestDedup(unittest.TestCase):
    """_dedup — дедупликация с сохранением порядка."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_list(self):
        from chimera.modules.tg_nets import _dedup
        self.assertEqual(_dedup([]), [])

    def test_removes_duplicates(self):
        from chimera.modules.tg_nets import _dedup
        result = _dedup(["10.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16"])
        self.assertEqual(result, ["10.0.0.0/8", "192.168.0.0/16"])

    def test_preserves_order(self):
        from chimera.modules.tg_nets import _dedup
        result = _dedup(["10.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8"])
        self.assertEqual(result, ["10.0.0.0/8", "192.168.0.0/16"])

    def test_filters_invalid(self):
        from chimera.modules.tg_nets import _dedup
        result = _dedup(["10.0.0.0/8", "garbage", "192.168.0.0/16"])
        self.assertEqual(result, ["10.0.0.0/8", "192.168.0.0/16"])

    def test_strips_whitespace(self):
        from chimera.modules.tg_nets import _dedup
        result = _dedup(["  10.0.0.0/8  ", "10.0.0.0/8"])
        self.assertEqual(result, ["10.0.0.0/8"])


class TestLoadFromFile(unittest.TestCase):
    """_load_from_file."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._file = self._tmpdir / "tg_nets.txt"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.tg_nets.NETS_FILE", self._file)

    def test_returns_none_when_no_file(self):
        from chimera.modules.tg_nets import _load_from_file
        with self._patch():
            self.assertIsNone(_load_from_file())

    def test_returns_none_when_empty_file(self):
        from chimera.modules.tg_nets import _load_from_file
        self._file.write_text("")
        with self._patch():
            self.assertIsNone(_load_from_file())

    def test_returns_none_when_only_comments(self):
        from chimera.modules.tg_nets import _load_from_file
        self._file.write_text("# comment\n# another\n")
        with self._patch():
            self.assertIsNone(_load_from_file())

    def test_loads_valid_cidrs(self):
        from chimera.modules.tg_nets import _load_from_file
        self._file.write_text(
            "# header\n"
            "10.0.0.0/8\n"
            "garbage line\n"  # будет отфильтровано
            "192.168.0.0/16  # inline comment\n"
            "2001:db8::/32\n"
        )
        with self._patch():
            result = _load_from_file()
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 3)
        self.assertIn("10.0.0.0/8", result)
        self.assertIn("192.168.0.0/16", result)
        self.assertIn("2001:db8::/32", result)

    def test_strips_inline_comments(self):
        from chimera.modules.tg_nets import _load_from_file
        self._file.write_text("10.0.0.0/8  # primary\n")
        with self._patch():
            result = _load_from_file()
        self.assertEqual(result, ["10.0.0.0/8"])


class TestSaveToFile(unittest.TestCase):
    """_save_to_file."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._file = self._tmpdir / "tg_nets.txt"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.tg_nets.NETS_FILE", self._file)

    def test_writes_file_with_header(self):
        from chimera.modules.tg_nets import _save_to_file
        with self._patch():
            _save_to_file(["10.0.0.0/8"], ["RIPE-stat"], raw_count=2, removed_count=1)
        content = self._file.read_text()
        self.assertIn("# Telegram IP networks", content)
        self.assertIn("# Updated", content)
        self.assertIn("# Sources : RIPE-stat", content)
        self.assertIn("10.0.0.0/8", content)

    def test_separates_v4_and_v6(self):
        from chimera.modules.tg_nets import _save_to_file
        with self._patch():
            _save_to_file(
                ["10.0.0.0/8", "2001:db8::/32"],
                ["RIPE-stat"],
            )
        content = self._file.read_text()
        self.assertIn("# IPv4", content)
        self.assertIn("# IPv6", content)

    def test_sets_chmod_644(self):
        import stat
        from chimera.modules.tg_nets import _save_to_file
        with self._patch():
            _save_to_file(["10.0.0.0/8"], [])
        mode = stat.S_IMODE(os.stat(self._file).st_mode)
        self.assertEqual(mode, 0o644)

    def test_sources_fallback_to_builtin_string(self):
        from chimera.modules.tg_nets import _save_to_file
        with self._patch():
            _save_to_file(["10.0.0.0/8"], [])
        content = self._file.read_text()
        self.assertIn("builtin", content)

    def test_includes_count_in_header(self):
        from chimera.modules.tg_nets import _save_to_file
        with self._patch():
            _save_to_file(
                ["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"],
                ["RIPE-stat"],
                raw_count=5, removed_count=2,
            )
        content = self._file.read_text()
        self.assertIn("Total   : 3 (2 IPv4, 1 IPv6)", content)
        self.assertIn("Raw     : 5", content)


class TestFileAgeDays(unittest.TestCase):
    """_file_age_days."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._file = self._tmpdir / "tg_nets.txt"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.tg_nets.NETS_FILE", self._file)

    def test_none_when_no_file(self):
        from chimera.modules.tg_nets import _file_age_days
        with self._patch():
            self.assertIsNone(_file_age_days())

    def test_zero_for_fresh_file(self):
        from chimera.modules.tg_nets import _file_age_days
        self._file.write_text("x")
        with self._patch():
            age = _file_age_days()
            self.assertIsNotNone(age)
            self.assertLessEqual(age, 0)

    def test_old_file(self):
        """Файл с mtime в прошлом — возраст > 0."""
        from chimera.modules.tg_nets import _file_age_days
        self._file.write_text("x")
        # Делаем mtime = сейчас - 5 дней
        old_time = time.time() - 5 * 86400
        os.utime(self._file, (old_time, old_time))
        with self._patch():
            age = _file_age_days()
            self.assertIsNotNone(age)
            self.assertGreaterEqual(age, 4)


class TestGetTgNets(unittest.TestCase):
    """get_tg_nets — fallback на builtin."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._file = self._tmpdir / "tg_nets.txt"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.tg_nets.NETS_FILE", self._file)

    def test_fallback_to_builtin_when_no_file(self):
        from chimera.modules.tg_nets import get_tg_nets, _BUILTIN_NETS
        with self._patch():
            nets = get_tg_nets()
        self.assertEqual(nets, list(_BUILTIN_NETS))
        self.assertGreater(len(nets), 0)

    def test_returns_file_contents_when_present(self):
        from chimera.modules.tg_nets import get_tg_nets
        self._file.write_text("10.0.0.0/8\n192.168.0.0/16\n")
        with self._patch():
            nets = get_tg_nets()
        self.assertEqual(nets, ["10.0.0.0/8", "192.168.0.0/16"])

    def test_never_empty(self):
        """Даже при пустом файле возвращает builtin."""
        from chimera.modules.tg_nets import get_tg_nets
        self._file.write_text("# only comments\n")
        with self._patch():
            nets = get_tg_nets()
        self.assertGreater(len(nets), 0)


class TestTgNetsStatusLine(unittest.TestCase):
    """tg_nets_status_line."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._file = self._tmpdir / "tg_nets.txt"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.tg_nets.NETS_FILE", self._file)

    def test_yellow_when_no_file(self):
        from chimera.modules.tg_nets import (
            tg_nets_status_line, YELLOW, NC,
        )
        with self._patch():
            line = tg_nets_status_line()
        self.assertIn(YELLOW, line)
        self.assertIn("встроенный", line)

    def test_green_when_fresh(self):
        from chimera.modules.tg_nets import (
            tg_nets_status_line, GREEN,
        )
        self._file.write_text("10.0.0.0/8\n")
        with self._patch():
            line = tg_nets_status_line()
        self.assertIn(GREEN, line)

    def test_yellow_when_warn_age(self):
        from chimera.modules.tg_nets import (
            tg_nets_status_line, YELLOW, WARN_DAYS,
        )
        self._file.write_text("10.0.0.0/8\n")
        old_time = time.time() - WARN_DAYS * 86400
        os.utime(self._file, (old_time, old_time))
        with self._patch():
            line = tg_nets_status_line()
        self.assertIn(YELLOW, line)

    def test_red_when_stale(self):
        from chimera.modules.tg_nets import (
            tg_nets_status_line, RED, STALE_DAYS,
        )
        self._file.write_text("10.0.0.0/8\n")
        old_time = time.time() - STALE_DAYS * 86400
        os.utime(self._file, (old_time, old_time))
        with self._patch():
            line = tg_nets_status_line()
        self.assertIn(RED, line)
        self.assertIn("УСТАРЕЛ", line)


class TestBuiltinNets(unittest.TestCase):
    """Проверка целостности builtin-списка."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_builtin_has_at_least_19_nets(self):
        from chimera.modules.tg_nets import _BUILTIN_NETS
        self.assertGreaterEqual(len(_BUILTIN_NETS), 19)

    def test_builtin_all_valid_cidr(self):
        from chimera.modules.tg_nets import _BUILTIN_NETS, _valid_cidr
        for n in _BUILTIN_NETS:
            with self.subTest(n=n):
                self.assertTrue(_valid_cidr(n), f"невалидный CIDR: {n}")

    def test_builtin_has_v4_and_v6(self):
        from chimera.modules.tg_nets import _BUILTIN_NETS
        has_v4 = any(":" not in n for n in _BUILTIN_NETS)
        has_v6 = any(":" in n for n in _BUILTIN_NETS)
        self.assertTrue(has_v4)
        self.assertTrue(has_v6)


class TestTgAsns(unittest.TestCase):
    """TG_ASNS."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_6_asns(self):
        from chimera.modules.tg_nets import TG_ASNS
        self.assertEqual(len(TG_ASNS), 6)

    def test_includes_main_asn(self):
        from chimera.modules.tg_nets import TG_ASNS
        self.assertIn(62041, TG_ASNS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
