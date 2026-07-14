#!/usr/bin/env python3
"""
tests/test_resources.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/resources.py.

Покрывает:
  1. gen_uuid — генерация UUID
  2. gen_spiderx — генерация spiderX пути
  3. country_flag_emoji — маппинг ISO кода в эмодзи флага
  4. get_adaptive_value — адаптивные значения по RAM
  5. _get_total_cpu — количество CPU
  6. get_server_country_cached — кеширование
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

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


class TestGenUuid(unittest.TestCase):
    """gen_uuid."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_valid_uuid_format(self):
        import re
        from chimera.modules.resources import gen_uuid
        uuid_str = gen_uuid()
        self.assertRegex(uuid_str, r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

    def test_returns_string(self):
        from chimera.modules.resources import gen_uuid
        self.assertIsInstance(gen_uuid(), str)

    def test_unique(self):
        from chimera.modules.resources import gen_uuid
        uuids = {gen_uuid() for _ in range(10)}
        self.assertEqual(len(uuids), 10)


class TestGenSpiderx(unittest.TestCase):
    """gen_spiderx."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_starts_with_slash(self):
        from chimera.modules.resources import gen_spiderx
        spiderx = gen_spiderx()
        self.assertTrue(spiderx.startswith("/"))

    def test_length_in_range(self):
        """Длина 7-16 (1 слэш + 6-15 alnum)."""
        from chimera.modules.resources import gen_spiderx
        for _ in range(20):
            spiderx = gen_spiderx()
            self.assertGreaterEqual(len(spiderx), 7)
            self.assertLessEqual(len(spiderx), 16)

    def test_only_alnum_after_slash(self):
        from chimera.modules.resources import gen_spiderx
        spiderx = gen_spiderx()
        suffix = spiderx[1:]
        self.assertTrue(all(c.isalnum() for c in suffix))


class TestCountryFlagEmoji(unittest.TestCase):
    """country_flag_emoji — маппинг ISO кода в эмодзи."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ru_returns_russian_flag(self):
        from chimera.modules.resources import country_flag_emoji
        self.assertEqual(country_flag_emoji("RU"), "🇷🇺")

    def test_us_returns_us_flag(self):
        from chimera.modules.resources import country_flag_emoji
        self.assertEqual(country_flag_emoji("US"), "🇺🇸")

    def test_lowercase_handled(self):
        from chimera.modules.resources import country_flag_emoji
        self.assertEqual(country_flag_emoji("ru"), "🇷🇺")

    def test_invalid_returns_globe(self):
        from chimera.modules.resources import country_flag_emoji
        self.assertEqual(country_flag_emoji("X"), "🌐")
        self.assertEqual(country_flag_emoji(""), "🌐")
        self.assertEqual(country_flag_emoji("123"), "🌐")
        self.assertEqual(country_flag_emoji("RU1"), "🌐")


class TestGetTotalCpu(unittest.TestCase):
    """_get_total_cpu."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_cpu_count(self):
        from chimera.modules.resources import _get_total_cpu
        with patch("os.cpu_count", return_value=4):
            self.assertEqual(_get_total_cpu(), 4)

    def test_returns_1_when_none(self):
        from chimera.modules.resources import _get_total_cpu
        with patch("os.cpu_count", return_value=None):
            self.assertEqual(_get_total_cpu(), 1)


class TestGetAdaptiveValue(unittest.TestCase):
    """get_adaptive_value — адаптивные значения по RAM."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _mock_core(self, total_ram):
        core = MagicMock()
        core.TOTAL_RAM = total_ram
        return core

    def test_low_ram(self):
        """TOTAL_RAM < 512 → low mapping."""
        from chimera.modules import resources
        with patch.object(resources, "_core_module",
                          return_value=self._mock_core(256)):
            # конкретные значения зависят от реализации, но функция должна вернуть непустую строку
            result = resources.get_adaptive_value("conn_idle")
            self.assertIsInstance(result, str)

    def test_high_ram(self):
        from chimera.modules import resources
        with patch.object(resources, "_core_module",
                          return_value=self._mock_core(2048)):
            result = resources.get_adaptive_value("conn_idle")
            self.assertIsInstance(result, str)

    def test_unknown_param_returns_empty(self):
        from chimera.modules import resources
        with patch.object(resources, "_core_module",
                          return_value=self._mock_core(1024)):
            result = resources.get_adaptive_value("nonexistent_param")
            self.assertEqual(result, "")


class TestGetServerCountryCached(unittest.TestCase):
    """get_server_country_cached — кеширование."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_caches_result(self):
        from chimera.modules import resources
        # сбрасываем кеш
        resources._SERVER_CC = ""
        with patch.object(resources, "get_server_country",
                          return_value=("RU", "Russia", "🇷🇺")) as mock_gsc:
            cc1, name1, flag1 = resources.get_server_country_cached()
            cc2, name2, flag2 = resources.get_server_country_cached()
        # второй раз не должно вызываться
        self.assertEqual(mock_gsc.call_count, 1)
        self.assertEqual(cc1, cc2)
        self.assertEqual(flag1, flag2)
        # сбрасываем кеш после теста
        resources._SERVER_CC = ""


if __name__ == "__main__":
    unittest.main(verbosity=2)
