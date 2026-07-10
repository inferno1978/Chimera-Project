#!/usr/bin/env python3
"""
tests/test_network_bench.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/network_bench.py.

Покрывает:
  1. calc_size — конвертация байт
  2. _c — цветная строка
  3. read_cpuinfo — парсинг /proc/cpuinfo
  4. read_meminfo — парсинг /proc/meminfo
  5. get_load_average — load average
  6. get_uptime — uptime
  7. check_rate_limit / mark_success — rate limiting
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
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


class TestCalcSize(unittest.TestCase):
    """calc_size — конвертация байт."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_zero_returns_empty(self):
        from vless_installer.modules.network_bench import calc_size
        self.assertEqual(calc_size(0), "")

    def test_negative_returns_empty(self):
        from vless_installer.modules.network_bench import calc_size
        self.assertEqual(calc_size(-1), "")

    def test_bytes(self):
        from vless_installer.modules.network_bench import calc_size
        self.assertIn("B", calc_size(1))
        self.assertIn("B", calc_size(1023))

    def test_kilobytes(self):
        from vless_installer.modules.network_bench import calc_size
        result = calc_size(1024)
        self.assertIn("KB", result)

    def test_megabytes(self):
        from vless_installer.modules.network_bench import calc_size
        result = calc_size(1024 ** 2)
        self.assertIn("MB", result)

    def test_gigabytes(self):
        from vless_installer.modules.network_bench import calc_size
        result = calc_size(1024 ** 3)
        self.assertIn("GB", result)

    def test_terabytes(self):
        from vless_installer.modules.network_bench import calc_size
        result = calc_size(1024 ** 4)
        self.assertIn("TB", result)


class TestC(unittest.TestCase):
    """_c — цветная строка."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_wraps_text_with_color_and_reset(self):
        from vless_installer.modules.network_bench import _c, RED, RESET
        result = _c(RED, "hello")
        self.assertTrue(result.startswith(RED))
        self.assertTrue(result.endswith(RESET))
        self.assertIn("hello", result)


class TestReadCpuinfo(unittest.TestCase):
    """read_cpuinfo — парсинг /proc/cpuinfo."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_parses_standard_cpuinfo(self):
        from vless_installer.modules.network_bench import read_cpuinfo
        content = (
            "processor\t: 0\n"
            "model name\t: Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz\n"
            "cpu MHz\t\t: 3600.000\n"
            "cache size\t: 12288 KB\n"
            "flags\t\t: fpu vme de apic sep aes avx vmx\n"
            "processor\t: 1\n"
            "model name\t: Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz\n"
        )
        with patch("pathlib.Path.read_text", return_value=content):
            info = read_cpuinfo()
        self.assertIn("model", info)
        self.assertIn("cores", info)
        self.assertEqual(info["cores"], 2)
        self.assertTrue(info["aes"])
        self.assertTrue(info["virt"])  # vmx

    def test_returns_empty_on_error(self):
        from vless_installer.modules.network_bench import read_cpuinfo
        with patch("pathlib.Path.read_text", side_effect=OSError("no file")):
            info = read_cpuinfo()
        # при ошибке — пустой dict с дефолтами
        self.assertIsInstance(info, dict)


class TestReadMeminfo(unittest.TestCase):
    """read_meminfo — парсинг /proc/meminfo."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_parses_standard_meminfo(self):
        from vless_installer.modules.network_bench import read_meminfo
        content = (
            "MemTotal:       16384000 kB\n"
            "MemFree:         8192000 kB\n"
            "MemAvailable:   12000000 kB\n"
            "SwapTotal:       2000000 kB\n"
            "SwapFree:        2000000 kB\n"
        )
        with patch("pathlib.Path.read_text", return_value=content):
            total, used, total_swap, used_swap = read_meminfo()
        self.assertGreater(total, 0)
        self.assertGreater(used, 0)
        self.assertGreater(total_swap, 0)
        self.assertEqual(used_swap, 0)  # SwapFree == SwapTotal → used = 0


class TestGetLoadAverage(unittest.TestCase):
    """get_load_average."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_formatted_string(self):
        from vless_installer.modules.network_bench import get_load_average
        with patch("os.getloadavg", return_value=(0.1, 0.2, 0.3)):
            result = get_load_average()
        self.assertIn("0.1", result)
        self.assertIn("0.2", result)
        self.assertIn("0.3", result)

    def test_returns_empty_on_error(self):
        from vless_installer.modules.network_bench import get_load_average
        with patch("os.getloadavg", side_effect=OSError):
            self.assertEqual(get_load_average(), "")


class TestGetUptime(unittest.TestCase):
    """get_uptime."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_formatted_string(self):
        from vless_installer.modules.network_bench import get_uptime
        content = "86400.50 1234.00\n"  # 1 day
        with patch("pathlib.Path.read_text", return_value=content):
            result = get_uptime()
        self.assertIn("day", result.lower())

    def test_returns_empty_on_error(self):
        from vless_installer.modules.network_bench import get_uptime
        with patch("pathlib.Path.read_text", side_effect=OSError):
            self.assertEqual(get_uptime(), "")


class TestCheckRateLimit(unittest.TestCase):
    """check_rate_limit / mark_success — rate limiting."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._lock = self._tmpdir / "lock"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.network_bench.LOCK_FILE", self._lock)

    def test_returns_true_when_no_lock_file(self):
        from vless_installer.modules.network_bench import check_rate_limit
        with self._patch():
            self.assertTrue(check_rate_limit())

    def test_returns_false_when_recently_run(self):
        from vless_installer.modules.network_bench import check_rate_limit
        self._lock.write_text(str(int(time.time())))
        with self._patch():
            self.assertFalse(check_rate_limit())

    def test_mark_success_writes_timestamp(self):
        from vless_installer.modules.network_bench import mark_success
        with self._patch():
            mark_success()
        content = self._lock.read_text()
        self.assertTrue(content.isdigit())


if __name__ == "__main__":
    unittest.main(verbosity=2)
