#!/usr/bin/env python3
"""
tests/test_yabs.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/yabs.py — Python порт YABS.

Покрывает:
  1. format_size — конвертация KiB → TiB/GiB/MiB/KiB
  2. format_speed — конвертация KiB/s → GB/s/MB/s/KB/s
  3. format_iops — форматирование IOPS (8, 123, 1.7k, 275.9k)
  4. _get_arch — определение архитектуры
  5. gather_system_info — сбор базовой информации
  6. _check_connectivity — проверка IPv4/IPv6
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


class TestFormatSize(unittest.TestCase):
    """format_size — конвертация KiB → TiB/GiB/MiB/KiB."""

    def test_kib(self):
        from chimera.modules.yabs import format_size
        self.assertEqual(format_size(512), "512 KiB")

    def test_mib(self):
        from chimera.modules.yabs import format_size
        self.assertEqual(format_size(2048), "2.0 MiB")

    def test_gib(self):
        from chimera.modules.yabs import format_size
        self.assertEqual(format_size(2097152), "2.0 GiB")

    def test_tib(self):
        from chimera.modules.yabs import format_size
        self.assertEqual(format_size(1073741824), "1.0 TiB")

    def test_zero(self):
        from chimera.modules.yabs import format_size
        self.assertEqual(format_size(0), "0 KiB")

    def test_negative(self):
        from chimera.modules.yabs import format_size
        self.assertEqual(format_size(-1), "")

    def test_non_number(self):
        from chimera.modules.yabs import format_size
        self.assertEqual(format_size("abc"), "")
        self.assertEqual(format_size(None), "")


class TestFormatSpeed(unittest.TestCase):
    """format_speed — конвертация KiB/s → GB/s/MB/s/KB/s."""

    def test_kbs(self):
        from chimera.modules.yabs import format_speed
        result = format_speed(100)
        self.assertIn("KB/s", result)

    def test_mbs(self):
        from chimera.modules.yabs import format_speed
        result = format_speed(50000)
        self.assertIn("MB/s", result)

    def test_gbs(self):
        from chimera.modules.yabs import format_speed
        result = format_speed(1000000)
        self.assertIn("GB/s", result)

    def test_empty(self):
        from chimera.modules.yabs import format_speed
        self.assertEqual(format_speed(""), "")
        self.assertEqual(format_speed(None), "")

    def test_non_number(self):
        from chimera.modules.yabs import format_speed
        self.assertEqual(format_speed("abc"), "")


class TestFormatIops(unittest.TestCase):
    """format_iops — форматирование IOPS."""

    def test_small(self):
        from chimera.modules.yabs import format_iops
        self.assertEqual(format_iops(8), "8")
        self.assertEqual(format_iops(123), "123")

    def test_thousands(self):
        from chimera.modules.yabs import format_iops
        self.assertEqual(format_iops(1500), "1.5k")
        self.assertEqual(format_iops(275900), "275.9k")

    def test_empty(self):
        from chimera.modules.yabs import format_iops
        self.assertEqual(format_iops(""), "")
        self.assertEqual(format_iops(None), "")


class TestGetArch(unittest.TestCase):
    """_get_arch — определение архитектуры."""

    def test_x64(self):
        from chimera.modules.yabs import _get_arch
        with patch("platform.machine", return_value="x86_64"):
            self.assertEqual(_get_arch(), "x64")

    def test_amd64(self):
        from chimera.modules.yabs import _get_arch
        with patch("platform.machine", return_value="amd64"):
            self.assertEqual(_get_arch(), "x64")

    def test_aarch64(self):
        from chimera.modules.yabs import _get_arch
        with patch("platform.machine", return_value="aarch64"):
            self.assertEqual(_get_arch(), "aarch64")

    def test_arm(self):
        from chimera.modules.yabs import _get_arch
        with patch("platform.machine", return_value="armv7l"):
            self.assertEqual(_get_arch(), "arm")

    def test_unknown(self):
        from chimera.modules.yabs import _get_arch
        with patch("platform.machine", return_value="mips"):
            self.assertEqual(_get_arch(), "unknown")


class TestGatherSystemInfo(unittest.TestCase):
    """gather_system_info — сбор базовой информации о системе."""

    def test_returns_system_info(self):
        from chimera.modules.yabs import gather_system_info, SystemInfo
        info = gather_system_info()
        self.assertIsInstance(info, SystemInfo)

    def test_uptime_not_empty(self):
        from chimera.modules.yabs import gather_system_info
        info = gather_system_info()
        self.assertTrue(info.uptime)
        self.assertNotEqual(info.uptime, "")

    def test_kernel_not_empty(self):
        from chimera.modules.yabs import gather_system_info
        info = gather_system_info()
        self.assertTrue(info.kernel)

    def test_cpu_cores_is_string(self):
        from chimera.modules.yabs import gather_system_info
        info = gather_system_info()
        self.assertIsInstance(info.cpu_cores, str)

    def test_aes_ni_contains_enabled_or_disabled(self):
        from chimera.modules.yabs import gather_system_info
        info = gather_system_info()
        # Should contain either "Enabled" or "Disabled" or "unknown"
        self.assertTrue(any(x in info.aes_ni for x in ["Enabled", "Disabled", "unknown"]))


class TestCheckConnectivity(unittest.TestCase):
    """_check_connectivity — проверка IPv4/IPv6."""

    def test_returns_tuple_of_bools(self):
        from chimera.modules.yabs import _check_connectivity
        result = _check_connectivity()
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], bool)
        self.assertIsInstance(result[1], bool)


class TestYabsMenu(unittest.TestCase):
    """do_yabs_menu — smoke test that menu function exists and is callable."""

    def test_menu_callable(self):
        from chimera.modules.yabs import do_yabs_menu
        self.assertTrue(callable(do_yabs_menu))


class TestRunYabs(unittest.TestCase):
    """run_yabs — smoke test that function exists and is callable."""

    def test_run_callable(self):
        from chimera.modules.yabs import run_yabs
        self.assertTrue(callable(run_yabs))


class TestIperfServers(unittest.TestCase):
    """Проверка списка iperf3 серверов."""

    def test_default_servers_count(self):
        from chimera.modules.yabs import _IPERF_SERVERS
        self.assertGreaterEqual(len(_IPERF_SERVERS), 5)

    def test_reduced_servers_count(self):
        from chimera.modules.yabs import _IPERF_SERVERS_REDUCED
        self.assertEqual(len(_IPERF_SERVERS_REDUCED), 3)

    def test_server_format(self):
        """Each server should be a 5-tuple."""
        from chimera.modules.yabs import _IPERF_SERVERS
        for server in _IPERF_SERVERS:
            self.assertEqual(len(server), 5)
            host, ports, name, location, modes = server
            self.assertTrue(host)
            self.assertTrue("-" in ports)
            self.assertTrue(name)
            self.assertTrue(location)
            self.assertTrue("IPv" in modes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
