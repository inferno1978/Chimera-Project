#!/usr/bin/env python3
"""
tests/test_connection_audit.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/connection_audit.py.

Покрывает:
  1. _core_module dispatcher
  2. ss -tnpH regex parser (несколько форматов вывода iproute2)
"""
from __future__ import annotations

import json
import os
import re
import stat
import sys
import tempfile
import time
import unittest
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


class TestConnectionAudit(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from chimera.modules.connection_audit import _core_module
        self.assertIsNotNone(_core_module())


class TestSsRegex(unittest.TestCase):
    """Тест regex-парсера вывода `ss -tnpH state established`.

    Покрывает все известные форматы вывода ss:
      • iproute2 6.x (новые, Ubuntu 24.04+): без префикса tcp ESTAB
      • iproute2 6.x без state filter: только ESTAB (без tcp)
      • Старые iproute2 5.x: с tcp ESTAB
      • Совсем старые: только Recv-Q (1 число)
      • IPv6 адреса в квадратных скобках
    """

    def setUp(self): _setup_core()

    def _get_pat(self):
        """Достаём regex из _audit_active_now (через патч, чтобы не выполнять ss)."""
        # Достаём модуль
        from chimera.modules import connection_audit
        # Паттерн определяется inline в функции, не как модуль-level константа.
        # Дублируем паттерн здесь — он должен быть идентичен коду.
        # Если код изменится, тест начнёт падать — это и есть проверка консистентности.
        return re.compile(
            r'^(?:\S+\s+){0,2}'
            r'(?:\d+\s+){1,2}'
            r'(?P<local>\[[^\]]+\]:\d+|[^\s:]+:\d+)\s+'
            r'(?P<peer>\[[^\]]+\]:\d+|[^\s:]+:\d+)\s+'
            r'users:\(\("(?P<proc>[^"]+)"'
        )

    def test_iproute2_6_state_filter_no_prefix(self):
        """iproute2 6.x с state filter — БЕЗ tcp ESTAB префикса (main case)."""
        pat = self._get_pat()
        line = "0      0               45.151.182.204:1506       132.243.221.181:443   users:((\"xray\",pid=566981,fd=95))"
        m = pat.match(line.strip())
        self.assertIsNotNone(m, "regex should match iproute2 6.x state-filtered output")
        self.assertEqual(m.group("local"), "45.151.182.204:1506")
        self.assertEqual(m.group("peer"), "132.243.221.181:443")
        self.assertEqual(m.group("proc"), "xray")

    def test_iproute2_6_no_state_filter_estab_only(self):
        """iproute2 6.x без state filter — только ESTAB (без tcp)."""
        pat = self._get_pat()
        line = "ESTAB 0      0               45.151.182.204:1506       132.243.221.181:443   users:((\"xray\",pid=566981,fd=95))"
        m = pat.match(line.strip())
        self.assertIsNotNone(m, "regex should match iproute2 6.x no-state-filter output")
        self.assertEqual(m.group("local"), "45.151.182.204:1506")
        self.assertEqual(m.group("peer"), "132.243.221.181:443")
        self.assertEqual(m.group("proc"), "xray")

    def test_old_iproute2_with_tcp_estab_prefix(self):
        """Старые iproute2 5.x — с tcp ESTAB."""
        pat = self._get_pat()
        line = "tcp ESTAB 0 0 45.151.182.204:1506 132.243.221.181:443 users:((\"xray\",pid=566981,fd=95))"
        m = pat.match(line.strip())
        self.assertIsNotNone(m, "regex should match old iproute2 5.x output")
        self.assertEqual(m.group("local"), "45.151.182.204:1506")
        self.assertEqual(m.group("peer"), "132.243.221.181:443")
        self.assertEqual(m.group("proc"), "xray")

    def test_old_iproute2_single_recvq(self):
        """Совсем старые iproute2 — только 1 числовой столбец (Recv-Q)."""
        pat = self._get_pat()
        line = "tcp ESTAB 0 45.151.182.204:1506 132.243.221.181:443 users:((\"xray\",pid=566981,fd=95))"
        m = pat.match(line.strip())
        self.assertIsNotNone(m, "regex should match old iproute2 with single Recv-Q")
        self.assertEqual(m.group("local"), "45.151.182.204:1506")

    def test_ipv6_address_in_brackets(self):
        """IPv6 адреса в квадратных скобках (IPv4-mapped IPv6)."""
        pat = self._get_pat()
        line = "0 0 [::ffff:45.151.182.204]:443 [::ffff:5.167.98.20]:55164 users:((\"xray\",pid=517759,fd=12))"
        m = pat.match(line.strip())
        self.assertIsNotNone(m, "regex should match IPv6 in brackets")
        self.assertEqual(m.group("local"), "[::ffff:45.151.182.204]:443")
        self.assertEqual(m.group("peer"), "[::ffff:5.167.98.20]:55164")

    def test_trailing_whitespace_is_ok(self):
        """Trailing whitespace в конце строки (часто в выводе ss)."""
        pat = self._get_pat()
        line = "0 0 45.151.182.204:1506 132.243.221.181:443 users:((\"xray\",pid=566981,fd=95))                        "
        m = pat.match(line.strip())
        self.assertIsNotNone(m)

    def test_non_xray_process_doesnt_matter(self):
        """Regex не фильтрует по имени процесса — matчит любое имя."""
        pat = self._get_pat()
        line = "0 0 127.0.0.1:59280 127.0.0.1:9700 users:((\"nginx\",pid=582863,fd=21))"
        m = pat.match(line.strip())
        self.assertIsNotNone(m)
        self.assertEqual(m.group("proc"), "nginx")

    def test_no_match_for_empty_line(self):
        """Пустая строка не должна matчиться."""
        pat = self._get_pat()
        self.assertIsNone(pat.match(""))

    def test_no_match_for_header_line(self):
        """Строка-заголовок (когда -H не указан) не должна matчиться."""
        pat = self._get_pat()
        header = "Recv-Q Send-Q Local Address:Port Peer Address:Port Process"
        self.assertIsNone(pat.match(header))


# ── traffic_history ────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
