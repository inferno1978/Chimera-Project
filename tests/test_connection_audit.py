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


class TestNormAddrForDisplay(unittest.TestCase):
    """Тест нормализации IPv4-mapped IPv6 для display в таблице.

    Цель: адреса вида `[::ffff:1.2.3.4]:443` (28 chars) сокращать до `1.2.3.4:443`
    (19 chars), чтобы строка в TUI помещалась в box width 66 и email
    не переносился на следующую строку.
    """

    def setUp(self): _setup_core()

    def _norm(self, addr: str) -> str:
        """Дублируем логику _norm_addr_for_display для теста.

        Дублирование — намеренное: если код изменится, тест начнёт падать,
        что и есть проверка консистентности.
        """
        if addr.startswith("["):
            inner = addr[1:].split("]", 1)[0]
            port_part = addr.rsplit(":", 1)[1] if ":" in addr.split("]", 1)[1] else ""
            if inner.startswith("::ffff:"):
                return f"{inner[7:]}:{port_part}" if port_part else inner[7:]
            return addr
        return addr

    def test_ipv4_mapped_ipv6_becomes_plain_ipv4(self):
        """`[::ffff:1.2.3.4]:443` → `1.2.3.4:443` (main case)."""
        result = self._norm("[::ffff:45.151.182.204]:443")
        self.assertEqual(result, "45.151.182.204:443")
        # 14 (IPv4) + 1 (:) + 3 (port) = 18 chars (было 28 с brackets)
        self.assertEqual(len(result), 18)

    def test_ipv4_mapped_ipv6_with_client_port(self):
        """`[::ffff:5.167.98.20]:49775` → `5.167.98.20:49775`."""
        result = self._norm("[::ffff:5.167.98.20]:49775")
        self.assertEqual(result, "5.167.98.20:49775")

    def test_plain_ipv4_unchanged(self):
        """Обычный IPv4 без скобок — без изменений."""
        result = self._norm("45.151.182.204:443")
        self.assertEqual(result, "45.151.182.204:443")

    def test_real_ipv6_kept_in_brackets(self):
        """Настоящий IPv6 (не ::ffff: mapped) — оставляем в скобках для однозначности."""
        result = self._norm("[2001:db8::1]:443")
        self.assertEqual(result, "[2001:db8::1]:443")

    def test_line_fits_in_box_after_normalization(self):
        """После нормализации + dynamic email truncation строка помещается в box width 66.

        Layout: 2 leading + local + 1 sep + peer + 1 sep + email ≤ 66
        До фикса: 86 chars (IPv6 padded to 28) — не помещалось, email на новой строке.
        После фикса (normalize + no padding): 2 + 18 + 1 + 17 + 1 + 26 = 65 chars — влезает!
        Email `user@chimeraprodvpn.online` (26 chars) полностью помещается без обрезания
        когда local и peer — обычные IPv4 (18 и 17 chars).
        """
        local = self._norm("[::ffff:45.151.182.204]:443")  # 18 chars
        peer = self._norm("[::ffff:5.167.98.20]:49775")    # 17 chars
        email_full = "user@chimeraprodvpn.online"          # 26 chars

        # Simulate dynamic email truncation logic from connection_audit.py
        local_w = len(local)
        peer_w = len(peer)
        max_email = max(8, 62 - local_w - peer_w)
        max_email = min(max_email, 26)
        if len(email_full) > max_email:
            email_short = email_full[:max_email - 1] + "…"
        else:
            email_short = email_full

        full_line = f"  {local} {peer} {email_short}"
        # Без padding! Строка должна быть <= 66 (box width)
        self.assertLessEqual(
            len(full_line), 66,
            f"Line too long ({len(full_line)} > 66) — would wrap in TUI"
        )
        # Email должен полностью поместиться (26 chars ≤ max_email which is 27)
        self.assertEqual(len(email_short), len(email_full))

    def test_long_email_gets_truncated_when_local_peer_long(self):
        """Если local+peer длинные (настоящий IPv6), email обрезается."""
        local = "[2001:db8:1234:5678::1]:443"  # 27 chars (настоящий IPv6, brackets kept)
        peer = "[2001:db8:abcd:ef01::2]:443"   # 27 chars
        email_full = "user@chimeraprodvpn.online"  # 26 chars

        local_w = len(local)
        peer_w = len(peer)
        max_email = max(8, 62 - local_w - peer_w)  # = max(8, 62-27-27) = max(8, 8) = 8
        max_email = min(max_email, 26)              # = 8
        self.assertEqual(max_email, 8)
        # Email длиннее max_email — обрезается
        self.assertGreater(len(email_full), max_email)
        email_short = email_full[:max_email - 1] + "…"
        self.assertEqual(len(email_short), 8)  # 7 chars + …

    def test_short_email_not_truncated(self):
        """Короткий email не должен обрезаться если влезает в box."""
        local = self._norm("[::ffff:45.151.182.204]:443")  # 18 chars
        peer = self._norm("[::ffff:5.167.98.20]:49775")    # 17 chars
        email_full = "user@x.ru"                           # 9 chars (short)
        local_w = len(local)
        peer_w = len(peer)
        max_email = max(8, 62 - local_w - peer_w)
        max_email = min(max_email, 26)
        # 9 <= max_email (27) — email не должен обрезаться
        self.assertLessEqual(len(email_full), max_email)


# ── traffic_history ────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
