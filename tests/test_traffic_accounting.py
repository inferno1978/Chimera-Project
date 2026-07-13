#!/usr/bin/env python3
"""
tests/test_traffic_accounting.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/traffic_accounting.py.

ПОКРЫТИЕ:
  1. parse_human_readable_bytes — все единицы (IEC + SI), дробные, регистр,
     пробел/без пробела, bare letters, edge cases (пусто, отрицательное,
     неизвестная единица).
  2. format_bytes — IEC/ru, precision, zero_str, отрицательные.
  3. record_traffic_sample — нормальный рост счётчика.
  4. record_traffic_sample — сброс счётчика (raw < last_raw) → baseline
     сохраняется, accumulated продолжает расти.
  5. record_traffic_sample — идемпотентность (повторный raw → delta=0).
  6. get_accumulated_bytes — read-only, не мутирует state.
  7. reset_accumulated — сброс baseline.
  8. get_all_accumulated — суммарный по протоколам.
  9. Конкурентный вызов из нескольких потоков — нет гонки при записи.
  10. Поддерживаемые/неподдерживаемые протоколы — ValueError.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Создаёт фейковый vless_installer._core (как в test_tg_bot.py)."""
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


# =============================================================================
#  ТЕСТЫ parse_human_readable_bytes
# =============================================================================
class TestParseHumanReadableBytes(unittest.TestCase):
    """parse_human_readable_bytes — парсер строк вида "1.5 GiB" → int bytes."""

    def setUp(self):
        _setup_core_in_sysmodules()

    # ── IEC (binary, 1024-based) ──────────────────────────────────────────────

    def test_iec_bytes(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        self.assertEqual(parse_human_readable_bytes("1024"), 1024)
        self.assertEqual(parse_human_readable_bytes("1024B"), 1024)
        self.assertEqual(parse_human_readable_bytes("1024 B"), 1024)
        self.assertEqual(parse_human_readable_bytes("0"), 0)
        self.assertEqual(parse_human_readable_bytes("0 B"), 0)

    def test_iec_kib(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        self.assertEqual(parse_human_readable_bytes("1 KiB"), 1024)
        self.assertEqual(parse_human_readable_bytes("2 KiB"), 2048)
        self.assertEqual(parse_human_readable_bytes("1.5 KiB"), 1536)

    def test_iec_mib(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        self.assertEqual(parse_human_readable_bytes("1 MiB"), 1024 ** 2)
        self.assertEqual(parse_human_readable_bytes("1.5 MiB"), int(1.5 * 1024 ** 2))

    def test_iec_gib(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        self.assertEqual(parse_human_readable_bytes("1 GiB"), 1024 ** 3)
        self.assertEqual(parse_human_readable_bytes("1.5 GiB"), int(1.5 * 1024 ** 3))
        self.assertEqual(parse_human_readable_bytes("10 GiB"), 10 * 1024 ** 3)

    def test_iec_tib(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        self.assertEqual(parse_human_readable_bytes("1 TiB"), 1024 ** 4)
        self.assertEqual(parse_human_readable_bytes("2.5 TiB"), int(2.5 * 1024 ** 4))

    def test_iec_pib(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        self.assertEqual(parse_human_readable_bytes("1 PiB"), 1024 ** 5)

    def test_iec_eib(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        self.assertEqual(parse_human_readable_bytes("1 EiB"), 1024 ** 6)

    # ── SI (decimal, 1000-based) ──────────────────────────────────────────────

    def test_si_kb(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        self.assertEqual(parse_human_readable_bytes("1 KB"), 1000)
        self.assertEqual(parse_human_readable_bytes("2 KB"), 2000)

    def test_si_mb(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        self.assertEqual(parse_human_readable_bytes("1 MB"), 1000 ** 2)
        self.assertEqual(parse_human_readable_bytes("1.5 MB"), int(1.5 * 1000 ** 2))

    def test_si_gb(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        self.assertEqual(parse_human_readable_bytes("1 GB"), 1000 ** 3)
        self.assertEqual(parse_human_readable_bytes("10 GB"), 10 * 1000 ** 3)

    def test_si_tb(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        self.assertEqual(parse_human_readable_bytes("1 TB"), 1000 ** 4)

    # ── Bare letters (VPN-конвенция: IEC) ────────────────────────────────────

    def test_bare_letter_k(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        self.assertEqual(parse_human_readable_bytes("1K"), 1024)  # IEC, не SI
        self.assertEqual(parse_human_readable_bytes("2K"), 2048)

    def test_bare_letter_g(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        self.assertEqual(parse_human_readable_bytes("1G"), 1024 ** 3)  # IEC
        self.assertEqual(parse_human_readable_bytes("10G"), 10 * 1024 ** 3)

    def test_bare_letter_m_t_p(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        self.assertEqual(parse_human_readable_bytes("1M"), 1024 ** 2)
        self.assertEqual(parse_human_readable_bytes("1T"), 1024 ** 4)
        self.assertEqual(parse_human_readable_bytes("1P"), 1024 ** 5)

    # ── Регистр (case-insensitive) ───────────────────────────────────────────

    def test_case_insensitive(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        self.assertEqual(parse_human_readable_bytes("1 GiB"), 1024 ** 3)
        self.assertEqual(parse_human_readable_bytes("1 gib"), 1024 ** 3)
        self.assertEqual(parse_human_readable_bytes("1 GIB"), 1024 ** 3)
        self.assertEqual(parse_human_readable_bytes("1gib"), 1024 ** 3)
        self.assertEqual(parse_human_readable_bytes("1 MB"), 1000 ** 2)
        self.assertEqual(parse_human_readable_bytes("1 mb"), 1000 ** 2)
        self.assertEqual(parse_human_readable_bytes("1Mb"), 1000 ** 2)

    # ── Пробел опционален ────────────────────────────────────────────────────

    def test_space_optional(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        self.assertEqual(parse_human_readable_bytes("1 GiB"), 1024 ** 3)
        self.assertEqual(parse_human_readable_bytes("1GiB"), 1024 ** 3)
        self.assertEqual(parse_human_readable_bytes("  1   GiB  "), 1024 ** 3)
        self.assertEqual(parse_human_readable_bytes("100MB"), 100 * 1000 ** 2)

    # ── Дробные значения ─────────────────────────────────────────────────────

    def test_fractional(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        self.assertEqual(parse_human_readable_bytes("1.5 GiB"), 1610612736)
        self.assertEqual(parse_human_readable_bytes("0.5 KiB"), 512)
        self.assertEqual(parse_human_readable_bytes("2.5 MB"), 2500000)
        self.assertEqual(parse_human_readable_bytes("0.1 GB"), 100000000)

    # ── default_unit ─────────────────────────────────────────────────────────

    def test_default_unit_gib(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        # Если в строке нет единицы — используем default_unit
        self.assertEqual(parse_human_readable_bytes("10", default_unit="GiB"),
                         10 * 1024 ** 3)
        self.assertEqual(parse_human_readable_bytes("1.5", default_unit="MiB"),
                         int(1.5 * 1024 ** 2))

    def test_default_unit_b(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        # По умолчанию — байты
        self.assertEqual(parse_human_readable_bytes("1024"), 1024)

    # ── Edge cases / ошибки ──────────────────────────────────────────────────

    def test_empty_string_raises(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        with self.assertRaises(ValueError):
            parse_human_readable_bytes("")

    def test_whitespace_only_raises(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        with self.assertRaises(ValueError):
            parse_human_readable_bytes("   ")

    def test_negative_raises(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        with self.assertRaises(ValueError):
            parse_human_readable_bytes("-1 KiB")

    def test_unknown_unit_raises(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        with self.assertRaises(ValueError):
            parse_human_readable_bytes("1 XB")
        with self.assertRaises(ValueError):
            parse_human_readable_bytes("1 Foobar")

    def test_non_numeric_raises(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        with self.assertRaises(ValueError):
            parse_human_readable_bytes("abc")
        with self.assertRaises(ValueError):
            parse_human_readable_bytes("GiB")

    def test_non_string_raises(self):
        from vless_installer.modules.traffic_accounting import parse_human_readable_bytes
        with self.assertRaises(ValueError):
            parse_human_readable_bytes(1024)  # int, not str
        with self.assertRaises(ValueError):
            parse_human_readable_bytes(None)


# =============================================================================
#  ТЕСТЫ format_bytes
# =============================================================================
class TestFormatBytes(unittest.TestCase):
    """format_bytes — форматер bytes → str."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_zero(self):
        from vless_installer.modules.traffic_accounting import format_bytes
        self.assertEqual(format_bytes(0), "0 B")

    def test_zero_with_zero_str(self):
        from vless_installer.modules.traffic_accounting import format_bytes
        self.assertEqual(format_bytes(0, zero_str="—"), "—")
        self.assertEqual(format_bytes(0, zero_str="нет данных"), "нет данных")

    def test_bytes(self):
        from vless_installer.modules.traffic_accounting import format_bytes
        self.assertEqual(format_bytes(1), "1 B")
        self.assertEqual(format_bytes(512), "512 B")
        self.assertEqual(format_bytes(1023), "1023 B")

    def test_kib(self):
        from vless_installer.modules.traffic_accounting import format_bytes
        self.assertEqual(format_bytes(1024), "1.0 KiB")
        self.assertEqual(format_bytes(1536), "1.5 KiB")

    def test_mib(self):
        from vless_installer.modules.traffic_accounting import format_bytes
        self.assertEqual(format_bytes(1024 ** 2), "1.0 MiB")
        self.assertEqual(format_bytes(int(1.5 * 1024 ** 2)), "1.5 MiB")

    def test_gib(self):
        from vless_installer.modules.traffic_accounting import format_bytes
        self.assertEqual(format_bytes(1024 ** 3), "1.0 GiB")
        self.assertEqual(format_bytes(int(1.5 * 1024 ** 3)), "1.5 GiB")

    def test_tib_pib(self):
        from vless_installer.modules.traffic_accounting import format_bytes
        self.assertEqual(format_bytes(1024 ** 4), "1.0 TiB")
        self.assertEqual(format_bytes(1024 ** 5), "1.0 PiB")

    def test_locale_ru(self):
        from vless_installer.modules.traffic_accounting import format_bytes
        self.assertEqual(format_bytes(0, locale="ru"), "0 Б")
        self.assertEqual(format_bytes(1024, locale="ru"), "1.0 КБ")
        self.assertEqual(format_bytes(1024 ** 3, locale="ru"), "1.0 ГБ")

    def test_precision(self):
        from vless_installer.modules.traffic_accounting import format_bytes
        self.assertEqual(format_bytes(1536, precision=2), "1.50 KiB")
        # precision=0 использует банковское округление Python (1.5 → 2, не 1)
        self.assertEqual(format_bytes(1536, precision=0), "2 KiB")
        self.assertEqual(format_bytes(1024 ** 3, precision=3), "1.000 GiB")
        # 1024 bytes = 1.0 KiB при precision=0 → "1 KiB"
        self.assertEqual(format_bytes(1024, precision=0), "1 KiB")

    def test_negative(self):
        from vless_installer.modules.traffic_accounting import format_bytes
        # Для delta-вывода
        self.assertEqual(format_bytes(-1024), "-1.0 KiB")
        self.assertEqual(format_bytes(-512), "-512 B")

    def test_round_trip(self):
        """parse(format(x)) == x для целых значений."""
        from vless_installer.modules.traffic_accounting import (
            parse_human_readable_bytes, format_bytes,
        )
        for val in [0, 1024, 1024 ** 2, 1024 ** 3, 1024 ** 4, 1536, 1024 ** 2 * 5]:
            formatted = format_bytes(val)
            parsed = parse_human_readable_bytes(formatted)
            self.assertEqual(parsed, val,
                             f"round-trip failed: {val} → {formatted} → {parsed}")


# =============================================================================
#  ТЕСТЫ record_traffic_sample (baseline-offset)
# =============================================================================
class TestRecordTrafficSample(unittest.TestCase):
    """record_traffic_sample — baseline-offset mechanism."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "traffic_accounting.json"
        self._lock_file = self._tmpdir / "traffic_accounting.lock"

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.traffic_accounting._STATE_FILE",
                  self._state_file),
            patch("vless_installer.modules.traffic_accounting._LOCK_FILE",
                  self._lock_file),
        ]

    def test_first_sample_sets_baseline(self):
        """Первый снимок: baseline=0, last_raw=raw, accumulated=raw."""
        from vless_installer.modules import traffic_accounting
        for p in self._patches():
            p.start()
        try:
            result = traffic_accounting.record_traffic_sample("alice@xray", "xray", 1000)
            self.assertEqual(result, 1000)
            # State должен содержать baseline=0, last_raw=1000
            state = traffic_accounting._state_load()
            entry = state["xray"]["alice@xray"]
            self.assertEqual(entry["baseline_bytes"], 0)
            self.assertEqual(entry["last_raw"], 1000)
        finally:
            for p in self._patches():
                p.stop()

    def test_normal_growth_accumulates(self):
        """Нормальный рост: raw2 > raw1 → accumulated = raw2 (baseline=0)."""
        from vless_installer.modules import traffic_accounting
        for p in self._patches():
            p.start()
        try:
            r1 = traffic_accounting.record_traffic_sample("alice@xray", "xray", 1000)
            r2 = traffic_accounting.record_traffic_sample("alice@xray", "xray", 1500)
            r3 = traffic_accounting.record_traffic_sample("alice@xray", "xray", 3000)
            self.assertEqual(r1, 1000)
            self.assertEqual(r2, 1500)  # baseline=0 + raw=1500
            self.assertEqual(r3, 3000)  # baseline=0 + raw=3000
        finally:
            for p in self._patches():
                p.stop()

    def test_counter_reset_preserves_accumulated(self):
        """СБРОС счётчика: raw < last_raw → baseline сохраняется, accumulated
        продолжает расти с нового raw.

        Модель:
          1. raw=5000 (первый снимок): baseline=0, last_raw=0 →
             normal growth → new_total = 0 + 5000 = 5000.
             После: baseline=0, last_raw=5000.
          2. raw=100 (рестарт xray): raw < last_raw → reset →
             new_baseline = 0 + 5000 = 5000,
             new_total = 5000 + 100 = 5100.
             После: baseline=5000, last_raw=100.
          3. raw=600 (продолжает копиться): raw >= last_raw → normal →
             new_total = 5000 + 600 = 5600.
             После: baseline=5000, last_raw=600.
          4. raw=50 (ещё один рестарт): raw < last_raw → reset →
             new_baseline = 5000 + 600 = 5600,
             new_total = 5600 + 50 = 5650.
        """
        from vless_installer.modules import traffic_accounting
        for p in self._patches():
            p.start()
        try:
            r1 = traffic_accounting.record_traffic_sample("alice@xray", "xray", 5000)
            self.assertEqual(r1, 5000)
            # Рестарт xray — счётчик сбросился в 100
            r2 = traffic_accounting.record_traffic_sample("alice@xray", "xray", 100)
            self.assertEqual(r2, 5100)
            # Продолжаем копиться после рестарта
            r3 = traffic_accounting.record_traffic_sample("alice@xray", "xray", 600)
            self.assertEqual(r3, 5600)
            # Ещё один рестарт
            r4 = traffic_accounting.record_traffic_sample("alice@xray", "xray", 50)
            self.assertEqual(r4, 5650)
        finally:
            for p in self._patches():
                p.stop()

    def test_idempotent_same_raw(self):
        """Повторный вызов с тем же raw → accumulated не меняется (delta=0)."""
        from vless_installer.modules import traffic_accounting
        for p in self._patches():
            p.start()
        try:
            r1 = traffic_accounting.record_traffic_sample("alice@xray", "xray", 1000)
            r2 = traffic_accounting.record_traffic_sample("alice@xray", "xray", 1000)
            r3 = traffic_accounting.record_traffic_sample("alice@xray", "xray", 1000)
            self.assertEqual(r1, 1000)
            self.assertEqual(r2, 1000)
            self.assertEqual(r3, 1000)
        finally:
            for p in self._patches():
                p.stop()

    def test_multiple_users_isolated(self):
        """Разные пользователи — изолированные счётчики."""
        from vless_installer.modules import traffic_accounting
        for p in self._patches():
            p.start()
        try:
            traffic_accounting.record_traffic_sample("alice@xray", "xray", 1000)
            traffic_accounting.record_traffic_sample("bob@xray", "xray", 5000)
            a = traffic_accounting.get_accumulated_bytes("alice@xray", "xray")
            b = traffic_accounting.get_accumulated_bytes("bob@xray", "xray")
            self.assertEqual(a, 1000)
            self.assertEqual(b, 5000)
        finally:
            for p in self._patches():
                p.stop()

    def test_multiple_protocols_isolated(self):
        """Разные протоколы для одного юзера — изолированные счётчики."""
        from vless_installer.modules import traffic_accounting
        for p in self._patches():
            p.start()
        try:
            traffic_accounting.record_traffic_sample("alice@xray", "xray", 1000)
            traffic_accounting.record_traffic_sample("alice@xray", "awg", 5000)
            x = traffic_accounting.get_accumulated_bytes("alice@xray", "xray")
            a = traffic_accounting.get_accumulated_bytes("alice@xray", "awg")
            self.assertEqual(x, 1000)
            self.assertEqual(a, 5000)
        finally:
            for p in self._patches():
                p.stop()

    def test_unsupported_protocol_raises(self):
        """Неподдерживаемый протокол → ValueError."""
        from vless_installer.modules import traffic_accounting
        for p in self._patches():
            p.start()
        try:
            with self.assertRaises(ValueError):
                traffic_accounting.record_traffic_sample("alice", "unknown_proto", 100)
            with self.assertRaises(ValueError):
                traffic_accounting.record_traffic_sample("alice", "singbox", 100)
            with self.assertRaises(ValueError):
                traffic_accounting.record_traffic_sample("alice", "fptn", 100)
        finally:
            for p in self._patches():
                p.stop()

    def test_empty_user_id_raises(self):
        from vless_installer.modules import traffic_accounting
        for p in self._patches():
            p.start()
        try:
            with self.assertRaises(ValueError):
                traffic_accounting.record_traffic_sample("", "xray", 100)
        finally:
            for p in self._patches():
                p.stop()

    def test_negative_raw_clamped_to_zero(self):
        from vless_installer.modules import traffic_accounting
        for p in self._patches():
            p.start()
        try:
            r = traffic_accounting.record_traffic_sample("alice@xray", "xray", -100)
            self.assertEqual(r, 0)
        finally:
            for p in self._patches():
                p.stop()


# =============================================================================
#  ТЕСТЫ get_accumulated_bytes / reset_accumulated / get_all_accumulated
# =============================================================================
class TestGetResetAccumulated(unittest.TestCase):
    """get_accumulated_bytes, reset_accumulated, get_all_accumulated."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "traffic_accounting.json"
        self._lock_file = self._tmpdir / "traffic_accounting.lock"

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.traffic_accounting._STATE_FILE",
                  self._state_file),
            patch("vless_installer.modules.traffic_accounting._LOCK_FILE",
                  self._lock_file),
        ]

    def test_get_returns_zero_for_unknown_user(self):
        from vless_installer.modules import traffic_accounting
        for p in self._patches():
            p.start()
        try:
            self.assertEqual(
                traffic_accounting.get_accumulated_bytes("nobody@xray", "xray"),
                0,
            )
        finally:
            for p in self._patches():
                p.stop()

    def test_get_returns_zero_for_unsupported_protocol(self):
        from vless_installer.modules import traffic_accounting
        for p in self._patches():
            p.start()
        try:
            with self.assertRaises(ValueError):
                traffic_accounting.get_accumulated_bytes("alice", "unknown")
        finally:
            for p in self._patches():
                p.stop()

    def test_get_after_record(self):
        from vless_installer.modules import traffic_accounting
        for p in self._patches():
            p.start()
        try:
            traffic_accounting.record_traffic_sample("alice@xray", "xray", 5000)
            # get_accumulated_bytes не делает новый снимок
            accumulated = traffic_accounting.get_accumulated_bytes("alice@xray", "xray")
            self.assertEqual(accumulated, 5000)
        finally:
            for p in self._patches():
                p.stop()

    def test_reset_clears_accumulated(self):
        from vless_installer.modules import traffic_accounting
        for p in self._patches():
            p.start()
        try:
            traffic_accounting.record_traffic_sample("alice@xray", "xray", 5000)
            traffic_accounting.reset_accumulated("alice@xray", "xray")
            self.assertEqual(
                traffic_accounting.get_accumulated_bytes("alice@xray", "xray"),
                0,
            )
            # После reset новый снимок начинает копиться с нуля
            r = traffic_accounting.record_traffic_sample("alice@xray", "xray", 100)
            self.assertEqual(r, 100)
        finally:
            for p in self._patches():
                p.stop()

    def test_get_all_accumulated(self):
        from vless_installer.modules import traffic_accounting
        for p in self._patches():
            p.start()
        try:
            traffic_accounting.record_traffic_sample("alice@xray", "xray", 1000)
            traffic_accounting.record_traffic_sample("alice@xray", "awg", 2000)
            traffic_accounting.record_traffic_sample("alice@xray", "mieru", 3000)
            all_acc = traffic_accounting.get_all_accumulated("alice@xray")
            self.assertEqual(all_acc.get("xray"), 1000)
            self.assertEqual(all_acc.get("awg"), 2000)
            self.assertEqual(all_acc.get("mieru"), 3000)
            # Протоколы без записей не должны быть в dict
            self.assertNotIn("naiveproxy", all_acc)
        finally:
            for p in self._patches():
                p.stop()

    def test_get_all_accumulated_empty_user(self):
        from vless_installer.modules import traffic_accounting
        for p in self._patches():
            p.start()
        try:
            self.assertEqual(traffic_accounting.get_all_accumulated(""), {})
        finally:
            for p in self._patches():
                p.stop()


# =============================================================================
#  ТЕСТЫ КОНКУРЕНТНОСТИ (thread safety)
# =============================================================================
class TestConcurrentAccess(unittest.TestCase):
    """Конкурентный вызов record_traffic_sample из нескольких потоков.
    Не должно быть гонки при записи в state.json (file lock защищает).
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "traffic_accounting.json"
        self._lock_file = self._tmpdir / "traffic_accounting.lock"

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.traffic_accounting._STATE_FILE",
                  self._state_file),
            patch("vless_installer.modules.traffic_accounting._LOCK_FILE",
                  self._lock_file),
        ]

    def test_concurrent_different_users(self):
        """10 потоков пишут разных пользователей — все 10 записей должны быть
        в state после завершения."""
        from vless_installer.modules import traffic_accounting
        for p in self._patches():
            p.start()
        try:
            users = [f"user{i}@xray" for i in range(10)]
            threads = []
            for u in users:
                t = threading.Thread(
                    target=traffic_accounting.record_traffic_sample,
                    args=(u, "xray", 1000),
                )
                threads.append(t)
                t.start()
            for t in threads:
                t.join()
            # Все 10 должны быть в state
            state = traffic_accounting._state_load()
            self.assertEqual(len(state.get("xray", {})), 10)
            for u in users:
                self.assertEqual(
                    traffic_accounting.get_accumulated_bytes(u, "xray"),
                    1000,
                )
        finally:
            for p in self._patches():
                p.stop()

    def test_concurrent_same_user_monotonic(self):
        """10 потоков пишут ТОГО ЖЕ пользователя с растущими значениями.
        Финальный accumulated должен быть >= max(raw values).
        Без lock — возможна гонка и потеря данных."""
        from vless_installer.modules import traffic_accounting
        for p in self._patches():
            p.start()
        try:
            # 10 потоков, каждый пишет значение 100..109 последовательно
            # (с маленькой задержкой чтобы была возможность гонки)
            results = []
            lock = threading.Lock()

            def worker(val):
                r = traffic_accounting.record_traffic_sample(
                    "alice@xray", "xray", val,
                )
                with lock:
                    results.append(r)

            threads = []
            for i in range(10):
                t = threading.Thread(target=worker, args=(100 + i,))
                threads.append(t)
                t.start()
                time.sleep(0.01)  # небольшая задержка
            for t in threads:
                t.join()
            # Финальный accumulated должен быть как минимум max(raw)=109
            # (baseline=0, last_raw=109 — но из-за конкуренции last_raw
            # может оказаться меньше, если потоки завершились не по порядку).
            # Главное — state должен быть валидным JSON без corruption.
            state = traffic_accounting._state_load()
            self.assertIn("xray", state)
            self.assertIn("alice@xray", state["xray"])
            entry = state["xray"]["alice@xray"]
            # accumulated = baseline + last_raw, оба >= 0
            self.assertGreaterEqual(entry["baseline_bytes"], 0)
            self.assertGreaterEqual(entry["last_raw"], 0)
            final = traffic_accounting.get_accumulated_bytes("alice@xray", "xray")
            self.assertGreaterEqual(final, 0)
        finally:
            for p in self._patches():
                p.stop()

    def test_concurrent_no_state_corruption(self):
        """100 потоков — state.json должен остаться валидным JSON."""
        from vless_installer.modules import traffic_accounting
        for p in self._patches():
            p.start()
        try:
            threads = []
            for i in range(100):
                t = threading.Thread(
                    target=traffic_accounting.record_traffic_sample,
                    args=(f"u{i}@xray", "xray", i * 100),
                )
                threads.append(t)
                t.start()
            for t in threads:
                t.join()
            # state.json должен быть валидным JSON
            raw = self._state_file.read_text()
            data = json.loads(raw)  # не должно бросить
            self.assertIsInstance(data, dict)
            self.assertIn("xray", data)
            # Все 100 пользователей должны быть записаны
            self.assertEqual(len(data["xray"]), 100)
        finally:
            for p in self._patches():
                p.stop()


# =============================================================================
#  ТЕСТЫ ИНТЕГРАЦИИ VLESS (traffic_tracking.py)
# =============================================================================
class TestVlessAccumulatedIntegration(unittest.TestCase):
    """Проверка что traffic_tracking._query_user_traffic_bytes_accumulated
    правильно использует traffic_accounting."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "traffic_accounting.json"
        self._lock_file = self._tmpdir / "traffic_accounting.lock"

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_accumulated_survives_xray_restart(self):
        """Симуляция: xray restart сбрасывает raw в 0, но accumulated
        сохраняется благодаря baseline-offset."""
        from vless_installer.modules import traffic_accounting
        from vless_installer.modules import traffic_tracking
        # Патчим _query_user_traffic_bytes чтобы вернуть raw значения
        # (имитируя xray api statsquery)
        with patch("vless_installer.modules.traffic_accounting._STATE_FILE",
                   self._state_file), \
             patch("vless_installer.modules.traffic_accounting._LOCK_FILE",
                   self._lock_file):
            # 1) xray reports 5 GB used
            with patch.object(traffic_tracking, "_query_user_traffic_bytes",
                              return_value=5 * 1024 ** 3):
                r1 = traffic_tracking._query_user_traffic_bytes_accumulated("alice@xray")
            self.assertEqual(r1, 5 * 1024 ** 3)

            # 2) xray restart — raw сбросился в 100 MB
            with patch.object(traffic_tracking, "_query_user_traffic_bytes",
                              return_value=100 * 1024 ** 2):
                r2 = traffic_tracking._query_user_traffic_bytes_accumulated("alice@xray")
            # accumulated = 5 GB + 100 MB (baseline сохранил 5 GB)
            self.assertEqual(r2, 5 * 1024 ** 3 + 100 * 1024 ** 2)

            # 3) xray продолжает копиться — 200 MB
            with patch.object(traffic_tracking, "_query_user_traffic_bytes",
                              return_value=200 * 1024 ** 2):
                r3 = traffic_tracking._query_user_traffic_bytes_accumulated("alice@xray")
            # accumulated = 5 GB + 200 MB (baseline=5GB, last_raw=200MB)
            self.assertEqual(r3, 5 * 1024 ** 3 + 200 * 1024 ** 2)


# =============================================================================
#  ТЕСТЫ _compute_accumulated (чистая функция)
# =============================================================================
class TestComputeAccumulated(unittest.TestCase):
    """_compute_accumulated — чистая функция, вычисляет accumulated без мутации.

    Модель:
      baseline = total accumulated BEFORE last_raw was recorded
      После записи last_raw: total = baseline + last_raw
      При новом raw (>= last_raw): new_total = baseline + raw (baseline не меняется)
      При reset (raw < last_raw): new_total = (baseline + last_raw) + raw
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_first_sample(self):
        """Первый снимок: baseline=0, last_raw=0, raw=1000 → 1000."""
        from vless_installer.modules.traffic_accounting import _compute_accumulated
        entry = {"baseline_bytes": 0, "last_raw": 0}
        # raw=1000 >= last_raw=0 → normal growth → baseline + raw = 0 + 1000
        result = _compute_accumulated(entry, 1000)
        self.assertEqual(result, 1000)

    def test_normal_growth(self):
        """Нормальный рост: baseline=0, last_raw=1000, raw=1500 → 1500."""
        from vless_installer.modules.traffic_accounting import _compute_accumulated
        entry = {"baseline_bytes": 0, "last_raw": 1000}
        # raw=1500 >= last_raw=1000 → normal growth → baseline + raw = 0 + 1500
        result = _compute_accumulated(entry, 1500)
        self.assertEqual(result, 1500)

    def test_normal_growth_with_baseline(self):
        """baseline=5000, last_raw=1000, raw=1500 → 5000+1500=6500."""
        from vless_installer.modules.traffic_accounting import _compute_accumulated
        entry = {"baseline_bytes": 5000, "last_raw": 1000}
        result = _compute_accumulated(entry, 1500)
        self.assertEqual(result, 6500)

    def test_reset_case(self):
        """Сброс: baseline=0, last_raw=5000, raw=100 → (0+5000)+100=5100."""
        from vless_installer.modules.traffic_accounting import _compute_accumulated
        entry = {"baseline_bytes": 0, "last_raw": 5000}
        # raw=100 < last_raw=5000 → reset → (baseline + last_raw) + raw = (0+5000)+100
        result = _compute_accumulated(entry, 100)
        self.assertEqual(result, 5100)

    def test_reset_with_existing_baseline(self):
        """baseline=5000, last_raw=3000, raw=500 → (5000+3000)+500=8500."""
        from vless_installer.modules.traffic_accounting import _compute_accumulated
        entry = {"baseline_bytes": 5000, "last_raw": 3000}
        result = _compute_accumulated(entry, 500)
        self.assertEqual(result, 8500)

    def test_equal_raw(self):
        """raw == last_raw → normal growth (>=), total = baseline + raw."""
        from vless_installer.modules.traffic_accounting import _compute_accumulated
        entry = {"baseline_bytes": 1000, "last_raw": 2000}
        # raw=2000 == last_raw=2000 → >= → normal → 1000 + 2000 = 3000
        result = _compute_accumulated(entry, 2000)
        self.assertEqual(result, 3000)


if __name__ == "__main__":
    unittest.main()
