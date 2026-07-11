#!/usr/bin/env python3
"""
tests/test_fragment_stats.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/fragment_stats.py.

Покрывает:
  1. _RE_TS / _RE_OK / _RE_BAD — regex паттерны
  2. _find_log — поиск лог-файла
  3. _parse_log — парсинг лога
  4. _calc_trend — расчёт тренда
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timedelta
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


class TestRegexPatterns(unittest.TestCase):
    """_RE_TS / _RE_OK / _RE_BAD — regex."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_re_ts_matches_slash_format(self):
        from vless_installer.modules.fragment_stats import _RE_TS
        m = _RE_TS.search("2026/07/10 12:00:00 some event")
        self.assertIsNotNone(m)

    def test_re_ts_matches_iso_format(self):
        from vless_installer.modules.fragment_stats import _RE_TS
        m = _RE_TS.search("2026-07-10T12:00:00 some event")
        self.assertIsNotNone(m)

    def test_re_ok_matches_handshake(self):
        from vless_installer.modules.fragment_stats import _RE_OK
        self.assertIsNotNone(_RE_OK.search("TLS handshake ok"))
        self.assertIsNotNone(_RE_OK.search("accepted from 1.2.3.4"))

    def test_re_bad_matches_connection_reset(self):
        from vless_installer.modules.fragment_stats import _RE_BAD
        self.assertIsNotNone(_RE_BAD.search("connection reset by peer"))
        self.assertIsNotNone(_RE_BAD.search("i/o timeout"))
        self.assertIsNotNone(_RE_BAD.search("broken pipe"))


class TestFindLog(unittest.TestCase):
    """_find_log — поиск лог-файла."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._log1 = self._tmpdir / "error.log"
        self._log2 = self._tmpdir / "alt.log"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("vless_installer.modules.fragment_stats._XRAY_LOG", self._log1),
            patch("vless_installer.modules.fragment_stats._ALT_LOG", self._log2),
        )

    def test_returns_none_when_no_logs(self):
        from vless_installer.modules.fragment_stats import _find_log
        with self._patch()[0], self._patch()[1]:
            self.assertIsNone(_find_log())

    def test_returns_first_when_exists(self):
        from vless_installer.modules.fragment_stats import _find_log
        self._log1.write_text("line\n")
        with self._patch()[0], self._patch()[1]:
            result = _find_log()
        self.assertEqual(result, self._log1)

    def test_skips_empty_file(self):
        from vless_installer.modules.fragment_stats import _find_log
        self._log1.write_text("")  # пустой
        self._log2.write_text("line\n")
        with self._patch()[0], self._patch()[1]:
            result = _find_log()
        self.assertEqual(result, self._log2)


class TestParseLog(unittest.TestCase):
    """_parse_log — парсинг лога."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._log = self._tmpdir / "error.log"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_empty_stats_for_empty_log(self):
        from vless_installer.modules.fragment_stats import _parse_log
        self._log.write_text("")
        result = _parse_log(self._log)
        self.assertEqual(result["total_ok"], 0)
        self.assertEqual(result["total_bad"], 0)
        self.assertEqual(result["slots"], {})

    def test_counts_ok_and_bad(self):
        from vless_installer.modules.fragment_stats import _parse_log
        now = datetime.now()
        ts = now.strftime("%Y/%m/%d %H:%M:%S")
        self._log.write_text(
            f"{ts} TLS handshake ok from 1.2.3.4\n"
            f"{ts} accepted from 5.6.7.8\n"
            f"{ts} connection reset by peer\n"
            f"{ts} i/o timeout\n"
        )
        result = _parse_log(self._log, window_minutes=60)
        self.assertEqual(result["total_ok"], 2)
        self.assertEqual(result["total_bad"], 2)

    def test_filters_old_entries(self):
        from vless_installer.modules.fragment_stats import _parse_log
        old = datetime.now() - timedelta(hours=2)
        old_ts = old.strftime("%Y/%m/%d %H:%M:%S")
        self._log.write_text(f"{old_ts} TLS handshake ok\n")
        result = _parse_log(self._log, window_minutes=60)
        self.assertEqual(result["total_ok"], 0)

    def test_uses_10_minute_slots(self):
        """Слоты округляются до 10 минут (не 5)."""
        from vless_installer.modules.fragment_stats import _parse_log
        now = datetime.now()
        ts = now.strftime("%Y/%m/%d %H:%M:%S")
        self._log.write_text(f"{ts} TLS handshake ok\n")
        result = _parse_log(self._log, window_minutes=60)
        # хотя бы один слот
        self.assertGreater(len(result["slots"]), 0)
        # слот заканчивается на "0" (10-минутный rounding)
        for slot_key in result["slots"]:
            self.assertTrue(slot_key.endswith("0"))

    def test_window_minutes_in_result(self):
        from vless_installer.modules.fragment_stats import _parse_log
        self._log.write_text("")
        result = _parse_log(self._log, window_minutes=30)
        self.assertEqual(result["window"], 30)


class TestCalcTrend(unittest.TestCase):
    """_calc_trend — расчёт тренда."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_insufficient_data(self):
        from vless_installer.modules.fragment_stats import _calc_trend
        slots = {"12:00": {"ok": 10, "bad": 0}}
        result = _calc_trend(slots)
        self.assertIn("недостаточно", result)

    def test_stable_when_ratio_in_range(self):
        from vless_installer.modules.fragment_stats import _calc_trend
        slots = {
            "12:00": {"ok": 90, "bad": 10},
            "12:10": {"ok": 90, "bad": 10},
            "12:20": {"ok": 90, "bad": 10},
            "12:30": {"ok": 90, "bad": 10},
        }
        result = _calc_trend(slots)
        self.assertIn("стабильно", result)

    def test_improves_when_bad_rate_drops(self):
        from vless_installer.modules.fragment_stats import _calc_trend
        slots = {
            "12:00": {"ok": 50, "bad": 50},
            "12:10": {"ok": 50, "bad": 50},
            "12:20": {"ok": 90, "bad": 10},
            "12:30": {"ok": 95, "bad": 5},
        }
        result = _calc_trend(slots)
        self.assertIn("улучшается", result)

    def test_worsens_when_bad_rate_rises(self):
        from vless_installer.modules.fragment_stats import _calc_trend
        slots = {
            "12:00": {"ok": 90, "bad": 10},
            "12:10": {"ok": 90, "bad": 10},
            "12:20": {"ok": 50, "bad": 50},
            "12:30": {"ok": 30, "bad": 70},
        }
        result = _calc_trend(slots)
        self.assertIn("ухудшается", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
