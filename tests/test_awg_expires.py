#!/usr/bin/env python3
"""
tests/test_awg_expires.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/awg_expires.py.

Покрывает:
  1. awgs_expires_parse — парсинг duration ('1h', '7d', '4w', '1mo', ...)
  2. awgs_expires_format — обратное форматирование
  3. awgs_expires_compute_iso — ISO-дата истечения
  4. awgs_expires_is_expired — проверка срока
  5. awgs_expires_remaining — оставшееся время
  6. awgs_expires_humanize — человекочитаемая строка
"""
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
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


class TestExpiresParse(unittest.TestCase):
    """awgs_expires_parse — парсинг duration."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_one_hour(self):
        from chimera.modules.awg_expires import awgs_expires_parse
        delta = awgs_expires_parse("1h")
        self.assertIsNotNone(delta)
        self.assertEqual(delta, timedelta(hours=1))

    def test_12_hours(self):
        from chimera.modules.awg_expires import awgs_expires_parse
        self.assertEqual(awgs_expires_parse("12h"), timedelta(hours=12))

    def test_one_day(self):
        from chimera.modules.awg_expires import awgs_expires_parse
        self.assertEqual(awgs_expires_parse("1d"), timedelta(days=1))

    def test_30_days(self):
        from chimera.modules.awg_expires import awgs_expires_parse
        self.assertEqual(awgs_expires_parse("30d"), timedelta(days=30))

    def test_4_weeks(self):
        from chimera.modules.awg_expires import awgs_expires_parse
        self.assertEqual(awgs_expires_parse("4w"), timedelta(weeks=4))

    def test_one_month_equals_30_days(self):
        from chimera.modules.awg_expires import awgs_expires_parse
        self.assertEqual(awgs_expires_parse("1mo"), timedelta(days=30))

    def test_minutes(self):
        from chimera.modules.awg_expires import awgs_expires_parse
        self.assertEqual(awgs_expires_parse("5m"), timedelta(minutes=5))

    def test_seconds(self):
        from chimera.modules.awg_expires import awgs_expires_parse
        self.assertEqual(awgs_expires_parse("600s"), timedelta(seconds=600))

    def test_case_insensitive(self):
        from chimera.modules.awg_expires import awgs_expires_parse
        self.assertEqual(awgs_expires_parse("1H"), timedelta(hours=1))
        self.assertEqual(awgs_expires_parse("7D"), timedelta(days=7))

    def test_strips_whitespace(self):
        from chimera.modules.awg_expires import awgs_expires_parse
        self.assertEqual(awgs_expires_parse("  1h  "), timedelta(hours=1))

    def test_empty_string_returns_none(self):
        from chimera.modules.awg_expires import awgs_expires_parse
        self.assertIsNone(awgs_expires_parse(""))

    def test_invalid_unit_returns_none(self):
        from chimera.modules.awg_expires import awgs_expires_parse
        self.assertIsNone(awgs_expires_parse("1x"))
        self.assertIsNone(awgs_expires_parse("1y"))

    def test_no_number_returns_none(self):
        from chimera.modules.awg_expires import awgs_expires_parse
        self.assertIsNone(awgs_expires_parse("h"))
        self.assertIsNone(awgs_expires_parse("abc"))

    def test_negative_invalid(self):
        from chimera.modules.awg_expires import awgs_expires_parse
        self.assertIsNone(awgs_expires_parse("-1h"))


class TestExpiresFormat(unittest.TestCase):
    """awgs_expires_format — обратное форматирование timedelta в строку."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_one_hour(self):
        from chimera.modules.awg_expires import awgs_expires_format
        self.assertEqual(awgs_expires_format(timedelta(hours=1)), "1h")

    def test_one_day(self):
        from chimera.modules.awg_expires import awgs_expires_format
        self.assertEqual(awgs_expires_format(timedelta(days=1)), "1d")

    def test_seven_days_as_week(self):
        from chimera.modules.awg_expires import awgs_expires_format
        self.assertEqual(awgs_expires_format(timedelta(days=7)), "1w")

    def test_30_days_as_month(self):
        from chimera.modules.awg_expires import awgs_expires_format
        self.assertEqual(awgs_expires_format(timedelta(days=30)), "1mo")

    def test_minutes(self):
        from chimera.modules.awg_expires import awgs_expires_format
        self.assertEqual(awgs_expires_format(timedelta(minutes=5)), "5m")

    def test_seconds_when_subminute(self):
        from chimera.modules.awg_expires import awgs_expires_format
        self.assertEqual(awgs_expires_format(timedelta(seconds=30)), "30s")

    def test_round_trip_parse_format(self):
        """parse → format → parse даёт тот же timedelta.
        format выбирает старшую кратную единицу: 7d → '1w', 30d → '1mo'."""
        from chimera.modules.awg_expires import (
            awgs_expires_parse, awgs_expires_format,
        )
        # (исходная строка, ожидаемый результат format)
        cases = [
            ("1h", "1h"),
            ("12h", "12h"),
            ("7d", "1w"),     # 7d кратно неделе → '1w'
            ("4w", "4w"),
            ("30d", "1mo"),   # 30d кратно месяцу → '1mo'
            ("5m", "5m"),
            ("600s", "10m"),  # 600s = 10 минут
        ]
        for s, expected in cases:
            with self.subTest(s=s):
                delta = awgs_expires_parse(s)
                self.assertIsNotNone(delta)
                self.assertEqual(awgs_expires_format(delta), expected)
                # пере-парсинг результата должен дать тот же timedelta
                re_parsed = awgs_expires_parse(expected)
                self.assertEqual(re_parsed, delta)


class TestExpiresComputeIso(unittest.TestCase):
    """awgs_expires_compute_iso — ISO-дата истечения."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_iso_with_tz(self):
        from chimera.modules.awg_expires import awgs_expires_compute_iso
        iso = awgs_expires_compute_iso(timedelta(hours=1))
        dt = datetime.fromisoformat(iso)
        self.assertIsNotNone(dt.tzinfo)

    def test_one_hour_from_now(self):
        from chimera.modules.awg_expires import awgs_expires_compute_iso
        before = datetime.now(timezone.utc)
        iso = awgs_expires_compute_iso(timedelta(hours=1))
        dt = datetime.fromisoformat(iso)
        delta = dt - before
        self.assertGreaterEqual(delta.total_seconds(), 3500)
        self.assertLessEqual(delta.total_seconds(), 3700)


class TestExpiresIsExpired(unittest.TestCase):
    """awgs_expires_is_expired — проверка срока."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_string_not_expired(self):
        """Пустая строка = бессрочный → False."""
        from chimera.modules.awg_expires import awgs_expires_is_expired
        self.assertFalse(awgs_expires_is_expired(""))

    def test_future_not_expired(self):
        from chimera.modules.awg_expires import awgs_expires_is_expired
        future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        self.assertFalse(awgs_expires_is_expired(future))

    def test_past_expired(self):
        from chimera.modules.awg_expires import awgs_expires_is_expired
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        self.assertTrue(awgs_expires_is_expired(past))

    def test_naive_datetime_treated_as_utc(self):
        """ISO без tzinfo интерпретируется как UTC."""
        from chimera.modules.awg_expires import awgs_expires_is_expired
        past_naive = (datetime.utcnow() - timedelta(days=1)).isoformat()
        self.assertTrue(awgs_expires_is_expired(past_naive))

    def test_invalid_string_returns_false(self):
        from chimera.modules.awg_expires import awgs_expires_is_expired
        self.assertFalse(awgs_expires_is_expired("invalid-date"))


class TestExpiresRemaining(unittest.TestCase):
    """awgs_expires_remaining."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_returns_none(self):
        from chimera.modules.awg_expires import awgs_expires_remaining
        self.assertIsNone(awgs_expires_remaining(""))

    def test_future_returns_positive(self):
        from chimera.modules.awg_expires import awgs_expires_remaining
        future = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
        remaining = awgs_expires_remaining(future)
        self.assertIsNotNone(remaining)
        self.assertGreater(remaining.total_seconds(), 0)

    def test_past_returns_zero(self):
        """Истёкший → timedelta(0)."""
        from chimera.modules.awg_expires import awgs_expires_remaining
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        remaining = awgs_expires_remaining(past)
        self.assertEqual(remaining, timedelta(0))

    def test_invalid_returns_none(self):
        from chimera.modules.awg_expires import awgs_expires_remaining
        self.assertIsNone(awgs_expires_remaining("garbage"))


class TestExpiresHumanize(unittest.TestCase):
    """awgs_expires_humanize — человекочитаемая строка."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_returns_bessrochno(self):
        from chimera.modules.awg_expires import awgs_expires_humanize
        self.assertEqual(awgs_expires_humanize(""), "бессрочно")

    def test_past_returns_istyok(self):
        from chimera.modules.awg_expires import awgs_expires_humanize
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        self.assertEqual(awgs_expires_humanize(past), "истёк")

    def test_days_format(self):
        from chimera.modules.awg_expires import awgs_expires_humanize
        future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        result = awgs_expires_humanize(future)
        self.assertIn("дн.", result)

    def test_hours_format(self):
        from chimera.modules.awg_expires import awgs_expires_humanize
        future = (datetime.now(timezone.utc) + timedelta(hours=3)).isoformat()
        result = awgs_expires_humanize(future)
        self.assertIn("ч.", result)

    def test_minutes_format(self):
        from chimera.modules.awg_expires import awgs_expires_humanize
        future = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
        result = awgs_expires_humanize(future)
        self.assertIn("мин.", result)

    def test_invalid_returns_question_mark(self):
        from chimera.modules.awg_expires import awgs_expires_humanize
        self.assertEqual(awgs_expires_humanize("garbage"), "?")


class TestExpiresCheck(unittest.TestCase):
    """awgs_expires_check — cron-проверка (без subprocess, только state)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(__import__("tempfile").mkdtemp())
        self._state_file = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state_file(self):
        return patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                     self._state_file)

    def test_no_peers_returns_zero(self):
        from chimera.modules import awg_expires, awg_state
        with self._patch_state_file():
            awg_state.awgs_state_save({"installed": True, "peers": []})
            # Мокаем awg_peer_remove чтобы не вызывать subprocess
            with patch("chimera.modules.awg_peers.awg_peer_remove"):
                self.assertEqual(awg_expires.awgs_expires_check(), 0)

    def test_no_state_returns_zero(self):
        from chimera.modules import awg_expires
        with self._patch_state_file():
            with patch("chimera.modules.awg_peers.awg_peer_remove"):
                self.assertEqual(awg_expires.awgs_expires_check(), 0)

    def test_removes_expired_peers(self):
        from chimera.modules import awg_expires, awg_state
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        with self._patch_state_file():
            awg_state.awgs_state_save({
                "installed": True,
                "peers": [
                    {"name": "alice", "expires_at": past},
                    {"name": "bob", "expires_at": ""},
                    {"name": "carol",
                     "expires_at": (datetime.now(timezone.utc)
                                    + timedelta(days=7)).isoformat()},
                ],
            })
            with patch("chimera.modules.awg_peers.awg_peer_remove") as mock_rm:
                count = awg_expires.awgs_expires_check()
                self.assertEqual(count, 1)
                self.assertEqual(mock_rm.call_count, 1)
                # первый аргумент вызова — имя пира
                self.assertEqual(mock_rm.call_args.args[0], "alice")


if __name__ == "__main__":
    unittest.main(verbosity=2)
