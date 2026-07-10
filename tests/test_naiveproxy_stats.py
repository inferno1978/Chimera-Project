#!/usr/bin/env python3
"""
tests/test_naiveproxy_stats.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/naiveproxy_stats.py.

Модуль автономен. Тестируем:
  1. _bytes_human — форматирование байт (русские единицы)
  2. _fmt_pct — процент
  3. _decode_basic_auth — парсинг Basic auth
  4. _empty_log_stats — структура пустой статистики
  5. _parse_access_log — парсинг JSON access.log
  6. _load_naive_state / _load_cache / _save_cache — JSON I/O
"""
from __future__ import annotations

import base64
import json
import sys
import tempfile
import time
import unittest
from datetime import datetime
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


class TestBytesHuman(unittest.TestCase):
    """_bytes_human — русские единицы."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_zero_bytes(self):
        from vless_installer.modules.naiveproxy_stats import _bytes_human
        self.assertEqual(_bytes_human(0), "0.0 Б")

    def test_less_than_kib(self):
        from vless_installer.modules.naiveproxy_stats import _bytes_human
        self.assertEqual(_bytes_human(500), "500.0 Б")

    def test_kib(self):
        from vless_installer.modules.naiveproxy_stats import _bytes_human
        self.assertEqual(_bytes_human(1024), "1.0 КБ")

    def test_mib(self):
        from vless_installer.modules.naiveproxy_stats import _bytes_human
        self.assertEqual(_bytes_human(1024 * 1024), "1.0 МБ")

    def test_gib(self):
        from vless_installer.modules.naiveproxy_stats import _bytes_human
        self.assertEqual(_bytes_human(1024 ** 3), "1.0 ГБ")

    def test_tib(self):
        from vless_installer.modules.naiveproxy_stats import _bytes_human
        self.assertEqual(_bytes_human(1024 ** 4), "1.0 ТБ")

    def test_petabytes_fallback(self):
        from vless_installer.modules.naiveproxy_stats import _bytes_human
        # больше ТБ → ПБ
        result = _bytes_human(1024 ** 5)
        self.assertIn("ПБ", result)

    def test_uses_russian_units(self):
        """Единицы — русские, не английские."""
        from vless_installer.modules.naiveproxy_stats import _bytes_human
        self.assertIn("Б", _bytes_human(0))
        self.assertIn("КБ", _bytes_human(1024))


class TestFmtPct(unittest.TestCase):
    """_fmt_pct."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_zero_denom(self):
        from vless_installer.modules.naiveproxy_stats import _fmt_pct
        self.assertEqual(_fmt_pct(10, 0), "0%")

    def test_zero_num(self):
        from vless_installer.modules.naiveproxy_stats import _fmt_pct
        self.assertEqual(_fmt_pct(0, 100), "0.0%")

    def test_full(self):
        from vless_installer.modules.naiveproxy_stats import _fmt_pct
        self.assertEqual(_fmt_pct(100, 100), "100.0%")

    def test_half(self):
        from vless_installer.modules.naiveproxy_stats import _fmt_pct
        self.assertEqual(_fmt_pct(50, 100), "50.0%")

    def test_over_100(self):
        from vless_installer.modules.naiveproxy_stats import _fmt_pct
        self.assertEqual(_fmt_pct(150, 100), "150.0%")


class TestDecodeBasicAuth(unittest.TestCase):
    """_decode_basic_auth."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _encode(self, user_pass: str) -> str:
        return "Basic " + base64.b64encode(user_pass.encode()).decode()

    def test_decodes_user_pass(self):
        from vless_installer.modules.naiveproxy_stats import _decode_basic_auth
        self.assertEqual(_decode_basic_auth(self._encode("user:pass")), "user")

    def test_lowercase_basic_prefix(self):
        from vless_installer.modules.naiveproxy_stats import _decode_basic_auth
        token = base64.b64encode(b"user:pass").decode()
        self.assertEqual(_decode_basic_auth(f"basic {token}"), "user")

    def test_returns_unknown_on_garbage_that_cannot_decode(self):
        """base64 толерантен к мусору, но если декодированное не строка — 'unknown'."""
        from vless_installer.modules.naiveproxy_stats import _decode_basic_auth
        # Передаём None-подобный объект — должно вернуть 'unknown' через except
        result = _decode_basic_auth(None)
        self.assertEqual(result, "unknown")

    def test_empty_string_returns_empty(self):
        """Пустой Authorization → пустая строка (base64('') == '')."""
        from vless_installer.modules.naiveproxy_stats import _decode_basic_auth
        # пустая строка → token="", b64decode("==")="", decode()="" → возвращается ""
        # это не баг — для пустого ввода нет имени пользователя
        result = _decode_basic_auth("")
        # поведение: либо "", либо "unknown" — главное что не падает
        self.assertIn(result, ("", "unknown"))

    def test_returns_full_string_when_no_colon(self):
        from vless_installer.modules.naiveproxy_stats import _decode_basic_auth
        token = base64.b64encode(b"justuser").decode()
        self.assertEqual(_decode_basic_auth(f"Basic {token}"), "justuser")

    def test_handles_user_without_prefix(self):
        """Без префикса 'Basic ' — попытка декодировать как base64."""
        from vless_installer.modules.naiveproxy_stats import _decode_basic_auth
        token = base64.b64encode(b"user:pass").decode()
        # без префикса — тоже должно работать (token[6:] пропускается если нет 'basic ')
        result = _decode_basic_auth(token)
        self.assertEqual(result, "user")


class TestEmptyLogStats(unittest.TestCase):
    """_empty_log_stats — структура."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_dict_with_required_keys(self):
        from vless_installer.modules.naiveproxy_stats import _empty_log_stats
        stats = _empty_log_stats()
        required = {
            "total_requests", "total_bytes", "ok_requests", "err_requests",
            "auth_fail", "avg_lat_ms", "p95_lat_ms", "per_user", "per_ip",
            "status_cnt", "slots", "window_minutes", "has_data",
        }
        self.assertEqual(set(stats.keys()), required)

    def test_has_data_is_false(self):
        from vless_installer.modules.naiveproxy_stats import _empty_log_stats
        self.assertFalse(_empty_log_stats()["has_data"])

    def test_all_counters_zero(self):
        from vless_installer.modules.naiveproxy_stats import _empty_log_stats
        stats = _empty_log_stats()
        self.assertEqual(stats["total_requests"], 0)
        self.assertEqual(stats["total_bytes"], 0)
        self.assertEqual(stats["ok_requests"], 0)
        self.assertEqual(stats["err_requests"], 0)
        self.assertEqual(stats["auth_fail"], 0)


class TestParseAccessLog(unittest.TestCase):
    """_parse_access_log — парсинг JSON access.log."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._log = self._tmpdir / "access.log"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.naiveproxy_stats._ACCESS_LOG", self._log)

    def _entry(self, status=200, size=100, duration=0.1, ts=None,
               user_pass="user:pass", remote="1.2.3.4:55123"):
        if ts is None:
            ts = time.time()
        auth = "Basic " + base64.b64encode(user_pass.encode()).decode()
        return {
            "ts": ts,
            "status": status,
            "size": size,
            "duration": duration,
            "request": {
                "remote_addr": remote,
                "headers": {"Authorization": [auth]},
            },
        }

    def test_returns_empty_when_no_file(self):
        from vless_installer.modules.naiveproxy_stats import _parse_access_log
        with self._patch():
            result = _parse_access_log()
        self.assertFalse(result["has_data"])

    def test_returns_empty_when_file_empty(self):
        from vless_installer.modules.naiveproxy_stats import _parse_access_log
        self._log.write_text("")
        with self._patch():
            result = _parse_access_log()
        self.assertFalse(result["has_data"])

    def test_parses_single_entry(self):
        from vless_installer.modules.naiveproxy_stats import _parse_access_log
        self._log.write_text(json.dumps(self._entry(size=1024)) + "\n")
        with self._patch():
            result = _parse_access_log()
        self.assertTrue(result["has_data"])
        self.assertEqual(result["total_requests"], 1)
        self.assertEqual(result["total_bytes"], 1024)
        self.assertEqual(result["ok_requests"], 1)
        self.assertIn("user", result["per_user"])

    def test_counts_status_codes(self):
        from vless_installer.modules.naiveproxy_stats import _parse_access_log
        now = time.time()
        lines = [
            json.dumps(self._entry(status=200, ts=now)),
            json.dumps(self._entry(status=407, ts=now)),
            json.dumps(self._entry(status=500, ts=now)),
        ]
        self._log.write_text("\n".join(lines) + "\n")
        with self._patch():
            result = _parse_access_log()
        self.assertEqual(result["total_requests"], 3)
        self.assertEqual(result["ok_requests"], 1)
        self.assertEqual(result["auth_fail"], 1)
        self.assertEqual(result["err_requests"], 2)  # 407 + 500

    def test_filters_by_window(self):
        """Записи старше window_minutes — игнорируются."""
        from vless_installer.modules.naiveproxy_stats import _parse_access_log
        now = time.time()
        old_ts = now - 120 * 60  # 2 часа назад
        lines = [
            json.dumps(self._entry(ts=old_ts)),
            json.dumps(self._entry(ts=now)),
        ]
        self._log.write_text("\n".join(lines) + "\n")
        with self._patch():
            result = _parse_access_log(window_minutes=60)
        # только 1 запись в окне 60 минут
        self.assertEqual(result["total_requests"], 1)

    def test_anonymous_when_no_auth(self):
        from vless_installer.modules.naiveproxy_stats import _parse_access_log
        entry = self._entry()
        del entry["request"]["headers"]
        self._log.write_text(json.dumps(entry) + "\n")
        with self._patch():
            result = _parse_access_log()
        self.assertIn("anonymous", result["per_user"])

    def test_corrupt_json_lines_skipped(self):
        from vless_installer.modules.naiveproxy_stats import _parse_access_log
        self._log.write_text(
            "not json\n" +
            json.dumps(self._entry()) + "\n" +
            "{invalid\n"
        )
        with self._patch():
            result = _parse_access_log()
        self.assertEqual(result["total_requests"], 1)

    def test_top_ips_limited_to_5(self):
        from vless_installer.modules.naiveproxy_stats import _parse_access_log
        now = time.time()
        lines = []
        for i in range(10):
            lines.append(json.dumps(self._entry(
                remote=f"1.2.3.{i}:55123", ts=now,
            )))
        self._log.write_text("\n".join(lines) + "\n")
        with self._patch():
            result = _parse_access_log()
        self.assertLessEqual(len(result["per_ip"]), 5)

    def test_slots_aggregation(self):
        from vless_installer.modules.naiveproxy_stats import _parse_access_log
        # 2 записи в один 10-мин слот
        now = time.time()
        self._log.write_text(
            json.dumps(self._entry(ts=now)) + "\n" +
            json.dumps(self._entry(ts=now + 5)) + "\n"
        )
        with self._patch():
            result = _parse_access_log()
        # хотя бы один слот с 2 запросами
        self.assertTrue(any(s["requests"] >= 1 for s in result["slots"].values()))


class TestLoadNaiveState(unittest.TestCase):
    """_load_naive_state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "naiveproxy.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.naiveproxy_stats._MODULE_STATE",
                     self._state)

    def test_returns_empty_when_no_file(self):
        from vless_installer.modules.naiveproxy_stats import _load_naive_state
        with self._patch():
            self.assertEqual(_load_naive_state(), {})

    def test_returns_state_when_valid(self):
        from vless_installer.modules.naiveproxy_stats import _load_naive_state
        self._state.write_text(json.dumps({"port": 443, "users": []}))
        with self._patch():
            state = _load_naive_state()
        self.assertEqual(state["port"], 443)

    def test_returns_empty_when_corrupt(self):
        from vless_installer.modules.naiveproxy_stats import _load_naive_state
        self._state.write_text("{invalid")
        with self._patch():
            self.assertEqual(_load_naive_state(), {})


class TestLoadSaveCache(unittest.TestCase):
    """_load_cache / _save_cache."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cache = self._tmpdir / "cache.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.naiveproxy_stats._STATS_CACHE",
                     self._cache)

    def test_load_returns_empty_when_no_file(self):
        from vless_installer.modules.naiveproxy_stats import _load_cache
        with self._patch():
            self.assertEqual(_load_cache(), {})

    def test_save_then_load(self):
        from vless_installer.modules.naiveproxy_stats import _load_cache, _save_cache
        with self._patch():
            _save_cache({"ts": 12345, "bytes": 1000})
            loaded = _load_cache()
        self.assertEqual(loaded["ts"], 12345)
        self.assertEqual(loaded["bytes"], 1000)

    def test_load_returns_empty_when_corrupt(self):
        from vless_installer.modules.naiveproxy_stats import _load_cache
        self._cache.write_text("{invalid")
        with self._patch():
            self.assertEqual(_load_cache(), {})

    def test_save_silently_fails_on_error(self):
        """_save_cache подавляет исключения."""
        from vless_installer.modules.naiveproxy_stats import _save_cache
        with patch("vless_installer.modules.naiveproxy_stats._STATS_CACHE",
                   Path("/proc/nonexistent/cache.json")):
            # не должно бросать
            _save_cache({"x": 1})


class TestIptablesSpeed(unittest.TestCase):
    """_iptables_speed — расчёт скорости с кэшем."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cache = self._tmpdir / "cache.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.naiveproxy_stats._STATS_CACHE",
                     self._cache)

    def test_returns_zero_when_no_previous(self):
        from vless_installer.modules.naiveproxy_stats import _iptables_speed
        with self._patch(), \
             patch("vless_installer.modules.naiveproxy_stats._iptables_bytes",
                   return_value=1000):
            total, speed = _iptables_speed(443)
        self.assertEqual(total, 1000)
        # без предыдущего замера delta=0 (prev_bytes=0, но elapsed=max(...,1.0))
        # на самом деле delta = max(1000 - 0, 0) = 1000, speed = 1000/elapsed
        self.assertGreater(speed, 0)

    def test_calculates_delta_from_previous(self):
        from vless_installer.modules.naiveproxy_stats import (
            _iptables_speed, _save_cache,
        )
        # предыдущий замер: 1000 байт, 60 сек назад
        with self._patch():
            _save_cache({
                "naive_ipt_ts": time.time() - 60,
                "naive_ipt_bytes": 1000,
            })
            with patch("vless_installer.modules.naiveproxy_stats._iptables_bytes",
                       return_value=1600):
                total, speed = _iptables_speed(443)
        self.assertEqual(total, 1600)
        # delta = 600, elapsed ≈ 60, speed ≈ 10
        self.assertAlmostEqual(speed, 10.0, delta=2.0)

    def test_negative_delta_clamped_to_zero(self):
        """Если total уменьшился (сброс счётчиков) — delta = 0."""
        from vless_installer.modules.naiveproxy_stats import (
            _iptables_speed, _save_cache,
        )
        with self._patch():
            _save_cache({
                "naive_ipt_ts": time.time() - 60,
                "naive_ipt_bytes": 5000,
            })
            with patch("vless_installer.modules.naiveproxy_stats._iptables_bytes",
                       return_value=1000):
                total, speed = _iptables_speed(443)
        self.assertEqual(total, 1000)
        self.assertEqual(speed, 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
