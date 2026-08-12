#!/usr/bin/env python3
"""
tests/test_mieru_stats.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/mieru_stats.py.

Модуль автономен. Тестируем:
  1. _bytes_human — русские единицы
  2. _load_mieru_state / _load_cache / _save_cache — JSON I/O
  3. _get_mita_ports — чтение portRange из /etc/mita/server.json
  4. _parse_kv — Key1=Val1 Key2=Val2 → dict
  5. _parse_journal — парсинг journalctl mita (mocked _run)
  6. _calc_trend — тренд активности
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
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


class TestBytesHuman(unittest.TestCase):
    """_bytes_human — русские единицы (аналог naiveproxy_stats)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_zero(self):
        from chimera.modules.mieru_stats import _bytes_human
        self.assertEqual(_bytes_human(0), "0.0 Б")

    def test_kib(self):
        from chimera.modules.mieru_stats import _bytes_human
        self.assertEqual(_bytes_human(1024), "1.0 КБ")

    def test_mib(self):
        from chimera.modules.mieru_stats import _bytes_human
        self.assertEqual(_bytes_human(1024 ** 2), "1.0 МБ")

    def test_gib(self):
        from chimera.modules.mieru_stats import _bytes_human
        self.assertEqual(_bytes_human(1024 ** 3), "1.0 ГБ")

    def test_petabytes_fallback(self):
        from chimera.modules.mieru_stats import _bytes_human
        result = _bytes_human(1024 ** 5)
        self.assertIn("ПБ", result)


class TestLoadMieruState(unittest.TestCase):
    """_load_mieru_state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "mieru.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.mieru_stats._MODULE_STATE",
                     self._state)

    def test_returns_empty_when_no_file(self):
        from chimera.modules.mieru_stats import _load_mieru_state
        with self._patch():
            self.assertEqual(_load_mieru_state(), {})

    def test_returns_state(self):
        from chimera.modules.mieru_stats import _load_mieru_state
        self._state.write_text(json.dumps({"port_start": 2012, "users": []}))
        with self._patch():
            state = _load_mieru_state()
        self.assertEqual(state["port_start"], 2012)

    def test_returns_empty_when_corrupt(self):
        from chimera.modules.mieru_stats import _load_mieru_state
        self._state.write_text("{invalid")
        with self._patch():
            self.assertEqual(_load_mieru_state(), {})


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
        return patch("chimera.modules.mieru_stats._STATS_CACHE",
                     self._cache)

    def test_load_returns_empty_when_no_file(self):
        from chimera.modules.mieru_stats import _load_cache
        with self._patch():
            self.assertEqual(_load_cache(), {})

    def test_save_then_load(self):
        from chimera.modules.mieru_stats import _load_cache, _save_cache
        with self._patch():
            _save_cache({"ts": 12345, "bytes": 1000})
            loaded = _load_cache()
        self.assertEqual(loaded["ts"], 12345)

    def test_save_silently_fails(self):
        from chimera.modules.mieru_stats import _save_cache
        with patch("chimera.modules.mieru_stats._STATS_CACHE",
                   Path("/proc/nonexistent/cache.json")):
            _save_cache({"x": 1})  # не должно бросать


class TestGetMitaPorts(unittest.TestCase):
    """_get_mita_ports — чтение portRange из /etc/mita/server.json."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "server.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_open(self):
        """Патчит Path в модуле mieru_stats так, чтобы Path('/etc/mita/server.json')
        указывал на временный файл конфига. Другие Path-вызовы не затрагиваются."""

        original_path = Path

        def _fake_path_constructor(*args, **kwargs):
            if args and str(args[0]) == "/etc/mita/server.json":
                # Возвращаем путь к нашему временному конфигу
                return self._cfg
            return original_path(*args, **kwargs)

        # Path — это класс, нельзя просто заменить на callable.
        # Используем MagicMock с side_effect.
        mock_path = MagicMock(side_effect=_fake_path_constructor)
        # Копируем статические методы/атрибуты Path, которые могут использоваться
        for attr in ("exists", "read_text", "write_text", "stat", "parent",
                     "name", "mkdir", "chmod", "touch", "open"):
            setattr(mock_path, attr, getattr(original_path, attr, None))
        return patch("chimera.modules.mieru_stats.Path", mock_path)

    def test_returns_default_when_no_file(self):
        from chimera.modules.mieru_stats import _get_mita_ports
        with self._patch_open():
            ports = _get_mita_ports()
        self.assertEqual(ports, (2012, 2022))

    def test_single_port_string(self):
        from chimera.modules.mieru_stats import _get_mita_ports
        self._cfg.write_text(json.dumps({"portRange": "2012"}))
        with self._patch_open():
            ports = _get_mita_ports()
        self.assertEqual(ports, (2012, 2012))

    def test_dash_separator(self):
        from chimera.modules.mieru_stats import _get_mita_ports
        self._cfg.write_text(json.dumps({"portRange": "2012-2022"}))
        with self._patch_open():
            ports = _get_mita_ports()
        self.assertEqual(ports, (2012, 2022))

    def test_colon_separator(self):
        from chimera.modules.mieru_stats import _get_mita_ports
        self._cfg.write_text(json.dumps({"portRange": "2012:2022"}))
        with self._patch_open():
            ports = _get_mita_ports()
        self.assertEqual(ports, (2012, 2022))

    def test_portBindings_first_element(self):
        from chimera.modules.mieru_stats import _get_mita_ports
        self._cfg.write_text(json.dumps({
            "portBindings": [{"portRange": "3000-3010"}],
        }))
        with self._patch_open():
            ports = _get_mita_ports()
        self.assertEqual(ports, (3000, 3010))

    def test_corrupt_json_returns_default(self):
        from chimera.modules.mieru_stats import _get_mita_ports
        self._cfg.write_text("{invalid")
        with self._patch_open():
            ports = _get_mita_ports()
        self.assertEqual(ports, (2012, 2022))


class TestParseKv(unittest.TestCase):
    """_parse_kv — Key1=Val1 Key2=Val2 → dict."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_string(self):
        from chimera.modules.mieru_stats import _parse_kv
        self.assertEqual(_parse_kv(""), {})

    def test_single_kv(self):
        from chimera.modules.mieru_stats import _parse_kv
        self.assertEqual(_parse_kv("Key1=42"), {"Key1": "42"})

    def test_multiple_kv(self):
        from chimera.modules.mieru_stats import _parse_kv
        result = _parse_kv("DownloadBytes=100 UploadBytes=200 OutputPaddingBytes=5")
        self.assertEqual(result, {
            "DownloadBytes": "100",
            "UploadBytes": "200",
            "OutputPaddingBytes": "5",
        })

    def test_ignores_non_digit_values(self):
        r"""Только \w+=\d+ — строковые значения игнорируются."""
        from chimera.modules.mieru_stats import _parse_kv
        result = _parse_kv("Key1=abc Key2=42")
        self.assertEqual(result, {"Key2": "42"})

    def test_duplicate_keys_last_wins(self):
        from chimera.modules.mieru_stats import _parse_kv
        result = _parse_kv("Key=1 Key=2")
        self.assertEqual(result, {"Key": "2"})

    def test_no_kv_in_string(self):
        from chimera.modules.mieru_stats import _parse_kv
        self.assertEqual(_parse_kv("just some text"), {})


class TestParseJournal(unittest.TestCase):
    """_parse_journal — парсинг journalctl mita (mocked _run)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _mock_run(self, stdout: str, returncode: int = 0):
        m = MagicMock()
        m.stdout = stdout
        m.returncode = returncode
        m.stderr = ""
        return m

    def test_empty_journal_returns_zeros(self):
        from chimera.modules import mieru_stats
        with patch.object(mieru_stats, "_run",
                          return_value=self._mock_run("")):
            result = mieru_stats._parse_journal()
        self.assertEqual(result["active_opens"], 0)
        self.assertEqual(result["download_bytes"], 0)
        self.assertEqual(result["users"], {})

    def test_parses_connections_metrics(self):
        from chimera.modules import mieru_stats
        line = (
            "2026-07-10T12:00:00 [metrics - connections] "
            "ActiveOpens=100 CurrEstablished=10 PassiveOpens=200"
        )
        with patch.object(mieru_stats, "_run",
                          return_value=self._mock_run(line)):
            result = mieru_stats._parse_journal()
        self.assertEqual(result["active_opens"], 100)
        self.assertEqual(result["curr_established"], 10)
        self.assertEqual(result["passive_opens"], 200)
        self.assertEqual(result["accepted"], 200)

    def test_parses_traffic_metrics(self):
        from chimera.modules import mieru_stats
        line = (
            "2026-07-10T12:00:00 [metrics - traffic] "
            "DownloadBytes=1024 UploadBytes=2048 OutputPaddingBytes=10"
        )
        with patch.object(mieru_stats, "_run",
                          return_value=self._mock_run(line)):
            result = mieru_stats._parse_journal()
        self.assertEqual(result["download_bytes"], 1024)
        self.assertEqual(result["upload_bytes"], 2048)
        self.assertEqual(result["padding_bytes"], 10)

    def test_parses_user_metrics(self):
        from chimera.modules import mieru_stats
        line = (
            "2026-07-10T12:00:00 [metrics - user - alice] "
            "DownloadBytes=100 UploadBytes=200"
        )
        with patch.object(mieru_stats, "_run",
                          return_value=self._mock_run(line)):
            result = mieru_stats._parse_journal()
        self.assertIn("alice", result["users"])
        self.assertEqual(result["users"]["alice"]["download"], 100)
        self.assertEqual(result["users"]["alice"]["upload"], 200)

    def test_parses_errors(self):
        from chimera.modules import mieru_stats
        lines = "\n".join([
            "2026-07-10T12:00:00 some error happened",
            "2026-07-10T12:00:01 FATAL: crash",
            "2026-07-10T12:00:02 warning: low memory",
        ])
        with patch.object(mieru_stats, "_run",
                          return_value=self._mock_run(lines)):
            result = mieru_stats._parse_journal()
        self.assertGreaterEqual(result["errors"], 2)
        self.assertGreaterEqual(result["warnings"], 1)

    def test_parses_replay_metrics(self):
        from chimera.modules import mieru_stats
        line = (
            "2026-07-10T12:00:00 [metrics - replay] "
            "KnownSession=50 NewSession=5"
        )
        with patch.object(mieru_stats, "_run",
                          return_value=self._mock_run(line)):
            result = mieru_stats._parse_journal()
        self.assertEqual(result["known_sessions"], 50)
        self.assertEqual(result["new_sessions"], 5)

    def test_parses_auth_fail(self):
        from chimera.modules import mieru_stats
        line = (
            "2026-07-10T12:00:00 [metrics - cipher aes-128] "
            "FailedDirectDecrypt=3 FailedHintMatchDecrypt=1"
        )
        with patch.object(mieru_stats, "_run",
                          return_value=self._mock_run(line)):
            result = mieru_stats._parse_journal()
        self.assertGreaterEqual(result["auth_fail"], 4)

    def test_raw_lines_count(self):
        from chimera.modules import mieru_stats
        lines = "line1\nline2\nline3"
        with patch.object(mieru_stats, "_run",
                          return_value=self._mock_run(lines)):
            result = mieru_stats._parse_journal()
        self.assertEqual(result["raw_lines"], 3)


class TestCalcTrend(unittest.TestCase):
    """_calc_trend — тренд активности."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_insufficient_data_less_than_3(self):
        from chimera.modules.mieru_stats import _calc_trend
        slots = {"12:00": {"accepted": 10}}
        result = _calc_trend(slots)
        self.assertIn("недостаточно", result)

    def test_no_activity(self):
        from chimera.modules.mieru_stats import _calc_trend
        slots = {
            "12:00": {"accepted": 0},
            "12:10": {"accepted": 0},
            "12:20": {"accepted": 0},
            "12:30": {"accepted": 0},
        }
        result = _calc_trend(slots)
        self.assertIn("нет активности", result)

    def test_growth(self):
        """ratio >= 1.3 → рост."""
        from chimera.modules.mieru_stats import _calc_trend
        slots = {
            "12:00": {"accepted": 10},
            "12:10": {"accepted": 10},
            "12:20": {"accepted": 50},  # recent avg
            "12:30": {"accepted": 60},  # recent avg = 55, older = 10 → ratio 5.5
        }
        result = _calc_trend(slots)
        self.assertIn("рост", result)

    def test_decline(self):
        """ratio <= 0.7 → спад."""
        from chimera.modules.mieru_stats import _calc_trend
        slots = {
            "12:00": {"accepted": 100},
            "12:10": {"accepted": 100},
            "12:20": {"accepted": 30},
            "12:30": {"accepted": 30},  # recent avg=30, older=100 → ratio 0.3
        }
        result = _calc_trend(slots)
        self.assertIn("спад", result)

    def test_stable(self):
        """0.7 < ratio < 1.3 → стабильно."""
        from chimera.modules.mieru_stats import _calc_trend
        slots = {
            "12:00": {"accepted": 100},
            "12:10": {"accepted": 100},
            "12:20": {"accepted": 100},
            "12:30": {"accepted": 100},  # ratio = 1.0
        }
        result = _calc_trend(slots)
        self.assertIn("стабильно", result)

    def test_growth_when_older_zero(self):
        """Если older=0 и recent>0 → 'растёт'."""
        from chimera.modules.mieru_stats import _calc_trend
        slots = {
            "12:00": {"accepted": 0},
            "12:10": {"accepted": 0},
            "12:20": {"accepted": 50},
            "12:30": {"accepted": 60},
        }
        result = _calc_trend(slots)
        self.assertIn("растёт", result)

    def test_three_slots_uses_first_two_as_older(self):
        """При 3 ключах older = keys[:2]."""
        from chimera.modules.mieru_stats import _calc_trend
        slots = {
            "12:00": {"accepted": 100},  # older
            "12:10": {"accepted": 100},  # older
            "12:20": {"accepted": 200},  # recent (последние 2 = 12:10, 12:20)
        }
        # recent avg = (100+200)/2 = 150, older avg = (100+100)/2 = 100 → ratio 1.5
        result = _calc_trend(slots)
        self.assertIn("рост", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТЫ МИГРАЦИИ НА NFTABLES (этап 1.5) — мок nft_common
# ══════════════════════════════════════════════════════════════════════════════
class TestNftMigration(unittest.TestCase):
    """Проверяет что mieru_stats.py использует nft_common вместо прямых
    iptables subprocess-вызовов (этап 1.5 миграции).

    Мокает nft_rule_insert / nft_rule_exists / nft_rule_delete_by_comment /
    nft_rule_counter_read / _nft_available — проверяет что:
      • _ensure_iptables_rule создаёт counter-rule через nft_rule_insert.
      • _iptables_stats читает bytes через nft_rule_counter_read.
      • Используется comment-tag "mita-stats" (из nft_constants).
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_uses_mita_stats_comment_tag(self):
        """Comment-tag для counter-rule — "mita-stats" из nft_constants."""
        from chimera.modules import mieru_stats
        from chimera.modules.nft_constants import COMMENT_MITA_STATS
        self.assertEqual(mieru_stats._MITA_STATS_COMMENT, COMMENT_MITA_STATS)
        self.assertEqual(mieru_stats._MITA_STATS_COMMENT, "mita-stats")

    def test_ensure_rule_returns_false_when_nft_unavailable(self):
        """Если nft binary недоступен — _ensure_iptables_rule возвращает False."""
        from chimera.modules import mieru_stats
        with patch("chimera.modules.mieru_stats._nft_available",
                   return_value=False):
            self.assertFalse(mieru_stats._ensure_iptables_rule(2012, 2022, "tcp"))

    def test_ensure_rule_returns_true_if_rule_already_exists(self):
        """Если counter-rule уже есть (через comment-tag) — не пересоздаём."""
        from chimera.modules import mieru_stats
        with patch("chimera.modules.mieru_stats._nft_available",
                   return_value=True), \
             patch("chimera.modules.mieru_stats.nft_rule_exists",
                   return_value=True) as mock_exists, \
             patch("chimera.modules.mieru_stats.nft_rule_insert") as mock_insert:
            result = mieru_stats._ensure_iptables_rule(2012, 2022, "tcp")
        self.assertTrue(result)
        mock_insert.assert_not_called()
        # Проверяем что exists вызван с правильным comment-tag
        _, kwargs = mock_exists.call_args
        self.assertEqual(kwargs.get("comment"), "mita-stats")
        self.assertEqual(kwargs.get("chain"), "input")

    def test_ensure_rule_inserts_when_missing(self):
        """Если counter-rule нет — создаём через nft_rule_insert с counter accept."""
        from chimera.modules import mieru_stats
        with patch("chimera.modules.mieru_stats._nft_available",
                   return_value=True), \
             patch("chimera.modules.mieru_stats.nft_rule_exists",
                   return_value=False), \
             patch("chimera.modules.mieru_stats.nft_rule_delete_by_comment",
                   return_value=0), \
             patch("chimera.modules.mieru_stats.nft_rule_insert",
                   return_value=True) as mock_insert:
            result = mieru_stats._ensure_iptables_rule(2012, 2012, "tcp")
        self.assertTrue(result)
        mock_insert.assert_called_once()
        _, kwargs = mock_insert.call_args
        # rule_spec должен содержать proto+port+counter
        spec = kwargs.get("rule_spec", "")
        self.assertIn("tcp", spec)
        self.assertIn("2012", spec)
        self.assertIn("counter accept", spec)
        self.assertEqual(kwargs.get("comment"), "mita-stats")

    def test_ensure_rule_uses_dash_for_port_range(self):
        """nft использует дефис для диапазона портов (не двоеточие)."""
        from chimera.modules import mieru_stats
        # Проверяем helper-функцию напрямую
        spec = mieru_stats._nft_mita_rule_spec(2012, 2022, "tcp")
        self.assertEqual(spec, "tcp dport 2012-2022 counter accept")
        # Одиночный порт — без дефиса
        spec = mieru_stats._nft_mita_rule_spec(2012, 2012, "udp")
        self.assertEqual(spec, "udp dport 2012 counter accept")

    def test_iptables_stats_uses_nft_counter_read(self):
        """_iptables_stats делегирует в nft_rule_counter_read с comment-tag."""
        from chimera.modules import mieru_stats
        with patch("chimera.modules.mieru_stats._nft_available",
                   return_value=True), \
             patch("chimera.modules.mieru_stats.nft_rule_counter_read",
                   return_value={"packets": 100, "bytes": 4096}) as mock_cnt:
            result = mieru_stats._iptables_stats(2012, 2022, "tcp")
        self.assertEqual(result["bytes"], 4096)
        self.assertEqual(result["packets"], 100)
        mock_cnt.assert_called_once()
        _, kwargs = mock_cnt.call_args
        self.assertEqual(kwargs.get("comment"), "mita-stats")
        self.assertEqual(kwargs.get("chain"), "input")

    def test_iptables_stats_returns_zero_when_nft_unavailable(self):
        """Если nft недоступен — _iptables_stats возвращает zeros."""
        from chimera.modules import mieru_stats
        with patch("chimera.modules.mieru_stats._nft_available",
                   return_value=False):
            result = mieru_stats._iptables_stats(2012, 2022, "tcp")
        self.assertEqual(result, {"bytes": 0, "packets": 0})
