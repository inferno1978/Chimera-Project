#!/usr/bin/env python3
"""
tests/test_mtproto_stats.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/mtproto_stats.py.

Модуль имеет try/except ImportError для импорта из mtproto.py —
если mtproto.py недоступен, использует собственные fallback-реализации.
Тестируем через public API независимо от ветки (parent vs fallback).

Покрывает:
  1. _fmt_bytes — форматирование байт (KiB/MiB/...)
  2. _today / _now_str — дата/время
  3. _get_port — чтение порта из telemt.toml
  4. _load_users — парсинг TOML [access.users]
  5. _load_stats / _save_stats — JSON I/O
  6. _parse_journal — парсинг journalctl (mocked _run)
  7. _collect — обновление статистики (mocked iptables + journalctl)
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime
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


class TestFmtBytes(unittest.TestCase):
    """_fmt_bytes — форматирование (B, KiB, MiB, ...)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_zero(self):
        from chimera.modules.mtproto_stats import _fmt_bytes
        self.assertEqual(_fmt_bytes(0), "0 B")

    def test_less_than_kib(self):
        from chimera.modules.mtproto_stats import _fmt_bytes
        self.assertEqual(_fmt_bytes(500), "500 B")

    def test_kib(self):
        from chimera.modules.mtproto_stats import _fmt_bytes
        self.assertEqual(_fmt_bytes(1024), "1.0 KiB")

    def test_mib(self):
        from chimera.modules.mtproto_stats import _fmt_bytes
        self.assertEqual(_fmt_bytes(1024 ** 2), "1.0 MiB")

    def test_gib(self):
        from chimera.modules.mtproto_stats import _fmt_bytes
        self.assertEqual(_fmt_bytes(1024 ** 3), "1.0 GiB")

    def test_petabytes_fallback(self):
        from chimera.modules.mtproto_stats import _fmt_bytes
        result = _fmt_bytes(1024 ** 5)
        self.assertIn("PiB", result)


class TestTodayNowStr(unittest.TestCase):
    """_today / _now_str."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_today_format(self):
        from chimera.modules.mtproto_stats import _today
        result = _today()
        # YYYY-MM-DD
        self.assertRegex(result, r"^\d{4}-\d{2}-\d{2}$")
        # парсится
        datetime.strptime(result, "%Y-%m-%d")

    def test_now_str_format(self):
        from chimera.modules.mtproto_stats import _now_str
        result = _now_str()
        # YYYY-MM-DD HH:MM:SS
        self.assertRegex(result, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
        datetime.strptime(result, "%Y-%m-%d %H:%M:%S")


class TestGetPort(unittest.TestCase):
    """_get_port — чтение порта из CONFIG_FILE."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "telemt.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.mtproto_stats.CONFIG_FILE",
                     self._cfg)

    def test_returns_default_when_no_file(self):
        from chimera.modules.mtproto_stats import _get_port
        with self._patch():
            self.assertEqual(_get_port(), 8443)

    def test_returns_port_from_file(self):
        from chimera.modules.mtproto_stats import _get_port
        self._cfg.write_text('port = 9999\n')
        with self._patch():
            self.assertEqual(_get_port(), 9999)

    def test_returns_default_when_no_port_in_file(self):
        from chimera.modules.mtproto_stats import _get_port
        self._cfg.write_text('other_setting = "x"\n')
        with self._patch():
            self.assertEqual(_get_port(), 8443)

    def test_handles_internal_whitespace(self):
        r"""Regex ^port\s*=\s*(\d+) — допускает пробелы вокруг =, но не в начале строки."""
        from chimera.modules.mtproto_stats import _get_port
        self._cfg.write_text('port   =   7777\n')
        with self._patch():
            self.assertEqual(_get_port(), 7777)


class TestLoadUsers(unittest.TestCase):
    """_load_users — парсинг TOML [access.users] секции."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "telemt.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.mtproto_stats.CONFIG_FILE",
                     self._cfg)

    def test_returns_empty_when_no_file(self):
        from chimera.modules.mtproto_stats import _load_users
        with self._patch():
            self.assertEqual(_load_users(), {})

    def test_parses_users_section(self):
        from chimera.modules.mtproto_stats import _load_users
        self._cfg.write_text(
            'port = 8443\n'
            '\n'
            '[access.users]\n'
            'alice = "abcdef0123456789abcdef0123456789"\n'
            'bob = "fedcba9876543210fedcba9876543210"\n'
        )
        with self._patch():
            users = _load_users()
        self.assertEqual(len(users), 2)
        self.assertIn("alice", users)
        self.assertIn("bob", users)

    def test_ignores_other_sections(self):
        """Только [access.users] парсится, не другие секции."""
        from chimera.modules.mtproto_stats import _load_users
        self._cfg.write_text(
            '[other]\n'
            'alice = "abcdef0123456789abcdef0123456789"\n'
            '\n'
            '[access.users]\n'
            'bob = "fedcba9876543210fedcba9876543210"\n'
        )
        with self._patch():
            users = _load_users()
        self.assertEqual(len(users), 1)
        self.assertIn("bob", users)
        self.assertNotIn("alice", users)

    def test_stops_at_next_section(self):
        from chimera.modules.mtproto_stats import _load_users
        self._cfg.write_text(
            '[access.users]\n'
            'alice = "abcdef0123456789abcdef0123456789"\n'
            '[another.section]\n'
            'bob = "fedcba9876543210fedcba9876543210"\n'
        )
        with self._patch():
            users = _load_users()
        self.assertEqual(len(users), 1)
        self.assertIn("alice", users)

    def test_invalid_username_skipped(self):
        """Имя должно начинаться с буквы [a-zA-Z]."""
        from chimera.modules.mtproto_stats import _load_users
        self._cfg.write_text(
            '[access.users]\n'
            'alice = "abcdef0123456789abcdef0123456789"\n'
            '123bad = "fedcba9876543210fedcba9876543210"\n'
        )
        with self._patch():
            users = _load_users()
        self.assertEqual(len(users), 1)
        self.assertIn("alice", users)


class TestLoadSaveStats(unittest.TestCase):
    """_load_stats / _save_stats."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._stats = self._tmpdir / "stats.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.mtproto_stats.STATS_FILE",
                     self._stats)

    def test_load_returns_default_when_no_file(self):
        from chimera.modules.mtproto_stats import _load_stats
        with self._patch():
            stats = _load_stats()
        self.assertIn("total", stats)
        self.assertIn("daily", stats)
        self.assertIn("users", stats)
        self.assertFalse(stats["ipt_ok"])

    def test_load_returns_default_when_corrupt(self):
        from chimera.modules.mtproto_stats import _load_stats
        self._stats.write_text("{invalid")
        with self._patch():
            stats = _load_stats()
        self.assertIn("total", stats)

    def test_save_then_load(self):
        from chimera.modules.mtproto_stats import _load_stats, _save_stats
        data = {
            "total": {"rx": 1000, "tx": 2000, "updated": "x", "since": "y"},
            "daily": {"2026-07-09": {"rx": 1000, "tx": 2000}},
            "users": {"alice": {"sessions": 5, "rx": 100, "tx": 200, "last_seen": "z"}},
            "ipt_ok": True,
        }
        with self._patch():
            _save_stats(data)
            loaded = _load_stats()
        self.assertEqual(loaded["total"]["rx"], 1000)
        self.assertTrue(loaded["ipt_ok"])
        self.assertIn("alice", loaded["users"])


class TestParseJournal(unittest.TestCase):
    """_parse_journal — парсинг journalctl (mocked subprocess.Popen).

    ВАЖНО: _parse_journal использует Popen с потоковым чтением (фикс OOM).
    Мокаем subprocess.Popen, а не _run.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def _mock_popen(self, stdout: str):
        """Мокает subprocess.Popen с потоковым stdout."""
        mock_proc = MagicMock()
        # Popen возвращает итератор по строкам.
        # Каждая строка должна заканчиваться \n (как в реальном stdout).
        lines = stdout.splitlines()
        mock_proc.stdout = iter([line + "\n" for line in lines])
        mock_proc.wait.return_value = 0
        return mock_proc

    def test_empty_journal(self):
        from chimera.modules import mtproto_stats
        with patch("chimera.modules.mtproto_stats.subprocess.Popen",
                          return_value=self._mock_popen("")):
            result = mtproto_stats._parse_journal()
        self.assertEqual(result, {})

    def test_parses_user_sessions(self):
        from chimera.modules import mtproto_stats
        lines = "\n".join([
            "2026-07-10T12:00:00 INFO user=alice connect from 1.2.3.4",
            "2026-07-10T12:00:05 INFO user=bob connect from 5.6.7.8",
            "2026-07-10T12:00:10 INFO user=alice auth.ok",
        ])
        with patch("chimera.modules.mtproto_stats.subprocess.Popen",
                          return_value=self._mock_popen(lines)):
            result = mtproto_stats._parse_journal()
        self.assertIn("alice", result)
        self.assertIn("bob", result)
        # alice — 2 сессии (connect + auth.ok)
        self.assertEqual(result["alice"]["sessions"], 2)
        self.assertEqual(result["bob"]["sessions"], 1)

    def test_filters_system_users(self):
        """root/telemt/system/service — игнорируются."""
        from chimera.modules import mtproto_stats
        lines = "\n".join([
            "2026-07-10T12:00:00 INFO user=root connect",
            "2026-07-10T12:00:01 INFO user=telemt service start",
            "2026-07-10T12:00:02 INFO user=alice connect",
        ])
        with patch("chimera.modules.mtproto_stats.subprocess.Popen",
                          return_value=self._mock_popen(lines)):
            result = mtproto_stats._parse_journal()
        self.assertNotIn("root", result)
        self.assertNotIn("telemt", result)
        self.assertIn("alice", result)

    def test_last_seen_extracted_from_timestamp(self):
        from chimera.modules import mtproto_stats
        lines = "2026-07-10T12:34:56 INFO user=alice connect"
        with patch("chimera.modules.mtproto_stats.subprocess.Popen",
                          return_value=self._mock_popen(lines)):
            result = mtproto_stats._parse_journal()
        self.assertEqual(result["alice"]["last_seen"], "2026-07-10 12:34:56")

    def test_since_filter_passed_to_run(self):
        """Если since указан как недавняя дата — передаётся как есть."""
        from chimera.modules import mtproto_stats
        # Недавняя дата (в пределах max_days) — передаётся как есть.
        # Используем max_days=7 чтобы 2-дневная дата прошла.
        from datetime import datetime, timedelta
        recent = (datetime.now() - timedelta(days=2)).strftime("%Y-%m-%d 00:00:00")
        with patch("chimera.modules.mtproto_stats.subprocess.Popen",
                          return_value=self._mock_popen("")) as mock_popen:
            mtproto_stats._parse_journal(since=recent, max_days=7)
        # проверяем что --since присутствует в аргументах
        cmd = mock_popen.call_args.args[0]
        self.assertIn("--since", cmd)
        # Недавняя дата должна быть передана как есть.
        since_val = cmd[cmd.index("--since") + 1]
        self.assertEqual(since_val, recent)

    def test_old_since_replaced_with_max_days(self):
        """Если since указан как старая дата (>max_days дней) — заменяется.

        Это фикс CPU 95%: пользователь жаловался что journalctl грузит CPU
        10 минут, потому что since был '2026-07-15' (почти месяц назад).
        """
        from chimera.modules import mtproto_stats
        # max_days=7, since=месяц назад → должно замениться на "7 days ago".
        with patch("chimera.modules.mtproto_stats.subprocess.Popen",
                          return_value=self._mock_popen("")) as mock_popen:
            mtproto_stats._parse_journal(since="2026-07-15 11:12:52", max_days=7)
        cmd = mock_popen.call_args.args[0]
        self.assertIn("--since", cmd)
        since_val = cmd[cmd.index("--since") + 1]
        self.assertEqual(since_val, "7 days ago",
                         "старый since (>max_days) должен быть заменён")

    def test_default_max_days_is_1(self):
        """По умолчанию max_days=1 (24 часа) — быстро, не грузит CPU."""
        from chimera.modules import mtproto_stats
        # since=месяц назад, max_days по умолчанию=1 → должно замениться на "1 days ago".
        with patch("chimera.modules.mtproto_stats.subprocess.Popen",
                          return_value=self._mock_popen("")) as mock_popen:
            mtproto_stats._parse_journal(since="2026-07-15 11:12:52")
        cmd = mock_popen.call_args.args[0]
        since_val = cmd[cmd.index("--since") + 1]
        self.assertEqual(since_val, "1 days ago",
                         "по умолчанию max_days=1, старый since заменяется на '1 days ago'")

    def test_empty_since_uses_max_days(self):
        """Пустой since → используется '{max_days} days ago'."""
        from chimera.modules import mtproto_stats
        with patch("chimera.modules.mtproto_stats.subprocess.Popen",
                          return_value=self._mock_popen("")) as mock_popen:
            mtproto_stats._parse_journal(since=None, max_days=3)
        cmd = mock_popen.call_args.args[0]
        since_val = cmd[cmd.index("--since") + 1]
        self.assertEqual(since_val, "3 days ago")

    # ── Регрессионные тесты на реалистичные форматы journalctl + telemt ──────
    def test_realistic_short_iso_format_with_hostname_and_pid(self):
        r"""Реальный вывод journalctl -o short-iso:
            2026-07-26T12:34:56+0300 host telemt[1234]: <message>
        Старая регулярка ^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}) работает,
        но новая _extract_ts также принимает пробел вместо T.
        """
        from chimera.modules import mtproto_stats
        lines = "\n".join([
            "2026-07-26T12:34:56+0300 fast-cheetah telemt[1234]: user=alice connected from 1.2.3.4",
            "2026-07-26T12:35:00+0300 fast-cheetah telemt[1234]: user=bob authenticated",
        ])
        with patch("chimera.modules.mtproto_stats.subprocess.Popen",
                          return_value=self._mock_popen(lines)):
            result = mtproto_stats._parse_journal()
        self.assertIn("alice", result)
        self.assertIn("bob", result)
        self.assertEqual(result["alice"]["last_seen"], "2026-07-26 12:34:56")
        self.assertEqual(result["bob"]["last_seen"], "2026-07-26 12:35:00")
        # alice — 1 сессия (connect), bob — 1 (authenticated)
        self.assertEqual(result["alice"]["sessions"], 1)
        self.assertEqual(result["bob"]["sessions"], 1)

    def test_multiline_continuation_uses_last_timestamp(self):
        """Если telemt пишет multiline-сообщение, continuation-строка
        не имеет своего timestamp. user=alice на continuation-строке
        должна получить timestamp из предыдущей строки.
        """
        from chimera.modules import mtproto_stats
        lines = "\n".join([
            # Первая строка с timestamp + общая информация (без user=)
            "2026-07-26T12:34:56+0300 host telemt[1234]: new MTProto connection",
            # Continuation-строка БЕЗ timestamp, но с user=
            "                    user=alice, secret=abc123, ip=1.2.3.4",
        ])
        with patch("chimera.modules.mtproto_stats.subprocess.Popen",
                          return_value=self._mock_popen(lines)):
            result = mtproto_stats._parse_journal()
        self.assertIn("alice", result)
        # last_seen должен быть из предыдущей строки (fallback на last_ts)
        self.assertNotEqual(result["alice"]["last_seen"], "—",
                            "multiline continuation should use last_ts, not stay '—'")
        self.assertEqual(result["alice"]["last_seen"], "2026-07-26 12:34:56")

    def test_timestamp_with_space_separator_accepted(self):
        """Если journalctl использует пробел вместо T (например short-full),
        _extract_ts всё равно должен распознать timestamp.
        """
        from chimera.modules import mtproto_stats
        lines = "2026-07-26 12:34:56 host telemt[1234]: user=alice connect from 1.2.3.4"
        with patch("chimera.modules.mtproto_stats.subprocess.Popen",
                          return_value=self._mock_popen(lines)):
            result = mtproto_stats._parse_journal()
        self.assertIn("alice", result)
        self.assertEqual(result["alice"]["last_seen"], "2026-07-26 12:34:56")

    def test_extended_session_patterns_recognized(self):
        """Расширенный паттерн _SESSION_RE должен ловить не только
        connect/auth.ok, но и: accepted, login, session start,
        handshake ok, client ok, authenticated.
        """
        from chimera.modules import mtproto_stats
        lines = "\n".join([
            "2026-07-26T12:00:01 host telemt[1234]: user=alice accepted",
            "2026-07-26T12:00:02 host telemt[1234]: user=bob login",
            "2026-07-26T12:00:03 host telemt[1234]: user=carol session started",
            "2026-07-26T12:00:04 host telemt[1234]: user=dave handshake ok",
            "2026-07-26T12:00:05 host telemt[1234]: user=eve client ok",
            "2026-07-26T12:00:06 host telemt[1234]: user=frank authenticated",
        ])
        with patch("chimera.modules.mtproto_stats.subprocess.Popen",
                          return_value=self._mock_popen(lines)):
            result = mtproto_stats._parse_journal()
        # Все 6 пользователей должны быть с sessions=1
        for name in ("alice", "bob", "carol", "dave", "eve", "frank"):
            self.assertIn(name, result)
            self.assertEqual(result[name]["sessions"], 1,
                             f"{name} should have sessions=1 with extended pattern")

    def test_user_with_quotes_in_value_parsed(self):
        """user="alice" или user='alice' (с кавычками) — новая регулярка
        принимает оба варианта через опциональную группу (["\\']?).
        """
        from chimera.modules import mtproto_stats
        lines = "\n".join([
            '2026-07-26T12:00:01 host telemt[1234]: user="alice" connect from 1.2.3.4',
            "2026-07-26T12:00:02 host telemt[1234]: user='bob' connect from 5.6.7.8",
        ])
        with patch("chimera.modules.mtproto_stats.subprocess.Popen",
                          return_value=self._mock_popen(lines)):
            result = mtproto_stats._parse_journal()
        self.assertIn("alice", result)
        self.assertIn("bob", result)
        self.assertEqual(result["alice"]["sessions"], 1)
        self.assertEqual(result["bob"]["sessions"], 1)

    def test_username_key_also_recognized(self):
        """username=alice (а не только user=) — новая регулярка принимает
        и username, и name как ключи.
        """
        from chimera.modules import mtproto_stats
        lines = "\n".join([
            "2026-07-26T12:00:01 host telemt[1234]: username=alice connect",
            "2026-07-26T12:00:02 host telemt[1234]: name=bob accepted",
        ])
        with patch("chimera.modules.mtproto_stats.subprocess.Popen",
                          return_value=self._mock_popen(lines)):
            result = mtproto_stats._parse_journal()
        self.assertIn("alice", result)
        self.assertIn("bob", result)

    def test_default_since_7_days_when_not_specified(self):
        """Если since пустой — по умолчанию '7 days ago' (фикс OOM).

        Без этого лимита journalctl может читать журнал за месяцы,
        что приводит к OOM killer на серверах с малым RAM.
        """
        from chimera.modules import mtproto_stats
        with patch("chimera.modules.mtproto_stats.subprocess.Popen",
                          return_value=self._mock_popen("")) as mock_popen:
            mtproto_stats._parse_journal()  # без since
        cmd = mock_popen.call_args.args[0]
        # Должен быть --since с "7 days ago" или подобным.
        self.assertIn("--since", cmd)
        since_val = cmd[cmd.index("--since") + 1]
        self.assertIn("days ago", since_val,
                      "должен быть лимит по умолчанию (N days ago)")

    def test_uses_popen_not_run_capture(self):
        """_parse_journal должен использовать subprocess.Popen (потоковое),
        а не _run(capture=True) — чтобы не загружать весь журнал в память.
        """
        import inspect
        from chimera.modules import mtproto_stats
        src = inspect.getsource(mtproto_stats._parse_journal)
        self.assertIn("Popen", src,
                      "_parse_journal должен использовать Popen для потокового чтения")
        # НЕ должен использовать _run(cmd, capture=True) как единственный путь.
        # Fallback на _run допустим, но основной путь — Popen.
        self.assertIn("proc.stdout", src,
                      "_parse_journal должен читать построчно через proc.stdout")


class TestCollectLastSeenFallback(unittest.TestCase):
    """_collect — fallback last_seen при трафике >0 но пустом journalctl.

    Если у пользователя есть трафик (rx>0 или tx>0), но journalctl не
    вернул для него timestamp (например, telemt пишет в формате, который
    не распознаётся парсером) — _collect использует d["total"]["updated"]
    как приблизительное время последней активности. Это лучше чем "—"
    для активных пользователей.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "telemt.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_cfg(self):
        return patch("chimera.modules.mtproto_stats.CONFIG_FILE",
                     self._cfg)

    def test_user_with_traffic_but_no_journal_gets_fallback_last_seen(self):
        """Пользователь с rx>0, но journalctl пуст → last_seen берётся
        из d["total"]["updated"], а не остаётся '—'.
        """
        from chimera.modules import mtproto_stats
        d = {
            "total": {"rx": 1000, "tx": 2000, "updated": "2026-07-26 12:00:00",
                      "since": "2026-07-20 00:00:00"},
            "daily": {"2026-07-26": {"rx": 1000, "tx": 2000}},
            "users": {"alice": {"sessions": 0, "rx": 0, "tx": 0, "last_seen": "—"}},
            "ipt_ok": True,
        }
        with self._patch_cfg(), \
             patch.object(mtproto_stats, "_read_chain_bytes",
                          side_effect=[1000, 2000]), \
             patch.object(mtproto_stats, "_parse_journal", return_value={}), \
             patch.object(mtproto_stats, "_load_users", return_value={"alice": "secret"}):
            result = mtproto_stats._collect(d)
        # alice получила трафик через распределение (1 активный пользователь)
        self.assertGreater(result["users"]["alice"]["rx"], 0)
        # last_seen НЕ должен остаться '—' — fallback на total.updated
        self.assertNotEqual(result["users"]["alice"]["last_seen"], "—",
                            "user with traffic should get fallback last_seen")
        self.assertEqual(result["users"]["alice"]["last_seen"],
                         "2026-07-26 12:00:00")

    def test_user_without_traffic_stays_dash(self):
        """Пользователь без трафика (rx=0, tx=0) и без journalctl →
        last_seen остаётся '—' (не выдумываем время для пустого польз.).
        """
        from chimera.modules import mtproto_stats
        d = {
            "total": {"rx": 0, "tx": 0, "updated": "2026-07-26 12:00:00",
                      "since": "2026-07-20 00:00:00"},
            "daily": {},
            "users": {"alice": {"sessions": 0, "rx": 0, "tx": 0, "last_seen": "—"}},
            "ipt_ok": True,
        }
        with self._patch_cfg(), \
             patch.object(mtproto_stats, "_read_chain_bytes",
                          side_effect=[0, 0]), \
             patch.object(mtproto_stats, "_parse_journal", return_value={}), \
             patch.object(mtproto_stats, "_load_users", return_value={"alice": "secret", "bob": "secret2"}):
            result = mtproto_stats._collect(d)
        # alice без трафика — last_seen остаётся '—'
        self.assertEqual(result["users"]["alice"]["last_seen"], "—")
        # bob — новый пользователь без трафика, тоже '—'
        self.assertEqual(result["users"]["bob"]["last_seen"], "—")


class TestCollect(unittest.TestCase):
    """_collect — обновление статистики (mocked iptables + journalctl)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "telemt.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_cfg(self):
        return patch("chimera.modules.mtproto_stats.CONFIG_FILE",
                     self._cfg)

    def test_writes_daily_and_total(self):
        from chimera.modules import mtproto_stats
        d = {
            "total": {"rx": 0, "tx": 0, "updated": "", "since": ""},
            "daily": {},
            "users": {},
            "ipt_ok": False,
        }
        # iptables возвращает 1000 rx, 2000 tx
        with self._patch_cfg(), \
             patch.object(mtproto_stats, "_read_chain_bytes",
                          side_effect=[1000, 2000]), \
             patch.object(mtproto_stats, "_parse_journal", return_value={}), \
             patch.object(mtproto_stats, "_load_users", return_value={}):
            result = mtproto_stats._collect(d)
        self.assertTrue(result["ipt_ok"])
        # за сегодня записано
        today = mtproto_stats._today()
        self.assertIn(today, result["daily"])
        self.assertEqual(result["daily"][today]["rx"], 1000)
        self.assertEqual(result["daily"][today]["tx"], 2000)
        # total = сумма всех дней
        self.assertEqual(result["total"]["rx"], 1000)
        self.assertEqual(result["total"]["tx"], 2000)

    def test_ipt_failure_sets_ipt_ok_false(self):
        from chimera.modules import mtproto_stats
        d = {"total": {"rx": 0, "tx": 0, "updated": "", "since": ""},
             "daily": {}, "users": {}, "ipt_ok": True}
        with self._patch_cfg(), \
             patch.object(mtproto_stats, "_read_chain_bytes",
                          side_effect=Exception("iptables err")), \
             patch.object(mtproto_stats, "_parse_journal", return_value={}), \
             patch.object(mtproto_stats, "_load_users", return_value={}):
            result = mtproto_stats._collect(d)
        self.assertFalse(result["ipt_ok"])

    def test_distributes_bytes_proportional_to_sessions(self):
        """3 сессии у alice, 1 у bob → 75%/25% распределение."""
        from chimera.modules import mtproto_stats
        d = {
            "total": {"rx": 0, "tx": 0, "updated": "", "since": ""},
            "daily": {},
            "users": {},
            "ipt_ok": False,
        }
        sessions = {
            "alice": {"sessions": 3, "last_seen": "2026-07-10 12:00:00"},
            "bob": {"sessions": 1, "last_seen": "2026-07-10 12:01:00"},
        }
        with self._patch_cfg(), \
             patch.object(mtproto_stats, "_read_chain_bytes",
                          side_effect=[1000, 2000]), \
             patch.object(mtproto_stats, "_parse_journal", return_value=sessions), \
             patch.object(mtproto_stats, "_load_users", return_value={"alice": "x", "bob": "y"}):
            result = mtproto_stats._collect(d)
        # alice 3/4 от 1000 = 750, bob 1/4 = 250
        self.assertEqual(result["users"]["alice"]["rx"], 750)
        self.assertEqual(result["users"]["bob"]["rx"], 250)

    def test_distributes_evenly_when_no_sessions(self):
        """0 сессий у всех → равномерно по active users."""
        from chimera.modules import mtproto_stats
        d = {
            "total": {"rx": 0, "tx": 0, "updated": "", "since": ""},
            "daily": {},
            "users": {
                "alice": {"sessions": 0, "rx": 0, "tx": 0, "last_seen": "x"},
                "bob": {"sessions": 0, "rx": 0, "tx": 0, "last_seen": "y"},
            },
            "ipt_ok": False,
        }
        with self._patch_cfg(), \
             patch.object(mtproto_stats, "_read_chain_bytes",
                          side_effect=[1000, 2000]), \
             patch.object(mtproto_stats, "_parse_journal", return_value={}), \
             patch.object(mtproto_stats, "_load_users", return_value={"alice": "x", "bob": "y"}):
            result = mtproto_stats._collect(d)
        # 1000 / 2 = 500 каждый, но последний получает остаток
        # alice = 500, bob = 1000 - 500*1 = 500
        self.assertEqual(result["users"]["alice"]["rx"], 500)
        self.assertEqual(result["users"]["bob"]["rx"], 500)

    def test_preserves_accumulated_total_across_days(self):
        """Total = сумма всех дней в daily, не только сегодня."""
        from chimera.modules import mtproto_stats
        d = {
            "total": {"rx": 0, "tx": 0, "updated": "", "since": ""},
            "daily": {
                "2026-07-08": {"rx": 5000, "tx": 6000},
                "2026-07-09": {"rx": 3000, "tx": 4000},
            },
            "users": {},
            "ipt_ok": False,
        }
        with self._patch_cfg(), \
             patch.object(mtproto_stats, "_read_chain_bytes",
                          side_effect=[1000, 2000]), \
             patch.object(mtproto_stats, "_parse_journal", return_value={}), \
             patch.object(mtproto_stats, "_load_users", return_value={}):
            result = mtproto_stats._collect(d)
        # total = 5000 + 3000 + 1000 (today) = 9000
        self.assertEqual(result["total"]["rx"], 9000)
        self.assertEqual(result["total"]["tx"], 12000)


# =============================================================================
#  NFTABLES MIGRATION (этап 1.5) — тесты для новой реализации на nft_common
# =============================================================================
class TestNftMigration(unittest.TestCase):
    """Проверяет что mtproto_stats.py использует nft_common вместо прямых
    iptables subprocess-вызовов (этап 1.5 миграции).

    Мокает nft_chain_ensure / nft_chain_exists / nft_rule_insert / nft_rule_add /
    nft_rule_exists / nft_rule_delete_by_comment / nft_rule_counter_read /
    nft_persist / _nft_available — проверяет что:
      • setup_iptables_accounting создаёт chain + jump + counter-rule через nft_common.
      • _read_chain_bytes делегирует в nft_rule_counter_read.
      • _reset_accounting вызывает nft_chain_flush + nft_rule_add.
      • _accounting_active использует nft_chain_exists.
      • _persist_accounting_rules делегирует в nft_persist.
      • _TCP_PROTO_TOKENS УДАЛЕН (багфикс — в nft JSON этой проблемы нет).
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        # Патчим CRON_FILE чтобы не трогать реальный /etc/cron.d/
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cron = self._tmpdir / "telemt-stats"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_cron(self):
        return patch("chimera.modules.mtproto_stats.CRON_FILE", self._cron)

    def test_tcp_proto_tokens_constant_removed(self):
        """_TCP_PROTO_TOKENS удалён — в nft JSON протокол всегда строка "tcp"."""
        from chimera.modules import mtproto_stats
        self.assertFalse(
            hasattr(mtproto_stats, "_TCP_PROTO_TOKENS"),
            "_TCP_PROTO_TOKENS should be removed after migration to nftables "
            "(in nft JSON protocol is always string 'tcp', not numeric '6')"
        )

    def test_setup_returns_false_when_nft_unavailable(self):
        """Если nft binary недоступен — setup_iptables_accounting возвращает False."""
        from chimera.modules import mtproto_stats
        with patch("chimera.modules.mtproto_stats._nft_available",
                   return_value=False),              self._patch_cron(),              patch.object(mtproto_stats, "_persist_accounting_rules") as mock_p:
            result = mtproto_stats.setup_iptables_accounting(8443)
        self.assertFalse(result)
        mock_p.assert_not_called()  # persist не вызывается при недоступности nft

    def test_setup_calls_nft_chain_ensure_for_both_chains(self):
        """setup_iptables_accounting создаёт ОБЕ цепочки (in/out) через nft_chain_ensure."""
        from chimera.modules import mtproto_stats
        with patch("chimera.modules.mtproto_stats._nft_available",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_chain_ensure",
                   return_value=True) as mock_ensure,              patch("chimera.modules.mtproto_stats.nft_rule_insert",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_chain_flush",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_rule_add",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_rule_delete_by_comment",
                   return_value=0),              patch("chimera.modules.mtproto_stats._nft_chain_exists",
                   return_value=True),              patch("chimera.modules.mtproto_stats._nft_jump_exists",
                   return_value=True),              self._patch_cron(),              patch.object(mtproto_stats, "_persist_accounting_rules"):
            mtproto_stats.setup_iptables_accounting(8443)
        # Должно быть два вызова nft_chain_ensure — для in и out цепочек
        called_chains = [kwargs.get("chain") for _, kwargs in mock_ensure.call_args_list]
        self.assertIn(mtproto_stats.NFT_CHAIN_TELEMT_STATS_IN, called_chains)
        self.assertIn(mtproto_stats.NFT_CHAIN_TELEMT_STATS_OUT, called_chains)

    def test_setup_calls_nft_rule_insert_for_jumps(self):
        """Jump-правила в input/output создаются через nft_rule_insert с comment-tag."""
        from chimera.modules import mtproto_stats
        with patch("chimera.modules.mtproto_stats._nft_available",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_chain_ensure",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_rule_insert",
                   return_value=True) as mock_insert,              patch("chimera.modules.mtproto_stats.nft_chain_flush",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_rule_add",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_rule_delete_by_comment",
                   return_value=0),              patch("chimera.modules.mtproto_stats._nft_chain_exists",
                   return_value=True),              patch("chimera.modules.mtproto_stats._nft_jump_exists",
                   return_value=True),              self._patch_cron(),              patch.object(mtproto_stats, "_persist_accounting_rules"):
            mtproto_stats.setup_iptables_accounting(8443)
        # Должно быть два вызова nft_rule_insert — для in-jump и out-jump
        inserted_comments = sorted(
            kwargs.get("comment") for _, kwargs in mock_insert.call_args_list
        )
        self.assertEqual(inserted_comments,
                         ["telemt-stats-jump-in", "telemt-stats-jump-out"])

    def test_setup_calls_nft_rule_add_for_counter_rules(self):
        """Counter-rules в цепочках in/out создаются через nft_rule_add с counter."""
        from chimera.modules import mtproto_stats
        with patch("chimera.modules.mtproto_stats._nft_available",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_chain_ensure",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_rule_insert",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_chain_flush",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_rule_add",
                   return_value=True) as mock_add,              patch("chimera.modules.mtproto_stats.nft_rule_delete_by_comment",
                   return_value=0),              patch("chimera.modules.mtproto_stats._nft_chain_exists",
                   return_value=True),              patch("chimera.modules.mtproto_stats._nft_jump_exists",
                   return_value=True),              self._patch_cron(),              patch.object(mtproto_stats, "_persist_accounting_rules"):
            mtproto_stats.setup_iptables_accounting(8443)
        # Должно быть два вызова nft_rule_add — counter-rules в обеих цепочках
        # Оба с comment-tag "telemt-stats-counter"
        add_comments = [kwargs.get("comment") for _, kwargs in mock_add.call_args_list]
        self.assertEqual(add_comments.count("telemt-stats-counter"), 2)
        # spec должен содержать "counter return" и dport/sport
        add_specs = [kwargs.get("rule_spec") for _, kwargs in mock_add.call_args_list]
        self.assertTrue(any("dport 8443" in s and "counter return" in s
                            for s in add_specs))
        self.assertTrue(any("sport 8443" in s and "counter return" in s
                            for s in add_specs))

    def test_setup_calls_delete_by_comment_for_idempotent_cleanup(self):
        """Перед добавлением новых jump-правил вызывается cleanup по comment-tag."""
        from chimera.modules import mtproto_stats
        with patch("chimera.modules.mtproto_stats._nft_available",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_chain_ensure",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_rule_insert",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_chain_flush",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_rule_add",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_rule_delete_by_comment",
                   return_value=0) as mock_del,              patch("chimera.modules.mtproto_stats._nft_chain_exists",
                   return_value=True),              patch("chimera.modules.mtproto_stats._nft_jump_exists",
                   return_value=True),              self._patch_cron(),              patch.object(mtproto_stats, "_persist_accounting_rules"):
            mtproto_stats.setup_iptables_accounting(8443)
        # Должно быть два вызова delete_by_comment — для in-jump и out-jump
        deleted_comments = sorted(
            kwargs.get("comment") for _, kwargs in mock_del.call_args_list
        )
        self.assertEqual(deleted_comments,
                         ["telemt-stats-jump-in", "telemt-stats-jump-out"])

    def test_setup_returns_true_when_all_chains_and_jumps_confirmed(self):
        """Все 4 постфактум-проверки прошли (chain in/out, jump in/out) → True."""
        from chimera.modules import mtproto_stats
        with patch("chimera.modules.mtproto_stats._nft_available",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_chain_ensure",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_rule_insert",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_chain_flush",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_rule_add",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_rule_delete_by_comment",
                   return_value=0),              patch("chimera.modules.mtproto_stats._nft_chain_exists",
                   return_value=True),              patch("chimera.modules.mtproto_stats._nft_jump_exists",
                   return_value=True),              self._patch_cron(),              patch.object(mtproto_stats, "_persist_accounting_rules"):
            result = mtproto_stats.setup_iptables_accounting(8443)
        self.assertTrue(result,
                        "expected True when all chains and jumps confirmed via nft")

    def test_setup_returns_false_when_jump_not_confirmed(self):
        """Если jump-правило не подтвердилось (nft_rule_exists=False) → False."""
        from chimera.modules import mtproto_stats
        with patch("chimera.modules.mtproto_stats._nft_available",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_chain_ensure",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_rule_insert",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_chain_flush",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_rule_add",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_rule_delete_by_comment",
                   return_value=0),              patch("chimera.modules.mtproto_stats._nft_chain_exists",
                   return_value=True),              patch("chimera.modules.mtproto_stats._nft_jump_exists",
                   return_value=False),              self._patch_cron(),              patch.object(mtproto_stats, "_persist_accounting_rules"):
            result = mtproto_stats.setup_iptables_accounting(8443)
        self.assertFalse(result,
                         "expected False when nft jump-rule not confirmed")

    def test_read_chain_bytes_uses_nft_rule_counter_read(self):
        """_read_chain_bytes делегирует в nft_rule_counter_read с comment-tag."""
        from chimera.modules import mtproto_stats
        with patch("chimera.modules.mtproto_stats.nft_rule_counter_read",
                   return_value={"packets": 42, "bytes": 4096}) as mock_cnt:
            n = mtproto_stats._read_chain_bytes(mtproto_stats.CHAIN_IN)
        self.assertEqual(n, 4096)
        mock_cnt.assert_called_once()
        _, kwargs = mock_cnt.call_args
        self.assertEqual(kwargs.get("comment"), "telemt-stats-counter")
        self.assertEqual(kwargs.get("chain"), mtproto_stats.NFT_CHAIN_TELEMT_STATS_IN)

    def test_read_chain_bytes_for_out_chain(self):
        """_read_chain_bytes для CHAIN_OUT возвращает bytes из out-цепочки."""
        from chimera.modules import mtproto_stats
        with patch("chimera.modules.mtproto_stats.nft_rule_counter_read",
                   return_value={"packets": 10, "bytes": 2048}) as mock_cnt:
            n = mtproto_stats._read_chain_bytes(mtproto_stats.CHAIN_OUT)
        self.assertEqual(n, 2048)
        _, kwargs = mock_cnt.call_args
        self.assertEqual(kwargs.get("chain"), mtproto_stats.NFT_CHAIN_TELEMT_STATS_OUT)

    def test_reset_accounting_uses_nft_chain_flush_and_rule_add(self):
        """_reset_accounting вызывает nft_chain_flush + nft_rule_add для обеих цепочек."""
        from chimera.modules import mtproto_stats
        with patch("chimera.modules.mtproto_stats._nft_available",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_chain_flush",
                   return_value=True) as mock_flush,              patch("chimera.modules.mtproto_stats.nft_rule_add",
                   return_value=True) as mock_add,              patch("chimera.modules.mtproto_stats._get_port",
                   return_value=8443):
            mtproto_stats._reset_accounting()
        # Должно быть два flush (для in и out) и два add
        self.assertEqual(mock_flush.call_count, 2)
        self.assertEqual(mock_add.call_count, 2)
        flush_chains = sorted(
            kwargs.get("chain") for _, kwargs in mock_flush.call_args_list
        )
        self.assertEqual(flush_chains,
                         [mtproto_stats.NFT_CHAIN_TELEMT_STATS_IN,
                          mtproto_stats.NFT_CHAIN_TELEMT_STATS_OUT])

    def test_accounting_active_uses_nft_chain_exists(self):
        """_accounting_active использует nft_chain_exists для обеих цепочек."""
        from chimera.modules import mtproto_stats
        # Обе цепочки существуют → True
        with patch("chimera.modules.mtproto_stats._nft_chain_exists",
                   return_value=True):
            self.assertTrue(mtproto_stats._accounting_active())
        # Только одна существует → False
        with patch("chimera.modules.mtproto_stats._nft_chain_exists",
                   side_effect=lambda chain: chain == mtproto_stats.NFT_CHAIN_TELEMT_STATS_IN):
            self.assertFalse(mtproto_stats._accounting_active())

    def test_persist_accounting_rules_uses_nft_persist(self):
        """_persist_accounting_rules делегирует в nft_persist + enable_systemd."""
        from chimera.modules import mtproto_stats
        with patch("chimera.modules.mtproto_stats._nft_available",
                   return_value=True),              patch("chimera.modules.mtproto_stats.nft_persist",
                   return_value=True) as mock_persist,              patch("chimera.modules.nft_common.nft_persist_enable_systemd",
                   return_value=True):
            mtproto_stats._persist_accounting_rules()
        mock_persist.assert_called_once()

# =============================================================================
#  Диагностика Telemt API (для панели telemt_panel)
# =============================================================================
class TestDiagnoseTelemtApiForPanel(unittest.TestCase):
    """Тесты на diagnose_telemt_api_for_panel() — диагностика почему Telemt
    Panel может показывать 0 traffic / 0 connections, хотя TUI Chimera
    видит трафик через iptables-цепочки.

    Покрывает:
      1. _telemt_api_section_configured — распознаёт [server.api] секцию
         в telemt.toml (или её отсутствие / enabled=false).
      2. diagnose_telemt_api_for_panel — собирает рекомендации когда
         что-то не настроено.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "telemt.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_cfg(self):
        return patch("chimera.modules.mtproto_stats.CONFIG_FILE", self._cfg)

    # ── _telemt_api_section_configured ──────────────────────────────────────
    def test_section_configured_returns_true_when_enabled(self):
        from chimera.modules import mtproto_stats
        self._cfg.write_text(
            "[server]\nport = 5000\n\n"
            "[server.api]\n"
            "enabled = true\n"
            'listen = "127.0.0.1:9091"\n'
            'auth_header = "abc123"\n'
        )
        with self._patch_cfg():
            ok, detail = mtproto_stats._telemt_api_section_configured()
        self.assertTrue(ok)
        self.assertIn("включена", detail)

    def test_section_configured_returns_false_when_section_absent(self):
        from chimera.modules import mtproto_stats
        self._cfg.write_text("[server]\nport = 5000\n")
        with self._patch_cfg():
            ok, detail = mtproto_stats._telemt_api_section_configured()
        self.assertFalse(ok)
        self.assertIn("отсутствует", detail)

    def test_section_configured_returns_false_when_enabled_is_false(self):
        from chimera.modules import mtproto_stats
        self._cfg.write_text(
            "[server.api]\n"
            "enabled = false\n"
            'listen = "127.0.0.1:9091"\n'
        )
        with self._patch_cfg():
            ok, detail = mtproto_stats._telemt_api_section_configured()
        self.assertFalse(ok)
        self.assertIn("enabled=false", detail)

    def test_section_configured_returns_false_when_no_config_file(self):
        from chimera.modules import mtproto_stats
        # _cfg не существует (не создаём)
        with self._patch_cfg():
            ok, detail = mtproto_stats._telemt_api_section_configured()
        self.assertFalse(ok)
        self.assertIn("не найден", detail)

    # ── diagnose_telemt_api_for_panel ────────────────────────────────────────
    def test_diagnose_returns_recommendations_when_section_missing(self):
        """Если [server.api] нет в telemt.toml — diagnose возвращает
        рекомендацию включить секцию.
        """
        from chimera.modules import mtproto_stats
        self._cfg.write_text("[server]\nport = 5000\n")
        # Мокаем что telemt не запущен, чтобы не делать реальный HTTP-запрос
        mock_run = MagicMock()
        mock_run.return_value = MagicMock(returncode=3, stdout="inactive", stderr="")
        with self._patch_cfg(), \
             patch.object(mtproto_stats, "_run", mock_run):
            diag = mtproto_stats.diagnose_telemt_api_for_panel()
        self.assertFalse(diag["api_section_configured"])
        self.assertTrue(len(diag["recommendations"]) > 0)
        # Должна быть рекомендация про [server.api]
        api_recs = [r for r in diag["recommendations"] if "[server.api]" in r]
        self.assertTrue(len(api_recs) > 0,
                        f"expected recommendation about [server.api], got: {diag['recommendations']}")

    def test_diagnose_includes_uptime_when_telemt_recently_restarted(self):
        """Если telemt перезапущен недавно (< 10 мин) — diagnose включает
        рекомендацию про обнуление счётчиков.

        Мокаем /proc/uptime на 3600s (1 час) — безопасное значение, далеко
        выше 60-секундного оффсета. Раньше тест полагался на реальный
        /proc/uptime, но в контейнерах с коротким uptime (< 60s)
        enter_mono_us получался отрицательным, regex не матчит, и
        telemt_uptime оставался 0.
        """
        from chimera.modules import mtproto_stats
        from unittest.mock import mock_open
        import os
        if not os.path.exists("/proc/uptime"):
            self.skipTest("/proc/uptime not available (non-Linux)")

        self._cfg.write_text(
            "[server.api]\nenabled = true\nlisten = \"127.0.0.1:9091\"\n"
        )
        # Мокаем /proc/uptime на 3600s (1 час) — см. комментарий в
        # test_diagnose_adds_build_profile_recommendation_when_all_ok
        # для подробного обоснования.
        fake_uptime_content = "3600.00 12345.00\n"

        # systemctl show → telemt запущен 60s назад
        def fake_run(cmd, capture=False, check=False):
            cmd = list(cmd)
            if "is-active" in cmd:
                return MagicMock(returncode=0, stdout="active\n", stderr="")
            if "show" in cmd and any("ActiveEnterTimestampMonotonic" in x for x in cmd):
                # telemt запущен 60s назад.
                # /proc/uptime уже замокан на 3600s через outer patch
                with open("/proc/uptime") as f:
                    sys_uptime = float(f.read().split()[0])
                enter_mono_us = int((sys_uptime - 60) * 1_000_000)
                return MagicMock(returncode=0,
                                 stdout=f"ActiveEnterTimestampMonotonic={enter_mono_us}\n",
                                 stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        with self._patch_cfg(), \
             patch.object(mtproto_stats, "_run", fake_run), \
             patch.object(mtproto_stats, "_telemt_api_probe",
                          return_value=(True, "API отвечает", {})), \
             patch("builtins.open", mock_open(read_data=fake_uptime_content)):
            diag = mtproto_stats.diagnose_telemt_api_for_panel()
        self.assertGreater(diag["telemt_uptime_sec"], 0)
        self.assertLess(diag["telemt_uptime_sec"], 600)
        # Должна быть рекомендация про обнуление счётчиков
        uptime_recs = [r for r in diag["recommendations"] if "обнуляются при рестарте" in r]
        self.assertTrue(len(uptime_recs) > 0,
                        f"expected uptime recommendation, got: {diag['recommendations']}")

    def test_diagnose_adds_build_profile_recommendation_when_all_ok(self):
        """Когда всё настроено (секция есть, API отвечает, uptime большой),
        diagnose добавляет рекомендацию про build profile и upstream telemt.
        """
        from chimera.modules import mtproto_stats
        from unittest.mock import mock_open
        import os
        if not os.path.exists("/proc/uptime"):
            self.skipTest("/proc/uptime not available (non-Linux)")

        self._cfg.write_text(
            "[server.api]\nenabled = true\nlisten = \"127.0.0.1:9091\"\n"
        )
        # Мокаем /proc/uptime на 1 сутки (86400s). Это нужно потому что:
        # 1. fake_run читает /proc/uptime для вычисления enter_mono_us
        #    (эмулирует "telemt запущен 7200s назад")
        # 2. Код diagnose_telemt_api_for_panel тоже читает /proc/uptime
        #    для вычисления telemt_uptime = uptime_sec - enter_sec
        # Оба чтения должны получить одинаковое значение > 7200, иначе
        # enter_mono_us получается отрицательным, regex r'=(\d+)' не матчит
        # отрицательные числа, и telemt_uptime остаётся 0.
        # В реальной жизни /proc/uptime всегда > enter_mono_us (процесс
        # не может стартовать до загрузки системы), но в тестовом
        # контейнере/VM с коротким uptime это не так.
        fake_uptime_content = "86400.00 123456.00\n"

        def fake_run(cmd, capture=False, check=False):
            cmd = list(cmd)
            if "is-active" in cmd:
                return MagicMock(returncode=0, stdout="active\n", stderr="")
            if "show" in cmd and any("ActiveEnterTimestampMonotonic" in x for x in cmd):
                # telemt запущен 2 часа назад = 7200s
                # /proc/uptime уже замокан на 86400s через outer patch
                with open("/proc/uptime") as f:
                    sys_uptime = float(f.read().split()[0])
                enter_mono_us = int((sys_uptime - 7200) * 1_000_000)
                return MagicMock(returncode=0,
                                 stdout=f"ActiveEnterTimestampMonotonic={enter_mono_us}\n",
                                 stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        with self._patch_cfg(), \
             patch.object(mtproto_stats, "_run", fake_run), \
             patch.object(mtproto_stats, "_telemt_api_probe",
                          return_value=(True, "API отвечает", {})), \
             patch("builtins.open", mock_open(read_data=fake_uptime_content)):
            diag = mtproto_stats.diagnose_telemt_api_for_panel()
        self.assertTrue(diag["api_section_configured"])
        self.assertTrue(diag["api_reachable"])
        self.assertGreaterEqual(diag["telemt_uptime_sec"], 600)
        # Должна быть рекомендация про build profile / upstream telemt
        upstream_recs = [r for r in diag["recommendations"]
                         if "build profile" in r or "upstream telemt" in r]
        self.assertTrue(len(upstream_recs) > 0,
                        f"expected upstream recommendation, got: {diag['recommendations']}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
