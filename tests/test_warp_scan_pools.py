#!/usr/bin/env python3
"""
tests/test_warp_scan_pools.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты автообновления пулов сканирования WARP из warpscout
(chimera/modules/warp_scan_pools.py).

Покрывает:
  1. _parse_pools_go — happy path (только блок poolsV4; poolsV6 и
     masquePoolsV4 НЕ подхватываются), переименованный блок → ValueError,
     мусорные/слишком широкие/узкие/v6-пулы пропускаются, дедупликация,
     границы числа пулов (MIN/MAX).
  2. _fetch_pools_go — зеркала до первого валидного; файл без poolsV4
     пропускается; все мертвы → None.
  3. Кэш и слияние — дефолты, get_scan_ranges() без сети (пулы апстрима
     вперёд + статические CF довеском, дедуп), scan_pools_auto().
  4. sync_scan_pools — успех (added/removed), сеть недоступна (кэш не
     тронут), парс провалился (last_error, кэш не тронут).
  5. cron — _manage_cron ставит/снимает файл, cron_installed().
  6. ensure_pools_ready — auto выкл → ничего; пустой/протухший кэш →
     синк + восстановление cron; свежий кэш → тишина; сбой синка — тихо.
  7. Меню — рендер/выход, «s» синхронизирует, «a» переключает auto
     (снимает cron), «r» сбрасывает пулы к статике.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import warp_scan_pools as wsp
from chimera.modules import warp as warp_mod


# ── Фикстуры ──────────────────────────────────────────────────────────────
POOLS_GO_SAMPLE = """package main

var poolsV4 = []netip.Prefix{
\tnetip.MustParsePrefix("8.6.112.0/24"),
\tnetip.MustParsePrefix("8.34.70.0/24"),
\tnetip.MustParsePrefix("162.159.192.0/24"),
\tnetip.MustParsePrefix("162.159.195.0/24"),
\tnetip.MustParsePrefix("188.114.96.0/24"),
}

var poolsV6 = []netip.Prefix{
\tnetip.MustParsePrefix("2606:4700:d0::/48"),
}

var masquePoolsV4 = []netip.Prefix{
\tnetip.MustParsePrefix("162.159.193.0/24"),
}

var pools = poolsV4
"""

POOLS_SAMPLE_EXPECTED = [
    "8.6.112.0/24", "8.34.70.0/24", "162.159.192.0/24",
    "162.159.195.0/24", "188.114.96.0/24",
]


class _TmpPaths(unittest.TestCase):
    """Подменяет CACHE_FILE/CRON_FILE на временные файлы."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self.tmp.name) / "pools_cache.json"
        self.cron = Path(self.tmp.name) / "warp-scan-pools-sync"
        self.patches = [
            patch.object(wsp, "CACHE_FILE", self.cache),
            patch.object(wsp, "CRON_FILE", self.cron),
        ]
        for p in self.patches:
            p.start()
        self._quiet = patch.object(wsp, "warn"), patch.object(wsp, "info"), \
            patch.object(wsp, "success")
        for p in self._quiet:
            p.start()

    def tearDown(self):
        for p in self.patches + list(self._quiet):
            p.stop()
        self.tmp.cleanup()


# ═════════════════════════════════════════════════════════════════════════
# 1. Разбор pools.go
# ═════════════════════════════════════════════════════════════════════════
class TestParse(unittest.TestCase):
    def test_happy_only_poolsV4_block(self):
        # poolsV6 и masquePoolsV4 (162.159.193.0/24) не должны попасть
        self.assertEqual(wsp._parse_pools_go(POOLS_GO_SAMPLE),
                         POOLS_SAMPLE_EXPECTED)

    def test_renamed_block_raises(self):
        with self.assertRaises(ValueError):
            wsp._parse_pools_go("var masquePoolsV4 = []netip.Prefix{\n"
                                '\tnetip.MustParsePrefix("8.6.112.0/24"),\n}\n')

    def test_empty_block_raises(self):
        with self.assertRaises(ValueError):
            wsp._parse_pools_go("var poolsV4 = []netip.Prefix{\n}\n")

    def test_dedup(self):
        text = ("var poolsV4 = []netip.Prefix{\n"
                '\tnetip.MustParsePrefix("8.6.112.0/24"),\n'
                '\tnetip.MustParsePrefix("8.6.112.0/24"),\n'
                '\tnetip.MustParsePrefix("8.34.70.0/24"),\n'
                '\tnetip.MustParsePrefix("8.35.211.0/24"),\n'
                '\tnetip.MustParsePrefix("8.39.125.0/24"),\n}\n')
        self.assertEqual(wsp._parse_pools_go(text),
                         ["8.6.112.0/24", "8.34.70.0/24",
                          "8.35.211.0/24", "8.39.125.0/24"])

    def test_invalid_wide_narrow_v6_skipped(self):
        text = ("var poolsV4 = []netip.Prefix{\n"
                '\tnetip.MustParsePrefix("999.1.2.3/24"),\n'   # мусор
                '\tnetip.MustParsePrefix("10.0.0.0/16"),\n'    # шире /20
                '\tnetip.MustParsePrefix("8.6.112.1/28"),\n'   # уже /24
                '\tnetip.MustParsePrefix("2606:4700:d0::/48"),\n'  # v6
                '\tnetip.MustParsePrefix("8.6.112.0/24"),\n'
                '\tnetip.MustParsePrefix("8.34.70.0/24"),\n'
                '\tnetip.MustParsePrefix("8.35.211.0/24"),\n'
                '\tnetip.MustParsePrefix("8.39.125.0/24"),\n'
                '\tnetip.MustParsePrefix("8.39.204.0/24"),\n}\n')
        with patch.object(wsp, "warn"):
            self.assertEqual(wsp._parse_pools_go(text),
                             ["8.6.112.0/24", "8.34.70.0/24",
                              "8.35.211.0/24", "8.39.125.0/24",
                              "8.39.204.0/24"])

    def test_too_many_pools_raises(self):
        entries = "".join(
            f'\tnetip.MustParsePrefix("10.{i}.0.0/24"),\n'
            for i in range(wsp.MAX_POOLS + 1))
        text = f"var poolsV4 = []netip.Prefix{{\n{entries}}}\n"
        with self.assertRaises(ValueError):
            wsp._parse_pools_go(text)


# ═════════════════════════════════════════════════════════════════════════
# 2. Зеркала
# ═════════════════════════════════════════════════════════════════════════
class TestFetchMirrors(unittest.TestCase):
    def test_first_dead_second_alive(self):
        urls = ("https://dead.example/pools.go",
                "https://alive.example/pools.go")
        ctx = MagicMock()
        ctx.__enter__.return_value.read.return_value = \
            POOLS_GO_SAMPLE.encode()
        with patch.object(wsp, "POOLS_URLS", urls), \
             patch.object(wsp, "warn") as m_warn, \
             patch.object(wsp._urlreq, "urlopen",
                          side_effect=[OSError("dead"), ctx]):
            body, url = wsp._fetch_pools_go()
        self.assertEqual(url, urls[1])
        self.assertIn("poolsV4", body)
        m_warn.assert_called_once()   # первое зеркало ругнулось один раз

    def test_file_without_poolsV4_skipped(self):
        with patch.object(wsp, "POOLS_URLS", ("https://x.example/1",)), \
             patch.object(wsp, "warn"), \
             patch.object(wsp._urlreq, "urlopen") as m_open:
            m_open.return_value.__enter__.return_value.read.return_value = \
                b"package main // no pools here"
            self.assertIsNone(wsp._fetch_pools_go())

    def test_all_dead_returns_none(self):
        with patch.object(wsp, "POOLS_URLS", ("https://x.example/1",)), \
             patch.object(wsp, "warn"), \
             patch.object(wsp._urlreq, "urlopen", side_effect=OSError("net down")):
            self.assertIsNone(wsp._fetch_pools_go())


# ═════════════════════════════════════════════════════════════════════════
# 3. Кэш и слияние диапазонов
# ═════════════════════════════════════════════════════════════════════════
class TestRanges(_TmpPaths):
    def test_defaults_empty_cache(self):
        cache = wsp._cache_load()
        self.assertEqual(cache, {"pools": [], "auto": wsp.DEFAULT_AUTO})
        self.assertTrue(wsp.DEFAULT_AUTO)  # авто ВКЛ по умолчанию

    def test_get_ranges_static_only_when_no_cache(self):
        # нет файла кэша вообще → статика, никакого сетевого IO
        with patch.object(wsp, "_fetch_pools_go") as m_fetch:
            self.assertEqual(wsp.get_scan_ranges(), wsp.STATIC_SCAN_RANGES)
            m_fetch.assert_not_called()

    def test_get_ranges_merge_upstream_first(self):
        self.cache.write_text('{"pools": ["8.6.112.0/24", "9.9.9.0/24"]}')
        ranges = wsp.get_scan_ranges()
        self.assertEqual(ranges[:2], ("8.6.112.0/24", "9.9.9.0/24"))
        # статика, которой нет у апстрима, — довеском, без дублей
        self.assertEqual(
            ranges[2:], tuple(c for c in wsp.STATIC_SCAN_RANGES
                              if c != "8.6.112.0/24"))
        self.assertEqual(len(ranges), len(set(ranges)))

    def test_scan_pools_auto_flag(self):
        self.assertTrue(wsp.scan_pools_auto())
        self.cache.write_text('{"pools": [], "auto": false}')
        self.assertFalse(wsp.scan_pools_auto())

    def test_warp_alias_warp_scan_ranges(self):
        # warp.WARP_SCAN_RANGES — алиас статического базиса (не разъехались)
        self.assertEqual(warp_mod.WARP_SCAN_RANGES, wsp.STATIC_SCAN_RANGES)


# ═════════════════════════════════════════════════════════════════════════
# 4. Синхронизация
# ═════════════════════════════════════════════════════════════════════════
class TestSync(_TmpPaths):
    def test_success_added_removed(self):
        # в кэше был пул, которого нет у апстрима (removed) — и наоборот
        self.cache.write_text('{"pools": ["1.2.3.0/24", "8.34.70.0/24"],'
                              ' "auto": true}')
        with patch.object(wsp, "_fetch_pools_go",
                          return_value=(POOLS_GO_SAMPLE, "https://mirror/1")):
            res = wsp.sync_scan_pools()
        self.assertTrue(res["ok"])
        self.assertEqual(res["pools"], POOLS_SAMPLE_EXPECTED)
        self.assertEqual(res["added"], [
            p for p in POOLS_SAMPLE_EXPECTED if p != "8.34.70.0/24"])
        self.assertEqual(res["removed"], ["1.2.3.0/24"])
        data = __import__("json").loads(self.cache.read_text())
        self.assertEqual(data["pools"], POOLS_SAMPLE_EXPECTED)
        self.assertTrue(data["ok"])
        self.assertEqual(data["source"], "https://mirror/1")

    def test_network_fail_keeps_old(self):
        self.cache.write_text('{"pools": ["1.2.3.0/24"], "auto": true}')
        with patch.object(wsp, "_fetch_pools_go", return_value=None):
            res = wsp.sync_scan_pools()
        self.assertFalse(res["ok"])
        self.assertEqual(res["pools"], ["1.2.3.0/24"])
        data = __import__("json").loads(self.cache.read_text())
        self.assertEqual(data["pools"], ["1.2.3.0/24"])
        self.assertFalse(data["ok"])
        self.assertIn("network", data["last_error"])

    def test_parse_fail_keeps_old(self):
        self.cache.write_text('{"pools": ["1.2.3.0/24"], "auto": true}')
        broken = "package main // poolsV4 уехал в другой файл"
        with patch.object(wsp, "_fetch_pools_go",
                          return_value=(broken, "https://mirror/1")):
            res = wsp.sync_scan_pools()
        self.assertFalse(res["ok"])
        data = __import__("json").loads(self.cache.read_text())
        self.assertEqual(data["pools"], ["1.2.3.0/24"])
        self.assertIn("parse", data["last_error"])


# ═════════════════════════════════════════════════════════════════════════
# 5. Cron
# ═════════════════════════════════════════════════════════════════════════
class TestCron(_TmpPaths):
    def test_enable_disable(self):
        wsp._manage_cron(True)
        self.assertTrue(wsp.cron_installed())
        content = self.cron.read_text()
        self.assertIn(wsp.CRON_SYNC_SCHEDULE, content)
        self.assertIn("--sync-pools", content)
        self.assertIn(str(wsp.MODULE_PATH), content)
        wsp._manage_cron(False)
        self.assertFalse(wsp.cron_installed())


# ═════════════════════════════════════════════════════════════════════════
# 6. ensure_pools_ready
# ═════════════════════════════════════════════════════════════════════════
class TestEnsure(_TmpPaths):
    def test_auto_off_noop(self):
        self.cache.write_text('{"pools": [], "auto": false}')
        with patch.object(wsp, "sync_scan_pools") as m_sync:
            wsp.ensure_pools_ready()
            m_sync.assert_not_called()
        self.assertFalse(wsp.cron_installed())

    def test_empty_pools_sync_and_cron_restored(self):
        with patch.object(wsp, "sync_scan_pools",
                          return_value={"ok": True, "pools": ["8.6.112.0/24"],
                                        "added": [], "removed": []}) as m_sync:
            wsp.ensure_pools_ready()
            m_sync.assert_called_once()
        self.assertTrue(wsp.cron_installed())

    def test_fresh_cache_no_sync(self):
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.cache.write_text(f'{{"pools": ["8.6.112.0/24"], '
                              f'"fetched_at": "{now}", "auto": true}}')
        wsp._manage_cron(True)
        with patch.object(wsp, "sync_scan_pools") as m_sync:
            wsp.ensure_pools_ready()
            m_sync.assert_not_called()

    def test_stale_cache_syncs(self):
        old = (datetime.now(timezone.utc) -
               timedelta(hours=wsp.STALE_AFTER_H + 2)).isoformat(
                   timespec="seconds")
        self.cache.write_text(f'{{"pools": ["8.6.112.0/24"], '
                              f'"fetched_at": "{old}", "auto": true}}')
        wsp._manage_cron(True)
        with patch.object(wsp, "sync_scan_pools",
                          return_value={"ok": False, "pools": [],
                                        "added": [], "removed": []}) as m_sync:
            wsp.ensure_pools_ready()   # сбой — тихо, без исключений
            m_sync.assert_called_once()

    def test_scan_select_targets_uses_live_ranges(self):
        # _select_scan_targets берёт get_scan_ranges(), не статический алиас:
        # свежие пулы warpscout попадают в скан без перезапуска TUI
        self.cache.write_text('{"pools": ["9.9.9.0/24"], "auto": true}')
        # random импортируется ЛОКАЛЬНО в функции — патчим сам модуль random
        with patch("random.randint", return_value=2), \
             patch("random.sample", side_effect=lambda hs, k: hs[:k]):
            targets = warp_mod._select_scan_targets()
        self.assertTrue(any(t.startswith("9.9.9.") for t in targets))
        self.assertTrue(any(t.startswith("8.6.112.") for t in targets))


# ═════════════════════════════════════════════════════════════════════════
# 7. Меню
# ═════════════════════════════════════════════════════════════════════════
class TestMenu(_TmpPaths):
    def _menu(self, inputs, **extra):
        with patch("builtins.input", side_effect=inputs), \
             patch.object(wsp.time, "sleep"), \
             patch.object(wsp, "sync_scan_pools",
                          **extra) as m_sync:
            wsp.do_manage_scan_pools()
            return m_sync

    def test_render_and_exit(self):
        self._menu(["0"])

    def test_s_syncs_now(self):
        m = self._menu(["s", "", "0"],
                       return_value={"ok": True, "pools": POOLS_SAMPLE_EXPECTED,
                                     "added": ["8.6.112.0/24"],
                                     "removed": []})
        m.assert_called_once()

    def test_a_toggles_auto_and_cron(self):
        wsp._manage_cron(True)
        self._menu(["a", "0"])
        data = __import__("json").loads(self.cache.read_text())
        self.assertFalse(data["auto"])
        self.assertFalse(wsp.cron_installed())

    def test_r_resets_pools(self):
        self.cache.write_text('{"pools": ["1.2.3.0/24"], "auto": true}')
        self._menu(["r", "0"])
        data = __import__("json").loads(self.cache.read_text())
        self.assertEqual(data["pools"], [])
        self.assertEqual(wsp.get_scan_ranges(), wsp.STATIC_SCAN_RANGES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
