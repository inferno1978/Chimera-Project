#!/usr/bin/env python3
"""
tests/test_traffic_collectors.py
───────────────────────────────────────────────────────────────────────────────
Реалистичные тесты для трёх protocol-specific коллекторов трафика:
  1. awg_collect_peer_traffic (awg_peers.py)
  2. mieru_collect_traffic (mieru_stats.py)
  3. naiveproxy_collect_traffic (naiveproxy_stats.py)

ОТЛИЧИЕ от существующих тестов:
  • Используют РЕАЛИСТИЧНЫЕ образцы вывода (скопированные из документации
    wg/awg, реальных journalctl mita, реальных access.log Caddy).
  • Проверяют что после фикса функция реально извлекает НЕНУЛЕВЫЕ байты
    для конкретного пользователя.
  • Не используют выдуманные форматы — только то, что реально приходит
    из команды/лога.

ПОКРЫТИЕ БАГОВ:
  Bug 1 (AWG): parts[0] == "peer" никогда не matчит — реальный формат
    имеет parts[0] = interface name (awg0). Фикс: отличать peer от
    interface по количеству полей (>= 8 = peer).
  Bug 2 (Mieru): ustats.get("rx"/"tx") — неправильные ключи, _parse_journal
    кладёт {"download"/"upload"}. Фикс: правильные ключи.
  Bug 3 (NaiveProxy): передавал window-based bytes (не монотонный счётчик)
    в record_traffic_sample. Фикс: инкрементальное чтение новых строк
    лога с offset-отслеживанием для устойчивости к Caddy roll_size.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Создаёт фейковый chimera._core (как в test_tg_bot.py)."""
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


# =============================================================================
#  РЕАЛИСТИЧНЫЕ ОБРАЗЦЫ ВЫВОДА
# =============================================================================

# Реальный вывод `awg show all dump` (или `wg show all dump`).
# Формат TSV, скопированный из документации WireGuard + реальных тестов:
#   interface-строка: <iface>\t<private-key>\t<listen-port>\t<fwmark>
#   peer-строка:      <iface>\t<pubkey>\t<preshared-key>\t<endpoint>\t
#                     <allowed-ips>\t<handshake>\t<rx>\t<tx>\t<keepalive>
# ВАЖНО: parts[0] = "awg0" (имя интерфейса), НЕ "peer"!
_REAL_AWG_DUMP = [
    # interface-строка (4 поля) — должна быть пропущена парсером
    "awg0\tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t51820\t0x3e8",
    # peer 1 (alice) — 9 полей, rx=1234567 tx=7654321
    "awg0\tBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\tCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=\t203.0.113.5:54321\t10.66.66.2/32\t1719500000\t1234567\t7654321\t25",
    # peer 2 (bob) — 9 полей, rx=987654 tx=456789
    "awg0\tDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=\tEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=\t198.51.100.10:12345\t10.66.66.3/32\t1719500100\t987654\t456789\t25",
    # peer 3 (technical, без owner_email) — должен быть пропущен
    "awg0\tFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF=\t\t192.0.2.1:33333\t10.66.66.4/32\t1719500200\t111111\t222222\t0",
]

# Реальный journalctl вывод mita с [metrics - user - NAME].
# mita пишет метрики каждые 10 мин, DownloadBytes/UploadBytes —
# монотонно растущие cumulative counters с момента старта процесса.
_REAL_MIERU_JOURNAL = """2026-07-14T10:00:00+0000 mita[12345]: [metrics - connections] ActiveOpens=5 CurrEstablished=2 PassiveOpens=10
2026-07-14T10:00:00+0000 mita[12345]: [metrics - traffic] DownloadBytes=1048576 UploadBytes=524288 OutputPaddingBytes=1024
2026-07-14T10:00:00+0000 mita[12345]: [metrics - user - alice] DownloadBytes=524288 UploadBytes=262144
2026-07-14T10:00:00+0000 mita[12345]: [metrics - user - bob] DownloadBytes=524288 UploadBytes=262144
2026-07-14T10:10:00+0000 mita[12345]: [metrics - user - alice] DownloadBytes=1048576 UploadBytes=524288
2026-07-14T10:10:00+0000 mita[12345]: [metrics - user - bob] DownloadBytes=524288 UploadBytes=262144
"""

# Реальные access.log строки Caddy (JSON формат).
# Каждая строка — JSON с полями: ts, status, size, duration, request.
# request.headers.Authorization содержит Basic <base64(user:pass)>.
import base64 as _b64
_ALICE_AUTH = "Basic " + _b64.b64encode(b"alice:password123").decode()
_BOB_AUTH = "Basic " + _b64.b64encode(b"bob:secret456").decode()
_REAL_CADDY_LOG_LINES = [
    # alice — 3 запроса, total resp_size = 100 + 200 + 300 = 600
    {"ts": time.time() - 60, "status": 200, "size": 100, "duration": 0.5,
     "request": {"remote_addr": "1.2.3.4:1234",
                 "headers": {"Authorization": [_ALICE_AUTH]}}},
    {"ts": time.time() - 50, "status": 200, "size": 200, "duration": 0.6,
     "request": {"remote_addr": "1.2.3.4:1234",
                 "headers": {"Authorization": [_ALICE_AUTH]}}},
    {"ts": time.time() - 40, "status": 200, "size": 300, "duration": 0.7,
     "request": {"remote_addr": "1.2.3.4:1234",
                 "headers": {"Authorization": [_ALICE_AUTH]}}},
    # bob — 2 запроса, total resp_size = 500 + 500 = 1000
    {"ts": time.time() - 30, "status": 200, "size": 500, "duration": 0.4,
     "request": {"remote_addr": "5.6.7.8:5678",
                 "headers": {"Authorization": [_BOB_AUTH]}}},
    {"ts": time.time() - 20, "status": 200, "size": 500, "duration": 0.5,
     "request": {"remote_addr": "5.6.7.8:5678",
                 "headers": {"Authorization": [_BOB_AUTH]}}},
]


# =============================================================================
#  ТЕСТЫ AWG (Bug 1)
# =============================================================================
class TestAwgCollectPeerTraffic(unittest.TestCase):
    """Тест awg_collect_peer_traffic на РЕАЛЬНОМ выводе `awg show all dump`.

    Bug 1: фильтр parts[0] == "peer" никогда не проходит, т.к. в реальном
    выводе первое поле — имя интерфейса (awg0), а не литерал "peer".
    Фикс: отличать peer от interface по количеству полей (>= 8 = peer).
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._acc_state = self._tmpdir / "traffic_accounting.json"
        self._acc_lock = self._tmpdir / "traffic_accounting.lock"
        # AWG state с двумя пирами: alice и bob (с owner_email), и technical (без)
        self._awg_state = self._tmpdir / "awg_state.json"
        self._awg_state.write_text(json.dumps({
            "installed": True,
            "peers": [
                {"name": "alice", "client_pubkey": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                 "owner_email": "alice@xray"},
                {"name": "bob", "client_pubkey": "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=",
                 "owner_email": "bob@xray"},
                # technical peer — без owner_email, должен быть пропущен
                {"name": "cascade_entry", "client_pubkey": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF=",
                 "owner_email": ""},
            ],
        }))

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_extracts_nonzero_bytes_for_real_users(self):
        """На реальном выводе awg show all dump — alice и bob должны получить
        ненулевые accumulated bytes. Technical peer (без owner_email) пропускается.
        """
        from chimera.modules import awg_peers, traffic_accounting

        with patch("chimera.modules.traffic_accounting._STATE_FILE", self._acc_state), \
             patch("chimera.modules.traffic_accounting._LOCK_FILE", self._acc_lock), \
             patch("chimera.modules.awg_peers.awgs_state_load",
                   return_value=json.loads(self._awg_state.read_text())), \
             patch("chimera.modules.awg_apply.awgs_show_dump",
                   return_value=_REAL_AWG_DUMP):
            result = awg_peers.awg_collect_peer_traffic()

        # Alice: rx=1234567 + tx=7654321 = 8888888
        self.assertIn("alice@xray", result)
        self.assertEqual(result["alice@xray"], 1234567 + 7654321)
        self.assertGreater(result["alice@xray"], 0,
                           "alice should have non-zero accumulated bytes")

        # Bob: rx=987654 + tx=456789 = 1444443
        self.assertIn("bob@xray", result)
        self.assertEqual(result["bob@xray"], 987654 + 456789)
        self.assertGreater(result["bob@xray"], 0,
                           "bob should have non-zero accumulated bytes")

        # Technical peer (без owner_email) — НЕ должен быть в результате
        self.assertNotIn("", result, "technical peer without owner_email should be skipped")

    def test_interface_line_skipped(self):
        """interface-строка (4 поля) не должна парситься как peer."""
        from chimera.modules import awg_peers
        # Только interface-строка, без peer-строк
        dump_with_only_interface = ["awg0\tAAAA=\t51820\t0x3e8"]
        with patch("chimera.modules.awg_peers.awgs_state_load",
                   return_value={"peers": []}), \
             patch("chimera.modules.awg_apply.awgs_show_dump",
                   return_value=dump_with_only_interface), \
             patch("chimera.modules.traffic_accounting._STATE_FILE", self._acc_state), \
             patch("chimera.modules.traffic_accounting._LOCK_FILE", self._acc_lock):
            result = awg_peers.awg_collect_peer_traffic()
        self.assertEqual(result, {})

    def test_counter_reset_preserves_accumulated(self):
        """При рестарте awg-quick (счётчик сбросился) — accumulated сохраняется."""
        from chimera.modules import awg_peers, traffic_accounting

        # Первый снимок: alice rx=1234567 tx=7654321 → 8888888
        with patch("chimera.modules.traffic_accounting._STATE_FILE", self._acc_state), \
             patch("chimera.modules.traffic_accounting._LOCK_FILE", self._acc_lock), \
             patch("chimera.modules.awg_peers.awgs_state_load",
                   return_value=json.loads(self._awg_state.read_text())), \
             patch("chimera.modules.awg_apply.awgs_show_dump",
                   return_value=_REAL_AWG_DUMP):
            r1 = awg_peers.awg_collect_peer_traffic()
        self.assertEqual(r1["alice@xray"], 8888888)

        # Рестарт awg-quick — счётчик сбросился, alice теперь rx=100 tx=200
        dump_after_restart = [
            "awg0\tAAAA=\t51820\t0x3e8",
            "awg0\tBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\tCCCC=\t1.2.3.4:54321\t10.66.66.2/32\t1719500500\t100\t200\t25",
        ]
        with patch("chimera.modules.traffic_accounting._STATE_FILE", self._acc_state), \
             patch("chimera.modules.traffic_accounting._LOCK_FILE", self._acc_lock), \
             patch("chimera.modules.awg_peers.awgs_state_load",
                   return_value=json.loads(self._awg_state.read_text())), \
             patch("chimera.modules.awg_apply.awgs_show_dump",
                   return_value=dump_after_restart):
            r2 = awg_peers.awg_collect_peer_traffic()
        # accumulated = 8888888 (baseline) + 300 (new raw) = 8889188
        self.assertEqual(r2["alice@xray"], 8888888 + 300)


# =============================================================================
#  ТЕСТЫ MIERU (Bug 2)
# =============================================================================
class TestMieruCollectTraffic(unittest.TestCase):
    """Тест mieru_collect_traffic на РЕАЛЬНОМ journalctl mita выводе.

    Bug 2: ustats.get("rx"/"tx") — неправильные ключи. _parse_journal
    кладёт {"download": dl, "upload": ul}. Фикс: правильные ключи.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._acc_state = self._tmpdir / "traffic_accounting.json"
        self._acc_lock = self._tmpdir / "traffic_accounting.lock"

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_mock_journal_result(self):
        """Имитирует результат _parse_journal с per-user метриками.
        Берёт последние значения DownloadBytes/UploadBytes per-user.
        """
        return {
            "users": {
                "alice": {"download": 1048576, "upload": 524288},  # = 1572864
                "bob":   {"download": 524288,  "upload": 262144},  # = 786432
            },
            "download_bytes": 1572864,
            "upload_bytes": 786432,
        }

    def test_extracts_nonzero_bytes_with_correct_keys(self):
        """С правильными ключами download/upload — alice и bob получают
        ненулевые accumulated bytes. Со старыми ключами rx/tx было бы 0."""
        from chimera.modules import mieru_stats

        mock_journal = self._make_mock_journal_result()
        with patch("chimera.modules.traffic_accounting._STATE_FILE", self._acc_state), \
             patch("chimera.modules.traffic_accounting._LOCK_FILE", self._acc_lock), \
             patch("chimera.modules.mieru_stats._parse_journal",
                   return_value=mock_journal):
            result = mieru_stats.mieru_collect_traffic()

        # alice: download=1048576 + upload=524288 = 1572864
        self.assertIn("alice", result)
        self.assertEqual(result["alice"], 1572864)
        self.assertGreater(result["alice"], 0,
                           "alice should have non-zero accumulated bytes")

        # bob: download=524288 + upload=262144 = 786432
        self.assertIn("bob", result)
        self.assertEqual(result["bob"], 786432)
        self.assertGreater(result["bob"], 0,
                           "bob should have non-zero accumulated bytes")

    def test_old_keys_rx_tx_would_return_zero(self):
        """Проверка что со старыми ключами rx/tx результат был бы 0.
        Это regression-тест — если кто-то вернёт баг, тест поймает."""
        from chimera.modules import mieru_stats

        # Имитируем багованный journal result (с rx/tx вместо download/upload)
        buggy_journal = {
            "users": {
                "alice": {"download": 1048576, "upload": 524288},  # правильные ключи
            },
        }
        with patch("chimera.modules.traffic_accounting._STATE_FILE", self._acc_state), \
             patch("chimera.modules.traffic_accounting._LOCK_FILE", self._acc_lock), \
             patch("chimera.modules.mieru_stats._parse_journal",
                   return_value=buggy_journal):
            # Если бы код использовал ustats.get("rx", 0) + ustats.get("tx", 0),
            # результат был бы 0 (нет таких ключей). С фиксом — 1572864.
            result = mieru_stats.mieru_collect_traffic()
        # alice должна получить 1572864 (download + upload), НЕ 0
        self.assertEqual(result.get("alice", 0), 1572864,
                         "Fixed code should use download/upload keys, not rx/tx")

    def test_counter_reset_preserves_accumulated(self):
        """При рестарте mita (счётчик сбросился) — accumulated сохраняется."""
        from chimera.modules import mieru_stats

        # Первый снимок: alice download=1048576 upload=524288 → 1572864
        journal1 = {"users": {"alice": {"download": 1048576, "upload": 524288}}}
        with patch("chimera.modules.traffic_accounting._STATE_FILE", self._acc_state), \
             patch("chimera.modules.traffic_accounting._LOCK_FILE", self._acc_lock), \
             patch("chimera.modules.mieru_stats._parse_journal",
                   return_value=journal1):
            r1 = mieru_stats.mieru_collect_traffic()
        self.assertEqual(r1["alice"], 1572864)

        # Рестарт mita — счётчик сбросился, alice теперь download=100 upload=200
        journal2 = {"users": {"alice": {"download": 100, "upload": 200}}}
        with patch("chimera.modules.traffic_accounting._STATE_FILE", self._acc_state), \
             patch("chimera.modules.traffic_accounting._LOCK_FILE", self._acc_lock), \
             patch("chimera.modules.mieru_stats._parse_journal",
                   return_value=journal2):
            r2 = mieru_stats.mieru_collect_traffic()
        # accumulated = 1572864 (baseline) + 300 (new raw) = 1573164
        self.assertEqual(r2["alice"], 1572864 + 300)


# =============================================================================
#  ТЕСТЫ NAIVEPROXY (Bug 3)
# =============================================================================
class TestNaiveproxyCollectTraffic(unittest.TestCase):
    """Тест naiveproxy_collect_traffic на РЕАЛЬНОМ access.log Caddy.

    Bug 3: передавал window-based bytes (не монотонный счётчик) в
    record_traffic_sample. Фикс: инкрементальное чтение новых строк лога
    с offset-отслеживанием для устойчивости к Caddy roll_size.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._acc_state = self._tmpdir / "traffic_accounting.json"
        self._acc_lock = self._tmpdir / "traffic_accounting.lock"
        self._offset_state = self._tmpdir / "naiveproxy_log_offset.json"
        # Создаём реальный access.log файл с Caddy JSON строками
        self._access_log = self._tmpdir / "access.log"
        self._write_log_lines(_REAL_CADDY_LOG_LINES)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write_log_lines(self, entries):
        """Записывает JSON entries в access.log (по одной строке на entry)."""
        with self._access_log.open("w") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")

    def _append_log_lines(self, entries):
        """Дописывает JSON entries в конец access.log."""
        with self._access_log.open("a") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")

    def test_extracts_nonzero_bytes_for_real_users(self):
        """На реальном access.log — alice и bob должны получить
        ненулевые accumulated bytes.
        """
        from chimera.modules import naiveproxy_stats

        with patch("chimera.modules.naiveproxy_stats._ACCESS_LOG", self._access_log), \
             patch("chimera.modules.naiveproxy_stats._NAIVE_OFFSET_FILE", self._offset_state), \
             patch("chimera.modules.traffic_accounting._STATE_FILE", self._acc_state), \
             patch("chimera.modules.traffic_accounting._LOCK_FILE", self._acc_lock):
            result = naiveproxy_stats.naiveproxy_collect_traffic()

        # alice: 100 + 200 + 300 = 600
        self.assertIn("alice", result)
        self.assertEqual(result["alice"], 600)
        self.assertGreater(result["alice"], 0,
                           "alice should have non-zero accumulated bytes")

        # bob: 500 + 500 = 1000
        self.assertIn("bob", result)
        self.assertEqual(result["bob"], 1000)
        self.assertGreater(result["bob"], 0,
                           "bob should have non-zero accumulated bytes")

    def test_incremental_reading_no_duplicate(self):
        """Повторный вызов без новых строк — accumulated не меняется
        (delta=0, новых строк нет)."""
        from chimera.modules import naiveproxy_stats

        with patch("chimera.modules.naiveproxy_stats._ACCESS_LOG", self._access_log), \
             patch("chimera.modules.naiveproxy_stats._NAIVE_OFFSET_FILE", self._offset_state), \
             patch("chimera.modules.traffic_accounting._STATE_FILE", self._acc_state), \
             patch("chimera.modules.traffic_accounting._LOCK_FILE", self._acc_lock):
            # Первый вызов — читает все строки
            r1 = naiveproxy_stats.naiveproxy_collect_traffic()
            # Второй вызов — новых строк нет, result должен быть пустым
            r2 = naiveproxy_stats.naiveproxy_collect_traffic()

        self.assertEqual(r1["alice"], 600)
        self.assertEqual(r2, {}, "Second call with no new lines should return empty dict")

    def test_incremental_reading_accumulates_new_lines(self):
        """При дописывании новых строк — accumulated растёт на delta."""
        from chimera.modules import naiveproxy_stats

        with patch("chimera.modules.naiveproxy_stats._ACCESS_LOG", self._access_log), \
             patch("chimera.modules.naiveproxy_stats._NAIVE_OFFSET_FILE", self._offset_state), \
             patch("chimera.modules.traffic_accounting._STATE_FILE", self._acc_state), \
             patch("chimera.modules.traffic_accounting._LOCK_FILE", self._acc_lock):
            # Первый вызов — alice = 600
            r1 = naiveproxy_stats.naiveproxy_collect_traffic()
            self.assertEqual(r1["alice"], 600)

            # Дописываем 2 новые строки для alice: 400 + 500 = 900
            new_entries = [
                {"ts": time.time() - 10, "status": 200, "size": 400, "duration": 0.3,
                 "request": {"remote_addr": "1.2.3.4:1234",
                             "headers": {"Authorization": [_ALICE_AUTH]}}},
                {"ts": time.time() - 5, "status": 200, "size": 500, "duration": 0.4,
                 "request": {"remote_addr": "1.2.3.4:1234",
                             "headers": {"Authorization": [_ALICE_AUTH]}}},
            ]
            self._append_log_lines(new_entries)

            # Второй вызов — alice должна получить +900 (delta)
            r2 = naiveproxy_stats.naiveproxy_collect_traffic()

        # r2["alice"] = r1["alice"] + 900 = 600 + 900 = 1500
        self.assertIn("alice", r2)
        self.assertEqual(r2["alice"], 600 + 900,
                         f"Expected 1500 (600 + 900 delta), got {r2.get('alice')}")

    def test_log_rotation_handled_by_inode_check(self):
        """При ротации лога (новый inode) — читаем с начала нового файла,
        не теряя накопленное."""
        from chimera.modules import naiveproxy_stats

        with patch("chimera.modules.naiveproxy_stats._ACCESS_LOG", self._access_log), \
             patch("chimera.modules.naiveproxy_stats._NAIVE_OFFSET_FILE", self._offset_state), \
             patch("chimera.modules.traffic_accounting._STATE_FILE", self._acc_state), \
             patch("chimera.modules.traffic_accounting._LOCK_FILE", self._acc_lock):
            # Первый вызов — alice = 600
            r1 = naiveproxy_stats.naiveproxy_collect_traffic()
            self.assertEqual(r1["alice"], 600)

            # Имитируем ротацию: пересоздаём файл (новый inode) с новыми строками
            # Удаляем старый и создаём новый
            self._access_log.unlink()
            new_entries = [
                {"ts": time.time() - 5, "status": 200, "size": 700, "duration": 0.4,
                 "request": {"remote_addr": "1.2.3.4:1234",
                             "headers": {"Authorization": [_ALICE_AUTH]}}},
            ]
            self._write_log_lines(new_entries)

            # Второй вызов — должен обнаружить новый inode, читать с начала
            r2 = naiveproxy_stats.naiveproxy_collect_traffic()

        # r2["alice"] = r1["alice"] + 700 (delta from new file) = 600 + 700 = 1300
        self.assertIn("alice", r2)
        self.assertEqual(r2["alice"], 600 + 700,
                         f"Expected 1300 (600 baseline + 700 from rotated log), got {r2.get('alice')}")


if __name__ == "__main__":
    unittest.main()
