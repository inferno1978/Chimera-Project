#!/usr/bin/env python3
"""
tests/test_mieru_cascade_b4qlog.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты querylog-harvest в chimera/modules/mieru_cascade.py — третьего
«клиентского» вида резолва ipset mieru_b4_direct (B4-EXEMPT).

Живой кейс (02.10.2026, RU-Entry + Karing): видео-хосты
rr*.googlevideo.com — ПЕР-ВИДЕО имена, в route_domains их НЕТ; их
GGC-кэши (IP вне AS15169, у провайдера клиента: 85.249.244.x,
81.27.242.x) не попадали в 2-минутный снапшот → ~100% промах ipset
→ весь видеотрафик каскадился через 4-слойную цепочку (mita→redsocks
→mieru-hop→exit DE) ОБРАТНО к RU-внутренним GGC-кэшам → спиннеры на
старте видео. Клиентский DoH приходит на AGH самой Entry-ноды →
querylog.json содержит ровно те имена и A-ответы, что видит клиент.

Покрывает:
  1. _b4_dns_skip_name / _b4_dns_a_records: wire-парсер DNS-ответов
     (вопрос+компрессия, CNAME-микс, приватные/0.0.0.0 отсеиваются,
     мусор/обрезка → пусто)
  2. _b4_qh_suffix_match: суффикс-матч по границе метки
     (evilgooglevideo.com НЕ матчит googlevideo.com — деанон-гард)
  3. _b4_qlog_epoch: RFC3339 с наносекундами/смещением/Z → epoch
  4. _b4_harvest_querylog: end-to-end по temp-файлу querylog.json
     (свежесть окна, не-матчущие домены, пустой Answer, «заблокировано»
     0.0.0.0, битые строки, шапка-метаданные AGH, обрезанный хвост,
     отсутствие AGH → мягкая деградация)
  5. _b4set_refresh: вживление harvest в снапшот (регрессия класса
     «harvest работает, но не подключён»): мерж с резолв-видами,
     выживание снапшота при лежащем резолве, guard пустого набора
     (оба вида пусты → старый ipset не трогаем)
"""
from __future__ import annotations

import base64
import json
import struct
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import mieru_cascade  # noqa: E402


# ─── helpers: сборка DNS-wire как их пишет AGH в Answer ─────────────────────

def _enc_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _a(ip: str) -> tuple:
    return 1, bytes(int(p) for p in ip.split("."))


def _cname(target: str) -> tuple:
    return 5, _enc_name(target)


def _dns_msg(qname: str, answers: list) -> bytes:
    """Ответ: 1 вопрос + N записей (имя записи — указатель на вопрос)."""
    msg = struct.pack(">HHHHHH", 0, 0x8180, 1, len(answers), 0, 0)
    msg += _enc_name(qname) + struct.pack(">HH", 1, 1)
    for rtype, rdata in answers:
        msg += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 300,
                                         len(rdata)) + rdata
    return msg


def _b64(msg: bytes) -> str:
    return base64.b64encode(msg).decode()


def _qlog_line(qh: str, answer: bytes, when: datetime,
               client: str = "127.0.0.1") -> str:
    return json.dumps({
        "T": when.isoformat(), "QH": qh, "QT": "A", "QC": "IN",
        "Answer": _b64(answer) if answer else "",
        "Result": {"IsFiltered": False}, "Elapsed": 1234567,
        "IP": client, "Upstream": "8.8.8.8:53",
    })


def _now() -> datetime:
    return datetime.now(timezone.utc)


class TestDnsARecords(unittest.TestCase):
    """Wire-парсер: только публичные IPv4 из A-записей."""

    def test_a_and_cname_mix(self):
        msg = _dns_msg("rr6---sn-x.googlevideo.com", [
            _cname("rr6---sn-y.googlevideo.com"),
            _a("85.249.244.49"),
            _a("81.27.242.141"),
        ])
        self.assertEqual(mieru_cascade._b4_dns_a_records(msg),
                         {"85.249.244.49", "81.27.242.141"})

    def test_private_loopback_unspecified_filtered(self):
        msg = _dns_msg("x.youtube.com", [
            _a("192.168.1.1"), _a("127.0.0.1"), _a("0.0.0.0"),
            _a("85.249.244.49"),
        ])
        # 0.0.0.0 — ответ «заблокировано» AGH; приватные — rebind-гард
        self.assertEqual(mieru_cascade._b4_dns_a_records(msg),
                         {"85.249.244.49"})

    def test_garbage_and_truncated(self):
        self.assertEqual(mieru_cascade._b4_dns_a_records(b""), set())
        self.assertEqual(mieru_cascade._b4_dns_a_records(b"\x01"), set())
        # заголовок обещает 3 ответа, тела нет → пусто, без исключения
        msg = struct.pack(">HHHHHH", 0, 0x8180, 1, 3, 0, 0) \
            + _enc_name("a.b") + struct.pack(">HH", 1, 1)
        self.assertEqual(mieru_cascade._b4_dns_a_records(msg), set())

    def test_ipv6_ignored(self):
        # AAAA (type 28, 16 байт) — не A, парсер пропускает
        aaa = bytes.fromhex("20010db8000000000000000000000001")
        msg = _dns_msg("x.googlevideo.com", [(28, aaa)])
        self.assertEqual(mieru_cascade._b4_dns_a_records(msg), set())


class TestQhSuffixMatch(unittest.TestCase):
    """Суффикс-матч по границе метки — деанон-гард."""

    def test_subdomain_and_apex(self):
        doms = ["googlevideo.com", "youtube.com"]
        self.assertTrue(mieru_cascade._b4_qh_suffix_match(
            "rr6---sn-8ph2xajvh-n8vs.googlevideo.com", doms))
        self.assertTrue(mieru_cascade._b4_qh_suffix_match(
            "googlevideo.com", doms))

    def test_label_boundary(self):
        doms = ["googlevideo.com"]
        self.assertFalse(mieru_cascade._b4_qh_suffix_match(
            "evilgooglevideo.com", doms))       # приклеено без метки
        self.assertFalse(mieru_cascade._b4_qh_suffix_match(
            "googlevideo.com.evil.ru", doms))   # суффикс, не домен

    def test_case_trailing_dot_and_empty(self):
        doms = ["GoogleVideo.COM"]
        self.assertTrue(mieru_cascade._b4_qh_suffix_match(
            "RR6.googlevideo.com.", doms))
        self.assertFalse(mieru_cascade._b4_qh_suffix_match("", doms))
        self.assertFalse(mieru_cascade._b4_qh_suffix_match("x.y", [""]))
        self.assertFalse(mieru_cascade._b4_qh_suffix_match("x.y", []))


class TestQlogEpoch(unittest.TestCase):
    """RFC3339 AGH (наносекунды, Z/смещение) → epoch."""

    def test_ns_with_offset(self):
        t = "2026-10-02T03:59:12.123456789+03:00"
        want = datetime.fromisoformat("2026-10-02T03:59:12.123456+03:00") \
            .timestamp()
        self.assertAlmostEqual(mieru_cascade._b4_qlog_epoch(t), want,
                               places=3)

    def test_z_and_plain(self):
        e1 = mieru_cascade._b4_qlog_epoch("2026-10-02T00:59:12Z")
        e2 = mieru_cascade._b4_qlog_epoch("2026-10-02T00:59:12+00:00")
        self.assertAlmostEqual(e1, e2, places=3)
        self.assertIsNotNone(
            mieru_cascade._b4_qlog_epoch("2026-10-02T03:59:12+03:00"))

    def test_garbage(self):
        self.assertIsNone(mieru_cascade._b4_qlog_epoch(""))
        self.assertIsNone(mieru_cascade._b4_qlog_epoch("не-дата"))
        self.assertIsNone(mieru_cascade._b4_qlog_epoch(None))


class TestHarvestQuerylog(unittest.TestCase):
    """End-to-end по temp-файлу: отбор, окно свежести, мягкие сбои."""

    DOMS = ["googlevideo.com", "youtube.com"]

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self._qlog = Path(self._td.name) / "querylog.json"
        self._patcher = patch.object(mieru_cascade, "_B4_QLOG_PATHS",
                                     (self._qlog,))
        self._patcher.start()
        self.addCleanup(self._patcher.stop)
        self.addCleanup(self._td.cleanup)

    def _write(self, lines):
        self._qlog.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_fresh_matching_entries_harvested(self):
        now = _now()
        self._write([
            '{"client_ips": [], "client_names": []}',      # шапка AGH
            _qlog_line("rr6---sn-x.googlevideo.com",
                       _dns_msg("rr6---sn-x.googlevideo.com",
                                [_a("85.249.244.49")]), now),
            _qlog_line("rr2---sn-y.googlevideo.com",
                       _dns_msg("rr2---sn-y.googlevideo.com",
                                [_a("81.27.242.142")]),
                       now - timedelta(minutes=10)),
            # 23ч — ещё внутри окна 24ч (проверка границы)
            _qlog_line("music.youtube.com",
                       _dns_msg("music.youtube.com",
                                [_a("142.250.190.5")]),
                       now - timedelta(hours=23)),
        ])
        ips, stats = mieru_cascade._b4_harvest_querylog(self.DOMS)
        self.assertEqual(ips, {"85.249.244.49", "81.27.242.142",
                               "142.250.190.5"})
        self.assertEqual(stats["names"], 3)
        self.assertEqual(stats["entries"], 3)

    def test_stale_outside_window_skipped(self):
        now = _now()
        self._write([
            _qlog_line("rr6---sn-x.googlevideo.com",
                       _dns_msg("rr6---sn-x.googlevideo.com",
                                [_a("85.249.244.49")]),
                       now - timedelta(hours=25)),        # старше окна 24ч
            _qlog_line("rr3---sn-y.googlevideo.com",
                       _dns_msg("rr3---sn-y.googlevideo.com",
                                [_a("81.27.242.141")]), now),
        ])
        ips, _ = mieru_cascade._b4_harvest_querylog(self.DOMS)
        self.assertEqual(ips, {"81.27.242.141"})          # только свежая

    def test_non_matching_domain_skipped(self):
        # НЕ блок-лист: чужой домен не должен отклеиваться от каскада
        now = _now()
        self._write([
            _qlog_line("example.org",
                       _dns_msg("example.org", [_a("93.184.216.34")]), now),
            _qlog_line("evilgooglevideo.com",
                       _dns_msg("evilgooglevideo.com",
                                [_a("203.0.113.7")]), now),
        ])
        ips, _ = mieru_cascade._b4_harvest_querylog(self.DOMS)
        self.assertEqual(ips, set())

    def test_empty_and_blocked_answers(self):
        now = _now()
        self._write([
            _qlog_line("rr6.googlevideo.com", b"", now),   # NOERROR-пусто
            # «заблокировано» AGH: A 0.0.0.0 — _b4_ip_ok отсечёт
            _qlog_line("rr7.googlevideo.com",
                       _dns_msg("rr7.googlevideo.com", [_a("0.0.0.0")]),
                       now),
            "}}} битая строка не JSON",
        ])
        ips, stats = mieru_cascade._b4_harvest_querylog(self.DOMS)
        self.assertEqual(ips, set())
        self.assertEqual(stats["names"], 0)

    def test_no_agh_file_soft_degrade(self):
        # файл не существует → пустой набор, без исключения
        ips, stats = mieru_cascade._b4_harvest_querylog(self.DOMS)
        self.assertEqual(ips, set())
        self.assertEqual(stats, {"names": 0, "entries": 0, "ips": 0})

    def test_no_domains_short_circuit(self):
        ips, stats = mieru_cascade._b4_harvest_querylog([])
        self.assertEqual(ips, set())
        self.assertEqual(stats, {"names": 0, "entries": 0, "ips": 0})

    def test_tail_cut_first_line_dropped(self):
        # хвост меньше файла → первая (обрезанная) строка выбрасывается:
        # мусор длиннее хвоста + валидная запись целиком в хвосте
        now = _now()
        good = _qlog_line("rr6.googlevideo.com",
                          _dns_msg("rr6.googlevideo.com",
                                   [_a("85.249.244.49")]), now)
        tail = len(good) + 16                 # хорошая строка влезает целиком
        self._write(["x" * (tail + 100), good])  # файл длиннее хвоста
        with patch.object(mieru_cascade, "_B4_QLOG_TAIL_B", tail):
            ips, _ = mieru_cascade._b4_harvest_querylog(self.DOMS)
        self.assertEqual(ips, {"85.249.244.49"})

    def test_dedup_same_ip_many_queries(self):
        # рекс-шторм: один и тот же хост 20 раз → 1 IP, entries=20
        now = _now()
        msg = _dns_msg("rr2---sn-g5njvh.googlevideo.com",
                       [_a("81.27.242.141")])
        self._write([_qlog_line("rr2---sn-g5njvh.googlevideo.com", msg,
                                now - timedelta(seconds=30 * i))
                     for i in range(20)])
        ips, stats = mieru_cascade._b4_harvest_querylog(self.DOMS)
        self.assertEqual(ips, {"81.27.242.141"})
        self.assertEqual(stats["entries"], 20)
        self.assertEqual(stats["names"], 1)


class TestRefreshMerge(unittest.TestCase):
    """_b4set_refresh: harvest вживлён в снапшот (регрессия «не подключён»).

    Мокаем резолв-виды/ipset и проверяем ipset restore input: harvested
    GGC-IP обязаны попасть в набор ВМЕСТЕ с резолвом, снапшот выживает
    при лежащем резолве (harvest один его тянет), а при пустоте ОБЕИХ
    видов старый набор не перестраивается (guard)."""

    def _run_refresh(self, resolve_ips, harvested):
        st = {"exits": [{"id": "de1", "enabled": True, "healthy": True,
                         "socks_port": 23081}]}
        run_mock = MagicMock()
        sub_run = MagicMock()
        with patch.object(mieru_cascade, "_b4_exempt_domains",
                          return_value=["googlevideo.com"]), \
             patch.object(mieru_cascade, "_b4set_ensure",
                          return_value=True), \
             patch.object(mieru_cascade, "_b4_resolve_ru",
                          return_value=set(resolve_ips)), \
             patch.object(mieru_cascade, "_b4_resolve_via_socks",
                          return_value=set()), \
             patch.object(mieru_cascade, "_b4_harvest_querylog",
                          return_value=(set(harvested),
                                        {"names": 3, "entries": 7,
                                         "ips": len(harvested)})), \
             patch.object(mieru_cascade, "_run", run_mock), \
             patch.object(mieru_cascade.subprocess, "run", sub_run):
            stats = mieru_cascade._b4set_refresh(st, verbose=False)
        restore = [c for c in sub_run.call_args_list
                   if c.args and c.args[0][:2] == ["ipset", "restore"]]
        restored = restore[0].kwargs.get("input", "") if restore else ""
        return stats, restored, run_mock

    def test_merge_resolve_and_harvest(self):
        stats, restored, _ = self._run_refresh(
            ["142.251.38.142"],            # RU-вид (redirector)
            ["85.249.244.49", "81.27.242.141"])   # GGC из querylog
        for ip in ("142.251.38.142", "85.249.244.49", "81.27.242.141"):
            self.assertIn(f"add {mieru_cascade._B4_IPSET_TMP} {ip}\n",
                          restored, f"IP {ip} не попал в снапшот")
        self.assertEqual(stats["ips"], 3)
        self.assertEqual(stats["qlog_ips"], 2)
        self.assertEqual(stats["qlog_names"], 3)
        self.assertEqual(stats["qlog_entries"], 7)

    def test_harvest_keeps_snapshot_alive_when_resolve_down(self):
        # резолв лег (сеть), querylog жив → снапшот всё равно собирается
        _, restored, _ = self._run_refresh([], ["85.249.244.49"])
        self.assertIn("85.249.244.49", restored)

    def test_both_empty_keeps_old_set(self):
        # оба вида пусты → restore/swap не вызываются (старый не трогаем)
        _, restored, run_mock = self._run_refresh([], [])
        self.assertEqual(restored, "")
        swaps = [c for c in run_mock.call_args_list
                 if c.args and c.args[0][:2] == ["ipset", "swap"]]
        self.assertEqual(swaps, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
