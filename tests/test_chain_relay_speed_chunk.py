#!/usr/bin/env python3
"""
tests/test_chain_relay_speed_chunk.py
───────────────────────────────────────────────────────────────────────────────
Регрессия живого кейса (окт. 2026, №15): «Download (через цепочку): не измерен»
для via-нод в speed-test — при выборе 1000 МБ (want_speed_mb=min(1000,100)=100)
единственный запрос __down?bytes=104857600 получал HTTP 403 с телом 1 байт
(жёсткий потолок endpoint: 99_999_999 → 200 OK, 100_000_000 → 403), curl без
--fail отдавал rc=0, порог «≥100 КБ скачано» не проходил никогда →
speed_mbps=0 → «не измерен».

После фикса: socks_cf_download_mbps() качает want_mb МБ последовательными
запросами по ≤90 МиБ через SOCKS5 временного xray-клиента; скорость =
сумма байт / сумма времени; при обрыве — частичный результат (≥1 МБ).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

import chimera.modules.chain_relay as cr   # noqa: E402


_CHUNK = 90 * 1024 * 1024                  # CF_DOWN_CHUNK_BYTES (chain_nodes)


def _make_completed(rc=0, stdout="", stderr=""):
    return MagicMock(returncode=rc, stdout=stdout, stderr=stderr)


class TestSocksCfDownloadMbps(unittest.TestCase):

    def _run_with(self, responses, want_mb, cf_ip=None):
        """socks_cf_download_mbps с очередью фейковых subprocess.run.

        Возвращает (speed_mbps, список curl-команд).
        """
        cmds = []
        queue = list(responses)

        def fake_run(cmd, *a, **kw):
            cmds.append(cmd)
            rc, out = queue.pop(0) if queue else (0, "0 0.0 0 200")
            return _make_completed(rc=rc, stdout=out)

        with patch.object(cr.subprocess, "run", side_effect=fake_run):
            mbps = cr.socks_cf_download_mbps(1080, want_mb, cf_ip=cf_ip)
        return mbps, cmds

    def test_10mb_single_request_through_socks(self):
        """10 МБ — один запрос bytes=10485760 через socks5h-прокси."""
        mbps, cmds = self._run_with(
            [(0, "10485760 1.0 10485760 200")], 10)
        self.assertAlmostEqual(mbps, 83.9, places=1)
        self.assertEqual(len(cmds), 1)
        self.assertIn("-x", cmds[0])
        self.assertIn("socks5h://127.0.0.1:1080", cmds[0])
        self.assertIn("bytes=10485760", cmds[0][-1])

    def test_100mb_two_chunks_summed(self):
        """100 МБ — два чанка (90 МиБ + 10 МиБ), скорость по сумме."""
        mbps, cmds = self._run_with([
            (0, f"{_CHUNK} 8.0 {_CHUNK} 200"),
            (0, "10485760 1.0 10485760 200"),
        ], 100)
        # 104857600 Б / 9.0 с → 93.2 Мбит/с
        self.assertAlmostEqual(mbps, 93.2, places=1)
        self.assertEqual(len(cmds), 2)
        self.assertIn(f"bytes={_CHUNK}", cmds[0][-1])
        self.assertIn("bytes=10485760", cmds[1][-1])

    def test_403_yields_zero_not_garbage(self):
        """403 с телом 1 байт (старый кейс) → 0.0, а не мусорная скорость."""
        mbps, cmds = self._run_with([(0, "1 0.03 33 403")], 100)
        self.assertEqual(mbps, 0.0)
        # повторных запросов сверх первого отказавшегося чанка не нужно
        self.assertEqual(len(cmds), 1)

    def test_all_fail_returns_zero(self):
        """Сеть умерла (rc=28 на первом чанке) → 0.0 («не измерен»)."""
        mbps, _ = self._run_with([(28, "")], 100)
        self.assertEqual(mbps, 0.0)

    def test_partial_failure_keeps_partial_result(self):
        """Обрыв после первого чанка → частичная скорость (>0)."""
        mbps, cmds = self._run_with([
            (0, f"{_CHUNK} 8.0 {_CHUNK} 200"),
            (28, ""),
        ], 100)
        self.assertAlmostEqual(mbps, 94.4, places=1)   # 94371840*8/8.0/1e6
        self.assertEqual(len(cmds), 2)

    def test_cf_ip_passed_to_resolve(self):
        """cf_ip (DoH) → --resolve speed.cloudflare.com:443:<ip> в curl."""
        _, cmds = self._run_with(
            [(0, "10485760 1.0 10485760 200")], 10, cf_ip="104.16.0.1")
        self.assertIn("--resolve", cmds[0])
        self.assertIn("speed.cloudflare.com:443:104.16.0.1", cmds[0])

    def test_subprocess_exception_breaks_gracefully(self):
        """subprocess.run бросил исключение (таймаут) → частичный/нулевой
        результат без трейсба наружу."""
        def boom(cmd, *a, **kw):
            raise RuntimeError("subprocess timeout")
        with patch.object(cr.subprocess, "run", side_effect=boom):
            mbps = cr.socks_cf_download_mbps(1080, 100)
        self.assertEqual(mbps, 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
