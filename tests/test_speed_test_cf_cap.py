#!/usr/bin/env python3
"""
tests/test_speed_test_cf_cap.py
───────────────────────────────────────────────────────────────────────────────
Регрессия живого кейса (окт. 2026, №15, прод-юзер):

В speed-test (Режим B, «Тест скорости по всем exit-нодам») выбор 100/500/1000 МБ
вечно давал «Download: Cloudflare недоступен с сервера — тестируйте на клиенте
(fast.com)», при этом 10 МБ работал. Корень: жёсткий потолок endpoint
speed.cloudflare.com/__down — bytes≥100_000_000 отвечает HTTP 403 с телом
1 байт (замер: 99_999_999 → 200 OK; 100_000_000 → 403), а curl без --fail
отдавал rc=0, и старый код по «скачано <1 КБ» ставил ложный диагноз
«недоступен». Режим A страдал дефолтом (Enter = 100 МБ), via-ноды — вечным
«Download (через цепочку): не измерен» (см. test_chain_relay_speed_chunk.py).

Ожидаемое поведение после фикса (_speed_test_download):
  1. 10 МБ — один запрос bytes=10485760 (как раньше, регрессия).
  2. 100 МБ — два последовательных запроса ≤90 МиБ; скорость = сумма байт /
     сумма времени.
  3. 1000 МБ — 11 запросов, каждый ≤90 МиБ.
  4. HTTP 403 — честный диагноз «отклонён … потолок», НЕ «недоступен».
  5. Обрыв в середине — частичный результат (если ≥1 МБ скачано).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Фейковый chimera._core (эталонный паттерн test_speed_test_cf_doh)."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core, g


def _make_completed(rc=0, stdout="", stderr=""):
    return MagicMock(returncode=rc, stdout=stdout, stderr=stderr)


def _patch_doh(return_value):
    """Патчит chain_nodes._resolve_host_fresh (DoH-резолв)."""
    from chimera.modules import chain_nodes
    return patch.object(chain_nodes, "_resolve_host_fresh",
                        return_value=return_value)


_CHUNK = 90 * 1024 * 1024          # 94371840 — CF_DOWN_CHUNK_BYTES


class _CapTest(unittest.TestCase):
    def setUp(self):
        self._fake_core, self._g = _setup_core_in_sysmodules()

    def _dl(self, size_mb, responses):
        """_speed_test_download с очередью фейковых curl-ответов.

        responses — список (rc, stdout); каждый элемент выдаётся на очередной
        вызов _run. Возвращает (строка-результат, список curl-команд).
        """
        cmds = []
        queue = list(responses)

        def fake_run(cmd, *a, **kw):
            cmds.append(cmd)
            rc, out = queue.pop(0) if queue else (0, "0 0.0 0 200")
            return _make_completed(rc=rc, stdout=out)

        with _patch_doh("104.16.0.1"), \
             patch.dict(self._g, {"_run": fake_run}):
            result = self._g["_speed_test_download"](
                "speed.cloudflare.com", "1.1.1.1", 443, size_mb)
        return result, cmds

    @staticmethod
    def _url(cmd):
        return cmd[-1]


class TestSmallSizeSingleRequest(_CapTest):
    """10 МБ — по-прежнему один запрос (регрессия разбиения)."""

    def test_10mb_single_request(self):
        result, cmds = self._dl(10, [(0, "10485760 1.0 10485760 200")])
        self.assertIn("Мбит/с", result)
        self.assertIn("83.9", result)      # 10485760*8/1.0/1e6
        self.assertEqual(len(cmds), 1)
        self.assertIn("bytes=10485760", self._url(cmds[0]))
        self.assertIn("--resolve", cmds[0])


class TestChunking(_CapTest):
    """Объём выше потолка ~100 МБ режется на последовательные чанки ≤90 МиБ."""

    def test_100mb_two_chunks_summed_speed(self):
        result, cmds = self._dl(100, [
            (0, f"{_CHUNK} 8.0 {_CHUNK} 200"),       # 90 МиБ за 8 с
            (0, "10485760 1.0 10485760 200"),        # 10 МиБ за 1 с
        ])
        # сумма: 104857600 Б за 9.0 с → 93.2 Мбит/с, 100 МБ
        self.assertIn("93.2", result)
        self.assertIn("100 МБ за 9.0с", result)
        self.assertEqual(len(cmds), 2)
        self.assertIn(f"bytes={_CHUNK}", self._url(cmds[0]))
        self.assertIn("bytes=10485760", self._url(cmds[1]))

    def test_1000mb_twelve_chunks_all_below_cap(self):
        big = _CHUNK
        # 1000 МБ = 1_048_576_000 Б → 11 полных чанков по 90 МиБ + хвост 10 МиБ
        responses = [(0, f"{big} 8.0 {big} 200")] * 11 + \
                    [(0, "10485760 1.0 10485760 200")]
        result, cmds = self._dl(1000, responses)
        self.assertEqual(len(cmds), 12)
        for cmd in cmds:
            b = int(self._url(cmd).split("bytes=")[1])
            self.assertLessEqual(b, big)
            self.assertGreaterEqual(b, 1024 * 1024)
        # 1_048_576_000 Б за 89.0 с → 94.3 Мбит/с, ровно 1000 МБ
        self.assertIn("94.3", result)
        self.assertIn("1000 МБ за 89.0с", result)

    def test_partial_failure_returns_partial_result(self):
        """Первый чан OK, второй rc=28 → честный частичный результат."""
        result, cmds = self._dl(100, [
            (0, f"{_CHUNK} 8.0 {_CHUNK} 200"),
            (28, ""),                              # обрыв сети
        ])
        self.assertIn("94.4", result)               # 94371840*8/8.0/1e6
        self.assertIn("90 МБ за 8.0с", result)
        self.assertEqual(len(cmds), 2)


class TestHonestDiagnosis(_CapTest):
    """403 от endpoint — «отклонён», а не «недоступен» (ядро кейса №15)."""

    def test_403_reported_as_rejection(self):
        result, cmds = self._dl(100, [(0, "1 0.03 33 403")])
        self.assertIn("Cloudflare отклонил запрос", result)
        self.assertIn("HTTP 403", result)
        self.assertIn("потолок", result)
        self.assertNotIn("недоступен с сервера", result)
        # запрос был ОДИН и ≤90 МиБ — чанкинг не должен сам напрашиваться на 403
        self.assertEqual(len(cmds), 1)
        self.assertIn(f"bytes={_CHUNK}", self._url(cmds[0]))

    def test_network_error_no_partial(self):
        """curl rc!=0 на первом же чанке → ошибка curl, без «недоступен»."""
        result, _ = self._dl(100, [(7, "")])        # rc=7 — connection refused
        self.assertIn("ошибка curl", result)
        self.assertIn("7", result)

    def test_tiny_body_no_http_code_still_unavailable(self):
        """Старый формат вывода (3 поля, без http_code) → прежний вердикт."""
        result, _ = self._dl(10, [(0, "0 0.1 0")])
        self.assertIn("Cloudflare недоступен", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
