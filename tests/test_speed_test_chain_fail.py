#!/usr/bin/env python3
"""
tests/test_speed_test_chain_fail.py
───────────────────────────────────────────────────────────────────────────────
Регрессия живого кейса (окт. 2026, прод-юзер, скриншоты error1/error2):

В шаге 12 «Тест скорости по всем exit-нодам» для via-ноды с УПАВШЕЙ цепочкой
рядом с «Цепочка: недоступна (HTTP 000)» выводился прямой «Download:
25.4 Мбит/с». Но _speed_test_download меряет канал САМОГО entry (замер идёт
напрямую в Cloudflare, минуя ноду) — число маскировало отказ цепочки, и
пользователь решал, что «всё работает».

Ожидаемое поведение после фикса:
  1. Цепочка упала → прямой Download НЕ показывается и НЕ вызывается,
     вместо него — диагноз чекера (reason/detail) и подсказка.
  2. Цепочка жива → скорость печатается из speed_mbps ЧЕРЕЗ цепочку,
     прямой замер тоже не вызывается.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import io
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Фейк chimera._core в sys.modules (эталонный паттерн test_chain_relay)."""
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
    return fake_core


_UUID = "d34df00d-1111-2222-3333-444455556666"

_VIA_NODE = {
    "host": "203.0.113.10", "port": 8443, "uuid": _UUID,
    "pubkey": "Q0hBSU1FUkEtZmFrZS1wYi1rZXktMDAwMDAwMDAwMDA",
    "shortid": "a1b2c3d4e5f60718", "sni": "exit.example.com",
    "fp": "chrome", "flow": "xtls-rprx-vision", "proto": "reality",
    "path": "/", "xhttp_mode": "stream-up", "via": "hop-203-0-113-20",
}

_HOP = {
    "tag": "hop-203-0-113-20", "host": "203.0.113.20", "port": 443,
    "uuid": _UUID, "pubkey": "RkFLRS1yZWFsaXR5LXB1YmxpYy1rZXktMTIzNDU2Nzg",
    "shortid": "0f1e2d3c4b5a6978", "sni": "hop.example.com",
    "fp": "chrome", "flow": "xtls-rprx-vision", "proto": "reality",
    "path": "/", "xhttp_mode": "stream-up", "via": "",
    "comment": "", "enabled": True,
}

_DEAD = {"ok": False, "ms": 0.0, "exit_ip": "", "speed_mbps": 0.0,
         "detail": "хоп «hop-203-0-113-20» жив, нода 203.0.113.10:8443 "
                   "напрямую жива, но с хопа до ноды не достучаться",
         "reason": "хоп→нода недостижима",
         "legs": {"hop": "ok", "direct": "ok"}, "xray_tail": ""}

_ALIVE = {"ok": True, "ms": 412.0, "exit_ip": "203.0.113.10",
          "speed_mbps": 25.4, "detail": "цепочка жива (hop-203-0-113-20 → exit)",
          "reason": "цепь жива", "legs": {}, "xray_tail": ""}


class TestSpeedTestViaFail(unittest.TestCase):

    def setUp(self):
        self._fake_core = _setup_core_in_sysmodules()
        # state.json: режим B, без AWG (иначе уйдёт в AWG-ветку)
        self._state_fh = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False)
        self._state_fh.write('{"install_mode": "B"}')
        self._state_fh.close()
        self._state_path = Path(self._state_fh.name)

    def tearDown(self):
        try:
            self._state_path.unlink(missing_ok=True)
        except Exception:
            pass

    def _run_speed_test(self, chain_result):
        """do_speed_test(auto_mode=True) с замоканным окружением.

        Возвращает (stdout, download_called).
        """
        import chimera.modules.speed_test as st
        import chimera.modules.chain_relay as cr

        dl_calls = []

        def fake_download(*a, **kw):
            dl_calls.append(a)
            return "25.4 Мбит/с (10 МБ за 3.3с)"

        out = io.StringIO()
        with redirect_stdout(out), \
             patch.object(self._fake_core, "STATE_FILE", self._state_path), \
             patch.object(self._fake_core, "_cf_probe_available",
                          lambda *a, **kw: True), \
             patch.object(self._fake_core, "_nodes_from_state",
                          lambda state: [_VIA_NODE]), \
             patch.object(self._fake_core, "_speed_test_node_geo",
                          lambda host: ("203.0.113.10", "DE", "Germany",
                                        "Frankfurt", "Example Hosting AG")), \
             patch.object(self._fake_core, "_speed_test_download",
                          side_effect=fake_download), \
             patch.object(self._fake_core, "log_to_file",
                          lambda *a, **kw: None), \
             patch.object(cr, "load_relay_hops", lambda: [_HOP]), \
             patch.object(cr, "check_via_node_full_path",
                          lambda nd, hops, **kw: dict(chain_result)):
            st.do_speed_test(auto_mode=True)
        return out.getvalue(), dl_calls

    def test_failed_chain_hides_direct_download(self):
        """FAIL цепочки → прямой Download не вызывается и не показывается;
        вместо него — диагноз reason/detail и подсказка."""
        out, dl_calls = self._run_speed_test(_DEAD)
        self.assertEqual(dl_calls, [],
                         "прямой _speed_test_download не должен вызываться "
                         "для via-ноды с упавшей цепочкой")
        self.assertIn("не измерен — цепочка недоступна", out)
        self.assertIn("хоп→нода недостижима", out)
        self.assertIn("не достучаться", out)
        self.assertIn("канал entry, а не нода", out)
        # старый маскирующий вывод отсутствует
        self.assertNotIn("Download: 25.4", out)

    def test_alive_chain_shows_chain_speed(self):
        """Живая цепочка → скорость из speed_mbps ЧЕРЕЗ цепочку, прямой
        замер не вызывается."""
        out, dl_calls = self._run_speed_test(_ALIVE)
        self.assertEqual(dl_calls, [])
        self.assertIn("Download (через цепочку hop-203-0-113-20)", out)
        self.assertIn("25.4 Мбит/с", out)
        self.assertIn("Полный путь", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
