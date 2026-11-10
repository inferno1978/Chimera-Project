#!/usr/bin/env python3
"""
tests/test_hysteria2_quality.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/hysteria2_quality.py.

Покрывает:
  1. _load_history / _save_history — JSON I/O
  2. _append_history — trim до _MAX_HISTORY
  3. (волна-4) h2_quality_report — метки h2_node_label вместо голых ip
     («alias · домен [IP](:порт)», канон node_identity); отправка через
     конвейер _tg_h2_event("h2_quality", …): шапка server_header +
     events-фильтр telegram.json + иконка 📊; полный TUI-текст с шапкой
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("chimera._core")
    m.__dict__.update(g)
    sys.modules["chimera._core"] = m


class TestH2QualityHistory(unittest.TestCase):
    def setUp(self):
        _setup_core()
        self._tmp = Path(tempfile.mkdtemp()); self._f = self._tmp / "h2q.json"
    def tearDown(self):
        import shutil; shutil.rmtree(self._tmp, ignore_errors=True)
    def _patch(self):
        return patch("chimera.modules.hysteria2_quality._HISTORY_FILE", self._f)
    def test_load_empty(self):
        from chimera.modules.hysteria2_quality import _load_history
        with self._patch(): self.assertEqual(_load_history(), {})
    def test_save_load(self):
        from chimera.modules.hysteria2_quality import _load_history, _save_history
        with self._patch():
            _save_history({"1.2.3.4": [{"ts":"x"}]}); self.assertTrue(_load_history()["1.2.3.4"])
    def test_append_trims(self):
        from chimera.modules.hysteria2_quality import _append_history, _load_history, _MAX_HISTORY
        with self._patch():
            for i in range(_MAX_HISTORY + 20):
                _append_history("1.2.3.4", {"ts": str(i)})
            h = _load_history()
        self.assertLessEqual(len(h["1.2.3.4"]), _MAX_HISTORY)


# ══════════════════════════════════════════════════════════════════════════════
#  Волна-4 (11.11.2026): h2_quality_report — метки h2_node_label (канон
#  node_identity «alias · домен [IP](:порт)») вместо голых ip:port + отправка
#  через конвейер _tg_h2_event("h2_quality"). Паттерн герметичности:
#  test_hysteria2_common._H2TmpBase / test_hysteria2_balancer (волны 1-3) —
#  канон-тесты с предзаполненным DNS-кэшем без getent: state/TG-конфиг/лог/
#  история/DNS-кэш на tmp, замеры и транспорт подменены, боевой TG не зовётся.
# ══════════════════════════════════════════════════════════════════════════════

class _QualityTmpBase(unittest.TestCase):
    """Все пути hysteria2_common/quality/node_identity — tmp; замеры и
    TG-транспорт — моки (QUIC-ping/UDP-burst и curl не выполняются)."""

    def setUp(self):
        _setup_core()
        import time as _time
        from chimera.modules import hysteria2_common as hc
        from chimera.modules import hysteria2_quality as hq
        from chimera.modules import node_identity as _ni
        self._hc = hc
        self._hq = hq
        self._ni = _ni
        self._now = _time.time()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(self._rmtree)
        patches = [
            patch.object(hc, "STATE_FILE", self.tmp / "state.json"),
            patch.object(hc, "TG_CONFIG_FILE", self.tmp / "telegram.json"),
            patch.object(hc, "LOG_FILE", self.tmp / "chimera.log"),
            patch.object(hq, "_HISTORY_FILE",
                         self.tmp / "h2_quality_history.json"),
            # node_identity: прод-файлы НЕ должны протекать в тесты
            # (герметичность на живых нодах — паттерн 652e692/71605f2)
            patch.object(_ni, "STATE_FILE", self.tmp / "ni_state.json"),
            patch.object(_ni, "TG_FILE", self.tmp / "tg-absent.json"),
            patch.object(_ni, "DNS_CACHE_FILE", self.tmp / "node_dns_cache.json"),
            patch.object(_ni, "ALIASES_FILE", self.tmp / "aliases-absent.json"),
        ]
        _ni._MEM.clear()
        self.addCleanup(_ni._MEM.clear)
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

        # hostname -s внутри _tg_h2_event — без реального subprocess
        class _Res:
            def __init__(self, stdout=""):
                self.stdout = stdout
                self.returncode = 0

        def fake_run(cmd, **kw):
            argv = cmd if isinstance(cmd, list) else list(cmd)
            if argv and argv[0] == "hostname":
                return _Res("testhost\n")
            return _Res("")

        r_ = patch.object(hc, "_run", side_effect=fake_run)
        r_.start()
        self.addCleanup(r_.stop)

        # TG-транспорт — перехват: боевой curl не зовётся
        self.sent: list[str] = []
        t_ = patch.object(hc, "_tg_send",
                          side_effect=lambda msg: self.sent.append(msg) or True)
        t_.start()
        self.addCleanup(t_.stop)

    def _rmtree(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_tg(self, events: dict | None = None):
        cfg = {"token": "TESTTOKEN", "chat_id": "12345"}
        if events is not None:
            cfg["events"] = events
        (self.tmp / "telegram.json").write_text(json.dumps(cfg))

    def _fill_dns(self, host: str, ip: str):
        """Предзаполненный DNS-кэш node_identity (без getent)."""
        (self.tmp / "node_dns_cache.json").write_text(json.dumps(
            {host: {"ip": ip, "ts": self._now}}))
        self._ni._MEM.clear()

    def _write_nodes(self, nodes: list[dict]):
        (self.tmp / "state.json").write_text(json.dumps(
            {"hysteria2": {"exit_nodes": nodes}}))

    @staticmethod
    def _fake_measure(node: dict) -> dict:
        """Фейковый замер качества (без сети): отличные метрики."""
        from datetime import datetime
        ports = node.get("ports") or [443]
        return {
            "ip": node.get("ip", ""),
            "port": ports[0] if ports else 443,
            "rtt_min": 10, "rtt_avg": 20, "rtt_max": 30,
            "loss_pct": 0, "speed_mbps": 100.0, "up": True,
            "ts": datetime.now().isoformat(),
        }

    def _patch_measure(self):
        return patch.object(self._hq, "_measure_node_quality",
                            side_effect=self._fake_measure)


class TestH2QualityReportLabels(_QualityTmpBase):
    """h2_quality_report: ноды в отчёте — метками h2_node_label (волна-4)."""

    def test_down_node_label_with_name(self):
        """DOWN-строка — метка «имя · IP» вместо голого ip."""
        self._write_tg()
        self._write_nodes([
            {"ip": "203.0.113.77", "ports": [443], "name": "H2-77",
             "status": "down"},
        ])
        with self._patch_measure():
            report = self._hq.h2_quality_report(send_tg=False)
        self.assertIn("🔴 <b>H2-77 · 203.0.113.77</b> — DOWN", report)
        # голого ip в DOWN-строке больше нет
        self.assertNotIn("🔴 <b>203.0.113.77</b>", report)

    def test_up_node_label_name_and_port(self):
        """UP-строка — метка с именем и нестандартным портом, порт не дублируется."""
        self._write_tg()
        self._write_nodes([
            {"ip": "203.0.113.78", "ports": [8443], "name": "H2-78"},
        ])
        with self._patch_measure():
            report = self._hq.h2_quality_report(send_tg=False)
        self.assertIn("<b>H2-78 · 203.0.113.78:8443</b>  🟢 отлично", report)
        # прежний формат «голый ip:port» без имени не возвращается
        self.assertNotIn("<b>203.0.113.78:8443</b>", report)

    def test_domain_node_resolved_via_cache(self):
        """Домен + предзаполненный DNS-кэш → «имя · домен [IP]» (без getent)."""
        self._write_tg()
        self._fill_dns("node-h2q.example.com", "203.0.113.79")
        self._write_nodes([
            {"ip": "node-h2q.example.com", "ports": [443], "name": "H2-Q"},
        ])
        with self._patch_measure():
            report = self._hq.h2_quality_report(send_tg=False)
        self.assertIn("<b>H2-Q · node-h2q.example.com [203.0.113.79]</b>", report)

    def test_report_keeps_full_tui_text(self):
        """Возвращаемый текст — полный, с прежней шапкой и датой (для TUI)."""
        self._write_tg()
        self._write_nodes([
            {"ip": "203.0.113.78", "ports": [443], "name": "H2-78"},
        ])
        with self._patch_measure():
            report = self._hq.h2_quality_report(send_tg=False)
        self.assertIn("📊 <b>Hysteria2 Quality Report</b>", report)
        self.assertIn("<i>", report)          # дата
        self.assertIn("RTT: avg=20ms", report)  # метрики замера

    def test_label_fallback_when_common_unavailable(self):
        """hysteria2_common недоступен → фолбэк на прежний «ip»/«ip:port»."""
        self._write_tg()
        self._write_nodes([
            {"ip": "203.0.113.78", "ports": [8443], "name": "H2-78"},
        ])
        import sys as _sys
        with self._patch_measure(), \
                patch.dict(_sys.modules, {"chimera.modules.hysteria2_common": None}):
            report = self._hq.h2_quality_report(send_tg=False)
        self.assertIn("<b>203.0.113.78:8443</b>", report)


class TestH2QualityReportTg(_QualityTmpBase):
    """h2_quality_report(send_tg=True): конвейер _tg_h2_event("h2_quality")."""

    def test_send_via_tg_h2_event(self):
        """send_tg=True → _tg_send вызван через _tg_h2_event: шапка + иконка,
        payload — строки отчёта без старой шапки «📊 Quality Report»."""
        self._write_tg()
        self._write_nodes([
            {"ip": "203.0.113.78", "ports": [443], "name": "H2-78"},
        ])
        with self._patch_measure():
            self._hq.h2_quality_report(send_tg=True)
        self.assertEqual(len(self.sent), 1)
        msg = self.sent[0]
        self.assertTrue(msg.startswith("📊"), msg)          # иконка h2_quality
        self.assertIn("[testhost] Hysteria2", msg)          # шапка конвейера
        self.assertIn("<b>H2-78 · 203.0.113.78</b>", msg)  # метка в payload
        self.assertIn("RTT: avg=20ms", msg)
        # шапку отчёта конвейер НЕ дублирует (её даёт server_header + иконка)
        self.assertNotIn("Hysteria2 Quality Report", msg)

    def test_muted_when_event_disabled(self):
        """events.h2_quality == false → уведа НЕ отправляется."""
        self._write_tg(events={"h2_quality": False})
        self._write_nodes([
            {"ip": "203.0.113.78", "ports": [443], "name": "H2-78"},
        ])
        with self._patch_measure():
            report = self._hq.h2_quality_report(send_tg=True)
        self.assertEqual(self.sent, [])
        # TUI-отчёт при этом возвращается как обычно
        self.assertIn("Hysteria2 Quality Report", report)

    def test_sent_when_event_enabled(self):
        """events.h2_quality == true (явно) → отправляется."""
        self._write_tg(events={"h2_quality": True})
        self._write_nodes([
            {"ip": "203.0.113.78", "ports": [443], "name": "H2-78"},
        ])
        with self._patch_measure():
            self._hq.h2_quality_report(send_tg=True)
        self.assertEqual(len(self.sent), 1)

# ── hysteria2_dpi ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
