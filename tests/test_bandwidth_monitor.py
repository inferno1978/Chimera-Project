#!/usr/bin/env python3
"""tests/test_bandwidth_monitor.py — unit-тесты для bandwidth_monitor."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    if "chimera._core" in sys.modules:
        return
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    if not core_path.exists():
        return
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


class TestConfigManagement(unittest.TestCase):
    """Конфиг: load/save/default merge."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor
        self._tmp = Path(tempfile.mkdtemp())
        self._cfg_file = self._tmp / "bw.json"
        self._patch_cfg = patch.object(self._m, "CONFIG_FILE", self._cfg_file)
        self._patch_cfg.start()

    def tearDown(self):
        self._patch_cfg.stop()
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_defaults_when_no_config(self):
        cfg = self._m.load_config()
        self.assertTrue(cfg["enabled"])
        self.assertEqual(cfg["sample_interval_min"], 30)
        self.assertEqual(cfg["report_interval_hours"], 6)
        self.assertIn("thresholds", cfg)
        # Политика флота 08.11.2026: ≥1G зелёный, <100M красный
        self.assertEqual(cfg["thresholds"]["normal_mbps"], 1000.0)
        self.assertEqual(cfg["thresholds"]["degraded_mbps"], 100.0)
        self.assertEqual(cfg["level_mode"], "absolute")
        self.assertFalse(cfg["alert_degraded"])

    def test_save_and_load(self):
        cfg = self._m.load_config()
        cfg["sample_interval_min"] = 15
        cfg["thresholds"]["normal_mbps"] = 200.0
        self._m.save_config(cfg)
        loaded = self._m.load_config()
        self.assertEqual(loaded["sample_interval_min"], 15)
        self.assertEqual(loaded["thresholds"]["normal_mbps"], 200.0)

    def test_thresholds_merge(self):
        """Частичный thresholds в конфиге — merge с дефолтами."""
        self._cfg_file.write_text(json.dumps({
            "thresholds": {"normal_mbps": 150.0}
        }))
        cfg = self._m.load_config()
        # normal из конфига
        self.assertEqual(cfg["thresholds"]["normal_mbps"], 150.0)
        # degraded из дефолта (не указан в конфиге)
        self.assertEqual(cfg["thresholds"]["degraded_mbps"], 100.0)


def _probe_result(speed_bps, source="cloudflare", peak_bps=None, streams=6,
                  probe_mb=60.0):
    """Фикстура результата _run_download_probe для тестов."""
    return {"speed_bps": speed_bps, "peak_bps": peak_bps, "source": source,
            "streams": streams, "probe_mb": probe_mb, "ookla": None}


class TestMeasureOnce(unittest.TestCase):
    """measure_once — классификация по порогам (без базлайна → absolute)."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor

    def test_classifies_critical_de_case_1564_is_normal(self):
        """Кейс DE 08.11.2026: 1564 Mbps на 5G-порту — ЗЕЛЁНЫЙ,
        а не ⚠️-алерт, как было в auto-режиме от базлайна."""
        cfg = {**self._m.DEFAULT_CONFIG}
        with patch.object(self._m, "_baseline_mbps", return_value=5000.0):
            self.assertEqual(self._m._classify_level(1564.33, cfg), "normal")

    def test_classifies_absolute_bands(self):
        """Политика флота: ≥1000 normal, 100-1000 degraded, <100 critical."""
        cfg = {**self._m.DEFAULT_CONFIG}
        with patch.object(self._m, "_baseline_mbps", return_value=None):
            self.assertEqual(self._m._classify_level(1000.0, cfg), "normal")
            self.assertEqual(self._m._classify_level(4790.0, cfg), "normal")
            self.assertEqual(self._m._classify_level(999.9, cfg), "degraded")
            self.assertEqual(self._m._classify_level(100.0, cfg), "degraded")
            self.assertEqual(self._m._classify_level(99.9, cfg), "critical")
            self.assertEqual(self._m._classify_level(16.0, cfg), "critical")

    def test_classifies_normal(self):
        """Скорость ≥ normal_mbps → level=normal (базлайна нет → absolute)."""
        with patch.object(self._m, "_ping_latency", return_value=2.5), \
             patch.object(self._m, "_run_download_probe",
                          return_value=_probe_result(150_000_000)), \
             patch.object(self._m, "_baseline_mbps", return_value=None), \
             patch.object(self._m, "_node_hostname", return_value="test-host"), \
             patch.object(self._m, "_node_public_ip", return_value="1.2.3.4"), \
             patch.object(self._m, "load_config",
                          return_value={**self._m.DEFAULT_CONFIG,
                                        "node_label": "TEST",
                                        "node_ip": "1.2.3.4"}):
            s = self._m.measure_once(big=False)
        # 150 MB/s = 1200 Mbps → normal (≥1000, политика флота 08.11.2026)
        self.assertEqual(s["level"], "normal")
        self.assertAlmostEqual(s["download_mbps"], 1200.0, places=1)
        self.assertEqual(s["label"], "TEST")
        self.assertFalse(s["big"])
        # новые поля методики
        self.assertEqual(s["streams"], 6)
        self.assertEqual(s["download_source"], "cloudflare")

    def test_classifies_degraded(self):
        """Скорость 100-1000 Mbps → level=degraded (жёлтый)."""
        with patch.object(self._m, "_ping_latency", return_value=5.0), \
             patch.object(self._m, "_run_download_probe",
                          return_value=_probe_result(25_000_000)), \
             patch.object(self._m, "_baseline_mbps", return_value=None), \
             patch.object(self._m, "_node_hostname", return_value="h"), \
             patch.object(self._m, "_node_public_ip", return_value="1.2.3.4"), \
             patch.object(self._m, "load_config",
                          return_value=self._m.DEFAULT_CONFIG):
            s = self._m.measure_once(big=False)
        # 25 MB/s = 200 Mbps → degraded (100-1000)
        self.assertEqual(s["level"], "degraded")
        self.assertAlmostEqual(s["download_mbps"], 200.0, places=1)

    def test_classifies_critical(self):
        """Скорость < 100 Mbps → level=critical (хостер обрезал)."""
        with patch.object(self._m, "_ping_latency", return_value=10.0), \
             patch.object(self._m, "_run_download_probe",
                          return_value=_probe_result(2_000_000)), \
             patch.object(self._m, "_baseline_mbps", return_value=None), \
             patch.object(self._m, "_node_hostname", return_value="h"), \
             patch.object(self._m, "_node_public_ip", return_value="1.2.3.4"), \
             patch.object(self._m, "load_config",
                          return_value=self._m.DEFAULT_CONFIG):
            s = self._m.measure_once(big=False)
        # 2 MB/s = 16 Mbps → critical (<100)
        self.assertEqual(s["level"], "critical")
        self.assertAlmostEqual(s["download_mbps"], 16.0, places=1)

    def test_big_flag(self):
        """big=True → big=True в сэмпле."""
        with patch.object(self._m, "_ping_latency", return_value=2.0), \
             patch.object(self._m, "_run_download_probe",
                          return_value=_probe_result(20_000_000, streams=8,
                                                     probe_mb=760.0)), \
             patch.object(self._m, "_baseline_mbps", return_value=None), \
             patch.object(self._m, "_node_hostname", return_value="h"), \
             patch.object(self._m, "_node_public_ip", return_value="1.2.3.4"), \
             patch.object(self._m, "load_config",
                          return_value=self._m.DEFAULT_CONFIG):
            s = self._m.measure_once(big=True)
        self.assertTrue(s["big"])
        self.assertEqual(s["streams"], 8)

    def test_ookla_fields_propagate(self):
        """Ookla-результат протаскивается в сэмпл (ul/server)."""
        probe = _probe_result(2_065_000_000, source="ookla", streams=1,
                              probe_mb=0.0)
        probe["ookla"] = {"dl_mbps": 16520.0, "ul_mbps": 19672.0,
                          "latency_ms": 3.68, "server": "fdcservers — Amsterdam"}
        with patch.object(self._m, "_ping_latency", return_value=3.68), \
             patch.object(self._m, "_run_download_probe", return_value=probe), \
             patch.object(self._m, "_baseline_mbps", return_value=None), \
             patch.object(self._m, "_node_hostname", return_value="h"), \
             patch.object(self._m, "_node_public_ip", return_value="1.2.3.4"), \
             patch.object(self._m, "load_config",
                          return_value=self._m.DEFAULT_CONFIG):
            s = self._m.measure_once(big=True)
        self.assertEqual(s["download_source"], "ookla")
        self.assertAlmostEqual(s["download_mbps"], 16520.0, places=1)
        self.assertEqual(s["ookla_ul_mbps"], 19672.0)
        self.assertIn("Amsterdam", s["ookla_server"])


class TestSteadyAndPeak(unittest.TestCase):
    """_steady_and_peak — отброс разгона + пик в скользящем окне 1 с."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor

    def test_steady_discards_ramp(self):
        # t0=100.0; разгон (первые 0.4 c) даёт 50 MB, дальше 0.9 c — 150 MB
        events = [(100.2, 25_000_000), (100.4, 50_000_000),
                  (100.9, 100_000_000), (101.4, 200_000_000)]
        steady, peak = self._m._steady_and_peak(events, t0=100.0, duration=1.4)
        # ramp_t=100.5 → cum_at_ramp=50MB; (200-50)MB за (101.4-100.5)=0.9 c
        self.assertAlmostEqual(steady, 150_000_000 / 0.9, places=1)
        # пик: окно [100.4, 101.4] → (200-25)MB / 1.0 c
        self.assertAlmostEqual(peak, 175_000_000.0, places=1)

    def test_short_transfer_plain_avg(self):
        """Замер короче отбрасываемого разгона → простое среднее."""
        events = [(100.1, 60_000_000)]
        steady, peak = self._m._steady_and_peak(events, t0=100.0, duration=0.1)
        self.assertAlmostEqual(steady, 600_000_000.0, places=1)
        self.assertAlmostEqual(peak, 60_000_000.0, places=1)


class TestParallelDownloadOne(unittest.TestCase):
    """_parallel_download_one — потоки, бюджет, события (без сети)."""

    _conns = []

    class _FakeResp:
        def __init__(self, chunk_count):
            self._n = chunk_count
        def read(self, n):
            if self._n > 0:
                self._n -= 1
                return b"x" * 65536
            return b""

    class _FakeConn:
        CHUNKS = 1000
        def __init__(self, host, timeout=None):
            TestParallelDownloadOne._conns.append(self)
            self.resp = TestParallelDownloadOne._FakeResp(self.CHUNKS)
        def request(self, *a, **kw):
            pass
        def getresponse(self):
            return self.resp
        def close(self):
            pass

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor
        TestParallelDownloadOne._conns = []
        TestParallelDownloadOne._FakeConn.CHUNKS = 1000
        self._patch_conn = patch.object(self._m, "HTTPSConnection",
                                        TestParallelDownloadOne._FakeConn)
        self._patch_conn.start()

    def tearDown(self):
        self._patch_conn.stop()

    def test_budget_split_across_streams(self):
        """2 потока, бюджет 2 MB → каждый читает ~1 MB и останавливается."""
        res = self._m._parallel_download_one(
            "https://speed.cloudflare.com/__down?bytes=1000000",
            streams=2, budget_bytes=2_000_000, active_cap=10)
        self.assertIsNotNone(res)
        self.assertEqual(res["streams"], 2)
        # per_stream = 1MB → по 16 блоков × 65536 на поток
        self.assertEqual(res["total_bytes"], 2 * 16 * 65536)
        self.assertGreater(res["speed_bps"], 0)
        self.assertEqual(len(self._conns), 2)

    def test_all_streams_empty_returns_none(self):
        """Ни один поток не получил байта → None."""
        TestParallelDownloadOne._FakeConn.CHUNKS = 0
        res = self._m._parallel_download_one(
            "https://speed.cloudflare.com/__down?bytes=1000000",
            streams=3, budget_bytes=3_000_000, active_cap=10)
        self.assertIsNone(res)


class TestOoklaParser(unittest.TestCase):
    """_ookla_test — парсинг JSON Ookla CLI."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor

    def _fake_run(self, rc=0, stdout=""):
        obj = SimpleNamespace(returncode=rc, stdout=stdout, stderr="")
        return patch.object(self._m, "_run", return_value=obj)

    def test_parses_ookla_json(self):
        payload = json.dumps({
            "download": {"bandwidth": 2_065_000_000},   # B/s → 16520 Mbps
            "upload": {"bandwidth": 2_459_000_000},     # B/s → 19672 Mbps
            "ping": {"latency": 3.68},
            "server": {"name": "fdcservers", "location": "Amsterdam"},
        })
        with patch.object(self._m.shutil, "which",
                          return_value="/usr/bin/speedtest"), \
             self._fake_run(0, payload):
            res = self._m._ookla_test()
        self.assertAlmostEqual(res["dl_mbps"], 16520.0, places=0)
        self.assertAlmostEqual(res["ul_mbps"], 19672.0, places=0)
        self.assertEqual(res["latency_ms"], 3.68)
        self.assertIn("fdcservers", res["server"])

    def test_missing_binary(self):
        with patch.object(self._m.shutil, "which", return_value=None):
            self.assertIsNone(self._m._ookla_test())

    def test_nonzero_exit(self):
        with patch.object(self._m.shutil, "which",
                          return_value="/usr/bin/speedtest"), \
             self._fake_run(1, ""):
            self.assertIsNone(self._m._ookla_test())


class TestRunDownloadProbe(unittest.TestCase):
    """Диспетчер методики: ookla → параллельные потоки → легаси-однопоток."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor

    def test_ookla_wins_when_enabled_big(self):
        cfg = {**self._m.DEFAULT_CONFIG, "use_ookla": True}
        ook = {"dl_mbps": 16520.0, "ul_mbps": 19672.0,
               "latency_ms": 3.68, "server": "fdcservers — Amsterdam"}
        with patch.object(self._m, "_ookla_test", return_value=ook) as pook:
            res = self._m._run_download_probe(cfg, big=True)
        pook.assert_called_once()
        self.assertEqual(res["source"], "ookla")
        self.assertAlmostEqual(res["speed_bps"] * 8 / 1e6, 16520.0, places=1)
        self.assertEqual(res["ookla"], ook)

    def test_ookla_not_used_for_light(self):
        cfg = {**self._m.DEFAULT_CONFIG, "use_ookla": True}
        par = {"speed_bps": 500_000_000, "peak_bps": 700_000_000,
               "source": "cloudflare", "total_bytes": 60_000_000,
               "duration": 1.0, "streams": 6}
        with patch.object(self._m, "_ookla_test") as pook, \
             patch.object(self._m, "_parallel_download", return_value=par) as ppar:
            res = self._m._run_download_probe(cfg, big=False)
        pook.assert_not_called()
        ppar.assert_called_once()
        self.assertEqual(res["streams"], 6)
        self.assertEqual(res["source"], "cloudflare")

    def test_single_stream_legacy(self):
        cfg = {**self._m.DEFAULT_CONFIG, "parallel_streams": 1}
        with patch.object(self._m, "_parallel_download") as ppar, \
             patch.object(self._m, "_try_download",
                          return_value=(15_000_000, "cachefly")) as pcur:
            res = self._m._run_download_probe(cfg, big=False)
        ppar.assert_not_called()
        pcur.assert_called_once()
        self.assertEqual(res["streams"], 1)
        self.assertEqual(res["source"], "cachefly")

    def test_parallel_failure_falls_back_to_curl(self):
        """Все параллельные источники упали → откат на однопотоковый curl."""
        cfg = {**self._m.DEFAULT_CONFIG}
        with patch.object(self._m, "_parallel_download", return_value=None), \
             patch.object(self._m, "_try_download",
                          return_value=(10_000_000, "testdebit")):
            res = self._m._run_download_probe(cfg, big=True)
        self.assertEqual(res["source"], "testdebit")
        self.assertEqual(res["streams"], 1)


class TestBaselineClassification(unittest.TestCase):
    """_classify_level auto-режим (opt-in): базлайн-медиана 24ч."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor

    def test_auto_fast_port_cut_is_critical(self):
        """Кейс №16 (auto): обрез 16.5G → ~1G = critical."""
        cfg = {**self._m.DEFAULT_CONFIG, "level_mode": "auto"}
        with patch.object(self._m, "_baseline_mbps", return_value=9000.0):
            self.assertEqual(self._m._classify_level(950.0, cfg), "critical")

    def test_auto_half_baseline_is_normal(self):
        cfg = {**self._m.DEFAULT_CONFIG, "level_mode": "auto"}
        with patch.object(self._m, "_baseline_mbps", return_value=9000.0):
            self.assertEqual(self._m._classify_level(5000.0, cfg), "normal")

    def test_auto_quarter_baseline_is_degraded(self):
        cfg = {**self._m.DEFAULT_CONFIG, "level_mode": "auto"}
        with patch.object(self._m, "_baseline_mbps", return_value=9000.0):
            self.assertEqual(self._m._classify_level(2000.0, cfg), "degraded")

    def test_auto_falls_back_to_absolute_without_baseline(self):
        """Нет базлайна — абсолютные пороги политики флота (1000/100)."""
        cfg = {**self._m.DEFAULT_CONFIG, "level_mode": "auto"}
        with patch.object(self._m, "_baseline_mbps", return_value=None):
            self.assertEqual(self._m._classify_level(1200.0, cfg), "normal")
            self.assertEqual(self._m._classify_level(200.0, cfg), "degraded")
            self.assertEqual(self._m._classify_level(60.0, cfg), "critical")
            self.assertEqual(self._m._classify_level(16.0, cfg), "critical")

    def test_absolute_mode_ignores_baseline(self):
        """Дефолт absolute: базлайн не зовётся, пороги фиксированные."""
        cfg = {**self._m.DEFAULT_CONFIG, "level_mode": "absolute"}
        with patch.object(self._m, "_baseline_mbps", return_value=9000.0) as pbl:
            self.assertEqual(self._m._classify_level(1200.0, cfg), "normal")
            self.assertEqual(self._m._classify_level(950.0, cfg), "degraded")
        pbl.assert_not_called()

    def test_baseline_median_from_samples(self):
        """_baseline_mbps: медиана по файлам сэмплов + окно + min_samples."""
        import shutil as _sh
        import tempfile
        import time as _t
        tmp = Path(tempfile.mkdtemp())
        patcher = patch.object(self._m, "SAMPLES_DIR", tmp)
        patcher.start()
        try:
            self.assertIsNone(self._m._baseline_mbps())  # сэмплов нет
            now = int(_t.time())
            rows = []
            # 5 свежих (медиана 8600) + 2 вне окна (не считаются)
            for v in (9000, 8800, 8600, 500, 8400):
                rows.append({"epoch": now - 60, "download_mbps": v})
            for v in (99999, 88888):
                rows.append({"epoch": now - 30 * 86400, "download_mbps": v})
            f = tmp / (_t.strftime("%Y-%m-%d") + ".jsonl")
            f.write_text("\n".join(json.dumps(r) for r in rows),
                         encoding="utf-8")
            self.assertAlmostEqual(self._m._baseline_mbps(), 8600.0)
        finally:
            patcher.stop()
            _sh.rmtree(tmp, ignore_errors=True)


class TestAlertFastPortCut(unittest.TestCase):
    """Кейс №16 (auto, opt-in): обрез 16.5G → ~1G должен давать
    critical-алерт в auto-режиме; в дефолтном absolute тот же обрез —
    жёлтый статус без мгновенного пуша (политика флота 08.11.2026)."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor

    def test_cut_triggers_critical_alert(self):
        cfg = {**self._m.DEFAULT_CONFIG, "alerts_enabled": True,
               "level_mode": "auto"}
        with patch.object(self._m, "_baseline_mbps", return_value=9000.0):
            level = self._m._classify_level(950.0, cfg)
        self.assertEqual(level, "critical")
        sample = {"level": level, "download_mbps": 950, "label": "test",
                  "ip": "1.2.3.4", "ts": "2026-11-08T10:00:00",
                  "latency_ms": 4.0, "latency_target": "1.1.1.1"}
        recent = [{"download_mbps": 1100, "level": "critical"},
                  {"download_mbps": 990, "level": "critical"}]
        with patch.object(self._m, "read_samples", return_value=recent), \
             patch.object(self._m, "_load_tg_state", return_value={}), \
             patch.object(self._m, "_save_tg_state"):
            result = self._m._check_alert(sample, cfg)
        self.assertIsNotNone(result)
        self.assertIn("КРИТИЧНО", result)

    def test_cut_950_silent_in_default_absolute(self):
        """Дефолт (absolute): обрез до 950 Mbps = degraded → БЕЗ алерта
        (жёлтый не пушится); статус виден в отчётах."""
        cfg = {**self._m.DEFAULT_CONFIG, "alerts_enabled": True}
        level = self._m._classify_level(950.0, cfg)
        self.assertEqual(level, "degraded")
        sample = {"level": level, "download_mbps": 950, "label": "test",
                  "ip": "1.2.3.4", "ts": "2026-11-08T10:00:00",
                  "latency_ms": 4.0, "latency_target": "1.1.1.1"}
        recent = [{"download_mbps": 900, "level": "degraded"},
                  {"download_mbps": 950, "level": "degraded"}]
        with patch.object(self._m, "read_samples", return_value=recent), \
             patch.object(self._m, "_load_tg_state", return_value={}), \
             patch.object(self._m, "_save_tg_state"):
            result = self._m._check_alert(sample, cfg)
        self.assertIsNone(result)


class TestAlertLogic(unittest.TestCase):
    """_check_alert — алерты: critical пушится, degraded — нет (дефолт)."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor

    def test_no_alert_for_normal(self):
        cfg = {**self._m.DEFAULT_CONFIG, "alerts_enabled": True}
        sample = {"level": "normal", "download_mbps": 150, "label": "test",
                  "ip": "1.2.3.4", "ts": "2026-10-13T10:00:00",
                  "latency_ms": 2.0, "latency_target": "1.1.1.1"}
        with patch.object(self._m, "read_samples", return_value=[]):
            result = self._m._check_alert(sample, cfg)
        self.assertIsNone(result)

    def test_alert_for_critical_with_consecutive(self):
        cfg = {**self._m.DEFAULT_CONFIG, "alerts_enabled": True}
        sample = {"level": "critical", "download_mbps": 30, "label": "test",
                  "ip": "1.2.3.4", "ts": "2026-10-13T10:00:00",
                  "latency_ms": 5.0, "latency_target": "1.1.1.1"}
        # 2 предыдущих сэмпла тоже critical
        recent = [
            {"download_mbps": 20, "level": "critical"},
            {"download_mbps": 25, "level": "critical"},
        ]
        with patch.object(self._m, "read_samples", return_value=recent), \
             patch.object(self._m, "_load_tg_state", return_value={}), \
             patch.object(self._m, "_save_tg_state"):
            result = self._m._check_alert(sample, cfg)
        self.assertIsNotNone(result)
        self.assertIn("КРИТИЧНО", result)
        self.assertIn("30 Mbps", result)

    def test_no_alert_cooldown(self):
        """Anti-spam: если последний алерт был недавно — не дублировать."""
        cfg = {**self._m.DEFAULT_CONFIG, "alerts_enabled": True}
        sample = {"level": "critical", "download_mbps": 30, "label": "test",
                  "ip": "1.2.3.4", "ts": "2026-10-13T10:00:00"}
        recent = [{"download_mbps": 20}, {"download_mbps": 25}]
        # последний алерт 10 минут назад (cooldown 180 мин)
        import time
        state = {"last_alert_epoch": int(time.time()) - 600}
        with patch.object(self._m, "read_samples", return_value=recent), \
             patch.object(self._m, "_load_tg_state", return_value=state), \
             patch.object(self._m, "_save_tg_state"):
            result = self._m._check_alert(sample, cfg)
        self.assertIsNone(result)

    def test_no_alert_without_consecutive(self):
        """Если только 1 сэмпл < degraded, а предыдущие норм — не алертить."""
        cfg = {**self._m.DEFAULT_CONFIG, "alerts_enabled": True}
        sample = {"level": "critical", "download_mbps": 30, "label": "test",
                  "ip": "1.2.3.4", "ts": "2026-10-13T10:00:00"}
        # предыдущие нормальные
        recent = [
            {"download_mbps": 200, "level": "normal"},
            {"download_mbps": 150, "level": "normal"},
        ]
        with patch.object(self._m, "read_samples", return_value=recent), \
             patch.object(self._m, "_load_tg_state", return_value={}), \
             patch.object(self._m, "_save_tg_state"):
            result = self._m._check_alert(sample, cfg)
        self.assertIsNone(result)

    def test_no_alert_for_degraded_by_default(self):
        """Политика флота 08.11.2026: жёлтый (100-1000) не пушится —
        даже при 2 сэмплах подряд и вне кулдауна (кейс DE 1564 Mbps)."""
        cfg = {**self._m.DEFAULT_CONFIG, "alerts_enabled": True}
        sample = {"level": "degraded", "download_mbps": 700, "label": "test",
                  "ip": "1.2.3.4", "ts": "2026-11-08T08:30:06"}
        recent = [
            {"download_mbps": 800, "level": "degraded"},
            {"download_mbps": 700, "level": "degraded"},
        ]
        with patch.object(self._m, "read_samples", return_value=recent), \
             patch.object(self._m, "_load_tg_state", return_value={}), \
             patch.object(self._m, "_save_tg_state"):
            result = self._m._check_alert(sample, cfg)
        self.assertIsNone(result)

    def test_alert_for_degraded_when_opt_in(self):
        """alert_degraded=true (opt-in) — жёлтый пушится как ВНИМАНИЕ."""
        cfg = {**self._m.DEFAULT_CONFIG, "alerts_enabled": True,
               "alert_degraded": True}
        sample = {"level": "degraded", "download_mbps": 700, "label": "test",
                  "ip": "1.2.3.4", "ts": "2026-11-08T08:30:06",
                  "latency_ms": 3.0, "latency_target": "1.1.1.1"}
        recent = [
            {"download_mbps": 800, "level": "degraded"},
            {"download_mbps": 700, "level": "degraded"},
        ]
        with patch.object(self._m, "read_samples", return_value=recent), \
             patch.object(self._m, "_load_tg_state", return_value={}), \
             patch.object(self._m, "_save_tg_state"):
            result = self._m._check_alert(sample, cfg)
        self.assertIsNotNone(result)
        self.assertIn("ВНИМАНИЕ", result)


class TestDailyReportClassification(unittest.TestCase):
    """send_daily_report: классификация дня по полным замерам, если есть
    (лёгкая проба — нижняя оценка; NL 16.5G даёт ~830 Mbps лёгкой пробой
    при 2.4G+ полной — вечное «жёлтое ВНИМАНИЕ» на живом порту)."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _samples(self, light, big):
        rows = [{"download_mbps": v, "level": "degraded", "big": False,
                 "label": "t", "ip": "1.2.3.4", "latency_ms": 4.0}
                for v in light]
        rows += [{"download_mbps": v, "level": "normal", "big": True,
                  "label": "t", "ip": "1.2.3.4", "latency_ms": 4.0}
                 for v in big]
        return rows

    def test_day_level_prefers_big_samples(self):
        """Лёгкие ~830 (жёлтые) + полный 2400 → день ЗЕЛЁНЫЙ."""
        cfg = {**self._m.DEFAULT_CONFIG}
        with patch.object(self._m, "load_config", return_value=cfg), \
             patch.object(self._m, "read_samples",
                          return_value=self._samples([700, 800, 900],
                                                      [2400])), \
             patch.object(self._m, "_tg_send", return_value=True), \
             patch.object(self._m, "REPORTS_DIR", self._tmp), \
             patch.object(self._m, "_log"):
            text = self._m.send_daily_report(send_tg=False)
        self.assertIn("НОРМА", text)

    def test_day_level_all_samples_when_no_big(self):
        """Полных нет — день по всем сэмплам (avg 800 → ВНИМАНИЕ)."""
        cfg = {**self._m.DEFAULT_CONFIG}
        with patch.object(self._m, "load_config", return_value=cfg), \
             patch.object(self._m, "read_samples",
                          return_value=self._samples([700, 800, 900], [])), \
             patch.object(self._m, "_tg_send", return_value=True), \
             patch.object(self._m, "REPORTS_DIR", self._tmp), \
             patch.object(self._m, "_log"):
            text = self._m.send_daily_report(send_tg=False)
        self.assertIn("ВНИМАНИЕ", text)

    def test_day_level_cut_to_sub100_is_critical(self):
        """Обрез канала < 100 Mbps → день КРИТИЧНО (красный)."""
        cfg = {**self._m.DEFAULT_CONFIG}
        with patch.object(self._m, "load_config", return_value=cfg), \
             patch.object(self._m, "read_samples",
                          return_value=self._samples([40, 60], [80])), \
             patch.object(self._m, "_tg_send", return_value=True), \
             patch.object(self._m, "REPORTS_DIR", self._tmp), \
             patch.object(self._m, "_log"):
            text = self._m.send_daily_report(send_tg=False)
        self.assertIn("КРИТИЧНО", text)


class TestSamplesStorage(unittest.TestCase):
    """save_sample / read_samples — хранение."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor
        self._tmp = Path(tempfile.mkdtemp())
        self._samples_dir = self._tmp / "samples"
        self._patch = patch.object(self._m, "SAMPLES_DIR", self._samples_dir)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_save_and_read(self):
        sample = {"ts": "2026-10-13T10:00:00", "epoch": 1791800000,
                  "label": "test", "download_mbps": 150, "level": "normal"}
        self._m.save_sample(sample)
        samples = self._m.read_samples(
            date_str=time.strftime("%Y-%m-%d")) if False else self._m.read_samples(days=1)
        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0]["download_mbps"], 150)

    def test_read_nonexistent(self):
        """Если файла нет — пустой список."""
        samples = self._m.read_samples(date_str="2099-01-01")
        self.assertEqual(samples, [])


class TestInstallUninstall(unittest.TestCase):
    """install/uninstall — cron + wrappers."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor
        self._tmp = Path(tempfile.mkdtemp())
        self._patch_cron = patch.object(self._m, "CRON_FILE", self._tmp / "cron")
        self._patch_sample = patch.object(self._m, "SAMPLE_SCRIPT", self._tmp / "sample.sh")
        self._patch_report = patch.object(self._m, "REPORT_SCRIPT", self._tmp / "report.sh")
        self._patch_daily = patch.object(self._m, "DAILY_SCRIPT", self._tmp / "daily.sh")
        self._patch_cfg = patch.object(self._m, "CONFIG_FILE", self._tmp / "bw.json")
        for p in (self._patch_cron, self._patch_sample, self._patch_report,
                  self._patch_daily, self._patch_cfg):
            p.start()

    def tearDown(self):
        for p in (self._patch_cron, self._patch_sample, self._patch_report,
                  self._patch_daily, self._patch_cfg):
            p.stop()
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_install_creates_files(self):
        ok, msg = self._m.install_bandwidth_monitor()
        self.assertTrue(ok)
        self.assertTrue((self._tmp / "cron").exists())
        self.assertTrue((self._tmp / "sample.sh").exists())
        self.assertTrue((self._tmp / "report.sh").exists())
        self.assertTrue((self._tmp / "daily.sh").exists())
        # cron содержит 3 строки правил
        cron_text = (self._tmp / "cron").read_text()
        self.assertIn("sample.sh", cron_text)
        self.assertIn("report.sh", cron_text)
        self.assertIn("daily.sh", cron_text)

    def test_uninstall_removes_files(self):
        self._m.install_bandwidth_monitor()
        ok, msg = self._m.uninstall_bandwidth_monitor()
        self.assertTrue(ok)
        self.assertFalse((self._tmp / "cron").exists())
        self.assertFalse((self._tmp / "sample.sh").exists())

    def test_is_installed(self):
        self.assertFalse(self._m.is_monitor_installed())
        self._m.install_bandwidth_monitor()
        self.assertTrue(self._m.is_monitor_installed())


class TestTgConfig(unittest.TestCase):
    """_load_tg_config — загрузка token/chat из telegram.json или tg_bot.json."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor
        self._tmp = Path(tempfile.mkdtemp())
        self._patch_tg = patch.object(self._m, "TG_CONFIG", self._tmp / "telegram.json")
        self._patch_bot = patch.object(self._m, "TG_BOT_CFG", self._tmp / "tg_bot.json")
        self._patch_tg.start()
        self._patch_bot.start()

    def tearDown(self):
        self._patch_tg.stop()
        self._patch_bot.stop()
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_load_from_telegram_json(self):
        (self._tmp / "telegram.json").write_text(json.dumps({
            "token": "abc:123", "chat_id": "999", "proxy": "http://127.0.0.1:25181"
        }))
        token, chat, proxy = self._m._load_tg_config()
        self.assertEqual(token, "abc:123")
        self.assertEqual(chat, "999")
        self.assertEqual(proxy, "http://127.0.0.1:25181")

    def test_load_from_tg_bot_json(self):
        (self._tmp / "tg_bot.json").write_text(json.dumps({
            "token": "xyz:456", "admin_id": "888"
        }))
        token, chat, proxy = self._m._load_tg_config()
        self.assertEqual(token, "xyz:456")
        self.assertEqual(chat, "888")
        self.assertEqual(proxy, "")  # tg_bot.json не имеет proxy

    def test_no_config_returns_empty(self):
        token, chat, proxy = self._m._load_tg_config()
        self.assertEqual(token, "")
        self.assertEqual(chat, "")
        self.assertEqual(proxy, "")


# ══════════════════════════════════════════════════════════════════════════════
#  PORT_MBPS — учёт порта канала (08.11.2026)
# ══════════════════════════════════════════════════════════════════════════════

class TestPortParse(unittest.TestCase):
    """_parse_port_mbps — парсер TUI-ввода порта."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor

    def test_plain_number_is_mbps(self):
        self.assertEqual(self._m._parse_port_mbps("1000"), 1000.0)
        self.assertEqual(self._m._parse_port_mbps("16500"), 16500.0)
        self.assertEqual(self._m._parse_port_mbps(" 950 "), 950.0)

    def test_g_suffix(self):
        self.assertEqual(self._m._parse_port_mbps("1g"), 1000.0)
        self.assertEqual(self._m._parse_port_mbps("2.5G"), 2500.0)
        self.assertEqual(self._m._parse_port_mbps("16.5g"), 16500.0)

    def test_m_and_k_suffix(self):
        self.assertEqual(self._m._parse_port_mbps("500m"), 500.0)
        self.assertEqual(self._m._parse_port_mbps("100Mbps"), 100.0)
        self.assertEqual(self._m._parse_port_mbps("1gbps"), 1000.0)
        # 100k = 0.1 Mbps — бессмыслица для порта, валидатор режет
        self.assertIsNone(self._m._parse_port_mbps("100k"))

    def test_cyrillic_and_comma(self):
        """Запятая как разделитель + кириллические суффиксы/хвосты."""
        self.assertEqual(self._m._parse_port_mbps("16,5г"), 16500.0)
        self.assertEqual(self._m._parse_port_mbps("1г"), 1000.0)
        self.assertEqual(self._m._parse_port_mbps("100мбит"), 100.0)

    def test_zero_resets(self):
        """0 — явный сброс («порт не задан»), а не мусор."""
        self.assertEqual(self._m._parse_port_mbps("0"), 0.0)

    def test_garbage_returns_none(self):
        for bad in ("", "abc", "-5", "1t", "тысяча", "10 20", "1.2.3"):
            self.assertIsNone(self._m._parse_port_mbps(bad), repr(bad))

    def test_out_of_range_returns_none(self):
        self.assertIsNone(self._m._parse_port_mbps("2000000g"))

    def test_port_mbps_cfg_validation(self):
        """_port_mbps: мусор/отрицательное/0 → 0 (не задан)."""
        self.assertEqual(self._m._port_mbps({}), 0.0)
        self.assertEqual(self._m._port_mbps({"port_mbps": 0}), 0.0)
        self.assertEqual(self._m._port_mbps({"port_mbps": "garbage"}), 0.0)
        self.assertEqual(self._m._port_mbps({"port_mbps": -100}), 0.0)
        self.assertEqual(self._m._port_mbps({"port_mbps": 5000}), 5000.0)

    def test_fmt_port(self):
        self.assertEqual(self._m._fmt_port(16500.0), "16500 Mbps (16.5G)")
        self.assertEqual(self._m._fmt_port(5000.0), "5000 Mbps (5G)")
        self.assertEqual(self._m._fmt_port(950.0), "950 Mbps")


class TestPortClassification(unittest.TestCase):
    """_classify_level с port_mbps — пороги относительно ПОРТА."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor

    def test_1g_user_950_is_normal(self):
        """ГЛАВНЫЙ кейс: 950 Mbps на порту 1000 (Ethernet-потолок ~95%)
        = ЗЕЛЁНЫЙ, а не вечное жёлтое от флот-порога 1000."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 1000}
        self.assertEqual(self._m._classify_level(950.0, cfg, big=True), "normal")

    def test_port_band_boundaries(self):
        """Порт 1000: ≥700 normal, 200-700 degraded, <200 critical."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 1000}
        self.assertEqual(self._m._classify_level(700.0, cfg, big=True), "normal")
        self.assertEqual(self._m._classify_level(699.9, cfg, big=True), "degraded")
        self.assertEqual(self._m._classify_level(200.0, cfg, big=True), "degraded")
        self.assertEqual(self._m._classify_level(199.9, cfg, big=True), "critical")

    def test_de_case_5g_port(self):
        """DE: порт 5000 — 4800 normal (96%), 1564 degraded (31%),
        900 critical (18% — «гигабит есть» больше не зелёный)."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 5000}
        self.assertEqual(self._m._classify_level(4800.0, cfg, big=True), "normal")
        self.assertEqual(self._m._classify_level(1564.33, cfg, big=True), "degraded")
        self.assertEqual(self._m._classify_level(900.0, cfg, big=True), "critical")

    def test_light_probe_stays_fleet_absolute(self):
        """Лёгкая проба — флот-политика даже при заданном порте:
        проверка живости, не замер порта (нулевая регрессия нод)."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 1000}
        self.assertEqual(self._m._classify_level(950.0, cfg, big=False), "degraded")
        self.assertEqual(self._m._classify_level(1200.0, cfg, big=False), "normal")
        self.assertEqual(self._m._classify_level(80.0, cfg, big=False), "critical")

    def test_fat_port_http_not_verified(self):
        """Порт 16.5G > PROBE_VERIFIABLE_MAX: HTTP-полный замер НЕ
        верифицирован → флот-политика (2400 → normal; NL не краснеет
        от структурного потолка пробы)."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 16500}
        self.assertEqual(self._m._classify_level(2400.0, cfg, big=True), "normal")
        self.assertEqual(self._m._classify_level(80.0, cfg, big=True), "critical")

    def test_fat_port_ookla_verified(self):
        """Тот же порт, но Ookla (verified) меряет честно: 16500 → normal,
        обрез до 2400 (15%) → critical — правдиво для >5G портов."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 16500}
        self.assertEqual(self._m._classify_level(16500.0, cfg, big=True,
                                                 verified=True), "normal")
        self.assertEqual(self._m._classify_level(2400.0, cfg, big=True,
                                                 verified=True), "critical")

    def test_port_zero_unchanged(self):
        """port_mbps=0/отсутствует — прежняя семантика absolute."""
        cfg = {**self._m.DEFAULT_CONFIG}
        with patch.object(self._m, "_baseline_mbps", return_value=None):
            self.assertEqual(self._m._classify_level(950.0, cfg, big=True), "degraded")
            self.assertEqual(self._m._classify_level(1200.0, cfg, big=True), "normal")

    def test_port_overrides_auto_for_big(self):
        """Порт + auto: для полных замеров порт — ground truth лучше
        базлайна (auto-кейс №16: 950 при базлайне 9000 был critical;
        при порте 1000 это normal — порт и есть истина)."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 1000,
               "level_mode": "auto"}
        with patch.object(self._m, "_baseline_mbps", return_value=9000.0):
            self.assertEqual(self._m._classify_level(950.0, cfg, big=True), "normal")
            # лёгкая проба в auto — по-прежнему базлайн
            self.assertEqual(self._m._classify_level(950.0, cfg, big=False), "critical")

    def test_custom_port_ratios(self):
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 1000,
               "port_normal_ratio": 0.9, "port_degraded_ratio": 0.5}
        self.assertEqual(self._m._classify_level(950.0, cfg, big=True), "normal")
        self.assertEqual(self._m._classify_level(600.0, cfg, big=True), "degraded")
        self.assertEqual(self._m._classify_level(400.0, cfg, big=True), "critical")

    def test_port_thresholds_active_matrix(self):
        base = {**self._m.DEFAULT_CONFIG}
        self.assertFalse(self._m._port_thresholds_active(base, big=True, verified=False))
        cfg = {**base, "port_mbps": 1000}
        self.assertTrue(self._m._port_thresholds_active(cfg, big=True, verified=False))
        self.assertFalse(self._m._port_thresholds_active(cfg, big=False, verified=False))
        self.assertTrue(self._m._port_thresholds_active(cfg, big=False, verified=True))
        fat = {**base, "port_mbps": 16500}
        self.assertFalse(self._m._port_thresholds_active(fat, big=True, verified=False))
        self.assertTrue(self._m._port_thresholds_active(fat, big=True, verified=True))


class TestPortProbeScaling(unittest.TestCase):
    """_run_download_probe — масштабирование потоков/бюджета под порт."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor

    def _probe_with(self, cfg, big):
        par = {"speed_bps": 500_000_000, "peak_bps": 700_000_000,
               "source": "cloudflare", "total_bytes": 60_000_000,
               "duration": 1.0, "streams": 6}
        with patch.object(self._m, "_parallel_download", return_value=par) as ppar:
            res = self._m._run_download_probe(cfg, big=big)
        kwargs = ppar.call_args[0]
        return res, kwargs

    def test_1g_port_unchanged(self):
        """Порт 1G → полный замер БЕЗ изменений: 8 потоков, 760 MB
        (текущая методика уже наполняет 1G-порт)."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 1000}
        res, (src, streams, budget, cap) = self._probe_with(cfg, big=True)
        self.assertEqual(streams, 8)
        self.assertEqual(budget, 760_000_000)
        self.assertEqual(res["streams"], 8)
        self.assertEqual(res["probe_mb"], 760.0)

    def test_5g_port_scales_streams_and_budget(self):
        """Порт 5G → ceil(5000/500)=10 потоков, бюджет 10×95=950 MB."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 5000}
        res, (src, streams, budget, cap) = self._probe_with(cfg, big=True)
        self.assertEqual(streams, 10)
        self.assertEqual(budget, 950_000_000)
        self.assertEqual(res["probe_mb"], 950.0)

    def test_16g_port_caps_at_16_streams(self):
        """Порт 16.5G → потолок 16 потоков (как Ookla), бюджет 1520 MB."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 16500}
        res, (src, streams, budget, cap) = self._probe_with(cfg, big=True)
        self.assertEqual(streams, 16)
        self.assertEqual(budget, 1_520_000_000)
        self.assertEqual(res["probe_mb"], 1520.0)

    def test_light_scales_modestly(self):
        """Лёгкая проба: ceil(порт/1000) зажат 6-12, бюджет прежний 60 MB."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 1000}
        res, (src, streams, budget, cap) = self._probe_with(cfg, big=False)
        self.assertEqual(streams, 6)
        self.assertEqual(budget, 60_000_000)
        cfg16 = {**self._m.DEFAULT_CONFIG, "port_mbps": 16500}
        res, (src, streams, budget, cap) = self._probe_with(cfg16, big=False)
        self.assertEqual(streams, 12)
        self.assertEqual(budget, 60_000_000)

    def test_explicit_streams_pin_wins(self):
        """Явный parallel_streams — пин юзера: без скейлинга и без
        раздувания бюджета."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 16500,
               "parallel_streams": 8}
        res, (src, streams, budget, cap) = self._probe_with(cfg, big=True)
        self.assertEqual(streams, 8)
        self.assertEqual(budget, 760_000_000)

    def test_no_port_unchanged(self):
        """Без порта — прежние дефолты (лёгкая 6, полный 8)."""
        cfg = {**self._m.DEFAULT_CONFIG}
        _, (src, streams, budget, cap) = self._probe_with(cfg, big=False)
        self.assertEqual(streams, 6)
        _, (src, streams, budget, cap) = self._probe_with(cfg, big=True)
        self.assertEqual(streams, 8)
        self.assertEqual(budget, 760_000_000)


class TestPortMeasureOnce(unittest.TestCase):
    """measure_once с портом: уровень для полных замеров — порт-пороги,
    сэмпл несёт port_mbps; лёгкая проба — флот-политика."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor

    def test_big_sample_port_level(self):
        """Порт 1000, полный замер 950 Mbps → normal + port_mbps в сэмпле."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 1000,
               "node_label": "T", "node_ip": "1.2.3.4"}
        with patch.object(self._m, "_ping_latency", return_value=2.0), \
             patch.object(self._m, "_run_download_probe",
                          return_value=_probe_result(118_750_000, streams=8,
                                                     probe_mb=760.0)), \
             patch.object(self._m, "_baseline_mbps", return_value=None), \
             patch.object(self._m, "_node_hostname", return_value="h"), \
             patch.object(self._m, "_node_public_ip", return_value="1.2.3.4"), \
             patch.object(self._m, "load_config", return_value=cfg):
            s = self._m.measure_once(big=True)
        self.assertEqual(s["level"], "normal")
        self.assertAlmostEqual(s["download_mbps"], 950.0, places=1)
        self.assertEqual(s["port_mbps"], 1000.0)
        self.assertTrue(s["big"])

    def test_light_sample_fleet_level_with_port(self):
        """Тот же порт, лёгкая проба 950 Mbps → degraded (флот), port_mbps
        всё равно в сэмпле (контекст для истории/TUI)."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 1000,
               "node_label": "T", "node_ip": "1.2.3.4"}
        with patch.object(self._m, "_ping_latency", return_value=2.0), \
             patch.object(self._m, "_run_download_probe",
                          return_value=_probe_result(118_750_000, streams=6,
                                                     probe_mb=60.0)), \
             patch.object(self._m, "_baseline_mbps", return_value=None), \
             patch.object(self._m, "_node_hostname", return_value="h"), \
             patch.object(self._m, "_node_public_ip", return_value="1.2.3.4"), \
             patch.object(self._m, "load_config", return_value=cfg):
            s = self._m.measure_once(big=False)
        self.assertEqual(s["level"], "degraded")
        self.assertEqual(s["port_mbps"], 1000.0)
        self.assertFalse(s["big"])

    def test_no_port_no_field(self):
        """Без порта поле port_mbps в сэмпл не пишется (обратная совместимость)."""
        with patch.object(self._m, "_ping_latency", return_value=2.0), \
             patch.object(self._m, "_run_download_probe",
                          return_value=_probe_result(150_000_000)), \
             patch.object(self._m, "_baseline_mbps", return_value=None), \
             patch.object(self._m, "_node_hostname", return_value="h"), \
             patch.object(self._m, "_node_public_ip", return_value="1.2.3.4"), \
             patch.object(self._m, "load_config",
                          return_value=self._m.DEFAULT_CONFIG):
            s = self._m.measure_once(big=False)
        self.assertNotIn("port_mbps", s)


class TestPortDailyReport(unittest.TestCase):
    """Дневной отчёт с портом: классификация дня (по полным замерам)
    относительно ПОРТА — 1G-юзер видит НОРМА на 950 Mbps."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _samples(self, light, big):
        rows = [{"download_mbps": v, "level": "degraded", "big": False,
                 "label": "t", "ip": "1.2.3.4", "latency_ms": 4.0}
                for v in light]
        rows += [{"download_mbps": v, "level": "normal", "big": True,
                  "label": "t", "ip": "1.2.3.4", "latency_ms": 4.0}
                 for v in big]
        return rows

    def _daily(self, cfg, samples):
        with patch.object(self._m, "load_config", return_value=cfg), \
             patch.object(self._m, "read_samples", return_value=samples), \
             patch.object(self._m, "_tg_send", return_value=True), \
             patch.object(self._m, "REPORTS_DIR", self._tmp), \
             patch.object(self._m, "_log"):
            return self._m.send_daily_report(send_tg=False)

    def test_day_1g_port_950_is_normal(self):
        """ГЛАВНЫЙ кейс: порт 1000, полные 920-950 → день НОРМА
        (без порта те же числа = ВНИМАНИЕ от флот-порога 1000)."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 1000}
        text = self._daily(cfg, self._samples([900, 930], [920, 950, 940]))
        self.assertIn("НОРМА", text)
        # footnote несёт порт и производные пороги
        self.assertIn("порт 1000 Mbps", text)
        self.assertIn("≥700/≥200", text)
        # а без порта — прежнее поведение (регресс-фиксатор)
        text2 = self._daily({**self._m.DEFAULT_CONFIG},
                            self._samples([900, 930], [920, 950, 940]))
        self.assertIn("ВНИМАНИЕ", text2)

    def test_day_5g_port_cut_is_critical(self):
        """Порт 5000, полные ~900 (18% порта) → день КРИТИЧНО,
        хотя «гигабит есть» (без порта было бы ВНИМАНИЕ)."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 5000}
        text = self._daily(cfg, self._samples([850, 880], [900, 910]))
        self.assertIn("КРИТИЧНО", text)
        self.assertIn("порт 5000 Mbps (5G)", text)

    def test_day_fat_port_http_absolute(self):
        """Порт 16.5G: дневная классификация по полным HTTP-замерам —
        флот-политика (не верифицировано), footnote с портом."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 16500}
        text = self._daily(cfg, self._samples([800, 850], [2400, 2500]))
        self.assertIn("НОРМА", text)
        self.assertIn("порт 16500 Mbps (16.5G)", text)


class TestPortPeriodicReport(unittest.TestCase):
    """Периодический отчёт с портом: строка порта + подсказка про Ookla."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _big_sample(self, **extra):
        s = {"ts": "2026-11-08T12:00:00", "label": "T", "ip": "1.2.3.4",
             "download_mbps": 4800, "download_source": "cloudflare",
             "peak_mbps": 5200, "streams": 10, "probe_mb": 950.0,
             "latency_ms": 4.0, "latency_target": "1.1.1.1",
             "level": "normal", "big": True}
        s.update(extra)
        return s

    def _report(self, cfg, sample):
        with patch.object(self._m, "load_config", return_value=cfg), \
             patch.object(self._m, "measure_once", return_value=sample), \
             patch.object(self._m, "read_samples", return_value=[]), \
             patch.object(self._m, "_tg_send", return_value=True), \
             patch.object(self._m, "REPORTS_DIR", self._tmp), \
             patch.object(self._m, "_log"), \
             patch.object(self._m, "save_sample"):
            return self._m.send_periodic_report()

    def test_report_shows_port_line(self):
        """Отчёт несёт строку «Порт канала» и масштабированный замер."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 5000}
        text = self._report(cfg, self._big_sample())
        self.assertIn("Порт канала: <b>5000 Mbps (5G)</b>", text)
        self.assertIn("10 потоков", text)
        self.assertIn("~950 MB", text)
        self.assertNotIn("Ookla (use_ookla)", text)

    def test_fat_port_hint(self):
        """Порт > 5G + HTTP-замер → подсказка включить Ookla."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 16500}
        text = self._report(cfg, self._big_sample(
            download_mbps=2400, streams=16, probe_mb=1520.0))
        self.assertIn("Порт канала: <b>16500 Mbps (16.5G)</b>", text)
        self.assertIn("HTTP-проба даёт только нижнюю оценку", text)
        self.assertIn("use_ookla", text)

    def test_fat_port_ookla_no_hint(self):
        """Тот же порт, но замер Ookla — подсказка не нужна (число честное)."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 16500}
        text = self._report(cfg, self._big_sample(
            download_mbps=16526, download_source="ookla", streams=1,
            probe_mb=0.0, peak_mbps=None))
        self.assertIn("Ookla speedtest", text)
        self.assertNotIn("нижнюю оценку", text)

    def test_no_port_no_port_line(self):
        cfg = {**self._m.DEFAULT_CONFIG}
        text = self._report(cfg, self._big_sample(streams=8, probe_mb=760.0))
        self.assertNotIn("Порт канала", text)


class TestPortAlert(unittest.TestCase):
    """Алерты при порт-порогах: critical-текст честно называет порт."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor

    def _alert(self, sample, cfg):
        recent = [{"download_mbps": 900, "level": "critical"},
                  {"download_mbps": 950, "level": "critical"}]
        with patch.object(self._m, "read_samples", return_value=recent), \
             patch.object(self._m, "_load_tg_state", return_value={}), \
             patch.object(self._m, "_save_tg_state"):
            return self._m._check_alert(sample, cfg)

    def test_port_critical_names_port(self):
        """Обрез 5G-порта до 900: текст «при порте 5000 Mbps … ~в 6x»."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 5000,
               "alerts_enabled": True}
        sample = {"level": "critical", "download_mbps": 900, "label": "DE",
                  "ip": "1.2.3.4", "ts": "2026-11-08T12:00:00",
                  "latency_ms": 4.0, "latency_target": "1.1.1.1",
                  "big": True, "download_source": "cloudflare"}
        result = self._alert(sample, cfg)
        self.assertIsNotNone(result)
        self.assertIn("КРИТИЧНО", result)
        self.assertIn("при порте 5000 Mbps (5G)", result)
        self.assertIn("~в 6x", result)

    def test_fat_port_http_critical_keeps_fleet_text(self):
        """Порт 16.5G, HTTP-полный замер 80 Mbps → critical по флот-порогу
        (не верифицирован) — прежний текст про < 100 Mbps."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 16500,
               "alerts_enabled": True}
        sample = {"level": "critical", "download_mbps": 80, "label": "NL",
                  "ip": "1.2.3.4", "ts": "2026-11-08T12:00:00",
                  "big": True, "download_source": "cloudflare"}
        result = self._alert(sample, cfg)
        self.assertIsNotNone(result)
        self.assertIn("ниже 100 Mbps", result)
        self.assertNotIn("при порте", result)

    def test_1g_port_yellow_not_pushed(self):
        """Порт 1000, полный замер 500 Mbps (50%) → degraded — БЕЗ пуша
        (политика: пуш только critical < 20% порта)."""
        cfg = {**self._m.DEFAULT_CONFIG, "port_mbps": 1000,
               "alerts_enabled": True}
        sample = {"level": "degraded", "download_mbps": 500, "label": "T",
                  "ip": "1.2.3.4", "ts": "2026-11-08T12:00:00",
                  "big": True, "download_source": "cloudflare"}
        self.assertIsNone(self._alert(sample, cfg))


if __name__ == "__main__":
    import time
    unittest.main()
