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
        self.assertEqual(cfg["thresholds"]["normal_mbps"], 100.0)
        self.assertEqual(cfg["thresholds"]["degraded_mbps"], 50.0)

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
        self.assertEqual(cfg["thresholds"]["degraded_mbps"], 50.0)


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

    def test_classifies_normal(self):
        """Скорость ≥ normal_mbps → level=normal (базлайна нет → absolute)."""
        with patch.object(self._m, "_ping_latency", return_value=2.5), \
             patch.object(self._m, "_run_download_probe",
                          return_value=_probe_result(15_000_000)), \
             patch.object(self._m, "_baseline_mbps", return_value=None), \
             patch.object(self._m, "_node_hostname", return_value="test-host"), \
             patch.object(self._m, "_node_public_ip", return_value="1.2.3.4"), \
             patch.object(self._m, "load_config",
                          return_value={**self._m.DEFAULT_CONFIG,
                                        "node_label": "TEST",
                                        "node_ip": "1.2.3.4"}):
            s = self._m.measure_once(big=False)
        # 15 MB/s = 120 Mbps → normal (>100)
        self.assertEqual(s["level"], "normal")
        self.assertAlmostEqual(s["download_mbps"], 120.0, places=1)
        self.assertEqual(s["label"], "TEST")
        self.assertFalse(s["big"])
        # новые поля методики
        self.assertEqual(s["streams"], 6)
        self.assertEqual(s["download_source"], "cloudflare")

    def test_classifies_degraded(self):
        """Скорость 50-100 Mbps → level=degraded."""
        with patch.object(self._m, "_ping_latency", return_value=5.0), \
             patch.object(self._m, "_run_download_probe",
                          return_value=_probe_result(7_500_000)), \
             patch.object(self._m, "_baseline_mbps", return_value=None), \
             patch.object(self._m, "_node_hostname", return_value="h"), \
             patch.object(self._m, "_node_public_ip", return_value="1.2.3.4"), \
             patch.object(self._m, "load_config",
                          return_value=self._m.DEFAULT_CONFIG):
            s = self._m.measure_once(big=False)
        # 7.5 MB/s = 60 Mbps → degraded (50-100)
        self.assertEqual(s["level"], "degraded")
        self.assertAlmostEqual(s["download_mbps"], 60.0, places=1)

    def test_classifies_critical(self):
        """Скорость < 50 Mbps → level=critical."""
        with patch.object(self._m, "_ping_latency", return_value=10.0), \
             patch.object(self._m, "_run_download_probe",
                          return_value=_probe_result(2_000_000)), \
             patch.object(self._m, "_baseline_mbps", return_value=None), \
             patch.object(self._m, "_node_hostname", return_value="h"), \
             patch.object(self._m, "_node_public_ip", return_value="1.2.3.4"), \
             patch.object(self._m, "load_config",
                          return_value=self._m.DEFAULT_CONFIG):
            s = self._m.measure_once(big=False)
        # 2 MB/s = 16 Mbps → critical (<50)
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
    """_classify_level auto-режим: базлайн-медиана 24ч вместо абсолютных порогов."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor

    def test_auto_fast_port_cut_is_critical(self):
        """Кейс №16: обрез 16.5G → ~1G. Абсолютные пороги дали бы normal."""
        cfg = {**self._m.DEFAULT_CONFIG}
        with patch.object(self._m, "_baseline_mbps", return_value=9000.0):
            self.assertEqual(self._m._classify_level(950.0, cfg), "critical")

    def test_auto_half_baseline_is_normal(self):
        cfg = {**self._m.DEFAULT_CONFIG}
        with patch.object(self._m, "_baseline_mbps", return_value=9000.0):
            self.assertEqual(self._m._classify_level(5000.0, cfg), "normal")

    def test_auto_quarter_baseline_is_degraded(self):
        cfg = {**self._m.DEFAULT_CONFIG}
        with patch.object(self._m, "_baseline_mbps", return_value=9000.0):
            self.assertEqual(self._m._classify_level(2000.0, cfg), "degraded")

    def test_auto_falls_back_to_absolute_without_baseline(self):
        cfg = {**self._m.DEFAULT_CONFIG}
        with patch.object(self._m, "_baseline_mbps", return_value=None):
            self.assertEqual(self._m._classify_level(120.0, cfg), "normal")
            self.assertEqual(self._m._classify_level(60.0, cfg), "degraded")
            self.assertEqual(self._m._classify_level(16.0, cfg), "critical")

    def test_absolute_mode_ignores_baseline(self):
        cfg = {**self._m.DEFAULT_CONFIG, "level_mode": "absolute"}
        with patch.object(self._m, "_baseline_mbps", return_value=9000.0) as pbl:
            self.assertEqual(self._m._classify_level(120.0, cfg), "normal")
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
    """Кейс №16: обрез 16.5G → ~1G должен давать critical-алерт,
    хотя абсолютный порог 50 Mbps пройден с запасом."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor

    def test_cut_triggers_critical_alert(self):
        cfg = {**self._m.DEFAULT_CONFIG, "alerts_enabled": True}
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


class TestAlertLogic(unittest.TestCase):
    """_check_alert — алерты при деградации."""
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


if __name__ == "__main__":
    import time
    unittest.main()
