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


class TestMeasureOnce(unittest.TestCase):
    """measure_once — классификация по порогам."""
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import bandwidth_monitor
        self._m = bandwidth_monitor

    def test_classifies_normal(self):
        """Скорость ≥ normal_mbps → level=normal."""
        with patch.object(self._m, "_ping_latency", return_value=2.5), \
             patch.object(self._m, "_try_download",
                          return_value=(15_000_000, "cachefly")), \
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

    def test_classifies_degraded(self):
        """Скорость 50-100 Mbps → level=degraded."""
        with patch.object(self._m, "_ping_latency", return_value=5.0), \
             patch.object(self._m, "_try_download",
                          return_value=(7_500_000, "cachefly")), \
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
             patch.object(self._m, "_try_download",
                          return_value=(2_000_000, "cachefly")), \
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
             patch.object(self._m, "_try_download",
                          return_value=(20_000_000, "cachefly")), \
             patch.object(self._m, "_node_hostname", return_value="h"), \
             patch.object(self._m, "_node_public_ip", return_value="1.2.3.4"), \
             patch.object(self._m, "load_config",
                          return_value=self._m.DEFAULT_CONFIG):
            s = self._m.measure_once(big=True)
        self.assertTrue(s["big"])


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
            "token": "abc:123", "chat_id": "999"
        }))
        token, chat = self._m._load_tg_config()
        self.assertEqual(token, "abc:123")
        self.assertEqual(chat, "999")

    def test_load_from_tg_bot_json(self):
        (self._tmp / "tg_bot.json").write_text(json.dumps({
            "token": "xyz:456", "admin_id": "888"
        }))
        token, chat = self._m._load_tg_config()
        self.assertEqual(token, "xyz:456")
        self.assertEqual(chat, "888")

    def test_no_config_returns_empty(self):
        token, chat = self._m._load_tg_config()
        self.assertEqual(token, "")
        self.assertEqual(chat, "")


if __name__ == "__main__":
    import time
    unittest.main()
