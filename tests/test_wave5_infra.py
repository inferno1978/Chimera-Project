#!/usr/bin/env python3
"""
tests/test_wave5_infra.py
Объединённые тесты для модулей Волны 5: config_backup, awg_hw_tuning,
ripe_file_age, fingerprint_manager, xray_safe_apply, scheduler, logrotate,
nginx_watchdog, system_deps, ipset_persist, connection_audit, traffic_history,
health_report, awg_backup, cold_boot_restore.
"""
from __future__ import annotations
import json, os, stat, sys, tempfile, time, unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

def _setup_core():
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text(); g = {}
    with patch.object(Path, 'mkdir', lambda s,*a,**k: None), \
         patch.object(Path, 'touch', lambda s,*a,**k: None), \
         patch.object(Path, 'chmod', lambda s,*a,**k: None), \
         patch('os.chown', lambda *a,**k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types; m = types.ModuleType("vless_installer._core"); m.__dict__.update(g)
    sys.modules["vless_installer._core"] = m

# ── ripe_file_age ──────────────────────────────────────────────────────────

class TestRipeFileAge(unittest.TestCase):
    def setUp(self):
        _setup_core()
        self._tmp = Path(tempfile.mkdtemp()); self._f = self._tmp / "ru.txt"
    def tearDown(self):
        import shutil; shutil.rmtree(self._tmp, ignore_errors=True)
    def _write_file(self, age_days=0):
        self._f.write_text("10.0.0.0/8\n" * 20); t = time.time() - age_days * 86400
        os.utime(self._f, (t, t))
    def test_get_info_no_file(self):
        from vless_installer.modules.ripe_file_age import get_ripe_file_info
        info = get_ripe_file_info(Path("/tmp/nonexistent_ripe_xyz.txt"))
        self.assertFalse(info["exists"])
    def test_get_info_fresh(self):
        from vless_installer.modules.ripe_file_age import get_ripe_file_info
        self._write_file(0)
        info = get_ripe_file_info(self._f)
        self.assertTrue(info["exists"])
        self.assertFalse(info["stale"])
        self.assertFalse(info["critical"])
    def test_get_info_stale(self):
        from vless_installer.modules.ripe_file_age import get_ripe_file_info, WARN_DAYS
        self._write_file(WARN_DAYS + 5)
        info = get_ripe_file_info(self._f)
        self.assertTrue(info["stale"])
    def test_get_info_critical(self):
        from vless_installer.modules.ripe_file_age import get_ripe_file_info, CRITICAL_DAYS
        self._write_file(CRITICAL_DAYS + 5)
        info = get_ripe_file_info(self._f)
        self.assertTrue(info["critical"])
    def test_banner_returns_string(self):
        from vless_installer.modules.ripe_file_age import ripe_file_age_banner
        self.assertIsInstance(ripe_file_age_banner(Path("/tmp/nonexistent.txt")), str)

# ── fingerprint_manager ────────────────────────────────────────────────────

class TestFingerprintManager(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_xray_fp_list_has_11_entries(self):
        from vless_installer.modules.fingerprint_manager import XRAY_FP_LIST
        self.assertGreaterEqual(len(XRAY_FP_LIST), 11)
        self.assertIn("chrome", XRAY_FP_LIST)
        self.assertIn("firefox", XRAY_FP_LIST)
        self.assertIn("safari", XRAY_FP_LIST)
    def test_default_fp_is_chrome(self):
        from vless_installer.modules.fingerprint_manager import DEFAULT_FP
        self.assertEqual(DEFAULT_FP, "chrome")
    def test_fp_menu_keys_are_numeric(self):
        from vless_installer.modules.fingerprint_manager import _FP_MENU
        for key in _FP_MENU:
            self.assertTrue(key.isdigit())

# ── config_backup ──────────────────────────────────────────────────────────

class TestConfigBackup(unittest.TestCase):
    def setUp(self):
        _setup_core()
        self._tmp = Path(tempfile.mkdtemp())
    def tearDown(self):
        import shutil; shutil.rmtree(self._tmp, ignore_errors=True)
    def test_parse_backup_ts_valid(self):
        from vless_installer.modules.config_backup import _parse_backup_ts
        ts = _parse_backup_ts("config-20260710-120000.json")
        self.assertGreater(ts, 0)
    def test_parse_backup_ts_invalid(self):
        from vless_installer.modules.config_backup import _parse_backup_ts
        self.assertEqual(_parse_backup_ts("invalid.json"), 0.0)
    def test_backup_filename_format(self):
        from vless_installer.modules.config_backup import _backup_filename, BACKUP_PREFIX, BACKUP_SUFFIX
        name = _backup_filename()
        self.assertTrue(name.startswith(BACKUP_PREFIX))
        self.assertTrue(name.endswith(BACKUP_SUFFIX))

# ── awg_hw_tuning ──────────────────────────────────────────────────────────

class TestAwgHwTuning(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_detect_ram_mb(self):
        from vless_installer.modules import awg_hw_tuning
        content = "MemTotal:       16384000 kB\n"
        with patch("pathlib.Path.read_text", return_value=content):
            with patch("pathlib.Path.exists", return_value=True):
                ram = awg_hw_tuning.awgs_detect_ram_mb()
        self.assertEqual(ram, 16000)
    def test_detect_ram_no_file(self):
        from vless_installer.modules import awg_hw_tuning
        orig_read = Path.read_text
        def _fake_read(self):
            raise OSError("no file")
        with patch("pathlib.Path.read_text", _fake_read):
            self.assertEqual(awg_hw_tuning.awgs_detect_ram_mb(), 0)

# ── xray_safe_apply ────────────────────────────────────────────────────────

class TestXraySafeApply(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_returns_false_when_apply_fails(self):
        from vless_installer.modules.xray_safe_apply import xray_apply_with_smoke
        result = xray_apply_with_smoke(_core_apply_fn=lambda **kw: False)
        self.assertFalse(result)
    def test_returns_true_when_apply_ok_no_smoke(self):
        from vless_installer.modules.xray_safe_apply import xray_apply_with_smoke
        result = xray_apply_with_smoke(_core_apply_fn=lambda **kw: True)
        self.assertTrue(result)
    def test_calls_smoke_when_provided(self):
        from vless_installer.modules.xray_safe_apply import xray_apply_with_smoke
        smoke_called = []
        def _smoke(_do_emergency_restore_fn=None):
            smoke_called.append(True)
            return True
        result = xray_apply_with_smoke(
            _core_apply_fn=lambda **kw: True, _smoke_fn=_smoke)
        self.assertTrue(result)
        self.assertEqual(len(smoke_called), 1)

# ── scheduler ──────────────────────────────────────────────────────────────

class TestScheduler(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_cron_exists_true(self):
        from vless_installer.modules.scheduler import _cron_exists
        with patch("pathlib.Path.exists", return_value=True):
            self.assertTrue(_cron_exists("/some/path"))
    def test_cron_exists_false(self):
        from vless_installer.modules.scheduler import _cron_exists
        with patch("pathlib.Path.exists", return_value=False):
            self.assertFalse(_cron_exists("/some/path"))
    def test_pad_short_string(self):
        from vless_installer.modules.scheduler import _pad
        result = _pad("hi", 10)
        self.assertEqual(len(result), 10)

# ── logrotate ──────────────────────────────────────────────────────────────

class TestLogrotate(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_detect_colors_non_tty(self):
        from vless_installer.modules.logrotate import _detect_colors
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = False
            c = _detect_colors()
            for v in c.values(): self.assertEqual(v, "")

# ── nginx_watchdog ─────────────────────────────────────────────────────────

class TestNginxWatchdog(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_protocol_mode_reality(self):
        from vless_installer.modules import nginx_watchdog
        import tempfile as tf
        tmpdir = Path(tf.mkdtemp())
        try:
            state = tmpdir / "state.json"
            state.write_text(json.dumps({"protocol_mode": "reality"}))
            with patch.object(nginx_watchdog, "_STATE", state):
                self.assertEqual(nginx_watchdog._protocol_mode(), "reality")
        finally:
            import shutil; shutil.rmtree(tmpdir, ignore_errors=True)
    def test_protocol_mode_default(self):
        from vless_installer.modules import nginx_watchdog
        import tempfile as tf
        tmpdir = Path(tf.mkdtemp())
        try:
            state = tmpdir / "state.json"
            state.write_text(json.dumps({"other": "x"}))
            with patch.object(nginx_watchdog, "_STATE", state):
                self.assertEqual(nginx_watchdog._protocol_mode(), "reality")
        finally:
            import shutil; shutil.rmtree(tmpdir, ignore_errors=True)

# ── system_deps ────────────────────────────────────────────────────────────

class TestSystemDeps(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_cmd_to_pkg_has_common_commands(self):
        from vless_installer.modules.system_deps import _CMD_TO_PKG
        for cmd in ("curl", "wget", "tar"):
            self.assertIn(cmd, _CMD_TO_PKG)
    def test_cmd_to_pkg_values_are_tuples(self):
        from vless_installer.modules.system_deps import _CMD_TO_PKG
        for cmd, pkg in _CMD_TO_PKG.items():
            with self.subTest(cmd=cmd):
                self.assertIsInstance(pkg, (tuple, list))
                self.assertEqual(len(pkg), 2)

# ── awg_backup ─────────────────────────────────────────────────────────────

class TestAwgBackup(unittest.TestCase):
    def setUp(self):
        _setup_core()
        self._tmp = Path(tempfile.mkdtemp())
    def tearDown(self):
        import shutil; shutil.rmtree(self._tmp, ignore_errors=True)
    def test_backup_list_empty(self):
        from vless_installer.modules.awg_backup import awgs_backup_list
        with patch("vless_installer.modules.awg_backup.AWGS_BACKUP_DIR", self._tmp):
            self.assertEqual(awgs_backup_list(), [])
    def test_backup_list_sorted(self):
        from vless_installer.modules.awg_backup import awgs_backup_list
        f1 = self._tmp / "h2_backup_1.tar.gz"; f1.write_text("x")
        time.sleep(0.01)
        f2 = self._tmp / "h2_backup_2.tar.gz"; f2.write_text("x")
        with patch("vless_installer.modules.awg_backup.AWGS_BACKUP_DIR", self._tmp):
            result = awgs_backup_list()
        self.assertEqual(len(result), 2)
        # newer first
        self.assertEqual(result[0].name, "h2_backup_2.tar.gz")

# ── cold_boot_restore ──────────────────────────────────────────────────────

class TestColdBootRestore(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_is_installed_false(self):
        from vless_installer.modules import cold_boot_restore
        with patch("pathlib.Path.exists", return_value=False):
            self.assertFalse(cold_boot_restore._is_installed())
    def test_is_installed_true(self):
        from vless_installer.modules import cold_boot_restore
        with patch("pathlib.Path.exists", return_value=True):
            self.assertTrue(cold_boot_restore._is_installed())

# ── connection_audit ───────────────────────────────────────────────────────

class TestConnectionAudit(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from vless_installer.modules.connection_audit import _core_module
        self.assertIsNotNone(_core_module())

# ── traffic_history ────────────────────────────────────────────────────────

class TestTrafficHistory(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_file_constant(self):
        from vless_installer.modules.traffic_history import TRAFFIC_HISTORY_FILE
        self.assertIsInstance(TRAFFIC_HISTORY_FILE, Path)

# ── health_report ──────────────────────────────────────────────────────────

class TestHealthReport(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from vless_installer.modules.health_report import _core_module
        self.assertIsNotNone(_core_module())

# ── ipset_persist ──────────────────────────────────────────────────────────

class TestIpsetPersist(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_detect_colors_non_tty(self):
        from vless_installer.modules.ipset_persist import _detect_colors
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = False
            c = _detect_colors()
            for v in c.values(): self.assertEqual(v, "")

# ── hysteria2_smoke_test ───────────────────────────────────────────────────

class TestH2SmokeTest(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_check_returns_bool(self):
        from vless_installer.modules.hysteria2_smoke_test import _check
        import io
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            self.assertTrue(_check("test", True))
            self.assertFalse(_check("test", False))

# ── hysteria2_watchdog ─────────────────────────────────────────────────────

class TestH2Watchdog(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_restart_limit_constant(self):
        from vless_installer.modules.hysteria2_watchdog import _RESTART_LIMIT
        self.assertGreater(_RESTART_LIMIT, 0)

# ── hysteria2_cluster ──────────────────────────────────────────────────────

class TestH2Cluster(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_ssh_base_opts_has_strict_host_checking(self):
        from vless_installer.modules.hysteria2_cluster import _ssh_base_opts
        opts = _ssh_base_opts()
        self.assertIn("StrictHostKeyChecking=no", opts)
    def test_ssh_key_opts_adds_identity(self):
        from vless_installer.modules.hysteria2_cluster import _ssh_key_opts
        opts = _ssh_key_opts("/path/to/key")
        self.assertIn("-i", opts)
        self.assertIn("/path/to/key", opts)

if __name__ == "__main__":
    unittest.main(verbosity=2)
