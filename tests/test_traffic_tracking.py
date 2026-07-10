#!/usr/bin/env python3
"""
tests/test_traffic_tracking.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/traffic_tracking.py.

Покрывает:
  1. _limits_load / _limits_save — JSON I/O
  2. _stats_api_is_configured — проверка конфигурации Stats API
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("vless_installer._core")
    fake_core.__dict__.update(g)
    sys.modules["vless_installer._core"] = fake_core


class TestLimitsLoadSave(unittest.TestCase):
    """_limits_load / _limits_save — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._limits = self._tmpdir / "traffic_limits.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.traffic_tracking.TRAFFIC_LIMITS_FILE",
                     self._limits)

    def test_load_returns_empty_when_no_file(self):
        from vless_installer.modules.traffic_tracking import _limits_load
        with self._patch():
            self.assertEqual(_limits_load(), {})

    def test_load_returns_empty_on_corrupt(self):
        from vless_installer.modules.traffic_tracking import _limits_load
        self._limits.write_text("{invalid")
        with self._patch():
            self.assertEqual(_limits_load(), {})

    def test_save_then_load(self):
        from vless_installer.modules.traffic_tracking import _limits_load, _limits_save
        data = {"alice@x.com": {"limit_gb": 10, "used_bytes": 0}}
        with self._patch():
            _limits_save(data)
            loaded = _limits_load()
        self.assertIn("alice@x.com", loaded)
        self.assertEqual(loaded["alice@x.com"]["limit_gb"], 10)

    def test_save_sets_chmod_600(self):
        from vless_installer.modules.traffic_tracking import _limits_save
        with self._patch():
            _limits_save({})
        mode = stat.S_IMODE(os.stat(self._limits).st_mode)
        self.assertEqual(mode, 0o600)


class TestStatsApiIsConfigured(unittest.TestCase):
    """_stats_api_is_configured — проверка конфигурации Stats API."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "config.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _mock_core(self, cfg_dict):
        core = MagicMock()
        core.CONFIG_DIR = self._tmpdir
        self._cfg.write_text(json.dumps(cfg_dict))
        return core

    def test_returns_false_when_no_config(self):
        from vless_installer.modules import traffic_tracking
        core = MagicMock()
        core.CONFIG_DIR = Path("/tmp/nonexistent_cfg_dir")
        with patch.object(traffic_tracking, "_core_module", return_value=core):
            self.assertFalse(traffic_tracking._stats_api_is_configured())

    def test_returns_false_when_missing_stats(self):
        from vless_installer.modules import traffic_tracking
        cfg = {"inbounds": [], "outbounds": []}
        with patch.object(traffic_tracking, "_core_module",
                          return_value=self._mock_core(cfg)):
            self.assertFalse(traffic_tracking._stats_api_is_configured())

    def test_returns_true_when_all_present(self):
        from vless_installer.modules import traffic_tracking
        cfg = {
            "stats": {},
            "policy": {},
            "inbounds": [{"tag": "xray-stats-api"}],
            "outbounds": [{"tag": "xray-stats-api"}],
        }
        with patch.object(traffic_tracking, "_core_module",
                          return_value=self._mock_core(cfg)):
            self.assertTrue(traffic_tracking._stats_api_is_configured())

    def test_returns_false_when_missing_policy(self):
        from vless_installer.modules import traffic_tracking
        cfg = {
            "stats": {},
            "inbounds": [{"tag": "xray-stats-api"}],
            "outbounds": [{"tag": "xray-stats-api"}],
        }
        with patch.object(traffic_tracking, "_core_module",
                          return_value=self._mock_core(cfg)):
            self.assertFalse(traffic_tracking._stats_api_is_configured())


if __name__ == "__main__":
    unittest.main(verbosity=2)
