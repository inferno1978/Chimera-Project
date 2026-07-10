#!/usr/bin/env python3
"""
tests/test_hysteria2_quality.py — _load_history, _save_history, _append_history
tests/test_hysteria2_dpi.py — _best_port
tests/test_hysteria2_traffic.py — _bytes_to_human, _load_cache, _save_cache
tests/test_hysteria2_backup.py — _fmt_size, h2_backup_include_in_main
Объединённый файл для кратких модулей.
"""
from __future__ import annotations
import json, os, stat, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

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

# ── hysteria2_quality ──────────────────────────────────────────────────────

class TestH2QualityHistory(unittest.TestCase):
    def setUp(self):
        _setup_core()
        self._tmp = Path(tempfile.mkdtemp()); self._f = self._tmp / "h2q.json"
    def tearDown(self):
        import shutil; shutil.rmtree(self._tmp, ignore_errors=True)
    def _patch(self):
        return patch("vless_installer.modules.hysteria2_quality._HISTORY_FILE", self._f)
    def test_load_empty(self):
        from vless_installer.modules.hysteria2_quality import _load_history
        with self._patch(): self.assertEqual(_load_history(), {})
    def test_save_load(self):
        from vless_installer.modules.hysteria2_quality import _load_history, _save_history
        with self._patch():
            _save_history({"1.2.3.4": [{"ts":"x"}]}); self.assertTrue(_load_history()["1.2.3.4"])
    def test_append_trims(self):
        from vless_installer.modules.hysteria2_quality import _append_history, _load_history, _MAX_HISTORY
        with self._patch():
            for i in range(_MAX_HISTORY + 20):
                _append_history("1.2.3.4", {"ts": str(i)})
            h = _load_history()
        self.assertLessEqual(len(h["1.2.3.4"]), _MAX_HISTORY)

# ── hysteria2_dpi ──────────────────────────────────────────────────────────

class TestH2DpiBestPort(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_returns_none_when_empty(self):
        from vless_installer.modules.hysteria2_dpi import _best_port
        self.assertIsNone(_best_port([]))
    def test_returns_unblocked_with_min_rtt(self):
        from vless_installer.modules.hysteria2_dpi import _best_port
        results = [
            {"port":443,"blocked":True,"rtt_ms":10},
            {"port":8443,"blocked":False,"rtt_ms":20},
            {"port":2083,"blocked":False,"rtt_ms":50},
        ]
        self.assertEqual(_best_port(results), 8443)
    def test_fallback_to_timeout_ok(self):
        from vless_installer.modules.hysteria2_dpi import _best_port
        results = [{"port":443,"blocked":True,"rtt_ms":0},{"port":8443,"blocked":False,"rtt_ms":0}]
        self.assertEqual(_best_port(results), 8443)

# ── hysteria2_traffic ──────────────────────────────────────────────────────

class TestH2TrafficBytesToHuman(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_zero(self):
        from vless_installer.modules.hysteria2_traffic import _bytes_to_human
        self.assertIn("B", _bytes_to_human(0))
    def test_kb(self):
        from vless_installer.modules.hysteria2_traffic import _bytes_to_human
        self.assertIn("KB", _bytes_to_human(1024))
    def test_mb(self):
        from vless_installer.modules.hysteria2_traffic import _bytes_to_human
        self.assertIn("MB", _bytes_to_human(1024**2))
    def test_pb(self):
        from vless_installer.modules.hysteria2_traffic import _bytes_to_human
        self.assertIn("PB", _bytes_to_human(1024**5))

class TestH2TrafficCache(unittest.TestCase):
    def setUp(self):
        _setup_core()
        self._tmp = Path(tempfile.mkdtemp()); self._c = self._tmp / "cache.json"
    def tearDown(self):
        import shutil; shutil.rmtree(self._tmp, ignore_errors=True)
    def _patch(self):
        return patch("vless_installer.modules.hysteria2_traffic._STATS_CACHE", self._c)
    def test_load_empty(self):
        from vless_installer.modules.hysteria2_traffic import _load_cache
        with self._patch(): self.assertEqual(_load_cache(), {})
    def test_save_load(self):
        from vless_installer.modules.hysteria2_traffic import _load_cache, _save_cache
        with self._patch():
            _save_cache({"bytes":100}); self.assertEqual(_load_cache()["bytes"], 100)

# ── hysteria2_backup ───────────────────────────────────────────────────────

class TestH2BackupFmtSize(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_zero(self):
        from vless_installer.modules.hysteria2_backup import _fmt_size
        self.assertIn("B", _fmt_size(0))
    def test_kb(self):
        from vless_installer.modules.hysteria2_backup import _fmt_size
        self.assertIn("KB", _fmt_size(1024))
    def test_mb(self):
        from vless_installer.modules.hysteria2_backup import _fmt_size
        self.assertIn("MB", _fmt_size(1024**2))

if __name__ == "__main__":
    unittest.main(verbosity=2)
