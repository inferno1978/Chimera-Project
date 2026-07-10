#!/usr/bin/env python3
"""
tests/test_geoip_block.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/geoip_block.py.

Покрывает:
  1. _geoip_block_get_rules — чтение block-правил из Xray config
"""
from __future__ import annotations

import json
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


class TestGeoipBlockGetRules(unittest.TestCase):
    """_geoip_block_get_rules — чтение block-правил."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "config.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _mock_core(self, cfg_dict=None):
        core = MagicMock()
        core.CONFIG_DIR = self._tmpdir
        if cfg_dict is not None:
            self._cfg.write_text(json.dumps(cfg_dict))
        return core

    def test_returns_empty_when_no_config(self):
        from vless_installer.modules import geoip_block
        with patch.object(geoip_block, "_core_module",
                          return_value=self._mock_core()):
            self.assertEqual(geoip_block._geoip_block_get_rules(), [])

    def test_returns_block_rules(self):
        from vless_installer.modules import geoip_block
        cfg = {"routing": {"rules": [
            {"outboundTag": "block", "domain": ["geosite:category-ads"]},
            {"outboundTag": "direct", "domain": ["geosite:ru"]},
        ]}}
        with patch.object(geoip_block, "_core_module",
                          return_value=self._mock_core(cfg)):
            result = geoip_block._geoip_block_get_rules()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["outboundTag"], "block")

    def test_returns_empty_when_no_block_rules(self):
        from vless_installer.modules import geoip_block
        cfg = {"routing": {"rules": [
            {"outboundTag": "direct", "domain": ["geosite:ru"]},
        ]}}
        with patch.object(geoip_block, "_core_module",
                          return_value=self._mock_core(cfg)):
            self.assertEqual(geoip_block._geoip_block_get_rules(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
