#!/usr/bin/env python3
"""
tests/test_turnable.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/turnable.py.

Покрывает:
  1. _xray_has_turnable_inbound — проверка наличия inbound
  2. _xray_inject_inbound — добавление inbound
  3. _xray_remove_inbound — удаление inbound
  4. _xray_config_path — поиск config.json
  5. _gen_uuid — генерация UUID
  6. _is_amd64 — определение архитектуры
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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


class TestXrayHasTurnableInbound(unittest.TestCase):
    """_xray_has_turnable_inbound — проверка наличия inbound."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_false_when_no_inbounds(self):
        from vless_installer.modules.turnable import _xray_has_turnable_inbound
        self.assertFalse(_xray_has_turnable_inbound({}))

    def test_returns_true_when_tag_present(self):
        from vless_installer.modules.turnable import (
            _xray_has_turnable_inbound, _XRAY_INBOUND_TAG,
        )
        cfg = {"inbounds": [{"tag": _XRAY_INBOUND_TAG}]}
        self.assertTrue(_xray_has_turnable_inbound(cfg))

    def test_returns_false_when_other_tags(self):
        from vless_installer.modules.turnable import _xray_has_turnable_inbound
        cfg = {"inbounds": [{"tag": "other"}, {"tag": "another"}]}
        self.assertFalse(_xray_has_turnable_inbound(cfg))


class TestXrayInjectInbound(unittest.TestCase):
    """_xray_inject_inbound — добавление inbound."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_adds_inbound_to_empty_cfg(self):
        from vless_installer.modules.turnable import (
            _xray_inject_inbound, _XRAY_INBOUND_TAG,
        )
        cfg = {}
        changed = _xray_inject_inbound(cfg, port=12767, vless_uuid="test-uuid")
        self.assertTrue(changed)
        self.assertEqual(len(cfg["inbounds"]), 1)
        ib = cfg["inbounds"][0]
        self.assertEqual(ib["tag"], _XRAY_INBOUND_TAG)
        self.assertEqual(ib["port"], 12767)
        self.assertEqual(ib["listen"], "127.0.0.1")
        self.assertEqual(ib["protocol"], "vless")
        self.assertEqual(ib["settings"]["clients"][0]["id"], "test-uuid")

    def test_returns_false_when_already_present(self):
        """Идемпотентность — повторный вызов не дублирует."""
        from vless_installer.modules.turnable import _xray_inject_inbound
        cfg = {}
        _xray_inject_inbound(cfg, port=12767, vless_uuid="uuid1")
        changed = _xray_inject_inbound(cfg, port=12767, vless_uuid="uuid2")
        self.assertFalse(changed)
        self.assertEqual(len(cfg["inbounds"]), 1)

    def test_preserves_existing_inbounds(self):
        from vless_installer.modules.turnable import _xray_inject_inbound
        cfg = {"inbounds": [{"tag": "other", "protocol": "vless"}]}
        _xray_inject_inbound(cfg, port=12767, vless_uuid="uuid")
        self.assertEqual(len(cfg["inbounds"]), 2)

    def test_includes_sniffing(self):
        from vless_installer.modules.turnable import _xray_inject_inbound
        cfg = {}
        _xray_inject_inbound(cfg, port=12767, vless_uuid="uuid")
        ib = cfg["inbounds"][0]
        self.assertIn("sniffing", ib)
        self.assertTrue(ib["sniffing"]["enabled"])

    def test_stream_settings_tcp_none(self):
        from vless_installer.modules.turnable import _xray_inject_inbound
        cfg = {}
        _xray_inject_inbound(cfg, port=12767, vless_uuid="uuid")
        ib = cfg["inbounds"][0]
        self.assertEqual(ib["streamSettings"]["network"], "tcp")
        self.assertEqual(ib["streamSettings"]["security"], "none")


class TestXrayRemoveInbound(unittest.TestCase):
    """_xray_remove_inbound — удаление inbound."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_false_when_not_present(self):
        from vless_installer.modules.turnable import _xray_remove_inbound
        cfg = {"inbounds": [{"tag": "other"}]}
        self.assertFalse(_xray_remove_inbound(cfg))

    def test_removes_and_returns_true(self):
        from vless_installer.modules.turnable import (
            _xray_remove_inbound, _xray_inject_inbound,
        )
        cfg = {}
        _xray_inject_inbound(cfg, port=12767, vless_uuid="uuid")
        self.assertTrue(_xray_remove_inbound(cfg))
        self.assertEqual(len(cfg["inbounds"]), 0)

    def test_preserves_other_inbounds(self):
        from vless_installer.modules.turnable import (
            _xray_remove_inbound, _xray_inject_inbound,
        )
        cfg = {"inbounds": [{"tag": "other"}]}
        _xray_inject_inbound(cfg, port=12767, vless_uuid="uuid")
        _xray_remove_inbound(cfg)
        self.assertEqual(len(cfg["inbounds"]), 1)
        self.assertEqual(cfg["inbounds"][0]["tag"], "other")


class TestXrayConfigPath(unittest.TestCase):
    """_xray_config_path — поиск config.json."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_none_when_no_config(self):
        from vless_installer.modules import turnable
        paths = [Path("/nonexistent1"), Path("/nonexistent2")]
        with patch.object(turnable, "_XRAY_CONFIG_PATHS", paths):
            self.assertIsNone(turnable._xray_config_path())

    def test_returns_first_existing(self):
        from vless_installer.modules import turnable
        path1 = self._tmpdir / "config1.json"
        path1.write_text("{}")
        with patch.object(turnable, "_XRAY_CONFIG_PATHS",
                          [path1, Path("/nonexistent")]):
            self.assertEqual(turnable._xray_config_path(), path1)


class TestGenUuid(unittest.TestCase):
    """_gen_uuid."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_valid_uuid_format(self):
        import re
        from vless_installer.modules.turnable import _gen_uuid
        uuid_str = _gen_uuid()
        self.assertRegex(uuid_str,
                         r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

    def test_unique(self):
        from vless_installer.modules.turnable import _gen_uuid
        uuids = {_gen_uuid() for _ in range(10)}
        self.assertEqual(len(uuids), 10)


class TestIsAmd64(unittest.TestCase):
    """_is_amd64."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_x86_64(self):
        from vless_installer.modules.turnable import _is_amd64
        with patch("platform.machine", return_value="x86_64"):
            self.assertTrue(_is_amd64())

    def test_aarch64(self):
        from vless_installer.modules.turnable import _is_amd64
        with patch("platform.machine", return_value="aarch64"):
            self.assertFalse(_is_amd64())


if __name__ == "__main__":
    unittest.main(verbosity=2)
