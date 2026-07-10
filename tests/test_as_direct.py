#!/usr/bin/env python3
"""
tests/test_as_direct.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/as_direct.py.

Покрывает:
  1. _as_normalize — нормализация ASN
  2. _as_validate — валидация ASN
  3. _as_direct_file / _as_direct_comment — генерация путей
  4. _as_direct_list_load / _as_direct_list_save — JSON I/O
  5. _as_get_proxy_outbound_tag — поиск outbound tag
"""
from __future__ import annotations

import json
import os
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


class TestAsNormalize(unittest.TestCase):
    """_as_normalize — нормализация ASN."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_adds_as_prefix(self):
        from vless_installer.modules.as_direct import _as_normalize
        self.assertEqual(_as_normalize("12345"), "AS12345")

    def test_uppercase(self):
        from vless_installer.modules.as_direct import _as_normalize
        self.assertEqual(_as_normalize("as12345"), "AS12345")

    def test_already_prefixed(self):
        from vless_installer.modules.as_direct import _as_normalize
        self.assertEqual(_as_normalize("AS12345"), "AS12345")

    def test_strips_whitespace(self):
        from vless_installer.modules.as_direct import _as_normalize
        self.assertEqual(_as_normalize("  12345  "), "AS12345")


class TestAsValidate(unittest.TestCase):
    """_as_validate — валидация ASN."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _mock_core(self):
        core = MagicMock()
        core.warn = MagicMock()
        return core

    def test_valid_asn(self):
        from vless_installer.modules import as_direct
        with patch.object(as_direct, "_core_module", return_value=self._mock_core()):
            ok, msg = as_direct._as_validate("AS12345")
        self.assertTrue(ok)

    def test_as0_invalid(self):
        from vless_installer.modules import as_direct
        with patch.object(as_direct, "_core_module", return_value=self._mock_core()):
            ok, msg = as_direct._as_validate("AS0")
        self.assertFalse(ok)

    def test_too_large_invalid(self):
        from vless_installer.modules import as_direct
        with patch.object(as_direct, "_core_module", return_value=self._mock_core()):
            ok, msg = as_direct._as_validate("AS4294967296")
        self.assertFalse(ok)

    def test_non_as_prefix_invalid(self):
        from vless_installer.modules import as_direct
        with patch.object(as_direct, "_core_module", return_value=self._mock_core()):
            ok, msg = as_direct._as_validate("XX12345")
        self.assertFalse(ok)


class TestAsDirectFile(unittest.TestCase):
    """_as_direct_file / _as_direct_comment — генерация путей."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_file_path(self):
        from vless_installer.modules.as_direct import _as_direct_file, AS_DIRECT_DIR
        path = _as_direct_file("AS12345")
        self.assertEqual(path, AS_DIRECT_DIR / "as_direct_AS12345.txt")

    def test_comment(self):
        from vless_installer.modules.as_direct import _as_direct_comment
        self.assertEqual(_as_direct_comment("AS12345"), "as_direct_AS12345")


class TestAsDirectListLoadSave(unittest.TestCase):
    """_as_direct_list_load / _as_direct_list_save — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._list = self._tmpdir / "as_direct_list.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("vless_installer.modules.as_direct.AS_DIRECT_LIST_FILE", self._list),
            patch("vless_installer.modules.as_direct.AS_DIRECT_DIR", self._tmpdir),
        )

    def test_load_returns_empty_when_no_file(self):
        from vless_installer.modules.as_direct import _as_direct_list_load
        with self._patch()[0], self._patch()[1]:
            self.assertEqual(_as_direct_list_load(), [])

    def test_load_old_format(self):
        """Старый формат: ["AS8359", "AS123"] → list of dicts."""
        from vless_installer.modules.as_direct import _as_direct_list_load
        self._list.write_text(json.dumps(["AS8359", "AS123"]))
        with self._patch()[0], self._patch()[1]:
            result = _as_direct_list_load()
        self.assertEqual(len(result), 2)
        self.assertIn("asn", result[0])

    def test_load_new_format(self):
        from vless_installer.modules.as_direct import _as_direct_list_load
        self._list.write_text(json.dumps([
            {"asn": "AS8359", "action": "direct"},
            {"asn": "AS123", "action": "proxy"},
        ]))
        with self._patch()[0], self._patch()[1]:
            result = _as_direct_list_load()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["action"], "direct")

    def test_save_then_load(self):
        from vless_installer.modules.as_direct import (
            _as_direct_list_load, _as_direct_list_save,
        )
        entries = [{"asn": "AS123", "action": "direct"}]
        with self._patch()[0], self._patch()[1]:
            _as_direct_list_save(entries)
            loaded = _as_direct_list_load()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["asn"], "AS123")

    def test_save_deduplicates(self):
        from vless_installer.modules.as_direct import (
            _as_direct_list_load, _as_direct_list_save,
        )
        entries = [
            {"asn": "AS123", "action": "direct"},
            {"asn": "AS123", "action": "proxy"},
        ]
        with self._patch()[0], self._patch()[1]:
            _as_direct_list_save(entries)
            loaded = _as_direct_list_load()
        self.assertEqual(len(loaded), 1)


class TestAsGetProxyOutboundTag(unittest.TestCase):
    """_as_get_proxy_outbound_tag — поиск outbound tag."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_chain_exit_1_first(self):
        from vless_installer.modules.as_direct import _as_get_proxy_outbound_tag
        cfg = {"outbounds": [
            {"tag": "chain-exit-1", "protocol": "vless"},
            {"tag": "chain-exit", "protocol": "vless"},
            {"tag": "vless-out", "protocol": "vless"},
        ]}
        self.assertEqual(_as_get_proxy_outbound_tag(cfg), "chain-exit-1")

    def test_returns_chain_exit_when_no_exit_1(self):
        from vless_installer.modules.as_direct import _as_get_proxy_outbound_tag
        cfg = {"outbounds": [
            {"tag": "chain-exit", "protocol": "vless"},
        ]}
        self.assertEqual(_as_get_proxy_outbound_tag(cfg), "chain-exit")

    def test_returns_vless_out_when_no_chain(self):
        from vless_installer.modules.as_direct import _as_get_proxy_outbound_tag
        cfg = {"outbounds": [
            {"tag": "vless-out", "protocol": "vless"},
        ]}
        self.assertEqual(_as_get_proxy_outbound_tag(cfg), "vless-out")

    def test_returns_first_non_service_when_no_preferred(self):
        from vless_installer.modules.as_direct import _as_get_proxy_outbound_tag
        cfg = {"outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
            {"tag": "my-proxy", "protocol": "vless"},
        ]}
        self.assertEqual(_as_get_proxy_outbound_tag(cfg), "my-proxy")

    def test_returns_direct_when_no_outbounds(self):
        from vless_installer.modules.as_direct import _as_get_proxy_outbound_tag
        self.assertEqual(_as_get_proxy_outbound_tag({}), "direct")


if __name__ == "__main__":
    unittest.main(verbosity=2)
