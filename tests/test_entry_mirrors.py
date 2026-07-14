#!/usr/bin/env python3
"""
tests/test_entry_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/entry_mirrors.py.

Покрывает:
  1. _parse_vless_link — парсинг vless:// ссылки
  2. _load / _save / _find — JSON I/O
  3. _status_str — строка статуса mirror
  4. _probe — TCP проверка (mocked socket)
  5. get_mirror_uris — генерация URI списка
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
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
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


class TestParseVlessLink(unittest.TestCase):
    """_parse_vless_link — парсинг vless:// ссылки."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_parses_valid_reality_link(self):
        from chimera.modules.entry_mirrors import _parse_vless_link
        link = "vless://uuid@1.2.3.4:443?type=tcp&security=reality&pbk=PUBKEY&sid=abcd&sni=vpn.example.com&fp=chrome#label"
        result = _parse_vless_link(link)
        self.assertIsNotNone(result)
        self.assertEqual(result["host"], "1.2.3.4")
        self.assertEqual(result["port"], 443)
        self.assertEqual(result["pbk"], "PUBKEY")
        self.assertEqual(result["sid"], "abcd")
        self.assertEqual(result["sni"], "vpn.example.com")
        self.assertEqual(result["fp"], "chrome")

    def test_returns_none_for_non_reality(self):
        from chimera.modules.entry_mirrors import _parse_vless_link
        link = "vless://uuid@1.2.3.4:443?type=tcp&security=tls&sni=vpn.example.com#label"
        self.assertIsNone(_parse_vless_link(link))

    def test_returns_none_for_non_vless(self):
        from chimera.modules.entry_mirrors import _parse_vless_link
        link = "https://example.com"
        self.assertIsNone(_parse_vless_link(link))

    def test_returns_none_when_no_pbk(self):
        from chimera.modules.entry_mirrors import _parse_vless_link
        link = "vless://uuid@1.2.3.4:443?type=tcp&security=reality&sid=abcd&sni=vpn.example.com#label"
        self.assertIsNone(_parse_vless_link(link))

    def test_default_port_is_443(self):
        from chimera.modules.entry_mirrors import _parse_vless_link
        link = "vless://uuid@1.2.3.4?type=tcp&security=reality&pbk=PUBKEY&sid=abcd&sni=vpn.example.com#label"
        result = _parse_vless_link(link)
        self.assertIsNotNone(result)
        self.assertEqual(result["port"], 443)

    def test_default_fp_is_chrome(self):
        from chimera.modules.entry_mirrors import _parse_vless_link
        link = "vless://uuid@1.2.3.4:443?type=tcp&security=reality&pbk=PUBKEY&sid=abcd&sni=vpn.example.com#label"
        result = _parse_vless_link(link)
        self.assertIsNotNone(result)
        self.assertEqual(result["fp"], "chrome")


class TestLoadSaveFind(unittest.TestCase):
    """_load / _save / _find — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "entry_mirrors.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.entry_mirrors._STATE_FILE", self._state)

    def test_load_returns_default_when_no_file(self):
        from chimera.modules.entry_mirrors import _load
        with self._patch():
            result = _load()
        self.assertIn("mirrors", result)
        self.assertEqual(result["mirrors"], [])

    def test_load_returns_default_on_corrupt(self):
        from chimera.modules.entry_mirrors import _load
        self._state.write_text("{invalid")
        with self._patch():
            result = _load()
        self.assertEqual(result["mirrors"], [])

    def test_save_then_load(self):
        from chimera.modules.entry_mirrors import _load, _save
        data = {"mirrors": [{"id": "m1", "host": "1.2.3.4", "port": 443}]}
        with self._patch():
            _save(data)
            loaded = _load()
        self.assertEqual(len(loaded["mirrors"]), 1)

    def test_save_sets_chmod_600(self):
        import stat
        from chimera.modules.entry_mirrors import _save
        with self._patch():
            _save({"mirrors": []})
        mode = stat.S_IMODE(os.stat(self._state).st_mode)
        self.assertEqual(mode, 0o600)

    def test_find_returns_mirror_when_found(self):
        from chimera.modules.entry_mirrors import _find
        data = {"mirrors": [{"id": "m1"}, {"id": "m2"}]}
        result = _find(data, "m2")
        self.assertIsNotNone(result)
        self.assertEqual(result["id"], "m2")

    def test_find_returns_none_when_not_found(self):
        from chimera.modules.entry_mirrors import _find
        data = {"mirrors": [{"id": "m1"}]}
        self.assertIsNone(_find(data, "nonexistent"))


class TestStatusStr(unittest.TestCase):
    """_status_str — строка статуса mirror."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_disabled(self):
        from chimera.modules.entry_mirrors import _status_str
        result = _status_str({"enabled": False})
        self.assertIn("выключен", result)

    def test_not_checked(self):
        from chimera.modules.entry_mirrors import _status_str
        result = _status_str({"enabled": True, "last_check": {}})
        self.assertIn("не проверялся", result)

    def test_ok(self):
        from chimera.modules.entry_mirrors import _status_str
        m = {"enabled": True, "last_check": {"ok": True, "latency_ms": 50}}
        result = _status_str(m)
        self.assertIn("живой", result)

    def test_unavailable(self):
        from chimera.modules.entry_mirrors import _status_str
        m = {"enabled": True, "last_check": {"ok": False}}
        result = _status_str(m)
        self.assertIn("недоступен", result)


class TestProbe(unittest.TestCase):
    """_probe — TCP проверка (mocked socket)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_true_on_success(self):
        from chimera.modules.entry_mirrors import _probe
        with patch("socket.create_connection"):
            ok, ms = _probe("1.2.3.4", 443)
        self.assertTrue(ok)
        self.assertIsNotNone(ms)

    def test_returns_false_on_failure(self):
        from chimera.modules.entry_mirrors import _probe
        with patch("socket.create_connection", side_effect=OSError("conn refused")):
            ok, ms = _probe("1.2.3.4", 443)
        self.assertFalse(ok)
        self.assertIsNone(ms)


class TestGetMirrorUris(unittest.TestCase):
    """get_mirror_uris — генерация URI списка."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "entry_mirrors.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.entry_mirrors._STATE_FILE", self._state)

    def test_returns_empty_when_no_mirrors(self):
        from chimera.modules.entry_mirrors import get_mirror_uris
        with self._patch():
            result = get_mirror_uris("uuid")
        self.assertEqual(result, [])

    def test_skips_disabled(self):
        from chimera.modules.entry_mirrors import get_mirror_uris
        data = {"mirrors": [{"id": "m1", "enabled": False,
                              "host": "1.2.3.4", "pbk": "P", "sid": "s",
                              "sni": "x", "port": 443}]}
        with self._patch():
            self._state.write_text(json.dumps(data))
            result = get_mirror_uris("uuid")
        self.assertEqual(result, [])

    def test_skips_unhealthy_when_only_healthy(self):
        from chimera.modules.entry_mirrors import get_mirror_uris
        data = {"mirrors": [{"id": "m1", "enabled": True,
                              "last_check": {"ok": False},
                              "host": "1.2.3.4", "pbk": "P", "sid": "s",
                              "sni": "x", "port": 443}]}
        with self._patch():
            self._state.write_text(json.dumps(data))
            result = get_mirror_uris("uuid", only_healthy=True)
        self.assertEqual(result, [])

    def test_includes_healthy_mirror(self):
        from chimera.modules import entry_mirrors
        data = {"mirrors": [{"id": "m1", "enabled": True,
                              "last_check": {"ok": True},
                              "host": "1.2.3.4", "pbk": "P", "sid": "s",
                              "sni": "x", "port": 443, "label": "test"}]}
        with self._patch():
            self._state.write_text(json.dumps(data))
            with patch.object(entry_mirrors, "_gen_vless_link",
                              return_value="vless://u@1.2.3.4:443?type=tcp&security=reality&pbk=P&sid=s&sni=x&fp=chrome#"):
                result = entry_mirrors.get_mirror_uris("uuid", only_healthy=True)
        self.assertEqual(len(result), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
