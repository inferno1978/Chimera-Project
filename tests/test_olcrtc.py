#!/usr/bin/env python3
"""
tests/test_olcrtc.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/olcrtc.py.

Покрывает:
  1. _ver_tuple — парсинг версии
  2. _sanitize_name — санитизация имени
  3. _gen_key / _gen_jitsi_room_path — генерация ключей
  4. _link_unit — имя systemd-юнита
  5. _next_socks_port — поиск свободного порта
  6. _load_state / _save_state — JSON I/O
"""
from __future__ import annotations

import json
import os
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


class TestVerTuple(unittest.TestCase):
    """_ver_tuple — парсинг версии."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_full_version(self):
        from vless_installer.modules.olcrtc import _ver_tuple
        self.assertEqual(_ver_tuple("1.26.3"), (1, 26, 3))

    def test_two_part(self):
        from vless_installer.modules.olcrtc import _ver_tuple
        self.assertEqual(_ver_tuple("1.26"), (1, 26, 0))

    def test_with_prefix(self):
        from vless_installer.modules.olcrtc import _ver_tuple
        self.assertEqual(_ver_tuple("go1.26"), (1, 26, 0))

    def test_empty_returns_zeros(self):
        from vless_installer.modules.olcrtc import _ver_tuple
        self.assertEqual(_ver_tuple(""), (0, 0, 0))

    def test_invalid_returns_zeros(self):
        from vless_installer.modules.olcrtc import _ver_tuple
        self.assertEqual(_ver_tuple("abc"), (0, 0, 0))


class TestSanitizeName(unittest.TestCase):
    """_sanitize_name — санитизация имени."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_lowercases(self):
        from vless_installer.modules.olcrtc import _sanitize_name
        self.assertEqual(_sanitize_name("HELLO"), "hello")

    def test_removes_special_chars(self):
        from vless_installer.modules.olcrtc import _sanitize_name
        self.assertEqual(_sanitize_name("hello world!"), "helloworld")

    def test_keeps_alnum_hyphen_underscore(self):
        from vless_installer.modules.olcrtc import _sanitize_name
        self.assertEqual(_sanitize_name("test-1_2"), "test-1_2")

    def test_truncates_to_32(self):
        from vless_installer.modules.olcrtc import _sanitize_name
        result = _sanitize_name("a" * 50)
        self.assertEqual(len(result), 32)

    def test_strips_whitespace(self):
        from vless_installer.modules.olcrtc import _sanitize_name
        self.assertEqual(_sanitize_name("  hello  "), "hello")

    def test_removes_cyrillic(self):
        from vless_installer.modules.olcrtc import _sanitize_name
        self.assertEqual(_sanitize_name("привет"), "")


class TestGenKey(unittest.TestCase):
    """_gen_key — генерация ключа."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_64_hex_chars(self):
        from vless_installer.modules.olcrtc import _gen_key
        key = _gen_key()
        self.assertEqual(len(key), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in key))

    def test_unique(self):
        from vless_installer.modules.olcrtc import _gen_key
        keys = {_gen_key() for _ in range(10)}
        self.assertEqual(len(keys), 10)


class TestGenJitsiRoomPath(unittest.TestCase):
    """_gen_jitsi_room_path — генерация пути комнаты."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_starts_with_olc_prefix(self):
        from vless_installer.modules.olcrtc import _gen_jitsi_room_path
        path = _gen_jitsi_room_path()
        self.assertTrue(path.startswith("olc-"))

    def test_has_8_hex_chars_after_prefix(self):
        from vless_installer.modules.olcrtc import _gen_jitsi_room_path
        path = _gen_jitsi_room_path()
        suffix = path[4:]
        self.assertEqual(len(suffix), 8)
        self.assertTrue(all(c in "0123456789abcdef" for c in suffix))


class TestLinkUnit(unittest.TestCase):
    """_link_unit — имя systemd-юнита."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_unit_name(self):
        from vless_installer.modules.olcrtc import _link_unit
        self.assertEqual(_link_unit("test"), "olcrtc@test.service")


class TestNextSocksPort(unittest.TestCase):
    """_next_socks_port — поиск свободного порта."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_8808_when_empty(self):
        from vless_installer.modules.olcrtc import _next_socks_port
        st = {"links": {}}
        self.assertEqual(_next_socks_port(st), 8808)

    def test_skips_used_ports(self):
        from vless_installer.modules.olcrtc import _next_socks_port
        st = {"links": {
            "link1": {"socks_port": 8808},
            "link2": {"socks_port": 8809},
        }}
        self.assertEqual(_next_socks_port(st), 8810)

    def test_finds_gap(self):
        from vless_installer.modules.olcrtc import _next_socks_port
        st = {"links": {
            "link1": {"socks_port": 8808},
            "link2": {"socks_port": 8810},
        }}
        self.assertEqual(_next_socks_port(st), 8809)


class TestLoadSaveState(unittest.TestCase):
    """_load_state / _save_state — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "olcrtc.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.olcrtc.OLC_STATE_FILE", self._state)

    def test_load_returns_default_when_no_file(self):
        from vless_installer.modules.olcrtc import _load_state
        with self._patch():
            st = _load_state()
        self.assertFalse(st["installed"])
        self.assertEqual(st["links"], {})

    def test_load_returns_default_on_corrupt(self):
        from vless_installer.modules.olcrtc import _load_state
        self._state.write_text("{invalid")
        with self._patch():
            st = _load_state()
        self.assertFalse(st["installed"])

    def test_save_then_load(self):
        from vless_installer.modules.olcrtc import _load_state, _save_state
        with self._patch():
            _save_state({"installed": True, "links": {"l1": {"socks_port": 8808}}})
            loaded = _load_state()
        self.assertTrue(loaded["installed"])
        self.assertIn("l1", loaded["links"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
