#!/usr/bin/env python3
"""
tests/test_turntunnel_links.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/turntunnel_links.py.

Покрывает:
  1. _validate_vk_link — валидация VK-ссылки
  2. _pool_stats — статистика пула ссылок
  3. _short_id — генерация short ID
  4. _now_str — текущая дата/время
  5. _plain / _wlen — unicode helpers
  6. _load_links / _save_links — JSON I/O
  7. _find_link — поиск по ID
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

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


class TestValidateVkLink(unittest.TestCase):
    """_validate_vk_link — pure validator."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_valid_vk_com(self):
        from chimera.modules.turntunnel_links import _validate_vk_link
        self.assertTrue(_validate_vk_link("https://vk.com/call/join/abc123"))

    def test_valid_m_vk_com(self):
        from chimera.modules.turntunnel_links import _validate_vk_link
        self.assertTrue(_validate_vk_link("https://m.vk.com/call/join/abc123"))

    def test_valid_vk_ru(self):
        from chimera.modules.turntunnel_links import _validate_vk_link
        self.assertTrue(_validate_vk_link("https://vk.ru/call/join/abc123"))

    def test_valid_http(self):
        from chimera.modules.turntunnel_links import _validate_vk_link
        self.assertTrue(_validate_vk_link("http://vk.com/call/join/abc123"))

    def test_valid_with_trailing_slash(self):
        from chimera.modules.turntunnel_links import _validate_vk_link
        self.assertTrue(_validate_vk_link("https://vk.com/call/join/abc123/"))

    def test_valid_with_special_chars_in_id(self):
        from chimera.modules.turntunnel_links import _validate_vk_link
        self.assertTrue(_validate_vk_link("https://vk.com/call/join/abc-123_def"))

    def test_invalid_other_domain(self):
        from chimera.modules.turntunnel_links import _validate_vk_link
        self.assertFalse(_validate_vk_link("https://example.com/call/join/abc"))

    def test_invalid_no_call_join(self):
        from chimera.modules.turntunnel_links import _validate_vk_link
        self.assertFalse(_validate_vk_link("https://vk.com/some/other/path"))

    def test_invalid_empty(self):
        from chimera.modules.turntunnel_links import _validate_vk_link
        self.assertFalse(_validate_vk_link(""))


class TestPoolStats(unittest.TestCase):
    """_pool_stats — pure."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_list(self):
        from chimera.modules.turntunnel_links import _pool_stats
        result = _pool_stats([])
        self.assertEqual(result["total"], 0)
        self.assertEqual(result["active"], 0)
        self.assertEqual(result["assigned"], 0)
        self.assertEqual(result["free"], 0)

    def test_mixed_links(self):
        from chimera.modules.turntunnel_links import _pool_stats
        links = [
            {"active": True, "assigned_to": "alice"},
            {"active": True, "assigned_to": ""},
            {"active": False, "assigned_to": "bob"},
            {"active": True, "assigned_to": "carol"},
        ]
        result = _pool_stats(links)
        self.assertEqual(result["total"], 4)
        self.assertEqual(result["active"], 3)
        self.assertEqual(result["assigned"], 3)  # alice, bob, carol
        self.assertEqual(result["free"], 1)  # active + not assigned


class TestShortId(unittest.TestCase):
    """_short_id — pure."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_8_hex_chars(self):
        from chimera.modules.turntunnel_links import _short_id
        sid = _short_id()
        self.assertEqual(len(sid), 8)
        self.assertTrue(all(c in "0123456789abcdef" for c in sid))

    def test_unique(self):
        from chimera.modules.turntunnel_links import _short_id
        ids = {_short_id() for _ in range(20)}
        self.assertGreater(len(ids), 1)


class TestNowStr(unittest.TestCase):
    """_now_str — pure."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_formatted_string(self):
        from chimera.modules.turntunnel_links import _now_str
        result = _now_str()
        # YYYY-MM-DD HH:MM
        self.assertRegex(result, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$")


class TestPlain(unittest.TestCase):
    """_plain — strip ANSI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_plain_string_unchanged(self):
        from chimera.modules.turntunnel_links import _plain
        self.assertEqual(_plain("hello"), "hello")

    def test_strips_ansi(self):
        from chimera.modules.turntunnel_links import _plain
        self.assertEqual(_plain("\033[1;31mhi\033[0m"), "hi")


class TestWlen(unittest.TestCase):
    """_wlen — display width."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ascii(self):
        from chimera.modules.turntunnel_links import _wlen
        self.assertEqual(_wlen("hello"), 5)

    def test_emoji_two_columns(self):
        from chimera.modules.turntunnel_links import _wlen
        self.assertEqual(_wlen("🚀"), 2)

    def test_ansi_zero_width(self):
        from chimera.modules.turntunnel_links import _wlen
        self.assertEqual(_wlen("\033[1mhi\033[0m"), 2)


class TestLoadSaveLinks(unittest.TestCase):
    """_load_links / _save_links — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._links = self._tmpdir / "links.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.turntunnel_links._LINKS_FILE",
                     self._links)

    def test_load_returns_empty_when_no_file(self):
        from chimera.modules.turntunnel_links import _load_links
        with self._patch():
            self.assertEqual(_load_links(), [])

    def test_load_returns_empty_on_corrupt(self):
        from chimera.modules.turntunnel_links import _load_links
        self._links.write_text("{invalid")
        with self._patch():
            self.assertEqual(_load_links(), [])

    def test_load_returns_empty_when_not_list(self):
        from chimera.modules.turntunnel_links import _load_links
        self._links.write_text('{"not": "a list"}')
        with self._patch():
            self.assertEqual(_load_links(), [])

    def test_save_then_load(self):
        from chimera.modules.turntunnel_links import _load_links, _save_links
        with self._patch():
            _save_links([{"id": "abc", "link": "x"}])
            loaded = _load_links()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["id"], "abc")


class TestFindLink(unittest.TestCase):
    """_find_link — поиск по ID."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_none_when_not_found(self):
        from chimera.modules.turntunnel_links import _find_link
        self.assertIsNone(_find_link([], "abc"))

    def test_returns_link_when_found(self):
        from chimera.modules.turntunnel_links import _find_link
        links = [{"id": "abc"}, {"id": "def"}]
        result = _find_link(links, "def")
        self.assertEqual(result["id"], "def")

    def test_returns_first_when_duplicate_ids(self):
        from chimera.modules.turntunnel_links import _find_link
        links = [{"id": "abc", "v": 1}, {"id": "abc", "v": 2}]
        result = _find_link(links, "abc")
        self.assertEqual(result["v"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
