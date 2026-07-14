#!/usr/bin/env python3
"""
tests/test_fragment_share.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/fragment_share.py.

Покрывает:
  1. _free_port — поиск свободного порта (mocked socket)
  2. _list_configs — список конфигов
"""
from __future__ import annotations

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


class TestFreePort(unittest.TestCase):
    """_free_port — поиск свободного порта."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_port_in_range(self):
        from chimera.modules.fragment_share import _free_port, _PORT_RANGE
        mock_sock = MagicMock()
        mock_sock.__enter__.return_value = mock_sock  # context manager returns self
        mock_sock.connect_ex.return_value = 1  # port free
        with patch("random.randint", return_value=35000), \
             patch("chimera.modules.fragment_share.socket.socket",
                   return_value=mock_sock):
            port = _free_port()
        self.assertEqual(port, 35000)

    def test_retries_on_occupied_port(self):
        from chimera.modules.fragment_share import _free_port
        mock_sock_busy = MagicMock()
        mock_sock_busy.__enter__.return_value = mock_sock_busy
        mock_sock_busy.connect_ex.return_value = 0  # port occupied
        mock_sock_free = MagicMock()
        mock_sock_free.__enter__.return_value = mock_sock_free
        mock_sock_free.connect_ex.return_value = 1  # port free
        with patch("random.randint", side_effect=[35000, 35001]), \
             patch("chimera.modules.fragment_share.socket.socket",
                   side_effect=[mock_sock_busy, mock_sock_free]):
            port = _free_port()
        self.assertEqual(port, 35001)


class TestListConfigs(unittest.TestCase):
    """_list_configs — список конфигов."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.fragment_share._FRAG_DIR", self._tmpdir)

    def test_returns_empty_when_no_dir(self):
        from chimera.modules.fragment_share import _list_configs
        with patch("chimera.modules.fragment_share._FRAG_DIR",
                   Path("/tmp/nonexistent_frag_dir")):
            self.assertEqual(_list_configs(), [])

    def test_returns_empty_when_no_configs(self):
        from chimera.modules.fragment_share import _list_configs
        with self._patch():
            self.assertEqual(_list_configs(), [])

    def test_returns_sorted_json_files(self):
        from chimera.modules.fragment_share import _list_configs
        (self._tmpdir / "b.json").write_text("{}")
        (self._tmpdir / "a.json").write_text("{}")
        (self._tmpdir / "not_json.txt").write_text("x")
        with self._patch():
            result = _list_configs()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].name, "a.json")
        self.assertEqual(result[1].name, "b.json")


if __name__ == "__main__":
    unittest.main(verbosity=2)
