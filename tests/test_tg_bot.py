#!/usr/bin/env python3
"""
tests/test_tg_bot.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/tg_bot.py.

Покрывает:
  1. _get_vless_link — генерация VLESS-ссылки (reality + xhttp, Mode B/AWG)
  2. tg_load / tg_save — JSON I/O
  3. _bot_load / _bot_save — JSON I/O
  4. _load_state — чтение state.json
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


class TestGetVlessLink(unittest.TestCase):
    """_get_vless_link — генерация VLESS-ссылки."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state(self, state_dict):
        self._state.write_text(json.dumps(state_dict))
        return patch("vless_installer.modules.tg_bot._STATE_FILE", self._state)

    def test_reality_mode(self):
        from vless_installer.modules.tg_bot import _get_vless_link
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
            "reality_dest": "dest.example.com:443",
            "fingerprint": "chrome",
            "xtls_flow": "xtls-rprx-vision",
        }
        with self._patch_state(state):
            link = _get_vless_link()
        self.assertTrue(link.startswith("vless://test-uuid@"))
        self.assertIn("vpn.example.com", link)
        self.assertIn("security=reality", link)
        self.assertIn("pbk=PUBKEY", link)
        self.assertIn("sid=abcd1234", link)
        self.assertIn("flow=xtls-rprx-vision", link)

    def test_reality_mode_b_awg_uses_reality_dest_sni(self):
        """Mode B + AWG: SNI берётся из reality_dest, а не domain."""
        from vless_installer.modules.tg_bot import _get_vless_link
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd",
            "reality_dest": "dest.example.com:443",
            "awg_exit_enabled": True,
            "install_mode": "B",
        }
        with self._patch_state(state):
            link = _get_vless_link()
        self.assertIn("sni=dest.example.com", link)

    def test_reality_mode_a_uses_domain_sni(self):
        """Mode A: SNI берётся из domain."""
        from vless_installer.modules.tg_bot import _get_vless_link
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd",
            "reality_dest": "dest.example.com:443",
            "install_mode": "A",
        }
        with self._patch_state(state):
            link = _get_vless_link()
        self.assertIn("sni=vpn.example.com", link)

    def test_xhttp_mode(self):
        from vless_installer.modules.tg_bot import _get_vless_link
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "xhttp",
            "xhttp_path": "/xhttp",
            "xhttp_mode": "streamup",
            "fingerprint": "chrome",
            "server_port": 443,
        }
        with self._patch_state(state):
            link = _get_vless_link()
        self.assertIn("type=xhttp", link)
        self.assertIn("security=tls", link)
        self.assertIn("path=/xhttp", link)

    def test_returns_empty_when_no_domain(self):
        from vless_installer.modules.tg_bot import _get_vless_link
        state = {"uuid": "test-uuid"}
        with self._patch_state(state):
            self.assertEqual(_get_vless_link(), "")

    def test_returns_empty_when_no_uuid(self):
        from vless_installer.modules.tg_bot import _get_vless_link
        state = {"domain": "vpn.example.com"}
        with self._patch_state(state):
            self.assertEqual(_get_vless_link(), "")

    def test_reality_without_flow(self):
        """Без xtls_flow — параметр flow не добавляется."""
        from vless_installer.modules.tg_bot import _get_vless_link
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd",
            "reality_dest": "dest:443",
            "xtls_flow": "",
        }
        with self._patch_state(state):
            link = _get_vless_link()
        self.assertNotIn("flow=", link)

    def test_default_fingerprint_is_chrome(self):
        from vless_installer.modules.tg_bot import _get_vless_link
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd",
            "reality_dest": "dest:443",
        }
        with self._patch_state(state):
            link = _get_vless_link()
        self.assertIn("fp=chrome", link)


class TestTgLoadSave(unittest.TestCase):
    """tg_load / tg_save — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._notif = self._tmpdir / "telegram.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.tg_bot._NOTIF_FILE", self._notif)

    def test_load_returns_empty_when_no_file(self):
        from vless_installer.modules.tg_bot import tg_load
        with self._patch():
            self.assertEqual(tg_load(), {})

    def test_save_then_load(self):
        from vless_installer.modules.tg_bot import tg_load, tg_save
        with self._patch():
            tg_save({"bot_token": "abc", "admin_id": "123"})
            loaded = tg_load()
        self.assertEqual(loaded["bot_token"], "abc")
        self.assertEqual(loaded["admin_id"], "123")

    def test_save_sets_chmod_600(self):
        import stat
        from vless_installer.modules.tg_bot import tg_save
        with self._patch():
            tg_save({"x": 1})
        mode = stat.S_IMODE(os.stat(self._notif).st_mode)
        self.assertEqual(mode, 0o600)


class TestBotLoadSave(unittest.TestCase):
    """_bot_load / _bot_save — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._bot = self._tmpdir / "tg_bot.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.tg_bot._BOT_FILE", self._bot)

    def test_load_returns_empty_when_no_file(self):
        from vless_installer.modules.tg_bot import _bot_load
        with self._patch():
            self.assertEqual(_bot_load(), {})

    def test_save_then_load(self):
        from vless_installer.modules.tg_bot import _bot_load, _bot_save
        with self._patch():
            _bot_save({"users": {"alice": "uuid1"}})
            loaded = _bot_load()
        self.assertIn("alice", loaded["users"])


class TestLoadState(unittest.TestCase):
    """_load_state — чтение state.json."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.tg_bot._STATE_FILE", self._state)

    def test_returns_empty_when_no_file(self):
        from vless_installer.modules.tg_bot import _load_state
        with self._patch():
            self.assertEqual(_load_state(), {})

    def test_returns_state(self):
        from vless_installer.modules.tg_bot import _load_state
        self._state.write_text(json.dumps({"domain": "x.com"}))
        with self._patch():
            st = _load_state()
        self.assertEqual(st["domain"], "x.com")


if __name__ == "__main__":
    unittest.main(verbosity=2)
