#!/usr/bin/env python3
"""
tests/test_credential_rotation.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/credential_rotation.py.

Покрывает:
  1. _uuid_rotate_now — ротация UUID (mocked config/state/users)
  2. _rotate_reality_keys — ротация REALITY ключей (mocked _run)
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


class TestUuidRotateNow(unittest.TestCase):
    """_uuid_rotate_now — ротация UUID."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "config.json"
        self._state = self._tmpdir / "state.json"
        self._users = self._tmpdir / "users.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _mock_core(self):
        core = MagicMock()
        core.STATE_FILE = self._state
        core.USERS_FILE = self._users
        core.CONFIG_DIR = self._tmpdir
        core.warn = MagicMock()
        return core

    def test_returns_new_uuid(self):
        from vless_installer.modules import credential_rotation
        cfg = {"inbounds": [{"settings": {"clients": [{"id": "old-uuid"}]}}]}
        self._cfg.write_text(json.dumps(cfg))
        self._state.write_text(json.dumps({"uuid": "old-uuid"}))
        self._users.write_text(json.dumps([{"uuid": "old-uuid"}]))
        with patch.object(credential_rotation, "_core_module",
                          return_value=self._mock_core()):
            result = credential_rotation._uuid_rotate_now()
        self.assertIsNotNone(result)
        self.assertNotEqual(result, "old-uuid")
        # config обновлён
        new_cfg = json.loads(self._cfg.read_text())
        self.assertEqual(new_cfg["inbounds"][0]["settings"]["clients"][0]["id"], result)
        # state обновлён
        new_state = json.loads(self._state.read_text())
        self.assertEqual(new_state["uuid"], result)
        # users обновлён
        new_users = json.loads(self._users.read_text())
        self.assertEqual(new_users[0]["uuid"], result)

    def test_returns_uuid_even_without_config(self):
        """Если config.json не существует — функция пропускает его
        и возвращает новый UUID (не возвращает "")."""
        from vless_installer.modules import credential_rotation
        with patch.object(credential_rotation, "_core_module",
                          return_value=self._mock_core()):
            result = credential_rotation._uuid_rotate_now()
        self.assertNotEqual(result, "")
        # это валидный UUID
        import re
        self.assertRegex(result,
                         r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class TestRotateRealityKeys(unittest.TestCase):
    """_rotate_reality_keys — ротация REALITY ключей."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "config.json"
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _mock_core(self):
        core = MagicMock()
        core.STATE_FILE = self._state
        core.CONFIG_DIR = self._tmpdir
        core.warn = MagicMock()
        core.log_to_file = MagicMock()
        core._tg_notify_event = MagicMock()
        # xray x25519 возвращает Private key / Public key
        run_result = MagicMock()
        run_result.returncode = 0
        run_result.stdout = "Private key: NEW_PRIV\nPublic key: NEW_PUB\n"
        run_result.stderr = ""
        core._run = MagicMock(return_value=run_result)
        return core

    def test_returns_new_keys(self):
        from vless_installer.modules import credential_rotation
        cfg = {"inbounds": [{"streamSettings": {"realitySettings": {
            "privateKey": "old_priv", "publicKey": "old_pub",
            "shortIds": ["old_sid"],
        }}}]}
        self._cfg.write_text(json.dumps(cfg))
        self._state.write_text(json.dumps({
            "private_key": "old_priv", "public_key": "old_pub",
            "short_id": "old_sid",
        }))
        orig_exists = Path.exists
        def _conditional_exists(self):
            if "vless_link" in str(self):
                return False
            return orig_exists(self)
        with patch.object(credential_rotation, "_core_module",
                          return_value=self._mock_core()), \
             patch("pathlib.Path.exists", _conditional_exists):
            result = credential_rotation._rotate_reality_keys()
        self.assertIn("private_key", result)
        self.assertIn("public_key", result)
        self.assertIn("short_id", result)
        self.assertEqual(result["private_key"], "NEW_PRIV")
        self.assertEqual(result["public_key"], "NEW_PUB")

    def test_returns_empty_on_failure(self):
        from vless_installer.modules import credential_rotation
        core = self._mock_core()
        run_result = MagicMock()
        run_result.returncode = 1
        run_result.stdout = ""
        run_result.stderr = "error"
        core._run = MagicMock(return_value=run_result)
        with patch.object(credential_rotation, "_core_module", return_value=core):
            result = credential_rotation._rotate_reality_keys()
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
