#!/usr/bin/env python3
"""
tests/test_fptn.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/fptn.py.

Покрывает:
  1. _valid_username — валидация имени пользователя
  2. _detect_arch — определение архитектуры
  3. _pick_server_asset — выбор ассета из GitHub release
  4. _save_user_to_state / _remove_user_from_state — CRUD пользователей
  5. _is_installed — проверка установки
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


class TestValidUsername(unittest.TestCase):
    """_valid_username — валидация имени пользователя."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_valid_alphanumeric(self):
        from vless_installer.modules.fptn import _valid_username
        self.assertTrue(_valid_username("alice"))
        self.assertTrue(_valid_username("bob123"))

    def test_invalid_hyphen(self):
        from vless_installer.modules.fptn import _valid_username
        self.assertFalse(_valid_username("alice-bob"))

    def test_invalid_underscore(self):
        from vless_installer.modules.fptn import _valid_username
        self.assertFalse(_valid_username("alice_bob"))

    def test_invalid_empty(self):
        from vless_installer.modules.fptn import _valid_username
        self.assertFalse(_valid_username(""))

    def test_invalid_dot(self):
        from vless_installer.modules.fptn import _valid_username
        self.assertFalse(_valid_username("alice.bob"))

    def test_invalid_space(self):
        from vless_installer.modules.fptn import _valid_username
        self.assertFalse(_valid_username("alice bob"))


class TestDetectArch(unittest.TestCase):
    """_detect_arch — определение архитектуры."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_x86_64(self):
        from vless_installer.modules.fptn import _detect_arch
        with patch("platform.machine", return_value="x86_64"):
            self.assertEqual(_detect_arch(), "amd64")

    def test_amd64(self):
        from vless_installer.modules.fptn import _detect_arch
        with patch("platform.machine", return_value="amd64"):
            self.assertEqual(_detect_arch(), "amd64")

    def test_aarch64(self):
        from vless_installer.modules.fptn import _detect_arch
        with patch("platform.machine", return_value="aarch64"):
            self.assertEqual(_detect_arch(), "arm64")

    def test_arm64(self):
        from vless_installer.modules.fptn import _detect_arch
        with patch("platform.machine", return_value="arm64"):
            self.assertEqual(_detect_arch(), "arm64")

    def test_unsupported_returns_none(self):
        from vless_installer.modules.fptn import _detect_arch
        with patch("platform.machine", return_value="i386"):
            self.assertIsNone(_detect_arch())
        with patch("platform.machine", return_value="mips"):
            self.assertIsNone(_detect_arch())


class TestPickServerAsset(unittest.TestCase):
    """_pick_server_asset — выбор ассета из GitHub release."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_url_when_match(self):
        from vless_installer.modules.fptn import _pick_server_asset
        release = {"assets": [
            {"name": "fptn-server-1.0.0_linux_amd64.deb",
             "browser_download_url": "https://example.com/fptn.deb"},
        ]}
        result = _pick_server_asset(release, "amd64")
        self.assertEqual(result, "https://example.com/fptn.deb")

    def test_returns_none_when_no_match(self):
        from vless_installer.modules.fptn import _pick_server_asset
        release = {"assets": [
            {"name": "other-package.deb", "browser_download_url": "url"},
        ]}
        self.assertIsNone(_pick_server_asset(release, "amd64"))

    def test_returns_none_when_wrong_arch(self):
        from vless_installer.modules.fptn import _pick_server_asset
        release = {"assets": [
            {"name": "fptn-server-1.0.0_linux_arm64.deb",
             "browser_download_url": "url"},
        ]}
        self.assertIsNone(_pick_server_asset(release, "amd64"))

    def test_returns_none_when_empty_assets(self):
        from vless_installer.modules.fptn import _pick_server_asset
        self.assertIsNone(_pick_server_asset({"assets": []}, "amd64"))

    def test_returns_none_when_no_assets_key(self):
        from vless_installer.modules.fptn import _pick_server_asset
        self.assertIsNone(_pick_server_asset({}, "amd64"))


class TestSaveUserToState(unittest.TestCase):
    """_save_user_to_state — добавление/обновление пользователя."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "fptn.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.fptn._MODULE_STATE", self._state)

    def test_adds_new_user(self):
        from vless_installer.modules.fptn import _save_user_to_state
        with self._patch():
            _save_user_to_state("alice", "pass1", 10000)
        state = json.loads(self._state.read_text())
        self.assertEqual(len(state["users"]), 1)
        self.assertEqual(state["users"][0]["username"], "alice")
        self.assertEqual(state["users"][0]["password"], "pass1")
        self.assertEqual(state["users"][0]["bandwidth"], 10000)

    def test_replaces_existing_user(self):
        from vless_installer.modules.fptn import _save_user_to_state
        with self._patch():
            _save_user_to_state("alice", "old", 5000)
            _save_user_to_state("alice", "new", 10000)
        state = json.loads(self._state.read_text())
        self.assertEqual(len(state["users"]), 1)
        self.assertEqual(state["users"][0]["password"], "new")
        self.assertEqual(state["users"][0]["bandwidth"], 10000)

    def test_preserves_other_users(self):
        from vless_installer.modules.fptn import _save_user_to_state
        with self._patch():
            _save_user_to_state("alice", "p1", 100)
            _save_user_to_state("bob", "p2", 200)
        state = json.loads(self._state.read_text())
        self.assertEqual(len(state["users"]), 2)


class TestRemoveUserFromState(unittest.TestCase):
    """_remove_user_from_state — удаление пользователя."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "fptn.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.fptn._MODULE_STATE", self._state)

    def test_removes_existing_user(self):
        from vless_installer.modules.fptn import _save_user_to_state, _remove_user_from_state
        with self._patch():
            _save_user_to_state("alice", "p1", 100)
            _save_user_to_state("bob", "p2", 200)
            _remove_user_from_state("alice")
        state = json.loads(self._state.read_text())
        self.assertEqual(len(state["users"]), 1)
        self.assertEqual(state["users"][0]["username"], "bob")

    def test_no_change_when_user_not_found(self):
        from vless_installer.modules.fptn import _save_user_to_state, _remove_user_from_state
        with self._patch():
            _save_user_to_state("alice", "p1", 100)
            _remove_user_from_state("nobody")
        state = json.loads(self._state.read_text())
        self.assertEqual(len(state["users"]), 1)


class TestIsInstalled(unittest.TestCase):
    """_is_installed."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._bin = self._tmpdir / "fptn-server"
        self._svc = self._tmpdir / "fptn.service"
        self._cfg = self._tmpdir / "fptn.conf"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("vless_installer.modules.fptn._BIN_SERVER", self._bin),
            patch("vless_installer.modules.fptn._SERVICE_FILE", self._svc),
            patch("vless_installer.modules.fptn._CFG_FILE", self._cfg),
        )

    def test_returns_false_when_neither(self):
        from vless_installer.modules.fptn import _is_installed
        with self._patch()[0], self._patch()[1], self._patch()[2]:
            self.assertFalse(_is_installed())

    def test_returns_true_when_all(self):
        from vless_installer.modules.fptn import _is_installed
        self._bin.write_text("x")
        self._svc.write_text("x")
        self._cfg.write_text("x")
        with self._patch()[0], self._patch()[1], self._patch()[2]:
            self.assertTrue(_is_installed())


if __name__ == "__main__":
    unittest.main(verbosity=2)
