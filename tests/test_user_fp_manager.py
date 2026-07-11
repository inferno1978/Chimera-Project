#!/usr/bin/env python3
"""
tests/test_user_fp_manager.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/user_fp_manager.py.

Покрывает:
  1. patch_tg_bot_script — идемпотентная вставка FP-команд в TG-бот скрипт
  2. current_fp — определение текущего fingerprint
  3. _patch_config_fp — замена fingerprint в Xray config
  4. _update_state_fp — обновление state
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


class TestPatchTgBotScript(unittest.TestCase):
    """patch_tg_bot_script — pure string replacement с идемпотентностью."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_input_returns_empty(self):
        from vless_installer.modules.user_fp_manager import patch_tg_bot_script
        result = patch_tg_bot_script("")
        # пустой ввод — ничего не вставляется
        self.assertEqual(result, "")

    def test_inserts_fp_commands_before_handle_start(self):
        from vless_installer.modules.user_fp_manager import (
            patch_tg_bot_script, TG_FP_COMMANDS_BLOCK,
        )
        script = "def handle_start(msg, args):\n    pass\n"
        result = patch_tg_bot_script(script)
        self.assertIn("handle_fp", result)
        self.assertIn(TG_FP_COMMANDS_BLOCK, result)

    def test_idempotent_on_repeated_call(self):
        """Повторный вызов не дублирует вставки."""
        from vless_installer.modules.user_fp_manager import patch_tg_bot_script
        script = (
            "def handle_start(msg, args):\n    pass\n"
            "elif cmd == \"/help\":   handle_help(msg)\n"
        )
        once = patch_tg_bot_script(script)
        twice = patch_tg_bot_script(once)
        # количество вхождений handle_fp должно быть одинаковым
        self.assertEqual(once.count("handle_fp"), twice.count("handle_fp"))

    def test_adds_fp_dispatcher_to_help_handler(self):
        from vless_installer.modules.user_fp_manager import patch_tg_bot_script
        script = 'elif cmd == "/help":   handle_help(msg)\n'
        result = patch_tg_bot_script(script)
        # должна добавиться диспетчеризация /fp
        self.assertIn("/fp", result)

    def test_no_anchors_no_changes(self):
        """Без якорей — возвращается исходный текст (возможно с пустыми вставками)."""
        from vless_installer.modules.user_fp_manager import patch_tg_bot_script
        script = "print('hello')\n"
        result = patch_tg_bot_script(script)
        # ничего не вставилось, потому что нет якорей
        self.assertNotIn("handle_fp", result)


class TestCurrentFp(unittest.TestCase):
    """current_fp — определение fingerprint."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"
        self._cfg_dir = self._tmpdir / "xray"
        self._cfg_dir.mkdir()
        self._cfg = self._cfg_dir / "config.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("vless_installer.modules.user_fp_manager._STATE_FILE", self._state),
            patch("vless_installer.modules.user_fp_manager._CONFIG_DIRS", [self._cfg_dir]),
        )

    def test_returns_chrome_when_nothing_found(self):
        from vless_installer.modules.user_fp_manager import current_fp
        with self._patch()[0], self._patch()[1]:
            self.assertEqual(current_fp(), "chrome")

    def test_returns_fp_from_state(self):
        from vless_installer.modules.user_fp_manager import current_fp
        self._state.write_text(json.dumps({"fingerprint": "firefox"}))
        with self._patch()[0], self._patch()[1]:
            self.assertEqual(current_fp(), "firefox")

    def test_returns_fp_from_config_reality(self):
        from vless_installer.modules.user_fp_manager import current_fp
        self._cfg.write_text(json.dumps({
            "outbounds": [{
                "streamSettings": {
                    "realitySettings": {"fingerprint": "safari"},
                },
            }],
        }))
        with self._patch()[0], self._patch()[1]:
            self.assertEqual(current_fp(), "safari")

    def test_returns_fp_from_config_tls(self):
        from vless_installer.modules.user_fp_manager import current_fp
        self._cfg.write_text(json.dumps({
            "outbounds": [{
                "streamSettings": {
                    "tlsSettings": {"fingerprint": "ios"},
                },
            }],
        }))
        with self._patch()[0], self._patch()[1]:
            self.assertEqual(current_fp(), "ios")


class TestPatchConfigFp(unittest.TestCase):
    """_patch_config_fp — замена fingerprint в Xray config."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_dir = self._tmpdir / "xray"
        self._cfg_dir.mkdir()
        self._cfg = self._cfg_dir / "config.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.user_fp_manager._CONFIG_DIRS",
                     [self._cfg_dir])

    def test_returns_false_when_no_config(self):
        from vless_installer.modules.user_fp_manager import _patch_config_fp
        with self._patch():
            changed, err = _patch_config_fp("firefox")
        self.assertFalse(changed)

    def test_replaces_reality_fingerprint(self):
        from vless_installer.modules.user_fp_manager import _patch_config_fp
        self._cfg.write_text(json.dumps({
            "outbounds": [{
                "streamSettings": {"realitySettings": {"fingerprint": "chrome"}},
            }],
        }))
        with self._patch():
            changed, err = _patch_config_fp("firefox")
        self.assertTrue(changed)
        cfg = json.loads(self._cfg.read_text())
        self.assertEqual(
            cfg["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"],
            "firefox",
        )

    def test_writes_even_when_same_value(self):
        """_patch_config_fp всегда перезаписывает (создаёт backup + write),
        даже если значение fingerprint не изменилось — это нормальное поведение
        для безопасного применения (гарантия что конфиг в нужном состоянии)."""
        from vless_installer.modules.user_fp_manager import _patch_config_fp
        self._cfg.write_text(json.dumps({
            "outbounds": [{
                "streamSettings": {"realitySettings": {"fingerprint": "firefox"}},
            }],
        }))
        with self._patch():
            changed, _ = _patch_config_fp("firefox")
        # changed=True, потому что файл перезаписан (backup создан)
        self.assertTrue(changed)
        # значение осталось тем же
        cfg = json.loads(self._cfg.read_text())
        self.assertEqual(
            cfg["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"],
            "firefox",
        )


class TestUpdateStateFp(unittest.TestCase):
    """_update_state_fp — обновление state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.user_fp_manager._STATE_FILE",
                     self._state)

    def test_does_not_raise_when_no_state(self):
        from vless_installer.modules.user_fp_manager import _update_state_fp
        with self._patch():
            _update_state_fp("firefox")  # не должно бросать

    def test_updates_fingerprint_key(self):
        from vless_installer.modules.user_fp_manager import _update_state_fp
        self._state.write_text(json.dumps({"uuid": "abc"}))
        with self._patch():
            _update_state_fp("firefox")
        st = json.loads(self._state.read_text())
        self.assertEqual(st["fingerprint"], "firefox")
        self.assertEqual(st["uuid"], "abc")

    def test_updates_chain_exit_fp(self):
        from vless_installer.modules.user_fp_manager import _update_state_fp
        self._state.write_text(json.dumps({"chain_exit_fp": "old"}))
        with self._patch():
            _update_state_fp("firefox")
        st = json.loads(self._state.read_text())
        self.assertEqual(st["chain_exit_fp"], "firefox")

    def test_updates_chain_nodes_fp(self):
        from vless_installer.modules.user_fp_manager import _update_state_fp
        self._state.write_text(json.dumps({
            "chain_nodes": [{"fp": "old"}, {"fp": "old2"}],
        }))
        with self._patch():
            _update_state_fp("firefox")
        st = json.loads(self._state.read_text())
        for node in st["chain_nodes"]:
            self.assertEqual(node["fp"], "firefox")


if __name__ == "__main__":
    unittest.main(verbosity=2)
