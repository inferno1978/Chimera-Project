#!/usr/bin/env python3
"""
tests/test_user_fp_manager.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/user_fp_manager.py.

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


class TestPatchTgBotScript(unittest.TestCase):
    """patch_tg_bot_script — pure string replacement с идемпотентностью."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_input_returns_empty(self):
        from chimera.modules.user_fp_manager import patch_tg_bot_script
        result = patch_tg_bot_script("")
        # пустой ввод — ничего не вставляется
        self.assertEqual(result, "")

    def test_inserts_fp_commands_before_handle_start(self):
        from chimera.modules.user_fp_manager import (
            patch_tg_bot_script, TG_FP_COMMANDS_BLOCK,
        )
        script = "def handle_start(msg, args):\n    pass\n"
        result = patch_tg_bot_script(script)
        self.assertIn("handle_fp", result)
        self.assertIn(TG_FP_COMMANDS_BLOCK, result)

    def test_idempotent_on_repeated_call(self):
        """Повторный вызов не дублирует вставки."""
        from chimera.modules.user_fp_manager import patch_tg_bot_script
        script = (
            "def handle_start(msg, args):\n    pass\n"
            "elif cmd == \"/help\":   handle_help(msg)\n"
        )
        once = patch_tg_bot_script(script)
        twice = patch_tg_bot_script(once)
        # количество вхождений handle_fp должно быть одинаковым
        self.assertEqual(once.count("handle_fp"), twice.count("handle_fp"))

    def test_adds_fp_dispatcher_to_help_handler(self):
        from chimera.modules.user_fp_manager import patch_tg_bot_script
        script = 'elif cmd == "/help":   handle_help(msg)\n'
        result = patch_tg_bot_script(script)
        # должна добавиться диспетчеризация /fp
        self.assertIn("/fp", result)

    def test_no_anchors_no_changes(self):
        """Без якорей — возвращается исходный текст (возможно с пустыми вставками)."""
        from chimera.modules.user_fp_manager import patch_tg_bot_script
        script = "print('hello')\n"
        result = patch_tg_bot_script(script)
        # ничего не вставилось, потому что нет якорей
        self.assertNotIn("handle_fp", result)


class TestApplyFpRealityGuard(unittest.TestCase):
    """v9 (2026-09-05): apply_fp отклоняет random/randomized (REALITY)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_random_rejected_with_reality_explanation(self):
        from chimera.modules import user_fp_manager as ufm
        with patch.object(ufm, "_patch_config_fp") as mock_patch:
            ok, msg = ufm.apply_fp("random")
        self.assertFalse(ok)
        self.assertIn("REALITY", msg)
        self.assertIn("session_id", msg)
        # гард срабатывает ДО каких-либо файловых операций
        mock_patch.assert_not_called()

    def test_randomized_rejected(self):
        from chimera.modules import user_fp_manager as ufm
        with patch.object(ufm, "_patch_config_fp") as mock_patch:
            ok, msg = ufm.apply_fp("randomized")
        self.assertFalse(ok)
        mock_patch.assert_not_called()

    def test_tg_bot_block_contains_guard(self):
        """TG-бот (/setfp) тоже отклоняет random/randomized."""
        from chimera.modules.user_fp_manager import TG_FP_COMMANDS_BLOCK
        self.assertIn('new_fp in ("random", "randomized")', TG_FP_COMMANDS_BLOCK)
        self.assertIn("несовместим с REALITY", TG_FP_COMMANDS_BLOCK)


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
            patch("chimera.modules.user_fp_manager._STATE_FILE", self._state),
            patch("chimera.modules.user_fp_manager._CONFIG_DIRS", [self._cfg_dir]),
        )

    def test_returns_chrome_when_nothing_found(self):
        from chimera.modules.user_fp_manager import current_fp
        with self._patch()[0], self._patch()[1]:
            self.assertEqual(current_fp(), "chrome")

    def test_returns_fp_from_state(self):
        from chimera.modules.user_fp_manager import current_fp
        self._state.write_text(json.dumps({"fingerprint": "firefox"}))
        with self._patch()[0], self._patch()[1]:
            self.assertEqual(current_fp(), "firefox")

    def test_returns_fp_from_config_reality(self):
        from chimera.modules.user_fp_manager import current_fp
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
        from chimera.modules.user_fp_manager import current_fp
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
        return patch("chimera.modules.user_fp_manager._CONFIG_DIRS",
                     [self._cfg_dir])

    def test_returns_false_when_no_config(self):
        from chimera.modules.user_fp_manager import _patch_config_fp
        with self._patch():
            changed, err = _patch_config_fp("firefox")
        self.assertFalse(changed)

    def test_replaces_reality_fingerprint(self):
        from chimera.modules.user_fp_manager import _patch_config_fp
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
        from chimera.modules.user_fp_manager import _patch_config_fp
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
        return patch("chimera.modules.user_fp_manager._STATE_FILE",
                     self._state)

    def test_does_not_raise_when_no_state(self):
        from chimera.modules.user_fp_manager import _update_state_fp
        with self._patch():
            _update_state_fp("firefox")  # не должно бросать

    def test_updates_fingerprint_key(self):
        from chimera.modules.user_fp_manager import _update_state_fp
        self._state.write_text(json.dumps({"uuid": "abc"}))
        with self._patch():
            _update_state_fp("firefox")
        st = json.loads(self._state.read_text())
        self.assertEqual(st["fingerprint"], "firefox")
        self.assertEqual(st["uuid"], "abc")

    def test_updates_chain_exit_fp(self):
        from chimera.modules.user_fp_manager import _update_state_fp
        self._state.write_text(json.dumps({"chain_exit_fp": "old"}))
        with self._patch():
            _update_state_fp("firefox")
        st = json.loads(self._state.read_text())
        self.assertEqual(st["chain_exit_fp"], "firefox")

    def test_updates_chain_nodes_fp(self):
        from chimera.modules.user_fp_manager import _update_state_fp
        self._state.write_text(json.dumps({
            "chain_nodes": [{"fp": "old"}, {"fp": "old2"}],
        }))
        with self._patch():
            _update_state_fp("firefox")
        st = json.loads(self._state.read_text())
        for node in st["chain_nodes"]:
            self.assertEqual(node["fp"], "firefox")


class TestApplyFpGlobalSync(unittest.TestCase):
    """(2026-09-10) apply_fp синхронизирует in-memory глобал
    _core.PARAM_FINGERPRINT — иначе ссылки в ТОЙ ЖЕ сессии меню
    генерировались бы со старым FP (_fp_from_state смотрит глобал
    первым; chain_nodes/pq_vless читают его getattr-ом)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _core(self):
        import sys
        return sys.modules["chimera._core"]

    def test_success_syncs_global(self):
        from chimera.modules import user_fp_manager as ufm
        core = self._core()
        core.PARAM_FINGERPRINT = "firefox"
        with patch.object(ufm, "_patch_config_fp", return_value=(True, "")), \
             patch.object(ufm, "_validate_and_restart", return_value=(True, "")), \
             patch.object(ufm, "_update_state_fp") as mock_state:
            ok, msg = ufm.apply_fp("safari")
        self.assertTrue(ok, msg)
        # глобал обновлён в той же сессии
        self.assertEqual(core.PARAM_FINGERPRINT, "safari")
        mock_state.assert_called_once_with("safari")

    def test_failed_restart_no_global_sync(self):
        """Xray не принял конфиг → глобал НЕ трогаем (откат по смыслу)."""
        from chimera.modules import user_fp_manager as ufm
        core = self._core()
        core.PARAM_FINGERPRINT = "firefox"
        with patch.object(ufm, "_patch_config_fp", return_value=(True, "")), \
             patch.object(ufm, "_validate_and_restart",
                          return_value=(False, "xray dead")):
            ok, msg = ufm.apply_fp("safari")
        self.assertFalse(ok)
        self.assertEqual(core.PARAM_FINGERPRINT, "firefox")

    def test_sync_core_global_fp_direct(self):
        from chimera.modules import user_fp_manager as ufm
        core = self._core()
        core.PARAM_FINGERPRINT = "firefox"
        self.assertTrue(ufm._sync_core_global_fp("edge"))
        self.assertEqual(core.PARAM_FINGERPRINT, "edge")


class TestShowRegeneratedLinks(unittest.TestCase):
    """_show_regenerated_links — показ перегенерированных ссылок после
    смены FP: только активные пользователи, без disabled и ios-shadow."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_shows_only_active_users(self):
        import sys
        from chimera.modules import user_fp_manager as ufm
        core = sys.modules["chimera._core"]
        users = [
            {"uuid": "u1", "name": "Alice", "email": "a@x"},
            {"uuid": "u2", "name": "Bob", "email": "b@x", "disabled": True},
            {"uuid": "u3", "name": "shadow", "email": "s@x",
             "is_ios_shadow": True},
            {"name": "no-uuid"},
        ]
        shown = []
        with patch("chimera.modules.users_manager._unified_load_users",
                   return_value=users), \
             patch("chimera.modules.users_manager._unified_show_links",
                   side_effect=lambda u, print_output=True:
                       shown.append((u["uuid"], print_output))):
            ufm._show_regenerated_links()
        self.assertEqual(shown, [("u1", True)])

    def test_no_users_no_calls_no_raise(self):
        from chimera.modules import user_fp_manager as ufm
        with patch("chimera.modules.users_manager._unified_load_users",
                   return_value=[]), \
             patch("chimera.modules.users_manager._unified_show_links") as m:
            ufm._show_regenerated_links()  # не бросает
        m.assert_not_called()

    def test_show_links_error_does_not_raise(self):
        """Сбой показа одного юзера не должен валить весь показ."""
        from chimera.modules import user_fp_manager as ufm
        users = [{"uuid": "u1"}, {"uuid": "u2"}]
        calls = []

        def _boom(u, print_output=True):
            calls.append(u["uuid"])
            if u["uuid"] == "u1":
                raise RuntimeError("QR renderer died")

        with patch("chimera.modules.users_manager._unified_load_users",
                   return_value=users), \
             patch("chimera.modules.users_manager._unified_show_links",
                   side_effect=_boom):
            ufm._show_regenerated_links()  # не бросает
        self.assertEqual(calls, ["u1", "u2"])


class TestFingerprintMenuWiring(unittest.TestCase):
    """Статические проверки _core.py — пункт F активен в
    do_unified_user_manager и вызывает do_change_fp_interactive;
    старое меню Ротации Fingerprint получило тот же REALITY-гард и
    синхронизацию глобала (единая семантика с user_fp_manager)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _extract_block(self, func_name):
        import re
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        m = re.search(
            rf'def {func_name}\(\).*?(?=\ndef [a-z_])',
            src, re.DOTALL
        )
        self.assertIsNotNone(m, f"{func_name} не найдена в _core.py")
        return m.group(0)

    def test_f_item_active_in_unified_menu(self):
        block = self._extract_block("do_unified_user_manager")
        found = any(
            line.strip().startswith('_box_item("F"')
            for line in block.split("\n")
        )
        self.assertTrue(
            found,
            "Пункт F должен быть активен в do_unified_user_manager "
            "(Смена TLS Fingerprint → перегенация ссылок)")

    def test_f_handler_calls_interactive(self):
        block = self._extract_block("do_unified_user_manager")
        self.assertIn('elif ch == "f":', block)
        self.assertIn("do_change_fp_interactive", block)

    def test_fp_rotate_menu_syncs_global(self):
        """do_manage_fingerprint: global PARAM_FINGERPRINT + присваивание
        после успешной смены — ссылки в той же сессии видят новый FP."""
        block = self._extract_block("do_manage_fingerprint")
        self.assertIn("global PARAM_FINGERPRINT", block)
        self.assertIn("PARAM_FINGERPRINT = new_fp", block)

    def test_fp_rotate_menu_randomized_guard(self):
        """do_manage_fingerprint: randomized (REALITY-несовместимый)
        отклоняется — тот же гард, что в apply_fp/TG-боте."""
        block = self._extract_block("do_manage_fingerprint")
        self.assertIn('new_fp == "randomized"', block)
        self.assertIn("reality_fp_warning", block)


if __name__ == "__main__":
    unittest.main(verbosity=2)
