#!/usr/bin/env python3
"""
tests/test_fingerprint_manager.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/fingerprint_manager.py.

Покрывает:
  1. XRAY_FP_LIST — список fingerprint'ов (LIVE-валидация 26.10.29)
  2. DEFAULT_FP — дефолт
  3. _FP_MENU — структура меню
  4. resolve_client_fp / save_default_fingerprint (v4.31)
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("chimera._core")
    m.__dict__.update(g)
    sys.modules["chimera._core"] = m


class TestFingerprintManager(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_xray_fp_list_live_validated(self):
        from chimera.modules.fingerprint_manager import XRAY_FP_LIST
        # LIVE-валидация 31.10.2026, xray run -test, ядро 26.10.29:
        # 11 принятых имён; «none» отвергнут (латентный баг старого списка);
        # randomizednoalpn — принят, добавлен.
        self.assertEqual(len(XRAY_FP_LIST), 11)
        for name in ("chrome", "firefox", "safari", "ios", "android",
                     "edge", "360", "qq", "random", "randomized",
                     "randomizednoalpn"):
            self.assertIn(name, XRAY_FP_LIST)
        self.assertNotIn("none", XRAY_FP_LIST)  # ядро: unknown "fingerprint": none
        self.assertNotIn("golang", XRAY_FP_LIST)
        for banned in ("chrome_120", "ios_17_0", "firefox_133"):
            self.assertNotIn(banned, XRAY_FP_LIST)  # utls-версионные не принимаются
    def test_default_fp_is_chrome(self):
        from chimera.modules.fingerprint_manager import DEFAULT_FP
        self.assertEqual(DEFAULT_FP, "chrome")
    def test_fp_menu_keys_are_numeric(self):
        from chimera.modules.fingerprint_manager import _FP_MENU
        for key in _FP_MENU:
            self.assertTrue(key.isdigit())


class TestRealityFpGuard(unittest.TestCase):
    """v9 (2026-09-05): REALITY-guard для random/randomized."""

    def setUp(self): _setup_core()

    def test_reality_incompatible_set_subset_of_fp_list(self):
        from chimera.modules.fingerprint_manager import (
            XRAY_FP_LIST, REALITY_INCOMPATIBLE_FP,
        )
        self.assertTrue(REALITY_INCOMPATIBLE_FP.issubset(set(XRAY_FP_LIST)))
        self.assertIn("random", REALITY_INCOMPATIBLE_FP)
        self.assertIn("randomized", REALITY_INCOMPATIBLE_FP)
        self.assertIn("randomizednoalpn", REALITY_INCOMPATIBLE_FP)

    def test_warning_nonempty_for_randomizednoalpn(self):
        from chimera.modules.fingerprint_manager import reality_fp_warning
        self.assertTrue(reality_fp_warning("randomizednoalpn"))

    def test_warning_nonempty_for_random(self):
        from chimera.modules.fingerprint_manager import reality_fp_warning
        w = reality_fp_warning("random")
        self.assertTrue(w)
        self.assertIn("REALITY", w)
        self.assertIn("session_id", w)

    def test_warning_nonempty_for_randomized(self):
        from chimera.modules.fingerprint_manager import reality_fp_warning
        self.assertTrue(reality_fp_warning("randomized"))

    def test_warning_empty_for_fixed_browser_fps(self):
        from chimera.modules.fingerprint_manager import reality_fp_warning
        for fp in ("chrome", "firefox", "safari", "ios", "android",
                   "edge", "360", "qq"):
            self.assertEqual(reality_fp_warning(fp), "", msg=fp)

    def test_prompt_confirm_declined_returns_fixed_fp(self):
        """Выбор random + отказ от подтверждения → повторный выбор chrome."""
        from chimera.modules import fingerprint_manager as fm
        inputs = iter(["9", "n", "1"])   # random → нет → chrome
        with patch("builtins.input", lambda *a, **k: next(inputs)):
            got = fm.prompt_fingerprint(current="firefox")
        self.assertEqual(got, "chrome")

    def test_prompt_confirm_accepted_keeps_random(self):
        """Выбор random + явное подтверждение → возвращается random."""
        from chimera.modules import fingerprint_manager as fm
        inputs = iter(["9", "y"])        # random → да
        with patch("builtins.input", lambda *a, **k: next(inputs)):
            got = fm.prompt_fingerprint(current="firefox")
        self.assertEqual(got, "random")


class TestResolveClientFp(unittest.TestCase):
    """v4.31: эффективный FP для генераторов (override → state → chrome)."""

    def setUp(self): _setup_core()

    def test_state_fingerprint_used_by_default(self):
        from chimera.modules.fingerprint_manager import resolve_client_fp
        self.assertEqual(resolve_client_fp({"fingerprint": "firefox"}), "firefox")

    def test_override_wins(self):
        from chimera.modules.fingerprint_manager import resolve_client_fp
        self.assertEqual(
            resolve_client_fp({"fingerprint": "firefox"}, "safari"), "safari")

    def test_garbage_falls_back_to_state(self):
        from chimera.modules.fingerprint_manager import resolve_client_fp
        self.assertEqual(
            resolve_client_fp({"fingerprint": "firefox"}, "garbage"), "firefox")

    def test_garbage_state_falls_back_to_chrome(self):
        from chimera.modules.fingerprint_manager import resolve_client_fp
        self.assertEqual(resolve_client_fp({"fingerprint": "none"}), "chrome")
        self.assertEqual(resolve_client_fp({}), "chrome")

    def test_case_insensitive(self):
        from chimera.modules.fingerprint_manager import resolve_client_fp
        self.assertEqual(resolve_client_fp({}, "  FIREFOX "), "firefox")

    def test_save_default_fingerprint(self):
        from chimera.modules import fingerprint_manager as fm
        with tempfile.TemporaryDirectory() as td:
            with patch.object(fm, "STATE_FILE", Path(td) / "state.json"):
                self.assertTrue(fm.save_default_fingerprint("ios"))
                saved = json.loads((Path(td) / "state.json").read_text())
                self.assertEqual(saved["fingerprint"], "ios")
                # мусор не сохраняется
                self.assertFalse(fm.save_default_fingerprint("garbage"))

# ── config_backup ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
