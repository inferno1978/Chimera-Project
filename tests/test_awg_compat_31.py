#!/usr/bin/env python3
"""
tests/test_awg_compat_31.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты детекции поддержки AWG 3.1 (awg_compat.py) и диагностики версии
(awg_diagnose.py).

Покрывает:
  1. awg_is_31_directive_error — классификация stderr
  2. awgs_supports_awg31 — setconf-проба, safe-default True, кэш
  3. awg_apply: 3.1-ошибка → точный warn (НЕ self-heal по I2-I5)
  4. _diag_protocol_version — секция отчёта диагностики
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


class TestIs31DirectiveError(unittest.TestCase):
    def setUp(self):
        from chimera.modules import awg_compat
        self.awg_compat = awg_compat
        awg_compat._reset_supports_cache()

    def test_line_unrecognized_hpk(self):
        err = "Line unrecognized: `HeaderProtectionKey='"
        self.assertTrue(self.awg_compat.awg_is_31_directive_error(err))

    def test_line_unrecognized_random_trailers(self):
        err = "Configuration parsing error: RandomTrailers unknown"
        self.assertTrue(self.awg_compat.awg_is_31_directive_error(err))

    def test_line_unrecognized_disable_cookies(self):
        self.assertTrue(self.awg_compat.awg_is_31_directive_error(
            "Line unrecognized: `DisableCookies='"))

    def test_i2_error_not_31(self):
        # Ошибка про I2-I5 — НЕ 3.1 (self-heal по I2-I5 не должен
        # срабатывать на 3.1-директивы и наоборот)
        self.assertFalse(self.awg_compat.awg_is_31_directive_error(
            "Line unrecognized: `I2='"))

    def test_unrelated_error_not_31(self):
        self.assertFalse(self.awg_compat.awg_is_31_directive_error(
            "invalid private key"))
        self.assertFalse(self.awg_compat.awg_is_31_directive_error(""))
        self.assertFalse(self.awg_compat.awg_is_31_directive_error(None))


class TestSupportsAwg31(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import awg_compat
        self.awg_compat = awg_compat
        awg_compat._reset_supports_cache()

    def tearDown(self):
        self.awg_compat._reset_supports_cache()

    def test_success_true(self):
        with patch.object(self.awg_compat, "_run_setconf_check",
                          return_value=(True, "")):
            self.assertTrue(self.awg_compat.awgs_supports_awg31())

    def test_explicit_31_error_false(self):
        stderr = "Line unrecognized: `HeaderProtectionKey='"
        with patch.object(self.awg_compat, "_run_setconf_check",
                          return_value=(False, stderr)):
            self.assertFalse(self.awg_compat.awgs_supports_awg31())

    def test_unrelated_error_safe_default_true(self):
        # Ошибка не про 3.1 → True (даём установке шанс)
        with patch.object(self.awg_compat, "_run_setconf_check",
                          return_value=(False, "no cap_net_admin")):
            self.assertTrue(self.awg_compat.awgs_supports_awg31())

    def test_cache(self):
        calls = []

        def fake_check(conf):
            calls.append(conf)
            return (True, "")

        with patch.object(self.awg_compat, "_run_setconf_check",
                          side_effect=fake_check):
            self.awg_compat.awgs_supports_awg31()
            self.awg_compat.awgs_supports_awg31()
            self.assertEqual(len(calls), 1)  # кэш на процесс
            self.awg_compat.awgs_supports_awg31(force_refresh=True)
            self.assertEqual(len(calls), 2)

    def test_reset_clears_cache(self):
        with patch.object(self.awg_compat, "_run_setconf_check",
                          return_value=(True, "")):
            self.awg_compat.awgs_supports_awg31()
        self.awg_compat._reset_supports_cache()
        self.assertNotIn("result", self.awg_compat._SUPPORTS_AWG31_CACHE)

    def test_sample_conf_contains_31_directives(self):
        captured = {}

        def fake_check(conf):
            captured["conf"] = conf
            return (True, "")

        with patch.object(self.awg_compat, "_run_setconf_check",
                          side_effect=fake_check):
            self.awg_compat.awgs_supports_awg31()
        conf = captured["conf"]
        for d in ("HeaderProtectionKey", "ContentPaddingAddition",
                  "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
                  "KeepaliveTimeout", "MaxHandshakeAttempts",
                  "RandomTrailers = on", "DisableCookies = on"):
            self.assertIn(d, conf, msg=d)
        # Stripped-формат: без awg-quick директив (Address/DNS/MTU/Table)
        self.assertNotIn("Address", conf)
        self.assertNotIn("MTU", conf)
        self.assertNotIn("Table", conf)


class TestApply31ErrorHandling(unittest.TestCase):
    """awgs_apply: 3.1-ошибка → точный warn, НЕ I2-I5 self-heal."""

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import awg_apply, awg_compat
        self.awg_apply = awg_apply
        self.awg_compat = awg_compat
        awg_compat._reset_supports_cache()
        awg_apply._SELF_HEAL_IN_PROGRESS = False

    def tearDown(self):
        self.awg_compat._reset_supports_cache()
        self.awg_apply._SELF_HEAL_IN_PROGRESS = False

    def test_31_error_returns_false_with_hint(self):
        # syncconf fail + stderr = 3.1-директива → False + warn про 3.1
        from chimera.modules.awg_constants import AWGS_APPLY_MODE_SYNCCONF
        core = MagicMock()
        core.warn = MagicMock()
        with patch.object(self.awg_apply, "_core_module", return_value=core), \
             patch.object(self.awg_apply, "awgs_apply_syncconf",
                          return_value=False), \
             patch.object(self.awg_apply, "_extract_apply_failure_stderr",
                          return_value="Line unrecognized: `HeaderProtectionKey='"), \
             patch.object(self.awg_apply, "awgs_apply_restart") as mock_restart:
            ok = self.awg_apply.awgs_apply(mode=AWGS_APPLY_MODE_SYNCCONF)
            self.assertFalse(ok)
            # restart НЕ вызывался (3.1-ошибка не лечится рестартом)
            mock_restart.assert_not_called()
            # warn содержит подсказку обновления
            warned = " ".join(str(c) for c in core.warn.call_args_list)
            self.assertIn("3.1", warned)
            self.assertIn("amneziawg-tools", warned)

    def test_i2_error_still_selfheals(self):
        # РЕГРЕССИЯ: I2-I5-ошибка по-прежнему уходит в self-heal
        from chimera.modules.awg_constants import AWGS_APPLY_MODE_SYNCCONF
        core = MagicMock()
        with patch.object(self.awg_apply, "_core_module", return_value=core), \
             patch.object(self.awg_apply, "awgs_apply_syncconf",
                          return_value=False), \
             patch.object(self.awg_apply, "_extract_apply_failure_stderr",
                          return_value="Line unrecognized: `I2='"), \
             patch.object(self.awg_apply, "_self_heal_i2_i5_incompatibility",
                          return_value=True) as mock_heal:
            ok = self.awg_apply.awgs_apply(mode=AWGS_APPLY_MODE_SYNCCONF)
            self.assertTrue(ok)
            mock_heal.assert_called_once()


class TestDiagnoseProtocolVersion(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _diagnose(self, state):
        self._state_file.write_text(json.dumps(state))
        from chimera.modules import awg_diagnose, awg_state
        from chimera.modules.awg_constants import AWGS_SERVER_CONF
        conf_path = self._tmpdir / "awg0.conf"
        with patch.object(awg_state, "AWGS_STATE_FILE", self._state_file), \
             patch.object(awg_diagnose, "awgs_state_load",
                          return_value=state), \
             patch("chimera.modules.awg_constants.AWGS_SERVER_CONF",
                   conf_path):
            return awg_diagnose._diag_protocol_version(), conf_path

    def test_20_state(self):
        result, _ = self._diagnose({"installed": True})
        self.assertEqual(result["version"], "2.0")
        # Для 2.0 — только одна проверка (версия), без 3.1-проверок
        self.assertEqual(len(result["checks"]), 1)

    def test_31_with_conf_directives(self):
        conf = ("[Interface]\nPrivateKey = x\n"
                "HeaderProtectionKey = K\nContentPaddingAddition = 12-40\n"
                "RekeyAfterTime = 100-140\nRekeyTimeout = 3-6\n"
                "RejectAfterTime = 170-250\nKeepaliveTimeout = 8-14\n"
                "MaxHandshakeAttempts = 15-35\nRandomTrailers = on\n"
                "DisableCookies = on\n")
        result, conf_path = self._diagnose(
            {"installed": True, "protocol_version": "3.1",
             "params": {"s1": 15, "s2": 20, "s3": 12, "s4": 12,
                        "i1": "<r 32>"}})
        conf_path.write_text(conf)
        from chimera.modules import awg_diagnose, awg_state
        from chimera.modules.awg_constants import AWGS_SERVER_CONF
        with patch.object(awg_state, "AWGS_STATE_FILE", self._state_file), \
             patch.object(awg_diagnose, "awgs_state_load",
                          return_value={"installed": True,
                                        "protocol_version": "3.1",
                                        "params": {"s1": 15, "s2": 20,
                                                   "s3": 12, "s4": 12,
                                                   "i1": "<r 32>"}}), \
             patch("chimera.modules.awg_constants.AWGS_SERVER_CONF",
                   conf_path), \
             patch("chimera.modules.awg_compat.awgs_supports_awg31",
                   return_value=True):
            result = awg_diagnose._diag_protocol_version()
        self.assertEqual(result["version"], "3.1")
        # Нет FAIL-проверок (конфиг полный, инструменты ok, параметры ok)
        fails = [c for c in result["checks"] if c[0] == "FAIL"]
        warns = [c for c in result["checks"] if c[0] == "WARN"]
        self.assertEqual(fails, [], msg=fails)
        self.assertEqual(warns, [], msg=warns)

    def test_31_missing_directives_fail(self):
        # awg0.conf БЕЗ 3.1-директив при 3.1-state → FAIL-проверка
        conf_path = self._tmpdir / "awg0.conf"
        conf_path.write_text("[Interface]\nPrivateKey = x\n")  # без 3.1
        state = {"installed": True, "protocol_version": "3.1",
                 "params": {"s1": 15, "s2": 20, "s3": 12, "s4": 12,
                            "i1": "<r 32>"}}
        from chimera.modules import awg_diagnose
        with patch.object(awg_diagnose, "awgs_state_load",
                          return_value=state), \
             patch("chimera.modules.awg_constants.AWGS_SERVER_CONF",
                   conf_path), \
             patch("chimera.modules.awg_compat.awgs_supports_awg31",
                   return_value=True):
            result = awg_diagnose._diag_protocol_version()
        fails = [c for c in result["checks"] if c[0] == "FAIL"]
        self.assertTrue(fails, msg=result["checks"])
        self.assertTrue(any("HeaderProtectionKey" in msg
                            for _, msg in fails))

    def test_diagnose_full_contains_protocol(self):
        # awgs_diagnose_full включает секцию protocol
        self._state_file.write_text(json.dumps({"installed": True}))
        from chimera.modules import awg_diagnose, awg_state
        with patch.object(awg_state, "AWGS_STATE_FILE", self._state_file), \
             patch.object(awg_diagnose, "awgs_state_load",
                          return_value={"installed": True,
                                        "protocol_version": "3.1",
                                        "params": {}}), \
             patch.object(awg_diagnose, "_diag_kernel_module",
                          return_value={"ok": True, "module": "amnezia",
                                        "version": "1.0"}), \
             patch.object(awg_diagnose, "_diag_sysctl", return_value=[]), \
             patch.object(awg_diagnose, "_diag_ufw",
                          return_value={"status": "SKIP", "ok": True,
                                        "msg": "skip"}), \
             patch.object(awg_diagnose, "_diag_service",
                          return_value={"ok": True, "active": True,
                                        "enabled": True}), \
             patch.object(awg_diagnose, "_diag_nat_routing",
                          return_value={"ok": True, "checks": []}), \
             patch.object(awg_diagnose, "_diag_tunnel",
                          return_value={"ok": True, "peers": 0}):
            report = awg_diagnose.awgs_diagnose_full()
        self.assertIn("protocol", report)
        self.assertEqual(report["protocol"]["version"], "3.1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
