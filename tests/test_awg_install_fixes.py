#!/usr/bin/env python3
"""
tests/test_awg_install_fixes.py
───────────────────────────────────────────────────────────────────────────────
Юнит-тесты фиксов (E2E fi1 2026-10-03):

  1. awgs_install: честный контракт — при провале awgs_setup_systemd
     установка возвращает False (раньше «успех» при мёртвом awg0).
  2. _awgs_apt_lock_heal: висячий apt.systemd.daily (или apt-get старше
     30 мин) завершается TERM→KILL; свежий/чужой процесс не трогается.
  3. _awgs_install_userspace_unit: юнит awg-quick@.service создаётся
     только при его отсутствии; при наличии пакетного — не перекрывает.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from tests.test_awg_standalone_31 import (  # noqa: E402
    _setup_core_in_sysmodules, _mock_core, _PARAMS_31,
)


class TestInstallHonestContract(unittest.TestCase):
    """FIX-A: setup_systemd=False → awgs_install=False."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_install_fails_when_systemd_fails(self):
        from chimera.modules import awg_standalone
        mock_core = _mock_core()
        with patch.object(Path, "mkdir", lambda self, *a, **kw: None), \
             patch.object(Path, "touch", lambda self, *a, **kw: None), \
             patch.object(awg_standalone, "_core_module",
                          return_value=mock_core), \
             patch.object(awg_standalone, "awgs_check_conflicts",
                          return_value=[]), \
             patch.object(awg_standalone, "awgs_install_dkms",
                          return_value=True), \
             patch.object(awg_standalone, "awgs_hw_tune_all",
                          return_value={}), \
             patch.object(awg_standalone, "awgs_generate_keys",
                          return_value=("PRIV", "PUB")), \
             patch.object(awg_standalone, "awgs_build_server_conf",
                          return_value="[Interface]\n"), \
             patch.object(awg_standalone, "awgs_write_server_conf",
                          return_value=True), \
             patch.object(awg_standalone, "awgs_setup_firewall",
                          return_value=True), \
             patch.object(awg_standalone, "awgs_setup_systemd",
                          return_value=False), \
             patch.object(awg_standalone, "awgs_setup_nat_and_routing",
                          return_value=True) as mock_nat, \
             patch.object(awg_standalone, "awgs_state_init"), \
             patch.object(awg_standalone, "awgs_setup_expires_cron",
                          return_value=True), \
             patch.object(awg_standalone, "awgs_presets_generate") as mock_gen:
            mock_gen.return_value = dict(_PARAMS_31)
            ok = awg_standalone.awgs_install(protocol_version="3.1")
            self.assertFalse(ok)
            # NAT/state НЕ настраиваем — установка честно прервана
            mock_nat.assert_not_called()


class TestAptLockHeal(unittest.TestCase):
    """FIX-B: лечение висячих apt-локов."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _run_result(self, stdout="", returncode=0, stderr=""):
        r = MagicMock()
        r.stdout = stdout
        r.stderr = stderr
        r.returncode = returncode
        return r

    def test_kills_stale_apt_systemd_daily(self):
        from chimera.modules import awg_standalone
        core = _mock_core()

        def fake_run(cmd, **kw):
            s = cmd if isinstance(cmd, str) else " ".join(map(str, cmd))
            if "fuser" in s:
                return self._run_result("178583: ")
            if "etimes" in s:
                return self._run_result("172800")  # 2 дня
            return self._run_result("")

        core._run = fake_run

        with patch.object(awg_standalone, "_core_module",
                          return_value=core), \
             patch("builtins.open",
                   create=True,
                   side_effect=lambda p, *a, **kw:
                       MagicMock(
                           __enter__=lambda s: MagicMock(
                               read=lambda: b"/bin/sh /usr/lib/apt/apt.systemd.daily update\x00"
                           ),
                           __exit__=lambda s, *a: False)), \
             patch.object(Path, "exists", return_value=False):
            killed = awg_standalone._awgs_apt_lock_heal()
        self.assertTrue(killed)

    def test_ignores_fresh_aptget(self):
        from chimera.modules import awg_standalone
        core = _mock_core()

        def fake_run(cmd, **kw):
            s = cmd if isinstance(cmd, str) else " ".join(map(str, cmd))
            if "fuser" in s:
                return self._run_result("12345: ")
            if "etimes" in s:
                return self._run_result("30")  # 30 секунд — свежий
            return self._run_result("")

        core._run = fake_run

        with patch.object(awg_standalone, "_core_module",
                          return_value=core), \
             patch("builtins.open",
                   create=True,
                   side_effect=lambda p, *a, **kw:
                       MagicMock(
                           __enter__=lambda s: MagicMock(
                               read=lambda: b"apt-get\x00install\x00vim\x00"
                           ),
                           __exit__=lambda s, *a: False)):
            killed = awg_standalone._awgs_apt_lock_heal()
        self.assertFalse(killed)

    def test_no_lock_holders(self):
        from chimera.modules import awg_standalone
        core = _mock_core()

        def fake_run(cmd, **kw):
            return self._run_result("")

        core._run = fake_run

        with patch.object(awg_standalone, "_core_module",
                          return_value=core):
            killed = awg_standalone._awgs_apt_lock_heal()
        self.assertFalse(killed)


class TestUserspaceUnit(unittest.TestCase):
    """FIX-C: userspace-юнит awg-quick@.service."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_creates_unit_when_absent(self):
        from chimera.modules import awg_standalone
        core = _mock_core()
        written = {}

        def fake_write(self, data):
            written[str(self)] = data
            return len(data)

        with patch.object(awg_standalone, "_core_module",
                          return_value=core), \
             patch.object(Path, "exists", return_value=False), \
             patch.object(Path, "write_text", fake_write):
            ok = awg_standalone._awgs_install_userspace_unit()
        self.assertTrue(ok)
        body = next(iter(written.values()))
        self.assertIn("amneziawg-go", body)
        self.assertIn("ExecStart=/usr/local/bin/awg-quick up %i", body)
        self.assertIn("RemainAfterExit=yes", body)

    def test_respects_existing_package_unit(self):
        from chimera.modules import awg_standalone
        core = _mock_core()
        with patch.object(awg_standalone, "_core_module",
                          return_value=core), \
             patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "write_text") as mock_write:
            ok = awg_standalone._awgs_install_userspace_unit()
        self.assertTrue(ok)
        mock_write.assert_not_called()

    def test_fallback_installs_unit(self):
        from chimera.modules import awg_standalone
        core = _mock_core()
        import chimera.modules.awg_transport as awg_transport
        with patch.object(awg_standalone, "_core_module",
                          return_value=core), \
             patch.object(awg_standalone, "_awgs_install_userspace_unit",
                          return_value=True) as mock_unit, \
             patch.object(awg_transport, "_awg_install_go_version",
                          return_value=True):
            ok = awg_standalone._awgs_install_dkms_fallback()
        self.assertTrue(ok)
        mock_unit.assert_called_once()




class TestShadowingStubs(unittest.TestCase):
    """FIX-D: userspace-стабы затемняют пакетный awg/awg-quick."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _paths(self, tmp, stubs=True, pkg=True, etc_unit=True, lib_unit=True):
        base = Path(tmp)
        for name in ("stub_awg", "pkg_awg", "stub_quick", "pkg_quick",
                     "etc_unit", "lib_unit"):
            f = base / name
            f.write_text("x")
        if not stubs:
            (base / "stub_awg").unlink()
            (base / "stub_quick").unlink()
        if not pkg:
            (base / "pkg_awg").unlink()
            (base / "pkg_quick").unlink()
        if not etc_unit:
            (base / "etc_unit").unlink()
        if not lib_unit:
            (base / "lib_unit").unlink()
        return {
            "stub_awg": str(base / "stub_awg"),
            "pkg_awg": str(base / "pkg_awg"),
            "stub_quick": str(base / "stub_quick"),
            "pkg_quick": str(base / "pkg_quick"),
            "etc_unit": str(base / "etc_unit"),
            "lib_unit": str(base / "lib_unit"),
            "usr_unit": str(base / "nonexistent"),
        }

    def test_stubs_removed_when_package_exists(self):
        import tempfile
        from chimera.modules import awg_standalone
        core = _mock_core()
        with tempfile.TemporaryDirectory() as tmp:
            P = self._paths(tmp)
            with patch.object(awg_standalone, "_core_module",
                              return_value=core):
                awg_standalone._awgs_remove_shadowing_stubs(P)
            self.assertFalse(Path(P["stub_awg"]).exists())
            self.assertFalse(Path(P["stub_quick"]).exists())
            self.assertFalse(Path(P["etc_unit"]).exists())
            self.assertTrue(Path(P["pkg_awg"]).exists())

    def test_stubs_kept_without_package(self):
        import tempfile
        from chimera.modules import awg_standalone
        core = _mock_core()
        with tempfile.TemporaryDirectory() as tmp:
            P = self._paths(tmp, pkg=False)
            with patch.object(awg_standalone, "_core_module",
                              return_value=core):
                awg_standalone._awgs_remove_shadowing_stubs(P)
            # userspace-режим без пакетов: стабы НЕ тронуты
            self.assertTrue(Path(P["stub_awg"]).exists())
            self.assertTrue(Path(P["stub_quick"]).exists())

    def test_etc_unit_kept_without_package_unit(self):
        import tempfile
        from chimera.modules import awg_standalone
        core = _mock_core()
        with tempfile.TemporaryDirectory() as tmp:
            P = self._paths(tmp, lib_unit=False)
            with patch.object(awg_standalone, "_core_module",
                              return_value=core):
                awg_standalone._awgs_remove_shadowing_stubs(P)
            # нет пакетного юнита → /etc-юнит не удаляем
            self.assertTrue(Path(P["etc_unit"]).exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
