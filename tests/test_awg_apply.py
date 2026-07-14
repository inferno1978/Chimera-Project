#!/usr/bin/env python3
"""
tests/test_awg_apply.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/awg_apply.py.

Покрывает:
  1. awgs_apply_syncconf — syncconf через awg-quick strip + awg syncconf (mocked)
  2. awgs_apply_restart — systemctl restart (mocked)
  3. awgs_apply — диспетчер с fallback
  4. awgs_service_status — is-active / is-enabled (mocked)
  5. awgs_show_handshakes / awgs_show_dump — awg show (mocked)
"""
from __future__ import annotations

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


class TestApplySyncconf(unittest.TestCase):
    """awgs_apply_syncconf — бездаунтаймовое применение."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._conf = self._tmpdir / "awg0.conf"
        self._conf.write_text("[Interface]\nPrivateKey = x\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_false_when_no_server_conf(self):
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "AWGS_SERVER_CONF",
                          Path("/tmp/nonexistent_awg_xyz.conf")):
            result = awg_apply.awgs_apply_syncconf()
            self.assertFalse(result)

    def test_returns_true_on_success(self):
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "AWGS_SERVER_CONF", self._conf), \
             patch("chimera._core._run") as mock_run:
            # strip → ok, syncconf → ok
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="stripped config", stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),
            ]
            result = awg_apply.awgs_apply_syncconf()
            self.assertTrue(result)

    def test_returns_false_on_strip_failure(self):
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "AWGS_SERVER_CONF", self._conf), \
             patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="strip err")
            result = awg_apply.awgs_apply_syncconf()
            self.assertFalse(result)

    def test_returns_false_on_syncconf_failure(self):
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "AWGS_SERVER_CONF", self._conf), \
             patch("chimera._core._run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="stripped", stderr=""),
                MagicMock(returncode=1, stdout="", stderr="syncconf err"),
            ]
            result = awg_apply.awgs_apply_syncconf()
            self.assertFalse(result)


class TestApplyRestart(unittest.TestCase):
    """awgs_apply_restart — systemctl restart."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_true_on_success(self):
        from chimera.modules import awg_apply
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            self.assertTrue(awg_apply.awgs_apply_restart())

    def test_returns_false_on_failure(self):
        from chimera.modules import awg_apply
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="err")
            self.assertFalse(awg_apply.awgs_apply_restart())


class TestApplyDispatcher(unittest.TestCase):
    """awgs_apply — режимы."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_restart_mode_calls_restart(self):
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "awgs_apply_restart", return_value=True) as mock_r, \
             patch.object(awg_apply, "awgs_apply_syncconf") as mock_s:
            result = awg_apply.awgs_apply(mode="restart")
            self.assertTrue(result)
            mock_r.assert_called_once()
            mock_s.assert_not_called()

    def test_syncconf_success_no_fallback(self):
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "awgs_apply_syncconf", return_value=True) as mock_s, \
             patch.object(awg_apply, "awgs_apply_restart") as mock_r:
            result = awg_apply.awgs_apply(mode="syncconf")
            self.assertTrue(result)
            mock_s.assert_called_once()
            mock_r.assert_not_called()

    def test_syncconf_failure_triggers_fallback(self):
        """При syncconf-failure должен вызываться restart."""
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "awgs_apply_syncconf", return_value=False) as mock_s, \
             patch.object(awg_apply, "awgs_apply_restart", return_value=True) as mock_r:
            result = awg_apply.awgs_apply(mode="syncconf")
            self.assertTrue(result)
            mock_s.assert_called_once()
            mock_r.assert_called_once()


class TestServiceStatus(unittest.TestCase):
    """awgs_service_status."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_active_and_enabled(self):
        from chimera.modules import awg_apply
        with patch("chimera._core._run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="active\n", stderr=""),
                MagicMock(returncode=0, stdout="enabled\n", stderr=""),
            ]
            status = awg_apply.awgs_service_status()
            self.assertTrue(status["active"])
            self.assertTrue(status["enabled"])

    def test_inactive_and_disabled(self):
        from chimera.modules import awg_apply
        with patch("chimera._core._run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=3, stdout="inactive\n", stderr=""),
                MagicMock(returncode=1, stdout="disabled\n", stderr=""),
            ]
            status = awg_apply.awgs_service_status()
            self.assertFalse(status["active"])
            self.assertFalse(status["enabled"])


class TestShowHandshakes(unittest.TestCase):
    """awgs_show_handshakes."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_stdout_on_success(self):
        from chimera.modules import awg_apply
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="peer: abc\nlatest handshake: 1s ago\n", stderr=""
            )
            out = awg_apply.awgs_show_handshakes()
            self.assertIn("peer: abc", out)

    def test_returns_empty_on_failure(self):
        from chimera.modules import awg_apply
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="err")
            out = awg_apply.awgs_show_handshakes()
            self.assertEqual(out, "")


class TestShowDump(unittest.TestCase):
    """awgs_show_dump — машиночитаемый формат."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_lines_on_success(self):
        from chimera.modules import awg_apply
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="iface line\npeer line1\npeer line2\n",
                stderr="",
            )
            lines = awg_apply.awgs_show_dump()
            self.assertEqual(len(lines), 3)

    def test_returns_empty_list_on_failure(self):
        from chimera.modules import awg_apply
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="err")
            self.assertEqual(awg_apply.awgs_show_dump(), [])

    def test_filters_empty_lines(self):
        from chimera.modules import awg_apply
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="line1\n\n  \nline2\n",
                stderr="",
            )
            lines = awg_apply.awgs_show_dump()
            self.assertEqual(len(lines), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
