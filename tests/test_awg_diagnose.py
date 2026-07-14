#!/usr/bin/env python3
"""
tests/test_awg_diagnose.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/awg_diagnose.py.

Покрывает:
  1. _diag_kernel_module — lsmod + awg --version (mocked)
  2. _diag_sysctl — проверка sysctl-целей (mocked)
  3. _diag_ufw — проверка UFW-правила
  4. _diag_service — статус сервиса
  5. _diag_tunnel — awg show
  6. _diag_nat_routing — NAT/MASQUERADE/FORWARD
  7. _diag_carrier_compare — сравнение с профилем
  8. awgs_diagnose_full — полный отчёт
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


class TestDiagKernelModule(unittest.TestCase):
    """_diag_kernel_module — DKMS amnezia."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ok_when_module_loaded(self):
        from chimera.modules import awg_diagnose
        with patch("chimera._core._run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="amnezia 1234567\n", stderr=""),
                MagicMock(returncode=0, stdout="amnezia-wg-tools v1.0\n", stderr=""),
            ]
            r = awg_diagnose._diag_kernel_module()
            self.assertTrue(r["ok"])
            self.assertEqual(r["status"], "OK")
            self.assertEqual(r["module"], "amnezia")
            self.assertIn("v1.0", r["version"])

    def test_fail_when_module_not_loaded(self):
        from chimera.modules import awg_diagnose
        with patch("chimera._core._run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="", stderr=""),
                MagicMock(returncode=1, stdout="", stderr="not found"),
            ]
            r = awg_diagnose._diag_kernel_module()
            self.assertFalse(r["ok"])
            self.assertEqual(r["status"], "FAIL")


class TestDiagSysctl(unittest.TestCase):
    """_diag_sysctl."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_all_ok_when_values_match(self):
        from chimera.modules import awg_diagnose
        from chimera.modules.awg_constants import AWGS_SYSCTL_TARGETS
        with patch.object(awg_diagnose, "awgs_sysctl_get") as mock_get, \
             patch("chimera._core._run") as mock_run:
            # IPv6 disable check → return "0" (IPv6 enabled)
            mock_run.return_value = MagicMock(returncode=0, stdout="0\n", stderr="")
            # все sysctl-параметры возвращают target-значение
            mock_get.side_effect = lambda key: str(AWGS_SYSCTL_TARGETS.get(key, ""))
            results = awg_diagnose._diag_sysctl()
            self.assertGreater(len(results), 0)
            for r in results:
                self.assertIn(r["status"], ("OK", "SKIP"))

    def test_warn_when_value_mismatch(self):
        from chimera.modules import awg_diagnose
        with patch.object(awg_diagnose, "awgs_sysctl_get") as mock_get, \
             patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="0\n", stderr="")
            mock_get.return_value = "wrong_value"
            results = awg_diagnose._diag_sysctl()
            self.assertGreater(len(results), 0)
            self.assertTrue(any(r["status"] == "WARN" for r in results))

    def test_skip_ipv6_forwarding_when_ipv6_disabled(self):
        """IPv6 forwarding — SKIP если disable_ipv6=1."""
        from chimera.modules import awg_diagnose
        with patch.object(awg_diagnose, "awgs_sysctl_get") as mock_get, \
             patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="1\n", stderr="")
            mock_get.return_value = "1"  # для остальных
            results = awg_diagnose._diag_sysctl()
            ipv6_entries = [r for r in results if "ipv6" in r["key"]]
            self.assertTrue(all(r["status"] == "SKIP" for r in ipv6_entries))


class TestDiagUfw(unittest.TestCase):
    """_diag_ufw."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_skip_when_ufw_inactive(self):
        from chimera.modules import awg_diagnose
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="Status: inactive\n", stderr=""
            )
            r = awg_diagnose._diag_ufw(51820)
            self.assertEqual(r["status"], "SKIP")
            self.assertTrue(r["ok"])

    def test_ok_when_rule_present(self):
        from chimera.modules import awg_diagnose
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="51820/udp ALLOW Anywhere\n",
                stderr="",
            )
            r = awg_diagnose._diag_ufw(51820)
            self.assertTrue(r["ok"])
            self.assertEqual(r["status"], "OK")

    def test_warn_when_rule_missing(self):
        from chimera.modules import awg_diagnose
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="22/tcp ALLOW Anywhere\n", stderr=""
            )
            r = awg_diagnose._diag_ufw(51820)
            self.assertFalse(r["ok"])
            self.assertEqual(r["status"], "WARN")


class TestDiagService(unittest.TestCase):
    """_diag_service — статус awg-quick@awg0."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ok_when_active(self):
        from chimera.modules import awg_diagnose
        with patch.object(awg_diagnose, "awgs_service_status") as mock_status:
            mock_status.return_value = {"active": True, "enabled": True}
            r = awg_diagnose._diag_service()
            self.assertTrue(r["ok"])
            self.assertEqual(r["status"], "OK")

    def test_fail_when_inactive(self):
        from chimera.modules import awg_diagnose
        with patch.object(awg_diagnose, "awgs_service_status") as mock_status:
            mock_status.return_value = {"active": False, "enabled": False}
            r = awg_diagnose._diag_service()
            self.assertFalse(r["ok"])
            self.assertEqual(r["status"], "FAIL")


class TestDiagTunnel(unittest.TestCase):
    """_diag_tunnel — awg show."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_warn_when_awg_show_empty(self):
        from chimera.modules import awg_diagnose
        with patch.object(awg_diagnose, "awgs_show_handshakes", return_value=""):
            r = awg_diagnose._diag_tunnel()
            self.assertFalse(r["ok"])
            self.assertEqual(r["status"], "WARN")

    def test_ok_with_peers(self):
        from chimera.modules import awg_diagnose
        output = "peer: abc123\nlatest handshake: 1s ago\npeer: def456\n"
        with patch.object(awg_diagnose, "awgs_show_handshakes", return_value=output):
            r = awg_diagnose._diag_tunnel()
            self.assertTrue(r["ok"])
            self.assertEqual(r["peers"], 2)
            self.assertEqual(r["handshakes"], 1)


class TestDiagNatRouting(unittest.TestCase):
    """_diag_nat_routing — NAT/MASQUERADE/FORWARD/Route/rp_filter."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state(self, subnet="10.66.66.0/24"):
        self._state_file.write_text(json.dumps({
            "installed": True, "subnet": subnet,
        }))
        return patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                     self._state_file)

    def test_all_ok(self):
        from chimera.modules import awg_diagnose
        with self._patch_state(), \
             patch("chimera._core._run") as mock_run:
            # ip_forward=1, MASQUERADE+subnet, FORWARD+awg0, route, rp_filter=0
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="1\n", stderr=""),
                MagicMock(returncode=0, stdout="MASQUERADE 10.66.66.0/24\n", stderr=""),
                MagicMock(returncode=0, stdout="ACCEPT awg0\n", stderr=""),
                MagicMock(returncode=0, stdout="10.66.66.0/24 dev awg0\n", stderr=""),
                MagicMock(returncode=0, stdout="0\n", stderr=""),
            ]
            r = awg_diagnose._diag_nat_routing()
            self.assertTrue(r["ok"])
            self.assertEqual(r["status"], "OK")

    def test_fail_when_ip_forward_off(self):
        from chimera.modules import awg_diagnose
        with self._patch_state(), \
             patch("chimera._core._run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="0\n", stderr=""),
                MagicMock(returncode=0, stdout="MASQUERADE 10.66.66.0/24\n", stderr=""),
                MagicMock(returncode=0, stdout="ACCEPT awg0\n", stderr=""),
                MagicMock(returncode=0, stdout="10.66.66.0/24 dev awg0\n", stderr=""),
                MagicMock(returncode=0, stdout="0\n", stderr=""),
            ]
            r = awg_diagnose._diag_nat_routing()
            self.assertFalse(r["ok"])
            self.assertEqual(r["status"], "FAIL")

    def test_fail_when_masquerade_missing(self):
        from chimera.modules import awg_diagnose
        with self._patch_state(), \
             patch("chimera._core._run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="1\n", stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),  # нет MASQUERADE
                MagicMock(returncode=0, stdout="ACCEPT awg0\n", stderr=""),
                MagicMock(returncode=0, stdout="10.66.66.0/24 dev awg0\n", stderr=""),
                MagicMock(returncode=0, stdout="0\n", stderr=""),
            ]
            r = awg_diagnose._diag_nat_routing()
            self.assertFalse(r["ok"])
            # MASQUERADE-fail → FAIL
            self.assertEqual(r["status"], "FAIL")


class TestDiagCarrierCompare(unittest.TestCase):
    """_diag_carrier_compare."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_compare_result(self):
        from chimera.modules import awg_diagnose
        self._state_file.write_text(json.dumps({
            "installed": True, "params": {"jc": 3, "jmin": 40, "jmax": 80, "i1": "dead"},
        }))
        with patch("chimera.modules.awg_state.AWGS_STATE_FILE", self._state_file):
            r = awg_diagnose._diag_carrier_compare("mobile")
            self.assertIn("status", r)
            self.assertIn("checks", r)


class TestDiagnoseFull(unittest.TestCase):
    """awgs_diagnose_full — оркестрация всех проверок."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_report_has_all_sections(self):
        from chimera.modules import awg_diagnose
        self._state_file.write_text(json.dumps({"installed": True, "port": 51820}))
        with patch("chimera.modules.awg_state.AWGS_STATE_FILE", self._state_file), \
             patch.object(awg_diagnose, "_diag_kernel_module") as mock_k, \
             patch.object(awg_diagnose, "_diag_sysctl") as mock_s, \
             patch.object(awg_diagnose, "_diag_ufw") as mock_u, \
             patch.object(awg_diagnose, "_diag_service") as mock_sv, \
             patch.object(awg_diagnose, "_diag_nat_routing") as mock_nr, \
             patch.object(awg_diagnose, "_diag_tunnel") as mock_t:
            mock_k.return_value = {"ok": True, "status": "OK"}
            mock_s.return_value = []
            mock_u.return_value = {"ok": True, "status": "SKIP"}
            mock_sv.return_value = {"ok": True, "status": "OK", "active": True, "enabled": True}
            mock_nr.return_value = {"ok": True, "status": "OK", "checks": []}
            mock_t.return_value = {"ok": True, "status": "OK", "peers": 0, "handshakes": 0}
            report = awg_diagnose.awgs_diagnose_full()
            for key in ("installed", "kernel", "sysctl", "ufw", "service",
                        "nat_routing", "tunnel"):
                self.assertIn(key, report)
            self.assertNotIn("carrier_compare", report)

    def test_report_includes_carrier_when_provided(self):
        from chimera.modules import awg_diagnose
        self._state_file.write_text(json.dumps({"installed": True, "port": 51820}))
        with patch("chimera.modules.awg_state.AWGS_STATE_FILE", self._state_file), \
             patch.object(awg_diagnose, "_diag_kernel_module"), \
             patch.object(awg_diagnose, "_diag_sysctl", return_value=[]), \
             patch.object(awg_diagnose, "_diag_ufw"), \
             patch.object(awg_diagnose, "_diag_service"), \
             patch.object(awg_diagnose, "_diag_nat_routing"), \
             patch.object(awg_diagnose, "_diag_tunnel"), \
             patch.object(awg_diagnose, "_diag_carrier_compare") as mock_cc:
            mock_cc.return_value = {"status": "OK", "checks": []}
            report = awg_diagnose.awgs_diagnose_full(carrier="mobile")
            self.assertIn("carrier_compare", report)
            mock_cc.assert_called_once_with("mobile")


if __name__ == "__main__":
    unittest.main(verbosity=2)
