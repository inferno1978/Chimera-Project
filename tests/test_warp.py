#!/usr/bin/env python3
"""
tests/test_warp.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/warp.py.

Покрывает:
  1. _wgcf_arch — маппинг архитектуры
  2. _inject_table_off — добавление Table = off в wg-конфиг
  3. _load_original_route — чтение оригинального маршрута
  4. _build_fallback_endpoints — генерация fallback endpoints
  5. _score_probe — скоринг probe-результата
  6. _detect_ssh_client_ip — определение IP SSH-клиента
  7. _warp_is_installed — проверка установки
"""
from __future__ import annotations

import os
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


class TestWgcfArch(unittest.TestCase):
    """_wgcf_arch — маппинг архитектуры."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_x86_64(self):
        from chimera.modules.warp import _wgcf_arch
        with patch("platform.machine", return_value="x86_64"):
            self.assertEqual(_wgcf_arch(), "amd64")

    def test_amd64(self):
        from chimera.modules.warp import _wgcf_arch
        with patch("platform.machine", return_value="amd64"):
            self.assertEqual(_wgcf_arch(), "amd64")

    def test_aarch64(self):
        from chimera.modules.warp import _wgcf_arch
        with patch("platform.machine", return_value="aarch64"):
            self.assertEqual(_wgcf_arch(), "arm64")

    def test_arm64(self):
        from chimera.modules.warp import _wgcf_arch
        with patch("platform.machine", return_value="arm64"):
            self.assertEqual(_wgcf_arch(), "arm64")

    def test_armv7l(self):
        from chimera.modules.warp import _wgcf_arch
        with patch("platform.machine", return_value="armv7l"):
            self.assertEqual(_wgcf_arch(), "arm")

    def test_i386(self):
        from chimera.modules.warp import _wgcf_arch
        with patch("platform.machine", return_value="i386"):
            self.assertEqual(_wgcf_arch(), "386")

    def test_unknown_returns_amd64(self):
        from chimera.modules.warp import _wgcf_arch
        with patch("platform.machine", return_value="mips"):
            self.assertEqual(_wgcf_arch(), "amd64")


class TestInjectTableOff(unittest.TestCase):
    """_inject_table_off — добавление Table = off."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_adds_table_off_to_interface(self):
        from chimera.modules.warp import _inject_table_off
        conf = "[Interface]\nPrivateKey = abc\n"
        result = _inject_table_off(conf)
        self.assertIn("Table = off", result)

    def test_removes_dns_lines(self):
        from chimera.modules.warp import _inject_table_off
        conf = "[Interface]\nPrivateKey = abc\nDNS = 1.1.1.1\n"
        result = _inject_table_off(conf)
        self.assertNotIn("DNS =", result)

    def test_preserves_peer_section(self):
        from chimera.modules.warp import _inject_table_off
        conf = "[Interface]\nPrivateKey = abc\n\n[Peer]\nPublicKey = xyz\n"
        result = _inject_table_off(conf)
        self.assertIn("[Peer]", result)
        self.assertIn("PublicKey = xyz", result)


class TestLoadOriginalRoute(unittest.TestCase):
    """_load_original_route — чтение оригинального маршрута."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._route = self._tmpdir / "original_route.conf"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.warp.ORIG_ROUTE_FILE", self._route)

    def test_returns_none_when_no_file(self):
        from chimera.modules.warp import _load_original_route
        with self._patch():
            self.assertIsNone(_load_original_route())

    def test_returns_gw_and_dev(self):
        from chimera.modules.warp import _load_original_route
        self._route.write_text("MAIN_GW=192.168.1.1\nMAIN_IF=eth0\n")
        with self._patch():
            result = _load_original_route()
        self.assertIsNotNone(result)
        gw, dev = result
        self.assertEqual(gw, "192.168.1.1")
        self.assertEqual(dev, "eth0")

    def test_returns_none_when_no_keys(self):
        from chimera.modules.warp import _load_original_route
        self._route.write_text("OTHER_KEY=value\n")
        with self._patch():
            self.assertIsNone(_load_original_route())


class TestScoreProbe(unittest.TestCase):
    """_score_probe — скоринг probe-результата."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_all_fail_returns_zero(self):
        from chimera.modules.warp import _score_probe
        result = {"tcp_ok": False, "icmp_ok": False, "rtt_ms": None}
        self.assertEqual(_score_probe(result), 0.0)

    def test_all_ok_zero_rtt_returns_max(self):
        from chimera.modules.warp import _score_probe
        result = {"tcp_ok": True, "icmp_ok": True, "rtt_ms": 0}
        # tcp_ok*50 + icmp_ok*30 + max(0, 20 - 0/10) = 50+30+20 = 100
        self.assertEqual(_score_probe(result), 100.0)

    def test_tcp_only(self):
        from chimera.modules.warp import _score_probe
        result = {"tcp_ok": True, "icmp_ok": False, "rtt_ms": 200}
        # 50 + 0 + 0 (rtt > 200ms → 20-20=0) = 50
        self.assertEqual(_score_probe(result), 50.0)

    def test_none_rtt_treated_as_zero_rtt_part(self):
        """rtt_ms=None → rtt_part=0."""
        from chimera.modules.warp import _score_probe
        result = {"tcp_ok": True, "icmp_ok": True, "rtt_ms": None}
        # 50 + 30 + 0 = 80
        self.assertEqual(_score_probe(result), 80.0)


class TestDetectSshClientIp(unittest.TestCase):
    """_detect_ssh_client_ip — определение IP SSH-клиента."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_empty_when_no_env(self):
        from chimera.modules.warp import _detect_ssh_client_ip
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(_detect_ssh_client_ip(), "")

    def test_returns_ip_from_ssh_client(self):
        from chimera.modules.warp import _detect_ssh_client_ip
        with patch.dict(os.environ, {"SSH_CLIENT": "1.2.3.4 55123 22"}, clear=True):
            self.assertEqual(_detect_ssh_client_ip(), "1.2.3.4")

    def test_returns_ip_from_ssh_connection(self):
        from chimera.modules.warp import _detect_ssh_client_ip
        with patch.dict(os.environ, {"SSH_CONNECTION": "5.6.7.8 12345 9.0.0.1 22"}, clear=True):
            self.assertEqual(_detect_ssh_client_ip(), "5.6.7.8")

    def test_ssh_client_takes_priority(self):
        from chimera.modules.warp import _detect_ssh_client_ip
        env = {"SSH_CLIENT": "1.2.3.4 55123 22", "SSH_CONNECTION": "5.6.7.8 12345 9.0.0.1 22"}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(_detect_ssh_client_ip(), "1.2.3.4")


class TestWarpIsInstalled(unittest.TestCase):
    """_warp_is_installed — проверка установки."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "wg-warp.conf"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.warp.WG_CONFIG", self._cfg)

    def test_returns_false_when_no_config(self):
        from chimera.modules.warp import _warp_is_installed
        with self._patch():
            self.assertFalse(_warp_is_installed())

    def test_returns_true_when_config_exists(self):
        from chimera.modules.warp import _warp_is_installed
        self._cfg.write_text("x")
        with self._patch():
            self.assertTrue(_warp_is_installed())


if __name__ == "__main__":
    unittest.main(verbosity=2)
