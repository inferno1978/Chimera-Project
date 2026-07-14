#!/usr/bin/env python3
"""
tests/test_ingress_geoip.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/ingress_geoip.py.

Покрывает:
  1. _ingress_state_load / _ingress_state_save — JSON I/O
  2. _ingress_ipset_available / _ingress_iptables_available — проверки
  3. _ingress_get_cidrs — получение CIDR из файла
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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


class TestIngressStateLoadSave(unittest.TestCase):
    """_ingress_state_load / _ingress_state_save — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "ingress_geoip.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.ingress_geoip.INGRESS_GEOIP_FILE",
                     self._state)

    def test_load_returns_default_when_no_file(self):
        from chimera.modules.ingress_geoip import _ingress_state_load
        with self._patch():
            result = _ingress_state_load()
        self.assertFalse(result["enabled"])
        self.assertEqual(result["port"], 0)

    def test_load_returns_default_on_corrupt(self):
        from chimera.modules.ingress_geoip import _ingress_state_load
        self._state.write_text("{invalid")
        with self._patch():
            result = _ingress_state_load()
        self.assertFalse(result["enabled"])

    def test_save_then_load(self):
        from chimera.modules.ingress_geoip import (
            _ingress_state_load, _ingress_state_save,
        )
        data = {"enabled": True, "port": 443, "cidrs_v4": 100}
        with self._patch():
            _ingress_state_save(data)
            loaded = _ingress_state_load()
        self.assertTrue(loaded["enabled"])
        self.assertEqual(loaded["port"], 443)

    def test_save_sets_chmod_600(self):
        import stat
        from chimera.modules.ingress_geoip import _ingress_state_save
        with self._patch():
            _ingress_state_save({"enabled": False})
        mode = stat.S_IMODE(os.stat(self._state).st_mode)
        self.assertEqual(mode, 0o600)


class TestIngressIpsetAvailable(unittest.TestCase):
    """_ingress_ipset_available / _ingress_iptables_available."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_true_when_ipset_found(self):
        from chimera.modules.ingress_geoip import _ingress_ipset_available
        with patch("shutil.which", return_value="/usr/sbin/ipset"):
            self.assertTrue(_ingress_ipset_available())

    def test_returns_false_when_not_found(self):
        from chimera.modules.ingress_geoip import _ingress_ipset_available
        with patch("shutil.which", return_value=None):
            self.assertFalse(_ingress_ipset_available())

    def test_iptables_available(self):
        from chimera.modules.ingress_geoip import _ingress_iptables_available
        with patch("shutil.which", return_value="/usr/sbin/iptables"):
            self.assertTrue(_ingress_iptables_available())


class TestIngressGetCidrs(unittest.TestCase):
    """_ingress_get_cidrs — получение CIDR из файла."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._ru_file = self._tmpdir / "ru_subnets.txt"
        self._ru_file.write_text(
            "# header\n"
            "10.0.0.0/8\n"
            "192.168.0.0/16\n"
            "2001:db8::/32\n"
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_reads_cidrs_from_file(self):
        from chimera.modules import ingress_geoip

        # Патчим модуль так, чтобы чтение файла работало
        original_path = Path

        def _fake_path_exists(self):
            if str(self) == str(self._ru_file) if hasattr(self, '_ru_file') else False:
                return True
            return original_path(self).exists()

        with patch("chimera.modules.ingress_geoip._fetch_ru_subnets_ripe",
                   return_value=[]) as mock_fetch:
            # _ingress_get_cidrs читает /etc/xray/ru_subnets_ripe.txt
            # Патчим Path чтобы указывал на наш файл
            from unittest.mock import MagicMock
            mock_path = MagicMock()
            mock_path.exists.return_value = True
            mock_path.stat.return_value = MagicMock(st_size=2000)
            mock_path.read_text.return_value = self._ru_file.read_text()

            with patch("chimera.modules.ingress_geoip.Path",
                       return_value=mock_path):
                v4, v6 = ingress_geoip._ingress_get_cidrs()

        self.assertIn("10.0.0.0/8", v4)
        self.assertIn("192.168.0.0/16", v4)
        self.assertIn("2001:db8::/32", v6)
        mock_fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
