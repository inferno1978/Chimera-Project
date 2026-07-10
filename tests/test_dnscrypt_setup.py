#!/usr/bin/env python3
"""
tests/test_dnscrypt_setup.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/dnscrypt_setup.py.

Покрывает:
  1. _get_dnscrypt_port — чтение порта из конфига
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


class TestGetDnscryptPort(unittest.TestCase):
    """_get_dnscrypt_port — чтение порта."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "dnscrypt-proxy.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _mock_core(self, cfg_content=None):
        core = MagicMock()
        core.DNSCRYPT_CONF = self._cfg
        core.DNSCRYPT_LISTEN_PORT = 5300
        if cfg_content is not None:
            self._cfg.write_text(cfg_content)
        return core

    def test_returns_default_when_no_file(self):
        from vless_installer.modules import dnscrypt_setup
        with patch.object(dnscrypt_setup, "_core_module",
                          return_value=self._mock_core()):
            self.assertEqual(dnscrypt_setup._get_dnscrypt_port(), 5300)

    def test_returns_port_from_config(self):
        from vless_installer.modules import dnscrypt_setup
        cfg = "listen_addresses = ['127.0.0.1:5300']\n"
        with patch.object(dnscrypt_setup, "_core_module",
                          return_value=self._mock_core(cfg)):
            self.assertEqual(dnscrypt_setup._get_dnscrypt_port(), 5300)

    def test_returns_port_with_double_quotes(self):
        from vless_installer.modules import dnscrypt_setup
        cfg = 'listen_addresses = ["127.0.0.1:5353"]\n'
        with patch.object(dnscrypt_setup, "_core_module",
                          return_value=self._mock_core(cfg)):
            self.assertEqual(dnscrypt_setup._get_dnscrypt_port(), 5353)

    def test_returns_default_when_no_listen_addresses(self):
        from vless_installer.modules import dnscrypt_setup
        cfg = "server_names = ['cloudflare']\n"
        with patch.object(dnscrypt_setup, "_core_module",
                          return_value=self._mock_core(cfg)):
            self.assertEqual(dnscrypt_setup._get_dnscrypt_port(), 5300)


if __name__ == "__main__":
    unittest.main(verbosity=2)
