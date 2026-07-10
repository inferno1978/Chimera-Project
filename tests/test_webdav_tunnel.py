#!/usr/bin/env python3
"""
tests/test_webdav_tunnel.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/webdav_tunnel.py.

Покрывает:
  1. _build_client_uri — генерация webdav(s):// URI (selfhosted + external)
  2. _client_run_cmd — генерация команды запуска клиента
  3. _gen_login — генерация логина
  4. _ver_tuple — парсинг версии
  5. _is_installed — проверка установки
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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


class TestBuildClientUri(unittest.TestCase):
    """_build_client_uri — генерация webdav(s):// URI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_selfhosted_with_tls(self):
        from vless_installer.modules import webdav_tunnel
        state = {"mode": "selfhosted", "tls": True, "port": 8443}
        with patch.object(webdav_tunnel, "_get_server_ip", return_value="1.2.3.4"):
            uri = webdav_tunnel._build_client_uri(state)
        self.assertTrue(uri.startswith("webdavs://"))
        self.assertIn("1.2.3.4:8443", uri)

    def test_selfhosted_without_tls(self):
        from vless_installer.modules import webdav_tunnel
        state = {"mode": "selfhosted", "tls": False, "port": 8080}
        with patch.object(webdav_tunnel, "_get_server_ip", return_value="1.2.3.4"):
            uri = webdav_tunnel._build_client_uri(state)
        self.assertTrue(uri.startswith("webdav://"))
        self.assertIn("1.2.3.4:8080", uri)

    def test_external_https(self):
        from vless_installer.modules import webdav_tunnel
        state = {"mode": "external", "webdav_url": "https://dav.example.com/path"}
        uri = webdav_tunnel._build_client_uri(state)
        self.assertTrue(uri.startswith("webdavs://"))
        self.assertIn("dav.example.com", uri)

    def test_external_http(self):
        from vless_installer.modules import webdav_tunnel
        state = {"mode": "external", "webdav_url": "http://dav.example.com:8080/path"}
        uri = webdav_tunnel._build_client_uri(state)
        self.assertTrue(uri.startswith("webdav://"))
        self.assertIn("dav.example.com:8080", uri)

    def test_selfhosted_includes_tuning_params(self):
        from vless_installer.modules import webdav_tunnel
        from vless_installer.modules.webdav_tunnel import _SH_TUNING
        state = {"mode": "selfhosted", "tls": True, "port": 8443}
        with patch.object(webdav_tunnel, "_get_server_ip", return_value="1.2.3.4"):
            uri = webdav_tunnel._build_client_uri(state)
        for key in _SH_TUNING:
            self.assertIn(f"{key}=", uri)


class TestClientRunCmd(unittest.TestCase):
    """_client_run_cmd — генерация команды запуска."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_command_with_uri(self):
        from vless_installer.modules.webdav_tunnel import _client_run_cmd
        cmd = _client_run_cmd("webdavs://1.2.3.4:8443")
        self.assertIn("webdav-tunnel", cmd)
        self.assertIn("-mode client", cmd)
        self.assertIn("-uri", cmd)
        self.assertIn("webdavs://1.2.3.4:8443", cmd)
        self.assertIn("-socks-listen 127.0.0.1:1080", cmd)


class TestGenLogin(unittest.TestCase):
    """_gen_login — генерация логина."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_starts_with_user_prefix(self):
        from vless_installer.modules.webdav_tunnel import _gen_login
        login = _gen_login()
        self.assertTrue(login.startswith("user"))

    def test_has_4_digits(self):
        from vless_installer.modules.webdav_tunnel import _gen_login
        login = _gen_login()
        suffix = login[4:]
        self.assertEqual(len(suffix), 4)
        self.assertTrue(all(c in "23456789" for c in suffix))

    def test_unique(self):
        from vless_installer.modules.webdav_tunnel import _gen_login
        logins = {_gen_login() for _ in range(20)}
        self.assertGreater(len(logins), 1)


class TestVerTuple(unittest.TestCase):
    """_ver_tuple — парсинг версии."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_full_version(self):
        from vless_installer.modules.webdav_tunnel import _ver_tuple
        self.assertEqual(_ver_tuple("1.22.0"), (1, 22, 0))

    def test_two_part(self):
        from vless_installer.modules.webdav_tunnel import _ver_tuple
        self.assertEqual(_ver_tuple("1.22"), (1, 22, 0))

    def test_invalid_returns_zeros(self):
        from vless_installer.modules.webdav_tunnel import _ver_tuple
        self.assertEqual(_ver_tuple("abc"), (0, 0, 0))


class TestIsInstalled(unittest.TestCase):
    """_is_installed."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._bin = self._tmpdir / "webdav-tunnel"
        self._svc = self._tmpdir / "webdav-tunnel.service"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("vless_installer.modules.webdav_tunnel._BIN_PATH", self._bin),
            patch("vless_installer.modules.webdav_tunnel._SERVICE_FILE", self._svc),
        )

    def test_returns_false_when_neither(self):
        from vless_installer.modules.webdav_tunnel import _is_installed
        with self._patch()[0], self._patch()[1]:
            self.assertFalse(_is_installed())

    def test_returns_true_when_both(self):
        from vless_installer.modules.webdav_tunnel import _is_installed
        self._bin.write_text("x")
        self._svc.write_text("x")
        with self._patch()[0], self._patch()[1]:
            self.assertTrue(_is_installed())


if __name__ == "__main__":
    unittest.main(verbosity=2)
