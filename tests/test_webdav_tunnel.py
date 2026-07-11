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


# ============================================================================
#  ТЕСТЫ _build_webdav_tunnel / _install_go_toolchain — интеграция с
#  download_manager.fetch_package (Волна 2)
# ============================================================================
# После миграции _build_webdav_tunnel() и _install_go_toolchain() делегируют
# в fetch_package() с PackageSpec из webdav_packages.py / go_toolchain_packages.py.
# Покрываем 4 сценария из ТЗ + sanity-проверки specs.
class TestBuildWebdavTunnelMigrated(unittest.TestCase):
    """_build_webdav_tunnel — делегирует в fetch_package(WEBDAV_SOURCE_SPEC)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_build_calls_fetch_package_with_webdav_spec(self):
        """_build_webdav_tunnel вызывает fetch_package(WEBDAV_SOURCE_SPEC)."""
        from vless_installer.modules import webdav_tunnel
        from vless_installer.modules.webdav_packages import WEBDAV_SOURCE_SPEC

        with patch("vless_installer.modules.webdav_tunnel._ensure_go",
                   return_value="/usr/local/bin/go"), \
             patch("vless_installer.modules.download_manager.fetch_package",
                   return_value=True) as mock_fp:
            result = webdav_tunnel._build_webdav_tunnel()

        self.assertTrue(result)
        mock_fp.assert_called_once()
        spec_arg = mock_fp.call_args.args[0]
        self.assertIs(spec_arg, WEBDAV_SOURCE_SPEC)

    def test_build_returns_false_when_go_unavailable(self):
        """Если _ensure_go вернул None — _build_webdav_tunnel сразу False,
        fetch_package НЕ вызывается."""
        from vless_installer.modules import webdav_tunnel
        with patch("vless_installer.modules.webdav_tunnel._ensure_go",
                   return_value=None), \
             patch("vless_installer.modules.download_manager.fetch_package") as mock_fp:
            result = webdav_tunnel._build_webdav_tunnel()
        self.assertFalse(result)
        mock_fp.assert_not_called()

    def test_build_returns_false_when_fetch_package_fails(self):
        """Сценарий 4: полный провал всех зеркал → False."""
        from vless_installer.modules import webdav_tunnel
        with patch("vless_installer.modules.webdav_tunnel._ensure_go",
                   return_value="/usr/local/bin/go"), \
             patch("vless_installer.modules.download_manager.fetch_package",
                   return_value=False) as mock_fp:
            result = webdav_tunnel._build_webdav_tunnel()
        self.assertFalse(result)
        mock_fp.assert_called_once()


class TestInstallGoToolchainMigrated(unittest.TestCase):
    """_install_go_toolchain — делегирует в fetch_package(GO_TOOLCHAIN_SPEC)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_install_calls_fetch_package_with_go_spec(self):
        """_install_go_toolchain вызывает fetch_package(GO_TOOLCHAIN_SPEC,
        version=..., arch=...)."""
        from vless_installer.modules import webdav_tunnel
        from vless_installer.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC

        mock_resp = unittest.mock.MagicMock()
        mock_resp.read.return_value = b"go1.23.4\n"
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None

        with patch("vless_installer.modules.webdav_tunnel.urllib.request.urlopen",
                   return_value=mock_resp), \
             patch("vless_installer.modules.download_manager.fetch_package",
                   return_value=True) as mock_fp, \
             patch("vless_installer.modules.webdav_tunnel._check_go",
                   return_value="/usr/local/bin/go"):
            result = webdav_tunnel._install_go_toolchain("1.22.0")

        self.assertEqual(result, "/usr/local/bin/go")
        mock_fp.assert_called_once()
        spec_arg = mock_fp.call_args.args[0]
        self.assertIs(spec_arg, GO_TOOLCHAIN_SPEC)
        self.assertEqual(mock_fp.call_args.kwargs.get("version"), "go1.23.4")
        self.assertEqual(mock_fp.call_args.kwargs.get("arch"), "amd64")

    def test_install_returns_none_when_fetch_fails(self):
        from vless_installer.modules import webdav_tunnel

        mock_resp = unittest.mock.MagicMock()
        mock_resp.read.return_value = b"go1.23.4\n"
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None

        with patch("vless_installer.modules.webdav_tunnel.urllib.request.urlopen",
                   return_value=mock_resp), \
             patch("vless_installer.modules.download_manager.fetch_package",
                   return_value=False):
            result = webdav_tunnel._install_go_toolchain("1.22.0")
        self.assertIsNone(result)

    def test_install_fallback_version_on_metadata_failure(self):
        """Если go.dev/VERSION?m=text недоступен — fallback на go{required}."""
        from vless_installer.modules import webdav_tunnel
        from urllib.error import URLError

        with patch("vless_installer.modules.webdav_tunnel.urllib.request.urlopen",
                   side_effect=URLError("blocked")), \
             patch("vless_installer.modules.download_manager.fetch_package",
                   return_value=True) as mock_fp, \
             patch("vless_installer.modules.webdav_tunnel._check_go",
                   return_value="/usr/local/bin/go"):
            webdav_tunnel._install_go_toolchain("1.22.0")

        self.assertEqual(mock_fp.call_args.kwargs.get("version"), "go1.22.0")


class TestWebdavSpecSanity(unittest.TestCase):
    """Sanity-проверки WEBDAV_SOURCE_SPEC — что мигрированный spec корректен."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_spec_filename_is_main_tarball(self):
        from vless_installer.modules.webdav_packages import WEBDAV_SOURCE_SPEC
        self.assertEqual(
            WEBDAV_SOURCE_SPEC.filename_builder(),
            "webdav-tunnel-main.tar.gz",
        )

    def test_spec_install_dests_is_tmp_webdav_packages(self):
        from vless_installer.modules.webdav_packages import WEBDAV_SOURCE_SPEC
        self.assertEqual(WEBDAV_SOURCE_SPEC.install_dests, [Path("/tmp/webdav_packages")])

    def test_spec_manual_dir_is_root(self):
        from vless_installer.modules.webdav_packages import WEBDAV_SOURCE_SPEC
        self.assertEqual(WEBDAV_SOURCE_SPEC.manual_incoming_dir, Path("/root"))

    def test_spec_manual_dir_not_in_install_dests(self):
        """КРИТИЧЕСКИЙ ИНВАРИАНТ: manual_dir != install_dests (баг 21d7baf)."""
        from vless_installer.modules.webdav_packages import WEBDAV_SOURCE_SPEC
        for dest in WEBDAV_SOURCE_SPEC.install_dests:
            self.assertNotEqual(WEBDAV_SOURCE_SPEC.manual_incoming_dir, dest)

    def test_spec_min_size_is_1kb(self):
        from vless_installer.modules.webdav_packages import WEBDAV_SOURCE_SPEC
        self.assertEqual(WEBDAV_SOURCE_SPEC.min_size, 1000)

    def test_spec_post_install_is_set(self):
        from vless_installer.modules.webdav_packages import WEBDAV_SOURCE_SPEC
        self.assertIsNotNone(WEBDAV_SOURCE_SPEC.post_install)

    def test_spec_has_multiple_mirrors_for_fallback(self):
        """Сценарий 2: spec имеет >1 зеркало для fallback."""
        from vless_installer.modules.webdav_packages import WEBDAV_SOURCE_SPEC
        urls = WEBDAV_SOURCE_SPEC.mirror_urls_builder(
            filename="webdav-tunnel-main.tar.gz",
        )
        self.assertGreaterEqual(len(urls), 2,
            "WEBDAV_SOURCE_SPEC должен иметь минимум 2 зеркала для fallback")


if __name__ == "__main__":
    unittest.main(verbosity=2)
