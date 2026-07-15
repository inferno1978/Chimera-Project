#!/usr/bin/env python3
"""
tests/test_naiveproxy_fptn_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для mirror-реестров и specs Волны 4 (naiveproxy + fptn):
  • chimera/modules/naiveproxy_mirrors.py
  • chimera/modules/naiveproxy_packages.py::NAIVEPROXY_SPEC
  • chimera/modules/fptn_mirrors.py
  • chimera/modules/fptn_packages.py::FPTN_SPEC
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlparse

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


# ============================================================================
#  naiveproxy_mirrors
# ============================================================================
class TestNaiveproxyMirrors(unittest.TestCase):
    """naiveproxy_mirrors — 12 зеркал для caddy-linux-amd64."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_12_urls(self):
        from chimera.modules.naiveproxy_mirrors import (
            get_naiveproxy_mirrors, NAIVEPROXY_MIRRORS_COUNT,
        )
        urls = get_naiveproxy_mirrors()
        self.assertEqual(len(urls), 12)
        self.assertEqual(NAIVEPROXY_MIRRORS_COUNT, 12)

    def test_all_urls_are_https(self):
        from chimera.modules.naiveproxy_mirrors import get_naiveproxy_mirrors
        for url in get_naiveproxy_mirrors():
            self.assertEqual(urlparse(url).scheme, "https")

    def test_all_urls_contain_repo_and_filename(self):
        from chimera.modules.naiveproxy_mirrors import get_naiveproxy_mirrors
        for url in get_naiveproxy_mirrors():
            self.assertIn("Michaol", url)
            self.assertIn("caddy-naive", url)
            self.assertIn("caddy-linux-amd64", url)

    def test_has_release_github_url(self):
        from chimera.modules.naiveproxy_mirrors import get_naiveproxy_mirrors
        urls = get_naiveproxy_mirrors()
        self.assertTrue(
            any("/releases/latest/download/caddy-linux-amd64" in u for u in urls)
        )

    def test_has_jsdelivr_cdn(self):
        from chimera.modules.naiveproxy_mirrors import get_naiveproxy_mirrors
        urls = get_naiveproxy_mirrors()
        self.assertTrue(any("jsdelivr.net" in u for u in urls))

    def test_recommended_manual_path_is_root(self):
        from chimera.modules.naiveproxy_mirrors import recommended_manual_path
        self.assertEqual(recommended_manual_path(), Path("/root"))


# ============================================================================
#  NAIVEPROXY_SPEC
# ============================================================================
class TestNaiveproxySpecSanity(unittest.TestCase):
    """Sanity-проверки NAIVEPROXY_SPEC."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_name_is_caddy_naive(self):
        from chimera.modules.naiveproxy_packages import NAIVEPROXY_SPEC
        self.assertEqual(NAIVEPROXY_SPEC.name, "caddy-naive")

    def test_filename_is_caddy_linux_amd64(self):
        from chimera.modules.naiveproxy_packages import NAIVEPROXY_SPEC
        self.assertEqual(NAIVEPROXY_SPEC.filename_builder(), "caddy-linux-amd64")

    def test_install_dests_is_usr_local_bin(self):
        from chimera.modules.naiveproxy_packages import NAIVEPROXY_SPEC
        self.assertEqual(NAIVEPROXY_SPEC.install_dests, [Path("/usr/local/bin")])

    def test_manual_dir_is_root(self):
        from chimera.modules.naiveproxy_packages import NAIVEPROXY_SPEC
        self.assertEqual(NAIVEPROXY_SPEC.manual_incoming_dir, Path("/root"))

    def test_manual_dir_not_in_install_dests(self):
        """КРИТИЧЕСКИЙ ИНВАРИАНТ (баг 21d7baf)."""
        from chimera.modules.naiveproxy_packages import NAIVEPROXY_SPEC
        for dest in NAIVEPROXY_SPEC.install_dests:
            self.assertNotEqual(NAIVEPROXY_SPEC.manual_incoming_dir, dest)

    def test_min_size_is_1mb(self):
        from chimera.modules.naiveproxy_packages import NAIVEPROXY_SPEC
        self.assertEqual(NAIVEPROXY_SPEC.min_size, 1_000_000)

    def test_post_install_is_set(self):
        from chimera.modules.naiveproxy_packages import NAIVEPROXY_SPEC
        self.assertIsNotNone(NAIVEPROXY_SPEC.post_install)

    def test_mirror_urls_has_12_entries(self):
        from chimera.modules.naiveproxy_packages import NAIVEPROXY_SPEC
        urls = NAIVEPROXY_SPEC.mirror_urls_builder(filename="caddy-linux-amd64")
        self.assertEqual(len(urls), 12)


# ============================================================================
#  NAIVEPROXY_SPEC post_install — ELF-проверка
# ============================================================================
class TestNaiveproxyPostInstallELF(unittest.TestCase):
    """post_install NAIVEPROXY_SPEC — ELF magic + copy2."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_post_install_copies_elf(self):
        from chimera.modules.naiveproxy_packages import NAIVEPROXY_SPEC
        src = self._tmpdir / "caddy-linux-amd64"
        src.write_bytes(b'\x7fELF' + b'\x00' * 100)
        install_dir = self._tmpdir / "install"
        ok = NAIVEPROXY_SPEC.post_install(src, [install_dir])
        self.assertTrue(ok)
        dest = install_dir / "caddy-naive"
        self.assertTrue(dest.exists())
        self.assertEqual(oct(dest.stat().st_mode & 0o777), '0o755')

    def test_post_install_rejects_non_elf(self):
        from chimera.modules.naiveproxy_packages import NAIVEPROXY_SPEC
        src = self._tmpdir / "caddy-linux-amd64"
        src.write_bytes(b'<html>404</html>' * 100)
        ok = NAIVEPROXY_SPEC.post_install(src, [self._tmpdir / "install"])
        self.assertFalse(ok)


# ============================================================================
#  naiveproxy _download_binary — миграция
# ============================================================================
class TestNaiveproxyDownloadBinaryMigrated(unittest.TestCase):
    """_download_binary — делегирует в fetch_package(NAIVEPROXY_SPEC)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_calls_fetch_package_with_spec(self):
        from chimera.modules import naiveproxy
        from chimera.modules.naiveproxy_packages import NAIVEPROXY_SPEC
        with patch("platform.machine", return_value="x86_64"), \
             patch("chimera.modules.download_manager.fetch_package",
                   return_value=True) as mock_fp:
            result = naiveproxy._download_binary()
        self.assertTrue(result)
        mock_fp.assert_called_once()
        self.assertIs(mock_fp.call_args.args[0], NAIVEPROXY_SPEC)

    def test_returns_false_on_non_amd64(self):
        from chimera.modules import naiveproxy
        with patch("platform.machine", return_value="aarch64"), \
             patch("chimera.modules.download_manager.fetch_package") as mock_fp:
            result = naiveproxy._download_binary()
        self.assertFalse(result)
        mock_fp.assert_not_called()


# ============================================================================
#  fptn_mirrors
# ============================================================================
class TestFptnMirrors(unittest.TestCase):
    """fptn_mirrors — 14 зеркал для fptn-server .deb."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_14_urls(self):
        from chimera.modules.fptn_mirrors import (
            get_fptn_mirrors, FPTN_MIRRORS_COUNT,
        )
        urls = get_fptn_mirrors(tag="0.7.6", filename="fptn-server-ubuntu22.04-amd64.deb")
        self.assertEqual(len(urls), 14)
        self.assertEqual(FPTN_MIRRORS_COUNT, 14)

    def test_all_urls_are_https(self):
        from chimera.modules.fptn_mirrors import get_fptn_mirrors
        for url in get_fptn_mirrors(tag="0.7.6", filename="test.deb"):
            self.assertEqual(urlparse(url).scheme, "https")

    def test_all_urls_contain_repo_tag_filename(self):
        from chimera.modules.fptn_mirrors import get_fptn_mirrors
        urls = get_fptn_mirrors(tag="0.7.6", filename="fptn-server-ubuntu22.04-amd64.deb")
        for url in urls:
            self.assertIn("fptn-project", url)
            self.assertIn("fptn", url)
            self.assertIn("fptn-server-ubuntu22.04-amd64.deb", url)
            self.assertIn("0.7.6", url)

    def test_has_release_github_url(self):
        from chimera.modules.fptn_mirrors import get_fptn_mirrors
        urls = get_fptn_mirrors(tag="0.7.6", filename="fptn-server-ubuntu22.04-amd64.deb")
        self.assertTrue(any("/releases/download/0.7.6/" in u for u in urls))

    def test_empty_tag_returns_empty_list(self):
        from chimera.modules.fptn_mirrors import get_fptn_mirrors
        self.assertEqual(get_fptn_mirrors(tag="", filename="test.deb"), [])

    def test_empty_filename_returns_empty_list(self):
        from chimera.modules.fptn_mirrors import get_fptn_mirrors
        self.assertEqual(get_fptn_mirrors(tag="0.7.6", filename=""), [])

    def test_recommended_manual_path_is_root(self):
        from chimera.modules.fptn_mirrors import recommended_manual_path
        self.assertEqual(recommended_manual_path(), Path("/root"))


# ============================================================================
#  FPTN_SPEC
# ============================================================================
class TestFptnSpecSanity(unittest.TestCase):
    """Sanity-проверки FPTN_SPEC."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_name_is_fptn_server_deb(self):
        from chimera.modules.fptn_packages import FPTN_SPEC
        self.assertEqual(FPTN_SPEC.name, "fptn-server .deb")

    def test_filename_builder_passes_through(self):
        """filename_builder возвращает динамическое имя как есть.

        После фикса бага №1: используем deb_filename (НЕ filename) чтобы
        не конфликтовать с download_manager который сам передаёт filename=
        в mirror_urls_builder.
        """
        from chimera.modules.fptn_packages import FPTN_SPEC
        self.assertEqual(
            FPTN_SPEC.filename_builder(deb_filename="fptn-server-ubuntu22.04-amd64.deb"),
            "fptn-server-ubuntu22.04-amd64.deb",
        )

    def test_install_dests_is_usr_bin(self):
        from chimera.modules.fptn_packages import FPTN_SPEC
        self.assertEqual(FPTN_SPEC.install_dests, [Path("/usr/bin")])

    def test_manual_dir_is_root(self):
        from chimera.modules.fptn_packages import FPTN_SPEC
        self.assertEqual(FPTN_SPEC.manual_incoming_dir, Path("/root"))

    def test_manual_dir_not_in_install_dests(self):
        """КРИТИЧЕСКИЙ ИНВАРИАНТ (баг 21d7baf)."""
        from chimera.modules.fptn_packages import FPTN_SPEC
        for dest in FPTN_SPEC.install_dests:
            self.assertNotEqual(FPTN_SPEC.manual_incoming_dir, dest)

    def test_min_size_is_100kb(self):
        from chimera.modules.fptn_packages import FPTN_SPEC
        self.assertEqual(FPTN_SPEC.min_size, 100_000)

    def test_post_install_is_set(self):
        from chimera.modules.fptn_packages import FPTN_SPEC
        self.assertIsNotNone(FPTN_SPEC.post_install)


# ============================================================================
#  FPTN_SPEC post_install — негативные сценарии
# ============================================================================
class TestFptnPostInstallArchive(unittest.TestCase):
    """post_install FPTN_SPEC — dpkg-deb -x + copy2."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_post_install_returns_false_on_non_deb(self):
        from chimera.modules.fptn_packages import FPTN_SPEC
        src = self._tmpdir / "fake.deb"
        src.write_bytes(b"not a deb" * 100)
        ok = FPTN_SPEC.post_install(src, [self._tmpdir / "install"])
        self.assertFalse(ok)

    def test_post_install_returns_false_on_empty_file(self):
        from chimera.modules.fptn_packages import FPTN_SPEC
        src = self._tmpdir / "empty.deb"
        src.write_bytes(b"")
        ok = FPTN_SPEC.post_install(src, [self._tmpdir / "install"])
        self.assertFalse(ok)


# ============================================================================
#  xray_mirrors — sanity (для полноты Волны 4)
# ============================================================================
class TestXrayMirrorsSanity(unittest.TestCase):
    """xray_mirrors — sanity-проверки."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_zip_mirrors_count_14(self):
        from chimera.modules.xray_mirrors import (
            get_xray_zip_mirrors, XRAY_ZIP_MIRRORS_COUNT,
        )
        urls = get_xray_zip_mirrors(tag="v25.4.30", arch="64")
        # 4 jsDelivr + raw + release + 7 proxy + Statically = 14
        self.assertEqual(len(urls), 14)
        self.assertEqual(XRAY_ZIP_MIRRORS_COUNT, 14)

    def test_checksums_mirrors_count_14(self):
        from chimera.modules.xray_mirrors import (
            get_xray_checksums_mirrors, XRAY_CHK_MIRRORS_COUNT,
        )
        urls = get_xray_checksums_mirrors(tag="v25.4.30", arch="64")
        # 4 jsDelivr + raw + release + 7 proxy + Statically = 14
        self.assertEqual(len(urls), 14)
        self.assertEqual(XRAY_CHK_MIRRORS_COUNT, 14)

    def test_installer_mirrors_non_empty(self):
        from chimera.modules.xray_mirrors import (
            get_xray_installer_mirrors, XRAY_INSTALLER_MIRRORS_COUNT,
        )
        urls = get_xray_installer_mirrors()
        self.assertGreater(len(urls), 0)
        self.assertEqual(XRAY_INSTALLER_MIRRORS_COUNT, len(urls))

    def test_all_zip_urls_are_https(self):
        from chimera.modules.xray_mirrors import get_xray_zip_mirrors
        for url in get_xray_zip_mirrors(tag="v25.4.30", arch="64"):
            self.assertEqual(urlparse(url).scheme, "https")

    def test_zip_urls_contain_repo_tag_arch(self):
        from chimera.modules.xray_mirrors import get_xray_zip_mirrors
        for url in get_xray_zip_mirrors(tag="v25.4.30", arch="64"):
            self.assertIn("XTLS", url)
            self.assertIn("Xray-core", url)
            self.assertIn("v25.4.30", url)
            self.assertIn("Xray-linux-64.zip", url)


# ============================================================================
#  XRAY_ZIP_SPEC / XRAY_INSTALLER_SPEC — sanity
# ============================================================================
class TestXraySpecSanity(unittest.TestCase):
    """Sanity-проверки XRAY_ZIP_SPEC и XRAY_INSTALLER_SPEC."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_zip_spec_name_is_xray_core(self):
        from chimera.modules.xray_packages import XRAY_ZIP_SPEC
        self.assertEqual(XRAY_ZIP_SPEC.name, "Xray-core")

    def test_zip_spec_filename_builder(self):
        from chimera.modules.xray_packages import XRAY_ZIP_SPEC
        self.assertEqual(XRAY_ZIP_SPEC.filename_builder(arch="64"), "Xray-linux-64.zip")
        self.assertEqual(
            XRAY_ZIP_SPEC.filename_builder(arch="arm64-v8a"),
            "Xray-linux-arm64-v8a.zip",
        )

    def test_zip_spec_install_dests_is_usr_local_bin(self):
        from chimera.modules.xray_packages import XRAY_ZIP_SPEC
        self.assertEqual(XRAY_ZIP_SPEC.install_dests, [Path("/usr/local/bin")])

    def test_zip_spec_manual_dir_is_root(self):
        from chimera.modules.xray_packages import XRAY_ZIP_SPEC
        self.assertEqual(XRAY_ZIP_SPEC.manual_incoming_dir, Path("/root"))

    def test_zip_spec_manual_dir_not_in_install_dests(self):
        from chimera.modules.xray_packages import XRAY_ZIP_SPEC
        for dest in XRAY_ZIP_SPEC.install_dests:
            self.assertNotEqual(XRAY_ZIP_SPEC.manual_incoming_dir, dest)

    def test_zip_spec_min_size_is_1mb(self):
        from chimera.modules.xray_packages import XRAY_ZIP_SPEC
        self.assertEqual(XRAY_ZIP_SPEC.min_size, 1_000_000)

    def test_zip_spec_post_install_is_set(self):
        from chimera.modules.xray_packages import XRAY_ZIP_SPEC
        self.assertIsNotNone(XRAY_ZIP_SPEC.post_install)

    def test_installer_spec_name_is_xray_installer(self):
        from chimera.modules.xray_packages import XRAY_INSTALLER_SPEC
        self.assertEqual(XRAY_INSTALLER_SPEC.name, "Xray-installer")

    def test_installer_spec_filename_is_install_release_sh(self):
        from chimera.modules.xray_packages import XRAY_INSTALLER_SPEC
        self.assertEqual(XRAY_INSTALLER_SPEC.filename_builder(), "install-release.sh")

    def test_installer_spec_manual_dir_not_in_install_dests(self):
        from chimera.modules.xray_packages import XRAY_INSTALLER_SPEC
        for dest in XRAY_INSTALLER_SPEC.install_dests:
            self.assertNotEqual(XRAY_INSTALLER_SPEC.manual_incoming_dir, dest)


if __name__ == "__main__":
    unittest.main(verbosity=2)
