#!/usr/bin/env python3
"""
tests/test_hysteria2_dnscrypt_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для mirror-реестров Волны 3:
  • vless_installer/modules/hysteria2_mirrors.py
  • vless_installer/modules/hysteria2_packages.py::HYSTERIA2_SPEC
  • vless_installer/modules/dnscrypt_mirrors.py
  • vless_installer/modules/dnscrypt_packages.py::DNSCRYPT_SPEC

Покрывает:
  • Корректность URL-шаблонов
  • Что все URL — HTTPS
  • Что URL содержат owner/repo/filename
  • КРИТИЧЕСКИЙ ИНВАРИАНТ: manual_incoming_dir != install_dests (баг 21d7baf)
  • Что post_install установлен и валиден
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


# ============================================================================
#  hysteria2_mirrors — реестр зеркал Hysteria2 binary
# ============================================================================
class TestHysteria2Mirrors(unittest.TestCase):
    """hysteria2_mirrors — 14 зеркал для hysteria-linux-{arch}."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_14_urls(self):
        from vless_installer.modules.hysteria2_mirrors import (
            get_hysteria2_mirrors, HYSTERIA2_MIRRORS_COUNT,
        )
        urls = get_hysteria2_mirrors(tag="latest", arch="amd64")
        self.assertEqual(len(urls), 14)
        self.assertEqual(HYSTERIA2_MIRRORS_COUNT, 14)

    def test_all_urls_are_https(self):
        from vless_installer.modules.hysteria2_mirrors import get_hysteria2_mirrors
        for url in get_hysteria2_mirrors(tag="latest", arch="amd64"):
            self.assertEqual(urlparse(url).scheme, "https")

    def test_all_urls_contain_repo_and_filename(self):
        from vless_installer.modules.hysteria2_mirrors import get_hysteria2_mirrors
        for url in get_hysteria2_mirrors(tag="latest", arch="amd64"):
            self.assertIn("apernet", url)
            self.assertIn("hysteria", url)
            self.assertIn("hysteria-linux-amd64", url)

    def test_has_release_github_url(self):
        """release GitHub URL присутствует (основной путь для binary)."""
        from vless_installer.modules.hysteria2_mirrors import get_hysteria2_mirrors
        urls = get_hysteria2_mirrors(tag="latest", arch="amd64")
        self.assertTrue(
            any("github.com/apernet/hysteria/releases/latest/download/" in u
                for u in urls),
            f"Нет release/latest/download URL: {urls}"
        )

    def test_has_jsdelivr_cdn(self):
        from vless_installer.modules.hysteria2_mirrors import get_hysteria2_mirrors
        urls = get_hysteria2_mirrors(tag="latest", arch="amd64")
        jsdelivr_count = sum(1 for u in urls if "jsdelivr.net" in u)
        self.assertGreaterEqual(jsdelivr_count, 1)

    def test_has_gh_proxy(self):
        from vless_installer.modules.hysteria2_mirrors import get_hysteria2_mirrors
        urls = get_hysteria2_mirrors(tag="latest", arch="amd64")
        proxy_domains = ["ghproxy", "gh.con.sh", "gitmirror", "moeyy", "ghps.cc"]
        has_proxy = any(any(d in u for d in proxy_domains) for u in urls)
        self.assertTrue(has_proxy)

    def test_arm64_arch(self):
        from vless_installer.modules.hysteria2_mirrors import get_hysteria2_mirrors
        urls = get_hysteria2_mirrors(tag="latest", arch="arm64")
        for url in urls:
            self.assertIn("hysteria-linux-arm64", url)

    def test_pinned_tag(self):
        """Конкретный tag 'app/v2.9.3' формирует /releases/download/app/v2.9.3/."""
        from vless_installer.modules.hysteria2_mirrors import get_hysteria2_mirrors
        urls = get_hysteria2_mirrors(tag="app/v2.9.3", arch="amd64")
        self.assertTrue(
            any("/releases/download/app/v2.9.3/" in u for u in urls),
            f"Нет /releases/download/app/v2.9.3/ URL для pinned tag: {urls}"
        )

    def test_recommended_manual_path_is_root(self):
        from vless_installer.modules.hysteria2_mirrors import recommended_manual_path
        self.assertEqual(recommended_manual_path(), Path("/root"))


# ============================================================================
#  dnscrypt_mirrors — реестр зеркал dnscrypt-proxy tarball
# ============================================================================
class TestDnscryptMirrors(unittest.TestCase):
    """dnscrypt_mirrors — 14 зеркал для dnscrypt-proxy-{arch}-{tag}.tar.gz."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_14_urls(self):
        from vless_installer.modules.dnscrypt_mirrors import (
            get_dnscrypt_mirrors, DNSCRYPT_MIRRORS_COUNT,
        )
        urls = get_dnscrypt_mirrors(tag="2.1.5", arch="linux_x86_64")
        self.assertEqual(len(urls), 14)
        self.assertEqual(DNSCRYPT_MIRRORS_COUNT, 14)

    def test_all_urls_are_https(self):
        from vless_installer.modules.dnscrypt_mirrors import get_dnscrypt_mirrors
        for url in get_dnscrypt_mirrors(tag="2.1.5", arch="linux_x86_64"):
            self.assertEqual(urlparse(url).scheme, "https")

    def test_all_urls_contain_repo_filename_and_tag(self):
        from vless_installer.modules.dnscrypt_mirrors import get_dnscrypt_mirrors
        for url in get_dnscrypt_mirrors(tag="2.1.5", arch="linux_x86_64"):
            self.assertIn("DNSCrypt", url)
            self.assertIn("dnscrypt-proxy", url)
            self.assertIn("dnscrypt-proxy-linux_x86_64-2.1.5.tar.gz", url)
            self.assertIn("2.1.5", url)

    def test_has_release_github_url(self):
        from vless_installer.modules.dnscrypt_mirrors import get_dnscrypt_mirrors
        urls = get_dnscrypt_mirrors(tag="2.1.5", arch="linux_x86_64")
        self.assertTrue(
            any("/releases/download/2.1.5/" in u for u in urls)
        )

    def test_empty_tag_returns_empty_list(self):
        from vless_installer.modules.dnscrypt_mirrors import get_dnscrypt_mirrors
        self.assertEqual(get_dnscrypt_mirrors(tag="", arch="linux_x86_64"), [])

    def test_arm64_arch(self):
        from vless_installer.modules.dnscrypt_mirrors import get_dnscrypt_mirrors
        urls = get_dnscrypt_mirrors(tag="2.1.5", arch="linux_arm64")
        for url in urls:
            self.assertIn("dnscrypt-proxy-linux_arm64-2.1.5.tar.gz", url)

    def test_recommended_manual_path_is_root(self):
        from vless_installer.modules.dnscrypt_mirrors import recommended_manual_path
        self.assertEqual(recommended_manual_path(), Path("/root"))


# ============================================================================
#  HYSTERIA2_SPEC — инварианты PackageSpec
# ============================================================================
class TestHysteria2SpecInvariants(unittest.TestCase):
    """КРИТИЧЕСКИЕ инварианты HYSTERIA2_SPEC."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_manual_dir_is_root(self):
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC
        self.assertEqual(HYSTERIA2_SPEC.manual_incoming_dir, Path("/root"))

    def test_manual_dir_not_in_install_dests(self):
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC
        for dest in HYSTERIA2_SPEC.install_dests:
            self.assertNotEqual(HYSTERIA2_SPEC.manual_incoming_dir, dest)

    def test_install_dests_is_usr_local_bin(self):
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC
        self.assertEqual(HYSTERIA2_SPEC.install_dests, [Path("/usr/local/bin")])

    def test_min_size_is_1mb(self):
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC
        self.assertEqual(HYSTERIA2_SPEC.min_size, 1_000_000)

    def test_post_install_is_set(self):
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC
        self.assertIsNotNone(HYSTERIA2_SPEC.post_install)


# ============================================================================
#  DNSCRYPT_SPEC — инварианты PackageSpec
# ============================================================================
class TestDnscryptSpecInvariants(unittest.TestCase):
    """КРИТИЧЕСКИЕ инварианты DNSCRYPT_SPEC."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_manual_dir_is_root(self):
        from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertEqual(DNSCRYPT_SPEC.manual_incoming_dir, Path("/root"))

    def test_manual_dir_not_in_install_dests(self):
        from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC
        for dest in DNSCRYPT_SPEC.install_dests:
            self.assertNotEqual(DNSCRYPT_SPEC.manual_incoming_dir, dest)

    def test_install_dests_is_usr_local_bin(self):
        from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertEqual(DNSCRYPT_SPEC.install_dests, [Path("/usr/local/bin")])

    def test_min_size_is_100kb(self):
        from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertEqual(DNSCRYPT_SPEC.min_size, 100_000)

    def test_post_install_is_set(self):
        from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertIsNotNone(DNSCRYPT_SPEC.post_install)


# ============================================================================
#  post_install — ELF-проверка для Hysteria2
# ============================================================================
class TestPostInstallHysteria2ELFCheck(unittest.TestCase):
    """post_install HYSTERIA2_SPEC — ELF magic проверка + atomic-replace."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_elf(self, name: str = "fake-hysteria") -> Path:
        p = self._tmpdir / name
        p.write_bytes(b'\x7fELF' + b'\x00' * 100)
        return p

    def _make_non_elf(self, name: str = "fake-html") -> Path:
        p = self._tmpdir / name
        p.write_bytes(b'<html>404 Not Found</html>' * 100)
        return p

    def test_post_install_copies_elf_to_hysteria(self):
        """post_install копирует ELF → install_dests/hysteria (chmod 0o755)."""
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC

        install_dir = self._tmpdir / "install"
        src = self._make_elf("hysteria-linux-amd64")
        # Мокаем systemctl чтобы не трогать реальный сервис
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = unittest.mock.MagicMock(returncode=1)  # service not active
            ok = HYSTERIA2_SPEC.post_install(src, [install_dir])
        self.assertTrue(ok)
        dest = install_dir / "hysteria"
        self.assertTrue(dest.exists())
        self.assertEqual(oct(dest.stat().st_mode & 0o777), '0o755')

    def test_post_install_rejects_non_elf(self):
        """Не-ELF файл → False (даёт fetch_package шанс попробовать другое зеркало)."""
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC

        install_dir = self._tmpdir / "install"
        src = self._make_non_elf("hysteria-linux-amd64")
        ok = HYSTERIA2_SPEC.post_install(src, [install_dir])
        self.assertFalse(ok)

    def test_post_install_creates_install_dir(self):
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC

        install_dir = self._tmpdir / "deeply" / "nested" / "install"
        src = self._make_elf("hysteria-linux-amd64")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = unittest.mock.MagicMock(returncode=1)
            ok = HYSTERIA2_SPEC.post_install(src, [install_dir])
        self.assertTrue(ok)
        self.assertTrue(install_dir.exists())


# ============================================================================
#  post_install — tarball-обработка для dnscrypt
# ============================================================================
class TestPostInstallDnscryptArchive(unittest.TestCase):
    """post_install DNSCRYPT_SPEC — extract + rglob + copy2."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_post_install_returns_false_on_non_tarball(self):
        from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC

        src = self._tmpdir / "fake.tar.gz"
        src.write_bytes(b"not a tarball" * 100)
        ok = DNSCRYPT_SPEC.post_install(src, [self._tmpdir / "install"])
        self.assertFalse(ok)

    def test_post_install_returns_false_on_empty_file(self):
        from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC

        src = self._tmpdir / "empty.tar.gz"
        src.write_bytes(b"")
        ok = DNSCRYPT_SPEC.post_install(src, [self._tmpdir / "install"])
        self.assertFalse(ok)


# ============================================================================
#  mirror_urls_builder — сигнатура совместимости с PackageSpec API
# ============================================================================
class TestMirrorUrlsBuilderSignature(unittest.TestCase):
    """mirror_urls_builder принимает filename= и **kwargs."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_hysteria2_builder_accepts_filename_and_arch(self):
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC
        urls = HYSTERIA2_SPEC.mirror_urls_builder(
            filename="hysteria-linux-amd64", arch="amd64",
        )
        self.assertGreater(len(urls), 0)

    def test_hysteria2_builder_uses_arch_in_urls(self):
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC
        urls = HYSTERIA2_SPEC.mirror_urls_builder(
            filename="ignored", arch="arm64",
        )
        for url in urls:
            self.assertIn("hysteria-linux-arm64", url)

    def test_dnscrypt_builder_accepts_filename_tag_and_arch(self):
        from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC
        urls = DNSCRYPT_SPEC.mirror_urls_builder(
            filename="ignored", tag="2.1.5", arch="linux_x86_64",
        )
        self.assertGreater(len(urls), 0)

    def test_dnscrypt_builder_uses_tag_and_arch_in_urls(self):
        from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC
        urls = DNSCRYPT_SPEC.mirror_urls_builder(
            filename="ignored", tag="2.1.5", arch="linux_arm64",
        )
        for url in urls:
            self.assertIn("dnscrypt-proxy-linux_arm64-2.1.5.tar.gz", url)


if __name__ == "__main__":
    unittest.main(verbosity=2)
