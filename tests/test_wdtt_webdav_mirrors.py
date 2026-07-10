#!/usr/bin/env python3
"""
tests/test_wdtt_webdav_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для mirror-реестров и PackageSpecs Волны 2:
  • vless_installer/modules/github_mirrors.py::build_source_archive_mirror_urls
  • vless_installer/modules/go_toolchain_mirrors.py
  • vless_installer/modules/go_toolchain_packages.py::GO_TOOLCHAIN_SPEC
  • vless_installer/modules/wdtt_mirrors.py
  • vless_installer/modules/wdtt_packages.py::WDTT_SOURCE_SPEC
  • vless_installer/modules/webdav_mirrors.py
  • vless_installer/modules/webdav_packages.py::WEBDAV_SOURCE_SPEC

Покрывает:
  • Корректность URL-шаблонов (прямой GitHub + codeload + 7 gh-proxy для
    source-архивов; go.dev + 3 региональных зеркала для Go toolchain)
  • Что все URL — HTTPS
  • Что URL содержат owner/repo/branch (source) или version/arch (Go)
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
#  build_source_archive_mirror_urls — общий билдер для source-архивов
# ============================================================================
class TestBuildSourceArchiveMirrorUrls(unittest.TestCase):
    """build_source_archive_mirror_urls — корректность URL."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_9_urls_for_default_config(self):
        """1 прямой + 1 codeload + 7 прокси = 9 URL."""
        from vless_installer.modules.github_mirrors import (
            build_source_archive_mirror_urls, GITHUB_PROXY_HOSTS,
        )
        urls = build_source_archive_mirror_urls(
            "SpaceNeuroX", "proxy-turn-vk-android", "master",
        )
        self.assertEqual(len(urls), 2 + len(GITHUB_PROXY_HOSTS))

    def test_all_urls_are_https(self):
        from vless_installer.modules.github_mirrors import build_source_archive_mirror_urls
        for url in build_source_archive_mirror_urls("a", "b", "main"):
            self.assertEqual(urlparse(url).scheme, "https")

    def test_first_url_is_direct_github(self):
        from vless_installer.modules.github_mirrors import build_source_archive_mirror_urls
        urls = build_source_archive_mirror_urls("a", "b", "main")
        self.assertEqual(
            urls[0],
            "https://github.com/a/b/archive/refs/heads/main.tar.gz",
        )

    def test_second_url_is_codeload(self):
        from vless_installer.modules.github_mirrors import build_source_archive_mirror_urls
        urls = build_source_archive_mirror_urls("a", "b", "main")
        self.assertEqual(
            urls[1],
            "https://codeload.github.com/a/b/tar.gz/refs/heads/main",
        )

    def test_proxy_urls_come_after_direct_and_codeload(self):
        from vless_installer.modules.github_mirrors import build_source_archive_mirror_urls
        urls = build_source_archive_mirror_urls("a", "b", "main")
        # URLs 2..8 — прокси (начиная с ghproxy.net)
        self.assertIn("ghproxy.net", urls[2])
        self.assertIn("/a/b/archive/refs/heads/main.tar.gz", urls[2])

    def test_can_disable_codeload(self):
        from vless_installer.modules.github_mirrors import build_source_archive_mirror_urls
        urls = build_source_archive_mirror_urls(
            "a", "b", "main", include_codeload=False,
        )
        # Без codeload: 1 прямой + 7 прокси = 8 URL
        self.assertEqual(len(urls), 8)
        self.assertNotIn("codeload.github.com", "".join(urls))

    def test_returns_empty_on_missing_args(self):
        from vless_installer.modules.github_mirrors import build_source_archive_mirror_urls
        self.assertEqual(build_source_archive_mirror_urls("", "b", "main"), [])
        self.assertEqual(build_source_archive_mirror_urls("a", "", "main"), [])
        self.assertEqual(build_source_archive_mirror_urls("a", "b", ""), [])

    def test_custom_proxy_hosts(self):
        from vless_installer.modules.github_mirrors import build_source_archive_mirror_urls
        urls = build_source_archive_mirror_urls(
            "a", "b", "main", proxy_hosts=["custom.proxy.com"],
        )
        # 1 прямой + 1 codeload + 1 кастомный прокси = 3 URL
        self.assertEqual(len(urls), 3)
        self.assertIn("custom.proxy.com", urls[2])


# ============================================================================
#  go_toolchain_mirrors — реестр зеркал Go toolchain
# ============================================================================
class TestGoToolchainMirrors(unittest.TestCase):
    """go_toolchain_mirrors — 4 зеркала (go.dev + 3 региональных)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_4_urls(self):
        from vless_installer.modules.go_toolchain_mirrors import (
            get_go_toolchain_mirrors, GO_TOOLCHAIN_MIRRORS_COUNT,
        )
        urls = get_go_toolchain_mirrors("go1.23.4", "amd64")
        self.assertEqual(len(urls), 4)
        self.assertEqual(GO_TOOLCHAIN_MIRRORS_COUNT, 4)

    def test_all_urls_are_https(self):
        from vless_installer.modules.go_toolchain_mirrors import get_go_toolchain_mirrors
        for url in get_go_toolchain_mirrors("go1.23.4", "amd64"):
            self.assertEqual(urlparse(url).scheme, "https")

    def test_first_url_is_go_dev(self):
        from vless_installer.modules.go_toolchain_mirrors import get_go_toolchain_mirrors
        urls = get_go_toolchain_mirrors("go1.23.4", "amd64")
        self.assertEqual(
            urls[0],
            "https://go.dev/dl/go1.23.4.linux-amd64.tar.gz",
        )

    def test_contains_regional_mirrors(self):
        from vless_installer.modules.go_toolchain_mirrors import get_go_toolchain_mirrors
        urls = get_go_toolchain_mirrors("go1.23.4", "amd64")
        all_urls = " ".join(urls)
        self.assertIn("golang.google.cn", all_urls)
        self.assertIn("mirrors.aliyun.com", all_urls)
        self.assertIn("mirrors.tencent.com", all_urls)

    def test_arm64_arch(self):
        from vless_installer.modules.go_toolchain_mirrors import get_go_toolchain_mirrors
        urls = get_go_toolchain_mirrors("go1.23.4", "arm64")
        for url in urls:
            self.assertIn("linux-arm64.tar.gz", url)

    def test_normalizes_version_without_go_prefix(self):
        """Если version передан как '1.23.4' (без 'go'), добавляется префикс."""
        from vless_installer.modules.go_toolchain_mirrors import get_go_toolchain_mirrors
        urls = get_go_toolchain_mirrors("1.23.4", "amd64")
        for url in urls:
            self.assertIn("go1.23.4.linux-amd64.tar.gz", url)

    def test_empty_version_returns_empty_list(self):
        from vless_installer.modules.go_toolchain_mirrors import get_go_toolchain_mirrors
        self.assertEqual(get_go_toolchain_mirrors("", "amd64"), [])

    def test_recommended_manual_path_is_root(self):
        from vless_installer.modules.go_toolchain_mirrors import recommended_manual_path
        self.assertEqual(recommended_manual_path(), Path("/root"))


# ============================================================================
#  GO_TOOLCHAIN_SPEC — sanity-проверки
# ============================================================================
class TestGoToolchainSpecSanity(unittest.TestCase):
    """GO_TOOLCHAIN_SPEC — инварианты PackageSpec."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_name_is_go_toolchain(self):
        from vless_installer.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
        self.assertEqual(GO_TOOLCHAIN_SPEC.name, "Go toolchain")

    def test_filename_builder_with_version_and_arch(self):
        from vless_installer.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
        self.assertEqual(
            GO_TOOLCHAIN_SPEC.filename_builder(version="go1.23.4", arch="amd64"),
            "go1.23.4.linux-amd64.tar.gz",
        )
        self.assertEqual(
            GO_TOOLCHAIN_SPEC.filename_builder(version="go1.23.4", arch="arm64"),
            "go1.23.4.linux-arm64.tar.gz",
        )

    def test_install_dests_is_usr_local(self):
        from vless_installer.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
        self.assertEqual(GO_TOOLCHAIN_SPEC.install_dests, [Path("/usr/local")])

    def test_manual_dir_is_root(self):
        from vless_installer.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
        self.assertEqual(GO_TOOLCHAIN_SPEC.manual_incoming_dir, Path("/root"))

    def test_manual_dir_not_in_install_dests(self):
        """КРИТИЧЕСКИЙ ИНВАРИАНТ (баг 21d7baf)."""
        from vless_installer.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
        for dest in GO_TOOLCHAIN_SPEC.install_dests:
            self.assertNotEqual(GO_TOOLCHAIN_SPEC.manual_incoming_dir, dest)

    def test_min_size_is_10mb(self):
        from vless_installer.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
        self.assertEqual(GO_TOOLCHAIN_SPEC.min_size, 10_000_000)

    def test_post_install_is_set(self):
        from vless_installer.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
        self.assertIsNotNone(GO_TOOLCHAIN_SPEC.post_install)

    def test_mirror_urls_builder_uses_version_and_arch(self):
        from vless_installer.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
        urls = GO_TOOLCHAIN_SPEC.mirror_urls_builder(
            filename="ignored.tar.gz",
            version="go1.23.4", arch="amd64",
        )
        self.assertEqual(len(urls), 4)
        # filename игнорируется — URL строится из version+arch
        for url in urls:
            self.assertIn("go1.23.4.linux-amd64.tar.gz", url)


# ============================================================================
#  wdtt_mirrors — реестр зеркал qWDTT source
# ============================================================================
class TestWdttMirrors(unittest.TestCase):
    """wdtt_mirrors — 9 зеркал для proxy-turn-vk-android-master.tar.gz."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_9_urls(self):
        from vless_installer.modules.wdtt_mirrors import (
            get_wdtt_source_mirrors, WDTT_SOURCE_MIRRORS_COUNT,
        )
        urls = get_wdtt_source_mirrors()
        self.assertEqual(len(urls), 9)
        self.assertEqual(WDTT_SOURCE_MIRRORS_COUNT, 9)

    def test_all_urls_are_https(self):
        from vless_installer.modules.wdtt_mirrors import get_wdtt_source_mirrors
        for url in get_wdtt_source_mirrors():
            self.assertEqual(urlparse(url).scheme, "https")

    def test_all_urls_contain_repo_and_branch(self):
        from vless_installer.modules.wdtt_mirrors import get_wdtt_source_mirrors
        for url in get_wdtt_source_mirrors():
            self.assertIn("SpaceNeuroX", url)
            self.assertIn("proxy-turn-vk-android", url)
            self.assertIn("master", url)

    def test_has_direct_github_url(self):
        from vless_installer.modules.wdtt_mirrors import get_wdtt_source_mirrors
        urls = get_wdtt_source_mirrors()
        self.assertTrue(
            any("github.com/SpaceNeuroX/proxy-turn-vk-android/archive/refs/heads/master.tar.gz" in u
                for u in urls)
        )

    def test_has_codeload_url(self):
        from vless_installer.modules.wdtt_mirrors import get_wdtt_source_mirrors
        urls = get_wdtt_source_mirrors()
        self.assertTrue(
            any("codeload.github.com" in u for u in urls)
        )

    def test_recommended_manual_path_is_root(self):
        from vless_installer.modules.wdtt_mirrors import recommended_manual_path
        self.assertEqual(recommended_manual_path(), Path("/root"))


# ============================================================================
#  WDTT_SOURCE_SPEC — sanity-проверки
# ============================================================================
class TestWdttSourceSpecSanity(unittest.TestCase):
    """WDTT_SOURCE_SPEC — инварианты PackageSpec."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_name_is_qwdtt_source(self):
        from vless_installer.modules.wdtt_packages import WDTT_SOURCE_SPEC
        self.assertEqual(WDTT_SOURCE_SPEC.name, "qWDTT source")

    def test_filename_is_master_tarball(self):
        from vless_installer.modules.wdtt_packages import WDTT_SOURCE_SPEC
        self.assertEqual(
            WDTT_SOURCE_SPEC.filename_builder(),
            "proxy-turn-vk-android-master.tar.gz",
        )

    def test_manual_dir_is_root(self):
        from vless_installer.modules.wdtt_packages import WDTT_SOURCE_SPEC
        self.assertEqual(WDTT_SOURCE_SPEC.manual_incoming_dir, Path("/root"))

    def test_manual_dir_not_in_install_dests(self):
        """КРИТИЧЕСКИЙ ИНВАРИАНТ (баг 21d7baf)."""
        from vless_installer.modules.wdtt_packages import WDTT_SOURCE_SPEC
        for dest in WDTT_SOURCE_SPEC.install_dests:
            self.assertNotEqual(WDTT_SOURCE_SPEC.manual_incoming_dir, dest)

    def test_min_size_is_1kb(self):
        from vless_installer.modules.wdtt_packages import WDTT_SOURCE_SPEC
        self.assertEqual(WDTT_SOURCE_SPEC.min_size, 1000)

    def test_post_install_is_set(self):
        from vless_installer.modules.wdtt_packages import WDTT_SOURCE_SPEC
        self.assertIsNotNone(WDTT_SOURCE_SPEC.post_install)

    def test_mirror_urls_has_9_entries(self):
        from vless_installer.modules.wdtt_packages import WDTT_SOURCE_SPEC
        urls = WDTT_SOURCE_SPEC.mirror_urls_builder(
            filename="proxy-turn-vk-android-master.tar.gz",
        )
        self.assertEqual(len(urls), 9)


# ============================================================================
#  webdav_mirrors — реестр зеркал webdav-tunnel source
# ============================================================================
class TestWebdavMirrors(unittest.TestCase):
    """webdav_mirrors — 9 зеркал для webdav-tunnel-main.tar.gz."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_9_urls(self):
        from vless_installer.modules.webdav_mirrors import (
            get_webdav_source_mirrors, WEBDAV_SOURCE_MIRRORS_COUNT,
        )
        urls = get_webdav_source_mirrors()
        self.assertEqual(len(urls), 9)
        self.assertEqual(WEBDAV_SOURCE_MIRRORS_COUNT, 9)

    def test_all_urls_are_https(self):
        from vless_installer.modules.webdav_mirrors import get_webdav_source_mirrors
        for url in get_webdav_source_mirrors():
            self.assertEqual(urlparse(url).scheme, "https")

    def test_all_urls_contain_repo_and_branch(self):
        from vless_installer.modules.webdav_mirrors import get_webdav_source_mirrors
        for url in get_webdav_source_mirrors():
            self.assertIn("spkprsnts", url)
            self.assertIn("webdav-tunnel", url)
            self.assertIn("main", url)

    def test_has_direct_github_url(self):
        from vless_installer.modules.webdav_mirrors import get_webdav_source_mirrors
        urls = get_webdav_source_mirrors()
        self.assertTrue(
            any("github.com/spkprsnts/webdav-tunnel/archive/refs/heads/main.tar.gz" in u
                for u in urls)
        )

    def test_recommended_manual_path_is_root(self):
        from vless_installer.modules.webdav_mirrors import recommended_manual_path
        self.assertEqual(recommended_manual_path(), Path("/root"))


# ============================================================================
#  WEBDAV_SOURCE_SPEC — sanity-проверки
# ============================================================================
class TestWebdavSourceSpecSanity(unittest.TestCase):
    """WEBDAV_SOURCE_SPEC — инварианты PackageSpec."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_name_is_webdav_tunnel_source(self):
        from vless_installer.modules.webdav_packages import WEBDAV_SOURCE_SPEC
        self.assertEqual(WEBDAV_SOURCE_SPEC.name, "webdav-tunnel source")

    def test_filename_is_main_tarball(self):
        from vless_installer.modules.webdav_packages import WEBDAV_SOURCE_SPEC
        self.assertEqual(
            WEBDAV_SOURCE_SPEC.filename_builder(),
            "webdav-tunnel-main.tar.gz",
        )

    def test_manual_dir_is_root(self):
        from vless_installer.modules.webdav_packages import WEBDAV_SOURCE_SPEC
        self.assertEqual(WEBDAV_SOURCE_SPEC.manual_incoming_dir, Path("/root"))

    def test_manual_dir_not_in_install_dests(self):
        """КРИТИЧЕСКИЙ ИНВАРИАНТ (баг 21d7baf)."""
        from vless_installer.modules.webdav_packages import WEBDAV_SOURCE_SPEC
        for dest in WEBDAV_SOURCE_SPEC.install_dests:
            self.assertNotEqual(WEBDAV_SOURCE_SPEC.manual_incoming_dir, dest)

    def test_min_size_is_1kb(self):
        from vless_installer.modules.webdav_packages import WEBDAV_SOURCE_SPEC
        self.assertEqual(WEBDAV_SOURCE_SPEC.min_size, 1000)

    def test_post_install_is_set(self):
        from vless_installer.modules.webdav_packages import WEBDAV_SOURCE_SPEC
        self.assertIsNotNone(WEBDAV_SOURCE_SPEC.post_install)

    def test_mirror_urls_has_9_entries(self):
        from vless_installer.modules.webdav_packages import WEBDAV_SOURCE_SPEC
        urls = WEBDAV_SOURCE_SPEC.mirror_urls_builder(
            filename="webdav-tunnel-main.tar.gz",
        )
        self.assertEqual(len(urls), 9)


# ============================================================================
#  post_install — проверка extract + build для wdtt/webdav
# ============================================================================
class TestPostInstallArchiveHandling(unittest.TestCase):
    """post_install для WDTT/WEBDAV — проверка обработки tarball'а.

    Реальная сборка (go build) требует Go toolchain и исходников — в unit-тестах
    это дорого. Поэтому тестируем только негативные сценарии:
      • post_install возвращает False если tarball битый (не tar.gz)
      • post_install возвращает False если tarball пустой
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_wdtt_post_install_returns_false_on_non_tarball(self):
        """post_install WDTT возвращает False на не-tar.gz файле."""
        from vless_installer.modules.wdtt_packages import WDTT_SOURCE_SPEC

        # Создаём файл который не tar.gz
        src = self._tmpdir / "fake.tar.gz"
        src.write_bytes(b"not a tarball" * 100)

        install_dir = self._tmpdir / "install"
        ok = WDTT_SOURCE_SPEC.post_install(src, [install_dir])
        self.assertFalse(ok)

    def test_webdav_post_install_returns_false_on_non_tarball(self):
        """post_install WEBDAV возвращает False на не-tar.gz файле."""
        from vless_installer.modules.webdav_packages import WEBDAV_SOURCE_SPEC

        src = self._tmpdir / "fake.tar.gz"
        src.write_bytes(b"not a tarball" * 100)

        install_dir = self._tmpdir / "install"
        ok = WEBDAV_SOURCE_SPEC.post_install(src, [install_dir])
        self.assertFalse(ok)

    def test_wdtt_post_install_returns_false_on_empty_file(self):
        """post_install WDTT возвращает False на пустом файле."""
        from vless_installer.modules.wdtt_packages import WDTT_SOURCE_SPEC

        src = self._tmpdir / "empty.tar.gz"
        src.write_bytes(b"")

        install_dir = self._tmpdir / "install"
        ok = WDTT_SOURCE_SPEC.post_install(src, [install_dir])
        self.assertFalse(ok)

    def test_webdav_post_install_returns_false_on_empty_file(self):
        from vless_installer.modules.webdav_packages import WEBDAV_SOURCE_SPEC

        src = self._tmpdir / "empty.tar.gz"
        src.write_bytes(b"")

        install_dir = self._tmpdir / "install"
        ok = WEBDAV_SOURCE_SPEC.post_install(src, [install_dir])
        self.assertFalse(ok)


# ============================================================================
#  post_install GO_TOOLCHAIN — проверка extract
# ============================================================================
class TestPostInstallGoToolchain(unittest.TestCase):
    """post_install для GO_TOOLCHAIN — распаковка в /usr/local/go.

    Реальная распаковка Go toolchain требует sudo и ~70 MB tarball — в unit-тестах
    это дорого и разрушительно для системы. Поэтому тестируем только негативные
    сценарии (битый tarball → False).
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_post_install_returns_false_on_non_tarball(self):
        """post_install GO_TOOLCHAIN возвращает False на не-tar.gz файле."""
        from vless_installer.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC

        src = self._tmpdir / "fake-go.tar.gz"
        src.write_bytes(b"not a go tarball" * 100)

        # post_install игнорирует install_dests — передаём пустой список
        ok = GO_TOOLCHAIN_SPEC.post_install(src, [])
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)
