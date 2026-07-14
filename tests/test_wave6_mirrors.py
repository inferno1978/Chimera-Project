#!/usr/bin/env python3
"""
tests/test_wave6_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для mirror-реестров и specs Волны 6 (awg_transport + olcrtc):
  • awg_transport_mirrors.py + awg_transport_packages.py
    (AWG_TOOLS_SPEC, AWG_GO_SOURCE_SPEC, AWG_KMOD_SOURCE_SPEC)
  • olcrtc_mirrors.py + olcrtc_packages.py (OLCRTC_SOURCE_SPEC)

Покрывает Variant A (HTTP tarball вместо git clone) для всех 3 git-clone
случаев + amneziawg-tools zip.
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
#  awg_transport_mirrors
# ============================================================================
class TestAwgTransportMirrors(unittest.TestCase):
    """awg_transport_mirrors — зеркала для 3 артефактов."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_awg_tools_mirrors_count(self):
        from chimera.modules.awg_transport_mirrors import (
            get_amneziawg_tools_mirrors, AWG_TOOLS_MIRRORS_COUNT,
        )
        urls = get_amneziawg_tools_mirrors(tag="v1.0.0", arch="amd64")
        self.assertEqual(len(urls), 14)
        self.assertEqual(AWG_TOOLS_MIRRORS_COUNT, 14)

    def test_awg_go_source_mirrors_count(self):
        from chimera.modules.awg_transport_mirrors import (
            get_amneziawg_go_source_mirrors, AWG_GO_SOURCE_MIRRORS_COUNT,
        )
        urls = get_amneziawg_go_source_mirrors()
        self.assertEqual(len(urls), 9)
        self.assertEqual(AWG_GO_SOURCE_MIRRORS_COUNT, 9)

    def test_awg_kmod_source_mirrors_count(self):
        from chimera.modules.awg_transport_mirrors import (
            get_amneziawg_kmod_source_mirrors, AWG_KMOD_SOURCE_MIRRORS_COUNT,
        )
        urls = get_amneziawg_kmod_source_mirrors()
        self.assertEqual(len(urls), 9)
        self.assertEqual(AWG_KMOD_SOURCE_MIRRORS_COUNT, 9)

    def test_all_urls_are_https(self):
        from chimera.modules.awg_transport_mirrors import (
            get_amneziawg_tools_mirrors, get_amneziawg_go_source_mirrors,
            get_amneziawg_kmod_source_mirrors,
        )
        for url in get_amneziawg_tools_mirrors(tag="v1.0.0", arch="amd64"):
            self.assertEqual(urlparse(url).scheme, "https")
        for url in get_amneziawg_go_source_mirrors():
            self.assertEqual(urlparse(url).scheme, "https")
        for url in get_amneziawg_kmod_source_mirrors():
            self.assertEqual(urlparse(url).scheme, "https")

    def test_awg_tools_urls_contain_repo_tag_filename(self):
        from chimera.modules.awg_transport_mirrors import get_amneziawg_tools_mirrors
        for url in get_amneziawg_tools_mirrors(tag="v1.0.0", arch="amd64"):
            self.assertIn("amnezia-vpn", url)
            self.assertIn("amneziawg-tools", url)
            self.assertIn("v1.0.0", url)
            self.assertIn("ubuntu-22.04-amneziawg-tools.zip", url)

    def test_awg_go_source_urls_contain_repo_and_branch(self):
        from chimera.modules.awg_transport_mirrors import get_amneziawg_go_source_mirrors
        for url in get_amneziawg_go_source_mirrors():
            self.assertIn("amnezia-vpn", url)
            self.assertIn("amneziawg-go", url)
            self.assertIn("master", url)

    def test_awg_kmod_source_urls_contain_repo_and_branch(self):
        from chimera.modules.awg_transport_mirrors import get_amneziawg_kmod_source_mirrors
        for url in get_amneziawg_kmod_source_mirrors():
            self.assertIn("amnezia-vpn", url)
            self.assertIn("amneziawg-linux-kernel-module", url)
            self.assertIn("master", url)

    def test_awg_tools_arm64_filename(self):
        from chimera.modules.awg_transport_mirrors import get_amneziawg_tools_mirrors
        for url in get_amneziawg_tools_mirrors(tag="v1.0.0", arch="arm64"):
            self.assertIn("ubuntu-22.04-arm64-amneziawg-tools.zip", url)

    def test_empty_tag_returns_empty(self):
        from chimera.modules.awg_transport_mirrors import get_amneziawg_tools_mirrors
        self.assertEqual(get_amneziawg_tools_mirrors(tag="", arch="amd64"), [])

    def test_recommended_manual_path_is_root(self):
        from chimera.modules.awg_transport_mirrors import recommended_manual_path
        self.assertEqual(recommended_manual_path(), Path("/root"))


# ============================================================================
#  AWG_TOOLS_SPEC / AWG_GO_SOURCE_SPEC / AWG_KMOD_SOURCE_SPEC
# ============================================================================
class TestAwgSpecsSanity(unittest.TestCase):
    """Sanity-проверки AWG specs."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_awg_tools_spec_name(self):
        from chimera.modules.awg_transport_packages import AWG_TOOLS_SPEC
        self.assertEqual(AWG_TOOLS_SPEC.name, "amneziawg-tools")

    def test_awg_go_source_spec_name(self):
        from chimera.modules.awg_transport_packages import AWG_GO_SOURCE_SPEC
        self.assertEqual(AWG_GO_SOURCE_SPEC.name, "amneziawg-go source")

    def test_awg_kmod_source_spec_name(self):
        from chimera.modules.awg_transport_packages import AWG_KMOD_SOURCE_SPEC
        self.assertEqual(AWG_KMOD_SOURCE_SPEC.name, "amneziawg-kernel-module source")

    def test_all_specs_manual_dir_is_root(self):
        from chimera.modules.awg_transport_packages import (
            AWG_TOOLS_SPEC, AWG_GO_SOURCE_SPEC, AWG_KMOD_SOURCE_SPEC,
        )
        for spec in (AWG_TOOLS_SPEC, AWG_GO_SOURCE_SPEC, AWG_KMOD_SOURCE_SPEC):
            self.assertEqual(spec.manual_incoming_dir, Path("/root"))

    def test_all_specs_manual_dir_not_in_install_dests(self):
        """КРИТИЧЕСКИЙ ИНВАРИАНТ (баг 21d7baf)."""
        from chimera.modules.awg_transport_packages import (
            AWG_TOOLS_SPEC, AWG_GO_SOURCE_SPEC, AWG_KMOD_SOURCE_SPEC,
        )
        for spec in (AWG_TOOLS_SPEC, AWG_GO_SOURCE_SPEC, AWG_KMOD_SOURCE_SPEC):
            for dest in spec.install_dests:
                self.assertNotEqual(spec.manual_incoming_dir, dest)

    def test_all_specs_post_install_set(self):
        from chimera.modules.awg_transport_packages import (
            AWG_TOOLS_SPEC, AWG_GO_SOURCE_SPEC, AWG_KMOD_SOURCE_SPEC,
        )
        for spec in (AWG_TOOLS_SPEC, AWG_GO_SOURCE_SPEC, AWG_KMOD_SOURCE_SPEC):
            self.assertIsNotNone(spec.post_install)

    def test_awg_tools_filename_builder(self):
        from chimera.modules.awg_transport_packages import AWG_TOOLS_SPEC
        self.assertEqual(
            AWG_TOOLS_SPEC.filename_builder(tag="v1.0.0", arch="amd64"),
            "ubuntu-22.04-amneziawg-tools.zip",
        )
        self.assertEqual(
            AWG_TOOLS_SPEC.filename_builder(tag="v1.0.0", arch="arm64"),
            "ubuntu-22.04-arm64-amneziawg-tools.zip",
        )

    def test_awg_go_source_filename(self):
        from chimera.modules.awg_transport_packages import AWG_GO_SOURCE_SPEC
        self.assertEqual(
            AWG_GO_SOURCE_SPEC.filename_builder(),
            "amneziawg-go-master.tar.gz",
        )

    def test_awg_kmod_source_filename(self):
        from chimera.modules.awg_transport_packages import AWG_KMOD_SOURCE_SPEC
        self.assertEqual(
            AWG_KMOD_SOURCE_SPEC.filename_builder(),
            "amneziawg-linux-kernel-module-master.tar.gz",
        )


# ============================================================================
#  post_install — негативные сценарии
# ============================================================================
class TestAwgPostInstallNegative(unittest.TestCase):
    """post_install AWG specs — негативные сценарии."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_awg_tools_post_install_returns_false_on_non_zip(self):
        from chimera.modules.awg_transport_packages import AWG_TOOLS_SPEC
        src = self._tmpdir / "fake.zip"
        src.write_bytes(b"not a zip" * 100)
        ok = AWG_TOOLS_SPEC.post_install(src, [self._tmpdir / "install"])
        self.assertFalse(ok)

    def test_awg_go_source_post_install_returns_false_on_non_tarball(self):
        from chimera.modules.awg_transport_packages import AWG_GO_SOURCE_SPEC
        src = self._tmpdir / "fake.tar.gz"
        src.write_bytes(b"not a tarball" * 100)
        ok = AWG_GO_SOURCE_SPEC.post_install(src, [self._tmpdir / "install"])
        self.assertFalse(ok)

    def test_awg_kmod_source_post_install_returns_false_on_non_tarball(self):
        from chimera.modules.awg_transport_packages import AWG_KMOD_SOURCE_SPEC
        src = self._tmpdir / "fake.tar.gz"
        src.write_bytes(b"not a tarball" * 100)
        ok = AWG_KMOD_SOURCE_SPEC.post_install(src, [self._tmpdir / "install"])
        self.assertFalse(ok)


# ============================================================================
#  olcrtc_mirrors
# ============================================================================
class TestOlcrtcMirrors(unittest.TestCase):
    """olcrtc_mirrors — 9 зеркал для source tarball."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_9_urls(self):
        from chimera.modules.olcrtc_mirrors import (
            get_olcrtc_source_mirrors, OLCRTC_SOURCE_MIRRORS_COUNT,
        )
        urls = get_olcrtc_source_mirrors()
        self.assertEqual(len(urls), 9)
        self.assertEqual(OLCRTC_SOURCE_MIRRORS_COUNT, 9)

    def test_all_urls_are_https(self):
        from chimera.modules.olcrtc_mirrors import get_olcrtc_source_mirrors
        for url in get_olcrtc_source_mirrors():
            self.assertEqual(urlparse(url).scheme, "https")

    def test_all_urls_contain_repo_and_branch(self):
        from chimera.modules.olcrtc_mirrors import get_olcrtc_source_mirrors
        for url in get_olcrtc_source_mirrors():
            self.assertIn("openlibrecommunity", url)
            self.assertIn("olcrtc", url)
            self.assertIn("master", url)

    def test_has_codeload_url(self):
        from chimera.modules.olcrtc_mirrors import get_olcrtc_source_mirrors
        urls = get_olcrtc_source_mirrors()
        self.assertTrue(any("codeload.github.com" in u for u in urls))

    def test_commits_api_url(self):
        """get_olcrtc_commits_api_url возвращает GitHub API URL для /commits/master."""
        from chimera.modules.olcrtc_mirrors import get_olcrtc_commits_api_url
        api_url = get_olcrtc_commits_api_url()
        self.assertIn("api.github.com", api_url)
        self.assertIn("openlibrecommunity", api_url)
        self.assertIn("olcrtc", api_url)
        self.assertIn("commits/master", api_url)

    def test_recommended_manual_path_is_root(self):
        from chimera.modules.olcrtc_mirrors import recommended_manual_path
        self.assertEqual(recommended_manual_path(), Path("/root"))


class TestOlcrtcSpecSanity(unittest.TestCase):
    """Sanity-проверки OLCRTC_SOURCE_SPEC."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_name_is_olcrtc_source(self):
        from chimera.modules.olcrtc_packages import OLCRTC_SOURCE_SPEC
        self.assertEqual(OLCRTC_SOURCE_SPEC.name, "olcrtc source")

    def test_filename_is_olcrtc_master_tarball(self):
        from chimera.modules.olcrtc_packages import OLCRTC_SOURCE_SPEC
        self.assertEqual(
            OLCRTC_SOURCE_SPEC.filename_builder(),
            "olcrtc-master.tar.gz",
        )

    def test_install_dests_is_usr_local_bin(self):
        from chimera.modules.olcrtc_packages import OLCRTC_SOURCE_SPEC
        self.assertEqual(OLCRTC_SOURCE_SPEC.install_dests, [Path("/usr/local/bin")])

    def test_manual_dir_is_root(self):
        from chimera.modules.olcrtc_packages import OLCRTC_SOURCE_SPEC
        self.assertEqual(OLCRTC_SOURCE_SPEC.manual_incoming_dir, Path("/root"))

    def test_manual_dir_not_in_install_dests(self):
        from chimera.modules.olcrtc_packages import OLCRTC_SOURCE_SPEC
        for dest in OLCRTC_SOURCE_SPEC.install_dests:
            self.assertNotEqual(OLCRTC_SOURCE_SPEC.manual_incoming_dir, dest)

    def test_post_install_is_set(self):
        from chimera.modules.olcrtc_packages import OLCRTC_SOURCE_SPEC
        self.assertIsNotNone(OLCRTC_SOURCE_SPEC.post_install)

    def test_post_install_returns_false_on_non_tarball(self):
        import tempfile
        from chimera.modules.olcrtc_packages import OLCRTC_SOURCE_SPEC
        tmpdir = Path(tempfile.mkdtemp())
        try:
            src = tmpdir / "fake.tar.gz"
            src.write_bytes(b"not a tarball" * 100)
            ok = OLCRTC_SOURCE_SPEC.post_install(src, [tmpdir / "install"])
            self.assertFalse(ok)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


# ============================================================================
#  olcrtc._olcrtc_fetch_commit_sha — миграция на GitHub API
# ============================================================================
class TestOlcrtcCommitShaMigrated(unittest.TestCase):
    """_olcrtc_fetch_commit_sha — GitHub API вместо git rev-parse."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_sha_from_api(self):
        """SHA получается из GitHub API ответа."""
        import json
        from chimera.modules import olcrtc

        # Мокаем _http_get_text чтобы вернуть JSON с SHA
        api_response = json.dumps({"sha": "ad5758513335cda54362a64621c29e9d9fe759b4"})
        with patch.object(olcrtc, "_http_get_text", return_value=api_response):
            sha = olcrtc._olcrtc_fetch_commit_sha()
        self.assertEqual(sha, "ad57585")  # первые 7 символов

    def test_returns_question_on_api_failure(self):
        """При ошибке API — fallback на '?'."""
        from chimera.modules import olcrtc
        with patch.object(olcrtc, "_http_get_text", return_value=None):
            sha = olcrtc._olcrtc_fetch_commit_sha()
        self.assertEqual(sha, "?")

    def test_returns_question_on_invalid_json(self):
        from chimera.modules import olcrtc
        with patch.object(olcrtc, "_http_get_text", return_value="not json"):
            sha = olcrtc._olcrtc_fetch_commit_sha()
        self.assertEqual(sha, "?")

    def test_returns_question_on_missing_sha_field(self):
        import json
        from chimera.modules import olcrtc
        api_response = json.dumps({"message": "Not Found"})
        with patch.object(olcrtc, "_http_get_text", return_value=api_response):
            sha = olcrtc._olcrtc_fetch_commit_sha()
        self.assertEqual(sha, "?")

    def test_olcrtc_commit_delegates_to_fetch_sha(self):
        """_olcrtc_commit() вызывает _olcrtc_fetch_commit_sha (после миграции)."""
        from chimera.modules import olcrtc
        with patch.object(olcrtc, "_olcrtc_fetch_commit_sha", return_value="abc1234") as mock_sha:
            result = olcrtc._olcrtc_commit()
        self.assertEqual(result, "abc1234")
        mock_sha.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
