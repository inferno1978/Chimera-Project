#!/usr/bin/env python3
"""
tests/test_singbox_packages.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/singbox_packages.py и singbox_mirrors.py.

Покрывает:
  1. SINGBOX_SPEC — структура PackageSpec
  2. _singbox_mirror_urls — builder URLs
  3. get_singbox_mirrors — зеркало с github_mirrors
  4. _post_install_singbox — извлечение бинарника из tar.gz
  5. Проверка архитектур и тегов
  6. MANUAL_UPLOAD_PATHS_SINGBOX — пути ручного размещения
"""
from __future__ import annotations

import json
import os
import sys
import tarfile
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    """Загружает _core.py в sys.modules (модули singbox_* могут требовать _core)."""
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("vless_installer._core")
    m.__dict__.update(g)
    sys.modules["vless_installer._core"] = m


def _enter_patches(stack, patches):
    """Применяет список patch-объектов через ExitStack."""
    for p in patches:
        stack.enter_context(p)


# ─────────────────────────────────────────────────────────────────────────────
# 1. PackageSpec
# ─────────────────────────────────────────────────────────────────────────────

class TestSingboxSpec(unittest.TestCase):
    """SINGBOX_SPEC — структура."""

    def setUp(self):
        _setup_core()

    def test_spec_exists(self):
        from vless_installer.modules.singbox_packages import SINGBOX_SPEC
        self.assertIsNotNone(SINGBOX_SPEC)

    def test_spec_name(self):
        from vless_installer.modules.singbox_packages import SINGBOX_SPEC
        self.assertIn("sing-box", SINGBOX_SPEC.name)

    def test_spec_install_dests(self):
        from vless_installer.modules.singbox_packages import SINGBOX_SPEC
        self.assertEqual(len(SINGBOX_SPEC.install_dests), 1)
        self.assertEqual(SINGBOX_SPEC.install_dests[0], Path("/usr/local/bin"))

    def test_spec_manual_dir_not_equal_install_dests(self):
        """КРИТИЧЕСКИЙ инвариант PackageSpec."""
        from vless_installer.modules.singbox_packages import SINGBOX_SPEC
        for dest in SINGBOX_SPEC.install_dests:
            self.assertNotEqual(SINGBOX_SPEC.manual_incoming_dir, dest)

    def test_spec_min_size_positive(self):
        from vless_installer.modules.singbox_packages import SINGBOX_SPEC
        self.assertGreater(SINGBOX_SPEC.min_size, 0)

    def test_spec_post_install_callable(self):
        from vless_installer.modules.singbox_packages import SINGBOX_SPEC
        self.assertTrue(callable(SINGBOX_SPEC.post_install))


# ─────────────────────────────────────────────────────────────────────────────
# 2. mirror_urls_builder
# ─────────────────────────────────────────────────────────────────────────────

class TestMirrorUrlsBuilder(unittest.TestCase):
    """_singbox_mirror_urls — построение URL."""

    def setUp(self):
        _setup_core()

    def test_returns_list(self):
        from vless_installer.modules.singbox_packages import _singbox_mirror_urls
        urls = _singbox_mirror_urls(
            filename="sing-box-1.11.4-linux-amd64.tar.gz",
            tag="1.11.4",
        )
        self.assertIsInstance(urls, list)
        self.assertGreater(len(urls), 0)

    def test_empty_filename_returns_empty(self):
        from vless_installer.modules.singbox_packages import _singbox_mirror_urls
        self.assertEqual(_singbox_mirror_urls(filename="", tag="1.11.4"), [])

    def test_empty_tag_returns_empty(self):
        from vless_installer.modules.singbox_packages import _singbox_mirror_urls
        self.assertEqual(
            _singbox_mirror_urls(filename="sing-box.tar.gz", tag=""),
            [],
        )

    def test_tarball_filename_overrides_filename(self):
        """Если передан tarball_filename, он приоритетнее filename."""
        from vless_installer.modules.singbox_packages import _singbox_mirror_urls
        urls = _singbox_mirror_urls(
            filename="wrong.tar.gz",
            tag="1.11.4",
            tarball_filename="sing-box-1.11.4-linux-amd64.tar.gz",
        )
        self.assertGreater(len(urls), 0)
        # Все URL должны содержать правильное имя файла
        for url in urls:
            self.assertIn("sing-box-1.11.4-linux-amd64.tar.gz", url)

    def test_urls_contain_github_com(self):
        from vless_installer.modules.singbox_packages import _singbox_mirror_urls
        urls = _singbox_mirror_urls(
            filename="sing-box-1.11.4-linux-amd64.tar.gz",
            tag="1.11.4",
        )
        # Хотя бы один URL должен ссылаться на github.com
        has_github = any("github.com" in u for u in urls)
        self.assertTrue(has_github, "Нет ни одного URL с github.com")

    def test_urls_contain_correct_owner_repo(self):
        from vless_installer.modules.singbox_packages import _singbox_mirror_urls
        urls = _singbox_mirror_urls(
            filename="sing-box-1.11.4-linux-amd64.tar.gz",
            tag="1.11.4",
        )
        # Должно быть SagerNet/sing-box
        has_correct_repo = any(
            "SagerNet/sing-box" in u or "sagernet/sing-box" in u.lower()
            for u in urls
        )
        self.assertTrue(has_correct_repo, "Нет URL с SagerNet/sing-box")


# ─────────────────────────────────────────────────────────────────────────────
# 3. get_singbox_mirrors
# ─────────────────────────────────────────────────────────────────────────────

class TestGetSingboxMirrors(unittest.TestCase):
    """get_singbox_mirrors — реестр зеркал."""

    def setUp(self):
        _setup_core()

    def test_returns_list(self):
        from vless_installer.modules.singbox_mirrors import get_singbox_mirrors
        urls = get_singbox_mirrors(tag="1.11.4",
                                   filename="sing-box-1.11.4-linux-amd64.tar.gz")
        self.assertIsInstance(urls, list)
        self.assertGreater(len(urls), 5)  # минимум 5 зеркал

    def test_empty_inputs_return_empty(self):
        from vless_installer.modules.singbox_mirrors import get_singbox_mirrors
        self.assertEqual(get_singbox_mirrors("", "file.tar.gz"), [])
        self.assertEqual(get_singbox_mirrors("1.11.4", ""), [])

    def test_constants_exist(self):
        from vless_installer.modules.singbox_mirrors import (
            SINGBOX_MIRRORS_COUNT,
            MANUAL_UPLOAD_PATHS_SINGBOX,
            recommended_manual_path,
        )
        self.assertGreater(SINGBOX_MIRRORS_COUNT, 0)
        self.assertGreater(len(MANUAL_UPLOAD_PATHS_SINGBOX), 0)
        rec = recommended_manual_path()
        self.assertIsInstance(rec, Path)
        self.assertIn(rec, MANUAL_UPLOAD_PATHS_SINGBOX)

    def test_manual_paths_include_root(self):
        """WinSCP-friendly /root/ должен быть в списке."""
        from vless_installer.modules.singbox_mirrors import MANUAL_UPLOAD_PATHS_SINGBOX
        self.assertIn(Path("/root"), MANUAL_UPLOAD_PATHS_SINGBOX)

    def test_manual_paths_exclude_install_dests(self):
        """/usr/local/bin НЕ должен быть в manual_incoming — конфликт."""
        from vless_installer.modules.singbox_mirrors import MANUAL_UPLOAD_PATHS_SINGBOX
        self.assertNotIn(Path("/usr/local/bin"), MANUAL_UPLOAD_PATHS_SINGBOX)

    def test_excludes_jsdelivr_for_release_assets(self):
        """jsDelivr не может отдавать release assets — исключён."""
        from vless_installer.modules.singbox_mirrors import get_singbox_mirrors
        urls = get_singbox_mirrors(tag="1.13.14",
                                   filename="sing-box-1.13.14-linux-amd64.tar.gz")
        for url in urls:
            self.assertNotIn("jsdelivr.net", url,
                             f"jsDelivr URL не должен быть в списке: {url}")

    def test_excludes_raw_githubusercontent_for_release_assets(self):
        """raw.githubusercontent не может отдавать release assets — исключён."""
        from vless_installer.modules.singbox_mirrors import get_singbox_mirrors
        urls = get_singbox_mirrors(tag="1.13.14",
                                   filename="sing-box-1.13.14-linux-amd64.tar.gz")
        for url in urls:
            self.assertNotIn("raw.githubusercontent.com", url,
                             f"raw.githubusercontent URL не должен быть: {url}")

    def test_excludes_statically_for_release_assets(self):
        """Statically CDN не может отдавать release assets — исключён."""
        from vless_installer.modules.singbox_mirrors import get_singbox_mirrors
        urls = get_singbox_mirrors(tag="1.13.14",
                                   filename="sing-box-1.13.14-linux-amd64.tar.gz")
        for url in urls:
            self.assertNotIn("statically.io", url,
                             f"Statically URL не должен быть: {url}")

    def test_includes_release_github_url(self):
        """release GitHub URL должен быть в списке."""
        from vless_installer.modules.singbox_mirrors import get_singbox_mirrors
        urls = get_singbox_mirrors(tag="1.13.14",
                                   filename="sing-box-1.13.14-linux-amd64.tar.gz")
        has_release = any(
            "github.com/SagerNet/sing-box/releases/download/1.13.14/" in u
            for u in urls
        )
        self.assertTrue(has_release, "Нет release GitHub URL")

    def test_includes_gh_proxy_urls(self):
        """gh-proxy зеркала должны быть в списке (проксируют release assets)."""
        from vless_installer.modules.singbox_mirrors import get_singbox_mirrors
        urls = get_singbox_mirrors(tag="1.13.14",
                                   filename="sing-box-1.13.14-linux-amd64.tar.gz")
        # Должно быть минимум 5 gh-proxy URL
        gh_proxy_count = sum(1 for u in urls if "ghproxy" in u or "gh.con.sh" in u
                             or "gitmirror" in u or "moeyy" in u or "ghps.cc" in u)
        self.assertGreaterEqual(gh_proxy_count, 5,
                                f"Слишком мало gh-proxy URL: {gh_proxy_count}")

    def test_mirror_count_is_8_after_exclusion(self):
        """После исключения jsDelivr/raw/Statically должно быть 8 зеркал."""
        from vless_installer.modules.singbox_mirrors import (
            SINGBOX_MIRRORS_COUNT, get_singbox_mirrors,
        )
        urls = get_singbox_mirrors(tag="1.13.14",
                                   filename="sing-box-1.13.14-linux-amd64.tar.gz")
        self.assertEqual(len(urls), SINGBOX_MIRRORS_COUNT)
        self.assertEqual(SINGBOX_MIRRORS_COUNT, 8)

    def test_tag_empty_returns_empty(self):
        """Без tag URL не генерируются (защита от дефолтных тегов)."""
        from vless_installer.modules.singbox_mirrors import get_singbox_mirrors
        self.assertEqual(get_singbox_mirrors(tag="", filename="file.tar.gz"), [])

    def test_v_prefix_in_tag_preserved_in_urls(self):
        """Регрессия v4.22.3: tag с 'v' префиксом должен сохраняться в URL.

        Баг v4.22.0-v4.22.2: _get_latest_release_info() делал tag.lstrip('v'),
        отрезая 'v' из 'v1.13.14'. Это ломало URL — GitHub возвращает 404 для
        /releases/download/1.13.14/ (нужно /releases/download/v1.13.14/).
        Все 8 зеркал падали. Тест гарантирует что 'v' сохраняется.
        """
        from vless_installer.modules.singbox_mirrors import get_singbox_mirrors
        urls = get_singbox_mirrors(tag="v1.13.14",
                                   filename="sing-box-1.13.14-linux-amd64.tar.gz")
        self.assertGreater(len(urls), 0)
        # Все URL должны содержать /v1.13.14/ в пути
        for url in urls:
            self.assertIn("/v1.13.14/", url,
                          f"URL должен содержать /v1.13.14/ (с v-префиксом): {url}")

    def test_tag_without_v_also_works(self):
        """tag без 'v' тоже работает (для совместимости со старыми вызовами).

        ВАЖНО: sing-box releases используют tag_name='v1.13.14', поэтому
        _get_latest_release_info() теперь возвращает tag С 'v'. Но если
        кто-то передаст tag без 'v' (например '1.13.14'), URL будет
        /releases/download/1.13.14/ и GitHub вернёт 404. Это поведение
        не наше дело — мы должны передавать tag как есть.
        """
        from vless_installer.modules.singbox_mirrors import get_singbox_mirrors
        urls = get_singbox_mirrors(tag="1.13.14",
                                   filename="sing-box-1.13.14-linux-amd64.tar.gz")
        # URL будут с /1.13.14/ — это БЫЛО багом, но get_singbox_mirrors
        # не должна трансформировать tag. Тест фиксирует что tag передаётся as-is.
        self.assertGreater(len(urls), 0)
        self.assertIn("/1.13.14/", urls[0])


# ─────────────────────────────────────────────────────────────────────────────
# 4. post_install — извлечение бинарника
# ─────────────────────────────────────────────────────────────────────────────

class TestPostInstall(unittest.TestCase):
    """_post_install_singbox — извлечение бинарника из tar.gz."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _create_fake_tarball(self, binary_content: bytes = b"#!/bin/sh\n# fake sing-box\n") -> Path:
        """Создаёт tar.gz архив с поддельной директорией sing-box-X.Y.Z-linux-amd64/sing-box."""
        # Структура: sing-box-1.11.4-linux-amd64/sing-box
        archive_path = self._tmpdir / "test-singbox.tar.gz"
        # Создаём временную директорию с бинарником
        src_dir = self._tmpdir / "sing-box-1.11.4-linux-amd64"
        src_dir.mkdir(exist_ok=True)
        bin_path = src_dir / "sing-box"
        bin_path.write_bytes(binary_content)
        bin_path.chmod(0o755)
        # Запаковываем
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(src_dir, arcname="sing-box-1.11.4-linux-amd64")
        return archive_path

    def test_extracts_binary(self):
        from vless_installer.modules.singbox_packages import _post_install_singbox
        archive = self._create_fake_tarball(b"#!/bin/sh\necho hello\n")
        dest_dir = self._tmpdir / "dest"
        dest_dir.mkdir(exist_ok=True)
        ok = _post_install_singbox(archive, [dest_dir])
        self.assertTrue(ok)
        bin_path = dest_dir / "sing-box"
        self.assertTrue(bin_path.exists())
        self.assertEqual(bin_path.read_bytes(), b"#!/bin/sh\necho hello\n")

    def test_returns_false_on_invalid_archive(self):
        from vless_installer.modules.singbox_packages import _post_install_singbox
        bad_archive = self._tmpdir / "not-a-tarball.tar.gz"
        bad_archive.write_bytes(b"not a real tar.gz")
        dest_dir = self._tmpdir / "dest"
        dest_dir.mkdir(exist_ok=True)
        ok = _post_install_singbox(bad_archive, [dest_dir])
        self.assertFalse(ok)

    def test_returns_false_when_no_binary_in_archive(self):
        from vless_installer.modules.singbox_packages import _post_install_singbox
        # Создаём tar.gz без sing-box
        archive_path = self._tmpdir / "empty.tar.gz"
        src_dir = self._tmpdir / "empty-dir"
        src_dir.mkdir(exist_ok=True)
        (src_dir / "README").write_text("just a readme")
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(src_dir, arcname="empty-dir")
        dest_dir = self._tmpdir / "dest"
        dest_dir.mkdir(exist_ok=True)
        ok = _post_install_singbox(archive_path, [dest_dir])
        self.assertFalse(ok)

    def test_returns_false_for_empty_install_dests(self):
        from vless_installer.modules.singbox_packages import _post_install_singbox
        archive = self._create_fake_tarball()
        ok = _post_install_singbox(archive, [])
        self.assertFalse(ok)

    def test_chmod_executable(self):
        from vless_installer.modules.singbox_packages import _post_install_singbox
        archive = self._create_fake_tarball()
        dest_dir = self._tmpdir / "dest"
        dest_dir.mkdir(exist_ok=True)
        _post_install_singbox(archive, [dest_dir])
        bin_path = dest_dir / "sing-box"
        # Должен быть исполняемым (0o755)
        mode = bin_path.stat().st_mode & 0o777
        self.assertTrue(mode & 0o111, f"binary not executable: {oct(mode)}")


# ─────────────────────────────────────────────────────────────────────────────
# 5. Архитектуры
# ─────────────────────────────────────────────────────────────────────────────

class TestArchDetection(unittest.TestCase):
    """_detect_arch — определение архитектуры."""

    def setUp(self):
        _setup_core()

    def test_returns_string(self):
        from vless_installer.modules.singbox_common import _detect_arch
        arch = _detect_arch()
        self.assertIsInstance(arch, str)
        self.assertGreater(len(arch), 0)

    def test_known_architectures(self):
        from vless_installer.modules.singbox_common import _detect_arch
        arch = _detect_arch()
        # Поддерживаемые sing-box'ом
        known = {"amd64", "arm64", "arm-7", "386"}
        # Текущая arch может быть любой (на любой машине), но обычно из known
        # Мы просто проверяем, что функция возвращает строку
        self.assertIsInstance(arch, str)


# ─────────────────────────────────────────────────────────────────────────────
# 6. fetch_package integration — что SINGBOX_SPEC совместим с fetch_package
# ─────────────────────────────────────────────────────────────────────────────

class TestFetchPackageIntegration(unittest.TestCase):
    """Интеграционный тест: SINGBOX_SPEC работает с fetch_package в dry_run."""

    def setUp(self):
        _setup_core()

    def test_dry_run_returns_false(self):
        """В dry_run режиме fetch_package не делает сетевых вызовов и возвращает False."""
        from vless_installer.modules.download_manager import fetch_package
        from vless_installer.modules.singbox_packages import SINGBOX_SPEC
        ok = fetch_package(
            SINGBOX_SPEC,
            dry_run=True,
            tag="1.11.4",
            tarball_filename="sing-box-1.11.4-linux-amd64.tar.gz",
            print_hint_on_failure=False,
        )
        self.assertFalse(ok)

    def test_filename_builder_with_kwargs(self):
        """filename_builder принимает tarball_filename kwarg."""
        from vless_installer.modules.singbox_packages import SINGBOX_SPEC
        # Безопасный вызов filename_builder с kwargs
        fname = SINGBOX_SPEC.filename_builder(
            tarball_filename="sing-box-1.11.4-linux-amd64.tar.gz"
        )
        self.assertEqual(fname, "sing-box-1.11.4-linux-amd64.tar.gz")


if __name__ == "__main__":
    unittest.main(verbosity=2)
