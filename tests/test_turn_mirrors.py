#!/usr/bin/env python3
"""
tests/test_turn_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/turn_mirrors.py и turn_packages.py.

Покрывает:
  • Структуру и инварианты списка зеркал для vk-turn-proxy и turnable
  • Корректность URL-шаблонов (jsDelivr CDN + release GitHub + 7 gh-proxy)
  • Что /root/ — первый в MANUAL_UPLOAD_PATHS (рекомендуемый для WinSCP)
  • Что manual_incoming_dir в PackageSpec'ах указывает на /root/
  • КРИТИЧЕСКИЙ ИНВАРИАНТ: manual_incoming_dir != install_dests (защита от
    бага 21d7baf)
  • Что все URL — HTTPS
  • Что URL содержат правильный filename и (для turnable) версию
  • Что post_install корректно копирует ELF-бинарник и отказывает на не-ELF
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
    """Подстановка фейкового _core в sys.modules — как в остальных тестах."""
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


from chimera.modules.turn_mirrors import (
    get_turntunnel_mirrors,
    get_turnable_mirrors,
    MANUAL_UPLOAD_PATHS_TURNTUNNEL,
    MANUAL_UPLOAD_PATHS_TURNABLE,
    TURNTUNNEL_MIRRORS_COUNT,
    TURNABLE_MIRRORS_COUNT,
    recommended_manual_path,
)
from chimera.modules.turn_packages import (
    TURNTUNNEL_SPEC,
    TURNABLE_SPEC,
)


# ============================================================================
#  Структура списков зеркал
# ============================================================================
class TestMirrorListStructure(unittest.TestCase):
    """Структура и инварианты списков зеркал."""

    def test_turntunnel_urls_non_empty(self):
        urls = get_turntunnel_mirrors()
        self.assertGreater(len(urls), 0)

    def test_turnable_urls_non_empty(self):
        urls = get_turnable_mirrors("0.4.1")
        self.assertGreater(len(urls), 0)

    def test_turntunnel_count_matches_list_length(self):
        self.assertEqual(TURNTUNNEL_MIRRORS_COUNT, len(get_turntunnel_mirrors()))

    def test_turnable_count_matches_list_length(self):
        # TURNABLE_MIRRORS_COUNT захардкожен для версии "0.4.1" на module-load
        self.assertEqual(TURNABLE_MIRRORS_COUNT, len(get_turnable_mirrors("0.4.1")))

    def test_turntunnel_at_least_5_mirrors(self):
        """Минимум 5 зеркал: 4 jsDelivr + release GitHub + gh-proxy (минимум 1).
        Реально 12: 4 jsDelivr + release GitHub + 7 gh-proxy = 12 (raw GitHub
        и Statically отключены для tag=latest, т.к. ветки "latest" не существует)."""
        self.assertGreaterEqual(TURNTUNNEL_MIRRORS_COUNT, 5)

    def test_turnable_at_least_5_mirrors(self):
        """Минимум 5 зеркал: 4 jsDelivr + release GitHub + gh-proxy (минимум 1).
        Реально 13: 4 jsDelivr + 1 raw (отключен для tag-ветки) ... смотрите
        конфигурацию в turn_mirrors.get_turnable_mirrors."""
        self.assertGreaterEqual(TURNABLE_MIRRORS_COUNT, 5)


# ============================================================================
#  Корректность URL
# ============================================================================
class TestUrlCorrectness(unittest.TestCase):
    """Все URL — HTTPS, содержат owner/repo/filename."""

    def test_all_turntunnel_urls_are_https(self):
        for url in get_turntunnel_mirrors():
            self.assertEqual(urlparse(url).scheme, "https",
                             f"URL не HTTPS: {url}")

    def test_all_turnable_urls_are_https(self):
        for url in get_turnable_mirrors("0.4.1"):
            self.assertEqual(urlparse(url).scheme, "https",
                             f"URL не HTTPS: {url}")

    def test_turntunnel_urls_contain_repo_and_filename(self):
        """Каждый URL содержит cacggghp/vk-turn-proxy и server-linux-amd64."""
        for url in get_turntunnel_mirrors():
            self.assertIn("cacggghp", url)
            self.assertIn("vk-turn-proxy", url)
            self.assertIn("server-linux-amd64", url)

    def test_turnable_urls_contain_repo_filename_and_version(self):
        """Каждый URL содержит TheAirBlow/Turnable, turnable-linux-amd64,
        и версию 0.4.1."""
        for url in get_turnable_mirrors("0.4.1"):
            self.assertIn("TheAirBlow", url)
            self.assertIn("Turnable", url)
            self.assertIn("turnable-linux-amd64", url)
            self.assertIn("0.4.1", url)

    def test_turntunnel_urls_contain_latest_release_path(self):
        """Хотя бы один URL использует /releases/latest/download/ — основной
        путь для vk-turn-proxy (никакого pinned tag)."""
        urls = get_turntunnel_mirrors()
        self.assertTrue(
            any("/releases/latest/download/" in u for u in urls),
            f"Ни один URL не содержит /releases/latest/download/: {urls}"
        )

    def test_turnable_urls_contain_pinned_tag_path(self):
        """Хотя бы один URL использует /releases/download/0.4.1/ — pinned tag."""
        urls = get_turnable_mirrors("0.4.1")
        self.assertTrue(
            any("/releases/download/0.4.1/" in u for u in urls),
            f"Ни один URL не содержит /releases/download/0.4.1/: {urls}"
        )

    def test_turntunnel_has_jsdelivr_cdn(self):
        """jsDelivr CDN присутствует (4 бэкенда по умолчанию)."""
        urls = get_turntunnel_mirrors()
        jsdelivr_count = sum(1 for u in urls if "jsdelivr.net" in u)
        self.assertGreaterEqual(jsdelivr_count, 1,
            "Хотя бы один jsDelivr CDN URL должен быть")

    def test_turnable_has_jsdelivr_cdn(self):
        urls = get_turnable_mirrors("0.4.1")
        jsdelivr_count = sum(1 for u in urls if "jsdelivr.net" in u)
        self.assertGreaterEqual(jsdelivr_count, 1)

    def test_turntunnel_has_gh_proxy(self):
        """Хотя бы один GitHub-прокси присутствует (ghproxy.net и т.д.)."""
        urls = get_turntunnel_mirrors()
        # Проверяем по типичным прокси-доменам
        proxy_domains = ["ghproxy", "gh.con.sh", "gitmirror", "moeyy", "ghps.cc"]
        has_proxy = any(any(d in u for d in proxy_domains) for u in urls)
        self.assertTrue(has_proxy, "Ни один gh-proxy URL не найден")


# ============================================================================
#  MANUAL_UPLOAD_PATHS
# ============================================================================
class TestManualUploadPaths(unittest.TestCase):
    """MANUAL_UPLOAD_PATHS — структура и /root/ первый."""

    def test_turntunnel_root_is_first(self):
        """Первый путь — /root/ (рекомендуется для WinSCP)."""
        self.assertEqual(MANUAL_UPLOAD_PATHS_TURNTUNNEL[0], Path("/root"))

    def test_turnable_root_is_first(self):
        self.assertEqual(MANUAL_UPLOAD_PATHS_TURNABLE[0], Path("/root"))

    def test_turntunnel_paths_non_empty(self):
        self.assertGreater(len(MANUAL_UPLOAD_PATHS_TURNTUNNEL), 0)

    def test_turnable_paths_non_empty(self):
        self.assertGreater(len(MANUAL_UPLOAD_PATHS_TURNABLE), 0)

    def test_recommended_manual_path_is_root(self):
        self.assertEqual(recommended_manual_path(), Path("/root"))

    def test_turntunnel_paths_do_not_include_install_dest(self):
        """MANUAL_UPLOAD_PATHS_TURNTUNNEL НЕ содержит /opt/vk-turn-proxy/
        (это install_dest, совпадение нарушило бы инвариант)."""
        install_dest = Path("/opt/vk-turn-proxy")
        for p in MANUAL_UPLOAD_PATHS_TURNTUNNEL:
            self.assertNotEqual(p, install_dest,
                f"MANUAL_UPLOAD_PATHS_TURNTUNNEL содержит {p} — это "
                f"install_dest, нарушение инварианта")

    def test_turnable_paths_do_not_include_install_dest(self):
        install_dest = Path("/opt/turnable")
        for p in MANUAL_UPLOAD_PATHS_TURNABLE:
            self.assertNotEqual(p, install_dest)


# ============================================================================
#  PackageSpec — инварианты
# ============================================================================
class TestPackageSpecInvariants(unittest.TestCase):
    """КРИТИЧЕСКИЕ инварианты PackageSpec."""

    def test_turntunnel_manual_dir_is_root(self):
        self.assertEqual(TURNTUNNEL_SPEC.manual_incoming_dir, Path("/root"))

    def test_turnable_manual_dir_is_root(self):
        self.assertEqual(TURNABLE_SPEC.manual_incoming_dir, Path("/root"))

    def test_turntunnel_manual_dir_not_in_install_dests(self):
        """КРИТИЧЕСКИЙ ИНВАРИАНТ: manual_dir != install_dests (баг 21d7baf)."""
        for dest in TURNTUNNEL_SPEC.install_dests:
            self.assertNotEqual(TURNTUNNEL_SPEC.manual_incoming_dir, dest)

    def test_turnable_manual_dir_not_in_install_dests(self):
        for dest in TURNABLE_SPEC.install_dests:
            self.assertNotEqual(TURNABLE_SPEC.manual_incoming_dir, dest)

    def test_turntunnel_install_dests_is_vk_turn_proxy_dir(self):
        self.assertEqual(TURNTUNNEL_SPEC.install_dests, [Path("/opt/vk-turn-proxy")])

    def test_turnable_install_dests_is_turnable_dir(self):
        self.assertEqual(TURNABLE_SPEC.install_dests, [Path("/opt/turnable")])

    def test_turntunnel_min_size_is_1mb(self):
        """min_size = 1 MB — защита от усечённых загрузок / 404 HTML-страниц."""
        self.assertEqual(TURNTUNNEL_SPEC.min_size, 1_000_000)

    def test_turnable_min_size_is_1mb(self):
        self.assertEqual(TURNABLE_SPEC.min_size, 1_000_000)

    def test_turntunnel_post_install_is_set(self):
        self.assertIsNotNone(TURNTUNNEL_SPEC.post_install)

    def test_turnable_post_install_is_set(self):
        self.assertIsNotNone(TURNABLE_SPEC.post_install)

    def test_turntunnel_filename_builder(self):
        self.assertEqual(TURNTUNNEL_SPEC.filename_builder(), "server-linux-amd64")

    def test_turnable_filename_builder(self):
        self.assertEqual(TURNABLE_SPEC.filename_builder(), "turnable-linux-amd64")


# ============================================================================
#  post_install — копирование ELF-бинарника
# ============================================================================
class TestPostInstallELFCheck(unittest.TestCase):
    """post_install проверяет ELF magic и копирует бинарник."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_elf(self, name: str = "fake-bin") -> Path:
        """Создаёт файл с валидным ELF magic."""
        p = self._tmpdir / name
        p.write_bytes(b'\x7fELF' + b'\x00' * 100)
        return p

    def _make_non_elf(self, name: str = "fake-html") -> Path:
        """Создаёт файл с НЕ-ELF содержимым (имитация 404 HTML-страницы)."""
        p = self._tmpdir / name
        p.write_bytes(b'<html>404 Not Found</html>' * 100)
        return p

    def test_turntunnel_post_install_copies_elf_to_server(self):
        """post_install для TURNTUNNEL копирует ELF → install_dests/server."""
        install_dir = self._tmpdir / "install"
        src = self._make_elf("server-linux-amd64")
        ok = TURNTUNNEL_SPEC.post_install(src, [install_dir])
        self.assertTrue(ok)
        dest = install_dir / "server"
        self.assertTrue(dest.exists())
        # Права 0o755 (исполняемый)
        self.assertEqual(oct(dest.stat().st_mode & 0o777), '0o755')

    def test_turnable_post_install_copies_elf_to_turnable(self):
        install_dir = self._tmpdir / "install"
        src = self._make_elf("turnable-linux-amd64")
        ok = TURNABLE_SPEC.post_install(src, [install_dir])
        self.assertTrue(ok)
        dest = install_dir / "turnable"
        self.assertTrue(dest.exists())
        self.assertEqual(oct(dest.stat().st_mode & 0o777), '0o755')

    def test_turntunnel_post_install_rejects_non_elf(self):
        """Если файл не ELF — post_install возвращает False (даёт fetch_package
        шанс попробовать следующее зеркало)."""
        install_dir = self._tmpdir / "install"
        src = self._make_non_elf("server-linux-amd64")
        ok = TURNTUNNEL_SPEC.post_install(src, [install_dir])
        self.assertFalse(ok)

    def test_turnable_post_install_rejects_non_elf(self):
        install_dir = self._tmpdir / "install"
        src = self._make_non_elf("turnable-linux-amd64")
        ok = TURNABLE_SPEC.post_install(src, [install_dir])
        self.assertFalse(ok)

    def test_turntunnel_post_install_creates_install_dir(self):
        """install_dest создаётся если не существует."""
        install_dir = self._tmpdir / "deeply" / "nested" / "install"
        src = self._make_elf("server-linux-amd64")
        ok = TURNTUNNEL_SPEC.post_install(src, [install_dir])
        self.assertTrue(ok)
        self.assertTrue(install_dir.exists())

    def test_turnable_post_install_creates_install_dir(self):
        install_dir = self._tmpdir / "deeply" / "nested" / "install"
        src = self._make_elf("turnable-linux-amd64")
        ok = TURNABLE_SPEC.post_install(src, [install_dir])
        self.assertTrue(ok)
        self.assertTrue(install_dir.exists())


# ============================================================================
#  mirror_urls_builder — сигнатура совместимости с PackageSpec API
# ============================================================================
class TestMirrorUrlsBuilderSignature(unittest.TestCase):
    """mirror_urls_builder принимает filename= и **kwargs (для PackageSpec API)."""

    def test_turntunnel_builder_accepts_filename_kwarg(self):
        """_turntunnel_mirror_urls(filename=...) работает (filename
        игнорируется, имя фиксировано)."""
        urls = TURNTUNNEL_SPEC.mirror_urls_builder(filename="server-linux-amd64")
        self.assertGreater(len(urls), 0)

    def test_turnable_builder_accepts_filename_and_version_kwargs(self):
        urls = TURNABLE_SPEC.mirror_urls_builder(
            filename="turnable-linux-amd64", version="0.4.1",
        )
        self.assertGreater(len(urls), 0)

    def test_turnable_builder_uses_version_in_urls(self):
        """URL содержат указанную version (pinned tag)."""
        urls = TURNABLE_SPEC.mirror_urls_builder(
            filename="turnable-linux-amd64", version="0.5.0",
        )
        # Хотя бы один URL содержит версию
        self.assertTrue(any("0.5.0" in u for u in urls),
            f"Версия 0.5.0 не найдена ни в одном URL: {urls}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
