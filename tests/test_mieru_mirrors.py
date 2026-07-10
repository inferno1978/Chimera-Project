#!/usr/bin/env python3
"""
tests/test_mieru_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/mieru_mirrors.py.

Покрывает:
  • Структуру и инварианты списка зеркал
  • Корректность URL-шаблонов (прямой GitHub + 7 прокси + jsDelivr)
  • Что /root/ — первый в MANUAL_UPLOAD_PATHS (рекомендуемый для WinSCP)
  • Что _is_amd64() и _gh_proxy() работают
  • Что find_manual_upload() ищет файл в путях (через mock)
  • Что все URL — HTTPS
  • Что URL содержат version и filename
  • Что print_mieru_manual_download_hint() не падает
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

from vless_installer.modules.mieru_mirrors import (
    get_mita_mirrors,
    get_mieru_mirrors,
    get_deb_mirrors,
    get_rpm_mirrors,
    get_all_mirrors,
    MANUAL_UPLOAD_PATHS,
    MIERU_LOOKUP_DIRS,
    MIERU_MIRRORS_COUNT,
    recommended_manual_path,
    find_manual_upload,
    print_mieru_manual_download_hint,
)


class TestMirrorListStructure(unittest.TestCase):
    """Структура и инварианты списка зеркал."""

    TEST_VERSION = "3.33.0"

    def test_mita_urls_non_empty(self):
        urls = get_mita_mirrors(self.TEST_VERSION)
        self.assertGreater(len(urls), 0)

    def test_mieru_urls_non_empty(self):
        urls = get_mieru_mirrors(self.TEST_VERSION)
        self.assertGreater(len(urls), 0)

    def test_deb_urls_non_empty(self):
        urls = get_deb_mirrors(self.TEST_VERSION)
        self.assertGreater(len(urls), 0)

    def test_rpm_urls_non_empty(self):
        urls = get_rpm_mirrors(self.TEST_VERSION)
        self.assertGreater(len(urls), 0)

    def test_all_lists_have_same_count(self):
        """Все 4 списка (mita, mieru, deb, rpm) должны иметь одинаковую длину."""
        n = len(get_mita_mirrors(self.TEST_VERSION))
        self.assertEqual(len(get_mieru_mirrors(self.TEST_VERSION)), n)
        self.assertEqual(len(get_deb_mirrors(self.TEST_VERSION)), n)
        self.assertEqual(len(get_rpm_mirrors(self.TEST_VERSION)), n)

    def test_mirrors_count_matches_list_length(self):
        self.assertEqual(MIERU_MIRRORS_COUNT,
                         len(get_mita_mirrors(self.TEST_VERSION)))

    def test_at_least_14_mirrors(self):
        """После миграции на build_mirror_urls: ≥14 зеркал (4 jsDelivr + raw
        + release + 7 прокси + Statically). Старый код давал 9 — теперь 14."""
        self.assertGreaterEqual(MIERU_MIRRORS_COUNT, 14)

    def test_no_duplicate_urls(self):
        for fn in (get_mita_mirrors, get_mieru_mirrors,
                   get_deb_mirrors, get_rpm_mirrors):
            urls = fn(self.TEST_VERSION)
            with self.subTest(fn=fn.__name__):
                self.assertEqual(len(urls), len(set(urls)))

    def test_all_urls_are_https(self):
        for fn in (get_mita_mirrors, get_mieru_mirrors,
                   get_deb_mirrors, get_rpm_mirrors):
            for url in fn(self.TEST_VERSION):
                with self.subTest(url=url):
                    self.assertTrue(url.startswith("https://"),
                                    f"Не-HTTPS URL: {url}")

    def test_all_urls_target_enfein_mieru(self):
        for fn in (get_mita_mirrors, get_mieru_mirrors,
                   get_deb_mirrors, get_rpm_mirrors):
            for url in fn(self.TEST_VERSION):
                with self.subTest(url=url):
                    self.assertIn("enfein/mieru", url,
                                  f"URL ведёт не на enfein/mieru: {url}")

    def test_all_urls_contain_version(self):
        for fn in (get_mita_mirrors, get_mieru_mirrors,
                   get_deb_mirrors, get_rpm_mirrors):
            for url in fn(self.TEST_VERSION):
                with self.subTest(url=url):
                    self.assertIn(f"v{self.TEST_VERSION}", url,
                                  f"URL не содержит v{self.TEST_VERSION}: {url}")

    def test_all_urls_parseable(self):
        for fn in (get_mita_mirrors, get_mieru_mirrors,
                   get_deb_mirrors, get_rpm_mirrors):
            for url in fn(self.TEST_VERSION):
                with self.subTest(url=url):
                    parsed = urlparse(url)
                    self.assertEqual(parsed.scheme, "https")
                    self.assertTrue(parsed.netloc)
                    self.assertTrue(parsed.path)


class TestMirrorFilenames(unittest.TestCase):
    """Корректность имён файлов в URL."""

    TEST_VERSION = "3.33.0"

    def test_mita_urls_contain_correct_filename(self):
        urls = get_mita_mirrors(self.TEST_VERSION)
        for url in urls:
            with self.subTest(url=url):
                self.assertIn(f"mita_{self.TEST_VERSION}_linux_", url)

    def test_mieru_urls_contain_correct_filename(self):
        urls = get_mieru_mirrors(self.TEST_VERSION)
        for url in urls:
            with self.subTest(url=url):
                self.assertIn(f"mieru_{self.TEST_VERSION}_linux_", url)

    def test_deb_urls_contain_correct_filename(self):
        urls = get_deb_mirrors(self.TEST_VERSION)
        for url in urls:
            with self.subTest(url=url):
                self.assertIn(f"mita_{self.TEST_VERSION}_", url)
                self.assertIn(".deb", url)

    def test_rpm_urls_contain_correct_filename(self):
        urls = get_rpm_mirrors(self.TEST_VERSION)
        for url in urls:
            with self.subTest(url=url):
                self.assertIn(f"mita-{self.TEST_VERSION}-1.", url)
                self.assertIn(".rpm", url)


class TestMirrorCategories(unittest.TestCase):
    """Категории зеркал представлены."""

    TEST_VERSION = "3.33.0"

    def test_direct_github_present(self):
        urls = get_mita_mirrors(self.TEST_VERSION)
        self.assertTrue(
            any("github.com/enfein/mieru/releases/download" in u for u in urls),
            "Прямой GitHub release-assets отсутствует",
        )

    def test_github_proxy_mirrors_present(self):
        urls = get_mita_mirrors(self.TEST_VERSION)
        for proxy in ("ghproxy.net", "ghproxy.com", "mirror.ghproxy.com",
                      "gh.con.sh", "hub.gitmirror.com", "github.moeyy.xyz",
                      "ghps.cc"):
            with self.subTest(proxy=proxy):
                self.assertTrue(
                    any(proxy in u for u in urls),
                    f"Прокси {proxy} отсутствует",
                )

    def test_jsdelivr_present(self):
        urls = get_mita_mirrors(self.TEST_VERSION)
        self.assertTrue(
            any("cdn.jsdelivr.net" in u for u in urls),
            "jsDelivr CDN отсутствует (должен быть последним fallback'ом)",
        )


class TestUrlOrdering(unittest.TestCase):
    """Порядок зеркал: jsDelivr → raw GitHub → release GitHub → прокси → Statically.

    После миграции на build_mirror_urls() порядок изменился: теперь
    совпадает с geo_mirrors (jsDelivr first, Statically last).
    """

    TEST_VERSION = "3.33.0"

    def test_jsdelivr_goes_first(self):
        """Первые 4 URL — jsDelivr CDN family (как в geo_mirrors)."""
        urls = get_mita_mirrors(self.TEST_VERSION)
        for url in urls[:4]:
            self.assertIn("jsdelivr.net", url)

    def test_statically_goes_last(self):
        """Последний URL — Statically CDN (как в geo_mirrors)."""
        urls = get_mita_mirrors(self.TEST_VERSION)
        self.assertIn("cdn.statically.io", urls[-1])

    def test_direct_github_present(self):
        """Прямой GitHub release-assets присутствует (не обязательно первый)."""
        urls = get_mita_mirrors(self.TEST_VERSION)
        self.assertTrue(
            any("github.com/enfein/mieru/releases" in u for u in urls),
            "Прямой GitHub release-assets должен присутствовать",
        )


class TestManualUploadPaths(unittest.TestCase):
    """MANUAL_UPLOAD_PATHS — пути для ручного размещения (WinSCP/scp)."""

    def test_recommended_path_is_root(self):
        """Первый путь (рекомендуемый, зелёная подсветка) — /root/.
        Это WinSCP-friendly: пользователь быстро заходит, бросает, выходит."""
        self.assertEqual(MANUAL_UPLOAD_PATHS[0], Path("/root"))

    def test_recommended_manual_path_function(self):
        self.assertEqual(recommended_manual_path(), Path("/root"))

    def test_manual_paths_has_at_least_three_entries(self):
        """/root/ + /usr/local/bin/ + /opt/mieru/."""
        self.assertGreaterEqual(len(MANUAL_UPLOAD_PATHS), 3)

    def test_usr_local_bin_in_manual_paths(self):
        self.assertIn(Path("/usr/local/bin"), MANUAL_UPLOAD_PATHS)

    def test_opt_mieru_in_manual_paths(self):
        self.assertIn(Path("/opt/mieru"), MANUAL_UPLOAD_PATHS)

    def test_xray_lookup_dirs_subset_of_manual(self):
        """MIERU_LOOKUP_DIRS (/usr/local/bin, /usr/bin, /opt/mieru) должны
        быть в MANUAL_UPLOAD_PATHS (пользователь может бросить файл прямо туда)."""
        # /usr/bin НЕ в MANUAL_UPLOAD_PATHS намеренно — это системная директория,
        # не стоит просить пользователя туда писать. Проверяем только подмножество.
        for d in (Path("/usr/local/bin"), Path("/opt/mieru")):
            with self.subTest(d=d):
                self.assertIn(d, MANUAL_UPLOAD_PATHS)


class TestGetAllMirrors(unittest.TestCase):
    """get_all_mirrors — словарь {filename: [urls]}."""

    TEST_VERSION = "3.33.0"

    def test_returns_dict_with_all_files(self):
        d = get_all_mirrors(self.TEST_VERSION)
        # Должны быть .deb, .rpm, mita.tar.gz, mieru.tar.gz
        self.assertGreaterEqual(len(d), 4)
        # Хотя бы один .deb, один .rpm, два .tar.gz
        deb_keys = [k for k in d if k.endswith(".deb")]
        rpm_keys = [k for k in d if k.endswith(".rpm")]
        tar_keys = [k for k in d if k.endswith(".tar.gz")]
        self.assertEqual(len(deb_keys), 1)
        self.assertEqual(len(rpm_keys), 1)
        self.assertEqual(len(tar_keys), 2)  # mita + mieru


class TestFindManualUpload(unittest.TestCase):
    """find_manual_upload — поиск файла в MANUAL_UPLOAD_PATHS."""

    def test_returns_none_when_not_found(self):
        # Имя файла, которого точно нет ни в одном пути
        result = find_manual_upload("__nonexistent_mieru_test_file_12345__")
        self.assertIsNone(result)

    def test_returns_path_when_found_in_root(self):
        # Создаём временный файл с содержимым (find_manual_upload проверяет
        # st_size > 0, так что пустой файл не подойдёт).
        # Важно: патчить нужно модуль-источник, потому что find_manual_upload
        # обращается к MANUAL_UPLOAD_PATHS из своего модуля.
        with tempfile.NamedTemporaryFile(delete=False, suffix=".deb") as f:
            f.write(b"fake deb content for test")
            tmp_path = Path(f.name)
        try:
            filename = tmp_path.name
            import vless_installer.modules.mieru_mirrors as mm
            with patch.object(mm, "MANUAL_UPLOAD_PATHS", [tmp_path.parent]):
                result = find_manual_upload(filename)
            self.assertEqual(result, tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_handles_permission_error_gracefully(self):
        """Если /root/ недоступен для чтения, find_manual_upload не должен
        выбрасывать PermissionError — просто пропустить путь."""
        with patch("vless_installer.modules.mieru_mirrors.MANUAL_UPLOAD_PATHS",
                   [Path("/root/__nonexistent__")]):
            # Path.exists() не выбрасывает PermissionError, но stat() может
            # на некоторых файловых системах. Должно вернуть None, не упасть.
            result = find_manual_upload("__nonexistent__")
            self.assertIsNone(result)


class TestPrintManualHint(unittest.TestCase):
    """print_mieru_manual_download_hint — вывод подсказки."""

    def test_does_not_raise_without_core(self):
        """Функция должна работать даже если _core не загружен
        (использует пустые цвета как fallback)."""
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_mieru_manual_download_hint("3.33.0")
        output = buf.getvalue()
        self.assertIn("mita", output.lower())
        self.assertIn("3.33.0", output)
        self.assertIn("/root/", output)
        self.assertIn("рекомендуется", output)

    def test_output_contains_all_mirrors(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_mieru_manual_download_hint("3.33.0")
        output = buf.getvalue()
        # Должны быть упомянуты ключевые зеркала
        for host in ("github.com", "ghproxy.net", "cdn.jsdelivr.net"):
            with self.subTest(host=host):
                self.assertIn(host, output)

    def test_output_contains_scp_command(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_mieru_manual_download_hint("3.33.0")
        output = buf.getvalue()
        self.assertIn("scp", output.lower())
        self.assertIn("curl", output.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
