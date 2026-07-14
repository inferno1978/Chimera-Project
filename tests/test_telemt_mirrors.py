#!/usr/bin/env python3
"""
tests/test_telemt_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/telemt_mirrors.py.

Это реальный regression-тест на баг "Telemt отвалился у двоих пользователей":
  • mtproto.py::_install_binary(url) качал через ОДИН прямой URL
    github.com/telemt/telemt/... — БЕЗ зеркал, БЕЗ fallback, БЕЗ /root/.
  • telemt_panel.py::_install_binary(url) делал то же для github.com/amirotin/
    telemt_panel/...
  • При блокировке github.com вся установка Telemt падала.

Теперь оба используют telemt_mirrors.py — единый реестр зеркал.
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

from chimera.modules.telemt_mirrors import (
    get_telemt_mirrors,
    get_telemt_panel_mirrors,
    get_all_mirrors,
    MANUAL_UPLOAD_PATHS,
    TELEMT_MIRRORS_COUNT,
    recommended_manual_path,
    find_manual_upload,
    print_telemt_manual_download_hint,
    detect_arch_libc,
)


class TestMirrorListStructure(unittest.TestCase):
    """Структура и инварианты списка зеркал."""

    def test_telemt_urls_non_empty(self):
        urls = get_telemt_mirrors()
        self.assertGreater(len(urls), 0)

    def test_panel_urls_non_empty(self):
        urls = get_telemt_panel_mirrors()
        self.assertGreater(len(urls), 0)

    def test_both_lists_have_same_count(self):
        """Telemt и panel должны иметь одинаковое количество зеркал."""
        self.assertEqual(len(get_telemt_mirrors()), len(get_telemt_panel_mirrors()))

    def test_mirrors_count_matches_list_length(self):
        self.assertEqual(TELEMT_MIRRORS_COUNT, len(get_telemt_mirrors()))
        self.assertEqual(TELEMT_MIRRORS_COUNT, len(get_telemt_panel_mirrors()))

    def test_at_least_8_mirrors(self):
        """Должно быть ≥8 зеркал: 1 GitHub + 7 GitHub-прокси."""
        self.assertGreaterEqual(TELEMT_MIRRORS_COUNT, 8)

    def test_no_duplicate_urls(self):
        for urls in (get_telemt_mirrors(), get_telemt_panel_mirrors()):
            with self.subTest():
                self.assertEqual(len(urls), len(set(urls)))

    def test_all_urls_are_https(self):
        for url in get_telemt_mirrors() + get_telemt_panel_mirrors():
            with self.subTest(url=url):
                self.assertTrue(url.startswith("https://"),
                                f"Не-HTTPS URL: {url}")

    def test_all_urls_parseable(self):
        for url in get_telemt_mirrors() + get_telemt_panel_mirrors():
            with self.subTest(url=url):
                parsed = urlparse(url)
                self.assertEqual(parsed.scheme, "https")
                self.assertTrue(parsed.netloc)
                self.assertTrue(parsed.path)


class TestTelemtMirrorsTargetCorrectRepo(unittest.TestCase):
    """Зеркала telemt должны вести на github.com/telemt/telemt."""

    def test_telemt_urls_target_telemt_repo(self):
        for url in get_telemt_mirrors():
            with self.subTest(url=url):
                self.assertIn("telemt/telemt", url,
                               f"URL ведёт не на telemt/telemt: {url}")

    def test_telemt_urls_contain_releases_download(self):
        for url in get_telemt_mirrors():
            with self.subTest(url=url):
                self.assertIn("releases/latest/download", url)

    def test_telemt_urls_contain_arch_and_libc(self):
        arch, libc = detect_arch_libc()
        for url in get_telemt_mirrors():
            with self.subTest(url=url):
                self.assertIn(f"telemt-{arch}-linux-{libc}.tar.gz", url)


class TestPanelMirrorsTargetCorrectRepo(unittest.TestCase):
    """Зеркала panel должны вести на github.com/amirotin/telemt_panel."""

    def test_panel_urls_target_amirotin_repo(self):
        for url in get_telemt_panel_mirrors():
            with self.subTest(url=url):
                self.assertIn("amirotin/telemt_panel", url,
                               f"URL ведёт не на amirotin/telemt_panel: {url}")

    def test_panel_urls_contain_releases_download(self):
        for url in get_telemt_panel_mirrors():
            with self.subTest(url=url):
                self.assertIn("releases/latest/download", url)

    def test_panel_urls_contain_arch_and_libc(self):
        arch, libc = detect_arch_libc()
        for url in get_telemt_panel_mirrors():
            with self.subTest(url=url):
                self.assertIn(f"telemt-panel-{arch}-linux-{libc}.tar.gz", url)


class TestMirrorCategories(unittest.TestCase):
    """Категории зеркал представлены."""

    def test_direct_github_present_for_telemt(self):
        urls = get_telemt_mirrors()
        self.assertTrue(
            any("github.com/telemt/telemt/releases" in u for u in urls),
            "Прямой GitHub release-assets для telemt отсутствует",
        )

    def test_direct_github_present_for_panel(self):
        urls = get_telemt_panel_mirrors()
        self.assertTrue(
            any("github.com/amirotin/telemt_panel/releases" in u for u in urls),
            "Прямой GitHub release-assets для panel отсутствует",
        )

    def test_github_proxy_mirrors_present(self):
        """Должны быть все 7 GitHub-прокси."""
        urls = get_telemt_mirrors()
        for proxy in ("ghproxy.net", "ghproxy.com", "mirror.ghproxy.com",
                      "gh.con.sh", "hub.gitmirror.com", "github.moeyy.xyz",
                      "ghps.cc"):
            with self.subTest(proxy=proxy):
                self.assertTrue(
                    any(proxy in u for u in urls),
                    f"Прокси {proxy} отсутствует",
                )


class TestUrlOrdering(unittest.TestCase):
    """Порядок: прямой GitHub → прокси."""

    def test_direct_github_goes_first_for_telemt(self):
        urls = get_telemt_mirrors()
        self.assertIn("github.com/telemt/telemt/releases/latest/download", urls[0])
        # Первый URL НЕ должен быть прокси
        self.assertFalse("ghproxy.net/https://" in urls[0])

    def test_direct_github_goes_first_for_panel(self):
        urls = get_telemt_panel_mirrors()
        self.assertIn("github.com/amirotin/telemt_panel/releases/latest/download", urls[0])
        self.assertFalse("ghproxy.net/https://" in urls[0])


class TestManualUploadPaths(unittest.TestCase):
    """MANUAL_UPLOAD_PATHS — пути для ручного размещения (WinSCP/scp)."""

    def test_recommended_path_is_root(self):
        """Первый путь (рекомендуемый, зелёная подсветка) — /root/."""
        self.assertEqual(MANUAL_UPLOAD_PATHS[0], Path("/root"))

    def test_recommended_manual_path_function(self):
        self.assertEqual(recommended_manual_path(), Path("/root"))

    def test_manual_paths_has_at_least_three_entries(self):
        """/root/ + /usr/local/bin/ + /etc/telemt/."""
        self.assertGreaterEqual(len(MANUAL_UPLOAD_PATHS), 3)

    def test_usr_local_bin_in_manual_paths(self):
        self.assertIn(Path("/usr/local/bin"), MANUAL_UPLOAD_PATHS)

    def test_etc_telemt_in_manual_paths(self):
        self.assertIn(Path("/etc/telemt"), MANUAL_UPLOAD_PATHS)


class TestDetectArchLibc(unittest.TestCase):
    """detect_arch_libc — определение архитектуры и libc."""

    def test_returns_tuple_of_two_strings(self):
        arch, libc = detect_arch_libc()
        self.assertIsInstance(arch, str)
        self.assertIsInstance(libc, str)

    def test_arch_is_valid(self):
        arch, _ = detect_arch_libc()
        self.assertIn(arch, ("x86_64", "aarch64"))

    def test_libc_is_valid(self):
        _, libc = detect_arch_libc()
        self.assertIn(libc, ("gnu", "musl"))


class TestFindManualUpload(unittest.TestCase):
    """find_manual_upload — поиск файла в MANUAL_UPLOAD_PATHS."""

    def test_returns_none_when_not_found(self):
        result = find_manual_upload("__nonexistent_telemt_test_file_12345__")
        self.assertIsNone(result)

    def test_returns_path_when_found_in_root(self):
        # Создаём временный файл с содержимым (find_manual_upload проверяет
        # st_size > 0, так что пустой файл не подойдёт).
        with tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz") as f:
            f.write(b"fake tar.gz content for test")
            tmp_path = Path(f.name)
        try:
            filename = tmp_path.name
            import chimera.modules.telemt_mirrors as tm
            with patch.object(tm, "MANUAL_UPLOAD_PATHS", [tmp_path.parent]):
                result = find_manual_upload(filename)
            self.assertEqual(result, tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_handles_permission_error_gracefully(self):
        """Если /root/ недоступен для чтения, не должен выбрасывать PermissionError."""
        with patch("chimera.modules.telemt_mirrors.MANUAL_UPLOAD_PATHS",
                   [Path("/root/__nonexistent__")]):
            result = find_manual_upload("__nonexistent__")
            self.assertIsNone(result)


class TestGetAllMirrors(unittest.TestCase):
    """get_all_mirrors — словарь {filename: [urls]}."""

    def test_returns_dict_with_two_files(self):
        d = get_all_mirrors()
        # Должны быть 2 файла: telemt tar.gz и telemt-panel tar.gz
        self.assertEqual(len(d), 2)
        tar_keys = [k for k in d if k.endswith(".tar.gz")]
        self.assertEqual(len(tar_keys), 2)


class TestPrintManualHint(unittest.TestCase):
    """print_telemt_manual_download_hint — вывод подсказки."""

    def test_telemt_hint_does_not_raise_without_core(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_telemt_manual_download_hint("telemt")
        output = buf.getvalue()
        self.assertIn("telemt", output.lower())
        self.assertIn("/root/", output)
        self.assertIn("рекомендуется", output)

    def test_panel_hint_does_not_raise_without_core(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_telemt_manual_download_hint("panel")
        output = buf.getvalue()
        self.assertIn("panel", output.lower())
        self.assertIn("/root/", output)
        self.assertIn("рекомендуется", output)

    def test_telemt_hint_contains_all_mirrors(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_telemt_manual_download_hint("telemt")
        output = buf.getvalue()
        for host in ("github.com", "ghproxy.net", "gh.con.sh"):
            with self.subTest(host=host):
                self.assertIn(host, output)

    def test_hint_contains_scp_command(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_telemt_manual_download_hint("telemt")
        output = buf.getvalue()
        self.assertIn("scp", output.lower())
        self.assertIn("curl", output.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
