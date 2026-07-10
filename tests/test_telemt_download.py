#!/usr/bin/env python3
"""
tests/test_telemt_download.py
───────────────────────────────────────────────────────────────────────────────
Тесты для multi-mirror логики скачивания telemt/telemt-panel.

Покрывает:
  • mtproto.py::_download_with_mirrors() — перебор зеркал, fallback
  • mtproto.py::_install_binary() — принимает список URL (новая сигнатура)
    + обратная совместимость со строкой
  • mtproto.py::_get_latest_release() — возвращает (tag, urls), urls — список
  • telemt_panel.py — те же проверки для панели

Это regression-тесты на баг "Telemt отвалился у двоих пользователей":
до патча mtproto.py/telemt_panel.py качали через ОДИН прямой URL.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Загружает _core.py в sys.modules как fake module (стандартный паттерн)."""
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
#  mtproto.py — multi-mirror скачивание telemt
# ============================================================================
class TestMtprotoDownloadWithMirrors(unittest.TestCase):
    """mtproto._download_with_mirrors — перебор зеркал."""

    @classmethod
    def setUpClass(cls):
        _setup_core_in_sysmodules()
        from vless_installer.modules import mtproto
        cls.mtproto = mtproto

    def test_returns_true_when_first_mirror_works(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "telemt.tar.gz"
            urls = [
                "https://github.com/telemt/telemt/releases/latest/download/telemt-x86_64-linux-gnu.tar.gz",
                "https://ghproxy.net/https://github.com/telemt/telemt/...",
            ]
            mock_resp = MagicMock()
            mock_resp.read.side_effect = [b"fake tar.gz content", b""]
            mock_resp.__enter__ = lambda self: self
            mock_resp.__exit__ = lambda self, *a: None
            with patch("vless_installer.modules.mtproto.urllib.request.urlopen",
                       return_value=mock_resp), \
                 patch.object(self.mtproto, "_find_telemt_manual_upload",
                              return_value=None):
                result = self.mtproto._download_with_mirrors(urls, dest, "telemt")
            self.assertTrue(result)
            self.assertTrue(dest.exists())

    def test_falls_through_to_second_mirror_when_first_fails(self):
        from urllib.error import URLError
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "telemt.tar.gz"
            urls = [
                "https://github.com/telemt/telemt/...",  # упадёт
                "https://ghproxy.net/https://github.com/telemt/telemt/...",  # ок
            ]
            mock_resp_ok = MagicMock()
            mock_resp_ok.read.side_effect = [b"fake content", b""]
            mock_resp_ok.__enter__ = lambda self: self
            mock_resp_ok.__exit__ = lambda self, *a: None

            call_count = [0]
            def fake_urlopen(req, timeout):
                call_count[0] += 1
                if call_count[0] == 1:
                    raise URLError("connection refused")
                return mock_resp_ok

            with patch("vless_installer.modules.mtproto.urllib.request.urlopen",
                       side_effect=fake_urlopen), \
                 patch.object(self.mtproto, "_find_telemt_manual_upload",
                              return_value=None):
                result = self.mtproto._download_with_mirrors(urls, dest, "telemt")
            self.assertTrue(result)
            self.assertEqual(call_count[0], 2)

    def test_returns_false_when_all_mirrors_fail(self):
        from urllib.error import URLError
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "telemt.tar.gz"
            urls = ["https://github.com/...", "https://ghproxy.net/..."]
            with patch("vless_installer.modules.mtproto.urllib.request.urlopen",
                       side_effect=URLError("blocked")), \
                 patch.object(self.mtproto, "_find_telemt_manual_upload",
                              return_value=None):
                result = self.mtproto._download_with_mirrors(urls, dest, "telemt")
            self.assertFalse(result)

    def test_uses_manual_upload_when_file_in_root(self):
        """АДАПТАЦИЯ: _download_with_mirrors теперь deprecated и НЕ проверяет
        manual upload (это делает fetch_package). Этот тест проверяет что
        deprecated функция работает для прямого скачивания по URL.
        Manual upload проверяется в download_manager тестах.
        """
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "telemt.tar.gz"
            urls = ["https://github.com/telemt/telemt/..."]

            mock_resp = MagicMock()
            mock_resp.read.side_effect = [b"downloaded tar.gz", b""]
            mock_resp.__enter__ = lambda self: self
            mock_resp.__exit__ = lambda self, *a: None

            with patch("vless_installer.modules.mtproto.urllib.request.urlopen",
                       return_value=mock_resp):
                result = self.mtproto._download_with_mirrors(urls, dest, "telemt")
            self.assertTrue(result)
            self.assertEqual(dest.read_bytes(), b"downloaded tar.gz")


class TestMtprotoGetLatestRelease(unittest.TestCase):
    """mtproto._get_latest_release — возвращает (tag, urls).

    АДАПТАЦИЯ: после миграции api.github.com убран. tag всегда "latest".
    urls — список из TELEMT_SPEC.mirror_urls_builder().
    """

    @classmethod
    def setUpClass(cls):
        _setup_core_in_sysmodules()
        from vless_installer.modules import mtproto
        cls.mtproto = mtproto

    def test_returns_tuple(self):
        tag, urls = self.mtproto._get_latest_release()
        self.assertIsInstance(tag, str)
        self.assertIsInstance(urls, list)

    def test_tag_is_latest_after_migration(self):
        """После миграции tag всегда 'latest' (api.github.com убран)."""
        tag, urls = self.mtproto._get_latest_release()
        self.assertEqual(tag, "latest")

    def test_urls_non_empty(self):
        """URLs всегда доступны (не зависят от api.github.com)."""
        tag, urls = self.mtproto._get_latest_release()
        self.assertGreater(len(urls), 0)


class TestMtprotoInstallBinarySignature(unittest.TestCase):
    """mtproto._install_binary — принимает список URL (новая сигнатура)
    + обратная совместимость со строкой."""

    @classmethod
    def setUpClass(cls):
        _setup_core_in_sysmodules()
        from vless_installer.modules import mtproto
        cls.mtproto = mtproto

    def test_accepts_list_of_urls(self):
        with tempfile.TemporaryDirectory() as td:
            import tarfile, io
            tar_path = Path(td) / "telemt.tar.gz"
            bin_content = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 100
            with tarfile.open(tar_path, "w:gz") as tar:
                info = tarfile.TarInfo(name="telemt")
                info.size = len(bin_content)
                tar.addfile(info, io.BytesIO(bin_content))

            # _download_with_mirrors запишет tar_path в archive
            def fake_dl(urls, archive, name):
                __import__("shutil").copy2(str(tar_path), str(archive))
                return True

            with patch.object(self.mtproto, "_download_with_mirrors",
                              side_effect=fake_dl), \
                 patch.object(self.mtproto, "BIN_PATH", Path(td) / "telemt"):
                result = self.mtproto._install_binary(["https://github.com/..."])
            self.assertTrue(result)

    def test_accepts_single_string_url_backward_compat(self):
        """_install_binary принимает ОДИН URL (строку) для обратной совместимости.
        Внутри _download_with_mirrors обернёт его в список."""
        with tempfile.TemporaryDirectory() as td:
            import tarfile, io
            tar_path = Path(td) / "telemt.tar.gz"
            bin_content = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 100
            with tarfile.open(tar_path, "w:gz") as tar:
                info = tarfile.TarInfo(name="telemt")
                info.size = len(bin_content)
                tar.addfile(info, io.BytesIO(bin_content))

            def fake_dl(urls, archive, name):
                # _download_with_mirrors должен обернуть строку в список
                # до вызова этого fake. Но т.к. мы патчим сам _download_with_mirrors,
                # обёртка не выполняется. Принимаем оба варианта.
                if isinstance(urls, str):
                    urls = [urls]
                __import__("shutil").copy2(str(tar_path), str(archive))
                return True

            with patch.object(self.mtproto, "_download_with_mirrors",
                              side_effect=fake_dl), \
                 patch.object(self.mtproto, "BIN_PATH", Path(td) / "telemt"):
                # Передаём СТРОКУ, а не список — старая сигнатура
                result = self.mtproto._install_binary("https://github.com/...")
            self.assertTrue(result)


# ============================================================================
#  telemt_panel.py — multi-mirror скачивание панели
# ============================================================================
class TestPanelDownloadWithMirrors(unittest.TestCase):
    """telemt_panel._download_with_mirrors — перебор зеркал."""

    @classmethod
    def setUpClass(cls):
        _setup_core_in_sysmodules()
        from vless_installer.modules import telemt_panel
        cls.panel = telemt_panel

    def test_returns_true_when_first_mirror_works(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "panel.tar.gz"
            urls = ["https://github.com/amirotin/telemt_panel/..."]
            mock_resp = MagicMock()
            mock_resp.read.side_effect = [b"fake content", b""]
            mock_resp.__enter__ = lambda self: self
            mock_resp.__exit__ = lambda self, *a: None
            with patch("vless_installer.modules.telemt_panel.urllib.request.urlopen",
                       return_value=mock_resp), \
                 patch.object(self.panel, "_find_telemt_manual_upload",
                              return_value=None):
                result = self.panel._download_with_mirrors(urls, dest, "telemt-panel")
            self.assertTrue(result)

    def test_returns_false_when_all_mirrors_fail(self):
        from urllib.error import URLError
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "panel.tar.gz"
            urls = ["https://github.com/...", "https://ghproxy.net/..."]
            with patch("vless_installer.modules.telemt_panel.urllib.request.urlopen",
                       side_effect=URLError("blocked")), \
                 patch.object(self.panel, "_find_telemt_manual_upload",
                              return_value=None):
                result = self.panel._download_with_mirrors(urls, dest, "telemt-panel")
            self.assertFalse(result)

    def test_uses_manual_upload_when_file_in_root(self):
        """АДАПТАЦИЯ: _download_with_mirrors теперь deprecated и НЕ проверяет
        manual upload. Проверяет прямое скачивание.
        """
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "panel.tar.gz"
            urls = ["https://github.com/amirotin/telemt_panel/..."]

            mock_resp = MagicMock()
            mock_resp.read.side_effect = [b"downloaded panel", b""]
            mock_resp.__enter__ = lambda self: self
            mock_resp.__exit__ = lambda self, *a: None

            with patch("vless_installer.modules.telemt_panel.urllib.request.urlopen",
                       return_value=mock_resp):
                result = self.panel._download_with_mirrors(urls, dest, "telemt-panel")
            self.assertTrue(result)
            self.assertEqual(dest.read_bytes(), b"downloaded panel")


class TestPanelGetLatestRelease(unittest.TestCase):
    """telemt_panel._get_latest_release — возвращает (tag, urls).

    АДАПТАЦИЯ: после миграции api.github.com убран. tag всегда "latest".
    """

    @classmethod
    def setUpClass(cls):
        _setup_core_in_sysmodules()
        from vless_installer.modules import telemt_panel
        cls.panel = telemt_panel

    def test_returns_tuple(self):
        tag, urls = self.panel._get_latest_release()
        self.assertIsInstance(tag, str)
        self.assertIsInstance(urls, list)

    def test_urls_non_empty(self):
        """URLs всегда доступны (не зависят от api.github.com)."""
        tag, urls = self.panel._get_latest_release()
        self.assertGreater(len(urls), 0)

    def test_tag_is_latest_after_migration(self):
        """После миграции tag всегда 'latest' (api.github.com убран)."""
        tag, urls = self.panel._get_latest_release()
        self.assertEqual(tag, "latest")


class TestTelemtVsPanelDifferentRepos(unittest.TestCase):
    """Regression-тест: telemt и telemt_panel используют РАЗНЫЕ owner/repo
    и не путаются друг с другом.

    Это защита от ошибки рода коммита 57cd80e (перепутали mieru с Telemt).
    Здесь риск перепутать telemt с telemt_panel внутри одного файла —
    тест гарантирует что URL'ы не пересекаются.
    """

    @classmethod
    def setUpClass(cls):
        _setup_core_in_sysmodules()

    def test_telemt_urls_contain_telemt_telemt(self):
        from vless_installer.modules.telemt_packages import TELEMT_SPEC
        urls = TELEMT_SPEC.mirror_urls_builder(
            filename=TELEMT_SPEC.filename_builder()
        )
        for url in urls:
            with self.subTest(url=url):
                self.assertIn("telemt/telemt", url,
                              "TELEMT_SPEC URLs должны содержать telemt/telemt")

    def test_panel_urls_contain_amirotin_telemt_panel(self):
        from vless_installer.modules.telemt_packages import TELEMT_PANEL_SPEC
        urls = TELEMT_PANEL_SPEC.mirror_urls_builder(
            filename=TELEMT_PANEL_SPEC.filename_builder()
        )
        for url in urls:
            with self.subTest(url=url):
                self.assertIn("amirotin/telemt_panel", url,
                              "TELEMT_PANEL_SPEC URLs должны содержать amirotin/telemt_panel")

    def test_no_cross_contamination(self):
        """telemt URLs не содержат amirotin, panel URLs не содержат telemt/telemt."""
        from vless_installer.modules.telemt_packages import TELEMT_SPEC, TELEMT_PANEL_SPEC
        telemt_urls = TELEMT_SPEC.mirror_urls_builder(
            filename=TELEMT_SPEC.filename_builder()
        )
        panel_urls = TELEMT_PANEL_SPEC.mirror_urls_builder(
            filename=TELEMT_PANEL_SPEC.filename_builder()
        )
        for url in telemt_urls:
            with self.subTest(url=url):
                self.assertNotIn("amirotin", url,
                                 "telemt URLs не должны содержать amirotin")
        for url in panel_urls:
            with self.subTest(url=url):
                self.assertNotIn("telemt/telemt", url,
                                 "panel URLs не должны содержать telemt/telemt")

    def test_different_specs_not_same_object(self):
        """TELEMT_SPEC и TELEMT_PANEL_SPEC — разные объекты."""
        from vless_installer.modules.telemt_packages import TELEMT_SPEC, TELEMT_PANEL_SPEC
        self.assertIsNot(TELEMT_SPEC, TELEMT_PANEL_SPEC)
        self.assertNotEqual(TELEMT_SPEC.name, TELEMT_PANEL_SPEC.name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
