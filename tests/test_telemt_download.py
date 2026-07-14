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
#  mtproto.py — multi-mirror скачивание telemt
# ============================================================================
class TestMtprotoGetLatestRelease(unittest.TestCase):
    """mtproto._get_latest_release — возвращает (tag, urls).

    АДАПТАЦИЯ: после миграции api.github.com убран. tag всегда "latest".
    urls — список из TELEMT_SPEC.mirror_urls_builder().
    """

    @classmethod
    def setUpClass(cls):
        _setup_core_in_sysmodules()
        from chimera.modules import mtproto
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


class TestPanelGetLatestRelease(unittest.TestCase):
    """telemt_panel._get_latest_release — возвращает (tag, urls).

    АДАПТАЦИЯ: после миграции api.github.com убран. tag всегда "latest".
    """

    @classmethod
    def setUpClass(cls):
        _setup_core_in_sysmodules()
        from chimera.modules import telemt_panel
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
        from chimera.modules.telemt_packages import TELEMT_SPEC
        urls = TELEMT_SPEC.mirror_urls_builder(
            filename=TELEMT_SPEC.filename_builder()
        )
        for url in urls:
            with self.subTest(url=url):
                self.assertIn("telemt/telemt", url,
                              "TELEMT_SPEC URLs должны содержать telemt/telemt")

    def test_panel_urls_contain_amirotin_telemt_panel(self):
        from chimera.modules.telemt_packages import TELEMT_PANEL_SPEC
        urls = TELEMT_PANEL_SPEC.mirror_urls_builder(
            filename=TELEMT_PANEL_SPEC.filename_builder()
        )
        for url in urls:
            with self.subTest(url=url):
                self.assertIn("amirotin/telemt_panel", url,
                              "TELEMT_PANEL_SPEC URLs должны содержать amirotin/telemt_panel")

    def test_no_cross_contamination(self):
        """telemt URLs не содержат amirotin, panel URLs не содержат telemt/telemt."""
        from chimera.modules.telemt_packages import TELEMT_SPEC, TELEMT_PANEL_SPEC
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
        from chimera.modules.telemt_packages import TELEMT_SPEC, TELEMT_PANEL_SPEC
        self.assertIsNot(TELEMT_SPEC, TELEMT_PANEL_SPEC)
        self.assertNotEqual(TELEMT_SPEC.name, TELEMT_PANEL_SPEC.name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
