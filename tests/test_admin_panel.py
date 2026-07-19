#!/usr/bin/env python3
"""
tests/test_admin_panel.py
───────────────────────────────────────────────────────────────────────────────
Smoke-тест для chimera/modules/admin_panel.py.

Проверяет: get_admin_html() возвращает непустую строку валидного HTML
без исключений.
"""
from __future__ import annotations
import sys, unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

def _setup_core():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text(); g = {}
    with patch.object(Path, 'mkdir', lambda s,*a,**k: None), \
         patch.object(Path, 'touch', lambda s,*a,**k: None), \
         patch.object(Path, 'chmod', lambda s,*a,**k: None), \
         patch('os.chown', lambda *a,**k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types; m = types.ModuleType("chimera._core"); m.__dict__.update(g)
    sys.modules["chimera._core"] = m

class TestGetAdminHtml(unittest.TestCase):
    """Smoke: get_admin_html() → непустой валидный HTML."""

    def setUp(self): _setup_core()

    def test_returns_nonempty_string(self):
        from chimera.modules.admin_panel import get_admin_html
        html = get_admin_html()
        self.assertIsInstance(html, str)
        self.assertGreater(len(html), 100)

    def test_starts_with_doctype(self):
        from chimera.modules.admin_panel import get_admin_html
        html = get_admin_html().strip()
        self.assertTrue(html.startswith("<!DOCTYPE html>"))

    def test_contains_html_tags(self):
        from chimera.modules.admin_panel import get_admin_html
        html = get_admin_html()
        self.assertIn("<html", html)
        self.assertIn("</html>", html)
        self.assertIn("<head>", html)
        self.assertIn("<body", html)

    def test_contains_title(self):
        from chimera.modules.admin_panel import get_admin_html
        html = get_admin_html()
        self.assertIn("<title>", html)

    def test_no_exceptions_on_multiple_calls(self):
        """Несколько вызовов подряд не вызывают исключений."""
        from chimera.modules.admin_panel import get_admin_html
        for _ in range(3):
            html = get_admin_html()
            self.assertGreater(len(html), 0)

    def test_rename_user_ui_present(self):
        """В HTML присутствуют элементы UI для переименования юзера:
        кнопка в строке таблицы, модальное окно и JS-функции."""
        from chimera.modules.admin_panel import get_admin_html
        html = get_admin_html()
        # Модальное окно
        self.assertIn('id="rename-user-modal"', html)
        # Кнопка в строке
        self.assertIn('showRenameUserModal(', html)
        # JS-функции
        self.assertIn('function showRenameUserModal(', html)
        self.assertIn('async function renameUser(', html)
        # Поле ввода нового имени
        self.assertIn('id="rename-user-new"', html)
        # Подсказка про Telemt в модалке
        self.assertIn('Telemt', html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
