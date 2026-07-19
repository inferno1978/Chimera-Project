#!/usr/bin/env python3
"""
tests/test_user_portal.py
───────────────────────────────────────────────────────────────────────────────
Smoke-тест для chimera/modules/user_portal.py.

Проверяет: get_portal_html() возвращает непустую строку валидного HTML
без исключений на разных входных данных.
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

class TestGetPortalHtml(unittest.TestCase):
    """Smoke: get_portal_html() → непустой валидный HTML."""

    def setUp(self): _setup_core()

    def test_returns_nonempty_string(self):
        from chimera.modules.user_portal import get_portal_html
        html = get_portal_html({"email": "alice@example.com", "name": "Alice"})
        self.assertIsInstance(html, str)
        self.assertGreater(len(html), 100)

    def test_starts_with_doctype(self):
        from chimera.modules.user_portal import get_portal_html
        html = get_portal_html({"email": "a@b.c"}).strip()
        self.assertTrue(html.startswith("<!DOCTYPE html>"))

    def test_contains_html_tags(self):
        from chimera.modules.user_portal import get_portal_html
        html = get_portal_html({"email": "a@b.c"})
        self.assertIn("<html", html)
        self.assertIn("</html>", html)

    def test_with_empty_user(self):
        """Пустой user dict — не падает."""
        from chimera.modules.user_portal import get_portal_html
        html = get_portal_html({})
        self.assertGreater(len(html), 100)

    def test_with_name_and_email(self):
        from chimera.modules.user_portal import get_portal_html
        html = get_portal_html({"email": "bob@example.com", "name": "Bob"})
        self.assertIn("Bob", html)

    def test_with_special_chars_in_name(self):
        """Спецсимволы в name — XSS-экранирование через html.escape."""
        from chimera.modules.user_portal import get_portal_html
        html = get_portal_html({"email": "a@b.c", "name": '<script>alert("xss")</script>'})
        # Экранированный вариант не содержит сырой <script>
        self.assertNotIn('<script>alert', html)
        # Но содержит экранированный
        self.assertIn("&lt;script&gt;", html)

    def test_with_unicode_name(self):
        """Юникод (кириллица) в name — не ломает HTML."""
        from chimera.modules.user_portal import get_portal_html
        html = get_portal_html({"email": "a@b.c", "name": "Иван"})
        self.assertIn("Иван", html)

    def test_no_exceptions_on_multiple_calls(self):
        from chimera.modules.user_portal import get_portal_html
        for user in [{"email":"a@b.c"}, {"email":"x@y.z","name":"Test"}, {}]:
            html = get_portal_html(user)
            self.assertGreater(len(html), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
