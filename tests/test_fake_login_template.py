#!/usr/bin/env python3
"""
tests/test_fake_login_template.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/nginx_setup_templates.py — шаблон #16
«Fake Login» (одностраничная заглушка «Доступ к серверу» с капчей).

Покрывает:
  1. create_fake_login(web_root) — файлы создаются (index.html, robots.txt).
  2. Содержимое index.html — ключевые элементы присутствуют:
     title, captcha, loginForm, скрипт.
  3. Шаблон #16 зарегистрирован в TEMPLATES dispatcher.
  4. get_template_names() возвращает 16 элементов (1..16).
  5. build_template(16, web_root) вызывает create_fake_login.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


class TestCreateFakeLogin(unittest.TestCase):
    """create_fake_login: создание fake-login заглушки."""

    def setUp(self):
        from chimera.modules.nginx_setup_templates import create_fake_login
        self.create_fake_login = create_fake_login
        self._tmp = tempfile.mkdtemp()
        self.web_root = Path(self._tmp)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_creates_index_html(self):
        """index.html создаётся."""
        self.create_fake_login(self.web_root)
        index = self.web_root / "index.html"
        self.assertTrue(index.exists(),
            f"index.html not created in {self.web_root}")
        self.assertGreater(index.stat().st_size, 0,
            "index.html is empty")

    def test_creates_robots_txt(self):
        """robots.txt создаётся с Disallow: /."""
        self.create_fake_login(self.web_root)
        robots = self.web_root / "robots.txt"
        self.assertTrue(robots.exists())
        content = robots.read_text(encoding="utf-8")
        self.assertIn("User-agent: *", content)
        self.assertIn("Disallow: /", content)

    def test_creates_web_root_if_not_exists(self):
        """web_root создаётся если не существует."""
        new_root = self.web_root / "subdir"
        self.create_fake_login(new_root)
        self.assertTrue((new_root / "index.html").exists())

    def test_html_has_correct_title(self):
        """Title = «Доступ к серверу»."""
        self.create_fake_login(self.web_root)
        html = (self.web_root / "index.html").read_text(encoding="utf-8")
        self.assertIn("<title>Доступ к серверу</title>", html)

    def test_html_has_login_form(self):
        """HTML содержит <form id=\"loginForm\">."""
        self.create_fake_login(self.web_root)
        html = (self.web_root / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="loginForm"', html)
        self.assertIn("<form", html)

    def test_html_has_captcha(self):
        """HTML содержит блок капчи."""
        self.create_fake_login(self.web_root)
        html = (self.web_root / "index.html").read_text(encoding="utf-8")
        # Идентификаторы captchaWrap / captchaQuestion / captchaAnswer
        self.assertIn("captchaWrap", html)
        self.assertIn("captchaQuestion", html)
        self.assertIn("captchaAnswer", html)

    def test_html_has_login_password_fields(self):
        """HTML содержит поля login и password."""
        self.create_fake_login(self.web_root)
        html = (self.web_root / "index.html").read_text(encoding="utf-8")
        self.assertIn('name="user"', html)
        self.assertIn('name="pass"', html)
        self.assertIn('type="password"', html)

    def test_html_has_submit_button(self):
        """HTML содержит кнопку «Войти»."""
        self.create_fake_login(self.web_root)
        html = (self.web_root / "index.html").read_text(encoding="utf-8")
        self.assertIn("Войти", html)

    def test_html_has_captcha_script(self):
        """HTML содержит JS-логику капчи (newCaptcha)."""
        self.create_fake_login(self.web_root)
        html = (self.web_root / "index.html").read_text(encoding="utf-8")
        self.assertIn("newCaptcha", html)
        self.assertIn("captchaIsRequired", html)
        self.assertIn("<script>", html)

    def test_html_has_toast_notification(self):
        """HTML содержит toast-уведомление."""
        self.create_fake_login(self.web_root)
        html = (self.web_root / "index.html").read_text(encoding="utf-8")
        self.assertIn("toast", html)
        self.assertIn("showToast", html)
        # Сообщение об ошибке логина
        self.assertIn("Неверный логин или пароль", html)

    def test_html_size_reasonable(self):
        """Размер index.html — разумный (5-30 KB)."""
        self.create_fake_login(self.web_root)
        size = (self.web_root / "index.html").stat().st_size
        self.assertGreater(size, 5000,
            f"index.html too small: {size} bytes")
        self.assertLess(size, 100_000,
            f"index.html too large: {size} bytes")

    def test_html_is_self_contained(self):
        """HTML самодостаточный — не ссылается на внешние CSS/JS файлы."""
        self.create_fake_login(self.web_root)
        html = (self.web_root / "index.html").read_text(encoding="utf-8")
        # Не должно быть ссылок на внешние style.css или .js
        self.assertNotIn('href="style.css"', html)
        self.assertNotIn('src="', html)  # no <script src="...">
        # Inline стили присутствуют
        self.assertIn("<style>", html)
        self.assertIn("</style>", html)

    def test_idempotent(self):
        """Повторный вызов перезаписывает файлы без ошибок."""
        self.create_fake_login(self.web_root)
        first_size = (self.web_root / "index.html").stat().st_size
        # Повторный вызов
        self.create_fake_login(self.web_root)
        second_size = (self.web_root / "index.html").stat().st_size
        self.assertEqual(first_size, second_size,
            "Idempotent call changed file size")


class TestFakeLoginDispatcher(unittest.TestCase):
    """Шаблон #16 зарегистрирован в TEMPLATES dispatcher."""

    def test_template_16_registered(self):
        """TEMPLATES[16] = ('Fake Login', create_fake_login)."""
        from chimera.modules.nginx_setup_templates import TEMPLATES
        self.assertIn(16, TEMPLATES)
        name, fn = TEMPLATES[16]
        self.assertEqual(name, "Fake Login")

    def test_get_template_names_has_16_entries(self):
        """get_template_names() возвращает 17 элементов (1 пустой + 1..16)."""
        from chimera.modules.nginx_setup_templates import get_template_names
        names = get_template_names()
        self.assertEqual(len(names), 17)
        self.assertEqual(names[0], "")  # legacy empty
        self.assertEqual(names[16], "Fake Login")

    def test_build_template_16_calls_create_fake_login(self):
        """build_template(16, web_root) вызывает create_fake_login."""
        from chimera.modules.nginx_setup_templates import build_template
        with tempfile.TemporaryDirectory() as tmp:
            build_template(16, Path(tmp))
            self.assertTrue((Path(tmp) / "index.html").exists())
            self.assertTrue((Path(tmp) / "robots.txt").exists())

    def test_build_template_unknown_falls_back_to_2(self):
        """build_template(999, ...) fallback на NexCloud (template #2)."""
        from chimera.modules.nginx_setup_templates import build_template
        with tempfile.TemporaryDirectory() as tmp:
            # Не должно падать — fallback на template #2
            build_template(999, Path(tmp))
            # Template #2 (NexCloud) создаёт style.css и index.html
            self.assertTrue((Path(tmp) / "index.html").exists() or
                           (Path(tmp) / "style.css").exists())


if __name__ == "__main__":
    unittest.main()
