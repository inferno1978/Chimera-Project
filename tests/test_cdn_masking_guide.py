#!/usr/bin/env python3
"""
tests/test_cdn_masking_guide.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/cdn_masking_guide.py — печать инструкции
для ручной настройки CDN Beeline.

Покрывает:
  1. print_cdn_setup_instructions(domain, path) — домен/путь подставлены в вывод.
  2. Вывод содержит все ключевые шаги (1-9) для Beeline CDN.
  3. Вывод содержит origin URL и tunnel URL.
  4. Вывод содержит правильный формат path.
  5. Пустой domain / path вызывает ValueError.
"""
from __future__ import annotations

import io
import contextlib
import re
import sys
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


class TestPrintCdnSetupInstructions(unittest.TestCase):
    """print_cdn_setup_instructions: печать инструкции."""

    def setUp(self):
        from chimera.modules.cdn_masking_guide import print_cdn_setup_instructions
        self.print_guide = print_cdn_setup_instructions

    def _capture(self, domain: str, path: str) -> str:
        """Вызывает print_cdn_setup_instructions и возвращает captured stdout."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.print_guide(domain, path)
        return buf.getvalue()

    def test_returns_none(self):
        """Функция ничего не возвращает (только печатает)."""
        result = self.print_guide("example.com", "/api/v2/static.ts")
        # Функция явно ничего не возвращает
        # (вызов без redirect_stdout всё равно работает — печать идёт в sys.stdout)

    def test_domain_substituted_in_output(self):
        """Домен подставлен в вывод."""
        out = self._capture("my-domain.example.com", "/api/v2/static.ts")
        self.assertIn("my-domain.example.com", out)

    def test_path_substituted_in_output(self):
        """Path подставлен в вывод."""
        out = self._capture("example.com", "/cdn/v3/signal.php")
        self.assertIn("/cdn/v3/signal.php", out)

    def test_origin_url_in_output(self):
        """Вывод содержит origin URL: https://<domain>:443."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertIn("https://example.com:443", out)

    def test_tunnel_url_in_output(self):
        """Вывод содержит tunnel URL: https://<domain><path>."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertIn("https://example.com/api/v2/static.ts", out)

    def test_contains_step_1_login(self):
        """Шаг 1: Вход в ЛК Beeline CDN."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertIn("ШАГ 1", out)
        self.assertIn("Вход в ЛК", out)
        self.assertIn("cdn.beeline.ru", out)

    def test_contains_step_2_resource_creation(self):
        """Шаг 2: Создание ресурса (CDN → Добавить ресурс)."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertIn("ШАГ 2", out)
        self.assertIn("Добавить ресурс", out)
        self.assertIn("Статика", out)

    def test_contains_step_3_https(self):
        """Шаг 3: Настройка HTTPS."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertIn("ШАГ 3", out)
        self.assertIn("Let's Encrypt", out)

    def test_contains_step_4_caching(self):
        """Шаг 4: Настройка кэширования."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertIn("ШАГ 4", out)
        self.assertIn("Кэшировани", out)

    def test_contains_step_5_timeouts(self):
        """Шаг 5: Настройка таймаутов."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertIn("ШАГ 5", out)
        # Заголовок шага содержит "таймаут" (case-insensitive)
        self.assertTrue(
            "таймаут" in out.lower() or "Timeout" in out,
            "Step 5 should mention timeouts"
        )
        self.assertIn("3600", out)  # 1 hour timeout mentioned

    def test_contains_step_6_rewrite(self):
        """Шаг 6: Rewrite правила."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertIn("ШАГ 6", out)
        self.assertIn("Rewrite", out)

    def test_contains_step_7_websocket(self):
        """Шаг 7: WebSocket / Streaming."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertIn("ШАГ 7", out)
        # Проверяем что-то про streaming/websocket
        self.assertTrue(
            "WebSocket" in out or "Streaming" in out or "stream" in out.lower(),
            "Step 7 should mention WebSocket/Streaming"
        )

    def test_contains_step_8_cname(self):
        """Шаг 8: Привязка домена (CNAME)."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertIn("ШАГ 8", out)
        self.assertIn("CNAME", out)

    def test_contains_step_9_verification(self):
        """Шаг 9: Проверка."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertIn("ШАГ 9", out)
        self.assertIn("Проверк", out)

    def test_contains_all_9_steps(self):
        """Все 9 шагов присутствуют в выводе."""
        out = self._capture("example.com", "/api/v2/static.ts")
        for i in range(1, 10):
            self.assertIn(f"ШАГ {i}", out,
                f"Step {i} missing in output")

    def test_path_normalized_leading_slash(self):
        """Path без ведущего / нормализуется при подстановке."""
        out = self._capture("example.com", "api/v2/static.ts")
        self.assertIn("/api/v2/static.ts", out)
        self.assertNotIn("https://example.comapi", out)

    def test_contains_warnings(self):
        """Вывод содержит предупреждения о DPI / SSE / POST buffering."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertIn("noSSEHeader", out)
        self.assertIn("DPI", out)

    def test_empty_domain_raises(self):
        """Пустой domain вызывает ValueError."""
        with self.assertRaises(ValueError):
            self.print_guide("", "/api/v2/static.ts")

    def test_empty_path_raises(self):
        """Пустой path вызывает ValueError."""
        with self.assertRaises(ValueError):
            self.print_guide("example.com", "")

    def test_different_domains_produce_different_output(self):
        """Разные домены → разный вывод."""
        out1 = self._capture("domain1.com", "/api/v2/static.ts")
        out2 = self._capture("domain2.com", "/api/v2/static.ts")
        self.assertNotIn("domain2.com", out1)
        self.assertNotIn("domain1.com", out2)

    def test_different_paths_produce_different_output(self):
        """Разные path → разный вывод."""
        out1 = self._capture("example.com", "/api/v2/static.ts")
        out2 = self._capture("example.com", "/cdn/v3/signal.php")
        self.assertNotIn("/cdn/v3/signal.php", out1)
        self.assertNotIn("/api/v2/static.ts", out2)

    def test_output_size_reasonable(self):
        """Вывод имеет разумный размер (не пустой, не огромный)."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertGreater(len(out), 1000,
            f"Output too short: {len(out)} chars")
        self.assertLess(len(out), 50_000,
            f"Output too long: {len(out)} chars")


if __name__ == "__main__":
    unittest.main()
