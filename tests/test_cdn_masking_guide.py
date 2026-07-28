#!/usr/bin/env python3
"""
tests/test_cdn_masking_guide.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/cdn_masking_guide.py — печать инструкции
для ручной настройки CDN Beeline.

Покрывает:
  1. print_cdn_setup_instructions(domain, path) — домен/путь подставлены в вывод.
  2. Вывод содержит все ключевые шаги (1-8) для Beeline CDN.
  3. Вывод содержит tunnel URL.
  4. Вывод содержит правильный формат path.
  5. Пустой domain / path вызывает ValueError.
  6. Шаг 5 (Rewrite) содержит явные ОТКУДА/КУДА с подставленным path.
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

    def test_contains_step_3_resource_config(self):
        """Шаг 3: Конфигурация ресурса (HTTPS/SNI/Host/Cache)."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertIn("ШАГ 3", out)
        self.assertIn("HTTPS", out)
        self.assertIn("SNI", out)

    def test_contains_step_4_expert_settings(self):
        """Шаг 4: Экспертные настройки (HTTP/2, TLS, таймауты, методы)."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertIn("ШАГ 4", out)
        self.assertIn("HTTP/2", out)
        self.assertIn("Таймауты", out)
        # Мануал Beeline: 5 / 300 / 300 (Connect/Read/Send)
        self.assertIn("5 / 300 / 300", out)
        self.assertIn("POST", out)

    def test_contains_step_5_rewrite_with_from_to(self):
        """Шаг 5: Rewrite с явными полями ОТКУДА/КУДА + path подставлен."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertIn("ШАГ 5", out)
        self.assertIn("Rewrite", out)
        self.assertIn("ОТКУДА", out)
        self.assertIn("КУДА", out)
        # Path подставлен в поля ОТКУДА/КУДА (без ведущего /, с trailing / в ОТКУДА)
        self.assertIn("api/v2/static.ts/", out)   # ОТКУДА
        self.assertIn("api/v2/static.ts\n", out + "\n")  # КУДА (без trailing /)
        # «На конечных узлах» — это правильный выбор по мануалу Beeline
        self.assertIn("На конечных узлах", out)

    def test_contains_step_6_cname(self):
        """Шаг 6: Привязка домена (CNAME)."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertIn("ШАГ 6", out)
        self.assertIn("CNAME", out)

    def test_contains_step_7_verification(self):
        """Шаг 7: Проверка."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertIn("ШАГ 7", out)
        self.assertIn("Проверк", out)

    def test_contains_step_8_final_cache_clear(self):
        """Шаг 8: Финал — очистка кэша CDN-ресурса."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertIn("ШАГ 8", out)
        self.assertIn("очистк", out.lower())  # «очистку кэша»

    def test_contains_all_8_steps(self):
        """Все 8 шагов присутствуют в выводе."""
        out = self._capture("example.com", "/api/v2/static.ts")
        for i in range(1, 9):
            self.assertIn(f"ШАГ {i}", out,
                f"Step {i} missing in output")

    def test_rewrite_from_to_substituted_correctly(self):
        """ОТКУДА/КУДА вычисляются правильно для разных path."""
        # Single-segment path
        out = self._capture("example.com", "/assets.ts")
        self.assertIn("ОТКУДА:  assets.ts/", out)
        self.assertIn("КУДА:    assets.ts", out)
        # Multi-segment path
        out = self._capture("example.com", "/api/v3/segment.ts")
        self.assertIn("ОТКУДА:  api/v3/segment.ts/", out)
        self.assertIn("КУДА:    api/v3/segment.ts", out)

    def test_rewrite_from_to_no_leading_slash(self):
        """В полях ОТКУДА/КУДА нет ведущего '/' (требование панели Beeline)."""
        out = self._capture("example.com", "/api/v2/static.ts")
        # Не должно быть '/api/v2/static.ts/' (с ведущим /) в ОТКУДА
        self.assertNotIn("ОТКУДА:  /api/v2/static.ts/", out)
        # Должно быть без ведущего /
        self.assertIn("ОТКУДА:  api/v2/static.ts/", out)

    def test_rewrite_trailing_slash_only_in_from(self):
        """Trailing '/' есть только в ОТКУДА, в КУДА его нет."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertIn("ОТКУДА:  api/v2/static.ts/", out)  # trailing /
        # КУДА — без trailing /
        # Ищем строку "КУДА:    api/v2/static.ts" (не "api/v2/static.ts/")
        # ВАЖНО: 'ОТКУДА' содержит подстроку 'КУДА', поэтому ищем строки
        # которые НЕ содержат 'ОТ' перед 'КУДА'.
        lines = out.split('\n')
        kuda_lines = [l for l in lines if 'КУДА:' in l and 'ОТКУДА' not in l]
        self.assertTrue(len(kuda_lines) > 0, "No КУДА line in output (without ОТКУДА)")
        for kuda_line in kuda_lines:
            # Должно содержать path без trailing /
            self.assertIn("api/v2/static.ts", kuda_line)
            # Но не должно заканчиваться на "static.ts/"
            self.assertFalse(re.search(r'static\.ts/\s*$', kuda_line),
                f"КУДА line must not have trailing slash: {kuda_line!r}")

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
        """Разные path → разный вывод (в т.ч. в ОТКУДА/КУДА)."""
        out1 = self._capture("example.com", "/api/v2/static.ts")
        out2 = self._capture("example.com", "/cdn/v3/signal.php")
        self.assertNotIn("/cdn/v3/signal.php", out1)
        self.assertNotIn("/api/v2/static.ts", out2)
        # ОТКУДА/КУДА тоже должны отличаться
        self.assertIn("api/v2/static.ts/", out1)
        self.assertIn("cdn/v3/signal.php/", out2)

    def test_output_size_reasonable(self):
        """Вывод имеет разумный размер (не пустой, не огромный)."""
        out = self._capture("example.com", "/api/v2/static.ts")
        self.assertGreater(len(out), 1000,
            f"Output too short: {len(out)} chars")
        self.assertLess(len(out), 50_000,
            f"Output too long: {len(out)} chars")


if __name__ == "__main__":
    unittest.main()
