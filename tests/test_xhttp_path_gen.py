#!/usr/bin/env python3
"""
tests/test_xhttp_path_gen.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/xhttp_path_gen.py — генератор случайного
path-обманки для профиля «CDN masking».

Покрывает:
  1. generate_decoy_path() — формат пути (regex ^/[\\w-]+(/[\\w-]+){0,2}\\.(php|ts)$)
  2. Списки WORDS/VERSIONS/EXTS — идентичность bash-оригиналу install-caddy-node.sh
  3. Распределение: 1-3 сегмента, расширение из {php,ts}
  4. Воспроизводимость через secrets (каждый вызов даёт разный результат,
     но всегда валидный формат)
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


# Regex из ТЗ: ^/[\w-]+(/[\w-]+){0,2}\.(php|ts)$
# 1-3 сегмента (директорий/файл), расширение php или ts.
PATH_REGEX = re.compile(r"^/[\w-]+(/[\w-]+){0,2}\.(php|ts)$")


class TestGenerateDecoyPath(unittest.TestCase):
    """generate_decoy_path: корректный формат пути."""

    def setUp(self):
        from chimera.modules.xhttp_path_gen import generate_decoy_path
        self.gen = generate_decoy_path

    def test_returns_non_empty_string(self):
        """Функция возвращает непустую строку."""
        p = self.gen()
        self.assertIsInstance(p, str)
        self.assertGreater(len(p), 0)

    def test_starts_with_slash(self):
        """Путь всегда начинается с /."""
        for _ in range(100):
            p = self.gen()
            self.assertTrue(p.startswith("/"),
                            f"Path does not start with /: {p!r}")

    def test_ends_with_php_or_ts(self):
        """Путь всегда заканчивается на .php или .ts."""
        for _ in range(100):
            p = self.gen()
            self.assertTrue(p.endswith(".php") or p.endswith(".ts"),
                            f"Path does not end with .php/.ts: {p!r}")

    def test_matches_required_regex(self):
        """Все сгенерированные пути соответствуют regex из ТЗ."""
        for _ in range(500):
            p = self.gen()
            m = PATH_REGEX.match(p)
            self.assertIsNotNone(m,
                f"Path does not match required regex: {p!r}")

    def test_at_least_one_segment(self):
        """Путь содержит минимум 1 сегмент перед расширением."""
        for _ in range(100):
            p = self.gen()
            # Убираем ведущий / и расширение
            body = p[1:].rsplit(".", 1)[0]   # "api/v2/static" из "/api/v2/static.ts"
            segments = body.split("/")
            self.assertGreaterEqual(len(segments), 1,
                f"Path has <1 segments: {p!r}")

    def test_at_most_three_segments(self):
        """Путь содержит максимум 3 сегмента перед расширением."""
        for _ in range(100):
            p = self.gen()
            body = p[1:].rsplit(".", 1)[0]
            segments = body.split("/")
            self.assertLessEqual(len(segments), 3,
                f"Path has >3 segments: {p!r}")

    def test_no_empty_segments(self):
        """Путь не содержит пустых сегментов (//, trailing /)."""
        for _ in range(100):
            p = self.gen()
            # Не должно быть "//"
            self.assertNotIn("//", p, f"Double slash in path: {p!r}")
            # Не должно быть trailing / (кроме корня, но корень не генерируется)
            self.assertFalse(p.endswith("/"),
                f"Trailing slash in path: {p!r}")

    def test_segments_are_word_chars_or_hyphen(self):
        """Каждый сегмент состоит только из word chars и дефисов."""
        for _ in range(100):
            p = self.gen()
            body = p[1:].rsplit(".", 1)[0]
            for seg in body.split("/"):
                self.assertGreater(len(seg), 0,
                    f"Empty segment in path: {p!r}")
                self.assertTrue(re.fullmatch(r"[\w-]+", seg),
                    f"Invalid segment chars in {p!r}: segment={seg!r}")

    def test_extension_only_php_or_ts(self):
        """Расширение — строго php или ts."""
        for _ in range(200):
            p = self.gen()
            ext = p.rsplit(".", 1)[1]
            self.assertIn(ext, ("php", "ts"),
                f"Invalid extension: {ext!r} in path {p!r}")

    def test_different_paths_across_calls(self):
        """100 вызовов дают хотя бы 5 разных путей (стохастическая проверка)."""
        paths = {self.gen() for _ in range(100)}
        self.assertGreaterEqual(len(paths), 5,
            f"Too few unique paths in 100 calls: {len(paths)}")

    def test_word_segment_from_words_list(self):
        """Если сегмент не версия (v1/v2/...), то это слово из WORDS."""
        from chimera.modules.xhttp_path_gen import WORDS, VERSIONS
        words_set = set(WORDS)
        versions_set = set(VERSIONS)
        for _ in range(50):
            p = self.gen()
            body = p[1:].rsplit(".", 1)[0]
            for seg in body.split("/"):
                # Каждый сегмент — либо слово, либо версия
                self.assertTrue(seg in words_set or seg in versions_set,
                    f"Segment {seg!r} is neither in WORDS nor VERSIONS (path={p!r})")


class TestPathGenLists(unittest.TestCase):
    """Списки WORDS/VERSIONS/EXTS идентичны bash-оригиналу."""

    def test_WORDS_matches_bash_original(self):
        """WORDS — точно тот же список, что в install-caddy-node.sh (строка 33)."""
        from chimera.modules.xhttp_path_gen import WORDS
        expected = (
            "api cdn static media stream assets data content core edge node "
            "live cache gateway service push pull sync fetch upload chunk "
            "segment frame track session blob object store queue relay proxy "
            "hub channel feed source origin mirror vault bucket shard packet "
            "tile manifest playlist thumb preview render worker signal beacon "
            "pixel event report metric"
        ).split()
        self.assertEqual(WORDS, tuple(expected))
        self.assertEqual(len(WORDS), 54)

    def test_VERSIONS_matches_bash_original(self):
        """VERSIONS — точно тот же список, что в bash (строка 34)."""
        from chimera.modules.xhttp_path_gen import VERSIONS
        expected = "v1 v2 v3 v4 v5 v6 api2 r2 g2 beta stable latest".split()
        self.assertEqual(VERSIONS, tuple(expected))
        self.assertEqual(len(VERSIONS), 12)

    def test_EXTS_matches_bash_original(self):
        """EXTS — точно тот же список, что в bash (строка 35)."""
        from chimera.modules.xhttp_path_gen import EXTS
        self.assertEqual(EXTS, ("php", "ts"))


if __name__ == "__main__":
    unittest.main()
