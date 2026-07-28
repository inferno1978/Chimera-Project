#!/usr/bin/env python3
"""
tests/test_no_streamup_typo.py
───────────────────────────────────────────────────────────────────────────────
Регрессионный тест на опечатку "streamup" (без дефиса).

Валидные значения xhttpSettings.mode по документации Xray-core:
  "auto", "packet-up", "stream-up", "stream-one"
(все, кроме auto, через дефис).

В коде проекта была опечатка "streamup" (слитно, без дефиса) — Xray не
знает такого значения, клиент не может подключиться. Эта опечатка
просочилась через 20+ "зелёных" тестов, потому что тесты сами содержали
ту же опечатку и проверяли код против самого себя.

Этот тест grep'ает весь chimera/ и tests/ на regex `streamup(?!-)` —
ноль совпадений. Если кто-то в будущем коммите снова напишет "streamup"
(без дефиса), этот тест упадёт.

Также проверяет "streamone" и "packetup" (тоже опечатки от "stream-one"
и "packet-up" соответственно).
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _grep_typo(pattern: str, directories: list[Path]) -> list[tuple[Path, int, str]]:
    """Ищет regex pattern в .py файлах, возвращает список (file, line_no, line).

    Исключает сам этот тестовый файл (он содержит слова 'streamup'/'streamone'/
    'packetup' в docstrings и комментариях — это НЕ опечатки в коде, а
    описание того, что тест проверяет).
    """
    results = []
    regex = re.compile(pattern)
    self_file = Path(__file__).resolve()
    for d in directories:
        if not d.exists():
            continue
        for py_file in d.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            if py_file.resolve() == self_file:
                continue  # не проверяем сам себя
            try:
                lines = py_file.read_text(encoding="utf-8").splitlines()
            except Exception:
                continue
            for i, line in enumerate(lines, 1):
                if regex.search(line):
                    results.append((py_file, i, line.strip()))
    return results


class TestNoStreamupTypo(unittest.TestCase):
    """Опечатка "streamup" (без дефиса) не должна встречаться нигде в коде.

    Регрессия: опечатка "streamup" присутствовала с самого начала фичи XHTTP
    и не была поймана 20+ тестами, потому что тесты сами содержали ту же
    опечатку. Только когда реальный пользователь (zvshka) не смог
    подключиться и мы сверились с документацией Xray-core, выяснилось, что
    правильное значение — "stream-up" (через дефис).
    """

    def test_no_streamup_in_chimera_modules(self):
        """В chimera/modules/ нет 'streamup' (без дефиса)."""
        hits = _grep_typo(r"streamup(?!-)", [_PROJECT_ROOT / "chimera"])
        self.assertEqual(hits, [],
            f"Found 'streamup' typo (should be 'stream-up') in chimera/:\n" +
            "\n".join(f"  {f}:{line}: {text}" for f, line, text in hits))

    def test_no_streamup_in_tests(self):
        """В tests/ нет 'streamup' (без дефиса)."""
        hits = _grep_typo(r"streamup(?!-)", [_PROJECT_ROOT / "tests"])
        self.assertEqual(hits, [],
            f"Found 'streamup' typo (should be 'stream-up') in tests/:\n" +
            "\n".join(f"  {f}:{line}: {text}" for f, line, text in hits))

    def test_no_streamup_in_scripts(self):
        """В scripts/ нет 'streamup' (без дефиса)."""
        hits = _grep_typo(r"streamup(?!-)", [_PROJECT_ROOT / "scripts"])
        self.assertEqual(hits, [],
            f"Found 'streamup' typo (should be 'stream-up') in scripts/:\n" +
            "\n".join(f"  {f}:{line}: {text}" for f, line, text in hits))

    def test_no_streamone_typo(self):
        """Нет 'streamone' (без дефиса) — должно быть 'stream-one'."""
        hits = _grep_typo(r"streamone(?!-)", [_PROJECT_ROOT / "chimera",
                                                _PROJECT_ROOT / "tests",
                                                _PROJECT_ROOT / "scripts"])
        self.assertEqual(hits, [],
            f"Found 'streamone' typo (should be 'stream-one'):\n" +
            "\n".join(f"  {f}:{line}: {text}" for f, line, text in hits))

    def test_no_packetup_typo(self):
        """Нет 'packetup' (без дефиса) — должно быть 'packet-up'."""
        hits = _grep_typo(r"packetup(?!-)", [_PROJECT_ROOT / "chimera",
                                               _PROJECT_ROOT / "tests",
                                               _PROJECT_ROOT / "scripts"])
        self.assertEqual(hits, [],
            f"Found 'packetup' typo (should be 'packet-up'):\n" +
            "\n".join(f"  {f}:{line}: {text}" for f, line, text in hits))

    def test_stream_up_present_as_default(self):
        """'stream-up' (с дефисом) присутствует как дефолт в _core.py."""
        core_path = _PROJECT_ROOT / "chimera" / "_core.py"
        content = core_path.read_text(encoding="utf-8")
        self.assertIn('XHTTP_MODE: str = "stream-up"', content,
            "XHTTP_MODE default must be 'stream-up' (with hyphen)")


if __name__ == "__main__":
    unittest.main()
