from __future__ import annotations

"""Гард синхронизации тестовой навигации (миграция 2026-10-29):

1. docs/TESTS_INDEX.md свеж (генератор scripts/tests_index.py детерминирован);
2. манифест tests/ci_gate.txt ↔ файлы tests/test_*.py — взаимно полны
   (заголовок манифеста обещает «каждый test_*.py обязан быть здесь» —
   этот гард делает обещание проверяемым);
3. индекс упоминает каждый тест-файл ровно один раз.

Плоский layout tests/ — намеренный (см. докстринг scripts/tests_index.py):
перенос в подкаталоги сломал бы _PROJECT_ROOT = parent.parent в 299+ файлах.
"""

import re
import sys
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "scripts"))

from tests_index import build_index, gate_modules  # noqa: E402

TESTS_DIR = _PROJECT_ROOT / "tests"
INDEX = _PROJECT_ROOT / "docs" / "TESTS_INDEX.md"
GATE = TESTS_DIR / "ci_gate.txt"


class TestTestsIndex(unittest.TestCase):

    def test_index_fresh(self):
        """Индекс совпадает с генератором: добавлен/удалён тест или изменился
        докстринг/ci_gate — прогнать python3 scripts/tests_index.py."""
        self.assertTrue(INDEX.exists(), "docs/TESTS_INDEX.md отсутствует")
        current = INDEX.read_text(encoding="utf-8")
        fresh = build_index()
        self.assertEqual(current, fresh,
                         "docs/TESTS_INDEX.md устарел: "
                         "python3 scripts/tests_index.py")

    def test_ci_gate_covers_all_tests(self):
        """Каждый tests/test_*.py есть в манифесте, и в манифесте нет лишнего."""
        files = {p.name for p in TESTS_DIR.glob("test_*.py")}
        gate = gate_modules()
        missing = files - gate
        extra = gate - files
        self.assertFalse(missing,
                         f"тесты вне ci_gate.txt (добавьте в манифест): {sorted(missing)}")
        self.assertFalse(extra,
                         f"в ci_gate.txt нет файлов (уберите из манифеста): {sorted(extra)}")

    def test_gate_manifest_lines_valid(self):
        """Строки манифеста — валидные module-пути tests.test_*."""
        for line in GATE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            self.assertTrue(re.fullmatch(r"tests\.[A-Za-z0-9_]+", line),
                            f"мусорная строка манифеста: {line!r}")
            self.assertTrue((TESTS_DIR / (line.split(".", 1)[1] + ".py")).exists(),
                            f"модуль манифеста не существует: {line}")

    def test_index_lists_every_test_once(self):
        """Каждый тест-файл упомянут в индексе ровно один раз."""
        files = sorted(p.name for p in TESTS_DIR.glob("test_*.py"))
        text = INDEX.read_text(encoding="utf-8")
        for f in files:
            n = text.count(f"`{f}`")
            self.assertEqual(n, 1, f"{f}: упомянут {n} раз (ожидался 1)")

    def test_index_counts_match(self):
        """Сводные числа в шапке индекса соответствуют реальности."""
        text = INDEX.read_text(encoding="utf-8")
        files = {p.name for p in TESTS_DIR.glob("test_*.py")}
        gate = gate_modules()
        m_total = re.search(r"тест-модулей: \*\*(\d+)\*\*", text)
        m_gate = re.search(r"гейт-манифест: \*\*(\d+)\*\*", text)
        self.assertTrue(m_total and m_gate, "шапка индекса не содержит счётчиков")
        self.assertEqual(int(m_total.group(1)), len(files))
        self.assertEqual(int(m_gate.group(1)), len(gate))


if __name__ == "__main__":
    unittest.main()
