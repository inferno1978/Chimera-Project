from __future__ import annotations

"""Гард парсера release_notes: первая запись CHANGELOG — независимо от
преамбулы (миграция 2026-10-29 добавила шапку-политику над записями),
упоминание формата в тексте записью не считается, фенсы вырезаются.

Регрессия: старый парсер text.split("\\n# Changelog new entry — ")
брал parts[0] — с преамбулой это давало ТЕКСТ ПРЕАМБУЛЫ вместо записи
в тело Forgejo Release.
"""

import sys
import tempfile
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "scripts"))

from release_notes import first_changelog_entry  # noqa: E402

ENTRY1_HDR = "# Changelog new entry — FEAT(x): заголовок первой (29 Oct 2026)"
ENTRY1_BODY = "Тело первой записи."

ENTRY2_HDR = "# Changelog new entry — FIX(y): заголовок второй (28 Oct 2026)"
ENTRY2_BODY = "Тело второй записи."

PREAMBLE_WITH_MENTION = """# Changelog

> Формат: запись = `# Changelog new entry — <заголовок> (дата)`;
> новые записи добавляются СВЕРХУ.

---

"""


class TestFirstChangelogEntry(unittest.TestCase):

    def _write(self, content: str) -> Path:
        tmp = tempfile.NamedTemporaryFile(
            "w", suffix=".md", delete=False, encoding="utf-8")
        tmp.write(content)
        tmp.close()
        self.addCleanup(Path(tmp.name).unlink)
        return Path(tmp.name)

    def test_no_preamble_backward_compat(self):
        """Файл начинается сразу с записи (формат до миграции 2026-10-29)."""
        p = self._write(f"{ENTRY1_HDR}\n{ENTRY1_BODY}\n{ENTRY2_HDR}\n{ENTRY2_BODY}\n")
        got = first_changelog_entry(p)
        self.assertIn("FEAT(x): заголовок первой", got)
        self.assertIn(ENTRY1_BODY, got)
        self.assertNotIn("заголовок второй", got)

    def test_with_preamble_returns_entry_not_preamble(self):
        """Регрессия: с преамбулой парсер обязан вернуть ПЕРВУЮ ЗАПИСЬ,
        а не текст шапки (старый split('\\n# …') возвращал преамбулу)."""
        p = self._write(
            PREAMBLE_WITH_MENTION + f"{ENTRY1_HDR}\n{ENTRY1_BODY}\n"
            f"{ENTRY2_HDR}\n{ENTRY2_BODY}\n")
        got = first_changelog_entry(p)
        self.assertIn("FEAT(x): заголовок первой", got)
        self.assertIn(ENTRY1_BODY, got)
        self.assertNotIn("Формат: запись", got)
        self.assertNotIn("новые записи добавляются", got)
        self.assertNotIn("заголовок второй", got)

    def test_format_mention_is_not_entry(self):
        """Упоминание формата в бэктиках (даже с em-dash и датой) — не запись:
        line-anchored парсер матчит только заголовки на начале строки."""
        mention = "текст с `# Changelog new entry — упоминание (01 Jan 2020)` внутри строки\n"
        p = self._write(mention + f"\n{ENTRY1_HDR}\n{ENTRY1_BODY}\n")
        got = first_changelog_entry(p)
        self.assertIn("FEAT(x): заголовок первой", got)
        self.assertNotIn("упоминание", got)

    def test_code_fences_stripped(self):
        """Фенсы вырезаются как маркеры (контент внутри сохраняется) —
        поведение прежнего парсера, меняется только поиск записи."""
        body = "До фенса.\n\n```bash\nx=1\n```\n\nПосле фенса.\n"
        p = self._write(f"{ENTRY1_HDR}\n{body}\n{ENTRY2_HDR}\n{ENTRY2_BODY}\n")
        got = first_changelog_entry(p)
        self.assertIn("До фенса.", got)
        self.assertIn("После фенса.", got)
        self.assertNotIn("```", got)

    def test_no_entries_returns_empty(self):
        p = self._write("# Changelog\n\nзаписей нет\n")
        self.assertEqual(first_changelog_entry(p), "")

    def test_single_entry_no_trailing_separator(self):
        p = self._write(f"{ENTRY1_HDR}\n{ENTRY1_BODY}\n")
        got = first_changelog_entry(p)
        self.assertIn(ENTRY1_BODY, got)
        self.assertNotIn("# Changelog new entry", got)

    def test_real_repo_changelog(self):
        """Живой CHANGELOG.md репо: свежая запись находится, преамбула
        (политика объёма/архивы) в тело Release не попадает."""
        p = _PROJECT_ROOT / "CHANGELOG.md"
        if not p.exists():
            self.skipTest("CHANGELOG.md отсутствует")
        got = first_changelog_entry(p)
        self.assertTrue(got.strip(), "первая запись пуста")
        self.assertFalse(got.lstrip().startswith("#"), "тело начинается с заголовка-преамбулы")
        self.assertNotIn("Правило объёма", got)      # маркер преамбулы
        self.assertNotIn("| Архив | Период |", got)  # таблица ссылок преамбулы


if __name__ == "__main__":
    unittest.main()
