#!/usr/bin/env python3
"""scripts/release_notes.py — сборка JSON тела Forgejo Release из CHANGELOG.

Берёт ПЕРВУЮ запись CHANGELOG.md (до следующего '# Changelog new entry'),
вырезает markdown-фенси, режет до 60000 символов (лимит API) и пишет
готовый JSON в указанный файл.

Запуск: python3 scripts/release_notes.py <tag> <out.json>
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def first_changelog_entry(changelog: Path) -> str:
    """Первая запись `# Changelog new entry — …` независимо от преамбулы.

    Line-anchored ((?m)^…): упоминание формата записи в тексте/преамбуле
    (например, в бэктиках в шапке CHANGELOG.md) записью не считается.
    Работает и без преамбулы (файл, начинающийся сразу с записи) —
    миграция 2026-10-29 добавила преамбулу-политику над записями.
    """
    text = changelog.read_text(encoding="utf-8")
    parts = re.split(r"(?m)^# Changelog new entry — ", text)
    if len(parts) < 2:
        return ""
    first = parts[1]
    # до следующего разделителя записи (уже вырезан split-ом); хвостовой
    # мусор после конца первой записи отсутствует по построению split.
    lines = [l for l in first.strip().splitlines() if not l.strip().startswith("```")]
    return "\n".join(lines).strip()


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: release_notes.py <tag> <out.json>", file=sys.stderr)
        return 2
    tag, out = sys.argv[1], sys.argv[2]
    root = Path(__file__).resolve().parent.parent
    body = first_changelog_entry(root / "CHANGELOG.md")[:60000]
    payload = {
        "tag_name": tag,
        "name": f"Chimera {tag}",
        "body": body,
        "draft": False,
        "prerelease": False,
    }
    Path(out).write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    print(f"release notes: {len(body)} символов -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
