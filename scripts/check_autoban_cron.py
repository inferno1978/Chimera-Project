#!/usr/bin/env python3
"""Проверка inline cron-скрипта в chimera/modules/autoban.py.

Скрипт `_autoban_install_cron()` генерирует Python-код как f-string и
записывает его в `/usr/local/bin/xray-autoban.sh`. Этот валидатор извлекает
тело скрипта из исходника, подставляет переменные (threshold=10, window=5)
и парсит через `ast` — должны получить валидный Python.

Запуск:
    python3 scripts/check_autoban_cron.py

Используется для регрессионной проверки после правок `py_body` в
`chimera/modules/autoban.py` — особенно после встраивания DoH-резолвера
(см. CHANGELOG: "DoH-резолв во всех модулях — массовый фикс «старого IP»").
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path


def main() -> int:
    # Путь к autoban.py — относительно этого скрипта (репо-agnostic).
    autoban_py = Path(__file__).resolve().parent.parent / "chimera" / "modules" / "autoban.py"
    if not autoban_py.exists():
        print(f"FAIL: {autoban_py} не найден")
        return 2

    src = autoban_py.read_text(encoding="utf-8")

    # Извлекаем f-string тело: всё между `py_body = f"""` и закрывающей `"""`
    m = re.search(r'py_body = f"""(.*?)"""', src, re.DOTALL)
    if not m:
        print('FAIL: не нашёл py_body = f"""...""" в autoban.py')
        return 2

    body_template = m.group(1)

    # Подставляем переменные (как делает f-string в _autoban_install_cron).
    threshold = 10
    window = 5
    body = body_template.format(threshold=threshold, window=window)

    # Парсим как Python.
    try:
        ast.parse(body)
        print(f"OK: inline cron-скрипт валиден ({len(body)} байт)")
        return 0
    except SyntaxError as e:
        print(f"FAIL: SyntaxError в inline cron-скрипте: {e}")
        lines = body.splitlines()
        for i, line in enumerate(
            lines[max(0, (e.lineno or 1) - 3):(e.lineno or 1) + 2],
            start=max(1, (e.lineno or 1) - 2),
        ):
            marker = ">>> " if i == e.lineno else "    "
            print(f"{marker}{i:4d}: {line}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
