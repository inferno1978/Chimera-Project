#!/usr/bin/env python3
"""
scripts/fstring_compat_scan.py
───────────────────────────────────────────────────────────────────────────────
Сканер несовместимости f-строк с Python 3.10/3.11 (заявленный минимум,
INSTALL.md «Требования»). Класс бага — PEP 701: конструкции, легальные
только с Python 3.12:
  1) бэкслеш ВНУТРИ ВЫРАЖЕНИЯ f-строки {…}            → SyntaxError <3.12;
  2) кавычка-разделитель f-строки внутри её выражения → SyntaxError <3.12
     (для одно-разделительных f"…"/f'…'; тройные кавычки внутри
     выражений ТРОЙНЫХ f-строк легальны всегда).

Симптом в проде: модуль падает на import → пункт меню умирает целиком,
[CRITICAL] Неуважительная… ошибка (кейс 5c, xray_downgrade.py:495,
«f-string expression part cannot include a backslash», python 3.10).

Почему токенайзер, а не py_compile: на стенде 3.12+ py_compile ЭТОТ класс
не ловит (там синтаксис легален) — а тесты и песочница как раз на 3.12.
Токенайзер 3.12+ (FSTRING_START/MIDDLE/END) видит выражения f-строк как
обычные токены → сканер ловит нарушение именно там, где компилятор слеп.
На питонах <3.12 FSTRING-токенов нет — там достаточно py_compile
(интерпретатор сам отвергает), см. tests/test_py_compat.py.

Запуск: python3 scripts/fstring_compat_scan.py [пути…]   (по умолчанию — репо)
Выход: список «файл:строка: причина», exit 1 при находках.
"""
from __future__ import annotations

import io
import sys
import tokenize
from pathlib import Path
from typing import List, Tuple

Problem = Tuple[int, str]


def scan_source(src: str) -> List[Problem]:
    """Возвращает [(строка, описание)] нарушений PEP 701-класса в src.

    Работает на Python 3.12+; на старых питонах f-строки токенизируются
    как единый STRING (FSTRING-токенов нет) → всегда пустой список —
    там авторитетен py_compile.
    """
    problems: List[Problem] = []
    stack: List[dict] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            t = tok.type
            if t == tokenize.FSTRING_START:
                quote = tok.string[-1]
                stack.append({
                    "delim": quote,
                    "triple": tok.string.endswith(quote * 3),
                    "depth": 0,
                })
            elif t == tokenize.FSTRING_END:
                if stack:
                    stack.pop()
            elif stack:
                top = stack[-1]
                if t == tokenize.OP and tok.string == "{":
                    top["depth"] += 1
                elif t == tokenize.OP and tok.string == "}":
                    top["depth"] = max(0, top["depth"] - 1)
                elif top["depth"] > 0:
                    if "\\" in tok.string:
                        problems.append((
                            tok.start[0],
                            f"backslash in f-string expression: {tok.string!r}",
                        ))
                    elif (not top["triple"] and t == tokenize.STRING
                          and top["delim"] in tok.string):
                        problems.append((
                            tok.start[0],
                            f"delimiter quote {top['delim']!r} inside "
                            f"f-string expression: {tok.string!r}",
                        ))
    except tokenize.TokenError as e:
        problems.append((0, f"tokenize error: {e}"))
    return problems


def scan_file(path: Path) -> List[Problem]:
    try:
        return scan_source(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as e:
        return [(0, f"read error: {e}")]


def repo_python_files(roots: List[Path]) -> List[Path]:
    files: List[Path] = []
    for root in roots:
        if root.is_file() and root.suffix == ".py":
            files.append(root)
        elif root.is_dir():
            files.extend(sorted(root.rglob("*.py")))
    return [p for p in files if "__pycache__" not in p.parts and ".git" not in p.parts]


def main() -> int:
    roots = [Path(p) for p in sys.argv[1:]] or [Path("chimera"), Path("main.py"),
                                                 Path("full_test.py"),
                                                 Path("smoke_test_modules.py"),
                                                 Path("scripts"),
                                                 Path("tests")]
    total = 0
    for py in repo_python_files(roots):
        for line, msg in scan_file(py):
            print(f"{py}:{line}: {msg}")
            total += 1
    print(f"\n=== нарушений PEP 701-класса: {total}")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
