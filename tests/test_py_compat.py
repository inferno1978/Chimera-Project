#!/usr/bin/env python3
"""
tests/test_py_compat.py
───────────────────────────────────────────────────────────────────────────────
Гард совместимости исходников с Python 3.10/3.11 — заявленным минимумом
(INSTALL.md «Требования»: Python 3.10+, рекомендуется 3.12).

Класс бага (PEP 701 — легален только с Python 3.12): бэкслеш или
кавычка-разделитель ВНУТРИ ВЫРАЖЕНИЯ f-строки {…}. Почему он живучий:
на 3.12+ код компилируется, все тесты зелёные — а на 3.10/3.11 модуль
падает SyntaxError ещё на import, пункт меню умирает целиком со scary
[CRITICAL]-обвязкой. Прод-кейс: «Даунгрейд ядра» (5c), python 3.10,
chimera/modules/xray_downgrade.py:495 — «f-string expression part
cannot include a backslash»; там же скрытая вторая мина — вложенная
f', …{info['strategy']}…' в awg_cascade_lb.py:1618 (unmatched '[').

Три метода, взаимодополняющие на любой версии стенда:
  1. compile() каждого файла — на 3.10/3.11 ловит нарушение нативно
     (интерпретатор сам его отвергает); на 3.12+ остаётся дым-проверкой
     синтаксиса;
  2. токенайзер-сканер (только 3.12+, FSTRING-токены) — ловит нарушение
     именно там, где py_compile слеп: на новом питоне стенда;
  3. ast.parse(feature_version=(3,10)) — гард от прочих >3.10-синтаксис
     (except* 3.11, type-параметры 3.12); PEP 701 он НЕ гейтит
     (проверено), потому и нужен метод 2.

Сканер живёт в scripts/fstring_compat_scan.py (CLI для человека),
тест импортирует его логику — одна точка правды.
"""
from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "scripts"))
sys.path.insert(0, str(_PROJECT_ROOT / "tests"))

from fstring_compat_scan import scan_source  # noqa: E402

# «Плохие» сэмплы собраны КОНКАТЕНАЦИЕЙ (не одним литералом!): сам
# тест-файл обязан оставаться чистым от того, что он ловит, — иначе
# сканер в test_no_pep701_violations найдёт их здесь же. Второй сэмпл
# собирает ПРОД-паттерн {x or '\"\"'} с настоящими бэкслешами в значении
# (литерал "…\\\"…" в исходнике теста даёт как раз backslash+dquote).
_BAD_BACKSLASH = "v = f\"{x or " + "'\\\"\\\"'" + "}\""
_BAD_SAME_QUOTE = "v = f'{d['k']}'"
_GOOD_CASES = [
    ("простая f-строка", 'v = f"{x}"'),
    ("одинарные ключи в двойной f-строке", 'v = f"{d[\'k\']}"'),
    ("бэкслеш-эскейп в ЛИТЕРАЛЬНОЙ части", 'v = f"lit\\n{x}"'),
    ("удвоенные фигурные", 'v = f"{{not-expression}} {x}"'),
    ("тройная f-строка с ключами", "v = f'''{d['k']}'''"),
    ("вложенная f с другим разделителем", 'v = f"{f\'{x}\'}"'),
    ("константа вместо литерала", 'E = \'""\'\nv = f"{x or E}"'),
]


def _repo_python_files():
    """Все .py репо (кроме __pycache__/.git): chimera/ (с _vendor),
    tests/, scripts/, точка-входа и автономные прогоны."""
    roots = [
        _PROJECT_ROOT / "chimera",
        _PROJECT_ROOT / "tests",
        _PROJECT_ROOT / "scripts",
    ]
    files = []
    for root in roots:
        files.extend(sorted(root.rglob("*.py")))
    for name in ("main.py", "full_test.py", "smoke_test_modules.py"):
        p = _PROJECT_ROOT / name
        if p.is_file():
            files.append(p)
    return [p for p in files if "__pycache__" not in p.parts]


class PyCompatGuard(unittest.TestCase):
    """PEP 701 и прочий >3.10 синтаксис не должны попадать в исходники."""

    maxDiff = None

    def test_repo_compiles_on_this_python(self):
        """compile() каждого файла: на 3.10/3.11 нативно ловит PEP 701,
        на любом стенде — прочие синтакс-поломки."""
        failures = []
        for py in _repo_python_files():
            try:
                compile(py.read_text(encoding="utf-8"), str(py), "exec")
            except SyntaxError as e:
                failures.append(f"{py}:{e.lineno}: {e.msg}")
        self.assertEqual(
            failures, [],
            "Файлы, не компилирующиеся текущим интерпретатором "
            f"(python {sys.version.split()[0]}):\n" + "\n".join(failures),
        )

    def test_no_pep701_violations(self):
        """Токенайзер-сканер: на 3.12+ стендах, где py_compile слеп к
        PEP 701, нарушения ловит разбор FSTRING-токенов."""
        if sys.version_info < (3, 12):
            self.skipTest("на <3.12 FSTRING-токенов нет; там ловит compile()")
        offenders = []
        for py in _repo_python_files():
            for line, msg in scan_source(py.read_text(encoding="utf-8")):
                offenders.append(f"{py}:{line}: {msg}")
        self.assertEqual(
            offenders, [],
            "Конструкции, легальные ТОЛЬКО на Python 3.12 (PEP 701) — "
            "валют заявленный минимум 3.10/3.11 (SyntaxError на import):\n"
            + "\n".join(offenders),
        )

    def test_no_post_310_syntax(self):
        """Гард от синтаксиса новее 3.10 (except*, type-параметры, …)."""
        failures = []
        for py in _repo_python_files():
            try:
                ast.parse(py.read_text(encoding="utf-8"),
                          feature_version=(3, 10))
            except SyntaxError as e:
                failures.append(f"{py}:{e.lineno}: {e.msg}")
        self.assertEqual(
            failures, [],
            "Синтаксис новее Python 3.10 (заявленный минимум):\n"
            + "\n".join(failures),
        )

    def test_scanner_detects_known_bad_patterns(self):
        """Самопроверка сканера: он обязан ловить оба прод-паттерна и
        НЕ трогать легальные до-3.12 формы (иначе гард тихо слепнет)."""
        if sys.version_info < (3, 12):
            self.skipTest("сканер определён для токенайзера 3.12+")
        found = scan_source(_BAD_BACKSLASH)
        self.assertTrue(
            any("backslash" in m.lower() for _, m in found),
            f"сканер пропустил бэкслеш в выражении: {found}",
        )
        found = scan_source(_BAD_SAME_QUOTE)
        self.assertTrue(
            any("delimiter quote" in m.lower() for _, m in found),
            f"сканер пропустил кавычку-разделитель в выражении: {found}",
        )
        for label, snippet in _GOOD_CASES:
            found = scan_source(snippet)
            self.assertEqual(
                found, [],
                f"ложное срабатывание на легальном до-3.12 случае "
                f"«{label}»: {found}",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
