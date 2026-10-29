#!/usr/bin/env python3
"""
scripts/const_default_scan.py
───────────────────────────────────────────────────────────────────────────────
CI-сканер класса «path-константа в дефолт-аргументе». Класс дважды ловился
на живых нодах и один раз найден аудитом — закрываем навсегда, как класс:

  • cb461fa — dpi_gate.load_model(MODEL_PATH в дефолте): патч константы в
    тестах не действовал на прод-вызов, тест зелёный — прод ходил по
    старому пути («патч в тестах не работал при существующей прод-модели,
    поймано на живой ноде»);
  • 3783ee3 — mask_gate.get_xray_port_from_state(STATE_FILE в дефолте):
    тот же паттерн, пойман фидбеком прод-пользователя;
  • аудит 29.10.2026 — ещё 7 экземпляров в telemt_fallback.py.

Механика бага: def f(p: Path = STATE_FILE) вычисляет дефолт ОДИН раз при
импорте модуля. Следствия:
  1) patch.object(mod, "STATE_FILE", tmp) в тестах меняет константу, но
     НЕ дефолт-аргумент — тест гоняет tmp-путь, прод молча ходит по
     оригинальному;
  2) runtime-резолв пути (env / state / argv) невозможен в принципе.

Лечение: p: Optional[Path] = None + резолв в теле функции:
    p = Path(p) if p else STATE_FILE

Правило сканера: флагуются дефолт-аргументы, являющиеся
  • Name, разрешающимся в module-level константу, значение которой —
    Path(...) (в т.ч. склейка через BinOp /: BASE / "file.json"), либо
  • прямым литералом Path(...) в сигнатуре.
Str/int-константы в дефолтах НЕ флагуются (иммутабельны, в этом классе
не встречались — правило держим узким, без ложных срабатываний).

Цели: chimera/ + main.py (scripts/ и tests/ — вне класса: там нет
runtime-патчей прод-констант).

Запуск: python3 scripts/const_default_scan.py [пути…]  (по умолчанию — репо)
Выход: список «файл:строка: def имя(…=CONST)», exit 1 при находках.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import List, Optional, Sequence

Problem = List[str]

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Цели по умолчанию: прод-код, где живут runtime-патчи констант
DEFAULT_TARGETS = (_PROJECT_ROOT / "chimera", _PROJECT_ROOT / "main.py")


def _is_path_expr(e: ast.expr, depth: int = 0) -> bool:
    """True, если выражение — Path(...) или склейка X / "…", где X — путь."""
    if depth > 8:
        return False
    if isinstance(e, ast.Call) and isinstance(e.func, ast.Name) \
            and e.func.id == "Path":
        return True
    if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Div):
        return _is_path_expr(e.left, depth + 1) or \
               _is_path_expr(e.right, depth + 1)
    return False


def _module_path_consts(tree: ast.Module) -> set:
    """Имена module-level констант, значения которых — path-выражения."""
    consts = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and _is_path_expr(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    consts.add(t.id)
        elif (isinstance(node, ast.AnnAssign) and node.value is not None
                and _is_path_expr(node.value)
                and isinstance(node.target, ast.Name)):
            consts.add(node.target.id)
    return consts


def scan_source(src: str, filename: str = "<src>") -> Problem:
    """Возвращает список находок 'файл:строка: def имя(…=CONST)' в src."""
    findings: Problem = []
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return findings  # синтакс-ошибки ловит compileall-этап CI
    consts = _module_path_consts(tree)
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for d in list(func.args.defaults) + \
                  [k for k in func.args.kw_defaults if k is not None]:
            if isinstance(d, ast.Name) and d.id in consts:
                findings.append(
                    f"{filename}:{func.lineno}: def {func.name}("
                    f"…={d.id}) — path-константа в дефолт-аргументе; "
                    f"лечится Optional[Path]=None + резолв в теле")
            elif isinstance(d, ast.Call) and isinstance(d.func, ast.Name) \
                    and d.func.id == "Path":
                findings.append(
                    f"{filename}:{func.lineno}: def {func.name}("
                    f"…=Path(...)) — path-литерал в дефолт-аргументе; "
                    f"лечится Optional[Path]=None + резолв в теле")
    return findings


def scan_path(target: Path) -> Problem:
    """Сканирует файл или дерево (по *.py)."""
    target = Path(target)
    files = ([target] if target.is_file()
             else sorted(target.rglob("*.py")))
    findings: Problem = []
    for py in files:
        try:
            src = py.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(scan_source(src, str(py)))
    return findings


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    targets = [Path(a) for a in args] if args else list(DEFAULT_TARGETS)
    findings: Problem = []
    for t in targets:
        findings.extend(scan_path(t))
    if findings:
        print("const-default сканер: НАЙДЕНЫ экземпляры класса "
              "(см. scripts/const_default_scan.py):")
        for f in findings:
            print(f"  {f}")
        print(f"Всего: {len(findings)}. Лечение: Optional[Path]=None + "
              f"резолв в теле функции.")
        return 1
    print("const-default сканер: чисто (0 находок в chimera/ + main.py)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
