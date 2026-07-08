"""
vless_installer/modules/tui.py
───────────────────────────────────────────────────────────────────────────────
TUI-компоненты для интерактивных форм и диалогов VLESS Ultimate Installer.

Содержит:
  • tui_input    — однострочный ввод с историей
  • tui_confirm  — диалог да/нет
  • tui_select   — выбор из списка стрелками
  • tui_progress — прогресс-бар
  • tui_form     — многострочная форма ввода

Точка входа из _core.py:
    from vless_installer.modules.tui import (
        tui_input, tui_confirm, tui_select, tui_progress, tui_form,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import sys
import re
import termios
import tty
from typing import Any
from vless_installer.modules.box_renderer import (
    _BOX_W, _box_top, _box_sep, _box_bottom, _box_row, _box_item,
    RED, GREEN, CYAN, BOLD, DIM, NC,
)
try:
    import unicodedata as _unicodedata
except ImportError:
    _unicodedata = None

def _is_tty() -> bool:
    """Проверяет что stdin и stdout — реальный терминал."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def _ansi_strip(s: str) -> str:
    return re.sub(r'\033\[[0-9;]*m', '', s)


def _vis_len(s: str) -> int:
    """Видимая ширина строки (без ANSI, с учётом emoji/CJK двойной ширины).
    Block elements (█░) и Box drawings (─│) считаются как 1 колонка."""
    _FORCE1 = (
        (0x2500, 0x259F),  # Box Drawing + Block Elements
        (0x25A0, 0x27BF),  # Geometric Shapes, Dingbats
    )
    w = 0
    for ch in _ansi_strip(s):
        cp = ord(ch)
        if any(lo <= cp <= hi for lo, hi in _FORCE1):
            w += 1
        else:
            eaw = _unicodedata.east_asian_width(ch)
            w += 2 if eaw in ('W', 'F') else 1
    return w


# ── базовый однострочный getch ────────────────────────────────────────────────

def _getch_raw() -> str:
    """
    Читает один (возможно многобайтный) кейстрок без echo.
    Возвращает строку: обычный символ, или ESC-последовательность,
    или спецкод: 'KEY_UP', 'KEY_DOWN', 'KEY_LEFT', 'KEY_RIGHT',
    'KEY_BACKSPACE', 'KEY_DELETE', 'KEY_HOME', 'KEY_END',
    'KEY_PGUP', 'KEY_PGDN', 'KEY_TAB', 'KEY_BTAB', '\r', '\n', '\x03'.
    """
    import termios, tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == '\x1b':
            # ESC-последовательность — читаем до конца
            rest = ''
            import select
            while True:
                r, _, _ = select.select([sys.stdin], [], [], 0.05)
                if not r:
                    break
                c = sys.stdin.read(1)
                rest += c
                if c.isalpha() or c == '~':
                    break
            seq = ch + rest
            _map = {
                '\x1b[A': 'KEY_UP',   '\x1bOA': 'KEY_UP',
                '\x1b[B': 'KEY_DOWN', '\x1bOB': 'KEY_DOWN',
                '\x1b[C': 'KEY_RIGHT','\x1bOC': 'KEY_RIGHT',
                '\x1b[D': 'KEY_LEFT', '\x1bOD': 'KEY_LEFT',
                '\x1b[H': 'KEY_HOME', '\x1b[F': 'KEY_END',
                '\x1b[1~': 'KEY_HOME','\x1b[4~': 'KEY_END',
                '\x1b[5~': 'KEY_PGUP','\x1b[6~': 'KEY_PGDN',
                '\x1b[3~': 'KEY_DELETE',
                '\x1b[Z': 'KEY_BTAB',
            }
            return _map.get(seq, seq)
        if ch in ('\x7f', '\x08'):
            return 'KEY_BACKSPACE'
        if ch == '\t':
            return 'KEY_TAB'
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


# ── tui_input ─────────────────────────────────────────────────────────────────

def tui_input(
    prompt:    str,
    default:   str = "",
    validator: "callable | None" = None,
    secret:    bool = False,
    max_len:   int  = 200,
    hint:      str  = "",
) -> str:
    """
    Строка ввода с валидацией на лету.

    validator(text) -> str | None
      None  — значение корректно
      str   — сообщение об ошибке (отображается красным под полем)

    Возвращает введённую строку (или default при пустом вводе).
    Graceful fallback на input() если не TTY.
    """
    if not _is_tty():
        raw = input(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
        return raw or default

    buf   = list(default)
    cur   = len(buf)
    err   = ""

    def _render():
        nonlocal err
        sys.stdout.write("\r\033[2K")          # очистить строку
        # подсказка
        text = ''.join(buf)
        display = ('*' * len(buf)) if secret else text
        err_txt = ""
        if validator:
            result = validator(text)
            err    = result or ""
        # строка ввода
        line = f"  {CYAN}{prompt}{NC}  {display}"
        if default and not buf:
            line += f"  {DIM}[{default}]{NC}"
        sys.stdout.write(line)
        sys.stdout.flush()
        # ошибка — на следующей строке
        if err:
            sys.stdout.write(f"\n  {RED}✗ {err}{NC}\033[A")  # вернуться на строку ввода
        elif hint:
            sys.stdout.write(f"\n  {DIM}{hint}{NC}\033[A")
        sys.stdout.flush()

    print()
    _render()

    while True:
        k = _getch_raw()

        if k in ('\r', '\n'):
            # очистить строку с ошибкой/hint
            sys.stdout.write("\n")
            if err:
                sys.stdout.write("\033[2K\033[A")
            print()
            result = ''.join(buf) or default
            return result

        elif k == '\x03':   # Ctrl+C
            sys.stdout.write("\n")
            raise KeyboardInterrupt

        elif k == 'KEY_BACKSPACE':
            if cur > 0:
                buf.pop(cur - 1)
                cur -= 1

        elif k == 'KEY_DELETE':
            if cur < len(buf):
                buf.pop(cur)

        elif k == 'KEY_LEFT':
            if cur > 0:
                cur -= 1

        elif k == 'KEY_RIGHT':
            if cur < len(buf):
                cur += 1

        elif k == 'KEY_HOME':
            cur = 0

        elif k == 'KEY_END':
            cur = len(buf)

        elif len(k) == 1 and k.isprintable():
            if len(buf) < max_len:
                buf.insert(cur, k)
                cur += 1

        _render()


# ── tui_confirm ───────────────────────────────────────────────────────────────

def tui_confirm(question: str, default: bool = False) -> bool:
    """
    [y/N] или [Y/n] диалог. Нажатие Enter = default.
    Graceful fallback.
    """
    if not _is_tty():
        hint = "Y/n" if default else "y/N"
        raw  = input(f"  {question} [{hint}]: ").strip().lower()
        if not raw:
            return default
        return raw.startswith('y')

    hint  = f"{GREEN}Y{NC}/{DIM}n{NC}" if default else f"{DIM}y{NC}/{RED}N{NC}"
    prompt = f"  {BOLD}{question}{NC}  [{hint}]  "
    sys.stdout.write(f"\n{prompt}")
    sys.stdout.flush()

    while True:
        k = _getch_raw().lower()
        if k in ('\r', '\n'):
            sys.stdout.write("\n\n")
            return default
        if k == 'y':
            sys.stdout.write(f"{GREEN}Да{NC}\n\n")
            return True
        if k in ('n', '\x1b'):
            sys.stdout.write(f"{RED}Нет{NC}\n\n")
            return False
        if k == '\x03':
            sys.stdout.write("\n")
            raise KeyboardInterrupt


# ── tui_select ────────────────────────────────────────────────────────────────

def tui_select(
    title:   str,
    options: "list[str]",
    default: int = 0,
) -> "int | None":
    """
    Выбор из списка стрелками ↑↓ + Enter. Esc/q = None (отмена).
    Возвращает индекс выбранного элемента или None.
    Graceful fallback: нумерованный список + input().
    """
    if not options:
        return None

    if not _is_tty():
        _box_top(title)
        for i, o in enumerate(options, 1):
            _box_item(str(i), o)
        _box_bottom()
        raw = input(f"  {CYAN}Выбор (1–{len(options)}):{NC} ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return int(raw) - 1
        return None

    cur = max(0, min(default, len(options) - 1))
    BOX = _BOX_W  # используем ту же ширину что у остального UI

    def _render():
        os.system("clear")
        print()
        _box_top(title)
        _box_row()
        for i, opt in enumerate(options):
            if i == cur:
                marker = f"{GREEN}▶{NC}"
                line   = f"  {marker} {BOLD}{opt}{NC}"
            else:
                marker = f"{DIM} {NC}"
                line   = f"  {marker} {DIM}{opt}{NC}"
            _box_row(line)
        _box_row()
        _box_row(f"  {DIM}↑↓ выбор  Enter подтвердить  Esc отмена{NC}")
        _box_bottom()

    _render()

    while True:
        k = _getch_raw()
        if k == 'KEY_UP':
            cur = (cur - 1) % len(options)
            _render()
        elif k == 'KEY_DOWN':
            cur = (cur + 1) % len(options)
            _render()
        elif k in ('\r', '\n'):
            return cur
        elif k in ('\x1b', 'q', '\x03'):
            if k == '\x03':
                raise KeyboardInterrupt
            return None


# ── tui_progress ──────────────────────────────────────────────────────────────

def tui_progress(
    label:   str,
    current: int,
    total:   int,
    width:   int = 40,
) -> None:
    """
    Рисует прогресс-бар в текущей строке терминала внутри стиля рамки.
    Вызывается повторно — перезаписывает строку через \\r.

      tui_progress("Загрузка", 45, 100)
      →  ║  Загрузка  [██████████████████░░░░░░░░░░░░░░░░░░░░]  45%  ║
    """
    pct    = min(100, int(current * 100 / total)) if total else 0
    filled = int(width * pct / 100)
    empty  = width - filled
    bar    = f"{GREEN}{'#' * filled}{NC}{DIM}{'-' * empty}{NC}"
    line   = f"  {label:<18}  [{bar}]  {BOLD}{pct:3d}%{NC}"
    # Печатаем внутри рамки
    pad = _BOX_W - _vis_len(line)
    sys.stdout.write(f"\r{CYAN}║{NC}{line}{' ' * max(0, pad)}{CYAN}║{NC}")
    sys.stdout.flush()
    if pct >= 100:
        sys.stdout.write("\n")
        sys.stdout.flush()


# ── tui_form ──────────────────────────────────────────────────────────────────

class TuiField:
    """Описание одного поля формы."""
    def __init__(
        self,
        key:       str,
        label:     str,
        default:   str = "",
        required:  bool = False,
        secret:    bool = False,
        validator: "callable | None" = None,
        hint:      str = "",
        max_len:   int = 200,
    ):
        self.key       = key
        self.label     = label
        self.default   = default
        self.required  = required
        self.secret    = secret
        self.validator = validator
        self.hint      = hint
        self.max_len   = max_len


def tui_form(
    title:  str,
    fields: "list[TuiField]",
) -> "dict[str, str] | None":
    """
    Многополевая форма. Tab/↓ — следующее поле, ↑ — предыдущее.
    Enter на последнем поле или пустой строке — подтвердить.
    Esc — отмена (возвращает None).

    Возвращает dict {field.key: value} или None при отмене.

    Graceful fallback: последовательный tui_input() для каждого поля.
    """
    if not fields:
        return {}

    values = {f.key: f.default for f in fields}

    if not _is_tty():
        # Fallback: последовательный ввод
        os.system("clear")
        print()
        _box_top(title)
        _box_row()
        try:
            for f in fields:
                def _v(text, _f=f):
                    if _f.required and not text:
                        return "Поле обязательно для заполнения"
                    return _f.validator(text) if _f.validator else None
                val = tui_input(
                    f.label, default=f.default,
                    validator=_v, secret=f.secret,
                    max_len=f.max_len, hint=f.hint,
                )
                values[f.key] = val
        except KeyboardInterrupt:
            return None
        _box_bottom()
        return values

    # ── TUI-режим ────────────────────────────────────────────────────────────
    cur_idx = 0
    bufs    = {f.key: list(f.default) for f in fields}
    cursors = {f.key: len(f.default)  for f in fields}
    errors  = {f.key: ""              for f in fields}

    def _validate_field(f: TuiField) -> str:
        text = ''.join(bufs[f.key])
        if f.required and not text:
            return "Поле обязательно для заполнения"
        if f.validator:
            return f.validator(text) or ""
        return ""

    def _render():
        os.system("clear")
        print()
        _box_top(title)
        _box_row()
        for i, f in enumerate(fields):
            active = (i == cur_idx)
            text   = ''.join(bufs[f.key])
            disp   = ('*' * len(bufs[f.key])) if f.secret else text
            err    = errors[f.key]

            if active:
                label_col = f"{BOLD}{CYAN}{f.label}{NC}"
                val_col   = f"{BOLD}{disp}{NC}{'_' if len(disp) < 40 else ''}"
                prefix    = f"  {GREEN}▶{NC}"
            else:
                label_col = f"{DIM}{f.label}{NC}"
                val_col   = f"{DIM}{disp if disp else f'[{f.default}]' if f.default else '—'}{NC}"
                prefix    = f"   "

            line = f"{prefix} {label_col:<28}  {val_col}"
            _box_row(line)

            if err:
                _box_row(f"     {RED}✗ {err}{NC}")
            elif active and f.hint:
                _box_row(f"     {DIM}ℹ {f.hint}{NC}")

        _box_sep()
        _box_row(f"  {DIM}Tab/↓ следующее  ↑ предыдущее  Enter подтвердить  Esc отмена{NC}")
        _box_bottom()

    _render()

    while True:
        k = _getch_raw()
        f = fields[cur_idx]

        if k in ('KEY_TAB', 'KEY_DOWN', '\r', '\n'):
            # валидируем текущее поле
            errors[f.key] = _validate_field(f)
            if errors[f.key]:
                _render()
                continue
            if cur_idx < len(fields) - 1:
                cur_idx += 1
                _render()
            else:
                # Последнее поле — финальная валидация всех
                all_ok = True
                for fi in fields:
                    errors[fi.key] = _validate_field(fi)
                    if errors[fi.key]:
                        all_ok = False
                if all_ok:
                    return {f.key: ''.join(bufs[f.key]) or f.default
                            for f in fields}
                # Перейти к первому полю с ошибкой
                cur_idx = next(
                    i for i, fi in enumerate(fields) if errors[fi.key]
                )
                _render()

        elif k == 'KEY_BTAB' or k == 'KEY_UP':
            errors[f.key] = _validate_field(f)
            cur_idx = max(0, cur_idx - 1)
            _render()

        elif k == '\x1b':
            return None

        elif k == '\x03':
            raise KeyboardInterrupt

        elif k == 'KEY_BACKSPACE':
            c = cursors[f.key]
            if c > 0:
                bufs[f.key].pop(c - 1)
                cursors[f.key] -= 1
                errors[f.key] = ""
                _render()

        elif k == 'KEY_DELETE':
            c = cursors[f.key]
            if c < len(bufs[f.key]):
                bufs[f.key].pop(c)
                errors[f.key] = ""
                _render()

        elif k == 'KEY_LEFT':
            cursors[f.key] = max(0, cursors[f.key] - 1)

        elif k == 'KEY_RIGHT':
            cursors[f.key] = min(len(bufs[f.key]), cursors[f.key] + 1)

        elif k == 'KEY_HOME':
            cursors[f.key] = 0

        elif k == 'KEY_END':
            cursors[f.key] = len(bufs[f.key])

        elif len(k) == 1 and k.isprintable():
            if len(bufs[f.key]) < f.max_len:
                c = cursors[f.key]
                bufs[f.key].insert(c, k)
                cursors[f.key] += 1
                errors[f.key] = ""
                _render()


