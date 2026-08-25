"""
chimera/modules/_tty_json.py
───────────────────────────────────────────────────────────────────────────────
Вспомогательный модуль для чтения произвольно-длинного JSON из TTY.

ПРОБЛЕМА:
  Python `input()` читает TTY в каноническом (ICANON) режиме. Буфер
  канонического режима в ядре Linux (N_TTY_BUF_SIZE) = 4096 байт.
  При вставке JSON длиннее 4096 байт одной строкой ядро молча усекает
  её до ~4096 байт — остальные байты теряются ДО того, как их увидит
  Python. json.loads() получает обрезанную строку и падает с ошибкой
  вида «Unterminated string starting at: line 1 column 4092 (char 4091)».

  Большие b4-сеты (Meta-facebook-v18-MAX, Meta-instagram-v18-MAX и т.п.)
  с dns.pins на 25+ доменов весят 8-15 КБ и регулярно упираются в этот
  лимит. Web UI B4 импортирует их без проблем (REST API без TTY-буфера),
  а TUI Chimera — падает.

РЕШЕНИЕ:
  Переключить stdin в cbreak-режим (termios: убрать ICANON, оставить ECHO)
  на время чтения. В cbreak-режиме нет 4-КБ буфера строки — ядро отдаёт
  байты по одному. Читаем посимвольно, считаем глубину фигурных скобок
  с учётом строк и escape-последовательностей, останавливаемся когда
  глубина возвращается к 0 после первой '{'.

  Если stdin — не TTY (pipe/тест/redirect), читаем sys.stdin.read() до EOF.

ИСПОЛЬЗОВАНИЕ:
  from chimera.modules._tty_json import read_long_json_stdin
  json_str = read_long_json_stdin()
  if not json_str:
      _warn("Пустой ввод.")
      return
  import_custom_set(json_str)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import sys
from typing import Optional


def _read_long_json_readline_fallback() -> str:
    """Запасной вариант, если raw/cbreak-режим недоступен.

    Читает построчно через input(). Работает для многострочного JSON
    (например, `json.dumps(..., indent=2)`), но НЕ работает для длинных
    однострочных JSON > 4 КБ — это и есть изначальная проблема, из-за
    которой существует этот модуль. Используется только если termios
    недоступен (Windows, sandbox без TTY-атрибутов и т.п.).
    """
    lines: list[str] = []
    try:
        while True:
            line = input()
            if not line.strip():
                break
            lines.append(line)
            joined = "".join(lines).strip()
            if joined.startswith("{") and joined.endswith("}"):
                break
    except (KeyboardInterrupt, EOFError):
        pass
    return "\n".join(lines)


def _brace_aware_read(fd: int, old_attrs) -> str:
    """Считывает JSON посимвольно в cbreak-режиме, считая глубину скобок.

    Возвращает JSON-строку (без лидирующих/хвостовых пробелов) или ""
    при отмене (Ctrl+C / Ctrl+D без данных).
    """
    import termios
    import tty

    try:
        # cbreak: убрать ICANON (нет 4-КБ буфера), оставить ECHO (юзер
        # видит что вводит). Сигналы (Ctrl+C, Ctrl+D) тоже оставляем.
        tty.setcbreak(fd)
    except Exception:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)
        except Exception:
            pass
        return _read_long_json_readline_fallback()

    buf: list[str] = []
    depth = 0          # глубина '{' (вне строк)
    in_string = False  # внутри "..."?
    escape = False     # предыдущий символ — '\'?
    saw_open = False   # видел открывающую '{'?

    try:
        while True:
            ch = sys.stdin.read(1)
            if not ch:                # EOF (Ctrl+D в начале)
                break
            if ch == "\x03":          # Ctrl+C — отмена
                raise KeyboardInterrupt
            if ch == "\x04":          # Ctrl+D — конец ввода
                break
            # Ctrl+R / Ctrl+L / Backspace и пр. игнорируем — для вставки
            # они не важны; обратно-совместимое поведение input() тут не нужно.

            if not saw_open:
                # Пропускаем мусор до первой '{' (пробелы, BOM, переносы).
                if ch.isspace():
                    continue
                if ch == "{":
                    saw_open = True
                    depth = 1
                    buf.append(ch)
                # Любой другой символ до '{' — игнорируем (включая BOM).
                continue

            if in_string:
                buf.append(ch)
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
                continue

            # Вне строки, после первой '{'.
            buf.append(ch)
            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            # '[' и ']' не считаем: b4-сет на верхнем уровне — это объект,
            # не массив. Если внутри объекта есть массивы, их скобки тоже
            # можно не считать: глубина по '{'/'}' корректно отследит
            # конец объекта.

        if not saw_open:
            return ""
        return "".join(buf)
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)
        except Exception:
            pass


def read_long_json_stdin() -> str:
    """Читает произвольно длинный JSON из stdin (TTY-aware).

    TTY: переключает stdin в cbreak-режим (termios), читает посимвольно,
    останавливается когда глубина '{...}' возвращается к 0. Echo
    остаётся включённым — юзер видит вставленные символы.

    Не-TTY (pipe/redirect/тест): читает sys.stdin.read() до EOF.

    Returns:
        JSON-строка без лидирующих/хвостых пробелов, или "" если ввод
        пустой или отменён (Ctrl+C/Ctrl+D без данных).

    Raises:
        KeyboardInterrupt: при Ctrl+C.
    """
    # Если stdin — не TTY (pipe, тесты, ssh -T), termios неприменим.
    # Читаем всё до EOF — это работает для любого размера.
    if not sys.stdin.isatty():
        try:
            return sys.stdin.read().strip()
        except (KeyboardInterrupt, EOFError):
            return ""

    # TTY — нужен cbreak для обхода 4-КБ буфера ICANON.
    try:
        import termios
        fd = sys.stdin.fileno()
        old_attrs = termios.tcgetattr(fd)
    except Exception:
        # termios недоступен (Windows и пр.) — запасной readline.
        return _read_long_json_readline_fallback()

    return _brace_aware_read(fd, old_attrs)
