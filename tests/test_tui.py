#!/usr/bin/env python3
"""
tests/test_tui.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/tui.py.

Покрывает:
  1. _is_tty — проверка TTY
  2. _ansi_strip — удаление ANSI-кодов
  3. _vis_len — вычисление видимой ширины строки
"""
from __future__ import annotations
import sys, unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

def _setup_core():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text(); g = {}
    with patch.object(Path, 'mkdir', lambda s,*a,**k: None), \
         patch.object(Path, 'touch', lambda s,*a,**k: None), \
         patch.object(Path, 'chmod', lambda s,*a,**k: None), \
         patch('os.chown', lambda *a,**k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types; m = types.ModuleType("chimera._core"); m.__dict__.update(g)
    sys.modules["chimera._core"] = m

class TestIsTty(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_returns_bool(self):
        from chimera.modules.tui import _is_tty
        self.assertIsInstance(_is_tty(), bool)

class TestAnsiStrip(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_plain_string(self):
        from chimera.modules.tui import _ansi_strip
        self.assertEqual(_ansi_strip("hello"), "hello")
    def test_strips_ansi(self):
        from chimera.modules.tui import _ansi_strip
        self.assertEqual(_ansi_strip("\033[1;31mhi\033[0m"), "hi")
    def test_empty(self):
        from chimera.modules.tui import _ansi_strip
        self.assertEqual(_ansi_strip(""), "")

class TestVisLen(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_ascii(self):
        from chimera.modules.tui import _vis_len
        self.assertEqual(_vis_len("hello"), 5)
    def test_cjk(self):
        from chimera.modules.tui import _vis_len
        self.assertEqual(_vis_len("中文"), 4)
    def test_ansi_zero_width(self):
        from chimera.modules.tui import _vis_len
        self.assertEqual(_vis_len("\033[1mhi\033[0m"), 2)
    def test_empty(self):
        from chimera.modules.tui import _vis_len
        self.assertEqual(_vis_len(""), 0)

# ── кейс 04.11 «стрелки убивают меню»: pty-прогоны _getch_raw/tui_select ────
# Регресс: sys.stdin.read(1) затягивал хвост \x1b[B в буфер Python, где его
# не видел select → стрелка возвращалась голым '\x1b' → tui_select закрывал
# меню как Esc-отмену. Читаем os.read'ом с реального pty — терминал как в
# SSH-сессии, последовательность кормится атомарным write.

import os as _os, re as _re, select as _select, time as _time
import pty as _pty

_PTYSLEEP = 0.25          # ребёнок успевает дойти до setraw/read


def _pty_wait(pid):
    for _ in range(40):
        try:
            wpid, _ = _os.waitpid(pid, _os.WNOHANG)
            if wpid:
                return
        except ChildProcessError:
            return
        _time.sleep(0.05)
    try:
        _os.kill(pid, 9)
        _os.waitpid(pid, 0)
    except Exception:
        pass


def _pty_run(feed, child, marker, feed2=None, feed2_gap=0.15, settle=0.0):
    """Ребёнок на pty исполняет child() (пишет '<marker>...'), родитель
    кормит feed атомарным write (опц. feed2 вторым пакетом через 150 мс,
    settle — тишина после кормления). Возвращает захваченный текст."""
    pid, fd = _pty.fork()
    if pid == 0:
        _os.environ.setdefault("TERM", "xterm")
        try:
            child()
        except BaseException as e:
            try:
                _os.write(2, ("\nCHILDFAIL=" + repr(e) + "\n").encode())
            except Exception:
                pass
        finally:
            _os._exit(0)
    try:
        _time.sleep(_PTYSLEEP)
        _os.write(fd, feed)
        if feed2:
            _time.sleep(feed2_gap)
            _os.write(fd, feed2)
        if settle:
            _time.sleep(settle)
        out = b""
        deadline = _time.time() + 5
        mb = marker.encode()
        while _time.time() < deadline:
            r, _, _ = _select.select([fd], [], [], 0.1)
            if not r:
                if mb in out:
                    break
                continue
            try:
                chunk = _os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
            if mb in out:
                break
        _pty_wait(pid)
        return out.decode("utf-8", "replace")
    finally:
        try:
            _os.close(fd)
        except OSError:
            pass


class TestGetchRawPty(unittest.TestCase):
    """_getch_raw на реальном pty: хвост ESC-последовательности приходит
    тем же пакетом, что и ESC (как из SSH-сессии)."""

    def setUp(self):
        _setup_core()

    def _getch(self, feed, feed2=None, feed2_gap=0.15, settle=0.0):
        def child():
            from chimera.modules.tui import _getch_raw
            _os.write(1, ("\nGETCH=" + repr(_getch_raw()) + "\n").encode())
        text = _pty_run(feed, child, "GETCH=", feed2=feed2, feed2_gap=feed2_gap, settle=settle)
        self.assertNotIn("CHILDFAIL", text, text[:400])
        m = _re.search(r"GETCH=(.+?)\n", text)
        self.assertIsNotNone(m, text[:400])
        return m.group(1).strip()

    def test_arrow_down(self):
        self.assertEqual(self._getch(b"\x1b[B"), "'KEY_DOWN'")
    def test_arrow_up(self):
        self.assertEqual(self._getch(b"\x1b[A"), "'KEY_UP'")
    def test_arrow_left(self):
        self.assertEqual(self._getch(b"\x1b[D"), "'KEY_LEFT'")
    def test_arrow_right(self):
        self.assertEqual(self._getch(b"\x1b[C"), "'KEY_RIGHT'")
    def test_app_mode_arrows(self):
        # альтернативная кодировка стрелок (application mode)
        self.assertEqual(self._getch(b"\x1bOB"), "'KEY_DOWN'")
        self.assertEqual(self._getch(b"\x1bOA"), "'KEY_UP'")
    def test_delete_key(self):
        self.assertEqual(self._getch(b"\x1b[3~"), "'KEY_DELETE'")
    def test_backtab(self):
        self.assertEqual(self._getch(b"\x1b[Z"), "'KEY_BTAB'")
    def test_lone_esc(self):
        # одиночный Esc (реальная отмена) — тишина после: вернуть '\x1b'
        self.assertEqual(self._getch(b"\x1b", settle=0.25), "'\\x1b'")
    def test_backspace(self):
        self.assertEqual(self._getch(b"\x7f"), "'KEY_BACKSPACE'")
    def test_tab(self):
        self.assertEqual(self._getch(b"\t"), "'KEY_TAB'")
    def test_enter(self):
        self.assertEqual(self._getch(b"\r"), "'\\r'")
    def test_ctrl_c(self):
        self.assertEqual(self._getch(b"\x03"), "'\\x03'")
    def test_plain_char(self):
        self.assertEqual(self._getch(b"q"), "'q'")
    def test_utf8_cyrillic(self):
        # кириллица в формах: 2 байта одним пакетом, как шлёт терминал
        self.assertEqual(self._getch("а".encode()), "'а'")
    def test_utf8_cyrillic_split(self):
        # экстремум: lead и продолжение РАЗНЫМИ пакетами (медленный канал)
        self.assertEqual(self._getch(b"\xd0", feed2=b"\xb0", feed2_gap=0.03), "'а'")


class TestTuiSelectPty(unittest.TestCase):
    """E2E: tui_select на pty — стрелка двигает курсор, Enter выбирает,
    а не убивает меню по первому ESC-байту (исходный баг владельца 04.11)."""

    def setUp(self):
        _setup_core()

    def _select(self, feed, settle=0.0):
        def child():
            from chimera.modules.tui import tui_select
            idx = tui_select("test", ["alpha", "beta", "gamma"])
            _os.write(1, ("\nRESULT=" + repr(idx) + "\n").encode())
        text = _pty_run(feed, child, "RESULT=", settle=settle)
        self.assertNotIn("CHILDFAIL", text, text[:600])
        m = _re.search(r"RESULT=(.+?)\n", text)
        self.assertIsNotNone(m, text[:600])
        raw = m.group(1).strip()
        return None if raw == "None" else int(raw)

    def test_arrow_navigates_and_enter_selects(self):
        # ↓ затем Enter: курсор с alpha (0) на beta (1) — выбор подтверждён
        self.assertEqual(self._select(b"\x1b[B\r"), 1)

    def test_two_arrows_wrap_around(self):
        # ↓↓↓ по кругу (3 пункта): 0→1→2→0, Enter — снова первый пункт
        self.assertEqual(self._select(b"\x1b[B\x1b[B\x1b[B\r"), 0)

    def test_esc_cancels(self):
        # одинокий Esc (тишина после) — честная отмена: None
        self.assertIsNone(self._select(b"\x1b", settle=0.25))

if __name__ == "__main__":
    unittest.main(verbosity=2)
