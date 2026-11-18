#!/usr/bin/env python3
"""Тесты для TUI-обёртки HSTS-апгрейда живых vhost'ов (меню 1 → 5d).

Вопрос сообщества 18.11 («где в меню найти мигратор, чтобы HSTS включить
на живой ноде»): upgrade_vhosts_hsts() (16.11, РКН-волна) была библиотечной
функцией — python -c с ноды. Теперь do_upgrade_vhosts_hsts_interactive() в
nginx_setup.py + пункт 5d в _menu_install_system (_core.py).

Покрывает:
  1. Экран выбора: заголовок, dry-run/применить, отмена (пусто/иное);
  2. Выбор 1 → upgrade_vhosts_hsts(apply=False), заголовок dry-run-отчёта;
  3. Выбор 2 → apply=True; отчёт: N vhost(ов) + reload/без reload;
  4. ok=True без изменений → «изменений не требуется»;
  5. ok=False (провал nginx -t) → «откачены» + строки отчёта;
  6. EOF/Ctrl+C на вводе — тихий выход без вызова апгрейдера;
  7. Исключение внутри апгрейдера → warn, без падения обёртки;
  8. Врезка 5d в _menu_install_system (_core.py): рендер + диспетчер.
"""
from __future__ import annotations

import io
import sys
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

_CHIMERA_SNAPSHOT = {k: v for k, v in sys.modules.items()
                     if k == "chimera" or k.startswith("chimera.")}


def tearDownModule():
    """Снять фейки sys.modules после модуля (анти-загрязнение сьюта)."""
    for k in [k for k in sys.modules
              if k == "chimera" or k.startswith("chimera.")]:
        if k not in _CHIMERA_SNAPSHOT:
            sys.modules.pop(k, None)
        else:
            sys.modules[k] = _CHIMERA_SNAPSHOT[k]


def _install_fake_core():
    """Фейковый chimera._core: цвета-пустышки + box-хелперы в stdout.

    Цвета — пустые строки: вывод чистый, ассерты — на подстроки без ANSI.
    """
    if "chimera" not in sys.modules:
        pkg = types.ModuleType("chimera")
        pkg.__path__ = [str(_PROJECT_ROOT / "chimera")]
        sys.modules["chimera"] = pkg
    if "chimera.modules" not in sys.modules:
        pkg = types.ModuleType("chimera.modules")
        pkg.__path__ = [str(_PROJECT_ROOT / "chimera" / "modules")]
        sys.modules["chimera.modules"] = pkg

    fake = types.ModuleType("chimera._core")
    fake.info = lambda *a, **kw: None
    fake.warns: list = []

    def _warn(msg, *a, **kw):
        fake.warns.append(str(msg))

    fake.warn = _warn
    fake.success = lambda *a, **kw: None
    fake.log_to_file = lambda *a, **kw: None
    fake.find_nginx_bin = lambda: "/usr/sbin/nginx"
    for _c in ("CYAN", "NC", "DIM", "GREEN", "RED", "BOLD", "BLUE",
               "YELLOW", "WHITE", "TITLE"):
        setattr(fake, _c, "")
    fake._box_top = lambda title="": print(title)
    fake._box_row = lambda text="": print(text if text else "")
    fake._box_sep = lambda: print()
    fake._box_item = lambda key, label: print(label)
    fake._box_back = lambda: print()
    fake._box_bottom = lambda: print()
    sys.modules["chimera._core"] = fake
    # nginx_setup импортируем свежим — против фейкового ядра
    sys.modules.pop("chimera.modules.nginx_setup", None)
    return fake


class TestHstsMenuInteractive(unittest.TestCase):
    """do_upgrade_vhosts_hsts_interactive(): экраны, выборы, отчёты."""

    def setUp(self):
        self.core = _install_fake_core()
        from chimera.modules import nginx_setup
        self.nginx_setup = nginx_setup

    def _run(self, inputs, result=None, raises=None):
        """Прогон обёртки с моком апгрейдера.

        inputs — side_effect для input() (последний может быть исключением).
        result — словарь-ответ upgrade_vhosts_hsts; raises — исключение.
        Возвращает (stdout, [apply-аргументы вызовов]).
        """
        calls = []

        def _mock_upgrade(apply=True):
            calls.append(apply)
            if raises is not None:
                raise raises
            return result

        buf = io.StringIO()
        with patch.object(self.nginx_setup, "upgrade_vhosts_hsts",
                          _mock_upgrade), \
             patch("builtins.input", side_effect=inputs), \
             redirect_stdout(buf):
            self.nginx_setup.do_upgrade_vhosts_hsts_interactive()
        return buf.getvalue(), calls

    def test_choice_1_is_dry_run(self):
        out, calls = self._run(
            ["1"],
            result={"ok": True, "changed": [], "reloaded": False,
                    "report": ["БЫЛО БЫ изменено (dry-run): site.conf (+1 HSTS)"]})
        self.assertEqual(calls, [False])
        self.assertIn("HSTS-АПГРЕЙД ЖИВЫХ VHOST'ОВ", out)
        self.assertIn("Dry-run", out)
        self.assertIn("файлы не менялись", out)
        self.assertIn("БЫЛО БЫ изменено (dry-run): site.conf", out)

    def test_choice_2_applies(self):
        out, calls = self._run(
            ["2"],
            result={"ok": True, "changed": ["site.conf"], "reloaded": True,
                    "report": ["site.conf: +HSTS (1 блок(ов))"]})
        self.assertEqual(calls, [True])
        self.assertIn("Готово:", out)
        self.assertIn("HSTS добавлен в", out)
        self.assertIn("1", out)
        self.assertIn("vhost(ов)", out)
        self.assertIn("nginx перезагружен", out)
        self.assertIn("site.conf: +HSTS", out)

    def test_choice_2_reload_failed_still_ok(self):
        out, calls = self._run(
            ["2"],
            result={"ok": True, "changed": ["site.conf"], "reloaded": False,
                    "report": ["site.conf: +HSTS (1 блок(ов))",
                               "WARN: systemctl reload nginx не удался"]})
        self.assertEqual(calls, [True])
        self.assertIn("reload не удался", out)
        self.assertIn("конфиг валиден", out)

    def test_choice_2_no_changes_needed(self):
        out, calls = self._run(
            ["2"],
            result={"ok": True, "changed": [], "reloaded": False,
                    "report": ["Изменений не требуется: HSTS уже на месте "
                               "во всех chimera-заглушках"]})
        self.assertEqual(calls, [True])
        self.assertIn("Изменений не требуется", out)

    def test_failure_report_shows_rollback(self):
        out, calls = self._run(
            ["2"],
            result={"ok": False, "changed": [], "reloaded": False,
                    "report": ["nginx -t ПРОВАЛ — все изменения откачены: "
                               "emerg: unexpected"]})
        self.assertEqual(calls, [True])
        self.assertIn("ПРОВАЛ", out)
        self.assertIn("откачены", out)
        self.assertIn("nginx -t ПРОВАЛ", out)
        self.assertNotIn("Готово:", out)

    def test_cancel_empty_choice_no_call(self):
        out, calls = self._run([""])
        self.assertEqual(calls, [])
        self.assertIn("HSTS-АПГРЕЙД ЖИВЫХ VHOST'ОВ", out)  # экран выбора был
        self.assertNotIn("ОТЧЁТ", out)                     # отчёта нет

    def test_cancel_other_choice_no_call(self):
        out, calls = self._run(["q"])
        self.assertEqual(calls, [])

    def test_eof_returns_silently(self):
        out, calls = self._run([EOFError()])
        self.assertEqual(calls, [])
        self.assertIn("HSTS-АПГРЕЙД ЖИВЫХ VHOST'ОВ", out)

    def test_keyboard_interrupt_returns_silently(self):
        out, calls = self._run([KeyboardInterrupt()])
        self.assertEqual(calls, [])

    def test_upgrader_exception_warns_not_crashes(self):
        self.core.warns.clear()
        out, calls = self._run(
            ["2"], raises=RuntimeError("boom on live node"))
        self.assertEqual(calls, [True])
        self.assertTrue(any("boom on live node" in w for w in self.core.warns))
        self.assertNotIn("ОТЧЁТ", out)


class TestMenuWiring(unittest.TestCase):
    """Пункт 5d в _menu_install_system (_core.py) — рендер и диспетчер."""

    def _exec_core(self):
        core_path = _PROJECT_ROOT / "chimera" / "_core.py"
        src = core_path.read_text()
        fake_core = types.ModuleType("chimera._core")
        sys.modules["chimera._core"] = fake_core
        with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
             patch.object(Path, 'touch', lambda self, *a, **kw: None), \
             patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
             patch('os.chown', lambda *a, **kw: None), \
             patch('os.geteuid', return_value=0):
            exec(compile(src, str(core_path), "exec"), fake_core.__dict__)
        return fake_core

    def setUp(self):
        self._saved_core = sys.modules.get("chimera._core")
        self._saved_ns = sys.modules.get("chimera.modules.nginx_setup")
        # Реальный nginx_setup (его имена нужны top-level импорту _core.py),
        # патчим только обёртку 5d — диспетчер зовёт её лениво.
        sys.modules.pop("chimera.modules.nginx_setup", None)
        import importlib
        real_ns = importlib.import_module("chimera.modules.nginx_setup")
        self._calls = []
        self._patcher = patch.object(
            real_ns, "do_upgrade_vhosts_hsts_interactive",
            lambda: self._calls.append("5d"))
        self._patcher.start()
        self.core = self._exec_core()

    def tearDown(self):
        self._patcher.stop()
        if self._saved_core is None:
            sys.modules.pop("chimera._core", None)
        else:
            sys.modules["chimera._core"] = self._saved_core
        if self._saved_ns is None:
            sys.modules.pop("chimera.modules.nginx_setup", None)
        else:
            sys.modules["chimera.modules.nginx_setup"] = self._saved_ns

    def test_menu_renders_5d_item(self):
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        self.assertIn('_box_item("5d"', src)
        self.assertIn("HSTS-апгрейд живых vhost'ов", src)

    def test_menu_dispatches_5d(self):
        buf = io.StringIO()
        with patch("builtins.input", side_effect=["5d", "", "q"]), \
             redirect_stdout(buf):
            self.core._menu_install_system()
        self.assertEqual(self._calls, ["5d"])
        self.assertIn("HSTS-апгрейд живых vhost'ов", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
