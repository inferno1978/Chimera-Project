#!/usr/bin/env python3
"""Тесты для TUI-обёртки HTTP/2-миграции живых vhost'ов (меню 1 → 5e).

Волна 19.11: владелец после перевода флота на nginx.org 1.30.7 — «варнинги
listen … http2 is deprecated в генерируемых конфигах сайтов». Генераторы
исправлены (panel_nginx_front / nginx_front_portal), do_upgrade_vhosts_http2_
interactive() + пункт 5e приводят к ним живые конфиги.

Покрывает (паттерн test_nginx_hsts_menu):
  1. Экран выбора: заголовок, версия nginx, dry-run/применить, отмена;
  2. Выбор 1 → upgrade_vhosts_http2_syntax(apply=False), dry-run-отчёт;
  3. Выбор 2 → apply=True; отчёт: N vhost(ов) + reload/без reload;
  4. ok=True без изменений → «изменений не требуется»;
  5. ok=False (провал nginx -t) → «откачены» + строки отчёта;
  6. EOF/Ctrl+C — тихий выход без вызова мигратора;
  7. Исключение внутри мигратора → warn, без падения обёртки;
  8. Врезка 5e в _menu_install_system (_core.py): рендер + диспетчер.
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
    """Фейковый chimera._core: цвета-пустышки + box-хелперы в stdout."""
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


class TestHttp2MenuInteractive(unittest.TestCase):
    """do_upgrade_vhosts_http2_interactive(): экраны, выборы, отчёты."""

    def setUp(self):
        self.core = _install_fake_core()
        from chimera.modules import nginx_setup
        self.nginx_setup = nginx_setup

    def _run(self, inputs, result=None, raises=None, version="1.30.7"):
        """Прогон обёртки с моком мигратора и детектора версии.

        inputs — side_effect для input(); result — словарь-ответ
        upgrade_vhosts_http2_syntax; raises — исключение; version — что
        показывает _nginx_version_tuple в шапке экрана.
        """
        calls = []

        def _mock_upgrade(apply=True):
            calls.append(apply)
            if raises is not None:
                raise raises
            return result

        buf = io.StringIO()
        with patch.object(self.nginx_setup, "upgrade_vhosts_http2_syntax",
                          _mock_upgrade), \
             patch.object(self.nginx_setup, "_nginx_version_tuple",
                          lambda: tuple(int(x) for x in version.split("."))), \
             patch("builtins.input", side_effect=inputs), \
             redirect_stdout(buf):
            self.nginx_setup.do_upgrade_vhosts_http2_interactive()
        return buf.getvalue(), calls

    def test_choice_1_is_dry_run(self):
        out, calls = self._run(
            ["1"],
            result={"ok": True, "changed": [], "reloaded": False,
                    "report": ["БЫЛО БЫ изменено (dry-run): site.conf "
                               "(listen: 2, +http2 on: 1)"]})
        self.assertEqual(calls, [False])
        self.assertIn("HTTP/2-СИНТАКСИС ЖИВЫХ VHOST'ОВ", out)
        self.assertIn("1.30.7", out)
        self.assertIn("Dry-run", out)
        self.assertIn("файлы не менялись", out)
        self.assertIn("БЫЛО БЫ изменено (dry-run): site.conf", out)

    def test_choice_2_applies(self):
        out, calls = self._run(
            ["2"],
            result={"ok": True, "changed": ["site.conf"], "reloaded": True,
                    "report": ["site.conf: listen ssl http2 → ssl (×2) "
                               "+ http2 on; (×1)"]})
        self.assertEqual(calls, [True])
        self.assertIn("Готово:", out)
        self.assertIn("синтаксис обновлён в", out)
        self.assertIn("1", out)
        self.assertIn("vhost(ах)", out)
        self.assertIn("nginx перезагружен", out)

    def test_choice_2_reload_failed_still_ok(self):
        out, calls = self._run(
            ["2"],
            result={"ok": True, "changed": ["site.conf"], "reloaded": False,
                    "report": ["site.conf: +http2 on; (×1)",
                               "WARN: systemctl reload nginx не удался"]})
        self.assertEqual(calls, [True])
        self.assertIn("reload не удался", out)
        self.assertIn("конфиг валиден", out)

    def test_choice_2_no_changes_needed(self):
        out, calls = self._run(
            ["2"],
            result={"ok": True, "changed": [], "reloaded": False,
                    "report": ["Изменений не требуется: listen без "
                               "deprecated-параметра http2 во всех "
                               "chimera-vhost'ах"]})
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
        self.assertNotIn("Готово:", out)

    def test_cancel_empty_choice_no_call(self):
        out, calls = self._run([""])
        self.assertEqual(calls, [])
        self.assertIn("HTTP/2-СИНТАКСИС ЖИВЫХ VHOST'ОВ", out)  # экран был
        self.assertNotIn("ОТЧЁТ", out)                          # отчёта нет

    def test_cancel_other_choice_no_call(self):
        out, calls = self._run(["q"])
        self.assertEqual(calls, [])

    def test_eof_returns_silently(self):
        out, calls = self._run([EOFError()])
        self.assertEqual(calls, [])
        self.assertIn("HTTP/2-СИНТАКСИС ЖИВЫХ VHOST'ОВ", out)

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
    """Пункт 5e в _menu_install_system (_core.py) — рендер и диспетчер."""

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
        # патчим только обёртку 5e — диспетчер зовёт её лениво.
        sys.modules.pop("chimera.modules.nginx_setup", None)
        import importlib
        real_ns = importlib.import_module("chimera.modules.nginx_setup")
        self._calls = []
        self._patcher = patch.object(
            real_ns, "do_upgrade_vhosts_http2_interactive",
            lambda: self._calls.append("5e"))
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

    def test_menu_renders_5e_item(self):
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        self.assertIn('_box_item("5e"', src)
        self.assertIn("HTTP/2-синтаксис живых vhost'ов", src)

    def test_menu_dispatches_5e(self):
        buf = io.StringIO()
        with patch("builtins.input", side_effect=["5e", "", "q"]), \
             redirect_stdout(buf):
            self.core._menu_install_system()
        self.assertEqual(self._calls, ["5e"])
        self.assertIn("HTTP/2-синтаксис живых vhost'ов", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
