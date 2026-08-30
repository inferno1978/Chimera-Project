# -*- coding: utf-8 -*-
"""Регрессионные тесты инцидента 29.08.2026 (прод, vds13216):

Выключение «NGINX Front для B4» падало:
  File panel_nginx_front.py, in panel_nginx_front_remove
      subprocess.run(["ufw", "delete", "allow", f"{port}/tcp"],
                     capture_output=True, input="y\n", check=False)
  TypeError: memoryview: a bytes-like object is required, not 'str'

Корень: input=STR без text=True. В остальных модулях (port_registry,
singbox_ufw) тот же вызов идёт с text=True — в panel_nginx_front забыли.

Класс бага общий для всего проекта: любой subprocess.run(..., input="str")
без text=True/universal_newlines=True умирает ДО запуска процесса.

Тесты:
  1. TestPanelNginxFrontRemove  — функциональный: remove() завершается
     без исключения и удаляет state-файл (старый код падал TypeError).
  2. TestSubprocessInputAudit   — аудит ВСЕГО chimera/: str input= без
     text=True запрещён (ловит класс, а не один случай).
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Компилирует _core.py в фейковый модуль (как test_tfo_settings)."""
    from unittest.mock import patch as _patch
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    import types
    with _patch.object(Path, 'mkdir', lambda s, *a, **kw: None), \
         _patch.object(Path, 'touch', lambda s, *a, **kw: None), \
         _patch.object(Path, 'chmod', lambda s, *a, **kw: None), \
         _patch('os.chown', lambda *a, **kw: None), \
         _patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core


class TestPanelNginxFrontRemove(unittest.TestCase):
    """panel_nginx_front_remove: happy-path без исключений + state удалён."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state_file = Path(self._tmp.name) / "b4_front.json"
        self.state_file.write_text('{"enabled": true, "port": 9743}')

    def test_remove_no_crash_and_state_deleted(self):
        """До фикса: TypeError memoryview (input=str без text=True).
        После фикса: исключения нет, state-файл удалён."""
        import os
        from chimera.modules import panel_nginx_front as pnf

        fake_bin = Path(self._tmp.name) / "fakebin"
        fake_bin.mkdir()
        fake_ufw = fake_bin / "ufw"
        fake_ufw.write_text("#!/bin/sh\nexit 0\n")
        fake_ufw.chmod(0o755)

        # Код зовёт ГОЛЫЙ "ufw" (полагаясь на PATH), а not which-путь:
        # подкладываем фейк в PATH — which("ufw") и exec("ufw") оба сработают.
        # nginx/iptables/netfilter-persistent в PATH нет → шаги пропускаются.
        new_path = f"{fake_bin}:{os.environ.get('PATH', '')}"

        import chimera.modules.port_registry as pr
        with patch.dict(os.environ, {"PATH": new_path}), \
             patch.object(pr, "ufw_close_port", return_value=(True, "ok")), \
             patch.object(pr, "port_unregister", return_value=True):
            # ВАЖНО: subprocess.run НЕ мокаем — баг воспроизводится в самом
            # subprocess (memoryview), внешний бинарник не важен.
            ok, msg = pnf.panel_nginx_front_remove(
                service_tag="b4_web",
                site_name="chimera-b4-front",
                state_file=self.state_file,
                title="B4",
            )
        self.assertTrue(ok, f"remove должен вернуть True: {msg}")
        self.assertFalse(
            self.state_file.exists(),
            "state-файл обязан быть удалён (до фикса функция умирала раньше)")


class TestSubprocessInputAudit(unittest.TestCase):
    """Аудит всего проекта: str input= без text=True — запрещён."""

    def test_no_str_input_without_text_mode(self):
        offenders = []
        call_re = re.compile(r'(?:subprocess|_sp|sp)\.run\(')
        for py in (_PROJECT_ROOT / "chimera").rglob("*.py"):
            src = py.read_text()
            for m in call_re.finditer(src):
                # грубая балансировка скобок — выкусить полный вызов
                i, depth = m.end(), 1
                while i < len(src) and depth > 0:
                    if src[i] == "(":
                        depth += 1
                    elif src[i] == ")":
                        depth -= 1
                    i += 1
                block = src[m.end():i]
                if not re.search(r'input\s*=\s*[fF]?["\']', block):
                    continue
                if re.search(r'text\s*=\s*True|universal_newlines\s*=\s*True', block):
                    continue
                offenders.append(f"{py.relative_to(_PROJECT_ROOT)}:"
                                  f"{src[:m.start()].count(chr(10)) + 1}")
        self.assertEqual(
            offenders, [],
            "subprocess.run с input=STR без text=True упадёт TypeError "
            "memoryview ДО запуска процесса (инцидент 29.08.2026, "
            "panel_nginx_front): " + "; ".join(offenders))


if __name__ == "__main__":
    unittest.main(verbosity=2)
