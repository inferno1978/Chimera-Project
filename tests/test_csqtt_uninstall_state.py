#!/usr/bin/env python3
"""
tests/test_csqtt_uninstall_state.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты починки трёх живых кейсов CSQTT:

  1. ЗАВИСАНИЕ при удалении/переустановке («при освобождении порта»):
     - _run с timeout → псевдо-результат rc=124, не исключение;
     - _svc_stop_hard: stop с потолком → is-active → SIGKILL → stop;
     - ufw-вызовы закрытия портов идут с input='y\\n' и таймаутом
       (ufw-промпты читают stdin БЛОКИРУЮЩЕ, /run/ufw.lock —
       блокирующий fcntl-лок);
     - _install_service пишет TimeoutStopSec=20 в юнит.
  2. РАССИНХРОН состояния после Ctrl+C:
     - _install_state различает 4 состояния (ok/no-service/no-binary/none);
     - меню показывает «частично» и «Доустановить», а не «не установлен»;
     - _run_install_inner для частичного состояния НЕ говорит «уже
       установлен» и не предлагает «Переустановить полностью».
  3. ИДЕМПОТЕНТНОЕ удаление:
     - порты к закрытию = state + текущие дефолты + легаси 40000/40500;
     - сбой одного шага (ufw-таймаут) не оставляет полуудалённую
       установку: state-файл удаляется ВСЕГДА;
     - _full_uninstall останавливает сервис через _svc_stop_hard.
"""
from __future__ import annotations

import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch, MagicMock, call

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import csqtt as cs


class _CsqttPathsMixin:
    """Перенаправляет системные пути модуля во временную директорию."""

    def setUp(self):
        super().setUp()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._bin = self._tmpdir / "csqtt-server"
        self._svc = self._tmpdir / "csqtt.service"
        self._state = self._tmpdir / "csqtt.json"
        self._cfgdir = self._tmpdir / "csqtt-etc"
        self._orig = {
            "_BIN_PATH": cs._BIN_PATH,
            "_SERVICE_FILE": cs._SERVICE_FILE,
            "_MODULE_STATE": cs._MODULE_STATE,
            "_CFG_DIR": cs._CFG_DIR,
            "_CFG_FILE": cs._CFG_FILE,
            "_PASSWORDS_FILE": cs._PASSWORDS_FILE,
        }
        cs._BIN_PATH = self._bin
        cs._SERVICE_FILE = self._svc
        cs._MODULE_STATE = self._state
        cs._CFG_DIR = self._cfgdir
        cs._CFG_FILE = self._cfgdir / "config.json"
        cs._PASSWORDS_FILE = self._cfgdir / "passwords.json"

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(cs, k, v)
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        super().tearDown()


# ══════════════════════════════════════════════════════════════════════════════
#  1. _run с таймаутом + _svc_stop_hard
# ══════════════════════════════════════════════════════════════════════════════
class TestRunTimeout(unittest.TestCase):

    def test_timeout_returns_rc124(self):
        """subprocess.TimeoutExpired → псевдо-результат rc=124 (конвенция
        timeout(1)), вызывающий код не падает."""
        def fake_run(cmd, **kw):
            self.assertIn("timeout", kw)
            raise subprocess.TimeoutExpired(cmd, timeout=kw["timeout"])

        with patch.object(subprocess, "run", side_effect=fake_run):
            r = cs._run(["sleep", "1000"], timeout=1)
        self.assertEqual(r.returncode, 124)

    def test_input_passed_through(self):
        """input='y\\n' уходит в subprocess.run (ufw-промпты)."""
        seen = {}

        def fake_run(cmd, **kw):
            seen["input"] = kw.get("input")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with patch.object(subprocess, "run", side_effect=fake_run):
            cs._run(["ufw", "delete", "allow", "40000/udp"],
                    check=False, timeout=60, input="y\n")
        self.assertEqual(seen["input"], "y\n")

    def test_no_timeout_backward_compatible(self):
        """Без timeout= — прежнее поведение, ничего не ломается."""
        with patch.object(subprocess, "run",
                          return_value=subprocess.CompletedProcess(["x"], 0, "", "")) as m:
            cs._run(["x"])
        m.assert_called_once_with(["x"], check=False,
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)


class TestSvcStopHard(unittest.TestCase):
    """Жёсткая остановка сервиса: никогда не виснет."""

    def test_happy_path_single_stop(self):
        """Сервис умер по SIGTERM сразу — достаточно одного stop."""
        with patch.object(cs, "_run") as m:
            m.side_effect = [
                subprocess.CompletedProcess(["systemctl"], 0, "", ""),   # stop
                subprocess.CompletedProcess(["systemctl"], 3, "inactive\n", ""),  # is-active
                subprocess.CompletedProcess(["pkill"], 0, "", ""),        # pkill
            ]
            cs._svc_stop_hard("csqtt")
        cmds = [c.args[0][:3] for c in m.call_args_list]
        self.assertEqual(cmds, [["systemctl", "stop", "csqtt"],
                                ["systemctl", "is-active", "csqtt"],
                                ["pkill", "-9", "-x"]])

    def test_sigkill_fallback(self):
        """stop не помог (TimeoutStopSec прошёл, сервис жив) — SIGKILL
        + повторный stop + pkill одиночных процессов."""
        with patch.object(cs, "_run") as m:
            m.side_effect = [
                subprocess.CompletedProcess(["systemctl"], 0, "", ""),        # stop
                subprocess.CompletedProcess(["systemctl"], 0, "active\n", ""), # is-active → жив
                subprocess.CompletedProcess(["systemctl"], 0, "", ""),        # kill SIGKILL
                subprocess.CompletedProcess(["systemctl"], 0, "", ""),        # stop again
                subprocess.CompletedProcess(["pkill"], 0, "", ""),            # pkill
            ]
            cs._svc_stop_hard("csqtt")
        cmds = [c.args[0] for c in m.call_args_list]
        self.assertIn(["systemctl", "kill", "--signal=SIGKILL", "csqtt"], cmds)
        # pkill добивает остатки мимо systemd
        self.assertEqual(cmds[-1], ["pkill", "-9", "-x", "csqtt-server"])


# ══════════════════════════════════════════════════════════════════════════════
#  2. Состояния установки + меню
# ══════════════════════════════════════════════════════════════════════════════
class TestInstallState(_CsqttPathsMixin, unittest.TestCase):

    def test_all_four_states(self):
        self.assertEqual(cs._install_state(), "none")
        self._bin.write_bytes(b"x")
        self.assertEqual(cs._install_state(), "no-service")
        self._svc.write_text("[Unit]")
        self.assertEqual(cs._install_state(), "ok")
        self._bin.unlink()
        self.assertEqual(cs._install_state(), "no-binary")

    def test_is_installed_unchanged_semantics(self):
        """_is_installed() по-прежнему = бинарник AND юнит (совместимость)."""
        self.assertFalse(cs._is_installed())
        self._bin.write_bytes(b"x")
        self.assertFalse(cs._is_installed())       # нет юнита — не установлено
        self._svc.write_text("[Unit]")
        self.assertTrue(cs._is_installed())


class TestMenuPartialState(_CsqttPathsMixin, unittest.TestCase):
    """Меню при частичной установке: «Доустановить», а не «Установить»."""

    def _render_menu(self, menu_input="q") -> str:
        """Прогоняет do_csqtt_menu один раз (ввод menu_input) и возвращает вывод."""
        buf = io.StringIO()
        with patch.object(cs, "proto_ask", return_value=menu_input), \
             patch.object(cs.os, "system"),                        \
             patch.object(cs, "_run",
                          return_value=subprocess.CompletedProcess(
                              ["systemctl"], 3, "inactive\n", "")), \
             redirect_stdout(buf):
            cs.do_csqtt_menu()
        return buf.getvalue()

    def test_no_service_shows_repair(self):
        self._bin.write_bytes(b"x")     # бинарник есть, юнита нет
        out = self._render_menu()
        self.assertIn("частично: нет systemd-сервиса", out)
        self.assertIn("Доустановить", out)
        self.assertNotIn("Установить CSQTT", out)
        # строка СТАТУС больше не врёт «не установлен»
        status_rows = [ln for ln in out.splitlines() if "Статус:" in ln]
        self.assertEqual(len(status_rows), 1)
        self.assertNotIn("не установлен", status_rows[0])

    def test_no_binary_shows_repair(self):
        self._svc.write_text("[Unit]")  # юнит есть, бинарника нет
        out = self._render_menu()
        self.assertIn("частично: нет бинарника", out)
        self.assertIn("Доустановить", out)

    def test_clean_not_installed_shows_install(self):
        out = self._render_menu()
        self.assertIn("Установить CSQTT", out)
        self.assertIn("не установлен", out)
        self.assertNotIn("Доустановить", out)

    def test_full_install_shows_reinstall(self):
        self._bin.write_bytes(b"x")
        self._svc.write_text("[Unit]")
        out = self._render_menu()
        self.assertIn("Переустановить", out)


class TestInstallInnerPartial(_CsqttPathsMixin, unittest.TestCase):
    """Установщик при частичном состоянии не говорит «уже установлен»."""

    def test_no_service_no_already_installed_box(self):
        """no-service: НЕ показываем «CSQTT уже установлен» с выбором
        1/2/Q — вместо этого диагностика + продолжение установки."""
        self._bin.write_bytes(b"x")
        buf = io.StringIO()

        def fake_ask(prompt, **kw):
            return ""

        with patch.object(cs, "proto_ask", side_effect=fake_ask), \
             patch.object(cs, "_build_csqtt_server", return_value=False), \
             patch.object(cs, "_pause"), \
             patch.object(cs.os, "system"), \
             redirect_stdout(buf):
            cs._run_install_inner()
        out = buf.getvalue()
        self.assertNotIn("уже установлен", out)
        self.assertIn("незавершённая установка", out)
        self.assertIn("нет systemd-сервиса", out)

    def test_ok_shows_already_installed_choice(self):
        """Полная установка: прежний выбор 1/2/Q сохранён."""
        self._bin.write_bytes(b"x")
        self._svc.write_text("[Unit]")
        buf = io.StringIO()
        with patch.object(cs, "proto_ask", return_value="q"), \
             patch.object(cs.os, "system"), \
             redirect_stdout(buf):
            cs._run_install_inner()
        out = buf.getvalue()
        self.assertIn("уже установлен", out)
        self.assertIn("Переустановить", out)


# ══════════════════════════════════════════════════════════════════════════════
#  3. Идемпотентное удаление
# ══════════════════════════════════════════════════════════════════════════════
class TestFullUninstall(_CsqttPathsMixin, unittest.TestCase):

    def _prepare(self, *, legacy_ports=False) -> None:
        self._bin.write_bytes(b"fake-bin")
        self._svc.write_text("[Unit]")
        self._cfgdir.mkdir(parents=True, exist_ok=True)
        cs._save_cfg({"a": 1})
        ports = ({"data_port": 40000, "web_port": 40500}
                 if legacy_ports
                 else {"data_port": 46000, "web_port": 46002})
        cs.proto_save_state(self._state, {
            "installed": True, "main_password": "p",
            **ports,
        })

    def test_closes_state_ports_plus_defaults_plus_legacy(self):
        """Юзер с легаси-портами 40000/40500: закрываем ИХ, и текущие
        дефолты 46000/46002, и легаси — дедуплицированно."""
        self._prepare(legacy_ports=True)
        closed_udp, closed_tcp = [], []
        with patch.object(cs, "_svc_stop_hard"), \
             patch.object(cs, "_csqtt_nginx_remove"), \
             patch.object(cs, "_run"), \
             patch.object(cs, "_ipt_close_udp",
                          side_effect=lambda p: closed_udp.append(p)), \
             patch.object(cs, "_ipt_close_tcp",
                          side_effect=lambda p: closed_tcp.append(p)), \
             patch.object(cs, "_ipt_remove_masquerade"), \
             patch.object(cs, "proto_ipt_persist"):
            ok = cs._full_uninstall(silent=True)
        self.assertTrue(ok)
        self.assertEqual(closed_udp, [40000, 46000])   # sorted, dedup
        self.assertEqual(closed_tcp, [40500, 46002])

    def test_state_file_removed_even_when_firewall_fails(self):
        """Таймаут ufw на закрытии порта НЕ оставляет полуудалённую
        установку: state-файл удаляется, остальные шаги выполняются."""
        self._prepare()
        with patch.object(cs, "_svc_stop_hard"), \
             patch.object(cs, "_csqtt_nginx_remove"), \
             patch.object(cs, "_run"), \
             patch.object(cs, "_ipt_close_udp",
                          side_effect=subprocess.TimeoutExpired("ufw", 60)), \
             patch.object(cs, "_ipt_close_tcp",
                          side_effect=subprocess.TimeoutExpired("ufw", 60)), \
             patch.object(cs, "_ipt_remove_masquerade",
                          side_effect=RuntimeError("xtables busy")), \
             patch.object(cs, "proto_ipt_persist"):
            ok = cs._full_uninstall(silent=True)
        self.assertTrue(ok)
        self.assertFalse(self._state.exists())         # state удалён ВСЕГДА
        self.assertFalse(self._bin.exists())
        self.assertFalse(self._svc.exists())

    def test_uses_hard_stop(self):
        """Удаление останавливает сервис через _svc_stop_hard (SIGKILL
        фолбэк), а не «голый» systemctl stop без потолка."""
        self._prepare()
        with patch.object(cs, "_svc_stop_hard") as mstop, \
             patch.object(cs, "_csqtt_nginx_remove"), \
             patch.object(cs, "_ipt_close_udp"), \
             patch.object(cs, "_ipt_close_tcp"), \
             patch.object(cs, "_ipt_remove_masquerade"), \
             patch.object(cs, "proto_ipt_persist"), \
             patch.object(cs, "_run"):
            cs._full_uninstall(silent=True)
        mstop.assert_called_once_with("csqtt")

    def test_rerun_after_interrupt_completes(self):
        """Повторное удаление после прерывания доводит дело до конца
        (идемпотентность: файлы уже частично удалены — не падает)."""
        self._prepare(legacy_ports=True)
        # имитируем прерванное удаление: юнит и конфиги уже снесены
        self._svc.unlink()
        shutil_rmtree = cs.shutil.rmtree
        with patch.object(cs, "_svc_stop_hard"), \
             patch.object(cs, "_csqtt_nginx_remove"), \
             patch.object(cs, "_ipt_close_udp"), \
             patch.object(cs, "_ipt_close_tcp"), \
             patch.object(cs, "_ipt_remove_masquerade"), \
             patch.object(cs, "proto_ipt_persist"), \
             patch.object(cs, "_run"):
            ok = cs._full_uninstall(silent=True)
        self.assertTrue(ok)
        self.assertFalse(self._state.exists())
        self.assertFalse(self._bin.exists())


# ══════════════════════════════════════════════════════════════════════════════
#  4. Юнит-файл + закрытие портов с таймаутами
# ══════════════════════════════════════════════════════════════════════════════
class TestServiceUnitAndFirewall(_CsqttPathsMixin, unittest.TestCase):

    def test_unit_has_timeout_stop(self):
        """Юнит содержит TimeoutStopSec=20 — stop больше не ждёт 90с."""
        cs._install_service(46000, 46002, "pass", "admin", "wpass", "1.1.1.1")
        text = self._svc.read_text()
        self.assertIn("TimeoutStopSec=20", text)
        self.assertIn("Restart=always", text)

    def test_close_udp_ufw_gets_input_and_timeout(self):
        """Orphaned-ветка _ipt_close_udp: ufw delete allow с input='y\\n'
        и таймаутом; iptables -D с таймаутом."""
        with patch.object(cs.shutil, "which", return_value="/usr/sbin/ufw"), \
             patch.object(cs, "_fw_tool", return_value="ufw"), \
             patch.object(cs, "_ipt_rule_exists", return_value=False), \
             patch.object(cs, "_run") as m, \
             patch("chimera.modules.port_registry.ufw_close_port",
                   return_value=(True, "ok")), \
             patch("chimera.modules.port_registry.port_unregister"):
            # импорт внутри функции — патчим по месту использования
            import chimera.modules.port_registry as pr
            with patch.object(pr, "ufw_close_port", return_value=(True, "ok")), \
                 patch.object(pr, "port_unregister"):
                cs._ipt_close_udp(40000)
        ufw_calls = [c for c in m.call_args_list
                     if c.args[0][:2] == ["ufw", "delete"]]
        self.assertTrue(ufw_calls, "ufw delete должен вызываться")
        for c in ufw_calls:
            self.assertEqual(c.kwargs.get("input"), "y\n")
            self.assertIsNotNone(c.kwargs.get("timeout"))

    def test_binary_version_probe_message(self):
        """csqtt_packages: найденный ручной бинарь печатается с версией —
        юзер видит, что ставит v2.0.0 (а апстрим уже 2.1.9)."""
        from chimera.modules import csqtt_packages
        fake = self._tmpdir / "manual"
        fake.write_bytes(b"\x7fELF" + b"\x00" * 2_000_000)
        with patch.object(csqtt_packages, "find_manual_binary",
                          return_value=(fake, [])), \
             patch.object(csqtt_packages, "_binary_version",
                          return_value="2.0.0"), \
             patch.object(csqtt_packages, "_atomic_replace_binary",
                          return_value=True), \
             patch.object(csqtt_packages, "LAST_BUILD_INFO", {}):
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = csqtt_packages.install_manual_binary(verbose=True)
        self.assertTrue(ok)
        self.assertIn("v2.0.0", buf.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
