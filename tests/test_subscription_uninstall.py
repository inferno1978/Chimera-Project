#!/usr/bin/env python3
"""
tests/test_subscription_uninstall.py
───────────────────────────────────────────────────────────────────────────────
Тесты для надёжного uninstall/stop сервиса vless-subscription.

Покрывает:
  1. uninstall_subscription_service — полный pipeline:
     mask → stop → disable → unlink unit → daemon-reload → reset-failed →
     _kill_port_holder fallback.
  2. _stop_service_reliable — mask → stop → _kill_port_holder.
  3. _kill_port_holder — парсинг `ss -tlnp`, kill -9 по PID.
  4. _install_service — unmask перед enable (иначе не стартует после stop).
  5. ufw-порт закрывается при uninstall/stop.

Принцип: тесты реально проверяют порядок и наличие команд systemctl
(mask ДО stop, disable ПОСЛЕ stop, reset-failed в конце), а не просто
что функция "не упала".

Контекст: фикс mirror commit e830f28 'fix(rest_api): mask+stop+kill for
reliable web panel uninstall' — та же проблема что и для vless-web, только
здесь в unit-файле стоит Restart=always (ещё агрессивнее, чем
Restart=on-failure у веб-панели).
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Загружает chimera._core через exec и регистрирует в sys.modules.

    Та же функция что и в test_rest_api_web_panel_firewall.py — без неё
    импорт chimera.modules.subscription падает на `from chimera._core ...`.
    """
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core


def _make_completed(stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr="",
    )


# Симуляция вывода `ss -tlnp` — процесс python3 держит порт 8443.
_SS_OUTPUT_WITH_PROC = (
    "State    Recv-Q   Send-Q     Local Address:Port    Peer Address:Port  Process\n"
    "LISTEN   0        128              0.0.0.0:22           0.0.0.0:*      users:((\"sshd\",pid=654,fd=3))\n"
    "LISTEN   0        128              0.0.0.0:8443          0.0.0.0:*      users:((\"python3\",pid=4966,fd=3))\n"
    "LISTEN   0        128                    *:443                *:*      users:((\"xray\",pid=711,fd=7))\n"
)

# Симуляция вывода `ss -tlnp` — порт 8443 свободен.
_SS_OUTPUT_EMPTY = (
    "State    Recv-Q   Send-Q     Local Address:Port    Peer Address:Port  Process\n"
    "LISTEN   0        128              0.0.0.0:22           0.0.0.0:*      users:((\"sshd\",pid=654,fd=3))\n"
)


class _CallRecorder:
    """Записывает все subprocess.run вызовы в self.calls (list[list[str]])."""

    def __init__(self, ss_stdout: str = "", ss_returncode: int = 0):
        self.calls: list[list[str]] = []
        self.ss_stdout = ss_stdout
        self.ss_returncode = ss_returncode

    def __call__(self, cmd, **kw):
        self.calls.append(list(cmd))
        # Возвращаем ss-вывод для команды ss, иначе пусто.
        if cmd[:1] == ["ss"]:
            return _make_completed(self.ss_stdout, self.ss_returncode)
        return _make_completed("")


class TestKillPortHolder(unittest.TestCase):
    """_kill_port_holder — парсинг ss -tlnp + kill -9."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_kills_python3_holding_port(self):
        """ss показывает python3 на порту 8443 → kill -9 4966 вызван."""
        from chimera.modules import subscription
        recorder = _CallRecorder(ss_stdout=_SS_OUTPUT_WITH_PROC)
        with patch("subprocess.run", side_effect=recorder):
            result = subscription._kill_port_holder(8443)
        self.assertTrue(result, "Должен вернуть True если процесс убит")
        kill_calls = [c for c in recorder.calls if c[:2] == ["kill", "-9"]]
        self.assertEqual(len(kill_calls), 1, "Должен быть один kill -9")
        self.assertEqual(kill_calls[0][2], "4966", "PID должен быть 4966")

    def test_no_process_returns_false(self):
        """Порт свободен — kill не вызывается, возвращает False."""
        from chimera.modules import subscription
        recorder = _CallRecorder(ss_stdout=_SS_OUTPUT_EMPTY)
        with patch("subprocess.run", side_effect=recorder):
            result = subscription._kill_port_holder(8443)
        self.assertFalse(result)
        kill_calls = [c for c in recorder.calls if c[:2] == ["kill", "-9"]]
        self.assertEqual(len(kill_calls), 0)

    def test_ss_fails_returns_false(self):
        """ss вернул non-zero — тихо return False, без исключения."""
        from chimera.modules import subscription
        recorder = _CallRecorder(ss_stdout="", ss_returncode=1)
        with patch("subprocess.run", side_effect=recorder):
            result = subscription._kill_port_holder(8443)
        self.assertFalse(result)

    def test_does_not_kill_pid_1(self):
        """Если ss показывает pid=1 (init) — не трогаем."""
        from chimera.modules import subscription
        ss_output = (
            "LISTEN   0        128              0.0.0.0:8443          0.0.0.0:*      "
            "users:((\"python3\",pid=1,fd=3))\n"
        )
        recorder = _CallRecorder(ss_stdout=ss_output)
        with patch("subprocess.run", side_effect=recorder):
            result = subscription._kill_port_holder(8443)
        self.assertFalse(result)
        kill_calls = [c for c in recorder.calls if c[:2] == ["kill", "-9"]]
        self.assertEqual(len(kill_calls), 0, "PID=1 не должен быть убит")


class TestStopServiceReliable(unittest.TestCase):
    """_stop_service_reliable — mask → stop → _kill_port_holder."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_stop_called_and_no_mask(self):
        """Для временной остановки [4] mask НЕ нужен — systemctl stop сам
        игнорирует Restart= (per systemd.service(5)). Проверяем что stop
        вызван, а mask — нет (не падает с 'File already exists')."""
        from chimera.modules import subscription
        cfg_file = tempfile.mkdtemp()
        cfg_path = Path(cfg_file) / "subscription.json"
        cfg_path.write_text(json.dumps({"listen_port": 8443, "enabled": True}))
        recorder = _CallRecorder(ss_stdout=_SS_OUTPUT_WITH_PROC)
        with patch.object(subscription, "_SUB_CONF", cfg_path), \
             patch("subprocess.run", side_effect=recorder):
            subscription._stop_service_reliable()
        actions = [c[1] for c in recorder.calls
                   if c[:1] == ["systemctl"] and len(c) > 1]
        self.assertIn("stop", actions, "stop должен быть вызван")
        self.assertNotIn("mask", actions,
                         "mask не нужен для [4] — stop игнорирует Restart=")

    def test_kill_port_holder_called_after_stop(self):
        """После stop вызывается _kill_port_holder — fallback на случай
        если stop не успел за TimeoutStopSec (процесс игнорит SIGTERM)."""
        from chimera.modules import subscription
        cfg_file = tempfile.mkdtemp()
        cfg_path = Path(cfg_file) / "subscription.json"
        cfg_path.write_text(json.dumps({"listen_port": 8443, "enabled": True}))
        recorder = _CallRecorder(ss_stdout=_SS_OUTPUT_WITH_PROC)
        with patch.object(subscription, "_SUB_CONF", cfg_path), \
             patch("subprocess.run", side_effect=recorder):
            subscription._stop_service_reliable()
        # ss вызов должен быть после systemctl stop.
        stop_idx = None
        ss_idx = None
        for i, c in enumerate(recorder.calls):
            if c[:3] == ["systemctl", "stop", subscription.SERVICE_NAME]:
                stop_idx = i
            elif c[:1] == ["ss"]:
                ss_idx = i
        self.assertIsNotNone(stop_idx)
        self.assertIsNotNone(ss_idx)
        self.assertLess(stop_idx, ss_idx,
                        "ss (kill fallback) должен быть вызван ПОСЛЕ stop")


class TestUninstallSubscriptionService(unittest.TestCase):
    """uninstall_subscription_service — полный pipeline."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _setup_paths(self, host_port: int = 8443):
        """Создаёт temp-пути для _SUB_CONF и _UNIT_PATH."""
        tmpdir = Path(tempfile.mkdtemp())
        cfg_path = tmpdir / "subscription.json"
        cfg_path.write_text(json.dumps({
            "listen_port": host_port, "enabled": True, "pepper": "abc",
        }))
        unit_path = tmpdir / "vless-subscription.service"
        unit_path.write_text("[Unit]\nDescription=test\n")
        return cfg_path, unit_path, tmpdir

    def test_full_pipeline_disable_unlink_mask_stop(self):
        """Все шаги pipeline вызваны в правильном порядке.

        Новый порядок (фикс 'Failed to mask unit: File already exists'):
          1. disable — убрать Wants symlink
          2. unlink unit-файла — чтобы mask смог создать symlink → /dev/null
          3. mask — symlink → /dev/null (теперь succeeds)
          4. stop — процесс уходит, не перезапускается (masked)
          5. unmask — убрать symlink → /dev/null (cleanup)
          6. daemon-reload
          7. reset-failed
        """
        from chimera.modules import subscription
        cfg_path, unit_path, tmpdir = self._setup_paths(8443)
        recorder = _CallRecorder(ss_stdout=_SS_OUTPUT_EMPTY)
        try:
            with patch.object(subscription, "_SUB_CONF", cfg_path), \
                 patch.object(subscription, "_UNIT_PATH", unit_path), \
                 patch("shutil.which", return_value=None), \
                 patch("subprocess.run", side_effect=recorder):
                subscription.uninstall_subscription_service()
            cmds = [c for c in recorder.calls if c[:1] == ["systemctl"]]
            actions = [c[1] for c in cmds if len(c) > 1]
            # Все ключевые действия должны быть вызваны.
            self.assertIn("disable", actions, "disable должен быть вызван")
            self.assertIn("mask", actions, "mask должен быть вызван")
            self.assertIn("stop", actions, "stop должен быть вызван")
            self.assertIn("unmask", actions, "unmask должен быть вызван (cleanup)")
            self.assertIn("daemon-reload", actions, "daemon-reload должен быть вызван")
            self.assertIn("reset-failed", actions, "reset-failed должен быть вызван")
            # Порядок: disable → mask → stop → unmask → daemon-reload → reset-failed.
            disable_idx = actions.index("disable")
            mask_idx = actions.index("mask")
            stop_idx = actions.index("stop")
            unmask_idx = actions.index("unmask")
            daemon_idx = actions.index("daemon-reload")
            reset_idx = actions.index("reset-failed")
            self.assertLess(disable_idx, mask_idx, "disable до mask")
            self.assertLess(mask_idx, stop_idx, "mask до stop")
            self.assertLess(stop_idx, unmask_idx, "stop до unmask")
            self.assertLess(unmask_idx, daemon_idx, "unmask до daemon-reload")
            self.assertLess(daemon_idx, reset_idx, "daemon-reload до reset-failed")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_unit_file_deleted(self):
        """unit-файл должен быть удалён с диска."""
        from chimera.modules import subscription
        cfg_path, unit_path, tmpdir = self._setup_paths(8443)
        recorder = _CallRecorder(ss_stdout=_SS_OUTPUT_EMPTY)
        try:
            with patch.object(subscription, "_SUB_CONF", cfg_path), \
                 patch.object(subscription, "_UNIT_PATH", unit_path), \
                 patch("shutil.which", return_value=None), \
                 patch("subprocess.run", side_effect=recorder):
                subscription.uninstall_subscription_service()
            self.assertFalse(unit_path.exists(),
                             "unit-файл должен быть удалён")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_kill_fallback_invoked(self):
        """Если ss показывает процесс на порту — kill -9 вызывается."""
        from chimera.modules import subscription
        cfg_path, unit_path, tmpdir = self._setup_paths(8443)
        recorder = _CallRecorder(ss_stdout=_SS_OUTPUT_WITH_PROC)
        try:
            with patch.object(subscription, "_SUB_CONF", cfg_path), \
                 patch.object(subscription, "_UNIT_PATH", unit_path), \
                 patch("shutil.which", return_value=None), \
                 patch("subprocess.run", side_effect=recorder):
                subscription.uninstall_subscription_service()
            kill_calls = [c for c in recorder.calls if c[:2] == ["kill", "-9"]]
            self.assertEqual(len(kill_calls), 1)
            self.assertEqual(kill_calls[0][2], "4966")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_cfg_marked_disabled_but_pepper_preserved(self):
        """enabled=False, но pepper/listen_port сохранены — при повторной
        установке старые ссылки продолжат работать."""
        from chimera.modules import subscription
        cfg_path, unit_path, tmpdir = self._setup_paths(8443)
        recorder = _CallRecorder(ss_stdout=_SS_OUTPUT_EMPTY)
        try:
            with patch.object(subscription, "_SUB_CONF", cfg_path), \
                 patch.object(subscription, "_UNIT_PATH", unit_path), \
                 patch("shutil.which", return_value=None), \
                 patch("subprocess.run", side_effect=recorder):
                subscription.uninstall_subscription_service()
            saved = json.loads(cfg_path.read_text())
            self.assertFalse(saved.get("enabled"), "enabled должен быть False")
            self.assertEqual(saved.get("pepper"), "abc",
                             "pepper должен быть сохранён (не инвалидирован)")
            self.assertEqual(saved.get("listen_port"), 8443,
                             "listen_port должен быть сохранён")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_ufw_port_closed_when_ufw_available(self):
        """Если ufw установлен — _fw_close_tcp вызывается (закрыть порт)."""
        from chimera.modules import subscription
        cfg_path, unit_path, tmpdir = self._setup_paths(8443)
        recorder = _CallRecorder(ss_stdout=_SS_OUTPUT_EMPTY)
        try:
            with patch.object(subscription, "_SUB_CONF", cfg_path), \
                 patch.object(subscription, "_UNIT_PATH", unit_path), \
                 patch("shutil.which", return_value="/usr/sbin/ufw"), \
                 patch("subprocess.run", side_effect=recorder):
                subscription.uninstall_subscription_service()
            # ufw delete allow 8443/tcp — закрытие порта.
            ufw_delete = [c for c in recorder.calls
                          if c[:2] == ["ufw", "delete"]]
            self.assertGreater(len(ufw_delete), 0,
                               "ufw delete должен быть вызван для закрытия порта")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_does_not_throw_if_unit_file_already_missing(self):
        """Если unit-файла нет (уже удалён) — не падает."""
        from chimera.modules import subscription
        cfg_path, unit_path, tmpdir = self._setup_paths(8443)
        unit_path.unlink()  # симулируем что unit уже удалён
        recorder = _CallRecorder(ss_stdout=_SS_OUTPUT_EMPTY)
        try:
            with patch.object(subscription, "_SUB_CONF", cfg_path), \
                 patch.object(subscription, "_UNIT_PATH", unit_path), \
                 patch("shutil.which", return_value=None), \
                 patch("subprocess.run", side_effect=recorder):
                # Не должно упасть.
                subscription.uninstall_subscription_service()
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestInstallServiceUnmask(unittest.TestCase):
    """_install_service — unmask перед enable.

    Без unmask: после uninstall через uninstall_subscription_service (которая
    маскирует юнит), повторный install через [1] молча не запустит сервис —
    unit symlink на /dev/null, systemctl enable молча игнорирует.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_unmask_called_before_enable(self):
        from chimera.modules import subscription
        tmpdir = Path(tempfile.mkdtemp())
        unit_path = tmpdir / "vless-subscription.service"
        nginx_snip = tmpdir / "vless-subscription.conf"
        recorder = _CallRecorder(ss_stdout=_SS_OUTPUT_EMPTY)
        try:
            with patch.object(subscription, "_UNIT_PATH", unit_path), \
                 patch.object(subscription, "_NGINX_SNIP", nginx_snip), \
                 patch("subprocess.run", side_effect=recorder):
                subscription._install_service(8443)
            actions = [c[1] for c in recorder.calls
                       if c[:1] == ["systemctl"] and len(c) > 1]
            # unmask должен быть вызван ДО enable.
            if "unmask" in actions and "enable" in actions:
                self.assertLess(actions.index("unmask"), actions.index("enable"),
                                "unmask должен быть ДО enable")
            else:
                self.fail("unmask или enable не вызваны")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestMaskFileAlreadyExistsRegression(unittest.TestCase):
    """Регрессия: 'Failed to mask unit: File ... already exists.' на systemd ≥252.

    Проблема: `systemctl mask` отказывается перезаписывать существующий
    unit-файл (нужен --force, которого нет на старом systemd). Решение:
    удалить unit-файл ДО mask — тогда mask создаёт symlink → /dev/null.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_unit_file_unlinked_before_mask(self):
        """Удаление unit-файла должно произойти ДО mask.

        Проверяем: путь unit_path.exists() должен быть False в момент
        вызова `systemctl mask`. Симулируем: записываем вызовы и для
        каждого mask-вызова проверяем что файла уже нет на диске.
        """
        from chimera.modules import subscription
        tmpdir = Path(tempfile.mkdtemp())
        cfg_path = tmpdir / "subscription.json"
        cfg_path.write_text(json.dumps({
            "listen_port": 8443, "enabled": True, "pepper": "abc",
        }))
        unit_path = tmpdir / "vless-subscription.service"
        unit_path.write_text("[Unit]\nDescription=test\n")
        mask_calls_with_file_state = []

        def mock_run(cmd, **kw):
            if cmd[:3] == ["systemctl", "mask", subscription.SERVICE_NAME]:
                # Записываем — существует ли файл в момент вызова mask.
                mask_calls_with_file_state.append(unit_path.exists())
            # Возвращаем пустой результат для всех команд.
            if cmd[:1] == ["ss"]:
                return _make_completed(_SS_OUTPUT_EMPTY)
            return _make_completed("")

        try:
            with patch.object(subscription, "_SUB_CONF", cfg_path), \
                 patch.object(subscription, "_UNIT_PATH", unit_path), \
                 patch("shutil.which", return_value=None), \
                 patch("subprocess.run", side_effect=mock_run):
                subscription.uninstall_subscription_service()
            self.assertEqual(len(mask_calls_with_file_state), 1,
                             "mask должен быть вызван ровно один раз")
            self.assertFalse(mask_calls_with_file_state[0],
                             "В момент вызова mask unit-файла уже не должно "
                             "быть на диске — иначе 'File already exists'")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_install_does_not_emit_reset_failed_not_loaded(self):
        """Проверка что reset-failed в _install_service глушит stderr —
        иначе пользователь видит 'Failed to reset failed state of unit
        vless-subscription.service: Unit ... not loaded.' при первом
        install (когда unit никогда не был загружен).
        """
        from chimera.modules import subscription
        tmpdir = Path(tempfile.mkdtemp())
        unit_path = tmpdir / "vless-subscription.service"
        nginx_snip = tmpdir / "vless-subscription.conf"
        reset_failed_calls = []

        def mock_run(cmd, **kw):
            # Ловим reset-failed и записываем kwargs.
            if cmd[:3] == ["systemctl", "reset-failed", subscription.SERVICE_NAME]:
                reset_failed_calls.append(kw)
            # Все вызовы возвращают success — daemon-reload, enable, restart
            # в тест-среде без systemd всё равно упадут, нам нужен только
            # факт вызова reset-failed с правильным stderr=DEVNULL.
            return _make_completed("")

        try:
            with patch.object(subscription, "_UNIT_PATH", unit_path), \
                 patch.object(subscription, "_NGINX_SNIP", nginx_snip), \
                 patch("subprocess.run", side_effect=mock_run):
                subscription._install_service(8443)
            # Проверяем что reset-failed вызван с подавленным stderr.
            self.assertGreater(len(reset_failed_calls), 0,
                               "reset-failed должен быть вызван в _install_service")
            for kw in reset_failed_calls:
                self.assertEqual(
                    kw.get("stderr"), subprocess.DEVNULL,
                    "stderr должен быть DEVNULL — иначе 'Unit ... not loaded.' "
                    "печатается и пугает пользователя"
                )
                self.assertEqual(
                    kw.get("stdout"), subprocess.DEVNULL,
                    "stdout тоже должен быть DEVNULL — иначе системный вывод "
                    "может загрязнять TUI"
                )
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
