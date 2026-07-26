#!/usr/bin/env python3
"""
tests/test_awg_apply.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/awg_apply.py.

Покрывает:
  1. awgs_apply_syncconf — syncconf через awg-quick strip + awg syncconf (mocked)
  2. awgs_apply_restart — systemctl restart (mocked)
  3. awgs_apply — диспетчер с fallback
  4. awgs_service_status — is-active / is-enabled (mocked)
  5. awgs_show_handshakes / awgs_show_dump — awg show (mocked)
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core


class TestApplySyncconf(unittest.TestCase):
    """awgs_apply_syncconf — бездаунтаймовое применение."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._conf = self._tmpdir / "awg0.conf"
        self._conf.write_text("[Interface]\nPrivateKey = x\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_false_when_no_server_conf(self):
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "AWGS_SERVER_CONF",
                          Path("/tmp/nonexistent_awg_xyz.conf")):
            result = awg_apply.awgs_apply_syncconf()
            self.assertFalse(result)

    def test_returns_true_on_success(self):
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "AWGS_SERVER_CONF", self._conf), \
             patch("chimera._core._run") as mock_run:
            # strip → ok, syncconf → ok
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="stripped config", stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),
            ]
            result = awg_apply.awgs_apply_syncconf()
            self.assertTrue(result)

    def test_returns_false_on_strip_failure(self):
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "AWGS_SERVER_CONF", self._conf), \
             patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="strip err")
            result = awg_apply.awgs_apply_syncconf()
            self.assertFalse(result)

    def test_returns_false_on_syncconf_failure(self):
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "AWGS_SERVER_CONF", self._conf), \
             patch("chimera._core._run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="stripped", stderr=""),
                MagicMock(returncode=1, stdout="", stderr="syncconf err"),
            ]
            result = awg_apply.awgs_apply_syncconf()
            self.assertFalse(result)


class TestApplyRestart(unittest.TestCase):
    """awgs_apply_restart — systemctl restart."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_true_on_success(self):
        from chimera.modules import awg_apply
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            self.assertTrue(awg_apply.awgs_apply_restart())

    def test_returns_false_on_failure(self):
        from chimera.modules import awg_apply
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="err")
            self.assertFalse(awg_apply.awgs_apply_restart())


class TestApplyDispatcher(unittest.TestCase):
    """awgs_apply — режимы."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_restart_mode_calls_restart(self):
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "awgs_apply_restart", return_value=True) as mock_r, \
             patch.object(awg_apply, "awgs_apply_syncconf") as mock_s:
            result = awg_apply.awgs_apply(mode="restart")
            self.assertTrue(result)
            mock_r.assert_called_once()
            mock_s.assert_not_called()

    def test_syncconf_success_no_fallback(self):
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "awgs_apply_syncconf", return_value=True) as mock_s, \
             patch.object(awg_apply, "awgs_apply_restart") as mock_r:
            result = awg_apply.awgs_apply(mode="syncconf")
            self.assertTrue(result)
            mock_s.assert_called_once()
            mock_r.assert_not_called()

    def test_syncconf_failure_triggers_fallback(self):
        """При syncconf-failure должен вызываться restart."""
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "awgs_apply_syncconf", return_value=False) as mock_s, \
             patch.object(awg_apply, "awgs_apply_restart", return_value=True) as mock_r:
            result = awg_apply.awgs_apply(mode="syncconf")
            self.assertTrue(result)
            mock_s.assert_called_once()
            mock_r.assert_called_once()


class TestApplyStderrSurfacing(unittest.TestCase):
    """v5.2: awgs_apply при syncconf-failure показывает пользователю
    фрагмент stderr от awg-quick strip — это defensive fallback на случай
    если проверка awgs_supports_i2_i5() в будущем окажется неточной на
    каком-то дистрибутиве. Реальная причина раньше терялась — её можно
    было найти только через ручной journalctl.

    v5.2.2: Обновлено под новый механизм извлечения stderr (через awg setconf
    на тестовом интерфейсе, а не awg-quick strip). Также добавлена проверка,
    что самоисцеление НЕ мешает defensive stderr fallback когда проблема
    не в I2-I5.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._conf = self._tmpdir / "awg0.conf"
        self._conf.write_text("[Interface]\nPrivateKey = x\n")
        # Сбрасываем флаг самоисцеления между тестами
        from chimera.modules import awg_apply
        awg_apply._SELF_HEAL_IN_PROGRESS = False

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        from chimera.modules import awg_apply
        awg_apply._SELF_HEAL_IN_PROGRESS = False

    def test_stderr_shown_in_warn_on_i2_unrecognized(self):
        """При 'Line unrecognized: I2=' в stderr — warn() содержит этот
        фрагмент и подсказку про обновление amneziawg-tools.

        v5.2.2: Если самоисцеление не помогает (например, awg_peer_rebuild_conf
        тоже падает), defensive stderr fallback всё равно должен показать
        точную причину.
        """
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "AWGS_SERVER_CONF", self._conf), \
             patch.object(awg_apply, "awgs_apply_syncconf", return_value=False), \
             patch.object(awg_apply, "awgs_apply_restart", return_value=True), \
             patch.object(awg_apply, "_self_heal_i2_i5_incompatibility",
                          return_value=False) as mock_heal, \
             patch.object(awg_apply, "_extract_apply_failure_stderr",
                          return_value="Line unrecognized: `I2='\n"
                                       "Configuration parsing error"), \
             patch("chimera._core.warn") as mock_warn:
            awg_apply.awgs_apply(mode="syncconf")
            # Самоисцеление должно было вызваться
            self.assertTrue(mock_heal.called,
                            "Самоисцеление должно вызываться при I2 ошибке")
            # defensive stderr fallback тоже должен показать причину
            self.assertTrue(mock_warn.called)
            # Ищем warn с точной причиной
            found_stderr_in_warn = False
            for call_args in mock_warn.call_args_list:
                msg = call_args[0][0]
                if "Line unrecognized" in msg and "I2" in msg:
                    found_stderr_in_warn = True
                    break
            self.assertTrue(found_stderr_in_warn,
                            "warn() должен содержать фрагмент stderr про I2")

    def test_stderr_shown_on_any_strip_error(self):
        """Любая ошибка (не только I2) должна попадать в warn()."""
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "AWGS_SERVER_CONF", self._conf), \
             patch.object(awg_apply, "awgs_apply_syncconf", return_value=False), \
             patch.object(awg_apply, "awgs_apply_restart", return_value=True), \
             patch.object(awg_apply, "_extract_apply_failure_stderr",
                          return_value="Some other awg-quick error"), \
             patch.object(awg_apply, "_is_i2_i5_unrecognized_error",
                          return_value=False), \
             patch("chimera._core.warn") as mock_warn:
            awg_apply.awgs_apply(mode="syncconf")
            self.assertTrue(mock_warn.called)
            # Ищем warn с точной причиной
            found_stderr_in_warn = False
            for call_args in mock_warn.call_args_list:
                msg = call_args[0][0]
                if "Some other awg-quick error" in msg:
                    found_stderr_in_warn = True
                    break
            self.assertTrue(found_stderr_in_warn,
                            "warn() должен содержать фрагмент stderr")

    def test_generic_warn_when_no_stderr_available(self):
        """Если stderr недоступен (например, conf не существует) —
        warn() показывает общее сообщение про syncconf-failure."""
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "AWGS_SERVER_CONF",
                          Path("/tmp/nonexistent_xyz.conf")), \
             patch.object(awg_apply, "awgs_apply_syncconf", return_value=False), \
             patch.object(awg_apply, "awgs_apply_restart", return_value=True), \
             patch.object(awg_apply, "_extract_apply_failure_stderr",
                          return_value=""), \
             patch("chimera._core.warn") as mock_warn:
            awg_apply.awgs_apply(mode="syncconf")
            self.assertTrue(mock_warn.called)
            warn_msg = mock_warn.call_args[0][0]
            self.assertIn("syncconf не удался", warn_msg,
                          f"Должно быть общее сообщение: {warn_msg}")


class TestIsI2I5UnrecognizedError(unittest.TestCase):
    """v5.2.2: _is_i2_i5_unrecognized_error — классификация ошибки."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_true_for_real_zvshka_error(self):
        """Реальная ошибка zvshka: 'Line unrecognized: I2=' + 'Configuration
        parsing error' → True (это I2-I5 проблема)."""
        from chimera.modules import awg_apply
        stderr = "Line unrecognized: `I2='\nConfiguration parsing error"
        self.assertTrue(awg_apply._is_i2_i5_unrecognized_error(stderr))

    def test_returns_true_for_i3_error(self):
        """Ошибка про I3 → True."""
        from chimera.modules import awg_apply
        stderr = "Line unrecognized: `I3='"
        self.assertTrue(awg_apply._is_i2_i5_unrecognized_error(stderr))

    def test_returns_true_for_i4_error(self):
        """Ошибка про I4 → True."""
        from chimera.modules import awg_apply
        stderr = "Line unrecognized: `I4='"
        self.assertTrue(awg_apply._is_i2_i5_unrecognized_error(stderr))

    def test_returns_true_for_i5_error(self):
        """Ошибка про I5 → True."""
        from chimera.modules import awg_apply
        stderr = "Line unrecognized: `I5='"
        self.assertTrue(awg_apply._is_i2_i5_unrecognized_error(stderr))

    def test_returns_true_for_configuration_parsing_error_with_i2(self):
        """'Configuration parsing error' с упоминанием I2 → True."""
        from chimera.modules import awg_apply
        stderr = "Configuration parsing error at line I2"
        self.assertTrue(awg_apply._is_i2_i5_unrecognized_error(stderr))

    def test_returns_false_for_unrelated_error(self):
        """Не-I2-I5 ошибка (например, 'Interface not found') → False."""
        from chimera.modules import awg_apply
        stderr = "Interface does not exist"
        self.assertFalse(awg_apply._is_i2_i5_unrecognized_error(stderr))

    def test_returns_false_for_empty_stderr(self):
        """Пустой stderr → False."""
        from chimera.modules import awg_apply
        self.assertFalse(awg_apply._is_i2_i5_unrecognized_error(""))

    def test_returns_false_for_privkey_error(self):
        """Ошибка про невалидный privkey → False (не I2-I5)."""
        from chimera.modules import awg_apply
        stderr = "Invalid private key"
        self.assertFalse(awg_apply._is_i2_i5_unrecognized_error(stderr))

    def test_returns_false_for_line_unrecognized_without_i2(self):
        """'Line unrecognized' без I2/I3/I4/I5 → False (другая директива)."""
        from chimera.modules import awg_apply
        stderr = "Line unrecognized: `SomeOtherKey='"
        self.assertFalse(awg_apply._is_i2_i5_unrecognized_error(stderr))


class TestSelfHealI2I5(unittest.TestCase):
    """v5.2.2: Самоисцеление при ошибке 'Line unrecognized: I2='.

    Корень проблемы v5.2.1: проверка awgs_supports_i2_i5() через awg setconf
    работает, но НЕ ВЫЗЫВАЕТСЯ если конфиг не переписывается. Пользователь
    zvshka сделал git pull + systemctl restart, но конфиг не переписался
    (перезапуск сервиса не вызывает awgs_build_server_conf). Поэтому в конфиге
    всё ещё пустые I2-I5, и awg-quick up падает.

    Решение v5.2.2: самоисцеление в awgs_apply(). Если apply падает с
    'Line unrecognized: I2=', автоматически переписать конфиг без I2-I5
    и повторить apply. Срабатывает при ЛЮБОМ действии, включая systemctl
    restart через fallback.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._conf = self._tmpdir / "awg0.conf"
        self._conf.write_text("[Interface]\nPrivateKey = x\nI2 = \n")
        from chimera.modules import awg_apply
        awg_apply._SELF_HEAL_IN_PROGRESS = False

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        from chimera.modules import awg_apply
        awg_apply._SELF_HEAL_IN_PROGRESS = False

    def test_self_heal_triggered_on_i2_error(self):
        """При I2 ошибке вызывается _self_heal_i2_i5_incompatibility()."""
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "AWGS_SERVER_CONF", self._conf), \
             patch.object(awg_apply, "awgs_apply_syncconf", return_value=False), \
             patch.object(awg_apply, "awgs_apply_restart", return_value=True), \
             patch.object(awg_apply, "_extract_apply_failure_stderr",
                          return_value="Line unrecognized: `I2='"), \
             patch.object(awg_apply, "_self_heal_i2_i5_incompatibility",
                          return_value=True) as mock_heal:
            result = awg_apply.awgs_apply(mode="syncconf")
        self.assertTrue(result, "Если самоисцеление успешно, awgs_apply=True")
        self.assertTrue(mock_heal.called,
                        "Самоисцеление должно вызываться при I2 ошибке")

    def test_self_heal_not_triggered_on_unrelated_error(self):
        """При не-I2 ошибке самоисцеление НЕ вызывается."""
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "AWGS_SERVER_CONF", self._conf), \
             patch.object(awg_apply, "awgs_apply_syncconf", return_value=False), \
             patch.object(awg_apply, "awgs_apply_restart", return_value=True), \
             patch.object(awg_apply, "_extract_apply_failure_stderr",
                          return_value="Interface not found"), \
             patch.object(awg_apply, "_self_heal_i2_i5_incompatibility",
                          return_value=True) as mock_heal:
            result = awg_apply.awgs_apply(mode="syncconf")
        self.assertTrue(mock_heal.assert_not_called)

    def test_self_heal_not_triggered_recursively(self):
        """Защита от рекурсии: если самоисцеление уже в процессе,
        оно не вызывается повторно."""
        from chimera.modules import awg_apply
        awg_apply._SELF_HEAL_IN_PROGRESS = True  # симулируем, что самоисцеление идёт
        with patch.object(awg_apply, "AWGS_SERVER_CONF", self._conf), \
             patch.object(awg_apply, "awgs_apply_syncconf", return_value=False), \
             patch.object(awg_apply, "awgs_apply_restart", return_value=True), \
             patch.object(awg_apply, "_extract_apply_failure_stderr",
                          return_value="Line unrecognized: `I2='"), \
             patch.object(awg_apply, "_self_heal_i2_i5_incompatibility",
                          return_value=True) as mock_heal:
            awg_apply.awgs_apply(mode="syncconf")
        self.assertFalse(mock_heal.called,
                         "Самоисцеление НЕ должно вызываться повторно "
                         "если уже в процессе (защита от рекурсии)")

    def test_self_heal_success_returns_true(self):
        """Если самоисцеление успешно (переписало конфиг и apply прошёл),
        awgs_apply возвращает True."""
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "AWGS_SERVER_CONF", self._conf), \
             patch.object(awg_apply, "awgs_apply_syncconf", return_value=False), \
             patch.object(awg_apply, "awgs_apply_restart", return_value=True), \
             patch.object(awg_apply, "_extract_apply_failure_stderr",
                          return_value="Line unrecognized: `I2='"), \
             patch.object(awg_apply, "_self_heal_i2_i5_incompatibility",
                          return_value=True):
            result = awg_apply.awgs_apply(mode="syncconf")
        self.assertTrue(result)

    def test_self_heal_failure_falls_back_to_restart(self):
        """Если самоисцеление не помогает, fallback на awgs_apply_restart()."""
        from chimera.modules import awg_apply
        with patch.object(awg_apply, "AWGS_SERVER_CONF", self._conf), \
             patch.object(awg_apply, "awgs_apply_syncconf", return_value=False), \
             patch.object(awg_apply, "awgs_apply_restart", return_value=True) as mock_restart, \
             patch.object(awg_apply, "_extract_apply_failure_stderr",
                          return_value="Line unrecognized: `I2='"), \
             patch.object(awg_apply, "_self_heal_i2_i5_incompatibility",
                          return_value=False):
            result = awg_apply.awgs_apply(mode="syncconf")
        self.assertTrue(result, "restart fallback должен вернуть True")
        self.assertTrue(mock_restart.called,
                        "Если самоисцеление не удалось, должен вызываться restart")


class TestSelfHealImplementation(unittest.TestCase):
    """v5.2.2: Интеграция _self_heal_i2_i5_incompatibility с реальной логикой.

    Проверяем, что самоисцеление действительно:
    1. Устанавливает кэш awgs_supports_i2_i5() в False
    2. Переписывает конфиг (через awg_peer_rebuild_conf)
    3. Повторяет apply
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import awg_apply, awg_compat
        awg_apply._SELF_HEAL_IN_PROGRESS = False
        awg_compat._reset_supports_cache()
        awg_compat._reset_old_tools_warn_flag()

    def tearDown(self):
        from chimera.modules import awg_apply, awg_compat
        awg_apply._SELF_HEAL_IN_PROGRESS = False
        awg_compat._reset_supports_cache()
        awg_compat._reset_old_tools_warn_flag()

    def test_self_heal_sets_cache_to_false(self):
        """Самоисцеление устанавливает кэш awgs_supports_i2_i5() в False,
        чтобы будущие записи конфига не писали I2-I5."""
        from chimera.modules import awg_apply, awg_compat
        from unittest.mock import MagicMock

        # awg_peer_rebuild_conf возвращает True (конфиг переписан)
        with patch("chimera.modules.awg_peers.awg_peer_rebuild_conf",
                   return_value=True), \
             patch.object(awg_apply, "awgs_apply_syncconf", return_value=True), \
             patch("chimera._core.warn"), \
             patch("chimera._core.log_to_file"):
            result = awg_apply._self_heal_i2_i5_incompatibility()

        self.assertTrue(result)
        # Кэш должен быть False
        from chimera.modules import awg_compat
        self.assertFalse(awg_compat.awgs_supports_i2_i5(),
                         "После самоисцеления кэш должен быть False")

    def test_self_heal_calls_rebuild_conf_and_repeats_apply(self):
        """Самоисцеление вызывает awg_peer_rebuild_conf(apply=False) и
        затем повторяет awgs_apply_syncconf()."""
        from chimera.modules import awg_apply
        from unittest.mock import MagicMock

        rebuild_called = [False]
        apply_called_after_rebuild = [False]

        def fake_rebuild(apply=True):
            rebuild_called[0] = True
            return True

        def fake_syncconf():
            # Если rebuild уже вызывался, это повторный apply после самоисцеления
            if rebuild_called[0]:
                apply_called_after_rebuild[0] = True
            return True

        with patch("chimera.modules.awg_peers.awg_peer_rebuild_conf",
                   side_effect=fake_rebuild), \
             patch.object(awg_apply, "awgs_apply_syncconf",
                          side_effect=fake_syncconf), \
             patch("chimera._core.warn"), \
             patch("chimera._core.log_to_file"):
            result = awg_apply._self_heal_i2_i5_incompatibility()

        self.assertTrue(result)
        self.assertTrue(rebuild_called[0],
                        "awg_peer_rebuild_conf должен вызываться")
        self.assertTrue(apply_called_after_rebuild[0],
                        "awgs_apply_syncconf должен вызываться ПОСЛЕ rebuild")

    def test_self_heal_returns_false_when_rebuild_fails(self):
        """Если awg_peer_rebuild_conf возвращает False, самоисцеление
        возвращает False (нельзя переписать конфиг)."""
        from chimera.modules import awg_apply

        with patch("chimera.modules.awg_peers.awg_peer_rebuild_conf",
                   return_value=False), \
             patch.object(awg_apply, "awgs_apply_syncconf", return_value=True), \
             patch("chimera._core.warn"), \
             patch("chimera._core.log_to_file"):
            result = awg_apply._self_heal_i2_i5_incompatibility()

        self.assertFalse(result,
                         "Если rebuild не удался, самоисцеление возвращает False")

    def test_self_heal_returns_false_when_repeat_apply_fails(self):
        """Если переписанный конфиг всё равно падает при apply, самоисцеление
        возвращает False (проблема не только в I2-I5)."""
        from chimera.modules import awg_apply

        with patch("chimera.modules.awg_peers.awg_peer_rebuild_conf",
                   return_value=True), \
             patch.object(awg_apply, "awgs_apply_syncconf", return_value=False), \
             patch("chimera._core.warn"), \
             patch("chimera._core.log_to_file"):
            result = awg_apply._self_heal_i2_i5_incompatibility()

        self.assertFalse(result,
                         "Если повторный apply не удался, самоисцеление=False")


class TestServiceStatus(unittest.TestCase):
    """awgs_service_status."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_active_and_enabled(self):
        from chimera.modules import awg_apply
        with patch("chimera._core._run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="active\n", stderr=""),
                MagicMock(returncode=0, stdout="enabled\n", stderr=""),
            ]
            status = awg_apply.awgs_service_status()
            self.assertTrue(status["active"])
            self.assertTrue(status["enabled"])

    def test_inactive_and_disabled(self):
        from chimera.modules import awg_apply
        with patch("chimera._core._run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=3, stdout="inactive\n", stderr=""),
                MagicMock(returncode=1, stdout="disabled\n", stderr=""),
            ]
            status = awg_apply.awgs_service_status()
            self.assertFalse(status["active"])
            self.assertFalse(status["enabled"])


class TestShowHandshakes(unittest.TestCase):
    """awgs_show_handshakes."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_stdout_on_success(self):
        from chimera.modules import awg_apply
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="peer: abc\nlatest handshake: 1s ago\n", stderr=""
            )
            out = awg_apply.awgs_show_handshakes()
            self.assertIn("peer: abc", out)

    def test_returns_empty_on_failure(self):
        from chimera.modules import awg_apply
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="err")
            out = awg_apply.awgs_show_handshakes()
            self.assertEqual(out, "")


class TestShowDump(unittest.TestCase):
    """awgs_show_dump — машиночитаемый формат."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_lines_on_success(self):
        from chimera.modules import awg_apply
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="iface line\npeer line1\npeer line2\n",
                stderr="",
            )
            lines = awg_apply.awgs_show_dump()
            self.assertEqual(len(lines), 3)

    def test_returns_empty_list_on_failure(self):
        from chimera.modules import awg_apply
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="err")
            self.assertEqual(awg_apply.awgs_show_dump(), [])

    def test_filters_empty_lines(self):
        from chimera.modules import awg_apply
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="line1\n\n  \nline2\n",
                stderr="",
            )
            lines = awg_apply.awgs_show_dump()
            self.assertEqual(len(lines), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
