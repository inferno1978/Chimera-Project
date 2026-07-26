#!/usr/bin/env python3
"""
tests/test_awg_compat.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/awg_compat.py.

Покрывает:
  1. awgs_supports_i2_i5 — проверка поддержки I2-I5 локальным awg-quick
  2. _run_setconf_check — реальный awg setconf на временном интерфейсе
  3. awgs_warn_old_tools_once — одноразовый warn про старый awg-tools
  4. Кэширование результата (на время процесса)
  5. Edge cases: awg не установлен, DKMS не загружен, и пр.
  6. Безопасность: тестовый интерфейс НИКОГДА не awg0, всегда удаляется

Контекст: v5.2.1 — критический фикс. v5.2 использовал `awg-quick strip`
для проверки поддержки I2-I5, но strip это текстовый фильтр, не валидирует
содержимое [Interface] за пределами своих собственных директив. Реальная
валидация (рождающая 'Line unrecognized: I2=') происходит внутри
`awg setconf`. v5.2.1 — заменён на реальный setconf против временного
интерфейса (не awg0!), единственный надёжный способ.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

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


class TestSupportsI2I5(unittest.TestCase):
    """awgs_supports_i2_i5 — определение поддержки I2-I5."""

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import awg_compat
        awg_compat._reset_supports_cache()
        awg_compat._reset_old_tools_warn_flag()

    def tearDown(self):
        from chimera.modules import awg_compat
        awg_compat._reset_supports_cache()
        awg_compat._reset_old_tools_warn_flag()

    def test_returns_true_when_setconf_succeeds(self):
        """Если awg setconf успешно применяет конфиг с I2 — поддерживается."""
        from chimera.modules import awg_compat
        with patch.object(awg_compat, "_run_setconf_check",
                          return_value=(True, "")):
            result = awg_compat.awgs_supports_i2_i5(force_refresh=True)
        self.assertTrue(result)

    def test_returns_false_when_setconf_fails_on_i2(self):
        """Если awg setconf падает с 'Line unrecognized: I2=' —
        поддержка отсутствует (старые amneziawg-tools AWG 1.5-эры).

        Это КЛЮЧЕВОЙ regression-тест на жалобу zvshka: v5.2 с strip
        давал False Positive здесь (strip возвращал 0, не валидируя I2).
        v5.2.1 с setconf — реальная валидация, должна поймать это.
        """
        from chimera.modules import awg_compat
        with patch.object(awg_compat, "_run_setconf_check",
                          return_value=(False,
                              "Line unrecognized: `I2='\n"
                              "Configuration parsing error")):
            result = awg_compat.awgs_supports_i2_i5(force_refresh=True)
        self.assertFalse(result)

    def test_returns_false_when_setconf_fails_on_i3(self):
        """Если ошибка про I3 — поддержка отсутствует (аналогично I2)."""
        from chimera.modules import awg_compat
        with patch.object(awg_compat, "_run_setconf_check",
                          return_value=(False,
                              "Line unrecognized: `I3='")):
            result = awg_compat.awgs_supports_i2_i5(force_refresh=True)
        self.assertFalse(result)

    def test_returns_false_when_setconf_fails_on_i4(self):
        """Если ошибка про I4 — поддержка отсутствует."""
        from chimera.modules import awg_compat
        with patch.object(awg_compat, "_run_setconf_check",
                          return_value=(False,
                              "Line unrecognized: `I4='")):
            result = awg_compat.awgs_supports_i2_i5(force_refresh=True)
        self.assertFalse(result)

    def test_returns_false_when_setconf_fails_on_i5(self):
        """Если ошибка про I5 — поддержка отсутствует."""
        from chimera.modules import awg_compat
        with patch.object(awg_compat, "_run_setconf_check",
                          return_value=(False,
                              "Line unrecognized: `I5='")):
            result = awg_compat.awgs_supports_i2_i5(force_refresh=True)
        self.assertFalse(result)

    def test_returns_false_on_configuration_parsing_error(self):
        """Если setconf падает с 'Configuration parsing error' — поддержка
        отсутствует (типичное сообщение старых amneziawg-tools)."""
        from chimera.modules import awg_compat
        with patch.object(awg_compat, "_run_setconf_check",
                          return_value=(False,
                              "Configuration parsing error")):
            result = awg_compat.awgs_supports_i2_i5(force_refresh=True)
        self.assertFalse(result)

    def test_returns_true_on_unrelated_error_safe_default(self):
        """Если setconf падает по НЕ I2-I5 причине (например, awg нет
        в PATH, или privkey невалидный) — возвращаем True (safe default).

        Обоснование: лучше написать все 5 ключей и пусть пользователь
        обновит amneziawg-tools, чем молча выкинуть I2-I5 и потерять
        decoy-пакеты на совместимой системе из-за ложного срабатывания.
        """
        from chimera.modules import awg_compat
        with patch.object(awg_compat, "_run_setconf_check",
                          return_value=(False,
                              "awg: command not found")):
            result = awg_compat.awgs_supports_i2_i5(force_refresh=True)
        self.assertTrue(result,
                        "Safe default должен быть True при unrelated error")

    def test_returns_true_on_empty_stderr_safe_default(self):
        """Если setconf падает без stderr (странно, но бывает) — safe True."""
        from chimera.modules import awg_compat
        with patch.object(awg_compat, "_run_setconf_check",
                          return_value=(False, "")):
            result = awg_compat.awgs_supports_i2_i5(force_refresh=True)
        self.assertTrue(result)


class TestSupportsCache(unittest.TestCase):
    """Кэширование результата awgs_supports_i2_i5 на время процесса."""

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import awg_compat
        awg_compat._reset_supports_cache()
        awg_compat._reset_old_tools_warn_flag()

    def tearDown(self):
        from chimera.modules import awg_compat
        awg_compat._reset_supports_cache()
        awg_compat._reset_old_tools_warn_flag()

    def test_result_cached_between_calls(self):
        """Результат кэшируется — _run_setconf_check вызывается только 1 раз
        даже при многократных вызовах awgs_supports_i2_i5()."""
        from chimera.modules import awg_compat
        call_count = [0]
        def fake_setconf_check(sample_conf):
            call_count[0] += 1
            return (True, "")
        with patch.object(awg_compat, "_run_setconf_check",
                          side_effect=fake_setconf_check):
            # Первый вызов — выполняет реальную проверку
            r1 = awg_compat.awgs_supports_i2_i5(force_refresh=True)
            # Второй вызов — должен использовать кэш, не вызывать setconf снова
            r2 = awg_compat.awgs_supports_i2_i5()
            r3 = awg_compat.awgs_supports_i2_i5()
        self.assertTrue(r1)
        self.assertTrue(r2)
        self.assertTrue(r3)
        self.assertEqual(call_count[0], 1,
                         "setconf должен запускаться только 1 раз, "
                         "последующие вызовы берут результат из кэша")

    def test_force_refresh_bypasses_cache(self):
        """force_refresh=True игнорирует кэш и запускает setconf снова."""
        from chimera.modules import awg_compat
        call_count = [0]
        def fake_setconf_check(sample_conf):
            call_count[0] += 1
            return (True, "")
        with patch.object(awg_compat, "_run_setconf_check",
                          side_effect=fake_setconf_check):
            awg_compat.awgs_supports_i2_i5(force_refresh=True)
            awg_compat.awgs_supports_i2_i5(force_refresh=True)
            awg_compat.awgs_supports_i2_i5(force_refresh=True)
        self.assertEqual(call_count[0], 3,
                         "force_refresh должен каждый раз запускать setconf")

    def test_set_supports_cache_for_tests(self):
        """_set_supports_cache — утилита для тестов, mock'ает результат
        без реального subprocess."""
        from chimera.modules import awg_compat
        awg_compat._set_supports_cache(True)
        self.assertTrue(awg_compat.awgs_supports_i2_i5())
        awg_compat._set_supports_cache(False)
        self.assertFalse(awg_compat.awgs_supports_i2_i5())

    def test_reset_supports_cache(self):
        """_reset_supports_cache сбрасывает кэш — следующий вызов снова
        запускает реальную проверку."""
        from chimera.modules import awg_compat
        awg_compat._set_supports_cache(True)
        self.assertTrue(awg_compat.awgs_supports_i2_i5())
        awg_compat._reset_supports_cache()
        # После сброса кэш пустой — следующий вызов должен запустить setconf
        with patch.object(awg_compat, "_run_setconf_check",
                          return_value=(False, "Line unrecognized: `I2='")):
            result = awg_compat.awgs_supports_i2_i5()
        self.assertFalse(result,
                         "После reset — должен запустить setconf и получить False")


class TestWarnOldToolsOnce(unittest.TestCase):
    """awgs_warn_old_tools_once — одноразовый warn про старый awg-tools."""

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import awg_compat
        awg_compat._reset_supports_cache()
        awg_compat._reset_old_tools_warn_flag()

    def tearDown(self):
        from chimera.modules import awg_compat
        awg_compat._reset_supports_cache()
        awg_compat._reset_old_tools_warn_flag()

    def test_warn_called_once_per_process(self):
        """warn() показывается ОДИН раз за процесс, не спамим на каждый apply."""
        from chimera.modules import awg_compat
        with patch("chimera._core.warn") as mock_warn:
            awg_compat.awgs_warn_old_tools_once()
            awg_compat.awgs_warn_old_tools_once()
            awg_compat.awgs_warn_old_tools_once()
        self.assertEqual(mock_warn.call_count, 1,
                         "warn() должен вызываться ровно 1 раз за процесс")

    def test_warn_message_contains_upgrade_advice(self):
        """Сообщение warn содержит совет обновить amneziawg-tools."""
        from chimera.modules import awg_compat
        with patch("chimera._core.warn") as mock_warn:
            awg_compat.awgs_warn_old_tools_once()
        self.assertTrue(mock_warn.called)
        msg = mock_warn.call_args[0][0]
        self.assertIn("amneziawg-tools", msg)
        self.assertIn("apt", msg)  # команда обновления
        self.assertIn("I2-I5", msg)

    def test_warn_can_be_reset_for_tests(self):
        """_reset_old_tools_warn_flag сбрасывает флаг — warn можно
        показать снова (для тестов)."""
        from chimera.modules import awg_compat
        with patch("chimera._core.warn") as mock_warn:
            awg_compat.awgs_warn_old_tools_once()
            awg_compat._reset_old_tools_warn_flag()
            awg_compat.awgs_warn_old_tools_once()
        self.assertEqual(mock_warn.call_count, 2,
                         "После reset — warn должен вызваться снова")


class TestRunSetconfCheck(unittest.TestCase):
    """_run_setconf_check — реальный awg setconf на временном интерфейсе.

    v5.2.1: заменяет TestRunStripCheck. Ключевое отличие — setconf это
    РЕАЛЬНЫЙ путь валидации (тот же, что при awg-quick up), а не
    текстовый фильтр как strip.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import awg_compat
        awg_compat._reset_supports_cache()
        awg_compat._reset_old_tools_warn_flag()

    def tearDown(self):
        from chimera.modules import awg_compat
        awg_compat._reset_supports_cache()
        awg_compat._reset_old_tools_warn_flag()

    def test_returns_true_on_success(self):
        """setconf returncode=0 → (True, combined_output).

        Полный сценарий: ip link add → OK, awg setconf → OK, ip link delete.
        """
        from chimera.modules import awg_compat
        with patch("chimera._core._run") as mock_run:
            # ip link add → OK
            # awg setconf → OK
            # ip link delete → OK (в finally)
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="", stderr=""),       # ip link add
                MagicMock(returncode=0, stdout="", stderr=""),       # awg setconf
                MagicMock(returncode=0, stdout="", stderr=""),       # ip link delete
            ]
            ok, output = awg_compat._run_setconf_check(
                "[Interface]\nPrivateKey = x\n"
            )
        self.assertTrue(ok)
        # 3 вызова: add, setconf, delete
        self.assertEqual(mock_run.call_count, 3)

    def test_returns_false_on_setconf_failure(self):
        """setconf returncode=1 → (False, stderr+stdout).

        Старые amneziawg-tools падают здесь с 'Line unrecognized: I2='.
        """
        from chimera.modules import awg_compat
        with patch("chimera._core._run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="", stderr=""),       # ip link add
                MagicMock(returncode=1, stdout="",
                          stderr="Line unrecognized: `I2='"),        # awg setconf
                MagicMock(returncode=0, stdout="", stderr=""),       # ip link delete
            ]
            ok, output = awg_compat._run_setconf_check(
                "[Interface]\nI2 = \n"
            )
        self.assertFalse(ok)
        self.assertIn("Line unrecognized", output)

    def test_returns_true_on_ip_link_add_failure_safe_default(self):
        """Если `ip link add` падает (DKMS не загружен, нет прав) —
        возвращаем (True, stderr) как safe default.

        Это НЕ I2-I5 ошибка — лучше вернуть True, чтобы не выкинуть
        I2-I5 из-за ложного срабатывания. awgs_supports_i2_i5() потом
        тоже вернёт True (safe default).
        """
        from chimera.modules import awg_compat
        with patch("chimera._core._run") as mock_run:
            # ip link add → fail (DKMS not loaded)
            mock_run.return_value = MagicMock(
                returncode=2, stdout="",
                stderr="RTNETLINK answers: Operation not permitted"
            )
            ok, output = awg_compat._run_setconf_check(
                "[Interface]\nPrivateKey = x\n"
            )
        self.assertTrue(ok, "Safe default True при ip link add failure")
        self.assertIn("Operation not permitted", output)
        # Только 1 вызов: ip link add (fail). setconf и delete не вызываются.
        self.assertEqual(mock_run.call_count, 1,
                         "Только ip link add — setconf не должен вызываться "
                         "если интерфейс не создан")

    def test_returns_false_on_exception(self):
        """Исключение из core._run (FileNotFoundError если ip/awg нет
        в PATH, и пр.) — возвращается как (False, str(e)), не валит процесс.

        v5.2.1: _run_setconf_check ловит исключения и возвращает (False, str(e)),
        чтобы awgs_supports_i2_i5 могла применить safe-default логику.
        """
        from chimera.modules import awg_compat
        with patch("chimera._core._run",
                   side_effect=FileNotFoundError("ip not found")):
            ok, output = awg_compat._run_setconf_check(
                "[Interface]\n"
            )
        self.assertFalse(ok)
        self.assertIn("ip not found", output)


class TestRunSetconfCheckInterfaceCleanup(unittest.TestCase):
    """v5.2.1: тестовый интерфейс ВСЕГДА удаляется, даже при ошибке setconf.

    Критично — не оставляем мусор в системе пользователя. Даже если
    setconf упал, интерфейс должен быть удалён в finally-блоке.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import awg_compat
        awg_compat._reset_supports_cache()
        awg_compat._reset_old_tools_warn_flag()

    def tearDown(self):
        from chimera.modules import awg_compat
        awg_compat._reset_supports_cache()
        awg_compat._reset_old_tools_warn_flag()

    def test_interface_cleaned_up_on_setconf_failure(self):
        """Если setconf упал — интерфейс всё равно удаляется."""
        from chimera.modules import awg_compat
        with patch("chimera._core._run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="", stderr=""),       # ip link add → OK
                MagicMock(returncode=1, stdout="",
                          stderr="Line unrecognized: `I2='"),        # awg setconf → FAIL
                MagicMock(returncode=0, stdout="", stderr=""),       # ip link delete
            ]
            awg_compat._run_setconf_check("[Interface]\nI2 = \n")
            # Проверяем что ip link delete был вызван
            calls = mock_run.call_args_list
            self.assertEqual(len(calls), 3,
                             "Должно быть 3 вызова: add, setconf, delete")
            # Третий вызов — ip link delete
            third_call_args = calls[2][0][0]
            self.assertIn("ip", third_call_args)
            self.assertIn("link", third_call_args)
            self.assertIn("delete", third_call_args)

    def test_interface_cleaned_up_on_setconf_success(self):
        """Если setconf успешен — интерфейс тоже удаляется."""
        from chimera.modules import awg_compat
        with patch("chimera._core._run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="", stderr=""),       # ip link add
                MagicMock(returncode=0, stdout="", stderr=""),       # awg setconf
                MagicMock(returncode=0, stdout="", stderr=""),       # ip link delete
            ]
            awg_compat._run_setconf_check("[Interface]\n")
            calls = mock_run.call_args_list
            # Третий вызов — ip link delete
            third_call_args = calls[2][0][0]
            self.assertIn("delete", third_call_args)

    def test_interface_not_deleted_when_add_fails(self):
        """Если ip link add упал — интерфейс не создан, delete не вызывается.

        Микро-оптимизация + semantic correctness: не пытаемся удалить
        то, чего нет.
        """
        from chimera.modules import awg_compat
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=2, stdout="", stderr="Operation not permitted"
            )
            awg_compat._run_setconf_check("[Interface]\n")
            # Только 1 вызов: ip link add (fail). delete не вызывается.
            self.assertEqual(mock_run.call_count, 1)


class TestRunSetconfCheckInterfaceName(unittest.TestCase):
    """v5.2.1: тестовый интерфейс НИКОГДА не равен awg0/AWGS_INTERFACE.

    Защита от случайного повреждения реального интерфейса пользователя.
    uuid гарантирует уникальность, но дополнительная explicit-проверка
    добавляет второй слой safety.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import awg_compat
        awg_compat._reset_supports_cache()
        awg_compat._reset_old_tools_warn_flag()

    def tearDown(self):
        from chimera.modules import awg_compat
        awg_compat._reset_supports_cache()
        awg_compat._reset_old_tools_warn_flag()

    def test_interface_name_never_awg0(self):
        """Сгенерированное имя интерфейса никогда не равно 'awg0'."""
        from chimera.modules import awg_compat
        captured_iface_names = []

        def capture_run(cmd, **kwargs):
            # Перехватываем имя интерфейса из `ip link add <name> type ...`
            if len(cmd) >= 4 and cmd[0] == "ip" and cmd[1] == "link" \
                    and cmd[2] == "add":
                captured_iface_names.append(cmd[3])
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("chimera._core._run", side_effect=capture_run):
            # Запускаем 100 раз — uuid должен каждый раз давать уникальное
            # имя, ни одно не должно совпасть с awg0
            for _ in range(100):
                awg_compat._run_setconf_check("[Interface]\n")

        self.assertEqual(len(captured_iface_names), 100)
        for name in captured_iface_names:
            self.assertNotEqual(name, "awg0",
                                f"Имя интерфейса НЕ должно быть 'awg0': {name}")
            self.assertTrue(name.startswith("awgprobe"),
                            f"Имя должно начинаться с 'awgprobe': {name}")

    def test_all_generated_names_unique(self):
        """uuid гарантирует уникальность — даже 1000 запусков не дают дублей."""
        from chimera.modules import awg_compat
        captured_names = []

        def capture_run(cmd, **kwargs):
            if len(cmd) >= 4 and cmd[0] == "ip" and cmd[1] == "link" \
                    and cmd[2] == "add":
                captured_names.append(cmd[3])
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("chimera._core._run", side_effect=capture_run):
            for _ in range(50):
                awg_compat._run_setconf_check("[Interface]\n")

        self.assertEqual(len(captured_names), 50)
        self.assertEqual(len(set(captured_names)), 50,
                         "Все 50 имён должны быть уникальными (uuid)")


class TestSampleConfContent(unittest.TestCase):
    """Проверка содержимого sample_conf, который awgs_supports_i2_i5
    передаёт в _run_setconf_check.

    v5.2.1: sample_conf должен быть в "striппнутом" формате — только
    [Interface] с PrivateKey/ListenPort/Jc.../I1-I5. НЕ содержит
    Address/MTU/DNS/Table/PreUp/PostUp — иначе setconf отвергнет его
    по другой причине (не про I2), и тест даст ложный отрицательный
    результат.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import awg_compat
        awg_compat._reset_supports_cache()
        awg_compat._reset_old_tools_warn_flag()

    def tearDown(self):
        from chimera.modules import awg_compat
        awg_compat._reset_supports_cache()
        awg_compat._reset_old_tools_warn_flag()

    def test_sample_conf_contains_i1_through_i5(self):
        """Sample conf должен содержать I1 (непустой) и I2-I5 (пустые) —
        это и есть тест на поддержку I2-I5."""
        from chimera.modules import awg_compat

        captured_conf = []
        def capture_setconf_check(sample_conf):
            captured_conf.append(sample_conf)
            return (True, "")

        with patch.object(awg_compat, "_run_setconf_check",
                          side_effect=capture_setconf_check):
            awg_compat.awgs_supports_i2_i5(force_refresh=True)

        self.assertEqual(len(captured_conf), 1)
        conf = captured_conf[0]
        self.assertIn("I1 = <r 24>", conf,
                      "Sample conf должен содержать I1 (непустой CPS tag)")
        self.assertIn("I2 = \n", conf,
                      "Sample conf должен содержать I2 (пустой)")
        self.assertIn("I3 = \n", conf)
        self.assertIn("I4 = \n", conf)
        self.assertIn("I5 = \n", conf)

    def test_sample_conf_contains_basic_awg_params(self):
        """Sample conf должен содержать базовые AWG-параметры (Jc/Jmin/
        Jmax/S1-S4/H1-H4) — без них setconf может упасть по другой причине."""
        from chimera.modules import awg_compat

        captured_conf = []
        def capture_setconf_check(sample_conf):
            captured_conf.append(sample_conf)
            return (True, "")

        with patch.object(awg_compat, "_run_setconf_check",
                          side_effect=capture_setconf_check):
            awg_compat.awgs_supports_i2_i5(force_refresh=True)

        conf = captured_conf[0]
        for param in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
                      "H1", "H2", "H3", "H4"):
            self.assertIn(f"{param} = ", conf,
                          f"Sample conf должен содержать {param}")

    def test_sample_conf_stripped_format_no_awg_quick_directives(self):
        """v5.2.1: sample_conf в "стриппнутом" формате для awg setconf.

        НЕ содержит Address/MTU/DNS/Table/PreUp/PostUp/SaveConfig —
        это awg-quick-only директивы, setconf их не понимает и
        отвергнет с ошибкой (не про I2), дав ложный отрицательный результат.
        """
        from chimera.modules import awg_compat

        captured_conf = []
        def capture_setconf_check(sample_conf):
            captured_conf.append(sample_conf)
            return (True, "")

        with patch.object(awg_compat, "_run_setconf_check",
                          side_effect=capture_setconf_check):
            awg_compat.awgs_supports_i2_i5(force_refresh=True)

        conf = captured_conf[0]
        # Эти директивы НЕ должны быть в stripped-формате
        forbidden = ["Address =", "MTU =", "DNS =", "Table =",
                     "PreUp =", "PreDown =", "PostUp =", "PostDown =",
                     "SaveConfig ="]
        for directive in forbidden:
            self.assertNotIn(directive, conf,
                             f"Sample conf НЕ должен содержать '{directive}' "
                             f"— это awg-quick-only директива, setconf её "
                             f"не примет")

    def test_sample_conf_contains_privatekey_and_listenport(self):
        """Sample conf должен содержать PrivateKey и ListenPort —
        обязательные директивы для setconf."""
        from chimera.modules import awg_compat

        captured_conf = []
        def capture_setconf_check(sample_conf):
            captured_conf.append(sample_conf)
            return (True, "")

        with patch.object(awg_compat, "_run_setconf_check",
                          side_effect=capture_setconf_check):
            awg_compat.awgs_supports_i2_i5(force_refresh=True)

        conf = captured_conf[0]
        self.assertIn("PrivateKey = ", conf,
                      "Sample conf должен содержать PrivateKey")
        self.assertIn("ListenPort = ", conf,
                      "Sample conf должен содержать ListenPort")

    def test_sample_conf_listenport_zero_avoids_conflicts(self):
        """ListenPort = 0 — kernel присваивает ephemeral port, не
        конфликтует с реальным awg0 (который обычно на 51820)."""
        from chimera.modules import awg_compat

        captured_conf = []
        def capture_setconf_check(sample_conf):
            captured_conf.append(sample_conf)
            return (True, "")

        with patch.object(awg_compat, "_run_setconf_check",
                          side_effect=capture_setconf_check):
            awg_compat.awgs_supports_i2_i5(force_refresh=True)

        conf = captured_conf[0]
        self.assertIn("ListenPort = 0", conf,
                      "ListenPort должен быть 0 — kernel присвоит ephemeral, "
                      "не конфликтует с awg0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
