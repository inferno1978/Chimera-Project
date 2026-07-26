#!/usr/bin/env python3
"""
tests/test_awg_compat.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/awg_compat.py.

Покрывает:
  1. awgs_supports_i2_i5 — проверка поддержки I2-I5 локальным awg-quick
  2. _run_strip_check — запуск awg-quick strip на тестовом конфиге
  3. awgs_warn_old_tools_once — одноразовый warn про старый awg-tools
  4. Кэширование результата (на время процесса)
  5. Edge cases: awg-quick не установлен, повреждённая установка, и пр.

Контекст: v5.2 — коммит 3e1fa70 ("всегда писать I1-I5") ломает совместимость
со старыми amneziawg-tools (AWG 1.5-эра). Этот модуль определяет возможности
локального awg-quick ПЕРЕД записью .conf, чтобы избежать регрессии.
"""
from __future__ import annotations

import sys
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


class TestSupportsI2I5(unittest.TestCase):
    """awgs_supports_i2_i5 — определение поддержки I2-I5."""

    def setUp(self):
        _setup_core_in_sysmodules()
        # Сбрасываем кэш перед каждым тестом
        from chimera.modules import awg_compat
        awg_compat._reset_supports_cache()
        awg_compat._reset_old_tools_warn_flag()

    def tearDown(self):
        from chimera.modules import awg_compat
        awg_compat._reset_supports_cache()
        awg_compat._reset_old_tools_warn_flag()

    def test_returns_true_when_strip_succeeds(self):
        """Если awg-quick strip успешно парсит конфиг с I2 — поддерживается."""
        from chimera.modules import awg_compat
        with patch.object(awg_compat, "_run_strip_check",
                          return_value=(True, "")):
            result = awg_compat.awgs_supports_i2_i5(force_refresh=True)
        self.assertTrue(result)

    def test_returns_false_when_strip_fails_on_i2(self):
        """Если awg-quick strip падает с 'Line unrecognized: I2=' —
        поддержка отсутствует (старые amneziawg-tools AWG 1.5-эры)."""
        from chimera.modules import awg_compat
        with patch.object(awg_compat, "_run_strip_check",
                          return_value=(False,
                              "Line unrecognized: `I2='\n"
                              "Configuration parsing error")):
            result = awg_compat.awgs_supports_i2_i5(force_refresh=True)
        self.assertFalse(result)

    def test_returns_false_when_strip_fails_on_i3(self):
        """Если ошибка про I3 — поддержка отсутствует (аналогично I2)."""
        from chimera.modules import awg_compat
        with patch.object(awg_compat, "_run_strip_check",
                          return_value=(False,
                              "Line unrecognized: `I3='")):
            result = awg_compat.awgs_supports_i2_i5(force_refresh=True)
        self.assertFalse(result)

    def test_returns_false_when_strip_fails_on_i4(self):
        """Если ошибка про I4 — поддержка отсутствует."""
        from chimera.modules import awg_compat
        with patch.object(awg_compat, "_run_strip_check",
                          return_value=(False,
                              "Line unrecognized: `I4='")):
            result = awg_compat.awgs_supports_i2_i5(force_refresh=True)
        self.assertFalse(result)

    def test_returns_false_when_strip_fails_on_i5(self):
        """Если ошибка про I5 — поддержка отсутствует."""
        from chimera.modules import awg_compat
        with patch.object(awg_compat, "_run_strip_check",
                          return_value=(False,
                              "Line unrecognized: `I5='")):
            result = awg_compat.awgs_supports_i2_i5(force_refresh=True)
        self.assertFalse(result)

    def test_returns_false_on_configuration_parsing_error(self):
        """Если strip падает с 'Configuration parsing error' — поддержка
        отсутствует (типичное сообщение старых amneziawg-tools)."""
        from chimera.modules import awg_compat
        with patch.object(awg_compat, "_run_strip_check",
                          return_value=(False,
                              "Configuration parsing error")):
            result = awg_compat.awgs_supports_i2_i5(force_refresh=True)
        self.assertFalse(result)

    def test_returns_true_on_unrelated_error_safe_default(self):
        """Если strip падает по НЕ I2-I5 причине (например, awg-quick нет
        в PATH, или privkey невалидный) — возвращаем True (safe default).

        Обоснование: лучше написать все 5 ключей и пусть пользователь
        обновит amneziawg-tools, чем молча выкинуть I2-I5 и потерять
        decoy-пакеты на совместимой системе из-за ложного срабатывания.
        """
        from chimera.modules import awg_compat
        with patch.object(awg_compat, "_run_strip_check",
                          return_value=(False,
                              "awg-quick: command not found")):
            result = awg_compat.awgs_supports_i2_i5(force_refresh=True)
        self.assertTrue(result,
                        "Safe default должен быть True при unrelated error")

    def test_returns_true_on_empty_stderr_safe_default(self):
        """Если strip падает без stderr (странно, но бывает) — safe True."""
        from chimera.modules import awg_compat
        with patch.object(awg_compat, "_run_strip_check",
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
        """Результат кэшируется — _run_strip_check вызывается только 1 раз
        даже при многократных вызовах awgs_supports_i2_i5()."""
        from chimera.modules import awg_compat
        call_count = [0]
        def fake_strip_check(quick_bin, sample_conf):
            call_count[0] += 1
            return (True, "")
        with patch.object(awg_compat, "_run_strip_check",
                          side_effect=fake_strip_check):
            # Первый вызов — выполняет реальную проверку
            r1 = awg_compat.awgs_supports_i2_i5(force_refresh=True)
            # Второй вызов — должен использовать кэш, не вызывать strip снова
            r2 = awg_compat.awgs_supports_i2_i5()
            r3 = awg_compat.awgs_supports_i2_i5()
        self.assertTrue(r1)
        self.assertTrue(r2)
        self.assertTrue(r3)
        self.assertEqual(call_count[0], 1,
                         "strip должен запускаться только 1 раз, "
                         "последующие вызовы берут результат из кэша")

    def test_force_refresh_bypasses_cache(self):
        """force_refresh=True игнорирует кэш и запускает strip снова."""
        from chimera.modules import awg_compat
        call_count = [0]
        def fake_strip_check(quick_bin, sample_conf):
            call_count[0] += 1
            return (True, "")
        with patch.object(awg_compat, "_run_strip_check",
                          side_effect=fake_strip_check):
            awg_compat.awgs_supports_i2_i5(force_refresh=True)
            awg_compat.awgs_supports_i2_i5(force_refresh=True)
            awg_compat.awgs_supports_i2_i5(force_refresh=True)
        self.assertEqual(call_count[0], 3,
                         "force_refresh должен каждый раз запускать strip")

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
        # После сброса кэш пустой — следующий вызов должен запустить strip
        with patch.object(awg_compat, "_run_strip_check",
                          return_value=(False, "Line unrecognized: `I2='")):
            result = awg_compat.awgs_supports_i2_i5()
        self.assertFalse(result,
                         "После reset — должен запустить strip и получить False")


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


class TestRunStripCheck(unittest.TestCase):
    """_run_strip_check — запуск awg-quick strip на тестовом конфиге."""

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
        """strip returncode=0 → (True, combined_output)."""
        from chimera.modules import awg_compat
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="stripped", stderr=""
            )
            ok, output = awg_compat._run_strip_check(
                "awg-quick", "[Interface]\nPrivateKey = x\n"
            )
        self.assertTrue(ok)
        self.assertIn("stripped", output)

    def test_returns_false_on_failure(self):
        """strip returncode=1 → (False, stderr+stdout)."""
        from chimera.modules import awg_compat
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="Line unrecognized: `I2='"
            )
            ok, output = awg_compat._run_strip_check(
                "awg-quick", "[Interface]\nI2 = \n"
            )
        self.assertFalse(ok)
        self.assertIn("Line unrecognized", output)

    def test_returns_false_on_exception(self):
        """Исключение (например, awg-quick нет в PATH) → (False, str(e))."""
        from chimera.modules import awg_compat
        with patch("chimera._core._run",
                   side_effect=FileNotFoundError("awg-quick not found")):
            ok, output = awg_compat._run_strip_check(
                "awg-quick", "[Interface]\n"
            )
        self.assertFalse(ok)
        self.assertIn("awg-quick not found", output)


class TestSampleConfContent(unittest.TestCase):
    """Проверка содержимого sample_conf, который awgs_supports_i2_i5
    передаёт в _run_strip_check — должен содержать все ключевые элементы."""

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
        def capture_strip_check(quick_bin, sample_conf):
            captured_conf.append(sample_conf)
            return (True, "")

        with patch.object(awg_compat, "_run_strip_check",
                          side_effect=capture_strip_check):
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
        Jmax/S1-S4/H1-H4) — без них strip может упасть по другой причине."""
        from chimera.modules import awg_compat

        captured_conf = []
        def capture_strip_check(quick_bin, sample_conf):
            captured_conf.append(sample_conf)
            return (True, "")

        with patch.object(awg_compat, "_run_strip_check",
                          side_effect=capture_strip_check):
            awg_compat.awgs_supports_i2_i5(force_refresh=True)

        conf = captured_conf[0]
        for param in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
                      "H1", "H2", "H3", "H4"):
            self.assertIn(f"{param} = ", conf,
                          f"Sample conf должен содержать {param}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
