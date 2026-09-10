#!/usr/bin/env python3
"""
tests/test_xray_safe_restart.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для (start-limit-fix):

  1. _core._xray_safe_restart — безопасный рестарт xray:
     • reset-failed вызывается ДО restart (сброс счётчика start-rate-limit);
     • мгновенный True при is-active=active;
     • повторная попытка (2× reset-failed), если первый start не взлетел;
     • честный False после исчерпания попыток;
     • wait_active respected (is-active опрашивается циклом).
  2. Пины регрессий:
     • юнит-шаблон xray (xray_install.py): StartLimitBurst=10 (было 3);
     • mtproto.py: reset-failed перед обоими restart xray;
     • emergency_repair.py: AGH в финальной проверке + reset-failed
       перед каждым start xray.

Контекст бага (репродукция vds13195, 2026-08-27): юнит xray.service
содержит StartLimitIntervalSec=60s + StartLimitBurst=3, а пересборка
конфига из меню (3 → 7 → R) делает 3-5 рестартов подряд (YouTube
restore → IP-pin → tproxy → финальный) — 4-й start отклонялся
systemd'ом («Start request repeated too quickly» → start-limit-hit),
xray оставался в failed при валидном конфиге.

Все внешние вызовы мокаются — тесты не трогают реальную систему.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Загружает chimera._core через exec ПРЯМО в __dict__ фейкового модуля.

    exec в __dict__ модуля (а не в отдельный dict с копированием)
    мутации ``core._run = MagicMock(...)`` из тестов видны функциям ядра
    через их __globals__.
    """
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    fake_core = types.ModuleType("chimera._core")
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), fake_core.__dict__)
    sys.modules["chimera._core"] = fake_core
    return fake_core


def _completed(stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr="",
    )


class _RunRecorder:
    """Мок _run: записывает все команды, возвращает результат по префиксу."""

    def __init__(self, is_active_outputs: list[str]):
        # outputs выдаются по очереди на каждый is-active вызов
        self.calls: list[list[str]] = []
        self._is_active_outputs = list(is_active_outputs)
        self._is_active_used = 0

    def __call__(self, args, check=True, quiet=False, capture=False, **kw):
        self.calls.append(list(args))
        if args[:3] == ["systemctl", "is-active", "xray"]:
            idx = min(self._is_active_used, len(self._is_active_outputs) - 1)
            out = self._is_active_outputs[idx]
            self._is_active_used += 1
            return _completed(out)
        return _completed("", 0)

    def cmd(self, *prefix: str) -> bool:
        """Есть ли среди вызовов команда с данным префиксом."""
        return any(c[:len(prefix)] == list(prefix) for c in self.calls)

    def cmd_index(self, *prefix: str):
        """Индекс первого вызова с данным префиксом (или None)."""
        for i, c in enumerate(self.calls):
            if c[:len(prefix)] == list(prefix):
                return i
        return None


class TestXraySafeRestart(unittest.TestCase):
    """_xray_safe_restart — ядро фикса start-limit-hit."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self.core = sys.modules["chimera._core"]
        self.core.warn = lambda *a, **kw: None

    def _helper(self):
        return self.core._xray_safe_restart

    def test_reset_failed_called_before_restart(self):
        """reset-failed обязан идти ПЕРЕД restart — иначе лимит не сбросится."""
        rec = _RunRecorder(["active"])
        self.core._run = rec
        ok = self._helper()()
        self.assertTrue(ok)
        self.assertTrue(rec.cmd("systemctl", "reset-failed", "xray"),
                        "reset-failed должен вызываться")
        rf = rec.cmd_index("systemctl", "reset-failed", "xray")
        rs = rec.cmd_index("systemctl", "restart", "xray")
        self.assertIsNotNone(rs, "restart должен вызываться")
        self.assertIsNotNone(rf)
        self.assertLess(rf, rs,
                        "reset-failed должен идти ДО restart (сброс лимита)")

    def test_returns_true_immediately_when_active(self):
        """is-active=active с первого раза → True, одна попытка."""
        rec = _RunRecorder(["active"])
        self.core._run = rec
        ok = self._helper()(wait_active=5)
        self.assertTrue(ok)
        self.assertEqual(
            sum(1 for c in rec.calls if c[:3] == ["systemctl", "is-active", "xray"]),
            1, "is-active должен опрашиваться ровно один раз при успехе")

    def test_retry_with_second_reset_failed(self):
        """Первая попытка не активна → вторая с повторным reset-failed."""
        rec = _RunRecorder(["failed", "failed", "failed", "active"])
        self.core._run = rec
        with patch("time.sleep", lambda s: None):
            ok = self._helper()(wait_active=2, attempts=2)
        self.assertTrue(ok, "Вторая попытка должна подняться")
        # Два reset-failed: по одному на каждую попытку
        self.assertEqual(
            sum(1 for c in rec.calls if c[:3] == ["systemctl", "reset-failed", "xray"]),
            2, "reset-failed должен вызываться перед КАЖДОЙ попыткой")
        # Оба reset-failed идут перед своим restart
        restarts = [i for i, c in enumerate(rec.calls)
                    if c[:3] == ["systemctl", "restart", "xray"]]
        resets = [i for i, c in enumerate(rec.calls)
                  if c[:3] == ["systemctl", "reset-failed", "xray"]]
        self.assertEqual(len(restarts), 2)
        self.assertLess(resets[0], restarts[0])
        self.assertLess(resets[1], restarts[1])

    def test_returns_false_after_attempts_exhausted(self):
        """is-active всегда failed → False, ровно attempts попыток."""
        rec = _RunRecorder(["failed"])
        self.core._run = rec
        with patch("time.sleep", lambda s: None):
            ok = self._helper()(wait_active=2, attempts=2)
        self.assertFalse(ok)
        self.assertEqual(
            sum(1 for c in rec.calls if c[:3] == ["systemctl", "restart", "xray"]),
            2, "Должно быть ровно 2 рестарта (attempts=2)")

    def test_single_attempt_mode(self):
        """attempts=1 (ru_subnets/as_direct путь с wait 90) — один рестарт."""
        rec = _RunRecorder(["failed"])
        self.core._run = rec
        with patch("time.sleep", lambda s: None):
            ok = self._helper()(wait_active=2, attempts=1)
        self.assertFalse(ok)
        self.assertEqual(
            sum(1 for c in rec.calls if c[:3] == ["systemctl", "restart", "xray"]),
            1)


class TestStartLimitRegressionPins(unittest.TestCase):
    """Пины регрессий: ключевые строки не должны быть потеряны при рефакторинге."""

    def test_unit_template_burst_raised(self):
        """Юнит-шаблон: StartLimitBurst=10 (старое значение 3 ломало пересборку)."""
        src = (_PROJECT_ROOT / "chimera" / "modules" / "xray_install.py").read_text()
        self.assertIn("StartLimitBurst=10", src)
        self.assertNotIn("StartLimitBurst=3\n", src)

    def test_mtproto_reset_failed_before_both_restarts(self):
        """mtproto: reset-failed перед restart xray в enable И disable tproxy."""
        src = (_PROJECT_ROOT / "chimera" / "modules" / "mtproto.py").read_text()
        needle = '_run(["systemctl", "reset-failed", XRAY_SERVICE_NAME])'
        self.assertEqual(src.count(needle), 2,
                         "reset-failed должен стоять перед обоими restart xray")

    def test_emergency_repair_has_agh_final_check(self):
        """Финальная проверка [11/11] содержит AdGuardHome (если установлен)."""
        src = (_PROJECT_ROOT / "chimera" / "modules" / "emergency_repair.py").read_text()
        self.assertIn('("AdGuardHome", "AdGuardHome")', src,
                      "AGH должен быть в списке финальной проверки")
        self.assertIn("is_aghome_installed", src)

    def test_emergency_repair_reset_failed_before_start(self):
        """emergency_repair: reset-failed перед каждым start xray."""
        src = (_PROJECT_ROOT / "chimera" / "modules" / "emergency_repair.py").read_text()
        needle = '_run(["systemctl", "reset-failed", "xray"], check=False, quiet=True)'
        self.assertGreaterEqual(src.count(needle), 2,
                                "reset-failed перед основной и повторной попыткой")

    def test_rebuild_uses_safe_restart(self):
        """_rebuild_and_restart_xray: финальный рестарт через _xray_safe_restart."""
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        self.assertIn("if _xray_safe_restart():", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
