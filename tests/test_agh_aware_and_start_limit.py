#!/usr/bin/env python3
"""
tests/test_agh_aware_and_start_limit.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для 

  A. AGH-aware DNS (умное определение резолва + автооткат на 5300):
     • olcrtc._resolver_for_olcrtc — живой AGH → 127.0.0.1:53;
       AGH болен + dnscrypt active → 127.0.0.1:5300; оба недоступны →
       8.8.8.8:53 (прежний дефолт);
     • _generate_config_json подставляет выбранный резолвер в dns каждого
       location;
     • сбой импорта agh_probe → тихий откат (не исключение).

  B. Тотальная защита от start-limit-hit (→):
     • СТАТИЧЕСКИЙ ГВАРД: каждый «systemctl restart xray» в chimera/ либо
       сопровождается reset-failed в соседних строках, либо идёт через
       безопасные обёртки (_xray_safe_restart / _xray_restart_safe /
       restart_service), либо покрыт явным исключением (ExecReload-юнит,
       комментарии/доки);
     • _xray_safe_apply_config (xray_install) зовёт _core._xray_safe_restart;
     • fail2ban watchdog-скрипт содержит reset-failed перед restart;
     • fp-rotate cron-скрипт (_core) содержит reset-failed.

Контекст: на <node-2> пересборка конфига из меню (3 → 7 → R) ловила
start-limit-hit (StartLimitBurst=3/60s). закрыла цепочку пересборки,
 закрывает ВСЕ остальные точки рестарта xray + добавляет AGH-aware
DNS в генератор конфига olcrtc-manager.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

# Файлы, где «restart xray» допустим без встроенного reset-failed рядом:
# это документация/комментарии либо ExecReload-семантика самого юнита.
_STATIC_GUARD_EXEMPT_MARKERS = [
    "ExecReload=/bin/systemctl restart xray",
]
# Каталоги, не входящие в рантайм-код.
_STATIC_GUARD_SKIP_DIRS = {"_vendor", "__pycache__", "docs"}


def _setup_core_in_sysmodules():
    """Загружает chimera._core через exec в __dict__ фейкового модуля."""
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


# ═════════════════════════════════════════════════════════════════════════════
#  A. olcrtc: AGH-aware DNS-резолвер
# ═════════════════════════════════════════════════════════════════════════════
class TestOlcrtcResolver(unittest.TestCase):
    """_resolver_for_olcrtc: AGH → dnscrypt:5300 → 8.8.8.8 с автооткатом."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _resolver(self, agh_available, dnscrypt_active="inactive",
                  agh_import_ok=True):
        """Вызывает _resolver_for_olcrtc с замоканными проверками."""
        import chimera.modules.olcrtc as olcrtc

        calls = []

        def fake_agh(run=None, log_info=None, log_warn=None, autostart=False):
            calls.append("agh_probe")
            return agh_available, "note"

        def fake_run(cmd, capture=False, check=False, quiet=False, **kw):
            calls.append(list(cmd))
            if cmd[:3] == ["systemctl", "is-active", "dnscrypt-proxy"]:
                return _completed(stdout=dnscrypt_active)
            return _completed()

        agh_mod = types.ModuleType("chimera.modules.agh_probe")
        agh_mod.agh_dns_available = fake_agh

        with patch.dict(sys.modules, {"chimera.modules.agh_probe": agh_mod}), \
             patch.object(olcrtc, "_run", fake_run):
            return olcrtc._resolver_for_olcrtc(), calls

    def test_agh_healthy_returns_53(self):
        """Живой AGH (все 3 критерия + проба резолва) → 127.0.0.1:53."""
        res, calls = self._resolver(agh_available=True)
        self.assertEqual(res, "127.0.0.1:53")
        self.assertIn("agh_probe", calls)

    def test_agh_dead_dnscrypt_active_returns_5300(self):
        """AGH не прошёл health-check → автооткат на dnscrypt:5300."""
        res, calls = self._resolver(agh_available=False, dnscrypt_active="active")
        self.assertEqual(res, "127.0.0.1:5300")

    def test_agh_dead_dnscrypt_dead_returns_public(self):
        """Нет AGH, нет dnscrypt → прежний дефолт 8.8.8.8:53."""
        res, _ = self._resolver(agh_available=False, dnscrypt_active="failed")
        self.assertEqual(res, "8.8.8.8:53")

    def test_agh_probe_import_failure_falls_back(self):
        """Исключение при импорте agh_probe → тихий откат, не крах."""
        import chimera.modules.olcrtc as olcrtc

        def boom_run(cmd, capture=False, check=False, quiet=False, **kw):
            if cmd[:3] == ["systemctl", "is-active", "dnscrypt-proxy"]:
                return _completed(stdout="active")
            return _completed()

        # agh_dns_available бросает исключение (как при битом импорте)
        agh_mod = types.ModuleType("chimera.modules.agh_probe")

        def raise_agh(**kw):
            raise RuntimeError("probe failed")

        agh_mod.agh_dns_available = raise_agh
        with patch.dict(sys.modules, {"chimera.modules.agh_probe": agh_mod}), \
             patch.object(olcrtc, "_run", boom_run):
            res = olcrtc._resolver_for_olcrtc()
        self.assertEqual(res, "127.0.0.1:5300")

    def test_generate_config_uses_resolver(self):
        """dns-поле каждого location берётся из _resolver_for_olcrtc."""
        import chimera.modules.olcrtc as olcrtc
        locations = [{
            "name": "wb-stream",
            "client_id": "wb",
            "carrier": "wbstream",
            "transport": "vp8channel",
            "room_id": "ROOM",
            "key": "KEY",
        }]
        with patch.object(olcrtc, "_resolver_for_olcrtc",
                          return_value="127.0.0.1:53"):
            cfg = json.loads(olcrtc._generate_config_json(locations))
        loc = cfg["clients"][0]["locations"][0]
        self.assertEqual(loc["dns"], "127.0.0.1:53")

        with patch.object(olcrtc, "_resolver_for_olcrtc",
                          return_value="127.0.0.1:5300"):
            cfg = json.loads(olcrtc._generate_config_json(locations))
        loc = cfg["clients"][0]["locations"][0]
        self.assertEqual(loc["dns"], "127.0.0.1:5300")


# ═════════════════════════════════════════════════════════════════════════════
#  B. Статический гвард: reset-failed у каждого restart xray
# ═════════════════════════════════════════════════════════════════════════════
class TestStartLimitStaticGuard(unittest.TestCase):
    """Каждый вызов restart xray защищён reset-failed или безопасной обёрткой.

    Сканирует ВЕСЬ рантайм-код chimera/ (py). Голый
    ``systemctl restart xray`` без сброса счётчика start-rate-limit —
    источник start-limit-hit.
    """

    def _iter_py_files(self):
        for p in (_PROJECT_ROOT / "chimera").rglob("*.py"):
            if any(part in _STATIC_GUARD_SKIP_DIRS for part in p.parts):
                continue
            yield p

    def _find_bare_restarts(self):
        """Возвращает список (файл, строка, текст) незащищённых рестартов."""
        bare = []
        # Паттерны «рестарта xray» (python-список, subprocess, bash-строка)
        restart_pats = [
            re.compile(r'_run\(\[\s*"systemctl",\s*"restart",\s*"xray"'),
            re.compile(r'subprocess\.run\(\[\s*"systemctl",\s*"restart",\s*"xray"'),
            re.compile(r'run\(\[\s*"systemctl",\s*"restart",\s*"xray"'),
            re.compile(r'"systemctl\s+restart\s+xray'),
            re.compile(r"'systemctl\s+restart\s+xray"),
            re.compile(r'systemctl restart xray'),
        ]
        # Маркеры «защищено» (в той же конструкции или в соседних строках)
        guard_pats = [
            re.compile(r'reset-failed'),
            re.compile(r'_xray_safe_restart'),
            re.compile(r'_xray_restart_safe'),
            re.compile(r'def restart_service'),
            re.compile(r'ExecReload'),
        ]
        # UI-подсказки: текст «systemctl restart xray» внутри строки-сообщения
        # (не реальный вызов) — печатается юзеру как инструкция
        hint_call_pats = [
            re.compile(r'_(box_row|box_item|wiz_hint|box_info)\('),
            re.compile(r'\b(print|warn|error|info|success|dim|c_yellow)\(\s*$'),
            re.compile(r'\b(print|warn|error|info|success|dim|c_yellow)\(.*["\']'),
        ]
        WINDOW = 3  # строк до/после для поиска guard-маркера
        for path in self._iter_py_files():
            try:
                lines = path.read_text(errors="replace").splitlines()
            except Exception:
                continue
            in_docstring = False
            for i, line in enumerate(lines):
                stripped = line.strip()
                # трекинг тройных кавычек (докстринги пропускаем целиком)
                tqs = len(re.findall(r'"""', line)) + len(re.findall(r"'''", line))
                if tqs % 2 == 1:
                    in_docstring = not in_docstring
                if in_docstring:
                    continue
                # пропускаем комментарии
                if not stripped or stripped.startswith("#"):
                    continue
                if any(m in line for m in _STATIC_GUARD_EXEMPT_MARKERS):
                    continue
                if not any(p.search(line) for p in restart_pats):
                    continue
                # UI-подсказка: текст внутри кавычек в print/box_row/...
                if any(p.search(line) for p in hint_call_pats) and \
                        re.search(r'["\'][^"\']*systemctl restart xray', line):
                    continue
                # Строка-сообщение (multil-line string): между кавычкой и
                # «systemctl restart xray» есть текст (например,
                # «и затем перезапустите: systemctl restart xray») — это
                # подсказка юзеру, не вызов. Точный bash-литерал
                # ('systemctl restart xray && ...') остаётся «реальным».
                if re.search(r'["\'`][^"\'`]{2,}systemctl restart xray', line):
                    continue
                # рестарт найден — ищем guard в окрестности
                ctx = lines[max(0, i - WINDOW): i + 1]
                # guard ищем в строках до рестарта (reset-failed идёт ПЕРЕД)
                if any(g.search(c) for c in ctx for g in guard_pats):
                    continue
                bare.append((str(path.relative_to(_PROJECT_ROOT)),
                             i + 1, line.strip()))
        return bare

    def test_no_bare_xray_restarts(self):
        bare = self._find_bare_restarts()
        if bare:
            detail = "\n".join(f"  {f}:{ln}: {t}" for f, ln, t in bare)
            self.fail(
                "Найдены голые 'restart xray' без reset-failed/безопасной "
                f"обёртки ({len(bare)} шт.) — риск start-limit-hit:\n{detail}"
            )

    def test_safe_apply_config_uses_safe_restart(self):
        """_xray_safe_apply_config идёт через _core._xray_safe_restart."""
        src = (_PROJECT_ROOT / "chimera" / "modules" / "xray_install.py").read_text()
        # вырезаем тело функции
        m = re.search(
            r"def _xray_safe_apply_config\(.*?\n(?=def |\Z)", src, re.S)
        self.assertIsNotNone(m, "_xray_safe_apply_config не найден")
        body = m.group(0)
        self.assertIn("_xray_safe_restart", body,
                      "_xray_safe_apply_config не использует _xray_safe_restart")

    def test_fail2ban_watchdog_has_reset_failed(self):
        """Watchdog-скрипт сбрасывает start-limit перед restart xray."""
        src = (_PROJECT_ROOT / "chimera" / "modules" / "fail2ban_setup.py").read_text()
        m = re.search(r"systemctl reset-failed xray.*?systemctl restart xray",
                      src, re.S)
        self.assertIsNotNone(m,
                             "fail2ban watchdog: нет reset-failed перед restart")

    def test_fp_rotate_cron_has_reset_failed(self):
        """fp-rotate cron-скрипт сбрасывает start-limit перед restart/start."""
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        m = re.search(
            r"systemctl reset-failed xray[^\n]*\n[^\n]*if systemctl is-active",
            src)
        self.assertIsNotNone(m,
                             "_core fp-rotate cron: нет reset-failed перед start")


if __name__ == "__main__":
    unittest.main(verbosity=2)
