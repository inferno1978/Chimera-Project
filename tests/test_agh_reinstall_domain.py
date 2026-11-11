#!/usr/bin/env python3
"""
tests/test_agh_reinstall_domain.py
───────────────────────────────────────────────────────────────────────────────
: «Вбиваю при установке один домен — домен-2.example, а доходит до
выпуска сертификата — ругается, что домен-1.example НЕ резолвится в IP
сервера» (инцидент: entry-2, 11.11.2026).

КОРНЕВАЯ ПРИЧИНА (stale-domain переустановки AGH):
  • первая попытка установки оборвалась ПОСЛЕ wizard-фазы AGH —
    aghome_state.json сохранил её домен (domain-old.example,
    web_mode=https_le, phase=wizard);
  • повторная установка: AGH_CONF уже существует → install_aghome()
    идёт в ветку «существующий конфиг → сразу финализируем» и брал
    domain ПРЯМО из aghome_state.json — только что введённый на шаге
    «Домен (SNI)» core.PARAM_DOMAIN (domain-new.example) игнорировался;
  • итог: finalize_aghome_config(domain=domain-old.example) →
    obtain_ssl_cert(domain-old.example) → WARN «НЕ резолвится в IP
    сервера» (A-запись старого домена больше не указывает на этот
    сервер) и LE-выпуск падал в self-signed под СТАРЫЙ домен.

Фикс: aghome_setup._reinstall_domain(stored) — приоритет свежего
домена установки (core.PARAM_DOMAIN) над сохранённым незавершённой
попыткой; при конфликте — явный выбор (дефолт [1] свежий, [2] старый);
PARAM_DOMAIN пуст (AGH-standalone без основного state.json) →
сохранённый (поведение прежнее).

Тестируем:
  1. _reinstall_domain: без свежего → stored; без stored → fresh;
     равные (и нормализация регистра) → fresh БЕЗ промпта;
     конфликт: Enter/мусор/EOF → fresh, «2» → stored;
  2. статический пин: re-install ветка install_aghome проходит через
     _reinstall_domain (прямая выборка domain из state в ветке —
     регресс, который и был багом).
"""
from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Фейковый chimera._core (паттерн test_agh_le_cert_order)."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core


_CORE = _setup_core_in_sysmodules()

from chimera.modules import aghome_setup  # noqa: E402


def _read(rel: str) -> str:
    return (_PROJECT_ROOT / rel).read_text()


# ─────────────────────────────────────────────────────────────────────────────
#  1. _reinstall_domain — приоритет домена при переустановке AGH
# ─────────────────────────────────────────────────────────────────────────────
class TestReinstallDomain(unittest.TestCase):
    """Инцидент entry-2: stale-домен из aghome_state не должен молча
    побеждать только что введённый домен установки."""

    FRESH = "domain-new.example"
    STORED = "domain-old.example"

    def setUp(self):
        self._orig = getattr(_CORE, "PARAM_DOMAIN", "")
        self._patcher = patch.object(
            aghome_setup, "_core_module", return_value=_CORE)
        self._patcher.start()
        self.addCleanup(self._patcher.stop)
        self.addCleanup(setattr, _CORE, "PARAM_DOMAIN", self._orig)

    def _set_param_domain(self, value: str):
        setattr(_CORE, "PARAM_DOMAIN", value)

    def test_no_fresh_domain_returns_stored(self):
        """PARAM_DOMAIN пуст (AGH-standalone без state.json) → stored."""
        self._set_param_domain("")
        with patch("builtins.input") as inp:
            self.assertEqual(
                aghome_setup._reinstall_domain(self.STORED), self.STORED)
        inp.assert_not_called()

    def test_no_stored_returns_fresh(self):
        """AGH-state без домена (первый заход) → свежий домен установки."""
        self._set_param_domain(self.FRESH)
        with patch("builtins.input") as inp:
            self.assertEqual(aghome_setup._reinstall_domain(""), self.FRESH)
        inp.assert_not_called()

    def test_same_domain_no_prompt(self):
        """Домены совпадают → fresh, промпта нет (идемпотентность)."""
        self._set_param_domain(self.FRESH)
        with patch("builtins.input") as inp:
            self.assertEqual(
                aghome_setup._reinstall_domain(self.FRESH), self.FRESH)
        inp.assert_not_called()

    def test_case_normalized_no_prompt(self):
        """Регистр нормализуется: OLD.Example == old.example → fresh,
        ложного конфликта (промпта) нет."""
        self._set_param_domain("Old.Example")
        with patch("builtins.input") as inp:
            self.assertEqual(
                aghome_setup._reinstall_domain("old.example"), "old.example")
        inp.assert_not_called()

    def test_conflict_enter_defaults_to_fresh(self):
        """Конфликт, Enter (дефолт 1) → свежий домен установки."""
        self._set_param_domain(self.FRESH)
        with patch("builtins.input", return_value=""):
            self.assertEqual(
                aghome_setup._reinstall_domain(self.STORED), self.FRESH)

    def test_conflict_choice_2_keeps_stored(self):
        """Конфликт, явное «2» → сохранённый домен (AGH сознательно на
        другом домене — выбор владельца)."""
        self._set_param_domain(self.FRESH)
        with patch("builtins.input", return_value="2"):
            self.assertEqual(
                aghome_setup._reinstall_domain(self.STORED), self.STORED)

    def test_conflict_garbage_input_falls_to_fresh(self):
        """Конфликт, мусорный ввод (не «2») → fresh (как дефолт)."""
        self._set_param_domain(self.FRESH)
        with patch("builtins.input", return_value="7"):
            self.assertEqual(
                aghome_setup._reinstall_domain(self.STORED), self.FRESH)

    def test_conflict_eof_falls_to_fresh(self):
        """Конфликт, EOF (неинтерактивный вызов) → fresh — безопасный
        дефолт, stale-домен молча не возвращается."""
        self._set_param_domain(self.FRESH)
        with patch("builtins.input", side_effect=EOFError):
            self.assertEqual(
                aghome_setup._reinstall_domain(self.STORED), self.FRESH)


# ─────────────────────────────────────────────────────────────────────────────
#  2. Статические пины wiring'а
# ─────────────────────────────────────────────────────────────────────────────
class TestStaticPinsWiring(unittest.TestCase):
    """install_aghome (re-install ветка) обязан идти через
    _reinstall_domain — прямая выборка domain из aghome_state в этой
    ветке и есть регресс инцидента entry-2."""

    def test_reinstall_branch_uses_reinstall_domain(self):
        src = _read("chimera/modules/aghome_setup.py")
        idx_fn = src.index("def install_aghome(")
        idx_re = src.index("# Существующий конфиг → сразу финализируем",
                           idx_fn)
        idx_call = src.index("domain = _reinstall_domain(", idx_re)
        idx_fin = src.index("finalize_aghome_config(web_mode=web_mode, "
                            "domain=domain)", idx_call)
        self.assertLess(idx_re, idx_call)
        self.assertLess(idx_call, idx_fin)

    def test_reinstall_domain_defined_before_install_aghome(self):
        src = _read("chimera/modules/aghome_setup.py")
        idx_helper = src.index("def _reinstall_domain(")
        idx_install = src.index("def install_aghome(")
        self.assertLess(idx_helper, idx_install)

    def test_wizard_branch_untouched(self):
        """Wizard-ветка (первая установка) не тронута: домен из
        _ask_web_mode, без _reinstall_domain."""
        src = _read("chimera/modules/aghome_setup.py")
        idx_fn = src.index("def install_aghome(")
        idx_wiz = src.index("web_mode, domain = _ask_web_mode()", idx_fn)
        idx_re = src.index("# Существующий конфиг → сразу финализируем",
                           idx_fn)
        self.assertLess(idx_wiz, idx_re)


if __name__ == "__main__":
    unittest.main()
