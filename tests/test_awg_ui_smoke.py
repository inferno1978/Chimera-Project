#!/usr/bin/env python3
"""
tests/test_awg_ui_smoke.py
───────────────────────────────────────────────────────────────────────────────
UI-smoke стилизации AWG-семейства (кейс стилизации AWG TUI, окт.2026).

Все интерактивные диалоги AmneziaWG standalone — диагностика (выбор
carrier), расширенные/ручные параметры (секции с врезанным вводом),
ротация (смена пресета), пиры, каскад (AWG0 / мульти-exit / exit_add),
LB-меню (стратегия/состав/закрепление), b4-сплит (сеты/домены/статус),
backup — рисуются рамками box_renderer и не падают под пайпом
(EOF на input = значение по умолчанию).

Канон: TestUiSmoke в test_icmp_gate.py; фейковый chimera._core —
эталонный паттерн test_speed_test_cf_cap._setup_core_in_sysmodules.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import io
import subprocess
import sys
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Фейковый chimera._core (эталонный паттерн test_speed_test_cf_cap)."""
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
    return fake_core, g


def _cp(stdout="", rc=0):
    return subprocess.CompletedProcess(["cmd"], rc, stdout, "")


def _feed(func, answers, *args, **kwargs):
    """Прогоняет func с очередью ответов на input (EOF = исчерпание).

    os.system (clear) замокан, stdout перехвачен. Возвращает (текст, результат).
    """
    it = iter(answers)

    def _fake_input(prompt=""):
        try:
            return next(it)
        except StopIteration:
            raise EOFError

    out = io.StringIO()
    with patch("builtins.input", _fake_input), \
         patch("os.system", lambda *a, **k: None), \
         redirect_stdout(out):
        res = func(*args, **kwargs)
    return out.getvalue(), res


class _AwgUiBase(unittest.TestCase):
    """База: фейковый chimera._core в sys.modules до первого _core_module()."""

    def setUp(self):
        self._fake_core, self._g = _setup_core_in_sysmodules()


# ── Диагностика: выбор carrier в рамке (плоский список до кейса) ────────────

class TestDiagnoseCarrierPicker(_AwgUiBase):

    def test_picker_and_report_framed(self):
        from chimera.modules import awg_diagnose
        report = {
            "installed": True,
            "protocol": {"version": "2.0", "label": "AmneziaWG 2.0",
                         "checks": [("OK", "Версия протокола: AmneziaWG 2.0")]},
            "kernel": {"ok": True, "status": "OK", "module": "amnezia",
                       "version": "tools v1.5"},
            "sysctl": [{"key": "net.ipv4.ip_forward", "current": "1",
                        "target": "1", "mode": "exact", "status": "OK"}],
            "ufw": {"ok": True, "status": "OK", "msg": "UFW разрешён UDP 45915"},
            "service": {"ok": True, "status": "OK", "active": True,
                        "enabled": True},
            "nat_routing": {"ok": True, "status": "OK",
                            "checks": [{"name": "ip_forward", "ok": True,
                                        "status": "OK", "msg": "= 1"}]},
            "tunnel": {"ok": True, "status": "OK", "peers": 1,
                       "handshakes": 1, "raw": ""},
        }
        with patch.object(awg_diagnose, "awgs_diagnose_full",
                          return_value=report) as m:
            text, _ = _feed(awg_diagnose.do_awg_diagnose_menu, ["1"])
        self.assertIn("СРАВНЕНИЕ С ОПЕРАТОРОМ", text)   # рамка выбора
        self.assertIn("╔", text)                        # рамки вообще
        self.assertIn("[1]", text)                      # нумерация пунктов
        self.assertIn("default", text)                  # пресет в списке
        self.assertIn("Diagnostic report", text)        # отчёт на месте
        m.assert_called_once_with(carrier="default")    # выбор дошёл

    def test_skip_carrier_on_eof(self):
        from chimera.modules import awg_diagnose
        report = {
            "installed": False,
            "protocol": {"checks": []},
            "kernel": {"ok": False, "status": "FAIL", "module": "не загружен",
                       "version": ""},
            "sysctl": [],
            "ufw": {"ok": True, "status": "SKIP", "msg": "UFW неактивен"},
            "service": {"ok": False, "status": "FAIL", "active": False,
                        "enabled": False},
            "nat_routing": {"ok": False, "status": "FAIL", "checks": []},
            "tunnel": {"ok": False, "status": "WARN", "msg": "awg show пуст"},
        }
        with patch.object(awg_diagnose, "awgs_diagnose_full",
                          return_value=report) as m:
            text, _ = _feed(awg_diagnose.do_awg_diagnose_menu, [])
        m.assert_called_once_with(carrier="")          # EOF = пропустить


# ── Расширенные параметры: конфиг-диалог с подсказками в рамке ──────────────

class TestAdvancedDialog(_AwgUiBase):

    def test_all_defaults_flow(self):
        from chimera.modules import awg_standalone
        captured = {}

        def fake_install(**kw):
            captured.update(kw)
            return True

        with patch.object(awg_standalone, "awgs_install", fake_install):
            # пустая очередь = EOF на каждом промпте = все значения default
            text, _ = _feed(awg_standalone._awgs_menu_advanced, [],
                            protocol_version="2.0")
        self.assertIn("РАСШИРЕННЫЕ ПАРАМЕТРЫ", text)
        self.assertIn("╔", text)
        self.assertIn("Carrier preset", text)          # kv-подсказки в рамке
        self.assertIn("UDP-порт", text)                # сам промпт был
        self.assertEqual(captured.get("port"), awg_standalone.AWGS_DEFAULT_PORT)
        self.assertEqual(captured.get("carrier_preset"), "default")
        self.assertTrue(captured.get("allow_ipv6_tunnel"))   # Enter = да


# ── Ручная настройка: секции с врезанным вводом + итоговая сводка ───────────

class TestCustomParamsDialog(_AwgUiBase):

    def test_full_defaults_20(self):
        from chimera.modules import awg_standalone
        captured = {}

        def fake_install(**kw):
            captured.update(kw)
            return True

        with patch.object(awg_standalone, "awgs_install", fake_install):
            text, _ = _feed(awg_standalone._awgs_menu_custom_params, [],
                            protocol_version="2.0")
        # все секции экспертного диалога — в рамках
        self.assertIn("БАЗОВЫЕ ПАРАМЕТРЫ", text)
        self.assertIn("ЧИСЛОВЫЕ ПАРАМЕТРЫ (JC/JMIN/JMAX/S1-S4)", text)
        self.assertIn("H1-H4 — MAGIC HEADERS", text)
        self.assertIn("ОПЦИОНАЛЬНЫЕ ПАРАМЕТРЫ (I1-I5)", text)
        self.assertIn("Итоговые параметры", text)
        self.assertIn("╔", text)
        # «всё по Enter» собирает валидный конфиг и доходит до install
        cp = captured.get("custom_params") or {}
        self.assertIn("jc", cp)
        self.assertIn("h1", cp)
        self.assertEqual(captured.get("port"), awg_standalone.AWGS_DEFAULT_PORT)

    def test_31_directives_section(self):
        from chimera.modules import awg_standalone
        text, params = _feed(awg_standalone.awgs_prompt_custom_params, [],
                             protocol_version="3.1")
        self.assertIn("ТРАНСПОРТНАЯ ЗАЩИТА AWG 3.1 (9 ДИРЕКТИВ)", text)
        self.assertIn("ЧИСЛОВЫЕ ПАРАМЕТРЫ", text)
        self.assertIsNotNone(params)                   # дефолты 3.1 валидны
        if params:
            self.assertIn("header_protection_key", params)
            self.assertTrue(params.get("s1", 0) >= 15)  # констрейнты 3.1


# ── Ротация: меню + рамочная смена пресета ──────────────────────────────────

class TestRotateMenu(_AwgUiBase):

    def test_menu_and_preset_picker(self):
        from chimera.modules import awg_state, awg_standalone
        st = {"installed": True, "carrier_preset": "default",
              "params": {"jc": 3, "jmin": 50, "jmax": 1000, "i1": "<r 24>"}}
        with patch.object(awg_state, "awgs_state_is_installed",
                          return_value=True), \
             patch.object(awg_state, "awgs_state_load", return_value=st), \
             patch.object(awg_state, "awgs_state_update"), \
             patch.object(awg_standalone, "awgs_rotate_obfuscation",
                          return_value=(False, "stub-ошибка")):
            # 2 = смена пресета; 1 = default; "" = пауза; q = выход
            text, _ = _feed(awg_standalone.do_awgs_rotate_menu,
                            ["2", "1", "", "q"])
        self.assertIn("Ротация параметров обфускации", text)  # само меню
        self.assertIn("СМЕНА ПРЕСЕТА ПЕРЕД РОТАЦИЕЙ", text)    # рамка пикера
        self.assertIn("← текущий", text)                      # маркер пресета
        self.assertIn("╔", text)


# ── Пиры: диалог добавления клиента ─────────────────────────────────────────

class TestPeersAddDialog(_AwgUiBase):

    def test_add_dialog_captures(self):
        from chimera.modules import awg_peers
        captured = {}

        def fake_add(*a, **kw):
            captured.update(kw)
            captured.setdefault("name", a[0] if a else kw.get("name"))
            return True

        with patch.object(awg_peers, "awg_peer_add", fake_add):
            text, _ = _feed(awg_peers._awgs_peers_menu_add,
                            ["user-test", "7d", "y"])
        self.assertIn("ДОБАВЛЕНИЕ КЛИЕНТА (PEER)", text)
        self.assertIn("╔", text)
        self.assertIn("PresharedKey", text)             # подсказка в рамке
        self.assertEqual(captured.get("name"), "user-test")
        self.assertEqual(captured.get("expires"), "7d")
        self.assertTrue(captured.get("psk"))


# ── Каскад: диалог настройки AWG0 ───────────────────────────────────────────

class TestCascadeAwg0Dialog(_AwgUiBase):

    def test_dialog_captures_fields(self):
        from chimera.modules import awg_cascade
        captured = {}

        def fake_setup(**kw):
            captured.update(kw)
            return True

        with patch.object(awg_cascade, "awgs_state_is_installed",
                          return_value=True), \
             patch.object(awg_cascade, "awgs_cascade_setup_awg0", fake_setup):
            text, _ = _feed(
                awg_cascade._awgs_cascade_menu_awg0,
                ["de.example.com", "", "PRIVKEY1", "PUBKEY1",
                 "", "", "", "", "y"])
        self.assertIn("НАСТРОЙКА AWG0", text)
        self.assertIn("Cascade peer privkey", text)     # kv-подсказка
        self.assertIn("╔", text)
        self.assertEqual(captured.get("exit_host"), "de.example.com")
        self.assertEqual(captured.get("exit_pubkey"), "PUBKEY1")
        self.assertEqual(captured.get("exit_peer_privkey"), "PRIVKEY1")
        self.assertEqual(captured.get("exit_port"), 51820)      # Enter = дефолт
        self.assertEqual(captured.get("exit_protocol_version"), "2.0")


# ── LB-меню: рамочный выбор стратегии/состава при включении ─────────────────

class TestLbMenuStrategy(_AwgUiBase):

    def test_enable_flow_framed(self):
        from chimera.modules import awg_cascade_lb as lb
        from chimera.modules.awg_constants import AWGS_LB_STRATEGIES
        info = {"on": True, "strategy": "smart", "pinned": "",
                "pinned_fallback": False, "balance_ts": "",
                "slots": [], "exits_selected": [],
                "exits_effective": 0, "exits_total": 3}
        state = {"cascade_exits": [
            {"name": "de", "endpoint": "1.2.3.4", "port": 51820},
            {"name": "nl1", "endpoint": "5.6.7.8", "port": 51820},
            {"name": "pl1", "endpoint": "9.10.11.12", "port": 51820},
        ]}
        calls = {}

        def fake_activate(strategy, pinned="", sel=None):
            calls.update(strategy=strategy, pinned=pinned, sel=sel)
            return True

        pick = str(AWGS_LB_STRATEGIES.index("smart") + 1)
        with patch.object(lb, "lb_status_info", return_value=info), \
             patch.object(lb, "awgs_state_load", return_value=state), \
             patch.object(lb, "lb_activate", fake_activate):
            # 1 = включить; pick = smart; n = без закрепления; "" = состав все;
            # "" = пауза; 0 = назад
            text, _ = _feed(lb.lb_menu, ["1", pick, "n", "", "", "0"])
        self.assertIn("СТРАТЕГИЯ БАЛАНСИРОВКИ", text)
        self.assertIn("СОСТАВ БАЛАНСИРОВКИ", text)      # >2 exits -> рамка состава
        self.assertIn("leastping", text)                # стратегии в списке
        self.assertIn("╔", text)
        self.assertEqual(calls.get("strategy"), "smart")
        self.assertEqual(calls.get("pinned"), "")
        self.assertIsNone(calls.get("sel"))


# ── B4-сплит: сеты / домены / живое состояние ───────────────────────────────

class TestB4SplitScreens(_AwgUiBase):

    def test_sets_checklist_framed(self):
        from chimera.modules import awg_b4_split as b4
        sets = [{"id": "yt", "name": "youtube", "enabled": True,
                 "domain_count": 123},
                {"id": "empty", "name": "nohostnames", "enabled": True,
                 "domain_count": 0}]
        with patch.object(b4, "detect_sets", return_value=sets), \
             patch.object(b4, "state_load", return_value={"set_ids": ["yt"]}), \
             patch.object(b4, "state_save"):
            text, _ = _feed(b4._menu_sets, ["q"])
        self.assertIn("СЕТЫ B4", text)
        self.assertIn("[x]", text)                      # отмеченный сет
        self.assertIn("123", text)                      # счётчик доменов
        self.assertIn("╔", text)

    def test_extra_domains_framed(self):
        from chimera.modules import awg_b4_split as b4
        with patch.object(b4, "state_load",
                          return_value={"extra_domains": ["example.com"]}), \
             patch.object(b4, "state_save"):
            text, _ = _feed(b4._menu_extra_domains, ["q"])
        self.assertIn("ДОПОЛНИТЕЛЬНЫЕ ДОМЕНА", text)
        self.assertIn("example.com", text)
        self.assertIn("╔", text)

    def test_full_status_framed(self):
        from chimera.modules import awg_b4_split as b4
        st = {"sets": [{"name": "youtube", "domain_count": 123,
                        "enabled": True}],
              "last_stats": {"ts": "2026-10-24T12:00:00", "ips": 42,
                             "applied": 7}}
        with patch.object(b4, "status_info", return_value=st), \
             patch.object(b4, "_bash",
                          lambda *a, **k: _cp("-A PREROUTING -i awg0 -j MARK")), \
             patch.object(b4, "_run",
                          lambda *a, **k: _cp("table inet b4_split")):
            text, _ = _feed(b4._menu_full_status, [])
        self.assertIn("ЖИВОЕ СОСТОЯНИЕ", text)
        self.assertIn("youtube", text)
        self.assertIn("42", text)
        self.assertIn("╔", text)


# ── Backup: диалоги создания/восстановления ─────────────────────────────────

class TestBackupDialog(_AwgUiBase):

    def test_create_dialog(self):
        from chimera.modules import awg_backup
        captured = {}

        def fake_create(label=""):
            captured["label"] = label
            return True

        with patch.object(awg_backup, "awgs_backup_list", return_value=[]), \
             patch.object(awg_backup, "awgs_backup_create", fake_create):
            # b = создать; mylabel = метка; "" = пауза; q = назад
            text, _ = _feed(awg_backup.do_manage_awg_backup,
                            ["b", "mylabel", "", "q"])
        self.assertIn("СОЗДАНИЕ BACKUP", text)
        self.assertIn("╔", text)
        self.assertEqual(captured.get("label"), "mylabel")


if __name__ == "__main__":
    unittest.main()
