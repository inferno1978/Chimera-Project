#!/usr/bin/env python3
"""
tests/test_port_knocking.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/port_knocking.py.

Покрывает:
  1. _pk_state_load / _pk_state_save — JSON I/O с дефолтами + merge
  2. _pk_validate / _pk_validate_int — валидация конфига (ranges, types)
  3. _pk_build_iptables_rules — структура правил (6 rules/port, INSERT/APPEND)
  4. _pk_build_ipset_create_cmd — команда создания ipset
  5. _pk_recent_name — имя recent-таблицы per port
  6. _pk_install — идемпотентная установка (mock subprocess, -C check)
  7. _pk_remove — очистка (mock subprocess, flush+destroy ipset)
  8. _pk_is_active — проверка через iptables -S
  9. _pk_status — форматированный статус
 10. _pk_test_knock — тест knocking (mock subprocess + socket)
 11. do_manage_port_knocking — функция-точка-входа существует

Все вызовы iptables/ipset — mock'd через _fake_run. Реальных сетевых
операций нет (socket в _pk_test_knock — mock'd через patch).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _cp(cmd, rc=0, stdout="", stderr=""):
    """Фабрика CompletedProcess."""
    return subprocess.CompletedProcess(list(cmd), rc, stdout, stderr)


class _PortKnockingBase(unittest.TestCase):
    """Базовый класс с патчингом state file, _run и _tg_notify_event.

    _fake_run симулирует iptables/ipset:
      • хранит правила в _iptables_rules (list of spec strings)
      • -C проверяет наличие правила по подстроке
      • -I/-A добавляет правило в список
      • -D удаляет первое совпадающее правило
      • -S INPUT возвращает все правила как `-A INPUT <spec>`
      • ipset create/list/flush/destroy — симулируются через _ipset_exists/entries
    """

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "port_knocking.json"
        self._calls: list[list] = []
        # Симулируемое состояние iptables INPUT (list of spec strings)
        self._iptables_rules: list[str] = []
        # Симулируемое состояние ipset
        self._ipset_exists = {
            "xray_knocked":    False,
            "clients_wl":      True,
            "xray_manual_ban": True,
        }
        self._ipset_entries = {
            "xray_knocked":    0,
            "clients_wl":      5,
            "xray_manual_ban": 2,
        }
        # Симулируемый вывод ipset list для теста knocked IPs
        self._ipset_list_lines = {
            "xray_knocked": "Name: xray_knocked\nNumber of entries: 0\n",
        }
        self._patches = [
            patch("chimera.modules.port_knocking._PK_STATE_FILE",
                  self._state_file),
            patch("chimera.modules.port_knocking._run", self._fake_run),
            patch("chimera.modules.port_knocking._tg_notify_event"),
            patch("chimera.modules.port_knocking._pk_persist"),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for p in self._patches:
            p.stop()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _fake_run(self, cmd, capture=False, check=False, quiet=False,
                  timeout=30):
        self._calls.append(list(cmd))
        # iptables -C INPUT <spec> — check if rule exists (подстрока)
        if cmd[:3] == ["iptables", "-C", "INPUT"]:
            spec_str = " ".join(str(c) for c in cmd[3:])
            for rule in self._iptables_rules:
                if spec_str in rule or rule in spec_str:
                    return _cp(cmd, 0, "", "")
            return _cp(cmd, 1, "", "rule not found")
        # iptables -I INPUT <pos> <spec>
        if cmd[:3] == ["iptables", "-I", "INPUT"]:
            spec_str = " ".join(str(c) for c in cmd[4:])
            self._iptables_rules.append(spec_str)
            return _cp(cmd, 0, "", "")
        # iptables -A INPUT <spec>
        if cmd[:3] == ["iptables", "-A", "INPUT"]:
            spec_str = " ".join(str(c) for c in cmd[3:])
            self._iptables_rules.append(spec_str)
            return _cp(cmd, 0, "", "")
        # iptables -D INPUT <spec> — delete first matching
        if cmd[:3] == ["iptables", "-D", "INPUT"]:
            spec_str = " ".join(str(c) for c in cmd[3:])
            for i, rule in enumerate(self._iptables_rules):
                if spec_str in rule or rule in spec_str:
                    self._iptables_rules.pop(i)
                    return _cp(cmd, 0, "", "")
            return _cp(cmd, 1, "", "rule not found")
        # iptables -S INPUT — list all rules
        if cmd[:3] == ["iptables", "-S", "INPUT"]:
            out = "\n".join("-A INPUT " + r for r in self._iptables_rules)
            if out:
                out += "\n"
            return _cp(cmd, 0, out, "")
        # ipset create <name> hash:ip timeout N exist
        if cmd[:2] == ["ipset", "create"]:
            self._ipset_exists["xray_knocked"] = True
            return _cp(cmd, 0, "", "")
        # ipset list <name>
        if cmd[:2] == ["ipset", "list"]:
            name = cmd[2] if len(cmd) > 2 else ""
            if not self._ipset_exists.get(name, False):
                return _cp(cmd, 1, "", "set does not exist")
            return _cp(cmd, 0, self._ipset_list_lines.get(
                name, f"Name: {name}\nNumber of entries: "
                f"{self._ipset_entries.get(name, 0)}\n"), "")
        # ipset flush <name>
        if cmd[:2] == ["ipset", "flush"]:
            name = cmd[2] if len(cmd) > 2 else ""
            if name in self._ipset_entries:
                self._ipset_entries[name] = 0
            return _cp(cmd, 0, "", "")
        # ipset destroy <name>
        if cmd[:2] == ["ipset", "destroy"]:
            name = cmd[2] if len(cmd) > 2 else ""
            self._ipset_exists[name] = False
            return _cp(cmd, 0, "", "")
        # ipset del <name> <ip>
        if cmd[:2] == ["ipset", "del"]:
            return _cp(cmd, 0, "", "")
        # default
        return _cp(cmd, 0, "", "")


# =============================================================================
#  1. STATE LOAD/SAVE
# =============================================================================
class TestStateLoadSave(_PortKnockingBase):

    def test_load_returns_default_when_no_file(self):
        from chimera.modules.port_knocking import (
            _pk_state_load, _pk_default_state,
        )
        state = _pk_state_load()
        default = _pk_default_state()
        self.assertEqual(state, default)
        self.assertFalse(state["enabled"])
        self.assertEqual(state["ports"], [443])
        self.assertEqual(state["knock_count"], 3)
        self.assertEqual(state["knock_window_sec"], 10)
        self.assertEqual(state["whitelist_ttl_sec"], 3600)

    def test_load_returns_default_on_corrupt(self):
        from chimera.modules.port_knocking import _pk_state_load
        self._state_file.write_text("{invalid json")
        state = _pk_state_load()
        self.assertFalse(state["enabled"])
        self.assertEqual(state["knock_count"], 3)

    def test_save_then_load(self):
        from chimera.modules.port_knocking import (
            _pk_state_load, _pk_state_save,
        )
        state = {
            "enabled":           True,
            "ports":             [9443],
            "knock_count":       5,
            "knock_window_sec":  30,
            "whitelist_ttl_sec": 7200,
            "log_success":       True,
            "installed_at":      "2026-09-24T15:00:00Z",
        }
        _pk_state_save(state)
        loaded = _pk_state_load()
        self.assertTrue(loaded["enabled"])
        self.assertEqual(loaded["ports"], [9443])
        self.assertEqual(loaded["knock_count"], 5)
        self.assertEqual(loaded["knock_window_sec"], 30)
        self.assertEqual(loaded["whitelist_ttl_sec"], 7200)
        self.assertTrue(loaded["log_success"])

    def test_save_sets_chmod_600(self):
        from chimera.modules.port_knocking import _pk_state_save
        _pk_state_save({
            "enabled": False, "ports": [443], "knock_count": 3,
            "knock_window_sec": 10, "whitelist_ttl_sec": 3600,
            "log_success": False, "installed_at": "",
        })
        mode = stat.S_IMODE(os.stat(self._state_file).st_mode)
        self.assertEqual(mode, 0o600)

    def test_load_merges_with_defaults(self):
        """Лишние/отсутствующие поля мержатся с дефолтами (обратная совместимость)."""
        from chimera.modules.port_knocking import _pk_state_load
        # state без log_success и installed_at (старый формат)
        self._state_file.write_text(json.dumps({
            "enabled": True, "ports": [443], "knock_count": 3,
            "knock_window_sec": 10, "whitelist_ttl_sec": 3600,
        }))
        state = _pk_state_load()
        self.assertTrue(state["enabled"])
        # log_success и installed_at — из дефолтов
        self.assertFalse(state["log_success"])
        self.assertEqual(state["installed_at"], "")

    def test_default_state_has_expected_fields(self):
        from chimera.modules.port_knocking import _pk_default_state
        d = _pk_default_state()
        for key in ("enabled", "ports", "knock_count", "knock_window_sec",
                    "whitelist_ttl_sec", "log_success", "installed_at"):
            self.assertIn(key, d)
        self.assertIsInstance(d["ports"], list)
        self.assertFalse(d["enabled"])


# =============================================================================
#  2. VALIDATION
# =============================================================================
class TestValidation(_PortKnockingBase):

    def test_validate_int_ok(self):
        from chimera.modules.port_knocking import _pk_validate_int
        ok, msg = _pk_validate_int(5, 1, 20, "knock_count")
        self.assertTrue(ok)
        self.assertEqual(msg, "")

    def test_validate_int_below_range(self):
        from chimera.modules.port_knocking import _pk_validate_int
        ok, msg = _pk_validate_int(0, 1, 20, "knock_count")
        self.assertFalse(ok)
        self.assertIn("knock_count", msg)

    def test_validate_int_above_range(self):
        from chimera.modules.port_knocking import _pk_validate_int
        ok, _ = _pk_validate_int(25, 1, 20, "knock_count")
        self.assertFalse(ok)

    def test_validate_int_not_int(self):
        from chimera.modules.port_knocking import _pk_validate_int
        ok, _ = _pk_validate_int("abc", 1, 20, "knock_count")
        self.assertFalse(ok)

    def test_validate_valid_state(self):
        from chimera.modules.port_knocking import (
            _pk_validate, _pk_default_state,
        )
        errors = _pk_validate(_pk_default_state())
        self.assertEqual(errors, [])

    def test_validate_knock_count_too_high(self):
        from chimera.modules.port_knocking import (
            _pk_validate, _pk_default_state,
        )
        state = _pk_default_state()
        state["knock_count"] = 25
        errors = _pk_validate(state)
        self.assertEqual(len(errors), 1)
        self.assertIn("knock_count", errors[0])

    def test_validate_knock_window_too_high(self):
        from chimera.modules.port_knocking import (
            _pk_validate, _pk_default_state,
        )
        state = _pk_default_state()
        state["knock_window_sec"] = 500
        errors = _pk_validate(state)
        self.assertEqual(len(errors), 1)

    def test_validate_ttl_too_low(self):
        from chimera.modules.port_knocking import (
            _pk_validate, _pk_default_state,
        )
        state = _pk_default_state()
        state["whitelist_ttl_sec"] = 30
        errors = _pk_validate(state)
        self.assertEqual(len(errors), 1)

    def test_validate_port_out_of_range(self):
        from chimera.modules.port_knocking import (
            _pk_validate, _pk_default_state,
        )
        state = _pk_default_state()
        state["ports"] = [70000]
        errors = _pk_validate(state)
        self.assertEqual(len(errors), 1)
        self.assertIn("port", errors[0])

    def test_validate_ports_not_list(self):
        from chimera.modules.port_knocking import (
            _pk_validate, _pk_default_state,
        )
        state = _pk_default_state()
        state["ports"] = "not a list"
        errors = _pk_validate(state)
        self.assertEqual(len(errors), 1)


# =============================================================================
#  3. BUILD IPTABLES RULES
# =============================================================================
class TestBuildIptablesRules(_PortKnockingBase):

    def test_returns_six_rules_per_port(self):
        from chimera.modules.port_knocking import (
            _pk_build_iptables_rules, _pk_default_state,
        )
        rules = _pk_build_iptables_rules(443, _pk_default_state())
        # 3 INSERT + 3 APPEND = 6
        self.assertEqual(len(rules), 6)

    def test_first_three_are_inserts_at_positions_1_2_3(self):
        from chimera.modules.port_knocking import (
            _pk_build_iptables_rules, _pk_default_state,
        )
        rules = _pk_build_iptables_rules(443, _pk_default_state())
        for i in range(3):
            self.assertEqual(rules[i]["op"], "insert")
        self.assertEqual(rules[0]["pos"], 1)
        self.assertEqual(rules[1]["pos"], 2)
        self.assertEqual(rules[2]["pos"], 3)

    def test_last_three_are_appends(self):
        from chimera.modules.port_knocking import (
            _pk_build_iptables_rules, _pk_default_state,
        )
        rules = _pk_build_iptables_rules(443, _pk_default_state())
        for i in range(3, 6):
            self.assertEqual(rules[i]["op"], "append")

    def test_insert_rules_reference_correct_ipsets(self):
        from chimera.modules.port_knocking import (
            _pk_build_iptables_rules, _pk_default_state,
        )
        rules = _pk_build_iptables_rules(443, _pk_default_state())
        # Rule 1 (pos 1): DROP from xray_manual_ban
        self.assertIn("xray_manual_ban", rules[0]["spec"])
        self.assertIn("DROP", rules[0]["spec"])
        # Rule 2 (pos 2): ACCEPT from clients_wl
        self.assertIn("clients_wl", rules[1]["spec"])
        self.assertIn("ACCEPT", rules[1]["spec"])
        # Rule 3 (pos 3): ACCEPT from xray_knocked
        self.assertIn("xray_knocked", rules[2]["spec"])
        self.assertIn("ACCEPT", rules[2]["spec"])

    def test_append_rules_use_recent_module(self):
        from chimera.modules.port_knocking import (
            _pk_build_iptables_rules, _pk_default_state,
        )
        rules = _pk_build_iptables_rules(443, _pk_default_state())
        # Rule 4 (append idx 0): recent --set
        self.assertIn("recent", rules[3]["spec"])
        self.assertIn("--set", rules[3]["spec"])
        self.assertIn("KNOCK443", rules[3]["spec"])
        # Rule 5 (append idx 1): recent --rcheck --hitcount + add-set
        self.assertIn("--rcheck", rules[4]["spec"])
        self.assertIn("--hitcount", rules[4]["spec"])
        self.assertIn("3", rules[4]["spec"])  # default knock_count=3
        self.assertIn("--add-set", rules[4]["spec"])
        self.assertIn("xray_knocked", rules[4]["spec"])
        # Rule 6 (append idx 2): --syn -j DROP
        self.assertIn("DROP", rules[5]["spec"])
        self.assertIn("--syn", rules[5]["spec"])

    def test_all_rules_have_comment_tag(self):
        from chimera.modules.port_knocking import (
            _pk_build_iptables_rules, _pk_default_state, _PK_COMMENT_TAG,
        )
        rules = _pk_build_iptables_rules(443, _pk_default_state())
        for rule in rules:
            self.assertIn(_PK_COMMENT_TAG, rule["spec"])

    def test_dport_in_all_rules(self):
        from chimera.modules.port_knocking import (
            _pk_build_iptables_rules, _pk_default_state,
        )
        rules = _pk_build_iptables_rules(9443, _pk_default_state())
        for rule in rules:
            self.assertIn("9443", rule["spec"])

    def test_recent_name_unique_per_port(self):
        """Уникальные recent-имена per port (лимит xt_recent)."""
        from chimera.modules.port_knocking import (
            _pk_build_iptables_rules, _pk_default_state,
        )
        rules_443  = _pk_build_iptables_rules(443, _pk_default_state())
        rules_9443 = _pk_build_iptables_rules(9443, _pk_default_state())
        names_443  = [s for r in rules_443  for s in r["spec"]
                      if str(s).startswith("KNOCK")]
        names_9443 = [s for r in rules_9443 for s in r["spec"]
                      if str(s).startswith("KNOCK")]
        self.assertIn("KNOCK443", names_443)
        self.assertNotIn("KNOCK9443", names_443)
        self.assertIn("KNOCK9443", names_9443)
        self.assertNotIn("KNOCK443", names_9443)

    def test_knock_count_propagates_to_hitcount(self):
        from chimera.modules.port_knocking import (
            _pk_build_iptables_rules, _pk_default_state,
        )
        state = _pk_default_state()
        state["knock_count"] = 5
        rules = _pk_build_iptables_rules(443, state)
        # Rule 5 (rcheck) должен иметь --hitcount 5
        self.assertIn("5", rules[4]["spec"])

    def test_knock_window_propagates_to_seconds(self):
        from chimera.modules.port_knocking import (
            _pk_build_iptables_rules, _pk_default_state,
        )
        state = _pk_default_state()
        state["knock_window_sec"] = 42
        rules = _pk_build_iptables_rules(443, state)
        # Rule 5 (rcheck) должен иметь --seconds 42
        self.assertIn("42", rules[4]["spec"])


# =============================================================================
#  4. BUILD IPSET CREATE CMD
# =============================================================================
class TestBuildIpsetCreateCmd(_PortKnockingBase):

    def test_returns_correct_command(self):
        from chimera.modules.port_knocking import (
            _pk_build_ipset_create_cmd, _pk_default_state, _PK_KNOCKED_SET,
        )
        cmd = _pk_build_ipset_create_cmd(_pk_default_state())
        self.assertEqual(cmd[0], "ipset")
        self.assertEqual(cmd[1], "create")
        self.assertEqual(cmd[2], _PK_KNOCKED_SET)
        self.assertIn("hash:ip", cmd)
        self.assertIn("timeout", cmd)
        self.assertIn("3600", cmd)  # default ttl
        self.assertIn("exist", cmd)  # idempotent flag

    def test_uses_state_ttl(self):
        from chimera.modules.port_knocking import (
            _pk_build_ipset_create_cmd, _pk_default_state,
        )
        state = _pk_default_state()
        state["whitelist_ttl_sec"] = 7200
        cmd = _pk_build_ipset_create_cmd(state)
        self.assertIn("7200", cmd)


# =============================================================================
#  5. RECENT NAME
# =============================================================================
class TestRecentName(_PortKnockingBase):

    def test_returns_knock_prefix(self):
        from chimera.modules.port_knocking import _pk_recent_name
        self.assertEqual(_pk_recent_name(443), "KNOCK443")
        self.assertEqual(_pk_recent_name(9443), "KNOCK9443")
        self.assertEqual(_pk_recent_name(8080), "KNOCK8080")


# =============================================================================
#  6. INSTALL (idempotent)
# =============================================================================
class TestInstall(_PortKnockingBase):

    def test_install_creates_ipset_and_rules(self):
        from chimera.modules.port_knocking import (
            _pk_install, _pk_default_state, _PK_KNOCKED_SET,
        )
        state = _pk_default_state()
        ok = _pk_install(state)
        self.assertTrue(ok)
        # ipset create was called
        create_calls = [c for c in self._calls
                        if c[:2] == ["ipset", "create"]]
        self.assertEqual(len(create_calls), 1)
        self.assertIn(_PK_KNOCKED_SET, create_calls[0])
        # iptables -I/-A rules were called (3 inserts + 3 appends for 1 port)
        insert_calls = [c for c in self._calls
                        if c[:3] == ["iptables", "-I", "INPUT"]]
        append_calls = [c for c in self._calls
                        if c[:3] == ["iptables", "-A", "INPUT"]]
        self.assertEqual(len(insert_calls), 3)
        self.assertEqual(len(append_calls), 3)

    def test_install_idempotent_no_duplicate(self):
        """Повторный install не дублирует правила (при -C check existing)."""
        from chimera.modules.port_knocking import (
            _pk_install, _pk_default_state,
        )
        # First install — rules don't exist, all 6 added
        state = _pk_default_state()
        ok = _pk_install(state)
        self.assertTrue(ok)
        first_inserts = [c for c in self._calls
                         if c[:3] == ["iptables", "-I", "INPUT"]]
        first_appends = [c for c in self._calls
                         if c[:3] == ["iptables", "-A", "INPUT"]]
        self.assertEqual(len(first_inserts), 3)
        self.assertEqual(len(first_appends), 3)

        # Reset calls — second install
        self._calls.clear()
        # Now _iptables_rules has 6 entries; -C will find them all → no inserts
        ok2 = _pk_install(_pk_default_state())
        self.assertTrue(ok2)
        second_inserts = [c for c in self._calls
                          if c[:3] == ["iptables", "-I", "INPUT"]]
        second_appends = [c for c in self._calls
                          if c[:3] == ["iptables", "-A", "INPUT"]]
        # All rules "exist" → no -I/-A calls
        self.assertEqual(len(second_inserts), 0)
        self.assertEqual(len(second_appends), 0)
        # But -C was called 6 times (to check existence)
        check_calls = [c for c in self._calls
                       if c[:3] == ["iptables", "-C", "INPUT"]]
        self.assertEqual(len(check_calls), 6)

    def test_install_skips_if_no_ports(self):
        from chimera.modules.port_knocking import (
            _pk_install, _pk_default_state,
        )
        state = _pk_default_state()
        state["ports"] = []
        ok = _pk_install(state)
        self.assertFalse(ok)

    def test_install_returns_false_on_invalid_state(self):
        from chimera.modules.port_knocking import (
            _pk_install, _pk_default_state,
        )
        state = _pk_default_state()
        state["knock_count"] = 25  # out of range
        ok = _pk_install(state)
        self.assertFalse(ok)

    def test_install_updates_state_enabled_true(self):
        from chimera.modules.port_knocking import (
            _pk_install, _pk_state_load, _pk_default_state,
        )
        _pk_install(_pk_default_state())
        state = _pk_state_load()
        self.assertTrue(state["enabled"])
        self.assertNotEqual(state["installed_at"], "")

    def test_install_multiple_ports(self):
        from chimera.modules.port_knocking import (
            _pk_install, _pk_default_state,
        )
        state = _pk_default_state()
        state["ports"] = [443, 9443]
        ok = _pk_install(state)
        self.assertTrue(ok)
        # 6 rules per port × 2 ports = 12 inserts+appends
        insert_calls = [c for c in self._calls
                        if c[:3] == ["iptables", "-I", "INPUT"]]
        append_calls = [c for c in self._calls
                        if c[:3] == ["iptables", "-A", "INPUT"]]
        self.assertEqual(len(insert_calls), 6)  # 3 per port × 2
        self.assertEqual(len(append_calls), 6)  # 3 per port × 2


# =============================================================================
#  7. REMOVE (cleanup)
# =============================================================================
class TestRemove(_PortKnockingBase):

    def test_remove_deletes_rules_by_comment_tag(self):
        from chimera.modules.port_knocking import _pk_remove, _PK_COMMENT_TAG
        # Pre-populate _iptables_rules with 6 of our rules (with comment tag)
        # Format: "-p tcp --dport 443 ... -m comment --comment chimera-port-knocking"
        rules_with_tag = [
            f"-p tcp --dport 443 -m set --match-set xray_manual_ban src "
            f"-j DROP -m comment --comment {_PK_COMMENT_TAG}",
            f"-p tcp --dport 443 -m set --match-set clients_wl src "
            f"-j ACCEPT -m comment --comment {_PK_COMMENT_TAG}",
            f"-p tcp --dport 443 -m set --match-set xray_knocked src "
            f"-j ACCEPT -m comment --comment {_PK_COMMENT_TAG}",
            f"-p tcp --dport 443 --syn -m recent --name KNOCK443 --set "
            f"-m comment --comment {_PK_COMMENT_TAG}",
            f"-p tcp --dport 443 --syn -m recent --name KNOCK443 --rcheck "
            f"--seconds 10 --hitcount 3 -m set --add-set xray_knocked src "
            f"-m comment --comment {_PK_COMMENT_TAG}",
            f"-p tcp --dport 443 --syn -j DROP -m comment "
            f"--comment {_PK_COMMENT_TAG}",
            # one extra non-our rule — should NOT be touched
            "-p tcp --dport 22 -j ACCEPT",
        ]
        self._iptables_rules.extend(rules_with_tag)
        # ipset exists
        self._ipset_exists["xray_knocked"] = True

        ok = _pk_remove()
        self.assertTrue(ok)
        # All 6 our rules deleted, the non-our rule (port 22) untouched
        self.assertEqual(len(self._iptables_rules), 1)
        self.assertIn("dport 22", self._iptables_rules[0])
        # -D was called 6 times (once per our rule)
        delete_calls = [c for c in self._calls
                        if c[:3] == ["iptables", "-D", "INPUT"]]
        self.assertEqual(len(delete_calls), 6)
        # ipset flush + destroy called
        flush_calls = [c for c in self._calls
                       if c[:2] == ["ipset", "flush"]]
        destroy_calls = [c for c in self._calls
                         if c[:2] == ["ipset", "destroy"]]
        self.assertEqual(len(flush_calls), 1)
        self.assertEqual(len(destroy_calls), 1)
        self.assertIn("xray_knocked", flush_calls[0])
        self.assertIn("xray_knocked", destroy_calls[0])
        # ipset no longer exists
        self.assertFalse(self._ipset_exists["xray_knocked"])

    def test_remove_no_rules_no_crash(self):
        """remove() безопасен когда правил нет."""
        from chimera.modules.port_knocking import _pk_remove
        # _iptables_rules empty, ipset doesn't exist
        ok = _pk_remove()
        self.assertTrue(ok)
        # -S INPUT called (loop exits immediately, no rules)
        list_calls = [c for c in self._calls
                      if c[:3] == ["iptables", "-S", "INPUT"]]
        self.assertEqual(len(list_calls), 1)

    def test_remove_updates_state_enabled_false(self):
        from chimera.modules.port_knocking import (
            _pk_remove, _pk_state_save, _pk_state_load, _pk_default_state,
        )
        state = _pk_default_state()
        state["enabled"] = True
        state["installed_at"] = "2026-09-24T15:00:00Z"
        _pk_state_save(state)
        _pk_remove()
        loaded = _pk_state_load()
        self.assertFalse(loaded["enabled"])
        self.assertEqual(loaded["installed_at"], "")

    def test_remove_does_not_touch_clients_wl_ipset(self):
        """clients_wl и xray_manual_ban — чужие ipsets, не flush/destroy."""
        from chimera.modules.port_knocking import _pk_remove
        self._ipset_exists["xray_knocked"] = True
        _pk_remove()
        # clients_wl and xray_manual_ban still exist
        self.assertTrue(self._ipset_exists["clients_wl"])
        self.assertTrue(self._ipset_exists["xray_manual_ban"])
        # no flush/destroy for clients_wl or xray_manual_ban
        for call in self._calls:
            if call[:2] in (["ipset", "flush"], ["ipset", "destroy"]):
                self.assertNotIn("clients_wl", call)
                self.assertNotIn("xray_manual_ban", call)


# =============================================================================
#  8. IS_ACTIVE
# =============================================================================
class TestIsActive(_PortKnockingBase):

    def test_is_active_false_when_no_rules(self):
        from chimera.modules.port_knocking import _pk_is_active
        self.assertFalse(_pk_is_active())

    def test_is_active_true_when_our_rules_present(self):
        from chimera.modules.port_knocking import (
            _pk_is_active, _PK_COMMENT_TAG,
        )
        self._iptables_rules.append(
            f"-p tcp --dport 443 -j DROP -m comment --comment "
            f"{_PK_COMMENT_TAG}"
        )
        self.assertTrue(_pk_is_active())


# =============================================================================
#  9. STATUS
# =============================================================================
class TestStatus(_PortKnockingBase):

    def test_status_returns_string(self):
        from chimera.modules.port_knocking import _pk_status
        s = _pk_status()
        self.assertIsInstance(s, str)
        self.assertGreater(len(s), 0)

    def test_status_contains_key_fields(self):
        from chimera.modules.port_knocking import _pk_status
        s = _pk_status()
        self.assertIn("Port Knocking", s)
        self.assertIn("Ports:", s)
        self.assertIn("Knock:", s)
        self.assertIn("Whitelist TTL:", s)
        self.assertIn("xray_knocked:", s)
        # default ports
        self.assertIn("443", s)

    def test_status_inactive_when_no_rules(self):
        from chimera.modules.port_knocking import _pk_status
        s = _pk_status()
        self.assertIn("inactive", s)


# =============================================================================
# 10. TEST KNOCK (mock socket + ipset)
# =============================================================================
class TestTestKnock(_PortKnockingBase):

    def test_test_knock_returns_dict_with_expected_fields(self):
        from chimera.modules.port_knocking import _pk_test_knock
        # Pre-set ipset exists + has 127.0.0.1 after knock
        self._ipset_exists["xray_knocked"] = True
        self._ipset_list_lines["xray_knocked"] = (
            "Name: xray_knocked\nNumber of entries: 1\n"
            "127.0.0.1 timeout 3599\n"
        )
        with patch("chimera.modules.port_knocking.socket.socket") as msock:
            msock.return_value.connect_ex.return_value = 0
            result = _pk_test_knock(443)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["port"], 443)
        self.assertEqual(result["knock_count"], 3)  # default
        self.assertIn("sent_syns", result)
        self.assertIn("in_xray_knocked", result)
        self.assertIn("success", result)

    def test_test_knock_success_when_ip_in_set(self):
        from chimera.modules.port_knocking import _pk_test_knock
        self._ipset_exists["xray_knocked"] = True
        self._ipset_list_lines["xray_knocked"] = (
            "Name: xray_knocked\nNumber of entries: 1\n"
            "127.0.0.1 timeout 3599\n"
        )
        with patch("chimera.modules.port_knocking.socket.socket") as msock:
            msock.return_value.connect_ex.return_value = 0
            result = _pk_test_knock(443)
        self.assertTrue(result["success"])
        self.assertTrue(result["in_xray_knocked"])

    def test_test_knock_fail_when_ip_not_in_set(self):
        from chimera.modules.port_knocking import _pk_test_knock
        self._ipset_exists["xray_knocked"] = True
        self._ipset_list_lines["xray_knocked"] = (
            "Name: xray_knocked\nNumber of entries: 0\n"
        )
        with patch("chimera.modules.port_knocking.socket.socket") as msock:
            msock.return_value.connect_ex.return_value = 0
            result = _pk_test_knock(443)
        self.assertFalse(result["success"])
        self.assertFalse(result["in_xray_knocked"])

    def test_test_knock_clears_ip_before_test(self):
        """Перед тестом 127.0.0.1 должен быть удалён из xray_knocked."""
        from chimera.modules.port_knocking import _pk_test_knock
        self._ipset_exists["xray_knocked"] = True
        with patch("chimera.modules.port_knocking.socket.socket") as msock:
            msock.return_value.connect_ex.return_value = 0
            _pk_test_knock(443)
        # ipset del was called
        del_calls = [c for c in self._calls
                     if c[:2] == ["ipset", "del"]]
        self.assertEqual(len(del_calls), 1)
        self.assertIn("127.0.0.1", del_calls[0])


# =============================================================================
# 11. MENU WIRING
# =============================================================================
class TestMenuWiring(unittest.TestCase):
    """Меню и точки интеграции существуют (source-маркеры)."""

    def test_menu_function_exists(self):
        from chimera.modules.port_knocking import do_manage_port_knocking
        self.assertTrue(callable(do_manage_port_knocking))

    def test_all_public_functions_exist(self):
        """Все публичные функции из spec существуют."""
        import chimera.modules.port_knocking as pk
        for fn_name in ("do_manage_port_knocking", "_pk_state_load",
                        "_pk_state_save", "_pk_install", "_pk_remove",
                        "_pk_status", "_pk_is_active", "_pk_test_knock",
                        "_pk_build_iptables_rules", "_pk_validate"):
            self.assertTrue(callable(getattr(pk, fn_name, None)),
                            f"missing: {fn_name}")

    def test_constants_exist(self):
        """Ключевые константы определены."""
        import chimera.modules.port_knocking as pk
        self.assertEqual(pk._PK_KNOCKED_SET, "xray_knocked")
        self.assertEqual(pk._PK_MANUAL_BAN_SET, "xray_manual_ban")
        self.assertEqual(pk._PK_WL_SET, "clients_wl")
        self.assertEqual(pk._PK_COMMENT_TAG, "chimera-port-knocking")
        self.assertEqual(pk._DEFAULT_KNOCK_COUNT, 3)
        self.assertEqual(pk._DEFAULT_KNOCK_WINDOW_SEC, 10)
        self.assertEqual(pk._DEFAULT_WHITELIST_TTL_SEC, 3600)

    def test_module_ast_parses(self):
        """Модуль — синтаксически валидный Python (ast.parse не падает)."""
        import ast
        src = (_PROJECT_ROOT / "chimera" / "modules" /
               "port_knocking.py").read_text()
        ast.parse(src)  # raises if invalid


if __name__ == "__main__":
    unittest.main(verbosity=2)
