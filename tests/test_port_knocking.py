#!/usr/bin/env python3
"""
tests/test_port_knocking.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/port_knocking.py.

Покрывает:
  1. _pk_state_load / _pk_state_save — JSON I/O с дефолтами + merge
  2. _pk_validate / _pk_validate_int — валидация конфига (ranges, types)
  3. _pk_build_iptables_rules — структура правил IPv4 (6 rules/port, 3+3)
  4. _pk_build_ip6tables_rules — структура правил IPv6 (5 rules/port, 2+3)
  5. _pk_build_ipset_create_cmd / _pk_build_ipset_create_cmd_v6 — ipset create
  6. _pk_recent_name / _pk_recent_name_v6 — имена recent-таблиц per port
  7. _pk_install — clean-before-install, UFW delete, IPv4+IPv6 rules
  8. _pk_remove — delete by line number (Bug 1), UFW restore, both ipsets
  9. _pk_is_active — проверка через iptables ИЛИ ip6tables
  10. _pk_status — форматированный статус с IPv4+IPv6
  11. _pk_test_knock — тест knocking (mock socket+ipset) для IPv4 и IPv6
  12. do_manage_port_knocking — функция-точка-входа существует

Все вызовы iptables/ip6tables/ipset/ufw — mock'd через _fake_run. Реальных
сетевых операций нет (socket в _pk_test_knock — mock'd через patch).
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

    _fake_run симулирует iptables/ip6tables/ufw/ipset:
      • хранит правила в _iptables_rules / _ip6tables_rules (list of spec strings)
      • -C проверяет наличие правила по подстроке
      • -I/-A добавляет правило в список
      • -D INPUT <N> удаляет по номеру строки (Bug 1 fix)
      • -L INPUT --line-numbers -n возвращает все правила с номерами строк
      • -S INPUT возвращает все правила как `-A INPUT <spec>`
      • ipset create/list/flush/destroy — симулируются через _ipset_exists/entries
      • ufw — no-op (всегда rc=0)
    """

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "port_knocking.json"
        self._calls: list[list] = []
        # Симулируемое состояние iptables INPUT (list of spec strings)
        self._iptables_rules: list[str] = []
        # Симулируемое состояние ip6tables INPUT (list of spec strings)
        self._ip6tables_rules: list[str] = []
        # Симулируемое состояние ipset
        self._ipset_exists = {
            "xray_knocked":       False,
            "xray_knocked6":      False,
            "clients_wl":         True,
            "xray_manual_ban":    True,
            "xray_manual_ban6":   True,
        }
        self._ipset_entries = {
            "xray_knocked":       0,
            "xray_knocked6":      0,
            "clients_wl":         5,
            "xray_manual_ban":    2,
            "xray_manual_ban6":   1,
        }
        # Симулируемый вывод ipset list для теста knocked IPs
        self._ipset_list_lines = {
            "xray_knocked":   "Name: xray_knocked\nNumber of entries: 0\n",
            "xray_knocked6":  "Name: xray_knocked6\nNumber of entries: 0\n",
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
        if not cmd:
            return _cp(cmd, 0, "", "")
        table = cmd[0]

        # iptables / ip6tables — общая обработка (Bug 1: -D by line number)
        if table in ("iptables", "ip6tables"):
            rules = (self._iptables_rules if table == "iptables"
                     else self._ip6tables_rules)
            return self._fake_table_cmd(cmd, rules)

        # ipset
        if table == "ipset":
            return self._fake_ipset_cmd(cmd)

        # ufw — no-op (Bug 3: ufw delete/allow)
        if table == "ufw":
            return _cp(cmd, 0, "", "")

        # default
        return _cp(cmd, 0, "", "")

    def _fake_table_cmd(self, cmd, rules):
        # -C INPUT <spec> — check if rule exists (substring)
        if cmd[1:3] == ["-C", "INPUT"]:
            spec_str = " ".join(str(c) for c in cmd[3:])
            for rule in rules:
                if spec_str in rule or rule in spec_str:
                    return _cp(cmd, 0, "", "")
            return _cp(cmd, 1, "", "rule not found")
        # -I INPUT <pos> <spec>
        if cmd[1:3] == ["-I", "INPUT"]:
            rules.append(" ".join(str(c) for c in cmd[4:]))
            return _cp(cmd, 0, "", "")
        # -A INPUT <spec>
        if cmd[1:3] == ["-A", "INPUT"]:
            rules.append(" ".join(str(c) for c in cmd[3:]))
            return _cp(cmd, 0, "", "")
        # -D INPUT <N>  (delete by line number — Bug 1 fix)
        # OR -D INPUT <spec> (legacy fallback — not used by new code)
        if cmd[1:3] == ["-D", "INPUT"]:
            if len(cmd) >= 4 and str(cmd[3]).isdigit():
                n = int(cmd[3])
                if 1 <= n <= len(rules):
                    rules.pop(n - 1)
                    return _cp(cmd, 0, "", "")
                return _cp(cmd, 1, "", "line number out of range")
            # legacy: delete by spec
            spec_str = " ".join(str(c) for c in cmd[3:])
            for i, rule in enumerate(rules):
                if spec_str in rule or rule in spec_str:
                    rules.pop(i)
                    return _cp(cmd, 0, "", "")
            return _cp(cmd, 1, "", "rule not found")
        # -L INPUT --line-numbers -n
        if cmd[1:3] == ["-L", "INPUT"]:
            out = "Chain INPUT (policy ACCEPT)\n" \
                  "num  pkts bytes target  prot opt in out source dest\n"
            for i, rule in enumerate(rules, 1):
                out += f"{i}    0  0  ACCEPT  ...  {rule}\n"
            return _cp(cmd, 0, out, "")
        # -S INPUT — list all rules
        if cmd[1:3] == ["-S", "INPUT"]:
            out = "\n".join("-A INPUT " + r for r in rules)
            if out:
                out += "\n"
            return _cp(cmd, 0, out, "")
        return _cp(cmd, 0, "", "")

    def _fake_ipset_cmd(self, cmd):
        # ipset create <name> hash:ip timeout N [family inet6] -exist
        if cmd[1] == "create":
            name = cmd[2] if len(cmd) > 2 else ""
            # detect IPv6 by "family inet6" arg
            self._ipset_exists[name] = True
            return _cp(cmd, 0, "", "")
        # ipset list <name>
        if cmd[1] == "list":
            name = cmd[2] if len(cmd) > 2 else ""
            if not self._ipset_exists.get(name, False):
                return _cp(cmd, 1, "", "set does not exist")
            return _cp(cmd, 0, self._ipset_list_lines.get(
                name, f"Name: {name}\nNumber of entries: "
                f"{self._ipset_entries.get(name, 0)}\n"), "")
        # ipset flush <name>
        if cmd[1] == "flush":
            name = cmd[2] if len(cmd) > 2 else ""
            if name in self._ipset_entries:
                self._ipset_entries[name] = 0
            return _cp(cmd, 0, "", "")
        # ipset destroy <name>
        if cmd[1] == "destroy":
            name = cmd[2] if len(cmd) > 2 else ""
            self._ipset_exists[name] = False
            return _cp(cmd, 0, "", "")
        # ipset del <name> <ip>
        if cmd[1] == "del":
            return _cp(cmd, 0, "", "")
        # ipset test <name> <ip> — returns 0 if IP is in set, 1 if not
        if cmd[1] == "test":
            return _cp(cmd, 1, "", "IP not in set")  # default: not in set
        # ipset save <name>
        if cmd[1] == "save":
            return _cp(cmd, 0, "", "")
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
#  3. BUILD IPTABLES RULES (IPv4)
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
        # Bug 5 fix: -j SET --add-set (not -m set --add-set)
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

    def test_uses_j_set_addset_not_m_set_addset(self):
        """Bug 5 fix: -j SET --add-set (iptables-nft compatible)."""
        from chimera.modules.port_knocking import (
            _pk_build_iptables_rules, _pk_default_state,
        )
        rules = _pk_build_iptables_rules(443, _pk_default_state())
        # Rule 5: -j SET --add-set xray_knocked src
        rule5 = rules[4]["spec"]
        # has "-j SET"
        j_set_idx = -1
        for i, s in enumerate(rule5):
            if s == "-j":
                j_set_idx = i
                break
        self.assertGreaterEqual(j_set_idx, 0)
        self.assertLess(j_set_idx + 1, len(rule5))
        self.assertEqual(rule5[j_set_idx + 1], "SET")
        self.assertIn("--add-set", rule5)


# =============================================================================
#  4. BUILD IP6TABLES RULES (IPv6) — NEW
# =============================================================================
class TestBuildIp6tablesRules(_PortKnockingBase):

    def test_returns_five_rules_per_port(self):
        """IPv6: 2 INSERT + 3 APPEND = 5 (no clients_wl rule for IPv6)."""
        from chimera.modules.port_knocking import (
            _pk_build_ip6tables_rules, _pk_default_state,
        )
        rules = _pk_build_ip6tables_rules(443, _pk_default_state())
        self.assertEqual(len(rules), 5)

    def test_first_two_are_inserts_at_positions_1_2(self):
        from chimera.modules.port_knocking import (
            _pk_build_ip6tables_rules, _pk_default_state,
        )
        rules = _pk_build_ip6tables_rules(443, _pk_default_state())
        self.assertEqual(rules[0]["op"], "insert")
        self.assertEqual(rules[1]["op"], "insert")
        self.assertEqual(rules[0]["pos"], 1)
        self.assertEqual(rules[1]["pos"], 2)

    def test_last_three_are_appends(self):
        from chimera.modules.port_knocking import (
            _pk_build_ip6tables_rules, _pk_default_state,
        )
        rules = _pk_build_ip6tables_rules(443, _pk_default_state())
        for i in range(2, 5):
            self.assertEqual(rules[i]["op"], "append")

    def test_insert_rules_reference_correct_v6_ipsets(self):
        from chimera.modules.port_knocking import (
            _pk_build_ip6tables_rules, _pk_default_state,
        )
        rules = _pk_build_ip6tables_rules(443, _pk_default_state())
        # Rule 1 (pos 1): DROP from xray_manual_ban6
        self.assertIn("xray_manual_ban6", rules[0]["spec"])
        self.assertIn("DROP", rules[0]["spec"])
        # Rule 2 (pos 2): ACCEPT from xray_knocked6
        self.assertIn("xray_knocked6", rules[1]["spec"])
        self.assertIn("ACCEPT", rules[1]["spec"])

    def test_no_clients_wl_in_ipv6_rules(self):
        """No clients_wl rule for IPv6 (whitelist module is IPv4-only)."""
        from chimera.modules.port_knocking import (
            _pk_build_ip6tables_rules, _pk_default_state,
        )
        rules = _pk_build_ip6tables_rules(443, _pk_default_state())
        for r in rules:
            self.assertNotIn("clients_wl", r["spec"])

    def test_append_rules_use_recent_v6_name(self):
        from chimera.modules.port_knocking import (
            _pk_build_ip6tables_rules, _pk_default_state,
        )
        rules = _pk_build_ip6tables_rules(443, _pk_default_state())
        # Rule 3 (append idx 0): recent --set with KNOCK443v6
        self.assertIn("recent", rules[2]["spec"])
        self.assertIn("--set", rules[2]["spec"])
        self.assertIn("KNOCK443v6", rules[2]["spec"])
        # Rule 4 (append idx 1): recent --rcheck + add-set xray_knocked6
        self.assertIn("--rcheck", rules[3]["spec"])
        self.assertIn("--hitcount", rules[3]["spec"])
        self.assertIn("3", rules[3]["spec"])  # default knock_count=3
        self.assertIn("--add-set", rules[3]["spec"])
        self.assertIn("xray_knocked6", rules[3]["spec"])
        # Rule 5 (append idx 2): --syn -j DROP
        self.assertIn("DROP", rules[4]["spec"])
        self.assertIn("--syn", rules[4]["spec"])

    def test_all_rules_have_comment_tag(self):
        from chimera.modules.port_knocking import (
            _pk_build_ip6tables_rules, _pk_default_state, _PK_COMMENT_TAG,
        )
        rules = _pk_build_ip6tables_rules(443, _pk_default_state())
        for rule in rules:
            # IPv6 comments use suffixed form (e.g. "chimera-port-knocking:DROP-ban6"),
            # so check substring via joined string (not exact element match).
            spec_str = " ".join(str(s) for s in rule["spec"])
            self.assertIn(_PK_COMMENT_TAG, spec_str,
                          f"comment tag not in spec: {spec_str}")

    def test_dport_in_all_rules(self):
        from chimera.modules.port_knocking import (
            _pk_build_ip6tables_rules, _pk_default_state,
        )
        rules = _pk_build_ip6tables_rules(9443, _pk_default_state())
        for rule in rules:
            self.assertIn("9443", rule["spec"])

    def test_recent_name_v6_unique_per_port(self):
        """IPv6 recent names per port: KNOCK443v6 vs KNOCK9443v6."""
        from chimera.modules.port_knocking import (
            _pk_build_ip6tables_rules, _pk_default_state,
        )
        rules_443  = _pk_build_ip6tables_rules(443, _pk_default_state())
        rules_9443 = _pk_build_ip6tables_rules(9443, _pk_default_state())
        names_443  = [s for r in rules_443  for s in r["spec"]
                      if str(s).startswith("KNOCK")]
        names_9443 = [s for r in rules_9443 for s in r["spec"]
                      if str(s).startswith("KNOCK")]
        self.assertIn("KNOCK443v6", names_443)
        self.assertNotIn("KNOCK9443v6", names_443)
        self.assertIn("KNOCK9443v6", names_9443)
        self.assertNotIn("KNOCK443v6", names_9443)

    def test_ipv6_recent_names_differ_from_ipv4(self):
        """IPv6 names must differ from IPv4 (separate xt_recent tables)."""
        from chimera.modules.port_knocking import (
            _pk_build_iptables_rules, _pk_build_ip6tables_rules,
            _pk_default_state,
        )
        v4 = _pk_build_iptables_rules(443, _pk_default_state())
        v6 = _pk_build_ip6tables_rules(443, _pk_default_state())
        v4_names = [s for r in v4 for s in r["spec"]
                    if str(s).startswith("KNOCK")]
        v6_names = [s for r in v6 for s in r["spec"]
                    if str(s).startswith("KNOCK")]
        # No overlap
        self.assertEqual(set(v4_names) & set(v6_names), set())
        self.assertIn("KNOCK443", v4_names)
        self.assertIn("KNOCK443v6", v6_names)

    def test_knock_count_propagates_to_v6_hitcount(self):
        from chimera.modules.port_knocking import (
            _pk_build_ip6tables_rules, _pk_default_state,
        )
        state = _pk_default_state()
        state["knock_count"] = 5
        rules = _pk_build_ip6tables_rules(443, state)
        self.assertIn("5", rules[3]["spec"])

    def test_knock_window_propagates_to_v6_seconds(self):
        from chimera.modules.port_knocking import (
            _pk_build_ip6tables_rules, _pk_default_state,
        )
        state = _pk_default_state()
        state["knock_window_sec"] = 42
        rules = _pk_build_ip6tables_rules(443, state)
        self.assertIn("42", rules[3]["spec"])

    def test_v6_uses_j_set_addset(self):
        """Bug 5 fix: -j SET --add-set (ip6tables-nft compatible)."""
        from chimera.modules.port_knocking import (
            _pk_build_ip6tables_rules, _pk_default_state,
        )
        rules = _pk_build_ip6tables_rules(443, _pk_default_state())
        rule4 = rules[3]["spec"]
        j_set_idx = -1
        for i, s in enumerate(rule4):
            if s == "-j":
                j_set_idx = i
                break
        self.assertGreaterEqual(j_set_idx, 0)
        self.assertLess(j_set_idx + 1, len(rule4))
        self.assertEqual(rule4[j_set_idx + 1], "SET")
        self.assertIn("--add-set", rule4)

    def test_v6_comment_suffixes(self):
        """IPv6 rules use suffixed comments like chimera-port-knocking:DROP-ban6."""
        from chimera.modules.port_knocking import (
            _pk_build_ip6tables_rules, _pk_default_state, _PK_COMMENT_TAG,
        )
        rules = _pk_build_ip6tables_rules(443, _pk_default_state())
        # Find the comment string in each rule spec
        comments_found = []
        for r in rules:
            for i, s in enumerate(r["spec"]):
                if s == "--comment" and i + 1 < len(r["spec"]):
                    comments_found.append(r["spec"][i + 1])
        self.assertEqual(len(comments_found), 5)
        for c in comments_found:
            self.assertTrue(c.startswith(_PK_COMMENT_TAG + ":"),
                            f"comment '{c}' should start with tag prefix")
            self.assertTrue(c.endswith("6"),
                            f"comment '{c}' should end with 6 for IPv6")


# =============================================================================
#  5. BUILD IPSET CREATE CMD
# =============================================================================
class TestBuildIpsetCreateCmd(_PortKnockingBase):

    def test_v4_returns_correct_command(self):
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
        # Bug 4 fix: -exist (with dash), not "exist"
        self.assertIn("-exist", cmd)
        # IPv4 — no family inet6
        self.assertNotIn("inet6", cmd)
        self.assertNotIn("family", cmd)

    def test_v4_uses_state_ttl(self):
        from chimera.modules.port_knocking import (
            _pk_build_ipset_create_cmd, _pk_default_state,
        )
        state = _pk_default_state()
        state["whitelist_ttl_sec"] = 7200
        cmd = _pk_build_ipset_create_cmd(state)
        self.assertIn("7200", cmd)

    def test_v6_returns_correct_command(self):
        from chimera.modules.port_knocking import (
            _pk_build_ipset_create_cmd_v6, _pk_default_state,
            _PK_KNOCKED_SET_V6,
        )
        cmd = _pk_build_ipset_create_cmd_v6(_pk_default_state())
        self.assertEqual(cmd[0], "ipset")
        self.assertEqual(cmd[1], "create")
        self.assertEqual(cmd[2], _PK_KNOCKED_SET_V6)
        self.assertIn("hash:ip", cmd)
        self.assertIn("timeout", cmd)
        self.assertIn("3600", cmd)
        # IPv6 — family inet6
        self.assertIn("family", cmd)
        self.assertIn("inet6", cmd)
        # Bug 4 fix: -exist
        self.assertIn("-exist", cmd)

    def test_v6_uses_state_ttl(self):
        from chimera.modules.port_knocking import (
            _pk_build_ipset_create_cmd_v6, _pk_default_state,
        )
        state = _pk_default_state()
        state["whitelist_ttl_sec"] = 7200
        cmd = _pk_build_ipset_create_cmd_v6(state)
        self.assertIn("7200", cmd)
        self.assertIn("inet6", cmd)


# =============================================================================
#  6. RECENT NAME
# =============================================================================
class TestRecentName(_PortKnockingBase):

    def test_v4_returns_knock_prefix(self):
        from chimera.modules.port_knocking import _pk_recent_name
        self.assertEqual(_pk_recent_name(443), "KNOCK443")
        self.assertEqual(_pk_recent_name(9443), "KNOCK9443")
        self.assertEqual(_pk_recent_name(8080), "KNOCK8080")

    def test_v6_returns_knock_v6_prefix(self):
        from chimera.modules.port_knocking import _pk_recent_name_v6
        self.assertEqual(_pk_recent_name_v6(443), "KNOCK443v6")
        self.assertEqual(_pk_recent_name_v6(9443), "KNOCK9443v6")
        self.assertEqual(_pk_recent_name_v6(8080), "KNOCK8080v6")


# =============================================================================
#  7. INSTALL (clean-before-install + UFW delete + IPv4 + IPv6)
# =============================================================================
class TestInstall(_PortKnockingBase):

    def test_install_creates_both_ipsets_and_rules(self):
        from chimera.modules.port_knocking import (
            _pk_install, _pk_default_state, _PK_KNOCKED_SET,
            _PK_KNOCKED_SET_V6,
        )
        state = _pk_default_state()
        ok = _pk_install(state)
        self.assertTrue(ok)
        # Both ipset create calls (v4 + v6)
        create_calls = [c for c in self._calls
                        if c[:2] == ["ipset", "create"]]
        self.assertEqual(len(create_calls), 2)
        self.assertTrue(any(_PK_KNOCKED_SET in c for c in create_calls))
        self.assertTrue(any(_PK_KNOCKED_SET_V6 in c for c in create_calls))
        # iptables -I/-A rules were called (3 inserts + 3 appends for 1 port)
        insert_calls = [c for c in self._calls
                        if c[:3] == ["iptables", "-I", "INPUT"]]
        append_calls = [c for c in self._calls
                        if c[:3] == ["iptables", "-A", "INPUT"]]
        self.assertEqual(len(insert_calls), 3)
        self.assertEqual(len(append_calls), 3)
        # ip6tables -I/-A rules were called (2 inserts + 3 appends for 1 port)
        insert_v6 = [c for c in self._calls
                     if c[:3] == ["ip6tables", "-I", "INPUT"]]
        append_v6 = [c for c in self._calls
                     if c[:3] == ["ip6tables", "-A", "INPUT"]]
        self.assertEqual(len(insert_v6), 2)
        self.assertEqual(len(append_v6), 3)

    def test_install_calls_remove_first(self):
        """Bug 2 fix: install() calls _pk_remove() before installing.

        Verify that iptables -L INPUT --line-numbers -n is called
        (which is what _pk_remove uses to find old rules).
        """
        from chimera.modules.port_knocking import (
            _pk_install, _pk_default_state,
        )
        ok = _pk_install(_pk_default_state())
        self.assertTrue(ok)
        # _pk_remove calls iptables -L INPUT --line-numbers -n
        list_v4 = [c for c in self._calls
                   if c[:3] == ["iptables", "-L", "INPUT"]]
        self.assertGreater(len(list_v4), 0)
        # _pk_remove calls ip6tables -L INPUT --line-numbers -n
        list_v6 = [c for c in self._calls
                   if c[:3] == ["ip6tables", "-L", "INPUT"]]
        self.assertGreater(len(list_v6), 0)
        # First table call should be -L (from _pk_remove), not -I/-A
        table_calls = [c for c in self._calls
                       if c[0] in ("iptables", "ip6tables")]
        self.assertGreater(len(table_calls), 0)
        self.assertEqual(table_calls[0][1], "-L",
                         f"first table call should be -L, got {table_calls[0]}")

    def test_install_deletes_ufw_rules_for_each_port(self):
        """Bug 3 fix: ufw delete allow <port>/tcp for each port."""
        from chimera.modules.port_knocking import (
            _pk_install, _pk_default_state,
        )
        state = _pk_default_state()
        state["ports"] = [443, 9443]
        ok = _pk_install(state)
        self.assertTrue(ok)
        # ufw delete allow <port>/tcp for each port
        ufw_delete = [c for c in self._calls
                      if c[:3] == ["ufw", "delete", "allow"]]
        self.assertEqual(len(ufw_delete), 2)
        # Verify both ports are present
        port_strs = [f"{p}/tcp" for p in (443, 9443)]
        for ps in port_strs:
            self.assertTrue(any(ps in c for c in ufw_delete),
                            f"ufw delete for {ps} not found")

    def test_install_idempotent_second_run_reinstalls(self):
        """Bug 2 fix: second install calls _pk_remove first (clears old),
        then reinstalls fresh rules."""
        from chimera.modules.port_knocking import (
            _pk_install, _pk_default_state,
        )
        # First install
        ok = _pk_install(_pk_default_state())
        self.assertTrue(ok)
        # Reset calls — second install
        self._calls.clear()
        # After first install, _iptables_rules has 6 rules + _ip6tables_rules has 5.
        # Second install calls _pk_remove → deletes all 11 rules, then reinstalls.
        ok2 = _pk_install(_pk_default_state())
        self.assertTrue(ok2)
        # _pk_remove was called: iptables -L INPUT invoked
        list_v4 = [c for c in self._calls
                   if c[:3] == ["iptables", "-L", "INPUT"]]
        self.assertGreater(len(list_v4), 0)
        # After remove, install re-adds rules (3 inserts + 3 appends iptables)
        insert_calls = [c for c in self._calls
                        if c[:3] == ["iptables", "-I", "INPUT"]]
        append_calls = [c for c in self._calls
                        if c[:3] == ["iptables", "-A", "INPUT"]]
        self.assertEqual(len(insert_calls), 3)
        self.assertEqual(len(append_calls), 3)
        # IPv6 rules also reinstalled
        insert_v6 = [c for c in self._calls
                     if c[:3] == ["ip6tables", "-I", "INPUT"]]
        self.assertEqual(len(insert_v6), 2)
        append_v6 = [c for c in self._calls
                     if c[:3] == ["ip6tables", "-A", "INPUT"]]
        self.assertEqual(len(append_v6), 3)

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
        # IPv4: 6 rules per port × 2 ports = 12 (3 inserts + 3 appends × 2)
        insert_calls = [c for c in self._calls
                        if c[:3] == ["iptables", "-I", "INPUT"]]
        append_calls = [c for c in self._calls
                        if c[:3] == ["iptables", "-A", "INPUT"]]
        self.assertEqual(len(insert_calls), 6)
        self.assertEqual(len(append_calls), 6)
        # IPv6: 5 rules per port × 2 ports = 10 (2 inserts + 3 appends × 2)
        insert_v6 = [c for c in self._calls
                     if c[:3] == ["ip6tables", "-I", "INPUT"]]
        append_v6 = [c for c in self._calls
                     if c[:3] == ["ip6tables", "-A", "INPUT"]]
        self.assertEqual(len(insert_v6), 4)
        self.assertEqual(len(append_v6), 6)

    def test_install_skips_clients_wl_if_ipset_missing(self):
        """If clients_wl ipset doesn't exist, skip its rule (don't crash)."""
        from chimera.modules.port_knocking import (
            _pk_install, _pk_default_state,
        )
        self._ipset_exists["clients_wl"] = False
        ok = _pk_install(_pk_default_state())
        self.assertTrue(ok)
        # Only 2 inserts (ban + knocked, skip wl) instead of 3
        insert_calls = [c for c in self._calls
                        if c[:3] == ["iptables", "-I", "INPUT"]]
        self.assertEqual(len(insert_calls), 2)

    def test_install_skips_manual_ban6_if_ipset_missing(self):
        """If xray_manual_ban6 ipset doesn't exist, skip its IPv6 rule."""
        from chimera.modules.port_knocking import (
            _pk_install, _pk_default_state,
        )
        self._ipset_exists["xray_manual_ban6"] = False
        ok = _pk_install(_pk_default_state())
        self.assertTrue(ok)
        # Only 1 insert (knocked6, skip ban6) instead of 2
        insert_v6 = [c for c in self._calls
                     if c[:3] == ["ip6tables", "-I", "INPUT"]]
        self.assertEqual(len(insert_v6), 1)


# =============================================================================
#  8. REMOVE (delete by line number, both tables, UFW restore)
# =============================================================================
class TestRemove(_PortKnockingBase):

    def test_remove_deletes_rules_by_line_number(self):
        """Bug 1 fix: delete by line number, not by comment."""
        from chimera.modules.port_knocking import (
            _pk_remove, _PK_COMMENT_TAG,
        )
        # Pre-populate _iptables_rules with 6 of our rules (with comment tag)
        # + 1 non-our rule that should NOT be touched.
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
            f"--seconds 10 --hitcount 3 -j SET --add-set xray_knocked src "
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
        # Bug 1 fix: each -D call has a numeric line number (not a spec)
        for c in delete_calls:
            self.assertEqual(len(c), 4,
                             f"-D call should be 'iptables -D INPUT <N>', got {c}")
            self.assertTrue(str(c[3]).isdigit(),
                            f"Expected numeric line number, got: {c}")
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

    def test_remove_deletes_bottom_up(self):
        """Bug 1 fix: line numbers sorted descending (bottom-up delete)."""
        from chimera.modules.port_knocking import (
            _pk_remove, _PK_COMMENT_TAG,
        )
        # 3 of our rules + 1 non-our rule (non-our rule is last, no tag)
        for i in range(3):
            self._iptables_rules.append(
                f"-p tcp --dport {443 + i} -j DROP "
                f"-m comment --comment {_PK_COMMENT_TAG}"
            )
        self._iptables_rules.append("-p tcp --dport 22 -j ACCEPT")
        self._ipset_exists["xray_knocked"] = True

        _pk_remove()
        # First -D should be line 3 (highest of our-tagged rules), then 2, then 1
        delete_calls = [c for c in self._calls
                        if c[:3] == ["iptables", "-D", "INPUT"]]
        self.assertEqual(len(delete_calls), 3)
        line_nums = [int(c[3]) for c in delete_calls]
        self.assertEqual(line_nums, [3, 2, 1])

    def test_remove_deletes_ip6tables_rules_too(self):
        """Remove also handles ip6tables rules (IPv6 support)."""
        from chimera.modules.port_knocking import (
            _pk_remove, _PK_COMMENT_TAG,
        )
        # 2 IPv6 rules with our tag
        self._ip6tables_rules.extend([
            f"-p tcp --dport 443 -m set --match-set xray_knocked6 src "
            f"-j ACCEPT -m comment --comment {_PK_COMMENT_TAG}:ACCEPT-knocked6",
            f"-p tcp --dport 443 --syn -j DROP -m comment --comment "
            f"{_PK_COMMENT_TAG}:DROP-default6",
        ])
        self._ipset_exists["xray_knocked6"] = True

        _pk_remove()
        # ip6tables -L called
        list_v6 = [c for c in self._calls
                   if c[:3] == ["ip6tables", "-L", "INPUT"]]
        self.assertGreater(len(list_v6), 0)
        # ip6tables -D called 2 times (once per IPv6 rule)
        delete_v6 = [c for c in self._calls
                     if c[:3] == ["ip6tables", "-D", "INPUT"]]
        self.assertEqual(len(delete_v6), 2)
        for c in delete_v6:
            self.assertTrue(str(c[3]).isdigit(),
                            f"Expected numeric line number, got: {c}")
        # All IPv6 rules deleted
        self.assertEqual(len(self._ip6tables_rules), 0)
        # ipset xray_knocked6 destroyed
        self.assertFalse(self._ipset_exists["xray_knocked6"])

    def test_remove_destroys_both_ipsets(self):
        """Both xray_knocked (IPv4) and xray_knocked6 (IPv6) destroyed."""
        from chimera.modules.port_knocking import (
            _pk_remove, _PK_KNOCKED_SET, _PK_KNOCKED_SET_V6,
        )
        self._ipset_exists["xray_knocked"] = True
        self._ipset_exists["xray_knocked6"] = True
        _pk_remove()
        self.assertFalse(self._ipset_exists["xray_knocked"])
        self.assertFalse(self._ipset_exists["xray_knocked6"])
        destroy_calls = [c for c in self._calls
                         if c[:2] == ["ipset", "destroy"]]
        destroyed_names = [c[2] for c in destroy_calls]
        self.assertIn(_PK_KNOCKED_SET, destroyed_names)
        self.assertIn(_PK_KNOCKED_SET_V6, destroyed_names)

    def test_remove_restores_ufw_when_was_enabled(self):
        """Bug 3 fix: restore ufw allow <port>/tcp when was previously enabled."""
        from chimera.modules.port_knocking import (
            _pk_remove, _pk_state_save, _pk_default_state,
        )
        # Save state as enabled with ports
        state = _pk_default_state()
        state["enabled"] = True
        state["ports"] = [443, 9443]
        _pk_state_save(state)
        self._ipset_exists["xray_knocked"] = True

        _pk_remove()
        # ufw allow called for each port (with comment)
        ufw_allow = [c for c in self._calls
                     if c[:2] == ["ufw", "allow"]]
        self.assertEqual(len(ufw_allow), 2)
        for c in ufw_allow:
            # ufw allow <port>/tcp comment "chimera-vless VLESS REALITY :<port>"
            self.assertIn("comment", c)
            # The whole command joined should contain the comment string
            call_str = " ".join(c)
            self.assertIn("chimera-vless", call_str,
                          f"comment not found in {call_str}")
            self.assertIn("VLESS REALITY", call_str)

    def test_remove_does_not_restore_ufw_when_not_enabled(self):
        """Don't restore UFW if module was not enabled (fresh install case)."""
        from chimera.modules.port_knocking import (
            _pk_remove, _pk_default_state,
        )
        # state not enabled (default)
        _pk_remove()
        ufw_allow = [c for c in self._calls if c[:2] == ["ufw", "allow"]]
        self.assertEqual(len(ufw_allow), 0)

    def test_remove_no_rules_no_crash(self):
        """remove() безопасен когда правил нет."""
        from chimera.modules.port_knocking import _pk_remove
        # _iptables_rules empty, ipset doesn't exist
        ok = _pk_remove()
        self.assertTrue(ok)
        # iptables -L INPUT called (Bug 1 fix uses -L, not -S)
        list_calls = [c for c in self._calls
                      if c[:3] == ["iptables", "-L", "INPUT"]]
        self.assertEqual(len(list_calls), 1)
        # ip6tables -L INPUT also called
        list_v6 = [c for c in self._calls
                   if c[:3] == ["ip6tables", "-L", "INPUT"]]
        self.assertEqual(len(list_v6), 1)

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
        """clients_wl и xray_manual_ban(6) — чужие ipsets, не flush/destroy."""
        from chimera.modules.port_knocking import _pk_remove
        self._ipset_exists["xray_knocked"] = True
        self._ipset_exists["xray_knocked6"] = True
        _pk_remove()
        # clients_wl and xray_manual_ban(6) still exist
        self.assertTrue(self._ipset_exists["clients_wl"])
        self.assertTrue(self._ipset_exists["xray_manual_ban"])
        self.assertTrue(self._ipset_exists["xray_manual_ban6"])
        # no flush/destroy for clients_wl or xray_manual_ban(6)
        for call in self._calls:
            if call[:2] in (["ipset", "flush"], ["ipset", "destroy"]):
                self.assertNotIn("clients_wl", call)
                self.assertNotIn("xray_manual_ban", call)


# =============================================================================
#  9. IS_ACTIVE (iptables OR ip6tables)
# =============================================================================
class TestIsActive(_PortKnockingBase):

    def test_is_active_false_when_no_rules(self):
        from chimera.modules.port_knocking import _pk_is_active
        self.assertFalse(_pk_is_active())

    def test_is_active_true_when_iptables_rules_present(self):
        from chimera.modules.port_knocking import (
            _pk_is_active, _PK_COMMENT_TAG,
        )
        self._iptables_rules.append(
            f"-p tcp --dport 443 -j DROP -m comment --comment "
            f"{_PK_COMMENT_TAG}"
        )
        self.assertTrue(_pk_is_active())

    def test_is_active_true_when_ip6tables_rules_present(self):
        """IPv6 support: _pk_is_active checks ip6tables too."""
        from chimera.modules.port_knocking import (
            _pk_is_active, _PK_COMMENT_TAG,
        )
        self._ip6tables_rules.append(
            f"-p tcp --dport 443 -j DROP -m comment --comment "
            f"{_PK_COMMENT_TAG}:DROP-default6"
        )
        self.assertTrue(_pk_is_active())

    def test_is_active_checks_both_tables(self):
        """_pk_is_active should call both iptables -S and ip6tables -S."""
        from chimera.modules.port_knocking import _pk_is_active
        _pk_is_active()
        # Both tables queried via -S INPUT
        ipt_calls = [c for c in self._calls
                     if c[:3] == ["iptables", "-S", "INPUT"]]
        ip6t_calls = [c for c in self._calls
                      if c[:3] == ["ip6tables", "-S", "INPUT"]]
        self.assertEqual(len(ipt_calls), 1)
        self.assertEqual(len(ip6t_calls), 1)


# =============================================================================
#  10. STATUS
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
        # IPv4 ipset
        self.assertIn("xray_knocked:", s)
        # IPv6 ipset (new)
        self.assertIn("xray_knocked6:", s)
        # default ports
        self.assertIn("443", s)

    def test_status_inactive_when_no_rules(self):
        from chimera.modules.port_knocking import _pk_status
        s = _pk_status()
        self.assertIn("inactive", s)

    def test_status_shows_both_rule_counts(self):
        """Status shows iptables=X, ip6tables=Y rule counts."""
        from chimera.modules.port_knocking import (
            _pk_status, _PK_COMMENT_TAG,
        )
        # Add rules to both tables
        self._iptables_rules.append(
            f"-p tcp --dport 443 -j DROP -m comment --comment {_PK_COMMENT_TAG}"
        )
        self._ip6tables_rules.append(
            f"-p tcp --dport 443 -j DROP -m comment --comment "
            f"{_PK_COMMENT_TAG}:v6"
        )
        s = _pk_status()
        self.assertIn("iptables=1", s)
        self.assertIn("ip6tables=1", s)


# =============================================================================
#  11. TEST KNOCK (mock socket + ipset) — IPv4 + IPv6
# =============================================================================
class TestTestKnock(_PortKnockingBase):

    def _mock_public_ips(self):
        """Patch _get_server_ipv4 and _get_server_ipv6 to return test IPs."""
        return [
            patch("chimera.modules.port_knocking._get_server_ipv4",
                  return_value="192.0.2.1"),
            patch("chimera.modules.port_knocking._get_server_ipv6",
                  return_value="2001:db8::1"),
        ]

    def test_test_knock_returns_dict_with_expected_fields(self):
        from chimera.modules.port_knocking import _pk_test_knock
        self._ipset_exists["xray_knocked"] = True
        self._ipset_list_lines["xray_knocked"] = (
            "Name: xray_knocked\nNumber of entries: 1\n"
            "192.0.2.1 timeout 3599\n"
        )
        patches = self._mock_public_ips()
        with patch("chimera.modules.port_knocking.socket.socket") as msock, \
             patches[0], patches[1]:
            msock.return_value.connect_ex.return_value = 0
            result = _pk_test_knock(443)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["port"], 443)
        self.assertEqual(result["knock_count"], 3)
        self.assertIn("sent_syns", result)
        self.assertIn("in_xray_knocked", result)
        self.assertIn("success", result)
        self.assertIn("ipv6_available", result)
        self.assertIn("ipv6_sent_syns", result)
        self.assertIn("in_xray_knocked6", result)
        self.assertIn("ipv6_success", result)
        self.assertIn("ipv4_ip", result)
        self.assertIn("ipv6_ip", result)

    def test_test_knock_success_when_ip_in_set(self):
        from chimera.modules.port_knocking import _pk_test_knock
        self._ipset_exists["xray_knocked"] = True
        self._ipset_list_lines["xray_knocked"] = (
            "Name: xray_knocked\nNumber of entries: 1\n"
            "192.0.2.1 timeout 3599\n"
        )
        patches = self._mock_public_ips()
        with patch("chimera.modules.port_knocking.socket.socket") as msock, \
             patches[0], patches[1]:
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
        patches = self._mock_public_ips()
        with patch("chimera.modules.port_knocking.socket.socket") as msock, \
             patches[0], patches[1]:
            msock.return_value.connect_ex.return_value = 0
            result = _pk_test_knock(443)
        self.assertFalse(result["success"])
        self.assertFalse(result["in_xray_knocked"])

    def test_test_knock_clears_ip_before_test(self):
        """Перед тестом публичный IP должен быть удалён из ipset."""
        from chimera.modules.port_knocking import _pk_test_knock
        self._ipset_exists["xray_knocked"] = True
        self._ipset_exists["xray_knocked6"] = True
        patches = self._mock_public_ips()
        with patch("chimera.modules.port_knocking.socket.socket") as msock, \
             patches[0], patches[1]:
            msock.return_value.connect_ex.return_value = 0
            _pk_test_knock(443)
        del_calls = [c for c in self._calls if c[:2] == ["ipset", "del"]]
        self.assertGreaterEqual(len(del_calls), 1)
        # IPv4 public IP del
        self.assertTrue(any("192.0.2.1" in c for c in del_calls))
        # IPv6 public IP del when available
        if any("2001:db8::1" in c for c in del_calls):
            self.assertGreaterEqual(len(del_calls), 2)

    def test_test_knock_ipv6_path_runs_when_available(self):
        """When IPv6 available, IPv6 knock path is executed with public IP."""
        from chimera.modules.port_knocking import _pk_test_knock
        self._ipset_exists["xray_knocked6"] = True
        self._ipset_list_lines["xray_knocked6"] = (
            "Name: xray_knocked6\nNumber of entries: 1\n"
            "2001:db8::1 timeout 3599\n"
        )
        patches = self._mock_public_ips()
        with patch("chimera.modules.port_knocking.socket.socket") as msock, \
             patches[0], patches[1]:
            msock.return_value.connect_ex.return_value = 0
            result = _pk_test_knock(443)
        self.assertTrue(result["ipv6_available"])
        self.assertEqual(result["ipv6_sent_syns"], 3)
        self.assertTrue(result["in_xray_knocked6"])
        self.assertTrue(result["ipv6_success"])

    def test_test_knock_ipv6_skipped_when_unavailable(self):
        """When IPv6 socket fails (no AF_INET6), IPv6 path is skipped."""
        from chimera.modules.port_knocking import _pk_test_knock
        patches = self._mock_public_ips()
        with patch("chimera.modules.port_knocking.socket.socket") as msock, \
             patches[0], patches[1]:
            msock.return_value.connect_ex.return_value = 0
            with patch("chimera.modules.port_knocking._pk_ipv6_available",
                       return_value=False):
                result = _pk_test_knock(443)
        self.assertFalse(result["ipv6_available"])
        self.assertEqual(result["ipv6_sent_syns"], 0)
        self.assertFalse(result["in_xray_knocked6"])
        self.assertFalse(result["ipv6_success"])
        del_calls = [c for c in self._calls if c[:2] == ["ipset", "del"]]
        for c in del_calls:
            self.assertNotIn("2001:db8::1", c)


# =============================================================================
#  12. MENU WIRING
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
                        "_pk_build_iptables_rules",
                        "_pk_build_ip6tables_rules",
                        "_pk_build_ipset_create_cmd",
                        "_pk_build_ipset_create_cmd_v6",
                        "_pk_recent_name", "_pk_recent_name_v6",
                        "_pk_validate"):
            self.assertTrue(callable(getattr(pk, fn_name, None)),
                            f"missing: {fn_name}")

    def test_constants_exist(self):
        """Ключевые константы определены (IPv4 + IPv6)."""
        import chimera.modules.port_knocking as pk
        # IPv4
        self.assertEqual(pk._PK_KNOCKED_SET, "xray_knocked")
        self.assertEqual(pk._PK_MANUAL_BAN_SET, "xray_manual_ban")
        self.assertEqual(pk._PK_WL_SET, "clients_wl")
        # IPv6 (new)
        self.assertEqual(pk._PK_KNOCKED_SET_V6, "xray_knocked6")
        self.assertEqual(pk._PK_MANUAL_BAN_SET_V6, "xray_manual_ban6")
        # Shared
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
