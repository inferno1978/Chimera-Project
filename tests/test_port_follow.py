#!/usr/bin/env python3
"""
tests/test_port_follow.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты (port-follow): зависимые модули следуют за портом Xray при его
смене (reconfigure [R] / полная переустановка).

Кейс (RU-1, окт.2026): юзер перевёл xray 9443 → 443 через [R]. Ingress-блок
РФ переехал сам (ingress_geoip_follow_port), а port hopping и port knocking
— нет: NAT REDIRECT 10000:20000 продолжал смотреть на мёртвый 9443,
port_knocking.json остался ports=[9443] (при том что живых цепочек
вообще не было) — 443 остался без knocking-защиты.

Покрывает:
  1. ph_follow_port (port_hopping): выключен/тот же порт/нет real_port →
     False; happy path → _enable_hopping(rs, re, new_port, proto);
     конфликт «порт внутри диапазона» → disable + False; интеграционный
     тест с реальным _enable_hopping (fake iptables): NAT-правило
     пересоздаётся --to-port 443, state real_port=443.
  2. pk_follow_port (port_knocking): выключен/тот же порт/old не в списке
     → False (state не тронут); happy path → ports=[443], правила на 443
     (INSERT 3 + APPEND 3, recent KNOCK443), ufw delete allow 443;
     критичный порядок: ufw allow 9443 (мёртвый порт) НЕ вызывается —
     state сохраняется ДО _pk_install; дедупликация; порты других
     сервисов сохраняются; install упал → False + enabled=False.
  3. Вайринг (source-invariants, паттерн test_bootstrap_mirrors):
     reconfigure.py импортирует/вызывает оба хука, старый WARN «проверьте
     port hopping вручную» удалён; _core._release_prev_vless_port зовёт
     оба хука (полная переустановка со сменой порта).

Все вызовы iptables/ip6tables/ipset/ufw — mock'd. Реальных сетевых
операций нет.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
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


# ──────────────────────────────────────────────────────────────────────────────
#  ph_follow_port — логика (recorder-моки _enable/_disable)
# ──────────────────────────────────────────────────────────────────────────────
class TestPhFollowPortLogic(unittest.TestCase):
    """Логика принятия решения ph_follow_port (без реальных iptables)."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._ph = self._tmpdir / "port_hopping.json"
        self._enabled_calls: list[tuple] = []
        self._disabled_calls: list[int] = []
        self._patches = [
            patch("chimera.modules.port_hopping._PH_FILE", self._ph),
            patch("chimera.modules.port_hopping._enable_hopping",
                  self._rec_enable),
            patch("chimera.modules.port_hopping._disable_hopping",
                  self._rec_disable),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for p in self._patches:
            p.stop()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _rec_enable(self, rs, re_, rp, proto):
        self._enabled_calls.append((rs, re_, rp, proto))
        # пишем state как настоящий _enable_hopping
        from chimera.modules.port_hopping import _save_ph
        _save_ph({"enabled": True, "real_port": rp, "range_start": rs,
                  "range_end": re_, "proto": proto})
        return True

    def _rec_disable(self):
        self._disabled_calls.append(1)
        from chimera.modules.port_hopping import _save_ph
        _save_ph({"enabled": False})
        return True

    def _write_ph(self, cfg: dict):
        self._ph.write_text(json.dumps(cfg))

    def test_disabled_returns_false(self):
        from chimera.modules.port_hopping import ph_follow_port
        self._write_ph({"enabled": False})
        self.assertFalse(ph_follow_port(443))
        self.assertEqual(self._enabled_calls, [])
        self.assertEqual(self._disabled_calls, [])

    def test_same_port_returns_false(self):
        from chimera.modules.port_hopping import ph_follow_port
        self._write_ph({"enabled": True, "real_port": 443,
                        "range_start": 10000, "range_end": 20000,
                        "proto": "tcp"})
        self.assertFalse(ph_follow_port(443))
        self.assertEqual(self._enabled_calls, [])
        self.assertEqual(self._disabled_calls, [])

    def test_missing_fields_returns_false(self):
        from chimera.modules.port_hopping import ph_follow_port
        # enabled, но нет real_port/диапазона (битый state)
        self._write_ph({"enabled": True})
        self.assertFalse(ph_follow_port(443))
        # диапазон есть, real_port нет
        self._write_ph({"enabled": True, "range_start": 10000,
                        "range_end": 20000})
        self.assertFalse(ph_follow_port(443))
        self.assertEqual(self._enabled_calls, [])

    def test_happy_path_reapplies_with_new_port(self):
        from chimera.modules.port_hopping import ph_follow_port
        self._write_ph({"enabled": True, "real_port": 9443,
                        "range_start": 10000, "range_end": 20000,
                        "proto": "tcp"})
        self.assertTrue(ph_follow_port(443))
        # _enable_hopping вызван с тем же диапазоном, но новым real_port
        self.assertEqual(self._enabled_calls, [(10000, 20000, 443, "tcp")])
        self.assertEqual(self._disabled_calls, [])
        # state обновлён
        st = json.loads(self._ph.read_text())
        self.assertEqual(st["real_port"], 443)

    def test_range_conflict_disables_hopping(self):
        from chimera.modules.port_hopping import ph_follow_port
        # новый порт попадает в диапазон 10000-20000 → disable, не enable
        self._write_ph({"enabled": True, "real_port": 9443,
                        "range_start": 10000, "range_end": 20000,
                        "proto": "tcp"})
        self.assertFalse(ph_follow_port(15000))
        self.assertEqual(self._enabled_calls, [])
        self.assertEqual(len(self._disabled_calls), 1)
        st = json.loads(self._ph.read_text())
        self.assertFalse(st.get("enabled"))


# ──────────────────────────────────────────────────────────────────────────────
#  ph_follow_port — интеграция с реальным _enable_hopping (fake iptables)
# ──────────────────────────────────────────────────────────────────────────────
class TestPhFollowPortIntegration(unittest.TestCase):
    """Реальный _enable_hopping под fake iptables: NAT-правило пересоздаётся."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._ph = self._tmpdir / "port_hopping.json"
        # живое «правило» в nat PREROUTING: REDIRECT на мёртвый 9443
        self._nat_rules: list[str] = [
            "-p tcp --dport 10000:20000 -m comment --comment "
            "xray-port-hopping -j REDIRECT --to-port 9443"
        ]
        self._cmds: list[list] = []
        self._patches = [
            patch("chimera.modules.port_hopping._PH_FILE", self._ph),
            patch("chimera.modules.port_hopping._run", self._fake_run),
            patch("chimera.modules.port_hopping._ufw_active",
                  lambda: False),
            patch("chimera.modules.port_hopping._persist_iptables",
                  lambda: None),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for p in self._patches:
            p.stop()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _fake_run(self, cmd, capture=False, quiet=False):
        self._cmds.append(list(cmd))
        if cmd[:5] == ["iptables", "-t", "nat", "-L", "PREROUTING"]:
            out = "Chain PREROUTING (policy ACCEPT)\n" \
                  "num target prot opt source destination\n"
            for i, r in enumerate(self._nat_rules, 1):
                if "xray-port-hopping" in r:
                    out += f"{i} REDIRECT  tcp -- 0.0.0.0/0 0.0.0.0/0 {r}\n"
            return _cp(cmd, 0, out, "")
        # iptables -t nat -D PREROUTING <N>
        if cmd[:4] == ["iptables", "-t", "nat", "-D"]:
            n = int(cmd[5])
            if 1 <= n <= len(self._nat_rules):
                self._nat_rules.pop(n - 1)
            return _cp(cmd, 0, "", "")
        # iptables -t nat -A PREROUTING <spec...>
        if cmd[:4] == ["iptables", "-t", "nat", "-A"]:
            self._nat_rules.append(" ".join(str(c) for c in cmd[6:]))
            return _cp(cmd, 0, "", "")
        return _cp(cmd, 0, "", "")

    def test_nat_redirect_recreated_to_new_port(self):
        from chimera.modules.port_hopping import ph_follow_port
        self._ph.write_text(json.dumps({
            "enabled": True, "real_port": 9443,
            "range_start": 10000, "range_end": 20000, "proto": "tcp",
        }))
        self.assertTrue(ph_follow_port(443))
        # старое правило (на мёртвый 9443) удалено, новое — на 443
        joined = "\n".join(self._nat_rules)
        self.assertNotIn("--to-port 9443", joined)
        self.assertIn("--to-port 443", joined)
        self.assertIn("10000:20000", joined)
        # и команда реально отдавалась в iptables
        add_cmds = [c for c in self._cmds
                    if c[:4] == ["iptables", "-t", "nat", "-A"]]
        self.assertTrue(any("--to-port" in c and "443" in c for c in add_cmds))
        # state: real_port обновлён
        st = json.loads(self._ph.read_text())
        self.assertTrue(st["enabled"])
        self.assertEqual(st["real_port"], 443)


# ──────────────────────────────────────────────────────────────────────────────
#  pk_follow_port — полный harness (fake iptables/ip6tables/ipset/ufw)
# ──────────────────────────────────────────────────────────────────────────────
class _PkBase(unittest.TestCase):
    """База как в test_port_knocking._PortKnockingBase (компактная версия)."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "port_knocking.json"
        self._iptables_rules: list[str] = []
        self._ip6tables_rules: list[str] = []
        self._ufw_calls: list[list] = []
        self._ipset_fail_create = False
        self._ipset_exists = {
            "clients_wl_v4": True, "xray_manual_ban": True,
            "xray_manual_ban6": True,
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
        cmd = list(cmd)
        if not cmd:
            return _cp(cmd, 0, "", "")
        if cmd[0] in ("iptables", "ip6tables"):
            rules = (self._iptables_rules if cmd[0] == "iptables"
                     else self._ip6tables_rules)
            return self._fake_table_cmd(cmd, rules)
        if cmd[0] == "ipset":
            return self._fake_ipset_cmd(cmd)
        if cmd[0] == "ufw":
            self._ufw_calls.append(cmd)
            return _cp(cmd, 0, "", "")
        return _cp(cmd, 0, "", "")

    def _fake_table_cmd(self, cmd, rules):
        if cmd[1:3] == ["-C", "INPUT"]:
            spec = " ".join(str(c) for c in cmd[3:])
            for r in rules:
                if spec in r or r in spec:
                    return _cp(cmd, 0, "", "")
            return _cp(cmd, 1, "", "not found")
        if cmd[1:3] == ["-I", "INPUT"]:
            rules.append(" ".join(str(c) for c in cmd[4:]))
            return _cp(cmd, 0, "", "")
        if cmd[1:3] == ["-A", "INPUT"]:
            rules.append(" ".join(str(c) for c in cmd[3:]))
            return _cp(cmd, 0, "", "")
        if cmd[1:3] == ["-D", "INPUT"] and str(cmd[3]).isdigit():
            n = int(cmd[3])
            if 1 <= n <= len(rules):
                rules.pop(n - 1)
                return _cp(cmd, 0, "", "")
            return _cp(cmd, 1, "", "out of range")
        if cmd[1:3] == ["-L", "INPUT"]:
            out = "Chain INPUT (policy ACCEPT)\n" \
                  "num target prot opt source destination\n"
            for i, r in enumerate(rules, 1):
                out += f"{i} ACCEPT  --  0.0.0.0/0 0.0.0.0/0 {r}\n"
            return _cp(cmd, 0, out, "")
        if cmd[1:3] == ["-S", "INPUT"]:
            return _cp(cmd, 0, "\n".join("-A INPUT " + r for r in rules), "")
        return _cp(cmd, 0, "", "")

    def _fake_ipset_cmd(self, cmd):
        if cmd[1] == "create":
            if self._ipset_fail_create:
                return _cp(cmd, 1, "", "cannot create ipset")
            self._ipset_exists[cmd[2]] = True
            return _cp(cmd, 0, "", "")
        if cmd[1] == "list":
            if not self._ipset_exists.get(cmd[2], False):
                return _cp(cmd, 1, "", "set does not exist")
            return _cp(cmd, 0, f"Name: {cmd[2]}\nNumber of entries: 0\n", "")
        if cmd[1] == "destroy":
            self._ipset_exists.pop(cmd[2], None)
            return _cp(cmd, 0, "", "")
        return _cp(cmd, 0, "", "")

    def _write_pk(self, **cfg):
        base = {"enabled": True, "ports": [9443], "knock_count": 3,
                "knock_window_sec": 10, "whitelist_ttl_sec": 3600,
                "log_success": False, "installed_at": "2026-10-01T00:00:00Z"}
        base.update(cfg)
        self._state_file.write_text(json.dumps(base))


class TestPkFollowPort(_PkBase):

    def test_disabled_returns_false(self):
        from chimera.modules.port_knocking import pk_follow_port
        self._write_pk(enabled=False, ports=[9443])
        before = self._state_file.read_text()
        self.assertFalse(pk_follow_port(443, 9443))
        self.assertEqual(self._state_file.read_text(), before)  # не тронут
        self.assertEqual(self._iptables_rules, [])

    def test_same_port_returns_false(self):
        from chimera.modules.port_knocking import pk_follow_port
        self._write_pk(ports=[9443])
        self.assertFalse(pk_follow_port(9443, 9443))
        self.assertEqual(self._iptables_rules, [])

    def test_old_port_not_in_list_returns_false(self):
        from chimera.modules.port_knocking import pk_follow_port
        # knocking настроен на другие сервисы (853) — не трогаем
        self._write_pk(ports=[853])
        before = self._state_file.read_text()
        self.assertFalse(pk_follow_port(443, 9443))
        self.assertEqual(self._state_file.read_text(), before)
        self.assertEqual(self._iptables_rules, [])

    def test_happy_path_moves_knocking_to_new_port(self):
        from chimera.modules.port_knocking import pk_follow_port
        # до: цепочки на мёртвом 9443 (или вовсе отсутствуют — лечится так же)
        self._write_pk(ports=[9443])
        self._iptables_rules.append(
            "-p tcp --dport 9443 -m set --match-set xray_knocked src "
            "-j ACCEPT -m comment --comment chimera-port-knocking")

        self.assertTrue(pk_follow_port(443, 9443))

        # state: ports=[443], enabled
        st = json.loads(self._state_file.read_text())
        self.assertEqual(st["ports"], [443])
        self.assertTrue(st["enabled"])

        # правила на 443: 6 штук (3 INSERT + 3 APPEND), тег модуля
        v4 = "\n".join(self._iptables_rules)
        self.assertIn("--dport 443", v4)
        self.assertIn("KNOCK443", v4)                    # recent-таблица
        self.assertIn("--match-set xray_knocked src -j ACCEPT", v4)
        self.assertEqual(v4.count("--dport 443"), 6)
        # старых правил на 9443 не осталось
        self.assertNotIn("--dport 9443", v4)
        # ufw delete allow 443 (Bug 3 fix внутри install)
        self.assertTrue(any(
            c[:3] == ["ufw", "delete", "allow"] and "443/tcp" in c
            for c in self._ufw_calls))

    def test_dead_old_port_not_reopened_in_ufw(self):
        """Критичный порядок: state сохраняется ДО install → _pk_remove
        восстанавливает UFW только для НОВЫХ портов; мёртвый 9443,
        закрытый reconfigure, НЕ переоткрывается."""
        from chimera.modules.port_knocking import pk_follow_port
        self._write_pk(ports=[9443])
        self.assertTrue(pk_follow_port(443, 9443))
        allow_9443 = [c for c in self._ufw_calls
                      if c[:2] == ["ufw", "allow"] and "9443" in " ".join(c)]
        self.assertEqual(allow_9443, [],
                         "ufw allow 9443 не должен вызываться при переносе")

    def test_dedupe_when_new_port_already_in_list(self):
        from chimera.modules.port_knocking import pk_follow_port
        self._write_pk(ports=[443, 9443])
        self.assertTrue(pk_follow_port(443, 9443))
        st = json.loads(self._state_file.read_text())
        self.assertEqual(st["ports"], [443])  # без дубликата

    def test_other_service_ports_preserved(self):
        from chimera.modules.port_knocking import pk_follow_port
        self._write_pk(ports=[9443, 853])
        self.assertTrue(pk_follow_port(443, 9443))
        st = json.loads(self._state_file.read_text())
        self.assertEqual(st["ports"], [443, 853])
        v4 = "\n".join(self._iptables_rules)
        self.assertIn("--dport 853", v4)  # чужой порт защищён как раньше

    def test_install_failure_returns_false_honest_state(self):
        from chimera.modules.port_knocking import pk_follow_port
        self._write_pk(ports=[9443])
        self._ipset_fail_create = True  # install падает на ipset create
        self.assertFalse(pk_follow_port(443, 9443))
        # state честный: enabled=False (внутренний _pk_remove выключил),
        # ports уже перенесены — повторная попытка install поднимет на 443
        st = json.loads(self._state_file.read_text())
        self.assertFalse(st["enabled"])
        self.assertEqual(st["ports"], [443])


# ──────────────────────────────────────────────────────────────────────────────
#  Вайринг — source-invariants (паттерн test_bootstrap_mirrors)
# ──────────────────────────────────────────────────────────────────────────────
class TestWiringSourceInvariants(unittest.TestCase):
    """reconfigure/_core реально зовут хуки port-follow (не WARN)."""

    def _src(self, rel: str) -> str:
        return (_PROJECT_ROOT / rel).read_text(encoding="utf-8")

    def test_follow_hooks_importable(self):
        from chimera.modules.port_hopping import ph_follow_port  # noqa: F401
        from chimera.modules.port_knocking import pk_follow_port  # noqa: F401

    def test_reconfigure_calls_both_hooks(self):
        src = self._src("chimera/modules/reconfigure.py")
        self.assertIn("from chimera.modules.port_hopping import "
                      "ph_follow_port", src)
        self.assertIn("ph_follow_port(new_port)", src)
        self.assertIn("from chimera.modules.port_knocking import "
                      "pk_follow_port", src)
        self.assertIn("pk_follow_port(new_port, old_port)", src)

    def test_reconfigure_stale_manual_warn_gone(self):
        src = self._src("chimera/modules/reconfigure.py")
        # старый WARN «проверьте port hopping вручную» удалён
        self.assertNotIn("правила ссылаются", src)
        self.assertNotIn("проверьте \"\n                      \"port hopping",
                         src)

    def test_core_release_prev_vless_port_wires_hooks(self):
        """Полная переустановка со сменой порта — те же хуки."""
        src = self._src("chimera/_core.py")
        # тело _release_prev_vless_port (между def и следующим def)
        start = src.index("def _release_prev_vless_port")
        end = src.index("\ndef ", start + 10)
        body = src[start:end]
        self.assertIn("ph_follow_port(SERVER_PORT)", body)
        self.assertIn("pk_follow_port(SERVER_PORT, prev_port)", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
