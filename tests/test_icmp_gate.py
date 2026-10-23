#!/usr/bin/env python3
"""
tests/test_icmp_gate.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/icmp_gate.py.

Покрывает:
  1. state — дефолты, load/save, мерж полей
  2. валидация — role/mode, кривые IP, /0-запрет, PMTUD-критичные
     drop_types запрещены, пустой drop_types
  3. семантика ролей — exit = admin+peer, entry = admin only,
     нормализация в CIDR + дедуп
  4. построители правил — v4 (allow→drop, теги), v6 (allow+echo-drop)
  5. raw install — clean-before-install, порядок (allow выше drop),
     persist в rules.v4/v6
  6. raw remove — вырезка по тегу
  7. ufw — блок перед сток-строкой, идемпотентность (один блок),
     remove возвращает сток-вид, before6, бэкап
  8. детект режима — raw-теги в INPUT → raw; чистый INPUT + before.rules → ufw
  9. check/apply — машинная проверка, headless-apply с overrides
Все вызовы iptables/ip6tables/ufw — mock'd через _fake_run.
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

from chimera.modules import icmp_gate as ig  # noqa: E402


def _cp(cmd, rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(list(cmd), rc, stdout, stderr)


STOCK_BEFORE = """# comments up top
*filter
:ufw-before-input - [0:0]
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT
-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT
COMMIT
"""

STOCK_BEFORE6 = """# comments
*filter
:ufw6-before-input - [0:0]
-A ufw6-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw6-before-input -p icmpv6 --icmpv6-type echo-request -j ACCEPT
COMMIT
"""


class _IGBase(unittest.TestCase):
    """База: tmp-пути, fake iptables/ip6tables/ufw/iptables-save."""

    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.state_file = tmp / "icmp_gate.json"
        self.before = tmp / "before.rules"
        self.before6 = tmp / "before6.rules"
        self.rules_v4 = tmp / "rules.v4"
        self.rules_v6 = tmp / "rules.v6"
        self.before.write_text(STOCK_BEFORE)
        self.before6.write_text(STOCK_BEFORE6)

        # симулируемое состояние таблиц
        self._ipt: list[str] = []    # v4 spec strings
        self._ipt6: list[str] = []   # v6 spec strings
        self._calls: list[list] = []

        self._patches = [
            patch.object(ig, "IG_STATE_FILE", self.state_file),
            patch.object(ig, "IG_BEFORE_RULES", self.before),
            patch.object(ig, "IG_BEFORE6_RULES", self.before6),
            patch.object(ig, "IG_RULES_V4", self.rules_v4),
            patch.object(ig, "IG_RULES_V6", self.rules_v6),
            patch.object(ig, "_run", self._fake_run),
            patch.object(ig, "_tg_notify_event"),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    # ── fake netfilter ────────────────────────────────────────────────────
    def _table_state(self, binary):
        return self._ipt if binary == "iptables" else self._ipt6

    def _fake_run(self, cmd, capture=False, quiet=False, timeout=30):
        cmd = list(cmd)
        self._calls.append(cmd)
        binary = cmd[0]
        if binary in ("iptables", "ip6tables"):
            state = self._table_state(binary)
            if cmd[1] == "-S":
                return _cp(cmd, 0, "".join(f"-A INPUT {s}\n" for s in state))
            if cmd[1] == "-L":
                out = "".join(f"{i+1:5d} ... {s} comments: {self._comment_of(s)}\n"
                              for i, s in enumerate(state))
                return _cp(cmd, 0, out)
            if cmd[1] == "-I":
                state.insert(0, " ".join(cmd[4:]))
                return _cp(cmd)
            if cmd[1] == "-D":
                n = int(cmd[3])
                if 1 <= n <= len(state):
                    state.pop(n - 1)
                    return _cp(cmd)
                return _cp(cmd, 1)
            if cmd[1] == "-C":
                spec = " ".join(cmd[3:])
                return _cp(cmd, 0 if spec in state else 1)
        if binary in ("iptables-save", "ip6tables-save"):
            state = self._table_state(binary.replace("-save", ""))
            return _cp(cmd, 0,
                       "*filter\n" + "".join(f"-A INPUT {s}\n" for s in state)
                       + "COMMIT\n")
        if binary == "ufw":
            return _cp(cmd)
        return _cp(cmd)

    @staticmethod
    def _comment_of(spec: str) -> str:
        return (ig.IG_COMMENT_TAG if ig.IG_COMMENT_TAG in spec
                else "none")


class TestState(_IGBase):
    def test_defaults(self):
        st = ig._ig_state_load()
        self.assertFalse(st["enabled"])
        self.assertEqual(st["role"], "exit")
        self.assertEqual(st["mode"], "auto")
        self.assertEqual(st["drop_types"],
                         ["echo-request", "timestamp-request",
                          "address-mask-request"])
        self.assertTrue(st["drop_v6"])

    def test_save_merge(self):
        st = ig._ig_default_state()
        st["admin_ips"] = ["198.51.100.10"]
        ig._ig_state_save(st)
        loaded = ig._ig_state_load()
        self.assertEqual(loaded["admin_ips"], ["198.51.100.10"])
        # новые поля будущих версий добираются дефолтами
        raw = json.loads(self.state_file.read_text())
        raw.pop("drop_v6")
        self.state_file.write_text(json.dumps(raw))
        self.assertTrue(ig._ig_state_load()["drop_v6"])


class TestValidation(_IGBase):
    def test_bad_role_mode(self):
        errs = ig._ig_validate({"role": "x", "mode": "auto"})
        self.assertTrue(any("role" in e for e in errs))
        errs = ig._ig_validate({"role": "exit", "mode": "x"})
        self.assertTrue(any("mode" in e for e in errs))

    def test_bad_ip_tokens(self):
        errs = ig._ig_validate({"role": "exit", "mode": "ufw",
                                "admin_ips": ["not-an-ip"]})
        self.assertTrue(any("admin_ips" in e for e in errs))
        errs = ig._ig_validate({"role": "exit", "mode": "ufw",
                                "admin_ips": ["0.0.0.0/0"]})
        self.assertTrue(any("весь интернет" in e for e in errs))

    def test_pmtud_types_forbidden(self):
        for t in ("destination-unreachable", "time-exceeded",
                  "parameter-problem", "any"):
            errs = ig._ig_validate({"role": "exit", "mode": "ufw",
                                    "drop_types": [t]})
            self.assertTrue(any("запрещён" in e for e in errs), t)

    def test_unknown_drop_type(self):
        errs = ig._ig_validate({"role": "exit", "mode": "ufw",
                                "drop_types": ["echo-reply"]})
        self.assertTrue(any("неизвестный тип" in e for e in errs))

    def test_empty_drop_types(self):
        errs = ig._ig_validate({"role": "exit", "mode": "ufw",
                                "drop_types": []})
        self.assertTrue(any("drop_types" in e for e in errs))


class TestRoles(_IGBase):
    def test_exit_admin_plus_peer(self):
        st = ig._ig_default_state()
        st.update({"role": "exit", "admin_ips": ["198.51.100.10"],
                   "peer_ips": ["203.0.113.20", "203.0.113.20"]})
        self.assertEqual(ig._ig_allowed_sources(st),
                         ["198.51.100.10/32", "203.0.113.20/32"])

    def test_entry_admin_only(self):
        st = ig._ig_default_state()
        st.update({"role": "entry", "admin_ips": ["198.51.100.10"],
                   "peer_ips": ["203.0.113.20"]})
        self.assertEqual(ig._ig_allowed_sources(st), ["198.51.100.10/32"])

    def test_v6_normalization(self):
        st = ig._ig_default_state()
        st.update({"role": "exit", "admin_ips": ["2001:db8::1"],
                   "peer_ips": ["2001:db8:aa::/48"]})
        self.assertEqual(ig._ig_allowed_sources(st),
                         ["2001:db8::1/128", "2001:db8:aa::/48"])


class TestBuilders(_IGBase):
    def _state(self, **kw):
        st = ig._ig_default_state()
        st.update({"role": "exit", "admin_ips": ["198.51.100.10"],
                   "peer_ips": ["2001:db8::7"]})
        st.update(kw)
        return st

    def test_v4_structure_order(self):
        rules = ig._ig_build_raw_rules_v4(self._state())
        allows = [r for r in rules if r[-1] == "ACCEPT"]
        drops = [r for r in rules if r[-1] == "DROP"]
        # v4-allow только от v4-источника; v6-источник уходит в v6-набор
        self.assertEqual(len(allows), 1)
        self.assertEqual(allows[0][1], "198.51.100.10/32")
        # 3 дефолтных дропа: echo/timestamp/mask
        self.assertEqual(len(drops), 3)
        types = [d[d.index("--icmp-type") + 1] for d in drops]
        self.assertEqual(types, ["echo-request", "timestamp-request",
                                 "address-mask-request"])
        # порядок: allow выше drop
        self.assertTrue(rules[0][-1] == "ACCEPT"
                        and rules[-1][-1] == "DROP")
        # тег на каждом правиле (в элементе вида 'chimera-icmp-gate:allow')
        for r in rules:
            self.assertTrue(any(ig.IG_COMMENT_TAG in p for p in r), r)

    def test_v6_structure(self):
        rules = ig._ig_build_raw_rules_v6(self._state())
        allows = [r for r in rules if r[-1] == "ACCEPT"]
        drops = [r for r in rules if r[-1] == "DROP"]
        self.assertEqual(len(allows), 1)          # 2001:db8::7/128
        self.assertEqual(len(drops), 1)           # echo-request
        self.assertIn("--icmpv6-type", drops[0])

    def test_drop_v6_off(self):
        st = self._state(drop_v6=False)
        self.assertEqual(ig._ig_build_raw_rules_v6(st),
                         [ig._ig_build_raw_rules_v6(st)[0]])  # только allow


class TestRawInstall(_IGBase):
    def test_install_order_and_tags(self):
        st = ig._ig_default_state()
        st.update({"role": "exit", "admin_ips": ["198.51.100.10"],
                   "peer_ips": ["203.0.113.20"], "mode": "raw"})
        self.assertTrue(ig._ig_install_raw(st))
        # порядок в INPUT: 2 allow сверху, затем 3 drop
        self.assertEqual(len(self._ipt), 5)
        self.assertEqual([r.split()[1] for r in self._ipt[:2]],
                         ["198.51.100.10/32", "203.0.113.20/32"])
        self.assertTrue(all("DROP" in r for r in self._ipt[2:]))
        self.assertTrue(all(ig.IG_COMMENT_TAG in r for r in self._ipt))

    def test_clean_before_install(self):
        # протухшее tagged-правило от прошлой конфигурации
        self._ipt.append("-s 192.0.2.99/32 -p icmp -m comment "
                         "--comment chimera-icmp-gate:allow -j ACCEPT")
        self._ipt.append("-p icmp --icmp-type echo-request -m comment "
                         "--comment chimera-icmp-gate:drop -j DROP")
        st = ig._ig_default_state()
        st.update({"role": "entry", "admin_ips": ["198.51.100.10"],
                   "mode": "raw"})
        self.assertTrue(ig._ig_install_raw(st))
        self.assertEqual(len(self._ipt), 4)  # 1 allow + 3 drop
        self.assertFalse(any("192.0.2.99" in r for r in self._ipt))
        # persist задампил свежее состояние
        self.assertIn("198.51.100.10/32", self.rules_v4.read_text())

    def test_remove(self):
        st = ig._ig_default_state()
        st.update({"role": "exit", "admin_ips": ["198.51.100.10"],
                   "mode": "raw"})
        ig._ig_install_raw(st)
        self.assertTrue(ig._ig_remove_raw())
        self.assertEqual(self._ipt, [])
        self.assertEqual(self._ipt6, [])


class TestUfw(_IGBase):
    def test_block_before_stock(self):
        st = ig._ig_default_state()
        st.update({"role": "exit", "admin_ips": ["198.51.100.10"],
                   "mode": "ufw"})
        self.assertTrue(ig._ig_install_ufw(st))
        text = self.before.read_text()
        self.assertIn(ig.IG_BLOCK_BEGIN, text)
        # блок стоит ДО сток-строки echo-request
        self.assertLess(text.index(ig.IG_BLOCK_BEGIN),
                        text.index("-p icmp --icmp-type echo-request -j ACCEPT"))
        # сток-строка и PMTUD-строки не тронуты
        self.assertIn("--icmp-type destination-unreachable -j ACCEPT", text)
        self.assertIn("--icmp-type time-exceeded -j ACCEPT", text)
        # before6 получил блок с icmpv6-drop (тег + тип + вердикт)
        text6 = self.before6.read_text()
        self.assertIn("chimera-icmp-gate:drop6", text6)
        self.assertIn("-p icmpv6 --icmpv6-type echo-request", text6)
        self.assertIn("-j DROP", text6)
        # бэкапы стока созданы
        self.assertTrue(self.before.with_name("before.rules.bak-icmp-gate").exists())

    def test_idempotent_reapply(self):
        st = ig._ig_default_state()
        st.update({"role": "exit", "admin_ips": ["198.51.100.10"],
                   "mode": "ufw"})
        ig._ig_install_ufw(st)
        ig._ig_install_ufw(st)
        text = self.before.read_text()
        self.assertEqual(text.count(ig.IG_BLOCK_BEGIN), 1)
        self.assertEqual(text.count(ig.IG_BLOCK_END), 1)

    def test_remove_restores_stock(self):
        st = ig._ig_default_state()
        st.update({"role": "exit", "admin_ips": ["198.51.100.10"],
                   "mode": "ufw"})
        ig._ig_install_ufw(st)
        self.assertTrue(ig._ig_remove_ufw())
        self.assertEqual(self.before.read_text(), STOCK_BEFORE)
        self.assertEqual(self.before6.read_text(), STOCK_BEFORE6)

    def test_v6_admin_goes_to_before6_only(self):
        st = ig._ig_default_state()
        st.update({"role": "exit", "admin_ips": ["2001:db8::1"],
                   "mode": "ufw"})
        ig._ig_install_ufw(st)
        self.assertNotIn("2001:db8::1", self.before.read_text())
        self.assertIn("2001:db8::1/128", self.before6.read_text())


class TestModeDetect(_IGBase):
    def test_raw_when_chimera_stack(self):
        self._ipt.append("-p tcp --dport 443 -m set --match-set clients_wl_v4 "
                         "src -m comment --comment chimera-clients-wl -j ACCEPT")
        self.assertEqual(ig._ig_detect_mode(), "raw")

    def test_ufw_when_clean(self):
        self.assertEqual(ig._ig_detect_mode(), "ufw")

    def test_raw_fallback_no_before(self):
        with patch.object(ig, "IG_BEFORE_RULES", Path("/nonexistent/x")):
            self._ipt.append("-p tcp -j ACCEPT")
            self.assertEqual(ig._ig_detect_mode(), "raw")


class TestCheckApply(_IGBase):
    def test_apply_headless_raw(self):
        ok = ig.icmp_gate_apply({"role": "entry", "mode": "raw",
                                 "admin_ips": ["198.51.100.10"]})
        self.assertTrue(ok)
        chk = ig.icmp_gate_check()
        self.assertTrue(chk["ok"])
        self.assertEqual(chk["mode"], "raw")
        self.assertEqual(chk["raw_v4_rules"], 4)   # 1 allow + 3 drop
        self.assertEqual(chk["raw_v6_rules"], 1)   # echo-request v6
        st = ig._ig_state_load()
        self.assertTrue(st["enabled"])
        self.assertEqual(st["mode"], "raw")

    def test_apply_headless_ufw(self):
        ok = ig.icmp_gate_apply({"role": "exit", "mode": "ufw",
                                 "admin_ips": ["198.51.100.10"],
                                 "peer_ips": ["203.0.113.20"]})
        self.assertTrue(ok)
        chk = ig.icmp_gate_check()
        self.assertTrue(chk["ok"])
        self.assertTrue(chk["ufw_block_v4"])
        self.assertTrue(chk["ufw_block_v6"])
        self.assertEqual(chk["expected_allow"], 2)

    def test_apply_rejects_pmtud(self):
        ok = ig.icmp_gate_apply({"role": "exit", "mode": "ufw",
                                 "admin_ips": ["198.51.100.10"],
                                 "drop_types": ["time-exceeded"]})
        self.assertFalse(ok)
        self.assertFalse(ig._ig_state_load()["enabled"])

    def test_remove_after_apply(self):
        ig.icmp_gate_apply({"role": "exit", "mode": "ufw",
                            "admin_ips": ["198.51.100.10"]})
        self.assertTrue(ig.icmp_gate_remove())
        self.assertEqual(self.before.read_text(), STOCK_BEFORE)
        self.assertFalse(ig._ig_state_load()["enabled"])

    def test_status_smoke(self):
        ig.icmp_gate_apply({"role": "entry", "mode": "ufw",
                            "admin_ips": ["198.51.100.10"]})
        s = ig.icmp_gate_status()
        self.assertIn("ICMP Gate", s)
        self.assertIn("role=entry", s)


if __name__ == "__main__":
    unittest.main()
