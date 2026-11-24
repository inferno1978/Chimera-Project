#!/usr/bin/env python3
"""
tests/test_rkn_guard.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/rkn_guard.py — UFW-jump авторековери.

Кейс <blw> 24.11: после `ufw reload` verify бинарника требует, чтобы
`-A ufw-before-input -j SCANNERS-BLOCK` был ПЕРВЫМ -A-правилом живой
цепочки. Если внешняя система (антидос/телеметрия хостера) успевает
вставить своё правило в начало цепочки — full/update падает
«SCANNERS-BLOCK is not the first rule». Обёртка _rg_cli_mutate_ufw_safe
диагностирует, переставляет jump на 1-е место (_rg_repair_ufw_jump) и
повторяет операцию один раз (fast-path бинарника, без reload).

Покрывает:
  1. _rg_ufw_first_rule — нет цепочки (None) / пустая ('') / первое -A
     (строки -N/-P пропускаются, как в verify бинарника)
  2. _rg_ufw_jump_conflicts — норма / чужое первым / отсутствующее
     семейство не конфликт / отсутствующий jump
  3. _rg_repair_ufw_jump — перестановка с дедупом дублей jump,
     без мутаций когда всё ок, v6-off, без нашей цепочки → False
  4. _rg_cli_mutate_ufw_safe — успех без повтора / повтор после
     рековери / чужая ошибка без повтора / рековери не смог /
     повтор тоже упал
Все вызовы iptables/ip6tables — mock'd через фейковые таблицы.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import rkn_guard as rg  # noqa: E402


def _cp(cmd, rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(list(cmd), rc, stdout, stderr)


JUMP4 = "-j SCANNERS-BLOCK"
UFW4 = "ufw-before-input"
UFW6 = "ufw6-before-input"


class _FakeTables:
    """Минимальный симулятор filter-таблиц iptables/ip6tables.

    table: {binary: {chain: [spec, ...]}}; spec — хвост правила после
    `-A <chain> `. Несуществующая цепочка: -S/-D → rc=1 (как живой
    iptables «No chain/target/match by that name»).
    """

    def __init__(self, v4=None, v6=None):
        self.tables = {"iptables": dict(v4 or {}),
                       "ip6tables": dict(v6 or {})}
        self.calls: list[list] = []

    def run(self, cmd, capture=False, quiet=False, timeout=120):
        cmd = list(cmd)
        self.calls.append(cmd)
        binary = cmd[0]
        if binary not in ("iptables", "ip6tables"):
            return _cp(cmd)
        args = cmd[1:]
        if args and args[0] == "-w":
            args = args[1:]
        tbl = self.tables[binary]
        op = args[0] if args else ""
        if op == "-S":
            chain = args[1] if len(args) > 1 else ""
            if chain not in tbl:
                return _cp(cmd, 1, "",
                           "iptables: No chain/target/match by that name.")
            return _cp(cmd, 0, "".join(f"-A {chain} {s}\n"
                                       for s in tbl[chain]))
        if op == "-D":
            chain, spec = args[1], " ".join(args[2:])
            rules = tbl.get(chain)
            if rules is None or spec not in rules:
                return _cp(cmd, 1, "", "iptables: Bad rule (does a "
                                       "matching rule exist in that chain?).")
            rules.remove(spec)
            return _cp(cmd)
        if op == "-I":
            chain, pos, spec = args[1], int(args[2]), " ".join(args[3:])
            tbl.setdefault(chain, []).insert(pos - 1, spec)
            return _cp(cmd)
        return _cp(cmd, 1, "", f"fake: unsupported {args[:2]}")


class _RGBase(unittest.TestCase):
    """База: tmp-пути, фейковые таблицы, подавленный stdout."""

    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.tables = _FakeTables()
        self._patches = [
            patch.object(rg, "RG_LOG_FILE", tmp / "chimera.log"),
            patch.object(rg, "IPSET_CONF", tmp / "ipset.conf"),
            patch.object(rg, "_run", self.tables.run),
            patch.object(rg, "_tg_notify_event"),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])
        self._out = io.StringIO()
        cm = redirect_stdout(self._out)
        cm.__enter__()
        self.addCleanup(lambda: cm.__exit__(None, None, None))


class TestUfwFirstRule(_RGBase):
    def test_missing_chain(self):
        self.assertIsNone(rg._rg_ufw_first_rule("iptables", UFW4))

    def test_empty_chain(self):
        self.tables.tables["iptables"][UFW4] = []
        self.assertEqual(rg._rg_ufw_first_rule("iptables", UFW4), "")

    def test_first_a_rule_skips_declarations(self):
        # как iptables-save/-S: -N/-P не считаются правилами
        self.tables.tables["iptables"][UFW4] = ["-i lo -j ACCEPT",
                                                JUMP4]
        self.assertEqual(rg._rg_ufw_first_rule("iptables", UFW4),
                         f"-A {UFW4} -i lo -j ACCEPT")


class TestUfwJumpConflicts(_RGBase):
    def test_all_ok(self):
        self.tables.tables["iptables"][UFW4] = [JUMP4, "-i lo -j ACCEPT"]
        self.tables.tables["ip6tables"][UFW6] = [JUMP4]
        self.assertEqual(rg._rg_ufw_jump_conflicts(), [])

    def test_foreign_first_is_conflict(self):
        self.tables.tables["iptables"][UFW4] = [
            "-s 203.0.113.0/24 -j DROP", JUMP4]
        self.assertEqual(rg._rg_ufw_jump_conflicts(),
                         [("iptables", UFW4,
                           f"-A {UFW4} -s 203.0.113.0/24 -j DROP")])

    def test_missing_family_is_not_conflict(self):
        # v6-off нода: ufw6-before-input не существует
        self.tables.tables["iptables"][UFW4] = [JUMP4]
        self.assertEqual(rg._rg_ufw_jump_conflicts(), [])

    def test_missing_jump_is_conflict(self):
        # цепочка есть, jump нет (как после неудачного reload)
        self.tables.tables["iptables"][UFW4] = ["-i lo -j ACCEPT"]
        self.assertEqual(rg._rg_ufw_jump_conflicts(),
                         [("iptables", UFW4,
                           f"-A {UFW4} -i lo -j ACCEPT")])

    def test_empty_chain_is_conflict(self):
        self.tables.tables["iptables"][UFW4] = []
        self.assertEqual(rg._rg_ufw_jump_conflicts(),
                         [("iptables", UFW4, "")])


class TestRepairUfwJump(_RGBase):
    def _mk(self, v4, v6=None):
        self.tables.tables["iptables"][UFW4] = list(v4)
        self.tables.tables["iptables"]["SCANNERS-BLOCK"] = [
            "-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN"]
        if v6 is not None:
            self.tables.tables["ip6tables"][UFW6] = list(v6)
            self.tables.tables["ip6tables"]["SCANNERS-BLOCK"] = [
                "-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN"]

    def test_moves_jump_to_first(self):
        self._mk(["-s 203.0.113.0/24 -j DROP", JUMP4])
        self.assertTrue(rg._rg_repair_ufw_jump())
        self.assertEqual(self.tables.tables["iptables"][UFW4],
                         [JUMP4, "-s 203.0.113.0/24 -j DROP"])

    def test_dedupes_jump_copies(self):
        self._mk(["-s 198.51.100.0/24 -j DROP", JUMP4, JUMP4])
        self.assertTrue(rg._rg_repair_ufw_jump())
        # дубли сняты, единственный jump — первым, чужое не тронуто
        self.assertEqual(self.tables.tables["iptables"][UFW4],
                         [JUMP4, "-s 198.51.100.0/24 -j DROP"])

    def test_inserts_jump_when_missing(self):
        self._mk(["-i lo -j ACCEPT"])
        self.assertTrue(rg._rg_repair_ufw_jump())
        self.assertEqual(self.tables.tables["iptables"][UFW4],
                         [JUMP4, "-i lo -j ACCEPT"])

    def test_both_families(self):
        self._mk(["-x -j DROP", JUMP4], ["-y -j DROP"])
        self.assertTrue(rg._rg_repair_ufw_jump())
        self.assertEqual(self.tables.tables["ip6tables"][UFW6],
                         [JUMP4, "-y -j DROP"])

    def test_v6_off_only_v4(self):
        self._mk(["-s 203.0.113.0/24 -j DROP", JUMP4])  # v6-семейства нет
        self.assertTrue(rg._rg_repair_ufw_jump())
        self.assertNotIn(UFW6, self.tables.tables["ip6tables"])

    def test_empty_v6_family_gets_jump(self):
        # ufw6-before-input существует, но пуста — jump должен появиться
        self._mk(["-s 203.0.113.0/24 -j DROP", JUMP4], v6=[])
        self.assertTrue(rg._rg_repair_ufw_jump())
        self.assertEqual(self.tables.tables["ip6tables"][UFW6], [JUMP4])

    def test_no_mutation_when_already_ok(self):
        self._mk([JUMP4, "-i lo -j ACCEPT"])
        self.assertTrue(rg._rg_repair_ufw_jump())
        self.assertFalse([c for c in self.tables.calls
                          if "-D" in c or "-I" in c])

    def test_false_when_our_chain_absent(self):
        # SCANNERS-BLOCK не создан (full упал раньше) — ремонт невозможен
        self.tables.tables["iptables"][UFW4] = ["-i lo -j ACCEPT"]
        self.assertFalse(rg._rg_repair_ufw_jump())
        # чужое правило не тронуто
        self.assertEqual(self.tables.tables["iptables"][UFW4],
                         ["-i lo -j ACCEPT"])


class TestCliMutateUfwSafe(_RGBase):
    """Обёртка: падение first-rule → диагностика → ремонт → один повтор."""

    def _patch_mutate(self, results):
        """results — список CompletedProcess для _rg_cli_mutate."""
        calls = []

        def fake_mutate(args, timeout=900, label=""):
            calls.append(list(args))
            return results[len(calls) - 1]

        p = patch.object(rg, "_rg_cli_mutate", side_effect=fake_mutate)
        p.start()
        self.addCleanup(p.stop)
        return calls

    @staticmethod
    def _fail_first_rule():
        return _cp(["rkn-guard"], 1, (
            '2026-11-24T04:18:08Z INF Сохранение правил iptables\n'
            '2026-11-24T04:18:08Z INF UFW обнаружен - интеграция с UFW\n'
            '2026-11-24T04:18:08Z INF Обновлён UFW before.rules для IPv4\n'
            '2026-11-24T04:18:08Z FTL Не удалось сохранить правила iptables '
            'error="ufw-before-input: SCANNERS-BLOCK is not the first rule"'),
            "")

    def test_success_first_try_no_retry(self):
        calls = self._patch_mutate([_cp(["rkn-guard"], 0, "ok", "")])
        r = rg._rg_cli_mutate_ufw_safe(["full"], label="test")
        self.assertEqual((r.returncode, len(calls)), (0, 1))

    def test_first_rule_fail_retry_success(self):
        calls = self._patch_mutate(
            [self._fail_first_rule(), _cp(["rkn-guard"], 0, "ok", "")])
        # живая цепочка: чужое правило перед jump (сценарий юзера)
        self.tables.tables["iptables"][UFW4] = [
            "-s 203.0.113.0/24 -j DROP", JUMP4]
        self.tables.tables["iptables"]["SCANNERS-BLOCK"] = [
            "-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN"]
        r = rg._rg_cli_mutate_ufw_safe(["full"], label="test")
        self.assertEqual((r.returncode, len(calls)), (0, 2))
        # jump переставлен первым
        self.assertEqual(self.tables.tables["iptables"][UFW4],
                         [JUMP4, "-s 203.0.113.0/24 -j DROP"])
        # в логе — диагностика конфликта
        self.assertIn("первым стоит", self._out.getvalue())

    def test_other_error_no_retry(self):
        calls = self._patch_mutate([
            _cp(["rkn-guard"], 1, "", "network unreachable")])
        r = rg._rg_cli_mutate_ufw_safe(["full"])
        self.assertEqual((r.returncode, len(calls)), (1, 1))

    def test_repair_impossible_no_retry(self):
        calls = self._patch_mutate([self._fail_first_rule()])
        # нашей цепочки нет — ремонт невозможен, повтор не делаем
        self.tables.tables["iptables"][UFW4] = ["-i lo -j ACCEPT"]
        r = rg._rg_cli_mutate_ufw_safe(["full"])
        self.assertEqual((r.returncode, len(calls)), (1, 1))
        self.assertIn("не удалось", self._out.getvalue().lower())

    def test_retry_also_fails_returns_last(self):
        calls = self._patch_mutate(
            [self._fail_first_rule(), self._fail_first_rule()])
        self.tables.tables["iptables"][UFW4] = [
            "-s 203.0.113.0/24 -j DROP", JUMP4]
        self.tables.tables["iptables"]["SCANNERS-BLOCK"] = [
            "-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN"]
        # конфликт воспроизводится: чужое правило возвращается на 1-е место
        orig_run = self.tables.run

        def run(cmd, **kw):
            r = orig_run(cmd, **kw)
            cmd_l = list(cmd)
            if (cmd_l[:2] == ["iptables", "-I"] and UFW4 in cmd_l
                    and JUMP4 in " ".join(cmd_l)):
                self.tables.tables["iptables"][UFW4].insert(
                    0, "-s 203.0.113.0/24 -j DROP")
            return r

        self._patches.append(patch.object(rg, "_run", run))
        self._patches[-1].start()
        r = rg._rg_cli_mutate_ufw_safe(["full"])
        self.assertEqual((r.returncode, len(calls)), (1, 2))
        self.assertIn("постоянный конфликт", self._out.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
