#!/usr/bin/env python3
"""
tests/test_awg_net_common.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/awg_net_common.py.

Покрывает:
  1. iptables_ensure — идемпотентность (правило добавляется один раз
     даже при повторных вызовах с одинаковыми args).
  2. iptables_ensure — корректное преобразование -A → -C в check-вызове.
  3. iptables_ensure — безопасность: args без '-A' не вызывают _run
     (защита от случайного вызова с -D или -I).
  4. build_nat_rule_args — возвращает 3 правила с правильными аргументами.
  5. build_nat_idempotent_shell — содержит -C/-A пары для всех 3 правил.
  6. build_nat_cleanup_shell — содержит -D для всех 3 правил.
  7. build_sysctl_lines — НЕ содержит all/default rp_filter (точечно).
  8. build_sysctl_lines — содержит per-interface rp_filter=2 (loose mode).
  9. write_sysctl_conf — вычищает старые global all/default записи.
 10. apply_rp_filter_per_iface — НЕ трогает all/default (только awg0/WAN).

Запуск:
  cd <repo-root>
  python3 -m pytest tests/test_awg_net_common.py -v
  # или
  python3 tests/test_awg_net_common.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

# ── Подготовка пути для импорта ────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _make_mock_core():
    """
    Создаёт mock-объект core, который ведёт себя как chimera._core:
      • core._run(args, ...) — возвращает MagicMock с returncode/stdout/stderr
      • core.info / core.warn / core.log_to_file — no-op
    """
    core = MagicMock()
    core.info = MagicMock()
    core.warn = MagicMock()
    core.success = MagicMock()
    core.log_to_file = MagicMock()
    # _run по умолчанию возвращает returncode=0 (правило уже существует)
    core._run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
    return core


class TestIptablesEnsure(unittest.TestCase):
    """Тесты идемпотентности iptables_ensure (пункт 1 ревью)."""

    def test_rule_added_once_when_absent(self):
        """Правило добавляется один раз даже при двух вызовах."""
        from chimera.modules.awg_net_common import iptables_ensure

        core = _make_mock_core()
        # Первый вызов -C: returncode=1 (правила нет) → -A выполняется
        # Второй вызов -C: returncode=0 (правило уже есть) → -A НЕ выполняется
        check_absent = MagicMock(returncode=1, stdout="", stderr="")
        check_present = MagicMock(returncode=0, stdout="", stderr="")
        # 1-й вызов: check_absent, затем add (returncode irrelevant для add).
        # 2-й вызов: только check_present.
        core._run.side_effect = [check_absent, check_present, check_present]

        args = ["-t", "nat", "-A", "POSTROUTING", "-s", "10.66.66.0/24",
                "-o", "eth0", "-j", "MASQUERADE"]

        # Первый вызов: -C возвращает 1 → выполняется -A
        iptables_ensure(core, args)
        # Должно быть 2 вызова _run: check (-C) и add (-A)
        self.assertEqual(core._run.call_count, 2)
        first_call = core._run.call_args_list[0]
        self.assertEqual(first_call.args[0][0], "iptables")
        self.assertIn("-C", first_call.args[0])
        self.assertNotIn("-A", first_call.args[0])
        second_call = core._run.call_args_list[1]
        self.assertIn("-A", second_call.args[0])
        self.assertNotIn("-C", second_call.args[0])

        # Второй вызов: -C возвращает 0 → -A НЕ выполняется
        iptables_ensure(core, args)
        # +1 вызов (только -C, без -A) → итого 3
        self.assertEqual(core._run.call_count, 3)
        third_call = core._run.call_args_list[2]
        self.assertIn("-C", third_call.args[0])
        self.assertNotIn("-A", third_call.args[0])

    def test_check_args_converts_A_to_C(self):
        """-A корректно заменяется на -C в check-вызове, исходные args не мутируют."""
        from chimera.modules.awg_net_common import iptables_ensure

        core = _make_mock_core()
        # -C возвращает 0 (правило уже есть) → -A не вызывается
        core._run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        args = ["-A", "FORWARD", "-i", "awg0", "-j", "ACCEPT"]
        args_snapshot = list(args)  # копия для проверки неизменности
        iptables_ensure(core, args)

        # Первый вызов — check с -C вместо -A
        first_call = core._run.call_args_list[0]
        check_args = first_call.args[0]
        self.assertEqual(check_args[0], "iptables")
        self.assertIn("-C", check_args)
        self.assertNotIn("-A", check_args)
        # Исходные args не мутированы
        self.assertEqual(args, args_snapshot)

    def test_no_A_in_args_is_safe_noop(self):
        """Если в args нет '-A', функция не вызывает _run и пишет WARN."""
        from chimera.modules.awg_net_common import iptables_ensure

        core = _make_mock_core()
        # args с -D (не должно было сюда попасть, но защита от ошибок вызова)
        args = ["-D", "FORWARD", "-i", "awg0", "-j", "ACCEPT"]
        iptables_ensure(core, args)

        # _run не вызывается ни разу
        self.assertEqual(core._run.call_count, 0)
        # log_to_file вызван с WARN
        self.assertTrue(core.log_to_file.called)
        warn_args = core.log_to_file.call_args
        self.assertEqual(warn_args.args[0], "WARN")

    def test_idempotent_multiple_consecutive_calls(self):
        """10 последовательных вызовов с одинаковыми args: -A выполняется 1 раз."""
        from chimera.modules.awg_net_common import iptables_ensure

        core = _make_mock_core()
        # Симулируем: первый -C=1 (правила нет), все последующие -C=0 (правило есть)
        side_effects = []
        side_effects.append(MagicMock(returncode=1, stdout="", stderr=""))  # 1st check
        side_effects.append(MagicMock(returncode=0, stdout="", stderr=""))  # 1st add (returncode irrelevant)
        for _ in range(9):  # 9 последующих вызовов — только check, returncode=0
            side_effects.append(MagicMock(returncode=0, stdout="", stderr=""))
        core._run.side_effect = side_effects

        args = ["-A", "FORWARD", "-i", "awg0", "-j", "ACCEPT"]
        for _ in range(10):
            iptables_ensure(core, args)

        # 1-й вызов: 2 _run (check + add)
        # 2..10 вызовы: 1 _run (check only)
        # Итого: 2 + 9*1 = 11
        self.assertEqual(core._run.call_count, 11)


class TestBuildNatRuleArgs(unittest.TestCase):
    """Тесты генератора списка правил NAT."""

    def test_returns_three_rules(self):
        from chimera.modules.awg_net_common import build_nat_rule_args
        rules = build_nat_rule_args("10.66.66.0/24", "awg0", "eth0")
        self.assertEqual(len(rules), 3)
        for rule in rules:
            self.assertEqual(rule[0], "iptables")

    def test_masquerade_rule_correct(self):
        from chimera.modules.awg_net_common import build_nat_rule_args
        rules = build_nat_rule_args("10.66.66.0/24", "awg0", "eth0")
        masq = rules[0]
        self.assertEqual(masq, [
            "iptables", "-t", "nat", "-A", "POSTROUTING",
            "-s", "10.66.66.0/24", "-o", "eth0", "-j", "MASQUERADE",
        ])

    def test_forward_in_rule_correct(self):
        from chimera.modules.awg_net_common import build_nat_rule_args
        rules = build_nat_rule_args("10.66.66.0/24", "awg0", "eth0")
        fwd_in = rules[1]
        self.assertEqual(fwd_in, [
            "iptables", "-A", "FORWARD",
            "-i", "awg0", "-j", "ACCEPT",
        ])

    def test_forward_out_rule_correct(self):
        from chimera.modules.awg_net_common import build_nat_rule_args
        rules = build_nat_rule_args("10.66.66.0/24", "awg0", "eth0")
        fwd_out = rules[2]
        self.assertEqual(fwd_out, [
            "iptables", "-A", "FORWARD",
            "-o", "awg0", "-m", "state",
            "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT",
        ])


class TestBuildNatIdempotentShell(unittest.TestCase):
    """Тесты bash-сниппета для PostUp (с -C/-A парами)."""

    def test_contains_check_before_add_for_masquerade(self):
        from chimera.modules.awg_net_common import build_nat_idempotent_shell
        s = build_nat_idempotent_shell("10.66.66.0/24", "awg0", "$WAN")
        # Для MASQUERADE: -C ... || -A ...
        self.assertIn("iptables -t nat -C POSTROUTING -s 10.66.66.0/24 -o $WAN -j MASQUERADE", s)
        self.assertIn("iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o $WAN -j MASQUERADE", s)
        # -C должен идти ДО -A (лексический порядок)
        self.assertLess(s.index("-t nat -C POSTROUTING"), s.index("-t nat -A POSTROUTING"))

    def test_contains_check_for_forward_in(self):
        from chimera.modules.awg_net_common import build_nat_idempotent_shell
        s = build_nat_idempotent_shell("10.66.66.0/24", "awg0", "$WAN")
        self.assertIn("iptables -C FORWARD -i awg0 -j ACCEPT", s)
        self.assertIn("iptables -A FORWARD -i awg0 -j ACCEPT", s)

    def test_contains_check_for_forward_out(self):
        from chimera.modules.awg_net_common import build_nat_idempotent_shell
        s = build_nat_idempotent_shell("10.66.66.0/24", "awg0", "$WAN")
        self.assertIn("iptables -C FORWARD -o awg0 -m state --state ESTABLISHED,RELATED -j ACCEPT", s)
        self.assertIn("iptables -A FORWARD -o awg0 -m state --state ESTABLISHED,RELATED -j ACCEPT", s)


class TestBuildNatCleanupShell(unittest.TestCase):
    """Тесты bash-сниппета для PostDown (с -D)."""

    def test_contains_delete_for_all_three_rules(self):
        from chimera.modules.awg_net_common import build_nat_cleanup_shell
        s = build_nat_cleanup_shell("10.66.66.0/24", "awg0", "$WAN")
        self.assertIn("iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -o $WAN -j MASQUERADE", s)
        self.assertIn("iptables -D FORWARD -i awg0 -j ACCEPT", s)
        self.assertIn("iptables -D FORWARD -o awg0 -m state --state ESTABLISHED,RELATED -j ACCEPT", s)

    def test_all_deletes_have_silent_fallback(self):
        from chimera.modules.awg_net_common import build_nat_cleanup_shell
        s = build_nat_cleanup_shell("10.66.66.0/24", "awg0", "$WAN")
        # Каждое -D должно быть обёрнуто в 2>/dev/null || true (или || true)
        # для безопасного PostDown даже если правила уже нет.
        self.assertGreaterEqual(s.count("2>/dev/null"), 3)


class TestScopeSourceParam(unittest.TestCase):
    """Тесты параметра scope_source для v4 и v6 билдеров (после фикса 47f56d3)."""

    def test_v4_rule_args_scoped_has_source(self):
        """scope_source=True (default) → MASQUERADE содержит -s {subnet}."""
        from chimera.modules.awg_net_common import build_nat_rule_args
        rules = build_nat_rule_args("10.66.66.0/24", "awg0", "eth0", scope_source=True)
        masq = rules[0]
        self.assertIn("-s", masq)
        self.assertIn("10.66.66.0/24", masq)

    def test_v4_rule_args_blanket_no_source(self):
        """scope_source=False → MASQUERADE БЕЗ -s (blanket, поведение до 47f56d3)."""
        from chimera.modules.awg_net_common import build_nat_rule_args
        rules = build_nat_rule_args("10.66.66.0/24", "awg0", "eth0", scope_source=False)
        masq = rules[0]
        self.assertNotIn("-s", masq)
        self.assertEqual(masq, [
            "iptables", "-t", "nat", "-A", "POSTROUTING",
            "-o", "eth0", "-j", "MASQUERADE",
        ])

    def test_v4_rule_args_default_is_scoped(self):
        """Если scope_source не передан — default = True (scoped)."""
        from chimera.modules.awg_net_common import build_nat_rule_args
        rules = build_nat_rule_args("10.66.66.0/24", "awg0", "eth0")
        masq = rules[0]
        self.assertIn("-s", masq)

    def test_v4_idempotent_shell_scoped_has_source(self):
        from chimera.modules.awg_net_common import build_nat_idempotent_shell
        s = build_nat_idempotent_shell("10.66.66.0/24", "awg0", "$WAN", scope_source=True)
        self.assertIn("-s 10.66.66.0/24 -o $WAN", s)

    def test_v4_idempotent_shell_blanket_no_source(self):
        """scope_source=False → MASQUERADE без -s (blanket) в shell-сниппете."""
        from chimera.modules.awg_net_common import build_nat_idempotent_shell
        s = build_nat_idempotent_shell("10.66.66.0/24", "awg0", "$WAN", scope_source=False)
        # MASQUERADE pair без -s
        self.assertIn("iptables -t nat -C POSTROUTING -o $WAN -j MASQUERADE", s)
        self.assertIn("iptables -t nat -A POSTROUTING -o $WAN -j MASQUERADE", s)
        # -s нигде не должно быть в MASQUERADE-части
        self.assertNotIn("-s 10.66.66.0/24", s)

    def test_v4_cleanup_shell_blanket_no_source(self):
        from chimera.modules.awg_net_common import build_nat_cleanup_shell
        s = build_nat_cleanup_shell("10.66.66.0/24", "awg0", "$WAN", scope_source=False)
        self.assertIn("iptables -t nat -D POSTROUTING -o $WAN -j MASQUERADE", s)
        self.assertNotIn("-s 10.66.66.0/24", s)


class TestBuildNat6RuleArgs(unittest.TestCase):
    """Тесты генератора списка правил NAT для IPv6 (ip6tables)."""

    def test_returns_three_rules_with_ip6tables(self):
        from chimera.modules.awg_net_common import build_nat6_rule_args
        rules = build_nat6_rule_args("fd66:66:66::/64", "awg0", "eth0")
        self.assertEqual(len(rules), 3)
        for rule in rules:
            self.assertEqual(rule[0], "ip6tables")

    def test_masquerade_rule_correct_scoped(self):
        from chimera.modules.awg_net_common import build_nat6_rule_args
        rules = build_nat6_rule_args("fd66:66:66::/64", "awg0", "eth0", scope_source=True)
        masq = rules[0]
        self.assertEqual(masq, [
            "ip6tables", "-t", "nat", "-A", "POSTROUTING",
            "-s", "fd66:66:66::/64", "-o", "eth0", "-j", "MASQUERADE",
        ])

    def test_masquerade_rule_correct_blanket(self):
        from chimera.modules.awg_net_common import build_nat6_rule_args
        rules = build_nat6_rule_args("fd66:66:66::/64", "awg0", "eth0", scope_source=False)
        masq = rules[0]
        self.assertEqual(masq, [
            "ip6tables", "-t", "nat", "-A", "POSTROUTING",
            "-o", "eth0", "-j", "MASQUERADE",
        ])

    def test_forward_in_rule_correct(self):
        from chimera.modules.awg_net_common import build_nat6_rule_args
        rules = build_nat6_rule_args("fd66:66:66::/64", "awg0", "eth0")
        fwd_in = rules[1]
        self.assertEqual(fwd_in, [
            "ip6tables", "-A", "FORWARD",
            "-i", "awg0", "-j", "ACCEPT",
        ])

    def test_forward_out_rule_correct(self):
        from chimera.modules.awg_net_common import build_nat6_rule_args
        rules = build_nat6_rule_args("fd66:66:66::/64", "awg0", "eth0")
        fwd_out = rules[2]
        self.assertEqual(fwd_out, [
            "ip6tables", "-A", "FORWARD",
            "-o", "awg0", "-m", "state",
            "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT",
        ])


class TestBuildNat6IdempotentShell(unittest.TestCase):
    """Тесты bash-сниппета для PostUp IPv6 (ip6tables с -C/-A парами)."""

    def test_contains_check_before_add_for_masquerade(self):
        from chimera.modules.awg_net_common import build_nat6_idempotent_shell
        s = build_nat6_idempotent_shell("fd66:66:66::/64", "awg0", "$WAN6")
        self.assertIn("ip6tables -t nat -C POSTROUTING -s fd66:66:66::/64 -o $WAN6 -j MASQUERADE", s)
        self.assertIn("ip6tables -t nat -A POSTROUTING -s fd66:66:66::/64 -o $WAN6 -j MASQUERADE", s)
        # -C должен идти ДО -A
        self.assertLess(s.index("-t nat -C POSTROUTING"), s.index("-t nat -A POSTROUTING"))

    def test_contains_check_for_forward_in(self):
        from chimera.modules.awg_net_common import build_nat6_idempotent_shell
        s = build_nat6_idempotent_shell("fd66:66:66::/64", "awg0", "$WAN6")
        self.assertIn("ip6tables -C FORWARD -i awg0 -j ACCEPT", s)
        self.assertIn("ip6tables -A FORWARD -i awg0 -j ACCEPT", s)

    def test_contains_check_for_forward_out(self):
        from chimera.modules.awg_net_common import build_nat6_idempotent_shell
        s = build_nat6_idempotent_shell("fd66:66:66::/64", "awg0", "$WAN6")
        self.assertIn("ip6tables -C FORWARD -o awg0 -m state --state ESTABLISHED,RELATED -j ACCEPT", s)
        self.assertIn("ip6tables -A FORWARD -o awg0 -m state --state ESTABLISHED,RELATED -j ACCEPT", s)

    def test_blanket_no_source_in_masquerade(self):
        """scope_source=False → MASQUERADE без -s в v6 shell-сниппете."""
        from chimera.modules.awg_net_common import build_nat6_idempotent_shell
        s = build_nat6_idempotent_shell("fd66:66:66::/64", "awg0", "$WAN6", scope_source=False)
        self.assertIn("ip6tables -t nat -C POSTROUTING -o $WAN6 -j MASQUERADE", s)
        self.assertIn("ip6tables -t nat -A POSTROUTING -o $WAN6 -j MASQUERADE", s)
        self.assertNotIn("-s fd66:66:66::/64", s)


class TestBuildNat6CleanupShell(unittest.TestCase):
    """Тесты bash-сниппета для PostDown IPv6 (ip6tables с -D)."""

    def test_contains_delete_for_all_three_rules(self):
        from chimera.modules.awg_net_common import build_nat6_cleanup_shell
        s = build_nat6_cleanup_shell("fd66:66:66::/64", "awg0", "$WAN6")
        self.assertIn("ip6tables -t nat -D POSTROUTING -s fd66:66:66::/64 -o $WAN6 -j MASQUERADE", s)
        self.assertIn("ip6tables -D FORWARD -i awg0 -j ACCEPT", s)
        self.assertIn("ip6tables -D FORWARD -o awg0 -m state --state ESTABLISHED,RELATED -j ACCEPT", s)

    def test_all_deletes_have_silent_fallback(self):
        from chimera.modules.awg_net_common import build_nat6_cleanup_shell
        s = build_nat6_cleanup_shell("fd66:66:66::/64", "awg0", "$WAN6")
        self.assertGreaterEqual(s.count("2>/dev/null"), 3)


class TestNoDuplicateRulesInPostUp(unittest.TestCase):
    """
    Тест, что итоговый PostUp из _awg_server_conf_text() НЕ содержит
    дублирующихся iptables-правил с одинаковым rule spec. Это регрессионный
    тест на баг после коммита 47f56d3, когда PostUp содержал дублирующиеся
    FORWARD -i и мёртвый FORWARD -o (без state-фильтра).
    """

    def setUp(self):
        # Загружаем _core.py с патчами системных путей (как в full_test.py)
        _PROJECT_ROOT = Path(__file__).resolve().parent.parent
        sys.path.insert(0, str(_PROJECT_ROOT))
        core_path = _PROJECT_ROOT / "chimera" / "_core.py"
        import importlib.util
        spec = importlib.util.spec_from_file_location("vless_core_test_v2", core_path)
        self.core_mod = importlib.util.module_from_spec(spec)
        with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
             patch.object(Path, 'touch', lambda self, *a, **kw: None), \
             patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
             patch('os.chown', lambda *a, **kw: None), \
             patch('os.geteuid', return_value=0):
            spec.loader.exec_module(self.core_mod)
        # Регистрируем как chimera._core, чтобы lazy import в модулях работал
        sys.modules['chimera._core'] = self.core_mod

    def _get_postup_postdown(self):
        """Возвращает (postup, postdown) строки из _awg_server_conf_text()."""
        from chimera.modules.awg_transport import _awg_server_conf_text
        text = _awg_server_conf_text()
        postup = ""
        postdown = ""
        for line in text.splitlines():
            if line.startswith("PostUp = "):
                postup = line[len("PostUp = "):]
            elif line.startswith("PostDown = "):
                postdown = line[len("PostDown = "):]
        return postup, postdown

    # ── Хелперы для подсчёта вхождений конкретных правил ──────────────────
    # Каждое правило в идемпотентной форме имеет вид:
    #   <binary> -C <spec> 2>/dev/null || <binary> -A <spec>
    # Т.е. для каждого правила ожидается РОВНО 1 вхождение как -A (и 1 как -C).
    # Дубликаты -A одного и того же rule spec = регрессия 47f56d3.
    # ВАЖНО: для MASQUERADE формат: `<binary> -t nat -A POSTROUTING ... MASQUERADE`
    # (т.е. -t nat стоит ПЕРЕД -A). Для FORWARD формат: `<binary> -A FORWARD ...`.

    def _count_add(self, s: str, binary: str, spec: str) -> int:
        """Считает вхождения `<binary> -A <spec>` (для FORWARD-правил)."""
        needle = f"{binary} -A {spec}"
        return s.count(needle)

    def _count_add_nat(self, s: str, binary: str, spec: str) -> int:
        """Считает вхождения `<binary> -t nat -A <spec>` (для MASQUERADE-правил)."""
        needle = f"{binary} -t nat -A {spec}"
        return s.count(needle)

    def _count_delete(self, s: str, binary: str, spec: str) -> int:
        """Считает вхождения `<binary> -D <spec>` (для FORWARD-правил)."""
        needle = f"{binary} -D {spec}"
        return s.count(needle)

    def _count_delete_nat(self, s: str, binary: str, spec: str) -> int:
        """Считает вхождения `<binary> -t nat -D <spec>` (для MASQUERADE-правил)."""
        needle = f"{binary} -t nat -D {spec}"
        return s.count(needle)

    # ── Тесты на отсутствие дубликатов IPv4 (iptables) в PostUp ────────────

    def test_postup_v4_masquerade_add_appears_once(self):
        """Регрессионный: `iptables -t nat -A ... MASQUERADE` ровно 1 раз в PostUp."""
        postup, _ = self._get_postup_postdown()
        # MASQUERADE spec (blanket, без -s — поведение до 47f56d3)
        n = self._count_add_nat(postup, "iptables",
                                "POSTROUTING -o $WAN -j MASQUERADE")
        self.assertEqual(n, 1,
                         f"iptables -t nat -A MASQUERADE должен встречаться 1 раз, "
                         f"найдено {n} (дубликат = регрессия 47f56d3)")

    def test_postup_v4_forward_in_add_appears_once(self):
        """Регрессионный: `iptables -A FORWARD -i awg0 -j ACCEPT` ровно 1 раз."""
        postup, _ = self._get_postup_postdown()
        n = self._count_add(postup, "iptables", "FORWARD -i awg0 -j ACCEPT")
        self.assertEqual(n, 1,
                         f"FORWARD -i awg0 -j ACCEPT (-A) должен встречаться 1 раз, "
                         f"найдено {n} (дубликат = ручная строка + строка из билдера)")

    def test_postup_v4_forward_out_add_appears_once(self):
        """`iptables -A FORWARD -o awg0 -m state --state ESTABLISHED,RELATED -j ACCEPT` ровно 1 раз."""
        postup, _ = self._get_postup_postdown()
        spec = "FORWARD -o awg0 -m state --state ESTABLISHED,RELATED -j ACCEPT"
        n = self._count_add(postup, "iptables", spec)
        self.assertEqual(n, 1,
                         f"FORWARD -o awg0 ESTABLISHED,RELATED (-A) должен встречаться 1 раз, "
                         f"найдено {n}")

    def test_postup_v4_no_blanket_forward_out(self):
        """Регрессионный: нет blanket `iptables -A FORWARD -o awg0 -j ACCEPT` (без state-фильтра).

        До этого фикса ручная строка `iptables -A FORWARD -o awg0 -j ACCEPT`
        создавала blanket-ACCEPT, который делал мёртвым правило с
        ESTABLISHED,RELATED из build_nat_idempotent_shell (оно никогда не
        достигалось, т.к. blanket выше по цепочке уже всё принимал).
        """
        postup, _ = self._get_postup_postdown()
        # Используем regex с негативным look-ahead: ищем "FORWARD -o awg0 -j ACCEPT"
        # НЕ сопровождаемый " -m state" сразу после (что отличает blanket от scoped).
        import re
        blanket_count = len(re.findall(
            r"iptables -A FORWARD -o awg0 -j ACCEPT(?!\s+-m\s)",
            postup,
        ))
        self.assertEqual(blanket_count, 0,
                         f"Найден blanket FORWARD -o awg0 -j ACCEPT (без state-фильтра): "
                         f"{blanket_count} вхождений. Это мёртвый код — делает "
                         f"правило ESTABLISHED,RELATED недостижимым.")

    def test_postup_v4_uses_blanket_masquerade_no_source(self):
        """Регрессионный: MASQUERADE на exit-VPS = blanket (без -s).

        Коммит 47f56d3 по ошибке сделал MASQUERADE scoped (-s awg_subnet),
        что сломало бы маскарадинг не-AWG трафика на exit-VPS. Этот тест
        гарантирует, что восстановлено поведение до 47f56d3.
        """
        postup, _ = self._get_postup_postdown()
        # MASQUERADE -A в iptables (IPv4) должна быть без -s
        import re
        masq_adds = re.findall(
            r"iptables -t nat -A POSTROUTING [^;]*?MASQUERADE",
            postup,
        )
        self.assertEqual(len(masq_adds), 1,
                         f"Ожидался 1 iptables -t nat -A MASQUERADE, найдено: {masq_adds}")
        for spec in masq_adds:
            self.assertNotIn(" -s ", spec,
                             f"MASQUERADE на exit-VPS должен быть blanket (без -s), "
                             f"но найдено -s: {spec}")

    # ── Тесты на отсутствие дубликатов IPv4 (iptables) в PostDown ──────────

    def test_postdown_v4_masquerade_delete_appears_once(self):
        """`iptables -t nat -D ... MASQUERADE` ровно 1 раз в PostDown."""
        _, postdown = self._get_postup_postdown()
        n = self._count_delete_nat(postdown, "iptables",
                                   "POSTROUTING -o $WAN -j MASQUERADE")
        self.assertEqual(n, 1,
                         f"iptables -t nat -D MASQUERADE должен встречаться 1 раз, "
                         f"найдено {n}")

    def test_postdown_v4_forward_in_delete_appears_once(self):
        _, postdown = self._get_postup_postdown()
        n = self._count_delete(postdown, "iptables", "FORWARD -i awg0 -j ACCEPT")
        self.assertEqual(n, 1,
                         f"FORWARD -i awg0 -j ACCEPT (-D) должен встречаться 1 раз, "
                         f"найдено {n}")

    def test_postdown_v4_forward_out_delete_appears_once(self):
        _, postdown = self._get_postup_postdown()
        spec = "FORWARD -o awg0 -m state --state ESTABLISHED,RELATED -j ACCEPT"
        n = self._count_delete(postdown, "iptables", spec)
        self.assertEqual(n, 1,
                         f"FORWARD -o awg0 ESTABLISHED,RELATED (-D) должен встречаться 1 раз, "
                         f"найдено {n}")

    # ── Тесты на отсутствие дубликатов IPv6 (ip6tables) в PostUp ───────────

    def test_postup_v6_masquerade_add_appears_once(self):
        """`ip6tables -t nat -A ... MASQUERADE` ровно 1 раз в PostUp."""
        postup, _ = self._get_postup_postdown()
        n = self._count_add_nat(postup, "ip6tables",
                                "POSTROUTING -o $WAN6 -j MASQUERADE")
        self.assertEqual(n, 1,
                         f"ip6tables -t nat -A MASQUERADE должен встречаться 1 раз, "
                         f"найдено {n}")

    def test_postup_v6_forward_in_add_appears_once(self):
        postup, _ = self._get_postup_postdown()
        n = self._count_add(postup, "ip6tables", "FORWARD -i awg0 -j ACCEPT")
        self.assertEqual(n, 1,
                         f"ip6tables -A FORWARD -i awg0 -j ACCEPT должен встречаться 1 раз, "
                         f"найдено {n}")

    def test_postup_v6_forward_out_add_appears_once(self):
        postup, _ = self._get_postup_postdown()
        spec = "FORWARD -o awg0 -m state --state ESTABLISHED,RELATED -j ACCEPT"
        n = self._count_add(postup, "ip6tables", spec)
        self.assertEqual(n, 1,
                         f"ip6tables -A FORWARD -o awg0 ESTABLISHED,RELATED должен встречаться 1 раз, "
                         f"найдено {n}")

    # ── Тесты на отсутствие дубликатов IPv6 (ip6tables) в PostDown ─────────

    def test_postdown_v6_masquerade_delete_appears_once(self):
        _, postdown = self._get_postup_postdown()
        n = self._count_delete_nat(postdown, "ip6tables",
                                   "POSTROUTING -o $WAN6 -j MASQUERADE")
        self.assertEqual(n, 1,
                         f"ip6tables -t nat -D MASQUERADE должен встречаться 1 раз, "
                         f"найдено {n}")

    def test_postdown_v6_forward_in_delete_appears_once(self):
        _, postdown = self._get_postup_postdown()
        n = self._count_delete(postdown, "ip6tables", "FORWARD -i awg0 -j ACCEPT")
        self.assertEqual(n, 1,
                         f"ip6tables -D FORWARD -i awg0 -j ACCEPT должен встречаться 1 раз, "
                         f"найдено {n}")

    def test_postdown_v6_forward_out_delete_appears_once(self):
        _, postdown = self._get_postup_postdown()
        spec = "FORWARD -o awg0 -m state --state ESTABLISHED,RELATED -j ACCEPT"
        n = self._count_delete(postdown, "ip6tables", spec)
        self.assertEqual(n, 1,
                         f"ip6tables -D FORWARD -o awg0 ESTABLISHED,RELATED должен встречаться 1 раз, "
                         f"найдено {n}")

    # ── Тест на идемпотентность IPv6 (ip6tables через -C/-A) ───────────────

    def test_postup_v6_has_check_before_add(self):
        """Регрессионный: ip6tables правила идут через -C/-A (идемпотентно).

        До этого фикса ip6tables правила добавлялись через -A без -C-проверки
        (тот же баг №1 из ревью, только для IPv6 — забыт при первичном рефакторинге).
        """
        postup, _ = self._get_postup_postdown()
        # Для каждого -A ip6tables правила должен быть соответствующий -C
        # MASQUERADE
        self.assertIn("ip6tables -t nat -C POSTROUTING", postup)
        self.assertIn("ip6tables -t nat -A POSTROUTING", postup)
        # FORWARD -i
        self.assertIn("ip6tables -C FORWARD -i awg0", postup)
        self.assertIn("ip6tables -A FORWARD -i awg0", postup)
        # FORWARD -o ESTABLISHED,RELATED
        self.assertIn("ip6tables -C FORWARD -o awg0 -m state --state ESTABLISHED,RELATED", postup)
        self.assertIn("ip6tables -A FORWARD -o awg0 -m state --state ESTABLISHED,RELATED", postup)

    # ── Тест на общую структуру PostUp (3 правила × 2 binary = 6 -A вхождений) ──

    def test_postup_total_add_count(self):
        """Сводный тест: ровно 6 вхождений `-A` (3 iptables + 3 ip6tables) в PostUp.

        Для MASQUERADE формат: `iptables -t nat -A POSTROUTING ...`
        Для FORWARD формат: `iptables -A FORWARD ...`
        Поэтому считаем оба паттерна и суммируем.
        """
        postup, _ = self._get_postup_postdown()
        import re
        # iptables: либо `-t nat -A POSTROUTING`, либо `-A FORWARD`
        ipt_masq_add = len(re.findall(r"\biptables\s+-t\s+nat\s+-A\s+POSTROUTING", postup))
        ipt_fwd_add = len(re.findall(r"\biptables\s+-A\s+FORWARD", postup))
        ipt_adds = ipt_masq_add + ipt_fwd_add
        # ip6tables: аналогично
        ip6_masq_add = len(re.findall(r"\bip6tables\s+-t\s+nat\s+-A\s+POSTROUTING", postup))
        ip6_fwd_add = len(re.findall(r"\bip6tables\s+-A\s+FORWARD", postup))
        ip6_adds = ip6_masq_add + ip6_fwd_add
        self.assertEqual(ipt_adds, 3,
                         f"Ожидалось 3 iptables -A правила в PostUp "
                         f"(1 MASQUERADE + 2 FORWARD), найдено {ipt_adds} "
                         f"(MASQUERADE={ipt_masq_add}, FORWARD={ipt_fwd_add}) — "
                         f"дубликаты = регрессия 47f56d3")
        self.assertEqual(ip6_adds, 3,
                         f"Ожидалось 3 ip6tables -A правила в PostUp, найдено {ip6_adds} "
                         f"(MASQUERADE={ip6_masq_add}, FORWARD={ip6_fwd_add}) — "
                         f"IPv6 идемпотентность")
        self.assertEqual(ipt_adds + ip6_adds, 6,
                         f"Ожидалось 6 -A правил суммарно (3 v4 + 3 v6), "
                         f"найдено {ipt_adds + ip6_adds}")


class TestBuildSysctlLines(unittest.TestCase):
    """Тесты генератора строк /etc/sysctl.d/XX-awg.conf (пункт 2 ревью)."""

    def test_no_global_all_default_rp_filter(self):
        """НЕ должно быть net.ipv4.conf.all.rp_filter / .default.rp_filter."""
        from chimera.modules.awg_net_common import build_sysctl_lines
        lines = build_sysctl_lines("awg0", "eth0")
        for line in lines:
            self.assertFalse(
                "conf.all.rp_filter" in line or "conf.default.rp_filter" in line,
                f"Найдена global rp_filter строка (недопустимо): {line}",
            )

    def test_per_interface_rp_filter_2(self):
        """Должны быть per-interface rp_filter=2 (loose mode) для awg0 и WAN."""
        from chimera.modules.awg_net_common import build_sysctl_lines
        lines = build_sysctl_lines("awg0", "eth0")
        joined = "\n".join(lines)
        self.assertIn("net.ipv4.conf.awg0.rp_filter = 2", joined)
        self.assertIn("net.ipv4.conf.eth0.rp_filter = 2", joined)

    def test_ip_forward_1_present(self):
        from chimera.modules.awg_net_common import build_sysctl_lines
        lines = build_sysctl_lines("awg0", "eth0")
        self.assertIn("net.ipv4.ip_forward = 1", lines)

    def test_default_rp_filter_value_is_2_loose_mode(self):
        from chimera.modules.awg_net_common import build_sysctl_lines, RP_FILTER_DEFAULT
        self.assertEqual(RP_FILTER_DEFAULT, 2)
        lines = build_sysctl_lines("awg0", "eth0")
        for line in lines:
            if "rp_filter" in line:
                self.assertIn("= 2", line, f"Ожидался loose mode (2), got: {line}")

    def test_explicit_value_0_only_as_fallback(self):
        """Если явно передан value=0 — должно быть 0 (явный fallback)."""
        from chimera.modules.awg_net_common import build_sysctl_lines
        lines = build_sysctl_lines("awg0", "eth0", rp_filter_value=0)
        joined = "\n".join(lines)
        self.assertIn("net.ipv4.conf.awg0.rp_filter = 0", joined)

    def test_invalid_value_falls_back_to_default_2(self):
        """Невалидное значение (7) должно сброситься в default=2."""
        from chimera.modules.awg_net_common import build_sysctl_lines
        lines = build_sysctl_lines("awg0", "eth0", rp_filter_value=7)
        joined = "\n".join(lines)
        self.assertIn("net.ipv4.conf.awg0.rp_filter = 2", joined)


class TestWriteSysctlConf(unittest.TestCase):
    """Тесты записи sysctl-конфига (пункт 2 — вычистка старых global записей)."""

    def test_cleans_old_global_all_default_lines(self):
        """Если в существующем файле есть all/default rp_filter — они удаляются."""
        from chimera.modules.awg_net_common import write_sysctl_conf
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "99-test.conf"
            # Старый файл с глобальным rp_filter=0 (баг из ревью)
            p.write_text(
                "net.ipv4.ip_forward = 1\n"
                "net.ipv4.conf.all.rp_filter = 0\n"
                "net.ipv4.conf.default.rp_filter = 0\n"
                "net.ipv6.conf.all.forwarding = 1\n"
            )
            ok = write_sysctl_conf(p, "awg0", "eth0")
            self.assertTrue(ok)
            content = p.read_text()
            self.assertNotIn("conf.all.rp_filter", content)
            self.assertNotIn("conf.default.rp_filter", content)
            # ipv6.forwarding стал managed-ключом — при ipv6_forward=False
            # он вычищается (управляется только нашим флагом), при True — пишется.
            # Старое поведение «чужая строка сохраняется» заменено сознательно:
            # двойные источники правды для одного ключа давали гонки значений.
            self.assertNotIn("net.ipv6.conf.all.forwarding", content)
            # per-interface записи должны быть добавлены
            self.assertIn("net.ipv4.conf.awg0.rp_filter = 2", content)
            self.assertIn("net.ipv4.conf.eth0.rp_filter = 2", content)

    def test_ipv6_forward_flag_writes_and_replaces(self):
        """ipv6_forward=True пишет net.ipv6.conf.all.forwarding = 1
        и заменяет старое вхождение (managed-ключ, без дублирования)."""
        from chimera.modules.awg_net_common import write_sysctl_conf
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "99-test.conf"
            # Уже есть строка (от прошлой версии chimera) — должна замениться
            p.write_text("net.ipv6.conf.all.forwarding = 1\n")
            ok = write_sysctl_conf(p, "awg0", "eth0", ipv6_forward=True)
            self.assertTrue(ok)
            content = p.read_text()
            self.assertEqual(content.count("net.ipv6.conf.all.forwarding = 1"), 1)
            self.assertIn("net.ipv4.ip_forward = 1", content)

            # ipv6_forward=False — ключ вычищается полностью
            ok = write_sysctl_conf(p, "awg0", "eth0", ipv6_forward=False)
            self.assertTrue(ok)
            self.assertNotIn("net.ipv6.conf.all.forwarding", p.read_text())

    def test_replaces_old_per_iface_with_new_value(self):
        """Если в файле есть старая per-interface запись — заменяется на новую."""
        from chimera.modules.awg_net_common import write_sysctl_conf
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "99-test.conf"
            p.write_text(
                "net.ipv4.conf.awg0.rp_filter = 0\n"
                "net.ipv4.conf.eth0.rp_filter = 0\n"
            )
            ok = write_sysctl_conf(p, "awg0", "eth0", rp_filter_value=2)
            self.assertTrue(ok)
            content = p.read_text()
            # Старое значение 0 не должно остаться
            self.assertNotIn("rp_filter = 0", content)
            self.assertIn("net.ipv4.conf.awg0.rp_filter = 2", content)
            self.assertIn("net.ipv4.conf.eth0.rp_filter = 2", content)


class TestApplyRpFilterPerIface(unittest.TestCase):
    """Тесты runtime-применения per-interface rp_filter (пункт 2)."""

    def test_does_not_touch_all_or_default(self):
        """apply_rp_filter_per_iface НЕ должна вызывать sysctl для all/default."""
        from chimera.modules.awg_net_common import apply_rp_filter_per_iface
        core = _make_mock_core()
        # Текущее значение для awg0 и eth0 — 1 (strict), ожидаем изменение на 2
        core._run.side_effect = [
            MagicMock(returncode=0, stdout="1\n", stderr=""),  # sysctl -n awg0
            MagicMock(returncode=0, stdout="", stderr=""),     # sysctl -w awg0=2
            MagicMock(returncode=0, stdout="1\n", stderr=""),  # sysctl -n eth0
            MagicMock(returncode=0, stdout="", stderr=""),     # sysctl -w eth0=2
        ]
        apply_rp_filter_per_iface(core, "awg0", "eth0", value=2)

        # Проверяем что НИ ОДИН вызов не был для all/default
        for c in core._run.call_args_list:
            args = c.args[0]
            args_str = " ".join(args)
            self.assertNotIn("conf.all.rp_filter", args_str)
            self.assertNotIn("conf.default.rp_filter", args_str)

    def test_skips_when_already_at_target_value(self):
        """Если интерфейс уже имеет целевое значение — sysctl -w не вызывается."""
        from chimera.modules.awg_net_common import apply_rp_filter_per_iface
        core = _make_mock_core()
        # Оба интерфейса уже на 2 → sysctl -w не нужен
        core._run.side_effect = [
            MagicMock(returncode=0, stdout="2\n", stderr=""),  # sysctl -n awg0 → 2
            MagicMock(returncode=0, stdout="2\n", stderr=""),  # sysctl -n eth0 → 2
        ]
        apply_rp_filter_per_iface(core, "awg0", "eth0", value=2)
        # Только 2 вызова (только -n чтение, без -w запись)
        self.assertEqual(core._run.call_count, 2)

    def test_handles_missing_interface_gracefully(self):
        """Если интерфейса ещё нет (awg0 до awg-quick up) — не падает."""
        from chimera.modules.awg_net_common import apply_rp_filter_per_iface
        core = _make_mock_core()
        # sysctl -n возвращает ненулевой код (интерфейс не существует)
        core._run.return_value = MagicMock(returncode=1, stdout="", stderr="sysctl: cannot stat")
        apply_rp_filter_per_iface(core, "awg0", "eth0", value=2)
        # Не должно бросать исключение
        self.assertTrue(True)  # если дошли — тест прошёл


class TestDetectWanIface(unittest.TestCase):
    """Тесты определения WAN-интерфейса."""

    def test_extracts_dev_from_ip_route(self):
        from chimera.modules.awg_net_common import detect_wan_iface
        core = _make_mock_core()
        core._run.return_value = MagicMock(
            returncode=0,
            stdout="default via 192.168.1.1 dev eth0 proto dhcp metric 100\n",
            stderr="",
        )
        iface = detect_wan_iface(core)
        self.assertEqual(iface, "eth0")

    def test_returns_empty_on_failure(self):
        from chimera.modules.awg_net_common import detect_wan_iface
        core = _make_mock_core()
        core._run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        iface = detect_wan_iface(core)
        self.assertEqual(iface, "")


class TestCheckPortUsedByOtherProtocol(unittest.TestCase):
    """Тесты core.check_port_used_by_other_protocol (пункт 4 ревью)."""

    def setUp(self):
        # Импортируем _core.py как модуль, чтобы получить доступ к функции.
        # Используем importlib + патч Path.mkdir (как в full_test.py).
        core_path = _PROJECT_ROOT / "chimera" / "_core.py"
        self._orig_mkdir = Path.mkdir
        self._orig_touch = Path.touch
        self._orig_chmod = Path.chmod

        def _safe_mkdir(self, *a, **kw):
            s = str(self)
            if s.startswith('/var/') or s.startswith('/etc/') or s.startswith('/usr/'):
                return
            try: return self._orig_mkdir_orig(self, *a, **kw)
            except: return

        # Патчим глобально для процесса загрузки _core.py
        import importlib.util
        spec = importlib.util.spec_from_file_location("vless_core_test", core_path)
        self.core_mod = importlib.util.module_from_spec(spec)

        # Патчим на время exec
        with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
             patch.object(Path, 'touch', lambda self, *a, **kw: None), \
             patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
             patch('os.chown', lambda *a, **kw: None), \
             patch('os.geteuid', return_value=0):
            spec.loader.exec_module(self.core_mod)

    def test_no_conflict_returns_empty_string(self):
        """Если никакой state-файл не содержит порт — возвращается ''."""
        with patch.object(self.core_mod, 'STATE_FILE', Path("/nonexistent_state.json")), \
             patch.object(Path, 'exists', lambda self: False):
            result = self.core_mod.check_port_used_by_other_protocol(51820)
            self.assertEqual(result, "")

    def test_exclude_module_skips_check(self):
        """exclude_module корректно пропускает указанный модуль."""
        # Создаём fake state.json с awg_exit_port = 51820 (в секции vless_state)
        with tempfile.TemporaryDirectory() as td:
            fake_state = Path(td) / "state.json"
            fake_state.write_text('{"awg_exit_port": 51820}')
            with patch.object(self.core_mod, 'STATE_FILE', fake_state):
                # Без exclude — должен найти конфликт
                result = self.core_mod.check_port_used_by_other_protocol(51820)
                self.assertNotEqual(result, "")
                self.assertIn("51820", result)
                # С exclude="vless_state" — конфликт с vless_state пропускается
                result = self.core_mod.check_port_used_by_other_protocol(
                    51820, exclude_module="vless_state"
                )
                self.assertEqual(result, "")

    def test_invalid_port_returns_empty(self):
        """Невалидный порт (0, -1, 70000, не-int) → пустая строка."""
        self.assertEqual(self.core_mod.check_port_used_by_other_protocol(0), "")
        self.assertEqual(self.core_mod.check_port_used_by_other_protocol(-1), "")
        self.assertEqual(self.core_mod.check_port_used_by_other_protocol(70000), "")

    def test_hysteria2_conflict_detected(self):
        """Если в state.json есть hysteria2.firewall.udp_ports=[51820] — детектируется."""
        with tempfile.TemporaryDirectory() as td:
            fake_state = Path(td) / "state.json"
            fake_state.write_text(
                '{"hysteria2": {"firewall": {"udp_ports": [51820]}, "exit_nodes": []}}'
            )
            with patch.object(self.core_mod, 'STATE_FILE', fake_state):
                result = self.core_mod.check_port_used_by_other_protocol(51820)
                self.assertIn("Hysteria2", result)
                self.assertIn("51820", result)

    def test_returns_readable_russian_message(self):
        """Возвращаемая строка должна быть на русском и содержать порт."""
        with tempfile.TemporaryDirectory() as td:
            fake_state = Path(td) / "state.json"
            fake_state.write_text('{"awg_exit_port": 51820}')
            with patch.object(self.core_mod, 'STATE_FILE', fake_state):
                result = self.core_mod.check_port_used_by_other_protocol(51820)
                # Должны быть ключевые слова на русском
                self.assertTrue(any(w in result for w in ["занят", "конфликт", "порт"]))
                self.assertIn("51820", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
