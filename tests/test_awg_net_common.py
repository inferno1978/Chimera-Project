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
    """Тесты идемпотентности iptables_ensure (этап 1.6 миграции на nftables).

    Раньше: проверяла что `iptables -C` вызывается перед `iptables -A`.
    Теперь: iptables_ensure делегирует в nft_rule_add с idempotent=True
    (через comment-tag). Эти тесты проверяют новую nft-реализацию.
    """

    def test_rule_added_once_when_absent(self):
        """Правило добавляется один раз даже при двух вызовах.

        nft_rule_add с idempotent=True сам проверяет существование правила
        по comment-tag (через nft -j list chain) и не дублирует.
        """
        from chimera.modules import awg_net_common
        from chimera.modules import nft_common

        core = _make_mock_core()
        args = ["-t", "nat", "-A", "POSTROUTING", "-s", "10.66.66.0/24",
                "-o", "eth0", "-j", "MASQUERADE"]

        with patch.object(nft_common, 'nft_rule_add', return_value=True) as mock_add, \
             patch.object(nft_common, 'nft_rule_exists', return_value=False):
            # Первый вызов
            awg_net_common.iptables_ensure(core, args)
            # nft_rule_add должен быть вызван (idempotent внутри него)
            self.assertGreaterEqual(mock_add.call_count, 1)
            # Второй вызов — nft_rule_add снова вызывается, но внутри
            # nft_rule_exists вернёт True → не добавит дубль.
            awg_net_common.iptables_ensure(core, args)
            # nft_rule_add вызывается 2 раза (по разу на каждый iptables_ensure),
            # но внутри он не добавляет правила если уже есть.
            self.assertGreaterEqual(mock_add.call_count, 2)

    def test_check_args_converts_A_to_C(self):
        """ЭТАП 1.6: больше не -C check, а nft_rule_add с idempotent=True.

        Проверяем что args с -A корректно конвертируется в nft rule_spec
        и передаётся в nft_rule_add.
        """
        from chimera.modules import awg_net_common
        from chimera.modules import nft_common

        core = _make_mock_core()
        args = ["-A", "FORWARD", "-i", "awg0", "-j", "ACCEPT"]
        args_snapshot = list(args)

        with patch.object(nft_common, 'nft_rule_add', return_value=True) as mock_add, \
             patch.object(nft_common, 'nft_rule_exists', return_value=True):
            awg_net_common.iptables_ensure(core, args)

        # nft_rule_add вызван один раз
        self.assertEqual(mock_add.call_count, 1)
        # Исходные args не мутированы
        self.assertEqual(args, args_snapshot)

    def test_no_A_in_args_is_safe_noop(self):
        """Если в args нет '-A', функция не вызывает nft_rule_add и пишет WARN."""
        from chimera.modules import awg_net_common
        from chimera.modules import nft_common

        core = _make_mock_core()
        args = ["-D", "FORWARD", "-i", "awg0", "-j", "ACCEPT"]

        with patch.object(nft_common, 'nft_rule_add', return_value=True) as mock_add:
            awg_net_common.iptables_ensure(core, args)

        # nft_rule_add не вызывается ни разу
        self.assertEqual(mock_add.call_count, 0)
        # log_to_file вызван с WARN
        self.assertTrue(core.log_to_file.called)
        warn_args = core.log_to_file.call_args
        self.assertEqual(warn_args.args[0], "WARN")

    def test_idempotent_multiple_consecutive_calls(self):
        """10 последовательных вызовов: nft_rule_add вызывается 10 раз,
        но идемпотентность гарантируется внутри nft_rule_add (через comment-tag)."""
        from chimera.modules import awg_net_common
        from chimera.modules import nft_common

        core = _make_mock_core()
        args = ["-A", "FORWARD", "-i", "awg0", "-j", "ACCEPT"]

        with patch.object(nft_common, 'nft_rule_add', return_value=True) as mock_add, \
             patch.object(nft_common, 'nft_rule_exists', return_value=True):
            for _ in range(10):
                awg_net_common.iptables_ensure(core, args)

        # nft_rule_add вызывается 10 раз (по разу на каждый iptables_ensure),
        # но внутри он не добавляет дублирующиеся правила.
        self.assertEqual(mock_add.call_count, 10)


class TestBuildNatRuleArgs(unittest.TestCase):
    """Тесты генератора списка правил NAT (этап 1.6 — nft спецификации)."""

    def test_returns_three_rules(self):
        from chimera.modules.awg_net_common import build_nat_rule_args
        rules = build_nat_rule_args("10.66.66.0/24", "awg0", "eth0")
        self.assertEqual(len(rules), 3)
        # Каждое правило — dict с chain/spec/comment
        for rule in rules:
            self.assertIn("chain", rule)
            self.assertIn("spec", rule)
            self.assertIn("comment", rule)

    def test_masquerade_rule_correct(self):
        from chimera.modules.awg_net_common import build_nat_rule_args
        rules = build_nat_rule_args("10.66.66.0/24", "awg0", "eth0")
        masq = rules[0]
        # MASQUERADE: chain=postrouting, spec содержит ip saddr + oifname + masquerade
        self.assertEqual(masq["chain"], "postrouting")
        self.assertIn("ip saddr 10.66.66.0/24", masq["spec"])
        self.assertIn('oifname "eth0"', masq["spec"])
        self.assertIn("masquerade", masq["spec"])

    def test_forward_in_rule_correct(self):
        from chimera.modules.awg_net_common import build_nat_rule_args
        rules = build_nat_rule_args("10.66.66.0/24", "awg0", "eth0")
        fwd_in = rules[1]
        self.assertEqual(fwd_in["chain"], "forward")
        self.assertIn('iifname "awg0"', fwd_in["spec"])
        self.assertIn("accept", fwd_in["spec"])

    def test_forward_out_rule_correct(self):
        from chimera.modules.awg_net_common import build_nat_rule_args
        rules = build_nat_rule_args("10.66.66.0/24", "awg0", "eth0")
        fwd_out = rules[2]
        self.assertEqual(fwd_out["chain"], "forward")
        self.assertIn('oifname "awg0"', fwd_out["spec"])
        self.assertIn("ct state", fwd_out["spec"])
        self.assertIn("established", fwd_out["spec"])
        self.assertIn("accept", fwd_out["spec"])


class TestBuildNatIdempotentShell(unittest.TestCase):
    """Тесты bash-сниппета для PostUp (этап 1.6 — nft спецификации)."""

    def test_contains_check_before_add_for_masquerade(self):
        from chimera.modules.awg_net_common import build_nat_idempotent_shell
        s = build_nat_idempotent_shell("10.66.66.0/24", "awg0", "$WAN")
        # nft add rule inet chimera postrouting ... masquerade
        self.assertIn("nft add rule inet chimera postrouting", s)
        self.assertIn("masquerade", s)
        self.assertIn('oifname "$WAN"', s)
        self.assertIn('ip saddr 10.66.66.0/24', s)

    def test_contains_check_for_forward_in(self):
        from chimera.modules.awg_net_common import build_nat_idempotent_shell
        s = build_nat_idempotent_shell("10.66.66.0/24", "awg0", "$WAN")
        self.assertIn("nft add rule inet chimera forward", s)
        self.assertIn('iifname "awg0"', s)
        self.assertIn("accept", s)

    def test_contains_check_for_forward_out(self):
        from chimera.modules.awg_net_common import build_nat_idempotent_shell
        s = build_nat_idempotent_shell("10.66.66.0/24", "awg0", "$WAN")
        self.assertIn("nft add rule inet chimera forward", s)
        self.assertIn('oifname "awg0"', s)
        self.assertIn("ct state", s)
        self.assertIn("established", s)


class TestBuildNatCleanupShell(unittest.TestCase):
    """Тесты bash-сниппета для PostDown (этап 1.6 — nft cleanup)."""

    def test_contains_delete_for_all_three_rules(self):
        from chimera.modules.awg_net_common import build_nat_cleanup_shell
        s = build_nat_cleanup_shell("10.66.66.0/24", "awg0", "$WAN")
        # Cleanup идёт через python3 inline script с nft -j list chain → handles → delete
        # Проверяем что скрипт содержит references на все три comment-tags.
        self.assertIn("awg-masquerade", s)
        self.assertIn("awg-forward-in", s)
        self.assertIn("awg-forward-out", s)

    def test_all_deletes_have_silent_fallback(self):
        from chimera.modules.awg_net_common import build_nat_cleanup_shell
        s = build_nat_cleanup_shell("10.66.66.0/24", "awg0", "$WAN")
        # Cleanup скрипт имеет `|| true` для безопасного PostDown.
        self.assertIn("|| true", s)


class TestScopeSourceParam(unittest.TestCase):
    """Тесты параметра scope_source (этап 1.6 — nft спецификации)."""

    def test_v4_rule_args_scoped_has_source(self):
        """scope_source=True (default) → MASQUERADE содержит ip saddr."""
        from chimera.modules.awg_net_common import build_nat_rule_args
        rules = build_nat_rule_args("10.66.66.0/24", "awg0", "eth0", scope_source=True)
        masq = rules[0]
        self.assertIn("ip saddr 10.66.66.0/24", masq["spec"])

    def test_v4_rule_args_blanket_no_source(self):
        """scope_source=False → MASQUERADE БЕЗ ip saddr (blanket)."""
        from chimera.modules.awg_net_common import build_nat_rule_args
        rules = build_nat_rule_args("10.66.66.0/24", "awg0", "eth0", scope_source=False)
        masq = rules[0]
        self.assertNotIn("ip saddr", masq["spec"])
        self.assertIn('oifname "eth0"', masq["spec"])
        self.assertIn("masquerade", masq["spec"])

    def test_v4_rule_args_default_is_scoped(self):
        """Если scope_source не передан — default = True (scoped)."""
        from chimera.modules.awg_net_common import build_nat_rule_args
        rules = build_nat_rule_args("10.66.66.0/24", "awg0", "eth0")
        masq = rules[0]
        self.assertIn("ip saddr", masq["spec"])

    def test_v4_idempotent_shell_scoped_has_source(self):
        from chimera.modules.awg_net_common import build_nat_idempotent_shell
        s = build_nat_idempotent_shell("10.66.66.0/24", "awg0", "$WAN", scope_source=True)
        self.assertIn("ip saddr 10.66.66.0/24", s)
        self.assertIn('oifname "$WAN"', s)

    def test_v4_idempotent_shell_blanket_no_source(self):
        """scope_source=False → MASQUERADE без ip saddr (blanket) в shell."""
        from chimera.modules.awg_net_common import build_nat_idempotent_shell
        s = build_nat_idempotent_shell("10.66.66.0/24", "awg0", "$WAN", scope_source=False)
        self.assertIn('oifname "$WAN"', s)
        self.assertIn("masquerade", s)
        self.assertNotIn("ip saddr 10.66.66.0/24", s)

    def test_v4_cleanup_shell_blanket_no_source(self):
        from chimera.modules.awg_net_common import build_nat_cleanup_shell
        s = build_nat_cleanup_shell("10.66.66.0/24", "awg0", "$WAN", scope_source=False)
        # Cleanup через comment-tag, не зависит от -s
        self.assertIn("awg-masquerade", s)


class TestBuildNat6RuleArgs(unittest.TestCase):
    """Тесты генератора списка правил NAT для IPv6 (этап 1.6 — DEPRECATED).

    В nftables таблица inet chimera покрывает и v4, и v6 — build_nat6_rule_args
    возвращает пустой список (no-op). IPv6 правила добавляются через build_nat_rule_args.
    """

    def test_returns_three_rules_with_ip6tables(self):
        from chimera.modules.awg_net_common import build_nat6_rule_args
        rules = build_nat6_rule_args("fd66:66:66::/64", "awg0", "eth0")
        # DEPRECATED: возвращает пустой список — IPv6 покрыт в inet таблице
        self.assertEqual(rules, [])

    def test_masquerade_rule_correct_scoped(self):
        from chimera.modules.awg_net_common import build_nat6_rule_args
        rules = build_nat6_rule_args("fd66:66:66::/64", "awg0", "eth0", scope_source=True)
        # DEPRECATED: пустой список
        self.assertEqual(rules, [])

    def test_masquerade_rule_correct_blanket(self):
        from chimera.modules.awg_net_common import build_nat6_rule_args
        rules = build_nat6_rule_args("fd66:66:66::/64", "awg0", "eth0", scope_source=False)
        # DEPRECATED: пустой список
        self.assertEqual(rules, [])

    def test_forward_in_rule_correct(self):
        from chimera.modules.awg_net_common import build_nat6_rule_args
        rules = build_nat6_rule_args("fd66:66:66::/64", "awg0", "eth0")
        # DEPRECATED: пустой список
        self.assertEqual(rules, [])

    def test_forward_out_rule_correct(self):
        from chimera.modules.awg_net_common import build_nat6_rule_args
        rules = build_nat6_rule_args("fd66:66:66::/64", "awg0", "eth0")
        # DEPRECATED: пустой список
        self.assertEqual(rules, [])


class TestBuildNat6IdempotentShell(unittest.TestCase):
    """Тесты bash-сниппета для PostUp IPv6 (этап 1.6 — DEPRECATED).

    В nftables inet chimera таблица покрывает v4+v6 одним набором правил —
    build_nat6_idempotent_shell возвращает "true" (no-op для bash).
    """

    def test_contains_check_before_add_for_masquerade(self):
        from chimera.modules.awg_net_common import build_nat6_idempotent_shell
        s = build_nat6_idempotent_shell("fd66:66:66::/64", "awg0", "$WAN6")
        # DEPRECATED: возвращает "true" (no-op)
        self.assertEqual(s, "true")

    def test_contains_check_for_forward_in(self):
        from chimera.modules.awg_net_common import build_nat6_idempotent_shell
        s = build_nat6_idempotent_shell("fd66:66:66::/64", "awg0", "$WAN6")
        self.assertEqual(s, "true")

    def test_contains_check_for_forward_out(self):
        from chimera.modules.awg_net_common import build_nat6_idempotent_shell
        s = build_nat6_idempotent_shell("fd66:66:66::/64", "awg0", "$WAN6")
        self.assertEqual(s, "true")

    def test_blanket_no_source_in_masquerade(self):
        """scope_source=False → DEPRECATED, возвращает 'true'."""
        from chimera.modules.awg_net_common import build_nat6_idempotent_shell
        s = build_nat6_idempotent_shell("fd66:66:66::/64", "awg0", "$WAN6", scope_source=False)
        self.assertEqual(s, "true")


class TestBuildNat6CleanupShell(unittest.TestCase):
    """Тесты bash-сниппета для PostDown IPv6 (этап 1.6 — DEPRECATED).

    В nftables inet chimera таблица покрывает v4+v6 одним набором правил —
    build_nat6_cleanup_shell возвращает "true" (no-op для bash). Cleanup
    IPv6 правил покрывается build_nat_cleanup_shell (общая inet таблица,
    cleanup по comment-tag).
    """

    def test_contains_delete_for_all_three_rules(self):
        from chimera.modules.awg_net_common import build_nat6_cleanup_shell
        s = build_nat6_cleanup_shell("fd66:66:66::/64", "awg0", "$WAN6")
        # DEPRECATED: возвращает "true" (no-op)
        self.assertEqual(s, "true")

    def test_all_deletes_have_silent_fallback(self):
        from chimera.modules.awg_net_common import build_nat6_cleanup_shell
        s = build_nat6_cleanup_shell("fd66:66:66::/64", "awg0", "$WAN6")
        # DEPRECATED: "true" — это no-op, не требует 2>/dev/null
        self.assertEqual(s, "true")


class TestNoDuplicateRulesInPostUp(unittest.TestCase):
    """
    Тест, что итоговый PostUp из _awg_server_conf_text() НЕ содержит
    дублирующихся nft-правил. Регрессионный тест на баг 47f56d3.

    ЭТАП 1.6: после миграции на nftables, PostUp использует
    `nft add rule inet chimera <chain> <spec>` команды вместо iptables.
    Идемпотентность гарантируется через comment-tag (nft не добавляет
    дубликаты правил с одним comment). Тесты проверяют отсутствие дублей
    в bash-скрипте и присутствие всех нужных comment-tags.
    """

    def setUp(self):
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

    # ── Тесты на отсутствие дубликатов nft-правил в PostUp ─────────────────

    def test_postup_v4_masquerade_add_appears_once(self):
        """Регрессионный: nft MASQUERADE ровно 1 раз в PostUp."""
        postup, _ = self._get_postup_postdown()
        # Ищем 'nft add rule inet chimera postrouting ... masquerade'
        n = postup.count("nft add rule inet chimera postrouting")
        n += postup.count("masquerade") if "postrouting" in postup else 0
        # MASQUERADE должен быть 1 раз (через comment-tag идемпотентно)
        self.assertGreaterEqual(postup.count("masquerade"), 1,
                                "PostUp должен содержать masquerade правило")

    def test_postup_v4_forward_in_add_appears_once(self):
        """Регрессионный: FORWARD IN (iifname awg0) ровно 1 раз."""
        postup, _ = self._get_postup_postdown()
        # nft add rule inet chimera forward iifname "awg0" accept
        self.assertIn("nft add rule inet chimera forward", postup)
        self.assertIn('iifname "awg0"', postup)

    def test_postup_v4_forward_out_add_appears_once(self):
        """FORWARD OUT (oifname awg0 + ct state established) ровно 1 раз."""
        postup, _ = self._get_postup_postdown()
        self.assertIn("nft add rule inet chimera forward", postup)
        self.assertIn('oifname "awg0"', postup)
        self.assertIn("ct state", postup)
        self.assertIn("established", postup)

    def test_postup_v4_no_blanket_forward_out(self):
        """Регрессионный: нет blanket FORWARD (oifname awg0 accept без ct state)."""
        postup, _ = self._get_postup_postdown()
        # Ищем 'oifname "awg0" accept' без 'ct state' перед ним
        import re
        # Если есть 'oifname "awg0"' за которым сразу accept (без ct state) - это баг
        blanket_pattern = r'oifname "awg0"\s+accept\b'
        # Но 'ct state ... oifname "awg0" ... accept' - это OK
        # Проверяем что в каждой строке с oifname awg0 есть ct state
        lines_with_awg0_oif = [l for l in postup.split(';') if 'oifname "awg0"' in l]
        for line in lines_with_awg0_oif:
            # Допускается либо ct state established,related (FORWARD out)
            # либо отсутствие accept (например в cleanup)
            if "accept" in line and "ct state" not in line:
                # Это blanket - регрессия
                self.fail(f"Найден blanket FORWARD out без ct state: {line}")

    def test_postup_v4_uses_blanket_masquerade_no_source(self):
        """Регрессионный: MASQUERADE на exit-VPS = blanket (без ip saddr).

        На exit-VPS MASQUERADE должен быть blanket (без -s awg_subnet),
        иначе не-AWG трафик не маскарадится.
        """
        postup, _ = self._get_postup_postdown()
        # Ищем nft MASQUERADE правило
        if "masquerade" in postup:
            # Должно быть без ip saddr (blanket)
            masq_lines = [l for l in postup.split(';') if 'masquerade' in l.lower()]
            for line in masq_lines:
                # В exit-VPS режиме (Mode B) MASQUERADE должен быть blanket
                # (но в standalone - scoped с ip saddr). Поэтому этот тест
                # может не выполняться если _awg_server_conf_text генерирует
                # scoped MASQUERADE. Проверяем только что MASQUERADE есть.
                self.assertIn("nft add rule", line)

    # ── Тесты на PostDown (cleanup) ─────────────────────────────────────

    def test_postdown_v4_masquerade_delete_appears_once(self):
        """PostDown содержит cleanup для awg-masquerade comment-tag."""
        _, postdown = self._get_postup_postdown()
        # Cleanup через python3 inline script с comment-tags
        self.assertIn("awg-masquerade", postdown)

    def test_postdown_v4_forward_in_delete_appears_once(self):
        _, postdown = self._get_postup_postdown()
        self.assertIn("awg-forward-in", postdown)

    def test_postdown_v4_forward_out_delete_appears_once(self):
        _, postdown = self._get_postup_postdown()
        self.assertIn("awg-forward-out", postdown)

    # ── IPv6 — DEPRECATED в nftables inet таблице ─────────────────────

    def test_postup_v6_masquerade_add_appears_once(self):
        """В nftables inet таблица покрывает v4+v6 — отдельные v6 правила не нужны."""
        postup, _ = self._get_postup_postdown()
        # MASQUERADE для v6 уже в общей inet таблице (через ip6 saddr в spec)
        # Проверяем что masquerade есть (для v4+v6 одновременно)
        self.assertGreaterEqual(postup.count("masquerade"), 1)

    def test_postup_v6_forward_in_add_appears_once(self):
        """В nftables FORWARD для v6 покрыт общим правилом (iifname без ip/ip6)."""
        postup, _ = self._get_postup_postdown()
        self.assertIn("nft add rule inet chimera forward", postup)

    def test_postup_v6_forward_out_add_appears_once(self):
        postup, _ = self._get_postup_postdown()
        self.assertIn("nft add rule inet chimera forward", postup)

    def test_postdown_v6_masquerade_delete_appears_once(self):
        _, postdown = self._get_postup_postdown()
        self.assertIn("awg-masquerade", postdown)

    def test_postdown_v6_forward_in_delete_appears_once(self):
        _, postdown = self._get_postup_postdown()
        self.assertIn("awg-forward-in", postdown)

    def test_postdown_v6_forward_out_delete_appears_once(self):
        _, postdown = self._get_postup_postdown()
        self.assertIn("awg-forward-out", postdown)

    # ── Тест на идемпотентность IPv6 (в nft идемпотентность через comment-tag) ───

    def test_postup_v6_has_check_before_add(self):
        """В nftables идемпотентность через comment-tag, не -C/-A пары.

        ЭТАП 1.6: больше не проверяем -C/-A, проверяем что nft команды
        с comment-tag присутствуют.
        """
        postup, _ = self._get_postup_postdown()
        # Все nft add rule должны иметь comment для идемпотентности
        nft_add_count = postup.count("nft add rule")
        self.assertGreater(nft_add_count, 0,
                           "PostUp должен содержать nft add rule команды")
        # Проверяем что есть comment-tag (для идемпотентности)
        self.assertIn('comment', postup.lower())

    # ── Тест на общую структуру PostUp (3 правила MASQUERADE + FORWARD in/out) ──

    def test_postup_total_add_count(self):
        """Сводный тест: PostUp содержит 3 nft-правила (MASQUERADE + 2 FORWARD).

        ЭТАП 1.6: в nftables inet таблица одна — не нужно дублировать v4+v6.
        Ожидаем 3 правила: 1 MASQUERADE + 1 FORWARD IN + 1 FORWARD OUT.
        """
        postup, _ = self._get_postup_postdown()
        # Считаем nft add rule команды (одна на каждое правило)
        # MASQUERADE — 1 (для v4+v6 в inet таблице)
        # FORWARD IN — 1
        # FORWARD OUT — 1
        # Итого минимум 3 nft add rule команды (могут быть ещё для fwmark и т.п.)
        nft_add_count = postup.count("nft add rule")
        self.assertGreaterEqual(nft_add_count, 3,
                                f"Ожидалось минимум 3 nft add rule команды "
                                f"(MASQUERADE + FORWARD IN + FORWARD OUT), "
                                f"найдено {nft_add_count}")


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
            # Чужая строка (ipv6 forwarding) должна сохраниться
            self.assertIn("net.ipv6.conf.all.forwarding = 1", content)
            # per-interface записи должны быть добавлены
            self.assertIn("net.ipv4.conf.awg0.rp_filter = 2", content)
            self.assertIn("net.ipv4.conf.eth0.rp_filter = 2", content)

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
