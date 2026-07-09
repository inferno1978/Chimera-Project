#!/usr/bin/env python3
"""
tests/test_awg_net_common.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/awg_net_common.py.

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
    Создаёт mock-объект core, который ведёт себя как vless_installer._core:
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
        from vless_installer.modules.awg_net_common import iptables_ensure

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
        from vless_installer.modules.awg_net_common import iptables_ensure

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
        from vless_installer.modules.awg_net_common import iptables_ensure

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
        from vless_installer.modules.awg_net_common import iptables_ensure

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
        from vless_installer.modules.awg_net_common import build_nat_rule_args
        rules = build_nat_rule_args("10.66.66.0/24", "awg0", "eth0")
        self.assertEqual(len(rules), 3)
        for rule in rules:
            self.assertEqual(rule[0], "iptables")

    def test_masquerade_rule_correct(self):
        from vless_installer.modules.awg_net_common import build_nat_rule_args
        rules = build_nat_rule_args("10.66.66.0/24", "awg0", "eth0")
        masq = rules[0]
        self.assertEqual(masq, [
            "iptables", "-t", "nat", "-A", "POSTROUTING",
            "-s", "10.66.66.0/24", "-o", "eth0", "-j", "MASQUERADE",
        ])

    def test_forward_in_rule_correct(self):
        from vless_installer.modules.awg_net_common import build_nat_rule_args
        rules = build_nat_rule_args("10.66.66.0/24", "awg0", "eth0")
        fwd_in = rules[1]
        self.assertEqual(fwd_in, [
            "iptables", "-A", "FORWARD",
            "-i", "awg0", "-j", "ACCEPT",
        ])

    def test_forward_out_rule_correct(self):
        from vless_installer.modules.awg_net_common import build_nat_rule_args
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
        from vless_installer.modules.awg_net_common import build_nat_idempotent_shell
        s = build_nat_idempotent_shell("10.66.66.0/24", "awg0", "$WAN")
        # Для MASQUERADE: -C ... || -A ...
        self.assertIn("iptables -t nat -C POSTROUTING -s 10.66.66.0/24 -o $WAN -j MASQUERADE", s)
        self.assertIn("iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o $WAN -j MASQUERADE", s)
        # -C должен идти ДО -A (лексический порядок)
        self.assertLess(s.index("-t nat -C POSTROUTING"), s.index("-t nat -A POSTROUTING"))

    def test_contains_check_for_forward_in(self):
        from vless_installer.modules.awg_net_common import build_nat_idempotent_shell
        s = build_nat_idempotent_shell("10.66.66.0/24", "awg0", "$WAN")
        self.assertIn("iptables -C FORWARD -i awg0 -j ACCEPT", s)
        self.assertIn("iptables -A FORWARD -i awg0 -j ACCEPT", s)

    def test_contains_check_for_forward_out(self):
        from vless_installer.modules.awg_net_common import build_nat_idempotent_shell
        s = build_nat_idempotent_shell("10.66.66.0/24", "awg0", "$WAN")
        self.assertIn("iptables -C FORWARD -o awg0 -m state --state ESTABLISHED,RELATED -j ACCEPT", s)
        self.assertIn("iptables -A FORWARD -o awg0 -m state --state ESTABLISHED,RELATED -j ACCEPT", s)


class TestBuildNatCleanupShell(unittest.TestCase):
    """Тесты bash-сниппета для PostDown (с -D)."""

    def test_contains_delete_for_all_three_rules(self):
        from vless_installer.modules.awg_net_common import build_nat_cleanup_shell
        s = build_nat_cleanup_shell("10.66.66.0/24", "awg0", "$WAN")
        self.assertIn("iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -o $WAN -j MASQUERADE", s)
        self.assertIn("iptables -D FORWARD -i awg0 -j ACCEPT", s)
        self.assertIn("iptables -D FORWARD -o awg0 -m state --state ESTABLISHED,RELATED -j ACCEPT", s)

    def test_all_deletes_have_silent_fallback(self):
        from vless_installer.modules.awg_net_common import build_nat_cleanup_shell
        s = build_nat_cleanup_shell("10.66.66.0/24", "awg0", "$WAN")
        # Каждое -D должно быть обёрнуто в 2>/dev/null || true (или || true)
        # для безопасного PostDown даже если правила уже нет.
        self.assertGreaterEqual(s.count("2>/dev/null"), 3)


class TestBuildSysctlLines(unittest.TestCase):
    """Тесты генератора строк /etc/sysctl.d/XX-awg.conf (пункт 2 ревью)."""

    def test_no_global_all_default_rp_filter(self):
        """НЕ должно быть net.ipv4.conf.all.rp_filter / .default.rp_filter."""
        from vless_installer.modules.awg_net_common import build_sysctl_lines
        lines = build_sysctl_lines("awg0", "eth0")
        for line in lines:
            self.assertFalse(
                "conf.all.rp_filter" in line or "conf.default.rp_filter" in line,
                f"Найдена global rp_filter строка (недопустимо): {line}",
            )

    def test_per_interface_rp_filter_2(self):
        """Должны быть per-interface rp_filter=2 (loose mode) для awg0 и WAN."""
        from vless_installer.modules.awg_net_common import build_sysctl_lines
        lines = build_sysctl_lines("awg0", "eth0")
        joined = "\n".join(lines)
        self.assertIn("net.ipv4.conf.awg0.rp_filter = 2", joined)
        self.assertIn("net.ipv4.conf.eth0.rp_filter = 2", joined)

    def test_ip_forward_1_present(self):
        from vless_installer.modules.awg_net_common import build_sysctl_lines
        lines = build_sysctl_lines("awg0", "eth0")
        self.assertIn("net.ipv4.ip_forward = 1", lines)

    def test_default_rp_filter_value_is_2_loose_mode(self):
        from vless_installer.modules.awg_net_common import build_sysctl_lines, RP_FILTER_DEFAULT
        self.assertEqual(RP_FILTER_DEFAULT, 2)
        lines = build_sysctl_lines("awg0", "eth0")
        for line in lines:
            if "rp_filter" in line:
                self.assertIn("= 2", line, f"Ожидался loose mode (2), got: {line}")

    def test_explicit_value_0_only_as_fallback(self):
        """Если явно передан value=0 — должно быть 0 (явный fallback)."""
        from vless_installer.modules.awg_net_common import build_sysctl_lines
        lines = build_sysctl_lines("awg0", "eth0", rp_filter_value=0)
        joined = "\n".join(lines)
        self.assertIn("net.ipv4.conf.awg0.rp_filter = 0", joined)

    def test_invalid_value_falls_back_to_default_2(self):
        """Невалидное значение (7) должно сброситься в default=2."""
        from vless_installer.modules.awg_net_common import build_sysctl_lines
        lines = build_sysctl_lines("awg0", "eth0", rp_filter_value=7)
        joined = "\n".join(lines)
        self.assertIn("net.ipv4.conf.awg0.rp_filter = 2", joined)


class TestWriteSysctlConf(unittest.TestCase):
    """Тесты записи sysctl-конфига (пункт 2 — вычистка старых global записей)."""

    def test_cleans_old_global_all_default_lines(self):
        """Если в существующем файле есть all/default rp_filter — они удаляются."""
        from vless_installer.modules.awg_net_common import write_sysctl_conf
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
        from vless_installer.modules.awg_net_common import write_sysctl_conf
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
        from vless_installer.modules.awg_net_common import apply_rp_filter_per_iface
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
        from vless_installer.modules.awg_net_common import apply_rp_filter_per_iface
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
        from vless_installer.modules.awg_net_common import apply_rp_filter_per_iface
        core = _make_mock_core()
        # sysctl -n возвращает ненулевой код (интерфейс не существует)
        core._run.return_value = MagicMock(returncode=1, stdout="", stderr="sysctl: cannot stat")
        apply_rp_filter_per_iface(core, "awg0", "eth0", value=2)
        # Не должно бросать исключение
        self.assertTrue(True)  # если дошли — тест прошёл


class TestDetectWanIface(unittest.TestCase):
    """Тесты определения WAN-интерфейса."""

    def test_extracts_dev_from_ip_route(self):
        from vless_installer.modules.awg_net_common import detect_wan_iface
        core = _make_mock_core()
        core._run.return_value = MagicMock(
            returncode=0,
            stdout="default via 192.168.1.1 dev eth0 proto dhcp metric 100\n",
            stderr="",
        )
        iface = detect_wan_iface(core)
        self.assertEqual(iface, "eth0")

    def test_returns_empty_on_failure(self):
        from vless_installer.modules.awg_net_common import detect_wan_iface
        core = _make_mock_core()
        core._run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        iface = detect_wan_iface(core)
        self.assertEqual(iface, "")


class TestCheckPortUsedByOtherProtocol(unittest.TestCase):
    """Тесты core.check_port_used_by_other_protocol (пункт 4 ревью)."""

    def setUp(self):
        # Импортируем _core.py как модуль, чтобы получить доступ к функции.
        # Используем importlib + патч Path.mkdir (как в full_test.py).
        core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
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
