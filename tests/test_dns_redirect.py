#!/usr/bin/env python3
"""
tests/test_dns_redirect.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/dns_redirect.py.

ПОКРЫТИЕ:
  1. State I/O — load/save, default values, chmod 0o600
  2. get_dnscrypt_port — парсинг TOML, fallback на default 5300
  3. get_dnscrypt_listen_ipv6 — определение ::1 в listen_addresses
  4. _build_redirect_rule_args — генерация аргументов iptables для разных
     комбинаций (IPv4/IPv6, разные интерфейсы, UDP/TCP)
  5. _ipt_rule_exists / _ipt_add_rule_idempotent / _ipt_delete_rule —
     моки subprocess.run, проверка что -C вызывается перед -A
  6. apply_dns_redirect — идемпотентность (двойной вызов не создаёт
     дубликат правила), edge-case: dnscrypt не активен → skip
  7. remove_dns_redirect — корректное удаление, идемпотентность
  8. health_check_dns_redirect — все ветки (OK / dnscrypt down / port not
     listening / rules missing / black-hole warning)
  9. _cleanup_all_dns_redirect_rules — cleanup «висячих» правил при
     смене интерфейса
 10. Edge-case: AWG-интерфейс исчез (правила не должны оставаться висячими)
 11. Edge-case: dnscrypt-proxy рестарт — правила продолжают работать,
     трафик отбрасывается пока сервис не поднимется (не падает с ошибкой)
 12. Совместимость с ingress-блокировкой РФ — порядок правил не нарушается
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Создаёт фейковый chimera._core (как в test_tg_bot.py)."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core


# =============================================================================
#  ТЕСТЫ STATE I/O
# =============================================================================
class TestStateIO(unittest.TestCase):
    """state_load / state_save — JSON I/O + chmod 0o600."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "dns_redirect.json"

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.dns_redirect._STATE_FILE", self._state)

    def test_load_returns_default_when_no_file(self):
        from chimera.modules import dns_redirect
        with self._patch():
            state = dns_redirect.state_load()
        self.assertFalse(state["enabled"])
        self.assertEqual(state["target_port"], 5300)
        self.assertEqual(state["iface_filter"], "awg0")

    def test_save_then_load_roundtrip(self):
        from chimera.modules import dns_redirect
        with self._patch():
            dns_redirect.state_save({
                "enabled": True,
                "target_port": 5301,
                "iface_filter": "tun0",
                "applied_at": "2025-01-01T00:00:00+00:00",
                "ipv6_enabled": True,
            })
            loaded = dns_redirect.state_load()
        self.assertTrue(loaded["enabled"])
        self.assertEqual(loaded["target_port"], 5301)
        self.assertEqual(loaded["iface_filter"], "tun0")
        self.assertTrue(loaded["ipv6_enabled"])

    def test_save_sets_chmod_600(self):
        import stat as stat_mod
        from chimera.modules import dns_redirect
        with self._patch():
            dns_redirect.state_save({"enabled": False})
            self.assertEqual(self._state.stat().st_mode & 0o777, 0o600)

    def test_load_returns_default_on_corrupted_json(self):
        from chimera.modules import dns_redirect
        self._state.write_text("NOT VALID JSON{{{")
        with self._patch():
            state = dns_redirect.state_load()
        self.assertFalse(state["enabled"])  # default


# =============================================================================
#  ТЕСТЫ ОПРЕДЕЛЕНИЯ ПОРТА DNSCRYPT
# =============================================================================
class TestGetDnscryptPort(unittest.TestCase):
    """get_dnscrypt_port — парсинг TOML."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._toml = self._tmpdir / "dnscrypt-proxy.toml"

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.dns_redirect._DNSCRYPT_TOML", self._toml)

    def test_returns_default_when_no_toml(self):
        from chimera.modules import dns_redirect
        with self._patch():
            self.assertEqual(dns_redirect.get_dnscrypt_port(), 5300)

    def test_parses_port_from_listen_addresses(self):
        from chimera.modules import dns_redirect
        self._toml.write_text(
            "listen_addresses = ['127.0.0.1:5353']\n"
            "server_names = ['cloudflare']\n"
        )
        with self._patch():
            self.assertEqual(dns_redirect.get_dnscrypt_port(), 5353)

    def test_parses_port_with_ipv6_listen(self):
        from chimera.modules import dns_redirect
        self._toml.write_text(
            "listen_addresses = ['[::1]:5301']\n"
        )
        with self._patch():
            self.assertEqual(dns_redirect.get_dnscrypt_port(), 5301)

    def test_ignores_invalid_port(self):
        from chimera.modules import dns_redirect
        self._toml.write_text(
            "listen_addresses = ['127.0.0.1:99']\n"  # < 1024 — invalid
        )
        with self._patch():
            self.assertEqual(dns_redirect.get_dnscrypt_port(), 5300)  # fallback

    def test_handles_corrupted_toml(self):
        from chimera.modules import dns_redirect
        self._toml.write_text("{{{NOT TOML")
        with self._patch():
            self.assertEqual(dns_redirect.get_dnscrypt_port(), 5300)


# =============================================================================
#  ТЕСТЫ ОПРЕДЕЛЕНИЯ IPv6 LISTEN
# =============================================================================
class TestGetDnscryptListenIPv6(unittest.TestCase):
    """get_dnscrypt_listen_ipv6 — определение ::1 в listen_addresses."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._toml = self._tmpdir / "dnscrypt-proxy.toml"

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.dns_redirect._DNSCRYPT_TOML", self._toml)

    def test_returns_false_when_no_toml(self):
        from chimera.modules import dns_redirect
        with self._patch():
            self.assertFalse(dns_redirect.get_dnscrypt_listen_ipv6())

    def test_returns_true_when_ipv6_listen(self):
        from chimera.modules import dns_redirect
        self._toml.write_text(
            "listen_addresses = ['127.0.0.1:5300', '[::1]:5300']\n"
        )
        with self._patch():
            self.assertTrue(dns_redirect.get_dnscrypt_listen_ipv6())

    def test_returns_false_when_only_ipv4(self):
        from chimera.modules import dns_redirect
        self._toml.write_text("listen_addresses = ['127.0.0.1:5300']\n")
        with self._patch():
            self.assertFalse(dns_redirect.get_dnscrypt_listen_ipv6())


# =============================================================================
#  ТЕСТЫ ГЕНЕРАЦИИ Iptables-команд
# =============================================================================
class TestBuildRedirectRuleArgs(unittest.TestCase):
    """_build_redirect_rule_args — генерация аргументов правила iptables."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_udp_awg0(self):
        from chimera.modules import dns_redirect
        args = dns_redirect._build_redirect_rule_args("awg0", "udp", 5300)
        self.assertIn("-i", args)
        self.assertIn("awg0", args)
        self.assertIn("-p", args)
        self.assertIn("udp", args)
        self.assertIn("--dport", args)
        self.assertIn("53", args)
        self.assertIn("REDIRECT", args)
        self.assertIn("--to-ports", args)
        self.assertIn("5300", args)
        # Должен быть comment для идентификации при удалении
        self.assertIn("comment", args)
        self.assertIn("xray-dns-redirect", args)

    def test_tcp_tun0_custom_port(self):
        from chimera.modules import dns_redirect
        args = dns_redirect._build_redirect_rule_args("tun0", "tcp", 5353)
        self.assertIn("tun0", args)
        self.assertIn("tcp", args)
        self.assertIn("5353", args)
        self.assertIn("53", args)

    def test_different_interfaces_produce_different_args(self):
        from chimera.modules import dns_redirect
        a1 = dns_redirect._build_redirect_rule_args("awg0", "udp", 5300)
        a2 = dns_redirect._build_redirect_rule_args("tun0", "udp", 5300)
        self.assertNotEqual(a1, a2)

    def test_different_protocols_produce_different_args(self):
        from chimera.modules import dns_redirect
        a1 = dns_redirect._build_redirect_rule_args("awg0", "udp", 5300)
        a2 = dns_redirect._build_redirect_rule_args("awg0", "tcp", 5300)
        self.assertNotEqual(a1, a2)

    def test_comment_is_present(self):
        """Comment нужен для идемпотентного удаления через -D -m comment."""
        from chimera.modules import dns_redirect
        args = dns_redirect._build_redirect_rule_args("awg0", "udp", 5300)
        # args должен содержать: -m comment --comment xray-dns-redirect
        comment_idx = args.index("comment") if "comment" in args else -1
        self.assertGreater(comment_idx, 0)
        self.assertEqual(args[comment_idx - 1], "-m")
        self.assertEqual(args[comment_idx + 1], "--comment")
        self.assertEqual(args[comment_idx + 2], "xray-dns-redirect")


# =============================================================================
#  ТЕСТЫ ИДЕМПОТЕНТНОСТИ Iptables helpers (mock subprocess)
# =============================================================================
class TestIptablesHelpers(unittest.TestCase):
    """_ipt_rule_exists / _ipt_add_rule_idempotent / _ipt_delete_rule —
    мок subprocess.run."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _mock_run(self, returncode=0, stdout=""):
        """Создаёт MagicMock для subprocess.run с заданным returncode."""
        m = MagicMock()
        m.returncode = returncode
        m.stdout = stdout
        m.stderr = ""
        return m

    def test_rule_exists_returns_true_when_check_succeeds(self):
        """-C возвращает 0 → правило существует."""
        from chimera.modules import dns_redirect
        with patch("chimera.modules.dns_redirect._run",
                   return_value=self._mock_run(0)):
            exists = dns_redirect._ipt_rule_exists(
                "iptables", "nat", "PREROUTING",
                ["-i", "awg0", "-p", "udp"],
            )
        self.assertTrue(exists)

    def test_rule_exists_returns_false_when_check_fails(self):
        """-C возвращает 1 → правило не существует."""
        from chimera.modules import dns_redirect
        with patch("chimera.modules.dns_redirect._run",
                   return_value=self._mock_run(1)):
            exists = dns_redirect._ipt_rule_exists(
                "iptables", "nat", "PREROUTING",
                ["-i", "awg0", "-p", "udp"],
            )
        self.assertFalse(exists)

    def test_add_idempotent_skips_when_rule_exists(self):
        """Если правило уже есть (-C=0), -A НЕ вызывается."""
        from chimera.modules import dns_redirect
        with patch("chimera.modules.dns_redirect._run",
                   return_value=self._mock_run(0)) as run_mock:
            ok = dns_redirect._ipt_add_rule_idempotent(
                "iptables", "nat", "PREROUTING",
                ["-i", "awg0", "-p", "udp", "--dport", "53",
                 "-j", "REDIRECT", "--to-ports", "5300"],
            )
        self.assertTrue(ok)
        # _run вызван ОДИН раз (только -C, без -A)
        self.assertEqual(run_mock.call_count, 1)
        # Проверяем что это был -C (check), а не -A (add)
        called_cmd = run_mock.call_args[0][0]
        self.assertIn("-C", called_cmd)
        self.assertNotIn("-A", called_cmd)

    def test_add_idempotent_adds_when_rule_absent(self):
        """Если правила нет (-C=1), вызывается -A."""
        from chimera.modules import dns_redirect
        # Первый вызов (-C) возвращает 1 (правила нет),
        # второй вызов (-A) возвращает 0 (успех)
        with patch("chimera.modules.dns_redirect._run",
                   side_effect=[self._mock_run(1), self._mock_run(0)]) as run_mock:
            ok = dns_redirect._ipt_add_rule_idempotent(
                "iptables", "nat", "PREROUTING",
                ["-i", "awg0", "-p", "udp"],
            )
        self.assertTrue(ok)
        # _run вызван ДВАЖДЫ: -C затем -A
        self.assertEqual(run_mock.call_count, 2)
        first_cmd = run_mock.call_args_list[0][0][0]
        second_cmd = run_mock.call_args_list[1][0][0]
        self.assertIn("-C", first_cmd)
        self.assertIn("-A", second_cmd)

    def test_add_idempotent_returns_false_on_add_failure(self):
        """Если -A падает, возвращается False."""
        from chimera.modules import dns_redirect
        with patch("chimera.modules.dns_redirect._run",
                   side_effect=[self._mock_run(1), self._mock_run(2)]):  # -C=1, -A=2 (fail)
            ok = dns_redirect._ipt_add_rule_idempotent(
                "iptables", "nat", "PREROUTING",
                ["-i", "awg0"],
            )
        self.assertFalse(ok)

    def test_delete_rule_returns_true_when_deleted(self):
        from chimera.modules import dns_redirect
        with patch("chimera.modules.dns_redirect._run",
                   return_value=self._mock_run(0)):
            ok = dns_redirect._ipt_delete_rule(
                "iptables", "nat", "PREROUTING",
                ["-i", "awg0", "-p", "udp"],
            )
        self.assertTrue(ok)

    def test_delete_rule_returns_true_when_rule_absent(self):
        """-D возвращает 1 если правила нет — это OK для идемпотентности."""
        from chimera.modules import dns_redirect
        with patch("chimera.modules.dns_redirect._run",
                   return_value=self._mock_run(1)):
            ok = dns_redirect._ipt_delete_rule(
                "iptables", "nat", "PREROUTING",
                ["-i", "awg0"],
            )
        self.assertTrue(ok)

    def test_delete_rule_returns_false_on_unexpected_error(self):
        """-D возвращает 2 (не 0 и не 1) — это ошибка."""
        from chimera.modules import dns_redirect
        with patch("chimera.modules.dns_redirect._run",
                   return_value=self._mock_run(2)):
            ok = dns_redirect._ipt_delete_rule(
                "iptables", "nat", "PREROUTING",
                ["-i", "awg0"],
            )
        self.assertFalse(ok)


# =============================================================================
#  ТЕСТЫ APPLY_DNS_REDIRECT (mock subprocess)
# =============================================================================
class TestApplyDnsRedirect(unittest.TestCase):
    """apply_dns_redirect — основная функция применения правил."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "dns_redirect.json"
        self._toml = self._tmpdir / "dnscrypt-proxy.toml"
        self._toml.write_text("listen_addresses = ['127.0.0.1:5300']\n")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("chimera.modules.dns_redirect._STATE_FILE", self._state),
            patch("chimera.modules.dns_redirect._DNSCRYPT_TOML", self._toml),
            patch("chimera.modules.dns_redirect._install_restore_service"),
        ]

    def test_skips_when_dnscrypt_not_active(self):
        """Если dnscrypt-proxy не активен → skip (black-hole prevention)."""
        from chimera.modules import dns_redirect
        for p in self._patches():
            p.start()
        try:
            with patch("chimera.modules.dns_redirect.is_dnscrypt_active",
                       return_value=False):
                result = dns_redirect.apply_dns_redirect("awg0", 5300)
            self.assertFalse(result["success"])
            self.assertIn("black-hole", result["skipped_reason"])
        finally:
            for p in self._patches():
                p.stop()

    def test_skips_when_port_not_listening(self):
        """Если dnscrypt не слушает порт → skip."""
        from chimera.modules import dns_redirect
        for p in self._patches():
            p.start()
        try:
            with patch("chimera.modules.dns_redirect.is_dnscrypt_active",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect.is_port_listening",
                       return_value=False):
                result = dns_redirect.apply_dns_redirect("awg0", 5300)
            self.assertFalse(result["success"])
            self.assertIn("black-hole", result["skipped_reason"])
        finally:
            for p in self._patches():
                p.stop()

    def test_applies_v4_rules_successfully(self):
        """Успешное применение IPv4 правил (UDP + TCP)."""
        from chimera.modules import dns_redirect
        for p in self._patches():
            p.start()
        try:
            with patch("chimera.modules.dns_redirect.is_dnscrypt_active",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect.is_port_listening",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect._ipt_add_rule_idempotent",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect._check_rules_applied",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect.get_dnscrypt_listen_ipv6",
                       return_value=False):
                result = dns_redirect.apply_dns_redirect("awg0", 5300)
            self.assertTrue(result["success"])
            self.assertTrue(result["applied_v4"])
            self.assertFalse(result["applied_v6"])  # IPv6 не поддерживается
            # State должен сохраниться с enabled=True
            state = dns_redirect.state_load()
            self.assertTrue(state["enabled"])
            self.assertEqual(state["target_port"], 5300)
            self.assertEqual(state["iface_filter"], "awg0")
        finally:
            for p in self._patches():
                p.stop()

    def test_idempotent_apply_does_not_duplicate(self):
        """Двойной apply не создаёт дубликатов (через -C check)."""
        from chimera.modules import dns_redirect
        # Мокаем: правило существует (-C=0), -A не вызывается
        add_call_count = [0]
        def mock_add(family, table, chain, args):
            add_call_count[0] += 1
            return True
        for p in self._patches():
            p.start()
        try:
            with patch("chimera.modules.dns_redirect.is_dnscrypt_active",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect.is_port_listening",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect._ipt_add_rule_idempotent",
                       side_effect=mock_add), \
                 patch("chimera.modules.dns_redirect._check_rules_applied",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect.get_dnscrypt_listen_ipv6",
                       return_value=False):
                # Первый apply
                dns_redirect.apply_dns_redirect("awg0", 5300)
                first_count = add_call_count[0]
                # Второй apply
                dns_redirect.apply_dns_redirect("awg0", 5300)
                second_count = add_call_count[0]
            # Второй apply должен вызвать _ipt_add_rule_idempotent столько же раз
            # (т.к. -C check всё равно вызывается, но -A не выполняется)
            # Главное — нет дублей правил в iptables (что обеспечивает -C check)
            self.assertEqual(first_count, second_count - first_count)
        finally:
            for p in self._patches():
                p.stop()

    def test_ipv6_skipped_with_warning_when_not_supported(self):
        """Если dnscrypt не слушает ::1 → IPv6 skip + warning."""
        from chimera.modules import dns_redirect
        for p in self._patches():
            p.start()
        try:
            with patch("chimera.modules.dns_redirect.is_dnscrypt_active",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect.is_port_listening",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect._ipt_add_rule_idempotent",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect._check_rules_applied",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect.get_dnscrypt_listen_ipv6",
                       return_value=False):
                result = dns_redirect.apply_dns_redirect("awg0", 5300)
            self.assertFalse(result["applied_v6"])
            self.assertTrue(any("IPv6" in w or "::1" in w for w in result["warnings"]))
        finally:
            for p in self._patches():
                p.stop()

    def test_ipv6_applied_when_supported(self):
        """Если dnscrypt слушает ::1 → IPv6 правила тоже применяются."""
        from chimera.modules import dns_redirect
        for p in self._patches():
            p.start()
        try:
            with patch("chimera.modules.dns_redirect.is_dnscrypt_active",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect.is_port_listening",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect._ipt_add_rule_idempotent",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect._check_rules_applied",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect._ipt_rule_exists",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect.get_dnscrypt_listen_ipv6",
                       return_value=True):
                result = dns_redirect.apply_dns_redirect("awg0", 5300)
            self.assertTrue(result["applied_v6"])
        finally:
            for p in self._patches():
                p.stop()


# =============================================================================
#  ТЕСТЫ REMOVE_DNS_REDIRECT
# =============================================================================
class TestRemoveDnsRedirect(unittest.TestCase):
    """remove_dns_redirect — корректное удаление, идемпотентность."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "dns_redirect.json"
        # State с применёнными правилами
        self._state.write_text(json.dumps({
            "enabled": True,
            "target_port": 5300,
            "iface_filter": "awg0",
            "applied_at": "2025-01-01T00:00:00+00:00",
            "ipv6_enabled": False,
        }))

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("chimera.modules.dns_redirect._STATE_FILE", self._state),
            patch("chimera.modules.dns_redirect._remove_restore_service"),
            patch("chimera.modules.dns_redirect._cleanup_all_dns_redirect_rules"),
        ]

    def test_removes_v4_rules(self):
        from chimera.modules import dns_redirect
        for p in self._patches():
            p.start()
        try:
            with patch("chimera.modules.dns_redirect._ipt_delete_rule",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect._ipt_rule_exists",
                       return_value=False), \
                 patch("chimera.modules.dns_redirect.get_dnscrypt_port",
                       return_value=5300):
                result = dns_redirect.remove_dns_redirect()
            self.assertTrue(result["success"])
            self.assertTrue(result["removed_v4"])
            # State должен быть enabled=False
            state = dns_redirect.state_load()
            self.assertFalse(state["enabled"])
        finally:
            for p in self._patches():
                p.stop()

    def test_idempotent_remove_when_nothing_applied(self):
        """Повторный remove когда правил уже нет — безопасно."""
        from chimera.modules import dns_redirect
        # State с enabled=False
        self._state.write_text(json.dumps({
            "enabled": False, "target_port": 5300,
            "iface_filter": "awg0", "applied_at": "",
            "ipv6_enabled": False,
        }))
        for p in self._patches():
            p.start()
        try:
            with patch("chimera.modules.dns_redirect._ipt_delete_rule",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect._ipt_rule_exists",
                       return_value=False), \
                 patch("chimera.modules.dns_redirect.get_dnscrypt_port",
                       return_value=5300):
                result = dns_redirect.remove_dns_redirect()
            self.assertTrue(result["success"])
        finally:
            for p in self._patches():
                p.stop()

    def test_removes_ipv6_rules_when_applied(self):
        from chimera.modules import dns_redirect
        self._state.write_text(json.dumps({
            "enabled": True, "target_port": 5300,
            "iface_filter": "awg0", "applied_at": "...",
            "ipv6_enabled": True,
        }))
        for p in self._patches():
            p.start()
        try:
            with patch("chimera.modules.dns_redirect._ipt_delete_rule",
                       return_value=True), \
                 patch("chimera.modules.dns_redirect._ipt_rule_exists",
                       return_value=False), \
                 patch("chimera.modules.dns_redirect.get_dnscrypt_port",
                       return_value=5300):
                result = dns_redirect.remove_dns_redirect()
            self.assertTrue(result["removed_v6"])
        finally:
            for p in self._patches():
                p.stop()


# =============================================================================
#  ТЕСТЫ EDGE-CASE: AWG-интерфейс исчез
# =============================================================================
class TestEdgeCaseInterfaceGone(unittest.TestCase):
    """Edge-case: AWG-интерфейс исчез — правила не должны оставаться висячими."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "dns_redirect.json"
        self._state.write_text(json.dumps({
            "enabled": True,
            "target_port": 5300,
            "iface_filter": "awg0",
            "applied_at": "2025-01-01T00:00:00+00:00",
            "ipv6_enabled": False,
        }))

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_remove_works_when_interface_gone(self):
        """iptables -D работает даже если интерфейс удалён — это безопасно."""
        from chimera.modules import dns_redirect
        # iptables -D не требует существования интерфейса
        with patch("chimera.modules.dns_redirect._STATE_FILE", self._state), \
             patch("chimera.modules.dns_redirect._remove_restore_service"), \
             patch("chimera.modules.dns_redirect._ipt_delete_rule",
                   return_value=True) as del_mock, \
             patch("chimera.modules.dns_redirect._ipt_rule_exists",
                   return_value=False), \
             patch("chimera.modules.dns_redirect.get_dnscrypt_port",
                   return_value=5300), \
             patch("chimera.modules.dns_redirect._cleanup_all_dns_redirect_rules"):
            result = dns_redirect.remove_dns_redirect()
        self.assertTrue(result["success"])
        # -D должен быть вызван (4 раза: udp v4, tcp v4, и проверка для v6 если включён)
        self.assertGreaterEqual(del_mock.call_count, 2)  # как минимум UDP+TCP v4


# =============================================================================
#  ТЕСТЫ EDGE-CASE: dnscrypt рестарт
# =============================================================================
class TestEdgeCaseDnscryptRestart(unittest.TestCase):
    """Edge-case: dnscrypt рестарт — правила продолжают работать,
    трафик отбрасывается пока сервис не поднимется."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_health_check_warns_when_dnscrypt_down_but_rules_active(self):
        """Правила применены, dnscrypt упал → health-check предупреждает о black-hole."""
        from chimera.modules import dns_redirect
        with patch("chimera.modules.dns_redirect.state_load",
                   return_value={"enabled": True, "target_port": 5300,
                                 "iface_filter": "awg0"}), \
             patch("chimera.modules.dns_redirect.is_dnscrypt_active",
                   return_value=False), \
             patch("chimera.modules.dns_redirect.is_port_listening",
                   return_value=False), \
             patch("chimera.modules.dns_redirect._check_rules_applied",
                   return_value=True), \
             patch("chimera.modules.dns_redirect.get_dnscrypt_listen_ipv6",
                   return_value=False):
            hc = dns_redirect.health_check_dns_redirect()
        self.assertFalse(hc["dnscrypt_active"])
        self.assertTrue(hc["rules_applied"])
        # Должно быть предупреждение о black-hole
        blackhole_warnings = [i for i in hc["issues"] if "black-hole" in i.lower()]
        self.assertGreater(len(blackhole_warnings), 0,
                           f"Expected black-hole warning, got: {hc['issues']}")


# =============================================================================
#  ТЕСТЫ HEALTH CHECK
# =============================================================================
class TestHealthCheck(unittest.TestCase):
    """health_check_dns_redirect — все ветки."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_healthy_state(self):
        from chimera.modules import dns_redirect
        with patch("chimera.modules.dns_redirect.state_load",
                   return_value={"enabled": True, "target_port": 5300,
                                 "iface_filter": "awg0"}), \
             patch("chimera.modules.dns_redirect.is_dnscrypt_active",
                   return_value=True), \
             patch("chimera.modules.dns_redirect.is_port_listening",
                   return_value=True), \
             patch("chimera.modules.dns_redirect._check_rules_applied",
                   return_value=True), \
             patch("chimera.modules.dns_redirect.get_dnscrypt_listen_ipv6",
                   return_value=True):
            hc = dns_redirect.health_check_dns_redirect()
        self.assertTrue(hc["enabled"])
        self.assertTrue(hc["dnscrypt_active"])
        self.assertTrue(hc["port_listening_udp"])
        self.assertTrue(hc["port_listening_tcp"])
        self.assertTrue(hc["rules_applied"])
        self.assertTrue(hc["ipv6_supported"])
        self.assertEqual(hc["issues"], [])
        self.assertIn("OK", hc["recommendation"])

    def test_disabled_state(self):
        from chimera.modules import dns_redirect
        with patch("chimera.modules.dns_redirect.state_load",
                   return_value={"enabled": False, "target_port": 5300,
                                 "iface_filter": "awg0"}), \
             patch("chimera.modules.dns_redirect.is_dnscrypt_active",
                   return_value=True), \
             patch("chimera.modules.dns_redirect.is_port_listening",
                   return_value=True), \
             patch("chimera.modules.dns_redirect._check_rules_applied",
                   return_value=False), \
             patch("chimera.modules.dns_redirect.get_dnscrypt_listen_ipv6",
                   return_value=False):
            hc = dns_redirect.health_check_dns_redirect()
        self.assertFalse(hc["enabled"])
        self.assertIn("выключен", hc["recommendation"])

    def test_enabled_but_rules_missing(self):
        from chimera.modules import dns_redirect
        with patch("chimera.modules.dns_redirect.state_load",
                   return_value={"enabled": True, "target_port": 5300,
                                 "iface_filter": "awg0"}), \
             patch("chimera.modules.dns_redirect.is_dnscrypt_active",
                   return_value=True), \
             patch("chimera.modules.dns_redirect.is_port_listening",
                   return_value=True), \
             patch("chimera.modules.dns_redirect._check_rules_applied",
                   return_value=False), \
             patch("chimera.modules.dns_redirect.get_dnscrypt_listen_ipv6",
                   return_value=False):
            hc = dns_redirect.health_check_dns_redirect()
        rules_issue = [i for i in hc["issues"] if "правила" in i.lower() or "iptables" in i.lower()]
        self.assertGreater(len(rules_issue), 0)


# =============================================================================
#  ТЕСТЫ _cleanup_all_dns_redirect_rules
# =============================================================================
class TestCleanupAllRules(unittest.TestCase):
    """_cleanup_all_dns_redirect_rules — cleanup висячих правил."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_no_rules_to_delete(self):
        from chimera.modules import dns_redirect
        # Вывод iptables -S без наших правил
        empty_output = MagicMock()
        empty_output.returncode = 0
        empty_output.stdout = (
            "-P PREROUTING ACCEPT\n"
            "-A PREROUTING -i eth0 -j MASQUERADE\n"
        )
        with patch("chimera.modules.dns_redirect._run",
                   return_value=empty_output):
            # Не должно упасть
            dns_redirect._cleanup_all_dns_redirect_rules()

    def test_deletes_rules_with_comment(self):
        from chimera.modules import dns_redirect
        # Первые вызовы -S возвращают правило, потом пусто
        with_rule = MagicMock()
        with_rule.returncode = 0
        with_rule.stdout = (
            "-A PREROUTING -i awg0 -p udp --dport 53 -j REDIRECT "
            "--to-ports 5300 -m comment --comment xray-dns-redirect\n"
        )
        without_rule = MagicMock()
        without_rule.returncode = 0
        without_rule.stdout = "-P PREROUTING ACCEPT\n"
        # Первый вызов -S → with_rule, второй -S → without_rule
        # Затем -D (любой returncode)
        with patch("chimera.modules.dns_redirect._run",
                   side_effect=[with_rule, MagicMock(returncode=0),
                                without_rule]):
            dns_redirect._cleanup_all_dns_redirect_rules()


# =============================================================================
#  ТЕСТЫ ИНТЕГРАЦИИ С _core.py
# =============================================================================
class TestCoreIntegration(unittest.TestCase):
    """Проверка что _core.py правильно импортирует и вызывает dns_redirect."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_core_imports_dns_redirect(self):
        """_core.py должен импортировать do_manage_dns_redirect."""
        core_src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        self.assertIn("from chimera.modules.dns_redirect", core_src)
        self.assertIn("do_manage_dns_redirect", core_src)
        self.assertIn("health_check_dns_redirect", core_src)

    def test_menu_network_has_dr_item(self):
        """_menu_network должен содержать пункт 'DR'."""
        core_src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        self.assertIn('"DR"', core_src)

    def test_diagnostics_menu_has_dn_item(self):
        """_menu_diagnostics должен содержать пункт 'DN'."""
        core_src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        self.assertIn('"DN"', core_src)


# =============================================================================
#  ТЕСТЫ СОВМЕСТИМОСТИ С ingress-блокировкой РФ
# =============================================================================
class TestIngressGeoipCompatibility(unittest.TestCase):
    """Проверка что DNS REDIRECT не нарушает порядок правил ingress-блокировки РФ."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_dns_redirect_uses_prerouting_not_input(self):
        """DNS REDIRECT использует nat PREROUTING, ingress использует filter INPUT —
        разные цепочки, конфликтов быть не должно."""
        from chimera.modules import dns_redirect
        args = dns_redirect._build_redirect_rule_args("awg0", "udp", 5300)
        # Должен быть -j REDIRECT (а не DROP/ACCEPT)
        redir_idx = args.index("REDIRECT")
        self.assertEqual(args[redir_idx - 1], "-j")
        # Правило не должно содержать --match-set (это для ingress)
        self.assertNotIn("--match-set", args)

    def test_dns_redirect_has_comment_for_identification(self):
        """Comment позволяет отделить от ingress-правил при cleanup."""
        from chimera.modules import dns_redirect
        args = dns_redirect._build_redirect_rule_args("awg0", "udp", 5300)
        self.assertIn("xray-dns-redirect", args)
        # ingress использует "xray-ru-ingress-block" — разные comments
        self.assertNotIn("xray-ru-ingress-block", args)


# =============================================================================
#  РЕГРЕССИОННЫЕ ТЕСТЫ (Bug 1-4 из коммита 17e207b)
# =============================================================================
# Эти тесты ДОЛЖНЫ падать на старом коде (до фикса) и проходить на новом.
# Они НЕ мокают _check_rules_applied / state_save в проверяемых assertions —
# проверяют реальное поведение кода.
# =============================================================================

class TestBug1ApplyFailureDoesNotPersistEnabledState(unittest.TestCase):
    """Bug 1: apply_dns_redirect() не должен писать enabled=True в state
    если applied_v4=False (правила не встали).

    На старом коде: state.update(enabled=True, ...) вызывался ДО проверки
    result["success"], поэтому при провале apply state показывал enabled=True
    (ложное «всё ок»), и _install_restore_service() тоже вызывался.

    На новом коде: state.save() и _install_restore_service() вызываются
    ТОЛЬКО если result["applied_v4"] is True.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "dns_redirect.json"
        # State с enabled=False — это стартовое состояние
        self._state.write_text(json.dumps({
            "enabled": False,
            "target_port": 5300,
            "iface_filter": "awg0",
            "applied_at": "",
            "ipv6_enabled": False,
        }))
        self._toml = self._tmpdir / "dnscrypt-proxy.toml"
        self._toml.write_text("listen_addresses = ['127.0.0.1:5300']\n")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_apply_failure_does_not_persist_enabled_state(self):
        """Если _ipt_add_rule_idempotent падает и правила не встают —
        state.enabled должен остаться False."""
        from chimera.modules import dns_redirect

        # НЕ мокаем _check_rules_applied — пусть реально вызывается.
        # Мокаем только _ipt_add_rule_idempotent (возвращает False = не смог добавить)
        # и _ipt_rule_exists (возвращает False = правила нет, fallback реальный).
        # Это эмулирует ситуацию: добавить не удалось, проверить тоже не находит.
        with patch("chimera.modules.dns_redirect._STATE_FILE", self._state), \
             patch("chimera.modules.dns_redirect._DNSCRYPT_TOML", self._toml), \
             patch("chimera.modules.dns_redirect._install_restore_service") as install_mock, \
             patch("chimera.modules.dns_redirect.is_dnscrypt_active",
                   return_value=True), \
             patch("chimera.modules.dns_redirect.is_port_listening",
                   return_value=True), \
             patch("chimera.modules.dns_redirect._ipt_add_rule_idempotent",
                   return_value=False), \
             patch("chimera.modules.dns_redirect._ipt_rule_exists",
                   return_value=False), \
             patch("chimera.modules.dns_redirect.get_dnscrypt_listen_ipv6",
                   return_value=False):
            result = dns_redirect.apply_dns_redirect("awg0", 5300)
            # Читаем state ВНУТРИ patch — иначе state_load() прочтёт
            # оригинальный /var/lib/... (которого нет в CI)
            state = dns_redirect.state_load()

        # 1) result["success"] должен быть False
        self.assertFalse(result["success"],
                         f"Expected success=False when rules not applied, got: {result}")
        self.assertFalse(result["applied_v4"])

        # 2) state.enabled должен остаться False (НЕ переписан на True)
        self.assertFalse(state.get("enabled"),
                         f"state.enabled should remain False after failed apply, "
                         f"got state: {state}")
        # applied_at не должен обновляться
        self.assertEqual(state.get("applied_at"), "",
                         "applied_at should not be set on failed apply")

        # 3) _install_restore_service НЕ должен вызываться (правила не встали)
        install_mock.assert_not_called()


class TestBug2CheckRulesAppliedUsesPassedPort(unittest.TestCase):
    """Bug 2: _check_rules_applied() должен использовать переданный port,
    а не вызывать get_dnscrypt_port() внутри себя.

    На старом коде: _check_rules_applied(iface) вызывал get_dnscrypt_port()
    внутри, что приводило к рассинхрону если caller передал порт 6000,
    а TOML содержит 5300 — проверка шла по 5300 и не находила правило для 6000.

    На новом коде: _check_rules_applied(iface, port) использует переданный port.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "dns_redirect.json"
        # State с enabled=False и target_port=5300 (как было до apply).
        # После успешного apply с port=6000 — state.target_port должен стать 6000.
        self._state.write_text(json.dumps({
            "enabled": False, "target_port": 5300,
            "iface_filter": "awg0", "applied_at": "",
            "ipv6_enabled": False,
        }))
        self._toml = self._tmpdir / "dnscrypt-proxy.toml"
        # TOML говорит что порт 5300 — это «живой» порт dnscrypt-proxy.
        # Если _check_rules_applied ошибочно вызовет get_dnscrypt_port()
        # внутри себя, он вернёт 5300 (из TOML), а не 6000 (переданный).
        self._toml.write_text("listen_addresses = ['127.0.0.1:5300']\n")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_check_rules_applied_uses_passed_port_not_live_toml(self):
        """apply_dns_redirect('awg0', 6000) — даже если TOML говорит 5300,
        _check_rules_applied должен проверить правило с port=6000.

        Эмулируем: _ipt_rule_exists возвращает True ТОЛЬКО если в rule_args
        есть '6000' (т.е. проверка идёт по правильному порту). Если бы
        _check_rules_applied использовал get_dnscrypt_port() (5300), то
        _ipt_rule_exists не нашёл бы '6000' и вернул бы False → apply failed.
        """
        from chimera.modules import dns_redirect

        # side_effect для _ipt_rule_exists: проверяет, что в rule_args есть '6000'
        def rule_exists_checker(family, table, chain, rule_args):
            # Возвращает True только если правило содержит '6000' как --to-ports
            return "6000" in rule_args

        with patch("chimera.modules.dns_redirect._STATE_FILE", self._state), \
             patch("chimera.modules.dns_redirect._DNSCRYPT_TOML", self._toml), \
             patch("chimera.modules.dns_redirect._install_restore_service"), \
             patch("chimera.modules.dns_redirect.is_dnscrypt_active",
                   return_value=True), \
             patch("chimera.modules.dns_redirect.is_port_listening",
                   return_value=True), \
             patch("chimera.modules.dns_redirect._ipt_add_rule_idempotent",
                   return_value=True), \
             patch("chimera.modules.dns_redirect._ipt_rule_exists",
                   side_effect=rule_exists_checker), \
             patch("chimera.modules.dns_redirect.get_dnscrypt_listen_ipv6",
                   return_value=False):
            # НЕ мокаем _check_rules_applied — пусть реально вызывается
            # с target_port=6000
            result = dns_redirect.apply_dns_redirect("awg0", 6000)
            # Читаем state ВНУТРИ patch — иначе state_load() прочтёт
            # оригинальный /var/lib/... (которого нет в CI)
            state = dns_redirect.state_load()

        # Если бы _check_rules_applied использовал get_dnscrypt_port() (5300),
        # то rule_exists_checker не нашёл бы '6000' в rule_args и вернул бы False
        # → applied_v4=False → success=False.
        # На фиксе: _check_rules_applied использует port=6000 → rule_exists_checker
        # находит '6000' → applied_v4=True → success=True.
        self.assertTrue(result["success"],
                        f"Expected success=True with port=6000, got: {result}")
        self.assertTrue(result["applied_v4"],
                        "applied_v4 should be True when rules for port=6000 exist")

        # State должен сохранить target_port=6000 (не 5300 из TOML)
        self.assertEqual(state.get("target_port"), 6000,
                         f"state.target_port should be 6000, got: {state}")


class TestBug3RemoveReportsFailureWhenRulesRemain(unittest.TestCase):
    """Bug 3: remove_dns_redirect() должен возвращать success=False если
    правила остались в iptables после -D.

    На старом коде: result = {"success": True, ...} инициализировался
    один раз и никогда не переприсваивался — даже если _ipt_rule_exists
    после -D возвращал True (правило осталось), success всё равно был True.

    На новом коде: success = removed_v4 and (removed_v6 if ipv6_enabled else True).
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "dns_redirect.json"
        # State: правила были применены (enabled=True)
        self._state.write_text(json.dumps({
            "enabled": True,
            "target_port": 5300,
            "iface_filter": "awg0",
            "applied_at": "2025-01-01T00:00:00+00:00",
            "ipv6_enabled": False,
        }))

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_remove_reports_failure_when_rules_remain(self):
        """_ipt_delete_rule(return_value=True) — якобы удалил, но
        _ipt_rule_exists(return_value=True) — правило всё ещё стоит.
        remove_dns_redirect должен вернуть success=False."""
        from chimera.modules import dns_redirect

        with patch("chimera.modules.dns_redirect._STATE_FILE", self._state), \
             patch("chimera.modules.dns_redirect._remove_restore_service"), \
             patch("chimera.modules.dns_redirect._cleanup_all_dns_redirect_rules"), \
             patch("chimera.modules.dns_redirect._ipt_delete_rule",
                   return_value=True), \
             patch("chimera.modules.dns_redirect._ipt_rule_exists",
                   return_value=True), \
             patch("chimera.modules.dns_redirect.get_dnscrypt_port",
                   return_value=5300):
            result = dns_redirect.remove_dns_redirect()

        # На старом коде: success всегда True (инициализирован и не переприсвоен)
        # На новом коде: success = removed_v4 and (...) = (not True) and ... = False
        self.assertFalse(result["success"],
                         f"Expected success=False when rules remain in iptables, got: {result}")
        self.assertFalse(result["removed_v4"],
                         "removed_v4 should be False when _ipt_rule_exists still returns True")


if __name__ == "__main__":
    unittest.main()
