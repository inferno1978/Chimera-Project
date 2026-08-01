#!/usr/bin/env python3
"""
tests/test_resolv_conf_fix.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/resolv_conf_fix.py — автоматическое исправление
/etc/resolv.conf для предотвращения DNS-leak.

Покрывает:
  1. diagnose_resolv_conf — диагностика состояния.
  2. fix_resolv_conf_to_localhost — программный fix (systemd_resolved/static).
  3. rollback_resolv_conf — откат.
  4. Pre-flight checks: фикс отменяется, если DNSCrypt не активен/не слушает.
  5. Idempotency: повторный фикс не ломает state.

Все внешние команды (systemctl, resolvectl, ss, os.readlink, Path.read_text)
мокаются — тесты не требуют root и не меняют реальный /etc/resolv.conf.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Фейковый chimera._core (как в test_health.py / test_chain_nodes.py)."""
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
    return fake_core, g


# ══════════════════════════════════════════════════════════════════════════════
#  Helper: мок всей внешней среды для resolv_conf_fix
# ══════════════════════════════════════════════════════════════════════════════
def _mock_run_factory(cmd_to_result: dict):
    """Создаёт mock _run() с заданным соответствием cmd → result.

    cmd_to_result: dict[cmd_prefix_tuple, MagicMock]
    Например: {("systemctl", "is-active", "systemd-resolved"): MagicMock(...)}
    """
    def _mock_run(cmd, capture=False, quiet=False, check=False, **kw):
        # Находим ближайший match по prefix
        for prefix, result in cmd_to_result.items():
            if tuple(cmd[:len(prefix)]) == prefix:
                return result
        # Дефолт: успешный пустой результат
        return MagicMock(returncode=0, stdout="", stderr="")
    return _mock_run


def _make_completed(rc=0, stdout="", stderr=""):
    return MagicMock(returncode=rc, stdout=stdout, stderr=stderr)


class _BaseTest(unittest.TestCase):
    """Общий setUp: фейковый _core, tmpdir для state-файла."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        # Патчим _STATE_FILE / _BACKUP / _RESOLV_CONF / _RESOLVED_DROPIN_*
        # на пути внутри tmpdir.
        self._state_file = self._tmpdir / "resolv_conf_fix.json"
        self._backup_file = self._tmpdir / "resolv.conf.chimera.bak"
        self._resolv_conf = self._tmpdir / "resolv.conf"
        self._dropin_dir = self._tmpdir / "resolved.conf.d"
        self._dropin_file = self._dropin_dir / "chimera-dns.conf"
        self._dnscrypt_toml = self._tmpdir / "dnscrypt-proxy.toml"

        patches = [
            patch("chimera.modules.resolv_conf_fix._STATE_FILE", self._state_file),
            patch("chimera.modules.resolv_conf_fix._BACKUP", self._backup_file),
            patch("chimera.modules.resolv_conf_fix._RESOLV_CONF", self._resolv_conf),
            patch("chimera.modules.resolv_conf_fix._RESOLVED_DROPIN_DIR", self._dropin_dir),
            patch("chimera.modules.resolv_conf_fix._RESOLVED_DROPIN_FILE", self._dropin_file),
            patch("chimera.modules.resolv_conf_fix._DNSCRYPT_TOML", self._dnscrypt_toml),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)


# ══════════════════════════════════════════════════════════════════════════════
#  diagnose_resolv_conf — диагностика
# ══════════════════════════════════════════════════════════════════════════════
class TestDiagnoseResolvConf(_BaseTest):
    """diagnose_resolv_conf: разбор состояния /etc/resolv.conf + systemd-resolved."""

    def test_no_resolv_conf_returns_no_fix(self):
        """Файл /etc/resolv.conf не существует → fix_needed=False."""
        from chimera.modules import resolv_conf_fix
        # resolv_conf не существует (setUp его не создаёт).
        with patch.object(resolv_conf_fix, "_run",
                          return_value=_make_completed(rc=3, stdout="inactive")):
            diag = resolv_conf_fix.diagnose_resolv_conf()
        self.assertFalse(diag["resolv_conf_exists"])
        self.assertFalse(diag["fix_needed"])

    def test_resolv_conf_on_localhost_no_fix(self):
        """resolv.conf → 127.0.0.1, systemd-resolved не активен → fix not needed."""
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.write_text("nameserver 127.0.0.1\n")
        cmd_to_result = {
            ("systemctl", "is-active", "systemd-resolved"):
                _make_completed(rc=3, stdout="inactive"),
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(stdout="active"),
            ("ss", "-tlnu"): _make_completed(
                stdout="UDP  127.0.0.1:5300  0.0.0.0:*"),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)):
            diag = resolv_conf_fix.diagnose_resolv_conf()
        self.assertTrue(diag["resolv_conf_already_localhost"])
        self.assertFalse(diag["fix_needed"])

    def test_resolv_conf_external_dns_fix_needed_static(self):
        """resolv.conf → 8.8.8.8, systemd-resolved не активен → static fix."""
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.write_text("nameserver 8.8.8.8\n")
        cmd_to_result = {
            ("systemctl", "is-active", "systemd-resolved"):
                _make_completed(rc=3, stdout="inactive"),
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(stdout="active"),
            ("ss", "-tlnu"): _make_completed(
                stdout="UDP  127.0.0.1:5300  0.0.0.0:*"),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)):
            diag = resolv_conf_fix.diagnose_resolv_conf()
        self.assertTrue(diag["fix_needed"])
        self.assertEqual(diag["fix_method"], "static_resolv_conf")
        self.assertIn("8.8.8.8", str(diag["leak_reasons"]))

    def test_systemd_resolved_with_per_link_dhcp_dns(self):
        """Ubuntu 24.04 кейс: systemd-resolved + Link eth0: 5.45.240.203 (DHCP).

        Симптом из баг-репорта пользователя.
        """
        from chimera.modules import resolv_conf_fix
        # resolv.conf — симлинк на stub.
        self._resolv_conf.symlink_to("/run/systemd/resolve/stub-resolv.conf")
        cmd_to_result = {
            ("systemctl", "is-active", "systemd-resolved"):
                _make_completed(stdout="active"),
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(stdout="active"),
            ("resolvectl", "dns"): _make_completed(
                stdout="Global:\nLink 2 (eth0): 5.45.240.203 37.140.169.116\n"),
            ("ss", "-tlnu"): _make_completed(
                stdout="UDP  127.0.0.1:5300  0.0.0.0:*"),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)):
            diag = resolv_conf_fix.diagnose_resolv_conf()
        self.assertTrue(diag["fix_needed"])
        self.assertEqual(diag["fix_method"], "systemd_resolved")
        # Должен увидеть IP-адрес провайдера в причинах
        reasons_str = str(diag["leak_reasons"])
        self.assertIn("5.45.240.203", reasons_str)
        self.assertIn("eth0", reasons_str)

    def test_dnscrypt_not_active_no_fix(self):
        """DNSCrypt не активен → фикс отменяется (black-hole risk)."""
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.write_text("nameserver 8.8.8.8\n")
        cmd_to_result = {
            ("systemctl", "is-active", "systemd-resolved"):
                _make_completed(rc=3, stdout="inactive"),
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(rc=3, stdout="inactive"),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=None):
            diag = resolv_conf_fix.diagnose_resolv_conf()
        # Утечка есть, но фикс невозможен
        self.assertFalse(diag["fix_needed"])
        self.assertTrue(any("DNSCrypt" in r for r in diag["leak_reasons"]))

    def test_dnscrypt_not_listening_no_fix(self):
        """DNSCrypt активен, но не слушает порт → фикс отменяется."""
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.write_text("nameserver 8.8.8.8\n")
        cmd_to_result = {
            ("systemctl", "is-active", "systemd-resolved"):
                _make_completed(rc=3, stdout="inactive"),
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(stdout="active"),
            ("ss", "-tlnu"): _make_completed(stdout=""),  # никто не слушает
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)):
            diag = resolv_conf_fix.diagnose_resolv_conf()
        self.assertFalse(diag["fix_needed"])
        self.assertTrue(any("DNSCrypt" in r for r in diag["leak_reasons"]))


# ══════════════════════════════════════════════════════════════════════════════
#  fix_resolv_conf_to_localhost — программный fix
# ══════════════════════════════════════════════════════════════════════════════
class TestFixResolvConfToLocahost(_BaseTest):
    """fix_resolv_conf_to_localhost: применение фикса."""

    def test_static_resolv_conf_fix_writes_localhost(self):
        """Static resolv.conf → backup + rewrite to 127.0.0.1."""
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.write_text("nameserver 8.8.8.8\n")
        cmd_to_result = {
            ("systemctl", "is-active", "systemd-resolved"):
                _make_completed(rc=3, stdout="inactive"),
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(stdout="active"),
            ("ss", "-tlnu"): _make_completed(
                stdout="UDP  127.0.0.1:5300  0.0.0.0:*"),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)):
            result = resolv_conf_fix.fix_resolv_conf_to_localhost()
        self.assertTrue(result["ok"])
        self.assertEqual(result["method"], "static_resolv_conf")
        # Проверяем, что resolv.conf переписан
        content = self._resolv_conf.read_text()
        self.assertIn("nameserver 127.0.0.1", content)
        self.assertNotIn("8.8.8.8", content)
        # Проверяем, что бэкап создан и содержит оригинальный контент
        backup_content = self._backup_file.read_text()
        self.assertIn("nameserver 8.8.8.8", backup_content)
        # State сохранён
        state = json.loads(self._state_file.read_text())
        self.assertTrue(state["fixed"])
        self.assertEqual(state["method"], "static_resolv_conf")

    def test_systemd_resolved_fix_creates_dropin(self):
        """systemd-resolved кейс: создаётся drop-in + resolvectl вызовы."""
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.symlink_to("/run/systemd/resolve/stub-resolv.conf")
        cmd_to_result = {
            ("systemctl", "is-active", "systemd-resolved"):
                _make_completed(stdout="active"),
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(stdout="active"),
            ("resolvectl", "dns"): _make_completed(
                stdout="Global:\nLink 2 (eth0): 5.45.240.203\n"),
            ("resolvectl", "dns-global"): _make_completed(rc=0),
            ("resolvectl", "dns-default-route"): _make_completed(rc=0),
            ("resolvectl", "flush-caches"): _make_completed(rc=0),
            ("systemctl", "restart", "systemd-resolved"): _make_completed(rc=0),
            ("ss", "-tlnu"): _make_completed(
                stdout="UDP  127.0.0.1:5300  0.0.0.0:*"),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)):
            result = resolv_conf_fix.fix_resolv_conf_to_localhost()
        self.assertTrue(result["ok"])
        self.assertEqual(result["method"], "systemd_resolved")
        # drop-in создан
        self.assertTrue(self._dropin_file.exists())
        dropin_content = self._dropin_file.read_text()
        self.assertIn("DNS=127.0.0.1", dropin_content)
        self.assertIn("[Resolve]", dropin_content)
        # State сохранён
        state = json.loads(self._state_file.read_text())
        self.assertTrue(state["fixed"])
        self.assertEqual(state["method"], "systemd_resolved")
        self.assertIn("dropin_path", state)

    def test_fix_returns_error_when_not_needed(self):
        """Если fix не нужен — возвращается ok=False с объяснением."""
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.write_text("nameserver 127.0.0.1\n")
        cmd_to_result = {
            ("systemctl", "is-active", "systemd-resolved"):
                _make_completed(rc=3, stdout="inactive"),
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(stdout="active"),
            ("ss", "-tlnu"): _make_completed(
                stdout="UDP  127.0.0.1:5300  0.0.0.0:*"),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)):
            result = resolv_conf_fix.fix_resolv_conf_to_localhost()
        self.assertFalse(result["ok"])
        self.assertIsNone(result["method"])

    def test_dry_run_does_not_modify(self):
        """dry_run=True — ничего не меняет, возвращает actions для отображения."""
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.write_text("nameserver 8.8.8.8\n")
        cmd_to_result = {
            ("systemctl", "is-active", "systemd-resolved"):
                _make_completed(rc=3, stdout="inactive"),
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(stdout="active"),
            ("ss", "-tlnu"): _make_completed(
                stdout="UDP  127.0.0.1:5300  0.0.0.0:*"),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)):
            result = resolv_conf_fix.fix_resolv_conf_to_localhost(dry_run=True)
        self.assertTrue(result["ok"])
        # Файл не изменён
        self.assertIn("8.8.8.8", self._resolv_conf.read_text())
        # Бэкап не создан
        self.assertFalse(self._backup_file.exists())

    def test_idempotent_second_fix_does_not_overwrite_backup(self):
        """Повторный фикс НЕ перезаписывает существующий бэкап."""
        from chimera.modules import resolv_conf_fix
        # Первый запуск с 8.8.8.8
        self._resolv_conf.write_text("nameserver 8.8.8.8\n")
        cmd_to_result = {
            ("systemctl", "is-active", "systemd-resolved"):
                _make_completed(rc=3, stdout="inactive"),
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(stdout="active"),
            ("ss", "-tlnu"): _make_completed(
                stdout="UDP  127.0.0.1:5300  0.0.0.0:*"),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)):
            r1 = resolv_conf_fix.fix_resolv_conf_to_localhost()
            # Симулируем: кто-то ещё раз пропатчил resolv.conf на 1.1.1.1.
            self._resolv_conf.write_text("nameserver 1.1.1.1\n")
            r2 = resolv_conf_fix.fix_resolv_conf_to_localhost()
        self.assertTrue(r1["ok"])
        self.assertTrue(r2["ok"])
        # Бэкап содержит ПЕРВОНАЧАЛЬНОЕ значение 8.8.8.8, а не 1.1.1.1
        backup_content = self._backup_file.read_text()
        self.assertIn("8.8.8.8", backup_content)
        self.assertNotIn("1.1.1.1", backup_content)


# ══════════════════════════════════════════════════════════════════════════════
#  rollback_resolv_conf — откат
# ══════════════════════════════════════════════════════════════════════════════
class TestRollbackResolvConf(_BaseTest):
    """rollback_resolv_conf: восстановление прежнего состояния."""

    def test_rollback_static_restores_backup(self):
        """Static resolv.conf: rollback восстанавливает из бэкапа."""
        from chimera.modules import resolv_conf_fix
        # Подготовка: resolv.conf → 127.0.0.1 (после фикса),
        # бэкап → 8.8.8.8 (оригинал), state → fixed.
        self._resolv_conf.write_text("nameserver 127.0.0.1\n")
        self._backup_file.write_text("nameserver 8.8.8.8\n")
        self._state_file.write_text(json.dumps({
            "fixed": True,
            "method": "static_resolv_conf",
            "applied_at": "2026-08-01T10:00:00",
            "backup_path": str(self._backup_file),
        }))
        result = resolv_conf_fix.rollback_resolv_conf()
        self.assertTrue(result["ok"])
        # resolv.conf восстановлен из бэкапа
        content = self._resolv_conf.read_text()
        self.assertIn("8.8.8.8", content)
        self.assertNotIn("127.0.0.1", content)
        # State обновлён
        state = json.loads(self._state_file.read_text())
        self.assertFalse(state["fixed"])

    def test_rollback_systemd_removes_dropin(self):
        """systemd-resolved: rollback удаляет drop-in + restart."""
        from chimera.modules import resolv_conf_fix
        # Подготовка: drop-in существует, state → fixed.
        self._dropin_dir.mkdir(parents=True, exist_ok=True)
        self._dropin_file.write_text("[Resolve]\nDNS=127.0.0.1\n")
        self._state_file.write_text(json.dumps({
            "fixed": True,
            "method": "systemd_resolved",
            "applied_at": "2026-08-01T10:00:00",
            "dropin_path": str(self._dropin_file),
        }))
        cmd_to_result = {
            ("systemctl", "restart", "systemd-resolved"): _make_completed(rc=0),
            ("resolvectl", "dns-default-route"): _make_completed(rc=0),
            ("resolvectl", "flush-caches"): _make_completed(rc=0),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)):
            result = resolv_conf_fix.rollback_resolv_conf()
        self.assertTrue(result["ok"])
        # Drop-in удалён
        self.assertFalse(self._dropin_file.exists())

    def test_rollback_without_state_returns_error(self):
        """Rollback без применённого фикса → ok=False с ошибкой."""
        from chimera.modules import resolv_conf_fix
        # state.json не существует (setUp не создаёт его).
        result = resolv_conf_fix.rollback_resolv_conf()
        self.assertFalse(result["ok"])
        self.assertIn("не был применён", result["error"])


# ══════════════════════════════════════════════════════════════════════════════
#  _get_dnscrypt_listen_addr_port — парсинг TOML
# ══════════════════════════════════════════════════════════════════════════════
class TestParseDnscryptListenAddr(_BaseTest):
    """_get_dnscrypt_listen_addr_port: парсинг listen_addresses из TOML."""

    def test_parses_ipv4_listen(self):
        from chimera.modules import resolv_conf_fix
        self._dnscrypt_toml.write_text(
            "listen_addresses = ['127.0.0.1:5300']\n"
        )
        result = resolv_conf_fix._get_dnscrypt_listen_addr_port()
        self.assertEqual(result, ("127.0.0.1", 5300))

    def test_parses_ipv6_listen(self):
        from chimera.modules import resolv_conf_fix
        self._dnscrypt_toml.write_text(
            "listen_addresses = ['[::1]:5300']\n"
        )
        result = resolv_conf_fix._get_dnscrypt_listen_addr_port()
        self.assertEqual(result, ("::1", 5300))

    def test_parses_multiple_addresses_takes_first(self):
        from chimera.modules import resolv_conf_fix
        self._dnscrypt_toml.write_text(
            "listen_addresses = ['127.0.0.1:5300', '[::1]:5300']\n"
        )
        result = resolv_conf_fix._get_dnscrypt_listen_addr_port()
        # Берём первый из списка (IPv4)
        self.assertEqual(result, ("127.0.0.1", 5300))

    def test_returns_none_when_no_toml(self):
        from chimera.modules import resolv_conf_fix
        # _dnscrypt_toml не существует (setUp его не создаёт).
        result = resolv_conf_fix._get_dnscrypt_listen_addr_port()
        self.assertIsNone(result)

    def test_returns_none_when_no_listen_addresses(self):
        from chimera.modules import resolv_conf_fix
        self._dnscrypt_toml.write_text("# no listen_addresses here\n")
        result = resolv_conf_fix._get_dnscrypt_listen_addr_port()
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
