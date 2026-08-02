#!/usr/bin/env python3
"""
tests/test_resolv_conf_fix.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/resolv_conf_fix.py v6 — static resolv.conf +
nsswitch.conf approach. БЕЗ networkctl, БЕЗ .network файлов, БЕЗ interface
manipulation.

Покрывает:
  1. diagnose_resolv_conf — диагностика состояния.
  2. fix_resolv_conf_to_localhost — программный fix (static resolv.conf +
     nsswitch.conf + drop-in + per-link resolvectl + persist).
  3. rollback_resolv_conf — откат.
  4. Pre-flight checks: фикс отменяется если DNSCrypt не активен/не слушает.
  5. force=True — переприменение.
  6. Persist-скрипт валидность (Python syntax check).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import ast
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


def _make_completed(rc=0, stdout="", stderr=""):
    return MagicMock(returncode=rc, stdout=stdout, stderr=stderr)


def _mock_run_factory(cmd_to_result: dict):
    def _mock_run(cmd, capture=False, quiet=False, check=False, **kw):
        for prefix, result in cmd_to_result.items():
            if tuple(cmd[:len(prefix)]) == prefix:
                return result
        return MagicMock(returncode=0, stdout="", stderr="")
    return _mock_run


class _BaseTest(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._resolv_conf = self._tmpdir / "resolv.conf"
        self._nsswitch = self._tmpdir / "nsswitch.conf"
        self._backup_resolv = self._tmpdir / "resolv.conf.bak"
        self._backup_nsswitch = self._tmpdir / "nsswitch.conf.bak"
        self._dropin_dir = self._tmpdir / "resolved.conf.d"
        self._dropin_file = self._dropin_dir / "chimera-dns.conf"
        self._state_file = self._tmpdir / "state.json"
        self._dnscrypt_toml = self._tmpdir / "dnscrypt.toml"
        self._persist_svc = self._tmpdir / "chimera-dns-fix.service"
        self._persist_script = self._tmpdir / "chimera-dns-fix-apply.py"

        patches = [
            patch("chimera.modules.resolv_conf_fix._RESOLV_CONF", self._resolv_conf),
            patch("chimera.modules.resolv_conf_fix._NSSWITCH_CONF", self._nsswitch),
            patch("chimera.modules.resolv_conf_fix._BACKUP_RESOLV", self._backup_resolv),
            patch("chimera.modules.resolv_conf_fix._BACKUP_NSSWITCH", self._backup_nsswitch),
            patch("chimera.modules.resolv_conf_fix._RESOLVED_DROPIN_DIR", self._dropin_dir),
            patch("chimera.modules.resolv_conf_fix._RESOLVED_DROPIN_FILE", self._dropin_file),
            patch("chimera.modules.resolv_conf_fix._STATE_FILE", self._state_file),
            patch("chimera.modules.resolv_conf_fix._DNSCRYPT_TOML", self._dnscrypt_toml),
            patch("chimera.modules.resolv_conf_fix._PERSIST_SVC_PATH", self._persist_svc),
            patch("chimera.modules.resolv_conf_fix._PERSIST_SCRIPT_PATH", self._persist_script),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)


# ══════════════════════════════════════════════════════════════════════════════
#  diagnose_resolv_conf
# ══════════════════════════════════════════════════════════════════════════════
class TestDiagnoseResolvConf(_BaseTest):
    def test_external_dns_fix_needed(self):
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.write_text("nameserver 8.8.8.8\n")
        self._nsswitch.write_text("hosts: files resolve [!UNAVAIL=return] dns\n")
        cmd_to_result = {
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(stdout="active"),
            ("ss", "-tlnu"): _make_completed(stdout="UDP 127.0.0.1:5300"),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)):
            diag = resolv_conf_fix.diagnose_resolv_conf()
        self.assertTrue(diag["fix_needed"])
        self.assertEqual(diag["fix_method"], "static_resolv_conf")

    def test_localhost_no_fix_needed(self):
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.write_text("nameserver 127.0.0.1\n")
        self._nsswitch.write_text("hosts: files dns\n")
        cmd_to_result = {
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(stdout="active"),
            ("ss", "-tlnu"): _make_completed(stdout="UDP 127.0.0.1:5300"),
            # iptables redirect активен (to:5300 + dpt:53 в выводе)
            ("iptables",): _make_completed(
                stdout="REDIRECT  tcp  --  127.0.0.1  anywhere  tcp dpt:53 redir ports 5300\n"
                       "REDIRECT  udp  --  127.0.0.1  anywhere  udp dpt:53 redir ports 5300\n"),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)):
            diag = resolv_conf_fix.diagnose_resolv_conf()
        self.assertFalse(diag["fix_needed"])
        self.assertTrue(diag["resolv_conf_on_localhost"])
        self.assertFalse(diag["nsswitch_has_resolve"])

    def test_nsswitch_has_resolve_detected(self):
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.write_text("nameserver 127.0.0.1\n")
        self._nsswitch.write_text("hosts: files resolve [!UNAVAIL=return] dns\n")
        cmd_to_result = {
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(stdout="active"),
            ("ss", "-tlnu"): _make_completed(stdout="UDP 127.0.0.1:5300"),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)):
            diag = resolv_conf_fix.diagnose_resolv_conf()
        self.assertTrue(diag["nsswitch_has_resolve"])
        self.assertTrue(diag["fix_needed"])  # nsswitch uses resolve → fix needed

    def test_dnscrypt_not_active_no_fix(self):
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.write_text("nameserver 8.8.8.8\n")
        self._nsswitch.write_text("hosts: files resolve [!UNAVAIL=return] dns\n")
        with patch.object(resolv_conf_fix, "_run",
                          return_value=_make_completed(rc=3, stdout="inactive")):
            diag = resolv_conf_fix.diagnose_resolv_conf()
        self.assertFalse(diag["fix_needed"])
        self.assertTrue(any("DNSCrypt" in r for r in diag["leak_reasons"]))


# ══════════════════════════════════════════════════════════════════════════════
#  fix_resolv_conf_to_localhost
# ══════════════════════════════════════════════════════════════════════════════
class TestFixResolvConf(_BaseTest):
    def test_fix_writes_localhost_and_removes_resolve(self):
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.write_text("nameserver 8.8.8.8\n")
        self._nsswitch.write_text("hosts: files resolve [!UNAVAIL=return] dns\n")
        cmd_to_result = {
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(stdout="active"),
            ("ss", "-tlnu"): _make_completed(stdout="UDP 127.0.0.1:5300"),
            ("resolvectl", "dns"): _make_completed(stdout=""),
            ("resolvectl", "dns", "eth0", "127.0.0.1"): _make_completed(rc=0),
            ("resolvectl", "default-route", "eth0", "false"): _make_completed(rc=0),
            ("systemctl", "restart", "systemd-resolved"): _make_completed(rc=0),
            ("resolvectl", "flush-caches"): _make_completed(rc=0),
            ("systemctl", "daemon-reload"): _make_completed(rc=0),
            ("systemctl", "enable"): _make_completed(rc=0),
            ("systemctl", "start"): _make_completed(rc=0),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)):
            result = resolv_conf_fix.fix_resolv_conf_to_localhost()
        self.assertTrue(result["ok"])
        # resolv.conf → 127.0.0.1
        self.assertIn("nameserver 127.0.0.1", self._resolv_conf.read_text())
        # nsswitch.conf → без resolve
        nss = self._nsswitch.read_text()
        self.assertNotIn("resolve", nss)
        # Backups created
        self.assertTrue(self._backup_resolv.exists())
        self.assertIn("8.8.8.8", self._backup_resolv.read_text())
        self.assertTrue(self._backup_nsswitch.exists())
        self.assertIn("resolve", self._backup_nsswitch.read_text())

    def test_fix_not_needed_returns_error(self):
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.write_text("nameserver 127.0.0.1\n")
        self._nsswitch.write_text("hosts: files dns\n")
        cmd_to_result = {
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(stdout="active"),
            ("ss", "-tlnu"): _make_completed(stdout="UDP 127.0.0.1:5300"),
            ("iptables",): _make_completed(
                stdout="REDIRECT  tcp  --  127.0.0.1  anywhere  tcp dpt:53 redir ports 5300\n"),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)):
            result = resolv_conf_fix.fix_resolv_conf_to_localhost()
        self.assertFalse(result["ok"])

    def test_force_reapplies(self):
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.write_text("nameserver 127.0.0.1\n")
        self._nsswitch.write_text("hosts: files dns\n")
        cmd_to_result = {
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(stdout="active"),
            ("ss", "-tlnu"): _make_completed(stdout="UDP 127.0.0.1:5300"),
            ("iptables",): _make_completed(
                stdout="REDIRECT  tcp  --  127.0.0.1  anywhere  tcp dpt:53 redir ports 5300\n"),
            ("resolvectl", "dns"): _make_completed(stdout=""),
            ("systemctl", "restart", "systemd-resolved"): _make_completed(rc=0),
            ("resolvectl", "flush-caches"): _make_completed(rc=0),
            ("systemctl", "daemon-reload"): _make_completed(rc=0),
            ("systemctl", "enable"): _make_completed(rc=0),
            ("systemctl", "start"): _make_completed(rc=0),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)):
            # Without force — fails
            r1 = resolv_conf_fix.fix_resolv_conf_to_localhost()
            self.assertFalse(r1["ok"])
            # With force — succeeds
            r2 = resolv_conf_fix.fix_resolv_conf_to_localhost(force=True)
        self.assertTrue(r2["ok"])

    def test_dry_run_no_changes(self):
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.write_text("nameserver 8.8.8.8\n")
        self._nsswitch.write_text("hosts: files resolve [!UNAVIL=return] dns\n")
        cmd_to_result = {
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(stdout="active"),
            ("ss", "-tlnu"): _make_completed(stdout="UDP 127.0.0.1:5300"),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)):
            result = resolv_conf_fix.fix_resolv_conf_to_localhost(dry_run=True)
        self.assertTrue(result["ok"])
        self.assertIn("8.8.8.8", self._resolv_conf.read_text())
        self.assertFalse(self._backup_resolv.exists())

    def test_no_networkctl_called(self):
        """РЕГРЕССИЯ: НИКОГДА не вызываем networkctl — убивает SSH."""
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.write_text("nameserver 8.8.8.8\n")
        self._nsswitch.write_text("hosts: files resolve [!UNAVAIL=return] dns\n")
        called = []
        def tracking_run(cmd, *a, **kw):
            called.append(tuple(cmd))
            if "is-active" in cmd:
                return _make_completed(stdout="active\n")
            if "ss" in cmd:
                return _make_completed(stdout="UDP 127.0.0.1:5300\n")
            return _make_completed(rc=0)
        with patch.object(resolv_conf_fix, "_run", side_effect=tracking_run), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)):
            resolv_conf_fix.fix_resolv_conf_to_localhost()
        # НЕ должно быть НИ ОДНОГО networkctl вызова
        networkctl_calls = [c for c in called if "networkctl" in c]
        self.assertEqual(networkctl_calls, [],
                         f"networkctl ВЫЗВАН — это убивает SSH! {networkctl_calls}")


# ══════════════════════════════════════════════════════════════════════════════
#  rollback_resolv_conf
# ══════════════════════════════════════════════════════════════════════════════
class TestRollback(_BaseTest):
    def test_rollback_restores_backups(self):
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.write_text("nameserver 127.0.0.1\n")
        self._nsswitch.write_text("hosts: files dns\n")
        self._backup_resolv.write_text("nameserver 8.8.8.8\n")
        self._backup_nsswitch.write_text("hosts: files resolve [!UNAVAIL=return] dns\n")
        self._dropin_dir.mkdir(parents=True)
        self._dropin_file.write_text("[Resolve]\nDNS=127.0.0.1\n")
        self._state_file.write_text(json.dumps({
            "fixed": True, "method": "static_resolv_conf",
            "applied_at": "2026-08-01T10:00:00",
        }))
        with patch.object(resolv_conf_fix, "_run",
                          return_value=_make_completed(rc=0)):
            result = resolv_conf_fix.rollback_resolv_conf()
        self.assertTrue(result["ok"])
        self.assertIn("8.8.8.8", self._resolv_conf.read_text())
        self.assertIn("resolve", self._nsswitch.read_text())
        self.assertFalse(self._dropin_file.exists())

    def test_rollback_no_state_error(self):
        from chimera.modules import resolv_conf_fix
        result = resolv_conf_fix.rollback_resolv_conf()
        self.assertFalse(result["ok"])
        self.assertIn("не был применён", result["error"])


# ══════════════════════════════════════════════════════════════════════════════
#  Persist-скрипт валидность
# ══════════════════════════════════════════════════════════════════════════════
class TestPersistScript(_BaseTest):
    def test_persist_script_valid_python(self):
        """Persist-скрипт должен быть валидным Python кодом."""
        from chimera.modules import resolv_conf_fix
        script_path, svc_path, err = resolv_conf_fix._write_persist_script_and_service()
        self.assertIsNone(err, f"persist-скрипт не создан: {err}")
        self.assertTrue(script_path.exists())
        # Проверяем Python-синтаксис
        content = script_path.read_text()
        ast.parse(content)  # бросает SyntaxError если невалидный
        # Проверяем ключевые элементы
        self.assertIn("#!/usr/bin/env python3", content)
        self.assertIn("127.0.0.1", content)
        self.assertIn("resolvectl", content)
        self.assertIn("nsswitch", content)
        # НЕ должно быть networkctl
        self.assertNotIn("networkctl", content,
                         "networkctl в persist-скрипте — УБИВАЕТ SSH!")

    def test_persist_service_valid(self):
        from chimera.modules import resolv_conf_fix
        _, svc_path, err = resolv_conf_fix._write_persist_script_and_service()
        self.assertIsNone(err)
        content = svc_path.read_text()
        self.assertIn("After=network-online.target", content)
        self.assertIn("chimera-dns-fix-apply.py", content)
        self.assertIn("Type=oneshot", content)


# ══════════════════════════════════════════════════════════════════════════════
#  _get_dnscrypt_listen_addr_port — парсинг TOML
# ══════════════════════════════════════════════════════════════════════════════
class TestParseDnscryptListenAddr(_BaseTest):
    def test_ipv4(self):
        from chimera.modules import resolv_conf_fix
        self._dnscrypt_toml.write_text("listen_addresses = ['127.0.0.1:5300']\n")
        self.assertEqual(
            resolv_conf_fix._get_dnscrypt_listen_addr_port(),
            ("127.0.0.1", 5300))

    def test_ipv6(self):
        from chimera.modules import resolv_conf_fix
        self._dnscrypt_toml.write_text("listen_addresses = ['[::1]:5300']\n")
        self.assertEqual(
            resolv_conf_fix._get_dnscrypt_listen_addr_port(),
            ("::1", 5300))

    def test_no_toml(self):
        from chimera.modules import resolv_conf_fix
        self.assertIsNone(resolv_conf_fix._get_dnscrypt_listen_addr_port())


if __name__ == "__main__":
    unittest.main(verbosity=2)
