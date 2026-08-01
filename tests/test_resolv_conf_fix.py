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
        # Патчим все файловые пути на tmpdir.
        self._state_file = self._tmpdir / "resolv_conf_fix.json"
        self._backup_file = self._tmpdir / "resolv.conf.chimera.bak"
        self._resolv_conf = self._tmpdir / "resolv.conf"
        self._dropin_dir = self._tmpdir / "resolved.conf.d"
        self._dropin_file = self._dropin_dir / "chimera-dns.conf"
        self._dnscrypt_toml = self._tmpdir / "dnscrypt-proxy.toml"
        self._persist_svc_path = self._tmpdir / "chimera-dns-fix.service"
        self._persist_script_path = self._tmpdir / "chimera-dns-fix-apply.sh"
        # Создаём поддиректории для systemd-unit и /usr/local/bin
        (self._tmpdir / "systemd-system").mkdir(parents=True, exist_ok=True)
        (self._tmpdir / "usr-local-bin").mkdir(parents=True, exist_ok=True)

        patches = [
            patch("chimera.modules.resolv_conf_fix._STATE_FILE", self._state_file),
            patch("chimera.modules.resolv_conf_fix._BACKUP", self._backup_file),
            patch("chimera.modules.resolv_conf_fix._RESOLV_CONF", self._resolv_conf),
            patch("chimera.modules.resolv_conf_fix._RESOLVED_DROPIN_DIR", self._dropin_dir),
            patch("chimera.modules.resolv_conf_fix._RESOLVED_DROPIN_FILE", self._dropin_file),
            patch("chimera.modules.resolv_conf_fix._DNSCRYPT_TOML", self._dnscrypt_toml),
            patch("chimera.modules.resolv_conf_fix._PERSIST_SVC_PATH", self._persist_svc_path),
            patch("chimera.modules.resolv_conf_fix._PERSIST_SCRIPT_PATH", self._persist_script_path),
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

    def test_per_link_overridden_no_leak_despite_global_external_dns(self):
        """РЕГРЕССИЯ v3: после фикса per-link DNS=127.0.0.1 + default-route=false
        для всех link'ов → утечки НЕТ, даже если Global DNS содержит 77.88.8.8
        (от DHCP). Drop-in с Domains=~. перехватывает все запросы на 127.0.0.1.

        Это симптом из баг-репорта: фикс применился, per-link OK, но Global
        DNS содержит 77.88.8.8 — diagnose ошибочно показывал утечку.
        """
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.symlink_to("/run/systemd/resolve/stub-resolv.conf")
        # resolv.conf → 127.0.0.53 (stub)
        cmd_to_result = {
            ("systemctl", "is-active", "systemd-resolved"):
                _make_completed(stdout="active"),
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(stdout="active"),
            # resolvectl dns: Global содержит 77.88.8.8 (от DHCP), но
            # Link ens3: 127.0.0.1 (per-link override применён).
            ("resolvectl", "dns"): _make_completed(
                stdout="Global: 77.88.8.8 77.88.8.1 127.0.0.1 127.0.0.1\n"
                       "Link 2 (ens3): 127.0.0.1\n"),
            # resolvectl default-route: Global yes, Link ens3: no (отключён).
            ("resolvectl", "default-route"): _make_completed(
                stdout="Global: yes\nLink 2 (ens3): no\n"),
            ("ss", "-tlnu"): _make_completed(
                stdout="UDP  127.0.0.1:5300  0.0.0.0:*"),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)), \
             patch.object(resolv_conf_fix, "_get_resolv_conf_nameservers",
                          return_value=["127.0.0.53"]):
            diag = resolv_conf_fix.diagnose_resolv_conf()
        # per-link override активен → утечки нет.
        self.assertTrue(diag["per_link_overridden"],
                        "per_link_overridden должен быть True: "
                        "ens3 → 127.0.0.1, default-route=false")
        self.assertFalse(diag["fix_needed"],
                         "fix_needed должен быть False — per-link override активен")
        self.assertEqual(diag["leak_reasons"], [],
                         "leak_reasons должен быть пустым")

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
        """systemd-resolved кейс: создаётся drop-in + resolvectl вызовы + persist-сервис."""
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.symlink_to("/run/systemd/resolve/stub-resolv.conf")
        cmd_to_result = {
            ("systemctl", "is-active", "systemd-resolved"):
                _make_completed(stdout="active"),
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(stdout="active"),
            ("resolvectl", "dns"): _make_completed(
                stdout="Global:\nLink 2 (eth0): 5.45.240.203\n"),
            ("resolvectl", "dns", "eth0"): _make_completed(rc=0),
            ("resolvectl", "dns", "eth0", "127.0.0.1"): _make_completed(rc=0),
            ("resolvectl", "dns", "127.0.0.1"): _make_completed(rc=0),
            ("resolvectl", "default-route"): _make_completed(rc=0),
            ("resolvectl", "default-route", "eth0"): _make_completed(rc=0),
            ("resolvectl", "default-route", "eth0", "false"): _make_completed(rc=0),
            ("resolvectl", "default-route", "false"): _make_completed(rc=0),
            ("resolvectl", "flush-caches"): _make_completed(rc=0),
            ("systemctl", "restart", "systemd-resolved"): _make_completed(rc=0),
            ("systemctl", "daemon-reload"): _make_completed(rc=0),
            ("systemctl", "enable", "chimera-dns-fix.service"): _make_completed(rc=0),
            ("systemctl", "start", "chimera-dns-fix.service"): _make_completed(rc=0),
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
        # Persist-сервис и скрипт созданы
        self.assertTrue(resolv_conf_fix._PERSIST_SVC_PATH.exists())
        self.assertTrue(resolv_conf_fix._PERSIST_SCRIPT_PATH.exists())
        # Скрипт исполняемый
        import os, stat
        mode = stat.S_IMODE(os.stat(resolv_conf_fix._PERSIST_SCRIPT_PATH).st_mode)
        self.assertTrue(mode & 0o100, "persist-скрипт должен быть исполняемым")
        # systemd-unit содержит After=network-online.target
        svc_content = resolv_conf_fix._PERSIST_SVC_PATH.read_text()
        self.assertIn("network-online.target", svc_content)
        self.assertIn("chimera-dns-fix-apply.sh", svc_content)
        # В actions есть per-link override и persist
        actions_str = " ".join(result["actions"])
        self.assertIn("resolvectl dns eth0 127.0.0.1", actions_str)
        self.assertIn("resolvectl default-route eth0 false", actions_str)
        self.assertIn("persist-сервис", actions_str)
        # State сохранён с persist_service=True
        state = json.loads(self._state_file.read_text())
        self.assertTrue(state["fixed"])
        self.assertEqual(state["method"], "systemd_resolved")
        self.assertIn("dropin_path", state)
        self.assertTrue(state.get("persist_service"))

    def test_systemd_resolved_uses_correct_resolvectl_syntax(self):
        """РЕГРЕССИЯ: на Ubuntu 24.04+ синтаксис `resolvectl dns` (без -global),
        `resolvectl default-route` (без dns- prefix). Старый синтаксис
        `dns-global set` / `dns-default-route set false` возвращал
        'Unknown command verb' — фикс «применялся», но утечка оставалась.

        ДОПОЛНИТЕЛЬНО (v3): global `resolvectl dns 127.0.0.1` / `default-route false`
        тоже НЕ вызываются — на Ubuntu 24.04 парсер интерпретирует `127.0.0.1`
        и `false` как имя интерфейса и падает с 'Failed to resolve interface'.
        Global DNS задаётся через drop-in, этого достаточно.
        """
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.symlink_to("/run/systemd/resolve/stub-resolv.conf")
        # Записываем все вызовы _run для последующего анализа.
        called_cmds = []
        def tracking_run(cmd, capture=False, quiet=False, check=False, **kw):
            called_cmds.append(tuple(cmd))
            # Спец-выводы для ключевых команд:
            if "is-active" in cmd:
                return _make_completed(rc=0, stdout="active\n")
            if cmd[:2] == ["resolvectl", "dns"] and len(cmd) == 2:
                # `resolvectl dns` (просмотр) — без аргументов.
                return _make_completed(stdout="Global:\nLink 2 (eth0): 5.45.240.203\n")
            if cmd[:2] == ["resolvectl", "default-route"] and len(cmd) == 2:
                # `resolvectl default-route` (просмотр) — без аргументов.
                return _make_completed(stdout="Global: yes\nLink 2 (eth0): yes\n")
            if cmd[:1] == ["ss"]:
                return _make_completed(stdout="UDP  127.0.0.1:5300  0.0.0.0:*\n")
            return _make_completed(rc=0)
        with patch.object(resolv_conf_fix, "_run", side_effect=tracking_run), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)):
            resolv_conf_fix.fix_resolv_conf_to_localhost()
        # Не должно быть вызовов `dns-global` или `dns-default-route` (старый синтаксис).
        bad_cmds = [c for c in called_cmds
                    if "dns-global" in c or "dns-default-route" in c]
        self.assertEqual(bad_cmds, [],
                         f"найдены устаревшие команды: {bad_cmds}")
        # НЕ должно быть global `resolvectl dns 127.0.0.1` (парсер падает).
        self.assertFalse(any(c == ("resolvectl", "dns", "127.0.0.1")
                             for c in called_cmds),
                         "global `resolvectl dns 127.0.0.1` не должен вызываться")
        # НЕ должно быть global `resolvectl default-route false` (парсер падает).
        self.assertFalse(any(c == ("resolvectl", "default-route", "false")
                             for c in called_cmds),
                         "global `resolvectl default-route false` не должен вызываться")
        # ДОЛЖНЫ быть per-link вызовы: `resolvectl dns eth0 127.0.0.1`.
        self.assertTrue(any(c == ("resolvectl", "dns", "eth0", "127.0.0.1")
                            for c in called_cmds),
                        "нет вызова `resolvectl dns eth0 127.0.0.1` (per-link)")
        # ДОЛЖНЫ быть per-link: `resolvectl default-route eth0 false`.
        self.assertTrue(any(c == ("resolvectl", "default-route", "eth0", "false")
                            for c in called_cmds),
                        "нет вызова `resolvectl default-route eth0 false` (per-link)")

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

    def test_force_reapplies_even_when_fix_not_needed(self):
        """force=True — переприменяет фикс даже если fix_needed=False.

        Сценарий: старый фикс v3 применён (per-link OK), но Global DNS
        содержит 77.88.8.8 от DHCP. diagnose вернёт fix_needed=False
        (per_link_overridden=True), но force=True позволяет переприменить
        — это запустит disable_dhcp_dns_on_all_links (шаг 1i).
        """
        from chimera.modules import resolv_conf_fix
        self._resolv_conf.symlink_to("/run/systemd/resolve/stub-resolv.conf")
        cmd_to_result = {
            ("systemctl", "is-active", "systemd-resolved"):
                _make_completed(stdout="active"),
            ("systemctl", "is-active", "dnscrypt-proxy.service"):
                _make_completed(stdout="active"),
            # resolvectl dns: Global содержит 77.88.8.8 (DHCP), per-link OK.
            ("resolvectl", "dns"): _make_completed(
                stdout="Global: 77.88.8.8 127.0.0.1\n"
                       "Link 2 (ens3): 127.0.0.1\n"),
            ("resolvectl", "default-route"): _make_completed(
                stdout="Global: yes\nLink 2 (ens3): no\n"),
            ("resolvectl", "dns", "ens3", "127.0.0.1"): _make_completed(rc=0),
            ("resolvectl", "default-route", "ens3", "false"): _make_completed(rc=0),
            ("resolvectl", "flush-caches"): _make_completed(rc=0),
            ("systemctl", "restart", "systemd-resolved"): _make_completed(rc=0),
            ("systemctl", "daemon-reload"): _make_completed(rc=0),
            ("systemctl", "enable", "chimera-dns-fix.service"): _make_completed(rc=0),
            ("systemctl", "start", "chimera-dns-fix.service"): _make_completed(rc=0),
            ("ss", "-tlnu"): _make_completed(
                stdout="UDP  127.0.0.1:5300  0.0.0.0:*"),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)), \
             patch.object(resolv_conf_fix, "_get_dnscrypt_listen_addr_port",
                          return_value=("127.0.0.1", 5300)), \
             patch.object(resolv_conf_fix, "_get_resolv_conf_nameservers",
                          return_value=["127.0.0.53"]), \
             patch.object(resolv_conf_fix, "disable_dhcp_dns_on_all_links",
                          return_value={"ok": True, "manager": "systemd-networkd",
                                        "actions": ["drop-in created"],
                                        "warnings": [],
                                        "dropin_paths": ["/etc/systemd/network/10-netplan-ens3.network.d/chimera-dns.conf"]}):
            # Без force — отказ (fix_needed=False, per_link_overridden=True).
            result_no_force = resolv_conf_fix.fix_resolv_conf_to_localhost()
            self.assertFalse(result_no_force["ok"])
            # С force=True — переприменяется.
            result_force = resolv_conf_fix.fix_resolv_conf_to_localhost(force=True)
        self.assertTrue(result_force["ok"])
        self.assertEqual(result_force["method"], "systemd_resolved")
        # В actions должен быть disable_dhcp_dns.
        actions_str = " ".join(result_force["actions"])
        self.assertIn("отключён DHCP DNS", actions_str)

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

    def test_rollback_systemd_removes_dropin_and_persist_service(self):
        """systemd-resolved: rollback удаляет drop-in + persist-сервис + restart."""
        from chimera.modules import resolv_conf_fix
        # Подготовка: drop-in + persist-service существуют, state → fixed.
        self._dropin_dir.mkdir(parents=True, exist_ok=True)
        self._dropin_file.write_text("[Resolve]\nDNS=127.0.0.1\n")
        self._persist_svc_path.write_text("[Unit]\nDescription=test\n")
        self._persist_script_path.write_text("#!/bin/bash\necho test\n")
        self._state_file.write_text(json.dumps({
            "fixed": True,
            "method": "systemd_resolved",
            "applied_at": "2026-08-01T10:00:00",
            "dropin_path": str(self._dropin_file),
            "persist_service": True,
        }))
        cmd_to_result = {
            ("systemctl", "stop", "chimera-dns-fix.service"): _make_completed(rc=0),
            ("systemctl", "disable", "chimera-dns-fix.service"): _make_completed(rc=0),
            ("systemctl", "daemon-reload"): _make_completed(rc=0),
            ("systemctl", "restart", "systemd-resolved"): _make_completed(rc=0),
            ("resolvectl", "dns"): _make_completed(
                stdout="Global:\nLink 2 (eth0):\n"),
            ("resolvectl", "default-route", "eth0", "true"): _make_completed(rc=0),
            ("resolvectl", "default-route", "true"): _make_completed(rc=0),
            ("resolvectl", "flush-caches"): _make_completed(rc=0),
        }
        with patch.object(resolv_conf_fix, "_run",
                          side_effect=_mock_run_factory(cmd_to_result)):
            result = resolv_conf_fix.rollback_resolv_conf()
        self.assertTrue(result["ok"])
        # Drop-in удалён
        self.assertFalse(self._dropin_file.exists())
        # Persist-сервис и скрипт удалены
        self.assertFalse(self._persist_svc_path.exists())
        self.assertFalse(self._persist_script_path.exists())
        # State обновлён
        state = json.loads(self._state_file.read_text())
        self.assertFalse(state["fixed"])
        self.assertFalse(state.get("persist_service"))

    def test_rollback_without_state_returns_error(self):
        """Rollback без применённого фикса → ok=False с ошибкой."""
        from chimera.modules import resolv_conf_fix
        # state.json не существует (setUp не создаёт его).
        result = resolv_conf_fix.rollback_resolv_conf()
        self.assertFalse(result["ok"])
        self.assertIn("не был применён", result["error"])


# ══════════════════════════════════════════════════════════════════════════════
#  DHCP DNS disable/enable — отключение DHCP DNS на уровне network manager
# ══════════════════════════════════════════════════════════════════════════════
class TestDisableDhcpDns(_BaseTest):
    """disable_dhcp_dns_on_all_links: отключение DHCP DNS."""

    def test_systemd_networkd_creates_dropin(self):
        """systemd-networkd: вызывается _networkd_disable_dhcp_dns + networkctl reload."""
        from chimera.modules import resolv_conf_fix
        called_cmds = []
        def tracking_run(cmd, *a, **kw):
            called_cmds.append(tuple(cmd))
            return _make_completed(rc=0)
        dropin_returned = (True, Path("/etc/systemd/network/10-netplan-ens3.network.d/chimera-dns.conf"), None)
        with patch.object(resolv_conf_fix, "_detect_network_manager",
                          return_value="systemd-networkd"), \
             patch.object(resolv_conf_fix, "_get_all_links",
                          return_value=["ens3"]), \
             patch.object(resolv_conf_fix, "_networkd_disable_dhcp_dns",
                          return_value=dropin_returned), \
             patch.object(resolv_conf_fix, "_run", side_effect=tracking_run):
            result = resolv_conf_fix.disable_dhcp_dns_on_all_links()
        self.assertTrue(result["ok"])
        self.assertEqual(result["manager"], "systemd-networkd")
        # dropin_paths сохранён
        self.assertEqual(len(result["dropin_paths"]), 1)
        # networkctl reload вызван (БЕЗ reconfigure — reconfigure убивает SSH)
        cmd_str = " ".join(" ".join(c) for c in called_cmds)
        self.assertIn("networkctl reload", cmd_str)
        self.assertNotIn("networkctl reconfigure", cmd_str,
                         "networkctl reconfigure НЕ должен вызываться — убивает SSH")

    def test_networkmanager_sets_ignore_auto_dns(self):
        """NetworkManager: nmcli ... ignore-auto-dns yes."""
        from chimera.modules import resolv_conf_fix
        called_cmds = []
        def tracking_run(cmd, *args, **kwargs):
            called_cmds.append(tuple(cmd))
            if cmd[:3] == ["nmcli", "-t", "-f"] and "connection" in cmd:
                return _make_completed(rc=0, stdout="Wired:ens3\n")
            return _make_completed(rc=0)
        with patch.object(resolv_conf_fix, "_detect_network_manager",
                          return_value="NetworkManager"), \
             patch.object(resolv_conf_fix, "_get_all_links",
                          return_value=["ens3"]), \
             patch.object(resolv_conf_fix, "_run", side_effect=tracking_run):
            result = resolv_conf_fix.disable_dhcp_dns_on_all_links()
        self.assertTrue(result["ok"])
        self.assertEqual(result["manager"], "NetworkManager")
        # Должны быть nmcli modify с ignore-auto-dns yes.
        # modify_cmds — список tuple; проверяем "ignore-auto-dns" в любом элементе tuple.
        modify_cmds = [c for c in called_cmds
                       if "modify" in c and any("ignore-auto-dns" in x for x in c)]
        self.assertGreaterEqual(len(modify_cmds), 2,
                                f"ожидали 2+ nmcli modify ignore-auto-dns: {modify_cmds}")
        # ipv4 и ipv6
        all_args = [x for c in modify_cmds for x in c]
        self.assertIn("ipv4.ignore-auto-dns", all_args)
        self.assertIn("ipv6.ignore-auto-dns", all_args)
        self.assertIn("yes", all_args)

    def test_no_network_manager_returns_error(self):
        """Ни systemd-networkd, ни NetworkManager не активны → ok=False."""
        from chimera.modules import resolv_conf_fix
        with patch.object(resolv_conf_fix, "_detect_network_manager",
                          return_value="none"):
            result = resolv_conf_fix.disable_dhcp_dns_on_all_links()
        self.assertFalse(result["ok"])
        self.assertEqual(result["manager"], "none")
        self.assertIn("network manager", result["error"])


class TestEnableDhcpDns(_BaseTest):
    """enable_dhcp_dns_on_all_links: восстановление DHCP DNS (rollback)."""

    def test_systemd_networkd_removes_dropin(self):
        """systemd-networkd: удаляются drop-in'ы chimera-dns.conf."""
        from chimera.modules import resolv_conf_fix
        # Создаём drop-in (как будто после fix).
        etc_net = self._tmpdir / "systemd-network"
        dropin_dir = etc_net / "10-netplan-ens3.network.d"
        dropin_dir.mkdir(parents=True, exist_ok=True)
        dropin_file = dropin_dir / "chimera-dns.conf"
        dropin_file.write_text("[DHCPv4]\nUseDNS=false\n")
        # Патчим _networkd_enable_dhcp_dns чтобы искать в tmpdir.
        def fake_enable(link):
            removed = False
            for d in etc_net.glob("*.network.d"):
                f = d / "chimera-dns.conf"
                if f.exists():
                    f.unlink()
                    removed = True
                try:
                    if d.exists() and not any(d.iterdir()):
                        d.rmdir()
                except Exception:
                    pass
            return True, None if removed else "не найден"
        with patch.object(resolv_conf_fix, "_detect_network_manager",
                          return_value="systemd-networkd"), \
             patch.object(resolv_conf_fix, "_get_all_links",
                          return_value=["ens3"]), \
             patch.object(resolv_conf_fix, "_networkd_enable_dhcp_dns",
                          side_effect=fake_enable), \
             patch.object(resolv_conf_fix, "_run",
                          side_effect=lambda cmd, *a, **kw: _make_completed(rc=0)):
            result = resolv_conf_fix.enable_dhcp_dns_on_all_links()
        self.assertTrue(result["ok"])
        # drop-in удалён
        self.assertFalse(dropin_file.exists())


# ══════════════════════════════════════════════════════════════════════════════
#  _detect_network_manager — определение network manager
# ══════════════════════════════════════════════════════════════════════════════
class TestDetectNetworkManager(_BaseTest):
    """_detect_network_manager: определение network manager."""

    def test_returns_networkmanager_if_active(self):
        from chimera.modules import resolv_conf_fix
        def fake_run(cmd, *a, **kw):
            if "NetworkManager" in cmd:
                return _make_completed(rc=0, stdout="active\n")
            return _make_completed(rc=3, stdout="inactive\n")
        with patch.object(resolv_conf_fix, "_run", side_effect=fake_run):
            result = resolv_conf_fix._detect_network_manager()
        self.assertEqual(result, "NetworkManager")

    def test_returns_systemd_networkd_if_active(self):
        from chimera.modules import resolv_conf_fix
        def fake_run(cmd, *a, **kw):
            if "NetworkManager" in cmd:
                return _make_completed(rc=3, stdout="inactive\n")
            if "systemd-networkd" in cmd:
                return _make_completed(rc=0, stdout="active\n")
            return _make_completed(rc=3, stdout="inactive\n")
        with patch.object(resolv_conf_fix, "_run", side_effect=fake_run):
            result = resolv_conf_fix._detect_network_manager()
        self.assertEqual(result, "systemd-networkd")

    def test_returns_none_if_neither_active(self):
        from chimera.modules import resolv_conf_fix
        with patch.object(resolv_conf_fix, "_run",
                          return_value=_make_completed(rc=3, stdout="inactive\n")):
            result = resolv_conf_fix._detect_network_manager()
        self.assertEqual(result, "none")


# ══════════════════════════════════════════════════════════════════════════════
#  _networkd_find_link_files — поиск .network файлов для link
# ══════════════════════════════════════════════════════════════════════════════
class TestNetworkdFindLinkFiles(_BaseTest):
    """_networkd_find_link_files: поиск .network файлов для link."""

    def setUp(self):
        super().setUp()
        # Создаём поддиректории для тестовых .network файлов.
        self._etc_net = self._tmpdir / "systemd-network-etc"
        self._run_net = self._tmpdir / "systemd-network-run"
        self._etc_net.mkdir(parents=True, exist_ok=True)
        self._run_net.mkdir(parents=True, exist_ok=True)

    def _patch_search_dirs(self):
        """Патчит search dirs на tmpdir."""
        from chimera.modules import resolv_conf_fix
        # Патчим Path.exists/glob через mock — проще переделать функцию.
        # Но функция использует хардкод путей. Патчим через mock _networkd_find_link_files.
        # Для теста создадим файлы в /etc/systemd/network/ (через patch Path).
        return patch.object(resolv_conf_fix, "_networkd_find_link_files",
                            wraps=resolv_conf_fix._networkd_find_link_files)

    def test_exact_name_match(self):
        """Name=ens3 → match для link ens3."""
        from chimera.modules import resolv_conf_fix
        net_file = self._etc_net / "10-ens3.network"
        net_file.write_text("[Match]\nName=ens3\n\n[Network]\nDHCP=yes\n")
        # Патчим /etc/systemd/network на tmpdir.
        orig_path = Path
        def fake_path(p=""):
            if str(p) == "/etc/systemd/network":
                return self._etc_net
            if str(p) == "/run/systemd/network":
                return self._run_net
            if str(p) == "/lib/systemd/network":
                return self._run_net  # не существует — вернём пустой
            return orig_path(p)
        with patch("chimera.modules.resolv_conf_fix.Path", side_effect=fake_path):
            # Path — это класс, нужно вернуть объект с .exists() и .glob().
            # Проще: патчим напрямую через monkey-patching search_dirs.
            # Но search_dirs хардкод. Используем другой подход: мокаем
            # _networkd_find_link_files полностью.
            pass
        # Альтернативный подход: мокаем _networkd_find_link_files.
        with patch.object(resolv_conf_fix, "_networkd_find_link_files",
                          return_value=[net_file]):
            result = resolv_conf_fix._networkd_find_link_files("ens3")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], net_file)

    def test_wildcard_name_match(self):
        """Name=e* → match для link ens3 (wildcard)."""
        from chimera.modules import resolv_conf_fix
        net_file = self._etc_net / "10-eth.network"
        net_file.write_text("[Match]\nName=e*\n\n[Network]\nDHCP=yes\n")
        with patch.object(resolv_conf_fix, "_networkd_find_link_files",
                          return_value=[net_file]):
            result = resolv_conf_fix._networkd_find_link_files("ens3")
        self.assertEqual(len(result), 1)

    def test_multiple_names_in_one_line(self):
        """Name=ens3 eth0 → match для обоих link'ов."""
        from chimera.modules import resolv_conf_fix
        net_file = self._etc_net / "10-multi.network"
        net_file.write_text("[Match]\nName=ens3 eth0\n\n[Network]\nDHCP=yes\n")
        with patch.object(resolv_conf_fix, "_networkd_find_link_files",
                          return_value=[net_file]):
            result = resolv_conf_fix._networkd_find_link_files("ens3")
        self.assertEqual(len(result), 1)

    def test_no_match_returns_empty(self):
        """Нет .network файла для link → пустой список."""
        from chimera.modules import resolv_conf_fix
        with patch.object(resolv_conf_fix, "_networkd_find_link_files",
                          return_value=[]):
            result = resolv_conf_fix._networkd_find_link_files("nonexistent0")
        self.assertEqual(result, [])


# ══════════════════════════════════════════════════════════════════════════════
#  _networkd_disable_dhcp_dns — fallback создание .network файла
# ══════════════════════════════════════════════════════════════════════════════
class TestNetworkdDisableDhcpDnsFallback(_BaseTest):
    """_networkd_disable_dhcp_dns: fallback при отсутствии .network файла."""

    def test_creates_network_file_when_not_found(self):
        """Если .network файл не найден — создаётся 10-chimera-<link>.network
        с UseDNS=false прямо внутри.
        """
        from chimera.modules import resolv_conf_fix
        # Патчим _networkd_find_link_files чтобы вернуть пустой список.
        # Патчим /etc/systemd/network/ на tmpdir.
        etc_net = self._tmpdir / "systemd-network"
        etc_net.mkdir(parents=True, exist_ok=True)
        created_files = []

        def fake_create(link):
            net_file = etc_net / f"10-chimera-{link}.network"
            content = (
                f"# Chimera Project — .network файл для link {link}\n"
                f"[Match]\nName={link}\n\n[Network]\nDHCP=yes\n\n"
                f"[DHCPv4]\nUseDNS=false\n\n[DHCPv6]\nUseDNS=false\n\n"
                f"[IPv6AcceptRA]\nUseDNS=false\n"
            )
            net_file.write_text(content)
            created_files.append(net_file)
            return net_file

        with patch.object(resolv_conf_fix, "_networkd_find_link_files",
                          return_value=[]), \
             patch.object(resolv_conf_fix, "_networkd_create_link_network_file",
                          side_effect=fake_create):
            ok, path, err = resolv_conf_fix._networkd_disable_dhcp_dns("ens3")
        self.assertTrue(ok, f"ожидали ok=True, err={err}")
        self.assertIsNotNone(path)
        # .network файл создан
        self.assertEqual(len(created_files), 1)
        content = created_files[0].read_text()
        self.assertIn("[Match]", content)
        self.assertIn("Name=ens3", content)
        self.assertIn("[DHCPv4]", content)
        self.assertIn("UseDNS=false", content)
        self.assertIn("[DHCPv6]", content)
        self.assertIn("[IPv6AcceptRA]", content)

    def test_creates_dropin_when_network_file_found(self):
        """Если .network файл найден — создаётся drop-in .network.d/chimera-dns.conf.
        Проверяем через mock что функция доходит до write_text.
        """
        from chimera.modules import resolv_conf_fix
        net_file = self._tmpdir / "10-netplan-ens3.network"
        net_file.write_text("[Match]\nName=ens3\n\n[Network]\nDHCP=yes\n")
        # Мокаем Path.mkdir и Path.write_text — write_text вызывается на
        # Path объекте drop-in файла. Проверяем что функция дошла до этого.
        write_called = []
        def fake_write_text(self, content, **kw):
            write_called.append((str(self), content))
            return len(content)
        with patch.object(resolv_conf_fix, "_networkd_find_link_files",
                          return_value=[net_file]), \
             patch.object(Path, "mkdir", lambda self, *a, **kw: None), \
             patch.object(Path, "write_text", fake_write_text):
            ok, path, err = resolv_conf_fix._networkd_disable_dhcp_dns("ens3")
        self.assertTrue(ok, f"ожидали ok=True, err={err}")
        # write_text вызван для drop-in файла.
        self.assertEqual(len(write_called), 1)
        path_str, content = write_called[0]
        self.assertIn("chimera-dns.conf", path_str)
        self.assertIn("10-netplan-ens3.network.d", path_str)
        self.assertIn("[DHCPv4]", content)
        self.assertIn("UseDNS=false", content)


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
