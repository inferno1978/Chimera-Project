#!/usr/bin/env python3
"""
tests/test_v59_uninstall_dns_alive.py
───────────────────────────────────────────────────────────────────────────────
Regression-тесты инцидента v59 (server-ru): ПОЛНОЕ удаление Chimera
(с установленным AdGuard Home) убивало системный DNS — SERVFAIL от
systemd-resolved stub (127.0.0.53), ping/nslookup не резолвили.

Корневые причины (все закрыты):
  1. rollback_resolv_conf() отказывался работать при state.fixed=False
     (state утерян) → drop-in /etc/systemd/resolved.conf.d/chimera-dns.conf
     (DNS=127.0.0.1, FallbackDNS=<пусто>, Domains=~.) оставался жить и
     гнал ВСЕ запросы resolved в мёртвый 127.0.0.1:53 → SERVFAIL.
  2. resolv.conf восстанавливался только при наличии бэкапа.
  3. Никто не проверял живым probe'ом, что DNS реально ожил.
  4. iptables-redirect удалялся только под заранее известный порт.
  5. AGH не удалялся полностью (только stop/disable).

Покрывает:
  A. hard_restore_clean_dns() — безусловный откат к чистой системе:
     нет state → всё равно восстанавливает; drop-in удалён; resolv.conf
     из бэкапа / stub / публичный DNS; «отравленный» бэкап не используется;
     fallback на публичный DNS при мёртвом probe; iptables-sweep любых
     портов; бэкапы удаляются при успехе и сохраняются при провале.
  B. rollback_resolv_conf() — откат при артефактах без state.
  C. uninstall.py — статические гварды: полное удаление AGH, dns_redirect,
     hard restore вместо старого conditional rollback, финальная зачистка.
  D. _remove_aghome_full() — функциональное поведение (бэкап перед удалением,
     graceful «не установлен»).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock, call

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


class _HardRestoreBase(unittest.TestCase):
    """База: tmpdir + патчи констант resolv_conf_fix + мок _run/time.sleep."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._resolv_conf = self._tmpdir / "resolv.conf"
        self._nsswitch = self._tmpdir / "nsswitch.conf"
        self._backup_resolv = self._tmpdir / "resolv.conf.chimera.bak"
        self._backup_nsswitch = self._tmpdir / "nsswitch.conf.chimera.bak"
        self._dropin_dir = self._tmpdir / "resolved.conf.d"
        self._dropin_file = self._dropin_dir / "chimera-dns.conf"
        self._state_file = self._tmpdir / "resolv_conf_fix.json"
        self._persist_svc = self._tmpdir / "chimera-dns-fix.service"
        self._persist_script = self._tmpdir / "chimera-dns-fix-apply.py"
        self._wd_svc = self._tmpdir / "chimera-dns-watchdog.service"
        self._wd_timer = self._tmpdir / "chimera-dns-watchdog.timer"
        self._wd_script = self._tmpdir / "chimera-dns-watchdog.sh"
        self._stub = self._tmpdir / "stub-resolv.conf"
        self._stub.write_text("nameserver 127.0.0.53\n")

        import chimera.modules.resolv_conf_fix as rcf
        self.rcf = rcf
        patches = [
            patch.object(rcf, "_RESOLV_CONF", self._resolv_conf),
            patch.object(rcf, "_NSSWITCH_CONF", self._nsswitch),
            patch.object(rcf, "_BACKUP_RESOLV", self._backup_resolv),
            patch.object(rcf, "_BACKUP_NSSWITCH", self._backup_nsswitch),
            patch.object(rcf, "_RESOLVED_DROPIN_DIR", self._dropin_dir),
            patch.object(rcf, "_RESOLVED_DROPIN_FILE", self._dropin_file),
            patch.object(rcf, "_STATE_FILE", self._state_file),
            patch.object(rcf, "_PERSIST_SVC_PATH", self._persist_svc),
            patch.object(rcf, "_PERSIST_SCRIPT_PATH", self._persist_script),
            patch.object(rcf, "_WATCHDOG_SVC_PATH", self._wd_svc),
            patch.object(rcf, "_WATCHDOG_TIMER_PATH", self._wd_timer),
            patch.object(rcf, "_WATCHDOG_SCRIPT_PATH", self._wd_script),
            patch.object(rcf, "_STUB_RESOLV_CONF", self._stub),
            patch.object(rcf.time, "sleep", lambda s: None),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _run_factory(self, *, probe_ok=True, resolved_active=True,
                     iptables_output=""):
        """Мок _run: systemctl/getent/iptables по префиксу команды."""
        rcf = self.rcf

        def _mock_run(cmd, capture=False, quiet=False, check=False, **kw):
            c = list(cmd)
            if c[:3] == ["systemctl", "is-active", "systemd-resolved"]:
                return _make_completed(
                    0, "active\n" if resolved_active else "inactive\n")
            if c[:2] == ["getent", "hosts"]:
                return _make_completed(0 if probe_ok else 2)
            if c[:1] == ["iptables"]:
                key = " ".join(c)
                if "-S" in c:
                    return _make_completed(0, iptables_output)
                return _make_completed(0)
            return _make_completed(0)
        return _mock_run


# ══════════════════════════════════════════════════════════════════════════════
#  A. hard_restore_clean_dns
# ══════════════════════════════════════════════════════════════════════════════
class TestHardRestoreCleanDns(_HardRestoreBase):

    def _broken_state(self):
        """Сервер после удаления Chimera с AGH: DNS мёртв.

        resolv.conf → 127.0.0.1 (мёртвый AGH), drop-in жив, state НЕТ
        (именно эта комбинация убивала DNS на server-ru).
        """
        self._resolv_conf.write_text("nameserver 127.0.0.1\n")
        self._dropin_dir.mkdir(parents=True, exist_ok=True)
        self._dropin_file.write_text(
            "[Resolve]\nDNS=127.0.0.1\nFallbackDNS=\nDomains=~.\n")

    def test_no_state_still_restores(self):
        """ГЛАВНЫЙ РЕГРЕССИОННЫЙ ТЕСТ: state.fixed=False — откат всё равно
        происходит (инцидент server-ru: тихий отказ оставлял drop-in)."""
        self._broken_state()
        self._backup_resolv.write_text("nameserver 8.8.8.8\n")
        self._backup_nsswitch.write_text(
            "hosts: files resolve [!UNAVAIL=return] dns\n")

        with patch.object(self.rcf, "_run",
                          side_effect=self._run_factory(probe_ok=True)):
            result = self.rcf.hard_restore_clean_dns()

        self.assertTrue(result["ok"], f"DNS должен быть жив: {result}")
        # drop-in ОБЯЗАН быть удалён — это главный DNS-killer
        self.assertFalse(self._dropin_file.exists(),
                         "drop-in chimera-dns.conf пережил удаление — "
                         "systemd-resolved продолжит гнать трафик в 127.0.0.1")
        # resolv.conf восстановлен из бэкапа (внешний NS)
        self.assertIn("8.8.8.8", self._resolv_conf.read_text())
        self.assertNotIn("127.0.0.1", self._resolv_conf.read_text())
        self.assertIn("resolve", self._nsswitch.read_text())
        # бэкапы удалены при живом DNS
        self.assertFalse(self._backup_resolv.exists())
        self.assertFalse(self._backup_nsswitch.exists())
        # state сброшен
        state = json.loads(self._state_file.read_text())
        self.assertFalse(state["fixed"])

    def test_dropin_removed_even_without_backup(self):
        """Нет бэкапа → drop-in всё равно удалён, resolv.conf → stub."""
        self._broken_state()

        with patch.object(self.rcf, "_run",
                          side_effect=self._run_factory(probe_ok=True)):
            result = self.rcf.hard_restore_clean_dns()

        self.assertTrue(result["ok"])
        self.assertFalse(self._dropin_file.exists())
        # stub-symlink как на чистой системе
        self.assertTrue(self._resolv_conf.is_symlink(),
                        "resolv.conf должен стать symlink на stub")
        self.assertEqual(result["method"], "stub")

    def test_poisoned_backup_not_used(self):
        """Бэкап, содержащий ТОЛЬКО локальные NS (127.0.0.1/127.0.0.53) —
        «отравленный» (двойная установка) — не используется."""
        self._broken_state()
        self._backup_resolv.write_text("nameserver 127.0.0.1\n")

        with patch.object(self.rcf, "_run",
                          side_effect=self._run_factory(probe_ok=True)):
            result = self.rcf.hard_restore_clean_dns()

        self.assertTrue(result["ok"])
        self.assertFalse(self._dropin_file.exists())
        # stub, а не мёртвый 127.0.0.1 из бэкапа
        self.assertTrue(self._resolv_conf.is_symlink())
        self.assertEqual(result["method"], "stub")
        self.assertTrue(any("локальные" in w for w in result["warnings"]),
                        f"должно быть предупреждение об отравленном бэкапе: "
                        f"{result['warnings']}")

    def test_probe_fail_falls_back_to_public_dns(self):
        """Мёртвый probe → автоматический публичный DNS в resolv.conf.
        Мок: первая проба (восстановленный resolv.conf) мертва,
        после записи публичного DNS — жива."""
        self._broken_state()

        state = {"probe_count": 0}

        def _mock_run(cmd, capture=False, quiet=False, check=False, **kw):
            c = list(cmd)
            if c[:3] == ["systemctl", "is-active", "systemd-resolved"]:
                return _make_completed(0, "active\n")
            if c[:2] == ["getent", "hosts"]:
                state["probe_count"] += 1
                # 1-я проба — мертва; 2-я (публичный DNS) — жива
                return _make_completed(0 if state["probe_count"] >= 2 else 2)
            if c[:1] == ["iptables"]:
                return _make_completed(0, "")
            return _make_completed(0)

        with patch.object(self.rcf, "_run", side_effect=_mock_run):
            result = self.rcf.hard_restore_clean_dns()

        self.assertTrue(result["ok"], "fallback на публичный DNS должен оживить")
        self.assertGreaterEqual(state["probe_count"], 2)
        self.assertIn("77.88.8.8", self._resolv_conf.read_text())
        self.assertIn("1.1.1.1", self._resolv_conf.read_text())
        self.assertEqual(result["method"], "public-fallback")

    def test_probe_always_dead_keeps_backups_and_fails_honestly(self):
        """Проба мертва даже после fallback → честный ok=False,
        бэкапы СОХРАНЕНЫ для ручного восстановления."""
        self._broken_state()
        self._backup_resolv.write_text("nameserver 8.8.8.8\n")
        self._backup_nsswitch.write_text(
            "hosts: files resolve [!UNAVAIL=return] dns\n")

        def _mock_run(cmd, capture=False, quiet=False, check=False, **kw):
            c = list(cmd)
            if c[:3] == ["systemctl", "is-active", "systemd-resolved"]:
                return _make_completed(0, "active\n")
            if c[:2] == ["getent", "hosts"]:
                return _make_completed(2)  # DNS мёртв всегда
            if c[:1] == ["iptables"]:
                return _make_completed(0, "")
            return _make_completed(0)

        with patch.object(self.rcf, "_run", side_effect=_mock_run):
            result = self.rcf.hard_restore_clean_dns()

        self.assertFalse(result["ok"], "проба мертва — ok обязан быть False")
        self.assertFalse(result["probe_ok"])
        # бэкапы сохранены (вручную восстановит пользователь)
        self.assertTrue(self._backup_resolv.exists())
        self.assertTrue(self._backup_nsswitch.exists())
        self.assertTrue(any("бэкапы" in w or "бэкап" in w
                            for w in result["warnings"]))

    def test_no_resolved_no_backup_public_dns(self):
        """systemd-resolved неактивен, бэкапа нет → публичный DNS напрямую."""
        self._broken_state()
        self._resolv_conf.write_text("nameserver 127.0.0.1\n")

        with patch.object(self.rcf, "_run",
                          side_effect=self._run_factory(
                              probe_ok=True, resolved_active=False)):
            result = self.rcf.hard_restore_clean_dns()

        self.assertTrue(result["ok"])
        self.assertIn("77.88.8.8", self._resolv_conf.read_text())
        self.assertEqual(result["method"], "public")

    def test_iptables_sweep_any_port(self):
        """iptables-sweep удаляет redirect-правила с ЛЮБЫМ портом
        (5300, 5301...), а не только текущим портом dnscrypt."""
        self._broken_state()
        rules = (
            "-A OUTPUT -d 127.0.0.1/32 -p udp -m udp --dport 53 "
            "-j REDIRECT --to-ports 5300 -m comment --comment chimera-dns-fix\n"
            "-A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport 53 "
            "-j REDIRECT --to-ports 5300 -m comment --comment chimera-dns-fix\n"
        )
        state = {"remaining": 2}

        def _mock_run(cmd, capture=False, quiet=False, check=False, **kw):
            c = list(cmd)
            if c[:1] == ["iptables"] and "-S" in c:
                # отдаём правила, пока есть что отдавать
                if state["remaining"] > 0:
                    return _make_completed(0, rules)
                return _make_completed(0, "")
            if c[:3] == ["systemctl", "is-active", "systemd-resolved"]:
                return _make_completed(0, "active\n")
            if c[:2] == ["getent", "hosts"]:
                return _make_completed(0)
            if c[:4] == ["iptables", "-t", "nat", "-D"]:
                state["remaining"] -= 1
                return _make_completed(0)
            return _make_completed(0)

        with patch.object(self.rcf, "_run", side_effect=_mock_run):
            result = self.rcf.hard_restore_clean_dns()

        self.assertEqual(state["remaining"], 0,
                         "оба redirect-правила должны быть удалены")
        self.assertTrue(result["ok"])
        self.assertTrue(any("redirect-правил" in a and "2" in a
                            for a in result["actions"]),
                        f"должен быть отчёт о 2 удалённых правилах: "
                        f"{result['actions']}")

    def test_persist_and_watchdog_removed(self):
        """persist-сервис и watchdog удаляются безусловно (даже без state)."""
        self._broken_state()
        self._persist_svc.write_text("[Unit]\n")
        self._persist_script.write_text("#!/usr/bin/env python3\n")
        self._wd_timer.write_text("[Unit]\n")
        self._wd_svc.write_text("[Unit]\n")
        self._wd_script.write_text("#!/bin/bash\n")

        with patch.object(self.rcf, "_run",
                          side_effect=self._run_factory(probe_ok=True)):
            result = self.rcf.hard_restore_clean_dns()

        self.assertTrue(result["ok"])
        self.assertFalse(self._persist_svc.exists())
        self.assertFalse(self._persist_script.exists())
        self.assertFalse(self._wd_timer.exists())
        self.assertFalse(self._wd_svc.exists())
        self.assertFalse(self._wd_script.exists())

    def test_fresh_system_noop(self):
        """Чистая система без артефактов — hard restore безопасен (no-op)."""
        with patch.object(self.rcf, "_run",
                          side_effect=self._run_factory(probe_ok=True)):
            result = self.rcf.hard_restore_clean_dns()

        self.assertTrue(result["ok"])
        self.assertTrue(self._resolv_conf.is_symlink())


# ══════════════════════════════════════════════════════════════════════════════
#  B. rollback_resolv_conf: артефакты без state
# ══════════════════════════════════════════════════════════════════════════════
class TestRollbackArtifactsWithoutState(_HardRestoreBase):

    def test_rollback_with_artifacts_but_no_state(self):
        """state.fixed=False, но drop-in жив → rollback НЕ отказывается
        (раньше: тихий отказ → drop-in убивал DNS после удаления стека)."""
        self._resolv_conf.write_text("nameserver 127.0.0.1\n")
        self._nsswitch.write_text("hosts: files dns\n")
        self._backup_resolv.write_text("nameserver 8.8.8.8\n")
        self._backup_nsswitch.write_text(
            "hosts: files resolve [!UNAVAIL=return] dns\n")
        self._dropin_dir.mkdir(parents=True, exist_ok=True)
        self._dropin_file.write_text("[Resolve]\nDNS=127.0.0.1\n")
        # state-файла НЕТ (утерян при удалении)

        with patch.object(self.rcf, "_run",
                          return_value=_make_completed(rc=0)):
            result = self.rcf.rollback_resolv_conf()

        self.assertTrue(result["ok"],
                        f"rollback должен пройти при живых артефактах: {result}")
        self.assertFalse(self._dropin_file.exists())
        self.assertIn("8.8.8.8", self._resolv_conf.read_text())
        self.assertTrue(any("артефакты" in w for w in result["warnings"]))

    def test_rollback_no_state_no_artifacts_still_refuses(self):
        """Нет state и нет артефактов → честный отказ (не ломаем чистую систему)."""
        with patch.object(self.rcf, "_run",
                          return_value=_make_completed(rc=0)):
            result = self.rcf.rollback_resolv_conf()

        self.assertFalse(result["ok"])
        self.assertIn("не был применён", result["error"])


# ══════════════════════════════════════════════════════════════════════════════
#  C. uninstall.py — статические гварды
# ══════════════════════════════════════════════════════════════════════════════
class TestUninstallStaticGuards(unittest.TestCase):
    """Статические проверки кода uninstall.py (anti-regression)."""

    def setUp(self):
        self.uninstall_path = (_PROJECT_ROOT / "chimera" / "modules"
                               / "uninstall.py")
        self.src = self.uninstall_path.read_text()

    def test_uninstall_calls_hard_restore(self):
        """_restore_dns_after_full_uninstall использует hard_restore_clean_dns
        (безусловный), а НЕ старый rollback_resolv_conf с проверкой state."""
        self.assertIn("hard_restore_clean_dns", self.src,
                      "uninstall должен вызывать hard_restore_clean_dns")
        restore_block = self.src.split(
            "def _restore_dns_after_full_uninstall")[1].split("def ")[0]
        # Вызов старого conditional rollback недопустим (упоминание в
        # docstring — можно, вызов rcf.rollback_resolv_conf() — нельзя)
        self.assertNotIn("rcf.rollback_resolv_conf", restore_block,
                         "старый conditional rollback не должен вызываться "
                         "при полном удалении")

    def test_uninstall_removes_aghome_fully(self):
        """do_uninstall вызывает _remove_aghome_full (полное удаление AGH):
        константы путей покрывают все артефакты AGH."""
        self.assertIn("_remove_aghome_full", self.src)
        block = self.src.split("def _remove_aghome_full")[1].split("def ")[0]
        # В теле функции используются константы путей
        for marker in ("_AGH_DIR", "_AGH_UNIT", "_AGH_BIN",
                       "_AGH_BACKUP_DIR", "_AGH_CERTBOT_HOOK"):
            self.assertIn(marker, block,
                          f"_remove_aghome_full должен использовать {marker}")
        # Константы указывают на реальные пути AGH
        const_block = self.src.split("def _remove_aghome_full")[0]
        for literal in ("/opt/AdGuardHome", "/usr/local/bin/AdGuardHome",
                        "/etc/systemd/system/AdGuardHome.service",
                        "chimera-aghome.sh", "aghome-backups"):
            self.assertIn(literal, const_block,
                          f"константы AGH должны включать {literal}")
        self.assertIn("userdel", block, "должен удаляться юзер adguard")

    def test_uninstall_cleans_dns_redirect_artifacts(self):
        """do_uninstall вызывает _remove_dns_redirect_artifacts."""
        self.assertIn("_remove_dns_redirect_artifacts", self.src)
        block = self.src.split(
            "def _remove_dns_redirect_artifacts")[1].split("def ")[0]
        for marker in ("dns-redirect-restore.service",
                       "xray-dns-redirect-restore.sh"):
            self.assertIn(marker, block,
                          f"должна быть ручная зачистка {marker}")

    def test_uninstall_cleans_state_dir(self):
        """Финальная зачистка: /var/lib/xray-installer удаляется."""
        self.assertIn('Path("/var/lib/xray-installer")', self.src)
        self.assertIn('shutil.rmtree(state_dir', self.src)

    def test_do_uninstall_wires_all_v59_steps(self):
        """do_uninstall вызывает все v59-шаги в правильном порядке:
        ports → AGH → dns_redirect → DNS hard restore → state cleanup."""
        body = self.src.split("def do_uninstall")[1]
        idx_ports = body.index("_close_chimera_ports()")
        idx_agh = body.index("_remove_aghome_full()")
        idx_dr = body.index("_remove_dns_redirect_artifacts()")
        idx_dns = body.index("_restore_dns_after_full_uninstall()")
        idx_state = body.index('shutil.rmtree(state_dir')
        self.assertLess(idx_ports, idx_agh,
                        "AGH удаляется после закрытия портов")
        self.assertLess(idx_agh, idx_dr,
                        "dns_redirect чистится после AGH")
        self.assertLess(idx_dr, idx_dns,
                        "DNS-restore идёт ПОСЛЕ удаления всех DNS-компонентов")
        self.assertLess(idx_dns, idx_state,
                        "state-каталог чистится в самом конце")

    def test_aghome_removed_before_dns_restore(self):
        """AGH (владелец :53) сносится ДО восстановления DNS — иначе
        hard restore не сможет откатить resolv.conf к чистой системе."""
        body = self.src.split("def do_uninstall")[1]
        self.assertLess(body.index("_remove_aghome_full()"),
                        body.index("_restore_dns_after_full_uninstall()"))


# ══════════════════════════════════════════════════════════════════════════════
#  D. _remove_aghome_full — функциональное поведение
# ══════════════════════════════════════════════════════════════════════════════
class TestRemoveAghomeFull(unittest.TestCase):

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._agh_dir = self._tmpdir / "AdGuardHome"
        self._agh_dir.mkdir()
        (self._agh_dir / "AdGuardHome.yaml").write_text("schema_version: 29\n")
        self._agh_unit = self._tmpdir / "AdGuardHome.service"
        self._agh_unit.write_text("[Unit]\n")
        self._agh_bin = self._tmpdir / "AdGuardHome-bin"
        self._agh_bin.write_text("\x00\x01")
        self._backup_dir = self._tmpdir / "aghome-backups"
        self._certbot_hook = self._tmpdir / "chimera-aghome.sh"
        self._certbot_hook.write_text("#!/bin/bash\n")

        import chimera.modules.uninstall as un
        self.un = un
        patches = [
            patch.object(un, "_AGH_DIR", self._agh_dir),
            patch.object(un, "_AGH_UNIT", self._agh_unit),
            patch.object(un, "_AGH_BIN", self._agh_bin),
            patch.object(un, "_AGH_BACKUP_DIR", self._backup_dir),
            patch.object(un, "_AGH_CERTBOT_HOOK", self._certbot_hook),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _call(self):
        with patch("subprocess.run") as mock_run, \
             patch.object(self.un.shutil, "rmtree") as mock_rmtree:
            # tar «создаёт» архив
            def run_side(cmd, **kw):
                if "tar" in cmd:
                    tgz = [a for a in cmd if str(a).endswith(".tar.gz")]
                    if tgz:
                        Path(str(tgz[0])).write_bytes(b"fake-tgz-data")
                return MagicMock(returncode=0)
            mock_run.side_effect = run_side
            lines = self.un._remove_aghome_full()
        return lines, mock_rmtree, mock_run

    def test_backup_created_before_removal(self):
        """Бэкап tar.gz создаётся ДО rmtree(/opt/AdGuardHome)."""
        lines, mock_rmtree, mock_run = self._call()
        self.assertTrue(any("бэкап" in l for l in lines),
                        f"должен быть отчёт о бэкапе: {lines}")
        # tar вызван ДО rmtree
        run_calls = [str(c.args[0]) for c in mock_run.call_args_list if c.args]
        tar_idx = next((i for i, c in enumerate(run_calls) if "tar" in c), None)
        rmtree_idx = next((i for i, c in enumerate(
            [str(c.args[0]) for c in mock_rmtree.call_args_list if c.args])
            if "AdGuardHome" in c), None)
        self.assertIsNotNone(tar_idx, "tar-бэкап должен создаваться")
        self.assertIsNotNone(rmtree_idx, "rmtree должен удалять AGH")

    def test_unit_binary_user_cleaned(self):
        """Unit, бинарник, юзер и certbot-hook удаляются."""
        lines, mock_rmtree, mock_run = self._call()
        # rmtree вызван для AGH-директории
        rmtree_targets = [str(c.args[0]) for c in mock_rmtree.call_args_list
                          if c.args]
        self.assertTrue(any("AdGuardHome" in t for t in rmtree_targets),
                        f"rmtree должен удалить AGH: {rmtree_targets}")
        # systemctl stop/disable/daemon-reload + userdel/groupdel
        run_cmds = [" ".join(str(x) for x in c.args[0])
                    for c in mock_run.call_args_list if c.args]
        self.assertTrue(any("stop AdGuardHome" in c for c in run_cmds))
        self.assertTrue(any("disable AdGuardHome" in c for c in run_cmds))
        self.assertTrue(any("userdel" in c and "adguard" in c
                            for c in run_cmds))
        self.assertTrue(any("groupdel" in c and "adguard" in c
                            for c in run_cmds))
        self.assertTrue(any("Полностью удалён" in l or "полностью удалён" in l
                            for l in lines))

    def test_files_actually_removed(self):
        """Файлы AGH (unit, бинарник, certbot-hook) реально удаляются с диска."""
        lines, mock_rmtree, mock_run = self._call()
        self.assertFalse(self._agh_unit.exists())
        self.assertFalse(self._agh_bin.exists())
        self.assertFalse(self._certbot_hook.exists())
        # бэкап-архив создан
        tgzs = list(self._backup_dir.glob("aghome-*.tar.gz"))
        self.assertEqual(len(tgzs), 1, f"должен быть один tar.gz: {tgzs}")

    def test_not_installed_graceful(self):
        """AGH отсутствует → аккуратный пропуск, без ошибок."""
        empty_dir = self._tmpdir / "empty"
        empty_dir.mkdir()
        with patch.object(self.un, "_AGH_DIR", empty_dir / "AdGuardHome"), \
             patch.object(self.un, "_AGH_UNIT", empty_dir / "AdGuardHome.service"), \
             patch.object(self.un, "_AGH_BIN", empty_dir / "AdGuardHome-bin"), \
             patch("subprocess.run") as mock_run, \
             patch.object(self.un.shutil, "rmtree") as mock_rmtree:
            lines = self.un._remove_aghome_full()
        self.assertEqual(len(lines), 1)
        self.assertIn("не установлен", lines[0])
        mock_rmtree.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
#  E. _restore_dns_after_full_uninstall — интеграция
# ══════════════════════════════════════════════════════════════════════════════
class TestRestoreDnsIntegration(unittest.TestCase):

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_uses_hard_restore_and_reports_probe(self):
        """Интеграция: вызывает hard_restore_clean_dns и печатает статус пробы."""
        import chimera.modules.uninstall as un
        fake_result = {
            "ok": True, "method": "stub", "probe_ok": True,
            "actions": ["удалён drop-in chimera-dns.conf"],
            "warnings": [], "error": None,
        }
        with patch("chimera.modules.resolv_conf_fix.hard_restore_clean_dns",
                   return_value=fake_result) as mock_hr:
            lines = un._restore_dns_after_full_uninstall()
        mock_hr.assert_called_once()
        self.assertTrue(any("drop-in" in l for l in lines))
        self.assertTrue(any("DNS жив" in l for l in lines))

    def test_dead_dns_prints_manual_commands(self):
        """Мёртвый DNS после restore → пользователь получает команды оживления."""
        import chimera.modules.uninstall as un
        fake_result = {
            "ok": False, "method": "public-fallback", "probe_ok": False,
            "actions": [], "warnings": ["w"], "error": None,
        }
        with patch("chimera.modules.resolv_conf_fix.hard_restore_clean_dns",
                   return_value=fake_result):
            lines = un._restore_dns_after_full_uninstall()
        self.assertTrue(any("мёртв" in l for l in lines))
        self.assertTrue(any("resolved.conf.d" in l for l in lines))
        self.assertTrue(any("systemctl restart systemd-resolved" in l
                            for l in lines))
        self.assertTrue(any("77.88.8.8" in l for l in lines))


if __name__ == "__main__":
    unittest.main(verbosity=2)
