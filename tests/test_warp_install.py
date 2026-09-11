#!/usr/bin/env python3
"""
tests/test_warp_install.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты установки/удаления WARP (warp.install_warp / uninstall_warp):
429-лимит регистраций Cloudflare и переиспользование wgcf-аккаунта.

Кейс из продакшена: uninstall → install ловит 429 Too Many Requests —
Cloudflare жёстко лимитирует число РЕГИСТРАЦИЙ с одного IP, а аккаунт
wgcf с прошлой установки жил только в /tmp и удалялся. Теперь account.toml
сохраняется в WGCF_ACCOUNT_FILE и переживает удаление.

Покрывает:
  1. install_warp — свежая установка сохраняет аккаунт (переустановка
     больше не регистрируется заново).
  2. _wgcf_register — 429 ретраится с паузами (30/60 с), успех со 2-й
     попытки; 3 неудачи → _show_register_error; не-429 не ретраится.
  3. install_warp с сохранённым аккаунтом — register НЕ вызывается,
     только generate; протухший аккаунт (generate failed) → удаление
     временного account.toml + свежая регистрация (wgcf register
     отказывается работать при существующем account.toml).
  4. uninstall_warp — аккаунт СОЗНАТЕЛЬНО остаётся.
  5. _show_register_error — 429-ветка рисует бокс с рекомендациями.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import warp as warp_mod

PROFILE = "[Interface]\nPrivateKey = K\nAddress = 172.16.0.2/32\n"
ACCOUNT = "api_token = 'tok'\ndevice_id = 'dev'\n"
URL = "https://github.com/ViRb3/wgcf/releases/wgcf_2.2.32_linux_amd64"

TMP_BIN = Path("/tmp/wgcf")
TMP_PROFILE = Path("/tmp/wgcf-profile.conf")
TMP_ACCOUNT = Path("/tmp/wgcf-account.toml")


def _cp(cmd, rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(cmd, rc, stdout=stdout, stderr=stderr)


class _Runner:
    """Мок warp._run для сценария установки. Успешный register/generate
    создают настоящие файлы в /tmp (world-writable) — install_warp потом
    читает tmp_profile и зачищает всё в finally."""

    def __init__(self, register_rcs=(0,), generate_rcs=(0,), download_rc=0):
        self.register_rcs = list(register_rcs)
        self.generate_rcs = list(generate_rcs)
        self.download_rc = download_rc
        self.register_calls = 0
        self.generate_calls = 0
        self.download_calls = 0

    def __call__(self, cmd, capture=False, check=False, quiet=False,
                 cwd=None, env=None):
        cmd = [str(a) for a in cmd]
        j = " ".join(cmd)
        if j == f"curl -fsSL -o {TMP_BIN} {URL}":
            self.download_calls += 1
            if self.download_rc == 0:
                TMP_BIN.write_text("#!/bin/sh\n")
            return _cp(cmd, self.download_rc)
        if j == f"{TMP_BIN} register --accept-tos":
            self.register_calls += 1
            rc = self.register_rcs.pop(0) if self.register_rcs else 1
            if rc == 0:
                TMP_ACCOUNT.write_text(ACCOUNT)
                return _cp(cmd, 0)
            return _cp(cmd, rc, stderr="2026/09/12 429 Too Many Requests")
        if j == f"{TMP_BIN} generate":
            self.generate_calls += 1
            rc = self.generate_rcs.pop(0) if self.generate_rcs else 0
            if rc == 0:
                TMP_PROFILE.write_text(PROFILE)
                return _cp(cmd, 0)
            return _cp(cmd, rc, stderr="401 unauthorized")
        return _cp(cmd, 0)


class TestInstallWarp(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="chimera-warp-install-")
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.wg_config = base / "wg-warp.conf"
        self.account = base / "wgcf-account.toml"
        self.orig_route = base / "orig-route.conf"
        for p in (TMP_BIN, TMP_PROFILE, TMP_ACCOUNT):
            p.unlink(missing_ok=True)

    def _install(self, runner, account_exists=False, active=True):
        if account_exists:
            self.account.write_text(ACCOUNT)
        m_time = MagicMock()
        m_show_err = MagicMock()
        with patch.object(warp_mod, "WG_CONFIG", self.wg_config), \
             patch.object(warp_mod, "WGCF_ACCOUNT_FILE", self.account), \
             patch.object(warp_mod, "ORIG_ROUTE_FILE", self.orig_route), \
             patch.object(warp_mod, "_ensure_wireguard_installed",
                          return_value=True), \
             patch.object(warp_mod, "command_exists", return_value=True), \
             patch.object(warp_mod, "_get_latest_wgcf_url",
                          return_value=URL), \
             patch.object(warp_mod, "_run", side_effect=runner), \
             patch.object(warp_mod, "time", m_time), \
             patch.object(warp_mod, "_show_register_error", m_show_err), \
             patch.object(warp_mod, "_inject_table_off", lambda s: s), \
             patch.object(warp_mod, "_state_set"), \
             patch.object(warp_mod, "_warp_service_active",
                          return_value=active), \
             patch.object(warp_mod, "info"), \
             patch.object(warp_mod, "success"), \
             patch.object(warp_mod, "warn"):
            ok = warp_mod.install_warp()
        return ok, m_time, m_show_err

    def test_fresh_install_saves_account(self):
        runner = _Runner(register_rcs=(0,), generate_rcs=(0,))
        ok, m_time, _ = self._install(runner)
        self.assertTrue(ok)
        self.assertEqual(runner.register_calls, 1)
        self.assertTrue(self.account.exists())
        self.assertEqual(self.account.read_text(), ACCOUNT)
        self.assertTrue(self.wg_config.exists())
        # без 429 пауз нет — только штатный sleep(2) после старта сервиса
        self.assertEqual(
            [c.args[0] for c in m_time.sleep.call_args_list if c.args[0] > 5],
            [])
        # /tmp зачищен
        self.assertFalse(TMP_ACCOUNT.exists())

    def test_429_retry_then_success(self):
        runner = _Runner(register_rcs=(1, 0))
        ok, m_time, m_err = self._install(runner)
        self.assertTrue(ok)
        self.assertEqual(runner.register_calls, 2)
        self.assertEqual(m_time.sleep.call_args_list[0].args[0], 30)
        m_err.assert_not_called()
        self.assertTrue(self.account.exists())

    def test_429_all_retries_fail(self):
        runner = _Runner(register_rcs=(1, 1, 1))
        ok, m_time, m_err = self._install(runner)
        self.assertFalse(ok)
        self.assertEqual(runner.register_calls, 3)
        waits = [c.args[0] for c in m_time.sleep.call_args_list if c.args[0] > 5]
        self.assertEqual(waits, [30, 60])
        m_err.assert_called_once()
        self.assertIn("429", m_err.call_args.args[0])
        # неудача — ничего не сохранилось
        self.assertFalse(self.wg_config.exists())
        self.assertFalse(self.account.exists())

    def test_non_429_no_retry(self):
        runner = _Runner()
        runner.register_rcs = []  # дефолт каждой попытки — rc=1 c 429… нет
        # отдельный сценарий: connection refused, без 429
        def refuse(cmd, **kw):
            if " register" in " ".join(cmd):
                runner.register_calls += 1
                return _cp([str(c) for c in cmd], 1,
                           stderr="dial tcp: connection refused")
            return runner.__call__(cmd, **kw)
        runner.register_calls = 0
        ok, m_time, m_err = self._install(refuse)
        self.assertFalse(ok)
        self.assertEqual(runner.register_calls, 1)
        m_err.assert_called_once()
        self.assertIn("connection refused", m_err.call_args.args[0])

    def test_saved_account_skips_register(self):
        runner = _Runner(generate_rcs=(0,))
        ok, _, m_err = self._install(runner, account_exists=True)
        self.assertTrue(ok)
        self.assertEqual(runner.register_calls, 0)   # регистрации не было
        self.assertEqual(runner.generate_calls, 1)
        m_err.assert_not_called()
        self.assertTrue(self.wg_config.exists())

    def test_saved_account_stale_falls_back_to_register(self):
        runner = _Runner(register_rcs=(0,), generate_rcs=(1, 0))
        ok, m_time, m_err = self._install(runner, account_exists=True)
        self.assertTrue(ok)
        self.assertEqual(runner.generate_calls, 2)
        self.assertEqual(runner.register_calls, 1)   # свежая регистрация
        m_err.assert_not_called()
        self.assertTrue(self.account.exists())

    def test_download_fail(self):
        runner = _Runner(download_rc=22)
        ok, _, _ = self._install(runner)
        self.assertFalse(ok)


class TestUninstallKeepsAccount(unittest.TestCase):
    def test_uninstall_keeps_account(self):
        with tempfile.TemporaryDirectory(prefix="chimera-warp-uninst-") as td:
            base = Path(td)
            wg_config = base / "wg-warp.conf"
            account = base / "wgcf-account.toml"
            wg_config.write_text(PROFILE)
            account.write_text(ACCOUNT)
            m_run = MagicMock()
            with patch.object(warp_mod, "WG_CONFIG", wg_config), \
                 patch.object(warp_mod, "WGCF_ACCOUNT_FILE", account), \
                 patch.object(warp_mod, "ORIG_ROUTE_FILE",
                              base / "orig-route.conf"), \
                 patch.object(warp_mod, "_manage_cron"), \
                 patch.object(warp_mod, "_clear_active_routes"), \
                 patch.object(warp_mod, "_run", m_run), \
                 patch.object(warp_mod, "_state_set"), \
                 patch.object(warp_mod, "_warp_state_save_autonomously"), \
                 patch.object(warp_mod, "info"), \
                 patch.object(warp_mod, "success"):
                ok = warp_mod.uninstall_warp()
            self.assertTrue(ok)
            self.assertFalse(wg_config.exists())
            self.assertTrue(account.exists())        # СОЗНАТЕЛЬНО остался


class TestRegisterErrorBox(unittest.TestCase):
    def test_429_box(self):
        rows = []
        with patch.object(warp_mod, "_box_top"), \
             patch.object(warp_mod, "_box_row",
                          side_effect=lambda t="": rows.append(t)), \
             patch.object(warp_mod, "_box_bottom"), \
             patch("builtins.print"):
            warp_mod._show_register_error(
                "Wraps: (3) 429 Too Many Requests")
        joined = " ".join(rows)
        self.assertIn("429", joined)
        self.assertIn("wgcf-account.toml", joined)
        self.assertIn("30–60", joined)

    def test_timeout_box(self):
        rows = []
        with patch.object(warp_mod, "_box_top"), \
             patch.object(warp_mod, "_box_row",
                          side_effect=lambda t="": rows.append(t)), \
             patch.object(warp_mod, "_box_bottom"), \
             patch("builtins.print"):
            warp_mod._show_register_error("TLS handshake timeout")
        self.assertIn("TLS handshake timeout", " ".join(rows))

    def test_unknown_error_no_box(self):
        with patch.object(warp_mod, "_box_top") as m_top, \
             patch.object(warp_mod, "_box_row"), \
             patch.object(warp_mod, "_box_bottom"), \
             patch("builtins.print"):
            warp_mod._show_register_error("something else entirely")
        m_top.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
