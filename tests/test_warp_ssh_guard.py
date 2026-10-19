#!/usr/bin/env python3
"""
tests/test_warp_ssh_guard.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты защиты SSH в chimera/modules/warp.py (живой кейс окт.2026 №12:
FULL-режим обрывал SSH-сессию юзера из Discord — «туннель не запускается,
отдельные домены работают», SELECTIVE дефолт не трогал и не отваливался).

Класс проблем, закрываемый этим фиксом:
  1. _capture_original_route не понимал on-link дефолт (`default dev eth0`
     без via) и прерывал разбор на wg-warp-строке → защитных маршрутов нет
     вовсе → split-default глотает обратные пакеты SSH → сессия рвётся,
     «y» не вводится → автооткат watchdog'ом → «Туннель: не активен».
  2. SSH IP в state.json протух (динамика/CGNAT/ручной ввод при install),
     автообновления из живой сессии не существовало, сменить IP без полного
     цикла удаления/установки было нельзя.
  3. Диагностика не сверяла state-IP с IP живых сессий.

Покрывает:
  • _capture_original_route — via/on-link/wg-warp-skip/no-clobber
  • _load_original_route — on-link (MAIN_GW пустой) + совместимость
  • _live_ssh_peer_ips — env → ss (в т.ч. кастомный порт sshd, v6/0.0.0.0
    отбрасываются) → who; дедуп с сохранением порядка
  • _refresh_ssh_protection_set — автообновление state, объединение наборов
  • _warp_apply_full_mode — мульти-IP маршруты via-gw и dev-only (on-link),
    endpoint-маршрут, split-default, запись state.json
  • _apply_mode — FULL уходит в commit-confirm обёртку (wiring)
  • _check_ssh_protection — предупреждение о протухшем state-IP
  • _menu_change_ssh_ip — auto/manual/clear/invalid сценарии
  • контракт меню: пункт [10] «Сменить SSH IP» и его обработчик
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

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


def _cp(cmd, rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(cmd, rc, stdout=stdout, stderr=stderr)


class FakeRunner:
    """Мок warp._run: сценарные ответы по подстроке-ключу (первое совпадение
    в порядке вставки) + журнал всех вызовов argv-строками."""

    def __init__(self, responses=None, default_rc=0, default_stdout=""):
        self.responses: list[tuple[str, tuple[int, str, str]]] = list(responses or [])
        self.default_rc = default_rc
        self.default_stdout = default_stdout
        self.calls: list[str] = []

    def __call__(self, cmd, capture=False, check=False, quiet=False,
                 cwd=None, env=None):
        cmd = [str(a) for a in cmd]
        joined = " ".join(cmd)
        self.calls.append(joined)
        for key, (rc, out, err) in self.responses:
            if key in joined:
                return _cp(cmd, rc, stdout=out, stderr=err)
        return _cp(cmd, self.default_rc, stdout=self.default_stdout, stderr="")


WG_CONF = ("[Interface]\nPrivateKey = K\nAddress = 172.16.0.2/32\n\n"
           "[Peer]\nPublicKey = P\nEndpoint = 162.159.192.1:2408\n")


class _TmpCase(unittest.TestCase):
    """База: fake _core в sys.modules + tmp-пути для констант модуля."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self.tmp = Path(tempfile.mkdtemp())
        sys.modules["chimera._core"].STATE_FILE = self.tmp / "state.json"
        import chimera.modules.warp as w
        self.warp = w
        self._patches = [
            patch.object(w, "ORIG_ROUTE_FILE", self.tmp / "orig-route.conf"),
            patch.object(w, "WG_CONFIG", self.tmp / "wg-warp.conf"),
        ]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self._rmtree)

    def _rmtree(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
class TestCaptureOriginalRoute(_TmpCase):
    """_capture_original_route — via / on-link / wg-warp-skip / no-clobber."""

    def _run_with(self, default_out=""):
        runner = FakeRunner([("route show default", (0, default_out, ""))])
        with patch.object(self.warp, "_run", runner):
            result = self.warp._capture_original_route()
        return result, runner

    def test_via_default(self):
        result, _ = self._run_with(
            "default via 192.168.1.1 dev ens3 proto static metric 100\n")
        self.assertEqual(result, ("192.168.1.1", "ens3"))
        self.assertEqual(
            (self.tmp / "orig-route.conf").read_text(),
            "MAIN_GW=192.168.1.1\nMAIN_IF=ens3\n")

    def test_onlink_default_without_via(self):
        """`default dev ens9 ...` (без via) — валидный захват (None, dev)."""
        result, _ = self._run_with("default dev ens9 proto static\n")
        self.assertEqual(result, (None, "ens9"))
        self.assertEqual(
            (self.tmp / "orig-route.conf").read_text(),
            "MAIN_GW=\nMAIN_IF=ens9\n")

    def test_wg_warp_line_skipped_real_default_behind(self):
        """РЕГРЕССИЯ: wg-warp-строка не должна прерывать разбор — за ней
        может стоять живой via-default (старый код возвращал None)."""
        result, _ = self._run_with(
            "default dev wg-warp metric 50\n"
            "default via 10.0.0.1 dev ens3 metric 100\n")
        self.assertEqual(result, ("10.0.0.1", "ens3"))

    def test_only_wg_warp_default_does_not_clobber_saved(self):
        """Только wg-warp дефолт → None, ранее сохранённый файл НЕ затёрт."""
        saved = self.tmp / "orig-route.conf"
        saved.write_text("MAIN_GW=10.9.9.1\nMAIN_IF=ens3\n")
        result, _ = self._run_with("default via 162.159.192.1 dev wg-warp\n")
        self.assertIsNone(result)
        self.assertEqual(saved.read_text(), "MAIN_GW=10.9.9.1\nMAIN_IF=ens3\n")

    def test_no_default_at_all(self):
        result, _ = self._run_with("")
        self.assertIsNone(result)


class TestLoadOriginalRoute(_TmpCase):
    """_load_original_route — on-link формат + обратная совместимость."""

    def test_onlink_file_gw_none(self):
        (self.tmp / "orig-route.conf").write_text("MAIN_GW=\nMAIN_IF=eth0\n")
        self.assertEqual(self.warp._load_original_route(), (None, "eth0"))

    def test_legacy_file_still_works(self):
        (self.tmp / "orig-route.conf").write_text("MAIN_GW=1.2.3.4\nMAIN_IF=eth0\n")
        self.assertEqual(self.warp._load_original_route(), ("1.2.3.4", "eth0"))

    def test_missing_file(self):
        self.assertIsNone(self.warp._load_original_route())

    def test_gw_without_dev_is_none(self):
        (self.tmp / "orig-route.conf").write_text("MAIN_GW=1.2.3.4\n")
        self.assertIsNone(self.warp._load_original_route())


# ─────────────────────────────────────────────────────────────────────────────
class TestLiveSshPeerIps(_TmpCase):
    """_live_ssh_peer_ips — env → ss → who, фильтры и дедуп."""

    SS_OK = (
        "Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
        "0 0 10.0.0.5:22 203.0.113.77:51424 users:((\"sshd\",pid=998,fd=3))\n"
        "0 0 10.0.0.5:2222 198.51.100.9:40000 users:((\"sshd\",pid=999,fd=4))\n"
        "0 0 10.0.0.5:443 203.0.113.50:51234 users:((\"nginx\",pid=1,fd=6))\n"
        "0 0 10.0.0.5:22 203.0.113.77:51425 users:((\"sshd\",pid=998,fd=5))\n"
    )

    def _live(self, responses, env=None):
        runner = FakeRunner(responses)
        environ = env if env is not None else {"PATH": "/usr/bin"}
        with patch.object(self.warp, "_run", runner), \
                patch.dict(os.environ, environ, clear=True):
            return self.warp._live_ssh_peer_ips()

    def test_env_then_ss_dedup_order(self):
        ips = self._live(
            [("ss -tnp", (0, self.SS_OK, "")), ("who", (0, "", ""))],
            env={"SSH_CLIENT": "203.0.113.77 55123 22"},
        )
        # env первым, ss добавляет второй sshd-пир, nginx и дубль отброшены
        self.assertEqual(ips, ["203.0.113.77", "198.51.100.9"])

    def test_custom_sshd_port_and_who_fallback(self):
        """ss недоступен (нет root) → who отдаёт пиры, включая (ip:0)."""
        ips = self._live([
            ("ss -tnp", (1, "", "permission denied")),
            ("who", (0,
                     "root  pts/0  2026-10-20 10:00 (203.0.113.9)\n"
                     "adm  pts/1  2026-10-20 11:00 (1.2.3.4:0)\n"
                     "adm  tty1  2026-10-20 09:00 (:0)\n", "")),
        ])
        self.assertEqual(ips, ["203.0.113.9", "1.2.3.4"])

    def test_v6_and_unspecified_and_loopback_skipped(self):
        ips = self._live([
            ("ss -tnp", (0,
                         "0 0 10.0.0.5:22 [2001:db8::1]:51424"
                         " users:((\"sshd\",pid=998,fd=3))\n"
                         "0 0 10.0.0.5:22 0.0.0.0:0 users:((\"sshd\",pid=998,fd=4))\n"
                         "0 0 10.0.0.5:22 127.0.0.1:51234 users:((\"sshd\",pid=9,fd=5))\n",
                         "")),
            ("who", (0, "", "")),
        ])
        self.assertEqual(ips, [])

    def test_nothing_found(self):
        ips = self._live([("ss -tnp", (0, "", "")), ("who", (0, "", ""))])
        self.assertEqual(ips, [])


# ─────────────────────────────────────────────────────────────────────────────
class TestRefreshSshProtectionSet(_TmpCase):
    """_refresh_ssh_protection_set — объединение наборов + автообновление."""

    def _refresh(self, state_ip, live, save_calls=None):
        def _record_save():
            if save_calls is not None:
                save_calls.append(1)

        with patch.object(self.warp, "_live_ssh_peer_ips", return_value=live), \
             patch.object(self.warp, "_warp_state_save_autonomously",
                          side_effect=_record_save):
            return self.warp._refresh_ssh_protection_set(state_ip)

    def test_stale_state_updated_to_live_and_both_protected(self):
        saves = []
        protect = self._refresh("198.51.100.7", ["203.0.113.77"], saves)
        self.assertEqual(protect, ["198.51.100.7", "203.0.113.77"])
        self.assertEqual(sys.modules["chimera._core"].WARP_SSH_CLIENT_IP,
                         "203.0.113.77")
        self.assertEqual(len(saves), 1)

    def test_state_matches_live_no_resave(self):
        saves = []
        protect = self._refresh("203.0.113.77", ["203.0.113.77"], saves)
        self.assertEqual(protect, ["203.0.113.77"])
        self.assertEqual(saves, [])  # перезаписи state не было

    def test_empty_state_filled_from_live(self):
        protect = self._refresh("", ["203.0.113.77", "198.51.100.9"])
        self.assertEqual(protect, ["203.0.113.77", "198.51.100.9"])
        self.assertEqual(sys.modules["chimera._core"].WARP_SSH_CLIENT_IP,
                         "203.0.113.77")

    def test_garbage_state_replaced_by_live(self):
        protect = self._refresh("ololo", ["203.0.113.77"])
        self.assertEqual(protect, ["203.0.113.77"])
        self.assertEqual(sys.modules["chimera._core"].WARP_SSH_CLIENT_IP,
                         "203.0.113.77")

    def test_valid_state_no_live_kept(self):
        """Валидный state без живых сессий: защищается как есть, state не
        перезаписывается (значение уже лежит в state.json)."""
        sys.modules["chimera._core"].WARP_SSH_CLIENT_IP = "198.51.100.7"
        saves = []
        protect = self._refresh("198.51.100.7", [], saves)
        self.assertEqual(protect, ["198.51.100.7"])
        self.assertEqual(sys.modules["chimera._core"].WARP_SSH_CLIENT_IP,
                         "198.51.100.7")
        self.assertEqual(saves, [])

    def test_cidr_state_normalized(self):
        protect = self._refresh("5.6.7.8/32", [])
        self.assertEqual(protect, ["5.6.7.8"])

    def test_nothing_at_all_returns_empty(self):
        protect = self._refresh("", [])
        self.assertEqual(protect, [])


# ─────────────────────────────────────────────────────────────────────────────
class TestApplyFullMode(_TmpCase):
    """_warp_apply_full_mode — мульти-IP защита, via/on-link, state.json."""

    def setUp(self):
        super().setUp()
        (self.tmp / "wg-warp.conf").write_text(WG_CONF)

    def test_via_default_multi_ip_protection_and_state(self):
        """State-IP (протухший) + живая сессия: маршруты на ОБА, state
        обновлён на живой IP, endpoint и split-default на месте."""
        gw_out = "default via 10.0.0.1 dev ens3 proto static\n"
        gets = {ip: f"{ip} via 10.0.0.1 dev ens3 src 10.0.0.5"
                for ip in ("198.51.100.7", "203.0.113.77", "162.159.192.1")}
        responses = [("route show default", (0, gw_out, ""))]
        responses += [(f"route get {ip}", (0, out, ""))
                      for ip, out in gets.items()]
        runner = FakeRunner(responses)
        with patch.object(self.warp, "_run", runner), \
             patch.object(self.warp, "_live_ssh_peer_ips",
                          return_value=["203.0.113.77"]):
            self.warp._warp_apply_full_mode("198.51.100.7")

        calls = " | ".join(runner.calls)
        self.assertIn("ip route add 198.51.100.7/32 via 10.0.0.1 dev ens3 onlink", calls)
        self.assertIn("ip route add 203.0.113.77/32 via 10.0.0.1 dev ens3 onlink", calls)
        self.assertIn("ip route add 162.159.192.1/32 via 10.0.0.1 dev ens3 onlink", calls)
        self.assertIn("ip route add 0.0.0.0/1 dev wg-warp", calls)
        self.assertIn("ip route add 128.0.0.0/1 dev wg-warp", calls)
        # state обновлён на живой IP и сохранён
        state = json.loads((self.tmp / "state.json").read_text())
        self.assertEqual(state["warp_ssh_ip"], "203.0.113.77")
        self.assertEqual(state["warp_active_routes"], ["0.0.0.0/1", "128.0.0.0/1"])

    def test_onlink_default_dev_only_routes(self):
        """Дефолт без via → защитные маршруты `dev IF` без via/onlink;
        живые сессии собираются по-настоящему (env + ss + who)."""
        ss = ("0 0 10.0.0.5:22 198.51.100.9:40000"
              " users:((\"sshd\",pid=999,fd=4))\n")
        who = "root pts/0 2026-10-20 10:00 (203.0.113.9)\n"
        ips = ["203.0.113.77", "198.51.100.9", "203.0.113.9", "162.159.192.1"]
        responses = [
            ("route show default", (0, "default dev ens9 proto static\n", "")),
            ("ss -tnp", (0, ss, "")),
            ("who", (0, who, "")),
        ]
        responses += [(f"route get {ip}", (0, f"{ip} dev ens9 src 10.0.0.5", ""))
                      for ip in ips]
        runner = FakeRunner(responses)
        env = {"SSH_CONNECTION": "203.0.113.77 55123 10.0.0.5 22"}
        with patch.object(self.warp, "_run", runner), \
                patch.dict(os.environ, env, clear=True):
            self.warp._warp_apply_full_mode("")

        calls = runner.calls
        for ip in ("203.0.113.77", "198.51.100.9", "203.0.113.9"):
            self.assertIn(f"ip route add {ip}/32 dev ens9", calls)
        self.assertIn("ip route add 162.159.192.1/32 dev ens9", calls)
        # ни один route add не содержит via (on-link вариант)
        for c in calls:
            if c.startswith("ip route add") and "dev wg-warp" not in c:
                self.assertNotIn(" via ", c, msg=c)
        # state заполнен env-IP живой сессии (первый приоритет)
        state = json.loads((self.tmp / "state.json").read_text())
        self.assertEqual(state["warp_ssh_ip"], "203.0.113.77")

    def test_no_ssh_ip_no_protection_route_but_split_default_applied(self):
        runner = FakeRunner([
            ("route show default", (0, "default via 10.0.0.1 dev ens3\n", "")),
        ])
        with patch.object(self.warp, "_run", runner), \
             patch.object(self.warp, "_live_ssh_peer_ips", return_value=[]):
            self.warp._warp_apply_full_mode("")
        add_ssh = [c for c in runner.calls
                   if c.startswith("ip route add") and "/32 " in c
                   and "162.159.192.1" not in c]
        self.assertEqual(add_ssh, [])  # SSH /32 не строился
        self.assertIn("ip route add 0.0.0.0/1 dev wg-warp", runner.calls)
        self.assertIn("ip route add 128.0.0.0/1 dev wg-warp", runner.calls)


class TestApplyModeWiring(_TmpCase):
    """_apply_mode(FULL) уходит в commit-confirm обёртку с исходным IP."""

    def test_full_dispatches_to_commit_confirm(self):
        with patch.object(self.warp, "_apply_full_mode_with_commit_confirm") as m:
            self.warp._apply_mode(self.warp.MODE_FULL, "198.51.100.7", [], [])
        m.assert_called_once_with("198.51.100.7")


# ─────────────────────────────────────────────────────────────────────────────
class TestCheckSshProtection(_TmpCase):
    """Диагностика: сверка state ↔ живые сессии + ip route get по каждому."""

    def test_stale_state_warns_and_live_checked(self):
        sys.modules["chimera._core"].WARP_SSH_CLIENT_IP = "198.51.100.7"
        gets = {
            "198.51.100.7": "198.51.100.7 via 10.0.0.1 dev ens3",
            "203.0.113.77": "203.0.113.77 via 10.0.0.1 dev ens3",
        }
        runner = FakeRunner([(f"route get {ip}", (0, out, ""))
                             for ip, out in gets.items()])
        warns, successes = MagicMock(), MagicMock()
        with patch.object(self.warp, "_run", runner), \
             patch.object(self.warp, "_live_ssh_peer_ips",
                          return_value=["203.0.113.77"]), \
             patch.object(self.warp, "warn", warns), \
             patch.object(self.warp, "success", successes):
            self.warp._check_ssh_protection()
        warn_texts = [c.args[0] for c in warns.call_args_list]
        self.assertTrue(any("не совпадает" in t and "198.51.100.7" in t
                            for t in warn_texts), msg=warn_texts)
        ok_texts = [c.args[0] for c in successes.call_args_list]
        self.assertTrue(any("198.51.100.7" in t for t in ok_texts))
        self.assertTrue(any("203.0.113.77" in t for t in ok_texts))

    def test_matching_state_no_stale_warning(self):
        sys.modules["chimera._core"].WARP_SSH_CLIENT_IP = "203.0.113.77"
        runner = FakeRunner([("route get 203.0.113.77",
                              (0, "203.0.113.77 via 10.0.0.1 dev ens3", ""))])
        warns = MagicMock()
        with patch.object(self.warp, "_run", runner), \
             patch.object(self.warp, "_live_ssh_peer_ips",
                          return_value=["203.0.113.77"]), \
             patch.object(self.warp, "warn", warns), \
             patch.object(self.warp, "success", MagicMock()):
            self.warp._check_ssh_protection()
        warn_texts = [c.args[0] for c in warns.call_args_list]
        self.assertFalse(any("не совпадает" in t for t in warn_texts),
                         msg=warn_texts)


class TestMenuChangeSshIp(_TmpCase):
    """Меню смены SSH IP: auto из живой сессии / вручную / очистка / мусор."""

    def _menu(self, inputs, live=(), mode="full", svc_active=False):
        sys.modules["chimera._core"].WARP_SSH_CLIENT_IP = ""
        sys.modules["chimera._core"].WARP_MODE = mode
        with patch.object(self.warp, "os") as wos, \
             patch.object(self.warp, "_live_ssh_peer_ips", return_value=list(live)), \
             patch.object(self.warp, "_warp_service_active", return_value=svc_active), \
             patch.object(self.warp, "_ensure_original_route", return_value=None), \
             patch.object(self.warp, "_warp_state_save_autonomously") as save, \
             patch("builtins.input", side_effect=inputs):
            self.warp._menu_change_ssh_ip()
        return save

    def test_manual_entry_sets_state(self):
        save = self._menu(["2", "9.9.9.9", ""])
        self.assertEqual(sys.modules["chimera._core"].WARP_SSH_CLIENT_IP, "9.9.9.9")
        save.assert_called_once()

    def test_auto_uses_live_session_ip(self):
        save = self._menu(["1", ""], live=["203.0.113.77"])
        self.assertEqual(sys.modules["chimera._core"].WARP_SSH_CLIENT_IP,
                         "203.0.113.77")
        save.assert_called_once()

    def test_invalid_input_changes_nothing(self):
        save = self._menu(["2", "not-an-ip", ""])
        self.assertEqual(sys.modules["chimera._core"].WARP_SSH_CLIENT_IP, "")
        save.assert_not_called()

    def test_clear_option(self):
        sys.modules["chimera._core"].WARP_SSH_CLIENT_IP = "1.2.3.4"
        with patch.object(self.warp, "os"), \
             patch.object(self.warp, "_live_ssh_peer_ips", return_value=[]), \
             patch.object(self.warp, "_warp_state_save_autonomously") as save, \
             patch("builtins.input", side_effect=["3", "y", ""]):
            self.warp._menu_change_ssh_ip()
        self.assertEqual(sys.modules["chimera._core"].WARP_SSH_CLIENT_IP, "")
        save.assert_called_once()

    def test_full_active_applies_route_immediately(self):
        """FULL + активный туннель → защитный маршрут строится сразу."""
        runner = FakeRunner([
            ("route get 9.9.9.9", (0, "9.9.9.9 via 10.0.0.1 dev ens3", "")),
        ])
        sys.modules["chimera._core"].WARP_SSH_CLIENT_IP = ""
        sys.modules["chimera._core"].WARP_MODE = "full"
        with patch.object(self.warp, "os"), \
             patch.object(self.warp, "_live_ssh_peer_ips", return_value=[]), \
             patch.object(self.warp, "_warp_service_active", return_value=True), \
             patch.object(self.warp, "_warp_state_save_autonomously"), \
             patch.object(self.warp, "_ensure_original_route",
                          return_value=("10.0.0.1", "ens3")), \
             patch("builtins.input", side_effect=["2", "9.9.9.9", ""]):
            with patch.object(self.warp, "_run", runner):
                self.warp._menu_change_ssh_ip()
        self.assertIn("ip route add 9.9.9.9/32 via 10.0.0.1 dev ens3 onlink",
                      runner.calls)


class TestMenuContract(unittest.TestCase):
    """Главное меню WARP содержит пункт [10] и обработчик (контракт TUI)."""

    def test_menu_item_and_handler_present(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" / "warp.py").read_text(
            encoding="utf-8")
        self.assertIn("Сменить SSH IP", src)
        self.assertIn('ch == "10" and installed', src)
        self.assertIn("def _menu_change_ssh_ip", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
