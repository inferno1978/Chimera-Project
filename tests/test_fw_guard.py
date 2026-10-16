#!/usr/bin/env python3
"""
tests/test_fw_guard.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/fw_guard.py.

Покрывает:
  1. fw_guard_check — детект пропавших ufw-правил / клиентов / RU-блока
  2. Модель снапшота: learn/forget (деинсталлированные сервисы)
  3. fw_guard_heal — SSH-безопасность ufw enable, восстановление правил
  4. fw_guard_run — лечение, лог, троттлинг уведомлений
  5. fw_guard_install — systemd service/timer + скрипт
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations
import json, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import fw_guard


def _cp(cmd, rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(cmd, rc, stdout, stderr)


_UFW_HEALTHY = """Status: active

To                         Action      From
--                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # chimera-fw-guard-ssh
[ 2] 9443/tcp                   ALLOW IN    Anywhere                   # chimera-vless
[ 3] 10000:20000/tcp            ALLOW IN    Anywhere                   # chimera-port-hopping
[ 4] 3128/tcp                   ALLOW IN    Anywhere                   # chimera-mtproto
[ 5] 9443/tcp (v6)              ALLOW IN    Anywhere (v6)              # chimera-vless
[104] 1.2.3.4                   DENY IN     Anywhere
"""

_UFW_MISSING_3128 = _UFW_HEALTHY.replace(
    "[ 4] 3128/tcp                   ALLOW IN    Anywhere                   # chimera-mtproto\n", ""
)

_REGISTRY = [
    {"service": "vless", "port": 9443, "proto": "tcp"},
    {"service": "mtproto", "port": 3128, "proto": "tcp"},
    {"service": "port_hopping", "port": 10000, "proto": "tcp"},
    {"service": "port_hopping", "port": 10001, "proto": "tcp"},
]

_SNAPSHOT = {
    "ufw_active_seen": True,
    "rules_seen": {
        "22/tcp":          {"proto": "tcp", "port_start": 22, "port_end": 22, "service": "fw-guard-ssh"},
        "9443/tcp":        {"proto": "tcp", "port_start": 9443, "port_end": 9443, "service": "vless"},
        "10000:20000/tcp": {"proto": "tcp", "port_start": 10000, "port_end": 20000, "service": "port_hopping"},
        "3128/tcp":        {"proto": "tcp", "port_start": 3128, "port_end": 3128, "service": "mtproto"},
    },
    "last_signature": "", "last_notify_ts": 0.0, "last_run": "", "heals_total": 0,
}

_RU_FILE_LINES = "\n".join(f"5.6.{i}.0/24" for i in range(120)) + "\n"


class _FakeEnv:
    """Фейковый _run + окружение для fw_guard."""

    def __init__(self, tmp: Path, ufw_status=_UFW_HEALTHY):
        self.tmp = tmp
        self.ufw_status = ufw_status
        self.ipset_entries = {"clients_wl_v4": 15, "xray_ru_block": 3000}
        self.ipt_ok = {("chimera-clients-wl", "ACCEPT"), ("xray-ru-ingress-block", "DROP")}
        self.calls: list[list] = []
        # Файлы окружения
        (tmp / "port_registry.json").write_text(json.dumps(_REGISTRY))
        (tmp / "ingress.json").write_text(json.dumps({"enabled": True, "port": 9443}))
        (tmp / "state.json").write_text(json.dumps({"SERVER_PORT": 9443}))
        (tmp / "clients-wl.cron").touch()
        (tmp / "ru_subnets.txt").write_text(_RU_FILE_LINES)
        (tmp / "fw_state.json").write_text(json.dumps(_SNAPSHOT))

    def run(self, cmd, timeout=30, **kw):
        self.calls.append(list(cmd))
        if cmd[:2] == ["ufw", "status"]:
            return _cp(cmd, 0, self.ufw_status, "")
        if cmd[:2] == ["ufw", "allow"]:
            return _cp(cmd, 0, "Rule added", "")
        if cmd[:2] == ["ufw", "--force"]:
            return _cp(cmd, 0, "Firewall is active", "")
        if cmd[0] == "ipset" and cmd[1] == "list":
            name = cmd[2]
            if name not in self.ipset_entries:
                return _cp(cmd, 1, "", "set does not exist")
            return _cp(cmd, 0, f"Name: {name}\nNumber of entries: {self.ipset_entries[name]}\n", "")
        if cmd[0] in ("iptables", "ip6tables") and "-C" in cmd:
            comment = cmd[cmd.index("--comment") + 1]
            jump = cmd[cmd.index("-j") + 1]
            ok = (comment, jump) in self.ipt_ok
            return _cp(cmd, 0 if ok else 1, "", "")
        if cmd[0] == "hostname":
            return _cp(cmd, 0, "testhost\n", "")
        return _cp(cmd, 0, "", "")


class _FwGuardBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.env = _FakeEnv(self.tmp)
        self._patches = [
            patch.object(fw_guard, "STATE_FILE", self.tmp / "fw_state.json"),
            patch.object(fw_guard, "LOG_FILE", self.tmp / "fw-guard.log"),
            patch.object(fw_guard, "SCRIPT_FILE", self.tmp / "fw-guard.sh"),
            patch.object(fw_guard, "SERVICE_FILE", self.tmp / "fw-guard.service"),
            patch.object(fw_guard, "TIMER_FILE", self.tmp / "fw-guard.timer"),
            patch.object(fw_guard, "PORT_REGISTRY", self.tmp / "port_registry.json"),
            patch.object(fw_guard, "INGRESS_STATE", self.tmp / "ingress.json"),
            patch.object(fw_guard, "INSTALLED_STATE", self.tmp / "state.json"),
            patch.object(fw_guard, "CLIENTS_WL_CRON", self.tmp / "clients-wl.cron"),
            patch.object(fw_guard, "RU_SUBNETS_FILE", self.tmp / "ru_subnets.txt"),
            patch.object(fw_guard, "_run", self.env.run),
            patch.object(fw_guard.shutil, "which",
                         lambda n: f"/usr/sbin/{n}" if n in ("ufw", "iptables", "ip6tables", "ipset") else None),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestFwGuardCheck(_FwGuardBase):
    def test_healthy_no_problems(self):
        rep = fw_guard.fw_guard_check()
        self.assertEqual(rep["problems"], [])
        self.assertTrue(rep["ufw_active"])
        # v6-дубликат схлопывается: 4 правила (22, 9443, PH-диапазон, 3128)
        self.assertEqual(len(rep["our_rules"]), 4)
        self.assertTrue(rep["clients_wl"]["rule_ok"])
        self.assertTrue(rep["ru_block"]["rule_ok"])
        self.assertEqual(rep["ru_block"]["entries"], 3000)

    def test_missing_port_rule_detected(self):
        self.env.ufw_status = _UFW_MISSING_3128
        rep = fw_guard.fw_guard_check()
        specs = [m["spec"] for m in rep["missing_rules"]]
        self.assertIn("3128/tcp", specs)
        self.assertTrue(any("3128/tcp" in p for p in rep["problems"]))

    def test_forgotten_when_service_uninstalled(self):
        # mtproto исчез из реестра → правило не «пропавшее», а забытое
        self.env.ufw_status = _UFW_MISSING_3128
        (self.tmp / "port_registry.json").write_text(json.dumps(
            [e for e in _REGISTRY if e["service"] != "mtproto"]))
        rep = fw_guard.fw_guard_check()
        specs = [m["spec"] for m in rep["missing_rules"]]
        self.assertNotIn("3128/tcp", specs)
        self.assertFalse(any("3128" in p for p in rep["problems"]))

    def test_clients_wl_rule_missing(self):
        self.env.ipt_ok.discard(("chimera-clients-wl", "ACCEPT"))
        rep = fw_guard.fw_guard_check()
        self.assertIn("нет ACCEPT-правила", rep["clients_wl"]["problem"])
        self.assertTrue(any("clients_wl" in p for p in rep["problems"]))

    def test_clients_wl_ipset_missing(self):
        self.env.ipset_entries.pop("clients_wl_v4")
        rep = fw_guard.fw_guard_check()
        self.assertIn("ipset clients_wl_v4 отсутствует", rep["clients_wl"]["problem"])

    def test_ru_block_ipset_empty(self):
        self.env.ipset_entries["xray_ru_block"] = 0
        rep = fw_guard.fw_guard_check()
        self.assertIn("пуст/отсутствует", rep["ru_block"]["problem"])

    def test_ru_block_drop_rule_missing(self):
        self.env.ipt_ok.discard(("xray-ru-ingress-block", "DROP"))
        rep = fw_guard.fw_guard_check()
        self.assertIn("нет DROP-правила", rep["ru_block"]["problem"])

    def test_ufw_inactive_reported_when_seen(self):
        self.env.ufw_status = "Status: inactive\n"
        rep = fw_guard.fw_guard_check()
        self.assertFalse(rep["ufw_active"])
        self.assertTrue(any("ufw не активен" in p for p in rep["problems"]))

    def test_ufw_inactive_silent_when_never_seen(self):
        # Снапшот без ufw_active_seen → не наша забота (никогда не включали)
        st = fw_guard._state_load()
        st["ufw_active_seen"] = False
        fw_guard._state_save(st)
        self.env.ufw_status = "Status: inactive\n"
        rep = fw_guard.fw_guard_check()
        self.assertFalse(any("ufw не активен" in p for p in rep["problems"]))


class TestFwGuardHeal(_FwGuardBase):
    def test_heal_ufw_enable_with_ssh_safety(self):
        # ufw выключен, но был активен → СНАЧАЛА allow SSH, ПОТОМ enable
        self.env.ufw_status = "Status: inactive\n"
        fw_guard.fw_guard_heal(fw_guard.fw_guard_check())
        allow_idx = next(i for i, c in enumerate(self.env.calls) if c[:2] == ["ufw", "allow"])
        enable_idx = next(i for i, c in enumerate(self.env.calls) if c[:2] == ["ufw", "--force"])
        self.assertLess(allow_idx, enable_idx, "SSH-порт обязан открываться ДО ufw enable")
        self.assertIn("22/tcp", self.env.calls[allow_idx])

    def test_heal_never_enables_ufw_without_seen(self):
        self.env.ufw_status = "Status: inactive\n"
        st = fw_guard._state_load()
        st["ufw_active_seen"] = False
        fw_guard._state_save(st)
        fw_guard.fw_guard_heal(fw_guard.fw_guard_check())
        self.assertFalse(any(c[:2] == ["ufw", "--force"] for c in self.env.calls))

    def test_heal_restores_snapshot_rules(self):
        self.env.ufw_status = _UFW_MISSING_3128
        with patch.object(fw_guard, "_registry_open", return_value=(True, "ok")) as m:
            actions = fw_guard.fw_guard_heal(fw_guard.fw_guard_check())
        m.assert_called_once()
        self.assertEqual(m.call_args[0][0]["spec"], "3128/tcp")
        self.assertTrue(any("3128" in a for a in actions))

    def test_heal_clients_wl_called(self):
        self.env.ipt_ok.discard(("chimera-clients-wl", "ACCEPT"))
        with patch.object(fw_guard, "_heal_clients_wl", return_value=(True, "ok")) as m:
            actions = fw_guard.fw_guard_heal(fw_guard.fw_guard_check())
        m.assert_called_once_with(9443)
        self.assertTrue(any("clients_wl" in a for a in actions))

    def test_heal_ru_block_skipped_without_file(self):
        self.env.ipt_ok.discard(("xray-ru-ingress-block", "DROP"))
        (self.tmp / "ru_subnets.txt").unlink()
        with patch.object(fw_guard, "_heal_ru_block", return_value=(True, "ok")) as m:
            actions = fw_guard.fw_guard_heal(fw_guard.fw_guard_check())
        m.assert_not_called()
        self.assertTrue(any("невозможно" in a for a in actions))

    def test_heal_full_opens_registry_service(self):
        # full-режим: сервис в реестре, правил нет совсем → открыть по реестру
        self.env.ufw_status = "Status: active\n\nTo  Action  From\n"
        empty_snap = dict(_SNAPSHOT)
        empty_snap["rules_seen"] = {}
        (self.tmp / "fw_state.json").write_text(json.dumps(empty_snap))
        with patch.object(fw_guard, "_registry_open", return_value=(True, "ok")) as m:
            fw_guard.fw_guard_heal(fw_guard.fw_guard_check(), full=True)
        opened = {call[0][0].get("service") for call in m.call_args_list}
        self.assertIn("vless", opened)
        self.assertIn("mtproto", opened)
        # маленькие сервисы — поштучно (port_hopping: 2 порта в реестре)
        ph_calls = [c for c in m.call_args_list
                    if c[0][0].get("service") == "port_hopping"]
        self.assertEqual(len(ph_calls), 2)
        self.assertEqual(ph_calls[0][0][0]["port_start"], 10000)
        self.assertEqual(ph_calls[0][0][0]["port_end"], 10000)

    def test_heal_full_big_service_opens_range(self):
        # full-режим: сервис с >50 портами (port-hopping-подобный) —
        # ОДНО правило min-max, а не 60 поштучных
        self.env.ufw_status = "Status: active\n\nTo  Action  From\n"
        big = [{"service": "ph2", "port": p, "proto": "tcp"} for p in range(20000, 20060)]
        (self.tmp / "port_registry.json").write_text(json.dumps(
            _REGISTRY + big))
        empty_snap = dict(_SNAPSHOT)
        empty_snap["rules_seen"] = {}
        (self.tmp / "fw_state.json").write_text(json.dumps(empty_snap))
        with patch.object(fw_guard, "_registry_open", return_value=(True, "ok")) as m:
            fw_guard.fw_guard_heal(fw_guard.fw_guard_check(), full=True)
        ph2_calls = [c for c in m.call_args_list
                     if c[0][0].get("service") == "ph2"]
        self.assertEqual(len(ph2_calls), 1)
        self.assertEqual(ph2_calls[0][0][0]["port_start"], 20000)
        self.assertEqual(ph2_calls[0][0][0]["port_end"], 20059)


class TestFwGuardRun(_FwGuardBase):
    def test_run_heals_and_logs(self):
        self.env.ufw_status = _UFW_MISSING_3128
        with patch.object(fw_guard, "_registry_open", return_value=(True, "ok")), \
             patch.object(fw_guard, "_notify_tg") as notify:
            res = fw_guard.fw_guard_run()
        self.assertTrue(res["actions"])
        notify.assert_called_once()  # лечение было → уведомление
        # после лечения learn зафиксировал текущие правила в снапшоте
        st = fw_guard._state_load()
        self.assertIn("9443/tcp", st["rules_seen"])
        # лог содержит строку о проблеме и лечении
        log = (self.tmp / "fw-guard.log").read_text()
        self.assertIn("PROBLEMS", log)
        self.assertIn("HEAL", log)

    def test_run_healthy_no_notify(self):
        with patch.object(fw_guard, "_notify_tg") as notify:
            res = fw_guard.fw_guard_run()
        self.assertEqual(res["actions"], [])
        notify.assert_not_called()
        log = (self.tmp / "fw-guard.log").read_text()
        self.assertIn("OK: 0 проблем", log)

    def test_notify_throttled_when_signature_stable(self):
        # Проблема есть, лечение невозможно, подпись не менялась, алерт недавно
        self.env.ipt_ok.discard(("chimera-clients-wl", "ACCEPT"))
        with patch.object(fw_guard, "_heal_clients_wl", return_value=(False, "fail")), \
             patch.object(fw_guard, "_notify_tg") as notify:
            fw_guard.fw_guard_run()
            notify.reset_mock()
            fw_guard.fw_guard_run()  # та же подпись, < 6ч — молчим
        notify.assert_not_called()

    def test_learn_forgets_uninstalled_service(self):
        self.env.ufw_status = _UFW_MISSING_3128
        (self.tmp / "port_registry.json").write_text(json.dumps(
            [e for e in _REGISTRY if e["service"] != "mtproto"]))
        fw_guard.fw_guard_run(notify=False)
        st = fw_guard._state_load()
        self.assertNotIn("3128/tcp", st["rules_seen"])
        self.assertIn("9443/tcp", st["rules_seen"])


class TestFwGuardInstall(_FwGuardBase):
    def test_install_writes_units_and_enables(self):
        with patch.object(fw_guard, "_installer_path", return_value="/opt/chimera"), \
             patch.object(fw_guard, "fw_guard_run") as first_run:
            ok, msg = fw_guard.fw_guard_install()
        self.assertTrue(ok, msg)
        script = (self.tmp / "fw-guard.sh").read_text()
        self.assertIn("fw_guard_run()", script)
        self.assertIn('/opt/chimera', script)
        service = (self.tmp / "fw-guard.service").read_text()
        self.assertIn("ExecStart=", service)
        timer = (self.tmp / "fw-guard.timer").read_text()
        self.assertIn("OnUnitActiveSec=120s", timer)
        self.assertIn("WantedBy=timers.target", timer)
        # systemd enable --now вызван
        self.assertTrue(any(c[:3] == ["systemctl", "enable", "--now"]
                            for c in self.env.calls))
        # первый прогон (обучение снапшота) выполнен
        first_run.assert_called_once()

    def test_remove_deletes_units(self):
        (self.tmp / "fw-guard.sh").write_text("#!/bin/bash\n")
        (self.tmp / "fw-guard.service").write_text("[Unit]\n")
        (self.tmp / "fw-guard.timer").write_text("[Unit]\n")
        ok, msg = fw_guard.fw_guard_remove()
        self.assertTrue(ok, msg)
        self.assertFalse((self.tmp / "fw-guard.sh").exists())
        self.assertFalse((self.tmp / "fw-guard.service").exists())
        self.assertFalse((self.tmp / "fw-guard.timer").exists())

    def test_script_template_valid_python(self):
        with patch.object(fw_guard, "_installer_path", return_value="/opt/chimera"):
            script = fw_guard._build_script()
        self.assertIn("#!/bin/bash", script)
        self.assertIn("fw_guard_run()", script)


class TestFwGuardMenuWiring(unittest.TestCase):
    """Меню и точки интеграции существуют (source-маркеры)."""

    def test_menu_function_exists(self):
        self.assertTrue(callable(getattr(fw_guard, "do_manage_fw_guard", None)))

    def test_core_menu_wired(self):
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        self.assertIn("do_manage_fw_guard()", src,
                      "меню Безопасность не вызывает FW Guard")
        self.assertIn('from chimera.modules.fw_guard', src,
                      "_core.py не импортирует fw_guard")


if __name__ == "__main__":
    unittest.main(verbosity=2)
