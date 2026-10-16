#!/usr/bin/env python3
"""
tests/test_users_watchdog.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/users_watchdog.py.

Покрывает:
  A. UUID-санитария и sanity клиентов (артефакт u1/a@x из инцидента 16.10).
  B. Конфиг: дефолты, слияние, валидация/клампы, roundtrip.
  C. Классификация инбаундов (main vs other) и expected-клиенты
     (flow: reality → vision, xhttp → без flow, перенос доп-полей).
  D. Diff: пропавшие / неизвестные / email-расхождение / битые UUID /
     пустой список; флаг remove_unknown.
  E. Цикл целиком (tmp-окружение): happy path + снапшот-обучение;
     реплей инцидента (подтверждение циклами → восстановление);
     insane → мгновенно; notify/none; maintenance; cooldown; бюджет;
     пустой users.json не вытирает конфиг; снапшот-источник для other;
     last-resort .bak.
  F. Механика восстановления: бэкап, откат при провале xray -test,
     откат при незапуске xray, прунинг бэкапов.
  G. Systemd-юниты: wrapper-скрипт (лёгкий запуск без _core), сервис,
     таймер с интервалом, install/remove, reapply.
  H. Проводка: main.py CLI, пункт меню UW в _core.py, stdlib-only импорт.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import users_watchdog as uw

UUID1 = "cd166266-f329-430e-9714-7c69b35de8d9"
UUID2 = "1fa9bc73-030c-440a-9d6b-014ba0861f07"
UUID3 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

USERS = [
    {"uuid": UUID1, "email": "user@chimeraprodcdn.online", "name": "user"},
    {"uuid": UUID2, "email": "second@example.com", "name": "second"},
]

GOOD_CLIENTS = [
    {"id": UUID1, "email": "user@chimeraprodcdn.online", "flow": "xtls-rprx-vision"},
    {"id": UUID2, "email": "second@example.com", "flow": "xtls-rprx-vision"},
]


def _cfg_inbound(tag="inbound-vless", port=443, clients=None, protocol="vless",
                 network="tcp", reality=True):
    st = {"network": network}
    if reality:
        st["realitySettings"] = {"dest": "x"}
    return {
        "tag": tag, "port": port, "protocol": protocol,
        "settings": {"clients": clients if clients is not None else GOOD_CLIENTS},
        "streamSettings": st,
    }


def _cfg_json(*inbounds, extra=None):
    cfg = {"inbounds": list(inbounds)}
    if extra:
        cfg.update(extra)
    return cfg


# ─────────────────────────────────────────────────────────────────────────────
#  A. UUID-санитария
# ─────────────────────────────────────────────────────────────────────────────
class TestSanity(unittest.TestCase):
    def test_uuid_valid(self):
        self.assertTrue(uw._uuid_valid(UUID1))
        self.assertTrue(uw._uuid_valid(UUID1.upper()))

    def test_uuid_invalid_artifacts(self):
        self.assertFalse(uw._uuid_valid("u1"))            # инцидент 16.10
        self.assertFalse(uw._uuid_valid("a@x"))
        self.assertFalse(uw._uuid_valid(""))
        self.assertFalse(uw._uuid_valid(None))
        self.assertFalse(uw._uuid_valid("cd166266f329430e97147c69b35de8d9"))  # без дефисов
        self.assertFalse(uw._uuid_valid("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"))

    def test_clients_sane(self):
        self.assertTrue(uw._clients_sane(GOOD_CLIENTS))
        self.assertFalse(uw._clients_sane([]))
        self.assertFalse(uw._clients_sane([{"id": "u1", "email": "a@x"}]))
        self.assertFalse(uw._clients_sane([{"email": "no-id"}]))
        self.assertFalse(uw._clients_sane(None))


# ─────────────────────────────────────────────────────────────────────────────
#  B. Конфиг
# ─────────────────────────────────────────────────────────────────────────────
class TestConfig(unittest.TestCase):
    def test_defaults_when_missing(self):
        with patch.object(uw, "_WD_CONFIG", Path("/nonexistent/x.json")):
            cfg = uw._load_wd_config()
        self.assertEqual(cfg, uw.DEFAULTS)

    def test_merge_partial(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "users-watchdog.json"
            p.write_text(json.dumps({"interval_minutes": 5}))
            with patch.object(uw, "_WD_CONFIG", p):
                cfg = uw._load_wd_config()
        self.assertEqual(cfg["interval_minutes"], 5)
        self.assertEqual(cfg["action_on_mismatch"], "restore")  # дефолт

    def test_validate_clamps(self):
        self.assertEqual(uw._validate_cfg(
            {"interval_minutes": 0})["interval_minutes"], 1)
        self.assertEqual(uw._validate_cfg(
            {"action_on_mismatch": "rm -rf"})["action_on_mismatch"], "restore")
        self.assertEqual(uw._validate_cfg(
            {"require_confirm_cycles": 99})["require_confirm_cycles"], 5)
        self.assertEqual(uw._validate_cfg(
            {"require_confirm_cycles": 0})["require_confirm_cycles"], 1)
        self.assertEqual(uw._validate_cfg(
            {"backup_keep": 1})["backup_keep"], 3)
        self.assertEqual(uw._validate_cfg(
            {"notify": "sms"})["notify"], "tg")

    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "users-watchdog.json"
            with patch.object(uw, "_WD_CONFIG", p):
                cfg = dict(uw.DEFAULTS)
                cfg["interval_minutes"] = 10
                uw._save_wd_config(cfg)
                self.assertEqual(uw._load_wd_config()["interval_minutes"], 10)


# ─────────────────────────────────────────────────────────────────────────────
#  C. Классификация и expected
# ─────────────────────────────────────────────────────────────────────────────
class TestClassification(unittest.TestCase):
    def test_main_detected(self):
        cfg = _cfg_json(_cfg_inbound())
        got = uw._classify_inbounds(cfg, USERS, 443)
        self.assertEqual([k for _, k in got], ["main"])

    def test_other_when_no_users(self):
        cfg = _cfg_json(_cfg_inbound())
        got = uw._classify_inbounds(cfg, [], 443)
        self.assertEqual([k for _, k in got], ["other"])

    def test_other_when_port_mismatch(self):
        cfg = _cfg_json(_cfg_inbound(port=8443))
        got = uw._classify_inbounds(cfg, USERS, 443)
        self.assertEqual([k for _, k in got], ["other"])

    def test_chain_inbound_is_other(self):
        # exit-нода: entry@chain, users.json пустой
        cfg = _cfg_json(_cfg_inbound(
            clients=[{"id": UUID3, "email": "entry@chain"}]))
        got = uw._classify_inbounds(cfg, [], 443)
        self.assertEqual([k for _, k in got], ["other"])

    def test_no_clients_skipped(self):
        inb = {"tag": "api", "protocol": "dokodemo-door", "settings": {}}
        self.assertEqual(uw._classify_inbounds({"inbounds": [inb]}, USERS, 443), [])

    def test_expected_from_users_flow_reality(self):
        inb = _cfg_inbound(clients=[{"id": UUID1, "email": "x@y",
                                     "flow": "xtls-rprx-vision"}])
        exp = uw._expected_from_users(USERS, inb, inb["settings"]["clients"])
        self.assertEqual([c["id"] for c in exp], [UUID1, UUID2])
        self.assertEqual(exp[0]["email"], "user@chimeraprodcdn.online")
        self.assertTrue(all(c.get("flow") == "xtls-rprx-vision" for c in exp))

    def test_expected_from_users_xhttp_no_flow(self):
        inb = _cfg_inbound(network="xhttp", clients=[])
        exp = uw._expected_from_users(USERS, inb, [])
        self.assertTrue(all("flow" not in c for c in exp))

    def test_expected_dedup_and_disabled(self):
        users = USERS + [{"uuid": UUID1, "email": "dup@x"},
                         {"uuid": UUID3, "email": "off@x", "disabled": True}]
        inb = _cfg_inbound()
        exp = uw._expected_from_users(users, inb, [])
        self.assertEqual(len(exp), 2)
        self.assertNotIn(UUID3, [c["id"] for c in exp])

    def test_expected_preserves_extra_fields(self):
        cur = [{"id": UUID1, "email": "old@x", "flow": "xtls-rprx-vision",
                "level": 8}]
        inb = _cfg_inbound(clients=cur)
        exp = uw._expected_from_users(USERS, inb, cur)
        by_id = {c["id"]: c for c in exp}
        self.assertEqual(by_id[UUID1].get("level"), 8)
        self.assertEqual(by_id[UUID1]["email"], "user@chimeraprodcdn.online")

    def test_flow_computed_when_no_live_client(self):
        inb = _cfg_inbound(clients=[])
        self.assertEqual(uw._flow_for_inbound(inb, []), "xtls-rprx-vision")
        inb2 = _cfg_inbound(network="xhttp", clients=[])
        self.assertEqual(uw._flow_for_inbound(inb2, []), "")


# ─────────────────────────────────────────────────────────────────────────────
#  D. Diff
# ─────────────────────────────────────────────────────────────────────────────
class TestDiff(unittest.TestCase):
    def test_no_diff(self):
        d = uw._diff_clients(GOOD_CLIENTS, GOOD_CLIENTS, True)
        self.assertFalse(d["needs_restore"])

    def test_incident_artifact(self):
        # Реплей RU-3 16.10: конфиг с [u1/a@x] вместо пользователей
        d = uw._diff_clients([{"id": "u1", "email": "a@x"}], GOOD_CLIENTS, True)
        self.assertTrue(d["needs_restore"])
        self.assertIn("u1", d["insane"])
        self.assertEqual(len(d["missing"]), 2)

    def test_missing_user(self):
        cur = [GOOD_CLIENTS[0]]
        d = uw._diff_clients(cur, GOOD_CLIENTS, True)
        self.assertTrue(d["needs_restore"])
        self.assertEqual(d["missing"], [UUID2])
        self.assertEqual(d["insane"], [])

    def test_unknown_kept_when_flag_off(self):
        cur = GOOD_CLIENTS + [{"id": UUID3, "email": "stray@x"}]
        d = uw._diff_clients(cur, GOOD_CLIENTS, False)
        self.assertFalse(d["needs_restore"])
        d2 = uw._diff_clients(cur, GOOD_CLIENTS, True)
        self.assertTrue(d2["needs_restore"])
        self.assertEqual(d2["unknown"], [UUID3])

    def test_email_mismatch(self):
        cur = [dict(GOOD_CLIENTS[0], email="wrong@x"), GOOD_CLIENTS[1]]
        d = uw._diff_clients(cur, GOOD_CLIENTS, True)
        self.assertTrue(d["needs_restore"])
        self.assertEqual(d["mismatch"], [UUID1])

    def test_empty_current(self):
        d = uw._diff_clients([], GOOD_CLIENTS, True)
        self.assertTrue(d["needs_restore"])
        self.assertTrue(d["empty"])

    def test_empty_expected_not_needed(self):
        # remove_unknown=False: неизвестные не вычищаются, дрейфа нет;
        # а «вытирание пустым эталоном» вообще не доходит до diff — min-clients
        # guard в цикле (см. test_empty_users_json_never_wipes)
        d = uw._diff_clients(GOOD_CLIENTS, [], False)
        self.assertFalse(d["needs_restore"])
        d2 = uw._diff_clients(GOOD_CLIENTS, [], True)
        self.assertTrue(d2["needs_restore"])
        self.assertEqual(set(d2["unknown"]), {UUID1, UUID2})


# ─────────────────────────────────────────────────────────────────────────────
#  E. Цикл целиком (tmp-окружение)
# ─────────────────────────────────────────────────────────────────────────────
class _Env:
    """tmp-окружение: /etc/xray/config.json + users.json + state + конфиги WDG."""

    def __init__(self, cfg_json=None, users=None, wd_cfg=None, wd_state=None):
        self.d = Path(tempfile.mkdtemp())
        self.cfg_dir = self.d / "etc" / "xray"
        self.cfg_dir.mkdir(parents=True)
        self.state_dir = self.d / "var" / "lib" / "xray-installer"
        self.state_dir.mkdir(parents=True)
        self.log = self.d / "users-watchdog.log"
        self.lock = self.d / "users-watchdog.lock"
        self.maint = self.state_dir / "users-watchdog.maintenance"

        self.cfg_path = self.cfg_dir / "config.json"
        self.cfg_path.write_text(json.dumps(
            cfg_json if cfg_json is not None else _cfg_json(_cfg_inbound())))
        (self.state_dir / "users.json").write_text(
            json.dumps(users if users is not None else USERS))
        (self.state_dir / "state.json").write_text(
            json.dumps({"server_port": 443}))
        (self.state_dir / "users-watchdog.json").write_text(
            json.dumps(wd_cfg if wd_cfg is not None else uw.DEFAULTS))
        if wd_state is not None:
            (self.state_dir / "users-watchdog-state.json").write_text(
                json.dumps(wd_state))

        self._patches = [
            patch.object(uw, "_CFG_DIR", self.cfg_dir),
            patch.object(uw, "_CFG_ALT_DIR", self.d / "nowhere"),
            patch.object(uw, "_STATE_DIR", self.state_dir),
            patch.object(uw, "_USERS_FILE", self.state_dir / "users.json"),
            patch.object(uw, "_XRAY_STATE", self.state_dir / "state.json"),
            patch.object(uw, "_WD_CONFIG", self.state_dir / "users-watchdog.json"),
            patch.object(uw, "_WD_STATE", self.state_dir / "users-watchdog-state.json"),
            patch.object(uw, "_MAINT_FLAG", self.maint),
            patch.object(uw, "_LOCK_FILE", self.lock),
            patch.object(uw, "_LOG", self.log),
            patch.object(uw, "_RESTART_WAIT_SEC", 0),
            patch.object(uw, "_xray_bin", lambda: "/usr/bin/true"),
        ]
        for p in self._patches:
            p.start()

        # systemctl-заглушка: xray всегда active
        self.systemctl_calls = []
        self.sh_orig = uw._sh
        uw._sh = self._fake_sh

    def _fake_sh(self, cmd, timeout=30):
        self.systemctl_calls.append(cmd)
        if cmd[:1] == ["systemctl"] and len(cmd) >= 3 and cmd[1] == "is-active":
            return subprocess.CompletedProcess(cmd, 0, stdout="active", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    def xray_test_result(self, rc):
        """Подменяет _sh так, что xray run -test возвращает rc."""
        def fake(cmd, timeout=30):
            if any("test" in str(x) for x in cmd):
                return subprocess.CompletedProcess(cmd, rc, stdout="", stderr="boom"
                                                   if rc else "")
            return self._fake_sh(cmd, timeout)
        uw._sh = fake

    def read_cfg(self):
        return json.loads(self.cfg_path.read_text())

    def read_state(self):
        return json.loads(
            (self.state_dir / "users-watchdog-state.json").read_text())

    def write_state(self, st):
        (self.state_dir / "users-watchdog-state.json").write_text(json.dumps(st))

    def cycle(self, force=True):
        return uw._cycle(force=force)

    def close(self):
        uw._sh = self.sh_orig
        for p in self._patches:
            p.stop()
        import shutil
        shutil.rmtree(self.d, ignore_errors=True)


class TestCycle(unittest.TestCase):
    def setUp(self):
        self.env = _Env()

    def tearDown(self):
        self.env.close()

    def test_happy_path_snapshot_learned(self):
        rc = self.env.cycle()
        self.assertEqual(rc, 0)
        st = self.env.read_state()
        self.assertEqual(st["last_status"], "ok")
        snap = st["snapshots"]["inbound-vless"]
        self.assertEqual([c["id"] for c in snap], [UUID1, UUID2])
        # рестарта не было
        self.assertFalse(any("restart" in " ".join(map(str, c))
                              for c in self.env.systemctl_calls))

    def test_incident_replay_confirm_then_restore(self):
        # Порча: артефакт u1/a@x (точно как на RU-3 16.10)
        cfg = self.env.read_cfg()
        cfg["inbounds"][0]["settings"]["clients"] = [{"id": "u1", "email": "a@x"}]
        self.env.cfg_path.write_text(json.dumps(cfg))

        # insane-клиенты → восстановление МГНОВЕННО, без циклов подтверждения
        rc = self.env.cycle()
        self.assertEqual(rc, 1)
        self.assertEqual(self.env.read_cfg()["inbounds"][0]["settings"]["clients"],
                         uw._expected_from_users(
                             USERS, cfg["inbounds"][0],
                             [{"id": "u1", "email": "a@x"}]))
        # рестарт был; бэкап создан
        self.assertTrue(any("restart" in " ".join(map(str, c))
                            for c in self.env.systemctl_calls))
        baks = list(self.env.cfg_dir.glob("config.json.bak-users-watchdog-*"))
        self.assertEqual(len(baks), 1)
        st = self.env.read_state()
        self.assertEqual(st["last_status"], "restored")

    def test_soft_drift_needs_confirm_cycles(self):
        # Пропал второй юзер (валидные UUID, но неполный список)
        cfg = self.env.read_cfg()
        cfg["inbounds"][0]["settings"]["clients"] = [GOOD_CLIENTS[0]]
        self.env.cfg_path.write_text(json.dumps(cfg))

        rc1 = self.env.cycle()  # цикл 1: подтверждение
        self.assertEqual(rc1, 0)
        st = self.env.read_state()
        self.assertEqual(st["pending"]["inbound-vless"]["count"], 1)
        # файл НЕ тронут
        self.assertEqual(len(self.env.read_cfg()["inbounds"][0]
                             ["settings"]["clients"]), 1)

        rc2 = self.env.cycle()  # цикл 2: подтверждён → restore
        self.assertEqual(rc2, 1)
        self.assertEqual(len(self.env.read_cfg()["inbounds"][0]
                             ["settings"]["clients"]), 2)

    def test_fingerprint_change_resets_counter(self):
        cfg = self.env.read_cfg()
        cfg["inbounds"][0]["settings"]["clients"] = [GOOD_CLIENTS[0]]
        self.env.cfg_path.write_text(json.dumps(cfg))
        self.env.cycle()  # count=1
        # дрейф изменился (теперь другой набор)
        cfg["inbounds"][0]["settings"]["clients"] = [GOOD_CLIENTS[1]]
        self.env.cfg_path.write_text(json.dumps(cfg))
        rc = self.env.cycle()
        self.assertEqual(rc, 0)
        st = self.env.read_state()
        self.assertEqual(st["pending"]["inbound-vless"]["count"], 1)

    def test_action_notify_no_write(self):
        cfg = self.env.read_cfg()
        cfg["inbounds"][0]["settings"]["clients"] = [{"id": "u1", "email": "a@x"}]
        self.env.cfg_path.write_text(json.dumps(cfg))
        wd = json.loads((self.env.state_dir / "users-watchdog.json").read_text())
        wd["action_on_mismatch"] = "notify"
        (self.env.state_dir / "users-watchdog.json").write_text(json.dumps(wd))

        rc = self.env.cycle()
        self.assertEqual(rc, 0)
        # конфиг НЕ восстановлен
        self.assertEqual(self.env.read_cfg()["inbounds"][0]["settings"]["clients"],
                         [{"id": "u1", "email": "a@x"}])
        self.assertEqual(self.env.read_state()["last_status"], "notify_only")

    def test_maintenance_skips(self):
        self.env.maint.write_text("on\n")
        cfg = self.env.read_cfg()
        cfg["inbounds"][0]["settings"]["clients"] = [{"id": "u1", "email": "a@x"}]
        self.env.cfg_path.write_text(json.dumps(cfg))

        rc = self.env.cycle()
        self.assertEqual(rc, 0)
        self.assertEqual(self.env.read_cfg()["inbounds"][0]["settings"]["clients"],
                         [{"id": "u1", "email": "a@x"}])
        st = self.env.read_state()
        self.assertEqual(st["last_status"], "skipped_maintenance")

    def test_cooldown_defers_second_restore(self):
        cfg = self.env.read_cfg()
        cfg["inbounds"][0]["settings"]["clients"] = [{"id": "u1", "email": "a@x"}]
        self.env.cfg_path.write_text(json.dumps(cfg))
        self.assertEqual(self.env.cycle(), 1)  # восстановили

        # снова испортили сразу
        cfg = self.env.read_cfg()
        cfg["inbounds"][0]["settings"]["clients"] = [{"id": "u2", "email": "b@y"}]
        self.env.cfg_path.write_text(json.dumps(cfg))
        rc = self.env.cycle()
        self.assertEqual(rc, 0)  # cooldown 5 мин → отложено
        self.assertEqual(self.env.read_state()["last_status"], "cooldown")
        self.assertEqual(self.env.read_cfg()["inbounds"][0]["settings"]["clients"],
                         [{"id": "u2", "email": "b@y"}])

    def test_budget_exhausted(self):
        # 6 событий за последний час
        from datetime import datetime, timedelta
        now = datetime.now()
        events = [(now - timedelta(minutes=i)).strftime("%Y-%m-%d %H:%M:%S")
                  for i in range(6)]
        st = {"snapshots": {}, "pending": {}, "restore_events": events}
        self.env.write_state(st)

        cfg = self.env.read_cfg()
        cfg["inbounds"][0]["settings"]["clients"] = [{"id": "u1", "email": "a@x"}]
        self.env.cfg_path.write_text(json.dumps(cfg))

        rc = self.env.cycle()
        self.assertEqual(rc, 0)
        st2 = self.env.read_state()
        self.assertEqual(st2["last_status"], "budget_exhausted")
        self.assertTrue(st2.get("budget_alerted"))
        # конфиг не тронут
        self.assertEqual(self.env.read_cfg()["inbounds"][0]["settings"]["clients"],
                         [{"id": "u1", "email": "a@x"}])

    def test_empty_users_json_never_wipes(self):
        (self.env.state_dir / "users.json").write_text("[]")
        rc = self.env.cycle()
        self.assertEqual(rc, 0)
        # конфиг с живыми клиентами не тронут (классифицирован как other,
        # здрав → снапшот выучен, ничего не стёрто)
        self.assertEqual(len(self.env.read_cfg()["inbounds"][0]
                             ["settings"]["clients"]), 2)
        snap = self.env.read_state()["snapshots"]["inbound-vless"]
        self.assertEqual(len(snap), 2)

    def test_other_inbound_restored_from_snapshot(self):
        # exit-нода: users.json пустой, снапшот с entry@chain уже выучен
        (self.env.state_dir / "users.json").write_text("[]")
        snap = [{"id": UUID3, "email": "entry@chain"}]
        self.env.write_state({"snapshots": {"inbound-vless": snap},
                              "pending": {}, "restore_events": []})

        # порча инбаунда
        cfg = self.env.read_cfg()
        cfg["inbounds"][0]["settings"]["clients"] = [{"id": "junk", "email": "j@k"}]
        self.env.cfg_path.write_text(json.dumps(cfg))

        rc = self.env.cycle()
        self.assertEqual(rc, 1)
        self.assertEqual(self.env.read_cfg()["inbounds"][0]["settings"]["clients"],
                         snap)

    def test_last_resort_backup_source(self):
        # users.json исчез, снапшота нет — остаётся свежий валидный .bak
        (self.env.state_dir / "users.json").write_text("[]")
        bak = self.env.cfg_dir / "config.json.bak-task56"
        bak.write_text(json.dumps(_cfg_json(_cfg_inbound())))
        # свежее mtime у бэка
        import os
        os.utime(bak)

        cfg = self.env.read_cfg()
        cfg["inbounds"][0]["settings"]["clients"] = [{"id": "u1", "email": "a@x"}]
        self.env.cfg_path.write_text(json.dumps(cfg))

        rc = self.env.cycle()
        self.assertEqual(rc, 1)
        restored = self.env.read_cfg()["inbounds"][0]["settings"]["clients"]
        self.assertEqual([c["id"] for c in restored], [UUID1, UUID2])

    def test_action_none_only_logs(self):
        cfg = self.env.read_cfg()
        cfg["inbounds"][0]["settings"]["clients"] = [{"id": "u1", "email": "a@x"}]
        self.env.cfg_path.write_text(json.dumps(cfg))
        wd = json.loads((self.env.state_dir / "users-watchdog.json").read_text())
        wd["action_on_mismatch"] = "none"
        (self.env.state_dir / "users-watchdog.json").write_text(json.dumps(wd))

        rc = self.env.cycle()
        self.assertEqual(rc, 0)
        self.assertEqual(self.env.read_cfg()["inbounds"][0]["settings"]["clients"],
                         [{"id": "u1", "email": "a@x"}])

    def test_second_config_path_dedup(self):
        # /usr/local/etc/xray/config.json — симлинк на основной
        alt = self.env.d / "usr" / "local" / "etc" / "xray"
        alt.mkdir(parents=True)
        (alt / "config.json").symlink_to(self.env.cfg_path)
        with patch.object(uw, "_CFG_ALT_DIR", alt):
            paths = uw._find_config_paths()
        self.assertEqual(len(paths), 1)


# ─────────────────────────────────────────────────────────────────────────────
#  F. Механика восстановления
# ─────────────────────────────────────────────────────────────────────────────
class TestRestoreMechanics(unittest.TestCase):
    def setUp(self):
        self.env = _Env()

    def tearDown(self):
        self.env.close()

    def test_rollback_on_xray_test_fail(self):
        self.env.xray_test_result(1)
        original = self.env.cfg_path.read_text()
        ok = uw._restore_path(self.env.cfg_path,
                              {"inbound-vless": GOOD_CLIENTS})
        self.assertFalse(ok)
        # конфиг откачен байт-в-байт
        self.assertEqual(self.env.cfg_path.read_text(), original)
        # бэкап с битым состоянием сохранён для форензики
        baks = list(self.env.cfg_dir.glob("config.json.bak-users-watchdog-*"))
        self.assertEqual(len(baks), 1)

    def test_rollback_when_xray_not_active_after_restart(self):
        # is-active → failed после рестарта
        def fake(cmd, timeout=30):
            self.env.systemctl_calls.append(cmd)
            if cmd[:2] == ["systemctl", "restart"]:
                return subprocess.CompletedProcess(cmd, 0, "", "")
            if cmd[:2] == ["systemctl", "is-active"]:
                return subprocess.CompletedProcess(cmd, 1, "failed", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        uw._sh = fake
        with patch.object(uw, "_wait_unit_active", lambda *a, **k: False):
            original = self.env.cfg_path.read_text()
            ok = uw._restore_path(self.env.cfg_path,
                                  {"inbound-vless": GOOD_CLIENTS})
            self.assertFalse(ok)
            self.assertEqual(self.env.cfg_path.read_text(), original)
            # рестарт повторялся (откат + повторный старт)
            restarts = [c for c in self.env.systemctl_calls
                         if c[:2] == ["systemctl", "restart"]]
            self.assertEqual(len(restarts), 2)
            uw._sh = self.env._fake_sh

    def test_atomic_write_preserves_mode(self):
        import os
        p = self.env.cfg_path
        os.chmod(p, 0o600)
        self.assertTrue(uw._atomic_write_text(p, "{}"))
        self.assertEqual(oct(p.stat().st_mode & 0o777), "0o600")
        # tmp-файлов не осталось
        leftovers = [f for f in p.parent.iterdir() if f.name.startswith(".config.json")]
        self.assertEqual(leftovers, [])

    def test_prune_backups(self):
        for i in range(8):
            b = self.env.cfg_dir / f"config.json.bak-users-watchdog-{i:04d}"
            b.write_text("{}")
        uw._prune_backups(3)
        left = sorted(self.env.cfg_dir.glob("config.json.bak-users-watchdog-*"))
        self.assertEqual(len(left), 3)
        # чужие бэкапы не тронуты
        other = self.env.cfg_dir / "config.json.bak-task56"
        other.write_text("{}")
        uw._prune_backups(3)
        self.assertTrue(other.exists())


# ─────────────────────────────────────────────────────────────────────────────
#  G. Systemd-юниты
# ─────────────────────────────────────────────────────────────────────────────
class TestUnits(unittest.TestCase):
    def test_wrapper_script_light(self):
        s = uw._build_wrapper_script()
        self.assertIn("chimera.modules.users_watchdog", s)
        # НЕ запускает main.py (независимость от тяжёлого _core)
        self.assertNotIn("main.py", s)

    def _unit_env(self, d: Path, interval: int = 1):
        """Полная изоляция всех путей install/remove через patch.object."""
        cfg_dir = d / "etc" / "xray"
        cfg_dir.mkdir(parents=True)
        state_dir = d / "state"
        state_dir.mkdir()
        (cfg_dir / "config.json").write_text(json.dumps(_cfg_json(_cfg_inbound())))
        (state_dir / "users.json").write_text(json.dumps(USERS))
        (state_dir / "state.json").write_text(json.dumps({"server_port": 443}))

        def _fake_systemctl(*a, **k):
            # args без префикса 'systemctl': ('is-active', 'xray')
            cmd = list(a)
            if cmd and cmd[0] == "is-active":
                return subprocess.CompletedProcess(cmd, 0, "active", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        patches = [
            patch.object(uw, "_CFG_DIR", cfg_dir),
            patch.object(uw, "_CFG_ALT_DIR", d / "nowhere"),
            patch.object(uw, "_STATE_DIR", state_dir),
            patch.object(uw, "_USERS_FILE", state_dir / "users.json"),
            patch.object(uw, "_XRAY_STATE", state_dir / "state.json"),
            patch.object(uw, "_WD_CONFIG", state_dir / "users-watchdog.json"),
            patch.object(uw, "_WD_STATE", state_dir / "users-watchdog-state.json"),
            patch.object(uw, "_MAINT_FLAG", state_dir / "users-watchdog.maintenance"),
            patch.object(uw, "_LOCK_FILE", d / "users-watchdog.lock"),
            patch.object(uw, "_LOG", d / "users-watchdog.log"),
            patch.object(uw, "_LOGROTATE", d / "logrotate"),
            patch.object(uw, "_SERVICE", d / "uwd.service"),
            patch.object(uw, "_TIMER", d / "uwd.timer"),
            patch.object(uw, "_SCRIPT", d / "uwd.sh"),
            patch.object(uw, "_RESTART_WAIT_SEC", 0),
            patch.object(uw, "_xray_bin", lambda: "/usr/bin/true"),
            patch.object(uw, "_systemctl", _fake_systemctl),
        ]
        return patches, d

    def test_install_writes_units(self):
        with tempfile.TemporaryDirectory() as d:
            dd = Path(d)
            patches, _ = self._unit_env(dd, 2)
            for p in patches:
                p.start()
            try:
                uw.users_watchdog_install(interval_minutes=2)
                self.assertTrue((dd / "uwd.service").exists())
                self.assertTrue((dd / "uwd.timer").exists())
                self.assertIn("OnUnitActiveSec=2min", (dd / "uwd.timer").read_text())
                self.assertIn("ExecStart=", (dd / "uwd.service").read_text())
                cfg = json.loads((dd / "state" / "users-watchdog.json").read_text())
                self.assertEqual(cfg["interval_minutes"], 2)
                self.assertTrue(cfg["enabled"])
                # скрипт исполняемый и лёгкий
                import stat
                self.assertTrue((dd / "uwd.sh").stat().st_mode & stat.S_IXUSR)
                self.assertNotIn("main.py", (dd / "uwd.sh").read_text())
                # первый проход выполнен: снапшот выучен, статус ok
                st = json.loads((dd / "state" / "users-watchdog-state.json").read_text())
                self.assertEqual(st.get("last_status"), "ok")
                self.assertIn("inbound-vless", st.get("snapshots", {}))
            finally:
                for p in patches:
                    p.stop()

    def test_install_first_cycle_fixes_corrupted(self):
        with tempfile.TemporaryDirectory() as d:
            dd = Path(d)
            patches, _ = self._unit_env(dd)
            for p in patches:
                p.start()
            try:
                # порча ДО установки: install должен починить сразу
                p = dd / "etc" / "xray" / "config.json"
                cfg = json.loads(p.read_text())
                cfg["inbounds"][0]["settings"]["clients"] = [{"id": "u1",
                                                             "email": "a@x"}]
                p.write_text(json.dumps(cfg))
                uw.users_watchdog_install(interval_minutes=1)
                cfg2 = json.loads(p.read_text())
                ids = [c["id"] for c in cfg2["inbounds"][0]["settings"]["clients"]]
                self.assertIn(UUID1, ids)
                self.assertNotIn("u1", ids)
            finally:
                for p in patches:
                    p.stop()

    def test_remove_deletes_units(self):
        with tempfile.TemporaryDirectory() as d:
            dd = Path(d)
            patches, _ = self._unit_env(dd)
            for p in patches:
                p.start()
            try:
                uw.users_watchdog_install(interval_minutes=1)
                self.assertTrue((dd / "uwd.service").exists())
                uw.users_watchdog_remove()
                self.assertFalse((dd / "uwd.service").exists())
                self.assertFalse((dd / "uwd.timer").exists())
                self.assertFalse((dd / "uwd.sh").exists())
                # конфиг/состояние переживают удаление
                self.assertTrue((dd / "state" / "users-watchdog.json").exists())
                cfg = json.loads((dd / "state" / "users-watchdog.json").read_text())
                self.assertFalse(cfg["enabled"])
            finally:
                for p in patches:
                    p.stop()

    def test_service_uses_script_path(self):
        with tempfile.TemporaryDirectory() as d:
            dd = Path(d)
            patches, _ = self._unit_env(dd)
            for p in patches:
                p.start()
            try:
                s = uw._build_service()
                self.assertIn("Type=oneshot", s)
                self.assertIn("After=xray.service", s)
                self.assertIn(str(uw._SCRIPT), s)
                self.assertIn("Users Watchdog", s)
            finally:
                for p in patches:
                    p.stop()

    def test_timer_interval(self):
        self.assertIn("OnUnitActiveSec=5min", uw._build_timer(5))
        self.assertIn("OnUnitActiveSec=1min", uw._build_timer(1))
        self.assertIn("WantedBy=timers.target", uw._build_timer(3))


# ─────────────────────────────────────────────────────────────────────────────
#  H. Проводка
# ─────────────────────────────────────────────────────────────────────────────
class TestWiring(unittest.TestCase):
    def test_main_py_cli(self):
        src = (_PROJECT_ROOT / "main.py").read_text()
        self.assertIn("--users-watchdog-run", src)
        self.assertIn("users_watchdog_run", src)

    def test_core_menu_item(self):
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        self.assertIn("do_manage_users_watchdog", src)
        self.assertIn('"UW"', src)
        self.assertIn("from chimera.modules.users_watchdog import", src)

    def test_module_stdlib_only_top_level(self):
        """Верхний уровень модуля не тянет chimera._core — watchdog живёт
        даже если ядро сломано (его и защищаем от этого)."""
        import ast as _ast
        tree = _ast.parse(
            (_PROJECT_ROOT / "chimera" / "modules" / "users_watchdog.py").read_text())
        for node in tree.body:
            if isinstance(node, _ast.Import):
                for a in node.names:
                    self.assertFalse(a.name.startswith("chimera"),
                                     f"top-level import {a.name}")
            if isinstance(node, _ast.ImportFrom):
                self.assertFalse((node.module or "").startswith("chimera"),
                                 f"top-level from-import {node.module}")

    def test_users_file_path_matches_core(self):
        # users.json живёт в /etc/xray/users.json (как USERS_FILE в _core:
        # CONFIG_DIR / "users.json") — НЕ в /var/lib/xray-installer.
        # Проверено на проде: /etc/xray/users.json существует на entry-нодах.
        self.assertEqual(uw._USERS_FILE, Path("/etc/xray/users.json"))

    def test_ts_epoch_and_iso(self):
        self.assertGreater(uw._ts(1760000000), 1.7e9)  # epoch-секунды
        t = uw._ts("2026-10-16 09:00:00")
        self.assertGreater(t, 1.7e9)
        self.assertEqual(uw._ts(None), 0.0)
        self.assertEqual(uw._ts("garbage"), 0.0)

    def test_diff_fingerprint_stable(self):
        d = uw._diff_clients([{"id": "u1"}], GOOD_CLIENTS, True)
        self.assertEqual(uw._diff_fingerprint(d), uw._diff_fingerprint(
            uw._diff_clients([{"id": "u1"}], GOOD_CLIENTS, True)))
        self.assertNotEqual(uw._diff_fingerprint(d), uw._diff_fingerprint(
            uw._diff_clients([], GOOD_CLIENTS, True)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
