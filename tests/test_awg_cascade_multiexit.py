#!/usr/bin/env python3
"""
tests/test_awg_cascade_multiexit.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты мульти-exit каскада (v5.5.3) в awg_cascade.py.

Покрывает:
  1. _awgs_cascade_parse_handshake_age — парсинг «latest handshake»
  2. _awgs_cascade_exits_load — леничная миграция legacy-каскада
  3. awgs_cascade_register_exit — happy path + валидации + дедуп + лимит
  4. awgs_cascade_activate_exit — конфиг из бокса, routing-скрипт, state
  5. awgs_cascade_remove_exit — удаление + авто-переключение
  6. awgs_cascade_failover_check — таблица решений (ok/ok-probe/failover/
     all-dead/single-exit/not-entry)
  7. awgs_cascade_failover_setup/teardown — юниты + wrapper
  8. awgs_cascade_setup_awg0 — регистрирует exit в cascade_exits (регресс
     нового поведения) + FIX-E (setup_awg1 бокс содержит peer privkey)
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

_AWG1_CONF_REAL = None  # путь подменяется в setUp каждого теста


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


def _mock_core_for_cascade():
    core = MagicMock()
    for attr in ("GREEN", "NC", "RED", "YELLOW", "CYAN", "BLUE", "DIM", "BOLD"):
        setattr(core, attr, "")
    for attr in ("_box_top", "_box_row", "_box_sep", "_box_bottom",
                 "_box_item", "_box_desc", "_box_wrap_msg"):
        setattr(core, attr, MagicMock())
    for attr in ("info", "success", "warn", "error", "log_to_file"):
        setattr(core, attr, MagicMock())
    r = MagicMock()
    r.returncode = 0
    r.stdout = ""
    r.stderr = ""
    core._run = MagicMock(return_value=r)
    core.get_server_ip = MagicMock(return_value="5.6.7.8")
    return core


_HPKEY = "aGVhZGVycHJvdGVjdGlvbi1rZXktMzItYnl0ZXMhISEhIQ=="

_PARAMS_31 = {
    "jc": 4, "jmin": 40, "jmax": 70,
    "s1": 15, "s2": 20, "s3": 12, "s4": 12,
    "h1": 1, "h2": 2, "h3": 3, "h4": 4,
    "i1": "<r 32>", "i2": "", "i3": "", "i4": "", "i5": "",
    "header_protection_key": _HPKEY,
    "content_padding_addition": "12-40",
    "rekey_after_time": "100-140",
    "rekey_timeout": "3-6",
    "reject_after_time": "170-250",
    "keepalive_timeout": "8-14",
    "max_handshake_attempts": "15-35",
    "random_trailers": "on",
    "disable_cookies": "on",
}

_STATE_31_ENTRY = {
    "installed": True,
    "interface": "awg0",
    "port": 51831,
    "subnet": "172.16.81.0/24",
    "mtu": 1280,
    "endpoint": "203.0.113.101",
    "params": dict(_PARAMS_31),
    "protocol_version": "3.1",
    "cascade_role": "entry",
}


def _box(name, endpoint, port=52831, subnet="172.16.91.0/24",
         params=None, pv="3.1"):
    return {
        "name": name,
        "endpoint": endpoint,
        "port": port,
        "server_pubkey": f"PUB-{name}",
        "peer_privkey": f"PRIV-{name}",
        "peer_psk": "",
        "peer_ip": "172.16.91.2",
        "subnet": subnet,
        "protocol_version": pv,
        "params": params if params is not None else dict(_PARAMS_31),
        "mtu": 1280,
        "added_at": "2026-10-04T00:00:00+00:00",
    }


class _CascadeTestBase(unittest.TestCase):
    """База: fake core + tmp state-файл + очистка /etc/amnezia артефактов."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "awg_standalone_state.json"
        self._awg1_conf = self._tmpdir / "awg1.conf"
        from chimera.modules import awg_cascade
        self.awg_cascade = awg_cascade
        self.mock_core = _mock_core_for_cascade()
        self._patches = [
            patch.object(awg_cascade, "_core_module",
                         return_value=self.mock_core),
            patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                  self._state_file),
            # awg1.conf → tmp (тесты не под root, /etc/amnezia недоступен)
            patch("chimera.modules.awg_cascade.AWGS_AWG1_CONF",
                  self._awg1_conf),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(self._stop_patches)

    def _stop_patches(self):
        for p in self._patches:
            p.stop()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write_state(self, state: dict):
        self._state_file.write_text(json.dumps(state))

    def _read_state(self) -> dict:
        return json.loads(self._state_file.read_text())


# ── 1. Парсер handshake ─────────────────────────────────────────────────────

class TestParseHandshakeAge(unittest.TestCase):
    def test_seconds(self):
        from chimera.modules.awg_cascade import _awgs_cascade_parse_handshake_age
        self.assertEqual(
            _awgs_cascade_parse_handshake_age("latest handshake: 45 seconds ago"),
            45)

    def test_minutes_seconds(self):
        from chimera.modules.awg_cascade import _awgs_cascade_parse_handshake_age
        self.assertEqual(
            _awgs_cascade_parse_handshake_age(
                "latest handshake: 1 minute, 25 seconds ago"), 85)

    def test_minutes_only(self):
        from chimera.modules.awg_cascade import _awgs_cascade_parse_handshake_age
        self.assertEqual(
            _awgs_cascade_parse_handshake_age("latest handshake: 2 minutes ago"),
            120)

    def test_hours_minutes(self):
        from chimera.modules.awg_cascade import _awgs_cascade_parse_handshake_age
        self.assertEqual(
            _awgs_cascade_parse_handshake_age(
                "latest handshake: 3 hours, 2 minutes ago"), 10920)

    def test_days(self):
        from chimera.modules.awg_cascade import _awgs_cascade_parse_handshake_age
        self.assertEqual(
            _awgs_cascade_parse_handshake_age(
                "latest handshake: 1 day, 1 hour ago"), 90000)

    def test_no_handshake_line(self):
        from chimera.modules.awg_cascade import _awgs_cascade_parse_handshake_age
        self.assertIsNone(
            _awgs_cascade_parse_handshake_age(
                "peer: xxx\n  endpoint: 1.2.3.4:5\n  allowed ips: 0.0.0.0/0"))

    def test_empty_and_garbage(self):
        from chimera.modules.awg_cascade import _awgs_cascade_parse_handshake_age
        self.assertIsNone(_awgs_cascade_parse_handshake_age(""))
        self.assertIsNone(_awgs_cascade_parse_handshake_age("мусор"))
        # непарсируемые компоненты → None (защита от частичного парса)
        self.assertIsNone(
            _awgs_cascade_parse_handshake_age("latest handshake: soon ago"))


# ── 2. Legacy-миграция ──────────────────────────────────────────────────────

class TestExitsLoadLegacyMigration(_CascadeTestBase):
    def test_legacy_flat_fields_migrated(self):
        state = dict(_STATE_31_ENTRY)
        state.update({
            "cascade_peer_host": "203.0.113.107",
            "cascade_peer_port": 52831,
            "cascade_peer_pubkey": "FI1-PUB",
            "cascade_peer_privkey": "FI1-PRIV",
            "cascade_subnet": "172.16.91.0/24",
        })
        self._write_state(state)

        exits = self.awg_cascade._awgs_cascade_exits_load()
        self.assertEqual(len(exits), 1)
        box = exits[0]
        self.assertEqual(box["name"], "203.0.113.107")  # slug от host
        self.assertEqual(box["endpoint"], "203.0.113.107")
        self.assertEqual(box["server_pubkey"], "FI1-PUB")
        self.assertEqual(box["peer_privkey"], "FI1-PRIV")
        self.assertEqual(box["protocol_version"], "3.1")
        self.assertEqual(box["params"], state["params"])

        # Миграция сохранена в state
        saved = self._read_state()
        self.assertEqual(len(saved["cascade_exits"]), 1)
        self.assertEqual(saved["cascade_active_exit"], "203.0.113.107")

    def test_no_cascade_no_migration(self):
        self._write_state(dict(_STATE_31_ENTRY))
        self.assertEqual(self.awg_cascade._awgs_cascade_exits_load(), [])
        self.assertNotIn("cascade_exits", self._read_state())

    def test_existing_exits_not_touched(self):
        state = dict(_STATE_31_ENTRY)
        state["cascade_exits"] = [_box("fi1", "203.0.113.107")]
        state["cascade_active_exit"] = "fi1"
        self._write_state(state)
        exits = self.awg_cascade._awgs_cascade_exits_load()
        self.assertEqual([e["name"] for e in exits], ["fi1"])


# ── 3. register_exit ────────────────────────────────────────────────────────

class TestRegisterExit(_CascadeTestBase):
    def _register(self, **kw):
        defaults = dict(
            name="de", endpoint="203.0.113.106", port=52831,
            server_pubkey="DE-PUB", peer_privkey="DE-PRIV",
            peer_ip="172.16.91.2", subnet="172.16.91.0/24",
            protocol_version="3.1", params=dict(_PARAMS_31),
        )
        defaults.update(kw)
        return self.awg_cascade.awgs_cascade_register_exit(**defaults)

    def test_happy_path_first_exit_activates(self):
        self._write_state(dict(_STATE_31_ENTRY))
        with patch.object(self.awg_cascade, "awgs_cascade_activate_exit",
                          return_value=True) as m_act:
            ok = self._register()
        self.assertTrue(ok)
        m_act.assert_called_once_with("de")  # первый exit активируется
        saved = self._read_state()
        self.assertEqual(len(saved["cascade_exits"]), 1)
        self.assertEqual(saved["cascade_exits"][0]["endpoint"],
                         "203.0.113.106")
        self.assertEqual(saved["cascade_active_exit"], "de")

    def test_second_exit_no_activate_by_default(self):
        state = dict(_STATE_31_ENTRY)
        state["cascade_exits"] = [_box("fi1", "203.0.113.107")]
        state["cascade_active_exit"] = "fi1"
        self._write_state(state)
        with patch.object(self.awg_cascade, "awgs_cascade_activate_exit",
                          return_value=True) as m_act:
            ok = self._register(name="de", endpoint="203.0.113.106")
        self.assertTrue(ok)
        m_act.assert_not_called()  # активным остаётся fi1
        saved = self._read_state()
        self.assertEqual([e["name"] for e in saved["cascade_exits"]],
                         ["fi1", "de"])

    def test_dedup_by_name(self):
        state = dict(_STATE_31_ENTRY)
        state["cascade_exits"] = [_box("de", "203.0.113.116")]
        state["cascade_active_exit"] = "de"
        self._write_state(state)
        with patch.object(self.awg_cascade, "awgs_cascade_activate_exit",
                          return_value=True):
            ok = self._register(name="de", endpoint="203.0.113.106")
        self.assertTrue(ok)
        saved = self._read_state()
        self.assertEqual(len(saved["cascade_exits"]), 1)
        self.assertEqual(saved["cascade_exits"][0]["endpoint"],
                         "203.0.113.106")  # обновлён

    def test_dedup_by_endpoint_port(self):
        state = dict(_STATE_31_ENTRY)
        state["cascade_exits"] = [_box("de-old", "203.0.113.106")]
        state["cascade_active_exit"] = "de-old"
        self._write_state(state)
        with patch.object(self.awg_cascade, "awgs_cascade_activate_exit",
                          return_value=True):
            ok = self._register(name="de", endpoint="203.0.113.106")
        self.assertTrue(ok)
        saved = self._read_state()
        self.assertEqual([e["name"] for e in saved["cascade_exits"]],
                         ["de"])  # заменён, не клон

    def test_version_mismatch_rejected(self):
        self._write_state(dict(_STATE_31_ENTRY))
        ok = self._register(protocol_version="2.0")
        self.assertFalse(ok)
        self.assertNotIn("cascade_exits", self._read_state())

    def test_self_loop_rejected(self):
        self._write_state(dict(_STATE_31_ENTRY))
        # get_server_ip замокан на 5.6.7.8
        ok = self._register(endpoint="5.6.7.8")
        self.assertFalse(ok)

    def test_subnet_conflict_rejected(self):
        self._write_state(dict(_STATE_31_ENTRY))  # subnet 172.16.81.0/24
        ok = self._register(subnet="172.16.81.0/24")
        self.assertFalse(ok)

    def test_missing_keys_rejected(self):
        self._write_state(dict(_STATE_31_ENTRY))
        self.assertFalse(self._register(server_pubkey=""))
        self.assertFalse(self._register(peer_privkey=""))
        self.assertFalse(self._register(endpoint=""))

    def test_bad_port_rejected(self):
        self._write_state(dict(_STATE_31_ENTRY))
        self.assertFalse(self._register(port=0))
        self.assertFalse(self._register(port=70000))
        self.assertFalse(self._register(port="abc"))

    def test_max_exits_cap(self):
        from chimera.modules.awg_constants import AWGS_FAILOVER_MAX_EXITS
        state = dict(_STATE_31_ENTRY)
        state["cascade_exits"] = [
            _box(f"e{i}", f"10.0.0.{i}") for i in range(AWGS_FAILOVER_MAX_EXITS)
        ]
        state["cascade_active_exit"] = "e0"
        self._write_state(state)
        self.assertFalse(self._register(name="overflow",
                                        endpoint="10.9.9.9"))

    def test_name_slugified(self):
        self._write_state(dict(_STATE_31_ENTRY))
        with patch.object(self.awg_cascade, "awgs_cascade_activate_exit",
                          return_value=True):
            ok = self._register(name="PL 1/Главная!", endpoint="1.2.3.4")
        self.assertTrue(ok)
        saved = self._read_state()
        # кириллица/слэши → дефисы, хвостовые дефисы срезаются
        self.assertEqual(saved["cascade_exits"][0]["name"], "PL-1")


# ── 4. activate_exit ────────────────────────────────────────────────────────

class TestActivateExit(_CascadeTestBase):
    def test_conf_written_from_box(self):
        state = dict(_STATE_31_ENTRY)
        state["cascade_exits"] = [
            _box("fi1", "203.0.113.107"),
            _box("de", "203.0.113.106"),
        ]
        state["cascade_active_exit"] = "fi1"
        self._write_state(state)

        with patch.object(self.awg_cascade,
                          "_awgs_cascade_create_routing_script"):
            ok = self.awg_cascade.awgs_cascade_activate_exit("de")
        self.assertTrue(ok)

        # awg1.conf построен из бокса de
        conf = self._awg1_conf.read_text()
        self.assertIn("Endpoint = 203.0.113.106:52831", conf)
        self.assertIn("PublicKey = PUB-de", conf)
        self.assertIn(f"HeaderProtectionKey = {_HPKEY}", conf)  # 3.1 из бокса

        # state: активный + зеркало legacy-полей
        saved = self._read_state()
        self.assertEqual(saved["cascade_active_exit"], "de")
        self.assertEqual(saved["cascade_peer_host"], "203.0.113.106")
        self.assertEqual(saved["cascade_peer_pubkey"], "PUB-de")
        self.assertEqual(saved["cascade_subnet"], "172.16.91.0/24")

        # routing-скрипт перегенерирован под подсеть exit
        # (через create_routing_script — замокан ниже проверкой вызовов)
        # systemctl: enable + restart awg1 + restart routing
        calls = [c[0][0] for c in self.mock_core._run.call_args_list
                 if c and c[0]]
        self.assertTrue(any("restart" in " ".join(c) and "awg-quick@awg1" in " ".join(c)
                            for c in calls if isinstance(c, list)))

    def test_unknown_name_rejected(self):
        state = dict(_STATE_31_ENTRY)
        state["cascade_exits"] = [_box("fi1", "203.0.113.107")]
        self._write_state(state)
        self.assertFalse(
            self.awg_cascade.awgs_cascade_activate_exit("nonexistent"))

    def test_routing_script_regenerated_with_subnet(self):
        state = dict(_STATE_31_ENTRY)
        state["cascade_exits"] = [
            _box("fi1", "203.0.113.107", subnet="172.16.91.0/24"),
            _box("de", "203.0.113.106", subnet="172.16.92.0/24"),
        ]
        state["cascade_active_exit"] = "fi1"
        self._write_state(state)
        with patch.object(self.awg_cascade,
                          "_awgs_cascade_create_routing_script") as m_rs:
            ok = self.awg_cascade.awgs_cascade_activate_exit("de")
        self.assertTrue(ok)
        # v5.5.8: activate_exit передаёт и v6-подсеть каскада (пустая строка
        # при выключенном allow_ipv6_tunnel — как в этом fixture)
        m_rs.assert_called_once_with("172.16.92.0/24", subnet_v6="")


# ── 5. remove_exit ──────────────────────────────────────────────────────────

class TestRemoveExit(_CascadeTestBase):
    def test_remove_inactive(self):
        state = dict(_STATE_31_ENTRY)
        state["cascade_exits"] = [
            _box("fi1", "203.0.113.107"), _box("de", "203.0.113.106")]
        state["cascade_active_exit"] = "fi1"
        self._write_state(state)
        with patch.object(self.awg_cascade, "awgs_cascade_activate_exit",
                          return_value=True) as m_act:
            ok = self.awg_cascade.awgs_cascade_remove_exit("de")
        self.assertTrue(ok)
        m_act.assert_not_called()  # активный не менялся
        saved = self._read_state()
        self.assertEqual([e["name"] for e in saved["cascade_exits"]], ["fi1"])

    def test_remove_active_switches_to_next(self):
        state = dict(_STATE_31_ENTRY)
        state["cascade_exits"] = [
            _box("fi1", "203.0.113.107"), _box("de", "203.0.113.106")]
        state["cascade_active_exit"] = "fi1"
        self._write_state(state)
        with patch.object(self.awg_cascade, "awgs_cascade_activate_exit",
                          return_value=True) as m_act:
            ok = self.awg_cascade.awgs_cascade_remove_exit("fi1")
        self.assertTrue(ok)
        m_act.assert_called_once_with("de")
        saved = self._read_state()
        self.assertEqual(saved["cascade_active_exit"], "de")

    def test_remove_unknown(self):
        state = dict(_STATE_31_ENTRY)
        state["cascade_exits"] = [_box("fi1", "203.0.113.107")]
        self._write_state(state)
        self.assertFalse(
            self.awg_cascade.awgs_cascade_remove_exit("ghost"))


# ── 6. failover_check — таблица решений ─────────────────────────────────────

class TestFailoverCheck(_CascadeTestBase):
    def _state_2exits(self):
        state = dict(_STATE_31_ENTRY)
        state["cascade_exits"] = [
            _box("fi1", "203.0.113.107"), _box("de", "203.0.113.106")]
        state["cascade_active_exit"] = "fi1"
        self._write_state(state)

    def test_not_entry(self):
        state = dict(_STATE_31_ENTRY)
        state["cascade_role"] = "exit"
        self._write_state(state)
        self.assertEqual(
            self.awg_cascade.awgs_cascade_failover_check(), "not-entry")

    def test_single_exit(self):
        state = dict(_STATE_31_ENTRY)
        state["cascade_exits"] = [_box("fi1", "203.0.113.107")]
        state["cascade_active_exit"] = "fi1"
        self._write_state(state)
        self.assertEqual(
            self.awg_cascade.awgs_cascade_failover_check(), "single-exit")

    def test_fresh_handshake_ok(self):
        self._state_2exits()
        with patch.object(self.awg_cascade, "awgs_cascade_handshake_age",
                          return_value=42):
            self.assertEqual(
                self.awg_cascade.awgs_cascade_failover_check(), "ok")

    def test_stale_but_ping_ok(self):
        self._state_2exits()
        with patch.object(self.awg_cascade, "awgs_cascade_handshake_age",
                          return_value=9999), \
             patch.object(self.awg_cascade, "_awgs_cascade_probe_alive",
                          return_value=True):
            self.assertEqual(
                self.awg_cascade.awgs_cascade_failover_check(), "ok-probe")

    def test_failover_to_next_candidate(self):
        self._state_2exits()
        with patch.object(self.awg_cascade, "awgs_cascade_handshake_age",
                          return_value=9999), \
             patch.object(self.awg_cascade, "_awgs_cascade_probe_alive",
                          return_value=False), \
             patch.object(self.awg_cascade, "awgs_cascade_activate_exit",
                          return_value=True) as m_act:
            result = self.awg_cascade.awgs_cascade_failover_check()
        self.assertEqual(result, "failover:de")
        m_act.assert_called_once_with("de", probe_timeout=18)

    def test_all_dead_restores_original(self):
        self._state_2exits()
        with patch.object(self.awg_cascade, "awgs_cascade_handshake_age",
                          return_value=9999), \
             patch.object(self.awg_cascade, "_awgs_cascade_probe_alive",
                          return_value=False), \
             patch.object(self.awg_cascade, "awgs_cascade_activate_exit",
                          return_value=False) as m_act:
            result = self.awg_cascade.awgs_cascade_failover_check()
        self.assertEqual(result, "all-dead")
        # второй вызов — восстановление исходного (fi1) без пробы
        self.assertEqual(m_act.call_count, 2)
        self.assertEqual(m_act.call_args_list[-1],
                         unittest.mock.call("fi1", probe_timeout=0))

    def test_never_handshaked_triggers_failover(self):
        # age=None (туннель свежий/мёртвый) + ping fail → failover
        self._state_2exits()
        with patch.object(self.awg_cascade, "awgs_cascade_handshake_age",
                          return_value=None), \
             patch.object(self.awg_cascade, "_awgs_cascade_probe_alive",
                          return_value=False), \
             patch.object(self.awg_cascade, "awgs_cascade_activate_exit",
                          return_value=True):
            self.assertEqual(
                self.awg_cascade.awgs_cascade_failover_check(),
                "failover:de")


# ── 7. failover_setup / teardown ────────────────────────────────────────────

class TestFailoverSetupTeardown(_CascadeTestBase):
    def setUp(self):
        super().setUp()
        self._script = self._tmpdir / "failover.sh"
        self._svc = self._tmpdir / "failover.service"
        self._timer = self._tmpdir / "failover.timer"
        self._patches += [
            patch("chimera.modules.awg_cascade.AWGS_FAILOVER_SCRIPT",
                  self._script),
            patch("chimera.modules.awg_cascade.AWGS_SYSTEMD_FAILOVER_SVC",
                  self._svc),
            patch("chimera.modules.awg_cascade.AWGS_SYSTEMD_FAILOVER_TIMER",
                  self._timer),
        ]
        for p in self._patches[-3:]:
            p.start()

    def test_setup_writes_units_and_enables(self):
        # is-active → "active"
        r_active = MagicMock()
        r_active.returncode = 0
        r_active.stdout = "active"
        self.mock_core._run = MagicMock(return_value=r_active)

        ok = self.awg_cascade.awgs_cascade_failover_setup()
        self.assertTrue(ok)

        wrapper = self._script.read_text()
        self.assertIn("sys.path.insert", wrapper)          # PYTHONPATH-safe
        self.assertIn("awgs_cascade_failover_check", wrapper)
        timer = self._timer.read_text()
        self.assertIn("OnCalendar=*:0/1", timer)           # каждую минуту
        self.assertIn("AccuracySec=10s", timer)
        self.assertIn("Persistent=true", timer)
        svc = self._svc.read_text()
        self.assertIn("Type=oneshot", svc)

        calls = [" ".join(c[0][0]) for c in
                 self.mock_core._run.call_args_list]
        self.assertTrue(any("enable" in c and
                            "awg-cascade-failover.timer" in c
                            for c in calls))

    def test_setup_fails_when_timer_not_active(self):
        r_dead = MagicMock()
        r_dead.returncode = 3
        r_dead.stdout = "inactive"
        self.mock_core._run = MagicMock(return_value=r_dead)
        self.assertFalse(
            self.awg_cascade.awgs_cascade_failover_setup())

    def test_teardown_stops_and_removes(self):
        for f in (self._script, self._svc, self._timer):
            f.write_text("x")
        self.awg_cascade.awgs_cascade_failover_teardown()
        self.assertFalse(self._script.exists())
        self.assertFalse(self._svc.exists())
        self.assertFalse(self._timer.exists())
        calls = [" ".join(c[0][0]) for c in
                 self.mock_core._run.call_args_list]
        self.assertTrue(any("stop" in c and "failover.timer" in c
                            for c in calls))
        self.assertTrue(any("disable" in c and "failover.timer" in c
                            for c in calls))


# ── 8. setup_awg0 регресс + FIX-E ───────────────────────────────────────────

class TestSetupAwg0RegistersExit(_CascadeTestBase):
    def _run_setup_awg0(self, exit_host="203.0.113.107", exit_port=52831):
        # Инициализация только при первом вызове — дальнейшие прогоны
        # работают с накопленным state (реальный сценарий повторной настройки)
        if not self._state_file.exists():
            state = dict(_STATE_31_ENTRY)
            self._write_state(state)

        # Умный _run: «which awg» → путь, «echo PRIV | awg pubkey» → PUB
        def _smart_run(cmd, **kw):
            r = MagicMock()
            r.returncode = 0
            r.stderr = ""
            joined = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            if "which awg" in joined or joined == "awg":
                r.stdout = "/usr/bin/awg"
            elif "pubkey" in joined:
                r.stdout = "EXIT-PEER-PUB"
            elif joined.startswith("ipset"):
                r.stdout = "Number of entries: 8652"
            else:
                r.stdout = ""
            return r
        self.mock_core._run = MagicMock(side_effect=_smart_run)

        with patch.object(self.awg_cascade, "awgs_generate_keys",
                          return_value=("GEN-PRIV", "GEN-PUB")), \
             patch.object(self.awg_cascade,
                          "awgs_state_set_cascade_role"), \
             patch.object(self.awg_cascade,
                          "_awgs_cascade_build_awg1_conf",
                          return_value="[Interface]\n"), \
             patch.object(self.awg_cascade,
                          "awgs_cascade_download_ru_zone",
                          return_value=True), \
             patch.object(self.awg_cascade, "awgs_cascade_load_ipset",
                          return_value=True), \
             patch.object(self.awg_cascade,
                          "_awgs_cascade_apply_iptables",
                          return_value=True), \
             patch.object(self.awg_cascade,
                          "_awgs_cascade_create_routing_script"), \
             patch.object(self.awg_cascade,
                          "_awgs_cascade_create_systemd_unit"), \
             patch.object(self.awg_cascade, "_awgs_cascade_setup_cron"):
            return self.awg_cascade.awgs_cascade_setup_awg0(
                exit_host=exit_host,
                exit_port=exit_port,
                exit_pubkey="EXIT-PUB",
                exit_subnet="172.16.91.0/24",
                exit_peer_privkey="EXIT-PEER-PRIV",
                exit_peer_ip="172.16.91.2",
                exit_params=dict(_PARAMS_31),
                exit_protocol_version="3.1",
            )

    def test_setup_registers_exit_in_list(self):
        self.assertTrue(self._run_setup_awg0())
        saved = self._read_state()
        self.assertEqual(len(saved["cascade_exits"]), 1)
        box = saved["cascade_exits"][0]
        self.assertEqual(box["endpoint"], "203.0.113.107")
        self.assertEqual(box["peer_privkey"], "EXIT-PEER-PRIV")
        self.assertEqual(box["protocol_version"], "3.1")
        self.assertEqual(saved["cascade_active_exit"], "203.0.113.107")

    def test_setup_dedup_on_second_run(self):
        self.assertTrue(self._run_setup_awg0())
        self.assertTrue(self._run_setup_awg0())  # тот же exit → замена
        saved = self._read_state()
        self.assertEqual(len(saved["cascade_exits"]), 1)

        # другой exit-хост → вторая запись (разные имена)
        self.assertTrue(
            self._run_setup_awg0(exit_host="203.0.113.106"))
        saved = self._read_state()
        self.assertEqual(len(saved["cascade_exits"]), 2)
        self.assertEqual(
            [e["endpoint"] for e in saved["cascade_exits"]],
            ["203.0.113.107", "203.0.113.106"])


class TestSetupAwg1BoxContainsPrivkey(_CascadeTestBase):
    """FIX-E: бокс exit обязан содержать privkey пира cascade_entry."""

    def test_box_row_printed_with_privkey(self):
        state = dict(_STATE_31_ENTRY)
        state["cascade_role"] = "exit"
        state["peers"] = [{
            "name": "cascade_entry", "client_ip": "172.16.91.2",
            "client_privkey": "PEER-PRIV-XYZ", "client_pubkey": "PEER-PUB",
        }]
        self._write_state(state)
        peer = state["peers"][0]

        with patch.object(self.awg_cascade, "awgs_state_is_installed",
                          return_value=True), \
             patch.object(self.awg_cascade, "awgs_state_load",
                          return_value=state), \
             patch("chimera.modules.awg_state.awgs_state_peer_find",
                   return_value=peer), \
             patch("chimera.modules.awg_state.awgs_state_peer_remove"), \
             patch.object(self.awg_cascade, "awg_peer_add",
                          return_value=True), \
             patch.object(self.awg_cascade, "awgs_state_set_cascade_role"), \
             patch.object(self.mock_core, "_box_row") as m_row:
            ok = self.awg_cascade.awgs_cascade_setup_awg1(
                protocol_version="3.1")
        self.assertTrue(ok)
        rows = " ".join(str(c[0][0]) for c in m_row.call_args_list
                        if c and c[0])
        self.assertIn("PEER-PRIV-XYZ", rows)


if __name__ == "__main__":
    unittest.main(verbosity=2)
