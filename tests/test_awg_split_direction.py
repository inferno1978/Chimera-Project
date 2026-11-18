#!/usr/bin/env python3
"""
tests/test_awg_split_direction.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты split-direction — пары однонаправленных туннелей entry↔exit
(chimera/modules/awg_split_direction.py).

Покрывает:
  1. Конфиги: клиентские плечи (Table=off, AllowedIPs, синхронная
     обфускация, 3.1-директивы) и серверные (ListenPort, Address /24,
     AllowedIPs пира in-плеча содержит out-адрес entry — dst-роутинг WG)
  2. Routing-скрипты: entry (снятие каскадной марки + split-марка +
     on-link default) и exit (connmark → in-плечо); идемпотентность форм
  3. split_box_validate: полнота бокса, версии протокола, коллизии
     подсетей, порты
  4. split_setup_entry: лестница включения (handshake обоих плеч,
     e2e-гейт, откат при провале БЕЗ переключения транзита), state
  5. split_off: снос правил + возврат транзита штатному awg1
  6. split_health_tick: таблица решений (off/ok/ok:e2e/recovered/
     rollback по fail_limit, e2e-кулдаун)
  7. watchdog setup/teardown: юниты + wrapper PYTHONPATH-safe
  8. Интеграция с awg_cascade: activate_exit отказывает при split on
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


def _mock_core():
    core = MagicMock()
    for attr in ("GREEN", "NC", "RED", "YELLOW", "CYAN", "BLUE", "DIM", "BOLD"):
        setattr(core, attr, "")
    for attr in ("_box_top", "_box_row", "_box_sep", "_box_bottom",
                 "_box_item", "_box_desc", "_box_kv", "_box_ask",
                 "_box_wrap_msg"):
        setattr(core, attr, MagicMock())
    for attr in ("info", "success", "warn", "error", "log_to_file"):
        setattr(core, attr, MagicMock())
    r = MagicMock()
    r.returncode = 0
    r.stdout = ""
    r.stderr = ""
    core._run = MagicMock(return_value=r)
    core.get_server_ip = MagicMock(return_value="198.51.100.7")
    return core


_HPKEY = "aGVhZGVycHJvdGVjdGlvbi1rZXktMzItYnl0ZXMhISEhIQ=="

_PARAMS = {
    "jc": 4, "jmin": 40, "jmax": 70,
    "s1": 0, "s2": 0, "s3": 0, "s4": 0,
    "h1": 1, "h2": 2, "h3": 3, "h4": 4,
    "i1": "", "i2": "", "i3": "", "i4": "", "i5": "",
}

_PARAMS_31 = dict(_PARAMS, s1=15, s2=20, s3=12, s4=12, i1="<r 32>",
                  header_protection_key=_HPKEY,
                  content_padding_addition="12-40",
                  rekey_after_time="100-140",
                  rekey_timeout="3-6",
                  reject_after_time="170-250",
                  keepalive_timeout="8-14",
                  max_handshake_attempts="15-35",
                  random_trailers="on",
                  disable_cookies="on")


def _box(endpoint="203.0.113.107", port_out=52840, port_in=52841,
         params=None, protocol_version="3.1"):
    return {
        "endpoint": endpoint,
        "port_out": port_out,
        "port_in": port_in,
        "server_pubkey_out": "SRV-OUT-PUB",
        "server_pubkey_in": "SRV-IN-PUB",
        "peer_privkey_out": "ENT-OUT-PRIV",
        "peer_privkey_in": "ENT-IN-PRIV",
        "protocol_version": protocol_version,
        "params": params if params is not None else dict(_PARAMS_31),
    }


def _awg_show(age=10, tx=1000, rx=1000):
    txt = (
        "interface: awg-split-out\n"
        "peer: PxYx=\n"
        f"  latest handshake: {age} seconds ago\n"
        f"  transfer: {rx} B received, {tx} B sent\n")
    return txt


def _awg_show_none():
    return "interface: awg-split-out\npeer: PxYx=\n"


class _SplitTestBase(unittest.TestCase):
    """База: fake core + tmp state + tmp конфиги + TG-герметичность."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "awg_standalone_state.json"
        self._conf_dir = self._tmpdir / "amneziawg"
        self._conf_dir.mkdir()
        self._scripts_dir = self._tmpdir / "sbin"
        self._scripts_dir.mkdir()
        self._units_dir = self._tmpdir / "systemd"
        self._units_dir.mkdir()
        self._cascade_dir = self._tmpdir / "awg-cascade"
        self._cascade_dir.mkdir()

        from chimera.modules import awg_split_direction as sd
        self.sd = sd

        self.mock_core = _mock_core()
        # Патчим константы В НЕЙМСПЕЙСЕ МОДУЛЯ sd (имена импортированы
        # `from .awg_constants import ...` — патч awg_constants.* на них
        # не действует): тесты не должны писать в /etc и /usr/local/sbin.
        self._patches = [
            patch.object(sd, "_core_module", return_value=self.mock_core),
            patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                  self._state_file),
            patch.object(sd, "AWGS_SPLIT_OUT_CONF",
                         self._conf_dir / "awg-split-out.conf"),
            patch.object(sd, "AWGS_SPLIT_IN_CONF",
                         self._conf_dir / "awg-split-in.conf"),
            patch.object(sd, "AWGS_SPLIT_SCRIPT",
                         self._scripts_dir / "awg-split-direction.sh"),
            patch.object(sd, "AWGS_SPLIT_SVC",
                         self._units_dir / "awg-split-direction.service"),
            patch.object(sd, "AWGS_SPLIT_TIMER",
                         self._units_dir / "awg-split-direction.timer"),
            patch.object(sd, "AWGS_SPLIT_ENTRY_SCRIPT",
                         self._cascade_dir / "awg-split-entry.sh"),
            patch.object(sd, "AWGS_SPLIT_ENTRY_SVC",
                         self._units_dir / "awg-split-entry-routing.service"),
            patch.object(sd, "AWGS_SPLIT_EXIT_SCRIPT",
                         self._cascade_dir / "awg-split-exit.sh"),
            patch.object(sd, "AWGS_SPLIT_EXIT_SVC",
                         self._units_dir / "awg-split-exit-routing.service"),
            # FIX 11.11 (TG-герметичность): уведы обязаны быть замоканы —
            # иначе root-прогон на живой ноде шлёт боевые TG из тестов
            patch("chimera.modules.tg_bot.tg_notify_event", MagicMock()),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(self._stop)

    def _stop(self):
        for p in self._patches:
            p.stop()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write_state(self, state: dict):
        self._state_file.write_text(json.dumps(state))

    def _read_state(self) -> dict:
        return json.loads(self._state_file.read_text())

    def _entry_state(self, split: dict = None) -> dict:
        st = {
            "installed": True,
            "interface": "awg0",
            "port": 51831,
            "subnet": "10.66.66.0/24",
            "mtu": 1280,
            "endpoint": "198.51.100.7",
            "params": dict(_PARAMS_31),
            "protocol_version": "3.1",
            "cascade_role": "entry",
            "cascade_peer_host": "203.0.113.107",
            "cascade_peer_port": 52831,
            "cascade_subnet": "172.16.91.0/24",
        }
        if split is not None:
            st["split_direction"] = split
        return st


# ── 1. Конфиги ──────────────────────────────────────────────────────────────

class TestClientConf(unittest.TestCase):
    def test_out_conf_fields(self):
        from chimera.modules.awg_split_direction import split_build_client_conf
        conf = split_build_client_conf(
            "out", "203.0.113.107", 52840, "SRV-OUT-PUB", "ENT-OUT-PRIV",
            "172.16.62.2", _PARAMS_31, "3.1")
        self.assertIn("Address = 172.16.62.2/32", conf)
        self.assertIn("Table = off", conf)          # без авто-маршрута!
        self.assertIn("Endpoint = 203.0.113.107:52840", conf)
        self.assertIn("AllowedIPs = 0.0.0.0/0", conf)
        self.assertIn("PersistentKeepalive = 25", conf)
        self.assertIn("Jc = 4", conf)
        self.assertIn("S1 = 15", conf)               # синхронная обфускация
        self.assertIn("I1 = <r 32>", conf)
        self.assertIn("HeaderProtectionKey", conf)   # 3.1-директивы
        self.assertNotIn("PresharedKey", conf)       # psk опционален

    def test_20_no_31_directives(self):
        from chimera.modules.awg_split_direction import split_build_client_conf
        conf = split_build_client_conf(
            "in", "203.0.113.107", 52841, "SRV-IN-PUB", "ENT-IN-PRIV",
            "172.16.63.2", _PARAMS, "2.0")
        self.assertNotIn("HeaderProtectionKey", conf)
        self.assertIn("# I1 = ", conf)               # пустые комментируются

    def test_iface_name_not_lb_slot(self):
        # имена плеч не должны попадать в программные слоты LB awg1..awg16
        from chimera.modules.awg_constants import (
            AWGS_SPLIT_OUT_IFACE, AWGS_SPLIT_IN_IFACE)
        import re
        for iface in (AWGS_SPLIT_OUT_IFACE, AWGS_SPLIT_IN_IFACE):
            self.assertFalse(re.fullmatch(r"awg\d+", iface),
                             f"{iface} конфликтует со слотом LB")
            self.assertLessEqual(len(iface), 15)     # IFNAMSIZ


class TestServerConf(unittest.TestCase):
    def test_out_server(self):
        from chimera.modules.awg_split_direction import (
            split_build_server_conf, split_out_server_allowed_ips)
        conf = split_build_server_conf(
            "out", "SRV-PRIV", 52840, "172.16.62.1/24", "ENT-OUT-PUB",
            split_out_server_allowed_ips(), _PARAMS, "2.0")
        self.assertIn("ListenPort = 52840", conf)
        self.assertIn("Address = 172.16.62.1/24", conf)   # НЕ /32
        self.assertIn("AllowedIPs = 172.16.62.2/32", conf)

    def test_in_server_allowed_ips_must_route_out_addr(self):
        # КЛЮЧЕВОЙ инвариант: пир in-плеча обязан пускать dst=out-адрес
        # entry — WG выбирает пира по dst, ответы транзита несут
        # dst=<entry-out-addr> после de-MASQ на exit
        from chimera.modules.awg_split_direction import (
            split_in_server_allowed_ips, split_build_server_conf)
        aip = split_in_server_allowed_ips()
        self.assertIn("172.16.62.2/32", aip)
        conf = split_build_server_conf(
            "in", "SRV-PRIV", 52841, "172.16.63.1/24", "ENT-IN-PUB",
            aip, _PARAMS, "2.0")
        self.assertIn("ListenPort = 52841", conf)
        self.assertIn("172.16.62.2/32", conf)

    def test_ports_must_differ(self):
        from chimera.modules.awg_constants import (
            AWGS_SPLIT_PORT_OUT, AWGS_SPLIT_PORT_IN)
        self.assertNotEqual(AWGS_SPLIT_PORT_OUT, AWGS_SPLIT_PORT_IN)


# ── 2. Routing-скрипты ──────────────────────────────────────────────────────

class TestRoutingScripts(unittest.TestCase):
    def test_entry_script_core_rules(self):
        from chimera.modules.awg_split_direction import (
            split_build_entry_routing_script)
        s = split_build_entry_routing_script(
            ru_excl=" -m set ! --match-set awg_ru_networks dst",
            b4_excl="", out_gw="172.16.62.1", out_net="172.16.62.0/24")
        # 1) каскадная марка снимается (две конкурирующие MARK = затирание)
        self.assertIn(
            "-j MARK --set-mark 33280 2>/dev/null; do :; done", s)
        # 2) split-марка на клиентский транзит с зеркалом RU-исключения
        self.assertIn(
            "-i awg0 -m set ! --match-set awg_ru_networks dst "
            "-j MARK --set-mark 33794", s)
        # 3) on-link подсеть ПЕРЕД default (Nexthop invalid gateway)
        self.assertIn(
            "ip route replace 172.16.62.0/24 dev awg-split-out table 2402", s)
        self.assertIn(
            "ip route replace default via 172.16.62.1 dev awg-split-out "
            "table 2402", s)
        # 4) идемпотентность: -C || -A
        self.assertIn("-C PREROUTING", s)
        # 5) ответы приезжают из in-плеча к клиентам
        self.assertIn(
            "iptables -A FORWARD -i awg-split-in -o awg0 -j ACCEPT", s)

    def test_entry_script_exit_all_blanket(self):
        # exit-all: RU-исключения нет — blanket-форма (зеркало каскада)
        from chimera.modules.awg_split_direction import (
            split_build_entry_routing_script)
        s = split_build_entry_routing_script(ru_excl="", b4_excl="")
        self.assertIn("-i awg0 -j MARK --set-mark 33794", s)

    def test_exit_script_connmark_return(self):
        from chimera.modules.awg_split_direction import (
            split_build_exit_routing_script)
        s = split_build_exit_routing_script()
        # connmark save при входе из out-плеча (первый пакет флоу)
        self.assertIn(
            "-i awg-split-out -m conntrack --ctstate NEW -j CONNMARK "
            "--set-mark 33795", s)
        # restore для ответов из WAN — МАРКА ДО route decision
        self.assertIn(
            "-m connmark --mark 33795 -j CONNMARK --restore-mark", s)
        # policy routing возврата: table 2403 → in-плечо
        self.assertIn(
            "ip route replace default dev awg-split-in table 2403", s)
        self.assertIn("fwmark 33795 lookup 2403", s)
        # NAT: транзит уходит в WAN с адресом exit
        self.assertIn(
            "-t nat -A POSTROUTING -o awg-split-out -j MASQUERADE", s)
        # идемпотентность
        self.assertIn("-C FORWARD", s)

    def test_marks_do_not_collide_with_cascade_and_lb(self):
        # каскад 0x8200(=33280), LB 0x8201..0x8210(=33281..33296):
        # split-марки обязаны быть вне этого диапазона
        from chimera.modules.awg_constants import (
            AWGS_SPLIT_FWMARK_OUT, AWGS_SPLIT_FWMARK_IN,
            AWGS_CASCADE_FWMARK)
        occupied = {AWGS_CASCADE_FWMARK} | {AWGS_CASCADE_FWMARK | s
                                            for s in range(1, 17)}
        self.assertNotIn(AWGS_SPLIT_FWMARK_OUT, occupied)
        self.assertNotIn(AWGS_SPLIT_FWMARK_IN, occupied)
        # b4-exempt бит сохранён (0x8000)
        for mark in (AWGS_SPLIT_FWMARK_OUT, AWGS_SPLIT_FWMARK_IN):
            self.assertTrue(mark & 0x8000)


# ── 3. Валидация бокса ──────────────────────────────────────────────────────

class TestBoxValidate(_SplitTestBase):
    def test_valid_box(self):
        self._write_state(self._entry_state())
        ok, reason = self.sd.split_box_validate(_box())
        self.assertTrue(ok, reason)

    def test_missing_fields(self):
        self._write_state(self._entry_state())
        for field in ("server_pubkey_out", "peer_privkey_in"):
            bad = _box()
            bad[field] = ""
            ok, reason = self.sd.split_box_validate(bad)
            self.assertFalse(ok)
            self.assertIn(field, reason)

    def test_same_ports_rejected(self):
        self._write_state(self._entry_state())
        ok, reason = self.sd.split_box_validate(_box(port_in=52840))
        self.assertFalse(ok)
        self.assertIn("различаться", reason)

    def test_port_out_of_range(self):
        self._write_state(self._entry_state())
        ok, reason = self.sd.split_box_validate(_box(port_out=70000))
        self.assertFalse(ok)

    def test_protocol_version_mismatch(self):
        st = self._entry_state()
        st["protocol_version"] = "2.0"
        self._write_state(st)
        ok, reason = self.sd.split_box_validate(_box(protocol_version="3.1"))
        self.assertFalse(ok)
        self.assertIn("не совпадают", reason)

    def test_subnet_collision_awg0(self):
        st = self._entry_state()
        st["subnet"] = "172.16.62.0/24"   # совпала с out-плечом
        self._write_state(st)
        ok, reason = self.sd.split_box_validate(_box())
        self.assertFalse(ok)
        self.assertIn("совпадает", reason)

    def test_subnet_collision_cascade_link(self):
        st = self._entry_state()
        st["cascade_subnet"] = "172.16.63.0/24"   # совпала с in-плечом
        self._write_state(st)
        ok, reason = self.sd.split_box_validate(_box())
        self.assertFalse(ok)
        self.assertIn("каскадного линка", reason)

    def test_params_required(self):
        self._write_state(self._entry_state())
        bad = _box()
        bad["params"] = {}
        ok, reason = self.sd.split_box_validate(bad)
        self.assertFalse(ok)
        self.assertIn("Обфускация", reason)


# ── 4. Включение: лестница безопасности ─────────────────────────────────────

class TestSetupEntry(_SplitTestBase):
    def _run_ok(self, *_a, **_kw):
        r = MagicMock()
        r.returncode = 0
        r.stdout = _awg_show()
        r.stderr = ""
        return r

    def test_happy_path(self):
        self._write_state(self._entry_state())
        # systemctl restart → rc 0; awg show обоих плеч → handshake жив;
        # e2e ping → ok; apply → юнит rc 0
        self.mock_core._run = MagicMock(side_effect=self._run_ok)
        with patch.object(self.sd, "split_e2e_probe",
                          return_value={"ok": True, "loss_pct": 0,
                                        "supported": True}) as e2e, \
             patch.object(self.sd, "split_apply_entry",
                          return_value=True) as apply:
            ok = self.sd.split_setup_entry(_box())
        self.assertTrue(ok)
        e2e.assert_called_once()
        apply.assert_called_once()
        # state зафиксирован
        st = self._read_state()
        self.assertTrue(st["split_direction"]["enabled"])
        self.assertEqual(st["split_direction"]["port_out"], 52840)
        # конфиги записаны
        self.assertTrue((self._conf_dir / "awg-split-out.conf").exists())
        self.assertTrue((self._conf_dir / "awg-split-in.conf").exists())

    def test_handshake_never_came_rollback_no_transit(self):
        """Провал handshake → туннели стоп, транзит НЕ переключался."""
        import time as _t
        self._write_state(self._entry_state())

        def _dead_show(*_a, **_kw):
            r = MagicMock()
            r.returncode = 0
            r.stdout = _awg_show_none()   # handshake нет
            r.stderr = ""
            return r

        self.mock_core._run = MagicMock(side_effect=_dead_show)
        with patch.object(self.sd, "split_apply_entry") as apply, \
             patch.object(self.sd, "split_tunnels_stop") as stop, \
             patch.object(self.sd, "AWGS_SPLIT_PROBE_SEC", 1):
            ok = self.sd.split_setup_entry(_box())
        self.assertFalse(ok)
        apply.assert_not_called()      # транзит не переключался
        stop.assert_called()
        st = self._read_state()
        self.assertNotIn("split_direction", st)

    def test_e2e_failed_rollback_no_transit(self):
        """E2E не прошёл → откат: туннели стоп, штатный awg1 не тронут."""
        self._write_state(self._entry_state())
        self.mock_core._run = MagicMock(side_effect=self._run_ok)
        with patch.object(self.sd, "split_e2e_probe",
                          return_value={"ok": False, "loss_pct": 100,
                                        "supported": True}), \
             patch.object(self.sd, "split_apply_entry") as apply, \
             patch.object(self.sd, "split_tunnels_stop") as stop:
            ok = self.sd.split_setup_entry(_box())
        self.assertFalse(ok)
        apply.assert_not_called()
        stop.assert_called()

    def test_requires_entry_role(self):
        st = self._entry_state()
        st["cascade_role"] = "exit"
        self._write_state(st)
        self.assertFalse(self.sd.split_setup_entry(_box()))

    def test_requires_cascade(self):
        st = self._entry_state()
        st.pop("cascade_peer_host")
        self._write_state(st)
        self.assertFalse(self.sd.split_setup_entry(_box()))


# ── 5. Выключение ───────────────────────────────────────────────────────────

class TestSplitOff(_SplitTestBase):
    def test_off_removes_marks_and_restores_cascade(self):
        self._write_state(self._entry_state(split={
            "enabled": True, "endpoint": "203.0.113.107",
            "port_out": 52840, "port_in": 52841,
        }))
        self.assertTrue(self.sd.split_off(reason="тест", auto=True))
        commands = []
        for call in self.mock_core._run.call_args_list:
            cmd = call[0][0]
            commands.append(" ".join(str(c) for c in cmd))
        joined = "\n".join(commands)
        # снос split-марок и правил
        self.assertIn("--set-mark 33794 2>/dev/null; do :; done", joined)
        self.assertIn("fwmark 33794 lookup 2402", joined)
        self.assertIn("ip route flush table 2402", joined)
        # возврат транзита штатному каскаду
        self.assertIn("restart awg-cascade-routing", joined)
        # стоп туннелей плеч
        self.assertIn("disable --now awg-quick@awg-split-out", joined)
        # state: выключен
        st = self._read_state()
        self.assertFalse(st["split_direction"]["enabled"])
        self.assertEqual(st["split_direction"]["disabled_reason"], "тест")


# ── 6. Health-тик: таблица решений ──────────────────────────────────────────

class TestHealthTick(_SplitTestBase):
    def _split_on_state(self, fail_count=0, last_e2e_ts=None):
        return self._entry_state(split={
            "enabled": True, "endpoint": "203.0.113.107",
            "port_out": 52840, "port_in": 52841,
            "protocol_version": "3.1", "params": dict(_PARAMS_31),
            "probe_host": "1.1.1.1", "fail_count": fail_count,
            "last_e2e": ({"ok": True, "ts": last_e2e_ts}
                         if last_e2e_ts else {}),
        })

    def _probe_alive(self, *ifaces):
        def _f(iface, **_kw):
            if iface in ifaces:
                return {"up": True, "handshake_age": 10, "tx": 1, "rx": 1}
            return {"up": True, "handshake_age": None, "tx": 0, "rx": 0}
        return _f

    def test_off_when_disabled(self):
        self._write_state(self._entry_state())
        self.assertEqual(self.sd.split_health_tick(), "off")

    def test_ok_with_fresh_e2e_cooldown(self):
        # e2e недавно прошёл → кулдаун, дешёвый ok без пинга
        from datetime import datetime, timezone, timedelta
        ts = (datetime.now(timezone.utc)
              - timedelta(seconds=30)).isoformat()
        self._write_state(self._split_on_state(last_e2e_ts=ts))
        with patch.object(self.sd, "split_iface_probe",
                          side_effect=self._probe_alive(
                              "awg-split-out", "awg-split-in")), \
             patch.object(self.sd, "split_e2e_probe") as e2e:
            self.assertEqual(self.sd.split_health_tick(), "ok")
        e2e.assert_not_called()   # кулдаун работает

    def test_ok_e2e_after_cooldown(self):
        from datetime import datetime, timezone, timedelta
        ts = (datetime.now(timezone.utc)
              - timedelta(seconds=600)).isoformat()
        self._write_state(self._split_on_state(last_e2e_ts=ts))
        with patch.object(self.sd, "split_iface_probe",
                          side_effect=self._probe_alive(
                              "awg-split-out", "awg-split-in")), \
             patch.object(self.sd, "split_e2e_probe",
                          return_value={"ok": True, "loss_pct": 0,
                                        "supported": True}):
            self.assertEqual(self.sd.split_health_tick(), "ok:e2e")

    def test_e2e_dead_restarts_both(self):
        # handshake жив, но e2e валится → рестарт обоих плеч
        from datetime import datetime, timezone, timedelta
        ts = (datetime.now(timezone.utc)
              - timedelta(seconds=600)).isoformat()
        self._write_state(self._split_on_state(last_e2e_ts=ts))
        with patch.object(self.sd, "split_iface_probe",
                          side_effect=self._probe_alive(
                              "awg-split-out", "awg-split-in")), \
             patch.object(self.sd, "split_e2e_probe",
                          return_value={"ok": False, "loss_pct": 100,
                                        "supported": True}), \
             patch.object(self.sd, "split_restart_tunnel") as restart, \
             patch.object(self.sd, "_time_sleep", lambda s: None):
            result = self.sd.split_health_tick()
        self.assertEqual(result, "both-dead:e2e-restart")
        self.assertEqual(restart.call_count, 2)

    def test_recovered_after_restart(self):
        # одно плечо мертво → рестарт → ожило
        self._write_state(self._split_on_state())
        probes = [
            {"up": True, "handshake_age": 10, "tx": 1, "rx": 1},   # out до
            {"up": True, "handshake_age": None, "tx": 0, "rx": 0},  # in до
            {"up": True, "handshake_age": 10, "tx": 1, "rx": 1},   # out после
            {"up": True, "handshake_age": 12, "tx": 1, "rx": 1},   # in после
        ]
        with patch.object(self.sd, "split_iface_probe",
                          side_effect=probes), \
             patch.object(self.sd, "split_restart_tunnel"), \
             patch.object(self.sd, "_time_sleep", lambda s: None):
            result = self.sd.split_health_tick()
        self.assertEqual(result, "recovered")

    def test_rollback_after_fail_limit(self):
        # оба плеча мертвы N тиков подряд → авто-откат на штатный awg1
        from chimera.modules.awg_constants import AWGS_SPLIT_FAIL_LIMIT
        self._write_state(self._split_on_state(
            fail_count=AWGS_SPLIT_FAIL_LIMIT - 1))
        dead = {"up": True, "handshake_age": None, "tx": 0, "rx": 0}
        with patch.object(self.sd, "split_iface_probe",
                          return_value=dead), \
             patch.object(self.sd, "split_restart_tunnel"), \
             patch.object(self.sd, "_time_sleep", lambda s: None), \
             patch.object(self.sd, "split_off", return_value=True) as off:
            result = self.sd.split_health_tick()
        self.assertEqual(result, "rollback")
        off.assert_called_once()
        self.assertTrue(off.call_args[1].get("auto"))

    def test_pending_before_limit(self):
        # первая неудача ещё не откат (копим fail_count)
        self._write_state(self._split_on_state(fail_count=0))
        dead = {"up": True, "handshake_age": None, "tx": 0, "rx": 0}
        with patch.object(self.sd, "split_iface_probe",
                          return_value=dead), \
             patch.object(self.sd, "split_restart_tunnel"), \
             patch.object(self.sd, "_time_sleep", lambda s: None), \
             patch.object(self.sd, "split_off") as off:
            result = self.sd.split_health_tick()
        self.assertTrue(result.startswith("both-dead:pending-"))
        off.assert_not_called()
        st = self._read_state()
        self.assertEqual(st["split_direction"]["fail_count"], 1)


# ── 7. Watchdog setup/teardown ──────────────────────────────────────────────

class TestWatchdog(_SplitTestBase):
    def test_setup_creates_units_and_wrapper(self):
        # is-active после enable --now обязан ответить active
        def _run(cmd, **_kw):
            r = MagicMock()
            r.returncode = 0
            r.stderr = ""
            if cmd[:2] == ["systemctl", "is-active"]:
                r.stdout = "active\n"
            else:
                r.stdout = ""
            return r

        self.mock_core._run = MagicMock(side_effect=_run)
        self.assertTrue(self.sd.split_watchdog_setup())
        wrapper = (self._scripts_dir / "awg-split-direction.sh").read_text()
        self.assertIn("split_health_tick", wrapper)
        self.assertIn("PYTHONPATH", wrapper)   # PYTHONPATH-safe канон
        svc = (self._units_dir / "awg-split-direction.service").read_text()
        self.assertIn("awg-split-direction.sh", svc)
        timer = (self._units_dir / "awg-split-direction.timer").read_text()
        self.assertIn("*:0/1", timer)          # каждую минуту

    def test_teardown_removes_units(self):
        self.sd.split_watchdog_teardown()
        self.assertFalse(
            (self._units_dir / "awg-split-direction.timer").exists())
        self.assertFalse(
            (self._units_dir / "awg-split-direction.service").exists())
        self.assertFalse(
            (self._scripts_dir / "awg-split-direction.sh").exists())


# ── 8. Интеграция с awg_cascade ─────────────────────────────────────────────

class TestCascadeIntegration(_SplitTestBase):
    def test_activate_exit_refuses_when_split_on(self):
        """Переключение exit при активном split — честный отказ
        (плечи привязаны к endpoint конкретного exit)."""
        from chimera.modules import awg_cascade
        self._write_state(self._entry_state(split={
            "enabled": True, "endpoint": "203.0.113.107",
            "port_out": 52840, "port_in": 52841,
        }))
        with patch.object(awg_cascade, "_core_module",
                          return_value=self.mock_core), \
             patch.object(awg_cascade, "_awgs_cascade_exits_load",
                          return_value=[
                              {"name": "de", "endpoint": "203.0.113.50",
                               "port": 52831, "subnet": "172.16.91.0/24",
                               "protocol_version": "3.1",
                               "params": dict(_PARAMS_31)},
                          ]), \
             patch.object(awg_cascade, "AWGS_AWG1_CONF",
                          self._tmpdir / "awg1.conf"), \
             patch.object(awg_cascade, "_awgs_cascade_create_routing_script"):
            ok = awg_cascade.awgs_cascade_activate_exit("de")
        self.assertFalse(ok)

    def test_split_is_on_reads_state(self):
        self._write_state(self._entry_state(split={
            "enabled": True, "endpoint": "x", "port_out": 1, "port_in": 2}))
        self.assertTrue(self.sd.split_is_on())
        self._write_state(self._entry_state())
        self.assertFalse(self.sd.split_is_on())


if __name__ == "__main__":
    unittest.main()
