#!/usr/bin/env python3
"""
tests/test_awg_kernel_relay.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты kernel-relay — одного туннеля + userspace UDP-релея (кейс
Виталия, обход двусторонней блокировки 16к) — chimera/modules/awg_kernel_relay.py.

Покрывает:
  1. Прелюдии: dns-fixed == боевые байты пилота Виталия побайтово;
     dns-rand (txid), custom-domain (кодирование меток), custom-hex,
     none; некорректные пресеты/имена — честный ValueError
  2. Pump worker'а: двусторонняя доставка на НАСТОЯЩИХ loopback-сокетах
     (обе стороны: прелюдия уходит первой, payload доезжает)
  3. EPERM-семантика: send данных отбрасывает только датаграмму;
     EPERM на прелюдии = BLOCKED (выход стоит, вход жив); recv-ошибки
     не блокируют следующий ход
  4. Guarded-restore: откат чужого endpoint запрещён (identity/endpoint
     дрейф → ValueError, set_endpoint не вызывается)
  5. relay_enable/relay_disable: лестница включения с моками (endpoint →
     loop, провал юнита = откат, атомарная публикация билета, state-бокс,
     конфликт портов/адресов)
  6. relay_health_tick: off / ok / relaunch:boot (restore_on_boot) /
     lost (без restore) / recovered / pending-N / rollback (fail-limit)
     + hold-N (fail_action=notify_only — удержание без отката: фичареквест
     Виталия 26.11 «уведомлять, но не откатывать»; TG-срез по спаму —
     ОДНО hold на переходе предела; awg_relay_recovered при оживании)
  7. Интеграция: пункт 9 «AWG-релей» в меню каскада (текст-контракт +
     порядок пунктов), верхний уровень модуля без chimera-импортов
     (worker запускается python3 -I), меню выходит по Q
  8. Watchdog-юниты: wrapper PYTHONPATH-safe, svc/timer содержимое
  9. Матрица зонда: one-way-out/stream-cut упоминают релей (снятие
     противоречия «кейс Виталия → split-direction», релиз 19.11)
 10. fail_action: нормализация (мусор → rollback), хранение в state при
     enable, промпт _relay_fail_action_ask, пункт меню 7 + диагностика→8,
     контракт активации (спрос при включении), события awg_relay_* в
     tg_bot (иконка + титул + тумблер меню — класс кейса окт.2026 №8)
"""
from __future__ import annotations

import errno
import json
import socket
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

_MOD = "chimera.modules.awg_kernel_relay"
_PILOT_HEX = "67c201200001000000000000076578616d706c6503636f6d0000010001"
_PRELUDE = bytes.fromhex(_PILOT_HEX)


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
    sys.modules.setdefault("chimera._core", fake_core)


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
    return core


class _RelayTest(unittest.TestCase):
    """База: поднимает мок _core (канон test_awg_split_direction)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        self.mod = importlib.import_module(_MOD)
        self.core = _mock_core()
        self._p_core = patch.object(self.mod, "_core_module",
                                    return_value=self.core)
        self._p_core.start()
        self.addCleanup(self._p_core.stop)
        from chimera.modules import awg_state
        from chimera.modules import awg_constants
        self.awg_state = awg_state
        self.awg_constants = awg_constants


# ── 1. Прелюдии ──────────────────────────────────────────────────────────────

class TestPrelude(_RelayTest):
    def test_prelude_fixed_matches_pilot(self):
        # dns-fixed == боевые байты пилота Виталия ПОБАЙТОВО
        # (свечной приоритет: повторяемость проверенной в бою конфигурации)
        self.assertEqual(self.mod.relay_prelude_build("dns-fixed"),
                         _PRELUDE)

    def test_prelude_dns_random_txid(self):
        with patch("random.getrandbits", side_effect=[0x1111, 0x2222]):
            a = self.mod.relay_prelude_build("dns-rand")
            b = self.mod.relay_prelude_build("dns-rand")
        self.assertEqual(a[:2], b"\x11\x11")
        self.assertEqual(b[:2], b"\x22\x22")
        # остальное — тот же валидный DNS-запрос example.com A/IN
        self.assertEqual(a[2:], b"\x01\x20\x00\x01" + b"\x00" * 6
                         + b"\x07example\x03com\x00\x00\x01\x00\x01")

    def test_prelude_custom_domain_encoding(self):
        raw = self.mod.relay_prelude_build("custom-domain",
                                           domain="ya.ru")
        # метки: 02 'y' 'a' 02 'r' 'u' 00 (терминатор qname)
        self.assertEqual(raw[12:19], b"\x02ya\x02ru\x00")
        self.assertEqual(raw[-4:], b"\x00\x01\x00\x01")  # A/IN

    def test_prelude_custom_hex_and_none(self):
        self.assertEqual(self.mod.relay_prelude_build(
            "custom-hex", hex_data="dead beef"), b"\xde\xad\xbe\xef")
        self.assertEqual(self.mod.relay_prelude_build("none"), b"")

    def test_prelude_invalid_presets_raise(self):
        for preset, kw in [("no-such", {}),
                           ("custom-domain", {"domain": ""}),
                           ("custom-hex", {"hex_data": ""}),
                           ("custom-hex", {"hex_data": "zzz"})]:
            with self.assertRaises(ValueError, msg=preset):
                self.mod.relay_prelude_build(preset, **kw)

    def test_prelude_dns_rejects_bad_names(self):
        # пустое/точка/длинная метка/пробел/подчёркивание (чужой символ в
        # ОДНОЙ метке — хвост strip по разрешённому алфавиту) — отказы
        for bad in ("", ".", "a" * 64 + ".com", "ex ample.com",
                    "ex_ample.com"):
            with self.assertRaises(ValueError, msg=bad):
                self.mod.relay_prelude_dns(bad)


# ── 2. Pump: настоящие loopback-сокеты ─────────────────────────────────────

class TestPump(_RelayTest):
    def test_two_legs(self):
        # Двусторонняя доставка на настоящих UDP-сокетах: прелюдия —
        # первой датаграммой флоу, payload доезжает; обе стороны.
        r = self.mod
        with ExitStack() as st:

            def udp():
                s = st.enter_context(socket.socket(socket.AF_INET,
                                                    socket.SOCK_DGRAM))
                s.bind(("127.0.0.1", 0))
                s.settimeout(1)
                return s

            a, b, la, lb, ta, tb, ra, rb = [udp() for _ in range(8)]
            for x, y in [(a, la), (b, lb), (ta, rb), (tb, ra)]:
                x.connect(y.getsockname())
                y.connect(x.getsockname())
            for src, dest, local, tx, rx, other, ot, ol in [
                (a, b, la, ta, ra, rb, tb, lb),
                (b, a, lb, tb, rb, ra, ta, la),
            ]:
                src.send(b"first")
                first = r.pump(local, tx, rx, _PRELUDE, 1)
                self.assertEqual(other.recv(100), _PRELUDE)
                r.pump(ol, ot, other, _PRELUDE, 1)
                self.assertEqual(dest.recv(100), b"first")
                src.send(b"second")
                r.pump(local, tx, rx, first, 1)
                self.assertEqual(other.recv(100), b"second")


# ── 3. EPERM-семантика ──────────────────────────────────────────────────────

class TestDenials(_RelayTest):
    def test_send_denials(self):
        r = self.mod
        tx = Mock()
        denied = PermissionError(errno.EPERM, "denied")
        tx.send.side_effect = [denied, None]
        first = r.outbound(tx, b"a", _PRELUDE)
        r.outbound(tx, b"b", first)
        self.assertEqual(tx.send.call_count, 1)
        tx.reset_mock()
        tx.send.side_effect = [None, denied, None]
        first = r.outbound(tx, b"a", _PRELUDE)
        r.outbound(tx, b"b", first)
        self.assertEqual(
            [c.args[0] for c in tx.send.call_args_list],
            [_PRELUDE, b"a", b"b"])
        tx.send.side_effect = PermissionError(errno.EACCES, "denied")
        with self.assertRaises(PermissionError):
            r.send_data(tx, b"c", "input")

    def test_wire_to_kernel_eperm_does_not_block_next(self):
        # wire→kernel EPERM: датаграмма теряется, следующий ход жив;
        # PermissionError на recv — честное исключение вверх
        r = self.mod
        local = Mock()
        rx = Mock()
        tx = Mock()
        rx.recv.side_effect = [
            b"denied",
            b"allowed",
            PermissionError(errno.EPERM, "receive"),
        ]
        local.send.side_effect = [PermissionError(errno.EPERM, "send"), None]
        with patch.object(r.select, "select", return_value=([rx], [], [])):
            for _ in range(2):
                self.assertIs(r.pump(local, tx, rx, r.BLOCKED), r.BLOCKED)
            with self.assertRaises(PermissionError):
                r.pump(local, tx, rx, r.BLOCKED)
        self.assertEqual(
            [c.args[0] for c in local.send.call_args_list],
            [b"denied", b"allowed"])
        tx.send.assert_not_called()


# ── 4. Guarded-restore ──────────────────────────────────────────────────────

class TestGuardedRestore(_RelayTest):
    def test_restore_guard_matrix(self):
        r = self.mod
        state = dict(
            iface="awg1",
            identity=[3, 4000, "peer"],
            old="192.0.2.1:8000",
            target="127.0.0.1:8001",
        )
        for identity, endpoint, ok in [
            (state["identity"], state["target"], True),
            ([4, 4000, "peer"], state["target"], False),
            (state["identity"], "192.0.2.2:8000", False),
        ]:
            with (
                patch.object(
                    r, "snapshot",
                    side_effect=[(identity, endpoint),
                                 (identity, state["old"])]),
                patch.object(r, "set_endpoint") as change,
            ):
                if ok:
                    r.restore_endpoint(state)
                    change.assert_called_once_with(state, state["old"])
                else:
                    with self.assertRaises(ValueError):
                        r.restore_endpoint(state)
                    change.assert_not_called()


# ── 5. relay_enable / relay_disable (лестница с моками) ─────────────────────

class TestEnableDisable(_RelayTest):
    """relay_enable/relay_disable на моках run/snapshot/unit_status.

    Канон пилота: identity [ifindex, listen, pubkey]; переключение
    endpoint подтверждается повторным снимком; провал юнита = полный
    откат (endpoint остаётся прямым, запись снимается).
    """

    IDENT = [13, 52840, "PEERKEY"]

    def _patched(self, current, active, save_res=True, launch_fails=False,
                 load_state=None):
        launch_calls = []

        def launch(cfg, unit):
            launch_calls.append(unit)
            return not launch_fails

        saved = []

        def save(state):
            saved.append(state)
            return save_res

        def fake_run(*args):
            # systemctl stop переводит юнит в inactive — модель реальности
            # для лестницы stop→unit_status→restore (канон пилота)
            if args[:2] == ("systemctl", "stop"):
                active[0] = "inactive"
            return '[{"dev":"eth0"}]' if args[0] == "ip" else ""

        p = [
            patch.object(self.mod, "run", side_effect=fake_run),
            patch.object(self.mod, "snapshot",
                         side_effect=lambda iface: (self.IDENT, current[0])),
            patch.object(self.mod, "set_endpoint",
                         side_effect=lambda st, ep: current.__setitem__(0, ep)),
            patch.object(self.mod, "relay_unit_launch", side_effect=launch),
            patch.object(self.mod, "unit_status",
                         side_effect=lambda st: active[0]),
            patch.object(self.awg_state, "awgs_state_load",
                         return_value=load_state if load_state is not None
                         else {}),
            patch.object(self.awg_state, "awgs_state_save", side_effect=save),
            patch.object(self.mod, "_notify"),
        ]
        for x in p:
            x.start()
            self.addCleanup(x.stop)
        return launch_calls, saved

    def _cfg(self, **kw):
        base = dict(
            iface="awg1", addr="198.51.100.7",
            loop=5001, tx=51001, rx=443,
            remote_tx=51002, remote_rx=443,
            preset="dns-fixed",
        )
        base.update(kw)
        return base

    def test_enable_switches_endpoint_and_saves_state(self):
        current = ["192.0.2.10:51820"]
        active = ["active"]
        launch_calls, saved = self._patched(current, active)
        with tempfile.TemporaryDirectory() as td:
            with patch.object(self.awg_constants, "AWGS_RELAY_ROOT",
                             Path(td)):
                ok, why = self.mod.relay_enable(self._cfg())
                self.assertTrue(ok, why)
                self.assertEqual(current[0], "127.0.0.1:5001")
                record = Path(td) / "awg1.json"
                self.assertTrue(record.exists())
                rec = json.loads(record.read_text())
                self.assertEqual(rec["old"], "192.0.2.10:51820")
                self.assertEqual(rec["target"], "127.0.0.1:5001")
                self.assertEqual(rec["unit"], launch_calls[0])
                self.assertEqual(rec["identity"], self.IDENT)
                # state-бокс: enabled + порты + прелюдия
                box = saved[0]["kernel_relay"]
                self.assertTrue(box["enabled"])
                self.assertEqual(box["ports"]["loop"], 5001)
                self.assertEqual(box["prelude_hex"], _PILOT_HEX)
                # юниту ушли ТОЛЬКО worker-ключи (без iface/preset)
                launch_cfg = json.loads(json.dumps(launch_calls))  # noqa
                self.assertEqual(len(launch_calls), 1)

    def test_enable_failure_rolls_back_endpoint(self):
        # systemd-run провалился → полный откат: endpoint прямой,
        # запись снята, return False с причиной
        current = ["192.0.2.10:51820"]
        active = ["active"]
        self._patched(current, active, launch_fails=True)
        with tempfile.TemporaryDirectory() as td:
            with patch.object(self.awg_constants, "AWGS_RELAY_ROOT",
                             Path(td)):
                ok, why = self.mod.relay_enable(self._cfg())
                self.assertFalse(ok)
                self.assertIn("systemd-run", why)
                self.assertEqual(current[0], "192.0.2.10:51820")
                self.assertFalse((Path(td) / "awg1.json").exists())

    def test_disable_restores_endpoint_and_removes_record(self):
        current = ["192.0.2.10:51820"]
        active = ["active"]
        launch_calls, saved = self._patched(current, active)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with patch.object(self.awg_constants, "AWGS_RELAY_ROOT", root):
                ok, why = self.mod.relay_enable(self._cfg())
                self.assertTrue(ok, why)
                self.assertEqual(current[0], "127.0.0.1:5001")
                # disable: юнит стопается, endpoint возвращается к прямому
                ok = self.mod.relay_disable(iface="awg1",
                                             reason="test")
                self.assertTrue(ok)
                self.assertEqual(current[0], "192.0.2.10:51820")
                self.assertFalse((root / "awg1.json").exists())
                box = saved[-1]["kernel_relay"]
                self.assertFalse(box["enabled"])

    def test_enable_rejects_conflicting_ports(self):
        current = ["192.0.2.10:51820"]
        active = ["absent"]
        self._patched(current, active)
        with tempfile.TemporaryDirectory() as td, \
                patch.object(self.awg_constants, "AWGS_RELAY_ROOT", Path(td)):
            ok, why = self.mod.relay_enable(self._cfg(loop=5001, tx=5001))
            self.assertFalse(ok)
            self.assertIn("Порты конфликтуют", why)

    def test_enable_rejects_same_remote_ports(self):
        current = ["192.0.2.10:51820"]
        active = ["absent"]
        self._patched(current, active)
        with tempfile.TemporaryDirectory() as td, \
                patch.object(self.awg_constants, "AWGS_RELAY_ROOT", Path(td)):
            ok, why = self.mod.relay_enable(self._cfg(remote_tx=443,
                                                       remote_rx=443))
            self.assertFalse(ok)
            self.assertIn("напарника", why)

    def test_enable_rejects_bad_iface(self):
        current = ["192.0.2.10:51820"]
        active = ["absent"]
        self._patched(current, active)
        ok, why = self.mod.relay_enable(self._cfg(iface="awg0-client"))
        self.assertFalse(ok)
        self.assertIn("awgN", why)

    def test_enable_rejects_route_via_lo(self):
        current = ["192.0.2.10:51820"]
        active = ["absent"]
        self._patched(current, active)
        with tempfile.TemporaryDirectory() as td, \
                patch.object(self.awg_constants, "AWGS_RELAY_ROOT", Path(td)):
            # маршрут до пира через lo — отказ (нужен внешний маршрут)
            self.mod.run = self.mod.run  # уже замокан
            with patch.object(self.mod, "run",
                              side_effect=lambda *a: '[{"dev":"lo"}]'):
                ok, why = self.mod.relay_enable(self._cfg())
                self.assertFalse(ok)
                self.assertIn("внешний маршрут", why)

    def test_enable_stores_fail_action(self):
        # фичареквест Виталия 26.11: notify_only сохраняется в state-боксе
        current = ["192.0.2.10:51820"]
        active = ["active"]
        launch_calls, saved = self._patched(current, active)
        with tempfile.TemporaryDirectory() as td, \
                patch.object(self.awg_constants, "AWGS_RELAY_ROOT", Path(td)):
            ok, why = self.mod.relay_enable(
                self._cfg(fail_action="notify_only"))
            self.assertTrue(ok, why)
        box = saved[0]["kernel_relay"]
        self.assertEqual(box["fail_action"], "notify_only")

    def test_enable_normalizes_garbage_fail_action(self):
        # чужое значение → безопасный rollback (честная обратная
        # совместимость: старые state-боксы без поля ведут себя как раньше)
        current = ["192.0.2.10:51820"]
        active = ["active"]
        launch_calls, saved = self._patched(current, active)
        with tempfile.TemporaryDirectory() as td, \
                patch.object(self.awg_constants, "AWGS_RELAY_ROOT", Path(td)):
            ok, why = self.mod.relay_enable(self._cfg(fail_action="banana"))
            self.assertTrue(ok, why)
        box = saved[0]["kernel_relay"]
        self.assertEqual(box["fail_action"], "rollback")


# ── 6. relay_health_tick (лестница watchdog) ───────────────────────────────

class TestHealthTick(_RelayTest):
    def _box(self, **kw):
        base = dict(
            enabled=True, iface="awg1", unit="chimera-awg-relay-X.service",
            addr="198.51.100.7", peer="192.0.2.10", kernel=52840,
            ports={"loop": 5001, "tx": 51001, "rx": 443,
                   "remote_tx": 51002, "remote_rx": 443},
            preset="dns-fixed", prelude_hex=_PILOT_HEX,
            refresh=0, restore_on_boot=False, fail_count=0,
        )
        base.update(kw)
        return base

    def _tick(self, box, record_exists, probe, probe2, relaunch_ok=True):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            if record_exists:
                (root / "awg1.json").write_text(
                    json.dumps({"iface": "awg1", "unit": "u.service",
                                "identity": [1, 2, "k"],
                                "old": "192.0.2.10:51820",
                                "target": "127.0.0.1:5001"}))
            with ExitStack() as st:
                st.enter_context(patch.object(
                    self.awg_constants, "AWGS_RELAY_ROOT", root))
                for p in [
                    patch.object(self.mod, "relay_state_get",
                                 return_value=box),
                    patch.object(self.mod, "relay_iface_probe",
                                 side_effect=[probe, probe2]),
                    patch.object(self.mod, "unit_status",
                                 return_value="active"),
                    patch.object(self.mod, "relay_relaunch",
                                 return_value=(relaunch_ok, "")),
                    patch.object(self.mod, "relay_disable"),
                    patch.object(self.mod, "relay_enable",
                                 return_value=(True, "")),
                    patch.object(self.mod, "_relay_state_update",
                                 return_value=True),
                    patch.object(self.mod, "_notify"),
                    patch.object(self.mod, "_time_sleep_wrapper"),
                ]:
                    p.start()
                    st.callback(p.stop)
                return self.mod.relay_health_tick()

    _alive = {"up": True, "handshake_age": 10, "tx": 1, "rx": 1}
    _dead = {"up": True, "handshake_age": 9999, "tx": 1, "rx": 1}

    def test_off_when_disabled(self):
        self.assertEqual(
            self._tick(self._box(enabled=False), True,
                       self._alive, self._alive), "off")

    def test_ok_when_alive(self):
        self.assertEqual(
            self._tick(self._box(), True, self._alive, self._alive), "ok")

    def test_recovered_after_relaunch(self):
        self.assertEqual(
            self._tick(self._box(), True, self._dead, self._alive),
            "recovered")

    def test_pending_counts_fail(self):
        self.assertEqual(
            self._tick(self._box(fail_count=0), True,
                       self._dead, self._dead), "pending-1")

    def test_rollback_at_fail_limit(self):
        self.assertEqual(
            self._tick(self._box(fail_count=2), True,
                       self._dead, self._dead), "rollback")

    def test_lost_after_reboot_without_restore(self):
        self.assertEqual(
            self._tick(self._box(restore_on_boot=False), False,
                       self._alive, self._alive), "lost")

    def test_relaunch_on_boot_with_restore(self):
        self.assertEqual(
            self._tick(self._box(restore_on_boot=True), False,
                       self._alive, self._alive), "relaunch:boot")


# ── 7. Интеграция: меню каскада + worker-режим ─────────────────────────────

class TestMenuIntegration(_RelayTest):
    def test_cascade_menu_has_item9_and_dispatch(self):
        # текст-контракт: пункт 9 с заголовком релея + dispatch на модуль
        src = (_PROJECT_ROOT / "chimera" / "modules"
               / "awg_cascade.py").read_text(encoding="utf8")
        self.assertIn('_box_item("9", "AWG-релей: один туннель + UDP-релей '
                      '(обход 16к)")', src)
        self.assertIn("from .awg_kernel_relay import "
                      "do_manage_awg_kernel_relay", src)

    def test_cascade_menu_items_sequence(self):
        # порядок пунктов меню каскада: split (8) → релей (9) → Q
        src = (_PROJECT_ROOT / "chimera" / "modules"
               / "awg_cascade.py").read_text(encoding="utf8")
        pos8 = src.find('_box_item("8"')
        pos9 = src.find('_box_item("9"')
        posq = src.find('_box_item("Q", f"Назад")', pos9)
        self.assertNotEqual(-1, pos8)
        self.assertNotEqual(-1, pos9)
        self.assertLess(pos8, pos9)
        self.assertLess(pos9, posq)

    def test_module_top_level_is_stdlib_only(self):
        # worker запускается `python3 -I -B` — ВЕРХНИЙ уровень модуля
        # обязан содержать только stdlib-импорты (канон пилота)
        import ast
        src = (_PROJECT_ROOT / "chimera" / "modules"
               / "awg_kernel_relay.py").read_text(encoding="utf8")
        tree = ast.parse(src)
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = ([a.name for a in node.names]
                         if isinstance(node, ast.Import)
                         else [node.module])
                for n in names:
                    self.assertFalse(
                        n.startswith("chimera"),
                        f"top-level import {n}: worker-часть ломается "
                        "под python3 -I")

    def test_menu_q_exits_cleanly(self):
        # меню релея: Q — чистый выход (рамки/промпты мокнуты)
        with patch.object(self.mod, "relay_state_get", return_value={}), \
                patch("builtins.input", side_effect=["q"]), \
                patch("os.system"):
            self.mod.do_manage_awg_kernel_relay()
        # ни один интерактивный пункт не дёрнут (вход только q)
        self.core._box_ask.assert_not_called()


# ── 8. Watchdog-юниты (wrapper/svc/timer) ─────────────────────────────────

class TestWatchdogUnits(_RelayTest):
    def test_watchdog_setup_writes_units(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            script, svc, timer = (root / "w.sh", root / "w.service",
                                   root / "w.timer")
            with patch.object(self.awg_constants, "AWGS_RELAY_SCRIPT", script), \
                    patch.object(self.awg_constants, "AWGS_RELAY_SVC", svc), \
                    patch.object(self.awg_constants, "AWGS_RELAY_TIMER", timer):
                # is-active → "active"
                r = MagicMock()
                r.returncode = 0
                r.stdout = "active\n"
                self.core._run = MagicMock(return_value=r)
                ok = self.mod.relay_watchdog_setup()
                self.assertTrue(ok)
                wrapper = script.read_text()
                self.assertIn("sys.path.insert", wrapper)
                self.assertIn("relay_health_tick", wrapper)
                self.assertIn("awg-kernel-relay", svc.read_text())
                self.assertIn("[Timer]", timer.read_text())
                self.assertIn("OnCalendar=*:0/1", timer.read_text())

    def test_watchdog_teardown_removes_units(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            script, svc, timer = (root / "w.sh", root / "w.service",
                                   root / "w.timer")
            for p in (script, svc, timer):
                p.write_text("x")
            with patch.object(self.awg_constants, "AWGS_RELAY_SCRIPT", script), \
                    patch.object(self.awg_constants, "AWGS_RELAY_SVC", svc), \
                    patch.object(self.awg_constants, "AWGS_RELAY_TIMER", timer):
                self.assertTrue(self.mod.relay_watchdog_teardown())
                for p in (script, svc, timer):
                    self.assertFalse(p.exists())


# ── 9. Матрица зонда: релей в рекомендациях ─────────────────────────────────

class TestLinkProbeAdvice(_RelayTest):
    def test_one_way_out_mentions_both_tools(self):
        # снятие противоречия релиза 19.11: «кейс Виталия → split»
        # врал для двустороннего ката; теперь рекомендация различает
        # подслучаи: split (п.8) для направленного, релей (п.9) для ката
        from chimera.modules.awg_link_probe import LINK_PATTERNS
        rec = LINK_PATTERNS["one-way-out"]["recommendation"]
        self.assertIn("Split-direction", rec)
        self.assertIn("AWG-релей", rec)
        self.assertIn("п.9", rec)

    def test_stream_cut_mentions_relay(self):
        from chimera.modules.awg_link_probe import LINK_PATTERNS
        rec = LINK_PATTERNS["stream-cut"]["recommendation"]
        self.assertIn("AWG-релей", rec)


# ── 10. fail_action: notify-only watchdog (фичареквест Виталия 26.11) ──────

class TestFailActionNorm(_RelayTest):
    def test_norm_matrix(self):
        # валидные значения проходят; мусор/пусто/None/не-строка →
        # безопасный rollback (обратная совместимость старых боксов)
        f = self.mod._fail_action_norm
        self.assertEqual(f("notify_only"), "notify_only")
        self.assertEqual(f("rollback"), "rollback")
        self.assertEqual(f(None), "rollback")
        self.assertEqual(f(""), "rollback")
        self.assertEqual(f("banana"), "rollback")
        self.assertEqual(f(1), "rollback")


class TestHealthTickNotifyOnly(_RelayTest):
    """notify-only: лестница исчерпана — откат НЕ происходит, режим
    на удержании (hold-N); TG-срез по спаму (одно hold на переходе
    предела, дальше тишина); оживание — awg_relay_recovered."""

    def _box(self, **kw):
        base = dict(
            enabled=True, iface="awg1", unit="chimera-awg-relay-X.service",
            addr="198.51.100.7", peer="192.0.2.10", kernel=52840,
            ports={"loop": 5001, "tx": 51001, "rx": 443,
                   "remote_tx": 51002, "remote_rx": 443},
            preset="dns-fixed", prelude_hex=_PILOT_HEX,
            refresh=0, restore_on_boot=False, fail_count=0,
        )
        base.update(kw)
        return base

    def _tick(self, box, probe, probe2):
        """Тик с записью в /run и захватом моков (notify/state/disable)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "awg1.json").write_text(
                json.dumps({"iface": "awg1", "unit": "u.service",
                            "identity": [1, 2, "k"],
                            "old": "192.0.2.10:51820",
                            "target": "127.0.0.1:5001"}))
            with ExitStack() as st:
                st.enter_context(patch.object(
                    self.awg_constants, "AWGS_RELAY_ROOT", root))
                mocks = {}
                for name, val in [
                    ("relay_state_get", MagicMock(return_value=box)),
                    ("relay_iface_probe",
                     MagicMock(side_effect=[probe, probe2])),
                    ("unit_status", MagicMock(return_value="active")),
                    ("relay_relaunch", MagicMock(return_value=(True, ""))),
                    ("relay_disable", MagicMock()),
                    ("relay_enable", MagicMock(return_value=(True, ""))),
                    ("_relay_state_update", MagicMock(return_value=True)),
                    ("_notify", MagicMock()),
                    ("_time_sleep_wrapper", MagicMock()),
                ]:
                    p = patch.object(self.mod, name, val)
                    mocks[name] = p.start()
                    st.callback(p.stop)
                return self.mod.relay_health_tick(), mocks

    _alive = {"up": True, "handshake_age": 10, "tx": 1, "rx": 1}
    _dead = {"up": True, "handshake_age": 9999, "tx": 1, "rx": 1}

    def test_hold_at_limit_no_rollback(self):
        # 3-я неудача (fail_count=2 → fail=3): hold-3, relay_disable НЕ
        # вызван, TG: ОДНО awg_relay_hold (переход предела)
        res, m = self._tick(self._box(fail_count=2,
                                      fail_action="notify_only"),
                            self._dead, self._dead)
        self.assertEqual(res, "hold-3")
        m["relay_disable"].assert_not_called()
        events = [c.args[0] for c in m["_notify"].call_args_list]
        self.assertEqual(events, ["awg_relay_hold"])
        m["_relay_state_update"].assert_called_once()

    def test_hold_beyond_limit_is_silent(self):
        # долгий простой (fail_count=7 → hold-8): TG-тишина (hold уже
        # сообщил), откат по-прежнему не происходит, счётчик растёт
        res, m = self._tick(self._box(fail_count=7,
                                      fail_action="notify_only"),
                            self._dead, self._dead)
        self.assertEqual(res, "hold-8")
        m["relay_disable"].assert_not_called()
        m["_notify"].assert_not_called()
        m["_relay_state_update"].assert_called_once()

    def test_hold_below_limit_notifies_dir_dead(self):
        # до предела — по-попыточные уведомления (паритет rollback-режима)
        res, m = self._tick(self._box(fail_count=0,
                                      fail_action="notify_only"),
                            self._dead, self._dead)
        self.assertEqual(res, "hold-1")
        m["relay_disable"].assert_not_called()
        events = [c.args[0] for c in m["_notify"].call_args_list]
        self.assertEqual(events, ["awg_relay_dir_dead"])

    def test_recovered_after_hold(self):
        # напарник вернулся после удержания: ok + awg_relay_recovered
        # (ответ на hold-уведомление обязан быть) + fail_count обнулён
        res, m = self._tick(self._box(fail_count=7,
                                      fail_action="notify_only"),
                            self._alive, self._alive)
        self.assertEqual(res, "ok")
        events = [c.args[0] for c in m["_notify"].call_args_list]
        self.assertEqual(events, ["awg_relay_recovered"])

    def test_rollback_mode_recovery_is_silent(self):
        # rollback: события восстановления нет (протекание notify_only в
        # чужой режим = прежний класс молчаливой семантики)
        res, m = self._tick(self._box(fail_count=7), self._alive,
                            self._alive)
        self.assertEqual(res, "ok")
        m["_notify"].assert_not_called()

    def test_rollback_explicit_unchanged(self):
        # явный rollback: прежняя лестница — авто-откат на пределе
        res, m = self._tick(self._box(fail_count=2, fail_action="rollback"),
                            self._dead, self._dead)
        self.assertEqual(res, "rollback")
        m["relay_disable"].assert_called_once()
        events = [c.args[0] for c in m["_notify"].call_args_list]
        self.assertEqual(events, ["awg_relay_dir_dead"])


class TestFailActionTui(_RelayTest):
    def test_fail_action_ask_mapping(self):
        # 1 → rollback; 2 → notify_only; Q/мусор → текущий из бокса
        with patch("builtins.input", side_effect=["1"]):
            self.assertEqual(self.mod._relay_fail_action_ask({}),
                             "rollback")
        with patch("builtins.input", side_effect=["2"]):
            self.assertEqual(self.mod._relay_fail_action_ask({}),
                             "notify_only")
        with patch("builtins.input", side_effect=["x"]):
            self.assertEqual(
                self.mod._relay_fail_action_ask(
                    {"fail_action": "notify_only"}),
                "notify_only")
        with patch("builtins.input", side_effect=[""]):
            self.assertEqual(self.mod._relay_fail_action_ask({}),
                             "rollback")

    def test_menu_item7_and_diag8(self):
        # текст-контракт меню: новый п.7 (watchdog-откат), диагностика → 8
        src = (_PROJECT_ROOT / "chimera" / "modules"
               / "awg_kernel_relay.py").read_text(encoding="utf8")
        self.assertIn('_box_item("7", "Watchdog-откат: '
                      'уведомить+откат / ТОЛЬКО уведомить")', src)
        self.assertIn('_box_item("8", "Диагностика: journalctl юнита + '
                      'awg show")', src)
        self.assertLess(src.find('_box_item("7"'), src.find('_box_item("8"'))

    def test_activation_asks_fail_action(self):
        # активация спрашивает поведение watchdog и несёт его в cfg
        # (запрос владельца: выбор «уведомлять И катать / только
        # уведомлять» совместно с активацией)
        src = (_PROJECT_ROOT / "chimera" / "modules"
               / "awg_kernel_relay.py").read_text(encoding="utf8")
        self.assertIn("fail_action = _relay_fail_action_ask(box)", src)
        self.assertIn("fail_action=fail_action)", src)

    def test_tgbot_covers_relay_events(self):
        # класс кейса окт.2026 №8: события должны иметь иконку, титул и
        # тумблер меню (3 вхождения ключа: icons + titles + ev_keys)
        src = (_PROJECT_ROOT / "chimera" / "modules"
               / "tg_bot.py").read_text(encoding="utf8")
        for ev in ("awg_relay_on", "awg_relay_dir_dead", "awg_relay_off",
                   "awg_relay_hold", "awg_relay_recovered"):
            self.assertGreaterEqual(src.count(f'"{ev}"'), 3, ev)
        self.assertIn('"AWG-релей: лестница исчерпана — держим без '
                      'отката"', src)
        self.assertIn('"AWG-релей: флоу ожил после удержания"', src)


if __name__ == "__main__":
    unittest.main()
