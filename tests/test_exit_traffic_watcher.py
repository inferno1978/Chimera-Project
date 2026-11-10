#!/usr/bin/env python3
"""
Unit-тесты для chimera/modules/exit_traffic_watcher.py.

Контекст (живой кейс окт.2026 №8, продолжение): exit_switch_watcher
вернул уведы о СОСТАВЕ ротации, но в балансировочных режимах
(roundRobin/leastPing/leastLoad/random) «активной ноды» не существует —
вопрос «через какую ноду реально идёт трафик?» оставался без ответа.
exit_traffic_watcher закрывает его счётчиками Stats API
(outbound>>>chain-exit-N>>>traffic>>>uplink/downlink) — дельты между
прогонами = фактическое распределение трафика, режим-агностично.

Покрывает (чистые функции + IO с патченными путями, без сервера):
  1. _tw_merge_cfg       — слияние конфига с дефолтами
  2. _tw_quiet/_tw_gap_ok/_tw_render — тихие часы / анти-спам / шаблоны
  3. _tw_parse_stats     — парсинг вывода xray api statsquery
  4. _tw_deltas          — дельты счётчиков + рестарт xray (сброс)
  5. _tw_acc_add         — накопитель окна дайджеста (без мутации входа)
  6. _tw_dominant        — доминирующая нода: пороги доли и объёма
  7. _tw_starve_update   — нода в selector без трафика (перевзвод)
  8. _tw_fmt_bytes/_tw_distribution_rows — человекочитаемый вывод
  9. _tw_parse_access_users/_tw_per_user_rows — per-user разбор access.log
 10. _tw_snapshot_text   — текст дайджеста
 11. _tw_tag_names       — chain-exit-N → нода + алиасы
 12. load_cfg/save_cfg   — JSON I/O
 13. install/uninstall   — cron file I/O
 14. run_once            — полный цикл: дельты → доминирование → дайджест
 15. Интеграция с tg_bot: события наблюдателя в icons/event_labels/
     ev_keys/ev_labels (управляемость из «менюшки»)
 16. Интеграция с _core.py: пункт меню TW + импорт (канон test_dns_redirect)
 17. _tw_strategy_label/_tw_dominant_change_text — человекочитаемый
     заголовок уведы смены ноды (режим + откуда → куда)
 18. _tw_tcp_probe/_tw_probe_nodes — TCP-проба host:port (патченный
     socket: успех/таймаут/отказ/DNS — без сети)
 19. _tw_probe_update — машина состояний проб: down/degraded/up,
     флап, агрегация, guard «все ноды разом» (локальная проблема)
 20. Тексты увед проб (_tw_probe_event_text + строки нод)
 21. run_once + пробы: события через общий _emit, персист
     probe-состояния (в т.ч. на пути отказа Stats API), метки
     last_traffic_ts, {node}-плейсхолдер
"""
from __future__ import annotations

import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Регистрирует chimera._core в sys.modules (нужен tg_bot для
    TUI-импортов; паттерн test_exit_switch_watcher / test_node_health_monitor)."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    from unittest.mock import MagicMock
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


# ─── фикстуры (примерные домены, не прод-инфра) ───────────────────────────────
ND_A = {"host": "node-a.example.com", "port": 443}
ND_B = {"host": "node-b.example.com", "port": 443}
KEY_A = "node-a.example.com:443"
KEY_B = "node-b.example.com:443"
TAG_A = "chain-exit-1"
TAG_B = "chain-exit-2"

MB = 1024 * 1024


class TestMergeCfg(unittest.TestCase):
    """_tw_merge_cfg — слияние с дефолтами."""

    def test_empty_gives_defaults(self):
        from chimera.modules.exit_traffic_watcher import _tw_merge_cfg, DEFAULTS
        out = _tw_merge_cfg(DEFAULTS, {})
        self.assertEqual(out["interval_min"], DEFAULTS["interval_min"])
        self.assertTrue(out["notify"]["traffic_snapshot"])

    def test_stored_overrides(self):
        from chimera.modules.exit_traffic_watcher import _tw_merge_cfg, DEFAULTS
        out = _tw_merge_cfg(DEFAULTS, {"interval_min": 5, "enabled": False,
                                       "dominant_min_share_pct": 75})
        self.assertEqual(out["interval_min"], 5)
        self.assertFalse(out["enabled"])
        self.assertEqual(out["dominant_min_share_pct"], 75)

    def test_notify_new_events_added(self):
        """Конфиг, сохранённый до появления новых типов событий, добирает
        их как ВКЛ (обратная совместимость при обновлении)."""
        from chimera.modules.exit_traffic_watcher import _tw_merge_cfg, DEFAULTS, EVENTS
        stored = {"notify": {"traffic_snapshot": True}}
        out = _tw_merge_cfg(DEFAULTS, stored)
        for ev in EVENTS:
            self.assertIn(ev, out["notify"])
        self.assertTrue(out["notify"]["traffic_dominant_change"])

    def test_nested_merge(self):
        from chimera.modules.exit_traffic_watcher import _tw_merge_cfg, DEFAULTS
        out = _tw_merge_cfg(DEFAULTS, {"quiet_hours": {"from": "23:00"}})
        self.assertEqual(out["quiet_hours"]["from"], "23:00")
        self.assertEqual(out["quiet_hours"]["to"], "")

    def test_aliases_kept(self):
        from chimera.modules.exit_traffic_watcher import _tw_merge_cfg, DEFAULTS
        out = _tw_merge_cfg(DEFAULTS, {"aliases": {KEY_A: "RU1"}})
        self.assertEqual(out["aliases"][KEY_A], "RU1")


class TestQuietGapRender(unittest.TestCase):
    """Тихие часы / анти-спам / шаблоны (паттерн exit_switch_watcher)."""

    def test_quiet_overnight(self):
        from chimera.modules.exit_traffic_watcher import _tw_quiet
        q = {"from": "23:00", "to": "08:00"}
        self.assertTrue(_tw_quiet("23:59", q))
        self.assertTrue(_tw_quiet("00:30", q))
        self.assertFalse(_tw_quiet("12:00", q))
        self.assertFalse(_tw_quiet("12:00", {"from": "", "to": ""}))

    def test_quiet_garbage_not_crash(self):
        from chimera.modules.exit_traffic_watcher import _tw_quiet
        self.assertFalse(_tw_quiet("10:00", {"from": "xx", "to": "yy"}))

    def test_gap_ok(self):
        from chimera.modules.exit_traffic_watcher import _tw_gap_ok
        self.assertTrue(_tw_gap_ok(0, 1000.0, 10))
        self.assertFalse(_tw_gap_ok(1000.0, 1000.0 + 5 * 60, 10))
        self.assertTrue(_tw_gap_ok(1000.0, 1000.0 + 10 * 60, 10))

    def test_render(self):
        from chimera.modules.exit_traffic_watcher import _tw_render
        self.assertEqual(_tw_render("<b>[{host}]</b> {detail}",
                                    host="srv", detail="ok"),
                         "<b>[srv]</b> ok")
        self.assertEqual(_tw_render("{detail} {unknown}", detail="d"),
                         "d {unknown}")


class TestParseStats(unittest.TestCase):
    """_tw_parse_stats — вывод xray api statsquery."""

    def test_typical_output(self):
        from chimera.modules.exit_traffic_watcher import _tw_parse_stats
        raw = json.dumps({"stat": [
            {"name": "outbound>>>chain-exit-1>>>traffic>>>uplink", "value": 100},
            {"name": "outbound>>>chain-exit-1>>>traffic>>>downlink", "value": 900},
            {"name": "outbound>>>chain-exit-2>>>traffic>>>uplink", "value": 5},
            {"name": "outbound>>>chain-exit-2>>>traffic>>>downlink", "value": 7},
        ]})
        out = _tw_parse_stats(raw)
        self.assertEqual(out[TAG_A], {"up": 100, "down": 900})
        self.assertEqual(out[TAG_B], {"up": 5, "down": 7})

    def test_service_and_foreign_names_ignored(self):
        from chimera.modules.exit_traffic_watcher import _tw_parse_stats
        raw = json.dumps({"stat": [
            {"name": "outbound>>>xray-stats-api>>>traffic>>>uplink", "value": 1},
            {"name": "user>>>andrew>>>traffic>>>uplink", "value": 2},
            {"name": "inbound>>>vless>>>traffic>>>downlink", "value": 3},
        ]})
        out = _tw_parse_stats(raw)
        # парсер тегов-нейтрален: user>>>/inbound>>> не совпадают с паттерном,
        # служебный xray-stats-api остаётся (фильтруется по именам нод выше)
        self.assertNotIn("user>>>andrew", out)
        self.assertIn("xray-stats-api", out)

    def test_garbage(self):
        from chimera.modules.exit_traffic_watcher import _tw_parse_stats
        self.assertEqual(_tw_parse_stats("not json"), {})
        self.assertEqual(_tw_parse_stats(""), {})
        self.assertEqual(_tw_parse_stats('{"stat": null}'), {})

    def test_negative_values_clamped(self):
        from chimera.modules.exit_traffic_watcher import _tw_parse_stats
        raw = json.dumps({"stat": [
            {"name": "outbound>>>chain-exit-1>>>traffic>>>uplink", "value": -5},
        ]})
        self.assertEqual(_tw_parse_stats(raw)[TAG_A]["up"], 0)


class TestDeltas(unittest.TestCase):
    """_tw_deltas — дельты счётчиков + сброс при рестарте xray."""

    def test_simple_delta(self):
        from chimera.modules.exit_traffic_watcher import _tw_deltas
        prev = {TAG_A: {"up": 100, "down": 900}}
        cur = {TAG_A: {"up": 150, "down": 1000}, TAG_B: {"up": 10, "down": 20}}
        d = _tw_deltas(prev, cur)
        self.assertEqual(d[TAG_A], {"up": 50, "down": 100})
        self.assertEqual(d[TAG_B], {"up": 10, "down": 20})

    def test_counter_reset_after_xray_restart(self):
        """cur < prev (рестарт xray сбросил счётчики) → дельта = cur,
        не отрицательная."""
        from chimera.modules.exit_traffic_watcher import _tw_deltas
        prev = {TAG_A: {"up": 1000, "down": 5000}}
        cur = {TAG_A: {"up": 30, "down": 70}}
        d = _tw_deltas(prev, cur)
        self.assertEqual(d[TAG_A], {"up": 30, "down": 70})

    def test_empty_prev(self):
        from chimera.modules.exit_traffic_watcher import _tw_deltas
        d = _tw_deltas({}, {TAG_A: {"up": 1, "down": 2}})
        self.assertEqual(d[TAG_A], {"up": 1, "down": 2})


class TestAccAdd(unittest.TestCase):
    """_tw_acc_add — накопитель окна дайджеста."""

    def test_accumulates(self):
        from chimera.modules.exit_traffic_watcher import _tw_acc_add
        acc = {TAG_A: {"up": 100, "down": 100}}
        acc = _tw_acc_add(acc, {TAG_A: {"up": 50, "down": 50},
                                TAG_B: {"up": 1, "down": 1}})
        self.assertEqual(acc[TAG_A], {"up": 150, "down": 150})
        self.assertEqual(acc[TAG_B], {"up": 1, "down": 1})

    def test_no_mutation_of_inputs(self):
        from chimera.modules.exit_traffic_watcher import _tw_acc_add
        acc = {TAG_A: {"up": 100, "down": 100}}
        delta = {TAG_A: {"up": 1, "down": 1}}
        _tw_acc_add(acc, delta)
        self.assertEqual(acc[TAG_A], {"up": 100, "down": 100})
        self.assertEqual(delta[TAG_A], {"up": 1, "down": 1})


class TestDominant(unittest.TestCase):
    """_tw_dominant — доминирующая нода окна."""

    def _acc(self, a: int, b: int) -> dict:
        return {TAG_A: {"up": a, "down": 0}, TAG_B: {"up": b, "down": 0}}

    def test_dominant_found(self):
        from chimera.modules.exit_traffic_watcher import _tw_dominant
        dom = _tw_dominant(self._acc(90, 10), 60, 50)
        self.assertEqual(dom["tag"], TAG_A)
        self.assertGreaterEqual(dom["share"], 60.0)
        self.assertEqual(dom["total"], 100)

    def test_below_share_threshold_is_none(self):
        """Равномерный roundRobin (50/50) не порождает доминирования."""
        from chimera.modules.exit_traffic_watcher import _tw_dominant
        self.assertIsNone(_tw_dominant(self._acc(50, 50), 60, 50))

    def test_below_volume_threshold_is_none(self):
        from chimera.modules.exit_traffic_watcher import _tw_dominant
        self.assertIsNone(_tw_dominant(self._acc(100, 1), 60, 50 * MB))

    def test_full_monopoly(self):
        from chimera.modules.exit_traffic_watcher import _tw_dominant
        dom = _tw_dominant(self._acc(100, 0), 60, 50)
        self.assertEqual(dom["share"], 100.0)


class TestStarve(unittest.TestCase):
    """_tw_starve_update — нода в selector без трафика."""

    def test_lifecycle_and_rearm(self):
        from chimera.modules.exit_traffic_watcher import _tw_starve_update
        deltas = {TAG_A: {"up": 1, "down": 1}}   # трафик жив, B молчит
        sel = [TAG_A, TAG_B]
        # окно 1: B запоминается как «без трафика с t=1000»
        zs, starved = _tw_starve_update({}, deltas, sel, 1000.0, 10, 0)
        self.assertIn(TAG_B, zs)
        self.assertEqual(starved, [])
        # окно 2 (через 5 сек): ещё не голодает
        zs, starved = _tw_starve_update(zs, deltas, sel, 1005.0, 10, 0)
        self.assertEqual(starved, [])
        # окно 3 (через 10+ сек): голод! таймер перевзводится
        zs, starved = _tw_starve_update(zs, deltas, sel, 1011.0, 10, 0)
        self.assertEqual(starved, [TAG_B])
        # окно 4 сразу после: не дублируется (перевзвод)
        zs, starved = _tw_starve_update(zs, deltas, sel, 1012.0, 10, 0)
        self.assertEqual(starved, [])

    def test_traffic_resets_timer(self):
        from chimera.modules.exit_traffic_watcher import _tw_starve_update
        zs, _ = _tw_starve_update({}, {TAG_A: {"up": 1, "down": 1}},
                                  [TAG_A, TAG_B], 1000.0, 10, 0)
        # трафик пошёл через B — таймер снят
        zs, starved = _tw_starve_update(
            zs, {TAG_A: {"up": 1, "down": 1}, TAG_B: {"up": 1, "down": 1}},
            [TAG_A, TAG_B], 2000.0, 10, 0)
        self.assertNotIn(TAG_B, zs)
        self.assertEqual(starved, [])

    def test_silent_window_no_alert(self):
        """Окно без трафика вообще (ночь) — голод не детектится:
        total окна ниже порога."""
        from chimera.modules.exit_traffic_watcher import _tw_starve_update
        zs, _ = _tw_starve_update({}, {}, [TAG_A, TAG_B], 1000.0, 10, 100)
        zs, starved = _tw_starve_update(zs, {}, [TAG_A, TAG_B], 5000.0, 10, 100)
        self.assertEqual(starved, [])

    def test_outside_selector_ignored(self):
        from chimera.modules.exit_traffic_watcher import _tw_starve_update
        zs, starved = _tw_starve_update({}, {TAG_A: {"up": 1, "down": 1}},
                                        [TAG_A], 1000.0, 10, 0)
        zs, starved = _tw_starve_update(zs, {TAG_A: {"up": 1, "down": 1}},
                                        [TAG_A], 2000.0, 10, 0)
        self.assertEqual(starved, [])   # B вне selector — не наша забота


class _FakeSock:
    """Фейковый сокет для патча socket.create_connection (контекст-менеджер)."""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class TestTcpProbe(unittest.TestCase):
    """_tw_tcp_probe — TCP-проба host:port (патченный socket — без сети)."""

    def test_success_measures_ms(self):
        from chimera.modules.exit_traffic_watcher import _tw_tcp_probe
        with patch("socket.create_connection", return_value=_FakeSock()):
            r = _tw_tcp_probe("node-a.example.com", 443, 5)
        self.assertTrue(r["ok"])
        self.assertIsInstance(r["ms"], int)
        self.assertGreaterEqual(r["ms"], 0)
        self.assertEqual(r["err"], "")

    def test_timeout(self):
        from chimera.modules.exit_traffic_watcher import _tw_tcp_probe
        with patch("socket.create_connection",
                   side_effect=socket.timeout("timed out")):
            r = _tw_tcp_probe("node-a.example.com", 443, 1)
        self.assertFalse(r["ok"])
        self.assertIsNone(r["ms"])
        self.assertEqual(r["err"], "timeout")

    def test_refused_errno_prefix_stripped(self):
        """ConnectionRefusedError '[Errno 111] Connection refused' →
        короткий текст 'Connection refused'."""
        from chimera.modules.exit_traffic_watcher import _tw_tcp_probe
        with patch("socket.create_connection",
                   side_effect=ConnectionRefusedError(111,
                                                      "Connection refused")):
            r = _tw_tcp_probe("node-a.example.com", 443, 5)
        self.assertFalse(r["ok"])
        self.assertEqual(r["err"], "Connection refused")

    def test_dns_failure(self):
        """Отказ getaddrinfo (внутри create_connection) → err='DNS'."""
        from chimera.modules.exit_traffic_watcher import _tw_tcp_probe
        with patch("socket.getaddrinfo",
                   side_effect=socket.gaierror("name resolution failed")):
            r = _tw_tcp_probe("nope.invalid", 443, 5)
        self.assertFalse(r["ok"])
        self.assertIsNone(r["ms"])
        self.assertEqual(r["err"], "DNS")


class TestProbeUpdate(unittest.TestCase):
    """_tw_probe_update — машина состояний активных проб
    (down/degraded/up, флап, guard «все ноды разом»)."""

    CFG = {"probe_fails": 2, "probe_degraded_ms": 500,
           "probe_degraded_fails": 2}

    def _res(self, ok_a=True, ms_a=50, ok_b=True, ms_b=50) -> dict:
        return {TAG_A: {"ok": ok_a, "ms": ms_a if ok_a else None,
                        "err": "" if ok_a else "timeout"},
                TAG_B: {"ok": ok_b, "ms": ms_b if ok_b else None,
                        "err": "" if ok_b else "timeout"}}

    def test_down_after_consecutive_fails_only(self):
        """ok → 1 неудача (молчим) → 2-я подряд → down → 3-я (молчим)."""
        from chimera.modules.exit_traffic_watcher import _tw_probe_update
        st, ev = _tw_probe_update({}, self._res(ok_a=False),
                                  self.CFG, 1000.0)
        self.assertEqual(ev, [])
        self.assertEqual(st["probe_fails"][TAG_A], 1)
        self.assertEqual(st["probe_status"][TAG_A], "ok")
        st, ev = _tw_probe_update(st, self._res(ok_a=False),
                                  self.CFG, 1010.0)
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["event"], "traffic_node_down")
        self.assertEqual(ev[0]["tags"], [TAG_A])
        self.assertEqual(ev[0]["info"][TAG_A]["fails"], 2)
        self.assertEqual(ev[0]["info"][TAG_A]["err"], "timeout")
        st, ev = _tw_probe_update(st, self._res(ok_a=False),
                                  self.CFG, 1020.0)
        self.assertEqual(ev, [])   # статус не менялся — анти-спам

    def test_recovery_after_down(self):
        from chimera.modules.exit_traffic_watcher import _tw_probe_update
        st = {"probe_fails": {TAG_A: 2}, "probe_slow": {},
              "probe_status": {TAG_A: "down"}, "all_probes_down": False}
        st, ev = _tw_probe_update(st, self._res(), self.CFG, 2000.0)
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["event"], "traffic_node_up")
        self.assertEqual(ev[0]["tags"], [TAG_A])
        self.assertEqual(ev[0]["info"][TAG_A]["prev"], "down")
        self.assertEqual(st["probe_fails"][TAG_A], 0)
        self.assertEqual(st["probe_status"][TAG_A], "ok")

    def test_degraded_after_consecutive_slow_probes(self):
        from chimera.modules.exit_traffic_watcher import _tw_probe_update
        st, ev = _tw_probe_update({}, self._res(ms_a=800),
                                  self.CFG, 1000.0)
        self.assertEqual(ev, [])   # одна медленная — ещё не деградация
        self.assertEqual(st["probe_slow"][TAG_A], 1)
        st, ev = _tw_probe_update(st, self._res(ms_a=900),
                                  self.CFG, 1010.0)
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["event"], "traffic_node_degraded")
        self.assertEqual(ev[0]["info"][TAG_A]["ms"], 900)
        self.assertEqual(ev[0]["info"][TAG_A]["threshold"], 500)
        self.assertEqual(ev[0]["info"][TAG_A]["fails"], 2)
        self.assertEqual(st["probe_status"][TAG_A], "degraded")

    def test_degraded_recovery(self):
        from chimera.modules.exit_traffic_watcher import _tw_probe_update
        st = {"probe_fails": {}, "probe_slow": {TAG_A: 2},
              "probe_status": {TAG_A: "degraded"}, "all_probes_down": False}
        st, ev = _tw_probe_update(st, self._res(ms_a=40),
                                  self.CFG, 2000.0)
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["event"], "traffic_node_up")
        self.assertEqual(ev[0]["info"][TAG_A]["prev"], "degraded")
        self.assertEqual(st["probe_slow"][TAG_A], 0)

    def test_flap_fail_then_ok_resets_counters(self):
        """Единичный отказ между успешными пробами — счётчики
        сбрасываются, событий нет."""
        from chimera.modules.exit_traffic_watcher import _tw_probe_update
        st, ev = _tw_probe_update({}, self._res(ok_a=False),
                                  self.CFG, 1000.0)
        self.assertEqual(ev, [])
        st, ev = _tw_probe_update(st, self._res(), self.CFG, 1010.0)
        self.assertEqual(ev, [])
        self.assertEqual(st["probe_fails"][TAG_A], 0)
        st, ev = _tw_probe_update(st, self._res(ok_a=False),
                                  self.CFG, 1020.0)
        self.assertEqual(ev, [])   # снова 1/2 — порог не достигнут

    def test_all_fail_guard_local_event_once(self):
        """Все ноды разом пали → ОДИН «локальный» down без персональных
        статусов; повторный прогон молчит (анти-спам)."""
        from chimera.modules.exit_traffic_watcher import _tw_probe_update
        st, ev = _tw_probe_update({}, self._res(ok_a=False, ok_b=False),
                                  self.CFG, 1000.0)
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["event"], "traffic_node_down")
        self.assertTrue(ev[0]["local"])
        self.assertEqual(ev[0]["total"], 2)
        self.assertNotIn("tags", ev[0])
        # персональные счётчики/статусы не тронуты
        self.assertEqual(st["probe_fails"], {})
        self.assertEqual(st["probe_status"], {})
        self.assertTrue(st["all_probes_down"])
        st, ev = _tw_probe_update(st, self._res(ok_a=False, ok_b=False),
                                  self.CFG, 1010.0)
        self.assertEqual(ev, [])   # уже было — молчим

    def test_local_recovery_after_guard(self):
        from chimera.modules.exit_traffic_watcher import _tw_probe_update
        st = {"probe_fails": {}, "probe_slow": {}, "probe_status": {},
              "all_probes_down": True}
        st, ev = _tw_probe_update(st, self._res(ok_a=True, ok_b=False),
                                  self.CFG, 2000.0)
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["event"], "traffic_node_up")
        self.assertTrue(ev[0]["local_recovery"])
        self.assertEqual(ev[0]["ok_count"], 1)
        self.assertEqual(ev[0]["total"], 2)
        self.assertFalse(st["all_probes_down"])

    def test_two_nodes_down_same_run_single_event(self):
        """Две ноды падают в одном прогоне (третья жива — guard не
        мешает) → ОДНО событие с двумя tags: одна TG-уведа на тип
        за прогон (min_gap friendly)."""
        from chimera.modules.exit_traffic_watcher import _tw_probe_update
        TAG_C = "chain-exit-3"
        res = {TAG_A: {"ok": False, "ms": None, "err": "timeout"},
               TAG_B: {"ok": False, "ms": None, "err": "Connection refused"},
               TAG_C: {"ok": True, "ms": 30, "err": ""}}
        st = {"probe_fails": {TAG_A: 1, TAG_B: 1}, "probe_slow": {},
              "probe_status": {TAG_A: "ok", TAG_B: "ok"},
              "all_probes_down": False}
        st, ev = _tw_probe_update(st, res, self.CFG, 2000.0)
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["event"], "traffic_node_down")
        self.assertEqual(ev[0]["tags"], [TAG_A, TAG_B])
        self.assertEqual(ev[0]["info"][TAG_A]["err"], "timeout")
        self.assertEqual(ev[0]["info"][TAG_B]["err"],
                         "Connection refused")
        # обе ноды в статусе down, живая нода не затронута
        self.assertEqual(st["probe_status"][TAG_A], "down")
        self.assertEqual(st["probe_status"][TAG_B], "down")
        self.assertEqual(st["probe_status"][TAG_C], "ok")
        self.assertFalse(st["all_probes_down"])

    def test_stale_tags_pruned_from_counters(self):
        """Нода исчезла из результатов (состав chain_nodes сменился) —
        её счётчики не копятся вечно."""
        from chimera.modules.exit_traffic_watcher import _tw_probe_update
        st = {"probe_fails": {TAG_A: 2, TAG_B: 1},
              "probe_slow": {TAG_B: 1},
              "probe_status": {TAG_A: "down", TAG_B: "ok"},
              "all_probes_down": False}
        st, ev = _tw_probe_update(st, {TAG_A: {"ok": True, "ms": 10,
                                               "err": ""}},
                                  self.CFG, 2000.0)
        self.assertNotIn(TAG_B, st["probe_fails"])
        self.assertNotIn(TAG_B, st["probe_slow"])
        self.assertNotIn(TAG_B, st["probe_status"])
        # A восстановлена — up-событие на переходе down→ok
        self.assertEqual(ev[0]["event"], "traffic_node_up")

    def test_degraded_disabled_when_threshold_zero(self):
        """probe_degraded_ms=0 — деградация выключена, любые RTT = ok."""
        from chimera.modules.exit_traffic_watcher import _tw_probe_update
        cfg = dict(self.CFG, probe_degraded_ms=0)
        st, ev = _tw_probe_update({}, self._res(ms_a=9999), cfg, 1000.0)
        st, ev = _tw_probe_update(st, self._res(ms_a=9999), cfg, 1010.0)
        self.assertEqual(ev, [])
        self.assertEqual(st["probe_slow"][TAG_A], 0)
        self.assertEqual(st["probe_status"][TAG_A], "ok")

    def test_tolerates_missing_and_none_state_keys(self):
        """Отсутствующие/None ключи pstate — норма (свежая __state__)."""
        from chimera.modules.exit_traffic_watcher import _tw_probe_update
        st, ev = _tw_probe_update(
            {"probe_fails": None, "probe_slow": None,
             "probe_status": None, "all_probes_down": None},
            self._res(), self.CFG, 1000.0)
        self.assertEqual(ev, [])
        self.assertEqual(st["probe_fails"][TAG_A], 0)
        self.assertFalse(st["all_probes_down"])
        # None-значения внутри счётчиков — как 0
        st, ev = _tw_probe_update(
            {"probe_fails": {TAG_A: None}, "probe_slow": {TAG_A: None},
             "probe_status": {TAG_A: None}, "all_probes_down": False},
            self._res(ok_a=False), self.CFG, 1010.0)
        self.assertEqual(st["probe_fails"][TAG_A], 1)

    def test_empty_results_noop(self):
        from chimera.modules.exit_traffic_watcher import _tw_probe_update
        st, ev = _tw_probe_update({}, None, self.CFG, 1000.0)
        self.assertEqual(ev, [])
        self.assertEqual(st, {"probe_fails": {}, "probe_slow": {},
                              "probe_status": {},
                              "all_probes_down": False})


class TestProbeTexts(unittest.TestCase):
    """Тексты увед активных проб: строки нод + локальные сценарии +
    агрегация нескольких нод в одно сообщение."""

    NAMES = {TAG_A: "RU1", TAG_B: KEY_B}
    KEYS = {TAG_A: KEY_A, TAG_B: KEY_B}

    def test_down_line_with_traffic_context_and_hm(self):
        from chimera.modules.exit_traffic_watcher import _tw_probe_event_text
        ev = {"event": "traffic_node_down", "tags": [TAG_A],
              "info": {TAG_A: {"err": "timeout", "fails": 2}}}
        txt = _tw_probe_event_text(
            ev, self.NAMES, self.KEYS, {TAG_A: 1000.0}, 1000.0 + 1800.0,
            {KEY_A: {"up": False}}, "relay")
        self.assertEqual(
            txt.split("\n")[0],
            f"Нода <b><code>RU1</code></b> ({KEY_A}) недоступна: "
            f"TCP-проба не проходит 2 прогонов подряд (timeout). "
            f"(Health Monitor: DOWN)")
        self.assertIn("Последний трафик через ноду: 30 мин назад", txt)

    def test_down_line_without_traffic(self):
        from chimera.modules.exit_traffic_watcher import _tw_probe_event_text
        ev = {"event": "traffic_node_down", "tags": [TAG_B],
              "info": {TAG_B: {"err": "Connection refused", "fails": 3}}}
        txt = _tw_probe_event_text(ev, self.NAMES, self.KEYS, {}, 0.0,
                                   {KEY_B: {"up": True}}, "relay")
        self.assertIn(
            f"Нода <b><code>{KEY_B}</code></b> ({KEY_B}) недоступна: "
            f"TCP-проба не проходит 3 прогонов подряд "
            f"(Connection refused).", txt)
        self.assertIn("Трафика через ноду в этом окне не было.", txt)
        self.assertNotIn("Health Monitor", txt)

    def test_degraded_line(self):
        from chimera.modules.exit_traffic_watcher import _tw_probe_event_text
        ev = {"event": "traffic_node_degraded", "tags": [TAG_A],
              "info": {TAG_A: {"ms": 812, "threshold": 500, "fails": 2}}}
        txt = _tw_probe_event_text(ev, self.NAMES, self.KEYS, {}, 0.0,
                                   {}, "relay")
        self.assertEqual(
            txt, f"Нода <b><code>RU1</code></b> ({KEY_A}) тупит: "
                 f"TCP-проба проходит, но RTT 812 мс выше порога "
                 f"500 мс (2 прогонов подряд).")

    def test_up_line_after_down_and_degraded(self):
        from chimera.modules.exit_traffic_watcher import _tw_probe_up_line
        self.assertEqual(
            _tw_probe_up_line("RU1", KEY_A, 42, "down"),
            f"Нода <b><code>RU1</code></b> ({KEY_A}) восстановлена: "
            f"RTT 42 мс (после отказа).")
        self.assertEqual(
            _tw_probe_up_line("RU1", KEY_A, 42, "degraded"),
            f"Нода <b><code>RU1</code></b> ({KEY_A}) восстановлена: "
            f"RTT 42 мс (после деградации).")

    def test_local_all_down_and_recovery(self):
        from chimera.modules.exit_traffic_watcher import _tw_probe_event_text
        txt = _tw_probe_event_text(
            {"event": "traffic_node_down", "local": True, "total": 3},
            {}, {}, {}, 0.0, {}, "relay-1")
        self.assertEqual(
            txt, "Все 3 exit-нод недоступны одновременно — вероятна "
                 "локальная проблема на relay-1 (сеть/DNS/исходящий "
                 "трафик). Уведы по отдельным нодам подавлены.")
        txt = _tw_probe_event_text(
            {"event": "traffic_node_up", "local_recovery": True,
             "ok_count": 2, "total": 3}, {}, {}, {}, 0.0, {}, "relay-1")
        self.assertEqual(txt, "Связь с exit-нодами восстановлена: "
                              "2 из 3 отвечают.")

    def test_multi_node_aggregation_one_detail(self):
        """Две ноды в одном событии — строки через \\n в одном detail."""
        from chimera.modules.exit_traffic_watcher import _tw_probe_event_text
        ev = {"event": "traffic_node_down",
              "tags": [TAG_A, TAG_B],
              "info": {TAG_A: {"err": "timeout", "fails": 2},
                       TAG_B: {"err": "DNS", "fails": 2}}}
        txt = _tw_probe_event_text(ev, self.NAMES, self.KEYS, {}, 0.0,
                                   {}, "relay")
        lines = txt.split("\n")
        self.assertEqual(len(lines), 4)   # 2 ноды × (строка + контекст)
        self.assertIn("<code>RU1</code>", lines[0])
        self.assertIn(f"<code>{KEY_B}</code>", lines[2])

    def test_event_extra_node_placeholder(self):
        from chimera.modules.exit_traffic_watcher import (
            _tw_probe_event_extra)
        ev = {"event": "traffic_node_down", "tags": [TAG_A, TAG_B],
              "info": {}}
        self.assertEqual(
            _tw_probe_event_extra(ev, self.NAMES, self.KEYS),
            {"node": "RU1"})
        self.assertEqual(
            _tw_probe_event_extra({"event": "traffic_node_down",
                                   "local": True, "total": 2},
                                  self.NAMES, self.KEYS), {})


class TestFmtAndRows(unittest.TestCase):
    """_tw_fmt_bytes / _tw_distribution_rows — человекочитаемый вывод."""

    def test_units(self):
        from chimera.modules.exit_traffic_watcher import _tw_fmt_bytes
        self.assertEqual(_tw_fmt_bytes(0), "0 Б")
        self.assertEqual(_tw_fmt_bytes(1000), "1000 Б")
        self.assertEqual(_tw_fmt_bytes(1536), "1.5 КБ")
        self.assertEqual(_tw_fmt_bytes(2 * 1024 * 1024), "2 МБ")
        self.assertEqual(_tw_fmt_bytes(3 * 1024 ** 3), "3 ГБ")
        self.assertEqual(_tw_fmt_bytes(-5), "0 Б")

    def test_rows_sorted_and_formatted(self):
        from chimera.modules.exit_traffic_watcher import _tw_distribution_rows
        acc = {TAG_A: {"up": 100, "down": 900},
               TAG_B: {"up": 10, "down": 10}}
        rows = _tw_distribution_rows(acc, {TAG_A: "RU1", TAG_B: "RU2"})
        self.assertEqual(rows[0], "• <code>RU1</code> — 1000 Б (98%)")
        self.assertEqual(rows[1], "• <code>RU2</code> — 20 Б (2%)")

    def test_rows_percent_only(self):
        from chimera.modules.exit_traffic_watcher import _tw_distribution_rows
        acc = {TAG_A: {"up": 75, "down": 0}, TAG_B: {"up": 25, "down": 0}}
        rows = _tw_distribution_rows(acc, {}, include_percent=True,
                                     include_bytes=False)
        self.assertEqual(rows[0], "• <code>chain-exit-1</code> — 75%")

    def test_rows_zero_total(self):
        from chimera.modules.exit_traffic_watcher import _tw_distribution_rows
        rows = _tw_distribution_rows({TAG_A: {"up": 0, "down": 0}}, {})
        self.assertEqual(rows, ["• <code>chain-exit-1</code> — 0 Б"])


class TestAccessUsers(unittest.TestCase):
    """_tw_parse_access_users / _tw_per_user_rows — per-user разбор."""

    LINES = [
        # формат access.log (loglevel=info)
        "2026/11/20 10:00:00 1.2.3.4:5555 accepted tcp:x.com:443 "
        f"[{TAG_B}] email: andrew@x",
        "2026/11/20 10:00:01 1.2.3.4:5556 accepted tcp:y.com:443 "
        f"[{TAG_A}] email: andrew@x",
        "2026/11/20 10:00:02 1.2.3.4:5557 accepted tcp:z.com:443 "
        "[balancer] email: mama@x",
        "2026/11/20 10:00:03 1.2.3.4:5558 closed tcp:z.com:443 "
        f"[{TAG_A}] email: andrew@x",
        "2026/11/20 10:00:04 1.2.3.4:5559 accepted tcp:w.com:443 "
        f"[{TAG_A}] email: mama@x",
        "2026/11/20 10:00:05 [info] some internal line without email",
    ]

    def test_parse(self):
        from chimera.modules.exit_traffic_watcher import _tw_parse_access_users
        cnt = _tw_parse_access_users(self.LINES, {TAG_A, TAG_B})
        # closed-строки и balancer-тег отфильтрованы
        self.assertEqual(cnt, {"andrew@x": {TAG_B: 1, TAG_A: 1},
                               "mama@x": {TAG_A: 1}})

    def test_parse_without_whitelist(self):
        from chimera.modules.exit_traffic_watcher import _tw_parse_access_users
        cnt = _tw_parse_access_users(self.LINES, None)
        self.assertEqual(cnt["mama@x"], {TAG_A: 1, "balancer": 1})

    def test_per_user_rows_top_and_share(self):
        from chimera.modules.exit_traffic_watcher import (
            _tw_parse_access_users, _tw_per_user_rows)
        cnt = _tw_parse_access_users(self.LINES, {TAG_A, TAG_B})
        rows = _tw_per_user_rows(cnt, {TAG_A: "RU1", TAG_B: "RU2"}, top_n=5)
        self.assertEqual(len(rows), 2)   # andrew (2) + mama (1)
        row = next(r for r in rows if "andrew" in r)
        self.assertIn("RU1 50%", row)
        self.assertIn("RU2 50%", row)

    def test_per_user_rows_top_n_limits(self):
        from chimera.modules.exit_traffic_watcher import _tw_per_user_rows
        counts = {f"u{i}@x": {TAG_A: 1} for i in range(10)}
        rows = _tw_per_user_rows(counts, {}, top_n=3)
        self.assertEqual(len(rows), 3)


class TestStrategyLabelAndDominantText(unittest.TestCase):
    """Человекочитаемый заголовок уведы traffic_dominant_change:
    «Режим: активная нода X» + «Переключение ноды: Y → X» (откуда/куда
    полностью) + доля окна; метка режима — SmartBalancer / нативная
    стратегия / каскад (запрос владельца 09.11.2026)."""

    def test_strategy_label_smart_balancer(self):
        from chimera.modules.exit_traffic_watcher import _tw_strategy_label
        self.assertEqual(
            _tw_strategy_label({"strategy": "leastPing"},
                               {"enabled": True}),
            "SmartBalancer")

    def test_strategy_label_native(self):
        from chimera.modules.exit_traffic_watcher import _tw_strategy_label
        for raw, pretty in (("leastPing", "LeastPing"),
                            ("roundRobin", "RoundRobin"),
                            ("leastLoad", "LeastLoad"),
                            ("random", "Random")):
            self.assertEqual(_tw_strategy_label({"strategy": raw}, {}),
                             pretty)

    def test_strategy_label_unknown_passthrough(self):
        from chimera.modules.exit_traffic_watcher import _tw_strategy_label
        self.assertEqual(_tw_strategy_label({"strategy": "myStrategy"}, {}),
                         "myStrategy")

    def test_strategy_label_no_balancer_cascade(self):
        """Без балансировщика (pinned/single, failover) — «Каскад»."""
        from chimera.modules.exit_traffic_watcher import _tw_strategy_label
        self.assertEqual(_tw_strategy_label({"strategy": ""}, {}),
                         "Каскад")
        self.assertEqual(_tw_strategy_label({}, None), "Каскад")

    def test_strategy_label_sb_disabled_falls_back(self):
        """SB выключен — метка от нативной стратегии chain-balancer."""
        from chimera.modules.exit_traffic_watcher import _tw_strategy_label
        self.assertEqual(
            _tw_strategy_label({"strategy": "leastPing"},
                               {"enabled": False}),
            "LeastPing")

    def test_dominant_change_text_format(self):
        """Заголовок: «Режим: активная нода X» / «Переключение ноды:
        Y → X» / доля окна — все имена полностью (host:port)."""
        from chimera.modules.exit_traffic_watcher import (
            _tw_dominant_change_text)
        txt = _tw_dominant_change_text(
            "SmartBalancer", "chimeraprodvpn.online:443",
            "totalshadows.online:443", 72.4,
            720 * MB, 1000 * MB)
        lines = txt.split("\n")
        self.assertEqual(
            lines[0],
            "SmartBalancer: активная нода "
            "<b><code>totalshadows.online:443</code></b>")
        self.assertEqual(
            lines[1],
            "Переключение ноды: <code>chimeraprodvpn.online:443</code> "
            "→ <b><code>totalshadows.online:443</code></b>")
        self.assertIn("72% окна", lines[2])

    def test_dominant_change_text_alias_names(self):
        """Имена — уже разрешённые (алиас либо host:port) — как есть."""
        from chimera.modules.exit_traffic_watcher import (
            _tw_dominant_change_text)
        txt = _tw_dominant_change_text(
            "LeastPing", "RU1", "DE", 100.0, 5 * MB, 5 * MB)
        self.assertIn("активная нода <b><code>DE</code></b>", txt)
        self.assertIn("Переключение ноды: <code>RU1</code> → ", txt)


class TestSnapshotText(unittest.TestCase):
    """_tw_snapshot_text — текст дайджеста."""

    def test_composition(self):
        from chimera.modules.exit_traffic_watcher import _tw_snapshot_text
        acc = {TAG_A: {"up": 100, "down": 900},
               TAG_B: {"up": 10, "down": 10}}
        names = {TAG_A: "RU1", TAG_B: "RU2"}
        text = _tw_snapshot_text(acc, names, "roundRobin",
                                 "20.11 08:00 → 20.11 20:00",
                                 ["👤 <code>andrew@x</code>: RU1 98%"])
        self.assertIn("roundRobin", text)
        self.assertIn("Окно:", text)
        self.assertIn("RU1", text)
        self.assertIn("RU2", text)
        self.assertIn("98%", text)
        self.assertIn("Пользователи", text)
        self.assertIn("andrew@x", text)

    def test_empty_window(self):
        from chimera.modules.exit_traffic_watcher import _tw_snapshot_text
        text = _tw_snapshot_text({}, {}, "", [], [], True, True)
        self.assertIn("не было", text)


class TestTagNames(unittest.TestCase):
    """_tw_tag_names — chain-exit-N → нода + алиасы."""

    def test_mapping_and_alias(self):
        from chimera.modules.exit_traffic_watcher import _tw_tag_names
        names, keys = _tw_tag_names(
            [ND_A, ND_B], {KEY_A: "RU1"})
        self.assertEqual(names[TAG_A], "RU1")
        self.assertEqual(names[TAG_B], KEY_B)
        self.assertEqual(keys[TAG_A], KEY_A)

    def test_no_alias(self):
        from chimera.modules.exit_traffic_watcher import _tw_tag_names
        names, _ = _tw_tag_names([ND_A], {})
        self.assertEqual(names[TAG_A], KEY_A)

    def test_empty(self):
        from chimera.modules.exit_traffic_watcher import _tw_tag_names
        self.assertEqual(_tw_tag_names([], {}), ({}, {}))


class TestCfgIO(unittest.TestCase):
    """load_cfg / save_cfg — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "exit_traffic_watcher.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        import chimera.modules.exit_traffic_watcher as tw
        return patch.multiple(tw, TW_CFG_FILE=self._cfg)

    def test_load_defaults_when_no_file(self):
        import chimera.modules.exit_traffic_watcher as tw
        with self._patch():
            cfg = tw.load_cfg()
        self.assertTrue(cfg["enabled"])
        self.assertEqual(cfg["snapshot_hours"], tw.DEFAULT_SNAPSHOT_HOURS)

    def test_load_defaults_when_corrupt(self):
        import chimera.modules.exit_traffic_watcher as tw
        self._cfg.write_text("{invalid")
        with self._patch():
            cfg = tw.load_cfg()
        self.assertTrue(cfg["enabled"])

    def test_save_then_load_roundtrip(self):
        import chimera.modules.exit_traffic_watcher as tw
        with self._patch():
            tw.save_cfg({"enabled": False, "interval_min": 7,
                         "aliases": {KEY_A: "RU1"}})
            cfg = tw.load_cfg()
        self.assertFalse(cfg["enabled"])
        self.assertEqual(cfg["interval_min"], 7)
        self.assertEqual(cfg["aliases"][KEY_A], "RU1")

    def test_save_chmod_600(self):
        import chimera.modules.exit_traffic_watcher as tw
        with self._patch():
            tw.save_cfg({"enabled": True})
        self.assertEqual(self._cfg.stat().st_mode & 0o777, 0o600)

    def test_state_rides_in_cfg(self):
        """__state__ (счётчики/накопитель) живёт в конфиг-файле рядом с
        настройками (паттерн exit_switch_watcher): загрузка в меню и
        save_cfg не теряют накопленное состояние."""
        import chimera.modules.exit_traffic_watcher as tw
        stored = {"enabled": True,
                  "__state__": {"counters": {TAG_A: {"up": 1, "down": 0}},
                                "acc": {TAG_A: {"up": 1, "down": 0}}}}
        self._cfg.write_text(json.dumps(stored), encoding="utf-8")
        with self._patch():
            cfg = tw.load_cfg()
            tw.save_cfg(cfg)
        reloaded = json.loads(self._cfg.read_text())
        self.assertEqual(reloaded["__state__"]["counters"][TAG_A]["up"], 1)
        self.assertEqual(reloaded["__state__"]["acc"][TAG_A]["up"], 1)


class TestCronInstall(unittest.TestCase):
    """install_watcher / uninstall_watcher / is_installed — cron I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cron = self._tmpdir / "xray-exit-traffic-watcher"
        self._script = self._tmpdir / "xray-exit-traffic-watcher.sh"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        import chimera.modules.exit_traffic_watcher as tw
        return patch.multiple(tw, CRON_FILE=self._cron,
                              CRON_SCRIPT=self._script)

    def test_install_creates_files(self):
        import chimera.modules.exit_traffic_watcher as tw
        with self._patch():
            ok, msg = tw.install_watcher(15)
            self.assertTrue(ok, msg)
            self.assertTrue(tw.is_installed())
            cron_text = self._cron.read_text()
        self.assertIn("*/15 * * * *", cron_text)
        self.assertIn("exit_traffic_watcher", self._script.read_text())

    def test_interval_clamped(self):
        import chimera.modules.exit_traffic_watcher as tw
        with self._patch():
            ok, _ = tw.install_watcher(999)
            self.assertTrue(ok)
            self.assertIn("*/60", self._cron.read_text())

    def test_uninstall_removes_files(self):
        import chimera.modules.exit_traffic_watcher as tw
        with self._patch():
            tw.install_watcher(5)
            ok, _ = tw.uninstall_watcher()
            self.assertTrue(ok)
            self.assertFalse(tw.is_installed())


class TestRunOnce(unittest.TestCase):
    """run_once — полный цикл наблюдения (патченные пути + фейки)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "exit_traffic_watcher.json"
        self._state = self._tmpdir / "state.json"
        self._sb = self._tmpdir / "smart_balancer.json"
        self._xray_cfg = self._tmpdir / "config.json"
        self._state.write_text(json.dumps(
            {"chain_nodes": [ND_A, ND_B]}), encoding="utf-8")
        # живой конфиг: chain-balancer с двумя нодами (roundRobin)
        self._xray_cfg.write_text(json.dumps(
            {"routing": {"balancers": [{
                "tag": "chain-balancer",
                "selector": [TAG_A, TAG_B],
                "strategy": {"type": "roundRobin"}}]}}),
            encoding="utf-8")
        self._events: list[str] = []
        self._details: list[tuple] = []

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_all(self, stats=None, probe=None):
        """Патчит пути IO + фейки Stats API/проб/увед (пробы — без сети)."""
        import chimera.modules.exit_traffic_watcher as tw

        def fake_notify(event, detail, cfg, extra=None):
            self._events.append(event)
            self._details.append((event, detail, extra))
            return True

        return patch.multiple(
            tw, TW_CFG_FILE=self._cfg, STATE_FILE=self._state,
            SB_STATE_FILE=self._sb, XRAY_CFG_CANDIDATES=(self._xray_cfg,),
            AWG_STATE_FILE=self._tmpdir / "awg-absent.json",
            MIERU_STATE_FILE=self._tmpdir / "mieru-absent.json",
            NAIVE_STATE_FILE=self._tmpdir / "naive-absent.json",
            _tw_query_stats=lambda timeout=8: stats,
            _tw_probe_nodes=lambda chain_nodes, cfg: probe,
            _tw_notify_event=fake_notify,
            _tw_ip_link_stats=lambda ifaces: {},
            _tw_iptables_nat_output=lambda: {},
            _tw_systemctl_show_ipacct=lambda unit: {
                "IPAccounting": False, "IPIngressBytes": None,
                "IPEgressBytes": None},
            _tw_log=lambda *a, **kw: None)

    def _stats(self, a_up=0, a_dn=0, b_up=0, b_dn=0) -> dict:
        return {TAG_A: {"up": a_up, "down": a_dn},
                TAG_B: {"up": b_up, "down": b_dn}}

    def test_disabled_returns_empty(self):
        import chimera.modules.exit_traffic_watcher as tw
        self._cfg.write_text(json.dumps({"enabled": False}))
        with self._patch_all():
            res = tw.run_once()
        self.assertEqual(res["events"], [])

    def test_no_chain_nodes_skips(self):
        import chimera.modules.exit_traffic_watcher as tw
        self._state.write_text(json.dumps({"chain_nodes": []}),
                               encoding="utf-8")
        with self._patch_all():
            res = tw.run_once()
        self.assertEqual(res["events"], [])

    def test_full_cycle_dominant_and_snapshot(self):
        """Прогон 1 — база; прогон 2 — трафик на A (доминирование, без
        события: прошлой доминирующей нет); прогон 3 — трафик переехал
        на B → traffic_dominant_change; прогон 4 (окно дайджеста истекло)
        → traffic_snapshot и накопитель сброшен."""
        import chimera.modules.exit_traffic_watcher as tw
        cfg = {"enabled": True, "snapshot_hours": 12,
               "dominant_min_share_pct": 60, "dominant_min_mb": 1,
               "min_gap_min": 0, "starve_hours": 0}
        self._cfg.write_text(json.dumps(cfg), encoding="utf-8")

        # Прогон 1: базовые счётчики
        with self._patch_all(stats=self._stats(100, 100, 0, 0)):
            res = tw.run_once()
        self.assertEqual(res["events"], [])
        st = json.loads(self._cfg.read_text())["__state__"]
        self.assertEqual(st["counters"][TAG_A]["up"], 100)

        # Прогон 2 должен считать дельты БЕЗ дайджеста — имитируем, что
        # дайджест уже отправлялся недавно (первый дайджест после базовой
        # линии уходит сразу; здесь проверяем именно детект доминирования)
        import time as _t
        st_now = json.loads(self._cfg.read_text())
        st_now["__state__"]["last_snapshot_ts"] = _t.time()
        self._cfg.write_text(json.dumps(st_now), encoding="utf-8")

        # Прогон 2: 10 МБ через A → доминирование A (без события)
        with self._patch_all(stats=self._stats(100 + 5 * MB, 100 + 5 * MB,
                                               0, 0)):
            res = tw.run_once()
        self.assertEqual(res["events"], [])
        self.assertEqual(res["dominant"]["tag"], TAG_A)

        # Прогон 3: трафик переехал на B (16 МБ против 10 МБ A в окне —
        # доля 61% ≥ порога) → смена доминирующей: человекочитаемый
        # заголовок «Режим: активная нода B» + «Переключение ноды: A → B»
        with self._patch_all(stats=self._stats(100 + 5 * MB, 100 + 5 * MB,
                                               9 * MB, 7 * MB)):
            res = tw.run_once()
        self.assertIn("traffic_dominant_change", res["events"])
        det = next(d for ev, d, _ in self._details
                   if ev == "traffic_dominant_change")
        self.assertIn(
            f"RoundRobin: активная нода <b><code>{KEY_B}</code></b>", det)
        self.assertIn(
            f"Переключение ноды: <code>{KEY_A}</code> → "
            f"<b><code>{KEY_B}</code></b>", det)
        extra = next(x for ev, _, x in self._details
                     if ev == "traffic_dominant_change")
        self.assertEqual(extra["strategy"], "RoundRobin")
        self.assertEqual(extra["node_from"], KEY_A)
        self.assertEqual(extra["node_to"], KEY_B)
        st = json.loads(self._cfg.read_text())["__state__"]
        self.assertEqual(st["dominant_tag"], TAG_B)

        # Прогон 4: окно дайджеста истекло → snapshot + сброс накопителя
        st_now = json.loads(self._cfg.read_text())
        st_now["__state__"]["last_snapshot_ts"] = 0
        self._cfg.write_text(json.dumps(st_now), encoding="utf-8")
        with self._patch_all(stats=self._stats(100 + 5 * MB + 10,
                                               100 + 5 * MB + 10,
                                               5 * MB + 10, 6 * MB + 10)):
            res = tw.run_once()
        self.assertIn("traffic_snapshot", res["events"])
        st = json.loads(self._cfg.read_text())["__state__"]
        self.assertEqual(st["acc"], {})          # окно закрыто
        self.assertEqual(st["dominant_tag"], "")  # доминирование сброшено

    def test_starve_event(self):
        import chimera.modules.exit_traffic_watcher as tw
        cfg = {"enabled": True, "snapshot_hours": 0,
               "starve_hours": 0.01, "starve_min_total_mb": 1,
               "min_gap_min": 0}
        self._cfg.write_text(json.dumps(cfg), encoding="utf-8")

        # Прогон 1: весь трафик через A, B в selector молчит
        with self._patch_all(stats=self._stats(2 * MB, 2 * MB, 0, 0)):
            tw.run_once()
        self.assertEqual(self._events, [])   # таймер заведён, ещё рано

        # Прогон 2 спустя starve_hours: B голодает
        import time as _t
        st_now = json.loads(self._cfg.read_text())
        st_now["__state__"]["updated"] = ""
        # сдвигаем метку заведения таймера в прошлое (чисто для теста)
        for k, v in st_now["__state__"].get("zero_since", {}).items():
            st_now["__state__"]["zero_since"][k] = _t.time() - 60
        self._cfg.write_text(json.dumps(st_now), encoding="utf-8")
        with self._patch_all(stats=self._stats(4 * MB, 4 * MB, 0, 0)):
            tw.run_once()
        self.assertIn("traffic_node_starved", self._events)

    def test_stats_error_after_three_fails(self):
        import chimera.modules.exit_traffic_watcher as tw
        cfg = {"enabled": True, "snapshot_hours": 0, "min_gap_min": 0}
        self._cfg.write_text(json.dumps(cfg), encoding="utf-8")
        # stats=None трижды → traffic_stats_error
        for _ in range(3):
            with self._patch_all(stats=None):
                res = tw.run_once()
        self.assertIn("traffic_stats_error", self._events)
        self.assertFalse(res["stats_ok"])
        # четвёртый раз — не чаще раза в сутки, молчим
        self._events.clear()
        with self._patch_all(stats=None):
            tw.run_once()
        self.assertEqual(self._events, [])

    def test_per_user_snapshot_section(self):
        """per_user=True: дайджест содержит разбор по пользователям из
        access.log (патченный путь)."""
        import chimera.modules.exit_traffic_watcher as tw
        acc_log = self._tmpdir / "access.log"
        acc_log.write_text(
            f"2026/11/20 10:00:00 1.2.3.4:1 accepted tcp:x.com:443 [{TAG_A}] email: andrew@x\n",
            encoding="utf-8")
        cfg = {"enabled": True, "snapshot_hours": 12, "min_gap_min": 0,
               "per_user": True, "per_user_top": 5}
        self._cfg.write_text(json.dumps(cfg), encoding="utf-8")
        with self._patch_all(stats=self._stats(2 * MB, 2 * MB, 0, 0)), \
             patch.multiple(tw, ACCESS_LOG=acc_log):
            tw.run_once()   # база
        with self._patch_all(stats=self._stats(2 * MB + 5, 2 * MB + 5,
                                               0, 0)), \
             patch.multiple(tw, ACCESS_LOG=acc_log):
            # окно дайджеста истекло (last_snapshot_ts=0)
            st_now = json.loads(self._cfg.read_text())
            st_now["__state__"]["last_snapshot_ts"] = 0
            self._cfg.write_text(json.dumps(st_now), encoding="utf-8")
            tw.run_once()
        # событие ушло; текст дайджеста содержит пользователя —
        # проверяем через факт отправки события snapshot
        self.assertIn("traffic_snapshot", self._events)


class TestRunOnceProbe(unittest.TestCase):
    """run_once + активные пробы: события через общий _emit (фильтр/
    quiet/min_gap), персист probe-состояния (в т.ч. при отказе Stats
    API), метки last_traffic_ts, {node}-плейсхолдер, вкл/выкл probe."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "exit_traffic_watcher.json"
        self._state = self._tmpdir / "state.json"
        self._sb = self._tmpdir / "smart_balancer.json"
        self._xray_cfg = self._tmpdir / "config.json"
        self._hm = self._tmpdir / "node-health-state.json"
        self._state.write_text(json.dumps(
            {"chain_nodes": [ND_A, ND_B]}), encoding="utf-8")
        self._xray_cfg.write_text(json.dumps(
            {"routing": {"balancers": [{
                "tag": "chain-balancer",
                "selector": [TAG_A, TAG_B],
                "strategy": {"type": "roundRobin"}}]}}),
            encoding="utf-8")
        self._events: list[str] = []
        self._details: list[tuple] = []

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_all(self, stats=None, probe=None, probe_fn=None):
        """probe — готовые результаты; probe_fn — фейк-функция проб
        (для assert not called)."""
        import chimera.modules.exit_traffic_watcher as tw

        def fake_notify(event, detail, cfg, extra=None):
            self._events.append(event)
            self._details.append((event, detail, extra))
            return True

        return patch.multiple(
            tw, TW_CFG_FILE=self._cfg, STATE_FILE=self._state,
            SB_STATE_FILE=self._sb, XRAY_CFG_CANDIDATES=(self._xray_cfg,),
            HM_STATE_FILE=self._hm,
            AWG_STATE_FILE=self._tmpdir / "awg-absent.json",
            MIERU_STATE_FILE=self._tmpdir / "mieru-absent.json",
            NAIVE_STATE_FILE=self._tmpdir / "naive-absent.json",
            _tw_query_stats=lambda timeout=8: stats,
            _tw_probe_nodes=probe_fn if probe_fn is not None
            else (lambda chain_nodes, cfg: probe),
            _tw_notify_event=fake_notify,
            _tw_ip_link_stats=lambda ifaces: {},
            _tw_iptables_nat_output=lambda: {},
            _tw_systemctl_show_ipacct=lambda unit: {
                "IPAccounting": False, "IPIngressBytes": None,
                "IPEgressBytes": None},
            _tw_log=lambda *a, **kw: None)

    def _stats(self, a_up=0, a_dn=0, b_up=0, b_dn=0) -> dict:
        return {TAG_A: {"up": a_up, "down": a_dn},
                TAG_B: {"up": b_up, "down": b_dn}}

    def _probe(self, ok_a=True, ms_a=40, ok_b=True, ms_b=40) -> dict:
        return {TAG_A: {"ok": ok_a, "ms": ms_a if ok_a else None,
                        "err": "" if ok_a else "timeout"},
                TAG_B: {"ok": ok_b, "ms": ms_b if ok_b else None,
                        "err": "" if ok_b else "timeout"}}

    def _cfg_write(self, **kw):
        cfg = {"enabled": True, "snapshot_hours": 0, "min_gap_min": 0,
               "aliases": {KEY_A: "RU1"}, "starve_hours": 0}
        cfg.update(kw)
        self._cfg.write_text(json.dumps(cfg), encoding="utf-8")

    def _state_of(self) -> dict:
        return json.loads(self._cfg.read_text())["__state__"]

    def test_dead_node_down_event_and_state_persisted(self):
        """(a) нода умирает (2 неудачи подряд) → traffic_node_down через
        _tw_notify_event + probe-состояние в __state__."""
        import chimera.modules.exit_traffic_watcher as tw
        self._cfg_write()
        stats = self._stats(100, 100, 100, 100)
        with self._patch_all(stats=stats, probe=self._probe()):
            res = tw.run_once()
        self.assertEqual(res["events"], [])   # 1-я проба прошла
        with self._patch_all(stats=stats, probe=self._probe(ok_a=False)):
            tw.run_once()                     # 1-я неудача — молчим
        self.assertEqual(self._events, [])
        with self._patch_all(stats=stats, probe=self._probe(ok_a=False)):
            res = tw.run_once()               # 2-я подряд — down
        self.assertIn("traffic_node_down", res["events"])
        det = next(d for ev, d, _ in self._details
                   if ev == "traffic_node_down")
        self.assertIn(f"Нода <b><code>RU1</code></b> ({KEY_A}) недоступна",
                      det)
        self.assertIn("2 прогонов подряд (timeout)", det)
        extra = next(x for ev, _, x in self._details
                     if ev == "traffic_node_down")
        self.assertEqual(extra, {"node": "RU1"})
        st = self._state_of()
        self.assertEqual(st["probe_fails"][TAG_A], 2)
        self.assertEqual(st["probe_status"][TAG_A], "down")

    def test_probe_disabled_no_calls(self):
        """(b) probe=false в cfg → пробы не выполняются вовсе."""
        import chimera.modules.exit_traffic_watcher as tw
        self._cfg_write(probe=False)
        probe_fn = MagicMock()
        with self._patch_all(stats=self._stats(1, 1, 1, 1),
                             probe_fn=probe_fn):
            tw.run_once()
        probe_fn.assert_not_called()

    def test_stats_fail_path_persists_probe_state(self):
        """(c) Stats API недоступен → ранний выход НЕ теряет
        probe-состояние этого прогона (down-событие проб всё равно
        уходит — пробы не зависят от Stats API)."""
        import chimera.modules.exit_traffic_watcher as tw
        self._cfg_write()
        with self._patch_all(stats=None, probe=self._probe(ok_a=False)):
            tw.run_once()
        with self._patch_all(stats=None, probe=self._probe(ok_a=False)):
            res = tw.run_once()
        self.assertFalse(res["stats_ok"])
        self.assertIn("traffic_node_down", res["events"])
        st = self._state_of()
        self.assertEqual(st["probe_fails"][TAG_A], 2)
        self.assertEqual(st["probe_status"][TAG_A], "down")
        self.assertEqual(st["stats_fails"], 2)

    def test_last_traffic_ts_context_in_down_message(self):
        """(d) нода несла трафик → умерла: down-уведа содержит «Последний
        трафик через ноду: N мин назад»; без трафика — «в этом окне
        не было»; метка обновляется только на живом трафике."""
        import time as _t
        import chimera.modules.exit_traffic_watcher as tw
        self._cfg_write()
        # прогон 1: A несла трафик (дельта > 0), обе ноды живы
        with self._patch_all(stats=self._stats(10, 10, 5, 5),
                             probe=self._probe()):
            tw.run_once()
        st = self._state_of()
        self.assertAlmostEqual(st["last_traffic_ts"][TAG_A], _t.time(),
                               delta=5)
        # прогоны 2-3: A умирает, счётчики A не двигаются
        for _ in range(2):
            with self._patch_all(stats=self._stats(10, 10, 10, 15),
                                 probe=self._probe(ok_a=False)):
                tw.run_once()
        det = next(d for ev, d, _ in self._details
                   if ev == "traffic_node_down")
        self.assertIn("Последний трафик через ноду:", det)
        self.assertIn("мин назад", det)
        # B без собственного трафика с базового прогона... нет: B
        # получает дельту; отдельно проверяем ноду БЕЗ трафика —
        # сбрасываем метки и роняем B (A жива, guard не мешает)
        st_now = json.loads(self._cfg.read_text())
        st_now["__state__"]["last_traffic_ts"] = {}
        st_now["__state__"]["probe_fails"] = {TAG_B: 1}
        st_now["__state__"]["probe_status"] = {TAG_B: "ok"}
        self._cfg.write_text(json.dumps(st_now), encoding="utf-8")
        with self._patch_all(stats=self._stats(10, 10, 10, 15),
                             probe=self._probe(ok_b=False)):
            tw.run_once()
        det_b = self._details[-1][1]
        self.assertIn("Трафика через ноду в этом окне не было.", det_b)

    def test_recovery_run_sends_node_up(self):
        """(e) после down — проба снова ОК → traffic_node_up
        («восстановлена... после отказа»)."""
        import chimera.modules.exit_traffic_watcher as tw
        self._cfg_write()
        stats = self._stats(100, 100, 100, 100)
        for _ in range(2):
            with self._patch_all(stats=stats, probe=self._probe(ok_a=False)):
                tw.run_once()
        self.assertIn("traffic_node_down", self._events)
        with self._patch_all(stats=stats, probe=self._probe()):
            res = tw.run_once()
        self.assertIn("traffic_node_up", res["events"])
        det = next(d for ev, d, _ in self._details
                   if ev == "traffic_node_up")
        self.assertIn(
            f"Нода <b><code>RU1</code></b> ({KEY_A}) восстановлена: "
            f"RTT 40 мс (после отказа).", det)
        st = self._state_of()
        self.assertEqual(st["probe_status"][TAG_A], "ok")
        self.assertEqual(st["probe_fails"][TAG_A], 0)

    def test_all_nodes_down_local_event(self):
        """Все ноды разом недоступны → «локальная проблема», отдельные
        down-уведы подавлены; восстановление связи — local_recovery."""
        import chimera.modules.exit_traffic_watcher as tw
        self._cfg_write()
        stats = self._stats(100, 100, 100, 100)
        with self._patch_all(stats=stats,
                             probe=self._probe(ok_a=False, ok_b=False)):
            res = tw.run_once()
        self.assertIn("traffic_node_down", res["events"])
        det = next(d for ev, d, _ in self._details
                   if ev == "traffic_node_down")
        self.assertIn("вероятна локальная проблема", det)
        self.assertIn("Уведы по отдельным нодам подавлены", det)
        # вторая итерация — анти-спам, молчим
        with self._patch_all(stats=stats,
                             probe=self._probe(ok_a=False, ok_b=False)):
            res = tw.run_once()
        self.assertEqual(res["events"], [])
        # связь вернулась (B жива) → local_recovery
        with self._patch_all(stats=stats,
                             probe=self._probe(ok_a=False)):
            res = tw.run_once()
        self.assertIn("traffic_node_up", res["events"])
        det = next(d for ev, d, _ in self._details
                   if ev == "traffic_node_up")
        self.assertIn("Связь с exit-нодами восстановлена: 1 из 2", det)

    def test_hm_verdict_enriches_down_message(self):
        """Health Monitor уже считает ноду DOWN → довесок
        «(Health Monitor: DOWN)» в down-уведе."""
        import chimera.modules.exit_traffic_watcher as tw
        self._cfg_write()
        self._hm.write_text(json.dumps({KEY_A: {"up": False}}),
                            encoding="utf-8")
        stats = self._stats(100, 100, 100, 100)
        for _ in range(2):
            with self._patch_all(stats=stats, probe=self._probe(ok_a=False)):
                tw.run_once()
        det = next(d for ev, d, _ in self._details
                   if ev == "traffic_node_down")
        self.assertIn("(Health Monitor: DOWN)", det)


class TestTgBotMenuIntegration(unittest.TestCase):
    """Интеграция с «менюшкой» Telegram-уведомлений (управляемость
    событий наблюдателя — суть кейса №8)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_watcher_events_in_event_labels(self):
        from chimera.modules import tg_bot
        import inspect, re
        src = inspect.getsource(tg_bot.do_manage_telegram)
        m_labels = re.search(r"event_labels = \{(.*?)\}", src, re.S)
        self.assertIsNotNone(m_labels, "event_labels не найден")
        body = m_labels.group(1)
        for ev in ("traffic_dominant_change", "traffic_snapshot",
                   "traffic_node_starved", "traffic_stats_error",
                   "traffic_node_down", "traffic_node_degraded",
                   "traffic_node_up"):
            self.assertIn(f'"{ev}"', body, f"{ev} отсутствует в event_labels")

    def test_ev_keys_labels_aligned(self):
        from chimera.modules import tg_bot
        import inspect, re
        src = inspect.getsource(tg_bot.do_manage_telegram)
        keys = re.findall(r'"([a-z_0-9]+)"',
                          re.search(r"ev_keys = \[(.*?)\]",
                                    src, re.S).group(1))
        labels = re.findall(r'"([^"]+)"',
                            re.search(r"ev_labels = \[(.*?)\]\n\s+events",
                                      src, re.S).group(1))
        self.assertEqual(len(keys), len(labels))
        self.assertIn("traffic_dominant_change", keys)
        idx = keys.index("traffic_dominant_change")
        self.assertIn("доминирующая", labels[idx])
        # новые события проб — в том же порядке keys↔labels
        for ev, lbl in (("traffic_node_down", "недоступна"),
                        ("traffic_node_degraded", "тупит"),
                        ("traffic_node_up", "восстановлена")):
            self.assertIn(ev, keys)
            self.assertIn(lbl, labels[keys.index(ev)])

    def test_icons_for_watcher_events(self):
        from chimera.modules import tg_bot
        import inspect
        src = inspect.getsource(tg_bot.tg_notify_event)
        for ev in ("traffic_dominant_change", "traffic_snapshot",
                   "traffic_node_starved", "traffic_stats_error",
                   "traffic_node_down", "traffic_node_degraded",
                   "traffic_node_up"):
            self.assertIn(f'"{ev}"', src, f"нет иконки для {ev}")

    def test_tg_menu_item_seven(self):
        """Пункт [7] в меню Telegram-уведомлений открывает
        трафик-наблюдатель (симметрия пункту [6] для exit_switch_watcher)."""
        from chimera.modules import tg_bot
        import inspect
        src = inspect.getsource(tg_bot.do_manage_telegram)
        self.assertIn('ch == "7"', src)
        self.assertIn("do_traffic_watcher_menu", src)


class TestCoreMenuIntegration(unittest.TestCase):
    """Интеграция с TUI монолита _core (канон test_dns_redirect:
    строковые ассерты на исходник — пункт меню и импорт залочены от
    потери при рефакторинге)."""

    def test_menu_item_and_import(self):
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text(
            encoding="utf-8")
        self.assertIn(
            "from chimera.modules.exit_traffic_watcher import do_traffic_watcher_menu",
            src, "импорт do_traffic_watcher_menu отсутствует в _core.py")
        self.assertIn('_box_item("TW"', src,
                      "пункт меню TW отсутствует в _core.py")
        self.assertIn('ch.lower() == "tw"', src,
                      "обработчик пункта TW отсутствует в _core.py")


# ══════════════════════════════════════════════════════════════════════════════
#  МУЛЬТИТРАНСПОРТНОСТЬ (11.11.2026): AWG/Mieru/Naive каскады
# ══════════════════════════════════════════════════════════════════════════════

IP_LINK_LIVE = """14: awg1: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1280 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/none
    RX:  bytes packets errors dropped  missed   mcast
         1214453   16253      0       0       0       0
    TX:  bytes packets errors dropped carrier collsns
      12199154  106539     0       0       0       0
15: awg2: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1280 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/none
    RX:  bytes packets errors dropped  missed   mcast
         1086570   16940      0       0       0       0
    TX:  bytes packets errors dropped carrier collsns
      12160378  104672     0       0       0       0
"""

IPTABLES_LIVE = """Chain OUTPUT (policy ACCEPT 9903556 packets, 752798568 bytes)
    pkts      bytes target     prot opt in     out     source               destination
   41692 36988152 RETURN     all  --  any    any     anywhere             anywhere             owner UID match dnscrypt
       0        0 REDIRECT   tcp  --  any    any     anywhere             anywhere             cgroup system.slice/mita.service statistic mode random probability 0.36620000005 redir ports 23081
       0        0 REDIRECT   tcp  --  any    any     anywhere             anywhere             cgroup system.slice/mita.service statistic mode random probability 0.50329999998 redir ports 23083
     126     7603 REDIRECT   tcp  --  any    any     anywhere             anywhere             cgroup system.slice/mita.service redir ports 23082
"""

SYSTEMCTL_IPACC_OFF = """IPAccounting=no
IPIngressBytes=[no data]
IPEgressBytes=[no data]
"""

SYSTEMCTL_IPACC_ON = """IPAccounting=yes
IPIngressBytes=987654321
IPEgressBytes=12345678
"""


class TestParsersMultitransport(unittest.TestCase):
    """Парсеры источников мультитранспортности (форматы сняты с живого
    entry RU1 11.11.2026): ip -s link / systemctl show / iptables nat
    / upstream-URL Naive."""

    def test_parse_ip_link_live_format(self):
        import chimera.modules.exit_traffic_watcher as tw
        out = tw._tw_parse_ip_link(IP_LINK_LIVE)
        self.assertEqual(out["awg1"]["rx"], 1214453)
        self.assertEqual(out["awg1"]["tx"], 12199154)
        self.assertEqual(out["awg2"]["rx"], 1086570)
        self.assertEqual(out["awg2"]["tx"], 12160378)

    def test_parse_ip_link_empty_garbage(self):
        import chimera.modules.exit_traffic_watcher as tw
        self.assertEqual(tw._tw_parse_ip_link(""), {})
        self.assertEqual(tw._tw_parse_ip_link("мусор\nбез интерфейсов"), {})

    def test_ip_link_stats_multiple_ifaces_argv(self):
        """Регрессия живого прогона RU1 (LB, 3 слота): iproute2 НЕ
        принимает несколько устройств в одном show — `ip -s link show
        awg1 awg2 awg3` падает («either "dev" is duplicate, or "awg2"
        is a garbage», rc=1, пустой stdout) → счётчики AWG терялись.
        Фейковый ip эмулирует реальную семантику argv: без устройств —
        все ссылки; два+ голых имён — ошибка (ловит старый вызов)."""
        import types
        import chimera.modules.exit_traffic_watcher as tw

        calls = []

        def fake_run(argv, **kw):
            calls.append(list(argv))
            devs = [a for a in argv[4:] if a != "dev"]
            if len(devs) > 1:
                return types.SimpleNamespace(
                    returncode=1, stdout="",
                    stderr='Error: either "dev" is duplicate, '
                           'or "%s" is a garbage.\n' % devs[1])
            return types.SimpleNamespace(returncode=0, stdout=IP_LINK_LIVE,
                                         stderr="")

        with patch.object(tw.subprocess, "run", fake_run):
            got = tw._tw_ip_link_stats(["awg1", "awg2", "awg3"])
        # один вызов, БЕЗ списка устройств в argv
        self.assertEqual(calls, [["ip", "-s", "link", "show"]])
        self.assertEqual(got.get("awg1"), {"rx": 1214453, "tx": 12199154})
        self.assertEqual(got.get("awg2"), {"rx": 1086570, "tx": 12160378})
        # awg3 нет в выводе (нет такого интерфейса) → пропущен
        self.assertNotIn("awg3", got)

    def test_parse_systemctl_show(self):
        import chimera.modules.exit_traffic_watcher as tw
        off = tw._tw_parse_systemctl_show(SYSTEMCTL_IPACC_OFF)
        self.assertFalse(off["IPAccounting"])
        self.assertIsNone(off["IPIngressBytes"])
        self.assertIsNone(off["IPEgressBytes"])
        on = tw._tw_parse_systemctl_show(SYSTEMCTL_IPACC_ON)
        self.assertTrue(on["IPAccounting"])
        self.assertEqual(on["IPIngressBytes"], 987654321)
        self.assertEqual(on["IPEgressBytes"], 12345678)

    def test_parse_iptables_redir(self):
        import chimera.modules.exit_traffic_watcher as tw
        out = tw._tw_parse_iptables_redir(IPTABLES_LIVE)
        self.assertEqual(set(out), {23081, 23083, 23082})
        self.assertEqual(out[23081]["pkts"], 0)
        self.assertEqual(out[23081]["bytes"], 0)
        self.assertEqual(out[23082]["pkts"], 126)
        self.assertEqual(out[23082]["bytes"], 7603)

    def test_parse_iptables_redir_skips_non_redirect(self):
        import chimera.modules.exit_traffic_watcher as tw
        self.assertEqual(tw._tw_parse_iptables_redir(""), {})
        self.assertEqual(
            tw._tw_parse_iptables_redir("  1  2 ACCEPT all -- any any\n"),
            {})

    def test_parse_naive_upstream(self):
        import chimera.modules.exit_traffic_watcher as tw
        u = tw._tw_parse_naive_upstream(
            "https://user:secret@exit.example.com:8443/")
        self.assertEqual(u, {"host": "exit.example.com", "port": 8443})
        # без порта → 443
        u2 = tw._tw_parse_naive_upstream("https://a@b.example.org")
        self.assertEqual(u2, {"host": "b.example.org", "port": 443})
        # битые → None
        self.assertIsNone(tw._tw_parse_naive_upstream(""))
        self.assertIsNone(tw._tw_parse_naive_upstream("not a url"))
        self.assertIsNone(tw._tw_parse_naive_upstream(None))

    def test_cascades_cfg_defaults_and_garbage(self):
        import chimera.modules.exit_traffic_watcher as tw
        # пустой cfg → дефолты
        c = tw._tw_cascades_cfg({})
        self.assertTrue(c["vless"]["traffic"])
        self.assertTrue(c["vless"]["probe"])
        self.assertTrue(c["awg"]["traffic"])
        self.assertFalse(c["awg"]["probe"])
        self.assertTrue(c["mieru"]["traffic"])
        self.assertFalse(c["mieru"]["probe"])
        self.assertEqual(c["mieru"]["bytes_source"], "auto")
        self.assertFalse(c["naive"]["traffic"])
        self.assertTrue(c["naive"]["probe"])
        # битые значения нормализуются
        bad = {"cascades": {"mieru": {"bytes_source": "?????"},
                            "awg": {"traffic": None, "probe": 1},
                            "vless": "не словарь"}}
        c2 = tw._tw_cascades_cfg(bad)
        self.assertEqual(c2["mieru"]["bytes_source"], "auto")
        self.assertTrue(c2["awg"]["traffic"])   # None игнор → дефолт
        self.assertTrue(c2["awg"]["probe"])     # 1 → истина
        self.assertTrue(c2["vless"]["traffic"]) # не dict → дефолт

    def test_cascade_acc_slices(self):
        import chimera.modules.exit_traffic_watcher as tw
        acc = {"chain-exit-1": {"up": 1, "down": 1},
               "chain-exit-2": {"up": 2, "down": 2},
               "awg:pl1": {"up": 3, "down": 3},
               "awg:de": {"up": 4, "down": 4},
               "mieru:de1": {"up": 5, "down": 5},
               "naive:upstream": {"up": 6, "down": 6}}
        self.assertEqual(set(tw._tw_cascade_acc(acc, "")),
                         {"chain-exit-1", "chain-exit-2"})
        self.assertEqual(set(tw._tw_cascade_acc(acc, "awg:")),
                         {"awg:pl1", "awg:de"})
        self.assertEqual(set(tw._tw_cascade_acc(acc, "mieru:")),
                         {"mieru:de1"})
        self.assertEqual(set(tw._tw_cascade_acc(acc, "naive:")),
                         {"naive:upstream"})
        self.assertEqual(tw._tw_cascade_acc({}, ""), {})
        self.assertEqual(tw._tw_cascade_acc(None, "awg:"), {})

    def test_state_v2_migration(self):
        import chimera.modules.exit_traffic_watcher as tw
        old = {"dominant_tag": "chain-exit-2", "stats_fails": 3,
               "acc": {"chain-exit-2": {"up": 1, "down": 1}}}
        st = tw._tw_state_v2(old)
        self.assertEqual(st["dominant_tags"], {"vless": "chain-exit-2"})
        self.assertEqual(st["stats_fails_map"], {"vless": 3})
        # плоские ключи сохраняются (откат версии ниже git)
        self.assertEqual(st["dominant_tag"], "chain-exit-2")
        self.assertEqual(st["stats_fails"], 3)
        # вход не мутирован
        self.assertNotIn("dominant_tags", old)
        # idempotent
        st2 = tw._tw_state_v2(st)
        self.assertEqual(st2["dominant_tags"], {"vless": "chain-exit-2"})
        # новый формат не перетирается плоским
        new = {"dominant_tags": {"vless": "a", "awg": "awg:pl1"},
               "stats_fails_map": {"vless": 0, "awg": 1},
               "dominant_tag": "a", "stats_fails": 0}
        st3 = tw._tw_state_v2(new)
        self.assertEqual(st3["dominant_tags"],
                         {"vless": "a", "awg": "awg:pl1"})

    def test_fmt_metric_and_noun(self):
        import chimera.modules.exit_traffic_watcher as tw
        self.assertEqual(tw._tw_fmt_metric("bytes", 5 * 1024 * 1024),
                         "5 МБ")
        self.assertEqual(tw._tw_fmt_metric("conn", 3456), "3 456 соед.")
        self.assertEqual(tw._tw_fmt_metric("conn", 0), "0 соед.")
        self.assertEqual(tw._tw_metric_noun("bytes"), "окна")
        self.assertEqual(tw._tw_metric_noun("conn"), "соединений окна")

    def test_awg_strategy_label(self):
        import chimera.modules.exit_traffic_watcher as tw
        self.assertEqual(tw._tw_awg_strategy_label(
            {"lb_mode": True, "lb_strategy": "smart"}), "AWG Smart")
        self.assertEqual(tw._tw_awg_strategy_label(
            {"lb_mode": True, "lb_strategy": "rr"}), "AWG RoundRobin")
        self.assertEqual(tw._tw_awg_strategy_label(
            {"lb_mode": True, "lb_strategy": "prio"}),
            "AWG Prio (active-backup)")
        self.assertEqual(tw._tw_awg_strategy_label(
            {"lb_mode": True, "lb_pinned": "pl1"}), "AWG Pinned (pl1)")
        self.assertEqual(tw._tw_awg_strategy_label(
            {"lb_mode": False}), "AWG-каскад (failover)")
        self.assertEqual(tw._tw_awg_strategy_label({}), "AWG-каскад")


class TestNaiveProbeMachine(unittest.TestCase):
    """Машина состояний Naive upstream: первый прогон молчит, down после
    probe_fails неудач, up при восстановлении, держит down при
    недоборе порога, флап не порождает событий."""

    def _cfg(self, **kw):
        base = {"probe_fails": 2}
        base.update(kw)
        return base

    def test_first_run_silent(self):
        import chimera.modules.exit_traffic_watcher as tw
        st, ev = tw._tw_naive_probe_update(
            {}, {"ok": False, "ms": None, "err": "timeout"},
            self._cfg(), 1000.0)
        self.assertEqual(ev, [])
        self.assertEqual(st["naive_fails"], 1)
        self.assertEqual(st["naive_status"], "ok")

    def test_down_after_threshold_then_up(self):
        import chimera.modules.exit_traffic_watcher as tw
        st, ev = tw._tw_naive_probe_update(
            {"naive_fails": 1, "naive_status": "ok"},
            {"ok": False, "ms": None, "err": "timeout"},
            self._cfg(), 1000.0)
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["event"], "naive_upstream_down")
        self.assertEqual(ev[0]["fails"], 2)
        self.assertEqual(st["naive_status"], "down")
        # восстановление
        st2, ev2 = tw._tw_naive_probe_update(
            {"naive_fails": 2, "naive_status": "down"},
            {"ok": True, "ms": 120, "err": ""},
            self._cfg(), 2000.0)
        self.assertEqual(len(ev2), 1)
        self.assertEqual(ev2[0]["event"], "naive_upstream_up")
        self.assertEqual(ev2[0]["ms"], 120)
        self.assertEqual(st2["naive_status"], "ok")
        self.assertEqual(st2["naive_fails"], 0)

    def test_hold_down_without_threshold_reached(self):
        import chimera.modules.exit_traffic_watcher as tw
        # после down одиночный ok → up; затем not-ok → статус ok (1 < 2)
        st, ev = tw._tw_naive_probe_update(
            {"naive_fails": 2, "naive_status": "down"},
            {"ok": True, "ms": 50, "err": ""},
            self._cfg(), 1000.0)
        self.assertEqual([e["event"] for e in ev], ["naive_upstream_up"])
        st2, ev2 = tw._tw_naive_probe_update(
            st, {"ok": False, "ms": None, "err": "refused"},
            self._cfg(), 2000.0)
        self.assertEqual(ev2, [])
        self.assertEqual(st2["naive_status"], "ok")
        self.assertEqual(st2["naive_fails"], 1)

    def test_none_result_no_events(self):
        import chimera.modules.exit_traffic_watcher as tw
        st, ev = tw._tw_naive_probe_update(
            {"naive_fails": 1, "naive_status": "ok"}, None,
            self._cfg(), 1000.0)
        self.assertEqual(ev, [])
        self.assertEqual(st["naive_fails"], 1)

    def test_naive_event_text(self):
        import chimera.modules.exit_traffic_watcher as tw
        d = tw._tw_naive_event_text(
            {"event": "naive_upstream_down", "fails": 2,
             "err": "timeout"}, "exit.example.com:443")
        self.assertIn("exit.example.com:443", d)
        self.assertIn("2 прогонов подряд", d)
        self.assertIn("timeout", d)
        u = tw._tw_naive_event_text(
            {"event": "naive_upstream_up", "ms": 120},
            "exit.example.com:443")
        self.assertIn("восстановлен", u)
        self.assertIn("RTT 120 мс", u)


# ─── фикстуры источников (примерные, не прод-инфра) ───────────────────────────

AWG_STATE_LB = {
    "cascade_role": "entry",
    "cascade_active_exit": "pl1",
    "lb_mode": True,
    "lb_strategy": "smart",
    "lb_pinned": "",
    "cascade_exits": [
        {"name": "pl1", "endpoint": "10.0.0.1", "port": 52831},
        {"name": "de", "endpoint": "10.0.0.2", "port": 52831},
        {"name": "nl1", "endpoint": "10.0.0.3", "port": 52831},
    ],
    "lb": {
        "slots_snapshot": {"pl1": 1, "de": 2, "nl1": 3},
        "alive": ["pl1", "nl1"],
        "probes": {
            "pl1": {"alive": True, "rtt_ms": 55},
            "de": {"alive": False, "rtt_ms": None},
            "nl1": {"alive": True, "rtt_ms": 49},
        },
    },
}

MIERU_STATE = {
    "role": "entry",
    "strategy": "smart",
    "exits": [
        {"id": "exit-1-de1", "label": "de1", "host": "10.1.0.1",
         "port": 2012, "enabled": True, "healthy": True,
         "redsocks_port": 23081},
        {"id": "exit-1-nl1", "label": "nl1", "host": "10.1.0.2",
         "port": 2012, "enabled": True, "healthy": False,
         "redsocks_port": 23082},
        {"id": "exit-1-pl1", "label": "pl1", "host": "10.1.0.3",
         "port": 2012, "enabled": False, "healthy": False,
         "redsocks_port": 23083},
    ],
}


class TestSourcesMultitransport(unittest.TestCase):
    """Источники AWG/Mieru/Naive с патченными путями и IO-обёртками."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._awg = self._tmpdir / "awg_standalone_state.json"
        self._mieru = self._tmpdir / "mieru_cascade.json"
        self._naive = self._tmpdir / "naiveproxy.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_awg_source_lb(self):
        import chimera.modules.exit_traffic_watcher as tw
        self._awg.write_text(json.dumps(AWG_STATE_LB), encoding="utf-8")
        link = {"awg1": {"rx": 100, "tx": 200},
                "awg3": {"rx": 300, "tx": 400}}
        with patch.multiple(tw, AWG_STATE_FILE=self._awg,
                            _tw_ip_link_stats=lambda ifaces: link):
            src = tw._tw_awg_source()
        self.assertIsNotNone(src)
        self.assertEqual(set(src["nodes"]),
                         {"awg:pl1", "awg:de", "awg:nl1"})
        # счётчики: up=tx, down=rx
        self.assertEqual(src["counters"]["awg:pl1"], {"up": 200, "down": 100})
        self.assertEqual(src["counters"]["awg:nl1"], {"up": 400, "down": 300})
        # слот 2 (de) не в link → без счётчиков (туннель упал)
        self.assertNotIn("awg:de", src["counters"])
        # ротация = живые; мёртвый de вне
        self.assertEqual(src["selector"], ["awg:pl1", "awg:nl1"])
        self.assertEqual(src["dead"], {"awg:de": True})
        self.assertEqual(src["strategy"], "AWG Smart")
        # probe_results из lb.probes
        self.assertTrue(src["probe_results"]["awg:pl1"]["ok"])
        self.assertFalse(src["probe_results"]["awg:de"]["ok"])
        self.assertEqual(src["probe_results"]["awg:nl1"]["ms"], 49)

    def test_awg_source_failover_mode(self):
        """Failover + УСТАРЕВШИЕ слоты (LB был, выключен): awg1 — только
        активному exit; слоты de→awg2/nl1→awg3 из прошлого LB — мимо
        (туннели awg2+ снесены lb_deactivate; живой кейс RU2)."""
        import chimera.modules.exit_traffic_watcher as tw
        st = dict(AWG_STATE_LB)
        st["lb_mode"] = False
        self._awg.write_text(json.dumps(st), encoding="utf-8")
        link = {"awg1": {"rx": 100, "tx": 200},
                "awg2": {"rx": 999, "tx": 999},
                "awg3": {"rx": 777, "tx": 777}}
        with patch.multiple(tw, AWG_STATE_FILE=self._awg,
                            _tw_ip_link_stats=lambda ifaces: link):
            src = tw._tw_awg_source()
        self.assertIsNotNone(src)
        # failover: ротация = активный exit
        self.assertEqual(src["selector"], ["awg:pl1"])
        self.assertEqual(src["dead"], {"awg:de": True, "awg:nl1": True})
        self.assertEqual(src["strategy"], "AWG-каскад (failover)")
        # счётчики ТОЛЬКО активному: awg1 принадлежит pl1, фантомных
        # байтов у неактивных (устаревшие слоты awg2/awg3) — нет
        self.assertEqual(src["counters"],
                         {"awg:pl1": {"up": 200, "down": 100}})
        self.assertEqual(src["nodes"]["awg:pl1"]["iface"], "awg1")
        self.assertEqual(src["nodes"]["awg:de"]["iface"], "")
        self.assertEqual(src["nodes"]["awg:nl1"]["iface"], "")

    def test_awg_source_failover_no_lb_tree(self):
        """Чистый failover без lb-поддерева (LB никогда не включался):
        счётчики awg1 — только активному exit, запрос интерфейсов —
        ровно [awg1] (живой кейс RU2: активный de, exits pl1/de/nl1)."""
        import chimera.modules.exit_traffic_watcher as tw
        st = {"cascade_role": "entry", "cascade_active_exit": "de",
              "lb_mode": False,
              "cascade_exits": AWG_STATE_LB["cascade_exits"]}
        self._awg.write_text(json.dumps(st), encoding="utf-8")
        link = {"awg1": {"rx": 500, "tx": 900},
                "awg2": {"rx": 111, "tx": 222}}
        seen: list = []

        def fake_link(ifaces):
            seen.append(list(ifaces))
            return link

        with patch.multiple(tw, AWG_STATE_FILE=self._awg,
                            _tw_ip_link_stats=fake_link):
            src = tw._tw_awg_source()
        self.assertIsNotNone(src)
        self.assertEqual(src["selector"], ["awg:de"])
        self.assertEqual(src["dead"], {"awg:pl1": True, "awg:nl1": True})
        self.assertEqual(src["counters"],
                         {"awg:de": {"up": 900, "down": 500}})
        # _tw_ip_link_stats вызван ровно с [awg1] — единственный туннель
        self.assertEqual(seen, [["awg1"]])

    def test_awg_source_not_entry_or_missing(self):
        import chimera.modules.exit_traffic_watcher as tw
        st = dict(AWG_STATE_LB)
        st["cascade_role"] = "exit"
        self._awg.write_text(json.dumps(st), encoding="utf-8")
        with patch.multiple(tw, AWG_STATE_FILE=self._awg):
            self.assertIsNone(tw._tw_awg_source())
        with patch.multiple(tw, AWG_STATE_FILE=self._tmpdir / "nope.json"):
            self.assertIsNone(tw._tw_awg_source())
        # пустые exits
        st2 = dict(AWG_STATE_LB)
        st2["cascade_exits"] = []
        self._awg.write_text(json.dumps(st2), encoding="utf-8")
        with patch.multiple(tw, AWG_STATE_FILE=self._awg):
            self.assertIsNone(tw._tw_awg_source())

    def test_mieru_source_conn_mode(self):
        import chimera.modules.exit_traffic_watcher as tw
        self._mieru.write_text(json.dumps(MIERU_STATE), encoding="utf-8")
        redir = {23081: {"pkts": 100, "bytes": 6000},
                 23082: {"pkts": 40, "bytes": 2400}}
        with patch.multiple(
                tw, MIERU_STATE_FILE=self._mieru,
                _tw_iptables_nat_output=lambda: redir,
                _tw_systemctl_show_ipacct=lambda unit: {
                    "IPAccounting": False, "IPIngressBytes": None,
                    "IPEgressBytes": None}):
            src = tw._tw_mieru_source("auto")
        self.assertIsNotNone(src)
        # enabled=False (pl1) — вне нод
        self.assertEqual(set(src["nodes"]), {"mieru:de1", "mieru:nl1"})
        self.assertEqual(src["metric"], "conn")
        # pkts правила = новые соединения
        self.assertEqual(src["counters"]["mieru:de1"], {"up": 100, "down": 0})
        self.assertEqual(src["counters"]["mieru:nl1"], {"up": 40, "down": 0})
        # healthy=False у nl1 → вне ротации
        self.assertEqual(src["selector"], ["mieru:de1"])
        self.assertEqual(src["dead"], {"mieru:nl1": True})
        self.assertEqual(src["strategy"], "Mieru Smart")
        self.assertEqual(
            src["probe_targets"],
            [("10.1.0.1", 2012, "mieru:de1"),
             ("10.1.0.2", 2012, "mieru:nl1")])

    def test_mieru_source_ipaccounting_mode(self):
        import chimera.modules.exit_traffic_watcher as tw
        self._mieru.write_text(json.dumps(MIERU_STATE), encoding="utf-8")
        # MIERU_STATE содержит enabled=False у pl1 → юниты только для
        # de1/nl1; ipacct включён у обоих → байты
        def fake_show(unit):
            if "de1" in unit:
                return {"IPAccounting": True,
                        "IPIngressBytes": 900, "IPEgressBytes": 100}
            if "nl1" in unit:
                return {"IPAccounting": True,
                        "IPIngressBytes": 400, "IPEgressBytes": 40}
            return {"IPAccounting": False, "IPIngressBytes": None,
                    "IPEgressBytes": None}
        with patch.multiple(
                tw, MIERU_STATE_FILE=self._mieru,
                _tw_systemctl_show_ipacct=fake_show,
                _tw_iptables_nat_output=lambda: {}):
            src = tw._tw_mieru_source("auto")
        self.assertEqual(src["metric"], "bytes")
        self.assertEqual(src["counters"]["mieru:de1"],
                         {"up": 100, "down": 900})
        self.assertEqual(src["counters"]["mieru:nl1"],
                         {"up": 40, "down": 400})

    def test_mieru_source_not_entry(self):
        import chimera.modules.exit_traffic_watcher as tw
        st = dict(MIERU_STATE)
        st["role"] = "exit"
        self._mieru.write_text(json.dumps(st), encoding="utf-8")
        with patch.multiple(tw, MIERU_STATE_FILE=self._mieru):
            self.assertIsNone(tw._tw_mieru_source("auto"))
        with patch.multiple(tw, MIERU_STATE_FILE=self._tmpdir / "no.json"):
            self.assertIsNone(tw._tw_mieru_source("auto"))

    def test_naive_source(self):
        import chimera.modules.exit_traffic_watcher as tw
        self._naive.write_text(json.dumps(
            {"upstream": "https://u:p@naive-exit.example.com:443/"}),
            encoding="utf-8")
        with patch.multiple(tw, NAIVE_STATE_FILE=self._naive):
            src = tw._tw_naive_source()
        self.assertIsNotNone(src)
        nd = src["nodes"]["naive:upstream"]
        self.assertEqual(nd["host"], "naive-exit.example.com")
        self.assertEqual(nd["port"], 443)
        self.assertEqual(nd["key"], "naive-exit.example.com:443")
        # нет upstream → None
        self._naive.write_text(json.dumps({"upstream": ""}), encoding="utf-8")
        with patch.multiple(tw, NAIVE_STATE_FILE=self._naive):
            self.assertIsNone(tw._tw_naive_source())
        with patch.multiple(tw, NAIVE_STATE_FILE=self._tmpdir / "no.json"):
            self.assertIsNone(tw._tw_naive_source())

    def test_mieru_set_ipaccounting_calls(self):
        import chimera.modules.exit_traffic_watcher as tw
        self._mieru.write_text(json.dumps(MIERU_STATE), encoding="utf-8")
        calls: list = []

        def fake_run(cmd, **kw):
            calls.append(list(cmd))
            r = MagicMock()
            r.returncode = 0
            r.stderr = ""
            return r
        with patch.multiple(tw, MIERU_STATE_FILE=self._mieru), \
             patch("subprocess.run", side_effect=fake_run):
            ok, msg = tw._tw_mieru_set_ipaccounting(True)
        self.assertTrue(ok)
        # юниты строятся по ВСЕМ exits (enabled и выключенные — юнит
        # mieru-hop@* у шаблона существует и для отключённого exit)
        units = [c[2] for c in calls
                 if len(c) > 2 and c[0] == "systemctl" and c[1] ==
                 "set-property"]
        self.assertEqual(units, ["mieru-hop@exit-1-de1.service",
                                 "mieru-hop@exit-1-nl1.service",
                                 "mieru-hop@exit-1-pl1.service"])
        for c in calls:
            if c[1] == "set-property":
                self.assertIn("IPAccounting=yes", c)
        # пустой каскад → отказ без вызовов
        self._mieru.write_text(json.dumps({"role": "entry", "exits": []}),
                               encoding="utf-8")
        calls.clear()
        with patch.multiple(tw, MIERU_STATE_FILE=self._mieru), \
             patch("subprocess.run", side_effect=fake_run):
            ok2, _ = tw._tw_mieru_set_ipaccounting(False)
        self.assertFalse(ok2)


class TestRunOnceMultiCascade(unittest.TestCase):
    """run_once в мультитранспортном режиме: AWG + Mieru + Naive
    источники (патченные), дельты/доминирование per-cascade, дайджест
    секциями, события naive_upstream_*, миграция старого state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "exit_traffic_watcher.json"
        self._state = self._tmpdir / "state.json"
        self._sb = self._tmpdir / "smart_balancer.json"
        self._xray_cfg = self._tmpdir / "config.json"
        self._awg = self._tmpdir / "awg_standalone_state.json"
        self._mieru = self._tmpdir / "mieru_cascade.json"
        self._naive = self._tmpdir / "naiveproxy.json"
        self._events: list[str] = []
        self._details: list[tuple] = []
        # VLESS-каскад тоже жив (мультикаскадная нода RU1-типа)
        self._state.write_text(json.dumps(
            {"chain_nodes": [ND_A, ND_B]}), encoding="utf-8")
        self._xray_cfg.write_text(json.dumps(
            {"routing": {"balancers": [{
                "tag": "chain-balancer",
                "selector": [TAG_A, TAG_B],
                "strategy": {"type": "roundRobin"}}]}}),
            encoding="utf-8")
        self._awg.write_text(json.dumps(AWG_STATE_LB), encoding="utf-8")
        self._mieru.write_text(json.dumps(MIERU_STATE), encoding="utf-8")
        self._naive.write_text(json.dumps(
            {"upstream": "https://u:p@naive-exit.example.com:443/"}),
            encoding="utf-8")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_all(self, stats=None, link=None, redir=None,
                   naive_probe=None):
        import chimera.modules.exit_traffic_watcher as tw

        def fake_notify(event, detail, cfg, extra=None):
            self._events.append(event)
            self._details.append((event, detail, extra))
            return True

        link = link if link is not None else {
            "awg1": {"rx": 1000, "tx": 2000},
            "awg2": {"rx": 0, "tx": 0},
            "awg3": {"rx": 0, "tx": 0}}
        redir = redir if redir is not None else {
            23081: {"pkts": 50, "bytes": 3000},
            23082: {"pkts": 0, "bytes": 0}}
        return patch.multiple(
            tw, TW_CFG_FILE=self._cfg, STATE_FILE=self._state,
            SB_STATE_FILE=self._sb, XRAY_CFG_CANDIDATES=(self._xray_cfg,),
            AWG_STATE_FILE=self._awg, MIERU_STATE_FILE=self._mieru,
            NAIVE_STATE_FILE=self._naive,
            _tw_query_stats=lambda timeout=8: stats,
            _tw_probe_nodes=lambda chain_nodes, cfg: None,
            _tw_notify_event=fake_notify,
            _tw_ip_link_stats=lambda ifaces: link,
            _tw_iptables_nat_output=lambda: redir,
            _tw_systemctl_show_ipacct=lambda unit: {
                "IPAccounting": False, "IPIngressBytes": None,
                "IPEgressBytes": None},
            _tw_log=lambda *a, **kw: None,
            _tw_tcp_probe=lambda host, port, t: naive_probe
            if host.startswith("naive-exit") else
            {"ok": True, "ms": 10, "err": ""})

    def _stats(self, a_up=0, a_dn=0, b_up=0, b_dn=0) -> dict:
        return {TAG_A: {"up": a_up, "down": a_dn},
                TAG_B: {"up": b_up, "down": b_dn}}

    def _write_cfg(self, **kw):
        cfg = {"enabled": True, "snapshot_hours": 12,
               "dominant_min_share_pct": 60, "dominant_min_mb": 1,
               "min_gap_min": 0, "starve_hours": 0, "probe": False}
        cfg.update(kw)
        self._cfg.write_text(json.dumps(cfg), encoding="utf-8")

    def _bump_snapshot_ts(self):
        """Дайджест-окно не должно закрываться между прогонами теста
        (после базы окно отсчитывается заново — паттерн TestRunOnce)."""
        import time as _t
        st_now = json.loads(self._cfg.read_text())
        st_now["__state__"]["last_snapshot_ts"] = _t.time()
        self._cfg.write_text(json.dumps(st_now), encoding="utf-8")

    def test_multi_deltas_and_snapshot_sections(self):
        """Прогоны 1-2: дельты AWG/Mieru попадают в общий накопитель;
        дайджест — секциями VLESS/AWG/Mieru; доминанты per-cascade."""
        import chimera.modules.exit_traffic_watcher as tw
        import time as _t
        self._write_cfg()
        # Прогон 1 — база (vless + awg + mieru)
        with self._patch_all(stats=self._stats(100, 100, 0, 0)):
            res = tw.run_once()
        self.assertTrue(res["stats_ok"])
        st = json.loads(self._cfg.read_text())["__state__"]
        # общий счётчик-словарь: vless-теги + префиксные
        self.assertEqual(st["counters"]["awg:pl1"]["up"], 2000)
        self.assertEqual(st["counters"]["mieru:de1"]["up"], 50)
        self.assertIn(TAG_A, st["counters"])
        # мигрированный state: оба представления доминант
        self.assertIn("dominant_tags", st)
        # vless-доминанта нет (дельты 200 Б < порога МБ) — плоский ключ
        # не пишется вовсе (прежняя семантика: ключ только при доминанте)
        self.assertEqual(st["stats_fails"], 0)
        self.assertEqual(st["stats_fails_map"]["vless"], 0)

        # Прогон 2: awg-трафик вырос, mieru-коннекты выросли
        self._bump_snapshot_ts()
        with self._patch_all(
                stats=self._stats(100, 100, 0, 0),
                link={"awg1": {"rx": 1000 + 5 * MB, "tx": 2000 + 6 * MB},
                      "awg2": {"rx": 0, "tx": 0},
                      "awg3": {"rx": 300, "tx": 400}},
                redir={23081: {"pkts": 150, "bytes": 9000},
                       23082: {"pkts": 0, "bytes": 0}}):
            res = tw.run_once()
        st = json.loads(self._cfg.read_text())["__state__"]
        # AWG-доминанта pl1 (11 МБ окна, 100%)
        self.assertEqual(st["dominant_tags"].get("awg"), "awg:pl1")
        # Mieru-доминанта de1 (100 коннектов)
        self.assertEqual(st["dominant_tags"].get("mieru"), "mieru:de1")
        # vless-доминанта нет (дельты нулевые) — плоский ключ пуст
        self.assertEqual(st.get("dominant_tag") or "", "")

        # Прогон 3: окно дайджеста истекло → snapshot секциями
        st_now = json.loads(self._cfg.read_text())
        st_now["__state__"]["last_snapshot_ts"] = 0
        self._cfg.write_text(json.dumps(st_now), encoding="utf-8")
        with self._patch_all(
                stats=self._stats(100, 100, 0, 0),
                link={"awg1": {"rx": 1000 + 5 * MB, "tx": 2000 + 6 * MB},
                      "awg2": {"rx": 0, "tx": 0},
                      "awg3": {"rx": 300, "tx": 400}},
                redir={23081: {"pkts": 150, "bytes": 9000}}):
            res = tw.run_once()
        self.assertIn("traffic_snapshot", res["events"])
        snap = next(d for ev, d, _ in self._details
                    if ev == "traffic_snapshot")
        self.assertIn("VLESS-каскад", snap)
        self.assertIn("AWG-каскад", snap)
        self.assertIn("Mieru-каскад", snap)
        self.assertIn("Mieru Smart", snap)
        # соединения, не байты
        self.assertIn("соед.", snap)
        # мёртвый awg:de с пометкой health
        self.assertIn("недоступна (health)", snap)
        # окно закрыто: всё сброшено
        st = json.loads(self._cfg.read_text())["__state__"]
        self.assertEqual(st["acc"], {})
        self.assertEqual(st["dominant_tags"], {})

    def test_awg_dominant_change_event(self):
        """Смена AWG-доминанты → traffic_dominant_change с меткой
        стратегии каскада («AWG Smart: активная нода ...»)."""
        import chimera.modules.exit_traffic_watcher as tw
        import time as _t
        self._write_cfg()
        link1 = {"awg1": {"rx": 0, "tx": 0}, "awg2": {"rx": 0, "tx": 0},
                 "awg3": {"rx": 0, "tx": 0}}
        # прогон 1: база
        with self._patch_all(stats=self._stats(1, 1, 1, 1), link=link1):
            tw.run_once()
        self._bump_snapshot_ts()
        # прогон 2: весь awg-трафик через nl1 (слот 3)
        link2 = {"awg1": {"rx": 0, "tx": 0}, "awg2": {"rx": 0, "tx": 0},
                 "awg3": {"rx": 2 * MB, "tx": 3 * MB}}
        with self._patch_all(stats=self._stats(1, 1, 1, 1), link=link2):
            tw.run_once()
        st = json.loads(self._cfg.read_text())["__state__"]
        self.assertEqual(st["dominant_tags"].get("awg"), "awg:nl1")
        # прогон 3: трафик переезжает на pl1 → событие
        link3 = {"awg1": {"rx": 5 * MB, "tx": 6 * MB},
                 "awg2": {"rx": 0, "tx": 0},
                 "awg3": {"rx": 2 * MB, "tx": 3 * MB}}
        with self._patch_all(stats=self._stats(1, 1, 1, 1), link=link3):
            res = tw.run_once()
        self.assertIn("traffic_dominant_change", res["events"])
        det = next(d for ev, d, _ in self._details
                   if ev == "traffic_dominant_change")
        # первая строка — НОВАЯ нода (формат уведы vless: «активная нода X»
        # где X — куда переехал трафик)
        self.assertIn("AWG Smart: активная нода "
                      "<b><code>pl1</code></b>", det)
        self.assertIn("Переключение ноды: <code>nl1</code> → "
                      "<b><code>pl1</code></b>", det)

    def test_awg_failover_dominance_and_no_phantoms(self):
        """Failover-AWG (RU2-кейс): счётчики только активному exit —
        фантомных нод в acc/counters нет; смена активного (de→nl1,
        awg1 перенацелен и рестартнут — счётчики с нуля) → событие
        «AWG-каскад (failover): активная нода nl1»."""
        import chimera.modules.exit_traffic_watcher as tw
        st = {"cascade_role": "entry", "cascade_active_exit": "de",
              "lb_mode": False,
              "cascade_exits": AWG_STATE_LB["cascade_exits"]}
        self._awg.write_text(json.dumps(st), encoding="utf-8")
        self._write_cfg(snapshot_hours=0)
        # прогон 1: база (de активен)
        with self._patch_all(stats=self._stats(1, 1, 1, 1),
                             link={"awg1": {"rx": 0, "tx": 0}}):
            tw.run_once()
        self._bump_snapshot_ts()
        # прогон 2: весь awg-трафик через awg1 (= активный de)
        with self._patch_all(stats=self._stats(1, 1, 1, 1),
                             link={"awg1": {"rx": 4 * MB, "tx": 2 * MB}}):
            tw.run_once()
        st_w = json.loads(self._cfg.read_text())["__state__"]
        self.assertEqual(st_w["dominant_tags"].get("awg"), "awg:de")
        # фантомных счётчиков у неактивных exit-ов нет
        self.assertNotIn("awg:nl1", st_w["counters"])
        self.assertNotIn("awg:pl1", st_w["counters"])
        self.assertNotIn("awg:nl1", st_w["acc"])
        self._bump_snapshot_ts()
        # прогон 3: failover переключил de→nl1, awg1 перенацелен и
        # рестартнут (счётчики с нуля) — доминанта уходит на nl1
        st["cascade_active_exit"] = "nl1"
        self._awg.write_text(json.dumps(st), encoding="utf-8")
        with self._patch_all(stats=self._stats(1, 1, 1, 1),
                             link={"awg1": {"rx": 3 * MB, "tx": 10 * MB}}):
            res = tw.run_once()
        self.assertIn("traffic_dominant_change", res["events"])
        det = next(d for ev, d, _ in self._details
                   if ev == "traffic_dominant_change")
        self.assertIn("AWG-каскад (failover): активная нода "
                      "<b><code>nl1</code></b>", det)
        self.assertIn("Переключение ноды: <code>de</code> → "
                      "<b><code>nl1</code></b>", det)

    def test_naive_upstream_events(self):
        """Naive upstream: падение после probe_fails прогонов →
        naive_upstream_down; восстановление → naive_upstream_up."""
        import chimera.modules.exit_traffic_watcher as tw
        self._write_cfg(probe=True, probe_fails=2,
                        probe_timeout_sec=2)
        bad = {"ok": False, "ms": None, "err": "timeout"}
        good = {"ok": True, "ms": 130, "err": ""}
        # прогон 1: статус фиксируется молча
        with self._patch_all(stats=self._stats(1, 1, 1, 1),
                             naive_probe=bad):
            res = tw.run_once()
        self._bump_snapshot_ts()
        self.assertEqual(res["events"], [])
        # прогон 2: down
        with self._patch_all(stats=self._stats(1, 1, 1, 1),
                             naive_probe=bad):
            res = tw.run_once()
        self.assertIn("naive_upstream_down", res["events"])
        det = next(d for ev, d, _ in self._details
                   if ev == "naive_upstream_down")
        self.assertIn("naive-exit.example.com:443", det)
        self.assertIn("2 прогонов подряд", det)
        st = json.loads(self._cfg.read_text())["__state__"]
        self.assertEqual(st["naive_status"], "down")
        # прогон 3: восстановление
        with self._patch_all(stats=self._stats(1, 1, 1, 1),
                             naive_probe=good):
            res = tw.run_once()
        self.assertIn("naive_upstream_up", res["events"])
        det = next(d for ev, d, _ in self._details
                   if ev == "naive_upstream_up")
        self.assertIn("RTT 130 мс", det)

    def test_naive_probe_disabled_by_cascades(self):
        """cascades.naive.probe=false — проба не выполняется, событий
        нет (vless-пробы тоже выключены probe=false)."""
        import chimera.modules.exit_traffic_watcher as tw
        self._write_cfg(probe=True, cascades={
            "naive": {"traffic": False, "probe": False}})
        bad = {"ok": False, "ms": None, "err": "timeout"}
        for _ in range(3):
            with self._patch_all(stats=self._stats(1, 1, 1, 1),
                                 naive_probe=bad):
                res = tw.run_once()
        self.assertNotIn("naive_upstream_down", res["events"])

    def test_stats_fail_with_other_sources_continues(self):
        """Stats API упал, но есть AWG/Mieru — прогон НЕ прерывается:
        awg-дельты копятся, stats_ok=True (другой источник жив)."""
        import chimera.modules.exit_traffic_watcher as tw
        self._write_cfg()
        with self._patch_all(stats=None):
            res = tw.run_once()
        self.assertTrue(res["stats_ok"])
        st = json.loads(self._cfg.read_text())["__state__"]
        self.assertEqual(st["stats_fails_map"]["vless"], 1)
        self.assertEqual(st["counters"]["awg:pl1"]["up"], 2000)
        # vless-часть доминант не тронута
        self.assertNotIn("vless", st["dominant_tags"])

    def test_only_naive_cascade_skips_vless(self):
        """Нода без VLESS/AWG/Mieru, только Naive — прогон работает:
        пробы upstream + персист (не SKIP «каскады не развёрнуты»)."""
        import chimera.modules.exit_traffic_watcher as tw
        self._state.write_text(json.dumps({"chain_nodes": []}),
                               encoding="utf-8")
        self._awg.unlink()
        self._mieru.unlink()
        self._write_cfg(probe=True, probe_fails=2)
        bad = {"ok": False, "ms": None, "err": "refused"}
        with self._patch_all(stats=None, naive_probe=bad):
            res = tw.run_once()
        self.assertEqual(res["events"], [])   # первый прогон молча
        with self._patch_all(stats=None, naive_probe=bad):
            res = tw.run_once()
        self.assertIn("naive_upstream_down", res["events"])

    def test_no_cascades_at_all_skips(self):
        """Ни одного каскада — прежний SKIP без событий."""
        import chimera.modules.exit_traffic_watcher as tw
        self._state.write_text(json.dumps({"chain_nodes": []}),
                               encoding="utf-8")
        self._awg.unlink()
        self._mieru.unlink()
        self._naive.unlink()
        self._write_cfg()
        with self._patch_all(stats=None):
            res = tw.run_once()
        self.assertEqual(res["events"], [])

    def test_mieru_probe_tcp_targets(self):
        """cascades.mieru.probe=true — TCP-пробы exit-нод в общем пуле
        traffic_node_* (проба mita-порта)."""
        import chimera.modules.exit_traffic_watcher as tw
        self._write_cfg(probe=True, probe_fails=2, cascades={
            "mieru": {"traffic": True, "probe": True}})
        # все пробы мieru падают; vless-ноды (node-a/b) — живые
        probe_map = {
            ("10.1.0.1", 2012): {"ok": False, "ms": None, "err": "timeout"},
            ("10.1.0.2", 2012): {"ok": False, "ms": None, "err": "timeout"},
        }

        def fake_probe(host, port, t):
            if (host, port) in probe_map:
                return probe_map[(host, port)]
            return {"ok": True, "ms": 10, "err": ""}

        def fake_probe_nodes(chain_nodes, cfg):
            return {TAG_A: {"ok": True, "ms": 5, "err": ""},
                    TAG_B: {"ok": True, "ms": 6, "err": ""}}

        import chimera.modules.exit_traffic_watcher as tw2
        with patch.multiple(
                tw2, TW_CFG_FILE=self._cfg, STATE_FILE=self._state,
                SB_STATE_FILE=self._sb, XRAY_CFG_CANDIDATES=(
                    self._xray_cfg,),
                AWG_STATE_FILE=self._awg, MIERU_STATE_FILE=self._mieru,
                NAIVE_STATE_FILE=self._naive,
                _tw_query_stats=lambda timeout=8: self._stats(1, 1, 1, 1),
                _tw_probe_nodes=fake_probe_nodes,
                _tw_notify_event=lambda ev, d, c, extra=None: (
                    self._events.append(ev) or True),
                _tw_ip_link_stats=lambda ifaces: {},
                _tw_iptables_nat_output=lambda: {},
                _tw_systemctl_show_ipacct=lambda unit: {
                    "IPAccounting": False, "IPIngressBytes": None,
                    "IPEgressBytes": None},
                _tw_tcp_probe=fake_probe):
            tw.run_once()
            tw.run_once()
        self.assertIn("traffic_node_down", self._events)
        # тег ноды mieru:de1 в статусах
        st = json.loads(self._cfg.read_text())["__state__"]
        self.assertEqual(st["probe_status"].get("mieru:de1"), "down")

    def test_awg_probe_from_health(self):
        """cascades.awg.probe=true — переходы alive из lb.probes
        становятся traffic_node_down/up (проба не TCP, вердикт
        failover-тика)."""
        import chimera.modules.exit_traffic_watcher as tw
        self._write_cfg(probe=True, probe_fails=2, cascades={
            "awg": {"traffic": True, "probe": True}})
        # прогон 1: первая неудача — молчим (probe_fails=2)
        with self._patch_all(stats=self._stats(1, 1, 1, 1)):
            res = tw.run_once()
        self.assertEqual(res["events"], [])
        self._bump_snapshot_ts()
        # прогон 2: de мёртв (probes.de.alive=false в AWG_STATE_LB) —
        # вторая неудача подряд → traffic_node_down для awg:de
        with self._patch_all(stats=self._stats(1, 1, 1, 1)):
            res = tw.run_once()
        self.assertIn("traffic_node_down", res["events"])
        st = json.loads(self._cfg.read_text())["__state__"]
        self.assertEqual(st["probe_status"].get("awg:de"), "down")
        # pl1/nl1 живы (rtt из probes)
        self.assertEqual(st["probe_status"].get("awg:pl1"), "ok")
        self.assertEqual(st["probe_status"].get("awg:nl1"), "ok")
        # прогон 3: de ожил → traffic_node_up
        st_awg = json.loads(self._awg.read_text())
        st_awg["lb"]["probes"]["de"] = {"alive": True, "rtt_ms": 34}
        self._awg.write_text(json.dumps(st_awg), encoding="utf-8")
        self._bump_snapshot_ts()
        with self._patch_all(stats=self._stats(1, 1, 1, 1)):
            res = tw.run_once()
        self.assertIn("traffic_node_up", res["events"])
        det = next(d for ev, d, _ in self._details
                   if ev == "traffic_node_up")
        self.assertIn("RTT 34 мс", det)


class TestTgBotNaiveEvents(unittest.TestCase):
    """Интеграция новых событий naive_upstream_* в tg_bot (иконки,
    подписи, выровненные ev_keys/ev_labels меню «вкл/выкл события»)."""

    def test_icons_and_labels(self):
        from chimera.modules import tg_bot
        import inspect, re
        src = inspect.getsource(tg_bot)
        # иконки
        self.assertIn('"naive_upstream_down":     "📴"', src)
        self.assertIn('"naive_upstream_up":       "🔌"', src)
        # подписи (event_labels в tg_notify_event)
        self.assertIn('"naive_upstream_down"', src)
        self.assertIn('"naive_upstream_up"', src)

    def test_ev_keys_labels_aligned_with_naive(self):
        from chimera.modules import tg_bot
        import inspect, re
        src = inspect.getsource(tg_bot.do_manage_telegram)
        keys = re.findall(r'"([a-z_0-9]+)"',
                          re.search(r"ev_keys = \[(.*?)\]",
                                    src, re.S).group(1))
        labels = re.findall(r'"([^"]+)"',
                            re.search(r"ev_labels = \[(.*?)\]\n\s+events",
                                      src, re.S).group(1))
        self.assertEqual(len(keys), len(labels),
                         "ev_keys/ev_labels разъехались")
        self.assertIn("naive_upstream_down", keys)
        self.assertIn("naive_upstream_up", keys)
        idx = keys.index("naive_upstream_down")
        self.assertIn("Naive", labels[idx])
        idx2 = keys.index("naive_upstream_up")
        self.assertIn("Naive", labels[idx2])

    def test_watcher_events_in_tg_bot_lists(self):
        """Все события watcher-а (EVENTS) известны tg_bot: иконка есть
        для каждого ключа (fallback ℹ️ не молчит)."""
        import chimera.modules.exit_traffic_watcher as tw
        from chimera.modules import tg_bot
        import inspect
        src = inspect.getsource(tg_bot)
        for ev in tw.EVENTS:
            self.assertIn(f'"{ev}"', src,
                          f"{ev} отсутствует в tg_bot.py")


if __name__ == "__main__":
    unittest.main(verbosity=2)
