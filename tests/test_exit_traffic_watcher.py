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
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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

    def _patch_all(self, stats=None):
        import chimera.modules.exit_traffic_watcher as tw

        def fake_notify(event, detail, cfg, extra=None):
            self._events.append(event)
            self._details.append((event, detail, extra))
            return True

        return patch.multiple(
            tw, TW_CFG_FILE=self._cfg, STATE_FILE=self._state,
            SB_STATE_FILE=self._sb, XRAY_CFG_CANDIDATES=(self._xray_cfg,),
            _tw_query_stats=lambda timeout=8: stats,
            _tw_notify_event=fake_notify)

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
                   "traffic_node_starved", "traffic_stats_error"):
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

    def test_icons_for_watcher_events(self):
        from chimera.modules import tg_bot
        import inspect
        src = inspect.getsource(tg_bot.tg_notify_event)
        for ev in ("traffic_dominant_change", "traffic_snapshot",
                   "traffic_node_starved", "traffic_stats_error"):
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
