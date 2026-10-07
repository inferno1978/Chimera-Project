#!/usr/bin/env python3
"""
tests/test_steal_monitor.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/steal_monitor.py — CPU Steal монитор.

Покрывает:
  1. read_proc_stat          — парсинг /proc/stat (агрегат + per-cpu)
  2. compute_deltas          — дельты: нет prev / ребут / норма
  3. percpu_steal            — per-core %steal
  4. boot_averages           — средние с бута
  5. _p95 / compute_stats    — статистика дня (вкл. hourly, stolen_share)
  6. classify_day            — ok/warn/crit/data по порогам флота
  7. recommendations         — рекомендации по уровням
  8. load/save_config        — дефолты, merge, roundtrip
  9. _append/read_samples    — JSONL хранилище, битые строки
  10. _record_node_sample    — 2 тика: prev → сэмпл (+ алерты)
  11. _alert_check           — стрик, cooldown, сброс на ошибке
  12. build_report           — HTML-отчёт: узлы, классификация, тикет-блок
  13. install/uninstall      — cron + wrappers (PYTHONPATH-safe)
  14. _load_peers            — cascade_peers + extra + фильтр + дедуп
  15. _tg_send               — events-гейтинг (отключённое событие)
  16. _ssh_proc_stat         — парсинг вывода SSH / мок отказа
  17. Интеграция: _core.py (импорт, пункт ST, диспетчер), tg_bot.py (events)
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

from chimera.modules import steal_monitor as sm


def _mk_proc_stat(steal_total=1000, busy_total=50000, idle_total=50000,
                  ncpu=2, per_steal=(100, 900)):
    """Синтетический /proc/stat: user nice system idle iowait irq softirq steal."""
    lines = ["cpu %d 10 %d %d 500 20 30 %d"
             % (busy_total // 2, busy_total // 2 - 100, idle_total, steal_total)]
    for i in range(ncpu):
        s = per_steal[i % len(per_steal)]
        b = max(1, busy_total // ncpu)
        lines.append("cpu%d %d 5 %d %d 250 10 15 %d"
                     % (i, b // 2, b // 2, idle_total // ncpu, s))
    return "\n".join(lines) + "\n"


def _mk_sample(steal, busy=10.0, ts=None, node="local", host="srv",
               steal_t=None, busy_t=None, hour=None, **extra):
    import time as _t
    ts = ts if ts is not None else _t.time()
    if hour is not None:
        # локальная полночь + hour часов
        import datetime as _dt
        d = _dt.datetime.now().replace(hour=hour, minute=5, second=0)
        ts = d.timestamp()
    rec = {"ts": ts, "node": node, "host": host, "ok": True,
           "steal": steal, "busy": busy, "iowait": 0.1,
           "steal_t": steal_t if steal_t is not None else int(steal * 100),
           "busy_t": busy_t if busy_t is not None else 10000,
           "total_t": 100000, "load1": 0.5, "ncpu": 2,
           "boot_steal": 1.0, "boot_busy": 12.0, "uptime_s": 864000}
    rec.update(extra)
    return rec


class StealMonitorTestBase(unittest.TestCase):
    """Тмп-каталоги + патчинг путей модуля."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        (self._tmp / "samples").mkdir()
        (self._tmp / "reports").mkdir()
        self._patches = [
            patch.object(sm, "BASE_DIR", self._tmp),
            patch.object(sm, "CONFIG_FILE", self._tmp / "steal-monitor.json"),
            patch.object(sm, "SAMPLES_DIR", self._tmp / "samples"),
            patch.object(sm, "REPORTS_DIR", self._tmp / "reports"),
            patch.object(sm, "PREV_FILE", self._tmp / "prev.json"),
            patch.object(sm, "TG_STATE_FILE", self._tmp / "tg-state.json"),
            patch.object(sm, "LOG_FILE", self._tmp / "steal-monitor.log"),
            patch.object(sm, "CRON_FILE", self._tmp / "cron.d/steal-monitor"),
            patch.object(sm, "SAMPLE_SCRIPT", self._tmp / "bin/steal-sample.sh"),
            patch.object(sm, "REPORT_SCRIPT", self._tmp / "bin/steal-report.sh"),
            patch.object(sm, "TG_CONFIG", self._tmp / "telegram.json"),
            patch.object(sm, "TG_BOT_CFG", self._tmp / "tg_bot.json"),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    def _write_cfg(self, cfg):
        sm.CONFIG_FILE.write_text(json.dumps(cfg), encoding="utf-8")


# ══════════════════════════════════════════════════════════════════════════════
#  1-4. Парсинг /proc/stat и дельты
# ══════════════════════════════════════════════════════════════════════════════

class TestProcStat(StealMonitorTestBase):

    def test_parse_aggregate_and_percpu(self):
        st = sm.read_proc_stat(_mk_proc_stat(ncpu=3))
        self.assertEqual(len(st["cpu"]), 8)
        self.assertEqual(len(st["percpu"]), 3)
        self.assertEqual(st["cpu"][7], 1000)  # steal

    def test_parse_missing_file_returns_none(self):
        self.assertIsNone(sm.read_proc_stat(""))

    def test_deltas_normal(self):
        prev = sm.read_proc_stat(_mk_proc_stat(steal_total=1000,
                                               idle_total=50000))
        cur = sm.read_proc_stat(_mk_proc_stat(steal_total=3000,
                                               idle_total=60000))
        d = sm.compute_deltas(prev, cur)
        self.assertIsNotNone(d)
        # +2000 steal тиков на фоне +10000 idle → реалистичный ~16.7%
        self.assertEqual(d["steal_t"], 2000)
        self.assertAlmostEqual(d["steal"], 2000 / 12000 * 100, delta=0.5)

    def test_deltas_no_prev(self):
        cur = sm.read_proc_stat(_mk_proc_stat())
        self.assertIsNone(sm.compute_deltas(None, cur))

    def test_deltas_reboot_counters_reset(self):
        prev = sm.read_proc_stat(_mk_proc_stat(steal_total=99999,
                                               busy_total=99999,
                                               idle_total=99999))
        cur = sm.read_proc_stat(_mk_proc_stat(steal_total=10))
        self.assertIsNone(sm.compute_deltas(prev, cur))

    def test_percpu_steal(self):
        prev = sm.read_proc_stat(_mk_proc_stat(ncpu=2, per_steal=(0, 0),
                                                idle_total=50000))
        cur = sm.read_proc_stat(_mk_proc_stat(ncpu=2, per_steal=(100, 900),
                                                idle_total=60000))
        per = sm.percpu_steal(prev, cur)
        self.assertEqual(len(per), 2)
        self.assertGreater(per[1], per[0])
        # ядро0: 100/(5000+100) ≈ 2%; ядро1: 900/(5000+900) ≈ 15%
        self.assertLess(per[0], 5.0)
        self.assertGreater(per[1], 10.0)

    def test_percpu_mismatch_returns_none(self):
        prev = sm.read_proc_stat(_mk_proc_stat(ncpu=2))
        cur = sm.read_proc_stat(_mk_proc_stat(ncpu=4))
        self.assertIsNone(sm.percpu_steal(prev, cur))

    def test_boot_averages(self):
        cur = sm.read_proc_stat(_mk_proc_stat(steal_total=2000,
                                              busy_total=10000,
                                              idle_total=10000))
        bs, bb = sm.boot_averages(cur)
        # busy = user+nice+system+irq+softirq = 9960; idle+iowait = 10500;
        # total = 9960 + 10500 + 2000 = 22460 → steal 8.9%
        self.assertAlmostEqual(bs, 2000 / 22460 * 100, delta=0.3)
        self.assertGreater(bb, bs)

    def test_read_loadavg(self):
        self.assertEqual(sm.read_loadavg("0.42 0.35 0.30 1/500 12345"), 0.42)
        self.assertIsNone(sm.read_loadavg("garbage"))


# ══════════════════════════════════════════════════════════════════════════════
#  5. Статистика
# ══════════════════════════════════════════════════════════════════════════════

class TestStats(StealMonitorTestBase):

    def test_p95_nearest_rank(self):
        self.assertEqual(sm._p95([1] * 100), 1)
        vals = [1] * 95 + [100] * 5
        self.assertEqual(sm._p95(vals), 100)
        self.assertEqual(sm._p95([]), 0.0)

    def test_compute_stats_basic(self):
        rows = [_mk_sample(1.0, hour=10), _mk_sample(3.0, hour=10),
                _mk_sample(5.0, hour=11), _mk_sample(9.0, hour=12)]
        st = sm.compute_stats(rows)
        self.assertEqual(st["n_ok"], 4)
        self.assertAlmostEqual(st["avg"], 4.5)
        self.assertEqual(st["peak"], 9.0)
        self.assertEqual(st["hourly"]["10"], (2.0, 2))
        self.assertEqual(st["hourly"]["12"], (9.0, 1))

    def test_compute_stats_errors_counted(self):
        rows = [_mk_sample(1.0), {"ts": 1, "node": "local", "ok": False,
                                  "err": "ssh failed"}]
        st = sm.compute_stats(rows)
        self.assertEqual(st["n_ok"], 1)
        self.assertEqual(st["n_err"], 1)

    def test_compute_stats_stolen_share(self):
        # steal 25% от желаемого: steal_t 1000, busy_t 3000 → 25%
        rows = [_mk_sample(25.0, steal_t=1000, busy_t=3000)]
        st = sm.compute_stats(rows)
        self.assertEqual(st["stolen_share"], 25.0)

    def test_compute_stats_smt_spread(self):
        rows = [_mk_sample(10.0, core_max=56.0, core_min=1.0)]
        st = sm.compute_stats(rows)
        self.assertTrue(st["smt_spread"])
        self.assertEqual(st["core_max"], 56.0)


# ══════════════════════════════════════════════════════════════════════════════
#  6. Классификация (пороги откалиброваны по живому флоту)
# ══════════════════════════════════════════════════════════════════════════════

class TestClassify(StealMonitorTestBase):
    THR = dict(sm.DEFAULT_CONFIG["thresholds"])

    def _stats(self, avg, peak, p95, n=50):
        return {"n_ok": n, "avg": avg, "peak": peak, "p95": p95}

    def test_clean_host_is_ok(self):
        # 91/pl1/de: 0.0-0.1%
        level, _ = sm.classify_day(self._stats(0.05, 0.3, 0.1), self.THR)
        self.assertEqual(level, "ok")

    def test_fi1_level_is_warn(self):
        # fi1: avg 3.8, пик 7.7 → «следить»
        level, reasons = sm.classify_day(self._stats(3.8, 7.7, 6.0), self.THR)
        self.assertEqual(level, "warn")
        self.assertTrue(any("avg" in r for r in reasons))

    def test_nl1_level_is_crit(self):
        # nl1: avg 7.9, пик 16, p95 12 → тикет
        level, _ = sm.classify_day(self._stats(7.9, 16.0, 12.0), self.THR)
        self.assertEqual(level, "crit")

    def test_138_level_is_crit(self):
        # 138: avg 20+, пик 60
        level, _ = sm.classify_day(self._stats(20.1, 59.7, 35.0), self.THR)
        self.assertEqual(level, "crit")

    def test_few_samples_is_data(self):
        level, reasons = sm.classify_day(self._stats(50.0, 90.0, 80.0, n=5),
                                         self.THR)
        self.assertEqual(level, "data")
        self.assertIn("сэмплов 5", reasons[0])

    def test_peak_only_triggers(self):
        # avg низкий, но пик 20 → crit по пику
        level, reasons = sm.classify_day(self._stats(1.0, 20.0, 3.0), self.THR)
        self.assertEqual(level, "crit")
        self.assertTrue(any("пик" in r for r in reasons))


# ══════════════════════════════════════════════════════════════════════════════
#  7. Рекомендации
# ══════════════════════════════════════════════════════════════════════════════

class TestRecommendations(StealMonitorTestBase):

    def test_crit_mentions_ticket_and_no_reboot(self):
        recs = " ".join(sm.recommendations("crit",
                                           {"stolen_share": 60.0,
                                            "core_max": 56, "core_min": 1}))
        self.assertIn("тикет", recs.lower())
        self.assertIn("НЕ ребут", recs)
        self.assertIn("AWG", recs)
        self.assertIn("миграц", recs.lower())

    def test_warn_mentions_observation(self):
        recs = " ".join(sm.recommendations("warn", {}))
        self.assertIn("Наблюдать", recs)
        self.assertIn("Mieru", recs)

    def test_ok_mentions_cpu_roles(self):
        recs = " ".join(sm.recommendations("ok", {}))
        self.assertIn("AWG", recs)
        self.assertIn("можно", recs.lower())


# ══════════════════════════════════════════════════════════════════════════════
#  8-9. Конфиг и хранилище
# ══════════════════════════════════════════════════════════════════════════════

class TestConfigAndStorage(StealMonitorTestBase):

    def test_load_defaults_when_missing(self):
        cfg = sm.load_config()
        self.assertEqual(cfg["sample_interval_min"], 5)
        self.assertEqual(cfg["thresholds"]["crit_peak"], 15.0)
        self.assertFalse(cfg["monitor_peers"])

    def test_save_load_roundtrip_and_merge(self):
        cfg = sm.load_config()
        cfg["thresholds"]["crit_avg"] = 12.5
        cfg["report"]["include_hourly"] = False
        sm.save_config(cfg)
        loaded = sm.load_config()
        self.assertEqual(loaded["thresholds"]["crit_avg"], 12.5)
        self.assertFalse(loaded["report"]["include_hourly"])
        # merge сохранил не переопределённые ключи
        self.assertEqual(loaded["thresholds"]["warn_avg"], 3.0)
        self.assertEqual(loaded["report"]["include_percpu"], True)

    def test_broken_config_falls_back_to_defaults(self):
        sm.CONFIG_FILE.write_text("{ not json", encoding="utf-8")
        cfg = sm.load_config()
        self.assertEqual(cfg["retention_days"], 30)

    def test_samples_roundtrip_and_bad_lines(self):
        sm._append_sample(_mk_sample(1.5), date="2026-10-06")
        p = sm.SAMPLES_DIR / "2026-10-06.jsonl"
        p.write_text(p.read_text() + "{broken json\n", encoding="utf-8")
        rows = sm.read_samples(date="2026-10-06")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["steal"], 1.5)


# ══════════════════════════════════════════════════════════════════════════════
#  10. _record_node_sample — два тика
# ══════════════════════════════════════════════════════════════════════════════

class TestRecordSample(StealMonitorTestBase):

    def test_first_tick_stores_prev_only(self):
        prev_store, tgst, alerts = {}, {"nodes": {}}, []
        cfg = dict(sm.DEFAULT_CONFIG)
        cur = sm.read_proc_stat(_mk_proc_stat())
        rec = sm._record_node_sample("local", "srv", cur, 0.5, 1000.0,
                                     prev_store, cfg, tgst, alerts)
        self.assertIsNone(rec)                     # нет prev → нет сэмпла
        self.assertIn("local", prev_store)          # prev запомнили
        self.assertEqual(len(sm.read_samples()), 0)

    def test_second_tick_produces_sample(self):
        prev_store, tgst, alerts = {}, {"nodes": {}}, []
        cfg = dict(sm.DEFAULT_CONFIG)
        cfg["alerts_enabled"] = False
        cur1 = sm.read_proc_stat(_mk_proc_stat())
        sm._record_node_sample("local", "srv", cur1, 0.5, 1000.0,
                               prev_store, cfg, tgst, alerts)
        cur2 = sm.read_proc_stat(_mk_proc_stat(steal_total=3000))
        rec = sm._record_node_sample("local", "srv", cur2, 0.7, 1000.0,
                                     prev_store, cfg, tgst, alerts)
        self.assertIsNotNone(rec)
        self.assertGreater(rec["steal"], 0)
        rows = sm.read_samples()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["node"], "local")
        self.assertEqual(rows[0]["load1"], 0.7)


# ══════════════════════════════════════════════════════════════════════════════
#  11. Алерты: стрик → кулдаун → сброс
# ══════════════════════════════════════════════════════════════════════════════

class TestAlerts(StealMonitorTestBase):

    def setUp(self):
        super().setUp()
        self.cfg = dict(sm.DEFAULT_CONFIG)
        self.cfg["alerts_enabled"] = True
        self.thr = self.cfg["thresholds"]
        self.thr["crit_peak"] = 15.0
        self.thr["alert_consecutive"] = 3
        self.thr["alert_cooldown_min"] = 180

    def test_streak_then_alert(self):
        tgst = {"nodes": {}}
        self.assertIsNone(sm._alert_check("nl1", "h", 20.0, self.cfg, tgst))
        self.assertIsNone(sm._alert_check("nl1", "h", 21.0, self.cfg, tgst))
        msg = sm._alert_check("nl1", "h", 22.0, self.cfg, tgst)
        self.assertIsNotNone(msg)
        self.assertIn("nl1", msg)
        self.assertIn("22.0%", msg)

    def test_cooldown_blocks_repeat(self):
        tgst = {"nodes": {"nl1": {"crit_streak": 2}}}
        self.assertIsNotNone(sm._alert_check("nl1", "h", 20.0, self.cfg, tgst))
        # сразу после алерта — streak обнулён
        self.assertIsNone(sm._alert_check("nl1", "h", 20.0, self.cfg, tgst))
        self.assertIsNone(sm._alert_check("nl1", "h", 20.0, self.cfg, tgst))
        # третья итерация снова алертит (строк накопился заново), но кулдаун
        self.assertIsNone(sm._alert_check("nl1", "h", 20.0, self.cfg, tgst))

    def test_error_resets_streak(self):
        tgst = {"nodes": {"nl1": {"crit_streak": 2}}}
        sm._alert_check("nl1", "h", None, self.cfg, tgst)
        self.assertEqual(tgst["nodes"]["nl1"]["crit_streak"], 0)

    def test_below_threshold_resets(self):
        tgst = {"nodes": {"nl1": {"crit_streak": 2}}}
        sm._alert_check("nl1", "h", 5.0, self.cfg, tgst)
        self.assertEqual(tgst["nodes"]["nl1"]["crit_streak"], 0)


# ══════════════════════════════════════════════════════════════════════════════
#  12. Отчёт
# ══════════════════════════════════════════════════════════════════════════════

class TestBuildReport(StealMonitorTestBase):

    def _seed_day(self):
        # конфиг с идентичностью локальной ноды (как на реальном деплое)
        self._write_cfg({"node_label": "RU-2", "node_ip": "203.0.113.20"})
        rows = []
        for i in range(30):   # чистая локальная
            rows.append(_mk_sample(0.2, hour=10 + i % 5, node="local",
                                   host="srv45"))
        for i in range(30):   # больная nl1 — новые сэмплы с идентичностью
            rows.append(_mk_sample(12.0 + (i % 5), hour=18 + i % 4,
                                   node="nl1", host="vm134610",
                                   steal_t=1500, busy_t=5000,
                                   core_max=40.0, core_min=2.0,
                                   label="NL", ip="203.0.113.30",
                                   hostname="vm134610"))
        rows.append({"ts": 1, "node": "nl1", "host": "vm134610",
                     "ok": False, "err": "ssh failed"})
        p = sm._samples_path()
        with p.open("w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    def test_report_contains_nodes_levels_ticket(self):
        self._seed_day()
        text = sm.build_report()
        self.assertIn("CPU Steal Report", text)
        self.assertIn("Монитор:", text)               # шапка идентифицирует ноду
        self.assertIn("RU-2", text)                   # label локальной из конфига
        self.assertIn("203.0.113.20", text)         # IP локальной из конфига
        self.assertIn("NL", text)
        self.assertIn("203.0.113.30", text)        # IP peer из сэмпла
        self.assertIn("КРИТИЧНО — есть проблемы", text)   # nl1 avg ~14 → crit
        self.assertIn("НОРМА — проблем нет", text)     # local 0.2 → ok
        self.assertIn("Флот: 🔴 1 (NL)", text)         # сводка с ярлыками
        self.assertIn("Черновик тикета", text)
        self.assertIn("vm134610", text)
        self.assertIn("Рекомендации", text)
        self.assertIn("НЕ ребут", text)                # рекомендация crit
        self.assertIn("ошибок 1", text)                # err-сэмпл nl1 виден в отчёте

    def test_report_russian_ticket_crit(self):
        self._seed_day()
        text = sm.build_report()
        self.assertIn("Тема: Хронический CPU steal", text)
        self.assertIn("Здравствуйте!", text)
        self.assertIn("мигрировать", text)             # требование миграции
        self.assertIn("не решает", text)               # ребут — не решение
        self.assertIn("шумного соседа на SMT-сиблинге", text)
        self.assertIn("Спасибо!", text)

    def test_report_russian_ticket_warn(self):
        for i in range(20):   # avg ~4% → warn (>=3), не crit
            sm._append_sample(_mk_sample(3.8 + (i % 3) * 0.2, hour=12,
                                         label="FI", ip="203.0.113.50",
                                         hostname="srv-fi"))
        self._write_cfg({"node_label": "FI", "node_ip": "203.0.113.50"})
        text = sm.build_report()
        self.assertIn("ВНИМАНИЕ — пограничное состояние", text)
        self.assertIn("Черновик тикета", text)
        self.assertIn("просьба проверить", text)       # вежливый warn-тикет
        self.assertIn("вернёмся с просьбой о миграции", text)

    def test_report_single_ok_node_gets_recommendations(self):
        for i in range(15):
            sm._append_sample(_mk_sample(0.3, hour=12))
        text = sm.build_report()
        self.assertIn("Рекомендации", text)
        self.assertIn("можно", text.lower())

    def test_report_no_samples(self):
        text = sm.build_report()
        self.assertIn("Сэмплов нет", text)

    def test_send_daily_report_saves_copy(self):
        for i in range(12):
            sm._append_sample(_mk_sample(1.0, hour=12))
        with patch.object(sm, "_tg_send", return_value=True) as m:
            text = sm.send_daily_report(send_tg=True)
            m.assert_called_once()
            self.assertEqual(m.call_args[0][1], "steal_report")
        saved = list(sm.REPORTS_DIR.glob("*.txt"))
        self.assertEqual(len(saved), 1)
        self.assertIn("CPU Steal Report", saved[0].read_text(encoding="utf-8"))


# ══════════════════════════════════════════════════════════════════════════════
#  13. Установка / удаление
# ══════════════════════════════════════════════════════════════════════════════

class TestInstall(StealMonitorTestBase):

    def test_install_writes_cron_and_wrappers(self):
        ok, msg = sm.install_steal_monitor({
            "sample_interval_min": 10, "report_hour": 23, "report_minute": 45})
        self.assertTrue(ok, msg)
        cron = sm.CRON_FILE.read_text()
        self.assertIn("*/10 * * * *", cron)
        self.assertIn("45 23 * * *", cron)
        self.assertIn("steal-sample.sh", cron)
        wrap = sm.SAMPLE_SCRIPT.read_text()
        self.assertIn("PYTHONPATH", wrap)
        self.assertIn("sample_once", wrap)
        self.assertIn("send_daily_report", sm.REPORT_SCRIPT.read_text())
        self.assertTrue(sm.is_monitor_installed())

    def test_interval_clamped(self):
        ok, _ = sm.install_steal_monitor({"sample_interval_min": 500,
                                          "report_hour": 99,
                                          "report_minute": 99})
        self.assertTrue(ok)
        cron = sm.CRON_FILE.read_text()
        self.assertIn("*/60", cron)
        self.assertIn("59 23", cron)

    def test_uninstall_keeps_data(self):
        sm.install_steal_monitor({})
        (sm.SAMPLES_DIR / "2026-10-06.jsonl").write_text("{}\n")
        ok, _ = sm.uninstall_steal_monitor()
        self.assertTrue(ok)
        self.assertFalse(sm.CRON_FILE.exists())
        self.assertTrue((sm.SAMPLES_DIR / "2026-10-06.jsonl").exists())
        self.assertFalse(sm.is_monitor_installed())


# ══════════════════════════════════════════════════════════════════════════════
#  14. Peers
# ══════════════════════════════════════════════════════════════════════════════

class TestPeers(StealMonitorTestBase):

    def test_load_peers_from_bot_cfg_and_extra(self):
        sm.TG_BOT_CFG.write_text(json.dumps({
            "cascade_peers": [
                {"host": "de", "user": "root", "port": 22, "name": "de"},
                {"host": "de", "user": "root", "port": 22, "name": "de-dup"},
            ]}), encoding="utf-8")
        cfg = {"extra_peers": [{"host": "nl1", "user": "root", "port": 2222,
                                "name": "nl1"}]}
        peers = sm._load_peers(cfg)
        self.assertEqual(len(peers), 2)      # дедуп по host:port
        self.assertEqual(peers[0]["name"], "de")

    def test_peer_filter(self):
        sm.TG_BOT_CFG.write_text(json.dumps({
            "cascade_peers": [
                {"host": "de", "name": "de"},
                {"host": "nl1", "name": "nl1"},
            ]}), encoding="utf-8")
        peers = sm._load_peers({"peer_filter": ["nl1"]})
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0]["name"], "nl1")


# ══════════════════════════════════════════════════════════════════════════════
#  15. TG events-гейтинг
# ══════════════════════════════════════════════════════════════════════════════

class TestTgSend(StealMonitorTestBase):

    def _tg_cfg(self, events=None):
        cfg = {"token": "T", "chat_id": "C"}
        if events is not None:
            cfg["events"] = events
        sm.TG_CONFIG.write_text(json.dumps(cfg), encoding="utf-8")

    def test_disabled_event_skips_curl(self):
        self._tg_cfg({"steal_report": False})
        with patch.object(sm, "_run") as m:
            self.assertFalse(sm._tg_send("msg", "steal_report"))
            m.assert_not_called()

    def test_enabled_event_sends(self):
        self._tg_cfg({})
        resp = MagicMock(stdout="200")
        with patch.object(sm, "_run", return_value=resp) as m:
            self.assertTrue(sm._tg_send("msg", "steal_report"))
            self.assertEqual(m.call_count, 1)

    def test_long_message_chunked(self):
        self._tg_cfg({})
        resp = MagicMock(stdout="200")
        with patch.object(sm, "_run", return_value=resp) as m:
            self.assertTrue(sm._tg_send("x" * 8000, "steal_report"))
            self.assertEqual(m.call_count, 3)   # 8000/3900 → 3 чанка

    def test_no_config_returns_false(self):
        with patch.object(sm, "_run") as m:
            self.assertFalse(sm._tg_send("msg", "steal_report"))
            m.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
#  16. SSH-замер peer
# ══════════════════════════════════════════════════════════════════════════════

class TestSshSample(StealMonitorTestBase):

    def test_ssh_success_parses(self):
        out = _mk_proc_stat() + "0.42 0.35 0.30 1/500 9\n" + "1480000.5 5\n"
        r = MagicMock(returncode=0, stdout=out)
        with patch("subprocess.run", return_value=r):
            got = sm._ssh_proc_stat({"host": "de", "user": "root", "port": 22})
        self.assertIsNotNone(got)
        self.assertEqual(got["load1"], 0.42)
        self.assertEqual(got["uptime_s"], 1480000.0)
        self.assertEqual(len(got["stat"]["percpu"]), 2)
        self.assertIsNone(got["hostname"])   # без маркера — обратная совместимость

    def test_ssh_parses_hostname_marker(self):
        out = (_mk_proc_stat() + "0.42 0.35 0.30 1/500 9\n" + "1480000.5 5\n"
               + "___HOSTNAME___vm999\n")
        r = MagicMock(returncode=0, stdout=out)
        with patch("subprocess.run", return_value=r):
            got = sm._ssh_proc_stat({"host": "de", "user": "root", "port": 22})
        self.assertIsNotNone(got)
        self.assertEqual(got["hostname"], "vm999")
        self.assertEqual(got["load1"], 0.42)      # хвост не сместился
        self.assertEqual(got["uptime_s"], 1480000.0)

    def test_ssh_failure_returns_none(self):
        r = MagicMock(returncode=255, stdout="")
        with patch("subprocess.run", return_value=r):
            self.assertIsNone(sm._ssh_proc_stat({"host": "de"}))

    def test_ssh_timeout_returns_none(self):
        import subprocess as _sp
        with patch("subprocess.run", side_effect=_sp.TimeoutExpired("ssh", 20)):
            self.assertIsNone(sm._ssh_proc_stat({"host": "de"}))


# ══════════════════════════════════════════════════════════════════════════════
#  16a. Идентификация нод (label · IP · hostname)
# ══════════════════════════════════════════════════════════════════════════════

class TestIdentity(StealMonitorTestBase):

    def test_local_identity_from_config(self):
        cfg = {"node_label": "RU-1", "node_ip": "203.0.113.10"}
        with patch.object(sm, "_hostname", return_value="srv-ru1"):
            ident = sm._local_identity(cfg)
        self.assertEqual(ident["label"], "RU-1")
        self.assertEqual(ident["ip"], "203.0.113.10")
        self.assertEqual(ident["hostname"], "srv-ru1")

    def test_local_identity_fallbacks(self):
        # без конфига label = hostname, ip = автодетект
        with patch.object(sm, "_hostname", return_value="vm134610"), \
             patch.object(sm, "_detect_local_ip", return_value="203.0.113.30"):
            ident = sm._local_identity({})
        self.assertEqual(ident["label"], "vm134610")
        self.assertEqual(ident["ip"], "203.0.113.30")

    def test_detect_local_ip_via_route(self):
        r = MagicMock(stdout="1.1.1.1 via 10.0.0.1 dev eth0 src 203.0.113.7 uid 0\n")
        with patch.object(sm, "_run", return_value=r):
            self.assertEqual(sm._detect_local_ip(), "203.0.113.7")

    def test_detect_local_ip_route_private_falls_to_hostname(self):
        # src внутренний (NAT) → берём первый публичный из hostname -I
        responses = {
            ("ip", "-4", "route", "get", "1.1.1.1"): MagicMock(
                stdout="1.1.1.1 dev eth0 src 10.0.0.5\n"),
            ("hostname", "-I"): MagicMock(
                stdout="10.0.0.5 172.16.0.1 203.0.113.9 fe80::1\n"),
        }

        def fake_run(cmd, timeout=20):
            return responses[tuple(cmd)]

        with patch.object(sm, "_run", side_effect=fake_run):
            self.assertEqual(sm._detect_local_ip(), "203.0.113.9")

    def test_is_private_ip(self):
        for priv in ("10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
                     "127.0.0.1", "169.254.1.1", "", "fd00::1", "не-ip"):
            self.assertTrue(sm._is_private_ip(priv), priv)
        for pub in ("203.0.113.10", "203.0.113.7", "8.8.8.8", "203.0.113.20"):
            self.assertFalse(sm._is_private_ip(pub), pub)

    def test_display_title_full(self):
        ident = {"label": "NL", "ip": "203.0.113.30", "hostname": "vm134610"}
        self.assertEqual(
            sm._display_title(ident, "nl1", "x"),
            "<b>NL</b> · <code>203.0.113.30</code> · vm134610")

    def test_display_title_dedup(self):
        # hostname совпадает с label / ip — не дублируем
        self.assertEqual(
            sm._display_title({"label": "vm1", "ip": "203.0.113.60", "hostname": "vm1"},
                              "local", "vm1"),
            "<b>vm1</b> · <code>203.0.113.60</code>")

    def test_display_title_legacy_samples(self):
        # старые сэмплы без ident → «local (srv45)» как раньше
        self.assertEqual(sm._display_title({}, "local", "srv45"),
                         "<b>local</b> (srv45)")

    def test_sample_writes_identity(self):
        prev_store, tgst, alerts = {}, {"nodes": {}}, []
        cur1 = sm.read_proc_stat(_mk_proc_stat(steal_total=1000))
        cur2 = sm.read_proc_stat(_mk_proc_stat(steal_total=3000))
        ident = {"label": "RU-1", "ip": "203.0.113.10", "hostname": "srv-ru1"}
        sm._record_node_sample("local", "srv-ru1", cur1, 0.5, 1000.0,
                               prev_store, dict(sm.DEFAULT_CONFIG), tgst, alerts)
        rec = sm._record_node_sample("local", "srv-ru1", cur2, 0.5, 1000.0,
                                     prev_store, dict(sm.DEFAULT_CONFIG), tgst,
                                     alerts, ident=ident)
        self.assertEqual(rec["label"], "RU-1")
        self.assertEqual(rec["ip"], "203.0.113.10")
        self.assertEqual(rec["hostname"], "srv-ru1")

    def test_fleet_summary_labels(self):
        node_data = [
            ("local", "h", {"n_ok": 1}, "ok", [],
             {"label": "RU-1", "ip": "1.1.1.1", "hostname": "a"}),
            ("nl1", "h", {"n_ok": 1}, "crit", [],
             {"label": "NL", "ip": "203.0.113.70", "hostname": "b"}),
        ]
        line = sm._fleet_summary_line(node_data)
        self.assertIn("🔴 1 (NL)", line)
        self.assertIn("🟢 1 (RU-1)", line)
        # crit идёт первым — проблемы видны сразу
        self.assertLess(line.index("🔴"), line.index("🟢"))


class TestTgChunks(StealMonitorTestBase):

    def test_split_respects_line_boundaries(self):
        lines = ["строка номер %02d с данными тикета" % i for i in range(300)]
        msg = "\n".join(lines)
        chunks = sm._split_tg_chunks(msg, limit=500)
        self.assertTrue(all(len(c) <= 500 for c in chunks))
        # ни одна строка не разрезана: конкатенация строк чанков = исходные строки
        restored = []
        for c in chunks:
            restored.extend(c.split("\n"))
        self.assertEqual(restored, lines)

    def test_split_hard_cuts_giant_line(self):
        self.assertEqual(sm._split_tg_chunks("x" * 8000),
                         ["x" * 3900, "x" * 3900, "x" * 200])

    def test_split_short_message_single_chunk(self):
        self.assertEqual(sm._split_tg_chunks("коротко"), ["коротко"])


# ══════════════════════════════════════════════════════════════════════════════
#  17. Интеграция: _core.py + tg_bot.py (static checks)
# ══════════════════════════════════════════════════════════════════════════════

class TestIntegration(unittest.TestCase):

    def test_core_imports_menu(self):
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text(encoding="utf-8")
        self.assertIn("from chimera.modules.steal_monitor        import do_steal_monitor_menu", src)
        self.assertIn('do_steal_monitor_menu()', src)

    def test_core_menu_item_and_dispatch(self):
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text(encoding="utf-8")
        self.assertIn('_box_item("ST"', src)
        self.assertIn('ch.lower() == "st"', src)

    def test_tg_bot_has_events(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" / "tg_bot.py").read_text(encoding="utf-8")
        for ev in ("steal_report", "steal_alert"):
            self.assertIn(f'"{ev}"', src)

    def test_module_standalone_no_core_at_import(self):
        # cron-путь не тянет _core: AST-проверка top-level импортов
        # (текстовая проверка ловит строки внутри f-string обёрток — ложные
        # срабатывания на embedded 'from chimera...' в bash-скриптах)
        import ast
        src = (_PROJECT_ROOT / "chimera" / "modules" / "steal_monitor.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        bad = []
        for node in tree.body:
            if isinstance(node, ast.Import):
                bad += [a.name for a in node.names if a.name.startswith("chimera")]
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.startswith("chimera"):
                    bad.append(node.module)
        self.assertEqual(bad, [],
                         "top-level импорты не должны тянуть chimera._core")


if __name__ == "__main__":
    unittest.main(verbosity=2)
