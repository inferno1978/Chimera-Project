#!/usr/bin/env python3
"""
tests/test_dpi_response.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/dpi_response.py.

Покрывает:
  1. state_load / state_save — мердж дефолтов, права 0600
  2. threat_level — уровни 0/1/2 по сигналам (зонды, mask_gate FAIL,
     dpi_gate tunnel)
  3. collect_signals — чтение error.log с паттернами dpi_detector,
     свежие отчёты гейтов (синтетика в tmp)
  4. action_rotate — окна/cooldown/лимиты (mock _rotate_reality_keys)
  5. dpi_response_run_once — полный цикл: уведомление + фаззер + ротация,
     деградация в notify-only при сбоях, авто-возврат в auto
  6. cron_install / cron_remove (мок файловой системы)
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import dpi_response as dr


def _setup_core_in_sysmodules():
    """Фейковый chimera._core (как в test_dpi_detector.py)."""
    import types
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core


class DrTestBase(unittest.TestCase):
    """База: tmp-пути для state/логов/отчётов."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        # подменяем все прод-пути модуля
        self.patches = [
            patch.object(dr, "STATE_FILE", self.tmp / "dpi_response.json"),
            patch.object(dr, "DPI_DETECTOR_STATE", self.tmp / "dpi_detector.json"),
            patch.object(dr, "MASK_GATE_DIR", self.tmp / "mask_gate"),
            patch.object(dr, "DPI_GATE_DIR", self.tmp / "dpi_gate"),
            patch.object(dr, "XRAY_ERROR_LOG", self.tmp / "error.log"),
            patch.object(dr, "LOG_FILE", self.tmp / "chimera.log"),
            patch.object(dr, "CRON_FILE", self.tmp / "cron.d", "..") if False else
            patch.object(dr, "CRON_FILE", self.tmp / "cron.d" / "chimera-dpi-response"),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)


class TestState(DrTestBase):
    def test_state_load_defaults(self):
        cfg = dr.state_load()
        self.assertTrue(cfg["enabled"])
        self.assertEqual(cfg["probe_threshold"], 3)
        self.assertEqual(cfg["probe_threshold_2"], 300)
        self.assertEqual(cfg["notify_cooldown_min"], 60)
        self.assertEqual(cfg["fuzz_cooldown_min"], 60)
        self.assertTrue(cfg["action_notify"])
        self.assertTrue(cfg["action_fuzz"])
        self.assertFalse(cfg["action_rotate"])
        self.assertEqual(cfg["mode"], "auto")
        self.assertIn("notifications", cfg["stats"])
        self.assertIn("score_history", cfg["stats"])

    def test_state_save_and_load_roundtrip(self):
        cfg = dr.state_load()
        cfg["probe_threshold"] = 7
        cfg["history"] = [{"action": "alert", "ts": "2026-10-28T00:00:00"}]
        dr.state_save(cfg)
        # права 0600
        self.assertEqual(dr.STATE_FILE.stat().st_mode & 0o777, 0o600)
        cfg2 = dr.state_load()
        self.assertEqual(cfg2["probe_threshold"], 7)
        self.assertEqual(len(cfg2["history"]), 1)

    def test_state_load_ignores_unknown_keys(self):
        dr.STATE_FILE.write_text(json.dumps({"enabled": False, "hacker": 1}),
                                 encoding="utf-8")
        cfg = dr.state_load()
        self.assertFalse(cfg["enabled"])
        self.assertNotIn("hacker", cfg)

    def test_history_trimmed_to_max(self):
        cfg = dr.state_load()
        cfg["history"] = [{"i": i} for i in range(200)]
        dr._history_append(cfg, {"action": "alert"})
        self.assertLessEqual(len(cfg["history"]), dr._MAX_HISTORY + 1)
        cfg["history"] = cfg["history"][-dr._MAX_HISTORY:]
        self.assertEqual(cfg["history"][-1]["action"], "alert")
        self.assertIn("ts", cfg["history"][-1])


class TestThreatLevel(DrTestBase):
    def test_level0_silence(self):
        cfg = dr.state_load()
        signals = {"probe_score": 0, "mask_gate": None, "dpi_gate": None,
                   "banned_now": 0}
        level, reasons = dr.threat_level(cfg, signals)
        self.assertEqual(level, 0)
        self.assertEqual(reasons, [])

    def test_level1_probes_background(self):
        # фон зондирования: выше минимального порога, но ниже порога атаки
        # и без скачка (пустая база) — уровень 1, а не 2
        cfg = dr.state_load()
        signals = {"probe_score": 5, "mask_gate": None, "dpi_gate": None,
                   "banned_now": 0}
        level, reasons = dr.threat_level(cfg, signals)
        self.assertEqual(level, 1)
        self.assertTrue(any("зонды" in r for r in reasons))

    def test_level2_probes_attack_threshold(self):
        # score ≥ порога атаки → уровень 2
        cfg = dr.state_load()
        signals = {"probe_score": 400, "mask_gate": None, "dpi_gate": None,
                   "banned_now": 0}
        level, reasons = dr.threat_level(cfg, signals)
        self.assertEqual(level, 2)
        self.assertTrue(any("порога атаки" in r for r in reasons))

    def test_level2_mask_gate_fail(self):
        cfg = dr.state_load()
        signals = {"probe_score": 0, "mask_gate": "FAIL", "dpi_gate": None,
                   "banned_now": 0}
        level, reasons = dr.threat_level(cfg, signals)
        self.assertEqual(level, 2)
        self.assertTrue(any("mask_gate" in r for r in reasons))

    def test_level1_mask_gate_suspect(self):
        cfg = dr.state_load()
        signals = {"probe_score": 0, "mask_gate": "SUSPECT", "dpi_gate": None,
                   "banned_now": 0}
        level, _ = dr.threat_level(cfg, signals)
        self.assertEqual(level, 1)

    def test_level1_dpi_gate_tunnel(self):
        cfg = dr.state_load()
        signals = {"probe_score": 0, "mask_gate": None, "dpi_gate": "tunnel",
                   "banned_now": 0}
        level, _ = dr.threat_level(cfg, signals)
        self.assertEqual(level, 1)

    def test_below_threshold_is_level0(self):
        cfg = dr.state_load()
        signals = {"probe_score": cfg["probe_threshold"] - 1, "mask_gate": None,
                   "dpi_gate": None, "banned_now": 0}
        level, _ = dr.threat_level(cfg, signals)
        self.assertEqual(level, 0)


class TestCollectSignals(DrTestBase):
    def test_probe_score_from_error_log(self):
        # Реальный паттерн dpi_detector: «TLS без SNI» (вес 3)
        now = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        lines = [f"{now} tls: failed to get client hello: no sni from client"] * 3
        dr.XRAY_ERROR_LOG.write_text("\n".join(lines), encoding="utf-8")
        cfg = dr.state_load()
        signals = dr.collect_signals(cfg)
        # каждый паттерн считается 1 раз на строку → ≥3 очков суммарно
        self.assertGreaterEqual(signals["probe_score"], 3)

    def test_stale_log_lines_ignored(self):
        old = (datetime.now() - timedelta(hours=2)).strftime("%Y/%m/%d %H:%M:%S")
        dr.XRAY_ERROR_LOG.write_text(
            f"{old} tls: no sni from client", encoding="utf-8")
        cfg = dr.state_load()
        signals = dr.collect_signals(cfg)
        self.assertEqual(signals["probe_score"], 0)

    def test_mask_gate_verdict_from_report(self):
        dr.MASK_GATE_DIR.mkdir(parents=True, exist_ok=True)
        (dr.MASK_GATE_DIR / "mask_gate_20260101_000000.json").write_text(
            json.dumps({"verdict": "FAIL"}), encoding="utf-8")
        cfg = dr.state_load()
        signals = dr.collect_signals(cfg)
        self.assertEqual(signals["mask_gate"], "FAIL")

    def test_old_reports_ignored(self):
        dr.MASK_GATE_DIR.mkdir(parents=True, exist_ok=True)
        p = dr.MASK_GATE_DIR / "mask_gate_old.json"
        p.write_text(json.dumps({"verdict": "FAIL"}), encoding="utf-8")
        # делаем файл старым
        import os
        old_ts = datetime.now().timestamp() - 7200
        os.utime(p, (old_ts, old_ts))
        cfg = dr.state_load()
        signals = dr.collect_signals(cfg)
        self.assertIsNone(signals["mask_gate"])


class TestActionRotate(DrTestBase):
    def _cfg_with_window_now(self):
        cfg = dr.state_load()
        cfg["action_rotate"] = True
        # подгоняем окно под текущий час
        h = datetime.now().hour
        cfg["rotate_window_start"] = h
        cfg["rotate_window_end"] = h + 1
        return cfg

    def test_rotate_outside_window_skipped(self):
        cfg = dr.state_load()
        cfg["rotate_window_start"] = (datetime.now().hour + 1) % 24
        cfg["rotate_window_end"] = (datetime.now().hour + 2) % 24
        res = dr.action_rotate(cfg)
        self.assertFalse(res["ok"])
        self.assertEqual(res["skipped"], "outside_window")

    def test_rotate_cooldown(self):
        cfg = self._cfg_with_window_now()
        dr._history_append(cfg, {"action": "rotate",
                                 "ts": datetime.now().isoformat(timespec="seconds")})
        res = dr.action_rotate(cfg)
        self.assertFalse(res["ok"])
        self.assertEqual(res["skipped"], "cooldown")

    def test_rotate_daily_limit(self):
        # Фейк-время 12:00 текущего дня: детерминизм против ночных запусков
        # (реальная запись «сегодня 01:00» при запуске теста в 00-07 утра
        # ловила бы cooldown раньше daily_limit). Окно тоже под фейк-время.
        class NoonDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                real = datetime.now()
                return cls(real.year, real.month, real.day, 12, 0, 0)

        cfg = dr.state_load()
        cfg["action_rotate"] = True
        cfg["rotate_window_start"] = 12   # под фейк-время 12:00
        cfg["rotate_window_end"] = 13
        today = datetime.now().strftime("%Y-%m-%d")
        # последняя ротация позавчера (cooldown прошёл), но сегодня уже 2
        cfg["history"] = [
            {"action": "rotate", "ts": (datetime.now() - timedelta(days=2)).isoformat(timespec="seconds")},
            {"action": "rotate", "ts": f"{today}T00:01:00"},
            {"action": "rotate", "ts": f"{today}T01:00:00"},
        ]
        with patch.object(dr, "datetime", NoonDatetime):
            res = dr.action_rotate(cfg)
        self.assertFalse(res["ok"])
        self.assertEqual(res["skipped"], "daily_limit")

    def test_rotate_success_calls_rotation(self):
        cfg = self._cfg_with_window_now()
        with patch("chimera.modules.credential_rotation._rotate_reality_keys",
                   return_value={"private_key": "x", "short_id": "y"}) as mock_rot:
            res = dr.action_rotate(cfg)
        self.assertTrue(res["ok"])
        mock_rot.assert_called_once()
        self.assertEqual(cfg["stats"]["rotations"], 1)

    def test_rotate_failure_sets_error(self):
        cfg = self._cfg_with_window_now()
        with patch("chimera.modules.credential_rotation._rotate_reality_keys",
                   side_effect=RuntimeError("xray binary missing")):
            res = dr.action_rotate(cfg)
        self.assertFalse(res["ok"])
        self.assertIn("error", res)


class TestRunOnce(DrTestBase):
    def test_disabled_short_circuit(self):
        cfg = dr.state_load()
        cfg["enabled"] = False
        dr.state_save(cfg)
        out = dr.dpi_response_run_once()
        self.assertFalse(out["ran"])

    def test_silence_no_actions(self):
        cfg = dr.state_load()
        dr.state_save(cfg)
        with patch.object(dr, "collect_signals",
                          return_value={"probe_score": 0, "mask_gate": None,
                                        "dpi_gate": None, "banned_now": 0}):
            out = dr.dpi_response_run_once()
        self.assertEqual(out["level"], 0)
        self.assertEqual(out["actions"], [])

    def test_level2_full_chain_notify_fuzz_rotate(self):
        cfg = dr.state_load()
        cfg["action_rotate"] = True
        h = datetime.now().hour
        cfg["rotate_window_start"] = h
        cfg["rotate_window_end"] = h + 1
        dr.state_save(cfg)
        signals = {"probe_score": 10, "mask_gate": "FAIL", "dpi_gate": None,
                   "banned_now": 2}
        with patch.object(dr, "collect_signals", return_value=signals), \
             patch.object(dr, "_tg_notify", return_value=True) as mock_tg, \
             patch.object(dr, "action_fuzz",
                          return_value={"ok": False, "error": "no xray"}), \
             patch("chimera.modules.credential_rotation._rotate_reality_keys",
                   return_value={"private_key": "x"}):
            out = dr.dpi_response_run_once()
        self.assertEqual(out["level"], 2)
        self.assertIn("notify", out["actions"])
        self.assertIn("fuzz", out["actions"])
        self.assertIn("rotate", out["actions"])
        mock_tg.assert_called()
        # state зафиксировал действия
        cfg2 = dr.state_load()
        self.assertEqual(cfg2["stats"]["notifications"], 1)
        self.assertEqual(cfg2["stats"]["fuzz_runs"], 1)
        self.assertEqual(cfg2["stats"]["rotations"], 1)

    def test_fuzz_success_prevents_rotation(self):
        """Если фаззер нашёл рабочую маскировку — ротация не нужна."""
        cfg = dr.state_load()
        cfg["action_rotate"] = True
        h = datetime.now().hour
        cfg["rotate_window_start"] = h
        cfg["rotate_window_end"] = h + 1
        dr.state_save(cfg)
        signals = {"probe_score": 5, "mask_gate": None, "dpi_gate": None,
                   "banned_now": 0}
        with patch.object(dr, "collect_signals", return_value=signals), \
             patch.object(dr, "_tg_notify", return_value=True), \
             patch.object(dr, "action_fuzz", return_value={"ok": True}), \
             patch("chimera.modules.credential_rotation._rotate_reality_keys",
                   return_value={"private_key": "x"}) as mock_rot:
            out = dr.dpi_response_run_once()
        self.assertIn("fuzz", out["actions"])
        self.assertNotIn("rotate", out["actions"])
        mock_rot.assert_not_called()

    def test_rotate_failure_degrades_to_notify_only(self):
        cfg = dr.state_load()
        cfg["action_rotate"] = True
        h = datetime.now().hour
        cfg["rotate_window_start"] = h
        cfg["rotate_window_end"] = h + 1
        dr.state_save(cfg)
        signals = {"probe_score": 400, "mask_gate": None, "dpi_gate": None,
                   "banned_now": 0}
        with patch.object(dr, "collect_signals", return_value=signals), \
             patch.object(dr, "_tg_notify", return_value=True), \
             patch.object(dr, "action_fuzz",
                          return_value={"ok": False, "error": "no xray"}), \
             patch.object(dr, "action_rotate",
                          return_value={"ok": False, "error": "rotation crashed"}):
            out = dr.dpi_response_run_once()
        # при error ротация не "skipped", а упала: actions помечают
        # rotate-skipped:<None>, детали — в history/mode ниже
        self.assertIn("rotate-skipped", str(out["actions"]))
        # run_once работает со своей копией state — проверяем файл
        cfg2 = dr.state_load()
        self.assertEqual(cfg2["mode"], "notify-only")
        self.assertIn("rotate-failed",
                      [h["action"] for h in cfg2["history"]])

    def test_notify_only_mode_skips_actions(self):
        cfg = dr.state_load()
        cfg["mode"] = "notify-only"
        dr.state_save(cfg)
        signals = {"probe_score": 5, "mask_gate": None, "dpi_gate": None,
                   "banned_now": 0}
        with patch.object(dr, "collect_signals", return_value=signals), \
             patch.object(dr, "_tg_notify", return_value=True), \
             patch.object(dr, "action_fuzz") as mock_fuzz:
            out = dr.dpi_response_run_once()
        self.assertIn("notify", out["actions"])
        self.assertNotIn("fuzz", out["actions"])
        mock_fuzz.assert_not_called()

    def test_auto_resume_after_quiet_hours(self):
        cfg = dr.state_load()
        cfg["mode"] = "notify-only"
        cfg["history"] = [
            {"action": "alert", "level": 2,
             "ts": (datetime.now() - timedelta(hours=7)).isoformat(timespec="seconds")},
        ]
        dr.state_save(cfg)
        with patch.object(dr, "collect_signals",
                          return_value={"probe_score": 0, "mask_gate": None,
                                        "dpi_gate": None, "banned_now": 0}):
            dr.dpi_response_run_once()
        cfg2 = dr.state_load()
        self.assertEqual(cfg2["mode"], "auto")
        self.assertIn("auto-resume", [h["action"] for h in cfg2["history"]])


class TestCron(DrTestBase):
    def test_cron_install_and_remove(self):
        dr.cron_install()
        self.assertTrue(dr.CRON_FILE.exists())
        content = dr.CRON_FILE.read_text(encoding="utf-8")
        self.assertIn("--dpi-response", content)
        self.assertEqual(dr.CRON_FILE.stat().st_mode & 0o777, 0o644)
        dr.cron_remove()
        self.assertFalse(dr.CRON_FILE.exists())


class TestNotifyAntiSpam(DrTestBase):
    """Анти-спам TG: уведомление — событие, а не каждый 5-минутный прогон.

    Сценарий боевого инцидента: RU-нода с постоянным фоном зондирования
    (score 26–150 при пороге 3) давала уровень 2 КАЖДЫЙ прогон крона →
    десятки одинаковых алертов в TG за утро.
    """

    SIG_L1 = {"probe_score": 50, "mask_gate": None, "dpi_gate": None,
              "banned_now": 0}           # уровень 1 (фон)
    SIG_L2 = {"probe_score": 400, "mask_gate": None, "dpi_gate": None,
              "banned_now": 0}           # уровень 2 (≥ порога атаки)
    SIG_QUIET = {"probe_score": 0, "mask_gate": None, "dpi_gate": None,
                 "banned_now": 0}

    def setUp(self):
        super().setUp()
        cfg = dr.state_load()
        cfg["action_fuzz"] = False       # изолируем логику уведомлений
        dr.state_save(cfg)

    def _run(self, signals):
        with patch.object(dr, "collect_signals", return_value=signals), \
             patch.object(dr, "_tg_notify", return_value=True):
            return dr.dpi_response_run_once()

    def test_same_level_silent_on_second_run(self):
        out1 = self._run(self.SIG_L1)
        self.assertIn("notify", out1["actions"])
        out2 = self._run(self.SIG_L1)
        self.assertNotIn("notify", out2["actions"])
        self.assertIn("notify-skipped:cooldown", out2["actions"])
        self.assertEqual(dr.state_load()["stats"]["notifications"], 1)

    def test_escalation_notifies_immediately(self):
        self._run(self.SIG_L1)
        out = self._run(self.SIG_L2)
        self.assertIn("notify", out["actions"])
        cfg = dr.state_load()
        self.assertEqual(cfg["stats"]["notifications"], 2)
        self.assertEqual(cfg["stats"]["last_notify"]["level"], 2)

    def test_reminder_after_cooldown_at_level2(self):
        self._run(self.SIG_L2)
        # состариваем last_notify на 2 часа — атака продолжается
        cfg = dr.state_load()
        cfg["stats"]["last_notify"]["ts"] = (
            datetime.now() - timedelta(hours=2)).isoformat(timespec="seconds")
        dr.state_save(cfg)
        out = self._run(self.SIG_L2)
        self.assertIn("notify", out["actions"])
        self.assertEqual(dr.state_load()["stats"]["notifications"], 2)

    def test_spike_against_baseline_elevates_level(self):
        # база ~10 → score 200: 200 ≥ 4×max(10, 40)=160 → уровень 2
        cfg = dr.state_load()
        cfg["stats"]["score_history"] = [10, 12, 11, 9, 10]
        dr.state_save(cfg)
        signals = {"probe_score": 200, "mask_gate": None,
                   "dpi_gate": None, "banned_now": 0}
        level, reasons = dr.threat_level(cfg, signals)
        self.assertEqual(level, 2)
        self.assertTrue(any("скачок" in r for r in reasons))

    def test_steady_background_is_level1(self):
        # градация: 3 ≤ score < порога атаки, без скачка против базы — фон
        cfg = dr.state_load()
        cfg["stats"]["score_history"] = [40, 45, 42]
        dr.state_save(cfg)
        signals = {"probe_score": 50, "mask_gate": None,
                   "dpi_gate": None, "banned_now": 0}
        level, _ = dr.threat_level(cfg, signals)
        self.assertEqual(level, 1)

    def test_normalization_message_once(self):
        self._run(self.SIG_L1)
        out_q1 = self._run(self.SIG_QUIET)   # quiet_runs=1 — анти-дребезг
        self.assertNotIn("notify-ok", out_q1["actions"])
        out_q2 = self._run(self.SIG_QUIET)   # quiet_runs=2 → нормализация
        self.assertIn("notify-ok", out_q2["actions"])
        out_q3 = self._run(self.SIG_QUIET)   # уже отправлено — тишина
        self.assertNotIn("notify-ok", out_q3["actions"])
        cfg = dr.state_load()
        self.assertEqual(cfg["stats"]["notifications"], 2)  # алерт + итог
        self.assertIsNone(cfg["stats"]["last_notify"])

    def test_flap_single_quiet_run_keeps_episode(self):
        # один тихий прогон внутри эпизода не рвёт его и не плодит сообщения
        self._run(self.SIG_L1)
        self._run(self.SIG_QUIET)
        out = self._run(self.SIG_L1)        # возврат фона — не новое событие
        self.assertNotIn("notify", out["actions"])
        self.assertNotIn("notify-ok", out["actions"])
        self.assertEqual(dr.state_load()["stats"]["notifications"], 1)


class TestFuzzCooldown(DrTestBase):
    def test_fuzz_not_repeated_within_cooldown(self):
        dr.state_save(dr.state_load())
        signals = {"probe_score": 50, "mask_gate": None,
                   "dpi_gate": None, "banned_now": 0}
        with patch.object(dr, "collect_signals", return_value=signals), \
             patch.object(dr, "_tg_notify", return_value=True), \
             patch.object(dr, "action_fuzz", return_value={"ok": True}) as mock_fz:
            out1 = dr.dpi_response_run_once()
            out2 = dr.dpi_response_run_once()
        self.assertIn("fuzz", out1["actions"])
        self.assertIn("fuzz-skipped:cooldown", out2["actions"])
        self.assertEqual(mock_fz.call_count, 1)
        self.assertEqual(dr.state_load()["stats"]["fuzz_runs"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
