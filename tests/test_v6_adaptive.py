#!/usr/bin/env python3
"""
tests/test_v6_adaptive.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты v6-adaptive watcher (chimera/modules/v6_adaptive.py).

Покрывает:
  1. _probe_v6 — парсинг проб (адрес/маршрут/двойной ping-таргет)
  2. run_once — контракт адаптива: skip-explicit / noop / switched
     (в обе стороны: v6 ожил и v6 умер) / busy / no-state / no-config
  3. Откаты: провал валидации (rollback-validate) и рестарта
     (rollback-restart) — конфиг восстанавливается байт-в-байт
  4. Интеграция с domain_strategy.apply_domain_strategy_to_config —
     реальный патч конфига (dns.queryStrategy + freedom + v6-DNS-чистка)
  5. Cron lifecycle: install/uninstall, клэмп интервала, контент
  6. enable/disable: state['strategy']='' без потери соседних ключей
  7. CLI main(): check/on/off/status
  8. TUI «Настройки сети → V»: чистые рендеры (_status_rows/_report_text/
     _log_tail) + smoke do_v6_adaptive_menu с фейковым chimera._core
     (канон tests/test_awg_ui_smoke.py) + строковые ассерты на _core.py
     (канон test_dns_redirect: пункт меню залочен)

Изоляция: все пути модуля патчатся на tmp; пробы/рестарты/TG — моки.
Реальных записей в /etc, /var, systemctl — НЕТ.
"""
from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import v6_adaptive as v6a  # noqa: E402
from chimera.modules.domain_strategy import (  # noqa: E402
    apply_domain_strategy_to_config,
)


# ── Фикстуры ─────────────────────────────────────────────────────────────────

class _R:
    """Заглушка результата subprocess.run."""
    def __init__(self, rc=0, out=""):
        self.returncode = rc
        self.stdout = out
        self.stderr = ""


def _fake_runner(responses):
    """responses: список (префикс-кортеж, _R); первое совпадение выигрывает."""
    def run(cmd, **kw):
        for pre, r in responses:
            if tuple(cmd[:len(pre)]) == tuple(pre):
                return r
        return _R(1, "")
    return run


def _cfg_xray(qs="UseIPv4", ds="UseIPv4", dns_servers=None):
    """Минимальный xray-конфиг: freedom direct в каноничной ДУАЛ-форме
    (settings.domainStrategy + streamSettings.sockopt.domainStrategy —
    как пишут генераторы Химеры), иначе патчер видит «изменение» там,
    где реальный конфиг уже соответствовал стратегии."""
    return {
        "log": {"loglevel": "warning"},
        "dns": {"queryStrategy": qs,
                "servers": dns_servers if dns_servers is not None
                else ["1.1.1.1", "8.8.8.8"]},
        "outbounds": [
            {"protocol": "freedom", "tag": "direct",
             "settings": {"domainStrategy": ds},
             "streamSettings": {"sockopt": {"domainStrategy": ds}}},
            {"protocol": "freedom", "tag": "xray-stats-api",
             "settings": {}},
        ],
        "inbounds": [{"protocol": "vless", "tag": "vless-in"}],
    }


class _Isolated(unittest.TestCase):
    """tmp-изоляция всех путей v6_adaptive + моки тяжёлых операций."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self.state_f = self._tmp / "state.json"
        self.cfg_f = self._tmp / "config.json"
        self.marker_f = self._tmp / "marker.json"
        self.lock_f = self._tmp / "v6a.lock"
        self.cron_f = self._tmp / "cron.d" / "chimera-v6-adaptive"
        self.script_f = self._tmp / "bin" / "chimera-v6-adaptive.sh"
        self.log_f = self._tmp / "v6a.log"
        self.tg_f = self._tmp / "telegram.json"

        self._patchers = [
            patch.object(v6a, "STATE_FILE", self.state_f),
            patch.object(v6a, "XRAY_CONFIG", self.cfg_f),
            patch.object(v6a, "MARKER_FILE", self.marker_f),
            patch.object(v6a, "LOCK_FILE", self.lock_f),
            patch.object(v6a, "CRON_FILE", self.cron_f),
            patch.object(v6a, "CRON_SCRIPT", self.script_f),
            patch.object(v6a, "LOG_FILE", self.log_f),
            patch.object(v6a, "TG_CFG_FILE", self.tg_f),
        ]
        for p in self._patchers:
            p.start()
            self.addCleanup(p.stop)

        self.mock_tg = MagicMock()
        self._tg_patch = patch.object(v6a, "_tg_notify", self.mock_tg)
        self._tg_patch.start()
        self.addCleanup(self._tg_patch.stop)

    def _set_state(self, state: dict):
        self.state_f.write_text(json.dumps(state), encoding="utf-8")

    def _set_cfg(self, cfg: dict):
        self.cfg_f.write_text(json.dumps(cfg, indent=2),
                              encoding="utf-8")

    def _run(self, **kw):
        """run_once с замоканными пробой/валидацией/рестартом."""
        defaults = dict(probe=(False, "egress мёртв"),
                        test_ok=True, restart=True)
        defaults.update(kw)
        with patch.object(v6a, "_probe_v6",
                          return_value=defaults["probe"]), \
             patch.object(v6a, "_xray_test_ok",
                          return_value=defaults["test_ok"]), \
             patch.object(v6a, "_safe_restart",
                          return_value=defaults["restart"]) as m_restart:
            rep = v6a.run_once(apply=True)
            return rep, m_restart


# ── 1. Пробы ─────────────────────────────────────────────────────────────────

class TestProbeV6(unittest.TestCase):

    def test_alive_first_target(self):
        run = _fake_runner([
            (("ip", "-6", "addr"), _R(0, "inet6 2a10:ab80:103:5::2/64 scope global")),
            (("ip", "-6", "route"), _R(0, "default via 2a10:ab80:103:5::1")),
            (("ping",), _R(0, "")),
        ])
        alive, detail = v6a._probe_v6(runner=run)
        self.assertTrue(alive)

    def test_alive_second_target(self):
        # первый таргет loss, второй отвечает (ранний выход по успеху)
        seq = {"n": 0}
        def run(cmd, **kw):
            t = tuple(cmd)
            if t[0] == "ip":
                return _R(0, "inet6 2a10::1/64\ndefault via 2a10::1")
            seq["n"] += 1
            return _R(0 if seq["n"] >= 2 else 1, "")
        alive, _ = v6a._probe_v6(runner=run)
        self.assertTrue(alive)

    def test_dead_egress(self):
        run = _fake_runner([
            (("ip", "-6", "addr"), _R(0, "inet6 2a10:ab80:103:5::2/64 scope global")),
            (("ip", "-6", "route"), _R(0, "default via 2a10:ab80:103:5::1")),
            (("ping",), _R(1, "")),
        ])
        alive, detail = v6a._probe_v6(runner=run)
        self.assertFalse(alive)
        self.assertIn("egress мёртв", detail)

    def test_no_global_address(self):
        run = _fake_runner([(("ip", "-6", "addr"), _R(0, ""))])
        alive, detail = v6a._probe_v6(runner=run)
        self.assertFalse(alive)
        self.assertIn("нет глобального", detail)

    def test_no_default_route(self):
        run = _fake_runner([
            (("ip", "-6", "addr"), _R(0, "inet6 2a10::2/64 scope global")),
            (("ip", "-6", "route"), _R(0, "2a10::/64 dev eth0")),
        ])
        alive, detail = v6a._probe_v6(runner=run)
        self.assertFalse(alive)
        self.assertIn("default-маршрут", detail)


# ── 2-4. run_once: контракт и откаты ────────────────────────────────────────

class TestRunOnce(_Isolated):

    def test_no_state(self):
        rep, _ = self._run()
        self.assertEqual(rep["action"], "no-state")

    def test_skip_explicit_choice(self):
        # кейс 91.х: явный выбор юзера — watcher не трогает НИКОГДА
        self._set_state({"strategy": "UseIPv4", "domain": "x.com"})
        self._set_cfg(_cfg_xray(qs="UseIPv4"))
        rep, m_restart = self._run(probe=(True, "жив"))
        self.assertEqual(rep["action"], "skip-explicit")
        m_restart.assert_not_called()
        # конфиг не переписан
        self.assertEqual(
            json.loads(self.cfg_f.read_text())["dns"]["queryStrategy"],
            "UseIPv4")

    def test_noop_when_target_matches(self):
        # адаптив + v6 мёртв + конфиг уже UseIPv4 → ничего не делает
        self._set_state({"strategy": ""})
        self._set_cfg(_cfg_xray(qs="UseIPv4", ds="UseIPv4"))
        rep, m_restart = self._run(probe=(False, "egress мёртв"))
        self.assertEqual(rep["action"], "noop")
        m_restart.assert_not_called()
        self.assertEqual(
            json.loads(self.marker_f.read_text())["action"], "noop")

    def test_switch_down_when_v6_died(self):
        # v6 отвалился ПОСЛЕ установки: UseIPv6v4 → UseIPv4
        self._set_state({"strategy": ""})
        self._set_cfg(_cfg_xray(qs="UseIPv6v4", ds="UseIPv6v4"))
        rep, m_restart = self._run(probe=(False, "egress мёртв"))
        self.assertEqual(rep["action"], "switched")
        self.assertEqual(rep["from"], "UseIPv6v4")
        self.assertEqual(rep["to"], "UseIPv4")
        m_restart.assert_called_once()
        cfg = json.loads(self.cfg_f.read_text())
        self.assertEqual(cfg["dns"]["queryStrategy"], "UseIPv4")
        direct = [o for o in cfg["outbounds"]
                  if o.get("tag") == "direct"][0]
        self.assertEqual(direct["settings"]["domainStrategy"], "UseIPv4")
        # дуал-запись: sockopt тоже переведён
        self.assertEqual(
            direct["streamSettings"]["sockopt"]["domainStrategy"],
            "UseIPv4")
        # бэкак создан и содержит прежний текст
        baks = list(self._tmp.glob("config.json.v6adapt-*.bak"))
        self.assertEqual(len(baks), 1)
        self.assertIn("UseIPv6v4", baks[0].read_text())
        # TG-уведомление о переключении
        self.mock_tg.assert_called_once()
        self.assertIn("UseIPv4", self.mock_tg.call_args.args[0])

    def test_switch_up_when_v6_alive(self):
        # КЕЙС Intezio: v6 ожил после починки хостера → UseIPv4 → UseIPv6v4
        self._set_state({"strategy": ""})
        self._set_cfg(_cfg_xray(qs="UseIPv4", ds="UseIPv4"))
        rep, _ = self._run(probe=(True, "жив"))
        self.assertEqual(rep["action"], "switched")
        self.assertEqual(rep["to"], "UseIPv6v4")
        cfg = json.loads(self.cfg_f.read_text())
        self.assertEqual(cfg["dns"]["queryStrategy"], "UseIPv6v4")

    def test_auto_value_accepted(self):
        # "auto" в state — тоже адаптив (либеральный приём)
        self._set_state({"strategy": "auto"})
        self._set_cfg(_cfg_xray(qs="UseIPv4"))
        rep, _ = self._run(probe=(False, "egress мёртв"))
        self.assertEqual(rep["action"], "noop")

    def test_no_config(self):
        self._set_state({"strategy": ""})
        rep, _ = self._run()
        self.assertEqual(rep["action"], "no-config")

    def test_busy_when_locked(self):
        import fcntl
        self._set_state({"strategy": ""})
        self.lock_f.parent.mkdir(parents=True, exist_ok=True)
        fd = open(self.lock_f, "a")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            rep = v6a.run_once(apply=True)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            fd.close()
        self.assertEqual(rep["action"], "busy")

    def test_dns_v6_servers_purged_on_useipv4(self):
        # интеграция с реальным apply_domain_strategy_to_config:
        # при UseIPv4 мёртвые v6-DNS вычищаются из dns.servers
        self._set_state({"strategy": ""})
        self._set_cfg(_cfg_xray(qs="UseIPv6v4", ds="UseIPv6v4",
                                dns_servers=["1.1.1.1",
                                             "2606:4700:4700::1111"]))
        rep, _ = self._run(probe=(False, "egress мёртв"))
        self.assertEqual(rep["action"], "switched")
        servers = json.loads(self.cfg_f.read_text())["dns"]["servers"]
        self.assertEqual(servers, ["1.1.1.1"])

    def test_stats_api_freedom_untouched(self):
        # служебный freedom xray-stats-api не получает domainStrategy
        self._set_state({"strategy": ""})
        self._set_cfg(_cfg_xray(qs="UseIPv4", ds="UseIPv4"))
        self._run(probe=(True, "жив"))
        cfg = json.loads(self.cfg_f.read_text())
        stats = [o for o in cfg["outbounds"]
                 if o.get("tag") == "xray-stats-api"][0]
        self.assertNotIn("domainStrategy", stats.get("settings", {}))

    def test_rollback_on_validate_fail(self):
        # xray -test провален → конфиг откачен байт-в-байт, НЕТ рестарта
        self._set_state({"strategy": ""})
        self._set_cfg(_cfg_xray(qs="UseIPv4", ds="UseIPv4"))
        before = self.cfg_f.read_text()
        rep, m_restart = self._run(probe=(True, "жив"), test_ok=False)
        self.assertEqual(rep["action"], "rollback-validate")
        self.assertEqual(self.cfg_f.read_text(), before)
        m_restart.assert_not_called()
        self.mock_tg.assert_called_once()

    def test_rollback_on_restart_fail(self):
        # рестарт не удался → текст возвращён + повторный рестарт на старом
        self._set_state({"strategy": ""})
        self._set_cfg(_cfg_xray(qs="UseIPv4", ds="UseIPv4"))
        before = self.cfg_f.read_text()
        rep, m_restart = self._run(probe=(True, "жив"), restart=False)
        self.assertEqual(rep["action"], "rollback-restart")
        self.assertEqual(self.cfg_f.read_text(), before)
        # дважды: неудачный рестарт + рестарт отката
        self.assertEqual(m_restart.call_count, 2)
        self.mock_tg.assert_called_once()

    def test_dry_run_does_not_touch_config(self):
        self._set_state({"strategy": ""})
        self._set_cfg(_cfg_xray(qs="UseIPv4", ds="UseIPv4"))
        before = self.cfg_f.read_text()
        with patch.object(v6a, "_probe_v6", return_value=(True, "жив")):
            rep = v6a.run_once(apply=False)
        self.assertEqual(rep["action"], "dry-run")
        self.assertEqual(rep["target"], "UseIPv6v4")
        self.assertEqual(self.cfg_f.read_text(), before)
        self.mock_tg.assert_not_called()

    def test_backups_pruned(self):
        # старые бэкапы подрезаются до BACKUP_KEEP
        self._set_state({"strategy": ""})
        self._set_cfg(_cfg_xray(qs="UseIPv4", ds="UseIPv4"))
        for i in range(v6a.BACKUP_KEEP + 3):
            (self._tmp / f"config.json.v6adapt-20261103-10000{i}.bak") \
                .write_text("{}", encoding="utf-8")
        self._run(probe=(True, "жив"))
        baks = list(self._tmp.glob("config.json.v6adapt-*.bak"))
        self.assertEqual(len(baks), v6a.BACKUP_KEEP)


# ── 5. Cron lifecycle ────────────────────────────────────────────────────────

class TestCronLifecycle(_Isolated):

    def test_install_content(self):
        ok, msg = v6a.install_watcher(10)
        self.assertTrue(ok)
        self.assertIn("10", msg)
        cron = self.cron_f.read_text()
        self.assertIn("*/10 * * * * root", cron)
        self.assertIn(str(self.script_f), cron)
        script = self.script_f.read_text()
        self.assertIn("from chimera.modules.v6_adaptive import run_once",
                      script)
        self.assertIn("PYTHONPATH", script)

    def test_interval_clamp(self):
        ok, msg = v6a.install_watcher(0)
        self.assertTrue(ok)
        self.assertIn("*/1", self.cron_f.read_text())
        ok, _ = v6a.install_watcher(999)
        self.assertTrue(ok)
        self.assertIn("*/60", self.cron_f.read_text())

    def test_uninstall(self):
        v6a.install_watcher(10)
        ok, _ = v6a.uninstall_watcher()
        self.assertTrue(ok)
        self.assertFalse(self.cron_f.exists())
        self.assertFalse(self.script_f.exists())


# ── 6. enable / disable ──────────────────────────────────────────────────────

class TestEnableDisable(_Isolated):

    def test_enable_sets_adaptive_and_keeps_keys(self):
        self._set_state({"strategy": "UseIPv4", "domain": "x.com",
                         "uuid": "U"})
        with patch.object(v6a, "run_once",
                          return_value={"action": "noop"}) as m_run:
            ok, msg = v6a.enable()
        self.assertTrue(ok)
        st = json.loads(self.state_f.read_text())
        self.assertEqual(st["strategy"], "")
        self.assertEqual(st["domain"], "x.com")   # соседние ключи целы
        self.assertEqual(st["uuid"], "U")
        self.assertTrue(self.cron_f.exists())
        m_run.assert_called_once()

    def test_enable_without_state(self):
        ok, msg = v6a.enable()
        self.assertFalse(ok)
        self.assertIn("state.json", msg)

    def test_disable_keeps_state(self):
        self._set_state({"strategy": ""})
        v6a.install_watcher(10)
        ok, msg = v6a.disable()
        self.assertTrue(ok)
        self.assertFalse(self.cron_f.exists())
        self.assertEqual(
            json.loads(self.state_f.read_text())["strategy"], "")


# ── 7. CLI ───────────────────────────────────────────────────────────────────

class TestCli(_Isolated):

    def test_check_flag(self):
        self._set_state({"strategy": ""})
        with patch.object(v6a, "run_once",
                          return_value={"action": "noop"}) as m_run:
            rc = v6a.main(["--v6-adaptive-check"])
        self.assertEqual(rc, 0)
        m_run.assert_called_once()

    def test_on_off_status(self):
        self._set_state({"strategy": "UseIPv4"})
        with patch.object(v6a, "run_once",
                          return_value={"action": "noop"}):
            rc = v6a.main(["--v6-adaptive", "on"])
            self.assertEqual(rc, 0)
            self.assertEqual(
                json.loads(self.state_f.read_text())["strategy"], "")
        rc = v6a.main(["--v6-adaptive", "off"])
        self.assertEqual(rc, 0)
        self.assertFalse(self.cron_f.exists())
        with patch.object(v6a, "_probe_v6", return_value=(False, "мёртв")):
            rc = v6a.main(["--v6-adaptive", "status"])
        self.assertEqual(rc, 0)

    def test_status_fields(self):
        self._set_state({"strategy": "UseIPv4"})
        self._set_cfg(_cfg_xray(qs="UseIPv4"))
        with patch.object(v6a, "_probe_v6", return_value=(False, "мёртв")):
            st = v6a.status()
        self.assertFalse(st["adaptive"])          # явный выбор — не адаптив
        self.assertEqual(st["strategy_state"], "UseIPv4")
        self.assertEqual(st["target"], "UseIPv4")
        self.assertEqual(st["current_query_strategy"], "UseIPv4")
        self.assertEqual(st["last"], {})          # маркера ещё нет


# ── 8. TUI «Настройки сети → V» ──────────────────────────────────────────────

class TestStatusRows(unittest.TestCase):
    """_status_rows: (label, value, цвет) для всех состояний."""

    def _st(self, **kw):
        base = {"strategy_state": "", "adaptive": True, "cron_installed": True,
                "v6_alive": False, "v6_detail": "egress мёртв (обе пробы loss)",
                "target": "UseIPv4", "current_query_strategy": "UseIPv4",
                "last": {"action": "noop", "ts": "2026-11-03 20:00:00"}}
        base.update(kw)
        return base

    def test_adaptive_on_dead_v6(self):
        rows = {r[0]: r for r in v6a._status_rows(self._st())}
        self.assertIn("АДАПТИВНЫЙ", rows["Режим"][1])
        self.assertEqual(rows["Режим"][2], v6a.C_OK)
        self.assertEqual(rows["Наблюдатель"][2], v6a.C_OK)
        self.assertIn("мёртв", rows["IPv6 сейчас"][1])
        self.assertEqual(rows["IPv6 сейчас"][2], v6a.C_BAD)
        self.assertEqual(rows["Цель стратегии"][1], "UseIPv4")
        self.assertIn("UseIPv4", rows["В конфиге Xray"][1])
        self.assertIn("noop", rows["Последний прогон"][1])

    def test_explicit_choice(self):
        rows = {r[0]: r for r in v6a._status_rows(
            self._st(adaptive=False, strategy_state="UseIPv4"))}
        self.assertIn("UseIPv4", rows["Режим"][1])
        self.assertEqual(rows["Режим"][2], v6a.C_WARN)
        # цель показываем только в адаптиве — при явном выборе её нет
        self.assertNotIn("Цель стратегии", rows)

    def test_v6_alive(self):
        rows = {r[0]: r for r in v6a._status_rows(
            self._st(v6_alive=True,
                     v6_detail="жив (ответ от 2001:4860:4860::8888)",
                     target="UseIPv6v4",
                     current_query_strategy="UseIPv6v4"))}
        # вердикт приходит из details пробы — без дублирования «ЖИВ (жив…)»
        self.assertEqual(rows["IPv6 сейчас"][1],
                         "жив (ответ от 2001:4860:4860::8888)")
        self.assertEqual(rows["IPv6 сейчас"][2], v6a.C_OK)
        self.assertEqual(rows["Цель стратегии"][1], "UseIPv6v4")

    def test_v6_alive_no_detail(self):
        # пустой detail → короткий вердикт, не пустая строка
        rows = {r[0]: r for r in v6a._status_rows(
            self._st(v6_alive=True, v6_detail=""))}
        self.assertEqual(rows["IPv6 сейчас"][1], "жив")

    def test_empty_query_strategy_and_no_last(self):
        rows = {r[0]: r for r in v6a._status_rows(
            self._st(current_query_strategy="", last={}))}
        self.assertIn("не задан", rows["В конфиге Xray"][1])
        self.assertNotIn("Последний прогон", rows)

    def test_cron_missing_dim(self):
        rows = {r[0]: r for r in v6a._status_rows(
            self._st(cron_installed=False))}
        self.assertEqual(rows["Наблюдатель"][1], "не установлен")
        self.assertEqual(rows["Наблюдатель"][2], v6a.C_DIM)


class TestReportText(unittest.TestCase):

    def test_switched(self):
        txt = v6a._report_text({"action": "switched", "from": "UseIPv4",
                                "to": "UseIPv6v4", "alive": True})
        self.assertIn("UseIPv4 → UseIPv6v4", txt)
        self.assertIn("v6 ожил", txt)

    def test_all_actions_have_labels(self):
        actions = {"no-state", "skip-explicit", "no-config", "bad-config",
                   "busy", "noop", "dry-run", "switched", "fail-write",
                   "rollback-validate", "rollback-restart"}
        self.assertEqual(set(v6a._REPORT_LABELS), actions)
        for a in actions:
            self.assertTrue(v6a._report_text({"action": a}))
        # неизвестный action → сам идентификатор (не пустота)
        self.assertEqual(v6a._report_text({"action": "weird"}), "weird")


class TestLogTail(_Isolated):

    def test_tail_and_missing(self):
        self.assertEqual(v6a._log_tail(), [])          # файла нет → []
        self.log_f.write_text("l1\nl2\nl3\n", encoding="utf-8")
        self.assertEqual(v6a._log_tail(2), ["l2", "l3"])


class TestTuiSmoke(_Isolated):
    """do_v6_adaptive_menu с фейковым chimera._core (канон
    tests/test_awg_ui_smoke.py) + патченный input: меню рисуется
    box-рендерером, действия диспетчеризуются, под пайпом (EOF) не падает."""

    def _fake_core(self):
        calls = []
        def rec(name):
            def f(*a, **kw):
                calls.append((name,) + a)
            return f
        m = types.ModuleType("chimera._core")
        for n in ("_box_top", "_box_row", "_box_item", "_box_desc",
                  "_box_sep", "_box_back", "_box_bottom"):
            setattr(m, n, rec(n))
        for n in ("info", "success", "warn", "log_to_file"):
            setattr(m, n, rec(n))
        for c in ("RED", "GREEN", "YELLOW", "DIM", "CYAN", "BLUE", "NC"):
            setattr(m, c, "")
        m._calls = calls
        return m

    def _st(self, **kw):
        base = {"strategy_state": "", "adaptive": False,
                "cron_installed": False, "v6_alive": False,
                "v6_detail": "egress мёртв", "target": "UseIPv4",
                "current_query_strategy": "UseIPv4", "last": {}}
        base.update(kw)
        return base

    def _menu(self, fake, answers, **st_kw):
        """Прогон меню: фейковый _core + патчи status/enable/disable/
        run_once + input(answers). Возвращает мок действий."""
        sys.modules["chimera._core"] = fake
        self.addCleanup(sys.modules.pop, "chimera._core", None)
        m_act = MagicMock()
        m_act.enable.return_value = (True, "вкл")
        m_act.disable.return_value = (True, "выкл")
        m_act.run_once.return_value = {"action": "switched",
                                       "from": "UseIPv4",
                                       "to": "UseIPv6v4", "alive": True}
        patches = [
            patch.object(v6a, "status", return_value=self._st(**st_kw)),
            patch.object(v6a, "enable", m_act.enable),
            patch.object(v6a, "disable", m_act.disable),
            patch.object(v6a, "run_once", m_act.run_once),
            patch("builtins.input", side_effect=answers),
            patch("os.system", return_value=0),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        v6a.do_v6_adaptive_menu()
        return m_act

    def test_renders_and_back(self):
        fake = self._fake_core()
        self._menu(fake, ["q"])   # Q — что рендерит _box_back()
        tops = [c for c in fake._calls if c[0] == "_box_top"]
        self.assertTrue(tops)
        self.assertIn("V6-ADAPTIVE", tops[0][1])
        # статус отрисован строками (Режим/Наблюдатель/IPv6 сейчас)
        rows = "\n".join(str(c) for c in fake._calls)
        for label in ("Режим", "Наблюдатель", "IPv6 сейчас"):
            self.assertIn(label, rows)

    def test_enable_flow(self):
        fake = self._fake_core()
        m = self._menu(fake, ["1", "", "b"])        # адаптив выключен
        m.enable.assert_called_once()
        m.disable.assert_not_called()
        self.assertIn(("success", "вкл"), fake._calls)

    def test_disable_flow(self):
        fake = self._fake_core()
        m = self._menu(fake, ["1", "", "b"], adaptive=True,
                       cron_installed=True)
        m.disable.assert_called_once()
        m.enable.assert_not_called()
        self.assertIn(("success", "выкл"), fake._calls)

    def test_manual_run_once(self):
        fake = self._fake_core()
        m = self._menu(fake, ["2", "", "b"])
        m.run_once.assert_called_once_with(apply=True)
        infos = [c[1] for c in fake._calls
                 if c[0] == "info" and len(c) > 1 and isinstance(c[1], str)]
        self.assertTrue(any("UseIPv4 → UseIPv6v4" in t for t in infos))

    def test_details_flow(self):
        marker = {"action": "switched", "ts": "2026-11-03 21:00:00",
                  "from": "UseIPv4", "to": "UseIPv6v4", "alive": True}
        self.marker_f.write_text(json.dumps(marker), encoding="utf-8")
        self.log_f.write_text("2026-11-03 21:00:00 switched\n",
                              encoding="utf-8")
        fake = self._fake_core()
        self._menu(fake, ["3", "", "b"])
        tops = [c[1] for c in fake._calls if c[0] == "_box_top"]
        self.assertTrue(any("ПОСЛЕДНИЙ ПРОГОН" in t for t in tops))
        rows = "\n".join(str(c) for c in fake._calls)
        self.assertIn("switched", rows)

    def test_invalid_choice(self):
        fake = self._fake_core()
        m = self._menu(fake, ["9", "", "b"])
        m.enable.assert_not_called()
        m.disable.assert_not_called()
        m.run_once.assert_not_called()
        self.assertTrue(any(c[0] == "warn" for c in fake._calls))

    def test_eof_no_crash(self):
        # пайп: EOF на первом же «Выбор:» — выход без исключений
        fake = self._fake_core()
        m = self._menu(fake, [EOFError()])
        m.enable.assert_not_called()

    def test_eof_midflow_no_crash(self):
        # EOF на «Нажмите Enter» после действия — проглочен (_pause),
        # затем EOF на «Выбор:» — выход; действие успело отработать
        fake = self._fake_core()
        m = self._menu(fake, ["1", EOFError(), EOFError()])
        m.enable.assert_called_once()


class TestCoreIntegration(unittest.TestCase):
    """Строковые ассерты на _core.py (канон test_dns_redirect: вход в
    меню залочен, чтобы рефакторинг монолита не потерял пункт V)."""

    def test_menu_network_has_v_item(self):
        core_src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        self.assertIn('_box_item("V"', core_src)
        self.assertIn("do_v6_adaptive_menu", core_src)

    def test_domain_strategy_mentions_watcher(self):
        core_src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        self.assertIn("Снять наблюдатель v6-adaptive", core_src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
