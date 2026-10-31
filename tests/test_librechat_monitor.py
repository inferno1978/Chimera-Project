#!/usr/bin/env python3
"""Unit-тесты ops-слоя LibreChat (chimera/modules/librechat_monitor.py).

Parity-модуль: «фишки b4_monitor — теперь для LibreChat». Контракты
(зеркало test_b4_monitor.py + специфика LibreChat):

  1. EMA ttfb: быстрый старт, сглаживание α=0.35, протухшая >15 мин —
     быстрый старт снова (те же константы, что у каскада/b4).
  2. _streak_update: 1 промах при прошлом healthy — «скорельно жив»,
     2 подряд → degraded (порог каскада).
  3. _curl_probe: ok = ровно 2xx (3xx/4xx/таймаут — фейл: api/config
     при живом api отдаёт 200, фронт при живом пути — 2xx), ms-конверт,
     TIMEOUT/RESET при пустом выводе.
  4. Тик: юнит oneshot «active» ≠ api жив — проба /api/config ловит
     сдохшие контейнеры; self-heal при падении сервиса; ремедия при
     api-смерти (рестарт стека) и фронт-смерти (nginx reload, api жив);
     cooldown 600с — одно действие на окно; EMA api+front пишутся.
  5. TG-слой: анти-спам по построению (алерт ТОЛЬКО при смене,
     первое наблюдение молча); события events.<event> в telegram.json
     (отсутствующий = ВКЛ); новые действия тика → по одному алерту;
     cert-порог 14 дней — по смене (20→10 алерт, 10→20 снятие).
  6. install: timer OnCalendar *:0/1, cron-контент, wrapper bash -n,
     PYTHONPATH-safe; uninstall — чистые удаления.
  7. Интеграция: tg_bot event_labels/ev_keys содержат все EVENT_KEYS
     (кейс окт.2026 №8: событие без пункта меню — неуправляемо).
"""
from __future__ import annotations

import sys
import json
import subprocess
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

# ── Мок chimera._core (страховка как в test_b4_monitor/test_certmon_v2) ────
fake_core = types.ModuleType("chimera._core")
fake_core.STATE_FILE = Path("/tmp/test-lcmon/state.json")
for attr in ("RED", "GREEN", "YELLOW", "CYAN", "BLUE", "BOLD", "DIM",
             "WHITE", "NC"):
    setattr(fake_core, attr, "")
fake_core.success = lambda msg: print(f"[OK] {msg}")
fake_core.warn = lambda msg: print(f"[WARN] {msg}")
fake_core.info = lambda msg: print(f"[INFO] {msg}")
fake_core._run = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "", "")

_saved = {k: sys.modules.get(k) for k in ("chimera", "chimera._core")}
if "chimera" not in sys.modules:
    pkg = types.ModuleType("chimera")
    pkg.__path__ = [str(_PROJECT_ROOT / "chimera")]
    sys.modules["chimera"] = pkg
sys.modules["chimera._core"] = fake_core


def tearDownModule():
    """Снять фейки sys.modules после модуля (анти-загрязнение сьюта,
    кейс окт.2026 №8 — паттерн test_certmon_v2.py)."""
    for k, v in _saved.items():
        if v is not None:
            sys.modules[k] = v
        else:
            sys.modules.pop(k, None)


from chimera.modules import librechat_monitor as lm   # noqa: E402


def _rmtree(p: Path):
    import shutil
    shutil.rmtree(p, ignore_errors=True)


# ── Фейковый librechat (ленивая зависимость — патчим _lc) ──────────────────

class _FakeLC(types.SimpleNamespace):
    pass


def _fake_lc(app_dir: Path, state: dict, front: dict,
             active: bool = True) -> _FakeLC:
    (app_dir / "docker-compose.yml").write_text("services: {}\n")
    return _FakeLC(
        _APP_DIR=app_dir,
        _SERVICE_NAME="librechat",
        _DEFAULT_PORT=3080,
        _load_state=lambda: state,
        _nginx_status=lambda: front,
        _service_active=lambda: active,
        _nginx_url=(lambda: (f"https://{front.get('domain')}:"
                             f"{front.get('port')}")
                    if front.get("enabled") and front.get("domain")
                    else None),
        _run=lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "", ""),
    )


class _TmpBase(unittest.TestCase):
    """tmp-пути вместо системных + фейковый librechat."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="test-lcmon-"))
        self.app = self.tmp / "opt" / "librechat"
        self.app.mkdir(parents=True)
        # состояние по умолчанию: установлен, фронт включён с доменом
        self.lc_state = {"installed": True, "web_port": 3080}
        self.front = {"enabled": True, "port": 3443,
                      "domain": "chat.example.com"}
        self.lc_active = True
        self.fake = _fake_lc(self.app, self.lc_state, self.front,
                             self.lc_active)
        _p = patch.object(lm, "_lc", lambda: self.fake)
        _p.start()
        self.addCleanup(_p.stop)
        for name in ("TICK_STATE", "TG_STATE", "TG_CONFIG", "MONITOR_LOG",
                     "CRON_FILE", "TG_SCRIPT", "TICK_SCRIPT",
                     "UNIT_TICK", "UNIT_TIMER"):
            const = getattr(lm, name)
            newp = self.tmp / const.name
            _pp = patch.object(lm, name, newp)
            _pp.start()
            self.addCleanup(_pp.stop)

    def tearDown(self):
        _rmtree(self.tmp)


# ════════════════════════════════════════════════════════════════════════════
#  Чистые функции: EMA / streak / curl-парсер / cert
# ════════════════════════════════════════════════════════════════════════════

class TestPure(unittest.TestCase):
    def test_ema_fast_start(self):
        self.assertEqual(lm._ema_update(None, 120.0), 120.0)
        self.assertIsNone(lm._ema_update({"ts": time.time(), "v": 100}, None))

    def test_ema_smoothing(self):
        # α=0.35: 0.35*200 + 0.65*100 = 135
        hist = {"ts": time.time(), "v": 100}
        self.assertEqual(lm._ema_update(hist, 200.0), 135.0)

    def test_ema_stale_history(self):
        # протухла >15 мин → быстрый старт свежей пробой
        hist = {"ts": time.time() - lm.EMA_MAX_AGE_S - 1, "v": 100}
        self.assertEqual(lm._ema_update(hist, 300.0), 300.0)

    def test_streak_semantics(self):
        # ok → здоров, streak 0
        self.assertEqual(lm._streak_update(True, 0, True), (True, 0))
        self.assertEqual(lm._streak_update(False, 3, True), (True, 0))
        # 1 промах при прошлом healthy — скорельно жив
        self.assertEqual(lm._streak_update(True, 0, False), (True, 1))
        # 2 подряд → degraded
        self.assertEqual(lm._streak_update(True, 1, False), (False, 2))
        # без прошлого healthy первый же фейл — unhealthy
        self.assertEqual(lm._streak_update(None, 0, False), (False, 1))

    def test_events_labels_complete(self):
        self.assertEqual(set(lm.EVENT_KEYS), set(lm.EVENT_LABELS))


class TestCurlProbe(unittest.TestCase):
    """_curl_probe: ok = ровно 2xx; ms; таймаут/резет = фейл."""

    @staticmethod
    def _resp(stdout="", rc=0):
        return subprocess.CompletedProcess([], rc, stdout, "")

    def test_200_ok(self):
        with patch.object(lm, "_run",
                          return_value=self._resp("200 0.123\n")):
            p = lm._curl_probe("http://127.0.0.1:3080/api/config")
        self.assertTrue(p["ok"])
        self.assertEqual(p["code"], "200")
        self.assertEqual(p["ms"], 123.0)

    def test_non_2xx_fail(self):
        # api/config при живом api отдаёт 200; 4xx/3xx — не «ответ живого
        # пути» (в отличие от CDN-проб b4): 404 от мёртвого api = фейл.
        for code in ("301", "404", "500", "502"):
            with patch.object(lm, "_run",
                              return_value=self._resp(f"{code} 0.05\n")):
                p = lm._curl_probe("http://127.0.0.1:3080/api/config")
                self.assertFalse(p["ok"], code)

    def test_timeout_reset(self):
        with patch.object(lm, "_run",
                          return_value=self._resp("", rc=28)):
            p = lm._curl_probe("https://x/api/config")
        self.assertFalse(p["ok"])
        self.assertEqual(p["code"], "TIMEOUT/RESET")
        self.assertIsNone(p["ms"])

    def test_exception(self):
        with patch.object(lm, "_run", side_effect=OSError("net down")):
            p = lm._curl_probe("https://x/api/config")
        self.assertFalse(p["ok"])
        self.assertEqual(p["code"], "ERR")


class TestCertDays(_TmpBase):
    def test_missing_cert(self):
        self.assertIsNone(lm._cert_days("chat.example.com"))

    def test_parse_days(self):
        import datetime
        # файл-заглушка в tmp-LE-каталоге (LE_CERT_DIR патчится)
        le = self.tmp / "le"
        (le / "chat.example.com").mkdir(parents=True)
        (le / "chat.example.com" / "fullchain.pem").write_text("cert\n")
        # +1ч буфер: между utcnow() теста и utcnow() _cert_days проходят
        # микросекунды — int((exp - now).days) без буфера даёт 19
        expires = datetime.datetime.utcnow() + datetime.timedelta(
            days=20, hours=1)
        out = ("notAfter=" +
               expires.strftime("%b %d %H:%M:%S %Y GMT"))
        with patch.object(lm, "LE_CERT_DIR", le), \
             patch.object(lm, "_run",
                          return_value=subprocess.CompletedProcess(
                              [], 0, out, "")):
            self.assertEqual(lm._cert_days("chat.example.com"), 20)

    def test_no_domain(self):
        self.assertIsNone(lm._cert_days(None))


# ════════════════════════════════════════════════════════════════════════════
#  HEALTH-TICK
# ════════════════════════════════════════════════════════════════════════════

class TestHealthTick(_TmpBase):
    def _seed_healthy(self):
        """Сид предыдущего healthy-состояния («скорельно жив» возможен
        только при прошлом healthy — как у b4: без истории первый фейл
        сразу unhealthy)."""
        lm.TICK_STATE.write_text(json.dumps({
            "ts": time.time() - 60,
            "probe": {"healthy": True, "fail_streak": 0,
                      "ttfb_ema": 100.0},
            "front": {"applicable": True, "healthy": True,
                      "fail_streak": 0, "ttfb_ema": 120.0},
            "ema": {"api": {"ts": time.time() - 60, "v": 100.0},
                    "front": {"ts": time.time() - 60, "v": 120.0}},
            "policy": dict(lm.DEFAULT_POLICY),
        }))

    def _run_tick(self, service=True, api_ok=True, front_ok=True,
                  front_applicable=None, heal=True,
                  heal_mock=None, fix_mock=None):
        """Тик с замоканными пробами. heal_mock/fix_mock — свои моки
        (иначе дефолтные Mock(return_value=…); свои моки НЕ перекрыты
        внутренними патчами — иначе assert_called_once по внешнему
        моку всегда 0 вызовов)."""
        from unittest.mock import Mock
        if front_applicable is None:
            front_applicable = self.front.get("enabled", False)
        probe_front = ({"applicable": front_applicable,
                        "ok": front_ok, "ttfb_ms": 42.0 if front_ok
                        else None, "code": "200" if front_ok else "502"})
        hm = heal_mock if heal_mock is not None else Mock(return_value=heal)
        fm = fix_mock if fix_mock is not None else Mock(return_value=True)
        with patch.object(lm, "_probe_service", return_value=service), \
             patch.object(lm, "_probe_api",
                          return_value={"ok": api_ok,
                                        "ttfb_ms": 55.0 if api_ok else None,
                                        "code": "200" if api_ok
                                        else "TIMEOUT/RESET"}), \
             patch.object(lm, "_probe_front", return_value=probe_front), \
             patch.object(lm, "_heal_restart", hm), \
             patch.object(lm, "_front_fix_reload", fm), \
             patch.object(lm, "_cert_days", return_value=30):
            return lm.health_tick(verbose=False)

    def test_not_installed(self):
        self.lc_state["installed"] = False
        self.assertEqual(lm.health_tick(), {"installed": False})

    def test_healthy_tick_writes_state(self):
        r = self._run_tick()
        self.assertTrue(r["installed"])
        self.assertTrue(r["service"])
        self.assertTrue(r["healthy"])
        self.assertEqual(r["fail_streak"], 0)
        st = json.loads(lm.TICK_STATE.read_text())
        self.assertTrue(st["probe"]["healthy"])
        self.assertEqual(st["probe"]["ttfb_ema"], 55.0)
        self.assertTrue(st["front"]["applicable"])
        self.assertEqual(st["front"]["ttfb_ema"], 42.0)
        self.assertEqual(st["ema"]["api"]["v"], 55.0)
        self.assertEqual(st["ema"]["front"]["v"], 42.0)
        self.assertEqual(st["cert"]["days"], 30)

    def test_front_disabled_not_applicable(self):
        r = self._run_tick(front_applicable=False)
        self.assertFalse(r["front"]["applicable"])
        st = json.loads(lm.TICK_STATE.read_text())
        self.assertEqual(st["front"], {"applicable": False})
        self.assertNotIn("front", st["ema"])

    def test_service_down_selfheal(self):
        from unittest.mock import Mock
        hr = Mock(return_value=True)
        r = self._run_tick(service=False, heal_mock=hr)
        hr.assert_called_once()
        self.assertTrue(r["service"])      # поднялся после self-heal
        self.assertEqual(r["actions"], ["restart"])
        st = json.loads(lm.TICK_STATE.read_text())
        self.assertEqual(st["actions"][-1]["type"], "restart")

    def test_service_down_no_heal_when_policy_off(self):
        st = {"policy": {"restart": False, "front_fix": True}}
        lm.TICK_STATE.write_text(json.dumps(st))
        with patch.object(lm, "_heal_restart") as hr:
            r = self._run_tick(service=False)
            hr.assert_not_called()
        self.assertFalse(r["service"])

    def test_api_two_fails_degraded_and_remedy(self):
        from unittest.mock import Mock
        self._seed_healthy()
        hr = Mock(return_value=True)
        # тик 1: api промах при прошлом healthy — скорельно жив
        r1 = self._run_tick(api_ok=False, heal_mock=hr)
        self.assertTrue(r1["healthy"])
        self.assertEqual(r1["fail_streak"], 1)
        self.assertIsNone(r1["remedy"])
        # тик 2: второй промах → degraded + ремедия-рестарт
        r2 = self._run_tick(api_ok=False, heal_mock=hr)
        hr.assert_called_once()
        self.assertFalse(r2["healthy"])
        self.assertEqual(r2["fail_streak"], 2)
        self.assertEqual(r2["remedy"], "restart")
        self.assertIn("restart", r2["actions"])

    def test_remedy_cooldown(self):
        from unittest.mock import Mock
        self._seed_healthy()
        hr = Mock(return_value=True)
        # первое окно: рестарт
        self._run_tick(api_ok=False, heal_mock=hr)   # streak 1 (жив)
        self._run_tick(api_ok=False, heal_mock=hr)   # streak 2 → рестарт
        self.assertEqual(hr.call_count, 1)
        # второе окно сразу за первым: cooldown 600с — ремедии НЕТ
        r = self._run_tick(api_ok=False, heal_mock=hr)
        self.assertEqual(hr.call_count, 1)
        self.assertIsNone(r["remedy"])

    def test_front_fail_remedy_nginx_reload(self):
        from unittest.mock import Mock
        self._seed_healthy()
        hr, fx = Mock(return_value=True), Mock(return_value=True)
        # api жив, фронт 2 фейла → nginx reload, НЕ рестарт стека
        self._run_tick(front_ok=False, heal_mock=hr, fix_mock=fx)
        r = self._run_tick(front_ok=False, heal_mock=hr, fix_mock=fx)
        hr.assert_not_called()
        fx.assert_called_once()
        self.assertEqual(r["remedy"], "front_fix")
        st = json.loads(lm.TICK_STATE.read_text())
        self.assertEqual(st["actions"][-1]["type"], "front_fix")
        self.assertTrue(st["probe"]["healthy"])   # api не трогали

    def test_front_fix_policy_off(self):
        from unittest.mock import Mock
        st = {"policy": {"restart": True, "front_fix": False},
              "probe": {"healthy": True, "fail_streak": 0},
              "front": {"applicable": True, "healthy": True,
                        "fail_streak": 0}}
        lm.TICK_STATE.write_text(json.dumps(st))
        fx = Mock(return_value=True)
        self._run_tick(front_ok=False, fix_mock=fx)
        r = self._run_tick(front_ok=False, fix_mock=fx)
        fx.assert_not_called()
        self.assertFalse(r["front"]["healthy"])
        self.assertIsNone(r["remedy"])


# ════════════════════════════════════════════════════════════════════════════
#  TG-СЛОЙ
# ════════════════════════════════════════════════════════════════════════════

class TestCheckOnce(_TmpBase):
    """check_librechat_once: алерты ТОЛЬКО при смене; первое — молча."""

    def _write_tick_state(self, **kw):
        st = {"ts": time.time(),
              "probe": {"healthy": kw.get("probe_healthy", True),
                        "fail_streak": kw.get("streak", 0),
                        "ttfb_ema": kw.get("ema", 120.0)},
              "front": kw.get("front",
                              {"applicable": True, "healthy": True,
                               "fail_streak": 0, "ttfb_ema": 150.0}),
              "cert": {"ts": time.time(), "days": kw.get("cert", 30)},
              "actions": kw.get("actions", []),
              "policy": dict(lm.DEFAULT_POLICY)}
        lm.TICK_STATE.write_text(json.dumps(st))
        return st

    def _check(self, service=True, sent=None):
        sent = sent if sent is not None else []
        with patch.object(lm, "_probe_service", return_value=service), \
             patch.object(lm, "_tg_send",
                          side_effect=lambda msg, ev="": sent.append(ev)
                          or True):
            rs = lm.check_librechat_once()
        return rs, sent

    def test_first_observation_silent(self):
        self._write_tick_state()
        _, sent = self._check()
        self.assertEqual(sent, [])    # анти-спам: первое — молча

    def test_down_then_up(self):
        self._write_tick_state()
        self._check(service=True)                       # baseline
        _, sent = self._check(service=False)            # ↓ down
        self.assertEqual(sent, ["librechat_down"])
        _, sent = self._check(service=True)             # ↑ up
        self.assertEqual(sent, ["librechat_up"])

    def test_degraded_recovered(self):
        self._write_tick_state()
        self._check()                                   # baseline
        self._write_tick_state(probe_healthy=False, streak=2)
        _, sent = self._check()
        self.assertEqual(sent, ["librechat_degraded"])
        self._write_tick_state(probe_healthy=True)
        _, sent = self._check()
        self.assertEqual(sent, ["librechat_recovered"])

    def test_front_down_up(self):
        self._write_tick_state()
        self._check()
        self._write_tick_state(front={"applicable": True, "healthy": False,
                                      "fail_streak": 2})
        _, sent = self._check()
        self.assertEqual(sent, ["librechat_front_down"])
        self._write_tick_state(front={"applicable": True, "healthy": True,
                                      "fail_streak": 0})
        _, sent = self._check()
        self.assertEqual(sent, ["librechat_front_up"])

    def test_cert_threshold_crossing(self):
        self._write_tick_state(cert=30)                 # baseline: далеко
        self._check()
        self._write_tick_state(cert=10)                 # ↓ порог 14
        _, sent = self._check()
        self.assertEqual(sent, ["librechat_cert_expire"])
        # ещё тик на 10 — НЕ спамим (состояние не менялось)
        _, sent = self._check()
        self.assertEqual(sent, [])
        self._write_tick_state(cert=30)                 # ↑ продлён
        _, sent = self._check()
        self.assertEqual(sent, ["librechat_cert_expire"])

    def test_stalled(self):
        self._write_tick_state()
        self._check()
        st = self._write_tick_state()
        st["ts"] = time.time() - lm.STALE_AFTER - 10
        lm.TICK_STATE.write_text(json.dumps(st))
        _, sent = self._check()
        self.assertEqual(sent, ["librechat_stalled"])
        # тик ожил → снятие
        self._write_tick_state()
        _, sent = self._check()
        self.assertEqual(sent, ["librechat_stalled"])

    def test_new_actions_alerted_once(self):
        self._write_tick_state()
        self._check()
        a = {"ts": time.time(), "type": "restart",
             "detail": "self-heal: ок"}
        self._write_tick_state(actions=[a])
        rs, sent = self._check()
        self.assertEqual(sent, ["librechat_restarted"])
        self.assertTrue(any(r["id"] == "action" and r["changed"]
                            for r in rs))
        # повторный чек — действие уже не «новое»
        _, sent = self._check()
        self.assertEqual(sent, [])

    def test_action_front_fix_event(self):
        self._write_tick_state()
        self._check()
        a = {"ts": time.time(), "type": "front_fix",
             "detail": "nginx reload — ок"}
        self._write_tick_state(actions=[a])
        _, sent = self._check()
        self.assertEqual(sent, ["librechat_front_fix"])

    def test_events_filter_respected(self):
        # librechat_down выключен в telegram.json → алерт не уходит
        lm.TG_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        lm.TG_CONFIG.write_text(json.dumps(
            {"token": "T", "chat_id": "1",
             "events": {"librechat_down": False}}))
        self._write_tick_state()
        self._check()
        self._write_tick_state(probe_healthy=False, streak=2)
        with patch.object(lm, "_tg_send", return_value=False) as ts:
            lm.check_librechat_once()
            # вызов был, но events-фильтр вернул False (SKIPPED/off)
            ts.assert_called_once()
            args = ts.call_args[0]
            self.assertEqual(args[1], "librechat_degraded")

    def test_no_state_file(self):
        rs = lm.check_librechat_once()
        self.assertEqual(rs, [])


# ════════════════════════════════════════════════════════════════════════════
#  INSTALL / UNINSTALL
# ════════════════════════════════════════════════════════════════════════════

class TestInstall(_TmpBase):
    def test_install_units_and_scripts(self):
        with patch.object(lm, "_run",
                          return_value=subprocess.CompletedProcess(
                              [], 0, "", "")):
            ok, msg = lm.install_librechat_monitor(5)
        self.assertTrue(ok, msg)
        # timer: 1/мин (OnCalendar *:0/1), Persistent
        timer = lm.UNIT_TIMER.read_text()
        self.assertIn("OnCalendar=*:0/1", timer)
        self.assertIn("Persistent=true", timer)
        # unit: oneshot + наш wrapper
        unit = lm.UNIT_TICK.read_text()
        self.assertIn("Type=oneshot", unit)
        self.assertIn(str(lm.TICK_SCRIPT), unit)
        # wrappers: bash -n + PYTHONPATH-safe + нужная функция
        for script, fn in ((lm.TICK_SCRIPT, "health_tick_cli"),
                           (lm.TG_SCRIPT, "check_librechat_once")):
            body = script.read_text()
            self.assertEqual(script.stat().st_mode & 0o111, 0o111)
            self.assertIn("export PYTHONPATH=", body)
            self.assertIn(fn, body)
            r = subprocess.run(["bash", "-n", str(script)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
        # cron: */5 + наш wrapper
        cron = lm.CRON_FILE.read_text()
        self.assertIn("*/5 * * * * root", cron)
        self.assertIn(str(lm.TG_SCRIPT), cron)
        self.assertTrue(lm.is_monitor_installed())

    def test_get_installed_interval(self):
        with patch.object(lm, "_run",
                          return_value=subprocess.CompletedProcess(
                              [], 0, "", "")):
            lm.install_librechat_monitor(10)
        self.assertEqual(lm.get_installed_interval(), 10)

    def test_uninstall_removes_everything(self):
        with patch.object(lm, "_run",
                          return_value=subprocess.CompletedProcess(
                              [], 0, "", "")):
            lm.install_librechat_monitor(5)
            lm.TG_STATE.write_text("{}")
            ok, _msg = lm.uninstall_librechat_monitor()
        self.assertTrue(ok)
        for p in (lm.UNIT_TICK, lm.UNIT_TIMER, lm.TICK_SCRIPT,
                  lm.CRON_FILE, lm.TG_SCRIPT, lm.TG_STATE):
            self.assertFalse(p.exists(), p)
        self.assertFalse(lm.is_monitor_installed())


# ════════════════════════════════════════════════════════════════════════════
#  ИНТЕГРАЦИЯ: tg_bot знает все события монитора (кейс окт.2026 №8)
# ════════════════════════════════════════════════════════════════════════════

class TestTgBotIntegration(unittest.TestCase):
    def test_event_keys_in_tg_bot_menu(self):
        import ast
        src = (_PROJECT_ROOT / "chimera" / "modules" /
               "tg_bot.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        # event_labels (dict в do_manage_telegram) + ev_keys (список ч.3)
        found_labels, found_keys = set(), set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for k in node.keys:
                    if (isinstance(k, ast.Constant)
                            and isinstance(k.value, str)
                            and k.value in lm.EVENT_LABELS):
                        found_labels.add(k.value)
            if (isinstance(node, ast.Assign)
                    and getattr(node.targets[0], "id", "") == "ev_keys"
                    and isinstance(node.value, ast.List)):
                for el in node.value.elts:
                    if (isinstance(el, ast.Constant)
                            and el.value in lm.EVENT_KEYS):
                        found_keys.add(el.value)
        self.assertEqual(found_labels, set(lm.EVENT_KEYS),
                         f"нет в event_labels: "
                         f"{set(lm.EVENT_KEYS) - found_labels}")
        self.assertEqual(found_keys, set(lm.EVENT_KEYS),
                         f"нет в ev_keys: "
                         f"{set(lm.EVENT_KEYS) - found_keys}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
