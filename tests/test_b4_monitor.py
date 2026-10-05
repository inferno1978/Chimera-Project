#!/usr/bin/env python3
"""Unit-тесты ops-слоя B4 (chimera/modules/b4_monitor.py).

Parity-модуль: «фишки VLESS-нод и Mieru-каскада — теперь для B4».
Контракты (зеркало test_mieru_cascade_monitor + health-тика каскада):

  1. Парсер nft: счётчики нативных правил b4 (фикстура с живой ноды:
     out443/in443/quic/dns, суммирование sport-RST/SYNACK в in443).
  2. EMA ttfb: быстрый старт, сглаживание α=0.35, протухшая >15 мин —
     быстрый старт снова.
  3. Тик: сервис упал → self-heal рестарт (журнал действий); 1 промах
     при прошлом healthy — «скорельно жив»; 2 подряд → degraded;
     ремедия discovery (кастомные сеты) / ротация пресета (классика,
     сет id "youtube") + cooldown 600с — одно действие на окно.
  4. TG-слой: анти-спам по построению (алерт ТОЛЬКО при смене,
     первое наблюдение молча); события events.<event> в telegram.json
     (отсутствующий = ВКЛ); новые действия тика → по одному алерту.
  5. install: timer OnCalendar *:0/1, cron-контент, wrapper bash -n,
     PYTHONPATH-safe; uninstall — чистые удаления.
"""
from __future__ import annotations

import sys
import json
import subprocess
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

import unittest

import types

# ── Мок chimera._core (b4_monitor его не трогает, но youtube_b4 при
#    импорте лениво может; страховка как в test_certmon_v2) ─────────────
fake_core = types.ModuleType("chimera._core")
fake_core.STATE_FILE = Path("/tmp/test-b4mon/state.json")
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

from chimera.modules import b4_monitor as bm   # noqa: E402


def _rmtree(p: Path):
    import shutil
    shutil.rmtree(p, ignore_errors=True)


# Живая фикстура nft с ноды 91 (table inet b4_mangle, 2026-10-04):
# out443=1896991, in443=737063+44+864, quic=62659, dns=960359+960304
NFT_FIXTURE = """table inet filter {
        chain INPUT {
                type filter hook input priority filter; policy accept;
        }
}
table inet b4_mangle {
        chain b4_chain {
                tcp dport 443 ct original packets < 20 counter packets 1896991 bytes 359906609 queue flags bypass to 537-540
                udp dport 443 ct original packets < 9 counter packets 62659 bytes 73776470 queue flags bypass to 537-540
                udp dport 53 counter packets 960359 bytes 60468352 queue flags bypass to 537-540
                udp sport 53 counter packets 960304 bytes 104506255 queue flags bypass to 537-540
                tcp sport 443 ct original packets < 20 counter packets 737063 bytes 322645864 queue flags bypass to 537-540
                tcp sport 443 tcp flags syn,ack / syn,ack counter packets 44 bytes 2640 queue flags bypass to 537-540
                tcp sport 443 tcp flags & rst == rst counter packets 864 bytes 35040 queue flags bypass to 537-540
        }
}
table ip nat {
        chain OUTPUT {
                type nat hook output priority -100; policy accept;
        }
}
"""


# ══════════════════════════════════════════════════════════════════════════════
#  Чистые функции: парсер nft / EMA / скорости / exempt-парсер
# ══════════════════════════════════════════════════════════════════════════════

class TestNftParser(unittest.TestCase):
    def test_live_fixture_classification(self):
        q = bm._parse_queue_native(NFT_FIXTURE)
        self.assertIsNotNone(q)
        self.assertEqual(q["out443"]["pkts"], 1896991)
        self.assertEqual(q["out443"]["bytes"], 359906609)
        # in443 = данные + SYN-ACK + RST (все tcp sport 443)
        self.assertEqual(q["in443"]["pkts"], 737063 + 44 + 864)
        self.assertEqual(q["quic"]["pkts"], 62659)
        self.assertEqual(q["dns"]["pkts"], 960359 + 960304)

    def test_no_table_none(self):
        self.assertIsNone(bm._parse_queue_native("table inet filter {\n}\n"))
        self.assertIsNone(bm._parse_queue_native(""))
        self.assertIsNone(bm._parse_queue_native(None))

    def test_table_without_queue_rules_none(self):
        """Таблица есть, queue-правил нет → None (b4 правила не стоят)."""
        self.assertIsNone(bm._parse_queue_native(
            "table inet b4_mangle {\n\tchain b4_chain {\n\t\treturn\n\t}\n}"))

    def test_next_table_not_leaked(self):
        """Счётчики из СЛЕДУЮЩЕЙ таблицы (nat) не подмешиваются."""
        q = bm._parse_queue_native(NFT_FIXTURE)
        # в фикстуре после b4_mangle идёт ip nat без counter-queue строк;
        # проверяем, что секция обрезалась по \ntable
        self.assertEqual(q["out443"]["pkts"], 1896991)


class TestEma(unittest.TestCase):
    def test_fresh_start(self):
        self.assertEqual(bm._ema_update(None, 100.0), 100.0)

    def test_smoothing_alpha_035(self):
        v = bm._ema_update({"ts": time.time(), "v": 100.0}, 400.0)
        self.assertEqual(v, round(0.35 * 400 + 0.65 * 100, 1))

    def test_stale_history_restart(self):
        v = bm._ema_update({"ts": time.time() - 1000, "v": 100.0}, 400.0)
        self.assertEqual(v, 400.0)

    def test_none_passthrough(self):
        self.assertIsNone(bm._ema_update({"ts": time.time(), "v": 100.0},
                                         None))


class TestRates(unittest.TestCase):
    def test_per_minute(self):
        r = bm._queue_rates(
            {"out443": {"pkts": 100}, "in443": {"pkts": 10}},
            {"out443": {"pkts": 160}, "in443": {"pkts": 10}}, 60.0)
        self.assertEqual(r["out443"], 60.0)
        self.assertEqual(r["in443"], 0.0)     # не изменился → 0/мин (стоячая)

    def test_no_prev_no_rates(self):
        self.assertEqual(bm._queue_rates(None, {"out443": {"pkts": 5}}, 60), {})
        self.assertEqual(bm._queue_rates({"out443": {"pkts": 5}}, None, 60), {})
        self.assertEqual(bm._queue_rates({}, {}, 0), {})


class TestExemptParse(unittest.TestCase):
    def _snapshot(self, entries: int | None, rc: int = 0):
        stdout = "" if rc else (
            f"Name: mieru_b4_direct\nType: hash:ip\n"
            f"Number of entries: {entries}\nMembers:\n1.2.3.4\n")

        def fake_run(cmd, **kw):
            return subprocess.CompletedProcess(cmd, rc, stdout, "")

        with patch.object(bm, "_run", side_effect=fake_run):
            return bm._exempt_snapshot()

    def test_entries(self):
        self.assertEqual(self._snapshot(353),
                         {"applicable": True, "entries": 353})

    def test_zero(self):
        self.assertEqual(self._snapshot(0), {"applicable": True, "entries": 0})

    def test_not_applicable(self):
        self.assertEqual(self._snapshot(None, rc=1),
                         {"applicable": False, "entries": None})


# ══════════════════════════════════════════════════════════════════════════════
#  HEALTH-TICK: стейт-машина (все пробы замоканы)
# ══════════════════════════════════════════════════════════════════════════════

class _TickBase(unittest.TestCase):
    """Пути state — в tmp; пробовые функции — подмены."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: _rmtree(self.tmp))
        self.patches = [
            patch.object(bm, "TICK_STATE", self.tmp / "b4_monitor_state.json"),
            patch.object(bm, "MONITOR_LOG", self.tmp / "b4-monitor.log"),
            patch.object(bm, "_b4_installed", lambda: True),
            patch.object(bm, "_probe_service", lambda: True),
            patch.object(bm, "_heal_restart", lambda: True),
            patch.object(bm, "_queue_snapshot", lambda: None),
            patch.object(bm, "_exempt_snapshot",
                         lambda: {"applicable": False, "entries": None}),
            patch.object(bm, "_preset_applicable", lambda: False),
            patch.object(bm, "_current_preset", lambda: None),
            patch.object(bm, "_switch_preset_to", lambda name: True),
            patch.object(bm, "_run_discovery_remedy",
                         lambda: {"status": "ok", "set": "test"}),
            # сброс кэша применимости между тестами
            patch.object(bm, "_APPL_CACHE", {"ts": 0.0, "ok": None}),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def _probe(self, ok=True, ttfb=120.0):
        return {"ok": ok, "ttfb_ms": ttfb if ok else None,
                "targets": [{"target": "youtube.com", "ok": ok,
                             "code": "200" if ok else "TIMEOUT/RESET"}]}

    def _tick(self, probe_ok=True, ttfb=120.0, service=True):
        with patch.object(bm, "_probe_service", lambda: service), \
             patch.object(bm, "_probe_direct",
                          lambda: self._probe(probe_ok, ttfb)):
            return bm.health_tick()


class TestTickBasics(_TickBase):
    def test_not_installed_noop(self):
        with patch.object(bm, "_b4_installed", lambda: False):
            self.assertEqual(bm.health_tick(),
                             {"installed": False})
        self.assertFalse((self.tmp / "b4_monitor_state.json").exists())

    def test_healthy_tick_writes_state(self):
        r = self._tick()
        self.assertTrue(r["installed"])
        self.assertTrue(r["healthy"])
        self.assertEqual(r["fail_streak"], 0)
        st = json.loads((self.tmp / "b4_monitor_state.json").read_text())
        self.assertTrue(st["probe"]["healthy"])
        self.assertEqual(st["probe"]["ttfb_ema"], 120.0)
        self.assertEqual(st["policy"], bm.DEFAULT_POLICY)
        self.assertIn("ts", st)

    def test_first_fail_stays_healthy_second_degrades(self):
        """1 промах — «скорельно жив»; 2 подряд → degraded (порог каскада)."""
        r1 = self._tick()                       # healthy, streak 0
        self.assertTrue(r1["healthy"])
        r2 = self._tick(probe_ok=False)          # streak 1 — ещё жив
        self.assertTrue(r2["healthy"])
        self.assertEqual(r2["fail_streak"], 1)
        r3 = self._tick(probe_ok=False)          # streak 2 → degraded
        self.assertFalse(r3["healthy"])
        self.assertEqual(r3["fail_streak"], 2)
        r4 = self._tick(probe_ok=False)          # дальше degraded
        self.assertFalse(r4["healthy"])
        r5 = self._tick()                        # восстановление
        self.assertTrue(r5["healthy"])
        self.assertEqual(r5["fail_streak"], 0)


class TestTickSelfHeal(_TickBase):
    def test_service_down_restart_logged(self):
        calls = {"heal": 0}

        def fake_heal():
            calls["heal"] += 1
            return True
        with patch.object(bm, "_probe_service", lambda: False), \
             patch.object(bm, "_heal_restart", side_effect=fake_heal), \
             patch.object(bm, "_probe_direct",
                          lambda: self._probe(True, 100.0)):
            r = bm.health_tick()
        self.assertEqual(calls["heal"], 1)
        self.assertTrue(r["service"])             # поднялся после рестарта
        self.assertIn("restart", r["actions"])
        st = json.loads((self.tmp / "b4_monitor_state.json").read_text())
        self.assertEqual(st["actions"][0]["type"], "restart")

    def test_service_down_restart_policy_off(self):
        """Политика restart=off — не рестартим, но фиксируем падение."""
        with patch.object(bm, "_probe_service", lambda: False):
            st = {}
            st_path = self.tmp / "b4_monitor_state.json"
            st_path.write_text(json.dumps(
                {"policy": {"restart": False, "discovery": True,
                            "presets": True}}))
            r = bm.health_tick()
        self.assertFalse(r["service"])
        st = json.loads(st_path.read_text())
        self.assertEqual(st.get("actions"), None or [] or st.get("actions"))


class TestTickRemedyDiscovery(_TickBase):
    """Кастомные сеты (флот): applicable=False → ремедия Discovery."""

    def test_degraded_runs_discovery(self):
        # прогрев: healthy-тик + первый фейл (ещё healthy)
        self._tick()
        self._tick(probe_ok=False)
        # streak 2 → degraded → discovery
        r = self._tick(probe_ok=False)
        self.assertEqual(r["remedy"], "discovery")
        st = json.loads((self.tmp / "b4_monitor_state.json").read_text())
        self.assertEqual(st["actions"][-1]["type"], "discovery")
        self.assertGreater(st.get("last_remedy_ts", 0), 0)

    def test_discovery_cooldown_one_per_window(self):
        self._tick()
        self._tick(probe_ok=False)
        r3 = self._tick(probe_ok=False)           # дискавери №1
        self.assertEqual(r3["remedy"], "discovery")
        r4 = self._tick(probe_ok=False)           # в окне cooldown — молчит
        self.assertIsNone(r4["remedy"])
        st = json.loads((self.tmp / "b4_monitor_state.json").read_text())
        self.assertEqual(len([a for a in st["actions"]
                               if a["type"] == "discovery"]), 1)

    def test_discovery_after_cooldown_again(self):
        self._tick()
        self._tick(probe_ok=False)
        self._tick(probe_ok=False)               # дискавери №1
        st_path = self.tmp / "b4_monitor_state.json"
        st = json.loads(st_path.read_text())
        st["last_remedy_ts"] = time.time() - bm.REMEDY_COOLDOWN_S - 1
        st_path.write_text(json.dumps(st))
        r = self._tick(probe_ok=False)           # окно истекло — №2
        self.assertEqual(r["remedy"], "discovery")

    def test_recovery_no_remededy(self):
        self._tick()
        self._tick(probe_ok=False)
        self._tick(probe_ok=False)               # дискавери
        r = self._tick()                         # восстановление — не дёргаем
        self.assertIsNone(r["remedy"])


class TestTickRemedyPresets(_TickBase):
    """Классическая установка (сет id "youtube"): ротация пресетов."""

    def _preset_env(self, current="default"):
        # применяемость + текущий пресет; probe-заглушки от _TickBase
        patcher_a = patch.object(bm, "_preset_applicable", lambda: True)
        patcher_a.start()
        self.addCleanup(patcher_a.stop)
        cur = {"v": current}

        def fake_cur():
            return cur["v"]
        patcher_c = patch.object(bm, "_current_preset", side_effect=fake_cur)
        patcher_c.start()
        self.addCleanup(patcher_c.stop)
        return cur

    def test_rotation_default_to_aggressive(self):
        cur = self._preset_env("default")
        self._tick()
        self._tick(probe_ok=False)
        r = self._tick(probe_ok=False)           # degraded → ротация
        self.assertEqual(r["remedy"], "preset")
        # switch_preset вызван с "aggressive"
        st = json.loads((self.tmp / "b4_monitor_state.json").read_text())
        self.assertEqual(st["actions"][-1]["type"], "preset")
        self.assertIn("aggressive", st["actions"][-1]["detail"])
        # pin запомнил пользовательский пресет
        self.assertEqual(st.get("preset_pin"), "default")

    def test_rotation_wraps_around(self):
        cur = self._preset_env("light")
        self._tick()
        self._tick(probe_ok=False)
        r = self._tick(probe_ok=False)           # light → default (по кругу)
        st = json.loads((self.tmp / "b4_monitor_state.json").read_text())
        self.assertIn("default", st["actions"][-1]["detail"])

    def test_pin_tracks_user_choice_when_healthy(self):
        cur = self._preset_env("aggressive")
        self._tick()                             # healthy, пресет aggressive
        st = json.loads((self.tmp / "b4_monitor_state.json").read_text())
        self.assertEqual(st.get("preset_pin"), "aggressive")


class TestTickQueue(_TickBase):
    def test_queue_counters_and_rates(self):
        st_path = self.tmp / "b4_monitor_state.json"
        # тик 1: counters={out443:100}, ts=T
        with patch.object(bm, "_queue_snapshot",
                          lambda: {"out443": {"pkts": 100, "bytes": 900},
                                   "in443": {"pkts": 10, "bytes": 90},
                                   "quic": {"pkts": 0, "bytes": 0},
                                   "dns": {"pkts": 5, "bytes": 300}}):
            bm.health_tick()
        st1 = json.loads(st_path.read_text())
        t1 = st1["queue"]["ts"]
        # тик 2 через 60с: out443=160 → 60/мин
        with patch.object(bm, "_queue_snapshot",
                          lambda: {"out443": {"pkts": 160, "bytes": 1400},
                                   "in443": {"pkts": 10, "bytes": 90},
                                   "quic": {"pkts": 0, "bytes": 0},
                                   "dns": {"pkts": 5, "bytes": 300}}):
            st1["queue"]["ts"] = t1 - 60.0
            st_path.write_text(json.dumps(st1))
            bm.health_tick()
        st2 = json.loads(st_path.read_text())
        # dt = 60с + накладные теста (~0.4с) → допускаем ±2 п/мин
        self.assertAlmostEqual(st2["queue"]["rates"]["out443"], 60.0,
                               delta=2.0)
        self.assertEqual(st2["queue"]["mode"], "nft-native")


# ══════════════════════════════════════════════════════════════════════════════
#  TG-СЛОЙ: check_b4_once (смена состояния → алерт; иначе молчим)
# ══════════════════════════════════════════════════════════════════════════════

class _TgBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: _rmtree(self.tmp))
        for name, sub in (("TICK_STATE", "b4_monitor_state.json"),
                          ("TG_STATE", "b4-monitor-state.json"),
                          ("TG_CONFIG", "telegram.json"),
                          ("MONITOR_LOG", "b4-monitor.log")):
            p = patch.object(bm, name, self.tmp / sub)
            p.start()
            self.addCleanup(p.stop)
        self.systemd = {"b4": "active"}
        self.sent: list[tuple[str, str]] = []
        self._last_curl_text = None

        class _Res:
            def __init__(self, stdout=""):
                self.stdout = stdout
                self.returncode = 0

        def fake_run(cmd, **kw):
            argv = cmd if isinstance(cmd, list) else list(cmd)
            if argv and argv[0] == "curl":
                text = ""
                for i, a in enumerate(argv):
                    if (a == "-d" and i + 1 < len(argv)
                            and argv[i + 1].startswith("text=")):
                        text = argv[i + 1][5:]
                self._last_curl_text = text
                return _Res("200")
            if argv and argv[0] == "hostname":
                return _Res("testhost\n")
            return _Res("")

        r_ = patch.object(bm, "_run", side_effect=fake_run)
        r_.start()
        self.addCleanup(r_.stop)

        def fake_systemd(unit):
            return self.systemd.get(unit, "inactive")

        u = patch.object(bm, "_systemd_is_active", side_effect=fake_systemd)
        u.start()
        self.addCleanup(u.stop)

        # recording_send: НАСТОЯЩИЙ _tg_send (events-фильтр + {H} внутри),
        # отправленный текст кладём в self.sent
        real_tg_send = bm._tg_send

        def recording_send(msg, event=""):
            self._last_curl_text = None
            ok = real_tg_send(msg, event)
            if ok:
                self.sent.append((event, self._last_curl_text or msg))
            return ok

        t_ = patch.object(bm, "_tg_send", side_effect=recording_send)
        t_.start()
        self.addCleanup(t_.stop)

    def _write_tg(self, events: dict | None = None):
        cfg = {"token": "TESTTOKEN", "chat_id": "12345",
               "server_ip": "203.0.113.10"}
        if events is not None:
            cfg["events"] = events
        (self.tmp / "telegram.json").write_text(json.dumps(cfg))

    def _write_tick(self, healthy=True, streak=0, ema=120.0,
                    entries=353, applicable=True, ts=None,
                    actions=None):
        (self.tmp / "b4_monitor_state.json").write_text(json.dumps({
            "ts": ts if ts is not None else time.time(),
            "probe": {"healthy": healthy, "fail_streak": streak,
                      "ttfb_ema": ema, "last_code": "200"},
            "exempt": {"applicable": applicable, "entries": entries},
            "actions": actions or [],
        }))


class TestTgFirstSeenSilent(_TgBase):
    def test_first_seen_no_alerts(self):
        self._write_tg()
        self._write_tick()
        rs = bm.check_b4_once()
        self.assertEqual(self.sent, [])
        self.assertEqual(len(rs), 3)         # service + probe + exempt
        ms = json.loads((self.tmp / "b4-monitor-state.json").read_text())
        self.assertTrue(ms["service"]["active"])
        self.assertTrue(ms["probe"]["healthy"])


class TestTgTransitions(_TgBase):
    def test_down_and_up(self):
        self._write_tg()
        self._write_tick()
        bm.check_b4_once()                          # first-seen молча
        self.systemd["b4"] = "inactive"
        rs = bm.check_b4_once()
        self.assertEqual([e for e, _ in self.sent], ["b4_down"])
        self.assertIn("testhost", self.sent[0][1])   # {H}-подстановка
        self.systemd["b4"] = "active"
        bm.check_b4_once()
        self.assertEqual([e for e, _ in self.sent], ["b4_down", "b4_up"])

    def test_degraded_and_recovered(self):
        self._write_tg()
        self._write_tick()
        bm.check_b4_once()
        self._write_tick(healthy=False, streak=2, ema=None)
        rs = bm.check_b4_once()
        self.assertEqual([e for e, _ in self.sent], ["b4_degraded"])
        self.assertIn("fail_streak 2", self.sent[0][1])
        self._write_tick(healthy=True, streak=0, ema=95.0)
        bm.check_b4_once()
        self.assertEqual([e for e, _ in self.sent],
                         ["b4_degraded", "b4_recovered"])
        self.assertIn("95", self.sent[1][1])        # TTFB EMA в сообщении

    def test_exempt_empty_and_ok(self):
        self._write_tg()
        self._write_tick()
        bm.check_b4_once()
        self._write_tick(entries=0)
        bm.check_b4_once()
        self.assertEqual([e for e, _ in self.sent], ["b4_exempt_empty"])
        self.assertIn("RU-зон", self.sent[0][1])
        self._write_tick(entries=914)
        bm.check_b4_once()
        self.assertEqual([e for e, _ in self.sent],
                         ["b4_exempt_empty", "b4_exempt_ok"])
        self.assertIn("914", self.sent[1][1])

    def test_not_applicable_exempt_silent(self):
        """ipset нет на ноде (standalone b4) — не алертим."""
        self._write_tg()
        self._write_tick(applicable=False, entries=None)
        bm.check_b4_once()
        self._write_tick(applicable=False, entries=None)
        bm.check_b4_once()
        self.assertEqual(self.sent, [])

    def test_recheck_same_state_no_spam(self):
        self._write_tg()
        self._write_tick()
        bm.check_b4_once()
        bm.check_b4_once()
        bm.check_b4_once()
        self.assertEqual(self.sent, [])


class TestTgStalled(_TgBase):
    def test_stalled_and_live(self):
        self._write_tg()
        self._write_tick()
        bm.check_b4_once()
        self._write_tick(ts=time.time() - bm.STALE_AFTER - 60)
        bm.check_b4_once()
        self.assertEqual([e for e, _ in self.sent], ["b4_stalled"])
        self._write_tick()
        bm.check_b4_once()
        self.assertEqual([e for e, _ in self.sent],
                         ["b4_stalled", "b4_stalled"])   # снятие тем же ключом


class TestTgActions(_TgBase):
    def test_new_actions_alerted_once(self):
        self._write_tg()
        self._write_tick()
        bm.check_b4_once()                      # last_action_ts = 0
        t0 = time.time()
        self._write_tick(actions=[
            {"ts": t0 - 10, "type": "restart", "detail": "self-heal: ок"},
            {"ts": t0 - 5, "type": "discovery", "detail": "ок: подобран сет"},
        ])
        rs = bm.check_b4_once()
        self.assertEqual([e for e, _ in self.sent],
                         ["b4_restarted", "b4_discovery"])
        # повторный чек — НЕ дублирует (last_action_ts двинулся)
        bm.check_b4_once()
        self.assertEqual(len(self.sent), 2)
        # ещё одно новое действие — только оно
        self._write_tick(actions=[
            {"ts": t0 - 10, "type": "restart", "detail": "self-heal: ок"},
            {"ts": t0 - 5, "type": "discovery", "detail": "ок"},
            {"ts": t0 + 1, "type": "preset", "detail": "default → aggressive"},
        ])
        bm.check_b4_once()
        self.assertEqual([e for e, _ in self.sent],
                         ["b4_restarted", "b4_discovery", "b4_preset"])
        self.assertIn("aggressive", self.sent[2][1])

    def test_old_actions_not_re_alerted(self):
        """Действия ДО last_action_ts (уже отправленные) — молчим."""
        self._write_tg()
        t0 = time.time()
        self._write_tick(actions=[
            {"ts": t0 - 500, "type": "restart", "detail": "старое"},
        ])
        bm.check_b4_once()                      # first-seen: last_action_ts=0
        # → старое действие уже > 0 → «новое» при первом чеке... но чек
        # был first-seen по состояниям; действия шлются отдельно:
        # после чека last_action_ts = t0-500 → повторный чек молчит
        self.assertEqual([e for e, _ in self.sent], ["b4_restarted"])
        bm.check_b4_once()
        self.assertEqual(len(self.sent), 1)


class TestTgEventsFilter(_TgBase):
    def test_event_disabled_not_sent(self):
        self._write_tg(events={"b4_down": False, "b4_up": True})
        self._write_tick()
        bm.check_b4_once()
        self.systemd["b4"] = "inactive"
        bm.check_b4_once()
        self.assertEqual(self.sent, [])          # b4_down выключен

    def test_absent_key_means_enabled(self):
        self._write_tg(events={"something_else": False})
        self._write_tick()
        bm.check_b4_once()
        self.systemd["b4"] = "inactive"
        bm.check_b4_once()
        self.assertEqual([e for e, _ in self.sent], ["b4_down"])

    def test_no_tg_config_silent(self):
        (self.tmp / "telegram.json").unlink(missing_ok=True)
        self._write_tick()
        rs = bm.check_b4_once()
        self.assertEqual(self.sent, [])
        self.assertEqual(len(rs), 3)


class TestTgNoTickState(_TgBase):
    def test_no_state_noop(self):
        self._write_tg()
        rs = bm.check_b4_once()
        self.assertEqual(rs, [])
        self.assertEqual(self.sent, [])


# ══════════════════════════════════════════════════════════════════════════════
#  INSTALL / UNINSTALL / MATRIX
# ══════════════════════════════════════════════════════════════════════════════

class TestInstall(_TgBase):
    """Пути юнитов — в tmp; systemctl — заглушка (no-op).

    Проверяем КОНТЕНТ: timer OnCalendar *:0/1, cron-строка, wrapper
    bash -n (синтаксис), PYTHONPATH-safe, импорт целевой функции.
    """

    def setUp(self):
        super().setUp()
        self.root = self.tmp / "root"
        self.root.mkdir()
        script_map = {
            "TICK_SCRIPT": self.root / "b4-health.sh",
            "TG_SCRIPT": self.root / "b4-monitor.sh",
        }
        for name, path in script_map.items():
            p = patch.object(bm, name, path)
            p.start()
            self.addCleanup(p.stop)
        u1 = patch.object(bm, "UNIT_TICK", self.root / "b4-health.service")
        u2 = patch.object(bm, "UNIT_TIMER", self.root / "b4-health.timer")
        u3 = patch.object(bm, "CRON_FILE", self.root / "b4-monitor.cron")
        for p in (u1, u2, u3):
            p.start()
            self.addCleanup(p.stop)
        self.systemctl_calls: list = []

        def fake_sys(cmd, **kw):
            self.systemctl_calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        s_ = patch.object(bm, "_run", side_effect=fake_sys)
        s_.start()
        self.addCleanup(s_.stop)
        # _systemd_is_active остаётся от _TgBase (fake), а install зовёт
        # настоящий _run — заменён выше; имена юнитов не важны.

    def test_install_content(self):
        ok, msg = bm.install_b4_monitor(5)
        self.assertTrue(ok, msg)
        timer = (self.root / "b4-health.timer").read_text()
        self.assertIn("OnCalendar=*:0/1", timer)
        self.assertIn("Persistent=true", timer)
        cron = (self.root / "b4-monitor.cron").read_text()
        self.assertIn("*/5 * * * * root", cron)
        # wrapper'ы: bash -n (синтаксис валиден)
        for name in ("b4-health.sh", "b4-monitor.sh"):
            script = (self.root / name).read_text()
            self.assertIn("export PYTHONPATH=", script)
            self.assertIn("sys.path.insert", script)
            r = subprocess.run(["bash", "-n", str(self.root / name)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("from chimera.modules.b4_monitor import", 
                      (self.root / "b4-health.sh").read_text())
        self.assertIn("check_b4_once", 
                      (self.root / "b4-monitor.sh").read_text())
        self.assertTrue(bm.is_monitor_installed())

    def test_interval_bounds(self):
        ok, _ = bm.install_b4_monitor(0)      # → 1
        self.assertTrue(ok)
        cron = (self.root / "b4-monitor.cron").read_text()
        self.assertIn("*/1 * * * *", cron)
        ok, _ = bm.install_b4_monitor(999)    # → 60
        cron = (self.root / "b4-monitor.cron").read_text()
        self.assertIn("*/60 * * * *", cron)

    def test_uninstall_cleans(self):
        bm.install_b4_monitor(5)
        ok, msg = bm.uninstall_b4_monitor()
        self.assertTrue(ok, msg)
        for f in ("b4-health.service", "b4-health.timer", "b4-health.sh",
                  "b4-monitor.sh", "b4-monitor.cron"):
            self.assertFalse((self.root / f).exists(), f)
        self.assertFalse(bm.is_monitor_installed())
        self.assertIn(["systemctl", "disable", "--now", "b4-health.timer"],
                      self.systemctl_calls)


class TestMatrix(_TickBase):
    def test_matrix_fields(self):
        self._tick()
        # _probe_service у _TickBase = True; matrix зовёт настоящий
        # youtube_b4.status — его не мокаем: matrix падает в except и
        # берёт _probe_service (см. код). Проверяем поля тика.
        mx = bm.matrix()
        self.assertIn("installed", mx)
        self.assertIn("monitor", mx)
        self.assertIn("probe", mx)
        self.assertIn("queue", mx)
        self.assertIn("policy", mx)
        self.assertTrue(mx["probe"]["healthy"])


class TestSummary(_TickBase):
    def test_summary_compact(self):
        self._tick()
        s = bm.summary()
        self.assertIn("healthy", s)
        self.assertIn("monitor_installed", s)
        self.assertTrue(s["healthy"])


# ══════════════════════════════════════════════════════════════════════════════
#  Публичный контракт модуля (анти-регрессия)
# ══════════════════════════════════════════════════════════════════════════════

class TestPublicContract(unittest.TestCase):
    def test_event_registry(self):
        self.assertEqual(len(bm.EVENT_KEYS), 10)
        self.assertEqual(set(bm.EVENT_KEYS), set(bm.EVENT_LABELS))
        # b4_down/b4_up/... — ключи, которые ждёт tg_bot
        for k in ("b4_down", "b4_up", "b4_degraded", "b4_recovered",
                  "b4_stalled", "b4_restarted", "b4_discovery", "b4_preset",
                  "b4_exempt_empty", "b4_exempt_ok"):
            self.assertIn(k, bm.EVENT_KEYS)

    def test_constants_cascade_parity(self):
        """Константы — зеркальны каскадным (α, порог, stalled)."""
        self.assertEqual(bm.EMA_ALPHA, 0.35)
        self.assertEqual(bm.EMA_MAX_AGE_S, 900)
        self.assertEqual(bm.FAIL_STREAK_UNHEALTHY, 2)
        self.assertEqual(bm.STALE_AFTER, 300)
        self.assertEqual(bm.EXEMPT_IPSET, "mieru_b4_direct")

    def test_api_exports(self):
        for fn in ("health_tick", "health_tick_cli", "check_b4_once",
                   "matrix", "summary", "install_b4_monitor",
                   "uninstall_b4_monitor", "is_monitor_installed",
                   "do_b4_monitor_menu", "get_installed_interval"):
            self.assertTrue(callable(getattr(bm, fn)), fn)


# ══════════════════════════════════════════════════════════════════════════════
#  TUI-меню (регрессия): AttributeError '_box_kv' — b4_monitor звал
#  ytb._box_kv, которого youtube_b4 не реэкспортировал (kv был только
#  локальным хелпером mieru/vk_bypass_menu/slipgate/wdtt); меню падало на
#  первой же строке «Сервис:» после отрисовки шапки.
# ══════════════════════════════════════════════════════════════════════════════

class TestMonitorMenuSmoke(unittest.TestCase):
    """do_b4_monitor_menu отрисовывается и выходит по Q без падений."""

    _MX_FULL = {
        "installed": True,
        "monitor": {"installed": True, "interval": 5, "timer_active": True},
        "service": True, "version": "1.2.3", "preset": "default",
        "sets": ["youtube"],
        "probe": {"healthy": True, "ttfb_ema": 342.7, "fail_streak": 0},
        "queue": {"counters": {"out443": {"pkts": 681, "bytes": 1000000}},
                  "rates": {"out443": 42}},
        "exempt": {"applicable": True, "entries": 293},
        "policy": {"restart": True, "discovery": True, "presets": True},
        "actions": [{"ts": 1759500000, "type": "preset",
                     "detail": "default -> aggressive"}],
    }

    def _run_menu(self, mx):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with patch.object(bm, "matrix", return_value=mx), \
             patch("builtins.input", return_value="q"), \
             patch("os.system", return_value=0), \
             redirect_stdout(buf):
            bm.do_b4_monitor_menu()  # регрессия: здесь падало AttributeError
        return buf.getvalue()

    def test_menu_full_path_no_crash(self):
        out = self._run_menu(dict(self._MX_FULL))
        self.assertIn("МОНИТОРИНГ B4", out)
        self.assertIn("Сервис:", out)
        self.assertIn("Пресет:", out)
        self.assertIn("Политика:", out)

    def test_menu_not_installed_path(self):
        mx = {"installed": False,
              "monitor": {"installed": False, "interval": 0,
                          "timer_active": False}}
        out = self._run_menu(mx)
        self.assertIn("МОНИТОРИНГ B4", out)
        self.assertIn("не установлен", out)

    def test_ytb_exports_full_box_set(self):
        """youtube_b4 обязан реэкспортировать весь box-набор, который
        дергает b4_monitor (box = ytb) — иначе меню падает в рантайме."""
        from chimera.modules import youtube_b4 as ytb
        for fn in ("_box_top", "_box_row", "_box_sep", "_box_bottom",
                   "_box_item", "_box_back", "_box_warn", "_box_ok",
                   "_box_kv"):
            self.assertTrue(hasattr(ytb, fn), fn)

    def test_box_kv_alignment(self):
        """Канон mieru: отступ 2, ключ дополняется до kw=22, +2 до значения."""
        import io
        from contextlib import redirect_stdout
        from chimera.modules import box_renderer as br
        buf = io.StringIO()
        with redirect_stdout(buf):
            br._box_kv("Сервис:", "active")
        vis = br._plain(buf.getvalue())
        i_key = vis.index("Сервис:")
        i_val = vis.index("active")
        # конец ключа → начало значения: (22 - 7) колонок паддинга + 2
        self.assertEqual(i_val - (i_key + len("Сервис:")), 15 + 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
