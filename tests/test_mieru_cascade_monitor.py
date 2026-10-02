#!/usr/bin/env python3
"""Unit-тесты TG-монитора mieru-каскада (chimera/modules/mieru_cascade_monitor.py).

Реплика бот-паттерна VLESS (node_health_monitor + xray-tg-monitor v2)
для mieru-каскада. Контракты:

  1. Анти-спам по построению: алерт ТОЛЬКО при смене состояния;
     первое наблюдение (нет сохранённого) — молча.
  2. События: каждый алерт проверяет events.<event> в telegram.json;
     отсутствующий ключ = ВКЛ (default True).
  3. Сценарии: mita down/up, Exit down/up, все-Exit-ы-down (+снятие),
     health-tick stall (+восстановление).
  4. Disabled-Exit не проверяется; роль != entry / нет файла — no-op.
  5. install/uninstall: wrapper bash -n, cron-контент, токены не
     запечены (читаются из telegram.json при каждом запуске).
"""
from __future__ import annotations

import sys
import json
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

import unittest

from chimera.modules import mieru_cascade_monitor as mcm
from chimera.modules import tg_bot


def _fresh_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _exits(n: int = 3, healthy: bool = True, stale: bool = False):
    ts = _fresh_ts()
    if stale:
        ts = datetime.fromtimestamp(time.time() - 600).strftime("%Y-%m-%d %H:%M:%S")
    return [
        {"id": f"exit-9418{i}-n{i}", "label": f"n{i}", "host": f"10.0.0.{i}",
         "port": 2012, "enabled": True, "healthy": healthy,
         "fail_streak": 0 if healthy else 3,
         "latency_ms": 20 + i, "last_check": ts}
        for i in range(1, n + 1)
    ]


class _TmpBase(unittest.TestCase):
    """Все пути модуля — в tmpdir; _run (транспорт) и _systemd_is_active — моки.

    _tg_send остаётся НАСТОЯЩИМ: events-фильтр и {H}-подстановка
    проверяются вживую (транспорт curl подменён fake_run).
    """

    def setUp(self):
        import os
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: _rmtree(self.tmp))
        patches = [
            patch.object(mcm, "TG_CONFIG", self.tmp / "telegram.json"),
            patch.object(mcm, "CASCADE_STATE", self.tmp / "mieru_cascade.json"),
            patch.object(mcm, "MONITOR_STATE", self.tmp / "monitor-state.json"),
            patch.object(mcm, "MONITOR_LOG", self.tmp / "monitor.log"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        # дефолтный TG-конфиг: все события включены (ключи есть)
        self._write_tg(events={
            "mieru_down": True, "mieru_up": True, "mieru_exit_down": True,
            "mieru_exit_up": True, "mieru_no_exits": True, "mieru_stalled": True,
        })
        self.sent: list[tuple[str, str]] = []          # (event, text)
        self.systemd = {"mita": "active"}

        class _Res:
            def __init__(self, stdout=""):
                self.stdout = stdout
                self.returncode = 0

        def fake_run(cmd, **kw):
            argv = cmd if isinstance(cmd, list) else list(cmd)
            if argv and argv[0] == "curl":
                # вытаскиваем текст и event-заголовок из curl-аргументов
                text = ""
                for i, a in enumerate(argv):
                    if a == "-d" and i + 1 < len(argv) and argv[i+1].startswith("text="):
                        text = argv[i+1][5:]
                self._last_curl_text = text
                return _Res("200")
            if argv and argv[0] == "hostname":
                return _Res("testhost\n")
            return _Res("")

        # Патчим транспорт (_run: curl/hostname) и systemd — до обёртки
        r_ = patch.object(mcm, "_run", side_effect=fake_run)
        r_.start(); self.addCleanup(r_.stop)

        def fake_systemd(unit):
            return self.systemd.get(unit, "active")

        u = patch.object(mcm, "_systemd_is_active", side_effect=fake_systemd)
        u.start(); self.addCleanup(u.stop)

        # _tg_send не патчим целиком — тонкая обёртка recording_send
        # вызывает НАСТОЯЩИЙ _tg_send (events-фильтр + {H}-подстановка
        # внутри него), а отправленный текст (записан fake_run при curl)
        # кладёт в self.sent.
        real_tg_send = mcm._tg_send

        def recording_send(msg, event=""):
            self._last_curl_text = None
            ok = real_tg_send(msg, event)
            if ok:
                self.sent.append((event, self._last_curl_text or msg))
            return ok

        t_ = patch.object(mcm, "_tg_send", side_effect=recording_send)
        t_.start(); self.addCleanup(t_.stop)

    def _write_tg(self, events: dict | None = None, drop_keys: bool = False):
        cfg = {"token": "TESTTOKEN", "chat_id": "12345",
               "server_ip": "203.0.113.10"}
        if events is not None:
            cfg["events"] = events
        (self.tmp / "telegram.json").write_text(json.dumps(cfg))

    def _write_cascade(self, exits, role="entry", strategy="rr"):
        (self.tmp / "mieru_cascade.json").write_text(json.dumps({
            "role": role, "strategy": strategy, "exits": exits,
        }))


def _rmtree(p: Path):
    import shutil
    shutil.rmtree(p, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════════════
#  check_cascade_once: смена состояния → алерт; без смены — молчим
# ══════════════════════════════════════════════════════════════════════════════

class TestCheckFirstSeenSilent(_TmpBase):
    def test_first_seen_no_alerts(self):
        """Первое наблюдение — НИ ОДНОГО алерта (анти-спам по построению)."""
        self._write_cascade(_exits(3, healthy=True))
        rs = mcm.check_cascade_once()
        self.assertEqual(self.sent, [])
        self.assertEqual(len(rs), 4)          # mita + 3 Exit-а
        ids = {r["id"] for r in rs}
        self.assertIn("mita", ids)
        # state сохранён
        ms = json.loads((self.tmp / "monitor-state.json").read_text())
        self.assertEqual(len(ms["exits"]), 3)
        self.assertTrue(ms["mita"]["active"])
        self.assertFalse(ms["no_exits"])


class TestExitTransitions(_TmpBase):
    def test_exit_down_and_up(self):
        """Exit здоров→болен: ровно 1 mieru_exit_down; обратно: 1 exit_up."""
        ex = _exits(3, healthy=True)
        self._write_cascade(ex)
        mcm.check_cascade_once()                       # first-seen, молча
        # n2 падает (fail_streak 3 — порог тика ≥2 соблюдён)
        ex[1]["healthy"] = False
        ex[1]["fail_streak"] = 3
        self._write_cascade(ex)
        rs = mcm.check_cascade_once()
        self.assertEqual([e for e, _ in self.sent], ["mieru_exit_down"])
        self.assertIn("n2", self.sent[0][1])           # label в сообщении
        self.assertIn("10.0.0.2", self.sent[0][1])     # host в сообщении
        self.assertEqual(sum(1 for r in rs if r.get("changed")), 1)
        # восстановление
        ex[1]["healthy"] = True
        ex[1]["fail_streak"] = 0
        self._write_cascade(ex)
        mcm.check_cascade_once()
        self.assertEqual([e for e, _ in self.sent],
                         ["mieru_exit_down", "mieru_exit_up"])

    def test_recheck_same_state_no_spam(self):
        """Повторная проверка без изменений — молчим (ядро анти-спама)."""
        ex = _exits(3, healthy=True)
        self._write_cascade(ex)
        mcm.check_cascade_once()
        mcm.check_cascade_once()
        mcm.check_cascade_once()
        self.assertEqual(self.sent, [])


class TestNoExitsCritical(_TmpBase):
    def test_all_down_and_recovery(self):
        """Все Exit-ы down → mieru_no_exits; частичное восстановление → снятие."""
        ex = _exits(3, healthy=True)
        self._write_cascade(ex)
        mcm.check_cascade_once()
        for e in ex:
            e["healthy"] = False; e["fail_streak"] = 3
        self._write_cascade(ex)
        mcm.check_cascade_once()
        events = [e for e, _ in self.sent]
        self.assertEqual(events.count("mieru_exit_down"), 3)
        self.assertIn("mieru_no_exits", events)
        # один ожил → no_exits снят (плюс 1 exit_up)
        ex[0]["healthy"] = True; ex[0]["fail_streak"] = 0
        self._write_cascade(ex)
        mcm.check_cascade_once()
        tail = [e for e, _ in self.sent][-2:]
        self.assertIn("mieru_exit_up", tail)
        self.assertIn("mieru_no_exits", tail)          # recovery-сообщение
        self.assertIn("1/3", self.sent[-1][1])         # «1/3 Exit-ов здоровы»


class TestMitaService(_TmpBase):
    def test_mita_down_up(self):
        ex = _exits(2, healthy=True)
        self._write_cascade(ex)
        mcm.check_cascade_once()
        self.systemd["mita"] = "inactive"
        mcm.check_cascade_once()
        self.assertEqual([e for e, _ in self.sent], ["mieru_down"])
        self.systemd["mita"] = "active"
        mcm.check_cascade_once()
        self.assertEqual([e for e, _ in self.sent],
                         ["mieru_down", "mieru_up"])


class TestStall(_TmpBase):
    def test_stall_and_recovery(self):
        """mtime+last_check старше STALE_AFTER → mieru_stalled; свежий → снятие.

        Stall-детекция опирается на свежесть файла (state_save перезаписывает
        mieru_cascade.json КАЖДЫЙ тик) — в тесте старим файл через utime.
        """
        import os
        ex = _exits(2, healthy=True)
        self._write_cascade(ex)
        mcm.check_cascade_once()
        # тик «умер»: last_check протух + mtime состарен (utime)
        self._write_cascade(_exits(2, healthy=True, stale=True))
        old = time.time() - 600
        os.utime(self.tmp / "mieru_cascade.json", (old, old))
        mcm.check_cascade_once()
        self.assertEqual([e for e, _ in self.sent], ["mieru_stalled"])
        self.assertIn("health-tick", self.sent[0][1])
        # тик «ожил»: свежий файл (перезапись = свежий mtime)
        self._write_cascade(_exits(2, healthy=True))
        mcm.check_cascade_once()
        self.assertEqual([e for e, _ in self.sent],
                         ["mieru_stalled", "mieru_stalled"])
        self.assertIn("обновляется", self.sent[-1][1])


class TestEventFilter(_TmpBase):
    def test_event_off_no_send(self):
        """events.mieru_exit_down=false → алерт не уходит (молчание не ошибка)."""
        self._write_tg(events={"mieru_exit_down": False})
        ex = _exits(2, healthy=True)
        self._write_cascade(ex)
        mcm.check_cascade_once()
        ex[0]["healthy"] = False; ex[0]["fail_streak"] = 3
        self._write_cascade(ex)
        mcm.check_cascade_once()
        self.assertEqual(self.sent, [])                # событие выключено
        # но state записан — повторная проверка не догонит алерт
        ms = json.loads((self.tmp / "monitor-state.json").read_text())
        self.assertFalse(ms["exits"]["exit-94181-n1"]["healthy"])

    def test_event_missing_key_means_enabled(self):
        """Отсутствующий ключ = ВКЛ (новые mieru-события без правки telegram.json)."""
        self._write_tg(events={"xray_down": True})    # только чужой ключ
        ex = _exits(2, healthy=True)
        self._write_cascade(ex)
        mcm.check_cascade_once()
        ex[1]["healthy"] = False; ex[1]["fail_streak"] = 2
        self._write_cascade(ex)
        mcm.check_cascade_once()
        self.assertEqual([e for e, _ in self.sent], ["mieru_exit_down"])


class TestEdgeCases(_TmpBase):
    def test_disabled_exit_skipped(self):
        ex = _exits(3, healthy=True)
        ex[2]["enabled"] = False
        self._write_cascade(ex)
        rs = mcm.check_cascade_once()
        self.assertEqual(len(rs), 3)                   # mita + 2 включённых
        ids = {r["id"] for r in rs}
        self.assertNotIn("exit-94183-n3", ids)

    def test_role_not_entry_noop(self):
        self._write_cascade(_exits(2), role="exit")
        self.assertEqual(mcm.check_cascade_once(), [])
        self.assertEqual(self.sent, [])

    def test_no_state_file_noop(self):
        self.assertEqual(mcm.check_cascade_once(), [])
        self.assertEqual(self.sent, [])

    def test_broken_state_file_noop(self):
        (self.tmp / "mieru_cascade.json").write_text("{broken json")
        self.assertEqual(mcm.check_cascade_once(), [])
        self.assertEqual(self.sent, [])


class TestNewestExitCheck(unittest.TestCase):
    def test_parsing(self):
        ex = _exits(2)
        newest = mcm._newest_exit_check(ex)
        self.assertIsNotNone(newest)
        self.assertLess(time.time() - newest, 30)
        self.assertIsNone(mcm._newest_exit_check([]))
        # мусорный last_check не ломает
        ex2 = _exits(1)
        ex2[0]["last_check"] = "not-a-date"
        self.assertIsNone(mcm._newest_exit_check(ex2))


class TestHeaderSubstitution(_TmpBase):
    def test_header_placeholder(self):
        """{H} подставляется как [testhost | 203.0.113.10] (паттерн v2).

        2 Exit-а, падает один → ровно 1 алерт (no_exits не срабатывает:
        остаётся живой Exit).
        """
        ex = _exits(2, healthy=True)
        self._write_cascade(ex)
        mcm.check_cascade_once()
        ex[0]["healthy"] = False; ex[0]["fail_streak"] = 3
        self._write_cascade(ex)
        mcm.check_cascade_once()
        self.assertEqual([e for e, _ in self.sent], ["mieru_exit_down"])
        text = self.sent[0][1]
        self.assertIn("[testhost | 203.0.113.10]", text)
        self.assertNotIn("{H}", text)


# ══════════════════════════════════════════════════════════════════════════════
#  install / uninstall
# ══════════════════════════════════════════════════════════════════════════════

class TestInstall(_TmpBase):
    def setUp(self):
        super().setUp()
        self.cron = self.tmp / "mieru-cascade-monitor.cron"
        self.script = self.tmp / "mieru-cascade-monitor.sh"
        for p in (patch.object(mcm, "CRON_FILE", self.cron),
                  patch.object(mcm, "CHECK_SCRIPT", self.script)):
            p.start(); self.addCleanup(p.stop)

    def test_install_wrapper_and_cron(self):
        ok, msg = mcm.install_cascade_monitor(5)
        self.assertTrue(ok, msg)
        # bash -n
        r = subprocess.run(["bash", "-n", str(self.script)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        # python-код wrapper'а компилируется
        import re
        m = re.search(r"-c \"\n(.*?)\n\" 2>>", self.script.read_text(), re.DOTALL)
        self.assertIsNotNone(m, "wrapper: python-блок не найден")
        compile(m.group(1), "<wrapper>", "exec")
        # cron-контент
        cron = self.cron.read_text()
        self.assertIn("*/5 * * * *", cron)
        self.assertIn("mieru-cascade-monitor.sh", cron)
        # токены НЕ запечены (читаются из telegram.json при каждом запуске)
        sh = self.script.read_text()
        self.assertNotIn("TESTTOKEN", sh)
        self.assertNotIn("12345", sh)
        # импорт и вызов корректного модуля
        self.assertIn("from chimera.modules.mieru_cascade_monitor import check_cascade_once", sh)

    def test_interval_clamped(self):
        ok, _ = mcm.install_cascade_monitor(999)
        self.assertTrue(ok)
        self.assertIn("*/60", self.cron.read_text())
        ok, _ = mcm.install_cascade_monitor(0)
        self.assertTrue(ok)
        self.assertIn("*/1", self.cron.read_text())

    def test_uninstall(self):
        mcm.install_cascade_monitor(5)
        (self.tmp / "monitor-state.json").write_text("{}")
        ok, msg = mcm.uninstall_cascade_monitor()
        self.assertTrue(ok, msg)
        self.assertFalse(self.cron.exists())
        self.assertFalse(self.script.exists())
        self.assertFalse((self.tmp / "monitor-state.json").exists())


# ══════════════════════════════════════════════════════════════════════════════
#  Согласованность с tg_bot (меню событий) и метками модуля
# ══════════════════════════════════════════════════════════════════════════════

class TestEventsConsistency(unittest.TestCase):
    def test_keys_labels_match(self):
        self.assertEqual(set(mcm.EVENT_KEYS), set(mcm.EVENT_LABELS))
        for k in mcm.EVENT_KEYS:
            self.assertTrue(k.startswith("mieru_"), k)

    def test_tg_bot_menus_cover_mieru_events(self):
        """Оба списка событий tg_bot (витрина + переключатель) содержат все 6."""
        src = (tg_bot.__file__ and Path(tg_bot.__file__).read_text())
        for k in mcm.EVENT_KEYS:
            self.assertIn(f'"{k}"', src, f"ключ {k} отсутствует в tg_bot.py")


if __name__ == "__main__":
    unittest.main(verbosity=2)
