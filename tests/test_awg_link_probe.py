#!/usr/bin/env python3
"""
tests/test_awg_link_probe.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты зонда плеча каскада и классификатора паттернов среды
(chimera/modules/awg_link_probe.py).

Покрывает:
  1. link_parse_awg_show — парсинг `awg show` (handshake + transfer)
  2. link_parse_ping_loss — парсинг summary ping
  3. link_classify — таблица решений (все 7 паттернов + порядок
     вопросов: no-tunnel → udp-dead → направленность → поток)
  4. LINK_PATTERNS / link_recommend — матрица «симптом → пресет»:
     каждый паттерн классификатора имеет запись, рекомендация непуста,
     split_direction=True только у лечимых паттернов
  5. link_probe_ping_big — mark-зонд (поддержан/не поддержан/потери)
  6. link_probe_run — лестница целиком (моки _run)
  7. link_probe_report — TUI-smoke (без исключений на моках)
"""
from __future__ import annotations

import sys
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
                 "_box_item", "_box_desc", "_box_wrap_msg"):
        setattr(core, attr, MagicMock())
    for attr in ("info", "success", "warn", "error", "log_to_file"):
        setattr(core, attr, MagicMock())
    r = MagicMock()
    r.returncode = 0
    r.stdout = ""
    r.stderr = ""
    core._run = MagicMock(return_value=r)
    core.get_server_ip = MagicMock(return_value="203.0.113.10")
    return core


_AWG_SHOW_OK = (
    "interface: awg1\n"
    "  public key: (hidden)\n"
    "  private key: (hidden)\n"
    "  listening port: 52831\n"
    "\n"
    "peer: PxYx=\n"
    "  endpoint: 203.0.113.107:52831\n"
    "  allowed ips: 0.0.0.0/0\n"
    "  latest handshake: 1 minute, 25 seconds ago\n"
    "  transfer: 57.66 KiB received, 118.11 KiB sent\n"
)

_AWG_SHOW_ONE_WAY = (
    "interface: awg1\n"
    "peer: PxYx=\n"
    "  endpoint: 203.0.113.107:52831\n"
    "  latest handshake: 45 seconds ago\n"
    "  transfer: 0 B received, 15.28 KiB sent\n"
)

_AWG_SHOW_IN_ONLY = (
    "interface: awg1\n"
    "peer: PxYx=\n"
    "  latest handshake: 45 seconds ago\n"
    "  transfer: 4.20 KiB received, 0 B sent\n"
)

_AWG_SHOW_NO_HS = (
    "interface: awg1\n"
    "peer: PxYx=\n"
    "  endpoint: 203.0.113.107:52831\n"
    "  allowed ips: 0.0.0.0/0\n"
)


# ── 1. Парсер awg show ──────────────────────────────────────────────────────

class TestParseAwgShow(unittest.TestCase):
    def test_full_show(self):
        from chimera.modules.awg_link_probe import link_parse_awg_show
        d = link_parse_awg_show(_AWG_SHOW_OK)
        self.assertEqual(d["handshake_age"], 85)
        self.assertEqual(d["tx"], int(118.11 * 1024))
        self.assertEqual(d["rx"], int(57.66 * 1024))

    def test_one_way_counters(self):
        from chimera.modules.awg_link_probe import link_parse_awg_show
        d = link_parse_awg_show(_AWG_SHOW_ONE_WAY)
        self.assertEqual(d["handshake_age"], 45)
        self.assertEqual(d["tx"], int(15.28 * 1024))
        self.assertEqual(d["rx"], 0)

    def test_in_only_counters(self):
        from chimera.modules.awg_link_probe import link_parse_awg_show
        d = link_parse_awg_show(_AWG_SHOW_IN_ONLY)
        self.assertEqual(d["tx"], 0)
        self.assertGreater(d["rx"], 0)

    def test_no_handshake_no_transfer(self):
        from chimera.modules.awg_link_probe import link_parse_awg_show
        d = link_parse_awg_show(_AWG_SHOW_NO_HS)
        self.assertIsNone(d["handshake_age"])
        self.assertEqual(d["tx"], 0)
        self.assertEqual(d["rx"], 0)

    def test_empty_and_garbage(self):
        from chimera.modules.awg_link_probe import link_parse_awg_show
        for txt in ("", "мусор", None):
            d = link_parse_awg_show(txt or "")
            self.assertIsNone(d["handshake_age"])
            self.assertEqual((d["tx"], d["rx"]), (0, 0))

    def test_mib_units(self):
        from chimera.modules.awg_link_probe import link_parse_awg_show
        d = link_parse_awg_show(
            "latest handshake: 10 seconds ago\n"
            "transfer: 1.50 MiB received, 2.25 MiB sent\n")
        self.assertEqual(d["rx"], int(1.5 * 1024 ** 2))
        self.assertEqual(d["tx"], int(2.25 * 1024 ** 2))


# ── 2. Парсер ping ──────────────────────────────────────────────────────────

class TestParsePingLoss(unittest.TestCase):
    def test_zero_loss(self):
        from chimera.modules.awg_link_probe import link_parse_ping_loss
        self.assertEqual(
            link_parse_ping_loss("5 packets transmitted, 5 received, "
                                 "0% packet loss, time 4000ms"), 0)

    def test_forty_loss(self):
        from chimera.modules.awg_link_probe import link_parse_ping_loss
        self.assertEqual(
            link_parse_ping_loss("5 packets transmitted, 3 received, "
                                 "40% packet loss, time 4000ms"), 40)

    def test_float_rounded(self):
        from chimera.modules.awg_link_probe import link_parse_ping_loss
        self.assertEqual(
            link_parse_ping_loss("48 transmitted, 0 received, "
                                 "100.0% packet loss"), 100)

    def test_no_summary(self):
        from chimera.modules.awg_link_probe import link_parse_ping_loss
        self.assertIsNone(link_parse_ping_loss("PING 1.1.1.1..."))
        self.assertIsNone(link_parse_ping_loss(""))


# ── 3. Классификатор: таблица решений ───────────────────────────────────────

def _awg1(up=True, age=85, tx=0, rx=0):
    return {"up": up, "handshake_age": age, "tx": tx, "rx": rx}


def _big(supported=True, loss=0):
    if not supported:
        return {"ok": False, "loss_pct": None, "sent_bytes": 59000,
                "supported": False}
    return {"ok": loss is not None and loss <= 20, "loss_pct": loss,
            "sent_bytes": 59000, "supported": True}


class TestClassify(unittest.TestCase):
    def test_no_tunnel(self):
        from chimera.modules.awg_link_probe import link_classify
        self.assertEqual(link_classify(_awg1(up=False), {}, {}),
                         "no-tunnel")

    def test_udp_dead(self):
        from chimera.modules.awg_link_probe import link_classify
        # handshake не сходился, шлюз не отвечает
        self.assertEqual(
            link_classify(_awg1(up=True, age=None, tx=0, rx=0),
                          {"ok": False}, _big()),
            "udp-dead")

    def test_one_way_out(self):
        from chimera.modules.awg_link_probe import link_classify
        # кейс Виталия: sent > 0, recv = 0 — направление определяется
        # ДО большого зонда (счётчики не врут о физике плеча)
        self.assertEqual(
            link_classify(_awg1(tx=15646, rx=0), {"ok": True},
                          _big(loss=100)),
            "one-way-out")

    def test_one_way_in(self):
        from chimera.modules.awg_link_probe import link_classify
        self.assertEqual(
            link_classify(_awg1(tx=0, rx=4300), {"ok": True}, _big()),
            "one-way-in")

    def test_stream_cut(self):
        from chimera.modules.awg_link_probe import link_classify
        # handshake жив, но большой поток режется (антитуннель 16-32 КБ)
        self.assertEqual(
            link_classify(_awg1(tx=500, rx=500), {"ok": True},
                          _big(loss=100)),
            "stream-cut")

    def test_flaky_gray_zone(self):
        from chimera.modules.awg_link_probe import link_classify
        self.assertEqual(
            link_classify(_awg1(tx=500, rx=500), {"ok": True},
                          _big(loss=50)),
            "flaky")

    def test_bidirectional_ok(self):
        from chimera.modules.awg_link_probe import link_classify
        self.assertEqual(
            link_classify(_awg1(tx=500, rx=500), {"ok": True},
                          _big(loss=0)),
            "bidirectional-ok")

    def test_big_ping_unsupported(self):
        from chimera.modules.awg_link_probe import link_classify
        self.assertEqual(
            link_classify(_awg1(tx=500, rx=500), {"ok": True},
                          _big(supported=False, loss=None)),
            "big-ping-unsupported")


# ── 4. Матрица «симптом → пресет» ──────────────────────────────────────────

class TestPatternMatrix(unittest.TestCase):
    def _pattern_codes(self):
        from chimera.modules.awg_link_probe import link_classify
        # все коды, которые классификатор умеет возвращать
        return {
            "bidirectional-ok", "one-way-out", "one-way-in", "stream-cut",
            "udp-dead", "flaky", "big-ping-unsupported", "no-tunnel",
        }

    def test_every_classify_code_has_matrix_entry(self):
        from chimera.modules.awg_link_probe import LINK_PATTERNS
        codes = self._pattern_codes()
        for code in codes:
            self.assertIn(code, LINK_PATTERNS,
                          f"паттерн {code} без записи в матрице")

    def test_matrix_entries_complete(self):
        from chimera.modules.awg_link_probe import LINK_PATTERNS
        for code, entry in LINK_PATTERNS.items():
            for field in ("label", "verdict", "recommendation",
                          "split_direction", "canon"):
                self.assertIn(field, entry, f"{code}: нет поля {field}")
                self.assertTrue(str(entry[field]).strip(),
                                f"{code}: пустое поле {field}")

    def test_split_direction_only_for_treatable(self):
        from chimera.modules.awg_link_probe import LINK_PATTERNS
        # split-режим рекомендован ровно для one-way-out (основной) и
        # stream-cut (паллиатив); для живого/мёртвого/инверсного — нет
        self.assertTrue(LINK_PATTERNS["one-way-out"]["split_direction"])
        self.assertTrue(LINK_PATTERNS["stream-cut"]["split_direction"])
        for code in ("bidirectional-ok", "one-way-in", "udp-dead",
                     "flaky", "no-tunnel"):
            self.assertFalse(LINK_PATTERNS[code]["split_direction"],
                             f"{code}: split не должен рекомендоваться")

    def test_recommendation_mentions_split_for_one_way_out(self):
        from chimera.modules.awg_link_probe import LINK_PATTERNS
        self.assertIn("Split-direction",
                      LINK_PATTERNS["one-way-out"]["recommendation"])

    def test_link_recommend_known_and_unknown(self):
        from chimera.modules.awg_link_probe import link_recommend
        rec = link_recommend("one-way-out")
        self.assertEqual(rec["label"], "Исходящее живо, входящее мертво")
        # неизвестный код — честная заглушка, не исключение (регресс-гард)
        rec = link_recommend("no-such-pattern")
        self.assertEqual(rec["label"], "Неизвестный паттерн")
        self.assertFalse(rec["split_direction"])


# ── 5. Живые зонды (моки _run) ──────────────────────────────────────────────

class _ProbeTestBase(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        self.mock_core = _mock_core()
        from chimera.modules import awg_link_probe
        self.probe = awg_link_probe
        self._p = patch.object(awg_link_probe, "_core_module",
                               return_value=self.mock_core)
        self._p.start()
        self.addCleanup(self._p.stop)

    def _run_result(self, rc=0, stdout="", stderr=""):
        r = MagicMock()
        r.returncode = rc
        r.stdout = stdout
        r.stderr = stderr
        return r


class TestProbeAwg1(_ProbeTestBase):
    def test_alive_tunnel(self):
        self.mock_core._run = MagicMock(
            return_value=self._run_result(0, _AWG_SHOW_OK))
        d = self.probe.link_probe_awg1()
        self.assertTrue(d["up"])
        self.assertEqual(d["handshake_age"], 85)
        self.assertEqual(d["tx"], int(118.11 * 1024))

    def test_dead_service(self):
        self.mock_core._run = MagicMock(
            return_value=self._run_result(1, "", "no such interface"))
        d = self.probe.link_probe_awg1()
        self.assertFalse(d["up"])

    def test_ping_gw(self):
        self.mock_core._run = MagicMock(
            return_value=self._run_result(0, "1 packets received"))
        d = self.probe.link_probe_ping_gw("172.16.91.0/24")
        self.assertTrue(d["ok"])
        self.assertEqual(d["gw"], "172.16.91.1")


class TestProbePingBig(_ProbeTestBase):
    def test_clean_pass(self):
        self.mock_core._run = MagicMock(
            return_value=self._run_result(
                0, "48 packets transmitted, 48 received, 0% packet loss"))
        d = self.probe.link_probe_ping_big()
        self.assertTrue(d["supported"])
        self.assertTrue(d["ok"])
        self.assertEqual(d["loss_pct"], 0)
        # зонд обязан ставить fwmark каскада на сокет (0x8200 = 33280
        # → ip rule → table 2000 → awg1): путь ровно как у транзита
        cmd = [str(c) for c in self.mock_core._run.call_args[0][0]]
        self.assertIn("33280", cmd)

    def test_cut_stream(self):
        self.mock_core._run = MagicMock(
            return_value=self._run_result(
                1, "48 packets transmitted, 0 received, 100% packet loss"))
        d = self.probe.link_probe_ping_big()
        self.assertTrue(d["supported"])
        self.assertFalse(d["ok"])
        self.assertEqual(d["loss_pct"], 100)

    def test_unsupported_ping_no_m(self):
        self.mock_core._run = MagicMock(
            return_value=self._run_result(2, "", "ping: invalid option -- m"))
        d = self.probe.link_probe_ping_big()
        self.assertFalse(d["supported"])
        self.assertIsNone(d["loss_pct"])


# ── 6. Полный прогон лестницы ───────────────────────────────────────────────

class TestProbeRun(_ProbeTestBase):
    def test_run_classifies_one_way(self):
        import tempfile, json as _json
        from chimera.modules import awg_state as awg_state_mod
        tmp = Path(tempfile.mkdtemp()) / "state.json"
        state_p = patch("chimera.modules.awg_state.AWGS_STATE_FILE", tmp)
        state_p.start()
        self.addCleanup(state_p.stop)
        tmp.write_text(_json.dumps({
            "installed": True,
            "cascade_role": "entry",
            "cascade_subnet": "172.16.91.0/24",
            "protocol_version": "3.1",
            "params": {"jc": 4},
        }))
        # _run по очереди: awg show (one-way) → ping gw → ping big
        self.mock_core._run = MagicMock(side_effect=[
            self._run_result(0, _AWG_SHOW_ONE_WAY),   # awg show awg1
            self._run_result(0, "1 received"),        # ping gw
            self._run_result(1, "100% packet loss"),  # ping big (не нужен:
        ])
        report = self.probe.link_probe_run()
        self.assertEqual(report["pattern"], "one-way-out")
        self.assertTrue(report["recommendation"]["split_direction"])

    def test_report_smoke_no_exception(self):
        self.mock_core._run = MagicMock(
            return_value=self._run_result(0, _AWG_SHOW_OK))
        report = {
            "awg1": {"up": True, "handshake_age": 85, "tx": 1000, "rx": 500},
            "ping_gw": {"ok": True, "gw": "172.16.91.1"},
            "ping_big": {"ok": True, "loss_pct": 0, "sent_bytes": 59000,
                         "supported": True},
            "pattern": "bidirectional-ok",
            "recommendation": self.probe.link_recommend("bidirectional-ok"),
        }
        # печать не может ронять зонд (бокс-рендерер мокнут целиком)
        try:
            self.probe.link_probe_report(report)
        except Exception as e:
            self.fail(f"link_probe_report бросил {e!r}")


if __name__ == "__main__":
    unittest.main()
