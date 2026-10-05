#!/usr/bin/env python3
"""
tests/test_awg_cascade_lb.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты балансировки мульти-exit каскада (chimera/modules/awg_cascade_lb.py
+ интеграции awg_cascade/awg_b4_split).

Покрывает:
 1. lb_slot_map / lb_is_on — слоты 1..N, марки 0x8200|slot, таблицы 2000+slot
 2. чистые spec: хук/save/голова/хвост (prio/rr/random/весовые/clienthash/
    закрепление), маски 0xFF00/0xFFFF
 3. lb_balance_shares + lb_shares_materially_changed (порт теста Mieru)
 4. _parse_ping / _argv_del / lb_extra_ifaces / _nft_ifaces
 5. lb_dispatcher_install/remove — применение/зачистка (rec-мок _run)
 6. lb_health_tick — пробы/EMA/ребаланс/self-heal/all-dead/фазы закрепления
 7. lb_activate/lb_deactivate — порядок (state первым при deactivate —
    урок v5.5.11.3), откат при сбое туннелей
 8. lb_routing_script_text — бут-заглушка/хук/save/пер-слот/зачистка
 9. awgs_cascade_failover_check — диспетчеризация в lb_health_tick
 10. B4-интеграция: cascade_mark_sync → lb_hook_sync; nft-сплит с awg2..N;
     _nft_ifaces форма iifname { ... }
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

sys.path.insert(0, str(_PROJECT_ROOT / "tests"))
from test_awg_cascade_multiexit import (      # noqa: E402
    _setup_core_in_sysmodules, _mock_core_for_cascade, _box, _PARAMS_31,
)


# ── rec-мок _run: запись всех вызовов ────────────────────────────────────────

class _Recorder:
    def __init__(self):
        self.calls: list = []          # list[list] argv
        self.bash: list = []           # list[str] bash -c тела
        self.nft_batches: list = []    # list[str] nft -f - тексты

    def run(self, argv, capture=False, check=False, **kw):
        self.calls.append(list(argv))
        if argv and argv[0] == "bash":
            self.bash.append(argv[-1])
        if argv[:2] == ["nft", "-f"]:
            self.nft_batches.append(kw.get("input_text", ""))
        r = MagicMock()
        r.returncode = 0
        r.stdout = kw.get("stdout", "")
        r.stderr = ""
        return r

    def has(self, *frag) -> bool:
        """Есть ли вызов, содержащий подряд все фрагменты."""
        for c in self.calls:
            if all(f in c for f in frag):
                return True
        return False

    def bash_has(self, text: str) -> bool:
        return any(text in b for b in self.bash)


def _hs(age_s: int) -> str:
    return f"latest handshake: {age_s} seconds ago"


class _LbTestBase(unittest.TestCase):
    """База: fake core + tmp state + пути в tmp + rec-мок lb._run."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "state.json"
        self._conf_dir = self._tmpdir / "awg"
        self._conf_dir.mkdir()
        from chimera.modules import awg_cascade_lb
        from chimera.modules import awg_cascade
        from chimera.modules import awg_b4_split
        self.lb = awg_cascade_lb
        self.cascade = awg_cascade
        self.b4 = awg_b4_split
        self.mock_core = _mock_core_for_cascade()
        self.rec = _Recorder()
        self._patches = [
            patch.object(awg_cascade, "_core_module",
                         return_value=self.mock_core),
            patch.object(awg_cascade_lb, "_core_module",
                         return_value=self.mock_core),
            patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                  self._state_file),
            patch.object(awg_cascade, "AWGS_AWG1_CONF",
                         self._tmpdir / "awg1.conf"),
            patch("chimera.modules.awg_constants.AWGS_CONF_DIR",
                  self._conf_dir),
            patch.object(awg_cascade, "AWGS_ROUTING_SCRIPT",
                         self._tmpdir / "awg-routing.sh"),
            patch.object(awg_cascade, "AWGS_RU_ZONE_FILE",
                         self._tmpdir / "ru.zone"),
            # create_routing_script делает mkdir /etc/awg-cascade — в tmp
            patch.object(awg_cascade, "AWGS_CASCADE_DIR", self._tmpdir),
            patch.object(awg_b4_split, "AWGS_CASCADE_DIR", self._tmpdir),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(self._stop_patches)

    def _stop_patches(self):
        for p in self._patches:
            p.stop()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _use_rec_run(self):
        self._patches.append(
            patch.object(self.lb, "_run", side_effect=self.rec.run))
        self._patches[-1].start()

    def _write_state(self, state: dict):
        self._state_file.write_text(json.dumps(state))

    def _read_state(self) -> dict:
        return json.loads(self._state_file.read_text())

    _EXIT_NAMES = ["de", "fi1", "nl1", "pl1", "us1", "uk1", "fr1",
                   "es1", "se1", "ca1", "jp1", "sg1", "nl2", "tr1",
                   "ch1", "at1", "it1", "pt1", "dk1", "no1"]

    def _lb_state(self, n=3, strategy="prio", pinned="", v6=False):
        return {
            "installed": True, "interface": "awg0", "port": 51831,
            "subnet": "172.16.81.0/24", "mtu": 1280,
            "endpoint": "5.6.7.8", "params": dict(_PARAMS_31),
            "protocol_version": "3.1", "cascade_role": "entry",
            "allow_ipv6_tunnel": v6,
            "cascade_subnet": "172.16.91.0/24",
            "cascade_active_exit": "de",
            "cascade_exits": [
                _box(self._EXIT_NAMES[i - 1], f"10.0.0.{i}", port=52831 + i,
                     subnet=f"172.16.9{i % 10}.0/24")
                for i in range(1, n + 1)
            ],
            "lb_mode": n >= 2, "lb_strategy": strategy, "lb_pinned": pinned,
            "lb": {},
        }


# ── 1. Слоты / is_on ─────────────────────────────────────────────────────────

class TestSlotMap(_LbTestBase):
    def test_slots_marks_tables(self):
        st = self._lb_state(n=3)
        m = self.lb.lb_slot_map(st)
        self.assertEqual(list(m), ["de", "fi1", "nl1"])
        de = m["de"]
        self.assertEqual(de["slot"], 1)
        self.assertEqual(de["mark"], 0x8200 | 1)
        self.assertEqual(de["table"], 2001)
        self.assertEqual(de["iface"], "awg1")
        self.assertEqual(m["fi1"]["mark"], 0x8202)
        self.assertEqual(m["nl1"]["table"], 2003)

    def test_slot_cap_16(self):
        st = self._lb_state(n=20)
        m = self.lb.lb_slot_map(st)
        self.assertEqual(len(m), 16)
        last = list(m.values())[-1]
        self.assertEqual(last["slot"], 16)
        self.assertEqual(last["mark"], 0x8200 | 16)

    def test_is_on(self):
        st1 = self._lb_state(n=1); st1["lb_mode"] = True
        self.assertFalse(self.lb.lb_is_on(st1))     # 1 exit — нечем
        st3 = self._lb_state(n=3)
        self.assertTrue(self.lb.lb_is_on(st3))
        st3["lb_mode"] = False
        self.assertFalse(self.lb.lb_is_on(st3))


# ── 2. Чистые spec: хук/save/голова/хвост ────────────────────────────────────

class TestHookSpecs(_LbTestBase):
    def test_hook_argv_v4(self):
        a = self.lb.lb_hook_argv(False)
        self.assertEqual(
            a, ["iptables", "-t", "mangle", "-A", "PREROUTING",
                "-i", "awg0", "-m", "set", "!", "--match-set",
                "awg_ru_networks", "dst", "-j", "awg_lb"])

    def test_hook_argv_v6(self):
        a = self.lb.lb_hook_argv(True)
        self.assertEqual(
            a, ["ip6tables", "-t", "mangle", "-A", "PREROUTING",
                "-i", "awg0", "-m", "set", "!", "--match-set",
                "awg_ru_networks", "dst", "-j", "awg_lb6"])

    def test_save_argv_masks(self):
        a = self.lb.lb_save_argv(False)
        self.assertIn("--nfmask", a)
        self.assertIn("0xffff", [x.lower() for x in a])
        self.assertIn("--ctmask", a)

    def test_head_specs(self):
        for v6 in (False, True):
            specs = self.lb.lb_head_specs(v6)
            self.assertEqual(len(specs), 2)
            ipt = "ip6tables" if v6 else "iptables"
            chain = "awg_lb6" if v6 else "awg_lb"
            self.assertEqual(specs[0][:4], [ipt, "-t", "mangle", "-A", chain][:4])
            joined = " ".join(specs[0])
            self.assertIn("--mark 0x8200/0xff00", joined)
            self.assertIn("--restore-mark", joined)
            self.assertIn("--nfmask 0xffff", joined)
            self.assertIn("RETURN", " ".join(specs[1]))


class TestTailSpecs(_LbTestBase):
    def _slots(self, n=3):
        return self.lb.lb_slot_map(self._lb_state(n=n))

    def test_prio_first_alive_only(self):
        specs = self.lb.lb_tail_specs("prio", self._slots(3),
                                      ["de", "fi1", "nl1"])
        # первый живой — ОДНА пара (MARK + RETURN), без statistic
        self.assertEqual(len(specs), 2)
        self.assertEqual(specs[0][-1], "0x8201")
        self.assertNotIn("statistic", " ".join(specs[0]))
        self.assertEqual(specs[1][-1], "RETURN")

    def test_prio_dead_first_next_takes_over(self):
        specs = self.lb.lb_tail_specs("prio", self._slots(3),
                                      ["fi1", "nl1"])   # de мёртв
        self.assertEqual(len(specs), 2)               # только fi1-пара
        self.assertEqual(specs[0][-1], "0x8202")        # fi1 = слот 2

    def test_rr_nth(self):
        specs = self.lb.lb_tail_specs("rr", self._slots(3),
                                      ["de", "fi1", "nl1"])
        first = " ".join(specs[0])
        self.assertIn("--mode nth", first)
        self.assertIn("--every 3", first)
        self.assertIn("--packet 0", first)
        # последний — catch-all без statistic
        last_pair = " ".join(specs[-2])
        self.assertNotIn("statistic", last_pair)
        # пары: после каждого MARK идёт RETURN той же марки
        self.assertIn("RETURN", " ".join(specs[1]))
        self.assertIn("0x8201", specs[1])

    def test_random_probabilities(self):
        specs = self.lb.lb_tail_specs("random", self._slots(3),
                                      ["de", "fi1", "nl1"])
        self.assertIn("--probability 0.3333", " ".join(specs[0]))
        self.assertIn("--probability 0.5000", " ".join(specs[2]))

    def test_weighted_order_by_share(self):
        slots = self._slots(3)
        shares = {"de": 0.2, "fi1": 0.5, "nl1": 0.3}
        specs = self.lb.lb_tail_specs("leastping", slots,
                                      ["de", "fi1", "nl1"], shares=shares)
        # порядок по убыванию доли: fi1 (0.5) первый
        self.assertEqual(specs[0][-1], "0x8202")
        self.assertIn("--probability 0.5000", " ".join(specs[0]))
        # fi1=0.5; далее nl1: p = 0.3/(1-0.5) = 0.6
        self.assertIn("--probability 0.6000", " ".join(specs[2]))
        # de — catch-all без statistic
        de_mark = " ".join([s for s in specs if s[-1] == "0x8201"][0])
        self.assertNotIn("statistic", de_mark)

    def test_weighted_floor_excludes_tiny(self):
        slots = self._slots(3)
        shares = {"de": 0.003, "fi1": 0.5, "nl1": 0.497}   # de < 0.5%
        specs = self.lb.lb_tail_specs("leastping", slots,
                                      ["de", "fi1", "nl1"], shares=shares)
        joined = " ".join(map(" ".join, specs))
        self.assertNotIn("0x8201", joined)    # de вне ротации

    def test_pinned_single_pair(self):
        specs = self.lb.lb_tail_specs("rr", self._slots(3),
                                      ["de", "fi1", "nl1"], pinned="nl1")
        self.assertEqual(len(specs), 2)               # одна пара
        self.assertEqual(specs[0][-1], "0x8203")
        self.assertNotIn("statistic", " ".join(specs[0]))

    def test_clienthash_hmark(self):
        specs = self.lb.lb_tail_specs("clienthash", self._slots(3),
                                      ["de", "fi1", "nl1"])
        hm = " ".join(specs[0])
        self.assertIn("HMARK", hm)
        self.assertIn("--hmark-mod 3", hm)
        self.assertIn("--hmark-offset 33281", hm)   # 0x8201

    def test_clienthash_no_xt_module_falls_back_random(self):
        specs = self.lb.lb_tail_specs("clienthash", self._slots(3),
                                      ["de", "fi1", "nl1"], hmark=False)
        joined = " ".join(map(" ".join, specs))
        self.assertNotIn("HMARK", joined)
        self.assertIn("--mode random", joined)

    def test_bad_strategy_falls_back_prio(self):
        specs = self.lb.lb_tail_specs("wtf", self._slots(2),
                                      ["de", "fi1"])
        self.assertIn("MARK", " ".join(map(" ".join, specs)))


# ── 3. Доли / гистерезис ─────────────────────────────────────────────────────

BASE = {"de": 0.30, "fi1": 0.35, "nl1": 0.35}


class TestShares(_LbTestBase):
    def test_materially_changed_jitter(self):
        self.assertFalse(self.lb.lb_shares_materially_changed(
            {"shares": dict(BASE)}, {"shares": {"de": 0.29, "fi1": 0.36, "nl1": 0.35}}))

    def test_materially_changed_drift(self):
        self.assertTrue(self.lb.lb_shares_materially_changed(
            {"shares": dict(BASE)}, {"shares": {"de": 0.40, "fi1": 0.30, "nl1": 0.30}}))

    def test_materially_changed_set(self):
        self.assertTrue(self.lb.lb_shares_materially_changed(
            {"shares": dict(BASE)}, {"shares": {"de": 0.5, "fi1": 0.5}}))

    def test_materially_changed_none(self):
        self.assertTrue(self.lb.lb_shares_materially_changed(None, {"shares": dict(BASE)}))
        self.assertFalse(self.lb.lb_shares_materially_changed(None, None))

    def test_balance_shares_leastping(self):
        # предыстория EMA = пробам → сглаживание не искажает
        lb = {"metrics_ema": {
            "de": {"rtt_ms": 20.0, "loss_pct": 0.0, "tx_kbps": 0},
            "fi1": {"rtt_ms": 40.0, "loss_pct": 0.0, "tx_kbps": 0},
            "nl1": {"rtt_ms": 60.0, "loss_pct": 0.0, "tx_kbps": 0}}}
        probes = {
            "de": {"alive": True, "rtt_ms": 20.0, "loss_pct": 0.0, "tx_rate_bps": 0},
            "fi1": {"alive": True, "rtt_ms": 40.0, "loss_pct": 0.0, "tx_rate_bps": 0},
            "nl1": {"alive": True, "rtt_ms": 60.0, "loss_pct": 0.0, "tx_rate_bps": 0},
        }
        bal = self.lb.lb_balance_shares(lb, "leastping", probes)
        sh = bal["shares"]
        # 1/20 : 1/40 : 1/60 = 6:3:2
        self.assertAlmostEqual(sh["de"], 6 / 11, places=2)
        self.assertGreater(sh["de"], sh["fi1"])
        self.assertGreater(sh["fi1"], sh["nl1"])
        self.assertAlmostEqual(sum(sh.values()), 1.0, places=6)

    def test_balance_shares_dead_excluded(self):
        lb = {}
        probes = {
            "de": {"alive": True, "rtt_ms": 20.0, "loss_pct": 0.0, "tx_rate_bps": 0},
            "fi1": {"alive": False},
            "nl1": {"alive": True, "rtt_ms": 60.0, "loss_pct": 0.0, "tx_rate_bps": 0},
        }
        bal = self.lb.lb_balance_shares(lb, "leastping", probes)
        self.assertNotIn("fi1", bal["shares"])

    def test_balance_shares_smart_score(self):
        # предыстория EMA = пробам → сглаживание не искажает
        lb = {"metrics_ema": {
            "de": {"rtt_ms": 30.0, "loss_pct": 0.0, "tx_kbps": 500},
            "fi1": {"rtt_ms": 30.0, "loss_pct": 0.0, "tx_kbps": 5000}}}
        probes = {
            "de": {"alive": True, "rtt_ms": 30.0, "loss_pct": 0.0, "tx_rate_bps": 500000},
            "fi1": {"alive": True, "rtt_ms": 30.0, "loss_pct": 0.0, "tx_rate_bps": 5000000},
        }
        bal = self.lb.lb_balance_shares(lb, "smart", probes)
        sh = bal["shares"]
        # одинаковый RTT, de в 10 раз менее нагружен → доля заметно выше
        self.assertGreater(sh["de"], sh["fi1"] * 2)

    def test_balance_shares_ema_smoothing(self):
        lb = {"metrics_ema": {"de": {"rtt_ms": 100.0, "loss_pct": 0.0, "tx_kbps": 0}}}
        probes = {"de": {"alive": True, "rtt_ms": 20.0, "loss_pct": 0.0, "tx_rate_bps": 0}}
        bal = self.lb.lb_balance_shares(lb, "leastping", probes)
        # EMA: 0.65*100 + 0.35*20 = 72 → не 20 (не даём всплеску качнуть долю)
        self.assertAlmostEqual(lb["metrics_ema"]["de"]["rtt_ms"], 72.0, places=1)


# ── 4. Мелкие чистые ─────────────────────────────────────────────────────────

class TestSmall(_LbTestBase):
    def test_parse_ping(self):
        txt = ("3 packets transmitted, 3 received, 0% packet loss, time 2003ms\n"
               "rtt min/avg/max/mdev = 20.1/25.4/30.2/2.1 ms")
        rtt, loss = self.lb._parse_ping(txt)
        self.assertEqual(rtt, 25.4)
        self.assertEqual(loss, 0.0)

    def test_parse_ping_lossy(self):
        rtt, loss = self.lb._parse_ping(
            "3 packets transmitted, 1 received, 66% packet loss")
        self.assertEqual(loss, 66.0)
        self.assertIsNone(rtt)

    def test_argv_del(self):
        spec = ["iptables", "-t", "mangle", "-A", "awg_lb", "-j", "X"]
        self.assertEqual(self.lb._argv_del(spec)[3], "-D")
        self.assertEqual(spec[3], "-A")            # оригинал не тронут

    def test_base_of(self):
        self.assertEqual(self.lb._base_of("172.16.91.0/24"), "172.16.91")
        self.assertEqual(self.lb._base_of(""), "10.66.66")


# ── 5. Dispatcher install/remove (rec-мок) ──────────────────────────────────

class TestDispatcherInstall(_LbTestBase):
    def setUp(self):
        super().setUp()
        self._use_rec_run()

    def test_install_full_v4(self):
        st = self._lb_state(n=3, strategy="rr")
        self._write_state(st)
        ok = self.lb.lb_dispatcher_install()
        self.assertTrue(ok)
        # хук + save (через _check_or_add → bash -c)
        self.assertTrue(self.rec.bash_has("-A PREROUTING -i awg0") and
                        self.rec.bash_has("-j awg_lb"))
        self.assertTrue(self.rec.bash_has("CONNMARK --save-mark"))
        # голова: restore + RETURN (через bash-c от _check_or_add)
        self.assertTrue(self.rec.bash_has("-A awg_lb -m connmark") and
                        self.rec.bash_has("--restore-mark"))
        # хвост rr: nth + RETURN-пары (applied записан в state)
        saved = self._read_state()
        applied = saved["lb"]["applied"]
        self.assertTrue(applied)
        self.assertIn("--mode nth", " ".join(applied[0]))
        # таблицы/маршруты/правила per-slot
        self.assertTrue(self.rec.has("ip", "route", "replace", "default",
                                     "via", "172.16.92.1", "dev", "awg2",
                                     "table", "2002"))
        self.assertTrue(self.rec.bash_has("ip rule add fwmark 0x8202 lookup 2002"))
        self.assertTrue(self.rec.bash_has("-A POSTROUTING -o awg3 -j MASQUERADE"))
        self.assertTrue(self.rec.bash_has("-A FORWARD -i awg0 -o awg2 -j ACCEPT"))
        self.assertTrue(self.rec.bash_has("TCPMSS --set-mss 1240"))
        # RU-forward
        self.assertTrue(self.rec.bash_has(
            "-A FORWARD -i awg0 -m set --match-set awg_ru_networks"))

    def test_install_v6_mirror(self):
        st = self._lb_state(n=2, v6=True)
        self._write_state(st)
        self.assertTrue(self.lb.lb_dispatcher_install())
        self.assertTrue(self.rec.bash_has("-j awg_lb6"))
        self.assertTrue(self.rec.bash_has("ip6tables") and
                        self.rec.bash_has("CONNMARK --save-mark"))
        self.assertTrue(self.rec.bash_has("-A POSTROUTING -o awg2 -j MASQUERADE"))
        self.assertTrue(self.rec.bash_has("TCPMSS --set-mss 1220"))
        self.assertTrue(self.rec.bash_has(
            "ip -6 rule add fwmark 0x8202 lookup 2002"))

    def test_install_cleans_cascade_mark_path(self):
        st = self._lb_state(n=2)
        self._write_state(st)
        self.lb.lb_dispatcher_install()
        self.assertTrue(self.rec.bash_has(
            "MARK --set-mark 0x8200 2>/dev/null; do :; done;"))

    def test_install_stub_false_when_empty(self):
        self.assertFalse(self.lb.lb_dispatcher_install(
            {"lb_mode": False}))
        self.assertFalse(self.lb.lb_dispatcher_install({}))

    def test_remove_deletes_everything(self):
        st = self._lb_state(n=3)
        self._write_state(st)
        self.lb.lb_dispatcher_install()
        saved = self._read_state()
        self.assertTrue(saved["lb"]["applied"])
        # свежий рекордер для фазы удаления
        rec2 = _Recorder()
        with patch.object(self.lb, "_run", side_effect=rec2.run):
            self.assertTrue(self.lb.lb_dispatcher_remove())
        # хук-варианты + save + хвосты по applied + цепочки + per-exit
        self.assertTrue(rec2.bash_has("-D PREROUTING -i awg0") or
                        rec2.has("iptables", "-D", "PREROUTING"))
        self.assertTrue(rec2.has("ip6tables", "-X"))
        self.assertTrue(rec2.bash_has("-D POSTROUTING -o awg3 -j MASQUERADE"))
        # таблицы 1..16 зачищаются (в т.ч. слоты > n — сдвиг списка)
        self.assertTrue(rec2.bash_has("lookup 2016"))
        self.assertTrue(rec2.bash_has("ip route flush table 2016"))
        # applied в state обнулён
        saved2 = self._read_state()
        self.assertEqual(saved2["lb"].get("applied"), [])


# ── 6. Health-тик ────────────────────────────────────────────────────────────

class TestHealthTick(_LbTestBase):
    def _mk(self, probes, *, strategy="leastping", balance=None,
            pinned="", alive_prev=None, in_sync=True, lb_extra=None):
        st = self._lb_state(n=3, strategy=strategy, pinned=pinned)
        st["lb"] = {
            "balance": balance,
            "alive_prev": alive_prev,
            "applied": [["iptables", "-t", "mangle", "-A", "awg_lb",
                         "-j", "MARK", "--set-mark", "0x8201"],
                        ["iptables", "-t", "mangle", "-A", "awg_lb",
                         "-m", "mark", "--mark", "0x8201", "-j", "RETURN"]],
        }
        if lb_extra:
            st["lb"].update(lb_extra)
        self._write_state(st)
        installed = []
        notified = []
        sync = {"ok": in_sync}
        with patch.object(self.lb, "_probe_slot",
                          side_effect=lambda info, lb: probes[info["name"]]), \
             patch.object(self.lb, "lb_dispatcher_install",
                          side_effect=lambda *a, **k: installed.append(1) or True), \
             patch.object(self.lb, "_notify",
                          side_effect=lambda d: notified.append(d)), \
             patch.object(self.lb, "_rules_in_sync",
                          side_effect=lambda lb, v6: sync["ok"]):
            status = self.lb.lb_health_tick()
        return status, self._read_state(), installed, notified

    def test_ok_no_rewrite(self):
        probes = {n: {"alive": True, "rtt_ms": 30.0, "loss_pct": 0.0,
                      "tx_rate_bps": 0, "age": 5}
                  for n in ("de", "fi1", "nl1")}
        # равные пробы → вычисленные доли 1/3 — совпадают со старыми:
        # материального дрейфа нет, ребаланс не нужен
        balance = {"shares": {"de": 0.3333, "fi1": 0.3333, "nl1": 0.3334}}
        status, st, installed, _ = self._mk(
            probes, balance=balance, alive_prev=["de", "fi1", "nl1"])
        self.assertEqual(status, "ok")
        self.assertEqual(installed, [])       # джиттер — без ребаланса
        self.assertEqual(st["lb"]["alive"], ["de", "fi1", "nl1"])

    def test_rebalance_on_material_drift(self):
        probes = {n: {"alive": True, "rtt_ms": 30.0, "loss_pct": 0.0,
                      "tx_rate_bps": 0}
                  for n in ("de", "fi1", "nl1")}
        old = {"shares": {"de": 0.30, "fi1": 0.35, "nl1": 0.35}}
        new = {"shares": {"de": 0.55, "fi1": 0.25, "nl1": 0.20}}
        with patch.object(self.lb, "lb_balance_shares",
                          return_value=new):
            status, st, installed, _ = self._mk(
                probes, balance=old, alive_prev=["de", "fi1", "nl1"])
        self.assertEqual(status, "rebalance")
        self.assertEqual(installed, [1])
        self.assertEqual(st["lb"]["balance"]["shares"]["de"], 0.55)

    def test_alive_set_change_forces_rewrite(self):
        probes = {n: {"alive": True, "rtt_ms": 30.0, "loss_pct": 0.0,
                      "tx_rate_bps": 0}
                  for n in ("de", "fi1", "nl1")}
        # прошлый состав без nl1 — состав изменился
        status, st, installed, _ = self._mk(
            probes, balance={"shares": {"de": 0.5, "fi1": 0.5}},
            alive_prev=["de", "fi1"])
        self.assertIn(installed, ([1], [1, 1]))
        self.assertEqual(st["lb"]["alive_prev"], ["de", "fi1", "nl1"])

    def test_all_dead_no_install_no_deanon(self):
        probes = {n: {"alive": False, "age": None}
                  for n in ("de", "fi1", "nl1")}
        status, st, installed, notified = self._mk(probes)
        self.assertEqual(status, "all-dead")
        self.assertEqual(installed, [])       # диспетчер НЕ снимаем
        self.assertTrue(any("недоступны" in x for x in notified))

    def test_pinned_fallback_and_return(self):
        dead = {"de": {"alive": False, "age": 9999},
                "fi1": {"alive": True, "rtt_ms": 30.0, "loss_pct": 0.0,
                        "tx_rate_bps": 0},
                "nl1": {"alive": True, "rtt_ms": 30.0, "loss_pct": 0.0,
                        "tx_rate_bps": 0}}
        status, st, _, notified = self._mk(
            dead, balance={"shares": {"fi1": 0.5, "nl1": 0.5}}, pinned="de")
        self.assertEqual(status, "pinned-fallback")
        self.assertTrue(st["lb"]["pinned_fallback"])
        # восстановление — возврат
        alive = {"de": {"alive": True, "rtt_ms": 30.0, "loss_pct": 0.0,
                        "tx_rate_bps": 0},
                 "fi1": {"alive": True, "rtt_ms": 30.0, "loss_pct": 0.0,
                         "tx_rate_bps": 0},
                 "nl1": {"alive": True, "rtt_ms": 30.0, "loss_pct": 0.0,
                         "tx_rate_bps": 0}}
        self._write_state(st)
        status2, st2, _, _ = self._mk(
            alive, balance=st["lb"]["balance"], pinned="de",
            alive_prev=st["lb"]["alive"],
            lb_extra={"pinned_fallback": True})
        self.assertEqual(status2, "pinned-return")
        self.assertFalse(st2["lb"]["pinned_fallback"])

    def test_self_heal_on_rules_out_of_sync(self):
        probes = {n: {"alive": True, "rtt_ms": 30.0, "loss_pct": 0.0,
                      "tx_rate_bps": 0}
                  for n in ("de", "fi1", "nl1")}
        # доли совпадают с вычисленными (равные) — материального дрейфа нет
        balance = {"shares": {"de": 0.3333, "fi1": 0.3333, "nl1": 0.3334}}
        status, st, installed, _ = self._mk(
            probes, balance=balance,
            alive_prev=["de", "fi1", "nl1"], in_sync=False)
        self.assertEqual(status, "heal")
        self.assertEqual(installed, [1])


# ── 7. Activate / deactivate ─────────────────────────────────────────────────

class TestActivateDeactivate(_LbTestBase):
    def test_activate_minimal(self):
        st = self._lb_state(n=3)
        st["lb_mode"] = False
        self._write_state(st)
        self._use_rec_run()
        self.assertTrue(self.lb.lb_activate("rr"))
        saved = self._read_state()
        self.assertTrue(saved["lb_mode"])
        self.assertEqual(saved["lb_strategy"], "rr")
        # туннели: конфиги в tmp + systemctl enable/restart
        self.assertTrue((self._conf_dir / "awg2.conf").exists())
        self.assertTrue((self._conf_dir / "awg3.conf").exists())
        self.assertTrue(self.rec.has("systemctl", "restart",
                                     "awg-quick@awg3"))
        # routing script lb-формы записан
        self.assertIn("LB-ФОРМА", self._tmpdir.joinpath("awg-routing.sh")
                      .read_text())

    def test_activate_rejects_single_exit(self):
        st = self._lb_state(n=1)
        st["lb_mode"] = False
        self._write_state(st)
        self.assertFalse(self.lb.lb_activate("rr"))

    def test_activate_clienthash_fallback_without_xt(self):
        st = self._lb_state(n=3)
        st["lb_mode"] = False
        self._write_state(st)
        self._use_rec_run()      # systemctl/iptables нет в песочнице
        with patch.object(self.lb, "_hmark_available", return_value=False):
            self.assertTrue(self.lb.lb_activate("clienthash"))
        saved = self._read_state()
        self.assertEqual(saved["lb_strategy"], "random")

    def test_activate_rollback_on_tunnel_fail(self):
        st = self._lb_state(n=3)
        st["lb_mode"] = False
        self._write_state(st)
        deact = []
        with patch.object(self.lb, "lb_tunnels_apply", return_value=False), \
             patch.object(self.lb, "lb_deactivate",
                          side_effect=lambda: deact.append(1) or True):
            self.assertFalse(self.lb.lb_activate("rr"))
        self.assertEqual(deact, [1])       # откат вызван

    def test_deactivate_state_first(self):
        st = self._lb_state(n=3)          # lb_mode True
        self._write_state(st)
        self._use_rec_run()
        snapshots = []
        orig_save = self.lb.awgs_state_save
        with patch.object(self.lb, "awgs_state_save",
                          side_effect=lambda s: (snapshots.append(json.loads(
                              json.dumps(s))), orig_save(s))[1] or True), \
             patch.object(self.cascade, "awgs_cascade_activate_exit",
                          return_value=True) as m_act, \
             patch.object(self.lb, "_notify", lambda d: None):
            self.assertTrue(self.lb.lb_deactivate())
        # ПЕРВЫЙ save уже с lb_mode=False (урок deactivate: state первым)
        self.assertFalse(snapshots[0]["lb_mode"])
        self.assertEqual(snapshots[0]["lb_pinned"], "")
        # прежний активный exit возвращён
        m_act.assert_called_once_with("de")
        # туннели >1 погашены
        self.assertTrue(self.rec.has("systemctl", "disable",
                                     "awg-quick@awg3"))
        # каскадный MARK-путь восстановлен (apply_iptables обычной формы)
        self.assertTrue(self.rec.bash_has("MARK --set-mark 0x8200"))
        # диспетчер снят
        self.assertTrue(self.rec.has("ip6tables", "-X"))


# ── 8. Routing script (lb-форма) ────────────────────────────────────────────

class TestRoutingScript(_LbTestBase):
    def test_lb_text_contains_core_blocks(self):
        st = self._lb_state(n=3, v6=True)
        txt = self.lb.lb_routing_script_text(st)
        # хук + save
        self.assertIn("-j awg_lb", txt)
        self.assertIn("-j awg_lb6", txt)
        self.assertIn("CONNMARK --save-mark", txt)
        # бут-заглушка: catch-all на awg1
        self.assertIn("--set-mark 0x8201", txt)
        # пер-слот таблицы/маршруты (подсети слотов 172.16.91/92/93)
        self.assertIn("default via 172.16.91.1 dev awg1 table 2001", txt)
        self.assertIn("default via 172.16.93.1 dev awg3 table 2003", txt)
        self.assertIn("ip -6 route replace default dev awg3 table 2003", txt)
        # TCPMSS v4/v6
        self.assertIn("--set-mss 1240", txt)
        self.assertIn("--set-mss 1220", txt)
        # зачистка лишних слотов
        self.assertIn("ip route flush table 2016", txt)

    def test_create_script_lb_branch(self):
        st = self._lb_state(n=2, v6=True)
        self._write_state(st)
        self.cascade._awgs_cascade_create_routing_script("172.16.91.0/24")
        content = self._tmpdir.joinpath("awg-routing.sh").read_text()
        self.assertIn("LB-ФОРМА", content)
        self.assertIn("awg_lb", content)
        # обычной каскадной формы в lb-скрипте нет
        self.assertNotIn("default via 172.16.91.1 dev awg1 table 2000", content)

    def test_regen_lb_wrapper(self):
        st = self._lb_state(n=2)
        self._write_state(st)
        self.assertTrue(self.cascade.awgs_cascade_routing_regen_lb())
        self.assertIn("LB-ФОРМА",
                      self._tmpdir.joinpath("awg-routing.sh").read_text())


# ── 9. failover_check диспетчеризация ────────────────────────────────────────

class TestFailoverDispatch(_LbTestBase):
    def test_dispatches_to_lb_tick(self):
        st = self._lb_state(n=3)
        self._write_state(st)
        with patch.object(self.lb, "lb_health_tick",
                          return_value="ok-lb") as m:
            self.assertEqual(self.cascade.awgs_cascade_failover_check(),
                             "ok-lb")
        m.assert_called_once()

    def test_lb_off_uses_regular_path(self):
        st = self._lb_state(n=3)
        st["lb_mode"] = False
        self._write_state(st)
        with patch.object(self.lb, "lb_health_tick") as m, \
             patch.object(self.cascade, "awgs_cascade_handshake_age",
                          return_value=10):
            self.assertEqual(self.cascade.awgs_cascade_failover_check(), "ok")
        m.assert_not_called()


# ── 10. B4-интеграция ────────────────────────────────────────────────────────

class TestB4Integration(_LbTestBase):
    def test_extra_ifaces(self):
        st = self._lb_state(n=4)
        self._write_state(st)
        self.assertEqual(self.b4.lb_extra_ifaces(),
                         ["awg2", "awg3", "awg4"])
        st["lb_mode"] = False
        self._write_state(st)
        self.assertEqual(self.b4.lb_extra_ifaces(), [])

    def test_nft_ifaces_forms(self):
        st = self._lb_state(n=3)
        self._write_state(st)
        self.assertEqual(self.b4._nft_ifaces(),
                          'iifname { "awg1", "awg2", "awg3" }')
        st["lb_mode"] = False
        self._write_state(st)
        self.assertEqual(self.b4._nft_ifaces(), 'iifname "awg1"')

    def test_nft_split_batch_with_lb(self):
        st = self._lb_state(n=3)
        self._write_state(st)
        rec = _Recorder()
        with patch.object(self.b4, "_run", side_effect=rec.run):
            self.assertTrue(self.b4.nft_apply_split())
        batch = rec.nft_batches[0] if rec.nft_batches else ""
        self.assertIn('iifname { "awg1", "awg2", "awg3" }', batch)
        self.assertIn('ip daddr @awg_b4direct return', batch)

    def test_mark_sync_routes_to_hook_in_lb(self):
        st = self._lb_state(n=3)
        self._write_state(st)
        synced = []
        with patch.object(self.lb, "lb_hook_sync",
                          side_effect=lambda excl: synced.append(excl) or True):
            self.assertTrue(self.b4.cascade_mark_sync(True))
        self.assertEqual(synced, [True])

    def test_routing_nft_block_split_form(self):
        st = self._lb_state(n=3)
        self._write_state(st)
        with patch.object(self.b4, "is_active", return_value=True):
            txt = self.b4.routing_nft_block()
        self.assertIn("daddr @awg_b4direct", txt)
        self.assertIn('sport 53', txt)
        self.assertIn('iifname { "awg1", "awg2", "awg3" }', txt)

    def test_hook_sync_two_forms(self):
        st = self._lb_state(n=2)
        self._write_state(st)
        self._use_rec_run()
        # сплит-исключение «включено» → форма с awg_b4_direct в хуке
        with patch.object(self.lb, "_split_excl",
                          return_value=["-m", "set", "!", "--match-set",
                                        "awg_b4_direct", "dst"]):
            self.assertTrue(self.lb.lb_hook_sync(True))
        bash = " ".join(self.rec.bash)
        self.assertIn("awg_b4_direct", bash)


if __name__ == "__main__":
    unittest.main(verbosity=2)
