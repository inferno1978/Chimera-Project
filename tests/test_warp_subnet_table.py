#!/usr/bin/env python3
"""
tests/test_warp_subnet_table.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты «таблицы подсетей» — warpscout-дашборда Chimera
(chimera/modules/warp_subnet_table.py).

Покрывает:
  1. aggregate_best_per_subnet — группировка по /24, лучший RTT на подсеть,
     сортировка по RTT, пустой вход, исходные dict не мутируются.
  2. colo_city — известные/незнакомые IATA-коды.
  3. render_subnet_table — заголовки, выравнивание, чёрный список (красная
     строка + «⚠ ЧС»), TG 5/5 (зелёная клетка), серые непрошедшие,
     быстрый режим (без проб), пустые данные.
  4. _status_line — сводка в пробном/быстром режимах.
  5. _default_route — парсинг `ip route show default` (via/dev/мусор).
  6. probe_endpoint_egress — полный жизненный цикл wg-scout на моках:
     порядок команд (link add → wg set → addr → up), host-маршрут до
     кандидата только при dev wg-warp, replace 1.1.1.1/32 с
     восстановлением прежнего, from-правило 303/140 для MTProto,
     cleanup в finally при исключении, ключ-файл удаляется.
  7. _tg_cell — 5/5 / 3/5 / не пробовали.
  8. rehandshake_prod — рестарт wg-quick при активном туннеле + перепримен
     маршрутов _apply_mode; неактивный туннель — ничего не делается.
  9. run_subnet_table_flow — интерактив: скан → проба → выбор →
     _change_warp_endpoint; быстрый режим (n); Ctrl+C — частичная таблица;
     WARP не установлен.
10. probe_dc(bind_to=...) — сокет биндится к адресу wg-scout до connect.
11. warp._scan_warp_endpoints(top=None) — возвращает все результаты.
"""
from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock, call

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import warp_subnet_table as wst
from chimera.modules import warp as warp_mod
from chimera.modules import warp_telegram_probe as wtp

ANSI = chr(27) + r"\[[0-9;]*m"


def _plain(s: str) -> str:
    import re
    return re.sub(ANSI, "", s)


FIELDS = {
    "address": ["172.16.0.2/32", "2606:4700:110:8bad:12ab::/128"],
    "private_key": "PRIVKEY",
    "public_key": "PUBKEY",
    "endpoint": "162.159.192.1:2408",
    "keepalive": "25", "mtu": None, "dns": "1.1.1.1",
}


def _cp(args, rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args, rc, stdout=stdout, stderr=stderr)


class FakeIP:
    """Мок wst._ip: пишет команды в self.calls, ответы по префиксу."""

    def __init__(self, route_get="", route_show_1111="", default="",
                 link_add_rc=0):
        self.calls: list[list] = []
        self.route_get = route_get
        self.route_show_1111 = route_show_1111
        self.default = default
        self.link_add_rc = link_add_rc

    def __call__(self, args, timeout=8):
        self.calls.append(list(args))
        joined = " ".join(args)
        if joined.startswith("ip link add"):
            return _cp(args, self.link_add_rc, stderr="err")
        if joined.startswith("ip route get"):
            return _cp(args, 0, stdout=self.route_get or "1.2.3.4 via 192.0.2.1 dev eth0")
        if joined.startswith("ip route show 1.1.1.1/32"):
            return _cp(args, 0, stdout=self.route_show_1111)
        if joined.startswith("ip route show default"):
            return _cp(args, 0, stdout=self.default)
        return _cp(args, 0)

    def flat(self):
        return [" ".join(c) for c in self.calls]


class TestAggregate(unittest.TestCase):
    def test_best_per_subnet_and_sort(self):
        rows = wst.aggregate_best_per_subnet([
            {"host": "162.159.192.9", "rtt_ms": 59.0},
            {"host": "162.159.192.6", "rtt_ms": 57.0},
            {"host": "188.114.96.68", "rtt_ms": 58.0},
        ])
        self.assertEqual([r["subnet"] for r in rows],
                         ["162.159.192.0/24", "188.114.96.0/24"])
        self.assertEqual(rows[0]["host"], "162.159.192.6")
        self.assertTrue(rows[0]["rtt_ms"] < rows[1]["rtt_ms"])

    def test_endpoint_fallback_for_host(self):
        rows = wst.aggregate_best_per_subnet(
            [{"endpoint": "8.34.70.148:500", "rtt_ms": 49.0}])
        self.assertEqual(rows[0]["subnet"], "8.34.70.0/24")

    def test_empty_and_garbage(self):
        self.assertEqual(wst.aggregate_best_per_subnet([]), [])
        self.assertEqual(wst.aggregate_best_per_subnet(
            [{"host": "not-an-ip"}]), [])

    def test_source_not_mutated(self):
        src = [{"host": "162.159.192.9", "rtt_ms": 59.0}]
        wst.aggregate_best_per_subnet(src)
        self.assertNotIn("subnet", src[0])


class TestColoCity(unittest.TestCase):
    def test_known(self):
        self.assertEqual(wst.colo_city("HEL"), "Хельсинки, FI")
        self.assertEqual(wst.colo_city("dme"), "Москва, RU")
        self.assertEqual(wst.colo_city("LED"), "Санкт-Петербург, RU")

    def test_unknown_and_none(self):
        self.assertEqual(wst.colo_city("ZZZ"), "ZZZ")
        self.assertEqual(wst.colo_city(None), "")


class TestRender(unittest.TestCase):
    ROW1 = {"subnet": "162.159.192.0/24", "endpoint": "162.159.192.6:2408",
            "rtt_ms": 57.0, "colo": "HEL", "loc": "RU", "probe_ok": True,
            "tg_cell": "5/5"}
    ROW2 = {"subnet": "162.159.195.0/24", "endpoint": "162.159.195.82:2408",
            "rtt_ms": 82.0, "colo": "DME", "loc": "RU", "probe_ok": True,
            "tg_cell": "3/5"}

    def test_header_and_rows(self):
        lines = wst.render_subnet_table([dict(self.ROW1)], [], probed=True)
        self.assertIn("ПОДСЕТЬ", lines[0])
        self.assertIn("ENDPOINT", lines[0])
        body = _plain(lines[2])
        self.assertIn("162.159.192.0/24", body)
        self.assertIn("162.159.192.6:2408", body)
        self.assertIn("57 мс", body)
        self.assertIn("Хельсинки, FI", body)
        self.assertIn("5/5", body)

    def test_blacklist_row_red_with_marker(self):
        lines = wst.render_subnet_table(
            [dict(self.ROW1), dict(self.ROW2)], ["DME"], probed=True)
        row2 = lines[3]
        self.assertIn("⚠ ЧС", row2)
        self.assertIn(wst.RED, row2)

    def test_tg_full_green(self):
        lines = wst.render_subnet_table([dict(self.ROW1)], [], probed=True)
        self.assertIn(wst.GREEN, lines[2])

    def test_failed_probe_dim(self):
        row = dict(self.ROW1, probe_ok=False, colo=None, loc=None)
        lines = wst.render_subnet_table([row], [], probed=True)
        self.assertIn(wst.DIM, lines[2])

    def test_fast_mode_dots(self):
        lines = wst.render_subnet_table(
            [dict(self.ROW1, colo=None)], [], probed=False)
        body = _plain(lines[2])
        self.assertIn("·", body)
        self.assertNotIn("ЧС", _plain(lines[-1]))

    def test_empty_rows(self):
        self.assertEqual(wst.render_subnet_table([], [], True),
                         ["  (нет отвечающих подсетей)"])

    def test_alignment_equal_lengths(self):
        rows = [dict(self.ROW1), dict(self.ROW2)]
        lines = wst.render_subnet_table(rows, [], probed=True)
        body = [_plain(l) for l in lines[2:4]]
        self.assertEqual(len(body[0]), len(body[1]))

    def test_no_emoji(self):
        for line in wst.render_subnet_table(
                [dict(self.ROW1)], [], True):
            self.assertFalse(any(ord(ch) > 0x2FFF for ch in line))


class TestStatusLine(unittest.TestCase):
    def test_probed(self):
        rows = [dict(TestRender.ROW1), dict(TestRender.ROW2)]
        s = wst._status_line(rows, True)
        self.assertIn("Рабочие: 2/2", s)
        self.assertIn("HEL", s)
        self.assertIn("DME", s)
        self.assertIn("Выход: RU", s)

    def test_fast(self):
        s = wst._status_line([], False)
        self.assertIn("быстрый режим", s)


class TestDefaultRoute(unittest.TestCase):
    def test_via_dev(self):
        fake = FakeIP(default="default via 192.0.2.1 dev eth0 proto dhcp")
        with patch.object(wst, "_ip", fake):
            self.assertEqual(wst._default_route(),
                             ["via", "192.0.2.1", "dev", "eth0"])

    def test_dev_only(self):
        fake = FakeIP(default="default dev eth0")
        with patch.object(wst, "_ip", fake):
            self.assertEqual(wst._default_route(), ["dev", "eth0"])

    def test_garbage(self):
        fake = FakeIP(default="nothing here")
        with patch.object(wst, "_ip", fake):
            self.assertIsNone(wst._default_route())


class TestProbeLifecycle(unittest.TestCase):
    def _run_probe(self, fake, trace=("HEL", "RU", True),
                   tg=None, with_tg=True, route_get="", prev_1111=""):
        if tg is None:
            tg = {"reached_mask": 0b11111, "ok": True}
        with patch.object(wst, "_ip", fake), \
             patch.object(wst, "_trace_via", return_value=trace), \
             patch.object(wst, "_tg_probe_via", return_value=tg), \
             patch.object(wst, "_default_route",
                          return_value=["via", "192.0.2.1", "dev", "eth0"]), \
             patch.object(warp_mod, "info"), \
             patch.object(warp_mod, "warn"):
            return wst.probe_endpoint_egress(
                {"subnet": "162.159.192.0/24", "host": "162.159.192.6",
                 "endpoint": "162.159.192.6:2408", "rtt_ms": 57.0},
                FIELDS, with_tg=with_tg)

    def test_setup_order_and_full_success(self):
        fake = FakeIP(route_get="162.159.192.6 dev wg-warp")
        res = self._run_probe(fake)
        f = fake.flat()
        i_add = f.index("ip link add wg-scout type wireguard")
        i_set = next(i for i, c in enumerate(f)
                     if c.startswith("wg set wg-scout"))
        i_addr = f.index("ip addr add 172.16.0.2/32 dev wg-scout")
        i_up = f.index("ip link set wg-scout up")
        self.assertLess(i_add, i_set)
        self.assertLess(i_set, i_addr)
        self.assertLess(i_addr, i_up)
        self.assertIn("wg set wg-scout listen-port 0", f[i_set])
        self.assertIn("peer PUBKEY", f[i_set])
        self.assertIn("endpoint 162.159.192.6:2408", f[i_set])
        self.assertTrue(res["probe_ok"])
        self.assertEqual(res["colo"], "HEL")
        self.assertEqual(res["loc"], "RU")
        self.assertEqual(res["tg_cell"], "5/5")
        # cleanup: link del в конце
        self.assertIn("ip link del wg-scout", f)

    def test_host_route_added_when_via_warp(self):
        fake = FakeIP(route_get="162.159.192.6 dev wg-warp")
        self._run_probe(fake)
        f = fake.flat()
        self.assertIn("ip route add 162.159.192.6/32 via 192.0.2.1 dev eth0", f)
        self.assertIn("ip route del 162.159.192.6/32", f)

    def test_host_route_skipped_when_direct(self):
        fake = FakeIP(route_get="162.159.192.6 via 192.0.2.1 dev eth0")
        self._run_probe(fake)
        self.assertNotIn("ip route add 162.159.192.6/32 via 192.0.2.1 dev eth0",
                         fake.flat())

    def test_trace_route_replace_and_restore_prev(self):
        fake = FakeIP(route_show_1111="1.1.1.1/32 dev wg-warp")
        self._run_probe(fake)
        f = fake.flat()
        self.assertIn("ip route replace 1.1.1.1/32 dev wg-scout", f)
        self.assertIn("ip route del 1.1.1.1/32 dev wg-scout", f)
        self.assertIn("ip route add 1.1.1.1/32 dev wg-warp", f)
        # восстановление — ПОСЛЕ удаления нашего
        self.assertLess(f.index("ip route del 1.1.1.1/32 dev wg-scout"),
                        f.index("ip route add 1.1.1.1/32 dev wg-warp"))

    def test_tg_rule_and_table(self):
        fake = FakeIP()
        self._run_probe(fake)
        f = fake.flat()
        self.assertIn("ip route replace default dev wg-scout table 303", f)
        self.assertIn("ip rule add from 172.16.0.2 lookup 303 priority 140", f)
        self.assertIn("ip rule del from 172.16.0.2 lookup 303 priority 140", f)
        # правило снято ДО удаления интерфейса
        self.assertLess(f.index("ip rule del from 172.16.0.2 lookup 303 priority 140"),
                        f.index("ip link del wg-scout"))

    def test_no_tg_no_rule(self):
        fake = FakeIP()
        self._run_probe(fake, with_tg=False)
        f = fake.flat()
        self.assertNotIn("ip rule add from 172.16.0.2 lookup 303 priority 140", f)

    def test_dead_trace(self):
        fake = FakeIP()
        res = self._run_probe(fake, trace=(None, None, False))
        self.assertFalse(res["probe_ok"])
        self.assertIsNone(res["colo"])

    def test_cleanup_on_exception(self):
        fake = FakeIP()
        with patch.object(wst, "_ip", fake), \
             patch.object(wst, "_trace_via",
                          side_effect=RuntimeError("boom")), \
             patch.object(warp_mod, "info"), \
             patch.object(warp_mod, "warn"):
            with self.assertRaises(RuntimeError):
                wst.probe_endpoint_egress(
                    {"endpoint": "162.159.192.6:2408", "rtt_ms": 57.0},
                    FIELDS)
        self.assertIn("ip link del wg-scout", fake.flat())

    def test_keyfile_removed(self):
        fake = FakeIP()
        unlink = patch("os.unlink", wraps=os.unlink)
        with unlink as m_unlink, \
             patch.object(wst, "_ip", fake), \
             patch.object(wst, "_trace_via", return_value=("HEL", "RU", True)), \
             patch.object(wst, "_tg_probe_via", return_value={"reached_mask": 31}), \
             patch.object(warp_mod, "info"), \
             patch.object(warp_mod, "warn"):
            wst.probe_endpoint_egress(
                {"endpoint": "162.159.192.6:2408"}, FIELDS)
        self.assertTrue(any("wgscout-" in str(a) for a in m_unlink.call_args_list))

    def test_link_add_fail(self):
        fake = FakeIP(link_add_rc=2)
        res = self._run_probe(fake)
        self.assertFalse(res["probe_ok"])
        self.assertIn("ip link del wg-scout", fake.flat())

    def test_bad_endpoint(self):
        res = wst.probe_endpoint_egress({"endpoint": "nope"}, FIELDS)
        self.assertFalse(res["probe_ok"])

    def test_no_v4(self):
        with patch.object(warp_mod, "info"), \
             patch.object(warp_mod, "warn"):
            res = wst.probe_endpoint_egress(
                {"endpoint": "1.2.3.4:2408"},
                dict(FIELDS, address=["2606:4700::1/128"]))
        self.assertFalse(res["probe_ok"])


class TestTgCell(unittest.TestCase):
    def test_cells(self):
        self.assertEqual(wst._tg_cell(None), "—")
        self.assertEqual(wst._tg_cell({"reached_mask": 0b11111}), "5/5")
        self.assertEqual(wst._tg_cell({"reached_mask": 0b10101}), "3/5")


class TestRehandshake(unittest.TestCase):
    def test_inactive_noop(self):
        with patch.object(warp_mod, "_warp_service_active",
                          return_value=False), \
             patch.object(warp_mod, "_run") as m_run:
            wst.rehandshake_prod()
            m_run.assert_not_called()

    def test_active_restarts_and_reapplies(self):
        with patch.object(warp_mod, "_warp_service_active",
                          return_value=True), \
             patch.object(warp_mod, "_run") as m_run, \
             patch.object(wst, "_trace_via", return_value=("HEL", "RU", True)), \
             patch.object(wst, "time") as m_time, \
             patch.object(warp_mod, "_state_get",
                          side_effect=lambda k, d=None: d), \
             patch.object(warp_mod, "_apply_mode") as m_apply, \
             patch.object(warp_mod, "success"), \
             patch.object(warp_mod, "info"):
            wst.rehandshake_prod()
        m_run.assert_called_once_with(
            ["systemctl", "restart", warp_mod.WG_SERVICE],
            capture=True, check=False)
        m_apply.assert_called_once()


class TestScanTopParam(unittest.TestCase):
    def test_top_none_returns_all(self):
        hosts = [f"162.159.192.{i}" for i in range(2, 8)]

        def make_probe(h):
            i = hosts.index(h)
            return {"host": h, "port": 2408, "rtt_ms": 50.0 + i,
                    "tcp_ok": True, "icmp_ok": True}

        for expect_len, top in ((6, None), (5, 5)):
            with patch.object(warp_mod, "_select_scan_targets",
                              return_value=hosts), \
                 patch.object(warp_mod, "_probe_host_all_ports",
                              side_effect=lambda h: make_probe(h)), \
                 patch.object(warp_mod, "info"), \
                 patch.object(warp_mod, "success"), \
                 patch.object(warp_mod, "warn"):
                res = warp_mod._scan_warp_endpoints(top=top)
            self.assertEqual(len(res), expect_len)
            self.assertTrue(all("endpoint" in r for r in res))


class TestProbeDcBindTo(unittest.TestCase):
    def test_bind_called_before_connect(self):
        sock = MagicMock()
        sock.recv.side_effect = [b"\x50\x00\x00\x00"]
        with patch.object(wtp, "socket") as m_socket:
            m_socket.socket.return_value = sock
            m_socket.AF_INET = 2
            m_socket.SOCK_STREAM = 1
            ok, rtt = wtp.probe_dc("149.154.175.50", bind_to="172.16.0.2")
        self.assertTrue(ok)
        sock.bind.assert_called_once_with(("172.16.0.2", 0))
        sock.connect.assert_called_once_with(("149.154.175.50", 443))
        # bind выполнен ДО connect — по фактическому порядку вызовов
        methods = [c[0] for c in sock.method_calls]
        self.assertLess(methods.index("bind"), methods.index("connect"))

    def test_bind_no_positional_side_effect(self):
        # call_args сравнение выше через порядок вызовов; проверим, что
        # bind действительно выполнен ДО connect по списку вызовов
        sock = MagicMock()
        sock.recv.side_effect = [b"\x50\x00\x00\x00"]
        with patch.object(wtp, "socket") as m_socket:
            m_socket.socket.return_value = sock
            m_socket.AF_INET = 2
            m_socket.SOCK_STREAM = 1
            wtp.probe_dc("149.154.175.50", bind_to="172.16.0.2")
        methods = [c[0] for c in sock.method_calls]
        self.assertLess(methods.index("bind"), methods.index("connect"))

    def test_bind_oserror(self):
        sock = MagicMock()
        sock.bind.side_effect = OSError("nope")
        with patch.object(wtp, "socket") as m_socket:
            m_socket.socket.return_value = sock
            m_socket.AF_INET = 2
            m_socket.SOCK_STREAM = 1
            ok, rtt = wtp.probe_dc("149.154.175.50", bind_to="172.16.0.2")
        self.assertFalse(ok)
        self.assertIsNone(rtt)


class TestFlow(unittest.TestCase):
    SCAN = [
        {"host": "162.159.192.6", "port": 2408, "rtt_ms": 57.0,
         "tcp_ok": True, "icmp_ok": True, "score": 91.0,
         "endpoint": "162.159.192.6:2408"},
        {"host": "188.114.96.68", "port": 2408, "rtt_ms": 58.0,
         "tcp_ok": True, "icmp_ok": True, "score": 90.0,
         "endpoint": "188.114.96.68:2408"},
    ]

    def _flow(self, inputs, probe_side_effect=None, active=False,
              blacklist=None, scan=None):
        scan = scan if scan is not None else self.SCAN
        changes = MagicMock()
        rehandshake = MagicMock()
        probes = probe_side_effect or (
            lambda row, fields, with_tg=True: dict(
                row, colo="HEL", loc="RU", warp_on=True, probe_ok=True,
                tg={"reached_mask": 31}, tg_cell="5/5"))
        with patch.object(wst.os, "system"), \
             patch("builtins.input", side_effect=inputs), \
             patch.object(warp_mod, "_parse_wg_config_fields",
                          return_value=dict(FIELDS)), \
             patch.object(warp_mod, "_scan_warp_endpoints", return_value=scan), \
             patch.object(warp_mod, "_endpoint_cache_save") as m_cache, \
             patch.object(warp_mod, "_warp_service_active",
                          return_value=active), \
             patch.object(wst, "rehandshake_prod", rehandshake), \
             patch.object(warp_mod, "_colo_blacklist",
                          return_value=blacklist or []), \
             patch.object(warp_mod, "_change_warp_endpoint", changes), \
             patch.object(wst, "probe_endpoint_egress", side_effect=probes), \
             patch.object(warp_mod, "info"), \
             patch.object(warp_mod, "success"), \
             patch.object(warp_mod, "warn"):
            wst.run_subnet_table_flow()
        return changes, rehandshake, m_cache

    def test_full_flow_applies_choice(self):
        changes, reh, cache = self._flow(["y", "1", "y", ""], active=True)
        changes.assert_called_once_with("162.159.192.6:2408")
        reh.assert_called_once()          # туннель был активен → ре-хендшейк
        cache.assert_called_once()        # топ-5 в кэш Endpoint Manager

    def test_fast_mode_no_probes(self):
        changes, reh, _ = self._flow(["n", "2", "y", ""])
        changes.assert_called_once_with("188.114.96.68:2408")
        reh.assert_not_called()

    def test_decline_confirm(self):
        changes, _, _ = self._flow(["y", "1", "n", ""])
        changes.assert_not_called()

    def test_invalid_choice(self):
        changes, _, _ = self._flow(["y", "99", ""])
        changes.assert_not_called()

    def test_keyboard_interrupt_partial(self):
        calls = {"n": 0}

        def probe(row, fields, with_tg=True):
            calls["n"] += 1
            if calls["n"] > 1:
                raise KeyboardInterrupt
            return dict(row, colo="HEL", loc="RU", warp_on=True,
                        probe_ok=True, tg={"reached_mask": 31},
                        tg_cell="5/5")

        changes, reh, _ = self._flow(["y", "", ""], probe_side_effect=probe,
                                     active=True)
        changes.assert_not_called()
        reh.assert_called_once()          # ре-хендшейк обязателен даже при Ctrl+C

    def test_no_scan_results(self):
        changes, _, _ = self._flow([""], scan=[])
        changes.assert_not_called()

    def test_warp_not_installed(self):
        with patch.object(wst.os, "system"), \
             patch("builtins.input", side_effect=[""]), \
             patch.object(warp_mod, "_parse_wg_config_fields",
                          return_value=None):
            wst.run_subnet_table_flow()  # просто не падает

    def test_blacklist_warn_before_apply(self):
        probe = lambda row, fields, with_tg=True: dict(
            row, colo="DME", loc="RU", warp_on=True, probe_ok=True,
            tg=None, tg_cell="—")
        changes, _, _ = self._flow(["y", "1", "n", ""],
                                   probe_side_effect=probe,
                                   blacklist=["DME"])
        changes.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
