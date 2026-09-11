#!/usr/bin/env python3
"""
tests/test_warp_telegram_probe.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты интеграции идей warpscout / warpscout-tg в WARP-модуль Chimera.

Покрывает:
  1. build_req_pq_multi — байтовая точность порта telegram.go
     (48 байт, magic intermediate, auth_key_id=0, msg_id unix<<32
     с msg_id % 4 == 0, LE-конструктор 0xBE7E8EF1, nonce 16).
  2. _frame_header_plausible — валидные/нулевые/огромные/обрывные ответы.
  3. probe_dc — ДЦ засчитан только по MTProto-ответу, не по TCP-connect.
  4. probe_all_dcs — все 5 / частично / blocked / WARP не поднят.
  5. telegram_status_str — человекочитаемые строки статуса.
  6. _ensure_probe_routing — через wg-warp уже идёт / временные правила +
     cleanup / интерфейс не поднят.
  7. warp._fetch_trace_meta — парсер trace-ответа (colo/loc/warp=on).
  8. warp._colo_blacklist — дефолт DME / override из state / выключен.
  9. warp._ext_state_save — read-modify-write не затирает чужие ключи.
 10. warp._parse_wg_config_fields + экспорт WG-конфига (v4/v6, AllowedIPs).
 11. warp._export_warp_mihomo_proxy / _yaml / _json — формат peers
     (как wgconf.go warpscout), JSON парсится, поля совпадают.
 12. telemt_warp_route._tg_probe_watchdog — частота по last_tg_probe_ts.
"""
from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import warp_telegram_probe as wtp
from chimera.modules import warp as warp_mod
from chimera.modules import telemt_warp_route as telemt_mod


def _fake_completed(stdout: str = "", returncode: int = 0):
    r = MagicMock()
    r.stdout = stdout
    r.returncode = returncode
    return r


# ═════════════════════════════════════════════════════════════════════════
#  1. build_req_pq_multi — байтовая точность (порт telegram.go)
# ═════════════════════════════════════════════════════════════════════════
class TestBuildReqPqMulti(unittest.TestCase):
    def test_length_is_48(self):
        self.assertEqual(len(wtp.build_req_pq_multi(unix_ts=1_700_000_000)), 48)

    def test_byte_layout_matches_telegram_go(self):
        msg = wtp.build_req_pq_multi(unix_ts=1_700_000_000, nonce=bytes(range(16)))
        self.assertEqual(msg[0:4], b"\xee\xee\xee\xee")                # intermediate
        self.assertEqual(struct.unpack_from("<I", msg, 4)[0], 40)      # frame len
        self.assertEqual(msg[8:16], b"\x00" * 8)                       # auth_key_id
        msg_id = struct.unpack_from("<Q", msg, 16)[0]
        self.assertEqual(msg_id, 1_700_000_000 << 32)                  # unix<<32
        self.assertEqual(msg_id % 4, 0)                                # %4==0 как клиенты
        self.assertEqual(struct.unpack_from("<I", msg, 24)[0], 20)     # data len
        self.assertEqual(struct.unpack_from("<I", msg, 28)[0], 0xBE7E8EF1)  # req_pq_multi
        self.assertEqual(msg[32:48], bytes(range(16)))                 # nonce

    def test_nonce_is_random(self):
        a = wtp.build_req_pq_multi(unix_ts=1)
        b = wtp.build_req_pq_multi(unix_ts=1)
        self.assertNotEqual(a[32:48], b[32:48])

    def test_bad_nonce_rejected(self):
        with self.assertRaises(ValueError):
            wtp.build_req_pq_multi(nonce=b"\x00" * 15)


# ═════════════════════════════════════════════════════════════════════════
#  2. _frame_header_plausible
# ═════════════════════════════════════════════════════════════════════════
class TestFrameHeader(unittest.TestCase):
    @staticmethod
    def _sock(payload: bytes):
        sock = MagicMock()
        chunks = [payload[i:i + 4] for i in range(0, len(payload), 4)] or [b""]
        sock.recv.side_effect = chunks
        return sock

    def test_plausible_res_pq(self):
        sock = self._sock(struct.pack("<I", 84) + b"x" * 8)
        self.assertTrue(wtp._frame_header_plausible(sock))

    def test_zero_len_rejected(self):
        self.assertFalse(wtp._frame_header_plausible(self._sock(struct.pack("<I", 0))))

    def test_huge_len_rejected(self):
        self.assertFalse(wtp._frame_header_plausible(self._sock(struct.pack("<I", 1 << 20))))

    def test_empty_reply_rejected(self):
        self.assertFalse(wtp._frame_header_plausible(self._sock(b"")))


# ═════════════════════════════════════════════════════════════════════════
#  3-4. probe_dc / probe_all_dcs
# ═════════════════════════════════════════════════════════════════════════
class TestProbe(unittest.TestCase):
    def test_probe_dc_answered(self):
        with patch.object(wtp.socket, "create_connection") as conn:
            sock = MagicMock()
            sock.recv.side_effect = [struct.pack("<I", 84), b"x" * 8]
            conn.return_value.__enter__.return_value = sock
            conn.return_value.__exit__.return_value = False
            ok, rtt = wtp.probe_dc("149.154.175.50")
        self.assertTrue(ok)
        self.assertIsNotNone(rtt)

    def test_probe_dc_tcp_only_is_not_enough(self):
        """DPI завершает TCP, но дропает payload: длина 0 → ДЦ НЕ засчитан."""
        with patch.object(wtp.socket, "create_connection") as conn:
            sock = MagicMock()
            sock.recv.return_value = struct.pack("<I", 0)
            conn.return_value.__enter__.return_value = sock
            conn.return_value.__exit__.return_value = False
            ok, rtt = wtp.probe_dc("149.154.175.50")
        self.assertFalse(ok)

    def test_probe_dc_timeout(self):
        with patch.object(wtp.socket, "create_connection", side_effect=OSError):
            self.assertEqual(wtp.probe_dc("149.154.175.50"), (False, None))

    def _probe_all(self, answers: dict):
        """answers: ip → (ok, rtt). Прочее мокается на дефолтах."""
        def fake_probe(ip, port=wtp.TG_DC_PORT, timeout=4.0):
            return answers.get(ip, (False, None))
        with patch.object(wtp, "_ensure_probe_routing", return_value=(True, [])), \
             patch.object(wtp, "probe_dc", side_effect=fake_probe):
            return wtp.probe_all_dcs()

    def test_all_five_reached(self):
        res = self._probe_all({ip: (True, 50.0) for _n, ip in wtp.TELEGRAM_DCS})
        self.assertTrue(res["ok"])
        self.assertEqual(res["reached_mask"], 0b11111)
        self.assertEqual(res["worst_rtt_ms"], 50.0)
        self.assertEqual(res["missing_names"], [])

    def test_partial_reach_not_ok(self):
        ips = [ip for _n, ip in wtp.TELEGRAM_DCS]
        answers = {ip: (True, 40.0) for ip in ips[:3]}
        res = self._probe_all(answers)
        self.assertFalse(res["ok"])
        self.assertEqual(len(res["reached_names"]), 3)
        self.assertEqual(res["missing_names"], ["DC4", "DC5"])
        self.assertEqual(res["worst_rtt_ms"], 40.0)

    def test_worst_rtt_wins(self):
        ips = [ip for _n, ip in wtp.TELEGRAM_DCS]
        answers = {ip: (True, 30.0 + i * 25.0) for i, ip in enumerate(ips)}
        res = self._probe_all(answers)
        self.assertEqual(res["worst_rtt_ms"], 130.0)

    def test_blocked(self):
        res = self._probe_all({})
        self.assertFalse(res["ok"])
        self.assertEqual(res["reached_names"], [])
        self.assertEqual(len(res["missing_names"]), 5)

    def test_warp_down(self):
        with patch.object(wtp, "_ensure_probe_routing", return_value=(False, [])):
            res = wtp.probe_all_dcs()
        self.assertFalse(res["warp_up"])
        self.assertFalse(res["ok"])

    def test_cleanup_runs_after_probe(self):
        """Временные правила снимаются даже при исключении в пробах."""
        cleanup = [["ip", "rule", "del"]]
        with patch.object(wtp, "_ensure_probe_routing", return_value=(True, cleanup)), \
             patch.object(wtp, "probe_dc", side_effect=OSError), \
             patch.object(wtp, "_run_cleanup") as rc:
            wtp.probe_all_dcs()
        rc.assert_called_once_with(cleanup)


# ═════════════════════════════════════════════════════════════════════════
#  5. telegram_status_str
# ═════════════════════════════════════════════════════════════════════════
class TestStatusStr(unittest.TestCase):
    def test_all_ok(self):
        s = wtp.telegram_status_str({"ok": True, "warp_up": True,
                                      "reached_names": ["DC1"], "worst_rtt_ms": 84.2})
        self.assertEqual(s, "Telegram: 5/5 · худший 84 мс")

    def test_partial(self):
        s = wtp.telegram_status_str({"ok": False, "warp_up": True,
                                      "reached_names": ["DC1", "DC2", "DC3"],
                                      "missing_names": ["DC4", "DC5"]})
        self.assertEqual(s, "Telegram: 3/5 (нет DC4, DC5)")

    def test_blocked(self):
        s = wtp.telegram_status_str({"ok": False, "warp_up": True,
                                      "reached_names": [], "missing_names": ["DC1"]})
        self.assertEqual(s, "Telegram: blocked (не ответил ни один ДЦ)")

    def test_warp_down(self):
        s = wtp.telegram_status_str({"ok": False, "warp_up": False})
        self.assertEqual(s, "WARP не поднят — проба Telegram пропущена")


# ═════════════════════════════════════════════════════════════════════════
#  6. _ensure_probe_routing
# ═════════════════════════════════════════════════════════════════════════
class TestProbeRouting(unittest.TestCase):
    def test_iface_down(self):
        with patch.object(wtp, "_ip_run", return_value=_fake_completed("", returncode=1)):
            ok, cleanup = wtp._ensure_probe_routing()
        self.assertFalse(ok)
        self.assertEqual(cleanup, [])

    def test_already_routed(self):
        responses = {
            "link": _fake_completed("wg-warp: <POINTOPOINT>", 0),
            "route": _fake_completed("149.154.175.50 dev wg-warp table 300", 0),
        }
        with patch.object(wtp, "_ip_run",
                          side_effect=lambda a: responses.get("route" if a[1] == "route" else "link")):
            ok, cleanup = wtp._ensure_probe_routing()
        self.assertTrue(ok)
        self.assertEqual(cleanup, [])

    def test_temporary_rules_installed_and_cleaned(self):
        responses = {
            "link": _fake_completed("wg-warp: <POINTOPOINT>", 0),
            "route": _fake_completed("149.154.175.50 dev eth0 via 1.2.3.4", 0),
        }
        with patch.object(wtp, "_ip_run",
                          side_effect=lambda a: responses.get("route" if a[1] == "route" else "link")) as ip_run:
            ok, cleanup = wtp._ensure_probe_routing()
        self.assertTrue(ok)
        self.assertEqual(len(cleanup), 6)  # 5 правил + маршрут из таблицы
        added = " ".join(" ".join(c.args[0]) for c in ip_run.call_args_list)
        self.assertIn("replace default dev wg-warp table 302", added)
        self.assertIn("priority 155", added)
        # cleanup: все 5 to-правил + таблица
        self.assertEqual(sum(1 for c in cleanup if "rule" in c), 5)
        self.assertEqual(sum(1 for c in cleanup if "route" in c and "del" in c), 1)


# ═════════════════════════════════════════════════════════════════════════
#  7. warp._fetch_trace_meta
# ═════════════════════════════════════════════════════════════════════════
TRACE_BODY = """fl=581f121
h=1.1.1.1
ip=1.2.3.4
colo=DME
loc=RU
warp=on
"""


class TestTraceMeta(unittest.TestCase):
    def test_parses_colo_loc_warp(self):
        with patch.object(warp_mod, "_run", return_value=_fake_completed(TRACE_BODY)):
            colo, loc, warp_on = warp_mod._fetch_trace_meta()
        self.assertEqual((colo, loc, warp_on), ("DME", "RU", True))

    def test_warp_off(self):
        body = TRACE_BODY.replace("warp=on", "warp=off")
        with patch.object(warp_mod, "_run", return_value=_fake_completed(body)):
            colo, loc, warp_on = warp_mod._fetch_trace_meta()
        self.assertEqual((colo, loc, warp_on), ("DME", "RU", False))

    def test_curl_fail(self):
        with patch.object(warp_mod, "_run", return_value=_fake_completed("", returncode=28)):
            self.assertEqual(warp_mod._fetch_trace_meta(), (None, None, False))


# ═════════════════════════════════════════════════════════════════════════
#  8-9. чёрный список colo + безопасный state
# ═════════════════════════════════════════════════════════════════════════
class TestColoBlacklistAndState(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state_file = Path(self.tmp.name) / "state.json"
        self.state_file.write_text(json.dumps({"xray_uuid": "do-not-touch"}))
        self.core = MagicMock()
        self.core.STATE_FILE = self.state_file
        self.patches = [
            patch.object(warp_mod, "_core_module", return_value=self.core),
            patch.object(warp_mod, "_ensure_state_file", return_value=True),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def test_default_blacklist(self):
        self.assertEqual(warp_mod._colo_blacklist(), ["DME"])

    def test_state_override(self):
        self.state_file.write_text(json.dumps(
            {"xray_uuid": "x", "warp_colo_blacklist": ["dme", " ams "]}))
        self.assertEqual(warp_mod._colo_blacklist(), ["DME", "AMS"])

    def test_empty_means_disabled(self):
        self.state_file.write_text(json.dumps({"warp_colo_blacklist": []}))
        self.assertEqual(warp_mod._colo_blacklist(), [])

    def test_ext_state_save_keeps_foreign_keys(self):
        warp_mod._ext_state_save({"warp_exit_colo": "AMS"})
        data = json.loads(self.state_file.read_text())
        self.assertEqual(data["xray_uuid"], "do-not-touch")
        self.assertEqual(data["warp_exit_colo"], "AMS")

    def test_ext_state_save_skips_none(self):
        warp_mod._ext_state_save({"warp_exit_colo": None, "warp_exit_loc": "RU"})
        data = json.loads(self.state_file.read_text())
        self.assertNotIn("warp_exit_colo", data)
        self.assertEqual(data["warp_exit_loc"], "RU")


# ═════════════════════════════════════════════════════════════════════════
# 10-11. экспорт клиентских конфигов
# ═════════════════════════════════════════════════════════════════════════
WG_CONF_SAMPLE = """# wgcf
[Interface]
PrivateKey = 4OnO86dDLpqJ2U10ODwX3tarx6xlRGLfkmbSBtMgaHg=
Address = 172.16.0.2/32
Address = 2606:4700:110:8d87::/128
DNS = 1.1.1.1
MTU = 1280
Table = off

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0
Endpoint = 162.159.192.1:2408
PersistentKeepalive = 25
"""


class TestExportConfigs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fields = warp_mod._parse_wg_config_fields.__wrapped__ if hasattr(
            warp_mod._parse_wg_config_fields, "__wrapped__") else None
        # _parse_wg_config_fields читает WG_CONFIG — подменяем на tmp-файл.
        self.wg_path = Path(self.tmp.name) / "wg-warp.conf"
        self.wg_path.write_text(WG_CONF_SAMPLE)
        self.patches = [patch.object(warp_mod, "WG_CONFIG", self.wg_path)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def _fields(self):
        return warp_mod._parse_wg_config_fields()

    def test_parse_fields(self):
        f = self._fields()
        self.assertEqual(f["private_key"], "4OnO86dDLpqJ2U10ODwX3tarx6xlRGLfkmbSBtMgaHg=")
        self.assertEqual(f["public_key"], "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
        self.assertEqual(f["endpoint"], "162.159.192.1:2408")
        self.assertEqual(f["mtu"], "1280")
        self.assertIn("172.16.0.2/32", f["address"])

    def test_parse_no_keys_returns_none(self):
        self.wg_path.write_text("[Interface]\nAddress = 1.2.3.4/32\n")
        self.assertIsNone(self._fields())

    def test_parse_comma_address_line(self):
        # wg-quick допускает «Address = v4/32, v6/128» одной строкой —
        # _warp_addr_v4_v6 режет и запятые (иначе v4 терялся, а проба
        # wg-scout считала конфиг IPv6-only)
        self.wg_path.write_text(WG_CONF_SAMPLE.replace(
            "Address = 172.16.0.2/32\nAddress = 2606:4700:110:8d87::/128",
            "Address = 172.16.0.2/32, 2606:4700:110:8d87::/128"))
        f = self._fields()
        v4, v6 = warp_mod._warp_addr_v4_v6(f)
        self.assertEqual(v4, "172.16.0.2")
        self.assertEqual(v6, "2606:4700:110:8d87::")
        # экспорт из comma-конфига тоже не теряет адреса
        conf = warp_mod._export_warp_wg_conf(f)
        self.assertIn("Address = 172.16.0.2/32", conf)
        self.assertIn("Address = 2606:4700:110:8d87::/128", conf)

    def test_wg_conf_export(self):
        conf = warp_mod._export_warp_wg_conf(self._fields())
        self.assertIn("[Interface]", conf)
        self.assertIn("Address = 172.16.0.2/32", conf)
        self.assertIn("Address = 2606:4700:110:8d87::/128", conf)
        self.assertIn("PrivateKey = 4OnO86", conf)
        self.assertIn("DNS = 1.1.1.1, 1.0.0.1", conf)
        self.assertIn("Endpoint = 162.159.192.1:2408", conf)
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", conf)
        self.assertIn("MTU = 1280", conf)
        self.assertIn("PersistentKeepalive = 25", conf)
        # Table = off — серверная опция wg-quick, клиенту не нужна:
        self.assertNotIn("Table", conf)

    def test_wg_conf_export_v4_only(self):
        f = self._fields()
        f["address"] = ["172.16.0.2/32"]
        conf = warp_mod._export_warp_wg_conf(f)
        self.assertNotIn("::/0", conf)
        self.assertNotIn("::/128", conf)

    def test_mihomo_proxy_structure(self):
        p = warp_mod._export_warp_mihomo_proxy(self._fields())
        self.assertEqual(p["name"], "CF-WARP")
        self.assertEqual(p["type"], "wireguard")
        self.assertEqual(p["ip"], "172.16.0.2")
        self.assertEqual(p["mtu"], 1280)
        self.assertTrue(p["udp"])
        self.assertTrue(p["remote-dns-resolve"])
        self.assertEqual(p["dns"], ["1.1.1.1", "1.0.0.1"])
        peer = p["peers"][0]
        self.assertEqual(peer["server"], "162.159.192.1")
        self.assertEqual(peer["port"], 2408)
        self.assertEqual(peer["public-key"], "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
        self.assertEqual(peer["allowed-ips"], ["0.0.0.0/0"])
        self.assertEqual(peer["persistent-keepalive"], 25)

    def test_mihomo_yaml_fragment(self):
        p = warp_mod._export_warp_mihomo_proxy(self._fields())
        y = warp_mod._export_warp_mihomo_yaml(p)
        self.assertTrue(y.startswith("proxies:"))
        self.assertIn('name: "CF-WARP"', y)          # имя в кавычках (YAML warpscout)
        self.assertIn("type: wireguard", y)
        self.assertIn("private-key: 4OnO86", y)
        self.assertIn("ip: 172.16.0.2", y)
        self.assertIn("server: 162.159.192.1", y)
        self.assertIn("port: 2408", y)
        self.assertIn("allowed-ips: ['0.0.0.0/0']", y)
        self.assertIn("persistent-keepalive: 25", y)
        self.assertIn("mtu: 1280", y)
        self.assertIn("udp: true", y)
        self.assertIn("dns: ['1.1.1.1', '1.0.0.1']", y)

    def test_mihomo_json_parses_and_matches(self):
        p = warp_mod._export_warp_mihomo_proxy(self._fields())
        j = json.loads(warp_mod._export_warp_mihomo_json([p]))
        self.assertEqual(j[0], p)

    def test_mihomo_domain_endpoint(self):
        f = self._fields()
        f["endpoint"] = "engage.cloudflareclient.com:2408"
        p = warp_mod._export_warp_mihomo_proxy(f)
        self.assertEqual(p["peers"][0]["server"], "engage.cloudflareclient.com")
        self.assertEqual(p["peers"][0]["port"], 2408)
        # домен в YAML — валиден без кавычек (как netip-хост у warpscout)
        y = warp_mod._export_warp_mihomo_yaml(p)
        self.assertIn("server: engage.cloudflareclient.com", y)

    def test_mtu_default_when_absent(self):
        f = self._fields()
        f["mtu"] = None
        p = warp_mod._export_warp_mihomo_proxy(f)
        self.assertEqual(p["mtu"], 1280)


# ═════════════════════════════════════════════════════════════════════════
# 12. telemt watchdog — частота MTProto-пробы
# ═════════════════════════════════════════════════════════════════════════
class TestTelemtProbeWatchdog(unittest.TestCase):
    def _patch_state(self, state: dict):
        holder = {"state": state, "saved": {}}

        def fake_load():
            return dict(holder["state"])

        def fake_save(new_state):
            holder["saved"] = dict(new_state)
            holder["state"].update(new_state)

        return holder, patch.object(telemt_mod, "_state_load", side_effect=fake_load), \
            patch.object(telemt_mod, "_state_save", side_effect=fake_save)

    def test_probe_skipped_when_recent(self):
        holder, load, save = self._patch_state({"enabled": True, "last_tg_probe_ts": 999_999_999_999})
        probe = MagicMock()
        with load, save, patch.object(wtp, "probe_all_dcs", probe):
            telemt_mod._tg_probe_watchdog()
        probe.assert_not_called()

    def test_probe_runs_when_due_and_writes_state(self):
        holder, load, save = self._patch_state({"enabled": True})
        res = {"ok": True, "warp_up": True, "reached_names": ["DC1"],
               "missing_names": [], "worst_rtt_ms": 84.0}
        with load, save, \
             patch.object(wtp, "probe_all_dcs", return_value=res), \
             patch.object(telemt_mod, "_log") as log:
            telemt_mod._tg_probe_watchdog()
        self.assertIn("last_tg_probe_ts", holder["saved"])
        self.assertIn("5/5", holder["saved"]["last_tg_status"])
        log.assert_called_once()

    def test_probe_failure_logs_warn_not_crash(self):
        holder, load, save = self._patch_state({"enabled": True})
        with load, save, \
             patch.object(wtp, "probe_all_dcs", side_effect=OSError("net down")), \
             patch.object(telemt_mod, "_log") as log:
            telemt_mod._tg_probe_watchdog()  # не должно поднять исключение
        self.assertTrue(any("ошибка пробы" in str(c) for c in log.call_args_list))


if __name__ == "__main__":
    unittest.main()
