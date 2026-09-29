#!/usr/bin/env python3
"""
tests/test_agh_probe.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/agh_probe.py — health-check локального
AdGuardHome и безопасное переключение DNS-пути Xray (стек
Xray → AGH:53 → DNSCrypt:5300 → интернет).

Покрывает:
  1. agh_service_active — парсинг systemctl is-active (обе формы юнита).
  2. agh_owns_dns53 — парсинг ss -ulnp (AGH на :53; отсечка :5300 и
     127.0.0.53:53 systemd-resolved).
  3. agh_probe_resolve — построение DNS-запроса / валидация ответа /
     таймаут (mock socket).
  4. dns53_redirect_state / remove / restore — парсинг и зеркальные
     спецификации iptables-правил.
  5. agh_dns_available — полный flow: сервис → порт → redirect
     (снятие + rollback при провале пробы) → проба резолва.
  6. agh_ensure_running — autostart-ветка для emergency_repair.

Все внешние вызовы мокаются — тесты не трогают реальную систему.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import agh_probe
from chimera.modules.agh_probe import (
    AGH_DNS_ADDR, AGH_DNS_PORT,
    agh_dns_available, agh_ensure_running, agh_service_active,
    agh_owns_dns53, agh_probe_resolve,
    dns53_redirect_state, dns53_redirect_remove, dns53_redirect_restore,
    _build_dns_query, _parse_dns_response,
)


def _completed(rc=0, stdout=""):
    m = MagicMock()
    m.returncode = rc
    m.stdout = stdout
    m.stderr = ""
    return m


def _mock_run_factory(cmd_to_result: dict, default=None):
    """run(cmd, capture=..., check=...) → CompletedProcess-подобный mock."""
    def _run(cmd, capture=False, check=False, quiet=True, **kw):
        for prefix, result in cmd_to_result.items():
            if tuple(cmd[:len(prefix)]) == tuple(prefix):
                return result
        return default if default is not None else _completed(0, "")
    return _run


# ─── Фикстуры вывода ss -ulnp ────────────────────────────────────────────────
SS_AGH_ON_53 = (
    "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
    "UNCONN 0      0         127.0.0.54:53        0.0.0.0:*    users:((\"systemd-resolve\",pid=1,fd=16))\n"
    "UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*    users:((\"systemd-resolve\",pid=1,fd=14))\n"
    "UNCONN 0      0     176.123.162.42:53         0.0.0.0:*    users:((\"AdGuardHome\",pid=3526174,fd=13))\n"
    "UNCONN 0      0         127.0.0.1:53          0.0.0.0:*    users:((\"AdGuardHome\",pid=3526174,fd=6))\n"
)

SS_DNSCRYPT_ON_5300 = (
    "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
    "UNCONN 0      0         127.0.0.1:5300        0.0.0.0:*    users:((\"dnscrypt-proxy\",pid=312626,fd=5))\n"
)

SS_AGH_ON_5300 = (
    "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
    "UNCONN 0      0         127.0.0.1:5300        0.0.0.0:*    users:((\"AdGuardHome\",pid=1,fd=5))\n"
)

SS_RESOLVED_ONLY = (
    "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
    "UNCONN 0      0         127.0.0.53%lo:53       0.0.0.0:*    users:((\"systemd-resolve\",pid=1,fd=14))\n"
)


class TestServiceActive(unittest.TestCase):
    def test_active_lowercase_unit(self):
        run = _mock_run_factory({("systemctl", "is-active", "adguardhome"):
                                  _completed(0, "active\n")})
        self.assertTrue(agh_service_active(run))

    def test_active_camelcase_unit(self):
        run = _mock_run_factory({("systemctl", "is-active", "AdGuardHome"):
                                  _completed(0, "active\n")})
        self.assertTrue(agh_service_active(run))

    def test_inactive(self):
        run = _mock_run_factory({("systemctl", "is-active", "adguardhome"):
                                  _completed(3, "inactive\n")})
        self.assertFalse(agh_service_active(run))

    def test_not_installed(self):
        # systemctl is-active несуществующего юнита: rc=3, "inactive"/"unknown"
        run = _mock_run_factory({("systemctl", "is-active", "adguardhome"):
                                  _completed(3, "inactive\n"),
                                 ("systemctl", "is-active", "AdGuardHome"):
                                  _completed(3, "inactive\n")})
        self.assertFalse(agh_service_active(run))

    def test_empty_stdout_no_crash(self):
        run = _mock_run_factory({}, default=_completed(1, ""))
        self.assertFalse(agh_service_active(run))


class TestOwnsDns53(unittest.TestCase):
    def test_agh_holds_53(self):
        run = _mock_run_factory({("ss", "-ulnp"): _completed(0, SS_AGH_ON_53)})
        self.assertTrue(agh_owns_dns53(run))

    def test_dnscrypt_on_5300_not_agh(self):
        run = _mock_run_factory({("ss", "-ulnp"):
                                  _completed(0, SS_DNSCRYPT_ON_5300)})
        self.assertFalse(agh_owns_dns53(run))

    def test_agh_on_5300_not_53(self):
        # AGH есть, но сидит на 5300 (не стандарт) — :53 ему не принадлежит
        run = _mock_run_factory({("ss", "-ulnp"): _completed(0, SS_AGH_ON_5300)})
        self.assertFalse(agh_owns_dns53(run))

    def test_systemd_resolved_only(self):
        run = _mock_run_factory({("ss", "-ulnp"):
                                  _completed(0, SS_RESOLVED_ONLY)})
        self.assertFalse(agh_owns_dns53(run))

    def test_port_5300_not_matched_as_53(self):
        # регресс: 127.0.0.1:5300 не должен матчиться как :53
        run = _mock_run_factory({("ss", "-ulnp"):
                                  _completed(0, SS_AGH_ON_53.replace(
                                      "127.0.0.1:53", "127.0.0.1:5300"))})
        self.assertFalse(agh_owns_dns53(run))

    def test_ss_fails(self):
        run = _mock_run_factory({("ss", "-ulnp"): _completed(1, "")})
        self.assertFalse(agh_owns_dns53(run))


class TestDnsWire(unittest.TestCase):
    def test_build_query_structure(self):
        q = _build_dns_query("www.example.com", 0x1234)
        # header(12) + qname(4+8+4+1=17: www.example.com + root) + qtype/qclass(4)
        self.assertEqual(len(q), 12 + 17 + 4)
        txid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", q[:12])
        self.assertEqual(txid, 0x1234)
        self.assertEqual(flags, 0x0100)
        self.assertEqual(qd, 1)
        self.assertEqual(an, 0)
        self.assertIn(b"\x03www\x07example\x03com\x00", q)

    def test_parse_valid_response(self):
        q = _build_dns_query("www.example.com", 0xBEEF)
        # Минимальный валидный ответ: QR=1, rcode=0, ANCOUNT=1, копия question
        question = q[12:]
        header = struct.pack(">HHHHHH", 0xBEEF, 0x8180, 1, 1, 0, 0)
        # answer: ptr на qname(0xC00C) A IN TTL=60 RDLEN=4 93.184.216.34
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
        resp = header + question + answer
        self.assertTrue(_parse_dns_response(resp, 0xBEEF))

    def test_parse_txid_mismatch(self):
        q = _build_dns_query("www.example.com", 1)
        header = struct.pack(">HHHHHH", 2, 0x8180, 1, 1, 0, 0)
        resp = header + q[12:]
        self.assertFalse(_parse_dns_response(resp, 1))

    def test_parse_servfail(self):
        q = _build_dns_query("www.example.com", 7)
        header = struct.pack(">HHHHHH", 7, 0x8182, 1, 0, 0, 0)  # rcode=2
        resp = header + q[12:]
        self.assertFalse(_parse_dns_response(resp, 7))

    def test_parse_no_answers(self):
        q = _build_dns_query("www.example.com", 7)
        header = struct.pack(">HHHHHH", 7, 0x8180, 1, 0, 0, 0)  # ANCOUNT=0
        resp = header + q[12:]
        self.assertFalse(_parse_dns_response(resp, 7))

    def test_parse_query_not_response(self):
        q = _build_dns_query("www.example.com", 7)
        self.assertFalse(_parse_dns_response(q, 7))  # QR=0

    def test_parse_short_garbage(self):
        self.assertFalse(_parse_dns_response(b"\x00\x01\x02", 1))


class TestProbeResolve(unittest.TestCase):
    def test_probe_ok(self):
        def fake_q(domain, txid):
            question = _build_dns_query(domain, txid)[12:]
            header = struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0)
            answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([1, 2, 3, 4])
            return header + question + answer

        with patch.object(agh_probe, "socket") as mock_socket:
            sock = MagicMock()
            sock.recvfrom.return_value = (fake_q("www.example.com", 42), ("127.0.0.1", 53))
            mock_socket.socket.return_value = sock
            with patch.object(agh_probe.random, "randint", return_value=42):
                ok, note = agh_probe_resolve()
        self.assertTrue(ok)
        self.assertIn("www.example.com", note)

    def test_probe_timeout(self):
        import socket as real_socket
        with patch.object(agh_probe, "socket") as mock_socket:
            sock = MagicMock()
            sock.recvfrom.side_effect = real_socket.timeout("timed out")
            mock_socket.socket.return_value = sock
            ok, note = agh_probe_resolve(attempts=1, timeout=0.01)
        self.assertFalse(ok)
        self.assertIn("TimeoutError", note)


class TestRedirectRules(unittest.TestCase):
    IPT_OUT = (
        "Chain OUTPUT (policy ACCEPT)\n"
        "target     prot opt source     destination\n"
        "REDIRECT   udp  --  0.0.0.0/0  127.0.0.1  udp dpt:53 redir ports 5300\n"
        "REDIRECT   tcp  --  0.0.0.0/0  127.0.0.1  tcp dpt:53 redir ports 5300\n"
    )

    def test_state_parses_port(self):
        run = _mock_run_factory({("iptables", "-t", "nat", "-L", "OUTPUT", "-n"):
                                  _completed(0, self.IPT_OUT)})
        self.assertEqual(dns53_redirect_state(run), 5300)

    def test_state_none_when_absent(self):
        run = _mock_run_factory({("iptables", "-t", "nat", "-L", "OUTPUT", "-n"):
                                  _completed(0, "Chain OUTPUT (policy ACCEPT)\n")})
        self.assertIsNone(dns53_redirect_state(run))

    def test_state_none_on_error(self):
        run = _mock_run_factory({("iptables", "-t", "nat", "-L", "OUTPUT", "-n"):
                                  _completed(1, "")})
        self.assertIsNone(dns53_redirect_state(run))

    def test_remove_and_restore_specs(self):
        calls = []
        def run(cmd, capture=False, check=False, quiet=True, **kw):
            calls.append(cmd)
            return _completed(0, "")
        self.assertTrue(dns53_redirect_remove(run, 5300))
        self.assertTrue(dns53_redirect_restore(run, 5300))
        deletes = [c for c in calls if "-D" in c]
        appends = [c for c in calls if "-A" in c]
        self.assertEqual(len(deletes), 2)   # udp + tcp
        self.assertEqual(len(appends), 2)
        for c in calls:
            self.assertIn("127.0.0.1", c)
            self.assertIn("--to-ports", c)
            self.assertIn("chimera-dns-fix", c)  # совместимость с resolv_conf_fix


class TestAghDnsAvailable(unittest.TestCase):
    """Полный flow с моками шагов."""

    def _healthy_env(self):
        run = _mock_run_factory({
            ("systemctl", "is-active", "adguardhome"): _completed(0, "active\n"),
            ("ss", "-ulnp"): _completed(0, SS_AGH_ON_53),
            ("iptables", "-t", "nat", "-L", "OUTPUT", "-n"): _completed(
                0, "Chain OUTPUT (policy ACCEPT)\n"),  # redirect отсутствует
        })
        return run

    def test_all_healthy_redirect_absent(self):
        run = self._healthy_env()
        with patch.object(agh_probe, "agh_probe_resolve",
                          return_value=(True, "www.example.com → 1 ответ, 12 мс")):
            ok, reason = agh_dns_available(run=run)
        self.assertTrue(ok)
        self.assertIn("12 мс", reason)

    def test_redirect_removed_when_healthy(self):
        run = _mock_run_factory({
            ("systemctl", "is-active", "adguardhome"): _completed(0, "active\n"),
            ("ss", "-ulnp"): _completed(0, SS_AGH_ON_53),
            ("iptables", "-t", "nat", "-L", "OUTPUT", "-n"): _completed(
                0, TestRedirectRules.IPT_OUT),
        })
        cmds = []
        real_run = run
        def spy_run(cmd, **kw):
            cmds.append(cmd)
            return real_run(cmd, **kw)
        with patch.object(agh_probe, "agh_probe_resolve",
                          return_value=(True, "www.example.com → 1 ответ, 12 мс")):
            ok, _ = agh_dns_available(run=spy_run)
        self.assertTrue(ok)
        deletes = [c for c in cmds if "-D" in c]
        self.assertEqual(len(deletes), 2)  # redirect снят (udp+tcp)
        appends = [c for c in cmds if "-A" in c]
        self.assertEqual(len(appends), 0)  # и НЕ восстановлен

    def test_redirect_rolled_back_when_probe_fails(self):
        run = _mock_run_factory({
            ("systemctl", "is-active", "adguardhome"): _completed(0, "active\n"),
            ("ss", "-ulnp"): _completed(0, SS_AGH_ON_53),
            ("iptables", "-t", "nat", "-L", "OUTPUT", "-n"): _completed(
                0, TestRedirectRules.IPT_OUT),
        })
        cmds = []
        real_run = run
        def spy_run(cmd, **kw):
            cmds.append(cmd)
            return real_run(cmd, **kw)
        with patch.object(agh_probe, "agh_probe_resolve",
                          return_value=(False, "нет валидного ответа")):
            ok, reason = agh_dns_available(run=spy_run)
        self.assertFalse(ok)
        self.assertIn("не резолвит", reason)
        deletes = [c for c in cmds if "-D" in c]
        appends = [c for c in cmds if "-A" in c]
        self.assertEqual(len(deletes), 2)  # снят
        self.assertEqual(len(appends), 2)  # и восстановлен (rollback)

    def test_service_down(self):
        run = _mock_run_factory({
            ("systemctl", "is-active", "adguardhome"): _completed(3, "inactive\n"),
            ("systemctl", "is-active", "AdGuardHome"): _completed(3, "inactive\n"),
        })
        with patch.object(agh_probe, "agh_probe_resolve") as probe:
            ok, reason = agh_dns_available(run=run)
        self.assertFalse(ok)
        self.assertIn("не активен", reason)
        probe.assert_not_called()  # рано вышли — проба не тратится

    def test_port_not_owned(self):
        run = _mock_run_factory({
            ("systemctl", "is-active", "adguardhome"): _completed(0, "active\n"),
            ("ss", "-ulnp"): _completed(0, SS_DNSCRYPT_ON_5300),
        })
        with patch.object(agh_probe, "agh_probe_resolve") as probe:
            ok, reason = agh_dns_available(run=run)
        self.assertFalse(ok)
        self.assertIn("не принадлежит", reason)
        probe.assert_not_called()

    def test_autostart_path(self):
        # сервис неактивен, но unit существует и стартует
        state = {"started": False}
        def run(cmd, capture=False, check=False, quiet=True, **kw):
            key = tuple(cmd)
            if key == ("systemctl", "is-active", "adguardhome"):
                return _completed(0, "active\n" if state["started"] else "inactive\n")
            if key == ("systemctl", "is-active", "AdGuardHome"):
                return _completed(3, "inactive\n")
            if tuple(cmd[:2]) == ("systemctl", "start"):
                state["started"] = True
                return _completed(0, "")
            if key == ("ss", "-ulnp"):
                return _completed(0, SS_AGH_ON_53)
            return _completed(0, "")
        with patch.object(agh_probe, "agh_probe_resolve",
                          return_value=(True, "www.example.com → 1 ответ, 5 мс")):
            ok, reason = agh_dns_available(run=run, autostart=True)
        self.assertTrue(ok)

    def test_autostart_not_installed(self):
        def run(cmd, capture=False, check=False, quiet=True, **kw):
            if tuple(cmd[:2]) == ("systemctl", "is-active"):
                return _completed(3, "inactive\n")
            if tuple(cmd[:2]) == ("systemctl", "start"):
                return _completed(5, "Unit adguardhome.service not found.")
            return _completed(0, "")
        ok, reason = agh_dns_available(run=run, autostart=True)
        self.assertFalse(ok)
        self.assertIn("не установлен", reason)

    def test_no_autostart_by_default(self):
        calls = []
        def run(cmd, capture=False, check=False, quiet=True, **kw):
            calls.append(tuple(cmd[:2]))
            if tuple(cmd[:2]) == ("systemctl", "is-active"):
                return _completed(3, "inactive\n")
            return _completed(0, "")
        ok, reason = agh_dns_available(run=run)
        self.assertFalse(ok)
        self.assertNotIn(("systemctl", "start"), calls)  # ничего не поднимали


class TestEnsureRunning(unittest.TestCase):
    def test_already_active(self):
        run = _mock_run_factory({
            ("systemctl", "is-active", "adguardhome"): _completed(0, "active\n"),
        })
        ok, note = agh_ensure_running(run)
        self.assertTrue(ok)
        self.assertIn("уже активен", note)

    def test_start_success(self):
        state = {"started": False}
        def run(cmd, capture=False, check=False, quiet=True, **kw):
            key = tuple(cmd)
            if key == ("systemctl", "is-active", "adguardhome"):
                return _completed(0, "active\n" if state["started"] else "inactive\n")
            if key == ("systemctl", "is-active", "AdGuardHome"):
                return _completed(3, "inactive\n")
            if tuple(cmd[:2]) == ("systemctl", "start"):
                state["started"] = True
                return _completed(0, "")
            return _completed(0, "")
        ok, note = agh_ensure_running(run, wait=1)
        self.assertTrue(ok)
        self.assertIn("запущен", note)

    def test_not_installed(self):
        def run(cmd, capture=False, check=False, quiet=True, **kw):
            if tuple(cmd[:2]) == ("systemctl", "start"):
                return _completed(5, "not found")
            return _completed(3, "inactive\n")
        ok, note = agh_ensure_running(run, wait=0)
        self.assertFalse(ok)
        self.assertIn("не установлен", note)


class TestGeneratorIntegration(unittest.TestCase):
    """Генераторы xray-конфига переключают dns_servers[0] на AGH:53.

    Проверяем через прямой вызов _make_dns_servers-подобной логики нельзя —
    она inline в генераторах. Вместо этого верифицируем, что оба модуля
    импортируют agh_dns_available и вызывают его в теле генераторов
    (гарантия wiring'а без полного mock'а _core на ~8000 строк).
    """
    def test_xray_imports_and_calls(self):
        import chimera.modules.xray_install as xi
        self.assertIs(xi.agh_dns_available, agh_dns_available)
        src = Path(xi.__file__).read_text(encoding="utf-8")
        # все три генератора (REALITY, xHTTP, xHTTP+REALITY) содержат
        # вызов + AGH-ветку (dda9e54 добавил generate_xray_config_xhttp_reality)
        self.assertEqual(src.count("agh_dns_available(run=_run"), 3)
        self.assertEqual(src.count('{"address": "127.0.0.1", "port": 53,'), 3)

    def test_chain_nodes_imports_and_calls(self):
        import chimera.modules.chain_nodes as cn
        self.assertIs(cn.agh_dns_available, agh_dns_available)
        src = Path(cn.__file__).read_text(encoding="utf-8")
        # оба chain-генератора (single и multi)
        self.assertEqual(src.count("agh_dns_available(run=_run"), 2)
        self.assertEqual(src.count('{"address": "127.0.0.1", "port": 53,'), 2)

    def test_emergency_repair_lifts_agh_before_regen(self):
        import chimera.modules.emergency_repair as er
        src = Path(er.__file__).read_text(encoding="utf-8")
        agh_pos = src.find("agh_ensure_running(_run)")
        regen_pos = src.find("_need_regen = (")
        self.assertGreater(agh_pos, 0, "emergency_repair должен вызывать agh_ensure_running")
        self.assertGreater(regen_pos, 0)
        self.assertLess(agh_pos, regen_pos,
                        "AGH поднимается ДО пересборки xray-конфига")

    def test_resolv_conf_fix_agh_guard(self):
        import chimera.modules.resolv_conf_fix as rcf
        src = Path(rcf.__file__).read_text(encoding="utf-8")
        # diagnose гоняет живую пробу при AGH на :53, fix-flow гейтится
        # agh_resolves и имеет ветку обхода сломанного AGH
        self.assertIn('agh_ok, agh_note = agh_probe_resolve()', src)
        self.assertIn('if agh_serving and agh_resolves:', src)
        self.assertIn('elif agh_serving:', src)
        self.assertIn('and result.get("agh_resolves")', src)
        self.assertIn('agh_probe_resolve', src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
