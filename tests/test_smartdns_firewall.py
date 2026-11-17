#!/usr/bin/env python3
"""
tests/test_smartdns_firewall.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/smartdns_firewall.py — firewall-слоя
SmartDNS-ноды (режимы standalone/companion).

Покрывает (КРИТИЧНЫЕ разводки companion-режима):
  1. NAT PREROUTING 443-редиректы: companion — каждое REDIRECT скоуплено
     «-d <bind_ip>» (VLESS/REALITY Химеры на основном IP жив); standalone —
     wildcard (паритет bash).
  2. INPUT DROP-правила: companion — порты 9443/9444/внутренние скоуплены
     на bind_ip (9443 = User Portal Химеры, 9444 = Subscription Химеры на
     основном IP продолжают работать); standalone — глобальные.
  3. Правила 853 скоуплены на bind_ip в companion (AGH-DoT Химеры не душим).
  4. UFW: companion — только per-IP allow (никаких --force enable и 443);
     standalone — глобальные allow + --force enable (паритет bash).
  5. Whitelist: валидация IPv4/IPv6 (паритет bash-валидаторов).
  6. render_firewall_apply_script — self-contained runtime-скрипт с
     пререндеренными правилами + ipset create/restore.
  7. Ватчеры: tail -F нужного лога, ipset add timeout 86400, фильтр
     приватных адресов.
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import smartdns_firewall as fw  # noqa: E402
from chimera.modules import smartdns_stack as st  # noqa: E402

CFG_COMPANION = {
    "mode": "companion", "bind_ip": "203.0.113.7",
    "server_ipv4": "198.51.100.2", "whitelist_enabled": "false",
    "whitelist_mode": "shared",
}
CFG_COMPANION_WL = dict(CFG_COMPANION, whitelist_enabled="true",
                        whitelist_mode="separate")
CFG_STANDALONE = {
    "mode": "standalone", "bind_ip": None, "server_ipv4": "198.51.100.2",
    "whitelist_enabled": "false", "whitelist_mode": "shared",
}


def _cmds(rules):
    return [" ".join(str(x) for x in r) for r in rules]


class TestNatScoping(unittest.TestCase):
    def test_companion_nat_redirects_scoped_to_bind_ip(self):
        rules = _cmds(fw.build_iptables_rules(CFG_COMPANION)["nat_v4"])
        redirects = [r for r in rules if "REDIRECT" in r]
        self.assertTrue(redirects)
        for r in redirects:
            self.assertIn("-d 203.0.113.7", r)
            self.assertNotIn("198.51.100.2 -d", r)

    def test_standalone_nat_redirects_wildcard(self):
        rules = _cmds(fw.build_iptables_rules(CFG_STANDALONE)["nat_v4"])
        redirects = [r for r in rules if "REDIRECT" in r]
        self.assertTrue(redirects)
        for r in redirects:
            self.assertNotIn(" -d ", r)

    def test_nat_whitelist_before_catchall(self):
        rules = fw.build_iptables_rules(CFG_COMPANION)["nat_v4"]
        idx_wl = next(i for i, r in enumerate(rules)
                      if "smartdns_clients" in _cmds([r])[0]
                      and "REDIRECT" in _cmds([r])[0])
        idx_catchall = next(i for i, r in enumerate(rules)
                            if _cmds([r])[0].endswith(
                                f"--to-ports {st.PORT_WEB}"))
        self.assertLess(idx_wl, idx_catchall)

    def test_separate_whitelist_second_redirect(self):
        rules = _cmds(fw.build_iptables_rules(CFG_COMPANION_WL)["nat_v4"])
        self.assertEqual(
            len([r for r in rules if "dot_clients" in r and "REDIRECT" in r]),
            1)


class TestInputScoping(unittest.TestCase):
    def test_companion_drops_scoped_away_from_chimera_ports(self):
        rules = _cmds(fw.build_iptables_rules(CFG_COMPANION)["in_v4"])
        # 9443 (User Portal Химеры) — отдельное DROP-правило, скоуплено
        scoped = [r for r in rules if f"--dport {st.PORT_WEB}" in r
                  and "DROP" in r]
        self.assertTrue(scoped, f"нет DROP для {st.PORT_WEB}")
        for r in scoped:
            self.assertIn("-d 203.0.113.7", r)
        # 9444 (Subscription Химеры) — внутри мультипортового DROP, скоуплен
        multi = [r for r in rules if "multiport" in r]
        self.assertTrue(multi)
        for r in multi:
            self.assertIn(f"{st.PORT_STEALTH},", r)   # 9444 в списке dports
            self.assertIn("-d 203.0.113.7", r)

    def test_standalone_drops_global(self):
        rules = _cmds(fw.build_iptables_rules(CFG_STANDALONE)["in_v4"])
        drops = [r for r in rules if "DROP" in r]
        self.assertTrue(drops)
        for r in drops:
            self.assertNotIn("203.0.113.7", r)

    def test_companion_dot_rules_scoped(self):
        for cfg in (CFG_COMPANION, CFG_COMPANION_WL):
            rules = _cmds(fw.build_iptables_rules(cfg)["in_v4"])
            dot = [r for r in rules if f"--dport {st.PORT_DOT}" in r]
            self.assertTrue(dot)
            for r in dot:
                self.assertIn("-d 203.0.113.7", r)

    def test_loopback_accept_present(self):
        rules = _cmds(fw.build_iptables_rules(CFG_COMPANION)["in_v4"])
        self.assertTrue(any("-i lo -j ACCEPT" in r for r in rules))
        # и стоит ДО мультипортового DROP (внутренние сервисы ходят по lo)
        idx_lo = next(i for i, r in enumerate(rules) if "-i lo" in r)
        idx_multi = next(i for i, r in enumerate(rules) if "multiport" in r)
        self.assertLess(idx_lo, idx_multi)

    def test_ipv6_rules_present(self):
        rules = fw.build_iptables_rules(CFG_COMPANION)
        self.assertTrue(rules["nat_v6"])
        self.assertTrue(rules["in_v6"])

    def test_output_rules_only_with_uid(self):
        rules = fw.build_iptables_rules(CFG_COMPANION)
        self.assertEqual(rules["out_v4"], [])       # uid=0 — заглушка
        with_uid = fw.build_iptables_rules(CFG_COMPANION, xray_uid=4242)
        self.assertTrue(with_uid["out_v4"])
        self.assertTrue(any("--uid-owner 4242" in c
                            for c in _cmds(with_uid["out_v4"])))


class TestUfw(unittest.TestCase):
    def test_companion_per_ip_only(self):
        cmds = _cmds(fw.build_ufw_commands(CFG_COMPANION))
        self.assertTrue(cmds)
        for c in cmds:
            self.assertIn("to 203.0.113.7", c)
            self.assertNotIn("--force", c)
            self.assertNotIn(" 443", c)     # 443 основного IP — Химеры
        for port in (80, st.PORT_DOT, st.PORT_DOH, st.PORT_WEB):
            self.assertTrue(any(f"port {port}" in c for c in cmds), port)

    def test_standalone_global_with_enable(self):
        cmds = _cmds(fw.build_ufw_commands(CFG_STANDALONE))
        self.assertTrue(any("--force enable" in c for c in cmds))
        self.assertTrue(any("443/tcp" in c for c in cmds))
        self.assertTrue(any("80/tcp" in c for c in cmds))
        self.assertTrue(any(f"{st.PORT_DOT}/tcp" in c for c in cmds))


class TestWhitelistValidation(unittest.TestCase):
    def test_valid_ips(self):
        self.assertEqual(fw._valid_ip("1.2.3.4"), "v4")
        self.assertEqual(fw._valid_ip("::1"), "v6")
        self.assertEqual(fw._valid_ip("2001:db8::5"), "v6")
        self.assertEqual(fw._valid_ip("fd00::1"), "v6")

    def test_invalid_ips(self):
        for bad in ("1.2.3.4/32", "999.1.1.1", "1.2.3", "", "abc",
                    "1.2.3.4:80"):
            self.assertEqual(fw._valid_ip(bad), "", bad)


class TestRuntimeScripts(unittest.TestCase):
    def test_firewall_apply_script_content(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            with patch_bin_dir(td):
                path = fw.render_firewall_apply_script(CFG_COMPANION)
                text = path.read_text()
                self.assertIn("#!/usr/bin/env python3", text)
                self.assertIn("nat_v4", text)          # пререндеренные правила
                self.assertIn("smartdns_clients", text)
                self.assertIn("ipset", text)
                # скоуп доехал в runtime-скрипт (JSON-список: элементы раздельно)
                self.assertIn('"-d"', text)
                self.assertIn('"203.0.113.7"', text)
                self.assertNotIn("from chimera", text)  # self-contained

    def test_watcher_scripts_content(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            with patch_bin_dir(td):
                doh, dot = fw.render_watcher_scripts()
                doh_t, dot_t = doh.read_text(), dot.read_text()
                for text, log in ((doh_t, "/var/log/nginx/smartdns-auth.log"),
                                  (dot_t, "xray/access.log")):
                    self.assertIn("#!/usr/bin/env python3", text)
                    self.assertIn("tail", text)
                    self.assertIn("timeout", text)       # ipset add ttl
                    self.assertIn("86400", text)
                    self.assertNotIn("from chimera", text)  # self-contained
                self.assertIn("web-auth-verified", doh_t)
                self.assertIn("dot-in", dot_t)
                self.assertIn("fe80:", doh_t)            # приватные скипаются
                # синтаксис сгенерированных скриптов валиден
                compile(doh_t, str(doh), "exec")
                compile(dot_t, str(dot), "exec")


class patch_bin_dir:
    """Подменяет BIN_DIR/LOG_DIR/STATE_DIR/IPSET_SAVE на временные каталоги
    (и в smartdns_stack, и в ССЫЛКИ smartdns_firewall — он импортирует
    константы по значению)."""

    def __init__(self, td: str):
        self.td = Path(td)

    def __enter__(self):
        from chimera.modules import smartdns_stack as _st
        from chimera.modules import smartdns_firewall as _fw
        self._saved = {m: {k: getattr(m, k) for k in
                           ("BIN_DIR", "LOG_DIR", "STATE_DIR",
                            "IPSET_SAVE_FILE")}
                       for m in (_st, _fw)}
        _st.BIN_DIR = self.td / "bin"
        _st.LOG_DIR = self.td / "log"
        _st.STATE_DIR = self.td / "state"
        _st.IPSET_SAVE_FILE = self.td / "state" / "ipset.save"
        _fw.BIN_DIR = _st.BIN_DIR
        _fw.LOG_DIR = _st.LOG_DIR
        _fw.STATE_DIR = _st.STATE_DIR
        _fw.IPSET_SAVE_FILE = _st.IPSET_SAVE_FILE
        return self

    def __exit__(self, *a):
        from chimera.modules import smartdns_stack as _st
        from chimera.modules import smartdns_firewall as _fw
        for m, saved in self._saved.items():
            for k, v in saved.items():
                setattr(m, k, v)


if __name__ == "__main__":
    unittest.main(verbosity=2)
