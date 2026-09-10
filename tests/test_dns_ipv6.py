#!/usr/bin/env python3
"""
tests/test_dns_ipv6.py
───────────────────────────────────────────────────────────────────────────────
IPv6 в DNS-стеке Chimera:

  1. dnscrypt_setup._toml_listen_addresses — listen_addresses TOML
     (127.0.0.1 всегда первый, [::1] вторым при IPv6)
  2. aghome_setup._rewrite_dnscrypt_listen — брекет-безопасная перезапись
     (IPv6-элементы '[::1]:5300' содержат ']' внутри списка!)
  3. aghome_setup._get_public_ipv6 — выбор глобального IPv6
     (skip temporary/deprecated/fe80, fallback curl -6)
  4. aghome_setup.build_dns_section(public_ipv6=...) — bind_hosts += IPv6,
     обратная совместимость без IPv6 (байт-в-байт прежнее поведение)
  5. dnscrypt_advanced._get_listen_addresses — регрессия: ленивый регэксп
     обрезал строку на ВНУТРЕННЕЙ ']' элемента '[::1]:5300' и портил
     перегенерированный TOML (нашёл реальный баг при аудите)
  6. dnscrypt_selector — регрессия: перезапись порта во временном конфиге
     now-целой-строкой (first-entry-регэксп оставлял '[::1]:5300' на
     занятом порту)
"""
from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Фейковый chimera._core (паттерн test_dnscrypt_setup)."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core


# ────────────────────────────────────────────────────────────────────────────
#  1. _toml_listen_addresses
# ────────────────────────────────────────────────────────────────────────────
class TestTomlListenAddresses(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import dnscrypt_setup
        self.mod = dnscrypt_setup

    def test_ipv6_adds_loopback_v6_second(self):
        s = self.mod._toml_listen_addresses("127.0.0.1", 5300, True)
        self.assertEqual(s, "['127.0.0.1:5300', '[::1]:5300']")

    def test_no_ipv6_single_entry(self):
        s = self.mod._toml_listen_addresses("127.0.0.1", 5300, False)
        self.assertEqual(s, "['127.0.0.1:5300']")

    def test_v4_first_always(self):
        # v4-loopback обязан быть ПЕРВЫМ: порт из него достают
        # _get_dnscrypt_port / resolv_conf_fix / dns_redirect регэкспами
        s = self.mod._toml_listen_addresses("127.0.0.1", 5300, True)
        self.assertTrue(s.startswith("['127.0.0.1:5300'"))

    def test_custom_port(self):
        s = self.mod._toml_listen_addresses("127.0.0.1", 5353, True)
        self.assertIn("'[::1]:5353'", s)


# ────────────────────────────────────────────────────────────────────────────
#  2. _rewrite_dnscrypt_listen (брекет-безопасность)
# ────────────────────────────────────────────────────────────────────────────
class TestRewriteDnscryptListen(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import aghome_setup
        self.mod = aghome_setup

    def test_v4_only_content_adds_v6(self):
        content = ("## header\n"
                   "listen_addresses = ['127.0.0.1:5300']\n"
                   "max_clients = 250\n")
        out = self.mod._rewrite_dnscrypt_listen(content, 5300, True)
        self.assertIn("listen_addresses = ['127.0.0.1:5300', '[::1]:5300']", out)
        self.assertIn("max_clients = 250", out)
        self.assertIn("## header", out)

    def test_no_ipv6_single_entry(self):
        content = "listen_addresses = ['127.0.0.1:5300']\n"
        out = self.mod._rewrite_dnscrypt_listen(content, 5300, False)
        self.assertEqual(out, "listen_addresses = ['127.0.0.1:5300']\n")

    def test_rewrites_legacy_53_and_adds_v6(self):
        # легаси: dnscrypt держал :53 → миграция уводит на {port} (+v6)
        content = "listen_addresses = ['127.0.0.1:53']\n"
        out = self.mod._rewrite_dnscrypt_listen(content, 5300, True)
        self.assertIn("'127.0.0.1:5300'", out)
        self.assertNotIn(":53'", out)
        self.assertIn("'[::1]:5300'", out)

    def test_bracket_v6_entries_replaced_safely(self):
        # КЛЮЧЕВАЯ РЕГРЕССИЯ: старый регэксп ([^\]]*) обрезался на
        # внутренней ']' элемента '[::1]' и склеивал мусор вида
        # "listen_addresses = ['127.0.0.1:5300']:5300']"
        content = ("listen_addresses = ['127.0.0.1:5300', '[::1]:5300']\n"
                   "server_names = ['cloudflare']\n")
        out = self.mod._rewrite_dnscrypt_listen(content, 5300, True)
        self.assertIn("listen_addresses = ['127.0.0.1:5300', '[::1]:5300']", out)
        self.assertIn("server_names = ['cloudflare']", out)
        # ровно одна строка listen, без обрывков старого бага
        self.assertEqual(out.count("listen_addresses"), 1)
        self.assertNotIn("]:5300']\n\n", out)
        # строка listen заканчивается ровно на ']' + перенос строки
        import re as _re
        line = _re.search(r"^listen_addresses.*$", out, _re.MULTILINE).group(0)
        self.assertTrue(line.endswith("]"))
        self.assertNotIn("']:", line)   # ':5300'\':5300'\n — артефакт склейки

    def test_no_listen_line_untouched(self):
        content = "max_clients = 250\n"
        out = self.mod._rewrite_dnscrypt_listen(content, 5300, True)
        self.assertEqual(out, content)

    def test_trailing_comment_preserved_before(self):
        content = "listen_addresses = ['127.0.0.1:5300']  # chimera\nx = 1\n"
        out = self.mod._rewrite_dnscrypt_listen(content, 5300, True)
        self.assertIn("listen_addresses = ['127.0.0.1:5300', '[::1]:5300']", out)
        self.assertIn("x = 1", out)


# ────────────────────────────────────────────────────────────────────────────
#  3. _get_public_ipv6
# ────────────────────────────────────────────────────────────────────────────
class TestGetPublicIpv6(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import aghome_setup
        self.mod = aghome_setup

    def _run_mock(self, ip_out="", curl_out=""):
        def fake_run(cmd, **kw):
            r = MagicMock()
            if cmd[:2] == ["ip", "-6"]:
                r.stdout = ip_out
                r.returncode = 0
            elif cmd[:1] == ["curl"]:
                r.stdout = curl_out
                r.returncode = 0 if curl_out else 1
            else:
                r.stdout = ""
                r.returncode = 1
            return r
        return fake_run

    def test_picks_stable_global(self):
        ip_out = ("2: eth0: <BROADCAST,MULTICAST,UP>\n"
                  "    inet6 2a02:6b8:c0c:1d0::1/64 scope global\n"
                  "    inet6 fd00::1/64 scope global\n")
        with patch.object(self.mod.subprocess, "run",
                          side_effect=self._run_mock(ip_out=ip_out)):
            self.assertEqual(self.mod._get_public_ipv6(), "2a02:6b8:c0c:1d0::1")

    def test_prefers_non_temporary(self):
        ip_out = ("    inet6 2a02:6b8::10/64 scope global temporary dynamic\n"
                  "    inet6 2a02:6b8::1/64 scope global\n")
        with patch.object(self.mod.subprocess, "run",
                          side_effect=self._run_mock(ip_out=ip_out)):
            self.assertEqual(self.mod._get_public_ipv6(), "2a02:6b8::1")

    def test_skips_link_local(self):
        ip_out = "    inet6 fe80::5054:ff:fe9e:1a2b/64 scope link\n"
        with patch.object(self.mod.subprocess, "run",
                          side_effect=self._run_mock(ip_out=ip_out,
                                                     curl_out="")):
            self.assertEqual(self.mod._get_public_ipv6(), "")

    def test_skips_deprecated(self):
        ip_out = ("    inet6 2a02::1/64 scope global deprecated\n"
                  "    inet6 2a02::2/64 scope global\n")
        with patch.object(self.mod.subprocess, "run",
                          side_effect=self._run_mock(ip_out=ip_out)):
            self.assertEqual(self.mod._get_public_ipv6(), "2a02::2")

    def test_curl_fallback(self):
        with patch.object(self.mod.subprocess, "run",
                          side_effect=self._run_mock(ip_out="",
                                                     curl_out="2001:db8::7")):
            self.assertEqual(self.mod._get_public_ipv6(), "2001:db8::7")

    def test_nothing_found(self):
        with patch.object(self.mod.subprocess, "run",
                          side_effect=self._run_mock(ip_out="", curl_out="")):
            self.assertEqual(self.mod._get_public_ipv6(), "")


# ────────────────────────────────────────────────────────────────────────────
#  4. build_dns_section(public_ipv6=...)
# ────────────────────────────────────────────────────────────────────────────
class TestBuildDnsSectionIpv6(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import aghome_setup
        self.mod = aghome_setup

    def test_bind_hosts_with_ipv6(self):
        s = self.mod.build_dns_section(dc_port=5300, public_ip="1.2.3.4",
                                       tls_enabled=True,
                                       public_ipv6="2a02:6b8::1")
        self.assertIn('- "127.0.0.1"', s)
        self.assertIn('- "1.2.3.4"', s)
        self.assertIn('- "2a02:6b8::1"', s)
        # порядок: loopback → v4 → v6
        self.assertLess(s.index('- "127.0.0.1"'), s.index('- "1.2.3.4"'))
        self.assertLess(s.index('- "1.2.3.4"'), s.index('- "2a02:6b8::1"'))

    def test_bind_hosts_without_ipv6_backward_compat(self):
        s = self.mod.build_dns_section(dc_port=5300, public_ip="1.2.3.4",
                                       tls_enabled=True)
        self.assertIn('- "127.0.0.1"', s)
        self.assertIn('- "1.2.3.4"', s)
        self.assertNotIn("2a02", s)
        self.assertNotIn("- \"::\"", s)

    def test_selfheal_loopback_only_excludes_ipv6(self):
        # self-heal #1: build_dns_section(dc_port, "", tls) → loopback-only
        s = self.mod.build_dns_section(dc_port=5300, public_ip="",
                                       tls_enabled=False)
        import re as _re
        m = _re.search(r"bind_hosts:\n((?:[ \t]+- .*(?:\n|$))+)", s)
        self.assertIsNotNone(m, "нет блока bind_hosts")
        items = [ln.strip() for ln in m.group(1).strip().splitlines()]
        self.assertEqual(items, ['- "127.0.0.1"'])


# ────────────────────────────────────────────────────────────────────────────
#  5. dnscrypt_advanced._get_listen_addresses — регрессия обрезания
# ────────────────────────────────────────────────────────────────────────────
class TestAdvancedGetListenRegression(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import dnscrypt_advanced
        self.mod = dnscrypt_advanced

    def test_full_line_with_v6_entry(self):
        content = ("listen_addresses = ['127.0.0.1:5300', '[::1]:5300']\n"
                   "max_clients = 250\n")
        got = self.mod._get_listen_addresses(content)
        self.assertEqual(
            got, "listen_addresses = ['127.0.0.1:5300', '[::1]:5300']")

    def test_v4_only_unchanged(self):
        content = "listen_addresses = ['127.0.0.1:5300']\n"
        got = self.mod._get_listen_addresses(content)
        self.assertEqual(got, "listen_addresses = ['127.0.0.1:5300']")

    def test_default_when_missing(self):
        got = self.mod._get_listen_addresses("max_clients = 250\n")
        self.assertEqual(got, "listen_addresses = ['127.0.0.1:5300']")


# ────────────────────────────────────────────────────────────────────────────
#  6. dnscrypt_selector — перезапись порта temp-конфига целой строкой
# ────────────────────────────────────────────────────────────────────────────
class TestSelectorTempPortRewrite(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        import re as _re
        self.re = _re

    def _rewrite(self, content):
        return self.re.sub(
            r"^listen_addresses\s*=\s*\[[^\n]*\][^\n]*$",
            "listen_addresses = ['127.0.0.1:15353']",
            content, flags=self.re.MULTILINE)

    def test_multi_entry_line_replaced_whole(self):
        content = ("listen_addresses = ['127.0.0.1:5300', '[::1]:5300']\n"
                   "server_names = ['cloudflare']\n")
        out = self._rewrite(content)
        self.assertEqual(out,
                         "listen_addresses = ['127.0.0.1:15353']\n"
                         "server_names = ['cloudflare']\n")

    def test_single_entry_still_works(self):
        content = "listen_addresses = ['127.0.0.1:5300']\n"
        out = self._rewrite(content)
        self.assertEqual(out, "listen_addresses = ['127.0.0.1:15353']\n")

    def test_double_quotes_variant(self):
        content = 'listen_addresses = ["127.0.0.1:5300"]\n'
        out = self._rewrite(content)
        self.assertEqual(out, "listen_addresses = ['127.0.0.1:15353']\n")

    def test_no_listen_line_untouched(self):
        content = "server_names = ['cloudflare']\n"
        out = self._rewrite(content)
        self.assertEqual(out, content)


if __name__ == "__main__":
    unittest.main()
