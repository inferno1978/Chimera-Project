#!/usr/bin/env python3
"""
tests/test_awg_b4_split.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для B4-сплита AWG-каскада (v5.5.11).

Контекст: юзер хочет YouTube и др. ресурсы с RU-IP (Google отключила
рекламу для RU-IP) — домены сетов b4 напрямую с entry через DPI-bypass,
остальное каскадом на exit. Модуль: chimera/modules/awg_b4_split.py.

Покрывает (чистая логика, без root/iptables):
  1. _normalize_domain    — wildcard/catch-all/мусор → домен/None
  2. collect_domains      — выбранные И enabled сеты + extra, дедуп
  3. detect_sets          — парс config.json b4
  4. _dns_a_records       — A-записи из DNS-wire (порт mieru_cascade)
  5. _qh_suffix_match     — граница метки (evilX ≠ X)
  6. _ip_ok               — публичный v4, отсев 0.0.0.0/приватных
  7. aaaa_rules_write     — yaml-хирургия user_rules AGH (маркеры, чужие
                            строки, идемпотентность, remove)
  8. _mark_spec           — форма каскадного mark-правила (сплит вкл/выкл)
  9. state                — roundtrip + фильтр неизвестных ключей
 10. routing script       — split-aware генерация (v5.5.11-блоки)
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Заглушка chimera._core (тот же приём, что test_awg_ipv6_v558)."""
    if "chimera._core" in sys.modules:
        return
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


def _mk_run(ok_stdout: str = "active"):
    """Фейковый _run для systemctl-вызовов (AGH 'active')."""
    def _fake_run(cmd, capture=False, check=False, timeout=60,
                  input_text=None):
        return SimpleNamespace(returncode=0, stdout=ok_stdout, stderr="")
    return _fake_run


class TestNormalizeDomain(unittest.TestCase):
    def test_wildcard_and_dots(self):
        from chimera.modules.awg_b4_split import _normalize_domain
        self.assertEqual(_normalize_domain("*.GoogleVideo.COM."), "googlevideo.com")
        self.assertEqual(_normalize_domain("  example.com  "), "example.com")

    def test_catchall_and_regexp(self):
        from chimera.modules.awg_b4_split import _normalize_domain
        for bad in ("*", "**", "*.*", "any", "all", "0/0", "regexp:.*", ""):
            self.assertIsNone(_normalize_domain(bad), bad)

    def test_ip_and_garbage(self):
        from chimera.modules.awg_b4_split import _normalize_domain
        self.assertIsNone(_normalize_domain("1.2.3.4"))
        self.assertIsNone(_normalize_domain("10.0.0.0/8"))
        self.assertIsNone(_normalize_domain("not a domain"))
        self.assertIsNone(_normalize_domain("-bad-.com"))

    def test_valid_multi_label(self):
        from chimera.modules.awg_b4_split import _normalize_domain
        self.assertEqual(_normalize_domain("rr1.sn-xyz.googlevideo.com"),
                         "rr1.sn-xyz.googlevideo.com")


class TestCollectDomains(unittest.TestCase):
    B4_CONF = {
        "sets": [
            {"id": "s1", "name": "Youtube-Fat", "enabled": True,
             "targets": {"sni_domains": ["youtube.com", "*.googlevideo.com",
                                          "ytimg.com", "*"]}},
            {"id": "s2", "name": "Heavy", "enabled": True,
             "targets": {"sni_domains": []}},
            {"id": "s3", "name": "Meta", "enabled": False,
             "targets": {"sni_domains": ["facebook.com"]}},
            {"id": "s4", "name": "GitLab", "enabled": True,
             "targets": {"sni_domains": ["gitlab.com"]}},
        ]
    }

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self._conf = self._tmp / "config.json"
        self._conf.write_text(json.dumps(self.B4_CONF))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _collect(self, st):
        from chimera.modules import awg_b4_split as m
        with patch.object(m, "_B4_CONFIG", self._conf):
            return m.collect_domains(st)

    def test_selected_and_enabled_only(self):
        st = {"set_ids": ["s1", "s3", "s2"], "extra_domains": []}
        # s3 disabled в b4 → мимо; s2 — 0 доменов; s1: 3 валидных (минус "*")
        self.assertEqual(self._collect(st),
                         ["googlevideo.com", "youtube.com", "ytimg.com"])

    def test_extra_domains_merged_dedup(self):
        st = {"set_ids": ["s1"], "extra_domains": ["YTIMG.com.",
                                                    "custom.example"]}
        out = self._collect(st)
        self.assertEqual(out.count("ytimg.com"), 1)
        self.assertIn("custom.example", out)

    def test_unknown_ids_ignored(self):
        st = {"set_ids": ["nope"], "extra_domains": []}
        self.assertEqual(self._collect(st), [])


class TestDnsARecords(unittest.TestCase):
    @staticmethod
    def _wire(ips, qname=b"\x03www\x07example\x03com\x00"):
        msg = bytearray()
        msg += b"\xab\xcd" + b"\x81\x80"
        msg += (1).to_bytes(2, "big") + len(ips).to_bytes(2, "big")
        msg += b"\x00\x00" * 2
        msg += qname + b"\x00\x01" + b"\x00\x01"
        for ip in ips:
            msg += b"\xc0\x0c" + b"\x00\x01" + b"\x00\x01"
            msg += (60).to_bytes(4, "big") + (4).to_bytes(2, "big")
            msg += bytes(int(x) for x in ip.split("."))
        return bytes(msg)

    def test_extracts_public_a(self):
        from chimera.modules.awg_b4_split import _dns_a_records
        ips = _dns_a_records(self._wire(["142.250.185.78", "173.194.222.101"]))
        self.assertEqual(ips, {"142.250.185.78", "173.194.222.101"})

    def test_filters_blocked_and_private(self):
        from chimera.modules.awg_b4_split import _dns_a_records
        ips = _dns_a_records(self._wire(["0.0.0.0", "10.1.2.3",
                                         "142.250.185.78"]))
        self.assertEqual(ips, {"142.250.185.78"})

    def test_garbage(self):
        from chimera.modules.awg_b4_split import _dns_a_records
        self.assertEqual(_dns_a_records(b""), set())
        self.assertEqual(_dns_a_records(b"\x01"), set())
        self.assertEqual(_dns_a_records(self._wire([])), set())


class TestQhSuffixMatch(unittest.TestCase):
    def test_boundary(self):
        from chimera.modules.awg_b4_split import _qh_suffix_match
        self.assertTrue(_qh_suffix_match("googlevideo.com",
                                         ["googlevideo.com"]))
        self.assertTrue(_qh_suffix_match("rr1.sn.googlevideo.com",
                                         ["googlevideo.com"]))
        self.assertFalse(_qh_suffix_match("evilgooglevideo.com",
                                          ["googlevideo.com"]))
        self.assertFalse(_qh_suffix_match("", ["googlevideo.com"]))
        self.assertFalse(_qh_suffix_match("youtube.com", []))


class TestIpOk(unittest.TestCase):
    def test_filters(self):
        from chimera.modules.awg_b4_split import _ip_ok
        self.assertTrue(_ip_ok("203.0.113.101"))
        self.assertFalse(_ip_ok("0.0.0.0"))
        self.assertFalse(_ip_ok("127.0.0.1"))
        self.assertFalse(_ip_ok("192.168.1.1"))
        self.assertFalse(_ip_ok("fd66:66::1"))
        self.assertFalse(_ip_ok("мусор"))


class TestAaaaYamlSurgery(unittest.TestCase):
    """yaml-хирургия user_rules AGH: маркеры, чужие строки, идемпотентность."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmp = Path(tempfile.mkdtemp())
        self._yaml = self._tmp / "AdGuardHome.yaml"
        self._bak = self._tmp / "AdGuardHome.yaml.bak"
        from chimera.modules import awg_b4_split as m
        self._m = m
        self._patches = [
            patch.object(m, "_AGH_YAML", self._yaml),
            patch.object(m, "_AGH_BACKUP", self._bak),
            patch.object(m, "_run", _mk_run()),
            patch.object(m.time, "sleep", lambda s: None),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_empty_user_rules(self):
        self._yaml.write_text("http:\n  address: 0.0.0.0:3000\n"
                              "user_rules: []\ndhcp:\n  enabled: false\n")
        ok = self._m.aaaa_rules_write(["youtube.com", "ytimg.com"])
        self.assertTrue(ok)
        body = self._yaml.read_text()
        self.assertIn("user_rules:", body)
        self.assertIn("- '||youtube.com^$dnstype=AAAA'", body)
        self.assertIn("- '||ytimg.com^$dnstype=AAAA'", body)
        self.assertIn(self._m._AAAA_BEGIN, body)
        self.assertIn(self._m._AAAA_END, body)
        # чужая секция не тронута
        self.assertIn("dhcp:", body)

    def test_nested_user_rules_with_foreign(self):
        # вложенный в filtering: вариант + чужое правило — обязано сохраниться
        self._yaml.write_text(
            "filtering:\n  enabled: true\n  user_rules:\n"
            "  - '||ads.example^'\n"
            "querylog:\n  enabled: true\n")
        ok = self._m.aaaa_rules_write(["googlevideo.com"])
        self.assertTrue(ok)
        body = self._yaml.read_text()
        self.assertIn("- '||ads.example^'", body)
        self.assertIn("- '||googlevideo.com^$dnstype=AAAA'", body)
        # наш блок ПОСЛЕ строки user_rules (та же вложенность)
        self.assertLess(body.index("||ads.example^"),
                        body.index(self._m._AAAA_BEGIN))

    def test_idempotent_no_rewrite(self):
        self._yaml.write_text("user_rules: []\n")
        self.assertTrue(self._m.aaaa_rules_write(["a.example"]))
        first = self._yaml.read_text()
        self.assertTrue(self._m.aaaa_rules_write(["a.example"]))
        self.assertEqual(self._yaml.read_text(), first)

    def test_update_replaces_block(self):
        self._yaml.write_text("user_rules: []\n")
        self._m.aaaa_rules_write(["a.example"])
        self._m.aaaa_rules_write(["b.example"])
        body = self._yaml.read_text()
        self.assertNotIn("||a.example^", body)
        self.assertIn("- '||b.example^$dnstype=AAAA'", body)

    def test_remove(self):
        self._yaml.write_text(
            "user_rules: []\n")
        self._m.aaaa_rules_write(["x.example"])
        self.assertIn(self._m._AAAA_BEGIN, self._yaml.read_text())
        self._m.aaaa_rules_remove()
        body = self._yaml.read_text()
        self.assertNotIn(self._m._AAAA_BEGIN, body)
        self.assertNotIn("||x.example^", body)

    def test_remove_noop_when_absent(self):
        self._yaml.write_text("user_rules: []\n")
        self._m.aaaa_rules_remove()   # не должен падать/менять файл
        self.assertIn("user_rules: []", self._yaml.read_text())


class TestMarkSpec(unittest.TestCase):
    def test_forms(self):
        from chimera.modules.awg_b4_split import _mark_spec
        plain = _mark_spec(False)
        self.assertNotIn("awg_b4_direct", plain)
        self.assertIn("awg_ru_networks", plain)
        self.assertIn("0x8200", plain)
        excl = _mark_spec(True)
        self.assertIn("awg_b4_direct", excl)
        self.assertEqual(excl[:6], plain[:6])
        # исключение стоит ДО -j MARK
        self.assertLess(excl.index("awg_b4_direct"), excl.index("-j"))


class TestStateRoundtrip(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        from chimera.modules import awg_b4_split as m
        self._m = m
        self._p = patch.object(m, "_STATE_FILE",
                               self._tmp / "awg_b4_split.json")
        self._p.start()

    def tearDown(self):
        self._p.stop()
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_roundtrip_and_key_filter(self):
        st = self._m._state_default()
        st["enabled"] = True
        st["set_ids"] = ["a", "b"]
        st["aaaa_domains"] = ["x.example"]
        st["hacker_key"] = "evil"          # неизвестный ключ — фильтруется
        self._m.state_save(st)
        loaded = self._m.state_load()
        self.assertTrue(loaded["enabled"])
        self.assertEqual(loaded["set_ids"], ["a", "b"])
        self.assertEqual(loaded["aaaa_domains"], ["x.example"])
        self.assertNotIn("hacker_key", loaded)

    def test_defaults_on_missing(self):
        self._m._STATE_FILE.unlink(missing_ok=True)
        st = self._m.state_load()
        self.assertFalse(st["enabled"])
        self.assertTrue(st["dns_redirect"])
        self.assertTrue(st["aaaa_filter"])
        self.assertEqual(st["refresh_sec"], 60)


class TestRoutingScriptSplitAware(unittest.TestCase):
    """Генератор awg-routing.sh: v5.5.11-блоки при сплите вкл/выкл."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmp = Path(tempfile.mkdtemp())
        self._script = self._tmp / "awg-routing.sh"
        from chimera.modules import awg_cascade, awg_b4_split
        self._casc = awg_cascade
        self._split = awg_b4_split

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _gen(self, enabled: bool) -> str:
        st = self._split._state_default()
        st["enabled"] = enabled
        st_file = self._tmp / "split_state.json"
        st_file.write_text(json.dumps(st))
        with patch.object(self._casc, "AWGS_CASCADE_DIR", self._tmp), \
             patch.object(self._casc, "AWGS_ROUTING_SCRIPT", self._script), \
             patch.object(self._split, "_STATE_FILE", st_file):
            self._casc._awgs_cascade_create_routing_script(
                "172.16.81.0/24", subnet_v6="fd66:66:81::/64")
        return self._script.read_text()

    def test_split_on_blocks(self):
        body = self._gen(True)
        # ipset direct-плеча + снапшот
        self.assertIn("ipset create awg_b4_direct hash:ip", body)
        self.assertIn("awg_b4_direct.snapshot", body)
        # mark-правило с исключением
        self.assertIn("! --match-set awg_b4_direct dst", body)
        # nft-сплит-форма: set + условный return ПЕРЕД blanket
        self.assertIn("nft add set inet awg_b4exempt awg_b4direct", body)
        self.assertIn("ip daddr @awg_b4direct return", body)
        # cleanup обеих форм
        self.assertIn("-m set ! --match-set awg_b4_direct dst -j MARK", body)

    def test_split_off_is_v559(self):
        body = self._gen(False)
        # активное mark-правило — БЕЗ исключения (cleanup-циклы другой
        # формы упоминают awg_b4_direct — это легально и нужно)
        mark_lines = [l for l in body.splitlines()
                      if "-A PREROUTING" in l and "awg_ru_networks" in l]
        self.assertTrue(mark_lines, "нет mark-правила в скрипте")
        for l in mark_lines:
            self.assertNotIn("awg_b4_direct", l)
        # сплит-блоки отсутствуют
        self.assertNotIn("ipset create awg_b4_direct", body)
        self.assertNotIn("awg_b4direct", body)      # nft-сет
        self.assertNotIn("snapshot", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
