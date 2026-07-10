#!/usr/bin/env python3
"""
tests/test_dns_rules.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/dns_rules.py.

Покрывает:
  1. _dns_validate_ip — валидация IP
  2. _dns_validate_domain — валидация домена
  3. _dns_rules_load / _dns_rules_save — JSON I/O
  4. _dns_apply_hosts / _dns_remove_host — мутация Xray config
  5. _dns_apply_routing_rule / _dns_remove_routing_rule — routing rules
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("vless_installer._core")
    fake_core.__dict__.update(g)
    sys.modules["vless_installer._core"] = fake_core


class TestDnsValidateIp(unittest.TestCase):
    """_dns_validate_ip — pure validator."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_returns_error(self):
        from vless_installer.modules.dns_rules import _dns_validate_ip
        self.assertIsNotNone(_dns_validate_ip(""))

    def test_valid_ipv4(self):
        from vless_installer.modules.dns_rules import _dns_validate_ip
        self.assertIsNone(_dns_validate_ip("1.2.3.4"))
        self.assertIsNone(_dns_validate_ip("192.168.1.1"))

    def test_invalid_ipv4_octet(self):
        from vless_installer.modules.dns_rules import _dns_validate_ip
        self.assertIsNotNone(_dns_validate_ip("1.2.3.256"))
        self.assertIsNotNone(_dns_validate_ip("999.999.999.999"))

    def test_valid_ipv6(self):
        from vless_installer.modules.dns_rules import _dns_validate_ip
        self.assertIsNone(_dns_validate_ip("::1"))
        self.assertIsNone(_dns_validate_ip("2001:db8::1"))

    def test_comma_separated_list(self):
        from vless_installer.modules.dns_rules import _dns_validate_ip
        self.assertIsNone(_dns_validate_ip("1.2.3.4,5.6.7.8"))
        self.assertIsNotNone(_dns_validate_ip("1.2.3.4,invalid"))

    def test_garbage_invalid(self):
        from vless_installer.modules.dns_rules import _dns_validate_ip
        self.assertIsNotNone(_dns_validate_ip("garbage"))
        self.assertIsNotNone(_dns_validate_ip("not.an.ip"))


class TestDnsValidateDomain(unittest.TestCase):
    """_dns_validate_domain — pure validator."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_returns_error(self):
        from vless_installer.modules.dns_rules import _dns_validate_domain
        self.assertIsNotNone(_dns_validate_domain(""))

    def test_valid_domain(self):
        from vless_installer.modules.dns_rules import _dns_validate_domain
        self.assertIsNone(_dns_validate_domain("example.com"))
        self.assertIsNone(_dns_validate_domain("sub.example.com"))

    def test_domain_with_space_invalid(self):
        from vless_installer.modules.dns_rules import _dns_validate_domain
        self.assertIsNotNone(_dns_validate_domain("example com"))

    def test_localhost_without_dot_invalid(self):
        from vless_installer.modules.dns_rules import _dns_validate_domain
        self.assertIsNotNone(_dns_validate_domain("localhost"))

    def test_domain_prefix_valid(self):
        from vless_installer.modules.dns_rules import _dns_validate_domain
        self.assertIsNone(_dns_validate_domain("domain:google.com"))
        self.assertIsNone(_dns_validate_domain("geosite:ru"))


class TestDnsRulesLoadSave(unittest.TestCase):
    """_dns_rules_load / _dns_rules_save."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._rules = self._tmpdir / "dns_rules.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.dns_rules.DNS_RULES_FILE", self._rules)

    def test_load_returns_defaults_when_no_file(self):
        from vless_installer.modules.dns_rules import _dns_rules_load
        with self._patch():
            result = _dns_rules_load()
        self.assertEqual(result, {"hosts": {}, "routing": []})

    def test_load_returns_defaults_on_corrupt(self):
        from vless_installer.modules.dns_rules import _dns_rules_load
        self._rules.write_text("{invalid")
        with self._patch():
            result = _dns_rules_load()
        self.assertEqual(result, {"hosts": {}, "routing": []})

    def test_save_then_load(self):
        from vless_installer.modules.dns_rules import _dns_rules_load, _dns_rules_save
        data = {"hosts": {"x.com": "1.2.3.4"}, "routing": []}
        with self._patch():
            _dns_rules_save(data)
            loaded = _dns_rules_load()
        self.assertEqual(loaded["hosts"]["x.com"], "1.2.3.4")

    def test_save_sets_chmod_600(self):
        import stat
        from vless_installer.modules.dns_rules import _dns_rules_save
        with self._patch():
            _dns_rules_save({"hosts": {}, "routing": []})
        mode = stat.S_IMODE(os.stat(self._rules).st_mode)
        self.assertEqual(mode, 0o600)


class TestDnsApplyHosts(unittest.TestCase):
    """_dns_apply_hosts — мутация Xray config."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "config.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_with_config(self, cfg_dict):
        self._cfg.write_text(json.dumps(cfg_dict))
        return patch("vless_installer.modules.dns_rules._dns_get_xray_config",
                     return_value=(self._cfg, cfg_dict))

    def test_returns_false_when_no_config(self):
        from vless_installer.modules.dns_rules import _dns_apply_hosts
        with patch("vless_installer.modules.dns_rules._dns_get_xray_config",
                   return_value=(None, {})):
            self.assertFalse(_dns_apply_hosts({"x.com": "1.2.3.4"}))

    def test_creates_dns_section_if_missing(self):
        from vless_installer.modules.dns_rules import _dns_apply_hosts
        with self._patch_with_config({}):
            _dns_apply_hosts({"x.com": "1.2.3.4"})
        cfg = json.loads(self._cfg.read_text())
        self.assertIn("hosts", cfg["dns"])
        self.assertEqual(cfg["dns"]["hosts"]["x.com"], "1.2.3.4")

    def test_merges_with_existing_hosts(self):
        from vless_installer.modules.dns_rules import _dns_apply_hosts
        with self._patch_with_config({"dns": {"hosts": {"existing.com": "5.6.7.8"}}}):
            _dns_apply_hosts({"new.com": "1.2.3.4"})
        cfg = json.loads(self._cfg.read_text())
        self.assertIn("existing.com", cfg["dns"]["hosts"])
        self.assertIn("new.com", cfg["dns"]["hosts"])


class TestDnsRemoveHost(unittest.TestCase):
    """_dns_remove_host."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "config.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_false_when_no_config(self):
        from vless_installer.modules.dns_rules import _dns_remove_host
        with patch("vless_installer.modules.dns_rules._dns_get_xray_config",
                   return_value=(None, {})):
            self.assertFalse(_dns_remove_host("x.com"))

    def test_removes_existing_host(self):
        from vless_installer.modules.dns_rules import _dns_remove_host
        cfg_dict = {"dns": {"hosts": {"x.com": "1.2.3.4", "y.com": "5.6.7.8"}}}
        self._cfg.write_text(json.dumps(cfg_dict))
        with patch("vless_installer.modules.dns_rules._dns_get_xray_config",
                   return_value=(self._cfg, cfg_dict)):
            self.assertTrue(_dns_remove_host("x.com"))
        cfg = json.loads(self._cfg.read_text())
        self.assertNotIn("x.com", cfg["dns"]["hosts"])
        self.assertIn("y.com", cfg["dns"]["hosts"])

    def test_returns_false_when_host_not_found(self):
        from vless_installer.modules.dns_rules import _dns_remove_host
        cfg_dict = {"dns": {"hosts": {"x.com": "1.2.3.4"}}}
        self._cfg.write_text(json.dumps(cfg_dict))
        with patch("vless_installer.modules.dns_rules._dns_get_xray_config",
                   return_value=(self._cfg, cfg_dict)):
            self.assertFalse(_dns_remove_host("nonexistent.com"))


class TestDnsApplyRoutingRule(unittest.TestCase):
    """_dns_apply_routing_rule."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "config.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_creates_routing_section_if_missing(self):
        from vless_installer.modules.dns_rules import _dns_apply_routing_rule
        cfg_dict = {}
        self._cfg.write_text(json.dumps(cfg_dict))
        with patch("vless_installer.modules.dns_rules._dns_get_xray_config",
                   return_value=(self._cfg, cfg_dict)):
            _dns_apply_routing_rule("blocked.com", "direct")
        cfg = json.loads(self._cfg.read_text())
        rules = cfg["routing"]["rules"]
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["domain"], ["blocked.com"])
        self.assertEqual(rules[0]["outboundTag"], "direct")
        self.assertTrue(rules[0]["comment"].startswith("dns_custom:"))

    def test_replaces_existing_rule_for_same_domain(self):
        from vless_installer.modules.dns_rules import _dns_apply_routing_rule
        cfg_dict = {"routing": {"rules": [
            {"type": "field", "domain": ["x.com"], "outboundTag": "old",
             "comment": "dns_custom:x.com"},
        ]}}
        self._cfg.write_text(json.dumps(cfg_dict))
        with patch("vless_installer.modules.dns_rules._dns_get_xray_config",
                   return_value=(self._cfg, cfg_dict)):
            _dns_apply_routing_rule("x.com", "new")
        cfg = json.loads(self._cfg.read_text())
        rules = cfg["routing"]["rules"]
        # старая удалена, новая добавлена
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["outboundTag"], "new")


class TestDnsRemoveRoutingRule(unittest.TestCase):
    """_dns_remove_routing_rule."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "config.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_false_when_no_config(self):
        from vless_installer.modules.dns_rules import _dns_remove_routing_rule
        with patch("vless_installer.modules.dns_rules._dns_get_xray_config",
                   return_value=(None, {})):
            self.assertFalse(_dns_remove_routing_rule("x.com"))

    def test_removes_custom_rule_for_domain(self):
        from vless_installer.modules.dns_rules import _dns_remove_routing_rule
        cfg_dict = {"routing": {"rules": [
            {"type": "field", "domain": ["x.com"], "outboundTag": "direct",
             "comment": "dns_custom:x.com"},
            {"type": "field", "domain": ["y.com"], "outboundTag": "block",
             "comment": "other"},
        ]}}
        self._cfg.write_text(json.dumps(cfg_dict))
        with patch("vless_installer.modules.dns_rules._dns_get_xray_config",
                   return_value=(self._cfg, cfg_dict)):
            self.assertTrue(_dns_remove_routing_rule("x.com"))
        cfg = json.loads(self._cfg.read_text())
        rules = cfg["routing"]["rules"]
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["domain"], ["y.com"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
