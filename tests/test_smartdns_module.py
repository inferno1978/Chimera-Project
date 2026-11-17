#!/usr/bin/env python3
"""
tests/test_smartdns_module.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/smartdns.py — оркестратора SmartDNS-ноды.

Покрывает:
  1. State/settings/secrets roundtrip (tmp-изоляция STATE_FILE и путей
     стека) + chmod 0600 у secrets.
  2. port_plan: публичные порты получают bind_ip в companion, loopback —
     wildcard; register_ports → записи в port_registry c bind_ip (tmp
     реестр); unregister чистит.
  3. validate_bind_ip: второй IP обязан лежать на интерфейсе, не совпадать
     с основным; validate_domain.
  4. detect_environment — снапшот без исключений, детект кандидатов.
  5. update_availability — кэш-математика «доступно новое» (паттерн B4).
  6. _refresh_latest_cache — TTL: свежий кэш не дёргает сеть; force — да.
  7. CLI: install --non-interactive без --domain → отказ; companion без
     --bind-ip → отказ; unknown → usage (rc=2); whitelist status без
     установки → rc=1.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import smartdns as sd  # noqa: E402
from chimera.modules import smartdns_stack as st  # noqa: E402


class _tmp_stack:
    """Изоляция state/settings/secrets/реестра на временный каталог."""

    def __init__(self):
        import chimera.modules.port_registry as pr
        self.pr = pr

    def __enter__(self):
        self.td = tempfile.TemporaryDirectory()
        root = Path(self.td.name)
        self._orig = {
            "state": sd.STATE_FILE,
            "st_state_dir": st.STATE_DIR,
            "st_settings": st.SETTINGS_FILE,
            "st_secrets": st.SECRETS_FILE,
            "registry": self.pr.PORT_REGISTRY_FILE,
            # LOCK_FILE вычислен на импорте от прод-пути — двигаем вместе
            # с реестром, иначе _registry_lock mkdir'ит /var/lib/xray-installer
            "registry_lock": self.pr.LOCK_FILE,
        }
        sd.STATE_FILE = root / "smartdns_state.json"
        st.STATE_DIR = root / "stack"
        st.SETTINGS_FILE = st.STATE_DIR / "settings.json"
        st.SECRETS_FILE = st.STATE_DIR / "secrets.json"
        self.pr.PORT_REGISTRY_FILE = root / "port_registry.json"
        self.pr.LOCK_FILE = root / "port_registry.lock"
        return root

    def __exit__(self, *a):
        sd.STATE_FILE = self._orig["state"]
        st.STATE_DIR = self._orig["st_state_dir"]
        st.SETTINGS_FILE = self._orig["st_settings"]
        st.SECRETS_FILE = self._orig["st_secrets"]
        self.pr.PORT_REGISTRY_FILE = self._orig["registry"]
        self.pr.LOCK_FILE = self._orig["registry_lock"]
        self.td.cleanup()


class TestStateIo(unittest.TestCase):
    def test_state_roundtrip_and_defaults(self):
        with _tmp_stack():
            self.assertFalse(sd._load_state()["installed"])
            sd._save_state({"installed": True, "mode": "companion",
                            "bind_ip": "203.0.113.7", "engine": "oxidns"})
            s = sd._load_state()
            self.assertTrue(s["installed"])
            self.assertEqual(s["mode"], "companion")
            # дефолты дополнены (whitelist_mode и пр.)
            self.assertEqual(s["whitelist_mode"], "shared")

    def test_settings_secrets_roundtrip(self):
        with _tmp_stack() as root:
            cfg = {"mode": "companion", "bind_ip": "203.0.113.7",
                   "engine": "oxidns", "domain": "example.com",
                   "dot_host": "dot.example.com",
                   "whitelist_enabled": "true", "whitelist_mode": "separate",
                   "server_ipv4": "203.0.113.7",
                   "cf_api_token": "T" * 40, "agh_admin_user": "admin_x",
                   "agh_admin_pass": "P" * 24}
            sd.save_settings(cfg)
            sd.save_secrets(cfg)
            loaded = sd.load_settings()
            self.assertEqual(loaded["domain"], "example.com")
            self.assertEqual(loaded["bind_ip"], "203.0.113.7")
            self.assertNotIn("cf_api_token", loaded)   # секреты — отдельно
            sec = sd.load_secrets()
            self.assertEqual(sec["cf_api_token"], "T" * 40)
            self.assertEqual(
                oct(st.SECRETS_FILE.stat().st_mode)[-3:], "600")


class TestPortPlan(unittest.TestCase):
    CFG = {"mode": "companion", "bind_ip": "203.0.113.7", "engine": "oxidns"}

    def test_public_bind_ip_loopback_wildcard(self):
        plan = sd.port_plan(self.CFG)
        pub = {tag: bind for tag, _p, _proto, _c, bind in plan
               if tag in ("smartdns_http", "smartdns_dot", "smartdns_doh",
                          "smartdns_web")}
        self.assertEqual(set(pub.values()), {"203.0.113.7"})
        loop = {tag: bind for tag, _p, _proto, _c, bind in plan
                if tag.startswith(("smartdns_engine", "smartdns_doh_local",
                                   "smartdns_dot_term", "smartdns_stealth"))}
        self.assertEqual(set(loop.values()), {None})

    def test_standalone_all_wildcard(self):
        plan = sd.port_plan({"mode": "standalone", "engine": "oxidns"})
        self.assertEqual({b for *_x, b in plan}, {None})

    def test_register_unregister_with_bind_ip(self):
        with _tmp_stack():
            sd.register_ports(self.CFG)
            import chimera.modules.port_registry as _pr
            entries = json.loads(_pr.PORT_REGISTRY_FILE.read_text())
            tagged = {e["service"]: e for e in entries}
            self.assertEqual(tagged["smartdns_web"]["bind_ip"],
                             "203.0.113.7")
            self.assertEqual(tagged["smartdns_web"]["port"], 9443)
            self.assertNotIn("bind_ip", tagged["smartdns_engine"])
            # force=True: наши же слушатели не мешают повторной регистрации
            self.assertTrue(sd.register_ports(self.CFG) >= 9)
            sd.unregister_ports(self.CFG)
            self.assertEqual(json.loads(
                _pr.PORT_REGISTRY_FILE.read_text()), [])


class TestValidation(unittest.TestCase):
    ENV = {"all_ips": ["198.51.100.2", "203.0.113.7"],
           "server_ipv4": "198.51.100.2"}

    def test_bind_ip_ok(self):
        ok, why = sd.validate_bind_ip(
            {"bind_ip": "203.0.113.7"}, self.ENV)
        self.assertTrue(ok, why)

    def test_bind_ip_not_on_interface(self):
        ok, why = sd.validate_bind_ip({"bind_ip": "203.0.113.99"}, self.ENV)
        self.assertFalse(ok)
        self.assertIn("не поднят", why)

    def test_bind_ip_equals_primary(self):
        ok, _ = sd.validate_bind_ip({"bind_ip": "198.51.100.2"}, self.ENV)
        self.assertFalse(ok)

    def test_bind_ip_malformed(self):
        ok, _ = sd.validate_bind_ip({"bind_ip": "not-an-ip"}, self.ENV)
        self.assertFalse(ok)

    def test_domain(self):
        self.assertTrue(sd.validate_domain("example.com"))
        self.assertTrue(sd.validate_domain("a-b.example.io"))
        self.assertFalse(sd.validate_domain("example"))
        self.assertFalse(sd.validate_domain("exa mple.com"))
        self.assertFalse(sd.validate_domain(""))


class TestEnvAndCache(unittest.TestCase):
    def test_detect_environment_smoke(self):
        env = sd.detect_environment()
        self.assertIn("arch", env)
        self.assertIn("chimera_detected", env)
        self.assertIn("second_ip_candidates", env)
        self.assertIsInstance(env["all_ips"], list)

    def test_update_availability(self):
        with _tmp_stack():
            sd._save_state({
                "installed": True,
                "versions": {"xray": "v1.0.0", "oxidns": "v1.7.1"},
                "latest_versions": {"xray": "v2.0.0", "oxidns": "v1.7.1"},
            })
            avail = sd.update_availability()
            self.assertTrue(avail["known"])
            self.assertEqual(avail["updates"], ["xray v1.0.0 → v2.0.0"])

    def test_update_availability_unknown(self):
        with _tmp_stack():
            self.assertFalse(sd.update_availability()["known"])

    def test_refresh_latest_cache_ttl(self):
        import time as _t
        with _tmp_stack():
            sd._save_state({"installed": True,
                            "latest_check_ok": True,
                            "latest_checked_at": _t.time(),   # свежий
                            "latest_versions": {"xray": "v9.9.9"}})
            with patch.object(st, "github_latest_tag",
                              side_effect=AssertionError(
                                  "сеть не должна дёргаться")):
                state = sd._refresh_latest_cache()
            self.assertEqual(state["latest_versions"]["xray"], "v9.9.9")
            # force → сеть зовётся (TTL игнорируется)
            with patch.object(st, "github_latest_tag", return_value="v1.0.0"):
                state = sd._refresh_latest_cache(force=True)
            self.assertEqual(state["latest_versions"]["xray"], "v1.0.0")


class TestCli(unittest.TestCase):
    def _run_cli(self, argv, euid=0):
        with _tmp_stack():
            with patch.object(sd.os, "geteuid", return_value=euid):
                with patch.object(sd.sys, "argv", ["smartdns.py"] + argv):
                    try:
                        rc = sd._cli()
                    except SystemExit as e:
                        rc = e.code
            return rc

    def test_help(self):
        with patch.object(sd.sys, "argv", ["smartdns.py", "--help"]):
            rc = sd._cli()
        self.assertEqual(rc, 0)

    def test_install_requires_domain_non_interactive(self):
        rc = self._run_cli(["install", "--mode", "standalone",
                            "--non-interactive"])
        self.assertEqual(rc, 1)

    def test_companion_requires_bind_ip(self):
        rc = self._run_cli(["install", "--mode", "companion",
                            "--domain", "example.com", "--cf-token",
                            "T" * 40, "--non-interactive"])
        self.assertEqual(rc, 1)

    def test_unknown_command_usage(self):
        self.assertEqual(self._run_cli(["frobnicate"]), 2)

    def test_whitelist_requires_install(self):
        self.assertEqual(
            self._run_cli(["whitelist", "status"]), 1)

    def test_status_ok_uninstalled(self):
        with _tmp_stack():
            with patch.object(sd, "show_status") as m:
                with patch.object(sd.sys, "argv",
                                  ["smartdns.py", "status"]):
                    rc = sd._cli()
                m.assert_called_once()
        self.assertEqual(rc, 0)

    def test_non_root_denied(self):
        self.assertEqual(
            self._run_cli(["update"], euid=1000), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
