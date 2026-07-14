#!/usr/bin/env python3
"""
tests/test_naiveproxy.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/naiveproxy.py.

Покрывает:
  1. _build_naive_link — генерация naive+https:// URL
  2. _gen_probe_secret — генерация секретного токена
  3. _gen_singbox_outbound — генерация sing-box outbound
  4. _build_caddyfile — генерация Caddyfile
  5. _hash_password — fallback-хеширование (без caddy binary)
  6. _is_amd64 — определение архитектуры
"""
from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

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


class TestBuildNaiveLink(unittest.TestCase):
    """_build_naive_link — генерация naive+https:// URL."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_basic_link(self):
        from chimera.modules.naiveproxy import _build_naive_link
        link = _build_naive_link("vpn.example.com", 443, "user", "pass")
        self.assertTrue(link.startswith("naive+https://"))
        self.assertIn("user:pass", link)
        self.assertIn("vpn.example.com:443", link)
        self.assertTrue(link.endswith("/"))

    def test_url_encodes_special_chars(self):
        from chimera.modules.naiveproxy import _build_naive_link
        link = _build_naive_link("vpn.example.com", 443, "us@er", "pa:ss")
        self.assertIn("%40", link)  # @ → %40
        self.assertIn("%3A", link)  # : → %3A

    def test_with_tag(self):
        from chimera.modules.naiveproxy import _build_naive_link
        link = _build_naive_link("vpn.example.com", 443, "user", "pass", tag="my tag")
        self.assertIn("#", link)
        self.assertIn("my%20tag", link)

    def test_without_tag(self):
        from chimera.modules.naiveproxy import _build_naive_link
        link = _build_naive_link("vpn.example.com", 443, "user", "pass")
        self.assertNotIn("#", link)


class TestGenProbeSecret(unittest.TestCase):
    """_gen_probe_secret — генерация секретного токена."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_nonempty_string(self):
        from chimera.modules.naiveproxy import _gen_probe_secret
        secret = _gen_probe_secret()
        self.assertGreater(len(secret), 0)

    def test_unique(self):
        from chimera.modules.naiveproxy import _gen_probe_secret
        secrets = {_gen_probe_secret() for _ in range(10)}
        self.assertGreater(len(secrets), 1)


class TestGenSingboxOutbound(unittest.TestCase):
    """_gen_singbox_outbound — генерация sing-box outbound."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_dict_with_required_keys(self):
        from chimera.modules.naiveproxy import _gen_singbox_outbound
        ob = _gen_singbox_outbound("vpn.example.com", 443, "alice", "pass")
        self.assertEqual(ob["type"], "naive")
        self.assertEqual(ob["tag"], "naive-alice")
        self.assertEqual(ob["server"], "vpn.example.com")
        self.assertEqual(ob["server_port"], 443)
        self.assertEqual(ob["username"], "alice")
        self.assertEqual(ob["password"], "pass")

    def test_tls_enabled(self):
        from chimera.modules.naiveproxy import _gen_singbox_outbound
        ob = _gen_singbox_outbound("vpn.example.com", 443, "u", "p")
        self.assertTrue(ob["tls"]["enabled"])
        self.assertEqual(ob["tls"]["server_name"], "vpn.example.com")


class TestBuildCaddyfile(unittest.TestCase):
    """_build_caddyfile — генерация Caddyfile."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_includes_domain_and_port(self):
        from chimera.modules.naiveproxy import _build_caddyfile
        caddyfile = _build_caddyfile("vpn.example.com", 443, [], "https://bing.com", "secret")
        self.assertIn("vpn.example.com:443", caddyfile)
        self.assertIn(":443", caddyfile)

    def test_includes_users_auth(self):
        from chimera.modules.naiveproxy import _build_caddyfile
        users = [{"username": "alice", "password": "p1"}, {"username": "bob", "password": "p2"}]
        caddyfile = _build_caddyfile("vpn.example.com", 443, users, "https://bing.com", "secret")
        self.assertIn("alice", caddyfile)
        self.assertIn("bob", caddyfile)

    def test_includes_probe_resistance(self):
        from chimera.modules.naiveproxy import _build_caddyfile
        caddyfile = _build_caddyfile("vpn.example.com", 443, [], "https://bing.com", "secret")
        self.assertIn("probe_resistance", caddyfile)

    def test_includes_upstream_when_provided(self):
        from chimera.modules.naiveproxy import _build_caddyfile
        caddyfile = _build_caddyfile("vpn.example.com", 443, [], "https://bing.com", "secret",
                                      upstream="socks5://127.0.0.1:1080")
        self.assertIn("upstream", caddyfile)
        self.assertIn("socks5://127.0.0.1:1080", caddyfile)


class TestHashPasswordFallback(unittest.TestCase):
    """_hash_password — fallback-хеширование (без caddy binary)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_fallback_returns_sha256(self):
        from chimera.modules.naiveproxy import _hash_password
        # Патчим _BIN_PATH.exists → False → fallback-ветка
        with patch("chimera.modules.naiveproxy._BIN_PATH") as mock_bin:
            mock_bin.exists.return_value = False
            result = _hash_password("mypassword")
        expected = "{sha256}" + hashlib.sha256(b"mypassword").hexdigest()
        self.assertEqual(result, expected)


class TestIsAmd64(unittest.TestCase):
    """_is_amd64."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_x86_64(self):
        from chimera.modules.naiveproxy import _is_amd64
        with patch("platform.machine", return_value="x86_64"):
            self.assertTrue(_is_amd64())

    def test_aarch64(self):
        from chimera.modules.naiveproxy import _is_amd64
        with patch("platform.machine", return_value="aarch64"):
            self.assertFalse(_is_amd64())


if __name__ == "__main__":
    unittest.main(verbosity=2)
