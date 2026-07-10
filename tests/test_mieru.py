#!/usr/bin/env python3
"""
tests/test_mieru.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/mieru.py.

Покрывает:
  1. _get_download_urls — вычисление URL для amd64/arm64
  2. _build_server_config — генерация серверного конфига
  3. _gen_singbox_outbound — генерация sing-box outbound
  4. _gen_client_share_link — генерация mierus:// ссылки
  5. _gen_client_share_link_nekobox — генерация Nekobox ссылки
  6. _is_amd64 — определение архитектуры
  7. _RE_USERNAME — валидация имени пользователя
"""
from __future__ import annotations

import sys
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


class TestGetDownloadUrls(unittest.TestCase):
    """_get_download_urls — вычисление URL."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_amd64_urls(self):
        from vless_installer.modules import mieru
        with patch.object(mieru, "_is_amd64", return_value=True):
            mita_url, mieru_url = mieru._get_download_urls("1.0.0")
        self.assertIn("amd64", mita_url)
        self.assertIn("amd64", mieru_url)
        self.assertIn("1.0.0", mita_url)
        self.assertIn("1.0.0", mieru_url)

    def test_arm64_urls(self):
        from vless_installer.modules import mieru
        with patch.object(mieru, "_is_amd64", return_value=False):
            mita_url, mieru_url = mieru._get_download_urls("2.0.0")
        self.assertIn("arm64", mita_url)
        self.assertIn("arm64", mieru_url)


class TestBuildServerConfig(unittest.TestCase):
    """_build_server_config — генерация серверного конфига."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_single_port(self):
        from vless_installer.modules.mieru import _build_server_config
        users = [{"username": "alice", "password": "pass1"}]
        cfg = _build_server_config(users, 2012, 2012, "TCP")
        self.assertEqual(len(cfg["portBindings"]), 1)
        self.assertEqual(cfg["portBindings"][0]["port"], 2012)
        self.assertEqual(cfg["portBindings"][0]["protocol"], "TCP")

    def test_port_range(self):
        from vless_installer.modules.mieru import _build_server_config
        users = [{"username": "alice", "password": "pass1"}]
        cfg = _build_server_config(users, 2012, 2022, "UDP")
        self.assertEqual(len(cfg["portBindings"]), 1)
        self.assertIn("portRange", cfg["portBindings"][0])
        self.assertEqual(cfg["portBindings"][0]["portRange"], "2012-2022")
        self.assertEqual(cfg["portBindings"][0]["protocol"], "UDP")

    def test_users_included(self):
        from vless_installer.modules.mieru import _build_server_config
        users = [{"username": "alice", "password": "p1"}, {"username": "bob", "password": "p2"}]
        cfg = _build_server_config(users, 2012, 2022, "TCP")
        self.assertEqual(len(cfg["users"]), 2)

    def test_logging_level_and_mtu(self):
        from vless_installer.modules.mieru import _build_server_config
        cfg = _build_server_config([], 2012, 2022, "TCP")
        self.assertEqual(cfg["loggingLevel"], "INFO")
        self.assertEqual(cfg["mtu"], 1400)


class TestGenSingboxOutbound(unittest.TestCase):
    """_gen_singbox_outbound — генерация sing-box outbound."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_dict_with_required_keys(self):
        from vless_installer.modules.mieru import _gen_singbox_outbound
        ob = _gen_singbox_outbound("1.2.3.4", 2012, 2022, "TCP", "alice", "pass")
        self.assertEqual(ob["type"], "mieru")
        self.assertEqual(ob["tag"], "mieru-alice")
        self.assertEqual(ob["server"], "1.2.3.4")
        self.assertEqual(ob["server_port"], 2012)
        self.assertEqual(ob["username"], "alice")
        self.assertEqual(ob["password"], "pass")

    def test_transport_uppercase(self):
        from vless_installer.modules.mieru import _gen_singbox_outbound
        ob = _gen_singbox_outbound("1.2.3.4", 2012, 2022, "tcp", "u", "p")
        self.assertEqual(ob["transport"], "TCP")

    def test_multiplexing_high(self):
        from vless_installer.modules.mieru import _gen_singbox_outbound
        ob = _gen_singbox_outbound("1.2.3.4", 2012, 2022, "TCP", "u", "p")
        self.assertEqual(ob["multiplexing"], "MULTIPLEXING_HIGH")


class TestGenClientShareLink(unittest.TestCase):
    """_gen_client_share_link — генерация mierus:// ссылки."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_mierus_url(self):
        from vless_installer.modules.mieru import _gen_client_share_link
        link = _gen_client_share_link("1.2.3.4", 2012, 2022, "TCP", "alice", "pass")
        self.assertTrue(link.startswith("mierus://"))

    def test_contains_credentials(self):
        from vless_installer.modules.mieru import _gen_client_share_link
        link = _gen_client_share_link("1.2.3.4", 2012, 2022, "TCP", "alice", "pass")
        self.assertIn("alice:pass", link)

    def test_contains_port_and_protocol(self):
        from vless_installer.modules.mieru import _gen_client_share_link
        link = _gen_client_share_link("1.2.3.4", 2012, 2022, "tcp", "u", "p")
        self.assertIn("port=2012", link)
        self.assertIn("protocol=TCP", link)

    def test_contains_mtu_and_multiplexing(self):
        from vless_installer.modules.mieru import _gen_client_share_link
        link = _gen_client_share_link("1.2.3.4", 2012, 2022, "TCP", "u", "p")
        self.assertIn("mtu=1400", link)
        self.assertIn("multiplexing=MULTIPLEXING_HIGH", link)


class TestGenClientShareLinkNekobox(unittest.TestCase):
    """_gen_client_share_link_nekobox — Nekobox формат."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_mierus_url(self):
        from vless_installer.modules.mieru import _gen_client_share_link_nekobox
        link = _gen_client_share_link_nekobox("1.2.3.4", 2012, "TCP", "alice", "pass")
        self.assertTrue(link.startswith("mierus://"))

    def test_contains_port_in_host_part(self):
        """Nekobox формат: host:PORT? а не ?port=PORT"""
        from vless_installer.modules.mieru import _gen_client_share_link_nekobox
        link = _gen_client_share_link_nekobox("1.2.3.4", 2012, "tcp", "u", "p")
        self.assertIn("1.2.3.4:2012", link)

    def test_contains_transport(self):
        from vless_installer.modules.mieru import _gen_client_share_link_nekobox
        link = _gen_client_share_link_nekobox("1.2.3.4", 2012, "tcp", "u", "p")
        self.assertIn("transport=TCP", link)


class TestIsAmd64(unittest.TestCase):
    """_is_amd64."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_x86_64(self):
        from vless_installer.modules.mieru import _is_amd64
        with patch("platform.machine", return_value="x86_64"):
            self.assertTrue(_is_amd64())

    def test_amd64(self):
        from vless_installer.modules.mieru import _is_amd64
        with patch("platform.machine", return_value="amd64"):
            self.assertTrue(_is_amd64())

    def test_aarch64(self):
        from vless_installer.modules.mieru import _is_amd64
        with patch("platform.machine", return_value="aarch64"):
            self.assertFalse(_is_amd64())


class TestReUsername(unittest.TestCase):
    """_RE_USERNAME — валидация имени."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_valid_names(self):
        from vless_installer.modules.mieru import _RE_USERNAME
        for name in ("alice", "bob123", "user-name", "user_name", "ABC"):
            with self.subTest(name=name):
                self.assertTrue(_RE_USERNAME.match(name))

    def test_invalid_names(self):
        from vless_installer.modules.mieru import _RE_USERNAME
        for name in ("", "user@name", "user.name", "user name", "пользователь"):
            with self.subTest(name=name):
                self.assertFalse(_RE_USERNAME.match(name))


if __name__ == "__main__":
    unittest.main(verbosity=2)
