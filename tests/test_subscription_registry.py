#!/usr/bin/env python3
"""
tests/test_subscription_registry.py
───────────────────────────────────────────────────────────────────────────────
Тесты для реестра сателлитных протоколов в subscription.py:
  _SUBSCRIBABLE_PROTOCOLS, _collect_registry_uris.

А также тесты для get_subscription_uris в singbox_menu.py и trusttunnel.py.
"""
from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core


class TestSubscribableRegistry(unittest.TestCase):
    """_SUBSCRIBABLE_PROTOCOLS реестр."""

    def setUp(self):
        _setup_core()

    def test_registry_contains_expected_modules(self):
        from chimera.modules import subscription
        self.assertIn("chimera.modules.trusttunnel", subscription._SUBSCRIBABLE_PROTOCOLS)
        self.assertIn("chimera.modules.singbox_menu", subscription._SUBSCRIBABLE_PROTOCOLS)

    def test_collect_registry_uris_returns_list(self):
        """_collect_registry_uris возвращает list (может быть пустым)."""
        from chimera.modules import subscription
        result = subscription._collect_registry_uris({"uuid": "test", "email": "a@b.c"})
        self.assertIsInstance(result, list)

    def test_collect_registry_uris_with_fake_module(self):
        """Фейковый модуль в реестре — его URIs добавляются."""
        from chimera.modules import subscription
        # Создаём фейковый модуль.
        fake_mod = types.ModuleType("chimera.modules._test_fake_sub")
        fake_mod.get_subscription_uris = MagicMock(return_value=["fake://uri1", "fake://uri2"])
        sys.modules["chimera.modules._test_fake_sub"] = fake_mod
        old_reg = subscription._SUBSCRIBABLE_PROTOCOLS
        subscription._SUBSCRIBABLE_PROTOCOLS = ["chimera.modules._test_fake_sub"]
        try:
            result = subscription._collect_registry_uris({"uuid": "test"})
        finally:
            subscription._SUBSCRIBABLE_PROTOCOLS = old_reg
            del sys.modules["chimera.modules._test_fake_sub"]
        self.assertEqual(result, ["fake://uri1", "fake://uri2"])

    def test_collect_registry_uris_handles_import_error(self):
        """ImportError на несуществующий модуль — не роняет, возвращает []."""
        from chimera.modules import subscription
        old_reg = subscription._SUBSCRIBABLE_PROTOCOLS
        subscription._SUBSCRIBABLE_PROTOCOLS = ["chimera.modules.nonexistent_proto"]
        try:
            result = subscription._collect_registry_uris({"uuid": "test"})
        finally:
            subscription._SUBSCRIBABLE_PROTOCOLS = old_reg
        self.assertEqual(result, [])

    def test_collect_registry_uris_handles_exception(self):
        """Exception из get_subscription_uris — не роняет другие модули."""
        from chimera.modules import subscription
        # Первый модуль бросает, второй — работает.
        broken = types.ModuleType("chimera.modules._test_broken_sub")
        broken.get_subscription_uris = MagicMock(side_effect=Exception("boom"))
        good = types.ModuleType("chimera.modules._test_good_sub")
        good.get_subscription_uris = MagicMock(return_value=["good://uri"])
        sys.modules["chimera.modules._test_broken_sub"] = broken
        sys.modules["chimera.modules._test_good_sub"] = good
        old_reg = subscription._SUBSCRIBABLE_PROTOCOLS
        subscription._SUBSCRIBABLE_PROTOCOLS = [
            "chimera.modules._test_broken_sub",
            "chimera.modules._test_good_sub",
        ]
        try:
            result = subscription._collect_registry_uris({"uuid": "test"})
        finally:
            subscription._SUBSCRIBABLE_PROTOCOLS = old_reg
            del sys.modules["chimera.modules._test_broken_sub"]
            del sys.modules["chimera.modules._test_good_sub"]
        self.assertEqual(result, ["good://uri"])


class TestSingboxMenuGetSubscriptionUris(unittest.TestCase):
    """singbox_menu.get_subscription_uris(user) — public API."""

    def setUp(self):
        _setup_core()

    def test_returns_list(self):
        from chimera.modules import singbox_menu
        result = singbox_menu.get_subscription_uris({"uuid": "test", "email": "a@b.c"})
        self.assertIsInstance(result, list)

    def test_returns_empty_when_no_state(self):
        """Нет singbox state — возвращается []."""
        from chimera.modules import singbox_menu
        with patch("chimera.modules.singbox_menu.singbox_state_load", return_value={}):
            result = singbox_menu.get_subscription_uris({"uuid": "test"})
        self.assertEqual(result, [])

    def test_returns_empty_when_no_inbounds(self):
        from chimera.modules import singbox_menu
        with patch("chimera.modules.singbox_menu.singbox_state_load",
                   return_value={"inbounds": {}}):
            result = singbox_menu.get_subscription_uris({"uuid": "test"})
        self.assertEqual(result, [])

    def test_returns_empty_when_protocol_disabled(self):
        from chimera.modules import singbox_menu
        state = {"inbounds": {"shadowtls": {"enabled": False, "users": []}}}
        with patch("chimera.modules.singbox_menu.singbox_state_load", return_value=state):
            result = singbox_menu.get_subscription_uris({"uuid": "test"})
        self.assertEqual(result, [])

    def test_returns_empty_when_no_user_match(self):
        """Если у юзера нет matching credential — возвращается [] (не чужой пароль)."""
        from chimera.modules import singbox_menu
        state = {
            "inbounds": {
                "shadowtls": {
                    "enabled": True,
                    "listen": "0.0.0.0",
                    "listen_port": 8443,
                    "handshake": {"server": "www.cloudflare.com"},
                    "users": [{"uuid": "other-uuid", "password": "other-pw", "name": "other"}],
                }
            }
        }
        with patch("chimera.modules.singbox_menu.singbox_state_load", return_value=state), \
             patch("chimera.modules.singbox_menu._get_public_endpoint",
                   return_value=("1.2.3.4", 8443, False)):
            result = singbox_menu.get_subscription_uris({"uuid": "my-uuid", "name": "alice"})
        self.assertEqual(result, [])

    def test_returns_uri_when_user_matches_by_name(self):
        from chimera.modules import singbox_menu
        state = {
            "inbounds": {
                "shadowtls": {
                    "enabled": True,
                    "listen": "0.0.0.0",
                    "listen_port": 8443,
                    "handshake": {"server": "www.cloudflare.com"},
                    "users": [{"uuid": "test-uuid", "password": "mypw", "name": "alice"}],
                }
            }
        }
        with patch("chimera.modules.singbox_menu.singbox_state_load", return_value=state), \
             patch("chimera.modules.singbox_menu._get_public_endpoint",
                   return_value=("1.2.3.4", 8443, False)):
            result = singbox_menu.get_subscription_uris({"uuid": "test-uuid", "name": "alice"})
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0].startswith("trojan://"))

    def test_returns_vless_ws_cdn_for_all_users(self):
        """VLESS-WS-CDN не имеет per-user — отдаётся всем."""
        from chimera.modules import singbox_menu
        state = {
            "inbounds": {
                "vless_ws_cdn": {
                    "enabled": True,
                    "uuid": "shared-uuid",
                    "host": "cdn.example.com",
                    "ws_path": "/ws",
                }
            }
        }
        with patch("chimera.modules.singbox_menu.singbox_state_load", return_value=state):
            result = singbox_menu.get_subscription_uris({"uuid": "any-user"})
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0].startswith("vless://"))


class TestTrustTunnelGetSubscriptionUris(unittest.TestCase):
    """trusttunnel.get_subscription_uris(user) — public API."""

    def setUp(self):
        _setup_core()

    def test_returns_list(self):
        from chimera.modules import trusttunnel
        result = trusttunnel.get_subscription_uris({"uuid": "test", "email": "a@b.c"})
        self.assertIsInstance(result, list)

    def test_returns_empty_when_no_email(self):
        from chimera.modules import trusttunnel
        result = trusttunnel.get_subscription_uris({"uuid": "test"})
        self.assertEqual(result, [])

    def test_returns_empty_when_no_uuid(self):
        from chimera.modules import trusttunnel
        result = trusttunnel.get_subscription_uris({"email": "a@b.c"})
        self.assertEqual(result, [])

    def test_returns_empty_when_not_installed(self):
        from chimera.modules import trusttunnel
        with patch("chimera.modules.trusttunnel.trusttunnel_load_state",
                   return_value={"installed": False}):
            result = trusttunnel.get_subscription_uris({"uuid": "test", "email": "a@b.c"})
        self.assertEqual(result, [])

    def test_returns_uri_when_installed_and_user_exists(self):
        from chimera.modules import trusttunnel
        state = {"installed": True, "domain": "tt.example.com", "listen_port": 443}
        with patch("chimera.modules.trusttunnel.trusttunnel_load_state",
                   return_value=state), \
             patch("chimera.modules.trusttunnel.trusttunnel_user_exists",
                   return_value=True), \
             patch("chimera.modules.trusttunnel.trusttunnel_derive_password",
                   return_value="derived-pw"), \
             patch("chimera.modules.trusttunnel.trusttunnel_deeplink_encode",
                   return_value="tt://fake-deeplink"):
            result = trusttunnel.get_subscription_uris({"uuid": "test", "email": "a@b.c"})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], "tt://fake-deeplink")


class TestFindSingboxUserCredential(unittest.TestCase):
    """_find_singbox_user_credential — per-user matching."""

    def setUp(self):
        _setup_core()

    def test_returns_none_when_no_users(self):
        from chimera.modules import singbox_menu
        self.assertIsNone(singbox_menu._find_singbox_user_credential({}, {"alice"}))

    def test_returns_first_when_no_candidates(self):
        """TUI-режим (нет candidates) — обратная совместимость: users[0]."""
        from chimera.modules import singbox_menu
        users = [{"uuid": "u1", "password": "pw1", "name": "alice"},
                 {"uuid": "u2", "password": "pw2", "name": "bob"}]
        result = singbox_menu._find_singbox_user_credential({"users": users})
        self.assertEqual(result["uuid"], "u1")

    def test_matches_by_uuid(self):
        from chimera.modules import singbox_menu
        users = [{"uuid": "abc-123", "password": "pw1", "name": "alice"},
                 {"uuid": "def-456", "password": "pw2", "name": "bob"}]
        result = singbox_menu._find_singbox_user_credential(
            {"users": users}, {"def-456"})
        self.assertEqual(result["name"], "bob")

    def test_matches_by_name(self):
        from chimera.modules import singbox_menu
        users = [{"uuid": "u1", "password": "pw1", "name": "alice"},
                 {"uuid": "u2", "password": "pw2", "name": "bob"}]
        result = singbox_menu._find_singbox_user_credential(
            {"users": users}, {"bob"})
        self.assertEqual(result["name"], "bob")

    def test_returns_none_when_no_match(self):
        from chimera.modules import singbox_menu
        users = [{"uuid": "u1", "password": "pw1", "name": "alice"}]
        result = singbox_menu._find_singbox_user_credential(
            {"users": users}, {"charlie"})
        self.assertIsNone(result)

    def test_case_insensitive_name_match(self):
        from chimera.modules import singbox_menu
        users = [{"uuid": "u1", "password": "pw1", "name": "Alice"}]
        result = singbox_menu._find_singbox_user_credential(
            {"users": users}, {"alice"})
        self.assertEqual(result["name"], "Alice")


if __name__ == "__main__":
    unittest.main(verbosity=2)
