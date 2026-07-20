#!/usr/bin/env python3
"""
tests/test_subscription_content_negotiation.py
───────────────────────────────────────────────────────────────────────────────
Тесты для content negotiation в единой подписке:
  _resolve_format, _filter_safe_links, build_subscription_singbox_config,
  _collect_registry_json_outbounds.
"""
from __future__ import annotations

import base64
import json
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


class TestResolveFormat(unittest.TestCase):
    """_resolve_format — определение формата подписки."""

    def setUp(self):
        _setup_core()

    def test_explicit_singbox(self):
        from chimera.modules import subscription
        self.assertEqual(subscription._resolve_format("singbox", ""), "singbox")
        self.assertEqual(subscription._resolve_format("sing-box", ""), "singbox")
        self.assertEqual(subscription._resolve_format("json", ""), "singbox")

    def test_explicit_base64(self):
        from chimera.modules import subscription
        self.assertEqual(subscription._resolve_format("base64", ""), "base64")
        self.assertEqual(subscription._resolve_format("auto", ""), "base64")
        self.assertEqual(subscription._resolve_format("default", ""), "base64")

    def test_explicit_safe(self):
        from chimera.modules import subscription
        self.assertEqual(subscription._resolve_format("safe", ""), "base64_safe")
        self.assertEqual(subscription._resolve_format("base64_safe", ""), "base64_safe")

    def test_default_when_no_param_no_ua(self):
        from chimera.modules import subscription
        self.assertEqual(subscription._resolve_format("", ""), "base64")

    def test_ua_nekobox(self):
        from chimera.modules import subscription
        self.assertEqual(subscription._resolve_format("", "NekoBox/1.0"), "singbox")

    def test_ua_karing(self):
        from chimera.modules import subscription
        self.assertEqual(subscription._resolve_format("", "Karing/1.2"), "base64_safe")

    def test_ua_unknown(self):
        from chimera.modules import subscription
        self.assertEqual(subscription._resolve_format("", "Mozilla/5.0"), "base64")

    def test_explicit_overrides_ua(self):
        """?format= имеет высший приоритет над User-Agent."""
        from chimera.modules import subscription
        # UA говорит singbox, но ?format=base64 — должно быть base64.
        self.assertEqual(subscription._resolve_format("base64", "NekoBox/1.0"), "base64")


class TestFilterSafeLinks(unittest.TestCase):
    """_filter_safe_links — фильтрация нераспознаваемых ссылок."""

    def setUp(self):
        _setup_core()

    def test_removes_naive(self):
        from chimera.modules import subscription
        links = ["vless://abc@host:443", "naive+https://user:pass@host:443/", "tg://proxy?server=host"]
        result = subscription._filter_safe_links(links)
        self.assertNotIn("naive+https://user:pass@host:443/", result)
        self.assertEqual(len(result), 2)

    def test_removes_mieru(self):
        from chimera.modules import subscription
        links = ["vless://abc", "mierus://user:pass@host", "trojan://pass@host"]
        result = subscription._filter_safe_links(links)
        self.assertNotIn("mierus://user:pass@host", result)
        self.assertEqual(len(result), 2)

    def test_keeps_valid_links(self):
        from chimera.modules import subscription
        links = ["vless://abc", "trojan://pass@host", "tg://proxy?server=host"]
        result = subscription._filter_safe_links(links)
        self.assertEqual(result, links)

    def test_empty_list(self):
        from chimera.modules import subscription
        self.assertEqual(subscription._filter_safe_links([]), [])


class TestBuildSubscriptionSingboxConfig(unittest.TestCase):
    """build_subscription_singbox_config — генерация sing-box JSON."""

    def setUp(self):
        _setup_core()

    def test_returns_json_string(self):
        from chimera.modules import subscription
        result = subscription.build_subscription_singbox_config({"uuid": "test", "email": "a@b.c"})
        self.assertIsInstance(result, str)
        # Должно парситься как JSON.
        config = json.loads(result)
        self.assertIsInstance(config, dict)

    def test_has_outbounds(self):
        from chimera.modules import subscription
        result = subscription.build_subscription_singbox_config({"uuid": "test", "email": "a@b.c"})
        config = json.loads(result)
        self.assertIn("outbounds", config)
        self.assertIsInstance(config["outbounds"], list)
        self.assertGreater(len(config["outbounds"]), 0)

    def test_has_direct_outbound(self):
        """Должен содержать как минимум direct outbound."""
        from chimera.modules import subscription
        result = subscription.build_subscription_singbox_config({"uuid": "test"})
        config = json.loads(result)
        types = [ob.get("type") for ob in config["outbounds"]]
        self.assertIn("direct", types)

    def test_has_route(self):
        from chimera.modules import subscription
        result = subscription.build_subscription_singbox_config({"uuid": "test"})
        config = json.loads(result)
        self.assertIn("route", config)
        self.assertIn("final", config["route"])

    def test_has_log(self):
        from chimera.modules import subscription
        result = subscription.build_subscription_singbox_config({"uuid": "test"})
        config = json.loads(result)
        self.assertIn("log", config)

    def test_never_throws(self):
        """Не должно бросать исключение даже при пустом user."""
        from chimera.modules import subscription
        result = subscription.build_subscription_singbox_config({})
        self.assertIsInstance(result, str)


class TestCollectRegistryJsonOutbounds(unittest.TestCase):
    """_collect_registry_json_outbounds — реестр JSON outbound'ов."""

    def setUp(self):
        _setup_core()

    def test_returns_list(self):
        from chimera.modules import subscription
        result = subscription._collect_registry_json_outbounds({"uuid": "test"})
        self.assertIsInstance(result, list)

    def test_handles_module_without_json_function(self):
        """Модуль без get_subscription_json_outbound — пропускается."""
        from chimera.modules import subscription
        fake_mod = types.ModuleType("chimera.modules._test_no_json")
        # Намеренно НЕ добавляем get_subscription_json_outbound.
        sys.modules["chimera.modules._test_no_json"] = fake_mod
        old_reg = subscription._SUBSCRIBABLE_PROTOCOLS
        subscription._SUBSCRIBABLE_PROTOCOLS = ["chimera.modules._test_no_json"]
        try:
            result = subscription._collect_registry_json_outbounds({"uuid": "test"})
        finally:
            subscription._SUBSCRIBABLE_PROTOCOLS = old_reg
            del sys.modules["chimera.modules._test_no_json"]
        self.assertEqual(result, [])

    def test_collects_from_module_with_json_function(self):
        from chimera.modules import subscription
        fake_mod = types.ModuleType("chimera.modules._test_with_json")
        fake_outbound = {"type": "test", "tag": "test-out"}
        fake_mod.get_subscription_json_outbound = MagicMock(return_value=fake_outbound)
        sys.modules["chimera.modules._test_with_json"] = fake_mod
        old_reg = subscription._SUBSCRIBABLE_PROTOCOLS
        subscription._SUBSCRIBABLE_PROTOCOLS = ["chimera.modules._test_with_json"]
        try:
            result = subscription._collect_registry_json_outbounds({"uuid": "test"})
        finally:
            subscription._SUBSCRIBABLE_PROTOCOLS = old_reg
            del sys.modules["chimera.modules._test_with_json"]
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "test")

    def test_handles_exception_in_json_function(self):
        """Exception из get_subscription_json_outbound — не роняет."""
        from chimera.modules import subscription
        broken = types.ModuleType("chimera.modules._test_broken_json")
        broken.get_subscription_json_outbound = MagicMock(side_effect=Exception("boom"))
        good = types.ModuleType("chimera.modules._test_good_json")
        good.get_subscription_json_outbound = MagicMock(return_value={"type": "good"})
        sys.modules["chimera.modules._test_broken_json"] = broken
        sys.modules["chimera.modules._test_good_json"] = good
        old_reg = subscription._SUBSCRIBABLE_PROTOCOLS
        subscription._SUBSCRIBABLE_PROTOCOLS = [
            "chimera.modules._test_broken_json",
            "chimera.modules._test_good_json",
        ]
        try:
            result = subscription._collect_registry_json_outbounds({"uuid": "test"})
        finally:
            subscription._SUBSCRIBABLE_PROTOCOLS = old_reg
            del sys.modules["chimera.modules._test_broken_json"]
            del sys.modules["chimera.modules._test_good_json"]
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "good")

    def test_handles_none_return(self):
        """None return — протокол пропускается."""
        from chimera.modules import subscription
        fake_mod = types.ModuleType("chimera.modules._test_none_json")
        fake_mod.get_subscription_json_outbound = MagicMock(return_value=None)
        sys.modules["chimera.modules._test_none_json"] = fake_mod
        old_reg = subscription._SUBSCRIBABLE_PROTOCOLS
        subscription._SUBSCRIBABLE_PROTOCOLS = ["chimera.modules._test_none_json"]
        try:
            result = subscription._collect_registry_json_outbounds({"uuid": "test"})
        finally:
            subscription._SUBSCRIBABLE_PROTOCOLS = old_reg
            del sys.modules["chimera.modules._test_none_json"]
        self.assertEqual(result, [])

    def test_handles_list_return(self):
        """List return — все outbound'ы добавляются."""
        from chimera.modules import subscription
        fake_mod = types.ModuleType("chimera.modules._test_list_json")
        fake_mod.get_subscription_json_outbound = MagicMock(
            return_value=[{"type": "a"}, {"type": "b"}])
        sys.modules["chimera.modules._test_list_json"] = fake_mod
        old_reg = subscription._SUBSCRIBABLE_PROTOCOLS
        subscription._SUBSCRIBABLE_PROTOCOLS = ["chimera.modules._test_list_json"]
        try:
            result = subscription._collect_registry_json_outbounds({"uuid": "test"})
        finally:
            subscription._SUBSCRIBABLE_PROTOCOLS = old_reg
            del sys.modules["chimera.modules._test_list_json"]
        self.assertEqual(len(result), 2)


class TestUaFormatMapExtensibility(unittest.TestCase):
    """_UA_FORMAT_MAP — словарь, легко расширяется."""

    def setUp(self):
        _setup_core()

    def test_is_dict(self):
        from chimera.modules import subscription
        self.assertIsInstance(subscription._UA_FORMAT_MAP, dict)

    def test_can_add_new_ua(self):
        from chimera.modules import subscription
        old_map = dict(subscription._UA_FORMAT_MAP)
        try:
            subscription._UA_FORMAT_MAP["v2rayng"] = "base64_safe"
            self.assertEqual(subscription._resolve_format("", "v2rayng/1.0"), "base64_safe")
        finally:
            subscription._UA_FORMAT_MAP.clear()
            subscription._UA_FORMAT_MAP.update(old_map)


if __name__ == "__main__":
    unittest.main(verbosity=2)
