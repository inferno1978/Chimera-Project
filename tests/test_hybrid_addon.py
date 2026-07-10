#!/usr/bin/env python3
"""
tests/test_hybrid_addon.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/hybrid_addon.py.

Модуль автономен (без _core). Тестируем:
  1. _detect_colors / _get_box_width / _plain / _wcslen
  2. gen_credentials — генерация логина/пароля
  3. build_mita_config — генерация конфига Mieru (tcp/udp/both + traffic_pattern)
  4. convert_inbound_to_socks_loopback — мутация inbound
  5. describe_inbound — форматированная строка
  6. find_vless_inbounds — фильтр по протоколу
  7. _traffic_pattern_basic / _traffic_pattern_aggressive
  8. _menu_status / save_state / load_state — JSON I/O
  9. detect_arch — определение архитектуры
  10. find_xray_config / load_json — поиск конфига Xray
"""
from __future__ import annotations

import json
import os
import platform
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


class TestDetectColors(unittest.TestCase):
    """_detect_colors."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_empty_when_not_tty(self):
        from vless_installer.modules import hybrid_addon
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = False
            c = hybrid_addon._detect_colors()
            for k in c.values():
                self.assertEqual(k, "")

    def test_returns_ansi_when_tty(self):
        from vless_installer.modules import hybrid_addon
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = True
            c = hybrid_addon._detect_colors()
            self.assertTrue(c["RED"].startswith("\033["))


class TestGetBoxWidth(unittest.TestCase):
    """_get_box_width."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_clamped_to_minimum_64(self):
        from vless_installer.modules import hybrid_addon
        with patch.dict(os.environ, {"COLUMNS": "40"}, clear=True), \
             patch("os.get_terminal_size", side_effect=OSError):
            self.assertEqual(hybrid_addon._get_box_width(), 64)

    def test_clamped_to_maximum_100(self):
        from vless_installer.modules import hybrid_addon
        with patch.dict(os.environ, {"COLUMNS": "500"}, clear=True), \
             patch("os.get_terminal_size",
                   return_value=os.terminal_size((500, 80))):
            self.assertEqual(hybrid_addon._get_box_width(), 100)


class TestPlain(unittest.TestCase):
    """_plain — strip ANSI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_plain_string_unchanged(self):
        from vless_installer.modules.hybrid_addon import _plain
        self.assertEqual(_plain("hello"), "hello")

    def test_strips_ansi(self):
        from vless_installer.modules.hybrid_addon import _plain
        self.assertEqual(_plain("\033[1;31mhi\033[0m"), "hi")


class TestWcslen(unittest.TestCase):
    """_wcslen — упрощённый подсчёт ширины."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ascii(self):
        from vless_installer.modules.hybrid_addon import _wcslen
        self.assertEqual(_wcslen("hello"), 5)

    def test_cjk_two_columns(self):
        from vless_installer.modules.hybrid_addon import _wcslen
        self.assertEqual(_wcslen("中文"), 4)

    def test_ansi_zero_width(self):
        from vless_installer.modules.hybrid_addon import _wcslen
        self.assertEqual(_wcslen("\033[1;31mhi\033[0m"), 2)

    def test_empty_string(self):
        from vless_installer.modules.hybrid_addon import _wcslen
        self.assertEqual(_wcslen(""), 0)


class TestGenCredentials(unittest.TestCase):
    """gen_credentials."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_tuple_of_two(self):
        from vless_installer.modules.hybrid_addon import gen_credentials
        login, pwd = gen_credentials()
        self.assertIsInstance(login, str)
        self.assertIsInstance(pwd, str)

    def test_login_has_u_prefix(self):
        from vless_installer.modules.hybrid_addon import gen_credentials
        login, _ = gen_credentials()
        self.assertTrue(login.startswith("u_"))

    def test_login_has_8_hex_chars_after_prefix(self):
        """u_ + 8 hex символов (4 байта token_hex(4))."""
        from vless_installer.modules.hybrid_addon import gen_credentials
        login, _ = gen_credentials()
        suffix = login[2:]
        self.assertEqual(len(suffix), 8)
        self.assertTrue(all(c in "0123456789abcdef" for c in suffix))

    def test_password_nonempty(self):
        from vless_installer.modules.hybrid_addon import gen_credentials
        _, pwd = gen_credentials()
        self.assertGreater(len(pwd), 10)

    def test_unique_on_multiple_calls(self):
        from vless_installer.modules.hybrid_addon import gen_credentials
        creds = {gen_credentials() for _ in range(10)}
        self.assertGreater(len(creds), 1)


class TestBuildMitaConfig(unittest.TestCase):
    """build_mita_config."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_tcp_only(self):
        from vless_installer.modules.hybrid_addon import build_mita_config
        cfg, creds = build_mita_config("tcp", 8443, 8444)
        self.assertEqual(len(cfg["portBindings"]), 1)
        self.assertEqual(cfg["portBindings"][0]["protocol"], "TCP")
        self.assertEqual(cfg["portBindings"][0]["port"], 8443)
        self.assertIn("tcp", creds)
        self.assertNotIn("udp", creds)
        self.assertEqual(len(cfg["users"]), 1)

    def test_udp_only(self):
        from vless_installer.modules.hybrid_addon import build_mita_config
        cfg, creds = build_mita_config("udp", 8443, 8444)
        self.assertEqual(len(cfg["portBindings"]), 1)
        self.assertEqual(cfg["portBindings"][0]["protocol"], "UDP")
        self.assertIn("udp", creds)
        self.assertNotIn("tcp", creds)

    def test_both_transports(self):
        from vless_installer.modules.hybrid_addon import build_mita_config
        cfg, creds = build_mita_config("both", 8443, 8444)
        self.assertEqual(len(cfg["portBindings"]), 2)
        self.assertEqual(len(cfg["users"]), 2)
        self.assertIn("tcp", creds)
        self.assertIn("udp", creds)

    def test_logging_level_info(self):
        from vless_installer.modules.hybrid_addon import build_mita_config
        cfg, _ = build_mita_config("tcp", 8443, 8444)
        self.assertEqual(cfg["loggingLevel"], "INFO")

    def test_egress_socks5_to_loopback(self):
        from vless_installer.modules.hybrid_addon import (
            build_mita_config, LOOPBACK_SOCKS_PORT,
        )
        cfg, _ = build_mita_config("tcp", 8443, 8444)
        proxy = cfg["egress"]["proxies"][0]
        self.assertEqual(proxy["protocol"], "SOCKS5_PROXY_PROTOCOL")
        self.assertEqual(proxy["host"], "127.0.0.1")
        self.assertEqual(proxy["port"], LOOPBACK_SOCKS_PORT)

    def test_egress_rule_proxy_all(self):
        from vless_installer.modules.hybrid_addon import build_mita_config
        cfg, _ = build_mita_config("tcp", 8443, 8444)
        rule = cfg["egress"]["rules"][0]
        self.assertEqual(rule["action"], "PROXY")
        self.assertIn("*", rule["ipRanges"])
        self.assertIn("*", rule["domainNames"])

    def test_traffic_pattern_added_when_provided(self):
        from vless_installer.modules.hybrid_addon import build_mita_config
        tp = {"nonce": {"type": "NONCE_TYPE_PRINTABLE"}}
        cfg, _ = build_mita_config("tcp", 8443, 8444, traffic_pattern=tp)
        self.assertIn("trafficPattern", cfg)
        self.assertEqual(cfg["trafficPattern"], tp)

    def test_traffic_pattern_omitted_when_none(self):
        from vless_installer.modules.hybrid_addon import build_mita_config
        cfg, _ = build_mita_config("tcp", 8443, 8444)
        self.assertNotIn("trafficPattern", cfg)

    def test_creds_have_login_password_port(self):
        from vless_installer.modules.hybrid_addon import build_mita_config
        _, creds = build_mita_config("both", 8443, 8444)
        for transport in ("tcp", "udp"):
            with self.subTest(transport=transport):
                self.assertIn("login", creds[transport])
                self.assertIn("password", creds[transport])
                self.assertIn("port", creds[transport])


class TestConvertInboundToSocksLoopback(unittest.TestCase):
    """convert_inbound_to_socks_loopback — мутация inbound."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_deep_copy_of_original(self):
        from vless_installer.modules.hybrid_addon import (
            convert_inbound_to_socks_loopback,
        )
        target = {
            "tag": "vless-in", "protocol": "vless",
            "listen": "0.0.0.0", "port": 443,
            "settings": {"clients": []},
        }
        original = convert_inbound_to_socks_loopback(target)
        self.assertEqual(original["protocol"], "vless")
        self.assertEqual(original["port"], 443)

    def test_mutates_target_to_socks(self):
        from vless_installer.modules.hybrid_addon import (
            convert_inbound_to_socks_loopback, LOOPBACK_SOCKS_PORT,
        )
        target = {
            "tag": "vless-in", "protocol": "vless",
            "listen": "0.0.0.0", "port": 443,
        }
        convert_inbound_to_socks_loopback(target)
        self.assertEqual(target["protocol"], "socks")
        self.assertEqual(target["listen"], "127.0.0.1")
        self.assertEqual(target["port"], LOOPBACK_SOCKS_PORT)
        self.assertEqual(target["settings"]["auth"], "noauth")
        self.assertTrue(target["settings"]["udp"])

    def test_preserves_tag(self):
        from vless_installer.modules.hybrid_addon import (
            convert_inbound_to_socks_loopback,
        )
        target = {"tag": "my-vless", "protocol": "vless"}
        convert_inbound_to_socks_loopback(target)
        self.assertEqual(target["tag"], "my-vless")

    def test_default_tag_when_missing(self):
        from vless_installer.modules.hybrid_addon import (
            convert_inbound_to_socks_loopback,
        )
        target = {"protocol": "vless"}
        convert_inbound_to_socks_loopback(target)
        self.assertEqual(target["tag"], "vless-in")

    def test_preserves_sniffing(self):
        from vless_installer.modules.hybrid_addon import (
            convert_inbound_to_socks_loopback,
        )
        sniffing = {"enabled": True, "destOverride": ["http", "tls"]}
        target = {"protocol": "vless", "sniffing": sniffing}
        convert_inbound_to_socks_loopback(target)
        self.assertEqual(target["sniffing"], sniffing)

    def test_no_sniffing_key_when_absent(self):
        from vless_installer.modules.hybrid_addon import (
            convert_inbound_to_socks_loopback,
        )
        target = {"protocol": "vless"}
        convert_inbound_to_socks_loopback(target)
        self.assertNotIn("sniffing", target)


class TestDescribeInbound(unittest.TestCase):
    """describe_inbound."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_includes_all_fields(self):
        from vless_installer.modules.hybrid_addon import describe_inbound
        ib = {
            "tag": "vless-in", "protocol": "vless",
            "listen": "0.0.0.0", "port": 443,
            "streamSettings": {"security": "reality", "network": "tcp"},
        }
        desc = describe_inbound(ib)
        self.assertIn("vless", desc)
        self.assertIn("443", desc)
        self.assertIn("reality", desc)
        self.assertIn("tcp", desc)

    def test_defaults_when_missing(self):
        from vless_installer.modules.hybrid_addon import describe_inbound
        desc = describe_inbound({})
        self.assertIn("без тега", desc)
        self.assertIn("0.0.0.0", desc)
        self.assertIn("none", desc)  # security default
        self.assertIn("tcp", desc)  # network default


class TestFindVlessInbounds(unittest.TestCase):
    """find_vless_inbounds."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_empty_when_no_inbounds(self):
        from vless_installer.modules.hybrid_addon import find_vless_inbounds
        self.assertEqual(find_vless_inbounds({}), [])

    def test_returns_only_vless(self):
        from vless_installer.modules.hybrid_addon import find_vless_inbounds
        cfg = {"inbounds": [
            {"tag": "a", "protocol": "vless"},
            {"tag": "b", "protocol": "vmess"},
            {"tag": "c", "protocol": "vless"},
        ]}
        result = find_vless_inbounds(cfg)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["tag"], "a")
        self.assertEqual(result[1]["tag"], "c")

    def test_returns_empty_when_no_vless(self):
        from vless_installer.modules.hybrid_addon import find_vless_inbounds
        cfg = {"inbounds": [{"protocol": "vmess"}]}
        self.assertEqual(find_vless_inbounds(cfg), [])


class TestTrafficPatterns(unittest.TestCase):
    """_traffic_pattern_basic / _traffic_pattern_aggressive."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_basic_has_nonce(self):
        from vless_installer.modules.hybrid_addon import _traffic_pattern_basic
        tp = _traffic_pattern_basic()
        self.assertIn("nonce", tp)
        self.assertEqual(tp["nonce"]["type"], "NONCE_TYPE_PRINTABLE")

    def test_basic_no_tcp_fragment(self):
        from vless_installer.modules.hybrid_addon import _traffic_pattern_basic
        tp = _traffic_pattern_basic()
        self.assertNotIn("tcpFragment", tp)

    def test_aggressive_has_tcp_fragment(self):
        from vless_installer.modules.hybrid_addon import _traffic_pattern_aggressive
        tp = _traffic_pattern_aggressive()
        self.assertIn("tcpFragment", tp)
        self.assertTrue(tp["tcpFragment"]["enable"])
        self.assertIn("maxSleepMs", tp["tcpFragment"])

    def test_aggressive_has_nonce(self):
        from vless_installer.modules.hybrid_addon import _traffic_pattern_aggressive
        tp = _traffic_pattern_aggressive()
        self.assertIn("nonce", tp)


class TestMenuStatus(unittest.TestCase):
    """_menu_status — чтение state с fallback."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "hybrid_state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.hybrid_addon.STATE_FILE", self._state)

    def test_returns_not_installed_when_no_file(self):
        from vless_installer.modules.hybrid_addon import _menu_status
        with self._patch():
            result = _menu_status()
        self.assertFalse(result["installed"])

    def test_returns_state_when_valid(self):
        from vless_installer.modules.hybrid_addon import _menu_status
        self._state.write_text(json.dumps({"version": "1.0", "tcp_port": 8443}))
        with self._patch():
            result = _menu_status()
        self.assertTrue(result["installed"])
        self.assertEqual(result["version"], "1.0")
        self.assertEqual(result["tcp_port"], 8443)

    def test_returns_corrupt_when_invalid_json(self):
        from vless_installer.modules.hybrid_addon import _menu_status
        self._state.write_text("{invalid")
        with self._patch():
            result = _menu_status()
        self.assertFalse(result["installed"])
        self.assertTrue(result.get("corrupt"))


class TestSaveLoadState(unittest.TestCase):
    """save_state / load_state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "hybrid_state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("vless_installer.modules.hybrid_addon.STATE_FILE", self._state),
            patch("vless_installer.modules.hybrid_addon.STATE_DIR", self._tmpdir),
        )

    def test_save_then_load(self):
        from vless_installer.modules.hybrid_addon import save_state, load_state
        data = {"version": "1.0", "installed_at": "2026-07-10"}
        with self._patch()[0], self._patch()[1]:
            save_state(data)
            loaded = load_state()
        self.assertEqual(loaded, data)

    def test_load_raises_when_no_file(self):
        """load_state вызывает die() (sys.exit) при отсутствии файла."""
        from vless_installer.modules.hybrid_addon import load_state
        with self._patch()[0], self._patch()[1]:
            with self.assertRaises(SystemExit):
                load_state()


class TestDetectArch(unittest.TestCase):
    """detect_arch."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_x86_64_returns_amd64(self):
        from vless_installer.modules import hybrid_addon
        with patch("platform.machine", return_value="x86_64"):
            self.assertEqual(hybrid_addon.detect_arch(), "amd64")

    def test_amd64_returns_amd64(self):
        from vless_installer.modules import hybrid_addon
        with patch("platform.machine", return_value="amd64"):
            self.assertEqual(hybrid_addon.detect_arch(), "amd64")

    def test_aarch64_returns_arm64(self):
        from vless_installer.modules import hybrid_addon
        with patch("platform.machine", return_value="aarch64"):
            self.assertEqual(hybrid_addon.detect_arch(), "arm64")

    def test_arm64_returns_arm64(self):
        from vless_installer.modules import hybrid_addon
        with patch("platform.machine", return_value="arm64"):
            self.assertEqual(hybrid_addon.detect_arch(), "arm64")

    def test_unsupported_arch_raises(self):
        from vless_installer.modules import hybrid_addon
        with patch("platform.machine", return_value="mips"):
            with self.assertRaises(SystemExit):
                hybrid_addon.detect_arch()


class TestFindXrayConfig(unittest.TestCase):
    """find_xray_config."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_first_existing(self):
        from vless_installer.modules import hybrid_addon
        path1 = self._tmpdir / "config1.json"
        path1.write_text("{}")
        with patch.object(hybrid_addon, "XRAY_CONFIG_CANDIDATES",
                          [path1, Path("/nonexistent")]):
            self.assertEqual(hybrid_addon.find_xray_config(), path1)

    def test_raises_when_no_existing(self):
        from vless_installer.modules import hybrid_addon
        with patch.object(hybrid_addon, "XRAY_CONFIG_CANDIDATES",
                          [Path("/nonexistent1"), Path("/nonexistent2")]):
            with self.assertRaises(SystemExit):
                hybrid_addon.find_xray_config()


class TestLoadJson(unittest.TestCase):
    """load_json."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_loads_valid_json(self):
        from vless_installer.modules.hybrid_addon import load_json
        path = self._tmpdir / "x.json"
        path.write_text(json.dumps({"key": "value"}))
        self.assertEqual(load_json(path), {"key": "value"})

    def test_raises_on_corrupt(self):
        from vless_installer.modules.hybrid_addon import load_json
        path = self._tmpdir / "x.json"
        path.write_text("{invalid")
        with self.assertRaises(SystemExit):
            load_json(path)


class TestCaptureRestoreOwnerMode(unittest.TestCase):
    """_capture_owner_mode / _restore_owner_mode."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_capture_returns_uid_gid_mode(self):
        import stat as _stat
        from vless_installer.modules.hybrid_addon import _capture_owner_mode
        path = self._tmpdir / "f"
        path.write_text("x")
        om = _capture_owner_mode(path)
        self.assertIn("uid", om)
        self.assertIn("gid", om)
        self.assertIn("mode", om)
        self.assertIsInstance(om["mode"], int)

    def test_restore_applies_chmod(self):
        """_restore_owner_mode восстанавливает права (chown мокаем, нужен root)."""
        import os
        import stat as _stat
        from vless_installer.modules.hybrid_addon import _restore_owner_mode
        path = self._tmpdir / "f"
        path.write_text("x")
        # chown мокаем (нужен root)
        with patch("os.chown"):
            _restore_owner_mode(path, {"uid": 0, "gid": 0, "mode": 0o644})
        mode = _stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode, 0o644)

    def test_restore_silently_fails_on_oserror(self):
        """При OSError — не должно бросать, только печатать предупреждение."""
        from vless_installer.modules.hybrid_addon import _restore_owner_mode
        path = self._tmpdir / "f"
        path.write_text("x")
        with patch("os.chown", side_effect=OSError("permission denied")):
            # не должно бросать
            _restore_owner_mode(path, {"uid": 0, "gid": 0, "mode": 0o644})


if __name__ == "__main__":
    unittest.main(verbosity=2)
