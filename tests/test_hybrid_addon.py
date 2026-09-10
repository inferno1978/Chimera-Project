#!/usr/bin/env python3
"""
tests/test_hybrid_addon.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/hybrid_addon.py.

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

import io
import json
import os
import platform
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

# ANSI-коды в выводе (срезаем в тестах захвата stdout)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


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


class TestDetectColors(unittest.TestCase):
    """_detect_colors."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_empty_when_not_tty(self):
        from chimera.modules import hybrid_addon
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = False
            c = hybrid_addon._detect_colors()
            for k in c.values():
                self.assertEqual(k, "")

    def test_returns_ansi_when_tty(self):
        from chimera.modules import hybrid_addon
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = True
            c = hybrid_addon._detect_colors()
            self.assertTrue(c["RED"].startswith("\033["))


class TestGetBoxWidth(unittest.TestCase):
    """_get_box_width."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_clamped_to_minimum_64(self):
        from chimera.modules import hybrid_addon
        with patch.dict(os.environ, {"COLUMNS": "40"}, clear=True), \
             patch("os.get_terminal_size", side_effect=OSError):
            self.assertEqual(hybrid_addon._get_box_width(), 64)

    def test_clamped_to_maximum_100(self):
        from chimera.modules import hybrid_addon
        with patch.dict(os.environ, {"COLUMNS": "500"}, clear=True), \
             patch("os.get_terminal_size",
                   return_value=os.terminal_size((500, 80))):
            self.assertEqual(hybrid_addon._get_box_width(), 100)


class TestPlain(unittest.TestCase):
    """_plain — strip ANSI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_plain_string_unchanged(self):
        from chimera.modules.hybrid_addon import _plain
        self.assertEqual(_plain("hello"), "hello")

    def test_strips_ansi(self):
        from chimera.modules.hybrid_addon import _plain
        self.assertEqual(_plain("\033[1;31mhi\033[0m"), "hi")


class TestWcslen(unittest.TestCase):
    """_wcslen — упрощённый подсчёт ширины."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ascii(self):
        from chimera.modules.hybrid_addon import _wcslen
        self.assertEqual(_wcslen("hello"), 5)

    def test_cjk_two_columns(self):
        from chimera.modules.hybrid_addon import _wcslen
        self.assertEqual(_wcslen("中文"), 4)

    def test_ansi_zero_width(self):
        from chimera.modules.hybrid_addon import _wcslen
        self.assertEqual(_wcslen("\033[1;31mhi\033[0m"), 2)

    def test_empty_string(self):
        from chimera.modules.hybrid_addon import _wcslen
        self.assertEqual(_wcslen(""), 0)


class TestGenCredentials(unittest.TestCase):
    """gen_credentials."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_tuple_of_two(self):
        from chimera.modules.hybrid_addon import gen_credentials
        login, pwd = gen_credentials()
        self.assertIsInstance(login, str)
        self.assertIsInstance(pwd, str)

    def test_login_has_u_prefix(self):
        from chimera.modules.hybrid_addon import gen_credentials
        login, _ = gen_credentials()
        self.assertTrue(login.startswith("u_"))

    def test_login_has_8_hex_chars_after_prefix(self):
        """u_ + 8 hex символов (4 байта token_hex(4))."""
        from chimera.modules.hybrid_addon import gen_credentials
        login, _ = gen_credentials()
        suffix = login[2:]
        self.assertEqual(len(suffix), 8)
        self.assertTrue(all(c in "0123456789abcdef" for c in suffix))

    def test_password_nonempty(self):
        from chimera.modules.hybrid_addon import gen_credentials
        _, pwd = gen_credentials()
        self.assertGreater(len(pwd), 10)

    def test_unique_on_multiple_calls(self):
        from chimera.modules.hybrid_addon import gen_credentials
        creds = {gen_credentials() for _ in range(10)}
        self.assertGreater(len(creds), 1)


class TestBuildMitaConfig(unittest.TestCase):
    """build_mita_config."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_tcp_only(self):
        from chimera.modules.hybrid_addon import build_mita_config
        cfg, creds = build_mita_config("tcp", 8443, 8444)
        self.assertEqual(len(cfg["portBindings"]), 1)
        self.assertEqual(cfg["portBindings"][0]["protocol"], "TCP")
        self.assertEqual(cfg["portBindings"][0]["port"], 8443)
        self.assertIn("tcp", creds)
        self.assertNotIn("udp", creds)
        self.assertEqual(len(cfg["users"]), 1)

    def test_udp_only(self):
        from chimera.modules.hybrid_addon import build_mita_config
        cfg, creds = build_mita_config("udp", 8443, 8444)
        self.assertEqual(len(cfg["portBindings"]), 1)
        self.assertEqual(cfg["portBindings"][0]["protocol"], "UDP")
        self.assertIn("udp", creds)
        self.assertNotIn("tcp", creds)

    def test_both_transports(self):
        from chimera.modules.hybrid_addon import build_mita_config
        cfg, creds = build_mita_config("both", 8443, 8444)
        self.assertEqual(len(cfg["portBindings"]), 2)
        self.assertEqual(len(cfg["users"]), 2)
        self.assertIn("tcp", creds)
        self.assertIn("udp", creds)

    def test_logging_level_info(self):
        from chimera.modules.hybrid_addon import build_mita_config
        cfg, _ = build_mita_config("tcp", 8443, 8444)
        self.assertEqual(cfg["loggingLevel"], "INFO")

    def test_egress_socks5_to_loopback(self):
        from chimera.modules.hybrid_addon import (
            build_mita_config, LOOPBACK_SOCKS_PORT,
        )
        cfg, _ = build_mita_config("tcp", 8443, 8444)
        proxy = cfg["egress"]["proxies"][0]
        self.assertEqual(proxy["protocol"], "SOCKS5_PROXY_PROTOCOL")
        self.assertEqual(proxy["host"], "127.0.0.1")
        self.assertEqual(proxy["port"], LOOPBACK_SOCKS_PORT)

    def test_egress_rule_proxy_all(self):
        from chimera.modules.hybrid_addon import build_mita_config
        cfg, _ = build_mita_config("tcp", 8443, 8444)
        rule = cfg["egress"]["rules"][0]
        self.assertEqual(rule["action"], "PROXY")
        self.assertIn("*", rule["ipRanges"])
        self.assertIn("*", rule["domainNames"])

    def test_traffic_pattern_added_when_provided(self):
        from chimera.modules.hybrid_addon import build_mita_config
        tp = {"nonce": {"type": "NONCE_TYPE_PRINTABLE"}}
        cfg, _ = build_mita_config("tcp", 8443, 8444, traffic_pattern=tp)
        self.assertIn("trafficPattern", cfg)
        self.assertEqual(cfg["trafficPattern"], tp)

    def test_traffic_pattern_omitted_when_none(self):
        from chimera.modules.hybrid_addon import build_mita_config
        cfg, _ = build_mita_config("tcp", 8443, 8444)
        self.assertNotIn("trafficPattern", cfg)

    def test_creds_have_login_password_port(self):
        from chimera.modules.hybrid_addon import build_mita_config
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
        from chimera.modules.hybrid_addon import (
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
        from chimera.modules.hybrid_addon import (
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
        from chimera.modules.hybrid_addon import (
            convert_inbound_to_socks_loopback,
        )
        target = {"tag": "my-vless", "protocol": "vless"}
        convert_inbound_to_socks_loopback(target)
        self.assertEqual(target["tag"], "my-vless")

    def test_default_tag_when_missing(self):
        from chimera.modules.hybrid_addon import (
            convert_inbound_to_socks_loopback,
        )
        target = {"protocol": "vless"}
        convert_inbound_to_socks_loopback(target)
        self.assertEqual(target["tag"], "vless-in")

    def test_preserves_sniffing(self):
        from chimera.modules.hybrid_addon import (
            convert_inbound_to_socks_loopback,
        )
        sniffing = {"enabled": True, "destOverride": ["http", "tls"]}
        target = {"protocol": "vless", "sniffing": sniffing}
        convert_inbound_to_socks_loopback(target)
        self.assertEqual(target["sniffing"], sniffing)

    def test_no_sniffing_key_when_absent(self):
        from chimera.modules.hybrid_addon import (
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
        from chimera.modules.hybrid_addon import describe_inbound
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
        from chimera.modules.hybrid_addon import describe_inbound
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
        from chimera.modules.hybrid_addon import find_vless_inbounds
        self.assertEqual(find_vless_inbounds({}), [])

    def test_returns_only_vless(self):
        from chimera.modules.hybrid_addon import find_vless_inbounds
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
        from chimera.modules.hybrid_addon import find_vless_inbounds
        cfg = {"inbounds": [{"protocol": "vmess"}]}
        self.assertEqual(find_vless_inbounds(cfg), [])


class TestTrafficPatterns(unittest.TestCase):
    """_traffic_pattern_basic / _traffic_pattern_aggressive."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_basic_has_nonce(self):
        from chimera.modules.hybrid_addon import _traffic_pattern_basic
        tp = _traffic_pattern_basic()
        self.assertIn("nonce", tp)
        self.assertEqual(tp["nonce"]["type"], "NONCE_TYPE_PRINTABLE")

    def test_basic_no_tcp_fragment(self):
        from chimera.modules.hybrid_addon import _traffic_pattern_basic
        tp = _traffic_pattern_basic()
        self.assertNotIn("tcpFragment", tp)

    def test_aggressive_has_tcp_fragment(self):
        from chimera.modules.hybrid_addon import _traffic_pattern_aggressive
        tp = _traffic_pattern_aggressive()
        self.assertIn("tcpFragment", tp)
        self.assertTrue(tp["tcpFragment"]["enable"])
        self.assertIn("maxSleepMs", tp["tcpFragment"])

    def test_aggressive_has_nonce(self):
        from chimera.modules.hybrid_addon import _traffic_pattern_aggressive
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
        return patch("chimera.modules.hybrid_addon.STATE_FILE", self._state)

    def test_returns_not_installed_when_no_file(self):
        from chimera.modules.hybrid_addon import _menu_status
        with self._patch():
            result = _menu_status()
        self.assertFalse(result["installed"])

    def test_returns_state_when_valid(self):
        from chimera.modules.hybrid_addon import _menu_status
        self._state.write_text(json.dumps({"version": "1.0", "tcp_port": 8443}))
        with self._patch():
            result = _menu_status()
        self.assertTrue(result["installed"])
        self.assertEqual(result["version"], "1.0")
        self.assertEqual(result["tcp_port"], 8443)

    def test_returns_corrupt_when_invalid_json(self):
        from chimera.modules.hybrid_addon import _menu_status
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
            patch("chimera.modules.hybrid_addon.STATE_FILE", self._state),
            patch("chimera.modules.hybrid_addon.STATE_DIR", self._tmpdir),
        )

    def test_save_then_load(self):
        from chimera.modules.hybrid_addon import save_state, load_state
        data = {"version": "1.0", "installed_at": "2026-07-10"}
        with self._patch()[0], self._patch()[1]:
            save_state(data)
            loaded = load_state()
        self.assertEqual(loaded, data)

    def test_load_raises_when_no_file(self):
        """load_state вызывает die() (sys.exit) при отсутствии файла."""
        from chimera.modules.hybrid_addon import load_state
        with self._patch()[0], self._patch()[1]:
            with self.assertRaises(SystemExit):
                load_state()


class TestDetectArch(unittest.TestCase):
    """detect_arch."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_x86_64_returns_amd64(self):
        from chimera.modules import hybrid_addon
        with patch("platform.machine", return_value="x86_64"):
            self.assertEqual(hybrid_addon.detect_arch(), "amd64")

    def test_amd64_returns_amd64(self):
        from chimera.modules import hybrid_addon
        with patch("platform.machine", return_value="amd64"):
            self.assertEqual(hybrid_addon.detect_arch(), "amd64")

    def test_aarch64_returns_arm64(self):
        from chimera.modules import hybrid_addon
        with patch("platform.machine", return_value="aarch64"):
            self.assertEqual(hybrid_addon.detect_arch(), "arm64")

    def test_arm64_returns_arm64(self):
        from chimera.modules import hybrid_addon
        with patch("platform.machine", return_value="arm64"):
            self.assertEqual(hybrid_addon.detect_arch(), "arm64")

    def test_unsupported_arch_raises(self):
        from chimera.modules import hybrid_addon
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
        from chimera.modules import hybrid_addon
        path1 = self._tmpdir / "config1.json"
        path1.write_text("{}")
        with patch.object(hybrid_addon, "XRAY_CONFIG_CANDIDATES",
                          [path1, Path("/nonexistent")]):
            self.assertEqual(hybrid_addon.find_xray_config(), path1)

    def test_raises_when_no_existing(self):
        from chimera.modules import hybrid_addon
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
        from chimera.modules.hybrid_addon import load_json
        path = self._tmpdir / "x.json"
        path.write_text(json.dumps({"key": "value"}))
        self.assertEqual(load_json(path), {"key": "value"})

    def test_raises_on_corrupt(self):
        from chimera.modules.hybrid_addon import load_json
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
        from chimera.modules.hybrid_addon import _capture_owner_mode
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
        from chimera.modules.hybrid_addon import _restore_owner_mode
        path = self._tmpdir / "f"
        path.write_text("x")
        # chown мокаем (нужен root)
        with patch("os.chown"):
            _restore_owner_mode(path, {"uid": 0, "gid": 0, "mode": 0o644})
        mode = _stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode, 0o644)

    def test_restore_silently_fails_on_oserror(self):
        """При OSError — не должно бросать, только печатать предупреждение."""
        from chimera.modules.hybrid_addon import _restore_owner_mode
        path = self._tmpdir / "f"
        path.write_text("x")
        with patch("os.chown", side_effect=OSError("permission denied")):
            # не должно бросать
            _restore_owner_mode(path, {"uid": 0, "gid": 0, "mode": 0o644})


class TestDoRollbackOrder(unittest.TestCase):
    """ (rollback-order): do_rollback() обязан глушить mita ДО
    восстановления config.json и рестарта Xray. Иначе восстановленный
    vless-инбаунд биндится на порт, который mita ещё держит: xray падает,
    systemd крутится в restart-backoff, is-active отвечает «activating»
    (живой кейс 07.09)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _run_rollback(self):
        """Прогоняет do_rollback() на моках, возвращает журнал вызовов."""
        import types
        from chimera.modules import hybrid_addon

        calls = []

        class _Res:
            returncode = 0
            stdout = ""
            stderr = ""

        stub_pr = types.ModuleType("chimera.modules.port_registry")
        stub_pr.ufw_close_port = lambda *a, **kw: None
        stub_pr.port_unregister = lambda *a, **kw: None
        stub_pr.SERVICE_HYBRID_ADDON = "hybrid_addon"

        state = {
            "xray_config_path": str(self._tmpdir / "config.json"),
            "backup_path": str(self._tmpdir / "config.json.bak"),
            "config_owner_mode": {"uid": 0, "gid": 0, "mode": 0o644},
            "tcp_port": 443,
            "udp_port": 8443,
        }
        Path(state["backup_path"]).write_text("{}")  # бэкап «существует»

        with patch.dict(sys.modules, {"chimera.modules.port_registry": stub_pr}):
            with patch.object(hybrid_addon, "load_state", return_value=state), \
                 patch("shutil.copy2",
                       side_effect=lambda s, d: calls.append(("copy2", str(d)))), \
                 patch.object(hybrid_addon, "restart_service",
                              side_effect=lambda name: calls.append(("restart", name)) or True), \
                 patch.object(hybrid_addon, "run",
                              side_effect=lambda cmd, **kw: calls.append(("run", tuple(cmd))) or _Res()), \
                 patch.object(hybrid_addon, "STATE_FILE", self._tmpdir / "state.json"), \
                 patch.object(hybrid_addon, "_restore_owner_mode", lambda *a, **kw: None), \
                 patch.object(hybrid_addon, "_log", lambda *a, **kw: None):
                hybrid_addon.do_rollback()
        return calls

    def test_mita_stopped_before_config_restore_and_xray_restart(self):
        calls = self._run_rollback()
        stop_i = next(i for i, c in enumerate(calls)
                      if c[0] == "run" and c[1][:2] == ("systemctl", "stop"))
        copy_i = next(i for i, c in enumerate(calls) if c[0] == "copy2")
        restart_i = next(i for i, c in enumerate(calls) if c[0] == "restart")
        self.assertLess(stop_i, copy_i,
                        "mita должна быть остановлена ДО восстановления config.json")
        self.assertLess(stop_i, restart_i,
                        "mita должна быть остановлена ДО рестарта Xray (порт!)")

    def test_mita_disabled_once_before_restart(self):
        calls = self._run_rollback()
        disables = [i for i, c in enumerate(calls)
                    if c[0] == "run" and c[1][:2] == ("systemctl", "disable")]
        restart_i = next(i for i, c in enumerate(calls) if c[0] == "restart")
        self.assertEqual(len(disables), 1, "systemctl disable mita — ровно один вызов")
        self.assertLess(disables[0], restart_i)


# ══════════════════════════════════════════════════════════════════════════════
# домен сервера + свой DNS в клиентских конфигах Karing
# ══════════════════════════════════════════════════════════════════════════════
class TestDetectServerDomain(unittest.TestCase):
    """_detect_server_domain — state.json → naiveproxy.json напрямую
    (CLI-безопасно: без импорта chimera._core)."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_state_json_wins(self):
        from chimera.modules import hybrid_addon as ha
        (self._tmp / "state.json").write_text('{"domain": "vless.example.com"}')
        (self._tmp / "naiveproxy.json").write_text('{"domain": "naive.example.com"}')
        with patch.object(ha, "STATE_DIR", self._tmp):
            self.assertEqual(ha._detect_server_domain(), "vless.example.com")

    def test_naive_fallback(self):
        from chimera.modules import hybrid_addon as ha
        (self._tmp / "naiveproxy.json").write_text(
            '{"domain": "naive.example.com", "port": 443}')
        with patch.object(ha, "STATE_DIR", self._tmp):
            self.assertEqual(ha._detect_server_domain(), "naive.example.com")

    def test_nothing_found(self):
        from chimera.modules import hybrid_addon as ha
        with patch.object(ha, "STATE_DIR", self._tmp):
            self.assertEqual(ha._detect_server_domain(), "")

    def test_garbage_ignored(self):
        from chimera.modules import hybrid_addon as ha
        (self._tmp / "state.json").write_text("не json")
        with patch.object(ha, "STATE_DIR", self._tmp):
            self.assertEqual(ha._detect_server_domain(), "")


class TestAskClientLinkSettings(unittest.TestCase):
    """_ask_client_link_settings — Enter=домен если найден, [1]=IP;
    DNS-меню, подсказка домена, опечатка → дефолт Google.

    AGH-детект патчу на «нет AGH» — детерминизм (на живом
    /var/lib/xray-installer тест зависел бы от машины)."""

    _NO_AGH = {"links": [], "self_signed": False, "status": "no-agh"}

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self._state = self._tmp / "hybrid_state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run(self, inputs, state_json=None, detected="cdn.example",
             agh=None):
        from chimera.modules import hybrid_addon as ha
        if state_json is not None:
            self._state.write_text(json.dumps(state_json))
        with patch("builtins.input", side_effect=inputs), \
             patch.object(ha, "STATE_FILE", self._state), \
             patch.object(ha, "_detect_server_domain", return_value=detected), \
             patch.object(ha, "_detect_agh_dns_endpoints",
                          return_value=agh if agh is not None else self._NO_AGH):
            return ha._ask_client_link_settings()

    def test_fresh_domain_default(self):
        """Enter+Enter: домен найден → адрес=домен, DNS=Google (как раньше)."""
        res = self._run(["", ""])
        self.assertEqual(res["client_server_addr"], "cdn.example")
        self.assertEqual(res["client_dns"], "")

    def test_explicit_ip(self):
        res = self._run(["1", ""])
        self.assertEqual(res["client_server_addr"], "")
        self.assertEqual(res["client_dns"], "")

    def test_custom_dns(self):
        res = self._run(["2", "panel.example"])
        self.assertEqual(res["client_server_addr"], "cdn.example")
        self.assertEqual(res["client_dns"], "panel.example")

    def test_dns_typo_falls_back(self):
        res = self._run(["1", "bad dns com"])
        self.assertEqual(res["client_server_addr"], "")
        self.assertEqual(res["client_dns"], "")

    def test_old_state_defaults(self):
        """Переустановка: Enter — прежние значения из state."""
        res = self._run(["", ""], state_json={
            "client_server_addr": "old.example.com",
            "client_dns": "10.0.0.53",
        })
        self.assertEqual(res["client_server_addr"], "old.example.com")
        self.assertEqual(res["client_dns"], "10.0.0.53")

    def test_no_domain_only_dns_question(self):
        """Домен не найден — вопроса про адрес нет, только DNS."""
        res = self._run([""], detected="")
        self.assertEqual(res["client_server_addr"], "")
        self.assertEqual(res["client_dns"], "")

    def test_doh_url_accepted(self):
        res = self._run(["1", "https://panel.example/dns-query"])
        self.assertEqual(res["client_dns"],
                         "https://panel.example/dns-query")


class TestShowMieruClientLinks(unittest.TestCase):
    """_show_mieru_client_links — Karing-JSON собирается общими билдерами
    из mieru.py: домен в server + domain_resolver + custom-dns через
    туннель. Пишем в фейковый Path, генераторы ссылок — фейки, QR — мьют."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmp = Path(tempfile.mkdtemp())
        store = {}
        self._store = store

        class _FakePath:
            def __init__(self, p):
                self._p = str(p)
            def write_text(self, data, encoding=None):
                store[self._p] = data
            def __str__(self):
                return self._p

        self._FakePath = _FakePath

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run(self, server_addr, client_dns=""):
        from chimera.modules import hybrid_addon as ha
        from chimera.modules import mieru
        creds = {"tcp": {"port": 443, "login": "u_d106fd33",
                         "password": "goep167KyRYE2u76w9sv-Sr3"}}
        with patch.object(ha, "Path", self._FakePath), \
             patch.object(mieru, "_gen_client_share_link",
                          return_value="mierus://fake"), \
             patch.object(mieru, "_gen_client_share_link_nekobox",
                          return_value="mierus://fake-neko"), \
             patch.object(mieru, "_print_qr", lambda *a, **k: None):
            ha._show_mieru_client_links(creds, server_addr,
                                        client_dns=client_dns)
        path = self._store.get("/tmp/karing-mieru-hybrid-tcp-u_d106fd33.json")
        self.assertIsNotNone(path, "Karing-JSON должен быть записан")
        return json.loads(path)

    def test_domain_and_custom_dns(self):
        cfg = self._run("cdn.example",
                        client_dns="panel.example")
        ob = cfg["outbounds"][0]
        self.assertEqual(ob["type"], "mieru")
        self.assertEqual(ob["server"], "cdn.example")
        self.assertEqual(ob["domain_resolver"], "local")
        custom = cfg["dns"]["servers"][0]
        self.assertEqual(custom["tag"], "custom-dns")
        self.assertEqual(custom["address"], "panel.example")
        self.assertEqual(custom["detour"], ob["tag"])
        self.assertEqual(custom["address_resolver"], "local")
        self.assertEqual(cfg["dns"]["rules"],
                         [{"domain": ["cdn.example"],
                           "server": "local"}])
        self.assertEqual(cfg["route"]["final"], ob["tag"])

    def test_ip_default_google(self):
        cfg = self._run("203.0.113.103")
        ob = cfg["outbounds"][0]
        self.assertEqual(ob["server"], "203.0.113.103")
        self.assertNotIn("domain_resolver", ob)
        self.assertEqual(cfg["dns"]["servers"][0],
                         {"tag": "google", "address": "8.8.8.8"})
        self.assertNotIn("rules", cfg["dns"])


class TestDnsMenu(unittest.TestCase):
    """DNS-меню — AGH-детект, умный дефолт, номера, ручной ввод."""

    _NO_AGH = {"links": [], "self_signed": False, "status": "no-agh"}
    _AGH = {"links": [
        ("DoH", "https://cdn.example:30443/dns-query"),
        ("DoT", "tls://cdn.example:853"),
        ("DoQ", "quic://cdn.example:853"),
    ], "self_signed": False, "status": "ok"}

    def _ask(self, inputs, old_dns="", agh=None):
        from chimera.modules import hybrid_addon as ha
        with patch("builtins.input", side_effect=inputs), \
             patch.object(ha, "_detect_agh_dns_endpoints",
                          return_value=agh if agh is not None else self._NO_AGH):
            return ha._ask_client_dns(old_dns)

    def test_agh_found_enter_defaults_to_agh_doh(self):
        """AGH на сервере — Enter выбирает DoH-ссылку (юзеру не нужно
        прописывать DNS руками — ровно запрос из)."""
        res = self._ask([""], agh=self._AGH)
        self.assertEqual(res, "https://cdn.example:30443/dns-query")

    def test_agh_dot_by_number(self):
        res = self._ask(["5"], agh=self._AGH)
        self.assertEqual(res, "tls://cdn.example:853")

    def test_agh_doq_by_number(self):
        res = self._ask(["6"], agh=self._AGH)
        self.assertEqual(res, "quic://cdn.example:853")

    def test_no_agh_enter_is_google(self):
        res = self._ask([""])
        self.assertEqual(res, "")

    def test_option3_google_cloudflare_pair(self):
        res = self._ask(["3"])
        self.assertEqual(res, "8.8.8.8,1.1.1.1")

    def test_manual_option_then_address(self):
        """Без AGH «вручную» — пункт 4; второй ввод — адрес."""
        res = self._ask(["4", "panel.example"])
        self.assertEqual(res, "panel.example")

    def test_manual_option_typo_falls_back(self):
        res = self._ask(["4", "bad dns com"])
        self.assertEqual(res, "")

    def test_raw_address_typed_directly(self):
        """Старое поведение адрес можно ввести сразу, без номера."""
        res = self._ask(["tls://panel.example:853"])
        self.assertEqual(res, "tls://panel.example:853")

    def test_old_dns_kept_on_enter(self):
        """Переустановка: прежний DNS не из меню — Enter оставляет его."""
        res = self._ask([""], old_dns="10.0.0.53")
        self.assertEqual(res, "10.0.0.53")

    def test_old_dns_mapped_to_option(self):
        res = self._ask([""], old_dns="8.8.8.8,1.1.1.1")
        self.assertEqual(res, "8.8.8.8,1.1.1.1")

    def test_number_out_of_range_is_typo(self):
        res = self._ask(["99"])
        self.assertEqual(res, "")


class TestAghEndpoints(unittest.TestCase):
    """_detect_agh_dns_endpoints — подглядывание в стейт AGH."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _detect(self, payload=None):
        from chimera.modules import hybrid_addon as ha
        state = self._tmp / "aghome_state.json"
        if payload is not None:
            state.write_text(json.dumps(payload))
        with patch.object(ha, "STATE_DIR", self._tmp):
            return ha._detect_agh_dns_endpoints()

    def test_ok_tls_domain(self):
        r = self._detect({"domain": "cdn.example",
                          "tls_enabled": True, "self_signed": False,
                          "doh_port": 30443, "dot_port": 853, "doq_port": 853})
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["links"][0],
                         ("DoH", "https://cdn.example:30443/dns-query"))
        self.assertEqual(r["links"][1],
                         ("DoT", "tls://cdn.example:853"))
        self.assertEqual(r["links"][2],
                         ("DoQ", "quic://cdn.example:853"))

    def test_no_file(self):
        r = self._detect(None)
        self.assertEqual(r, {"links": [], "self_signed": False,
                             "status": "no-agh"})

    def test_no_tls(self):
        r = self._detect({"domain": "cdn.example",
                          "tls_enabled": False})
        self.assertEqual((r["links"], r["status"]), ([], "no-tls"))

    def test_no_domain(self):
        r = self._detect({"domain": "", "tls_enabled": True})
        self.assertEqual((r["links"], r["status"]), ([], "no-domain"))

    def test_self_signed_flag(self):
        r = self._detect({"domain": "dns.example.com", "tls_enabled": True,
                          "self_signed": True})
        self.assertTrue(r["self_signed"])

    def test_default_ports_when_missing(self):
        r = self._detect({"domain": "dns.example.com", "tls_enabled": True})
        self.assertEqual(r["links"][0],
                         ("DoH", "https://dns.example.com:30443/dns-query"))


class TestLinksOutsideFrame(unittest.TestCase):
    """mierus://-ссылки печатаются ВНЕ рамки — строки со ссылками
    не содержат символов рамки (║), рамка закрывается до ссылок."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmp = Path(tempfile.mkdtemp())
        store = {}
        self._store = store

        class _FakePath:
            def __init__(self, p):
                self._p = str(p)
            def write_text(self, data, encoding=None):
                store[self._p] = data
            def __str__(self):
                return self._p

        self._FakePath = _FakePath

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_hybrid_links_have_no_frame_chars(self):
        from chimera.modules import hybrid_addon as ha
        from chimera.modules import mieru
        creds = {"tcp": {"port": 443, "login": "u_d106fd33",
                         "password": "goep167KyRYE2u76w9sv-Sr3"}}
        buf = io.StringIO()
        with patch.object(ha, "Path", self._FakePath), \
             patch.object(mieru, "_print_qr", lambda *a, **k: None), \
             redirect_stdout(buf):
            ha._show_mieru_client_links(creds, "cdn.example")
        lines = [_ANSI_RE.sub("", ln).strip()
                 for ln in buf.getvalue().splitlines()]
        link_lines = [l for l in lines if l.startswith("mierus://")]
        self.assertEqual(len(link_lines), 2)  # Karing + Nekobox/Nyamebox
        for l in link_lines:
            self.assertNotIn("║", l, "ссылка должна быть вне рамки")
        # рамка закрылась ДО ссылок: строка ╚ раньше первой строки-ссылки
        # (внутри рамки есть предупреждение, содержащее «mierus://» как
        # текст — ищем только строки, НАЧИНАЮЩИЕСЯ с mierus://)
        first_link_idx = next(i for i, l in enumerate(lines)
                              if l.startswith("mierus://"))
        bottom_idx = next(i for i, l in enumerate(lines) if "╚" in l)
        self.assertLess(bottom_idx, first_link_idx)


class TestTrafficPatternSingleParam(unittest.TestCase):
    """Karing-ссылка с blob — ровно ОДИН traffic-pattern=.

    До фиксы _gen_client_share_link вставлял preset basic, а вызывающий код
    дописывал blob — в ссылке оказывались ДВА параметра, и первый (basic)
    мог перебивать реальный паттерн сервера. Генераторы ссылок — НАСТОЯЩИЕ
    (не фейки), чтобы двойной параметр был бы виден, как у юзера."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmp = Path(tempfile.mkdtemp())
        store = {}
        self._store = store

        class _FakePath:
            def __init__(self, p):
                self._p = str(p)
            def write_text(self, data, encoding=None):
                store[self._p] = data
            def __str__(self):
                return self._p

        self._FakePath = _FakePath

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _karing_links(self, blob):
        """Прогоняет выдачу ссылок с реальными генераторами; возвращает
        Karing-ссылки (отличаются параметром protocol=).

        ссылки печатаются ВНЕ рамки (`print`, одной строкой)
        перехватываем stdout и срезаем ANSI, вместо патча _box_link."""
        from chimera.modules import hybrid_addon as ha
        from chimera.modules import mieru
        buf = io.StringIO()
        creds = {"tcp": {"port": 443, "login": "u_d106fd33",
                         "password": "goep167KyRYE2u76w9sv-Sr3"}}
        with patch.object(ha, "Path", self._FakePath), \
             patch.object(ha, "box_header", lambda *a, **k: None), \
             patch.object(ha, "_box_row", lambda *a, **k: None), \
             patch.object(ha, "_box_bottom", lambda *a, **k: None), \
             patch.object(mieru, "_print_qr", lambda *a, **k: None), \
             redirect_stdout(buf):
            ha._show_mieru_client_links(creds, "203.0.113.103",
                                        client_dns="",
                                        traffic_pattern_blob=blob)
        lines = [_ANSI_RE.sub("", ln).strip()
                 for ln in buf.getvalue().splitlines()]
        return [l for l in lines
                if l.startswith("mierus://") and "protocol=" in l]

    def test_blob_single_traffic_pattern(self):
        links = self._karing_links("GgQIARAFIgIIAQ==")
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].count("traffic-pattern="), 1)
        # параметр — сам blob (url-encoded), НЕ basic-пресет
        self.assertIn("traffic-pattern=GgQIARAFIgIIAQ%3D%3D", links[0])

    def test_no_blob_keeps_basic_preset(self):
        """Регресс: без blob в ссылке один traffic-pattern (basic-пресет)."""
        links = self._karing_links(None)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].count("traffic-pattern="), 1)

    def test_blob_saved_to_state(self):
        """_persist_traffic_pattern_blob пишет blob в state (для
        singbox-подписки nyamebox); пустой blob ничего не трогает."""
        from chimera.modules import hybrid_addon as ha
        saved = {}
        with patch.object(ha, "load_state", return_value={"transport": "both"}), \
             patch.object(ha, "save_state", lambda st: saved.update(st)):
            ha._persist_traffic_pattern_blob("GgQIARAFIgIIAQ==")
        self.assertEqual(saved.get("traffic_pattern_blob"), "GgQIARAFIgIIAQ==")
        self.assertEqual(saved.get("transport"), "both")  # state не затёрт

        # пустой blob — load/save не вызываются вовсе
        calls = []
        with patch.object(ha, "load_state", side_effect=lambda: calls.append("load")), \
             patch.object(ha, "save_state", side_effect=lambda st: calls.append("save")):
            ha._persist_traffic_pattern_blob(None)
            ha._persist_traffic_pattern_blob("")
        self.assertEqual(calls, [])

    def test_blob_state_write_error_not_fatal(self):
        """Битый state (die() внутри load_state) — не бросает наружу."""
        from chimera.modules import hybrid_addon as ha

        def _die():
            raise SystemExit("state not found")

        with patch.object(ha, "load_state", side_effect=_die):
            ha._persist_traffic_pattern_blob("GgQIARAFIgIIAQ==")  # не падает


class TestKaringUdpAddr(unittest.TestCase):
    """_karing_udp_addr (гибрид) — UDP+домен подставляет IP
    (баг ядра Karing: mieru-UDP не резолвит домен). TCP/IP — как есть."""

    def test_udp_domain_substitutes_ip(self):
        from chimera.modules import hybrid_addon as ha
        with patch.object(ha, "_karing_udp_server_ip",
                          return_value="203.0.113.103"):
            addr, sub = ha._karing_udp_addr("udp", "cdn.example")
        self.assertEqual(addr, "203.0.113.103")
        self.assertTrue(sub)

    def test_udp_domain_ip_missing_keeps_domain(self):
        from chimera.modules import hybrid_addon as ha
        with patch.object(ha, "_karing_udp_server_ip", return_value=""):
            addr, sub = ha._karing_udp_addr("udp", "cdn.example")
        self.assertEqual(addr, "cdn.example")
        self.assertFalse(sub)

    def test_tcp_and_ip_unchanged(self):
        from chimera.modules import hybrid_addon as ha
        with patch.object(ha, "_karing_udp_server_ip", return_value="1.2.3.4"):
            self.assertEqual(ha._karing_udp_addr("tcp", "cdn.example"),
                             ("cdn.example", False))
            self.assertEqual(ha._karing_udp_addr("udp", "203.0.113.103"),
                             ("203.0.113.103", False))

    def test_is_public_ipv4(self):
        from chimera.modules import hybrid_addon as ha
        self.assertTrue(ha._is_public_ipv4("203.0.113.103"))
        for bad in ("", "foo", "10.0.0.1", "127.0.0.1", "192.168.0.1",
                    "172.20.1.1", "169.254.0.9", "1.2.3", "999.1.1.1"):
            self.assertFalse(ha._is_public_ipv4(bad), bad)


class TestLinksUdpIpIntegration(unittest.TestCase):
    """_show_mieru_client_links с udp+домен — Karing-ссылка и JSON
    с IP (домен+UDP в Karing = 0 байт/с), Nekobox-ссылка с доменом;
    TCP-выдача подстановкой не затронута."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmp = Path(tempfile.mkdtemp())
        store = {}
        self._store = store

        class _FakePath:
            def __init__(self, p):
                self._p = str(p)

            def write_text(self, data, encoding=None):
                store[self._p] = data

            def __str__(self):
                return self._p

        self._FakePath = _FakePath

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_udp_links_ip_and_json(self):
        import json as _json
        from chimera.modules import hybrid_addon as ha
        from chimera.modules import mieru
        creds = {"udp": {"port": 5443, "login": "u_be3f4705",
                         "password": "ag7SFeda2C2n1ofvWIEjcWiu"}}
        buf = io.StringIO()
        with patch.object(ha, "Path", self._FakePath), \
             patch.object(mieru, "_print_qr", lambda *a, **k: None), \
             patch.object(ha, "_karing_udp_server_ip",
                          return_value="203.0.113.103"), \
             redirect_stdout(buf):
            ha._show_mieru_client_links(creds, "cdn.example")
        plain = _ANSI_RE.sub("", buf.getvalue())
        # Karing-ссылка — с IP; Nekobox-ссылка — с доменом
        self.assertIn("@203.0.113.103?port=5443&protocol=UDP", plain)
        self.assertIn("@cdn.example:5443?transport=UDP", plain)
        self.assertNotIn("@cdn.example?port=5443&protocol=UDP", plain)
        # JSON: server = IP, без domain_resolver и dns.rules
        cfg = _json.loads(self._store["/tmp/karing-mieru-hybrid-udp-u_be3f4705.json"])
        ob = cfg["outbounds"][0]
        self.assertEqual(ob["server"], "203.0.113.103")
        self.assertNotIn("domain_resolver", ob)
        self.assertNotIn("rules", cfg["dns"])
        # предупреждение о подстановке — в боксе (рамка цела)
        self.assertIn("UDP для Karing: с IP", plain)

    def test_tcp_links_not_touched(self):
        from chimera.modules import hybrid_addon as ha
        from chimera.modules import mieru
        creds = {"tcp": {"port": 443, "login": "u_d106fd33",
                         "password": "goep167KyRYE2u76w9sv-Sr3"}}
        buf = io.StringIO()
        with patch.object(ha, "Path", self._FakePath), \
             patch.object(mieru, "_print_qr", lambda *a, **k: None), \
             patch.object(ha, "_karing_udp_server_ip",
                          return_value="203.0.113.103"), \
             redirect_stdout(buf):
            ha._show_mieru_client_links(creds, "cdn.example")
        plain = _ANSI_RE.sub("", buf.getvalue())
        self.assertIn("@cdn.example?port=443&protocol=TCP", plain)
        self.assertNotIn("203.0.113.103", plain)
        self.assertNotIn("UDP для Karing", plain)


if __name__ == "__main__":
    unittest.main(verbosity=2)
