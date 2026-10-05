#!/usr/bin/env python3
"""
tests/test_awg_qr.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/awg_qr.py.

Покрывает:
  1. awgs_qr_build_client_conf — генерация .conf
  2. awgs_qr_build_vpn_uri — генерация vpn:// URI
  3. awgs_qr_save_client_conf — сохранение в файл + chmod 0o600
  4. awgs_qr_show_terminal / awgs_qr_save_png — qrencode (mocked)
"""
from __future__ import annotations

import base64
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

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


def _peer(name="alice", **overrides):
    base = {
        "name": name,
        "client_privkey": "CLIENT_PRIV_KEY",
        "client_pubkey": "CLIENT_PUB_KEY",
        "client_ip": "10.66.66.2",
        "client_ipv6": "fd66:66:66::2",
        "preshared_key": "PSK_KEY",
        "dns1": "1.1.1.1",
        "dns2": "8.8.8.8",
    }
    base.update(overrides)
    return base


def _server_state(**overrides):
    base = {
        "server_pubkey": "SERVER_PUB_KEY",
        "endpoint_host": "vpn.example.com",
        "endpoint": "1.2.3.4",
        "port": 51820,
        "mtu": 1280,
        "allow_ipv6_tunnel": False,
        "params": {
            "jc": 4, "jmin": 40, "jmax": 70,
            "s1": 0, "s2": 0, "s3": 0, "s4": 0,
            "h1": 1, "h2": 2, "h3": 3, "h4": 4,
            "i1": "", "i2": "", "i3": "", "i4": "", "i5": "",
        },
    }
    base.update(overrides)
    return base


class TestBuildClientConf(unittest.TestCase):
    """awgs_qr_build_client_conf — генерация .conf."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_interface_section(self):
        from chimera.modules.awg_qr import awgs_qr_build_client_conf
        conf = awgs_qr_build_client_conf(_peer(), _server_state())
        self.assertIn("[Interface]", conf)
        self.assertIn("[Peer]", conf)

    def test_includes_private_key(self):
        from chimera.modules.awg_qr import awgs_qr_build_client_conf
        conf = awgs_qr_build_client_conf(_peer(), _server_state())
        self.assertIn("PrivateKey = CLIENT_PRIV_KEY", conf)

    def test_includes_address_v4(self):
        from chimera.modules.awg_qr import awgs_qr_build_client_conf
        conf = awgs_qr_build_client_conf(_peer(), _server_state())
        self.assertIn("Address = 10.66.66.2/32", conf)

    def test_includes_endpoint(self):
        from chimera.modules.awg_qr import awgs_qr_build_client_conf
        conf = awgs_qr_build_client_conf(_peer(), _server_state())
        # endpoint_host приоритетнее endpoint
        self.assertIn("Endpoint = vpn.example.com:51820", conf)

    def test_endpoint_fallback_to_endpoint_ip(self):
        from chimera.modules.awg_qr import awgs_qr_build_client_conf
        state = _server_state(endpoint_host="")
        conf = awgs_qr_build_client_conf(_peer(), state)
        self.assertIn("Endpoint = 1.2.3.4:51820", conf)

    def test_includes_psk_when_present(self):
        from chimera.modules.awg_qr import awgs_qr_build_client_conf
        conf = awgs_qr_build_client_conf(_peer(), _server_state())
        self.assertIn("PresharedKey = PSK_KEY", conf)

    def test_omits_psk_when_empty(self):
        from chimera.modules.awg_qr import awgs_qr_build_client_conf
        peer = _peer(preshared_key="")
        conf = awgs_qr_build_client_conf(peer, _server_state())
        self.assertNotIn("PresharedKey", conf)

    def test_includes_awg_params(self):
        from chimera.modules.awg_qr import awgs_qr_build_client_conf
        conf = awgs_qr_build_client_conf(_peer(), _server_state())
        self.assertIn("Jc = 4", conf)
        self.assertIn("Jmin = 40", conf)
        self.assertIn("Jmax = 70", conf)
        self.assertIn("H1 = 1", conf)
        self.assertIn("H4 = 4", conf)

    def test_includes_i1_when_present(self):
        from chimera.modules.awg_qr import awgs_qr_build_client_conf
        state = _server_state()
        state["params"]["i1"] = "deadbeef"
        conf = awgs_qr_build_client_conf(_peer(), state)
        self.assertIn("I1 = deadbeef", conf)

    def test_client_i1_to_i5_empty_commented_v545(self):
        """ПУСТЫЕ I1-I5 в клиентском .conf КОММЕНТИРУЮТСЯ (# I2 = ).

        E2E 2026-10-03 (de1→nl1): Linux-клиент awg-quick падает на голой
        пустой 'I2 = ' — "Line unrecognized: I2=" (awg setconf требует
        значение). '# I2 = ' принимается сервером и клиентом; приложения
        (Keenetic/amneziawg-go) комментарии игнорируют.
        Прежнее правило "клиенту без #" ломало awg-quick на Linux.
        """
        from chimera.modules.awg_qr import awgs_qr_build_client_conf
        conf = awgs_qr_build_client_conf(_peer(), _server_state())
        # Все 5 I-ключей (пустые в дефолтном state) — ЗАКОММЕНТИРОВАНЫ
        for key in ("I1", "I2", "I3", "I4", "I5"):
            self.assertIn(f"# {key} = ", conf,
                          f"# {key} = должен присутствовать (закомментирован) "
                          f"в клиентском conf")
            self.assertNotIn(f"\n{key} = \n", conf,
                             f"голая пустая строка '{key} = ' НЕ должна быть "
                             f"в клиентском conf (awg setconf падает)")

    def test_client_i_set_when_nonempty_v545(self):
        """НЕПУСТЫЕ I в клиентском .conf пишутся без комментария."""
        from chimera.modules.awg_qr import awgs_qr_build_client_conf
        state = _server_state()
        state["params"].update({"i1": "aa", "i2": "bb", "i3": "cc",
                                 "i4": "dd", "i5": "ee"})
        conf = awgs_qr_build_client_conf(_peer(), state)
        for key, val in (("I1", "aa"), ("I2", "bb"), ("I3", "cc"),
                         ("I4", "dd"), ("I5", "ee")):
            self.assertIn(f"{key} = {val}", conf,
                          f"непустой {key} должен быть без #")

    def test_includes_ipv6_address_when_enabled(self):
        from chimera.modules.awg_qr import awgs_qr_build_client_conf
        state = _server_state(allow_ipv6_tunnel=True)
        conf = awgs_qr_build_client_conf(_peer(), state)
        self.assertIn("fd66:66:66::2/128", conf)
        self.assertIn("::/0", conf)

    def test_omits_ipv6_address_when_disabled(self):
        from chimera.modules.awg_qr import awgs_qr_build_client_conf
        conf = awgs_qr_build_client_conf(_peer(), _server_state())
        self.assertNotIn("::/0", conf)

    def test_persistent_keepalive(self):
        from chimera.modules.awg_qr import awgs_qr_build_client_conf
        conf = awgs_qr_build_client_conf(_peer(), _server_state())
        self.assertIn("PersistentKeepalive = 25", conf)

    def test_custom_dns(self):
        from chimera.modules.awg_qr import awgs_qr_build_client_conf
        peer = _peer(dns1="9.9.9.9", dns2="149.112.112.112")
        conf = awgs_qr_build_client_conf(peer, _server_state())
        self.assertIn("DNS = 9.9.9.9, 149.112.112.112", conf)


class TestBuildVpnUri(unittest.TestCase):
    """awgs_qr_build_vpn_uri — генерация vpn:// URI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_starts_with_vpn_scheme(self):
        from chimera.modules.awg_qr import awgs_qr_build_vpn_uri
        uri = awgs_qr_build_vpn_uri(_peer(), _server_state())
        self.assertTrue(uri.startswith("vpn://free/"))

    def test_has_two_base64_segments(self):
        from chimera.modules.awg_qr import awgs_qr_build_vpn_uri
        uri = awgs_qr_build_vpn_uri(_peer(), _server_state())
        # vpn://free/<outer_b64>/<inner_b64>
        parts = uri.split("/")
        self.assertGreaterEqual(len(parts), 4)
        outer_b64 = parts[3]
        inner_b64 = parts[4] if len(parts) > 4 else ""
        # должны быть валидные base64
        outer = json.loads(base64.b64decode(outer_b64))
        inner = json.loads(base64.b64decode(inner_b64))
        self.assertIn("containers", outer)
        self.assertIn("awg", outer["containers"][0])

    def test_inner_contains_awg_params(self):
        from chimera.modules.awg_qr import awgs_qr_build_vpn_uri
        uri = awgs_qr_build_vpn_uri(_peer(), _server_state())
        parts = uri.split("/")
        inner = json.loads(base64.b64decode(parts[4]))
        self.assertEqual(inner["Jc"], "4")
        self.assertEqual(inner["Jmin"], "40")
        self.assertEqual(inner["Jmax"], "70")
        self.assertEqual(inner["H1"], "1")

    def test_inner_contains_endpoint(self):
        from chimera.modules.awg_qr import awgs_qr_build_vpn_uri
        uri = awgs_qr_build_vpn_uri(_peer(), _server_state())
        parts = uri.split("/")
        inner = json.loads(base64.b64decode(parts[4]))
        self.assertEqual(inner["hostName"], "vpn.example.com")
        self.assertEqual(inner["port"], 51820)

    def test_inner_contains_keys(self):
        from chimera.modules.awg_qr import awgs_qr_build_vpn_uri
        uri = awgs_qr_build_vpn_uri(_peer(), _server_state())
        parts = uri.split("/")
        inner = json.loads(base64.b64decode(parts[4]))
        self.assertEqual(inner["client_priv_key"], "CLIENT_PRIV_KEY")
        self.assertEqual(inner["server_pub_key"], "SERVER_PUB_KEY")
        self.assertEqual(inner["psk_key"], "PSK_KEY")

    def test_inner_omits_psk_when_empty(self):
        from chimera.modules.awg_qr import awgs_qr_build_vpn_uri
        peer = _peer(preshared_key="")
        uri = awgs_qr_build_vpn_uri(peer, _server_state())
        parts = uri.split("/")
        inner = json.loads(base64.b64decode(parts[4]))
        self.assertNotIn("psk_key", inner)


class TestSaveClientConf(unittest.TestCase):
    """awgs_qr_save_client_conf — сохранение в файл."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._keys_dir = self._tmpdir / "keys"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_saves_to_keys_dir(self):
        from chimera.modules import awg_qr
        with patch.object(awg_qr, "AWGS_KEYS_DIR", self._keys_dir):
            path = awg_qr.awgs_qr_save_client_conf(_peer(), _server_state())
            self.assertIsNotNone(path)
            self.assertTrue(path.exists())
            self.assertEqual(path.name, "alice.conf")

    def test_sets_chmod_600(self):
        """Приватный ключ в .conf — права 0o600."""
        from chimera.modules import awg_qr
        with patch.object(awg_qr, "AWGS_KEYS_DIR", self._keys_dir):
            path = awg_qr.awgs_qr_save_client_conf(_peer(), _server_state())
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o600)

    def test_creates_keys_dir_with_0o700(self):
        from chimera.modules import awg_qr
        with patch.object(awg_qr, "AWGS_KEYS_DIR", self._keys_dir):
            awg_qr.awgs_qr_save_client_conf(_peer(), _server_state())
            self.assertTrue(self._keys_dir.exists())
            mode = stat.S_IMODE(os.stat(self._keys_dir).st_mode)
            self.assertEqual(mode, 0o700)

    def test_returns_none_on_exception(self):
        from chimera.modules import awg_qr
        # Директория read-only — chmod упадёт, но write_text тоже
        with patch.object(awg_qr, "AWGS_KEYS_DIR", Path("/proc/nonexistent/keys")):
            result = awg_qr.awgs_qr_save_client_conf(_peer(), _server_state())
            self.assertIsNone(result)


class TestQrShowTerminal(unittest.TestCase):
    """awgs_qr_show_terminal — qrencode (mocked)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_false_when_qrencode_missing(self):
        from chimera.modules import awg_qr
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
            result = awg_qr.awgs_qr_show_terminal("content")
            self.assertFalse(result)

    def test_returns_true_when_qrencode_ok(self):
        from chimera.modules import awg_qr
        with patch("chimera._core._run") as mock_run:
            # which qrencode → 0, qrencode → 0 + stdout
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="/usr/bin/qrencode", stderr=""),
                MagicMock(returncode=0, stdout="ANSI QR OUTPUT", stderr=""),
            ]
            result = awg_qr.awgs_qr_show_terminal("content", label="test")
            self.assertTrue(result)


class TestQrSavePng(unittest.TestCase):
    """awgs_qr_save_png — сохранение PNG (mocked)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_false_when_qrencode_missing(self):
        from chimera.modules import awg_qr
        with patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
            result = awg_qr.awgs_qr_save_png("content", self._tmpdir / "out.png")
            self.assertFalse(result)

    def test_returns_true_on_success(self):
        from chimera.modules import awg_qr
        png_path = self._tmpdir / "out.png"
        with patch("chimera._core._run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="/usr/bin/qrencode", stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),
            ]
            # chmod на Path в _setup_core мокается глобально, но конкретный файл
            # создаём вручную чтобы chmod не падал
            png_path.write_bytes(b"PNG")
            result = awg_qr.awgs_qr_save_png("content", png_path)
            self.assertTrue(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
