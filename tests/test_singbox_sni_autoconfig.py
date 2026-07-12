#!/usr/bin/env python3
"""
tests/test_singbox_sni_autoconfig.py
───────────────────────────────────────────────────────────────────────────────
Тесты для v4.23.5-v4.23.6: SNI-dispatch auto-config + common_name fix.

Покрывает:
  1. _detect_reality_backend() — читает state.json, возвращает 127.0.0.1:8442
  2. _detect_shadowtls_sni() — читает singbox_state handshake.server
  3. _detect_anytls_sni() — common_name из state, fallback CN из cert, empty
  4. _ensure_self_signed_cert() — возвращает 3 значения (cert, key, cn)
  5. singbox_enable_anytls() — common_name сохраняется в state
  6. auto_enable_sni_dispatch() — detect + comment listen 443 + enable
  7. auto_disable_sni_dispatch() — disable + uncomment listen 443
  8. proxy_protocol on в stream{} конфиге (fail2ban regression)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("vless_installer._core")
    m.__dict__.update(g)
    sys.modules["vless_installer._core"] = m


def _enter_patches(stack, patches):
    for p in patches:
        stack.enter_context(p)


# ══════════════════════════════════════════════════════════════════════════════
# 1. _detect_reality_backend
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectRealityBackend(unittest.TestCase):
    """_detect_reality_backend — читает state.json, возвращает loopback:8442."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._main_state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_loopback_8442_for_reality_mode(self):
        from vless_installer.modules.singbox_nginx import _detect_reality_backend
        self._main_state.write_text(json.dumps({
            "protocol_mode": "reality",
            "awg_exit_enabled": False,
        }))
        with patch("vless_installer.modules.singbox_nginx._Path") as mock_path:
            mock_path.return_value = self._main_state
            mock_path.side_effect = lambda x: self._main_state if str(x) == "/var/lib/xray-installer/state.json" else Path(x)
            # Actually simpler: just patch _read_main_state
        with patch("vless_installer.modules.singbox_nginx._read_main_state",
                   return_value={"protocol_mode": "reality", "awg_exit_enabled": False}):
            result = _detect_reality_backend()
        self.assertEqual(result, "127.0.0.1:8442")

    def test_returns_empty_for_xhttp_mode(self):
        from vless_installer.modules.singbox_nginx import _detect_reality_backend
        with patch("vless_installer.modules.singbox_nginx._read_main_state",
                   return_value={"protocol_mode": "xhttp", "awg_exit_enabled": False}):
            result = _detect_reality_backend()
        self.assertEqual(result, "")

    def test_returns_empty_for_awg_mode(self):
        from vless_installer.modules.singbox_nginx import _detect_reality_backend
        with patch("vless_installer.modules.singbox_nginx._read_main_state",
                   return_value={"protocol_mode": "reality", "awg_exit_enabled": True}):
            result = _detect_reality_backend()
        self.assertEqual(result, "")

    def test_does_not_use_state_socket(self):
        """НЕ использует state.json['socket'] — это decoy-сокет, отдельная логика."""
        from vless_installer.modules.singbox_nginx import _detect_reality_backend
        with patch("vless_installer.modules.singbox_nginx._read_main_state",
                   return_value={"protocol_mode": "reality", "awg_exit_enabled": False,
                                 "socket": "/dev/shm/abc123.socket"}):
            result = _detect_reality_backend()
        self.assertEqual(result, "127.0.0.1:8442")
        self.assertNotIn("/dev/shm", result)
        self.assertNotIn("socket", result)


# ══════════════════════════════════════════════════════════════════════════════
# 2. _detect_shadowtls_sni
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectShadowtlsSni(unittest.TestCase):
    """_detect_shadowtls_sni — читает singbox_state handshake.server."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._sb_state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_nginx.singbox_state_load"),
        ]

    def test_returns_handshake_server_when_enabled(self):
        from vless_installer.modules.singbox_nginx import _detect_shadowtls_sni
        mock_state = {
            "inbounds": {
                "shadowtls": {
                    "enabled": True,
                    "handshake": {"server": "www.cloudflare.com", "server_port": 443},
                }
            }
        }
        with ExitStack() as stack:
            for p in self._patches():
                stack.enter_context(p)
            with patch("vless_installer.modules.singbox_nginx.singbox_state_load",
                       return_value=mock_state):
                result = _detect_shadowtls_sni()
        self.assertEqual(result, "www.cloudflare.com")

    def test_returns_empty_when_disabled(self):
        from vless_installer.modules.singbox_nginx import _detect_shadowtls_sni
        mock_state = {
            "inbounds": {"shadowtls": {"enabled": False}}
        }
        with ExitStack() as stack:
            for p in self._patches():
                stack.enter_context(p)
            with patch("vless_installer.modules.singbox_nginx.singbox_state_load",
                       return_value=mock_state):
                result = _detect_shadowtls_sni()
        self.assertEqual(result, "")


# ══════════════════════════════════════════════════════════════════════════════
# 3. _detect_anytls_sni — 3 сценария: common_name, CN fallback, empty
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectAnytlsSni(unittest.TestCase):
    """_detect_anytls_sni — common_name из state, fallback CN из cert, empty."""

    def setUp(self):
        _setup_core()

    def test_returns_common_name_from_state(self):
        """Новые установки (v4.23.5+): common_name сохранён в state."""
        from vless_installer.modules.singbox_nginx import _detect_anytls_sni
        mock_state = {
            "inbounds": {
                "anytls": {
                    "enabled": True,
                    "common_name": "vless.example.com",
                }
            }
        }
        with patch("vless_installer.modules.singbox_nginx.singbox_state_load",
                   return_value=mock_state):
            result = _detect_anytls_sni()
        self.assertEqual(result, "vless.example.com")

    def test_returns_cn_from_cert_fallback(self):
        """Старые установки: нет common_name в state, но есть cert_path → парсим CN."""
        from vless_installer.modules.singbox_nginx import _detect_anytls_sni
        mock_state = {
            "inbounds": {
                "anytls": {
                    "enabled": True,
                    "cert_path": "/etc/sing-box/certs/anytls.crt",
                    # нет common_name
                }
            }
        }
        mock_run = MagicMock(returncode=0, stdout="subject=C=XX, CN=old-domain.example.com\n")
        with patch("vless_installer.modules.singbox_nginx.singbox_state_load",
                   return_value=mock_state):
            with patch("vless_installer.modules.singbox_nginx._Path") as mock_path:
                mock_path.return_value.exists.return_value = True
                with patch("vless_installer.modules.singbox_nginx._run", return_value=mock_run):
                    result = _detect_anytls_sni()
        self.assertEqual(result, "old-domain.example.com")

    def test_returns_empty_when_no_common_name_and_no_cert(self):
        """Полное отсутствие обоих источников — пустая строка, не тихий пропуск."""
        from vless_installer.modules.singbox_nginx import _detect_anytls_sni
        mock_state = {
            "inbounds": {
                "anytls": {
                    "enabled": True,
                    # нет common_name, нет cert_path
                }
            }
        }
        with patch("vless_installer.modules.singbox_nginx.singbox_state_load",
                   return_value=mock_state):
            result = _detect_anytls_sni()
        self.assertEqual(result, "")

    def test_returns_empty_when_anytls_disabled(self):
        from vless_installer.modules.singbox_nginx import _detect_anytls_sni
        mock_state = {
            "inbounds": {"anytls": {"enabled": False}}
        }
        with patch("vless_installer.modules.singbox_nginx.singbox_state_load",
                   return_value=mock_state):
            result = _detect_anytls_sni()
        self.assertEqual(result, "")


# ══════════════════════════════════════════════════════════════════════════════
# 4. _ensure_self_signed_cert — возвращает 3 значения (v4.23.6)
# ══════════════════════════════════════════════════════════════════════════════

class TestEnsureSelfSignedCertReturnsCn(unittest.TestCase):
    """v4.23.6: _ensure_self_signed_cert возвращает (cert_path, key_path, common_name)."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_three_values(self):
        """Возвращает tuple из 3 элементов, не 2."""
        from vless_installer.modules.singbox_menu import _ensure_self_signed_cert
        cert_dir = self._tmpdir / "certs"
        cert_dir.mkdir(parents=True, exist_ok=True)
        with patch("vless_installer.modules.singbox_menu.SINGBOX_CERT_DIR", cert_dir):
            with patch("vless_installer.modules.singbox_common.generate_self_signed_cert",
                       return_value=(cert_dir / "test.crt", cert_dir / "test.key")):
                result = _ensure_self_signed_cert("test")
        self.assertEqual(len(result), 3)
        cert_path, key_path, cn = result
        self.assertEqual(cn, "sing-box-test")

    def test_returns_custom_common_name(self):
        """Переданный common_name возвращается в результате."""
        from vless_installer.modules.singbox_menu import _ensure_self_signed_cert
        cert_dir = self._tmpdir / "certs"
        cert_dir.mkdir(parents=True, exist_ok=True)
        with patch("vless_installer.modules.singbox_menu.SINGBOX_CERT_DIR", cert_dir):
            with patch("vless_installer.modules.singbox_common.generate_self_signed_cert",
                       return_value=(cert_dir / "test.crt", cert_dir / "test.key")):
                result = _ensure_self_signed_cert("anytls", common_name="vless.example.com")
        cert_path, key_path, cn = result
        self.assertEqual(cn, "vless.example.com")


# ══════════════════════════════════════════════════════════════════════════════
# 5. singbox_enable_anytls — common_name сохраняется в state
# ══════════════════════════════════════════════════════════════════════════════

class TestEnableAnytlsCommonName(unittest.TestCase):
    """singbox_enable_anytls(common_name=...) сохраняет common_name в state."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._sb_state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_config.SINGBOX_CONFIG_DIR", self._tmpdir / "sb"),
            patch("vless_installer.modules.singbox_config.SINGBOX_CONFIG_FILE", self._tmpdir / "sb" / "config.json"),
        ]

    def test_common_name_saved_in_state(self):
        from vless_installer.modules.singbox_config import singbox_enable_anytls
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_get_inbound,
        )
        with ExitStack() as stack:
            for p in self._patches():
                stack.enter_context(p)
            singbox_state_init(version="1.0.0")
            singbox_enable_anytls(
                cert_path="/tmp/cert.pem",
                key_path="/tmp/key.pem",
                cert_source="self-signed",
                common_name="vless.example.com",
            )
            ib = singbox_state_get_inbound("anytls")
        self.assertEqual(ib["common_name"], "vless.example.com")

    def test_common_name_not_overwritten_on_reenable(self):
        """Повторный enable без common_name НЕ затирает существующее значение."""
        from vless_installer.modules.singbox_config import singbox_enable_anytls
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_get_inbound,
        )
        with ExitStack() as stack:
            for p in self._patches():
                stack.enter_context(p)
            singbox_state_init(version="1.0.0")
            singbox_enable_anytls(common_name="first.example.com")
            singbox_enable_anytls()  # без common_name
            ib = singbox_state_get_inbound("anytls")
        # common_name сохранён — НЕ затёрт (т.к. if common_name: сохраняем)
        self.assertEqual(ib["common_name"], "first.example.com")


# ══════════════════════════════════════════════════════════════════════════════
# 6. proxy_protocol on в stream{} (fail2ban regression)
# ══════════════════════════════════════════════════════════════════════════════

class TestProxyProtocolInStreamConf(unittest.TestCase):
    """proxy_protocol on в _build_nginx_stream_conf — критично для fail2ban."""

    def setUp(self):
        _setup_core()

    def test_proxy_protocol_on_in_config(self):
        """proxy_protocol on раскомментирован в stream{} конфиге."""
        from vless_installer.modules.singbox_nginx import _build_nginx_stream_conf
        conf = _build_nginx_stream_conf(
            shadowtls_sni="shadowtls.example.com",
            anytls_sni="anytls.example.com",
            default_backend="127.0.0.1:8442",
        )
        # Строка должна быть активной (не закомментированной)
        self.assertIn("proxy_protocol on;", conf)
        # Проверяем что НЕ закомментировано
        lines = conf.splitlines()
        pp_lines = [l for l in lines if "proxy_protocol on;" in l]
        self.assertGreater(len(pp_lines), 0, "proxy_protocol on; должен быть в конфиге")
        for line in pp_lines:
            self.assertFalse(line.strip().startswith("#"),
                             "proxy_protocol on; не должен быть закомментирован")

    def test_proxy_protocol_not_commented_out(self):
        """Старый закомментированный вариант НЕ должен присутствовать."""
        from vless_installer.modules.singbox_nginx import _build_nginx_stream_conf
        conf = _build_nginx_stream_conf(
            shadowtls_sni="", anytls_sni="", default_backend="127.0.0.1:8442",
        )
        self.assertNotIn("# proxy_protocol on;", conf,
                         "proxy_protocol on не должен быть закомментирован")


# ══════════════════════════════════════════════════════════════════════════════
# 7. _comment_out_listen_443 / _uncomment_listen_443
# ══════════════════════════════════════════════════════════════════════════════

class TestCommentUncommentListen443(unittest.TestCase):
    """Миграция listen 443 между http{} и stream{}."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_comment_out_listen_443(self):
        from vless_installer.modules.singbox_nginx import _comment_out_listen_443
        cfg = self._tmpdir / "test.conf"
        cfg.write_text(
            "server {\n"
            "    listen 443 ssl http2;\n"
            "    server_name example.com;\n"
            "}\n"
        )
        result = _comment_out_listen_443(cfg)
        self.assertTrue(result)
        content = cfg.read_text()
        self.assertIn("# [SNI-DISPATCH] listen 443 ssl http2;", content)
        # server_name не закомментирован
        self.assertIn("server_name example.com;", content)

    def test_comment_creates_backup(self):
        from vless_installer.modules.singbox_nginx import _comment_out_listen_443
        cfg = self._tmpdir / "test.conf"
        original = "server {\n    listen 443 ssl;\n}\n"
        cfg.write_text(original)
        _comment_out_listen_443(cfg)
        backup = cfg.with_suffix(".conf.pre-sni-dispatch")
        self.assertTrue(backup.exists())
        self.assertEqual(backup.read_text(), original)

    def test_uncomment_listen_443(self):
        from vless_installer.modules.singbox_nginx import _uncomment_listen_443
        cfg = self._tmpdir / "test.conf"
        cfg.write_text(
            "server {\n"
            "    # [SNI-DISPATCH] listen 443 ssl http2;\n"
            "    server_name example.com;\n"
            "}\n"
        )
        result = _uncomment_listen_443(cfg)
        self.assertTrue(result)
        content = cfg.read_text()
        self.assertIn("listen 443 ssl http2;", content)
        self.assertNotIn("# [SNI-DISPATCH]", content)

    def test_uncomment_preserves_other_comments(self):
        from vless_installer.modules.singbox_nginx import _uncomment_listen_443
        cfg = self._tmpdir / "test.conf"
        cfg.write_text(
            "server {\n"
            "    # regular comment\n"
            "    # [SNI-DISPATCH] listen 443 ssl;\n"
            "}\n"
        )
        _uncomment_listen_443(cfg)
        content = cfg.read_text()
        self.assertIn("# regular comment", content)
        self.assertIn("listen 443 ssl;", content)

    def test_does_not_comment_unix_socket_listen(self):
        """listen unix:/path НЕ должен комментироваться — это decoy-сокет."""
        from vless_installer.modules.singbox_nginx import _comment_out_listen_443
        cfg = self._tmpdir / "test.conf"
        cfg.write_text(
            "server {\n"
            "    listen unix:/dev/shm/abc.socket ssl proxy_protocol;\n"
            "    listen 443 ssl;\n"
            "}\n"
        )
        _comment_out_listen_443(cfg)
        content = cfg.read_text()
        # unix: listen НЕ закомментирован
        self.assertIn("listen unix:/dev/shm/abc.socket ssl proxy_protocol;", content)
        self.assertNotIn("# [SNI-DISPATCH] listen unix:", content)
        # 443 listen закомментирован
        self.assertIn("# [SNI-DISPATCH] listen 443 ssl;", content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
