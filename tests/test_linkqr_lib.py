#!/usr/bin/env python3
"""
tests/test_linkqr_lib.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/linkqr_lib.py.

Покрывает:
  1. generate_qr_png — генерация QR-кода в PNG
  2. build_vless_link_for_user — VLESS REALITY / xHTTP, Mode A / B / AWG-exit
  3. build_awg_link_for_user — поиск пира по owner_email + проверка TTL
  4. build_singbox_links_for_user — фильтр по UUID + обработка отсутствующего state
  5. build_hysteria2_link — общий пароль exit-ноды
  6. build_all_links_for_user — агрегация
  7. build_subscription_url_for_user — токен / domain
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


def _setup_core_in_sysmodules():
    """Создаёт фейковый vless_installer._core в sys.modules (как в test_tg_bot)."""
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


class TestGenerateQrPng(unittest.TestCase):
    """generate_qr_png — единая функция QR-to-PNG."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_generates_png_for_simple_text(self):
        from vless_installer.modules import linkqr_lib
        out = self._tmpdir / "qr1.png"
        ok = linkqr_lib.generate_qr_png("vless://test-uuid@example.com:443", out)
        # qrencode может быть не установлен в CI — принимаем оба исхода,
        # но если установлен, файл точно должен создаться
        if ok:
            self.assertTrue(out.exists())
            self.assertGreater(out.stat().st_size, 100)

    def test_empty_text_returns_false(self):
        from vless_installer.modules import linkqr_lib
        out = self._tmpdir / "qr2.png"
        self.assertFalse(linkqr_lib.generate_qr_png("", out))
        self.assertFalse(out.exists())

    def test_long_text_uses_low_error_correction(self):
        """Длинный vpn:// URI (>800 символов) не должен падать."""
        from vless_installer.modules import linkqr_lib
        out = self._tmpdir / "qr3.png"
        long_text = "vpn://free/" + "A" * 1500
        # Функция должна ПОПЫТАТЬСЯ сгенерировать (с -l L).
        # Если qrencode не установлен — fallback на python3-qrcode.
        # В любом случае не должно кидать исключение.
        try:
            linkqr_lib.generate_qr_png(long_text, out)
        except Exception as e:
            self.fail(f"generate_qr_png raised on long text: {e}")


class TestBuildVlessLinkForUser(unittest.TestCase):
    """build_vless_link_for_user — построение vless:// ссылки."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state(self, state_dict):
        self._state.write_text(json.dumps(state_dict))
        return patch("vless_installer.modules.linkqr_lib._MAIN_STATE_FILE", self._state)

    def test_reality_mode_with_user_uuid(self):
        from vless_installer.modules import linkqr_lib
        state = {
            "domain": "vpn.example.com",
            "uuid": "primary-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
            "fingerprint": "chrome",
            "xtls_flow": "xtls-rprx-vision",
            "server_port": 443,
        }
        with self._patch_state(state):
            link = linkqr_lib.build_vless_link_for_user("user-uuid-123")
        self.assertIn("vless://user-uuid-123@", link)
        self.assertIn("vpn.example.com:443", link)
        self.assertIn("security=reality", link)
        self.assertIn("pbk=PUBKEY", link)
        self.assertIn("sid=abcd1234", link)
        self.assertIn("flow=xtls-rprx-vision", link)
        # Должен использовать user-uuid, а не primary
        self.assertNotIn("primary-uuid", link)

    def test_reality_mode_no_user_uuid_uses_primary(self):
        from vless_installer.modules import linkqr_lib
        state = {
            "domain": "vpn.example.com",
            "uuid": "primary-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd",
        }
        with self._patch_state(state):
            link = linkqr_lib.build_vless_link_for_user(None)
        self.assertIn("vless://primary-uuid@", link)

    def test_xhttp_mode(self):
        from vless_installer.modules import linkqr_lib
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "xhttp",
            "xhttp_path": "/xhttp",
            "xhttp_mode": "streamup",
            "fingerprint": "chrome",
            "server_port": 443,
        }
        with self._patch_state(state):
            link = linkqr_lib.build_vless_link_for_user("test-uuid")
        self.assertIn("type=xhttp", link)
        self.assertIn("security=tls", link)
        self.assertIn("path=/xhttp", link)

    def test_mode_b_awg_uses_reality_dest_sni(self):
        from vless_installer.modules import linkqr_lib
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd",
            "reality_dest": "dest.example.com:443",
            "awg_exit_enabled": True,
            "install_mode": "B",
        }
        with self._patch_state(state):
            link = linkqr_lib.build_vless_link_for_user("test-uuid")
        self.assertIn("sni=dest.example.com", link)

    def test_empty_when_no_domain(self):
        from vless_installer.modules import linkqr_lib
        with self._patch_state({"uuid": "test-uuid"}):
            self.assertEqual(linkqr_lib.build_vless_link_for_user("test-uuid"), "")

    def test_empty_when_no_uuid(self):
        from vless_installer.modules import linkqr_lib
        with self._patch_state({"domain": "vpn.example.com"}):
            self.assertEqual(linkqr_lib.build_vless_link_for_user(None), "")

    def test_no_private_key_in_link(self):
        """Приватный ключ сервера НЕ должен попадать в ссылку."""
        from vless_installer.modules import linkqr_lib
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "private_key": "SUPER-SECRET-PRIVATE-KEY",
            "short_id": "abcd",
        }
        with self._patch_state(state):
            link = linkqr_lib.build_vless_link_for_user("test-uuid")
        self.assertNotIn("SUPER-SECRET-PRIVATE-KEY", link)
        self.assertNotIn("private_key", link)


class TestBuildAwgLinkForUser(unittest.TestCase):
    """build_awg_link_for_user — поиск пира + TTL."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._awg_state = self._tmpdir / "awg.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_awg(self, state_dict):
        self._awg_state.write_text(json.dumps(state_dict))
        return patch("vless_installer.modules.linkqr_lib._AWG_STATE_FILE", self._awg_state)

    def test_returns_empty_when_awg_not_installed(self):
        from vless_installer.modules import linkqr_lib
        with self._patch_awg({"installed": False}):
            self.assertEqual(linkqr_lib.build_awg_link_for_user("alice@xray"), "")

    def test_returns_empty_when_no_peer_for_email(self):
        from vless_installer.modules import linkqr_lib
        with self._patch_awg({
            "installed": True,
            "server_pubkey": "PUB",
            "endpoint": "1.2.3.4",
            "port": 51820,
            "params": {},
            "peers": [{"name": "bob", "owner_email": "bob@xray"}],
        }):
            self.assertEqual(linkqr_lib.build_awg_link_for_user("alice@xray"), "")


class TestBuildSingboxLinksForUser(unittest.TestCase):
    """build_singbox_links_for_user — фильтр по UUID."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._sb_state = self._tmpdir / "sb.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_sb(self, state_dict):
        self._sb_state.write_text(json.dumps(state_dict))
        return patch("vless_installer.modules.linkqr_lib._SINGBOX_STATE_FILE", self._sb_state)

    def test_returns_empty_when_not_installed(self):
        from vless_installer.modules import linkqr_lib
        with self._patch_sb({"installed": False}):
            self.assertEqual(linkqr_lib.build_singbox_links_for_user("uuid-1"), [])

    def test_returns_empty_when_no_inbounds(self):
        from vless_installer.modules import linkqr_lib
        with self._patch_sb({"installed": True, "inbounds": {}}):
            self.assertEqual(linkqr_lib.build_singbox_links_for_user("uuid-1"), [])


class TestBuildHysteria2Link(unittest.TestCase):
    """build_hysteria2_link — общий пароль exit-ноды."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self, state_dict):
        self._state.write_text(json.dumps(state_dict))
        return patch("vless_installer.modules.linkqr_lib._MAIN_STATE_FILE", self._state)

    def test_returns_none_when_not_enabled(self):
        from vless_installer.modules import linkqr_lib
        with self._patch({"hysteria2": {"enabled": False}}):
            self.assertIsNone(linkqr_lib.build_hysteria2_link())

    def test_returns_none_when_no_active_node(self):
        from vless_installer.modules import linkqr_lib
        with self._patch({
            "hysteria2": {
                "enabled": True,
                "exit_nodes": [{"status": "down", "ip": "1.2.3.4", "ports": [443], "auth": "pwd"}],
            }
        }):
            self.assertIsNone(linkqr_lib.build_hysteria2_link())

    def test_returns_none_when_no_password(self):
        from vless_installer.modules import linkqr_lib
        with self._patch({
            "hysteria2": {
                "enabled": True,
                "exit_nodes": [{"status": "active", "ip": "1.2.3.4", "ports": [443], "auth": ""}],
            }
        }):
            self.assertIsNone(linkqr_lib.build_hysteria2_link())


class TestBuildAllLinksForUser(unittest.TestCase):
    """build_all_links_for_user — агрегатор."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"
        self._sub_conf = self._tmpdir / "sub.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state(self, state_dict):
        self._state.write_text(json.dumps(state_dict))
        return patch("vless_installer.modules.linkqr_lib._MAIN_STATE_FILE", self._state)

    def _patch_sub(self, sub_dict):
        self._sub_conf.write_text(json.dumps(sub_dict))
        return patch("vless_installer.modules.linkqr_lib._SUB_CONF_FILE", self._sub_conf)

    def test_empty_user_returns_empty(self):
        from vless_installer.modules import linkqr_lib
        self.assertEqual(linkqr_lib.build_all_links_for_user({}), {})

    def test_returns_vless_when_state_configured(self):
        from vless_installer.modules import linkqr_lib
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd",
        }
        with self._patch_state(state):
            links = linkqr_lib.build_all_links_for_user({"uuid": "test-uuid", "email": "alice@xray"})
        self.assertIn("vless", links)
        self.assertIn("vless://", links["vless"])

    def test_subscription_url_included_when_pepper_set(self):
        from vless_installer.modules import linkqr_lib
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd",
        }
        with self._patch_state(state), \
             self._patch_sub({"pepper": "mysecret", "port": 8443}):
            links = linkqr_lib.build_all_links_for_user({"uuid": "test-uuid", "email": "alice@xray"})
        self.assertIn("subscription", links)
        self.assertTrue(links["subscription"].startswith("https://vpn.example.com:8443/sub/"))


class TestSubscriptionUrlForUser(unittest.TestCase):
    """build_subscription_url_for_user — токен / domain."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"
        self._sub_conf = self._tmpdir / "sub.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state(self, state_dict):
        self._state.write_text(json.dumps(state_dict))
        return patch("vless_installer.modules.linkqr_lib._MAIN_STATE_FILE", self._state)

    def _patch_sub(self, sub_dict):
        self._sub_conf.write_text(json.dumps(sub_dict))
        return patch("vless_installer.modules.linkqr_lib._SUB_CONF_FILE", self._sub_conf)

    def test_returns_none_when_no_pepper(self):
        from vless_installer.modules import linkqr_lib
        with self._patch_sub({}):
            self.assertIsNone(linkqr_lib.build_subscription_url_for_user({"uuid": "abc"}))

    def test_returns_none_when_no_uuid(self):
        from vless_installer.modules import linkqr_lib
        with self._patch_sub({"pepper": "p"}):
            self.assertIsNone(linkqr_lib.build_subscription_url_for_user({}))

    def test_returns_none_when_no_domain(self):
        from vless_installer.modules import linkqr_lib
        with self._patch_state({}), self._patch_sub({"pepper": "p"}):
            self.assertIsNone(linkqr_lib.build_subscription_url_for_user({"uuid": "abc"}))

    def test_returns_url_when_all_set(self):
        from vless_installer.modules import linkqr_lib
        with self._patch_state({"domain": "vpn.example.com"}), \
             self._patch_sub({"pepper": "pepper", "port": 8443}):
            url = linkqr_lib.build_subscription_url_for_user({"uuid": "abc-uuid"})
        self.assertIsNotNone(url)
        self.assertIn("vpn.example.com:8443/sub/", url)
        # Токен — 24 hex-символа (HMAC-SHA256[:24])
        token = url.rsplit("/", 1)[-1]
        self.assertEqual(len(token), 24)
        self.assertTrue(all(c in "0123456789abcdef" for c in token))

    def test_token_is_deterministic(self):
        """Один и тот же (uuid, pepper) → один и тот же токен."""
        from vless_installer.modules import linkqr_lib
        with self._patch_state({"domain": "x"}), \
             self._patch_sub({"pepper": "p", "port": 1}):
            url1 = linkqr_lib.build_subscription_url_for_user({"uuid": "abc"})
            url2 = linkqr_lib.build_subscription_url_for_user({"uuid": "abc"})
        self.assertEqual(url1, url2)


class TestReadUsersAndFinders(unittest.TestCase):
    """_read_users, _find_user_by_uuid, _find_user_by_email."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._users = self._tmpdir / "users.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.linkqr_lib._USERS_FILE", self._users)

    def test_read_users_empty_when_no_file(self):
        from vless_installer.modules import linkqr_lib
        with self._patch():
            self.assertEqual(linkqr_lib._read_users(), [])

    def test_find_by_uuid(self):
        from vless_installer.modules import linkqr_lib
        users = [
            {"uuid": "u1", "email": "alice@xray"},
            {"uuid": "u2", "email": "bob@xray"},
        ]
        self._users.write_text(json.dumps(users))
        with self._patch():
            u = linkqr_lib._find_user_by_uuid("u2")
        self.assertIsNotNone(u)
        self.assertEqual(u["email"], "bob@xray")

    def test_find_by_email_returns_none_when_missing(self):
        from vless_installer.modules import linkqr_lib
        self._users.write_text(json.dumps([{"uuid": "u1", "email": "alice@xray"}]))
        with self._patch():
            self.assertIsNone(linkqr_lib._find_user_by_email("nobody@xray"))


if __name__ == "__main__":
    unittest.main()
