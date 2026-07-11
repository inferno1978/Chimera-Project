#!/usr/bin/env python3
"""
tests/test_subscription.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/subscription.py.

Покрывает:
  1. _token_for — HMAC токен
  2. _make_tls_secret — генерация TLS-секрета
  3. _candidate_names — сбор кандидатов имён
  4. _resolve_sni — выбор SNI
  5. _build_userinfo_header — заголовок userinfo
  6. _unit_text — генерация systemd unit
  7. _gen_mieru_share_link — генерация mierus:// URL
  8. _load_sub_conf / _save_sub_conf — JSON I/O
  9. _ensure_pepper — генерация pepper
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

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


class TestTokenFor(unittest.TestCase):
    """_token_for — HMAC токен (pure)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_24_char_hex(self):
        from vless_installer.modules.subscription import _token_for
        token = _token_for("uuid-123", "pepper-123")
        self.assertEqual(len(token), 24)
        self.assertTrue(all(c in "0123456789abcdef" for c in token))

    def test_deterministic(self):
        """Одинаковые ввод → одинаковый токен."""
        from vless_installer.modules.subscription import _token_for
        t1 = _token_for("uuid-123", "pepper-123")
        t2 = _token_for("uuid-123", "pepper-123")
        self.assertEqual(t1, t2)

    def test_different_uuid_different_token(self):
        from vless_installer.modules.subscription import _token_for
        t1 = _token_for("uuid-1", "pepper")
        t2 = _token_for("uuid-2", "pepper")
        self.assertNotEqual(t1, t2)

    def test_different_pepper_different_token(self):
        from vless_installer.modules.subscription import _token_for
        t1 = _token_for("uuid", "pepper-1")
        t2 = _token_for("uuid", "pepper-2")
        self.assertNotEqual(t1, t2)

    def test_uses_hmac_sha256(self):
        """Проверка что используется именно HMAC-SHA256."""
        from vless_installer.modules.subscription import _token_for
        expected = hmac.new(
            b"pepper", b"uuid", hashlib.sha256
        ).hexdigest()[:24]
        self.assertEqual(_token_for("uuid", "pepper"), expected)


class TestMakeTlsSecret(unittest.TestCase):
    """_make_tls_secret — pure."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_ee_prefix(self):
        from vless_installer.modules.subscription import _make_tls_secret
        result = _make_tls_secret("base_secret", "example.com")
        self.assertTrue(result.startswith("ee"))

    def test_contains_base_secret(self):
        from vless_installer.modules.subscription import _make_tls_secret
        result = _make_tls_secret("mysecret", "example.com")
        self.assertIn("mysecret", result)

    def test_contains_hex_domain(self):
        from vless_installer.modules.subscription import _make_tls_secret
        result = _make_tls_secret("base", "example.com")
        # domain.encode().hex() должен присутствовать
        self.assertIn("example.com".encode().hex(), result)

    def test_deterministic(self):
        from vless_installer.modules.subscription import _make_tls_secret
        self.assertEqual(
            _make_tls_secret("base", "domain"),
            _make_tls_secret("base", "domain"),
        )


class TestCandidateNames(unittest.TestCase):
    """_candidate_names — pure."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_set(self):
        from vless_installer.modules.subscription import _candidate_names
        result = _candidate_names({"name": "alice", "email": "alice@x.com"})
        self.assertIsInstance(result, set)

    def test_includes_name_and_email_local_part(self):
        from vless_installer.modules.subscription import _candidate_names
        result = _candidate_names({
            "name": "alice", "email": "alice@example.com",
        })
        self.assertIn("alice", result)

    def test_lowercases(self):
        from vless_installer.modules.subscription import _candidate_names
        result = _candidate_names({"name": "ALICE", "email": "ALICE@Example.COM"})
        self.assertIn("alice", result)

    def test_empty_fields_excluded(self):
        from vless_installer.modules.subscription import _candidate_names
        result = _candidate_names({"name": "", "email": ""})
        self.assertNotIn("", result)


class TestResolveSni(unittest.TestCase):
    """_resolve_sni — выбор SNI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_domain_for_reality_without_awg(self):
        from vless_installer.modules.subscription import _resolve_sni
        state = {"proto": "reality", "domain": "vpn.example.com"}
        self.assertEqual(_resolve_sni(state), "vpn.example.com")

    def test_returns_reality_dest_for_awg_reality_mode_b(self):
        from vless_installer.modules.subscription import _resolve_sni
        state = {
            "proto": "reality", "awg_exit_enabled": True,
            "install_mode": "B", "reality_dest": "dest.example.com:443",
            "domain": "vpn.example.com",
        }
        self.assertEqual(_resolve_sni(state), "dest.example.com")


class TestBuildUserinfoHeader(unittest.TestCase):
    """_build_userinfo_header — pure."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_none_when_no_email(self):
        from vless_installer.modules.subscription import _build_userinfo_header
        self.assertIsNone(_build_userinfo_header({"email": ""}))

    def test_returns_none_when_no_limit(self):
        from vless_installer.modules.subscription import _build_userinfo_header
        with patch("vless_installer.modules.subscription._load_traffic_limits",
                   return_value={}):
            result = _build_userinfo_header({"email": "alice@x.com"})
        self.assertIsNone(result)

    def test_returns_header_when_limit_set(self):
        from vless_installer.modules.subscription import _build_userinfo_header
        with patch("vless_installer.modules.subscription._load_traffic_limits",
                   return_value={"alice@x.com": {"limit_gb": 10}}):
            result = _build_userinfo_header({"email": "alice@x.com"})
        self.assertIsNotNone(result)
        self.assertIn("upload=", result)
        self.assertIn("download=", result)
        self.assertIn("total=", result)
        # 10 GB = 10 * 1024^3
        self.assertIn(str(10 * 1024 ** 3), result)


class TestUnitText(unittest.TestCase):
    """_unit_text — pure string builder."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_string_with_substitutions(self):
        from vless_installer.modules.subscription import _unit_text
        result = _unit_text("/usr/bin/python3", "/path/to/module.py", 8443)
        self.assertIn("/usr/bin/python3", result)
        self.assertIn("/path/to/module.py", result)
        self.assertIn("8443", result)

    def test_contains_restart_always(self):
        from vless_installer.modules.subscription import _unit_text
        result = _unit_text("/usr/bin/python3", "/path.py", 8443)
        self.assertIn("Restart=always", result)


class TestGenMieruShareLink(unittest.TestCase):
    """_gen_mieru_share_link — pure URL builder."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_mierus_url(self):
        from vless_installer.modules.subscription import _gen_mieru_share_link
        result = _gen_mieru_share_link("1.2.3.4", 8443, "tcp", "user", "pass")
        self.assertTrue(result.startswith("mierus://"))

    def test_contains_credentials(self):
        from vless_installer.modules.subscription import _gen_mieru_share_link
        result = _gen_mieru_share_link("1.2.3.4", 8443, "tcp", "user", "pass")
        self.assertIn("user:pass", result)

    def test_contains_port_and_protocol(self):
        from vless_installer.modules.subscription import _gen_mieru_share_link
        result = _gen_mieru_share_link("1.2.3.4", 8443, "tcp", "user", "pass")
        self.assertIn("port=8443", result)
        self.assertIn("protocol=TCP", result)  # uppercase


class TestLoadSaveSubConf(unittest.TestCase):
    """_load_sub_conf / _save_sub_conf — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._conf = self._tmpdir / "sub_conf.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.subscription._SUB_CONF", self._conf)

    def test_load_returns_empty_when_no_file(self):
        from vless_installer.modules.subscription import _load_sub_conf
        with self._patch():
            self.assertEqual(_load_sub_conf(), {})

    def test_load_returns_empty_on_corrupt(self):
        from vless_installer.modules.subscription import _load_sub_conf
        self._conf.write_text("{invalid")
        with self._patch():
            self.assertEqual(_load_sub_conf(), {})

    def test_save_then_load(self):
        from vless_installer.modules.subscription import _load_sub_conf, _save_sub_conf
        with self._patch():
            _save_sub_conf({"pepper": "abc", "identity_map": {}})
            loaded = _load_sub_conf()
        self.assertEqual(loaded["pepper"], "abc")


class TestEnsurePepper(unittest.TestCase):
    """_ensure_pepper — генерация pepper."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._conf = self._tmpdir / "sub_conf.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.subscription._SUB_CONF", self._conf)

    def test_returns_existing_pepper(self):
        from vless_installer.modules.subscription import (
            _ensure_pepper, _load_sub_conf,
        )
        self._conf.write_text(json.dumps({"pepper": "existing"}))
        with self._patch():
            cfg = _load_sub_conf()
            result = _ensure_pepper(cfg)
        self.assertEqual(result, "existing")

    def test_generates_new_pepper_when_missing(self):
        from vless_installer.modules.subscription import _ensure_pepper
        with self._patch():
            result = _ensure_pepper({})
        self.assertGreater(len(result), 10)
        # pepper сохраняется в конфиг
        saved = json.loads(self._conf.read_text())
        self.assertEqual(saved["pepper"], result)

    def test_generated_pepper_is_hex(self):
        from vless_installer.modules.subscription import _ensure_pepper
        with self._patch():
            result = _ensure_pepper({})
        self.assertTrue(all(c in "0123456789abcdef" for c in result))


if __name__ == "__main__":
    unittest.main(verbosity=2)
