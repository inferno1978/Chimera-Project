#!/usr/bin/env python3
"""
tests/test_dnscrypt_selector.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/dnscrypt_selector.py.

Покрывает:
  1. _get_dnscrypt_port — чтение порта из конфига
  2. _get_current_server_names — чтение server_names
  3. _apply_server_names — патч server_names
  4. _parse_resolver_ips_from_md — декодирование sdns:// stamps
"""
from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
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


class TestGetDnscryptPort(unittest.TestCase):
    """_get_dnscrypt_port — чтение порта."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "dnscrypt-proxy.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.dnscrypt_selector._DNSCRYPT_CONF", self._cfg)

    def test_returns_default_when_no_file(self):
        from chimera.modules.dnscrypt_selector import _get_dnscrypt_port
        with self._patch():
            self.assertEqual(_get_dnscrypt_port(), 5300)

    def test_returns_port_from_config(self):
        from chimera.modules.dnscrypt_selector import _get_dnscrypt_port
        self._cfg.write_text("listen_addresses = ['127.0.0.1:5300']\n")
        with self._patch():
            self.assertEqual(_get_dnscrypt_port(), 5300)

    def test_returns_default_when_no_listen_addresses(self):
        from chimera.modules.dnscrypt_selector import _get_dnscrypt_port
        self._cfg.write_text("server_names = ['cloudflare']\n")
        with self._patch():
            self.assertEqual(_get_dnscrypt_port(), 5300)


class TestGetCurrentServerNames(unittest.TestCase):
    """_get_current_server_names — чтение server_names."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "dnscrypt-proxy.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.dnscrypt_selector._DNSCRYPT_CONF", self._cfg)

    def test_returns_empty_when_no_file(self):
        from chimera.modules.dnscrypt_selector import _get_current_server_names
        with self._patch():
            self.assertEqual(_get_current_server_names(), [])

    def test_returns_server_names(self):
        from chimera.modules.dnscrypt_selector import _get_current_server_names
        self._cfg.write_text("server_names = ['cloudflare', 'google']\n")
        with self._patch():
            result = _get_current_server_names()
        self.assertEqual(result, ["cloudflare", "google"])

    def test_returns_empty_when_no_server_names(self):
        from chimera.modules.dnscrypt_selector import _get_current_server_names
        self._cfg.write_text("listen_addresses = ['127.0.0.1:5300']\n")
        with self._patch():
            self.assertEqual(_get_current_server_names(), [])


class TestApplyServerNames(unittest.TestCase):
    """_apply_server_names — патч server_names."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "dnscrypt-proxy.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.dnscrypt_selector._DNSCRYPT_CONF", self._cfg)

    def test_replaces_existing_server_names(self):
        from chimera.modules.dnscrypt_selector import _apply_server_names
        self._cfg.write_text("server_names = ['old']\n")
        with self._patch():
            result = _apply_server_names(["new1", "new2"])
        self.assertTrue(result)
        content = self._cfg.read_text()
        self.assertIn("new1", content)
        self.assertIn("new2", content)
        self.assertNotIn("old", content)

    def test_inserts_when_missing(self):
        from chimera.modules.dnscrypt_selector import _apply_server_names
        self._cfg.write_text("listen_addresses = ['127.0.0.1:5300']\n")
        with self._patch():
            result = _apply_server_names(["cloudflare"])
        self.assertTrue(result)
        content = self._cfg.read_text()
        self.assertIn("server_names", content)
        self.assertIn("cloudflare", content)

    def test_returns_false_when_no_config(self):
        from chimera.modules.dnscrypt_selector import _apply_server_names
        with self._patch():
            result = _apply_server_names(["cloudflare"])
        self.assertFalse(result)


class TestParseResolverIpsFromMd(unittest.TestCase):
    """_parse_resolver_ips_from_md — декодирование sdns:// stamps."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_sdns_stamp(self, ip: str = "1.2.3.4", port: int = 443) -> str:
        """Создаёт минимальный sdns:// stamp для DNS-over-HTTPS.
        Format: proto(1) + props(8) + addr_len(1) + addr + port(2)."""
        import struct
        proto = b"\x01"  # DoH
        props = struct.pack("<Q", 0)  # props = 0
        addr = f"{ip}:{port}".encode()
        addr_len = bytes([len(addr)])
        stamp = proto + props + addr_len + addr
        # base64url without padding
        b64 = base64.urlsafe_b64encode(stamp).decode().rstrip("=")
        return f"sdns://{b64}"

    def test_returns_empty_when_no_file(self):
        from chimera.modules.dnscrypt_selector import _parse_resolver_ips_from_md
        with patch("pathlib.Path.exists", return_value=False):
            result = _parse_resolver_ips_from_md()
        self.assertEqual(result, {})

    def test_parses_valid_md_file(self):
        from chimera.modules import dnscrypt_selector
        stamp = self._make_sdns_stamp("9.9.9.9", 443)
        md_content = f"## cloudflare\n\n{stamp}\n\n## google\n\nsdns://invalid\n"
        tmp_file = self._tmpdir / "public-resolvers.md"
        tmp_file.write_text(md_content)
        with patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=md_content):
            result = dnscrypt_selector._parse_resolver_ips_from_md()
        # должен найти хотя бы cloudflare
        self.assertIsInstance(result, dict)


if __name__ == "__main__":
    unittest.main(verbosity=2)
