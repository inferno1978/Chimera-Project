#!/usr/bin/env python3
"""
tests/test_dnscrypt_setup.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/dnscrypt_setup.py.

Покрывает:
  1. _get_dnscrypt_port — чтение порта из конфига
"""
from __future__ import annotations

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


class TestGetDnscryptPort(unittest.TestCase):
    """_get_dnscrypt_port — чтение порта."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "dnscrypt-proxy.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _mock_core(self, cfg_content=None):
        core = MagicMock()
        core.DNSCRYPT_CONF = self._cfg
        core.DNSCRYPT_LISTEN_PORT = 5300
        if cfg_content is not None:
            self._cfg.write_text(cfg_content)
        return core

    def test_returns_default_when_no_file(self):
        from vless_installer.modules import dnscrypt_setup
        with patch.object(dnscrypt_setup, "_core_module",
                          return_value=self._mock_core()):
            self.assertEqual(dnscrypt_setup._get_dnscrypt_port(), 5300)

    def test_returns_port_from_config(self):
        from vless_installer.modules import dnscrypt_setup
        cfg = "listen_addresses = ['127.0.0.1:5300']\n"
        with patch.object(dnscrypt_setup, "_core_module",
                          return_value=self._mock_core(cfg)):
            self.assertEqual(dnscrypt_setup._get_dnscrypt_port(), 5300)

    def test_returns_port_with_double_quotes(self):
        from vless_installer.modules import dnscrypt_setup
        cfg = 'listen_addresses = ["127.0.0.1:5353"]\n'
        with patch.object(dnscrypt_setup, "_core_module",
                          return_value=self._mock_core(cfg)):
            self.assertEqual(dnscrypt_setup._get_dnscrypt_port(), 5353)

    def test_returns_default_when_no_listen_addresses(self):
        from vless_installer.modules import dnscrypt_setup
        cfg = "server_names = ['cloudflare']\n"
        with patch.object(dnscrypt_setup, "_core_module",
                          return_value=self._mock_core(cfg)):
            self.assertEqual(dnscrypt_setup._get_dnscrypt_port(), 5300)


# ============================================================================
#  ТЕСТЫ DNSCRYPT_SPEC — sanity-проверки (Волна 3)
# ============================================================================
class TestDnscryptSpecSanity(unittest.TestCase):
    """Sanity-проверки DNSCRYPT_SPEC — что мигрированный spec корректен."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_name_is_dnscrypt_proxy(self):
        from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertEqual(DNSCRYPT_SPEC.name, "dnscrypt-proxy")

    def test_filename_builder_uses_tag_and_arch(self):
        from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertEqual(
            DNSCRYPT_SPEC.filename_builder(tag="2.1.5", arch="linux_x86_64"),
            "dnscrypt-proxy-linux_x86_64-2.1.5.tar.gz",
        )
        self.assertEqual(
            DNSCRYPT_SPEC.filename_builder(tag="2.1.5", arch="linux_arm64"),
            "dnscrypt-proxy-linux_arm64-2.1.5.tar.gz",
        )

    def test_install_dests_is_usr_local_bin(self):
        from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertEqual(DNSCRYPT_SPEC.install_dests, [Path("/usr/local/bin")])

    def test_manual_dir_is_root(self):
        from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertEqual(DNSCRYPT_SPEC.manual_incoming_dir, Path("/root"))

    def test_manual_dir_not_in_install_dests(self):
        """КРИТИЧЕСКИЙ ИНВАРИАНТ (баг 21d7baf)."""
        from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC
        for dest in DNSCRYPT_SPEC.install_dests:
            self.assertNotEqual(DNSCRYPT_SPEC.manual_incoming_dir, dest)

    def test_min_size_is_100kb(self):
        """min_size = 100 KB — защита от 404 HTML-страниц (раньше не было)."""
        from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertEqual(DNSCRYPT_SPEC.min_size, 100_000)

    def test_post_install_is_set(self):
        from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC
        self.assertIsNotNone(DNSCRYPT_SPEC.post_install)

    def test_mirror_urls_has_14_entries(self):
        """Сценарий 2: 14 зеркал для fallback."""
        from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC
        urls = DNSCRYPT_SPEC.mirror_urls_builder(
            filename="dnscrypt-proxy-linux_x86_64-2.1.5.tar.gz",
            tag="2.1.5", arch="linux_x86_64",
        )
        self.assertEqual(len(urls), 14)

    def test_post_install_returns_false_on_non_tarball(self):
        """post_install возвращает False на не-tar.gz файле."""
        import tempfile
        from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC

        tmpdir = Path(tempfile.mkdtemp())
        try:
            src = tmpdir / "fake.tar.gz"
            src.write_bytes(b"not a tarball" * 100)
            ok = DNSCRYPT_SPEC.post_install(src, [tmpdir / "install"])
            self.assertFalse(ok)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_post_install_returns_false_on_empty_file(self):
        from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC

        tmpdir = Path(tempfile.mkdtemp())
        try:
            src = tmpdir / "empty.tar.gz"
            src.write_bytes(b"")
            ok = DNSCRYPT_SPEC.post_install(src, [tmpdir / "install"])
            self.assertFalse(ok)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
