#!/usr/bin/env python3
"""
tests/test_hysteria2_exit_mgr.py — _generate_h2_config
"""
from __future__ import annotations
import sys, unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

def _setup_core():
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text(); g = {}
    with patch.object(Path, 'mkdir', lambda s,*a,**k: None), \
         patch.object(Path, 'touch', lambda s,*a,**k: None), \
         patch.object(Path, 'chmod', lambda s,*a,**k: None), \
         patch('os.chown', lambda *a,**k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types; m = types.ModuleType("vless_installer._core"); m.__dict__.update(g)
    sys.modules["vless_installer._core"] = m

class TestGenerateH2Config(unittest.TestCase):
    def setUp(self): _setup_core()

    def test_single_port(self):
        from vless_installer.modules.hysteria2_exit_mgr import _generate_h2_config
        cfg = _generate_h2_config("0.0.0.0", [443], "pass", "/cert.pem", "/key.pem")
        self.assertIn("443", cfg)
        self.assertIn("pass", cfg)
        self.assertIn("/cert.pem", cfg)

    def test_port_range(self):
        from vless_installer.modules.hysteria2_exit_mgr import _generate_h2_config
        cfg = _generate_h2_config("0.0.0.0", [443, 444, 445], "pass", "/c", "/k")
        # range: 443-445
        self.assertIn("443-445", cfg)

    def test_ipv6_bracket(self):
        from vless_installer.modules.hysteria2_exit_mgr import _generate_h2_config
        cfg = _generate_h2_config("::", [443], "pass", "/c", "/k", ipv6=True)
        self.assertIn("[::]", cfg)

    def test_includes_auth_and_tls(self):
        from vless_installer.modules.hysteria2_exit_mgr import _generate_h2_config
        cfg = _generate_h2_config("0.0.0.0", [443], "mypassword", "/cert.pem", "/key.pem")
        self.assertIn("mypassword", cfg)
        self.assertIn("cert", cfg.lower())
        self.assertIn("key", cfg.lower())


# ============================================================================
#  ТЕСТЫ _install_h2_binary — интеграция с download_manager.fetch_package
#  (Волна 3)
# ============================================================================
class TestInstallH2BinaryMigrated(unittest.TestCase):
    """_install_h2_binary — делегирует в fetch_package(HYSTERIA2_SPEC, arch=...)."""

    def setUp(self):
        _setup_core()

    def test_install_calls_fetch_package_with_h2_spec(self):
        """_install_h2_binary вызывает fetch_package(HYSTERIA2_SPEC, arch=...)."""
        from vless_installer.modules import hysteria2_exit_mgr
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC

        with patch("vless_installer.modules.hysteria2_exit_mgr._detect_arch",
                   return_value="amd64"), \
             patch("vless_installer.modules.hysteria2_exit_mgr._h2_latest_url",
                   return_value=("https://example.com/hysteria", "app/v2.9.3")), \
             patch("vless_installer.modules.download_manager.fetch_package",
                   return_value=True) as mock_fp:
            result = hysteria2_exit_mgr._install_h2_binary()

        self.assertTrue(result)
        mock_fp.assert_called_once()
        spec_arg = mock_fp.call_args.args[0]
        self.assertIs(spec_arg, HYSTERIA2_SPEC)
        self.assertEqual(mock_fp.call_args.kwargs.get("arch"), "amd64")

    def test_install_returns_false_when_fetch_fails(self):
        """Сценарий 4: полный провал всех зеркал → False."""
        from vless_installer.modules import hysteria2_exit_mgr

        with patch("vless_installer.modules.hysteria2_exit_mgr._detect_arch",
                   return_value="amd64"), \
             patch("vless_installer.modules.download_manager.fetch_package",
                   return_value=False) as mock_fp:
            result = hysteria2_exit_mgr._install_h2_binary()

        self.assertFalse(result)
        mock_fp.assert_called_once()


class TestHysteria2SpecSanity(unittest.TestCase):
    """Sanity-проверки HYSTERIA2_SPEC."""

    def setUp(self):
        _setup_core()

    def test_name_is_hysteria2(self):
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC
        self.assertEqual(HYSTERIA2_SPEC.name, "Hysteria2")

    def test_filename_builder_uses_arch(self):
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC
        self.assertEqual(HYSTERIA2_SPEC.filename_builder(arch="amd64"),
                         "hysteria-linux-amd64")
        self.assertEqual(HYSTERIA2_SPEC.filename_builder(arch="arm64"),
                         "hysteria-linux-arm64")

    def test_install_dests_is_usr_local_bin(self):
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC
        self.assertEqual(HYSTERIA2_SPEC.install_dests, [Path("/usr/local/bin")])

    def test_manual_dir_is_root(self):
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC
        self.assertEqual(HYSTERIA2_SPEC.manual_incoming_dir, Path("/root"))

    def test_manual_dir_not_in_install_dests(self):
        """КРИТИЧЕСКИЙ ИНВАРИАНТ (баг 21d7baf)."""
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC
        for dest in HYSTERIA2_SPEC.install_dests:
            self.assertNotEqual(HYSTERIA2_SPEC.manual_incoming_dir, dest)

    def test_min_size_is_1mb(self):
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC
        self.assertEqual(HYSTERIA2_SPEC.min_size, 1_000_000)

    def test_post_install_is_set(self):
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC
        self.assertIsNotNone(HYSTERIA2_SPEC.post_install)

    def test_mirror_urls_has_14_entries(self):
        """Сценарий 2: 14 зеркал для fallback."""
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC
        urls = HYSTERIA2_SPEC.mirror_urls_builder(
            filename="hysteria-linux-amd64", arch="amd64",
        )
        self.assertEqual(len(urls), 14)

    def test_post_install_rejects_non_elf(self):
        """post_install возвращает False на не-ELF файле."""
        import tempfile
        from vless_installer.modules.hysteria2_packages import HYSTERIA2_SPEC

        tmpdir = Path(tempfile.mkdtemp())
        try:
            src = tmpdir / "not-elf"
            src.write_bytes(b"<html>404</html>" * 100)
            ok = HYSTERIA2_SPEC.post_install(src, [tmpdir / "install"])
            self.assertFalse(ok)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
