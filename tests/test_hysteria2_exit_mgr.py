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

if __name__ == "__main__":
    unittest.main(verbosity=2)
