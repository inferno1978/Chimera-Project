#!/usr/bin/env python3
"""
tests/test_wave6_smoke.py
───────────────────────────────────────────────────────────────────────────────
Smoke-тесты для оставшихся модулей Волны 6:
quick_status, switch_mode, uninstall, reconfigure, fail2ban_setup,
ssh_hardening, network_setup, nginx_setup, emergency_repair,
split_tunnel, standalone_screens, hysteria2_menu, vkturn_menu,
install_prompts.

Каждый модуль — _core_module() smoke или константа.
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

class TestQuickStatusSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from vless_installer.modules.quick_status import _core_module
        self.assertIsNotNone(_core_module())

class TestSwitchModeSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from vless_installer.modules.switch_mode import _core_module
        self.assertIsNotNone(_core_module())

class TestUninstallSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from vless_installer.modules.uninstall import _core_module
        self.assertIsNotNone(_core_module())

class TestReconfigureSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from vless_installer.modules.reconfigure import _core_module
        self.assertIsNotNone(_core_module())

class TestFail2banSetupSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from vless_installer.modules.fail2ban_setup import _core_module
        self.assertIsNotNone(_core_module())

class TestSshHardeningSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from vless_installer.modules.ssh_hardening import _core_module
        self.assertIsNotNone(_core_module())

class TestNetworkSetupSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from vless_installer.modules.network_setup import _core_module
        self.assertIsNotNone(_core_module())

class TestNginxSetupSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from vless_installer.modules.nginx_setup import _core_module
        self.assertIsNotNone(_core_module())

class TestEmergencyRepairSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from vless_installer.modules.emergency_repair import _core_module
        self.assertIsNotNone(_core_module())

class TestSplitTunnelSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from vless_installer.modules.split_tunnel import _core_module
        self.assertIsNotNone(_core_module())

class TestStandaloneScreensSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_module_imports(self):
        import vless_installer.modules.standalone_screens
        self.assertIsNotNone(vless_installer.modules.standalone_screens)

class TestHysteria2MenuSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_module_imports(self):
        import vless_installer.modules.hysteria2_menu
        self.assertIsNotNone(vless_installer.modules.hysteria2_menu)

class TestVkturnMenuSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_module_imports(self):
        import vless_installer.modules.vkturn_menu
        self.assertIsNotNone(vless_installer.modules.vkturn_menu)

class TestInstallPromptsSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_module_imports(self):
        import vless_installer.modules.install_prompts
        self.assertIsNotNone(vless_installer.modules.install_prompts)

if __name__ == "__main__":
    unittest.main(verbosity=2)
