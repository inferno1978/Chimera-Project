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
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text(); g = {}
    with patch.object(Path, 'mkdir', lambda s,*a,**k: None), \
         patch.object(Path, 'touch', lambda s,*a,**k: None), \
         patch.object(Path, 'chmod', lambda s,*a,**k: None), \
         patch('os.chown', lambda *a,**k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types; m = types.ModuleType("chimera._core"); m.__dict__.update(g)
    sys.modules["chimera._core"] = m

class TestQuickStatusSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from chimera.modules.quick_status import _core_module
        self.assertIsNotNone(_core_module())

class TestSwitchModeSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from chimera.modules.switch_mode import _core_module
        self.assertIsNotNone(_core_module())

class TestUninstallSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from chimera.modules.uninstall import _core_module
        self.assertIsNotNone(_core_module())

class TestReconfigureSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from chimera.modules.reconfigure import _core_module
        self.assertIsNotNone(_core_module())

class TestFail2banSetupSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from chimera.modules.fail2ban_setup import _core_module
        self.assertIsNotNone(_core_module())

class TestSshHardeningSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from chimera.modules.ssh_hardening import _core_module
        self.assertIsNotNone(_core_module())

class TestNetworkSetupSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from chimera.modules.network_setup import _core_module
        self.assertIsNotNone(_core_module())

class TestNginxSetupSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from chimera.modules.nginx_setup import _core_module
        self.assertIsNotNone(_core_module())

class TestEmergencyRepairSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from chimera.modules.emergency_repair import _core_module
        self.assertIsNotNone(_core_module())

class TestSplitTunnelSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from chimera.modules.split_tunnel import _core_module
        self.assertIsNotNone(_core_module())

class TestStandaloneScreensSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_module_imports(self):
        import chimera.modules.standalone_screens
        self.assertIsNotNone(chimera.modules.standalone_screens)

class TestHysteria2MenuSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_module_imports(self):
        import chimera.modules.hysteria2_menu
        self.assertIsNotNone(chimera.modules.hysteria2_menu)

class TestVkturnMenuSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_module_imports(self):
        import chimera.modules.vkturn_menu
        self.assertIsNotNone(chimera.modules.vkturn_menu)

class TestInstallPromptsSmoke(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_module_imports(self):
        import chimera.modules.install_prompts
        self.assertIsNotNone(chimera.modules.install_prompts)

if __name__ == "__main__":
    unittest.main(verbosity=2)
