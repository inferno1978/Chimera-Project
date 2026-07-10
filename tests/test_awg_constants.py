#!/usr/bin/env python3
"""
tests/test_awg_constants.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/awg_constants.py.

Модуль содержит только константы — проверяем целостность значений,
типы Path/str/int, непротиворечивость диапазонов валидации.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    from unittest.mock import patch
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


class TestAwgConstantsNames(unittest.TestCase):
    """Имена интерфейса/порта/подсетей."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_interface_name_is_awg0(self):
        from vless_installer.modules.awg_constants import AWGS_INTERFACE
        self.assertEqual(AWGS_INTERFACE, "awg0")

    def test_default_port_in_valid_range(self):
        from vless_installer.modules.awg_constants import (
            AWGS_DEFAULT_PORT, AWGS_PORT_MIN, AWGS_PORT_MAX,
        )
        self.assertGreaterEqual(AWGS_DEFAULT_PORT, AWGS_PORT_MIN)
        self.assertLessEqual(AWGS_DEFAULT_PORT, AWGS_PORT_MAX)

    def test_default_subnet_is_v4_cidr(self):
        from vless_installer.modules.awg_constants import AWGS_DEFAULT_SUBNET
        self.assertIn("/", AWGS_DEFAULT_SUBNET)
        self.assertTrue(AWGS_DEFAULT_SUBNET.endswith("/24"))

    def test_default_subnet_v6_is_ula(self):
        from vless_installer.modules.awg_constants import AWGS_DEFAULT_SUBNET_V6
        self.assertTrue(AWGS_DEFAULT_SUBNET_V6.startswith("fd"))
        self.assertIn("::", AWGS_DEFAULT_SUBNET_V6)

    def test_mtu_is_safe_for_mobile(self):
        """MTU 1280 — минимальный безопасный для IPv6."""
        from vless_installer.modules.awg_constants import AWGS_DEFAULT_MTU
        self.assertLessEqual(AWGS_DEFAULT_MTU, 1280)


class TestAwgConstantsPaths(unittest.TestCase):
    """Пути Path-объектов."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_server_conf_under_amnezia_dir(self):
        from vless_installer.modules.awg_constants import (
            AWGS_CONF_DIR, AWGS_SERVER_CONF,
        )
        self.assertEqual(AWGS_SERVER_CONF.parent, AWGS_CONF_DIR)
        self.assertEqual(AWGS_SERVER_CONF.name, "awg0.conf")

    def test_keys_dir_under_awg_dir(self):
        from vless_installer.modules.awg_constants import (
            AWGS_AWG_DIR, AWGS_KEYS_DIR,
        )
        self.assertEqual(AWGS_KEYS_DIR.parent, AWGS_AWG_DIR)

    def test_state_file_under_xray_installer(self):
        from vless_installer.modules.awg_constants import AWGS_STATE_FILE
        self.assertIn("xray-installer", str(AWGS_STATE_FILE))
        self.assertEqual(AWGS_STATE_FILE.name, "awg_standalone_state.json")

    def test_all_path_constants_are_path_instances(self):
        """Все AWGS_*_FILE / AWGS_*_DIR должны быть Path."""
        from vless_installer.modules import awg_constants
        for name in dir(awg_constants):
            if name.startswith("AWGS_") and any(
                suf in name for suf in ("_FILE", "_DIR", "_CONF", "_SERVICE")
            ):
                v = getattr(awg_constants, name)
                self.assertIsInstance(v, Path, f"{name} должен быть Path")


class TestAwgConstantsParams(unittest.TestCase):
    """AWGS_DEFAULT_PARAMS — структура дефолтных параметров обфускации."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_all_jc_jmin_jmax(self):
        from vless_installer.modules.awg_constants import AWGS_DEFAULT_PARAMS
        for k in ("jc", "jmin", "jmax"):
            self.assertIn(k, AWGS_DEFAULT_PARAMS)
            self.assertIsInstance(AWGS_DEFAULT_PARAMS[k], int)

    def test_has_s1_s4(self):
        from vless_installer.modules.awg_constants import AWGS_DEFAULT_PARAMS
        for k in ("s1", "s2", "s3", "s4"):
            self.assertIn(k, AWGS_DEFAULT_PARAMS)

    def test_has_h1_h4(self):
        from vless_installer.modules.awg_constants import AWGS_DEFAULT_PARAMS
        for k in ("h1", "h2", "h3", "h4"):
            self.assertIn(k, AWGS_DEFAULT_PARAMS)

    def test_i_keys_are_optional_empty_strings(self):
        from vless_installer.modules.awg_constants import AWGS_DEFAULT_PARAMS
        for k in ("i1", "i2", "i3", "i4", "i5"):
            self.assertIn(k, AWGS_DEFAULT_PARAMS)
            self.assertEqual(AWGS_DEFAULT_PARAMS[k], "")

    def test_default_jc_in_valid_range(self):
        from vless_installer.modules.awg_constants import (
            AWGS_DEFAULT_PARAMS, AWGS_JC_MIN, AWGS_JC_MAX,
        )
        self.assertGreaterEqual(AWGS_DEFAULT_PARAMS["jc"], AWGS_JC_MIN)
        self.assertLessEqual(AWGS_DEFAULT_PARAMS["jc"], AWGS_JC_MAX)

    def test_default_jmin_le_jmax(self):
        from vless_installer.modules.awg_constants import AWGS_DEFAULT_PARAMS
        self.assertLessEqual(AWGS_DEFAULT_PARAMS["jmin"],
                             AWGS_DEFAULT_PARAMS["jmax"])


class TestAwgConstantsRanges(unittest.TestCase):
    """Валидационные диапазоны — внутренняя непротиворечивость."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_jc_min_lt_max(self):
        from vless_installer.modules.awg_constants import (
            AWGS_JC_MIN, AWGS_JC_MAX,
        )
        self.assertLess(AWGS_JC_MIN, AWGS_JC_MAX)

    def test_port_min_lt_max(self):
        from vless_installer.modules.awg_constants import (
            AWGS_PORT_MIN, AWGS_PORT_MAX,
        )
        self.assertLess(AWGS_PORT_MIN, AWGS_PORT_MAX)
        self.assertEqual(AWGS_PORT_MIN, 1)
        self.assertEqual(AWGS_PORT_MAX, 65535)

    def test_peer_ip_range_in_subnet(self):
        """Диапазон .2..254 укладывается в /24."""
        from vless_installer.modules.awg_constants import (
            AWGS_PEER_IP_START, AWGS_PEER_IP_END,
        )
        self.assertGreaterEqual(AWGS_PEER_IP_START, 2)
        self.assertLessEqual(AWGS_PEER_IP_END, 254)
        self.assertLess(AWGS_PEER_IP_START, AWGS_PEER_IP_END)


class TestAwgConstantsApplyMode(unittest.TestCase):
    """AWGS_APPLY_MODE_* — режимы применения."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_two_distinct_modes(self):
        from vless_installer.modules.awg_constants import (
            AWGS_APPLY_MODE_SYNCCONF, AWGS_APPLY_MODE_RESTART,
        )
        self.assertEqual(AWGS_APPLY_MODE_SYNCCONF, "syncconf")
        self.assertEqual(AWGS_APPLY_MODE_RESTART, "restart")
        self.assertNotEqual(AWGS_APPLY_MODE_SYNCCONF, AWGS_APPLY_MODE_RESTART)


class TestAwgConstantsSysctl(unittest.TestCase):
    """AWGS_SYSCTL_TARGETS — цели sysctl."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ip_forward_target_is_1(self):
        from vless_installer.modules.awg_constants import AWGS_SYSCTL_TARGETS
        self.assertEqual(AWGS_SYSCTL_TARGETS["net.ipv4.ip_forward"], 1)

    def test_qdisc_is_fq(self):
        from vless_installer.modules.awg_constants import AWGS_SYSCTL_TARGETS
        self.assertEqual(AWGS_SYSCTL_TARGETS["net.core.default_qdisc"], "fq")

    def test_congestion_is_bbr(self):
        from vless_installer.modules.awg_constants import AWGS_SYSCTL_TARGETS
        self.assertEqual(
            AWGS_SYSCTL_TARGETS["net.ipv4.tcp_congestion_control"], "bbr"
        )


class TestAwgConstantsCascadeFwmark(unittest.TestCase):
    """Fwmark каскада не должен конфликтовать с chain Mode B (1000)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_fwmark_not_1000(self):
        from vless_installer.modules.awg_constants import AWGS_CASCADE_FWMARK
        self.assertNotEqual(AWGS_CASCADE_FWMARK, 1000)

    def test_fwmark_is_8192(self):
        from vless_installer.modules.awg_constants import AWGS_CASCADE_FWMARK
        self.assertEqual(AWGS_CASCADE_FWMARK, 0x2000)
        self.assertEqual(AWGS_CASCADE_FWMARK, 8192)


if __name__ == "__main__":
    unittest.main(verbosity=2)
