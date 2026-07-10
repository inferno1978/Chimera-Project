#!/usr/bin/env python3
"""
tests/test_awg_cascade.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/awg_cascade.py.

Покрывает:
  1. _awgs_cascade_build_awg1_conf — генерация awg1.conf
  2. _awgs_cascade_create_routing_script — генерация bash-скрипта
  3. _awgs_cascade_create_systemd_unit — генерация systemd-unit
  4. _awgs_cascade_setup_cron — генерация cron-файла
"""
from __future__ import annotations

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


class TestAwgsCascadeBuildAwg1Conf(unittest.TestCase):
    """_awgs_cascade_build_awg1_conf — генерация awg1.conf."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.awg_state.AWGS_STATE_FILE",
                     self._state)

    def test_generates_interface_and_peer_sections(self):
        from vless_installer.modules import awg_cascade
        # state с дефолтными params
        self._state.write_text(json.dumps({
            "installed": True,
            "params": {"jc": 4, "jmin": 40, "jmax": 70,
                        "s1": 0, "s2": 0, "s3": 0, "s4": 0,
                        "h1": 1, "h2": 2, "h3": 3, "h4": 4,
                        "i1": "", "i2": "", "i3": "", "i4": "", "i5": ""},
        }))
        with self._patch():
            conf = awg_cascade._awgs_cascade_build_awg1_conf(
                exit_host="1.2.3.4", exit_port=51820,
                exit_pubkey="EXIT_PUBKEY", client_privkey="CLIENT_PRIV",
                psk="PSK_KEY", exit_subnet="172.16.61.0/24",
            )
        self.assertIn("[Interface]", conf)
        self.assertIn("[Peer]", conf)
        self.assertIn("CLIENT_PRIV", conf)
        self.assertIn("EXIT_PUBKEY", conf)
        self.assertIn("PSK_KEY", conf)
        self.assertIn("Jc = 4", conf)

    def test_client_ip_from_exit_subnet(self):
        """client_ip = base.2/32 где base = exit_subnet без последнего октета."""
        from vless_installer.modules import awg_cascade
        self._state.write_text(json.dumps({
            "installed": True, "params": {},
        }))
        with self._patch():
            conf = awg_cascade._awgs_cascade_build_awg1_conf(
                exit_host="1.2.3.4", exit_port=51820,
                exit_pubkey="PUB", client_privkey="PRIV",
                psk="", exit_subnet="172.16.61.0/24",
            )
        # base = 172.16.61 → client_ip = 172.16.61.2/32
        self.assertIn("172.16.61.2/32", conf)

    def test_omits_preshared_key_when_empty(self):
        from vless_installer.modules import awg_cascade
        self._state.write_text(json.dumps({
            "installed": True, "params": {},
        }))
        with self._patch():
            conf = awg_cascade._awgs_cascade_build_awg1_conf(
                exit_host="1.2.3.4", exit_port=51820,
                exit_pubkey="PUB", client_privkey="PRIV",
                psk="", exit_subnet="172.16.61.0/24",
            )
        # PSK пустой → PresharedKey не добавляется
        self.assertNotIn("PresharedKey", conf)


class TestAwgsCascadeCreateRoutingScript(unittest.TestCase):
    """_awgs_cascade_create_routing_script — генерация bash-скрипта."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._script = self._tmpdir / "awg-routing.sh"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        # Патчим и AWGS_CASCADE_DIR (для mkdir) и AWGS_ROUTING_SCRIPT (для write)
        return (
            patch("vless_installer.modules.awg_cascade.AWGS_CASCADE_DIR", self._tmpdir),
            patch("vless_installer.modules.awg_cascade.AWGS_ROUTING_SCRIPT", self._script),
        )

    def test_writes_script_with_ipset_references(self):
        """Скрипт содержит ссылки на ipset и exit_gw (base.1 из exit_subnet).
        Ранее f-string конфликтовал с bash ${line:0:1} → NameError при вызове
        (фикс: экранирование через ${{line:0:1}})."""
        from vless_installer.modules.awg_cascade import (
            _awgs_cascade_create_routing_script, AWGS_IPSET_NAME,
        )
        with self._patch()[0], self._patch()[1]:
            _awgs_cascade_create_routing_script("172.16.61.0/24")
        content = self._script.read_text()
        self.assertIn(AWGS_IPSET_NAME, content)
        # exit_gw = base.1 где base = exit_subnet без последнего октета и /CIDR
        # 172.16.61.0/24 → base=172.16.61 → exit_gw=172.16.61.1
        self.assertIn("172.16.61.1", content)
        # bash-конструкция ${line:0:1} должна остаться в скрипте как есть
        self.assertIn("${line:0:1}", content)

    def test_script_is_executable(self):
        """Скрипт создаётся с executable bit (0o755)."""
        import stat
        from vless_installer.modules.awg_cascade import (
            _awgs_cascade_create_routing_script,
        )
        with self._patch()[0], self._patch()[1]:
            _awgs_cascade_create_routing_script("172.16.61.0/24")
        mode = stat.S_IMODE(os.stat(self._script).st_mode)
        self.assertTrue(mode & 0o100)  # executable bit


class TestAwgsCascadeCreateSystemdUnit(unittest.TestCase):
    """_awgs_cascade_create_systemd_unit — генерация systemd-unit."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._unit = self._tmpdir / "awg-cascade-routing.service"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.awg_cascade.AWGS_SYSTEMD_CASCADE",
                     self._unit)

    def test_writes_unit_with_exec_start(self):
        from vless_installer.modules.awg_cascade import (
            _awgs_cascade_create_systemd_unit, AWGS_ROUTING_SCRIPT,
        )
        with self._patch():
            _awgs_cascade_create_systemd_unit()
        content = self._unit.read_text()
        self.assertIn("[Unit]", content)
        self.assertIn("[Service]", content)
        self.assertIn("ExecStart=", content)
        self.assertIn(str(AWGS_ROUTING_SCRIPT), content)


class TestAwgsCascadeSetupCron(unittest.TestCase):
    """_awgs_cascade_setup_cron — генерация cron-файла."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cron = self._tmpdir / "awg-cascade-ru-update"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.awg_cascade.AWGS_CRON_RU_UPDATE",
                     self._cron)

    def test_writes_cron_file(self):
        from vless_installer.modules.awg_cascade import _awgs_cascade_setup_cron
        with self._patch():
            _awgs_cascade_setup_cron()
        self.assertTrue(self._cron.exists())
        content = self._cron.read_text()
        self.assertIn("awgs_cascade_update_ru_zone", content)

    def test_cron_chmod_644(self):
        import stat
        from vless_installer.modules.awg_cascade import _awgs_cascade_setup_cron
        with self._patch():
            _awgs_cascade_setup_cron()
        mode = stat.S_IMODE(os.stat(self._cron).st_mode)
        self.assertEqual(mode, 0o644)


if __name__ == "__main__":
    unittest.main(verbosity=2)
