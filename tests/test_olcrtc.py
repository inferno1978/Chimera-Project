#!/usr/bin/env python3
"""
tests/test_olcrtc.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/olcrtc.py — переработанная версия с manager panel.

Покрывает:
  1. _generate_config_json — генерация JSON конфига (формат из гайда)
  2. _generate_panel_env — basic auth env
  3. _generate_systemd_unit — systemd unit
  4. _generate_olcbox_uri — OlcBox URI формат
  5. _load_state / _save_state — JSON I/O
  6. _go_arch — архитектура
  7. _ver_tuple — парсинг версии
  8. _go_required_version — требует Go 1.26+
  9. Интеграция с port_registry — SERVICE_OLCRTC_MANAGER существует
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

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


class TestGenerateConfigJson(unittest.TestCase):
    """_generate_config_json — генерация JSON конфига (формат из гайда)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_config_has_required_fields(self):
        """JSON должен содержать все поля из гайда."""
        from chimera.modules.olcrtc import _generate_config_json
        config_text = _generate_config_json(
            carrier="wbstream",
            room_id="test-room-123",
            key="abc123",
            transport="vp8channel",
        )
        config = json.loads(config_text)

        self.assertEqual(config["version"], 1)
        self.assertEqual(config["port"], 8888)
        self.assertIn("refresh", config)
        self.assertIn("clients", config)
        self.assertEqual(len(config["clients"]), 1)

        client = config["clients"][0]
        self.assertEqual(client["client-id"], "wb")
        self.assertIn("locations", client)
        self.assertEqual(len(client["locations"]), 1)

        loc = client["locations"][0]
        self.assertEqual(loc["carrier"], "wbstream")
        self.assertEqual(loc["link"], "direct")
        self.assertEqual(loc["data"], "/var/lib/olcrtc/data")
        self.assertEqual(loc["dns"], "8.8.8.8:53")

        endpoint = loc["endpoint"]
        self.assertEqual(endpoint["room_id"], "test-room-123")
        self.assertEqual(endpoint["key"], "abc123")

        transport = loc["transport"]
        self.assertEqual(transport["type"], "vp8channel")
        self.assertIn("payload", transport)
        self.assertEqual(transport["payload"]["vp8-fps"], "30")
        self.assertEqual(transport["payload"]["vp8-batch"], "64")

    def test_config_different_carrier(self):
        from chimera.modules.olcrtc import _generate_config_json
        config = json.loads(_generate_config_json(
            carrier="jitsi", room_id="room", key="key",
            transport="datachannel",
        ))
        self.assertEqual(config["clients"][0]["locations"][0]["carrier"], "jitsi")
        self.assertEqual(config["clients"][0]["locations"][0]["transport"]["type"], "datachannel")


class TestGeneratePanelEnv(unittest.TestCase):
    """_generate_panel_env — basic auth env."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_env_has_credentials(self):
        from chimera.modules.olcrtc import _generate_panel_env
        env = _generate_panel_env("admin", "secret123")
        self.assertIn("OLCRTC_MANAGER_USER='admin'", env)
        self.assertIn("OLCRTC_MANAGER_PASS='secret123'", env)
        self.assertIn("OLCRTC_MANAGER_ADMIN_PATH='/admin'", env)
        self.assertIn("OLCRTC_MANAGER_TLS_CERT=", env)
        self.assertIn("OLCRTC_MANAGER_TLS_KEY=", env)


class TestGenerateSystemdUnit(unittest.TestCase):
    """_generate_systemd_unit — systemd unit."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_unit_has_required_directives(self):
        from chimera.modules.olcrtc import _generate_systemd_unit
        unit = _generate_systemd_unit()
        self.assertIn("[Unit]", unit)
        self.assertIn("[Service]", unit)
        self.assertIn("[Install]", unit)
        self.assertIn("ExecStart=/usr/local/bin/olcrtc-manager", unit)
        self.assertIn("-addr 0.0.0.0", unit)
        self.assertIn("-config /etc/olcrtc-manager/config.json", unit)
        self.assertIn("Environment=OLCRTC_PATH=/usr/local/bin/olcrtc", unit)
        self.assertIn("EnvironmentFile=-/etc/olcrtc-manager/panel.env", unit)
        self.assertIn("Restart=on-failure", unit)


class TestGenerateOlcBoxUri(unittest.TestCase):
    """_generate_olcbox_uri — OlcBox URI формат."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_uri_format_vp8channel(self):
        """URI для vp8channel точно как в гайде."""
        from chimera.modules.olcrtc import _generate_olcbox_uri
        uri = _generate_olcbox_uri(
            carrier="wbstream",
            transport="vp8channel",
            room_id="ROOM_ID",
            key="KEY",
            location_name="wb-vps",
        )
        # Формат: olcrtc://wbstream?vp8channel<vp8-batch=64&vp8-fps=30>@ROOM_ID#KEY$wb-vps
        self.assertTrue(uri.startswith("olcrtc://wbstream?vp8channel"))
        self.assertIn("vp8-batch=64", uri)
        self.assertIn("vp8-fps=30", uri)
        self.assertIn("@ROOM_ID", uri)
        self.assertIn("#KEY", uri)
        self.assertIn("$wb-vps", uri)

    def test_uri_format_datachannel(self):
        """URI для datachannel — без payload."""
        from chimera.modules.olcrtc import _generate_olcbox_uri
        uri = _generate_olcbox_uri(
            carrier="jitsi",
            transport="datachannel",
            room_id="ROOM",
            key="KEY",
            location_name="loc",
        )
        self.assertTrue(uri.startswith("olcrtc://jitsi?datachannel"))
        self.assertNotIn("<", uri)  # datachannel не имеет payload
        self.assertIn("@ROOM#KEY$loc", uri)


class TestStateIO(unittest.TestCase):
    """_load_state / _save_state — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "olcrtc.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_load_default_state(self):
        from chimera.modules import olcrtc
        with patch.object(olcrtc, "OLC_STATE_FILE", self._state_file):
            st = olcrtc._load_state()
        self.assertFalse(st["installed"])
        self.assertFalse(st["manager_installed"])
        self.assertEqual(st["config"], {})

    def test_save_then_load(self):
        from chimera.modules import olcrtc
        with patch.object(olcrtc, "OLC_STATE_FILE", self._state_file):
            olcrtc._save_state({"installed": True, "manager_installed": True,
                                "config": {"carrier": "wbstream"}})
            st = olcrtc._load_state()
        self.assertTrue(st["installed"])
        self.assertTrue(st["manager_installed"])
        self.assertEqual(st["config"]["carrier"], "wbstream")


class TestGoToolchain(unittest.TestCase):
    """Go toolchain helpers."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ver_tuple(self):
        from chimera.modules.olcrtc import _ver_tuple
        self.assertEqual(_ver_tuple("1.26.0"), (1, 26, 0))
        self.assertEqual(_ver_tuple("1.26"), (1, 26, 0))
        self.assertEqual(_ver_tuple("1.26.5"), (1, 26, 5))

    def test_go_required_version(self):
        """Требуется Go 1.26+ (из гайда)."""
        from chimera.modules.olcrtc import _go_required_version
        v = _go_required_version()
        self.assertEqual(v, "1.26.0")

    def test_go_arch(self):
        from chimera.modules.olcrtc import _go_arch
        arch = _go_arch()
        self.assertIn(arch, ("amd64", "arm64"))


class TestPortRegistryIntegration(unittest.TestCase):
    """Интеграция с port_registry."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_service_tag_exists(self):
        """SERVICE_OLCRTC_MANAGER определён в port_registry."""
        from chimera.modules.port_registry import SERVICE_OLCRTC_MANAGER
        self.assertEqual(SERVICE_OLCRTC_MANAGER, "olcrtc_manager")

    def test_manager_port_constant(self):
        """Порт manager панели — 8888 (из гайда)."""
        from chimera.modules.olcrtc import MGR_PORT
        self.assertEqual(MGR_PORT, 8888)


class TestManagerInstalledCheck(unittest.TestCase):
    """_manager_installed / _olcrtc_installed — проверки бинарников."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_not_installed_when_binary_missing(self):
        from chimera.modules import olcrtc
        with patch.object(olcrtc, "OLC_BIN", Path("/nonexistent/olcrtc")), \
             patch.object(olcrtc, "OLC_MGR_BIN", Path("/nonexistent/olcrtc-manager")):
            self.assertFalse(olcrtc._olcrtc_installed())
            self.assertFalse(olcrtc._manager_installed())


if __name__ == "__main__":
    unittest.main()
