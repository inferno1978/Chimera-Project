#!/usr/bin/env python3
"""
tests/test_geoblock.py
───────────────────────────────────────────────────────────────────────────────
Тесты для chimera/modules/geoblock.py — гео-блокировка по странам.

Покрывает:
  1. geoblock_add_country — вызов с моком _run() для iptables/ipset
  2. geoblock_remove_country — удаляет правила + ipset
  3. geoblock_list — возвращает список из state
  4. geoblock_add_country с невалидным кодом → False
  5. State сохраняется после add/remove
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import sys
import tempfile
import types
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
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core


class TestGeoblockAddCountry(unittest.TestCase):
    """geoblock_add_country — блокировка страны."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "geoblock_telemt.json"
        _setup_core_in_sysmodules()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_add_country_calls_ipset_and_iptables(self):
        """Кейс 1: add_country вызывает ipset create + iptables DROP."""
        from chimera.modules import geoblock
        core = sys.modules["chimera._core"]
        core.info = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        core.success = lambda *a, **kw: None

        _run_mock = MagicMock(return_value=MagicMock(returncode=0, stderr=""))

        with patch.object(geoblock, "_core_module", lambda: core), \
             patch.object(geoblock, "_STATE_FILE", self._state_file), \
             patch.object(geoblock, "_run", _run_mock), \
             patch.object(geoblock, "_fetch_country_cidrs",
                          return_value=(["1.2.3.0/24", "5.6.7.0/24"], [])), \
             patch("shutil.which", return_value="/usr/sbin/ipset"):
            ok = geoblock.geoblock_add_country(443, "ir")

        self.assertTrue(ok)
        # Проверяем что ipset create вызывался
        calls = [c.args[0] for c in _run_mock.call_args_list]
        ipset_creates = [c for c in calls if "ipset" in c and "create" in c]
        self.assertGreater(len(ipset_creates), 0, "Должен быть вызов ipset create")
        # Проверяем что iptables DROP вызывался
        ipt_drops = [c for c in calls if "iptables" in c and "DROP" in c]
        self.assertGreater(len(ipt_drops), 0, "Должен быть вызов iptables DROP")
        # State сохранён
        state = json.loads(self._state_file.read_text())
        self.assertIn("ir", state.get("443", []))

    def test_invalid_country_code_returns_false(self):
        """Кейс 4: невалидный код страны → False."""
        from chimera.modules import geoblock
        core = sys.modules["chimera._core"]
        core.warn = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None

        with patch.object(geoblock, "_core_module", lambda: core), \
             patch.object(geoblock, "_STATE_FILE", self._state_file):
            ok = geoblock.geoblock_add_country(443, "invalid")
        self.assertFalse(ok)


class TestGeoblockRemoveCountry(unittest.TestCase):
    """geoblock_remove_country — разблокировка."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "geoblock_telemt.json"
        _setup_core_in_sysmodules()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_remove_country_calls_ipset_destroy(self):
        """Кейс 2: remove вызывает ipset destroy + iptables -D."""
        from chimera.modules import geoblock
        core = sys.modules["chimera._core"]
        core.info = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        core.success = lambda *a, **kw: None

        _run_mock = MagicMock(return_value=MagicMock(returncode=0, stderr=""))

        # Pre-populate state
        self._state_file.write_text(json.dumps({"443": ["ir", "cn"]}))

        with patch.object(geoblock, "_core_module", lambda: core), \
             patch.object(geoblock, "_STATE_FILE", self._state_file), \
             patch.object(geoblock, "_run", _run_mock):
            ok = geoblock.geoblock_remove_country(443, "ir")

        self.assertTrue(ok)
        calls = [c.args[0] for c in _run_mock.call_args_list]
        ipset_destroys = [c for c in calls if "ipset" in c and "destroy" in c]
        self.assertGreater(len(ipset_destroys), 0, "Должен быть вызов ipset destroy")
        # State обновлён — "ir" удалён, "cn" остался
        state = json.loads(self._state_file.read_text())
        self.assertNotIn("ir", state.get("443", []))
        self.assertIn("cn", state.get("443", []))


class TestGeoblockList(unittest.TestCase):
    """geoblock_list — список заблокированных."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "geoblock_telemt.json"
        _setup_core_in_sysmodules()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_list_returns_countries_from_state(self):
        """Кейс 3: list возвращает страны из state."""
        from chimera.modules import geoblock
        self._state_file.write_text(json.dumps({"443": ["ir", "cn", "ru"]}))

        with patch.object(geoblock, "_STATE_FILE", self._state_file):
            result = geoblock.geoblock_list(443)

        self.assertEqual(result, ["ir", "cn", "ru"])

    def test_list_empty_state_returns_empty(self):
        """Пустой state → пустой список."""
        from chimera.modules import geoblock
        with patch.object(geoblock, "_STATE_FILE", self._state_file):
            result = geoblock.geoblock_list(443)
        self.assertEqual(result, [])

    def test_list_different_port_returns_empty(self):
        """Другой порт без блокировок → пустой список."""
        from chimera.modules import geoblock
        self._state_file.write_text(json.dumps({"443": ["ir"]}))
        with patch.object(geoblock, "_STATE_FILE", self._state_file):
            result = geoblock.geoblock_list(8443)
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
