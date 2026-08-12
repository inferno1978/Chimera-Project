#!/usr/bin/env python3
"""
tests/test_port_hopping.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/port_hopping.py.

Покрывает:
  1. _load_ph / _save_ph — JSON I/O port_hopping.json
  2. _load_state — чтение state.json
  3. _real_port — реальный порт из state
  4. _log — запись в лог-файл
"""
from __future__ import annotations

import json
import os
import re
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


class TestLoadSavePh(unittest.TestCase):
    """_load_ph / _save_ph — JSON I/O port_hopping.json."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._ph = self._tmpdir / "port_hopping.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.port_hopping._PH_FILE", self._ph)

    def test_load_returns_default_when_no_file(self):
        from chimera.modules.port_hopping import _load_ph
        with self._patch():
            result = _load_ph()
        self.assertFalse(result["enabled"])

    def test_load_returns_default_on_corrupt(self):
        from chimera.modules.port_hopping import _load_ph
        self._ph.write_text("{invalid")
        with self._patch():
            result = _load_ph()
        self.assertFalse(result["enabled"])

    def test_save_then_load(self):
        from chimera.modules.port_hopping import _load_ph, _save_ph
        with self._patch():
            _save_ph({"enabled": True, "port_start": 10000, "port_end": 10050})
            loaded = _load_ph()
        self.assertTrue(loaded["enabled"])
        self.assertEqual(loaded["port_start"], 10000)

    def test_save_sets_chmod_600(self):
        import stat
        from chimera.modules.port_hopping import _save_ph
        with self._patch():
            _save_ph({"enabled": False})
        mode = stat.S_IMODE(os.stat(self._ph).st_mode)
        self.assertEqual(mode, 0o600)


class TestLoadState(unittest.TestCase):
    """_load_state — чтение state.json."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.port_hopping._STATE_FILE", self._state)

    def test_returns_empty_when_no_file(self):
        from chimera.modules.port_hopping import _load_state
        with self._patch():
            self.assertEqual(_load_state(), {})

    def test_returns_empty_on_corrupt(self):
        from chimera.modules.port_hopping import _load_state
        self._state.write_text("{invalid")
        with self._patch():
            self.assertEqual(_load_state(), {})

    def test_returns_state(self):
        from chimera.modules.port_hopping import _load_state
        self._state.write_text(json.dumps({"server_port": 8443}))
        with self._patch():
            st = _load_state()
        self.assertEqual(st["server_port"], 8443)


class TestRealPort(unittest.TestCase):
    """_real_port — реальный порт из state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.port_hopping._STATE_FILE", self._state)

    def test_returns_port_from_state(self):
        from chimera.modules.port_hopping import _real_port
        self._state.write_text(json.dumps({"server_port": 8443}))
        with self._patch():
            self.assertEqual(_real_port(), 8443)

    def test_returns_443_when_no_state(self):
        from chimera.modules.port_hopping import _real_port
        with self._patch():
            self.assertEqual(_real_port(), 443)

    def test_returns_443_when_no_server_port(self):
        from chimera.modules.port_hopping import _real_port
        self._state.write_text(json.dumps({"other": "x"}))
        with self._patch():
            self.assertEqual(_real_port(), 443)


class TestLog(unittest.TestCase):
    """_log — запись в лог-файл."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._log = self._tmpdir / "vless-install.log"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.port_hopping._LOG_FILE", self._log)

    def test_writes_timestamped_line(self):
        from chimera.modules.port_hopping import _log
        with self._patch():
            _log("INFO", "test message")
        content = self._log.read_text()
        self.assertIn("INFO", content)
        self.assertIn("test message", content)

    def test_strips_ansi_codes(self):
        """ANSI-коды удаляются из лог-файла."""
        from chimera.modules.port_hopping import _log
        with self._patch():
            _log("INFO", "\033[1;31mred text\033[0m")
        content = self._log.read_text()
        self.assertNotIn("\033[", content)
        self.assertIn("red text", content)


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТЫ МИГРАЦИИ НА NFTABLES (этап 1.4) — мок nft_common
# ══════════════════════════════════════════════════════════════════════════════
class TestNftMigration(unittest.TestCase):
    """Проверяет что port_hopping.py использует nft_common вместо прямых
    iptables subprocess-вызовов (этап 1.4 миграции).

    Мокает nft_nat_redirect / nft_rule_exists / nft_rule_delete_by_comment /
    _nft_available — проверяет что:
      • _add_rules делегирует в nft_nat_redirect с правильными аргументами
        (диапазон через дефис '10000-20000', не двоеточие '10000:20000').
      • _rules_exists использует nft_rule_exists по comment-tag.
      • _remove_rules вызывает nft_rule_delete_by_comment.
      • _iptables_available() делегирует в _nft_available().
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_iptables_available_delegates_to_nft(self):
        """_iptables_available() теперь алиас для _nft_available()."""
        from chimera.modules import port_hopping
        with patch("chimera.modules.port_hopping._nft_available",
                   return_value=True):
            self.assertTrue(port_hopping._iptables_available())
        with patch("chimera.modules.port_hopping._nft_available",
                   return_value=False):
            self.assertFalse(port_hopping._iptables_available())

    def test_add_rules_calls_nft_nat_redirect_with_dash_range(self):
        """_add_rules передаёт диапазон портов через дефис, не двоеточие."""
        from chimera.modules import port_hopping
        with patch("chimera.modules.port_hopping.nft_nat_redirect",
                   return_value=True) as mock_redirect:
            ok = port_hopping._add_rules(10000, 20000, 443, "tcp")
        self.assertTrue(ok)
        mock_redirect.assert_called_once()
        _, kwargs = mock_redirect.call_args
        self.assertEqual(kwargs.get("dport"), "10000-20000")  # дефис, не двоеточие
        self.assertEqual(kwargs.get("to_port"), 443)
        self.assertEqual(kwargs.get("proto"), "tcp")
        self.assertEqual(kwargs.get("comment"), "xray-port-hopping")
        self.assertTrue(kwargs.get("prerouting"))

    def test_add_rules_both_proto_calls_redirect_twice(self):
        """Для proto='both' — два вызова nft_nat_redirect (tcp + udp)."""
        from chimera.modules import port_hopping
        with patch("chimera.modules.port_hopping.nft_nat_redirect",
                   return_value=True) as mock_redirect:
            ok = port_hopping._add_rules(10000, 20000, 443, "both")
        self.assertTrue(ok)
        self.assertEqual(mock_redirect.call_count, 2)
        protos_called = sorted(
            kwargs.get("proto") for _, kwargs in mock_redirect.call_args_list
        )
        self.assertEqual(protos_called, ["tcp", "udp"])

    def test_add_rules_returns_false_on_failure(self):
        """Если nft_nat_redirect возвращает False — _add_rules тоже False."""
        from chimera.modules import port_hopping
        with patch("chimera.modules.port_hopping.nft_nat_redirect",
                   return_value=False):
            ok = port_hopping._add_rules(10000, 20000, 443, "tcp")
        self.assertFalse(ok)

    def test_rules_exist_calls_nft_rule_exists(self):
        """_rules_exist делегирует в nft_rule_exists по comment-tag."""
        from chimera.modules import port_hopping
        with patch("chimera.modules.port_hopping.nft_rule_exists",
                   return_value=True) as mock_exists:
            result = port_hopping._rules_exist()
        self.assertTrue(result)
        mock_exists.assert_called_once()
        _, kwargs = mock_exists.call_args
        self.assertEqual(kwargs.get("comment"), "xray-port-hopping")
        self.assertEqual(kwargs.get("chain"), "prerouting")
        self.assertEqual(kwargs.get("table"), "chimera")

    def test_remove_rules_calls_nft_delete_by_comment(self):
        """_remove_rules делегирует в nft_rule_delete_by_comment."""
        from chimera.modules import port_hopping
        with patch("chimera.modules.port_hopping.nft_rule_delete_by_comment",
                   return_value=2) as mock_del:
            port_hopping._remove_rules()
        mock_del.assert_called_once()
        _, kwargs = mock_del.call_args
        self.assertEqual(kwargs.get("comment"), "xray-port-hopping")
        self.assertEqual(kwargs.get("chain"), "prerouting")
        self.assertEqual(kwargs.get("table"), "chimera")

    def test_persist_iptables_uses_nft_persist(self):
        """_persist_iptables вызывает nft_persist (а не iptables-save)."""
        from chimera.modules import port_hopping
        with patch("chimera.modules.port_hopping._nft_available",
                   return_value=True), \
             patch("chimera.modules.port_hopping.nft_persist",
                   return_value=True) as mock_persist, \
             patch("chimera.modules.nft_common.nft_persist_enable_systemd",
                   return_value=True):
            port_hopping._persist_iptables()
        mock_persist.assert_called_once()

    def test_persist_iptables_skipped_when_nft_unavailable(self):
        """Если nft недоступен — _persist_iptensors не падает, ничего не делает."""
        from chimera.modules import port_hopping
        with patch("chimera.modules.port_hopping._nft_available",
                   return_value=False), \
             patch("chimera.modules.port_hopping.nft_persist") as mock_persist:
            port_hopping._persist_iptables()
        mock_persist.assert_not_called()

    def test_ph_status_returns_rules_active_from_nft(self):
        """ph_status() возвращает rules_active на основе nft_rule_exists."""
        from chimera.modules import port_hopping
        import tempfile
        tmpdir = Path(tempfile.mkdtemp())
        ph_file = tmpdir / "ph.json"
        ph_file.write_text(json.dumps({
            "enabled": True, "real_port": 443,
            "range_start": 10000, "range_end": 20000, "proto": "tcp",
        }))
        try:
            with patch("chimera.modules.port_hopping._PH_FILE", ph_file), \
                 patch("chimera.modules.port_hopping.nft_rule_exists",
                       return_value=True):
                st = port_hopping.ph_status()
            self.assertTrue(st["enabled"])
            self.assertTrue(st["rules_active"])
            self.assertEqual(st["real_port"], 443)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
