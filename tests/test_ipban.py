#!/usr/bin/env python3
"""
tests/test_ipban.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/ipban.py.

Покрывает:
  1. _parse_ip — парсинг IPv4/IPv6
  2. _parse_cidr — парсинг CIDR
  3. _parse_range — парсинг диапазона
  4. _asn_normalize — нормализация ASN
  5. _detect_input_kind — классификатор ввода
  6. _state_load / _state_save — JSON I/O
  7. _state_add_entry / _state_remove_entry — CRUD
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

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


class TestParseIp(unittest.TestCase):
    """_parse_ip — парсинг IP."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ipv4(self):
        from vless_installer.modules.ipban import _parse_ip
        self.assertEqual(_parse_ip("1.2.3.4"), ["1.2.3.4/32"])

    def test_ipv6(self):
        from vless_installer.modules.ipban import _parse_ip
        self.assertEqual(_parse_ip("::1"), ["::1/128"])
        self.assertEqual(_parse_ip("2001:db8::1"), ["2001:db8::1/128"])

    def test_invalid_raises(self):
        from vless_installer.modules.ipban import _parse_ip
        with self.assertRaises(ValueError):
            _parse_ip("invalid")


class TestParseCidr(unittest.TestCase):
    """_parse_cidr — парсинг CIDR."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_valid_cidr(self):
        from vless_installer.modules.ipban import _parse_cidr
        self.assertEqual(_parse_cidr("10.0.0.0/24"), ["10.0.0.0/24"])

    def test_normalizes_non_strict(self):
        """10.0.0.5/24 нормализуется в 10.0.0.0/24."""
        from vless_installer.modules.ipban import _parse_cidr
        self.assertEqual(_parse_cidr("10.0.0.5/24"), ["10.0.0.0/24"])

    def test_ipv6_cidr(self):
        from vless_installer.modules.ipban import _parse_cidr
        self.assertEqual(_parse_cidr("2001:db8::/32"), ["2001:db8::/32"])


class TestParseRange(unittest.TestCase):
    """_parse_range — парсинг диапазона."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_valid_range(self):
        from vless_installer.modules.ipban import _parse_range
        result = _parse_range("1.2.3.0-1.2.3.255")
        self.assertGreater(len(result), 0)
        # summarize_address_range даёт ["1.2.3.0/24"]
        self.assertIn("1.2.3.0/24", result)

    def test_reversed_range_swapped(self):
        """Если start > end — меняются местами."""
        from vless_installer.modules.ipban import _parse_range
        result = _parse_range("1.2.3.255-1.2.3.0")
        self.assertIn("1.2.3.0/24", result)

    def test_no_hyphen_raises(self):
        from vless_installer.modules.ipban import _parse_range
        with self.assertRaises(ValueError):
            _parse_range("1.2.3.4")


class TestAsnNormalize(unittest.TestCase):
    """_asn_normalize — нормализация ASN."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_adds_as_prefix(self):
        from vless_installer.modules.ipban import _asn_normalize
        self.assertEqual(_asn_normalize("12345"), "AS12345")

    def test_uppercase(self):
        from vless_installer.modules.ipban import _asn_normalize
        self.assertEqual(_asn_normalize("as12345"), "AS12345")

    def test_already_prefixed(self):
        from vless_installer.modules.ipban import _asn_normalize
        self.assertEqual(_asn_normalize("AS12345"), "AS12345")
        self.assertEqual(_asn_normalize("as12345"), "AS12345")


class TestDetectInputKind(unittest.TestCase):
    """_detect_input_kind — классификатор."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_asn_with_prefix(self):
        from vless_installer.modules.ipban import _detect_input_kind
        self.assertEqual(_detect_input_kind("AS12345"), "asn")

    def test_asn_numeric(self):
        from vless_installer.modules.ipban import _detect_input_kind
        self.assertEqual(_detect_input_kind("12345"), "asn")

    def test_cidr(self):
        from vless_installer.modules.ipban import _detect_input_kind
        self.assertEqual(_detect_input_kind("10.0.0.0/24"), "cidr")

    def test_range(self):
        from vless_installer.modules.ipban import _detect_input_kind
        self.assertEqual(_detect_input_kind("1.2.3.0-1.2.3.255"), "range")

    def test_ip(self):
        from vless_installer.modules.ipban import _detect_input_kind
        self.assertEqual(_detect_input_kind("1.2.3.4"), "ip")

    def test_ipv6_is_ip(self):
        """IPv6 без / → 'ip' (нет дефиса, нет /)."""
        from vless_installer.modules.ipban import _detect_input_kind
        self.assertEqual(_detect_input_kind("2001:db8::1"), "ip")


class TestStateLoadSave(unittest.TestCase):
    """_state_load / _state_save."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "ipban.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.ipban._STATE_FILE", self._state)

    def test_load_returns_default_when_no_file(self):
        from vless_installer.modules.ipban import _state_load
        with self._patch():
            result = _state_load()
        self.assertEqual(result, {"entries": []})

    def test_load_returns_default_on_corrupt(self):
        from vless_installer.modules.ipban import _state_load
        self._state.write_text("{invalid")
        with self._patch():
            result = _state_load()
        self.assertEqual(result, {"entries": []})

    def test_save_then_load(self):
        from vless_installer.modules.ipban import _state_load, _state_save
        with self._patch():
            _state_save({"entries": [{"display": "x"}]})
            loaded = _state_load()
        self.assertEqual(len(loaded["entries"]), 1)


class TestStateAddRemoveEntry(unittest.TestCase):
    """_state_add_entry / _state_remove_entry."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "ipban.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.ipban._STATE_FILE", self._state)

    def test_add_new_entry(self):
        from vless_installer.modules.ipban import (
            _state_add_entry, _state_load,
        )
        with self._patch():
            _state_add_entry("1.2.3.4/32", ["1.2.3.4/32"], "ip")
            state = _state_load()
        self.assertEqual(len(state["entries"]), 1)
        self.assertEqual(state["entries"][0]["display"], "1.2.3.4/32")
        self.assertEqual(state["entries"][0]["kind"], "ip")

    def test_add_replaces_duplicate_by_display(self):
        """Добавление с тем же display — заменяет старую."""
        from vless_installer.modules.ipban import (
            _state_add_entry, _state_load,
        )
        with self._patch():
            _state_add_entry("test", ["1.0.0.0/8"], "cidr", "old")
            _state_add_entry("test", ["2.0.0.0/8"], "cidr", "new")
            state = _state_load()
        self.assertEqual(len(state["entries"]), 1)
        self.assertEqual(state["entries"][0]["comment"], "new")

    def test_remove_existing_entry(self):
        from vless_installer.modules.ipban import (
            _state_add_entry, _state_remove_entry, _state_load,
        )
        with self._patch():
            _state_add_entry("test", ["1.0.0.0/8"], "cidr")
            self.assertTrue(_state_remove_entry("test"))
            state = _state_load()
        self.assertEqual(len(state["entries"]), 0)

    def test_remove_nonexistent_returns_false(self):
        from vless_installer.modules.ipban import _state_remove_entry
        with self._patch():
            self.assertFalse(_state_remove_entry("nonexistent"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
