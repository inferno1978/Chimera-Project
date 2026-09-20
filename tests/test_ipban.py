#!/usr/bin/env python3
"""
tests/test_ipban.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/ipban.py.

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


class TestParseIp(unittest.TestCase):
    """_parse_ip — парсинг IP."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ipv4(self):
        from chimera.modules.ipban import _parse_ip
        self.assertEqual(_parse_ip("1.2.3.4"), ["1.2.3.4/32"])

    def test_ipv6(self):
        from chimera.modules.ipban import _parse_ip
        self.assertEqual(_parse_ip("::1"), ["::1/128"])
        self.assertEqual(_parse_ip("2001:db8::1"), ["2001:db8::1/128"])

    def test_invalid_raises(self):
        from chimera.modules.ipban import _parse_ip
        with self.assertRaises(ValueError):
            _parse_ip("invalid")


class TestParseCidr(unittest.TestCase):
    """_parse_cidr — парсинг CIDR."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_valid_cidr(self):
        from chimera.modules.ipban import _parse_cidr
        self.assertEqual(_parse_cidr("10.0.0.0/24"), ["10.0.0.0/24"])

    def test_normalizes_non_strict(self):
        """10.0.0.5/24 нормализуется в 10.0.0.0/24."""
        from chimera.modules.ipban import _parse_cidr
        self.assertEqual(_parse_cidr("10.0.0.5/24"), ["10.0.0.0/24"])

    def test_ipv6_cidr(self):
        from chimera.modules.ipban import _parse_cidr
        self.assertEqual(_parse_cidr("2001:db8::/32"), ["2001:db8::/32"])


class TestParseRange(unittest.TestCase):
    """_parse_range — парсинг диапазона."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_valid_range(self):
        from chimera.modules.ipban import _parse_range
        result = _parse_range("1.2.3.0-1.2.3.255")
        self.assertGreater(len(result), 0)
        # summarize_address_range даёт ["1.2.3.0/24"]
        self.assertIn("1.2.3.0/24", result)

    def test_reversed_range_swapped(self):
        """Если start > end — меняются местами."""
        from chimera.modules.ipban import _parse_range
        result = _parse_range("1.2.3.255-1.2.3.0")
        self.assertIn("1.2.3.0/24", result)

    def test_no_hyphen_raises(self):
        from chimera.modules.ipban import _parse_range
        with self.assertRaises(ValueError):
            _parse_range("1.2.3.4")


class TestAsnNormalize(unittest.TestCase):
    """_asn_normalize — нормализация ASN."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_adds_as_prefix(self):
        from chimera.modules.ipban import _asn_normalize
        self.assertEqual(_asn_normalize("12345"), "AS12345")

    def test_uppercase(self):
        from chimera.modules.ipban import _asn_normalize
        self.assertEqual(_asn_normalize("as12345"), "AS12345")

    def test_already_prefixed(self):
        from chimera.modules.ipban import _asn_normalize
        self.assertEqual(_asn_normalize("AS12345"), "AS12345")
        self.assertEqual(_asn_normalize("as12345"), "AS12345")


class TestDetectInputKind(unittest.TestCase):
    """_detect_input_kind — классификатор."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_asn_with_prefix(self):
        from chimera.modules.ipban import _detect_input_kind
        self.assertEqual(_detect_input_kind("AS12345"), "asn")

    def test_asn_numeric(self):
        from chimera.modules.ipban import _detect_input_kind
        self.assertEqual(_detect_input_kind("12345"), "asn")

    def test_cidr(self):
        from chimera.modules.ipban import _detect_input_kind
        self.assertEqual(_detect_input_kind("10.0.0.0/24"), "cidr")

    def test_range(self):
        from chimera.modules.ipban import _detect_input_kind
        self.assertEqual(_detect_input_kind("1.2.3.0-1.2.3.255"), "range")

    def test_ip(self):
        from chimera.modules.ipban import _detect_input_kind
        self.assertEqual(_detect_input_kind("1.2.3.4"), "ip")

    def test_ipv6_is_ip(self):
        """IPv6 без / → 'ip' (нет дефиса, нет /)."""
        from chimera.modules.ipban import _detect_input_kind
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
        return patch("chimera.modules.ipban._STATE_FILE", self._state)

    def test_load_returns_default_when_no_file(self):
        from chimera.modules.ipban import _state_load
        with self._patch():
            result = _state_load()
        self.assertEqual(result, {"entries": []})

    def test_load_returns_default_on_corrupt(self):
        from chimera.modules.ipban import _state_load
        self._state.write_text("{invalid")
        with self._patch():
            result = _state_load()
        self.assertEqual(result, {"entries": []})

    def test_save_then_load(self):
        from chimera.modules.ipban import _state_load, _state_save
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
        return patch("chimera.modules.ipban._STATE_FILE", self._state)

    def test_add_new_entry(self):
        from chimera.modules.ipban import (
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
        from chimera.modules.ipban import (
            _state_add_entry, _state_load,
        )
        with self._patch():
            _state_add_entry("test", ["1.0.0.0/8"], "cidr", "old")
            _state_add_entry("test", ["2.0.0.0/8"], "cidr", "new")
            state = _state_load()
        self.assertEqual(len(state["entries"]), 1)
        self.assertEqual(state["entries"][0]["comment"], "new")

    def test_remove_existing_entry(self):
        from chimera.modules.ipban import (
            _state_add_entry, _state_remove_entry, _state_load,
        )
        with self._patch():
            _state_add_entry("test", ["1.0.0.0/8"], "cidr")
            self.assertTrue(_state_remove_entry("test"))
            state = _state_load()
        self.assertEqual(len(state["entries"]), 0)

    def test_remove_nonexistent_returns_false(self):
        from chimera.modules.ipban import _state_remove_entry
        with self._patch():
            self.assertFalse(_state_remove_entry("nonexistent"))


# ============================================================================
#  Порядок правил + персистентность (кейс vds14808 / AS25369, 2026-09-21)
# ============================================================================
from unittest.mock import MagicMock


class _FakeRunner:
    """Рекордер subprocess.run с управляемыми кодами возврата."""

    def __init__(self):
        self.calls: list = []

    def __call__(self, cmd, **kw):
        self.calls.append(list(cmd))
        rc = 1
        if cmd[:2] == ["ipset", "create"]:
            rc = 0
        elif cmd[0] == "systemctl":
            rc = 0
        elif "-C" in cmd:
            rc = 1   # правило не найдено → вставка выполнится
        elif "-D" in cmd:
            rc = 1   # нечего удалять → цикл миграции прерывается сразу
        elif "-I" in cmd:
            rc = 0
        elif "which" == cmd[0]:
            rc = 0
        r = MagicMock()
        r.returncode = rc
        r.stdout = ""
        r.stderr = ""
        return r


class TestRulesOrderingAndPersistence(unittest.TestCase):
    """Правила банa обязаны стоять ПЕРВОЙ строкой INPUT — до ufw-цепочек.

    Регрессия кейса AS25369 (2026-09-21): при включённом UFW (дефолт
    Chimera) пакеты на открытые порты принимаются внутри
    ufw-before-input/ufw-user-input (first-match-wins) и НИКОГДА не
    доходят до правила, добавленного -A INPUT (в конец) → бан ASN был
    декоративным. Дополнительно: ipset_persist восстанавливает только
    сеты, правила iptables после reboot терялись.
    """

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self._runner = _FakeRunner()
        _p1 = patch("chimera.modules.ipban.subprocess.run", self._runner)
        _p1.start()
        self.addCleanup(_p1.stop)
        _p2 = patch("chimera.modules.ipban._BOOT_UNIT",
                    self._tmp / "xray-ipban-restore.service")
        _p2.start()
        self.addCleanup(_p2.stop)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_rule_spec_includes_comment(self):
        """-C/-D/-I используют единый spec с comment-матчером.

        Старый код проверял -C БЕЗ comment, а правило создавал С
        comment → проверка никогда не находила правило → дубликаты.
        """
        from chimera.modules.ipban import _iptables_rule_spec, _COMMENT
        spec = _iptables_rule_spec("xray_manual_ban")
        self.assertIn("-m", spec)
        self.assertIn("comment", spec)
        self.assertIn(_COMMENT, spec)

    def test_ensure_uses_insert_at_top_not_append(self):
        """Правило вставляется -I INPUT 1, НЕ -A INPUT (в конец)."""
        from chimera.modules.ipban import _ensure_iptables_rules
        _ensure_iptables_rules()
        inserted = [c for c in self._runner.calls if c[:4] == ["iptables", "-I", "INPUT", "1"]]
        self.assertTrue(inserted, "iptables -I INPUT 1 не вызван")
        for c in inserted:
            self.assertIn("--match-set", c)
            self.assertIn("xray_manual_ban", c)
        inserted6 = [c for c in self._runner.calls if c[:4] == ["ip6tables", "-I", "INPUT", "1"]]
        self.assertTrue(inserted6, "ip6tables -I INPUT 1 не вызван")
        appended = [c for c in self._runner.calls if c[:3] in (
            ["iptables", "-A", "INPUT"], ["ip6tables", "-A", "INPUT"])]
        self.assertFalse(appended, f"-A INPUT запрещён (недостижимо за ufw): {appended}")

    def test_ensure_migrates_old_appended_rules(self):
        """Старые правила (любой spec-вариант) удаляются перед вставкой."""
        from chimera.modules.ipban import _ensure_iptables_rules
        _ensure_iptables_rules()
        deletes = [c for c in self._runner.calls if c[:3] == ["iptables", "-D", "INPUT"]]
        self.assertTrue(deletes, "миграция: старые правила не удаляются")
        # удаляются ОБА варианта spec — с comment и без
        with_comment = [c for c in deletes if "comment" in c]
        without_comment = [c for c in deletes if "comment" not in c]
        self.assertTrue(with_comment, "миграция не удаляет вариант с comment")
        self.assertTrue(without_comment, "миграция не удаляет вариант без comment")

    def test_boot_unit_created_and_persists_rules(self):
        """После reboot правила восстанавливаются юнитом (сеты + INPUT 1)."""
        from chimera.modules.ipban import _ensure_boot_unit, _BOOT_UNIT
        _ensure_boot_unit()
        self.assertTrue(_BOOT_UNIT.exists(), "юнит не записан")
        text = _BOOT_UNIT.read_text(encoding="utf-8")
        self.assertIn("ipset create xray_manual_ban", text)
        self.assertIn("-exist", text)
        self.assertIn("-I INPUT 1", text, "юнит восстанавливает правило НЕ первой строкой")
        self.assertIn("xray_manual_ban6", text)
        self.assertIn("After=xray-ipset-restore.service", text)
        # enable вызван
        enabled = [c for c in self._runner.calls
                   if c[:2] == ["systemctl", "enable"]]
        self.assertTrue(enabled, "systemctl enable юнита не вызван")

    def test_ipban_add_bootstraps_rules_and_unit(self):
        """ipban_add ставит правила + юнит (мокается только резолв CIDR)."""
        import chimera.modules.ipban as ipban
        with patch.object(ipban, "_resolve_to_cidrs",
                          return_value=("1.2.3.4", "ip", ["1.2.3.4/32"])), \
             patch.object(ipban, "_ensure_sets", return_value=True), \
             patch.object(ipban, "_state_add_entry"), \
             patch.object(ipban, "_ipban_persist_save"):
            ipban.ipban_add("1.2.3.4")
        top_insert = [c for c in self._runner.calls if c[:4] == ["iptables", "-I", "INPUT", "1"]]
        self.assertTrue(top_insert, "ipban_add не вставил правило в вершину INPUT")
        unit_calls = [c for c in self._runner.calls if c[:2] == ["systemctl", "enable"]]
        self.assertTrue(unit_calls, "ipban_add не установил boot-юнит")


if __name__ == "__main__":
    unittest.main(verbosity=2)
