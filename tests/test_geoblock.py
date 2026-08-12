#!/usr/bin/env python3
"""
tests/test_geoblock.py
───────────────────────────────────────────────────────────────────────────────
Тесты для chimera/modules/geoblock.py — гео-блокировка по странам.

Покрывает:
  1. geoblock_add_country — вызывает nft_common (set_create + atomic_swap +
     rule_add) для применения DROP-правила на TCP-порту.
  2. geoblock_remove_country — вызывает nft_rule_delete_by_comment +
     nft_set_destroy для очистки.
  3. geoblock_list — возвращает список из state.
  4. geoblock_add_country с невалидным кодом → False.
  5. geoblock_add_country без nft binary → False.
  6. State сохраняется после add/remove.

МИГРАЦИЯ (этап 1.2):
  Раньше тесты мокали `geoblock._run` (который вызывал ipset/iptables).
  Теперь `geoblock.py` использует функции из `chimera.modules.nft_common`,
  поэтому тесты мокают именно эти функции. Семантика идентична: что
  блокировалось — то и блокируется; изменился только firewall backend.
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

    def test_add_country_calls_nft_set_create_and_rule_add(self):
        """Кейс 1: add_country вызывает nft_set_create + nft_set_atomic_swap +
        nft_rule_add для применения DROP-правила."""
        from chimera.modules import geoblock
        core = sys.modules["chimera._core"]
        core.info = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        core.success = lambda *a, **kw: None

        # Мокаем все nft_common-функции, которые вызывает geoblock.
        nft_calls = []

        def _track(name):
            def _f(*args, **kwargs):
                nft_calls.append((name, args, kwargs))
                return True
            return _f

        with patch.object(geoblock, "_core_module", lambda: core), \
             patch.object(geoblock, "_STATE_FILE", self._state_file), \
             patch.object(geoblock, "_nft_available", return_value=True), \
             patch.object(geoblock, "nft_set_create", side_effect=_track("nft_set_create")), \
             patch.object(geoblock, "nft_set_atomic_swap", side_effect=_track("nft_set_atomic_swap")), \
             patch.object(geoblock, "nft_rule_add", side_effect=_track("nft_rule_add")), \
             patch.object(geoblock, "nft_persist", side_effect=_track("nft_persist")), \
             patch.object(geoblock, "_fetch_country_cidrs",
                          return_value=(["1.2.3.0/24", "5.6.7.0/24"], [])):
            ok = geoblock.geoblock_add_country(443, "ir")

        self.assertTrue(ok)

        # Проверяем что nft_set_create был вызван для v4 (с флагом interval).
        set_creates = [c for c in nft_calls if c[0] == "nft_set_create"]
        self.assertGreater(len(set_creates), 0,
                           "Должен быть вызов nft_set_create")
        v4_create = set_creates[0]
        self.assertEqual(v4_create[1][0], "geoblock_ir_v4")
        self.assertEqual(v4_create[2].get("set_type"), "ipv4_addr")
        self.assertIn("interval", v4_create[2].get("flags", []))

        # Проверяем atomic swap: обновление содержимого set.
        swaps = [c for c in nft_calls if c[0] == "nft_set_atomic_swap"]
        self.assertEqual(len(swaps), 1)
        self.assertEqual(swaps[0][1][0], "geoblock_ir_v4")
        self.assertEqual(swaps[0][1][1], ["1.2.3.0/24", "5.6.7.0/24"])

        # Проверяем DROP-правило: tcp dport 443 ip saddr @geoblock_ir_v4 drop
        rule_adds = [c for c in nft_calls if c[0] == "nft_rule_add"]
        self.assertEqual(len(rule_adds), 1)
        spec = rule_adds[0][2].get("rule_spec", "")
        self.assertIn("tcp dport 443", spec)
        self.assertIn("ip saddr @geoblock_ir_v4", spec)
        self.assertIn("drop", spec)
        self.assertEqual(rule_adds[0][2].get("comment"), "telemt-geoblock-ir")

        # State сохранён.
        state = json.loads(self._state_file.read_text())
        self.assertIn("ir", state.get("443", []))

    def test_add_country_with_ipv6_adds_v6_rule(self):
        """Доп: если страна имеет IPv6 CIDR, добавляется второе правило с ip6."""
        from chimera.modules import geoblock
        core = sys.modules["chimera._core"]
        core.info = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        core.success = lambda *a, **kw: None

        nft_calls = []

        def _track(name):
            def _f(*args, **kwargs):
                nft_calls.append((name, args, kwargs))
                return True
            return _f

        with patch.object(geoblock, "_core_module", lambda: core), \
             patch.object(geoblock, "_STATE_FILE", self._state_file), \
             patch.object(geoblock, "_nft_available", return_value=True), \
             patch.object(geoblock, "nft_set_create", side_effect=_track("nft_set_create")), \
             patch.object(geoblock, "nft_set_atomic_swap", side_effect=_track("nft_set_atomic_swap")), \
             patch.object(geoblock, "nft_rule_add", side_effect=_track("nft_rule_add")), \
             patch.object(geoblock, "nft_persist", side_effect=_track("nft_persist")), \
             patch.object(geoblock, "_fetch_country_cidrs",
                          return_value=(["1.2.3.0/24"], ["2001:db8::/32"])):
            ok = geoblock.geoblock_add_country(8443, "cn")

        self.assertTrue(ok)

        # Должно быть два nft_set_create, два atomic_swap, два rule_add.
        self.assertEqual(len([c for c in nft_calls if c[0] == "nft_set_create"]), 2)
        self.assertEqual(len([c for c in nft_calls if c[0] == "nft_set_atomic_swap"]), 2)
        rule_adds = [c for c in nft_calls if c[0] == "nft_rule_add"]
        self.assertEqual(len(rule_adds), 2)
        # Один с ip saddr, второй с ip6 saddr.
        specs = [c[2].get("rule_spec", "") for c in rule_adds]
        self.assertTrue(any("ip saddr @geoblock_cn_v4" in s for s in specs))
        self.assertTrue(any("ip6 saddr @geoblock_cn_v6" in s for s in specs))
        # Comment-tag одинаковый для обоих правил.
        for c in rule_adds:
            self.assertEqual(c[2].get("comment"), "telemt-geoblock-cn")

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

    def test_add_country_without_nft_returns_false(self):
        """Кейс 5: если `nft` binary не установлен → False (с предупреждением)."""
        from chimera.modules import geoblock
        core = sys.modules["chimera._core"]
        core.info = lambda *a, **kw: None
        core.warn = MagicMock()
        core.success = lambda *a, **kw: None

        with patch.object(geoblock, "_core_module", lambda: core), \
             patch.object(geoblock, "_STATE_FILE", self._state_file), \
             patch.object(geoblock, "_nft_available", return_value=False):
            ok = geoblock.geoblock_add_country(443, "ir")
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

    def test_remove_country_calls_nft_delete_and_destroy(self):
        """Кейс 2: remove вызывает nft_rule_delete_by_comment + nft_set_destroy."""
        from chimera.modules import geoblock
        core = sys.modules["chimera._core"]
        core.info = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        core.success = lambda *a, **kw: None

        # Pre-populate state.
        self._state_file.write_text(json.dumps({"443": ["ir", "cn"]}))

        nft_calls = []

        def _track(name):
            def _f(*args, **kwargs):
                nft_calls.append((name, args, kwargs))
                return True if name != "nft_rule_delete_by_comment" else 1
            return _f

        with patch.object(geoblock, "_core_module", lambda: core), \
             patch.object(geoblock, "_STATE_FILE", self._state_file), \
             patch.object(geoblock, "nft_rule_delete_by_comment",
                          side_effect=_track("nft_rule_delete_by_comment")), \
             patch.object(geoblock, "nft_set_destroy",
                          side_effect=_track("nft_set_destroy")), \
             patch.object(geoblock, "nft_persist",
                          side_effect=_track("nft_persist")):
            ok = geoblock.geoblock_remove_country(443, "ir")

        self.assertTrue(ok)

        # nft_rule_delete_by_comment вызывается с comment="telemt-geoblock-ir".
        deletes = [c for c in nft_calls if c[0] == "nft_rule_delete_by_comment"]
        self.assertEqual(len(deletes), 1)
        self.assertEqual(deletes[0][2].get("comment"), "telemt-geoblock-ir")
        self.assertEqual(deletes[0][2].get("chain"), "input")
        self.assertEqual(deletes[0][2].get("table"), "chimera")

        # nft_set_destroy вызывается дважды — для v4 и v6 set-ов.
        destroys = [c for c in nft_calls if c[0] == "nft_set_destroy"]
        self.assertEqual(len(destroys), 2)
        destroyed_names = {d[1][0] for d in destroys}
        self.assertIn("geoblock_ir_v4", destroyed_names)
        self.assertIn("geoblock_ir_v6", destroyed_names)

        # State обновлён — "ir" удалён, "cn" остался.
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
