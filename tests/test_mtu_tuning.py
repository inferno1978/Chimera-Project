#!/usr/bin/env python3
"""
tests/test_mtu_tuning.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/mtu_tuning.py.

Покрывает:
  1. _mtu_state_load / _mtu_state_save — JSON I/O
"""
from __future__ import annotations

import json
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


class TestMtuStateLoadSave(unittest.TestCase):
    """_mtu_state_load / _mtu_state_save — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "mtu_tuning.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.mtu_tuning._MTU_STATE_FILE", self._state)

    def test_load_returns_empty_when_no_file(self):
        from chimera.modules.mtu_tuning import _mtu_state_load
        with self._patch():
            self.assertEqual(_mtu_state_load(), {})

    def test_load_returns_empty_on_corrupt(self):
        from chimera.modules.mtu_tuning import _mtu_state_load
        self._state.write_text("{invalid")
        with self._patch():
            self.assertEqual(_mtu_state_load(), {})

    def test_save_then_load(self):
        from chimera.modules.mtu_tuning import _mtu_state_load, _mtu_state_save
        data = {"mtu": 1280, "iface": "eth0"}
        with self._patch():
            _mtu_state_save(data)
            loaded = _mtu_state_load()
        self.assertEqual(loaded["mtu"], 1280)
        self.assertEqual(loaded["iface"], "eth0")


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТЫ МИГРАЦИИ НА NFTABLES (этап 1.4) — мок nft_common
# ══════════════════════════════════════════════════════════════════════════════
class TestNftMigration(unittest.TestCase):
    """Проверяет что mtu_tuning.py использует nft_common вместо прямых
    iptables subprocess-вызовов (этап 1.4 миграции).

    Мокает nft_mangle_mssclamp / nft_rule_delete_by_comment — проверяет что:
      • _mtu_apply вызывает nft_mangle_mssclamp дважды: с mss=<int> (set-mss)
        и с mss=None (clamp-to-pmtu). Оба вызова используют один comment-tag
        "chimera-mss-clamp" (для cleanup через nft_rule_delete_by_comment).
      • _mtu_apply перед удалением вызывает nft_rule_delete_by_comment
        (идемпотентность — очистка старых правил перед применением новых).
      • _mtu_remove_rules делегирует в nft_rule_delete_by_comment полностью
        (nodes больше не нужны для cleanup — одна команда на все правила).
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_mtu_apply_calls_nft_mangle_mssclamp_twice(self):
        """_mtu_apply вызывает nft_mangle_mssclamp дважды: set-mss + clamp-pmtu."""
        from chimera.modules import mtu_tuning
        with patch("chimera.modules.mtu_tuning.nft_mangle_mssclamp",
                   return_value=True) as mock_clamp, \
             patch("chimera.modules.mtu_tuning.nft_rule_delete_by_comment",
                   return_value=0):
            # _mtu_apply internally calls core._run for `ip link set mtu`
            # and that should be mocked too
            with patch("chimera._core._run") as mock_run:
                mtu_tuning._mtu_apply("eth0", 1400, [])
        # Должно быть 2 вызова nft_mangle_mssclamp:
        # 1) mss=1360 (1400-40), out_iface="eth0"  → set-mss
        # 2) mss=None (clamp-to-pmtu)
        self.assertEqual(mock_clamp.call_count, 2)
        # Первый вызов: set-mss с out_iface
        _, kwargs_first = mock_clamp.call_args_list[0]
        self.assertEqual(kwargs_first.get("mss"), 1360)  # 1400 - 40
        self.assertEqual(kwargs_first.get("out_iface"), "eth0")
        self.assertEqual(kwargs_first.get("comment"), "chimera-mss-clamp")
        self.assertFalse(kwargs_first.get("idempotent"))  # уже почистили выше
        # Второй вызов: clamp-to-pmtu
        _, kwargs_second = mock_clamp.call_args_list[1]
        self.assertIsNone(kwargs_second.get("mss"))
        self.assertEqual(kwargs_second.get("comment"), "chimera-mss-clamp")

    def test_mtu_apply_calls_cleanup_before_add(self):
        """_mtu_apply перед apply вызывает nft_rule_delete_by_comment для cleanup."""
        from chimera.modules import mtu_tuning
        with patch("chimera.modules.mtu_tuning.nft_mangle_mssclamp",
                   return_value=True), \
             patch("chimera.modules.mtu_tuning.nft_rule_delete_by_comment",
                   return_value=1) as mock_del, \
             patch("chimera._core._run"):
            mtu_tuning._mtu_apply("eth0", 1400, [])
        mock_del.assert_called_once()
        _, kwargs = mock_del.call_args
        self.assertEqual(kwargs.get("comment"), "chimera-mss-clamp")
        self.assertEqual(kwargs.get("chain"), "mangle_forward")
        self.assertEqual(kwargs.get("table"), "chimera")

    def test_mtu_remove_rules_uses_nft_delete_by_comment(self):
        """_mtu_remove_rules делегирует в nft_rule_delete_by_comment (один вызов
        вместо цикла iptables -D по нодам)."""
        from chimera.modules import mtu_tuning
        # nodes больше не нужны для cleanup, но сигнатура сохранена для
        # обратной совместимости с _core.py
        with patch("chimera.modules.mtu_tuning.nft_rule_delete_by_comment",
                   return_value=3) as mock_del:
            mtu_tuning._mtu_remove_rules([
                {"host": "1.2.3.4", "port": 443},
                {"host": "5.6.7.8", "port": 443},
            ])
        mock_del.assert_called_once()
        _, kwargs = mock_del.call_args
        self.assertEqual(kwargs.get("comment"), "chimera-mss-clamp")
        self.assertEqual(kwargs.get("chain"), "mangle_forward")
        self.assertEqual(kwargs.get("table"), "chimera")

    def test_mtu_apply_mss_computed_from_mtu(self):
        """MSS вычисляется как mtu - 40 (20 IP + 20 TCP)."""
        from chimera.modules import mtu_tuning
        with patch("chimera.modules.mtu_tuning.nft_mangle_mssclamp",
                   return_value=True) as mock_clamp, \
             patch("chimera.modules.mtu_tuning.nft_rule_delete_by_comment",
                   return_value=0), \
             patch("chimera._core._run"):
            # MTU 1500 → MSS 1460
            mtu_tuning._mtu_apply("eth0", 1500, [])
        _, kwargs_first = mock_clamp.call_args_list[0]
        self.assertEqual(kwargs_first.get("mss"), 1460)


if __name__ == "__main__":
    unittest.main(verbosity=2)
