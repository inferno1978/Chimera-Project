#!/usr/bin/env python3
"""
tests/test_ipset_persist.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/ipset_persist.py.

Покрывает:
  1. _detect_colors — tty/non-tty
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("chimera._core")
    m.__dict__.update(g)
    sys.modules["chimera._core"] = m


class TestIpsetPersist(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_detect_colors_non_tty(self):
        from chimera.modules.ipset_persist import _detect_colors
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = False
            c = _detect_colors()
            for v in c.values(): self.assertEqual(v, "")

# ── hysteria2_smoke_test ───────────────────────────────────────────────────

# ============================================================================
#  Тихое испарение бана ГРЧЦ (Москва, окт.2026): ipset_save() перезаписывал
#  /etc/ipset.conf ЦЕЛИКОМ, вычищая чужие секции xray_manual_ban* → ребут
#  восстанавливал пустые сеты. Фикс: merge — вырезаются только свои секции.
# ============================================================================

class _RuBlockSim:
    """Симулятор: сеты xray_ru_block* существуют, дамп фиксированный."""

    def __init__(self, dump_v4, dump_v6):
        self._dump = {
            "xray_ru_block": dump_v4,
            "xray_ru_block6": dump_v6,
        }

    def __call__(self, cmd, **kw):
        r = MagicMock()
        r.stderr = ""
        r.returncode = 0
        if cmd[:2] == ["ipset", "list"] and "-n" in cmd:
            r.returncode = 0 if cmd[3] in self._dump else 1
            r.stdout = ""
        elif cmd[:2] == ["ipset", "save"]:
            r.stdout = self._dump.get(cmd[2], "")
        elif cmd[0] == "which":
            r.returncode = 0
        else:
            r.stdout = ""
        return r


class TestIpsetSaveMerge(unittest.TestCase):
    """ipset_save() — merge-запись: чужие секции сохраняются дословно."""

    MANUAL_BAN_SECTION = (
        "create xray_manual_ban hash:net family inet maxelem 65536\n"
        "add xray_manual_ban 80.66.66.0/24\n"
        "add xray_manual_ban 185.242.246.0/24\n"
        "create xray_manual_ban6 hash:net family inet6 maxelem 65536\n"
        "add xray_manual_ban6 2a00:7360::/32\n"
    )

    def setUp(self):
        _setup_core()
        self._tmp = Path(tempfile.mkdtemp())
        self._conf = self._tmp / "ipset.conf"
        # свежий дамп ru_block (как после обновления геосписка)
        self._sim = _RuBlockSim(
            "create xray_ru_block hash:net family inet maxelem 65536\n"
            "add xray_ru_block 1.2.3.0/24\n",
            "create xray_ru_block6 hash:net family inet6 maxelem 65536\n",
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _patched_save(self):
        import chimera.modules.ipset_persist as mod
        with patch("chimera.modules.ipset_persist.subprocess.run", self._sim), \
             patch.object(mod, "_IPSET_CONF", self._conf):
            return mod.ipset_save()

    def test_save_preserves_foreign_manual_ban_sections(self):
        """РЕГРЕССИЯ кейса ГРЧЦ: чужие секции не вычищаются при сохранении."""
        self._conf.write_text(self.MANUAL_BAN_SECTION, encoding="utf-8")
        ok = self._patched_save()
        self.assertTrue(ok)
        text = self._conf.read_text(encoding="utf-8")
        self.assertIn("add xray_manual_ban 80.66.66.0/24", text,
                      "секция manual-ban вычищена ipset_save (регрессия ГРЧЦ)")
        self.assertIn("add xray_manual_ban 185.242.246.0/24", text)
        self.assertIn("add xray_manual_ban6 2a00:7360::/32", text)
        # свои секции — записаны свежим дампом
        self.assertIn("add xray_ru_block 1.2.3.0/24", text)

    def test_save_replaces_own_stale_ru_block_entries(self):
        """Устаревшие собственные строки заменяются, дубликатов нет."""
        self._conf.write_text(
            "create xray_ru_block hash:net family inet maxelem 65536\n"
            "add xray_ru_block 9.9.9.0/24\n"      # устаревшая запись
            + self.MANUAL_BAN_SECTION,
            encoding="utf-8",
        )
        ok = self._patched_save()
        self.assertTrue(ok)
        text = self._conf.read_text(encoding="utf-8")
        self.assertNotIn("add xray_ru_block 9.9.9.0/24", text,
                         "устаревшая собственная запись не заменена")
        self.assertEqual(text.count("create xray_ru_block "), 1)
        self.assertEqual(text.count("create xray_manual_ban "), 1)
        self.assertEqual(text.count("create xray_manual_ban6 "), 1)

    def test_save_creates_file_when_missing(self):
        """Файла нет → создаётся только из собственных секций."""
        ok = self._patched_save()
        self.assertTrue(ok)
        text = self._conf.read_text(encoding="utf-8")
        self.assertIn("add xray_ru_block 1.2.3.0/24", text)

    def test_save_returns_false_when_no_sets(self):
        """Сетов нет → файл не трогается вовсе (нечего сохранять)."""
        import chimera.modules.ipset_persist as mod
        nosets = MagicMock()
        nosets.returncode = 1
        nosets.stdout = ""
        nosets.stderr = ""
        self._conf.write_text(self.MANUAL_BAN_SECTION, encoding="utf-8")
        before = self._conf.read_text(encoding="utf-8")
        with patch("chimera.modules.ipset_persist.subprocess.run",
                   lambda cmd, **kw: nosets), \
             patch.object(mod, "_IPSET_CONF", self._conf):
            ok = mod.ipset_save()
        self.assertFalse(ok)
        self.assertEqual(self._conf.read_text(encoding="utf-8"), before,
                         "файл не должен меняться при отсутствии сетов")


if __name__ == "__main__":
    unittest.main(verbosity=2)
