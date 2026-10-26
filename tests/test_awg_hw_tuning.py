#!/usr/bin/env python3
"""
tests/test_awg_hw_tuning.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/awg_hw_tuning.py.

Покрывает:
  1. awgs_detect_ram_mb — чтение /proc/meminfo
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
    import chimera as _pkg310  # 3.10: mock._dot_lookup идёт через атрибут пакета
    _pkg310._core = m
class TestAwgHwTuning(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_detect_ram_mb(self):
        from chimera.modules import awg_hw_tuning
        content = "MemTotal:       16384000 kB\n"
        with patch("pathlib.Path.read_text", return_value=content):
            with patch("pathlib.Path.exists", return_value=True):
                ram = awg_hw_tuning.awgs_detect_ram_mb()
        self.assertEqual(ram, 16000)
    def test_detect_ram_no_file(self):
        from chimera.modules import awg_hw_tuning
        orig_read = Path.read_text
        def _fake_read(self):
            raise OSError("no file")
        with patch("pathlib.Path.read_text", _fake_read):
            self.assertEqual(awg_hw_tuning.awgs_detect_ram_mb(), 0)


class TestSysctlApplyIdempotent(unittest.TestCase):
    """awgs_sysctl_apply_idempotent — семантика MIN-ключей (буферы)."""

    def setUp(self): _setup_core()

    def _run_apply(self, fake_values):
        """Запуск применителя с замоканным чтением sysctl."""
        from chimera.modules import awg_hw_tuning
        from chimera.modules.awg_constants import AWGS_SYSCTL_TARGETS
        with patch.object(awg_hw_tuning, "awgs_sysctl_get") as mock_get, \
             patch.object(awg_hw_tuning, "awgs_sysctl_set") as mock_set, \
             patch("chimera._core._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="0\n", stderr="")

            def _get(key):
                if key in fake_values:
                    return fake_values[key]
                return str(AWGS_SYSCTL_TARGETS.get(key, ""))

            mock_get.side_effect = _get
            results = awg_hw_tuning.awgs_sysctl_apply_idempotent()
        return results, mock_set

    def test_does_not_downgrade_raised_buffers(self):
        """current(128МБ) > target(7.5МБ) → НЕ понижаем, changed=False.

        Кейс со 138.х: rmem_max/wmem_max = 134217728 — повторный прогон
        тюнинга не должен опускать их до 7500000.
        """
        from chimera.modules.awg_constants import AWGS_SYSCTL_MIN_KEYS
        fake = {k: "134217728" for k in AWGS_SYSCTL_MIN_KEYS}
        results, mock_set = self._run_apply(fake)
        for k in AWGS_SYSCTL_MIN_KEYS:
            self.assertFalse(results[k]["changed"], k)
            self.assertEqual(results[k]["old"], "134217728", k)
            self.assertEqual(results[k]["new"], "134217728", k)
        # set() не вызывался ни для одного буфера
        self.assertEqual(mock_set.call_count, 0)

    def test_raises_buffers_below_target(self):
        """current(1МБ) < target(7.5МБ) → применяем target, changed=True."""
        fake = {"net.core.rmem_default": "1048576",
                "net.core.wmem_default": "1048576"}
        results, mock_set = self._run_apply(fake)
        for k in fake:
            self.assertTrue(results[k]["changed"], k)
            self.assertEqual(results[k]["new"], "7500000", k)
        self.assertEqual(mock_set.call_count, len(fake))
        # вызовы — с target-значением
        for call in mock_set.call_args_list:
            self.assertEqual(call.args[1], 7500000)

    def test_exact_keys_unchanged_semantics(self):
        """Немонотонные ключи: значение на цели → не трогаем (как раньше)."""
        results, mock_set = self._run_apply({})
        for r in results.values():
            self.assertFalse(r["changed"])
        self.assertEqual(mock_set.call_count, 0)


class TestSysctlSetDedup(unittest.TestCase):
    """awgs_sysctl_set — дедуп строк в /etc/sysctl.d/99-awg-standalone.conf.

    Баг (пойман на RU-1): writer пишет «key = value» (с пробелами вокруг =),
    а фильтр удаления матчил только «key=» (без пробелов) → при повторном
    применении того же ключа в файле плодились дубли.
    """

    def setUp(self): _setup_core()

    def _write_with(self, existing, key, value):
        from chimera.modules import awg_hw_tuning
        written = {}

        def _capture_write(self_path, content, *a, **kw):
            written["content"] = content

        with patch("chimera._core._run") as mock_run, \
             patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", return_value=existing), \
             patch.object(Path, "write_text", _capture_write):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            ok = awg_hw_tuning.awgs_sysctl_set(key, value)
        return ok, written.get("content", "")

    def test_no_duplicate_lines_on_rewrite(self):
        """Повторная запись ключа заменяет старые строки (включая spaced)."""
        existing = (
            "net.core.rmem_max = 7500000\n"
            "net.core.rmem_default = 7500000\n"
            "net.core.rmem_default = 7500000\n"   # дубль от старого writer
            "net.ipv4.ip_forward = 1\n"
        )
        ok, content = self._write_with(existing, "net.core.rmem_default", 7500000)
        self.assertTrue(ok)
        self.assertEqual(content.count("net.core.rmem_default"), 1)
        # прочие ключи не тронуты
        self.assertIn("net.core.rmem_max = 7500000", content)
        self.assertIn("net.ipv4.ip_forward = 1", content)

    def test_no_space_format_replaced_too(self):
        """Строки легаси-формата «key=value» (без пробелов) тоже заменяются."""
        existing = (
            "net.core.wmem_default=1048576\n"
            "net.core.rmem_default = 7500000\n"
        )
        ok, content = self._write_with(existing, "net.core.wmem_default", 1048576)
        self.assertTrue(ok)
        self.assertEqual(content.count("net.core.wmem_default"), 1)
        self.assertIn("net.core.wmem_default = 1048576", content)
        self.assertNotIn("net.core.wmem_default=1048576", content)

    def test_prefix_key_not_clobbered(self):
        """Запись ip_forward НЕ трогает ip_forward_use_pmtu (префикс-ключ)."""
        existing = (
            "net.ipv4.ip_forward = 1\n"
            "net.ipv4.ip_forward_use_pmtu = 0\n"
        )
        ok, content = self._write_with(existing, "net.ipv4.ip_forward", 1)
        self.assertTrue(ok)
        self.assertIn("net.ipv4.ip_forward_use_pmtu = 0", content)
        self.assertEqual(content.count("net.ipv4.ip_forward ="), 1)
        # use_pmtu не превратился в дубль ip_forward
        self.assertEqual(content.count("ip_forward_use_pmtu"), 1)

# ── xray_safe_apply ────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
