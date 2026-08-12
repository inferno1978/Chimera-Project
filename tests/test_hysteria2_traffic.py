#!/usr/bin/env python3
"""
tests/test_hysteria2_traffic.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/hysteria2_traffic.py.

Покрывает:
  1. _bytes_to_human — форматирование байт
  2. _load_cache / _save_cache — JSON I/O
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


class TestH2TrafficBytesToHuman(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_zero(self):
        from chimera.modules.hysteria2_traffic import _bytes_to_human
        self.assertIn("B", _bytes_to_human(0))
    def test_kb(self):
        from chimera.modules.hysteria2_traffic import _bytes_to_human
        self.assertIn("KB", _bytes_to_human(1024))
    def test_mb(self):
        from chimera.modules.hysteria2_traffic import _bytes_to_human
        self.assertIn("MB", _bytes_to_human(1024**2))
    def test_pb(self):
        from chimera.modules.hysteria2_traffic import _bytes_to_human
        self.assertIn("PB", _bytes_to_human(1024**5))


class TestH2TrafficCache(unittest.TestCase):
    def setUp(self):
        _setup_core()
        self._tmp = Path(tempfile.mkdtemp()); self._c = self._tmp / "cache.json"
    def tearDown(self):
        import shutil; shutil.rmtree(self._tmp, ignore_errors=True)
    def _patch(self):
        return patch("chimera.modules.hysteria2_traffic._STATS_CACHE", self._c)
    def test_load_empty(self):
        from chimera.modules.hysteria2_traffic import _load_cache
        with self._patch(): self.assertEqual(_load_cache(), {})
    def test_save_load(self):
        from chimera.modules.hysteria2_traffic import _load_cache, _save_cache
        with self._patch():
            _save_cache({"bytes":100}); self.assertEqual(_load_cache()["bytes"], 100)

# ── hysteria2_backup ───────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТЫ МИГРАЦИИ НА NFTABLES (этап 1.5) — мок nft_common
# ══════════════════════════════════════════════════════════════════════════════
class TestNftMigration(unittest.TestCase):
    """Проверяет что hysteria2_traffic.py использует nft_common вместо прямых
    iptables/ip6tables subprocess-вызовов (этап 1.5 миграции).

    Мокает nft_rule_insert / nft_rule_exists / nft_rule_counter_read /
    _nft_available — проверяет что:
      • _ensure_h2_counter_rule создаёт per-port counter-rule через nft_rule_insert.
      • _parse_iptables_bytes делегирует в nft_rule_counter_read.
      • Параметр ipv6 игнорируется (inet таблица покрывает v4+v6 одним правилом).
      • Используется per-port comment-tag "hysteria2-stats-<port>".
    """

    def setUp(self):
        _setup_core()

    def test_uses_per_port_comment_tag(self):
        """Comment-tag для counter-rule — per-port (динамический)."""
        from chimera.modules import hysteria2_traffic
        self.assertEqual(hysteria2_traffic._h2_stats_comment(443),
                         "hysteria2-stats-443")
        self.assertEqual(hysteria2_traffic._h2_stats_comment(8443),
                         "hysteria2-stats-8443")

    def test_ensure_h2_counter_rule_returns_false_when_unavailable(self):
        """Если nft binary недоступен — _ensure_h2_counter_rule возвращает False."""
        from chimera.modules import hysteria2_traffic
        with patch("chimera.modules.hysteria2_traffic._nft_available",
                   return_value=False):
            self.assertFalse(hysteria2_traffic._ensure_h2_counter_rule(443))

    def test_ensure_h2_counter_rule_returns_true_if_exists(self):
        """Если counter-rule уже есть — не пересоздаём."""
        from chimera.modules import hysteria2_traffic
        with patch("chimera.modules.hysteria2_traffic._nft_available",
                   return_value=True), \
             patch("chimera.modules.hysteria2_traffic.nft_rule_exists",
                   return_value=True) as mock_exists, \
             patch("chimera.modules.hysteria2_traffic.nft_rule_insert") as mock_insert:
            result = hysteria2_traffic._ensure_h2_counter_rule(443)
        self.assertTrue(result)
        mock_insert.assert_not_called()
        _, kwargs = mock_exists.call_args
        self.assertEqual(kwargs.get("comment"), "hysteria2-stats-443")
        self.assertEqual(kwargs.get("chain"), "input")

    def test_ensure_h2_counter_rule_inserts_when_missing(self):
        """Если counter-rule нет — создаём через nft_rule_insert."""
        from chimera.modules import hysteria2_traffic
        with patch("chimera.modules.hysteria2_traffic._nft_available",
                   return_value=True), \
             patch("chimera.modules.hysteria2_traffic.nft_rule_exists",
                   return_value=False), \
             patch("chimera.modules.hysteria2_traffic.nft_rule_insert",
                   return_value=True) as mock_insert:
            result = hysteria2_traffic._ensure_h2_counter_rule(443)
        self.assertTrue(result)
        mock_insert.assert_called_once()
        _, kwargs = mock_insert.call_args
        spec = kwargs.get("rule_spec", "")
        self.assertIn("udp dport 443", spec)
        self.assertIn("counter accept", spec)
        self.assertEqual(kwargs.get("comment"), "hysteria2-stats-443")

    def test_parse_iptables_bytes_uses_nft_counter_read(self):
        """_parse_iptables_bytes делегирует в nft_rule_counter_read (имя сохранено)."""
        from chimera.modules import hysteria2_traffic
        with patch("chimera.modules.hysteria2_traffic._nft_available",
                   return_value=True), \
             patch("chimera.modules.hysteria2_traffic.nft_rule_counter_read",
                   return_value={"packets": 100, "bytes": 4096}) as mock_cnt, \
             patch("chimera.modules.hysteria2_traffic._ensure_h2_counter_rule",
                   return_value=True):
            result = hysteria2_traffic._parse_iptables_bytes(443)
        self.assertEqual(result, 4096)
        mock_cnt.assert_called_once()
        _, kwargs = mock_cnt.call_args
        self.assertEqual(kwargs.get("comment"), "hysteria2-stats-443")
        self.assertEqual(kwargs.get("chain"), "input")

    def test_parse_iptables_bytes_returns_zero_when_nft_unavailable(self):
        """Если nft недоступен — _parse_iptables_bytes возвращает 0."""
        from chimera.modules import hysteria2_traffic
        with patch("chimera.modules.hysteria2_traffic._nft_available",
                   return_value=False):
            self.assertEqual(hysteria2_traffic._parse_iptables_bytes(443), 0)

    def test_parse_iptables_bytes_ipv6_param_ignored(self):
        """Параметр ipv6 игнорируется — inet покрывает v4+v6 одним правилом."""
        from chimera.modules import hysteria2_traffic
        # Два вызова — с ipv6=False и ipv6=True — возвращают одинаковый результат
        with patch("chimera.modules.hysteria2_traffic._nft_available",
                   return_value=True), \
             patch("chimera.modules.hysteria2_traffic.nft_rule_counter_read",
                   return_value={"packets": 100, "bytes": 4096}), \
             patch("chimera.modules.hysteria2_traffic._ensure_h2_counter_rule",
                   return_value=True):
            n_v4 = hysteria2_traffic._parse_iptables_bytes(443, ipv6=False)
            n_v6 = hysteria2_traffic._parse_iptables_bytes(443, ipv6=True)
        self.assertEqual(n_v4, n_v6)
        self.assertEqual(n_v4, 4096)
