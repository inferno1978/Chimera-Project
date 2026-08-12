#!/usr/bin/env python3
"""
tests/test_telemt_syn_limiter.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/telemt_syn_limiter.py.

Покрывает:
  1. _plain / _wlen — unicode helpers
  2. SynLimiterConfig — dataclass с дефолтами
  3. _load_state / _save_state — JSON I/O с фильтрацией ключей
  4. _get_telemt_port — чтение порта из TOML
  5. _PRESETS — структура пресетов
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


class TestPlain(unittest.TestCase):
    """_plain — strip ANSI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_plain_string_unchanged(self):
        from chimera.modules.telemt_syn_limiter import _plain
        self.assertEqual(_plain("hello"), "hello")

    def test_strips_ansi(self):
        from chimera.modules.telemt_syn_limiter import _plain
        self.assertEqual(_plain("\033[1;31mhi\033[0m"), "hi")


class TestWlen(unittest.TestCase):
    """_wlen — display width."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ascii(self):
        from chimera.modules.telemt_syn_limiter import _wlen
        self.assertEqual(_wlen("hello"), 5)

    def test_cjk_two_columns(self):
        from chimera.modules.telemt_syn_limiter import _wlen
        self.assertEqual(_wlen("中文"), 4)

    def test_emoji_two_columns(self):
        from chimera.modules.telemt_syn_limiter import _wlen
        self.assertEqual(_wlen("🛡️"), 2)  # shield + VS16

    def test_ansi_zero_width(self):
        from chimera.modules.telemt_syn_limiter import _wlen
        self.assertEqual(_wlen("\033[1mhi\033[0m"), 2)


class TestSynLimiterConfig(unittest.TestCase):
    """SynLimiterConfig — dataclass."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_defaults(self):
        from chimera.modules.telemt_syn_limiter import SynLimiterConfig
        cfg = SynLimiterConfig()
        self.assertFalse(cfg.enabled)
        self.assertEqual(cfg.port, 0)
        self.assertEqual(cfg.rate_per_sec, 1)
        self.assertEqual(cfg.burst, 1)
        self.assertEqual(cfg.htable_expire_ms, 60000)
        self.assertEqual(cfg.preset_name, "hard")


class TestLoadSaveState(unittest.TestCase):
    """_load_state / _save_state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "syn_limiter.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.telemt_syn_limiter._STATE_FILE",
                     self._state)

    def test_load_returns_default_when_no_file(self):
        from chimera.modules.telemt_syn_limiter import _load_state
        with self._patch():
            cfg = _load_state()
        self.assertFalse(cfg.enabled)
        self.assertEqual(cfg.preset_name, "hard")

    def test_load_returns_default_on_corrupt(self):
        from chimera.modules.telemt_syn_limiter import _load_state
        self._state.write_text("{invalid")
        with self._patch():
            cfg = _load_state()
        self.assertFalse(cfg.enabled)

    def test_load_filters_unknown_keys(self):
        """Лишние ключи игнорируются."""
        from chimera.modules.telemt_syn_limiter import _load_state
        self._state.write_text(json.dumps({
            "enabled": True, "port": 443, "rate_per_sec": 5,
            "burst": 10, "htable_expire_ms": 30000, "preset_name": "soft",
            "unknown_key": "ignored",
        }))
        with self._patch():
            cfg = _load_state()
        self.assertTrue(cfg.enabled)
        self.assertEqual(cfg.port, 443)
        self.assertEqual(cfg.rate_per_sec, 5)

    def test_save_then_load(self):
        from chimera.modules.telemt_syn_limiter import (
            _load_state, _save_state, SynLimiterConfig,
        )
        cfg = SynLimiterConfig(enabled=True, port=8443, rate_per_sec=10,
                                burst=20, htable_expire_ms=120000,
                                preset_name="medium")
        with self._patch():
            _save_state(cfg)
            loaded = _load_state()
        self.assertTrue(loaded.enabled)
        self.assertEqual(loaded.port, 8443)
        self.assertEqual(loaded.rate_per_sec, 10)


class TestGetTelemtPort(unittest.TestCase):
    """_get_telemt_port — чтение порта из TOML."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "telemt.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.telemt_syn_limiter._CONFIG_FILE",
                     self._cfg)

    def test_returns_zero_when_no_file(self):
        from chimera.modules.telemt_syn_limiter import _get_telemt_port
        with self._patch():
            self.assertEqual(_get_telemt_port(), 0)

    def test_returns_port(self):
        from chimera.modules.telemt_syn_limiter import _get_telemt_port
        self._cfg.write_text('port = 8443\n')
        with self._patch():
            self.assertEqual(_get_telemt_port(), 8443)

    def test_returns_zero_when_no_port(self):
        from chimera.modules.telemt_syn_limiter import _get_telemt_port
        self._cfg.write_text('other = "x"\n')
        with self._patch():
            self.assertEqual(_get_telemt_port(), 0)


class TestPresets(unittest.TestCase):
    """_PRESETS — структура."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_presets(self):
        from chimera.modules.telemt_syn_limiter import _PRESETS
        self.assertGreater(len(_PRESETS), 0)

    def test_each_preset_has_required_fields(self):
        """Структура: (preset_name, rate_per_sec, burst, label, detail, recommended)."""
        from chimera.modules.telemt_syn_limiter import _PRESETS
        for name, preset in _PRESETS.items():
            with self.subTest(preset=name):
                # preset — tuple из 6 элементов
                self.assertIsInstance(preset, tuple)
                self.assertEqual(len(preset), 6)
                # rate_per_sec и burst — положительные int
                self.assertGreater(preset[1], 0)  # rate_per_sec
                self.assertGreater(preset[2], 0)  # burst


# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТЫ МИГРАЦИИ НА NFTABLES (этап 1.4) — мок nft_common
# ══════════════════════════════════════════════════════════════════════════════
class TestNftMigration(unittest.TestCase):
    """Проверяет что telemt_syn_limiter.py использует nft_common вместо прямых
    iptables subprocess-вызовов (этап 1.4 миграции).

    Мокает nft_syn_limiter / nft_rule_exists / nft_rule_delete_by_comment /
    nft_rule_counter_read / _nft_available — проверяет что:
      • _rule_exists проверяет ОБА comment-tag (accept и reject).
      • _remove_rules вызывает nft_rule_delete_by_comment дважды (для accept
        и reject тегов).
      • _apply_rules делегирует в nft_syn_limiter (один вызов, который внутри
        создаёт пару правил accept+reject).
      • _persist_rules вызывает nft_persist (а не netfilter-persistent/iptables-save).
      • _get_accept_counter / _get_drop_counter используют nft_rule_counter_read.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_rule_exists_checks_both_accept_and_reject_tags(self):
        """_rule_exists проверяет ОБА comment-tag (accept и reject)."""
        from chimera.modules import telemt_syn_limiter
        # Если accept-правило найдено → True (даже если reject не найден)
        with patch("chimera.modules.telemt_syn_limiter.nft_rule_exists",
                   side_effect=lambda **kw: kw.get("comment") == "telemt-syn-limit-accept"):
            self.assertTrue(telemt_syn_limiter._rule_exists())
        # Если reject-правило найдено → True (даже если accept не найден)
        with patch("chimera.modules.telemt_syn_limiter.nft_rule_exists",
                   side_effect=lambda **kw: kw.get("comment") == "telemt-syn-limit-reject"):
            self.assertTrue(telemt_syn_limiter._rule_exists())
        # Если ни одного правила нет → False
        with patch("chimera.modules.telemt_syn_limiter.nft_rule_exists",
                   return_value=False):
            self.assertFalse(telemt_syn_limiter._rule_exists())

    def test_remove_rules_deletes_both_tags(self):
        """_remove_rules вызывает nft_rule_delete_by_comment дважды."""
        from chimera.modules import telemt_syn_limiter
        with patch("chimera.modules.telemt_syn_limiter.nft_rule_delete_by_comment",
                   return_value=1) as mock_del:
            removed = telemt_syn_limiter._remove_rules()
        self.assertEqual(mock_del.call_count, 2)
        # Сумма удалённых: 1 (accept) + 1 (reject) = 2
        self.assertEqual(removed, 2)
        # Проверяем что оба тега были переданы
        comments_called = sorted(
            kwargs.get("comment") for _, kwargs in mock_del.call_args_list
        )
        self.assertEqual(comments_called,
                         ["telemt-syn-limit-accept", "telemt-syn-limit-reject"])

    def test_apply_rules_calls_nft_syn_limiter(self):
        """_apply_rules делегирует в nft_syn_limiter (один вызов создаёт оба правила)."""
        from chimera.modules import telemt_syn_limiter
        cfg = telemt_syn_limiter.SynLimiterConfig(
            enabled=True, port=8443, rate_per_sec=2, burst=5,
            htable_expire_ms=60000, preset_name="soft",
        )
        with patch("chimera.modules.telemt_syn_limiter.nft_syn_limiter",
                   return_value=True) as mock_lim, \
             patch("chimera.modules.telemt_syn_limiter.nft_rule_delete_by_comment",
                   return_value=0):
            ok, msg = telemt_syn_limiter._apply_rules(cfg)
        self.assertTrue(ok)
        mock_lim.assert_called_once()
        _, kwargs = mock_lim.call_args
        self.assertEqual(kwargs.get("port"), 8443)
        self.assertEqual(kwargs.get("rate_per_sec"), 2)
        self.assertEqual(kwargs.get("burst"), 5)
        self.assertEqual(kwargs.get("comment"), "telemt-syn-limit")
        # idempotent=False т.к. cleanup уже сделан выше
        self.assertFalse(kwargs.get("idempotent"))

    def test_apply_rules_returns_false_on_nft_failure(self):
        """Если nft_syn_limiter возвращает False → _apply_rules тоже False."""
        from chimera.modules import telemt_syn_limiter
        cfg = telemt_syn_limiter.SynLimiterConfig(
            enabled=True, port=8443, rate_per_sec=1, burst=1,
            htable_expire_ms=60000, preset_name="hard",
        )
        with patch("chimera.modules.telemt_syn_limiter.nft_syn_limiter",
                   return_value=False), \
             patch("chimera.modules.telemt_syn_limiter.nft_rule_delete_by_comment",
                   return_value=0):
            ok, msg = telemt_syn_limiter._apply_rules(cfg)
        self.assertFalse(ok)
        self.assertIn("Ошибка", msg)

    def test_apply_rules_returns_false_when_port_zero(self):
        """port=0 → нельзя применять правила (порт неизвестен)."""
        from chimera.modules import telemt_syn_limiter
        cfg = telemt_syn_limiter.SynLimiterConfig(
            enabled=True, port=0, rate_per_sec=1, burst=1,
        )
        with patch("chimera.modules.telemt_syn_limiter.nft_syn_limiter") as mock_lim:
            ok, msg = telemt_syn_limiter._apply_rules(cfg)
        self.assertFalse(ok)
        mock_lim.assert_not_called()  # не дошли до вызова nft

    def test_persist_rules_uses_nft_persist(self):
        """_persist_rules вызывает nft_persist (а не netfilter-persistent/iptables-save)."""
        from chimera.modules import telemt_syn_limiter
        with patch("chimera.modules.telemt_syn_limiter._nft_available",
                   return_value=True), \
             patch("chimera.modules.telemt_syn_limiter.nft_persist",
                   return_value=True) as mock_persist, \
             patch("chimera.modules.nft_common.nft_persist_enable_systemd",
                   return_value=True):
            telemt_syn_limiter._persist_rules()
        mock_persist.assert_called_once()

    def test_persist_rules_skipped_when_nft_unavailable(self):
        """Если nft недоступен — _persist_rules ничего не делает."""
        from chimera.modules import telemt_syn_limiter
        with patch("chimera.modules.telemt_syn_limiter._nft_available",
                   return_value=False), \
             patch("chimera.modules.telemt_syn_limiter.nft_persist") as mock_persist:
            telemt_syn_limiter._persist_rules()
        mock_persist.assert_not_called()

    def test_get_accept_counter_uses_nft_counter_read(self):
        """_get_accept_counter делегирует в nft_rule_counter_read с accept tag."""
        from chimera.modules import telemt_syn_limiter
        with patch("chimera.modules.telemt_syn_limiter.nft_rule_counter_read",
                   return_value={"packets": 42, "bytes": 4096}) as mock_cnt:
            pkts, byts = telemt_syn_limiter._get_accept_counter(8443)
        self.assertEqual(pkts, 42)
        self.assertEqual(byts, 4096)
        mock_cnt.assert_called_once()
        _, kwargs = mock_cnt.call_args
        self.assertEqual(kwargs.get("comment"), "telemt-syn-limit-accept")
        self.assertEqual(kwargs.get("chain"), "input")

    def test_get_drop_counter_uses_nft_counter_read(self):
        """_get_drop_counter делегирует в nft_rule_counter_read с reject tag."""
        from chimera.modules import telemt_syn_limiter
        with patch("chimera.modules.telemt_syn_limiter.nft_rule_counter_read",
                   return_value={"packets": 10, "bytes": 600}) as mock_cnt:
            pkts, byts = telemt_syn_limiter._get_drop_counter(8443)
        self.assertEqual(pkts, 10)
        self.assertEqual(byts, 600)
        _, kwargs = mock_cnt.call_args
        self.assertEqual(kwargs.get("comment"), "telemt-syn-limit-reject")

    def test_status_reflects_nft_rule_existence(self):
        """status() возвращает enabled=True только если правила есть в nftables."""
        from chimera.modules import telemt_syn_limiter
        # Сохраним state и подменяем nft_rule_exists
        import tempfile
        tmpdir = Path(tempfile.mkdtemp())
        state_file = tmpdir / "syn.json"
        state_file.write_text(json.dumps({
            "enabled": True, "port": 8443, "rate_per_sec": 1, "burst": 1,
            "htable_expire_ms": 60000, "preset_name": "hard",
        }))
        try:
            with patch("chimera.modules.telemt_syn_limiter._STATE_FILE", state_file), \
                 patch("chimera.modules.telemt_syn_limiter.nft_rule_exists",
                       return_value=True):
                st = telemt_syn_limiter.status()
            self.assertTrue(st["enabled"])
            self.assertEqual(st["port"], 8443)
            # configured_but_inactive=False (правила есть)
            self.assertFalse(st["configured_but_inactive"])
            with patch("chimera.modules.telemt_syn_limiter._STATE_FILE", state_file), \
                 patch("chimera.modules.telemt_syn_limiter.nft_rule_exists",
                       return_value=False):
                st = telemt_syn_limiter.status()
            # enabled=False (правил нет), configured_but_inactive=True
            self.assertFalse(st["enabled"])
            self.assertTrue(st["configured_but_inactive"])
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
