#!/usr/bin/env python3
"""
tests/test_telemt_fallback.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/telemt_fallback.py.

Покрывает:
  1. FallbackConfig — dataclass с дефолтами и клемпингом
  2. read_fallback_config — парсинг TOML-секции
  3. read_runtime_middle_proxy — чтение use_middle_proxy
  4. append_fallback_section — запись секции в файл
  5. _patch_config_middle_proxy — патч telemt.toml
  6. MiddleProxyProbe — проверка доступности ME (mocked socket)
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

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


class TestFallbackConfig(unittest.TestCase):
    """FallbackConfig — dataclass."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_defaults(self):
        from vless_installer.modules.telemt_fallback import FallbackConfig
        cfg = FallbackConfig.defaults()
        self.assertTrue(cfg.fallback_to_direct)
        self.assertEqual(cfg.fallback_after_attempts, 3)
        self.assertEqual(cfg.fallback_after_seconds, 45)
        self.assertFalse(cfg.auto_revert_to_middle)

    def test_clamps_attempts_to_min_1(self):
        from vless_installer.modules.telemt_fallback import FallbackConfig
        cfg = FallbackConfig(fallback_after_attempts=0)
        self.assertEqual(cfg.fallback_after_attempts, 1)

    def test_clamps_attempts_to_max_20(self):
        from vless_installer.modules.telemt_fallback import FallbackConfig
        cfg = FallbackConfig(fallback_after_attempts=21)
        self.assertEqual(cfg.fallback_after_attempts, 20)

    def test_clamps_seconds_to_min_10(self):
        from vless_installer.modules.telemt_fallback import FallbackConfig
        cfg = FallbackConfig(fallback_after_seconds=5)
        self.assertEqual(cfg.fallback_after_seconds, 10)

    def test_clamps_seconds_to_max_300(self):
        from vless_installer.modules.telemt_fallback import FallbackConfig
        cfg = FallbackConfig(fallback_after_seconds=301)
        self.assertEqual(cfg.fallback_after_seconds, 300)

    def test_to_toml_section(self):
        from vless_installer.modules.telemt_fallback import FallbackConfig
        cfg = FallbackConfig.defaults()
        toml = cfg.to_toml_section()
        self.assertIn("[middle_proxy]", toml)
        self.assertIn("fallback_to_direct", toml)
        self.assertIn("fallback_after_attempts", toml)


class TestReadFallbackConfig(unittest.TestCase):
    """read_fallback_config — парсинг TOML."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._fb = self._tmpdir / "fallback.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_defaults_when_no_file(self):
        from vless_installer.modules.telemt_fallback import (
            read_fallback_config, FallbackConfig,
        )
        cfg = read_fallback_config(self._fb)
        self.assertTrue(cfg.fallback_to_direct)

    def test_parses_section(self):
        from vless_installer.modules.telemt_fallback import read_fallback_config
        self._fb.write_text(
            "[middle_proxy]\n"
            "fallback_to_direct = false\n"
            "fallback_after_attempts = 5\n"
            "fallback_after_seconds = 60\n"
        )
        cfg = read_fallback_config(self._fb)
        self.assertFalse(cfg.fallback_to_direct)
        self.assertEqual(cfg.fallback_after_attempts, 5)
        self.assertEqual(cfg.fallback_after_seconds, 60)

    def test_never_raises(self):
        """Функция никогда не бросает исключений."""
        from vless_installer.modules.telemt_fallback import read_fallback_config
        self._fb.write_text("garbage {{{\n")
        cfg = read_fallback_config(self._fb)
        self.assertIsInstance(cfg.fallback_after_attempts, int)


class TestReadRuntimeMiddleProxy(unittest.TestCase):
    """read_runtime_middle_proxy — чтение use_middle_proxy."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "telemt.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_none_when_no_file(self):
        from vless_installer.modules.telemt_fallback import read_runtime_middle_proxy
        self.assertIsNone(read_runtime_middle_proxy(self._cfg))

    def test_returns_true(self):
        from vless_installer.modules.telemt_fallback import read_runtime_middle_proxy
        self._cfg.write_text("[general]\nuse_middle_proxy = true\n")
        result = read_runtime_middle_proxy(self._cfg)
        self.assertTrue(result)

    def test_returns_false(self):
        from vless_installer.modules.telemt_fallback import read_runtime_middle_proxy
        self._cfg.write_text("[general]\nuse_middle_proxy = false\n")
        result = read_runtime_middle_proxy(self._cfg)
        self.assertFalse(result)

    def test_returns_none_when_no_key(self):
        from vless_installer.modules.telemt_fallback import read_runtime_middle_proxy
        self._cfg.write_text("[general]\nport = 443\n")
        self.assertIsNone(read_runtime_middle_proxy(self._cfg))


class TestAppendFallbackSection(unittest.TestCase):
    """append_fallback_section — запись секции."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._fb = self._tmpdir / "fallback.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_creates_file_when_missing(self):
        from vless_installer.modules.telemt_fallback import (
            append_fallback_section, FallbackConfig, read_fallback_config,
        )
        cfg = FallbackConfig.defaults()
        append_fallback_section(cfg, self._fb)
        self.assertTrue(self._fb.exists())
        loaded = read_fallback_config(self._fb)
        self.assertTrue(loaded.fallback_to_direct)

    def test_replaces_existing_section(self):
        from vless_installer.modules.telemt_fallback import (
            append_fallback_section, FallbackConfig, read_fallback_config,
        )
        # записываем старую секцию
        old_cfg = FallbackConfig(fallback_after_attempts=5)
        append_fallback_section(old_cfg, self._fb)
        # перезаписываем новой
        new_cfg = FallbackConfig(fallback_after_attempts=10)
        append_fallback_section(new_cfg, self._fb)
        loaded = read_fallback_config(self._fb)
        self.assertEqual(loaded.fallback_after_attempts, 10)


class TestPatchConfigMiddleProxy(unittest.TestCase):
    """_patch_config_middle_proxy — патч telemt.toml."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "telemt.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_enables_middle_proxy(self):
        from vless_installer.modules.telemt_fallback import _patch_config_middle_proxy
        self._cfg.write_text("[general]\nuse_middle_proxy = false\n")
        _patch_config_middle_proxy(self._cfg, enable=True)
        content = self._cfg.read_text()
        self.assertIn("use_middle_proxy = true", content)

    def test_disables_middle_proxy(self):
        from vless_installer.modules.telemt_fallback import _patch_config_middle_proxy
        self._cfg.write_text("[general]\nuse_middle_proxy = true\n")
        _patch_config_middle_proxy(self._cfg, enable=False)
        content = self._cfg.read_text()
        self.assertIn("use_middle_proxy = false", content)


class TestMiddleProxyProbe(unittest.TestCase):
    """MiddleProxyProbe — проверка доступности ME."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_probe_one_success(self):
        from vless_installer.modules.telemt_fallback import MiddleProxyProbe
        probe = MiddleProxyProbe(endpoints=[("1.1.1.1", 443)])
        with patch("socket.create_connection"):
            self.assertTrue(probe.probe_one("1.1.1.1", 443))

    def test_probe_one_failure(self):
        from vless_installer.modules.telemt_fallback import MiddleProxyProbe
        probe = MiddleProxyProbe(endpoints=[("1.1.1.1", 443)])
        with patch("socket.create_connection", side_effect=OSError("conn refused")):
            self.assertFalse(probe.probe_one("1.1.1.1", 443))

    def test_is_available_when_quorum_met(self):
        from vless_installer.modules.telemt_fallback import MiddleProxyProbe
        probe = MiddleProxyProbe(endpoints=[("h1", 1), ("h2", 2), ("h3", 3)])
        with patch.object(probe, "probe_all", return_value=(3, 3)):
            self.assertTrue(probe.is_available())

    def test_is_unavailable_when_quorum_not_met(self):
        from vless_installer.modules.telemt_fallback import MiddleProxyProbe
        probe = MiddleProxyProbe(endpoints=[("h1", 1), ("h2", 2), ("h3", 3)])
        with patch.object(probe, "probe_all", return_value=(0, 3)):
            self.assertFalse(probe.is_available())


if __name__ == "__main__":
    unittest.main(verbosity=2)
