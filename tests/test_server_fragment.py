#!/usr/bin/env python3
"""
tests/test_server_fragment.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/server_fragment.py.

Покрывает:
  1. _PRESETS — структура пресетов
  2. _find_reality_inbound / _find_xhttp_inbound — поиск inbound
  3. server_fragment_enable — патч config.json (REALITY)
  4. server_fragment_enable — отказ в xHTTP-режиме
  5. server_fragment_disable — снятие fragment
  6. server_fragment_status — структура dict
  7. server_fragment_reapply_after_rebuild — хук
  8. Идемпотентность (повторный enable не дублирует fragment)
  9. Валидация custom-параметров
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch, MagicMock


def _enter_patches(stack, patches):
    """Применяет список patch-объектов через ExitStack (надёжно в любой версии Python)."""
    for p in patches:
        stack.enter_context(p)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    """Загружает _core.py в sys.modules (модуль server_fragment его не
    использует напрямую, но box_renderer может требовать)."""
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


# ─────────────────────────────────────────────────────────────────────────────
# Фикстуры: тестовые config.json
# ─────────────────────────────────────────────────────────────────────────────

_REALITY_CONFIG = {
    "inbounds": [
        {
            "tag": "vless-reality",
            "protocol": "vless",
            "port": 443,
            "settings": {
                "clients": [{"id": "test-uuid", "flow": "xtls-rprx-vision"}],
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": "www.cloudflare.com:443",
                    "serverNames": ["www.cloudflare.com"],
                    "privateKey": "privkey",
                    "publicKey": "pubkey",
                    "shortIds": ["abc123"],
                },
            },
        },
    ],
    "outbounds": [
        {"tag": "direct", "protocol": "freedom"},
    ],
    "routing": {"rules": []},
}

_XHTTP_CONFIG = {
    "inbounds": [
        {
            "tag": "vless-xhttp",
            "protocol": "vless",
            "port": 443,
            "settings": {
                "clients": [{"id": "test-uuid"}],
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [{"certificateFile": "/etc/xray/cert.pem"}],
                },
                "xhttpSettings": {
                    "path": "/xhttp",
                    "mode": "stream-up",
                },
            },
        },
    ],
    "outbounds": [{"tag": "direct", "protocol": "freedom"}],
}


def _reality_with_fragment():
    """Возвращает копию _REALITY_CONFIG с уже добавленным fragment."""
    cfg = json.loads(json.dumps(_REALITY_CONFIG))
    cfg["inbounds"][0]["streamSettings"]["sockopt"] = {
        "tcpFastOpen": True,
        "fragment": {
            "packets": "1-3",
            "length": "3-7",
            "interval": "10-20",
        },
    }
    return cfg


# ─────────────────────────────────────────────────────────────────────────────
# 1. Пресеты
# ─────────────────────────────────────────────────────────────────────────────

class TestPresets(unittest.TestCase):
    """_PRESETS — структура."""

    def setUp(self):
        _setup_core()

    def test_has_required_presets(self):
        from chimera.modules.server_fragment import _PRESETS
        for key in ("aggressive", "balanced", "light", "custom"):
            self.assertIn(key, _PRESETS)

    def test_each_preset_has_required_fields(self):
        from chimera.modules.server_fragment import _PRESETS
        for name, p in _PRESETS.items():
            self.assertIn("packets", p, f"{name} missing packets")
            self.assertIn("length", p, f"{name} missing length")
            self.assertIn("interval", p, f"{name} missing interval")
            self.assertIn("desc", p, f"{name} missing desc")

    def test_non_custom_presets_have_nonempty_values(self):
        from chimera.modules.server_fragment import _PRESETS
        for name in ("aggressive", "balanced", "light"):
            p = _PRESETS[name]
            self.assertTrue(p["packets"], f"{name} packets empty")
            self.assertTrue(p["length"], f"{name} length empty")
            self.assertTrue(p["interval"], f"{name} interval empty")

    def test_custom_preset_has_empty_values(self):
        from chimera.modules.server_fragment import _PRESETS
        p = _PRESETS["custom"]
        self.assertEqual(p["packets"], "")
        self.assertEqual(p["length"], "")
        self.assertEqual(p["interval"], "")


# ─────────────────────────────────────────────────────────────────────────────
# 2. Поиск inbound
# ─────────────────────────────────────────────────────────────────────────────

class TestFindInbounds(unittest.TestCase):
    """_find_reality_inbound / _find_xhttp_inbound."""

    def setUp(self):
        _setup_core()

    def test_find_reality_returns_inbound(self):
        from chimera.modules.server_fragment import _find_reality_inbound
        inb = _find_reality_inbound(_REALITY_CONFIG)
        self.assertIsNotNone(inb)
        self.assertEqual(inb["protocol"], "vless")

    def test_find_reality_returns_none_for_xhttp(self):
        from chimera.modules.server_fragment import _find_reality_inbound
        inb = _find_reality_inbound(_XHTTP_CONFIG)
        self.assertIsNone(inb)

    def test_find_reality_returns_none_for_empty(self):
        from chimera.modules.server_fragment import _find_reality_inbound
        self.assertIsNone(_find_reality_inbound({}))
        self.assertIsNone(_find_reality_inbound({"inbounds": []}))

    def test_find_xhttp_returns_inbound(self):
        from chimera.modules.server_fragment import _find_xhttp_inbound
        inb = _find_xhttp_inbound(_XHTTP_CONFIG)
        self.assertIsNotNone(inb)
        self.assertEqual(inb["streamSettings"]["network"], "xhttp")

    def test_find_xhttp_returns_none_for_reality(self):
        from chimera.modules.server_fragment import _find_xhttp_inbound
        self.assertIsNone(_find_xhttp_inbound(_REALITY_CONFIG))


# ─────────────────────────────────────────────────────────────────────────────
# 3. server_fragment_enable — REALITY режим
# ─────────────────────────────────────────────────────────────────────────────

class TestEnableReality(unittest.TestCase):
    """server_fragment_enable — патч REALITY inbound."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        self._state_path = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self, cfg=None):
        if cfg is not None:
            self._cfg_path.write_text(json.dumps(cfg))
        return [
            patch("chimera.modules.server_fragment._XRAY_CONFIG",
                  self._cfg_path),
            patch("chimera.modules.server_fragment._STATE_FILE",
                  self._state_path),
            patch("chimera.modules.server_fragment._xray_test_and_restart",
                  return_value=True),
        ]

    def test_enable_adds_fragment_to_reality_inbound(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(_REALITY_CONFIG))
            ok = server_fragment_enable(preset="balanced", restart=True)
        self.assertTrue(ok)

        # _load_xray_config должен патчить путь, поэтому внутри with
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            cfg = _load_xray_config()
        inb = cfg["inbounds"][0]
        frag = inb["streamSettings"]["sockopt"]["fragment"]
        self.assertEqual(frag["packets"], "1-3")
        self.assertEqual(frag["length"], "3-7")
        self.assertEqual(frag["interval"], "10-20")

    def test_enable_aggressive_preset(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(_REALITY_CONFIG))
            server_fragment_enable(preset="aggressive")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            cfg = _load_xray_config()
        frag = cfg["inbounds"][0]["streamSettings"]["sockopt"]["fragment"]
        self.assertEqual(frag["length"], "1-3")
        self.assertEqual(frag["interval"], "5-10")

    def test_enable_custom_preset_with_explicit_values(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(_REALITY_CONFIG))
            ok = server_fragment_enable(
                preset="custom",
                packets="2-4", length="8-16", interval="15-30",
            )
        self.assertTrue(ok)
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            cfg = _load_xray_config()
        frag = cfg["inbounds"][0]["streamSettings"]["sockopt"]["fragment"]
        self.assertEqual(frag["packets"], "2-4")
        self.assertEqual(frag["length"], "8-16")
        self.assertEqual(frag["interval"], "15-30")

    def test_enable_custom_without_values_fails(self):
        from chimera.modules.server_fragment import server_fragment_enable
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(_REALITY_CONFIG))
            ok = server_fragment_enable(preset="custom")
        self.assertFalse(ok)

    def test_enable_unknown_preset_fails(self):
        from chimera.modules.server_fragment import server_fragment_enable
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(_REALITY_CONFIG))
            ok = server_fragment_enable(preset="nonexistent")
        self.assertFalse(ok)

    def test_enable_saves_to_state(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_server_fragment_state,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(_REALITY_CONFIG))
            server_fragment_enable(preset="balanced")
            sf = _load_server_fragment_state()
        self.assertTrue(sf["enabled"])
        self.assertEqual(sf["preset"], "balanced")
        self.assertEqual(sf["packets"], "1-3")
        self.assertIn("last_applied", sf)

    def test_enable_returns_false_when_no_config(self):
        from chimera.modules.server_fragment import server_fragment_enable
        with ExitStack() as stack:
            stack.enter_context(patch("chimera.modules.server_fragment._XRAY_CONFIG",
                                      Path("/tmp/nonexistent_config.json")))
            stack.enter_context(patch("chimera.modules.server_fragment._STATE_FILE",
                                      self._state_path))
            ok = server_fragment_enable(preset="balanced")
        self.assertFalse(ok)

    def test_enable_returns_false_on_xhttp_config(self):
        from chimera.modules.server_fragment import server_fragment_enable
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(_XHTTP_CONFIG))
            ok = server_fragment_enable(preset="balanced")
        self.assertFalse(ok)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Идемпотентность
# ─────────────────────────────────────────────────────────────────────────────

class TestIdempotency(unittest.TestCase):
    """Повторный enable должен обновлять, а не дублировать fragment."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        self._state_path = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self, cfg=None):
        if cfg is not None:
            self._cfg_path.write_text(json.dumps(cfg))
        return [
            patch("chimera.modules.server_fragment._XRAY_CONFIG",
                  self._cfg_path),
            patch("chimera.modules.server_fragment._STATE_FILE",
                  self._state_path),
            patch("chimera.modules.server_fragment._xray_test_and_restart",
                  return_value=True),
        ]

    def test_double_enable_single_fragment_block(self):
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(_REALITY_CONFIG))
            server_fragment_enable(preset="balanced")
            server_fragment_enable(preset="aggressive")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            cfg = _load_xray_config()
        sockopt = cfg["inbounds"][0]["streamSettings"]["sockopt"]
        # Только один fragment-блок
        self.assertEqual(len(sockopt.get("fragment", {}).keys()), 3)
        # Значения из второго вызова
        self.assertEqual(sockopt["fragment"]["length"], "1-3")

    def test_enable_preserves_existing_sockopt_keys(self):
        """Если sockopt уже содержит tcpFastOpen — он не должен потеряться."""
        from chimera.modules.server_fragment import (
            server_fragment_enable, _load_xray_config,
        )
        cfg = json.loads(json.dumps(_REALITY_CONFIG))
        cfg["inbounds"][0]["streamSettings"]["sockopt"] = {
            "tcpFastOpen": True,
            "tcpKeepAliveInterval": 15,
        }
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(cfg))
            server_fragment_enable(preset="balanced")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            out = _load_xray_config()
        sockopt = out["inbounds"][0]["streamSettings"]["sockopt"]
        self.assertTrue(sockopt.get("tcpFastOpen"))
        self.assertEqual(sockopt.get("tcpKeepAliveInterval"), 15)
        self.assertIn("fragment", sockopt)


# ─────────────────────────────────────────────────────────────────────────────
# 5. server_fragment_disable
# ─────────────────────────────────────────────────────────────────────────────

class TestDisable(unittest.TestCase):
    """server_fragment_disable — снятие fragment."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        self._state_path = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self, cfg=None):
        if cfg is not None:
            self._cfg_path.write_text(json.dumps(cfg))
        return [
            patch("chimera.modules.server_fragment._XRAY_CONFIG",
                  self._cfg_path),
            patch("chimera.modules.server_fragment._STATE_FILE",
                  self._state_path),
            patch("chimera.modules.server_fragment._xray_test_and_restart",
                  return_value=True),
        ]

    def test_disable_removes_fragment(self):
        from chimera.modules.server_fragment import (
            server_fragment_disable, _load_xray_config,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(_reality_with_fragment()))
            ok = server_fragment_disable()
        self.assertTrue(ok)
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            cfg = _load_xray_config()
        sockopt = cfg["inbounds"][0]["streamSettings"].get("sockopt", {})
        self.assertNotIn("fragment", sockopt)

    def test_disable_preserves_other_sockopt_keys(self):
        """tcpFastOpen и др. не должны пострадать."""
        from chimera.modules.server_fragment import (
            server_fragment_disable, _load_xray_config,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(_reality_with_fragment()))
            server_fragment_disable()
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            cfg = _load_xray_config()
        sockopt = cfg["inbounds"][0]["streamSettings"]["sockopt"]
        self.assertTrue(sockopt.get("tcpFastOpen"))
        self.assertNotIn("fragment", sockopt)

    def test_disable_updates_state(self):
        from chimera.modules.server_fragment import (
            server_fragment_disable, _load_server_fragment_state,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(_reality_with_fragment()))
            server_fragment_disable()
            sf = _load_server_fragment_state()
        self.assertFalse(sf["enabled"])
        self.assertIn("last_disabled", sf)

    def test_disable_no_op_when_no_fragment(self):
        """Если fragment уже отсутствует — disable всё равно возвращает True."""
        from chimera.modules.server_fragment import server_fragment_disable
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(_REALITY_CONFIG))
            ok = server_fragment_disable()
        self.assertTrue(ok)


# ─────────────────────────────────────────────────────────────────────────────
# 6. server_fragment_status
# ─────────────────────────────────────────────────────────────────────────────

class TestStatus(unittest.TestCase):
    """server_fragment_status — структура dict."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        self._state_path = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self, cfg=None):
        if cfg is not None:
            self._cfg_path.write_text(json.dumps(cfg))
        return [
            patch("chimera.modules.server_fragment._XRAY_CONFIG",
                  self._cfg_path),
            patch("chimera.modules.server_fragment._STATE_FILE",
                  self._state_path),
        ]

    def test_status_returns_dict_with_required_keys(self):
        from chimera.modules.server_fragment import server_fragment_status
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(_REALITY_CONFIG))
            st = server_fragment_status()
        self.assertIsInstance(st, dict)
        for key in ("enabled", "preset", "packets", "length", "interval",
                    "in_config", "inbound_protocol"):
            self.assertIn(key, st, f"missing key: {key}")

    def test_status_disabled_by_default(self):
        from chimera.modules.server_fragment import server_fragment_status
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(_REALITY_CONFIG))
            st = server_fragment_status()
        self.assertFalse(st["enabled"])
        self.assertFalse(st["in_config"])

    def test_status_detects_fragment_in_config(self):
        from chimera.modules.server_fragment import server_fragment_status
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(_reality_with_fragment()))
            st = server_fragment_status()
        self.assertTrue(st["in_config"])
        self.assertEqual(st["inbound_protocol"], "reality")

    def test_status_reports_xhttp_protocol(self):
        from chimera.modules.server_fragment import server_fragment_status
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(_XHTTP_CONFIG))
            st = server_fragment_status()
        self.assertEqual(st["inbound_protocol"], "xhttp")
        self.assertFalse(st["in_config"])

    def test_status_reports_none_when_no_config(self):
        from chimera.modules.server_fragment import server_fragment_status
        with ExitStack() as stack:
            stack.enter_context(patch("chimera.modules.server_fragment._XRAY_CONFIG",
                                      Path("/tmp/nonexistent.json")))
            stack.enter_context(patch("chimera.modules.server_fragment._STATE_FILE",
                                      self._state_path))
            st = server_fragment_status()
        self.assertEqual(st["inbound_protocol"], "none")
        self.assertFalse(st["in_config"])


# ─────────────────────────────────────────────────────────────────────────────
# 7. server_fragment_reapply_after_rebuild — хук
# ─────────────────────────────────────────────────────────────────────────────

class TestReapplyHook(unittest.TestCase):
    """server_fragment_reapply_after_rebuild — хук после пересоздания config."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        self._state_path = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self, cfg=None):
        if cfg is not None:
            self._cfg_path.write_text(json.dumps(cfg))
        return [
            patch("chimera.modules.server_fragment._XRAY_CONFIG",
                  self._cfg_path),
            patch("chimera.modules.server_fragment._STATE_FILE",
                  self._state_path),
            patch("chimera.modules.server_fragment._xray_test_and_restart",
                  return_value=True),
        ]

    def test_noop_when_disabled(self):
        from chimera.modules.server_fragment import (
            server_fragment_reapply_after_rebuild, _load_xray_config,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(_REALITY_CONFIG))
            server_fragment_reapply_after_rebuild()
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            cfg = _load_xray_config()
        sockopt = cfg["inbounds"][0]["streamSettings"].get("sockopt", {})
        self.assertNotIn("fragment", sockopt)

    def test_reapplies_when_enabled(self):
        from chimera.modules.server_fragment import (
            server_fragment_reapply_after_rebuild,
            _save_server_fragment_state, _load_xray_config,
        )
        # В state включён, но config без fragment (имитация после reconfigure)
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(_REALITY_CONFIG))
            _save_server_fragment_state({
                "enabled": True,
                "preset": "balanced",
                "packets": "1-3",
                "length": "3-7",
                "interval": "10-20",
            })
            server_fragment_reapply_after_rebuild()
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            cfg = _load_xray_config()
        sockopt = cfg["inbounds"][0]["streamSettings"].get("sockopt", {})
        self.assertIn("fragment", sockopt)
        self.assertEqual(sockopt["fragment"]["length"], "3-7")


# ─────────────────────────────────────────────────────────────────────────────
# 8. Конфигурация state по умолчанию
# ─────────────────────────────────────────────────────────────────────────────

class TestEnsureState(unittest.TestCase):
    """_ensure_state — создание дефолтной подсекции."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_path = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.server_fragment._STATE_FILE",
                     self._state_path)

    def test_creates_default_when_missing(self):
        from chimera.modules.server_fragment import _ensure_state
        with self._patch():
            sf = _ensure_state()
        self.assertIn("enabled", sf)
        self.assertIn("preset", sf)
        self.assertFalse(sf["enabled"])
        self.assertTrue(self._state_path.exists())

    def test_returns_existing_when_present(self):
        from chimera.modules.server_fragment import _ensure_state
        self._state_path.write_text(json.dumps({
            "server_fragment": {"enabled": True, "preset": "aggressive"}
        }))
        with self._patch():
            sf = _ensure_state()
        self.assertTrue(sf["enabled"])
        self.assertEqual(sf["preset"], "aggressive")


# ─────────────────────────────────────────────────────────────────────────────
# 9. Сохраение/чтение state
# ─────────────────────────────────────────────────────────────────────────────

class TestStateIO(unittest.TestCase):
    """_load_state / _save_state / _load_server_fragment_state / _save_server_fragment_state."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_path = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.server_fragment._STATE_FILE",
                     self._state_path)

    def test_load_returns_empty_when_no_file(self):
        from chimera.modules.server_fragment import _load_state
        with self._patch():
            self.assertEqual(_load_state(), {})

    def test_load_returns_empty_on_corrupt(self):
        from chimera.modules.server_fragment import _load_state
        self._state_path.write_text("{invalid")
        with self._patch():
            self.assertEqual(_load_state(), {})

    def test_save_writes_json(self):
        from chimera.modules.server_fragment import (
            _save_state, _load_state,
        )
        with self._patch():
            _save_state({"server_fragment": {"enabled": True}})
            self.assertEqual(_load_state()["server_fragment"]["enabled"], True)

    def test_save_server_fragment_preserves_other_keys(self):
        """Серверный fragment не должен стирать uuid/domain/etc."""
        from chimera.modules.server_fragment import (
            _save_server_fragment_state, _load_state,
        )
        self._state_path.write_text(json.dumps({
            "uuid": "test-uuid",
            "domain": "example.com",
        }))
        with self._patch():
            _save_server_fragment_state({"enabled": True})
            full = _load_state()
        self.assertEqual(full["uuid"], "test-uuid")
        self.assertEqual(full["domain"], "example.com")
        self.assertTrue(full["server_fragment"]["enabled"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
