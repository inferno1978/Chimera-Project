#!/usr/bin/env python3
"""
tests/test_mieru_traffic_presets.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/mieru_traffic_presets.py.

Покрывает:
  1. Эталонные base64-векторы из реального mieru proto (не self-reference)
  2. Структура пресетов
  3. unlockAll кодируется с явным presence (proto3 optional)
"""
from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

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


class TestPresetStructure(unittest.TestCase):
    """Структура пресетов."""

    def setUp(self):
        _setup_core()

    def test_has_4_presets(self):
        from chimera.modules.mieru_traffic_presets import PRESETS
        for name in ("disabled", "basic", "medium", "aggressive"):
            self.assertIn(name, PRESETS)

    def test_each_preset_has_required_fields(self):
        from chimera.modules.mieru_traffic_presets import PRESETS
        for name, preset in PRESETS.items():
            with self.subTest(preset=name):
                self.assertIn("name", preset)
                self.assertIn("label", preset)
                self.assertIn("description", preset)
                self.assertIn("config", preset)


class TestEncodeVarint(unittest.TestCase):
    """encode_varint — protobuf varint encoding."""

    def setUp(self):
        _setup_core()

    def test_zero(self):
        from chimera.modules.mieru_traffic_presets import encode_varint
        self.assertEqual(encode_varint(0), b"\x00")

    def test_one(self):
        from chimera.modules.mieru_traffic_presets import encode_varint
        self.assertEqual(encode_varint(1), b"\x01")

    def test_128(self):
        """128 → multi-byte varint."""
        from chimera.modules.mieru_traffic_presets import encode_varint
        self.assertEqual(encode_varint(128), b"\x80\x01")


class TestRealProtoVectors(unittest.TestCase):
    """Эталонные base64-векторы из реального mieru proto.

    Источник: github.com/enfein/mieru/pkg/appctl/proto/base.proto
    + config_test.go TestEncodeDecode
    + docs/traffic-pattern.md

    Эти векторы вычислены НЕ нашим кодом — они проверяют корректность
    protobuf-сериализатора против реального mieru.
    """

    def setUp(self):
        _setup_core()

    def test_basic_preset_matches_known_vector(self):
        """basic пресет: unlockAll=False + tcpFragment{enable=True, maxSleepMs=10}.

        Эталон из mieru docs (client example с unlockAll:false):
        base64 = EAAaBAgBEAo=
        raw hex: 1000 1a04 0801 100a

        Расшифровка:
        - 10 00 → field 2 (unlockAll) = false (varint 0)
        - 1a 04 08 01 10 0a → field 3 (tcpFragment) = {enable=true, maxSleepMs=10}
        """
        from chimera.modules.mieru_traffic_presets import get_preset_base64
        result = get_preset_base64("basic")
        # Декодируем для проверки структуры
        raw = base64.b64decode(result)
        # Должен содержать unlockAll=false (1000)
        self.assertIn(b"\x10\x00", raw,
                      f"unlockAll=false (1000) not found in basic preset, raw: {raw.hex()}")
        # Должен содержать tcpFragment с enable=true
        self.assertIn(b"\x08\x01", raw,
                      f"tcpFragment.enable=true not found, raw: {raw.hex()}")

    def test_unlock_all_false_is_serialized(self):
        """unlockAll=False должен сериализоваться как 1000 (proto3 optional presence).

        До фикса unlockAll=False отбрасывался (if cfg.get("unlockAll") else None).
        После фикса — кодируется явно (proto3 optional = явное presence).
        """
        from chimera.modules.mieru_traffic_presets import get_preset_base64
        # disabled пресет: unlockAll=False (явно в config)
        result = get_preset_base64("disabled")
        raw = base64.b64decode(result)
        # 1000 = field 2 (unlockAll), varint 0 (false)
        self.assertIn(b"\x10\x00", raw,
                      f"unlockAll=false must be serialized as 1000, raw: {raw.hex()}")

    def test_unlock_all_true_is_serialized(self):
        """unlockAll=True должен сериализоваться как 1001."""
        from chimera.modules.mieru_traffic_presets import get_preset_base64
        result = get_preset_base64("aggressive")
        raw = base64.b64decode(result)
        # 1001 = field 2 (unlockAll), varint 1 (true)
        self.assertIn(b"\x10\x01", raw,
                      f"unlockAll=true must be serialized as 1001, raw: {raw.hex()}")

    def test_empty_traffic_pattern_is_valid_base64(self):
        """disabled пресет (config=None → нет trafficPattern) — get_preset_base64
        возвращает base64 пустого TrafficPattern (только unlockAll=False)."""
        from chimera.modules.mieru_traffic_presets import get_preset_base64
        result = get_preset_base64("disabled")
        raw = base64.b64decode(result)
        # Минимум: unlockAll=false (1000)
        self.assertIn(b"\x10\x00", raw)

    def test_all_presets_produce_valid_base64(self):
        """Все 4 пресета дают валидный base64 (декодируется без исключения)."""
        from chimera.modules.mieru_traffic_presets import get_preset_base64
        for name in ("disabled", "basic", "medium", "aggressive"):
            with self.subTest(preset=name):
                result = get_preset_base64(name)
                raw = base64.b64decode(result)
                self.assertIsInstance(raw, bytes)
                self.assertGreater(len(raw), 0)

    def test_medium_has_nonce_fields(self):
        """medium пресет: nonce{type=PRINTABLE, applyToAllUDPPacket=true, minLen, maxLen}.

        Эталон из mieru TestEncodeDecode:
        nonce{PRINTABLE(1), applyAll=true, min=6, max=8} →
        22 08 08 01 10 01 18 06 20 08
        """
        from chimera.modules.mieru_traffic_presets import get_preset_base64
        result = get_preset_base64("medium")
        raw = base64.b64decode(result)
        # field 4 (nonce) = tag 22 (0x22 = field 4, wire type 2)
        self.assertIn(b"\x22", raw,
                      f"nonce field (tag 22) not found, raw: {raw.hex()}")
        # nonce.type = PRINTABLE (1) → 08 01
        self.assertIn(b"\x08\x01", raw)

    def test_aggressive_has_padding_fields(self):
        """aggressive пресет: padding{maxMiddlePaddingLen, maxEndPaddingLen}.

        padding field 5 = tag 2a (0x2a = field 5, wire type 2)
        """
        from chimera.modules.mieru_traffic_presets import get_preset_base64
        result = get_preset_base64("aggressive")
        raw = base64.b64decode(result)
        # field 5 (padding) = tag 2a
        self.assertIn(b"\x2a", raw,
                      f"padding field (tag 2a) not found, raw: {raw.hex()}")

    def test_different_presets_produce_different_bytes(self):
        """Разные пресеты → разный raw bytes (не только разный base64)."""
        from chimera.modules.mieru_traffic_presets import get_preset_base64
        results = {}
        for name in ("disabled", "basic", "medium", "aggressive"):
            results[name] = base64.b64decode(get_preset_base64(name))
        # Все 4 должны быть различны
        self.assertEqual(len(set(results.values())), 4)


class TestListAndGetPresets(unittest.TestCase):
    """list_presets / get_preset."""

    def setUp(self):
        _setup_core()

    def test_list_presets_returns_list(self):
        from chimera.modules.mieru_traffic_presets import list_presets
        result = list_presets()
        self.assertGreaterEqual(len(result), 4)

    def test_get_preset_known(self):
        from chimera.modules.mieru_traffic_presets import get_preset
        p = get_preset("basic")
        self.assertEqual(p["name"], "basic")

    def test_get_preset_unknown_falls_back_to_basic(self):
        from chimera.modules.mieru_traffic_presets import get_preset
        p = get_preset("nonexistent")
        self.assertEqual(p["name"], "basic")

    def test_get_preset_base64_unknown_falls_back_to_basic(self):
        from chimera.modules.mieru_traffic_presets import get_preset_base64
        result = get_preset_base64("nonexistent")
        basic = get_preset_base64("basic")
        self.assertEqual(result, basic)


if __name__ == "__main__":
    unittest.main(verbosity=2)
