#!/usr/bin/env python3
"""
tests/test_mieru_traffic_presets.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/mieru_traffic_presets.py.

Покрывает:
  1. Эталонные base64-векторы: ЖИВОЙ `mita export traffic-pattern`
     (прод-нода 45.151.182.204, 02.10.2026) + реальный mieru proto
  2. Структура пресетов (= конфиги server.json mita, единый источник)
  3. Семантика proto3-без-presence: false/0/отсутствующее НЕ пишется
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
    """Эталонные base64-векторы: живой `mita export traffic-pattern`
    (прод-нода 45.151.182.204, 02.10.2026) + base.proto mieru
    (github.com/enfein/mieru/pkg/appctl/proto/base.proto).

    Семантика сериализации (сверена с mita export, байт-в-байт):
      - поле false/0/отсутствующее в JSON → НЕ сериализуется
        (proto3 без presence: mita export для aggressive не содержит
        ни unlockAll, ни applyToAllUDPPacket, ни seed);
      - вложенный message без живых полей → опускается целиком;
      - порядок полей — по номеру (совпадает с mita export).

    Эти векторы вычислены НЕ нашим кодом — они проверяют корректность
    protobuf-сериализатора против реального mieru.
    """

    def setUp(self):
        _setup_core()

    def test_aggressive_matches_live_mita_export(self):
        """ЭТАЛОН (живая нода, 02.10.2026): aggressive →
        GgQIARAUIgIIASoFCEAQgAE= байт-в-байт.

        `mita export traffic-pattern` на 45.151.182.204 для конфига
        aggressive: tcpFragment{enable,maxSleepMs=20} +
        nonce{PRINTABLE} + padding{64,128}:
          1a 04 08 01 10 14   tcpFragment {enable=1, maxSleepMs=20}
          22 02 08 01         nonce {type=PRINTABLE(1)}
          2a 05 08 40 10 80 01  padding {maxMiddle=64, maxEnd=128}
        Ни unlockAll (1000/1001), ни seed — их нет в серверном JSON,
        proto3-без-presence их НЕ пишет.
        """
        from chimera.modules.mieru_traffic_presets import get_preset_base64
        self.assertEqual(get_preset_base64("aggressive"),
                         "GgQIARAUIgIIASoFCEAQgAE=")

    def test_basic_preset_matches_known_vector(self):
        """basic = nonce{PRINTABLE} → 22 02 08 01 (base64 IgIIAQ==).

        Живой вектор mita export для {"type":"NONCE_TYPE_PRINTABLE"}
        → байты 22 02 08 01 (поле 4 nonce, type=1 PRINTABLE —
        подтверждено на прод-ноде 02.10.2026).
        """
        from chimera.modules.mieru_traffic_presets import get_preset_base64
        result = get_preset_base64("basic")
        self.assertEqual(result, "IgIIAQ==")
        raw = base64.b64decode(result)
        # nonce (field 4, tag 22) + type=PRINTABLE (08 01)
        self.assertIn(b"\x22\x02\x08\x01", raw,
                      f"nonce{{PRINTABLE}} not found in basic preset, raw: {raw.hex()}")

    def test_unlock_all_false_not_serialized(self):
        """unlockAll=False НЕ сериализуется (proto3 без presence).

        mita export не пишет поле, когда серверный JSON его не задал
        или задал false — раньше кодировалось 1000 (старая семантика
        «явное presence», разошедшаяся с живым mita).
        """
        from chimera.modules.mieru_traffic_presets import encode_traffic_pattern
        raw = base64.b64decode(encode_traffic_pattern(
            {"nonce": {"type": "NONCE_TYPE_PRINTABLE"}, "unlockAll": False}))
        self.assertNotIn(b"\x10\x00", raw,
                         "unlockAll=false must NOT be serialized as 1000")
        self.assertNotIn(b"\x10\x01", raw)

    def test_unlock_all_true_is_serialized(self):
        """unlockAll=True сериализуется как 1001 — единственное значение
        поля 2, которое mita export реально пишет."""
        from chimera.modules.mieru_traffic_presets import encode_traffic_pattern
        raw = base64.b64decode(encode_traffic_pattern({"unlockAll": True}))
        self.assertIn(b"\x10\x01", raw,
                      "unlockAll=true must be serialized as 1001")

    def test_disabled_preset_returns_empty(self):
        """disabled (config=None → trafficPattern нет) → '' — параметр/
        поле в клиентскую выдачу не добавляется вовсе."""
        from chimera.modules.mieru_traffic_presets import (
            encode_traffic_pattern, get_preset_base64)
        self.assertEqual(get_preset_base64("disabled"), "")
        self.assertEqual(encode_traffic_pattern(None), "")

    def test_empty_traffic_pattern_is_valid_base64(self):
        """disabled → '' (пустой паттерн); остальные — непустой валидный
        base64 (декодируется без исключения)."""
        from chimera.modules.mieru_traffic_presets import get_preset_base64
        result = get_preset_base64("disabled")
        self.assertEqual(result, "")
        for name in ("basic", "medium", "aggressive"):
            raw = base64.b64decode(get_preset_base64(name))
            self.assertIsInstance(raw, bytes)
            self.assertGreater(len(raw), 0)

    def test_all_presets_produce_valid_base64(self):
        """Все 4 пресета: disabled → '', остальные — валидный base64."""
        from chimera.modules.mieru_traffic_presets import get_preset_base64
        for name in ("disabled", "basic", "medium", "aggressive"):
            with self.subTest(preset=name):
                result = get_preset_base64(name)
                raw = base64.b64decode(result)
                self.assertIsInstance(raw, bytes)
                if name == "disabled":
                    self.assertEqual(result, "")
                else:
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
