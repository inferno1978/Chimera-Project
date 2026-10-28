#!/usr/bin/env python3
"""
tests/test_fragment_presets.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/fragment_presets.py.

Покрывает:
  1. PRESET_MATRIX — структура 9 пресетов
  2. _GROUP_LABELS — метки групп
  3. generate_all_presets — генерация всех (mocked state)
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


class TestPresetMatrix(unittest.TestCase):
    """PRESET_MATRIX — структура."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_11_presets(self):
        from chimera.modules.fragment_presets import PRESET_MATRIX
        self.assertEqual(len(PRESET_MATRIX), 11)

    def test_frag_04b_tlshello_preset_values(self):
        """Пресет frag_04b (рецепт DPI/CHECKER окт-2026): packets=tlshello,
        length=10-20, interval=10-20 — цифры пастбина tuv9BiG7."""
        from chimera.modules.fragment_presets import PRESET_MATRIX
        p = next((x for x in PRESET_MATRIX if x["label"] == "frag_04b_medium_tlshello"), None)
        self.assertIsNotNone(p)
        self.assertEqual(p["packets"], "tlshello")
        self.assertEqual(p["length"], "10-20")
        self.assertEqual(p["interval"], "10-20")
        self.assertEqual(p["group"], "medium")

    def test_frag_09_noise_preset_values(self):
        """Комбо-пресет fragment+noise одной генерацией (группа combo)."""
        from chimera.modules.fragment_presets import PRESET_MATRIX
        p = next((x for x in PRESET_MATRIX if x["label"] == "frag_09_noise_std"), None)
        self.assertIsNotNone(p)
        self.assertEqual(p["group"], "combo")
        self.assertEqual(p["packets"], "1-3")
        self.assertEqual(p["length"], "10-20")
        self.assertEqual(p["interval"], "10-20")
        self.assertEqual(p["noise_packet"], "10-20")
        self.assertEqual(p["noise_delay"], "5-10")

    def test_each_preset_has_required_keys(self):
        from chimera.modules.fragment_presets import PRESET_MATRIX
        required = {"label", "group", "packets", "length", "interval", "name", "hint"}
        for p in PRESET_MATRIX:
            with self.subTest(label=p.get("label")):
                for key in required:
                    self.assertIn(key, p)

    def test_labels_unique(self):
        from chimera.modules.fragment_presets import PRESET_MATRIX
        labels = [p["label"] for p in PRESET_MATRIX]
        self.assertEqual(len(labels), len(set(labels)))

    def test_baseline_has_none_packets(self):
        """Один пресет (baseline) имеет packets=None."""
        from chimera.modules.fragment_presets import PRESET_MATRIX
        baselines = [p for p in PRESET_MATRIX if p["packets"] is None]
        self.assertEqual(len(baselines), 1)

    def test_groups_are_valid(self):
        from chimera.modules.fragment_presets import (
            PRESET_MATRIX, _GROUP_LABELS,
        )
        for p in PRESET_MATRIX:
            with self.subTest(label=p["label"]):
                self.assertIn(p["group"], _GROUP_LABELS)


class TestGroupLabels(unittest.TestCase):
    """_GROUP_LABELS."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_5_groups(self):
        from chimera.modules.fragment_presets import _GROUP_LABELS
        for g in ("aggressive", "medium", "light", "combo", "baseline"):
            self.assertIn(g, _GROUP_LABELS)


class TestGenerateAllPresets(unittest.TestCase):
    """generate_all_presets — генерация всех."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"
        self._frag_dir = self._tmpdir / "fragment"
        self._frag_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("chimera.modules.fragment_presets._STATE_FILE", self._state),
            patch("chimera.modules.fragment_presets._FRAGMENT_DIR", self._frag_dir),
            patch("chimera.modules.fragment_config._STATE_FILE", self._state),
            patch("chimera.modules.fragment_config._FRAGMENT_DIR", self._frag_dir),
        )

    def test_returns_list_with_9_entries(self):
        from chimera.modules.fragment_presets import (
            generate_all_presets, PRESET_MATRIX,
        )
        with self._patch()[0], self._patch()[1], self._patch()[2], self._patch()[3]:
            results = generate_all_presets()
        self.assertEqual(len(results), len(PRESET_MATRIX))

    def test_baseline_fails_without_state(self):
        """baseline-пресет не генерируется без state.json."""
        from chimera.modules.fragment_presets import generate_all_presets
        with self._patch()[0], self._patch()[1], self._patch()[2], self._patch()[3]:
            results = generate_all_presets()
        # baseline должен быть с ok=False (нет state)
        baselines = [r for r in results if r["preset"]["packets"] is None]
        self.assertEqual(len(baselines), 1)
        self.assertFalse(baselines[0]["ok"])

    def test_all_non_baseline_fail_without_state(self):
        """Без state.json не- baseline тоже не генерируются (делегируют в fragment_config)."""
        from chimera.modules.fragment_presets import generate_all_presets
        with self._patch()[0], self._patch()[1], self._patch()[2], self._patch()[3]:
            results = generate_all_presets()
        non_baseline = [r for r in results if r["preset"]["packets"] is not None]
        for r in non_baseline:
            self.assertFalse(r["ok"])

    def test_baseline_xhttp_reality_without_flow(self):
        """baseline-пресет при xhttp_reality: xhttp + REALITY, БЕЗ flow."""
        from chimera.modules.fragment_presets import _generate_one, PRESET_MATRIX
        self._state.write_text(json.dumps({
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "xhttp_reality",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
            "fingerprint": "chrome",
            "xhttp_path": "/xhttp",
            "xhttp_mode": "stream-up",
            "xtls_flow": "xtls-rprx-vision",
        }))
        baseline = next(p for p in PRESET_MATRIX if p["packets"] is None)
        with self._patch()[0], self._patch()[1], self._patch()[2], self._patch()[3]:
            path = _generate_one(baseline)
        self.assertIsNotNone(path)
        data = json.loads(path.read_text())
        ob = data["outbounds"][0]
        ss = ob["streamSettings"]
        # users БЕЗ flow — xhttp-транспорт несовместим с vision
        self.assertNotIn("flow", ob["settings"]["vnext"][0]["users"][0])
        self.assertEqual(ss["network"], "xhttp")
        self.assertEqual(ss["security"], "reality")
        self.assertEqual(ss["xhttpSettings"],
                         {"path": "/xhttp", "mode": "stream-up"})
        rs = ss["realitySettings"]
        # SNI по канону: без AWG — domain
        self.assertEqual(rs["serverName"], "vpn.example.com")
        self.assertEqual(rs["publicKey"], "PUBKEY")
        self.assertEqual(rs["shortId"], "abcd1234")
        # baseline — без фрагментации: ни fragment-ключа в sockopt, ни
        # dialerProxy, ни fragment-outbound (валидная схема включается
        # только с fragment-параметрами)
        self.assertNotIn("fragment", ss["sockopt"])
        self.assertNotIn("dialerProxy", ss["sockopt"])
        tags = [ob.get("tag") for ob in data["outbounds"]]
        self.assertNotIn("fragment", tags)

    def test_tlshello_preset_generates_config(self):
        """frag_04b: packets='tlshello' доходит до settings.fragment
        freedom-outbound."""
        from chimera.modules.fragment_presets import _generate_one, PRESET_MATRIX
        self._state.write_text(json.dumps({
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "reality",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
        }))
        preset = next(p for p in PRESET_MATRIX
                      if p["label"] == "frag_04b_medium_tlshello")
        with self._patch()[0], self._patch()[1], self._patch()[2], self._patch()[3]:
            path = _generate_one(preset)
        self.assertIsNotNone(path)
        data = json.loads(path.read_text())
        frag_ob = [ob for ob in data["outbounds"]
                   if ob.get("tag") == "fragment"][0]
        frag = frag_ob["settings"]["fragment"]
        self.assertEqual(frag["packets"], "tlshello")
        self.assertEqual(frag["length"], "10-20")
        self.assertEqual(frag["interval"], "10-20")
        # основной outbound: dialerProxy, без placebo fragment-ключа
        proxy = data["outbounds"][0]
        sockopt = proxy["streamSettings"]["sockopt"]
        self.assertEqual(sockopt["dialerProxy"], "fragment")
        self.assertNotIn("fragment", sockopt)

    def test_noise_preset_generates_fragment_plus_noise(self):
        """frag_09 (combo): freedom-outbound содержит И fragment, И noises;
        основной outbound — dialerProxy без placebo-ключей."""
        from chimera.modules.fragment_presets import _generate_one, PRESET_MATRIX
        self._state.write_text(json.dumps({
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "reality",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
        }))
        preset = next(p for p in PRESET_MATRIX
                      if p["label"] == "frag_09_noise_std")
        with self._patch()[0], self._patch()[1], self._patch()[2], self._patch()[3]:
            path = _generate_one(preset)
        self.assertIsNotNone(path)
        data = json.loads(path.read_text())
        sockopt = data["outbounds"][0]["streamSettings"]["sockopt"]
        frag_ob = [ob for ob in data["outbounds"]
                   if ob.get("tag") == "fragment"][0]
        self.assertIn("fragment", frag_ob["settings"])
        noises = frag_ob["settings"]["noises"]
        self.assertEqual(noises[0]["packet"], "10-20")
        self.assertEqual(noises[0]["delay"], "5-10")
        self.assertEqual(noises[0]["type"], "rand")
        # сингулярный noise не появляется нигде
        self.assertNotIn("noise", frag_ob["settings"])
        # основной outbound: dialerProxy, без fragment/noise/noises
        self.assertEqual(sockopt["dialerProxy"], "fragment")
        self.assertNotIn("fragment", sockopt)
        self.assertNotIn("noise", sockopt)
        self.assertNotIn("noises", sockopt)

    def test_regular_presets_have_no_noise(self):
        """Обычные пресеты (без noise-ключей) не добавляют noises —
        обратная совместимость генерации (шум — опция комбо-пресета)."""
        from chimera.modules.fragment_presets import _generate_one, PRESET_MATRIX
        self._state.write_text(json.dumps({
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "reality",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
        }))
        preset = next(p for p in PRESET_MATRIX
                      if p["label"] == "frag_04_medium_fast")
        with self._patch()[0], self._patch()[1], self._patch()[2], self._patch()[3]:
            path = _generate_one(preset)
        self.assertIsNotNone(path)
        data = json.loads(path.read_text())
        sockopt = data["outbounds"][0]["streamSettings"]["sockopt"]
        frag_ob = [ob for ob in data["outbounds"]
                   if ob.get("tag") == "fragment"][0]
        self.assertIn("fragment", frag_ob["settings"])
        self.assertNotIn("noises", frag_ob["settings"])
        self.assertNotIn("noise", frag_ob["settings"])
        self.assertNotIn("noise", sockopt)

    def test_regular_preset_fragment_outbound_and_unique_tags(self):
        """Регулярный пресет: fragment-outbound с точными settings.fragment,
        теги outbound уникальны (proxy/fragment/direct/block)."""
        from chimera.modules.fragment_presets import _generate_one, PRESET_MATRIX
        self._state.write_text(json.dumps({
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "reality",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
        }))
        preset = next(p for p in PRESET_MATRIX
                      if p["label"] == "frag_04_medium_fast")
        with self._patch()[0], self._patch()[1], self._patch()[2], self._patch()[3]:
            path = _generate_one(preset)
        self.assertIsNotNone(path)
        data = json.loads(path.read_text())
        frag_ob = [ob for ob in data["outbounds"]
                   if ob.get("tag") == "fragment"][0]
        self.assertEqual(frag_ob["protocol"], "freedom")
        self.assertEqual(
            frag_ob["settings"]["fragment"],
            {"packets": preset["packets"], "length": preset["length"],
             "interval": preset["interval"]})
        tags = [ob.get("tag") for ob in data["outbounds"]]
        self.assertEqual(len(tags), len(set(tags)),
                         f"теги outbound должны быть уникальны: {tags}")
        for expected in ("proxy", "fragment", "direct", "block"):
            self.assertIn(expected, tags)


if __name__ == "__main__":
    unittest.main(verbosity=2)
