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

    def test_has_9_presets(self):
        from chimera.modules.fragment_presets import PRESET_MATRIX
        self.assertEqual(len(PRESET_MATRIX), 9)

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

    def test_has_4_groups(self):
        from chimera.modules.fragment_presets import _GROUP_LABELS
        for g in ("aggressive", "medium", "light", "baseline"):
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
        # baseline — без fragment в sockopt
        self.assertNotIn("fragment", ss["sockopt"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
