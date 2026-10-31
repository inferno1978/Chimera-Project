#!/usr/bin/env python3
"""
tests/test_fragment_customizer.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты v4.31 «Fragment & FP Customizer».

Покрывает:
  1. _FRAGMENT_PRESETS — пресет tlshello в fragment_config
  2. generate_fragment_client_config(fp_override=…) — FP в готовом JSON
  3. _build_xray_client_json / _build_singbox_json — fp_override
  4. _base_uri_params / _gen_*_link — flow из state (не прибит гвоздями) + &fp=
  5. fragment_noise / fragment_mux билдеры — fp_override + свои параметры mux
  6. fragment_presets.generate_all_presets(fp_override=…) — FP всей матрицы
  7. client_fragment.fp — ключ FP fragment-аддона экспорта
  8. user_fp_manager._FP_LIST_BOT — live-валидированный список (без none)
  9. _pick_fingerprint_step — интерактивный выбор (mocked input)
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


_STATE = {
    "protocol_mode": "reality",
    "domain": "chimeraprodcdn.online",
    "server_port": 443,
    "uuid": "cd166266-f329-430e-9714-7c69b35de8d9",
    "public_key": "ppbbZGg9A0SvIpP8kM9Ctdv87w81YaBgjpCBxW_vnAg",
    "short_id": "a2ea5d2b57c10ae8",
    "fingerprint": "firefox",
    "xtls_flow": "xtls-rprx-vision",
}


class TestFragmentPresetsV431(unittest.TestCase):
    """_FRAGMENT_PRESETS: + tlshello, данные — единый источник."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_tlshello_preset_present(self):
        from chimera.modules.fragment_config import _FRAGMENT_PRESETS
        self.assertIn("tlshello", _FRAGMENT_PRESETS)
        p = _FRAGMENT_PRESETS["tlshello"]
        self.assertEqual(p["packets"], "tlshello")
        self.assertEqual(p["length"], "10-20")
        self.assertEqual(p["interval"], "10-20")

    def test_no_hardcoded_chrome_in_sources(self):
        """Хардкод хрома больше не существует в стеке (ни с пробелами, ни без)."""
        for rel in ("fragment_config.py", "fragment_presets.py"):
            src = (_PROJECT_ROOT / "chimera" / "modules" / rel).read_text()
            compact = src.replace(" ", "")
            with self.subTest(module=rel):
                self.assertNotIn('"fingerprint": "chrome"', src)
                self.assertNotIn('"fingerprint":"chrome"', compact)


class TestGenerateWithFpOverride(unittest.TestCase):
    """generate_fragment_client_config: fp_override попадает в JSON."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"
        self._state.write_text(json.dumps(_STATE))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _gen(self, **kw):
        kw.pop("_lbl", None)
        from chimera.modules import fragment_config as fc
        with patch.object(fc, "_STATE_FILE", self._state), \
             patch.object(fc, "_FRAGMENT_DIR", self._tmpdir / "frag"):
            return fc.generate_fragment_client_config(
                packets="tlshello", length="10-20", interval="10-20",
                label="t_x", **kw)

    def test_override_applied(self):
        path = self._gen(fp_override="safari", _lbl="safari")
        cfg = json.loads(path.read_text())
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "proxy")
        self.assertEqual(
            ob["streamSettings"]["realitySettings"]["fingerprint"], "safari")

    def test_default_is_state_fingerprint(self):
        path = self._gen(_lbl="def")
        cfg = json.loads(path.read_text())
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "proxy")
        self.assertEqual(
            ob["streamSettings"]["realitySettings"]["fingerprint"], "firefox")

    def test_garbage_override_falls_back_to_state(self):
        path = self._gen(fp_override="garbage", _lbl="garbage")
        cfg = json.loads(path.read_text())
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "proxy")
        self.assertEqual(
            ob["streamSettings"]["realitySettings"]["fingerprint"], "firefox")


class TestLinkBuildersFp(unittest.TestCase):
    """_build_xray_client_json / _build_singbox_json: fp_override."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_xray_json_fp_override(self):
        from chimera.modules.fragment_link import _build_xray_client_json
        cfg = _build_xray_client_json(_STATE, "1-3", "3-7", "10-20",
                                      fp_override="edge")
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "proxy")
        self.assertEqual(
            ob["streamSettings"]["realitySettings"]["fingerprint"], "edge")

    def test_xray_json_default_state_fp(self):
        from chimera.modules.fragment_link import _build_xray_client_json
        cfg = _build_xray_client_json(_STATE, "1-3", "3-7", "10-20")
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "proxy")
        self.assertEqual(
            ob["streamSettings"]["realitySettings"]["fingerprint"], "firefox")

    def test_singbox_json_fp_override(self):
        from chimera.modules.fragment_link import _build_singbox_json
        cfg = _build_singbox_json(_STATE, "1-3", "3-7", "10-20",
                                  fp_override="qq")
        ob = cfg["outbounds"][0]
        self.assertEqual(ob["tls"]["utls"]["fingerprint"], "qq")

    def test_finalmask_still_applied(self):
        from chimera.modules.fragment_link import _build_xray_client_json
        cfg = _build_xray_client_json(_STATE, "tlshello", "10-20", "10-20",
                                      fp_override="ios")
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "proxy")
        fm = ob["streamSettings"].get("finalmask", {})
        self.assertEqual(fm["tcp"][0]["settings"]["packets"], "tlshello")


class TestUriFlowAndFp(unittest.TestCase):
    """_base_uri_params: flow настраиваем; ссылки несут &fp= и &flow=."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_reality_flow_param(self):
        from chimera.modules.fragment_link import _base_uri_params
        uri = _base_uri_params("h", "u", "pbk", "sid", "sni",
                               "safari", "reality", "/", "stream-up", 443,
                               flow="xtls-rprx-vision")
        self.assertIn("&flow=xtls-rprx-vision", uri)
        uri2 = _base_uri_params("h", "u", "pbk", "sid", "sni",
                                "safari", "reality", "/", "stream-up", 443,
                                flow="my-custom-flow")
        self.assertIn("&flow=my-custom-flow", uri2)

    def test_happ_link_carries_fp_and_flow(self):
        from chimera.modules.fragment_link import _gen_happ_link
        link = _gen_happ_link("h", "u", "pbk", "sid", "sni",
                              "1-3", "3-7", "10-20",
                              "safari", "reality", "/", "stream-up", 443,
                              flow="some-flow")
        self.assertIn("&fp=safari", link)
        self.assertIn("&flow=some-flow", link)
        self.assertIn("fragment=3-7%2C10-20%2C1-3", link)

    def test_neko_link_carries_fp(self):
        from chimera.modules.fragment_link import _gen_nekoray_link
        link = _gen_nekoray_link("h", "u", "pbk", "sid", "sni",
                                 "tlshello", "10-20", "10-20",
                                 "ios", "reality", "/", "stream-up", 443)
        self.assertIn("&fp=ios", link)
        self.assertIn("fragment=tlshello%2C10-20%2C10-20", link)


class TestNoiseBuildersFp(unittest.TestCase):
    """fragment_noise: fp_override в обоих билдерах."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_xray_noise_fp_override(self):
        from chimera.modules.fragment_noise import _build_xray_noise_json
        cfg = _build_xray_noise_json(_STATE, "1-3", "3-7", "10-20",
                                      "20-50", "10-20",
                                      fp_override="android")
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "proxy")
        self.assertEqual(
            ob["streamSettings"]["realitySettings"]["fingerprint"], "android")

    def test_singbox_noise_fp_override(self):
        from chimera.modules.fragment_noise import _build_singbox_noise_json
        cfg = _build_singbox_noise_json(_STATE, "1-3", "3-7", "10-20",
                                        "20-50", "10-20",
                                        fp_override="360")
        self.assertEqual(cfg["outbounds"][0]["tls"]["utls"]["fingerprint"], "360")


class TestMuxBuildersFp(unittest.TestCase):
    """fragment_mux: fp_override + свои параметры multiplex."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_xray_mux_fp_override(self):
        from chimera.modules.fragment_mux import _build_xray_mux_json
        cfg = _build_xray_mux_json(_STATE, "1-3", "3-7", "10-20",
                                    8, 16, fp_override="edge")
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "proxy")
        self.assertEqual(
            ob["streamSettings"]["realitySettings"]["fingerprint"], "edge")
        self.assertEqual(ob["mux"]["concurrency"], 8)
        self.assertEqual(ob["mux"]["xudpConcurrency"], 16)

    def test_singbox_mux_custom_params(self):
        from chimera.modules.fragment_mux import _build_singbox_mux_json
        cfg = _build_singbox_mux_json(_STATE, "1-3", "3-7", "10-20",
                                      "smux",
                                      sb_max_connections=7, sb_min_streams=3,
                                      fp_override="qq")
        ob = cfg["outbounds"][0]
        self.assertEqual(ob["tls"]["utls"]["fingerprint"], "qq")
        self.assertEqual(ob["multiplex"]["protocol"], "smux")
        self.assertEqual(ob["multiplex"]["max_connections"], 7)
        self.assertEqual(ob["multiplex"]["min_streams"], 3)


class TestPresetsFpPlumb(unittest.TestCase):
    """generate_all_presets(fp_override=…): FP всей матрицы (вкл. baseline)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"
        self._state.write_text(json.dumps(_STATE))
        self._frag_dir = self._tmpdir / "frag"
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

    def test_matrix_fp_override(self):
        from chimera.modules.fragment_presets import generate_all_presets
        p1, p2, p3, p4 = self._patch()
        with p1, p2, p3, p4:
            results = generate_all_presets(fp_override="ios")
        frag04 = next(r for r in results
                      if r["preset"]["label"] == "frag_04_medium_fast")
        self.assertTrue(frag04["ok"])
        cfg = json.loads(frag04["path"].read_text())
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "proxy")
        self.assertEqual(
            ob["streamSettings"]["realitySettings"]["fingerprint"], "ios")

    def test_baseline_fp_override(self):
        from chimera.modules.fragment_presets import generate_all_presets
        p1, p2, p3, p4 = self._patch()
        with p1, p2, p3, p4:
            results = generate_all_presets(fp_override="edge")
        base = next(r for r in results
                    if r["preset"]["label"] == "frag_00_no_fragment")
        self.assertTrue(base["ok"])
        cfg = json.loads(base["path"].read_text())
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "proxy")
        self.assertEqual(
            ob["streamSettings"]["realitySettings"]["fingerprint"], "edge")


class TestClientFragmentFpKey(unittest.TestCase):
    """client_fragment.fp: ключ FP fragment-аддона экспорта."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_settings_include_fp_key(self):
        from chimera.modules.fragment_config import get_client_fragment_settings
        st = {"client_fragment": {
            "enabled": True, "packets": "tlshello",
            "length": "10-20", "interval": "10-20", "fp": "safari",
        }}
        cf = get_client_fragment_settings(st)
        self.assertEqual(cf.get("fp"), "safari")

    def test_settings_without_fp(self):
        from chimera.modules.fragment_config import get_client_fragment_settings
        st = {"client_fragment": {
            "enabled": True, "packets": "1-3",
            "length": "3-7", "interval": "10-20",
        }}
        cf = get_client_fragment_settings(st)
        self.assertIsNone(cf.get("fp"))

    def test_export_honors_addon_fp(self):
        """Экспорт передаёт client_fragment.fp в билдеры/ссылки (source-guard)."""
        src = (_PROJECT_ROOT / "chimera" / "modules"
               / "client_config_export.py").read_text()
        self.assertIn('_fp_frag = _cf.get("fp")', src)
        self.assertIn("fp_override=_fp_frag", src)
        self.assertIn("_fp_links = _fp_frag or fp", src)


class TestUserFpBotList(unittest.TestCase):
    """TG-бот /setfp: live-валидированный список (без none)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_bot_list_has_no_none(self):
        from chimera.modules.user_fp_manager import TG_FP_COMMANDS_BLOCK
        self.assertIn('"randomizednoalpn"', TG_FP_COMMANDS_BLOCK)
        self.assertNotIn('"none"', TG_FP_COMMANDS_BLOCK)


class TestCoreRotateSets(unittest.TestCase):
    """_core: множества исключений ротации — live-валидированные."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_rotate_exclude_set(self):
        src = (_PROJECT_ROOT / "chimera" / "_core.py").read_text()
        self.assertIn(
            '_FP_ROTATE_EXCLUDE = {"random", "randomized", "randomizednoalpn"}',
            src)


class TestPickFingerprintStep(unittest.TestCase):
    """_pick_fingerprint_step (fragment_link): mocked input."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_enter_keeps_default(self):
        from chimera.modules import fragment_link as fl
        with patch("builtins.input", lambda *a, **k: ""):
            self.assertIsNone(fl._pick_fingerprint_step(dict(_STATE)))

    def test_number_selects(self):
        from chimera.modules import fragment_link as fl
        # 3 = safari; затем «n» на «сохранить как дефолт»
        inputs = iter(["3", "n"])
        with patch("builtins.input", lambda *a, **k: next(inputs)):
            self.assertEqual(fl._pick_fingerprint_step(dict(_STATE)), "safari")

    def test_name_selects_and_save(self):
        from chimera.modules import fragment_link as fl
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            from chimera.modules import fingerprint_manager as fm
            state_file = Path(td) / "state.json"
            state_file.write_text(json.dumps(_STATE))
            with patch.object(fm, "STATE_FILE", state_file):
                # qq (по имени), затем «y» → сохранить в state
                inputs = iter(["qq", "y"])
                with patch("builtins.input", lambda *a, **k: next(inputs)):
                    got = fl._pick_fingerprint_step(dict(_STATE))
                self.assertEqual(got, "qq")
                saved = json.loads(state_file.read_text())
                self.assertEqual(saved["fingerprint"], "qq")

    def test_garbage_rejected(self):
        from chimera.modules import fragment_link as fl
        with patch("builtins.input", lambda *a, **k: "garbage"):
            self.assertIsNone(fl._pick_fingerprint_step(dict(_STATE)))

    def test_ctrl_c_aborts(self):
        from chimera.modules import fragment_link as fl
        def _raise(*a, **k):
            raise KeyboardInterrupt
        with patch("builtins.input", _raise):
            self.assertEqual(fl._pick_fingerprint_step(dict(_STATE)), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
