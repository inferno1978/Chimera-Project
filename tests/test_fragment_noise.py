#!/usr/bin/env python3
"""
tests/test_fragment_noise.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/fragment_noise.py.

Покрывает:
  1. build_fragment_outbound(noise args) — комбо fragment+noises в одном
     freedom-outbound (замена удалённой build_noise_sockopt — валидная
     схема Xray-core, сингулярный noise из ядра удалён)
  2. _build_xray_noise_json — полный клиентский Xray JSON (комбо-путь)
  3. build_singbox_noise_dial — генерация Sing-box dial
  4. _resolve_sni — выбор SNI
  5. _load_state — чтение state
  6. _NOISE_PRESETS — структура пресетов
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


class TestBuildFragmentOutboundNoise(unittest.TestCase):
    """build_fragment_outbound(noise args) — замена удалённой
    build_noise_sockopt: комбо fragment+noises в одном freedom-outbound
    (валидная схема Xray-core; fragment_noise реэкспортирует билдеры
    из fragment_config — проверяем его публичное API-пространство имён)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_freedom_outbound_with_fragment_and_noises(self):
        from chimera.modules.fragment_noise import build_fragment_outbound
        ob = build_fragment_outbound(noise_packet="20-50", noise_delay="10-20")
        self.assertEqual(ob["protocol"], "freedom")
        self.assertEqual(ob["tag"], "fragment")
        self.assertIn("fragment", ob["settings"])
        noises = ob["settings"]["noises"]
        self.assertIsInstance(noises, list)
        self.assertEqual(len(noises), 1)
        self.assertEqual(noises[0]["type"], "rand")
        # сингулярный noise (удалён из Xray-core) не появляется
        self.assertNotIn("noise", ob["settings"])

    def test_default_noise_values(self):
        """Штатные noise-значения комбо (20-50/10-20) — как прежде в
        build_noise_sockopt, теперь в noises freedom-outbound."""
        from chimera.modules.fragment_noise import build_fragment_outbound
        ob = build_fragment_outbound(noise_packet="20-50", noise_delay="10-20")
        noise = ob["settings"]["noises"][0]
        self.assertEqual(noise["type"], "rand")
        self.assertEqual(noise["packet"], "20-50")
        self.assertEqual(noise["delay"], "10-20")

    def test_custom_noise_values(self):
        from chimera.modules.fragment_noise import build_fragment_outbound
        ob = build_fragment_outbound(noise_packet="100-200", noise_delay="50-100")
        noise = ob["settings"]["noises"][0]
        self.assertEqual(noise["packet"], "100-200")
        self.assertEqual(noise["delay"], "50-100")

    def test_noises_omitted_without_noise_args(self):
        """Без noise-аргументов noises нет — шум опционален."""
        from chimera.modules.fragment_noise import build_fragment_outbound
        ob = build_fragment_outbound()
        self.assertNotIn("noises", ob["settings"])
        self.assertNotIn("noise", ob["settings"])

    def test_no_tcp_fast_open_by_default(self):
        """TFO выключен по умолчанию (инцидент 28.08.2026: DPI резал data-in-SYN)."""
        from chimera.modules.fragment_noise import (
            build_fragment_outbound, build_fragment_sockopt,
        )
        ob = build_fragment_outbound(noise_packet="20-50", noise_delay="10-20")
        self.assertNotIn("tcpFastOpen", ob["streamSettings"]["sockopt"])
        self.assertNotIn("tcpFastOpen", build_fragment_sockopt())

    def test_tcp_fast_open_when_enabled(self):
        from chimera.modules import tfo_settings
        from chimera.modules.fragment_noise import (
            build_fragment_outbound, build_fragment_sockopt,
        )
        tfo_settings.set_tfo_override(True)
        try:
            ob = build_fragment_outbound(noise_packet="20-50", noise_delay="10-20")
            self.assertTrue(ob["streamSettings"]["sockopt"].get("tcpFastOpen"))
            self.assertTrue(build_fragment_sockopt().get("tcpFastOpen"))
        finally:
            tfo_settings.clear_tfo_override()


class TestBuildXrayNoiseJson(unittest.TestCase):
    """_build_xray_noise_json — комбо fragment+noises (валидная схема)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _state(self):
        return {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd",
            "reality_dest": "dest:443",
            "fingerprint": "chrome",
            "server_port": 443,
        }

    def _build(self):
        from chimera.modules.fragment_noise import _build_xray_noise_json
        return _build_xray_noise_json(
            self._state(), "1-3", "10-20", "10-20", "20-50", "10-20")

    def test_fragment_outbound_present_with_fragment_and_noises(self):
        """Комбо-путь: freedom-outbound несёт settings.fragment И noises."""
        cfg = self._build()
        frag_obs = [ob for ob in cfg["outbounds"] if ob.get("tag") == "fragment"]
        self.assertEqual(len(frag_obs), 1)
        ob = frag_obs[0]
        self.assertEqual(ob["protocol"], "freedom")
        self.assertEqual(
            ob["settings"]["fragment"],
            {"packets": "1-3", "length": "10-20", "interval": "10-20"})
        noises = ob["settings"]["noises"]
        self.assertEqual(noises[0]["type"], "rand")
        self.assertEqual(noises[0]["packet"], "20-50")
        self.assertEqual(noises[0]["delay"], "10-20")
        # сингулярный noise не появляется
        self.assertNotIn("noise", ob["settings"])

    def test_proxy_sockopt_dialer_proxy_without_placebo_keys(self):
        """Основной outbound: dialerProxy="fragment", НЕТ placebo-ключей
        fragment/noise/noises в sockopt (регрессия плацебо-схемы)."""
        cfg = self._build()
        proxy = [ob for ob in cfg["outbounds"] if ob["tag"] == "proxy"][0]
        sockopt = proxy["streamSettings"]["sockopt"]
        self.assertEqual(sockopt["dialerProxy"], "fragment")
        self.assertNotIn("fragment", sockopt)
        self.assertNotIn("noise", sockopt)
        self.assertNotIn("noises", sockopt)
        # DUAL-схема (31.10.2026): finalmask зеркалит fragment
        fm = proxy["streamSettings"]["finalmask"]["tcp"][0]
        self.assertEqual(fm["type"], "fragment")
        self.assertEqual(fm["settings"],
                         {"packets": "1-3", "length": "10-20",
                          "interval": "10-20"})

    def test_outbound_tags_unique(self):
        """Теги outbound уникальны (proxy/fragment/direct/block)."""
        cfg = self._build()
        tags = [ob.get("tag") for ob in cfg["outbounds"]]
        self.assertEqual(len(tags), len(set(tags)),
                         f"теги outbound должны быть уникальны: {tags}")
        for expected in ("proxy", "fragment", "direct", "block"):
            self.assertIn(expected, tags)

    def test_reality_transport_intact(self):
        """Транспорт не пострадал: reality-ветка с vision-flow."""
        cfg = self._build()
        proxy = [ob for ob in cfg["outbounds"] if ob["tag"] == "proxy"][0]
        ss = proxy["streamSettings"]
        self.assertEqual(ss["network"], "tcp")
        self.assertEqual(ss["security"], "reality")
        self.assertEqual(ss["realitySettings"]["serverName"], "vpn.example.com")
        self.assertEqual(ss["realitySettings"]["publicKey"], "PUBKEY")
        self.assertEqual(
            proxy["settings"]["vnext"][0]["users"][0].get("flow"),
            "xtls-rprx-vision")


class TestBuildSingboxNoiseDial(unittest.TestCase):
    """build_singbox_noise_dial — pure dict builder."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_dict_with_required_keys(self):
        from chimera.modules.fragment_noise import build_singbox_noise_dial
        d = build_singbox_noise_dial("1-3", "3-7", "10-20", "20-50", "10-20")
        # tcp_fast_open по умолчанию НЕТ (TFO дефолт ВЫКЛ)
        for key in ("fragment", "noise"):
            self.assertIn(key, d)
        self.assertNotIn("tcp_fast_open", d)

    def test_tcp_fast_open_present_when_enabled(self):
        from chimera.modules import tfo_settings
        from chimera.modules.fragment_noise import build_singbox_noise_dial
        tfo_settings.set_tfo_override(True)
        try:
            d = build_singbox_noise_dial("1-3", "3-7", "10-20", "20-50", "10-20")
            self.assertTrue(d.get("tcp_fast_open"))
        finally:
            tfo_settings.clear_tfo_override()

    def test_fragment_enabled(self):
        from chimera.modules.fragment_noise import build_singbox_noise_dial
        d = build_singbox_noise_dial("1-3", "3-7", "10-20", "20-50", "10-20")
        self.assertTrue(d["fragment"]["enabled"])
        self.assertEqual(d["fragment"]["size"], "3-7")
        self.assertEqual(d["fragment"]["sleep"], "10-20")

    def test_noise_enabled(self):
        from chimera.modules.fragment_noise import build_singbox_noise_dial
        d = build_singbox_noise_dial("1-3", "3-7", "10-20", "20-50", "10-20")
        self.assertTrue(d["noise"]["enabled"])
        self.assertEqual(d["noise"]["type"], "rand")
        self.assertEqual(d["noise"]["packet"], "20-50")


class TestResolveSni(unittest.TestCase):
    """_resolve_sni — выбор SNI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_domain_for_reality_without_awg(self):
        from chimera.modules.fragment_noise import _resolve_sni
        state = {"proto": "reality", "domain": "vpn.example.com"}
        self.assertEqual(_resolve_sni(state), "vpn.example.com")

    def test_returns_reality_dest_for_awg_reality_mode_b(self):
        from chimera.modules.fragment_noise import _resolve_sni
        state = {
            "proto": "reality", "awg_exit_enabled": True,
            "install_mode": "B", "reality_dest": "dest.example.com:443",
            "domain": "vpn.example.com",
        }
        self.assertEqual(_resolve_sni(state), "dest.example.com")

    def test_returns_domain_when_awg_but_mode_not_b(self):
        from chimera.modules.fragment_noise import _resolve_sni
        state = {
            "proto": "reality", "awg_exit_enabled": True,
            "install_mode": "A", "reality_dest": "dest:443",
            "domain": "vpn.example.com",
        }
        self.assertEqual(_resolve_sni(state), "vpn.example.com")

    def test_returns_domain_for_xhttp(self):
        from chimera.modules.fragment_noise import _resolve_sni
        state = {"proto": "xhttp", "domain": "vpn.example.com"}
        self.assertEqual(_resolve_sni(state), "vpn.example.com")


class TestLoadState(unittest.TestCase):
    """_load_state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.fragment_noise._STATE_FILE", self._state)

    def test_returns_none_when_no_file(self):
        from chimera.modules.fragment_noise import _load_state
        with self._patch():
            self.assertIsNone(_load_state())

    def test_returns_none_when_no_domain(self):
        from chimera.modules.fragment_noise import _load_state
        self._state.write_text(json.dumps({"uuid": "u"}))
        with self._patch():
            self.assertIsNone(_load_state())

    def test_returns_none_when_no_uuid(self):
        from chimera.modules.fragment_noise import _load_state
        self._state.write_text(json.dumps({"domain": "x.com"}))
        with self._patch():
            self.assertIsNone(_load_state())

    def test_returns_state_when_valid(self):
        from chimera.modules.fragment_noise import _load_state
        self._state.write_text(json.dumps({"domain": "x.com", "uuid": "u"}))
        with self._patch():
            st = _load_state()
        self.assertIsNotNone(st)
        self.assertEqual(st["domain"], "x.com")


class TestNoisePresets(unittest.TestCase):
    """_NOISE_PRESETS — структура."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_light_medium_aggressive(self):
        from chimera.modules.fragment_noise import _NOISE_PRESETS
        for name in ("light", "medium", "aggressive"):
            self.assertIn(name, _NOISE_PRESETS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
