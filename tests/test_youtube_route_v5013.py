#!/usr/bin/env python3
"""
tests/test_youtube_route_v5013.py
───────────────────────────────────────────────────────────────────────────────
Регрессионные тесты для v5.0.13/v5.0.14 — стабильность YouTube через RU+fragment.

v5.0.14 HOTFIX: патч sniffing и sockopt ВЫКЛЮЧЕНЫ (ломали YouTube).
  - _youtube_patch_inbounds_for_fragment / _youtube_restore_inbounds_after_fragment
    ОПРЕДЕЛЕНЫ, но вызовы из _youtube_apply_fragment_to_xray / _youtube_remove_from_xray
    УБРАНЫ. Тестируем что функции работают корректно (если их вызывать вручную),
    и что _youtube_apply_fragment_to_xray НЕ применяет sockopt и НЕ патчит sniffing.

Покрывает:
  1. _youtube_patch_inbounds_for_fragment — функция работает корректно (в коде, не вызывается)
  2. _youtube_restore_inbounds_after_fragment — функция работает корректно (в коде, не вызывается)
  3. _youtube_apply_fragment_to_xray с max_split — поле maxSplit в fragment settings.
  4. v5.0.14: БЕЗ sockopt в freedom outbound (откат).
  5. v5.0.14: БЕЗ патча sniffing (откат).
  6. Грейсфул-рестарт — 500мс sleep перед systemctl restart xray.
  7. Расширенный список YouTube-доменов (CDN variants).
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules(awg_enabled: bool = False):
    """Загружает chimera._core через exec и регистрирует в sys.modules."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    fake_core.AWG_EXIT_ENABLED = awg_enabled
    return fake_core


def _make_completed(stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr="",
    )


def _make_xray_config_with_fragment(inbounds=None,
                                    outbounds=None,
                                    routing_rules=None) -> dict:
    """Создаёт Xray config с inbound блоком (для тестов sniffing patch)."""
    if inbounds is None:
        inbounds = [
            {
                "protocol": "vless", "tag": "vless-in", "port": 443,
                "settings": {"clients": []},
                "sniffing": {
                    "enabled":      True,
                    "destOverride": ["http", "tls"],
                    "metadataOnly": False,
                    "routeOnly":    False,
                },
            },
        ]
    if outbounds is None:
        outbounds = [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ]
    return {
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": routing_rules or [
                {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
            ],
        },
    }


class TestPatchInboundsFunctionDefined(unittest.TestCase):
    """Функция _youtube_patch_inbounds_for_fragment определена и работает
    корректно при вызове вручную. В v5.0.14 вызовы убраны из apply_fragment."""

    def setUp(self):
        _setup_core_in_sysmodules(awg_enabled=False)

    def test_sets_routeonly_true_and_adds_quic(self):
        """Функция работает корректно при прямом вызове."""
        from chimera.modules import youtube_route
        cfg = _make_xray_config_with_fragment()
        changed = youtube_route._youtube_patch_inbounds_for_fragment(cfg)
        self.assertTrue(changed)
        sn = cfg["inbounds"][0]["sniffing"]
        self.assertTrue(sn["routeOnly"])
        self.assertIn("quic", sn["destOverride"])

    def test_skips_awg_metadataonly_true(self):
        """AWG-режим (metadataOnly=True) — НЕ трогаем."""
        from chimera.modules import youtube_route
        cfg = _make_xray_config_with_fragment(inbounds=[{
            "protocol": "vless", "tag": "vless-in", "port": 443,
            "settings": {"clients": []},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"],
                         "metadataOnly": True, "routeOnly": False},
        }])
        changed = youtube_route._youtube_patch_inbounds_for_fragment(cfg)
        self.assertFalse(changed)

    def test_restore_function_works(self):
        """_youtube_restore_inbounds_after_fragment работает корректно."""
        from chimera.modules import youtube_route
        cfg = _make_xray_config_with_fragment()
        youtube_route._youtube_patch_inbounds_for_fragment(cfg)
        self.assertIn("quic", cfg["inbounds"][0]["sniffing"]["destOverride"])
        changed = youtube_route._youtube_restore_inbounds_after_fragment(cfg)
        self.assertTrue(changed)
        sn = cfg["inbounds"][0]["sniffing"]
        self.assertFalse(sn["routeOnly"])
        self.assertNotIn("quic", sn["destOverride"])


class TestApplyFragmentNoSockoptV5014(unittest.TestCase):
    """v5.0.14: freedom outbound БЕЗ sockopt (откат v5.0.13 regression)."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        _setup_core_in_sysmodules(awg_enabled=False)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_paths(self):
        from chimera.modules import youtube_route
        core = sys.modules["chimera._core"]
        return (
            patch.object(youtube_route, "_core_module", lambda: core),
            patch.object(core, "CONFIG_DIR", self._tmpdir),
        )

    def test_no_sockopt_in_freedom_outbound(self):
        """v5.0.14: freedom outbound НЕ должен содержать sockopt."""
        from chimera.modules import youtube_route
        self._cfg_path.write_text(json.dumps(_make_xray_config_with_fragment()))
        core = sys.modules["chimera._core"]
        core._set_config_owner = lambda p: None
        core._run = MagicMock(return_value=_make_completed("active"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        with self._patch_paths()[0], self._patch_paths()[1], \
             patch.object(youtube_route, "time"):
            youtube_route._youtube_apply_fragment_to_xray(
                "1", "10-30", "3-8", block_quic=False,
            )
        cfg = json.loads(self._cfg_path.read_text())
        frag_ob = [ob for ob in cfg["outbounds"]
                   if ob.get("tag") == "direct-fragment"][0]
        # КРИТИЧНО: sockopt НЕ должен присутствовать (v5.0.14 откат).
        self.assertNotIn("sockopt", frag_ob,
                         "sockopt НЕ должен быть в freedom outbound (v5.0.14 откат)")


class TestApplyFragmentNoSniffingPatchV5014(unittest.TestCase):
    """v5.0.14: _youtube_apply_fragment_to_xray НЕ патчит inbound sniffing."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        _setup_core_in_sysmodules(awg_enabled=False)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_paths(self):
        from chimera.modules import youtube_route
        core = sys.modules["chimera._core"]
        return (
            patch.object(youtube_route, "_core_module", lambda: core),
            patch.object(core, "CONFIG_DIR", self._tmpdir),
        )

    def test_inbound_sniffing_not_modified(self):
        """v5.0.14: routeOnly остаётся False, destOverride без 'quic'
        после _youtube_apply_fragment_to_xray (патч выключен)."""
        from chimera.modules import youtube_route
        self._cfg_path.write_text(json.dumps(_make_xray_config_with_fragment()))
        core = sys.modules["chimera._core"]
        core._set_config_owner = lambda p: None
        core._run = MagicMock(return_value=_make_completed("active"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        with self._patch_paths()[0], self._patch_paths()[1], \
             patch.object(youtube_route, "time"):
            youtube_route._youtube_apply_fragment_to_xray(
                "1", "10-30", "3-8", block_quic=False,
            )
        cfg = json.loads(self._cfg_path.read_text())
        sn = cfg["inbounds"][0]["sniffing"]
        # routeOnly должен остаться False (не патчим в v5.0.14).
        self.assertFalse(sn["routeOnly"],
                         "routeOnly НЕ должен меняться (v5.0.14 — patch выключен)")
        # 'quic' НЕ должен быть добавлен в destOverride.
        self.assertNotIn("quic", sn["destOverride"],
                         "'quic' НЕ должен добавляться (v5.0.14 — patch выключен)")


class TestApplyFragmentWithMaxSplit(unittest.TestCase):
    """_youtube_apply_fragment_to_xray с параметром max_split (v5.0.13, сохранено в v5.0.14)."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        _setup_core_in_sysmodules(awg_enabled=False)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_paths(self):
        from chimera.modules import youtube_route
        core = sys.modules["chimera._core"]
        return (
            patch.object(youtube_route, "_core_module", lambda: core),
            patch.object(core, "CONFIG_DIR", self._tmpdir),
        )

    def test_maxsplit_written_to_config(self):
        """max_split="3-6" → в config.json должно быть fragment.maxSplit="3-6"."""
        from chimera.modules import youtube_route
        self._cfg_path.write_text(json.dumps(_make_xray_config_with_fragment()))
        core = sys.modules["chimera._core"]
        core._set_config_owner = lambda p: None
        core._run = MagicMock(return_value=_make_completed("active"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        with self._patch_paths()[0], self._patch_paths()[1], \
             patch.object(youtube_route, "time") as mock_time:
            mock_time.sleep = MagicMock()
            youtube_route._youtube_apply_fragment_to_xray(
                "1", "10-30", "3-8", block_quic=False, max_split="3-6",
            )
        cfg = json.loads(self._cfg_path.read_text())
        frag_obs = [ob for ob in cfg["outbounds"]
                    if ob.get("tag") == "direct-fragment"]
        self.assertEqual(len(frag_obs), 1)
        frag = frag_obs[0]["settings"]["fragment"]
        self.assertEqual(frag["packets"], "1")
        self.assertEqual(frag["length"], "10-30")
        self.assertEqual(frag["interval"], "3-8")
        self.assertEqual(frag["maxSplit"], "3-6")

    def test_no_maxsplit_when_none(self):
        """max_split=None → поле maxSplit НЕ должно быть в fragment."""
        from chimera.modules import youtube_route
        self._cfg_path.write_text(json.dumps(_make_xray_config_with_fragment()))
        core = sys.modules["chimera._core"]
        core._set_config_owner = lambda p: None
        core._run = MagicMock(return_value=_make_completed("active"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        with self._patch_paths()[0], self._patch_paths()[1], \
             patch.object(youtube_route, "time"):
            youtube_route._youtube_apply_fragment_to_xray(
                "1", "10-30", "3-8", block_quic=False, max_split=None,
            )
        cfg = json.loads(self._cfg_path.read_text())
        frag_obs = [ob for ob in cfg["outbounds"]
                    if ob.get("tag") == "direct-fragment"][0]
        self.assertNotIn("maxSplit", frag_obs["settings"]["fragment"])


class TestGracefulRestart(unittest.TestCase):
    """v5.0.13/v5.0.14: грейсфул-рестарт — 500мс sleep перед systemctl restart xray."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        _setup_core_in_sysmodules(awg_enabled=False)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_paths(self):
        from chimera.modules import youtube_route
        core = sys.modules["chimera._core"]
        return (
            patch.object(youtube_route, "_core_module", lambda: core),
            patch.object(core, "CONFIG_DIR", self._tmpdir),
        )

    def test_sleep_called_before_restart(self):
        """time.sleep(0.5) вызывается перед systemctl restart xray."""
        from chimera.modules import youtube_route
        self._cfg_path.write_text(json.dumps(_make_xray_config_with_fragment()))
        core = sys.modules["chimera._core"]
        core._set_config_owner = lambda p: None
        core._run = MagicMock(return_value=_make_completed("active"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        with self._patch_paths()[0], self._patch_paths()[1], \
             patch.object(youtube_route, "time") as mock_time:
            mock_time.sleep = MagicMock()
            youtube_route._youtube_apply_fragment_to_xray(
                "1", "10-30", "3-8", block_quic=False,
            )
        sleep_calls = [c for c in mock_time.sleep.call_args_list
                       if c == unittest.mock.call(0.5)]
        self.assertGreaterEqual(len(sleep_calls), 1,
                                "time.sleep(0.5) должен быть вызван перед restart")


class TestExpandedYoutubeDomains(unittest.TestCase):
    """v5.0.13/v5.0.14: расширенный список YouTube-доменов (CDN variants)."""

    def test_cdn_domains_present(self):
        """Должны быть добавлены CDN variants для асимметричной маршрутизации."""
        from chimera.modules import youtube_route
        domains = youtube_route._YOUTUBE_DOMAINS
        # Основные.
        self.assertIn("domain:youtube.com", domains)
        self.assertIn("domain:googlevideo.com", domains)
        # v5.0.13: CDN variants.
        self.assertIn("domain:wide-youtube.l.google.com", domains)
        self.assertIn("domain:youtube-ui.l.google.com", domains)
        self.assertIn("domain:youtubeembedded-pa.googleapis.com", domains)
        self.assertIn("domain:youtube.googleapis.com", domains)
        self.assertIn("domain:lh3.googleusercontent.com", domains)


class TestFragmentPresetMenuV5013(unittest.TestCase):
    """_fragment_preset_menu возвращает 5-tuple с max_split (v5.0.13, сохранено в v5.0.14)."""

    def setUp(self):
        _setup_core_in_sysmodules(awg_enabled=False)

    def test_preset_returns_5_tuple_with_maxsplit(self):
        """При выборе пресета medium — должен вернуть 5-tuple с max_split='3-6'."""
        from chimera.modules import youtube_route
        core = sys.modules["chimera._core"]
        core._box_top = lambda *a, **kw: None
        core._box_row = lambda *a, **kw: None
        core._box_sep = lambda *a, **kw: None
        core._box_bottom = lambda *a, **kw: None
        core._box_item = lambda *a, **kw: None
        core._box_info = lambda *a, **kw: None
        core._box_warn = lambda *a, **kw: None
        core.CYAN = ""
        core.NC = ""
        core.DIM = ""
        core.GREEN = ""
        core.YELLOW = ""
        core.BLUE = ""
        with patch("builtins.input", side_effect=["2", "n"]):
            result = youtube_route._fragment_preset_menu(core)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 5, "Должен вернуть 5-tuple")
        packets, length, interval, block_quic, max_split = result
        self.assertEqual(packets, "1")
        self.assertEqual(length, "10-30")
        self.assertEqual(interval, "3-8")
        self.assertFalse(block_quic)
        self.assertEqual(max_split, "3-6", "medium preset должен дать max_split='3-6'")

    def test_light_preset_returns_none_maxsplit(self):
        """Light preset (index 1) — max_split должен быть None."""
        from chimera.modules import youtube_route
        core = sys.modules["chimera._core"]
        core._box_top = lambda *a, **kw: None
        core._box_row = lambda *a, **kw: None
        core._box_sep = lambda *a, **kw: None
        core._box_bottom = lambda *a, **kw: None
        core._box_item = lambda *a, **kw: None
        core._box_info = lambda *a, **kw: None
        core._box_warn = lambda *a, **kw: None
        core.CYAN = ""
        core.NC = ""
        core.DIM = ""
        core.GREEN = ""
        core.YELLOW = ""
        core.BLUE = ""
        with patch("builtins.input", side_effect=["1", "n"]):
            result = youtube_route._fragment_preset_menu(core)
        self.assertEqual(len(result), 5)
        _, _, _, _, max_split = result
        self.assertIsNone(max_split, "Light preset не имеет maxSplit")


if __name__ == "__main__":
    unittest.main()
