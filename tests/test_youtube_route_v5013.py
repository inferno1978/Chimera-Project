#!/usr/bin/env python3
"""
tests/test_youtube_route_v5013.py
───────────────────────────────────────────────────────────────────────────────
Регрессионные тесты для    — стабильность YouTube через RU+fragment.

 добавлены patch sniffing + safe sockopt + maxSplit + расширенные домены.
 HOTFIX — откат  (ломал UseIPv4 на серверах без IPv6).
 ВОЗВРАТ  — пользователь переезжает на сервер с IPv6, где
  routeOnly=True безопасен и чинит асимметричную маршрутизацию QUIC-видео.

Покрывает:
  1. _youtube_patch_inbounds_for_fragment — routeOnly=True + destOverride["quic"]
     для всех VLESS/REALITY inbound (кроме AWG metadataOnly=True).
  2. _youtube_restore_inbounds_after_fragment — откат routeOnly=False, убирает "quic".
  3. _youtube_apply_fragment_to_xray с max_split — поле maxSplit в fragment settings.
  4. Безопасный sockopt — нет tcpCongestion="bbr", нет tcpNoDelay (удалён в Xray).
  5. Грейсфул-рестарт — 500мс sleep перед systemctl restart xray.
  6. Расширенный список YouTube-доменов (CDN variants).
  7. _youtube_remove_from_xray откатывает sniffing patch.
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
    """Загружает chimera._core через exec и регистрирует в sys.modules.

    v56: exec выполняется ПРЯМО в __dict__ фейкового модуля (раньше — в
    отдельный dict g, копируемый в модуль). Теперь мутации вида
    ``core._run = MagicMock(...)`` из тестов видны функциям ядра через
    их __globals__ — без этого _xray_safe_restart и другие функции,
    вызывающие _run напрямую, уходили в реальный subprocess и висли
    в wait-циклах по 45-90 секунд.
    """
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    fake_core = types.ModuleType("chimera._core")
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), fake_core.__dict__)
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


class TestPatchInboundsForFragment(unittest.TestCase):
    """_youtube_patch_inbounds_for_fragment — routeOnly=True + destOverride[quic]."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        _setup_core_in_sysmodules(awg_enabled=False)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_sets_routeonly_true_and_adds_quic(self):
        """Для VLESS inbound с metadataOnly=False — патч устанавливает
        routeOnly=True и добавляет 'quic' в destOverride."""
        from chimera.modules import youtube_route
        cfg = _make_xray_config_with_fragment()
        changed = youtube_route._youtube_patch_inbounds_for_fragment(cfg)
        self.assertTrue(changed, "Должно вернуть True — inbound был изменён")
        sn = cfg["inbounds"][0]["sniffing"]
        self.assertTrue(sn["routeOnly"], "routeOnly должен быть True")
        self.assertIn("quic", sn["destOverride"], "destOverride должен содержать 'quic'")
        # http и tls должны остаться
        self.assertIn("http", sn["destOverride"])
        self.assertIn("tls", sn["destOverride"])

    def test_skips_awg_metadataonly_true(self):
        """AWG-режим (metadataOnly=True) — НЕ трогаем."""
        from chimera.modules import youtube_route
        cfg = _make_xray_config_with_fragment(inbounds=[{
            "protocol": "vless", "tag": "vless-in", "port": 443,
            "settings": {"clients": []},
            "sniffing": {
                "enabled":      True,
                "destOverride": ["http", "tls"],
                "metadataOnly": True,
                "routeOnly":    False,
            },
        }])
        changed = youtube_route._youtube_patch_inbounds_for_fragment(cfg)
        self.assertFalse(changed, "AWG inbound НЕ должен быть изменён")
        sn = cfg["inbounds"][0]["sniffing"]
        self.assertFalse(sn["routeOnly"], "routeOnly НЕ должен меняться в AWG")
        self.assertNotIn("quic", sn["destOverride"], "quic НЕ должен добавляться в AWG")

    def test_skips_disabled_sniffing(self):
        """Если sniffing disabled — пропускаем."""
        from chimera.modules import youtube_route
        cfg = _make_xray_config_with_fragment(inbounds=[{
            "protocol": "vless", "tag": "vless-in", "port": 443,
            "settings": {"clients": []},
            "sniffing": {"enabled": False},
        }])
        changed = youtube_route._youtube_patch_inbounds_for_fragment(cfg)
        self.assertFalse(changed)

    def test_skips_non_vless_protocols(self):
        """Только VLESS/Trojan/VMess/dokodemo-door patching."""
        from chimera.modules import youtube_route
        cfg = _make_xray_config_with_fragment(inbounds=[{
            "protocol": "socks", "tag": "socks-in", "port": 1080,
            "settings": {},
            "sniffing": {
                "enabled":      True,
                "destOverride": ["http", "tls"],
                "metadataOnly": False,
                "routeOnly":    False,
            },
        }])
        changed = youtube_route._youtube_patch_inbounds_for_fragment(cfg)
        self.assertFalse(changed, "socks inbound НЕ должен быть patch")

    def test_idempotent(self):
        """Повторный вызов не делает изменений если уже применено."""
        from chimera.modules import youtube_route
        cfg = _make_xray_config_with_fragment()
        youtube_route._youtube_patch_inbounds_for_fragment(cfg)
        # Второй вызов — уже применено, изменений быть не должно.
        changed = youtube_route._youtube_patch_inbounds_for_fragment(cfg)
        self.assertFalse(changed, "Повторный вызов не должен делать изменений")

    def test_handles_multiple_inbounds(self):
        """Все VLESS/REALITY inbound должны быть patch."""
        from chimera.modules import youtube_route
        cfg = _make_xray_config_with_fragment(inbounds=[
            {"protocol": "vless", "tag": "vless-in1", "port": 443,
             "settings": {"clients": []},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls"],
                          "metadataOnly": False, "routeOnly": False}},
            {"protocol": "vless", "tag": "vless-in2", "port": 8443,
             "settings": {"clients": []},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls"],
                          "metadataOnly": False, "routeOnly": False}},
            {"protocol": "vless", "tag": "vless-awg", "port": 10443,
             "settings": {"clients": []},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls"],
                          "metadataOnly": True, "routeOnly": False}},
        ])
        changed = youtube_route._youtube_patch_inbounds_for_fragment(cfg)
        self.assertTrue(changed)
        # Первые два — patched.
        self.assertTrue(cfg["inbounds"][0]["sniffing"]["routeOnly"])
        self.assertIn("quic", cfg["inbounds"][0]["sniffing"]["destOverride"])
        self.assertTrue(cfg["inbounds"][1]["sniffing"]["routeOnly"])
        self.assertIn("quic", cfg["inbounds"][1]["sniffing"]["destOverride"])
        # Третий (AWG) — НЕ тронут.
        self.assertFalse(cfg["inbounds"][2]["sniffing"]["routeOnly"])
        self.assertNotIn("quic", cfg["inbounds"][2]["sniffing"]["destOverride"])


class TestRestoreInboundsAfterFragment(unittest.TestCase):
    """_youtube_restore_inbounds_after_fragment — откат sniffing."""

    def setUp(self):
        _setup_core_in_sysmodules(awg_enabled=False)

    def test_restores_routeonly_false_and_removes_quic(self):
        """После fragment — корректно откатывает routeOnly и убирает quic."""
        from chimera.modules import youtube_route
        cfg = _make_xray_config_with_fragment()
        # Сначала patch.
        youtube_route._youtube_patch_inbounds_for_fragment(cfg)
        self.assertIn("quic", cfg["inbounds"][0]["sniffing"]["destOverride"])
        # Потом restore.
        changed = youtube_route._youtube_restore_inbounds_after_fragment(cfg)
        self.assertTrue(changed)
        sn = cfg["inbounds"][0]["sniffing"]
        self.assertFalse(sn["routeOnly"])
        self.assertNotIn("quic", sn["destOverride"])

    def test_restore_skips_awg(self):
        """AWG inbound (metadataOnly=True) НЕ трогаем при restore."""
        from chimera.modules import youtube_route
        cfg = _make_xray_config_with_fragment(inbounds=[{
            "protocol": "vless", "tag": "vless-in", "port": 443,
            "settings": {"clients": []},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"],
                         "metadataOnly": True, "routeOnly": False},
        }])
        changed = youtube_route._youtube_restore_inbounds_after_fragment(cfg)
        self.assertFalse(changed)


class TestApplyFragmentWithMaxSplit(unittest.TestCase):
    """_youtube_apply_fragment_to_xray с параметром max_split ."""

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
        # Находим fragment outbound.
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


class TestSafeSockopt(unittest.TestCase):
    """ безопасный sockopt в freedom outbound (БЕЗ tcpCongestion='bbr')."""

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

    def test_sockopt_present_without_bbr(self):
        """freedom outbound должен иметь sockopt с tcpKeepAlive*, но БЕЗ
        tcpCongestion='bbr' и БЕЗ tcpFastOpen (дефолт TFO ВЫКЛ с 28.08.2026 —
        DPI/TSPU резали data-in-SYN)."""
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
        self.assertIn("sockopt", frag_ob, "sockopt должен присутствовать")
        so = frag_ob["sockopt"]
        # Должны быть безопасные поля.
        self.assertIn("tcpKeepAliveIdle", so)
        self.assertIn("tcpKeepAliveInterval", so)
        self.assertIn("tcpUserTimeout", so)
        # TFO по умолчанию ВЫКЛЮЧЕН (инцидент 28.08.2026).
        self.assertNotIn("tcpFastOpen", so,
                         "tcpFastOpen не должен быть в sockopt по умолчанию (анти-DPI)")
        # КРИТИЧНО: не должно быть tcpCongestion='bbr' — это ломало YouTube.
        self.assertNotIn("tcpCongestion", so,
                         "tcpCongestion НЕ должен присутствовать (bbr ломал YouTube)")
        # tcpNoDelay удалён в Xray — не должен быть в sockopt.
        self.assertNotIn("tcpNoDelay", so,
                         "tcpNoDelay удалён в Xray — не должен быть в sockopt")


class TestSniffingPatchedOnApply(unittest.TestCase):
    """ _youtube_apply_fragment_to_xray патчит inbound sniffing."""

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

    def test_inbound_sniffing_patched(self):
        """ routeOnly=True и 'quic' в destOverride после apply."""
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
        self.assertTrue(sn["routeOnly"], "routeOnly должен быть True")
        self.assertIn("quic", sn["destOverride"])


class TestGracefulRestart(unittest.TestCase):
    """ грейсфул-рестарт — 500мс sleep перед systemctl restart xray."""

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
        # sleep должен быть вызван хотя бы один раз с 0.5
        sleep_calls = [c for c in mock_time.sleep.call_args_list
                       if c == unittest.mock.call(0.5)]
        self.assertGreaterEqual(len(sleep_calls), 1,
                                "time.sleep(0.5) должен быть вызван перед restart")


class TestExpandedYoutubeDomains(unittest.TestCase):
    """ расширенный список YouTube-доменов (CDN variants)."""

    def test_cdn_domains_present(self):
        """Должны быть добавлены CDN variants для асимметричной маршрутизации."""
        from chimera.modules import youtube_route
        domains = youtube_route._YOUTUBE_DOMAINS
        # Основные.
        self.assertIn("domain:youtube.com", domains)
        self.assertIn("domain:googlevideo.com", domains)
        #  CDN variants.
        self.assertIn("domain:wide-youtube.l.google.com", domains)
        self.assertIn("domain:youtube-ui.l.google.com", domains)
        self.assertIn("domain:youtubeembedded-pa.googleapis.com", domains)
        self.assertIn("domain:youtube.googleapis.com", domains)
        self.assertIn("domain:lh3.googleusercontent.com", domains)


class TestRemoveFromXrayRestoresSniffing(unittest.TestCase):
    """_youtube_remove_from_xray должен откатывать sniffing patch ."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        _setup_core_in_sysmodules(awg_enabled=False)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_remove_restores_routeonly_and_quic(self):
        """После remove — routeOnly=False, destOverride без 'quic'."""
        from chimera.modules import youtube_route
        # Конфиг с уже применённым fragment (routeOnly=True, quic в destOverride).
        cfg = _make_xray_config_with_fragment()
        # Patch sniffing как будто fragment был применён.
        youtube_route._youtube_patch_inbounds_for_fragment(cfg)
        # Добавляем YouTube правило.
        cfg["routing"]["rules"].insert(0, {
            "type": "field",
            "domain": ["domain:youtube.com"],
            "outboundTag": "direct-fragment",
            "comment": "youtube_via_ru_fragment",
        })
        cfg["outbounds"].append({
            "protocol": "freedom", "tag": "direct-fragment",
            "settings": {"domainStrategy": "UseIPv4",
                         "fragment": {"packets": "1", "length": "10-30",
                                      "interval": "3-8"}},
        })
        self._cfg_path.write_text(json.dumps(cfg))
        core = sys.modules["chimera._core"]
        core._set_config_owner = lambda p: None
        core._run = MagicMock(return_value=_make_completed("active"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        with patch.object(youtube_route, "_core_module", lambda: core), \
             patch.object(core, "CONFIG_DIR", self._tmpdir), \
             patch.object(youtube_route, "time"):
            youtube_route._youtube_remove_from_xray()
        cfg2 = json.loads(self._cfg_path.read_text())
        sn = cfg2["inbounds"][0]["sniffing"]
        self.assertFalse(sn["routeOnly"],
                         "routeOnly должен вернуться в False после remove")
        self.assertNotIn("quic", sn["destOverride"],
                         "'quic' должен быть убран из destOverride после remove")


class TestFragmentPresetMenuV5013(unittest.TestCase):
    """_fragment_preset_menu возвращает 5-tuple с max_split (  ."""

    def setUp(self):
        _setup_core_in_sysmodules(awg_enabled=False)

    def test_preset_returns_5_tuple_with_maxsplit(self):
        """При выборе пресета medium — должен вернуть 5-tuple с max_split='3-6'."""
        from chimera.modules import youtube_route
        core = sys.modules["chimera._core"]
        # Минимальные mock'и для box rendering.
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
        # Выбираем пресет 2 (medium) и N для QUIC block.
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
