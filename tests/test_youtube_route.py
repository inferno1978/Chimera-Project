#!/usr/bin/env python3
"""
tests/test_youtube_route.py
───────────────────────────────────────────────────────────────────────────────
Тесты для chimera/modules/youtube_route.py — переключателя маршрутизации
YouTube между RU entry-нодой (direct) и exit-нодами (default catch-all).

Покрывает:
  1. _youtube_apply_to_xray — добавление правила geosite:youtube → direct
     в routing.rules. Идемпотентность (повторный вызов не дублирует).
  2. _youtube_apply_to_xray AWG-aware — outboundTag=direct-local когда
     AWG_EXIT_ENABLED=True.
  3. _youtube_remove_from_xray — убирает правило по comment.
  4. _youtube_rule_in_xray_config — детектор наличия правила.
  5. _save_youtube_state — запись youtube_via_ru в state.json.
  6. restore_youtube_rule_if_needed — re-apply после regenerate если
     state.json говорит что правило должно быть, но его нет в config.
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
    # Override AWG_EXIT_ENABLED after loading (default is False from state).
    fake_core.AWG_EXIT_ENABLED = awg_enabled
    return fake_core


def _make_completed(stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr="",
    )


def _make_xray_config(routing_rules: list = None,
                      outbounds: list = None) -> dict:
    """Создаёт минимальный Xray config с routing.rules и outbounds."""
    if outbounds is None:
        outbounds = [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "freedom", "tag": "direct-local",
             "settings": {"domainStrategy": "UseIPv4"}},
            {"protocol": "blackhole", "tag": "block"},
        ]
    return {
        "inbounds": [{"protocol": "vless", "tag": "vless-in", "port": 443,
                      "settings": {"clients": []}}],
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": routing_rules or [
                {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
            ],
        },
    }


class TestYoutubeApplyToXray(unittest.TestCase):
    """_youtube_apply_to_xray — добавление правила YouTube→direct."""

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

    def test_adds_youtube_rule_with_domain_entries(self):
        """Правило должно содержать domain:youtube.com в domain[].

        v5.0.0: geosite:youtube убран — его нет в runetfreedom geosite.dat.
        Теперь используем только domain: записи.
        """
        from chimera.modules import youtube_route
        self._cfg_path.write_text(json.dumps(_make_xray_config()))
        # Mocks: _set_config_owner, _run, _nginx_restart_if_reality, info/success/warn.
        core = sys.modules["chimera._core"]
        core._set_config_owner = lambda p: None
        core._run = MagicMock(return_value=_make_completed("active"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        with self._patch_paths()[0], self._patch_paths()[1]:
            youtube_route._youtube_apply_to_xray()
        cfg = json.loads(self._cfg_path.read_text())
        rules = cfg["routing"]["rules"]
        yt_rules = [r for r in rules if r.get("comment") == "youtube_via_ru"]
        self.assertEqual(len(yt_rules), 1, "Должно быть ровно одно YouTube правило")
        self.assertIn("domain:youtube.com", yt_rules[0]["domain"])
        self.assertIn("domain:googlevideo.com", yt_rules[0]["domain"])
        # geosite:youtube НЕ должно быть — его нет в runetfreedom geosite.dat.
        self.assertNotIn("geosite:youtube", yt_rules[0]["domain"])
        self.assertNotIn("geosite:google", yt_rules[0]["domain"])

    def test_uses_direct_outbound_in_non_awg_mode(self):
        """Без AWG: outboundTag='direct'."""
        from chimera.modules import youtube_route
        self._cfg_path.write_text(json.dumps(_make_xray_config()))
        core = sys.modules["chimera._core"]
        core._set_config_owner = lambda p: None
        core._run = MagicMock(return_value=_make_completed("active"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        with self._patch_paths()[0], self._patch_paths()[1]:
            youtube_route._youtube_apply_to_xray()
        cfg = json.loads(self._cfg_path.read_text())
        yt_rules = [r for r in cfg["routing"]["rules"]
                    if r.get("comment") == "youtube_via_ru"]
        self.assertEqual(yt_rules[0]["outboundTag"], "direct")

    def test_uses_direct_local_in_awg_mode(self):
        """С AWG_EXIT_ENABLED=True: outboundTag='direct-local'."""
        from chimera.modules import youtube_route
        _setup_core_in_sysmodules(awg_enabled=True)
        self._cfg_path.write_text(json.dumps(_make_xray_config()))
        core = sys.modules["chimera._core"]
        core._set_config_owner = lambda p: None
        core._run = MagicMock(return_value=_make_completed("active"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        with patch.object(youtube_route, "_core_module", lambda: core), \
             patch.object(core, "CONFIG_DIR", self._tmpdir):
            youtube_route._youtube_apply_to_xray()
        cfg = json.loads(self._cfg_path.read_text())
        yt_rules = [r for r in cfg["routing"]["rules"]
                    if r.get("comment") == "youtube_via_ru"]
        self.assertEqual(yt_rules[0]["outboundTag"], "direct-local")

    def test_idempotent_no_duplicate_rules(self):
        """Повторный вызов НЕ дублирует правило — заменяет старое."""
        from chimera.modules import youtube_route
        self._cfg_path.write_text(json.dumps(_make_xray_config()))
        core = sys.modules["chimera._core"]
        core._set_config_owner = lambda p: None
        core._run = MagicMock(return_value=_make_completed("active"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        with self._patch_paths()[0], self._patch_paths()[1]:
            youtube_route._youtube_apply_to_xray()
            youtube_route._youtube_apply_to_xray()
        cfg = json.loads(self._cfg_path.read_text())
        yt_rules = [r for r in cfg["routing"]["rules"]
                    if r.get("comment") == "youtube_via_ru"]
        self.assertEqual(len(yt_rules), 1,
                         "Повторный вызов не должен дублировать правило")

    def test_rule_prepended_before_catchall(self):
        """YouTube правило должно быть ВЫШЕ catch-all правила
        (tcp,udp → direct) — иначе оно никогда не сработает."""
        from chimera.modules import youtube_route
        self._cfg_path.write_text(json.dumps(_make_xray_config()))
        core = sys.modules["chimera._core"]
        core._set_config_owner = lambda p: None
        core._run = MagicMock(return_value=_make_completed("active"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        with self._patch_paths()[0], self._patch_paths()[1]:
            youtube_route._youtube_apply_to_xray()
        cfg = json.loads(self._cfg_path.read_text())
        rules = cfg["routing"]["rules"]
        yt_idx = next(i for i, r in enumerate(rules)
                      if r.get("comment") == "youtube_via_ru")
        catchall_idx = next(i for i, r in enumerate(rules)
                            if r.get("network") == "tcp,udp"
                            and not r.get("domain"))
        self.assertLess(yt_idx, catchall_idx,
                        "YouTube правило должно быть ВЫШЕ catch-all")

    def test_xray_not_started_returns_false(self):
        """Если Xray не запустился — возвращаем False."""
        from chimera.modules import youtube_route
        self._cfg_path.write_text(json.dumps(_make_xray_config()))
        core = sys.modules["chimera._core"]
        core._set_config_owner = lambda p: None
        # systemctl is-active возвращает 'failed'.
        core._run = MagicMock(return_value=_make_completed("failed"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        with self._patch_paths()[0], self._patch_paths()[1]:
            result = youtube_route._youtube_apply_to_xray()
        self.assertFalse(result)


class TestYoutubeRemoveFromXray(unittest.TestCase):
    """_youtube_remove_from_xray — удаление правила по comment."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        _setup_core_in_sysmodules(awg_enabled=False)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_removes_youtube_rule(self):
        """Удаляет только YouTube правило, оставляя остальные."""
        from chimera.modules import youtube_route
        cfg = _make_xray_config(routing_rules=[
            {"type": "field", "domain": ["domain:youtube.com"],
             "outboundTag": "direct", "comment": "youtube_via_ru"},
            {"type": "field", "ip": ["10.0.0.0/8"],
             "outboundTag": "direct", "comment": "ru_subnets_ripe"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
        ])
        self._cfg_path.write_text(json.dumps(cfg))
        core = sys.modules["chimera._core"]
        core._set_config_owner = lambda p: None
        core._run = MagicMock(return_value=_make_completed("active"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        with patch.object(youtube_route, "_core_module", lambda: core), \
             patch.object(core, "CONFIG_DIR", self._tmpdir):
            youtube_route._youtube_remove_from_xray()
        cfg2 = json.loads(self._cfg_path.read_text())
        rules = cfg2["routing"]["rules"]
        yt_rules = [r for r in rules if r.get("comment") == "youtube_via_ru"]
        self.assertEqual(len(yt_rules), 0, "YouTube правило должно быть удалено")
        # Другие правила не тронуты.
        ripe_rules = [r for r in rules if r.get("comment") == "ru_subnets_ripe"]
        self.assertEqual(len(ripe_rules), 1, "RIPE правило не должно быть тронуто")
        catchall_rules = [r for r in rules if r.get("network") == "tcp,udp"]
        self.assertEqual(len(catchall_rules), 1, "Catch-all не должен быть тронут")

    def test_no_rule_returns_true_silently(self):
        """Если правила нет — не ошибка, возвращает True (already off)."""
        from chimera.modules import youtube_route
        self._cfg_path.write_text(json.dumps(_make_xray_config()))
        core = sys.modules["chimera._core"]
        core._set_config_owner = lambda p: None
        core._run = MagicMock(return_value=_make_completed("active"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        with patch.object(youtube_route, "_core_module", lambda: core), \
             patch.object(core, "CONFIG_DIR", self._tmpdir):
            result = youtube_route._youtube_remove_from_xray()
        self.assertTrue(result)


class TestYoutubeRuleInConfig(unittest.TestCase):
    """_youtube_rule_in_xray_config — детектор наличия правила."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        _setup_core_in_sysmodules()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_true_when_rule_exists(self):
        from chimera.modules import youtube_route
        cfg = _make_xray_config(routing_rules=[
            {"type": "field", "domain": ["domain:youtube.com"],
             "outboundTag": "direct", "comment": "youtube_via_ru"},
        ])
        self._cfg_path.write_text(json.dumps(cfg))
        core = sys.modules["chimera._core"]
        with patch.object(youtube_route, "_core_module", lambda: core), \
             patch.object(core, "CONFIG_DIR", self._tmpdir):
            self.assertTrue(youtube_route._youtube_rule_in_xray_config())

    def test_returns_false_when_rule_missing(self):
        from chimera.modules import youtube_route
        self._cfg_path.write_text(json.dumps(_make_xray_config()))
        core = sys.modules["chimera._core"]
        with patch.object(youtube_route, "_core_module", lambda: core), \
             patch.object(core, "CONFIG_DIR", self._tmpdir):
            self.assertFalse(youtube_route._youtube_rule_in_xray_config())

    def test_returns_false_when_no_config_file(self):
        """Нет config.json — False (не падает)."""
        from chimera.modules import youtube_route
        core = sys.modules["chimera._core"]
        with patch.object(youtube_route, "_core_module", lambda: core), \
             patch.object(core, "CONFIG_DIR", self._tmpdir):
            self.assertFalse(youtube_route._youtube_rule_in_xray_config())


class TestSaveYoutubeState(unittest.TestCase):
    """_save_youtube_state — запись в state.json."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_path = self._tmpdir / "state.json"
        _setup_core_in_sysmodules()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_writes_youtube_via_ru_true(self):
        from chimera.modules import youtube_route
        self._state_path.write_text(json.dumps({"domain": "x.com"}))
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path
        with patch.object(youtube_route, "_core_module", lambda: core):
            youtube_route._save_youtube_state("ru")
        state = json.loads(self._state_path.read_text())
        self.assertTrue(state.get("youtube_via_ru"))
        self.assertEqual(state.get("youtube_route_target"), "ru")
        self.assertEqual(state.get("domain"), "x.com",
                         "Существующие поля не должны быть потеряны")

    def test_writes_youtube_via_ru_false(self):
        from chimera.modules import youtube_route
        self._state_path.write_text(json.dumps({"youtube_via_ru": True}))
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path
        with patch.object(youtube_route, "_core_module", lambda: core):
            youtube_route._save_youtube_state("off")
        state = json.loads(self._state_path.read_text())
        self.assertFalse(state.get("youtube_via_ru"))
        self.assertEqual(state.get("youtube_route_target"), "off")

    def test_creates_state_file_if_missing(self):
        """Если state.json не существует — создаёт."""
        from chimera.modules import youtube_route
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path  # не существует
        with patch.object(youtube_route, "_core_module", lambda: core):
            youtube_route._save_youtube_state("ru")
        state = json.loads(self._state_path.read_text())
        self.assertTrue(state.get("youtube_via_ru"))
        self.assertEqual(state.get("youtube_route_target"), "ru")


class TestRestoreYoutubeRuleIfNeeded(unittest.TestCase):
    """restore_youtube_rule_if_needed — re-apply после regenerate."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        self._state_path = self._tmpdir / "state.json"
        _setup_core_in_sysmodules()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_false_when_state_says_disabled(self):
        """state["youtube_via_ru"]=False — ничего не делаем."""
        from chimera.modules import youtube_route
        self._state_path.write_text(json.dumps({"youtube_via_ru": False}))
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path
        with patch.object(youtube_route, "_core_module", lambda: core):
            result = youtube_route.restore_youtube_rule_if_needed()
        self.assertFalse(result)

    def test_returns_false_when_state_missing(self):
        """Нет state.json — ничего не делаем."""
        from chimera.modules import youtube_route
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path  # не существует
        with patch.object(youtube_route, "_core_module", lambda: core):
            result = youtube_route.restore_youtube_rule_if_needed()
        self.assertFalse(result)

    def test_returns_false_when_rule_already_present(self):
        """state=True но правило уже в config — ничего не делаем."""
        from chimera.modules import youtube_route
        self._state_path.write_text(json.dumps({"youtube_via_ru": True}))
        cfg = _make_xray_config(routing_rules=[
            {"type": "field", "domain": ["domain:youtube.com"],
             "outboundTag": "direct", "comment": "youtube_via_ru"},
        ])
        self._cfg_path.write_text(json.dumps(cfg))
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path
        core.CONFIG_DIR = self._tmpdir
        with patch.object(youtube_route, "_core_module", lambda: core):
            result = youtube_route.restore_youtube_rule_if_needed()
        self.assertFalse(result)

    def test_reapplies_when_state_true_but_rule_missing(self):
        """state=True но правила нет (после regenerate) — пере-применяем."""
        from chimera.modules import youtube_route
        self._state_path.write_text(json.dumps({"youtube_via_ru": True}))
        self._cfg_path.write_text(json.dumps(_make_xray_config()))
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path
        core.CONFIG_DIR = self._tmpdir
        core._set_config_owner = lambda p: None
        core._run = MagicMock(return_value=_make_completed("active"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        with patch.object(youtube_route, "_core_module", lambda: core):
            result = youtube_route.restore_youtube_rule_if_needed()
        self.assertTrue(result, "Должен вернуть True — правило было пере-применено")
        # Проверяем что правило реально в конфиге.
        cfg2 = json.loads(self._cfg_path.read_text())
        yt_rules = [r for r in cfg2["routing"]["rules"]
                    if r.get("comment") == "youtube_via_ru"]
        self.assertEqual(len(yt_rules), 1)


class TestYoutubeDomainsList(unittest.TestCase):
    """Проверка что список доменов покрывает все CDN YouTube."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_domains_list_includes_key_youtube_domains(self):
        """Список _YOUTUBE_DOMAINS должен покрывать ключевые домены."""
        from chimera.modules.youtube_route import _YOUTUBE_DOMAINS
        # domain:youtube.com — основной домен.
        self.assertIn("domain:youtube.com", _YOUTUBE_DOMAINS)
        # geosite:youtube НЕ должно быть — его нет в runetfreedom geosite.dat.
        self.assertNotIn("geosite:youtube", _YOUTUBE_DOMAINS)
        self.assertNotIn("geosite:google", _YOUTUBE_DOMAINS)
        # googlevideo.com — CDN видео-стримов.
        self.assertIn("domain:googlevideo.com", _YOUTUBE_DOMAINS)
        # ytimg.com — thumbnails.
        self.assertIn("domain:ytimg.com", _YOUTUBE_DOMAINS)
        # youtu.be — короткие ссылки.
        self.assertIn("domain:youtu.be", _YOUTUBE_DOMAINS)


# ============================================================================
#  v5.0.0 — Multi-node YouTube routing: target_tag = "chain-exit-N"
# ============================================================================

class TestYoutubeApplyToXrayTargetTag(unittest.TestCase):
    """_youtube_apply_to_xray(target_tag) — multi-node routing."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        _setup_core_in_sysmodules(awg_enabled=False)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_and_mock(self):
        from chimera.modules import youtube_route
        core = sys.modules["chimera._core"]
        core.CONFIG_DIR = self._tmpdir
        core._set_config_owner = lambda p: None
        core._run = MagicMock(return_value=_make_completed("active"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        return patch.object(youtube_route, "_core_module", lambda: core)

    # ── Кейс 1: target_tag=None — regression, поведение не изменилось ──────
    def test_target_none_uses_direct(self):
        """target_tag=None → outboundTag='direct' (как раньше)."""
        from chimera.modules import youtube_route
        self._cfg_path.write_text(json.dumps(_make_xray_config()))
        with self._patch_and_mock():
            youtube_route._youtube_apply_to_xray()
        cfg = json.loads(self._cfg_path.read_text())
        yt_rules = [r for r in cfg["routing"]["rules"]
                    if r.get("comment") == "youtube_via_ru"]
        self.assertEqual(yt_rules[0]["outboundTag"], "direct")

    # ── Кейс 2: target_tag="chain-exit-2", outbound существует ────────────
    def test_target_chain_exit_2_writes_rule(self):
        """target_tag='chain-exit-2' с существующим outbound → правило пишется."""
        from chimera.modules import youtube_route
        outbounds = [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "vless", "tag": "chain-exit-1"},
            {"protocol": "vless", "tag": "chain-exit-2"},
            {"protocol": "vless", "tag": "chain-exit-3"},
        ]
        self._cfg_path.write_text(json.dumps(_make_xray_config(outbounds=outbounds)))
        with self._patch_and_mock():
            result = youtube_route._youtube_apply_to_xray(target_tag="chain-exit-2")
        self.assertTrue(result)
        cfg = json.loads(self._cfg_path.read_text())
        yt_rules = [r for r in cfg["routing"]["rules"]
                    if r.get("comment") == "youtube_via_ru"]
        self.assertEqual(len(yt_rules), 1)
        self.assertEqual(yt_rules[0]["outboundTag"], "chain-exit-2")

    # ── Кейс 3: target_tag="chain-exit-5", outbound НЕ существует ─────────
    def test_target_nonexistent_outbound_returns_false(self):
        """target_tag='chain-exit-5' без такого outbound → False, config не тронут."""
        from chimera.modules import youtube_route
        outbounds = [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "vless", "tag": "chain-exit-1"},
        ]
        original_config = json.dumps(_make_xray_config(outbounds=outbounds))
        self._cfg_path.write_text(original_config)
        core_warn = MagicMock()
        with self._patch_and_mock():
            # Подменяем warn чтобы проверить вызов.
            sys.modules["chimera._core"].warn = core_warn
            result = youtube_route._youtube_apply_to_xray(target_tag="chain-exit-5")
        self.assertFalse(result, "Должен вернуть False — outbound не существует")
        core_warn.assert_called()
        # Config не должен быть изменён.
        self.assertEqual(self._cfg_path.read_text(), original_config,
                         "Config.json не должен быть тронут при несуществующей ноде")


class TestSaveYoutubeStateTarget(unittest.TestCase):
    """_save_youtube_state(target) — новый ключ + legacy."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_path = self._tmpdir / "state.json"
        _setup_core_in_sysmodules()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    # ── Кейс 4: _save_youtube_state("chain-exit-2") ───────────────────────
    def test_save_chain_exit_2(self):
        """_save_youtube_state('chain-exit-2') — youtube_route_target записан,
        youtube_via_ru==False (не 'ru')."""
        from chimera.modules import youtube_route
        self._state_path.write_text(json.dumps({}))
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path
        with patch.object(youtube_route, "_core_module", lambda: core):
            youtube_route._save_youtube_state("chain-exit-2")
        state = json.loads(self._state_path.read_text())
        self.assertEqual(state.get("youtube_route_target"), "chain-exit-2")
        self.assertFalse(state.get("youtube_via_ru"),
                         "youtube_via_ru должен быть False для chain-exit-2")

    # ── Кейс 5: _save_youtube_state("ru") — legacy ────────────────────────
    def test_save_ru_legacy_compat(self):
        """_save_youtube_state('ru') — youtube_via_ru==True, обратная совместимость."""
        from chimera.modules import youtube_route
        self._state_path.write_text(json.dumps({}))
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path
        with patch.object(youtube_route, "_core_module", lambda: core):
            youtube_route._save_youtube_state("ru")
        state = json.loads(self._state_path.read_text())
        self.assertTrue(state.get("youtube_via_ru"))
        self.assertEqual(state.get("youtube_route_target"), "ru")


class TestRestoreYoutubeTargetTag(unittest.TestCase):
    """restore_youtube_rule_if_needed — multi-node target."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        self._state_path = self._tmpdir / "state.json"
        _setup_core_in_sysmodules()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    # ── Кейс 9: target="chain-exit-2", нода существует, правила нет ───────
    def test_reapplies_chain_exit_2(self):
        """target='chain-exit-2', нода существует, правила нет → пере-применяет."""
        from chimera.modules import youtube_route
        self._state_path.write_text(json.dumps({
            "youtube_route_target": "chain-exit-2",
        }))
        outbounds = [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "vless", "tag": "chain-exit-1"},
            {"protocol": "vless", "tag": "chain-exit-2"},
        ]
        self._cfg_path.write_text(json.dumps(_make_xray_config(outbounds=outbounds)))
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path
        core.CONFIG_DIR = self._tmpdir
        core._set_config_owner = lambda p: None
        core._run = MagicMock(return_value=_make_completed("active"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        with patch.object(youtube_route, "_core_module", lambda: core):
            result = youtube_route.restore_youtube_rule_if_needed(silent=True)
        self.assertTrue(result, "Должен вернуть True — правило пере-применено")
        cfg2 = json.loads(self._cfg_path.read_text())
        yt_rules = [r for r in cfg2["routing"]["rules"]
                    if r.get("comment") == "youtube_via_ru"]
        self.assertEqual(len(yt_rules), 1)
        self.assertEqual(yt_rules[0]["outboundTag"], "chain-exit-2")

    # ── Кейс 10: target="chain-exit-9", ноды не существует ────────────────
    def test_returns_false_when_node_deleted(self):
        """target='chain-exit-9', ноды не существует → False, не падает."""
        from chimera.modules import youtube_route
        self._state_path.write_text(json.dumps({
            "youtube_route_target": "chain-exit-9",
        }))
        outbounds = [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "vless", "tag": "chain-exit-1"},
        ]
        self._cfg_path.write_text(json.dumps(_make_xray_config(outbounds=outbounds)))
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path
        core.CONFIG_DIR = self._tmpdir
        core._set_config_owner = lambda p: None
        core._run = MagicMock(return_value=_make_completed("active"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        with patch.object(youtube_route, "_core_module", lambda: core):
            result = youtube_route.restore_youtube_rule_if_needed(silent=True)
        self.assertFalse(result, "Должен вернуть False — нода не существует")
        # Config не должен быть тронут.
        cfg2 = json.loads(self._cfg_path.read_text())
        yt_rules = [r for r in cfg2["routing"]["rules"]
                    if r.get("comment") == "youtube_via_ru"]
        self.assertEqual(len(yt_rules), 0, "Правило не должно быть добавлено")


class TestDoManageYoutubeMigration(unittest.TestCase):
    """do_manage_youtube_via_ru() — миграция и multi-node меню.

    Эти тесты мокают input() и вызывают do_manage_youtube_via_ru() напрямую,
    перехватывая stdout. Проверяют что меню отображает правильные пункты.
    """

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_path = self._tmpdir / "state.json"
        _setup_core_in_sysmodules()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    # ── Кейс 6: миграция — старый youtube_via_ru=True без youtube_route_target
    def test_migration_old_bool_shows_ru(self):
        """state.json со старым youtube_via_ru=True и БЕЗ youtube_route_target
        → меню показывает текущий маршрут как RU."""
        import io
        from contextlib import redirect_stdout
        from chimera.modules import youtube_route
        self._state_path.write_text(json.dumps({"youtube_via_ru": True}))
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path
        core.CHAIN_NODES = []  # single-node
        core.AWG_EXIT_ENABLED = False
        core.CONFIG_DIR = self._tmpdir  # нет config.json
        # Mocks
        core.info = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.CYAN = core.NC = core.GREEN = core.YELLOW = ""
        core.RED = core.BOLD = core.DIM = core.BLUE = ""

        # input должна печатать prompt перед возвратом — иначе prompt не
        # попадает в captured stdout.
        def _input_with_print(prompt="", *a, **kw):
            print(prompt, end="", flush=True)
            return "q"

        captured = io.StringIO()
        with patch.object(youtube_route, "_core_module", lambda: core), \
             patch("builtins.input", side_effect=_input_with_print), \
             redirect_stdout(captured):
            youtube_route.do_manage_youtube_via_ru()

        output = captured.getvalue()
        self.assertIn("RU", output,
                      f"Должен показать RU как текущий маршрут, вывод:\n{output}")

    # ── Кейс 7: len(CHAIN_NODES)<=1 → старое двухпунктовое меню ───────────
    def test_single_node_shows_two_item_menu(self):
        """len(CHAIN_NODES)<=1 → старое двухпунктовое меню."""
        import io
        from contextlib import redirect_stdout
        from chimera.modules import youtube_route
        self._state_path.write_text(json.dumps({"youtube_route_target": "off"}))
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path
        core.CHAIN_NODES = []  # 0 nodes → single-node mode
        core.AWG_EXIT_ENABLED = False
        core.CONFIG_DIR = self._tmpdir
        core.info = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.CYAN = core.NC = core.GREEN = core.YELLOW = ""
        core.RED = core.BOLD = core.DIM = core.BLUE = ""

        def _input_with_print(prompt="", *a, **kw):
            print(prompt, end="", flush=True)
            return "q"

        captured = io.StringIO()
        with patch.object(youtube_route, "_core_module", lambda: core), \
             patch("builtins.input", side_effect=_input_with_print), \
             redirect_stdout(captured):
            youtube_route.do_manage_youtube_via_ru()

        output = captured.getvalue()
        # v5.0.1: prompt теперь [1/2/W/Q] — добавлена кнопка W (YouTube->WARP)
        self.assertIn("[1/2/W/Q]", output,
                      f"Single-node должен показать [1/2/W/Q], вывод:\n{output}")
        # НЕ должно быть multi-node prompt типа [1-5/W/Q]
        self.assertNotIn("[1-5/W/Q]", output)

    # ── Кейс 8: len(CHAIN_NODES)==3 → меню показывает 5 пунктов ───────────
    def test_three_nodes_shows_five_items(self):
        """len(CHAIN_NODES)==3 → меню показывает 5 пунктов (RU + 3 ноды + default)."""
        import io
        from contextlib import redirect_stdout
        from chimera.modules import youtube_route
        self._state_path.write_text(json.dumps({"youtube_route_target": "off"}))
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path
        core.CHAIN_NODES = [
            {"host": "1.1.1.1", "port": 443},
            {"host": "2.2.2.2", "port": 443},
            {"host": "3.3.3.3", "port": 443},
        ]
        core.AWG_EXIT_ENABLED = False
        core.CONFIG_DIR = self._tmpdir
        core.info = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.CYAN = core.NC = core.GREEN = core.YELLOW = ""
        core.RED = core.BOLD = core.DIM = core.BLUE = ""

        def _input_with_print(prompt="", *a, **kw):
            print(prompt, end="", flush=True)
            return "q"

        captured = io.StringIO()
        with patch.object(youtube_route, "_core_module", lambda: core), \
             patch("builtins.input", side_effect=_input_with_print), \
             redirect_stdout(captured):
            youtube_route.do_manage_youtube_via_ru()

        output = captured.getvalue()
        # v5.0.1: prompt теперь [1-5/W/Q] — добавлена кнопка W (YouTube->WARP)
        self.assertIn("[1-5/W/Q]", output,
                      f"Multi-node (3 nodes) должен показать [1-5/W/Q], вывод:\n{output}")
        # Не должно быть single-node prompt
        self.assertNotIn("[1/2/W/Q]", output)
        # Должны быть хосты нод
        self.assertIn("1.1.1.1", output)
        self.assertIn("2.2.2.2", output)
        self.assertIn("3.3.3.3", output)

    # ── Кейс 9: REGRESSION v5.0.1 — нажатие 'w' не должно молча выходить ──
    # БАГ (исправлен в v5.0.1): в multi-node меню `int("w")` бросал
    # ValueError → except ValueError: return → кнопка [W] молча возвращала
    # пользователя в основное меню без какого-либо сообщения.
    def test_multi_node_w_key_calls_warp_interactive(self):
        """v5.0.1 regression: 'w' в multi-node меню должен вызвать
        do_youtube_warp_interactive, а не молча выйти из-за ValueError
        в int('w')."""
        import io
        from contextlib import redirect_stdout
        from chimera.modules import youtube_route
        self._state_path.write_text(json.dumps({"youtube_route_target": "off"}))
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path
        core.CHAIN_NODES = [
            {"host": "1.1.1.1", "port": 443},
            {"host": "2.2.2.2", "port": 443},
            {"host": "3.3.3.3", "port": 443},
        ]
        core.AWG_EXIT_ENABLED = False
        core.CONFIG_DIR = self._tmpdir
        core.info = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.CYAN = core.NC = core.GREEN = core.YELLOW = ""
        core.RED = core.BOLD = core.DIM = core.BLUE = ""

        # Флаг что do_youtube_warp_interactive был вызван.
        warp_called = {"count": 0}

        def _fake_warp_interactive(_core):
            warp_called["count"] += 1
            return (False, "WARP не установлен (тестовый мок)")

        def _input_with_print(prompt="", *a, **kw):
            print(prompt, end="", flush=True)
            return "w"   # нажимаем W

        # Также мокаем input для финального "Нажмите Enter..."
        inputs = iter(["w", ""])

        def _input_seq(prompt="", *a, **kw):
            print(prompt, end="", flush=True)
            try:
                return next(inputs)
            except StopIteration:
                return ""

        captured = io.StringIO()
        with patch.object(youtube_route, "_core_module", lambda: core), \
             patch("builtins.input", side_effect=_input_seq), \
             patch("chimera.modules.youtube_warp_route.do_youtube_warp_interactive",
                   side_effect=_fake_warp_interactive), \
             redirect_stdout(captured):
            youtube_route.do_manage_youtube_via_ru()

        # КРИТИЧНО: do_youtube_warp_interactive должен быть вызван.
        # До v5.0.1 фикса это было невозможно — int('w') бросал ValueError.
        self.assertEqual(warp_called["count"], 1,
                         "do_youtube_warp_interactive должен быть вызван 1 раз "
                         f"при нажатии 'w', фактически {warp_called['count']}. "
                         "Возможно, regression: int('w') снова бросает ValueError "
                         "и обработчик 'w' недостижим.")

    # ── Кейс 10: REGRESSION v5.0.1 — то же для single-node меню ──────────
    def test_single_node_w_key_calls_warp_interactive(self):
        """v5.0.1 regression: 'w' в single-node меню должен вызвать
        do_youtube_warp_interactive."""
        import io
        from contextlib import redirect_stdout
        from chimera.modules import youtube_route
        self._state_path.write_text(json.dumps({"youtube_route_target": "off"}))
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path
        core.CHAIN_NODES = []  # single-node
        core.AWG_EXIT_ENABLED = False
        core.CONFIG_DIR = self._tmpdir
        core.info = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.CYAN = core.NC = core.GREEN = core.YELLOW = ""
        core.RED = core.BOLD = core.DIM = core.BLUE = ""

        warp_called = {"count": 0}

        def _fake_warp_interactive(_core):
            warp_called["count"] += 1
            return (False, "WARP не установлен (тестовый мок)")

        inputs = iter(["w", ""])

        def _input_seq(prompt="", *a, **kw):
            print(prompt, end="", flush=True)
            try:
                return next(inputs)
            except StopIteration:
                return ""

        captured = io.StringIO()
        with patch.object(youtube_route, "_core_module", lambda: core), \
             patch("builtins.input", side_effect=_input_seq), \
             patch("chimera.modules.youtube_warp_route.do_youtube_warp_interactive",
                   side_effect=_fake_warp_interactive), \
             redirect_stdout(captured):
            youtube_route.do_manage_youtube_via_ru()

        self.assertEqual(warp_called["count"], 1,
                         "do_youtube_warp_interactive должен быть вызван 1 раз "
                         f"при нажатии 'w' в single-node меню, "
                         f"фактически {warp_called['count']}.")


class TestResolveNodeIpAndFlag(unittest.TestCase):
    """Тесты для _resolve_node_ip_and_flag — хелпер резолва IP + emoji-флага.

    v5.0.2: флаги стран (🇩🇪, 🇳🇱, ...) рядом с IP exit-нод в YouTube меню.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        # Очищаем кеш перед каждым тестом
        from chimera.modules import youtube_route
        youtube_route._NODE_IP_FLAG_CACHE.clear()

    def test_nonexistent_host_returns_unavailable_ip(self):
        """Host не резолвится → ('(IP недоступен)', '')."""
        from chimera.modules import youtube_route
        with patch("socket.gethostbyname", side_effect=OSError("no such host")):
            ip, flag = youtube_route._resolve_node_ip_and_flag("nonexistent.invalid")
        self.assertEqual(ip, "(IP недоступен)")
        self.assertEqual(flag, "")

    def test_successful_resolve_with_country(self):
        """Host резолвится, ip-api.com отдаёт DE → (IP, '🇩🇪️').
        
        v5.0.3: флаг включает U+FE0F (VS16) чтобы терминал рендерил
        regional indicator pair как emoji-флаг, не как буквы.
        """
        from chimera.modules import youtube_route
        core = sys.modules["chimera._core"]
        core._run = lambda args, **kw: _make_completed(
            '{"status":"success","countryCode":"DE"}'
        )
        with patch("socket.gethostbyname", return_value="203.0.113.132"):
            ip, flag = youtube_route._resolve_node_ip_and_flag("node1.example.com")
        self.assertEqual(ip, "203.0.113.132")
        # v5.0.3: флаг теперь содержит U+FE0F (VS16) в конце
        self.assertEqual(flag, "🇩🇪\ufe0f",
                         f"Флаг должен быть 🇩🇪+VS16, получили {flag!r} "
                         f"(codepoints: {[hex(ord(c)) for c in flag]})")

    def test_russian_flag(self):
        """countryCode=RU → 🇷🇺️ (с VS16)."""
        from chimera.modules import youtube_route
        core = sys.modules["chimera._core"]
        core._run = lambda args, **kw: _make_completed(
            '{"status":"success","countryCode":"RU"}'
        )
        with patch("socket.gethostbyname", return_value="203.0.113.135"):
            ip, flag = youtube_route._resolve_node_ip_and_flag("ru-node.example.com")
        self.assertEqual(ip, "203.0.113.135")
        # v5.0.3: флаг теперь содержит U+FE0F (VS16) в конце
        self.assertEqual(flag, "🇷🇺\ufe0f",
                         f"Флаг должен быть 🇷🇺+VS16, получили {flag!r}")

    def test_cache_avoids_repeat_network_calls(self):
        """Повторный вызов с тем же host берёт результат из кеша —
        socket.gethostbyname вызывается только один раз."""
        from chimera.modules import youtube_route
        core = sys.modules["chimera._core"]
        core._run = lambda args, **kw: _make_completed(
            '{"status":"success","countryCode":"NL"}'
        )
        call_count = [0]
        def counting_gethostbyname(host):
            call_count[0] += 1
            return "203.0.113.133"
        with patch("socket.gethostbyname", side_effect=counting_gethostbyname):
            r1 = youtube_route._resolve_node_ip_and_flag("cached.example.com")
            r2 = youtube_route._resolve_node_ip_and_flag("cached.example.com")
        self.assertEqual(r1, r2)
        self.assertEqual(call_count[0], 1,
                         "gethostbyname должен вызываться 1 раз (кеш), "
                         f"фактически {call_count[0]}")

    def test_ip_api_failure_returns_empty_flag(self):
        """ip-api.com вернул ошибку → flag пустой, IP всё равно отдаём."""
        from chimera.modules import youtube_route
        core = sys.modules["chimera._core"]
        core._run = lambda args, **kw: _make_completed(
            '{"status":"fail"}', returncode=0
        )
        with patch("socket.gethostbyname", return_value="1.2.3.4"):
            ip, flag = youtube_route._resolve_node_ip_and_flag("fail.example.com")
        self.assertEqual(ip, "1.2.3.4")
        self.assertEqual(flag, "",
                         "При ошибке ip-api.com flag должен быть пустым, "
                         "не 🌐 (это зарезервировано для балансировщика)")

    def test_flag_has_vs16_variation_selector(self):
        """v5.0.3 regression: emoji-флаг должен заканчиваться U+FE0F (VS16).

        Без VS16 некоторые терминалы рендерят regional indicator pair как
        ОДНУ букву вместо emoji-флага. Был зафиксирован случай (скриншот
        пользователя 2026-07-24): 🇳🇱 рендерилась как "N", 🇩🇪 как "D",
        🇮🇹 как "I", но 🇧🇾 рендерилась корректно. Добавление U+FE0F
        принудительно заставляет терминал рендерить пару как emoji.
        """
        from chimera.modules import youtube_route
        core = sys.modules["chimera._core"]
        core._run = lambda args, **kw: _make_completed(
            '{"status":"success","countryCode":"DE"}'
        )
        with patch("socket.gethostbyname", return_value="1.2.3.4"):
            ip, flag = youtube_route._resolve_node_ip_and_flag("vs16-test.example.com")
        self.assertTrue(flag.endswith("\ufe0f"),
                        f"Флаг должен заканчиваться U+FE0F (VS16), "
                        f"получили {flag!r} (codepoints: {[hex(ord(c)) for c in flag]}). "
                        f"Без VS16 терминалы могут рендерить regional indicator "
                        f"pair как одну букву вместо emoji-флага.")

    def test_with_emoji_vs16_helper(self):
        """_with_emoji_vs16 helper корректно добавляет VS16."""
        from chimera.modules import youtube_route
        # Пустая строка — возвращаем как есть
        self.assertEqual(youtube_route._with_emoji_vs16(""), "")
        # Флаг без VS16 — добавляем
        result = youtube_route._with_emoji_vs16("🇷🇺")
        self.assertEqual(result, "🇷🇺\ufe0f")
        self.assertTrue(result.endswith("\ufe0f"))
        # Флаг уже с VS16 — не дублируем
        result2 = youtube_route._with_emoji_vs16("🇷🇺\ufe0f")
        self.assertEqual(result2, "🇷🇺\ufe0f")
        self.assertEqual(len(result2), len("🇷🇺\ufe0f"),
                         "VS16 не должен дублироваться")
        # 🌍 тоже получает VS16
        result3 = youtube_route._with_emoji_vs16("🌍")
        self.assertEqual(result3, "🌍\ufe0f")


class TestYoutubeMenuFlagRendering(unittest.TestCase):
    """Регрессионные тесты рендера multi-node меню с флагами.

    v5.0.2: флаги 🇷🇺 (RU), 🇩🇪/🇳🇱/... (exit-ноды), 🌍 (балансировщик).
    Границы бокса не должны сломаться — _wcslen корректно считает emoji.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_path = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _render_menu(self, chain_nodes: list, state_target: str = "off") -> str:
        """Рендерит multi-node YouTube меню, возвращает вывод."""
        import io
        from contextlib import redirect_stdout
        from chimera.modules import youtube_route
        # Очищаем кеш флагов перед каждым рендером
        youtube_route._NODE_IP_FLAG_CACHE.clear()

        self._state_path.write_text(json.dumps({"youtube_route_target": state_target}))
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path
        core.CHAIN_NODES = chain_nodes
        core.AWG_EXIT_ENABLED = False
        core.CONFIG_DIR = self._tmpdir
        # Stub info/warn/success чтобы не засорять вывод
        core.info = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        core.success = lambda *a, **kw: None

        def _input_with_print(prompt="", *a, **kw):
            print(prompt, end="", flush=True)
            return "q"

        captured = io.StringIO()
        with patch.object(youtube_route, "_core_module", lambda: core), \
             patch("builtins.input", side_effect=_input_with_print), \
             patch("socket.gethostbyname",
                   side_effect=lambda h: f"1.2.3.{len(h) % 200 + 1}"), \
             redirect_stdout(captured):
            youtube_route.do_manage_youtube_via_ru()
        return captured.getvalue()

    def test_ru_entry_has_russian_flag(self):
        """Пункт 'RU entry' должен содержать 🇷🇺."""
        output = self._render_menu([
            {"host": "node1.example.com", "port": 443},
        ])
        # Ищем строку с RU entry
        ru_line = [l for l in output.splitlines() if "RU entry" in l]
        self.assertEqual(len(ru_line), 1, f"Должна быть 1 строка RU entry, вывод:\n{output}")
        self.assertIn("🇷🇺", ru_line[0],
                      f"RU entry должен содержать 🇷🇺, строка: {ru_line[0]}")

    def test_balancer_has_globe_emoji(self):
        """Пункт 'балансировщик' должен содержать 🌍."""
        output = self._render_menu([
            {"host": "node1.example.com", "port": 443},
            {"host": "node2.example.com", "port": 443},
        ])
        balancer_lines = [l for l in output.splitlines() if "балансировщик" in l]
        self.assertEqual(len(balancer_lines), 1)
        self.assertIn("🌍", balancer_lines[0],
                      f"Балансировщик должен содержать 🌍, строка: {balancer_lines[0]}")

    def test_box_right_border_aligned_with_emoji(self):
        """Правая граница бокса (║) должна быть выровнена на всех строках,
        несмотря на emoji-флаги (2 колонки) и 🌍.

        Это regression-тест на багу: если _wcslen не учитывал emoji как
        2 колонки, правая граница съезжала.
        """
        # 3 ноды с разными hostnames → разная длина IP, но флаги добавляют
        # 2 колонки каждый. Граница должна остаться ровной.
        output = self._render_menu([
            {"host": "a.example.com",   "port": 443},
            {"host": "bb.example.com",  "port": 443},
            {"host": "ccc.example.com", "port": 443},
        ])
        lines = output.splitlines()
        # Находим строки с exit-нодами (содержат 'Exit-нода #')
        exit_lines = [l for l in lines if "Exit-нода #" in l]
        self.assertGreaterEqual(len(exit_lines), 3,
                                f"Должно быть 3 exit-ноды, вывод:\n{output}")
        # Все строки должны заканчиваться на '║' (правая граница бокса)
        for line in exit_lines:
            # Убираем trailing whitespace и проверяем последний символ
            stripped = line.rstrip()
            self.assertTrue(stripped.endswith("║"),
                            f"Строка должна заканчиваться на '║' (правая граница "
                            f"бокса), но заканчивается на {stripped[-5:]!r}:\n{line}")
        # Проверим также RU entry и балансировщик
        ru_lines = [l for l in lines if "RU entry" in l]
        balancer_lines = [l for l in lines if "балансировщик" in l]
        for line in ru_lines + balancer_lines:
            stripped = line.rstrip()
            self.assertTrue(stripped.endswith("║"),
                            f"Строка должна заканчиваться на '║':\n{line}")

    def test_flag_appears_after_ip_for_exit_nodes(self):
        """Флаг emoji должен идти после IP-адреса exit-ноды, не до него."""
        # Mock: ip-api.com отдаёт DE для всех IP.
        # ВАЖНО: _render_menu использует lambda h: f"1.2.3.{len(h) % 200 + 1}"
        # для socket.gethostbyname — поэтому IP будут вида 1.2.3.X.
        # Нужно передать ≥2 ноды чтобы сработал multi-node режим (иначе
        # рендерится single-node меню без 'Exit-нода #1').
        core = sys.modules["chimera._core"]
        original_run = core._run
        core._run = lambda args, **kw: _make_completed(
            '{"status":"success","countryCode":"DE"}'
        )
        try:
            output = self._render_menu([
                {"host": "node1.example.com", "port": 443},
                {"host": "node2.example.com", "port": 443},
            ])
        finally:
            core._run = original_run

        exit_lines = [l for l in output.splitlines() if "Exit-нода #1" in l]
        self.assertEqual(len(exit_lines), 1,
                         f"Должна быть 1 строка с Exit-нода #1, вывод:\n{output}")
        line = exit_lines[0]
        # IP должен быть раньше флага в строке.
        # _render_menu генерирует IP вида 1.2.3.X (mock gethostbyname).
        ip_pos = line.find("1.2.3.")
        flag_pos = line.find("🇩🇪")
        self.assertGreater(ip_pos, 0, f"IP должен быть в строке: {line}")
        self.assertGreater(flag_pos, 0, f"Флаг 🇩🇪 должен быть в строке: {line}")
        self.assertLess(ip_pos, flag_pos,
                        f"IP должен быть раньше флага в строке:\n{line}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
