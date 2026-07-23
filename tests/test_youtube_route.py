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

        v5.0.1: geosite:youtube убран — его нет в runetfreedom geosite.dat.
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
            youtube_route._save_youtube_state(True)
        state = json.loads(self._state_path.read_text())
        self.assertTrue(state.get("youtube_via_ru"))
        self.assertEqual(state.get("domain"), "x.com",
                         "Существующие поля не должны быть потеряны")

    def test_writes_youtube_via_ru_false(self):
        from chimera.modules import youtube_route
        self._state_path.write_text(json.dumps({"youtube_via_ru": True}))
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path
        with patch.object(youtube_route, "_core_module", lambda: core):
            youtube_route._save_youtube_state(False)
        state = json.loads(self._state_path.read_text())
        self.assertFalse(state.get("youtube_via_ru"))

    def test_creates_state_file_if_missing(self):
        """Если state.json не существует — создаёт."""
        from chimera.modules import youtube_route
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path  # не существует
        with patch.object(youtube_route, "_core_module", lambda: core):
            youtube_route._save_youtube_state(True)
        state = json.loads(self._state_path.read_text())
        self.assertTrue(state.get("youtube_via_ru"))


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
