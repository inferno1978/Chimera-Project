#!/usr/bin/env python3
"""
tests/test_youtube_ip_pin.py
───────────────────────────────────────────────────────────────────────────────
Тесты для chimera/modules/youtube_ip_pin.py — экспериментальная опция
закрепления YouTube-CDN по IP.

Покрывает:
  1. PackageSpec x2 валидны (manual_incoming_dir != install_dests)
  2. post_install-валидатор: 557 валидных CIDR → принимается
  3. post_install-валидатор: <300 CIDR / мусор → отбраковывается
  4. apply_youtube_ip_pin() при target="off" → False
  5. apply_youtube_ip_pin() при target="chain-exit-2" → IP-правило добавлено
  6. remove_youtube_ip_pin() → убирает только IP-правило, доменное не трогает
  7. restore_ip_pin_if_needed() с route_target="off" → не применяется, не падает
───────────────────────────────────────────────────────────────────────────────
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


def _setup_core_in_sysmodules():
    """Загружает chimera._core через exec и регистрирует в sys.modules.

    exec выполняется ПРЯМО в __dict__ фейкового модуля (раньше — в
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
    return fake_core
def _make_completed(stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr="",
    )


def _make_xray_config(routing_rules: list = None,
                      outbounds: list = None) -> dict:
    """Создаёт минимальный Xray config."""
    if outbounds is None:
        outbounds = [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "vless", "tag": "chain-exit-1"},
            {"protocol": "vless", "tag": "chain-exit-2"},
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


# Реалистичные CIDR для тестов
_SAMPLE_CIDR4 = """173.194.0.0/16
207.223.160.0/20
209.85.128.0/17
216.58.192.0/19
216.239.32.0/19
64.233.160.0/19
66.102.0.0/20
66.249.64.0/19
72.14.192.0/18
74.125.0.0/16
""" * 60  # 600 строк — больше _MIN_CIDR4=300

_SAMPLE_CIDR6 = """2600:1f00::/32
2604:1380::/32
2604:1380:1000::/40
2604:aec0::/40
2606:2800::/32
2607:f8b0::/32
""" * 100  # 600 строк — больше _MIN_CIDR6=400

_GARBAGE_HTML = """<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body><h1>404 Not Found</h1>
<p>The resource could not be found.</p>
</body></html>"""


class TestPackageSpecsValid(unittest.TestCase):
    """Кейс 1: PackageSpec x2 валидны — assert из __post_init__ не падает."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_cidr4_spec_valid(self):
        from chimera.modules.youtube_ip_pin import CIDR4_SPEC
        self.assertEqual(CIDR4_SPEC.name, "youtube-cidr4")
        self.assertTrue(CIDR4_SPEC.min_size >= 4000)
        # manual_incoming_dir != install_dests (инвариант PackageSpec)
        for dest in CIDR4_SPEC.install_dests:
            self.assertNotEqual(CIDR4_SPEC.manual_incoming_dir, dest)

    def test_cidr6_spec_valid(self):
        from chimera.modules.youtube_ip_pin import CIDR6_SPEC
        self.assertEqual(CIDR6_SPEC.name, "youtube-cidr6")
        self.assertTrue(CIDR6_SPEC.min_size >= 8000)
        for dest in CIDR6_SPEC.install_dests:
            self.assertNotEqual(CIDR6_SPEC.manual_incoming_dir, dest)

    def test_mirror_order_raw_github_first(self):
        """raw.githubusercontent.com первым, jsDelivr — fallback вторым.

        Без checksum_urls нельзя полагаться на кэширующий CDN как основной
        источник (см. e90f255 — staleness от jsDelivr нечем ловить).
        Regression-тест чтобы порядок не откатили молча в будущем.
        """
        from chimera.modules.youtube_ip_pin import _mirror_urls
        urls = _mirror_urls("cidr4.txt")
        self.assertEqual(len(urls), 2)
        self.assertIn("raw.githubusercontent.com", urls[0],
                      f"raw.githubusercontent.com должен быть ПЕРВЫМ, фактически: {urls}")
        self.assertIn("jsdelivr", urls[1],
                      f"jsDelivr должен быть ВТОРЫМ (fallback), фактически: {urls}")


class TestPostInstallValidator(unittest.TestCase):
    """Кейсы 2-3: post_install валидатор — принимает/отбраковывает."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._install_dir = self._tmpdir / "install"
        _setup_core_in_sysmodules()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_valid_cidr4_accepted(self):
        """Кейс 2: файл с 600 валидными CIDR → принимается."""
        from chimera.modules.youtube_ip_pin import _post_install_iplist
        src = self._tmpdir / "cidr4.txt"
        src.write_text(_SAMPLE_CIDR4)
        core = sys.modules["chimera._core"]
        core._run = MagicMock()
        core.info = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        result = _post_install_iplist(src, [self._install_dir])
        self.assertTrue(result)
        # Файл скопирован
        dest = self._install_dir / "cidr4.txt"
        self.assertTrue(dest.exists())

    def test_garbage_rejected(self):
        """Кейс 3: мусор (HTML 404 вместо CIDR) → отбраковывается."""
        from chimera.modules.youtube_ip_pin import _post_install_iplist
        src = self._tmpdir / "cidr4.txt"
        src.write_text(_GARBAGE_HTML)
        core = sys.modules["chimera._core"]
        core._run = MagicMock()
        core.info = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        result = _post_install_iplist(src, [self._install_dir])
        self.assertFalse(result, "Мусорный файл должен быть отбракован")
        # Файл НЕ скопирован
        dest = self._install_dir / "cidr4.txt"
        self.assertFalse(dest.exists(),
                         "Файл не должен быть скопирован при отбраковке")


class TestApplyYoutubeIpPin(unittest.TestCase):
    """Кейсы 4-5: apply_youtube_ip_pin — применение правила."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        self._iplist_dir = self._tmpdir / "iplist"
        self._iplist_dir.mkdir()
        _setup_core_in_sysmodules()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_and_mock(self):
        from chimera.modules import youtube_ip_pin
        core = sys.modules["chimera._core"]
        core.CONFIG_DIR = self._tmpdir
        core._set_config_owner = lambda p: None
        core._run = MagicMock(return_value=_make_completed("active"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None
        return patch.object(youtube_ip_pin, "_core_module", lambda: core)

    def test_target_off_returns_false(self):
        """Кейс 4: target='off' → False с понятным сообщением."""
        from chimera.modules import youtube_ip_pin
        with self._patch_and_mock():
            result = youtube_ip_pin.apply_youtube_ip_pin("off")
        self.assertFalse(result)

    def test_target_chain_exit_2_adds_ip_rule(self):
        """Кейс 5: target='chain-exit-2' → IP-правило добавлено с этим тегом,
        доменное правило НЕ тронуто/не задвоено."""
        from chimera.modules import youtube_ip_pin
        # Создаём IP-список
        (self._iplist_dir / "cidr4.txt").write_text(_SAMPLE_CIDR4)
        # Конфиг с существующим доменным правилом
        cfg = _make_xray_config(routing_rules=[
            {"type": "field", "domain": ["domain:youtube.com"],
             "outboundTag": "chain-exit-2", "comment": "youtube_via_ru"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
        ])
        self._cfg_path.write_text(json.dumps(cfg))

        with self._patch_and_mock():
            with patch.object(youtube_ip_pin, "_CIDR4_FILE",
                              self._iplist_dir / "cidr4.txt"):
                result = youtube_ip_pin.apply_youtube_ip_pin("chain-exit-2")

        self.assertTrue(result)
        cfg2 = json.loads(self._cfg_path.read_text())
        rules = cfg2["routing"]["rules"]
        # IP-правило добавлено
        ip_rules = [r for r in rules if r.get("comment") == "youtube_ip_pin"]
        self.assertEqual(len(ip_rules), 1)
        self.assertEqual(ip_rules[0]["outboundTag"], "chain-exit-2")
        self.assertIn("ip", ip_rules[0])
        # Доменное правило НЕ тронуто
        yt_rules = [r for r in rules if r.get("comment") == "youtube_via_ru"]
        self.assertEqual(len(yt_rules), 1, "Доменное правило не должно быть тронуто")


class TestRemoveYoutubeIpPin(unittest.TestCase):
    """Кейс 6: remove_youtube_ip_pin — убирает только IP-правило."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_path = self._tmpdir / "config.json"
        _setup_core_in_sysmodules()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_removes_only_ip_rule(self):
        """Убирает только IP-правило, доменное остаётся."""
        from chimera.modules import youtube_ip_pin
        cfg = _make_xray_config(routing_rules=[
            {"type": "field", "domain": ["domain:youtube.com"],
             "outboundTag": "direct", "comment": "youtube_via_ru"},
            {"type": "field", "ip": ["173.194.0.0/16"],
             "outboundTag": "direct", "comment": "youtube_ip_pin"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
        ])
        self._cfg_path.write_text(json.dumps(cfg))
        core = sys.modules["chimera._core"]
        core.CONFIG_DIR = self._tmpdir
        core._set_config_owner = lambda p: None
        core._run = MagicMock(return_value=_make_completed("active"))
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None

        with patch.object(youtube_ip_pin, "_core_module", lambda: core):
            result = youtube_ip_pin.remove_youtube_ip_pin()

        self.assertTrue(result)
        cfg2 = json.loads(self._cfg_path.read_text())
        rules = cfg2["routing"]["rules"]
        # IP-правило убрано
        ip_rules = [r for r in rules if r.get("comment") == "youtube_ip_pin"]
        self.assertEqual(len(ip_rules), 0)
        # Доменное правило осталось
        yt_rules = [r for r in rules if r.get("comment") == "youtube_via_ru"]
        self.assertEqual(len(yt_rules), 1)


class TestRestoreIpPin(unittest.TestCase):
    """Кейс 7: restore_ip_pin_if_needed — рассинхрон."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_path = self._tmpdir / "state.json"
        _setup_core_in_sysmodules()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_ip_pin_enabled_but_target_off_returns_false(self):
        """ip_pin_enabled=True, route_target='off' → не применяется, не падает."""
        from chimera.modules import youtube_ip_pin
        self._state_path.write_text(json.dumps({
            "youtube_ip_pin_enabled": True,
            "youtube_route_target": "off",
        }))
        core = sys.modules["chimera._core"]
        core.STATE_FILE = self._state_path
        core.AWG_EXIT_ENABLED = False
        core.CONFIG_DIR = self._tmpdir  # нет config.json
        core._set_config_owner = lambda p: None
        core._run = MagicMock()
        core._nginx_restart_if_reality = MagicMock()
        core.info = lambda *a, **kw: None
        core.success = lambda *a, **kw: None
        core.warn = lambda *a, **kw: None

        with patch.object(youtube_ip_pin, "_core_module", lambda: core):
            result = youtube_ip_pin.restore_ip_pin_if_needed(silent=True)

        self.assertFalse(result, "Не должен применять IP-pin при target='off'")


if __name__ == "__main__":
    unittest.main(verbosity=2)
