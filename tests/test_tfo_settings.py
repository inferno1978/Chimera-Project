#!/usr/bin/env python3
"""
tests/test_tfo_settings.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/tfo_settings.py (TCP Fast Open).

Инцидент 28.08.2026: DPI/TSPU на транзитном сегменте резали TFO-пакеты
(data-in-SYN). Каскад vds13216 (.112) → xyloss.online:9443 умирал при
живом TLS-хендшейке. A/B-тест доказал: без tcpFastOpen туннель работает.

Политика проекта с этого момента: TFO ПОЛНОСТЬЮ ВЫКЛЮЧЕН ПО УМОЛЧАНИЮ
во всех генераторах конфигов. Включение — только явно.

Покрывает:
  1. is_tfo_enabled — дефолт False / state.json / override
  2. set_tfo_state — merge-запись в state.json
  3. tfo_sockopt / tfo_dial — формы полей
  4. apply_tfo_to_xray_config — живой патчер config.json
  5. _build_sockopt (_core) — интеграция: TFO нет по умолчанию,
     появляется при override
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
    """Компилирует _core.py в фейковый модуль (как test_fragment_config)."""
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


class TestIsTfoEnabled(unittest.TestCase):
    """is_tfo_enabled: override → state.json → False."""

    def setUp(self):
        from chimera.modules import tfo_settings
        self.tfo = tfo_settings
        tfo_settings.clear_tfo_override()
        self._tmp = tempfile.mkdtemp()
        self.state_file = Path(self._tmp) / "state.json"

    def tearDown(self):
        self.tfo.clear_tfo_override()

    def test_default_off_no_state_file(self):
        self.assertFalse(self.tfo.is_tfo_enabled(self.state_file))

    def test_state_file_false(self):
        self.state_file.write_text(json.dumps({"tfo_enabled": False}))
        self.assertFalse(self.tfo.is_tfo_enabled(self.state_file))

    def test_state_file_true(self):
        self.state_file.write_text(json.dumps({"tfo_enabled": True}))
        self.assertTrue(self.tfo.is_tfo_enabled(self.state_file))

    def test_state_file_missing_key(self):
        self.state_file.write_text(json.dumps({"installed": True}))
        self.assertFalse(self.tfo.is_tfo_enabled(self.state_file))

    def test_state_file_corrupted(self):
        self.state_file.write_text("{not json")
        self.assertFalse(self.tfo.is_tfo_enabled(self.state_file))

    def test_override_true(self):
        self.tfo.set_tfo_override(True)
        self.assertTrue(self.tfo.is_tfo_enabled(self.state_file))

    def test_override_beats_state(self):
        self.state_file.write_text(json.dumps({"tfo_enabled": True}))
        self.tfo.set_tfo_override(False)
        self.assertFalse(self.tfo.is_tfo_enabled(self.state_file))

    def test_clear_override_falls_back_to_state(self):
        self.state_file.write_text(json.dumps({"tfo_enabled": True}))
        self.tfo.set_tfo_override(False)
        self.tfo.clear_tfo_override()
        self.assertTrue(self.tfo.is_tfo_enabled(self.state_file))


class TestSetTfoState(unittest.TestCase):
    """set_tfo_state: merge-запись в state.json (не затирает чужие ключи)."""

    def setUp(self):
        from chimera.modules import tfo_settings
        self.tfo = tfo_settings
        tfo_settings.clear_tfo_override()
        self._tmp = tempfile.mkdtemp()
        self.state_file = Path(self._tmp) / "state.json"

    def tearDown(self):
        self.tfo.clear_tfo_override()

    def test_write_creates_file(self):
        self.assertTrue(self.tfo.set_tfo_state(True, self.state_file))
        data = json.loads(self.state_file.read_text())
        self.assertTrue(data["tfo_enabled"])

    def test_write_merges(self):
        self.state_file.write_text(json.dumps({"domain": "x.com", "uuid": "u"}))
        self.assertTrue(self.tfo.set_tfo_state(False, self.state_file))
        data = json.loads(self.state_file.read_text())
        self.assertFalse(data["tfo_enabled"])
        self.assertEqual(data["domain"], "x.com")
        self.assertEqual(data["uuid"], "u")

    def test_write_false_then_true(self):
        self.tfo.set_tfo_state(False, self.state_file)
        self.tfo.set_tfo_state(True, self.state_file)
        data = json.loads(self.state_file.read_text())
        self.assertTrue(data["tfo_enabled"])


class TestSockoptDialFields(unittest.TestCase):
    """tfo_sockopt / tfo_dial — формы полей для Xray и sing-box."""

    def setUp(self):
        from chimera.modules import tfo_settings
        self.tfo = tfo_settings
        tfo_settings.clear_tfo_override()

    def tearDown(self):
        self.tfo.clear_tfo_override()

    def test_sockopt_empty_by_default(self):
        self.assertEqual(self.tfo.tfo_sockopt(), {})

    def test_sockopt_when_enabled(self):
        self.tfo.set_tfo_override(True)
        self.assertEqual(self.tfo.tfo_sockopt(), {"tcpFastOpen": True})

    def test_dial_empty_by_default(self):
        self.assertEqual(self.tfo.tfo_dial(), {})

    def test_dial_when_enabled(self):
        self.tfo.set_tfo_override(True)
        self.assertEqual(self.tfo.tfo_dial(), {"tcp_fast_open": True})


class TestApplyTfoToXrayConfig(unittest.TestCase):
    """apply_tfo_to_xray_config: живой патчер /etc/xray/config.json."""

    def setUp(self):
        from chimera.modules import tfo_settings
        self.tfo = tfo_settings
        tfo_settings.clear_tfo_override()
        self._tmp = tempfile.mkdtemp()
        self.cfg_path = Path(self._tmp) / "config.json"
        self.cfg_path.write_text(json.dumps({
            "inbounds": [
                {"tag": "inbound-vless", "streamSettings": {
                    "network": "tcp",
                    "sockopt": {"tcpFastOpen": True,
                                "tcpKeepAliveInterval": 15}}},
                {"tag": "xray-stats-api", "port": 10085},  # без streamSettings
            ],
            "outbounds": [
                {"tag": "chain-exit-1", "protocol": "vless",
                 "streamSettings": {
                     "sockopt": {"tcpFastOpen": True, "mark": 1000,
                                 "fragment": {"packets": "1-3"}}}},
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "proxy", "streamSettings": {"sockopt": {
                    "tcpKeepAliveIdle": 60}}},  # sockopt без TFO
            ],
        }))

    def tearDown(self):
        self.tfo.clear_tfo_override()

    def _read(self):
        return json.loads(self.cfg_path.read_text())

    def test_disable_removes_everywhere_and_keeps_rest(self):
        added, removed = self.tfo.apply_tfo_to_xray_config(
            False, self.cfg_path)
        self.assertEqual((added, removed), (0, 2))
        cfg = self._read()
        for section in ("inbounds", "outbounds"):
            for ent in cfg[section]:
                so = ent.get("streamSettings", {}).get("sockopt", {})
                self.assertNotIn("tcpFastOpen", so)
        # Остальные поля не тронуты
        inb = cfg["inbounds"][0]["streamSettings"]["sockopt"]
        self.assertEqual(inb["tcpKeepAliveInterval"], 15)
        chain = cfg["outbounds"][0]["streamSettings"]["sockopt"]
        self.assertEqual(chain["mark"], 1000)
        self.assertEqual(chain["fragment"]["packets"], "1-3")

    def test_enable_adds_everywhere(self):
        self.tfo.apply_tfo_to_xray_config(False, self.cfg_path)  # очистить
        added, removed = self.tfo.apply_tfo_to_xray_config(
            True, self.cfg_path)
        # 3 места с streamSettings.sockopt: inbound + chain-exit + proxy
        self.assertEqual((added, removed), (3, 0))
        cfg = self._read()
        for section in ("inbounds", "outbounds"):
            for ent in cfg[section]:
                ss = ent.get("streamSettings")
                if ss is not None:
                    self.assertTrue(
                        ss["sockopt"].get("tcpFastOpen"),
                        f"{ent.get('tag')}: TFO должен быть добавлен")

    def test_idempotent(self):
        self.tfo.apply_tfo_to_xray_config(True, self.cfg_path)
        added, removed = self.tfo.apply_tfo_to_xray_config(
            True, self.cfg_path)
        self.assertEqual((added, removed), (0, 0))

    def test_missing_file_returns_zero(self):
        added, removed = self.tfo.apply_tfo_to_xray_config(
            True, Path(self._tmp) / "nope.json")
        self.assertEqual((added, removed), (0, 0))

    def test_stats_inbound_without_streamsettings_untouched(self):
        """dokodemo-door (stats) не получает streamSettings/sockopt."""
        self.tfo.apply_tfo_to_xray_config(True, self.cfg_path)
        cfg = self._read()
        stats = cfg["inbounds"][1]
        self.assertNotIn("streamSettings", stats)


class TestBuildSockoptIntegration(unittest.TestCase):
    """_core._build_sockopt: TFO нет по умолчанию, есть при override."""

    def setUp(self):
        from chimera.modules import tfo_settings
        self.tfo = tfo_settings
        tfo_settings.clear_tfo_override()
        _setup_core_in_sysmodules()

    def tearDown(self):
        self.tfo.clear_tfo_override()

    def test_no_tfo_by_default(self):
        core = sys.modules["chimera._core"]
        s = core._build_sockopt()
        self.assertNotIn("tcpFastOpen", s)
        for key in ("tcpKeepAliveInterval", "tcpKeepAliveIdle",
                    "tcpUserTimeout", "tcpCongestion"):
            self.assertIn(key, s)

    def test_tfo_when_override_enabled(self):
        core = sys.modules["chimera._core"]
        self.tfo.set_tfo_override(True)
        s = core._build_sockopt()
        self.assertTrue(s.get("tcpFastOpen"))

    def test_xhttp_settings_no_tfo_by_default(self):
        """_build_xhttp_settings (sockopt для xHTTP) — тоже без TFO."""
        core = sys.modules["chimera._core"]
        _xhttp, sockopt = core._build_xhttp_settings("stream-up", "/x")
        self.assertNotIn("tcpFastOpen", sockopt)


class TestCoreBindingsRegression(unittest.TestCase):
    """Регрессия инцидента 29.08.2026 (меню T на проде):

    AttributeError: module '__main__' has no attribute 'error' —
    tfo_settings дергал core.error, которого в _core.py НЕТ
    (есть только info/success/warn + log_to_file). main.py исполняет
    _core.py в namespace __main__, поэтому вылетает именно так.

    Тест №1 ловит ВЕСЬ класс багов: каждое core.X из tfo_settings.py
    обязано существовать в реальном _core.py.
    Тест №2: core.error больше не запрашивается вообще (хелпер _error).
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import tfo_settings
        self.tfo = tfo_settings
        self.tfo.clear_tfo_override()

    def test_every_core_attr_exists_in_real_core(self):
        import re
        src = (_PROJECT_ROOT / "chimera" / "modules" / "tfo_settings.py").read_text()
        # (?<![\w.]) — не матчим «_core.py» из комментариев: реальный доступ
        # core.X в коде идёт после пробела/скобки/оператора, не после буквы
        attrs = set(re.findall(r"(?<![\w.])core\.([A-Za-z_]\w*)", src))
        self.assertTrue(attrs, "regex сломан — не найдено ни одного core.X")
        core = sys.modules["chimera._core"]
        missing = sorted(a for a in attrs if not hasattr(core, a))
        self.assertEqual(
            missing, [],
            f"tfo_settings дергает core.{'/'.join(missing)}, но в _core.py "
            f"этого нет — будет AttributeError на проде")

    def test_core_error_never_requested(self):
        import re
        src = (_PROJECT_ROOT / "chimera" / "modules" / "tfo_settings.py").read_text()
        self.assertNotIn(
            "core.error", src,
            "core.error не существует в _core.py — используйте локальный "
            "хелпер _error() (инцидент 29.08.2026)")


class TestMenuTSmoke(unittest.TestCase):
    """Smoke-прогон UI-функций TFO: отрисовка меню/промпта не падает
    (ловит и NameError отзабинженных локалов — _box_desc/_box_back)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import tfo_settings
        self.tfo = tfo_settings
        self.tfo.clear_tfo_override()

    def tearDown(self):
        self.tfo.clear_tfo_override()

    def test_manage_menu_renders_and_exits(self):
        """Меню T: полная отрисовка (все box-функции) + выход по 'b'.
        До фикса падало: AttributeError core.error (до input) и
        NameError _box_desc/_box_back (при отрисовке)."""
        with patch("builtins.input", return_value="b"):
            self.tfo.do_manage_tfo()  # не должно бросить ничего

    def test_prompt_choice_default_is_off(self):
        """Промпт установки: Enter по умолчанию = ВЫКЛЮЧИТЬ."""
        with patch("builtins.input", return_value=""):
            enabled = self.tfo.prompt_tfo_choice()
        self.assertFalse(enabled)
        self.assertFalse(self.tfo.is_tfo_enabled())

    def test_prompt_choice_explicit_on(self):
        with patch("builtins.input", return_value="2"):
            enabled = self.tfo.prompt_tfo_choice()
        self.assertTrue(enabled)
        self.assertTrue(self.tfo.is_tfo_enabled())

    def test_tfo_apply_no_config_branch(self):
        """_tfo_apply при отсутствии config.json: state пишется, xray
        не трогается (warn-ветка). Проверяет привязки info/success/warn."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            old_state, old_cfg = self.tfo.STATE_FILE, self.tfo.XRAY_CONFIG
            self.tfo.STATE_FILE = Path(td) / "state.json"
            self.tfo.XRAY_CONFIG = Path(td) / "config.json"
            try:
                self.tfo._tfo_apply(False)
                data = json.loads(self.tfo.STATE_FILE.read_text())
                self.assertFalse(data["tfo_enabled"])
                self.assertFalse(self.tfo.is_tfo_enabled())
            finally:
                self.tfo.STATE_FILE, self.tfo.XRAY_CONFIG = old_state, old_cfg


if __name__ == "__main__":
    unittest.main(verbosity=2)
