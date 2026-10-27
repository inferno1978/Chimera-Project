#!/usr/bin/env python3
"""
tests/test_fragment_config.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/fragment_config.py.

Покрывает:
  1. build_fragment_sockopt — генерация sockopt dict
  2. _validate_range_str — валидация диапазонов "3-7"
  3. _FRAGMENT_PRESETS — структура пресетов
  4. generate_fragment_client_config — генерация конфига (mocked state)
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


class TestBuildFragmentSockopt(unittest.TestCase):
    """build_fragment_sockopt — pure dict builder."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_dict_with_required_keys(self):
        from chimera.modules.fragment_config import build_fragment_sockopt
        s = build_fragment_sockopt()
        # TFO (tcpFastOpen) УБРАН из дефолта — инцидент 28.08.2026 (DPI
        # резал data-in-SYN). Проверяем что базовые поля на месте.
        for key in ("tcpKeepAliveInterval", "tcpKeepAliveIdle",
                     "tcpUserTimeout", "tcpCongestion", "fragment"):
            self.assertIn(key, s)
        self.assertNotIn("tcpFastOpen", s,
                         "TFO не должен быть в sockopt по умолчанию")

    def test_default_values(self):
        from chimera.modules.fragment_config import build_fragment_sockopt
        s = build_fragment_sockopt()
        self.assertNotIn("tcpFastOpen", s)
        self.assertEqual(s["tcpCongestion"], "bbr")
        self.assertEqual(s["fragment"]["packets"], "1-3")
        self.assertEqual(s["fragment"]["length"], "3-7")
        self.assertEqual(s["fragment"]["interval"], "10-20")

    def test_tfo_added_when_enabled(self):
        """При включённом TFO (override) поле tcpFastOpen появляется."""
        from chimera.modules import tfo_settings
        from chimera.modules.fragment_config import build_fragment_sockopt
        tfo_settings.set_tfo_override(True)
        try:
            s = build_fragment_sockopt()
            self.assertTrue(s.get("tcpFastOpen"))
        finally:
            tfo_settings.clear_tfo_override()

    def test_custom_values(self):
        from chimera.modules.fragment_config import build_fragment_sockopt
        s = build_fragment_sockopt(packets="5-10", length="100-200", interval="50-100")
        self.assertEqual(s["fragment"]["packets"], "5-10")
        self.assertEqual(s["fragment"]["length"], "100-200")
        self.assertEqual(s["fragment"]["interval"], "50-100")


class TestValidateRangeStr(unittest.TestCase):
    """_validate_range_str — валидатор диапазонов."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_single_number_valid(self):
        from chimera.modules.fragment_config import _validate_range_str
        self.assertTrue(_validate_range_str("3", "test"))
        self.assertTrue(_validate_range_str("10", "test"))

    def test_range_valid(self):
        from chimera.modules.fragment_config import _validate_range_str
        self.assertTrue(_validate_range_str("3-7", "test"))
        self.assertTrue(_validate_range_str("1-100", "test"))

    def test_zero_invalid(self):
        from chimera.modules.fragment_config import _validate_range_str
        self.assertFalse(_validate_range_str("0", "test"))
        self.assertFalse(_validate_range_str("0-5", "test"))

    def test_reversed_range_invalid(self):
        from chimera.modules.fragment_config import _validate_range_str
        self.assertFalse(_validate_range_str("7-3", "test"))

    def test_non_numeric_invalid(self):
        from chimera.modules.fragment_config import _validate_range_str
        self.assertFalse(_validate_range_str("abc", "test"))
        self.assertFalse(_validate_range_str("a-b", "test"))

    def test_three_parts_invalid(self):
        from chimera.modules.fragment_config import _validate_range_str
        self.assertFalse(_validate_range_str("3-7-9", "test"))

    def test_strips_whitespace(self):
        from chimera.modules.fragment_config import _validate_range_str
        self.assertTrue(_validate_range_str("  3-7  ", "test"))

    def test_tlshello_valid_for_packets(self):
        """Спец-значение 'tlshello' валидно ТОЛЬКО для поля packets
        (Xray sockopt.fragment.packets — фрагментировать до конца
        TLS ClientHello; живая валидация xray run -test 26.10.21 OK)."""
        from chimera.modules.fragment_config import _validate_range_str
        self.assertTrue(_validate_range_str("tlshello", "packets"))

    def test_tlshello_case_insensitive_and_whitespace(self):
        from chimera.modules.fragment_config import _validate_range_str
        self.assertTrue(_validate_range_str("TLSHELLO", "packets"))
        self.assertTrue(_validate_range_str("  tlshello ", "packets"))

    def test_tlshello_invalid_for_length_and_interval(self):
        """tlshello — спец-значение только packets; для length/interval
        оно невалидно (там Xray ждёт числовой диапазон)."""
        from chimera.modules.fragment_config import _validate_range_str
        self.assertFalse(_validate_range_str("tlshello", "length"))
        self.assertFalse(_validate_range_str("tlshello", "interval"))
        self.assertFalse(_validate_range_str("tlshello", "test"))


class TestFragmentPresets(unittest.TestCase):
    """_FRAGMENT_PRESETS — структура."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_aggressive_balanced_light_custom(self):
        from chimera.modules.fragment_config import _FRAGMENT_PRESETS
        for name in ("aggressive", "balanced", "light", "custom"):
            self.assertIn(name, _FRAGMENT_PRESETS)

    def test_each_preset_has_required_keys(self):
        from chimera.modules.fragment_config import _FRAGMENT_PRESETS
        for name, preset in _FRAGMENT_PRESETS.items():
            with self.subTest(preset=name):
                for key in ("packets", "length", "interval", "desc"):
                    self.assertIn(key, preset)


class TestGenerateFragmentClientConfig(unittest.TestCase):
    """generate_fragment_client_config — генерация конфига."""

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
            patch("chimera.modules.fragment_config._STATE_FILE", self._state),
            patch("chimera.modules.fragment_config._FRAGMENT_DIR", self._frag_dir),
        )

    def test_returns_none_when_no_state(self):
        from chimera.modules.fragment_config import generate_fragment_client_config
        with self._patch()[0], self._patch()[1]:
            result = generate_fragment_client_config("1-3", "3-7", "10-20")
        self.assertIsNone(result)

    def test_returns_none_when_no_domain(self):
        from chimera.modules.fragment_config import generate_fragment_client_config
        self._state.write_text(json.dumps({"uuid": "abc"}))
        with self._patch()[0], self._patch()[1]:
            result = generate_fragment_client_config("1-3", "3-7", "10-20")
        self.assertIsNone(result)

    def test_returns_none_when_no_uuid(self):
        from chimera.modules.fragment_config import generate_fragment_client_config
        self._state.write_text(json.dumps({"domain": "x.com"}))
        with self._patch()[0], self._patch()[1]:
            result = generate_fragment_client_config("1-3", "3-7", "10-20")
        self.assertIsNone(result)

    def test_generates_reality_config(self):
        from chimera.modules.fragment_config import generate_fragment_client_config
        self._state.write_text(json.dumps({
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "reality",
            "reality_dest": "dest.example.com:443",
            "reality_pubkey": "PUBKEY",
            "reality_privkey": "PRIVKEY",
            "reality_shortid": "abcd1234",
        }))
        with self._patch()[0], self._patch()[1]:
            result = generate_fragment_client_config("1-3", "3-7", "10-20", label="test")
        self.assertIsNotNone(result)
        self.assertTrue(result.exists())
        content = result.read_text()
        self.assertIn("vpn.example.com", content)
        self.assertIn("test-uuid", content)

    def test_generates_xhttp_reality_config(self):
        """xhttp_reality: транспорт xhttp + REALITY TLS, БЕЗ flow."""
        from chimera.modules.fragment_config import generate_fragment_client_config
        self._state.write_text(json.dumps({
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "xhttp_reality",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
            "fingerprint": "firefox",
            "xhttp_path": "/xhttp",
            "xhttp_mode": "stream-up",
            "xtls_flow": "xtls-rprx-vision",
        }))
        with self._patch()[0], self._patch()[1]:
            result = generate_fragment_client_config("1-3", "3-7", "10-20",
                                                     label="xhttpreality")
        self.assertIsNotNone(result)
        self.assertTrue(result.exists())
        data = json.loads(result.read_text())
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
        self.assertEqual(rs["spiderX"], "/")
        # фрагментация на месте
        self.assertEqual(ss["sockopt"]["fragment"]["length"], "3-7")

    def test_generates_xhttp_reality_config_awg_sni(self):
        """xhttp_reality + AWG Mode B: SNI = reality_dest (serverNames)."""
        from chimera.modules.fragment_config import generate_fragment_client_config
        self._state.write_text(json.dumps({
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "xhttp_reality",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
            "awg_exit_enabled": True,
            "install_mode": "B",
            "reality_dest": "dest.example.com:443",
        }))
        with self._patch()[0], self._patch()[1]:
            result = generate_fragment_client_config("1-3", "3-7", "10-20",
                                                     label="xhttprealityawg")
        self.assertIsNotNone(result)
        data = json.loads(result.read_text())
        rs = data["outbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(rs["serverName"], "dest.example.com")

    def test_sanitizes_label(self):
        """label с пробелами и спецсимволами — санитизируется."""
        from chimera.modules.fragment_config import generate_fragment_client_config
        self._state.write_text(json.dumps({
            "domain": "x.com", "uuid": "u",
            "protocol_mode": "reality",
            "reality_dest": "d:443", "reality_pubkey": "p",
            "reality_privkey": "k", "reality_shortid": "s",
        }))
        with self._patch()[0], self._patch()[1]:
            result = generate_fragment_client_config("1-3", "3-7", "10-20",
                                                     label="test name!@#")
        self.assertIsNotNone(result)
        # имя файла должно содержать только alnum/-/_
        for c in result.name:
            self.assertTrue(c.isalnum() or c in "-_.")

    def test_generates_config_with_tlshello_packets(self):
        """packets='tlshello' проходит насквозь в sockopt.fragment
        (рецепт DPI/CHECKER окт-2026)."""
        from chimera.modules.fragment_config import generate_fragment_client_config
        self._state.write_text(json.dumps({
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "reality",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
        }))
        with self._patch()[0], self._patch()[1]:
            result = generate_fragment_client_config(
                "tlshello", "10-20", "10-20", label="tlshello_recipe")
        self.assertIsNotNone(result)
        data = json.loads(result.read_text())
        frag = (data["outbounds"][0]["streamSettings"]["sockopt"]["fragment"])
        self.assertEqual(frag["packets"], "tlshello")
        self.assertEqual(frag["length"], "10-20")
        self.assertEqual(frag["interval"], "10-20")
        # noise не добавлен — комбо опционально
        self.assertNotIn("noise",
                         data["outbounds"][0]["streamSettings"]["sockopt"])

    def test_generates_config_with_fragment_and_noise(self):
        """Комбо fragment+noise одной генерацией: noise_packet+noise_delay
        → sockopt.noise появляется; без них — нет (обратная совместимость)."""
        from chimera.modules.fragment_config import generate_fragment_client_config
        self._state.write_text(json.dumps({
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "reality",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
        }))
        with self._patch()[0], self._patch()[1]:
            result = generate_fragment_client_config(
                "1-3", "10-20", "10-20", label="combo_noise",
                noise_packet="10-20", noise_delay="5-10")
        self.assertIsNotNone(result)
        data = json.loads(result.read_text())
        sockopt = data["outbounds"][0]["streamSettings"]["sockopt"]
        self.assertEqual(sockopt["fragment"]["length"], "10-20")
        self.assertIn("noise", sockopt)
        self.assertEqual(sockopt["noise"][0]["type"], "rand")
        self.assertEqual(sockopt["noise"][0]["packet"], "10-20")
        self.assertEqual(sockopt["noise"][0]["delay"], "5-10")


class TestClientFragmentSettings(unittest.TestCase):
    """get_client_fragment_settings / _save_client_fragment_state —
    тумблер fragment-аддона дефолтного экспорта."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_none_when_absent_or_disabled(self):
        from chimera.modules.fragment_config import get_client_fragment_settings
        self.assertIsNone(get_client_fragment_settings({}))
        self.assertIsNone(get_client_fragment_settings(
            {"client_fragment": {"enabled": False, "packets": "1-3"}}))
        self.assertIsNone(get_client_fragment_settings(
            {"client_fragment": {}}))

    def test_returns_none_when_params_incomplete(self):
        """Честный экспорт: неполные параметры = выключено (None)."""
        from chimera.modules.fragment_config import get_client_fragment_settings
        self.assertIsNone(get_client_fragment_settings(
            {"client_fragment": {"enabled": True, "packets": "1-3"}}))
        self.assertIsNone(get_client_fragment_settings(
            {"client_fragment": {"enabled": True, "packets": "1-3",
                                  "length": "", "interval": "10-20"}}))

    def test_returns_settings_when_enabled(self):
        from chimera.modules.fragment_config import get_client_fragment_settings
        cf = {"enabled": True, "packets": "tlshello",
              "length": "10-20", "interval": "10-20"}
        got = get_client_fragment_settings({"client_fragment": cf})
        self.assertEqual(got, {"packets": "tlshello",
                               "length": "10-20", "interval": "10-20"})

    def test_returns_none_for_non_dict_input(self):
        from chimera.modules.fragment_config import get_client_fragment_settings
        self.assertIsNone(get_client_fragment_settings(None))
        self.assertIsNone(get_client_fragment_settings(
            {"client_fragment": "garbage"}))

    def test_save_roundtrip_preserves_other_state(self):
        """_save_client_fragment_state не затирает остальные ключи state.json
        и округляет блок client_fragment через get_client_fragment_settings."""
        import tempfile
        from chimera.modules import fragment_config
        tmpdir = Path(tempfile.mkdtemp())
        state_file = tmpdir / "state.json"
        state_file.write_text(json.dumps({
            "domain": "x.com", "uuid": "u", "client_fragment": {"enabled": False},
        }))
        try:
            with patch("chimera.modules.fragment_config._STATE_FILE", state_file):
                ok = fragment_config._save_client_fragment_state(
                    {"enabled": True, "packets": "tlshello",
                     "length": "10-20", "interval": "10-20"})
                self.assertTrue(ok)
                st = json.loads(state_file.read_text())
                # остальной state цел
                self.assertEqual(st["domain"], "x.com")
                self.assertEqual(st["uuid"], "u")
                # блок записан и читается тумблером
                self.assertEqual(
                    fragment_config.get_client_fragment_settings(st),
                    {"packets": "tlshello", "length": "10-20",
                     "interval": "10-20"})
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
