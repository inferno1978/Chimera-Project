#!/usr/bin/env python3
"""
tests/test_fragment_config.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/fragment_config.py.

Покрывает:
  1. build_fragment_sockopt — sockopt основного outbound (dialerProxy)
  2. build_fragment_outbound — freedom-outbound с settings.fragment(+noises)
  3. _validate_range_str — валидация диапазонов "3-7"
  4. _FRAGMENT_PRESETS — структура пресетов
  5. generate_fragment_client_config — генерация конфига (mocked state)

Валидная схема Xray-core (infra/conf/freedom.go + transport_sockopt.go):
fragment/noises живут в settings freedom-outbound, основной outbound
цепляется через streamSettings.sockopt.dialerProxy. Поля fragment/noise
внутри sockopt ядром НЕ поддерживались (плацебо до фикса 2026-10-28).
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
    """build_fragment_sockopt — sockopt ОСНОВНОГО (proxy) outbound."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_dict_with_required_keys(self):
        from chimera.modules.fragment_config import build_fragment_sockopt
        s = build_fragment_sockopt()
        # TFO (tcpFastOpen) УБРАН из дефолта — инцидент 28.08.2026 (DPI
        # резал data-in-SYN). Проверяем что базовые поля на месте.
        for key in ("tcpKeepAliveInterval", "tcpKeepAliveIdle",
                     "tcpUserTimeout", "tcpCongestion", "dialerProxy"):
            self.assertIn(key, s)
        self.assertNotIn("tcpFastOpen", s,
                         "TFO не должен быть в sockopt по умолчанию")
        # Регрессия плацебо-схемы: в sockopt основного outbound НЕТ полей
        # fragment/noise — фрагментацию выполняет freedom-outbound.
        self.assertNotIn("fragment", s)
        self.assertNotIn("noise", s)

    def test_default_values(self):
        from chimera.modules.fragment_config import (
            build_fragment_sockopt, FRAGMENT_OUTBOUND_TAG,
        )
        s = build_fragment_sockopt()
        self.assertNotIn("tcpFastOpen", s)
        self.assertEqual(s["tcpCongestion"], "bbr")
        self.assertEqual(s["tcpKeepAliveInterval"], 15)
        self.assertEqual(s["tcpKeepAliveIdle"], 60)
        self.assertEqual(s["tcpUserTimeout"], 30000)
        # основное соединение набирается через freedom-outbound
        self.assertEqual(s["dialerProxy"], FRAGMENT_OUTBOUND_TAG)

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

    def test_custom_values_ignored_signature_compat(self):
        """packets/length/interval сохранены в сигнатуре только для
        совместимости вызовов (fragment_link/mux/fuzzer): на результат они
        НЕ влияют — значения фрагментации задаёт build_fragment_outbound,
        здесь всегда dialerProxy без placebo-ключей."""
        from chimera.modules.fragment_config import build_fragment_sockopt
        s = build_fragment_sockopt(packets="5-10", length="100-200", interval="50-100")
        self.assertEqual(s["dialerProxy"], "fragment")
        self.assertNotIn("fragment", s)
        self.assertNotIn("noise", s)


class TestStreamFinalmask(unittest.TestCase):
    """build_stream_finalmask/apply_stream_finalmask — DUAL-схема finalmask
    (миграция Xray 26.10.29: freedom.fragment deprecated →
    streamSettings.finalmask.tcp). Проставляется ВДОБАВОК к legacy-паре
    (freedom.settings.fragment + sockopt.dialerProxy), а не вместо неё;
    ядра < миграции поле молча игнорируют (encoding/json)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_structure_final_mask_recipe(self):
        """Структура = «Final Mask» (пастбин DPI/CHECKER): tcp→[{type,
        settings}], значения зеркалируют freedom.settings.fragment."""
        from chimera.modules.fragment_config import build_stream_finalmask
        fm = build_stream_finalmask("tlshello", "10-20", "10-20")
        self.assertEqual(fm, {"tcp": [{
            "type": "fragment",
            "settings": {"packets": "tlshello", "length": "10-20",
                         "interval": "10-20"},
        }]})

    def test_incomplete_params_return_none(self):
        """Неполные параметры → None: proxy-outbound остаётся чистым
        (как при пресете «0»)."""
        from chimera.modules.fragment_config import build_stream_finalmask
        self.assertIsNone(build_stream_finalmask("", "", ""))
        self.assertIsNone(build_stream_finalmask("tlshello", "", "10-20"))
        self.assertIsNone(build_stream_finalmask("", "10-20", "10-20"))

    def test_env_knob_off(self):
        """CHIMERA_FRAGMENT_FINALMASK=0 — escape-hatch (дефолт вкл)."""
        import os
        from chimera.modules.fragment_config import (
            build_stream_finalmask, apply_stream_finalmask)
        with patch.dict(os.environ, {"CHIMERA_FRAGMENT_FINALMASK": "0"}):
            self.assertIsNone(
                build_stream_finalmask("tlshello", "10-20", "10-20"))
            ob = {"tag": "proxy", "streamSettings": {}}
            self.assertIsNone(
                apply_stream_finalmask(ob, "tlshello", "10-20", "10-20"))
            self.assertNotIn("finalmask", ob["streamSettings"])
        # дефолт (переменной нет) — включено
        ob = {"tag": "proxy", "streamSettings": {}}
        fm = apply_stream_finalmask(ob, "tlshello", "10-20", "10-20")
        self.assertIsNotNone(fm)
        self.assertEqual(ob["streamSettings"]["finalmask"], fm)

    def test_apply_sets_on_stream_settings_keeps_legacy(self):
        """finalmask проставляется в streamSettings, legacy-пара не тронута:
        dual, а не замена."""
        from chimera.modules.fragment_config import apply_stream_finalmask
        ob = {"tag": "proxy",
              "streamSettings": {"sockopt": {"dialerProxy": "fragment"}}}
        fm = apply_stream_finalmask(ob, "tlshello", "10-20", "10-20")
        self.assertEqual(
            ob["streamSettings"]["finalmask"]["tcp"][0]["settings"]["packets"],
            "tlshello")
        self.assertIs(ob["streamSettings"]["finalmask"], fm)
        self.assertEqual(
            ob["streamSettings"]["sockopt"]["dialerProxy"], "fragment")


class TestBuildFragmentOutbound(unittest.TestCase):
    """build_fragment_outbound — freedom-outbound (валидная схема Xray-core)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_freedom_outbound_with_fragment_settings(self):
        from chimera.modules.fragment_config import (
            build_fragment_outbound, FRAGMENT_OUTBOUND_TAG,
        )
        ob = build_fragment_outbound()
        self.assertEqual(ob["tag"], FRAGMENT_OUTBOUND_TAG)
        self.assertEqual(ob["protocol"], "freedom")
        frag = ob["settings"]["fragment"]
        self.assertEqual(frag["packets"], "1-3")
        self.assertEqual(frag["length"], "3-7")
        self.assertEqual(frag["interval"], "10-20")
        # без noise-аргументов — ни noises, ни сингулярного noise
        self.assertNotIn("noises", ob["settings"])
        self.assertNotIn("noise", ob["settings"])

    def test_custom_values(self):
        from chimera.modules.fragment_config import build_fragment_outbound
        ob = build_fragment_outbound(
            packets="5-10", length="100-200", interval="50-100")
        self.assertEqual(ob["settings"]["fragment"]["packets"], "5-10")
        self.assertEqual(ob["settings"]["fragment"]["length"], "100-200")
        self.assertEqual(ob["settings"]["fragment"]["interval"], "50-100")

    def test_noises_added_when_noise_args_present(self):
        """noise_packet+noise_delay → массив noises в settings (комбо)."""
        from chimera.modules.fragment_config import build_fragment_outbound
        ob = build_fragment_outbound(noise_packet="100-200", noise_delay="50-100")
        noises = ob["settings"]["noises"]
        self.assertIsInstance(noises, list)
        self.assertEqual(len(noises), 1)
        self.assertEqual(noises[0]["type"], "rand")
        self.assertEqual(noises[0]["packet"], "100-200")
        self.assertEqual(noises[0]["delay"], "50-100")
        # сингулярный "noise" из Xray-core удалён — только массив noises
        self.assertNotIn("noise", ob["settings"])

    def test_noises_omitted_when_single_noise_arg(self):
        """Комбо «обе или ни одной»: один noise-аргумент — noises НЕТ."""
        from chimera.modules.fragment_config import build_fragment_outbound
        ob = build_fragment_outbound(noise_packet="100-200")
        self.assertNotIn("noises", ob["settings"])
        self.assertNotIn("noise", ob["settings"])

    def test_custom_tag(self):
        from chimera.modules.fragment_config import build_fragment_outbound
        ob = build_fragment_outbound(tag="frag-custom")
        self.assertEqual(ob["tag"], "frag-custom")

    def test_tcp_tuning_in_stream_settings_sockopt(self):
        """TCP-тюнинг продублирован на freedom-outbound: фактический dial
        выполняет именно он (без dialerProxy — это терминальный dialer)."""
        from chimera.modules.fragment_config import build_fragment_outbound
        sso = build_fragment_outbound()["streamSettings"]["sockopt"]
        for key in ("tcpKeepAliveInterval", "tcpKeepAliveIdle",
                    "tcpUserTimeout", "tcpCongestion"):
            self.assertIn(key, sso)
        self.assertEqual(sso["tcpCongestion"], "bbr")
        self.assertNotIn("tcpFastOpen", sso)
        self.assertNotIn("dialerProxy", sso)
        # fragment/noise в sockopt — невалидная схема, их тут быть не должно
        self.assertNotIn("fragment", sso)
        self.assertNotIn("noise", sso)

    def test_tfo_added_when_enabled(self):
        from chimera.modules import tfo_settings
        from chimera.modules.fragment_config import build_fragment_outbound
        tfo_settings.set_tfo_override(True)
        try:
            sso = build_fragment_outbound()["streamSettings"]["sockopt"]
            self.assertTrue(sso.get("tcpFastOpen"))
        finally:
            tfo_settings.clear_tfo_override()


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
        # фрагментация на месте — валидная схема: freedom-outbound
        frag_obs = [ob for ob in data["outbounds"] if ob.get("tag") == "fragment"]
        self.assertEqual(len(frag_obs), 1,
                         "должен быть ровно один fragment-outbound")
        self.assertEqual(frag_obs[0]["protocol"], "freedom")
        self.assertEqual(frag_obs[0]["settings"]["fragment"]["length"], "3-7")
        # основной outbound цепляется через dialerProxy, без placebo-ключей
        self.assertEqual(ss["sockopt"]["dialerProxy"], "fragment")
        self.assertNotIn("fragment", ss["sockopt"])
        self.assertNotIn("noise", ss["sockopt"])

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
        """packets='tlshello' проходит насквозь в settings.fragment
        freedom-outbound (рецепт DPI/CHECKER окт-2026)."""
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
        proxy = data["outbounds"][0]
        sockopt = proxy["streamSettings"]["sockopt"]
        frag_ob = [ob for ob in data["outbounds"]
                   if ob.get("tag") == "fragment"][0]
        frag = frag_ob["settings"]["fragment"]
        self.assertEqual(frag["packets"], "tlshello")
        self.assertEqual(frag["length"], "10-20")
        self.assertEqual(frag["interval"], "10-20")
        # основной outbound: dialerProxy есть, fragment-ключа нет
        self.assertEqual(sockopt["dialerProxy"], "fragment")
        self.assertNotIn("fragment", sockopt)
        # DUAL-схема (31.10.2026): finalmask зеркалит fragment (миграция
        # Xray 26.10.29: freedom.fragment deprecated → finalmask.tcp)
        self.assertEqual(
            proxy["streamSettings"]["finalmask"],
            {"tcp": [{"type": "fragment",
                      "settings": {"packets": "tlshello", "length": "10-20",
                                   "interval": "10-20"}}]})
        # noise не добавлен — комбо опционально (ни noises, ни noise)
        self.assertNotIn("noises", frag_ob["settings"])
        self.assertNotIn("noise", frag_ob["settings"])
        self.assertNotIn("noise", sockopt)

    def test_fragment_outbound_settings_passthrough(self):
        """Значения packets/length/interval доезжают в settings.fragment
        freedom-outbound без искажений (не в sockopt!)."""
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
                "5-10", "100-200", "50-100", label="values_passthrough")
        self.assertIsNotNone(result)
        data = json.loads(result.read_text())
        frag_ob = [ob for ob in data["outbounds"]
                   if ob.get("tag") == "fragment"][0]
        self.assertEqual(frag_ob["settings"]["fragment"],
                         {"packets": "5-10", "length": "100-200",
                          "interval": "50-100"})

    def test_outbound_tags_unique(self):
        """Теги всех outbound уникальны (proxy/fragment/direct/block)."""
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
                "1-3", "3-7", "10-20", label="tags_unique")
        self.assertIsNotNone(result)
        data = json.loads(result.read_text())
        tags = [ob.get("tag") for ob in data["outbounds"]]
        self.assertEqual(len(tags), len(set(tags)),
                         f"теги outbound должны быть уникальны: {tags}")
        for expected in ("proxy", "fragment", "direct", "block"):
            self.assertIn(expected, tags)

    def test_generates_config_with_fragment_and_noise(self):
        """Комбо fragment+noise одной генерацией: noise_packet+noise_delay
        → noises в settings freedom-outbound; без них — нет (обратная
        совместимость)."""
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
        frag_ob = [ob for ob in data["outbounds"]
                   if ob.get("tag") == "fragment"][0]
        self.assertEqual(frag_ob["settings"]["fragment"]["length"], "10-20")
        noises = frag_ob["settings"]["noises"]
        self.assertEqual(noises[0]["type"], "rand")
        self.assertEqual(noises[0]["packet"], "10-20")
        self.assertEqual(noises[0]["delay"], "5-10")
        # основной outbound чист: dialerProxy, без fragment/noise
        self.assertEqual(sockopt["dialerProxy"], "fragment")
        self.assertNotIn("fragment", sockopt)
        self.assertNotIn("noise", sockopt)
        # сингулярный noise (удалён из Xray-core) не появляется нигде
        self.assertNotIn("noise", frag_ob["settings"])


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
