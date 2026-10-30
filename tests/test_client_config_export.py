#!/usr/bin/env python3
"""
tests/test_client_config_export.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/client_config_export.py — TUI генерация
клиентских конфигов (Clash Meta, Sing-box, Hiddify, VLESS-ссылка).

Покрывает:
  1. do_generate_client_config — генерация 4 файлов (clash/singbox/hiddify/vless-link)
  2. VLESS-ссылка содержит все параметры REALITY
  3. Hiddify JSON валиден и содержит routing rules
  4. SNI корректный для Mode A и Mode B + AWG
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

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
    return fake_core


_FAKE_STATE_REALITY = {
    "domain": "fleet-b.example",
    "server_port": 443,
    "protocol_mode": "reality",
    "install_mode": "A",
    "public_key": "TEST_PUB_KEY_123",
    "short_id": "abcd1234",
    "uuid": "test-uuid-1234",
    "fingerprint": "firefox",
    "xtls_flow": "xtls-rprx-vision",
    "xhttp_path": "/",
    "reality_dest": "",
    "awg_exit_enabled": False,
}

_FAKE_STATE_XHTTP = {
    **_FAKE_STATE_REALITY,
    "protocol_mode": "xhttp",
    "xhttp_path": "/xhttp",
}

_FAKE_STATE_XHTTP_REALITY = {
    **_FAKE_STATE_REALITY,
    "protocol_mode": "xhttp_reality",
    "xhttp_path": "/xhttp",
    "xhttp_mode": "stream-up",
}


class TestGenerateClientConfig(unittest.TestCase):
    """do_generate_client_config — генерация всех 4 файлов."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._state_file = Path(self._tmpdir) / "state.json"
        self._out_dir = Path(self._tmpdir) / "configs"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _run_generate(self, state_dict: dict):
        """Запускает do_generate_client_config с замоканным state.
        Файлы пишутся во временную директорию (патч out_dir).
        """
        from chimera.modules import client_config_export
        self._state_file.write_text(json.dumps(state_dict))
        self._out_dir = Path(self._tmpdir) / "configs"

        core = sys.modules.get("chimera._core")

        # Патчим Path("/root/xray-client-configs") на временную директорию.
        # do_generate_client_config использует: out_dir = Path("/root/xray-client-configs")
        # Патчим конструктор Path для этого конкретного пути.
        _orig_path_new = Path.__new__
        _orig_path_init = Path.__init__

        def _patched_new(cls, *args, **kwargs):
            p = _orig_path_new(cls, *args, **kwargs)
            return p

        def _patched_init(self, *args, **kwargs):
            _orig_path_init(self, *args, **kwargs)
            # Если путь = /root/xray-client-configs — подменяем на temp
            if str(self) == "/root/xray-client-configs":
                object.__setattr__(self, '_path', str(self._out_dir) if hasattr(self, '_out_dir') else str(self))

        # Простой подход: патчим модуль client_config_export так,
        # чтобы out_dir указывал на нашу временную директорию.
        # do_generate_client_config создаёт out_dir = Path("/root/xray-client-configs")
        # и затем out_dir.mkdir(exist_ok=True) и out_dir / "file.json"
        # Патчим Path.mkdir чтобы не падал на /root, и Path.__truediv__ чтобы
        # перехватить file paths. Но это слишком сложно.
        #
        # Альтернатива: запускаем с os.makedirs патчем и просто проверяем
        # что код не падает. А для проверки содержимого — мокаем write_text.
        #
        # Самый надёжный способ: патчить _box_ok (чтобы не печатать) и
        # перехватывать write_text через side_effect на уровне экземпляра.

        written = {}
        _orig_write = Path.write_text

        def _capture_write(self_path, data, *a, **kw):
            s = str(self_path)
            if "xray-client-configs" in s or "configs" in s:
                # Записываем во временную директорию
                name = Path(s).name
                dest = self._out_dir / name
                os.makedirs(str(dest.parent), exist_ok=True)
                _orig_write(dest, data, *a, **kw)
                written[name] = data
                return len(data)
            return _orig_write(self_path, data, *a, **kw)

        with patch.object(core, "STATE_FILE", self._state_file), \
             patch.object(client_config_export, "_core_module", return_value=core), \
             patch.object(Path, "write_text", _capture_write), \
             patch.object(Path, "mkdir", lambda self, *a, **kw: None):
            core._box_top = MagicMock()
            core._box_row = MagicMock()
            core._box_sep = MagicMock()
            core._box_bottom = MagicMock()
            core._box_ok = MagicMock()
            core._box_warn = MagicMock()
            core._box_info = MagicMock()
            core.log_to_file = MagicMock()
            client_config_export.do_generate_client_config()

        return written

    def test_generates_all_4_files(self):
        """Должны быть созданы 4 файла: clash, singbox, hiddify, vless-link."""
        written = self._run_generate(_FAKE_STATE_REALITY)
        filenames = [Path(p).name for p in written.keys()]
        self.assertIn("clash-meta.yaml", filenames)
        self.assertIn("sing-box.json", filenames)
        self.assertIn("hiddify.json", filenames)
        self.assertIn("vless-link.txt", filenames)

    def test_clash_config_has_reality_fields(self):
        written = self._run_generate(_FAKE_STATE_REALITY)
        clash = written.get("clash-meta.yaml", "")
        if not clash:
            self.skipTest("clash-meta.yaml not captured")
        self.assertIn("type: vless", clash)
        self.assertIn("fleet-b.example", clash)
        self.assertIn("TEST_PUB_KEY_123", clash)
        self.assertIn("abcd1234", clash)
        self.assertIn("xtls-rprx-vision", clash)

    def test_clash_reality_mlkem_recipe_b(self):
        """Рецепт B (Xray-core 26.9.8+): clash-meta.yaml REALITY-ветка —
        support-x25519mlkem768: true ВНУТРИ reality-opts и
        client-fingerprint: chrome (форсирован — фиксура state имеет
        fingerprint=firefox, но MLKEM768 есть только в HelloChrome mihomo).
        vless-link.txt сохраняет fp из state (Xray-семья клиентов)."""
        written = self._run_generate(_FAKE_STATE_REALITY)
        clash = written.get("clash-meta.yaml", "")
        if not clash:
            self.skipTest("clash-meta.yaml not captured")
        self.assertIn("support-x25519mlkem768: true", clash)
        self.assertIn("client-fingerprint: chrome", clash)
        self.assertNotIn("client-fingerprint: firefox", clash)
        # Порядок: флаг — поле RealityOptions (внутри reality-opts,
        # после short-id), client-fingerprint — уровень прокси
        i_ro  = clash.index("reality-opts:")
        i_sid = clash.index("short-id:")
        i_flg = clash.index("support-x25519mlkem768: true")
        i_cf  = clash.index("client-fingerprint: chrome")
        self.assertLess(i_ro, i_sid)
        self.assertLess(i_sid, i_flg)
        self.assertLess(i_flg, i_cf)
        # Источник правды для vless://-ссылок не тронут
        vless_link = written.get("vless-link.txt", "")
        if vless_link:
            self.assertIn("fp=firefox", vless_link)

    def test_singbox_config_valid_json(self):
        written = self._run_generate(_FAKE_STATE_REALITY)
        singbox_str = written.get("sing-box.json", "")
        if not singbox_str:
            self.skipTest("sing-box.json not captured")
        config = json.loads(singbox_str)
        self.assertIn("outbounds", config)
        ob = config["outbounds"][0]
        self.assertEqual(ob["type"], "vless")
        self.assertEqual(ob["server"], "fleet-b.example")

    def test_hiddify_config_has_routing(self):
        written = self._run_generate(_FAKE_STATE_REALITY)
        hiddify_str = written.get("hiddify.json", "")
        if not hiddify_str:
            self.skipTest("hiddify.json not captured")
        config = json.loads(hiddify_str)
        self.assertIn("routing", config)
        self.assertIn("rules", config["routing"])

    def test_vless_link_contains_all_params(self):
        written = self._run_generate(_FAKE_STATE_REALITY)
        vless_link = written.get("vless-link.txt", "")
        if not vless_link:
            self.skipTest("vless-link.txt not captured")
        self.assertIn("vless://", vless_link)
        self.assertIn("security=reality", vless_link)
        self.assertIn("fp=firefox", vless_link)
        self.assertIn("pbk=TEST_PUB_KEY_123", vless_link)
        self.assertIn("sid=abcd1234", vless_link)
        self.assertIn("flow=xtls-rprx-vision", vless_link)

    def test_xhttp_vless_link_has_path(self):
        written = self._run_generate(_FAKE_STATE_XHTTP)
        vless_link = written.get("vless-link.txt", "")
        if not vless_link:
            self.skipTest("vless-link.txt not captured")
        self.assertIn("security=tls", vless_link)
        # ФИКС: ранее тут было type=http (устаревший HTTP/2 транспорт).
        # Актуальный xHTTP Xray 1.8.16+ использует type=xhttp — это
        # синхронизировано с users_manager.py (где всегда type=xhttp).
        # Защита отката фикса — см. tests/test_ios_link_regression.py
        # ::TestClientConfigExportXhttpFix.
        self.assertIn("type=xhttp", vless_link)
        self.assertNotIn("type=http", vless_link)
        self.assertIn("path=", vless_link)

    def test_sni_correct_for_awg_mode_b(self):
        """Mode B + AWG: SNI = reality_dest, не domain."""
        state = {
            **_FAKE_STATE_REALITY,
            "install_mode": "B",
            "awg_exit_enabled": True,
            "reality_dest": "www.cloudflare.com",
        }
        written = self._run_generate(state)
        vless_link = written.get("vless-link.txt", "")
        if not vless_link:
            self.skipTest("vless-link.txt not captured")
        self.assertIn("sni=www.cloudflare.com", vless_link)
        self.assertNotIn("sni=fleet-b.example", vless_link)


class TestGenerateClientConfigXhttpReality(unittest.TestCase):
    """xHTTP + REALITY (третий protocol_mode) — vless/clash/singbox/hiddify."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._state_file = Path(self._tmpdir) / "state.json"
        self._out_dir = Path(self._tmpdir) / "configs"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _run_generate(self, state_dict: dict):
        from chimera.modules import client_config_export
        self._state_file.write_text(json.dumps(state_dict))
        core = sys.modules.get("chimera._core")
        written = {}
        _orig_write = Path.write_text

        def _capture_write(self_path, data, *a, **kw):
            s = str(self_path)
            if "xray-client-configs" in s or "configs" in s:
                name = Path(s).name
                dest = self._out_dir / name
                os.makedirs(str(dest.parent), exist_ok=True)
                _orig_write(dest, data, *a, **kw)
                written[name] = data
                return len(data)
            return _orig_write(self_path, data, *a, **kw)

        with patch.object(core, "STATE_FILE", self._state_file), \
             patch.object(client_config_export, "_core_module", return_value=core), \
             patch.object(Path, "write_text", _capture_write), \
             patch.object(Path, "mkdir", lambda self, *a, **kw: None):
            for _fn in ("_box_top", "_box_row", "_box_sep", "_box_bottom",
                        "_box_ok", "_box_warn", "_box_info"):
                setattr(core, _fn, MagicMock())
            core.log_to_file = MagicMock()
            client_config_export.do_generate_client_config()

        return written

    def test_vless_link_xhttp_reality(self):
        """vless:// для xhttp_reality: type=xhttp + security=reality,
        pbk/sid присутствуют, mode= из state, БЕЗ flow."""
        written = self._run_generate(_FAKE_STATE_XHTTP_REALITY)
        vless_link = written.get("vless-link.txt", "")
        if not vless_link:
            self.skipTest("vless-link.txt not captured")
        self.assertIn("security=reality", vless_link)
        self.assertIn("type=xhttp", vless_link)
        self.assertIn("pbk=TEST_PUB_KEY_123", vless_link)
        self.assertIn("sid=abcd1234", vless_link)
        self.assertIn("fp=firefox", vless_link)
        self.assertIn("mode=stream-up", vless_link)
        self.assertIn("path=%2Fxhttp", vless_link)
        # flow быть НЕ должно (xhttp-транспорт не поддерживает vision)
        self.assertNotIn("flow=", vless_link)
        self.assertIn("#VLESS-xHTTP-REALITY", vless_link)

    def test_clash_xhttp_reality_not_generated(self):
        """Честный экспорт (баг 4): mihomo не поддерживает xHTTP —
        clash-meta.yaml для xhttp_reality НЕ генерируется."""
        written = self._run_generate(_FAKE_STATE_XHTTP_REALITY)
        self.assertNotIn("clash-meta.yaml", written,
                         "clash-meta.yaml не должен генерироваться для "
                         "xhttp_reality (mihomo не поддерживает xHTTP)")

    def test_singbox_hiddify_xhttp_reality_not_generated(self):
        """Честный экспорт (баг 3): sing-box не поддерживает транспорт
        xhttp — sing-box.json/hiddify.json НЕ генерируются, ios-дубль тоже."""
        written = self._run_generate(_FAKE_STATE_XHTTP_REALITY)
        self.assertNotIn("sing-box.json", written,
                         "sing-box.json не должен генерироваться для "
                         "xhttp_reality (unknown transport type: xhttp)")
        self.assertNotIn("hiddify.json", written,
                         "hiddify.json не должен генерироваться (ядро sing-box)")
        self.assertNotIn("vless-link-ios.txt", written,
                         "iOS-дубль ссылки не нужен: Karing/V2Box — sing-box)")
        # vless-ссылка при этом обязана быть — единственный рабочий формат
        self.assertIn("vless-link.txt", written)

    def test_xhttp_reality_sni_awg_mode_b(self):
        """SNI-правило REALITY наследуется: Mode B + AWG → reality_dest."""
        state = {
            **_FAKE_STATE_XHTTP_REALITY,
            "install_mode": "B",
            "awg_exit_enabled": True,
            "reality_dest": "www.cloudflare.com",
        }
        written = self._run_generate(state)
        vless_link = written.get("vless-link.txt", "")
        if not vless_link:
            self.skipTest("vless-link.txt not captured")
        self.assertIn("sni=www.cloudflare.com", vless_link)
        # Честный экспорт: sing-box для xhttp_reality не генерируется вовсе
        self.assertNotIn("sing-box.json", written)


_FRAG_ADDON_FILES = (
    "xray-client-fragment.json",
    "singbox-client-fragment.json",
    "vless-links-fragment.txt",
)

_FAKE_STATE_REALITY_FRAG_ON = {
    **_FAKE_STATE_REALITY,
    "client_fragment": {
        "enabled": True,
        "packets": "tlshello",
        "length": "10-20",
        "interval": "10-20",
    },
}


class TestExportFragmentAddon(unittest.TestCase):
    """Fragment-аддон дефолтного экспорта (тумблер client_fragment).

    ВЫКЛ (дефолт): набор файлов байт-в-байт прежний — fragment-файлов нет.
    ВКЛ: ДОПОЛНИТЕЛЬНО xray-client-fragment.json + singbox-client-fragment.json
    (только reality) + vless-links-fragment.txt; существующие файлы не меняются.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._state_file = Path(self._tmpdir) / "state.json"
        self._out_dir = Path(self._tmpdir) / "configs"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _run_generate(self, state_dict: dict):
        from chimera.modules import client_config_export
        self._state_file.write_text(json.dumps(state_dict))
        core = sys.modules.get("chimera._core")
        written = {}
        _orig_write = Path.write_text

        def _capture_write(self_path, data, *a, **kw):
            s = str(self_path)
            if "xray-client-configs" in s or "configs" in s:
                name = Path(s).name
                dest = self._out_dir / name
                os.makedirs(str(dest.parent), exist_ok=True)
                _orig_write(dest, data, *a, **kw)
                written[name] = data
                return len(data)
            return _orig_write(self_path, data, *a, **kw)

        with patch.object(core, "STATE_FILE", self._state_file), \
             patch.object(client_config_export, "_core_module", return_value=core), \
             patch.object(Path, "write_text", _capture_write), \
             patch.object(Path, "mkdir", lambda self, *a, **kw: None):
            for _fn in ("_box_top", "_box_row", "_box_sep", "_box_bottom",
                        "_box_ok", "_box_warn", "_box_info"):
                setattr(core, _fn, MagicMock())
            core.log_to_file = MagicMock()
            client_config_export.do_generate_client_config()

        return written

    def test_fragment_files_absent_when_toggle_off(self):
        """Регрессия: тумблер ВЫКЛ — fragment-файлов нет, дефолтный набор
        не изменился (обратная совместимость 100%)."""
        written = self._run_generate(_FAKE_STATE_REALITY)
        for fname in _FRAG_ADDON_FILES:
            self.assertNotIn(fname, written,
                             f"{fname} не должен генерироваться при "
                             f"client_fragment=OFF")

    def test_fragment_files_generated_when_toggle_on(self):
        """Тумблер ВКЛ (reality): три доп. файла; vless-link.txt и прочие
        дефолтные файлы не изменились."""
        written_off = self._run_generate(_FAKE_STATE_REALITY)
        written_on = self._run_generate(_FAKE_STATE_REALITY_FRAG_ON)

        self.assertIn("xray-client-fragment.json", written_on)
        self.assertIn("singbox-client-fragment.json", written_on)
        self.assertIn("vless-links-fragment.txt", written_on)

        # Дефолтные файлы не изменились
        for fname in ("clash-meta.yaml", "sing-box.json", "hiddify.json",
                      "vless-link.txt"):
            self.assertIn(fname, written_on)
            self.assertEqual(written_on[fname], written_off[fname],
                             f"{fname} не должен меняться при включении "
                             f"fragment-аддона")

    def test_xray_fragment_json_contains_fragment(self):
        """Xray JSON (v2rayN/v2rayNG): валидная схема — параметры тумблера
        (tlshello-рецепт) в settings.fragment freedom-outbound."""
        written = self._run_generate(_FAKE_STATE_REALITY_FRAG_ON)
        xray_cfg = json.loads(written["xray-client-fragment.json"])
        frag_obs = [ob for ob in xray_cfg["outbounds"]
                    if ob.get("tag") == "fragment"]
        self.assertEqual(len(frag_obs), 1,
                         "должен быть ровно один fragment-outbound")
        self.assertEqual(frag_obs[0]["protocol"], "freedom")
        frag = frag_obs[0]["settings"]["fragment"]
        self.assertEqual(frag["packets"], "tlshello")
        self.assertEqual(frag["length"], "10-20")
        self.assertEqual(frag["interval"], "10-20")
        # тумблер не передаёт noise-аргументы — noises нет (и noise тоже)
        self.assertNotIn("noises", frag_obs[0]["settings"])
        self.assertNotIn("noise", frag_obs[0]["settings"])
        proxy = [ob for ob in xray_cfg["outbounds"] if ob["tag"] == "proxy"][0]
        # REALITY-параметры на месте (транспорт не пострадал)
        rs = proxy["streamSettings"]["realitySettings"]
        self.assertEqual(rs["publicKey"], "TEST_PUB_KEY_123")
        self.assertEqual(rs["shortId"], "abcd1234")

    def test_xray_fragment_json_valid_schema_dialer_proxy(self):
        """Регрессия плацебо-схемы: основной outbound — dialerProxy="fragment",
        БЕЗ placebo-ключей fragment/noise/noises в sockopt; теги уникальны."""
        written = self._run_generate(_FAKE_STATE_REALITY_FRAG_ON)
        xray_cfg = json.loads(written["xray-client-fragment.json"])
        proxy = [ob for ob in xray_cfg["outbounds"] if ob["tag"] == "proxy"][0]
        sockopt = proxy["streamSettings"]["sockopt"]
        self.assertEqual(sockopt["dialerProxy"], "fragment")
        for placebo in ("fragment", "noise", "noises"):
            self.assertNotIn(placebo, sockopt)
        # DUAL-схема (31.10.2026): finalmask зеркалит fragment (экспорт
        # делегирует _build_xray_client_json — покрытие сквозное)
        self.assertEqual(
            proxy["streamSettings"]["finalmask"],
            {"tcp": [{"type": "fragment",
                      "settings": {"packets": "tlshello", "length": "10-20",
                                   "interval": "10-20"}}]})
        tags = [ob.get("tag") for ob in xray_cfg["outbounds"]]
        self.assertEqual(len(tags), len(set(tags)),
                         f"теги outbound должны быть уникальны: {tags}")
        for expected in ("proxy", "fragment", "direct", "block"):
            self.assertIn(expected, tags)

    def test_singbox_fragment_json_contains_fragment(self):
        """Sing-box JSON (Hiddify/NekoBox): dial-поле fragment."""
        written = self._run_generate(_FAKE_STATE_REALITY_FRAG_ON)
        sb_cfg = json.loads(written["singbox-client-fragment.json"])
        ob = sb_cfg["outbounds"][0]
        self.assertTrue(ob["fragment"]["enabled"])
        self.assertEqual(ob["fragment"]["size"], "10-20")

    def test_links_fragment_file_has_client_formats(self):
        """vless-links-fragment.txt: Happ (length,interval,packets),
        Incy (fragmentLength/fragmentInterval), Neko (packets,length,interval)."""
        written = self._run_generate(_FAKE_STATE_REALITY_FRAG_ON)
        links = written["vless-links-fragment.txt"]
        import urllib.parse
        # Happ: fragment=length,interval,packets
        self.assertIn("fragment=", links)
        happ_val = urllib.parse.unquote(
            [p for p in links.split() if p.startswith("vless://")][0]
            .split("fragment=", 1)[1].split("#", 1)[0].split("&", 1)[0])
        self.assertEqual(happ_val, "10-20,10-20,tlshello")
        # Incy: fragmentLength/fragmentInterval
        self.assertIn("fragmentLength=10-20", links)
        self.assertIn("fragmentInterval=10-20", links)
        # Три ссылки — Happ/Incy/Neko
        self.assertEqual(links.count("vless://"), 3)

    def test_xhttp_reality_honest_export_no_singbox_fragment(self):
        """Честный экспорт: xhttp_reality — sing-box fragment НЕ генерируем
        (ядро sing-box не поддерживает xhttp), Xray JSON и ссылки — генерируем."""
        state = {
            **_FAKE_STATE_XHTTP_REALITY,
            "client_fragment": {"enabled": True, "packets": "1-3",
                                "length": "10-20", "interval": "10-20"},
        }
        written = self._run_generate(state)
        self.assertIn("xray-client-fragment.json", written)
        self.assertIn("vless-links-fragment.txt", written)
        self.assertNotIn("singbox-client-fragment.json", written)

    def test_broken_toggle_state_falls_back_to_default(self):
        """Честный экспорт: битый блок client_fragment (неполные параметры)
        = выключено, дефолтный набор без fragment-файлов, ничего не падает."""
        state = {
            **_FAKE_STATE_REALITY,
            "client_fragment": {"enabled": True, "packets": "1-3"},
        }
        written = self._run_generate(state)
        for fname in _FRAG_ADDON_FILES:
            self.assertNotIn(fname, written)


if __name__ == "__main__":
    unittest.main(verbosity=2)
