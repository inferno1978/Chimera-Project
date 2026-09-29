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
    "domain": "total-shadows.online",
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
        self.assertIn("total-shadows.online", clash)
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
        self.assertEqual(ob["server"], "total-shadows.online")

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
        self.assertNotIn("sni=total-shadows.online", vless_link)


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

    def test_clash_xhttp_reality_mihomo_fallback(self):
        """mihomo-фолбэк: tcp+reality (network tcp + reality-opts +
        MLKEM768 + chrome FP) с комментарием про фолбэк."""
        written = self._run_generate(_FAKE_STATE_XHTTP_REALITY)
        clash = written.get("clash-meta.yaml", "")
        if not clash:
            self.skipTest("clash-meta.yaml not captured")
        self.assertIn("network: tcp", clash)
        self.assertIn("reality-opts:", clash)
        self.assertIn("support-x25519mlkem768: true", clash)
        self.assertIn("client-fingerprint: chrome", clash)
        self.assertIn("flow: xtls-rprx-vision", clash)
        # Комментарий-маркер фолбэка
        self.assertIn("mihomo fallback to tcp+reality", clash)
        # НЕ xhttp-транспорт (mihomo его не умеет)
        self.assertNotIn("network: http", clash)

    def test_singbox_xhttp_reality(self):
        """sing-box: transport type=xhttp (mode+path) + TLS REALITY, без flow."""
        written = self._run_generate(_FAKE_STATE_XHTTP_REALITY)
        singbox_str = written.get("sing-box.json", "")
        if not singbox_str:
            self.skipTest("sing-box.json not captured")
        config = json.loads(singbox_str)
        ob = config["outbounds"][0]
        self.assertEqual(ob["type"], "vless")
        self.assertEqual(ob["transport"]["type"], "xhttp")
        self.assertEqual(ob["transport"]["mode"], "stream-up")
        self.assertEqual(ob["transport"]["path"], "/xhttp")
        self.assertEqual(ob["tls"]["reality"]["public_key"], "TEST_PUB_KEY_123")
        self.assertEqual(ob["tls"]["reality"]["short_id"], "abcd1234")
        self.assertEqual(ob["tls"]["server_name"], "total-shadows.online")
        self.assertNotIn("flow", ob)

    def test_hiddify_xhttp_reality(self):
        """Hiddify-копия = sing-box + routing rules (наследует xhttp_reality)."""
        written = self._run_generate(_FAKE_STATE_XHTTP_REALITY)
        hiddify_str = written.get("hiddify.json", "")
        if not hiddify_str:
            self.skipTest("hiddify.json not captured")
        config = json.loads(hiddify_str)
        self.assertIn("routing", config)
        ob = config["outbounds"][0]
        self.assertEqual(ob["transport"]["type"], "xhttp")
        self.assertEqual(ob["tls"]["reality"]["enabled"], True)

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
        # sing-box тоже должен получить reality_dest как server_name
        singbox = json.loads(written.get("sing-box.json", "{}"))
        if singbox.get("outbounds"):
            self.assertEqual(
                singbox["outbounds"][0]["tls"]["server_name"],
                "www.cloudflare.com")


if __name__ == "__main__":
    unittest.main(verbosity=2)
