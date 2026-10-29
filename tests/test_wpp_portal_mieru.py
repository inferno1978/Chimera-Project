#!/usr/bin/env python3
"""
tests/test_wpp_portal_mieru.py — вкладка Mieru + «Подключение: все протоколы».

Покрывает:
  • _get_user_mieru_info: привязка по bindings → login/порты/ссылки;
    Karing-ссылка — traffic-pattern ДЕФИСОМ, NekoBox — ПОДЧЁРКИВАНИЕМ +
    server_ports=START-END; BOTH → TCP+UDP; mita-only нода (без mieru.json)
    парсит порты из portBindings; без привязки — None.
  • _mita_pattern_blob: кэш → пресет-fallback.
  • _get_user_mtproto_info: tg://proxy + t.me ссылки, ee-secret+hex-домен.
  • _get_user_awg_summary: резюме без ключей; None без пира.
  • _get_connect_all: агрегат vless+awg+mieru(без outbounds)+mtproto.
  • HTTP: /api/portal/{mieru-info,connect-all} — 401 без сессии, JSON с ней.
  • UI (wpp_ui): вкладка tab-mieru/panel-mieru, loadMieru в init и
    pull-to-refresh, connect-all в JS + fallback на старый эндпоинт.

Запуск:
  cd <repo-root>
  python3 -m pytest tests/test_wpp_portal_mieru.py -v
"""
from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    """Загружает chimera._core через exec и регистрирует в sys.modules
    (как test_satellite_bindings._setup_core — для lazy-импортов rest_api)."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core


_USER = {
    "uuid": "11111111-2222-3333-4444-555555555555",
    "email": "alice@test.online",
    "name": "alice",
    "protocol": "vless",
}

_MIERU_STATE = {
    "installed": True,
    "port_start": 2012,
    "port_end": 2022,
    "protocol": "TCP",
    "traffic_preset": "aggressive",
    "client_dns": "https://test.online:30443/dns-query",
    "users": [
        {"username": "admin", "password": "ADMINPWD"},
        {"username": "alice", "password": "ALICEPWD"},
    ],
}

_MITA_CFG = {
    "portBindings": [{"portRange": "2012-2022", "protocol": "TCP"}],
    "users": [
        {"name": "admin", "password": "ADMINPWD"},
        {"name": "alice", "password": "ALICEPWD"},
    ],
}

_BINDING = {
    "bindings": [{
        "satellite": "mieru", "login": "alice",
        "owner_uuid": _USER["uuid"], "owner_email": _USER["email"],
        "added_at": "x", "updated_at": "x",
    }]
}

_BLOB = "GgQIARAUIgIIASoFCEAQgAE="


class _FakeHandler:
    """Минимальный хендлер для wpp_portal.handle_get (без реального HTTP)."""

    def __init__(self, path="/api/portal/mieru-info"):
        self.path = path
        self.headers = {}
        self.client_address = ("127.0.0.1", 44444)
        self.sent = []
        self.status = None
        self.resp_headers = {}
        self.body = b""

    def send_json(self, data, status=200):
        self.sent.append((data, status))
        self.status = status
        self.resp_headers["Content-Type"] = "application/json; charset=utf-8"

    def send_response(self, status, *a, **kw):
        self.status = status

    def send_header(self, k, v):
        self.resp_headers[k] = v

    def end_headers(self):
        pass

    @property
    def wfile(self):
        w = types.SimpleNamespace()
        w.write = lambda data: setattr(self, "body", data)
        return w


class MieruInfoBase(unittest.TestCase):
    """Общий контекст: fake core + tmp-файлы + патчи окружения."""

    @classmethod
    def setUpClass(cls):
        _setup_core()
        from chimera.modules import wpp_portal
        from chimera.modules import satellite_bindings as sb
        cls._wp = wpp_portal
        cls._sb = sb
        cls._tmp = Path(tempfile.mkdtemp())
        cls._mieru_state = cls._tmp / "mieru.json"
        cls._mita_cfg = cls._tmp / "server.json"
        cls._bindings = cls._tmp / "satellite_bindings.json"
        cls._telemt = cls._tmp / "telemt.toml"
        cls._awg_state = cls._tmp / "awg_state.json"

    def _ctx(self, mieru=_MIERU_STATE, mita=_MITA_CFG, bindings=_BINDING,
             blob=_BLOB, domain="test.example.com"):
        """Собирает контекст-менеджер с патчами окружения."""
        if mieru is not None:
            self._mieru_state.write_text(json.dumps(mieru))
        if mita is not None:
            self._mita_cfg.write_text(json.dumps(mita))
        if bindings is not None:
            self._bindings.write_text(json.dumps(bindings))
        # Кэш blob — без запуска mita-бинаря.
        cache = {"ts": 9999999999.0, "blob": blob} if blob else \
            {"ts": 0.0, "blob": ""}
        return patch.multiple(
            self._wp,
            _MIERU_STATE_FILE=str(self._mieru_state),
            _MITA_CONFIG_FILE=str(self._mita_cfg),
            _MITA_BIN=str(self._tmp / "no-such-mita"),
            _MIERU_BLOB_CACHE=cache,
        )

    def _patched_domain(self):
        return patch.object(self._wp, "_panel_domain",
                            return_value="test.example.com")


class TestMieruInfo(MieruInfoBase):

    def test_bound_user_full_info(self):
        with self._ctx(), self._patched_domain(), \
                patch.object(self._wp, "_mita_service_active", return_value=True):
            info = self._wp._get_user_mieru_info(_USER)
        self.assertIsNotNone(info)
        self.assertEqual(info["login"], "alice")
        self.assertEqual(info["port_start"], 2012)
        self.assertEqual(info["port_end"], 2022)
        self.assertEqual(info["ports"], "2012-2022")
        self.assertEqual(info["protocol"], "TCP")
        self.assertEqual(info["server"], "test.example.com")
        self.assertEqual(info["client_dns"], "https://test.online:30443/dns-query")
        self.assertTrue(info["installed"])
        self.assertTrue(info["service_active"])
        self.assertTrue(info["has_traffic_pattern"])
        # Ссылки: Karing + NekoBox
        apps = [l["app"] for l in info["links"]]
        self.assertEqual(apps, ["Karing", "NekoBox"])
        karing = info["links"][0]["link"]
        neko = info["links"][1]["link"]
        # Karing: паттерн ДЕФИСОМ, port=..., protocol=TCP
        self.assertIn("mierus://alice:ALICEPWD@test.example.com", karing)
        self.assertIn("port=2012", karing)
        self.assertIn("protocol=TCP", karing)
        self.assertIn("multiplexing=MULTIPLEXING_HIGH", karing)
        self.assertIn("traffic-pattern=GgQIARAUIgIIASoFCEAQgAE%3D", karing)
        # NekoBox: server_ports=START-END, паттерн ПОДЧЁРКИВАНИЕМ
        self.assertIn(":2012?", neko)
        self.assertIn("server_ports=2012-2022", neko)
        self.assertIn("traffic_pattern=GgQIARAUIgIIASoFCEAQgAE%3D", neko)
        self.assertNotIn("traffic-pattern=", neko)
        # sing-box outbound с traffic_pattern-полем
        self.assertEqual(len(info["outbounds"]), 1)
        ob = info["outbounds"][0]
        self.assertEqual(ob["type"], "mieru")
        self.assertEqual(ob["server"], "test.example.com")
        self.assertEqual(ob["server_port"], 2012)
        self.assertEqual(ob["traffic_pattern"], _BLOB)

    def test_both_protocol_doubles_links(self):
        state = dict(_MIERU_STATE, protocol="BOTH")
        with self._ctx(mieru=state), self._patched_domain(), \
                patch.object(self._wp, "_mita_service_active", return_value=True):
            info = self._wp._get_user_mieru_info(_USER)
        self.assertIsNotNone(info)
        self.assertEqual(len(info["links"]), 4)  # Karing+NekoBox × TCP/UDP
        self.assertEqual(info["protocol"], "TCP+UDP")
        tags = {ob["tag"] for ob in info["outbounds"]}
        self.assertIn("mieru-alice-tcp", tags)
        self.assertIn("mieru-alice-udp", tags)
        udp_links = [l for l in info["links"] if l["transport"] == "UDP"]
        self.assertEqual(len(udp_links), 2)

    def test_no_binding_no_name_match_returns_none(self):
        # Пул логинов без "alice" и без binding для юзера.
        state = dict(_MIERU_STATE)
        state["users"] = [{"username": "carol", "password": "x"}]
        mita = {"portBindings": [{"portRange": "2012-2022",
                                 "protocol": "TCP"}],
                "users": [{"name": "carol", "password": "x"}]}
        with self._ctx(mieru=state, mita=mita, bindings={"bindings": []}), \
                self._patched_domain():
            info = self._wp._get_user_mieru_info(_USER)
        self.assertIsNone(info)

    def test_name_heuristic_fallback(self):
        # binding нет, но логин совпадает с email-local-part.
        with self._ctx(bindings={"bindings": []}), self._patched_domain(), \
                patch.object(self._wp, "_mita_service_active", return_value=False):
            info = self._wp._get_user_mieru_info(_USER)
        self.assertIsNotNone(info)
        self.assertEqual(info["login"], "alice")
        self.assertFalse(info["service_active"])

    def test_mita_only_node_ports_from_portbindings(self):
        # Нода без mieru.json: mita server.json — единственный источник.
        with self._ctx(mieru=None, mita=_MITA_CFG), self._patched_domain(), \
                patch.object(self._wp, "_mita_service_active", return_value=True):
            # Файл mieru.json не должен читаться: подменим на несуществующий.
            with patch.object(self._wp, "_MIERU_STATE_FILE",
                              str(self._tmp / "no-mieru-state.json")):
                info = self._wp._get_user_mieru_info(_USER)
        self.assertIsNotNone(info)
        self.assertEqual(info["port_start"], 2012)
        self.assertEqual(info["port_end"], 2022)
        self.assertEqual(info["ports"], "2012-2022")
        self.assertTrue(info["installed"])

    def test_blob_falls_back_to_preset(self):
        # Кэш пуст, бинаря нет → preset из state (aggressive == _BLOB).
        with self._ctx(blob=""), self._patched_domain():
            with patch.object(self._wp, "_MIERU_BLOB_CACHE",
                              {"ts": 0.0, "blob": ""}):
                blob = self._wp._mita_pattern_blob(_MIERU_STATE)
        self.assertEqual(blob, _BLOB)  # aggressive preset

    def test_client_server_addr_wins(self):
        state = dict(_MIERU_STATE, client_server_addr="vpn.custom.net")
        with self._ctx(mieru=state), self._patched_domain():
            info = self._wp._get_user_mieru_info(_USER)
        self.assertEqual(info["server"], "vpn.custom.net")


class TestMtprotoInfo(MieruInfoBase):

    _TELEMT_TOML = (
        '[server]\nport = 9443\n\n[censorship]\n'
        'tls_domain = "test.example.com"\n\n[access.users]\n'
        'alice = "67daaf98532fd1ce9e86ef5dcb86a0a4"\n'
    )

    def test_tg_links(self):
        self._telemt.write_text(self._TELEMT_TOML)
        from chimera.modules import subscription
        with patch.object(subscription, "_TELEMT_TOML", self._telemt), \
                self._patched_domain():
            info = self._wp._get_user_mtproto_info(_USER)
        self.assertIsNotNone(info)
        self.assertEqual(info["login"], "alice")
        self.assertEqual(info["port"], 9443)
        self.assertEqual(len(info["links"]), 2)
        tg = info["links"][0]["link"]
        web = info["links"][1]["link"]
        self.assertTrue(tg.startswith("tg://proxy?server=test.example.com&port=9443&secret=ee"))
        self.assertIn("746573742e6578616d706c652e636f6d", tg)  # hex(test.example.com)
        self.assertTrue(web.startswith("https://t.me/proxy?server=test.example.com&port=9443&secret=ee"))

    def test_no_match_returns_none(self):
        toml = ("[server]\nport = 9443\n\n[censorship]\n"
                'tls_domain = "test.example.com"\n\n[access.users]\n'
                'carol = "67daaf98532fd1ce9e86ef5dcb86a0a4"\n')
        self._telemt.write_text(toml)
        from chimera.modules import subscription
        with patch.object(subscription, "_TELEMT_TOML", self._telemt), \
                self._patched_domain():
            info = self._wp._get_user_mtproto_info(_USER)
        self.assertIsNone(info)


class TestAwgSummary(MieruInfoBase):

    def test_summary_shape(self):
        from chimera.modules import awg_state
        self._awg_state.write_text(json.dumps({
            "installed": True,
            "port": 9741,
            "peers": [{
                "name": "user-main",
                "owner_email": _USER["email"],
                "client_privkey": "SECRETKEY",
                "client_pubkey": "PUB",
                "expires_at": "",
            }],
        }))
        with patch.object(awg_state, "AWGS_STATE_FILE", self._awg_state):
            s = self._wp._get_user_awg_summary(_USER)
        self.assertIsNotNone(s)
        self.assertEqual(s["name"], "user-main")
        self.assertEqual(s["status"], "active")
        self.assertEqual(s["qr_url"], "/api/awg/my-peer/qr")
        self.assertEqual(s["conf_url"], "/api/awg/my-peer/config")
        self.assertNotIn("client_privkey", s)

    def test_no_peer_returns_none(self):
        from chimera.modules import awg_state
        self._awg_state.write_text(json.dumps({
            "installed": True, "port": 9741, "peers": [],
        }))
        with patch.object(awg_state, "AWGS_STATE_FILE", self._awg_state):
            s = self._wp._get_user_awg_summary(_USER)
        self.assertIsNone(s)


class TestConnectAll(MieruInfoBase):

    def test_aggregate_shape(self):
        fake_vless = [{"label": "IPv4 / Domain", "link": "vless://x",
                       "protocol": "reality"}]
        self._telemt.write_text(TestMtprotoInfo._TELEMT_TOML)
        from chimera.modules import subscription
        with patch.object(self._wp, "_generate_vless_links",
                          return_value=fake_vless), \
                self._patched_domain(), \
                patch.object(self._wp, "_get_user_awg_summary",
                             return_value={"name": "user-main",
                                           "status": "active",
                                           "qr_url": "/api/awg/my-peer/qr",
                                           "conf_url": "/api/awg/my-peer/config",
                                           "tab": "awg"}), \
                patch.object(self._wp, "_get_user_mtproto_info",
                             return_value={"login": "alice", "port": 9443,
                                           "links": [
                                               {"app": "tg", "link": "tg://x"},
                                               {"app": "t.me", "link": "https://t.me/x"}]}), \
                patch.object(subscription, "_TELEMT_TOML", self._telemt):
            d = self._wp._get_connect_all(_USER)
        self.assertEqual(d["vless"]["count"], 1)
        self.assertEqual(d["vless"]["links"], fake_vless)
        self.assertEqual(d["awg"]["name"], "user-main")
        self.assertEqual(d["mtproto"]["port"], 9443)
        self.assertEqual(d["domain"], "test.example.com")
        self.assertIn("other_satellites", d)

    def test_mieru_excluded_from_other_satellites(self):
        """mieru — отдельная секция, не дублируется в other_satellites."""
        fake_vless = []
        with patch.object(self._wp, "_generate_vless_links",
                          return_value=fake_vless), \
                self._ctx(), self._patched_domain(), \
                patch.object(self._sb, "_STATE_FILE", self._bindings), \
                patch.object(self._wp, "_get_user_awg_summary", return_value=None), \
                patch.object(self._wp, "_get_user_mtproto_info", return_value=None), \
                patch.object(self._sb, "_scan_mieru",
                             return_value=[{"satellite": "mieru",
                                            "login": "alice"}]), \
                patch.object(self._sb, "_scan_naive", return_value=[]), \
                patch.object(self._sb, "_scan_telemt", return_value=[]), \
                patch.object(self._sb, "_scan_trusttunnel", return_value=[]), \
                patch.object(self._sb, "_scan_singbox", return_value=[]):
            d = self._wp._get_connect_all(_USER)
        self.assertIsNotNone(d["mieru"])
        self.assertNotIn("outbounds", d["mieru"])  # вырезан из агрегата
        for s in d["other_satellites"]:
            self.assertNotEqual(s.get("satellite"), "mieru")


class TestHttpRoutes(MieruInfoBase):

    def _handle(self, path):
        h = _FakeHandler(path=path)
        self._wp.handle_get(h, path, {})
        return h

    def test_unauthorized_401(self):
        for path in ("/api/portal/mieru-info", "/api/portal/connect-all"):
            h = self._handle(path)
            self.assertEqual(h.sent[0][1], 401, path)
            self.assertIn("error", h.sent[0][0])

    def test_mieru_info_with_session(self):
        h = _FakeHandler(path="/api/portal/mieru-info")
        with patch.object(self._wp, "_require_user", return_value=_USER), \
                self._ctx(), self._patched_domain(), \
                patch.object(self._wp, "_mita_service_active", return_value=True):
            self._wp.handle_get(h, "/api/portal/mieru-info", {})
        self.assertEqual(len(h.sent), 1)
        data, status = h.sent[0]
        self.assertEqual(status, 200)
        self.assertIn("mieru", data)
        self.assertEqual(data["mieru"]["login"], "alice")

    def test_connect_all_with_session(self):
        h = _FakeHandler(path="/api/portal/connect-all")
        fake_vless = [{"label": "IPv4", "link": "vless://x",
                       "protocol": "reality"}]
        with patch.object(self._wp, "_require_user", return_value=_USER), \
                patch.object(self._wp, "_generate_vless_links",
                             return_value=fake_vless), \
                patch.object(self._wp, "_get_user_awg_summary", return_value=None), \
                patch.object(self._wp, "_get_user_mtproto_info", return_value=None), \
                self._ctx(), self._patched_domain():
            self._wp.handle_get(h, "/api/portal/connect-all", {})
        self.assertEqual(len(h.sent), 1)
        data, status = h.sent[0]
        self.assertEqual(status, 200)
        self.assertEqual(data["vless"]["links"], fake_vless)
        self.assertEqual(data["mieru"]["login"], "alice")

    def test_mieru_config_download(self):
        h = _FakeHandler(path="/api/portal/mieru-config")
        with patch.object(self._wp, "_require_user", return_value=_USER), \
                self._ctx(), self._patched_domain():
            self._wp.handle_get(h, "/api/portal/mieru-config", {})
        self.assertEqual(h.status, 200)
        self.assertIn("attachment", h.resp_headers.get("Content-Disposition", ""))
        body = json.loads(self.body_or(h))
        self.assertEqual(body["outbounds"][0]["type"], "mieru")

    @staticmethod
    def body_or(h):
        if isinstance(h.body, bytes):
            return h.body.decode("utf-8", "replace")
        return h.body

    def test_mieru_config_404_without_mieru(self):
        h = _FakeHandler(path="/api/portal/mieru-config")
        with patch.object(self._wp, "_require_user", return_value=_USER), \
                patch.object(self._wp, "_get_user_mieru_info", return_value=None):
            self._wp.handle_get(h, "/api/portal/mieru-config", {})
        self.assertEqual(h.sent[0][1], 404)


class TestUiMarkup(unittest.TestCase):
    """Вкладка Mieru + connect-all в HTML/JS портала (wpp_ui)."""

    @classmethod
    def setUpClass(cls):
        _setup_core()
        from chimera.modules import wpp_ui
        cls._ui = wpp_ui

    def _portal_html(self):
        return self._ui.portal_page(
            {"email": "alice@test.online", "name": "alice"}, "/portal")

    def test_tab_and_panel_present(self):
        html = self._portal_html()
        self.assertIn('id="tab-mieru"', html)
        self.assertIn('id="panel-mieru"', html)
        self.assertIn('id="mieru-card"', html)
        self.assertIn('id="mieru-container"', html)
        self.assertIn("switchTab('mieru')", html)
        # Кнопка одна (не задвоена)
        self.assertEqual(html.count('id="tab-mieru"'), 1)
        self.assertEqual(html.count('id="panel-mieru"'), 1)

    def test_load_mieru_in_init_and_ptr(self):
        html = self._portal_html()
        self.assertIn("loadMieru();", html)
        # init-строка и pull-to-refresh
        self.assertGreaterEqual(html.count("loadMieru();"), 2)

    def test_connect_all_js_with_fallback(self):
        js = self._ui.PORTAL_TABS_JS
        self.assertIn("/api/portal/connect-all", js)
        self.assertIn("renderConnectAll", js)
        # fallback на старый эндпоинт
        self.assertIn("'/api/portal/links'", js)
        self.assertIn("renderVlessTiles", js)

    def test_load_mieru_fetches_info(self):
        js = self._ui.PORTAL_TABS_JS
        self.assertIn("/api/portal/mieru-info", js)
        self.assertIn("/api/portal/mieru-config", js)

    def test_configs_tab_mentions_mieru(self):
        html = self._portal_html()
        self.assertIn("🟣 Mieru", html)

    def test_inline_onclick_quotes_escaped(self):
        """Регрессия 5c4ee01: switchTab(\\'awg\\') с ОДНИМ бэкслешем на уровне
        Python «схлопывался» в switchTab('awg') и разрывал JS-строку
        (Uncaught SyntaxError: missing ) after argument list → весь
        скрипт-блок портала умирал: кнопки/вкладки/pwStrength).
        В отдаваемом JS внутри JS-строк кавычки должны быть экранированы."""
        js = self._ui.PORTAL_TABS_JS
        # валидные (экранированные) формы
        self.assertIn("switchTab(\\'awg\\')", js)
        self.assertIn("switchTab(\\'mieru\\')", js)
        # битые (неэкранированные) формы внутри JS-строк
        self.assertNotIn("switchTab('awg')", js)
        self.assertNotIn("switchTab('mieru')", js)

    def test_portal_js_syntax(self):
        """Полный синтакс-чек инлайн-JS страницы портала через node --check."""
        import re as _re
        import shutil
        import subprocess
        node = shutil.which("node")
        if not node:
            self.skipTest("node недоступен — синтакс-чек пропущен")
        html = self._portal_html()
        blocks = _re.findall(r"<script[^>]*>(.*?)</script>", html, _re.S)
        self.assertGreaterEqual(len(blocks), 1, "на странице нет JS-блоков")
        import tempfile
        for i, block in enumerate(blocks):
            with tempfile.NamedTemporaryFile(
                    "w", suffix=".js", delete=False,
                    encoding="utf-8") as fh:
                fh.write(block)
                path = fh.name
            proc = subprocess.run([node, "--check", path],
                                  capture_output=True, text=True)
            self.assertEqual(
                proc.returncode, 0,
                f"JS-блок {i} не проходит node --check:\n{proc.stderr[:600]}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
