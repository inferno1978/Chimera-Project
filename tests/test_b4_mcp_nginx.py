#!/usr/bin/env python3
"""
tests/test_b4_mcp_nginx.py
───────────────────────────────────────────────────────────────────────────────
Тесты MCP-проксирования b4 через nginx front (v72.2).

Контекст: b4 >= 1.80 поднял MCP-сервер (/api/mcp). MCP go-sdk
(StreamableHTTPHandler) требует, чтобы при loopback-бэкенде Host-заголовок
был loopback (DNS-rebinding защита) — иначе 403 «invalid Host header».
nginx front b4 (порт 9743) до v72.2 слал Host $host (домен) → все
стандартные MCP-клиенты получали 403.

Покрывает:
  1. _generate_vhost(mcp_proxy=True) — location /api/mcp с loopback-Host,
     SSE-стримингом (proxy_buffering off) и долгим read-timeout.
  2. _generate_vhost() по умолчанию — БЕЗ /api/mcp (не меняем чужие панели:
     telemt, user portal, subscription).
  3. panel_nginx_front_install(mcp_proxy=...) — параметр доезжает до
     _generate_vhost.
  4. dpi_bypass._b4_nginx_install / youtube_b4._b4_nginx_install —
     передают mcp_proxy=True.
  5. REST-авторизация b4: _b4_web_credentials (config.json),
     _b4_api_token (POST /api/login, кэш), _b4_rest_request (Bearer,
     перевыпуск при 401).
  6. scripts/enable-b4-mcp-nginx.sh (v72.3): бэкапы НЕ в sites-enabled
     (nginx подключает sites-enabled/* ЦЕЛИКОМ, включая .bak → дубликат
     server-блока «conflicting server name ... ignored»); повторный
     запуск выносит старые .preMCP.bak в /etc/nginx/chimera-backups/.
     Функционально — в песочнице (фейковые nginx/systemctl/curl).
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
import types
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    """Загружает chimera._core через exec и регистрирует в sys.modules."""
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


def _load_module(name: str):
    """Импортирует chimera.modules.<name> с подготовленным _core."""
    _setup_core()
    import importlib
    mod = importlib.import_module(f"chimera.modules.{name}")
    return mod


class TestGenerateVhostMcp(unittest.TestCase):
    """_generate_vhost: MCP-локация (v72.2)."""

    @classmethod
    def setUpClass(cls):
        cls.pnf = _load_module("panel_nginx_front")

    def _vhost(self, **kw) -> str:
        from pathlib import Path as P
        return self.pnf._generate_vhost(
            port=9743, backend_port=9700,
            cert_path=P("/etc/ssl/certs/chimera-b4.crt"),
            key_path=P("/etc/ssl/private/chimera-b4.key"),
            domain="example.com",
            panel_name_slug="chimera-b4",
            **kw)

    def test_mcp_proxy_true_generates_location(self):
        v = self._vhost(mcp_proxy=True)
        self.assertIn("location /api/mcp {", v)

    def test_mcp_location_has_loopback_host(self):
        v = self._vhost(mcp_proxy=True)
        # Host обязан быть loopback (go-sdk DNS-rebinding protection).
        self.assertIn("proxy_set_header Host 127.0.0.1:9700;", v)

    def test_mcp_location_sse_streaming(self):
        v = self._vhost(mcp_proxy=True)
        # SSE: без буферизации, долгий read-timeout (discovery идёт минутами).
        self.assertIn("proxy_buffering off;", v)
        self.assertIn("proxy_read_timeout 3600s;", v)

    def test_mcp_location_strips_origin(self):
        v = self._vhost(mcp_proxy=True)
        # mcpGate сверяет Origin с Host — стриппаем, чтобы браузерные
        # MCP-клиенты не ловили "origin not allowed".
        self.assertIn('proxy_set_header Origin "";', v)

    def test_mcp_location_passes_to_backend(self):
        v = self._vhost(mcp_proxy=True)
        self.assertIn("proxy_pass http://127.0.0.1:9700;", v)

    def test_mcp_location_before_root_location(self):
        v = self._vhost(mcp_proxy=True)
        # prefix-локация длиннее / выигрывает независимо от порядка,
        # но в конфиге MCP-блок должен идти первым (читабельность).
        self.assertLess(v.index("location /api/mcp {"), v.index("location / {"))
    def test_default_has_no_mcp_location(self):
        # КРИТИЧНО: чужие панели (telemt/user portal/subscription) не
        # должны получить /api/mcp — там нет MCP-сервера, а 404 от бэкенда
        # вместо UI-роута был бы багом. (Ищем с «{», чтобы не матчить
        # поясняющий комментарий в шаблоне.)
        v = self._vhost()
        self.assertNotIn("location /api/mcp {", v)
        self.assertNotIn("proxy_set_header Host 127.0.0.1:9700;", v)

    def test_websocket_rewrite_still_works_with_mcp(self):
        # Сочетание параметров не должно падать (хотя b4 его не использует).
        v = self._vhost(mcp_proxy=True, websocket_origin_rewrite=True)
        self.assertIn("location /api/mcp {", v)
        self.assertIn("proxy_set_header Host 127.0.0.1:9700;", v)


class TestB4NginxInstallPassesMcp(unittest.TestCase):
    """dpi_bypass / youtube_b4: _b4_nginx_install передаёт mcp_proxy=True."""

    def _check(self, modname: str):
        mod = _load_module(modname)
        captured = {}

        def fake_install(**kw):
            captured.update(kw)
            return True, "ok"

        with patch("chimera.modules.panel_nginx_front.panel_nginx_front_install",
                   side_effect=fake_install):
            ok, _ = mod._b4_nginx_install(9743, True, None)
        self.assertTrue(ok)
        self.assertTrue(captured.get("mcp_proxy"),
                        f"{modname}._b4_nginx_install должен передавать mcp_proxy=True")
        self.assertEqual(captured.get("backend_port"), 9700)
        # ufw deny 9700 — мокаем subprocess, чтобы не трогать реальный.
        self.assertEqual(captured.get("cert_name_slug"), "chimera-b4")

    def test_dpi_bypass(self):
        mod = _load_module("dpi_bypass")
        captured = {}
        with patch("chimera.modules.panel_nginx_front.panel_nginx_front_install",
                   side_effect=lambda **kw: (captured.update(kw), (True, "ok"))[1]), \
             patch.object(mod, "subprocess", MagicMock()):
            mod._b4_nginx_install(9743, True, None)
        self.assertTrue(captured.get("mcp_proxy"))
        self.assertEqual(captured.get("backend_port"), 9700)

    def test_youtube_b4(self):
        mod = _load_module("youtube_b4")
        captured = {}
        with patch("chimera.modules.panel_nginx_front.panel_nginx_front_install",
                   side_effect=lambda **kw: (captured.update(kw), (True, "ok"))[1]), \
             patch.object(mod, "subprocess", MagicMock()):
            mod._b4_nginx_install(9743, True, None)
        self.assertTrue(captured.get("mcp_proxy"))


class _FakeResponse(io.BytesIO):
    """urllib-совместимый response-объект."""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    @property
    def status(self):
        return 200


class TestB4RestAuth(unittest.TestCase):
    """REST-авторизация b4 (v72.2): логин → Bearer → 401-retry.

    Сценарий: администратор включил username/password в b4 Web UI —
    REST-запросы Chimera без токена получали бы 401 и импорт сетов
    откатывался бы на прямую запись config.json (конфликт с live-режимом
    b4). Теперь Chimera логинится и шлёт Bearer.
    """

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.config_file = self.tmpdir / "config.json"
        self.dpi = _load_module("dpi_bypass")
        self.dpi.B4_CONFIG_FILE = self.config_file
        # Сброс кэша токена между тестами.
        self.dpi._B4_API_TOKEN["value"] = None

    def _write_config(self, username="", password=""):
        self.config_file.write_text(json.dumps({
            "system": {"web_server": {
                "port": 9700, "username": username, "password": password}}}))

    def test_credentials_none_when_no_auth(self):
        self._write_config()
        self.assertIsNone(self.dpi._b4_web_credentials())

    def test_credentials_from_config(self):
        self._write_config(username="admin", password="secret")
        self.assertEqual(self.dpi._b4_web_credentials(), ("admin", "secret"))

    def test_token_none_when_no_auth(self):
        self._write_config()
        with patch.object(self.dpi, "_b4_web_port", return_value=9700), \
             patch.object(self.dpi, "_B4_REST_OPENER") as opener:
            self.assertIsNone(self.dpi._b4_api_token())
            opener.open.assert_not_called()

    def test_token_login_and_cache(self):
        self._write_config(username="admin", password="secret")
        opener = MagicMock()
        opener.open.return_value = _FakeResponse(b'{"token": "tok123"}')
        with patch.object(self.dpi, "_b4_web_port", return_value=9700), \
             patch.object(self.dpi, "_B4_REST_OPENER", opener):
            tok = self.dpi._b4_api_token()
            self.assertEqual(tok, "tok123")
            # Второй вызов — из кэша, без нового /api/login.
            self.assertEqual(self.dpi._b4_api_token(), "tok123")
            self.assertEqual(opener.open.call_count, 1)
            # Проверяем тело логина.
            req = opener.open.call_args[0][0]
            self.assertIn("/api/login", req.full_url)
            self.assertEqual(json.loads(req.data.decode()),
                             {"username": "admin", "password": "secret"})

    def test_rest_request_sends_bearer(self):
        self._write_config(username="admin", password="secret")
        opener = MagicMock()

        def _route(req, timeout=None):
            if "/api/login" in req.full_url:
                return _FakeResponse(b'{"token": "tok123"}')
            return _FakeResponse(b'[{"id": "s1"}]')

        opener.open.side_effect = _route
        with patch.object(self.dpi, "_b4_web_port", return_value=9700), \
             patch.object(self.dpi, "_B4_REST_OPENER", opener):
            status, body = self.dpi._b4_rest_request("GET", "/api/sets")
        self.assertEqual(status, 200)
        self.assertEqual(body, [{"id": "s1"}])
        req = opener.open.call_args[0][0]
        self.assertIn("/api/sets", req.full_url)
        self.assertEqual(req.get_header("Authorization"), "Bearer tok123")

    def test_rest_request_401_retry(self):
        """Протухший токен → перевыпуск → повтор → успех."""
        self._write_config(username="admin", password="secret")
        self.dpi._B4_API_TOKEN["value"] = "STALE"
        opener = MagicMock()
        err = urllib.error.HTTPError("url", 401, "Unauthorized",
                                     io.StringIO("x"), io.BytesIO(b"{}"))
        resp_ok = _FakeResponse(b'[{"id": "s2"}]')
        # 1-й вызов — 401, 2-й (логин) — токен, 3-й — успешный ответ.
        opener.open.side_effect = [err, _FakeResponse(b'{"token": "tokNEW"}'), resp_ok]
        with patch.object(self.dpi, "_b4_web_port", return_value=9700), \
             patch.object(self.dpi, "_B4_REST_OPENER", opener):
            status, body = self.dpi._b4_rest_request("GET", "/api/sets")
        self.assertEqual(status, 200)
        self.assertEqual(body, [{"id": "s2"}])
        self.assertEqual(self.dpi._B4_API_TOKEN["value"], "tokNEW")
        self.assertEqual(opener.open.call_count, 3)

    def test_rest_request_no_auth_header_without_credentials(self):
        self._write_config()
        opener = MagicMock()
        opener.open.return_value = _FakeResponse(b'[{"id": "s1"}]')
        with patch.object(self.dpi, "_b4_web_port", return_value=9700), \
             patch.object(self.dpi, "_B4_REST_OPENER", opener):
            status, _ = self.dpi._b4_rest_request("GET", "/api/sets")
        self.assertEqual(status, 200)
        self.assertEqual(opener.open.call_count, 1)  # без /api/login
        req = opener.open.call_args[0][0]
        self.assertIsNone(req.get_header("Authorization"))


# ─── v72.3: гигиена бэкапов scripts/enable-b4-mcp-nginx.sh ───────────────────

SH_PATH = _PROJECT_ROOT / "scripts" / "enable-b4-mcp-nginx.sh"

_SITE_CONF = """server {
    listen 9743 ssl;
    server_name chimeravpn.online;
    location / {
        proxy_pass http://127.0.0.1:9700;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
"""

_MCP_LOCATION = """    # MCP (Model Context Protocol) — b4 control plane.
    location /api/mcp {
        proxy_pass http://127.0.0.1:9700;
        proxy_set_header Host 127.0.0.1:9700;
        proxy_buffering off;
    }
"""


def _site_with_mcp() -> str:
    return _SITE_CONF.replace(
        "    location / {", _MCP_LOCATION + "\n    location / {", 1)


class TestScriptBackupHygieneStructural(unittest.TestCase):
    """Инцидент 91.224.87.154 (30.08): скрипт v72.2 клал бэкап рядом с
    сайтом (/etc/nginx/sites-enabled/chimera-b4-nginx.<ts>.preMCP.bak).
    Debian-nginx подключает sites-enabled/* ЦЕЛИКОМ — все расширения,
    включая .bak — поэтому бэкап грузился как дубликат server-блока:
    «conflicting server name "chimeravpn.online" on 0.0.0.0:9743, ignored»
    на каждый nginx -t/reload.
    """

    @classmethod
    def setUpClass(cls):
        cls.text = SH_PATH.read_text(encoding="utf-8")

    def test_bash_syntax(self):
        import subprocess
        r = subprocess.run(["bash", "-n", str(SH_PATH)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_backup_written_outside_sites_enabled(self):
        """Бэкап пишется в /etc/nginx/chimera-backups/, НЕ рядом с сайтом."""
        self.assertIn('BAKDIR="/etc/nginx/chimera-backups"', self.text)
        self.assertIn('BAK="$BAKDIR/$(basename "$SITE").$TS.preMCP.bak"',
                      self.text)
        # паттерн v72.2 (бэкап прямо в sites-enabled) не должен вернуться
        self.assertNotIn('BAK="$SITE.$TS.preMCP.bak"', self.text)

    def test_cleanup_precedes_early_exit(self):
        """Чистка старых .preMCP.bak идёт ДО раннего exit 0 «уже есть».

        Без этого повторный запуск на ноде 91.224.87.154 (локация уже
        вставлена) никогда не дошёл бы до чистки — warning остался бы
        навсегда.
        """
        cleanup = self.text.index("*.preMCP.bak")
        early = self.text.index("уже есть — готово")
        self.assertLess(cleanup, early)
        self.assertIn("conflicting server name", self.text)

    def test_site_search_skips_bak_files(self):
        """Поиск фронта не должен принять .bak-файл за сайт."""
        self.assertIn("*.bak) continue", self.text)


class TestScriptBackupHygieneFunctional(unittest.TestCase):
    """Скрипт в песочнице: /etc/nginx → временный каталог, nginx/
    systemctl/curl — фейки. Сценарии: исцеление легаси-бэкапа, свежая
    вставка (бэкап вне sites-enabled), идемпотентный повтор.
    """

    def _sandbox(self, site_text: str, legacy_bak: bool = False):
        import os
        import subprocess
        import tempfile
        tmp = tempfile.mkdtemp(prefix="b4mcp_")
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        tmp = Path(tmp)
        nginx_root = tmp / "nginx"
        sites = nginx_root / "sites-enabled"
        sites.mkdir(parents=True)
        (tmp / "bin").mkdir()
        calls = tmp / "calls.txt"

        def fake(name: str, body: str):
            p = tmp / "bin" / name
            p.write_text(body)
            p.chmod(0o755)

        fake("nginx", '#!/usr/bin/env bash\necho "nginx $*" >> "$CALLS"\nexit 0\n')
        fake("systemctl", '#!/usr/bin/env bash\necho "systemctl $*" >> "$CALLS"\nexit 0\n')
        # ответ MCP-эндпоинта (SSE) — чтобы финальная проба прошла
        fake("curl", '#!/usr/bin/env bash\necho "event: message"\n'
                     'echo \'data: {"jsonrpc":"2.0","id":1,"result":{}}\'\nexit 0\n')

        site = sites / "chimera-b4-nginx"
        site.write_text(site_text, encoding="utf-8")
        if legacy_bak:
            (sites / "chimera-b4-nginx.20260830115539.preMCP.bak").write_text(
                _SITE_CONF, encoding="utf-8")

        src = SH_PATH.read_text(encoding="utf-8")
        src = src.replace("/etc/nginx", str(nginx_root))
        src = src.replace('[ "$(id -u)" -eq 0 ]', "true")  # sandbox не root
        run_sh = tmp / "run.sh"
        run_sh.write_text(src, encoding="utf-8")

        env = dict(os.environ,
                   PATH=f"{tmp / 'bin'}:{os.environ['PATH']}",
                   CALLS=str(calls))
        r = subprocess.run(["bash", str(run_sh)], capture_output=True,
                           text=True, env=env, timeout=60)
        return r, site, sites, nginx_root / "chimera-backups", calls

    def test_heal_legacy_backup_on_rerun(self):
        """Нода после v72.2: локация есть, .bak лежит в sites-enabled →
        повторный запуск выносит .bak в chimera-backups/ и reload'ит."""
        r, site, sites, backups, calls = self._sandbox(
            _site_with_mcp(), legacy_bak=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        # .bak покинул sites-enabled и живёт в chimera-backups/
        self.assertEqual(list(sites.glob("*.bak")), [])
        moved = list(backups.glob("*.preMCP.bak"))
        self.assertEqual(len(moved), 1, f"ожидался 1 бэкап: {moved}")
        # конфиг сайта не тронут (идемпотентность)
        self.assertEqual(site.read_text(encoding="utf-8"), _site_with_mcp())
        # после чистки: nginx -t + reload
        calls_text = calls.read_text()
        self.assertIn("nginx -t", calls_text)
        self.assertIn("nginx -s reload", calls_text)
        self.assertIn("уже есть", r.stdout)

    def test_fresh_insert_backup_outside_sites_enabled(self):
        """Свежая нода: вставка локации + бэкап ТОЛЬКО в chimera-backups/."""
        r, site, sites, backups, calls = self._sandbox(_SITE_CONF)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cfg = site.read_text(encoding="utf-8")
        self.assertIn("location /api/mcp {", cfg)
        self.assertIn("proxy_set_header Host 127.0.0.1:9700;", cfg)
        self.assertIn("proxy_buffering off;", cfg)
        # оригинал сохранён и НЕ в sites-enabled (корень инцидента v72.2)
        self.assertEqual(list(sites.glob("*.bak")), [])
        saved = next(iter(backups.glob("*.preMCP.bak")))
        self.assertEqual(saved.read_text(encoding="utf-8"), _SITE_CONF)
        # nginx -t + reload + финальная проба прошли
        calls_text = calls.read_text()
        self.assertIn("nginx -t", calls_text)
        self.assertIn("nginx -s reload", calls_text)
        self.assertIn("MCP-эндпоинт отвечает", r.stdout)

    def test_rerun_creates_no_new_backup(self):
        """Повторный запуск после вставки: новых бэкапов, ноль изменений."""
        r1, site, _, _, _ = self._sandbox(_SITE_CONF)
        self.assertEqual(r1.returncode, 0, r1.stdout + r1.stderr)
        cfg_after_first = site.read_text(encoding="utf-8")
        # второй запуск по уже пропатченному конфигу (новая песочница с ним)
        r2, site2, sites2, backups2, _ = self._sandbox(cfg_after_first)
        self.assertEqual(r2.returncode, 0, r2.stdout + r2.stderr)
        self.assertEqual(len(list(backups2.glob("*.preMCP.bak"))), 0)
        self.assertEqual(list(sites2.glob("*.bak")), [])
        self.assertEqual(
            site2.read_text(encoding="utf-8"), cfg_after_first)
        self.assertIn("уже есть", r2.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
