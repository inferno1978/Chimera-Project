#!/usr/bin/env python3
"""
tests/test_librechat.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/librechat.py (+ интеграция panel_nginx_front /
port_registry / rest_api).

Тестируем (чистая логика + контракты делегирования на фейках, без сети/docker):
  1. Версии: _version_key / _strip_v / _update_availability /
     _update_header_row (кэш+сравнение — паттерн dpi_bypass)
  2. Зеркала: _app_mirror_urls (тег первым, github-прокси, детерминизм)
  3. PackageSpec: _app_spec (имя файла, min_size, manual_incoming_dir ≠ dests)
  4. Тарболл: _extract_app (реальный tar.gz: срез repo-tag/, traversal guard,
     LICENSE-кредит, docker-compose.yml на месте) + _app_actual_version
  5. ENV-патч: _patch_env_text (PORT/CREDS/MEILI/UID/GID/REGISTRATION/
     ADMIN_PANEL_PORT/ZAI; закомментированные строки; недостающие — в конец)
  6. Compose-патч: _patch_compose_text (loopback-маппинги api+admin-panel,
     volume librechat.yaml, идемпотентность)
  7. librechat.yaml: _render_librechat_yaml (custom endpoint zai, без ключа
     в plaintext — интерполяция ${ZAI_API_KEY})
  8. systemd-юнит: compose up -d --remove-orphans, RemainAfterExit, docker
  9. Версии runtime: _runtime_version-регекс (из тела /api/version)
 10. nginx front: делегирование в panel_nginx_front с long_timeouts=True
     (фейк-модуль) + _generate_vhost long_timeouts (3600s vs 60s)
 11. port_registry: SERVICE_LIBRECHAT_WEB/NGINX теги существуют
 12. rest_api: пункт меню 9 → do_librechat_menu (интеграция хаба панелей)
 13. CLI: __main__ вызывает do_librechat_menu (регресс-паттерн triple_panel)
"""
from __future__ import annotations

import io
import json
import re
import sys
import tarfile
import tempfile
import unittest
import urllib.request
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import librechat as lc


# ── хелперы подмены модулей (канон test_triple_panel.py) ─────────────────
def _install_fake(name: str, mod) -> None:
    sys.modules[name] = mod
    parent, _, child = name.rpartition(".")
    parent_mod = sys.modules.get(parent)
    if parent_mod is not None:
        setattr(parent_mod, child, mod)

def _snapshot_module(name: str) -> tuple:
    parent, _, child = name.rpartition(".")
    parent_mod = sys.modules.get(parent)
    had_attr = parent_mod is not None and hasattr(parent_mod, child)
    return (sys.modules.get(name),
            getattr(parent_mod, child, None) if had_attr else None,
            had_attr)

def _restore_module(name: str, snap: tuple) -> None:
    mod, attr, had_attr = snap
    if mod is not None:
        sys.modules[name] = mod
    else:
        sys.modules.pop(name, None)
    parent, _, child = name.rpartition(".")
    parent_mod = sys.modules.get(parent)
    if parent_mod is not None:
        if had_attr:
            setattr(parent_mod, child, attr)
        elif hasattr(parent_mod, child):
            delattr(parent_mod, child)


# ════════════════════════════════════════════════════════════════════════════
#  1. ВЕРСИИ
# ════════════════════════════════════════════════════════════════════════════
class TestVersionLogic(unittest.TestCase):

    def test_version_key_parses(self):
        self.assertEqual(lc._version_key("v0.8.8"), (0, 8, 8))
        self.assertEqual(lc._version_key("0.8.8"), (0, 8, 8))
        self.assertEqual(lc._version_key("v0.8"), (0, 8))
        self.assertEqual(lc._version_key(""), (0,))
        self.assertEqual(lc._version_key(None), (0,))

    def test_version_key_ordering(self):
        self.assertTrue(lc._version_key("0.8.9") > lc._version_key("0.8.8"))
        self.assertTrue(lc._version_key("0.9.0") > lc._version_key("0.8.99"))
        self.assertTrue(lc._version_key("1.0.0") > lc._version_key("0.99.99"))

    def test_strip_v(self):
        self.assertEqual(lc._strip_v("v0.8.8"), "0.8.8")
        self.assertEqual(lc._strip_v("0.8.8"), "0.8.8")
        self.assertEqual(lc._strip_v(""), "")
        self.assertEqual(lc._strip_v(None), "")

    def test_update_availability_matrix(self):
        cases = [
            ("0.8.8", "0.8.8", "up-to-date"),
            ("0.8.8", "0.8.9", "update-available"),
            ("0.8.8", "", "unknown"),
            ("", "0.8.9", "update-available"),
            ("0.8.9", "0.8.8", "up-to-date"),
        ]
        for installed, latest, expected in cases:
            self.assertEqual(
                lc._update_availability(installed, latest), expected,
                f"{installed}/{latest} → {expected}")

    def test_update_header_row(self):
        row = lc._update_header_row("0.8.8", "0.8.9")
        self.assertIn("0.8.8", row)
        self.assertIn("0.8.9", row)
        row = lc._update_header_row("0.8.8", "0.8.8")
        self.assertIn("актуальна", row)
        row = lc._update_header_row("0.8.8", "")
        self.assertIn("недоступен", row)


# ════════════════════════════════════════════════════════════════════════════
#  2-3. ЗЕРКАЛА + PACKAGE SPEC
# ════════════════════════════════════════════════════════════════════════════
class TestMirrorsAndSpec(unittest.TestCase):

    def test_mirror_urls_tag_first(self):
        urls = lc._app_mirror_urls("librechat-v0.8.8.tar.gz")
        self.assertGreaterEqual(len(urls), 5)
        # теговые архивы — первыми (детерминизм версии)
        self.assertIn("https://github.com/LibreChat-AI/LibreChat"
                      "/archive/refs/tags/v0.8.8.tar.gz", urls)
        self.assertIn("https://codeload.github.com/LibreChat-AI/LibreChat"
                      "/tar.gz/refs/tags/v0.8.8", urls)
        # github-прокси — рабочие хосты из github_mirrors.GITHUB_PROXY_HOSTS
        self.assertTrue(any(u.startswith("https://ghproxy.net/") for u in urls))
        self.assertTrue(any(u.startswith("https://gh-proxy.com/") for u in urls))

    def test_mirror_urls_deterministic(self):
        a = lc._app_mirror_urls("librechat-v0.8.8.tar.gz")
        b = lc._app_mirror_urls("librechat-v0.8.8.tar.gz")
        self.assertEqual(a, b)

    def test_app_spec_invariants(self):
        spec = lc._app_spec("v0.8.8")
        self.assertEqual(spec.filename_builder(), "librechat-v0.8.8.tar.gz")
        self.assertGreaterEqual(spec.min_size, 1_000_000)
        self.assertEqual(spec.manual_incoming_dir, Path("/root"))
        # инвариант download_manager: manual_incoming_dir ≠ install_dests
        for dest in spec.install_dests:
            self.assertNotEqual(spec.manual_incoming_dir, dest)
        # зеркала получают имя файла (аргумент fetch_package)
        self.assertTrue(spec.mirror_urls_builder(
            filename="librechat-v0.8.8.tar.gz"))


# ════════════════════════════════════════════════════════════════════════════
#  4. ТАРБОЛЛ: extract + actual version
# ════════════════════════════════════════════════════════════════════════════
class TestTarball(unittest.TestCase):

    def _make_tarball(self, tmp: Path) -> Path:
        """Мини-тарболл апстрима: <repo>-<tag>/{docker-compose.yml,
        .env.example, package.json, api/server.js}."""
        src = tmp / "src"
        (src / "api").mkdir(parents=True)
        (src / "docker-compose.yml").write_text("services: {}\n")
        (src / ".env.example").write_text("PORT=3080\nCREDS_KEY=\n")
        (src / "package.json").write_text('{"version": "v0.8.8"}\n')
        (src / "api" / "server.js").write_text("// api\n")
        tar_path = tmp / "librechat-v0.8.8.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            # GitHub-архивы кладут всё под <repo>-<tag>/
            tar.add(src, arcname="LibreChat-0.8.8")
        return tar_path

    def test_extract_app_slices_repo_root(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            tar_path = self._make_tarball(tmp)
            dest = tmp / "out"
            self.assertTrue(lc._extract_app(tar_path, dest))
            # срез <repo>-<tag>/ — файлы в корне dest
            self.assertTrue((dest / "docker-compose.yml").exists())
            self.assertTrue((dest / ".env.example").exists())
            self.assertTrue((dest / "api" / "server.js").exists())
            # LICENSE-кредит MIT (условие лицензии апстрима)
            lic = dest / "LICENSE.upstream"
            self.assertTrue(lic.exists())
            self.assertIn("MIT", lic.read_text())

    def test_extract_app_traversal_guard(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = tmp / "src"
            src.mkdir()
            (src / "ok.txt").write_text("ok")
            evil_dir = src / ".."
            # готовим тарболл с «злым» членом вручную
            tar_path = tmp / "evil.tar.gz"
            with tarfile.open(tar_path, "w:gz") as tar:
                tar.add(src / "ok.txt", arcname="LibreChat-0.8.8/ok.txt")
                # абсолютный путь + .. — оба должны быть отброшены
                info = tarfile.TarInfo("/etc/passwd-evil")
                info.size = 0
                tar.addfile(info)
                info2 = tarfile.TarInfo("LibreChat-0.8.8/../../evil.txt")
                info2.size = 0
                tar.addfile(info2)
            dest = tmp / "out"
            # docker-compose.yml нет → extract вернёт False, но и не упадёт;
            # проверяем именно guard: злые файлы не созданы
            lc._extract_app(tar_path, dest)
            self.assertFalse((Path("/etc/passwd-evil")).exists())
            self.assertFalse((dest / "../../evil.txt").exists()
                             or (tmp / "evil.txt").exists())
            self.assertTrue((dest / "ok.txt").exists())

    def test_app_actual_version(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "package.json").write_text('{"version": "v0.8.8"}\n')
            self.assertEqual(lc._app_actual_version(tmp), "0.8.8")
            (tmp / "package.json").write_text('{"version": "garbage"}\n')
            self.assertEqual(lc._app_actual_version(tmp), "")
            self.assertEqual(lc._app_actual_version(tmp / "missing"), "")


# ════════════════════════════════════════════════════════════════════════════
#  5. ENV-ПАТЧ
# ════════════════════════════════════════════════════════════════════════════
class TestEnvPatch(unittest.TestCase):

    _EXAMPLE = (
        "HOST=localhost\n"
        "PORT=3080\n"
        "DOMAIN_CLIENT=http://localhost:3080\n"
        "# UID=1000\n"
        "# GID=1000\n"
        "CREDS_KEY=\n"
        "CREDS_IV=\n"
        "MEILI_MASTER_KEY=\n"
        "ALLOW_REGISTRATION=true\n"
        "# ENDPOINTS=openAI,assistants,azureOpenAI,google,anthropic\n"
    )

    def test_patch_env_replaces_keys(self):
        env = lc._patch_env_text(
            self._EXAMPLE, port=3456, creds_key="K" * 64, creds_iv="I" * 16,
            meili_key="M" * 64, allow_registration=False)
        self.assertIn("PORT=3456\n", env)
        self.assertNotIn("PORT=3080\n", env)
        self.assertIn(f"CREDS_KEY={'K' * 64}\n", env)
        self.assertIn(f"CREDS_IV={'I' * 16}\n", env)
        self.assertIn(f"MEILI_MASTER_KEY={'M' * 64}\n", env)
        self.assertIn("ALLOW_REGISTRATION=false\n", env)

    def test_patch_env_uncomments_uid_gid(self):
        env = lc._patch_env_text(
            self._EXAMPLE, port=3080, creds_key="k", creds_iv="i",
            meili_key="m", allow_registration=True)
        # закомментированные UID/GID должны быть раскомментированы и заданы
        self.assertIn("UID=0\n", env)
        self.assertIn("GID=0\n", env)
        self.assertNotIn("# UID=1000\n", env)

    def test_patch_env_appends_missing(self):
        env = lc._patch_env_text(
            "HOST=localhost\n", port=3080, creds_key="k", creds_iv="i",
            meili_key="m", allow_registration=True, admin_port=3095)
        for key in ("PORT=", "CREDS_KEY=", "CREDS_IV=", "MEILI_MASTER_KEY=",
                    "ALLOW_REGISTRATION=", "ADMIN_PANEL_PORT=", "UID=",
                    "GID="):
            self.assertIsNotNone(
                re.search(rf"^{re.escape(key)}", env, re.MULTILINE),
                f"нет активной строки {key}")

    def test_patch_env_admin_port_and_zai(self):
        env = lc._patch_env_text(
            self._EXAMPLE, port=3080, creds_key="k", creds_iv="i",
            meili_key="m", allow_registration=True, admin_port=3097,
            zai_key="sk-secret", admin_secret="S" * 64)
        self.assertIn("ADMIN_PANEL_PORT=3097\n", env)
        self.assertIn(f"ADMIN_PANEL_SESSION_SECRET={'S' * 64}\n", env)
        self.assertIn("ZAI_API_KEY=sk-secret\n", env)
        # без ключа ZAI_API_KEY не пишется вовсе
        env2 = lc._patch_env_text(
            self._EXAMPLE, port=3080, creds_key="k", creds_iv="i",
            meili_key="m", allow_registration=True)
        self.assertNotIn("ZAI_API_KEY", env2)

    def test_write_env_file_live_formats(self):
        """REGRESSION (живой инцидент 01.11 №3, vds13195): форматы секретов
        LIVE-валидированы апстримом — api: «CREDS_IV must be exactly 32
        hexadecimal characters (16 bytes)», admin-panel: «SESSION_SECRET
        must be set to at least 32 characters». hex(N) = 2N символов."""
        with tempfile.TemporaryDirectory() as td:
            app = Path(td)
            (app / ".env.example").write_text(
                "PORT=3080\nCREDS_KEY=\nCREDS_IV=\n"
                "ADMIN_PANEL_SESSION_SECRET=\n# UID=1000\n")
            with patch.object(lc, "_APP_DIR", app):
                self.assertTrue(lc._write_env_file(
                    3456, True, zai_key="", admin_port=3095))
            env = (app / ".env").read_text(encoding="utf-8")
            key = re.search(r"^CREDS_KEY=([0-9a-f]+)$", env, re.M).group(1)
            iv = re.search(r"^CREDS_IV=([0-9a-f]+)$", env, re.M).group(1)
            sec = re.search(
                r"^ADMIN_PANEL_SESSION_SECRET=([0-9a-f]+)$", env, re.M).group(1)
            self.assertEqual(len(key), 64)            # 32 байта
            self.assertEqual(len(iv), 32)             # 16 байт (!)
            self.assertGreaterEqual(len(sec), 32)     # панель требует ≥32
            self.assertIn("PORT=3456\n", env)
            self.assertIn("UID=0\n", env)
            # librechat.yaml (custom endpoint GLM) записан рядом
            self.assertTrue((app / "librechat.yaml").exists())

    def test_patch_env_idempotent_shape(self):
        once = lc._patch_env_text(
            self._EXAMPLE, port=3080, creds_key="k", creds_iv="i",
            meili_key="m", allow_registration=True)
        twice = lc._patch_env_text(
            once, port=3080, creds_key="k", creds_iv="i",
            meili_key="m", allow_registration=True)
        self.assertEqual(once, twice)


# ════════════════════════════════════════════════════════════════════════════
#  6. COMPOSE-ПАТЧ
# ════════════════════════════════════════════════════════════════════════════
class TestComposePatch(unittest.TestCase):

    _COMPOSE = (
        "services:\n"
        "  api:\n"
        "    ports:\n"
        "      - \"${PORT}:${PORT}\"\n"
        "    volumes:\n"
        "      - ./skill:/app/skill\n"
        "  admin-panel:\n"
        "    ports:\n"
        "      - \"${ADMIN_PANEL_PORT:-3000}:3000\"\n"
    )

    def test_ports_go_loopback(self):
        out = lc._patch_compose_text(self._COMPOSE)
        self.assertIn('- "127.0.0.1:${PORT}:${PORT}"', out)
        self.assertIn('- "127.0.0.1:${ADMIN_PANEL_PORT:-3000}:3000"', out)
        self.assertNotIn('- "${PORT}:${PORT}"', out)
        self.assertNotIn('- "${ADMIN_PANEL_PORT:-3000}:3000"', out)

    def test_librechat_yaml_volume_mounted(self):
        out = lc._patch_compose_text(self._COMPOSE)
        self.assertIn("- ./librechat.yaml:/app/librechat.yaml", out)

    def test_idempotent(self):
        once = lc._patch_compose_text(self._COMPOSE)
        twice = lc._patch_compose_text(once)
        self.assertEqual(once, twice)
        # volume не задублирован
        self.assertEqual(
            once.count("./librechat.yaml:/app/librechat.yaml"),
            twice.count("./librechat.yaml:/app/librechat.yaml"))

    def test_mount_yaml_disabled(self):
        out = lc._patch_compose_text(self._COMPOSE, mount_yaml=False)
        self.assertNotIn("librechat.yaml:/app/librechat.yaml", out)
        self.assertIn("127.0.0.1", out)   # порты — всё равно loopback


# ════════════════════════════════════════════════════════════════════════════
#  7. librechat.yaml (custom endpoint GLM)
# ════════════════════════════════════════════════════════════════════════════
class TestLibrechatYaml(unittest.TestCase):

    def test_yaml_custom_endpoint_contract(self):
        y = lc._render_librechat_yaml()
        self.assertIn("endpoints:", y)
        self.assertIn("custom:", y)
        self.assertIn("name: 'zai'", y)
        # ключ НЕ в plaintext — только интерполяция env
        self.assertIn("apiKey: '${ZAI_API_KEY}'", y)
        # OpenAI-совместимый базовый URL Z.ai
        self.assertIn("baseURL: 'https://api.z.ai/api/paas/v4'", y)
        self.assertIn("fetch: true", y)
        # REGRESSION (живой инцидент 01.11 №4): models.default — ОБЯЗАТЕЛЬНЫЙ
        # массив (Zod: «expected array, received undefined» → Exiting)
        self.assertRegex(y, r"models:\s*\n\s+default:\s*\[")
        # управление — из TUI (канон проектов: «НЕ редактировать вручную»)
        self.assertIn("НЕ редактировать вручную", y)


# ════════════════════════════════════════════════════════════════════════════
#  8. SYSTEMD-ЮНИТ
# ════════════════════════════════════════════════════════════════════════════
class TestSystemdUnit(unittest.TestCase):

    def test_unit_contract(self):
        import inspect
        src = inspect.getsource(lc._write_service_unit)
        # compose lifecycle
        self.assertIn("docker compose up -d --remove-orphans", src)
        self.assertIn("docker compose down", src)
        # oneshot + RemainAfterExit (up -d выходит сразу)
        self.assertIn("RemainAfterExit=yes", src)
        # зависимость от docker
        self.assertIn("Requires=docker.service", src)
        # длинный pull при первом старте
        self.assertIn("TimeoutStartSec=1800", src)


# ════════════════════════════════════════════════════════════════════════════
#  9. RUNTIME-ВЕРСИЯ (package.json из контейнера) + смоук /api/config
# ════════════════════════════════════════════════════════════════════════════
class TestRuntimeVersion(unittest.TestCase):

    def test_runtime_version_regex_variants(self):
        # _runtime_version парсит package.json из контейнера; проверяем
        # сам регекс на форматах версий апстрима (вкл. rc-префиксы).
        pattern = r'"version"\s*:\s*"v?(\d+\.\d+\.\d+[\w.-]*)"'
        for body, expected in [
            ('{"name":"librechat","version":"v0.8.8"}', "0.8.8"),
            ('{"version":"0.8.8"}', "0.8.8"),
            ('{"version":"v0.8.9-rc1"}', "0.8.9-rc1"),
            ('{"version":"v1.0.0-beta.3"}', "1.0.0-beta.3"),
        ]:
            m = re.search(pattern, body)
            self.assertIsNotNone(m, body)
            self.assertEqual(m.group(1), expected, body)

    def test_smoke_check_no_proxy_leak(self):
        # ProxyHandler({}) — на серверах с http_proxy 127.0.0.1 не должен
        # гнаться через прокси (урок triple_panel._smoke_check);
        # /api/version в новых образах УДАЛЁН (LIVE 01.11, 404) —
        # смоук обязан идти на /api/config (публичный, без auth).
        # (assertNotIn — только на КОДОВУЮ строку запроса: докстринг
        # законно упоминает /api/version как историческую справку)
        import inspect
        src = inspect.getsource(lc._smoke_check)
        self.assertIn("ProxyHandler({})", src)
        self.assertIn(
            'opener.open(f"http://127.0.0.1:{port}/api/config"', src)
        self.assertNotIn(
            'opener.open(f"http://127.0.0.1:{port}/api/version"', src)


# ════════════════════════════════════════════════════════════════════════════
#  10. NGINX FRONT: делегирование + long_timeouts
# ════════════════════════════════════════════════════════════════════════════
class TestNginxFront(unittest.TestCase):

    def test_nginx_install_delegates_with_long_timeouts(self):
        """_nginx_install обязан звать panel_nginx_front_install с
        long_timeouts=True (LLM-стримы) и service_tag chimera-librechat-nginx."""
        calls = {}

        def fake_install(**kwargs):
            calls.update(kwargs)
            return True, "ok"

        def fake_ask_tls(panel_name=""):
            return False, None

        def fake_ask_domain(default=None):
            return "chat.example.com"

        fake_pnf = type(sys)("chimera.modules.panel_nginx_front")
        fake_pnf.panel_nginx_front_install = fake_install
        fake_pnf.ask_tls_mode = fake_ask_tls
        fake_pnf.ask_domain = fake_ask_domain

        snap = _snapshot_module("chimera.modules.panel_nginx_front")
        _install_fake("chimera.modules.panel_nginx_front", fake_pnf)
        try:
            # состояние + /opt не существуют — только контракт вызова
            with patch.object(lc, "_NGINX_STATE_FILE",
                              Path(tempfile.gettempdir()) / "lc-test-nginx.json"):
                ok, msg = lc._nginx_install(False, "chat.example.com")
            self.assertTrue(ok)
            self.assertEqual(calls.get("service_tag"),
                             "chimera-librechat-nginx")
            self.assertEqual(calls.get("site_name"), "chimera-librechat")
            self.assertEqual(calls.get("backend_port"), lc._DEFAULT_PORT)
            self.assertEqual(calls.get("cert_name_slug"), "chimera-librechat")
            self.assertTrue(calls.get("long_timeouts"))
            self.assertEqual(calls.get("title"), "LibreChat")
            # nginx front порт — 3443 (дефолт из констант)
            self.assertEqual(calls.get("port"), lc.DEFAULT_NGINX_PORT)
        finally:
            _restore_module("chimera.modules.panel_nginx_front", snap)

    def test_generate_vhost_long_timeouts(self):
        from chimera.modules.panel_nginx_front import _generate_vhost
        cert = Path("/etc/nginx/ssl/x.crt"); key = Path("/etc/nginx/ssl/x.key")
        short = _generate_vhost(443, 3080, cert, key, "x.example",
                                panel_name_slug="t")
        longv = _generate_vhost(443, 3080, cert, key, "x.example",
                                panel_name_slug="t", long_timeouts=True)
        self.assertIn("proxy_read_timeout 60s", short)
        self.assertIn("proxy_read_timeout 3600s", longv)
        self.assertIn("proxy_send_timeout 3600s", longv)
        # дефолт не изменился (обратная совместимость панелей B4/Triple/WPP)
        self.assertIn("proxy_read_timeout 60s", short)
        self.assertIn("proxy_send_timeout 60s", short)


# ════════════════════════════════════════════════════════════════════════════
#  11. PORT REGISTRY: теги
# ════════════════════════════════════════════════════════════════════════════
class TestPortRegistryTags(unittest.TestCase):

    def test_service_tags_exist(self):
        from chimera.modules import port_registry as pr
        self.assertEqual(pr.SERVICE_LIBRECHAT_WEB, "librechat_web")
        self.assertEqual(pr.SERVICE_LIBRECHAT_NGINX,
                         "chimera-librechat-nginx")

    def test_install_uses_registry_tag(self):
        import inspect
        src = inspect.getsource(lc._install)
        self.assertIn("SERVICE_LIBRECHAT_WEB", src)
        self.assertIn("port_register", src)
        # uninstall снимает регистрацию
        src2 = inspect.getsource(lc._uninstall)
        self.assertIn("port_unregister", src2)
        self.assertIn("SERVICE_LIBRECHAT_WEB", src2)

    def test_reinstall_owns_registry_tag(self):
        """REGRESSION (живой инцидент 01.11, vds13195): повторная установка
        после сбоя не должна конфликтовать с СОБСТВЕННОЙ регистрацией
        порта (прошлый запуск упал после port_register, до state).
        Контракт: _install снимает ВСЕ записи тега перед регистрацией и
        спрашивает порт с exclude_tag=SERVICE_LIBRECHAT_WEB."""
        import inspect
        src = inspect.getsource(lc._install)
        self.assertIn("port_unregister(SERVICE_LIBRECHAT_WEB)", src)
        self.assertIn("_ask_web_port(exclude_tag=SERVICE_LIBRECHAT_WEB)", src)
        # хелперы прокидывают exclude в port_registry API
        sig_ask = inspect.signature(lc._ask_web_port)
        self.assertIn("exclude_tag", sig_ask.parameters)
        src_val = inspect.getsource(lc._validate_web_port)
        self.assertIn("exclude_service=exclude_tag", src_val)
        src_pc = inspect.getsource(lc._port_conflicts)
        self.assertIn("exclude_service=exclude_service", src_pc)
        # port_get_conflicts/port_is_free реально поддерживают exclude
        from chimera.modules import port_registry as pr
        self.assertIn("exclude_service",
                      inspect.signature(pr.port_get_conflicts).parameters)
        self.assertIn("exclude_service",
                      inspect.signature(pr.port_is_free).parameters)


# ════════════════════════════════════════════════════════════════════════════
#  12. rest_api: пункт 9 в хабе панелей
# ════════════════════════════════════════════════════════════════════════════
class TestRestApiIntegration(unittest.TestCase):

    def test_hub_menu_has_librechat_item(self):
        from chimera.modules import rest_api
        import inspect
        src = inspect.getsource(rest_api.do_manage_web_panel)
        self.assertIn('ch == "9"', src)
        self.assertIn("do_librechat_menu", src)
        self.assertIn("LibreChat (AI-чат)", src)


# ════════════════════════════════════════════════════════════════════════════
#  13. МЕНЮ + CLI (регресс-паттерн test_triple_panel)
# ════════════════════════════════════════════════════════════════════════════
class TestMenuAndCli(unittest.TestCase):

    def test_menu_items_render(self):
        """Пункты меню 1-9/0/Q присутствуют в рендере (not installed)."""
        fake_state = {"installed": False, "web_port": 3080,
                      "admin_port": 3095, "version": "", "zai_enabled": False,
                      "allow_registration": True, "upstream_cache":
                          {"version": "", "ts": 0}}
        buf = io.StringIO()
        inputs = iter(["q"])
        with patch.object(lc, "_load_state", return_value=dict(fake_state)), \
             patch.object(lc, "_refresh_upstream_cache", return_value=""), \
             patch.object(lc, "_service_active", return_value=False), \
             patch.object(lc.os, "system", return_value=0), \
             patch("builtins.input", lambda *a, **k: next(inputs)), \
             patch.object(lc, "proto_ask", side_effect=lambda *a, **k: next(inputs)), \
             redirect_stdout(buf):
            try:
                lc.do_librechat_menu()
            except StopIteration:
                pass
        out = buf.getvalue()
        for item in ("Установить LibreChat", "Обновить стек",
                     "Перезапустить стек", "Регистрация", "Сменить порт",
                     "Логи api", "SSH-туннелю", "nginx front",
                     "GLM (Z.ai)", "Удалить", "Назад"):
            self.assertIn(item, out, f"пункт «{item}» не найден в меню")

    def test_main_calls_menu(self):
        """REGRESSION: __main__ librechat вызывает do_librechat_menu."""
        src = (Path(lc.__file__)).read_text(encoding="utf-8")
        self.assertIn("do_librechat_menu()", src.split('if __name__')[1])

    def test_main_smoke_cli(self):
        src = (Path(lc.__file__)).read_text(encoding="utf-8")
        tail = src.split('if __name__')[1]
        self.assertIn('"--smoke" in sys.argv', tail)
        self.assertIn('"--version" in sys.argv', tail)

    def test_run_signature_accepts_cwd(self):
        """REGRESSION (живой инцидент 01.11, установка на vds13195):
        _compose передаёт cwd=str(_APP_DIR) в _run — сигнатура _run
        обязана принимать cwd и timeout, иначе pull падает TypeError."""
        import inspect
        sig = inspect.signature(lc._run)
        self.assertIn("cwd", sig.parameters)
        self.assertIn("timeout", sig.parameters)
        # и действительно прокидывает
        src = inspect.getsource(lc._compose)
        self.assertIn("cwd=str(_APP_DIR)", src)
        # живой вызов с cwd не падает (docker не нужен: несуществующая cwd
        # → только FileNotFoundError от subprocess, не TypeError)
        try:
            lc._run(["/bin/true"], capture=True, check=False,
                    timeout=10, cwd="/tmp")
        except TypeError:
            self.fail("_run не принимает cwd (живой инцидент)")

    def test_state_defaults(self):
        """Дефолты state: версия порта, порты, upstream-кэш (без файла)."""
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td) / "librechat_state.json"
            with patch.object(lc, "_STATE_FILE", fake):
                st = lc._load_state()
                self.assertFalse(st["installed"])
                self.assertEqual(st["web_port"], 3080)
                self.assertEqual(st["admin_port"], 3095)
                self.assertTrue(st["allow_registration"])

    def test_upstream_cache_ttl(self):
        """Кэш 5 мин: свежий — не ходит в сеть, протухший — обновляет."""
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td) / "librechat_state.json"
            with patch.object(lc, "_STATE_FILE", fake):
                with patch.object(lc, "_detect_latest_version",
                                  return_value="0.9.0") as det:
                    v = lc._refresh_upstream_cache(force=True)
                    self.assertEqual(v, "0.9.0")
                    self.assertEqual(det.call_count, 1)
                    # свежий кэш — сеть не дёргается
                    v2 = lc._refresh_upstream_cache()
                    self.assertEqual(v2, "0.9.0")
                    self.assertEqual(det.call_count, 1)
                    # протухший — дёргается
                    st = lc._load_state()
                    st["upstream_cache"]["ts"] = 0
                    lc._save_state(st)
                    v3 = lc._refresh_upstream_cache()
                    self.assertEqual(v3, "0.9.0")
                    self.assertEqual(det.call_count, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
