#!/usr/bin/env python3
"""
tests/test_openflux.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/openflux.py.

Покрывает:
  1.  _validate_doc_url — edit-ссылка vs короткая /i/ vs мусор
  2.  _parse_go_version / _go_meets — версии тулчейна
  3.  _gen_transport_key — генерация секрета e2e
  4.  _render_env_file — EnvironmentFile (URL/транспорт/oneme-хвост)
  5.  _render_systemd_unit — proxy (unprivileged, без iptables) и
      raw (root, scoped RST-drop + ExecStopPost-cleanup)
  6.  _render_mihomo_fragment — узел socks5 для клиентского mihomo
  7.  _render_client_bundle — бандл: команды, ключ, mihomo-фрагмент
  8.  state roundtrip через proto_load_state/proto_save_state (tmpdir)
  9.  _TRANSPORTS — целостность реестра (ключи, тройки, oneme вне меню)
  10. download_manager: GO_TARBALL_SPEC / OPENFLUX_SRC_SPEC
      (зеркала, имена, min_size, _ref_slug), _ensure_go fallback-порядок,
      _resolve_main_sha / _fetch_sources (пин/main/fallback)
  11. bridge: _render_bridge_env_file / _render_bridge_unit
      (unprivileged, явный bind — не дефолт ':1080' апстрима),
      фрагмент mihomo, CLI-валидация bind/port
  12. port-цикл через port_registry: _bridge_port_open
      (занят → провал с конфликтами; свободен → регистрация; 0.0.0.0 →
      UFW), _bridge_port_close (ufw_close + unregister),
      деактивация/удаление вызывают закрытие, экстрактор _core
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """openflux.py не импортирует chimera._core (лёгкий модуль), но
    proto_common/text_width могут; фейкосл@Module гарантирует изоляцию
    от живого окружения сервера — тот же приём, что test_mieru.py."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    if not core_path.exists():
        return
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
    sys.modules.setdefault("chimera._core", fake_core)


_EDIT_URL = ("https://disk.yandex.ru/edit/d/abc123XYZ?v=1697"
             "&sk=u89f8sfahflkajshdflkajsdfhlasdf")


class OpenfluxTestCase(unittest.TestCase):
    """Базовый класс: чистый импорт модуля под тест."""

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import openflux
        self.of = openflux


class TestValidateDocUrl(OpenfluxTestCase):
    """1. _validate_doc_url — валидация носителя."""

    def test_edit_url_ok(self):
        ok, why = self.of._validate_doc_url(_EDIT_URL, "yandex")
        self.assertTrue(ok, why)
        ok, why = self.of._validate_doc_url(_EDIT_URL, "vyandex")
        self.assertTrue(ok, why)

    def test_short_link_rejected_with_hint(self):
        ok, why = self.of._validate_doc_url(
            "https://disk.yandex.ru/i/abc123", "yandex")
        self.assertFalse(ok)
        self.assertIn("/i/", why)

    def test_http_rejected(self):
        ok, _ = self.of._validate_doc_url(
            "http://disk.yandex.ru/edit/d/x?sk=y", "yandex")
        self.assertFalse(ok)

    def test_foreign_host_rejected(self):
        ok, _ = self.of._validate_doc_url(
            "https://example.com/edit/d/x?sk=y", "yandex")
        self.assertFalse(ok)

    def test_empty_rejected(self):
        ok, _ = self.of._validate_doc_url("", "yandex")
        self.assertFalse(ok)

    def test_no_query_rejected(self):
        ok, _ = self.of._validate_doc_url(
            "https://disk.yandex.ru/edit/d/abc", "yandex")
        self.assertFalse(ok)

    def test_cups_and_oneme_dont_need_url(self):
        # cups: комнаты создаёт exit, oneme: токен вместо URL
        for t in ("cupsonline", "oneme"):
            ok, _ = self.of._validate_doc_url("", t)
            self.assertTrue(ok)
            ok, _ = self.of._validate_doc_url("что угодно", t)
            self.assertTrue(ok)


class TestGoVersion(OpenfluxTestCase):
    """2. Версии Go-тулчейна."""

    def test_parse_real_output(self):
        self.assertEqual(
            self.of._parse_go_version("go version go1.26.4 linux/amd64"),
            (1, 26, 4))
        self.assertEqual(
            self.of._parse_go_version("go version go1.27.1 windows/amd64"),
            (1, 27, 1))

    def test_parse_two_component(self):
        self.assertEqual(self.of._parse_go_version("go1.26"), (1, 26, 0))

    def test_parse_garbage(self):
        self.assertIsNone(self.of._parse_go_version("bash: go: command not found"))
        self.assertIsNone(self.of._parse_go_version(""))

    def test_meets(self):
        self.assertTrue(self.of._go_meets("go version go1.26.4 linux/amd64"))
        self.assertTrue(self.of._go_meets("go version go1.27.0 linux/amd64"))
        self.assertFalse(self.of._go_meets("go version go1.25.9 linux/amd64"))
        self.assertFalse(self.of._go_meets("нет го"))
        # ровно на границе (1.26.4 == минимум)
        self.assertTrue(self.of._go_meets("go1.26.4", (1, 26, 4)))
        self.assertFalse(self.of._go_meets("go1.26.3", (1, 26, 4)))


class TestGenTransportKey(OpenfluxTestCase):
    """3. Секрет e2e (AES-256-GCM upstream требует ≥16 символов)."""

    def test_length_and_uniqueness(self):
        keys = {self.of._gen_transport_key() for _ in range(32)}
        self.assertEqual(len(keys), 32)          # все разные
        for k in keys:
            self.assertGreaterEqual(len(k), 16)  # минимум upstream
            self.assertEqual(len(k), 44)         # base64(32 байта)
        import base64
        for k in keys:
            raw = base64.b64decode(k)            # валидный base64
            self.assertEqual(len(raw), 32)       # энтропия 256 бит


class TestRenderEnvFile(OpenfluxTestCase):
    """4. EnvironmentFile для systemd."""

    def test_basic(self):
        out = self.of._render_env_file(_EDIT_URL, "yandex")
        self.assertIn("OPENFLUX_URL=" + _EDIT_URL, out)
        self.assertIn("OPENFLUX_TRANSPORT=yandex", out)
        self.assertNotIn("transport.key", out)      # ключ — отдельным файлом

    def test_url_with_space_quoted(self):
        out = self.of._render_env_file("https://x/edit/d/a b?sk=c", "yandex")
        self.assertIn('OPENFLUX_URL="https://x/edit/d/a b?sk=c"', out)

    def test_oneme_gets_token_placeholders(self):
        out = self.of._render_env_file("", "oneme")
        self.assertIn("OPENFLUX_MAX_TOKEN=", out)
        self.assertIn("OPENFLUX_MAX_UID=", out)

    def test_yandex_no_oneme_placeholders(self):
        out = self.of._render_env_file(_EDIT_URL, "yandex")
        self.assertNotIn("OPENFLUX_MAX_TOKEN", out)


class TestRenderSystemdUnit(OpenfluxTestCase):
    """5. Юнит: proxy-режим по умолчанию, raw — опция."""

    def test_proxy_mode_unprivileged(self):
        u = self.of._render_systemd_unit("yandex")
        self.assertIn("User=openflux", u)
        self.assertIn("Group=openflux", u)
        self.assertIn("--exit-node", u)
        self.assertIn("--transport yandex", u)
        self.assertIn("--url ${OPENFLUX_URL}", u)
        self.assertIn("--encryption-key-file /etc/openflux/transport.key", u)
        self.assertIn("EnvironmentFile=/etc/openflux/openflux.env", u)
        self.assertIn("NoNewPrivileges=true", u)
        # proxy-режим: НИКАКИХ iptables и root-привилегий
        self.assertNotIn("iptables", u)
        self.assertNotIn("--mode raw", u)
        self.assertNotIn("--local-ip", u)

    def test_raw_mode_root_and_scoped_rst(self):
        u = self.of._render_systemd_unit(
            "yandex", raw_mode=True, local_ip="198.51.100.7")
        self.assertNotIn("User=openflux", u)            # root (systemd default)
        self.assertIn("--mode raw", u)
        self.assertIn("--local-ip 198.51.100.7", u)
        # scoped RST-drop только с egress-IP, не host-wide
        self.assertIn("--tcp-flags RST RST -s 198.51.100.7 -j DROP", u)
        # cleanup: правило снимается на остановке — мусора не остаётся
        self.assertIn("ExecStopPost=", u)
        self.assertIn("-D OUTPUT", u)

    def test_raw_mode_default_ip(self):
        with patch.object(self.of, "_get_server_ip",
                          return_value="203.0.113.10"):
            u = self.of._render_systemd_unit("vyandex", raw_mode=True)
        self.assertIn("--local-ip 203.0.113.10", u)

    def test_restart_policy(self):
        for raw in (False, True):
            u = self.of._render_systemd_unit("yandex", raw_mode=raw)
            self.assertIn("Restart=always", u)
            self.assertIn("WantedBy=multi-user.target", u)

    def test_oneme_token_passthrough(self):
        u = self.of._render_systemd_unit("oneme")
        self.assertIn("--maxToken ${OPENFLUX_MAX_TOKEN}", u)
        self.assertIn("--maxUid ${OPENFLUX_MAX_UID}", u)
        u2 = self.of._render_systemd_unit("yandex")
        self.assertNotIn("--maxToken", u2)


class TestMihomoFragment(OpenfluxTestCase):
    """6. Узел для клиентского mihomo/Party."""

    def test_fragment(self):
        f = self.of._render_mihomo_fragment()
        self.assertIn('- name: "🛟 OpenFlux"', f)
        self.assertIn("type: socks5", f)
        self.assertIn("server: 127.0.0.1", f)
        self.assertIn("port: 1080", f)
        # TCP-only туннель: UDP узел обещать не должен
        self.assertIn("udp: false", f)
        # никаких серверных секретов во фрагменте
        self.assertNotIn("sk=", f)


class TestClientBundle(OpenfluxTestCase):
    """7. Бандл: команды обеих сторон + ключ + mihomo."""

    def test_bundle_contents(self):
        b = self.of._render_client_bundle(
            _EDIT_URL, "yandex", "K"*44, "203.0.113.10")
        self.assertIn(_EDIT_URL, b)                      # URL целиком
        self.assertIn("--client", b)                      # клиентская команда
        self.assertIn("--transport yandex", b)
        self.assertIn("--encryption-key-file", b)
        self.assertIn("K"*44, b)                          # ключ отдельным блоком
        self.assertIn("203.0.113.10", b)                  # ожидаемый IP
        self.assertIn("testflight.apple.com/join/BwnAcdus", b)  # iOS
        self.assertIn("OpenFluxAndroid", b)               # Android
        self.assertIn("- name: \"🛟 OpenFlux\"", b)       # mihomo-фрагмент
        self.assertIn("curl --socks5-hostname", b)        # проверка

    def test_bundle_windows_and_linux_commands(self):
        b = self.of._render_client_bundle(_EDIT_URL, "yandex", "K"*44,
                                          "1.2.3.4")
        self.assertIn("openflux.exe", b)     # Windows
        self.assertIn("./openflux", b)       # Linux/macOS
        self.assertIn("--socks5 127.0.0.1:1080", b)


class TestStateRoundtrip(OpenfluxTestCase):
    """8. State-файл (proto_load/proto_save) в tmpdir."""

    def test_roundtrip(self):
        from chimera.modules.proto_common import (proto_load_state,
                                                  proto_save_state)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "openflux.json"
            proto_save_state(p, {
                "transport": "yandex",
                "doc_url": _EDIT_URL,
                "transport_key": "K"*44,
                "commit": "461905369bd8f44ad2aacff240540d6a01d38c4d",
                "pinned": True, "raw_mode": False, "local_ip": "",
            }, name="openflux.json")
            self.assertTrue(p.exists())
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            st = proto_load_state(p)
            self.assertEqual(st["transport"], "yandex")
            self.assertEqual(st["doc_url"], _EDIT_URL)
            self.assertTrue(st["pinned"])
            # повторная загрузка с дефолтами добивает отсутствующие ключи
            st2 = proto_load_state(p, {"raw_mode": False, "new_key": "x"})
            self.assertEqual(st2["new_key"], "x")
            self.assertEqual(st2["transport"], "yandex")

    def test_load_missing_returns_defaults(self):
        from chimera.modules.proto_common import proto_load_state
        st = proto_load_state(Path("/nonexistent/openflux.json"),
                              {"transport": "yandex"})
        self.assertEqual(st, {"transport": "yandex"})


class TestTransportRegistry(OpenfluxTestCase):
    """9. Реестр транспортов."""

    def test_registry_shape(self):
        for key, (label, needs_url, stability) in self.of._TRANSPORTS.items():
            self.assertTrue(label)                       # непустая метка
            self.assertIsInstance(needs_url, bool)
            self.assertIn(stability, ("verified", "experimental", "risky"))

    def test_oneme_not_in_menu(self):
        # README upstream: риск лимитации MAX-аккаунта — из меню скрыт
        self.assertNotIn("oneme", self.of._MENU_TRANSPORTS)
        self.assertIn("yandex", self.of._MENU_TRANSPORTS)

    def test_pinned_commit_shape(self):
        self.assertRegex(self.of._PINNED_COMMIT,
                         r"^[0-9a-f]{40}$")             # полный sha1

    def test_ls_remote_mirrors_cover_repo(self):
        # git больше не для клона — только ls-remote sha main
        for url in self.of._LS_REMOTE_URLS:
            self.assertIn("p1neappleXpress/OpenFlux.git", url)
        self.assertGreaterEqual(len(self.of._LS_REMOTE_URLS), 2)

    def test_default_bridge_constants(self):
        self.assertEqual(self.of._DEFAULT_BRIDGE_BIND, "127.0.0.1")
        self.assertEqual(self.of._DEFAULT_BRIDGE_PORT, 1080)
        self.assertIn("openflux-bridge", str(self.of._BRIDGE_SERVICE_FILE))


class TestOpenfluxPackages(OpenfluxTestCase):
    """10. PackageSpec'и всё через download_manager."""

    def setUp(self):
        super().setUp()
        from chimera.modules import openflux_packages
        self.pk = openflux_packages

    def test_go_delegates_to_shared_spec(self):
        # конвенция проекта: один GO_TOOLCHAIN_SPEC на все source-build
        # модули (wdtt/webdav_tunnel/olcrtc) — openflux НЕ дублирует спек
        from chimera.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
        self.assertFalse(hasattr(self.pk, "GO_TARBALL_SPEC"))
        self.assertEqual(GO_TOOLCHAIN_SPEC.filename_builder(
            version="go1.26.4", arch="amd64"),
            "go1.26.4.linux-amd64.tar.gz")
        from chimera.modules.go_toolchain_mirrors import (
            get_go_toolchain_mirrors,
        )
        urls = get_go_toolchain_mirrors("go1.26.4", "amd64")
        hosts = [u.split("/")[2] for u in urls]
        self.assertIn("go.dev", hosts)
        self.assertIn("mirrors.aliyun.com", hosts)   # РФ-устойчивый fallback
        self.assertGreaterEqual(len(urls), 3)
        self.assertNotIn(GO_TOOLCHAIN_SPEC.manual_incoming_dir,
                         GO_TOOLCHAIN_SPEC.install_dests)

    def test_src_spec_pin_urls(self):
        s = self.pk.OPENFLUX_SRC_SPEC
        sha = "461905369bd8f44ad2aacff240540d6a01d38c4d"
        fname = s.filename_builder(ref=sha)
        self.assertIn(sha[:12], fname)
        urls = s.mirror_urls_builder(filename=fname, ref=sha)
        self.assertIn(
            f"https://codeload.github.com/p1neappleXpress/OpenFlux"
            f"/tar.gz/{sha}", urls)
        # gh-proxy обёртки (конвенция проекта)
        proxied = [u for u in urls if "/https://github.com/" in u]
        self.assertGreaterEqual(len(proxied), 3)
        for u in proxied:
            self.assertIn(f"archive/{sha}.tar.gz", u)
        self.assertGreaterEqual(s.min_size, 30_000)
        self.assertNotIn(s.manual_incoming_dir, s.install_dests)

    def test_ref_slug_sanitizes_branch_ref(self):
        # 'refs/heads/main' содержит слэши — в имени файла быть не должно
        slug = self.pk._ref_slug("refs/heads/main")
        self.assertNotIn("/", slug)
        self.assertTrue(slug)
        self.assertEqual(self.pk._ref_slug("4619053abc"), "4619053abc")

    def test_src_spec_branch_fallback_url(self):
        s = self.pk.OPENFLUX_SRC_SPEC
        urls = s.mirror_urls_builder(
            filename="openflux-refs-heads-main.tar.gz",
            ref="refs/heads/main")
        self.assertTrue(any("tar.gz/refs/heads/main" in u for u in urls))
        self.assertTrue(any("archive/refs/heads/main.tar.gz" in u
                            for u in urls))


class TestResolveMainSha(OpenfluxTestCase):
    """10. ls-remote для main (best-effort)."""

    def test_sha_from_first_mirror(self):
        sha = "a" * 40
        r = type("R", (), {"returncode": 0, "stdout": sha + "\tHEAD\n"})()
        with patch.object(self.of, "_run", return_value=r), \
                patch("shutil.which", return_value="/usr/bin/git"):
            self.assertEqual(self.of._resolve_main_sha(), sha)

    def test_no_git_returns_empty(self):
        with patch("shutil.which", return_value=None):
            self.assertEqual(self.of._resolve_main_sha(), "")

    def test_garbage_output_skipped(self):
        bad = type("R", (), {"returncode": 0, "stdout": "not-a-sha\n"})()
        good = type("R", (), {"returncode": 0,
                               "stdout": "b" * 40 + "\tHEAD\n"})()
        with patch.object(self.of, "_run", side_effect=[bad, good]), \
                patch("shutil.which", return_value="/usr/bin/git"):
            self.assertEqual(self.of._resolve_main_sha(), "b" * 40)


class TestFetchSources(OpenfluxTestCase):
    """10. tarball-режим: пин / main по sha / main-fallback."""

    def test_pinned_ref_passed_to_fetch(self):
        calls = {}
        def fake_fetch(spec, **kw):
            calls["spec"], calls["kw"] = spec, kw
            return True
        import chimera.modules.download_manager as dm
        with patch.object(dm, "fetch_package", side_effect=fake_fetch):
            got = self.of._fetch_sources(use_main=False)
        self.assertEqual(got, self.of._PINNED_COMMIT)
        self.assertEqual(calls["kw"]["ref"], self.of._PINNED_COMMIT)

    def test_main_with_resolved_sha(self):
        sha = "c" * 40
        import chimera.modules.download_manager as dm
        with patch.object(dm, "fetch_package", return_value=True), \
                patch.object(self.of, "_resolve_main_sha", return_value=sha):
            got = self.of._fetch_sources(use_main=True)
        self.assertEqual(got, sha)

    def test_main_fallback_branch(self):
        import chimera.modules.download_manager as dm
        calls = {}
        def fake_fetch(spec, **kw):
            calls["kw"] = kw
            return True
        with patch.object(dm, "fetch_package", side_effect=fake_fetch), \
                patch.object(self.of, "_resolve_main_sha", return_value=""):
            got = self.of._fetch_sources(use_main=True)
        self.assertEqual(got, "main")
        self.assertEqual(calls["kw"]["ref"], "refs/heads/main")

    def test_fetch_failure_returns_none(self):
        import chimera.modules.download_manager as dm
        with patch.object(dm, "fetch_package", return_value=False):
            self.assertIsNone(self.of._fetch_sources(use_main=False))


class TestEnsureGoTarballFallback(OpenfluxTestCase):
    """10. snap провалился → fetch_package(GO_TOOLCHAIN_SPEC)."""

    def test_tarball_via_download_manager(self):
        import chimera.modules.download_manager as dm
        calls = {}
        def fake_fetch(spec, **kw):
            calls["spec"], calls["kw"] = spec, kw
            return True
        snap_fail = type("R", (), {"returncode": 1, "stderr": "no snap"})()
        with patch.object(self.of, "_current_go",
                          side_effect=["", "go version go1.26.4 linux/amd64"]), \
                patch.object(self.of, "_run", return_value=snap_fail), \
                patch.object(dm, "fetch_package", side_effect=fake_fetch):
            got = self.of._ensure_go()
        self.assertIn("1.26.4", got or "")
        from chimera.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
        self.assertIs(calls["spec"], GO_TOOLCHAIN_SPEC)
        self.assertEqual(calls["kw"]["version"], "go1.26.4")
        self.assertIn(calls["kw"]["arch"], ("amd64", "arm64"))

    def test_fetch_failure_returns_none(self):
        import chimera.modules.download_manager as dm
        snap_fail = type("R", (), {"returncode": 1, "stderr": ""})()
        with patch.object(self.of, "_current_go", return_value=""), \
                patch.object(self.of, "_run", return_value=snap_fail), \
                patch.object(dm, "fetch_package", return_value=False):
            self.assertIsNone(self.of._ensure_go())


class TestBridgeRender(OpenfluxTestCase):
    """11. Bridge env/unit/фрагмент."""

    def test_bridge_env_same_room(self):
        out = self.of._render_bridge_env_file(_EDIT_URL, "yandex")
        self.assertIn("OPENFLUX_URL=" + _EDIT_URL, out)
        self.assertIn("OPENFLUX_TRANSPORT=yandex", out)

    def test_bridge_env_oneme_placeholders(self):
        out = self.of._render_bridge_env_file("", "oneme")
        self.assertIn("OPENFLUX_MAX_TOKEN=", out)

    def test_bridge_unit_unprivileged_explicit_bind(self):
        u = self.of._render_bridge_unit("127.0.0.1", 1080, "yandex")
        self.assertIn("--client", u)
        self.assertIn("--socks5 127.0.0.1:1080", u)
        # дефолт апстрима ':1080' слушает ВСЕ интерфейсы — запрещено:
        # bind всегда явный
        self.assertNotIn("--socks5 :", u)
        self.assertIn("User=openflux", u)
        self.assertIn("EnvironmentFile=/etc/openflux/openflux-bridge.env", u)
        self.assertIn("--encryption-key-file /etc/openflux/transport.key", u)
        self.assertIn("NoNewPrivileges=true", u)
        self.assertNotIn("iptables", u)
        self.assertNotIn("--exit-node", u)

    def test_bridge_unit_public_bind(self):
        u = self.of._render_bridge_unit("0.0.0.0", 9050, "vyandex")
        self.assertIn("--socks5 0.0.0.0:9050", u)

    def test_bridge_unit_oneme_tail(self):
        u = self.of._render_bridge_unit("127.0.0.1", 1080, "oneme")
        self.assertIn("--maxToken ${OPENFLUX_MAX_TOKEN}", u)

    def test_bridge_mihomo_fragment(self):
        f = self.of._render_bridge_mihomo_fragment(9050)
        self.assertIn('- name: "🛟 OpenFlux (bridge)"', f)
        self.assertIn("type: socks5", f)
        self.assertIn("port: 9050", f)
        self.assertIn("udp: false", f)
        self.assertNotIn("sk=", f)

    def test_ask_bind_port_cli_validation(self):
        self.assertEqual(self.of._ask_bridge_bind("0.0.0.0"), "0.0.0.0")
        self.assertEqual(self.of._ask_bridge_bind("127.0.0.1"), "127.0.0.1")
        self.assertIsNone(self.of._ask_bridge_bind("8.8.8.8"))
        self.assertEqual(self.of._ask_bridge_port(9050), 9050)
        self.assertIsNone(self.of._ask_bridge_port(70000))
        self.assertIsNone(self.of._ask_bridge_port(0))

    def test_is_loopback_bind(self):
        self.assertTrue(self.of._is_loopback_bind("127.0.0.1"))
        self.assertTrue(self.of._is_loopback_bind("::1"))
        self.assertFalse(self.of._is_loopback_bind("0.0.0.0"))
        self.assertFalse(self.of._is_loopback_bind(""))


class _PortRegistryPatched(OpenfluxTestCase):
    """База: патает функции port_registry (openflux импортирует их
    лениво внутри функций — патчим атрибуты модуля)."""

    def setUp(self):
        super().setUp()
        import chimera.modules.port_registry as pr
        self.pr = pr
        self._patches = [
            patch.object(pr, "port_is_free",
                         return_value=(True, [])),
            patch.object(pr, "port_register",
                         return_value=(True, "Порт 1080/tcp зарегистрирован")),
            patch.object(pr, "port_unregister", return_value=True),
            patch.object(pr, "ufw_open_port",
                         return_value=(True, "Порт 1080/tcp открыт в UFW")),
            patch.object(pr, "ufw_close_port",
                         return_value=(True, "удалено")),
        ]
        for p in self._patches:
            p.start()
            setattr(self, p.attribute, p.target)  # noqa: удобство
        self.addCleanup(lambda: [p.stop() for p in self._patches])


class TestBridgePortLifecycle(_PortRegistryPatched):
    """12. Требование проверка → регистрация → открытие /
    закрытие → разрегистрация."""

    def test_open_free_loopback_registers_without_ufw(self):
        ok, msg = self.of._bridge_port_open("127.0.0.1", 1080)
        self.assertTrue(ok, msg)
        self.pr.port_register.assert_called_once_with(
            self.pr.SERVICE_OPENFLUX_BRIDGE, 1080, "tcp",
            comment="OpenFlux bridge SOCKS5")
        self.pr.ufw_open_port.assert_not_called()   # loopback — UFW не нужен

    def test_open_public_bind_opens_ufw(self):
        ok, _ = self.of._bridge_port_open("0.0.0.0", 1080)
        self.assertTrue(ok)
        self.pr.port_register.assert_called_once()
        self.pr.ufw_open_port.assert_called_once_with(
            1080, "tcp", self.pr.SERVICE_OPENFLUX_BRIDGE,
            comment="OpenFlux bridge SOCKS5")

    def test_open_busy_port_fails_with_conflicts(self):
        self.pr.port_is_free.return_value = (
            False, ["Зарегистрирован за сервисом 'web_panel'",
                    "Порт уже слушается процессом: nginx (pid=123)"])
        ok, msg = self.of._bridge_port_open("127.0.0.1", 1080)
        self.assertFalse(ok)
        self.assertIn("web_panel", msg)
        self.assertIn("nginx", msg)
        self.pr.port_register.assert_not_called()
        self.pr.ufw_open_port.assert_not_called()

    def test_open_register_failure_propagates(self):
        self.pr.port_register.return_value = (False, "Порт занят: конфликт")
        ok, msg = self.of._bridge_port_open("127.0.0.1", 1080)
        self.assertFalse(ok)
        self.assertIn("конфликт", msg)

    def test_close_unregisters_and_closes_ufw(self):
        self.of._bridge_port_close(1080)
        self.pr.ufw_close_port.assert_called_once_with(
            1080, "tcp", self.pr.SERVICE_OPENFLUX_BRIDGE)
        self.pr.port_unregister.assert_called_once_with(
            self.pr.SERVICE_OPENFLUX_BRIDGE, 1080, "tcp")

    def test_port_registry_service_tags_exist(self):
        self.assertEqual(self.pr.SERVICE_OPENFLUX, "openflux")
        self.assertEqual(self.pr.SERVICE_OPENFLUX_BRIDGE, "openflux_bridge")


class TestBridgeFlows(_PortRegistryPatched):
    """12. Деактивация/удаление ЗАКРЫВАЮТ порты; CLI-конфликт — отказ."""

    _STATE = {
        "transport": "yandex", "doc_url": _EDIT_URL,
        "transport_key": "K" * 44, "commit": "a" * 40,
        "pinned": True, "raw_mode": False, "local_ip": "",
        "bridge_active": True, "bridge_bind": "127.0.0.1",
        "bridge_port": 1080,
    }

    def test_deactivate_closes_port(self):
        saved = {}
        with patch.object(self.of, "_is_installed", return_value=True), \
                patch.object(self.of, "proto_load_state",
                             return_value=dict(self._STATE)), \
                patch.object(self.of, "proto_save_state",
                             side_effect=lambda p, d, **kw: saved.update(d)), \
                patch.object(self.of, "_run", return_value=None), \
                patch.object(self.of, "_pause"), \
                patch.object(self.of, "_bridge_port_close") as closer:
            self.of._deactivate_services()
        closer.assert_called_once_with(1080)
        self.assertFalse(saved.get("bridge_active"))

    def test_uninstall_closes_bridge_port(self):
        with patch.object(self.of, "proto_ask", return_value="YES"), \
                patch.object(self.of, "proto_load_state",
                             return_value=dict(self._STATE)), \
                patch.object(self.of, "_run", return_value=None), \
                patch.object(self.of, "_bridge_port_close") as closer, \
                patch.object(self.of, "_MODULE_STATE"), \
                patch.object(self.of, "_BRIDGE_SERVICE_FILE"), \
                patch.object(self.of, "_BRIDGE_ENV_FILE"), \
                patch.object(self.of, "_SERVICE_FILE"), \
                patch("shutil.rmtree"), \
                patch.object(self.of, "_ENV_DIR"):
            self.of._uninstall()
        closer.assert_called_once_with(1080)

    def test_bridge_setup_cli_conflict_aborts_cleanly(self):
        self.pr.port_is_free.return_value = (
            False, ["Зарегистрирован за сервисом 'b4_web'"])
        saved = {}
        with patch.object(self.of, "proto_load_state",
                           return_value=dict(self._STATE)), \
                patch.object(self.of, "_BIN", Path("/bin/ls")), \
                patch.object(self.of, "proto_save_state",
                             side_effect=lambda p, d, **kw: saved.update(d)), \
                patch.object(self.of, "_pause"), \
                patch.object(self.of, "_ensure_openflux_user"), \
                patch.object(self.of, "_run", return_value=None):
            self.of._bridge_setup(cli_bind="127.0.0.1", cli_port=1080)
        self.assertEqual(saved, {})   # state не тронут — чистый отказ
        self.pr.port_register.assert_not_called()


class TestCorePortExtractor(OpenfluxTestCase):
    """12. _extract_openflux_ports в _core (PROTOCOL_PORT_REGISTRY)."""

    def _extract(self):
        import importlib
        core = importlib.import_module("chimera._core")
        return core._extract_openflux_ports

    def test_no_bridge_no_ports(self):
        f = self._extract()
        self.assertEqual(f({"transport": "yandex"}), [])
        self.assertEqual(f({"bridge_active": False,
                            "bridge_port": 1080}), [])
        self.assertEqual(f("не словарь"), [])

    def test_active_bridge_returns_port(self):
        f = self._extract()
        self.assertEqual(
            f({"bridge_active": True, "bridge_port": 1080}), [1080])

    def test_bad_port_ignored(self):
        f = self._extract()
        self.assertEqual(
            f({"bridge_active": True, "bridge_port": 70000}), [])
        self.assertEqual(
            f({"bridge_active": True, "bridge_port": "1080"}), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
