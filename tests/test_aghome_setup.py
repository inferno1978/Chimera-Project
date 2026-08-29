#!/usr/bin/env python3
"""
tests/test_aghome_setup.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для AdGuard Home стека Chimera:
  1. aghome_mirrors  — построение URL зеркал
  2. aghome_packages — PackageSpec инварианты
  3. yaml_replace_sections — хирургическая замена top-level секций YAML
  4. _yaml_has_users       — детекция завершённого мастера
  5. build_*_section       — сборка канонических секций (dns/tls/filters)
  6. migrate_dnscrypt_off_53 — снятие :53 у dnscrypt
  7. resolv_conf_fix AGH-aware — diagnose/фикс при живом AGH
  8. aghome_dns_ready / is_aghome_active — хелперы состояния
  9. wizard-доступ: UFW «для всех» + URL из адреса сервера (v44 — без туннелей)
  10. DNS-ALIVE гарантия: probe dig/getent + лестница восстановления (v44)
  11. HEADLESS-мастер: POST /control/install/configure на loopback (v44)
  12. uninstall: DNS проверяется фактическим запросом после удаления (v44)
  13. v47 anti-duplicate-keys: дубли top-level ключей YAML = crash-loop AGH
      (инцидент vds13195: «whitelist_filters already defined», рестарт-каунтер 390+)
      + _wait_service: флапающий crash-loop не считается успехом
"""
from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Фейковый chimera._core (паттерн test_dnscrypt_setup)."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core


# ─────────────────────────────────────────────────────────────────────────────
#  aghome_mirrors
# ─────────────────────────────────────────────────────────────────────────────
class TestAghomeMirrors(unittest.TestCase):
    def test_mirrors_contain_github_and_adtidy(self):
        from chimera.modules.aghome_mirrors import get_aghome_mirrors
        urls = get_aghome_mirrors("v0.107.62", "amd64")
        self.assertTrue(any(u ==
            "https://github.com/AdguardTeam/AdGuardHome/releases/download/"
            "v0.107.62/AdGuardHome_linux_amd64.tar.gz" for u in urls))
        self.assertTrue(any(u ==
            "https://static.adtidy.org/adguardhome/release/"
            "AdGuardHome_linux_amd64.tar.gz" for u in urls))
        self.assertTrue(any("releases/latest/download/AdGuardHome_linux_amd64.tar.gz"
                            in u for u in urls))
        # GitHub-прокси между прямым GitHub и adtidy.org
        i_gh = next(i for i, u in enumerate(urls) if u.startswith("https://github.com/"))
        i_adtidy = next(i for i, u in enumerate(urls) if "adtidy.org" in u)
        self.assertGreater(i_adtidy, i_gh)

    def test_mirrors_arch_substituted(self):
        from chimera.modules.aghome_mirrors import get_aghome_mirrors
        urls = get_aghome_mirrors("v0.107.62", "arm64")
        self.assertTrue(all("linux_arm64" in u for u in urls if "AdGuardHome_linux" in u))

    def test_mirrors_empty_tag(self):
        from chimera.modules.aghome_mirrors import get_aghome_mirrors
        self.assertEqual(get_aghome_mirrors("", "amd64"), [])

    def test_fallback_tag_format(self):
        from chimera.modules.aghome_mirrors import AGHOME_FALLBACK_TAG
        self.assertTrue(AGHOME_FALLBACK_TAG.startswith("v"))


# ─────────────────────────────────────────────────────────────────────────────
#  aghome_packages
# ─────────────────────────────────────────────────────────────────────────────
class TestAghomePackages(unittest.TestCase):
    def test_spec_fields(self):
        from chimera.modules.aghome_packages import AGHOME_SPEC
        self.assertEqual(AGHOME_SPEC.name, "AdGuardHome")
        self.assertEqual(AGHOME_SPEC.install_dests, [Path("/usr/local/bin")])
        self.assertEqual(AGHOME_SPEC.manual_incoming_dir, Path("/root"))
        self.assertGreaterEqual(AGHOME_SPEC.min_size, 2_000_000)
        # инвариант PackageSpec: manual_dir != install_dests
        self.assertNotIn(AGHOME_SPEC.manual_incoming_dir, AGHOME_SPEC.install_dests)

    def test_filename_builder(self):
        from chimera.modules.aghome_packages import AGHOME_SPEC
        self.assertEqual(
            AGHOME_SPEC.filename_builder(tag="v0.107.62", arch="amd64"),
            "AdGuardHome_linux_amd64.tar.gz")

    def test_post_install_extracts_binary(self):
        """post_install: реальный tar.gz → извлечение бинарника."""
        import subprocess as _sp
        import shutil
        from chimera.modules.aghome_packages import _post_install_aghome
        tmp = Path(tempfile.mkdtemp())
        try:
            # Собираем структуру AdGuardHome/AdGuardHome и пакуем в tar.gz
            src_dir = tmp / "src" / "AdGuardHome"
            src_dir.mkdir(parents=True)
            fake_bin = src_dir / "AdGuardHome"
            fake_bin.write_text("#!/bin/sh\n")
            fake_tar = tmp / "AdGuardHome_linux_amd64.tar.gz"
            r = _sp.run(["tar", "-czf", str(fake_tar), "-C", str(tmp / "src"),
                         "AdGuardHome"], capture_output=True)
            self.assertEqual(r.returncode, 0)

            dest_dir = tmp / "dest"
            ok = _post_install_aghome(fake_tar, [dest_dir])
            self.assertTrue(ok)
            installed = dest_dir / "AdGuardHome"
            self.assertTrue(installed.exists())
            self.assertGreater(installed.stat().st_size, 0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
#  yaml_replace_sections
# ─────────────────────────────────────────────────────────────────────────────
class TestYamlReplaceSections(unittest.TestCase):
    def setUp(self):
        from chimera.modules import aghome_setup
        self.mod = aghome_setup

    def test_replaces_existing_section(self):
        text = "users:\n  - name: admin\ndns:\n  port: 53\n  ratelimit: 0\n"
        out = self.mod.yaml_replace_sections(
            text, {"dns": "dns:\n  port: 5353\n  ratelimit: 20\n"})
        self.assertIn("port: 5353", out)
        self.assertIn("ratelimit: 20", out)
        self.assertNotIn("ratelimit: 0", out)
        # users не тронуты
        self.assertIn("- name: admin", out)

    def test_appends_missing_section(self):
        text = "users:\n  - name: admin\n"
        out = self.mod.yaml_replace_sections(
            text, {"statistics": "statistics:\n  enabled: true\n"})
        self.assertIn("statistics:", out)
        self.assertIn("enabled: true", out)
        self.assertIn("- name: admin", out)

    def test_deletes_section_with_none(self):
        text = "users:\n  - name: admin\ndhcp:\n  enabled: true\n"
        out = self.mod.yaml_replace_sections(text, {"dhcp": None})
        self.assertNotIn("dhcp:", out)
        self.assertNotIn("enabled: true", out)

    def test_preserves_users_and_scalars(self):
        text = (
            "http:\n  address: 0.0.0.0:3000\n"
            "users:\n"
            "  - name: admin\n    password: $2a$10$hash\n"
            "schema_version: 29\n"
            "theme: auto\n"
            "dns:\n  port: 53\n"
        )
        out = self.mod.yaml_replace_sections(
            text,
            {"dns": "dns:\n  port: 53\n  ratelimit: 20\n"},
            scalars={"language": "ru"},
        )
        self.assertIn("password: $2a$10$hash", out)
        self.assertIn("schema_version: 29", out)
        self.assertIn("theme: auto", out)
        self.assertIn("language: ru", out)
        self.assertIn("ratelimit: 20", out)

    def test_scalar_replaced_not_duplicated(self):
        text = "language: en\ndns:\n  port: 53\n"
        out = self.mod.yaml_replace_sections(
            text, {}, scalars={"language": "ru"})
        self.assertEqual(out.count("language:"), 1)
        self.assertIn("language: ru", out)

    def test_multiple_sections_at_once(self):
        text = ("http:\n  address: 0.0.0.0:3000\n"
                "users:\n  - name: admin\n"
                "dns:\n  port: 53\n"
                "tls:\n  enabled: false\n"
                "querylog:\n  enabled: false\n")
        out = self.mod.yaml_replace_sections(text, {
            "http": "http:\n  address: 127.0.0.1:3000\n",
            "dns": "dns:\n  port: 53\n  ratelimit: 20\n",
            "tls": "tls:\n  enabled: true\n",
            "querylog": "querylog:\n  enabled: true\n",
        })
        self.assertIn("address: 127.0.0.1:3000", out)
        self.assertIn("ratelimit: 20", out)
        self.assertIn("tls:\n  enabled: true", out)
        self.assertIn("querylog:\n  enabled: true", out)
        self.assertIn("- name: admin", out)


# ─────────────────────────────────────────────────────────────────────────────
#  v47: ANTI-DUPLICATE-KEYS (инцидент vds13195 — crash-loop AGH)
# ─────────────────────────────────────────────────────────────────────────────
class TestYamlNoDuplicateTopKeys(unittest.TestCase):
    """Regression v47: финализация писала в AdGuardHome.yaml дубли
    whitelist_filters/user_rules (секция filters тащила их внутри себя,
    а мастерские копии оставались) — строгий YAML-парсер AGH падал:
    «mapping key whitelist_filters already defined at line 108».
    """

    WIZARD_CONFIG = (
        "http:\n  address: 0.0.0.0:3000\n"
        "users:\n  - name: admin\n    password: $2a$10$bcrypt\n"
        "schema_version: 29\n"
        "dns:\n  port: 53\n"
        "tls:\n  enabled: false\n"
        "filters:\n  - enabled: true\n    url: https://x/f.txt\n    name: f\n    id: 1\n"
        "whitelist_filters: []\n"
        "user_rules: []\n"
        "querylog:\n  enabled: true\n"
        "statistics:\n  enabled: true\n"
    )

    def setUp(self):
        from chimera.modules import aghome_setup
        self.mod = aghome_setup

    def _finalize_sections(self):
        return {
            "http": self.mod.build_http_section(self.mod.AGH_WEB_LOOPBACK),
            "filters": self.mod.build_filters_section(),
            "whitelist_filters": self.mod.build_whitelist_filters_section(),
            "user_rules": self.mod.build_user_rules_section(),
            "querylog": self.mod.build_querylog_section(),
            "statistics": self.mod.build_statistics_section(),
            "dhcp": "dhcp:\n  enabled: false\n",
        }

    def test_finalize_on_wizard_config_no_dups(self):
        out = self.mod.yaml_replace_sections(
            self.WIZARD_CONFIG, self._finalize_sections(),
            scalars={"language": "ru"})
        self.assertEqual(self.mod._duplicate_top_keys(out), [])
        for key in ("filters", "whitelist_filters", "user_rules",
                    "querylog", "statistics", "dhcp"):
            self.assertEqual(
                sum(1 for ln in out.splitlines() if ln.startswith(key + ":")),
                1, f"top-level key {key!r} must appear exactly once")
        # users/master-данные не тронуты, скаляр применён
        self.assertIn("- name: admin", out)
        self.assertIn("$2a$10$bcrypt", out)
        self.assertIn("language: ru", out)

    def test_filters_section_no_embedded_keys(self):
        top = [ln for ln in self.mod.build_filters_section().splitlines()
               if not ln.startswith((" ", "-"))]
        self.assertEqual(top, ["filters:"],
                         "build_filters_section не должен тащить чужие top-level ключи")

    def test_safety_net_collapses_preexisting_dups(self):
        # даже если дубли УЖЕ в конфиге — заменять можно безопасно
        text = ("filters:\n  - id: 1\n"
                "whitelist_filters: []\nuser_rules: []\n"
                "whitelist_filters: []\nuser_rules: []\n"
                "querylog:\n  enabled: true\n")
        out = self.mod.yaml_replace_sections(
            text, {"querylog": "querylog:\n  enabled: true\n"})
        self.assertEqual(self.mod._duplicate_top_keys(out), [])
        self.assertEqual(out.count("whitelist_filters:"), 1)
        self.assertEqual(out.count("user_rules:"), 1)

    def test_duplicate_top_keys_detects(self):
        self.assertEqual(self.mod._duplicate_top_keys("a: 1\nb: 2\na: 3\n"), ["a"])
        self.assertEqual(self.mod._duplicate_top_keys("a: 1\nb: 2\n"), [])

    def test_dedup_keeps_first_occurrence(self):
        text = ("user_rules:\n  - '@@||ok^'\n"
                "user_rules: []\nquerylog:\n  enabled: true\n")
        out = self.mod._dedup_top_level_sections(text)
        self.assertEqual(self.mod._duplicate_top_keys(out), [])
        self.assertIn("- '@@||ok^'", out)
        self.assertNotIn("user_rules: []", out)
        self.assertIn("querylog:", out)


class TestWaitServiceStable(unittest.TestCase):
    """v47: crash-loop флап (systemd active на ~0.5с каждые 5с) не должен
    считаться успехом — иначе self-heal откат конфига не срабатывал и
    AGH оставался в crash-loop (рестарт-каунтер 390+ на vds13195).
    """

    def setUp(self):
        from chimera.modules import aghome_setup
        self.mod = aghome_setup

    def test_stable_active_passes(self):
        with patch.object(self.mod, "_svc_is_active",
                          side_effect=[True] * 10), \
             patch.object(self.mod.time, "sleep", lambda s: None):
            self.assertTrue(self.mod._wait_service("svc", 10))

    def test_flapping_active_rejected(self):
        # миг «active» при старте → процесс умирает → failed до рестарта
        flap = [True, False, False, False, False, True, False]
        failed = MagicMock()
        failed.stdout = "failed\n"
        with patch.object(self.mod, "_svc_is_active", side_effect=flap), \
             patch.object(self.mod, "subprocess") as sp, \
             patch.object(self.mod.time, "sleep", lambda s: None):
            sp.run.return_value = failed
            self.assertFalse(self.mod._wait_service("svc", 12))

    def test_slow_start_then_stable_passes(self):
        seq = [False] * 5 + [True] * 10
        activating = MagicMock()
        activating.stdout = "active\n"
        with patch.object(self.mod, "_svc_is_active", side_effect=seq), \
             patch.object(self.mod, "subprocess") as sp, \
             patch.object(self.mod.time, "sleep", lambda s: None):
            sp.run.return_value = activating
            self.assertTrue(self.mod._wait_service("svc", 12))


class TestYamlHasUsers(unittest.TestCase):
    def setUp(self):
        from chimera.modules import aghome_setup
        self.mod = aghome_setup

    def test_users_present(self):
        text = ("http:\n  address: 0.0.0.0:3000\n"
                "users:\n"
                "  - name: admin\n"
                "    password: $2a$10$hash\n"
                "dns:\n  port: 53\n")
        self.assertTrue(self.mod._yaml_has_users(text))

    def test_users_empty_list(self):
        text = "users: []\ndns:\n  port: 53\n"
        self.assertFalse(self.mod._yaml_has_users(text))

    def test_users_missing(self):
        text = "http:\n  address: 0.0.0.0:3000\ndns:\n  port: 53\n"
        self.assertFalse(self.mod._yaml_has_users(text))

    def test_users_empty_section(self):
        text = "users:\ndns:\n  port: 53\n"
        self.assertFalse(self.mod._yaml_has_users(text))


# ─────────────────────────────────────────────────────────────────────────────
#  build_*_section
# ─────────────────────────────────────────────────────────────────────────────
class TestBuildSections(unittest.TestCase):
    def setUp(self):
        from chimera.modules import aghome_setup
        self.mod = aghome_setup

    def test_dns_section_upstream_dnscrypt(self):
        s = self.mod.build_dns_section(dc_port=5300, public_ip="1.2.3.4",
                                       tls_enabled=True)
        self.assertIn("- 127.0.0.1:5300", s)
        # upstream + bootstrap содержат порт dnscrypt
        self.assertGreaterEqual(s.count("127.0.0.1:5300"), 2)
        # fallback: Quad9 x2 (v67 — 1.1.1.1 душится из РФ, заменён на
        # второй anycast Quad9 149.112.112.112)
        self.assertIn("- 9.9.9.9:53", s)
        self.assertIn("- 149.112.112.112:53", s)
        self.assertNotIn("- 1.1.1.1:53", s)
        # bind_hosts: loopback + public
        self.assertIn("- \"127.0.0.1\"", s)
        self.assertIn("- \"1.2.3.4\"", s)
        # кеш 4MB optimistic + dnssec
        self.assertIn("cache_size: 4194304", s)
        self.assertIn("cache_optimistic: true", s)
        self.assertIn("enable_dnssec: true", s)
        # v65: ratelimit 0 (тихие дропы лимита убивали DNS Xray — EOF-шторм)
        self.assertIn("ratelimit: 0", s)
        self.assertNotIn("ratelimit: 20", s)
        self.assertIn("upstream_timeout: 3s", s)
        self.assertIn("serve_plain_dns: true", s)

    def test_dns_section_no_public_ip(self):
        s = self.mod.build_dns_section(dc_port=5300, public_ip="",
                                       tls_enabled=False)
        self.assertIn("- \"127.0.0.1\"", s)
        self.assertNotIn("- \"1.2.3.4\"", s)

    def test_tls_section_enabled(self):
        s = self.mod.build_tls_section(
            True, "dns.example.com",
            Path("/opt/AdGuardHome/certs/agh-tls.crt"),
            Path("/opt/AdGuardHome/certs/agh-tls.key"))
        self.assertIn("enabled: true", s)
        self.assertIn('server_name: "dns.example.com"', s)
        self.assertIn("port_https: 30443", s)
        self.assertIn("port_dns_over_tls: 853", s)
        self.assertIn("port_dns_over_quic: 853", s)
        self.assertIn('certificate_path: "/opt/AdGuardHome/certs/agh-tls.crt"', s)

    def test_tls_section_disabled(self):
        s = self.mod.build_tls_section(False, "", None, None)
        self.assertIn("enabled: false", s)
        self.assertIn("port_https: 0", s)

    def test_http_section_modes(self):
        self.assertIn("address: 0.0.0.0:3000",
                      self.mod.build_http_section(self.mod.AGH_WEB_HTTP_PUB))
        self.assertIn("address: 127.0.0.1:3000",
                      self.mod.build_http_section(self.mod.AGH_WEB_LOOPBACK))
        # v48: TLS-режимы биндят 0.0.0.0 — HTTPS :30443 следует хосту
        # http.address, иначе Web UI снаружи требует SSH-туннель
        self.assertIn("address: 0.0.0.0:3000",
                      self.mod.build_http_section(self.mod.AGH_WEB_HTTPS_LE))
        self.assertIn("address: 0.0.0.0:3000",
                      self.mod.build_http_section(self.mod.AGH_WEB_HTTPS_SELF))

    def test_http_section_tls_bind_follows_v48(self):
        """Regression v48: https-режимы НЕ должны уходить в loopback —
        AGH биндит port_https на хост http.address (web.go:
        netip.AddrPortFrom(BindAddr, portHTTPS)), loopback-бинд оставлял
        :30443 недоступным снаружи при открытом UFW.
        """
        for mode in (self.mod.AGH_WEB_HTTPS_LE, self.mod.AGH_WEB_HTTPS_SELF,
                     self.mod.AGH_WEB_HTTP_PUB):
            s = self.mod.build_http_section(mode)
            self.assertIn("address: 0.0.0.0:3000", s,
                          f"{mode}: HTTPS-порт останется loopback-only")
        # loopback — единственный полностью локальный режим
        self.assertIn("address: 127.0.0.1:3000",
                      self.mod.build_http_section(self.mod.AGH_WEB_LOOPBACK))

    def test_http_section_custom_port_v49(self):
        """v49: кастомный порт Web UI применяется во всех режимах."""
        self.assertIn("address: 0.0.0.0:8081",
                      self.mod.build_http_section(self.mod.AGH_WEB_HTTP_PUB, 8081))
        self.assertIn("address: 0.0.0.0:8081",
                      self.mod.build_http_section(self.mod.AGH_WEB_HTTPS_LE, 8081))
        self.assertIn("address: 127.0.0.1:8081",
                      self.mod.build_http_section(self.mod.AGH_WEB_LOOPBACK, 8081))
        # дефолт не сломан
        self.assertIn("address: 0.0.0.0:3000",
                      self.mod.build_http_section(self.mod.AGH_WEB_HTTP_PUB))

    def test_validate_web_port_v49(self):
        """v49: валидация кастомного порта — диапазон/служебные/занятость."""
        # привилегированные (<1024) отклоняются диапазоном —
        # это покрывает и системные 22/53/80/443
        for bad in (22, 53, 80, 443, 853):   # 853 тоже < 1024
            ok, why = self.mod._validate_web_port(bad)
            self.assertFalse(ok, f"{bad} должен быть запрещён")
            self.assertIn("диапазон", why)
        # служебные порты DNS-стека (>=1024) — отдельная блокировка
        for bad in (5300, 30443):
            ok, why = self.mod._validate_web_port(bad)
            self.assertFalse(ok, f"{bad} должен быть запрещён")
            self.assertIn("служебный", why)
        # вне диапазона
        ok, _ = self.mod._validate_web_port(70000)
        self.assertFalse(ok)
        # занят по реестру (port_is_free → конфликты)
        import chimera.modules.port_registry as pr
        with patch.object(pr, "port_is_free",
                          return_value=(False, ["vless слушает :8081"])):
            ok, why = self.mod._validate_web_port(8081)
            self.assertFalse(ok)
            self.assertIn("занят", why)
            self.assertIn("8081", why)
        # свободен
        with patch.object(pr, "port_is_free", return_value=(True, [])):
            ok, _ = self.mod._validate_web_port(8081)
            self.assertTrue(ok)

    def test_filters_section_three_filters(self):
        s = self.mod.build_filters_section()
        self.assertIn("adguardteam.github.io/AdGuardSDNSFilter", s)
        self.assertIn("adaway.org/hosts.txt", s)
        # OISD: корневой URL (роутерный /basic отдаёт 404)
        self.assertIn("https://big.oisd.nl/", s)
        self.assertNotIn("oisd.nl/basic", s)
        self.assertEqual(s.count("- enabled: true"), 3)

    def test_querylog_statistics_enabled(self):
        self.assertIn("enabled: true", self.mod.build_querylog_section())
        self.assertIn("file_enabled: true", self.mod.build_querylog_section())
        self.assertIn("interval: 2160h", self.mod.build_querylog_section())
        self.assertIn("enabled: true", self.mod.build_statistics_section())


# ─────────────────────────────────────────────────────────────────────────────
#  migrate_dnscrypt_off_53
# ─────────────────────────────────────────────────────────────────────────────
class TestMigrateDnscryptOff53(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        import importlib
        import chimera.modules.aghome_setup as ags
        importlib.reload(ags)
        self.mod = ags
        self.toml = self._tmpdir / "dnscrypt-proxy.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _core_mock(self, ipv6=False):
        core = MagicMock()
        core.info = lambda *a, **k: None
        core.warn = lambda *a, **k: None
        core.success = lambda *a, **k: None
        # v72: явное значение — иначе MagicMock-атрибут truthy и миграция
        # считает IPv6 доступным (добавляет '[::1]')
        core.IS_IPV6_AVAILABLE = ipv6
        return core

    def test_strips_53_from_listen_addresses(self):
        self.toml.write_text(
            "listen_addresses = ['127.0.0.1:53', '127.0.0.1:5300']\n"
            "server_names = ['cloudflare']\n")
        # ss: dnscrypt держит :53
        ss_53 = ("udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* "
                 "users:((\"dnscrypt-proxy\"))\n")
        # после рестарта — только 5300
        ss_5300 = ("udp UNCONN 0 0 127.0.0.1:5300 0.0.0.0:* "
                   "users:((\"dnscrypt-proxy\"))\n")
        safety_calls = []
        with patch.object(self.mod, "_core_module",
                          return_value=self._core_mock()), \
             patch.object(self.mod, "AGH_DNSCRYPT_TOML", self.toml), \
             patch.object(self.mod, "_ensure_dns_redirect_safety",
                          side_effect=lambda port, remove=False:
                              safety_calls.append((port, remove)) or True), \
             patch.object(self.mod, "subprocess") as sub:
            state = {"migrated": False, "restarted": False}
            def run_side_effect(cmd, **kw):
                cmd_s = " ".join(cmd)
                out = ""
                if "is-active" in cmd_s:
                    out = "active"
                elif "is-failed" in cmd_s:
                    out = "inactive"
                elif "restart" in cmd_s:
                    state["restarted"] = True
                    safety_calls.append(("restart", None))
                elif "-ulnp" in cmd_s or "-tulnp" in cmd_s:
                    # до рестарта dnscrypt держит :53, после — только 5300
                    out = ss_5300 if state["restarted"] else ss_53
                return MagicMock(returncode=0, stdout=out, stderr="")
            sub.run.side_effect = run_side_effect

            ok = self.mod.migrate_dnscrypt_off_53()
        self.assertTrue(ok)
        content = self.toml.read_text()
        self.assertIn("listen_addresses = ['127.0.0.1:5300']", content)
        self.assertNotIn(":53'", content)
        # v72: без IPv6 — только v4-loopback
        self.assertNotIn("[::1]", content)
        # бэкап создан
        baks = list(self.toml.parent.glob("dnscrypt-proxy.toml.*.preAGH.bak"))
        self.assertEqual(len(baks), 1)
        # бэкап содержит оригинальный (двухадресный) конфиг
        self.assertIn("127.0.0.1:53", baks[0].read_text())
        # v41: страховка 53→5300 поставлена ДО рестарта dnscrypt
        self.assertEqual(safety_calls[0], (5300, False))
        restarts = [i for i, c in enumerate(safety_calls) if c[0] == "restart"]
        self.assertTrue(restarts, "restart dnscrypt должен быть вызван")
        self.assertLess(safety_calls.index((5300, False)), restarts[0])

    def test_strips_53_adds_ipv6_listen_v72(self):
        """v72: при живом IPv6 миграция добавляет '[::1]:5300' вторым
        слушателем (127.0.0.1 всегда первый)."""
        self.toml.write_text(
            "listen_addresses = ['127.0.0.1:53', '127.0.0.1:5300']\n"
            "server_names = ['cloudflare']\n")
        ss_53 = ("udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* "
                 "users:((\"dnscrypt-proxy\"))\n")
        ss_both = ("udp UNCONN 0 0 127.0.0.1:5300 0.0.0.0:* "
                   "users:((\"dnscrypt-proxy\"))\n"
                   "udp UNCONN 0 0 [::1]:5300 [::]:* "
                   "users:((\"dnscrypt-proxy\"))\n")
        with patch.object(self.mod, "_core_module",
                          return_value=self._core_mock(ipv6=True)), \
             patch.object(self.mod, "AGH_DNSCRYPT_TOML", self.toml), \
             patch.object(self.mod, "_ensure_dns_redirect_safety",
                          return_value=True), \
             patch.object(self.mod, "subprocess") as sub:
            state = {"restarted": False}
            def run_side_effect(cmd, **kw):
                cmd_s = " ".join(cmd)
                out = ""
                if "is-active" in cmd_s:
                    out = "active"
                elif "is-failed" in cmd_s:
                    out = "inactive"
                elif "restart" in cmd_s:
                    state["restarted"] = True
                elif "-ulnp" in cmd_s or "-tulnp" in cmd_s:
                    out = ss_both if state["restarted"] else ss_53
                return MagicMock(returncode=0, stdout=out, stderr="")
            sub.run.side_effect = run_side_effect
            ok = self.mod.migrate_dnscrypt_off_53()
        self.assertTrue(ok)
        content = self.toml.read_text()
        self.assertIn(
            "listen_addresses = ['127.0.0.1:5300', '[::1]:5300']", content)
        self.assertNotIn(":53'", content)
        self.assertIn("server_names = ['cloudflare']", content)

    def test_no_migration_when_53_free(self):
        self.toml.write_text("listen_addresses = ['127.0.0.1:5300']\n")
        with patch.object(self.mod, "_core_module",
                          return_value=self._core_mock()), \
             patch.object(self.mod, "AGH_DNSCRYPT_TOML", self.toml), \
             patch.object(self.mod, "_ensure_dns_redirect_safety",
                          return_value=True) as safety, \
             patch.object(self.mod, "subprocess") as sub:
            sub.run.return_value = MagicMock(
                returncode=0,
                stdout="udp UNCONN 0 0 127.0.0.1:5300 0.0.0.0:*\n")
            ok = self.mod.migrate_dnscrypt_off_53()
        self.assertTrue(ok)
        # TOML не менялся, бэкапов нет
        self.assertEqual(
            self.toml.read_text(), "listen_addresses = ['127.0.0.1:5300']\n")
        self.assertEqual(list(self.toml.parent.glob("*.bak")), [])
        # v41: даже без миграции — страховка wizard-фазы (self-healing
        # серверов, где прошлая миграция сняла :53 без redirect)
        safety.assert_called_once_with(5300)

    def test_aborts_before_toml_when_no_redirect_safety(self):
        """v41: без redirect-страховки TOML НЕ трогаем (DNS не сломаем).

        Регресс живого сервера: миграция снимала :53, redirect никто не
        ставил (v33-серверы жили без redirect — dnscrypt был на :53) →
        после снятия :53 DNS black-hole («Could not resolve host»).
        """
        original = ("listen_addresses = ['127.0.0.1:53', '127.0.0.1:5300']\n")
        self.toml.write_text(original)
        ss_53 = ("udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* "
                 "users:((\"dnscrypt-proxy\"))\n")
        with patch.object(self.mod, "_core_module",
                          return_value=self._core_mock()), \
             patch.object(self.mod, "AGH_DNSCRYPT_TOML", self.toml), \
             patch.object(self.mod, "_ensure_dns_redirect_safety",
                          return_value=False), \
             patch.object(self.mod, "subprocess") as sub:
            restarted = []
            def run_side_effect(cmd, **kw):
                cmd_s = " ".join(cmd)
                out = ""
                if "is-active" in cmd_s:
                    out = "active"
                elif "restart" in cmd_s:
                    restarted.append(cmd_s)
                elif "-ulnp" in cmd_s or "-tulnp" in cmd_s:
                    out = ss_53
                return MagicMock(returncode=0, stdout=out, stderr="")
            sub.run.side_effect = run_side_effect
            ok = self.mod.migrate_dnscrypt_off_53()
        self.assertFalse(ok)
        # TOML не тронут, бэкапов нет, dnscrypt не рестартился
        self.assertEqual(self.toml.read_text(), original)
        self.assertEqual(list(self.toml.parent.glob("*.bak")), [])
        self.assertEqual(restarted, [])

    def test_rollback_removes_redirect_safety(self):
        """v41: провал рестарта dnscrypt — откат TOML + снятие страховки."""
        self.toml.write_text(
            "listen_addresses = ['127.0.0.1:53', '127.0.0.1:5300']\n")
        ss_53 = ("udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* "
                 "users:((\"dnscrypt-proxy\"))\n")
        safety_calls = []
        with patch.object(self.mod, "_core_module",
                          return_value=self._core_mock()), \
             patch.object(self.mod, "AGH_DNSCRYPT_TOML", self.toml), \
             patch.object(self.mod, "_ensure_dns_redirect_safety",
                          side_effect=lambda port, remove=False:
                              safety_calls.append((port, remove)) or True), \
             patch.object(self.mod, "subprocess") as sub:
            flags = {"restarted": False}

            def run_side_effect(cmd, **kw):
                cmd_s = " ".join(cmd)
                out = ""
                if "is-active" in cmd_s:
                    # до рестарта — active; после рестарта dnscrypt «упал»
                    out = "failed" if flags["restarted"] else "active"
                elif "is-failed" in cmd_s:
                    out = "failed" if flags["restarted"] else "inactive"
                elif "restart" in cmd_s:
                    flags["restarted"] = True
                elif "-ulnp" in cmd_s or "-tulnp" in cmd_s:
                    out = ss_53
                rc = 1 if out == "failed" else 0
                return MagicMock(returncode=rc, stdout=out, stderr="")
            sub.run.side_effect = run_side_effect

            ok = self.mod.migrate_dnscrypt_off_53()
        self.assertFalse(ok)
        # TOML восстановлен из бэкапа (двухадресный конфиг вернулся)
        self.assertIn("127.0.0.1:53", self.toml.read_text())
        # страховка: поставлена ДО правки, снята при откате
        self.assertIn((5300, False), safety_calls)
        self.assertIn((5300, True), safety_calls)
        self.assertLess(safety_calls.index((5300, False)),
                        safety_calls.index((5300, True)))


# ─────────────────────────────────────────────────────────────────────────────
#  Хелперы состояния (subprocess моки)
# ─────────────────────────────────────────────────────────────────────────────
class TestStateHelpers(unittest.TestCase):
    def setUp(self):
        import importlib
        import chimera.modules.aghome_setup as ags
        self.mod = ags

    def test_is_aghome_active(self):
        with patch.object(self.mod, "subprocess") as sub:
            sub.run.return_value = MagicMock(returncode=0, stdout="active\n")
            self.assertTrue(self.mod.is_aghome_active())
            sub.run.return_value = MagicMock(returncode=3, stdout="inactive\n")
            self.assertFalse(self.mod.is_aghome_active())

    def test_aghome_dns_ready(self):
        with patch.object(self.mod, "subprocess") as sub:
            # активна + :53 udp слушается AdGuardHome
            def run_ok(cmd, **kw):
                cmd_s = " ".join(cmd)
                if "is-active" in cmd_s:
                    return MagicMock(returncode=0, stdout="active\n")
                if "ss" in cmd_s:
                    return MagicMock(returncode=0, stdout=(
                        "udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* "
                        "users:((\"AdGuardHome\",pid=1))\n"))
                return MagicMock(returncode=0, stdout="")
            sub.run.side_effect = run_ok
            self.assertTrue(self.mod.aghome_dns_ready())

            # активна, но :53 не слушается (wizard-режим)
            def run_wizard(cmd, **kw):
                cmd_s = " ".join(cmd)
                if "is-active" in cmd_s:
                    return MagicMock(returncode=0, stdout="active\n")
                if "ss" in cmd_s:
                    return MagicMock(returncode=0, stdout="nothing\n")
                return MagicMock(returncode=0, stdout="")
            sub.run.side_effect = run_wizard
            self.assertFalse(self.mod.aghome_dns_ready())

    def test_aghome_wizard_pending(self):
        with patch.object(self.mod, "subprocess") as sub, \
             patch.object(self.mod, "AGH_CONF",
                          Path("/nonexistent/AdGuardHome.yaml")):
            sub.run.return_value = MagicMock(returncode=0, stdout="active\n")
            self.assertTrue(self.mod.aghome_wizard_pending())

    def test_state_roundtrip(self):
        with patch.object(self.mod, "AGH_STATE_FILE",
                          self._tmp() / "aghome_state.json"):
            self.mod.aghome_state_save({"phase": "wizard", "enabled": True})
            st = self.mod.aghome_state_load()
            self.assertEqual(st["phase"], "wizard")
            self.assertTrue(st["enabled"])

    def _tmp(self):
        import tempfile
        d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d


# ─────────────────────────────────────────────────────────────────────────────
#  wizard-доступ: UFW-правила + URL из адреса сервера
# ─────────────────────────────────────────────────────────────────────────────
class TestWizardAccess(unittest.TestCase):
    """Регресс v40: URL мастера строился из IP SSH-клиента.

    При SSH через VLESS-туннель sshd видит IP самого VPS, при прямом
    SSH — домашний IP (на нём ничего не слушает). UFW открывался только
    для одного IP: браузер через туннель (source = IP VPS) блокировался,
    а после отключения туннеля «Failed to fetch» / страница недоступна.
    """

    def setUp(self):
        import chimera.modules.aghome_setup as ags
        self.mod = ags

    def test_is_public_ipv4(self):
        self.assertTrue(self.mod._is_public_ipv4("138.124.255.238"))
        self.assertFalse(self.mod._is_public_ipv4("192.168.1.10"))
        self.assertFalse(self.mod._is_public_ipv4("10.0.0.1"))
        self.assertFalse(self.mod._is_public_ipv4("172.16.0.2"))
        self.assertFalse(self.mod._is_public_ipv4("127.0.0.1"))
        self.assertFalse(self.mod._is_public_ipv4("100.64.1.1"))  # CGNAT
        self.assertFalse(self.mod._is_public_ipv4("not-an-ip"))
        self.assertFalse(self.mod._is_public_ipv4("::1"))

    def test_ufw_clean_wizard_rules(self):
        calls = []
        with patch.object(self.mod, "shutil") as sh, \
             patch.object(self.mod, "subprocess") as sub:
            sh.which.return_value = "/usr/sbin/ufw"

            def run_side(cmd, **kw):
                calls.append(" ".join(cmd))
                if "status" in cmd:
                    return MagicMock(returncode=0, stdout=(
                        "To                         Action      From\n"
                        "--                         ------      ----\n"
                        "3000/tcp                   ALLOW       138.124.255.238  # chimera-aghome-wizard-temp\n"
                        "3000/tcp                   ALLOW       203.0.113.7     # chimera-aghome-wizard-temp\n"
                        "3000/tcp                   ALLOW       Anywhere       # chimera-aghome-wizard-temp\n"
                        "22/tcp                     ALLOW       Anywhere\n"))
                return MagicMock(returncode=0, stdout="Rule deleted\n")

            sub.run.side_effect = run_side
            removed = self.mod._ufw_clean_wizard_rules()
        # per-IP (legacy) + правило «для всех» (v44)
        self.assertEqual(sorted(removed),
                         ["0.0.0.0/0", "138.124.255.238", "203.0.113.7"])
        deletes = [c for c in calls if c.startswith("ufw delete")]
        self.assertEqual(len(deletes), 3)
        self.assertIn("ufw delete allow 3000/tcp", deletes)
        # посторонние правила (22/tcp ALLOW Anywhere) не тронуты

    def test_open_wizard_access_opens_port_for_all(self):
        # v44: доступ «для всех» — без туннелей, CGNAT и смены IP не страшны
        with patch.object(self.mod, "_ufw_clean_wizard_rules",
                          return_value=[]) as clean, \
             patch.object(self.mod, "_ufw_allow_port_all",
                          side_effect=lambda port: True) as allow:
            opened = self.mod._open_wizard_access("203.0.113.7")
        self.assertEqual(opened, ["0.0.0.0/0"])
        self.assertEqual(allow.call_count, 1)
        allow.assert_called_once_with(self.mod.AGH_WEB_PORT)
        clean.assert_called_once()

    def test_open_wizard_access_empty_when_ufw_unavailable(self):
        with patch.object(self.mod, "_ufw_clean_wizard_rules",
                          return_value=[]), \
             patch.object(self.mod, "_ufw_allow_port_all",
                          return_value=False):
            opened = self.mod._open_wizard_access("203.0.113.7")
        self.assertEqual(opened, [])

    def test_open_wizard_access_cleans_old_rules_first(self):
        order = []
        with patch.object(self.mod, "_ufw_clean_wizard_rules",
                          side_effect=lambda *a, **kw: order.append("clean")), \
             patch.object(self.mod, "_ufw_allow_port_all",
                          side_effect=lambda port:
                              order.append("allow-all") or True):
            self.mod._open_wizard_access("203.0.113.7")
        self.assertEqual(order, ["clean", "allow-all"])

    def test_ufw_allow_port_all_command(self):
        calls = []
        with patch.object(self.mod.shutil, "which",
                          return_value="/usr/sbin/ufw"), \
             patch.object(self.mod.subprocess, "run") as run:
            run.return_value = MagicMock(returncode=0)
            self.assertTrue(self.mod._ufw_allow_port_all(3000))
            cmd = run.call_args[0][0]
            self.assertEqual(
                cmd, ["ufw", "allow", "3000/tcp", "comment",
                      "chimera-aghome-wizard-temp"])

    def test_wizard_url_never_uses_ssh_client_ip(self):
        """Source-guard: URL мастера — только из адреса сервера."""
        src = (_PROJECT_ROOT / "chimera" / "modules" /
               "aghome_setup.py").read_text(encoding="utf-8")
        self.assertNotIn("http://{ssh_ip", src)
        self.assertIn("http://{wizard_host}", src)


# ─────────────────────────────────────────────────────────────────────────────
#  resolv_conf_fix — AGH-aware ветки
# ─────────────────────────────────────────────────────────────────────────────
class TestWebPortLifecycleV49(unittest.TestCase):
    """v49: кастомный порт Web UI — открытие/смена/закрытие через
    port_registry (register на установке, close+unregister на удалении,
    при смене порта старый не течёт)."""

    def setUp(self):
        import chimera.modules.aghome_setup as ags
        self.mod = ags

    def test_register_custom_port_opens_ufw_public(self):
        import chimera.modules.port_registry as pr
        with patch.object(pr, "port_register", return_value=(True, "")) as reg, \
             patch.object(pr, "ufw_open_port", return_value=(True, "")) as opn, \
             patch.object(pr, "port_list_for_service", return_value=[]), \
             patch.object(pr, "port_unregister", return_value=True), \
             patch.object(self.mod, "ufw_close_quiet") as cq, \
             patch.object(self.mod, "_core_module") as cm:
            cm.return_value.info = MagicMock()
            self.mod._register_aghome_ports(5300, True, True, web_port=8081)
        reg_calls = [c for c in reg.call_args_list
                     if c.args[:2] == (pr.SERVICE_AGHOME_WEB, 8081)]
        self.assertEqual(len(reg_calls), 1)
        opn.assert_any_call(8081, "tcp", pr.SERVICE_AGHOME_WEB,
                            comment="AdGuard Home Web UI (HTTP)")
        cq.assert_not_called()   # публичный режим — не закрываем

    def test_register_custom_port_closes_ufw_tls_mode(self):
        import chimera.modules.port_registry as pr
        with patch.object(pr, "port_register", return_value=(True, "")), \
             patch.object(pr, "ufw_open_port", return_value=(True, "")), \
             patch.object(pr, "port_list_for_service", return_value=[]), \
             patch.object(pr, "port_unregister"), \
             patch.object(self.mod, "ufw_close_quiet") as cq, \
             patch.object(self.mod, "_core_module") as cm:
            cm.return_value.info = MagicMock()
            self.mod._register_aghome_ports(5300, True, False, web_port=8081)
        cq.assert_called_once_with(8081, "tcp", pr.SERVICE_AGHOME_WEB)

    def test_register_port_change_closes_old(self):
        """Смена порта: старый (3000) закрывается в UFW и реестре."""
        import chimera.modules.port_registry as pr
        with patch.object(pr, "port_register", return_value=(True, "")), \
             patch.object(pr, "ufw_open_port", return_value=(True, "")), \
             patch.object(pr, "ufw_close_port", return_value=(True, "")) as close, \
             patch.object(pr, "port_list_for_service",
                          return_value=[{"service": "aghome_web",
                                         "port": 3000, "proto": "tcp"}]) as lst, \
             patch.object(pr, "port_unregister", return_value=True) as unreg, \
             patch.object(self.mod, "_core_module") as cm:
            cm.return_value.info = MagicMock()
            self.mod._register_aghome_ports(5300, True, True, web_port=8081)
        lst.assert_called_with(pr.SERVICE_AGHOME_WEB)
        close.assert_any_call(3000, "tcp", pr.SERVICE_AGHOME_WEB)
        unreg.assert_any_call(pr.SERVICE_AGHOME_WEB, port=3000, proto="tcp")

    def test_unregister_closes_custom_and_default(self):
        """Удаление AGH: закрываются и кастомный порт (реестр/state), и 3000."""
        import chimera.modules.port_registry as pr
        st = {"web_port": 8081}
        with patch.object(pr, "ufw_close_port", return_value=(True, "")) as close, \
             patch.object(pr, "port_list_for_service",
                          return_value=[{"service": "aghome_web",
                                         "port": 8081, "proto": "tcp"}]), \
             patch.object(pr, "port_unregister", return_value=True) as unreg, \
             patch.object(self.mod, "aghome_state_load", return_value=st):
            self.mod._unregister_aghome_ports()
        close.assert_any_call(8081, "tcp", pr.SERVICE_AGHOME_WEB)
        close.assert_any_call(3000, "tcp", pr.SERVICE_AGHOME_WEB)
        unreg.assert_any_call(pr.SERVICE_AGHOME_WEB, port=8081, proto="tcp")
        unreg.assert_any_call(pr.SERVICE_AGHOME_WEB, port=3000, proto="tcp")
        # DNS/DoH/DoT/DoQ тоже закрыты
        close.assert_any_call(53, "udp", pr.SERVICE_AGHOME)
        close.assert_any_call(30443, "tcp", pr.SERVICE_AGHOME_DOH)
        close.assert_any_call(853, "tcp", pr.SERVICE_AGHOME_DOT)
        close.assert_any_call(853, "udp", pr.SERVICE_AGHOME_DOQ)


class TestResolvConfAghAware(unittest.TestCase):
    def setUp(self):
        import importlib
        import chimera.modules.resolv_conf_fix as rcf
        self.mod = rcf

    def _mock_run(self, agh_serving: bool, redirect_present: bool,
                  dnscrypt_active: bool = True):
        """Фабрика _run-мока для resolv_conf_fix."""
        def _run(cmd, capture=False, check=False, quiet=False, **kw):
            cmd_s = " ".join(cmd)
            out, rc = "", 0
            if "is-active" in cmd_s:
                if "AdGuardHome" in cmd_s:
                    out, rc = ("active" if agh_serving else "inactive"), \
                              (0 if agh_serving else 3)
                else:
                    out, rc = ("active" if dnscrypt_active else "inactive"), \
                              (0 if dnscrypt_active else 3)
            elif "iptables" in cmd_s and "-L" in cmd_s:
                out = ("REDIRECT udp -- 0.0.0.0/0 127.0.0.1 udp dpt:53 "
                       "to:5300\n" if redirect_present else "")
            elif cmd and cmd[0] == "ss":
                if agh_serving:
                    out = ("udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* "
                           "users:((\"AdGuardHome\"))\n")
                else:
                    out = ("udp UNCONN 0 0 127.0.0.1:5300 0.0.0.0:* "
                           "users:((\"dnscrypt-proxy\"))\n")
            return MagicMock(returncode=rc, stdout=out, stderr="")
        return _run

    def test_agh_serving_53_detected(self):
        with patch.object(self.mod, "_run", self._mock_run(True, False)):
            self.assertTrue(self.mod._is_aghome_serving_53())

    def test_agh_not_serving(self):
        with patch.object(self.mod, "_run", self._mock_run(False, False)):
            self.assertFalse(self.mod._is_aghome_serving_53())

    def test_diag_no_false_reason_when_agh_serves(self):
        """AGH служит :53 (и резолвит — v55 мок пробы), redirect отсутствует →
        НЕТ причины 'redirect не активен' (DNS жив через AGH), fix не требуется."""
        with patch.object(self.mod, "_run", self._mock_run(True, False)), \
             patch.object(self.mod, "agh_probe_resolve",
                          return_value=(True, "www.example.com → 1 ответ, 5 мс")), \
             patch.object(self.mod, "_RESOLV_CONF") as p_resolv, \
             patch.object(self.mod, "_NSSWITCH_CONF") as p_ns, \
             patch.object(self.mod, "_DNSCRYPT_TOML") as p_toml:
            p_resolv.exists.return_value = True
            p_resolv.read_text.return_value = "nameserver 127.0.0.1\n"
            p_ns.exists.return_value = False
            p_toml.exists.return_value = True
            p_toml.read_text.return_value = (
                "listen_addresses = ['127.0.0.1:5300']\n")
            diag = self.mod.diagnose_resolv_conf()
        self.assertTrue(diag["aghome_serving_53"])
        self.assertTrue(diag["dns_redirect_active"])  # redirect отсутствует = ОК
        has_dead_dns_reason = any("DNS мёртв" in r for r in diag["leak_reasons"])
        self.assertFalse(has_dead_dns_reason)

    def test_diag_reason_when_redirect_steals_agh_traffic(self):
        """AGH служит :53 (и резолвит — v55 мок пробы), НО redirect активен →
        причина 'запросы обходят AGH', fix_required → фикс снимет redirect."""
        with patch.object(self.mod, "_run", self._mock_run(True, True)), \
             patch.object(self.mod, "agh_probe_resolve",
                          return_value=(True, "www.example.com → 1 ответ, 5 мс")), \
             patch.object(self.mod, "_RESOLV_CONF") as p_resolv, \
             patch.object(self.mod, "_NSSWITCH_CONF") as p_ns, \
             patch.object(self.mod, "_DNSCRYPT_TOML") as p_toml:
            p_resolv.exists.return_value = True
            p_resolv.read_text.return_value = "nameserver 127.0.0.1\n"
            p_ns.exists.return_value = False
            p_toml.exists.return_value = True
            p_toml.read_text.return_value = (
                "listen_addresses = ['127.0.0.1:5300']\n")
            diag = self.mod.diagnose_resolv_conf()
        self.assertTrue(diag["aghome_serving_53"])
        self.assertFalse(diag["dns_redirect_active"])  # redirect есть = ПЛОХО
        has_steal_reason = any("обходят AGH" in r for r in diag["leak_reasons"])
        self.assertTrue(has_steal_reason)


if __name__ == "__main__":
    unittest.main()


# ─────────────────────────────────────────────────────────────────────────────
#  Интеграционные source-level проверки (меню/wizard/порядок запуска)
# ─────────────────────────────────────────────────────────────────────────────
class TestIntegrationSourceChecks(unittest.TestCase):
    """Регрессионные guard'ы: ключевые точки интеграции AGH в _core.py,
    install_prompts.py и xray_install.py не должны исчезнуть."""

    def _read(self, rel: str) -> str:
        return (_PROJECT_ROOT / rel).read_text(errors="replace")

    def test_core_has_aghome_constants(self):
        src = self._read("chimera/_core.py")
        self.assertIn("AGHOME_BIN", src)
        self.assertIn("AGHOME_WEB_PORT", src)
        self.assertIn("PARAM_USE_AGHOME", src)
        self.assertIn("AGHOME_DNS_PORT:     int = 53", src)

    def test_core_network_menu_item_A(self):
        src = self._read("chimera/_core.py")
        self.assertIn('_box_item("A", f"🛡️ AdGuard Home', src)
        self.assertIn("do_aghome_menu", src)

    def test_core_install_flow_calls_install_aghome(self):
        src = self._read("chimera/_core.py")
        self.assertIn("install_aghome", src)
        # Шаг 1.5 — порядок dnscrypt → AGH → xray
        self.assertIn("Шаг 1.5: запуск AdGuard Home", src)

    def test_core_state_persists_use_aghome(self):
        src = self._read("chimera/_core.py")
        self.assertIn('"use_aghome":', src)
        self.assertIn('state.get("use_aghome"', src)

    def test_install_prompts_has_agh_question(self):
        src = self._read("chimera/modules/install_prompts.py")
        self.assertIn("Установить AdGuard Home? [Y/n]", src)
        # вопрос только при выбранном DNSCrypt
        self.assertIn("if PARAM_USE_DNSCRYPT:", src)
        self.assertIn("PARAM_USE_AGHOME", src)
        # сводка упоминает AGH
        self.assertIn("AdGuard Home:", src)

    def test_xray_config_agh_branch(self):
        for rel in ("chimera/modules/xray_install.py",
                    "chimera/modules/chain_nodes.py"):
            src = self._read(rel)
            self.assertIn("agh_dns_available", src,
                          f"{rel}: нет AGH-ветки DNS (v55: agh_dns_available "
                          f"— глубокий health-check, заменил aghome_dns_ready)")
            self.assertIn('"port": 53', src,
                          f"{rel}: нет DNS-сервера 127.0.0.1:53")

    def test_port_registry_has_agh_tags(self):
        src = self._read("chimera/modules/port_registry.py")
        for tag in ("SERVICE_DNSCRYPT", "SERVICE_AGHOME", "SERVICE_AGHOME_WEB",
                    "SERVICE_AGHOME_DOH", "SERVICE_AGHOME_DOT",
                    "SERVICE_AGHOME_DOQ"):
            self.assertIn(tag, src)

    def test_dnscrypt_setup_registers_port(self):
        src = self._read("chimera/modules/dnscrypt_setup.py")
        self.assertIn("SERVICE_DNSCRYPT", src)

    def test_aghome_unit_order(self):
        """systemd-unit AGH: после dnscrypt, до xray/nginx/chimera-dns-fix."""
        from chimera.modules import aghome_setup
        # _write_aghome_unit пишет литерал — проверяем содержимое функции
        import inspect
        src = inspect.getsource(aghome_setup._write_aghome_unit)
        self.assertIn("After=network.target network-online.target dnscrypt-proxy.service",
                      src)
        self.assertIn("Before=xray.service nginx.service chimera-dns-fix.service",
                      src)
        self.assertIn("User={AGH_USER}", src)
        self.assertIn("AmbientCapabilities=CAP_NET_BIND_SERVICE", src)
        # Рендер реального unit'а: подменяем запись и смотрим содержимое
        written = {}
        class _FakePath(str):
            def __getattr__(self, name):
                return self
            def mkdir(self, *a, **kw): pass
        with patch.object(aghome_setup, "AGH_SERVICE_UNIT", _FakePath()), \
             patch.object(aghome_setup, "subprocess") as sub:
            def write_text(self, content, *a, **kw):
                written["unit"] = content
            _FakePath.write_text = write_text
            _FakePath.parent = _FakePath()
            ok = aghome_setup._write_aghome_unit()
        self.assertTrue(ok)
        unit = written.get("unit", "")
        self.assertIn("User=adguard", unit)
        self.assertIn("ExecStart=/usr/local/bin/AdGuardHome -w /opt/AdGuardHome", unit)


# ─────────────────────────────────────────────────────────────────────────────
#  finalize_aghome_config — end-to-end YAML-хирургия на конфиге мастера
# ─────────────────────────────────────────────────────────────────────────────
class TestFinalizeAghomeConfig(unittest.TestCase):
    WIZARD_YAML = """http:
  pprof:
    port: 6060
    enabled: false
  address: 0.0.0.0:3000
  session_ttl: 720h
users:
  - name: admin
    password: $2a$10$SomeBcryptHashFromWizard
auth_attempts: 5
block_auth_min: 15
language: en
theme: auto
dns:
  bind_hosts:
    - 127.0.0.1
  port: 53
  upstream_dns:
    - https://dns.adguard-dns.com/dns-query
  bootstrap_dns:
    - 9.9.9.9
  fallback_dns: []
  ratelimit: 0
tls:
  enabled: false
  server_name: ""
filters: []
querylog:
  enabled: true
  file_enabled: true
  interval: 168h
statistics:
  enabled: true
  interval: 24h
schema_version: 29
"""

    def setUp(self):
        import importlib
        import chimera.modules.aghome_setup as ags
        self.mod = importlib.reload(ags)
        self._tmpdir = Path(tempfile.mkdtemp())
        self.conf = self._tmpdir / "AdGuardHome.yaml"
        self.conf.write_text(self.WIZARD_YAML)
        self.state_file = self._tmpdir / "aghome_state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_finalize_full_flow(self):
        """Мастер завершён (users есть) → финализатор:
        - сохраняет users/schema_version/theme (bcrypt не тронут)
        - заменяет dns/tls/http/filters/querylog/statistics
        - language: en → ru
        - вызывает снятие redirect + перегенерацию xray
        """
        core = MagicMock()
        core.info = core.warn = core.success = core.dim = (
            lambda *a, **k: None)
        core._box_top = core._box_row = core._box_sep = core._box_bottom = (
            lambda *a, **k: None)
        core.PARAM_DOMAIN = "dns.example.com"

        state = {"enabled": True, "phase": "wizard",
                 "web_mode": "https_self", "domain": "dns.example.com",
                 "tls_enabled": True, "web_port": 3000}
        calls = {"resolv_fix": 0, "xray_regen": 0, "ports_reg": 0}

        def ss_listener(cmd, **kw):
            cmd_s = " ".join(cmd)
            out, rc = "", 0
            if "is-active" in cmd_s:
                out = "active"
            elif "is-failed" in cmd_s:
                out = "inactive"
            elif cmd and cmd[0] == "ss":
                # :53 udp+tcp, :853, :30443 слушаются AGH
                out = (
                    "udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* "
                    "users:((\"AdGuardHome\"))\n"
                    "tcp LISTEN 0 0 127.0.0.1:53 0.0.0.0:* "
                    "users:((\"AdGuardHome\"))\n"
                    "tcp LISTEN 0 0 0.0.0.0:853 0.0.0.0:* "
                    "users:((\"AdGuardHome\"))\n"
                    "tcp LISTEN 0 0 0.0.0.0:30443 0.0.0.0:* "
                    "users:((\"AdGuardHome\"))\n")
            return MagicMock(returncode=rc, stdout=out, stderr="")

        with patch.object(self.mod, "_core_module", return_value=core), \
             patch.object(self.mod, "AGH_CONF", self.conf), \
             patch.object(self.mod, "AGH_STATE_FILE", self.state_file), \
             patch.object(self.mod, "AGH_BACKUP_DIR", self._tmpdir / "backups"), \
             patch.object(self.mod, "_prepare_tls_cert",
                          return_value=(Path("/opt/AdGuardHome/certs/c.crt"),
                                        Path("/opt/AdGuardHome/certs/c.key"))), \
             patch.object(self.mod, "_get_dnscrypt_port", return_value=5300), \
             patch.object(self.mod, "_get_public_ip", return_value="1.2.3.4"), \
             patch.object(self.mod, "_register_aghome_ports",
                          side_effect=lambda *a, **kw:
                              calls.__setitem__("ports_reg",
                                                calls["ports_reg"] + 1)), \
             patch.object(self.mod, "_regenerate_xray_config",
                          side_effect=lambda *a, **kw:
                              calls.__setitem__("xray_regen",
                                                calls["xray_regen"] + 1)), \
             patch.object(self.mod, "subprocess") as sub:
            sub.run.side_effect = ss_listener

            # Мок fix_resolv_conf_to_localhost внутри модуля resolv_conf_fix
            import chimera.modules.resolv_conf_fix as rcf
            with patch.object(rcf, "fix_resolv_conf_to_localhost",
                              side_effect=lambda **kw:
                              calls.__setitem__("resolv_fix",
                                                calls["resolv_fix"] + 1)
                              or {"ok": True, "actions": [], "warnings": [],
                                  "error": None}):
                # aghome_state_load/save идут через AGH_STATE_FILE (патчен),
                # но state в файле нет — финализатор возьмёт из аргументов
                ok = self.mod.finalize_aghome_config(
                    web_mode="https_self", domain="dns.example.com")

        self.assertTrue(ok)
        text = self.conf.read_text()

        # 1. users и прочее пользовательское сохранено
        self.assertIn("$2a$10$SomeBcryptHashFromWizard", text)
        self.assertIn("schema_version: 29", text)
        self.assertIn("theme: auto", text)
        self.assertIn("- name: admin", text)

        # 2. канонические секции применены
        self.assertIn("- 127.0.0.1:5300", text)          # upstream → dnscrypt
        self.assertIn("ratelimit: 0", text)              # v65: без лимита
        self.assertIn("cache_size: 4194304", text)
        self.assertIn("address: 0.0.0.0:3000", text)      # v48: TLS-режим биндит 0.0.0.0 (UFW снаружи закрыт)
        self.assertIn("port_https: 30443", text)         # DoH+UI TLS
        self.assertIn("port_dns_over_tls: 853", text)
        self.assertIn("adguardteam.github.io/AdGuardSDNSFilter", text)
        self.assertIn("big.oisd.nl/", text)
        self.assertIn("querylog:", text)
        self.assertIn("interval: 2160h", text)           # 90 дней
        self.assertIn("statistics:", text)
        self.assertIn("language: ru", text)

        # 3. дефолты мастера вычищены
        self.assertNotIn("dns.adguard-dns.com", text)
        self.assertNotIn("language: en", text)

        # 4. побочные эффекты
        self.assertEqual(calls["resolv_fix"], 1)   # redirect снят
        self.assertEqual(calls["xray_regen"], 1)   # xray → AGH :53
        self.assertEqual(calls["ports_reg"], 1)    # порты зарегистрированы

        # 5. state → finalized
        st = json.loads(self.state_file.read_text())
        self.assertEqual(st["phase"], "finalized")
        self.assertEqual(st["web_mode"], "https_self")

        # 6. бэкап конфига мастера создан
        baks = list((self._tmpdir / "backups").glob("AdGuardHome.yaml.*.bak"))
        self.assertEqual(len(baks), 1)

    def test_finalize_refuses_without_users(self):
        """Конфиг без users (мастер не завершён) → отказ, lockout-защита."""
        core = MagicMock()
        core.info = core.warn = core.success = core.dim = (
            lambda *a, **k: None)
        self.conf.write_text("http:\n  address: 0.0.0.0:3000\ndns:\n  port: 53\n")
        with patch.object(self.mod, "_core_module", return_value=core), \
             patch.object(self.mod, "AGH_CONF", self.conf), \
             patch.object(self.mod, "AGH_STATE_FILE", self.state_file):
            ok = self.mod.finalize_aghome_config()
        self.assertFalse(ok)


# ─────────────────────────────────────────────────────────────────────────────
#  v44: DNS-ALIVE гарантия — фактический probe + авто-восстановление
# ─────────────────────────────────────────────────────────────────────────────
class TestDnsAliveGuarantee(unittest.TestCase):
    """Инцидент v44 (vds13195): удаление AGH / провал скачивания
    оставляли систему с мёртвым DNS (GitHub «недоступен», повторная
    установка невозможна). ok:true фикса ≠ живой DNS — проверяем
    фактическим запросом и чиним лестницей: resolv-фикс → рестарт
    AGH → прямые iptables (оба протокола).
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        import chimera.modules.aghome_setup as ags
        importlib.reload(ags)
        self.mod = ags

    def test_probe_ok_dig(self):
        with patch.object(self.mod.shutil, "which",
                          return_value="/usr/bin/dig"), \
             patch.object(self.mod.subprocess, "run") as run:
            run.return_value = MagicMock(returncode=0)
            self.assertTrue(self.mod._dns_probe_ok())
            cmd = run.call_args[0][0]
            self.assertEqual(cmd[:3], ["dig", "@127.0.0.1", "github.com"])
            self.assertIn("+tries=1", cmd)

    def test_probe_dead_dig_rc9(self):
        with patch.object(self.mod.shutil, "which",
                          return_value="/usr/bin/dig"), \
             patch.object(self.mod.subprocess, "run") as run:
            run.return_value = MagicMock(returncode=9)  # no reply
            self.assertFalse(self.mod._dns_probe_ok())

    def test_probe_falls_back_to_getent(self):
        with patch.object(self.mod.shutil, "which", return_value=None), \
             patch.object(self.mod.subprocess, "run") as run:
            run.return_value = MagicMock(returncode=2)  # not found
            self.assertFalse(self.mod._dns_probe_ok())
            cmd = run.call_args[0][0]
            self.assertEqual(cmd[:2], ["getent", "hosts"])

    def test_ensure_no_action_when_alive(self):
        with patch.object(self.mod, "_system_dns_ok", return_value=True), \
             patch.object(self.mod, "_emergency_restore_dnscrypt_redirect") as em:
            self.assertTrue(self.mod._ensure_system_dns_alive())
            em.assert_not_called()

    def test_ensure_no_action_when_provider_dns_alive(self):
        """v60: чистая установка — системный DNS провайдера жив, :53 пуст:
        выход молча, БЕЗ resolv-фикса (старый код ломал DNS провайдера)."""
        with patch.object(self.mod, "_system_dns_ok", return_value=True) as sysok, \
             patch.object(self.mod, "_dns_probe_ok", return_value=False), \
             patch("chimera.modules.resolv_conf_fix."
                   "fix_resolv_conf_to_localhost") as fix, \
             patch.object(self.mod.time, "sleep", lambda s: None):
            self.assertTrue(self.mod._ensure_system_dns_alive("перед установкой AGH"))
        sysok.assert_called()
        fix.assert_not_called()

    def test_ensure_flap_protection(self):
        """v60: единичный таймаут системного резолва ≠ мёртвый DNS —
        вторая проба проходит, восстановление не запускается."""
        with patch.object(self.mod, "_system_dns_ok",
                          side_effect=[False, True]) as sysok, \
             patch("chimera.modules.resolv_conf_fix."
                   "fix_resolv_conf_to_localhost") as fix, \
             patch.object(self.mod.time, "sleep", lambda s: None):
            self.assertTrue(self.mod._ensure_system_dns_alive())
        self.assertEqual(sysok.call_count, 2)
        fix.assert_not_called()

    def test_ensure_repairs_with_resolv_fix(self):
        calls = {"fix": 0}

        def fake_fix(force=False):
            calls["fix"] += 1
            return {"ok": True}

        # системная проба: мёртв → мёртв → (после фикса + settle) жив
        with patch.object(self.mod, "_system_dns_ok",
                          side_effect=[False, False, True]), \
             patch("chimera.modules.resolv_conf_fix."
                   "fix_resolv_conf_to_localhost",
                   side_effect=fake_fix), \
             patch.object(self.mod.time, "sleep", lambda s: None):
            self.assertTrue(self.mod._ensure_system_dns_alive("тест"))
        self.assertEqual(calls["fix"], 1)

    def test_ensure_direct_iptables_both_protos(self):
        """resolv-фикс недоступен → прямые iptables udp+tcp на порт dnscrypt."""
        ipt = []

        def run_side(cmd, **kw):
            ipt.append(" ".join(cmd))
            return MagicMock(returncode=0, stdout="")

        # проба: фаза0 ×2 мёртв → settle после фикса ×3 мёртв →
        # settle после iptables: мёртв, мёртв, жив; AGH/dnscrypt не активны
        with patch.object(self.mod, "_system_dns_ok",
                          side_effect=[False, False,
                                       False, False, False,
                                       False, False, True]), \
             patch("chimera.modules.resolv_conf_fix."
                   "fix_resolv_conf_to_localhost",
                   side_effect=ImportError("модуль недоступен")), \
             patch.object(self.mod, "_svc_is_active", return_value=False), \
             patch.object(self.mod, "_wait_service", return_value=True), \
             patch.object(self.mod, "_get_dnscrypt_port", return_value=5300), \
             patch.object(self.mod.subprocess, "run", side_effect=run_side), \
             patch.object(self.mod.time, "sleep", lambda s: None):
            self.assertTrue(self.mod._ensure_system_dns_alive())

        adds = [c for c in ipt if "-A OUTPUT" in c and "REDIRECT" in c]
        self.assertEqual(len(adds), 2, msg=str(ipt))
        self.assertTrue(any("-p udp" in a for a in adds))
        self.assertTrue(any("-p tcp" in a for a in adds))
        self.assertTrue(all("--to-ports 5300" in a for a in adds))

    def test_ensure_public_dns_last_resort(self):
        """v60: локальный стек не поднялся — публичный DNS в resolv.conf,
        установка продолжается (DNS жив любой ценой)."""
        with patch.object(self.mod, "_system_dns_ok",
                          side_effect=[False, False,
                                       False, False, False,
                                       False, False, False,
                                       True]), \
             patch("chimera.modules.resolv_conf_fix."
                   "fix_resolv_conf_to_localhost",
                   side_effect=ImportError("нет")), \
             patch.object(self.mod, "_svc_is_active", return_value=False), \
             patch.object(self.mod, "_wait_service", return_value=True), \
             patch.object(self.mod, "_get_dnscrypt_port", return_value=5300), \
             patch.object(self.mod.subprocess, "run",
                          return_value=MagicMock(returncode=0)), \
             patch.object(self.mod, "_emergency_public_dns_fallback",
                          return_value=True) as pub, \
             patch.object(self.mod.time, "sleep", lambda s: None):
            self.assertTrue(self.mod._ensure_system_dns_alive())
        pub.assert_called_once()

    def test_ensure_failed_shows_help_box(self):
        """Все ступени (включая публичный DNS) провалились → бокс + False."""
        with patch.object(self.mod, "_system_dns_ok", return_value=False), \
             patch("chimera.modules.resolv_conf_fix."
                   "fix_resolv_conf_to_localhost",
                   side_effect=ImportError("нет")), \
             patch.object(self.mod, "_svc_is_active", return_value=False), \
             patch.object(self.mod, "_get_dnscrypt_port", return_value=5300), \
             patch.object(self.mod.subprocess, "run",
                          return_value=MagicMock(returncode=0)), \
             patch.object(self.mod, "_emergency_public_dns_fallback",
                          return_value=False), \
             patch.object(self.mod.time, "sleep", lambda s: None), \
             patch.object(self.mod, "_dns_blackhole_help_box") as box:
            self.assertFalse(self.mod._ensure_system_dns_alive())
        box.assert_called_once()

    def test_wait_wizard_repairs_dns(self):
        """Во время ожидания мастера DNS умер → _ensure_system_dns_alive."""
        with patch.object(self.mod, "AGH_CONF") as conf, \
             patch.object(self.mod, "_system_dns_ok", return_value=False), \
             patch.object(self.mod, "_ensure_system_dns_alive") as ensure, \
             patch.object(self.mod, "_svc_is_active", return_value=False), \
             patch.object(self.mod.time, "monotonic",
                          side_effect=[0, 1]), \
             patch.object(self.mod.time, "sleep", lambda s: None):
            conf.exists.return_value = False
            self.assertFalse(self.mod._wait_wizard_completed(300))
        ensure.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
#  v44: HEADLESS-мастер — API loopback, без браузера и туннелей
# ─────────────────────────────────────────────────────────────────────────────
class TestHeadlessWizard(unittest.TestCase):
    """Браузерный POST /control/install/check_config падал «Failed to
    fetch» (сетевой путь браузер→VPS). Headless: те же endpoints на
    loopback — не зависят от UFW/туннелей/прокси клиента.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        import chimera.modules.aghome_setup as ags
        importlib.reload(ags)
        self.mod = ags

    def test_api_post_url_method_payload(self):
        import urllib.request

        captured = {}

        class FakeResp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=0):
            captured["url"] = req.full_url
            captured["data"] = json.loads(req.data.decode())
            captured["method"] = req.get_method()
            return FakeResp()

        with patch.object(urllib.request, "urlopen",
                          side_effect=fake_urlopen):
            ok, err = self.mod._agh_install_api_post(
                "/control/install/configure", {"username": "admin"})
        self.assertTrue(ok)
        self.assertIsNone(err)
        self.assertEqual(
            captured["url"],
            "http://127.0.0.1:3000/control/install/configure")
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["data"]["username"], "admin")

    def test_api_post_http_error(self):
        import urllib.error
        import urllib.request

        def fake_urlopen(req, timeout=0):
            raise urllib.error.HTTPError(
                req.full_url, 500, "boom", {}, None)

        with patch.object(urllib.request, "urlopen",
                          side_effect=fake_urlopen):
            ok, err = self.mod._agh_install_api_post("/x", {})
        self.assertFalse(ok)
        self.assertIn("500", err)

    def test_api_post_connection_error(self):
        import urllib.request

        with patch.object(urllib.request, "urlopen",
                          side_effect=OSError("conn refused")):
            ok, err = self.mod._agh_install_api_post("/x", {})
        self.assertFalse(ok)
        self.assertIn("conn refused", err)

    def test_configure_headless_success(self):
        with patch.object(self.mod, "_agh_install_api_post",
                          return_value=(True, None)) as api, \
             patch.object(self.mod, "AGH_CONF") as conf, \
             patch.object(self.mod.time, "sleep", lambda s: None):
            conf.exists.return_value = True
            conf.read_text.return_value = "users:\n- name: admin\n  password: $2a$10$x\n"
            self.assertTrue(
                self.mod._wizard_configure_headless("admin", "pw123456"))
        # два вызова: check_config + configure
        self.assertEqual(api.call_count, 2)
        paths = [c.args[0] for c in api.call_args_list]
        self.assertEqual(paths, ["/control/install/check_config",
                                 "/control/install/configure"])
        payload = api.call_args_list[1].args[1]
        self.assertEqual(payload["username"], "admin")
        self.assertEqual(payload["password"], "pw123456")
        self.assertEqual(payload["dns"], {"ip": "127.0.0.1", "port": 53})
        self.assertEqual(payload["web"], {"ip": "0.0.0.0", "port": 3000})

    def test_configure_headless_configure_fail(self):
        with patch.object(self.mod, "_agh_install_api_post",
                          return_value=(False, "HTTP 400: bad")):
            self.assertFalse(
                self.mod._wizard_configure_headless("admin", "pw123456"))

    def test_ask_admin_credentials_retry_mismatch(self):
        with patch("builtins.input", return_value="admin"), \
             patch("getpass.getpass",
                   side_effect=["short", "longpassword1",
                                "longpassword2",
                                "longpassword2", "longpassword2"]) as gp:
            creds = self.mod._ask_admin_credentials()
        self.assertEqual(creds, ("admin", "longpassword2"))
        # короткий + несовпадение (оба пароля заново) + успешная пара
        self.assertEqual(gp.call_count, 5)

    def test_ask_admin_credentials_eof_returns_none(self):
        with patch("builtins.input", side_effect=EOFError):
            self.assertIsNone(self.mod._ask_admin_credentials())

    def test_ask_headless_wizard_default(self):
        with patch("builtins.input", return_value=""):
            self.assertTrue(self.mod._ask_headless_wizard())
        with patch("builtins.input", return_value="2"):
            self.assertFalse(self.mod._ask_headless_wizard())

    def test_complete_first_run_wizard_headless(self):
        """Headless-путь: configure → True; UFW/веб-ожидание не нужны."""
        with patch.object(self.mod, "_ask_headless_wizard", return_value=True), \
             patch.object(self.mod, "_ask_admin_credentials",
                          return_value=("admin", "pw123456")) as ask, \
             patch.object(self.mod, "_wizard_configure_headless",
                          return_value=True) as configure, \
             patch.object(self.mod, "_open_wizard_access") as open_acc, \
             patch.object(self.mod, "_wait_wizard_completed") as wait, \
             patch.object(self.mod, "_print_wizard_instructions") as instr, \
             patch.object(self.mod, "aghome_state_save") as save:
            self.assertTrue(self.mod._complete_first_run_wizard(
                self.mod.AGH_WEB_HTTP_PUB, "", True))
        ask.assert_called_once()
        # v49: headless получает и кастомный порт Web UI (дефолт 3000)
        configure.assert_called_once_with("admin", "pw123456",
                                          web_port=self.mod.AGH_WEB_PORT)
        open_acc.assert_not_called()
        wait.assert_not_called()
        instr.assert_not_called()
        save.assert_called_once()
        st = save.call_args[0][0]
        self.assertEqual(st["phase"], "wizard")
        self.assertEqual(st["wizard_ips"], ["0.0.0.0/0"])
        self.assertEqual(st["web_port"], self.mod.AGH_WEB_PORT)

    def test_complete_first_run_wizard_custom_port(self):
        """v49: кастомный порт Web UI — в payload мастера и в state."""
        with patch.object(self.mod, "_ask_headless_wizard", return_value=True), \
             patch.object(self.mod, "_ask_admin_credentials",
                          return_value=("admin", "pw123456")), \
             patch.object(self.mod, "_wizard_configure_headless",
                          return_value=True) as configure, \
             patch.object(self.mod, "_open_wizard_access") as open_acc, \
             patch.object(self.mod, "aghome_state_save") as save:
            self.assertTrue(self.mod._complete_first_run_wizard(
                self.mod.AGH_WEB_HTTP_PUB, "", True, web_port=8081))
        configure.assert_called_once_with("admin", "pw123456", web_port=8081)
        open_acc.assert_not_called()
        st = save.call_args[0][0]
        self.assertEqual(st["web_port"], 8081)

    def test_complete_first_run_wizard_falls_back_to_web(self):
        """Headless-провал → веб-мастер: :3000 открыт, инструкция, ожидание."""
        with patch.object(self.mod, "_ask_headless_wizard", return_value=True), \
             patch.object(self.mod, "_ask_admin_credentials",
                          return_value=("admin", "pw123456")), \
             patch.object(self.mod, "_wizard_configure_headless",
                          return_value=False), \
             patch.object(self.mod, "_open_wizard_access",
                          return_value=["0.0.0.0/0"]) as open_acc, \
             patch.object(self.mod, "_print_wizard_instructions") as instr, \
             patch.object(self.mod, "_wait_wizard_completed",
                          return_value=True) as wait:
            self.assertTrue(self.mod._complete_first_run_wizard(
                self.mod.AGH_WEB_HTTP_PUB, "", True))
        open_acc.assert_called_once()
        instr.assert_called_once()
        wait.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
#  v44: uninstall — DNS проверяется фактическим запросом после удаления
# ─────────────────────────────────────────────────────────────────────────────
class TestUninstallDnsAlive(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        import chimera.modules.aghome_setup as ags
        importlib.reload(ags)
        self.mod = ags

    def test_uninstall_verifies_dns_alive(self):
        with patch.object(self.mod, "is_aghome_installed",
                          return_value=True), \
             patch.object(self.mod, "AGH_SERVICE_UNIT") as unit, \
             patch.object(self.mod, "AGH_BIN") as aghbin, \
             patch.object(self.mod, "AGH_WORK_DIR") as workdir, \
             patch.object(self.mod, "AGH_STATE_FILE") as statef, \
             patch.object(self.mod, "AGH_BACKUP_DIR") as backup_dir, \
             patch.object(self.mod.subprocess, "run",
                          MagicMock(returncode=0)), \
             patch.object(self.mod.shutil, "rmtree"), \
             patch.object(self.mod, "_remove_certbot_deploy_hook"), \
             patch.object(self.mod, "_ufw_clean_wizard_rules"), \
             patch.object(self.mod, "_unregister_aghome_ports"), \
             patch.object(self.mod, "_regenerate_xray_config"), \
             patch.object(self.mod, "aghome_state_save"), \
             patch("chimera.modules.resolv_conf_fix."
                   "fix_resolv_conf_to_localhost",
                   return_value={"ok": True}), \
             patch.object(self.mod, "_ensure_system_dns_alive",
                          return_value=True) as ensure:
            unit.exists.return_value = True
            aghbin.unlink = MagicMock()
            workdir.exists.return_value = False
            statef.unlink = MagicMock()
            backup_dir.mkdir = MagicMock()
            self.assertTrue(self.mod.uninstall_aghome())
        ensure.assert_called_once()

    def test_install_calls_dns_alive_before_download(self):
        """Шаг 0: DNS-alive проверяется ДО скачивания (v44)."""
        import re as _re
        src = (_PROJECT_ROOT / "chimera" / "modules" /
               "aghome_setup.py").read_text(encoding="utf-8")
        m = _re.search(r"def install_aghome.*?(?=\ndef )", src, _re.DOTALL)
        body = m.group(0)
        i_ensure = body.find('_ensure_system_dns_alive("перед установкой AGH")')
        i_dnscrypt = body.find('_svc_is_active("dnscrypt-proxy")')
        i_fetch = body.find("fetch_package(AGHOME_SPEC")
        self.assertGreater(i_ensure, 0)
        self.assertLess(i_ensure, i_dnscrypt,
                        "DNS-alive должен идти ПЕРЕД проверкой dnscrypt")
        self.assertLess(i_ensure, i_fetch,
                        "DNS-alive должен идти ПЕРЕД скачиванием")


# ─────────────────────────────────────────────────────────────────────────────
#  v45: ложный :53 (systemd-resolved stub) + proc-фильтр
# ─────────────────────────────────────────────────────────────────────────────
class TestPortListeningResolvedStub(unittest.TestCase):
    """vds13195: _port_listening(53) матчила 127.0.0.53:53 (systemd-resolved)
    → ложное «AGH владеет :53» → resolv-фикс снимал redirect → black-hole."""

    def setUp(self):
        _setup_core_in_sysmodules()
        import chimera.modules.aghome_setup as ags
        self.mod = ags

    def _ss(self, lines):
        patcher = patch.object(self.mod, "subprocess")
        sub = patcher.start()
        self.addCleanup(patcher.stop)
        sub.run.return_value = MagicMock(returncode=0, stdout="\n".join(lines))
        return sub

    def test_resolved_stub_is_not_owner_of_53(self):
        self._ss([
            "udp UNCONN 0 0 127.0.0.53:53 0.0.0.0:* "
            'users:(("systemd-resolve",pid=999))',
            "tcp LISTEN 0 0 127.0.0.53:53 0.0.0.0:* "
            'users:(("systemd-resolve",pid=999))',
        ])
        self.assertFalse(self.mod._port_listening(53, "udp"))
        self.assertFalse(self.mod._port_listening(53, "tcp"))

    def test_agh_owner_of_53_detected(self):
        self._ss([
            "udp UNCONN 0 0 127.0.0.53:53 0.0.0.0:* "
            'users:(("systemd-resolve",pid=999))',
            "udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* "
            'users:(("AdGuardHome",pid=1))',
        ])
        self.assertTrue(self.mod._port_listening(53, "udp"))
        self.assertTrue(self.mod._port_listening(53, "udp", proc="AdGuardHome"))

    def test_proc_filter_excludes_foreign_owner(self):
        """:53 слушает dnscrypt → proc=AdGuardHome обязан вернуть False."""
        self._ss([
            "udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* "
            'users:(("dnscrypt-proxy",pid=7))',
        ])
        self.assertTrue(self.mod._port_listening(53, "udp"))
        self.assertFalse(self.mod._port_listening(53, "udp", proc="AdGuardHome"))
        self.assertTrue(self.mod._port_listening(53, "udp", proc="dnscrypt-proxy"))

    def test_aghome_dns_ready_requires_agh_process(self):
        """resolved-stub на :53 ≠ «AGH владеет :53» (критично для
        resolv_conf_fix: ложный positive сносил redirect 53→5300)."""
        def run_stub(cmd, **kw):
            cmd_s = " ".join(cmd)
            if "is-active" in cmd_s:
                return MagicMock(returncode=0, stdout="active\n")
            if cmd and cmd[0] == "ss":
                return MagicMock(returncode=0, stdout=(
                    "udp UNCONN 0 0 127.0.0.53:53 0.0.0.0:* "
                    'users:(("systemd-resolve",pid=999))\n'
                    "udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* "
                    'users:(("dnscrypt-proxy",pid=7))\n'))
            return MagicMock(returncode=0, stdout="")
        with patch.object(self.mod, "subprocess") as sub:
            sub.run.side_effect = run_stub
            self.assertFalse(self.mod.aghome_dns_ready())


# ─────────────────────────────────────────────────────────────────────────────
#  v45: TLS-self-heal — tls-секция, диагностика, починка
# ─────────────────────────────────────────────────────────────────────────────
class TestTlsSelfHealV45(unittest.TestCase):
    """AGH при битом сертификате молча ставит tls.enabled=false и живёт
    на plain DNS (home.go: newTLSManager err → лог, не fatal). v45:
    финализация диагностирует и чинит TLS-порты."""

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        import chimera.modules.aghome_setup as ags
        importlib.reload(ags)
        self.mod = ags
        self._tmpdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self._tmpdir, ignore_errors=True))

    def _core(self):
        core = MagicMock()
        core.info = core.warn = core.success = core.dim = (
            lambda *a, **k: None)
        core._box_top = core._box_row = core._box_sep = core._box_bottom = (
            lambda *a, **k: None)
        return core

    def test_tls_live_enabled_parse(self):
        self.assertTrue(self.mod._tls_live_enabled(
            "tls:\n  enabled: true\n  port_https: 30443\n"))
        self.assertFalse(self.mod._tls_live_enabled(
            "tls:\n  enabled: false\n  port_https: 0\n"))
        self.assertIsNone(self.mod._tls_live_enabled("http:\n  address: x\n"))
        # секция закончилась — следующая top-level
        self.assertTrue(self.mod._tls_live_enabled(
            "tls:\n  enabled: true\nhttp:\n  address: x\n"))

    def test_cert_pair_matches_definitive_mismatch(self):
        """Оба pubkey получены и различаются → False (блокируем)."""
        cert = self._tmpdir / "c.crt"
        key = self._tmpdir / "c.key"
        cert.write_text("x")
        key.write_text("y")
        with patch.object(self.mod, "subprocess") as sub:
            sub.run.side_effect = [
                MagicMock(returncode=0, stdout="-----BEGIN PUBLIC KEY-----\nAAA\n"),
                MagicMock(returncode=0, stdout="-----BEGIN PUBLIC KEY-----\nBBB\n"),
            ]
            ok, why = self.mod._cert_pair_matches(cert, key)
            self.assertFalse(ok)
            self.assertIn("различаются", why)
        with patch.object(self.mod, "subprocess") as sub:
            pub = "-----BEGIN PUBLIC KEY-----\nAAA\n"
            sub.run.side_effect = [
                MagicMock(returncode=0, stdout=pub),
                MagicMock(returncode=0, stdout=pub),
            ]
            ok, _ = self.mod._cert_pair_matches(cert, key)
            self.assertTrue(ok)
        # openssl недоступен → не блокируем (ok=True)
        with patch.object(self.mod, "subprocess") as sub:
            sub.run.side_effect = [
                MagicMock(returncode=1, stdout=""),
                MagicMock(returncode=1, stdout=""),
            ]
            ok, _ = self.mod._cert_pair_matches(cert, key)
            self.assertTrue(ok)

    def test_heal_tls_pair_mismatch_falls_back_selfsigned(self):
        """Пара LE рассинхронена → self-signed fallback + перезапись
        tls-секции в live-конфиге (AGH успел выставить enabled:false)."""
        conf = self._tmpdir / "AdGuardHome.yaml"
        conf.write_text(
            "http:\n  address: 127.0.0.1:3000\n"
            "tls:\n  enabled: false\n  port_https: 0\n"
            "users:\n  - name: admin\n    password: $2a$10$hash\n")

        bad_cert = self._tmpdir / "agh-tls.crt"
        bad_key = self._tmpdir / "agh-tls.key"
        bad_cert.write_text("cert")
        bad_key.write_text("key")
        ss_cert = self._tmpdir / "self.crt"
        ss_key = self._tmpdir / "self.key"
        ss_cert.write_text("ss-cert")
        ss_key.write_text("ss-key")

        with patch.object(self.mod, "_core_module",
                          return_value=self._core()), \
             patch.object(self.mod, "AGH_CONF", conf), \
             patch.object(self.mod, "_agh_tls_journal_errors",
                          return_value="tls_manager: initializing err=bad pair"), \
             patch.object(self.mod, "_cert_pair_matches",
                          return_value=(False, "pubkey различаются")), \
             patch.object(self.mod, "_certs_readable_by_user",
                          return_value=(True, "")), \
             patch.object(self.mod, "_generate_self_signed_tls",
                          return_value=(ss_cert, ss_key)) as gen_ss, \
             patch.object(self.mod, "_wait_service",
                          return_value=True), \
             patch.object(self.mod, "_tls_ports_status",
                          return_value={(30443, "tcp"): True,
                                        (853, "tcp"): True,
                                        (853, "udp"): True}), \
             patch.object(self.mod, "subprocess") as sub:
            sub.run.return_value = MagicMock(returncode=0, stdout="")
            healed, cpath, kpath, msg = self.mod._heal_tls_listeners(
                "chimeraprodcdn.online", "chimeraprodcdn.online",
                bad_cert, bad_key)

        self.assertTrue(healed, msg)
        gen_ss.assert_called_once()
        self.assertEqual(cpath, ss_cert)
        text = conf.read_text()
        self.assertIn("enabled: true", text)
        self.assertIn(str(ss_cert), text)          # новая пара в yaml
        self.assertIn("port_https: 30443", text)
        # старые (битые) пути не должны остаться в tls-секции
        tls_sec = text[text.find("tls:"):text.find("users:")]
        self.assertNotIn(str(bad_cert), tls_sec)

    def test_heal_tls_only_perms_fixes_ownership(self):
        """Единственная проблема — права → chown, LE-пара сохраняется."""
        conf = self._tmpdir / "AdGuardHome.yaml"
        conf.write_text("tls:\n  enabled: false\n  port_https: 0\n")
        cert = self._tmpdir / "agh-tls.crt"
        key = self._tmpdir / "agh-tls.key"
        cert.write_text("c")
        key.write_text("k")

        with patch.object(self.mod, "_core_module",
                          return_value=self._core()), \
             patch.object(self.mod, "AGH_CONF", conf), \
             patch.object(self.mod, "_agh_tls_journal_errors",
                          return_value=""), \
             patch.object(self.mod, "_cert_pair_matches",
                          return_value=(True, "")), \
             patch.object(self.mod, "_certs_readable_by_user",
                          return_value=(False, "runuser rc=1: Permission denied")), \
             patch.object(self.mod, "_own_certs") as own, \
             patch.object(self.mod, "_own_certs_dir") as ownd, \
             patch.object(self.mod, "_generate_self_signed_tls") as gen_ss, \
             patch.object(self.mod, "_wait_service",
                          return_value=True), \
             patch.object(self.mod, "_tls_ports_status",
                          return_value={(30443, "tcp"): True,
                                        (853, "tcp"): True,
                                        (853, "udp"): True}), \
             patch.object(self.mod, "subprocess") as sub:
            sub.run.return_value = MagicMock(returncode=0, stdout="")
            healed, cpath, kpath, msg = self.mod._heal_tls_listeners(
                "chimeraprodcdn.online", "chimeraprodcdn.online",
                cert, key)

        self.assertTrue(healed, msg)
        gen_ss.assert_not_called()          # LE-пара сохранена
        own.assert_called_once()
        ownd.assert_called_once()
        self.assertEqual(cpath, cert)
        self.assertIn("enabled: true", conf.read_text())


# ─────────────────────────────────────────────────────────────────────────────
#  v45: перегенерация Xray в режиме B — chain_nodes (не xray_install)
# ─────────────────────────────────────────────────────────────────────────────
class TestXrayRegenModeB(unittest.TestCase):
    """vds13195: AttributeError «xray_install has no attribute
    generate_xray_config_chain_entry_multi» — генератор живёт в chain_nodes."""

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        import chimera.modules.aghome_setup as ags
        importlib.reload(ags)
        self.mod = ags
        self._tmpdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self._tmpdir, ignore_errors=True))
        # фейковые chain_nodes / xray_install — без тяжёлых импортов
        self._fake_cn = types.ModuleType("chimera.modules.chain_nodes")
        self._fake_cn.generate_xray_config_chain_entry_multi = MagicMock()
        self._fake_xi = types.ModuleType("chimera.modules.xray_install")
        self._fake_xi.generate_xray_config = MagicMock()
        self._fake_xi.generate_xray_config_xhttp = MagicMock()
        import chimera.modules as cm_pkg
        self._saved = tuple(sys.modules.get(k) for k in
                            ("chimera.modules.chain_nodes",
                             "chimera.modules.xray_install"))
        sys.modules["chimera.modules.chain_nodes"] = self._fake_cn
        sys.modules["chimera.modules.xray_install"] = self._fake_xi
        cm_pkg.chain_nodes = self._fake_cn
        cm_pkg.xray_install = self._fake_xi
        self.addCleanup(self._restore)

    def _restore(self):
        import chimera.modules as cm_pkg
        for key, mod in zip(("chimera.modules.chain_nodes",
                             "chimera.modules.xray_install"), self._saved):
            if mod is not None:
                sys.modules[key] = mod
            else:
                sys.modules.pop(key, None)
        for attr in ("chain_nodes", "xray_install"):
            if hasattr(cm_pkg, attr):
                delattr(cm_pkg, attr)

    def _state(self, mode, protocol):
        st = self._tmpdir / "state.json"
        st.write_text(json.dumps(
            {"protocol_mode": protocol, "install_mode": mode}))
        return st

    def test_mode_b_calls_chain_nodes(self):
        core = MagicMock()
        core.info = core.warn = lambda *a, **k: None
        with patch.object(self.mod, "_core_module", return_value=core), \
             patch.object(self.mod, "XRAY_STATE_FILE",
                          self._state("B", "reality")), \
             patch.object(self.mod, "_svc_is_active", return_value=True), \
             patch.object(self.mod, "subprocess") as sub:
            sub.run.return_value = MagicMock(returncode=0, stdout="")
            self.assertTrue(self.mod._regenerate_xray_config())
        self._fake_cn.generate_xray_config_chain_entry_multi.assert_called_once()
        self._fake_xi.generate_xray_config.assert_not_called()
        self._fake_xi.generate_xray_config_xhttp.assert_not_called()

    def test_mode_a_reality_calls_standard_generator(self):
        core = MagicMock()
        core.info = core.warn = lambda *a, **k: None
        with patch.object(self.mod, "_core_module", return_value=core), \
             patch.object(self.mod, "XRAY_STATE_FILE",
                          self._state("A", "reality")), \
             patch.object(self.mod, "_svc_is_active", return_value=True), \
             patch.object(self.mod, "subprocess") as sub:
            sub.run.return_value = MagicMock(returncode=0, stdout="")
            self.assertTrue(self.mod._regenerate_xray_config())
        self._fake_xi.generate_xray_config.assert_called_once()
        self._fake_cn.generate_xray_config_chain_entry_multi.assert_not_called()

    def test_mode_a_xhttp_calls_xhttp_generator(self):
        core = MagicMock()
        core.info = core.warn = lambda *a, **k: None
        with patch.object(self.mod, "_core_module", return_value=core), \
             patch.object(self.mod, "XRAY_STATE_FILE",
                          self._state("A", "xhttp")), \
             patch.object(self.mod, "_svc_is_active", return_value=True), \
             patch.object(self.mod, "subprocess") as sub:
            sub.run.return_value = MagicMock(returncode=0, stdout="")
            self.assertTrue(self.mod._regenerate_xray_config())
        self._fake_xi.generate_xray_config_xhttp.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
#  v45: финализация вызывает TLS-лечение, если порты не поднялись
# ─────────────────────────────────────────────────────────────────────────────
class TestFinalizeTlsHealInvocation(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        import chimera.modules.aghome_setup as ags
        importlib.reload(ags)
        self.mod = ags
        self._tmpdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self._tmpdir, ignore_errors=True))

    def test_finalize_heals_tls_when_ports_down(self):
        """:53 у AGH, но TLS-порты не поднялись → _heal_tls_listeners."""
        core = MagicMock()
        core.info = core.warn = core.success = core.dim = (
            lambda *a, **k: None)
        core._box_top = core._box_row = core._box_sep = core._box_bottom = (
            lambda *a, **k: None)
        core.PARAM_DOMAIN = "chimeraprodcdn.online"

        conf = self._tmpdir / "AdGuardHome.yaml"
        conf.write_text(
            "http:\n  address: 0.0.0.0:3000\n"
            "dns:\n  port: 53\n"
            "tls:\n  enabled: false\n"
            "users:\n  - name: admin\n    password: $2a$10$bcrypt\n"
            "schema_version: 29\n")
        state_file = self._tmpdir / "aghome_state.json"
        ss_cert = self._tmpdir / "self.crt"
        ss_key = self._tmpdir / "self.key"
        ss_cert.write_text("c")
        ss_key.write_text("k")

        def ss_listener(cmd, **kw):
            cmd_s = " ".join(cmd)
            out, rc = "", 0
            if "is-active" in cmd_s:
                out = "active"
            elif "is-failed" in cmd_s:
                out = "inactive"
            elif cmd and cmd[0] == "ss":
                # ТОЛЬКО :53 (AGH) — TLS-порты не поднялись
                out = ("udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* "
                       'users:(("AdGuardHome",pid=1))\n'
                       "tcp LISTEN 0 0 127.0.0.1:53 0.0.0.0:* "
                       'users:(("AdGuardHome",pid=1))\n')
            return MagicMock(returncode=rc, stdout=out, stderr="")

        with patch.object(self.mod, "_core_module", return_value=core), \
             patch.object(self.mod, "AGH_CONF", conf), \
             patch.object(self.mod, "AGH_STATE_FILE", state_file), \
             patch.object(self.mod, "AGH_BACKUP_DIR", self._tmpdir / "bak"), \
             patch.object(self.mod, "_prepare_tls_cert",
                          return_value=(self._tmpdir / "le.crt",
                                        self._tmpdir / "le.key")), \
             patch.object(self.mod, "_get_dnscrypt_port", return_value=5300), \
             patch.object(self.mod, "_get_public_ip", return_value="1.2.3.4"), \
             patch.object(self.mod, "_register_aghome_ports"), \
             patch.object(self.mod, "_regenerate_xray_config"), \
             patch.object(self.mod, "_heal_tls_listeners",
                          return_value=(True, ss_cert, ss_key,
                                        "TLS-порты подняты")) as heal, \
             patch("time.sleep", lambda s: None), \
             patch.object(self.mod, "subprocess") as sub:
            sub.run.side_effect = ss_listener
            import chimera.modules.resolv_conf_fix as rcf
            with patch.object(rcf, "fix_resolv_conf_to_localhost",
                              return_value={"ok": True, "actions": [],
                                            "warnings": [], "error": None}):
                ok = self.mod.finalize_aghome_config(
                    web_mode="https_le", domain="chimeraprodcdn.online")

        self.assertTrue(ok)
        heal.assert_called_once()
        # после heal конфиг содержит self-signed пару (AGH успел
        # переписать tls.enabled=false — финализация вернула секцию)
        self.assertEqual(heal.call_args[0][:2],
                         ("chimeraprodcdn.online", "chimeraprodcdn.online"))
