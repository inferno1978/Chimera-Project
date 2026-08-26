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
        # fallback как на роутере
        self.assertIn("- 9.9.9.9:53", s)
        self.assertIn("- 1.1.1.1:53", s)
        # bind_hosts: loopback + public
        self.assertIn("- \"127.0.0.1\"", s)
        self.assertIn("- \"1.2.3.4\"", s)
        # кеш 4MB optimistic + dnssec
        self.assertIn("cache_size: 4194304", s)
        self.assertIn("cache_optimistic: true", s)
        self.assertIn("enable_dnssec: true", s)
        self.assertIn("ratelimit: 20", s)
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
        self.assertIn("address: 127.0.0.1:3000",
                      self.mod.build_http_section(self.mod.AGH_WEB_HTTPS_LE))

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

    def _core_mock(self):
        core = MagicMock()
        core.info = lambda *a, **k: None
        core.warn = lambda *a, **k: None
        core.success = lambda *a, **k: None
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
        with patch.object(self.mod, "_core_module",
                          return_value=self._core_mock()), \
             patch.object(self.mod, "AGH_DNSCRYPT_TOML", self.toml), \
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
        # бэкап создан
        baks = list(self.toml.parent.glob("dnscrypt-proxy.toml.*.preAGH.bak"))
        self.assertEqual(len(baks), 1)
        # бэкап содержит оригинальный (двухадресный) конфиг
        self.assertIn("127.0.0.1:53", baks[0].read_text())

    def test_no_migration_when_53_free(self):
        self.toml.write_text("listen_addresses = ['127.0.0.1:5300']\n")
        with patch.object(self.mod, "_core_module",
                          return_value=self._core_mock()), \
             patch.object(self.mod, "AGH_DNSCRYPT_TOML", self.toml), \
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
#  resolv_conf_fix — AGH-aware ветки
# ─────────────────────────────────────────────────────────────────────────────
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
        """AGH служит :53, redirect отсутствует → НЕТ причины 'redirect не
        активен' (DNS жив через AGH), fix не требуется."""
        with patch.object(self.mod, "_run", self._mock_run(True, False)), \
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
        """AGH служит :53, НО redirect активен → причина 'запросы обходят AGH',
        fix_required → фикс снимет redirect."""
        with patch.object(self.mod, "_run", self._mock_run(True, True)), \
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
            self.assertIn("aghome_dns_ready", src,
                          f"{rel}: нет AGH-ветки DNS")
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
        self.assertIn("ratelimit: 20", text)
        self.assertIn("cache_size: 4194304", text)
        self.assertIn("address: 127.0.0.1:3000", text)   # web loopback
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
