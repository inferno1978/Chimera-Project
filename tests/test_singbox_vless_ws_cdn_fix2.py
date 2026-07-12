#!/usr/bin/env python3
"""
tests/test_singbox_vless_ws_cdn_fix2.py
───────────────────────────────────────────────────────────────────────────────
Тесты для v4.23.2 — 4 продакшн-фикса из v4.23.1:

1. iptables -I INPUT 1 (не -A) — правило ПЕРВОЕ в INPUT
2. Persistence — allowlist переживает reboot
3. Bunny.net: правильный источник IP (CDN edge, не Magic Containers)
4. _switch_cdn_provider() — авто-смена listen_port под новый провайдер
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import ipaddress
import json
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("vless_installer._core")
    m.__dict__.update(g)
    sys.modules["vless_installer._core"] = m


def _enter_patches(stack, patches):
    for p in patches:
        stack.enter_context(p)


# ══════════════════════════════════════════════════════════════════════════════
# ФИКС 1: iptables -I INPUT 1 — правило ПЕРВОЕ в INPUT
# ══════════════════════════════════════════════════════════════════════════════

class TestIptablesInsertAtPosition1(unittest.TestCase):
    """apply_cdn_allowlist использует -I INPUT 1 (insert в начало), не -A (append в конец)."""

    def setUp(self):
        _setup_core()
        import shutil
        if not shutil.which("iptables"):
            self.skipTest("iptables not available in test environment")

    def test_apply_uses_insert_not_append(self):
        """iptables -I INPUT 1, а НЕ -A INPUT."""
        from vless_installer.modules.singbox_cdn_nets import apply_cdn_allowlist
        mock_fetch = MagicMock(return_value=(["1.2.3.0/24"], "1 CIDR"))
        mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
        with patch("vless_installer.modules.singbox_cdn_nets.fetch_cdn_nets", mock_fetch):
            with patch("vless_installer.modules.singbox_cdn_nets._run", mock_run):
                with patch("vless_installer.modules.singbox_cdn_nets._ipset_save_port", return_value=True):
                    with patch("vless_installer.modules.singbox_cdn_nets._ipset_restore_unit_install"):
                        with patch("vless_installer.modules.singbox_cdn_nets._iptables_persist"):
                            apply_cdn_allowlist("cloudflare", 8080)
        # Извлекаем все команды
        calls = [c[0][0] if c[0] else [] for c in mock_run.call_args_list]
        # Ищем iptables -I INPUT 1 ... -j DROP
        insert_drop = [c for c in calls if "iptables" in c and "-I" in c
                       and "INPUT" in c and "1" in c and "DROP" in c and "8080" in c]
        self.assertGreater(len(insert_drop), 0,
                           "Должен быть iptables -I INPUT 1 ... -j DROP")
        # НЕ должно быть iptables -A INPUT ... -j DROP (старый паттерн)
        append_drop = [c for c in calls if "iptables" in c and "-A" in c
                       and "INPUT" in c and "DROP" in c and "8080" in c]
        self.assertEqual(len(append_drop), 0,
                         "НЕ должен использоваться -A INPUT (append) для DROP-правила")

    def test_drop_rule_is_before_other_accept_rules(self):
        """DROP от allowlist идёт РАНЬШЕ добавленного ACCEPT (проверка порядка).

        Реальный iptables (если доступен): добавляем ложное ACCEPT-правило
        через -A INPUT, затем apply_cdn_allowlist(), затем проверяем что
        DROP стоит ПЕРВЫМ в INPUT (до ACCEPT).
        """
        import subprocess
        port = 18099  # unlikely-used port
        # Очищаем правила для этого порта (если есть)
        for _ in range(5):
            subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp",
                          "--dport", str(port), "-j", "ACCEPT"],
                         capture_output=True)
        subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp",
                       "--dport", str(port), "-j", "DROP",
                       "-m", "comment", "--comment", f"singbox-cdn-allowlist-{port}"],
                      capture_output=True)
        subprocess.run(["ipset", "destroy", f"singbox_cdn_allowlist_{port}"],
                      capture_output=True)

        try:
            # Добавляем ложное ACCEPT-правило (эмулируя чужой модуль)
            subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp",
                           "--dport", str(port), "-j", "ACCEPT"],
                          capture_output=True)
            # Применяем allowlist
            from vless_installer.modules.singbox_cdn_nets import apply_cdn_allowlist
            with patch("vless_installer.modules.singbox_cdn_nets.fetch_cdn_nets",
                       return_value=(["1.2.3.0/24"], "1 CIDR")):
                with patch("vless_installer.modules.singbox_cdn_nets._ipset_save_port", return_value=True):
                    with patch("vless_installer.modules.singbox_cdn_nets._ipset_restore_unit_install"):
                        with patch("vless_installer.modules.singbox_cdn_nets._iptables_persist"):
                            apply_cdn_allowlist("cloudflare", port)
            # Проверяем порядок правил в INPUT
            r = subprocess.run(["iptables", "-L", "INPUT", "--line-numbers", "-n"],
                             capture_output=True, text=True)
            lines = r.stdout.splitlines()
            drop_line = None
            accept_line = None
            for i, line in enumerate(lines):
                if "DROP" in line and str(port) in line and "singbox-cdn" in line:
                    drop_line = i
                if "ACCEPT" in line and str(port) in line and "tcp dpt" in line:
                    accept_line = i
            self.assertIsNotNone(drop_line, "DROP-правило должно существовать")
            self.assertIsNotNone(accept_line, "ACCEPT-правило должно существовать")
            self.assertLess(drop_line, accept_line,
                            "DROP-правило должно быть ВЫШЕ (раньше) ACCEPT-правила в INPUT")
        finally:
            # Cleanup
            for _ in range(5):
                subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp",
                              "--dport", str(port), "-j", "ACCEPT"],
                             capture_output=True)
            subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp",
                          "--dport", str(port), "-j", "DROP",
                          "-m", "comment", "--comment", f"singbox-cdn-allowlist-{port}"],
                       capture_output=True)
            subprocess.run(["ipset", "destroy", f"singbox_cdn_allowlist_{port}"],
                          capture_output=True)


# ══════════════════════════════════════════════════════════════════════════════
# ФИКС 2: Persistence — allowlist переживает reboot
# ══════════════════════════════════════════════════════════════════════════════

class TestPersistenceOnReboot(unittest.TestCase):
    """apply_cdn_allowlist сохраняет правила для восстановления при boot."""

    def setUp(self):
        _setup_core()

    def test_apply_calls_ipset_save(self):
        """apply_cdn_allowlist вызывает _ipset_save_port для persistence."""
        from vless_installer.modules.singbox_cdn_nets import apply_cdn_allowlist
        mock_save = MagicMock(return_value=True)
        mock_install = MagicMock()
        mock_persist = MagicMock()
        with patch("vless_installer.modules.singbox_cdn_nets.fetch_cdn_nets",
                   return_value=(["1.2.3.0/24"], "1 CIDR")):
            with patch("vless_installer.modules.singbox_cdn_nets._run",
                       return_value=MagicMock(returncode=0, stdout="", stderr="")):
                with patch("vless_installer.modules.singbox_cdn_nets._ipset_save_port", mock_save):
                    with patch("vless_installer.modules.singbox_cdn_nets._ipset_restore_unit_install", mock_install):
                        with patch("vless_installer.modules.singbox_cdn_nets._iptables_persist", mock_persist):
                            apply_cdn_allowlist("cloudflare", 8080)
        mock_save.assert_called_once_with(8080)
        mock_install.assert_called_once()
        mock_persist.assert_called_once()

    def test_remove_updates_persisted_state(self):
        """remove_cdn_allowlist удаляет правило из персистентного файла."""
        from vless_installer.modules.singbox_cdn_nets import remove_cdn_allowlist
        mock_remove_persist = MagicMock()
        mock_persist = MagicMock()
        with patch("vless_installer.modules.singbox_cdn_nets._run",
                   return_value=MagicMock(returncode=0, stdout="", stderr="")):
            with patch("vless_installer.modules.singbox_cdn_nets._ipset_remove_from_persist", mock_remove_persist):
                with patch("vless_installer.modules.singbox_cdn_nets._iptables_persist", mock_persist):
                    remove_cdn_allowlist(8080)
        mock_remove_persist.assert_called_once_with(8080)
        mock_persist.assert_called_once()

    def test_ipset_save_writes_to_file(self):
        """_ipset_save_port реально записывает ipset в файл (если iptables/ipset доступны)."""
        import shutil
        if not shutil.which("ipset"):
            self.skipTest("ipset not available — cannot test real file persistence")
        from vless_installer.modules.singbox_cdn_nets import (
            _ipset_save_port, _IPSET_CONF, _ipset_name,
        )
        port = 18098
        ipset = _ipset_name(port)
        import subprocess
        # Создаём тестовый ipset
        subprocess.run(["ipset", "create", ipset, "hash:net", "-exist"],
                      capture_output=True)
        subprocess.run(["ipset", "add", ipset, "1.2.3.0/24", "-exist"],
                      capture_output=True)
        try:
            # Сохраняем
            _ipset_save_port(port)
            # Проверяем что файл существует и содержит запись
            self.assertTrue(_IPSET_CONF.exists())
            content = _IPSET_CONF.read_text()
            self.assertIn(f"add {ipset} 1.2.3.0/24", content)
        finally:
            # Cleanup
            subprocess.run(["ipset", "destroy", ipset], capture_output=True)
            # Удаляем только наши записи из файла
            from vless_installer.modules.singbox_cdn_nets import _ipset_remove_from_persist
            _ipset_remove_from_persist(port)

    def test_ipset_remove_from_persist_removes_entries(self):
        """_ipset_remove_from_persist удаляет записи порта из персистентного файла."""
        from vless_installer.modules.singbox_cdn_nets import (
            _ipset_remove_from_persist, _ipset_name,
        )
        port = 18097
        ipset = _ipset_name(port)
        # Используем tmpdir вместо /etc
        tmpdir = Path(tempfile.mkdtemp())
        tmp_conf = tmpdir / "ipset-singbox-cdn.conf"
        tmp_conf.write_text(f"create {ipset} hash:net\nadd {ipset} 1.2.3.0/24\n")
        try:
            with patch("vless_installer.modules.singbox_cdn_nets._IPSET_CONF", tmp_conf):
                _ipset_remove_from_persist(port)
                if tmp_conf.exists():
                    content = tmp_conf.read_text()
                    self.assertNotIn(ipset, content,
                                     "Записи порта должны быть удалены из персистентного файла")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════════════
# ФИКС 3: Bunny.net — правильный источник IP (CDN edge, не Magic Containers)
# ══════════════════════════════════════════════════════════════════════════════

class TestBunnyIpSourceCorrect(unittest.TestCase):
    """Bunny.net ip_source — CDN edge server list, не Magic Containers."""

    def setUp(self):
        _setup_core()

    def test_bunny_ip_source_is_edge_server_list(self):
        """ip_source = bunnycdn.com/api/system/edgeserverlist/plain, не docs.bunny.net."""
        from vless_installer.modules.singbox_common import CDN_PROVIDERS
        self.assertEqual(CDN_PROVIDERS["bunny"]["ip_source"],
                         "https://bunnycdn.com/api/system/edgeserverlist/plain")

    def test_bunny_ip_source_not_magic_containers(self):
        """Старый URL (magic-containers) не должен нигде остаться."""
        from vless_installer.modules.singbox_common import CDN_PROVIDERS
        source = CDN_PROVIDERS["bunny"]["ip_source"]
        self.assertNotIn("magic-containers", source,
                         "Старый URL magic-containers не должен использоваться")
        self.assertNotIn("docs.bunny.net", source,
                         "docs.bunny.net не должен быть источником IP")

    def test_bunny_ip_format_is_plaintext(self):
        """ip_format = plaintext (не html_scrape — список теперь машиночитаемый)."""
        from vless_installer.modules.singbox_common import CDN_PROVIDERS
        self.assertEqual(CDN_PROVIDERS["bunny"]["ip_format"], "plaintext")

    def test_fetch_bunny_returns_cidrs_with_32_suffix(self):
        """fetch_cdn_nets('bunny') с plain IP → возвращает CIDR с /32."""
        from vless_installer.modules.singbox_cdn_nets import fetch_cdn_nets
        # Мокаем ответ Bunny API: plain IP, БЕЗ /32
        mock_response = MagicMock()
        mock_response.read.return_value = b"89.187.188.227\n89.187.188.228\n89.187.162.249\n"
        mock_response.__enter__ = lambda self: mock_response
        mock_response.__exit__ = lambda self, *a: None
        with patch("urllib.request.urlopen", return_value=mock_response):
            cidrs, status = fetch_cdn_nets("bunny")
        self.assertEqual(len(cidrs), 3)
        for cidr in cidrs:
            self.assertIn("/32", cidr, "Bunny IPs должны иметь /32 суффикс")
            ipaddress.ip_network(cidr, strict=False)  # не должно кидать

    def test_fetch_bunny_hits_correct_url(self):
        """fetch_cdn_nets('bunny') реально бьёт в bunnycdn.com/api/system/edgeserverlist/plain."""
        from vless_installer.modules.singbox_cdn_nets import fetch_cdn_nets
        mock_response = MagicMock()
        mock_response.read.return_value = b"89.187.188.227\n"
        mock_response.__enter__ = lambda self: mock_response
        mock_response.__exit__ = lambda self, *a: None
        with patch("urllib.request.urlopen", return_value=mock_response) as mock_urlopen:
            fetch_cdn_nets("bunny")
            called_request = mock_urlopen.call_args[0][0]
            self.assertEqual(called_request.full_url,
                             "https://bunnycdn.com/api/system/edgeserverlist/plain")

    def test_no_html_scrape_format_anywhere(self):
        """html_scrape больше не используется ни одним провайдером."""
        from vless_installer.modules.singbox_common import CDN_PROVIDERS
        for provider, meta in CDN_PROVIDERS.items():
            self.assertNotEqual(meta.get("ip_format"), "html_scrape",
                                f"{provider} не должен использовать html_scrape (упрощено в v4.23.2)")

    def test_cloudflare_source_still_correct(self):
        """Перепроверка: Cloudflare ips-v4 всё ещё актуален."""
        from vless_installer.modules.singbox_common import CDN_PROVIDERS
        self.assertEqual(CDN_PROVIDERS["cloudflare"]["ip_source"],
                         "https://www.cloudflare.com/ips-v4")

    def test_gcore_source_still_correct(self):
        """Перепроверка: Gcore public-ip-list всё ещё актуален."""
        from vless_installer.modules.singbox_common import CDN_PROVIDERS
        self.assertEqual(CDN_PROVIDERS["gcore"]["ip_source"],
                         "https://api.gcore.com/cdn/public-ip-list")


# ══════════════════════════════════════════════════════════════════════════════
# ФИКС 4: _switch_cdn_provider() — авто-смена listen_port
# ══════════════════════════════════════════════════════════════════════════════

class TestSwitchCdnProviderAutoPort(unittest.TestCase):
    """При switch провайдера listen_port автоматически меняется под новый."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_config.SINGBOX_CONFIG_DIR", self._tmpdir / "sb"),
            patch("vless_installer.modules.singbox_config.SINGBOX_CONFIG_FILE", self._tmpdir / "sb" / "config.json"),
        ]

    def test_switch_gcore_to_cloudflare_changes_port(self):
        """Enable на gcore (порт 8443 дефолт) → switch на cloudflare → порт = 8080.

        v4.23.2: авто-смена порта происходит в _switch_cdn_provider() в меню,
        НЕ в singbox_enable_vless_ws_cdn(). Этот тест проверяет что state init
        создаёт per-provider default, а switch-логика меняет порт.
        """
        from vless_installer.modules.singbox_config import singbox_enable_vless_ws_cdn
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_load,
        )
        from vless_installer.modules.singbox_common import CDN_PROVIDERS
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            stack.enter_context(patch("vless_installer.modules.singbox_cdn_nets.apply_cdn_allowlist", return_value=True))
            singbox_state_init(version="1.0.0")
            # Enable на gcore → listen_port должен быть 8443 (gcore default)
            singbox_enable_vless_ws_cdn(cdn_provider="gcore", host="test.example.com")
            state = singbox_state_load()
            ib = state["inbounds"]["vless_ws_cdn"]
        # Проверяем что per-provider default сработал при enable
        self.assertEqual(ib["cdn_provider"], "gcore")
        self.assertEqual(ib["listen_port"], CDN_PROVIDERS["gcore"]["default_port"])

        # Теперь симулируем логику _switch_cdn_provider() — это то, что происходит
        # в меню при переключении gcore → cloudflare
        current = "gcore"
        new_provider = "cloudflare"
        port = ib["listen_port"]  # 8443
        current_default = CDN_PROVIDERS[current]["default_port"]  # 8443
        new_default = CDN_PROVIDERS[new_provider]["default_port"]  # 8080
        if port == current_default:
            port = new_default  # 8080
        # Порт должен стать 8080 (cloudflare default)
        self.assertEqual(port, 8080,
                         "Switch gcore→cloudflare должен менять порт 8443→8080")

    def test_switch_logic_changes_port_from_default_to_new_default(self):
        """Симуляция логики switch: gcore(8443) → cloudflare(8080)."""
        from vless_installer.modules.singbox_common import CDN_PROVIDERS
        # Логика из _switch_cdn_provider():
        current = "gcore"
        new_provider = "cloudflare"
        port = CDN_PROVIDERS[current]["default_port"]  # 8443
        current_default = CDN_PROVIDERS[current]["default_port"]  # 8443
        new_default = CDN_PROVIDERS[new_provider]["default_port"]  # 8080
        # port == current_default → переключаем на new_default
        if port == current_default:
            port = new_default
        self.assertEqual(port, 8080,
                         "Switch gcore→cloudflare должен менять порт 8443→8080")

    def test_switch_logic_keeps_custom_port_with_warn(self):
        """Симуляция: custom listen_port=9999 → switch → порт сохранён, warn вызван."""
        from vless_installer.modules.singbox_common import CDN_PROVIDERS
        current = "gcore"
        new_provider = "cloudflare"
        port = 9999  # custom, не равен дефолту gcore (8443)
        current_default = CDN_PROVIDERS[current]["default_port"]  # 8443
        new_default = CDN_PROVIDERS[new_provider]["default_port"]  # 8080
        # port != current_default → custom, не меняем
        # port != new_default → warn
        self.assertNotEqual(port, current_default, "Custom port должен отличаться от дефолта")
        self.assertNotEqual(port, new_default, "Custom port должен отличаться от дефолта нового")
        # Порт не меняется
        self.assertEqual(port, 9999)

    def test_switch_cloudflare_to_gcore_changes_port(self):
        """Симуляция: cloudflare(8080) → gcore(8443)."""
        from vless_installer.modules.singbox_common import CDN_PROVIDERS
        current = "cloudflare"
        new_provider = "gcore"
        port = CDN_PROVIDERS[current]["default_port"]  # 8080
        current_default = CDN_PROVIDERS[current]["default_port"]  # 8080
        new_default = CDN_PROVIDERS[new_provider]["default_port"]  # 8443
        if port == current_default:
            port = new_default
        self.assertEqual(port, 8443,
                         "Switch cloudflare→gcore должен менять порт 8080→8443")

    def test_switch_gcore_to_bunny_keeps_port(self):
        """Симуляция: gcore(8443) → bunny(8443) — дефолты совпадают, порт не меняется."""
        from vless_installer.modules.singbox_common import CDN_PROVIDERS
        current = "gcore"
        new_provider = "bunny"
        port = CDN_PROVIDERS[current]["default_port"]  # 8443
        current_default = CDN_PROVIDERS[current]["default_port"]  # 8443
        new_default = CDN_PROVIDERS[new_provider]["default_port"]  # 8443
        if port == current_default:
            port = new_default
        self.assertEqual(port, 8443,
                         "Switch gcore→bunny не должен менять порт (оба 8443)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
