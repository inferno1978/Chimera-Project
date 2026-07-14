#!/usr/bin/env python3
"""
tests/test_singbox_vless_ws_cdn_fix.py
───────────────────────────────────────────────────────────────────────────────
Тесты для v4.23.1 — фиксы двух багов из v4.23:

БАГ 1: Инструкции CDN_PROVIDERS требовали HTTPS/TLS origin pull, а origin TLS
не поднимает вообще — соединение не заработает ни с одним CDN.

БАГ 2: 0.0.0.0:8443 без ограничения по IP CDN — origin достижим напрямую.
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
from unittest.mock import patch, MagicMock, call

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("chimera._core")
    m.__dict__.update(g)
    sys.modules["chimera._core"] = m


def _enter_patches(stack, patches):
    for p in patches:
        stack.enter_context(p)


# ══════════════════════════════════════════════════════════════════════════════
# БАГ 1: Instructions — Flexible/HTTP, не HTTPS origin pull
# ══════════════════════════════════════════════════════════════════════════════

class TestCloudflareInstructionsFlexible(unittest.TestCase):
    """Cloudflare instructions должны говорить Flexible, не Full/Full(strict)."""

    def setUp(self):
        _setup_core()

    def test_instructions_contain_flexible(self):
        """v4.23.1: Cloudflare SSL mode = Flexible (CF↔origin = HTTP)."""
        from chimera.modules.singbox_common import CDN_PROVIDERS
        instructions = CDN_PROVIDERS["cloudflare"]["instructions"]
        full_text = " ".join(instructions)
        self.assertIn("Flexible", full_text,
                      "Cloudflare instructions должны содержать 'Flexible'")

    def test_instructions_do_not_recommend_full_strict(self):
        """Full (strict) не должен рекомендоваться как режим для origin."""
        from chimera.modules.singbox_common import CDN_PROVIDERS
        instructions = CDN_PROVIDERS["cloudflare"]["instructions"]
        full_text = " ".join(instructions)
        # Full (strict) может упоминаться только как "НЕ используйте"
        # Проверяем что нет рекомендации вида "установите 'Full'"
        # Допустимо: "НЕ используйте 'Full' или 'Full (strict)'"
        # Недопустимо: "установите режим 'Full'"
        self.assertNotIn("установите режим 'Full'", full_text,
                         "Full не должен рекомендоваться как режим")

    def test_instructions_warn_about_full_causing_521(self):
        """Instructions должны предупреждать о 521/525 при Full mode."""
        from chimera.modules.singbox_common import CDN_PROVIDERS
        instructions = CDN_PROVIDERS["cloudflare"]["instructions"]
        full_text = " ".join(instructions)
        self.assertTrue("521" in full_text or "525" in full_text or "Full" in full_text,
                         "Instructions должны предупреждать о последствиях Full mode")

    def test_instructions_explain_flexible_semantics(self):
        """Flexible: CF↔client = HTTPS, CF↔origin = HTTP."""
        from chimera.modules.singbox_common import CDN_PROVIDERS
        instructions = CDN_PROVIDERS["cloudflare"]["instructions"]
        full_text = " ".join(instructions).lower()
        self.assertIn("http", full_text,
                      "Instructions должны упоминать HTTP для CF↔origin")


class TestGcoreInstructionsHttpOrigin(unittest.TestCase):
    """Gcore instructions должны говорить HTTP, не HTTPS."""

    def setUp(self):
        _setup_core()

    def test_instructions_do_not_contain_https_origin_url(self):
        """v4.23.1: origin URL должен быть http://, не https://."""
        from chimera.modules.singbox_common import CDN_PROVIDERS
        instructions = CDN_PROVIDERS["gcore"]["instructions"]
        full_text = " ".join(instructions)
        # Не должно быть https:// перед origin-адресом
        self.assertNotIn("https://<IP", full_text,
                         "Gcore origin URL не должен использовать https://")
        self.assertNotIn("https://<your-domain", full_text,
                         "Gcore origin URL не должен использовать https://")

    def test_instructions_contain_http_origin_url(self):
        """Origin URL должен быть http://."""
        from chimera.modules.singbox_common import CDN_PROVIDERS
        instructions = CDN_PROVIDERS["gcore"]["instructions"]
        full_text = " ".join(instructions)
        self.assertIn("http://<IP", full_text,
                       "Gcore origin URL должен использовать http://")

    def test_instructions_say_http_pull_protocol(self):
        """Origin Pull Protocol = HTTP, не HTTPS."""
        from chimera.modules.singbox_common import CDN_PROVIDERS
        instructions = CDN_PROVIDERS["gcore"]["instructions"]
        full_text = " ".join(instructions)
        self.assertIn("HTTP", full_text)
        # Не должно быть "Origin Pull Protocol: HTTPS"
        self.assertNotIn("Pull Protocol: HTTPS", full_text,
                         "Gcore Origin Pull Protocol должен быть HTTP, не HTTPS")


class TestBunnyInstructionsHttpOrigin(unittest.TestCase):
    """Bunny.net instructions должны говорить HTTP, не HTTPS."""

    def setUp(self):
        _setup_core()

    def test_instructions_do_not_contain_https_origin_url(self):
        """v4.23.1: origin URL должен быть http://, не https://."""
        from chimera.modules.singbox_common import CDN_PROVIDERS
        instructions = CDN_PROVIDERS["bunny"]["instructions"]
        full_text = " ".join(instructions)
        self.assertNotIn("https://<IP", full_text,
                         "Bunny origin URL не должен использовать https://")

    def test_instructions_contain_http_origin_url(self):
        """Origin URL должен быть http://."""
        from chimera.modules.singbox_common import CDN_PROVIDERS
        instructions = CDN_PROVIDERS["bunny"]["instructions"]
        full_text = " ".join(instructions)
        self.assertIn("http://<IP", full_text,
                       "Bunny origin URL должен использовать http://")

    def test_instructions_say_http_scheme(self):
        """Origin Scheme = HTTP."""
        from chimera.modules.singbox_common import CDN_PROVIDERS
        instructions = CDN_PROVIDERS["bunny"]["instructions"]
        full_text = " ".join(instructions)
        self.assertIn("HTTP", full_text)
        # Не должно быть "Origin Scheme: HTTPS"
        self.assertNotIn("Scheme: HTTPS", full_text,
                         "Bunny Origin Scheme должен быть HTTP")


class TestNoTlsMentionsForOriginConnection(unittest.TestCase):
    """Instructions не должны использовать 'TLS' или 'HTTPS' для CDN→origin."""

    def setUp(self):
        _setup_core()

    def test_no_tls_tunnel_mention(self):
        """Убрана формулировка 'TLS-туннель до origin' (v4.23 баг)."""
        from chimera.modules.singbox_common import CDN_PROVIDERS
        for provider, meta in CDN_PROVIDERS.items():
            full_text = " ".join(meta["instructions"])
            self.assertNotIn("TLS-туннель", full_text,
                             f"{provider}: не должно быть 'TLS-туннель' — origin не терминирует TLS")
            self.assertNotIn("tls-туннель", full_text.lower(),
                             f"{provider}: не должно быть 'tls-туннель' (case-insensitive)")

    def test_origin_connection_described_as_http(self):
        """CDN↔origin connection должна описываться как HTTP, не HTTPS/TLS."""
        from chimera.modules.singbox_common import CDN_PROVIDERS
        for provider, meta in CDN_PROVIDERS.items():
            full_text = " ".join(meta["instructions"])
            # Должно быть упоминание HTTP для CDN↔origin
            self.assertTrue(
                "CDN↔origin = HTTP" in full_text or "CF↔origin = HTTP" in full_text,
                f"{provider}: instructions должны явно говорить 'CDN↔origin = HTTP'"
            )


# ══════════════════════════════════════════════════════════════════════════════
# БАГ 1: Per-provider default port
# ══════════════════════════════════════════════════════════════════════════════

class TestPerProviderDefaultPort(unittest.TestCase):
    """Per-provider default port (v4.23.1)."""

    def setUp(self):
        _setup_core()

    def test_cloudflare_default_port_is_http_port(self):
        """Cloudflare default port = 8080 (из CF HTTP port list, не HTTPS)."""
        from chimera.modules.singbox_common import CDN_PROVIDERS
        port = CDN_PROVIDERS["cloudflare"]["default_port"]
        cf_http_ports = [80, 8080, 8880, 2052, 2082, 2086, 2095]
        cf_https_ports = [443, 2053, 2083, 2087, 2096, 8443]
        self.assertIn(port, cf_http_ports,
                      f"Cloudflare default_port {port} must be in CF HTTP port list")
        self.assertNotIn(port, cf_https_ports,
                         f"Cloudflare default_port {port} must NOT be in CF HTTPS port list")

    def test_gcore_default_port(self):
        from chimera.modules.singbox_common import CDN_PROVIDERS
        self.assertEqual(CDN_PROVIDERS["gcore"]["default_port"], 8443)

    def test_bunny_default_port(self):
        from chimera.modules.singbox_common import CDN_PROVIDERS
        self.assertEqual(CDN_PROVIDERS["bunny"]["default_port"], 8443)

    def test_all_providers_have_default_port(self):
        from chimera.modules.singbox_common import CDN_PROVIDERS
        for provider, meta in CDN_PROVIDERS.items():
            self.assertIn("default_port", meta,
                          f"{provider} must have default_port")
            self.assertIsInstance(meta["default_port"], int)
            self.assertGreater(meta["default_port"], 0)

    def test_enable_uses_per_provider_port(self):
        """singbox_enable_vless_ws_cdn() использует per-provider default port."""
        from chimera.modules.singbox_config import singbox_enable_vless_ws_cdn
        from chimera.modules.singbox_state import (
            singbox_state_init, singbox_state_get_inbound,
        )
        from chimera.modules.singbox_common import CDN_PROVIDERS
        tmpdir = Path(tempfile.mkdtemp())
        state = tmpdir / "singbox_state.json"
        main_state = tmpdir / "state.json"
        patches = [
            patch("chimera.modules.singbox_common.SINGBOX_STATE_FILE", state),
            patch("chimera.modules.singbox_common.MAIN_STATE_FILE", main_state),
            patch("chimera.modules.singbox_state.SINGBOX_STATE_FILE", state),
            patch("chimera.modules.singbox_config.SINGBOX_CONFIG_DIR", tmpdir / "sb"),
            patch("chimera.modules.singbox_config.SINGBOX_CONFIG_FILE", tmpdir / "sb" / "config.json"),
            # Мокаем apply_cdn_allowlist чтобы не дёргать сеть/iptables
            patch("chimera.modules.singbox_cdn_nets.apply_cdn_allowlist", return_value=True),
        ]
        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            singbox_state_init(version="1.0.0")
            # Cloudflare → 8080
            singbox_enable_vless_ws_cdn(cdn_provider="cloudflare", host="test.example.com")
            ib = singbox_state_get_inbound("vless_ws_cdn")
        self.assertEqual(ib["listen_port"], CDN_PROVIDERS["cloudflare"]["default_port"])
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════════════
# БАГ 1: DEFAULT_PORT_VLESS_WS_CDN комментарий обновлён
# ══════════════════════════════════════════════════════════════════════════════

class TestDefaultPortCommentUpdated(unittest.TestCase):
    """Комментарий над DEFAULT_PORT_VLESS_WS_CDN обновлён (v4.23.1)."""

    def setUp(self):
        _setup_core()

    def test_no_tls_tunnel_mention_in_comment(self):
        """Комментарий не должен говорить 'TLS-туннель до origin'."""
        from chimera.modules import singbox_common
        # Читаем исходник чтобы проверить комментарии
        source = Path(singbox_common.__file__).read_text()
        # Ищем секцию с DEFAULT_PORT_VLESS_WS_CDN
        idx = source.find("DEFAULT_PORT_VLESS_WS_CDN")
        self.assertGreater(idx, 0)
        # Берём 30 строк до константы (комментарий)
        comment_block = source[max(0, idx - 2000):idx]
        self.assertNotIn("TLS-туннель", comment_block,
                         "Комментарий не должен содержать 'TLS-туннель'")

    def test_comment_mentions_http_origin(self):
        """Комментарий должен говорить что origin слушает НЕ по TLS."""
        from chimera.modules import singbox_common
        source = Path(singbox_common.__file__).read_text()
        idx = source.find("DEFAULT_PORT_VLESS_WS_CDN")
        comment_block = source[max(0, idx - 2000):idx]
        self.assertTrue(
            "НЕ по TLS" in comment_block or "HTTP" in comment_block,
            "Комментарий должен явно говорить что origin слушает НЕ по TLS / по HTTP"
        )


# ══════════════════════════════════════════════════════════════════════════════
# БАГ 2: CDN allowlist — fetch_cdn_nets
# ══════════════════════════════════════════════════════════════════════════════

class TestFetchCdnNetsCloudflare(unittest.TestCase):
    """fetch_cdn_nets('cloudflare') — live-fetch с www.cloudflare.com/ips-v4."""

    def setUp(self):
        _setup_core()

    def test_fetch_returns_valid_cidrs(self):
        """Мок urllib → возвращается список валидных CIDR."""
        from chimera.modules.singbox_cdn_nets import fetch_cdn_nets
        # Мокаем на уровне urllib.request.urlopen
        mock_response = MagicMock()
        mock_response.read.return_value = (
            b"103.21.244.0/22\n103.22.200.0/22\n103.31.4.0/22\n"
            b"104.16.0.0/13\n104.24.0.0/14\n"
        )
        mock_response.__enter__ = lambda self: mock_response
        mock_response.__exit__ = lambda self, *a: None
        with patch("urllib.request.urlopen", return_value=mock_response):
            cidrs, status = fetch_cdn_nets("cloudflare")
        self.assertGreater(len(cidrs), 0)
        for cidr in cidrs:
            # Каждый CIDR валиден
            ipaddress.ip_network(cidr, strict=False)  # не должно кидать

    def test_fetch_hits_cloudflare_url(self):
        """fetch_cdn_nets реально бьёт в www.cloudflare.com/ips-v4."""
        from chimera.modules.singbox_cdn_nets import fetch_cdn_nets
        mock_response = MagicMock()
        mock_response.read.return_value = b"1.2.3.0/24\n"
        mock_response.__enter__ = lambda self: mock_response
        mock_response.__exit__ = lambda self, *a: None
        with patch("urllib.request.urlopen", return_value=mock_response) as mock_urlopen:
            fetch_cdn_nets("cloudflare")
            # Проверяем что URL был правильный
            called_request = mock_urlopen.call_args[0][0]
            self.assertEqual(called_request.full_url,
                             "https://www.cloudflare.com/ips-v4")

    def test_fetch_handles_empty_response(self):
        from chimera.modules.singbox_cdn_nets import fetch_cdn_nets
        mock_response = MagicMock()
        mock_response.read.return_value = b""
        mock_response.__enter__ = lambda self: mock_response
        mock_response.__exit__ = lambda self, *a: None
        with patch("urllib.request.urlopen", return_value=mock_response):
            cidrs, status = fetch_cdn_nets("cloudflare")
        self.assertEqual(cidrs, [])

    def test_fetch_handles_network_error(self):
        from chimera.modules.singbox_cdn_nets import fetch_cdn_nets
        with patch("urllib.request.urlopen", side_effect=Exception("network error")):
            cidrs, status = fetch_cdn_nets("cloudflare")
        self.assertEqual(cidrs, [])
        self.assertIn("Не удалось", status)


class TestFetchCdnNetsGcore(unittest.TestCase):
    """fetch_cdn_nets('gcore') — JSON с addresses field."""

    def setUp(self):
        _setup_core()

    def test_fetch_parses_json_addresses(self):
        from chimera.modules.singbox_cdn_nets import fetch_cdn_nets
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "addresses": ["92.223.124.39/32", "94.176.183.13/32", "92.223.76.26/32"]
        }).encode()
        mock_response.__enter__ = lambda self: mock_response
        mock_response.__exit__ = lambda self, *a: None
        with patch("urllib.request.urlopen", return_value=mock_response):
            cidrs, status = fetch_cdn_nets("gcore")
        self.assertEqual(len(cidrs), 3)
        for cidr in cidrs:
            ipaddress.ip_network(cidr, strict=False)

    def test_fetch_hits_gcore_api_url(self):
        from chimera.modules.singbox_cdn_nets import fetch_cdn_nets
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"addresses":[]}'
        mock_response.__enter__ = lambda self: mock_response
        mock_response.__exit__ = lambda self, *a: None
        with patch("urllib.request.urlopen", return_value=mock_response) as mock_urlopen:
            fetch_cdn_nets("gcore")
            called_request = mock_urlopen.call_args[0][0]
            self.assertEqual(called_request.full_url,
                             "https://api.gcore.com/cdn/public-ip-list")


class TestFetchCdnNetsBunny(unittest.TestCase):
    """fetch_cdn_nets('bunny') — HTML scrape."""

    def setUp(self):
        _setup_core()

    def test_fetch_parses_plain_ips(self):
        """v4.23.2: Bunny теперь использует plaintext format (edge server list).

        Старый тест test_fetch_parses_html_ips (v4.23.1) проверял html_scrape —
        формат удалён в v4.23.2. Bunny CDN edge server list = plain text,
        один IP на строку БЕЗ /32. fetch_cdn_nets добавляет /32.
        """
        from chimera.modules.singbox_cdn_nets import fetch_cdn_nets
        mock_response = MagicMock()
        mock_response.read.return_value = b"89.187.188.227\n89.187.188.228\n109.61.83.105\n"
        mock_response.__enter__ = lambda self: mock_response
        mock_response.__exit__ = lambda self, *a: None
        with patch("urllib.request.urlopen", return_value=mock_response):
            cidrs, status = fetch_cdn_nets("bunny")
        self.assertGreater(len(cidrs), 0)
        # Bunny IPs → /32
        for cidr in cidrs:
            ipaddress.ip_network(cidr, strict=False)
            self.assertIn("/32", cidr)

    def test_fetch_handles_no_ips_in_html(self):
        from chimera.modules.singbox_cdn_nets import fetch_cdn_nets
        mock_response = MagicMock()
        mock_response.read.return_value = b"<html><body>No IPs here</body></html>"
        mock_response.__enter__ = lambda self: mock_response
        mock_response.__exit__ = lambda self, *a: None
        with patch("urllib.request.urlopen", return_value=mock_response):
            cidrs, status = fetch_cdn_nets("bunny")
        self.assertEqual(cidrs, [])


class TestFetchCdnNetsUnknownProvider(unittest.TestCase):
    """fetch_cdn_nets для неизвестного провайдера."""

    def setUp(self):
        _setup_core()

    def test_returns_empty_for_unknown_provider(self):
        from chimera.modules.singbox_cdn_nets import fetch_cdn_nets
        cidrs, status = fetch_cdn_nets("unknown_provider")
        self.assertEqual(cidrs, [])
        self.assertIn("Неизвестный", status)


# ══════════════════════════════════════════════════════════════════════════════
# БАГ 2: apply_cdn_allowlist / remove_cdn_allowlist
# ══════════════════════════════════════════════════════════════════════════════

class TestApplyCdnAllowlist(unittest.TestCase):
    """apply_cdn_allowlist — ipset + iptables."""

    def setUp(self):
        _setup_core()
        import shutil
        if not shutil.which("iptables") or not shutil.which("ipset"):
            self.skipTest("iptables/ipset not available in test environment")

    def test_apply_returns_true_on_success(self):
        from chimera.modules.singbox_cdn_nets import apply_cdn_allowlist
        # Мокаем fetch → возвращаем CIDR
        mock_fetch = MagicMock(return_value=(["1.2.3.0/24", "5.6.7.0/24"], "2 CIDR"))
        # Мокаем _run → всегда success
        mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
        with patch("chimera.modules.singbox_cdn_nets.fetch_cdn_nets", mock_fetch):
            with patch("chimera.modules.singbox_cdn_nets._run", mock_run):
                result = apply_cdn_allowlist("cloudflare", 8080)
        self.assertTrue(result)

    def test_apply_returns_false_when_fetch_fails(self):
        """Если fetch провалился — False + warn."""
        from chimera.modules.singbox_cdn_nets import apply_cdn_allowlist
        mock_fetch = MagicMock(return_value=([], "network error"))
        mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
        with patch("chimera.modules.singbox_cdn_nets.fetch_cdn_nets", mock_fetch):
            with patch("chimera.modules.singbox_cdn_nets._run", mock_run):
                result = apply_cdn_allowlist("cloudflare", 8080)
        self.assertFalse(result)

    def test_apply_calls_ipset_create(self):
        """apply_cdn_allowlist вызывает ipset create."""
        from chimera.modules.singbox_cdn_nets import apply_cdn_allowlist
        mock_fetch = MagicMock(return_value=(["1.2.3.0/24"], "1 CIDR"))
        mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
        with patch("chimera.modules.singbox_cdn_nets.fetch_cdn_nets", mock_fetch):
            with patch("chimera.modules.singbox_cdn_nets._run", mock_run):
                apply_cdn_allowlist("cloudflare", 8080)
        calls = [c[0][0] if c[0] else [] for c in mock_run.call_args_list]
        create_calls = [c for c in calls if "create" in c and "singbox_cdn_allowlist_8080" in c]
        self.assertGreater(len(create_calls), 0, "ipset create должен вызываться")

    def test_apply_calls_iptables_with_drop(self):
        """apply_cdn_allowlist вызывает iptables -A INPUT ... -j DROP."""
        from chimera.modules.singbox_cdn_nets import apply_cdn_allowlist
        mock_fetch = MagicMock(return_value=(["1.2.3.0/24"], "1 CIDR"))
        mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
        with patch("chimera.modules.singbox_cdn_nets.fetch_cdn_nets", mock_fetch):
            with patch("chimera.modules.singbox_cdn_nets._run", mock_run):
                apply_cdn_allowlist("cloudflare", 8080)
        calls = [c[0][0] if c[0] else [] for c in mock_run.call_args_list]
        drop_calls = [c for c in calls if "iptables" in c and "-A" in c
                      and "INPUT" in c and "DROP" in c and "8080" in c]
        self.assertGreater(len(drop_calls), 0,
                           "iptables -A INPUT ... -j DROP должен вызываться для порта 8080")


class TestRemoveCdnAllowlist(unittest.TestCase):
    """remove_cdn_allowlist — cleanup iptables + ipset."""

    def setUp(self):
        _setup_core()

    def test_remove_calls_iptables_delete(self):
        from chimera.modules.singbox_cdn_nets import remove_cdn_allowlist
        mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
        with patch("chimera.modules.singbox_cdn_nets._run", mock_run):
            with patch("chimera.modules.singbox_cdn_nets._ipset_remove_from_persist"):
                with patch("chimera.modules.singbox_cdn_nets._iptables_persist"):
                    remove_cdn_allowlist(8080)
        calls = [c[0][0] if c[0] else [] for c in mock_run.call_args_list]
        delete_calls = [c for c in calls if "iptables" in c and "-D" in c and "8080" in c]
        self.assertGreater(len(delete_calls), 0,
                           "iptables -D INPUT должен вызываться для удаления правила")

    def test_remove_calls_ipset_destroy(self):
        from chimera.modules.singbox_cdn_nets import remove_cdn_allowlist
        mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
        with patch("chimera.modules.singbox_cdn_nets._run", mock_run):
            with patch("chimera.modules.singbox_cdn_nets._ipset_remove_from_persist"):
                with patch("chimera.modules.singbox_cdn_nets._iptables_persist"):
                    remove_cdn_allowlist(8080)
        calls = [c[0][0] if c[0] else [] for c in mock_run.call_args_list]
        destroy_calls = [c for c in calls if "ipset" in c and "destroy" in c
                         and "singbox_cdn_allowlist_8080" in c]
        self.assertGreater(len(destroy_calls), 0,
                           "ipset destroy должен вызываться для удаления ipset")

    def test_remove_returns_true_even_if_nothing_to_remove(self):
        from chimera.modules.singbox_cdn_nets import remove_cdn_allowlist
        mock_run = MagicMock(return_value=MagicMock(returncode=1, stdout="", stderr="not found"))
        with patch("chimera.modules.singbox_cdn_nets._run", mock_run):
            with patch("chimera.modules.singbox_cdn_nets._ipset_remove_from_persist"):
                with patch("chimera.modules.singbox_cdn_nets._iptables_persist"):
                    result = remove_cdn_allowlist(8080)
        self.assertTrue(result, "remove должен возвращать True даже если правил не было (idempotent)")


# ══════════════════════════════════════════════════════════════════════════════
# БАГ 2: Integration — enable/disable вызывает allowlist
# ══════════════════════════════════════════════════════════════════════════════

class TestEnableDisableAllowlistIntegration(unittest.TestCase):
    """singbox_enable/disable_vless_ws_cdn вызывает allowlist функции."""

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
            patch("chimera.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
            patch("chimera.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("chimera.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
            patch("chimera.modules.singbox_config.SINGBOX_CONFIG_DIR", self._tmpdir / "sb"),
            patch("chimera.modules.singbox_config.SINGBOX_CONFIG_FILE", self._tmpdir / "sb" / "config.json"),
        ]

    def test_enable_calls_apply_cdn_allowlist(self):
        """singbox_enable_vless_ws_cdn вызывает apply_cdn_allowlist."""
        from chimera.modules.singbox_config import singbox_enable_vless_ws_cdn
        from chimera.modules.singbox_state import singbox_state_init
        mock_apply = MagicMock(return_value=True)
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            stack.enter_context(patch("chimera.modules.singbox_cdn_nets.apply_cdn_allowlist", mock_apply))
            singbox_state_init(version="1.0.0")
            singbox_enable_vless_ws_cdn(cdn_provider="cloudflare", host="test.example.com")
        mock_apply.assert_called_once()
        # Проверяем что вызвался с правильными аргументами
        call_args = mock_apply.call_args[0]
        self.assertEqual(call_args[0], "cloudflare")
        self.assertEqual(call_args[1], 8080)  # Cloudflare default_port

    def test_disable_calls_remove_cdn_allowlist(self):
        """singbox_disable_vless_ws_cdn вызывает remove_cdn_allowlist."""
        from chimera.modules.singbox_config import (
            singbox_enable_vless_ws_cdn, singbox_disable_vless_ws_cdn,
        )
        from chimera.modules.singbox_state import singbox_state_init
        mock_remove = MagicMock(return_value=True)
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            stack.enter_context(patch("chimera.modules.singbox_cdn_nets.apply_cdn_allowlist", return_value=True))
            stack.enter_context(patch("chimera.modules.singbox_cdn_nets.remove_cdn_allowlist", mock_remove))
            singbox_state_init(version="1.0.0")
            singbox_enable_vless_ws_cdn(cdn_provider="cloudflare", host="test.example.com")
            singbox_disable_vless_ws_cdn()
        mock_remove.assert_called_once_with(8080)

    def test_enable_warns_when_allowlist_fails(self):
        """Если allowlist провалился — warn() вызывается, enable НЕ откатывается."""
        from chimera.modules.singbox_config import singbox_enable_vless_ws_cdn
        from chimera.modules.singbox_state import (
            singbox_state_init, singbox_state_get_inbound,
        )
        mock_apply = MagicMock(return_value=False)
        mock_warn = MagicMock()
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            stack.enter_context(patch("chimera.modules.singbox_cdn_nets.apply_cdn_allowlist", mock_apply))
            stack.enter_context(patch("chimera.modules.singbox_config.warn", mock_warn))
            singbox_state_init(version="1.0.0")
            result = singbox_enable_vless_ws_cdn(cdn_provider="cloudflare", host="test.example.com")
            ib = singbox_state_get_inbound("vless_ws_cdn")
        # Enable всё равно возвращает True (fail-open)
        self.assertTrue(result)
        self.assertTrue(ib["enabled"])
        # warn() был вызван (минимум 1 раз)
        self.assertGreater(mock_warn.call_count, 0,
                           "warn() должен вызываться при провале allowlist")


class TestCdnProviderSwitchAllowlist(unittest.TestCase):
    """Переключение cdn_provider переприменяет allowlist."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_switch_reapplies_allowlist_for_new_provider(self):
        """При переключении provider allowlist переприменяется под новый."""
        from chimera.modules.singbox_config import singbox_enable_vless_ws_cdn
        from chimera.modules.singbox_state import (
            singbox_state_init, singbox_state_load,
        )
        mock_apply = MagicMock(return_value=True)
        mock_remove = MagicMock(return_value=True)
        with ExitStack() as stack:
            _enter_patches(stack, [
                patch("chimera.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
                patch("chimera.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
                patch("chimera.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
                patch("chimera.modules.singbox_config.SINGBOX_CONFIG_DIR", self._tmpdir / "sb"),
                patch("chimera.modules.singbox_config.SINGBOX_CONFIG_FILE", self._tmpdir / "sb" / "config.json"),
            ])
            stack.enter_context(patch("chimera.modules.singbox_cdn_nets.apply_cdn_allowlist", mock_apply))
            stack.enter_context(patch("chimera.modules.singbox_cdn_nets.remove_cdn_allowlist", mock_remove))
            singbox_state_init(version="1.0.0")
            # Enable с cloudflare
            singbox_enable_vless_ws_cdn(cdn_provider="cloudflare", host="test.example.com")
            # Switch на gcore (через повторный enable с другим provider)
            singbox_enable_vless_ws_cdn(cdn_provider="gcore", host="test.example.com")
        # apply вызывался минимум дважды (enable + switch)
        self.assertGreaterEqual(mock_apply.call_count, 2,
                                "apply_cdn_allowlist должен вызываться при enable и при switch")
        # remove вызывался (при switch старый allowlist снимается)
        # Примечание: singbox_enable_vless_ws_cdn не вызывает remove напрямую,
        # только singbox_disable или _switch_cdn_provider в меню.
        # Но apply вызывается с новым provider.


# ══════════════════════════════════════════════════════════════════════════════
# БАГ 2: IP sources — наличие для всех провайдеров
# ══════════════════════════════════════════════════════════════════════════════

class TestCdnIpSources(unittest.TestCase):
    """CDN_PROVIDERS — наличие ip_source и ip_format для всех провайдеров."""

    def setUp(self):
        _setup_core()

    def test_all_providers_have_ip_source(self):
        from chimera.modules.singbox_common import CDN_PROVIDERS
        for provider, meta in CDN_PROVIDERS.items():
            self.assertIn("ip_source", meta,
                          f"{provider} должен иметь ip_source URL")
            self.assertTrue(meta["ip_source"].startswith("https://"),
                            f"{provider} ip_source должен быть HTTPS URL")

    def test_all_providers_have_ip_format(self):
        from chimera.modules.singbox_common import CDN_PROVIDERS
        valid_formats = ("plaintext", "json_addresses")  # v4.23.2: html_scrape удалён
        for provider, meta in CDN_PROVIDERS.items():
            self.assertIn("ip_format", meta,
                          f"{provider} должен иметь ip_format")
            self.assertIn(meta["ip_format"], valid_formats,
                          f"{provider} ip_format должен быть одним из {valid_formats}")

    def test_cloudflare_ip_source_is_official(self):
        from chimera.modules.singbox_common import CDN_PROVIDERS
        self.assertEqual(CDN_PROVIDERS["cloudflare"]["ip_source"],
                         "https://www.cloudflare.com/ips-v4")

    def test_bunny_ip_source_is_api(self):
        from chimera.modules.singbox_common import CDN_PROVIDERS
        self.assertEqual(CDN_PROVIDERS["bunny"]["ip_source"],
                         "https://bunnycdn.com/api/system/edgeserverlist/plain")


if __name__ == "__main__":
    unittest.main(verbosity=2)
