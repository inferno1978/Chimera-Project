#!/usr/bin/env python3
"""
tests/test_speed_test_cf_doh.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для DoH-резолва speed.cloudflare.com в speed-test функциях.

Покрывает:
  1. _cf_resolve_ip — DoH-резолв через _resolve_host_fresh.
  2. _cf_probe_available — probe с --resolve в curl.
  3. _speed_test_download — download с --resolve в curl.
  4. Регрессия: после фикса DNS-leak серверный DNS на 127.0.0.1 (DNSCrypt),
     но speed test всё равно работает через DoH + --resolve.

Все внешние команды (curl, _resolve_host_fresh) мокаются.

ВАЖНО: функции _speed_test_download / _cf_probe_available / _cf_resolve_ip
берут _run из globals g (exec'ed _core.py), а не из fake_core.__dict__.
Патчить нужно g['_run'] через patch.dict — см. test_core_dns_redirect_integration.py
для того же паттерна.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Фейковый chimera._core (как в test_chain_nodes.py)."""
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
    return fake_core, g


def _make_completed(rc=0, stdout="", stderr=""):
    return MagicMock(returncode=rc, stdout=stdout, stderr=stderr)


class _BaseTest(unittest.TestCase):
    def setUp(self):
        self._fake_core, self._g = _setup_core_in_sysmodules()


def _patch_doh(return_value):
    """Патчит chain_nodes._resolve_host_fresh."""
    from chimera.modules import chain_nodes
    return patch.object(chain_nodes, "_resolve_host_fresh", return_value=return_value)


# ══════════════════════════════════════════════════════════════════════════════
#  _cf_resolve_ip — DoH-резолв speed.cloudflare.com
# ══════════════════════════════════════════════════════════════════════════════
class TestCfResolveIp(_BaseTest):
    """_cf_resolve_ip: DoH-резолв через _resolve_host_fresh."""

    def test_returns_ip_from_doh(self):
        """DoH отдаёт IP → возвращается IP-строка."""
        with _patch_doh("104.16.0.1"):
            result = self._g["_cf_resolve_ip"]()
        self.assertEqual(result, "104.16.0.1")

    def test_returns_none_on_doh_failure(self):
        """DoH упал → None (caller использует fallback)."""
        from chimera.modules import chain_nodes
        with patch.object(chain_nodes, "_resolve_host_fresh",
                          side_effect=Exception("DoH timeout")):
            result = self._g["_cf_resolve_ip"]()
        self.assertIsNone(result)


# ══════════════════════════════════════════════════════════════════════════════
#  _cf_probe_available — probe с --resolve
# ══════════════════════════════════════════════════════════════════════════════
class TestCfProbeAvailable(_BaseTest):
    """_cf_probe_available: probe Cloudflare через DoH + --resolve."""

    def test_returns_true_when_cf_available_with_doh(self):
        """Cloudflare доступен, DoH отдал IP → True.
        Проверяем, что --resolve передаётся в curl.
        """
        captured_cmd = []
        def tracking_run(cmd, *args, **kwargs):
            captured_cmd.append(cmd)
            return _make_completed(rc=0, stdout="1048576\n")
        with _patch_doh("104.16.0.1"), \
             patch.dict(self._g, {"_run": tracking_run}):
            result = self._g["_cf_probe_available"]()
        self.assertTrue(result)
        # curl должен получить --resolve speed.cloudflare.com:443:104.16.0.1
        self.assertTrue(len(captured_cmd) == 1, f"ожидали 1 вызов _run, получили {len(captured_cmd)}")
        cmd = captured_cmd[0]
        self.assertIn("--resolve", cmd)
        self.assertIn("speed.cloudflare.com:443:104.16.0.1", cmd)

    def test_returns_true_when_cf_available_without_doh(self):
        """DoH не сработал, но Cloudflare доступен через системный DNS → True.
        Fallback: curl без --resolve.
        """
        captured_cmd = []
        def tracking_run(cmd, *args, **kwargs):
            captured_cmd.append(cmd)
            return _make_completed(rc=0, stdout="1048576\n")
        with _patch_doh(None), \
             patch.dict(self._g, {"_run": tracking_run}):
            result = self._g["_cf_probe_available"]()
        self.assertTrue(result)
        # curl НЕ получил --resolve
        cmd = captured_cmd[0]
        self.assertNotIn("--resolve", cmd)

    def test_returns_false_when_cf_unavailable(self):
        """Cloudflare недоступен (curl rc!=0) → False."""
        with _patch_doh("104.16.0.1"), \
             patch.dict(self._g, {"_run":
                 lambda *a, **kw: _make_completed(rc=6, stdout="0\n")}):
            result = self._g["_cf_probe_available"]()
        self.assertFalse(result)

    def test_returns_false_when_size_too_small(self):
        """Cloudflare вернул <500KB → False (считаем недоступным)."""
        with _patch_doh("104.16.0.1"), \
             patch.dict(self._g, {"_run":
                 lambda *a, **kw: _make_completed(rc=0, stdout="1024\n")}):
            result = self._g["_cf_probe_available"]()
        self.assertFalse(result)


# ══════════════════════════════════════════════════════════════════════════════
#  _speed_test_download — download с --resolve
# ══════════════════════════════════════════════════════════════════════════════
class TestSpeedTestDownload(_BaseTest):
    """_speed_test_download: download через DoH + --resolve."""

    def test_download_uses_resolve_when_doh_available(self):
        """DoH отдал IP → curl получает --resolve speed.cloudflare.com:443:IP."""
        captured_cmd = []
        def tracking_run(cmd, *args, **kwargs):
            captured_cmd.append(cmd)
            # size_download time_total speed_download
            return _make_completed(rc=0, stdout="10485760 1.0 10485760\n")
        with _patch_doh("104.16.0.1"), \
             patch.dict(self._g, {"_run": tracking_run}):
            result = self._g["_speed_test_download"](
                "speed.cloudflare.com", "1.1.1.1", 443, 10)
        self.assertIn("Мбит/с", result)
        self.assertEqual(len(captured_cmd), 1)
        cmd = captured_cmd[0]
        self.assertIn("--resolve", cmd)
        self.assertIn("speed.cloudflare.com:443:104.16.0.1", cmd)

    def test_download_fallback_without_doh(self):
        """DoH не сработал → curl без --resolve (через системный DNS)."""
        captured_cmd = []
        def tracking_run(cmd, *args, **kwargs):
            captured_cmd.append(cmd)
            return _make_completed(rc=0, stdout="10485760 1.0 10485760\n")
        with _patch_doh(None), \
             patch.dict(self._g, {"_run": tracking_run}):
            result = self._g["_speed_test_download"](
                "speed.cloudflare.com", "1.1.1.1", 443, 10)
        self.assertIn("Мбит/с", result)
        cmd = captured_cmd[0]
        self.assertNotIn("--resolve", cmd)

    def test_download_returns_error_on_curl_failure(self):
        """curl rc!=0 → возвращается строка с ошибкой."""
        with _patch_doh("104.16.0.1"), \
             patch.dict(self._g, {"_run":
                 lambda *a, **kw: _make_completed(rc=28, stdout="")}):
            result = self._g["_speed_test_download"](
                "speed.cloudflare.com", "1.1.1.1", 443, 10)
        self.assertIn("ошибка curl", result)
        self.assertIn("28", result)

    def test_download_returns_unavailable_when_size_small(self):
        """Cloudflare вернул <1024 байт → 'Cloudflare недоступен'."""
        with _patch_doh("104.16.0.1"), \
             patch.dict(self._g, {"_run":
                 lambda *a, **kw: _make_completed(rc=0, stdout="0 0.1 0\n")}):
            result = self._g["_speed_test_download"](
                "speed.cloudflare.com", "1.1.1.1", 443, 10)
        self.assertIn("Cloudflare недоступен", result)

    def test_download_returns_speed_on_success(self):
        """Успешный download → строка со скоростью в Мбит/с.
        10 MB за 1 сек = 80 Мбит/с.
        """
        with _patch_doh("104.16.0.1"), \
             patch.dict(self._g, {"_run":
                 lambda *a, **kw: _make_completed(rc=0,
                     stdout="10485760 1.0 10485760\n")}):
            result = self._g["_speed_test_download"](
                "speed.cloudflare.com", "1.1.1.1", 443, 10)
        self.assertIn("Мбит/с", result)
        # 10485760 bytes/s * 8 / 1_000_000 = 83.9 Мбит/с
        self.assertIn("83.9", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
