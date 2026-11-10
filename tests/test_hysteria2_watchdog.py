#!/usr/bin/env python3
"""
tests/test_hysteria2_watchdog.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/hysteria2_watchdog.py.

Покрывает:
  1. _RESTART_LIMIT — константа
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

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


class TestH2Watchdog(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_restart_limit_constant(self):
        from chimera.modules.hysteria2_watchdog import _RESTART_LIMIT
        self.assertGreater(_RESTART_LIMIT, 0)


# ══════════════════════════════════════════════════════════════════════════════
#  Волна-2 (11.11.2026): fallback-уведа watchdog — метка целевой ноды каноном
#  node_identity («alias · домен [IP](:порт)») вместо голого ip.
#  Герметичность: state/TG/DNS-кэш node_identity на tmp, systemd/транспорт
#  подменены, _tg_h2_event перехвачен (боевой TG из тестов не уходит).
# ══════════════════════════════════════════════════════════════════════════════

class TestWatchdogFallbackLabel(unittest.TestCase):
    """h2_watchdog_run: h2_switch fallback → метка ноды в detail."""

    def setUp(self):
        _setup_core()
        import time as _time
        from chimera.modules import hysteria2_watchdog as wd
        from chimera.modules import node_identity as _ni
        self._wd = wd
        self._ni = _ni
        self._now = _time.time()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(self._rmtree)
        for p in (
            patch.object(_ni, "STATE_FILE", self.tmp / "state.json"),
            patch.object(_ni, "TG_FILE", self.tmp / "tg-absent.json"),
            patch.object(_ni, "DNS_CACHE_FILE", self.tmp / "node_dns_cache.json"),
            patch.object(_ni, "ALIASES_FILE", self.tmp / "aliases-absent.json"),
        ):
            p.start()
            self.addCleanup(p.stop)
        _ni._MEM.clear()
        self.addCleanup(_ni._MEM.clear)

        self.state = {
            "enabled": True,
            "_wd_fail_count": 5,          # >= _RESTART_LIMIT → fallback-ветка
            "_active_node_ip": "203.0.113.10",
            "exit_nodes": [
                {"ip": "203.0.113.10", "ports": [443], "auth": "a",
                 "weight": 1.0, "status": "down"},
            ],
        }
        self.applied: list[dict] = []
        self.events: list[tuple] = []
        for p in (
            patch.object(wd, "_load_h2_state", lambda: dict(self.state)),
            patch.object(wd, "_save_h2_state", lambda h2: None),
            patch.object(wd, "_service_active", lambda svc: False),
            patch.object(wd, "_wd_log", lambda msg: None),
            patch.object(wd, "_tg_h2_event",
                         lambda ev, detail="": self.events.append((ev, detail))),
            patch("chimera.modules.hysteria2_balancer.h2_balancer_select_node",
                  side_effect=self._select_node),
            patch("chimera.modules.hysteria2_transport.h2_transport_apply",
                  side_effect=lambda **kw: self.applied.append(kw) or True),
        ):
            p.start()
            self.addCleanup(p.stop)

    def _rmtree(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _select_node(self, prefer_ipv6=False):
        return self._fallback_node

    def _fill_dns(self, host: str, ip: str):
        (self.tmp / "node_dns_cache.json").write_text(json.dumps(
            {host: {"ip": ip, "ts": self._now}}))
        self._ni._MEM.clear()

    def test_fallback_event_carries_node_label(self):
        """Fallback на домен-ноду: уведа «fallback → alias · домен [IP]:порт»."""
        self._fill_dns("node-h2b.example.com", "203.0.113.99")
        self._fallback_node = {"ip": "node-h2b.example.com", "ports": [8443],
                               "auth": "x", "name": "H2-B", "status": "active"}
        self._wd.h2_watchdog_run()
        self.assertEqual([e for e, _ in self.events],
                         ["h2_down", "h2_switch"])
        detail = self.events[1][1]
        self.assertIn("fallback → H2-B · node-h2b.example.com [203.0.113.99]:8443",
                      detail)
        # транспорт применён к выбранной ноде
        self.assertEqual(self.applied[0]["exit_ip"], "node-h2b.example.com")

    def test_fallback_ip_node_label(self):
        """Fallback на IP-ноду: метка «ip:порт» (нестандартный порт)."""
        self._fallback_node = {"ip": "203.0.113.99", "ports": [8443],
                               "auth": "x", "status": "active"}
        self._wd.h2_watchdog_run()
        detail = self.events[1][1]
        self.assertIn("fallback → 203.0.113.99:8443", detail)

    def test_fallback_no_alternative_plain_message(self):
        """Нет альтернативной ноды — прежний текст без «→» (событие всё равно уходит)."""
        self._fallback_node = {"ip": "203.0.113.10", "ports": [443],
                               "auth": "a", "status": "down"}  # == active_ip
        self._wd.h2_watchdog_run()
        self.assertEqual([e for e, _ in self.events],
                         ["h2_down", "h2_switch"])
        self.assertEqual(self.events[1][1], "Превышен лимит рестартов, fallback")
        self.assertEqual(self.applied, [])

    def test_down_event_without_labels_unchanged(self):
        """Падение сервиса — прежний текст (без ip, локальный сервис)."""
        self._fallback_node = None
        self.state["_wd_fail_count"] = 0   # обычный рестарт-путь (#1)
        for p in (
            patch.object(self._wd, "_systemctl", lambda a, s: True),
            patch.object(self._wd, "_service_active", lambda svc: False),
        ):
            p.start()
            self.addCleanup(p.stop)
        import time as _t
        with patch.object(_t, "sleep", lambda s: None):
            self._wd.h2_watchdog_run()
        self.assertEqual(self.events[0], ("h2_down", "Сервис упал (рестарт #1)"))
        # рестарт не помог → второе событие (прежний текст без ip)
        self.assertEqual(self.events[1],
                         ("h2_down", "Hysteria2 не смог перезапуститься"))

# ── hysteria2_cluster ──────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
