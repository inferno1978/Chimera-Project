#!/usr/bin/env python3
"""
tests/test_smartdns_port_registry.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для bind_ip-расширения port_registry (режим companion SmartDNS:
второй IP на том же VPS).

Покрывает:
  1. _bind_scopes_overlap — матрица пересечений (None=wildcard): None/None
     → конфликт; None/specific → сосуществование (ядро Linux разрешает
     одновременный bind wildcard+specific); specific/same → конфликт;
     specific/other → нет.
  2. port_check_system(bind_ip=...) — IP-осознанный ss-парсинг (мок
     _ss_listeners): wildcard-слушатель НЕ конфликтует с specific-bind;
     слушатель на том же IP — конфликт; на чужом — нет; bind_ip=None —
     старая семантика «любой слушатель = занят».
  3. port_get_conflicts по реестру: записи с разными bind_ip не конфликтуют
     (Chimera 80 wildcard + smartdns 80 на втором IP); один bind_ip —
     конфликт; wildcard/wildcard — конфликт (обратная совместимость).
  4. port_register(bind_ip=...) — поле bind_ip в записи; дедуп по
     (service, port, proto, bind_ip); записи без bind_ip сохраняют старый
     формат (нет поля) — обратная совместимость.
  5. Реестр без bind_ip-полей (старые записи) продолжает работать как
     раньше: тот же порт, другой сервис → конфликт.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

import chimera.modules.port_registry as pr  # noqa: E402


class _tmp_registry:
    def __enter__(self):
        self.td = tempfile.TemporaryDirectory()
        self._orig_file = pr.PORT_REGISTRY_FILE
        # LOCK_FILE вычислен на импорте от прод-пути — двигаем вместе
        self._orig_lock = pr.LOCK_FILE
        pr.PORT_REGISTRY_FILE = Path(self.td.name) / "port_registry.json"
        pr.LOCK_FILE = Path(self.td.name) / "port_registry.lock"
        return pr.PORT_REGISTRY_FILE

    def __exit__(self, *a):
        pr.PORT_REGISTRY_FILE = self._orig_file
        pr.LOCK_FILE = self._orig_lock
        self.td.cleanup()


def _seed(entries):
    pr.PORT_REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
    pr.PORT_REGISTRY_FILE.write_text(json.dumps(entries))


class TestBindScopesOverlap(unittest.TestCase):
    def test_matrix(self):
        f = pr._bind_scopes_overlap
        self.assertTrue(f(None, None))          # wildcard/wildcard
        self.assertFalse(f(None, "1.2.3.4"))    # wildcard/specific
        self.assertFalse(f("1.2.3.4", None))    # specific/wildcard
        self.assertTrue(f("1.2.3.4", "1.2.3.4"))
        self.assertFalse(f("1.2.3.4", "5.6.7.8"))


class TestSystemListenersIpAware(unittest.TestCase):
    LISTENERS = [
        ("*", "nginx (pid=1)"),            # 0.0.0.0:80 (Chimera)
        ("127.0.0.1", "panel (pid=2)"),     # specific loopback
        ("203.0.113.7", "other (pid=3)"),   # чужой specific
    ]

    def test_wildcard_query_old_semantics(self):
        with patch.object(pr, "_ss_listeners",
                          return_value=self.LISTENERS):
            taken = pr.port_check_system(80, "tcp")
        self.assertEqual(len(taken), 3)     # любой слушатель = занят

    def test_specific_bind_wildcard_listeners_coexist(self):
        with patch.object(pr, "_ss_listeners",
                          return_value=[("*", "nginx (pid=1)")]):
            taken = pr.port_check_system(80, "tcp", bind_ip="203.0.113.7")
        self.assertEqual(taken, [])         # ядро допускает оба сокета

    def test_specific_bind_same_ip_conflict(self):
        with patch.object(pr, "_ss_listeners",
                          return_value=[("203.0.113.7", "other (pid=3)")]):
            taken = pr.port_check_system(80, "tcp", bind_ip="203.0.113.7")
        self.assertEqual(len(taken), 1)
        self.assertIn("203.0.113.7", taken[0])

    def test_specific_bind_foreign_ip_ok(self):
        with patch.object(pr, "_ss_listeners",
                          return_value=[("198.51.100.2", "chimera (pid=4)")]):
            taken = pr.port_check_system(80, "tcp", bind_ip="203.0.113.7")
        self.assertEqual(taken, [])

    def test_ss_parse_wildcard_variants(self):
        with patch.object(pr, "_ss_listeners") as m:
            m.return_value = pr._ss_listeners.__wrapped__ if hasattr(
                pr._ss_listeners, "__wrapped__") else []
        # прямой смоук парсера на реальном ss (если доступен) — только типы
        out = pr._ss_listeners(80, "tcp")
        self.assertIsInstance(out, list)


class TestRegistryConflictsIpAware(unittest.TestCase):
    def test_different_bind_no_conflict(self):
        with _tmp_registry():
            _seed([{"service": "subscription_nginx", "port": 80,
                    "proto": "tcp", "comment": "Chimera"}])
            conflicts = pr.port_get_conflicts(
                80, "tcp", exclude_service="smartdns_http",
                bind_ip="203.0.113.7")
        self.assertEqual(
            [c for c in conflicts if c["type"] == "registry"], [])

    def test_same_bind_conflict(self):
        with _tmp_registry():
            _seed([{"service": "subscription_nginx", "port": 80,
                    "proto": "tcp", "comment": "Chimera",
                    "bind_ip": "203.0.113.7"}])
            conflicts = pr.port_get_conflicts(
                80, "tcp", exclude_service="smartdns_http",
                bind_ip="203.0.113.7")
        self.assertTrue(
            any(c["type"] == "registry" for c in conflicts))

    def test_wildcard_entry_vs_specific_query_ok(self):
        """Chimera зарегистрировала 443 без bind_ip (wildcard) — smartdns
        companion на втором IP не конфликтует (ядровая семантика)."""
        with _tmp_registry():
            _seed([{"service": "vless", "port": 443, "proto": "tcp",
                    "comment": "VLESS Reality"}])
            conflicts = pr.port_get_conflicts(
                443, "tcp", exclude_service="smartdns_doh",
                bind_ip="203.0.113.7")
        self.assertEqual(
            [c for c in conflicts if c["type"] == "registry"], [])

    def test_wildcard_query_vs_wildcard_entry_conflict(self):
        """Старая семантика сохранилась: wildcard-запрос против wildcard-записи
        другого сервиса — конфликт (как до расширения)."""
        with _tmp_registry():
            _seed([{"service": "vless", "port": 443, "proto": "tcp",
                    "comment": "VLESS"}])
            conflicts = pr.port_get_conflicts(443, "tcp",
                                              exclude_service="other")
        self.assertTrue(any(c["type"] == "registry" for c in conflicts))


class TestRegisterBindIp(unittest.TestCase):
    def test_register_entry_has_bind_ip(self):
        with _tmp_registry():
            ok, msg = pr.port_register("smartdns_web", 9443, "tcp",
                                       comment="cover", force=True,
                                       bind_ip="203.0.113.7")
            self.assertTrue(ok, msg)
            entries = json.loads(pr.PORT_REGISTRY_FILE.read_text())
            self.assertEqual(entries[0]["bind_ip"], "203.0.113.7")
            self.assertIn("bind 203.0.113.7", msg)

    def test_register_no_bind_ip_omits_field(self):
        with _tmp_registry():
            pr.port_register("smartdns_engine", 5353, "tcp",
                             comment="loopback", force=True)
            entries = json.loads(pr.PORT_REGISTRY_FILE.read_text())
            self.assertNotIn("bind_ip", entries[0])   # обратная совместимость

    def test_dedup_considers_bind_ip(self):
        with _tmp_registry():
            pr.port_register("smartdns_web", 9443, "tcp", force=True,
                             bind_ip="203.0.113.7")
            pr.port_register("smartdns_web", 9443, "tcp", force=True,
                             bind_ip="198.51.100.2")
            pr.port_register("smartdns_web", 9443, "tcp", force=True)  # wc
            entries = json.loads(pr.PORT_REGISTRY_FILE.read_text())
            self.assertEqual(len(entries), 3)
            pr.port_register("smartdns_web", 9443, "tcp", force=True,
                             bind_ip="203.0.113.7")   # дубликат
            entries = json.loads(pr.PORT_REGISTRY_FILE.read_text())
            self.assertEqual(len(entries), 3)

    def test_is_free_bind_aware(self):
        with _tmp_registry():
            _seed([{"service": "vless", "port": 443, "proto": "tcp"}])
            with patch.object(pr, "port_check_system",
                              return_value=[]), \
                 patch.object(pr, "_check_ufw_rules", return_value=[]):
                ok, _ = pr.port_is_free(443, "tcp",
                                        exclude_service="smartdns_doh",
                                        bind_ip="203.0.113.7")
                self.assertTrue(ok)
                ok2, why = pr.port_is_free(443, "tcp",
                                           exclude_service="smartdns_doh")
                self.assertFalse(ok2)   # wildcard-запрос — старый конфликт


if __name__ == "__main__":
    unittest.main(verbosity=2)
