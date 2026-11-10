#!/usr/bin/env python3
"""
tests/test_hysteria2_common.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/hysteria2_common.py.

Покрывает:
  1. _h2_default_state — структура дефолтного state
  2. _is_ipv6 — определение IPv6
  3. _bracket — оборачивание IPv6 в […]
  4. _load_state / _save_state — JSON I/O
  5. _load_h2_state / _save_h2_state — подсекция hysteria2
  6. _ensure_h2_state — гарантирует наличие секции
  7. _h2_binary_exists — проверка бинарника
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
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


class TestH2DefaultState(unittest.TestCase):
    """_h2_default_state — структура."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_dict(self):
        from chimera.modules.hysteria2_common import _h2_default_state
        st = _h2_default_state()
        self.assertIsInstance(st, dict)

    def test_has_required_top_level_keys(self):
        from chimera.modules.hysteria2_common import _h2_default_state
        st = _h2_default_state()
        for key in ("enabled", "transport_only", "exit_nodes", "cert",
                     "health_check", "firewall", "balancer", "auto_update"):
            self.assertIn(key, st, f"missing key: {key}")

    def test_enabled_is_false_by_default(self):
        from chimera.modules.hysteria2_common import _h2_default_state
        self.assertFalse(_h2_default_state()["enabled"])


class TestIsIpv6(unittest.TestCase):
    """_is_ipv6 — определение IPv6."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ipv4_returns_false(self):
        from chimera.modules.hysteria2_common import _is_ipv6
        self.assertFalse(_is_ipv6("1.2.3.4"))
        self.assertFalse(_is_ipv6("192.168.1.1"))

    def test_ipv6_returns_true(self):
        from chimera.modules.hysteria2_common import _is_ipv6
        self.assertTrue(_is_ipv6("::1"))
        self.assertTrue(_is_ipv6("2001:db8::1"))
        self.assertTrue(_is_ipv6("fd66:66:66::1"))

    def test_empty_returns_false(self):
        from chimera.modules.hysteria2_common import _is_ipv6
        self.assertFalse(_is_ipv6(""))


class TestBracket(unittest.TestCase):
    """_bracket — оборачивание IPv6 в […]."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ipv4_unchanged(self):
        from chimera.modules.hysteria2_common import _bracket
        self.assertEqual(_bracket("1.2.3.4"), "1.2.3.4")

    def test_ipv6_wrapped(self):
        from chimera.modules.hysteria2_common import _bracket
        self.assertEqual(_bracket("2001:db8::1"), "[2001:db8::1]")
        self.assertEqual(_bracket("::1"), "[::1]")

    def test_already_bracketed_unchanged(self):
        from chimera.modules.hysteria2_common import _bracket
        self.assertEqual(_bracket("[2001:db8::1]"), "[2001:db8::1]")


class TestLoadSaveState(unittest.TestCase):
    """_load_state / _save_state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.hysteria2_common.STATE_FILE", self._state)

    def test_load_returns_empty_when_no_file(self):
        from chimera.modules.hysteria2_common import _load_state
        with self._patch():
            self.assertEqual(_load_state(), {})

    def test_load_returns_empty_on_corrupt(self):
        from chimera.modules.hysteria2_common import _load_state
        self._state.write_text("{invalid")
        with self._patch():
            self.assertEqual(_load_state(), {})

    def test_load_returns_state(self):
        from chimera.modules.hysteria2_common import _load_state
        self._state.write_text(json.dumps({"hysteria2": {"enabled": True}}))
        with self._patch():
            st = _load_state()
        self.assertTrue(st["hysteria2"]["enabled"])

    def test_save_writes_json(self):
        from chimera.modules.hysteria2_common import _save_state, _load_state
        with self._patch():
            _save_state({"hysteria2": {"enabled": True}})
            loaded = _load_state()
        self.assertTrue(loaded["hysteria2"]["enabled"])


class TestLoadSaveH2State(unittest.TestCase):
    """_load_h2_state / _save_h2_state — подсекция hysteria2."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.hysteria2_common.STATE_FILE", self._state)

    def test_load_h2_returns_empty_when_no_section(self):
        from chimera.modules.hysteria2_common import _load_h2_state
        with self._patch():
            self.assertEqual(_load_h2_state(), {})

    def test_load_h2_returns_section(self):
        from chimera.modules.hysteria2_common import _load_h2_state
        self._state.write_text(json.dumps({"hysteria2": {"enabled": True, "port": 8443}}))
        with self._patch():
            h2 = _load_h2_state()
        self.assertTrue(h2["enabled"])
        self.assertEqual(h2["port"], 8443)

    def test_save_h2_preserves_other_keys(self):
        from chimera.modules.hysteria2_common import (
            _save_h2_state, _load_h2_state, _load_state,
        )
        self._state.write_text(json.dumps({"uuid": "abc", "domain": "x.com"}))
        with self._patch():
            _save_h2_state({"enabled": True})
            full = _load_state()
        self.assertEqual(full["uuid"], "abc")
        self.assertEqual(full["domain"], "x.com")
        self.assertTrue(full["hysteria2"]["enabled"])


class TestEnsureH2State(unittest.TestCase):
    """_ensure_h2_state — гарантирует наличие секции."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.hysteria2_common.STATE_FILE", self._state)

    def test_creates_default_when_missing(self):
        from chimera.modules.hysteria2_common import _ensure_h2_state
        with self._patch():
            h2 = _ensure_h2_state()
        self.assertIn("enabled", h2)
        # файл создан
        self.assertTrue(self._state.exists())

    def test_returns_existing_when_present(self):
        from chimera.modules.hysteria2_common import _ensure_h2_state
        self._state.write_text(json.dumps({"hysteria2": {"enabled": True, "custom": "x"}}))
        with self._patch():
            h2 = _ensure_h2_state()
        self.assertTrue(h2["enabled"])
        self.assertEqual(h2["custom"], "x")


class TestH2BinaryExists(unittest.TestCase):
    """_h2_binary_exists."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_false_when_no_binary(self):
        from chimera.modules.hysteria2_common import _h2_binary_exists
        with patch("chimera.modules.hysteria2_common.H2_BINARY",
                   Path("/tmp/nonexistent_h2_binary")):
            self.assertFalse(_h2_binary_exists())


# ══════════════════════════════════════════════════════════════════════════════
#  Волна-2 (11.11.2026): _tg_h2_event — events-фильтр + заголовок server_header;
#  h2_node_label — канон node_identity («alias · домен [IP](:порт)»)
#  Паттерн герметичности: test_mieru_cascade_monitor._TmpBase (волна-1) —
#  TG-конфиг/лог/DNS-кэш на tmp, транспорт и hostname подменены, боевой
#  TG из тестов не отправляется.
# ══════════════════════════════════════════════════════════════════════════════

class _H2TmpBase(unittest.TestCase):
    """Все пути hysteria2_common/node_identity — tmp; curl/hostname — моки."""

    def setUp(self):
        _setup_core_in_sysmodules()
        import time as _time
        from chimera.modules import hysteria2_common as hc
        from chimera.modules import node_identity as _ni
        self._hc = hc
        self._ni = _ni
        self._now = _time.time()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(self._rmtree)
        patches = [
            patch.object(hc, "TG_CONFIG_FILE", self.tmp / "telegram.json"),
            patch.object(hc, "LOG_FILE", self.tmp / "chimera.log"),
        ]
        # node_identity: прод-файлы НЕ должны протекать в тесты
        # (герметичность на живых нодах — паттерн 652e692/71605f2)
        patches += [
            patch.object(_ni, "STATE_FILE", self.tmp / "state.json"),
            patch.object(_ni, "TG_FILE", self.tmp / "tg-absent.json"),
            patch.object(_ni, "DNS_CACHE_FILE", self.tmp / "node_dns_cache.json"),
            patch.object(_ni, "ALIASES_FILE", self.tmp / "aliases-absent.json"),
        ]
        _ni._MEM.clear()
        self.addCleanup(_ni._MEM.clear)
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

        class _Res:
            def __init__(self, stdout=""):
                self.stdout = stdout
                self.returncode = 0

        def fake_run(cmd, **kw):
            argv = cmd if isinstance(cmd, list) else list(cmd)
            if argv and argv[0] == "hostname":
                return _Res("testhost\n")
            if argv and argv[0] == "curl":
                return _Res("200")
            return _Res("")

        r_ = patch.object(hc, "_run", side_effect=fake_run)
        r_.start()
        self.addCleanup(r_.stop)

        self.sent: list[str] = []
        t_ = patch.object(hc, "_tg_send",
                          side_effect=lambda msg: self.sent.append(msg) or True)
        t_.start()
        self.addCleanup(t_.stop)

    def _rmtree(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_tg(self, events: dict | None = None, extra: dict | None = None):
        cfg = {"token": "TESTTOKEN", "chat_id": "12345",
               "server_ip": "203.0.113.10"}
        if events is not None:
            cfg["events"] = events
        if extra:
            cfg.update(extra)
        (self.tmp / "telegram.json").write_text(json.dumps(cfg))

    def _fill_dns(self, host: str, ip: str):
        (self.tmp / "node_dns_cache.json").write_text(json.dumps(
            {host: {"ip": ip, "ts": self._now}}))
        self._ni._MEM.clear()

    def _log_text(self) -> str:
        f = self.tmp / "chimera.log"
        return f.read_text() if f.exists() else ""


class TestTgH2Event(_H2TmpBase):
    """_tg_h2_event: events-фильтр вкл/выкл/дефолт + заголовок server_header."""

    def test_sent_by_default_no_events_key(self):
        """Нет ключа events → слать (видимость существующих увед не меняется)."""
        self._write_tg(events=None)
        self._hc._tg_h2_event("h2_down", "Нода 203.0.113.99 недоступна")
        self.assertEqual(len(self.sent), 1)
        self.assertIn("Hysteria2", self.sent[0])
        self.assertIn("203.0.113.99", self.sent[0])

    def test_sent_when_event_enabled(self):
        self._write_tg(events={"h2_down": True, "h2_up": False})
        self._hc._tg_h2_event("h2_down", "down")
        self.assertEqual(len(self.sent), 1)

    def test_muted_when_event_disabled(self):
        """events.h2_down == false → уведа НЕ отправляется."""
        self._write_tg(events={"h2_down": False, "h2_up": True})
        self._hc._tg_h2_event("h2_down", "Нода недоступна")
        self.assertEqual(self.sent, [])
        # событие логируется независимо от фильтра (как tg_bot)
        self.assertIn("TG H2 event", self._log_text())
        self.assertIn("h2_down", self._log_text())

    def test_other_events_not_affected(self):
        """Выключенный h2_down не глушит h2_up (ключи независимы)."""
        self._write_tg(events={"h2_down": False})
        self._hc._tg_h2_event("h2_up", "Нода поднялась")
        self.assertEqual(len(self.sent), 1)

    def test_header_canonical_server_header(self):
        """Заголовок — канон node_identity: «имя · домен · IP» вместо hostname."""
        self._write_tg(extra={"server_name": "RU1"})
        (self.tmp / "state.json").write_text(json.dumps(
            {"domain": "node-ru1.example.com"}))
        self._ni._MEM.clear()
        self._hc._tg_h2_event("h2_down", "Нода недоступна")
        self.assertEqual(len(self.sent), 1)
        self.assertIn("[RU1 · node-ru1.example.com · 203.0.113.10] Hysteria2",
                      self.sent[0])
        # прежний hostname-формат не остаётся
        self.assertNotIn("[testhost]", self.sent[0])

    def test_header_fallback_hostname(self):
        """Нет server_name/domain — фолбэк на hostname (прежний формат)."""
        self._write_tg()
        # убрать server_ip из заголовка: конфиг без него
        (self.tmp / "telegram.json").write_text(json.dumps(
            {"token": "TESTTOKEN", "chat_id": "12345"}))
        self._hc._tg_h2_event("h2_cert", "Сертификат обновлён")
        self.assertEqual(len(self.sent), 1)
        self.assertIn("[testhost] Hysteria2", self.sent[0])

    def test_header_fallback_when_node_identity_unavailable(self):
        """node_identity недоступен → прежний hostname-формат, не бросает."""
        self._write_tg()
        import sys as _sys
        with patch.dict(_sys.modules, {"chimera.modules.node_identity": None}):
            self._hc._tg_h2_event("h2_update", "Обновлён до v2.0.0")
        self.assertEqual(len(self.sent), 1)
        self.assertIn("[testhost] Hysteria2", self.sent[0])

    def test_icons(self):
        """Иконки событий h2_* в тексте (🔴 h2_down / 🔁 h2_port_fb / 📊 h2_traffic)."""
        self._write_tg()
        for ev, icon in (("h2_down", "🔴"), ("h2_port_fb", "🔁"),
                         ("h2_traffic", "📊"), ("h2_switch", "🔀")):
            self.sent.clear()
            self._hc._tg_h2_event(ev, "детали")
            self.assertTrue(self.sent[0].startswith(icon), ev)


class TestH2NodeLabel(_H2TmpBase):
    """h2_node_label: домен/IP, с портом/без, алиас, фолбэк «ip:port»."""

    def test_ip_with_port(self):
        self.assertEqual(self._hc.h2_node_label("203.0.113.99", 8443),
                         "203.0.113.99:8443")

    def test_ip_default_port_hidden(self):
        """Порт 443 — дефолт, в метке не пишется (канон node_label)."""
        self.assertEqual(self._hc.h2_node_label("203.0.113.99", 443),
                         "203.0.113.99")

    def test_ip_without_port(self):
        self.assertEqual(self._hc.h2_node_label("203.0.113.99"), "203.0.113.99")

    def test_ip_with_name(self):
        self.assertEqual(self._hc.h2_node_label("203.0.113.99", 8443, "H2-99"),
                         "H2-99 · 203.0.113.99:8443")

    def test_port_list_takes_first(self):
        """ports[] — список: берётся первый порт (как в вызывающих модулях)."""
        self.assertEqual(self._hc.h2_node_label("10.0.0.5", [8443, 9443]),
                         "10.0.0.5:8443")

    def test_domain_resolved_via_cache(self):
        """Домен + предзаполненный DNS-кэш → «домен [IP]» (без getent)."""
        self._fill_dns("node-h2b.example.com", "203.0.113.99")
        self.assertEqual(
            self._hc.h2_node_label("node-h2b.example.com", 443),
            "node-h2b.example.com [203.0.113.99]")

    def test_domain_with_name_and_port(self):
        self._fill_dns("node-h2b.example.com", "203.0.113.99")
        self.assertEqual(
            self._hc.h2_node_label("node-h2b.example.com", 8443, "H2-B"),
            "H2-B · node-h2b.example.com [203.0.113.99]:8443")

    def test_fallback_when_node_identity_unavailable(self):
        """node_identity недоступен → прежний формат «ip:port», не бросает."""
        import sys as _sys
        with patch.dict(_sys.modules, {"chimera.modules.node_identity": None}):
            self.assertEqual(self._hc.h2_node_label("203.0.113.99", 8443, "X"),
                             "203.0.113.99:8443")
            self.assertEqual(self._hc.h2_node_label("203.0.113.99", 0),
                             "203.0.113.99")

    def test_empty_ip(self):
        self.assertEqual(self._hc.h2_node_label("", 443, "X"), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
