#!/usr/bin/env python3
"""
tests/test_health_report.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/health_report.py.

Smoke: _core_module dispatcher
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


class TestHealthReport(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_core_module_returns_module(self):
        from chimera.modules.health_report import _core_module
        self.assertIsNotNone(_core_module())


# ══════════════════════════════════════════════════════════════════════════════
#  Волна-3 (канон node_identity): заголовок отчёта «[имя · домен · IP]»
#  (server_header; фолбэк — прежний [hostname]). Интерактивный отчёт и
#  inline cron-скрипт. Герметичность: node_identity/пути — на tmp, _run —
#  мок (реальных systemctl/df из тестов нет), TG-отправка отключена.
# ══════════════════════════════════════════════════════════════════════════════

class _Res:
    def __init__(self, out=""):
        self.stdout = out
        self.stderr = ""
        self.returncode = 0

    def strip(self):
        return self.stdout.strip()


def _fake_run(cmd, capture=False, check=False):
    argv = list(cmd)
    if argv[:2] == ["hostname", "-s"]:
        return _Res("testhost")
    if argv[:2] == ["systemctl", "is-active"]:
        return _Res("active")
    return _Res("")


class TestHeaderCanon(unittest.TestCase):
    """Заголовок «[RU1 · домен · IP]» в отчёте и cron-скрипте."""

    def setUp(self):
        _setup_core()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(self._rmtree)
        (self.tmp / "telegram.json").write_text(json.dumps(
            {"server_name": "RU1", "server_ip": "203.0.113.10"}))
        (self.tmp / "ni-state.json").write_text(
            json.dumps({"domain": "entry-ru.example.com"}))
        from chimera.modules import node_identity as _ni
        for p in (
            patch.object(_ni, "TG_FILE", self.tmp / "telegram.json"),
            patch.object(_ni, "STATE_FILE", self.tmp / "ni-state.json"),
            patch.object(_ni, "DNS_CACHE_FILE", self.tmp / "ni-dns-absent.json"),
            patch.object(_ni, "ALIASES_FILE", self.tmp / "ni-aliases-absent.json"),
        ):
            p.start()
            self.addCleanup(p.stop)
        _ni._MEM.clear()
        self.addCleanup(_ni._MEM.clear)

    def _rmtree(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_report_header_canon(self):
        """Первая строка отчёта — «📋 [RU1 · домен · IP] Daily Health Report»."""
        import types as _types
        from chimera.modules import health_report as hr
        core = _types.ModuleType("chimera._core")
        core._run = _fake_run
        core.log_to_file = lambda *a, **kw: None
        core.STATE_FILE = self.tmp / "ni-state.json"
        core.GEOSITE_DAT = self.tmp / "geosite.dat"
        core.GEOIP_DAT = self.tmp / "geoip.dat"
        core._tg_load = lambda: {}
        core.tg_send = lambda *a, **kw: False
        with patch.object(hr, "_core_module", lambda: core):
            text = hr.do_health_report(send_tg_flag=False)
        first = text.splitlines()[0]
        self.assertIn("[RU1 · entry-ru.example.com · 203.0.113.10] "
                      "Daily Health Report", first)
        self.assertNotIn("[testhost]", first)

    def test_report_header_fallback_hostname(self):
        """node_identity недоступен → прежний вид [hostname]."""
        import types as _types
        from chimera.modules import health_report as hr
        core = _types.ModuleType("chimera._core")
        core._run = _fake_run
        core.log_to_file = lambda *a, **kw: None
        core.STATE_FILE = self.tmp / "ni-state.json"
        core.GEOSITE_DAT = self.tmp / "geosite.dat"
        core.GEOIP_DAT = self.tmp / "geoip.dat"
        core._tg_load = lambda: {}
        core.tg_send = lambda *a, **kw: False
        with patch.object(hr, "_core_module", lambda: core), \
             patch.dict(sys.modules,
                        {"chimera.modules.node_identity": None}):
            text = hr.do_health_report(send_tg_flag=False)
        first = text.splitlines()[0]
        self.assertIn("[testhost] Daily Health Report", first)

    def test_cron_script_header_canon(self):
        """Inline cron-скрипт: рантайм-заголовок из telegram.json/state.json."""
        import re
        import types as _types
        from chimera.modules import health_report as hr
        captured = []

        def _fake_path(*a, **kw):
            p = Path(*a, **kw)
            if a and str(a[0]) in ("/usr/local/bin/xray-health-report.sh",
                                   "/etc/cron.d/xray-health-report"):
                mock = MagicMock()
                mock.write_text = lambda c: captured.append(c)
                mock.chmod = lambda m: None
                return mock
            return p

        core = _types.ModuleType("chimera._core")
        core.success = lambda *a, **kw: None
        with patch.object(hr, "Path", side_effect=_fake_path), \
             patch.object(hr, "_core_module", lambda: core):
            hr._health_report_install_cron()
        self.assertTrue(captured)
        script = captured[0]
        # канон server_header: имя из telegram.json, домен из state.json,
        # IP из telegram.json; фолбэк имени — hostname
        self.assertIn("server_name", script)
        self.assertIn("server_ip", script)
        self.assertIn("gethostname", script)
        self.assertIn("' · '.join(_parts)", script)
        self.assertIn("[{_hdr}] Daily Health Report", script)
        # заголовочная строка с доменом (рендер читает его ДО lines)
        m = re.search(r"python3 -c \"\n(.*?)\" 2>>", script, re.S)
        self.assertIsNotNone(m, "python-хердок не найден")
        compile(m.group(1), "<health-cron>", "exec")


# ── ipset_persist ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
