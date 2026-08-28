#!/usr/bin/env python3
"""
tests/test_v62_dns_path_report.py
───────────────────────────────────────────────────────────────────────────────
v62: фактический DNS-путь Xray в health-отчёте меню и emergency repair.

Запрос пользователя (после v61): «добавь вывод DNS-пути в итоговый
health-отчёт меню и в emergency_repair». Один вопрос — «через что идут
DNS-запросы Xray: AGH / DNSCrypt / системный резольвер?» — теперь виден
везде: строка строится по ФАКТИЧЕСКОМУ config.json (dns.servers[0]) +
живому состоянию стека.

Контракт v62:
  1. agh_probe.xray_dns_path_report — единый источник строки:
     • конфиг «AGH:53» + AGH жив (сервис + владение :53 + проба резолва)
       → ok ✅ «Xray → AGH:53 → DNSCrypt:5300 — AGH отвечает (…)»;
     • конфиг «AGH:53» + AGH мёртв/не резолвит → ⚠️ «… Xray идёт через
       fallback, фильтры AGH не применяются» (plain text, без ANSI —
       пригодно для Telegram);
     • конфиг «DNSCrypt:5300» → ✅/⚠️ по is-active dnscrypt-proxy;
     • публичный DNS → ℹ️ (легитимный путь);
     • конфига нет → ❌.
     Побочных эффектов НЕТ (iptables не трогаем — диагностика, не лечение).
  2. health.py: health_check_dns_path в run_full_health_check (после
     Xray); провал DNS-пути → degraded.
  3. health_report.py: DNS-строка в do_health_report (после Nginx) и в
     stringified cron-скрипте (рендер компилируется, ветки AGH/DNSCrypt/
     публичный присутствуют, AGH-ветка проверяет владение :53 через ss).
  4. emergency_repair.py: DNS-строка в итоговом health-report (шаг 11/11),
     all_ok не трогает (DNS жив через runtime-fallback — это диагностика).
"""
from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Фейковый chimera._core (паттерн test_health/test_v60)."""
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
    fake_core.success = lambda *a, **k: None
    sys.modules["chimera._core"] = fake_core
    return fake_core


def _read(rel: str) -> str:
    return (_PROJECT_ROOT / rel).read_text(encoding="utf-8")


AGH_CFG = {"dns": {"servers": [
    {"address": "127.0.0.1", "port": 53, "network": "udp",
     "skipFallback": False},
    {"address": "127.0.0.1", "port": 5300, "network": "udp",
     "skipFallback": False},
]}}
DNSCRYPT_CFG = {"dns": {"servers": [
    {"address": "127.0.0.1", "port": 5300, "network": "udp",
     "skipFallback": False},
]}}
PUBLIC_CFG = {"dns": {"servers": [
    {"address": "1.1.1.1", "port": 53, "network": "udp"},
]}}


# ─────────────────────────────────────────────────────────────────────────────
#  1. agh_probe.xray_dns_path_report — единый источник строки
# ─────────────────────────────────────────────────────────────────────────────
class TestXrayDnsPathReport(unittest.TestCase):
    def setUp(self):
        import importlib
        import chimera.modules.agh_probe as ap
        importlib.reload(ap)
        self.ap = ap
        self._tmpdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self._tmpdir, ignore_errors=True))

    def _cfg(self, cfg: dict) -> Path:
        p = self._tmpdir / "config.json"
        p.write_text(json.dumps(cfg))
        return p

    def _with_config(self, cfg: dict):
        return patch.object(self.ap, "_XRAY_CONFIG_CANDIDATES",
                            (self._cfg(cfg),))

    def test_no_config(self):
        with patch.object(self.ap, "_XRAY_CONFIG_CANDIDATES", ()):
            rep = self.ap.xray_dns_path_report()
        self.assertFalse(rep["ok"])
        self.assertEqual(rep["icon"], "❌")
        self.assertIn("config.json", rep["line"])

    def test_agh_alive(self):
        """Конфиг «AGH:53» + сервис активен + владеет :53 + резолвит →
        ok, цепочка Xray → AGH:53 → DNSCrypt:5300."""
        with self._with_config(AGH_CFG), \
             patch.object(self.ap, "agh_service_active", return_value=True), \
             patch.object(self.ap, "agh_owns_dns53", return_value=True), \
             patch.object(self.ap, "agh_probe_resolve",
                          return_value=(True, "www.example.com → 1 ответ, 5 мс")):
            rep = self.ap.xray_dns_path_report()
        self.assertTrue(rep["ok"])
        self.assertEqual(rep["icon"], "✅")
        self.assertEqual(rep["chain"], "Xray → AGH:53 → DNSCrypt:5300")
        self.assertIn("AGH отвечает", rep["line"])

    def test_agh_service_dead(self):
        """Конфиг «AGH:53» + сервис неактивен → ⚠️ fallback, фильтры
        не применяются (главный сценарий, ради которого всё затевалось)."""
        with self._with_config(AGH_CFG), \
             patch.object(self.ap, "agh_service_active", return_value=False):
            rep = self.ap.xray_dns_path_report()
        self.assertFalse(rep["ok"])
        self.assertEqual(rep["icon"], "⚠️")
        self.assertIn("fallback", rep["line"])
        self.assertIn("не применяются", rep["line"])

    def test_agh_not_resolving(self):
        with self._with_config(AGH_CFG), \
             patch.object(self.ap, "agh_service_active", return_value=True), \
             patch.object(self.ap, "agh_owns_dns53", return_value=True), \
             patch.object(self.ap, "agh_probe_resolve",
                          return_value=(False, "таймаут")):
            rep = self.ap.xray_dns_path_report()
        self.assertFalse(rep["ok"])
        self.assertIn("не резолвит", rep["line"])

    def test_agh_does_not_own_port(self):
        """Сервис активен, но :53 не у AGH (resolved stub/wizard) → ⚠️."""
        with self._with_config(AGH_CFG), \
             patch.object(self.ap, "agh_service_active", return_value=True), \
             patch.object(self.ap, "agh_owns_dns53", return_value=False):
            rep = self.ap.xray_dns_path_report()
        self.assertFalse(rep["ok"])
        self.assertIn("не владеет :53", rep["line"])

    def test_dnscrypt_direct_active(self):
        def fake_run(cmd, **kw):
            if cmd[:2] == ["systemctl", "is-active"]:
                return MagicMock(returncode=0, stdout="active\n")
            return MagicMock(returncode=0, stdout="")

        with self._with_config(DNSCRYPT_CFG):
            rep = self.ap.xray_dns_path_report(run=fake_run)
        self.assertTrue(rep["ok"])
        self.assertEqual(rep["chain"], "Xray → DNSCrypt:5300")
        self.assertIn("интернет", rep["line"])

    def test_dnscrypt_direct_dead(self):
        def fake_run(cmd, **kw):
            if cmd[:2] == ["systemctl", "is-active"]:
                return MagicMock(returncode=3, stdout="inactive\n")
            return MagicMock(returncode=0, stdout="")

        with self._with_config(DNSCRYPT_CFG):
            rep = self.ap.xray_dns_path_report(run=fake_run)
        self.assertFalse(rep["ok"])
        self.assertIn("dnscrypt-proxy не активен", rep["line"])

    def test_public_dns(self):
        with self._with_config(PUBLIC_CFG):
            rep = self.ap.xray_dns_path_report()
        self.assertTrue(rep["ok"])
        self.assertEqual(rep["icon"], "ℹ️")
        self.assertIn("публичный", rep["line"])

    def test_no_side_effects_on_iptables(self):
        """Диагностика, а не лечение: dns53_redirect_* не вызываются."""
        with self._with_config(AGH_CFG), \
             patch.object(self.ap, "agh_service_active", return_value=False), \
             patch.object(self.ap, "dns53_redirect_state") as st, \
             patch.object(self.ap, "dns53_redirect_remove") as rm:
            self.ap.xray_dns_path_report()
        st.assert_not_called()
        rm.assert_not_called()

    def test_broken_json_falls_through(self):
        """Битый первый кандидат → пустой список (без исключений наружу)."""
        p = self._tmpdir / "config.json"
        p.write_text("{broken")
        with patch.object(self.ap, "_XRAY_CONFIG_CANDIDATES", (p,)):
            rep = self.ap.xray_dns_path_report()
        self.assertFalse(rep["ok"])


# ─────────────────────────────────────────────────────────────────────────────
#  2. health.py — health_check_dns_path в run_full_health_check
# ─────────────────────────────────────────────────────────────────────────────
class TestHealthCheckDnsPath(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        import chimera.modules.health as h
        importlib.reload(h)
        self.h = h
        self._tmpdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self._tmpdir, ignore_errors=True))

    def test_ok_calls_success(self):
        rep = {"ok": True, "icon": "✅", "chain": "Xray → AGH:53 → DNSCrypt:5300",
               "line": "DNS-путь: Xray → AGH:53 → DNSCrypt:5300 — AGH отвечает"}
        import chimera.modules.agh_probe as ap
        with patch.object(ap, "xray_dns_path_report", return_value=rep), \
             patch.object(self.h, "success") as ok:
            self.assertTrue(self.h.health_check_dns_path())
        ok.assert_called_once_with(rep["line"])

    def test_fail_calls_warn(self):
        rep = {"ok": False, "icon": "⚠️", "chain": "—",
               "line": "DNS-путь: конфиг указывает на AGH:53, но…"}
        import chimera.modules.agh_probe as ap
        with patch.object(ap, "xray_dns_path_report", return_value=rep), \
             patch.object(self.h, "warn") as w:
            self.assertFalse(self.h.health_check_dns_path())
        w.assert_called_once_with(rep["line"])

    def test_exception_warns_and_false(self):
        import chimera.modules.agh_probe as ap
        with patch.object(ap, "xray_dns_path_report",
                          side_effect=RuntimeError("boom")), \
             patch.object(self.h, "warn") as w:
            self.assertFalse(self.h.health_check_dns_path())
        self.assertIn("не удалось проверить", w.call_args.args[0])

    def test_run_full_health_check_includes_dns(self):
        """Полная проверка здоровья вызывает DNS-проверку; провал DNS-пути
        → статус degraded (конфиг «через AGH» + мёртвый AGH ≠ healthy)."""
        with patch.object(self.h, "health_check_xray", return_value=True), \
             patch.object(self.h, "health_check_dns_path",
                          return_value=False) as dns_chk, \
             patch.object(self.h, "health_check_nginx", return_value=True), \
             patch.object(self.h, "health_check_ssl", return_value=True), \
             patch.object(self.h, "health_check_ports", return_value=True), \
             patch.object(self.h, "HEALTH_CHECK_FILE",
                          self._tmpdir / "health.status"), \
             patch.object(self.h, "info"), \
             patch.object(self.h, "warn"), \
             patch.object(self.h, "success"):
            result = self.h.run_full_health_check()
        dns_chk.assert_called_once()
        self.assertFalse(result)
        self.assertEqual((self._tmpdir / "health.status").read_text(),
                         "degraded")

    def test_run_full_health_check_order_after_xray(self):
        """DNS-путь логически связан с Xray — проверка идёт сразу после
        health_check_xray, до Nginx/SSL."""
        src = _read("chimera/modules/health.py")
        i_xray = src.index("if not health_check_xray()")
        i_dns = src.index("if not health_check_dns_path()")
        i_nginx = src.index("if not health_check_nginx()")
        self.assertLess(i_xray, i_dns)
        self.assertLess(i_dns, i_nginx)


# ─────────────────────────────────────────────────────────────────────────────
#  3. health_report.py — DNS-строка в отчёте меню + cron-скрипт
# ─────────────────────────────────────────────────────────────────────────────
class TestHealthReportDnsLine(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        import chimera.modules.health_report as hr
        importlib.reload(hr)
        self.hr = hr
        self._tmpdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self._tmpdir, ignore_errors=True))
        # Фейковый core с минимальным набором для do_health_report
        core = sys.modules["chimera._core"]

        def fake_run(cmd, capture=False, check=False, quiet=False, **kw):
            out = ""
            if cmd[:2] == ["systemctl", "is-active"]:
                out = "active\n"
            elif cmd[0] == "hostname":
                out = "testhost\n"
            elif cmd[0] == "df":
                out = ("Filesystem Size Used Avail Use% Mounted on\n"
                       "/dev/vda1 40G 10G 30G 25% /\n")
            return MagicMock(returncode=0, stdout=out, stderr="")

        core._run = fake_run
        core.STATE_FILE = self._tmpdir / "missing-state.json"
        core.GEOSITE_DAT = self._tmpdir / "geosite.dat"
        core.GEOIP_DAT = self._tmpdir / "geoip.dat"
        core._tg_load = lambda: {}
        core.tg_send = lambda *a, **k: None
        core.log_to_file = lambda *a, **k: None

    def test_report_contains_dns_line(self):
        import chimera.modules.agh_probe as ap
        rep = {"ok": True, "icon": "✅",
               "chain": "Xray → AGH:53 → DNSCrypt:5300",
               "line": "DNS-путь: Xray → AGH:53 → DNSCrypt:5300 — AGH отвечает"}
        with patch.object(ap, "xray_dns_path_report", return_value=rep):
            text = self.hr.do_health_report(send_tg_flag=False)
        self.assertIn("DNS-путь: Xray → AGH:53 → DNSCrypt:5300", text)

    def test_report_dns_exception_handled(self):
        import chimera.modules.agh_probe as ap
        with patch.object(ap, "xray_dns_path_report",
                          side_effect=RuntimeError("boom")):
            text = self.hr.do_health_report(send_tg_flag=False)
        self.assertIn("DNS-путь: не удалось проверить", text)


class TestCronScriptDnsBlock(unittest.TestCase):
    """Stringified cron-скрипт: рендер компилируется + DNS-блок живой."""

    def setUp(self):
        _setup_core_in_sysmodules()
        import importlib
        import chimera.modules.health_report as hr
        importlib.reload(hr)
        self.hr = hr
        self._written = {}

        def fake_write(p, data, *a, **kw):
            self._written[str(p)] = data
            return len(data)

        with patch.object(Path, "write_text", fake_write), \
             patch.object(Path, "chmod", lambda s, *a, **k: None):
            self.hr._health_report_install_cron()
        self.sh = self._written.get("/usr/local/bin/xray-health-report.sh", "")
        start = self.sh.index('python3 -c "') + len('python3 -c "')
        end = self.sh.index('" 2>>', start)
        self.payload = (self.sh[start:end]
                        .replace('\\"', '"').replace("\\\\", "\\"))

    def test_payload_compiles(self):
        compile(self.payload, "<cron-health-report>", "exec")

    def test_dns_block_markers(self):
        for marker in ("AdGuardHome", "DNS: Xray → AGH:53 → DNSCrypt:5300",
                       "dnscrypt-proxy", "публичный", "127[.]0[.]0[.]1:53"):
            self.assertIn(marker, self.payload, msg=marker)

    def test_payload_agh_branch_line(self):
        """End-to-end exec отрендеренного cron-скрипта: конфиг «AGH:53» +
        активный AGH, владеющий :53 → строка «DNS: Xray → AGH:53 →
        DNSCrypt:5300» без пометки fallback, уходит в tg_send."""
        tg_cfg = {"token": "T", "chat_id": "C",
                  "events": {"health_report": True}}
        cfg = AGH_CFG
        sent = {}

        def fake_exists(self):
            s = str(self)
            return s in ("/var/lib/xray-installer/telegram.json",
                         "/etc/xray/config.json")

        def fake_read_text(self, *a, **kw):
            s = str(self)
            if s == "/var/lib/xray-installer/telegram.json":
                return json.dumps(tg_cfg)
            if s == "/etc/xray/config.json":
                return json.dumps(cfg)
            return ""

        def fake_subprocess_run(cmd, **kw):
            out = ""
            if cmd[:2] == ["systemctl", "is-active"]:
                out = "active\n"
            elif cmd[0] == "hostname":
                out = "cronhost\n"
            elif cmd[0] == "df":
                out = ("Filesystem Size Used Avail Use% Mounted on\n"
                       "/dev/vda1 40G 10G 30G 25% /\n")
            elif cmd[0] == "ss":
                out = ("udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* "
                       'users:(("AdGuardHome",pid=1,fd=6))\n')
            elif cmd[0] == "curl":
                # tg_send: '-d', 'text=<msg>'
                for i, arg in enumerate(cmd):
                    if arg.startswith("text="):
                        sent["text"] = arg[len("text="):]
                out = ""
            return MagicMock(returncode=0, stdout=out, stderr="")

        ns = {}
        with patch.object(Path, "exists", fake_exists), \
             patch.object(Path, "read_text", fake_read_text), \
             patch("subprocess.run", fake_subprocess_run):
            exec(self.payload, ns)

        self.assertIn("DNS: Xray → AGH:53 → DNSCrypt:5300", sent.get("text", ""))
        self.assertNotIn("fallback", sent.get("text", ""))

    def test_payload_agh_dead_branch(self):
        """AGH не активен → ⚠️-строка с пометкой про fallback."""
        tg_cfg = {"token": "T", "chat_id": "C",
                  "events": {"health_report": True}}
        sent = {}

        def fake_exists(self):
            return str(self) in ("/var/lib/xray-installer/telegram.json",
                                 "/etc/xray/config.json")

        def fake_read_text(self, *a, **kw):
            s = str(self)
            if s == "/var/lib/xray-installer/telegram.json":
                return json.dumps(tg_cfg)
            if s == "/etc/xray/config.json":
                return json.dumps(AGH_CFG)
            return ""

        def fake_subprocess_run(cmd, **kw):
            out = ""
            if cmd[:2] == ["systemctl", "is-active"]:
                # xray/nginx active, AdGuardHome — inactive
                out = ("inactive\n" if "AdGuardHome" in cmd else "active\n")
            elif cmd[0] == "hostname":
                out = "cronhost\n"
            elif cmd[0] == "df":
                out = ("Filesystem Size Used Avail Use% Mounted on\n"
                       "/dev/vda1 40G 10G 30G 25% /\n")
            elif cmd[0] == "curl":
                for i, arg in enumerate(cmd):
                    if arg.startswith("text="):
                        sent["text"] = arg[len("text="):]
            return MagicMock(returncode=0, stdout=out, stderr="")

        ns = {}
        with patch.object(Path, "exists", fake_exists), \
             patch.object(Path, "read_text", fake_read_text), \
             patch("subprocess.run", fake_subprocess_run):
            exec(self.payload, ns)

        self.assertIn("AGH не активен — запросы через fallback",
                      sent.get("text", ""))


# ─────────────────────────────────────────────────────────────────────────────
#  4. emergency_repair.py — DNS-строка в итоговом health-report (шаг 11/11)
# ─────────────────────────────────────────────────────────────────────────────
class TestEmergencyRepairDnsPath(unittest.TestCase):
    def test_final_report_contains_dns_path(self):
        """Шаг 11/11 вызывает xray_dns_path_report и выводит строку
        (ok → _box_ok с цепочкой, провал → _box_warn с диагнозом)."""
        src = _read("chimera/modules/emergency_repair.py")
        self.assertIn("from chimera.modules.agh_probe import "
                      "xray_dns_path_report", src)
        i_step11 = src.index("[11/11]")
        i_dns = src.index("xray_dns_path_report", i_step11)
        i_summary = src.index("Аварийное восстановление завершено", i_dns)
        self.assertLess(i_step11, i_dns)
        self.assertLess(i_dns, i_summary)

    def test_all_ok_not_touched_by_dns_path(self):
        """Провал DNS-пути НЕ валит итоговый all_ok — DNS жив через
        runtime-fallback (skipFallback=False), это диагностика."""
        src = _read("chimera/modules/emergency_repair.py")
        i_dns = src.index("xray_dns_path_report", src.index("[11/11]"))
        block_end = src.index("_box_row()\n    if all_ok:", i_dns)
        block = src[i_dns:block_end]
        self.assertNotIn("all_ok =", block.replace("all_ok ==", ""))

    def test_agh_probe_exports_report(self):
        import chimera.modules.agh_probe as ap
        self.assertTrue(callable(ap.xray_dns_path_report))


if __name__ == "__main__":
    unittest.main()
