#!/usr/bin/env python3
"""
tests/test_cdn_ranges.py
───────────────────────────────────────────────────────────────────────────────
CDN-защита авто-бана (инцидент 2026-10-29: 950 банов edge-IP Cloudflare).

Домен/подписки за CF-прокси → error.log Xray видит источником TLS-ошибок
edge-IP Cloudflare (CF ротирует пулы) → авто-бан банил edge (self-DoS),
реальный атакующий за CF недостижим. Класс закрыт тремя барьерами:

  1. chimera/modules/cdn_ranges.py — статические CIDR Cloudflare v4/v6
     + ip_in_cdn() (офлайн, для автономного cron-скрипта без сети)
  2. гард в скане (_autoban_run_once + cron-шаблон): CDN-IP не кандидат
  3. гард в _fw_ban/fw_ban: отказ бана даже при прямом вызове
     + АВТО-ХИЛ: баны CDN-сетей, поставленные старыми версиями,
     снимаются сами (TUI-путь — батчем _fw_unban_batch; cron — по-IP).

Покрывает:
  • константы CIDR парсятся, инцидентные IP из живого скрина — в CDN
  • ip_in_cdn / cdn_provider_for / cdn_providers_label
  • _fw_ban отказывает для CDN-IP (без вызова ufw/iptables)
  • _autoban_run_once: CDN-IP не банится при превышении порога,
    не-CDN атакующий банится как раньше
  • _autoban_heal_cdn: снимает CDN-баны, закрывает историю unbanned_at,
    не трогает обычные баны, батч вызывается ровно с CDN-целями
  • cron-шаблон: маркеры CDN-гарда в исходнике + рендер валидного
    Python с реальными CIDR (compile без SyntaxError)
  • TUI: статус-строка «CDN-защита» и пункт меню [C]
"""
from __future__ import annotations
import inspect, json, re, sys, tempfile, unittest
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    """Минимальный стаб chimera._core (как test_autoban, но легче:
    autoban-путям нужны только log_to_file/_tg_notify_event/_lookup_asn/_run).
    """
    stub = SimpleNamespace(
        log_to_file=lambda *a, **k: None,
        _tg_notify_event=lambda *a, **k: None,
        _lookup_asn=lambda ip: {"asn": "", "isp": "", "org": ""},
        _run=lambda cmd, **kw: MagicMock(returncode=0, stdout=""),
        success=lambda *a, **k: None,
        info=lambda *a, **k: None,
        warn=lambda *a, **k: None,
    )
    import types
    m = types.ModuleType("chimera._core")
    m.__dict__.update(stub.__dict__)
    sys.modules["chimera._core"] = m
    import chimera as _pkg
    _pkg._core = m


# ── инцидентные IP из живого скрина ноды (2026-10-29) ───────────────────────
_INCIDENT_CDN_IPS = [
    "141.101.84.181",   # AS13335, 141.101.64.0/18
    "172.70.216.112",   # AS13335, 172.64.0.0/13
    "172.69.228.140",   # AS14789, 172.64.0.0/13
    "104.22.5.132",     # AS14789, 104.16.0.0/13
    "172.68.166.176",   # AS13335, 172.64.0.0/13
    "172.68.65.131",    # AS14789, 172.64.0.0/13
    "172.68.86.134",    # AS13335, 172.64.0.0/13
    "104.22.199.133",   # 104.16.0.0/13
    "172.69.157.150",   # AS14789, 172.64.0.0/13
    "162.158.98.135",   # AS14789, 162.158.0.0/15
]
_NON_CDN_IPS = [
    "203.0.113.66",     # TEST-NET-3 — атакующий (не CDN)
    "198.51.100.7",     # TEST-NET-2
    "192.0.2.44",       # TEST-NET-1
    "8.8.8.8",
]


class TestCdnRangesStatic(unittest.TestCase):
    """Константы и хелперы chimera/modules/cdn_ranges.py."""

    def test_all_cidrs_parse_as_networks(self):
        import ipaddress
        from chimera.modules import cdn_ranges
        for cidr in cdn_ranges.cdn_cidrs_compact():
            ipaddress.ip_network(cidr, strict=False)  # ValueError = тест красный
        self.assertGreaterEqual(len(cdn_ranges.CLOUDFLARE_V4), 15)
        self.assertGreaterEqual(len(cdn_ranges.CLOUDFLARE_V6), 7)

    def test_incident_ips_are_cdn(self):
        from chimera.modules.cdn_ranges import ip_in_cdn
        for ip in _INCIDENT_CDN_IPS:
            self.assertTrue(ip_in_cdn(ip),
                            f"инцидентный IP {ip} не распознан как CDN — "
                            f"гвард не сработал бы")

    def test_non_cdn_ips_not_in_cdn(self):
        from chimera.modules.cdn_ranges import ip_in_cdn
        for ip in _NON_CDN_IPS:
            self.assertFalse(ip_in_cdn(ip),
                             f"{ip} ошибочно попал в CDN — бан атакующих сломается")

    def test_cloudflare_ipv6_in_cdn(self):
        from chimera.modules.cdn_ranges import ip_in_cdn
        self.assertTrue(ip_in_cdn("2606:4700:4700::1111"))
        self.assertTrue(ip_in_cdn("2400:cb00:f021:5c9:be5f:22a2:e4c2:4d1a"))
        self.assertFalse(ip_in_cdn("2001:db8::1"))  # doc-диапазон

    def test_garbage_ip_is_not_cdn_and_not_crash(self):
        from chimera.modules.cdn_ranges import ip_in_cdn, cdn_provider_for
        self.assertFalse(ip_in_cdn("not-an-ip"))
        self.assertFalse(ip_in_cdn(""))
        self.assertIsNone(cdn_provider_for("not-an-ip"))

    def test_provider_for_and_label(self):
        from chimera.modules.cdn_ranges import cdn_provider_for, cdn_providers_label
        self.assertEqual(cdn_provider_for("104.22.5.132"), "cloudflare")
        self.assertIsNone(cdn_provider_for("203.0.113.66"))
        self.assertIn("Cloudflare", cdn_providers_label())

    def test_network_boundaries_exact(self):
        """Границы подсетей: первый/последний адрес 172.64.0.0/13 — CDN,
        соседние (172.63.255.255 / 172.72.0.0) — нет."""
        from chimera.modules.cdn_ranges import ip_in_cdn
        self.assertTrue(ip_in_cdn("172.64.0.0"))
        self.assertTrue(ip_in_cdn("172.71.255.255"))
        self.assertFalse(ip_in_cdn("172.63.255.255"))
        self.assertFalse(ip_in_cdn("172.72.0.0"))


class TestFwBanCdnGuard(unittest.TestCase):
    """_fw_ban отказывает для CDN-IP ДО любого вызова ufw/iptables."""

    def setUp(self):
        _setup_core()

    def test_fw_ban_refuses_cdn_without_fw_call(self):
        from chimera.modules import autoban
        # гард стоит ДО _core_module()/_run: поднимаем исключение,
        # если код дошёл до фаервола — значит гард не сработал.
        def _boom(*a, **k):
            raise AssertionError("_fw_ban дошёл до фаервола для CDN-IP!")
        with patch.object(autoban, "_core_module", _boom), \
             patch("shutil.which", _boom):
            for ip in _INCIDENT_CDN_IPS:
                self.assertFalse(autoban._fw_ban(ip),
                                 f"_fw_ban не отказал для CDN-IP {ip}")

    def test_fw_ban_allows_non_cdn(self):
        """Обычный атакующий проходит в фаервол как раньше (не блокируется гардом)."""
        from chimera.modules import autoban
        calls = []
        core = SimpleNamespace(_run=lambda cmd, **kw: (calls.append(cmd),
                                                      MagicMock(returncode=0))[1])
        with patch.object(autoban, "_core_module", lambda: core), \
             patch("shutil.which", lambda n: "/usr/sbin/ufw"):
            self.assertTrue(autoban._fw_ban("203.0.113.66"))
        self.assertEqual(len(calls), 1)
        self.assertIn("203.0.113.66", calls[0])


class _RunOnceBase(unittest.TestCase):
    """Общее окружение для интеграции с _autoban_run_once/_autoban_heal_cdn."""

    def setUp(self):
        _setup_core()
        self._tmp = Path(tempfile.mkdtemp())
        self._state = self._tmp / "autoban.json"
        self._errlog = self._tmp / "error.log"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write_state(self, banned: dict, history: list | None = None) -> None:
        self._state.write_text(json.dumps({
            "enabled": True, "threshold": 10, "window_min": 10,
            "whitelist": ["127.0.0.1", "::1"],
            "banned": banned,
            "ban_history": history or [],
        }))

    def _write_errlog(self, counts: dict) -> None:
        """counts: {ip: n} — n свежих TLS-ошибок от каждого IP."""
        ts = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        lines = []
        for ip, n in counts.items():
            lines += [f"{ts} {ip}:8888 [tcp] tls: handshake failure: "
                      f"remote error: tls: bad certificate"] * n
        self._errlog.write_text("\n".join(lines) + "\n")

    def _patches(self, fw_ban=None, unban_batch=None):
        """Список патчей; применять ЧЕРЕЗ ExitStack (все одновременно)."""
        from chimera.modules import autoban
        return [
            patch.object(autoban, "_XRAY_BAN_STATE", self._state),
            patch.object(autoban, "_XRAY_ERROR_LOG", self._errlog),
            patch.object(autoban, "_autoban_get_chain_ips", lambda: []),
            patch.object(autoban, "_fw_ban", fw_ban or (lambda ip: True)),
            patch.object(autoban, "_fw_unban_batch", unban_batch or (lambda ips: len(ips))),
        ]

    def _enter(self, **kw):
        """ExitStack со всеми патчами: with self._enter() as ...: / stack."""
        stack = ExitStack()
        for p in self._patches(**kw):
            stack.enter_context(p)
        return stack


class TestRunOnceCdnGuard(_RunOnceBase):
    """Скан: CDN-IP не кандидат на бан даже при превышении порога."""

    def test_cdn_ip_not_banned_above_threshold(self):
        from chimera.modules import autoban
        banned_calls: list = []
        self._write_state(banned={})
        # 15 ошибок от CF-edge (порог 10) + 15 от реального атакующего
        self._write_errlog({"141.101.84.181": 15, "203.0.113.66": 15})
        fw_ban = lambda ip: (banned_calls.append(ip), True)[1]
        with self._enter(fw_ban=fw_ban):
            new_bans = autoban._autoban_run_once()
        # Банился ТОЛЬКО атакующий; CF-edge проигнорирован гардом
        self.assertEqual(banned_calls, ["203.0.113.66"],
                         f"CDN-гард в скане не сработал: {banned_calls}")
        self.assertEqual(new_bans, 1)
        cfg = json.loads(self._state.read_text())
        self.assertNotIn("141.101.84.181", cfg["banned"])
        self.assertIn("203.0.113.66", cfg["banned"])

    def test_all_incident_ips_ignored_by_scan(self):
        """Все 10 инцидентных IP со скрина — по 15 ошибок, ни один не баним."""
        from chimera.modules import autoban
        self._write_state(banned={})
        counts = {ip: 15 for ip in _INCIDENT_CDN_IPS}
        self._write_errlog(counts)
        banned_calls: list = []
        with self._enter(fw_ban=lambda ip: (banned_calls.append(ip), True)[1]):
            autoban._autoban_run_once()
        self.assertEqual(banned_calls, [],
                         "скан по-прежнему предлагает к бану CDN-IP")


class TestAutobanHealCdn(_RunOnceBase):
    """Авто-хил: баны CDN-сетей из state снимаются, обычные — остаются."""

    def test_heal_removes_cdn_keeps_regular(self):
        from chimera.modules import autoban
        ts_old = "2026-10-29T15:47:00"
        self._write_state(
            banned={
                "141.101.84.181": {"count": 15, "banned_at": ts_old, "reason": "x"},
                "172.70.216.112": {"count": 15, "banned_at": ts_old, "reason": "x"},
                "203.0.113.66":   {"count": 15, "banned_at": ts_old, "reason": "x"},
            },
            history=[
                {"ip": "141.101.84.181", "banned_at": ts_old, "unbanned_at": None,
                 "count": 15, "reason": "x", "asn": "AS13335", "isp": "", "org": ""},
                {"ip": "203.0.113.66", "banned_at": ts_old, "unbanned_at": None,
                 "count": 15, "reason": "x", "asn": "", "isp": "", "org": ""},
            ],
        )
        unban_targets: list = []
        with self._enter(unban_batch=lambda ips: (unban_targets.extend(ips), len(ips))[1]):
            cfg = autoban._autoban_load()
            n = autoban._autoban_heal_cdn(cfg)
        self.assertEqual(n, 2)
        # FW-батч вызван ровно с двумя CDN-целями
        self.assertEqual(sorted(unban_targets),
                         ["141.101.84.181", "172.70.216.112"])
        # state: CDN-банов нет, обычный бан на месте
        cfg = json.loads(self._state.read_text())
        self.assertNotIn("141.101.84.181", cfg["banned"])
        self.assertNotIn("172.70.216.112", cfg["banned"])
        self.assertIn("203.0.113.66", cfg["banned"])
        # история: CDN-записи закрыты unbanned_at, обычная — активна
        by_ip = {h["ip"]: h for h in cfg["ban_history"]}
        self.assertIsNotNone(by_ip["141.101.84.181"]["unbanned_at"])
        self.assertIsNone(by_ip["203.0.113.66"]["unbanned_at"])

    def test_heal_noop_without_cdn_bans(self):
        from chimera.modules import autoban
        self._write_state(banned={"203.0.113.66": {"count": 15}})
        called = []
        with self._enter(unban_batch=lambda ips: called.extend(ips) or len(ips)):
            cfg = autoban._autoban_load()
            n = autoban._autoban_heal_cdn(cfg)
        self.assertEqual(n, 0)
        self.assertEqual(called, [])
        cfg = json.loads(self._state.read_text())
        self.assertIn("203.0.113.66", cfg["banned"])

    def test_run_once_heals_before_missing_errlog_exit(self):
        """Хил срабатывает даже когда error.log отсутствует (ранний return 0) —
        нода самолечится сразу после обновления, без нового трафика."""
        from chimera.modules import autoban
        self._write_state(banned={"104.22.5.132": {"count": 15}})
        # error.log НЕ создаём
        with self._enter():
            new_bans = autoban._autoban_run_once()
        self.assertEqual(new_bans, 0)
        cfg = json.loads(self._state.read_text())
        self.assertNotIn("104.22.5.132", cfg["banned"],
                         "хил не отработал на раннем выходе без error.log")


class TestCronScriptCdn(unittest.TestCase):
    """Автономный cron-скрипт: CDN-гвард + авто-хил в шаблоне _autoban_install_cron."""

    def _py_body_source(self) -> str:
        src = (_PROJECT_ROOT / "chimera" / "modules" / "autoban.py").read_text()
        m = re.search(r'py_body = f"""(.*?)"""', src, re.DOTALL)
        self.assertIsNotNone(m, "py_body f-string не найден в исходнике")
        return m.group(1)

    def test_cron_script_contains_cdn_markers(self):
        body = self._py_body_source()
        self.assertIn("CDN_NETS", body)
        self.assertIn("def _in_cdn(ip):", body)
        self.assertIn("CDN AUTO-UNBAN", body,
                      "cron-скрипт не пишет запись авто-хила в лог")
        # гард в скане: CDN-проверка до whitelist-проверки
        self.assertLess(body.index("if _in_cdn(im.group(1)): continue"),
                        body.index("if _wl_hit(im.group(1)): continue"))
        # гард в fw_ban: отказ до вызова ufw
        self.assertLess(body.index("if _in_cdn(ip):"),
                        body.index("'ufw','insert','1','deny'"))

    def test_cron_script_renders_valid_python_with_real_cidrs(self):
        """Рендер шаблона целиком: extract → unescape → compile.
        Ловит битые f-string-эскейпы {{}} и потерянные интерполяции."""
        _setup_core()
        from chimera.modules import autoban
        tmp = Path(tempfile.mkdtemp())
        try:
            script = tmp / "xray-autoban.sh"
            cron = tmp / "xray-autoban-cron"
            with patch.object(autoban, "_XRAY_BAN_SCRIPT", script), \
                 patch.object(autoban, "_XRAY_BAN_CRON", cron):
                autoban._autoban_install_cron(10, 10)
            self.assertTrue(script.exists(), "cron-скрипт не записан")
            raw = script.read_text()
            # bash-обёртка: #!/bin/bash / python3 - <<'PYEOF' ... PYEOF
            m = re.search(r"python3 - <<'PYEOF'\n(.*)\nPYEOF", raw, re.DOTALL)
            self.assertIsNotNone(m, "PYEOF-обёртка не найдена")
            body = m.group(1)
            compile(body, "cron_render", "exec")  # SyntaxError = тест красный
            # реальные CIDR из cdn_ranges интерполированы в скрипт
            from chimera.modules.cdn_ranges import cdn_cidrs_compact
            for cidr in cdn_cidrs_compact():
                self.assertIn(cidr, body, f"CIDR {cidr} не попал в cron-скрипт")
            self.assertIn("_cdn_banned", body)
            self.assertIn("ufw','delete','deny'", body)
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


class TestTuiCdnMarkers(unittest.TestCase):
    """TUI-меню авто-бана: статус «CDN-защита» + пункт [C] с хилом."""

    def test_status_row_and_menu_item(self):
        from chimera.modules import autoban
        src_menu = inspect.getsource(autoban.do_manage_autoban)
        self.assertIn("CDN-защита:", src_menu,
                      "нет статус-строки CDN-защиты в главном экране")
        self.assertIn('_box_item("C"', src_menu,
                      "нет пункта меню [C] — разбан CDN вручную")
        self.assertIn('ch == "c"', src_menu,
                      "нет обработчика пункта [C]")
        self.assertIn("_autoban_heal_cdn(cfg)", src_menu,
                      "меню [C] не вызывает хил")

    def test_run_once_calls_heal(self):
        from chimera.modules import autoban
        src = inspect.getsource(autoban._autoban_run_once)
        self.assertIn("_autoban_heal_cdn(cfg)", src,
                      "_autoban_run_once не вызывает авто-хил CDN")


if __name__ == "__main__":
    unittest.main()
