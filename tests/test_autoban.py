#!/usr/bin/env python3
"""
tests/test_autoban.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/autoban.py.

Покрывает:
  1. _autoban_load / _autoban_save — JSON I/O с дефолтами
  2. _ban_report_append — добавление записи в отчёт
"""
from __future__ import annotations
import inspect, json, os, stat, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

def _setup_core():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text(); g = {}
    with patch.object(Path, 'mkdir', lambda s,*a,**k: None), \
         patch.object(Path, 'touch', lambda s,*a,**k: None), \
         patch.object(Path, 'chmod', lambda s,*a,**k: None), \
         patch('os.chown', lambda *a,**k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types; m = types.ModuleType("chimera._core"); m.__dict__.update(g)
    sys.modules["chimera._core"] = m

class TestAutobanLoadSave(unittest.TestCase):
    def setUp(self):
        _setup_core()
        self._tmp = Path(tempfile.mkdtemp())
        self._state = self._tmp / "autoban.json"
    def tearDown(self):
        import shutil; shutil.rmtree(self._tmp, ignore_errors=True)
    def _patch(self):
        return patch("chimera.modules.autoban._XRAY_BAN_STATE", self._state)
    def test_load_returns_defaults_when_no_file(self):
        from chimera.modules.autoban import _autoban_load
        with self._patch():
            data = _autoban_load()
        self.assertFalse(data["enabled"])
        self.assertIn("banned", data)
        self.assertIn("whitelist", data)
    def test_load_returns_defaults_on_corrupt(self):
        from chimera.modules.autoban import _autoban_load
        self._state.write_text("{invalid")
        with self._patch():
            data = _autoban_load()
        self.assertFalse(data["enabled"])
    def test_save_then_load(self):
        from chimera.modules.autoban import _autoban_load, _autoban_save
        with self._patch():
            _autoban_save({"enabled": True, "banned": {"1.2.3.4": {"count": 5}}})
            loaded = _autoban_load()
        self.assertTrue(loaded["enabled"])
        self.assertIn("1.2.3.4", loaded["banned"])
    def test_save_adds_ban_history(self):
        from chimera.modules.autoban import _autoban_load, _autoban_save
        with self._patch():
            _autoban_save({"enabled": True, "banned": {}})
            loaded = _autoban_load()
        self.assertIn("ban_history", loaded)
    def test_save_sets_chmod_600(self):
        from chimera.modules.autoban import _autoban_save
        with self._patch():
            _autoban_save({"enabled": False})
        mode = stat.S_IMODE(os.stat(self._state).st_mode)
        self.assertEqual(mode, 0o600)


class TestBanHistoryMigration(unittest.TestCase):
    """
    Регрессия: ранее cron-скрипт банил IP, но не добавлял запись
    в ban_history. Из-за этого у существующих инсталляций пункт меню
    [6] «История банов» показывал «История пуста» хотя banned-список
    был непустой. _autoban_load() теперь мигрирует banned → ban_history
    при первом открытии.
    """
    def setUp(self):
        _setup_core()
        self._tmp = Path(tempfile.mkdtemp())
        self._state = self._tmp / "autoban.json"
    def tearDown(self):
        import shutil; shutil.rmtree(self._tmp, ignore_errors=True)
    def _patch(self):
        return patch("chimera.modules.autoban._XRAY_BAN_STATE", self._state)

    def test_migrates_banned_to_history_when_history_empty(self):
        """Существующие баны (без истории) переносятся в ban_history."""
        from chimera.modules.autoban import _autoban_load, _autoban_save
        # Симулируем старый сломанный state: 3 бана, ban_history пуст
        with self._patch():
            _autoban_save({
                "enabled": True,
                "banned": {
                    "1.2.3.4": {"count": 10, "banned_at": "2026-08-02T14:10:00",
                                "reason": "10 TLS errors in 10min"},
                    "5.6.7.8": {"count": 15, "banned_at": "2026-08-03T08:55:00",
                                "reason": "15 TLS errors in 10min"},
                    "9.10.11.12": {"count": 64, "banned_at": "2026-08-09T18:40:00",
                                   "reason": "64 TLS errors in 10min"},
                },
                # ban_history не указан — старый формат
            })
            loaded = _autoban_load()
        # После миграции ban_history должен содержать 3 записи
        self.assertEqual(len(loaded["ban_history"]), 3)
        ips_in_history = {r["ip"] for r in loaded["ban_history"]}
        self.assertEqual(ips_in_history, {"1.2.3.4", "5.6.7.8", "9.10.11.12"})
        # banned-словарь не должен пострадать
        self.assertEqual(len(loaded["banned"]), 3)
        # unbanned_at должен быть None (они ещё активны)
        for rec in loaded["ban_history"]:
            self.assertIsNone(rec["unbanned_at"])

    def test_no_migration_when_history_already_present(self):
        """Если ban_history уже есть — миграция не трогает его."""
        from chimera.modules.autoban import _autoban_load, _autoban_save
        with self._patch():
            _autoban_save({
                "enabled": True,
                "banned": {"1.2.3.4": {"count": 10, "banned_at": "2026-08-02T14:10:00"}},
                "ban_history": [
                    {"ip": "9.9.9.9", "banned_at": "2026-01-01T00:00:00",
                     "unbanned_at": "2026-01-02T00:00:00", "count": 5, "reason": "old"}
                ],
            })
            loaded = _autoban_load()
        # История осталась как была — 1 запись, не 2
        self.assertEqual(len(loaded["ban_history"]), 1)
        self.assertEqual(loaded["ban_history"][0]["ip"], "9.9.9.9")

    def test_no_migration_when_banned_empty(self):
        """Если banned пуст — миграция не создаёт пустой ban_history."""
        from chimera.modules.autoban import _autoban_load, _autoban_save
        with self._patch():
            _autoban_save({"enabled": True, "banned": {}})
            loaded = _autoban_load()
        self.assertEqual(loaded["ban_history"], [])


class TestCronScriptWritesHistory(unittest.TestCase):
    """
    Регрессия: проверяем что встроенный Python-скрипт внутри
    _autoban_install_cron() содержит код добавления ban_history.
    Раньше он только инициализировал пустой список, но не append'ил.
    """
    def test_cron_script_contains_ban_history_append(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" / "autoban.py").read_text()
        # Извлекаем тело встроенного скрипта
        import re
        m = re.search(r'py_body = f"""(.*?)"""', src, re.DOTALL)
        self.assertIsNotNone(m, "py_body f-string не найден в исходнике")
        body = m.group(1)
        # Проверяем наличие ключевых маркеров фикса
        self.assertIn("cfg['ban_history'].append(", body,
                      "cron-скрипт не append'ит в ban_history — регрессия!")
        self.assertIn("'unbanned_at': None", body,
                      "cron-скрипт не задаёт unbanned_at=None в записях истории")
        self.assertIn("'banned_at':   _ban_ts", body,
                      "cron-скрипт не сохраняет banned_at в записях истории")

    def test_cron_script_truncates_history_at_500(self):
        """История не должна расти бесконечно — лимит 500 записей."""
        src = (_PROJECT_ROOT / "chimera" / "modules" / "autoban.py").read_text()
        import re
        m = re.search(r'py_body = f"""(.*?)"""', src, re.DOTALL)
        body = m.group(1)
        self.assertIn("len(cfg['ban_history']) > 500", body)
        self.assertIn("cfg['ban_history'][-500:]", body)


class TestServerOwnIPsWhitelist(unittest.TestCase):
    """
    Регрессия: сервер не должен банить свой собственный IP.
    Раньше _autoban_get_chain_ips() добавлял только IP нод каскада,
    но не собственные IP сервера. При TLS-handshake ошибках от
    loopback/health-check сервер банил сам себя.
    """
    def setUp(self):
        _setup_core()
    def test_get_server_own_ips_function_exists(self):
        """Функция _get_server_own_ips() определена."""
        from chimera.modules import autoban
        self.assertTrue(callable(getattr(autoban, '_get_server_own_ips', None)),
                        "_get_server_own_ips() не определена")

    def test_get_server_own_ips_returns_list(self):
        """Возвращает список строк (даже если пустой)."""
        from chimera.modules import autoban
        ips = autoban._get_server_own_ips()
        self.assertIsInstance(ips, list)
        for ip in ips:
            self.assertIsInstance(ip, str)

    def test_chain_ips_includes_server_own_ips(self):
        """_autoban_get_chain_ips() включает собственные IP сервера."""
        from chimera.modules import autoban
        own_ips = set(autoban._get_server_own_ips())
        chain_ips = set(autoban._autoban_get_chain_ips())
        # Все собственные IP должны быть в chain_ips
        for ip in own_ips:
            self.assertIn(ip, chain_ips,
                         f"Собственный IP {ip} не попал в chain_ips — сервер может забанить сам себя")

    def test_cron_script_detects_server_own_ips(self):
        """Cron-скрипт определяет собственные IP сервера и добавляет в whitelist."""
        src = (_PROJECT_ROOT / "chimera" / "modules" / "autoban.py").read_text()
        import re
        m = re.search(r'py_body = f"""(.*?)"""', src, re.DOTALL)
        self.assertIsNotNone(m, "py_body f-string не найден")
        body = m.group(1)
        # Проверяем наличие команд определения IP сервера
        self.assertIn("'ip', 'route', 'get'", body,
                      "cron-скрипт не определяет primary IP через ip route get")
        self.assertIn("'ip', '-4', 'addr'", body,
                      "cron-скрипт не получает все интерфейсные IP через ip -4 addr show")
        self.assertIn("whitelist.add(_candidate)", body,
                      "cron-скрипт не добавляет primary IP в whitelist")
        self.assertIn("whitelist.add(_ip)", body,
                      "cron-скрипт не добавляет интерфейсные IP в whitelist")


class TestBanReportFileSync(unittest.TestCase):
    """
    Регрессия: файл отчёта /var/log/xray-ban-report.txt должен создаваться
    при миграции ban_history и при банах из cron-скрипта.
    Раньше: пункт [6] показывал историю (из JSON), а файл отчёта был пуст
    со статусом «не создан (появится после первого бана)» — несостыковка.
    """
    def test_migration_writes_to_report_file(self):
        """При миграции banned→ban_history также пишем в файл отчёта."""
        from chimera.modules import autoban
        tmp = Path(tempfile.mkdtemp())
        state_file = tmp / "autoban.json"
        report_file = tmp / "xray-ban-report.txt"
        import shutil
        try:
            # Create a fake core module with _lookup_asn returning empty dict
            import types
            fake_core = types.ModuleType("chimera._core_fake")
            fake_core._lookup_asn = lambda ip: {}
            fake_core.STATE_FILE = tmp / "nonexistent_state.json"

            with patch("chimera.modules.autoban._XRAY_BAN_STATE", state_file), \
                 patch("chimera.modules.autoban._XRAY_BAN_REPORT", report_file), \
                 patch("chimera.modules.autoban._core_module", return_value=fake_core):
                # Pre-existing state: 2 bans, no ban_history
                state_file.write_text(json.dumps({
                    "enabled": True,
                    "banned": {
                        "1.2.3.4": {"count": 10, "banned_at": "2026-08-13T02:20:00",
                                    "reason": "10 TLS errors in 10min"},
                        "5.6.7.8": {"count": 15, "banned_at": "2026-08-13T00:25:00",
                                    "reason": "15 TLS errors in 10min"},
                    },
                }))
                # Trigger migration via _autoban_load
                loaded = autoban._autoban_load()
            # After migration: ban_history has 2 entries
            self.assertEqual(len(loaded["ban_history"]), 2)
            # Report file should now exist (created during migration)
            self.assertTrue(report_file.exists(),
                           "Файл отчёта не создан при миграции — несостыковка с историей")
            # Report file should contain both IPs
            content = report_file.read_text()
            self.assertIn("1.2.3.4", content)
            self.assertIn("5.6.7.8", content)
            self.assertIn("ЗАБЛОКИРОВАН:", content)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_cron_script_writes_to_report_file(self):
        """Cron-скрипт пишет в файл отчёта при банах."""
        src = (_PROJECT_ROOT / "chimera" / "modules" / "autoban.py").read_text()
        import re
        m = re.search(r'py_body = f"""(.*?)"""', src, re.DOTALL)
        self.assertIsNotNone(m, "py_body f-string не найден")
        body = m.group(1)
        self.assertIn("xray-ban-report.txt", body,
                      "cron-скрипт не пишет в файл отчёта")
        self.assertIn("ЗАБЛОКИРОВАН:", body,
                      "cron-скрипт не форматирует запись отчёта")


class TestFwRuleOrdering(unittest.TestCase):
    """
    Регрессия кейса AS25369 (2026-09-21): `ufw deny from X` добавляется
    в КОНЕЦ ufw-user-input — ПОСЛЕ allow-правил портов (configure_firewall
    → ufw allow 22/80/SERVER_PORT) → first-match-wins пропускал
    нарушителей на открытые порты: баны росли в state, трафик тек.
    Теперь deny ставится ПЕРВОЙ строкой (ufw insert 1) — в TUI-пути
    и в cron-скрипте; для существующих банов — миграция через
    _fw_repair_order (меню [F]).
    """

    def test_fw_ban_uses_ufw_insert_1(self):
        from chimera.modules import autoban
        src = inspect.getsource(autoban._fw_ban)
        self.assertIn('"ufw", "insert", "1", "deny"', src,
                      "_fw_ban не ставит deny первой строкой ufw-user-input")

    def test_fw_repair_order_exists(self):
        from chimera.modules import autoban
        self.assertTrue(callable(getattr(autoban, "_fw_repair_order", None)),
                        "_fw_repair_order не определена (миграция старых правил)")

    def test_cron_script_uses_ufw_insert_1(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" / "autoban.py").read_text()
        import re
        m = re.search(r'py_body = f"""(.*?)"""', src, re.DOTALL)
        self.assertIsNotNone(m, "py_body не найден")
        body = m.group(1)
        self.assertIn("'ufw','insert','1','deny'", body,
                      "cron-скрипт не ставит deny первой строкой")
        self.assertNotIn("['ufw','deny','from',ip", body,
                         "cron-скрипт вернулся к deny в конец ufw-user-input")


class TestCronScriptAsnLookup(unittest.TestCase):
    """
    Регрессия кейса vds14808 (2026-09-20): история банов из cron шла с
    прочерками «ASN: — (cron-скрипт, без ASN-lookup)». Теперь cron сам
    делает lookup (ip-api.com, тот же endpoint что asn_cache) с
    файл-кешем, пишет asn/isp/org в ban_history и в отчёт.
    """

    def _py_body(self) -> str:
        import re
        src = (_PROJECT_ROOT / "chimera" / "modules" / "autoban.py").read_text()
        m = re.search(r'py_body = f"""(.*?)"""', src, re.DOTALL)
        self.assertIsNotNone(m, "py_body не найден")
        return m.group(1)

    def test_lookup_asn_function_in_cron(self):
        body = self._py_body()
        self.assertIn("def lookup_asn(ip):", body)
        # py_body — ШАБЛОН f-string: литеральные скобки удвоены
        self.assertIn("ip-api.com/json/{{ip}}?fields=as,org,isp,status", body)
        self.assertIn("autoban_asn_cache.json", body,
                      "нет файл-кеша ASN (повторные баны дёргают API)")
        self.assertIn("ASN_CACHE_TTL", body)

    def test_ban_history_entry_contains_asn_fields(self):
        body = self._py_body()
        self.assertIn("'asn':         _asn.get('asn', '')", body)
        self.assertIn("'isp':         _asn.get('isp', '')", body)
        self.assertIn("'org':         _asn.get('org', '')", body)

    def test_report_block_has_real_values(self):
        body = self._py_body()
        self.assertIn("ASN:         {{_asn_v}}", body)
        self.assertIn("Провайдер:   {{_isp_v}}", body)
        self.assertIn("Организация: {{_org_v}}", body)
        self.assertNotIn("ASN:         — (cron-скрипт", body,
                         "возврат к прочерку без ASN-lookup")

    def test_lookup_asn_cache_roundtrip(self):
        """Сгенерированный lookup_asn реально работает: API-мок + кеш."""
        import re as _re
        src = (_PROJECT_ROOT / "chimera" / "modules" / "autoban.py").read_text()
        m = _re.search(r'py_body = f"""(.*?)"""', src, _re.DOTALL)
        generated = eval(f'f"""{m.group(1)}"""', {"threshold": 20, "window": 10})
        m2 = _re.search(
            r"ASN_CACHE_F\s*=.*?(?=\n#  DoH-resolver|\ndef _resolve_fresh)",
            generated, _re.DOTALL)
        self.assertIsNotNone(m2, "фрагмент lookup_asn не найден")
        snippet = m2.group(0)

        tmp = Path(tempfile.mkdtemp())
        cache_f = tmp / "asn_cache.json"
        snippet = snippet.replace(
            "Path('/var/lib/xray-installer/autoban_asn_cache.json')",
            f"Path('{cache_f}')")

        # мок urlopen: ip-api возвращает success-JSON (контекст-менеджер)
        _resp = MagicMock()
        _resp.read.return_value = json.dumps(
            {"status": "success", "as": "AS63737 VIETSERVER",
             "org": "YUH", "isp": "VIETSERVER"}).encode()
        _resp.__enter__.return_value = _resp
        import urllib.request as _ur
        g: dict = {}
        exec("import json, re, time\nfrom pathlib import Path\n" + snippet, g)
        with patch.object(_ur, "urlopen", return_value=_resp):
            info = g["lookup_asn"]("203.0.113.118")
        self.assertEqual(info["asn"], "AS63737 VIETSERVER")
        self.assertEqual(info["isp"], "VIETSERVER")
        self.assertEqual(info["org"], "YUH")
        self.assertTrue(cache_f.exists(), "кеш-файл не создан")

        # второй вызов — из памяти, urlopen не нужен
        with patch.object(_ur, "urlopen",
                          side_effect=AssertionError("не из кеша")):
            info2 = g["lookup_asn"]("203.0.113.118")
        self.assertEqual(info2["asn"], "AS63737 VIETSERVER")


class TestTuiHistoryAsnFields(unittest.TestCase):
    """TUI-скан (_autoban_run_once) и меню [6]: ASN-поля в записях."""

    def test_run_once_history_contains_asn_fields(self):
        from chimera.modules import autoban
        src = inspect.getsource(autoban._autoban_run_once)
        self.assertIn('"asn":         _asn.get("asn", "")', src)
        self.assertIn('"isp":         _asn.get("isp", "")', src)
        self.assertIn('"org":         _asn.get("org", "")', src)

    def test_history_menu_prefers_stored_fields(self):
        """Меню [6] берёт ASN из записи (если есть), иначе lookup на лету."""
        from chimera.modules import autoban
        src = inspect.getsource(autoban.do_manage_autoban)
        self.assertIn('rec.get("asn") or rec.get("isp") or rec.get("org")', src)
        self.assertIn("_lookup_asn(_ip)", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
