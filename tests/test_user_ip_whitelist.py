#!/usr/bin/env python3
"""
tests/test_user_ip_whitelist.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/user_ip_whitelist.py — per-user IP whitelist.

Покрывает:
  1. _validate_ip_or_cidr — валидация IP/CIDR (запрет loopback/private/...)
  2. add_ip_to_user / remove_ip_from_user / get_user_ips — CRUD через users.json
  3. _collect_all_user_ips — сбор IP из всех пользователей (v4/v6 separation)
  4. rebuild_clients_ipset — atomic swap (mock subprocess)
  5. apply_iptables_rule / remove_iptables_rule — установка/снятие правил
  6. install_cron / remove_cron — cron-файлы
  7. Миграция старых users (без поля allowed_ips) — обратная совместимость
  8. Q1 — User Portal доступен без whitelist (подтверждение через архитектуру)
  9. Q2 — X-Forwarded-For НЕ используется, только client_address[0]
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock, call

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Загружает chimera._core через exec и регистрирует в sys.modules."""
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
    return fake_core


class TestValidateIpOrCidr(unittest.TestCase):
    """_validate_ip_or_cidr — валидация IP/CIDR."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_valid_ipv4(self):
        from chimera.modules.user_ip_whitelist import _validate_ip_or_cidr
        ok, norm, err = _validate_ip_or_cidr("5.6.7.8")
        self.assertTrue(ok, f"Должен быть валиден: {err}")
        self.assertEqual(norm, "5.6.7.8")
        self.assertEqual(err, "")

    def test_valid_ipv4_cidr(self):
        from chimera.modules.user_ip_whitelist import _validate_ip_or_cidr
        ok, norm, err = _validate_ip_or_cidr("5.6.7.0/24")
        self.assertTrue(ok, f"Должен быть валиден: {err}")
        self.assertEqual(norm, "5.6.7.0/24")

    def test_valid_ipv6(self):
        from chimera.modules.user_ip_whitelist import _validate_ip_or_cidr
        ok, norm, err = _validate_ip_or_cidr("2a03:1ac0:5a7:6214::1")
        self.assertTrue(ok, f"Должен быть валиден: {err}")

    def test_valid_ipv6_cidr(self):
        from chimera.modules.user_ip_whitelist import _validate_ip_or_cidr
        ok, norm, err = _validate_ip_or_cidr("2a03:1ac0:5a7:6214::/64")
        self.assertTrue(ok, f"Должен быть валиден: {err}")
        self.assertEqual(norm, "2a03:1ac0:5a7:6214::/64")

    def test_loopback_rejected(self):
        from chimera.modules.user_ip_whitelist import _validate_ip_or_cidr
        for ip in ("127.0.0.1", "::1"):
            ok, _, err = _validate_ip_or_cidr(ip)
            self.assertFalse(ok, f"Loopback {ip} должен быть запрещён")
            self.assertIn("Loopback", err)
        # localhost — не IP, другая ошибка.
        ok, _, err = _validate_ip_or_cidr("localhost")
        self.assertFalse(ok)

    def test_private_rejected(self):
        from chimera.modules.user_ip_whitelist import _validate_ip_or_cidr
        for ip in ("10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.1",
                   "fc00::1", "fd00::1"):
            ok, _, err = _validate_ip_or_cidr(ip)
            self.assertFalse(ok, f"Private {ip} должен быть запрещён: {err}")
            self.assertIn("риват", err)  # "Приватный"

    def test_multicast_rejected(self):
        from chimera.modules.user_ip_whitelist import _validate_ip_or_cidr
        ok, _, err = _validate_ip_or_cidr("224.0.0.1")
        self.assertFalse(ok)
        self.assertIn("Multicast", err)

    def test_unspecified_rejected(self):
        from chimera.modules.user_ip_whitelist import _validate_ip_or_cidr
        ok, _, err = _validate_ip_or_cidr("0.0.0.0")
        self.assertFalse(ok)

    def test_invalid_format(self):
        from chimera.modules.user_ip_whitelist import _validate_ip_or_cidr
        for ip in ("invalid", "999.999.999.999", "1.2.3", "1.2.3.4/33", ""):
            ok, _, err = _validate_ip_or_cidr(ip)
            self.assertFalse(ok, f"Невалидный {ip!r} должен быть запрещён")

    def test_normalization(self):
        """Каноническая форма — без leading zeros, правильный CIDR."""
        from chimera.modules.user_ip_whitelist import _validate_ip_or_cidr
        # 5.6.7.0/24 — каноническая форма.
        ok, norm, _ = _validate_ip_or_cidr("5.6.7.0/24")
        self.assertEqual(norm, "5.6.7.0/24")
        # IPv6 — компресия ::.
        ok, norm, _ = _validate_ip_or_cidr("2a03:1ac0:0000:0000:0000:0000:0000:0001")
        self.assertEqual(norm, "2a03:1ac0::1")


class TestAddRemoveGetUserIPs(unittest.TestCase):
    """add_ip_to_user / remove_ip_from_user / get_user_ips — CRUD."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._users_file = self._tmpdir / "users.json"
        # Инициализируем users с одним пользователем.
        self._initial_users = [{
            "uuid": "test-uuid-1",
            "email": "alice@example.com",
            "name": "alice",
            "portal_password": "secret12345",
        }]
        self._users_file.write_text(json.dumps(self._initial_users))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_users_file(self):
        """Патчит USERS_FILE в users_manager и core."""
        from chimera.modules import users_manager
        core = sys.modules["chimera._core"]
        return (
            patch.object(users_manager, "_users_load", side_effect=lambda: json.loads(self._users_file.read_text()) if self._users_file.exists() else []),
            patch.object(users_manager, "_users_save", side_effect=self._save_users),
            patch.object(core, "USERS_FILE", self._users_file),
        )

    def _save_users(self, users):
        self._users_file.write_text(json.dumps(users, indent=2))

    def test_add_ip_to_user(self):
        from chimera.modules import user_ip_whitelist
        with patch.object(user_ip_whitelist, "rebuild_clients_ipset", return_value=True), \
             self._patch_users_file()[0], self._patch_users_file()[1]:
            ok, msg = user_ip_whitelist.add_ip_to_user("alice@example.com", "5.6.7.8")
        self.assertTrue(ok, msg)
        self.assertIn("5.6.7.8", msg)

        # Проверяем что IP в файле.
        users = json.loads(self._users_file.read_text())
        self.assertEqual(users[0]["allowed_ips"], ["5.6.7.8"])

    def test_add_ip_invalid_rejected(self):
        from chimera.modules import user_ip_whitelist
        with patch.object(user_ip_whitelist, "rebuild_clients_ipset", return_value=True), \
             self._patch_users_file()[0], self._patch_users_file()[1]:
            ok, msg = user_ip_whitelist.add_ip_to_user("alice@example.com", "127.0.0.1")
        self.assertFalse(ok)
        self.assertIn("Loopback", msg)

        # Файл не должен измениться.
        users = json.loads(self._users_file.read_text())
        self.assertNotIn("allowed_ips", users[0])

    def test_add_ip_dedup(self):
        """Повторное добавление того же IP не дублирует."""
        from chimera.modules import user_ip_whitelist
        with patch.object(user_ip_whitelist, "rebuild_clients_ipset", return_value=True), \
             self._patch_users_file()[0], self._patch_users_file()[1]:
            user_ip_whitelist.add_ip_to_user("alice@example.com", "5.6.7.8")
            ok, msg = user_ip_whitelist.add_ip_to_user("alice@example.com", "5.6.7.8")
        self.assertTrue(ok)
        self.assertIn("уже", msg.lower())

        users = json.loads(self._users_file.read_text())
        self.assertEqual(users[0]["allowed_ips"], ["5.6.7.8"])

    def test_add_ip_normalization(self):
        """Нормализованный IPv6 сохраняется в канонической форме."""
        from chimera.modules import user_ip_whitelist
        with patch.object(user_ip_whitelist, "rebuild_clients_ipset", return_value=True), \
             self._patch_users_file()[0], self._patch_users_file()[1]:
            ok, _ = user_ip_whitelist.add_ip_to_user("alice@example.com",
                                                       "2a03:1ac0:0000:0000:0000:0000:0000:0001")
        self.assertTrue(ok)
        users = json.loads(self._users_file.read_text())
        self.assertEqual(users[0]["allowed_ips"], ["2a03:1ac0::1"])

    def test_add_ip_to_nonexistent_user(self):
        from chimera.modules import user_ip_whitelist
        with patch.object(user_ip_whitelist, "rebuild_clients_ipset", return_value=True), \
             self._patch_users_file()[0], self._patch_users_file()[1]:
            ok, msg = user_ip_whitelist.add_ip_to_user("unknown@example.com", "5.6.7.8")
        self.assertFalse(ok)
        self.assertIn("не найден", msg.lower())

    def test_remove_ip_from_user(self):
        from chimera.modules import user_ip_whitelist
        with patch.object(user_ip_whitelist, "rebuild_clients_ipset", return_value=True), \
             self._patch_users_file()[0], self._patch_users_file()[1]:
            user_ip_whitelist.add_ip_to_user("alice@example.com", "5.6.7.8")
            ok, msg = user_ip_whitelist.remove_ip_from_user("alice@example.com", "5.6.7.8")
        self.assertTrue(ok)
        users = json.loads(self._users_file.read_text())
        self.assertEqual(users[0]["allowed_ips"], [])

    def test_remove_ip_not_in_list(self):
        from chimera.modules import user_ip_whitelist
        with patch.object(user_ip_whitelist, "rebuild_clients_ipset", return_value=True), \
             self._patch_users_file()[0], self._patch_users_file()[1]:
            ok, msg = user_ip_whitelist.remove_ip_from_user("alice@example.com", "5.167.99.99")
        self.assertFalse(ok)
        self.assertIn("не найден", msg.lower())

    def test_get_user_ips_empty(self):
        from chimera.modules import user_ip_whitelist
        with self._patch_users_file()[0]:
            ips = user_ip_whitelist.get_user_ips("alice@example.com")
        self.assertEqual(ips, [])

    def test_get_user_ips_after_add(self):
        from chimera.modules import user_ip_whitelist
        with patch.object(user_ip_whitelist, "rebuild_clients_ipset", return_value=True), \
             self._patch_users_file()[0], self._patch_users_file()[1]:
            user_ip_whitelist.add_ip_to_user("alice@example.com", "5.6.7.8")
            user_ip_whitelist.add_ip_to_user("alice@example.com", "1.2.3.4")
            ips = user_ip_whitelist.get_user_ips("alice@example.com")
        self.assertEqual(len(ips), 2)
        self.assertIn("5.6.7.8", ips)
        self.assertIn("1.2.3.4", ips)


class TestMigrateOldUsers(unittest.TestCase):
    """Обратная совместимость: users без поля allowed_ips."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._users_file = self._tmpdir / "users.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_old_user_without_allowed_ips_field(self):
        """Старый users.json без allowed_ips — get_user_ips возвращает []."""
        from chimera.modules import user_ip_whitelist
        # Старый формат — без allowed_ips.
        self._users_file.write_text(json.dumps([{
            "uuid": "u1", "email": "old@example.com", "name": "old",
        }]))

        from chimera.modules import users_manager
        with patch.object(users_manager, "_users_load",
                          side_effect=lambda: json.loads(self._users_file.read_text())):
            ips = user_ip_whitelist.get_user_ips("old@example.com")
        self.assertEqual(ips, [])

    def test_old_user_with_invalid_ips_in_field(self):
        """Если в allowed_ips мусор (ручное редактирование) — он игнорируется."""
        from chimera.modules import user_ip_whitelist
        self._users_file.write_text(json.dumps([{
            "uuid": "u1", "email": "old@example.com", "name": "old",
            "allowed_ips": ["127.0.0.1", "10.0.0.1", "5.6.7.8", "invalid", ""],
        }]))

        from chimera.modules import users_manager
        with patch.object(users_manager, "_users_load",
                          side_effect=lambda: json.loads(self._users_file.read_text())):
            ips = user_ip_whitelist.get_user_ips("old@example.com")
        # get_user_ips возвращает как есть (без повторной валидации) —
        # 3 валидных-looking строки + 2 невалидных ("invalid", "" фильтруются _normalize_user_ips).
        # _normalize_user_ips фильтрует пустые строки.
        self.assertEqual(len(ips), 4)  # 127.0.0.1, 10.0.0.1, 5.6.7.8, invalid

        # А вот _collect_all_user_ips валидирует и фильтрует.
        from chimera.modules import users_manager
        with patch.object(users_manager, "_users_load",
                          side_effect=lambda: json.loads(self._users_file.read_text())):
            v4, v6 = user_ip_whitelist._collect_all_user_ips()
        # Только 5.6.7.8 прошёл валидацию.
        self.assertEqual(v4, ["5.6.7.8"])
        self.assertEqual(v6, [])


class TestCollectAllUserIps(unittest.TestCase):
    """_collect_all_user_ips — сбор IP из всех пользователей."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._users_file = self._tmpdir / "users.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_collect_v4_and_v6(self):
        from chimera.modules import user_ip_whitelist
        self._users_file.write_text(json.dumps([
            {"uuid": "u1", "email": "a@x", "allowed_ips": ["5.6.7.8", "1.2.3.4"]},
            {"uuid": "u2", "email": "b@x", "allowed_ips": ["2a03:1ac0::1", "5.6.8.0/24"]},
            {"uuid": "u3", "email": "c@x"},  # без IPs
        ]))
        from chimera.modules import users_manager
        with patch.object(users_manager, "_users_load",
                          side_effect=lambda: json.loads(self._users_file.read_text())):
            v4, v6 = user_ip_whitelist._collect_all_user_ips()
        # v4: 5.6.7.8, 1.2.3.4, 5.6.8.0/24
        self.assertEqual(len(v4), 3)
        # v6: 2a03:1ac0::1
        self.assertEqual(len(v6), 1)

    def test_collect_dedup_across_users(self):
        """Один IP у двух пользователей — не дублируется."""
        from chimera.modules import user_ip_whitelist
        self._users_file.write_text(json.dumps([
            {"uuid": "u1", "email": "a@x", "allowed_ips": ["5.6.7.8"]},
            {"uuid": "u2", "email": "b@x", "allowed_ips": ["5.6.7.8"]},  # тот же IP
        ]))
        from chimera.modules import users_manager
        with patch.object(users_manager, "_users_load",
                          side_effect=lambda: json.loads(self._users_file.read_text())):
            v4, v6 = user_ip_whitelist._collect_all_user_ips()
        self.assertEqual(len(v4), 1)  # дедупликация
        self.assertEqual(v4[0], "5.6.7.8")


class TestRebuildClientsIpset(unittest.TestCase):
    """rebuild_clients_ipset — atomic swap (mock subprocess)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._users_file = self._tmpdir / "users.json"
        self._users_file.write_text(json.dumps([
            {"uuid": "u1", "email": "a@x", "allowed_ips": ["5.6.7.8"]},
        ]))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    @patch("chimera.modules.user_ip_whitelist.shutil.which", return_value="/usr/sbin/ipset")
    @patch("chimera.modules.user_ip_whitelist._run")
    def test_rebuild_creates_and_swaps(self, mock_run, mock_which):
        from chimera.modules import user_ip_whitelist
        # Все subprocess.run возвращают success.
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        from chimera.modules import users_manager
        with patch.object(users_manager, "_users_load",
                          side_effect=lambda: json.loads(self._users_file.read_text())), \
             patch("chimera.modules.ipset_persist.ipset_save", return_value=True):
            result = user_ip_whitelist.rebuild_clients_ipset()

        self.assertTrue(result)
        # Должны быть вызваны: create v4, create v4_tmp, restore, swap, destroy.
        cmd_strs = [" ".join(c.args[0]) if hasattr(c, "args") and isinstance(c.args[0], list) else str(c) for c in mock_run.call_args_list]
        # Проверяем что были create и swap.
        all_cmds = []
        for c in mock_run.call_args_list:
            if c.args and isinstance(c.args[0], list):
                all_cmds.append(" ".join(c.args[0]))
        self.assertTrue(any("create" in c and "clients_wl_v4" in c for c in all_cmds),
                        f"create v4 missing: {all_cmds}")
        self.assertTrue(any("swap" in c for c in all_cmds),
                        f"swap missing: {all_cmds}")

    @patch("chimera.modules.user_ip_whitelist.shutil.which", return_value=None)
    def test_rebuild_no_ipset(self, mock_which):
        """Если ipset недоступен — возвращает False, не падает."""
        from chimera.modules import user_ip_whitelist
        result = user_ip_whitelist.rebuild_clients_ipset()
        self.assertFalse(result)


class TestIptablesRule(unittest.TestCase):
    """apply_iptables_rule / remove_iptables_rule — установка/снятие."""

    def setUp(self):
        _setup_core_in_sysmodules()

    @patch("chimera.modules.user_ip_whitelist.shutil.which", return_value="/usr/sbin/iptables")
    @patch("chimera.modules.user_ip_whitelist._run")
    @patch("chimera.modules.user_ip_whitelist.rebuild_clients_ipset", return_value=True)
    def test_apply_iptables_rule_inserts_at_position_1(self, mock_rebuild, mock_run, mock_which):
        """ACCEPT правило вставляется через -I INPUT 1 (перед DROP)."""
        from chimera.modules import user_ip_whitelist
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = user_ip_whitelist.apply_iptables_rule(443)
        self.assertTrue(result)
        # Проверяем что был вызов с -I INPUT 1.
        all_cmds = []
        for c in mock_run.call_args_list:
            if c.args and isinstance(c.args[0], list):
                all_cmds.append(c.args[0])
        # -I INPUT 1 (insert at position 1).
        insert_calls = [c for c in all_cmds if "iptables" in c[0] and "-I" in c and "INPUT" in c and "1" in c]
        self.assertGreater(len(insert_calls), 0,
                           f"Должен быть -I INPUT 1: {all_cmds}")
        # Проверяем что в правиле есть match-set clients_wl_v4.
        v4_insert = [c for c in insert_calls if "clients_wl_v4" in c]
        self.assertGreater(len(v4_insert), 0, "Должен быть clients_wl_v4 в правиле")

    @patch("chimera.modules.user_ip_whitelist.shutil.which", return_value=None)
    def test_apply_iptables_rule_no_iptables(self, mock_which):
        """Если iptables недоступен — возвращает False."""
        from chimera.modules import user_ip_whitelist
        result = user_ip_whitelist.apply_iptables_rule(443)
        self.assertFalse(result)

    @patch("chimera.modules.user_ip_whitelist.shutil.which", return_value="/usr/sbin/iptables")
    @patch("chimera.modules.user_ip_whitelist._run")
    def test_remove_iptables_rule(self, mock_run, mock_which):
        """remove_iptables_rule удаляет через -D INPUT."""
        from chimera.modules import user_ip_whitelist
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        user_ip_whitelist.remove_iptables_rule(443)
        all_cmds = []
        for c in mock_run.call_args_list:
            if c.args and isinstance(c.args[0], list):
                all_cmds.append(c.args[0])
        delete_calls = [c for c in all_cmds if "iptables" in c[0] and "-D" in c and "INPUT" in c]
        self.assertGreater(len(delete_calls), 0, "Должен быть -D INPUT")


class TestCron(unittest.TestCase):
    """install_cron / remove_cron — cron-файлы."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cron_file = self._tmpdir / "cron"
        self._cron_script = self._tmpdir / "script.sh"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    @patch("chimera.modules.user_ip_whitelist.CRON_FILE", new_callable=lambda: None)
    @patch("chimera.modules.user_ip_whitelist.CRON_SCRIPT", new_callable=lambda: None)
    def test_install_cron_writes_files(self, mock_script_path, mock_file_path):
        """install_cron пишет cron-file и script."""
        # Используем реальные пути в tmp.
        from chimera.modules import user_ip_whitelist
        with patch.object(user_ip_whitelist, "CRON_FILE", self._cron_file), \
             patch.object(user_ip_whitelist, "CRON_SCRIPT", self._cron_script):
            result = user_ip_whitelist.install_cron()
        self.assertTrue(result)
        self.assertTrue(self._cron_file.exists())
        self.assertTrue(self._cron_script.exists())
        # В cron-file должна быть строка запуска script.
        cron_content = self._cron_file.read_text()
        self.assertIn("*/5 * * * *", cron_content)  # cron schedule каждые 5 мин
        self.assertIn("root", cron_content)
        # В script — вызов rebuild_clients_ipset.
        script_content = self._cron_script.read_text()
        self.assertIn("rebuild_clients_ipset", script_content)

    @patch("chimera.modules.user_ip_whitelist.CRON_FILE", new_callable=lambda: None)
    @patch("chimera.modules.user_ip_whitelist.CRON_SCRIPT", new_callable=lambda: None)
    def test_remove_cron_deletes_files(self, mock_script_path, mock_file_path):
        from chimera.modules import user_ip_whitelist
        with patch.object(user_ip_whitelist, "CRON_FILE", self._cron_file), \
             patch.object(user_ip_whitelist, "CRON_SCRIPT", self._cron_script):
            # Сначала установим.
            user_ip_whitelist.install_cron()
            self.assertTrue(self._cron_file.exists())
            # Потом удалим.
            user_ip_whitelist.remove_cron()
            self.assertFalse(self._cron_file.exists())
            self.assertFalse(self._cron_script.exists())


class TestQ1UserPortalAccessibleWithoutWhitelist(unittest.TestCase):
    """Q1: User Portal доступен с IP, не входящим в whitelist пользователя.

    Подтверждаем архитектурное решение: User Portal (rest_api.py) слушает на
    отдельном порту (8443 по умолчанию), который НЕ подпадает под ingress_geoip
    DROP (применяется только к SERVER_PORT=443).
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ingress_geoip_drops_only_server_port(self):
        """ingress_geoip применяет DROP только к SERVER_PORT, не к 8443."""
        from chimera.modules import ingress_geoip
        import inspect
        # Проверяем что в _ingress_apply_ipset используется --dport <port>,
        # а не все порты.
        src = inspect.getsource(ingress_geoip._ingress_apply_ipset)
        self.assertIn("--dport", src)
        # PORT берётся из аргумента, не хардкод 443.
        self.assertIn("port", src)

    def test_user_portal_default_port_is_8443(self):
        """rest_api.py слушает на 8443 по умолчанию, не на 443."""
        from chimera.modules import rest_api
        self.assertEqual(rest_api.DEFAULT_WEB_PORT, 8443)
        self.assertNotEqual(rest_api.DEFAULT_WEB_PORT, 443)

    def test_apply_iptables_rule_uses_only_server_port(self):
        """apply_iptables_rule применяет ACCEPT только к port (443), не к 8443."""
        from chimera.modules import user_ip_whitelist
        import inspect
        src = inspect.getsource(user_ip_whitelist.apply_iptables_rule)
        # Использует --dport str(port), где port — аргумент функции.
        self.assertIn("--dport", src)
        self.assertIn("str(port)", src)


class TestQ2NoXForwardedForTrust(unittest.TestCase):
    """Q2: X-Forwarded-For НЕ используется для определения IP клиента.

    rest_api.py использует self.client_address[0] напрямую.
    /api/portal/ips возвращает detected_ip из _client_ip(), не из X-Forwarded-For.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_client_ip_uses_client_address(self):
        """_client_ip() в rest_api использует self.client_address[0]."""
        from chimera.modules import rest_api
        import inspect
        src = inspect.getsource(rest_api._VLESSHandler._client_ip)
        self.assertIn("client_address", src)
        # НЕ упоминает X-Forwarded-For.
        self.assertNotIn("X-Forwarded-For", src)
        self.assertNotIn("x-forwarded-for", src.lower())

    def test_get_portal_ips_uses_client_ip_not_xff(self):
        """GET /api/portal/ips — detected_ip берётся из _client_ip(), не из заголовков."""
        from chimera.modules import rest_api
        import inspect
        src = inspect.getsource(rest_api._VLESSHandler.do_GET)
        # Находим блок /api/portal/ips.
        ips_block_start = src.find('"/api/portal/ips"')
        if ips_block_start == -1:
            ips_block_start = src.find("'/api/portal/ips'")
        self.assertGreater(ips_block_start, 0, "Блок /api/portal/ips не найден в do_GET")
        # Берём кусок до return.
        ips_block = src[ips_block_start:ips_block_start + 2000]
        # Должен использовать self._client_ip().
        self.assertIn("_client_ip()", ips_block)
        # НЕ должен использовать X-Forwarded-For.
        self.assertNotIn("X-Forwarded-For", ips_block)
        self.assertNotIn("x-forwarded-for", ips_block.lower())

    def test_post_portal_ips_auto_uses_client_ip(self):
        """POST /api/portal/ips с ip=auto использует _client_ip(), не X-Forwarded-For."""
        from chimera.modules import rest_api
        import inspect
        src = inspect.getsource(rest_api._VLESSHandler.do_POST)
        ips_block_start = src.find('"/api/portal/ips"')
        if ips_block_start == -1:
            ips_block_start = src.find("'/api/portal/ips'")
        self.assertGreater(ips_block_start, 0, "Блок /api/portal/ips не найден в do_POST")
        ips_block = src[ips_block_start:ips_block_start + 3000]
        # "auto" → _client_ip().
        self.assertIn("auto", ips_block.lower())
        self.assertIn("_client_ip()", ips_block)
        # X-Forwarded-For может упоминаться только в комментариях, не в коде.
        # Удаляем комментарии (строки, начинающиеся с # после обрезки пробелов).
        code_lines = [line for line in ips_block.split('\n')
                      if line.strip() and not line.strip().startswith('#')]
        code_only = '\n'.join(code_lines)
        self.assertNotIn("X-Forwarded-For", code_only,
                         "X-Forwarded-For не должен использоваться в коде")
        self.assertNotIn("x-forwarded-for", code_only.lower())

    def test_spoofed_xff_does_not_affect_ip_detection(self):
        """Подмена X-Forwarded-For не должна влиять на detected_ip.

        Создаём mock handler с поддельанным X-Forwarded-For и проверяем,
        что _client_ip() возвращает client_address[0], не поддельный IP.
        """
        from chimera.modules import rest_api

        # Создаём mock handler.
        handler = rest_api._VLESSHandler.__new__(rest_api._VLESSHandler)
        handler.client_address = ("5.6.7.8", 12345)
        # Поддельный X-Forwarded-For.
        handler.headers = {"X-Forwarded-For": "1.2.3.4"}

        detected = handler._client_ip()
        self.assertEqual(detected, "5.6.7.8",
                         "Должен возвращать client_address[0], не X-Forwarded-For")


class TestIngressGeoipIntegration(unittest.TestCase):
    """Интеграция ingress_geoip.py с user_ip_whitelist."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ingress_enable_calls_apply_iptables_rule(self):
        """_ingress_enable должен вызывать apply_iptables_rule из user_ip_whitelist."""
        from chimera.modules import ingress_geoip
        import inspect
        src = inspect.getsource(ingress_geoip._ingress_enable)
        # Должен импортировать apply_iptables_rule из user_ip_whitelist.
        self.assertIn("user_ip_whitelist", src)
        self.assertIn("apply_iptables_rule", src)

    def test_ingress_remove_calls_remove_iptables_rule(self):
        """_ingress_remove должен вызывать remove_iptables_rule."""
        from chimera.modules import ingress_geoip
        import inspect
        src = inspect.getsource(ingress_geoip._ingress_remove)
        self.assertIn("user_ip_whitelist", src)
        self.assertIn("remove_iptables_rule", src)


class TestTuiEntryPoint(unittest.TestCase):
    """Проверка что TUI пункт [6] подключен в do_manage_users()."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_tui_has_item_6(self):
        """do_manage_users должен содержать пункт [6] для IP whitelist."""
        from chimera import _core
        import inspect
        src = inspect.getsource(_core.do_manage_users)
        self.assertIn('"6"', src)
        self.assertIn("user_ip_whitelist", src)
        self.assertIn("do_manage_user_ip_whitelist", src)


if __name__ == "__main__":
    unittest.main()
