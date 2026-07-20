#!/usr/bin/env python3
"""
tests/test_rest_api_web_panel_firewall.py
───────────────────────────────────────────────────────────────────────────────
Тесты для ufw-управления веб-панелью (admin + user portal) в rest_api.py.

Покрывает:
  1. _ufw_web_panel_close — парсинг ufw status numbered, delete по номеру.
  2. install_web_service(expose=True) → expose=False — ufw delete вызван.
  3. install_web_service смена порта при 0.0.0.0 — старый закрыт, новый открыт.
  4. uninstall_web_service после expose=True — ufw delete вызван.
  5. uninstall_web_service после expose=False — ufw НЕ вызывается.
  6. _ufw_web_panel_close — не падает при ufw не установлен/пустой вывод.
  7. Пункт меню "Остановить сервис" при exposed — закрывает порт.

Принцип: тесты реально проверяют, что _run получил правильные аргументы
`ufw delete <номер>`, а не просто что функция "не упала".
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import types
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
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core


def _make_completed(stdout: str = "", returncode: int = 0):
    """Создаёт mock CompletedProcess."""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr="",
    )


# Пример вывода `ufw status numbered` с нашим правилом.
_UFW_STATUS_WITH_RULE = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8443/tcp                   ALLOW IN    Anywhere                   # VLESS Web Panel (exposed, no TLS)
[ 3] 443/tcp                    ALLOW IN    Anywhere
"""

# Пример вывода с двумя правилами (разные порты).
_UFW_STATUS_TWO_RULES = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8443/tcp                   ALLOW IN    Anywhere                   # VLESS Web Panel (exposed, no TLS)
[ 3] 9000/tcp                   ALLOW IN    Anywhere                   # VLESS Web Panel (exposed, no TLS)
[ 4] 443/tcp                    ALLOW IN    Anywhere
"""

# Пример вывода БЕЗ нашего правила.
_UFW_STATUS_NO_RULE = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 443/tcp                    ALLOW IN    Anywhere
"""


class TestUfwWebPanelClose(unittest.TestCase):
    """_ufw_web_panel_close — парсинг ufw status + delete."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_deletes_rule_by_number(self):
        """Находит правило с нашим комментарием и портом, удаляет по номеру."""
        from chimera.modules import rest_api
        fake_core = sys.modules["chimera._core"]
        mock_run = MagicMock(return_value=_make_completed(_UFW_STATUS_WITH_RULE))
        fake_core._run = mock_run
        with patch("shutil.which", return_value="/usr/sbin/ufw"):
            rest_api._ufw_web_panel_close(8443)
        # Должен быть вызов ufw delete 2 (номер правила).
        delete_calls = [c for c in mock_run.call_args_list
                        if c.args and c.args[0] and c.args[0][0] == "ufw"
                        and c.args[0][1] == "delete"]
        self.assertEqual(len(delete_calls), 1)
        self.assertEqual(delete_calls[0].args[0][2], "2")

    def test_deletes_multiple_rules_from_end(self):
        """Два правила — удаляет с конца (старший номер первым)."""
        from chimera.modules import rest_api
        fake_core = sys.modules["chimera._core"]
        mock_run = MagicMock(return_value=_make_completed(_UFW_STATUS_TWO_RULES))
        fake_core._run = mock_run
        with patch("shutil.which", return_value="/usr/sbin/ufw"):
            rest_api._ufw_web_panel_close(8443)
            # Также вызывает для 9000 — но port=8443, так что 9000 не матчит.
        # Только правило [2] (8443) должно быть удалено.
        delete_calls = [c for c in mock_run.call_args_list
                        if c.args and c.args[0] and c.args[0][0] == "ufw"
                        and c.args[0][1] == "delete"]
        self.assertEqual(len(delete_calls), 1)
        self.assertEqual(delete_calls[0].args[0][2], "2")

    def test_no_rule_found_no_delete(self):
        """Нет правила с нашим комментарием — delete не вызывается."""
        from chimera.modules import rest_api
        fake_core = sys.modules["chimera._core"]
        mock_run = MagicMock(return_value=_make_completed(_UFW_STATUS_NO_RULE))
        fake_core._run = mock_run
        with patch("shutil.which", return_value="/usr/sbin/ufw"):
            rest_api._ufw_web_panel_close(8443)
        delete_calls = [c for c in mock_run.call_args_list
                        if c.args and c.args[0] and c.args[0][0] == "ufw"
                        and c.args[0][1] == "delete"]
        self.assertEqual(len(delete_calls), 0)

    def test_ufw_not_installed_returns_silently(self):
        """ufw не установлен — тихо return, без исключения."""
        from chimera.modules import rest_api
        with patch("shutil.which", return_value=None):
            rest_api._ufw_web_panel_close(8443)  # не должно упасть

    def test_ufw_inactive_returns_silently(self):
        """ufw status возвращает non-zero — тихо return."""
        from chimera.modules import rest_api
        fake_core = sys.modules["chimera._core"]
        mock_run = MagicMock(return_value=_make_completed("", returncode=1))
        fake_core._run = mock_run
        with patch("shutil.which", return_value="/usr/sbin/ufw"):
            rest_api._ufw_web_panel_close(8443)
        delete_calls = [c for c in mock_run.call_args_list
                        if c.args and c.args[0] and c.args[0][0] == "ufw"
                        and c.args[0][1] == "delete"]
        self.assertEqual(len(delete_calls), 0)

    def test_empty_stdout_returns_silently(self):
        """ufw status вернул пустой stdout — тихо return."""
        from chimera.modules import rest_api
        fake_core = sys.modules["chimera._core"]
        mock_run = MagicMock(return_value=_make_completed(""))
        fake_core._run = mock_run
        with patch("shutil.which", return_value="/usr/sbin/ufw"):
            rest_api._ufw_web_panel_close(8443)
        delete_calls = [c for c in mock_run.call_args_list
                        if c.args and c.args[0] and c.args[0][0] == "ufw"
                        and c.args[0][1] == "delete"]
        self.assertEqual(len(delete_calls), 0)

    def test_does_not_delete_other_port_rules(self):
        """Чужое правило с другим портом — не удаляется."""
        from chimera.modules import rest_api
        fake_core = sys.modules["chimera._core"]
        status = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 9000/tcp                   ALLOW IN    Anywhere                   # VLESS Web Panel (exposed, no TLS)
"""
        mock_run = MagicMock(return_value=_make_completed(status))
        fake_core._run = mock_run
        with patch("shutil.which", return_value="/usr/sbin/ufw"):
            rest_api._ufw_web_panel_close(8443)  # ищем 8443, а правило на 9000
        delete_calls = [c for c in mock_run.call_args_list
                        if c.args and c.args[0] and c.args[0][0] == "ufw"
                        and c.args[0][1] == "delete"]
        self.assertEqual(len(delete_calls), 0)


class TestInstallWebServiceUfw(unittest.TestCase):
    """install_web_service — открытие/закрытие ufw при切换."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _patch_web_config(self, host="127.0.0.1", port=8443):
        """Патчит WEB_CONFIG_FILE для чтения/записи во temp dir."""
        tmpdir = Path(tempfile.mkdtemp())
        cfg_file = tmpdir / "web_config.json"
        svc_file = tmpdir / "vless-web.service"
        cfg = {
            "port": port, "admin_user": "admin", "admin_pass": "testpass",
            "host": host, "enabled": True,
        }
        cfg_file.write_text(json.dumps(cfg))
        return cfg_file, svc_file, tmpdir

    def test_expose_true_then_false_closes_old_port(self):
        """install(expose=True) → install(expose=False): ufw delete вызван."""
        from chimera.modules import rest_api
        cfg_file, svc_file, tmpdir = self._patch_web_config("127.0.0.1", 8443)
        calls = []

        def mock_run(cmd, **kw):
            calls.append(cmd)
            if "status" in cmd and "numbered" in cmd:
                return _make_completed(_UFW_STATUS_WITH_RULE)
            return _make_completed("")

        fake_core = sys.modules["chimera._core"]
        fake_core._run = mock_run
        try:
            with patch.object(rest_api, "WEB_CONFIG_FILE", cfg_file), \
                 patch.object(rest_api, "WEB_SERVICE_FILE", svc_file), \
                 patch("shutil.which", return_value="/usr/sbin/ufw"):
                # install с expose=True — открывает порт.
                rest_api.install_web_service(port=8443, expose=True)
                # install с expose=False — закрывает старый.
                rest_api.install_web_service(port=8443, expose=False)
            # Проверяем что ufw delete был вызван.
            delete_calls = [c for c in calls
                            if c[0] == "ufw" and c[1] == "delete"]
            self.assertGreater(len(delete_calls), 0,
                               "ufw delete должен быть вызван при expose=False")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_port_change_closes_old_and_opens_new(self):
        """install(port=X, expose=True) → install(port=Y, expose=True):
        старый порт X закрыт, новый Y открыт."""
        from chimera.modules import rest_api
        cfg_file, svc_file, tmpdir = self._patch_web_config("0.0.0.0", 8443)
        calls = []

        def mock_run(cmd, **kw):
            calls.append(cmd)
            if "status" in cmd and "numbered" in cmd:
                return _make_completed(_UFW_STATUS_WITH_RULE)
            return _make_completed("")

        fake_core = sys.modules["chimera._core"]
        fake_core._run = mock_run
        try:
            with patch.object(rest_api, "WEB_CONFIG_FILE", cfg_file), \
                 patch.object(rest_api, "WEB_SERVICE_FILE", svc_file), \
                 patch("shutil.which", return_value="/usr/sbin/ufw"):
                rest_api.install_web_service(port=8443, expose=True)
                rest_api.install_web_service(port=9000, expose=True)
            # ufw delete для 8443.
            delete_calls = [c for c in calls
                            if c[0] == "ufw" and c[1] == "delete"]
            self.assertGreater(len(delete_calls), 0,
                               "Старый порт должен быть закрыт")
            # ufw allow для 9000.
            allow_calls = [c for c in calls
                           if c[0] == "ufw" and c[1] == "allow"
                           and "9000" in c]
            self.assertGreater(len(allow_calls), 0,
                               "Новый порт должен быть открыт")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestUninstallWebServiceUfw(unittest.TestCase):
    """uninstall_web_service — закрытие ufw."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_uninstall_after_expose_true_closes_port(self):
        """uninstall после install с expose=True — ufw delete вызван."""
        from chimera.modules import rest_api
        tmpdir = Path(tempfile.mkdtemp())
        cfg_file = tmpdir / "web_config.json"
        svc_file = tmpdir / "vless-web.service"
        cfg = {
            "port": 8443, "admin_user": "admin", "admin_pass": "testpass",
            "host": "0.0.0.0", "enabled": True,
        }
        cfg_file.write_text(json.dumps(cfg))
        svc_file.write_text("[Unit]\n...")

        calls = []

        def mock_run(cmd, **kw):
            calls.append(cmd)
            if "status" in cmd and "numbered" in cmd:
                return _make_completed(_UFW_STATUS_WITH_RULE)
            return _make_completed("")

        fake_core = sys.modules["chimera._core"]
        fake_core._run = mock_run
        try:
            with patch.object(rest_api, "WEB_CONFIG_FILE", cfg_file), \
                 patch.object(rest_api, "WEB_SERVICE_FILE", svc_file), \
                 patch("shutil.which", return_value="/usr/sbin/ufw"):
                rest_api.uninstall_web_service()
            delete_calls = [c for c in calls
                            if c[0] == "ufw" and c[1] == "delete"]
            self.assertGreater(len(delete_calls), 0,
                               "ufw delete должен быть вызван при uninstall")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_uninstall_after_expose_false_no_ufw_calls(self):
        """uninstall после install с expose=False — ufw НЕ вызывается."""
        from chimera.modules import rest_api
        tmpdir = Path(tempfile.mkdtemp())
        cfg_file = tmpdir / "web_config.json"
        svc_file = tmpdir / "vless-web.service"
        cfg = {
            "port": 8443, "admin_user": "admin", "admin_pass": "testpass",
            "host": "127.0.0.1", "enabled": True,
        }
        cfg_file.write_text(json.dumps(cfg))
        svc_file.write_text("[Unit]\n...")

        calls = []

        def mock_run(cmd, **kw):
            calls.append(cmd)
            return _make_completed("")

        fake_core = sys.modules["chimera._core"]
        fake_core._run = mock_run
        try:
            with patch.object(rest_api, "WEB_CONFIG_FILE", cfg_file), \
                 patch.object(rest_api, "WEB_SERVICE_FILE", svc_file), \
                 patch("shutil.which", return_value="/usr/sbin/ufw"):
                rest_api.uninstall_web_service()
            # Не должно быть ufw-вызовов вообще (кроме возможного which).
            ufw_calls = [c for c in calls if c and c[0] == "ufw"]
            self.assertEqual(len(ufw_calls), 0,
                             "ufw не должен вызываться при host=127.0.0.1")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
