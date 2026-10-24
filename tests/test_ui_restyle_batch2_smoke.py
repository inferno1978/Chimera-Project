#!/usr/bin/env python3
"""
tests/test_ui_restyle_batch2_smoke.py
───────────────────────────────────────────────────────────────────────────────
UI-smoke стилизации второй партии модулей (окт.2026, продолжение кейса
Task 11 AWG + Task 12 entry_mirrors): as_direct, ttl_users, chain_relay,
hysteria2_exit_mgr.

Все интерактивные диалоги рисуются рамками box_renderer и не падают под
пайпом (EOF на input = значение по умолчанию / отмена). Легаси-фрейм
_as_ask_action заменён каноном, пикеры — рамочные списки [1]…[Q],
паузы — EOF-безопасный _pause, y/N — _box_ask.

Канон харнесса: tests/test_entry_mirrors_ui_smoke.py (фейковый
chimera._core, эталонный паттерн test_awg_ui_smoke).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Фейковый chimera._core (эталонный паттерн test_entry_mirrors_ui_smoke)."""
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
    sys.modules["chimera._core"] = fake_core
    return fake_core, g


def _feed(func, answers, *args, **kwargs):
    """Прогоняет func с очередью ответов на input (EOF = исчерпание)."""
    it = iter(answers)

    def _fake_input(prompt=""):
        try:
            return next(it)
        except StopIteration:
            raise EOFError

    out = io.StringIO()
    with patch("builtins.input", _fake_input), \
         patch("os.system", lambda *a, **k: None), \
         redirect_stdout(out):
        res = func(*args, **kwargs)
    return out.getvalue(), res


_CIDRS = ["10.10.0.0/16", "10.20.0.0/16"]
_UUID = "d34df00d-1111-2222-3333-444455556666"


# ═════════════════════════════════════════════════════════════════════════════
#  as_direct
# ═════════════════════════════════════════════════════════════════════════════

class TestAsDirectUi(unittest.TestCase):

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import as_direct
        self._m = as_direct
        self._tmpdir = Path(tempfile.mkdtemp())
        self._entries = [{"asn": "AS123", "action": "direct"},
                         {"asn": "AS456", "action": "proxy"}]
        self._patches = [
            patch.object(self._m, "_as_direct_list_load",
                         side_effect=lambda: [dict(e) for e in self._entries]),
            patch.object(self._m, "_as_direct_list_save", MagicMock()),
            patch.object(self._m, "_as_direct_timer_status",
                         return_value="тест"),
            patch.object(self._m, "_as_direct_count_rules", return_value=3),
            patch.object(self._m, "_as_direct_load_from_file",
                         return_value=list(_CIDRS)),
            patch.object(self._m, "_as_direct_apply_to_xray",
                         return_value=True),
            patch.object(self._m, "_fetch_prefixes_for_asn",
                         return_value=list(_CIDRS)),
            patch.object(self._m, "_as_direct_remove_from_xray"),
            patch.object(self._m, "_as_direct_install_timer"),
            patch.object(self._m, "_as_direct_remove_timer"),
            patch.object(self._m, "_as_direct_file",
                         side_effect=lambda asn: self._tmpdir / f"{asn}.txt"),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _menu(self, answers):
        return _feed(self._m.do_manage_as_direct, answers)[0]

    def test_menu_framed_and_eof_safe(self):
        text = self._menu([])
        self.assertIn("╔", text)
        self.assertIn("Управление AS-маршрутами", text)   # заголовок (был и до стилизации)
        self.assertIn("[1]", text)
        self.assertIn("[C]", text)
        self.assertIn("[Q]", text)
        self.assertIn("AS123", text)

    def test_ask_action_framed_eof_cancel(self):
        text, res = _feed(self._m._as_ask_action, [], "AS123")
        self.assertEqual(res, "")
        self.assertIn("ДЕЙСТВИЕ ДЛЯ AS123", text)
        self.assertIn("direct", text)
        self.assertIn("proxy", text)
        self.assertIn("block", text)
        self.assertIn("Отмена (Enter)", text)

    def test_ask_action_choices(self):
        self.assertEqual(_feed(self._m._as_ask_action, ["1"])[1], "direct")
        self.assertEqual(_feed(self._m._as_ask_action, ["2"])[1], "proxy")
        self.assertEqual(_feed(self._m._as_ask_action, ["3"])[1], "block")
        self.assertEqual(_feed(self._m._as_ask_action, ["q"])[1], "")

    def test_pick_as_entry_number_asn_invalid(self):
        entries = self._entries
        self.assertIs(_feed(self._m._pick_as_entry, ["1"], entries, "T")[1],
                      entries[0])
        self.assertIs(_feed(self._m._pick_as_entry, ["AS456"], entries, "T")[1],
                      entries[1])
        self.assertIs(_feed(self._m._pick_as_entry, ["456"], entries, "T")[1],
                      entries[1])
        text, res = _feed(self._m._pick_as_entry, ["zz"], entries, "T")
        self.assertIsNone(res)
        self.assertIn("Не найдено", text)          # рамочная карточка ошибки
        self.assertIsNone(_feed(self._m._pick_as_entry, [""], entries, "T")[1])
        self.assertIsNone(_feed(self._m._pick_as_entry, [], entries, "T")[1])

    def test_change_action_flow_framed(self):
        text = self._menu(["1", "1", "2"])          # AS123 -> proxy
        self.assertIn("ИЗМЕНЕНИЕ ДЕЙСТВИЯ AS", text)
        self.assertIn("ДЕЙСТВИЕ ДЛЯ AS123", text)   # канон вместо legacy-фрейма
        self.assertIn("действие изменено", text)
        self._m._as_direct_apply_to_xray.assert_called_with(
            "AS123", list(_CIDRS), "proxy")
        self._m._as_direct_list_save.assert_called()

    def test_delete_flow_framed(self):
        text = self._menu(["4", "1", "y"])
        self.assertIn("УДАЛЕНИЕ AS", text)
        self.assertIn("AS будет убран", text)       # карточка подтверждения
        self.assertIn("удалён", text)
        self._m._as_direct_remove_from_xray.assert_called_once_with("AS123")
        # EOF на y/N — безопасная отмена
        self._m._as_direct_remove_from_xray.reset_mock()
        text2 = self._menu(["4", "1"])
        self.assertIn("УДАЛЕНИЕ AS", text2)
        self._m._as_direct_remove_from_xray.assert_not_called()

    def test_timer_input_validation_retry(self):
        text = self._menu(["5", "99", "x", "4", "30"])
        self.assertIn("ВРЕМЯ ЗАПУСКА", text)
        self.assertIn("Неверный формат", text)       # рамочный переспрос
        self._m._as_direct_install_timer.assert_called_once_with(4, 30)

    def test_prefixes_framed(self):
        text = self._menu(["7", ""])
        self.assertIn("ПРЕФИКСЫ AS123", text)
        self.assertIn("2 префиксов", text)
        self.assertIn("10.10.0.0/16", text)


# ═════════════════════════════════════════════════════════════════════════════
#  ttl_users
# ═════════════════════════════════════════════════════════════════════════════

class TestTtlUsersUi(unittest.TestCase):

    def setUp(self):
        self._fake_core, self._g = _setup_core_in_sysmodules()
        from chimera.modules import ttl_users
        self._m = ttl_users
        self._tmpdir = Path(tempfile.mkdtemp())
        self._ttl = self._tmpdir / "ttl_users.json"
        self._ttl.write_text("{}")
        self._users = [{"email": "u@x.io", "uuid": _UUID, "name": "User One"}]
        self._patches = [
            patch.object(self._m, "TTL_FILE", self._ttl),
            patch.object(self._fake_core, "_users_load",
                         return_value=list(self._users)),
            patch.object(self._m, "_ttl_install_cron"),
            patch.object(self._m, "_ttl_remove_cron"),
            patch.object(self._m, "_ttl_check_and_expire", return_value=0),
            patch.object(self._m, "_ttl_block_user", return_value=True),
            patch.object(self._m, "_ttl_unblock_user", return_value=True),
            patch.object(self._m, "_ttl_is_blocked", return_value=False),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _menu(self, answers):
        return _feed(self._m.do_manage_ttl_users, answers)[0]

    def _state(self) -> dict:
        return json.loads(self._ttl.read_text())

    def test_menu_framed_and_eof_safe(self):
        text = self._menu([])
        self.assertIn("╔", text)
        self.assertIn("ВРЕМЕННЫЕ ПОЛЬЗОВАТЕЛИ", text)
        self.assertIn("[1]", text)
        self.assertIn("[Q]", text)

    def test_assign_ttl_preset_framed(self):
        text = self._menu(["1", "1", "5"])          # юзер 1, пресет 30 дней
        self.assertIn("НАЗНАЧЕНИЕ TTL", text)
        self.assertIn("ВЫБОР ПОЛЬЗОВАТЕЛЯ", text)   # рамочный пикер
        self.assertIn("TTL назначен", text)
        st = self._state()
        self.assertIn("u@x.io", st)
        self.assertEqual(st["u@x.io"]["days"], 30)

    def test_assign_ttl_custom_days_reasks(self):
        text = self._menu(["1", "1", "7", "abc", "45"])
        self.assertIn("Нужно целое число", text)    # рамочный переспрос
        self.assertEqual(self._state()["u@x.io"]["days"], 45)

    def test_extend_flow_framed(self):
        self._ttl.write_text(json.dumps(
            {"u@x.io": {"email": "u@x.io", "expires_at": "2030-01-01T00:00:00+00:00",
                        "days": 30, "notified_24h": False}}))
        text = self._menu(["2", "1", "5"])
        self.assertIn("ПРОДЛЕНИЕ СРОКА", text)
        self.assertIn("Срок обновлён", text)
        self.assertEqual(self._state()["u@x.io"]["days"], 30)

    def test_remove_ttl_confirm_framed(self):
        self._ttl.write_text(json.dumps(
            {"u@x.io": {"email": "u@x.io", "expires_at": "2030-01-01T00:00:00+00:00",
                        "days": 30, "notified_24h": False}}))
        text = self._menu(["3", "1", "y"])
        self.assertIn("СНЯТИЕ TTL", text)
        self.assertIn("TTL снят", text)
        self.assertEqual(self._state(), {})

    def test_block_flow_framed(self):
        self._ttl.write_text(json.dumps(
            {"u@x.io": {"email": "u@x.io", "expires_at": "2030-01-01T00:00:00+00:00",
                        "days": 30, "notified_24h": False}}))
        text = self._menu(["6", "1", "y"])
        self.assertIn("РУЧНАЯ БЛОКИРОВКА", text)
        self.assertIn("заблокирован", text)
        self._m._ttl_block_user.assert_called_once_with("u@x.io", reason="manual")

    def test_unblock_flow_framed(self):
        self._ttl.write_text(json.dumps(
            {"u@x.io": {"email": "u@x.io", "expires_at": "2030-01-01T00:00:00+00:00",
                        "days": 30, "notified_24h": False, "blocked": True}}))
        with patch.object(self._m, "_ttl_is_blocked", return_value=True):
            text = _feed(self._m.do_manage_ttl_users, ["7", "1", "y"])[0]
        self.assertIn("РАЗБЛОКИРОВКА", text)
        self.assertIn("разблокирован", text)
        self._m._ttl_unblock_user.assert_called_once_with("u@x.io")

    def test_check_expired_framed(self):
        with patch.object(self._m, "_ttl_check_and_expire", return_value=2):
            text = self._menu(["4"])
        self.assertIn("ПРОВЕРКА ИСТЁКШИХ", text)
        self.assertIn("Заблокировано 2", text)


# ═════════════════════════════════════════════════════════════════════════════
#  chain_relay
# ═════════════════════════════════════════════════════════════════════════════

_HOP = {
    "tag": "hop-one", "host": "hop1.example.net", "port": 443,
    "uuid": _UUID, "pubkey": "PBKEY123", "shortid": "aabb1122",
    "sni": "hop1.example.net", "fp": "chrome", "flow": "xtls-rprx-vision",
    "proto": "reality", "path": "/", "xhttp_mode": "stream-up",
    "via": "", "comment": "", "enabled": True,
}


class TestChainRelayUi(unittest.TestCase):

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import chain_relay
        self._m = chain_relay
        self._hops = []
        self._nodes = []
        self._patches = [
            patch.object(self._m, "load_relay_hops",
                         side_effect=lambda: [dict(h) for h in self._hops]),
            patch.object(self._m, "save_relay_hops", return_value=True),
            patch.object(self._m, "_chain_nodes_from_state",
                         side_effect=lambda: [dict(n) for n in self._nodes]),
            patch.object(self._m, "_save_chain_nodes_via", return_value=True),
            patch.object(self._m, "check_hop_tcp", return_value=(True, 12.3)),
            patch.object(self._m, "check_via_node_full_path"),
            patch.object(self._m, "_offer_rebuild"),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    def _menu(self, answers):
        return _feed(self._m.do_chain_relay_menu, answers)[0]

    def test_menu_framed_and_eof_safe(self):
        text = self._menu([])
        self.assertIn("╔", text)
        self.assertIn("CHAIN RELAY", text)
        self.assertIn("[A]", text)
        self.assertIn("[0]", text)                  # выход

    def test_add_hop_manual_full_flow_framed(self):
        fields = ["hop2.example.net", "443", _UUID, "PBKEY123", "aabb1122",
                  "hop2.example.net", "chrome", "", "reality", "/",
                  "stream-up", "", ""]
        text = self._menu(["a", "3", *fields, "", ""])
        self.assertIn("ДОБАВЛЕНИЕ ХОПА", text)
        self.assertIn("ПОЛЯ ХОПА", text)            # легенда полей
        self.assertIn("ENTER = ОСТАВИТЬ ТЕКУЩЕЕ", text)
        self.assertIn("добавлен", text)
        args = self._m.save_relay_hops.call_args[0][0]
        self.assertEqual(len(args), 1)
        self.assertEqual(args[0]["host"], "hop2.example.net")
        self.assertEqual(args[0]["port"], 443)
        self.assertTrue(args[0]["tag"].startswith("hop-"))
        self._m._offer_rebuild.assert_called_once()

    def test_add_hop_bad_link_framed_error(self):
        text = self._menu(["a", "1", "https://example.com/not-vless"])
        self.assertIn("ДОБАВЛЕНИЕ ХОПА: ИЗ VLESS-ССЫЛКИ", text)
        self.assertIn("Не удалось распарсить", text)
        self._m.save_relay_hops.assert_not_called()

    def test_toggle_hop_framed(self):
        self._hops.append(dict(_HOP))
        text = self._menu(["e", "1", "t"])
        self.assertIn("ИЗМЕНЕНИЕ ХОПА", text)
        self.assertIn("ХОП «hop-one»", text)
        self.assertIn("выключен", text)
        saved = self._m.save_relay_hops.call_args[0][0]
        self.assertFalse(saved[0]["enabled"])

    def test_delete_hop_dependency_warn_framed(self):
        self._hops.append(dict(_HOP))
        self._nodes.append({"host": "nd1.example.net", "port": 443,
                            "via": "hop-one"})
        text = self._menu(["d", "1"])
        self.assertIn("УДАЛЕНИЕ ХОПА", text)
        self.assertIn("используется", text)
        self.assertIn("Сначала снимите зависимости", text)
        self._m.save_relay_hops.assert_not_called()

    def test_via_assign_flow_framed(self):
        self._hops.append(dict(_HOP))
        self._nodes.append({"host": "nd1.example.net", "port": 443, "via": ""})
        text = self._menu(["v", "1", "1"])
        self.assertIn("VIA: ВЫБОР EXIT-НОДЫ", text)
        self.assertIn("VIA ДЛЯ EXIT-НОДЫ", text)
        self.assertIn("VIA НАЗНАЧЕНО", text)
        saved_nodes = self._m._save_chain_nodes_via.call_args[0][0]
        self.assertEqual(saved_nodes[0]["via"], "hop-one")
        self._m._offer_rebuild.assert_called_once()

    def test_check_chains_framed(self):
        self._hops.append(dict(_HOP))
        text = self._menu(["t"])
        self.assertIn("ПРОВЕРКА ЦЕПОЧЕК", text)
        self.assertIn("OK", text)
        self.assertIn("12 мс", text)


# ═════════════════════════════════════════════════════════════════════════════
#  hysteria2_exit_mgr
# ═════════════════════════════════════════════════════════════════════════════

class TestH2ExitUi(unittest.TestCase):

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import hysteria2_exit_mgr as m
        self._m = m
        self._patches = [
            patch.object(m, "h2_exit_status",
                         return_value={"active": False, "version": "",
                                       "ports": "443"}),
            patch.object(m, "h2_exit_remove"),
            patch.object(m, "h2_exit_install"),
            patch.object(m, "h2_exit_remote_install"),
            patch.object(m, "_load_h2_state",
                         return_value={"exit_nodes": [{"ip": "1.2.3.4"}]}),
            patch.object(m, "_h2_remote_status",
                         return_value={"active": "active", "version": "2.6.0",
                                       "log_tail": "2026-10-24 listening"}),
            patch.object(m, "_systemctl"),
            patch.object(m, "_service_active", return_value=False),
            patch("getpass.getpass", return_value=""),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    def _menu(self, answers):
        return _feed(self._m.do_h2_exit_menu, answers)[0]

    def test_menu_framed_and_eof_safe(self):
        text = self._menu([])
        self.assertIn("╔", text)
        self.assertIn("HYSTERIA2 — EXIT-НОДА", text)
        self.assertIn("[1]", text)
        self.assertIn("[Q]", text)

    def test_local_install_defaults_framed(self):
        text = self._menu(["1"])                    # далее EOF = дефолты
        self.assertIn("УСТАНОВКА HYSTERIA2", text)
        self.assertIn("ЛОКАЛЬНО", text)
        kwargs = self._m.h2_exit_install.call_args[1]
        self.assertEqual(kwargs["ports"], [443])
        self.assertEqual(kwargs["domain"], "")
        self.assertTrue(kwargs["auth_password"])    # авто-пароль не пуст

    def test_remote_install_flow_framed(self):
        answers = ["2", "5.6.7.8", "8443,2087", "", "22", ""]
        text = self._menu(answers)
        self.assertIn("УСТАНОВКА HYSTERIA2 НА УДАЛЁННУЮ EXIT-НОДУ", text)
        args, kwargs = self._m.h2_exit_remote_install.call_args
        self.assertEqual(args[0], "5.6.7.8")
        self.assertEqual(kwargs["ports"], [8443, 2087])
        self.assertEqual(kwargs["ssh_port"], 22)

    def test_remote_status_ssh_framed(self):
        text = self._menu(["7"])                    # хост из state по Enter
        self.assertIn("СТАТУС УДАЛЁННОЙ EXIT-НОДЫ", text)
        self.assertIn("2.6.0", text)
        self._m._h2_remote_status.assert_called_once()

    def test_delete_confirm_framed(self):
        self._menu(["6", "y"])
        self._m.h2_exit_remove.assert_called_once()
        # EOF на y/N — безопасная отмена (диалог выдерживает пайп)
        self._m.h2_exit_remove.reset_mock()
        self._menu(["6"])
        self._m.h2_exit_remove.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
