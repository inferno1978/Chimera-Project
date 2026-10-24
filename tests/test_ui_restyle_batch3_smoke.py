#!/usr/bin/env python3
"""
tests/test_ui_restyle_batch3_smoke.py
───────────────────────────────────────────────────────────────────────────────
UI-smoke стилизации третьей партии модулей (окт.2026, продолжение кейса
batch2: as_direct/ttl_users/chain_relay/hysteria2_exit_mgr): failover,
updater, dnscrypt_advanced.

Все интерактивные диалоги рисуются рамками box_renderer и не падают под
пайпом (EOF на input = значение по умолчанию / отмена / назад — канон
icmp_gate._ig_pause / as_direct._pause). Подтверждения с последствиями
(установка watchdog, git pull, применение пресета, перезапуск TUI) под
EOF обязаны ОТМЕНЯТЬСЯ, а не срабатывать.

Канон харнесса: tests/test_ui_restyle_batch2_smoke.py / entry_mirrors.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _feed(func, answers, *args, **kwargs):
    """Прогоняет func с очередью ответов на input (EOF = исчерпание).

    Промпт input() эхается в захваченный stdout — можно ассертить тексты
    приглашений (канон batch2).
    """
    it = iter(answers)

    def _fake_input(prompt=""):
        print(prompt, end="")
        try:
            return next(it)
        except StopIteration:
            raise EOFError

    out = io.StringIO()
    with patch("builtins.input", _fake_input), redirect_stdout(out):
        func(*args, **kwargs)
    return out.getvalue()


def _rc(code=0, out="", err=""):
    return subprocess.CompletedProcess([], code, out, err)


# ═════════════════════════════════════════════════════════════════════════════
#  FAILOVER
# ═════════════════════════════════════════════════════════════════════════════
class FailoverSmokeBase(unittest.TestCase):
    def setUp(self):
        from chimera.modules import box_renderer as br
        from chimera.modules import failover

        self.failover = failover
        self.tmp = Path(tempfile.mkdtemp())

        core = MagicMock()
        for name in ("_box_top", "_box_row", "_box_sep", "_box_bottom",
                     "_box_item", "_box_back", "_box_warn", "_box_ok",
                     "_box_info", "_box_kv", "_box_desc", "_box_ask",
                     "_box_input", "_box_item_exit"):
            setattr(core, name, getattr(br, name))
        for name in ("RED", "GREEN", "YELLOW", "CYAN", "BLUE", "BOLD",
                     "DIM", "WHITE", "NC"):
            setattr(core, name, "")
        core.STATE_FILE = self.tmp / "state.json"
        core.STATE_FILE.write_text(json.dumps({"install_mode": "B"}))
        core._nodes_from_state = lambda st: [
            {"host": "10.0.0.1", "port": 443},
            {"host": "10.0.0.2", "port": 8443},
        ]
        core._speed_test_node_latency = lambda h, p: "42 мс"
        core.success = MagicMock(side_effect=lambda m: print(f"  OK: {m}"))
        core.warn    = MagicMock(side_effect=lambda m: print(f"  WARN: {m}"))
        core.info    = MagicMock(side_effect=lambda m: print(f"  INFO: {m}"))
        core.switch_mode_ab = MagicMock()
        core._AUTO_FALLBACK_CRON    = self.tmp / "af.cron"      # не существует
        core._AUTO_FALLBACK_SCRIPT  = self.tmp / "af.sh"
        core._AUTO_FALLBACK_LOGFILE = self.tmp / "af.log"
        self.core = core

        self._patcher = patch.object(failover, "_core_module",
                                     return_value=core)
        self._patcher.start()
        self.addCleanup(self._patcher.stop)

        # state/логи failover — во временную директорию
        self._st = patch.object(failover, "_FAILOVER_STATE",
                                self.tmp / "failover.json")
        self._st.start()
        self.addCleanup(self._st.stop)
        self._lg = patch.object(failover, "_FAILOVER_LOG",
                                self.tmp / "failover.log")
        self._lg.start()
        self.addCleanup(self._lg.stop)


class TestFailoverStatusUI(FailoverSmokeBase):
    def test_menu_framed_and_eof_safe(self):
        out = _feed(self.failover.do_failover_status, [])
        self.assertIn("Failover Exit-нод", out)
        self.assertIn("║", out)
        self.assertIn("[1]", out)          # рамочный список пунктов
        self.assertNotIn("Traceback", out)

    def test_menu_eof_exits_not_crashes(self):
        # EOF сразу → выбор "" → назад: ни одного исключения наружу
        try:
            _feed(self.failover.do_failover_status, [])
        except EOFError:
            self.fail("EOF пробросился наружу вместо выхода в меню")

    def test_install_flow_framed_with_confirm(self):
        with patch.object(self.failover, "_failover_install") as inst:
            out = _feed(self.failover.do_failover_status,
                        ["1", "", "y"])
        inst.assert_called_once()
        nodes, token, chat = inst.call_args[0]
        self.assertEqual(len(nodes), 2)
        self.assertEqual(token, "")
        self.assertIn("TELEGRAM-АЛЕРТЫ WATCHDOG", out)
        self.assertIn("Установить watchdog", out)

    def test_install_eof_cancels(self):
        with patch.object(self.failover, "_failover_install") as inst:
            _feed(self.failover.do_failover_status, ["1", "", ""])
        inst.assert_not_called()

    def test_manual_check_framed_with_summary(self):
        out = _feed(self.failover.do_failover_status, ["2"])
        self.assertIn("ПРОВЕРКА EXIT-НОД ПРЯМО СЕЙЧАС", out)
        self.assertIn("Живых нод: 2 из 2", out)
        state = json.loads((self.tmp / "failover.json").read_text())
        self.assertEqual(state["10.0.0.1"]["status"], "up")

    def test_log_view_framed(self):
        (self.tmp / "failover.log").write_text(
            "[2026-10-24 10:00:00] FAILOVER: 10.0.0.1:443 DOWN\n")
        out = _feed(self.failover.do_failover_status, ["3"])
        self.assertIn("ЛОГ FAILOVER WATCHDOG", out)
        self.assertIn("10.0.0.1:443 DOWN", out)
        self.assertIn("║", out)

    def test_log_missing_warn_box(self):
        out = _feed(self.failover.do_failover_status, ["3"])
        self.assertIn("[WARN]", out)

    def test_awg_guard_framed_eof_safe(self):
        self.core.STATE_FILE.write_text(json.dumps(
            {"install_mode": "B", "awg_exit_enabled": True}))
        out = _feed(self.failover.do_failover_status, [])
        self.assertIn("AWG 2.0", out)
        self.assertIn("║", out)


class TestAutoFallbackUI(FailoverSmokeBase):
    def test_menu_framed_and_eof_safe(self):
        out = _feed(self.failover.do_manage_auto_fallback, [])
        self.assertIn("Авто-фолбэк", out)
        self.assertIn("║", out)
        self.assertIn("auto_fallback_to_direct", out)

    def test_flag_toggle_eof_safe(self):
        with patch.object(self.failover, "_auto_fallback_set_flag") as sf:
            _feed(self.failover.do_manage_auto_fallback, ["1"])
        sf.assert_called_once_with(True)

    def test_install_flow_confirm(self):
        with patch.object(self.failover, "_auto_fallback_install") as inst, \
             patch.object(self.failover, "_auto_fallback_set_flag") as sf:
            out = _feed(self.failover.do_manage_auto_fallback,
                        ["2", "", "y"])
        inst.assert_called_once()
        sf.assert_called_with(True)
        self.assertIn("TELEGRAM-АЛЕРТЫ WATCHDOG", out)

    def test_install_mode_a_warns_framed(self):
        self.core.STATE_FILE.write_text(json.dumps({"install_mode": "A"}))
        with patch.object(self.failover, "_auto_fallback_install") as inst:
            out = _feed(self.failover.do_manage_auto_fallback, ["2"])
        inst.assert_not_called()
        self.assertIn("только при Режиме B", out)
        self.assertIn("║", out)

    def test_log_view_framed(self):
        self.core._AUTO_FALLBACK_LOGFILE = self.tmp / "af.log"
        (self.tmp / "af.log").write_text(
            "[2026-10-24 09:00:00] Все exit-ноды недоступны.\n")
        out = _feed(self.failover.do_manage_auto_fallback, ["l"])
        self.assertIn("ЛОГ АВТО-ФОЛБЭКА", out)
        self.assertIn("Все exit-ноды недоступны", out)


# ═════════════════════════════════════════════════════════════════════════════
#  UPDATER
# ═════════════════════════════════════════════════════════════════════════════
class UpdaterSmokeBase(unittest.TestCase):
    def setUp(self):
        from chimera.modules import updater

        self.upd = updater
        self.tmp = Path(tempfile.mkdtemp())
        self.repo = self.tmp / "repo"
        (self.repo / ".git").mkdir(parents=True)

        self._find = patch.object(updater, "find_repo_root",
                                  return_value=self.repo)
        self._find.start()
        self.addCleanup(self._find.stop)

        self._cron = patch.object(updater, "CRON_FILE", self.tmp / "cron")
        self._cron.start()
        self.addCleanup(self._cron.stop)

        self._log = patch.object(updater, "LOG_FILE", self.tmp / "update.log")
        self._log.start()
        self.addCleanup(self._log.stop)

    def _patch_info(self, **info):
        base = {"repo": str(self.repo), "branch": "main",
                "remote_branch": "main", "local": "aaa111222333444555",
                "remote": "bbb666777888999000", "behind": 0, "ahead": 0,
                "new_commits": [], "fetched_at": 0, "error": None,
                "fetch_err": None, "cached": False}
        base.update(info)
        self._info = patch.object(self.upd, "update_info",
                                  return_value=base)
        self._info.start()
        self.addCleanup(self._info.stop)
        return base


class TestUpdateInteractiveUI(UpdaterSmokeBase):
    def test_up_to_date_boxed_eof_safe(self):
        self._patch_info(behind=0)
        out = _feed(self.upd.do_update_interactive, [])
        self.assertIn("последняя версия", out)
        self.assertIn("║", out)
        self.assertNotIn("Traceback", out)

    def test_fetch_failed_framed_with_git_text(self):
        self._patch_info(error="fetch-failed",
                         fetch_err="fatal: unable to access 'https://…': 403")
        out = _feed(self.upd.do_update_interactive, [])
        self.assertIn("git fetch не удался", out)
        self.assertIn("403", out)
        self.assertIn("fetch origin", out)

    def test_confirm_eof_cancels_no_pull(self):
        self._patch_info(behind=2, new_commits=[("abc123def", "fix: что-то")])
        with patch.object(self.upd, "_git_retry") as pull:
            _feed(self.upd.do_update_interactive, [])
        pull.assert_not_called()

    def test_confirm_y_pulls_and_result_box(self):
        info = self._patch_info(behind=2, new_commits=[("abc123def", "fix")])
        with patch.object(self.upd, "_git_retry", return_value=_rc(0)) as pull, \
             patch.object(self.upd, "tree_state",
                          return_value={"dirty": False, "entries": [],
                                        "untracked": []}), \
             patch.object(self.upd, "_head", return_value="bbb666777888999000"), \
             patch.object(self.upd, "_current_version",
                          return_value="9.9.9"), \
             patch.object(self.upd, "_remember_session_head") as rh, \
             patch.object(self.upd, "_restart_tui") as rs:
            out = _feed(self.upd.do_update_interactive, ["y"])
        pull.assert_called_once()
        rs.assert_not_called()          # EOF на перезапуск = отмена
        rh.assert_called_once()
        self.assertIn("РЕЗУЛЬТАТ ОБНОВЛЕНИЯ", out)
        self.assertIn("Обновлено:", out)

    def test_dirty_tree_stash_dialog_framed(self):
        self._patch_info(behind=1)
        with patch.object(self.upd, "_git_retry", return_value=_rc(0)) as pull, \
             patch.object(self.upd, "tree_state",
                          return_value={"dirty": True,
                                        "entries": ["M  chimera/x.py"],
                                        "untracked": []}), \
             patch.object(self.upd, "_git", return_value=_rc(0)), \
             patch.object(self.upd, "_head", return_value="bbb666777888999000"), \
             patch.object(self.upd, "_current_version",
                          return_value="9.9.9"), \
             patch.object(self.upd, "_remember_session_head"), \
             patch.object(self.upd, "_restart_tui"):
            out = _feed(self.upd.do_update_interactive, ["y", "s"])
        pull.assert_called_once()
        self.assertIn("НЕЗАКОММИЧЕННЫЕ ПРАВКИ", out)
        self.assertIn("спрятать в stash", out)
        self.assertIn("M  chimera/x.py", out)

    def test_dirty_dialog_eof_means_cancel(self):
        self._patch_info(behind=1)
        with patch.object(self.upd, "_git_retry") as pull, \
             patch.object(self.upd, "tree_state",
                          return_value={"dirty": True,
                                        "entries": ["M  chimera/x.py"],
                                        "untracked": []}):
            out = _feed(self.upd.do_update_interactive, ["y"])
        pull.assert_not_called()
        self.assertIn("Отмена", out)

    def test_pull_error_framed(self):
        self._patch_info(behind=1)
        with patch.object(self.upd, "_git_retry",
                          return_value=_rc(1, err="fatal: Not possible to fast-forward")), \
             patch.object(self.upd, "tree_state",
                          return_value={"dirty": False, "entries": [],
                                        "untracked": []}):
            out = _feed(self.upd.do_update_interactive, ["y"])
        self.assertIn("ОШИБКА ОБНОВЛЕНИЯ", out)
        self.assertIn("fast-forward", out)
        self.assertIn("pull --ff-only", out)


class TestManageUpdateUI(UpdaterSmokeBase):
    def test_menu_framed_and_eof_safe(self):
        self._patch_info()
        with patch.object(self.upd, "cron_enabled", return_value=False), \
             patch.object(self.upd, "autocheck_enabled", return_value=True):
            out = _feed(self.upd.do_manage_update, [])
        self.assertIn("ОБНОВЛЕНИЕ CHIMERA", out)
        self.assertIn("║", out)

    def test_toggle_cron_confirm_y(self):
        self._patch_info()
        with patch.object(self.upd, "cron_enabled", return_value=False), \
             patch.object(self.upd, "autocheck_enabled", return_value=True), \
             patch.object(self.upd, "manage_cron",
                          return_value=True) as mc:
            _feed(self.upd.do_manage_update, ["2", "y"])
        mc.assert_called_once_with(True)

    def test_toggle_cron_eof_cancels(self):
        self._patch_info()
        with patch.object(self.upd, "cron_enabled", return_value=False), \
             patch.object(self.upd, "autocheck_enabled", return_value=True), \
             patch.object(self.upd, "manage_cron",
                          return_value=True) as mc:
            _feed(self.upd.do_manage_update, ["2"])
        mc.assert_not_called()

    def test_log_view_framed(self):
        self._patch_info()
        (self.tmp / "update.log").write_text(
            "2026-10-24 04:30:00 OK: обновлён aaa → bbb (+3)\n")
        with patch.object(self.upd, "cron_enabled", return_value=False), \
             patch.object(self.upd, "autocheck_enabled", return_value=True):
            out = _feed(self.upd.do_manage_update, ["l"])
        self.assertIn("ЛОГ АВТООБНОВЛЕНИЙ", out)
        self.assertIn("OK: обновлён", out)
        self.assertIn("║", out)


# ═════════════════════════════════════════════════════════════════════════════
#  DNSCRYPT ADVANCED
# ═════════════════════════════════════════════════════════════════════════════
class DnscryptSmokeBase(unittest.TestCase):
    """Патчит только UI-слой: _safe_apply_preset/_apply_single_param — моки,
    конфиг и RTT — из временных данных. /etc/dnscrypt-proxy не трогается."""

    SAMPLE_CONF = (
        "listen_addresses = ['127.0.0.1:5300']\n"
        "server_names = ['srv-a', 'srv-b']\n"
        "cache_size = 32768\n"
        "lb_strategy = 'p2'\n"
        "require_dnssec = true\n"
    )

    def setUp(self):
        from chimera.modules import dnscrypt_advanced as adv

        self.adv = adv
        self.tmp = Path(tempfile.mkdtemp())

        binp = self.tmp / "dnscrypt-proxy"
        binp.write_text("#!/bin/sh\n")
        self._bin = patch.object(adv, "_DNSCRYPT_BIN", binp)
        self._bin.start()
        self.addCleanup(self._bin.stop)

        self._cfg = patch.object(adv, "_read_config",
                                 return_value=self.SAMPLE_CONF)
        self._cfg.start()
        self.addCleanup(self._cfg.stop)

        self._apply_patcher = patch.object(adv, "_safe_apply_preset")
        self._apply = self._apply_patcher.start()
        self.addCleanup(self._apply_patcher.stop)

        self._one_patcher = patch.object(adv, "_apply_single_param",
                                         return_value=True)
        self._one = self._one_patcher.start()
        self.addCleanup(self._one_patcher.stop)

        self._rtt = patch.object(adv, "_measure_rtt",
                                 return_value={n: 12.0 for n in adv._SERVER_NAMES})
        self._rtt.start()
        self.addCleanup(self._rtt.stop)


class TestDnscryptPresetUI(DnscryptSmokeBase):
    def test_preset_screen_framed_eof_cancels(self):
        out = _feed(self.adv._screen_preset, [])
        self.assertIn("ПРЕСЕТ:", out)
        self.assertIn("dnscry.pt-moscow", out)     # чиненая dim-строка
        self.assertIn("║", out)
        self._apply.assert_not_called()

    def test_preset_enter_applies(self):
        _feed(self.adv._screen_preset, [""])
        self._apply.assert_called_once()
        names = self._apply.call_args[0][0]
        self.assertEqual(len(names), len(self.adv._SERVER_NAMES))


class TestDnscryptRttUI(DnscryptSmokeBase):
    def test_rtt_eof_returns_without_apply(self):
        out = _feed(self.adv._screen_rtt_select, [])
        self.assertIn("РЕЗУЛЬТАТ RTT-ЗАМЕРА", out)
        self._apply.assert_not_called()

    def test_rtt_pick_numbers_then_enter_applies(self):
        out = _feed(self.adv._screen_rtt_select, ["1,2", ""])
        self.assertIn("ВЫБРАННЫЕ СЕРВЕРЫ (2)", out)
        self._apply.assert_called_once()
        chosen = self._apply.call_args[0][0]
        self.assertEqual(len(chosen), 2)

    def test_rtt_pick_none_warns_framed(self):
        out = _feed(self.adv._screen_rtt_select, ["zzz"])
        self.assertIn("Ни одного сервера не выбрано", out)
        self._apply.assert_not_called()

    def test_rtt_bin_missing_warn_box(self):
        self._bin.stop()
        binp = self.tmp / "nope"
        with patch.object(self.adv, "_DNSCRYPT_BIN", binp):
            out = _feed(self.adv._screen_rtt_select, [])
        self.assertIn("не установлен", out)
        self.assertIn("║", out)


class TestDnscryptManualParamsUI(DnscryptSmokeBase):
    def test_menu_framed_eof_back(self):
        out = _feed(self.adv._screen_manual_params, [])
        self.assertIn("РУЧНАЯ НАСТРОЙКА ПАРАМЕТРОВ", out)
        self.assertIn("║", out)

    def test_int_param_edit_framed_validation(self):
        # 14-й пункт — cache_size (int): мусор → рамочный отказ
        out = _feed(self.adv._screen_manual_params, ["14", "abc"])
        self.assertIn("ПАРАМЕТР:", out)
        self.assertIn("Нужно целое число", out)
        self._one.assert_not_called()

    def test_int_param_edit_ok(self):
        _feed(self.adv._screen_manual_params, ["14", "65536"])
        self._one.assert_called_once()
        self.assertEqual(self._one.call_args[0][:2], ("cache_size", "65536"))

    def test_str_param_lb_strategy_hint(self):
        # 22-й пункт — lb_strategy (str): подсказка вариантов
        out = _feed(self.adv._screen_manual_params, ["22", ""])
        self.assertIn("fastest_addr", out)
        self.assertIn("Отмена", out)
        self._one.assert_not_called()

    def test_unknown_kv_warns_framed(self):
        out = _feed(self.adv._screen_manual_params, ["bogus_key=1"])
        self.assertIn("Неизвестный параметр", out)
        self.assertIn("║", out)

    def test_bool_toggle_eof_safe(self):
        # 1-й пункт — require_dnssec (bool): переключение без ввода значения
        _feed(self.adv._screen_manual_params, ["1"])
        self._one.assert_called_once()
        self.assertEqual(self._one.call_args[0][:2],
                         ("require_dnssec", "false"))


class TestDnscryptStatusAndMenuUI(DnscryptSmokeBase):
    def test_status_framed_eof_safe(self):
        out = _feed(self.adv._screen_status, [])
        self.assertIn("СТАТУС DNSCRYPT-PROXY", out)
        self.assertIn("srv-a", out)
        self.assertIn("║", out)

    def test_main_menu_framed_eof_back(self):
        out = _feed(self.adv.do_dnscrypt_advanced_menu, [])
        self.assertIn("РАСШИРЕННАЯ НАСТРОЙКА DNSCRYPT-PROXY", out)
        self.assertIn("║", out)

    def test_main_menu_pool_sync_eof_safe(self):
        fake_sync = MagicMock()
        fake_mod = MagicMock(run_pool_sync_now=fake_sync,
                             do_dnscrypt_update_menu=lambda: None)
        with patch.dict("sys.modules",
                        {"chimera.modules.dnscrypt_update": fake_mod}):
            out = _feed(self.adv.do_dnscrypt_advanced_menu, ["5"])
        fake_sync.assert_called_once()
        self.assertIn("║", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
