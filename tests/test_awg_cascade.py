#!/usr/bin/env python3
"""
tests/test_awg_cascade.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/awg_cascade.py.

Покрывает:
  1. _awgs_cascade_build_awg1_conf — генерация awg1.conf
  2. _awgs_cascade_create_routing_script — генерация bash-скрипта
  3. _awgs_cascade_create_systemd_unit — генерация systemd-unit
  4. _awgs_cascade_setup_cron — генерация cron-файла
  5. awgs_cascade_setup_awg1 — regression: NameError на голом NC (core.NC fix)
  6. _awgs_cascade_status — smoke: нет NameError на цветовые переменные
  7. do_manage_awg_cascade — smoke: нет NameError в TUI (mock input → 'q')
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

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


class TestAwgsCascadeBuildAwg1Conf(unittest.TestCase):
    """_awgs_cascade_build_awg1_conf — генерация awg1.conf."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                     self._state)

    def test_generates_interface_and_peer_sections(self):
        from chimera.modules import awg_cascade
        # state с дефолтными params
        self._state.write_text(json.dumps({
            "installed": True,
            "params": {"jc": 4, "jmin": 40, "jmax": 70,
                        "s1": 0, "s2": 0, "s3": 0, "s4": 0,
                        "h1": 1, "h2": 2, "h3": 3, "h4": 4,
                        "i1": "", "i2": "", "i3": "", "i4": "", "i5": ""},
        }))
        with self._patch():
            conf = awg_cascade._awgs_cascade_build_awg1_conf(
                exit_host="1.2.3.4", exit_port=51820,
                exit_pubkey="EXIT_PUBKEY", client_privkey="CLIENT_PRIV",
                psk="PSK_KEY", exit_subnet="172.16.61.0/24",
            )
        self.assertIn("[Interface]", conf)
        self.assertIn("[Peer]", conf)
        self.assertIn("CLIENT_PRIV", conf)
        self.assertIn("EXIT_PUBKEY", conf)
        self.assertIn("PSK_KEY", conf)
        self.assertIn("Jc = 4", conf)

    def test_client_ip_from_exit_subnet(self):
        """client_ip = base.2/32 где base = exit_subnet без последнего октета."""
        from chimera.modules import awg_cascade
        self._state.write_text(json.dumps({
            "installed": True, "params": {},
        }))
        with self._patch():
            conf = awg_cascade._awgs_cascade_build_awg1_conf(
                exit_host="1.2.3.4", exit_port=51820,
                exit_pubkey="PUB", client_privkey="PRIV",
                psk="", exit_subnet="172.16.61.0/24",
            )
        # base = 172.16.61 → client_ip = 172.16.61.2/32
        self.assertIn("172.16.61.2/32", conf)

    def test_omits_preshared_key_when_empty(self):
        from chimera.modules import awg_cascade
        self._state.write_text(json.dumps({
            "installed": True, "params": {},
        }))
        with self._patch():
            conf = awg_cascade._awgs_cascade_build_awg1_conf(
                exit_host="1.2.3.4", exit_port=51820,
                exit_pubkey="PUB", client_privkey="PRIV",
                psk="", exit_subnet="172.16.61.0/24",
            )
        # PSK пустой → PresharedKey не добавляется
        self.assertNotIn("PresharedKey", conf)

    # ── Regression: Table = off (SSH lockout fix) ────────────────────────────

    def test_config_contains_table_off(self):
        """Regression: awg1.conf должен содержать 'Table = off' в [Interface].

        Без Table = off awg-quick автоматически создаёт маршрут
        0.0.0.0/0 dev awg1, перехватывая весь трафик сервера (включая
        SSH-ответы) — сессия обрывается. Фикс: коммит 33970c2.
        """
        from chimera.modules import awg_cascade
        self._state.write_text(json.dumps({
            "installed": True,
            "params": {"jc": 4, "jmin": 40, "jmax": 70,
                        "s1": 0, "s2": 0, "s3": 0, "s4": 0,
                        "h1": 1, "h2": 2, "h3": 3, "h4": 4,
                        "i1": "", "i2": "", "i3": "", "i4": "", "i5": ""},
        }))
        with self._patch():
            conf = awg_cascade._awgs_cascade_build_awg1_conf(
                exit_host="1.2.3.4", exit_port=51820,
                exit_pubkey="PUB", client_privkey="PRIV",
                psk="", exit_subnet="172.16.61.0/24",
            )
        self.assertIn("Table = off", conf)
        # Table = off должен быть в [Interface] секции, а не в [Peer]
        iface_section = conf.split("[Peer]")[0]
        self.assertIn("Table = off", iface_section)

    def test_table_off_present_regardless_of_mtu_or_params(self):
        """Table = off присутствует независимо от params/mtu — безусловная строка."""
        from chimera.modules import awg_cascade
        # Тест с пустыми params и кастомным mtu
        self._state.write_text(json.dumps({
            "installed": True, "params": {}, "mtu": 1400,
        }))
        with self._patch():
            conf = awg_cascade._awgs_cascade_build_awg1_conf(
                exit_host="1.2.3.4", exit_port=51820,
                exit_pubkey="PUB", client_privkey="PRIV",
                psk="", exit_subnet="172.16.61.0/24",
            )
        self.assertIn("Table = off", conf)
        # Тест с полными params и дефолтным mtu
        self._state.write_text(json.dumps({
            "installed": True,
            "params": {"jc": 9, "jmin": 50, "jmax": 200,
                        "s1": 1, "s2": 2, "s3": 3, "s4": 4,
                        "h1": 5, "h2": 6, "h3": 7, "h4": 8,
                        "i1": "dead", "i2": "", "i3": "", "i4": "", "i5": ""},
        }))
        with self._patch():
            conf = awg_cascade._awgs_cascade_build_awg1_conf(
                exit_host="5.6.7.8", exit_port=9999,
                exit_pubkey="PUB2", client_privkey="PRIV2",
                psk="PSK", exit_subnet="10.0.0.0/24",
            )
        self.assertIn("Table = off", conf)


class TestAwgsCascadeApplyIptablesRules(unittest.TestCase):
    """_awgs_cascade_apply_iptables — regression: SSH lockout fix (OUTPUT → FORWARD).

    ЭТАП 1.6: после миграции на nftables, функция использует nft_rule_add
    вместо core._run(['iptables', ...]). Тесты патчат nft_rule_add и
    проверяют что rule_spec содержит правильные цепочки/матчеры.

    ВНИМАНИЕ: эти тесты проверяют только корректность генерируемой конфигурации/
    команд. Они не могут подтвердить отсутствие SSH lockout на реальном сервере
    — это требует ручной проверки на тестовом VPS перед использованием в проде.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def _mock_core(self):
        """Создаёт mock core, записывающий все _run вызовы."""
        core = MagicMock()
        core.log_to_file = MagicMock()
        core.info = MagicMock()
        core.warn = MagicMock()
        self._run_calls = []

        def _capture_run(cmd, **kwargs):
            self._run_calls.append(cmd)
            r = MagicMock()
            r.returncode = 0
            r.stdout = ""
            r.stderr = ""
            return r

        core._run = _capture_run
        return core

    def _capture_nft_add(self):
        """Список для записи всех вызовов nft_rule_add."""
        self._nft_add_calls = []
        def _fake_add(**kwargs):
            self._nft_add_calls.append(kwargs)
            return True
        return _fake_add

    def test_mark_rule_uses_forward_not_output(self):
        """Regression: MARK-правило использует mangle_forward chain,
        а НЕ mangle_output.

        До фикса (коммит 33970c2) правило было '-A OUTPUT', что маркировало
        весь исходящий трафик сервера (включая SSH-ответы) → SSH lockout.
        ЭТАП 1.6: в nftables проверяем что chain=mangle_forward (не output).
        """
        from chimera.modules import awg_cascade
        from chimera.modules import nft_common

        mock_core = self._mock_core()
        _fake_add = self._capture_nft_add()
        with patch.object(awg_cascade, "_core_module", return_value=mock_core), \
             patch.object(nft_common, 'nft_rule_add', side_effect=_fake_add), \
             patch.object(nft_common, 'nft_set_create', return_value=True), \
             patch.object(awg_cascade, 'nft_rule_add', side_effect=_fake_add), \
             patch.object(awg_cascade, 'nft_set_create', return_value=True):
            awg_cascade._awgs_cascade_apply_iptables("172.16.61.0/24")

        # Ищем MARK правило (с meta mark set 0x2000)
        mark_calls = [c for c in self._nft_add_calls
                      if "meta mark set" in c.get("rule_spec", "")]
        self.assertGreater(len(mark_calls), 0,
                           f"Expected at least 1 MARK rule, got: {self._nft_add_calls}")
        # Проверяем что MARK правило в mangle_forward chain (НЕ mangle_output)
        for call in mark_calls:
            self.assertEqual(call.get("chain"), "mangle_forward",
                             f"MARK rule should be in mangle_forward (not output) — "
                             f"SSH lockout regression. Got chain={call.get('chain')}")

    def test_no_leftover_conntrack_output_rule(self):
        """Regression: удалённое conntrack OUTPUT-правило отсутствует.

        ЭТАП 1.6: проверяем что в mangle_output chain нет conntrack правил.
        """
        from chimera.modules import awg_cascade
        from chimera.modules import nft_common

        mock_core = self._mock_core()
        _fake_add = self._capture_nft_add()
        with patch.object(awg_cascade, "_core_module", return_value=mock_core), \
             patch.object(nft_common, 'nft_rule_add', side_effect=_fake_add), \
             patch.object(nft_common, 'nft_set_create', return_value=True), \
             patch.object(awg_cascade, 'nft_rule_add', side_effect=_fake_add), \
             patch.object(awg_cascade, 'nft_set_create', return_value=True):
            awg_cascade._awgs_cascade_apply_iptables("172.16.61.0/24")

        # Не должно быть conntrack правил в mangle_output
        for call in self._nft_add_calls:
            if call.get("chain") == "mangle_output":
                self.assertNotIn("ct state", call.get("rule_spec", ""),
                                 "conntrack rule in mangle_output found (leftover)")

    def test_forward_mark_rule_not_for_ru_networks(self):
        """Дополнительно: FORWARD MARK правило исключает RU-сети через @awg_cascade_nodes.

        ЭТАП 1.6: вместо iptables `-m set ! --match-set awgs_ipset dst` используется
        nft синтаксис `ip daddr != @awg_cascade_nodes`.
        """
        from chimera.modules import awg_cascade
        from chimera.modules import nft_common

        mock_core = self._mock_core()
        _fake_add = self._capture_nft_add()
        with patch.object(awg_cascade, "_core_module", return_value=mock_core), \
             patch.object(nft_common, 'nft_rule_add', side_effect=_fake_add), \
             patch.object(nft_common, 'nft_set_create', return_value=True), \
             patch.object(awg_cascade, 'nft_rule_add', side_effect=_fake_add), \
             patch.object(awg_cascade, 'nft_set_create', return_value=True):
            awg_cascade._awgs_cascade_apply_iptables("172.16.61.0/24")

        # Ищем MARK правило в mangle_forward
        mark_calls = [c for c in self._nft_add_calls
                      if "meta mark set" in c.get("rule_spec", "")
                      and c.get("chain") == "mangle_forward"]
        self.assertGreater(len(mark_calls), 0,
                           f"Expected MARK rule in mangle_forward, got: {self._nft_add_calls}")
        # Должно содержать исключение через @awg_cascade_nodes
        for call in mark_calls:
            spec = call.get("rule_spec", "")
            self.assertIn("@awg_cascade_nodes", spec,
                          f"MARK rule should exclude RU-networks via @awg_cascade_nodes, "
                          f"got: {spec}")
            self.assertIn("!=", spec,
                          f"MARK rule should have != (negation), got: {spec}")


class TestAwgsCascadeCreateRoutingScript(unittest.TestCase):
    """_awgs_cascade_create_routing_script — генерация bash-скрипта."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._script = self._tmpdir / "awg-routing.sh"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        # Патчим и AWGS_CASCADE_DIR (для mkdir) и AWGS_ROUTING_SCRIPT (для write)
        return (
            patch("chimera.modules.awg_cascade.AWGS_CASCADE_DIR", self._tmpdir),
            patch("chimera.modules.awg_cascade.AWGS_ROUTING_SCRIPT", self._script),
        )

    def test_writes_script_with_ipset_references(self):
        """Скрипт содержит ссылки на nft set и exit_gw (base.1 из exit_subnet).

        ЭТАП 1.6: после миграции на nftables, вместо ipset используется nft set
        awg_cascade_nodes. Проверяем что в скрипте есть ссылка на этот set.
        Ранее f-string конфликтовал с bash ${line:0:1} → NameError при вызове
        (фикс: экранирование через ${{line:0:1}})."""
        from chimera.modules.awg_cascade import (
            _awgs_cascade_create_routing_script,
        )
        from chimera.modules.nft_constants import NFT_SET_AWG_CASCADE
        with self._patch()[0], self._patch()[1]:
            _awgs_cascade_create_routing_script("172.16.61.0/24")
        content = self._script.read_text()
        # Проверяем что скрипт ссылается на nft set awg_cascade_nodes
        self.assertIn(NFT_SET_AWG_CASCADE, content)
        # exit_gw = base.1 где base = exit_subnet без последнего октета и /CIDR
        # 172.16.61.0/24 → base=172.16.61 → exit_gw=172.16.61.1
        self.assertIn("172.16.61.1", content)
        # bash-конструкция ${line:0:1} должна остаться в скрипте как есть
        self.assertIn("${line:0:1}", content)

    def test_script_is_executable(self):
        """Скрипт создаётся с executable bit (0o755)."""
        import stat
        from chimera.modules.awg_cascade import (
            _awgs_cascade_create_routing_script,
        )
        with self._patch()[0], self._patch()[1]:
            _awgs_cascade_create_routing_script("172.16.61.0/24")
        mode = stat.S_IMODE(os.stat(self._script).st_mode)
        self.assertTrue(mode & 0o100)  # executable bit


class TestAwgsCascadeCreateSystemdUnit(unittest.TestCase):
    """_awgs_cascade_create_systemd_unit — генерация systemd-unit."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._unit = self._tmpdir / "awg-cascade-routing.service"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.awg_cascade.AWGS_SYSTEMD_CASCADE",
                     self._unit)

    def test_writes_unit_with_exec_start(self):
        from chimera.modules.awg_cascade import (
            _awgs_cascade_create_systemd_unit, AWGS_ROUTING_SCRIPT,
        )
        with self._patch():
            _awgs_cascade_create_systemd_unit()
        content = self._unit.read_text()
        self.assertIn("[Unit]", content)
        self.assertIn("[Service]", content)
        self.assertIn("ExecStart=", content)
        self.assertIn(str(AWGS_ROUTING_SCRIPT), content)


class TestAwgsCascadeSetupCron(unittest.TestCase):
    """_awgs_cascade_setup_cron — генерация cron-файла.

    v5.1: теперь функция пишет ДВА файла — wrapper bash-скрипт
    (AWGS_CRON_RU_UPDATE_SCRIPT) и cron-файл (AWGS_CRON_RU_UPDATE),
    который вызывает wrapper. Bare ``python3 -c "from chimera..."`` в
    cron НЕ работает (ModuleNotFoundError без PYTHONPATH), поэтому
    wrapper-скрипт экспорит PYTHONPATH перед вызовом python (тот же
    паттерн, что в node_health_monitor.py и geo_files.py).
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cron = self._tmpdir / "awg-cascade-ru-update"
        self._script = self._tmpdir / "awg-cascade-ru-update.sh"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("chimera.modules.awg_cascade.AWGS_CRON_RU_UPDATE",
                  self._cron),
            patch("chimera.modules.awg_cascade.AWGS_CRON_RU_UPDATE_SCRIPT",
                  self._script),
        )

    def test_writes_cron_file(self):
        from chimera.modules.awg_cascade import _awgs_cascade_setup_cron
        with self._patch()[0], self._patch()[1]:
            _awgs_cascade_setup_cron()
        self.assertTrue(self._cron.exists())
        # v5.1: cron-файл теперь ссылается на wrapper-скрипт, а не содержит
        # `python3 -c "from chimera..."` напрямую. Проверяем, что wrapper
        # указан и что в нём (через чтение wrapper-файла) есть вызов
        # целевой функции.
        content = self._cron.read_text()
        self.assertIn(str(self._script), content,
                      "cron-файл должен ссылаться на wrapper-скрипт")
        # Wrapper-скрипт тоже должен существовать и содержать вызов функции.
        self.assertTrue(self._script.exists(),
                       "wrapper-скрипт должен быть создан")
        script_content = self._script.read_text()
        self.assertIn("awgs_cascade_update_ru_zone", script_content,
                      "wrapper-скрипт должен вызывать awgs_cascade_update_ru_zone")

    def test_cron_chmod_644(self):
        import stat
        from chimera.modules.awg_cascade import _awgs_cascade_setup_cron
        with self._patch()[0], self._patch()[1]:
            _awgs_cascade_setup_cron()
        mode = stat.S_IMODE(os.stat(self._cron).st_mode)
        self.assertEqual(mode, 0o644)

    def test_wrapper_script_chmod_755(self):
        """v5.1: wrapper-скрипт должен быть исполняемым (0o755)."""
        import stat
        from chimera.modules.awg_cascade import _awgs_cascade_setup_cron
        with self._patch()[0], self._patch()[1]:
            _awgs_cascade_setup_cron()
        mode = stat.S_IMODE(os.stat(self._script).st_mode)
        self.assertEqual(mode, 0o755)

    def test_wrapper_script_has_pythonpath_export(self):
        """v5.1: wrapper-скрипт должен экспортить PYTHONPATH (иначе
        cron-вызов упадёт с ModuleNotFoundError, как и раньше)."""
        from chimera.modules.awg_cascade import _awgs_cascade_setup_cron
        with self._patch()[0], self._patch()[1]:
            _awgs_cascade_setup_cron()
        content = self._script.read_text()
        self.assertIn("export PYTHONPATH", content,
                      "wrapper-скрипт должен содержать export PYTHONPATH")
        self.assertIn("sys.path.insert", content,
                      "wrapper-скрипт должен содержать sys.path.insert")

    def test_cron_does_not_use_bare_python_c_from_chimera(self):
        """v5.1: regression — в cron-файле НЕ должно быть
        ``python3 -c "from chimera...`` (старый ломанный паттерн)."""
        from chimera.modules.awg_cascade import _awgs_cascade_setup_cron
        with self._patch()[0], self._patch()[1]:
            _awgs_cascade_setup_cron()
        content = self._cron.read_text()
        # Старый паттерн: `python3 -c "from chimera...` в самом cron-файле
        self.assertNotIn('python3 -c "from chimera', content,
                         "cron-файл НЕ должен содержать bare python3 -c "
                         "\"from chimera...\" — это ломает cron из-за "
                         "отсутствия PYTHONPATH")


# ────────────────────────────────────────────────────────────────────────────
#  Regression: awgs_cascade_setup_awg1 — NameError на голом NC
# ────────────────────────────────────────────────────────────────────────────

def _mock_core_for_cascade():
    """Создаёт mock core с цветами и box-функциями для awg_cascade."""
    core = MagicMock()
    # Цвета как пустые строки (non-tty режим)
    for attr in ("GREEN", "NC", "RED", "YELLOW", "CYAN", "BLUE", "DIM", "BOLD"):
        setattr(core, attr, "")
    # Box-функции — no-op
    for attr in ("_box_top", "_box_row", "_box_sep", "_box_bottom",
                 "_box_item", "_box_desc", "_box_wrap_msg"):
        setattr(core, attr, MagicMock())
    # info/success/warn — no-op
    for attr in ("info", "success", "warn", "error", "log_to_file"):
        setattr(core, attr, MagicMock())
    # _run для systemctl/ipset — возвращает неактивный статус
    run_result = MagicMock()
    run_result.returncode = 1
    run_result.stdout = ""
    run_result.stderr = ""
    core._run = MagicMock(return_value=run_result)
    return core


class TestAwgsCascadeSetupAwg1(unittest.TestCase):
    """awgs_cascade_setup_awg1 — regression: NameError на голом NC.

    До фикса (коммит 86a5b97) переменная NC использовалась в f-string без
    префикса core. — NameError при каждом вызове функции после успешной
    настройки AWG1. Заменено на core.NC.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_runs_without_nameerror(self):
        """Функция отрабатывает без NameError — главный regression-тест.

        Мокаются все внешние вызовы: awgs_state_is_installed (True → skip
        install), awg_peer_add (True), awgs_state_set_cascade_role (no-op),
        awgs_state_load (returns state), awgs_state_peer_find (returns peer),
        core._box_* (no-op), core.info/success (no-op).
        """
        from chimera.modules import awg_cascade

        mock_core = _mock_core_for_cascade()

        state = {
            "installed": True,
            "endpoint": "1.2.3.4",
            "port": 51820,
            "server_pubkey": "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD" * 2,
            "subnet": "10.66.66.0/24",
        }
        peer = {"name": "cascade_entry", "client_ip": "10.66.66.2/32"}

        with patch.object(awg_cascade, "_core_module", return_value=mock_core), \
             patch.object(awg_cascade, "awgs_state_is_installed", return_value=True), \
             patch.object(awg_cascade, "awg_peer_add", return_value=True), \
             patch.object(awg_cascade, "awgs_state_set_cascade_role"), \
             patch.object(awg_cascade, "awgs_state_load", return_value=state), \
             patch("chimera.modules.awg_state.awgs_state_peer_find", return_value=peer), \
             patch("chimera.modules.awg_state.awgs_state_peer_remove"), \
             patch("builtins.print"):
            # Не должно поднять NameError или любое другое исключение
            result = awg_cascade.awgs_cascade_setup_awg1()

        self.assertTrue(result)

    def test_box_row_called_with_core_nc_not_bare_nc(self):
        """core._box_row вызывается — проверяем что core.NC доступен.

        Если NC не определена, f-string внутри awgs_cascade_setup_awg1
        поднимет NameError ДО вызова _box_row. Тест проверяет что
        _box_row действительно вызывается (значит f-string отработал).
        """
        from chimera.modules import awg_cascade

        mock_core = _mock_core_for_cascade()

        state = {
            "installed": True,
            "endpoint": "1.2.3.4",
            "port": 51820,
            "server_pubkey": "PUBKEY",
            "subnet": "10.66.66.0/24",
        }
        peer = {"name": "cascade_entry", "client_ip": "10.66.66.2/32"}

        with patch.object(awg_cascade, "_core_module", return_value=mock_core), \
             patch.object(awg_cascade, "awgs_state_is_installed", return_value=True), \
             patch.object(awg_cascade, "awg_peer_add", return_value=True), \
             patch.object(awg_cascade, "awgs_state_set_cascade_role"), \
             patch.object(awg_cascade, "awgs_state_load", return_value=state), \
             patch("chimera.modules.awg_state.awgs_state_peer_find", return_value=peer), \
             patch("chimera.modules.awg_state.awgs_state_peer_remove"), \
             patch("builtins.print"):
            awg_cascade.awgs_cascade_setup_awg1()

        # _box_row должен был вызваться (минимум 5 раз для вывода данных AWG0)
        self.assertGreaterEqual(mock_core._box_row.call_count, 5)

    def test_box_row_contains_endpoint_value(self):
        """В выводе _box_row присутствует значение endpoint из state."""
        from chimera.modules import awg_cascade

        mock_core = _mock_core_for_cascade()

        state = {
            "installed": True,
            "endpoint": "5.6.7.8",
            "port": 9999,
            "server_pubkey": "TESTPUBKEY",
            "subnet": "10.66.66.0/24",
        }
        peer = {"name": "cascade_entry", "client_ip": "10.66.66.5/32"}

        with patch.object(awg_cascade, "_core_module", return_value=mock_core), \
             patch.object(awg_cascade, "awgs_state_is_installed", return_value=True), \
             patch.object(awg_cascade, "awg_peer_add", return_value=True), \
             patch.object(awg_cascade, "awgs_state_set_cascade_role"), \
             patch.object(awg_cascade, "awgs_state_load", return_value=state), \
             patch("chimera.modules.awg_state.awgs_state_peer_find", return_value=peer), \
             patch("chimera.modules.awg_state.awgs_state_peer_remove"), \
             patch("builtins.print"):
            awg_cascade.awgs_cascade_setup_awg1()

        # Проверяем что endpoint, port, subnet и client_ip попали в вывод
        all_calls = " ".join(str(c) for c in mock_core._box_row.call_args_list)
        self.assertIn("5.6.7.8", all_calls)
        self.assertIn("9999", all_calls)
        self.assertIn("10.66.66.0/24", all_calls)
        self.assertIn("10.66.66.5", all_calls)

    def test_returns_false_when_peer_add_fails(self):
        """Если awg_peer_add возвращает False — функция возвращает False."""
        from chimera.modules import awg_cascade

        mock_core = _mock_core_for_cascade()

        with patch.object(awg_cascade, "_core_module", return_value=mock_core), \
             patch.object(awg_cascade, "awgs_state_is_installed", return_value=True), \
             patch.object(awg_cascade, "awg_peer_add", return_value=False), \
             patch("chimera.modules.awg_state.awgs_state_peer_find", return_value=None), \
             patch("chimera.modules.awg_state.awgs_state_peer_remove"), \
             patch("builtins.print"):
            result = awg_cascade.awgs_cascade_setup_awg1()

        self.assertFalse(result)


class TestAwgsCascadeStatus(unittest.TestCase):
    """_awgs_cascade_status — smoke: нет NameError на цветовые переменные.

    Функция определяет GREEN, NC, RED, DIM, CYAN локально через core.* —
    тест проверяет что при вызове с замоканными зависимостями не возникает
    NameError или AttributeError.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_runs_without_nameerror_no_role(self):
        """Нет cascade_role → выводит 'Каскад не настроен' без NameError."""
        from chimera.modules import awg_cascade

        mock_core = _mock_core_for_cascade()

        with patch.object(awg_cascade, "_core_module", return_value=mock_core), \
             patch.object(awg_cascade, "awgs_state_load", return_value={}), \
             patch("builtins.print"):
            # Не должно поднять NameError
            awg_cascade._awgs_cascade_status()

        # _box_row вызывался (значит f-string с {DIM}...{NC} отработал)
        self.assertGreater(mock_core._box_row.call_count, 0)

    def test_runs_without_nameerror_entry_role(self):
        """role='entry' → проверка systemctl/ipset без NameError."""
        from chimera.modules import awg_cascade

        mock_core = _mock_core_for_cascade()

        state = {
            "cascade_role": "entry",
            "cascade_peer_host": "1.2.3.4",
            "cascade_peer_port": 51820,
            "cascade_subnet": "172.16.61.0/24",
        }

        with patch.object(awg_cascade, "_core_module", return_value=mock_core), \
             patch.object(awg_cascade, "awgs_state_load", return_value=state), \
             patch("builtins.print"):
            awg_cascade._awgs_cascade_status()

        self.assertGreater(mock_core._box_row.call_count, 0)

    def test_runs_without_nameerror_exit_role(self):
        """role='exit' → проверка standalone AWG без NameError."""
        from chimera.modules import awg_cascade

        mock_core = _mock_core_for_cascade()

        state = {"cascade_role": "exit"}

        with patch.object(awg_cascade, "_core_module", return_value=mock_core), \
             patch.object(awg_cascade, "awgs_state_load", return_value=state), \
             patch.object(awg_cascade, "awgs_service_status",
                          return_value={"active": True, "enabled": True}), \
             patch("chimera.modules.awg_state.awgs_state_peer_find",
                          return_value={"client_ip": "10.66.66.2/32"}), \
             patch("builtins.print"):
            awg_cascade._awgs_cascade_status()

        self.assertGreater(mock_core._box_row.call_count, 0)


class TestDoManageAwgCascade(unittest.TestCase):
    """do_manage_awg_cascade — smoke: нет NameError в TUI.

    TUI-меню с while True + input(). Мокаем input() → 'q' для немедленного
    выхода. Проверяем что рендеринг меню (f-string с NC/GREEN/DIM) не
    вызывает NameError.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_menu_renders_without_nameerror(self):
        """Меню рендерится и выходит по 'q' без NameError."""
        from chimera.modules import awg_cascade

        mock_core = _mock_core_for_cascade()

        with patch.object(awg_cascade, "_core_module", return_value=mock_core), \
             patch.object(awg_cascade, "awgs_state_load", return_value={}), \
             patch("builtins.input", return_value="q"), \
             patch("os.system"), \
             patch("builtins.print"):
            # Не должно поднять NameError
            awg_cascade.do_manage_awg_cascade()

        # _box_top вызывался (значит меню отрендерилось)
        self.assertGreater(mock_core._box_top.call_count, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
