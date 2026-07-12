#!/usr/bin/env python3
"""
tests/test_singbox_vless_ws_cdn_fix3.py
───────────────────────────────────────────────────────────────────────────────
Тесты для v4.23.3 — 2 фикса порядка операций:

1. _switch_cdn_provider(): allowlist применяется ДО generate_config/restart,
   не после — не оставляем окно с открытым портом без защиты.

2. systemd unit: Before=netfilter-persistent.service — ipset restore
   отрабатывает ДО netfilter-persistent, иначе iptables-restore падает
   на ссылке на несуществующий ipset.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import textwrap
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch, MagicMock, call

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("vless_installer._core")
    m.__dict__.update(g)
    sys.modules["vless_installer._core"] = m


def _enter_patches(stack, patches):
    for p in patches:
        stack.enter_context(p)


# ══════════════════════════════════════════════════════════════════════════════
# ФИКС 1: _switch_cdn_provider() — порядок операций
# ══════════════════════════════════════════════════════════════════════════════

class TestSwitchProviderOperationOrder(unittest.TestCase):
    """allowlist применяется ДО generate_config/restart, не после.

    Тест записывает порядок вызовов в общий список через side_effect,
    затем проверяет что apply_cdn_allowlist вызывается РАНЬШЕ
    singbox_generate_config и singbox_restart.
    """

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_config.SINGBOX_CONFIG_DIR", self._tmpdir / "sb"),
            patch("vless_installer.modules.singbox_config.SINGBOX_CONFIG_FILE", self._tmpdir / "sb" / "config.json"),
        ]

    def test_allowlist_applied_before_generate_config_and_restart(self):
        """apply_cdn_allowlist вызывается ДО singbox_generate_config и singbox_restart.

        side_effect записывает имя функции в общий список call_order.
        Проверяем позицию: apply_cdn_allowlist[0] раньше generate_config[1] раньше restart[2].
        """
        from vless_installer.modules.singbox_config import singbox_enable_vless_ws_cdn
        from vless_installer.modules.singbox_state import singbox_state_init
        from vless_installer.modules import singbox_menu

        call_order: list[str] = []

        def make_recorder(name):
            def recorder(*args, **kwargs):
                call_order.append(name)
                if name == "apply_cdn_allowlist":
                    return True
                return None
            return recorder

        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            # Подготавливаем state с включённым gcore
            stack.enter_context(patch("vless_installer.modules.singbox_cdn_nets.apply_cdn_allowlist",
                                      return_value=True))
            singbox_state_init(version="1.0.0")
            singbox_enable_vless_ws_cdn(cdn_provider="gcore", host="test.example.com")

            # Теперь мокаем функции для switch с записью порядка
            stack.enter_context(patch("vless_installer.modules.singbox_cdn_nets.apply_cdn_allowlist",
                                      side_effect=make_recorder("apply_cdn_allowlist")))
            stack.enter_context(patch("vless_installer.modules.singbox_cdn_nets.remove_cdn_allowlist",
                                      side_effect=make_recorder("remove_cdn_allowlist")))
            stack.enter_context(patch.object(singbox_menu, "singbox_generate_config",
                                             side_effect=make_recorder("singbox_generate_config")))
            stack.enter_context(patch.object(singbox_menu, "singbox_restart",
                                             side_effect=make_recorder("singbox_restart")))
            stack.enter_context(patch.object(singbox_menu, "_service_active", return_value=True))
            stack.enter_context(patch.object(singbox_menu, "_pick_cdn_provider",
                                             return_value="cloudflare"))
            stack.enter_context(patch.object(singbox_menu, "_show_cdn_instructions"))
            stack.enter_context(patch.object(singbox_menu, "info"))
            stack.enter_context(patch.object(singbox_menu, "warn"))
            stack.enter_context(patch.object(singbox_menu, "success"))

            singbox_menu._switch_cdn_provider()

        # Проверяем порядок: apply_cdn_allowlist ДО singbox_generate_config ДО singbox_restart
        self.assertIn("apply_cdn_allowlist", call_order)
        self.assertIn("singbox_generate_config", call_order)
        self.assertIn("singbox_restart", call_order)

        apply_idx = call_order.index("apply_cdn_allowlist")
        gen_idx = call_order.index("singbox_generate_config")
        restart_idx = call_order.index("singbox_restart")

        self.assertLess(apply_idx, gen_idx,
                        f"apply_cdn_allowlist (pos {apply_idx}) должен вызываться ДО "
                        f"singbox_generate_config (pos {gen_idx}). Order: {call_order}")
        self.assertLess(gen_idx, restart_idx,
                        f"singbox_generate_config (pos {gen_idx}) должен вызываться ДО "
                        f"singbox_restart (pos {restart_idx}). Order: {call_order}")

    def test_restart_not_before_allowlist(self):
        """singbox_restart НЕ должен вызываться раньше apply_cdn_allowlist."""
        from vless_installer.modules.singbox_config import singbox_enable_vless_ws_cdn
        from vless_installer.modules.singbox_state import singbox_state_init
        from vless_installer.modules import singbox_menu

        call_order: list[str] = []

        def make_recorder(name):
            def recorder(*args, **kwargs):
                call_order.append(name)
                if name == "apply_cdn_allowlist":
                    return True
                return None
            return recorder

        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            stack.enter_context(patch("vless_installer.modules.singbox_cdn_nets.apply_cdn_allowlist",
                                      return_value=True))
            singbox_state_init(version="1.0.0")
            singbox_enable_vless_ws_cdn(cdn_provider="gcore", host="test.example.com")

            stack.enter_context(patch("vless_installer.modules.singbox_cdn_nets.apply_cdn_allowlist",
                                      side_effect=make_recorder("apply_cdn_allowlist")))
            stack.enter_context(patch("vless_installer.modules.singbox_cdn_nets.remove_cdn_allowlist",
                                      side_effect=make_recorder("remove_cdn_allowlist")))
            stack.enter_context(patch.object(singbox_menu, "singbox_generate_config",
                                             side_effect=make_recorder("singbox_generate_config")))
            stack.enter_context(patch.object(singbox_menu, "singbox_restart",
                                             side_effect=make_recorder("singbox_restart")))
            stack.enter_context(patch.object(singbox_menu, "_service_active", return_value=True))
            stack.enter_context(patch.object(singbox_menu, "_pick_cdn_provider",
                                             return_value="cloudflare"))
            stack.enter_context(patch.object(singbox_menu, "_show_cdn_instructions"))
            stack.enter_context(patch.object(singbox_menu, "info"))
            stack.enter_context(patch.object(singbox_menu, "warn"))
            stack.enter_context(patch.object(singbox_menu, "success"))

            singbox_menu._switch_cdn_provider()

        restart_idx = call_order.index("singbox_restart")
        apply_idx = call_order.index("apply_cdn_allowlist")
        self.assertGreater(restart_idx, apply_idx,
                           f"singbox_restart (pos {restart_idx}) НЕ должен вызываться раньше "
                           f"apply_cdn_allowlist (pos {apply_idx}). Order: {call_order}")

    def test_old_port_allowlist_removed_after_restart(self):
        """remove_cdn_allowlist(old_port) вызывается ПОСЛЕ restart (не раньше)."""
        from vless_installer.modules.singbox_config import singbox_enable_vless_ws_cdn
        from vless_installer.modules.singbox_state import singbox_state_init
        from vless_installer.modules import singbox_menu

        # Записываем (имя_функции, аргумент_порта) в общем списке
        call_log: list[tuple[str, int]] = []

        def make_recorder(name, is_allowlist=False):
            def recorder(*args, **kwargs):
                port_arg = args[0] if args else kwargs.get("port", 0)
                call_log.append((name, port_arg))
                if is_allowlist:
                    return True
                return None
            return recorder

        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            stack.enter_context(patch("vless_installer.modules.singbox_cdn_nets.apply_cdn_allowlist",
                                      return_value=True))
            singbox_state_init(version="1.0.0")
            # Enable на gcore → listen_port = 8443
            singbox_enable_vless_ws_cdn(cdn_provider="gcore", host="test.example.com")

            # Теперь мокаем с записью (имя, порт)
            stack.enter_context(patch("vless_installer.modules.singbox_cdn_nets.apply_cdn_allowlist",
                                      side_effect=make_recorder("apply_cdn_allowlist", is_allowlist=True)))
            stack.enter_context(patch("vless_installer.modules.singbox_cdn_nets.remove_cdn_allowlist",
                                      side_effect=make_recorder("remove_cdn_allowlist")))
            # singbox_generate_config и singbox_restart не имеют port-аргумента
            stack.enter_context(patch.object(singbox_menu, "singbox_generate_config",
                                             side_effect=lambda *a, **k: call_log.append(("singbox_generate_config", 0))))
            stack.enter_context(patch.object(singbox_menu, "singbox_restart",
                                             side_effect=lambda *a, **k: call_log.append(("singbox_restart", 0))))
            stack.enter_context(patch.object(singbox_menu, "_service_active", return_value=True))
            stack.enter_context(patch.object(singbox_menu, "_pick_cdn_provider",
                                             return_value="cloudflare"))
            stack.enter_context(patch.object(singbox_menu, "_show_cdn_instructions"))
            stack.enter_context(patch.object(singbox_menu, "info"))
            stack.enter_context(patch.object(singbox_menu, "warn"))
            stack.enter_context(patch.object(singbox_menu, "success"))

            singbox_menu._switch_cdn_provider()

        # old_port = 8443 (gcore default), new port = 8080 (cloudflare default)
        # call_log должен содержать:
        #   remove_cdn_allowlist(8080) — ДО restart (очистка нового порта)
        #   apply_cdn_allowlist(8080) — ДО restart
        #   singbox_generate_config(0)
        #   singbox_restart(0)
        #   remove_cdn_allowlist(8443) — ПОСЛЕ restart (старый порт)
        names = [name for name, _ in call_log]

        # restart_idx — позиция singbox_restart в call_log
        self.assertIn("singbox_restart", names)
        restart_idx = names.index("singbox_restart")

        # Находим remove_cdn_allowlist с портом 8443 (old_port)
        old_port_remove_indices = [i for i, (name, port) in enumerate(call_log)
                                   if name == "remove_cdn_allowlist" and port == 8443]
        self.assertGreater(len(old_port_remove_indices), 0,
                           f"remove_cdn_allowlist(8443) должен вызываться. "
                           f"Call log: {call_log}")

        # Хотя бы один remove_cdn_allowlist(8443) после restart
        post_restart_removes = [i for i in old_port_remove_indices if i > restart_idx]
        self.assertGreater(len(post_restart_removes), 0,
                           f"remove_cdn_allowlist(8443) должен вызываться ПОСЛЕ restart "
                           f"(pos {restart_idx}). Call log: {call_log}")


# ══════════════════════════════════════════════════════════════════════════════
# ФИКС 2: systemd unit — Before=netfilter-persistent.service
# ══════════════════════════════════════════════════════════════════════════════

class TestSystemdUnitBeforeNetfilterPersistent(unittest.TestCase):
    """_ipset_restore_unit_install() генерирует unit с Before=netfilter-persistent.service."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._unit_path = self._tmpdir / "singbox-cdn-ipset-restore.service"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_unit_contains_before_netfilter_persistent(self):
        """Before=netfilter-persistent.service присутствует в юните."""
        from vless_installer.modules.singbox_cdn_nets import _ipset_restore_unit_install
        from vless_installer.modules import singbox_cdn_nets

        with patch.object(singbox_cdn_nets, "_RESTORE_SVC", self._unit_path):
            with patch.object(singbox_cdn_nets, "_IPSET_CONF", self._tmpdir / "ipset.conf"):
                with patch("subprocess.run", return_value=MagicMock(returncode=0)):
                    _ipset_restore_unit_install()

        self.assertTrue(self._unit_path.exists())
        content = self._unit_path.read_text()
        self.assertIn("Before=netfilter-persistent.service", content,
                      "Unit должен содержать Before=netfilter-persistent.service")

    def test_unit_contains_before_sing_box_service(self):
        """Before=sing-box.service тоже присутствует (не заменён, а добавлен)."""
        from vless_installer.modules.singbox_cdn_nets import _ipset_restore_unit_install
        from vless_installer.modules import singbox_cdn_nets

        with patch.object(singbox_cdn_nets, "_RESTORE_SVC", self._unit_path):
            with patch.object(singbox_cdn_nets, "_IPSET_CONF", self._tmpdir / "ipset.conf"):
                with patch("subprocess.run", return_value=MagicMock(returncode=0)):
                    _ipset_restore_unit_install()

        content = self._unit_path.read_text()
        self.assertIn("Before=sing-box.service", content,
                      "Before=sing-box.service должен присутствовать")
        self.assertIn("Before=netfilter-persistent.service", content,
                      "Before=netfilter-persistent.service должен присутствовать")

    def test_unit_has_two_separate_before_lines(self):
        """Два отдельных Before= (не одна строка через пробел).

        systemd поддерживает оба варианта, но тест проверяет что оба target'а
        видны в юните как отдельные директивы — это формат, который мы генерируем.
        """
        from vless_installer.modules.singbox_cdn_nets import _ipset_restore_unit_install
        from vless_installer.modules import singbox_cdn_nets

        with patch.object(singbox_cdn_nets, "_RESTORE_SVC", self._unit_path):
            with patch.object(singbox_cdn_nets, "_IPSET_CONF", self._tmpdir / "ipset.conf"):
                with patch("subprocess.run", return_value=MagicMock(returncode=0)):
                    _ipset_restore_unit_install()

        content = self._unit_path.read_text()
        lines = content.splitlines()
        before_lines = [l.strip() for l in lines if l.strip().startswith("Before=")]
        self.assertEqual(len(before_lines), 2,
                         f"Должно быть ровно 2 Before= строки, получено: {before_lines}")
        targets = [l.split("=", 1)[1].strip() for l in before_lines]
        self.assertIn("sing-box.service", targets)
        self.assertIn("netfilter-persistent.service", targets)

    def test_unit_idempotent(self):
        """Повторный вызов _ipset_restore_unit_install не перезаписывает существующий юнит."""
        from vless_installer.modules.singbox_cdn_nets import _ipset_restore_unit_install
        from vless_installer.modules import singbox_cdn_nets

        with patch.object(singbox_cdn_nets, "_RESTORE_SVC", self._unit_path):
            with patch.object(singbox_cdn_nets, "_IPSET_CONF", self._tmpdir / "ipset.conf"):
                with patch("subprocess.run", return_value=MagicMock(returncode=0)):
                    _ipset_restore_unit_install()
                    first_content = self._unit_path.read_text()
                    # Второй вызов — не должен перезаписать (файл уже существует)
                    _ipset_restore_unit_install()
                    second_content = self._unit_path.read_text()
        self.assertEqual(first_content, second_content,
                         "Повторный вызов не должен перезаписывать существующий юнит")


if __name__ == "__main__":
    unittest.main(verbosity=2)
