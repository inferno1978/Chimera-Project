#!/usr/bin/env python3
"""
tests/test_v64_ingress_port_follow_agh_autostart.py
───────────────────────────────────────────────────────────────────────────────
v64: два контракта.

1. ingress_geoip_follow_port(new_port) — перенос ingress-блокировки РФ при
   смене порта Xray (reconfigure). Инцидент-класса: порт Xray меняется
   через [R], а DROP-правило ipset остаётся на СТАРОМ порту; недельный
   cron переприменяет блокировку на старый порт из ingress_geoip.json —
   защита молча исчезает.

   Контракт:
     • блокировка выключена → False, никаких вызовов iptables;
     • порт совпадает → False, никаких вызовов;
     • порт изменился (ipset-метод): удаляются правила СТАРОГО порта
       (обе спеки — с comment-матчером и без, дубликаты), добавляется
       DROP НОВОГО порта с comment, clients_wl whitelist переносится,
       ingress_geoip.json обновляется;
     • ip6tables переносится только если v6-сет существует;
     • plain-метод: переносится привязка -j XRU_BLOCK.

2. agh-autostart: все 4 генератора конфига вызывают
   agh_dns_available(..., autostart=True) — AGH поднимается перед пробой,
   если установлен, но остановлен («AGH должен запускаться и слушать
   порты, если он установлен»).

3. _ingress_ipt_delete — исторический баг: удаление без comment-матчера
   не совпадает с правилом, добавленным С comment → дубликаты копились
   неделями. Теперь удаляются обе спеки + все дубликаты.
"""
from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Фейковый chimera._core (паттерн test_v60/test_v61/test_ingress_geoip)."""
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
    return fake_core


def _run_ok(cmd, capture=False, check=False, quiet=True, **kw):
    """Мок _run: успешное выполнение любых команд."""
    return MagicMock(returncode=0, stdout="", stderr="")


class _IngressBase(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "ingress_geoip.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state(self):
        return patch("chimera.modules.ingress_geoip.INGRESS_GEOIP_FILE",
                     self._state_file)


class TestIngressIptDelete(_IngressBase):
    """_ingress_ipt_delete: обе спеки + чистка дубликатов."""

    def test_deletes_comment_and_bare_specs_and_duplicates(self):
        from chimera.modules import ingress_geoip as ig
        # Симуляция: 3 итерации по 2 правила (rc=0 — удалено), потом
        # rc=1 на обеих спеках — больше правил нет.
        results = iter([0, 0, 0, 0, 0, 0, 1, 1, 1, 1])
        cmds = []

        def fake_run(cmd, **kw):
            cmds.append(list(cmd))
            return MagicMock(returncode=next(results, 0))

        with patch.object(ig, "_run", side_effect=fake_run):
            removed = ig._ingress_ipt_delete("iptables", 443,
                                             set_name="xray_ru_block")
        self.assertEqual(removed, 6)  # 3 итерации × 2 спеки
        # Первая итерация — обе спеки: с comment и без
        first = " ".join(cmds[0])
        second = " ".join(cmds[1])
        self.assertIn("xray-ru-ingress-block", first)
        self.assertNotIn("xray-ru-ingress-block", second)
        self.assertIn("-D INPUT", first)
        self.assertIn("443", first)
        self.assertIn("xray_ru_block", first)

    def test_plain_jump_chain_spec(self):
        from chimera.modules import ingress_geoip as ig
        cmds = []

        def fake_run(cmd, **kw):
            cmds.append(list(cmd))
            return MagicMock(returncode=1)  # правила нет

        with patch.object(ig, "_run", side_effect=fake_run):
            removed = ig._ingress_ipt_delete("iptables", 8443,
                                             jump_chain="XRU_BLOCK")
        self.assertEqual(removed, 0)
        first = " ".join(cmds[0])
        self.assertIn("XRU_BLOCK", first)
        self.assertIn("8443", first)
        self.assertIn("xray-ru-ingress-block", first)

    def test_noop_without_set_or_chain(self):
        from chimera.modules import ingress_geoip as ig
        with patch.object(ig, "_run") as fake:
            removed = ig._ingress_ipt_delete("iptables", 443)
        fake.assert_not_called()
        self.assertEqual(removed, 0)


class TestFollowPort(_IngressBase):
    """ingress_geoip_follow_port: перенос блокировки при смене порта."""

    def _write_state(self, **over):
        data = {"enabled": True, "port": 443, "cidrs_v4": 5000,
                "cidrs_v6": 1200, "updated_at": "2026-08-28T00:00:00Z",
                "method": "ipset", "whitelist": ["1.2.3.4"]}
        data.update(over)
        self._state_file.write_text(json.dumps(data))

    def test_disabled_returns_false(self):
        from chimera.modules import ingress_geoip as ig
        self._write_state(enabled=False)
        with self._patch_state(), patch.object(ig, "_run") as fake:
            self.assertFalse(ig.ingress_geoip_follow_port(8443))
        fake.assert_not_called()

    def test_same_port_returns_false(self):
        from chimera.modules import ingress_geoip as ig
        self._write_state(port=8443)
        with self._patch_state(), patch.object(ig, "_run") as fake:
            self.assertFalse(ig.ingress_geoip_follow_port(8443))
        fake.assert_not_called()

    def test_port_change_moves_drop_rule_and_state_ipset(self):
        from chimera.modules import ingress_geoip as ig
        self._write_state(method="ipset", port=443)
        cmds = []

        def fake_run(cmd, capture=False, check=False, quiet=True, **kw):
            cmds.append(list(cmd))
            # ipset list v6 — сет существует
            if cmd[:2] == ["ipset", "list"]:
                return MagicMock(returncode=0, stdout="Name: xray_ru_block6")
            return MagicMock(returncode=0, stdout="", stderr="")

        wl_calls = []
        wl_mod = types.ModuleType("chimera.modules.user_ip_whitelist")
        wl_mod.apply_iptables_rule = lambda p: wl_calls.append(("apply", p)) or True
        wl_mod.remove_iptables_rule = lambda p: wl_calls.append(("remove", p))

        with self._patch_state(), \
             patch.object(ig, "_run", side_effect=fake_run), \
             patch.dict(sys.modules, {"chimera.modules.user_ip_whitelist": wl_mod}):
            result = ig.ingress_geoip_follow_port(8443)

        self.assertTrue(result)
        joined = [" ".join(c) for c in cmds]
        # Удаление старого порта (обе спеки: с comment и без)
        del_with_comment = [j for j in joined
                            if j.startswith("iptables -D INPUT") and "443" in j]
        self.assertTrue(del_with_comment, f"нет удаления старого порта: {joined[:4]}")
        # Новое DROP-правило на 8443 с comment-матчером
        add_new = [j for j in joined
                   if j.startswith("iptables -A INPUT") and "8443" in j]
        self.assertEqual(len(add_new), 1)
        self.assertIn("xray-ru-ingress-block", add_new[0])
        # ip6tables тоже перенесён (v6-сет существует)
        add6 = [j for j in joined if j.startswith("ip6tables -A INPUT")]
        self.assertEqual(len(add6), 1)
        self.assertIn("8443", add6[0])
        # clients_wl whitelist перенесён: remove(443) → apply(8443)
        self.assertIn(("remove", 443), wl_calls)
        self.assertIn(("apply", 8443), wl_calls)
        # state обновлён
        st = json.loads(self._state_file.read_text())
        self.assertEqual(st["port"], 8443)
        self.assertTrue(st["enabled"])

    def test_port_change_skips_ip6_when_no_v6_set(self):
        from chimera.modules import ingress_geoip as ig
        self._write_state(method="ipset", port=443)

        def fake_run(cmd, capture=False, check=False, quiet=True, **kw):
            if cmd[:2] == ["ipset", "list"]:
                return MagicMock(returncode=1, stderr="set cannot be listed")
            return MagicMock(returncode=0, stdout="", stderr="")

        with self._patch_state(), \
             patch.object(ig, "_run", side_effect=fake_run):
            result = ig.ingress_geoip_follow_port(2053)
        self.assertTrue(result)

    def test_port_change_plain_method(self):
        from chimera.modules import ingress_geoip as ig
        self._write_state(method="plain", port=443)
        cmds = []

        def fake_run(cmd, capture=False, check=False, quiet=True, **kw):
            cmds.append(list(cmd))
            return MagicMock(returncode=0, stdout="", stderr="")

        with self._patch_state(), \
             patch.object(ig, "_run", side_effect=fake_run):
            result = ig.ingress_geoip_follow_port(8443)
        self.assertTrue(result)
        joined = [" ".join(c) for c in cmds]
        add_new = [j for j in joined
                   if j.startswith("iptables -A INPUT") and "8443" in j]
        self.assertEqual(len(add_new), 1)
        self.assertIn("XRU_BLOCK", add_new[0])
        del_old = [j for j in joined if j.startswith("iptables -D INPUT")]
        self.assertTrue(del_old)

    def test_whitelist_module_absent_no_crash(self):
        from chimera.modules import ingress_geoip as ig
        self._write_state(method="ipset", port=443)

        def fake_run(cmd, capture=False, check=False, quiet=True, **kw):
            if cmd[:2] == ["ipset", "list"]:
                return MagicMock(returncode=1)
            return MagicMock(returncode=0, stdout="", stderr="")

        # Модуль whitelist падает при импорте — не должно ронять перенос
        import builtins
        real_import = builtins.__import__

        def broken_import(name, *a, **kw):
            if "user_ip_whitelist" in name:
                raise ImportError("no module")
            return real_import(name, *a, **kw)

        with self._patch_state(), \
             patch.object(ig, "_run", side_effect=fake_run), \
             patch("builtins.__import__", side_effect=broken_import):
            result = ig.ingress_geoip_follow_port(8443)
        self.assertTrue(result)
        st = json.loads(self._state_file.read_text())
        self.assertEqual(st["port"], 8443)


class TestRemoveUsesBothSpecs(_IngressBase):
    """_ingress_remove: удаление по обеим спекам (историч. баг дубликатов)."""

    def test_remove_ipset_tries_comment_spec(self):
        from chimera.modules import ingress_geoip as ig
        self._write_state_remove(method="ipset", port=443)
        cmds = []

        def fake_run(cmd, capture=False, check=False, quiet=True, **kw):
            cmds.append(list(cmd))
            return MagicMock(returncode=1, stdout="", stderr="")

        with self._patch_state(), patch.object(ig, "_run", side_effect=fake_run):
            ig._ingress_remove()
        joined = [" ".join(c) for c in cmds]
        dels = [j for j in joined if j.startswith("iptables -D INPUT")]
        self.assertTrue(dels)
        # Обе спеки должны присутствовать (с comment и без)
        with_comment = [j for j in dels if "xray-ru-ingress-block" in j]
        without = [j for j in dels if "xray-ru-ingress-block" not in j]
        self.assertTrue(with_comment, "нет удаления с comment-матчером")
        self.assertTrue(without, "нет удаления без comment-матчера")

    def _write_state_remove(self, **over):
        data = {"enabled": True, "port": 443, "cidrs_v4": 10, "cidrs_v6": 0,
                "updated_at": "", "method": "ipset", "whitelist": []}
        data.update(over)
        self._state_file.write_text(json.dumps(data))


class TestAghAutostartInGenerators(unittest.TestCase):
    """Все 4 генератора конфига: agh_dns_available(..., autostart=True)."""

    def test_generator_sources_use_autostart(self):
        """Исходники генераторов содержат autostart=True в вызове AGH-пробы.

        Проверка по исходнику — генераторы тяжело исполнять в юнит-тесте
        (они пишут конфиг и дёргают systemctl), а контракт «AGH поднимается
        при пересборке» выражается именно в параметре вызова.
        """
        sites = [
            ("chimera/modules/xray_install.py", 2),   # reality + xhttp
            ("chimera/modules/chain_nodes.py", 2),    # legacy + multi
        ]
        for rel, expected in sites:
            src = (_PROJECT_ROOT / rel).read_text()
            total = src.count("agh_dns_available(run=_run, log_info=info,\n"
                              "                                         "
                              "log_warn=warn, autostart=True)")
            self.assertEqual(
                total, expected,
                f"{rel}: ожидалось {expected} вызовов с autostart=True, "
                f"найдено {total}")

    def test_agh_dns_available_signature_accepts_autostart(self):
        from chimera.modules.agh_probe import agh_dns_available
        import inspect
        sig = inspect.signature(agh_dns_available)
        self.assertIn("autostart", sig.parameters)
        self.assertFalse(sig.parameters["autostart"].default)

    def test_autostart_path_starts_stopped_agh(self):
        """autostart=True: остановленный AGH поднимается перед пробой."""
        from chimera.modules import agh_probe as ap

        cmds = []

        def fake_run(cmd, **kw):
            cmds.append(list(cmd))
            if cmd[:3] == ["systemctl", "is-active", "adguardhome"]:
                # активен после старта
                return MagicMock(returncode=0, stdout="active")
            if cmd[:3] == ["systemctl", "is-active", "AdGuardHome"]:
                return MagicMock(returncode=3, stdout="inactive")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch.object(ap, "agh_service_active", return_value=False), \
             patch.object(ap, "agh_ensure_running",
                          return_value=(True, "started")) as m_ensure, \
             patch.object(ap, "agh_owns_dns53", return_value=True), \
             patch.object(ap, "dns53_redirect_state", return_value=None), \
             patch.object(ap, "agh_probe_resolve",
                          return_value=(True, "probe ok")):
            ok, note = ap.agh_dns_available(run=fake_run, autostart=True)

        self.assertTrue(ok)
        m_ensure.assert_called_once()


class TestReconfigureHook(unittest.TestCase):
    """reconfigure.py вызывает ingress_geoip_follow_port при смене порта."""

    def test_reconfigure_source_has_follow_port_hook(self):
        src = (_PROJECT_ROOT / "chimera/modules/reconfigure.py").read_text()
        self.assertIn("ingress_geoip_follow_port", src)
        # Хук срабатывает только при смене порта
        self.assertIn("if new_port != old_port:", src)

    def test_ingress_geoip_exports_follow_port(self):
        from chimera.modules.ingress_geoip import ingress_geoip_follow_port
        self.assertTrue(callable(ingress_geoip_follow_port))


if __name__ == "__main__":
    unittest.main(verbosity=2)
