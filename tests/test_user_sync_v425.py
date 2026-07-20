#!/usr/bin/env python3
"""
tests/test_user_sync_v425.py
───────────────────────────────────────────────────────────────────────────────
Тесты для v4.25 — двусторонняя синхронизация пользователей между VLESS
и спутниковыми протоколами (NaiveProxy, Mieru, TrustTunnel, sing-box, Telemt).

Покрывает:
  1. Контрактные функции каждого протокола (is_active / ensure_user_full /
     remove_user_full / rename_user_full) — экспортируются и не падают.
  2. _SYNCABLE_PROTOCOLS реестр содержит все 5 протоколов.
  3. _sync_dispatch предпочитает _full вариант при передаче user dict.
  4. _sync_all_from_vless передаёт full user dicts (не просто names).

Принцип: тесты НЕ запускают реальные сервисы (нет root/network). Проверяется
что функции существуют, имеют правильную сигнатуру, и вызываются корректно
через mock-объекты.
"""
from __future__ import annotations

import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

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
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core


class TestSyncableRegistryContents(unittest.TestCase):
    """v4.25: реестр _SYNCABLE_PROTOCOLS содержит все 5 спутниковых протоколов."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_registry_contains_all_satellite_protocols(self):
        """В реестре должны быть: mtproto, naiveproxy, mieru, trusttunnel, singbox."""
        from chimera.modules import rest_api
        # Извлекаем короткие имена.
        proto_names = {p.rsplit(".", 1)[-1] for p in rest_api._SYNCABLE_PROTOCOLS}
        self.assertIn("mtproto", proto_names, "mtproto должен быть в реестре")
        self.assertIn("naiveproxy", proto_names, "naiveproxy должен быть в реестре")
        self.assertIn("mieru", proto_names, "mieru должен быть в реестре")
        self.assertIn("trusttunnel", proto_names, "trusttunnel должен быть в реестре")
        self.assertIn("singbox", proto_names, "singbox должен быть в реестре")

    def test_registry_does_not_contain_vless(self):
        """VLESS НЕ в реестре — это canonical source, синхронизация идёт ОТ него."""
        from chimera.modules import rest_api
        proto_names = {p.rsplit(".", 1)[-1] for p in rest_api._SYNCABLE_PROTOCOLS}
        self.assertNotIn("vless", proto_names,
                         "VLESS не должен быть в реестре — это source, не satellite")


class TestProtocolContractFunctions(unittest.TestCase):
    """Каждый syncable-протокол экспортирует функции контракта."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_naiveproxy_exports_contract(self):
        """naiveproxy.py экспортирует is_active / ensure_user_full /
        remove_user_full / rename_user_full / ensure_user / remove_user / rename_user."""
        from chimera.modules import naiveproxy
        for fn_name in ("is_active", "ensure_user_full", "remove_user_full",
                         "rename_user_full", "ensure_user", "remove_user",
                         "rename_user"):
            self.assertTrue(hasattr(naiveproxy, fn_name),
                            f"naiveproxy должен экспортировать {fn_name}")

    def test_mieru_exports_contract(self):
        from chimera.modules import mieru
        for fn_name in ("is_active", "ensure_user_full", "remove_user_full",
                         "rename_user_full", "ensure_user", "remove_user",
                         "rename_user"):
            self.assertTrue(hasattr(mieru, fn_name),
                            f"mieru должен экспортировать {fn_name}")

    def test_trusttunnel_exports_contract(self):
        from chimera.modules import trusttunnel
        for fn_name in ("is_active", "ensure_user_full", "remove_user_full",
                         "rename_user_full", "ensure_user", "remove_user",
                         "rename_user"):
            self.assertTrue(hasattr(trusttunnel, fn_name),
                            f"trusttunnel должен экспортировать {fn_name}")

    def test_singbox_exports_contract(self):
        """sing-box контракт в singbox_users.py (не singbox_menu.py)."""
        from chimera.modules import singbox_users
        for fn_name in ("is_active", "ensure_user_full", "remove_user_full",
                         "rename_user_full", "ensure_user", "remove_user",
                         "rename_user"):
            self.assertTrue(hasattr(singbox_users, fn_name),
                            f"singbox_users должен экспортировать {fn_name}")


class TestSyncDispatchPrefersFullContract(unittest.TestCase):
    """_sync_dispatch предпочитает _full вариант при передаче user dict."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_dispatch_calls_ensure_user_full_when_user_provided(self):
        """Если передан user dict — вызывается ensure_user_full, не ensure_user."""
        from chimera.modules import rest_api
        import types as _types
        fake_proto = _types.ModuleType("chimera.modules._test_full_proto")
        fake_proto.is_active = MagicMock(return_value=True)
        fake_proto.ensure_user = MagicMock(return_value=True)
        fake_proto.ensure_user_full = MagicMock(return_value=True)
        sys.modules["chimera.modules._test_full_proto"] = fake_proto
        orig_protocols = list(rest_api._SYNCABLE_PROTOCOLS)
        rest_api._SYNCABLE_PROTOCOLS = ["chimera.modules._test_full_proto"]
        try:
            user = {"uuid": "u1", "email": "a@x.com", "name": "alice"}
            rest_api._sync_ensure_user("alice", user=user)
            # ensure_user_full должен быть вызван.
            fake_proto.ensure_user_full.assert_called_once_with(user)
            # ensure_user (legacy) НЕ должен быть вызван.
            fake_proto.ensure_user.assert_not_called()
        finally:
            rest_api._SYNCABLE_PROTOCOLS = orig_protocols
            sys.modules.pop("chimera.modules._test_full_proto", None)

    def test_dispatch_falls_back_to_legacy_when_no_full(self):
        """Если модуль не экспортирует _full — fallback на legacy ensure_user(name)."""
        from chimera.modules import rest_api
        import types as _types
        fake_proto = _types.ModuleType("chimera.modules._test_legacy_proto")
        fake_proto.is_active = MagicMock(return_value=True)
        fake_proto.ensure_user = MagicMock(return_value=True)
        # НЕ экспортируем ensure_user_full.
        sys.modules["chimera.modules._test_legacy_proto"] = fake_proto
        orig_protocols = list(rest_api._SYNCABLE_PROTOCOLS)
        rest_api._SYNCABLE_PROTOCOLS = ["chimera.modules._test_legacy_proto"]
        try:
            user = {"uuid": "u1", "email": "a@x.com", "name": "alice"}
            rest_api._sync_ensure_user("alice", user=user)
            # legacy ensure_user вызван с name.
            fake_proto.ensure_user.assert_called_once_with("alice")
        finally:
            rest_api._SYNCABLE_PROTOCOLS = orig_protocols
            sys.modules.pop("chimera.modules._test_legacy_proto", None)


class TestSyncAllFromVlessPassesFullDicts(unittest.TestCase):
    """_sync_all_from_vless передаёт full user dicts (не просто names)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_passes_full_user_dict_to_ensure_user_full(self):
        from chimera.modules import rest_api
        import types as _types
        fake_proto = _types.ModuleType("chimera.modules._test_pass_full")
        fake_proto.is_active = MagicMock(return_value=True)
        fake_proto.ensure_user_full = MagicMock(return_value=True)
        fake_proto.ensure_user = MagicMock(return_value=True)
        sys.modules["chimera.modules._test_pass_full"] = fake_proto
        orig_protocols = list(rest_api._SYNCABLE_PROTOCOLS)
        rest_api._SYNCABLE_PROTOCOLS = ["chimera.modules._test_pass_full"]
        try:
            vless_users = [
                {"uuid": "u1", "email": "a@x.com", "name": "alice", "disabled": False},
                {"uuid": "u2", "email": "b@x.com", "name": "bob", "disabled": False},
            ]
            rest_api._sync_all_from_vless(vless_users)
            # ensure_user_full вызван дважды — с каждым user dict.
            self.assertEqual(fake_proto.ensure_user_full.call_count, 2)
            # Первый вызов — с alice dict.
            _args, _kwargs = fake_proto.ensure_user_full.call_args_list[0]
            self.assertEqual(_args[0]["uuid"], "u1")
            self.assertEqual(_args[0]["email"], "a@x.com")
            # legacy ensure_user НЕ вызван.
            fake_proto.ensure_user.assert_not_called()
        finally:
            rest_api._SYNCABLE_PROTOCOLS = orig_protocols
            sys.modules.pop("chimera.modules._test_pass_full", None)


class TestCoreSyncHelper(unittest.TestCase):
    """_core._sync_user_to_protocols — диспетчер для TUI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_add_action_calls_sync_ensure_user(self):
        """Action 'add' → вызывает _sync_ensure_user."""
        from chimera import _core
        from chimera.modules import rest_api
        called = {}
        def fake_ensure(name, user=None):
            called["ensure"] = (name, user)
            return {"naiveproxy": True}
        with patch.object(rest_api, "_sync_ensure_user", side_effect=fake_ensure):
            _core._sync_user_to_protocols(
                "add", {"uuid": "u1", "email": "a@x.com", "name": "alice"}
            )
        self.assertIn("ensure", called)
        self.assertEqual(called["ensure"][0], "alice")
        self.assertEqual(called["ensure"][1]["uuid"], "u1")

    def test_remove_action_calls_sync_remove_user(self):
        from chimera import _core
        from chimera.modules import rest_api
        called = {}
        def fake_remove(name, user=None):
            called["remove"] = (name, user)
            return {"naiveproxy": True}
        with patch.object(rest_api, "_sync_remove_user", side_effect=fake_remove):
            _core._sync_user_to_protocols(
                "remove", {"uuid": "u1", "email": "a@x.com", "name": "alice"}
            )
        self.assertIn("remove", called)

    def test_toggle_off_calls_remove(self):
        from chimera import _core
        from chimera.modules import rest_api
        called = {}
        def fake_remove(name, user=None):
            called["toggle_off"] = True
            return {}
        with patch.object(rest_api, "_sync_remove_user", side_effect=fake_remove):
            _core._sync_user_to_protocols(
                "toggle_off", {"uuid": "u1", "name": "alice"}
            )
        self.assertIn("toggle_off", called)

    def test_toggle_on_calls_ensure(self):
        from chimera import _core
        from chimera.modules import rest_api
        called = {}
        def fake_ensure(name, user=None):
            called["toggle_on"] = True
            return {}
        with patch.object(rest_api, "_sync_ensure_user", side_effect=fake_ensure):
            _core._sync_user_to_protocols(
                "toggle_on", {"uuid": "u1", "name": "alice"}
            )
        self.assertIn("toggle_on", called)


class TestNaiveproxyContractIdempotency(unittest.TestCase):
    """naiveproxy.ensure_user_full идемпотентна — повторный вызов no-op."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ensure_user_full_returns_true_for_existing_user(self):
        """Если юзер уже есть в state — возвращает True (no-op)."""
        from chimera.modules import naiveproxy
        import tempfile
        tmpdir = Path(tempfile.mkdtemp())
        state_file = tmpdir / "naiveproxy.json"
        # Pre-populate state с существующим юзером.
        state_file.write_text(json.dumps({
            "installed": True,
            "domain": "x.com",
            "port": 443,
            "users": [{"username": "alice", "password": "p", "password_hash": "h"}],
        }))
        # Mock _is_installed to return True.
        with patch.object(naiveproxy, "_is_installed", return_value=True), \
             patch.object(naiveproxy, "_MODULE_STATE", state_file), \
             patch.object(naiveproxy, "_apply_config", return_value=None):
            result = naiveproxy.ensure_user_full({"email": "alice@x.com", "name": "alice"})
        self.assertTrue(result, "Должен вернуть True для существующего юзера")
        try:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass


class TestTrustTunnelContractRequiresUuid(unittest.TestCase):
    """trusttunnel.ensure_user_full требует UUID для derive пароля."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ensure_user_full_returns_false_without_uuid(self):
        """Без UUID не может derive пароль → возвращает False."""
        from chimera.modules import trusttunnel
        with patch.object(trusttunnel, "_is_installed", return_value=True):
            result = trusttunnel.ensure_user_full({"email": "alice@x.com"})
        self.assertFalse(result, "Должен вернуть False без UUID")

    def test_ensure_user_full_returns_true_with_uuid(self):
        from chimera.modules import trusttunnel
        with patch.object(trusttunnel, "_is_installed", return_value=True), \
             patch.object(trusttunnel, "trusttunnel_add_user", return_value=True), \
             patch.object(trusttunnel, "trusttunnel_restart_service", return_value=True):
            result = trusttunnel.ensure_user_full({
                "email": "alice@x.com", "uuid": "abc-123",
            })
        self.assertTrue(result, "Должен вернуть True с UUID")


if __name__ == "__main__":
    unittest.main(verbosity=2)
