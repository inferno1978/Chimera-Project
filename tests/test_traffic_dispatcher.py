#!/usr/bin/env python3
"""
tests/test_traffic_dispatcher.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты на мультипротокольный диспетчер трафика:
  • traffic_tracking.query_user_traffic_bytes(identifier, protocol)
  • traffic_tracking.query_user_traffic_bytes_accumulated(identifier, protocol)
  • traffic_history._traffic_snapshot_save() — мультипротокольный снимок

Покрывает тесты 4-6 из задачи про интеграцию Telemt в TUI трафика:
  4. Диспетчер query_user_traffic_bytes(identifier, "mtproto") →
     вызывает mtproto._get_user_traffic_bytes, не Xray Stats API
  5. _traffic_snapshot_save(): telemt-пользователь появляется в
     history.json после снэпшота
  6. Аналогично для mieru/naiveproxy/awg (по итогам проверки подтвердился
     тот же разрыв — чиним для всех 4 протоколов одним заходом)
"""
from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Эталонный паттерн — exec _core.py в fake module."""
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


# =============================================================================
#  Test 4: диспетчер query_user_traffic_bytes для всех протоколов
# =============================================================================
class TestQueryUserTrafficBytesDispatcher(unittest.TestCase):
    """Проверяем что query_user_traffic_bytes(identifier, protocol)
    корректно диспетчеризует в per-protocol функции:

      • protocol="xray"/"vless" → _query_user_traffic_bytes (Xray Stats API)
      • protocol="mtproto"/"telemt" → mtproto._get_user_traffic_bytes
      • protocol="mieru" → mieru_stats.mieru_get_traffic_accumulated
      • protocol="naiveproxy" → naiveproxy_stats.naiveproxy_get_traffic_accumulated
      • protocol="awg" → awg_peers.awg_get_peer_traffic_accumulated
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_xray_protocol_uses_xray_stats_api(self):
        """protocol="xray" → вызывает _query_user_traffic_bytes (не пер-протокол)."""
        from chimera.modules import traffic_tracking
        with patch.object(traffic_tracking, "_query_user_traffic_bytes",
                          return_value=12345) as mock_xray:
            result = traffic_tracking.query_user_traffic_bytes(
                "alice@example.com", "xray")
        self.assertEqual(result, 12345)
        mock_xray.assert_called_once_with("alice@example.com")

    def test_vless_protocol_alias_for_xray(self):
        """protocol="vless" — синоним для "xray"."""
        from chimera.modules import traffic_tracking
        with patch.object(traffic_tracking, "_query_user_traffic_bytes",
                          return_value=999) as mock_xray:
            result = traffic_tracking.query_user_traffic_bytes(
                "bob@example.com", "vless")
        self.assertEqual(result, 999)
        mock_xray.assert_called_once_with("bob@example.com")

    # ── Тест 4: mtproto → mtproto._get_user_traffic_bytes ────────────────────
    def test_mtproto_protocol_uses_mtproto_get_user_traffic_bytes(self):
        """protocol="mtproto" → вызывает mtproto._get_user_traffic_bytes,
        НЕ Xray Stats API.
        """
        from chimera.modules import traffic_tracking
        # Мокаем mtproto._get_user_traffic_bytes (lazy import внутри диспетчера)
        fake_mtproto = types.ModuleType("chimera.modules.mtproto")
        fake_mtproto._get_user_traffic_bytes = MagicMock(return_value=555555)
        with patch.dict(sys.modules, {"chimera.modules.mtproto": fake_mtproto}):
            # Также мокаем _query_user_traffic_bytes чтобы убедиться что
            # Xray Stats API НЕ вызывается для mtproto
            with patch.object(traffic_tracking, "_query_user_traffic_bytes",
                              return_value=0) as mock_xray:
                result = traffic_tracking.query_user_traffic_bytes(
                    "alice_telemt", "mtproto")
        self.assertEqual(result, 555555)
        fake_mtproto._get_user_traffic_bytes.assert_called_once_with("alice_telemt")
        # Xray Stats API НЕ должен был вызваться
        mock_xray.assert_not_called()

    def test_telemt_protocol_alias_for_mtproto(self):
        """protocol="telemt" — синоним для "mtproto"."""
        from chimera.modules import traffic_tracking
        fake_mtproto = types.ModuleType("chimera.modules.mtproto")
        fake_mtproto._get_user_traffic_bytes = MagicMock(return_value=777)
        with patch.dict(sys.modules, {"chimera.modules.mtproto": fake_mtproto}):
            result = traffic_tracking.query_user_traffic_bytes(
                "carol_telemt", "telemt")
        self.assertEqual(result, 777)
        fake_mtproto._get_user_traffic_bytes.assert_called_once_with("carol_telemt")

    # ── Тест 6a: mieru ───────────────────────────────────────────────────────
    def test_mieru_protocol_uses_mieru_stats(self):
        """protocol="mieru" → mieru_stats.mieru_get_traffic_accumulated."""
        from chimera.modules import traffic_tracking
        fake_mieru_stats = types.ModuleType("chimera.modules.mieru_stats")
        fake_mieru_stats.mieru_get_traffic_accumulated = MagicMock(return_value=888)
        with patch.dict(sys.modules, {"chimera.modules.mieru_stats": fake_mieru_stats}):
            with patch.object(traffic_tracking, "_query_user_traffic_bytes",
                              return_value=0) as mock_xray:
                result = traffic_tracking.query_user_traffic_bytes(
                    "alice_mieru", "mieru")
        self.assertEqual(result, 888)
        fake_mieru_stats.mieru_get_traffic_accumulated.assert_called_once_with("alice_mieru")
        mock_xray.assert_not_called()

    # ── Тест 6b: naiveproxy ──────────────────────────────────────────────────
    def test_naiveproxy_protocol_uses_naiveproxy_stats(self):
        """protocol="naiveproxy" → naiveproxy_stats.naiveproxy_get_traffic_accumulated."""
        from chimera.modules import traffic_tracking
        fake_naive_stats = types.ModuleType("chimera.modules.naiveproxy_stats")
        fake_naive_stats.naiveproxy_get_traffic_accumulated = MagicMock(return_value=999)
        with patch.dict(sys.modules, {"chimera.modules.naiveproxy_stats": fake_naive_stats}):
            with patch.object(traffic_tracking, "_query_user_traffic_bytes",
                              return_value=0) as mock_xray:
                result = traffic_tracking.query_user_traffic_bytes(
                    "alice_naive", "naiveproxy")
        self.assertEqual(result, 999)
        fake_naive_stats.naiveproxy_get_traffic_accumulated.assert_called_once_with("alice_naive")
        mock_xray.assert_not_called()

    # ── Тест 6c: awg ─────────────────────────────────────────────────────────
    def test_awg_protocol_uses_awg_peers(self):
        """protocol="awg" → awg_peers.awg_get_peer_traffic_accumulated."""
        from chimera.modules import traffic_tracking
        fake_awg_peers = types.ModuleType("chimera.modules.awg_peers")
        fake_awg_peers.awg_get_peer_traffic_accumulated = MagicMock(return_value=1111)
        with patch.dict(sys.modules, {"chimera.modules.awg_peers": fake_awg_peers}):
            with patch.object(traffic_tracking, "_query_user_traffic_bytes",
                              return_value=0) as mock_xray:
                result = traffic_tracking.query_user_traffic_bytes(
                    "alice@awg.com", "awg")
        self.assertEqual(result, 1111)
        fake_awg_peers.awg_get_peer_traffic_accumulated.assert_called_once_with("alice@awg.com")
        mock_xray.assert_not_called()

    def test_unknown_protocol_returns_zero(self):
        """Неизвестный протокол → 0, не бросает исключение."""
        from chimera.modules import traffic_tracking
        result = traffic_tracking.query_user_traffic_bytes("anyone", "unknown_proto")
        self.assertEqual(result, 0)

    def test_mtproto_failure_returns_zero(self):
        """Если mtproto._get_user_traffic_bytes бросает — возвращаем 0,
        не роняем вызывающий код (snapshot/TUI).
        """
        from chimera.modules import traffic_tracking
        fake_mtproto = types.ModuleType("chimera.modules.mtproto")
        fake_mtproto._get_user_traffic_bytes = MagicMock(side_effect=RuntimeError("boom"))
        with patch.dict(sys.modules, {"chimera.modules.mtproto": fake_mtproto}):
            result = traffic_tracking.query_user_traffic_bytes(
                "alice", "mtproto")
        self.assertEqual(result, 0)


# =============================================================================
#  Test 5+6: _traffic_snapshot_save — мультипротокольный снимок
# =============================================================================
class TestTrafficSnapshotSaveMultiProtocol(unittest.TestCase):
    """Проверяем что _traffic_snapshot_save() теперь перебирает
    пользователей ВСЕХ протоколов (VLESS/Telemt/Mieru/NaiveProxy/AWG),
    а не только VLESS как раньше.

    Тест 5: telemt-пользователь появляется в history.json после снэпшота.
    Тест 6: аналогично для mieru/naiveproxy/awg (разрыв подтверждён).
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._history_file = self._tmpdir / "traffic_history.json"
        self._users_file = self._tmpdir / "users.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_history_file(self):
        return patch("chimera.modules.traffic_history.TRAFFIC_HISTORY_FILE",
                     self._history_file)

    def _setup_vless_users(self, emails: list[str]):
        """Мокает core._users_load чтобы вернуть VLESS-пользователей."""
        users = [{"email": e} for e in emails]
        return patch("chimera._core._users_load", return_value=users)

    # ── Тест 5: telemt-пользователь появляется в history.json ───────────────
    def test_telemt_user_appears_in_snapshot(self):
        """_traffic_snapshot_save() с telemt-пользователем "alice_telemt"
        → в history.json появляется ключ "mtproto::alice_telemt_max" с
        трафиком, отданным mtproto._get_user_traffic_bytes().
        """
        from chimera.modules import traffic_history, traffic_tracking
        import chimera._core as core

        # VLESS users — пусто (чтобы проверить что добавляется ТОЛЬКО telemt)
        # Telemt users — один
        fake_mtproto = types.ModuleType("chimera.modules.mtproto")
        fake_mtproto._load_users = MagicMock(return_value={"alice_telemt": "deadbeef"})
        fake_mtproto._get_user_traffic_bytes = MagicMock(return_value=42_000_000)

        with patch.dict(sys.modules, {"chimera.modules.mtproto": fake_mtproto}), \
             patch("chimera._core._users_load", return_value=[]), \
             self._patch_history_file(), \
             patch("chimera.modules.mieru.proto_load_state", side_effect=Exception("no mieru")), \
             patch("chimera.modules.naiveproxy._load_users", side_effect=Exception("no naive")), \
             patch("chimera.modules.awg_state.awgs_state_load", side_effect=Exception("no awg")):
            traffic_history._traffic_snapshot_save()

        # Проверяем history.json
        history = json.loads(self._history_file.read_text())
        today = list(history.keys())[0]
        # Должен быть ключ "mtproto::alice_telemt_max"
        self.assertIn("mtproto::alice_telemt_max", history[today])
        self.assertEqual(history[today]["mtproto::alice_telemt_max"], 42_000_000)
        # VLESS ключей быть не должно (VLESS users пусто)
        vless_keys = [k for k in history[today] if "::" not in k]
        self.assertEqual(len(vless_keys), 0)

    # ── Тест 6a: mieru-пользователь появляется в snapshot ───────────────────
    def test_mieru_user_appears_in_snapshot(self):
        from chimera.modules import traffic_history
        from chimera.modules import mieru as mieru_mod
        # Создаём фейковый mieru state с одним пользователем
        from chimera.modules.proto_common import proto_load_state as real_proto_load_state

        fake_mtproto = types.ModuleType("chimera.modules.mtproto")
        fake_mtproto._load_users = MagicMock(side_effect=Exception("no telemt"))

        fake_naive = types.ModuleType("chimera.modules.naiveproxy")
        fake_naive._load_users = MagicMock(side_effect=Exception("no naive"))

        fake_awg_state = types.ModuleType("chimera.modules.awg_state")
        fake_awg_state.awgs_state_load = MagicMock(side_effect=Exception("no awg"))

        # Патчим proto_load_state чтобы вернуть mieru state с alice_mieru
        mieru_state = {"users": [{"username": "alice_mieru"}]}

        # Патчим mieru_get_traffic_accumulated через фейковый mieru_stats
        fake_mieru_stats = types.ModuleType("chimera.modules.mieru_stats")
        fake_mieru_stats.mieru_get_traffic_accumulated = MagicMock(return_value=33_000_000)

        with patch.dict(sys.modules, {
            "chimera.modules.mtproto": fake_mtproto,
            "chimera.modules.naiveproxy": fake_naive,
            "chimera.modules.awg_state": fake_awg_state,
            "chimera.modules.mieru_stats": fake_mieru_stats,
        }), \
             patch("chimera._core._users_load", return_value=[]), \
             self._patch_history_file(), \
             patch("chimera.modules.proto_common.proto_load_state",
                   return_value=mieru_state):
            traffic_history._traffic_snapshot_save()

        history = json.loads(self._history_file.read_text())
        today = list(history.keys())[0]
        self.assertIn("mieru::alice_mieru_max", history[today])
        self.assertEqual(history[today]["mieru::alice_mieru_max"], 33_000_000)

    # ── Тест 6b: naiveproxy-пользователь появляется в snapshot ──────────────
    def test_naiveproxy_user_appears_in_snapshot(self):
        from chimera.modules import traffic_history

        fake_mtproto = types.ModuleType("chimera.modules.mtproto")
        fake_mtproto._load_users = MagicMock(side_effect=Exception("no telemt"))

        fake_naive = types.ModuleType("chimera.modules.naiveproxy")
        fake_naive._load_users = MagicMock(return_value=[
            {"username": "alice_naive"}
        ])

        fake_awg_state = types.ModuleType("chimera.modules.awg_state")
        fake_awg_state.awgs_state_load = MagicMock(side_effect=Exception("no awg"))

        fake_naive_stats = types.ModuleType("chimera.modules.naiveproxy_stats")
        fake_naive_stats.naiveproxy_get_traffic_accumulated = MagicMock(return_value=22_000_000)

        # mieru proto_load_state бросает
        with patch.dict(sys.modules, {
            "chimera.modules.mtproto": fake_mtproto,
            "chimera.modules.naiveproxy": fake_naive,
            "chimera.modules.awg_state": fake_awg_state,
            "chimera.modules.naiveproxy_stats": fake_naive_stats,
        }), \
             patch("chimera._core._users_load", return_value=[]), \
             self._patch_history_file(), \
             patch("chimera.modules.proto_common.proto_load_state",
                   side_effect=Exception("no mieru")):
            traffic_history._traffic_snapshot_save()

        history = json.loads(self._history_file.read_text())
        today = list(history.keys())[0]
        self.assertIn("naiveproxy::alice_naive_max", history[today])
        self.assertEqual(history[today]["naiveproxy::alice_naive_max"], 22_000_000)

    # ── Тест 6c: awg peer появляется в snapshot ─────────────────────────────
    def test_awg_peer_appears_in_snapshot(self):
        from chimera.modules import traffic_history

        fake_mtproto = types.ModuleType("chimera.modules.mtproto")
        fake_mtproto._load_users = MagicMock(side_effect=Exception("no telemt"))

        fake_naive = types.ModuleType("chimera.modules.naiveproxy")
        fake_naive._load_users = MagicMock(side_effect=Exception("no naive"))

        fake_awg_state = types.ModuleType("chimera.modules.awg_state")
        fake_awg_state.awgs_state_load = MagicMock(return_value={
            "peers": [{"owner_email": "alice@awg.com"}]
        })

        fake_awg_peers = types.ModuleType("chimera.modules.awg_peers")
        fake_awg_peers.awg_get_peer_traffic_accumulated = MagicMock(return_value=11_000_000)

        with patch.dict(sys.modules, {
            "chimera.modules.mtproto": fake_mtproto,
            "chimera.modules.naiveproxy": fake_naive,
            "chimera.modules.awg_state": fake_awg_state,
            "chimera.modules.awg_peers": fake_awg_peers,
        }), \
             patch("chimera._core._users_load", return_value=[]), \
             self._patch_history_file(), \
             patch("chimera.modules.proto_common.proto_load_state",
                   side_effect=Exception("no mieru")):
            traffic_history._traffic_snapshot_save()

        history = json.loads(self._history_file.read_text())
        today = list(history.keys())[0]
        self.assertIn("awg::alice@awg.com_max", history[today])
        self.assertEqual(history[today]["awg::alice@awg.com_max"], 11_000_000)

    # ── Регрессия: VLESS по-прежнему работает (старый ключ {email}_max) ─────
    def test_vless_users_still_use_legacy_key(self):
        """Старый формат ключа '{email}_max' для VLESS сохранён для
        обратной совместимости со старыми снимками и do_traffic_history TUI.
        """
        from chimera.modules import traffic_history, traffic_tracking

        # Мокаем все протоколы чтобы они бросали (только VLESS работает)
        fake_mtproto = types.ModuleType("chimera.modules.mtproto")
        fake_mtproto._load_users = MagicMock(side_effect=Exception("no telemt"))

        with patch.dict(sys.modules, {
            "chimera.modules.mtproto": fake_mtproto,
        }), \
             patch("chimera._core._users_load",
                   return_value=[{"email": "alice@vless.com"}]), \
             self._patch_history_file(), \
             patch.object(traffic_tracking, "query_user_traffic_bytes",
                          return_value=5_000_000) as mock_disp, \
             patch("chimera.modules.proto_common.proto_load_state",
                   side_effect=Exception("no mieru")), \
             patch("chimera.modules.naiveproxy._load_users",
                   side_effect=Exception("no naive")), \
             patch("chimera.modules.awg_state.awgs_state_load",
                   side_effect=Exception("no awg")):
            traffic_history._traffic_snapshot_save()

        history = json.loads(self._history_file.read_text())
        today = list(history.keys())[0]
        # VLESS использует старый ключ "{email}_max" (без proto:: prefix)
        self.assertIn("alice@vless.com_max", history[today])
        self.assertEqual(history[today]["alice@vless.com_max"], 5_000_000)
        # Диспетчер вызван с protocol="xray"
        mock_disp.assert_any_call("alice@vless.com", "xray")


if __name__ == "__main__":
    unittest.main(verbosity=2)
