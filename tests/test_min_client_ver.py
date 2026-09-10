#!/usr/bin/env python3
"""
tests/test_min_client_ver.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для гейта версий клиента REALITY (minClientVer) — опция меню 5b.

Покрывает:
  1. _min_client_ver_from_state / PARAM_MIN_CLIENT_VER — ленивое чтение из
     state.json с приоритетом глобали (паттерн _fp_from_state)
  2. _save_min_client_ver_to_state — read-modify-write под flock, сохранение
     чужих ключей, синхронизация глобали
  3. _prompt_min_client_ver — интерактивный ввод: Enter = "1.8.0",
     "-" = сброс, валидация версии, no-op при том же значении
  4. do_rebuild_xray_config (пункт 5b) — врезка подпромпта: значение
     сохраняется ДО перегенерации и переживает rebuild
  5. inject_pq_inbound — чистая функция эмитит min_client_ver в
     realitySettings PQ-инбаунда
  6. _make_exit_node_config — exit-нода (режим B) берёт значение из
     state.json через core._min_client_ver_from_state

Механика гейта (почему "1.8.0", а не что-то ещё): docs/faq/VLESS_FAQ.md §18.
"""
from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _exec_core():
    """Компилирует chimera/_core.py в фейковый модуль (паттерн проекта).

    Отличие от тестов соседних модулей: exec выполняется ПРЯМО в
    __dict__ фейкового модуля (а не в промежуточный dict g) — тогда
    functions' __globals__ совпадает с атрибутами модуля, и правки вида
    core.STATE_FILE = ... / core.PARAM_MIN_CLIENT_VER = ... видны коду
    внутри exec'нутых функций (проверяемые функции читают свои глобали
    напрямую, а не через core.X-индирекцию).
    """
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    fake_core = types.ModuleType("chimera._core")
    sys.modules["chimera._core"] = fake_core
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), fake_core.__dict__)
    return fake_core


def _base_state() -> dict:
    """Минимальный валидный state.json для REALITY-режима (пункт 5b)."""
    return {
        "domain": "test.example.com",
        "uuid": "11111111-2222-3333-4444-555555555555",
        "private_key": "PRIVKEY",
        "public_key": "PUBKEY",
        "short_id": "aabbccdd",
        "fingerprint": "chrome",
        "socket": "/dev/shm/test-chimera.sock",
        "install_mode": "A",
    }


class TestMinClientVerHelpers(unittest.TestCase):
    """_min_client_ver_from_state / _save_min_client_ver_to_state."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.core = _exec_core()
        self.core.STATE_FILE = Path(self._tmp) / "state.json"

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write_state(self, d: dict):
        self.core.STATE_FILE.write_text(json.dumps(d, ensure_ascii=False))

    def test_default_empty_when_no_state_file(self):
        self.assertEqual(self.core._min_client_ver_from_state(), "")

    def test_default_empty_when_field_absent(self):
        self._write_state({"domain": "x.com"})
        self.assertEqual(self.core._min_client_ver_from_state(), "")

    def test_reads_value_from_state(self):
        self._write_state({"domain": "x.com", "min_client_ver": "1.8.0"})
        self.assertEqual(self.core._min_client_ver_from_state(), "1.8.0")

    def test_global_takes_priority_over_state(self):
        self._write_state({"min_client_ver": "1.8.0"})
        self.core.PARAM_MIN_CLIENT_VER = "26.3.27"
        self.assertEqual(self.core._min_client_ver_from_state(), "26.3.27")

    def test_corrupt_state_falls_back_to_empty(self):
        self.core.STATE_FILE.write_text("{not json")
        self.assertEqual(self.core._min_client_ver_from_state(), "")

    def test_save_roundtrip_preserves_other_keys(self):
        self._write_state({"domain": "x.com", "uuid": "u-1", "min_client_ver": "old"})
        ok = self.core._save_min_client_ver_to_state("1.8.0")
        self.assertTrue(ok)
        st = json.loads(self.core.STATE_FILE.read_text())
        self.assertEqual(st["min_client_ver"], "1.8.0")
        self.assertEqual(st["domain"], "x.com")
        self.assertEqual(st["uuid"], "u-1")
        # глобаль синхронизирована — генераторы в этой же сессии видят значение
        self.assertEqual(self.core.PARAM_MIN_CLIENT_VER, "1.8.0")

    def test_save_reset_to_empty(self):
        self._write_state({"min_client_ver": "1.8.0"})
        ok = self.core._save_min_client_ver_to_state("")
        self.assertTrue(ok)
        st = json.loads(self.core.STATE_FILE.read_text())
        self.assertEqual(st["min_client_ver"], "")
        self.assertEqual(self.core.PARAM_MIN_CLIENT_VER, "")

    def test_save_missing_state_file_returns_false(self):
        # state.json не существует — сеттер не должен падать
        ok = self.core._save_min_client_ver_to_state("1.8.0")
        self.assertFalse(ok)
        # но глобаль всё равно выставлена (память сессии)
        self.assertEqual(self.core.PARAM_MIN_CLIENT_VER, "1.8.0")

    def test_load_state_into_globals_loads_field(self):
        st = _base_state()
        st["min_client_ver"] = "1.8.0"
        self._write_state(st)
        self.core.PARAM_MIN_CLIENT_VER = ""
        self.core._load_state_into_globals()
        self.assertEqual(self.core.PARAM_MIN_CLIENT_VER, "1.8.0")
        # и хелпер это видит (глобаль приоритетнее файла)
        self.assertEqual(self.core._min_client_ver_from_state(), "1.8.0")


class TestPromptMinClientVer(unittest.TestCase):
    """_prompt_min_client_ver — интерактивный ввод (подпункт 5b)."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.core = _exec_core()
        self.core.STATE_FILE = Path(self._tmp) / "state.json"
        self.core.STATE_FILE.write_text(json.dumps(_base_state()))

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _state(self) -> dict:
        return json.loads(self.core.STATE_FILE.read_text())

    def test_enter_defaults_to_1_8_0(self):
        with patch("builtins.input", return_value=""):
            self.core._prompt_min_client_ver("")
        self.assertEqual(self._state().get("min_client_ver"), "1.8.0")

    def test_dash_resets_to_empty(self):
        self._state()  # файл есть
        with patch("builtins.input", return_value="-"):
            self.core._prompt_min_client_ver("1.8.0")
        self.assertEqual(self._state().get("min_client_ver"), "")

    def test_explicit_version_saved(self):
        with patch("builtins.input", return_value="26.3.27"):
            self.core._prompt_min_client_ver("")
        self.assertEqual(self._state().get("min_client_ver"), "26.3.27")

    def test_invalid_value_not_saved(self):
        with patch("builtins.input", return_value="не-версия"):
            self.core._prompt_min_client_ver("")
        self.assertNotIn("min_client_ver", self._state())

    def test_same_value_is_noop(self):
        with patch("builtins.input", return_value=""):
            # current уже "1.8.0" и Enter даёт "1.8.0" — сохранять нечего
            self.core._prompt_min_client_ver("1.8.0")
        self.assertNotIn("min_client_ver", self._state())

    def test_eof_cancels_without_save(self):
        with patch("builtins.input", side_effect=EOFError):
            self.core._prompt_min_client_ver("")
        self.assertNotIn("min_client_ver", self._state())


class TestRebuildMenu5b(unittest.TestCase):
    """do_rebuild_xray_config (пункт 5b) — подпромпт minClientVer + rebuild."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.core = _exec_core()
        self.core.STATE_FILE = Path(self._tmp) / "state.json"
        self.core.STATE_FILE.write_text(json.dumps(_base_state()))
        self.core.CONFIG_DIR = Path(self._tmp)
        self.core.PROTOCOL_MODE = "reality"
        self.core.INSTALL_MODE = "A"
        self.core.AWG_EXIT_ENABLED = False
        self.core.PARAM_SOCKET_PATH = _base_state()["socket"]
        self.core.PARAM_SPIDERX = "/"
        self.core.PARAM_DOMAIN = _base_state()["domain"]
        self.core._rebuild_and_restart_xray = MagicMock()

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _state(self) -> dict:
        return json.loads(self.core.STATE_FILE.read_text())

    def test_flow_set_value_then_rebuild(self):
        # y = перегенерировать; y = выставить minClientVer; Enter = "1.8.0"
        with patch("builtins.input", side_effect=["y", "y", ""]):
            self.core.do_rebuild_xray_config()
        self.assertEqual(self._state().get("min_client_ver"), "1.8.0")
        self.core._rebuild_and_restart_xray.assert_called_once()
        # глобаль синхронизирована для генераторов этой же сессии
        self.assertEqual(self.core.PARAM_MIN_CLIENT_VER, "1.8.0")

    def test_flow_skip_option_keeps_default(self):
        with patch("builtins.input", side_effect=["y", "n"]):
            self.core.do_rebuild_xray_config()
        self.assertNotIn("min_client_ver", self._state())
        self.core._rebuild_and_restart_xray.assert_called_once()

    def test_flow_declined_no_rebuild(self):
        with patch("builtins.input", side_effect=["n"]):
            self.core.do_rebuild_xray_config()
        self.core._rebuild_and_restart_xray.assert_not_called()
        self.assertNotIn("min_client_ver", self._state())

    def test_flow_reset_existing_override(self):
        self._state()
        st = _base_state()
        st["min_client_ver"] = "1.8.0"
        self.core.STATE_FILE.write_text(json.dumps(st))
        # y = rebuild; y = выставить; "-" = сброс в ""
        with patch("builtins.input", side_effect=["y", "y", "-"]):
            self.core.do_rebuild_xray_config()
        self.assertEqual(self._state().get("min_client_ver"), "")
        self.core._rebuild_and_restart_xray.assert_called_once()


class TestPqInboundEmitsValue(unittest.TestCase):
    """inject_pq_inbound — чистая функция (без I/O), значение приходит
    параметром min_client_ver от вызывающих обёрток."""

    def _inject(self, cfg: dict, **kw) -> dict:
        from chimera.modules.pq_vless import inject_pq_inbound
        changed = inject_pq_inbound(
            cfg,
            port=kw.get("port", 8443),
            decryption=kw.get("decryption", "none"),
            shortid=kw.get("shortid", "aabbccdd"),
            reality_dest=kw.get("reality_dest", "www.cloudflare.com"),
            domain=kw.get("domain", "test.example.com"),
            private_key=kw.get("private_key", "PRIV"),
            public_key=kw.get("public_key", "PUB"),
            spiderx=kw.get("spiderx", "/"),
            users=kw.get("users", [{"uuid": "u-1", "email": "u@e"}]),
            xtls_flow=kw.get("xtls_flow", ""),
            min_client_ver=kw.get("min_client_ver", ""),
        )
        self.assertTrue(changed)
        return cfg["inbounds"][0]["streamSettings"]["realitySettings"]

    def test_emits_explicit_value(self):
        cfg: dict = {"inbounds": []}
        rs = self._inject(cfg, min_client_ver="1.8.0")
        self.assertEqual(rs["minClientVer"], "1.8.0")
        self.assertEqual(rs["maxClientVer"], "")

    def test_default_is_empty(self):
        cfg: dict = {"inbounds": []}
        rs = self._inject(cfg)
        self.assertEqual(rs["minClientVer"], "")

    def test_min_client_ver_from_state_file_reads_state(self):
        import chimera.modules.pq_vless as pq
        with tempfile.TemporaryDirectory() as tmp:
            fake_state = Path(tmp) / "state.json"
            fake_state.write_text(json.dumps(
                {"domain": "x.com", "min_client_ver": "1.8.0"}))
            old = pq.STATE_FILE
            pq.STATE_FILE = fake_state
            try:
                self.assertEqual(pq._min_client_ver_from_state_file(), "1.8.0")
            finally:
                pq.STATE_FILE = old

    def test_min_client_ver_from_state_file_no_file(self):
        import chimera.modules.pq_vless as pq
        with tempfile.TemporaryDirectory() as tmp:
            old = pq.STATE_FILE
            pq.STATE_FILE = Path(tmp) / "nonexistent.json"
            try:
                self.assertEqual(pq._min_client_ver_from_state_file(), "")
            finally:
                pq.STATE_FILE = old


class TestChainExitNodeEmitsValue(unittest.TestCase):
    """_make_exit_node_config — exit-нода REALITY читает minClientVer из
    state.json через core._min_client_ver_from_state (лениво, меню 5b)."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.core = _exec_core()
        self.core.STATE_FILE = Path(self._tmp) / "state.json"

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _exit_cfg(self) -> dict:
        from chimera.modules import chain_nodes
        nd = {
            "proto": "reality",
            "port": 443,
            "uuid": "11111111-2222-3333-4444-555555555555",
            "sni": "exit.example.com",
            "pubkey": "EXITPUB",
            "shortid": "11223344",
        }
        return chain_nodes._make_exit_node_config(nd)

    def test_exit_node_picks_up_override_from_state(self):
        st = _base_state()
        st["min_client_ver"] = "1.8.0"
        self.core.STATE_FILE.write_text(json.dumps(st))
        cfg = self._exit_cfg()
        rs = cfg["inbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(rs["minClientVer"], "1.8.0")

    def test_exit_node_default_empty(self):
        self.core.STATE_FILE.write_text(json.dumps(_base_state()))
        cfg = self._exit_cfg()
        rs = cfg["inbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(rs["minClientVer"], "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
