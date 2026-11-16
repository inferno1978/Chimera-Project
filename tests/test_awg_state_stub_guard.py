#!/usr/bin/env python3
"""
tests/test_awg_state_stub_guard.py
───────────────────────────────────────────────────────────────────────────────
Регрессионные тесты инцидента 16.11.2026 «стаб-перезапись поверх потери
state» (живые RU1/RU2 10.11: оба state сброшены в 535-байтные стабы без
installed/peers одной минутой; у RU2 — {"cascade_exits":[{"name":"1.2.3.4"}]}
от add-exit поверх потери).

Покрывает:
  1. Гард awgs_state_save — отказ записи state без installed при живом
     awg0.conf (стаб не создаётся, существующий state не затирается);
     force=True — обход.
  2. awgs_state_update — отказ (без создания стаба) при потерянном state,
     честный возврат содержимого диска; штатная работа при installed.
  3. awgs_state_set_protocol_version — честный результат сохранения.
  4. awgs_state_loss_reason — классификатор ''|missing|corrupt|stub
     (сопоставление файла state с фактом установки по awg0.conf).
  5. Env-изоляция тестов: AWG/Telemt-прод-деревья в _DEFAULT_PREFIXES
     (класс «тест на живой ноде сносит прод»: 27.10 xray, 16.11 telemt).
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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


_FULL_STATE = {
    "installed": True,
    "version": "1.0.0",
    "port": 55277,
    "subnet": "10.66.68.0/24",
    "peers": [{"name": "user-main"}],
}


class _TmpBase(unittest.TestCase):
    """Общая база: tmp-каталог + патчи AWGS_STATE_FILE/AWGS_SERVER_CONF."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._state_file = Path(self._tmpdir) / "awg_standalone_state.json"
        self._conf_file = Path(self._tmpdir) / "awg0.conf"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state(self):
        return patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                     self._state_file)

    def _patch_conf(self, exists: bool):
        target = self._conf_file if exists else (Path(self._tmpdir) / "nope.conf")
        return patch("chimera.modules.awg_state.AWGS_SERVER_CONF", target)

    def _make_conf(self):
        self._conf_file.write_text("[Interface]\nListenPort = 55277\n")


class TestSaveGuard(_TmpBase):
    """Гард awgs_state_save: стаб не пишется при живом awg0.conf."""

    def test_save_refuses_stub_when_awg0_conf_exists(self):
        from chimera.modules import awg_state
        self._make_conf()
        stub = {"cascade_exits": [{"name": "1.2.3.4", "port": 51820}]}
        with self._patch_state(), self._patch_conf(True):
            self.assertFalse(awg_state.awgs_state_save(stub))
            self.assertFalse(self._state_file.exists(),
                             "стаб не должен создаваться поверх потери")

    def test_save_stub_allowed_on_clean_server(self):
        from chimera.modules import awg_state
        # awg0.conf нет → писать можно (чистый сервер, первый запуск)
        stub = {"lb": {"balance": None}}
        with self._patch_state(), self._patch_conf(False):
            self.assertTrue(awg_state.awgs_state_save(stub))
            self.assertTrue(self._state_file.exists())

    def test_save_refusal_leaves_existing_state_intact(self):
        from chimera.modules import awg_state
        self._make_conf()
        self._state_file.write_text(json.dumps(_FULL_STATE))
        stub = {"lb": {"slots_snapshot": {}}}   # RMW-тик поверх живого state
        with self._patch_state(), self._patch_conf(True):
            self.assertFalse(awg_state.awgs_state_save(stub))
            on_disk = json.loads(self._state_file.read_text())
        self.assertTrue(on_disk.get("installed"))
        self.assertEqual(on_disk.get("peers"), [{"name": "user-main"}],
                         "существующий state не должен затираться стабом")

    def test_save_full_state_allowed_with_conf(self):
        from chimera.modules import awg_state
        self._make_conf()
        with self._patch_state(), self._patch_conf(True):
            self.assertTrue(awg_state.awgs_state_save(dict(_FULL_STATE)))
            self.assertTrue(json.loads(self._state_file.read_text())["installed"])

    def test_save_force_bypasses_guard(self):
        from chimera.modules import awg_state
        self._make_conf()
        stub = {"maintenance": True}
        with self._patch_state(), self._patch_conf(True):
            self.assertTrue(awg_state.awgs_state_save(stub, force=True))
            self.assertTrue(self._state_file.exists())


class TestUpdateRefusal(_TmpBase):
    """awgs_state_update / set_protocol_version при потерянном state."""

    def test_update_does_not_create_stub_on_lost_state(self):
        # Репро живого RU2 10.11: add-exit поверх потерянного state
        # писал {"cascade_exits":[{"name":"1.2.3.4"}]} без installed.
        from chimera.modules import awg_state
        self._make_conf()
        with self._patch_state(), self._patch_conf(True):
            res = awg_state.awgs_state_update(
                cascade_exits=[{"name": "1.2.3.4", "port": 51820}])
            self.assertEqual(res, {}, "при отказе — содержимое диска, не призрак")
            self.assertFalse(self._state_file.exists(),
                             "стаб не должен создаваться поверх потери")

    def test_update_persists_when_installed(self):
        from chimera.modules import awg_state
        self._make_conf()
        self._state_file.write_text(json.dumps(_FULL_STATE))
        with self._patch_state(), self._patch_conf(True):
            res = awg_state.awgs_state_update(lb={"mode": "rr"})
        self.assertTrue(res["installed"])
        on_disk = json.loads(self._state_file.read_text())
        self.assertTrue(on_disk["installed"])
        self.assertEqual(on_disk["lb"], {"mode": "rr"})

    def test_set_protocol_version_honest_false_on_lost_state(self):
        from chimera.modules import awg_state
        self._make_conf()
        with self._patch_state(), self._patch_conf(True):
            self.assertFalse(awg_state.awgs_state_set_protocol_version("3.1"))
            self.assertFalse(self._state_file.exists())

    def test_set_protocol_version_true_when_installed(self):
        from chimera.modules import awg_state
        self._make_conf()
        self._state_file.write_text(json.dumps(_FULL_STATE))
        with self._patch_state(), self._patch_conf(True):
            self.assertTrue(awg_state.awgs_state_set_protocol_version("3.1"))
        self.assertEqual(
            json.loads(self._state_file.read_text())["protocol_version"], "3.1")


class TestLossReason(_TmpBase):
    """awgs_state_loss_reason: '' | missing | corrupt | stub."""

    def test_ok_when_installed(self):
        from chimera.modules import awg_state
        self._make_conf()
        self._state_file.write_text(json.dumps(_FULL_STATE))
        with self._patch_state(), self._patch_conf(True):
            self.assertEqual(awg_state.awgs_state_loss_reason(), "")

    def test_missing_with_conf(self):
        from chimera.modules import awg_state
        self._make_conf()
        with self._patch_state(), self._patch_conf(True):
            self.assertEqual(awg_state.awgs_state_loss_reason(), "missing")

    def test_missing_without_conf_is_not_a_loss(self):
        from chimera.modules import awg_state
        with self._patch_state(), self._patch_conf(False):
            self.assertEqual(awg_state.awgs_state_loss_reason(), "")

    def test_corrupt_with_conf(self):
        from chimera.modules import awg_state
        self._make_conf()
        self._state_file.write_text("{invalid json!!!")
        with self._patch_state(), self._patch_conf(True):
            self.assertEqual(awg_state.awgs_state_loss_reason(), "corrupt")

    def test_stub_detected(self):
        # Репро живых RU1/RU2: файл есть, JSON валиден, installed нет.
        from chimera.modules import awg_state
        self._make_conf()
        self._state_file.write_text(
            json.dumps({"cascade_exits": [{"name": "1.2.3.4"}]}))
        with self._patch_state(), self._patch_conf(True):
            self.assertEqual(awg_state.awgs_state_loss_reason(), "stub")

    def test_stub_without_conf_is_not_a_loss(self):
        from chimera.modules import awg_state
        self._state_file.write_text(json.dumps({"lb": {}}))
        with self._patch_state(), self._patch_conf(False):
            self.assertEqual(awg_state.awgs_state_loss_reason(), "")


class TestEnvIsolationPrefixes(unittest.TestCase):
    """AWG/Telemt-прод-деревья обязаны быть в изоляции тестов.

    Класс инцидентов «тест на живой ноде сносит прод»: 27.10
    (identity_guard/credential_rotation перезаписали live-конфиг xray),
    16.11 (telemt-тест снёс /etc/telemt + бинарь + unit + state —
    b79e067). Префиксный список — защита по умолчанию для БУДУЩИХ тестов.
    """

    _REQUIRED_DIRS = (
        "/etc/amnezia",
        "/etc/awg-cascade",
        "/root/awg",
        "/etc/telemt",
    )
    _REQUIRED_FILES = (
        "/usr/local/bin/telemt",
        "/etc/systemd/system/telemt.service",
        "/etc/systemd/system/awg-cascade-routing.service",
        "/etc/systemd/system/awg-quick@.service",
        "/usr/local/sbin/awg-nat-rules.sh",
        "/usr/local/sbin/awg-expires-check.sh",
        "/usr/local/sbin/awg-cascade-ru-update.sh",
        "/usr/local/sbin/awg-cascade-failover.sh",
    )

    def test_awg_and_telemt_prod_trees_in_default_prefixes(self):
        from tests import _env_isolation
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CHIMERA_TEST_ISOLATE_PREFIXES", None)
            for d in self._REQUIRED_DIRS:
                self.assertIn(d, _env_isolation._DEFAULT_PREFIXES)
                self.assertTrue(
                    _env_isolation._is_isolated(d + "/awg0.conf"),
                    f"{d}/… должно быть изолировано")
            for f in self._REQUIRED_FILES:
                self.assertIn(f, _env_isolation._DEFAULT_PREFIXES)
                self.assertTrue(_env_isolation._is_isolated(f),
                                f"{f} должно быть изолировано")


if __name__ == "__main__":
    unittest.main()
