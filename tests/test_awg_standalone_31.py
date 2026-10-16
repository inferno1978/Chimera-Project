#!/usr/bin/env python3
"""
tests/test_awg_standalone_31.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты AWG 3.1 в awg_standalone.py / awg_state.py / awg_peers.py.

Покрывает:
  1. awgs_build_server_conf(protocol_version="3.1") — 9 директив после I1-I5
  2. awgs_state_init(protocol_version=...) — state-ключ protocol_version
  3. awg_peer_rebuild_conf — проброс версии из state в конфиг
  4. awgs_install — передача версии (контракт вызовов)
  5. РЕГРЕССИЯ 2.0: конфиг без версии — байт-в-байт прежний формат
"""
from __future__ import annotations

import json
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


def _mock_core():
    core = MagicMock()
    for attr in ("GREEN", "NC", "RED", "YELLOW", "CYAN", "BLUE", "DIM", "BOLD"):
        setattr(core, attr, "")
    for attr in ("_box_top", "_box_row", "_box_sep", "_box_bottom",
                 "_box_item", "_box_desc", "_box_wrap_msg"):
        setattr(core, attr, MagicMock())
    for attr in ("info", "success", "warn", "error", "log_to_file"):
        setattr(core, attr, MagicMock())
    return core


_PARAMS_20 = {
    "jc": 4, "jmin": 40, "jmax": 70,
    "s1": 15, "s2": 20, "s3": 12, "s4": 12,
    "h1": 1, "h2": 2, "h3": 3, "h4": 4,
    "i1": "<r 32>", "i2": "", "i3": "", "i4": "", "i5": "",
}
_PARAMS_31 = dict(_PARAMS_20)
_PARAMS_31.update({
    "header_protection_key": "oqOZEgg1pPbnVE4/wykuOmE875ghVEoLJS8Jd7rO2TQ=",
    "content_padding_addition": "12-40",
    "rekey_after_time": "100-140",
    "rekey_timeout": "3-6",
    "reject_after_time": "170-250",
    "keepalive_timeout": "8-14",
    "max_handshake_attempts": "15-35",
    "random_trailers": "on",
    "disable_cookies": "on",
})


class TestBuildServerConf31(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()

    def _build(self, protocol_version="", params=None):
        from chimera.modules import awg_standalone
        return awg_standalone.awgs_build_server_conf(
            server_privkey="SERVER_PRIV",
            port=51820,
            subnet="10.66.66.0/24",
            subnet_v6="",
            mtu=1280,
            params=params or _PARAMS_31,
            peers=[],
            endpoint_host="",
            protocol_version=protocol_version,
        )

    def test_31_directives_present(self):
        conf = self._build("3.1")
        self.assertIn("HeaderProtectionKey = ", conf)
        self.assertIn("ContentPaddingAddition = 12-40", conf)
        self.assertIn("RekeyAfterTime = 100-140", conf)
        self.assertIn("RekeyTimeout = 3-6", conf)
        self.assertIn("RejectAfterTime = 170-250", conf)
        self.assertIn("KeepaliveTimeout = 8-14", conf)
        self.assertIn("MaxHandshakeAttempts = 15-35", conf)
        self.assertIn("RandomTrailers = on", conf)
        self.assertIn("DisableCookies = on", conf)

    def test_31_directives_after_i_lines(self):
        # Порядок: ... I1-I5, затем блок 3.1 (GenerateObfuscation31)
        conf = self._build("3.1")
        i5_pos = conf.find("# I5 = ")
        hpk_pos = conf.find("HeaderProtectionKey = ")
        self.assertGreater(hpk_pos, i5_pos)
        self.assertGreater(hpk_pos, conf.find("I1 = <r 32>"))

    def test_31_empty_extra_commented(self):
        # Правило: пустые 3.1-параметры комментируются
        params = dict(_PARAMS_31)
        params["rekey_timeout"] = ""
        conf = self._build("3.1", params)
        self.assertIn("# RekeyTimeout = ", conf)
        self.assertNotIn("\nRekeyTimeout = \n", conf)

    def test_20_regression_no_31_directives(self):
        # РЕГРЕССИЯ: без версии (или "2.0") — ни одной 3.1-директивы
        for pv in ("", "2.0"):
            conf = self._build(pv)
            for d in ("HeaderProtectionKey", "ContentPaddingAddition",
                      "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
                      "KeepaliveTimeout", "MaxHandshakeAttempts",
                      "RandomTrailers", "DisableCookies"):
                self.assertNotIn(d, conf, msg=f"pv={pv!r}: {d} не должно быть")

    def test_20_regression_byte_identical(self):
        # 2.0-конфиг не зависит от наличия 3.1-ключей в params:
        # без версии они просто игнорируются
        from chimera.modules import awg_standalone
        conf_20_params_31 = awg_standalone.awgs_build_server_conf(
            "SERVER_PRIV", 51820, "10.66.66.0/24", "", 1280,
            _PARAMS_31, [], "", "", None, "")
        conf_20_params_20 = awg_standalone.awgs_build_server_conf(
            "SERVER_PRIV", 51820, "10.66.66.0/24", "", 1280,
            _PARAMS_20, [], "", "", None, "")
        self.assertEqual(conf_20_params_31, conf_20_params_20)

    def test_31_with_peers(self):
        peers = [{"name": "alice", "client_pubkey": "PUB",
                  "client_ip": "10.66.66.2", "client_ipv6": "",
                  "preshared_key": ""}]
        from chimera.modules import awg_standalone
        conf = awg_standalone.awgs_build_server_conf(
            "SERVER_PRIV", 51820, "10.66.66.0/24", "", 1280,
            _PARAMS_31, peers, "", "", None, "3.1")
        self.assertIn("HeaderProtectionKey = ", conf)
        self.assertIn("# alice", conf)
        self.assertIn("[Peer]", conf)


class TestStateProtocolVersion(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state(self):
        from chimera.modules import awg_state
        return patch.object(awg_state, "AWGS_STATE_FILE", self._state_file)

    def test_init_default_20(self):
        from chimera.modules import awg_state
        with self._patch_state():
            st = awg_state.awgs_state_init("PRIV", "PUB")
            self.assertEqual(st["protocol_version"], "2.0")

    def test_init_31(self):
        from chimera.modules import awg_state
        with self._patch_state():
            st = awg_state.awgs_state_init("PRIV", "PUB",
                                           protocol_version="3.1")
            self.assertEqual(st["protocol_version"], "3.1")
            # Нормализация: "awg31" → "3.1"
            st2 = awg_state.awgs_state_init("PRIV", "PUB",
                                            protocol_version="awg31")
            self.assertEqual(st2["protocol_version"], "3.1")

    def test_get_missing_is_20(self):
        # Старый state-файл без ключа → 2.0 (миграция без миграции)
        self._state_file.write_text(json.dumps({"installed": True}))
        from chimera.modules import awg_state
        with self._patch_state():
            self.assertEqual(
                awg_state.awgs_state_get_protocol_version(), "2.0")

    def test_get_set_31(self):
        from chimera.modules import awg_state
        with self._patch_state():
            awg_state.awgs_state_init("PRIV", "PUB")
            awg_state.awgs_state_set_protocol_version("3.1")
            self.assertEqual(
                awg_state.awgs_state_get_protocol_version(), "3.1")

    def test_chmod_600_preserved(self):
        import os, stat
        from chimera.modules import awg_state
        with self._patch_state():
            awg_state.awgs_state_init("PRIV", "PUB", protocol_version="3.1")
            mode = stat.S_IMODE(os.stat(self._state_file).st_mode)
            self.assertEqual(mode, 0o600)


class TestPeerRebuildPropagatesVersion(unittest.TestCase):
    """awg_peer_rebuild_conf пробрасывает protocol_version из state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_rebuild_passes_version_to_build(self):
        state = {
            "installed": True,
            "server_privkey": "PRIV",
            "port": 51820,
            "subnet": "10.66.66.0/24",
            "subnet_v6": "",
            "mtu": 1280,
            "params": _PARAMS_31,
            "peers": [],
            "protocol_version": "3.1",
        }
        self._state_file.write_text(json.dumps(state))
        from chimera.modules import awg_peers, awg_state
        with patch.object(awg_state, "AWGS_STATE_FILE", self._state_file), \
             patch.object(awg_peers, "awgs_state_load",
                          return_value=state), \
             patch.object(awg_peers, "awgs_write_server_conf",
                          return_value=True) as mock_write, \
             patch.object(awg_peers, "awgs_apply", return_value=True):
            ok = awg_peers.awg_peer_rebuild_conf(apply=True)
            self.assertTrue(ok)
            written = mock_write.call_args.args[0]
            self.assertIn("HeaderProtectionKey = ", written)
            self.assertIn("RandomTrailers = on", written)

    def test_rebuild_20_state_no_31(self):
        state = {
            "installed": True,
            "server_privkey": "PRIV",
            "port": 51820,
            "subnet": "10.66.66.0/24",
            "subnet_v6": "",
            "mtu": 1280,
            "params": _PARAMS_20,
            "peers": [],
            # protocol_version отсутствует = 2.0
        }
        from chimera.modules import awg_peers
        with patch.object(awg_peers, "awgs_state_load", return_value=state), \
             patch.object(awg_peers, "awgs_write_server_conf",
                          return_value=True) as mock_write, \
             patch.object(awg_peers, "awgs_apply", return_value=True):
            ok = awg_peers.awg_peer_rebuild_conf(apply=True)
            self.assertTrue(ok)
            written = mock_write.call_args.args[0]
            self.assertNotIn("HeaderProtectionKey", written)


class TestInstallContract31(unittest.TestCase):
    """awgs_install: версия протокола пробрасывается в state и конфиг."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_install_31_calls(self):
        from chimera.modules import awg_standalone
        mock_core = _mock_core()
        with patch.object(Path, "mkdir", lambda self, *a, **kw: None), \
             patch.object(Path, "touch", lambda self, *a, **kw: None), \
             patch.object(awg_standalone, "_core_module",
                          return_value=mock_core), \
             patch.object(awg_standalone, "awgs_check_conflicts",
                          return_value=[]), \
             patch.object(awg_standalone, "awgs_install_dkms",
                          return_value=True), \
             patch.object(awg_standalone, "awgs_hw_tune_all",
                          return_value={}), \
             patch.object(awg_standalone, "awgs_generate_keys",
                          return_value=("PRIV", "PUB")), \
             patch.object(awg_standalone, "awgs_build_server_conf",
                          return_value="[Interface]\n") as mock_build, \
             patch.object(awg_standalone, "awgs_write_server_conf",
                          return_value=True), \
             patch.object(awg_standalone, "awgs_setup_firewall",
                          return_value=True), \
             patch.object(awg_standalone, "awgs_setup_systemd",
                          return_value=True), \
             patch.object(awg_standalone, "awgs_setup_nat_and_routing",
                          return_value=True), \
             patch.object(awg_standalone, "awgs_state_init") as mock_init, \
             patch.object(awg_standalone, "awgs_setup_expires_cron",
                          return_value=True), \
             patch.object(awg_standalone, "awgs_presets_generate") as mock_gen:
            mock_gen.return_value = dict(_PARAMS_31)
            ok = awg_standalone.awgs_install(protocol_version="3.1")
            self.assertTrue(ok)
            # Генерация — с версией 3.1
            self.assertEqual(
                mock_gen.call_args.kwargs.get("protocol_version"), "3.1")
            # Конфиг — с версией 3.1
            self.assertEqual(
                mock_build.call_args.kwargs.get("protocol_version"), "3.1")
            # State — с версией 3.1
            self.assertEqual(
                mock_init.call_args.kwargs.get("protocol_version"), "3.1")

    def test_install_20_default_contract(self):
        # РЕГРЕССИЯ: без версии — все вызовы с protocol_version="2.0"
        from chimera.modules import awg_standalone
        mock_core = _mock_core()
        with patch.object(Path, "mkdir", lambda self, *a, **kw: None), \
             patch.object(Path, "touch", lambda self, *a, **kw: None), \
             patch.object(awg_standalone, "_core_module",
                          return_value=mock_core), \
             patch.object(awg_standalone, "awgs_check_conflicts",
                          return_value=[]), \
             patch.object(awg_standalone, "awgs_install_dkms",
                          return_value=True), \
             patch.object(awg_standalone, "awgs_hw_tune_all",
                          return_value={}), \
             patch.object(awg_standalone, "awgs_generate_keys",
                          return_value=("PRIV", "PUB")), \
             patch.object(awg_standalone, "awgs_build_server_conf",
                          return_value="[Interface]\n") as mock_build, \
             patch.object(awg_standalone, "awgs_write_server_conf",
                          return_value=True), \
             patch.object(awg_standalone, "awgs_setup_firewall",
                          return_value=True), \
             patch.object(awg_standalone, "awgs_setup_systemd",
                          return_value=True), \
             patch.object(awg_standalone, "awgs_setup_nat_and_routing",
                          return_value=True), \
             patch.object(awg_standalone, "awgs_state_init") as mock_init, \
             patch.object(awg_standalone, "awgs_setup_expires_cron",
                          return_value=True), \
             patch.object(awg_standalone, "awgs_presets_generate") as mock_gen:
            mock_gen.return_value = dict(_PARAMS_20)
            ok = awg_standalone.awgs_install()
            self.assertTrue(ok)
            self.assertEqual(
                mock_build.call_args.kwargs.get("protocol_version"), "2.0")
            self.assertEqual(
                mock_init.call_args.kwargs.get("protocol_version"), "2.0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
