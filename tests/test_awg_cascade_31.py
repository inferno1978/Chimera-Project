#!/usr/bin/env python3
"""
tests/test_awg_cascade_31.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты AWG 3.1 в awg_cascade.py — каскад из 2 серверов.

Покрывает:
  1. _awgs_cascade_build_awg1_conf(exit_protocol_version="3.1") — 9 директив
  2. awgs_cascade_setup_awg0 — версионная валидация (entry 2.0 vs exit 3.1)
  3. awgs_cascade_setup_awg1 — бокс данных содержит Protocol version
  4. РЕГРЕССИЯ 2.0: без версии — конфиг и валидация байт-в-байт как v5.4.5
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


def _mock_core_for_cascade():
    core = MagicMock()
    for attr in ("GREEN", "NC", "RED", "YELLOW", "CYAN", "BLUE", "DIM", "BOLD"):
        setattr(core, attr, "")
    for attr in ("_box_top", "_box_row", "_box_sep", "_box_bottom",
                 "_box_item", "_box_desc", "_box_wrap_msg"):
        setattr(core, attr, MagicMock())
    for attr in ("info", "success", "warn", "error", "log_to_file"):
        setattr(core, attr, MagicMock())
    r = MagicMock()
    r.returncode = 0
    r.stdout = ""
    r.stderr = ""
    core._run = MagicMock(return_value=r)
    core.get_server_ip = MagicMock(return_value="5.6.7.8")
    return core


_HPKEY = "aGVhZGVycHJvdGVjdGlvbi1rZXktMzItYnl0ZXMhISEhIQ=="

_PARAMS_31 = {
    "jc": 4, "jmin": 40, "jmax": 70,
    "s1": 15, "s2": 20, "s3": 12, "s4": 12,
    "h1": 1, "h2": 2, "h3": 3, "h4": 4,
    "i1": "<r 32>", "i2": "", "i3": "", "i4": "", "i5": "",
    "header_protection_key": _HPKEY,
    "content_padding_addition": "12-40",
    "rekey_after_time": "100-140",
    "rekey_timeout": "3-6",
    "reject_after_time": "170-250",
    "keepalive_timeout": "8-14",
    "max_handshake_attempts": "15-35",
    "random_trailers": "on",
    "disable_cookies": "on",
}

_STATE_31 = {
    "installed": True,
    "subnet": "10.66.66.0/24",
    "mtu": 1280,
    "params": dict(_PARAMS_31),
    "protocol_version": "3.1",
}


class TestBuildAwg1Conf31(unittest.TestCase):
    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "awg_standalone_state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _build(self, exit_protocol_version="", exit_params=None,
               own_state=None):
        from chimera.modules import awg_cascade
        state = own_state if own_state is not None else _STATE_31
        self._state_file.write_text(json.dumps(state))
        with patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                   self._state_file), \
             patch("chimera.modules.awg_cascade.awgs_state_load",
                   return_value=state):
            return awg_cascade._awgs_cascade_build_awg1_conf(
                exit_host="1.2.3.4",
                exit_port=51820,
                exit_pubkey="EXIT_PUB",
                client_privkey="CLIENT_PRIV",
                psk="",
                exit_subnet="172.16.61.0/24",
                exit_peer_ip="172.16.61.2",
                exit_params=exit_params if exit_params is not None
                else dict(_PARAMS_31),
                exit_protocol_version=exit_protocol_version,
            )

    def test_31_directives_present(self):
        conf = self._build("3.1")
        self.assertIn(f"HeaderProtectionKey = {_HPKEY}", conf)
        self.assertIn("ContentPaddingAddition = 12-40", conf)
        self.assertIn("RekeyAfterTime = 100-140", conf)
        self.assertIn("RandomTrailers = on", conf)
        self.assertIn("DisableCookies = on", conf)

    def test_31_after_i_lines_before_peer(self):
        conf = self._build("3.1")
        self.assertGreater(conf.find("HeaderProtectionKey = "),
                           conf.find("I1 = <r 32>"))
        self.assertLess(conf.find("HeaderProtectionKey = "),
                        conf.find("[Peer]"))

    def test_table_off_preserved(self):
        # SSH-lockout guard (33970c2) не должен сломаться 3.1-блоком
        conf = self._build("3.1")
        self.assertIn("Table = off", conf)

    def test_regression_20_no_directives(self):
        # Без версии (или "2.0") — ни одной 3.1-директивы, даже если
        # exit_params содержат 3.1-ключи
        for pv in ("", "2.0"):
            conf = self._build(pv)
            for d in ("HeaderProtectionKey", "RandomTrailers",
                      "DisableCookies", "RekeyAfterTime"):
                self.assertNotIn(d, conf, msg=f"pv={pv!r}")

    def test_regression_20_byte_identical(self):
        # 2.0-конфиг не зависит от версии entry-state
        state_20 = {"installed": True, "subnet": "10.66.66.0/24",
                    "mtu": 1280,
                    "params": {k: v for k, v in _PARAMS_31.items()
                               if k not in ("header_protection_key",
                                            "content_padding_addition",
                                            "rekey_after_time", "rekey_timeout",
                                            "reject_after_time", "keepalive_timeout",
                                            "max_handshake_attempts",
                                            "random_trailers", "disable_cookies")}}
        conf_a = self._build("", own_state=_STATE_31)
        conf_b = self._build("", own_state=state_20)
        self.assertEqual(conf_a, conf_b)


class TestSetupAwg0VersionValidation(unittest.TestCase):
    """Версии entry и exit обязаны совпадать — иначе handshake мёртв."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "awg_standalone_state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _setup_awg0(self, own_state, exit_protocol_version):
        from chimera.modules import awg_cascade
        self._state_file.write_text(json.dumps(own_state))
        mock_core = _mock_core_for_cascade()
        with patch.object(awg_cascade, "_core_module",
                          return_value=mock_core), \
             patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                   self._state_file), \
             patch("chimera.modules.awg_cascade.awgs_state_load",
                   return_value=own_state) as mock_load, \
             patch("chimera.modules.awg_cascade.awgs_generate_keys",
                   return_value=("PEER_PRIV", "PEER_PUB")), \
             patch("chimera.modules.awg_cascade.awgs_state_set_cascade_role") \
             as mock_role, \
             patch("chimera.modules.awg_cascade._awgs_cascade_build_awg1_conf",
                   return_value="[Interface]\n") as mock_build_conf, \
             patch("chimera.modules.awg_cascade.awgs_cascade_download_ru_zone",
                   return_value=True), \
             patch("chimera.modules.awg_cascade.awgs_cascade_load_ipset",
                   return_value=True), \
             patch("chimera.modules.awg_cascade._awgs_cascade_apply_iptables",
                   return_value=True), \
             patch("chimera.modules.awg_cascade._awgs_cascade_create_routing_script"), \
             patch("chimera.modules.awg_cascade._awgs_cascade_create_systemd_unit"), \
             patch("chimera.modules.awg_cascade._awgs_cascade_setup_cron"), \
             patch.object(Path, "write_text"), patch.object(Path, "chmod"), \
             patch.object(Path, "mkdir"):
            ok = awg_cascade.awgs_cascade_setup_awg0(
                exit_host="1.2.3.4",
                exit_port=51820,
                exit_pubkey="EXIT_PUB",
                exit_subnet="172.16.61.0/24",
                exit_params=dict(_PARAMS_31),
                exit_protocol_version=exit_protocol_version,
            )
            return ok, mock_build_conf, mock_core

    def test_mismatch_rejected(self):
        # entry 2.0 + exit 3.1 → отказ ДО любых изменений
        state_20 = {"installed": True, "subnet": "10.66.66.0/24",
                    "mtu": 1280, "params": {}}
        ok, mock_build, core = self._setup_awg0(state_20, "3.1")
        self.assertFalse(ok)
        # Конфиг awg1 не строился, роль не менялась
        mock_build.assert_not_called()
        # Предупреждение показано
        warned = [str(c) for c in core.warn.call_args_list]
        self.assertTrue(any("не совпадают" in w for w in warned),
                        msg=warned)

    def test_match_31_ok(self):
        ok, mock_build, core = self._setup_awg0(dict(_STATE_31), "3.1")
        self.assertTrue(ok)
        # Конфиг awg1 строится с 3.1-версией
        self.assertEqual(
            mock_build.call_args.kwargs.get("exit_protocol_version"), "3.1")

    def test_match_20_ok(self):
        state_20 = {"installed": True, "subnet": "10.66.66.0/24",
                    "mtu": 1280, "params": {}}
        ok, mock_build, core = self._setup_awg0(state_20, "2.0")
        self.assertTrue(ok)
        self.assertEqual(
            mock_build.call_args.kwargs.get("exit_protocol_version"), "2.0")

    def test_missing_exit_version_treated_as_20(self):
        # Старые боксы AWG1 (без Protocol version) → exit=2.0;
        # entry 2.0 → OK (обратная совместимость)
        state_20 = {"installed": True, "subnet": "10.66.66.0/24",
                    "mtu": 1280, "params": {}}
        ok, mock_build, core = self._setup_awg0(state_20, "")
        self.assertTrue(ok)


class TestSetupAwg1DataBox(unittest.TestCase):
    """Бокс данных AWG1 содержит Protocol version + расширенный JSON."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state_file = self._tmpdir / "awg_standalone_state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_databox_contains_version(self):
        from chimera.modules import awg_cascade
        state = dict(_STATE_31)
        state.update({
            "endpoint": "9.9.9.9", "port": 51821,
            "server_pubkey": "EXIT_PUB",
            "peers": [{"name": "cascade_entry", "client_ip": "172.16.61.2"}],
        })
        self._state_file.write_text(json.dumps(state))
        mock_core = _mock_core_for_cascade()
        with patch.object(awg_cascade, "_core_module",
                          return_value=mock_core), \
             patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                   self._state_file), \
             patch("chimera.modules.awg_cascade.awgs_state_is_installed",
                   return_value=True), \
             patch("chimera.modules.awg_state.awgs_state_load",
                   return_value=state), \
             patch("chimera.modules.awg_state.awgs_state_peer_find",
                   return_value={"name": "cascade_entry",
                                 "client_ip": "172.16.61.2"}), \
             patch("chimera.modules.awg_state.awgs_state_set_cascade_role"), \
             patch("chimera.modules.awg_cascade.awg_peer_add",
                   return_value=True):
            ok = awg_cascade.awgs_cascade_setup_awg1(protocol_version="3.1")
            self.assertTrue(ok)
            # _box_row вызывался со строкой Protocol version: 3.1
            rows = [str(c) for c in mock_core._box_row.call_args_list]
            self.assertTrue(
                any("Protocol version: 3.1" in r for r in rows), msg=rows)

    def test_databox_obfuscation_json_contains_31_keys(self):
        from chimera.modules import awg_cascade
        state = dict(_STATE_31)
        state.update({
            "endpoint": "9.9.9.9", "port": 51821,
            "server_pubkey": "EXIT_PUB",
        })
        self._state_file.write_text(json.dumps(state))
        mock_core = _mock_core_for_cascade()
        with patch.object(awg_cascade, "_core_module",
                          return_value=mock_core), \
             patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                   self._state_file), \
             patch("chimera.modules.awg_cascade.awgs_state_is_installed",
                   return_value=True), \
             patch("chimera.modules.awg_state.awgs_state_load",
                   return_value=state), \
             patch("chimera.modules.awg_state.awgs_state_peer_find",
                   return_value={"name": "cascade_entry",
                                 "client_ip": "172.16.61.2"}), \
             patch("chimera.modules.awg_state.awgs_state_set_cascade_role"), \
             patch("chimera.modules.awg_cascade.awg_peer_add",
                   return_value=True):
            awg_cascade.awgs_cascade_setup_awg1(protocol_version="3.1")
            # JSON обфускации в боксе содержит header_protection_key
            rows = [str(c) for c in mock_core._box_row.call_args_list]
            json_rows = [r for r in rows if "header_protection_key" in r]
            self.assertTrue(json_rows, msg=rows)


if __name__ == "__main__":
    unittest.main(verbosity=2)
