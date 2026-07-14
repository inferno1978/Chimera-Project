#!/usr/bin/env python3
"""
tests/test_pq_vless.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/pq_vless.py.

Покрывает:
  1. pq_state_load — чтение pq_vless_* ключей
  2. pq_state_save — merge с flock
  3. _find_xray_bin / _xray_config_path
  4. _read_users — чтение users.json с fallback
  5. _port_is_free / find_unused_port
  6. _gen_shortid
  7. inject_pq_inbound / remove_pq_inbound / has_pq_inbound
  8. _build_pq_link — генерация vless:// URL
"""
from __future__ import annotations

import json
import os
import socket
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


class TestPqStateLoad(unittest.TestCase):
    """pq_state_load — чтение pq_vless_* ключей."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.pq_vless.STATE_FILE", self._state)

    def test_returns_empty_when_no_file(self):
        from chimera.modules.pq_vless import pq_state_load
        with self._patch():
            self.assertEqual(pq_state_load(), {})

    def test_returns_empty_when_corrupt(self):
        from chimera.modules.pq_vless import pq_state_load
        self._state.write_text("{invalid")
        with self._patch():
            self.assertEqual(pq_state_load(), {})

    def test_returns_only_pq_keys(self):
        """Только pq_vless_* ключи, не UUID и не другие."""
        from chimera.modules.pq_vless import pq_state_load
        self._state.write_text(json.dumps({
            "uuid": "abc",
            "domain": "example.com",
            "pq_vless_enabled": True,
            "pq_vless_port": 8443,
        }))
        with self._patch():
            state = pq_state_load()
        self.assertEqual(state, {"pq_vless_enabled": True, "pq_vless_port": 8443})

    def test_returns_all_pq_keys_when_present(self):
        from chimera.modules.pq_vless import pq_state_load
        full = {
            "pq_vless_enabled": True,
            "pq_vless_port": 8443,
            "pq_vless_shortid": "deadbeef",
            "pq_vless_decryption": "dec",
            "pq_vless_encryption": "enc",
            "pq_vless_xtls_flow": "xtls-rprx-vision",
            "pq_vless_mldsa65_enabled": False,
            "pq_vless_mldsa65_seed": "",
            "pq_vless_mldsa65_verify": "",
        }
        self._state.write_text(json.dumps(full))
        with self._patch():
            state = pq_state_load()
        for k, v in full.items():
            self.assertEqual(state[k], v)


class TestPqStateSave(unittest.TestCase):
    """pq_state_save — merge с flock."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.pq_vless.STATE_FILE", self._state)

    def test_does_nothing_when_no_file(self):
        from chimera.modules.pq_vless import pq_state_load, pq_state_save
        with self._patch():
            pq_state_save({"pq_vless_enabled": True})
            self.assertFalse(self._state.exists())
            self.assertEqual(pq_state_load(), {})

    def test_merges_pq_keys_preserving_others(self):
        from chimera.modules.pq_vless import pq_state_load, pq_state_save
        self._state.write_text(json.dumps({
            "uuid": "abc",
            "domain": "example.com",
            "pq_vless_port": 8443,
        }))
        with self._patch():
            pq_state_save({"pq_vless_enabled": True})
            state = pq_state_load()
        self.assertEqual(state.get("pq_vless_enabled"), True)
        self.assertEqual(state.get("pq_vless_port"), 8443)
        # другие ключи сохранены
        full = json.loads(self._state.read_text())
        self.assertEqual(full["uuid"], "abc")
        self.assertEqual(full["domain"], "example.com")

    def test_overwrites_existing_pq_keys(self):
        from chimera.modules.pq_vless import pq_state_load, pq_state_save
        self._state.write_text(json.dumps({"pq_vless_port": 8443}))
        with self._patch():
            pq_state_save({"pq_vless_port": 9999})
            self.assertEqual(pq_state_load()["pq_vless_port"], 9999)


class TestFindXrayBin(unittest.TestCase):
    """_find_xray_bin."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_first_existing(self):
        from chimera.modules import pq_vless
        def _fake_exists(self_path):
            return "xray" in str(self_path)
        with patch.object(Path, "exists", _fake_exists):
            result = pq_vless._find_xray_bin()
            self.assertIsNotNone(result)

    def test_returns_none_when_not_found(self):
        from chimera.modules import pq_vless
        with patch.object(Path, "exists", return_value=False), \
             patch("shutil.which", return_value=None):
            self.assertIsNone(pq_vless._find_xray_bin())


class TestXrayConfigPath(unittest.TestCase):
    """_xray_config_path."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_first_existing(self):
        from chimera.modules import pq_vless
        path1 = self._tmpdir / "config1.json"
        path1.write_text("{}")
        with patch.object(pq_vless, "XRAY_CONFIG_PATHS", [path1, Path("/nonexistent")]):
            result = pq_vless._xray_config_path()
            self.assertEqual(result, path1)

    def test_returns_none_when_no_existing(self):
        from chimera.modules import pq_vless
        with patch.object(pq_vless, "XRAY_CONFIG_PATHS",
                          [Path("/nonexistent1"), Path("/nonexistent2")]):
            self.assertIsNone(pq_vless._xray_config_path())


class TestReadUsers(unittest.TestCase):
    """_read_users."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._users = self._tmpdir / "users.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.pq_vless.USERS_FILE", self._users)

    def test_returns_empty_when_no_file_no_uuid(self):
        from chimera.modules.pq_vless import _read_users
        with self._patch():
            self.assertEqual(_read_users(), [])

    def test_returns_uuid_when_no_file(self):
        from chimera.modules.pq_vless import _read_users
        with self._patch():
            result = _read_users("UUID-123")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["uuid"], "UUID-123")

    def test_returns_users_from_file(self):
        from chimera.modules.pq_vless import _read_users
        self._users.write_text(json.dumps([
            {"uuid": "uuid1", "email": "a@x"},
            {"uuid": "uuid2", "email": "b@x"},
        ]))
        with self._patch():
            result = _read_users()
        self.assertEqual(len(result), 2)

    def test_returns_uuid_when_file_corrupt(self):
        from chimera.modules.pq_vless import _read_users
        self._users.write_text("{invalid")
        with self._patch():
            result = _read_users("fallback-uuid")
        self.assertEqual(result, [{"uuid": "fallback-uuid"}])

    def test_returns_uuid_fallback_when_file_empty_list(self):
        """Пустой список в users.json → fallback на primary_uuid
        (isinstance(data, list) and data — empty list falsy)."""
        from chimera.modules.pq_vless import _read_users
        self._users.write_text("[]")
        with self._patch():
            result = _read_users("fallback-uuid")
        self.assertEqual(result, [{"uuid": "fallback-uuid"}])


class TestPortIsFree(unittest.TestCase):
    """_port_is_free."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_true_when_port_free(self):
        from chimera.modules.pq_vless import _port_is_free
        # находим реально свободный порт через bind
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", 0))
        free_port = s.getsockname()[1]
        s.close()
        self.assertTrue(_port_is_free(free_port))

    def test_returns_false_when_port_taken(self):
        from chimera.modules.pq_vless import _port_is_free
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", 0))
        s.listen(1)
        taken_port = s.getsockname()[1]
        try:
            self.assertFalse(_port_is_free(taken_port))
        finally:
            s.close()

    def test_returns_true_when_ipv6_unavailable_and_port_free(self):
        """Regression: на хосте без IPv6 socket.socket(AF_INET6, ...) падает
        с OSError — _port_is_free должен пропустить IPv6 и проверить только IPv4."""
        from chimera.modules.pq_vless import _port_is_free
        # находим свободный IPv4-порт
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", 0))
        free_port = s.getsockname()[1]
        s.close()

        real_socket = socket.socket

        def _fake_socket(family, *args, **kwargs):
            if family == socket.AF_INET6:
                raise OSError("Address family not supported by protocol")
            return real_socket(family, *args, **kwargs)

        with patch("chimera.modules.pq_vless.socket.socket",
                   side_effect=_fake_socket):
            # не должно падать, IPv4-проверка проходит → True
            self.assertTrue(_port_is_free(free_port))

    def test_returns_false_when_ipv6_unavailable_and_port_taken(self):
        """Regression: на хосте без IPv6 _port_is_free всё ещё возвращает False
        для занятого IPv4-порта (не падает, корректно проверяет IPv4)."""
        from chimera.modules.pq_vless import _port_is_free
        # занимаем IPv4-порт
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", 0))
        s.listen(1)
        taken_port = s.getsockname()[1]

        real_socket = socket.socket

        def _fake_socket(family, *args, **kwargs):
            if family == socket.AF_INET6:
                raise OSError("Address family not supported by protocol")
            return real_socket(family, *args, **kwargs)

        try:
            with patch("chimera.modules.pq_vless.socket.socket",
                       side_effect=_fake_socket):
                # IPv4 занят → False, не падает на IPv6
                self.assertFalse(_port_is_free(taken_port))
        finally:
            s.close()

    def test_find_unused_port_works_without_ipv6(self):
        """Regression: find_unused_port делегирует в _port_is_free — должен
        работать на хосте без IPv6 (через фикс в _port_is_free)."""
        from chimera.modules import pq_vless
        # находим свободный IPv4-порт
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", 0))
        free_port = s.getsockname()[1]
        s.close()

        real_socket = socket.socket

        def _fake_socket(family, *args, **kwargs):
            if family == socket.AF_INET6:
                raise OSError("Address family not supported by protocol")
            return real_socket(family, *args, **kwargs)

        with patch("chimera.modules.pq_vless.socket.socket",
                   side_effect=_fake_socket):
            # не падает, возвращает свободный порт
            result = pq_vless.find_unused_port(free_port)
            self.assertIsInstance(result, int)
            self.assertGreaterEqual(result, 1)


class TestFindUnusedPort(unittest.TestCase):
    """find_unused_port."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_preferred_when_free(self):
        from chimera.modules import pq_vless
        with patch.object(pq_vless, "_port_is_free", return_value=True):
            self.assertEqual(pq_vless.find_unused_port(8443), 8443)

    def test_finds_next_free(self):
        from chimera.modules import pq_vless
        # первые 5 заняты, 6-й свободен
        with patch.object(pq_vless, "_port_is_free",
                          side_effect=[False, False, False, False, False, True]):
            self.assertEqual(pq_vless.find_unused_port(8443), 8448)

    def test_returns_preferred_when_all_taken(self):
        from chimera.modules import pq_vless
        with patch.object(pq_vless, "_port_is_free", return_value=False):
            self.assertEqual(pq_vless.find_unused_port(8443), 8443)


class TestGenShortid(unittest.TestCase):
    """_gen_shortid."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_8_hex_chars(self):
        from chimera.modules.pq_vless import _gen_shortid
        sid = _gen_shortid()
        self.assertEqual(len(sid), 8)
        self.assertTrue(all(c in "0123456789abcdef" for c in sid))

    def test_different_from_existing(self):
        from chimera.modules.pq_vless import _gen_shortid
        existing = "aabbccdd"
        # мокаем urandom чтобы первый раз вернуть existing, второй — другой
        with patch("os.urandom",
                   side_effect=[bytes.fromhex(existing), bytes.fromhex("11223344")]):
            sid = _gen_shortid(existing)
            self.assertEqual(sid, "11223344")

    def test_unique_on_multiple_calls(self):
        from chimera.modules.pq_vless import _gen_shortid
        ids = {_gen_shortid() for _ in range(10)}
        self.assertGreater(len(ids), 1)  # хотя бы 2 разных


class TestInjectPqInbound(unittest.TestCase):
    """inject_pq_inbound — мутирует cfg."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _users(self):
        return [{"uuid": "uuid1", "email": "a@x"}]

    def test_appends_when_absent(self):
        from chimera.modules.pq_vless import (
            inject_pq_inbound, PQ_TAG,
        )
        cfg = {"inbounds": []}
        changed = inject_pq_inbound(
            cfg, port=8443, decryption="dec", shortid="abcd",
            reality_dest="dest.example.com", domain="example.com",
            private_key="priv", public_key="pub", spiderx="/",
            users=self._users(),
        )
        self.assertTrue(changed)
        self.assertEqual(len(cfg["inbounds"]), 1)
        self.assertEqual(cfg["inbounds"][0]["tag"], PQ_TAG)
        self.assertEqual(cfg["inbounds"][0]["port"], 8443)

    def test_returns_false_when_identical(self):
        from chimera.modules.pq_vless import inject_pq_inbound
        cfg = {"inbounds": []}
        # первый раз — append
        inject_pq_inbound(
            cfg, port=8443, decryption="dec", shortid="abcd",
            reality_dest="dest.example.com", domain="example.com",
            private_key="priv", public_key="pub", spiderx="/",
            users=self._users(),
        )
        # второй раз — идентичный → False
        changed = inject_pq_inbound(
            cfg, port=8443, decryption="dec", shortid="abcd",
            reality_dest="dest.example.com", domain="example.com",
            private_key="priv", public_key="pub", spiderx="/",
            users=self._users(),
        )
        self.assertFalse(changed)

    def test_replaces_when_different(self):
        from chimera.modules.pq_vless import inject_pq_inbound
        cfg = {"inbounds": []}
        inject_pq_inbound(
            cfg, port=8443, decryption="dec", shortid="abcd",
            reality_dest="dest.example.com", domain="example.com",
            private_key="priv", public_key="pub", spiderx="/",
            users=self._users(),
        )
        # другой порт → замена
        changed = inject_pq_inbound(
            cfg, port=9999, decryption="dec", shortid="abcd",
            reality_dest="dest.example.com", domain="example.com",
            private_key="priv", public_key="pub", spiderx="/",
            users=self._users(),
        )
        self.assertTrue(changed)
        self.assertEqual(cfg["inbounds"][0]["port"], 9999)

    def test_empty_users_uses_placeholder_uuid(self):
        from chimera.modules.pq_vless import inject_pq_inbound
        cfg = {"inbounds": []}
        inject_pq_inbound(
            cfg, port=8443, decryption="dec", shortid="abcd",
            reality_dest="dest.example.com", domain="example.com",
            private_key="priv", public_key="pub", spiderx="/",
            users=[],
        )
        clients = cfg["inbounds"][0]["settings"]["clients"]
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0]["id"], "00000000-0000-0000-0000-000000000000")

    def test_includes_xtls_flow_when_provided(self):
        from chimera.modules.pq_vless import inject_pq_inbound
        cfg = {"inbounds": []}
        inject_pq_inbound(
            cfg, port=8443, decryption="dec", shortid="abcd",
            reality_dest="dest.example.com", domain="example.com",
            private_key="priv", public_key="pub", spiderx="/",
            users=self._users(), xtls_flow="xtls-rprx-vision",
        )
        self.assertEqual(cfg["inbounds"][0]["settings"]["clients"][0]["flow"],
                         "xtls-rprx-vision")

    def test_omits_xtls_flow_when_empty(self):
        from chimera.modules.pq_vless import inject_pq_inbound
        cfg = {"inbounds": []}
        inject_pq_inbound(
            cfg, port=8443, decryption="dec", shortid="abcd",
            reality_dest="dest.example.com", domain="example.com",
            private_key="priv", public_key="pub", spiderx="/",
            users=self._users(),
        )
        self.assertNotIn("flow", cfg["inbounds"][0]["settings"]["clients"][0])

    def test_mldsa65_seed_added_when_provided(self):
        from chimera.modules.pq_vless import inject_pq_inbound
        cfg = {"inbounds": []}
        inject_pq_inbound(
            cfg, port=8443, decryption="dec", shortid="abcd",
            reality_dest="dest.example.com", domain="example.com",
            private_key="priv", public_key="pub", spiderx="/",
            users=self._users(), mldsa65_seed="seed123",
        )
        self.assertEqual(
            cfg["inbounds"][0]["streamSettings"]["realitySettings"]["mldsa65Seed"],
            "seed123",
        )

    def test_mldsa65_seed_omitted_when_empty(self):
        from chimera.modules.pq_vless import inject_pq_inbound
        cfg = {"inbounds": []}
        inject_pq_inbound(
            cfg, port=8443, decryption="dec", shortid="abcd",
            reality_dest="dest.example.com", domain="example.com",
            private_key="priv", public_key="pub", spiderx="/",
            users=self._users(),
        )
        self.assertNotIn(
            "mldsa65Seed",
            cfg["inbounds"][0]["streamSettings"]["realitySettings"],
        )

    def test_reality_dest_priority_over_domain(self):
        from chimera.modules.pq_vless import inject_pq_inbound
        cfg = {"inbounds": []}
        inject_pq_inbound(
            cfg, port=8443, decryption="dec", shortid="abcd",
            reality_dest="dest.example.com", domain="other.com",
            private_key="priv", public_key="pub", spiderx="/",
            users=self._users(),
        )
        rs = cfg["inbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(rs["dest"], "dest.example.com:443")
        self.assertEqual(rs["serverNames"], ["dest.example.com"])

    def test_domain_used_when_no_reality_dest(self):
        from chimera.modules.pq_vless import inject_pq_inbound
        cfg = {"inbounds": []}
        inject_pq_inbound(
            cfg, port=8443, decryption="dec", shortid="abcd",
            reality_dest="", domain="example.com",
            private_key="priv", public_key="pub", spiderx="/",
            users=self._users(),
        )
        rs = cfg["inbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(rs["dest"], "example.com:443")


class TestRemovePqInbound(unittest.TestCase):
    """remove_pq_inbound."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_false_when_absent(self):
        from chimera.modules.pq_vless import remove_pq_inbound
        cfg = {"inbounds": [{"tag": "other"}]}
        self.assertFalse(remove_pq_inbound(cfg))

    def test_returns_true_when_removed(self):
        from chimera.modules.pq_vless import (
            remove_pq_inbound, inject_pq_inbound, PQ_TAG,
        )
        cfg = {"inbounds": []}
        inject_pq_inbound(
            cfg, port=8443, decryption="dec", shortid="abcd",
            reality_dest="d", domain="x", private_key="p", public_key="k",
            spiderx="/", users=[{"uuid": "u"}],
        )
        self.assertTrue(remove_pq_inbound(cfg))
        self.assertEqual(len(cfg["inbounds"]), 0)

    def test_returns_false_when_no_inbounds_key(self):
        from chimera.modules.pq_vless import remove_pq_inbound
        cfg = {}
        self.assertFalse(remove_pq_inbound(cfg))


class TestHasPqInbound(unittest.TestCase):
    """has_pq_inbound."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_false_when_no_inbounds(self):
        from chimera.modules.pq_vless import has_pq_inbound
        self.assertFalse(has_pq_inbound({}))

    def test_false_when_no_pq(self):
        from chimera.modules.pq_vless import has_pq_inbound
        cfg = {"inbounds": [{"tag": "other"}]}
        self.assertFalse(has_pq_inbound(cfg))

    def test_true_when_pq_present(self):
        from chimera.modules.pq_vless import (
            has_pq_inbound, inject_pq_inbound,
        )
        cfg = {"inbounds": []}
        inject_pq_inbound(
            cfg, port=8443, decryption="dec", shortid="abcd",
            reality_dest="d", domain="x", private_key="p", public_key="k",
            spiderx="/", users=[{"uuid": "u"}],
        )
        self.assertTrue(has_pq_inbound(cfg))


class TestBuildPqLink(unittest.TestCase):
    """_build_pq_link — генерация vless:// URL."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._users = self._tmpdir / "users.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_users(self, users_list):
        if users_list:
            self._users.write_text(json.dumps(users_list))
        return patch("chimera.modules.pq_vless.USERS_FILE", self._users)

    def test_returns_none_when_no_users(self):
        from chimera.modules.pq_vless import _build_pq_link
        with self._patch_users([]):
            result = _build_pq_link(
                {}, server_ip="1.2.3.4", domain="example.com",
                public_key="PUBKEY",
            )
        self.assertIsNone(result)

    def test_basic_link(self):
        from chimera.modules.pq_vless import _build_pq_link
        users = [{"uuid": "uuid1", "email": "a@x"}]
        with self._patch_users(users):
            result = _build_pq_link(
                {"pq_vless_encryption": "ENC",
                 "pq_vless_port": 8443,
                 "pq_vless_shortid": "abcd1234"},
                server_ip="1.2.3.4",
                domain="example.com",
                public_key="PUBKEY",
            )
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("vless://uuid1@"))
        self.assertIn("1.2.3.4:8443", result)
        self.assertIn("pbk=PUBKEY", result)
        self.assertIn("sni=example.com", result)
        self.assertIn("sid=abcd1234", result)
        self.assertIn("encryption=ENC", result)

    def test_uses_domain_when_no_server_ip(self):
        from chimera.modules.pq_vless import _build_pq_link
        with self._patch_users([{"uuid": "u1"}]):
            result = _build_pq_link(
                {"pq_vless_encryption": "ENC", "pq_vless_port": 8443,
                 "pq_vless_shortid": "abcd"},
                server_ip="", domain="vpn.example.com",
                public_key="PUB",
            )
        self.assertIn("vpn.example.com:8443", result)

    def test_includes_flow_when_provided(self):
        from chimera.modules.pq_vless import _build_pq_link
        with self._patch_users([{"uuid": "u1"}]):
            result = _build_pq_link(
                {"pq_vless_encryption": "ENC", "pq_vless_port": 8443,
                 "pq_vless_shortid": "abcd"},
                server_ip="1.2.3.4", domain="x.com", public_key="PUB",
                xtls_flow="xtls-rprx-vision",
            )
        self.assertIn("&flow=xtls-rprx-vision", result)

    def test_omits_flow_when_empty(self):
        from chimera.modules.pq_vless import _build_pq_link
        with self._patch_users([{"uuid": "u1"}]):
            result = _build_pq_link(
                {"pq_vless_encryption": "ENC", "pq_vless_port": 8443,
                 "pq_vless_shortid": "abcd"},
                server_ip="1.2.3.4", domain="x.com", public_key="PUB",
            )
        self.assertNotIn("&flow=", result)

    def test_includes_mldsa65_verify_when_enabled(self):
        from chimera.modules.pq_vless import _build_pq_link
        with self._patch_users([{"uuid": "u1"}]):
            result = _build_pq_link(
                {"pq_vless_encryption": "ENC", "pq_vless_port": 8443,
                 "pq_vless_shortid": "abcd",
                 "pq_vless_mldsa65_enabled": True,
                 "pq_vless_mldsa65_verify": "VERIFY123"},
                server_ip="1.2.3.4", domain="x.com", public_key="PUB",
            )
        self.assertIn("&mldsa65Verify=VERIFY123", result)

    def test_omits_mldsa65_verify_when_disabled(self):
        from chimera.modules.pq_vless import _build_pq_link
        with self._patch_users([{"uuid": "u1"}]):
            result = _build_pq_link(
                {"pq_vless_encryption": "ENC", "pq_vless_port": 8443,
                 "pq_vless_shortid": "abcd",
                 "pq_vless_mldsa65_enabled": False,
                 "pq_vless_mldsa65_verify": "VERIFY123"},
                server_ip="1.2.3.4", domain="x.com", public_key="PUB",
            )
        self.assertNotIn("mldsa65Verify", result)

    def test_country_flag_in_label(self):
        from chimera.modules.pq_vless import _build_pq_link
        import urllib.parse
        with self._patch_users([{"uuid": "u1"}]):
            result = _build_pq_link(
                {"pq_vless_encryption": "ENC", "pq_vless_port": 8443,
                 "pq_vless_shortid": "abcd"},
                server_ip="1.2.3.4", domain="x.com", public_key="PUB",
                country_flag="🇷🇺",
            )
        # label после #
        label = result.split("#", 1)[1]
        decoded = urllib.parse.unquote(label)
        self.assertIn("🇷🇺", decoded)

    def test_no_flag_prefix_for_globe(self):
        """Флаг '🌐' (глобус) — без префикса в label."""
        from chimera.modules.pq_vless import _build_pq_link
        import urllib.parse
        with self._patch_users([{"uuid": "u1"}]):
            result = _build_pq_link(
                {"pq_vless_encryption": "ENC", "pq_vless_port": 8443,
                 "pq_vless_shortid": "abcd"},
                server_ip="1.2.3.4", domain="x.com", public_key="PUB",
                country_flag="🌐",
            )
        label = urllib.parse.unquote(result.split("#", 1)[1])
        self.assertNotIn("🌐", label)


if __name__ == "__main__":
    unittest.main(verbosity=2)
