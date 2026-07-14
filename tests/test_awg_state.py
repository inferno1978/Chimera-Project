#!/usr/bin/env python3
"""
tests/test_awg_state.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/awg_state.py.

Покрывает:
  1. awgs_state_load / awgs_state_save — JSON state с chmod 0o600
  2. awgs_state_update — partial merge
  3. awgs_state_init — initial state при первой установке
  4. Peers management: add/remove/find/update
  5. IP allocation: awgs_state_next_ip / awgs_state_next_ipv6
  6. Cascade: awgs_state_set_cascade_role
  7. Helpers: is_installed / get_params / get_endpoint / ...
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timezone
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


class TestStateLoadSave(unittest.TestCase):
    """awgs_state_load / awgs_state_save."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._state_file = Path(self._tmpdir) / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state_file(self):
        return patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                     self._state_file)

    def test_load_returns_empty_dict_when_no_file(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            self.assertEqual(awg_state.awgs_state_load(), {})

    def test_load_returns_empty_dict_on_corrupt_json(self):
        from chimera.modules import awg_state
        self._state_file.write_text("{invalid json!!!")
        with self._patch_state_file():
            self.assertEqual(awg_state.awgs_state_load(), {})

    def test_load_returns_state_dict(self):
        from chimera.modules import awg_state
        data = {"installed": True, "port": 51820, "peers": []}
        self._state_file.write_text(json.dumps(data))
        with self._patch_state_file():
            loaded = awg_state.awgs_state_load()
            self.assertTrue(loaded["installed"])
            self.assertEqual(loaded["port"], 51820)

    def test_save_writes_json(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            ok = awg_state.awgs_state_save({"installed": True, "port": 8443})
            self.assertTrue(ok)
            data = json.loads(self._state_file.read_text())
            self.assertEqual(data["port"], 8443)

    def test_save_sets_chmod_600(self):
        """State содержит приватные ключи → 0o600."""
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_save({"installed": True})
            mode = stat.S_IMODE(os.stat(self._state_file).st_mode)
            self.assertEqual(mode, 0o600)

    def test_save_creates_parent_dir(self):
        from chimera.modules import awg_state
        nested = Path(self._tmpdir) / "subdir" / "state.json"
        with patch("chimera.modules.awg_state.AWGS_STATE_FILE", nested):
            # mkdir в _core патчится, но awg_state_save использует AWGS_STATE_FILE.parent.mkdir
            # напрямую — должно работать
            ok = awg_state.awgs_state_save({"installed": True})
            self.assertTrue(ok)
            self.assertTrue(nested.exists())


class TestStateUpdate(unittest.TestCase):
    """awgs_state_update — merge top-level keys."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._state_file = Path(self._tmpdir) / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state_file(self):
        return patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                     self._state_file)

    def test_merges_new_keys(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_save({"installed": True, "port": 51820})
            state = awg_state.awgs_state_update(carrier_preset="mobile")
            self.assertEqual(state["carrier_preset"], "mobile")
            # существующие ключи сохраняются
            self.assertEqual(state["port"], 51820)

    def test_overwrites_existing_keys(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_save({"port": 51820})
            state = awg_state.awgs_state_update(port=8443)
            self.assertEqual(state["port"], 8443)

    def test_creates_state_when_missing(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            state = awg_state.awgs_state_update(installed=True)
            self.assertTrue(state["installed"])
            self.assertTrue(self._state_file.exists())


class TestStateInit(unittest.TestCase):
    """awgs_state_init — создание начального state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._state_file = Path(self._tmpdir) / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state_file(self):
        return patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                     self._state_file)

    def test_creates_full_state(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            state = awg_state.awgs_state_init(
                server_privkey="priv", server_pubkey="pub",
                port=51820, endpoint="1.2.3.4",
            )
            self.assertTrue(state["installed"])
            self.assertEqual(state["version"], "1.0.0")
            self.assertEqual(state["interface"], "awg0")
            self.assertEqual(state["port"], 51820)
            self.assertEqual(state["endpoint"], "1.2.3.4")
            self.assertEqual(state["server_privkey"], "priv")
            self.assertEqual(state["server_pubkey"], "pub")
            self.assertEqual(state["peers"], [])
            self.assertEqual(state["cascade_role"], "")

    def test_installed_at_is_iso(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            state = awg_state.awgs_state_init("priv", "pub")
            # должно парситься как ISO
            dt = datetime.fromisoformat(state["installed_at"])
            self.assertIsNotNone(dt.tzinfo)

    def test_default_params_used_when_none(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            state = awg_state.awgs_state_init("priv", "pub")
            self.assertIn("jc", state["params"])
            self.assertIn("h1", state["params"])

    def test_custom_params_override(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            custom = {"jc": 9, "jmin": 50, "jmax": 200}
            state = awg_state.awgs_state_init(
                "priv", "pub", params=custom,
            )
            self.assertEqual(state["params"]["jc"], 9)


class TestPeersManagement(unittest.TestCase):
    """Peers CRUD."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._state_file = Path(self._tmpdir) / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state_file(self):
        return patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                     self._state_file)

    def _init_state(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_init("priv", "pub")

    def test_peer_add(self):
        from chimera.modules import awg_state
        self._init_state()
        with self._patch_state_file():
            ok = awg_state.awgs_state_peer_add({
                "name": "alice", "client_ip": "10.66.66.2",
            })
            self.assertTrue(ok)
            peers = awg_state.awgs_state_peers_get()
            self.assertEqual(len(peers), 1)
            self.assertEqual(peers[0]["name"], "alice")

    def test_peer_add_duplicate_returns_false(self):
        from chimera.modules import awg_state
        self._init_state()
        with self._patch_state_file():
            awg_state.awgs_state_peer_add({"name": "alice"})
            ok = awg_state.awgs_state_peer_add({"name": "alice"})
            self.assertFalse(ok)

    def test_peer_remove(self):
        from chimera.modules import awg_state
        self._init_state()
        with self._patch_state_file():
            awg_state.awgs_state_peer_add({"name": "alice"})
            removed = awg_state.awgs_state_peer_remove("alice")
            self.assertIsNotNone(removed)
            self.assertEqual(removed["name"], "alice")
            self.assertEqual(awg_state.awgs_state_peers_get(), [])

    def test_peer_remove_unknown_returns_none(self):
        from chimera.modules import awg_state
        self._init_state()
        with self._patch_state_file():
            self.assertIsNone(awg_state.awgs_state_peer_remove("nobody"))

    def test_peer_find(self):
        from chimera.modules import awg_state
        self._init_state()
        with self._patch_state_file():
            awg_state.awgs_state_peer_add({"name": "alice", "client_ip": "10.66.66.2"})
            p = awg_state.awgs_state_peer_find("alice")
            self.assertIsNotNone(p)
            self.assertEqual(p["client_ip"], "10.66.66.2")
            self.assertIsNone(awg_state.awgs_state_peer_find("nobody"))

    def test_peer_update(self):
        from chimera.modules import awg_state
        self._init_state()
        with self._patch_state_file():
            awg_state.awgs_state_peer_add({"name": "alice", "client_ip": "10.66.66.2"})
            ok = awg_state.awgs_state_peer_update("alice", client_ip="10.66.66.5")
            self.assertTrue(ok)
            p = awg_state.awgs_state_peer_find("alice")
            self.assertEqual(p["client_ip"], "10.66.66.5")

    def test_peer_update_unknown_returns_false(self):
        from chimera.modules import awg_state
        self._init_state()
        with self._patch_state_file():
            ok = awg_state.awgs_state_peer_update("nobody", client_ip="x")
            self.assertFalse(ok)

    def test_find_peer_by_owner(self):
        from chimera.modules import awg_state
        self._init_state()
        with self._patch_state_file():
            awg_state.awgs_state_peer_add({
                "name": "alice", "owner_email": "alice@example.com",
            })
            p = awg_state.awgs_state_find_peer_by_owner("alice@example.com")
            self.assertIsNotNone(p)
            self.assertEqual(p["name"], "alice")
            self.assertIsNone(awg_state.awgs_state_find_peer_by_owner("nobody@example.com"))

    def test_find_peer_by_owner_empty_email_returns_none(self):
        from chimera.modules import awg_state
        self._init_state()
        with self._patch_state_file():
            awg_state.awgs_state_peer_add({"name": "alice", "owner_email": ""})
            self.assertIsNone(awg_state.awgs_state_find_peer_by_owner(""))


class TestEnsurePeerOwnerField(unittest.TestCase):
    """awgs_state_ensure_peer_owner_field — миграция."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._state_file = Path(self._tmpdir) / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state_file(self):
        return patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                     self._state_file)

    def test_adds_owner_email_when_missing(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_save({
                "installed": True,
                "peers": [{"name": "alice"}, {"name": "bob", "owner_email": "bob@x"}],
            })
            awg_state.awgs_state_ensure_peer_owner_field()
            peers = awg_state.awgs_state_peers_get()
            self.assertEqual(peers[0].get("owner_email"), "")
            self.assertEqual(peers[1].get("owner_email"), "bob@x")

    def test_idempotent_when_already_present(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_save({
                "installed": True,
                "peers": [{"name": "alice", "owner_email": "a@x"}],
            })
            awg_state.awgs_state_ensure_peer_owner_field()
            awg_state.awgs_state_ensure_peer_owner_field()
            peers = awg_state.awgs_state_peers_get()
            self.assertEqual(peers[0]["owner_email"], "a@x")

    def test_no_op_when_no_peers(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_save({"installed": True, "peers": []})
            awg_state.awgs_state_ensure_peer_owner_field()
            self.assertEqual(awg_state.awgs_state_peers_get(), [])


class TestIpAllocation(unittest.TestCase):
    """awgs_state_next_ip / awgs_state_next_ipv6."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._state_file = Path(self._tmpdir) / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state_file(self):
        return patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                     self._state_file)

    def test_next_ip_returns_2_when_empty(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_init("priv", "pub")
            ip = awg_state.awgs_state_next_ip()
            self.assertEqual(ip, "10.66.66.2")

    def test_next_ip_skips_used(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_init("priv", "pub")
            awg_state.awgs_state_peer_add({"name": "alice", "client_ip": "10.66.66.2"})
            awg_state.awgs_state_peer_add({"name": "bob", "client_ip": "10.66.66.3"})
            ip = awg_state.awgs_state_next_ip()
            self.assertEqual(ip, "10.66.66.4")

    def test_next_ip_with_custom_subnet(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_save({"installed": True, "peers": []})
            ip = awg_state.awgs_state_next_ip("10.99.99.0/24")
            self.assertEqual(ip, "10.99.99.2")

    def test_next_ip_invalid_subnet_returns_none(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_save({"installed": True, "peers": []})
            self.assertIsNone(awg_state.awgs_state_next_ip("invalid"))

    def test_next_ipv6_returns_2_when_empty(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_init("priv", "pub")
            ip = awg_state.awgs_state_next_ipv6()
            self.assertEqual(ip, "fd66:66:66::2")

    def test_next_ipv6_skips_used(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_init("priv", "pub")
            awg_state.awgs_state_peer_add({
                "name": "alice", "client_ipv6": "fd66:66:66::2",
            })
            ip = awg_state.awgs_state_next_ipv6()
            self.assertEqual(ip, "fd66:66:66::3")


class TestCascadeRole(unittest.TestCase):
    """awgs_state_set_cascade_role."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._state_file = Path(self._tmpdir) / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state_file(self):
        return patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                     self._state_file)

    def test_entry_role(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_init("priv", "pub")
            ok = awg_state.awgs_state_set_cascade_role(
                "entry", cascade_peer_host="1.2.3.4",
            )
            self.assertTrue(ok)
            state = awg_state.awgs_state_load()
            self.assertEqual(state["cascade_role"], "entry")
            self.assertEqual(state["cascade_peer_host"], "1.2.3.4")

    def test_exit_role(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_init("priv", "pub")
            ok = awg_state.awgs_state_set_cascade_role("exit")
            self.assertTrue(ok)

    def test_empty_role_resets(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_init("priv", "pub")
            awg_state.awgs_state_set_cascade_role("entry")
            ok = awg_state.awgs_state_set_cascade_role("")
            self.assertTrue(ok)
            self.assertEqual(
                awg_state.awgs_state_load()["cascade_role"], ""
            )

    def test_invalid_role_returns_false(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_init("priv", "pub")
            ok = awg_state.awgs_state_set_cascade_role("invalid")
            self.assertFalse(ok)


class TestHelpers(unittest.TestCase):
    """Простые getter'ы."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = tempfile.mkdtemp()
        self._state_file = Path(self._tmpdir) / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state_file(self):
        return patch("chimera.modules.awg_state.AWGS_STATE_FILE",
                     self._state_file)

    def test_is_installed_false_when_no_state(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            self.assertFalse(awg_state.awgs_state_is_installed())

    def test_is_installed_true_after_init(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_init("priv", "pub")
            self.assertTrue(awg_state.awgs_state_is_installed())

    def test_get_params_returns_defaults_when_empty(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            params = awg_state.awgs_state_get_params()
            self.assertIn("jc", params)
            self.assertIn("h1", params)

    def test_get_endpoint_prefers_endpoint_host(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_save({
                "endpoint": "1.1.1.1", "endpoint_host": "vpn.example.com",
            })
            self.assertEqual(awg_state.awgs_state_get_endpoint(), "vpn.example.com")

    def test_get_endpoint_fallback_to_endpoint(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_save({"endpoint": "1.1.1.1"})
            self.assertEqual(awg_state.awgs_state_get_endpoint(), "1.1.1.1")

    def test_get_server_pubkey(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            awg_state.awgs_state_init("priv", "PUBKEY")
            self.assertEqual(awg_state.awgs_state_get_server_pubkey(), "PUBKEY")

    def test_get_port_returns_default_when_empty(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            self.assertEqual(awg_state.awgs_state_get_port(), 51820)

    def test_get_subnet_returns_default_when_empty(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            self.assertEqual(
                awg_state.awgs_state_get_subnet(), "10.66.66.0/24",
            )

    def test_get_mtu_returns_default_when_empty(self):
        from chimera.modules import awg_state
        with self._patch_state_file():
            self.assertEqual(awg_state.awgs_state_get_mtu(), 1280)


if __name__ == "__main__":
    unittest.main(verbosity=2)
