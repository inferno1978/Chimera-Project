#!/usr/bin/env python3
"""
tests/test_cluster_ops.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/cluster_ops.py.

Покрывает:
  1. _find_ssh_key — поиск SSH ключа
  2. _has_sshpass — проверка sshpass
  3. _ssh_base_opts / _ssh_opts_key / _ssh_opts_pass — SSH опции
  4. load_exit_nodes — чтение chain_nodes из state
  5. NodeResult — dataclass
"""
from __future__ import annotations

import json
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


class TestFindSshKey(unittest.TestCase):
    """_find_ssh_key — поиск SSH ключа."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_none_when_no_keys(self):
        from chimera.modules.cluster_ops import _find_ssh_key
        with patch("pathlib.Path.exists", return_value=False):
            self.assertIsNone(_find_ssh_key())

    def test_returns_path_when_key_exists(self):
        from chimera.modules.cluster_ops import _find_ssh_key
        def _fake_exists(self):
            return "id_ed25519" in str(self)
        with patch.object(Path, "exists", _fake_exists):
            result = _find_ssh_key()
        self.assertIsNotNone(result)
        self.assertIn("id_ed25519", result)


class TestHasSshpass(unittest.TestCase):
    """_has_sshpass."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_true_when_found(self):
        from chimera.modules.cluster_ops import _has_sshpass
        with patch("shutil.which", return_value="/usr/bin/sshpass"):
            self.assertTrue(_has_sshpass())

    def test_returns_false_when_not_found(self):
        from chimera.modules.cluster_ops import _has_sshpass
        with patch("shutil.which", return_value=None):
            self.assertFalse(_has_sshpass())


class TestSshBaseOpts(unittest.TestCase):
    """_ssh_base_opts — базовые SSH опции."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_list_starting_with_ssh(self):
        from chimera.modules.cluster_ops import _ssh_base_opts
        opts = _ssh_base_opts()
        self.assertEqual(opts[0], "ssh")

    def test_includes_strict_host_key_checking_no(self):
        from chimera.modules.cluster_ops import _ssh_base_opts
        opts = _ssh_base_opts()
        self.assertIn("StrictHostKeyChecking=no", opts)

    def test_includes_connect_timeout(self):
        from chimera.modules.cluster_ops import _ssh_base_opts, _CONN_TIMEOUT
        opts = _ssh_base_opts()
        # ConnectTimeout=N — это один элемент списка
        timeout_str = f"ConnectTimeout={_CONN_TIMEOUT}"
        self.assertIn(timeout_str, opts)

    def test_includes_user_known_hosts_file_devnull(self):
        from chimera.modules.cluster_ops import _ssh_base_opts
        opts = _ssh_base_opts()
        self.assertIn("UserKnownHostsFile=/dev/null", opts)


class TestSshOptsKey(unittest.TestCase):
    """_ssh_opts_key — SSH опции с ключом."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_includes_batch_mode(self):
        from chimera.modules.cluster_ops import _ssh_opts_key
        opts = _ssh_opts_key()
        self.assertIn("BatchMode=yes", opts)

    def test_includes_identity_file_when_provided(self):
        from chimera.modules.cluster_ops import _ssh_opts_key
        opts = _ssh_opts_key(ssh_key="/path/to/key")
        self.assertIn("-i", opts)
        self.assertIn("/path/to/key", opts)

    def test_no_identity_file_when_none(self):
        from chimera.modules.cluster_ops import _ssh_opts_key
        with patch("chimera.modules.cluster_ops._find_ssh_key", return_value=None):
            opts = _ssh_opts_key()
        self.assertNotIn("-i", opts)


class TestSshOptsPass(unittest.TestCase):
    """_ssh_opts_pass — SSH опции с паролем."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_includes_password_auth(self):
        from chimera.modules.cluster_ops import _ssh_opts_pass
        opts = _ssh_opts_pass()
        self.assertIn("PreferredAuthentications=password", opts)
        self.assertIn("PubkeyAuthentication=no", opts)


class TestLoadExitNodes(unittest.TestCase):
    """load_exit_nodes — чтение chain_nodes из state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.cluster_ops._STATE_FILE", self._state)

    def test_returns_empty_when_no_file(self):
        from chimera.modules.cluster_ops import load_exit_nodes
        with self._patch():
            self.assertEqual(load_exit_nodes(), [])

    def test_returns_empty_on_corrupt(self):
        from chimera.modules.cluster_ops import load_exit_nodes
        self._state.write_text("{invalid")
        with self._patch():
            self.assertEqual(load_exit_nodes(), [])

    def test_returns_chain_nodes(self):
        from chimera.modules.cluster_ops import load_exit_nodes
        self._state.write_text(json.dumps({
            "chain_nodes": [{"host": "1.1.1.1", "port": 443},
                            {"host": "2.2.2.2", "port": 8443}],
        }))
        with self._patch():
            result = load_exit_nodes()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["host"], "1.1.1.1")

    def test_returns_legacy_single_host(self):
        from chimera.modules.cluster_ops import load_exit_nodes
        self._state.write_text(json.dumps({
            "chain_exit_host": "3.3.3.3",
            "chain_exit_port": 443,
        }))
        with self._patch():
            result = load_exit_nodes()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["host"], "3.3.3.3")

    def test_filters_nodes_without_host(self):
        from chimera.modules.cluster_ops import load_exit_nodes
        self._state.write_text(json.dumps({
            "chain_nodes": [{"host": "1.1.1.1"}, {"host": ""}, {"other": "x"}],
        }))
        with self._patch():
            result = load_exit_nodes()
        self.assertEqual(len(result), 1)


class TestNodeResult(unittest.TestCase):
    """NodeResult — dataclass."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_defaults(self):
        from chimera.modules.cluster_ops import NodeResult
        nr = NodeResult(host="1.2.3.4", ok=False)
        self.assertEqual(nr.host, "1.2.3.4")
        self.assertFalse(nr.ok)
        self.assertEqual(nr.output, "")
        self.assertEqual(nr.error, "")
        self.assertEqual(nr.duration, 0.0)

    def test_with_values(self):
        from chimera.modules.cluster_ops import NodeResult
        nr = NodeResult(host="1.2.3.4", ok=True, output="success",
                        error="", duration=1.5)
        self.assertTrue(nr.ok)
        self.assertEqual(nr.output, "success")
        self.assertEqual(nr.duration, 1.5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
