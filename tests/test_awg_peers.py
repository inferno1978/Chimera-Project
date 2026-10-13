#!/usr/bin/env python3
"""
tests/test_awg_peers.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/awg_peers.py.

Покрывает:
  1. _validate_peer_name — валидация имени пира
  2. _validate_email — валидация email
  3. _format_bytes — форматирование байт
  4. _format_handshake — форматирование времени handshake
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
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


class TestValidatePeerName(unittest.TestCase):
    """_validate_peer_name — валидация имени пира."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_valid_name(self):
        from chimera.modules.awg_peers import _validate_peer_name
        self.assertTrue(_validate_peer_name("alice"))
        self.assertTrue(_validate_peer_name("bob123"))
        self.assertTrue(_validate_peer_name("user-name"))
        self.assertTrue(_validate_peer_name("user_name"))

    def test_empty_invalid(self):
        from chimera.modules.awg_peers import _validate_peer_name
        self.assertFalse(_validate_peer_name(""))

    def test_starts_with_digit_invalid(self):
        from chimera.modules.awg_peers import _validate_peer_name
        self.assertFalse(_validate_peer_name("1alice"))
        self.assertFalse(_validate_peer_name("123"))

    def test_contains_space_invalid(self):
        from chimera.modules.awg_peers import _validate_peer_name
        self.assertFalse(_validate_peer_name("alice bob"))

    def test_too_long_invalid(self):
        from chimera.modules.awg_peers import _validate_peer_name
        self.assertFalse(_validate_peer_name("a" * 33))

    def test_max_length_valid(self):
        from chimera.modules.awg_peers import _validate_peer_name
        self.assertTrue(_validate_peer_name("a" * 32))

    def test_unicode_invalid(self):
        from chimera.modules.awg_peers import _validate_peer_name
        self.assertFalse(_validate_peer_name("алиса"))

    def test_special_chars_invalid(self):
        from chimera.modules.awg_peers import _validate_peer_name
        self.assertFalse(_validate_peer_name("alice@bob"))
        self.assertFalse(_validate_peer_name("alice.bob"))


class TestValidateEmail(unittest.TestCase):
    """_validate_email — валидация email."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_returns_true(self):
        """Пустой email — валиден (технический пир)."""
        from chimera.modules.awg_peers import _validate_email
        self.assertTrue(_validate_email(""))

    def test_valid_email(self):
        from chimera.modules.awg_peers import _validate_email
        self.assertTrue(_validate_email("alice@example.com"))
        self.assertTrue(_validate_email("bob@sub.example.com"))

    def test_invalid_no_at(self):
        from chimera.modules.awg_peers import _validate_email
        self.assertFalse(_validate_email("aliceexample.com"))

    def test_invalid_no_dot_after_at(self):
        from chimera.modules.awg_peers import _validate_email
        self.assertFalse(_validate_email("alice@example"))

    def test_invalid_with_space(self):
        from chimera.modules.awg_peers import _validate_email
        self.assertFalse(_validate_email("alice @example.com"))


class TestFormatBytes(unittest.TestCase):
    """_format_bytes — форматирование байт."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_zero(self):
        from chimera.modules.awg_peers import _format_bytes
        self.assertEqual(_format_bytes(0), "0 B")

    def test_kib(self):
        from chimera.modules.awg_peers import _format_bytes
        self.assertEqual(_format_bytes(1024), "1.0 KiB")

    def test_mib(self):
        from chimera.modules.awg_peers import _format_bytes
        self.assertEqual(_format_bytes(1024 ** 2), "1.0 MiB")

    def test_gib(self):
        from chimera.modules.awg_peers import _format_bytes
        self.assertEqual(_format_bytes(1024 ** 3), "1.0 GiB")

    def test_tib(self):
        from chimera.modules.awg_peers import _format_bytes
        self.assertEqual(_format_bytes(1024 ** 4), "1.0 TiB")

    def test_petabytes_fallback(self):
        from chimera.modules.awg_peers import _format_bytes
        result = _format_bytes(1024 ** 5)
        self.assertIn("PiB", result)


class TestFormatHandshake(unittest.TestCase):
    """_format_handshake — форматирование времени handshake."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_returns_nikogda(self):
        from chimera.modules.awg_peers import _format_handshake
        self.assertEqual(_format_handshake(""), "никогда")

    def test_zero_returns_nikogda(self):
        from chimera.modules.awg_peers import _format_handshake
        self.assertEqual(_format_handshake("0"), "никогда")

    def test_recent_seconds(self):
        from chimera.modules.awg_peers import _format_handshake
        recent = str(int(time.time()) - 30)  # 30 секунд назад
        result = _format_handshake(recent)
        self.assertIn("сек", result)

    def test_minutes_ago(self):
        from chimera.modules.awg_peers import _format_handshake
        recent = str(int(time.time()) - 5 * 60)  # 5 минут назад
        result = _format_handshake(recent)
        self.assertIn("мин", result)

    def test_hours_ago(self):
        from chimera.modules.awg_peers import _format_handshake
        recent = str(int(time.time()) - 3 * 3600)  # 3 часа назад
        result = _format_handshake(recent)
        self.assertIn("ч", result)

    def test_days_ago(self):
        from chimera.modules.awg_peers import _format_handshake
        recent = str(int(time.time()) - 2 * 86400)  # 2 дня назад
        result = _format_handshake(recent)
        self.assertIn("дн", result)

    def test_invalid_returns_input(self):
        """Невалидный timestamp — возвращается исходная строка."""
        from chimera.modules.awg_peers import _format_handshake
        result = _format_handshake("not_a_number")
        # функция не должна падать
        self.assertIsInstance(result, str)


_PARAMS_20 = {
    "jc": 5, "jmin": 86, "jmax": 287,
    "s1": 75, "s2": 125, "s3": 54, "s4": 25,
    "h1": 1106297626, "h2": 888479848,
    "h3": 125665432, "h4": 1802677046,
}


class TestPeerRebuildNoCascadeResidue(unittest.TestCase):
    """awg_peer_rebuild_conf — LB-residue guard (регрессия 13.10.2026).

    При cascade_role='entry' + legacy-зеркале cascade_peer_* в state
    rebuild НЕ должен рендерить [Peer] "# cascade exit peer" в awg0.conf:
    связь с exit обеспечивают отдельные интерфейсы awg1/awg2/awg3
    (awg_cascade multiexit/LB), а пир в awg0 никогда не хендшейкался
    (0 B rx, вечные retry в пустоту — инцидент с мёртвым пиром
    198.51.100.49:52831 на awg0 всех трёх нод RU-каскада).
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def _state(self):
        return {
            "installed": True,
            "server_privkey": "PRIV",
            "server_pubkey": "PUB",
            "port": 45915,
            "subnet": "172.16.82.0/24",
            "subnet_v6": "fd66:66:82::/64",
            "mtu": 1280,
            "params": dict(_PARAMS_20),
            "peers": [
                {
                    "name": "user-main",
                    "client_pubkey": "CLIENT_PUBKEY",
                    "client_ip": "172.16.82.2",
                    "client_ipv6": "fd66:66:82::2",
                },
            ],
            "endpoint_host": "203.0.113.238",
            "protocol_version": "2.0",
            # legacy-зеркало каскада — присутствует в state, читается
            # role-потребителями, но в awg0.conf рендериться НЕ должно
            "cascade_role": "entry",
            "cascade_peer_host": "198.51.100.49",
            "cascade_peer_port": 52831,
            "cascade_peer_pubkey": "DEAD_PEER_PUBKEY",
            "cascade_peer_privkey": "DEAD_PEER_PRIVKEY",
            "cascade_subnet": "172.16.91.0/24",
            "cascade_active_exit": "de",
        }

    def test_rebuild_no_cascade_peer_in_conf(self):
        from chimera.modules import awg_peers
        state = self._state()
        with patch.object(awg_peers, "awgs_state_load",
                          return_value=state), \
             patch.object(awg_peers, "awgs_write_server_conf",
                          return_value=True) as mock_write, \
             patch.object(awg_peers, "awgs_apply", return_value=True):
            ok = awg_peers.awg_peer_rebuild_conf(apply=True)
            self.assertTrue(ok)
        written = mock_write.call_args.args[0]
        # LB-residue: каскадное зеркало НЕ попало в awg0.conf
        self.assertNotIn("# cascade exit peer", written)
        self.assertNotIn("DEAD_PEER_PUBKEY", written)
        self.assertNotIn("198.51.100.49", written)
        self.assertNotIn("172.16.91.0/24", written)
        self.assertNotIn("PersistentKeepalive = 25", written)
        # клиентские пиры — на месте, конфиг не оголён
        self.assertIn("# user-main", written)
        self.assertIn("CLIENT_PUBKEY", written)
        self.assertIn("172.16.82.2/32", written)
        self.assertIn("fd66:66:82::2/128", written)

    def test_rebuild_standalone_state_unchanged(self):
        """cascade_role='' (standalone без каскада) — rebuild работает как раньше."""
        from chimera.modules import awg_peers
        state = self._state()
        state["cascade_role"] = ""
        for k in ("cascade_peer_host", "cascade_peer_port",
                  "cascade_peer_pubkey", "cascade_peer_privkey",
                  "cascade_subnet", "cascade_active_exit"):
            state[k] = ""
        with patch.object(awg_peers, "awgs_state_load",
                          return_value=state), \
             patch.object(awg_peers, "awgs_write_server_conf",
                          return_value=True) as mock_write, \
             patch.object(awg_peers, "awgs_apply", return_value=True):
            ok = awg_peers.awg_peer_rebuild_conf(apply=True)
            self.assertTrue(ok)
        written = mock_write.call_args.args[0]
        self.assertIn("# user-main", written)
        self.assertIn("CLIENT_PUBKEY", written)


if __name__ == "__main__":
    unittest.main(verbosity=2)
