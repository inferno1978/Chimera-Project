#!/usr/bin/env python3
"""
tests/test_hysteria2_salamander.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/hysteria2_salamander.py.

Покрывает:
  1. _generate_salamander_password — формат/длина/энтропия
  2. _has_obfs_block / _inject_obfs / _strip_obfs — YAML-патчер
  3. _build_obfs_block — структура блока
  4. Идемпотентность inject (повторный inject не дублирует блок)
  5. _load_salamander_state / _save_salamander_state — JSON I/O
  6. _ensure_salamander_state — гарантирует наличие подсекции
  7. h2_salamander_status — структура возвращаемого dict
  8. _apply_obfs_to_client — запись/чтение client.yaml
  9. Семантика YAML (если установлен PyYAML)
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    """Загружает _core.py в sys.modules, чтобы импорты hysteria2_* сработали."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("chimera._core")
    m.__dict__.update(g)
    sys.modules["chimera._core"] = m


# ─────────────────────────────────────────────────────────────────────────────
# 1. Генерация пароля
# ─────────────────────────────────────────────────────────────────────────────

class TestGeneratePassword(unittest.TestCase):
    """_generate_salamander_password — формат/энтропия."""

    def setUp(self):
        _setup_core()

    def test_returns_string(self):
        from chimera.modules.hysteria2_salamander import (
            _generate_salamander_password,
        )
        pw = _generate_salamander_password()
        self.assertIsInstance(pw, str)

    def test_length_is_64_chars(self):
        """32 байта в hex = 64 символа — криптостойкость."""
        from chimera.modules.hysteria2_salamander import (
            _generate_salamander_password,
        )
        pw = _generate_salamander_password()
        self.assertEqual(len(pw), 64)

    def test_is_hex(self):
        from chimera.modules.hysteria2_salamander import (
            _generate_salamander_password,
        )
        pw = _generate_salamander_password()
        self.assertRegex(pw, r'^[0-9a-f]{64}$')

    def test_two_calls_differ(self):
        """Два вызова должны давать разные пароли (энтропия)."""
        from chimera.modules.hysteria2_salamander import (
            _generate_salamander_password,
        )
        a = _generate_salamander_password()
        b = _generate_salamander_password()
        self.assertNotEqual(a, b)


# ─────────────────────────────────────────────────────────────────────────────
# 2. YAML-патчер: _has_obfs_block / _inject_obfs / _strip_obfs
# ─────────────────────────────────────────────────────────────────────────────

_SAMPLE_CLIENT_YAML = """\
# Hysteria2 client config
server: 1.2.3.4:443

auth: mypassword

tls:
  insecure: true
  pinSHA256: abc123def456

socks5:
  listen: 127.0.0.1:10809

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
"""

_SAMPLE_SERVER_YAML = """\
# Hysteria2 server config
listen: "0.0.0.0:443"

tls:
  cert: /etc/xray/hysteria.crt
  key: /etc/xray/hysteria.key

auth:
  type: password
  password: mypassword

masquerade:
  type: proxy
  proxy:
    url: https://news.ycombinator.com
    rewriteHost: true

quic:
  initStreamReceiveWindow: 8388608
"""


class TestHasObfsBlock(unittest.TestCase):
    """_has_obfs_block — детекция существующей секции obfs."""

    def setUp(self):
        _setup_core()

    def test_returns_false_for_plain_yaml(self):
        from chimera.modules.hysteria2_salamander import _has_obfs_block
        self.assertFalse(_has_obfs_block(_SAMPLE_CLIENT_YAML))

    def test_returns_true_after_inject(self):
        from chimera.modules.hysteria2_salamander import (
            _has_obfs_block, _inject_obfs,
        )
        injected = _inject_obfs(_SAMPLE_CLIENT_YAML, "mypassword")
        self.assertTrue(_has_obfs_block(injected))

    def test_returns_false_for_empty(self):
        from chimera.modules.hysteria2_salamander import _has_obfs_block
        self.assertFalse(_has_obfs_block(""))

    def test_does_not_match_substring(self):
        """Строка `obfs:` в комментарии не должна считаться секцией."""
        from chimera.modules.hysteria2_salamander import _has_obfs_block
        # Строка с `obfs:` но не в начале — не валидная YAML-секция
        bad = "# comment about obfs: not a real section\nserver: 1.2.3.4\n"
        self.assertFalse(_has_obfs_block(bad))


class TestInjectObfs(unittest.TestCase):
    """_inject_obfs — вставка секции obfs."""

    def setUp(self):
        _setup_core()

    def test_adds_obfs_block_at_end(self):
        from chimera.modules.hysteria2_salamander import (
            _inject_obfs, _has_obfs_block,
        )
        out = _inject_obfs(_SAMPLE_CLIENT_YAML, "secret123")
        self.assertTrue(_has_obfs_block(out))
        # Пресет-структура
        self.assertIn("obfs:", out)
        self.assertIn("type: salamander", out)
        self.assertIn("salamander:", out)
        self.assertIn("password: secret123", out)

    def test_preserves_original_content(self):
        from chimera.modules.hysteria2_salamander import _inject_obfs
        out = _inject_obfs(_SAMPLE_CLIENT_YAML, "pw")
        # Все исходные строки сохранены
        self.assertIn("server: 1.2.3.4:443", out)
        self.assertIn("auth: mypassword", out)
        self.assertIn("pinSHA256: abc123def456", out)
        self.assertIn("initStreamReceiveWindow: 8388608", out)

    def test_works_for_server_yaml_too(self):
        from chimera.modules.hysteria2_salamander import (
            _inject_obfs, _has_obfs_block,
        )
        out = _inject_obfs(_SAMPLE_SERVER_YAML, "serverpw")
        self.assertTrue(_has_obfs_block(out))
        self.assertIn("masquerade:", out)
        self.assertIn("rewriteHost: true", out)

    def test_ends_with_newline(self):
        from chimera.modules.hysteria2_salamander import _inject_obfs
        out = _inject_obfs(_SAMPLE_CLIENT_YAML, "pw")
        self.assertTrue(out.endswith("\n"))

    def test_handles_no_trailing_newline(self):
        from chimera.modules.hysteria2_salamander import _inject_obfs
        no_nl = _SAMPLE_CLIENT_YAML.rstrip()
        out = _inject_obfs(no_nl, "pw")
        # Должен добавить \n перед obfs-блоком
        self.assertIn("\nobfs:", out)


class TestStripObfs(unittest.TestCase):
    """_strip_obfs — удаление секции obfs."""

    def setUp(self):
        _setup_core()

    def test_removes_obfs_block(self):
        from chimera.modules.hysteria2_salamander import (
            _inject_obfs, _strip_obfs, _has_obfs_block,
        )
        injected = _inject_obfs(_SAMPLE_CLIENT_YAML, "pw")
        stripped = _strip_obfs(injected)
        self.assertFalse(_has_obfs_block(stripped))

    def test_preserves_other_sections(self):
        from chimera.modules.hysteria2_salamander import (
            _inject_obfs, _strip_obfs,
        )
        injected = _inject_obfs(_SAMPLE_CLIENT_YAML, "pw")
        stripped = _strip_obfs(injected)
        self.assertIn("server: 1.2.3.4:443", stripped)
        self.assertIn("auth: mypassword", stripped)
        self.assertIn("pinSHA256: abc123def456", stripped)

    def test_idempotent_when_no_obfs(self):
        from chimera.modules.hysteria2_salamander import _strip_obfs
        out = _strip_obfs(_SAMPLE_CLIENT_YAML)
        self.assertEqual(out, _SAMPLE_CLIENT_YAML)


class TestInjectIdempotency(unittest.TestCase):
    """Повторный inject должен заменять, а не дублировать блок."""

    def setUp(self):
        _setup_core()

    def test_double_inject_single_block(self):
        from chimera.modules.hysteria2_salamander import _inject_obfs
        once = _inject_obfs(_SAMPLE_CLIENT_YAML, "pw1")
        twice = _inject_obfs(once, "pw2")
        self.assertEqual(twice.count("obfs:"), 1)
        self.assertEqual(twice.count("type: salamander"), 1)
        self.assertEqual(twice.count("salamander:"), 1)

    def test_double_inject_replaces_password(self):
        from chimera.modules.hysteria2_salamander import _inject_obfs
        once = _inject_obfs(_SAMPLE_CLIENT_YAML, "oldpass")
        twice = _inject_obfs(once, "newpass")
        self.assertNotIn("password: oldpass", twice)
        self.assertIn("password: newpass", twice)


class TestBuildObfsBlock(unittest.TestCase):
    """_build_obfs_block — структура блока."""

    def setUp(self):
        _setup_core()

    def test_contains_all_required_keys(self):
        from chimera.modules.hysteria2_salamander import _build_obfs_block
        block = _build_obfs_block("mypw")
        self.assertIn("obfs:", block)
        self.assertIn("type: salamander", block)
        self.assertIn("salamander:", block)
        self.assertIn("password: mypw", block)

    def test_ends_with_newline(self):
        from chimera.modules.hysteria2_salamander import _build_obfs_block
        block = _build_obfs_block("mypw")
        self.assertTrue(block.endswith("\n"))

    def test_supports_indent(self):
        from chimera.modules.hysteria2_salamander import _build_obfs_block
        block = _build_obfs_block("mypw", indent="  ")
        self.assertIn("  obfs:", block)
        self.assertIn("    type: salamander", block)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Семантика YAML (если PyYAML установлен)
# ─────────────────────────────────────────────────────────────────────────────

class TestYamlSemantics(unittest.TestCase):
    """Проверяем, что пропатченный YAML парсится корректно."""

    def setUp(self):
        _setup_core()
        try:
            import yaml  # noqa: F401
            self._has_yaml = True
        except ImportError:
            self._has_yaml = False

    def test_injected_client_yaml_parses(self):
        if not self._has_yaml:
            self.skipTest("PyYAML not installed")
        import yaml
        from chimera.modules.hysteria2_salamander import _inject_obfs
        out = _inject_obfs(_SAMPLE_CLIENT_YAML, "secretpw")
        parsed = yaml.safe_load(out)
        self.assertEqual(parsed["obfs"]["type"], "salamander")
        self.assertEqual(parsed["obfs"]["salamander"]["password"], "secretpw")
        # Исходные секции не пострадали
        self.assertEqual(parsed["server"], "1.2.3.4:443")
        self.assertEqual(parsed["auth"], "mypassword")
        self.assertTrue(parsed["tls"]["insecure"])

    def test_injected_server_yaml_parses(self):
        if not self._has_yaml:
            self.skipTest("PyYAML not installed")
        import yaml
        from chimera.modules.hysteria2_salamander import _inject_obfs
        out = _inject_obfs(_SAMPLE_SERVER_YAML, "secretpw")
        parsed = yaml.safe_load(out)
        self.assertEqual(parsed["obfs"]["type"], "salamander")
        self.assertEqual(parsed["auth"]["password"], "mypassword")
        self.assertEqual(parsed["masquerade"]["type"], "proxy")

    def test_stripped_yaml_parses(self):
        if not self._has_yaml:
            self.skipTest("PyYAML not installed")
        import yaml
        from chimera.modules.hysteria2_salamander import (
            _inject_obfs, _strip_obfs,
        )
        out = _strip_obfs(_inject_obfs(_SAMPLE_CLIENT_YAML, "pw"))
        parsed = yaml.safe_load(out)
        self.assertNotIn("obfs", parsed)
        self.assertEqual(parsed["server"], "1.2.3.4:443")


# ─────────────────────────────────────────────────────────────────────────────
# 4. State helpers
# ─────────────────────────────────────────────────────────────────────────────

class TestSalamanderState(unittest.TestCase):
    """_load_salamander_state / _save_salamander_state / _ensure_salamander_state."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state(self):
        return patch("chimera.modules.hysteria2_common.STATE_FILE",
                     self._state)

    def test_load_returns_empty_when_no_section(self):
        from chimera.modules.hysteria2_salamander import (
            _load_salamander_state,
        )
        with self._patch_state():
            self.assertEqual(_load_salamander_state(), {})

    def test_load_returns_section(self):
        from chimera.modules.hysteria2_salamander import (
            _load_salamander_state,
        )
        self._state.write_text(json.dumps({
            "hysteria2": {"salamander": {"enabled": True, "password": "abc"}}
        }))
        with self._patch_state():
            sal = _load_salamander_state()
        self.assertTrue(sal["enabled"])
        self.assertEqual(sal["password"], "abc")

    def test_save_preserves_other_hysteria2_keys(self):
        from chimera.modules.hysteria2_salamander import (
            _save_salamander_state, _load_salamander_state,
        )
        from chimera.modules.hysteria2_common import _load_h2_state
        self._state.write_text(json.dumps({
            "hysteria2": {"enabled": True, "exit_nodes": [{"ip": "1.2.3.4"}]}
        }))
        with self._patch_state():
            _save_salamander_state({"enabled": True, "password": "pw"})
            h2 = _load_h2_state()
        # Другие ключи hysteria2 сохранены
        self.assertTrue(h2["enabled"])
        self.assertEqual(len(h2["exit_nodes"]), 1)
        # Salamander добавлен
        self.assertTrue(h2["salamander"]["enabled"])
        self.assertEqual(h2["salamander"]["password"], "pw")

    def test_ensure_creates_default_when_missing(self):
        from chimera.modules.hysteria2_salamander import (
            _ensure_salamander_state,
        )
        with self._patch_state():
            sal = _ensure_salamander_state()
        self.assertIn("enabled", sal)
        self.assertIn("password", sal)
        self.assertIn("applied_to_client", sal)
        self.assertIn("applied_to_nodes", sal)
        # Файл создан
        self.assertTrue(self._state.exists())

    def test_ensure_returns_existing_when_present(self):
        from chimera.modules.hysteria2_salamander import (
            _ensure_salamander_state,
        )
        self._state.write_text(json.dumps({
            "hysteria2": {"salamander": {"enabled": True, "password": "exist"}}
        }))
        with self._patch_state():
            sal = _ensure_salamander_state()
        self.assertTrue(sal["enabled"])
        self.assertEqual(sal["password"], "exist")


# ─────────────────────────────────────────────────────────────────────────────
# 5. h2_salamander_status — структура dict
# ─────────────────────────────────────────────────────────────────────────────

class TestSalamanderStatus(unittest.TestCase):
    """h2_salamander_status — структура возвращаемого dict."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"
        self._client_yaml = self._tmpdir / "client.yaml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return (
            patch("chimera.modules.hysteria2_common.STATE_FILE",
                  self._state),
            patch("chimera.modules.hysteria2_salamander._H2_CLIENT_CONFIG",
                  self._client_yaml),
        )

    def test_status_returns_dict_with_required_keys(self):
        from chimera.modules.hysteria2_salamander import h2_salamander_status
        with self._patches()[0], self._patches()[1]:
            st = h2_salamander_status()
        self.assertIsInstance(st, dict)
        for key in ("enabled", "has_password", "applied_to_client",
                    "applied_to_nodes", "all_nodes"):
            self.assertIn(key, st, f"missing key: {key}")

    def test_status_disabled_by_default(self):
        from chimera.modules.hysteria2_salamander import h2_salamander_status
        with self._patches()[0], self._patches()[1]:
            st = h2_salamander_status()
        self.assertFalse(st["enabled"])
        self.assertFalse(st["has_password"])

    def test_status_detects_obfs_in_client_yaml(self):
        from chimera.modules.hysteria2_salamander import (
            h2_salamander_status, _inject_obfs,
        )
        # Записываем client.yaml с obfs
        self._client_yaml.write_text(_inject_obfs(_SAMPLE_CLIENT_YAML, "pw"))
        with self._patches()[0], self._patches()[1]:
            st = h2_salamander_status()
        self.assertTrue(st["applied_to_client"])

    def test_status_detects_absence_of_obfs(self):
        from chimera.modules.hysteria2_salamander import h2_salamander_status
        self._client_yaml.write_text(_SAMPLE_CLIENT_YAML)
        with self._patches()[0], self._patches()[1]:
            st = h2_salamander_status()
        self.assertFalse(st["applied_to_client"])

    def test_status_handles_missing_client_yaml(self):
        from chimera.modules.hysteria2_salamander import h2_salamander_status
        # _client_yaml не существует
        with self._patches()[0], self._patches()[1]:
            st = h2_salamander_status()
        self.assertFalse(st["applied_to_client"])


# ─────────────────────────────────────────────────────────────────────────────
# 6. _apply_obfs_to_client — запись/чтение client.yaml
# ─────────────────────────────────────────────────────────────────────────────

class TestApplyObfsToClient(unittest.TestCase):
    """_apply_obfs_to_client — патч локального client.yaml."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._client_yaml = self._tmpdir / "client.yaml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.hysteria2_salamander._H2_CLIENT_CONFIG",
                     self._client_yaml)

    def test_returns_false_when_no_file(self):
        from chimera.modules.hysteria2_salamander import _apply_obfs_to_client
        with self._patch():
            self.assertFalse(_apply_obfs_to_client("pw"))

    def test_writes_obfs_to_existing_file(self):
        from chimera.modules.hysteria2_salamander import (
            _apply_obfs_to_client, _has_obfs_block,
        )
        self._client_yaml.write_text(_SAMPLE_CLIENT_YAML)
        with self._patch():
            ok = _apply_obfs_to_client("mypw")
        self.assertTrue(ok)
        out = self._client_yaml.read_text()
        self.assertTrue(_has_obfs_block(out))
        self.assertIn("password: mypw", out)

    def test_preserves_original_content(self):
        from chimera.modules.hysteria2_salamander import _apply_obfs_to_client
        self._client_yaml.write_text(_SAMPLE_CLIENT_YAML)
        with self._patch():
            _apply_obfs_to_client("mypw")
        out = self._client_yaml.read_text()
        self.assertIn("server: 1.2.3.4:443", out)
        self.assertIn("auth: mypassword", out)

    def test_chmod_0600_after_write(self):
        """Пароль секретный — права доступа 0o600."""
        from chimera.modules.hysteria2_salamander import _apply_obfs_to_client
        self._client_yaml.write_text(_SAMPLE_CLIENT_YAML)
        with self._patch():
            _apply_obfs_to_client("mypw")
        mode = self._client_yaml.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)


class TestStripObfsFromClient(unittest.TestCase):
    """_strip_obfs_from_client — удаление obfs из client.yaml."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._client_yaml = self._tmpdir / "client.yaml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.hysteria2_salamander._H2_CLIENT_CONFIG",
                     self._client_yaml)

    def test_returns_true_when_no_file(self):
        from chimera.modules.hysteria2_salamander import _strip_obfs_from_client
        with self._patch():
            self.assertTrue(_strip_obfs_from_client())

    def test_removes_obfs_from_existing_file(self):
        from chimera.modules.hysteria2_salamander import (
            _strip_obfs_from_client, _inject_obfs, _has_obfs_block,
        )
        self._client_yaml.write_text(_inject_obfs(_SAMPLE_CLIENT_YAML, "pw"))
        with self._patch():
            ok = _strip_obfs_from_client()
        self.assertTrue(ok)
        out = self._client_yaml.read_text()
        self.assertFalse(_has_obfs_block(out))

    def test_no_op_when_no_obfs(self):
        from chimera.modules.hysteria2_salamander import _strip_obfs_from_client
        self._client_yaml.write_text(_SAMPLE_CLIENT_YAML)
        with self._patch():
            ok = _strip_obfs_from_client()
        self.assertTrue(ok)
        # Файл не изменился
        self.assertEqual(self._client_yaml.read_text(), _SAMPLE_CLIENT_YAML)


# ─────────────────────────────────────────────────────────────────────────────
# 7. h2_salamander_ensure_state — хук повторного применения
# ─────────────────────────────────────────────────────────────────────────────

class TestEnsureStateHook(unittest.TestCase):
    """h2_salamander_ensure_state — хук для пере-применения."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"
        self._client_yaml = self._tmpdir / "client.yaml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return (
            patch("chimera.modules.hysteria2_common.STATE_FILE",
                  self._state),
            patch("chimera.modules.hysteria2_salamander._H2_CLIENT_CONFIG",
                  self._client_yaml),
            patch("chimera.modules.hysteria2_salamander._restart_hysteria_client",
                  return_value=True),
        )

    def test_noop_when_disabled(self):
        from chimera.modules.hysteria2_salamander import (
            h2_salamander_ensure_state,
        )
        # State пустой — salamander не включён
        with self._patches()[0], self._patches()[1], self._patches()[2]:
            h2_salamander_ensure_state()
        # client.yaml не тронут (даже не создан)
        self.assertFalse(self._client_yaml.exists())

    def test_noop_when_no_password(self):
        from chimera.modules.hysteria2_salamander import (
            h2_salamander_ensure_state, _save_salamander_state,
        )
        with self._patches()[0]:
            _save_salamander_state({"enabled": True, "password": ""})
            h2_salamander_ensure_state()
        self.assertFalse(self._client_yaml.exists())

    def test_reapplies_obfs_when_enabled(self):
        from chimera.modules.hysteria2_salamander import (
            h2_salamander_ensure_state, _save_salamander_state,
            _has_obfs_block,
        )
        # Подготавливаем: salamander включён с паролем, client.yaml без obfs
        self._client_yaml.write_text(_SAMPLE_CLIENT_YAML)
        with self._patches()[0]:
            _save_salamander_state({"enabled": True, "password": "reapplypw"})
            with self._patches()[1], self._patches()[2]:
                h2_salamander_ensure_state()
        # obfs появился в client.yaml
        out = self._client_yaml.read_text()
        self.assertTrue(_has_obfs_block(out))
        self.assertIn("password: reapplypw", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
