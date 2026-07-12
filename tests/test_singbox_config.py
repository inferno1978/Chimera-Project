#!/usr/bin/env python3
"""
tests/test_singbox_config.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/singbox_config.py и singbox_state.py.

Покрывает:
  1. singbox_state_init / load / save / update
  2. _build_shadowtls_inbound — структура ShadowTLS inbound
  3. _build_trojan_inbound — структура Trojan inbound (внутренний)
  4. _build_anytls_inbound — структура AnyTLS inbound
  5. _build_tuic_inbound — структура TUIC v5 inbound
  6. singbox_generate_config — полный config.json
  7. singbox_enable/disable_shadowtls/anytls/tuic — state changes
  8. singbox_state_get_enabled_protocols
  9. Сертификаты — self-signed cert generation
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("vless_installer._core")
    m.__dict__.update(g)
    sys.modules["vless_installer._core"] = m


def _enter_patches(stack, patches):
    for p in patches:
        stack.enter_context(p)


# ─────────────────────────────────────────────────────────────────────────────
# Фикстуры
# ─────────────────────────────────────────────────────────────────────────────

_SAMPLE_USERS = [
    {"uuid": "11111111-1111-1111-1111-111111111111", "password": "pw1", "name": "alice"},
    {"uuid": "22222222-2222-2222-2222-222222222222", "password": "pw2", "name": "bob"},
]

_SAMPLE_TUIC_USERS = [
    {"uuid": "11111111-1111-1111-1111-111111111111", "password": "tuic-pw1", "name": "alice"},
]


# ─────────────────────────────────────────────────────────────────────────────
# 1. State management
# ─────────────────────────────────────────────────────────────────────────────

class TestStateManagement(unittest.TestCase):
    """singbox_state_init / load / save / update."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "singbox_state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches_list(self):
        """Возвращает список patch-объектов для ExitStack."""
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._tmpdir / "main_state.json"),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
        ]

    def _patch(self):
        """Совместимость со старым API — возвращает один patch (SINGBOX_STATE_FILE).
        Использовать _patches_list() + ExitStack для надёжного тестирования.
        """
        return patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._state)

    def test_init_creates_default_state(self):
        from vless_installer.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patches_list())
            state = singbox_state_init(version="1.11.4")
        self.assertTrue(state["installed"])
        self.assertEqual(state["version"], "1.11.4")
        self.assertIn("inbounds", state)
        self.assertIn("shadowtls", state["inbounds"])
        self.assertIn("anytls", state["inbounds"])
        self.assertIn("tuic", state["inbounds"])
        self.assertIn("trojan", state["inbounds"])

    def test_load_returns_empty_when_no_file(self):
        from vless_installer.modules.singbox_state import singbox_state_load
        with ExitStack() as stack:
            _enter_patches(stack, self._patches_list())
            self.assertEqual(singbox_state_load(), {})

    def test_load_returns_state_after_save(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_load,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches_list())
            singbox_state_init(version="1.0.0")
            state = singbox_state_load()
        self.assertTrue(state["installed"])

    def test_update_modifies_top_level_keys(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update, singbox_state_load,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches_list())
            singbox_state_init(version="1.0.0")
            singbox_state_update(version="2.0.0", last_applied="2026-01-01")
            state = singbox_state_load()
        self.assertEqual(state["version"], "2.0.0")
        self.assertEqual(state["last_applied"], "2026-01-01")

    def test_update_inbound_partial(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update_inbound, singbox_state_get_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches_list())
            singbox_state_init(version="1.0.0")
            singbox_state_update_inbound("shadowtls", enabled=True, password="newpw")
            ib = singbox_state_get_inbound("shadowtls")
        self.assertTrue(ib["enabled"])
        self.assertEqual(ib["password"], "newpw")

    def test_get_enabled_protocols_empty_by_default(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_get_enabled_protocols,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches_list())
            singbox_state_init(version="1.0.0")
            protos = singbox_state_get_enabled_protocols()
        self.assertEqual(protos, [])

    def test_get_enabled_protocols_after_enable(self):
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update_inbound,
            singbox_state_get_enabled_protocols,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches_list())
            singbox_state_init(version="1.0.0")
            singbox_state_update_inbound("shadowtls", enabled=True)
            singbox_state_update_inbound("tuic", enabled=True)
            protos = singbox_state_get_enabled_protocols()
        self.assertIn("shadowtls", protos)
        self.assertIn("tuic", protos)
        self.assertEqual(len(protos), 2)

    def test_state_file_permissions_0600(self):
        """State содержит пароли/сертификаты — права 0o600."""
        from vless_installer.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patches_list())
            singbox_state_init(version="1.0.0")
        mode = self._state.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)


# ─────────────────────────────────────────────────────────────────────────────
# 2. ShadowTLS inbound builder
# ─────────────────────────────────────────────────────────────────────────────

class TestShadowtlsInboundBuilder(unittest.TestCase):
    """_build_shadowtls_inbound — структура ShadowTLS inbound."""

    def setUp(self):
        _setup_core()

    def test_returns_dict(self):
        from vless_installer.modules.singbox_config import _build_shadowtls_inbound
        ib = _build_shadowtls_inbound({
            "enabled": True,
            "listen": "127.0.0.1",
            "listen_port": 8443,
            "version": 3,
            "users": _SAMPLE_USERS,
            "handshake": {"server": "www.cloudflare.com", "server_port": 443},
            "detour": "trojan-in",
        })
        self.assertIsInstance(ib, dict)

    def test_has_required_fields(self):
        from vless_installer.modules.singbox_config import _build_shadowtls_inbound
        ib = _build_shadowtls_inbound({
            "enabled": True,
            "listen": "127.0.0.1",
            "listen_port": 8443,
            "version": 3,
            "users": _SAMPLE_USERS,
            "handshake": {"server": "www.cloudflare.com", "server_port": 443},
            "detour": "trojan-in",
        })
        self.assertEqual(ib["type"], "shadowtls")
        self.assertEqual(ib["tag"], "shadowtls-in")
        self.assertEqual(ib["listen"], "127.0.0.1")
        self.assertEqual(ib["listen_port"], 8443)
        self.assertEqual(ib["version"], 3)
        self.assertEqual(ib["detour"], "trojan-in")
        self.assertIn("handshake", ib)
        self.assertEqual(ib["handshake"]["server"], "www.cloudflare.com")
        self.assertEqual(ib["handshake"]["server_port"], 443)

    def test_users_format_password_name(self):
        from vless_installer.modules.singbox_config import _build_shadowtls_inbound
        ib = _build_shadowtls_inbound({
            "enabled": True,
            "users": _SAMPLE_USERS,
        })
        self.assertEqual(len(ib["users"]), 2)
        for u in ib["users"]:
            self.assertIn("password", u)
            self.assertIn("name", u)
            self.assertNotIn("uuid", u)  # ShadowTLS не использует UUID

    def test_skips_users_without_password(self):
        from vless_installer.modules.singbox_config import _build_shadowtls_inbound
        ib = _build_shadowtls_inbound({
            "enabled": True,
            "users": [
                {"password": "pw1", "name": "alice"},
                {"name": "bob"},  # без password — должен быть пропущен
            ],
        })
        self.assertEqual(len(ib["users"]), 1)
        self.assertEqual(ib["users"][0]["name"], "alice")

    def test_tls_block_never_present_even_if_cert_paths_exist(self):
        """v4.22.3: ShadowTLS v3 НЕ поддерживает локальный TLS-сертификат.

        Протокол проксирует TLS-handshake на внешний сервер (handshake.server),
        наблюдатель видит настоящий сертификат реального сайта. Поле "tls" в
        inbound НЕ должно генерироваться НИ ПРИ КАКИХ УСЛОВИЯХ — даже если
        cert_path/key_path заданы в state и файлы существуют на диске.

        Старый тест test_tls_block_included_when_cert_paths_exist (v4.22.0)
        проверял ОБРАТНОЕ — что tls-блок добавляется. Это было ошибкой
        понимания протокола, исправлено в v4.22.3.
        """
        from vless_installer.modules.singbox_config import _build_shadowtls_inbound
        with tempfile.TemporaryDirectory() as td:
            cert = Path(td) / "cert.pem"
            key = Path(td) / "key.pem"
            cert.write_text("fake cert")
            key.write_text("fake key")
            ib = _build_shadowtls_inbound({
                "enabled": True,
                "users": [],
                "cert_path": str(cert),
                "key_path":  str(key),
            })
            # КРИТИЧНО: "tls" не должно быть в inbound, даже если файлы существуют
            self.assertNotIn("tls", ib,
                              "ShadowTLS v3 не должен генерировать TLS-блок — "
                              "протокол проксирует handshake на handshake.server")

    def test_tls_block_omitted_when_cert_missing(self):
        """cert_path/key_path могут отсутствовать — TLS-блока тоже нет."""
        from vless_installer.modules.singbox_config import _build_shadowtls_inbound
        ib = _build_shadowtls_inbound({
            "enabled": True,
            "users": [],
            "cert_path": "/nonexistent/cert.pem",
            "key_path":  "/nonexistent/key.pem",
        })
        self.assertNotIn("tls", ib)

    def test_cert_path_key_path_in_state_ignored(self):
        """v4.22.3: cert_path/key_path в state игнорируются безусловно.

        Даже если файлы существуют и пути валидны — ShadowTLS не должен
        использовать их для локального TLS. Это backcompat-носитель:
        старые state-файлы (v4.22.0-v4.22.2) могут содержать эти поля,
        но генератор их не читает.
        """
        from vless_installer.modules.singbox_config import _build_shadowtls_inbound
        with tempfile.TemporaryDirectory() as td:
            cert = Path(td) / "cert.pem"
            key = Path(td) / "key.pem"
            cert.write_text("fake cert")
            key.write_text("fake key")
            ib = _build_shadowtls_inbound({
                "enabled": True,
                "users": [],
                "cert_path": str(cert),
                "key_path":  str(key),
                "cert_source": "letsencrypt",  # тоже игнорируется
            })
            self.assertNotIn("tls", ib)
            self.assertNotIn("certificate", ib)
            self.assertNotIn("key", ib)

    def test_defaults_applied(self):
        """Если поля отсутствуют — должны подставляться defaults."""
        from vless_installer.modules.singbox_config import _build_shadowtls_inbound
        ib = _build_shadowtls_inbound({"enabled": True, "users": []})
        self.assertEqual(ib["listen"], "127.0.0.1")
        self.assertEqual(ib["listen_port"], 8443)
        self.assertEqual(ib["version"], 3)
        self.assertEqual(ib["handshake"]["server"], "www.cloudflare.com")
        self.assertEqual(ib["handshake"]["server_port"], 443)
        self.assertEqual(ib["detour"], "trojan-in")


# ─────────────────────────────────────────────────────────────────────────────
# 3. Trojan inbound builder
# ─────────────────────────────────────────────────────────────────────────────

class TestTrojanInboundBuilder(unittest.TestCase):
    """_build_trojan_inbound — Trojan (внутренний под ShadowTLS)."""

    def setUp(self):
        _setup_core()

    def test_returns_dict_with_required_fields(self):
        from vless_installer.modules.singbox_config import _build_trojan_inbound
        ib = _build_trojan_inbound({"enabled": True, "users": _SAMPLE_USERS})
        self.assertEqual(ib["type"], "trojan")
        self.assertEqual(ib["tag"], "trojan-in")
        self.assertEqual(ib["listen"], "127.0.0.1")
        self.assertEqual(ib["listen_port"], 0)  # 0 = через detour
        self.assertEqual(len(ib["users"]), 2)

    def test_users_format(self):
        from vless_installer.modules.singbox_config import _build_trojan_inbound
        ib = _build_trojan_inbound({"enabled": True, "users": _SAMPLE_USERS})
        for u in ib["users"]:
            self.assertIn("password", u)
            self.assertIn("name", u)


# ─────────────────────────────────────────────────────────────────────────────
# 4. AnyTLS inbound builder
# ─────────────────────────────────────────────────────────────────────────────

class TestAnytlsInboundBuilder(unittest.TestCase):
    """_build_anytls_inbound."""

    def setUp(self):
        _setup_core()

    def test_returns_dict_with_required_fields(self):
        from vless_installer.modules.singbox_config import _build_anytls_inbound
        ib = _build_anytls_inbound({"enabled": True, "users": _SAMPLE_USERS})
        self.assertEqual(ib["type"], "anytls")
        self.assertEqual(ib["tag"], "anytls-in")
        self.assertEqual(ib["listen"], "127.0.0.1")
        self.assertEqual(ib["listen_port"], 8444)
        self.assertEqual(len(ib["users"]), 2)

    def test_tls_block_when_cert_paths_exist(self):
        from vless_installer.modules.singbox_config import _build_anytls_inbound
        with tempfile.TemporaryDirectory() as td:
            cert = Path(td) / "anytls.crt"
            key = Path(td) / "anytls.key"
            cert.write_text("fake")
            key.write_text("fake")
            ib = _build_anytls_inbound({
                "enabled": True,
                "users": [],
                "cert_path": str(cert),
                "key_path":  str(key),
            })
            self.assertIn("tls", ib)


# ─────────────────────────────────────────────────────────────────────────────
# 5. TUIC inbound builder
# ─────────────────────────────────────────────────────────────────────────────

class TestTuicInboundBuilder(unittest.TestCase):
    """_build_tuic_inbound — TUIC v5."""

    def setUp(self):
        _setup_core()

    def test_returns_dict_with_required_fields(self):
        from vless_installer.modules.singbox_config import _build_tuic_inbound
        ib = _build_tuic_inbound({"enabled": True, "users": _SAMPLE_TUIC_USERS})
        self.assertEqual(ib["type"], "tuic")
        self.assertEqual(ib["tag"], "tuic-in")
        self.assertEqual(ib["listen"], "::")
        self.assertEqual(ib["listen_port"], 443)  # default TUIC port
        self.assertEqual(ib["congestion_control"], "bbr")

    def test_users_format_uuid_password(self):
        """TUIC users format: {uuid, password} (без name)."""
        from vless_installer.modules.singbox_config import _build_tuic_inbound
        ib = _build_tuic_inbound({"enabled": True, "users": _SAMPLE_TUIC_USERS})
        self.assertEqual(len(ib["users"]), 1)
        u = ib["users"][0]
        self.assertEqual(u["uuid"], "11111111-1111-1111-1111-111111111111")
        self.assertEqual(u["password"], "tuic-pw1")
        self.assertNotIn("name", u)  # TUIC users не имеют name

    def test_skips_users_without_uuid(self):
        from vless_installer.modules.singbox_config import _build_tuic_inbound
        ib = _build_tuic_inbound({
            "enabled": True,
            "users": [
                {"uuid": "abc", "password": "pw1"},
                {"password": "pw2"},  # без uuid — пропускаем
                {"uuid": "def"},      # без password — пропускаем
            ],
        })
        self.assertEqual(len(ib["users"]), 1)

    def test_tls_block_when_cert_paths_exist(self):
        from vless_installer.modules.singbox_config import _build_tuic_inbound
        with tempfile.TemporaryDirectory() as td:
            cert = Path(td) / "tuic.crt"
            key = Path(td) / "tuic.key"
            cert.write_text("fake")
            key.write_text("fake")
            ib = _build_tuic_inbound({
                "enabled": True,
                "users": [],
                "cert_path": str(cert),
                "key_path":  str(key),
            })
            self.assertIn("tls", ib)


# ─────────────────────────────────────────────────────────────────────────────
# 6. singbox_generate_config — полный config.json
# ─────────────────────────────────────────────────────────────────────────────

class TestGenerateConfig(unittest.TestCase):
    """singbox_generate_config — генерация /etc/sing-box/config.json."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._config_dir = self._tmpdir / "sing-box"
        self._config_file = self._config_dir / "config.json"
        self._state = self._tmpdir / "singbox_state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_CONFIG_DIR", self._config_dir),
            patch("vless_installer.modules.singbox_common.SINGBOX_CONFIG_FILE", self._config_file),
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._tmpdir / "main_state.json"),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_config.SINGBOX_CONFIG_DIR", self._config_dir),
            patch("vless_installer.modules.singbox_config.SINGBOX_CONFIG_FILE", self._config_file),
        ]

    def test_returns_false_when_not_installed(self):
        from vless_installer.modules.singbox_config import singbox_generate_config
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            ok = singbox_generate_config()
        self.assertFalse(ok)

    def test_generates_empty_config_when_no_protocols(self):
        from vless_installer.modules.singbox_config import singbox_generate_config
        from vless_installer.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            ok = singbox_generate_config()
        self.assertTrue(ok)
        cfg = json.loads(self._config_file.read_text())
        self.assertEqual(cfg["inbounds"], [])
        self.assertEqual(cfg["outbounds"][0]["type"], "direct")
        self.assertEqual(cfg["outbounds"][1]["type"], "block")

    def test_generates_config_with_shadowtls_and_trojan(self):
        from vless_installer.modules.singbox_config import singbox_generate_config
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_state_update_inbound("shadowtls", enabled=True, users=_SAMPLE_USERS)
            singbox_state_update_inbound("trojan", enabled=True, users=_SAMPLE_USERS)
            ok = singbox_generate_config()
        self.assertTrue(ok)
        cfg = json.loads(self._config_file.read_text())
        types = [ib["type"] for ib in cfg["inbounds"]]
        self.assertIn("shadowtls", types)
        self.assertIn("trojan", types)

    def test_generates_config_with_anytls(self):
        from vless_installer.modules.singbox_config import singbox_generate_config
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_state_update_inbound("anytls", enabled=True, users=_SAMPLE_USERS)
            ok = singbox_generate_config()
        self.assertTrue(ok)
        cfg = json.loads(self._config_file.read_text())
        types = [ib["type"] for ib in cfg["inbounds"]]
        self.assertIn("anytls", types)

    def test_generates_config_with_tuic(self):
        from vless_installer.modules.singbox_config import singbox_generate_config
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_state_update_inbound("tuic", enabled=True, users=_SAMPLE_TUIC_USERS)
            ok = singbox_generate_config()
        self.assertTrue(ok)
        cfg = json.loads(self._config_file.read_text())
        types = [ib["type"] for ib in cfg["inbounds"]]
        self.assertIn("tuic", types)

    def test_generates_config_with_all_protocols(self):
        from vless_installer.modules.singbox_config import singbox_generate_config
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_update_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_state_update_inbound("shadowtls", enabled=True, users=_SAMPLE_USERS)
            singbox_state_update_inbound("trojan", enabled=True, users=_SAMPLE_USERS)
            singbox_state_update_inbound("anytls", enabled=True, users=_SAMPLE_USERS)
            singbox_state_update_inbound("tuic", enabled=True, users=_SAMPLE_TUIC_USERS)
            ok = singbox_generate_config()
        self.assertTrue(ok)
        cfg = json.loads(self._config_file.read_text())
        self.assertEqual(len(cfg["inbounds"]), 4)

    def test_log_block_present(self):
        from vless_installer.modules.singbox_config import singbox_generate_config
        from vless_installer.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_generate_config()
        cfg = json.loads(self._config_file.read_text())
        self.assertIn("log", cfg)
        self.assertIn("level", cfg["log"])

    def test_route_block_present(self):
        from vless_installer.modules.singbox_config import singbox_generate_config
        from vless_installer.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_generate_config()
        cfg = json.loads(self._config_file.read_text())
        self.assertIn("route", cfg)
        self.assertEqual(cfg["route"]["final"], "direct")

    def test_updates_last_applied(self):
        from vless_installer.modules.singbox_config import singbox_generate_config
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_load,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_generate_config()
            state = singbox_state_load()
        self.assertTrue(state.get("last_applied"))


# ─────────────────────────────────────────────────────────────────────────────
# 7. Enable/disable functions
# ─────────────────────────────────────────────────────────────────────────────

class TestEnableDisableFunctions(unittest.TestCase):
    """singbox_enable/disable_shadowtls/anytls/tuic."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "singbox_state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._tmpdir / "main_state.json"),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
            patch("vless_installer.modules.singbox_config.SINGBOX_CONFIG_DIR", self._tmpdir / "sb"),
            patch("vless_installer.modules.singbox_config.SINGBOX_CONFIG_FILE", self._tmpdir / "sb" / "config.json"),
        ]

    def test_enable_shadowtls_sets_state(self):
        """v4.22.3: singbox_enable_shadowtls() не принимает cert_path/key_path."""
        from vless_installer.modules.singbox_config import singbox_enable_shadowtls
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_get_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patch())
            singbox_state_init(version="1.0.0")
            singbox_enable_shadowtls()  # без cert-параметров
            ib = singbox_state_get_inbound("shadowtls")
        self.assertTrue(ib["enabled"])
        self.assertTrue(ib.get("password"))
        # cert_path/key_path/cert_source НЕ должны быть в state (v4.22.3)
        self.assertNotIn("cert_path", ib)
        self.assertNotIn("key_path", ib)
        self.assertNotIn("cert_source", ib)

    def test_enable_shadowtls_rejects_cert_params(self):
        """v4.22.3: передача cert_path должна вызвать TypeError.

        Это намеренно — скрытый ignore привёл бы к тихому накоплению мусора
        в state. Лучше явная ошибка, чтобы вызывающий код не передавал
        больше не нужные параметры.
        """
        from vless_installer.modules.singbox_config import singbox_enable_shadowtls
        from vless_installer.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patch())
            singbox_state_init(version="1.0.0")
            with self.assertRaises(TypeError):
                singbox_enable_shadowtls(cert_path="/tmp/cert.pem")
            with self.assertRaises(TypeError):
                singbox_enable_shadowtls(key_path="/tmp/key.pem")
            with self.assertRaises(TypeError):
                singbox_enable_shadowtls(cert_source="self-signed")

    def test_enable_shadowtls_also_enables_trojan(self):
        from vless_installer.modules.singbox_config import singbox_enable_shadowtls
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_get_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patch())
            singbox_state_init(version="1.0.0")
            singbox_enable_shadowtls()
            trojan = singbox_state_get_inbound("trojan")
        self.assertTrue(trojan["enabled"])

    def test_disable_shadowtls_disables_trojan(self):
        from vless_installer.modules.singbox_config import (
            singbox_enable_shadowtls, singbox_disable_shadowtls,
        )
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_get_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patch())
            singbox_state_init(version="1.0.0")
            singbox_enable_shadowtls()
            singbox_disable_shadowtls()
            sh = singbox_state_get_inbound("shadowtls")
            tr = singbox_state_get_inbound("trojan")
        self.assertFalse(sh["enabled"])
        self.assertFalse(tr["enabled"])

    def test_enable_anytls(self):
        from vless_installer.modules.singbox_config import singbox_enable_anytls
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_get_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patch())
            singbox_state_init(version="1.0.0")
            singbox_enable_anytls(cert_source="self-signed")
            ib = singbox_state_get_inbound("anytls")
        self.assertTrue(ib["enabled"])
        self.assertTrue(ib.get("password"))

    def test_enable_tuic_does_not_generate_password(self):
        """TUIC не имеет общего пароля — пароли у пользователей."""
        from vless_installer.modules.singbox_config import singbox_enable_tuic
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_get_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patch())
            singbox_state_init(version="1.0.0")
            singbox_enable_tuic(cert_source="self-signed")
            ib = singbox_state_get_inbound("tuic")
        self.assertTrue(ib["enabled"])
        # Поле password у TUIC inbound не должно быть (пароли в users)
        self.assertNotIn("password", ib)


# ─────────────────────────────────────────────────────────────────────────────
# 8. Сертификаты — self-signed generation
# ─────────────────────────────────────────────────────────────────────────────

class TestSelfSignedCert(unittest.TestCase):
    """generate_self_signed_cert — генерация сертификата."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_generates_cert_and_key(self):
        # openssl должен быть в системе
        import shutil as _sh
        if not _sh.which("openssl"):
            self.skipTest("openssl not installed")
        from vless_installer.modules.singbox_common import generate_self_signed_cert
        cert = self._tmpdir / "test.crt"
        key = self._tmpdir / "test.key"
        result_cert, result_key = generate_self_signed_cert(
            common_name="test-singbox",
            cert_path=cert,
            key_path=key,
            san_dns="example.com",
        )
        self.assertEqual(result_cert, cert)
        self.assertEqual(result_key, key)
        self.assertTrue(cert.exists())
        self.assertTrue(key.exists())
        # Содержимое должно быть похоже на PEM
        cert_text = cert.read_text()
        self.assertIn("BEGIN CERTIFICATE", cert_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
