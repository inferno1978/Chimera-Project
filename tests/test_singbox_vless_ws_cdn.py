#!/usr/bin/env python3
"""
tests/test_singbox_vless_ws_cdn.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для VLESS-WS-CDN (v4.23).

Покрывает:
  1. _build_vless_ws_cdn_inbound — структура inbound (type, transport, NO tls)
  2. singbox_enable_vless_ws_cdn — генерация uuid/ws_path, сохранение в state
  3. singbox_disable_vless_ws_cdn — снятие enabled
  4. Переключение cdn_provider между всеми тремя без потери uuid/path/host
  5. enable/disable не создаёт tls-полей в state (регрессия v4.22.3)
  6. При enabled=False singbox_generate_config() не добавляет inbound
  7. Реальный вызов singbox_generate_config() с vless_ws_cdn.enabled=True →
     парсинг config.json → проверка structure
  8. singbox_validate_config() с реальным бинарником (skip если недоступен)
  9. CDN_PROVIDERS — структура, наличие инструкций для всех трёх
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


def _enter_patches(stack, patches):
    for p in patches:
        stack.enter_context(p)


# ─────────────────────────────────────────────────────────────────────────────
# 1. _build_vless_ws_cdn_inbound — структура
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildVlessWsCdnInbound(unittest.TestCase):
    """_build_vless_ws_cdn_inbound — структура inbound."""

    def setUp(self):
        _setup_core()

    def test_returns_dict_with_required_fields(self):
        from chimera.modules.singbox_config import _build_vless_ws_cdn_inbound
        ib = _build_vless_ws_cdn_inbound({
            "enabled": True,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "ws_path": "/a3f4b2c1",
            "host": "vless.example.com",
        })
        self.assertEqual(ib["type"], "vless")
        self.assertEqual(ib["tag"], "vless-ws-cdn-in")
        self.assertIn("transport", ib)
        self.assertEqual(ib["transport"]["type"], "ws")

    def test_listen_defaults_to_0_0_0_0(self):
        """VLESS-WS-CDN bound externally — CDN подключается к этому порту."""
        from chimera.modules.singbox_config import _build_vless_ws_cdn_inbound
        ib = _build_vless_ws_cdn_inbound({"enabled": True, "uuid": "x"})
        self.assertEqual(ib["listen"], "0.0.0.0")

    def test_listen_port_default_8443(self):
        from chimera.modules.singbox_config import _build_vless_ws_cdn_inbound
        ib = _build_vless_ws_cdn_inbound({"enabled": True, "uuid": "x"})
        self.assertEqual(ib["listen_port"], 8443)

    def test_ws_path_in_transport(self):
        from chimera.modules.singbox_config import _build_vless_ws_cdn_inbound
        ib = _build_vless_ws_cdn_inbound({
            "enabled": True,
            "uuid": "x",
            "ws_path": "/my-secret-path",
        })
        self.assertEqual(ib["transport"]["path"], "/my-secret-path")

    def test_host_header_in_transport(self):
        from chimera.modules.singbox_config import _build_vless_ws_cdn_inbound
        ib = _build_vless_ws_cdn_inbound({
            "enabled": True,
            "uuid": "x",
            "ws_path": "/",
            "host": "vless.example.com",
        })
        self.assertIn("headers", ib["transport"])
        self.assertEqual(ib["transport"]["headers"]["Host"], "vless.example.com")

    def test_host_header_omitted_when_empty(self):
        from chimera.modules.singbox_config import _build_vless_ws_cdn_inbound
        ib = _build_vless_ws_cdn_inbound({
            "enabled": True,
            "uuid": "x",
            "ws_path": "/",
            "host": "",
        })
        self.assertNotIn("headers", ib["transport"])

    def test_uuid_in_users(self):
        from chimera.modules.singbox_config import _build_vless_ws_cdn_inbound
        ib = _build_vless_ws_cdn_inbound({
            "enabled": True,
            "uuid": "11111111-1111-1111-1111-111111111111",
        })
        self.assertEqual(len(ib["users"]), 1)
        self.assertEqual(ib["users"][0]["uuid"], "11111111-1111-1111-1111-111111111111")

    def test_users_empty_when_no_uuid(self):
        """пустой uuid → ValueError (раньше молча давал users: []
        мёртвый inbound, коннекты есть, авторизация невозможна). Guard
        гарантирует: конфиг с пустыми кредами не генерится вовсе."""
        from chimera.modules.singbox_config import _build_vless_ws_cdn_inbound
        with self.assertRaises(ValueError):
            _build_vless_ws_cdn_inbound({"enabled": True, "uuid": ""})

    # ── КРИТИЧНО: отсутствие TLS-блока (регрессия v4.22.3) ─────────────────

    def test_no_tls_block_in_inbound(self):
        """v4.23: VLESS-WS-CDN НЕ содержит поля 'tls' — CDN терминирует TLS.

        Аналог регрессии v4.22.3 с ShadowTLS TLS-блоком. CDN терминирует TLS
        своим сертификатом, origin (sing-box) слушает plain WS. Добавление
        'tls' было бы мёртвым JSON-полем.
        """
        from chimera.modules.singbox_config import _build_vless_ws_cdn_inbound
        ib = _build_vless_ws_cdn_inbound({
            "enabled": True,
            "uuid": "x",
            "ws_path": "/",
            "host": "vless.example.com",
            # cert_path/key_path в state — игнорируются безусловно
            "cert_path": "/etc/letsencrypt/live/example.com/fullchain.pem",
            "key_path": "/etc/letsencrypt/live/example.com/privkey.pem",
            "cert_source": "letsencrypt",
        })
        self.assertNotIn("tls", ib,
                         "VLESS-WS-CDN не должен содержать tls{} — CDN терминирует TLS")
        self.assertNotIn("certificate", ib)
        self.assertNotIn("key", ib)

    def test_no_tls_block_even_if_cert_paths_exist_on_disk(self):
        """Даже если cert_path/key_path указывают на существующие файлы — tls не добавляется."""
        from chimera.modules.singbox_config import _build_vless_ws_cdn_inbound
        with tempfile.TemporaryDirectory() as td:
            cert = Path(td) / "cert.pem"
            key = Path(td) / "key.pem"
            cert.write_text("fake cert")
            key.write_text("fake key")
            ib = _build_vless_ws_cdn_inbound({
                "enabled": True,
                "uuid": "x",
                "cert_path": str(cert),
                "key_path": str(key),
            })
            self.assertNotIn("tls", ib)


# ─────────────────────────────────────────────────────────────────────────────
# 2. singbox_enable_vless_ws_cdn — генерация и сохранение
# ─────────────────────────────────────────────────────────────────────────────

class TestEnableVlessWsCdn(unittest.TestCase):
    """singbox_enable_vless_ws_cdn — генерация uuid/ws_path, сохранение в state."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("chimera.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
            patch("chimera.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("chimera.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
            patch("chimera.modules.singbox_config.SINGBOX_CONFIG_DIR", self._tmpdir / "sb"),
            patch("chimera.modules.singbox_config.SINGBOX_CONFIG_FILE", self._tmpdir / "sb" / "config.json"),
        ]

    def test_enable_generates_uuid_if_missing(self):
        from chimera.modules.singbox_config import singbox_enable_vless_ws_cdn
        from chimera.modules.singbox_state import (
            singbox_state_init, singbox_state_get_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_enable_vless_ws_cdn(cdn_provider="cloudflare", host="vless.example.com")
            ib = singbox_state_get_inbound("vless_ws_cdn")
        self.assertTrue(ib["enabled"])
        self.assertTrue(ib["uuid"])  # UUID сгенерирован
        # Формат UUID v4
        import re
        self.assertRegex(ib["uuid"],
                         r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')

    def test_enable_generates_ws_path_if_missing(self):
        from chimera.modules.singbox_config import singbox_enable_vless_ws_cdn
        from chimera.modules.singbox_state import (
            singbox_state_init, singbox_state_get_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_enable_vless_ws_cdn(cdn_provider="cloudflare", host="vless.example.com")
            ib = singbox_state_get_inbound("vless_ws_cdn")
        self.assertTrue(ib["ws_path"])
        self.assertTrue(ib["ws_path"].startswith("/"))

    def test_enable_does_not_regenerate_uuid_if_exists(self):
        """Повторный enable НЕ перегенерирует UUID (только по явному действию)."""
        from chimera.modules.singbox_config import singbox_enable_vless_ws_cdn
        from chimera.modules.singbox_state import (
            singbox_state_init, singbox_state_get_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            # Первый enable — генерирует
            singbox_enable_vless_ws_cdn(cdn_provider="cloudflare", host="vless.example.com")
            ib1 = singbox_state_get_inbound("vless_ws_cdn")
            uuid1 = ib1["uuid"]
            # Второй enable — должен сохранить
            singbox_enable_vless_ws_cdn(cdn_provider="cloudflare", host="vless.example.com")
            ib2 = singbox_state_get_inbound("vless_ws_cdn")
        self.assertEqual(uuid1, ib2["uuid"],
                         "Повторный enable не должен перегенерировать UUID")

    def test_enable_does_not_regenerate_ws_path_if_exists(self):
        """Повторный enable НЕ перегенерирует ws_path."""
        from chimera.modules.singbox_config import singbox_enable_vless_ws_cdn
        from chimera.modules.singbox_state import (
            singbox_state_init, singbox_state_get_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_enable_vless_ws_cdn(cdn_provider="cloudflare", host="vless.example.com")
            ib1 = singbox_state_get_inbound("vless_ws_cdn")
            path1 = ib1["ws_path"]
            singbox_enable_vless_ws_cdn(cdn_provider="cloudflare", host="vless.example.com")
            ib2 = singbox_state_get_inbound("vless_ws_cdn")
        self.assertEqual(path1, ib2["ws_path"])

    def test_enable_rejects_unknown_cdn_provider(self):
        from chimera.modules.singbox_config import singbox_enable_vless_ws_cdn
        from chimera.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            ok = singbox_enable_vless_ws_cdn(cdn_provider="unknown_provider", host="x")
        self.assertFalse(ok)

    def test_enable_rejects_cert_params(self):
        """Передача cert_path/key_path должна вызвать TypeError.

        Аналог fixed-логики shadowtls v4.22.3: поле не нужно — не принимаем.
        """
        from chimera.modules.singbox_config import singbox_enable_vless_ws_cdn
        from chimera.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            with self.assertRaises(TypeError):
                singbox_enable_vless_ws_cdn(
                    cdn_provider="cloudflare", host="x",
                    cert_path="/tmp/cert.pem",  # НЕ принимается
                )

    # ── Регрессия v4.22.3: enable не создаёт tls-полей в state ────────────

    def test_enable_does_not_create_tls_fields_in_state(self):
        """После enable в state не должно быть cert_path/key_path/cert_source."""
        from chimera.modules.singbox_config import singbox_enable_vless_ws_cdn
        from chimera.modules.singbox_state import (
            singbox_state_init, singbox_state_get_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_enable_vless_ws_cdn(cdn_provider="cloudflare", host="vless.example.com")
            ib = singbox_state_get_inbound("vless_ws_cdn")
        self.assertNotIn("cert_path", ib)
        self.assertNotIn("key_path", ib)
        self.assertNotIn("cert_source", ib)


# ─────────────────────────────────────────────────────────────────────────────
# 3. singbox_disable_vless_ws_cdn
# ─────────────────────────────────────────────────────────────────────────────

class TestDisableVlessWsCdn(unittest.TestCase):
    """singbox_disable_vless_ws_cdn."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("chimera.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
            patch("chimera.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("chimera.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
            patch("chimera.modules.singbox_config.SINGBOX_CONFIG_DIR", self._tmpdir / "sb"),
            patch("chimera.modules.singbox_config.SINGBOX_CONFIG_FILE", self._tmpdir / "sb" / "config.json"),
        ]

    def test_disable_sets_enabled_false(self):
        from chimera.modules.singbox_config import (
            singbox_enable_vless_ws_cdn, singbox_disable_vless_ws_cdn,
        )
        from chimera.modules.singbox_state import (
            singbox_state_init, singbox_state_get_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_enable_vless_ws_cdn(cdn_provider="cloudflare", host="x")
            singbox_disable_vless_ws_cdn()
            ib = singbox_state_get_inbound("vless_ws_cdn")
        self.assertFalse(ib["enabled"])

    def test_disable_preserves_other_fields(self):
        """Disable не должен стирать uuid/ws_path/host — только снимает enabled."""
        from chimera.modules.singbox_config import (
            singbox_enable_vless_ws_cdn, singbox_disable_vless_ws_cdn,
        )
        from chimera.modules.singbox_state import (
            singbox_state_init, singbox_state_get_inbound,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_enable_vless_ws_cdn(cdn_provider="cloudflare", host="vless.example.com")
            singbox_disable_vless_ws_cdn()
            ib = singbox_state_get_inbound("vless_ws_cdn")
        self.assertFalse(ib["enabled"])
        self.assertTrue(ib["uuid"])  # сохранён
        self.assertTrue(ib["ws_path"])  # сохранён
        self.assertEqual(ib["host"], "vless.example.com")  # сохранён
        self.assertEqual(ib["cdn_provider"], "cloudflare")  # сохранён


# ─────────────────────────────────────────────────────────────────────────────
# 4. Переключение cdn_provider без потери uuid/path/host
# ─────────────────────────────────────────────────────────────────────────────

class TestCdnProviderSwitch(unittest.TestCase):
    """Переключение cdn_provider между всеми тремя без потери секретов."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("chimera.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
            patch("chimera.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("chimera.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
            patch("chimera.modules.singbox_config.SINGBOX_CONFIG_DIR", self._tmpdir / "sb"),
            patch("chimera.modules.singbox_config.SINGBOX_CONFIG_FILE", self._tmpdir / "sb" / "config.json"),
        ]

    def test_switch_preserves_uuid_path_host(self):
        """Manual switch между CDN не должен регенерировать секреты."""
        from chimera.modules.singbox_config import singbox_enable_vless_ws_cdn
        from chimera.modules.singbox_state import (
            singbox_state_init, singbox_state_load,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            # Начнём с Cloudflare
            singbox_enable_vless_ws_cdn(cdn_provider="cloudflare", host="vless.example.com")
            state = singbox_state_load()
            ib1 = state["inbounds"]["vless_ws_cdn"]
            uuid1 = ib1["uuid"]
            path1 = ib1["ws_path"]
            host1 = ib1["host"]

            # Switch на Gcore — через enable с теми же параметрами
            singbox_enable_vless_ws_cdn(cdn_provider="gcore", host=host1)
            state = singbox_state_load()
            ib2 = state["inbounds"]["vless_ws_cdn"]

        self.assertEqual(ib2["cdn_provider"], "gcore")
        # Секреты сохранены
        self.assertEqual(ib2["uuid"], uuid1)
        self.assertEqual(ib2["ws_path"], path1)
        self.assertEqual(ib2["host"], host1)

    def test_switch_to_all_three_providers(self):
        """Переключение по цепочке cloudflare → gcore → bunny → cloudflare."""
        from chimera.modules.singbox_config import singbox_enable_vless_ws_cdn
        from chimera.modules.singbox_state import (
            singbox_state_init, singbox_state_load,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_enable_vless_ws_cdn(cdn_provider="cloudflare", host="vless.example.com")
            state = singbox_state_load()
            uuid_orig = state["inbounds"]["vless_ws_cdn"]["uuid"]
            path_orig = state["inbounds"]["vless_ws_cdn"]["ws_path"]

            for provider in ("gcore", "bunny", "cloudflare"):
                singbox_enable_vless_ws_cdn(cdn_provider=provider, host="vless.example.com")
                state = singbox_state_load()
                ib = state["inbounds"]["vless_ws_cdn"]
                self.assertEqual(ib["cdn_provider"], provider)
                # Секреты не изменились
                self.assertEqual(ib["uuid"], uuid_orig)
                self.assertEqual(ib["ws_path"], path_orig)
                self.assertEqual(ib["host"], "vless.example.com")


# ─────────────────────────────────────────────────────────────────────────────
# 5. singbox_generate_config — полный config.json с VLESS-WS-CDN
# ─────────────────────────────────────────────────────────────────────────────

class TestGenerateConfigWithVlessWsCdn(unittest.TestCase):
    """Реальный вызов singbox_generate_config() с vless_ws_cdn.enabled=True."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._config_dir = self._tmpdir / "sing-box"
        self._config_file = self._config_dir / "config.json"
        self._state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("chimera.modules.singbox_common.SINGBOX_CONFIG_DIR", self._config_dir),
            patch("chimera.modules.singbox_common.SINGBOX_CONFIG_FILE", self._config_file),
            patch("chimera.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
            patch("chimera.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("chimera.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
            patch("chimera.modules.singbox_config.SINGBOX_CONFIG_DIR", self._config_dir),
            patch("chimera.modules.singbox_config.SINGBOX_CONFIG_FILE", self._config_file),
        ]

    def test_generate_config_creates_vless_ws_cdn_inbound(self):
        """Реальный вызов singbox_generate_config() → парсинг config.json → проверка structure."""
        from chimera.modules.singbox_config import (
            singbox_generate_config, singbox_enable_vless_ws_cdn,
        )
        from chimera.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_enable_vless_ws_cdn(
                cdn_provider="cloudflare",
                host="vless.example.com",
                ws_path="/my-test-path",
                uuid_val="11111111-1111-1111-1111-111111111111",
            )
            ok = singbox_generate_config()
        self.assertTrue(ok)
        self.assertTrue(self._config_file.exists())
        cfg = json.loads(self._config_file.read_text())
        # Найти vless_ws_cdn inbound
        vless_inbounds = [i for i in cfg["inbounds"] if i["type"] == "vless"]
        self.assertEqual(len(vless_inbounds), 1)
        ib = vless_inbounds[0]
        # Критичные проверки
        self.assertEqual(ib["type"], "vless")
        self.assertEqual(ib["transport"]["type"], "ws")
        self.assertEqual(ib["transport"]["path"], "/my-test-path")
        self.assertEqual(ib["transport"]["headers"]["Host"], "vless.example.com")
        self.assertEqual(ib["users"][0]["uuid"], "11111111-1111-1111-1111-111111111111")
        # ОТСУТСТВИЕ tls — критично (регрессия v4.22.3)
        self.assertNotIn("tls", ib)

    def test_generate_config_skips_vless_ws_cdn_when_disabled(self):
        """При enabled=False singbox_generate_config() не добавляет vless_ws_cdn inbound."""
        from chimera.modules.singbox_config import singbox_generate_config
        from chimera.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            # vless_ws_cdn.disabled по умолчанию
            singbox_generate_config()
        cfg = json.loads(self._config_file.read_text())
        vless_inbounds = [i for i in cfg["inbounds"] if i["type"] == "vless"]
        self.assertEqual(vless_inbounds, [],
                         "При enabled=False vless_ws_cdn inbound не должен добавляться")

    def test_generate_config_with_only_vless_ws_cdn(self):
        """Только VLESS-WS-CDN включён — в config.json ровно 1 inbound."""
        from chimera.modules.singbox_config import (
            singbox_generate_config, singbox_enable_vless_ws_cdn,
        )
        from chimera.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_enable_vless_ws_cdn(cdn_provider="gcore", host="test.example.com")
            singbox_generate_config()
        cfg = json.loads(self._config_file.read_text())
        self.assertEqual(len(cfg["inbounds"]), 1)
        self.assertEqual(cfg["inbounds"][0]["type"], "vless")


# ─────────────────────────────────────────────────────────────────────────────
# 6. singbox_validate_config — с реальным бинарником (skip если недоступен)
# ─────────────────────────────────────────────────────────────────────────────

class TestValidateConfigWithRealBinary(unittest.TestCase):
    """Реальный запуск sing-box check -c <generated config>.

    НЕ мок subprocess — если бинарник недоступен в тестовом окружении, skip
    с explicit причиной, а не тихий pass.
    """

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._config_dir = self._tmpdir / "sing-box"
        self._config_file = self._config_dir / "config.json"
        self._state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("chimera.modules.singbox_common.SINGBOX_CONFIG_DIR", self._config_dir),
            patch("chimera.modules.singbox_common.SINGBOX_CONFIG_FILE", self._config_file),
            patch("chimera.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
            patch("chimera.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("chimera.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
            patch("chimera.modules.singbox_config.SINGBOX_CONFIG_DIR", self._config_dir),
            patch("chimera.modules.singbox_config.SINGBOX_CONFIG_FILE", self._config_file),
        ]

    def test_generated_config_passes_singbox_check(self):
        """Сгенерированный config.json проходит `sing-box check -c ...`.

        Skip если sing-box бинарник недоступен — НЕ тихий pass.
        """
        from chimera.modules.singbox_common import _singbox_binary_exists, SINGBOX_BINARY
        if not _singbox_binary_exists():
            self.skipTest(f"sing-box binary not available at {SINGBOX_BINARY} — "
                         "cannot run real `sing-box check`. Install sing-box to enable this test.")
        from chimera.modules.singbox_config import (
            singbox_generate_config, singbox_validate_config,
            singbox_enable_vless_ws_cdn,
        )
        from chimera.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_enable_vless_ws_cdn(
                cdn_provider="cloudflare",
                host="vless.example.com",
                ws_path="/test-path",
                uuid_val="11111111-1111-1111-1111-111111111111",
            )
            singbox_generate_config()
            ok = singbox_validate_config()
        self.assertTrue(ok, "sing-box check должен пройти на сгенерированном конфиге")


# ─────────────────────────────────────────────────────────────────────────────
# 7. CDN_PROVIDERS — структура
# ─────────────────────────────────────────────────────────────────────────────

class TestCdnProvidersRegistry(unittest.TestCase):
    """CDN_PROVIDERS — структура, наличие инструкций для всех трёх."""

    def setUp(self):
        _setup_core()

    def test_has_all_three_providers(self):
        from chimera.modules.singbox_common import CDN_PROVIDERS
        for provider in ("cloudflare", "gcore", "bunny"):
            self.assertIn(provider, CDN_PROVIDERS,
                          f"CDN_PROVIDERS должен содержать {provider}")

    def test_each_provider_has_display_name(self):
        from chimera.modules.singbox_common import CDN_PROVIDERS
        for key, meta in CDN_PROVIDERS.items():
            self.assertIn("display_name", meta,
                          f"{key} должен иметь display_name")
            self.assertIsInstance(meta["display_name"], str)
            self.assertTrue(meta["display_name"])

    def test_each_provider_has_instructions(self):
        from chimera.modules.singbox_common import CDN_PROVIDERS
        for key, meta in CDN_PROVIDERS.items():
            self.assertIn("instructions", meta,
                          f"{key} должен иметь instructions")
            self.assertIsInstance(meta["instructions"], list)
            self.assertGreater(len(meta["instructions"]), 3,
                               f"{key} должен иметь минимум 4 строки инструкций")

    def test_cloudflare_instructions_mention_proxied_dns(self):
        from chimera.modules.singbox_common import CDN_PROVIDERS
        instructions = CDN_PROVIDERS["cloudflare"]["instructions"]
        full_text = " ".join(instructions).lower()
        self.assertIn("proxied", full_text,
                      "Cloudflare instructions должны упоминать Proxied DNS")
        self.assertIn("dns", full_text)

    def test_bunny_instructions_mention_origin_port(self):
        from chimera.modules.singbox_common import CDN_PROVIDERS
        instructions = CDN_PROVIDERS["bunny"]["instructions"]
        full_text = " ".join(instructions).lower()
        self.assertIn("origin port", full_text,
                      "Bunny.net instructions должны упоминать Origin Port field")

    def test_default_port_vless_ws_cdn_is_8080(self):
        """v4.23.1: default port = 8080 (Cloudflare HTTP port list, Flexible mode)."""
        from chimera.modules.singbox_common import DEFAULT_PORT_VLESS_WS_CDN
        self.assertEqual(DEFAULT_PORT_VLESS_WS_CDN, 8080)


# ─────────────────────────────────────────────────────────────────────────────
# 8. State init — секция vless_ws_cdn
# ─────────────────────────────────────────────────────────────────────────────

class TestStateInitVlessWsCdn(unittest.TestCase):
    """singbox_state_init() создаёт секцию vless_ws_cdn с correct defaults."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("chimera.modules.singbox_common.SINGBOX_STATE_FILE", self._state),
            patch("chimera.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("chimera.modules.singbox_state.SINGBOX_STATE_FILE", self._state),
        ]

    def test_init_creates_vless_ws_cdn_section(self):
        from chimera.modules.singbox_state import singbox_state_init, singbox_state_load
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            state = singbox_state_load()
        self.assertIn("vless_ws_cdn", state["inbounds"])

    def test_init_vless_ws_cdn_disabled_by_default(self):
        from chimera.modules.singbox_state import singbox_state_init, singbox_state_load
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            state = singbox_state_load()
        self.assertFalse(state["inbounds"]["vless_ws_cdn"]["enabled"])

    def test_init_vless_ws_cdn_has_required_fields(self):
        from chimera.modules.singbox_state import singbox_state_init, singbox_state_load
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            state = singbox_state_load()
        ib = state["inbounds"]["vless_ws_cdn"]
        for field in ("enabled", "listen", "listen_port", "uuid",
                      "ws_path", "host", "cdn_provider"):
            self.assertIn(field, ib, f"vless_ws_cdn state missing field: {field}")

    def test_init_vless_ws_cdn_does_not_have_cert_fields(self):
        """v4.23: state init НЕ создаёт cert_path/key_path/cert_source для vless_ws_cdn.

        Регрессия v4.22.3 (ShadowTLS): поле не нужно — не создаём.
        """
        from chimera.modules.singbox_state import singbox_state_init, singbox_state_load
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            state = singbox_state_load()
        ib = state["inbounds"]["vless_ws_cdn"]
        self.assertNotIn("cert_path", ib)
        self.assertNotIn("key_path", ib)
        self.assertNotIn("cert_source", ib)
        self.assertNotIn("cert_sha256", ib)

    def test_init_vless_ws_cdn_default_port_8080(self):
        """v4.23.1: default port changed to 8080 (Cloudflare HTTP port list)."""
        from chimera.modules.singbox_state import singbox_state_init, singbox_state_load
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            state = singbox_state_load()
        self.assertEqual(state["inbounds"]["vless_ws_cdn"]["listen_port"], 8080)


if __name__ == "__main__":
    unittest.main(verbosity=2)
