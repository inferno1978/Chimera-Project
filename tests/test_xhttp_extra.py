#!/usr/bin/env python3
"""
tests/test_xhttp_extra.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/xhttp_extra.py — персистенс дополнительного
VLESS+xHTTP+TLS инбаунда с выделенным клиентом (инцидент 05.11.2026:
generate_* стирал инбаунд при каждой пересборке).

Покрывает:
  1. xhttp_extra_state_load — чтение xhttp_extra_* ключей
  2. xhttp_extra_state_save — merge с flock, только свои ключи
  3. _state_sane / _clients_valid — валидация состояния
  4. inject_xhttp_extra_inbound — добавление/идентичность/замена/удаление
  5. xhttp_extra_managed_tags — пусто при выключенном, {tag} при включённом
  6. restore_xhttp_extra_if_enabled — None/восстановление/уже на месте/
     битое состояние/отсутствие config
  7. xhttp_extra_seed_from_live_config — извлечение параметров из живого
     конфига в state
  8. xhttp_extra_disable — удаление инбаунда + флаг в state
  9. users_manager-интеграция — три точки синхронизации clients
     (_users_patch_config_no_restart / _users_apply_to_config /
     _unified_save_users) пропускают managed-тег (регрессия инцидента:
     выделенный клиент не должен затираться панельными юзерами)
"""
from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Эталонный паттерн из tests/test_pq_vless.py / test_users_manager.py."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core


_UUID = "0d1907fd-ca00-4a4b-942c-cf25644e5b03"
_UUID2 = "11111111-2222-3333-4444-555555555555"


def _sane_state() -> dict:
    """Валидное состояние: все ключи, certs указывают на существующие файлы."""
    return {
        "xhttp_extra_enabled": True,
        "xhttp_extra_port": 4443,
        "xhttp_extra_path": "/abc123def456",
        "xhttp_extra_host": "example.com",
        "xhttp_extra_server_name": "example.com",
        "xhttp_extra_cert_file": "___CERT___",
        "xhttp_extra_key_file": "___KEY___",
        "xhttp_extra_clients": [{"id": _UUID, "email": "xhttp@example.com"}],
    }


class _TmpBase(unittest.TestCase):
    """tmpdir + state/config/cert фикстуры с патчем констант модуля."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"
        self._cfg = self._tmpdir / "config.json"
        self._cert = self._tmpdir / "fullchain.pem"
        self._key = self._tmpdir / "privkey.pem"
        self._cert.write_text("CERT")
        self._key.write_text("KEY")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _st(self, **over):
        st = _sane_state()
        st["xhttp_extra_cert_file"] = str(self._cert)
        st["xhttp_extra_key_file"] = str(self._key)
        st.update(over)
        return st

    def _patch_module(self):
        import chimera.modules.xhttp_extra as xhe
        return patch.multiple(xhe, STATE_FILE=self._state,
                              XRAY_CONFIG_PATHS=[self._cfg])

    def _write_state(self, st: dict):
        self._state.write_text(json.dumps(st))

    def _write_cfg(self, inbounds: list):
        self._cfg.write_text(json.dumps({"inbounds": inbounds}))


# ── 1. state_load ────────────────────────────────────────────────────────────
class TestStateLoad(_TmpBase):

    def test_returns_empty_when_no_file(self):
        from chimera.modules.xhttp_extra import xhttp_extra_state_load
        with self._patch_module():
            self.assertEqual(xhttp_extra_state_load(), {})

    def test_returns_empty_when_corrupt(self):
        from chimera.modules.xhttp_extra import xhttp_extra_state_load
        self._state.write_text("{invalid")
        with self._patch_module():
            self.assertEqual(xhttp_extra_state_load(), {})

    def test_returns_only_own_keys(self):
        from chimera.modules.xhttp_extra import xhttp_extra_state_load
        self._write_state({**self._st(), "uuid": "abc", "domain": "x.com"})
        with self._patch_module():
            loaded = xhttp_extra_state_load()
        self.assertNotIn("uuid", loaded)
        self.assertNotIn("domain", loaded)
        self.assertEqual(loaded["xhttp_extra_port"], 4443)
        self.assertTrue(loaded["xhttp_extra_enabled"])

    def test_missing_keys_absent_not_none(self):
        from chimera.modules.xhttp_extra import xhttp_extra_state_load
        self._write_state({"xhttp_extra_enabled": True})
        with self._patch_module():
            loaded = xhttp_extra_state_load()
        self.assertEqual(loaded, {"xhttp_extra_enabled": True})


# ── 2. state_save ────────────────────────────────────────────────────────────
class TestStateSave(_TmpBase):

    def test_creates_file_when_missing(self):
        """В отличие от pq_state_save — файл СОЗДАЁТСЯ: seed обязан
        работать и как disaster-recovery (state.json потерян)."""
        from chimera.modules.xhttp_extra import xhttp_extra_state_save
        with self._patch_module():
            xhttp_extra_state_save({"xhttp_extra_enabled": True})
        st = json.loads(self._state.read_text())
        self.assertTrue(st["xhttp_extra_enabled"])

    def test_merges_own_keys_preserving_others(self):
        from chimera.modules.xhttp_extra import xhttp_extra_state_save
        self._state.write_text(json.dumps(
            {"uuid": "keep-me", "xhttp_extra_port": 4443}))
        with self._patch_module():
            xhttp_extra_state_save({"xhttp_extra_enabled": True})
        st = json.loads(self._state.read_text())
        self.assertEqual(st["uuid"], "keep-me")
        self.assertEqual(st["xhttp_extra_port"], 4443)
        self.assertTrue(st["xhttp_extra_enabled"])

    def test_does_not_write_foreign_keys(self):
        from chimera.modules.xhttp_extra import xhttp_extra_state_save
        self._state.write_text(json.dumps({"uuid": "u"}))
        with self._patch_module():
            xhttp_extra_state_save({"foreign_key": "x",
                                    "xhttp_extra_host": "example.com"})
        st = json.loads(self._state.read_text())
        self.assertNotIn("foreign_key", st)
        self.assertEqual(st["xhttp_extra_host"], "example.com")


# ── 3. валидация ─────────────────────────────────────────────────────────────
class TestStateSane(_TmpBase):

    def test_sane_state_passes(self):
        from chimera.modules.xhttp_extra import _state_sane
        ok, why = _state_sane(self._st())
        self.assertTrue(ok, why)

    def test_bad_port(self):
        from chimera.modules.xhttp_extra import _state_sane
        for bad in (None, "4443", 0, 70000):
            ok, why = _state_sane(self._st(xhttp_extra_port=bad))
            self.assertFalse(ok)
            self.assertIn("port", why)

    def test_bad_path(self):
        from chimera.modules.xhttp_extra import _state_sane
        ok, why = _state_sane(self._st(xhttp_extra_path="no-slash"))
        self.assertFalse(ok)
        self.assertIn("path", why)

    def test_missing_host(self):
        from chimera.modules.xhttp_extra import _state_sane
        ok, why = _state_sane(self._st(xhttp_extra_host=""))
        self.assertFalse(ok)
        self.assertIn("host", why)

    def test_missing_cert_files(self):
        from chimera.modules.xhttp_extra import _state_sane
        ok, why = _state_sane(self._st(xhttp_extra_cert_file="/nonexistent/x.pem"))
        self.assertFalse(ok)
        self.assertIn("cert_file", why)
        ok, why = _state_sane(self._st(xhttp_extra_key_file="/nonexistent/k.pem"))
        self.assertFalse(ok)
        self.assertIn("key_file", why)

    def test_bad_clients(self):
        from chimera.modules.xhttp_extra import _state_sane
        for bad in ([], "not-a-list", [{"id": "not-uuid"}], [{"email": "x"}]):
            ok, why = _state_sane(self._st(xhttp_extra_clients=bad))
            self.assertFalse(ok, f"clients={bad!r} должен быть невалиден")
            self.assertIn("clients", why)

    def test_clients_without_email_valid(self):
        from chimera.modules.xhttp_extra import _state_sane
        ok, why = _state_sane(
            self._st(xhttp_extra_clients=[{"id": _UUID}]))
        self.assertTrue(ok, why)


# ── 4. inject / remove ───────────────────────────────────────────────────────
class TestInjectRemove(_TmpBase):

    def test_inject_appends_when_absent(self):
        from chimera.modules.xhttp_extra import (
            inject_xhttp_extra_inbound, has_xhttp_extra_inbound)
        cfg = {"inbounds": [{"tag": "inbound-vless", "port": 443}]}
        changed = inject_xhttp_extra_inbound(cfg, self._st())
        self.assertTrue(changed)
        self.assertTrue(has_xhttp_extra_inbound(cfg))
        self.assertEqual(len(cfg["inbounds"]), 2)
        ib = cfg["inbounds"][1]
        self.assertEqual(ib["tag"], "inbound-vless-xhttp")
        self.assertEqual(ib["port"], 4443)
        self.assertEqual(ib["streamSettings"]["network"], "xhttp")
        self.assertEqual(ib["streamSettings"]["security"], "tls")
        self.assertEqual(ib["streamSettings"]["xhttpSettings"]["path"],
                         "/abc123def456")
        self.assertEqual(ib["settings"]["clients"][0]["id"], _UUID)

    def test_inject_identical_returns_false(self):
        from chimera.modules.xhttp_extra import inject_xhttp_extra_inbound
        cfg = {"inbounds": []}
        inject_xhttp_extra_inbound(cfg, self._st())
        self.assertFalse(inject_xhttp_extra_inbound(cfg, self._st()))

    def test_inject_replaces_when_diverged(self):
        from chimera.modules.xhttp_extra import inject_xhttp_extra_inbound
        cfg = {"inbounds": []}
        inject_xhttp_extra_inbound(cfg, self._st())
        # «Кто-то» поменял порт в живом конфиге
        cfg["inbounds"][0]["port"] = 8443
        changed = inject_xhttp_extra_inbound(cfg, self._st())
        self.assertTrue(changed)
        self.assertEqual(cfg["inbounds"][0]["port"], 4443)

    def test_inject_creates_inbounds_key(self):
        from chimera.modules.xhttp_extra import inject_xhttp_extra_inbound
        cfg = {}
        changed = inject_xhttp_extra_inbound(cfg, self._st())
        self.assertTrue(changed)
        self.assertEqual(len(cfg["inbounds"]), 1)

    def test_built_structure_matches_expected_shape(self):
        """Структура 1:1 с инбаундом, жившим в config.json до персистенса."""
        from chimera.modules.xhttp_extra import inject_xhttp_extra_inbound
        cfg = {}
        inject_xhttp_extra_inbound(cfg, self._st())
        ib = cfg["inbounds"][0]
        self.assertEqual(set(ib.keys()),
                         {"tag", "port", "listen", "protocol", "settings",
                          "sniffing", "streamSettings"})
        self.assertEqual(ib["listen"], "::")
        self.assertEqual(ib["settings"]["decryption"], "none")
        self.assertEqual(ib["sniffing"]["destOverride"], ["http", "tls", "quic"])
        self.assertFalse(ib["sniffing"]["metadataOnly"])
        tls = ib["streamSettings"]["tlsSettings"]
        self.assertEqual(tls["serverName"], "example.com")
        self.assertEqual(tls["alpn"], ["h2", "http/1.1"])
        self.assertEqual(tls["certificates"],
                         [{"certificateFile": str(self._cert),
                           "keyFile": str(self._key)}])

    def test_server_name_falls_back_to_host(self):
        from chimera.modules.xhttp_extra import inject_xhttp_extra_inbound
        cfg = {}
        inject_xhttp_extra_inbound(cfg, self._st(xhttp_extra_server_name=""))
        self.assertEqual(
            cfg["inbounds"][0]["streamSettings"]["tlsSettings"]["serverName"],
            "example.com")

    def test_remove(self):
        from chimera.modules.xhttp_extra import (
            inject_xhttp_extra_inbound, remove_xhttp_extra_inbound)
        cfg = {"inbounds": [{"tag": "inbound-vless"},
                            {"tag": "inbound-vless-xhttp"}]}
        self.assertTrue(remove_xhttp_extra_inbound(cfg))
        self.assertEqual([i["tag"] for i in cfg["inbounds"]], ["inbound-vless"])
        self.assertFalse(remove_xhttp_extra_inbound(cfg))


# ── 5. managed_tags ──────────────────────────────────────────────────────────
class TestManagedTags(_TmpBase):

    def test_empty_when_disabled(self):
        from chimera.modules.xhttp_extra import xhttp_extra_managed_tags
        with self._patch_module():
            self._write_state(self._st(xhttp_extra_enabled=False))
            self.assertEqual(xhttp_extra_managed_tags(), set())

    def test_empty_when_no_state(self):
        from chimera.modules.xhttp_extra import xhttp_extra_managed_tags
        with self._patch_module():
            self.assertEqual(xhttp_extra_managed_tags(), set())

    def test_tag_when_enabled(self):
        from chimera.modules.xhttp_extra import (
            xhttp_extra_managed_tags, XHTTP_EXTRA_TAG)
        with self._patch_module():
            self._write_state(self._st())
            self.assertEqual(xhttp_extra_managed_tags(), {XHTTP_EXTRA_TAG})


# ── 6. restore ───────────────────────────────────────────────────────────────
class TestRestore(_TmpBase):

    def test_none_when_disabled(self):
        from chimera.modules.xhttp_extra import restore_xhttp_extra_if_enabled
        with self._patch_module():
            self._write_state(self._st(xhttp_extra_enabled=False))
            self.assertIsNone(restore_xhttp_extra_if_enabled())

    def test_none_when_no_state(self):
        from chimera.modules.xhttp_extra import restore_xhttp_extra_if_enabled
        with self._patch_module():
            self.assertIsNone(restore_xhttp_extra_if_enabled())

    def test_false_when_no_config(self):
        from chimera.modules.xhttp_extra import restore_xhttp_extra_if_enabled
        with self._patch_module():
            self._write_state(self._st())
            ok, msg = restore_xhttp_extra_if_enabled()
        self.assertFalse(ok)
        self.assertIn("config.json", msg)

    def test_restores_after_rebuild(self):
        """ГЛАВНЫЙ сценарий: generate_* стёр инбаунд — хук вернул его.
        Реальная запись на диск (_find_xray_bin → None: без xray -test,
        детерминированно на любом раннере)."""
        from chimera.modules.xhttp_extra import restore_xhttp_extra_if_enabled
        with self._patch_module():
            self._write_state(self._st())
            # Свежий конфиг после пересборки: только основной инбаунд
            self._write_cfg([{"tag": "inbound-vless", "port": 443}])
            with patch("chimera.modules.xhttp_extra._find_xray_bin",
                       return_value=None):
                ok, msg = restore_xhttp_extra_if_enabled()
            self.assertTrue(ok, msg)
            cfg = json.loads(self._cfg.read_text())
            self.assertEqual(len(cfg["inbounds"]), 2)
            self.assertEqual(cfg["inbounds"][1]["tag"], "inbound-vless-xhttp")
        # last_applied зафиксирован
        st = json.loads(self._state.read_text())
        self.assertTrue(st.get("xhttp_extra_last_applied"))

    def test_already_in_place_no_write(self):
        from chimera.modules.xhttp_extra import (
            restore_xhttp_extra_if_enabled, inject_xhttp_extra_inbound)
        with self._patch_module():
            self._write_state(self._st())
            cfg = {"inbounds": [{"tag": "inbound-vless"}]}
            inject_xhttp_extra_inbound(cfg, self._st())
            self._write_cfg(cfg["inbounds"])
            with patch("chimera.modules.xhttp_extra._write_and_test",
                       return_value=None) as wt:
                ok, msg = restore_xhttp_extra_if_enabled()
            self.assertTrue(ok)
            self.assertIn("уже на месте", msg)
            wt.assert_not_called()

    def test_replaces_diverged_inbound(self):
        """Инбаунд есть, но параметры разошлись — state источник истины."""
        from chimera.modules.xhttp_extra import restore_xhttp_extra_if_enabled
        with self._patch_module():
            self._write_state(self._st())
            stale = {
                "tag": "inbound-vless-xhttp", "port": 9443,
                "protocol": "vless", "settings": {"clients": []},
            }
            self._write_cfg([stale])
            with patch("chimera.modules.xhttp_extra._find_xray_bin",
                       return_value=None):
                ok, msg = restore_xhttp_extra_if_enabled()
            self.assertTrue(ok, msg)
            cfg = json.loads(self._cfg.read_text())
            self.assertEqual(cfg["inbounds"][0]["port"], 4443)

    def test_broken_state_no_config_touch(self):
        from chimera.modules.xhttp_extra import restore_xhttp_extra_if_enabled
        with self._patch_module():
            # enabled, но порт/клиенты потеряны
            self._write_state({"xhttp_extra_enabled": True,
                               "xhttp_extra_host": "example.com"})
            self._write_cfg([{"tag": "inbound-vless"}])
            before = self._cfg.read_text()
            with patch("chimera.modules.xhttp_extra._write_and_test",
                       return_value=None) as wt:
                ok, msg = restore_xhttp_extra_if_enabled()
            self.assertFalse(ok)
            self.assertIn("повреждено", msg)
            wt.assert_not_called()
            self.assertEqual(self._cfg.read_text(), before)

    def test_write_failure_propagates(self):
        from chimera.modules.xhttp_extra import restore_xhttp_extra_if_enabled
        with self._patch_module():
            self._write_state(self._st())
            self._write_cfg([{"tag": "inbound-vless"}])
            with patch("chimera.modules.xhttp_extra._write_and_test",
                       return_value="xray -test провалился: boom"):
                ok, msg = restore_xhttp_extra_if_enabled()
        self.assertFalse(ok)
        self.assertIn("провалился", msg)


# ── 7. seed из живого конфига ────────────────────────────────────────────────
class TestSeedFromLiveConfig(_TmpBase):

    def _live_inbound(self) -> dict:
        return {
            "tag": "inbound-vless-xhttp", "port": 4443, "listen": "::",
            "protocol": "vless",
            "settings": {
                "clients": [{"id": _UUID, "email": "xhttp@example.com"}],
                "decryption": "none",
            },
            "sniffing": {"enabled": True,
                         "destOverride": ["http", "tls", "quic"],
                         "metadataOnly": False, "routeOnly": False},
            "streamSettings": {
                "network": "xhttp",
                "xhttpSettings": {"path": "/abc123def456",
                                  "host": "example.com"},
                "security": "tls",
                "tlsSettings": {
                    "serverName": "example.com",
                    "alpn": ["h2", "http/1.1"],
                    "certificates": [{"certificateFile": str(self._cert),
                                      "keyFile": str(self._key)}],
                },
            },
        }

    def test_seed_extracts_all_params(self):
        from chimera.modules.xhttp_extra import xhttp_extra_seed_from_live_config
        self._write_cfg([{"tag": "inbound-vless"}, self._live_inbound()])
        with self._patch_module():
            ok, msg = xhttp_extra_seed_from_live_config(self._cfg)
        self.assertTrue(ok, msg)
        st = json.loads(self._state.read_text())
        self.assertTrue(st["xhttp_extra_enabled"])
        self.assertEqual(st["xhttp_extra_port"], 4443)
        self.assertEqual(st["xhttp_extra_path"], "/abc123def456")
        self.assertEqual(st["xhttp_extra_host"], "example.com")
        self.assertEqual(st["xhttp_extra_server_name"], "example.com")
        self.assertEqual(st["xhttp_extra_cert_file"], str(self._cert))
        self.assertEqual(st["xhttp_extra_key_file"], str(self._key))
        self.assertEqual(st["xhttp_extra_clients"],
                         [{"id": _UUID, "email": "xhttp@example.com"}])
        self.assertEqual(st["xhttp_extra_alpn"], ["h2", "http/1.1"])

    def test_seed_then_restore_roundtrip(self):
        """Seed из живого конфига → снести инбаунд → restore вернул 1:1."""
        from chimera.modules.xhttp_extra import (
            xhttp_extra_seed_from_live_config, restore_xhttp_extra_if_enabled)
        live = self._live_inbound()
        self._write_cfg([{"tag": "inbound-vless"}, live])
        with self._patch_module():
            ok, _ = xhttp_extra_seed_from_live_config(self._cfg)
            self.assertTrue(ok)
            # «Пересборка» стёрла дополнительный инбаунд
            self._write_cfg([{"tag": "inbound-vless"}])
            with patch("chimera.modules.xhttp_extra._find_xray_bin",
                       return_value=None):
                ok, msg = restore_xhttp_extra_if_enabled()
            self.assertTrue(ok, msg)
        cfg = json.loads(self._cfg.read_text())
        self.assertEqual(cfg["inbounds"][1], live)

    def test_seed_fails_when_no_inbound(self):
        from chimera.modules.xhttp_extra import xhttp_extra_seed_from_live_config
        self._write_cfg([{"tag": "inbound-vless"}])
        with self._patch_module():
            ok, msg = xhttp_extra_seed_from_live_config(self._cfg)
        self.assertFalse(ok)
        self.assertIn("не найден", msg)

    def test_seed_fails_on_inconsistent_live(self):
        """Живой инбаунд без валидных клиентов — seed отменён."""
        from chimera.modules.xhttp_extra import xhttp_extra_seed_from_live_config
        bad = self._live_inbound()
        bad["settings"]["clients"] = []
        self._write_cfg([bad])
        with self._patch_module():
            ok, msg = xhttp_extra_seed_from_live_config(self._cfg)
        self.assertFalse(ok)
        self.assertIn("clients", msg)


# ── 8. disable ───────────────────────────────────────────────────────────────
class TestDisable(_TmpBase):

    def test_disable_removes_inbound_and_flag(self):
        from chimera.modules.xhttp_extra import (
            xhttp_extra_seed_from_live_config, xhttp_extra_disable)
        live = {
            "tag": "inbound-vless-xhttp", "port": 4443,
            "protocol": "vless",
            "settings": {"clients": [{"id": _UUID,
                                      "email": "xhttp@example.com"}],
                         "decryption": "none"},
            "streamSettings": {
                "network": "xhttp",
                "xhttpSettings": {"path": "/abc123def456",
                                  "host": "example.com"},
                "security": "tls",
                "tlsSettings": {
                    "serverName": "example.com",
                    "certificates": [{"certificateFile": str(self._cert),
                                      "keyFile": str(self._key)}],
                },
            },
        }
        self._write_cfg([{"tag": "inbound-vless"}, live])
        with self._patch_module():
            ok, _ = xhttp_extra_seed_from_live_config(self._cfg)
            self.assertTrue(ok)
            with patch("chimera.modules.xhttp_extra._find_xray_bin",
                       return_value=None):
                ok, msg = xhttp_extra_disable()
            self.assertTrue(ok, msg)
        cfg = json.loads(self._cfg.read_text())
        self.assertEqual([i["tag"] for i in cfg["inbounds"]],
                         ["inbound-vless"])
        st = json.loads(self._state.read_text())
        self.assertFalse(st["xhttp_extra_enabled"])
        # Параметры сохранены для повторного включения
        self.assertEqual(st["xhttp_extra_port"], 4443)


# ── 9. users_manager-интеграция (регрессия инцидента) ────────────────────────
class TestUsersManagerSkip(_TmpBase):
    """Три функции синхронизации clients пропускают managed-тег:
    выделенный клиент xHTTP-extra не затирается панельными юзерами."""

    def setUp(self):
        super().setUp()
        self._fake_core = _setup_core_in_sysmodules()
        self._fake_core.CONFIG_DIR = self._tmpdir
        # USERS_FILE вычислен при exec _core.py от реального CONFIG_DIR —
        # без переноса пишет в изолированный /etc/xray (ENOENT)
        self._fake_core.USERS_FILE = self._tmpdir / "users.json"
        self._fake_core.XTLS_FLOW = "xtls-rprx-vision"
        self._fake_core._set_config_owner = MagicMock()
        self._fake_core.warn = MagicMock()
        self._fake_core.XRAY_BIN = str(self._tmpdir / "xray-absent")
        self._users = [{"uuid": _UUID2, "email": "panel@example.com"}]

    def _write_two_inbound_cfg(self):
        """Основной REALITY-инбаунд + xHTTP-extra с выделенным клиентом."""
        from chimera.modules.xhttp_extra import inject_xhttp_extra_inbound
        cfg = {
            "inbounds": [{
                "tag": "inbound-vless", "port": 443, "protocol": "vless",
                "settings": {"clients": [{"id": _UUID2,
                                          "email": "panel@example.com"}]},
                "streamSettings": {"network": "tcp", "security": "reality",
                                   "realitySettings": {"serverNames":
                                                       ["example.com"]}},
            }],
        }
        inject_xhttp_extra_inbound(cfg, self._st())
        self._cfg.write_text(json.dumps(cfg))

    def _assert_split(self):
        cfg = json.loads(self._cfg.read_text())
        by_tag = {i["tag"]: i for i in cfg["inbounds"]}
        main_clients = by_tag["inbound-vless"]["settings"]["clients"]
        self.assertEqual([c["id"] for c in main_clients], [_UUID2])
        extra_clients = by_tag["inbound-vless-xhttp"]["settings"]["clients"]
        self.assertEqual([c["id"] for c in extra_clients], [_UUID])
        self.assertEqual(extra_clients[0]["email"], "xhttp@example.com")
        self.assertNotIn("flow", extra_clients[0])

    def test_patch_config_no_restart_skips_managed(self):
        from chimera.modules.users_manager import _users_patch_config_no_restart
        self._write_two_inbound_cfg()
        with self._patch_module():
            self._write_state(self._st())
            self.assertTrue(_users_patch_config_no_restart(self._users))
        self._assert_split()

    def test_unified_save_users_skips_managed(self):
        from chimera.modules.users_manager import _unified_save_users
        self._write_two_inbound_cfg()
        with self._patch_module():
            self._write_state(self._st())
            _unified_save_users(self._users)
        self._assert_split()

    def test_apply_to_config_skips_managed(self):
        from chimera.modules.users_manager import _users_apply_to_config
        self._write_two_inbound_cfg()
        # _users_apply_to_config тянет _run/_xray_safe_restart/
        # _nginx_restart_if_reality из core — мокаем их на fake-core,
        # иначе тест дёрнет реальный systemctl на живой ноде.
        self._fake_core._run = MagicMock(
            return_value=MagicMock(returncode=0, stdout="", stderr=""))
        self._fake_core._xray_safe_restart = MagicMock(return_value=True)
        self._fake_core._nginx_restart_if_reality = MagicMock()
        with self._patch_module():
            self._write_state(self._st())
            self.assertTrue(_users_apply_to_config(self._users))
        self._assert_split()

    def test_no_state_no_skip(self):
        """Без state (фича выключена) — старое поведение: все инбаунды
        с clients получают панельных юзеров (по этому и нужен скип)."""
        from chimera.modules.users_manager import _users_patch_config_no_restart
        self._write_two_inbound_cfg()
        with self._patch_module():
            # state.json не создан — managed_tags пуст
            self.assertTrue(_users_patch_config_no_restart(self._users))
        cfg = json.loads(self._cfg.read_text())
        by_tag = {i["tag"]: i for i in cfg["inbounds"]}
        extra = by_tag["inbound-vless-xhttp"]["settings"]["clients"]
        self.assertEqual([c["id"] for c in extra], [_UUID2])


if __name__ == "__main__":
    unittest.main(verbosity=2)
