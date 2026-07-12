#!/usr/bin/env python3
"""
tests/test_sni_dispatch_xray_patch.py
───────────────────────────────────────────────────────────────────────────────
Тесты для v4.23.8: автоматический патч config.json Xray для SNI-dispatch.

Покрывает:
  1. apply_reality_sni_dispatch_patch — меняет port/listen/sockopt на нужном inbound
  2. Идемпотентность — повторный вызов не ломает уже пропатченный конфиг
  3. realitySettings.dest НЕ тронут (критичный регресс-тест)
  4. Не трогает другие инбаунды в config.json
  5. Откат (revert) возвращает port/listen к исходным значениям
  6. Re-apply после регенерации (sni_dispatch_reapply_after_rebuild)
  7. AWG/xHTTP — патч явно отказывается применяться, не молчит
  8. Бэкап .pre-sni-dispatch создаётся при первом патче
───────────────────────────────────────────────────────────────────────────────
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


def _make_reality_config(server_port: int = 443,
                         reality_dest: str = "/dev/shm/test.socket",
                         extra_inbounds: list = None) -> dict:
    """Создаёт тестовый config.json Xray с REALITY-инбаундом (как generate_xray_config)."""
    inbounds = [{
        "tag":      "inbound-vless",
        "port":     server_port,
        "listen":   "::",
        "protocol": "vless",
        "settings": {
            "clients":     [{"id": "test-uuid", "email": "user@test.example"}],
            "decryption":  "none",
        },
        "sniffing": {
            "enabled":      True,
            "destOverride": ["http", "tls"],
            "metadataOnly": False,
        },
        "streamSettings": {
            "network":  "tcp",
            "sockopt":  {
                "tcpFastOpen":          True,
                "tcpKeepAliveInterval": 15,
                "tcpKeepAliveIdle":     60,
                "tcpUserTimeout":       10000,
                "tcpCongestion":        "bbr",
            },
            "security": "reality",
            "realitySettings": {
                "show":        False,
                "dest":        reality_dest,
                "xver":        1,
                "spiderX":     "",
                "serverNames": ["test.example.com"],
                "privateKey":  "test-private-key",
                "publicKey":   "test-public-key",
                "shortIds":    ["test-short-id"],
            },
        },
    }]
    if extra_inbounds:
        inbounds.extend(extra_inbounds)
    return {
        "log": {"loglevel": "warning"},
        "inbounds":  inbounds,
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "BLOCK"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [],
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
# 1. apply_reality_sni_dispatch_patch — меняет port/listen/sockopt
# ══════════════════════════════════════════════════════════════════════════════

class TestApplyPatchChangesCorrectFields(unittest.TestCase):
    """apply_reality_sni_dispatch_patch — меняет port/listen/acceptProxyProtocol."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._xray_cfg = self._tmpdir / "config.json"
        self._xray_cfg.write_text(json.dumps(_make_reality_config(), indent=2))
        self._sb_state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"
        self._main_state.write_text(json.dumps({
            "protocol_mode": "reality",
            "awg_exit_enabled": False,
            "server_port": 443,
        }))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_nginx._xray_config_paths",
                  return_value=[self._xray_cfg]),
            patch("vless_installer.modules.singbox_nginx._run",
                  return_value=MagicMock(returncode=0, stdout="active\n", stderr="")),
        ]

    def test_patch_changes_listen_to_loopback(self):
        from vless_installer.modules.singbox_nginx import apply_reality_sni_dispatch_patch
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            ok = apply_reality_sni_dispatch_patch(restart_xray=False)
        self.assertTrue(ok)
        cfg = json.loads(self._xray_cfg.read_text())
        ib = cfg["inbounds"][0]
        self.assertEqual(ib["listen"], "127.0.0.1",
                         "listen должен стать 127.0.0.1 после патча")

    def test_patch_changes_port_to_8442(self):
        from vless_installer.modules.singbox_nginx import apply_reality_sni_dispatch_patch
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            ok = apply_reality_sni_dispatch_patch(restart_xray=False)
        self.assertTrue(ok)
        cfg = json.loads(self._xray_cfg.read_text())
        ib = cfg["inbounds"][0]
        self.assertEqual(ib["port"], 8442,
                         "port должен стать 8442 (_REALITY_LOOPBACK_PORT) после патча")

    def test_patch_adds_acceptProxyProtocol_true(self):
        from vless_installer.modules.singbox_nginx import apply_reality_sni_dispatch_patch
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            ok = apply_reality_sni_dispatch_patch(restart_xray=False)
        self.assertTrue(ok)
        cfg = json.loads(self._xray_cfg.read_text())
        ib = cfg["inbounds"][0]
        sockopt = ib["streamSettings"]["sockopt"]
        self.assertIn("acceptProxyProtocol", sockopt,
                      "acceptProxyProtocol должен быть добавлен в sockopt")
        self.assertIs(sockopt["acceptProxyProtocol"], True,
                      "acceptProxyProtocol должен быть true")

    def test_patch_preserves_other_sockopt_fields(self):
        """tcpFastOpen, tcpCongestion и т.д. — НЕ должны быть потеряны."""
        from vless_installer.modules.singbox_nginx import apply_reality_sni_dispatch_patch
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            ok = apply_reality_sni_dispatch_patch(restart_xray=False)
        self.assertTrue(ok)
        cfg = json.loads(self._xray_cfg.read_text())
        sockopt = cfg["inbounds"][0]["streamSettings"]["sockopt"]
        self.assertEqual(sockopt["tcpFastOpen"], True)
        self.assertEqual(sockopt["tcpCongestion"], "bbr")
        self.assertEqual(sockopt["tcpKeepAliveInterval"], 15)


# ══════════════════════════════════════════════════════════════════════════════
# 2. Идемпотентность — повторный вызов не ломает конфиг
# ══════════════════════════════════════════════════════════════════════════════

class TestPatchIdempotent(unittest.TestCase):
    """Дублирующий/повторный вызов патча — идемпотентен."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._xray_cfg = self._tmpdir / "config.json"
        self._xray_cfg.write_text(json.dumps(_make_reality_config(), indent=2))
        self._sb_state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"
        self._main_state.write_text(json.dumps({
            "protocol_mode": "reality",
            "awg_exit_enabled": False,
        }))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_nginx._xray_config_paths",
                  return_value=[self._xray_cfg]),
            patch("vless_installer.modules.singbox_nginx._run",
                  return_value=MagicMock(returncode=0, stdout="active\n", stderr="")),
        ]

    def test_double_patch_is_idempotent(self):
        from vless_installer.modules.singbox_nginx import apply_reality_sni_dispatch_patch
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            ok1 = apply_reality_sni_dispatch_patch(restart_xray=False)
            ok2 = apply_reality_sni_dispatch_patch(restart_xray=False)
        self.assertTrue(ok1)
        self.assertTrue(ok2)
        cfg = json.loads(self._xray_cfg.read_text())
        ib = cfg["inbounds"][0]
        self.assertEqual(ib["listen"], "127.0.0.1")
        self.assertEqual(ib["port"], 8442)
        self.assertIs(ib["streamSettings"]["sockopt"]["acceptProxyProtocol"], True)

    def test_double_patch_does_not_create_second_backup(self):
        """Бэкап .pre-sni-dispatch создаётся только при первом патче."""
        from vless_installer.modules.singbox_nginx import apply_reality_sni_dispatch_patch
        backup = self._xray_cfg.with_suffix(".json.pre-sni-dispatch")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            apply_reality_sni_dispatch_patch(restart_xray=False)
            self.assertTrue(backup.exists(), "Бэкап должен быть создан при первом патче")
            backup_mtime_first = backup.stat().st_mtime
            import time as _t; _t.sleep(0.05)
            apply_reality_sni_dispatch_patch(restart_xray=False)
            backup_mtime_second = backup.stat().st_mtime
        self.assertEqual(backup_mtime_first, backup_mtime_second,
                         "Бэкап НЕ должен перезаписываться при повторном патче")

    def test_double_patch_does_not_overwrite_original_listen_in_state(self):
        """original_listen в state не должен перезаписываться при повторном патче."""
        from vless_installer.modules.singbox_nginx import (
            apply_reality_sni_dispatch_patch,
            singbox_state_get_sni_dispatch,
        )
        from vless_installer.modules.singbox_state import singbox_state_init
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            apply_reality_sni_dispatch_patch(restart_xray=False)
            sd1 = singbox_state_get_sni_dispatch()
            self.assertEqual(sd1.get("original_listen"), "::",
                             "original_listen должен быть '::' (до патча)")
            apply_reality_sni_dispatch_patch(restart_xray=False)
            sd2 = singbox_state_get_sni_dispatch()
            self.assertEqual(sd2.get("original_listen"), "::",
                             "original_listen НЕ должен измениться после второго патча")


# ══════════════════════════════════════════════════════════════════════════════
# 3. realitySettings.dest НЕ тронут (КРИТИЧНЫЙ регресс-тест)
# ══════════════════════════════════════════════════════════════════════════════

class TestRealityDestUntouched(unittest.TestCase):
    """realitySettings.dest — decoy-сокет, НЕ ТРОГАТЬ. Критичный регресс-тест."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._xray_cfg = self._tmpdir / "config.json"
        self._decoy_socket = "/dev/shm/test-decoy-12345.socket"
        self._xray_cfg.write_text(
            json.dumps(_make_reality_config(reality_dest=self._decoy_socket), indent=2)
        )
        self._sb_state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"
        self._main_state.write_text(json.dumps({
            "protocol_mode": "reality",
            "awg_exit_enabled": False,
        }))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_nginx._xray_config_paths",
                  return_value=[self._xray_cfg]),
            patch("vless_installer.modules.singbox_nginx._run",
                  return_value=MagicMock(returncode=0, stdout="active\n", stderr="")),
        ]

    def test_reality_dest_unchanged_after_patch(self):
        from vless_installer.modules.singbox_nginx import apply_reality_sni_dispatch_patch
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            apply_reality_sni_dispatch_patch(restart_xray=False)
        cfg = json.loads(self._xray_cfg.read_text())
        reality_settings = cfg["inbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(reality_settings["dest"], self._decoy_socket,
                         "realitySettings.dest НЕ должен измениться — это decoy-сокет")

    def test_reality_other_fields_unchanged(self):
        """Все поля realitySettings (кроме явно затронутых) — неизменны."""
        from vless_installer.modules.singbox_nginx import apply_reality_sni_dispatch_patch
        original_cfg = json.loads(self._xray_cfg.read_text())
        original_rs = dict(original_cfg["inbounds"][0]["streamSettings"]["realitySettings"])
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            apply_reality_sni_dispatch_patch(restart_xray=False)
        new_rs = json.loads(self._xray_cfg.read_text())["inbounds"][0]["streamSettings"]["realitySettings"]
        for key, value in original_rs.items():
            self.assertEqual(new_rs.get(key), value,
                             f"realitySettings.{key} не должен измениться")

    def test_reality_dest_unchanged_after_revert(self):
        from vless_installer.modules.singbox_nginx import (
            apply_reality_sni_dispatch_patch,
            revert_reality_sni_dispatch_patch,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            apply_reality_sni_dispatch_patch(restart_xray=False)
            # Удаляем бэкап чтобы проверить reverse-patch (не restore)
            backup = self._xray_cfg.with_suffix(".json.pre-sni-dispatch")
            if backup.exists():
                backup.unlink()
            revert_reality_sni_dispatch_patch(restart_xray=False)
        cfg = json.loads(self._xray_cfg.read_text())
        reality_settings = cfg["inbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(reality_settings["dest"], self._decoy_socket,
                         "realitySettings.dest НЕ должен измениться даже после revert")


# ══════════════════════════════════════════════════════════════════════════════
# 4. Не трогает другие инбаунды в config.json
# ══════════════════════════════════════════════════════════════════════════════

class TestPatchDoesNotTouchOtherInbounds(unittest.TestCase):
    """Патч меняет только REALITY-инбаунд, не трогает остальные."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._xray_cfg = self._tmpdir / "config.json"
        # Создаём конфиг с двумя инбаундами — REALITY и dokodemo (как Telemt)
        extra = [{
            "tag":      "dokodemo-in",
            "port":     12345,
            "listen":   "127.0.0.1",
            "protocol": "dokodemo",
            "settings": {"address": "127.0.0.1", "port": 5353, "network": "tcp"},
        }]
        self._xray_cfg.write_text(
            json.dumps(_make_reality_config(extra_inbounds=extra), indent=2)
        )
        self._sb_state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"
        self._main_state.write_text(json.dumps({
            "protocol_mode": "reality",
            "awg_exit_enabled": False,
        }))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_nginx._xray_config_paths",
                  return_value=[self._xray_cfg]),
            patch("vless_installer.modules.singbox_nginx._run",
                  return_value=MagicMock(returncode=0, stdout="active\n", stderr="")),
        ]

    def test_other_inbound_untouched(self):
        from vless_installer.modules.singbox_nginx import apply_reality_sni_dispatch_patch
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            apply_reality_sni_dispatch_patch(restart_xray=False)
        cfg = json.loads(self._xray_cfg.read_text())
        # REALITY patched
        reality_ib = next(ib for ib in cfg["inbounds"] if ib["tag"] == "inbound-vless")
        self.assertEqual(reality_ib["listen"], "127.0.0.1")
        self.assertEqual(reality_ib["port"], 8442)
        # dokodemo untouched
        dokodemo_ib = next(ib for ib in cfg["inbounds"] if ib["tag"] == "dokodemo-in")
        self.assertEqual(dokodemo_ib["listen"], "127.0.0.1",
                         "listen другого инбаунда не должен измениться")
        self.assertEqual(dokodemo_ib["port"], 12345,
                         "port другого инбаунда не должен измениться")
        self.assertNotIn("streamSettings", dokodemo_ib,
                         "У dokodemo не должно появиться streamSettings")


# ══════════════════════════════════════════════════════════════════════════════
# 5. Откат (revert) возвращает port/listen к исходным значениям
# ══════════════════════════════════════════════════════════════════════════════

class TestRevertRestoresOriginal(unittest.TestCase):
    """Откат (disable) возвращает port/listen к исходным значениям."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._xray_cfg = self._tmpdir / "config.json"
        # Используем нестандартный server_port (8443), чтобы проверить
        # что revert возвращает ИМЕННО его, а не хардкод 443
        self._original_port = 8443
        self._xray_cfg.write_text(
            json.dumps(_make_reality_config(server_port=self._original_port), indent=2)
        )
        self._sb_state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"
        self._main_state.write_text(json.dumps({
            "protocol_mode": "reality",
            "awg_exit_enabled": False,
            "server_port": self._original_port,
        }))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_nginx._xray_config_paths",
                  return_value=[self._xray_cfg]),
            patch("vless_installer.modules.singbox_nginx._run",
                  return_value=MagicMock(returncode=0, stdout="active\n", stderr="")),
        ]

    def test_revert_via_backup_restores_original(self):
        from vless_installer.modules.singbox_nginx import (
            apply_reality_sni_dispatch_patch,
            revert_reality_sni_dispatch_patch,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            apply_reality_sni_dispatch_patch(restart_xray=False)
            revert_reality_sni_dispatch_patch(restart_xray=False)
        cfg = json.loads(self._xray_cfg.read_text())
        ib = cfg["inbounds"][0]
        self.assertEqual(ib["listen"], "::",
                         "listen должен вернуться на '::' после revert")
        self.assertEqual(ib["port"], self._original_port,
                         f"port должен вернуться на {self._original_port} после revert")
        self.assertNotIn("acceptProxyProtocol",
                         ib["streamSettings"]["sockopt"],
                         "acceptProxyProtocol должен быть убран после revert")

    def test_revert_reverse_patch_without_backup(self):
        """Если бэкап удалён — reverse-patch по state восстанавливает значения."""
        from vless_installer.modules.singbox_nginx import (
            apply_reality_sni_dispatch_patch,
            revert_reality_sni_dispatch_patch,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            apply_reality_sni_dispatch_patch(restart_xray=False)
            # Удаляем бэкап — simulate stale/missing backup
            backup = self._xray_cfg.with_suffix(".json.pre-sni-dispatch")
            self.assertTrue(backup.exists())
            backup.unlink()
            revert_reality_sni_dispatch_patch(restart_xray=False)
        cfg = json.loads(self._xray_cfg.read_text())
        ib = cfg["inbounds"][0]
        self.assertEqual(ib["listen"], "::",
                         "reverse-patch должен восстановить listen из state")
        self.assertEqual(ib["port"], self._original_port,
                         "reverse-patch должен восстановить port из state")
        self.assertNotIn("acceptProxyProtocol",
                         ib["streamSettings"]["sockopt"])


# ══════════════════════════════════════════════════════════════════════════════
# 6. Re-apply после регенерации (sni_dispatch_reapply_after_rebuild)
# ══════════════════════════════════════════════════════════════════════════════

class TestReapplyAfterRebuild(unittest.TestCase):
    """Re-apply после регенерации — sni_dispatch_reapply_after_rebuild."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._xray_cfg = self._tmpdir / "config.json"
        self._sb_state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"
        self._main_state.write_text(json.dumps({
            "protocol_mode": "reality",
            "awg_exit_enabled": False,
        }))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_nginx._xray_config_paths",
                  return_value=[self._xray_cfg]),
            patch("vless_installer.modules.singbox_nginx._run",
                  return_value=MagicMock(returncode=0, stdout="active\n", stderr="")),
        ]

    def test_reapply_noop_when_disabled(self):
        """Если SNI-dispatch выключен — reapply ничего не делает."""
        from vless_installer.modules.singbox_nginx import sni_dispatch_reapply_after_rebuild
        from vless_installer.modules.singbox_state import singbox_state_init
        # config.json НЕ существует — reapply должен молча вернуться
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            # Должно пройти без ошибок и без вызова apply_patch
            sni_dispatch_reapply_after_rebuild()
        # config.json не создан — патч не применялся
        self.assertFalse(self._xray_cfg.exists())

    def test_reapply_repatches_after_regenerate(self):
        """Сценарий: config.json перезаписан generate_*, патч переприменяется."""
        from vless_installer.modules.singbox_nginx import (
            sni_dispatch_reapply_after_rebuild,
            apply_reality_sni_dispatch_patch,
        )
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_set_sni_dispatch,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            # Симулируем: патч уже был применён ранее (state показывает enabled+auto_configured)
            singbox_state_set_sni_dispatch({
                "enabled": True,
                "auto_configured": True,
                "reality_backend": "127.0.0.1:8442",
                "original_listen": "::",
                "original_port":   443,
            })
            # simulate generate_xray_config() — config.json перезаписан с дефолтным :443
            self._xray_cfg.write_text(json.dumps(_make_reality_config(), indent=2))
            # reapply hook должен переприменить патч
            sni_dispatch_reapply_after_rebuild()
        cfg = json.loads(self._xray_cfg.read_text())
        ib = cfg["inbounds"][0]
        self.assertEqual(ib["listen"], "127.0.0.1",
                         "reapply должен перевести listen на loopback")
        self.assertEqual(ib["port"], 8442,
                         "reapply должен перевести port на 8442")
        self.assertIs(ib["streamSettings"]["sockopt"]["acceptProxyProtocol"], True)

    def test_reapply_skipped_in_manual_mode(self):
        """auto_configured=False (ручной режим) — reapply пропускается."""
        from vless_installer.modules.singbox_nginx import sni_dispatch_reapply_after_rebuild
        from vless_installer.modules.singbox_state import (
            singbox_state_init, singbox_state_set_sni_dispatch,
        )
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            singbox_state_init(version="1.0.0")
            singbox_state_set_sni_dispatch({
                "enabled": True,
                "auto_configured": False,  # ручной режим
            })
            self._xray_cfg.write_text(json.dumps(_make_reality_config(), indent=2))
            original_content = self._xray_cfg.read_text()
            sni_dispatch_reapply_after_rebuild()
        # config.json не тронут
        self.assertEqual(self._xray_cfg.read_text(), original_content,
                         "reapply НЕ должен трогать config.json в ручном режиме")


# ══════════════════════════════════════════════════════════════════════════════
# 7. AWG/xHTTP — патч явно отказывается применяться
# ══════════════════════════════════════════════════════════════════════════════

class TestPatchRefusesAwgXhttp(unittest.TestCase):
    """AWG/xHTTP — патч явно отказывается применяться, не молчит."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._xray_cfg = self._tmpdir / "config.json"
        self._xray_cfg.write_text(json.dumps(_make_reality_config(), indent=2))
        self._sb_state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self, main_state_dict=None):
        patches = [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_nginx._xray_config_paths",
                  return_value=[self._xray_cfg]),
            patch("vless_installer.modules.singbox_nginx._run",
                  return_value=MagicMock(returncode=0, stdout="active\n", stderr="")),
        ]
        if main_state_dict is not None:
            # _read_main_state() в singbox_nginx.py хардкодит путь — патчим саму функцию.
            # Это соответствует существующему паттерну test_singbox_sni_autoconfig.py.
            patches.append(
                patch("vless_installer.modules.singbox_nginx._read_main_state",
                      return_value=main_state_dict)
            )
        return patches

    def test_patch_refuses_xhttp_mode(self):
        from vless_installer.modules.singbox_nginx import apply_reality_sni_dispatch_patch
        original_content = self._xray_cfg.read_text()
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(main_state_dict={
                "protocol_mode": "xhttp",
                "awg_exit_enabled": False,
            }))
            ok = apply_reality_sni_dispatch_patch(restart_xray=False)
        self.assertFalse(ok, "Патч должен вернуть False в xHTTP-режиме")
        self.assertEqual(self._xray_cfg.read_text(), original_content,
                         "config.json НЕ должен быть изменён в xHTTP-режиме")

    def test_patch_refuses_awg_mode(self):
        from vless_installer.modules.singbox_nginx import apply_reality_sni_dispatch_patch
        original_content = self._xray_cfg.read_text()
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(main_state_dict={
                "protocol_mode": "reality",
                "awg_exit_enabled": True,
            }))
            ok = apply_reality_sni_dispatch_patch(restart_xray=False)
        self.assertFalse(ok, "Патч должен вернуть False в AWG-режиме")
        self.assertEqual(self._xray_cfg.read_text(), original_content,
                         "config.json НЕ должен быть изменён в AWG-режиме")

    def test_patch_skip_mode_check_bypasses_guard(self):
        """skip_mode_check=True — для reapply где проверка уже выполнена выше."""
        from vless_installer.modules.singbox_nginx import apply_reality_sni_dispatch_patch
        with ExitStack() as stack:
            _enter_patches(stack, self._patches(main_state_dict={
                "protocol_mode": "xhttp",
                "awg_exit_enabled": False,
            }))
            # skip_mode_check=True — патч применится даже в xHTTP
            ok = apply_reality_sni_dispatch_patch(restart_xray=False, skip_mode_check=True)
        self.assertTrue(ok, "skip_mode_check=True должен обходить guard")
        cfg = json.loads(self._xray_cfg.read_text())
        self.assertEqual(cfg["inbounds"][0]["listen"], "127.0.0.1")


# ══════════════════════════════════════════════════════════════════════════════
# 8. Бэкап .pre-sni-dispatch создаётся при первом патче
# ══════════════════════════════════════════════════════════════════════════════

class TestBackupCreation(unittest.TestCase):
    """Бэкап .pre-sni-dispatch создаётся при первом патче (по аналогии с nginx)."""

    def setUp(self):
        _setup_core()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._xray_cfg = self._tmpdir / "config.json"
        self._original_content = json.dumps(_make_reality_config(), indent=2) + "\n"
        self._xray_cfg.write_text(self._original_content)
        self._sb_state = self._tmpdir / "singbox_state.json"
        self._main_state = self._tmpdir / "state.json"
        self._main_state.write_text(json.dumps({
            "protocol_mode": "reality",
            "awg_exit_enabled": False,
        }))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patches(self):
        return [
            patch("vless_installer.modules.singbox_common.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_common.MAIN_STATE_FILE", self._main_state),
            patch("vless_installer.modules.singbox_state.SINGBOX_STATE_FILE", self._sb_state),
            patch("vless_installer.modules.singbox_nginx._xray_config_paths",
                  return_value=[self._xray_cfg]),
            patch("vless_installer.modules.singbox_nginx._run",
                  return_value=MagicMock(returncode=0, stdout="active\n", stderr="")),
        ]

    def test_backup_created_on_first_patch(self):
        from vless_installer.modules.singbox_nginx import apply_reality_sni_dispatch_patch
        backup = self._xray_cfg.with_suffix(".json.pre-sni-dispatch")
        self.assertFalse(backup.exists(), "До патча бэкапа быть не должно")
        with ExitStack() as stack:
            _enter_patches(stack, self._patches())
            apply_reality_sni_dispatch_patch(restart_xray=False)
        self.assertTrue(backup.exists(), "После патча бэкап должен быть создан")
        self.assertEqual(backup.read_text(), self._original_content,
                         "Бэкап должен содержать оригинальный config.json")

    def test_backup_suffix_matches_nginx_convention(self):
        """Suffix .pre-sni-dispatch — для консистентности с nginx бэкапом."""
        from vless_installer.modules.singbox_nginx import (
            apply_reality_sni_dispatch_patch, _XRAY_CONFIG_BACKUP_SUFFIX,
            _NGINX_HTTP_BACKUP_SUFFIX,
        )
        self.assertEqual(_XRAY_CONFIG_BACKUP_SUFFIX, _NGINX_HTTP_BACKUP_SUFFIX,
                         "Suffix для Xray config бэкапа должен совпадать с nginx")


# ══════════════════════════════════════════════════════════════════════════════
# 9. _find_reality_inbound — fallback по security=="reality"
# ══════════════════════════════════════════════════════════════════════════════

class TestFindRealityInboundFallback(unittest.TestCase):
    """_find_reality_inbound — fallback по security=='reality' если tag переименован."""

    def setUp(self):
        _setup_core()

    def test_finds_by_tag_inbound_vless(self):
        from vless_installer.modules.singbox_nginx import _find_reality_inbound
        cfg = {"inbounds": [{"tag": "inbound-vless", "streamSettings": {"security": "reality"}}]}
        ib = _find_reality_inbound(cfg)
        self.assertIsNotNone(ib)
        self.assertEqual(ib["tag"], "inbound-vless")

    def test_falls_back_to_security_reality(self):
        from vless_installer.modules.singbox_nginx import _find_reality_inbound
        cfg = {"inbounds": [
            {"tag": "other", "streamSettings": {"security": "tls"}},
            {"tag": "renamed-inbound", "streamSettings": {"security": "reality"}},
        ]}
        ib = _find_reality_inbound(cfg)
        self.assertIsNotNone(ib)
        self.assertEqual(ib["tag"], "renamed-inbound",
                         "Должен найти REALITY-инбаунд по security, даже если tag переименован")

    def test_returns_none_when_no_reality_inbound(self):
        from vless_installer.modules.singbox_nginx import _find_reality_inbound
        cfg = {"inbounds": [{"tag": "xhttp-in", "streamSettings": {"security": "tls"}}]}
        ib = _find_reality_inbound(cfg)
        self.assertIsNone(ib)


if __name__ == "__main__":
    unittest.main(verbosity=2)
