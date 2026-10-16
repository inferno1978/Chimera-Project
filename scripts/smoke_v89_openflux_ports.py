#!/usr/bin/env python3
"""
scripts/smoke_v89_openflux_ports.py
───────────────────────────────────────────────────────────────────────────────
Смоук OpenFlux через download_manager + port_registry.

Проверяет БЕЗ сервера, но с НАСТОЯЩИМ port_registry (файл реестра
перенаправлен в tmpdir):
  1. Спеки openflux_packages: имена/зеркала/min_size/инвариант 21d7baf
  2. Реестр: port_register(1080, openflux_bridge) → чужой сервис видит
     конфликт → port_unregister → порт снова свободен
  3. _bridge_port_open/_close поверх реального реестра (loopback:
     без UFW; занятость чужим тегом → (False, конфликты в сообщении))
  4. Рамки меню/гайда целы (каждая строка — ровно два ║, урок про рамки)
"""
from __future__ import annotations

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "tests"))

from test_openflux import _setup_core_in_sysmodules  # noqa: E402


def _box_lines_ok(text: str) -> bool:
    """Контентные строки бокса (начинаются с ║) имеют ровно 2 ║.
    Сепараторы ╠…║ и рамки ╔/╚ — не контентные, не проверяются."""
    bad = [ln for ln in text.splitlines()
           if ln.startswith("║") and ln.count("║") != 2]
    return not bad, bad


class SmokeV89(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        _setup_core_in_sysmodules()
        import chimera.modules.port_registry as pr
        import chimera.modules.openflux_packages as pk
        cls.pr, cls.pk = pr, pk
        # Реестр → tmpdir (не трогаем /var/lib)
        cls._td = tempfile.TemporaryDirectory()
        td = Path(cls._td.name)
        cls.pr.PORT_REGISTRY_FILE = td / "port_registry.json"
        cls.pr.LOCK_FILE = td / "port_registry.lock"

    @classmethod
    def tearDownClass(cls):
        cls._td.cleanup()

    def test_01_specs(self):
        from chimera.modules.download_manager import PackageSpec
        from chimera.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
        from chimera.modules.go_toolchain_mirrors import (
            get_go_toolchain_mirrors,
        )
        self.assertIsInstance(self.pk.OPENFLUX_SRC_SPEC, PackageSpec)
        self.assertNotIn(self.pk.OPENFLUX_SRC_SPEC.manual_incoming_dir,
                         self.pk.OPENFLUX_SRC_SPEC.install_dests)
        # Go — через ОБЩИЙ спек проекта (wdtt/webdav_tunnel/olcrtc)
        self.assertFalse(hasattr(self.pk, "GO_TARBALL_SPEC"))
        go_urls = get_go_toolchain_mirrors("go1.26.4", "amd64")
        self.assertGreaterEqual(len(go_urls), 3)
        self.assertTrue(any("go.dev" in u for u in go_urls))
        self.assertTrue(any("aliyun" in u for u in go_urls))
        self.assertNotIn(GO_TOOLCHAIN_SPEC.manual_incoming_dir,
                         GO_TOOLCHAIN_SPEC.install_dests)
        # исходники: codeload + gh-proxy по sha
        sha = "461905369bd8f44ad2aacff240540d6a01d38c4d"
        self.assertTrue(any(f"tar.gz/{sha}" in u
                            for u in self.pk._src_mirror_urls("x", ref=sha)))
        self.assertNotIn("/", self.pk._ref_slug("refs/heads/main"))

    def test_02_registry_lifecycle(self):
        pr = self.pr
        # чужой сервис смотрит на 1080 до регистрации — свободен
        free, _ = pr.port_is_free(1080, "tcp")
        self.assertTrue(free)
        # bridge регистрируется
        ok, msg = pr.port_register(pr.SERVICE_OPENFLUX_BRIDGE, 1080, "tcp",
                                   comment="OpenFlux bridge SOCKS5")
        self.assertTrue(ok, msg)
        # чужой сервис теперь видит конфликт
        free, conflicts = pr.port_is_free(1080, "tcp")
        self.assertFalse(free)
        self.assertTrue(any("openflux_bridge" in c for c in conflicts))
        # сам bridge себя не считает конфликтом (exclude_service)
        free, _ = pr.port_is_free(1080, "tcp",
                                  exclude_service=pr.SERVICE_OPENFLUX_BRIDGE)
        self.assertTrue(free)
        # разрегистрация → свободен для всех
        self.assertTrue(pr.port_unregister(pr.SERVICE_OPENFLUX_BRIDGE,
                                           1080, "tcp"))
        free, _ = pr.port_is_free(1080, "tcp")
        self.assertTrue(free)

    def test_03_bridge_port_open_close_over_real_registry(self):
        from chimera.modules import openflux as of
        pr = self.pr
        # loopback: открытие = только регистрация (UFW не зовём —
        # ufw_open_port патчим, чтобы не звать systemctl/ufw из смоука)
        with patch.object(pr, "ufw_open_port",
                          return_value=(True, "ok")) as ufw_open:
            ok, msg = of._bridge_port_open("127.0.0.1", 1080)
        self.assertTrue(ok, msg)
        ufw_open.assert_not_called()
        # закрытие: ufw (no-op) + разрегистрация
        with patch.object(pr, "ufw_close_port",
                          return_value=(True, "нет правила")):
            of._bridge_port_close(1080)
        free, _ = pr.port_is_free(1080, "tcp")
        self.assertTrue(free)
        # теперь порт занял чужой сервис → bridge не должен открыться
        ok2, _ = pr.port_register("web_panel", 1080, "tcp", comment="панель")
        self.assertTrue(ok2)
        ok, msg = of._bridge_port_open("127.0.0.1", 1080)
        self.assertFalse(ok)
        self.assertIn("web_panel", msg)
        # клинап
        pr.port_unregister("web_panel", 1080, "tcp")
        free, _ = pr.port_is_free(1080, "tcp")
        self.assertTrue(free)

    def test_04_boxes_intact(self):
        from chimera.modules import openflux as of
        state = {"transport": "yandex", "doc_url": "https://x/edit/d/a?sk=b",
                 "transport_key": "K" * 44, "commit": "a" * 40,
                 "pinned": True, "raw_mode": False, "local_ip": "",
                 "bridge_active": True, "bridge_bind": "127.0.0.1",
                 "bridge_port": 1080, "installed_at": "2026-09-15"}
        with patch.object(of, "_is_installed", return_value=True), \
                patch.object(of, "_svc_active", return_value=True), \
                patch.object(of, "_bridge_svc_active", return_value=True), \
                patch.object(of, "_bridge_probe_listener",
                             return_value=True), \
                patch.object(of, "proto_load_state", return_value=state), \
                patch.object(of, "_run",
                             return_value=type("R", (), {
                                 "returncode": 0, "stdout": "ok"})()), \
                patch.object(of, "proto_ask", return_value="q"), \
                patch("os.system"):
            buf = io.StringIO()
            with redirect_stdout(buf):
                of.do_openflux_menu()
        ok, bad = _box_lines_ok(buf.getvalue())
        self.assertTrue(ok, f"сломанные рамки: {bad[:5]}")
        # bridge-строка в шапке меню
        self.assertIn("Bridge:", buf.getvalue())

        buf2 = io.StringIO()
        with patch.object(of, "proto_load_state", return_value=state), \
                patch.object(of, "_is_installed", return_value=True), \
                patch.object(of, "_svc_active", return_value=True), \
                patch.object(of, "_bridge_probe_listener",
                             return_value=True), \
                patch.object(of, "_run",
                             return_value=type("R", (), {
                                 "returncode": 0, "stdout": "ok"})()), \
                patch.object(of, "_pause"):
            with redirect_stdout(buf2):
                of._show_guide()
        ok2, bad2 = _box_lines_ok(buf2.getvalue())
        self.assertTrue(ok2, f"гайд ломает рамки: {bad2[:5]}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
