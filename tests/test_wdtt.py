#!/usr/bin/env python3
"""
tests/test_wdtt.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/wdtt.py.

Покрывает:
  1. _plain / _wlen — unicode helpers
  2. _ver_tuple — парсинг версии
  3. _go_required_version — чтение go.mod
  4. _is_installed — проверка установки
  5. _load_cfg / _save_cfg / _load_passwords / _save_passwords — JSON I/O
  6. _save_link_file — сохранение ссылки
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("vless_installer._core")
    fake_core.__dict__.update(g)
    sys.modules["vless_installer._core"] = fake_core


class TestPlain(unittest.TestCase):
    """_plain — strip ANSI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_plain_string_unchanged(self):
        from vless_installer.modules.wdtt import _plain
        self.assertEqual(_plain("hello"), "hello")

    def test_strips_ansi(self):
        from vless_installer.modules.wdtt import _plain
        self.assertEqual(_plain("\033[1;31mhi\033[0m"), "hi")


class TestWlen(unittest.TestCase):
    """_wlen — display width."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ascii(self):
        from vless_installer.modules.wdtt import _wlen
        self.assertEqual(_wlen("hello"), 5)

    def test_cjk_two_columns(self):
        from vless_installer.modules.wdtt import _wlen
        self.assertEqual(_wlen("中文"), 4)

    def test_ansi_zero_width(self):
        from vless_installer.modules.wdtt import _wlen
        self.assertEqual(_wlen("\033[1mhi\033[0m"), 2)


class TestVerTuple(unittest.TestCase):
    """_ver_tuple — парсинг версии."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_full_version(self):
        from vless_installer.modules.wdtt import _ver_tuple
        self.assertEqual(_ver_tuple("1.21.0"), (1, 21, 0))

    def test_two_part(self):
        from vless_installer.modules.wdtt import _ver_tuple
        self.assertEqual(_ver_tuple("1.21"), (1, 21, 0))

    def test_with_v_prefix(self):
        from vless_installer.modules.wdtt import _ver_tuple
        self.assertEqual(_ver_tuple("v1.21.5"), (1, 21, 5))

    def test_invalid_returns_zeros(self):
        from vless_installer.modules.wdtt import _ver_tuple
        self.assertEqual(_ver_tuple("abc"), (0, 0, 0))

    def test_long_version_truncates(self):
        from vless_installer.modules.wdtt import _ver_tuple
        self.assertEqual(_ver_tuple("1.2.3.4.5"), (1, 2, 3))


class TestGoRequiredVersion(unittest.TestCase):
    """_go_required_version — чтение go.mod."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._gomod = self._tmpdir / "go.mod"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_default_when_no_file(self):
        from vless_installer.modules.wdtt import _go_required_version
        self.assertEqual(_go_required_version(self._gomod), "1.21.0")

    def test_returns_version_from_file(self):
        from vless_installer.modules.wdtt import _go_required_version
        self._gomod.write_text("module wdtt\ngo 1.22.5\n")
        self.assertEqual(_go_required_version(self._gomod), "1.22.5")

    def test_returns_default_when_no_directive(self):
        from vless_installer.modules.wdtt import _go_required_version
        self._gomod.write_text("module wdtt\n")
        self.assertEqual(_go_required_version(self._gomod), "1.21.0")


class TestIsInstalled(unittest.TestCase):
    """_is_installed."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._bin = self._tmpdir / "wdtt"
        self._svc = self._tmpdir / "wdtt.service"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("vless_installer.modules.wdtt._BIN_PATH", self._bin),
            patch("vless_installer.modules.wdtt._SERVICE_FILE", self._svc),
        )

    def test_returns_false_when_neither(self):
        from vless_installer.modules.wdtt import _is_installed
        with self._patch()[0], self._patch()[1]:
            self.assertFalse(_is_installed())

    def test_returns_true_when_both(self):
        from vless_installer.modules.wdtt import _is_installed
        self._bin.write_text("x")
        self._svc.write_text("x")
        with self._patch()[0], self._patch()[1]:
            self.assertTrue(_is_installed())


class TestLoadSaveCfg(unittest.TestCase):
    """_load_cfg / _save_cfg — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "config.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("vless_installer.modules.wdtt._CFG_FILE", self._cfg),
            patch("vless_installer.modules.wdtt._CFG_DIR", self._tmpdir),
        )

    def test_load_returns_empty_when_no_file(self):
        from vless_installer.modules.wdtt import _load_cfg
        with self._patch()[0], self._patch()[1]:
            self.assertEqual(_load_cfg(), {})

    def test_load_returns_empty_on_corrupt(self):
        from vless_installer.modules.wdtt import _load_cfg
        self._cfg.write_text("{invalid")
        with self._patch()[0], self._patch()[1]:
            self.assertEqual(_load_cfg(), {})

    def test_save_then_load(self):
        from vless_installer.modules.wdtt import _load_cfg, _save_cfg
        with self._patch()[0], self._patch()[1]:
            _save_cfg({"port": 56000, "users": []})
            loaded = _load_cfg()
        self.assertEqual(loaded["port"], 56000)


class TestLoadSavePasswords(unittest.TestCase):
    """_load_passwords / _save_passwords — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._pw = self._tmpdir / "passwords.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("vless_installer.modules.wdtt._PASSWORDS_FILE", self._pw),
            patch("vless_installer.modules.wdtt._CFG_DIR", self._tmpdir),
        )

    def test_load_returns_default_when_no_file(self):
        from vless_installer.modules.wdtt import _load_passwords
        with self._patch()[0], self._patch()[1]:
            result = _load_passwords()
        self.assertIn("main_password", result)
        self.assertIn("passwords", result)
        self.assertEqual(result["passwords"], {})

    def test_save_then_load(self):
        from vless_installer.modules.wdtt import _load_passwords, _save_passwords
        with self._patch()[0], self._patch()[1]:
            _save_passwords({"main_password": "secret", "passwords": {"dev1": "pw1"}})
            loaded = _load_passwords()
        self.assertEqual(loaded["main_password"], "secret")
        self.assertIn("dev1", loaded["passwords"])


class TestSaveLinkFile(unittest.TestCase):
    """_save_link_file — сохранение ссылки."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_dir = self._tmpdir / "cfg"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.wdtt._CFG_DIR", self._cfg_dir)

    def test_writes_file_with_link(self):
        import stat
        from vless_installer.modules.wdtt import _save_link_file
        with self._patch():
            path = _save_link_file("wdtt://link", "test.link")
        self.assertTrue(path.exists())
        content = path.read_text()
        self.assertIn("wdtt://link", content)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode, 0o600)


# ============================================================================
#  ТЕСТЫ _build_wdtt_server / _install_go_toolchain — интеграция с
#  download_manager.fetch_package (Волна 2)
# ============================================================================
# После миграции _build_wdtt_server() и _install_go_toolchain() делегируют
# в fetch_package() с PackageSpec из wdtt_packages.py / go_toolchain_packages.py.
# Покрываем 4 сценария из ТЗ + sanity-проверки specs:
#   1. Успешное скачивание с первого зеркала.
#   2. Fallback на второе зеркало (через проверку что spec имеет >1 зеркала).
#   3. Срабатывание ручного размещения файла (без сети).
#   4. Полный провал всех зеркал → False.
class TestBuildWdttServerMigrated(unittest.TestCase):
    """_build_wdtt_server — делегирует в fetch_package(WDTT_SOURCE_SPEC)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_build_calls_fetch_package_with_wdtt_spec(self):
        """_build_wdtt_server вызывает fetch_package(WDTT_SOURCE_SPEC)."""
        from vless_installer.modules import wdtt
        from vless_installer.modules.wdtt_packages import WDTT_SOURCE_SPEC

        # _ensure_go мокаем чтобы вернуть готовый путь (не идём в сеть за Go)
        with patch("vless_installer.modules.wdtt._ensure_go",
                   return_value="/usr/local/bin/go"), \
             patch("vless_installer.modules.download_manager.fetch_package",
                   return_value=True) as mock_fp:
            result = wdtt._build_wdtt_server()

        self.assertTrue(result)
        mock_fp.assert_called_once()
        # Проверяем что передан именно WDTT_SOURCE_SPEC
        spec_arg = mock_fp.call_args.args[0]
        self.assertIs(spec_arg, WDTT_SOURCE_SPEC)

    def test_build_returns_false_when_go_unavailable(self):
        """Если _ensure_go вернул None — _build_wdtt_server сразу False,
        fetch_package НЕ вызывается."""
        from vless_installer.modules import wdtt
        with patch("vless_installer.modules.wdtt._ensure_go",
                   return_value=None), \
             patch("vless_installer.modules.download_manager.fetch_package") as mock_fp:
            result = wdtt._build_wdtt_server()
        self.assertFalse(result)
        mock_fp.assert_not_called()

    def test_build_returns_false_when_fetch_package_fails(self):
        """Сценарий 4: полный провал всех зеркал → False."""
        from vless_installer.modules import wdtt
        with patch("vless_installer.modules.wdtt._ensure_go",
                   return_value="/usr/local/bin/go"), \
             patch("vless_installer.modules.download_manager.fetch_package",
                   return_value=False) as mock_fp:
            result = wdtt._build_wdtt_server()
        self.assertFalse(result)
        mock_fp.assert_called_once()


class TestInstallGoToolchainMigrated(unittest.TestCase):
    """_install_go_toolchain — делегирует в fetch_package(GO_TOOLCHAIN_SPEC)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_install_calls_fetch_package_with_go_spec(self):
        """_install_go_toolchain вызывает fetch_package(GO_TOOLCHAIN_SPEC,
        version=..., arch=...)."""
        from vless_installer.modules import wdtt
        from vless_installer.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC

        # Мокаем go.dev/VERSION?m=text чтобы вернуть предсказуемую версию
        mock_resp = unittest.mock.MagicMock()
        mock_resp.read.return_value = b"go1.23.4\n"
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None

        with patch("vless_installer.modules.wdtt.urllib.request.urlopen",
                   return_value=mock_resp), \
             patch("vless_installer.modules.download_manager.fetch_package",
                   return_value=True) as mock_fp, \
             patch("vless_installer.modules.wdtt._check_go",
                   return_value="/usr/local/bin/go"):
            result = wdtt._install_go_toolchain("1.22.0")

        self.assertEqual(result, "/usr/local/bin/go")
        mock_fp.assert_called_once()
        # Проверяем что передан GO_TOOLCHAIN_SPEC и правильные version/arch
        spec_arg = mock_fp.call_args.args[0]
        self.assertIs(spec_arg, GO_TOOLCHAIN_SPEC)
        self.assertEqual(mock_fp.call_args.kwargs.get("version"), "go1.23.4")
        self.assertEqual(mock_fp.call_args.kwargs.get("arch"), "amd64")

    def test_install_returns_none_when_fetch_fails(self):
        """fetch_package вернул False → _install_go_toolchain вернёт None."""
        from vless_installer.modules import wdtt

        mock_resp = unittest.mock.MagicMock()
        mock_resp.read.return_value = b"go1.23.4\n"
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None

        with patch("vless_installer.modules.wdtt.urllib.request.urlopen",
                   return_value=mock_resp), \
             patch("vless_installer.modules.download_manager.fetch_package",
                   return_value=False):
            result = wdtt._install_go_toolchain("1.22.0")
        self.assertIsNone(result)

    def test_install_fallback_version_on_metadata_failure(self):
        """Если go.dev/VERSION?m=text недоступен — fallback на go{required}."""
        from vless_installer.modules import wdtt
        from urllib.error import URLError

        with patch("vless_installer.modules.wdtt.urllib.request.urlopen",
                   side_effect=URLError("blocked")), \
             patch("vless_installer.modules.download_manager.fetch_package",
                   return_value=True) as mock_fp, \
             patch("vless_installer.modules.wdtt._check_go",
                   return_value="/usr/local/bin/go"):
            result = wdtt._install_go_toolchain("1.22.0")

        # version kwarg должен быть "go1.22.0" (fallback из required)
        self.assertEqual(mock_fp.call_args.kwargs.get("version"), "go1.22.0")


class TestWdttSpecSanity(unittest.TestCase):
    """Sanity-проверки WDTT_SOURCE_SPEC — что мигрированный spec корректен."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_spec_filename_is_master_tarball(self):
        from vless_installer.modules.wdtt_packages import WDTT_SOURCE_SPEC
        self.assertEqual(
            WDTT_SOURCE_SPEC.filename_builder(),
            "proxy-turn-vk-android-master.tar.gz",
        )

    def test_spec_install_dests_is_tmp_wdtt_packages(self):
        """install_dests — временная директория (post_install игнорирует её)."""
        from vless_installer.modules.wdtt_packages import WDTT_SOURCE_SPEC
        self.assertEqual(WDTT_SOURCE_SPEC.install_dests, [Path("/tmp/wdtt_packages")])

    def test_spec_manual_dir_is_root(self):
        from vless_installer.modules.wdtt_packages import WDTT_SOURCE_SPEC
        self.assertEqual(WDTT_SOURCE_SPEC.manual_incoming_dir, Path("/root"))

    def test_spec_manual_dir_not_in_install_dests(self):
        """КРИТИЧЕСКИЙ ИНВАРИАНТ: manual_dir != install_dests (баг 21d7baf)."""
        from vless_installer.modules.wdtt_packages import WDTT_SOURCE_SPEC
        for dest in WDTT_SOURCE_SPEC.install_dests:
            self.assertNotEqual(WDTT_SOURCE_SPEC.manual_incoming_dir, dest)

    def test_spec_min_size_is_1kb(self):
        """min_size = 1 KB — защита от 404 HTML-страниц (раньше не было)."""
        from vless_installer.modules.wdtt_packages import WDTT_SOURCE_SPEC
        self.assertEqual(WDTT_SOURCE_SPEC.min_size, 1000)

    def test_spec_post_install_is_set(self):
        from vless_installer.modules.wdtt_packages import WDTT_SOURCE_SPEC
        self.assertIsNotNone(WDTT_SOURCE_SPEC.post_install)

    def test_spec_has_multiple_mirrors_for_fallback(self):
        """Сценарий 2: spec имеет >1 зеркало для fallback."""
        from vless_installer.modules.wdtt_packages import WDTT_SOURCE_SPEC
        urls = WDTT_SOURCE_SPEC.mirror_urls_builder(
            filename="proxy-turn-vk-android-master.tar.gz",
        )
        self.assertGreaterEqual(len(urls), 2,
            "WDTT_SOURCE_SPEC должен иметь минимум 2 зеркала для fallback")


class TestGoToolchainSpecSanity(unittest.TestCase):
    """Sanity-проверки GO_TOOLCHAIN_SPEC."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_spec_filename_builder(self):
        from vless_installer.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
        self.assertEqual(
            GO_TOOLCHAIN_SPEC.filename_builder(version="go1.23.4", arch="amd64"),
            "go1.23.4.linux-amd64.tar.gz",
        )
        self.assertEqual(
            GO_TOOLCHAIN_SPEC.filename_builder(version="go1.23.4", arch="arm64"),
            "go1.23.4.linux-arm64.tar.gz",
        )

    def test_spec_manual_dir_is_root(self):
        from vless_installer.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
        self.assertEqual(GO_TOOLCHAIN_SPEC.manual_incoming_dir, Path("/root"))

    def test_spec_manual_dir_not_in_install_dests(self):
        from vless_installer.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
        for dest in GO_TOOLCHAIN_SPEC.install_dests:
            self.assertNotEqual(GO_TOOLCHAIN_SPEC.manual_incoming_dir, dest)

    def test_spec_min_size_is_10mb(self):
        """min_size = 10 MB — Go toolchain tarball ~60-70 MB."""
        from vless_installer.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
        self.assertEqual(GO_TOOLCHAIN_SPEC.min_size, 10_000_000)

    def test_spec_has_4_mirrors(self):
        """4 зеркала: go.dev + golang.google.cn + aliyun + tencent."""
        from vless_installer.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
        urls = GO_TOOLCHAIN_SPEC.mirror_urls_builder(
            filename="go1.23.4.linux-amd64.tar.gz",
            version="go1.23.4", arch="amd64",
        )
        self.assertEqual(len(urls), 4)
        # Проверяем что go.dev первый (основной источник)
        self.assertIn("go.dev", urls[0])

    def test_spec_post_install_is_set(self):
        from vless_installer.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
        self.assertIsNotNone(GO_TOOLCHAIN_SPEC.post_install)


if __name__ == "__main__":
    unittest.main(verbosity=2)
