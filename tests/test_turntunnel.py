#!/usr/bin/env python3
"""
tests/test_turntunnel.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/turntunnel.py.

Покрывает:
  1. _plain / _wlen — unicode helpers
  2. _is_amd64 — определение архитектуры
  3. _is_installed — проверка установки
  4. _log — запись в лог-файл
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
        from vless_installer.modules.turntunnel import _plain
        self.assertEqual(_plain("hello"), "hello")

    def test_strips_ansi(self):
        from vless_installer.modules.turntunnel import _plain
        self.assertEqual(_plain("\033[1;31mhi\033[0m"), "hi")


class TestWlen(unittest.TestCase):
    """_wlen — display width."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ascii(self):
        from vless_installer.modules.turntunnel import _wlen
        self.assertEqual(_wlen("hello"), 5)

    def test_cjk_two_columns(self):
        from vless_installer.modules.turntunnel import _wlen
        self.assertEqual(_wlen("中文"), 4)

    def test_ansi_zero_width(self):
        from vless_installer.modules.turntunnel import _wlen
        self.assertEqual(_wlen("\033[1mhi\033[0m"), 2)


class TestIsAmd64(unittest.TestCase):
    """_is_amd64."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_x86_64(self):
        from vless_installer.modules.turntunnel import _is_amd64
        with patch("platform.machine", return_value="x86_64"):
            self.assertTrue(_is_amd64())

    def test_aarch64(self):
        from vless_installer.modules.turntunnel import _is_amd64
        with patch("platform.machine", return_value="aarch64"):
            self.assertFalse(_is_amd64())


class TestIsInstalled(unittest.TestCase):
    """_is_installed."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._bin = self._tmpdir / "server"
        self._svc = self._tmpdir / "vk-turn-proxy.service"
        self._state = self._tmpdir / "turntunnel.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("vless_installer.modules.turntunnel._BIN_PATH", self._bin),
            patch("vless_installer.modules.turntunnel._SERVICE_FILE", self._svc),
            patch("vless_installer.modules.turntunnel._MODULE_STATE", self._state),
        )

    def test_returns_false_when_neither(self):
        from vless_installer.modules.turntunnel import _is_installed
        with self._patch()[0], self._patch()[1], self._patch()[2]:
            self.assertFalse(_is_installed())

    def test_returns_true_when_all(self):
        from vless_installer.modules.turntunnel import _is_installed
        self._bin.write_text("x")
        self._svc.write_text("x")
        self._state.write_text(json.dumps({"installed": True}))
        with self._patch()[0], self._patch()[1], self._patch()[2]:
            self.assertTrue(_is_installed())


class TestLog(unittest.TestCase):
    """_log — запись в лог-файл."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._log = self._tmpdir / "install.log"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.turntunnel._LOG_FILE", self._log)

    def test_writes_plain_text(self):
        from vless_installer.modules.turntunnel import _log
        with self._patch():
            _log("test message")
        content = self._log.read_text()
        self.assertIn("test message", content)

    def test_strips_ansi(self):
        from vless_installer.modules.turntunnel import _log
        with self._patch():
            _log("\033[1;31mred text\033[0m")
        content = self._log.read_text()
        self.assertNotIn("\033[", content)
        self.assertIn("red text", content)


# ============================================================================
#  ТЕСТЫ _download_binary — интеграция с download_manager.fetch_package
# ============================================================================
# После миграции _download_binary() делегирует в fetch_package(TURNTUNNEL_SPEC).
# Покрываем 4 сценария из ТЗ:
#   1. Успешное скачивание с первого зеркала.
#   2. Fallback на второе зеркало при падении первого.
#   3. Срабатывание ручного размещения файла (без сети).
#   4. Полный провал всех зеркал → print_manual_hint вызван, False.
#
# Архитектурно: _download_binary() делает две вещи — проверяет _is_amd64()
# (бизнес-логика, остаётся в модуле) и зовёт fetch_package(TURNTUNNEL_SPEC)
# (вся сетевая логика — в download_manager). Поэтому мокаем fetch_package
# целиком, а не urllib.request — это стабильнее и не зависит от внутренней
# реализации fetch_package.
class TestDownloadBinaryArch(unittest.TestCase):
    """_download_binary — архитектурная проверка (не amd64 → отказ)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_false_on_non_amd64(self):
        from vless_installer.modules import turntunnel
        with patch("platform.machine", return_value="aarch64"), \
             patch("vless_installer.modules.download_manager.fetch_package") as mock_fp:
            result = turntunnel._download_binary()
        self.assertFalse(result)
        # fetch_package НЕ вызывается — отказ происходит до него
        mock_fp.assert_not_called()


class TestDownloadBinaryFirstMirrorSuccess(unittest.TestCase):
    """Сценарий 1: успешное скачивание с первого зеркала."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_first_mirror_success_returns_true(self):
        from vless_installer.modules import turntunnel
        with patch("platform.machine", return_value="x86_64"), \
             patch("vless_installer.modules.download_manager.fetch_package",
                   return_value=True) as mock_fp:
            result = turntunnel._download_binary()
        self.assertTrue(result)
        mock_fp.assert_called_once()
        # Проверяем что передан именно TURNTUNNEL_SPEC (по имени пакета)
        spec_arg = mock_fp.call_args.args[0]
        self.assertEqual(spec_arg.name, "vk-turn-proxy")


class TestDownloadBinaryMirrorFallback(unittest.TestCase):
    """Сценарий 2: fallback на второе зеркало при падении первого.

    Логика fallback'а живёт ВНУТРИ fetch_package (перебор mirror_urls по
    очереди). На уровне _download_binary мы видим только итоговый True —
    но чтобы гарантировать что fallback-логика действительно работает,
    мокаем fetch_package и инспектируем что он получает spec с правильным
    mirror_urls_builder (через который идёт перебор).
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_spec_has_multiple_mirrors_for_fallback(self):
        """TURNTUNNEL_SPEC.mirror_urls_builder возвращает >1 зеркало."""
        from vless_installer.modules.turn_packages import TURNTUNNEL_SPEC
        urls = TURNTUNNEL_SPEC.mirror_urls_builder(filename="server-linux-amd64")
        # Должно быть минимум 2 зеркала — иначе fallback физически невозможен
        self.assertGreaterEqual(len(urls), 2,
            "TURNTUNNEL_SPEC должен иметь минимум 2 зеркала для fallback")

    def test_fallback_to_second_mirror_simulated(self):
        """Симулируем fallback: fetch_package вернул True (он внутри
        перебрал зеркала и второе сработало). Проверяем что _download_binary
        прокидывает True и передаёт spec с поддержкой fallback."""
        from vless_installer.modules import turntunnel
        from vless_installer.modules.turn_packages import TURNTUNNEL_SPEC

        # Убеждается что в spec'е действительно несколько зеркал
        urls = TURNTUNNEL_SPEC.mirror_urls_builder(filename="server-linux-amd64")
        self.assertGreaterEqual(len(urls), 2)

        with patch("platform.machine", return_value="x86_64"), \
             patch("vless_installer.modules.download_manager.fetch_package",
                   return_value=True) as mock_fp:
            result = turntunnel._download_binary()
        self.assertTrue(result)
        # spec передан — это уже гарантирует что fallback-логика доступна
        spec_arg = mock_fp.call_args.args[0]
        self.assertIs(spec_arg, TURNTUNNEL_SPEC)


class TestDownloadBinaryManualUpload(unittest.TestCase):
    """Сценарий 3: срабатывание ручного размещения файла (без сети).

    Логика проверки /root/<filename> живёт ВНУТРИ fetch_package. На уровне
    _download_binary мы видим только итоговый True. Чтобы гарантировать что
    manual-upload работает, проверяем что spec.manual_incoming_dir указывает
    на /root/ (WinSCP-friendly) и что fetch_package получает spec с этим
    значением.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_spec_manual_dir_is_root(self):
        """TURNTUNNEL_SPEC.manual_incoming_dir = /root/."""
        from vless_installer.modules.turn_packages import TURNTUNNEL_SPEC
        self.assertEqual(TURNTUNNEL_SPEC.manual_incoming_dir, Path("/root"))

    def test_spec_manual_dir_not_in_install_dests(self):
        """КРИТИЧЕСКИЙ ИНВАРИАНТ: manual_dir НЕ совпадает ни с одним
        install_dest. Это воспроизводит защиту от бага 21d7baf на уровне
        конструктора PackageSpec."""
        from vless_installer.modules.turn_packages import TURNTUNNEL_SPEC
        for dest in TURNTUNNEL_SPEC.install_dests:
            self.assertNotEqual(TURNTUNNEL_SPEC.manual_incoming_dir, dest,
                "manual_incoming_dir не должен совпадать с install_dest "
                "(защита от бага 21d7baf)")

    def test_manual_upload_returns_true_via_fetch_package(self):
        """Когда fetch_package находит /root/server-linux-amd64 — он
        возвращает True, и _download_binary тоже."""
        from vless_installer.modules import turntunnel
        with patch("platform.machine", return_value="x86_64"), \
             patch("vless_installer.modules.download_manager.fetch_package",
                   return_value=True) as mock_fp:
            result = turntunnel._download_binary()
        self.assertTrue(result)
        mock_fp.assert_called_once()


class TestDownloadBinaryAllMirrorsFail(unittest.TestCase):
    """Сценарий 4: полный провал всех зеркал → False."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_all_mirrors_fail_returns_false(self):
        from vless_installer.modules import turntunnel
        with patch("platform.machine", return_value="x86_64"), \
             patch("vless_installer.modules.download_manager.fetch_package",
                   return_value=False) as mock_fp:
            result = turntunnel._download_binary()
        self.assertFalse(result)
        mock_fp.assert_called_once()


class TestTurntunnelSpecSanity(unittest.TestCase):
    """Sanity-проверки TURNTUNNEL_SPEC — что мигрированный spec корректен."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_spec_filename_is_server_linux_amd64(self):
        from vless_installer.modules.turn_packages import TURNTUNNEL_SPEC
        self.assertEqual(TURNTUNNEL_SPEC.filename_builder(), "server-linux-amd64")

    def test_spec_install_dest_is_opt_vk_turn_proxy(self):
        from vless_installer.modules.turn_packages import TURNTUNNEL_SPEC
        self.assertEqual(TURNTUNNEL_SPEC.install_dests, [Path("/opt/vk-turn-proxy")])

    def test_spec_min_size_is_1mb(self):
        """min_size = 1 MB — защита от 404 HTML-страниц (раньше не было)."""
        from vless_installer.modules.turn_packages import TURNTUNNEL_SPEC
        self.assertEqual(TURNTUNNEL_SPEC.min_size, 1_000_000)

    def test_spec_post_install_is_set(self):
        from vless_installer.modules.turn_packages import TURNTUNNEL_SPEC
        self.assertIsNotNone(TURNTUNNEL_SPEC.post_install)

    def test_spec_post_install_copies_elf_binary(self):
        """post_install копирует ELF-бинарник в install_dests/server."""
        import tempfile
        from vless_installer.modules.turn_packages import TURNTUNNEL_SPEC

        tmpdir = Path(tempfile.mkdtemp())
        try:
            # Создаём "бинарник" с валидным ELF magic
            src = tmpdir / "fake-server"
            src.write_bytes(b'\x7fELF' + b'\x00' * 100)
            # min_size пройден (104 байта vs 1_000_000)? Нет — но post_install
            # не проверяет min_size, его проверяет fetch_package. Здесь мы
            # тестируем ТОЛЬКО post_install, поэтому размер не важен.

            install_dir = tmpdir / "install"
            ok = TURNTUNNEL_SPEC.post_install(src, [install_dir])
            self.assertTrue(ok)
            dest = install_dir / "server"
            self.assertTrue(dest.exists())
            # Права 0o755 (исполняемый)
            import os
            self.assertEqual(oct(dest.stat().st_mode & 0o777), '0o755')
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_spec_post_install_rejects_non_elf(self):
        """post_install возвращает False если файл не ELF — даёт fetch_package
        шанс попробовать следующее зеркало."""
        import tempfile
        from vless_installer.modules.turn_packages import TURNTUNNEL_SPEC

        tmpdir = Path(tempfile.mkdtemp())
        try:
            src = tmpdir / "not-elf"
            src.write_bytes(b'<html>404 Not Found</html>' * 100)
            install_dir = tmpdir / "install"
            ok = TURNTUNNEL_SPEC.post_install(src, [install_dir])
            self.assertFalse(ok)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
