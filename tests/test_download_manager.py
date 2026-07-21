#!/usr/bin/env python3
"""
tests/test_download_manager.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/download_manager.py.

КЛЮЧЕВЫЕ ПРОВЕРКИ:
  1. PackageSpec.__post_init__ assert: manual_incoming_dir == install_dest
     должен упасть — это regression-тест на класс бага 21d7baf.
  2. fetch_package(): manual-файл найден → сеть НЕ вызывается.
  3. fetch_package(): manual-файла нет → перебор зеркал, первое падает →
     второе успешно → копия во все install_dests.
  4. fetch_package(): все зеркала провалились → print_manual_hint вызван,
     возвращает False.
  5. Сценарий "уже второй вызов, файл в install_dests[0], manual_dir пуст"
     → сеть ВСЁ РАВНО вызывается (баг 21d7baf физически невозможен).
  6. post_install вызывается при успехе, НЕ вызывается при провале.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules.download_manager import (
    PackageSpec,
    fetch_package,
    print_manual_hint,
)


# ============================================================================
#  ТЕСТЫ PackageSpec — КРИТИЧЕСКИЙ ИНВАРИАНТ
# ============================================================================

class TestPackageSpecInvariant(unittest.TestCase):
    """PackageSpec.__post_init__ — КРИТИЧЕСКИЙ ИНВАРИАНТ.

    manual_incoming_dir НЕ должен совпадать ни с одним install_dest.
    Это prevents класс бага из geo_files.py (регрессия 21d7baf).
    """

    def _make_spec(self, manual_dir: Path, install_dests: list[Path]):
        """Создаёт минимальный PackageSpec для тестов инварианта."""
        return PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: ["https://example.com/test.dat"],
            install_dests=install_dests,
            manual_incoming_dir=manual_dir,
            min_size=0,
        )

    def test_manual_dir_equals_install_dest_raises_assert(self):
        """КЛЮЧЕВОЙ regression-тест: manual_incoming_dir == install_dest[0]
        ДОЛЖЕН упасть на __post_init__."""
        with self.assertRaises(AssertionError) as ctx:
            self._make_spec(
                manual_dir=Path("/root"),
                install_dests=[Path("/root"), Path("/etc/xray")],
            )
        self.assertIn("manual_incoming_dir", str(ctx.exception))
        self.assertIn("21d7baf", str(ctx.exception))

    def test_manual_dir_equals_second_install_dest_raises(self):
        """Проверяем ВСЕ install_dests, не только первый."""
        with self.assertRaises(AssertionError):
            self._make_spec(
                manual_dir=Path("/usr/local/share/xray"),
                install_dests=[Path("/etc/xray"), Path("/usr/local/share/xray")],
            )

    def test_manual_dir_different_from_all_dests_ok(self):
        """Корректный spec: manual_dir НЕ совпадает ни с одним dest."""
        spec = self._make_spec(
            manual_dir=Path("/root"),
            install_dests=[Path("/usr/local/share/xray"), Path("/etc/xray")],
        )
        self.assertEqual(spec.manual_incoming_dir, Path("/root"))
        self.assertEqual(len(spec.install_dests), 2)

    def test_default_manual_dir_is_root(self):
        """По умолчанию manual_incoming_dir = /root."""
        spec = PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: [],
            install_dests=[Path("/usr/local/share/xray")],
        )
        self.assertEqual(spec.manual_incoming_dir, Path("/root"))

    def test_default_min_size_is_zero(self):
        spec = PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: [],
            install_dests=[Path("/tmp")],
        )
        self.assertEqual(spec.min_size, 0)

    def test_default_post_install_is_none(self):
        spec = PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: [],
            install_dests=[Path("/tmp")],
        )
        self.assertIsNone(spec.post_install)


# ============================================================================
#  ТЕСТЫ fetch_package — ручное размещение
# ============================================================================

class TestFetchPackageManualUpload(unittest.TestCase):
    """fetch_package(): файл в manual_incoming_dir — сеть НЕ вызывается."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.manual_dir = Path(self.tmpdir) / "manual"
        self.manual_dir.mkdir()
        self.install_dir = Path(self.tmpdir) / "install"
        self.install_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_manual_file_found_skips_network(self):
        """Файл в manual_incoming_dir → сеть НЕ вызывается."""
        # Создаём файл в manual_dir
        manual_file = self.manual_dir / "test.dat"
        manual_file.write_bytes(b"x" * 100)

        spec = PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: ["https://example.com/test.dat"],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
        )

        with patch("chimera.modules.download_manager.urllib.request.urlopen") as mock_urlopen, \
             patch("chimera.modules.download_manager._default_copy_to_dests"):
            result = fetch_package(spec)

        self.assertTrue(result)
        mock_urlopen.assert_not_called()

    def test_manual_file_too_small_goes_to_network(self):
        """Файл в manual_dir но меньше min_size → идём в сеть."""
        manual_file = self.manual_dir / "test.dat"
        manual_file.write_bytes(b"x" * 10)  # меньше min_size=50

        spec = PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: ["https://example.com/test.dat"],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
        )

        # Мокаем urlopen чтобы вернуть "скачанный" файл
        mock_resp = MagicMock()
        downloaded_content = b"x" * 100
        mock_resp.read.side_effect = [downloaded_content, b""]
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None

        # tmp_path будет создан через open(tmp_path, 'wb')
        tmp_path = Path("/tmp") / "_download_mgr_test.dat"
        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   return_value=mock_resp), \
             patch("chimera.modules.download_manager._default_copy_to_dests") as mock_copy, \
             patch("chimera.modules.download_manager.Path.unlink"):
            # Записываем файл в tmp_path чтобы stat() прошёл
            def fake_open(path, *a, **kw):
                if "wb" in str(a) or "wb" in str(kw.get("mode", "")):
                    tmp_path.write_bytes(downloaded_content)
                return MagicMock()
            with patch("builtins.open", side_effect=fake_open):
                result = fetch_package(spec)

        self.assertTrue(result)
        mock_copy.assert_called_once()


# ============================================================================
#  ТЕСТЫ fetch_package — сетевое скачивание
# ============================================================================

class TestFetchPackageNetworkDownload(unittest.TestCase):
    """fetch_package(): перебор зеркал."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.manual_dir = Path(self.tmpdir) / "manual"
        self.manual_dir.mkdir()
        self.install_dir = Path(self.tmpdir) / "install"
        self.install_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_first_mirror_fails_second_succeeds(self):
        """Первое зеркало падает → второе успешно → копия во все install_dests."""
        from urllib.error import URLError

        spec = PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: [
                "https://mirror1.example.com/test.dat",
                "https://mirror2.example.com/test.dat",
            ],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
        )

        # Первое зеркало падает, второе отдаёт файл
        mock_resp_ok = MagicMock()
        mock_resp_ok.read.side_effect = [b"x" * 100, b""]
        mock_resp_ok.__enter__ = lambda self: self
        mock_resp_ok.__exit__ = lambda self, *a: None

        call_count = [0]
        def fake_urlopen(req, timeout):
            call_count[0] += 1
            if call_count[0] == 1:
                raise URLError("connection refused")
            return mock_resp_ok

        tmp_path = Path("/tmp") / "_download_mgr_test.dat"

        # Записываем файл в tmp_path чтобы stat() прошёл
        def fake_open(path, *a, **kw):
            if "wb" in str(a) or "wb" in str(kw.get("mode", "")):
                tmp_path.write_bytes(b"x" * 100)
            return MagicMock()

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=fake_urlopen), \
             patch("chimera.modules.download_manager._default_copy_to_dests") as mock_copy, \
             patch("chimera.modules.download_manager.Path.unlink"), \
             patch("builtins.open", side_effect=fake_open):
            result = fetch_package(spec)

        self.assertTrue(result)
        self.assertEqual(call_count[0], 2)  # оба зеркала были попытаны
        # _default_copy_to_dests вызван (файл скопирован в install_dests)
        mock_copy.assert_called_once()

    def test_all_mirrors_fail_returns_false(self):
        """Все зеркала провалились → print_manual_hint вызван, False."""
        from urllib.error import URLError

        spec = PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: [
                "https://mirror1.example.com/test.dat",
                "https://mirror2.example.com/test.dat",
            ],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
        )

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=URLError("blocked")), \
             patch("chimera.modules.download_manager.Path.unlink"), \
             patch("chimera.modules.download_manager.print_manual_hint") as mock_hint:
            result = fetch_package(spec)

        self.assertFalse(result)
        mock_hint.assert_called_once()

    def test_all_mirrors_fail_print_manual_hint_with_filename(self):
        """print_manual_hint вызван с правильным filename."""
        from urllib.error import URLError

        spec = PackageSpec(
            name="test-pkg",
            filename_builder=lambda: "my-file.dat",
            mirror_urls_builder=lambda filename: ["https://mirror1.example.com/my-file.dat"],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
        )

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=URLError("blocked")), \
             patch("chimera.modules.download_manager.Path.unlink"), \
             patch("chimera.modules.download_manager.print_manual_hint") as mock_hint:
            result = fetch_package(spec)

        self.assertFalse(result)
        # Проверяем что filename передан правильно
        call_kwargs = mock_hint.call_args.kwargs
        self.assertEqual(call_kwargs.get("filename"), "my-file.dat")


# ============================================================================
#  ТЕСТ fetch_package — РЕГРЕССИЯ 21d7baf (КЛЮЧЕВОЙ)
# ============================================================================

class TestFetchPackageRegression21d7baf(unittest.TestCase):
    """КЛЮЧЕВОЙ ТЕСТ: файл уже лежит в install_dests, но manual_dir пуст →
    сеть ВСЁ РАВНО вызывается.

    Это прямая проверка того, что баг из geo_files.py (регрессия 21d7baf)
    здесь физически невозможен по конструкции PackageSpec.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.manual_dir = Path(self.tmpdir) / "manual"
        self.manual_dir.mkdir()
        self.install_dir = Path(self.tmpdir) / "install"
        self.install_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_file_in_install_dests_still_triggers_network(self):
        """Файл УЖЕ лежит в install_dests[0] (от предыдущего запуска),
        manual_dir пуст → сеть ВСЁ РАВНО вызывается.

        Баг 21d7baf: в geo_files.py безусловная проверка искала файл по
        всем директориям включая install_dests → находила свой же файл
        → сеть не вызывалась → замораживание навсегда.

        В download_manager: manual_incoming_dir != install_dests (assert
        в __post_init__), поэтому файл в install_dests НЕ проверяется
        в безусловной проверке → сеть вызывается.
        """
        # Файл УЖЕ лежит в install_dests (от предыдущего запуска)
        existing_file = self.install_dir / "test.dat"
        existing_file.write_bytes(b"x" * 100)

        # manual_dir ПУСТ (нет ручного размещения)
        spec = PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: ["https://example.com/test.dat"],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,  # != install_dir
            min_size=50,
        )

        # Мокаем urlopen чтобы "скачать" файл
        mock_resp = MagicMock()
        mock_resp.read.side_effect = [b"y" * 100, b""]
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None

        tmp_path = Path("/tmp") / "_download_mgr_test.dat"

        def fake_open(path, *a, **kw):
            if "wb" in str(a) or "wb" in str(kw.get("mode", "")):
                tmp_path.write_bytes(b"y" * 100)
            return MagicMock()

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   return_value=mock_resp) as mock_urlopen, \
             patch("chimera.modules.download_manager._default_copy_to_dests"), \
             patch("chimera.modules.download_manager.Path.unlink"), \
             patch("builtins.open", side_effect=fake_open):
            result = fetch_package(spec)

        self.assertTrue(result)
        # КЛЮЧЕВАЯ ПРОВЕРКА: urlopen БЫЛ вызван — сеть затронута
        mock_urlopen.assert_called()

    def test_file_in_install_dests_only_does_not_use_them_as_manual(self):
        """Даже если install_dests содержат валидный файл, он НЕ используется
        как "ручное размещение" — сеть вызывается."""
        existing_file = self.install_dir / "test.dat"
        existing_file.write_bytes(b"x" * 100)

        spec = PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: ["https://example.com/test.dat"],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
        )

        # urlopen возвращает неудачу
        from urllib.error import URLError
        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=URLError("blocked")), \
             patch("chimera.modules.download_manager.Path.unlink"), \
             patch("chimera.modules.download_manager.print_manual_hint"):
            result = fetch_package(spec)

        # Функция провалилась — сеть была затронута, но не сработала
        # Файл из install_dests НЕ был использован
        self.assertFalse(result)


# ============================================================================
#  ТЕСТЫ post_install
# ============================================================================

class TestPostInstallCallback(unittest.TestCase):
    """post_install вызывается при успехе, НЕ вызывается при провале."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.manual_dir = Path(self.tmpdir) / "manual"
        self.manual_dir.mkdir()
        self.install_dir = Path(self.tmpdir) / "install"
        self.install_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_post_install_called_on_manual_upload_success(self):
        """post_install вызывается когда файл найден в manual_dir."""
        manual_file = self.manual_dir / "test.dat"
        manual_file.write_bytes(b"x" * 100)

        post_install = MagicMock(return_value=True)
        spec = PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: [],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
            post_install=post_install,
        )

        result = fetch_package(spec)

        self.assertTrue(result)
        post_install.assert_called_once()
        # Проверяем аргументы: (manual_path, install_dests)
        call_args = post_install.call_args
        self.assertEqual(call_args.args[0], manual_file)
        self.assertEqual(call_args.args[1], [self.install_dir])

    def test_post_install_called_on_network_success(self):
        """post_install вызывается при успешном сетевом скачивании."""
        post_install = MagicMock(return_value=True)
        spec = PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: ["https://example.com/test.dat"],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
            post_install=post_install,
        )

        mock_resp = MagicMock()
        mock_resp.read.side_effect = [b"x" * 100, b""]
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None

        tmp_path = Path("/tmp") / "_download_mgr_test.dat"

        def fake_open(path, *a, **kw):
            if "wb" in str(a) or "wb" in str(kw.get("mode", "")):
                tmp_path.write_bytes(b"x" * 100)
            return MagicMock()

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   return_value=mock_resp), \
             patch("chimera.modules.download_manager.Path.unlink"), \
             patch("builtins.open", side_effect=fake_open):
            result = fetch_package(spec)

        self.assertTrue(result)
        post_install.assert_called_once()

    def test_post_install_not_called_on_failure(self):
        """post_install НЕ вызывается при провале всех зеркал."""
        from urllib.error import URLError
        post_install = MagicMock(return_value=True)
        spec = PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: ["https://example.com/test.dat"],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
            post_install=post_install,
        )

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=URLError("blocked")), \
             patch("chimera.modules.download_manager.Path.unlink"), \
             patch("chimera.modules.download_manager.print_manual_hint"):
            result = fetch_package(spec)

        self.assertFalse(result)
        post_install.assert_not_called()

    def test_post_install_returns_false_tries_next_mirror(self):
        """Если post_install возвращает False — пробуем следующее зеркало."""
        from urllib.error import URLError
        post_install = MagicMock(side_effect=[False, True])  # первый раз fail, второй ok
        spec = PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: [
                "https://mirror1.example.com/test.dat",
                "https://mirror2.example.com/test.dat",
            ],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
            post_install=post_install,
        )

        # Каждый urlopen возвращает новый mock_resp с бесконечным read
        def make_mock_resp():
            resp = MagicMock()
            data = b"x" * 100
            resp.read.side_effect = [data, b""]
            resp.__enter__ = lambda self: self
            resp.__exit__ = lambda self, *a: None
            return resp

        tmp_path = Path("/tmp") / "_download_mgr_test.dat"

        def fake_open(path, *a, **kw):
            if "wb" in str(a) or "wb" in str(kw.get("mode", "")):
                tmp_path.write_bytes(b"x" * 100)
            return MagicMock()

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=lambda req, timeout: make_mock_resp()), \
             patch("chimera.modules.download_manager.Path.unlink"), \
             patch("builtins.open", side_effect=fake_open):
            result = fetch_package(spec)

        self.assertTrue(result)
        self.assertEqual(post_install.call_count, 2)  # оба зеркала попытаны


# ============================================================================
#  ТЕСТЫ MIN_SIZES — отбраковка слишком маленьких файлов (v4.25.1)
# ============================================================================

class TestFetchPackageMinSizeRejection(unittest.TestCase):
    """fetch_package() — отбраковка файлов меньше min_size и retry на следующее зеркало.

    v4.25.1: на проде был инцидент — CDN отдал устаревший geosite.dat (10 МБ
    вместо 73 МБ). Старый порог 3 МБ пропустил его как валидный. Тест проверяет:
      1. Файл < min_size отбраковывается.
      2. Код переходит к следующему зеркалу (НЕ считает загрузку успешной).
      3. В логе виден реальный размер vs порог (для диагностики).
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.manual_dir = Path(self.tmpdir) / "manual"
        self.manual_dir.mkdir()
        self.install_dir = Path(self.tmpdir) / "install"
        self.install_dir.mkdir()
        self.tmp_path = Path("/tmp") / "_download_mgr_test_minsize.dat"
        self.tmp_path.unlink(missing_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        self.tmp_path.unlink(missing_ok=True)

    def test_small_file_rejected_retries_next_mirror(self):
        """Файл < min_size отбраковывается → retry на следующее зеркало.

        Симулируем: первое зеркало отдаёт 50 байт (меньше порога 100),
        второе зеркало отдаёт 200 байт (больше порога) → успех.
        """
        spec = PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: [
                "https://mirror1.example.com/test.dat",
                "https://mirror2.example.com/test.dat",
            ],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=100,  # порог 100 байт
        )

        call_count = [0]
        def make_mock_resp(size: int):
            mock_resp = MagicMock()
            mock_resp.read.side_effect = [b"x" * size, b""]
            mock_resp.headers = {"Content-Length": str(size)}
            mock_resp.__enter__ = lambda self: self
            mock_resp.__exit__ = lambda self, *a: None
            return mock_resp

        def fake_urlopen(req, timeout):
            call_count[0] += 1
            if call_count[0] == 1:
                return make_mock_resp(50)   # 50 байт — ОТБРАКОВЫВАЕТСЯ (< 100)
            return make_mock_resp(200)      # 200 байт — ОК

        # Реально пишем в tmp_path чтобы stat() прошёл. Используем real open
        # (НЕ мокаем builtins.open — иначе Path.write_bytes не запишет).
        def fake_urlopen_and_write():
            # Записываем разный размер в зависимости от того, какое зеркало
            size = 50 if call_count[0] == 1 else 200
            self.tmp_path.write_bytes(b"x" * size)

        # Оборачиваем fake_urlopen чтобы сразу писать файл после получения ответа.
        original_fake_urlopen = fake_urlopen
        def wrapped_urlopen(req, timeout):
            resp = original_fake_urlopen(req, timeout)
            # Записываем файл сразу (имитируем что urlopen + read уже отработал).
            size = 50 if call_count[0] == 1 else 200
            self.tmp_path.write_bytes(b"x" * size)
            return resp

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=wrapped_urlopen), \
             patch("chimera.modules.download_manager._default_copy_to_dests") as mock_copy, \
             patch("chimera.modules.download_manager.Path.unlink"):
            result = fetch_package(spec, progress_label="test")

        self.assertTrue(result, "Должен вернуть True — второе зеркало отдало валидный файл")
        self.assertEqual(call_count[0], 2, "Должен быть вызван 2 раза (retry после отбраковки)")
        mock_copy.assert_called_once(), "Файл должен быть скопирован в install_dests"

    def test_small_file_from_all_mirrors_returns_false(self):
        """Все зеркала отдали маленькие файлы → False (отбраковка сработала)."""
        spec = PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: [
                "https://mirror1.example.com/test.dat",
                "https://mirror2.example.com/test.dat",
            ],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=1000,  # порог 1000 байт
        )

        def make_mock_resp(size: int):
            mock_resp = MagicMock()
            mock_resp.read.side_effect = [b"x" * size, b""]
            mock_resp.headers = {"Content-Length": str(size)}
            mock_resp.__enter__ = lambda self: self
            mock_resp.__exit__ = lambda self, *a: None
            return mock_resp

        call_count = [0]
        def wrapped_urlopen(req, timeout):
            call_count[0] += 1
            self.tmp_path.write_bytes(b"x" * 50)  # все зеркала отдают 50 байт (< 1000)
            return make_mock_resp(50)

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=wrapped_urlopen), \
             patch("chimera.modules.download_manager._default_copy_to_dests") as mock_copy, \
             patch("chimera.modules.download_manager.Path.unlink"), \
             patch("chimera.modules.download_manager.print_manual_hint"):
            result = fetch_package(spec, progress_label="test")

        self.assertFalse(result, "Должен вернуть False — все файлы слишком маленькие")
        mock_copy.assert_not_called(), "Ничего не должно быть скопировано"
        self.assertEqual(call_count[0], 2, "Оба зеркала должны быть попытаны")

    def test_logs_actual_size_vs_threshold_on_rejection(self):
        """При отбраковке логируется реальный размер vs порог (для диагностики)."""
        import io
        from contextlib import redirect_stdout

        spec = PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: [
                "https://mirror1.example.com/test.dat",
                "https://mirror2.example.com/test.dat",
            ],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=1000,  # порог 1000 байт
        )

        def make_mock_resp(size: int):
            mock_resp = MagicMock()
            mock_resp.read.side_effect = [b"x" * size, b""]
            mock_resp.headers = {"Content-Length": str(size)}
            mock_resp.__enter__ = lambda self: self
            mock_resp.__exit__ = lambda self, *a: None
            return mock_resp

        call_count = [0]
        def wrapped_urlopen(req, timeout):
            call_count[0] += 1
            if call_count[0] == 1:
                self.tmp_path.write_bytes(b"x" * 50)    # 50 байт — отбраковка
            else:
                self.tmp_path.write_bytes(b"x" * 2000)  # 2000 байт — ОК
            return make_mock_resp(50 if call_count[0] == 1 else 2000)

        captured = io.StringIO()
        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=wrapped_urlopen), \
             patch("chimera.modules.download_manager._default_copy_to_dests"), \
             patch("chimera.modules.download_manager.Path.unlink"), \
             redirect_stdout(captured):
            fetch_package(spec, progress_label="test")

        output = captured.getvalue()
        # В выводе должно быть сообщение об отбраковке с реальным размером и порогом.
        self.assertIn("50", output, "Должен логировать реальный размер (50 байт)")
        self.assertIn("1000", output, "Должен логировать порог (1000 байт)")
        self.assertIn("минимум", output.lower(),
                      "Должно быть слово 'минимум' для понятности")


# ============================================================================
#  ТЕСТЫ dry_run
# ============================================================================

class TestFetchPackageDryRun(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.manual_dir = Path(self.tmpdir) / "manual"
        self.manual_dir.mkdir()
        self.install_dir = Path(self.tmpdir) / "install"
        self.install_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_dry_run_returns_false(self):
        """dry_run=True → возвращает False (нет реальных вызовов)."""
        spec = PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: ["https://example.com/test.dat"],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
        )

        with patch("chimera.modules.download_manager.urllib.request.urlopen") as mock_urlopen:
            result = fetch_package(spec, dry_run=True)

        self.assertFalse(result)
        mock_urlopen.assert_not_called()


# ============================================================================
#  ТЕСТЫ print_manual_hint
# ============================================================================

class TestPrintManualHint(unittest.TestCase):
    """print_manual_hint — формат вывода."""

    def test_prints_filename_and_manual_dir(self):
        import io
        from contextlib import redirect_stdout

        spec = PackageSpec(
            name="test-pkg",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: ["https://example.com/test.dat"],
            install_dests=[Path("/usr/local/share/xray")],
            manual_incoming_dir=Path("/root"),
            min_size=50,
        )

        buf = io.StringIO()
        with redirect_stdout(buf):
            print_manual_hint(spec, filename="test.dat")
        output = buf.getvalue()

        self.assertIn("test.dat", output)
        self.assertIn("/root", output)
        self.assertIn("WinSCP", output)
        self.assertIn("https://example.com/test.dat", output)

    def test_prints_without_core_colors(self):
        """print_manual_hint должен работать без загруженного _core."""
        import io
        from contextlib import redirect_stdout

        spec = PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: ["https://example.com/test.dat"],
            install_dests=[Path("/tmp")],
            manual_incoming_dir=Path("/root"),
        )

        buf = io.StringIO()
        with redirect_stdout(buf):
            print_manual_hint(spec, filename="test.dat")
        # Не должно упасть
        self.assertGreater(len(buf.getvalue()), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
