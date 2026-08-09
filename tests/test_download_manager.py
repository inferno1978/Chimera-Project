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
#  ТЕСТЫ MIN_SIZES — отбраковка слишком маленьких файлов 
# ============================================================================

class TestFetchPackageMinSizeRejection(unittest.TestCase):
    """fetch_package() — отбраковка файлов меньше min_size и retry на следующее зеркало.

     на проде был инцидент — CDN отдал устаревший geosite.dat (10 МБ
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


# ============================================================================
#  ТЕСТЫ sha256-верификации 
# ============================================================================
# Тесты покрывают 3 ключевых сценария:
#   1. Hash НЕ совпал → файл отбракован, переход к следующему зеркалу
#   2. Hash совпал → файл принят с первой попытки
#   3. Все checksum_url 404 → деградация до одобрения по размеру с warn
#
# Также отдельный класс TestParseChecksumContent покрывает парсер
# .sha256sum на разных форматах (стандартный, только-хэш, с пробелами,
# с комментариями, upper-case).

import hashlib as _hashlib_for_tests


class TestParseChecksumContent(unittest.TestCase):
    """Парсер .sha256sum контента — терпимость к разным форматам."""

    def test_standard_sha256sum_format(self):
        """Стандартный вывод sha256sum: '<hex>  <filename>\\n'."""
        from chimera.modules.download_manager import _parse_checksum_content
        h = "a" * 64
        content = f"{h}  geosite.dat\n"
        self.assertEqual(_parse_checksum_content(content), h)

    def test_single_space_format(self):
        """Один пробел между хэшем и именем файла."""
        from chimera.modules.download_manager import _parse_checksum_content
        h = "b" * 64
        content = f"{h} geosite.dat\n"
        self.assertEqual(_parse_checksum_content(content), h)

    def test_hash_only(self):
        """Только hex-хэш, без имени файла."""
        from chimera.modules.download_manager import _parse_checksum_content
        h = "c" * 64
        content = f"{h}\n"
        self.assertEqual(_parse_checksum_content(content), h)

    def test_hash_with_surrounding_whitespace(self):
        """Хэш с пробелами по краям."""
        from chimera.modules.download_manager import _parse_checksum_content
        h = "d" * 64
        content = f"  {h}  \n"
        self.assertEqual(_parse_checksum_content(content), h)

    def test_hash_with_comment(self):
        """Хэш после строки комментария."""
        from chimera.modules.download_manager import _parse_checksum_content
        h = "e" * 64
        content = f"# Generated 2026-07-21\n{h}  geosite.dat\n"
        self.assertEqual(_parse_checksum_content(content), h)

    def test_uppercase_hash_normalized_to_lower(self):
        """Upper-case hex должен нормализоваться в lower-case."""
        from chimera.modules.download_manager import _parse_checksum_content
        h_upper = "F" * 64
        h_lower = "f" * 64
        content = f"{h_upper}  geosite.dat\n"
        self.assertEqual(_parse_checksum_content(content), h_lower)

    def test_garbage_returns_none(self):
        """Нет 64-символьной hex-строки → None."""
        from chimera.modules.download_manager import _parse_checksum_content
        self.assertIsNone(_parse_checksum_content("garbage without hex"))
        self.assertIsNone(_parse_checksum_content(""))
        self.assertIsNone(_parse_checksum_content("abc123"))

    def test_partial_hex_returns_none(self):
        """63-символьный hex (неполный) → None."""
        from chimera.modules.download_manager import _parse_checksum_content
        # 63 символа вместо 64
        h63 = "a" * 63
        self.assertIsNone(_parse_checksum_content(h63))

    def test_real_sha256_format(self):
        """Реальный пример .sha256sum файла от runetfreedom."""
        from chimera.modules.download_manager import _parse_checksum_content
        # Реальный 64-символьный hex (это sha256 пустой строки для теста)
        h = _hashlib_for_tests.sha256(b"").hexdigest()
        content = f"{h}  geosite.dat\n"
        self.assertEqual(_parse_checksum_content(content), h)


class TestFetchPackageChecksumVerification(unittest.TestCase):
    """fetch_package() с checksum_urls — три ключевых сценария.

     после успешной загрузки файла (размер >= min_size) дополнительно
    проверяется sha256 через скачивание .sha256sum с checksum_urls.

    Сценарии:
      1. Hash НЕ совпал → файл отбракован, retry на следующее зеркало
      2. Hash совпал → файл принят с первой попытки
      3. Все checksum_url 404 → деградация до одобрения по размеру с warn
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.manual_dir = Path(self.tmpdir) / "manual"
        self.manual_dir.mkdir()
        self.install_dir = Path(self.tmpdir) / "install"
        self.install_dir.mkdir()
        # Уникальное имя tmp-файла для каждого теста, чтобы не было конфликтов
        self.tmp_filename = f"_test_checksum_{id(self)}.dat"
        self.tmp_path = Path("/tmp") / f"_download_mgr_{self.tmp_filename}"
        self.tmp_path.unlink(missing_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        self.tmp_path.unlink(missing_ok=True)

    def _make_file_response(self, content: bytes):
        """Создаёт mock-ответ для запроса К ФАЙЛУ (test.dat).

        read() возвращает content, затем пустой chunk (EOF).
        """
        mock_resp = MagicMock()
        mock_resp.read.side_effect = [content, b""]
        mock_resp.headers = {"Content-Length": str(len(content))}
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None
        return mock_resp

    def _make_checksum_response(self, content: str):
        """Создаёт mock-ответ для запроса К .sha256sum.

        read() возвращает content.encode(), затем пустой chunk.
        """
        mock_resp = MagicMock()
        mock_resp.read.side_effect = [content.encode("utf-8"), b""]
        mock_resp.headers = {"Content-Length": str(len(content))}
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None
        return mock_resp

    def test_hash_mismatch_retries_next_mirror(self):
        """Сценарий 1: hash НЕ совпал → файл отбракован → retry.

        Реалистичный сценарий: CDN с кэшем по branch-ref отдаёт устаревший
        файл (mirror1) — большой, но не текущий. .sha256sum с приоритетного
        источника (raw.githubusercontent.com) соответствует НОВОЙ версии
        файла, поэтому hash не совпадает со старым файлом → отбраковка.
        Mirror2 отдаёт актуальный файл, hash совпадает → успех.

         : эталонный хэш получается ОДИН РАЗ через _fetch_reference_hash
        (короткий приоритетный список) ПЕРЕД циклом скачивания. Внутри цикла
        — простое сравнение actual_hash с reference_hash, без повторных
        запросов .sha256sum.

        КЛЮЧЕВЫЕ проверки:
          - Первое зеркало отбраковано (hash mismatch)
          - Второе зеркало принято (hash match)
          - _default_copy_to_dests вызван ровно 1 раз
          - fetch_package вернул True
        """
        # Файл от mirror1 — устаревший (CDN кэш)
        stale_content = b"stale content from cache" * 10   # 250 байт
        # Файл от mirror2 — актуальный
        fresh_content = b"fresh content from upstream" * 10  # 270 байт

        # Единый "правильный" hash для актуального файла
        fresh_hash = _hashlib_for_tests.sha256(fresh_content).hexdigest()

        spec = PackageSpec(
            name="test",
            filename_builder=lambda: self.tmp_filename,
            mirror_urls_builder=lambda filename: [
                f"https://mirror1.example.com/{filename}",
                f"https://mirror2.example.com/{filename}",
            ],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
            # checksum_urls содержит ОДИН URL — он же приоритетный
            # (edge case: _fetch_reference_hash fallback на первые 2 URL
            # если нет raw.githubusercontent.com/github.com/statically.io).
            checksum_urls=[
                f"https://raw.githubusercontent.com/test/repo/main/{self.tmp_filename}.sha256sum",
            ],
            checksum_algo="sha256",
        )

        call_log = []  # лог URL-ов в порядке вызова

        def fake_urlopen(req, timeout):
            url = req.full_url
            call_log.append(url)

            # Запрос файла
            if url.endswith(self.tmp_filename) and not url.endswith(".sha256sum"):
                if "mirror1" in url:
                    # mirror1 отдаёт устаревший кэш
                    self.tmp_path.write_bytes(stale_content)
                    return self._make_file_response(stale_content)
                else:
                    # mirror2 отдаёт актуальный файл
                    self.tmp_path.write_bytes(fresh_content)
                    return self._make_file_response(fresh_content)

            # Запрос checksum (приоритетный источник raw.githubusercontent.com)
            if url.endswith(".sha256sum"):
                return self._make_checksum_response(f"{fresh_hash}  {self.tmp_filename}\n")

            raise AssertionError(f"Unexpected URL: {url}")

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=fake_urlopen), \
             patch("chimera.modules.download_manager._default_copy_to_dests") as mock_copy, \
             patch("chimera.modules.download_manager.Path.unlink"):
            result = fetch_package(spec, progress_label="test")

        self.assertTrue(result, "Должен вернуть True — второе зеркало прошло верификацию")

        #  : эталонный хэш получен ОДИН РАЗ перед циклом, а НЕ для
        # каждого кандидата. Порядок вызовов:
        #   1. raw.githubusercontent.com/.sha256sum → fresh_hash (reference_hash)
        #   2. mirror1.example.com/.dat (stale) → hash=stale_hash, mismatch
        #   3. mirror2.example.com/.dat (fresh) → hash=fresh_hash, match ✓
        # Итого 3 вызова (1 checksum + 2 файла). Раньше было 5-6 вызовов
        # потому что _verify_checksum перебирал checksum_urls для каждого
        # кандидата — это и было проблемой.
        self.assertEqual(len(call_log), 3,
                         f"Должно быть 3 вызова (1 reference_hash + 2 файла), "
                         f"фактически: {call_log}")

        # Проверяем что первый запрос был к .sha256sum (reference hash)
        self.assertIn(".sha256sum", call_log[0])
        # Второй — к mirror1.dat
        self.assertIn(f"mirror1.example.com/{self.tmp_filename}", call_log[1])
        # Третий — к mirror2.dat
        self.assertIn(f"mirror2.example.com/{self.tmp_filename}", call_log[2])

        # Только второе зеркало прошло верификацию → copy вызван 1 раз
        mock_copy.assert_called_once()

    def test_hash_match_accepts_first_mirror(self):
        """Сценарий 2: hash совпал → файл принят с первой попытки.

        Симулируем: единственное зеркало, файл валидного размера,
        .sha256sum совпадает → успех с первого раза.

         : reference_hash получен ОДИН РАЗ перед циклом, затем
        actual_hash скачанного файла сравнивается напрямую.

        КЛЮЧЕВЫЕ проверки:
          - urlopen вызван 2 раза (1 reference_hash + 1 файл)
          - _default_copy_to_dests вызван 1 раз
          - fetch_package вернул True
        """
        file_content = b"valid content" * 10   # 130 байт
        right_hash = _hashlib_for_tests.sha256(file_content).hexdigest()

        spec = PackageSpec(
            name="test",
            filename_builder=lambda: self.tmp_filename,
            mirror_urls_builder=lambda filename: [
                f"https://mirror1.example.com/{filename}",
            ],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
            checksum_urls=[
                f"https://raw.githubusercontent.com/test/repo/main/{self.tmp_filename}.sha256sum",
            ],
            checksum_algo="sha256",
        )

        call_log = []

        def fake_urlopen(req, timeout):
            url = req.full_url
            call_log.append(url)

            if url.endswith(".sha256sum"):
                return self._make_checksum_response(f"{right_hash}  {self.tmp_filename}\n")
            # Файл
            self.tmp_path.write_bytes(file_content)
            return self._make_file_response(file_content)

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=fake_urlopen), \
             patch("chimera.modules.download_manager._default_copy_to_dests") as mock_copy, \
             patch("chimera.modules.download_manager.Path.unlink"):
            result = fetch_package(spec, progress_label="test")

        self.assertTrue(result, "Должен вернуть True — hash совпал")
        self.assertEqual(len(call_log), 2,
                         f"Должно быть 2 вызова (1 reference_hash + 1 файл), "
                         f"фактически: {call_log}")
        # Первый — .sha256sum (reference hash)
        self.assertIn(".sha256sum", call_log[0])
        # Второй — сам файл
        self.assertIn(f"mirror1.example.com/{self.tmp_filename}", call_log[1])
        mock_copy.assert_called_once()

    def test_all_checksum_urls_404_degrades_to_size_check(self):
        """Сценарий 3: все priority-источники недоступны → деградация.

        Симулируем: единственное зеркало, файл валидного размера,
        но .sha256sum на ВСЕХ приоритетных источниках (raw.githubusercontent,
        github.com, cdn.statically.io) возвращает 404 → fetch_package
        принимает файл по размерной проверке с warn.

         : _fetch_reference_hash возвращает None (деградация) если
        все 3 приоритетных источника недоступны. Полный список checksum_urls
        (19 зеркал) НЕ перебирается — только короткий приоритетный список.

        КЛЮЧЕВЫЕ проверки:
          - urlopen вызван 1 (файл) + 3 (priority-источники) раз = 4
          - _default_copy_to_dests вызван 1 раз (файл принят по размеру)
          - fetch_package вернул True (не упал)
          - В логе виден warn "принято по размеру"
        """
        import io
        from contextlib import redirect_stdout
        from urllib.error import HTTPError, URLError

        file_content = b"valid content" * 10   # 130 байт

        spec = PackageSpec(
            name="test",
            filename_builder=lambda: self.tmp_filename,
            mirror_urls_builder=lambda filename: [
                f"https://mirror1.example.com/{filename}",
            ],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
            # 3 приоритетных источника — все упадут
            checksum_urls=[
                f"https://raw.githubusercontent.com/test/repo/main/{self.tmp_filename}.sha256sum",
                f"https://github.com/test/repo/releases/latest/download/{self.tmp_filename}.sha256sum",
                f"https://cdn.statically.io/gh/test/repo/main/{self.tmp_filename}.sha256sum",
            ],
            checksum_algo="sha256",
        )

        call_log = []

        def fake_urlopen(req, timeout):
            url = req.full_url
            call_log.append(url)

            if url.endswith(".sha256sum"):
                # Все приоритетные источники возвращают 404 / network error
                raise URLError("404 Not Found")
            # Файл
            self.tmp_path.write_bytes(file_content)
            return self._make_file_response(file_content)

        captured = io.StringIO()
        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=fake_urlopen), \
             patch("chimera.modules.download_manager._default_copy_to_dests") as mock_copy, \
             patch("chimera.modules.download_manager.Path.unlink"), \
             redirect_stdout(captured):
            result = fetch_package(spec, progress_label="test")

        # Файл принят по размерной проверке (деградация)
        self.assertTrue(result, "Должен вернуть True — деградация до размерной проверки")
        # 1 вызов файла + 3 попытки priority-checksum (все упали)
        self.assertEqual(len(call_log), 4,
                         f"Должно быть 4 вызова (1 файл + 3 priority-checksum), "
                         f"фактически: {call_log}")
        mock_copy.assert_called_once()

        # В логе должен быть warn о деградации
        output = captured.getvalue()
        self.assertIn("принято по размеру", output.lower(),
                      f"Должен быть warn 'принято по размеру' при деградации, вывод: {output}")

    def test_checksum_urls_none_no_verification(self):
        """Обратная совместимость: checksum_urls=None → верификация не делается.

        PackageSpec без checksum_urls должен работать байт-в-байт как раньше:
          - urlopen вызван 1 раз (только файл, без checksum)
          - _default_copy_to_dests вызван 1 раз
          - fetch_package вернул True
        """
        file_content = b"valid content" * 10   # 130 байт

        spec = PackageSpec(
            name="test",
            filename_builder=lambda: self.tmp_filename,
            mirror_urls_builder=lambda filename: [
                f"https://mirror1.example.com/{filename}",
            ],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
            # checksum_urls не задан — обратная совместимость
        )

        call_log = []

        def fake_urlopen(req, timeout):
            url = req.full_url
            call_log.append(url)
            self.tmp_path.write_bytes(file_content)
            return self._make_file_response(file_content)

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=fake_urlopen), \
             patch("chimera.modules.download_manager._default_copy_to_dests") as mock_copy, \
             patch("chimera.modules.download_manager.Path.unlink"):
            result = fetch_package(spec, progress_label="test")

        self.assertTrue(result)
        # ТОЛЬКО 1 вызов — файла, без checksum
        self.assertEqual(len(call_log), 1,
                         f"Без checksum_urls не должно быть запросов .sha256sum, фактически: {call_log}")
        mock_copy.assert_called_once()

    def test_checksum_unparseable_degrades_to_size_check(self):
        """Сценарий 4: .sha256sum скачан, но hex не парсится → деградация.

        Симулируем: приоритетный источник отдаёт .sha256sum с мусором
        (нет 64-символьного hex) → _fetch_reference_hash пробует следующий
        приоритетный источник, если все 3 отдают мусор → None → деградация.

         : _fetch_reference_hash перебирает 3 приоритетных источника.
        Если все 3 ответили мусором (или упали) → None → деградация.
        """
        import io
        from contextlib import redirect_stdout

        file_content = b"valid content" * 10   # 130 байт

        spec = PackageSpec(
            name="test",
            filename_builder=lambda: self.tmp_filename,
            mirror_urls_builder=lambda filename: [
                f"https://mirror1.example.com/{filename}",
            ],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
            # Все 3 приоритетных источника отдают мусор
            checksum_urls=[
                f"https://raw.githubusercontent.com/test/repo/main/{self.tmp_filename}.sha256sum",
                f"https://github.com/test/repo/releases/latest/download/{self.tmp_filename}.sha256sum",
                f"https://cdn.statically.io/gh/test/repo/main/{self.tmp_filename}.sha256sum",
            ],
            checksum_algo="sha256",
        )

        def fake_urlopen(req, timeout):
            url = req.full_url
            if url.endswith(".sha256sum"):
                # Мусор — нет 64-символьного hex
                return self._make_checksum_response("garbage content without hex\n")
            # Файл
            self.tmp_path.write_bytes(file_content)
            return self._make_file_response(file_content)

        captured = io.StringIO()
        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=fake_urlopen), \
             patch("chimera.modules.download_manager._default_copy_to_dests") as mock_copy, \
             patch("chimera.modules.download_manager.Path.unlink"), \
             redirect_stdout(captured):
            result = fetch_package(spec, progress_label="test")

        # Деградация — файл принят по размеру
        self.assertTrue(result)
        mock_copy.assert_called_once()
        # В логе должен быть warn о невозможности распарсить или о деградации
        output = captured.getvalue()
        # Либо "не удалось распарсить" (из цикла), либо "принято по размеру" (финал)
        self.assertTrue(
            "распарсить" in output.lower() or "распарсен" in output.lower()
            or "принято по размеру" in output.lower(),
            f"Должен быть warn о проблеме парсинга или деградации, вывод: {output}",
        )



class TestChecksumNotCalledInManualBranch(unittest.TestCase):
    """ regression-тест: sha256-верификация НЕ вызывается в manual-ветке.

    Когда файл найден в manual_incoming_dir (/root/ — ручное размещение
    через WinSCP), fetch_package использует его без сети и БЕЗ sha256-
    верификации. Это самый быстрый путь получения файла (пользователь
    сам туда кладёт то, что скачал вручную через curl), верификация по
    хэшу там избыточна.

     : вместо _verify_checksum теперь мокаем _fetch_reference_hash
    (она заменила _verify_checksum). Логика та же: в manual-ветке
    fetch_package должен вернуть True ДО сетевого цикла, не вызывая
    ни _fetch_reference_hash, ни _compute_hash.

    Тест гарантирует, что sha256-верификация живёт СТРОГО внутри сетевого
    цикла fetch_package (после успешной загрузки), а не в ветке /root/.
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

    def test_manual_file_does_not_trigger_verify_checksum(self):
        """Файл в manual_dir → _fetch_reference_hash НЕ вызывается."""
        # Создаём валидный файл в manual_dir
        manual_file = self.manual_dir / "test.dat"
        manual_file.write_bytes(b"x" * 100)

        # Spec с checksum_urls — если бы они использовались в manual-ветке,
        # тест упал бы на mock_fetch.assert_not_called()
        spec = PackageSpec(
            name="test",
            filename_builder=lambda: "test.dat",
            mirror_urls_builder=lambda filename: ["https://example.com/test.dat"],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
            checksum_urls=["https://example.com/test.dat.sha256sum"],
            checksum_algo="sha256",
        )

        with patch("chimera.modules.download_manager.urllib.request.urlopen") as mock_urlopen, \
             patch("chimera.modules.download_manager._fetch_reference_hash") as mock_fetch, \
             patch("chimera.modules.download_manager._default_copy_to_dests"):
            result = fetch_package(spec)

        self.assertTrue(result, "fetch_package должен вернуть True (manual-файл валидный)")
        mock_urlopen.assert_not_called()
        mock_fetch.assert_not_called()


# ============================================================================
#   REGRESSION TEST: файл в install_dests должен иметь каноническое имя
# ============================================================================
# КРИТИЧЕСКИЙ regression-тест на баг, обнаруженный 22.07.2026 на проде:
# geosite.dat/geoip.dat копировались под именем '_download_mgr_geosite.dat'
# вместо 'geosite.dat' — из-за того что _post_install_geo и
# _default_copy_to_dests использовали src.name, а src был tmp_path =
# /tmp/_download_mgr_{filename}. Баг введён в fbb2285 (10.07.2026), жил 12
# дней, все geo-обновления за это время были no-op по факту.

class TestCanonicalFileNameInInstallDests(unittest.TestCase):
    """ regression: файл в install_dests должен называться
    'geosite.dat', а НЕ '_download_mgr_geosite.dat'.

    Баг введён в fbb2285 (10.07.2026), обнаружен 22.07.2026 на проде —
    все geo-обновления с 10 июля по 22 июля были no-op: скачивание и
    sha256-верификация проходили успешно, но результат не попадал в
    реальный /etc/xray/geosite.dat (создавался файл с префиксом
    _download_mgr_ рядом со старым нетронутым geosite.dat).

    Этот тест проверяет ИМЕННО ИТОГОВОЕ ИМЯ ФАЙЛА в install_dests,
    а не только факт копирования — это слепое пятно существующих тестов,
    которое и позволило багу жить 12 дней незамеченным.
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

    def test_installed_file_has_canonical_name_not_tmp_prefix(self):
        """Регрессия: после fetch_package() файл в install_dests должен
        называться 'geosite.dat', а НЕ '_download_mgr_geosite.dat'.

        Баг введён в fbb2285 (10.07.2026), обнаружен на проде 22.07.2026 —
        все geo-обновления с 10 июля были no-op из-за этого имени.
        """
        # Реальный контент файла
        file_content = b"valid geosite content" * 100  # > min_size
        filename = "geosite.dat"

        # Используем РЕАЛЬНЫЙ post_install (не mock) — _default_copy_to_dests,
        # чтобы проверить именно тот путь, который использует fetch_package
        # по умолчанию. Запись в /tmp будет реальной (через builtins.open).
        spec = PackageSpec(
            name="geosite-test",
            filename_builder=lambda **kw: filename,
            mirror_urls_builder=lambda filename, **kw: [f"https://mirror.example.com/{filename}"],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
            # post_install=None → используется _default_copy_to_dests,
            # который копирует src → dest_dir/src.name
        )

        # Мокаем urlopen — отдаём file_content
        mock_resp = MagicMock()
        mock_resp.read.side_effect = [file_content, b""]
        mock_resp.headers = {"Content-Length": str(len(file_content))}
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   return_value=mock_resp):
            result = fetch_package(spec)

        # fetch_package должен завершиться успешно
        self.assertTrue(result,
                        "fetch_package должен вернуть True — файл скачан и скопирован")

        # КЛЮЧЕВАЯ ПРОВЕРКА: в install_dir должен лежать 'geosite.dat',
        # а НЕ '_download_mgr_geosite.dat'
        installed_files = list(self.install_dir.iterdir())
        names = {f.name for f in installed_files}
        self.assertIn("geosite.dat", names,
                      f"В install_dests должен быть 'geosite.dat', "
                      f"фактически: {names}")
        self.assertNotIn("_download_mgr_geosite.dat", names,
                         f"В install_dests НЕ должно быть "
                         f"'_download_mgr_geosite.dat' (регрессия fbb2285), "
                         f"фактически: {names}")

    def test_installed_file_has_canonical_name_with_post_install(self):
        """Та же регрессия, но с явным post_install callback.

        Проверяет что post_install получает src с каноническим именем
        (через src.name) — это та точка, где _post_install_geo использует
        src.name для построения dest пути.
        """
        filename = "geosite.dat"
        file_content = b"valid content" * 100

        # post_install callback, который использует src.name (как _post_install_geo)
        captured_src_name = []
        def fake_post_install(src, dests):
            captured_src_name.append(src.name)
            for dest_dir in dests:
                dest_dir.mkdir(parents=True, exist_ok=True)
                dest = dest_dir / src.name
                import shutil as _shutil
                _shutil.copy2(str(src), str(dest))
            return True

        spec = PackageSpec(
            name="geosite-test",
            filename_builder=lambda **kw: filename,
            mirror_urls_builder=lambda filename, **kw: [f"https://mirror.example.com/{filename}"],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
            post_install=fake_post_install,
        )

        mock_resp = MagicMock()
        mock_resp.read.side_effect = [file_content, b""]
        mock_resp.headers = {"Content-Length": str(len(file_content))}
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   return_value=mock_resp):
            result = fetch_package(spec)

        self.assertTrue(result)
        # post_install получил src с каноническим именем
        self.assertEqual(len(captured_src_name), 1,
                         "post_install должен быть вызван ровно 1 раз")
        self.assertEqual(captured_src_name[0], "geosite.dat",
                         f"post_install должен получить src.name='geosite.dat', "
                         f"фактически: {captured_src_name[0]!r} "
                         f"(регрессия fbb2285 — было '_download_mgr_geosite.dat')")

        # И файл в install_dir имеет каноническое имя
        installed_files = list(self.install_dir.iterdir())
        names = {f.name for f in installed_files}
        self.assertIn("geosite.dat", names)
        self.assertNotIn("_download_mgr_geosite.dat", names)


# ============================================================================
#   REGRESSION TESTS: эталонный хэш ОДИН РАЗ, continue-при-mismatch
# ============================================================================
# Эти тесты защищают от регрессии класса багов, который был в v5.0.0-v5.0.3:
#
# 1. _verify_checksum() перебирала ВСЕ 19 checksum_urls для КАЖДОГО кандидата
#    .dat-файла — избыточно (эталон один и тот же для всех попыток).
#
# 2. Если CDN закэшировал устаревший .sha256sum, _verify_checksum спотыкалась
#    на одном и том же (протухшем) первом checksum-зеркале для всех кандидатов,
#    и ВСЕ .dat-кандидаты помечались невалидными одинаково — скачивание
#    проваливалось целиком, хотя годные зеркала .dat были дальше в списке.
#
#  фикс: _fetch_reference_hash() получает эталонный хэш ОДИН РАЗ с
# короткого приоритетного списка (raw.githubusercontent.com → release-assets →
# cdn.statically.io), затем fetch_package просто сравнивает actual_hash
# с reference_hash для каждого кандидата. continue (НЕ return) при mismatch.

class TestFetchReferenceHashHelper(unittest.TestCase):
    """Прямые тесты _fetch_reference_hash() — без overhead полного fetch_package.

     новая функция заменяет старую _verify_checksum.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_checksum_response(self, content: str):
        mock_resp = MagicMock()
        mock_resp.read.side_effect = [content.encode("utf-8"), b""]
        mock_resp.headers = {"Content-Length": str(len(content))}
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None
        return mock_resp

    def test_empty_checksum_urls_returns_none(self):
        """Пустой список checksum_urls → None (деградация)."""
        from chimera.modules.download_manager import _fetch_reference_hash
        result = _fetch_reference_hash([], "sha256")
        self.assertIsNone(result)

    def test_raw_github_priority_first(self):
        """raw.githubusercontent.com — первый приоритет.
        Если отвечает — возвращаем хэш с него, НЕ трогая остальные источники.
        """
        from chimera.modules.download_manager import _fetch_reference_hash
        right_hash = _hashlib_for_tests.sha256(b"fresh content").hexdigest()

        call_log = []
        def fake_urlopen(req, timeout):
            url = req.full_url
            call_log.append(url)
            return self._make_checksum_response(f"{right_hash}  geosite.dat\n")

        checksum_urls = [
            "https://cdn.jsdelivr.net/gh/test/repo@main/geosite.dat.sha256sum",
            "https://raw.githubusercontent.com/test/repo/main/geosite.dat.sha256sum",
            "https://github.com/test/repo/releases/latest/download/geosite.dat.sha256sum",
            "https://cdn.statically.io/gh/test/repo/main/geosite.dat.sha256sum",
        ]

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=fake_urlopen):
            result = _fetch_reference_hash(checksum_urls, "sha256")

        self.assertEqual(result, right_hash)
        # Должен быть ТОЛЬКО 1 вызов — raw.githubusercontent.com (приоритет 1)
        self.assertEqual(len(call_log), 1,
                         f"Должен быть 1 вызов (raw.github приоритет), "
                         f"фактически: {call_log}")
        self.assertIn("raw.githubusercontent.com", call_log[0])

    def test_raw_github_timeout_fallback_to_release_github(self):
        """raw.githubusercontent.com недоступен → fallback на release GitHub.

        Проверяем что приоритетный список работает: первый источник упал,
        второй ответил — хэш получен со второго, НЕ со всех 19.
        """
        from chimera.modules.download_manager import _fetch_reference_hash
        from urllib.error import URLError
        right_hash = _hashlib_for_tests.sha256(b"fresh content").hexdigest()

        call_log = []
        def fake_urlopen(req, timeout):
            url = req.full_url
            call_log.append(url)
            if "raw.githubusercontent.com" in url:
                raise URLError("timeout")
            return self._make_checksum_response(f"{right_hash}  geosite.dat\n")

        checksum_urls = [
            "https://cdn.jsdelivr.net/gh/test/repo@main/geosite.dat.sha256sum",
            "https://raw.githubusercontent.com/test/repo/main/geosite.dat.sha256sum",
            "https://github.com/test/repo/releases/latest/download/geosite.dat.sha256sum",
            "https://cdn.statically.io/gh/test/repo/main/geosite.dat.sha256sum",
        ]

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=fake_urlopen):
            result = _fetch_reference_hash(checksum_urls, "sha256")

        self.assertEqual(result, right_hash)
        # Должно быть 2 вызова: raw.github (упал) + github.com/releases (ответил)
        self.assertEqual(len(call_log), 2,
                         f"Должно быть 2 вызова (raw упал + release ответил), "
                         f"фактически: {call_log}")
        self.assertIn("raw.githubusercontent.com", call_log[0])
        self.assertIn("github.com", call_log[1])
        self.assertIn("releases/latest/download", call_log[1])

    def test_all_priority_sources_unavailable_returns_none(self):
        """Все 3 приоритетных источника недоступны → None (деградация)."""
        from chimera.modules.download_manager import _fetch_reference_hash
        from urllib.error import URLError

        call_log = []
        def fake_urlopen(req, timeout):
            url = req.full_url
            call_log.append(url)
            raise URLError("timeout")

        checksum_urls = [
            "https://raw.githubusercontent.com/test/repo/main/geosite.dat.sha256sum",
            "https://github.com/test/repo/releases/latest/download/geosite.dat.sha256sum",
            "https://cdn.statically.io/gh/test/repo/main/geosite.dat.sha256sum",
            # Также добавим jsDelivr и gh-proxy — они НЕ должны вызываться
            "https://cdn.jsdelivr.net/gh/test/repo@main/geosite.dat.sha256sum",
            "https://ghproxy.net/https://github.com/test/repo/releases/latest/download/geosite.dat.sha256sum",
        ]

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=fake_urlopen):
            result = _fetch_reference_hash(checksum_urls, "sha256")

        self.assertIsNone(result, "Все приоритетные упали → None (деградация)")
        # Должно быть РОВНО 3 вызова — только приоритетные источники.
        # jsDelivr и gh-proxy НЕ должны вызываться.
        self.assertEqual(len(call_log), 3,
                         f"Должно быть 3 вызова (только приоритетные), "
                         f"фактически: {call_log}")
        # Проверяем что каждый вызов — к одному из приоритетных источников
        for url in call_log:
            is_priority = (
                "raw.githubusercontent.com" in url or
                ("github.com" in url and "releases/latest/download" in url
                 and "ghproxy" not in url) or
                "cdn.statically.io" in url
            )
            self.assertTrue(is_priority,
                            f"URL не является приоритетным источником: {url}. "
                            f"jsDelivr и gh-proxy НЕ должны вызываться.")
        # Дополнительно: проверяем что jsDelivr и gh-proxy НЕ были вызваны
        for url in call_log:
            self.assertNotIn("jsdelivr", url,
                             f"jsDelivr не должен вызываться, но был: {url}")
            self.assertNotIn("ghproxy", url,
                             f"gh-proxy не должен вызываться, но был: {url}")

    def test_ghproxy_excluded_from_priority(self):
        """gh-proxy URL'ы НЕ включаются в приоритетный список.

        gh-proxy (ghproxy.net, ghproxy.com, ...) — это прокси-кэши GitHub,
        та же проблема кэш-рассинхрона что у jsDelivr. Должны быть исключены.
        """
        from chimera.modules.download_manager import _fetch_reference_hash
        from urllib.error import URLError
        right_hash = _hashlib_for_tests.sha256(b"fresh").hexdigest()

        call_log = []
        def fake_urlopen(req, timeout):
            url = req.full_url
            call_log.append(url)
            # raw и cdn.statically — упадут, должен сработать github.com/releases
            if "raw.githubusercontent.com" in url:
                raise URLError("timeout")
            if "cdn.statically.io" in url:
                raise URLError("timeout")
            return self._make_checksum_response(f"{right_hash}  geosite.dat\n")

        # gh-proxy выглядит как github.com но содержит /https://github.com/
        checksum_urls = [
            "https://ghproxy.net/https://github.com/test/repo/releases/latest/download/geosite.dat.sha256sum",
            "https://raw.githubusercontent.com/test/repo/main/geosite.dat.sha256sum",
            "https://github.com/test/repo/releases/latest/download/geosite.dat.sha256sum",
            "https://cdn.statically.io/gh/test/repo/main/geosite.dat.sha256sum",
        ]

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=fake_urlopen):
            result = _fetch_reference_hash(checksum_urls, "sha256")

        self.assertEqual(result, right_hash)
        # ghproxy.net НЕ должен быть в call_log — только raw, statically,
        # и реальный github.com/releases.
        for url in call_log:
            self.assertNotIn("ghproxy", url,
                             f"gh-proxy не должен вызываться, но был: {url}")
        # Должен быть вызван реальный github.com/releases (не ghproxy)
        self.assertTrue(
            any("github.com" in u and "releases/latest/download" in u
                and "ghproxy" not in u for u in call_log),
            f"Должен быть вызван реальный github.com/releases, "
            f"call_log: {call_log}",
        )

    def test_no_priority_urls_fallback_to_first_two(self):
        """Edge case: в checksum_urls нет приоритетных хостов →
        fallback на первые 2 URL из полного списка."""
        from chimera.modules.download_manager import _fetch_reference_hash
        right_hash = _hashlib_for_tests.sha256(b"fresh").hexdigest()

        call_log = []
        def fake_urlopen(req, timeout):
            url = req.full_url
            call_log.append(url)
            return self._make_checksum_response(f"{right_hash}  geosite.dat\n")

        # Только example.com — нет raw.github/github.com/statically
        checksum_urls = [
            "https://mirror1.example.com/geosite.dat.sha256sum",
            "https://mirror2.example.com/geosite.dat.sha256sum",
            "https://mirror3.example.com/geosite.dat.sha256sum",
        ]

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=fake_urlopen):
            result = _fetch_reference_hash(checksum_urls, "sha256")

        self.assertEqual(result, right_hash)
        # Только 1 вызов — первый ответивший из первых 2 URL
        self.assertEqual(len(call_log), 1,
                         f"Должен быть 1 вызов (fallback на первые 2, "
                         f"первый ответил), фактически: {call_log}")


class TestSingleMirrorMismatchDoesNotInvalidateAllCandidates(unittest.TestCase):
    """ГЛАВНЫЙ regression-тест  несовпадение хэша у ОДНОГО кандидата
    НЕ должно прекращать проверку остальных .dat-зеркал.

    Это защита от класса регрессии, который был в v5.0.0- если CDN
    закэшировал устаревший .sha256sum, _verify_checksum спотыкалась на
    одном и том же протухшем зеркале для ВСЕХ .dat-кандидатов — и все
    кандидаты помечались невалидными одинаково, скачивание проваливалось
    целиком, хотя годные зеркала .dat были дальше в списке.

     фикс:
      - reference_hash получается ОДИН РАЗ (через короткий приоритетный список)
      - цикл по .dat-зеркалам ПРОДОЛЖАЕТСЯ (continue) при несовпадении хэша
      - пробуется СЛЕДУЮЩЕЕ зеркало .dat с ТЕМ ЖЕ reference_hash
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.manual_dir = Path(self.tmpdir) / "manual"
        self.manual_dir.mkdir()
        self.install_dir = Path(self.tmpdir) / "install"
        self.install_dir.mkdir()
        self.tmp_filename = f"_test_mismatch_{id(self)}.dat"
        self.tmp_path = Path("/tmp") / f"_download_mgr_{self.tmp_filename}"
        self.tmp_path.unlink(missing_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        self.tmp_path.unlink(missing_ok=True)

    def _make_file_response(self, content: bytes):
        mock_resp = MagicMock()
        mock_resp.read.side_effect = [content, b""]
        mock_resp.headers = {"Content-Length": str(len(content))}
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None
        return mock_resp

    def _make_checksum_response(self, content: str):
        mock_resp = MagicMock()
        mock_resp.read.side_effect = [content.encode("utf-8"), b""]
        mock_resp.headers = {"Content-Length": str(len(content))}
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None
        return mock_resp

    def test_single_mirror_mismatch_does_not_invalidate_all_candidates(self):
        """5 кандидатов .dat-зеркал: 1-4 с неверным хэшем, 5-й — верный.

        Сценарий: CDN кэширует устаревшие .dat-файлы на зеркалах 1-4
        (разные устаревшие версии, не одна и та же ошибка). Зеркало 5
        отдаёт актуальный файл. reference_hash получен ОДИН РАЗ с
        raw.githubusercontent.com — соответствует актуальному файлу.

        КЛЮЧЕВЫЕ проверки:
          а) _fetch_reference_hash вызван РОВНО ОДИН РАЗ за весь fetch_package
             (не 5 раз, не 0 раз после первого mismatch);
          б) хэш реально пересчитывается и сравнивается для КАЖДОГО из 5
             кандидатов по очереди (не прерывается после первого/второго
             несовпадения);
          в) итоговый результат — файл с кандидата 5, fetch_package вернул
             True, а не False/провал из-за предыдущих 4 несовпадений.
        """
        # 5 разных "устаревших" контентов (каждый со своим хэшем)
        stale_contents = [
            b"stale content v1 from mirror 1" * 10,
            b"stale content v2 from mirror 2" * 10,
            b"stale content v3 from mirror 3" * 10,
            b"stale content v4 from mirror 4" * 10,
        ]
        # Актуальный контент с зеркала 5
        fresh_content = b"fresh content from mirror 5 - the right one" * 10

        # reference_hash соответствует fresh_content
        reference_hash = _hashlib_for_tests.sha256(fresh_content).hexdigest()

        spec = PackageSpec(
            name="test",
            filename_builder=lambda: self.tmp_filename,
            mirror_urls_builder=lambda filename: [
                f"https://mirror1.example.com/{filename}",
                f"https://mirror2.example.com/{filename}",
                f"https://mirror3.example.com/{filename}",
                f"https://mirror4.example.com/{filename}",
                f"https://mirror5.example.com/{filename}",
            ],
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
            checksum_urls=[
                f"https://raw.githubusercontent.com/test/repo/main/{self.tmp_filename}.sha256sum",
            ],
            checksum_algo="sha256",
        )

        call_log = []  # лог URL-ов в порядке вызова

        def fake_urlopen(req, timeout):
            url = req.full_url
            call_log.append(url)

            # Запрос reference_hash (только raw.githubusercontent.com)
            if url.endswith(".sha256sum"):
                return self._make_checksum_response(
                    f"{reference_hash}  {self.tmp_filename}\n"
                )

            # Запрос .dat-файла с одного из 5 зеркал
            if url.endswith(self.tmp_filename):
                # Определяем номер зеркала
                for i in range(1, 5):
                    if f"mirror{i}.example.com" in url:
                        content = stale_contents[i - 1]
                        self.tmp_path.write_bytes(content)
                        return self._make_file_response(content)
                # mirror5 — актуальный
                if "mirror5.example.com" in url:
                    self.tmp_path.write_bytes(fresh_content)
                    return self._make_file_response(fresh_content)

            raise AssertionError(f"Unexpected URL: {url}")

        # Мокаем _fetch_reference_hash чтобы подсчитать его вызовы
        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=fake_urlopen), \
             patch("chimera.modules.download_manager._default_copy_to_dests") as mock_copy, \
             patch("chimera.modules.download_manager.Path.unlink"):
            result = fetch_package(spec, progress_label="test")

        # (в) Файл с зеркала 5 принят, fetch_package вернул True
        self.assertTrue(result,
                        "fetch_package должен вернуть True — зеркало 5 валидное, "
                        "несмотря на 4 предыдущих mismatch. Если False — regression "
                        "бага когда mismatch на одном зеркале инвалидирует все остальные.")

        # (а) reference_hash запрошен ровно 1 раз
        checksum_calls = [u for u in call_log if u.endswith(".sha256sum")]
        self.assertEqual(len(checksum_calls), 1,
                         f"reference_hash должен быть запрошен РОВНО 1 раз, "
                         f"фактически {len(checksum_calls)}: {checksum_calls}. "
                         f"Если >1 — regression: _fetch_reference_hash вызывается "
                         f"повторно для каждого .dat-кандидата. "
                         f"Если 0 — regression: reference_hash вообще не получен.")

        # (б) Все 5 .dat-зеркал были опробованы (хэш пересчитан и сравнён
        # для каждого). Не прервались после первого/второго mismatch.
        dat_calls = [u for u in call_log if u.endswith(self.tmp_filename)
                     and not u.endswith(".sha256sum")]
        self.assertEqual(len(dat_calls), 5,
                         f"Должны быть опробованы ВСЕ 5 .dat-зеркал, "
                         f"фактически {len(dat_calls)}: {dat_calls}. "
                         f"Если <5 — regression: цикл прервался после mismatch "
                         f"вместо continue к следующему зеркалу.")

        # Проверяем порядок: сначала reference_hash, потом mirror1, 2, 3, 4, 5
        self.assertIn(".sha256sum", call_log[0],
                      f"Первый вызов должен быть reference_hash, "
                      f"фактически: {call_log[0]}")
        for i, expected_mirror in enumerate(["mirror1", "mirror2", "mirror3",
                                              "mirror4", "mirror5"], start=1):
            self.assertIn(f"{expected_mirror}.example.com", call_log[i],
                          f"Вызов {i} должен быть к {expected_mirror}, "
                          f"фактически: {call_log[i]}")

        # Только зеркало 5 прошло верификацию → copy вызван 1 раз
        mock_copy.assert_called_once()

    def test_reference_hash_fetched_once_even_with_many_mirrors(self):
        """Дополнительная проверка: с 10 .dat-зеркалами reference_hash
        всё равно запрашивается ОДИН раз, не 10.

        Это явная защита от regression: если кто-то случайно вернёт вызов
        _fetch_reference_hash (или её аналога) ВНУТРЬ цикла for url in urls,
        этот тест упадёт.
        """
        # Все 10 зеркал отдают один и тот же валидный контент
        fresh_content = b"fresh content from any mirror" * 10
        reference_hash = _hashlib_for_tests.sha256(fresh_content).hexdigest()

        mirror_urls = [f"https://mirror{i}.example.com/{self.tmp_filename}"
                       for i in range(1, 11)]

        spec = PackageSpec(
            name="test",
            filename_builder=lambda: self.tmp_filename,
            mirror_urls_builder=lambda filename: mirror_urls,
            install_dests=[self.install_dir],
            manual_incoming_dir=self.manual_dir,
            min_size=50,
            checksum_urls=[
                f"https://raw.githubusercontent.com/test/repo/main/{self.tmp_filename}.sha256sum",
            ],
            checksum_algo="sha256",
        )

        call_log = []
        def fake_urlopen(req, timeout):
            url = req.full_url
            call_log.append(url)
            if url.endswith(".sha256sum"):
                return self._make_checksum_response(
                    f"{reference_hash}  {self.tmp_filename}\n"
                )
            # Все зеркала отдают fresh_content (валидный)
            self.tmp_path.write_bytes(fresh_content)
            return self._make_file_response(fresh_content)

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=fake_urlopen), \
             patch("chimera.modules.download_manager._default_copy_to_dests") as mock_copy, \
             patch("chimera.modules.download_manager.Path.unlink"):
            result = fetch_package(spec, progress_label="test")

        self.assertTrue(result)

        # reference_hash запрошен РОВНО 1 раз (НЕ 10!)
        checksum_calls = [u for u in call_log if u.endswith(".sha256sum")]
        self.assertEqual(len(checksum_calls), 1,
                         f"reference_hash должен быть запрошен 1 раз даже с "
                         f"10 зеркалами, фактически {len(checksum_calls)}. "
                         f"Если >1 — regression: верификация вызывается "
                         f"повторно для каждого .dat-кандидата.")

        # Только первое зеркало прошло (hash совпал) → copy 1 раз,
        # остальные 9 зеркал НЕ опробовались.
        dat_calls = [u for u in call_log if u.endswith(self.tmp_filename)
                     and not u.endswith(".sha256sum")]
        self.assertEqual(len(dat_calls), 1,
                         f"Должно быть опробовано только 1 зеркало (первое "
                         f"с валидным hash), фактически {len(dat_calls)}: {dat_calls}")
        mock_copy.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
