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
#  ТЕСТЫ MIN_SIZES — отбраковка слишком маленьких файлов (v5.0.1)
# ============================================================================

class TestFetchPackageMinSizeRejection(unittest.TestCase):
    """fetch_package() — отбраковка файлов меньше min_size и retry на следующее зеркало.

    v5.0.1: на проде был инцидент — CDN отдал устаревший geosite.dat (10 МБ
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
#  ТЕСТЫ sha256-верификации (v5.0.2)
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

    v5.0.2: после успешной загрузки файла (размер >= min_size) дополнительно
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
        файл (mirror1) — большой, но не текущий. .sha256sum на mirror1
        тоже закэширован и соответствует НОВОЙ версии файла, поэтому
        hash не совпадает со старым файлом → отбраковка. Mirror2 отдаёт
        актуальный файл, .sha256sum совпадает → успех.

        Симметрично: checksum_urls перебираются по порядку, независимо
        от того, какое зеркало дало сам файл (см. спеку v5.0.2). Это
        гарантирует верификацию того, что РЕАЛЬНО пришло, а не того,
        что зеркало "должно" было отдать.

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

        # Единый "правильный" hash для актуального файла — оба checksum-зеркала
        # отдают одно и то же (апстрим публикует один .sha256sum, CDN кэшируют).
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
            checksum_urls=[
                f"https://mirror1.example.com/{self.tmp_filename}.sha256sum",
                f"https://mirror2.example.com/{self.tmp_filename}.sha256sum",
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

            # Запрос checksum — оба checksum-зеркала отдают актуальный hash
            # (апстрим обновил .sha256sum, CDN кэширует его быстрее, чем сам
            # большой .dat файл — реалистичный сценарий с jsDelivr)
            if url.endswith(".sha256sum"):
                return self._make_checksum_response(f"{fresh_hash}  {self.tmp_filename}\n")

            raise AssertionError(f"Unexpected URL: {url}")

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=fake_urlopen), \
             patch("chimera.modules.download_manager._default_copy_to_dests") as mock_copy, \
             patch("chimera.modules.download_manager.Path.unlink"):
            result = fetch_package(spec, progress_label="test")

        self.assertTrue(result, "Должен вернуть True — второе зеркало прошло верификацию")

        # mirror1: file1 → checksum1 (mismatch, fresh_hash vs stale_content hash)
        # mirror2: file2 → checksum1 (match, fresh_hash vs fresh_content hash)
        # Итого: 4 вызова (2 файла + 2 checksum — на mirror2 первый же checksum_url совпал)
        self.assertGreaterEqual(len(call_log), 3,
                               f"Должно быть минимум 3 вызова (file1 + checksum1 + file2 + checksum1), фактически: {call_log}")
        self.assertLessEqual(len(call_log), 4,
                             f"Не более 4 вызовов, фактически: {call_log}")

        # Проверяем что первый запрос был к mirror1 (файл)
        self.assertIn(f"mirror1.example.com/{self.tmp_filename}", call_log[0])
        # Второй — к .sha256sum (mirror1)
        self.assertIn(".sha256sum", call_log[1])

        # Только второе зеркало прошло верификацию → copy вызван 1 раз
        mock_copy.assert_called_once()

    def test_hash_match_accepts_first_mirror(self):
        """Сценарий 2: hash совпал → файл принят с первой попытки.

        Симулируем: единственное зеркало, файл валидного размера,
        .sha256sum совпадает → успех с первого раза.

        КЛЮЧЕВЫЕ проверки:
          - urlopen вызван 2 раза (1 файл + 1 checksum)
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
                f"https://mirror1.example.com/{self.tmp_filename}.sha256sum",
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
                         f"Должно быть 2 вызова (1 файл + 1 checksum), фактически: {call_log}")
        mock_copy.assert_called_once()

    def test_all_checksum_urls_404_degrades_to_size_check(self):
        """Сценарий 3: все checksum_url 404 → деградация до размерной проверки.

        Симулируем: единственное зеркало, файл валидного размера,
        но .sha256sum возвращает 404 на ВСЕХ checksum-зеркалах →
        fetch_package принимает файл по размерной проверке с warn.

        КЛЮЧЕВЫЕ проверки:
          - urlopen вызван 1 + N раз (1 файл + N попыток checksum)
          - _default_copy_to_dests вызван 1 раз (файл принят по размеру)
          - fetch_package вернул True (не упал)
          - В логе виден warn "не удалось проверить ... принято по размеру"
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
            checksum_urls=[
                f"https://mirror1.example.com/{self.tmp_filename}.sha256sum",
                f"https://mirror2.example.com/{self.tmp_filename}.sha256sum",
                f"https://mirror3.example.com/{self.tmp_filename}.sha256sum",
            ],
            checksum_algo="sha256",
        )

        call_log = []

        def fake_urlopen(req, timeout):
            url = req.full_url
            call_log.append(url)

            if url.endswith(".sha256sum"):
                # Все checksum-зеркала возвращают 404 / network error
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
        # 1 вызов файла + 3 попытки checksum (все упали)
        self.assertEqual(len(call_log), 4,
                         f"Должно быть 4 вызова (1 файл + 3 checksum), фактически: {call_log}")
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

        Симулируем: зеркало отдаёт .sha256sum с мусором (нет 64-символьного hex)
        на ВСЕХ checksum-зеркалах → деградация до размерной проверки.

        Это отличается от сценария 3 (404) — здесь checksum_obtained=True,
        но парсинг не удался. Должна быть другая ветка warn.
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
            checksum_urls=[
                f"https://mirror1.example.com/{self.tmp_filename}.sha256sum",
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
        # В логе должен быть warn о невозможности распарсить
        output = captured.getvalue()
        # Либо "не удалось распарсить" (из цикла), либо "hex не распарсен" (финал)
        self.assertTrue(
            "распарсить" in output.lower() or "распарсен" in output.lower(),
            f"Должен быть warn о проблеме парсинга, вывод: {output}",
        )


class TestVerifyChecksumHelper(unittest.TestCase):
    """Прямые тесты _verify_checksum() — без overhead полного fetch_package.

    Покрывает edge cases:
      - Пустой список checksum_urls → None (деградация)
      - Несколько checksum_urls, первый отвечает с совпадением → True
      - Несколько checksum_urls, первый 404, второй отвечает с несовпадением → False
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.test_file = Path(self.tmpdir) / "test.dat"
        self.test_file.write_bytes(b"test content" * 10)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_empty_checksum_urls_returns_none(self):
        """Пустой список checksum_urls → None (деградация, не отбраковка)."""
        from chimera.modules.download_manager import _verify_checksum
        result = _verify_checksum(self.test_file, [], "sha256")
        self.assertIsNone(result)

    def test_first_url_matches_returns_true(self):
        """Первый checksum_url отвечает с совпадающим hash → True."""
        from chimera.modules.download_manager import _verify_checksum
        right_hash = _hashlib_for_tests.sha256(b"test content" * 10).hexdigest()

        def fake_urlopen(req, timeout):
            mock_resp = MagicMock()
            mock_resp.read.side_effect = [f"{right_hash}  test.dat\n".encode(), b""]
            mock_resp.__enter__ = lambda self: self
            mock_resp.__exit__ = lambda self, *a: None
            return mock_resp

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=fake_urlopen):
            result = _verify_checksum(
                self.test_file,
                ["https://example.com/test.dat.sha256sum"],
                "sha256",
            )
        self.assertTrue(result)

    def test_first_404_second_mismatch_returns_false(self):
        """Первый checksum_url 404, второй отвечает с НЕсовпадающим hash → False."""
        from chimera.modules.download_manager import _verify_checksum
        wrong_hash = _hashlib_for_tests.sha256(b"different content").hexdigest()

        from urllib.error import URLError
        call_count = [0]

        def fake_urlopen(req, timeout):
            call_count[0] += 1
            if call_count[0] == 1:
                raise URLError("404")
            mock_resp = MagicMock()
            mock_resp.read.side_effect = [f"{wrong_hash}  test.dat\n".encode(), b""]
            mock_resp.__enter__ = lambda self: self
            mock_resp.__exit__ = lambda self, *a: None
            return mock_resp

        with patch("chimera.modules.download_manager.urllib.request.urlopen",
                   side_effect=fake_urlopen):
            result = _verify_checksum(
                self.test_file,
                [
                    "https://mirror1.example.com/test.dat.sha256sum",
                    "https://mirror2.example.com/test.dat.sha256sum",
                ],
                "sha256",
            )
        self.assertFalse(result, "Hash не совпал → False (отбраковка)")
        self.assertEqual(call_count[0], 2, "Должны быть попытаны оба URL")


class TestChecksumNotCalledInManualBranch(unittest.TestCase):
    """v5.0.2 regression-тест: _verify_checksum НЕ вызывается в manual-ветке.

    Когда файл найден в manual_incoming_dir (/root/ — ручное размещение
    через WinSCP), fetch_package использует его без сети и БЕЗ sha256-
    верификации. Это самый быстрый путь получения файла (пользователь
    сам туда кладёт то, что скачал вручную через curl), верификация по
    хэшу там избыточна.

    Если бы _verify_checksum вызывался в manual-ветке, глобальные моки
    builtins.open в других тестах (например в test_geo_files.py) ломали
    бы _compute_hash → fetch_package возвращал бы False → regression.

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
        """Файл в manual_dir → _verify_checksum НЕ вызывается."""
        # Создаём валидный файл в manual_dir
        manual_file = self.manual_dir / "test.dat"
        manual_file.write_bytes(b"x" * 100)

        # Spec с checksum_urls — если бы они использовались в manual-ветке,
        # тест упал бы на mock_verify.assert_not_called()
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
             patch("chimera.modules.download_manager._verify_checksum") as mock_verify, \
             patch("chimera.modules.download_manager._default_copy_to_dests"):
            result = fetch_package(spec)

        self.assertTrue(result, "fetch_package должен вернуть True (manual-файл валидный)")
        mock_urlopen.assert_not_called()
        mock_verify.assert_not_called()


# ============================================================================
#  v5.0.4 REGRESSION TEST: файл в install_dests должен иметь каноническое имя
# ============================================================================
# КРИТИЧЕСКИЙ regression-тест на баг, обнаруженный 22.07.2026 на проде:
# geosite.dat/geoip.dat копировались под именем '_download_mgr_geosite.dat'
# вместо 'geosite.dat' — из-за того что _post_install_geo и
# _default_copy_to_dests использовали src.name, а src был tmp_path =
# /tmp/_download_mgr_{filename}. Баг введён в fbb2285 (10.07.2026), жил 12
# дней, все geo-обновления за это время были no-op по факту.

class TestCanonicalFileNameInInstallDests(unittest.TestCase):
    """v5.0.4 regression: файл в install_dests должен называться
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
