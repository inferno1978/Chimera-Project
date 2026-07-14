#!/usr/bin/env python3
"""
tests/test_geo_files.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/geo_files.py.

Покрывает:
  1. _core_module() — importlib dispatcher
  2. download_geo_files() — мигрирована на download_manager.fetch_package().
     Регрессия 21d7baf: после первого успешного запуска файлы уже лежат в
     install_dests (/usr/local/share/xray/, /etc/xray/, /usr/local/etc/xray/).
     Безусловная проверка ручного размещения (через PackageSpec) ищет
     ТОЛЬКО в /root/ — файлы в install_dests НЕ блокируют сетевое скачивание.
  3. ГЛАВНЫЙ regression-тест: второй вызов подряд с файлом уже лежащим в
     install_dests — сеть ВСЁ РАВНО вызывается (urlopen called).

АДАПТАЦИЯ ПОД НОВЫЙ API:
  Ранее тесты мокали core._run (curl) для проверки сетевых вызовов.
  Теперь download_geo_files() использует fetch_package() из download_manager.py,
  который вызывает urllib.request.urlopen. Тесты мокают urlopen вместо _run.
  Внешне видимое поведение (что пишется в dest_dirs, что происходит при
  провале сети) — НЕ изменилось, только моки под новую реализацию.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
             patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core


class TestCoreModule(unittest.TestCase):
    """_core_module — importlib dispatcher."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_module(self):
        from chimera.modules.geo_files import _core_module
        result = _core_module()
        self.assertIsNotNone(result)


class TestDownloadGeoFilesRegression(unittest.TestCase):
    """Регрессия 21d7baf: файлы в install_dests не должны блокировать сетевое
    обновление.

    Баг: безусловная проверка ручного размещения искала по MANUAL_UPLOAD_PATHS
    который включал dest_dirs. После первого успешного запуска файлы лежат в
    dest_dirs → проверка находила их → копировала сам на себя → репортила
    успех БЕЗ сети.

    Фикс: download_geo_files() использует fetch_package(GEOSITE_SPEC).
    PackageSpec.__post_init__ assert гарантирует manual_incoming_dir (/root/)
    != install_dests. fetch_package проверяет ТОЛЬКО /root/ — файлы в
    install_dests игнорируются, сеть вызывается.

    АДАПТАЦИЯ: тесты мокают urllib.request.urlopen (используется
    fetch_package) вместо core._run (curl, использовался старым кодом).
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def _make_mock_core(self):
        """Создаёт mock core с всеми атрибутами нужными download_geo_files."""
        core = MagicMock()
        for attr in ("GREEN", "NC", "RED", "YELLOW", "CYAN", "BLUE", "DIM", "BOLD", "WHITE"):
            setattr(core, attr, "")
        for attr in ("info", "warn", "success", "error"):
            setattr(core, attr, MagicMock())
        core._geo_print_manual_download_hint = MagicMock()
        core._run = MagicMock()
        core.CONFIG_DIR = Path("/etc/xray")
        core.GEOSITE_DAT = Path("/etc/xray/geosite.dat")
        core.GEOIP_DAT = Path("/etc/xray/geoip.dat")
        core.log_to_file = MagicMock()
        return core

    def _make_existing_files_set(self, in_dest_dirs: bool, in_root: bool):
        """Возвращает set строк-путей которые 'существуют' (для mock Path.exists).

        in_dest_dirs: True — файлы уже лежат в dest_dirs (от предыдущего запуска)
        in_root:      True — файл лежит в /root/ (ручное размещение через WinSCP)
        """
        existing = set()
        if in_dest_dirs:
            for d in ("/usr/local/share/xray", "/etc/xray", "/usr/local/etc/xray"):
                existing.add(f"{d}/geosite.dat")
                existing.add(f"{d}/geoip.dat")
        if in_root:
            existing.add("/root/geosite.dat")
            existing.add("/root/geoip.dat")
        return existing

    def _patch_path_exists_stat(self, existing_files: set):
        """Патчит Path.exists и Path.stat чтобы симулировать существование файлов.

        Файлы в existing_files — существуют с размером 10 МБ (> min_size).
        /root/ пути — всегда возвращают False (нет ручного размещения),
        БЕЗ обращения к реальному Path.exists (PermissionError на /root/
        в тест-окружении без root-прав).
        /tmp/_download_mgr_* пути — всегда возвращают True + 10 МБ (файл
        "скачан" urlopen mock'ом).
        """
        original_exists = Path.exists
        original_stat = Path.stat

        class MockStat:
            st_size = 10_000_000  # 10 МБ > MIN_SIZES для обоих файлов
            st_mtime = 0

        def mock_exists(self, *a, **kw):
            s = str(self)
            if s in existing_files:
                return True
            # /root/ пути — НЕ вызываем реальный Path.exists (PermissionError
            # в тест-окружении без root-прав). Просто возвращаем False.
            if s.startswith("/root/"):
                return False
            # /tmp/_download_mgr_* — "скачанный" файл существует
            if s.startswith("/tmp/_download_mgr_"):
                return True
            return original_exists(self, *a, **kw)

        def mock_stat(self, *a, **kw):
            s = str(self)
            if s in existing_files or s.startswith("/tmp/_download_mgr_"):
                return MockStat()
            return original_stat(self, *a, **kw)

        return patch.object(Path, 'exists', mock_exists), \
               patch.object(Path, 'stat', mock_stat)

    def _make_urlopen_mock(self, success: bool = True):
        """Создаёт mock для urllib.request.urlopen.

        success=True — возвращает "скачанный" файл (10 МБ данных).
        success=False — выбрасывает URLError (сеть заблокирована).
        """
        if not success:
            from urllib.error import URLError
            return MagicMock(side_effect=URLError("blocked"))

        mock_resp = MagicMock()
        mock_resp.read.side_effect = [b"x" * 10_000_000, b""]
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None
        return MagicMock(return_value=mock_resp)

    def test_files_in_dest_dirs_still_triggers_network_download(self):
        """КЛЮЧЕВОЙ РЕГРЕССИОННЫЙ ТЕСТ:

        Файлы geosite.dat/geoip.dat УЖЕ существуют в dest_dirs
        (/usr/local/share/xray/, /etc/xray/, /usr/local/etc/xray/) от
        предыдущего успешного запуска. Файлов в /root/ НЕТ.

        После фикса: функция должна ПОПЫТАТЬСЯ скачать через сеть
        (urllib.request.urlopen вызывается), а не тихо скопировать сам на себя.

        До фикса (баг 21d7baf): безусловная проверка по MANUAL_UPLOAD_PATHS
        находила файл в dest_dirs → urlopen НЕ вызывался → функция ложно
        репортила успех.
        """
        from chimera.modules import geo_files

        mock_core = self._make_mock_core()

        # Файлы существуют в dest_dirs, но НЕ в /root/
        existing_files = self._make_existing_files_set(
            in_dest_dirs=True, in_root=False
        )

        p_exists, p_stat = self._patch_path_exists_stat(existing_files)
        urlopen_mock = self._make_urlopen_mock(success=True)

        with patch.object(geo_files, "_core_module", return_value=mock_core), \
             p_exists, p_stat, \
             patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
             patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
             patch("chimera.modules.download_manager.urllib.request.urlopen",
                   urlopen_mock) as mock_urlopen, \
             patch("shutil.copy2", lambda *a, **kw: None), \
             patch.object(Path, "unlink", lambda self, *a, **kw: None), \
             patch("builtins.open", new_callable=MagicMock), \
             patch("builtins.input", return_value="n"):
            result = geo_files.download_geo_files()

        # КЛЮЧЕВАЯ ПРОВЕРКА: urlopen БЫЛ вызван — сеть была затронута
        self.assertTrue(mock_urlopen.called,
                        "urllib.request.urlopen ДОЛЖЕН быть вызван даже когда "
                        "файлы уже есть в dest_dirs. Баг 21d7baf: безусловная "
                        "проверка по всему MANUAL_UPLOAD_PATHS пропускала скачивание.")

        # Функция вернула True (успех — файлы скачаны)
        self.assertTrue(result)

    def test_files_in_root_skips_network_download(self):
        """Штатный сценарий: файл в /root/ (ручное размещение через WinSCP) —
        используется БЕЗ похода в сеть. Это желаемое поведение, не трогать.

        Проверка: urllib.request.urlopen НЕ вызывается.
        """
        from chimera.modules import geo_files

        mock_core = self._make_mock_core()

        # Файлы существуют ТОЛЬКО в /root/ (ручное размещение)
        existing_files = self._make_existing_files_set(
            in_dest_dirs=False, in_root=True
        )

        p_exists, p_stat = self._patch_path_exists_stat(existing_files)
        urlopen_mock = self._make_urlopen_mock(success=True)

        with patch.object(geo_files, "_core_module", return_value=mock_core), \
             p_exists, p_stat, \
             patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
             patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
             patch("chimera.modules.download_manager.urllib.request.urlopen",
                   urlopen_mock) as mock_urlopen, \
             patch("shutil.copy2", lambda *a, **kw: None), \
             patch.object(Path, "unlink", lambda self, *a, **kw: None), \
             patch("builtins.open", new_callable=MagicMock), \
             patch("builtins.input", return_value="n"):
            result = geo_files.download_geo_files()

        # urlopen НЕ должен вызываться (файл взят из /root/)
        self.assertFalse(mock_urlopen.called,
                         "urllib.request.urlopen НЕ должен вызываться когда "
                         "файл есть в /root/ (ручное размещение через WinSCP)")

        # Функция вернула True (успех — файлы найдены локально)
        self.assertTrue(result)

    def test_files_in_dest_dirs_only_does_not_use_them_unconditionally(self):
        """Дополнительная проверка: файлы в dest_dirs (/usr/local/share/xray/)
        но НЕ в /root/ — функция НЕ должна использовать их как "ручное размещение"
        в безусловной проверке.

        Здесь urlopen возвращает НЕУДАЧУ (URLError) — функция должна провалиться,
        а НЕ тихо взять файл из dest_dirs.
        """
        from chimera.modules import geo_files

        mock_core = self._make_mock_core()

        # Файлы существуют в dest_dirs, но НЕ в /root/
        existing_files = self._make_existing_files_set(
            in_dest_dirs=True, in_root=False
        )

        p_exists, p_stat = self._patch_path_exists_stat(existing_files)
        urlopen_mock = self._make_urlopen_mock(success=False)  # сеть заблокирована

        with patch.object(geo_files, "_core_module", return_value=mock_core), \
             p_exists, p_stat, \
             patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
             patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
             patch("chimera.modules.download_manager.urllib.request.urlopen",
                   urlopen_mock) as mock_urlopen, \
             patch.object(Path, "unlink", lambda self, *a, **kw: None), \
             patch("builtins.input", return_value="n"):
            result = geo_files.download_geo_files()

        # КЛЮЧЕВАЯ ПРОВЕРКА: urlopen БЫЛ вызван (сеть затронута, не пропущена)
        self.assertTrue(mock_urlopen.called,
                        "urllib.request.urlopen должен вызываться — регрессия "
                        "21d7baf: безусловная проверка брала файл из dest_dirs "
                        "и пропускала скачивание")

        # Функция вернула False (все зеркала упали, /root/ пуст)
        self.assertFalse(result,
                         "Функция должна провалиться когда urlopen не сработал "
                         "и /root/ пуст — даже если dest_dirs содержат старые файлы")


class TestDownloadGeoFilesSecondCallRegression(unittest.TestCase):
    """ГЛАВНЫЙ regression-тест (тот, что раньше физически нельзя было
    написать против старого кода):

    Вызвать download_geo_files() с валидным geosite.dat уже лежащим в
    install_dests[1] (XRAY_SHARE_DIR) — и убедиться, что сетевой вызов
    (urlopen) ВСЁ РАВНО происходит.

    Раньше это было невозможно проверить, потому что баг делал именно это
    недостижимым: второй вызов находил свой же файл и не шёл в сеть.

    Теперь PackageSpec.__post_init__ assert физически запрещает
    manual_incoming_dir совпадать с install_dests — баг невозможен по
    конструкции, и этот тест это подтверждает.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def _make_mock_core(self):
        core = MagicMock()
        for attr in ("GREEN", "NC", "RED", "YELLOW", "CYAN", "BLUE", "DIM", "BOLD", "WHITE"):
            setattr(core, attr, "")
        for attr in ("info", "warn", "success", "error"):
            setattr(core, attr, MagicMock())
        core._geo_print_manual_download_hint = MagicMock()
        core._run = MagicMock()
        core.CONFIG_DIR = Path("/etc/xray")
        core.GEOSITE_DAT = Path("/etc/xray/geosite.dat")
        core.GEOIP_DAT = Path("/etc/xray/geoip.dat")
        core.log_to_file = MagicMock()
        return core

    def test_second_call_with_file_in_install_dests_still_uses_network(self):
        """Симуляция второго вызова: geosite.dat УЖЕ лежит в
        /usr/local/share/xray/geosite.dat (install_dests[1]) от первого
        успешного запуска. /root/ пуст.

        urlopen ДОЛЖЕН быть вызван — сеть затронута, не пропущена.
        """
        from chimera.modules import geo_files

        mock_core = self._make_mock_core()

        # Файл УЖЕ лежит в install_dests (симуляция второго вызова)
        existing_files = {
            "/usr/local/share/xray/geosite.dat",
            "/usr/local/share/xray/geoip.dat",
            "/etc/xray/geosite.dat",
            "/etc/xray/geoip.dat",
            "/usr/local/etc/xray/geosite.dat",
            "/usr/local/etc/xray/geoip.dat",
        }

        original_exists = Path.exists
        original_stat = Path.stat

        class MockStat:
            st_size = 10_000_000
            st_mtime = 0

        def mock_exists(self, *a, **kw):
            s = str(self)
            if s in existing_files:
                return True
            if s.startswith("/root/"):
                return False  # /root/ пуст
            if s.startswith("/tmp/_download_mgr_"):
                return True  # "скачанный" файл
            return original_exists(self, *a, **kw)

        def mock_stat(self, *a, **kw):
            s = str(self)
            if s in existing_files or s.startswith("/tmp/_download_mgr_"):
                return MockStat()
            return original_stat(self, *a, **kw)

        # urlopen mock — "успешное скачивание"
        mock_resp = MagicMock()
        mock_resp.read.side_effect = [b"y" * 10_000_000, b""]
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None
        urlopen_mock = MagicMock(return_value=mock_resp)

        with patch.object(geo_files, "_core_module", return_value=mock_core), \
             patch.object(Path, 'exists', mock_exists), \
             patch.object(Path, 'stat', mock_stat), \
             patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
             patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
             patch("chimera.modules.download_manager.urllib.request.urlopen",
                   urlopen_mock) as mock_urlopen, \
             patch("shutil.copy2", lambda *a, **kw: None), \
             patch.object(Path, "unlink", lambda self, *a, **kw: None), \
             patch("builtins.open", new_callable=MagicMock), \
             patch("builtins.input", return_value="n"):
            result = geo_files.download_geo_files()

        # КЛЮЧЕВАЯ ПРОВЕРКА: urlopen БЫЛ вызван — сеть затронута
        # Даже хотя файлы уже лежат во всех install_dests
        self.assertTrue(mock_urlopen.called,
                        "ГЛАВНЫЙ regression-тест: urlopen ДОЛЖЕН быть вызван "
                        "даже при втором вызове с файлами уже в install_dests. "
                        "Баг 21d7baf делал это недостижимым — теперь "
                        "PackageSpec.__post_init__ assert физически запрещает "
                        "manual_incoming_dir совпадать с install_dests.")

        # Функция вернула True (успех — файлы скачаны через сеть)
        self.assertTrue(result)

    def test_package_spec_assert_prevents_bug_by_construction(self):
        """Дополнительная проверка: PackageSpec для geo файлов действительно
        имеет manual_incoming_dir != install_dests. Это структурная защита."""
        from chimera.modules.geo_packages import GEOSITE_SPEC, GEOIP_SPEC

        for spec in (GEOSITE_SPEC, GEOIP_SPEC):
            with self.subTest(spec=spec.name):
                # manual_incoming_dir = /root/
                self.assertEqual(spec.manual_incoming_dir, Path("/root"))
                # /root/ НЕ в install_dests
                self.assertNotIn(Path("/root"), spec.install_dests)
                # install_dests = те же 3 директории что раньше
                self.assertEqual(spec.install_dests, [
                    Path("/etc/xray"),
                    Path("/usr/local/share/xray"),
                    Path("/usr/local/etc/xray"),
                ])


if __name__ == "__main__":
    unittest.main(verbosity=2)
