#!/usr/bin/env python3
"""
tests/test_geo_files.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/geo_files.py.

Покрывает:
  1. _core_module() — importlib dispatcher
  2. download_geo_files() — регрессия 21d7baf: после первого успешного
     запуска файлы уже лежат в dest_dirs (/usr/local/share/xray/, /etc/xray/,
     /usr/local/etc/xray/). Безусловная проверка ручного размещения НЕ должна
     искать файлы в dest_dirs — только в /root/. Иначе повторный вызов
     "Обновить сейчас" тихо копирует сам на себя и репортит успех без
     похода в сеть.
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


class TestCoreModule(unittest.TestCase):
    """_core_module — importlib dispatcher."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_module(self):
        from vless_installer.modules.geo_files import _core_module
        result = _core_module()
        self.assertIsNotNone(result)


class TestDownloadGeoFilesRegression(unittest.TestCase):
    """Регрессия 21d7baf: файлы в dest_dirs не должны блокировать сетевое
    обновление.

    Баг: _MANUAL_ROOTS = MANUAL_UPLOAD_PATHS включал dest_dirs
    (/usr/local/share/xray, /etc/xray, /usr/local/etc/xray). После первого
    успешного запуска файлы лежат в dest_dirs → безусловная проверка
    находила их, копировала сам на себя, репортила успех БЕЗ сети.

    Фикс: _MANUAL_ROOTS = [recommended_manual_path()] = [Path("/root")].
    Безусловная проверка ищет только в /root/. dest_dirs проверяются только
    в retry-блоке после явного подтверждения пользователя.
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

        /tmp/ пути всегда включены — tmp_path.stat() вызывается после shutil.copy2
        (mock no-op), поэтому /tmp/ файлы должны "существовать" в mock-мире.
        """
        existing = set()
        # /tmp/ пути всегда "существуют" (tmp_path.stat() после copy2 mock)
        existing.add("/tmp/geosite.dat")
        existing.add("/tmp/geoip.dat")
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
        БЕЗ обращения к реальному Path.exists (который может вызвать
        PermissionError на /root/ в тест-окружении без root-прав).
        Остальные пути — обычное поведение Path.exists/Path.stat.
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
            return original_exists(self, *a, **kw)

        def mock_stat(self, *a, **kw):
            if str(self) in existing_files:
                return MockStat()
            return original_stat(self, *a, **kw)

        return patch.object(Path, 'exists', mock_exists), \
               patch.object(Path, 'stat', mock_stat)

    def test_files_in_dest_dirs_still_triggers_network_download(self):
        """КЛЮЧЕВОЙ РЕГРЕССИОННЫЙ ТЕСТ:

        Файлы geosite.dat/geoip.dat УЖЕ существуют в dest_dirs
        (/usr/local/share/xray/, /etc/xray/, /usr/local/etc/xray/) от
        предыдущего успешного запуска. Файлов в /root/ НЕТ.

        После фикса: функция должна ПОПЫТАТЬСЯ скачать через сеть
        (_run с curl вызывается), а не тихо скопировать сам на себя.

        До фикса (баг 21d7baf): _MANUAL_ROOTS включал dest_dirs →
        безусловная проверка находила файл → curl НЕ вызывался →
        функция ложно репортила успех.
        """
        from vless_installer.modules import geo_files

        mock_core = self._make_mock_core()
        # _run возвращает успех (curl "скачал" файл)
        mock_core._run.return_value = MagicMock(returncode=0)

        # Файлы существуют в dest_dirs, но НЕ в /root/
        existing_files = self._make_existing_files_set(
            in_dest_dirs=True, in_root=False
        )

        p_exists, p_stat = self._patch_path_exists_stat(existing_files)

        with patch.object(geo_files, "_core_module", return_value=mock_core), \
             p_exists, p_stat, \
             patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
             patch("vless_installer.modules.geo_files.shutil.copy2"), \
             patch("builtins.input", return_value="n"), \
             patch.object(Path, "unlink", lambda self, *a, **kw: None):
            # Нам нужно чтобы curl "записал" файл в tmp_path
            def fake_run(cmd, *a, **kw):
                # Имитируем что curl скачал файл
                if "curl" in cmd and "-o" in cmd:
                    tmp_path = Path(cmd[cmd.index("-o") + 1])
                    tmp_path.write_bytes(b"x" * 10_000_000)
                r = MagicMock()
                r.returncode = 0
                return r

            mock_core._run.side_effect = fake_run

            result = geo_files.download_geo_files()

        # КЛЮЧЕВАЯ ПРОВЕРКА: _run (curl) БЫЛ вызван — сеть была затронута
        self.assertTrue(mock_core._run.called,
                        "curl/_run ДОЛЖЕН быть вызван даже когда файлы уже "
                        "есть в dest_dirs. Баг 21d7baf: безусловная проверка "
                        "по всему MANUAL_UPLOAD_PATHS пропускала скачивание.")

        # Проверяем что именно curl был вызван (а не только chown)
        curl_calls = [c for c in mock_core._run.call_args_list
                      if c.args and "curl" in str(c.args[0])]
        self.assertGreater(len(curl_calls), 0,
                           "Должен быть хотя бы один curl-вызов для скачивания")

        # Функция вернула True (успех)
        self.assertTrue(result)

    def test_files_in_root_skips_network_download(self):
        """Штатный сценарий: файл в /root/ (ручное размещение через WinSCP) —
        используется БЕЗ похода в сеть. Это желаемое поведение, не трогать.

        Проверка: curl/_run НЕ вызывается (кроме chown который не считается
        сетевым запросом).
        """
        from vless_installer.modules import geo_files

        mock_core = self._make_mock_core()
        mock_core._run.return_value = MagicMock(returncode=0)

        # Файлы существуют ТОЛЬКО в /root/ (ручное размещение)
        existing_files = self._make_existing_files_set(
            in_dest_dirs=False, in_root=True
        )

        p_exists, p_stat = self._patch_path_exists_stat(existing_files)

        with patch.object(geo_files, "_core_module", return_value=mock_core), \
             p_exists, p_stat, \
             patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
             patch("vless_installer.modules.geo_files.shutil.copy2"), \
             patch("builtins.input", return_value="n"), \
             patch.object(Path, "unlink", lambda self, *a, **kw: None):
            result = geo_files.download_geo_files()

        # Проверяем что curl НЕ вызывался (файл взят из /root/)
        curl_calls = [c for c in mock_core._run.call_args_list
                      if c.args and "curl" in str(c.args[0])]
        self.assertEqual(len(curl_calls), 0,
                         "curl НЕ должен вызываться когда файл есть в /root/ "
                         "(ручное размещение через WinSCP)")

        # Функция вернула True (успех — файлы найдены локально)
        self.assertTrue(result)

    def test_files_in_dest_dirs_only_does_not_use_them_unconditionally(self):
        """Дополнительная проверка: файлы в dest_dirs (/usr/local/share/xray/)
        но НЕ в /root/ — функция НЕ должна использовать их как "ручное размещение"
        в безусловной проверке.

        Разница с test_files_in_dest_dirs_still_triggers_network_download:
        здесь curl возвращает НЕУДАЧУ (returncode=1) — функция должна провалиться,
        а НЕ тихо взять файл из dest_dirs.
        """
        from vless_installer.modules import geo_files

        mock_core = self._make_mock_core()
        # curl возвращает неудачу для всех зеркал
        mock_core._run.return_value = MagicMock(returncode=1)

        # Файлы существуют в dest_dirs, но НЕ в /root/
        existing_files = self._make_existing_files_set(
            in_dest_dirs=True, in_root=False
        )

        p_exists, p_stat = self._patch_path_exists_stat(existing_files)

        with patch.object(geo_files, "_core_module", return_value=mock_core), \
             p_exists, p_stat, \
             patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
             patch("vless_installer.modules.geo_files.shutil.copy2"), \
             patch("builtins.input", return_value="n"), \
             patch.object(Path, "unlink", lambda self, *a, **kw: None):
            result = geo_files.download_geo_files()

        # КЛЮЧЕВАЯ ПРОВЕРКА: curl БЫЛ вызван (сеть затронута, не пропущена)
        curl_calls = [c for c in mock_core._run.call_args_list
                      if c.args and "curl" in str(c.args[0])]
        self.assertGreater(len(curl_calls), 0,
                           "curl должен вызываться — регрессия 21d7baf: "
                           "безусловная проверка брала файл из dest_dirs и "
                           "пропускала скачивание")

        # Функция вернула False (все зеркала упали, /root/ пуст)
        self.assertFalse(result,
                         "Функция должна провалиться когда curl не сработал "
                         "и /root/ пуст — даже если dest_dirs содержат старые файлы")


if __name__ == "__main__":
    unittest.main(verbosity=2)
