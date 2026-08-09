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
from unittest.mock import patch, MagicMock, mock_open

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

        Файлы в existing_files — существуют с размером 30 МБ (> min_size).
        /root/ пути — всегда возвращают False (нет ручного размещения),
        БЕЗ обращения к реальному Path.exists (PermissionError на /root/
        в тест-окружении без root-прав).
        /tmp/_download_mgr_* пути — всегда возвращают True + 30 МБ (файл
        "скачан" urlopen mock'ом).

         FIX: расширено для поддержки _post_install_geo, который
        после shutil.copy2(src, dest) вызывает dest.stat().st_size для
        проверки что копия записалась. dest-пути (в /etc/xray/,
        /usr/local/share/xray/, /usr/local/etc/xray/) с суффиксом
        geosite.dat/geoip.dat теперь тоже возвращают True + MockStat,
        даже если их не было в existing_files — потому что copy2 их
        "создаёт". Раньше dest.stat() падал с FileNotFoundError →
        _post_install_geo возвращал False → fetch_package возвращал
        False → тест падал на assertTrue(result).
        """
        original_exists = Path.exists
        original_stat = Path.stat

        class MockStat:
            st_size = 30_000_000  # 30 МБ > MIN_SIZES для обоих файлов ( geosite=20MB, geoip=1MB)
            st_mtime = 0

        # Имена файлов, для которых dest.stat() должен вернуть MockStat
        # даже после copy2 — это geo-файлы в трёх директориях Xray.
        _GEO_FILENAMES = ("geosite.dat", "geoip.dat")
        _GEO_DIRS = ("/etc/xray/", "/usr/local/share/xray/", "/usr/local/etc/xray/")

        def _is_geo_dest(s: str) -> bool:
            """True если s — путь к geo-файлу в одной из dest-директорий Xray.

            Например: '/etc/xray/geosite.dat' → True
                      '/usr/local/share/xray/geoip.dat' → True
                      '/etc/xray/config.json' → False (не geo-файл)
            """
            return any(s.startswith(d) for d in _GEO_DIRS) and \
                   any(s.endswith(fn) for fn in _GEO_FILENAMES)

        def _is_tmp_geo(s: str) -> bool:
            """True если s — tmp-путь к geo-файлу (любой вариант имени).

             после фикса tmp_path переименования, файл в /tmp/
            называется канонически (/tmp/geosite.dat), а не
            /tmp/_download_mgr_geosite.dat. Покрываем оба варианта,
            чтобы тест работал и со старым (до фикса) и с новым кодом.
            """
            return (s.startswith("/tmp/_download_mgr_") and
                    any(s.endswith(fn) for fn in _GEO_FILENAMES)) or \
                   (s.startswith("/tmp/") and
                    any(s == f"/tmp/{fn}" for fn in _GEO_FILENAMES))

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
            #  canonical tmp path после rename — /tmp/{filename}
            if _is_tmp_geo(s):
                return True
            #  geo-файлы в dest-директориях "создаются" copy2 в
            # _post_install_geo — даже если их не было в existing_files,
            # dest.stat() должен их видеть.
            if _is_geo_dest(s):
                return True
            return original_exists(self, *a, **kw)

        def mock_stat(self, *a, **kw):
            s = str(self)
            if s in existing_files or s.startswith("/tmp/_download_mgr_"):
                return MockStat()
            #  canonical tmp path после rename
            if _is_tmp_geo(s):
                return MockStat()
            #  geo-файлы в dest-директориях — copy2 "создал" их,
            # dest.stat() должен вернуть MockStat чтобы size-check
            # (dest_size == src_size) прошёл.
            if _is_geo_dest(s):
                return MockStat()
            return original_stat(self, *a, **kw)

        return patch.object(Path, 'exists', mock_exists), \
               patch.object(Path, 'stat', mock_stat)

    def _make_urlopen_mock(self, success: bool = True):
        """Создаёт mock для urllib.request.urlopen.

        success=True — возвращает "скачанный" файл (10 МБ данных).
        success=False — выбрасывает URLError (сеть заблокирована).

         КАЖДЫЙ вызов urlopen() возвращает НОВЫЙ mock_resp со
        свежим read.side_effect. Раньше mock_resp был один на все вызовы,
        и после 2 вызовов read() (в _fetch_reference_hash + первый chunk
        в основном цикле) side_effect исчерпывался → StopIteration →
        все 14 зеркал "падали" → fetch_package возвращал False.
        """
        if not success:
            from urllib.error import URLError
            return MagicMock(side_effect=URLError("blocked"))

        def make_fresh_resp():
            """Создаёт свежий mock_resp с полным side_effect."""
            r = MagicMock()
            r.read.side_effect = [b"x" * 30_000_000, b""]
            r.headers = {"Content-Length": "30000000"}
            r.__enter__ = lambda self: self
            r.__exit__ = lambda self, *a: None
            return r

        # return_value — это factory, который для каждого urlopen() вызова
        # создаёт НОВЫЙ mock_resp. MagicMock(return_value=X) возвращает X
        # каждый раз, нам нужно side_effect который возвращает новый объект.
        return MagicMock(side_effect=lambda *a, **kw: make_fresh_resp())

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

         мок builtins.open заменён с голого MagicMock на mock_open
        с реальным бинарным содержимым. Раньше глобальный MagicMock ломал
        _compute_hash (f.read() возвращал MagicMock, не bytes, hashlib.update
        падал с TypeError). Теперь _compute_hash корректно читает bytes и
        либо верифицирует файл (если checksum_urls доступны), либо деградирует
        с warn, но не падает с TypeError.
        """
        from chimera.modules import geo_files

        mock_core = self._make_mock_core()

        # Файлы существуют в dest_dirs, но НЕ в /root/
        existing_files = self._make_existing_files_set(
            in_dest_dirs=True, in_root=False
        )

        p_exists, p_stat = self._patch_path_exists_stat(existing_files)
        urlopen_mock = self._make_urlopen_mock(success=True)

        # mock_open с read_data возвращает bytes для f.read(N) — нужно для
        # _compute_hash, который вызывается в sha256-верификации.
        # Без read_data _compute_hash.get('rb').read() вернул бы MagicMock,
        # что ломает hashlib.update.
        mock_open_inst = mock_open(read_data=b"x" * 65536)

        with patch.object(geo_files, "_core_module", return_value=mock_core), \
             p_exists, p_stat, \
             patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
             patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
             patch("chimera.modules.download_manager.urllib.request.urlopen",
                   urlopen_mock) as mock_urlopen, \
             patch("shutil.copy2", lambda *a, **kw: None), \
             patch.object(Path, "unlink", lambda self, *a, **kw: None), \
             patch.object(Path, "rename", lambda self, *a, **kw: None), \
             patch("builtins.open", mock_open_inst), \
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

         тест использует _patch_path_exists_stat (расширенный mock
        Path.exists/stat для dest-путей) и mock_open вместо голого MagicMock.
        Без этого _post_install_geo падал на dest.stat().st_size (реальный
        Path.stat на несуществующем /etc/xray/geosite.dat → FileNotFoundError),
        и fetch_package возвращал False хотя manual-файл был найден в /root/.
        Сетевая ветка (где _compute_hash) тут не должна вызываться — но mock_open
        оставлен для консистентности и на случай будущих изменений.
        """
        from chimera.modules import geo_files

        mock_core = self._make_mock_core()

        # Файлы существуют ТОЛЬКО в /root/ (ручное размещение)
        existing_files = self._make_existing_files_set(
            in_dest_dirs=False, in_root=True
        )

        p_exists, p_stat = self._patch_path_exists_stat(existing_files)
        urlopen_mock = self._make_urlopen_mock(success=True)

        mock_open_inst = mock_open(read_data=b"x" * 65536)

        with patch.object(geo_files, "_core_module", return_value=mock_core), \
             p_exists, p_stat, \
             patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
             patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
             patch("chimera.modules.download_manager.urllib.request.urlopen",
                   urlopen_mock) as mock_urlopen, \
             patch("shutil.copy2", lambda *a, **kw: None), \
             patch.object(Path, "unlink", lambda self, *a, **kw: None), \
             patch.object(Path, "rename", lambda self, *a, **kw: None), \
             patch("builtins.open", mock_open_inst), \
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

         как и в TestDownloadGeoFilesRegression, mock Path.exists/stat
        расширен чтобы покрывать geo-файлы в dest-директориях (нужны для
        _post_install_geo который вызывает dest.stat().st_size после copy2).
        mock builtins.open заменён с голого MagicMock на mock_open с реальным
        бинарным содержимым — нужно для _compute_hash в sha256-верификации.
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
            st_size = 30_000_000  # 30 МБ > MIN_SIZES 
            st_mtime = 0

        # Geo-файлы в dest-директориях — нужны для _post_install_geo size-check
        _GEO_FILENAMES = ("geosite.dat", "geoip.dat")
        _GEO_DIRS = ("/etc/xray/", "/usr/local/share/xray/", "/usr/local/etc/xray/")

        def _is_geo_dest(s: str) -> bool:
            return any(s.startswith(d) for d in _GEO_DIRS) and \
                   any(s.endswith(fn) for fn in _GEO_FILENAMES)

        def _is_tmp_geo(s: str) -> bool:
            """ canonical tmp path /tmp/{filename} (после rename)
            + старый /tmp/_download_mgr_{filename} (до фикса)."""
            return (s.startswith("/tmp/_download_mgr_") and
                    any(s.endswith(fn) for fn in _GEO_FILENAMES)) or \
                   (s.startswith("/tmp/") and
                    any(s == f"/tmp/{fn}" for fn in _GEO_FILENAMES))

        def mock_exists(self, *a, **kw):
            s = str(self)
            if s in existing_files:
                return True
            if s.startswith("/root/"):
                return False  # /root/ пуст
            if s.startswith("/tmp/_download_mgr_"):
                return True  # "скачанный" файл
            #  canonical tmp path после rename
            if _is_tmp_geo(s):
                return True
            #  copy2 в _post_install_geo "создаёт" dest-файлы
            if _is_geo_dest(s):
                return True
            return original_exists(self, *a, **kw)

        def mock_stat(self, *a, **kw):
            s = str(self)
            if s in existing_files or s.startswith("/tmp/_download_mgr_"):
                return MockStat()
            #  canonical tmp path после rename
            if _is_tmp_geo(s):
                return MockStat()
            #  dest-файлы после copy2 — size-check должен пройти
            if _is_geo_dest(s):
                return MockStat()
            return original_stat(self, *a, **kw)

        # urlopen mock — "успешное скачивание"
        #  КАЖДЫЙ вызов urlopen() возвращает НОВЫЙ mock_resp со
        # свежим read.side_effect. Раньше один mock_resp на все вызовы,
        # и после 2 read() (в _fetch_reference_hash + первый chunk) side_effect
        # исчерпывался → StopIteration → все 14 зеркал "падали" → False.
        def make_fresh_resp():
            r = MagicMock()
            r.read.side_effect = [b"y" * 30_000_000, b""]
            r.headers = {"Content-Length": "30000000"}
            r.__enter__ = lambda self: self
            r.__exit__ = lambda self, *a: None
            return r
        urlopen_mock = MagicMock(side_effect=lambda *a, **kw: make_fresh_resp())

        mock_open_inst = mock_open(read_data=b"y" * 65536)

        with patch.object(geo_files, "_core_module", return_value=mock_core), \
             patch.object(Path, 'exists', mock_exists), \
             patch.object(Path, 'stat', mock_stat), \
             patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
             patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
             patch("chimera.modules.download_manager.urllib.request.urlopen",
                   urlopen_mock) as mock_urlopen, \
             patch("shutil.copy2", lambda *a, **kw: None), \
             patch.object(Path, "unlink", lambda self, *a, **kw: None), \
             patch.object(Path, "rename", lambda self, *a, **kw: None), \
             patch("builtins.open", mock_open_inst), \
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
