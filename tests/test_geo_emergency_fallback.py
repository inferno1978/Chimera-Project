#!/usr/bin/env python3
"""
tests/test_geo_emergency_fallback.py
───────────────────────────────────────────────────────────────────────────────
Regression-тесты для chimera/modules/geo_files.py::emergency_curl_fallback
и _emergency_curl_one.

ПОКРЫВАЕМЫЕ СЦЕНАРИИ:

1. Regression TypeError: _emergency_curl_one НЕ должен падать с
   "TypeError: _run() got an unexpected keyword argument 'capture_output'"
   при вызове через core._run (который принимает capture=, не capture_output=).
   Баг зафиксирован 2026-07-24 на реальном сервере в РФ — emergency fallback
   падал на самом первом curl-вызове, пользователь видел:
     [WARN] emergency curl exception: TypeError: _run() got an unexpected
            keyword argument 'capture_output'
   Геофайлы не скачивались, установка проваливалась.

2. only_files filter: emergency_curl_fallback должен качать ТОЛЬКО файлы
   из only_files, не трогая другие. Это важно когда fetch_package уже
   успешно скачал один из файлов — не нужно его перезаписывать.

3. SHA256-верификация вызывается когда передан checksum_urls.

4. Возврат False когда curl падает (returncode != 0).

5. Возврат False когда файл слишком маленький (< min_size).

6. Возврат False когда SHA256 не совпал.

ВСЕ тесты мокают core._run и download_manager._fetch_reference_hash — реальная
сеть и реальный curl НЕ вызываются.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_fake_core():
    """Создаёт fake chimera._core с _run как в реальном проекте.

    Реальный core._run имеет сигнатуру:
        _run(args, check=True, quiet=False, capture=False, input_text=None,
             env=None, cwd=None) -> subprocess.CompletedProcess[str]

    НЕ принимает capture_output / text — это аргументы subprocess.run.
    Если код вызывает core._run(capture_output=True) — упадёт с TypeError,
    что и было в баге 2026-07-24.
    """
    import types

    core_src = """
import subprocess
import os

def _run(args, check=True, quiet=False, capture=False, input_text=None, env=None, cwd=None):
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    # Имитируем поведение реального core._run — передаём в subprocess.run
    # capture_output=(capture or quiet), text=True.
    try:
        result = subprocess.run(
            args,
            capture_output=(capture or quiet),
            text=True,
            input=input_text,
            env=merged_env,
            cwd=cwd,
        )
    except FileNotFoundError:
        if check:
            raise
        return subprocess.CompletedProcess(args, 127, stdout="", stderr=f"command not found: {args[0]}")
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, args, result.stdout, result.stderr)
    return result

def info(msg): pass
def warn(msg): pass
def success(msg): pass
def log_to_file(level, msg): pass

# Константы, которые нужны geo_files.py
CONFIG_DIR = Path("/etc/xray")
GEOSITE_DAT = Path("/etc/xray/geosite.dat")
GEOIP_DAT = Path("/etc/xray/geoip.dat")
CYAN = NC = DIM = GREEN = YELLOW = RED = BLUE = BOLD = WHITE = ""

# Минимальный _geo_print_manual_download_hint
def _geo_print_manual_download_hint(): pass
"""

    g = {"Path": Path, "__name__": "chimera._core"}
    exec(compile(core_src, "<fake_core>", "exec"), g)
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core


class TestEmergencyCurlOneNoTypeError(unittest.TestCase):
    """Regression 2026-07-24: _emergency_curl_one НЕ должен падать с
    TypeError: _run() got an unexpected keyword argument 'capture_output'.

    Баг: код вызывал core._run(capture_output=True, text=True, check=False),
    но core._run принимает capture= (не capture_output=) и не принимает text=.

    Фикс: в _emergency_curl_one добавлена функция _do_run, которая вызывает
    core._run(args, check=False, capture=True) с правильными аргументами.
    """

    def setUp(self):
        self.fake_core = _setup_fake_core()
        self.tmpdir = Path(tempfile.mkdtemp(prefix="test_em_curl_"))

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_fake_file(self, size: int = 25_000_000) -> Path:
        """Создаёт фейковый файл-результат curl заданного размера."""
        fake = self.tmpdir / "_fake_geosite.dat"
        fake.write_bytes(b"x" * size)
        return fake

    def _make_mock_run(self, fake_file: Path, returncode: int = 0):
        """Создаёт mock для core._run, который имитирует curl + chown."""
        def mock_run(args, check=True, quiet=False, capture=False,
                     input_text=None, env=None, cwd=None):
            if args and args[0] == "curl":
                # Имитируем curl: копируем fake_file в destination
                for i, a in enumerate(args):
                    if a == "-o" and i + 1 < len(args):
                        Path(args[i + 1]).write_bytes(fake_file.read_bytes())
                        break
                return subprocess.CompletedProcess(args, returncode, "", "")
            if args and args[0] == "chown":
                return subprocess.CompletedProcess(args, 0, "", "")
            return subprocess.CompletedProcess(args, 1, "", "unknown command")
        return mock_run

    def test_no_typeerror_with_core_run(self):
        """ГЛАВНЫЙ regression-тест: core._run с capture=True (не capture_output).

        До фикса: TypeError: _run() got an unexpected keyword argument
        'capture_output'.
        После фикса: _emergency_curl_one корректно вызывает core._run и
        возвращает True.
        """
        from chimera.modules.geo_files import _emergency_curl_one

        fake_file = self._make_fake_file()
        self.fake_core._run = self._make_mock_run(fake_file)

        with patch("chimera.modules.download_manager._fetch_reference_hash",
                   return_value="match_hash"), \
             patch("chimera.modules.download_manager._compute_hash",
                   return_value="match_hash"):
            result = _emergency_curl_one(
                url="https://github.com/test/repo/releases/latest/download/geosite.dat",
                dest_path=self.tmpdir / "dest_geosite.dat",
                min_size=20_000_000,
                checksum_urls=["https://example.com/checksum.sha256sum"],
                progress_label="geosite.dat",
            )

        self.assertTrue(result,
                        "Ожидается True — файл скачан, прошёл размер и SHA256. "
                        "Если упало TypeError про capture_output — это regression "
                        "бага 2026-07-24.")

    def test_returns_false_when_curl_fails(self):
        """Если curl возвращает ненулевой returncode — _emergency_curl_one
        должен вернуть False, не упасть с исключением."""
        from chimera.modules.geo_files import _emergency_curl_one

        fake_file = self._make_fake_file()
        self.fake_core._run = self._make_mock_run(fake_file, returncode=22)

        with patch("chimera.modules.download_manager._fetch_reference_hash",
                   return_value="match_hash"), \
             patch("chimera.modules.download_manager._compute_hash",
                   return_value="match_hash"):
            result = _emergency_curl_one(
                url="https://github.com/test/repo/releases/latest/download/geosite.dat",
                dest_path=self.tmpdir / "dest_geosite.dat",
                min_size=20_000_000,
                checksum_urls=["https://example.com/checksum.sha256sum"],
                progress_label="geosite.dat",
            )

        self.assertFalse(result, "curl с returncode=22 → False")

    def test_returns_false_when_file_too_small(self):
        """Если скачанный файл меньше min_size — _emergency_curl_one
        должен вернуть False."""
        from chimera.modules.geo_files import _emergency_curl_one

        # Файл 5 МБ < min_size 20 МБ
        fake_file = self._make_fake_file(size=5_000_000)
        self.fake_core._run = self._make_mock_run(fake_file)

        with patch("chimera.modules.download_manager._fetch_reference_hash",
                   return_value="match_hash"), \
             patch("chimera.modules.download_manager._compute_hash",
                   return_value="match_hash"):
            result = _emergency_curl_one(
                url="https://github.com/test/repo/releases/latest/download/geosite.dat",
                dest_path=self.tmpdir / "dest_geosite.dat",
                min_size=20_000_000,
                checksum_urls=["https://example.com/checksum.sha256sum"],
                progress_label="geosite.dat",
            )

        self.assertFalse(result, "Файл 5МБ < min_size 20МБ → False")

    def test_returns_false_when_sha256_mismatch(self):
        """Если SHA256 не совпал (reference_hash != actual_hash) — файл отбраковывается,
        возвращается False."""
        from chimera.modules.geo_files import _emergency_curl_one

        fake_file = self._make_fake_file()
        self.fake_core._run = self._make_mock_run(fake_file)

        with patch("chimera.modules.download_manager._fetch_reference_hash",
                   return_value="0" * 64):  # SHA256 НЕ совпал
            result = _emergency_curl_one(
                url="https://github.com/test/repo/releases/latest/download/geosite.dat",
                dest_path=self.tmpdir / "dest_geosite.dat",
                min_size=20_000_000,
                checksum_urls=["https://example.com/checksum.sha256sum"],
                progress_label="geosite.dat",
            )

        self.assertFalse(result,
                         "SHA256 mismatch → False, файл отбракован. Это защита "
                         "от кэшированных устаревших файлов (см. cdadfab).")

    def test_accepts_when_sha256_unavailable(self):
        """Если SHA256 checksum недоступен со всех зеркал (reference_hash is None)
        — деградация до размерной проверки, файл принимается."""
        from chimera.modules.geo_files import _emergency_curl_one

        fake_file = self._make_fake_file()
        self.fake_core._run = self._make_mock_run(fake_file)

        with patch("chimera.modules.download_manager._fetch_reference_hash",
                   return_value=None):  # checksum недоступен
            result = _emergency_curl_one(
                url="https://github.com/test/repo/releases/latest/download/geosite.dat",
                dest_path=self.tmpdir / "dest_geosite.dat",
                min_size=20_000_000,
                checksum_urls=["https://example.com/checksum.sha256sum"],
                progress_label="geosite.dat",
            )

        self.assertTrue(result,
                        "SHA256 недоступен (None) → деградация до размерной "
                        "проверки, файл принят (как в fetch_package).")


class TestEmergencyCurlFallbackOnlyFiles(unittest.TestCase):
    """emergency_curl_fallback с only_files должен качать только указанные
    файлы, не трогая уже успешно скачанные.

    Сценарий: fetch_package успешно скачал geoip.dat, но провалился на
    geosite.dat. failed_files = ['geosite.dat']. emergency_curl_fallback
    вызывается с only_files=['geosite.dat'] — должен качать ТОЛЬКО
    geosite.dat, не geoip.dat.
    """

    def setUp(self):
        self.fake_core = _setup_fake_core()
        self.tmpdir = Path(tempfile.mkdtemp(prefix="test_em_fallback_"))

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_mock_run_with_file(self, file_contents: dict):
        """Создаёт mock core._run, который для curl-вызовов пишет заданный
        контент в destination.

        file_contents: dict {fname: bytes} — какой контент отдать для каждого
        файла. Если curl вызывается для URL содержащего fname — пишем
        file_contents[fname] в -o destination.
        """
        def mock_run(args, check=True, quiet=False, capture=False,
                     input_text=None, env=None, cwd=None):
            if args and args[0] == "curl":
                # URL — последний аргумент
                url = args[-1] if args else ""
                # Находим -o destination
                dest = None
                for i, a in enumerate(args):
                    if a == "-o" and i + 1 < len(args):
                        dest = Path(args[i + 1])
                        break

                # Определяем какой файл скачивается по URL
                content = None
                for fname, data in file_contents.items():
                    if fname in url:
                        content = data
                        break

                if dest is not None and content is not None:
                    dest.write_bytes(content)
                    return subprocess.CompletedProcess(args, 0, "", "")
                return subprocess.CompletedProcess(args, 1, "",
                                                   "unknown file in URL")
            if args and args[0] == "chown":
                return subprocess.CompletedProcess(args, 0, "", "")
            return subprocess.CompletedProcess(args, 1, "", "unknown command")
        return mock_run

    def test_only_geosite_dat_does_not_download_geoip(self):
        """only_files=['geosite.dat'] — curl вызывается только для geosite.dat,
        НЕ для geoip.dat. Это критично: если geoip.dat уже скачан
        fetch_package'ом, мы не должны его перезаписывать."""
        from chimera.modules.geo_files import emergency_curl_fallback

        # Фейковый geosite.dat (большой, проходит min_size)
        geosite_data = b"x" * 25_000_000
        self.fake_core._run = self._make_mock_run_with_file({
            "geosite.dat": geosite_data,
            "geoip.dat": b"y" * 2_000_000,
        })

        # Логируем все curl-вызовы
        curl_urls = []
        original_run = self.fake_core._run

        def logging_run(args, **kw):
            if args and args[0] == "curl":
                curl_urls.append(args[-1])
            return original_run(args, **kw)

        self.fake_core._run = logging_run

        dest_dir = self.tmpdir / "xray"
        dest_dir.mkdir(exist_ok=True)

        with patch("chimera.modules.download_manager._fetch_reference_hash",
                   return_value="match_hash"), \
             patch("chimera.modules.download_manager._compute_hash",
                   return_value="match_hash"):
            result = emergency_curl_fallback(
                dest_dirs=[dest_dir],
                only_files=["geosite.dat"],
                log_to_file=False,
            )

        self.assertTrue(result)
        # КЛЮЧЕВАЯ ПРОВЕРКА: curl вызывался ровно 1 раз, и URL содержит geosite.dat
        self.assertEqual(len(curl_urls), 1,
                         f"Ожидается 1 curl-вызов (только geosite.dat), "
                         f"получено {len(curl_urls)}: {curl_urls}")
        self.assertIn("geosite.dat", curl_urls[0])
        self.assertNotIn("geoip.dat", curl_urls[0])

    def test_only_geoip_dat_does_not_download_geosite(self):
        """only_files=['geoip.dat'] — curl вызывается только для geoip.dat."""
        from chimera.modules.geo_files import emergency_curl_fallback

        self.fake_core._run = self._make_mock_run_with_file({
            "geosite.dat": b"x" * 25_000_000,
            "geoip.dat": b"y" * 2_000_000,
        })

        curl_urls = []
        original_run = self.fake_core._run

        def logging_run(args, **kw):
            if args and args[0] == "curl":
                curl_urls.append(args[-1])
            return original_run(args, **kw)

        self.fake_core._run = logging_run

        dest_dir = self.tmpdir / "xray"
        dest_dir.mkdir(exist_ok=True)

        with patch("chimera.modules.download_manager._fetch_reference_hash",
                   return_value="match_hash"), \
             patch("chimera.modules.download_manager._compute_hash",
                   return_value="match_hash"):
            result = emergency_curl_fallback(
                dest_dirs=[dest_dir],
                only_files=["geoip.dat"],
                log_to_file=False,
            )

        self.assertTrue(result)
        self.assertEqual(len(curl_urls), 1)
        self.assertIn("geoip.dat", curl_urls[0])
        self.assertNotIn("geosite.dat", curl_urls[0])

    def test_no_only_files_downloads_both(self):
        """only_files=None (по умолчанию) — качаем оба файла."""
        from chimera.modules.geo_files import emergency_curl_fallback

        self.fake_core._run = self._make_mock_run_with_file({
            "geosite.dat": b"x" * 25_000_000,
            "geoip.dat": b"y" * 2_000_000,
        })

        curl_urls = []
        original_run = self.fake_core._run

        def logging_run(args, **kw):
            if args and args[0] == "curl":
                curl_urls.append(args[-1])
            return original_run(args, **kw)

        self.fake_core._run = logging_run

        dest_dir = self.tmpdir / "xray"
        dest_dir.mkdir(exist_ok=True)

        with patch("chimera.modules.download_manager._fetch_reference_hash",
                   return_value="match_hash"), \
             patch("chimera.modules.download_manager._compute_hash",
                   return_value="match_hash"):
            result = emergency_curl_fallback(
                dest_dirs=[dest_dir],
                only_files=None,  # оба
                log_to_file=False,
            )

        self.assertTrue(result)
        self.assertEqual(len(curl_urls), 2,
                         f"Ожидается 2 curl-вызова (оба файла), "
                         f"получено {len(curl_urls)}")

    def test_invalid_only_files_returns_false(self):
        """only_files=['nonexistent.dat'] — нет такого файла, возвращаем False."""
        from chimera.modules.geo_files import emergency_curl_fallback

        self.fake_core._run = self._make_mock_run_with_file({})

        dest_dir = self.tmpdir / "xray"
        dest_dir.mkdir(exist_ok=True)

        result = emergency_curl_fallback(
            dest_dirs=[dest_dir],
            only_files=["nonexistent.dat"],
            log_to_file=False,
        )

        self.assertFalse(result)


class TestEmergencyCurlFallbackDestDirs(unittest.TestCase):
    """emergency_curl_fallback должен копировать скачанный файл во ВСЕ
    dest_dirs, не только в первую."""

    def setUp(self):
        self.fake_core = _setup_fake_core()
        self.tmpdir = Path(tempfile.mkdtemp(prefix="test_em_dests_"))

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_file_copied_to_all_dest_dirs(self):
        """Файл должен появиться во всех dest_dirs, не только в первой."""
        from chimera.modules.geo_files import emergency_curl_fallback

        geosite_data = b"x" * 25_000_000

        def mock_run(args, check=True, quiet=False, capture=False,
                     input_text=None, env=None, cwd=None):
            if args and args[0] == "curl":
                url = args[-1] if args else ""
                dest = None
                for i, a in enumerate(args):
                    if a == "-o" and i + 1 < len(args):
                        dest = Path(args[i + 1])
                        break
                if dest and "geosite.dat" in url:
                    dest.write_bytes(geosite_data)
                    return subprocess.CompletedProcess(args, 0, "", "")
                return subprocess.CompletedProcess(args, 1, "", "unknown")
            if args and args[0] == "chown":
                return subprocess.CompletedProcess(args, 0, "", "")
            return subprocess.CompletedProcess(args, 1, "", "unknown")

        self.fake_core._run = mock_run

        # 3 dest dirs
        dest1 = self.tmpdir / "etc_xray"
        dest2 = self.tmpdir / "share_xray"
        dest3 = self.tmpdir / "usrlocal_etc_xray"
        for d in (dest1, dest2, dest3):
            d.mkdir(exist_ok=True)

        with patch("chimera.modules.download_manager._fetch_reference_hash",
                   return_value="match_hash"), \
             patch("chimera.modules.download_manager._compute_hash",
                   return_value="match_hash"):
            result = emergency_curl_fallback(
                dest_dirs=[dest1, dest2, dest3],
                only_files=["geosite.dat"],
                log_to_file=False,
            )

        self.assertTrue(result)

        # КЛЮЧЕВАЯ ПРОВЕРКА: файл есть во всех 3 директориях
        for d in (dest1, dest2, dest3):
            f = d / "geosite.dat"
            self.assertTrue(f.exists(),
                            f"Файл должен быть в {d}, но его там нет")
            self.assertEqual(f.stat().st_size, 25_000_000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
