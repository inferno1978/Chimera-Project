#!/usr/bin/env python3
"""
tests/test_snell_packages.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/snell_packages.py — PackageSpec для установки
бинарника snell-server v4.

Покрывает:
  1. PackageSpec sanity (name, manual_incoming_dir != install_dests)
  2. post_install: ZIP → ELF extraction → копирование в /usr/local/bin
  3. post_install: отклонение не-ZIP файлов (HTML 404 страницы)
  4. post_install: chmod 0o755 на установленный бинарник
  5. filename_builder: формат snell-server-v<ver>-linux-<arch>.zip
  6. mirror_urls_builder: делегирование в snell_mirrors
"""
from __future__ import annotations

import io
import shutil
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Загружает chimera._core через exec и регистрирует в sys.modules.

    Нужно чтобы chimera.modules.snell_packages мог импортировать
    chimera.modules.mieru_packages (который импортирует _atomic_install_binary
    через _core_module()).
    """
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core
    return fake_core


def _make_zip_with_elf(elf_content: bytes = b'\x7fELF' + b'\x00' * (1024 * 1024 + 100),
                       elf_name: str = "snell-server") -> bytes:
    """Создаёт zip-архив с ELF-бинарником внутри, возвращает bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(elf_name, elf_content)
    return buf.getvalue()


class TestSnellSpecSanity(unittest.TestCase):
    """Базовые sanity-проверки PackageSpec."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_name_is_snell_server(self):
        from chimera.modules.snell_packages import SNELL_SPEC
        self.assertEqual(SNELL_SPEC.name, "snell-server")

    def test_manual_dir_not_in_install_dests(self):
        """КРИТИЧЕСКИЙ ИНВАРИАНТ (баг 21d7baf в download_manager).
        manual_incoming_dir НЕ должен совпадать ни с одним install_dests."""
        from chimera.modules.snell_packages import SNELL_SPEC
        for dest in SNELL_SPEC.install_dests:
            self.assertNotEqual(SNELL_SPEC.manual_incoming_dir, dest,
                                "manual_incoming_dir не должен совпадать "
                                "с install_dests")

    def test_install_dests_contains_usr_local_bin(self):
        from chimera.modules.snell_packages import SNELL_SPEC
        self.assertIn(Path("/usr/local/bin"), SNELL_SPEC.install_dests)

    def test_manual_incoming_dir_is_root(self):
        from chimera.modules.snell_packages import SNELL_SPEC
        self.assertEqual(SNELL_SPEC.manual_incoming_dir, Path("/root"))

    def test_min_size_at_least_1mb(self):
        """min_size должен отсекать HTML 404 страницы (~500-800 байт)."""
        from chimera.modules.snell_packages import SNELL_SPEC
        self.assertGreaterEqual(SNELL_SPEC.min_size, 1_000_000)

    def test_post_install_is_callable(self):
        from chimera.modules.snell_packages import SNELL_SPEC
        self.assertTrue(callable(SNELL_SPEC.post_install))


class TestPostInstallZipExtraction(unittest.TestCase):
    """Тестируем _post_install_snell — распаковку zip и установку ELF."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_post_install_extracts_zip_and_copies_elf(self):
        """Корректный zip с ELF внутри → бинарник установлен в install_dests."""
        from chimera.modules.snell_packages import _post_install_snell
        # Создаём zip с ELF-бинарником > 1MB.
        elf_content = b'\x7fELF' + b'\x00' * (1024 * 1024 + 100)
        zip_bytes = _make_zip_with_elf(elf_content=elf_content,
                                       elf_name="snell-server")
        src = self._tmpdir / "snell-server-v4.1.1-linux-amd64.zip"
        src.write_bytes(zip_bytes)
        install_dir = self._tmpdir / "install"
        ok = _post_install_snell(src, [install_dir])
        self.assertTrue(ok, "post_install должен вернуть True для корректного zip")
        dest = install_dir / "snell-server"
        self.assertTrue(dest.exists(), "Бинарник должен быть установлен")
        # Проверяем содержимое.
        with dest.open("rb") as f:
            self.assertEqual(f.read(4), b'\x7fELF')

    def test_post_install_chmods_binary_to_755(self):
        """Установленный бинарник должен иметь chmod 0o755."""
        from chimera.modules.snell_packages import _post_install_snell
        elf_content = b'\x7fELF' + b'\x00' * (1024 * 1024 + 100)
        zip_bytes = _make_zip_with_elf(elf_content=elf_content)
        src = self._tmpdir / "test.zip"
        src.write_bytes(zip_bytes)
        install_dir = self._tmpdir / "install"
        _post_install_snell(src, [install_dir])
        dest = install_dir / "snell-server"
        self.assertEqual(oct(dest.stat().st_mode & 0o777), '0o755')

    def test_post_install_rejects_non_zip_non_elf(self):
        """HTML 404 страница должна быть отклонена."""
        from chimera.modules.snell_packages import _post_install_snell
        src = self._tmpdir / "fake.zip"
        src.write_bytes(b"<html>404 Not Found</html>" * 100)
        ok = _post_install_snell(src, [self._tmpdir / "install"])
        self.assertFalse(ok, "post_install должен отклонить HTML")

    def test_post_install_rejects_empty_file(self):
        """Пустой файл должен быть отклонён."""
        from chimera.modules.snell_packages import _post_install_snell
        src = self._tmpdir / "empty.zip"
        src.write_bytes(b"")
        ok = _post_install_snell(src, [self._tmpdir / "install"])
        self.assertFalse(ok)

    def test_post_install_accepts_direct_elf(self):
        """Если src уже ELF (админ распаковал вручную) — принимаем напрямую."""
        from chimera.modules.snell_packages import _post_install_snell
        src = self._tmpdir / "snell-server"
        # ELF magic + > 1MB.
        src.write_bytes(b'\x7fELF' + b'\x00' * (1024 * 1024 + 100))
        install_dir = self._tmpdir / "install"
        ok = _post_install_snell(src, [install_dir])
        self.assertTrue(ok)
        self.assertTrue((install_dir / "snell-server").exists())

    def test_post_install_rejects_zip_without_elf(self):
        """Zip без ELF-бинарника внутри должен быть отклонён."""
        from chimera.modules.snell_packages import _post_install_snell
        # Zip с readme.txt, без ELF.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.txt", "This is not an ELF binary.")
        src = self._tmpdir / "noelf.zip"
        src.write_bytes(buf.getvalue())
        ok = _post_install_snell(src, [self._tmpdir / "install"])
        self.assertFalse(ok)

    def test_post_install_finds_elf_in_subdirectory(self):
        """ELF в подпапке zip-архива должна быть найдена."""
        from chimera.modules.snell_packages import _post_install_snell
        elf_content = b'\x7fELF' + b'\x00' * (1024 * 1024 + 100)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("subdir/snell-server", elf_content)
        src = self._tmpdir / "subdir.zip"
        src.write_bytes(buf.getvalue())
        install_dir = self._tmpdir / "install"
        ok = _post_install_snell(src, [install_dir])
        self.assertTrue(ok)


class TestFilenameBuilder(unittest.TestCase):
    """filename_builder PackageSpec должен возвращать корректное имя файла."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_filename_default_version(self):
        from chimera.modules.snell_packages import SNELL_SPEC
        fn = SNELL_SPEC.filename_builder()
        self.assertIn("snell-server-v", fn)
        self.assertTrue(fn.endswith(".zip"))

    def test_filename_explicit_version(self):
        from chimera.modules.snell_packages import SNELL_SPEC
        fn = SNELL_SPEC.filename_builder(version="4.1.1", arch="amd64")
        self.assertEqual(fn, "snell-server-v4.1.1-linux-amd64.zip")

    def test_filename_strips_v_prefix(self):
        """Если версия передана с 'v' префиксом — он не дублируется."""
        from chimera.modules.snell_packages import SNELL_SPEC
        fn = SNELL_SPEC.filename_builder(version="v4.1.1", arch="amd64")
        self.assertEqual(fn, "snell-server-v4.1.1-linux-amd64.zip")
        self.assertNotIn("vv", fn)


class TestMirrorUrlsBuilder(unittest.TestCase):
    """mirror_urls_builder должен возвращать список URL-ов."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_non_empty_list(self):
        from chimera.modules.snell_packages import SNELL_SPEC
        urls = SNELL_SPEC.mirror_urls_builder(
            filename="snell-server-v4.1.1-linux-amd64.zip",
            version="4.1.1",
        )
        self.assertGreater(len(urls), 0)

    def test_parses_version_from_filename(self):
        """Если только filename= передан — версия извлекается из него."""
        from chimera.modules.snell_packages import _snell_mirror_urls
        urls = _snell_mirror_urls("snell-server-v4.1.1-linux-amd64.zip")
        self.assertGreater(len(urls), 0)
        # Все URL должны содержать версию или быть валидными зеркалами.
        for url in urls:
            self.assertTrue(url.startswith("https://"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
