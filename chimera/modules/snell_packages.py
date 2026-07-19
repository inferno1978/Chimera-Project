"""
chimera/modules/snell_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec для установки бинарника snell-server v4 (Surge / nssurge.com).

Архитектура:
  1. download_manager.fetch_package(SNELL_SPEC) скачивает zip-архив
     (через snell_mirrors.get_snell_mirrors)
  2. _post_install_snell(src, install_dests):
     a) проверяет что src — это zip (magic bytes PK\x03\x04)
     b) распаковывает zip во временную директорию
     c) находит внутри ELF-бинарник snell-server (magic \x7fELF)
     d) копирует в /usr/local/bin/snell-server с chmod 0o755
     e) возвращает True если всё прошло OK

PackageSpec.manual_incoming_dir НЕ должен совпадать ни с одним install_dests
— это критический инварант (см. баг 21d7baf в download_manager.py). Используем
/root для manual_uploads и /usr/local/bin для install — они не пересекаются.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import shutil
import zipfile
from pathlib import Path
from typing import Callable, Optional

from chimera.modules.download_manager import PackageSpec
from chimera.modules.snell_mirrors import (
    SNELL_DEFAULT_VERSION,
    get_snell_mirrors,
    _snell_filename,
)

# ─── Пути установки ──────────────────────────────────────────────────────────
_SNELL_BIN = Path("/usr/local/bin/snell-server")
_SNELL_INSTALL_DESTS: list[Path] = [Path("/usr/local/bin")]
_SNELL_DEST_FILENAME = "snell-server"
_MANUAL_DIR = Path("/root")

# Минимальный размер ELF-бинарника Snell. Реально ~3-5MB, но ставим 1MB
# чтобы отсечь HTML-страницы 404 (типично ~500-800 байт) и пустые файлы.
_MIN_SNELL_BINARY_SIZE = 1_000_000

# Magic bytes для проверки содержимого.
_ZIP_MAGIC = b"PK\x03\x04"
_ELF_MAGIC = b"\x7fELF"


def _snell_mirror_urls(filename: str, version: str = SNELL_DEFAULT_VERSION,
                       **kw) -> list[str]:
    """Адаптер для PackageSpec.mirror_urls_builder.

    PackageSpec передаёт filename= как keyword, get_snell_mirrors ожидает
    version= + arch=. Извлекаем версию из filename (формат
    snell-server-v4.1.1-linux-amd64.zip) — архитектуру можно вытащить
    тоже, но проще делегировать в snell_mirrors._arch_suffix() который
    сам определит её по platform.machine().
    """
    # Если filename пришёл — парсим версию из него, иначе берём default.
    if filename and filename.startswith("snell-server-v"):
        # snell-server-v4.1.1-linux-amd64.zip → "4.1.1"
        try:
            ver_part = filename[len("snell-server-v"):]
            ver = ver_part.split("-linux-")[0]
            return get_snell_mirrors(version=ver)
        except (IndexError, ValueError):
            pass
    return get_snell_mirrors(version=version)


def _is_zip(path: Path) -> bool:
    """Проверяет magic bytes zip-архива."""
    try:
        with path.open("rb") as f:
            return f.read(4) == _ZIP_MAGIC
    except (OSError, PermissionError):
        return False


def _is_elf(path: Path) -> bool:
    """Проверяет magic bytes ELF-бинарника."""
    try:
        with path.open("rb") as f:
            return f.read(4) == _ELF_MAGIC
    except (OSError, PermissionError):
        return False


def _find_elf_in_zip(zip_path: Path) -> Optional[Path]:
    """Распаковывает zip во временную директорию и находит snell-server.

    Возвращает Path к ELF-бинарнику или None если не найден.
    Вызывающий код должен сам очистить временную директорию (через
    shutil.rmtree в finally-блоке).
    """
    import tempfile
    tmpdir = Path(tempfile.mkdtemp(prefix="snell_extract_"))
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(tmpdir)
        # Ищем snell-server: либо по точному имени, либо по ELF-magic.
        # Сначала точное имя — обычно Snell zip содержит ровно один файл
        # с именем "snell-server" (без расширения).
        candidate = tmpdir / _SNELL_DEST_FILENAME
        if candidate.exists() and candidate.is_file() and _is_elf(candidate):
            return candidate
        # Если точного имени нет — ищем любой ELF в архиве (вдруг Surge
        # переименовал или добавил подпапку).
        for path in tmpdir.rglob("*"):
            if path.is_file() and _is_elf(path):
                # Берём первый ELF с разумным размером.
                if path.stat().st_size >= _MIN_SNELL_BINARY_SIZE:
                    return path
        return None
    except (zipfile.BadZipFile, OSError):
        return None
    # Не очищаем tmpdir тут — вызывающий код копирует ELF оттуда.
    # Очистка в finally вызывающего кода.


def _post_install_snell(src: Path, install_dests: list[Path]) -> bool:
    """post_install hook для SNELL_SPEC.

    Шаги:
      1. Проверяем что src — это zip (PK\x03\x04 magic)
      2. Распаковываем и находим ELF snell-server
      3. Копируем в каждый install_dests/snell-server с chmod 0o755
      4. Возвращаем True если хотя бы один dest успешно записан
    """
    if not src.exists() or not src.is_file():
        return False
    # Шаг 1: проверка zip-magic.
    if not _is_zip(src):
        # Если src уже ELF (админ распаковал вручную) — принимаем напрямую.
        if _is_elf(src) and src.stat().st_size >= _MIN_SNELL_BINARY_SIZE:
            return _copy_elf_to_dests(src, install_dests)
        return False

    # Шаг 2: распаковка и поиск ELF.
    import tempfile
    tmpdir = Path(tempfile.mkdtemp(prefix="snell_extract_"))
    try:
        try:
            with zipfile.ZipFile(src, "r") as zf:
                zf.extractall(tmpdir)
        except (zipfile.BadZipFile, OSError):
            return False

        # Ищем snell-server: сначала по точному имени, потом любой ELF.
        candidate = tmpdir / _SNELL_DEST_FILENAME
        if not (candidate.exists() and candidate.is_file() and _is_elf(candidate)):
            candidate = None
            for path in tmpdir.rglob("*"):
                if (path.is_file() and _is_elf(path)
                        and path.stat().st_size >= _MIN_SNELL_BINARY_SIZE):
                    candidate = path
                    break
        if candidate is None:
            return False

        # Шаг 3: копирование в install_dests.
        return _copy_elf_to_dests(candidate, install_dests)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _copy_elf_to_dests(src_elf: Path, install_dests: list[Path]) -> bool:
    """Копирует ELF-бинарник в каждый install_dests/snell-server, chmod 0o755.

    Возвращает True если хотя бы одна копия успешна. Использует
    _atomic_install_binary из mieru_packages — atomic os.replace() через
    временный файл, безопасно даже если dest уже запущен.
    """
    from chimera.modules.mieru_packages import _atomic_install_binary
    ok = False
    for dest_dir in install_dests:
        dest = dest_dir / _SNELL_DEST_FILENAME
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            _atomic_install_binary(src_elf, dest)
            dest.chmod(0o755)
            ok = True
        except (OSError, PermissionError):
            continue
    return ok


# ─── PackageSpec ─────────────────────────────────────────────────────────────
# filename_builder возвращает строку вида "snell-server-v4.1.1-linux-amd64.zip".
# mirror_urls_builder делегирует в snell_mirrors.get_snell_mirrors().
# post_install распаковывает zip и устанавливает ELF.
SNELL_SPEC = PackageSpec(
    name="snell-server",
    filename_builder=lambda version=SNELL_DEFAULT_VERSION, arch=None, **kw:
        _snell_filename(version, arch),
    mirror_urls_builder=_snell_mirror_urls,
    install_dests=_SNELL_INSTALL_DESTS,
    manual_incoming_dir=_MANUAL_DIR,
    min_size=_MIN_SNELL_BINARY_SIZE,
    post_install=_post_install_snell,
)
