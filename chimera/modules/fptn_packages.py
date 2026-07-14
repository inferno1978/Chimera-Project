"""
chimera/modules/fptn_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec для fptn-server .deb пакета (fptn-project/fptn).

Используется fptn.py::_download_binaries() для скачивания .deb архива и
извлечения бинарников fptn-server + fptn-passwd. До миграции fptn.py делал
это ad-hoc через urllib.request.urlretrieve + dpkg-deb -x.

Особенности:
  • Скачанный файл — .deb пакет (ar архив), содержащий data.tar.* с
    бинарниками в usr/bin/.
  • post_install делает:
      1. dpkg-deb -x {src} {tmpdir} — извлечение во временную директорию
         (БЕЗ dpkg -i — мы не хотим модифицировать system package DB,
          только достать 2 бинарника)
      2. Поиск usr/bin/fptn-server и usr/bin/fptn-passwd в распакованном
      3. copy2 в /usr/bin/fptn-server и /usr/bin/fptn-passwd (chmod 0o755)
      4. cleanup временной директории

  • filename подставляется через filename_kwargs:
    fetch_package(FPTN_SPEC, tag=..., filename=...)
    Это нужно потому что имя .deb файла динамическое (зависит от Ubuntu
    версии в имени — "fptn-server-ubuntu22.04-amd64.deb" или подобное).

install_dests = [/usr/bin] — куда ставятся извлечённые бинарники.
manual_incoming_dir = /root/ — не совпадает с install_dests.

Точки входа:
    from chimera.modules.fptn_packages import FPTN_SPEC
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from chimera.modules.download_manager import PackageSpec
from chimera.modules.fptn_mirrors import get_fptn_mirrors


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================

# _BIN_SERVER = Path("/usr/bin/fptn-server"), _BIN_PASSWD = Path("/usr/bin/fptn-passwd").
# install_dests = [/usr/bin] — директория, post_install ставит бинарники
# с именами "fptn-server" и "fptn-passwd".
_FPTN_INSTALL_DESTS: list[Path] = [Path("/usr/bin")]

# manual_incoming_dir — /root/ (WinSCP-friendly).
_MANUAL_DIR = Path("/root")

# Имена файлов в install_dests.
_FPTN_SERVER_FILENAME = "fptn-server"
_FPTN_PASSWD_FILENAME = "fptn-passwd"

# Минимальный размер .deb пакета.
# Реальный размер: ~5-15 MB.
# 100 KB — нижний порог, отлавливает HTML-страницы 404.
_MIN_FPTN_DEB_SIZE = 100_000  # 100 KB


# ============================================================================
#  mirror_urls_builder — обёртка для PackageSpec API
# ============================================================================
# ВАЖНО: download_manager.py L176 вызывает mirror_urls_builder как
# spec.mirror_urls_builder(filename=filename, **filename_kwargs).
# Если caller передаёт `filename` через filename_kwargs — будет TypeError
# (got multiple values for keyword argument 'filename'). Поэтому
# используем `deb_filename` вместо `filename` в filename_kwargs.
def _fptn_mirror_urls(
    filename: str,
    tag: str = "0.7.6",
    deb_filename: str = "",
    **kw,
) -> list[str]:
    """Собирает URL для fptn .deb через fptn_mirrors.

    filename — передаётся download_manager'ом (имя файла из filename_builder).
    deb_filename — передаётся caller'ом (динамическое имя .deb из GitHub API).
    Берём deb_filename если передан, иначе filename.
    tag — release tag.
    """
    # Приоритет: deb_filename (из caller kwargs) > filename (из download_manager)
    actual_filename = deb_filename or filename
    if not actual_filename:
        return []
    return get_fptn_mirrors(tag=tag, filename=actual_filename)


# ============================================================================
#  post_install — dpkg-deb -x + copy2 двух бинарников
# ============================================================================
def _post_install_fptn(src: Path, install_dests: list[Path]) -> bool:
    """Распаковывает .deb пакет, извлекает fptn-server + fptn-passwd,
    копирует в install_dests[0]/.

    Шаги (повторяют логику из старого fptn.py::_download_binaries):
      1. dpkg-deb -x {src} {tmpdir} — извлечение (БЕЗ dpkg -i — мы не хотим
         модифицировать system package DB)
      2. Поиск usr/bin/fptn-server и usr/bin/fptn-passwd в распакованном
      3. copy2 в install_dests[0]/fptn-server и install_dests[0]/fptn-passwd
      4. chmod 0o755
      5. cleanup временной директории

    Параметры:
      src:           Скачанный/ручной .deb файл.
      install_dests: Куда копировать бинарники (обычно [/usr/bin]).

    Возвращает:
      True если ОБА бинарника найдены и скопированы. False если dpkg-deb
      упал или бинарники не найдены — даёт fetch_package шанс попробовать
      следующее зеркало.
    """
    if not install_dests:
        return False

    tmp = Path(tempfile.mkdtemp(prefix="fptn-extract-"))
    try:
        # 1. dpkg-deb -x
        r = subprocess.run(
            ["dpkg-deb", "-x", str(src), str(tmp)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return False

        # 2. Поиск бинарников
        server_bin = tmp / "usr" / "bin" / _FPTN_SERVER_FILENAME
        passwd_bin = tmp / "usr" / "bin" / _FPTN_PASSWD_FILENAME
        if not server_bin.exists() or not passwd_bin.exists():
            return False

        # 3. copy2 в install_dests[0]/
        dest_dir = install_dests[0]
        dest_dir.mkdir(parents=True, exist_ok=True)

        server_dest = dest_dir / _FPTN_SERVER_FILENAME
        passwd_dest = dest_dir / _FPTN_PASSWD_FILENAME

        shutil.copy2(str(server_bin), str(server_dest))
        server_dest.chmod(0o755)
        shutil.copy2(str(passwd_bin), str(passwd_dest))
        passwd_dest.chmod(0o755)

        return True

    except Exception:
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================================
#  PackageSpec — fptn .deb package
# ============================================================================
FPTN_SPEC = PackageSpec(
    name="fptn-server .deb",
    # ВАЖНО: filename_builder получает **filename_kwargs (без `filename=`).
    # Caller передаёт deb_filename=... (НЕ filename=, чтобы не конфликтовать
    # с download_manager'ом который сам передаёт filename= в mirror_urls_builder).
    filename_builder=lambda deb_filename, **kw: deb_filename,  # динамическое имя из API
    mirror_urls_builder=_fptn_mirror_urls,
    install_dests=_FPTN_INSTALL_DESTS,           # [/usr/bin]
    manual_incoming_dir=_MANUAL_DIR,             # /root/
    min_size=_MIN_FPTN_DEB_SIZE,                 # 100 KB
    post_install=_post_install_fptn,             # dpkg-deb -x + copy2
)
