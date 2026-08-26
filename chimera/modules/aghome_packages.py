"""
chimera/modules/aghome_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec для AdGuard Home tarball'а (AdguardTeam/AdGuardHome).

Используется aghome_setup.py::install_aghome() для скачивания
архива и извлечения бинарника — по тому же паттерну, что
dnscrypt_packages.py / DNSCRYPT_SPEC.

Особенности post_install:
  • Скачанный файл — tar.gz архив со структурой "AdGuardHome/AdGuardHome"
    (бинарник лежит ВНУТРИ директории AdGuardHome).
  • post_install делает:
      1. tar -xzf во временную директорию
      2. rglob("AdGuardHome") — поиск бинарника в распакованном дереве
      3. copy2 в install_dests[0]/AdGuardHome (= /usr/local/bin/AdGuardHome,
         это AGHOME_BIN из _core)
      4. chmod 0o755
      5. cleanup временной директории

  • Архитектура и версия подставляются через filename_kwargs:
    fetch_package(AGHOME_SPEC, tag="v0.107.62", arch="amd64")

install_dests = [/usr/local/bin] — это AGHOME_BIN.parent из _core.
manual_incoming_dir = /root/ — не совпадает с install_dests, assert проходит.

Точки входа:
    from chimera.modules.aghome_packages import AGHOME_SPEC
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from chimera.modules.download_manager import PackageSpec
from chimera.modules.aghome_mirrors import get_aghome_mirrors


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================

# AGHOME_BIN из _core = Path("/usr/local/bin/AdGuardHome").
# install_dests = [/usr/local/bin] — директория, post_install ставит
# бинарник с именем "AdGuardHome".
_AGHOME_INSTALL_DESTS: list[Path] = [Path("/usr/local/bin")]

# manual_incoming_dir — /root/ (WinSCP-friendly).
_MANUAL_DIR = Path("/root")

# Имя файла в install_dests — "AdGuardHome" (без архитектуры/версии).
_AGHOME_DEST_FILENAME = "AdGuardHome"

# Минимальный размер tarball'а.
# Реальный размер: ~10-15 MB (бинарник + LICENSE).
# 2 MB — нижний порог, отлавливает HTML-страницы 404.
_MIN_AGHOME_TARBALL_SIZE = 2_000_000  # 2 MB


# ============================================================================
#  mirror_urls_builder — обёртка для PackageSpec API
# ============================================================================
def _aghome_mirror_urls(
    filename: str,
    tag: str = "v0.107.62",
    arch: str = "amd64",
    **kw,
) -> list[str]:
    """Собирает URL для AdGuardHome через aghome_mirrors.

    filename параметр принимается для совместимости с PackageSpec API,
    но игнорируется — имя файла конструируется из arch внутри
    get_aghome_mirrors().
    """
    return get_aghome_mirrors(tag=tag, arch=arch)


# ============================================================================
#  post_install — распаковка + поиск бинарника + copy2
# ============================================================================
def _post_install_aghome(src: Path, install_dests: list[Path]) -> bool:
    """Распаковывает tar.gz, находит AdGuardHome бинарник, копирует в
    install_dests[0]/AdGuardHome.

    Шаги (повторяют логику dnscrypt_packages._post_install_dnscrypt):
      1. tar -xzf во временную директорию
      2. rglob("AdGuardHome") — поиск бинарника в распакованном дереве
      3. copy2 в install_dests[0]/AdGuardHome
      4. chmod 0o755
      5. cleanup временной директории

    Параметры:
      src:           Скачанный/ручной tar.gz архив.
      install_dests: Куда копировать бинарник (обычно [/usr/local/bin]).

    Возвращает:
      True если бинарник найден и скопирован. False если tar упал или
      бинарник не найден — даёт fetch_package шанс попробовать следующее
      зеркало.
    """
    if not install_dests:
        return False

    tmp = Path(tempfile.mkdtemp())
    try:
        # 1. Распаковка
        r = subprocess.run(
            ["tar", "-xzf", str(src), "-C", str(tmp)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return False

        # 2. Поиск бинарника AdGuardHome в распакованном дереве.
        #    Тarball имеет структуру AdGuardHome/AdGuardHome — rglob
        #    надёжно находит его на любой глубине.
        bin_found: Path | None = None
        for p in tmp.rglob("AdGuardHome"):
            if p.is_file():
                bin_found = p
                break

        if not bin_found:
            return False

        # 3. copy2 в install_dests[0]/AdGuardHome
        dest_dir = install_dests[0]
        dest = dest_dir / _AGHOME_DEST_FILENAME
        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(bin_found), str(dest))
        dest.chmod(0o755)

        return True

    except Exception:
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================================
#  PackageSpec — AdGuardHome tarball
# ============================================================================
AGHOME_SPEC = PackageSpec(
    name="AdGuardHome",
    filename_builder=lambda tag, arch, **kw: f"AdGuardHome_linux_{arch}.tar.gz",
    mirror_urls_builder=_aghome_mirror_urls,
    install_dests=_AGHOME_INSTALL_DESTS,     # [/usr/local/bin]
    manual_incoming_dir=_MANUAL_DIR,          # /root/
    min_size=_MIN_AGHOME_TARBALL_SIZE,        # 2 MB
    post_install=_post_install_aghome,        # extract + rglob + copy2
)
