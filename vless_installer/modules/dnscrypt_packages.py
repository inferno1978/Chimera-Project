"""
vless_installer/modules/dnscrypt_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec для dnscrypt-proxy tarball'а (DNSCrypt/dnscrypt-proxy).

Используется dnscrypt_setup.py::install_dnscrypt() для скачивания
архива и извлечения бинарника. До миграции dnscrypt_setup.py делал это
ad-hoc через curl + tar + rglob.

Особенности post_install:
  • Скачанный файл — tar.gz архив, содержащий dnscrypt-proxy бинарник +
    примеры конфигов.
  • post_install делает:
      1. tar -xzf во временную директорию
      2. rglob("dnscrypt-proxy") — поиск бинарника в распакованном дереве
      3. copy2 в install_dests[0]/dnscrypt-proxy (это DNSCRYPT_BIN из _core)
      4. chmod 0o755
      5. cleanup временной директории

  • Архитектура и версия подставляются через filename_kwargs:
    fetch_package(DNSCRYPT_SPEC, tag="2.1.5", arch="linux_x86_64")

install_dests = [/usr/local/bin] — это DNSCRYPT_BIN.parent из _core.
manual_incoming_dir = /root/ — не совпадает с install_dests, assert проходит.

Точки входа:
    from vless_installer.modules.dnscrypt_packages import DNSCRYPT_SPEC
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from vless_installer.modules.download_manager import PackageSpec
from vless_installer.modules.dnscrypt_mirrors import get_dnscrypt_mirrors


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================

# DNSCRYPT_BIN из _core = Path("/usr/local/bin/dnscrypt-proxy").
# install_dests = [/usr/local/bin] — директория, post_install ставит
# бинарник с именем "dnscrypt-proxy".
_DNSCRYPT_INSTALL_DESTS: list[Path] = [Path("/usr/local/bin")]

# manual_incoming_dir — /root/ (WinSCP-friendly).
_MANUAL_DIR = Path("/root")

# Имя файла в install_dests — "dnscrypt-proxy" (без архитектуры/версии).
_DNSCRYPT_DEST_FILENAME = "dnscrypt-proxy"

# Минимальный размер tarball'а.
# Реальный размер: ~3-5 MB (бинарник + примеры конфигов).
# 100 KB — нижний порог, отлавливает HTML-страницы 404.
_MIN_DNSCRYPT_TARBALL_SIZE = 100_000  # 100 KB


# ============================================================================
#  mirror_urls_builder — обёртка для PackageSpec API
# ============================================================================
def _dnscrypt_mirror_urls(
    filename: str,
    tag: str = "2.1.5",
    arch: str = "linux_x86_64",
    **kw,
) -> list[str]:
    """Собирает URL для dnscrypt-proxy через dnscrypt_mirrors.

    filename параметр принимается для совместимости с PackageSpec API,
    но игнорируется — имя файла конструируется из tag+arch внутри
    get_dnscrypt_mirrors().
    """
    return get_dnscrypt_mirrors(tag=tag, arch=arch)


# ============================================================================
#  post_install — распаковка + поиск бинарника + copy2
# ============================================================================
def _post_install_dnscrypt(src: Path, install_dests: list[Path]) -> bool:
    """Распаковывает tar.gz, находит dnscrypt-proxy бинарник, копирует в
    install_dests[0]/dnscrypt-proxy.

    Шаги (повторяют логику из старого dnscrypt_setup.py::install_dnscrypt):
      1. tar -xzf во временную директорию
      2. rglob("dnscrypt-proxy") — поиск бинарника в распакованном дереве
      3. copy2 в install_dests[0]/dnscrypt-proxy
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

        # 2. Поиск бинарника dnscrypt-proxy в распакованном дереве
        bin_found: Path | None = None
        for p in tmp.rglob("dnscrypt-proxy"):
            if p.is_file():
                bin_found = p
                break

        if not bin_found:
            return False

        # 3. copy2 в install_dests[0]/dnscrypt-proxy
        dest_dir = install_dests[0]
        dest = dest_dir / _DNSCRYPT_DEST_FILENAME
        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(bin_found), str(dest))
        dest.chmod(0o755)

        return True

    except Exception:
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================================
#  PackageSpec — dnscrypt-proxy tarball
# ============================================================================
DNSCRYPT_SPEC = PackageSpec(
    name="dnscrypt-proxy",
    filename_builder=lambda tag, arch: f"dnscrypt-proxy-{arch}-{tag}.tar.gz",
    mirror_urls_builder=_dnscrypt_mirror_urls,
    install_dests=_DNSCRYPT_INSTALL_DESTS,    # [/usr/local/bin]
    manual_incoming_dir=_MANUAL_DIR,          # /root/
    min_size=_MIN_DNSCRYPT_TARBALL_SIZE,      # 100 KB
    post_install=_post_install_dnscrypt,      # extract + rglob + copy2
)
