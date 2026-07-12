"""
vless_installer/modules/singbox_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec для sing-box бинарника (SagerNet/sing-box).

Используется singbox_install.py для скачивания .tar.gz архива и извлечения
бинарника sing-box.

По образцу fptn_packages.py:
  • Скачанный файл — .tar.gz архив с директорией
    sing-box-{version}-linux-{arch}/ содержащей бинарник sing-box.
  • post_install делает:
      1. tar -xzf {src} -C {tmpdir} — извлечение во временную директорию
      2. Поиск sing-box в распакованной директории
      3. copy2 в /usr/local/bin/sing-box (chmod 0o755)
      4. cleanup временной директории

  • filename подставляется через filename_kwargs:
    fetch_package(SINGBOX_SPEC, tag=..., tarball_filename=...)
    Это нужно потому что имя tar.gz файла динамическое (зависит от версии
    и архитектуры в имени — "sing-box-1.11.4-linux-amd64.tar.gz").

install_dests = [/usr/local/bin] — куда ставится распакованный бинарник.
manual_incoming_dir = /root/ — не совпадает с install_dests.

Точки входа:
    from vless_installer.modules.singbox_packages import SINGBOX_SPEC
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from vless_installer.modules.download_manager import PackageSpec
from vless_installer.modules.singbox_mirrors import get_singbox_mirrors


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================

# install_dests = [/usr/local/bin] — директория, post_install ставит бинарник
# с именем "sing-box".
_SINGBOX_INSTALL_DESTS: list[Path] = [Path("/usr/local/bin")]

# manual_incoming_dir — /root/ (WinSCP-friendly).
_MANUAL_DIR = Path("/root")

# Имя файла в install_dests.
_SINGBOX_BINARY_FILENAME = "sing-box"

# Минимальный размер tar.gz архива.
# Реальный размер: ~10-15 MB.
# 100 KB — нижний порог, отлавливает HTML-страницы 404.
_MIN_SINGBOX_TARBALL_SIZE = 100_000  # 100 KB


# ============================================================================
#  mirror_urls_builder — обёртка для PackageSpec API
# ============================================================================
# ВАЖНО: download_manager.py L176 вызывает mirror_urls_builder как
# spec.mirror_urls_builder(filename=filename, **filename_kwargs).
# Если caller передаёт `filename` через filename_kwargs — будет TypeError
# (got multiple values for keyword argument 'filename'). Поэтому
# используем `tarball_filename` вместо `filename` в filename_kwargs.
def _singbox_mirror_urls(
    filename: str,
    tag: str = "",
    tarball_filename: str = "",
    **kw,
) -> list[str]:
    """Собирает URL для sing-box tar.gz через singbox_mirrors.

    filename — передаётся download_manager'ом (имя файла из filename_builder).
    tarball_filename — передаётся caller'ом (динамическое имя tar.gz из GitHub API).
    Берём tarball_filename если передан, иначе filename.
    tag — release tag (动态, из GitHub API).
    """
    # Приоритет: tarball_filename (из caller kwargs) > filename (из download_manager)
    actual_filename = tarball_filename or filename
    if not actual_filename or not tag:
        return []
    return get_singbox_mirrors(tag=tag, filename=actual_filename)


# ============================================================================
#  post_install — tar -xzf + copy2 бинарника
# ============================================================================
def _post_install_singbox(src: Path, install_dests: list[Path]) -> bool:
    """Распаковывает tar.gz архив, извлекает sing-box, копирует в install_dests[0]/.

    Шаги:
      1. tar -xzf {src} -C {tmpdir} — извлечение
      2. Поиск sing-box бинарника в распакованной директории
         (вложенная структура: sing-box-{version}-linux-{arch}/sing-box)
      3. copy2 в install_dests[0]/sing-box
      4. chmod 0o755
      5. cleanup временной директории

    Параметры:
      src:           Скачанный/ручной tar.gz файл.
      install_dests: Куда копировать бинарник (обычно [/usr/local/bin]).

    Возвращает:
      True если бинарник найден и скопирован. False если tar упал или
      бинарник не найден — даёт fetch_package шанс попробовать следующее зеркало.
    """
    if not install_dests:
        return False

    tmp = Path(tempfile.mkdtemp(prefix="singbox-extract-"))
    try:
        # 1. tar -xzf
        r = subprocess.run(
            ["tar", "-xzf", str(src), "-C", str(tmp)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return False

        # 2. Поиск бинарника sing-box (может быть в поддиректории)
        # Структура: sing-box-{version}-linux-{arch}/sing-box
        binary_path: Path | None = None
        for candidate in tmp.rglob("sing-box"):
            if candidate.is_file() and os.access(str(candidate), os.X_OK):
                binary_path = candidate
                break
        # Если не нашли исполняемый — берём любой файл с этим именем
        if binary_path is None:
            for candidate in tmp.rglob("sing-box"):
                if candidate.is_file():
                    binary_path = candidate
                    break

        if binary_path is None:
            return False

        # 3. copy2 в install_dests[0]/
        dest_dir = install_dests[0]
        dest_dir.mkdir(parents=True, exist_ok=True)

        dest = dest_dir / _SINGBOX_BINARY_FILENAME
        shutil.copy2(str(binary_path), str(dest))
        dest.chmod(0o755)

        return True

    except Exception:
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================================
#  PackageSpec — sing-box tar.gz package
# ============================================================================
SINGBOX_SPEC = PackageSpec(
    name="sing-box binary",
    # ВАЖНО: filename_builder получает **filename_kwargs (без `filename=`).
    # Caller передаёт tarball_filename=... (НЕ filename=, чтобы не конфликтовать
    # с download_manager'ом который сам передаёт filename= в mirror_urls_builder).
    filename_builder=lambda tarball_filename, **kw: tarball_filename,  # динамическое имя из API
    mirror_urls_builder=_singbox_mirror_urls,
    install_dests=_SINGBOX_INSTALL_DESTS,         # [/usr/local/bin]
    manual_incoming_dir=_MANUAL_DIR,              # /root/
    min_size=_MIN_SINGBOX_TARBALL_SIZE,           # 100 KB
    post_install=_post_install_singbox,           # tar -xzf + copy2
)
