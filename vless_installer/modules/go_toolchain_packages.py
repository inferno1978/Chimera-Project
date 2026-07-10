"""
vless_installer/modules/go_toolchain_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec для официального Go toolchain (tarball с go.dev/dl/).

Используется тремя модулями:
  • wdtt.py — для сборки wdtt-server из исходников
  • webdav_tunnel.py — для сборки webdav-tunnel из исходников
  • olcrtc.py — для сборки olcrtc из исходников (Wave 6)

До миграции каждый из этих модулей содержал свою копию _http_download +
_install_go_toolchain с ОДНИМ прямым URL go.dev/dl/, без зеркал, без fallback,
без проверки ручного размещения. Теперь все три используют единый
GO_TOOLCHAIN_SPEC через fetch_package().

АРХИТЕКТурное решение — почему install_dests = [/usr/local]:
  Go toolchain tarball распаковывается в /usr/local/go/, затем go/gofmt
  симлинки создаются в /usr/local/bin/. install_dests=[/usr/local] — это
  НЕ место куда fetch_package копирует tarball (post_install игнорирует
  install_dests и сам решает куда ставить), а скорее декларация "целевая
  директория установки — /usr/local". Это нужно только для того, чтобы
  PackageSpec.__post_init__ assert (manual_dir != install_dests) работал:
  manual_dir = /root/, install_dests = [/usr/local] — коллизии нет.

  Фактическая установка идёт в post_install:
    1. rm -rf /usr/local/go (если есть старая версия)
    2. tar -C /usr/local -xzf {tarball} (создаёт /usr/local/go/)
    3. symlink /usr/local/go/bin/go → /usr/local/bin/go
    4. symlink /usr/local/go/bin/gofmt → /usr/local/bin/gofmt

Особенность вызова:
  fetch_package(GO_TOOLCHAIN_SPEC, version=go_version, arch=go_arch)
  где go_version — строка вида 'go1.23.4' (динамически разрешается через
  go.dev/VERSION?m=text в вызывающем коде — это metadata, non-migration),
  а go_arch — 'amd64' или 'arm64' (через _go_arch()).

Точки входа:
    from vless_installer.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC
"""
from __future__ import annotations

import shutil
from pathlib import Path

from vless_installer.modules.download_manager import PackageSpec
from vless_installer.modules.go_toolchain_mirrors import (
    get_go_toolchain_mirrors,
)


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================

# Go toolchain устанавливается в /usr/local/go/, бинарники симлинкятся в
# /usr/local/bin/. install_dests=[/usr/local] — декларация целевой директории
# (post_install игнорирует это значение и сам решает куда ставить).
_GO_INSTALL_DESTS: list[Path] = [Path("/usr/local")]

# manual_incoming_dir — /root/ (WinSCP-friendly). Пользователь может положить
# go1.23.4.linux-amd64.tar.gz в /root/ и fetch_package использует его без сети.
# /root/ != /usr/local — assert в __post_init__ проходит.
_MANUAL_DIR = Path("/root")

# Минимальный размер Go toolchain tarball'а.
# Реальный размер: ~60-70 MB для amd64, ~55-65 MB для arm64.
# 10 MB — нижний порог, отлавливает HTML-страницы 404 (обычно <100 KB) и
# усечённые загрузки. Раньше проверки не было вообще — только
# dest.stat().st_size > 0 (один байт проходил).
_MIN_GO_TARBALL_SIZE = 10_000_000  # 10 MB


# ============================================================================
#  mirror_urls_builder — обёртка для PackageSpec API
# ============================================================================
def _go_toolchain_mirror_urls(
    filename: str,
    version: str = "go1.22.0",
    arch: str = "amd64",
    **kw,
) -> list[str]:
    """Собирает URL для Go toolchain через go_toolchain_mirrors.

    filename параметр принимается для совместимости с PackageSpec API,
    но игнорируется — имя файла конструируется из version+arch внутри
    get_go_toolchain_mirrors().
    """
    return get_go_toolchain_mirrors(version, arch)


# ============================================================================
#  post_install — распаковка Go toolchain + создание симлинков
# ============================================================================
def _post_install_go_toolchain(src: Path, install_dests: list[Path]) -> bool:
    """Распаковывает Go toolchain tarball в /usr/local/go и создаёт симлинки.

    Шаги (идентичны старой логике из wdtt.py._install_go_toolchain /
    webdav_tunnel.py._install_go_toolchain):
      1. rm -rf /usr/local/go (удаляем старую версию если есть)
      2. tar -C /usr/local -xzf {src} (создаёт /usr/local/go/)
      3. symlink /usr/local/go/bin/go → /usr/local/bin/go
      4. symlink /usr/local/go/bin/gofmt → /usr/local/bin/gofmt

    Параметры:
      src:           Скачанный/ручной tarball (например go1.23.4.linux-amd64.tar.gz).
      install_dests: Игнорируется — установка идёт в /usr/local (захардкожено
                     upstream Go toolchain layout).

    Возвращает:
      True если /usr/local/go/bin/go существует после распаковки.
      False если tar упал или go-бинарник не найден.
    """
    import subprocess

    go_dir = Path("/usr/local/go")

    # 1. Удаляем старую версию
    if go_dir.exists():
        try:
            shutil.rmtree(go_dir)
        except Exception:
            # Если не удалось удалить — tar ниже может упасть, но пробуем
            subprocess.run(["rm", "-rf", str(go_dir)], check=False)

    # 2. Распаковываем tarball в /usr/local
    r = subprocess.run(
        ["tar", "-C", "/usr/local", "-xzf", str(src)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return False

    # 3. Создаём симлинки go/gofmt в /usr/local/bin/
    for exe in ("go", "gofmt"):
        bin_src = go_dir / "bin" / exe
        bin_dst = Path("/usr/local/bin") / exe
        if bin_src.exists():
            try:
                if bin_dst.exists() or bin_dst.is_symlink():
                    bin_dst.unlink()
                bin_dst.symlink_to(bin_src)
            except Exception:
                pass

    # 4. Проверяем что go действительно появился
    return (go_dir / "bin" / "go").exists()


# ============================================================================
#  PackageSpec — Go toolchain
# ============================================================================
GO_TOOLCHAIN_SPEC = PackageSpec(
    name="Go toolchain",
    filename_builder=lambda version, arch: f"{version}.linux-{arch}.tar.gz",
    mirror_urls_builder=_go_toolchain_mirror_urls,
    install_dests=_GO_INSTALL_DESTS,           # [/usr/local] — для assert'а
    manual_incoming_dir=_MANUAL_DIR,           # /root/
    min_size=_MIN_GO_TARBALL_SIZE,             # 10 MB
    post_install=_post_install_go_toolchain,   # extract + symlinks
)
