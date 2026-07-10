"""
vless_installer/modules/mieru_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec-инстансы для бинарников mita/mieru — декларативное описание
пакетов для download_manager.fetch_package().

Особенность mieru (в отличие от geo): скачиваемые артефакты — версионированные
архивы (.deb/.rpm/.tar.gz с версией и архитектурой в имени), а установочный
путь — ИЗВЛЕЧЁННЫЙ бинарник (/usr/local/bin/mita), а не сам скачанный файл.
Поэтому post_install обязателен и делает разную работу:
  • .deb → dpkg -i + извлечение бинарника из /usr/bin/mita → _MITA_BIN
  • .rpm → rpm -Uvh + извлечение бинарника → _MITA_BIN
  • tar.gz → tar -xzf + поиск ELF-бинарника + atomic install → _MITA_BIN/_MIERU_BIN

install_dests для .deb/.rpm/tar.gz спеков — ВРЕМЕННАЯ директория
(/tmp/mieru_packages), т.к. финальная установка идёт через post_install,
а не прямое копирование. manual_incoming_dir = /root/ — не совпадает
с install_dests, PackageSpec.__post_init__ инвариант соблюдён.

Точки входа:
    from vless_installer.modules.mieru_packages import (
        MITA_DEB_SPEC, MITA_RPM_SPEC, MITA_TARGZ_SPEC, MIERU_TARGZ_SPEC,
    )
"""
from __future__ import annotations

import shutil
import tarfile
import tempfile
from pathlib import Path

from vless_installer.modules.download_manager import PackageSpec
from vless_installer.modules.github_mirrors import build_mirror_urls


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================
_MITA_BIN  = Path("/usr/local/bin/mita")
_MIERU_BIN = Path("/usr/local/bin/mieru")

# Временная директория для install_dests — post_install делает реальную
# установку (dpkg/rpm/tar), а не copy2 в install_dests.
# /root/ НЕ должен совпадать с этим путём — PackageSpec инвариант.
_INSTALL_TMP = Path("/tmp/mieru_packages")

# manual_incoming_dir — ТОЛЬКО /root/ (WinSCP-friendly).
# PackageSpec.__post_init__ assert гарантирует /root/ != install_dests.
_MANUAL_DIR = Path("/root")


# ============================================================================
#  ВСПОМОГАТЕЛЬНЫЕ: _run, _atomic_install_binary (lazy import из mieru.py)
# ============================================================================
def _get_mieru_module():
    """Ленивый импорт mieru.py — избегает циклического импорта."""
    import importlib
    return importlib.import_module("vless_installer.modules.mieru")


def _atomic_install_binary(src: Path, dest: Path) -> None:
    """Делегирует в mieru._atomic_install_binary (та же функция что раньше)."""
    mieru = _get_mieru_module()
    mieru._atomic_install_binary(src, dest)


def _run(cmd: list, capture: bool = False, check: bool = False):
    """Делегирует в mieru._run."""
    mieru = _get_mieru_module()
    return mieru._run(cmd, capture=capture, check=check)


# ============================================================================
#  post_install функции
# ============================================================================
def _post_install_deb(src: Path, install_dests: list[Path]) -> bool:
    """Установка .deb пакета: dpkg -i + извлечение бинарника.

    src = скачанный .deb файл (во /tmp/_download_mgr_mita_*.deb).
    install_dests — игнорируется (dpkg сам решает куда ставить).
    """
    import io
    mieru = _get_mieru_module()
    GREEN, NC, YELLOW = mieru.GREEN, mieru.NC, mieru.YELLOW

    try:
        r = _run(["dpkg", "-i", str(src)], capture=True)
        if r.returncode == 0:
            # dpkg кладёт бинарник в /usr/bin/mita
            sys_bin = Path("/usr/bin/mita")
            if sys_bin.exists():
                _atomic_install_binary(sys_bin, _MITA_BIN)
            print(f"  {GREEN}✓{NC}  mita установлен через dpkg.")
            return True
        else:
            print(f"  {YELLOW}⚠{NC}  dpkg завершился с ошибкой, пробую tar.gz...")
            return False
    except Exception as e:
        print(f"  {YELLOW}⚠{NC}  Ошибка .deb: {e}, пробую tar.gz...")
        return False


def _post_install_rpm(src: Path, install_dests: list[Path]) -> bool:
    """Установка .rpm пакета: rpm -Uvh + извлечение бинарника."""
    mieru = _get_mieru_module()
    GREEN, NC, YELLOW = mieru.GREEN, mieru.NC, mieru.YELLOW

    try:
        r = _run(["rpm", "-Uvh", "--force", str(src)], capture=True)
        if r.returncode == 0:
            sys_bin = Path("/usr/bin/mita")
            if sys_bin.exists():
                _atomic_install_binary(sys_bin, _MITA_BIN)
            print(f"  {GREEN}✓{NC}  mita установлен через rpm.")
            return True
        else:
            print(f"  {YELLOW}⚠{NC}  rpm завершился с ошибкой, пробую tar.gz...")
            return False
    except Exception as e:
        print(f"  {YELLOW}⚠{NC}  Ошибка .rpm: {e}, пробую tar.gz...")
        return False


def _post_install_targz(src: Path, install_dests: list[Path]) -> bool:
    """Установка tar.gz: распаковка + поиск ELF-бинарника + atomic install.

    src = скачанный tar.gz архив.
    install_dests — игнорируется (бинарник ставится в _MITA_BIN).
    """
    mieru = _get_mieru_module()
    GREEN, NC, RED = mieru.GREEN, mieru.NC, mieru.RED

    tmp = Path(tempfile.mkdtemp())
    try:
        _run(["tar", "-xzf", str(src), "-C", str(tmp)], check=True)

        # Ищем бинарник mita в распакованном
        candidates = list(tmp.glob("**/mita"))
        if not candidates:
            candidates = list(tmp.glob("**/mieru"))
        if not candidates:
            print(f"  {RED}✗{NC}  mita не найден в архиве.")
            return False

        bin_file = candidates[0]
        with bin_file.open("rb") as f:
            if f.read(4) != b'\x7fELF':
                print(f"  {RED}✗{NC}  mita — не ELF бинарник.")
                return False

        _atomic_install_binary(bin_file, _MITA_BIN)
        print(f"  {GREEN}✓{NC}  mita установлен: {_MITA_BIN}")
        return True
    except Exception as e:
        print(f"  {RED}✗{NC}  Ошибка распаковки mita: {e}")
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _post_install_mieru_targz(src: Path, install_dests: list[Path]) -> bool:
    """Установка клиентского mieru tar.gz: распаковка + atomic install в _MIERU_BIN."""
    mieru = _get_mieru_module()
    GREEN, NC, RED = mieru.GREEN, mieru.NC, mieru.RED

    tmp = Path(tempfile.mkdtemp())
    try:
        _run(["tar", "-xzf", str(src), "-C", str(tmp)], check=True)

        candidates = list(tmp.glob("**/mieru"))
        if not candidates:
            candidates = list(tmp.glob("**/mita"))
        if not candidates:
            print(f"  {RED}✗{NC}  mieru не найден в архиве.")
            return False

        bin_file = candidates[0]
        with bin_file.open("rb") as f:
            if f.read(4) != b'\x7fELF':
                print(f"  {RED}✗{NC}  mieru — не ELF бинарник.")
                return False

        _atomic_install_binary(bin_file, _MIERU_BIN)
        print(f"  {GREEN}✓{NC}  mieru установлен: {_MIERU_BIN}")
        return True
    except Exception as e:
        print(f"  {RED}✗{NC}  Ошибка распаковки mieru: {e}")
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================================
#  Зеркала — обёртка над build_mirror_urls
# ============================================================================
def _mieru_mirror_urls(filename: str, version: str = "", **kw) -> list[str]:
    """Собирает URL для mieru через единый build_mirror_urls.

    owner=enfein, repo=mieru, tag=v{version}.
    Использует полный набор зеркал (14): jsDelivr(4) + raw GitHub + release
    GitHub + gh-proxy(7) + Statically — больше чем старые 9 зеркал.
    """
    tag = f"v{version}" if version else "latest"
    return build_mirror_urls(
        owner="enfein",
        repo="mieru",
        filename=filename,
        tag=tag,
    )


# ============================================================================
#  PackageSpec — mita .deb
# ============================================================================
MITA_DEB_SPEC = PackageSpec(
    name="mita .deb",
    filename_builder=lambda version, arch: f"mita_{version}_{arch}.deb",
    mirror_urls_builder=_mieru_mirror_urls,
    install_dests=[_INSTALL_TMP],
    manual_incoming_dir=_MANUAL_DIR,
    min_size=1000,  # .deb пакеты обычно > 1 КБ
    post_install=_post_install_deb,
)


# ============================================================================
#  PackageSpec — mita .rpm
# ============================================================================
MITA_RPM_SPEC = PackageSpec(
    name="mita .rpm",
    filename_builder=lambda version, rpm_arch: f"mita-{version}-1.{rpm_arch}.rpm",
    mirror_urls_builder=_mieru_mirror_urls,
    install_dests=[_INSTALL_TMP],
    manual_incoming_dir=_MANUAL_DIR,
    min_size=1000,
    post_install=_post_install_rpm,
)


# ============================================================================
#  PackageSpec — mita tar.gz
# ============================================================================
MITA_TARGZ_SPEC = PackageSpec(
    name="mita tar.gz",
    filename_builder=lambda version, arch: f"mita_{version}_linux_{arch}.tar.gz",
    mirror_urls_builder=_mieru_mirror_urls,
    install_dests=[_INSTALL_TMP],
    manual_incoming_dir=_MANUAL_DIR,
    min_size=1000,
    post_install=_post_install_targz,
)


# ============================================================================
#  PackageSpec — mieru tar.gz (клиентский бинарник)
# ============================================================================
MIERU_TARGZ_SPEC = PackageSpec(
    name="mieru tar.gz",
    filename_builder=lambda version, arch: f"mieru_{version}_linux_{arch}.tar.gz",
    mirror_urls_builder=_mieru_mirror_urls,
    install_dests=[_INSTALL_TMP],
    manual_incoming_dir=_MANUAL_DIR,
    min_size=1000,
    post_install=_post_install_mieru_targz,
)
