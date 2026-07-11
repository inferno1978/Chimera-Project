"""
vless_installer/modules/awg_transport_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpecs для AWG transport артефактов:
  • AWG_TOOLS_SPEC — amneziawg-tools prebuilt zip (awg + awg-quick binaries)
  • AWG_GO_SOURCE_SPEC — amneziawg-go source tarball (build via make)
  • AWG_KMOD_SOURCE_SPEC — amneziawg-linux-kernel-module source tarball
    (build via dkms-install или make install)

Все три используют fetch_package() из download_manager.py.

Variant A (HTTP tarball вместо git clone) применим ко всем исходникам
согласно анализу Wave 6:
  • amneziawg-go Makefile tolerates missing .git/ (version generation
    wrapped in `|| true`).
  • amneziawg-linux-kernel-module Makefile (в src/) не использует git
    вообще (версия hardcoded как 1.0.0).
  • Ни в одном репо нет .gitmodules.

Особенности post_install:
  • AWG_TOOLS_SPEC: unzip → find awg/awg-quick → copy в /usr/local/bin/
    (chmod 0o755).
  • AWG_GO_SOURCE_SPEC: extract tarball → make → copy amneziawg-go в
    /usr/local/bin/ (chmod 0o755) → cleanup.
  • AWG_KMOD_SOURCE_SPEC: extract tarball → cd src → make dkms-install +
    dkms add/build/install (fallback: make && make install) → modprobe +
    verify → cleanup.

Точки входа:
    from vless_installer.modules.awg_transport_packages import (
        AWG_TOOLS_SPEC, AWG_GO_SOURCE_SPEC, AWG_KMOD_SOURCE_SPEC,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from vless_installer.modules.download_manager import PackageSpec
from vless_installer.modules.awg_transport_mirrors import (
    get_amneziawg_tools_mirrors,
    get_amneziawg_go_source_mirrors,
    get_amneziawg_kmod_source_mirrors,
)


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================

# /usr/local/bin — куда ставятся бинарники awg, awg-quick, amneziawg-go.
_AWG_BIN_INSTALL_DESTS: list[Path] = [Path("/usr/local/bin")]

# Временная директория для source-build post_install (игнорируется).
_AWG_BUILD_TMP: list[Path] = [Path("/tmp/awg_build")]

# manual_incoming_dir — /root/ (WinSCP-friendly).
_MANUAL_DIR = Path("/root")

# Минимальные размеры.
_MIN_AWG_TOOLS_ZIP_SIZE = 100_000      # 100 KB (zip с двумя бинарниками)
_MIN_AWG_GO_SOURCE_SIZE = 1000         # 1 KB (source tarball)
_MIN_AWG_KMOD_SOURCE_SIZE = 1000       # 1 KB (source tarball)


# ============================================================================
#  mirror_urls_builder — обёртки для PackageSpec API
# ============================================================================
def _awg_tools_mirror_urls(filename: str, tag: str = "latest", arch: str = "amd64", **kw) -> list[str]:
    return get_amneziawg_tools_mirrors(tag=tag, arch=arch)


def _awg_go_source_mirror_urls(filename: str, **kw) -> list[str]:
    return get_amneziawg_go_source_mirrors()


def _awg_kmod_source_mirror_urls(filename: str, **kw) -> list[str]:
    return get_amneziawg_kmod_source_mirrors()


# ============================================================================
#  post_install — AWG_TOOLS_SPEC: unzip + copy awg/awg-quick
# ============================================================================
def _post_install_awg_tools(src: Path, install_dests: list[Path]) -> bool:
    """Распаковывает amneziawg-tools zip, копирует awg + awg-quick в
    /usr/local/bin/ (chmod 0o755).

    Повторяет логику из старого awg_transport.py (L194-220).
    """
    if not install_dests:
        return False

    tmp = Path(tempfile.mkdtemp(prefix="awg_tools_"))
    try:
        # 1. Распаковка zip
        r = subprocess.run(
            ["unzip", "-o", str(src), "-d", str(tmp)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return False

        # 2. Поиск бинарников awg и awg-quick
        awg_bin = None
        awg_quick_bin = None
        for p in tmp.rglob("awg"):
            if p.is_file():
                awg_bin = p
                break
        for p in tmp.rglob("awg-quick"):
            if p.is_file():
                awg_quick_bin = p
                break

        if not awg_bin:
            return False

        # 3. Копирование в /usr/local/bin/
        dest_dir = install_dests[0]
        dest_dir.mkdir(parents=True, exist_ok=True)

        awg_dest = dest_dir / "awg"
        shutil.copy2(str(awg_bin), str(awg_dest))
        awg_dest.chmod(0o755)

        if awg_quick_bin:
            awg_quick_dest = dest_dir / "awg-quick"
            shutil.copy2(str(awg_quick_bin), str(awg_quick_dest))
            awg_quick_dest.chmod(0o755)

        return True

    except Exception:
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================================
#  post_install — AWG_GO_SOURCE_SPEC: extract + make + copy
# ============================================================================
def _post_install_awg_go_source(src: Path, install_dests: list[Path]) -> bool:
    """Распаковывает amneziawg-go source tarball, собирает через make,
    копирует бинарник в /usr/local/bin/amneziawg-go (chmod 0o755).

    Variant A (HTTP tarball вместо git clone). Makefile tolerates missing
    .git/ (version generation wrapped in `|| true`) — см. анализ Wave 6.

    Повторяет логику из старого awg_transport.py (L256-265, L298-308).
    """
    if not install_dests:
        return False

    tmp = Path(tempfile.mkdtemp(prefix="awg_go_build_"))
    try:
        # 1. Распаковка tarball
        r = subprocess.run(
            ["tar", "-xzf", str(src), "-C", str(tmp)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return False

        # 2. Поиск директории с исходниками (amneziawg-go-master/)
        src_dirs = list(tmp.glob("amneziawg-go-*"))
        if not src_dirs:
            return False
        src_dir = src_dirs[0]

        # 3. make (Makefile tolerates missing .git/)
        import os
        env = {**os.environ, "HOME": "/root"}
        r = subprocess.run(
            ["make"],
            cwd=str(src_dir),
            env=env,
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return False

        # 4. Поиск собранного бинарника
        built = src_dir / "amneziawg-go"
        if not built.exists():
            return False

        # 5. Копирование в /usr/local/bin/amneziawg-go
        dest_dir = install_dests[0]
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / "amneziawg-go"
        shutil.copy2(str(built), str(dest))
        dest.chmod(0o755)

        return True

    except Exception:
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================================
#  post_install — AWG_KMOD_SOURCE_SPEC: extract + dkms-install + modprobe
# ============================================================================
def _post_install_awg_kmod_source(src: Path, install_dests: list[Path]) -> bool:
    """Распаковывает amneziawg-linux-kernel-module source tarball, собирает
    через dkms-install (или fallback make && make install), проверяет через
    modprobe + ip link add/delete.

    Variant A (HTTP tarball вместо git clone). Makefile в src/ не использует
    git вообще (версия hardcoded как 1.0.0) — см. анализ Wave 6.

    ВАЖНО: исправлен давний баг — старый код искал dkms-install.sh в root
    репозитория, но этот файл там не существует. Реальный Makefile находится
    в src/. Теперь cd в src/ перед сборкой.

    Повторяет логику из старого awg_transport.py (L942-952), но с исправленным
    путём к src/.
    """
    # install_dests игнорируется — модуль ставится в /lib/modules через dkms
    # или make install.
    tmp = Path(tempfile.mkdtemp(prefix="awg_kmod_build_"))
    try:
        # 1. Распаковка tarball
        r = subprocess.run(
            ["tar", "-xzf", str(src), "-C", str(tmp)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return False

        # 2. Поиск директории с исходниками
        src_dirs = list(tmp.glob("amneziawg-linux-kernel-module-*"))
        if not src_dirs:
            return False
        repo_dir = src_dirs[0]

        # 3. cd в src/ и сборка
        # Пытаемся DKMS path: make dkms-install && dkms add/build/install
        # Fallback: make && make install
        src_dir = repo_dir / "src"
        if not src_dir.exists():
            return False

        # DKMS path
        r = subprocess.run(
            ["make", "dkms-install"],
            cwd=str(src_dir),
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            # Fallback: direct make && make install
            r = subprocess.run(
                ["make"],
                cwd=str(src_dir),
                capture_output=True, text=True,
            )
            if r.returncode != 0:
                return False
            r = subprocess.run(
                ["make", "install"],
                cwd=str(src_dir),
                capture_output=True, text=True,
            )
            if r.returncode != 0:
                return False

        # 4. modprobe amneziawg
        subprocess.run(
            ["modprobe", "amneziawg"],
            capture_output=True, text=True,
        )

        # 5. Verify: ip link add test_awg0 type amneziawg && ip link delete
        r = subprocess.run(
            ["ip", "link", "add", "test_awg0", "type", "amneziawg"],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            subprocess.run(
                ["ip", "link", "delete", "dev", "test_awg0"],
                capture_output=True, text=True,
            )
            return True

        return False

    except Exception:
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================================
#  PackageSpec — amneziawg-tools zip
# ============================================================================
AWG_TOOLS_SPEC = PackageSpec(
    name="amneziawg-tools",
    filename_builder=lambda tag, arch: (
        "ubuntu-22.04-arm64-amneziawg-tools.zip" if arch == "arm64"
        else "ubuntu-22.04-amneziawg-tools.zip"
    ),
    mirror_urls_builder=_awg_tools_mirror_urls,
    install_dests=_AWG_BIN_INSTALL_DESTS,         # [/usr/local/bin]
    manual_incoming_dir=_MANUAL_DIR,              # /root/
    min_size=_MIN_AWG_TOOLS_ZIP_SIZE,             # 100 KB
    post_install=_post_install_awg_tools,         # unzip + copy awg/awg-quick
)


# ============================================================================
#  PackageSpec — amneziawg-go source tarball (Variant A)
# ============================================================================
AWG_GO_SOURCE_SPEC = PackageSpec(
    name="amneziawg-go source",
    filename_builder=lambda: "amneziawg-go-master.tar.gz",
    mirror_urls_builder=_awg_go_source_mirror_urls,
    install_dests=_AWG_BIN_INSTALL_DESTS,         # [/usr/local/bin]
    manual_incoming_dir=_MANUAL_DIR,              # /root/
    min_size=_MIN_AWG_GO_SOURCE_SIZE,             # 1 KB
    post_install=_post_install_awg_go_source,     # extract + make + copy
)


# ============================================================================
#  PackageSpec — amneziawg-linux-kernel-module source tarball (Variant A)
# ============================================================================
AWG_KMOD_SOURCE_SPEC = PackageSpec(
    name="amneziawg-kernel-module source",
    filename_builder=lambda: "amneziawg-linux-kernel-module-master.tar.gz",
    mirror_urls_builder=_awg_kmod_source_mirror_urls,
    install_dests=_AWG_BUILD_TMP,                 # [/tmp/awg_build] — placeholder
    manual_incoming_dir=_MANUAL_DIR,              # /root/
    min_size=_MIN_AWG_KMOD_SOURCE_SIZE,           # 1 KB
    post_install=_post_install_awg_kmod_source,   # extract + dkms-install + modprobe
)
