"""
vless_installer/modules/olcrtc_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec для olcrtc source tarball (openlibrecommunity/olcrtc).

Используется olcrtc.py::_olcrtc_clone_or_update() для скачивания исходников
и их сборки. До миграции olcrtc.py делал это через `git clone --depth 1`
(или `git pull --ff-only`).

Variant A (HTTP tarball вместо git clone) применим согласно анализу Wave 6:
  • Build — pure `go build`, не требует .git/.
  • Submodules отсутствуют.
  • Commit SHA для state file получается через отдельный GitHub API call
    (см. olcrtc.py::_olcrtc_fetch_commit_sha), вместо `git rev-parse`.

Особенности post_install:
  • extract tarball → olcrtc-master/ директория
  • go build -trimpath -ldflags "-s -w" -o /usr/local/bin/olcrtc ./cmd/olcrtc
    (env: CGO_ENABLED=0, GOOS=linux, GOARCH={amd64,arm64}, timeout 900s)
  • cleanup временной директории

Go toolchain должен быть установлен ДО вызова fetch_package(OLCRTC_SOURCE_SPEC)
— вызывающий код отвечает за _ensure_go() (переиспользует GO_TOOLCHAIN_SPEC
из go_toolchain_packages.py, созданный в Волне 2).

install_dests = [/usr/local/bin] — куда ставится бинарник olcrtc.
manual_incoming_dir = /root/ — не совпадает с install_dests.

Точки входа:
    from vless_installer.modules.olcrtc_packages import OLCRTC_SOURCE_SPEC
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from vless_installer.modules.download_manager import PackageSpec
from vless_installer.modules.olcrtc_mirrors import get_olcrtc_source_mirrors


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================

# /usr/local/bin — куда ставится бинарник olcrtc (OLC_BIN из olcrtc.py).
_OLCRTC_INSTALL_DESTS: list[Path] = [Path("/usr/local/bin")]

# manual_incoming_dir — /root/ (WinSCP-friendly).
_MANUAL_DIR = Path("/root")

# Имя файла в install_dests — "olcrtc".
_OLCRTC_DEST_FILENAME = "olcrtc"

# Минимальный размер source tarball'а.
# Реальный размер: ~100-500 KB (Go-проект с исходниками).
# 1000 байт — нижний порог, отлавливает HTML-страницы 404.
_MIN_OLCRTC_SOURCE_SIZE = 1000


# ============================================================================
#  mirror_urls_builder — обёртка для PackageSpec API
# ============================================================================
def _olcrtc_source_mirror_urls(filename: str, **kw) -> list[str]:
    """Собирает URL для olcrtc source через olcrtc_mirrors.

    filename параметр принимается для совместимости с PackageSpec API,
    но игнорируется — имя файла фиксировано (olcrtc-master.tar.gz).
    """
    return get_olcrtc_source_mirrors()


# ============================================================================
#  Вспомогательные: поиск Go бинарника
# ============================================================================
def _find_go_binary() -> str | None:
    """Возвращает путь к go бинарнику (предпочитая /usr/local/bin/go).

    Локальная копия olcrtc.py::_check_go() — нужна чтобы post_install не
    зависел от импорта olcrtc.py (циклический импорт).
    """
    go_path = Path("/usr/local/bin/go")
    if go_path.exists():
        r = subprocess.run(
            [str(go_path), "version"],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            return str(go_path)

    found = shutil.which("go")
    if found:
        r = subprocess.run(
            [found, "version"],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            return found

    return None


def _go_arch() -> str:
    """Возвращает GOARCH ('amd64' или 'arm64')."""
    r = subprocess.run(["uname", "-m"], capture_output=True, text=True)
    m = (r.stdout or "").strip() if r.returncode == 0 else ""
    return {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(m, "amd64")


# ============================================================================
#  post_install — extract + go build + copy
# ============================================================================
def _post_install_olcrtc_source(src: Path, install_dests: list[Path]) -> bool:
    """Распаковывает olcrtc source tarball, собирает через go build,
    копирует бинарник в /usr/local/bin/olcrtc (chmod 0o755).

    Шаги (повторяют логику из старого olcrtc.py::_olcrtc_build):
      1. extract tarball → olcrtc-master/ директория
      2. go build -trimpath -ldflags "-s -w" -o /usr/local/bin/olcrtc ./cmd/olcrtc
         (env: CGO_ENABLED=0, GOOS=linux, GOARCH={amd64,arm64}, timeout 900s)
      3. cleanup временной директории

    Go toolchain должен быть установлен ДО этого вызова.

    Возвращает True при успехе, False при любой ошибке.
    """
    if not install_dests:
        return False

    tmp = Path(tempfile.mkdtemp(prefix="olcrtc_build_"))
    try:
        # 1. Распаковка tarball
        r = subprocess.run(
            ["tar", "-xzf", str(src), "-C", str(tmp)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return False

        # 2. Поиск директории с исходниками (olcrtc-master/)
        src_dirs = list(tmp.glob("olcrtc-*"))
        if not src_dirs:
            return False
        src_dir = src_dirs[0]

        # 3. Поиск Go бинарника
        go = _find_go_binary()
        if not go:
            return False

        # 4. go build (timeout 900s = 15 min, как в старом коде)
        env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": _go_arch()}
        dest_dir = install_dests[0]
        dest_dir.mkdir(parents=True, exist_ok=True)
        olc_bin = dest_dir / _OLCRTC_DEST_FILENAME

        r = subprocess.run(
            [go, "build", "-trimpath", "-ldflags", "-s -w",
             "-o", str(olc_bin), "./cmd/olcrtc"],
            cwd=str(src_dir),
            env=env,
            capture_output=True, text=True,
            timeout=900,
        )
        if r.returncode != 0 or not olc_bin.exists():
            return False

        # 5. chmod 0o755
        olc_bin.chmod(0o755)

        return True

    except Exception:
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================================
#  PackageSpec — olcrtc source tarball (Variant A)
# ============================================================================
OLCRTC_SOURCE_SPEC = PackageSpec(
    name="olcrtc source",
    filename_builder=lambda: "olcrtc-master.tar.gz",
    mirror_urls_builder=_olcrtc_source_mirror_urls,
    install_dests=_OLCRTC_INSTALL_DESTS,        # [/usr/local/bin]
    manual_incoming_dir=_MANUAL_DIR,            # /root/
    min_size=_MIN_OLCRTC_SOURCE_SIZE,           # 1 KB
    post_install=_post_install_olcrtc_source,   # extract + go build + copy
)
