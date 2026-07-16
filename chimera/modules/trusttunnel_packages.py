"""
chimera/modules/trusttunnel_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec для TrustTunnel prebuilt binaries (TrustTunnel/TrustTunnel
GitHub Releases).

Используется trusttunnel.py::_download_and_install_binary() для скачивания
Linux release tarball'а и распаковки бинарников.

Содержимое tarball'а (подтверждено extract'ом v1.0.33 в Phase 0):
  trusttunnel-v${VERSION}-linux-${ARCH}/
  ├── trusttunnel_endpoint          (сервер, stripped static-pie ELF)
  ├── trusttunnel_endpoint.sig      (GPG detached signature)
  ├── setup_wizard                  (config generator)
  ├── setup_wizard.sig
  ├── LICENSE                       (Apache 2.0)
  └── trusttunnel.service.template  (systemd unit template)

Naming convention (подтверждён через GitHub API):
  trusttunnel-v${VERSION}-linux-x86_64.tar.gz
  trusttunnel-v${VERSION}-linux-aarch64.tar.gz

post_install делает:
  1. tar xzf {src} → {tmpdir}
  2. Поиск trusttunnel_endpoint + setup_wizard + *.sig + LICENSE + template
     (через rglob — не завязываемся на точное имя директории с версией)
  3. copy2 в /opt/trusttunnel/ (chmod 0o755 для бинарников, 0o644 для .sig)
  4. cleanup временной директории

install_dests = [/opt/trusttunnel] — директория установки.
manual_incoming_dir = /root/ — не совпадает с install_dests (PackageSpec
инвариант, защита от бага 21d7baf из geo_files.py).

Точка входа:
    from chimera.modules.trusttunnel_packages import TRUSTTUNNEL_SPEC
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

from chimera.modules.download_manager import PackageSpec
from chimera.modules.trusttunnel_mirrors import get_trusttunnel_mirrors


# ══════════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════
_TRUSTTUNNEL_INSTALL_DESTS: list[Path] = [Path("/opt/trusttunnel")]
_MANUAL_DIR = Path("/root")

# Минимальный размер tarball'а: реальный v1.0.33 x86_64 = ~10.7 МБ.
# Порог 1 МБ отлавливает HTML-страницы 404.
_MIN_TARBALL_SIZE = 1_000_000

# Файлы для извлечения из tarball'а.
_BINARIES_TO_COPY = ["trusttunnel_endpoint", "setup_wizard"]
_SIGS_TO_COPY     = ["trusttunnel_endpoint.sig", "setup_wizard.sig"]
_OTHER_FILES      = ["LICENSE", "trusttunnel.service.template"]


# ══════════════════════════════════════════════════════════════════════════════
#  filename_builder — имя tarball'а по tag + архитектуре
# ══════════════════════════════════════════════════════════════════════════════
def _build_filename(tag: str = "v1.0.33", **kw) -> str:
    """Собрать имя tarball'а по tag + текущей архитектуре.

    Naming convention (подтверждён через GitHub API для v1.0.33):
      trusttunnel-v${VERSION}-linux-x86_64.tar.gz
      trusttunnel-v${VERSION}-linux-aarch64.tar.gz

    где VERSION = tag без ведущей 'v'.
    """
    arch = platform.machine().lower()
    if arch in ("x86_64", "amd64"):
        arch = "x86_64"
    elif arch in ("aarch64", "arm64"):
        arch = "aarch64"
    else:
        arch = "x86_64"  # safe default
    version = tag.lstrip("v")
    return f"trusttunnel-v{version}-linux-{arch}.tar.gz"


# ══════════════════════════════════════════════════════════════════════════════
#  mirror_urls_builder — обёртка для PackageSpec API
# ══════════════════════════════════════════════════════════════════════════════
def _trusttunnel_mirror_urls(filename: str, tag: str = "v1.0.33", **kw) -> list[str]:
    """Собрать URL'ы для TrustTunnel release tarball'а через trusttunnel_mirrors.

    filename — передаётся download_manager'ом (имя из filename_builder).
    tag — release tag С ведущей 'v'.
    """
    if not filename:
        return []
    return get_trusttunnel_mirrors(tag=tag, filename=filename)


# ══════════════════════════════════════════════════════════════════════════════
#  post_install — tar xzf + copy бинарников + sigs в /opt/trusttunnel
# ══════════════════════════════════════════════════════════════════════════════
def _post_install_trusttunnel(src: Path, install_dests: list[Path]) -> bool:
    """Распаковать tarball, извлечь бинарники + sigs, скопировать в
    install_dests[0]/.

    Возвращает True если ОБА бинарника (trusttunnel_endpoint + setup_wizard)
    найдены и скопированы. False при любой ошибке — даёт fetch_package шанс
    попробовать следующее зеркало.
    """
    if not install_dests:
        return False

    tmp = Path(tempfile.mkdtemp(prefix="trusttunnel-extract-"))
    try:
        # 1. tar xzf
        r = subprocess.run(
            ["tar", "xzf", str(src), "-C", str(tmp)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return False

        # 2. Найти файлы по имени (rglob — не завязываемся на имя директории)
        found_endpoint = False
        found_wizard = False
        dest_dir = install_dests[0]
        dest_dir.mkdir(parents=True, exist_ok=True)

        for name in _BINARIES_TO_COPY + _SIGS_TO_COPY + _OTHER_FILES:
            matches = list(tmp.rglob(name))
            if not matches:
                continue
            src_file = matches[0]
            dest_file = dest_dir / name
            shutil.copy2(str(src_file), str(dest_file))
            if name in _BINARIES_TO_COPY:
                dest_file.chmod(0o755)
                if name == "trusttunnel_endpoint":
                    found_endpoint = True
                elif name == "setup_wizard":
                    found_wizard = True
            else:
                try:
                    dest_file.chmod(0o644)
                except Exception:
                    pass

        return found_endpoint and found_wizard

    except Exception:
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════════════
#  PackageSpec
# ══════════════════════════════════════════════════════════════════════════════
TRUSTTUNNEL_SPEC = PackageSpec(
    name="trusttunnel prebuilt binaries",
    filename_builder=_build_filename,
    mirror_urls_builder=_trusttunnel_mirror_urls,
    install_dests=_TRUSTTUNNEL_INSTALL_DESTS,
    manual_incoming_dir=_MANUAL_DIR,
    min_size=_MIN_TARBALL_SIZE,
    post_install=_post_install_trusttunnel,
)
