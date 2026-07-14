"""
chimera/modules/iperf3_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec для статического iperf3 binary (userdocs/iperf3-static).

Используется network_bench.py::install_iperf3() для скачивания готового
ELF-бинарника. До миграции network_bench.py делал это ad-hoc через
urllib.request.urlretrieve.

Особенности:
  • Бинарник — готовый ELF, без распаковки.
  • post_install: ELF magic проверка → copy2 в install_dests[0]/iperf3
    (chmod 0o755).
  • arch подставляется через filename_kwargs: fetch_package(IPERF3_SPEC,
    arch="amd64").
  • install_dests = [/tmp] — временная директория (iperf3 используется
    только для speed test, не персистентный артефакт согласно Addendum).
  • manual_incoming_dir = /root/ — не совпадает с install_dests.

Точки входа:
    from chimera.modules.iperf3_packages import IPERF3_SPEC
"""
from __future__ import annotations

import shutil
from pathlib import Path

from chimera.modules.download_manager import PackageSpec
from chimera.modules.iperf3_mirrors import get_iperf3_mirrors


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================

# /tmp — временная директория для iperf3 (не персистентный артефакт).
_IPERF3_INSTALL_DESTS: list[Path] = [Path("/tmp")]

# manual_incoming_dir — /root/ (WinSCP-friendly).
# /root/ != /tmp — assert в __post_init__ проходит.
_MANUAL_DIR = Path("/root")

# Имя файла в install_dests — "iperf3".
_IPERF3_DEST_FILENAME = "iperf3"

# Минимальный размер iperf3 binary.
# Реальный размер: ~3-5 MB (статически слинкованный C-бинарник).
# 500 KB — нижний порог, отлавливает HTML-страницы 404 (раньше не было).
_MIN_IPERF3_BINARY_SIZE = 500_000


# ============================================================================
#  mirror_urls_builder — обёртка для PackageSpec API
# ============================================================================
def _iperf3_mirror_urls(filename: str, arch: str = "amd64", **kw) -> list[str]:
    """Собирает URL для iperf3 через iperf3_mirrors.

    filename параметр принимается для совместимости с PackageSpec API,
    но игнорируется — имя файла конструируется из arch внутри
    get_iperf3_mirrors().
    """
    return get_iperf3_mirrors(arch=arch)


# ============================================================================
#  post_install — ELF magic проверка + copy2
# ============================================================================
def _post_install_iperf3(src: Path, install_dests: list[Path]) -> bool:
    """Копирует готовый ELF-бинарник в install_dests[0]/iperf3.

    Шаги:
      1. Проверка ELF magic (первые 4 байта == b'\\x7fELF').
      2. mkdir install_dest (parents=True, exist_ok=True).
      3. shutil.copy2(src → install_dest/iperf3).
      4. chmod 0o755.
    """
    # 1. Проверка ELF magic
    try:
        with src.open("rb") as f:
            magic = f.read(4)
        if magic != b'\x7fELF':
            return False
    except Exception:
        return False

    # 2-4. Копирование
    if not install_dests:
        return False
    dest_dir = install_dests[0]
    dest = dest_dir / _IPERF3_DEST_FILENAME
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src), str(dest))
        dest.chmod(0o755)
        return True
    except Exception:
        return False


# ============================================================================
#  PackageSpec — iperf3 static binary
# ============================================================================
IPERF3_SPEC = PackageSpec(
    name="iperf3 static",
    filename_builder=lambda arch, **kw: f"iperf3-{arch}",
    mirror_urls_builder=_iperf3_mirror_urls,
    install_dests=_IPERF3_INSTALL_DESTS,        # [/tmp]
    manual_incoming_dir=_MANUAL_DIR,            # /root/
    min_size=_MIN_IPERF3_BINARY_SIZE,           # 500 KB
    post_install=_post_install_iperf3,          # ELF check + copy2 + chmod
)
