"""
chimera/modules/naiveproxy_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec для caddy-forwardproxy-naive binary (Michaol/caddy-naive).

Используется naiveproxy.py::_download_binary() для скачивания готового
ELF-бинарника. До миграции naiveproxy.py делал это ad-hoc через
urllib.request.urlretrieve + ELF magic check.

Особенности:
  • Бинарник — готовый ELF, без распаковки.
  • post_install: ELF magic проверка → copy2 в install_dests/caddy-naive
    (chmod 0o755).
  • amd64 only (naiveproxy.py отказывает на других arch до вызова
    fetch_package — это бизнес-логика, не ответственность spec'а).

install_dests = [/usr/local/bin] — это _BIN_PATH.parent из naiveproxy.py.
manual_incoming_dir = /root/ — не совпадает с install_dests.

Точки входа:
    from chimera.modules.naiveproxy_packages import NAIVEPROXY_SPEC
"""
from __future__ import annotations

import shutil
from pathlib import Path

from chimera.modules.download_manager import PackageSpec
from chimera.modules.naiveproxy_mirrors import get_naiveproxy_mirrors


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================

# _BIN_PATH из naiveproxy.py = Path("/usr/local/bin/caddy-naive").
# install_dests = [/usr/local/bin] — директория, post_install ставит
# бинарник с именем "caddy-naive" (имя из _BIN_PATH.name).
_NAIVEPROXY_INSTALL_DESTS: list[Path] = [Path("/usr/local/bin")]

# manual_incoming_dir — /root/ (WinSCP-friendly).
_MANUAL_DIR = Path("/root")

# Имя файла в install_dests — "caddy-naive" (из _BIN_PATH.name).
_NAIVEPROXY_DEST_FILENAME = "caddy-naive"

# Минимальный размер caddy-naive бинарника.
# Реальный размер: ~30-40 MB (Go-бинарник с Caddy + forwardproxy plugin).
# 1 MB — нижний порог, отлавливает HTML-страницы 404 (раньше не было).
_MIN_NAIVEPROXY_BINARY_SIZE = 1_000_000


# ============================================================================
#  mirror_urls_builder — обёртка для PackageSpec API
# ============================================================================
def _naiveproxy_mirror_urls(filename: str, **kw) -> list[str]:
    """Собирает URL для caddy-naive через naiveproxy_mirrors.

    filename параметр принимается для совместимости с PackageSpec API,
    но игнорируется — имя файла фиксировано (caddy-linux-amd64).
    """
    return get_naiveproxy_mirrors()


# ============================================================================
#  post_install — ELF magic проверка + copy2
# ============================================================================
def _post_install_naiveproxy(src: Path, install_dests: list[Path]) -> bool:
    """Копирует готовый ELF-бинарник в install_dests/caddy-naive.

    Шаги:
      1. Проверка ELF magic (первые 4 байта == b'\\x7fELF') — защита от
         усечённых/HTML-загрузок.
      2. mkdir install_dest (parents=True, exist_ok=True).
      3. shutil.copy2(src → install_dest/caddy-naive).
      4. chmod 0o755.

    Возвращает True если скопировано. False если файл не ELF или
    копирование упало.
    """
    # 1. Проверка ELF magic
    try:
        with src.open("rb") as f:
            magic = f.read(4)
        if magic != b'\x7fELF':
            return False
    except Exception:
        return False

    # 2. Копирование во все install_dests
    if not install_dests:
        return False
    any_ok = False
    for dest_dir in install_dests:
        dest = dest_dir / _NAIVEPROXY_DEST_FILENAME
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dest))
            dest.chmod(0o755)
            any_ok = True
        except Exception:
            pass

    return any_ok


# ============================================================================
#  PackageSpec — caddy-naive binary
# ============================================================================
NAIVEPROXY_SPEC = PackageSpec(
    name="caddy-naive",
    filename_builder=lambda **kw: "caddy-linux-amd64",
    mirror_urls_builder=_naiveproxy_mirror_urls,
    install_dests=_NAIVEPROXY_INSTALL_DESTS,    # [/usr/local/bin]
    manual_incoming_dir=_MANUAL_DIR,            # /root/
    min_size=_MIN_NAIVEPROXY_BINARY_SIZE,       # 1 MB
    post_install=_post_install_naiveproxy,      # ELF check + copy2 + chmod
)
