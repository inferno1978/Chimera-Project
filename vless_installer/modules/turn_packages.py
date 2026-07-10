"""
vless_installer/modules/turn_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec-инстансы для бинарников vk-turn-proxy и turnable — декларативное
описание пакетов для download_manager.fetch_package().

Этот модуль ОТДЕЛЁН от turn_mirrors.py (реестр URL-фабрик) и от turntunnel.py
/ turnable.py (оркестрация установки). Спеки пакетов — это связка «зеркала +
пути установки + post_install», которая говорит fetch_package() КАК качать и
КУДА ставить, не зная внутренних деталей.

АРХИТЕКТУРНАЯ ЗАЩИТА ОТ БАГА 21d7baf:
  PackageSpec.__post_init__ assert проверяет что manual_incoming_dir (/root/)
  НЕ совпадает ни с одним install_dest. Это физически запрещает создание
  spec'а с коллизией — баг «повторный вызов находит свой же файл в
  install_dests и не идёт в сеть» невозможен по конструкции.

  Для TURNTUNNEL_SPEC: install_dests = [/opt/vk-turn-proxy], manual = /root/.
  Для TURNABLE_SPEC:   install_dests = [/opt/turnable],        manual = /root/.
  Коллизии нет, assert проходит.

Особенности post_install:
  • Скачанный/ручной файл — это ГОТОВЫЙ ELF-бинарник (без распаковки).
    post_install делает: mkdir install_dest → copy2 → chmod 0o755 →
    проверка ELF magic. Если файл не ELF — возвращает False (даёт
    fetch_package шанс попробовать следующее зеркало).
  • Раньше ELF magic проверялся в самих модулях (turntunnel.py / turnable.py).
    Теперь эта проверка централизована в _post_install_binary.

Точки входа:
    from vless_installer.modules.turn_packages import (
        TURNTUNNEL_SPEC, TURNABLE_SPEC,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import shutil
from pathlib import Path

from vless_installer.modules.download_manager import PackageSpec
from vless_installer.modules.turn_mirrors import (
    get_turntunnel_mirrors, get_turnable_mirrors,
)


# ============================================================================
#  КОНСТАНТЫ — пути установки (из turntunnel.py / turnable.py)
# ============================================================================

# vk-turn-proxy: бинарник ставится в /opt/vk-turn-proxy/server.
# Turntunnel.py использует _BIN_PATH = Path("/opt/vk-turn-proxy/server"),
# _BIN_DIR = Path("/opt/vk-turn-proxy").
_TURNTUNNEL_INSTALL_DESTS: list[Path] = [Path("/opt/vk-turn-proxy")]

# turnable: бинарник ставится в /opt/turnable/turnable.
# turnable.py использует _BIN_PATH = Path("/opt/turnable/turnable"),
# _BIN_DIR = Path("/opt/turnable").
_TURNABLE_INSTALL_DESTS: list[Path] = [Path("/opt/turnable")]

# manual_incoming_dir — ТОЛЬКО /root/. Не весь MANUAL_UPLOAD_PATHS_*.
# PackageSpec.__post_init__ assert гарантирует что /root/ не совпадает
# ни с одним install_dest — это структурная защита от бага 21d7baf.
_MANUAL_DIR = Path("/root")

# Минимальный размер ELF-бинарника. Реальные размеры:
#   • vk-turn-proxy server-linux-amd64 — ~5-15 MB (Go-бинарник с TURN/STUN)
#   • turnable turnable-linux-amd64 — ~5-10 MB (Go-бинарник)
# 1 MB — разумный нижний порог: отлавливает усечённые загрузки и HTML-страницы
# с ошибкой 404 (которые обычно <100 KB), не блокируя маленькие легитимные
# бинарники. Раньше этой проверки не было вообще — только 4-байтная ELF
# magic проверка, которая пропускала бы пустой файл с 7f 45 4c 46 в начале.
_MIN_BINARY_SIZE = 1_000_000  # 1 MB


# ============================================================================
#  post_install — копирование ELF-бинарника + chmod 0o755 + проверка ELF magic
# ============================================================================
def _post_install_binary(
    src: Path,
    install_dests: list[Path],
    *,
    dest_filename: str,
) -> bool:
    """Копирует готовый ELF-бинарник во все install_dests.

    Шаги:
      1. Проверка ELF magic (первые 4 байта == b'\\x7fELF') — защита от
         усечённых/HTML-загрузок, которые прошли min_size проверку.
      2. mkdir install_dest (parents=True, exist_ok=True).
      3. shutil.copy2(src → install_dest/dest_filename).
      4. chmod 0o755 (исполняемый).

    Параметры:
      src:             Скачанный/ручной файл (готовый ELF-бинарник).
      install_dests:   Куда копировать (обычно одна директория).
      dest_filename:   Имя файла в install_dests (например "server"
                       для vk-turn-proxy, "turnable" для turnable).

    Возвращает:
      True если скопировано хотя бы в одну install_dest.
      False если файл не ELF или все копирования упали — даёт fetch_package
      шанс попробовать следующее зеркало.
    """
    # 1) Проверка ELF magic
    try:
        with src.open("rb") as f:
            magic = f.read(4)
        if magic != b'\x7fELF':
            # Файл прошёл min_size, но не ELF — вероятно HTML-страница 404
            # или файл из неподдерживаемой архитектуры. Возвращаем False,
            # fetch_package попробует следующее зеркало.
            return False
    except Exception:
        return False

    # 2) Копирование во все install_dests
    any_ok = False
    for dest_dir in install_dests:
        dest = dest_dir / dest_filename
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dest))
            dest.chmod(0o755)
            any_ok = True
        except Exception:
            pass

    return any_ok


# ============================================================================
#  post_install — обёртки для конкретных бинарников
# ============================================================================
def _post_install_turntunnel(src: Path, install_dests: list[Path]) -> bool:
    """post_install для vk-turn-proxy: ставит в install_dests/server."""
    return _post_install_binary(src, install_dests, dest_filename="server")


def _post_install_turnable(src: Path, install_dests: list[Path]) -> bool:
    """post_install для turnable: ставит в install_dests/turnable."""
    return _post_install_binary(src, install_dests, dest_filename="turnable")


# ============================================================================
#  Зеркала — обёртки над turn_mirrors для соответствия сигнатуре
#  mirror_urls_builder(filename: str, **kwargs) -> list[str]
# ============================================================================
def _turntunnel_mirror_urls(filename: str, **kw) -> list[str]:
    """Собирает URL для vk-turn-proxy через turn_mirrors.

    filename параметр принимается для совместимости с PackageSpec API,
    но игнорируется: имя файла фиксировано (server-linux-amd64).
    """
    return get_turntunnel_mirrors()


def _turnable_mirror_urls(filename: str, version: str = "0.4.1", **kw) -> list[str]:
    """Собирает URL для turnable через turn_mirrors.

    version — pinned tag из turnable.py (_TURNABLE_VERSION).
    filename параметр принимается для совместимости с PackageSpec API,
    но игнорируется: имя файла фиксировано (turnable-linux-amd64).
    """
    return get_turnable_mirrors(version)


# ============================================================================
#  PackageSpec — vk-turn-proxy (turntunnel)
# ============================================================================
TURNTUNNEL_SPEC = PackageSpec(
    name="vk-turn-proxy",
    filename_builder=lambda: "server-linux-amd64",
    mirror_urls_builder=_turntunnel_mirror_urls,
    install_dests=_TURNTUNNEL_INSTALL_DESTS,    # [/opt/vk-turn-proxy]
    manual_incoming_dir=_MANUAL_DIR,            # /root/
    min_size=_MIN_BINARY_SIZE,                  # 1 MB — защита от 404-страниц
    post_install=_post_install_turntunnel,      # копирование + chmod + ELF check
)


# ============================================================================
#  PackageSpec — turnable
# ============================================================================
TURNABLE_SPEC = PackageSpec(
    name="turnable",
    filename_builder=lambda: "turnable-linux-amd64",
    mirror_urls_builder=_turnable_mirror_urls,
    install_dests=_TURNABLE_INSTALL_DESTS,      # [/opt/turnable]
    manual_incoming_dir=_MANUAL_DIR,            # /root/
    min_size=_MIN_BINARY_SIZE,                  # 1 MB
    post_install=_post_install_turnable,
)
