"""
vless_installer/modules/telemt_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Thin wrapper над github_mirrors.build_mirror_urls() для telemt/telemt_panel.

ПОСЛЕ МИГРАЦИИ:
  Раньше здесь было 4 копии фабрик URL (_gh_proxy_telemt, _gh_proxy_panel,
  _jsdelivr_telemt, _jsdelivr_panel) — копипаста с разницей только в
  owner/repo. Теперь — thin wrapper: get_telemt_mirrors() и
  get_telemt_panel_mirrors() просто вызывают build_mirror_urls() с разными
  owner/repo. Никакой копипасты.

  PackageSpec-инстансы живут в telemt_packages.py.

УБРАНА зависимость от api.github.com:
  _get_latest_release() в mtproto.py/telemt_panel.py больше не идёт в
  api.github.com. tag="latest" в build_mirror_urls() — GitHub сам делает
  редирект при скачивании. api.github.com не нужен.

Точки входа (сохранены для обратной совместимости):
    from vless_installer.modules.telemt_mirrors import (
        get_telemt_mirrors, get_telemt_panel_mirrors,
        MANUAL_UPLOAD_PATHS, TELEMT_MIRRORS_COUNT,
        recommended_manual_path, find_manual_upload,
        print_telemt_manual_download_hint,
        detect_arch_libc,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import platform
import subprocess
from pathlib import Path
from typing import Optional

from vless_installer.modules.github_mirrors import build_mirror_urls


# ============================================================================
#  ОПРЕДЕЛЕНИЕ АРХИТЕКТУРЫ / LIBC
# ============================================================================
def detect_arch_libc() -> tuple[str, str]:
    """Возвращает (arch, libc) для построения имени файла.

    arch: 'x86_64' или 'aarch64' (как в release-assets telemt).
    libc: 'gnu' или 'musl' (telemt публикует оба варианта).
    """
    arch = "aarch64" if platform.machine().lower() in ("aarch64", "arm64") else "x86_64"
    try:
        r = subprocess.run(["ldd", "--version"],
                           capture_output=True, text=True, timeout=5)
        libc = "musl" if "musl" in (r.stdout + r.stderr).lower() else "gnu"
    except Exception:
        libc = "gnu"
    return arch, libc


# ============================================================================
#  ПУБЛИЧНЫЙ API — thin wrappers над build_mirror_urls
# ============================================================================
def get_telemt_mirrors() -> list[str]:
    """Упорядоченный список URL для скачивания telemt tar.gz."""
    arch, libc = detect_arch_libc()
    filename = f"telemt-{arch}-linux-{libc}.tar.gz"
    return build_mirror_urls(
        owner="telemt", repo="telemt", filename=filename,
        tag="latest",
        jsdelivr_hosts=(),            # jsDelivr не работает с release-assets
        include_raw_github=False,      # telemt не публикует raw файлы
        include_statically=False,      # Statically тоже не работает с release-assets
    )


def get_telemt_panel_mirrors() -> list[str]:
    """Упорядоченный список URL для скачивания telemt-panel tar.gz."""
    arch, libc = detect_arch_libc()
    filename = f"telemt-panel-{arch}-linux-{libc}.tar.gz"
    return build_mirror_urls(
        owner="amirotin", repo="telemt_panel", filename=filename,
        tag="latest",
        jsdelivr_hosts=(),
        include_raw_github=False,
        include_statically=False,
    )


def get_all_mirrors() -> dict[str, list[str]]:
    """Словарь {filename: [urls]} — для меню/подсказок."""
    arch, libc = detect_arch_libc()
    return {
        f"telemt-{arch}-linux-{libc}.tar.gz": get_telemt_mirrors(),
        f"telemt-panel-{arch}-linux-{libc}.tar.gz": get_telemt_panel_mirrors(),
    }


TELEMT_MIRRORS_COUNT: int = 8
"""Количество зеркал на каждый файл (1 release + 7 прокси)."""


# --- Пути ручного размещения ------------------------------------------------
MANUAL_UPLOAD_PATHS: list[Path] = [
    Path("/root"),                       # ← РЕКОМЕНДУЕТСЯ (зелёным в TUI)
    Path("/usr/local/bin"),              # куда в итоге ставится бинарник
    Path("/etc/telemt"),                 # конфиг-директория Telemt
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения (первый в списке)."""
    return MANUAL_UPLOAD_PATHS[0]


def find_manual_upload(filename: str) -> Optional[Path]:
    """Ищет файл `filename` в MANUAL_UPLOAD_PATHS.
    Возвращает путь если найден, иначе None.
    """
    for p in MANUAL_UPLOAD_PATHS:
        candidate = p / filename
        try:
            if candidate.exists() and candidate.stat().st_size > 0:
                return candidate
        except (PermissionError, OSError):
            continue
    return None


# ============================================================================
#  ПОДСКАЗКА ДЛЯ РУЧНОГО СКАЧИВАНИЯ
# ============================================================================
def print_telemt_manual_download_hint(component: str = "telemt") -> None:
    """Выводит инструкцию для ручного скачивания telemt или telemt-panel."""
    import importlib
    try:
        core = importlib.import_module("vless_installer._core")
        YELLOW = core.YELLOW
        NC = core.NC
        BOLD = core.BOLD
        WHITE = core.WHITE
        CYAN = core.CYAN
        GREEN = core.GREEN
        DIM = core.DIM
    except Exception:
        YELLOW = NC = BOLD = WHITE = CYAN = GREEN = DIM = ""

    arch, libc = detect_arch_libc()
    all_mirrors = get_all_mirrors()
    recommended = recommended_manual_path()

    if component == "panel":
        filename = f"telemt-panel-{arch}-linux-{libc}.tar.gz"
        label = "telemt-panel (веб-панель)"
    else:
        filename = f"telemt-{arch}-linux-{libc}.tar.gz"
        label = "telemt (MTProxy-сервер)"

    urls = all_mirrors.get(filename, [])

    sep = f"{YELLOW}{'─' * 64}{NC}"
    print()
    print(sep)
    print(f"{BOLD}{YELLOW}Не удалось скачать {label} автоматически.{NC}")
    print(f"{WHITE}   Скачайте файл вручную и разместите на сервере.{NC}")
    print(sep)
    print()
    print(f"{CYAN}Файл: {filename}{NC}")
    if urls:
        print(f"{DIM}({len(urls)} зеркал в fallback){NC}")
        for i, url in enumerate(urls, 1):
            print(f"    {DIM}{i:>2}){NC} {url}")
    print()
    print(f"{CYAN}Разместите файл в:{NC}")
    for p in MANUAL_UPLOAD_PATHS:
        if p == recommended:
            print(f"    {BOLD}{GREEN}{p}/{NC}  {BOLD}{GREEN}← рекомендуется (WinSCP-friendly){NC}")
        else:
            print(f"    {BOLD}{p}/{NC}")
    print()
    if urls:
        print(f"{WHITE}Команда для скачивания на сервере:{NC}")
        print(f"    {DIM}curl -fL \"{urls[0]}\" -o {recommended}/{filename}{NC}")
    print()
    print(f"{WHITE}Или SCP с вашего ПК:{NC}")
    print(f"    {DIM}scp {filename} root@<IP>:{recommended}/{NC}")
    print()
    print(f"{WHITE}После размещения файла повторите операцию.{NC}")
    print()
    print(sep)
    print()
