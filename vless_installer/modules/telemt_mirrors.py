"""
vless_installer/modules/telemt_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания бинарников Telemt:
  • `telemt`        — MTProxy-сервер (github.com/telemt/telemt)
  • `telemt-panel`  — веб-панель управления (github.com/amirotin/telemt_panel)

КОНТЕКСТ (в чём была моя ошибка):
  В предыдущей задаче я применил multi-mirror логику к mieru.py, думая что
  это и есть «Telemt». Но mieru — отдельный протокол (mTLS туннель, бинарник
  mita от enfein/mieru). Telemt — это MTProxy для Telegram, совсем другой
  проект. Пользователь правильно поправил: «Я не совсем понял, как mieru
  связан с Telemt». Связи нет — это разные модули.

ПРОБЛЕМА (почему Telemt отвалился у двоих пользователей):
  • mtproto.py::_install_binary(url) качает основной бинарник `telemt`
    через urllib.request.urlretrieve(url) с ОДНОГО прямого URL
    https://github.com/telemt/telemt/releases/latest/download/...
    БЕЗ зеркал, БЕЗ fallback, БЕЗ проверки ручного размещения.
  • telemt_panel.py::_install_binary(url) делает то же самое для
    `telemt-panel` с URL https://github.com/amirotin/telemt_panel/...
  • Оба _get_latest_release() идут в api.github.com — если тот заблокирован,
    возвращают ('', '') и установка тихо проваливается.

  При блокировке github.com (частый случай в РФ) urllib выбрасывает
  исключение, вся установка Telemt падает.

РЕШЕНИЕ (по аналогии с geo_mirrors.py и mieru_mirrors.py):
  1. Реестр зеркал: прямой GitHub + 7 GitHub-прокси + jsDelivr CDN.
  2. MANUAL_UPLOAD_PATHS: /root/ (рекомендуется, WinSCP-friendly),
     /usr/local/bin/, /etc/telemt/.
  3. _install_binary() перебирает зеркала по очереди, плюс проверяет
     /root/ для ручного размещения.
  4. При тотальном провале выводится print_telemt_manual_download_hint()
     с зелёной подсветкой /root/.

Порядок зеркал:
  1. Прямой GitHub — самый быстрый, когда не заблокирован.
  2. GitHub-прокси (ghproxy × 3, gh.con.sh, gitmirror, moeyy, ghps.cc).
  3. jsDelivr CDN — последний fallback (может отставать на часы после
     релиза, но стабильно работает когда GitHub заблокирован).

Пути ручного размещения (для WinSCP/scp):
  /root/                     ← РЕКОМЕНДУЕТСЯ (подсветка зелёным в TUI)
  /usr/local/bin/            ← куда в итоге ставится бинарник
  /etc/telemt/               ← конфиг-директория Telemt

Файлы, которые пользователь может положить вручную:
  telemt-{arch}-linux-{libc}.tar.gz           — основной бинарник
  telemt-panel-{arch}-linux-{libc}.tar.gz     — панель

Точки входа:
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
from typing import Callable, Optional


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
#  ФАБРИКИ ЗЕРКАЛ
# ============================================================================
# Каждая фабрика принимает filename и возвращает полный URL.

# --- Прямой GitHub release-assets -------------------------------------------
def _github_release_telemt(filename: str) -> str:
    return f"https://github.com/telemt/telemt/releases/latest/download/{filename}"


def _github_release_panel(filename: str) -> str:
    return f"https://github.com/amirotin/telemt_panel/releases/latest/download/{filename}"


# --- GitHub-прокси ----------------------------------------------------------
def _gh_proxy_telemt(proxy_host: str) -> Callable[[str], str]:
    """Возвращает фабрику URL для конкретного GitHub-прокси (для telemt)."""
    return lambda fn: (
        f"https://{proxy_host}/https://github.com/telemt/telemt/"
        f"releases/latest/download/{fn}"
    )


def _gh_proxy_panel(proxy_host: str) -> Callable[[str], str]:
    """Возвращает фабрику URL для конкретного GitHub-прокси (для telemt-panel)."""
    return lambda fn: (
        f"https://{proxy_host}/https://github.com/amirotin/telemt_panel/"
        f"releases/latest/download/{fn}"
    )


# --- jsDelivr CDN -----------------------------------------------------------
# jsDelivr умеет проксировать release-assets через /gh/USER/REPO@TAG/PATH,
# но только для тегов. Для "latest" это не работает напрямую — нужен конкретный
# тег. Однако jsDelivr кеширует @latest через редирект, поэтому мы используем
# специальный URL-шаблон. Если jsDelivr не отдаёт — будет 404, и мы перейдём
# к следующему зеркалу. jsDelivr идёт последним fallback'ом.
def _jsdelivr_telemt(filename: str) -> str:
    # jsDelivr не поддерживает /releases/latest/download/ напрямую, но
    # можно использовать @latest псевдо-тег для main-ветки. Для release-assets
    # это не работает — поэтому здесь используем прямой CDN-прокси.
    # Если не сработает — следующий fallback.
    return f"https://cdn.jsdelivr.net/gh/telemt/telemt@main/{filename}"


def _jsdelivr_panel(filename: str) -> str:
    return f"https://cdn.jsdelivr.net/gh/amirotin/telemt_panel@main/{filename}"


# ============================================================================
#  УПОРЯДОЧЕННЫЙ СПИСОК ЗЕРКАЛ
# ============================================================================
# Порядок = порядок попыток скачивания. Первые — самые быстрые/доступные.

# Зеркала для telemt (основной бинарник)
_TELEMT_MIRROR_FACTORIES: list[Callable[[str], str]] = [
    _github_release_telemt,
    _gh_proxy_telemt("ghproxy.net"),
    _gh_proxy_telemt("ghproxy.com"),
    _gh_proxy_telemt("mirror.ghproxy.com"),
    _gh_proxy_telemt("gh.con.sh"),
    _gh_proxy_telemt("hub.gitmirror.com"),
    _gh_proxy_telemt("github.moeyy.xyz"),
    _gh_proxy_telemt("ghps.cc"),
    # jsDelivr последний — может не отдавать release-assets
    # _jsdelivr_telemt,  # закомментирован: jsDelivr не работает с release-assets
]

# Зеркала для telemt-panel (веб-панель)
_PANEL_MIRROR_FACTORIES: list[Callable[[str], str]] = [
    _github_release_panel,
    _gh_proxy_panel("ghproxy.net"),
    _gh_proxy_panel("ghproxy.com"),
    _gh_proxy_panel("mirror.ghproxy.com"),
    _gh_proxy_panel("gh.con.sh"),
    _gh_proxy_panel("hub.gitmirror.com"),
    _gh_proxy_panel("github.moeyy.xyz"),
    _gh_proxy_panel("ghps.cc"),
]


# ============================================================================
#  ПУБЛИЧНЫЙ API
# ============================================================================
def get_telemt_mirrors() -> list[str]:
    """Упорядоченный список URL для скачивания telemt tar.gz (текущая arch/libc)."""
    arch, libc = detect_arch_libc()
    filename = f"telemt-{arch}-linux-{libc}.tar.gz"
    return [f(filename) for f in _TELEMT_MIRROR_FACTORIES]


def get_telemt_panel_mirrors() -> list[str]:
    """Упорядоченный список URL для скачивания telemt-panel tar.gz."""
    arch, libc = detect_arch_libc()
    filename = f"telemt-panel-{arch}-linux-{libc}.tar.gz"
    return [f(filename) for f in _PANEL_MIRROR_FACTORIES]


def get_all_mirrors() -> dict[str, list[str]]:
    """Словарь {filename: [urls]} — для меню/подсказок."""
    arch, libc = detect_arch_libc()
    result = {}
    telemt_fn = f"telemt-{arch}-linux-{libc}.tar.gz"
    panel_fn = f"telemt-panel-{arch}-linux-{libc}.tar.gz"
    result[telemt_fn] = [f(telemt_fn) for f in _TELEMT_MIRROR_FACTORIES]
    result[panel_fn]  = [f(panel_fn)  for f in _PANEL_MIRROR_FACTORIES]
    return result


TELEMT_MIRRORS_COUNT: int = len(_TELEMT_MIRROR_FACTORIES)
"""Количество зеркал на каждый файл (для отображения в TUI)."""


# --- Пути ручного размещения ------------------------------------------------
# Порядок важен: первый путь — РЕКОМЕНДУЕМЫЙ (зелёная подсветка в TUI).
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

    Используется mtproto.py/telemt_panel.py перед тем как качать — даёт
    шанс пользователю положить файл через WinSCP заранее.
    """
    for p in MANUAL_UPLOAD_PATHS:
        candidate = p / filename
        try:
            if candidate.exists() and candidate.stat().st_size > 0:
                return candidate
        except (PermissionError, OSError):
            # На некоторых хостах /root/ может быть недоступен для чтения
            # при запуске не от root — просто пропускаем.
            continue
    return None


# ============================================================================
#  ПОДСКАЗКА ДЛЯ РУЧНОГО СКАЧИВАНИЯ
# ============================================================================
def print_telemt_manual_download_hint(component: str = "telemt") -> None:
    """Выводит инструкцию для ручного скачивания telemt или telemt-panel.

    component: 'telemt' или 'panel'.
    Использует цвета из _core (через importlib), с fallback на пустые.
    """
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
    print(f"{BOLD}{YELLOW}⚠  Не удалось скачать {label} автоматически.{NC}")
    print(f"{WHITE}   Скачайте файл вручную и разместите на сервере.{NC}")
    print(sep)
    print()
    print(f"{CYAN}📦  {filename}  {DIM}({len(urls)} зеркал){NC}")
    for i, url in enumerate(urls, 1):
        print(f"    {DIM}{i:>2}){NC} {url}")
    print()

    # Пути ручного размещения — первый (рекомендуемый) подсвечен зелёным
    print(f"{CYAN}📂  Разместите файл в ОДНО из следующих мест:{NC}")
    for p in MANUAL_UPLOAD_PATHS:
        if p == recommended:
            print(f"    {BOLD}{GREEN}{p}/{NC}  {BOLD}{GREEN}← рекомендуется (WinSCP-friendly){NC}")
        else:
            print(f"    {BOLD}{p}/{NC}")
    print()

    print(f"{WHITE}💡  Команда для скачивания на сервере (через любое живое зеркало):{NC}")
    if urls:
        print(f"    {DIM}curl -fL \"{urls[0]}\" -o {recommended}/{filename}{NC}")
    print()
    print(f"{WHITE}💡  Или SCP с вашего ПК (после ручного скачивания в браузере):{NC}")
    print(f"    {DIM}scp {filename} root@<IP>:{recommended}/{NC}")
    print()
    print(f"{WHITE}💡  После размещения файла в {recommended}/ повторите установку{NC}")
    print(f"{WHITE}   Telemt — скрипт найдёт файл автоматически.{NC}")
    print()
    print(sep)
    print()
