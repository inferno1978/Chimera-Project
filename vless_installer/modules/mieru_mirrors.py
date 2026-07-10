"""
vless_installer/modules/mieru_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания бинарников mita/mieru
из проекта enfein/mieru (он же Telemt в пользовательском сленге).

ПРОБЛЕМА (почему отвалился Telemt у двоих пользователей):
  До этого патча mieru.py качал .deb/.rpm/.tar.gz через ОДИН прямой URL
  https://github.com/enfein/mieru/releases/download/v{version}/...
  БЕЗ зеркал, БЕЗ fallback, БЕЗ проверки ручного размещения.

  Если github.com заблокирован (что часто бывает в РФ), urllib.request.
  urlretrieve() выбрасывает исключение, вся установка Telemt падает.

  Дополнительно: proto_get_latest_version() шёл в api.github.com —
  если тот заблокирован, версия = "unknown", fallback на 3.33.0,
  и пользователь не получает актуальный бинарник.

РЕШЕНИЕ (по аналогии с geo_mirrors.py):
  1. Реестр зеркал: прямой GitHub + 7 GitHub-прокси + jsDelivr CDN
     (jsDelivr умеет проксировать release-assets через /gh/…@tag/).
  2. MANUAL_UPLOAD_PATHS: /root/ (рекомендуется, WinSCP-friendly),
     /usr/local/bin/, /opt/mieru/.
  3. _install_mita_package() и _download_binary() перебирают зеркала
     по очереди, плюс проверяют /root/ для ручного размещения.
  4. При тотальном провале выводится _print_mieru_manual_download_hint()
     с зелёной подсветкой /root/.

Порядок зеркал (важен):
  1. Прямой GitHub — самый быстрый, когда не заблокирован.
  2. GitHub-прокси (ghproxy × 3, gh.con.sh, gitmirror, moeyy, ghps.cc) —
     китайские/комьюнити-прокси, медленно но работают.
  3. jsDelivr CDN — умеет проксировать release-assets (с задержкой
     несколько часов после релиза, но стабильно).

Пути ручного размещения (для WinSCP/scp):
  /root/                     ← РЕКОМЕНДУЕТСЯ (подсветка зелёным в TUI)
                                WinSCP-friendly: быстро зайти, бросить,
                                выйти. Скрипт найдёт файл автоматически.
  /usr/local/bin/            ← Системная директория для бинарников.
  /opt/mieru/                ← Альтернативная директория.

Файлы, которые пользователь может положить вручную:
  mita_<version>_<arch>.deb       — Debian/Ubuntu пакет
  mita-<version>-1.<arch>.rpm     — RPM пакет
  mita_<version>_linux_<arch>.tar.gz  — tar.gz архив
  mieru_<version>_linux_<arch>.tar.gz — клиентский tar.gz (опционально)

Точки входа:
    from vless_installer.modules.mieru_mirrors import (
        get_mita_mirrors, get_mieru_mirrors,
        get_deb_mirrors, get_rpm_mirrors,
        MANUAL_UPLOAD_PATHS, MIERU_LOOKUP_DIRS,
        MIERU_MIRRORS_COUNT, recommended_manual_path,
        print_mieru_manual_download_hint,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable


# ============================================================================
#  ФАБРИКИ ЗЕРКАЛ
# ============================================================================
# Каждая фабрика принимает (version, filename) и возвращает полный URL.
# Это позволяет единообразно работать с зеркалами, у которых разные URL-шаблоны.

# --- Прямой GitHub release-assets -------------------------------------------
def _github_release(version: str, filename: str) -> str:
    return f"https://github.com/enfein/mieru/releases/download/v{version}/{filename}"


# --- GitHub-прокси (проксируют release-assets) ------------------------------
def _gh_proxy(proxy_host: str) -> Callable[[str, str], str]:
    """Возвращает фабрику URL для конкретного GitHub-прокси."""
    return lambda ver, fn: (
        f"https://{proxy_host}/https://github.com/enfein/mieru/"
        f"releases/download/v{ver}/{fn}"
    )


# --- jsDelivr CDN -----------------------------------------------------------
# jsDelivr умеет проксировать release-assets через /gh/USER/REPO@TAG/PATH,
# НО только для тегов, не для "latest". Поэтому мы строим URL с конкретным
# тегом v{version}. Иногда jsDelivr кеширует с задержкой несколько часов
# после релиза, поэтому jsDelivr идёт последним fallback'ом.
def _jsdelivr(version: str, filename: str) -> str:
    return (
        f"https://cdn.jsdelivr.net/gh/enfein/mieru@v{version}/{filename}"
    )


# ============================================================================
#  УПОРЯДОЧЕННЫЙ СПИСОК ЗЕРКАЛ
# ============================================================================
# Порядок = порядок попыток скачивания. Первые — самые быстрые/доступные.
_MIRROR_FACTORIES: list[Callable[[str, str], str]] = [
    # 1) Прямой GitHub — самый быстрый, когда не заблокирован
    _github_release,

    # 2) GitHub-прокси (китайские + комьюнити)
    _gh_proxy("ghproxy.net"),
    _gh_proxy("ghproxy.com"),
    _gh_proxy("mirror.ghproxy.com"),
    _gh_proxy("gh.con.sh"),
    _gh_proxy("hub.gitmirror.com"),
    _gh_proxy("github.moeyy.xyz"),
    _gh_proxy("ghps.cc"),

    # 3) jsDelivr CDN — последний fallback (может отставать на часы)
    _jsdelivr,
]


# ============================================================================
#  ПУБЛИЧНЫЙ API
# ============================================================================
def get_mita_mirrors(version: str) -> list[str]:
    """Упорядоченный список URL для скачивания mita tar.gz."""
    arch = "amd64" if _is_amd64() else "arm64"
    filename = f"mita_{version}_linux_{arch}.tar.gz"
    return [f(version, filename) for f in _MIRROR_FACTORIES]


def get_mieru_mirrors(version: str) -> list[str]:
    """Упорядоченный список URL для скачивания mieru tar.gz (клиент)."""
    arch = "amd64" if _is_amd64() else "arm64"
    filename = f"mieru_{version}_linux_{arch}.tar.gz"
    return [f(version, filename) for f in _MIRROR_FACTORIES]


def get_deb_mirrors(version: str) -> list[str]:
    """Упорядоченный список URL для скачивания mita .deb пакета."""
    arch = "amd64" if _is_amd64() else "arm64"
    filename = f"mita_{version}_{arch}.deb"
    return [f(version, filename) for f in _MIRROR_FACTORIES]


def get_rpm_mirrors(version: str) -> list[str]:
    """Упорядоченный список URL для скачивания mita .rpm пакета."""
    rpm_arch = "x86_64" if _is_amd64() else "aarch64"
    filename = f"mita-{version}-1.{rpm_arch}.rpm"
    return [f(version, filename) for f in _MIRROR_FACTORIES]


def get_all_mirrors(version: str) -> dict[str, list[str]]:
    """Словарь {filename: [urls]} — для меню/подсказок.

    Возвращает зеркала для ВСЕХ файлов данной версии: mita .deb/.rpm/.tar.gz
    и mieru .tar.gz.
    """
    result = {}
    arch = "amd64" if _is_amd64() else "arm64"
    rpm_arch = "x86_64" if _is_amd64() else "aarch64"
    for filename in (
        f"mita_{version}_{arch}.deb",
        f"mita-{version}-1.{rpm_arch}.rpm",
        f"mita_{version}_linux_{arch}.tar.gz",
        f"mieru_{version}_linux_{arch}.tar.gz",
    ):
        result[filename] = [f(version, filename) for f in _MIRROR_FACTORIES]
    return result


MIERU_MIRRORS_COUNT: int = len(_MIRROR_FACTORIES)
"""Количество зеркал на каждый файл (для отображения в TUI)."""


# --- Пути ручного размещения ------------------------------------------------
# Порядок важен: первый путь — РЕКОМЕНДУЕМЫЙ (зелёная подсветка в TUI).
# /root/ — WinSCP-friendly: пользователь быстро заходит, бросает файл,
# выходит. Скрипт найдёт его автоматически при следующей попытке.
MANUAL_UPLOAD_PATHS: list[Path] = [
    Path("/root"),                       # ← РЕКОМЕНДУЕТСЯ (зелёным в TUI)
    Path("/usr/local/bin"),              # системная директория бинарников
    Path("/opt/mieru"),                  # альтернативная директория
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения (первый в списке)."""
    return MANUAL_UPLOAD_PATHS[0]


# --- Директории где mieru.py ищет бинарник mita в рантайме ------------------
MIERU_LOOKUP_DIRS: list[Path] = [
    Path("/usr/local/bin"),
    Path("/usr/bin"),
    Path("/opt/mieru"),
]


# ============================================================================
#  ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================================
def _is_amd64() -> bool:
    """Определяет архитектуру (вынесено сюда чтобы избежать циклического импорта
    с mieru.py, где _is_amd64() тоже определена)."""
    import platform
    machine = platform.machine().lower()
    return machine in ("x86_64", "amd64")


def find_manual_upload(filename: str) -> Path | None:
    """Ищет файл `filename` в MANUAL_UPLOAD_PATHS.
    Возвращает путь если найден, иначе None.

    Используется mieru.py перед тем как качать — даёт шанс пользователю
    положить файл через WinSCP заранее.
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
def print_mieru_manual_download_hint(version: str) -> None:
    """Выводит инструкцию для ручного скачивания mita/mieru.

    Аналог _geo_print_manual_download_hint() из xray_install.py.
    Использует цвета из _core (через importlib).
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
        # Fallback без цветов
        YELLOW = NC = BOLD = WHITE = CYAN = GREEN = DIM = ""

    arch = "amd64" if _is_amd64() else "arm64"
    rpm_arch = "x86_64" if _is_amd64() else "aarch64"

    all_mirrors = get_all_mirrors(version)
    recommended = recommended_manual_path()

    sep = f"{YELLOW}{'─' * 64}{NC}"
    print()
    print(sep)
    print(f"{BOLD}{YELLOW}⚠  Не удалось скачать mita/mieru автоматически.{NC}")
    print(f"{WHITE}   Скачайте файл вручную и разместите на сервере.{NC}")
    print(sep)
    print()
    print(f"{CYAN}📦  Файлы для версии {version} (архитектура {arch}):{NC}")
    print()

    # Показываем ссылки только для mita deb/rpm/tar.gz (mieru.tar.gz — опционально)
    primary_files = [
        f"mita_{version}_{arch}.deb",
        f"mita-{version}-1.{rpm_arch}.rpm",
        f"mita_{version}_linux_{arch}.tar.gz",
    ]
    for filename in primary_files:
        urls = all_mirrors.get(filename, [])
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
    first_deb_url = all_mirrors[f"mita_{version}_{arch}.deb"][0]
    print(f"    {DIM}curl -fL \"{first_deb_url}\" -o {recommended}/mita_{version}_{arch}.deb{NC}")
    print()
    print(f"{WHITE}💡  Или SCP с вашего ПК (после ручного скачивания в браузере):{NC}")
    print(f"    {DIM}scp mita_{version}_{arch}.deb root@<IP>:{recommended}/{NC}")
    print()
    print(f"{WHITE}💡  После размещения файла в {recommended}/ повторите установку{NC}")
    print(f"{WHITE}   Telemt — скрипт найдёт файл автоматически.{NC}")
    print()
    print(sep)
    print()
