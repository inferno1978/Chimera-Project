"""
chimera/modules/snell_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Mirror URL registry для Snell v4 (Surge / nssurge.com).

Snell — закрытый бинарник от команды Surge (nssurge.com), распространяется
как готовый zip-архив по прямой ссылке dl.nssurge.com. Лицензионных проблем
с самим бинарником нет (как с Hysteria2/Xray — мы просто скачиваем и
оборачиваем официальный релиз). Python-обвязка написана с нуля.

Архитектура зеркал (fallback в этом порядке):
  1. Официальный источник: https://dl.nssurge.com/snell/snell-server-v<ver>-linux-<arch>.zip
  2. GitHub-репак: passeway/Snell releases (проверенный community-репозиторий
     с бинарниками, совместимыми с протоколом v4)
  3. jsDelivr CDN — кэш GitHub releases (4 хоста: cdn/fastly/gcore/testingcf)
  4. GitHub proxy hosts (ghproxy.net, ghproxy.com, mirror.ghproxy.com и т.д.)
     — нужны для РФ, где прямой raw.githubusercontent.com часто заблокирован
  5. Ручная загрузка — fallback-опция если все автоматические источники
     недоступны. Админ сам скачивает zip через VPN и кладёт в /root/.

Паттерн — повторяет naiveproxy_mirrors.py (минимальный) с расширением:
добавлены прямой официальный URL и GitHub-репак, чтобы покрыть случай когда
github.com заблокирован, но dl.nssurge.com доступен (или наоборот).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from chimera.modules.github_mirrors import build_mirror_urls

# ─── Официальный источник (закрытый бинарник Surge) ─────────────────────────
# Прямая ссылка, стабильно работает даже когда github.com заблокирован.
# Формат: https://dl.nssurge.com/snell/snell-server-v<ver>-linux-<arch>.zip
SNELL_OFFICIAL_BASE = "https://dl.nssurge.com/snell"

# ─── GitHub-репак (community-зеркало) ───────────────────────────────────────
# passeway/Snell содержит бинарные релизы snell-server по тем же тегам
# версий, что и официальный источник. Используется когда официальный сайт
# недоступен (блокировка, DDOS, и т.д.), но GitHub доступен.
SNELL_GH_OWNER = "passeway"
SNELL_GH_REPO  = "Snell"

# ─── Поддерживаемые архитектуры ─────────────────────────────────────────────
# Соответствие platform.machine() → arch-суффикс в имени файла.
SNELL_ARCH_MAP = {
    "x86_64":  "amd64",
    "amd64":   "amd64",
    "i386":    "i386",
    "i686":    "i386",
    "aarch64": "aarch64",
    "arm64":   "aarch64",
    "armv7l":  "armv7l",
    "armv6l":  "armv7l",   # armv6 не выпускается — fallback на armv7l
}

# Версия по умолчанию. Surge обновляет нечасто (раз в несколько месяцев).
# Константа нужна для случаев когда GitHub API недоступен и получить
# "latest" через api.github.com/repos/.../releases/latest невозможно.
SNELL_DEFAULT_VERSION = "4.1.1"

# ─── Manual upload paths ────────────────────────────────────────────────────
# Проверяются по порядку при поиске zip-файла, загруженного админом вручную.
# В TUI-меню первый путь подсвечивается зелёным как «рекомендуемый».
MANUAL_UPLOAD_PATHS: list[Path] = [
    Path("/root"),
    Path("/tmp"),
    Path("/opt/chimera"),
]

# Локации, где модуль ищет уже установленный бинарник (для определения
# установленной версии через _get_installed_version).
SNELL_LOOKUP_DIRS: list[Path] = [
    Path("/usr/local/bin"),
    Path("/usr/bin"),
    Path("/opt/chimera"),
]


def _arch_suffix(arch: Optional[str] = None) -> str:
    """Возвращает суффикс архитектуры для имени файла.

    Raises ValueError если архитектура не поддерживается Snell.
    """
    import platform as _plat
    machine = (arch or _plat.machine()).lower()
    if machine not in SNELL_ARCH_MAP:
        raise ValueError(
            f"Неподдерживаемая архитектура: {machine!r}. "
            f"Snell поддерживает: {sorted(set(SNELL_ARCH_MAP.values()))}"
        )
    return SNELL_ARCH_MAP[machine]


def _snell_filename(version: str = SNELL_DEFAULT_VERSION,
                    arch: Optional[str] = None) -> str:
    """Имя zip-архива официального релиза Snell.

    Формат: snell-server-v4.1.1-linux-amd64.zip
    """
    arch_s = _arch_suffix(arch)
    # Surge использует 'v' префикс в имени файла: snell-server-v4.1.1-...
    # Версия может передаваться с или без 'v' — нормализуем.
    ver = version.lstrip("v")
    return f"snell-server-v{ver}-linux-{arch_s}.zip"


def _official_url(version: str = SNELL_DEFAULT_VERSION,
                  arch: Optional[str] = None) -> str:
    """Прямой URL на dl.nssurge.com — основной источник."""
    return f"{SNELL_OFFICIAL_BASE}/{_snell_filename(version, arch)}"


def _github_mirror_urls(version: str = SNELL_DEFAULT_VERSION,
                        arch: Optional[str] = None) -> list[str]:
    """URL-ы через GitHub-репак passeway/Snell + jsDelivr CDN + gh-proxy hosts.

    Делегирует в github_mirrors.build_mirror_urls — это даёт 12-14 URL-ов:
    jsDelivr (4 хоста) + raw.githubusercontent + releases + gh-proxy (7 хостов)
    + statically. Этого достаточно для любого сценария блокировок.
    """
    filename = _snell_filename(version, arch)
    ver = version.lstrip("v")
    tag = f"v{ver}"
    return build_mirror_urls(
        owner=SNELL_GH_OWNER,
        repo=SNELL_GH_REPO,
        filename=filename,
        tag=tag,
    )


def get_snell_mirrors(version: str = SNELL_DEFAULT_VERSION,
                      arch: Optional[str] = None) -> list[str]:
    """Возвращает упорядоченный список URL-ов для скачивания Snell.

    Порядок (важен для fallback):
      1. Официальный dl.nssurge.com (если доступен — самый быстрый путь)
      2-15. GitHub-репак passeway/Snell через все зеркала build_mirror_urls:
            jsDelivr (4) + raw.githubusercontent + releases
            + gh-proxy hosts (7) + statically
    """
    urls: list[str] = []
    # 1. Официальный источник — всегда первый.
    urls.append(_official_url(version, arch))
    # 2-N. GitHub-репак со всеми зеркалами.
    urls.extend(_github_mirror_urls(version, arch))
    # Дедупликация (на случай если официальный URL совпал с каким-то GitHub
    # зеркалом — теоретически невозможно, но безопасно).
    seen: set[str] = set()
    unique: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique.append(u)
    return unique


# Количество зеркал — используется в TUI для отображения "доступно N зеркал".
SNELL_MIRRORS_COUNT: int = len(get_snell_mirrors())


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручной загрузки zip-файла."""
    return MANUAL_UPLOAD_PATHS[0]


def find_manual_upload(filename: str) -> Optional[Path]:
    """Ищет уже загруженный zip в MANUAL_UPLOAD_PATHS.

    Возвращает Path если найден, иначе None. Молча пропускает пути
    без прав на чтение (PermissionError/OSError) — это нормально,
    админ мог запустить TUI от не-root.
    """
    for d in MANUAL_UPLOAD_PATHS:
        try:
            candidate = d / filename
            if candidate.exists() and candidate.is_file():
                # Минимальная sanity-проверка: zip должен быть > 1KB
                # (реально ~3-5MB, но 1KB отсекает пустые/placeholder-файлы).
                if candidate.stat().st_size >= 1024:
                    return candidate
        except (PermissionError, OSError):
            continue
    return None


def print_snell_manual_download_hint(version: str = SNELL_DEFAULT_VERSION,
                                     arch: Optional[str] = None) -> None:
    """Печатает цветной бокс со всеми зеркалами и инструкцией для ручной загрузки.

    Используется из snell.py когда все автоматические попытки скачивания
    провалились. Подсказывает админу: скачайте zip через VPN с одного из
    перечисленных URL и положите в /root/.
    """
    # Lazy import colors из _core — для консистентности с остальными модулями.
    try:
        import importlib
        core = importlib.import_module("chimera._core")
        GREEN = core.GREEN; YELLOW = core.YELLOW; CYAN = core.CYAN
        RED = core.RED; BOLD = core.BOLD; DIM = core.DIM; NC = core.NC
    except Exception:
        GREEN = YELLOW = CYAN = RED = BOLD = DIM = NC = ""

    filename = _snell_filename(version, arch)
    mirrors = get_snell_mirrors(version, arch)
    rec = recommended_manual_path()

    print()
    print(f"{RED}┌─ Не удалось скачать {filename} автоматически.{NC}")
    print(f"{RED}│  Попробуйте ручную загрузку:{NC}")
    print(f"{RED}│{NC}")
    for i, url in enumerate(mirrors[:5], 1):
        print(f"{RED}│{NC}  {DIM}{i}.{NC} {CYAN}{url}{NC}")
    if len(mirrors) > 5:
        print(f"{RED}│{NC}  {DIM}... и ещё {len(mirrors)-5} зеркал{NC}")
    print(f"{RED}│{NC}")
    print(f"{RED}│{NC}  {BOLD}Положите файл сюда:{NC}")
    print(f"{RED}│{NC}  {GREEN}{rec / filename}{NC}")
    print(f"{RED}└─────────────────────────────────────────────────{NC}")
    print()
