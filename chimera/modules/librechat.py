"""
chimera/modules/librechat.py
───────────────────────────────────────────────────────────────────────────────
LibreChat — AI-чат панель (LibreChat-AI/LibreChat) в архитектуре Chimera.

КОНЦЕПЦИЯ (по образцу модуля B4 / youtube_b4.py):
  Полный жизненный цикл стороннего продукта из TUI Chimera: зашёл в
  меню — тыкнул кнопку — поставилось. Тыкнул кнопку — удалилось.
  Docker compose стек LibreChat (api + mongodb + meilisearch, опционально
  RAG pgvector и admin-panel) управляется как единый systemd-сервис.

АРХИТЕКТУРА:
  • СТЕК: официальный compose-файл апстрима (тег версии, качается через
    download_manager с лестницей зеркал) + детерминированные патчи
    Chimera: пин релизного образа librechat/librechat:<tag> (Docker Hub),
    привязка портов только на 127.0.0.1 (SSH-туннель по умолчанию),
    profiles для тяжёлых сервисов (rag / admin — ставятся опционально).
  • SECRETS: .env генерируется с JWT_SECRET / CREDS_KEY / CREDS_IV /
    MEILI_MASTER_KEY — секреты создаются ОДИН раз и переживают все
    обновления (смена CREDS_* = потеря зашифрованных ключей юзеров).
  • SYSTEMD: librechat.service (Type=oneshot RemainAfterExit) —
    ExecStart=docker compose up -d, ExecStop=docker compose down.
    Профили активных сервисов вшиты в юнит (перегенерация при toggle).
  • ПОРТЫ: port_registry (конфликт-чек + регистрация). Порт панели
    выбирает юзер (дефолт 3080), привязка loopback-only.
  • ДОСТУП (эталон b4): SSH-туннель (по умолчанию) ИЛИ nginx front с
    TLS через panel_nginx_front (self-signed по IP / Let's Encrypt по
    домену, long_timeouts для LLM-стримов SSE). При toggle nginx
    патчится DOMAIN_CLIENT/DOMAIN_SERVER в .env (OAuth/cookies).
  • ВЕРСИИ (паттерн dpi_bypass/B4): GitHub API releases/latest +
    releases (pre-release), TTL-кэш 6ч/30мин в state, header row в
    шапке меню. Обновление = новый тег → скачали compose → патч →
    docker compose pull → up -d → health-смоук с откатом при провале.

ИНТЕГРАЦИЯ С CHIMERA:
  • download_manager — скачивание docker-compose.yml апстрима
    (зеркала raw.githubusercontent / jsDelivr / gh-прокси + ручное
    размещение в /root как у всех пакетов).
  • port_registry — SERVICE_LIBRECHAT_WEB (порт панели) и
    SERVICE_LIBRECHAT_NGINX (nginx front). Конфликт-чек на установке
    и смене порта, снятие регистрации при удалении.
  • panel_nginx_front — TLS-фронт: Let's Encrypt домен или self-signed
    IP, ACME-challenge, HSTS, ufw-открытие порта.
  • systemd — юнит librechat.service, is-active/is-enabled как у b4.
  • Docker Engine — авто-установка при отсутствии: apt (docker.io +
    docker-compose-v2) → официальный get.docker.com как fallback.

ТОЧКА ВХОДА ИЗ TUI: Раздел 1 → W → 9 (do_librechat_menu), рядом с
Triple Panel и WPP Web Panel (меню «Веб-панель управления»).

ПОЛНАЯ АВТОНОМНОСТЬ: модуль не требует изменений в _core.py, ядро
резолвится лениво через _core_module() (паттерн warp.py).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

# ── Прямой запуск (python3 .../librechat.py) — bootstrap корня проекта ───────
if __package__ in (None, ""):
    _ROOT = Path(__file__).resolve().parent.parent.parent
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))

# ── Цвета (канон проекта: youtube_b4.py / naiveproxy.py) ────────────────────
def _detect_colors() -> dict:
    if os.environ.get("NO_COLOR"):
        return {k: "" for k in ("RED", "GREEN", "YELLOW", "CYAN",
                                "BOLD", "DIM", "WHITE", "NC")}
    if not sys.stdout.isatty() and os.environ.get("FORCE_COLOR") is None:
        return {k: "" for k in ("RED", "GREEN", "YELLOW", "CYAN",
                                "BOLD", "DIM", "WHITE", "NC")}
    return dict(
        RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
        CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m',
        WHITE='\033[1;37m', NC='\033[0m',
    )

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, WHITE, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'],
    _C['BOLD'], _C['DIM'], _C['WHITE'], _C['NC'],
)

# ── Логирование (единый формат с остальными модулями) ────────────────────────
_LOG_FILE = Path("/var/log/chimera.log")

def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        with _LOG_FILE.open("a") as f:
            f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [librechat] [{level}] {clean}\n")
    except Exception:
        pass

def _info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");  _log("INFO", msg)
def _ok(msg: str)      -> None: print(f"{GREEN}[OK]{NC}    {msg}"); _log("OK", msg)
def _warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)
def _err(msg: str)     -> None: print(f"{RED}[ERR]{NC}   {msg}");   _log("ERR", msg)

# ── box_renderer (UI меню, общий для всех модулей) ───────────────────────────
from chimera.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_item_exit,
    _box_back, _box_info, _box_warn, _box_ok, _box_link, _box_desc, _box_kv,
)

# ── Делегирование в _core.py ─────────────────────────────────────────────────
def _core_module():
    import importlib
    return importlib.import_module("chimera._core")

# ════════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ
# ════════════════════════════════════════════════════════════════════════════

# Апстрим: github.com/LibreChat-AI/LibreChat (MIT-лицензия).
LC_UPSTREAM_REPO     = "LibreChat-AI/LibreChat"
LC_UPSTREAM_API_LATEST = f"https://api.github.com/repos/{LC_UPSTREAM_REPO}/releases/latest"
LC_UPSTREAM_API_ALL    = f"https://api.github.com/repos/{LC_UPSTREAM_REPO}/releases"

# Версия, которую ставим по умолчанию (пин релизного тега апстрима).
LC_VERSION = "v0.8.8"

# Каталог установки: compose + .env + bind-монты (images/uploads/logs/
# data-node/meili_data — как в апстримном compose).
LC_INSTALL_DIR   = Path("/opt/librechat")
LC_COMPOSE_FILE  = LC_INSTALL_DIR / "docker-compose.yml"
LC_ENV_FILE      = LC_INSTALL_DIR / ".env"
LC_DATA_DIRS     = ("images", "uploads", "logs", "data-node", "meili_data_v1.35.1")
LC_DATA_UID      = 1000   # UID/GID контейнеров (upstream: user: "${UID}:${GID}")
LC_DATA_GID      = 1000

# systemd.
LC_SERVICE      = "librechat"
LC_UNIT_PATH    = Path(f"/etc/systemd/system/{LC_SERVICE}.service")

# Релизный образ апстрима (Docker Hub, официальные теги версий).
LC_IMAGE_REPO   = "librechat/librechat"

# State.
_STATE_DIR      = Path("/var/lib/xray-installer")
_STATE_FILE     = _STATE_DIR / "librechat_state.json"

# Порты: панель (дефолт 3080 = PORT апстрима; loopback-only) и nginx front
# (9763 — не конфликтует: 9443 portal, 9444 sub, 9700 b4, 9701 wpp,
# 9743 b4-nginx, 9760/9761 triple).
DEFAULT_LC_PORT       = 3080
DEFAULT_LC_ADMIN_PORT = 3100   # admin-panel (profile admin), host-side
DEFAULT_LC_NGINX_PORT = 9763

# nginx front (по эталону b4/triple: панель в loopback, наружу — nginx+TLS).
LC_NGINX_SITE_NAME  = "chimera-librechat-nginx"
LC_NGINX_STATE_FILE = _STATE_DIR / "librechat_nginx.json"

# TTL-кэш latest-версий (идиома upstream_updates / youtube_b4):
#   успешная проверка → повтор не раньше 6 ч; неудачная → через 30 мин,
#   прежние значения не затираются (показываем последние известные).
LC_LATEST_CACHE_TTL  = 6 * 3600
LC_LATEST_RETRY_TTL  = 30 * 60
LC_LATEST_TIMEOUT    = 6

# Health-check: GET /api/status (возвращает JSON с версией апстрима).
LC_HEALTH_TIMEOUT    = 5
LC_HEALTH_WAIT_SEC   = 180     # первый старт: миграции mongo + подъем api
LC_HEALTH_INTERVAL   = 3

# Ресурсные пре-чеки (LibreChat стек: api ~700M + mongo ~300M + meili ~300M).
LC_MIN_RAM_MB        = 1536
LC_MIN_DISK_MB       = 6144    # образы: api ~1GB + mongo + meili

# Профили compose (тяжёлые опциональные сервисы).
LC_PROFILES = ("rag", "admin")


class ComposePatchError(Exception):
    """Патч апстримного docker-compose.yml не применился (структура изменилась)."""


# ════════════════════════════════════════════════════════════════════════════
#  STATE
# ════════════════════════════════════════════════════════════════════════════

def _load_state() -> dict:
    defaults = {
        "installed": False,
        "version": "",
        "port": DEFAULT_LC_PORT,
        "admin_port": DEFAULT_LC_ADMIN_PORT,
        "enabled": False,
        "profiles": [],
        "docker_by_chimera": False,
        "installed_at": "",
    }
    if not _STATE_FILE.exists():
        return defaults
    try:
        data = json.loads(_STATE_FILE.read_text())
        if not isinstance(data, dict):
            return defaults
        defaults.update(data)
        return defaults
    except Exception as e:
        _warn(f"librechat_state.json повреждён: {e}")
        return defaults


def _save_state(state: dict) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    _STATE_FILE.chmod(0o600)


# ════════════════════════════════════════════════════════════════════════════
#  ВЕРСИИ (паттерн youtube_b4: key / latest / кэш / availability / header row)
# ════════════════════════════════════════════════════════════════════════════

def _lc_version_key(version: str) -> tuple:
    """Ключ сравнения версий: 'v0.8.8' → ((0, 8, 8), 1, '').

    LibreChat тегает релизы 'vX.Y.Z', pre-release 'vX.Y.Z-rcN'.
    Свойства semver-совместимые: числа как числа, rc младше своего
    релиза (признак 0 < 1). Паттерн _b4_version_key.
    """
    v = str(version or "").strip()
    if v.startswith("v"):
        v = v[1:]
    m = re.match(r"^(\d+(?:\.\d+)*)", v)
    if not m:
        return ((), 0, v)
    nums = tuple(int(x) for x in m.group(1).split("."))
    suffix = v[m.end():]           # "-rc1", "" для чистого релиза
    is_release = 1 if not suffix else 0
    return (nums, is_release, suffix)


def _lc_strip_v(version: str) -> str:
    return str(version or "").strip().lstrip("vV")


def _detect_installed() -> bool:
    """Установлен ли LibreChat (systemd-юнит + compose-файл)."""
    return LC_UNIT_PATH.exists() and LC_COMPOSE_FILE.exists()


def _detect_service_active() -> bool:
    r = subprocess.run(["systemctl", "is-active", LC_SERVICE],
                       capture_output=True, text=True, check=False)
    return (r.returncode == 0 and r.stdout.strip() == "active")


def _detect_service_enabled() -> bool:
    r = subprocess.run(["systemctl", "is-enabled", LC_SERVICE],
                       capture_output=True, text=True, check=False)
    return (r.returncode == 0 and r.stdout.strip() == "enabled")


def _detect_latest_version(timeout: int = 10) -> str:
    """Последняя СТАБИЛЬНАЯ версия апстрима на GitHub ('' при ошибке).

    /releases/latest возвращает только релизы (prerelease=false).
    """
    try:
        req = urllib.request.Request(
            LC_UPSTREAM_API_LATEST,
            headers={"User-Agent": "chimera-installer/5.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        tag = data.get("tag_name", "")
        return tag if tag else ""
    except Exception as e:
        _log("WARN", f"check_latest_version: {e}")
        return ""


def _detect_latest_prerelease_version(timeout: int = 10) -> str:
    """Последний ПРЕ-релиз апстрима ('' если нет / GitHub недоступен).

    /releases возвращает все релизы новьё-вперёд; берём первый
    prerelease=true. Паттерн _detect_latest_prerelease_version (b4).
    """
    try:
        req = urllib.request.Request(
            LC_UPSTREAM_API_ALL,
            headers={"User-Agent": "chimera-installer/5.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        for release in data:
            if release.get("prerelease", False):
                tag = release.get("tag_name", "")
                if tag:
                    return tag
        return ""
    except Exception as e:
        _log("WARN", f"check_latest_prerelease_version: {e}")
        return ""


def _lc_latest_cache() -> dict:
    """Кэш latest-версий из state (БЕЗ сети). Поля как у b4."""
    state = _load_state()
    try:
        checked_at = float(state.get("latest_checked_at", 0) or 0)
    except (TypeError, ValueError):
        checked_at = 0.0
    return {
        "release":     str(state.get("latest_release", "") or ""),
        "prerelease":  str(state.get("latest_prerelease", "") or ""),
        "checked_at":  checked_at,
        "ok":          bool(state.get("latest_check_ok", False)),
    }


def _refresh_lc_latest_cache(force: bool = False) -> dict:
    """Обновляет кэш latest (release + pre-release) в state.

    TTL: успешная проверка 6ч (LC_LATEST_CACHE_TTL), неудачная — 30 мин
    (LC_LATEST_RETRY_TTL); при неудаче прежние значения не затираются.
    Если LibreChat не установлен — GitHub не дёргаем (обновлять нечего).
    """
    cache = _lc_latest_cache()
    ttl = LC_LATEST_CACHE_TTL if cache.get("ok") else LC_LATEST_RETRY_TTL
    checked_at = cache.get("checked_at", 0.0)
    if (not force and checked_at
            and 0 <= time.time() - checked_at < ttl):
        return cache
    if not _detect_installed():
        return cache
    release = _detect_latest_version(timeout=LC_LATEST_TIMEOUT)
    prerelease = _detect_latest_prerelease_version(timeout=LC_LATEST_TIMEOUT)
    ok = bool(release or prerelease)
    try:
        state = _load_state()
        if ok:
            state["latest_release"] = release
            state["latest_prerelease"] = prerelease
        state["latest_checked_at"] = time.time()
        state["latest_check_ok"] = ok
        _save_state(state)
        if ok:
            _log("INFO", f"librechat latest: release={release or '—'}, "
                         f"pre-release={prerelease or '—'} (кэш обновлён)")
        else:
            _log("WARN", "librechat latest: GitHub недоступен — кэш не "
                         "обновлён (повтор через 30 мин)")
    except Exception as e:
        _log("WARN", f"refresh_lc_latest_cache: {e}")
    return _lc_latest_cache()


def _lc_update_availability(installed: str = "",
                            cache: Optional[dict] = None) -> dict:
    """Сводка «есть ли что ставить» для шапки меню (БЕЗ сети)."""
    if cache is None:
        cache = _lc_latest_cache()
    rel = str(cache.get("release", "") or "")
    pre = str(cache.get("prerelease", "") or "")
    installed = str(installed or "")
    if not (rel or pre):
        return {"known": False, "release": "", "prerelease": "",
                "release_update": False, "pre_update": False,
                "up_to_date": False, "installed": installed}
    can_compare = bool(installed) and bool(_lc_version_key(installed)[0])
    rel_upd = bool(can_compare and rel
                   and _lc_version_key(installed) < _lc_version_key(rel))
    pre_upd = bool(can_compare and pre
                   and _lc_version_key(installed) < _lc_version_key(pre))
    return {"known": True, "release": rel, "prerelease": pre,
            "release_update": rel_upd, "pre_update": pre_upd,
            "up_to_date": bool(can_compare and not rel_upd and not pre_upd),
            "installed": installed}


def _lc_update_header_row(installed: str = "",
                          cache: Optional[dict] = None) -> str:
    """Строка «Обновление: …» для шапки ГЛАВНОГО меню (без сети)."""
    a = _lc_update_availability(installed, cache)
    if not a["known"]:
        return f"  Обновление:   {DIM}не проверено (GitHub недоступен) → [2]{NC}"
    parts = []
    if a["release_update"]:
        parts.append(f"release {a['release']}")
    if a["pre_update"]:
        parts.append(f"pre-release {a['prerelease']}")
    if parts:
        return (f"  Обновление:   {YELLOW}{BOLD}{' / '.join(parts)}{NC}"
                f"  {DIM}→ [2]{NC}")
    if a["up_to_date"]:
        return f"  Обновление:   {GREEN}нет — установлена актуальная версия{NC}"
    avail = " / ".join(x for x in (f"release {a['release']}"
                                   if a["release"] else "",
                                   f"pre-release {a['prerelease']}"
                                   if a["prerelease"] else "") if x)
    return f"  Обновление:   {DIM}{avail} (версия не определена){NC}"


# ════════════════════════════════════════════════════════════════════════════
#  DOCKER: наличие / установка / compose-команда
# ════════════════════════════════════════════════════════════════════════════

def _docker_bin() -> Optional[str]:
    return shutil.which("docker")


def _compose_v2_ok() -> bool:
    """docker compose (v2 plugin) доступен? (v1 profiles не умеет — не годен)"""
    docker = _docker_bin()
    if not docker:
        return False
    try:
        r = subprocess.run([docker, "compose", "version"],
                           capture_output=True, text=True, check=False,
                           timeout=15)
        return r.returncode == 0
    except Exception:
        return False


def _run_apt(*args: str) -> bool:
    """apt-get с noninteractive; True при rc=0."""
    try:
        r = subprocess.run(
            ["apt-get", *args],
            capture_output=True, text=True, check=False, timeout=1800,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
        return r.returncode == 0
    except Exception:
        return False


def _ensure_docker() -> bool:
    """Docker Engine + compose v2: проверить → apt → get.docker.com.

    Порядок (как system_deps для системных пакетов, но для docker):
      1. уже есть + compose v2 → ок;
      2. apt-get install docker.io docker-compose-v2 (Ubuntu 22+/Debian 13);
      3. официальный скрипт get.docker.com (docker-ce + compose plugin) —
         ставится и когда apt-пакета нет, и когда compose v2 не завёлся;
      4. systemctl enable --now docker.
    """
    if _compose_v2_ok():
        return True
    state = _load_state()

    # 2. apt: docker.io + docker-compose-v2.
    if shutil.which("apt-get"):
        _info("Устанавливаю Docker (apt: docker.io docker-compose-v2)...")
        _run_apt("update")
        _run_apt("install", "-y", "-q", "docker.io", "docker-compose-v2")
        if _compose_v2_ok():
            state["docker_by_chimera"] = True
            _save_state(state)
            _ok("Docker установлен через apt")
            _enable_docker_service()
            return True
        # compose v2 мог не появиться (старый дистрибутив) — попробуем
        # поставить только плагин из репо docker-ce ниже.
        if not _docker_bin():
            pass  # переходим к get.docker.com
        else:
            _warn("docker есть, но compose v2 отсутствует — доустанавливаю "
                  "через официальный скрипт")

    # 3. Официальный установщик (docker-ce + docker-compose-plugin).
    _info("Устанавливаю Docker через официальный скрипт get.docker.com...")
    curl = shutil.which("curl")
    if not curl:
        if shutil.which("apt-get"):
            _run_apt("update")
            _run_apt("install", "-y", "-q", "curl")
            curl = shutil.which("curl")
    if not curl:
        _err("curl не найден — установите Docker вручную: https://docs.docker.com/engine/install/")
        return False
    try:
        r = subprocess.run(
            ["bash", "-c", f"{curl} -fsSL https://get.docker.com | sh"],
            timeout=1800, check=False,
        )
    except Exception as e:
        _err(f"get.docker.com не отработал: {e}")
        return False
    if r.returncode != 0 or not _compose_v2_ok():
        _err("Docker не установился. Установите вручную: "
             "curl -fsSL https://get.docker.com | sh")
        return False
    state["docker_by_chimera"] = True
    _save_state(state)
    _ok("Docker установлен через get.docker.com")
    _enable_docker_service()
    return True


def _enable_docker_service() -> None:
    subprocess.run(["systemctl", "enable", "--now", "docker"],
                   capture_output=True, check=False)


def _compose_cmd(profiles: Optional[list] = None) -> list:
    """Базовая команда docker compose с project-dir и профилями."""
    docker = _docker_bin() or "docker"
    cmd = [docker, "compose",
           "--project-directory", str(LC_INSTALL_DIR),
           "-f", str(LC_COMPOSE_FILE)]
    for p in (profiles or []):
        if p in LC_PROFILES:
            cmd += ["--profile", p]
    return cmd


def _compose_run(args: list, profiles: Optional[list] = None,
                 capture: bool = False, timeout: int = 1800) -> subprocess.CompletedProcess:
    cmd = _compose_cmd(profiles) + args
    return subprocess.run(cmd, capture_output=capture, text=capture,
                          check=False, timeout=timeout)


# ════════════════════════════════════════════════════════════════════════════
#  COMPOSE-ФАЙЛ: download_manager (зеркала) + детерминированные патчи Chimera
# ════════════════════════════════════════════════════════════════════════════

def _compose_mirror_urls(filename: str) -> list:
    """Лестница зеркал для docker-compose.yml@тег.

    Тег — ИММУТАБЛЕН (git tag), содержимое детерминировано: патчи
    _patch_upstream_compose применяются к одному и тому же файлу.
    Порядок: raw GitHub → jsDelivr → gh-прокси (как в github_mirrors).
    """
    m = re.search(r"v(\d+\.\d+\.\d+(-rc\d+)?)", filename)
    tag = f"v{m.group(1)}" if m else LC_VERSION
    urls = [
        f"https://raw.githubusercontent.com/{LC_UPSTREAM_REPO}/{tag}/docker-compose.yml",
        f"https://cdn.jsdelivr.net/gh/{LC_UPSTREAM_REPO}@{tag}/docker-compose.yml",
    ]
    for host in ("ghproxy.net", "gh-proxy.com", "gh.llkk.cc"):
        urls.append(
            f"https://{host}/https://raw.githubusercontent.com/"
            f"{LC_UPSTREAM_REPO}/{tag}/docker-compose.yml")
    return urls


def _compose_spec(version: str):
    """PackageSpec для docker-compose.yml@версия (download_manager).

    manual_incoming_dir=/root: ручное размещение docker-compose.yml
    (переименуйте в librechat-compose-vX.Y.Z.yml) поддерживается как у
    всех пакетов Chimera — работает даже при полностью заблокированном
    GitHub.
    """
    from chimera.modules.download_manager import PackageSpec
    v = _lc_strip_v(version) or _lc_strip_v(LC_VERSION)
    return PackageSpec(
        name=f"LibreChat docker-compose.yml v{v}",
        filename_builder=lambda: f"librechat-compose-v{v}.yml",
        mirror_urls_builder=_compose_mirror_urls,
        install_dests=[_STATE_DIR],
        manual_incoming_dir=Path("/root"),
        min_size=2_000,   # compose ~3-4 KB; страница-заглушка меньше
    )


def _patch_upstream_compose(text: str, version: str) -> str:
    """Применяет патчи Chimera к апстримному compose (in-place, raise при дрейфе).

    Патчи (все — точные строки против пин-тега):
      1. api-образ → релизный librechat/librechat:<tag> (Docker Hub);
         апстримный compose ссылается на dev-образ dev-registry.
      2. Порт api — только loopback: '127.0.0.1:${PORT}:${PORT}'
         (SSH-туннель по умолчанию; наружу — nginx front с TLS).
      3. rag_api убран из depends_on api (RAG — опциональный profile;
         без профиля compose отказывается стартовать из-за зависит-он
         на неактивный сервис).
      4. profiles: rag → rag_api+vectordb, admin → admin-panel
         (тяжёлые сервисы ставятся только по явному выбору).
      5. Порт admin-panel — loopback + дефолт хост-стороны 3100
         (3000 занят AdGuard Home Web UI в Chimera).

    Любой неприменившийся патч = ComposePatchError: обновление/установка
    останавливается с честной ошибкой (апстрим изменил структуру —
    нужен свежий патч-сет, молчаливый fallback скрыл бы поломку).
    """
    v = _lc_strip_v(version)

    def _replace_once(haystack: str, old: str, new: str, what: str) -> str:
        if old not in haystack:
            raise ComposePatchError(
                f"патч «{what}» не применился — апстрим-структура изменилась")
        return haystack.replace(old, new, 1)

    # 1. Релизный образ api.
    text = _replace_once(
        text,
        "image: registry.librechat.ai/librechat-ai/librechat-dev:latest",
        f"image: {LC_IMAGE_REPO}:v{v}",
        "пин релизного образа api")

    # 2. Порт api — loopback-only.
    text = _replace_once(
        text,
        '      - "${PORT}:${PORT}"',
        '      - "127.0.0.1:${PORT}:${PORT}"',
        "loopback-привязка порта api")

    # 3. Убираем rag_api из depends_on api (profile-изоляция).
    text = _replace_once(
        text,
        "    depends_on:\n      - mongodb\n      - rag_api\n",
        "    depends_on:\n      - mongodb\n",
        "depends_on без rag_api")

    # 4. Профили тяжёлых сервисов.
    text = _replace_once(
        text,
        "  rag_api:\n    container_name: rag_api\n",
        '  rag_api:\n    container_name: rag_api\n    profiles: ["rag"]\n',
        "profile rag → rag_api")
    text = _replace_once(
        text,
        "  vectordb:\n    container_name: vectordb\n",
        '  vectordb:\n    container_name: vectordb\n    profiles: ["rag"]\n',
        "profile rag → vectordb")
    text = _replace_once(
        text,
        "  admin-panel:\n    container_name: admin-panel\n",
        '  admin-panel:\n    container_name: admin-panel\n'
        '    profiles: ["admin"]\n',
        "profile admin → admin-panel")

    # 5. Порт admin-panel — loopback + дефолт 3100.
    text = _replace_once(
        text,
        '      - "${ADMIN_PANEL_PORT:-3000}:3000"\n',
        '      - "127.0.0.1:${ADMIN_PANEL_PORT:-3100}:3000"\n',
        "loopback-привязка порта admin-panel")

    # Кредит лицензии (MIT © LibreChat) — требование апстрима.
    header = (
        "# Chimera LibreChat — docker-compose (upstream "
        f"github.com/{LC_UPSTREAM_REPO} @ v{v}, MIT).\n"
        "# Патчи Chimera: пин релизного образа, loopback-порты, profiles "
        "rag/admin, depends_on без rag.\n"
        "# Управление: TUI Chimera → 1 → W → 9. НЕ редактировать вручную.\n")
    if not text.startswith("# Chimera LibreChat"):
        text = header + text
    return text


def _fetch_compose(version: str, quiet: bool = False) -> bool:
    """Скачивает compose@версия через download_manager, патчит, ставит на место.

    Возвращает True при успехе (LC_COMPOSE_FILE записан).
    """
    from chimera.modules.download_manager import fetch_package
    if not quiet:
        _info(f"Скачиваю docker-compose.yml апстрима v{_lc_strip_v(version)}...")
    spec = _compose_spec(version)
    if not fetch_package(spec, progress_label="librechat compose"):
        return False
    tar_path = _STATE_DIR / spec.filename_builder()
    try:
        raw = tar_path.read_text(encoding="utf-8")
    except Exception as e:
        _err(f"Не удалось прочитать скачанный compose: {e}")
        return False
    try:
        patched = _patch_upstream_compose(raw, version)
    except ComposePatchError as e:
        _err(f"Compose апстрима v{_lc_strip_v(version)} не патчится: {e}")
        _info("Версия с изменённой структурой — обновите Chimera "
              "(новый патч-сет) или выберите другую версию.")
        return False
    try:
        LC_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        LC_COMPOSE_FILE.write_text(patched, encoding="utf-8")
        LC_COMPOSE_FILE.chmod(0o644)
    except OSError as e:
        _err(f"Не удалось записать {LC_COMPOSE_FILE}: {e}")
        return False
    try:
        tar_path.unlink(missing_ok=True)
    except Exception:
        pass
    if not quiet:
        _ok(f"docker-compose.yml (v{_lc_strip_v(version)} + патчи Chimera) готов")
    return True


# ════════════════════════════════════════════════════════════════════════════
#  .ENV: генерация с секретами (секреты переживают обновления!)
# ════════════════════════════════════════════════════════════════════════════

# Ключи .env, которые НЕЛЬЗЯ перегенеривать при пере-записи .env
# (смена = потеря логинов/зашифрованных ключей юзеров).
_ENV_SECRET_KEYS = ("JWT_SECRET", "CREDS_KEY", "CREDS_IV",
                    "MEILI_MASTER_KEY", "ADMIN_PANEL_SESSION_SECRET")


def _gen_secret(nbytes: int = 24) -> str:
    return secrets.token_hex(nbytes)


def _parse_env_text(text: str) -> dict:
    """Парсер .env в dict (ключи как есть, без интерполяции)."""
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


def _render_env(env: dict) -> str:
    """dict → текст .env (сортировка: секциями, ключи по алфавиту)."""
    order = [
        # (заголовок секции, [ключи])
        ("LibreChat core", ["HOST", "PORT", "MONGO_URI",
                            "DOMAIN_CLIENT", "DOMAIN_SERVER",
                            "TRUST_PROXY", "NO_INDEX", "LOG_TO_FILE",
                            "NODE_MAX_OLD_SPACE_SIZE"]),
        ("Секреты (НЕ перегенерировать — смена ломает учётки/шифрование)",
         ["JWT_SECRET", "CREDS_KEY", "CREDS_IV", "MEILI_MASTER_KEY",
          "ADMIN_PANEL_SESSION_SECRET"]),
        ("Docker compose", ["UID", "GID", "COMPOSE_PROFILES",
                            "ADMIN_PANEL_PORT"]),
        ("Meilisearch", ["MEILI_HOST", "MEILI_NO_ANALYTICS"]),
        ("RAG (profile rag)", ["RAG_PORT", "RAG_API_URL"]),
        ("Эндпоинты (ключи API добавляются в Web UI или тут)",
         ["ENDPOINTS"]),
    ]
    lines = [
        "# Chimera LibreChat — .env (сгенерировано librechat.py).",
        "# Секреты созданы при установке и сохраняются при обновлениях.",
    ]
    seen = set()
    for title, keys in order:
        section = [k for k in keys if k in env]
        if not section:
            continue
        lines.append("")
        lines.append(f"# ── {title} ──")
        for k in section:
            lines.append(f"{k}={env[k]}")
            seen.add(k)
    # Хвост (не из order) — как есть.
    rest = sorted(k for k in env if k not in seen)
    if rest:
        lines.append("")
        lines.append("# ── прочее ──")
        for k in rest:
            lines.append(f"{k}={env[k]}")
    return "\n".join(lines) + "\n"


def _write_env(port: int, admin_port: int, profiles: list,
               preserve_from: "Optional[Path]" = None) -> dict:
    """Генерирует .env; секреты берёт из существующего файла (preserve_from).

    Возвращает dict записанного окружения.
    """
    old = {}
    if preserve_from is not None and preserve_from.exists():
        try:
            old = _parse_env_text(preserve_from.read_text(encoding="utf-8"))
        except Exception:
            old = {}
    env = {
        # core
        "HOST": "0.0.0.0",
        "PORT": str(port),
        "MONGO_URI": "mongodb://mongodb:27017/LibreChat",
        "DOMAIN_CLIENT": f"http://localhost:{port}",
        "DOMAIN_SERVER": f"http://localhost:{port}",
        "TRUST_PROXY": "1",
        "NO_INDEX": "true",
        "LOG_TO_FILE": "true",
        "NODE_MAX_OLD_SPACE_SIZE": "2048",
        # секреты: сохраняем старые (если есть), иначе генерим
        "JWT_SECRET": old.get("JWT_SECRET") or _gen_secret(24),
        "CREDS_KEY": old.get("CREDS_KEY") or _gen_secret(16),   # ровно 32 симв.
        "CREDS_IV": old.get("CREDS_IV") or _gen_secret(16),     # ровно 32 симв.
        "MEILI_MASTER_KEY": old.get("MEILI_MASTER_KEY") or _gen_secret(16),
        "ADMIN_PANEL_SESSION_SECRET":
            old.get("ADMIN_PANEL_SESSION_SECRET") or _gen_secret(24),
        # docker
        "UID": str(LC_DATA_UID),
        "GID": str(LC_DATA_GID),
        "COMPOSE_PROFILES": ",".join(p for p in profiles if p in LC_PROFILES),
        "ADMIN_PANEL_PORT": str(admin_port),
        # meilisearch
        "MEILI_HOST": "http://meilisearch:7700",
        "MEILI_NO_ANALYTICS": "true",
        # rag
        "RAG_PORT": "8000",
        "RAG_API_URL": "http://rag_api:8000",
        # endpoints — дефолт апстрима
        "ENDPOINTS": "openAI,anthropic,google",
    }
    text = _render_env(env)
    LC_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    LC_ENV_FILE.write_text(text, encoding="utf-8")
    LC_ENV_FILE.chmod(0o600)
    return env


def _patch_env_keys(**overrides) -> bool:
    """Точечно обновляет ключи .env (PORT/DOMAIN_*/COMPOSE_PROFILES/...).

    Секреты не трогает. Возвращает True при успехе.
    """
    if not LC_ENV_FILE.exists():
        return False
    try:
        env = _parse_env_text(LC_ENV_FILE.read_text(encoding="utf-8"))
    except Exception:
        return False
    changed = False
    for k, v in overrides.items():
        if v is None:
            continue
        val = str(v)
        if env.get(k) != val:
            env[k] = val
            changed = True
    if not changed:
        return True
    try:
        LC_ENV_FILE.write_text(_render_env(env), encoding="utf-8")
        LC_ENV_FILE.chmod(0o600)
        return True
    except OSError:
        return False


def _current_profiles_from_env() -> list:
    """Активные profiles из .env (COMPOSE_PROFILES, читабельно для статуса)."""
    if not LC_ENV_FILE.exists():
        return []
    try:
        env = _parse_env_text(LC_ENV_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []
    raw = env.get("COMPOSE_PROFILES", "")
    return [p.strip() for p in raw.split(",") if p.strip() in LC_PROFILES]


# ════════════════════════════════════════════════════════════════════════════
#  SYSTEMD-ЮНИТ (docker compose под systemd, канон compose-стеков)
# ════════════════════════════════════════════════════════════════════════════

def _write_systemd_unit(profiles: Optional[list] = None) -> bool:
    """Юнит librechat.service: up -d / down c профилями.

    Type=oneshot + RemainAfterExit=yes — канон systemd для compose-стеков:
      systemctl start  → docker compose up -d   (is-active=active)
      systemctl stop   → docker compose down    (is-active=inactive)
    Профили вшиты в ExecStart/ExecStop — toggle профиля = перегенерация
    юнита (COMPOSE_PROFILES в .env — только для ручного CLI-паритета).
    """
    docker = _docker_bin() or "/usr/bin/docker"
    prof_flags = " ".join(f"--profile {p}" for p in (profiles or []))
    prof_flags_exec = prof_flags + " " if prof_flags else ""
    # systemctl stop для профилей: down чистит и неактивные профили
    # (--remove-orphans), поэтому ExecStop без --profile.
    unit = f"""# Chimera — LibreChat docker compose stack.
# Сгенерировано chimera/modules/librechat.py. НЕ редактировать вручную.
# Управление: TUI Chimera → 1 → W → 9.

[Unit]
Description=LibreChat (AI chat panel, docker compose)
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory={LC_INSTALL_DIR}
ExecStart={docker} compose --project-directory {LC_INSTALL_DIR} -f {LC_COMPOSE_FILE} {prof_flags_exec}up -d --remove-orphans
ExecStop={docker} compose --project-directory {LC_INSTALL_DIR} -f {LC_COMPOSE_FILE} down --remove-orphans
TimeoutStartSec=900
TimeoutStopSec=180

[Install]
WantedBy=multi-user.target
"""
    try:
        LC_UNIT_PATH.write_text(unit)
    except OSError as e:
        _err(f"Не удалось записать {LC_UNIT_PATH}: {e}")
        return False
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    _ok(f"systemd-unit создан: {LC_UNIT_PATH}")
    return True


# ════════════════════════════════════════════════════════════════════════════
#  HEALTH CHECK (GET /api/status)
# ════════════════════════════════════════════════════════════════════════════

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _health_check(port: Optional[int] = None, timeout: int = LC_HEALTH_TIMEOUT) -> dict:
    """GET /api/status → {ok, http_code, version, error}.

    Opener без прокси (ProxyHandler({})): на серверах с http_proxy в
    окружении urllib гнал 127.0.0.1 ЧЕРЕЗ прокси и живой сервис выглядел
    «не отвечающим» (паттерн triple_panel._smoke_check).
    """
    port = port or int(_load_state().get("port", DEFAULT_LC_PORT))
    url = f"http://127.0.0.1:{port}/api/status"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "chimera-installer/5.0"})
        with _OPENER.open(req, timeout=timeout) as resp:
            body = resp.read(65536).decode(errors="replace")
            version = ""
            try:
                data = json.loads(body)
                version = str(data.get("version", "") or "")
            except Exception:
                pass
            return {"ok": resp.status == 200, "http_code": resp.status,
                    "version": version, "error": ""}
    except urllib.error.HTTPError as e:
        # API отвечает (пусть и ошибкой) — сервис жив, это не timeout.
        return {"ok": False, "http_code": e.code, "version": "",
                "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"ok": False, "http_code": 0, "version": "", "error": str(e)}


def _wait_healthy(port: int, attempts: int = int(LC_HEALTH_WAIT_SEC / LC_HEALTH_INTERVAL),
                  delay: float = LC_HEALTH_INTERVAL, announce: bool = False) -> bool:
    """Ждёт ответа /api/status с ретраями (первый старт: миграции mongo)."""
    for i in range(attempts):
        if _health_check(port, timeout=3).get("ok"):
            return True
        if announce and i == 0:
            _info("Жду готовности LibreChat (первый старт: миграции БД, "
                  "до пары минут)...")
        time.sleep(delay)
    return False


# ════════════════════════════════════════════════════════════════════════════
#  РЕСУРСНЫЕ ПРЕ-ЧЕКИ
# ════════════════════════════════════════════════════════════════════════════

def _ram_mb() -> int:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) // 1024
    except Exception:
        pass
    return 0


def _disk_mb(path: str = "/var/lib") -> int:
    try:
        usage = shutil.disk_usage(path)
        return usage.free // (1024 * 1024)
    except Exception:
        return 0


def _preflight_warnings() -> list:
    """Предупреждения о ресурсах (не блокируют, но честно показываются)."""
    warns = []
    ram = _ram_mb()
    if ram and ram < LC_MIN_RAM_MB:
        warns.append(f"RAM {ram} МБ < {LC_MIN_RAM_MB} МБ — стеку "
                     f"(api+mongo+meilisearch) будет тесно")
    disk = _disk_mb("/var/lib")
    if disk and disk < LC_MIN_DISK_MB:
        warns.append(f"свободно {disk} МБ < {LC_MIN_DISK_MB} МБ — образы "
                     f"займут ~2-3 ГБ")
    return warns


# ════════════════════════════════════════════════════════════════════════════
#  ПОРТ: выбор + port_registry (конфликт-чек, как в triple_panel)
# ════════════════════════════════════════════════════════════════════════════

SERVICE_LIBRECHAT_WEB   = "librechat_web"          # порт панели (loopback)
SERVICE_LIBRECHAT_NGINX = "chimera-librechat-nginx"  # nginx front (TLS)


def _port_conflicts(port: int) -> list:
    try:
        from chimera.modules.port_registry import port_get_conflicts
        return port_get_conflicts(port, proto="tcp")
    except Exception:
        return []


def _validate_port(port: int) -> "tuple[bool, list]":
    if not isinstance(port, int) or port < 1024 or port > 65535:
        return False, ["порт должен быть 1024-65535"]
    conflicts = _port_conflicts(port)
    return (len(conflicts) == 0), conflicts


def _ask_port(default: int = DEFAULT_LC_PORT, title: str = "LibreChat") -> Optional[int]:
    """Интерактивный выбор порта с конфликт-чеком. None = отмена."""
    while True:
        _box_top(f"🔌  ВЫБОР ПОРТА  •  {title}")
        _box_row()
        _box_row(f"  Порт панели на 127.0.0.1 (Enter = {default}):")
        _box_row(f"  {DIM}Проверю port_registry и слушателей перед регистрацией.{NC}")
        _box_row()
        try:
            raw = input(f"{CYAN}  Порт [{default}]:{NC} ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return None
        if raw.lower() == "q":
            return None
        if not raw:
            raw = str(default)
        try:
            port = int(raw)
        except ValueError:
            _box_warn("Нужно число (или Q — отмена).")
            _box_bottom()
            continue
        ok, conflicts = _validate_port(port)
        if ok:
            _box_bottom()
            return port
        _box_warn(f"Порт {port} недоступен:")
        for c in conflicts[:4]:
            _box_row(f"     {RED}•{NC} {c}")
        _box_row(f"  {DIM}Выберите другой порт (или Q — отмена).{NC}")
        _box_bottom()


# ════════════════════════════════════════════════════════════════════════════
#  NGINX FRONT (TLS) — эталон b4: SSH-туннель / self-signed IP / LE-домен
# ════════════════════════════════════════════════════════════════════════════

def _lc_nginx_status() -> dict:
    if not LC_NGINX_STATE_FILE.exists():
        return {"enabled": False}
    try:
        return json.loads(LC_NGINX_STATE_FILE.read_text())
    except Exception:
        return {"enabled": False}


def _lc_nginx_install(port: int, use_self_signed: bool, domain) -> tuple:
    """nginx front с TLS для LibreChat (panel_nginx_front, эталон b4).

    long_timeouts=True: LLM-стримы/SSE идут минутами без единого чанка —
    дефолтные 60s рвали бы длинные ответы моделей на середине.
    """
    from chimera.modules.panel_nginx_front import panel_nginx_front_install
    state = _load_state()
    backend_port = int(state.get("port", DEFAULT_LC_PORT))
    ok, msg = panel_nginx_front_install(
        service_tag=SERVICE_LIBRECHAT_NGINX,
        port=port,
        backend_port=backend_port,
        site_name=LC_NGINX_SITE_NAME,
        state_file=LC_NGINX_STATE_FILE,
        title="LibreChat",
        use_self_signed=use_self_signed,
        domain=domain,
        websocket_origin_rewrite=False,
        backend_http_scheme="http",   # api за nginx — plain HTTP
        cert_name_slug="chimera-librechat",
        mcp_proxy=False,
        long_timeouts=True,
    )
    if ok:
        # DOMAIN_* → https-адрес (OAuth-редиректы, secure cookies).
        base = f"https://{domain}:{port}" if domain else ""
        if base:
            _patch_env_keys(DOMAIN_CLIENT=base, DOMAIN_SERVER=base)
            _compose_up()
    return ok, msg


def _lc_nginx_remove() -> tuple:
    """Снимает nginx front; DOMAIN_* → localhost (SSH-туннель)."""
    from chimera.modules.panel_nginx_front import panel_nginx_front_remove
    if not _lc_nginx_status().get("enabled"):
        return True, "nginx front уже выключен"
    state = _load_state()
    port = int(state.get("port", DEFAULT_LC_PORT))
    panel_nginx_front_remove(
        service_tag=SERVICE_LIBRECHAT_NGINX,
        site_name=LC_NGINX_SITE_NAME,
        state_file=LC_NGINX_STATE_FILE,
        title="LibreChat",
    )
    base = f"http://localhost:{port}"
    _patch_env_keys(DOMAIN_CLIENT=base, DOMAIN_SERVER=base)
    _compose_up()
    return True, "nginx front удалён"


def _lc_nginx_get_url() -> Optional[str]:
    st = _lc_nginx_status()
    if not st.get("enabled"):
        return None
    port = st.get("port", DEFAULT_LC_NGINX_PORT)
    domain = st.get("domain")
    if not domain:
        # self-signed: url по IP (domain=None, поле url в state от front-а)
        url = st.get("url")
        return url or None
    return f"https://{domain}:{port}"


def _compose_up() -> bool:
    """docker compose up -d (recreate при изменении конфига). Живой рефреш."""
    if not LC_COMPOSE_FILE.exists():
        return False
    try:
        r = _compose_run(["up", "-d", "--remove-orphans"],
                         profiles=_current_profiles_from_env(),
                         timeout=300)
        return r.returncode == 0
    except Exception as e:
        _log("WARN", f"compose up: {e}")
        return False


# ════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА / УДАЛЕНИЕ
# ════════════════════════════════════════════════════════════════════════════

def install_librechat(port: Optional[int] = None) -> bool:
    """Полная установка LibreChat: docker + compose + .env + systemd + реестр.

    Шаги:
      0. пре-чеки (ресурсы) и выбор порта (port_registry конфликт-чек);
      1. Docker Engine + compose v2 (apt → get.docker.com);
      2. compose-файл апстрима@пин-тег через download_manager + патчи;
      3. .env с секретами (JWT/CREDS/MEILI — создаются здесь ОДИН раз);
      4. systemd-юнит + регистрация порта в port_registry;
      5. docker compose pull (видимый прогресс) + enable --now;
      6. health-смоук GET /api/status с ожиданием миграций.
    """
    # 0. Пре-чеки + порт.
    for w in _preflight_warnings():
        _warn(w)
    if port is None:
        port = _ask_port()
        if port is None:
            _info("Отменено пользователем.")
            return False
    else:
        ok, conflicts = _validate_port(port)
        if not ok:
            _err(f"Порт {port} недоступен: {'; '.join(conflicts[:3])}")
            return False

    state = _load_state()

    # 1. Docker.
    if not _ensure_docker():
        return False

    # 2. Compose-файл (download_manager + патчи).
    version = _lc_strip_v(LC_VERSION)
    if not _fetch_compose(version):
        return False

    # 3. Каталоги + .env (секреты из старого .env, если переустановка).
    try:
        LC_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        for d in LC_DATA_DIRS:
            (LC_INSTALL_DIR / d).mkdir(parents=True, exist_ok=True)
        # UID/GID контейнеров (upstream user: "${UID}:${GID}") — владелец
        # bind-директорий, чтобы mongo/meili не падали с EACCES.
        subprocess.run(["chown", "-R", f"{LC_DATA_UID}:{LC_DATA_GID}",
                        str(LC_INSTALL_DIR)], capture_output=True, check=False)
    except OSError as e:
        _err(f"Не удалось создать {LC_INSTALL_DIR}: {e}")
        return False
    env = _write_env(port, DEFAULT_LC_ADMIN_PORT, [], preserve_from=LC_ENV_FILE)
    _ok(f".env сгенерирован (секреты: JWT/CREDS/MEILI, "
        f"{len(_ENV_SECRET_KEYS)} ключей)")

    # 4. systemd-юнит + port_registry.
    if not _write_systemd_unit([]):
        return False
    try:
        from chimera.modules.port_registry import port_register
        reg_ok, reg_msg = port_register(
            SERVICE_LIBRECHAT_WEB, port, "tcp",
            comment="LibreChat web UI (loopback, docker)", force=True)
        if not reg_ok:
            _warn(f"port_registry: {reg_msg}")
    except Exception as e:
        _warn(f"port_registry недоступен: {e}")

    # 5. Pull (видимый прогресс) + запуск.
    _info("Скачиваю образы (api ~1 ГБ; зависит от канала)...")
    try:
        r = _compose_run(["pull"], timeout=3600)
        if r.returncode != 0:
            _err("docker compose pull не прошёл — проверьте сеть/прокси.")
            _info("Логи: docker compose -f " + str(LC_COMPOSE_FILE) + " pull")
            return False
    except subprocess.TimeoutExpired:
        _err("docker compose pull: таймаут (канал?). Повторите установку.")
        return False
    _ok("Образы скачаны")

    _info(f"Запускаю {LC_SERVICE}.service...")
    r = subprocess.run(["systemctl", "enable", "--now", LC_SERVICE],
                       capture_output=True, text=True, check=False)
    if r.returncode != 0:
        _err(f"Не удалось запустить: {r.stderr.strip()[:300]}")
        _info(f"Логи: journalctl -u {LC_SERVICE} -n 30")
        return False

    # 6. Health-смоук.
    if not _wait_healthy(port, announce=True):
        _err("LibreChat не ответил на /api/status.")
        _info(f"Логи: docker compose -f {LC_COMPOSE_FILE} logs --tail 30")
        _info("Сервис оставлен запущенным — проверьте логи и повторите "
              "Health check [3].")
    else:
        _ok("LibreChat отвечает на /api/status")

    # State.
    _save_state({
        **state,
        "installed": True,
        "version": f"v{version}",
        "port": port,
        "admin_port": DEFAULT_LC_ADMIN_PORT,
        "enabled": True,
        "profiles": [],
        "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    _ok("LibreChat установлен и запущен!")
    _info(f"Веб-интерфейс: http://127.0.0.1:{port} (только локально)")
    _info(f"SSH-туннель:   ssh -L {port}:127.0.0.1:{port} root@<server>")
    _info(f"Каталог:       {LC_INSTALL_DIR}")
    _info("Регистрация первого юзера = админ (кнопка Sign up).")
    _info("Прямой доступ по HTTPS — пункт меню [6] (nginx front, TLS).")
    return True


def uninstall_librechat(remove_data: bool = False) -> bool:
    """Полное удаление LibreChat.

    remove_data=False (по умолчанию) — данные чатов/загрузки сохраняются
    в /opt/librechat (переустановка подхватит), контейнеры и волюмы
    compose удаляются. remove_data=True — снести и /opt/librechat.
    Docker Engine НЕ трогаем (системная зависимость; b4-паттерн: логи
    тоже оставляем).
    """
    state = _load_state()
    profiles = list(state.get("profiles") or [])

    # 1. Стоп + disable.
    subprocess.run(["systemctl", "disable", "--now", LC_SERVICE],
                   capture_output=True, check=False)

    # 2. Compose down (--volumes: локальные волюмы pgdata/librechat-data).
    if LC_COMPOSE_FILE.exists():
        _info("Останавливаю контейнеры и удаляю волюмы стека...")
        try:
            _compose_run(["down", "--volumes", "--remove-orphans"],
                         profiles=list(LC_PROFILES), timeout=300)
        except Exception as e:
            _warn(f"compose down: {e}")

    # 3. nginx front (если был) — закрывает TLS-порт.
    try:
        _lc_nginx_remove()
    except Exception:
        pass

    # 4. port_registry: снятие регистрации.
    try:
        from chimera.modules.port_registry import port_unregister
        port_unregister(SERVICE_LIBRECHAT_WEB)
        port_unregister(SERVICE_LIBRECHAT_NGINX)
    except Exception:
        pass

    # 5. Юнит.
    subprocess.run(["systemctl", "mask", LC_SERVICE],
                   capture_output=True, check=False)
    LC_UNIT_PATH.unlink(missing_ok=True)
    subprocess.run(["systemctl", "unmask", LC_SERVICE],
                   capture_output=True, check=False)
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "reset-failed", LC_SERVICE],
                   capture_output=True, check=False)

    # 6. Файлы.
    if remove_data:
        if LC_INSTALL_DIR.exists():
            shutil.rmtree(LC_INSTALL_DIR, ignore_errors=True)
        _ok(f"Каталог {LC_INSTALL_DIR} удалён (данные чатов стёрты)")
    else:
        LC_COMPOSE_FILE.unlink(missing_ok=True)
        LC_ENV_FILE.unlink(missing_ok=True)
        _info(f"Данные сохранены: {LC_INSTALL_DIR} "
              f"(data-node/images/uploads) — переустановка подхватит")

    # 7. State.
    _save_state({
        "installed": False, "version": "", "port": DEFAULT_LC_PORT,
        "admin_port": DEFAULT_LC_ADMIN_PORT, "enabled": False,
        "profiles": [], "docker_by_chimera": False,
    })
    _ok("LibreChat полностью удалён (Docker Engine не тронут)")
    return True


# ════════════════════════════════════════════════════════════════════════════
#  СТАТУС / УПРАВЛЕНИЕ
# ════════════════════════════════════════════════════════════════════════════

def _containers_status() -> list:
    """docker compose ps: [{name, state, image}] (пусто при ошибке)."""
    if not LC_COMPOSE_FILE.exists():
        return []
    try:
        r = _compose_run(["ps", "--format", "json"], timeout=30)
        out = (r.stdout or "").strip()
        if not out:
            return []
        # compose v2: одна JSON-строка на контейнер (или массив в новых).
        items = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except Exception:
                continue
            if isinstance(data, list):
                items.extend(x for x in data if isinstance(x, dict))
            elif isinstance(data, dict):
                items.append(data)
        return [{"name": x.get("name") or x.get("Name") or "?",
                 "state": x.get("state") or x.get("State") or "?",
                 "image": x.get("image") or x.get("Image") or "?"}
                for x in items]
    except Exception:
        return []


def status() -> dict:
    """Сводка состояния LibreChat (для TUI и REST)."""
    state = _load_state()
    installed = _detect_installed()
    if not installed:
        return {"installed": False, "service_active": False,
                "version": "", "port": state.get("port", DEFAULT_LC_PORT)}
    service_active = _detect_service_active()
    version = state.get("version", "")
    port = int(state.get("port", DEFAULT_LC_PORT))
    profiles = _current_profiles_from_env() or list(state.get("profiles") or [])
    health = _health_check(port) if service_active else {"ok": False}
    ng = _lc_nginx_status()
    return {
        "installed": True,
        "service_active": service_active,
        "service_enabled": _detect_service_enabled(),
        "version": version,
        "port": port,
        "admin_port": int(state.get("admin_port", DEFAULT_LC_ADMIN_PORT)),
        "profiles": profiles,
        "health_ok": bool(health.get("ok")),
        "health_version": health.get("version", ""),
        "docker_ok": _compose_v2_ok(),
        "compose_path": str(LC_COMPOSE_FILE),
        "env_path": str(LC_ENV_FILE),
        "install_dir": str(LC_INSTALL_DIR),
        "containers": _containers_status() if service_active else [],
        "nginx_front_enabled": ng.get("enabled", False),
        "nginx_front_port": ng.get("port", DEFAULT_LC_NGINX_PORT),
        "nginx_front_url": _lc_nginx_get_url(),
    }


def enable() -> bool:
    """Запуск (compose up -d через systemd)."""
    if not _detect_installed():
        _err("LibreChat не установлен. Сначала выполните установку.")
        return False
    r = subprocess.run(["systemctl", "start", LC_SERVICE],
                       capture_output=True, text=True, check=False)
    if r.returncode != 0:
        _err(f"Не удалось запустить: {r.stderr.strip()[:300]}")
        return False
    state = _load_state()
    state["enabled"] = True
    _save_state(state)
    _ok("LibreChat запущен")
    return True


def disable() -> bool:
    """Остановка без удаления (compose down через systemd)."""
    subprocess.run(["systemctl", "stop", LC_SERVICE],
                   capture_output=True, check=False)
    state = _load_state()
    state["enabled"] = False
    _save_state(state)
    _ok("LibreChat остановлен (данные и конфиг сохранены)")
    return True


# ════════════════════════════════════════════════════════════════════════════
#  СМЕНА ПОРТА
# ════════════════════════════════════════════════════════════════════════════

def change_port(new_port: Optional[int] = None) -> bool:
    """Смена порта панели: .env → port_registry → nginx front → рестарт.

    nginx front (если включён) переустанавливается с новым backend_port
    на ТОМ ЖЕ TLS-порту (vhost перегенерируется panel_nginx_front).
    """
    state = _load_state()
    old = int(state.get("port", DEFAULT_LC_PORT))
    if new_port is None:
        new_port = _ask_port(default=old, title="LibreChat — новый порт")
    if new_port is None or new_port == old:
        return False
    ok, conflicts = _validate_port(new_port)
    if not ok:
        _err(f"Порт {new_port} недоступен: {'; '.join(conflicts[:3])}")
        return False
    # 1. .env.
    base_local = f"http://localhost:{new_port}"
    if not _patch_env_keys(PORT=str(new_port),
                           DOMAIN_CLIENT=base_local,
                           DOMAIN_SERVER=base_local):
        _err("Не удалось обновить .env")
        return False
    # 2. port_registry: перерегистрация.
    try:
        from chimera.modules.port_registry import port_register, port_unregister
        port_unregister(SERVICE_LIBRECHAT_WEB, old, "tcp")
        reg_ok, reg_msg = port_register(
            SERVICE_LIBRECHAT_WEB, new_port, "tcp",
            comment="LibreChat web UI (loopback, docker)", force=True)
        if not reg_ok:
            _warn(f"port_registry: {reg_msg}")
    except Exception as e:
        _warn(f"port_registry: {e}")
    # 3. nginx front: переустановка vhost с новым backend.
    ng = _lc_nginx_status()
    if ng.get("enabled"):
        use_ss = bool(ng.get("self_signed"))
        domain = ng.get("domain")
        try:
            _lc_nginx_install(int(ng.get("port", DEFAULT_LC_NGINX_PORT)),
                              use_ss, domain)
        except Exception as e:
            _warn(f"nginx front re-install: {e}")
    # 4. State + рестарт (down/up пересоздаёт контейнеры с новым портом).
    state["port"] = new_port
    _save_state(state)
    subprocess.run(["systemctl", "restart", LC_SERVICE],
                   capture_output=True, check=False)
    if _wait_healthy(new_port, attempts=40):
        _ok(f"Порт изменён: {old} → {new_port} (сервис здоров)")
    else:
        _warn("Сервис поднялся, но /api/status не отвечает — см. логи [4]")
    return True


# ════════════════════════════════════════════════════════════════════════════
#  ПРОФИЛИ (rag / admin — тяжёлые опциональные сервисы)
# ════════════════════════════════════════════════════════════════════════════

def set_profiles(profiles: list) -> bool:
    """Включает/выключает профили compose (юнит + .env + up -d).

    rag      → rag_api + vectordb (RAG-поиск по документам, +~1 ГБ RAM)
    admin    → admin-panel (админ-панель апстрима, порт admin_port)
    """
    clean = [p for p in profiles if p in LC_PROFILES]
    state = _load_state()
    if not _detect_installed():
        _err("LibreChat не установлен")
        return False
    _patch_env_keys(COMPOSE_PROFILES=",".join(clean))
    _write_systemd_unit(clean)   # профили вшиты в ExecStart
    state["profiles"] = clean
    _save_state(state)
    # Рестарт с новыми профилями (down чистит снятые, up поднимает новые).
    subprocess.run(["systemctl", "restart", LC_SERVICE],
                   capture_output=True, check=False)
    _ok(f"Профили стека: {', '.join(clean) if clean else 'нет (базовый стек)'}")
    return True


# ════════════════════════════════════════════════════════════════════════════
#  ОБНОВЛЕНИЕ (release / pre-release, паттерн B4: смоук с откатом)
# ════════════════════════════════════════════════════════════════════════════

def auto_update(force: bool = False, target_version: Optional[str] = None) -> dict:
    """Обновление до release (или конкретной target_version).

    Флоу (как _do_b4_binary_update, адаптировано под compose):
      1. определить latest (GitHub API) / target;
      2. скачать compose@тег (download_manager) + патч — ДО любых
         изменений на диске (теги иммутабельны, патч детерминирован);
      3. бэкап текущего compose → новый compose на место;
      4. docker compose pull (новые образы);
      5. up -d (пересоздание контейнеров);
      6. health-смоук /api/status — при провале ОТКАТ compose + up -d;
      7. state.version = новый тег.

    Возвращает dict {updated, old_version, new_version, message}.
    """
    if not _detect_installed():
        return {"updated": False, "old_version": "", "new_version": "",
                "message": "LibreChat не установлен"}
    state = _load_state()
    old = state.get("version", "")
    if target_version:
        target = _lc_strip_v(target_version)
        if not target.startswith("v"):
            target = f"v{target}"
    else:
        latest = _detect_latest_version()
        if not latest:
            return {"updated": False, "old_version": old, "new_version": "",
                    "message": "GitHub недоступен — не удалось проверить версию"}
        target = latest
    if (not force and old
            and _lc_version_key(old) >= _lc_version_key(target)):
        return {"updated": False, "old_version": old, "new_version": old,
                "message": f"Установлена актуальная версия ({old})"}

    _info(f"Обновляю LibreChat: {old or '—'} → {target}...")

    # 1-2. Новый compose (проверяем ДО подмены: скачали → патч → на место).
    backup = LC_COMPOSE_FILE.with_suffix(".yml.bak")
    try:
        if LC_COMPOSE_FILE.exists():
            shutil.copy2(LC_COMPOSE_FILE, backup)
    except Exception:
        backup = None
    if not _fetch_compose(target):
        if backup and backup.exists():
            backup.unlink(missing_ok=True)
        return {"updated": False, "old_version": old, "new_version": target,
                "message": "Не удалось скачать/запатчить compose новой версии"}

    # 3. Образы.
    _info("Скачиваю образы новой версии (api ~1 ГБ)...")
    try:
        r = _compose_run(["pull"], timeout=3600)
        if r.returncode != 0:
            _err("docker compose pull не прошёл — ОТКАТ compose.")
            if backup and backup.exists():
                shutil.copy2(backup, LC_COMPOSE_FILE)
                backup.unlink(missing_ok=True)
            return {"updated": False, "old_version": old, "new_version": target,
                    "message": "docker pull не прошёл (сеть?) — версия не менялась"}
    except subprocess.TimeoutExpired:
        if backup and backup.exists():
            shutil.copy2(backup, LC_COMPOSE_FILE)
            backup.unlink(missing_ok=True)
        return {"updated": False, "old_version": old, "new_version": target,
                "message": "docker pull: таймаут — версия не менялась"}

    # 4. Пересоздание контейнеров.
    _info("Пересоздаю контейнеры...")
    if not _compose_up():
        _err("compose up не прошёл — ОТКАТ.")
        if backup and backup.exists():
            shutil.copy2(backup, LC_COMPOSE_FILE)
            _compose_up()
            backup.unlink(missing_ok=True)
        return {"updated": False, "old_version": old, "new_version": target,
                "message": "compose up провален — откат к прежней версии"}

    # 5. Health-смоук с откатом.
    port = int(state.get("port", DEFAULT_LC_PORT))
    if not _wait_healthy(port, attempts=40):
        _err("Новая версия не прошла health-смоук — ОТКАТ.")
        if backup and backup.exists():
            shutil.copy2(backup, LC_COMPOSE_FILE)
            _compose_up()
            _wait_healthy(port, attempts=20)
            backup.unlink(missing_ok=True)
            return {"updated": False, "old_version": old, "new_version": target,
                    "message": "Новая версия не здорова — восстановлена прежняя"}
        return {"updated": False, "old_version": old, "new_version": target,
                "message": "Health-смоук провален (бэкапа не было)"}

    # 6. State + cleanup.
    state["version"] = target
    _save_state(state)
    if backup and backup.exists():
        backup.unlink(missing_ok=True)
    return {"updated": True, "old_version": old, "new_version": target,
            "message": f"LibreChat обновлён: {old or '—'} → {target}"}


def auto_update_prerelease(confirm: bool = True, force: bool = False) -> dict:
    """Обновление до pre-release (rc-теги). Паттерн youtube_b4."""
    if not _detect_installed():
        return {"updated": False, "old_version": "", "new_version": "",
                "message": "LibreChat не установлен"}
    state = _load_state()
    old = state.get("version", "")
    latest_pre = _detect_latest_prerelease_version()
    if not latest_pre:
        return {"updated": False, "old_version": old, "new_version": "",
                "message": "Pre-release версии не найдены на GitHub"}
    if (not force and old
            and _lc_version_key(old) >= _lc_version_key(latest_pre)):
        return {"updated": False, "old_version": old, "new_version": old,
                "message": f"Установлена актуальная pre-release ({old})"}
    if confirm:
        _warn(f"Pre-release {latest_pre} — НЕстабильная версия (rc-тег "
              f"апстрима). Возможны баги и миграции без отката.")
        try:
            ans = input(f"{YELLOW}Обновиться до {latest_pre}? [y/N]:{NC} "
                        ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans not in ("y", "yes", "д", "да"):
            return {"updated": False, "old_version": old,
                    "new_version": latest_pre, "message": "Отменено"}
    return auto_update(force=force, target_version=latest_pre)


def sync_version_state() -> dict:
    """Синхронизация фактической версии: state ← /api/status (если живой).

    Версию в state меняет только auto_update; но /api/status отдаёт
    версию, на которой реально работает api — сверка ловит ручные
    `docker compose` вне Chimera. Паттерн sync_b4_version_state.
    """
    state = _load_state()
    old = state.get("version", "")
    h = _health_check()
    live = str(h.get("version", "") or "")
    if live and not live.startswith("v"):
        live = f"v{live}"
    if live and live != old:
        state["version"] = live
        _save_state(state)
        _log("INFO", f"sync_version_state: {old or '—'} → {live}")
        return {"synced": True, "version": live, "old_version": old}
    return {"synced": False, "version": old, "old_version": old}


def do_librechat_update_menu() -> None:
    """Раздел «Обновление LibreChat» — release / pre-release (паттерн B4).

      [1] Обновление до последней release
      [2] Обновление до pre-release (нестабильно)

    После успешного обновления кэш latest сбрасывается (force=True) —
    шапка главного меню сразу показывает честное «актуальная версия».
    """
    while True:
        os.system("clear")
        sync_version_state()
        state = _load_state()
        installed_version = state.get("version", "")
        latest_stable = _detect_latest_version()
        latest_pre = _detect_latest_prerelease_version()

        _box_top("🔄  ОБНОВЛЕНИЕ LIBRECHAT")
        _box_row()
        if installed_version:
            _box_row(f"  Установленная версия:  {CYAN}{installed_version}{NC}")
        else:
            _box_row(f"  Установленная версия:  {YELLOW}не определена{NC}")
        if latest_stable:
            _box_row(f"  Последняя release:     {GREEN}{latest_stable}{NC}")
        else:
            _box_row(f"  Последняя release:     {DIM}недоступна (GitHub не отвечает){NC}")
        if latest_pre:
            _box_row(f"  Последняя pre-release: {YELLOW}{latest_pre}{NC}")
        else:
            _box_row(f"  Последняя pre-release: {DIM}нет доступных pre-release{NC}")
        _box_row()
        _box_row(f"  {DIM}Обновление = пин нового тега → docker compose pull →{NC}")
        _box_row(f"  {DIM}пересоздание контейнеров → health-смоук с откатом.{NC}")
        _box_row(f"  {DIM}Данные (mongo/uploads) не трогаются. Секреты .env — тоже.{NC}")
        _box_row()
        _box_item("1", "✅ Обновление до последней release версии")
        _box_item("2", f"🧪 Обновление до prerelease версии  {YELLOW}(нестабильно!){NC}")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return
        if ch in ("q", "0", ""):
            return

        if ch == "1":
            if not _detect_installed():
                _err("LibreChat не установлен. Сначала выполните установку.")
                input(f"\n{BOLD}Enter…{NC}")
                continue
            old = _load_state().get("version", "")
            latest = _detect_latest_version()
            if not latest:
                _err("Не удалось проверить последнюю release-версию (GitHub недоступен).")
                input(f"\n{BOLD}Enter…{NC}")
                continue
            if old == latest:
                _info(f"Установлена последняя release-версия: {old}.")
                try:
                    ans = input(
                        f"{YELLOW}Принудительно переустановить {latest}? [y/N]:{NC} "
                    ).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    ans = "n"
                if ans not in ("y", "yes", "д", "да"):
                    _info("Отменено — версия не менялась.")
                    input(f"\n{BOLD}Enter…{NC}")
                    continue
                result = auto_update(force=True)
            else:
                _info("Проверяю обновления...")
                result = auto_update()
            if result.get("updated"):
                _ok(result["message"])
                _refresh_lc_latest_cache(force=True)
            else:
                _info(result["message"])
            input(f"\n{BOLD}Enter…{NC}")

        elif ch == "2":
            if not _detect_installed():
                _err("LibreChat не установлен. Сначала выполните установку.")
                input(f"\n{BOLD}Enter…{NC}")
                continue
            state2 = _load_state()
            old = state2.get("version", "")
            latest_pre = _detect_latest_prerelease_version()
            if not latest_pre:
                _err("Pre-release версии не найдены на GitHub.")
                input(f"\n{BOLD}Enter…{NC}")
                continue
            if old == latest_pre:
                _info(f"Установлена последняя pre-release версия: {old}.")
                try:
                    ans = input(
                        f"{YELLOW}Принудительно переустановить {latest_pre}? [y/N]:{NC} "
                    ).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    ans = "n"
                if ans not in ("y", "yes", "д", "да"):
                    _info("Отменено — версия не менялась.")
                    input(f"\n{BOLD}Enter…{NC}")
                    continue
                result = auto_update_prerelease(confirm=False, force=True)
            else:
                result = auto_update_prerelease(confirm=True)
            if result.get("updated"):
                _ok(result["message"])
                _refresh_lc_latest_cache(force=True)
            else:
                _info(result["message"])
            input(f"\n{BOLD}Enter…{NC}")


# ════════════════════════════════════════════════════════════════════════════
#  INFO ДЛЯ ПОРТАЛОВ (REST API / веб-панель Chimera)
# ════════════════════════════════════════════════════════════════════════════

def get_admin_info() -> dict:
    """Полный статус для Admin Panel / блока веб-панелей."""
    s = status()
    # Логи (последние 20 строк юнита).
    s["logs"] = []
    try:
        r = subprocess.run(
            ["journalctl", "-u", LC_SERVICE, "-n", "20", "--no-pager",
             "-o", "cat"],
            capture_output=True, text=True, check=False, timeout=5)
        s["logs"] = r.stdout.splitlines()[-20:] if r.stdout else []
    except Exception:
        pass
    return s


# ════════════════════════════════════════════════════════════════════════════
#  TUI-МЕНЮ (точка входа: Раздел 1 → W → 9)
# ════════════════════════════════════════════════════════════════════════════

def _show_logs(n: int = 40) -> None:
    """Логи контейнеров (docker compose logs) в рамке."""
    os.system("clear")
    _box_top(f"📋  ЛОГИ LIBRECHAT (ПОСЛЕДНИЕ {n} СТРОК)")
    _box_row()
    raw = ""
    if LC_COMPOSE_FILE.exists():
        try:
            r = _compose_run(["logs", "--tail", str(n), "--no-color"],
                             profiles=_current_profiles_from_env(), timeout=30)
            raw = r.stdout or "(пусто)"
        except Exception as e:
            raw = f"Ошибка: {e}"
    else:
        raw = "LibreChat не установлен"
    from chimera.modules.box_renderer import _get_box_width as _gw
    _w = _gw() - 4
    for line in raw.splitlines():
        _line = line if len(line) <= _w else line[:_w - 3] + "..."
        _box_row(f"  {DIM}{_line}{NC}")
    _box_row()
    _box_row(f"  {DIM}Полные логи:{NC}")
    _box_row(f"    {CYAN}docker compose -f {LC_COMPOSE_FILE} logs -f{NC}  {DIM}(live){NC}")
    _box_row(f"    {CYAN}journalctl -u {LC_SERVICE} -n 100 --no-pager{NC}")
    _box_row()
    _box_back()
    _box_bottom()
    input(f"\n{BOLD}Enter…{NC}")


def _show_containers() -> None:
    """docker compose ps — матрица контейнеров."""
    os.system("clear")
    _box_top("🐳  КОНТЕЙНЕРЫ LIBRECHAT")
    _box_row()
    cs = _containers_status()
    if not cs:
        _box_warn("Контейнеры не найдены (сервис остановлен или не установлен).")
    else:
        for c in cs:
            col = GREEN if str(c.get("state", "")).lower() in ("running",) else RED
            _box_row(f"  {col}●{NC} {c.get('name', '?'):<24} "
                     f"{col}{c.get('state', '?')}{NC}")
            _box_row(f"    {DIM}{c.get('image', '?')}{NC}")
    _box_row()
    _box_row(f"  {DIM}Профили: {', '.join(_current_profiles_from_env()) or 'нет'}{NC}")
    _box_row()
    _box_back()
    _box_bottom()
    input(f"\n{BOLD}Enter…{NC}")


def _profiles_menu() -> None:
    """Toggle профилей rag / admin (тяжёлые опциональные сервисы)."""
    while True:
        os.system("clear")
        current = set(_current_profiles_from_env())
        _box_top("🧩  ПРОФИЛИ СТЕКА LIBRECHAT")
        _box_row()
        rag_on = "rag" in current
        adm_on = "admin" in current
        _box_row(f"  Базовый стек: {GREEN}api + mongodb + meilisearch{NC} "
                 f"{DIM}(всегда){NC}")
        _box_row()
        _box_row(f"  [1] RAG-поиск по документам (rag_api + pgvector): "
                 f"{'включён' if rag_on else 'выключен'}")
        _box_row(f"      {DIM}+~1 ГБ RAM и ~700 МБ образов; поиск по загруженным файлам{NC}")
        _box_row(f"  [2] Admin-panel апстрима: "
                 f"{'включена' if adm_on else 'выключена'}")
        _box_row(f"      {DIM}панель модераторов апстрима, порт admin (loopback){NC}")
        _box_row()
        _box_row(f"  {DIM}Смена профиля перегенерирует юнит и пересоздаёт стек.{NC}")
        _box_row()
        _box_item("1", f"{'Выключить' if rag_on else 'Включить'} профиль RAG")
        _box_item("2", f"{'Выключить' if adm_on else 'Включить'} профиль admin-panel")
        _box_row()
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return
        if ch in ("q", "0", ""):
            return
        if ch == "1":
            current ^= {"rag"}
            set_profiles(sorted(current))
            input(f"\n{BOLD}Enter…{NC}")
        elif ch == "2":
            current ^= {"admin"}
            set_profiles(sorted(current))
            input(f"\n{BOLD}Enter…{NC}")


def _access_menu() -> None:
    """Доступ: SSH-туннель (по умолчанию) / nginx front TLS (эталон b4)."""
    while True:
        os.system("clear")
        st = _lc_nginx_status()
        state = _load_state()
        port = int(state.get("port", DEFAULT_LC_PORT))
        _box_top("🌐  ДОСТУП  •  LIBRECHAT")
        _box_row()
        _box_kv("Прямой порт:", f"{CYAN}127.0.0.1:{port}{NC} {DIM}(SSH-туннель){NC}")
        url = _lc_nginx_get_url()
        _box_kv("nginx front:", (f"{GREEN}включён{NC} — {YELLOW}{url}{NC}" if url
                                 else f"{DIM}выключен (доступ только SSH-туннелем){NC}"))
        _box_row()
        _box_row(f"  {DIM}Три режима (как у b4):{NC}")
        _box_row(f"  {DIM}SSH-туннель = фронт выключен, порт loopback-only{NC}")
        _box_row(f"  {DIM}Публичный IP = self-signed TLS через nginx{NC}")
        _box_row(f"  {DIM}Домен = Let's Encrypt (сертификат через certbot){NC}")
        _box_row()
        _box_sep()
        if st.get("enabled"):
            _box_item("1", f"{RED}Выключить nginx front{NC} "
                            f"{DIM}(вернуть SSH-режим){NC}")
        else:
            _box_item("1", "🌐  Включить nginx front (TLS)")
        _box_item("Q", "← Назад")
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            break
        if ch in ("q", "", "0"):
            break
        if ch == "1":
            if st.get("enabled"):
                _box_top("🌐  ДОСТУП  •  LIBRECHAT — ВЫКЛЮЧЕНИЕ ФРОНТА")
                _box_row()
                _box_row(f"  {DIM}Будет удалён nginx vhost + закрыт порт "
                         f"{st.get('port', DEFAULT_LC_NGINX_PORT)}.{NC}")
                _box_row(f"  {DIM}Доступ вернётся на SSH-туннель.{NC}")
                _box_row()
                confirm = input(f"  {YELLOW}Выключить nginx front? [y/N]:{NC} "
                                ).strip().lower()
                if confirm == "y":
                    ok, msg = _lc_nginx_remove()
                    (_ok if ok else _err)(msg)
                else:
                    _info("Отменено.")
            else:
                # Порт nginx front.
                try:
                    port_str = input(
                        f"  Порт для nginx front [Enter={DEFAULT_LC_NGINX_PORT}]: "
                        ).strip()
                    ng_port = int(port_str) if port_str else DEFAULT_LC_NGINX_PORT
                except (ValueError, EOFError, KeyboardInterrupt):
                    ng_port = DEFAULT_LC_NGINX_PORT
                try:
                    from chimera.modules.panel_nginx_front import (
                        ask_tls_mode, ask_domain)
                except ImportError:
                    _err("panel_nginx_front недоступен — не могу установить nginx front.")
                    input(f"\n{BOLD}Enter…{NC}")
                    continue
                use_self_signed, _ = ask_tls_mode("LibreChat")
                domain = None
                if not use_self_signed:
                    try:
                        core = _core_module()
                        if not getattr(core, "PARAM_DOMAIN", ""):
                            if hasattr(core, "_load_state_into_globals"):
                                core._load_state_into_globals()
                        domain = ask_domain(default=getattr(core, "PARAM_DOMAIN", ""))
                    except Exception:
                        domain = ask_domain(default="")
                    if not domain:
                        _warn("Домен не указан — отмена. Используйте self-signed режим.")
                        input(f"\n{BOLD}Enter…{NC}")
                        continue
                ok, msg = _lc_nginx_install(ng_port, use_self_signed, domain)
                if ok:
                    _ok(f"nginx front включён на порту {ng_port}.")
                    url = _lc_nginx_get_url()
                    if url:
                        _info(f"LibreChat доступен: {url}")
                else:
                    _err(f"Не удалось установить nginx front: {msg}")
            input(f"\n{BOLD}Enter…{NC}")


def do_librechat_menu() -> None:
    """TUI-меню управления LibreChat (образец: do_youtube_b4_menu)."""
    while True:
        os.system("clear")
        s = status()
        _lc_latest = _refresh_lc_latest_cache()
        _box_top(f"🤖  LIBRECHAT — AI ЧАТ-ПАНЕЛЬ  "
                 f"{DIM}{s.get('version', '') or ''}{NC}")
        _box_row()
        if not s["installed"]:
            _box_warn("LibreChat не установлен.")
            _box_row()
            _box_row(f"  {DIM}LibreChat — self-hosted AI-чат (OpenAI/Anthropic/{NC}")
            _box_row(f"  {DIM}Google/GPT/Ollama, мультиюзерный, с RAG-поиском).{NC}")
            _box_row(f"  {DIM}Стек: docker compose (api + mongodb + meilisearch).{NC}")
            _box_row(f"  {DIM}Требования: ~2 ГБ RAM, ~3 ГБ диска, Docker.{NC}")
            _box_row(f"  {DIM}Доступ: SSH-туннель или nginx front с TLS (домен/IP).{NC}")
            _box_row()
            _box_item("1", "🚀 Установить LibreChat (docker + compose + systemd + реестр)")
            _box_row()
            _box_back()
            _box_bottom()
        else:
            status_col = GREEN if s.get("service_active") else RED
            status_str = "active" if s.get("service_active") else "stopped"
            _box_row(f"  Сервис:       {status_col}{status_str}{NC}")
            _box_row(f"  Версия:       {CYAN}{s.get('version', '?')}{NC}")
            _box_row(_lc_update_header_row(str(s.get("version", "") or ""),
                                           _lc_latest))
            health_col = GREEN if s.get("health_ok") else YELLOW
            health_str = "✓ отвечает" if s.get("health_ok") else "не отвечает"
            _box_row(f"  Health:       {health_col}{health_str}{NC}  "
                     f"{DIM}GET /api/status{NC}")
            _box_row(f"  Порт:         {CYAN}127.0.0.1:{s.get('port')}{NC} "
                     f"{DIM}(SSH-туннель){NC}")
            ng_url = s.get("nginx_front_url")
            if ng_url:
                _box_row(f"  Web UI (TLS): {GREEN}{ng_url}{NC}")
            profiles = s.get("profiles") or []
            prof_str = ", ".join(profiles) if profiles else "базовый стек"
            _box_row(f"  Профили:      {CYAN}{prof_str}{NC}")
            docker_ok = s.get("docker_ok")
            _box_row(f"  Docker:       "
                     f"{GREEN if docker_ok else RED}{'ok' if docker_ok else 'не найден'}{NC}")
            _box_row(f"  Install dir:  {DIM}{s.get('install_dir')}{NC}")
            _box_row()
            _box_row(f"  {DIM}Как это работает:{NC}")
            _box_row(f"  {DIM}1. docker compose стек: api + mongodb + meilisearch{NC}")
            _box_row(f"  {DIM}2. Порт привязан к 127.0.0.1 — наружу только через TLS-фронт{NC}")
            _box_row(f"  {DIM}3. nginx front [6]: домен (Let's Encrypt) или IP (self-signed){NC}")
            _box_row(f"  {DIM}4. Ключи API моделей вводятся в Web UI или в .env{NC}")
            _box_row()
            _box_sep()
            if s.get("service_active"):
                _box_item("1", "🛑 Остановить LibreChat (без удаления)")
            else:
                _box_item("1", "🚀 Запустить LibreChat")
            _box_item("2", "🔄 Обновление LibreChat (release / pre-release)")
            _box_item("3", "🏥 Health check (api/status + сводка)")
            _box_item("4", "📋 Логи контейнеров (последние 40 строк)")
            _box_item("5", "🌐 Web UI (SSH-туннель инструкция)")
            ng_st = _lc_nginx_status()
            if ng_st.get("enabled"):
                _box_item("6", f"🌐 nginx front (TLS) — {YELLOW}выключить{NC}  "
                               f"{DIM}({s.get('nginx_front_url')}){NC}")
            else:
                _box_item("6", "🌐 nginx front (TLS) — включить прямой доступ по HTTPS")
            _box_item("7", "🔀 Сменить порт панели")
            _box_item("8", "🧩 Профили стека (RAG / admin-panel)")
            _box_item("M", "🐳 Статус контейнеров (docker compose ps)")
            _box_row()
            _box_item("R", f"{RED}🗑️  Удалить LibreChat полностью{NC}")
            _box_row()
            _box_back()
            _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return

        if ch in ("q", "0", ""):
            return

        if not s["installed"] and ch == "1":
            if install_librechat():
                _info("Первый зарегистрированный юзер = администратор.")
            input(f"\n{BOLD}Enter…{NC}")

        elif s["installed"] and ch == "1":
            if s.get("service_active"):
                disable()
            else:
                enable()
            input(f"\n{BOLD}Enter…{NC}")

        elif s["installed"] and ch == "2":
            do_librechat_update_menu()

        elif s["installed"] and ch == "3":
            _info("Проверяю /api/status (до 5с)...")
            h = _health_check()
            if h.get("ok"):
                ver = h.get("version", "")
                _ok(f"LibreChat отвечает (версия api: {ver or '?'})")
                _info("Все контейнеры: см. пункт M.")
            else:
                _warn(f"Не отвечает: {h.get('error') or h.get('http_code')}")
                _info("Если сервис только что запущен — миграции БД занимают минуту.")
            input(f"\n{BOLD}Enter…{NC}")

        elif s["installed"] and ch == "4":
            _show_logs()

        elif s["installed"] and ch == "5":
            port = s.get("port", DEFAULT_LC_PORT)
            os.system("clear")
            _box_top("🌐  WEB UI LIBRECHAT (ИНСТРУКЦИЯ)")
            _box_row()
            _box_row(f"  LibreChat слушает только 127.0.0.1:{port}")
            _box_row(f"  {DIM}(не открывается наружу — безопасность){NC}")
            _box_row()
            _box_row(f"  {BOLD}Доступ через SSH-туннель:{NC}")
            _box_row(f"    {CYAN}ssh -L {port}:127.0.0.1:{port} root@<server>{NC}")
            _box_row(f"  {BOLD}Затем в браузере:{NC}")
            _box_row(f"    {CYAN}http://localhost:{port}{NC}")
            _box_row()
            _box_row(f"  {DIM}Прямой доступ (домен/IP + TLS) — пункт [6].{NC}")
            _box_row()
            _box_row(f"  {DIM}Первый вход: Sign up → этот юзер станет админом.{NC}")
            _box_row(f"  {DIM}Ключи API (OpenAI/Anthropic/...) — в настройках UI или .env.{NC}")
            _box_row()
            _box_back()
            _box_bottom()
            input(f"\n{BOLD}Enter…{NC}")

        elif s["installed"] and ch == "6":
            _access_menu()

        elif s["installed"] and ch == "7":
            _box_top("🔀  СМЕНА ПОРТА  •  LIBRECHAT")
            _box_row()
            _box_row(f"  {DIM}Смена порта: .env → port_registry → nginx front → рестарт.{NC}")
            _box_row()
            _box_bottom()
            change_port()
            input(f"\n{BOLD}Enter…{NC}")

        elif s["installed"] and ch == "8":
            _profiles_menu()

        elif s["installed"] and ch == "m":
            _show_containers()

        elif s["installed"] and ch == "r":
            _box_top("🗑️  УДАЛЕНИЕ  •  LIBRECHAT")
            _box_row()
            _box_row(f"  {DIM}Будет остановлено: контейнеры, волюмы стека, systemd-юнит,{NC}")
            _box_row(f"  {DIM}nginx front, регистрации портов. Docker Engine останется.{NC}")
            _box_row()
            confirm = input(f"  {RED}Удалить LibreChat? [y/N]:{NC} ").strip().lower()
            if confirm == "y":
                try:
                    data_ans = input(
                        f"  {YELLOW}Удалить и данные (чаты/загрузки/mongo)? [y/N]:{NC} "
                        ).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    data_ans = "n"
                uninstall_librechat(remove_data=(data_ans == "y"))
            input(f"\n{BOLD}Enter…{NC}")


# ════════════════════════════════════════════════════════════════════════════
#  КЛИЕНТ CLI
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":  # pragma: no cover
    if len(sys.argv) < 2:
        do_librechat_menu()
    else:
        import argparse
        p = argparse.ArgumentParser(description="LibreChat (AI-чат панель Chimera)")
        p.add_argument("cmd", choices=["install", "uninstall", "status",
                                       "enable", "disable", "health",
                                       "update", "update-pre", "sync-version",
                                       "set-profiles"])
        p.add_argument("--port", type=int, default=None,
                       help="порт панели (для install)")
        p.add_argument("--profiles", default="",
                       help="профили через запятую: rag,admin (для set-profiles)")
        p.add_argument("--remove-data", action="store_true",
                       help="удалить данные чатов (для uninstall)")
        args = p.parse_args()
        if args.cmd == "install":
            install_librechat(port=args.port)
        elif args.cmd == "uninstall":
            uninstall_librechat(remove_data=args.remove_data)
        elif args.cmd == "status":
            print(json.dumps(status(), indent=2, ensure_ascii=False))
        elif args.cmd == "enable":
            enable()
        elif args.cmd == "disable":
            disable()
        elif args.cmd == "health":
            print(json.dumps(_health_check(), indent=2, ensure_ascii=False))
        elif args.cmd == "update":
            print(json.dumps(auto_update(), indent=2, ensure_ascii=False))
        elif args.cmd == "update-pre":
            print(json.dumps(auto_update_prerelease(confirm=False),
                             indent=2, ensure_ascii=False))
        elif args.cmd == "sync-version":
            print(json.dumps(sync_version_state(), indent=2, ensure_ascii=False))
        elif args.cmd == "set-profiles":
            profs = [x.strip() for x in args.profiles.split(",") if x.strip()]
            set_profiles(profs)
