"""
chimera/modules/dpi_censor_check.py
───────────────────────────────────────────────────────────────────────────────
Обёртка над сторонним инструментом Runnin4ik/dpi-detector — диагностика
цензуры на стороне провайдера (TLS/TCP/HTTP/DNS-блокировки, обрыв
соединений на 16-20KB, подмена DNS-ответов).

ВАЖНО — не путать с chimera/modules/dpi_detector.py:
    dpi_detector.py (соседний модуль) — анализирует error.log Xray НА
    СЕРВЕРЕ и банит IP при активном зондировании (server-side защита).
    dpi_censor_check.py (этот файл) — проверяет, ЧТО блокирует провайдер
    СНАРУЖИ, в сторону произвольных доменов/IP (client-side диагностика).
    Это две разные сущности с похожими названиями — разные задачи,
    разный код, объединять не нужно.

Архитектура интеграции:
    Апстрим (httpx + rich + PyYAML, пакеты core/cli/utils, ~190 КБ) вендорится
    БЕЗ ИЗМЕНЕНИЙ в _vendor/dpi_detector/ (см. там VENDOR_INFO.md) и
    запускается как ОТДЕЛЬНЫЙ процесс через subprocess. Причины:
      • Изоляция: апстрим сам ставит signal-хендлер на SIGINT и вызывает
        os._exit() — в отдельном процессе это не заденет установщик.
      • Апстрим использует относительные импорты (from utils import config,
        from core.dns_scanner import ...) и резолвит свои файлы конфигурации
        через __file__ — корректно работает только как точка входа
        интерпретатора, а не как импортируемый пакет. Подмена этого на
        нормальные пакетные импорты означала бы переписывать апстрим —
        higher risk, никакой пользы.
      • Новые pip-зависимости (httpx, rich, PyYAML) не тянутся в основной
        интерпретатор установщика. Ставятся лениво — только когда
        пользователь реально открывает этот пункт меню.

АВТООБНОВЛЕНИЕ АПСТРИМА:
    Автор апстрима релизит часто (за лето 2026: v3.3.0 → v4.1.0), вендорная
    копия в git-дереве Химеры устаревает между релизами Химеры. Поэтому:
      • при КАЖДОМ входе в меню Химера смотрит, какая версия установлена,
        и (тихо, с кэшем) проверяет последнюю на GitHub:
        GitHub API /releases/latest → фолбэк git ls-remote --tags
        (API бывает rate-limited, ls-remote — нет);
      • запуск всегда идёт из АКТИВНОЙ копии — новейшей из двух:
          1) вендорная _vendor/dpi_detector/ — офлайн-фолбэк, часть
             git-дерева, обновляется только вместе с Химерой;
          2) runtime-копия /var/lib/xray-installer/dpi-detector/<версия>/
             — скачивается с codeload.github.com при обновлении
             (пункт [4] меню или предложение перед запуском теста);
      • git-дерево при runtime-обновлении НЕ трогается (никаких конфликтов
        с git pull) — tarball распаковывается в .staging-<v>, финальный
        каталог появляется одним rename, старые версии подчищаются;
      • версия читается из dpi_detector.py активной копии (CURRENT_VERSION)
        — «установленная версия» всегда факт с диска, а не из state.

Точка входа из _core.py:
    from chimera.modules.dpi_censor_check import do_dpi_censor_check_menu
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

# ── Цвета (самодостаточно, как и в остальных модулях) ───────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                    DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m')
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BLUE', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, WHITE, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'], _C['BLUE'],
    _C['BOLD'], _C['DIM'], _C['WHITE'], _C['NC'],
)

# ── box_renderer (UI меню, общий для всех модулей установщика) ─────────────────
from chimera.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_item, _box_back,
    _box_info, _box_warn, _box_row, _box_desc, _box_ok,
)

# ── Константы ─────────────────────────────────────────────────────────────────
_VENDOR_DIR = Path(__file__).resolve().parent / "_vendor" / "dpi_detector"
_ENTRY      = _VENDOR_DIR / "dpi_detector.py"
_REQS       = _VENDOR_DIR / "requirements.txt"
_LOG_FILE   = Path("/var/log/chimera.log")
_REPORT_DIR = Path("/var/log/xray-installer/dpi-censor-reports")

# Имена пакетов для импорта (PyYAML импортируется как "yaml")
_REQUIRED_MODULES = ("httpx", "rich", "yaml")

# ── Автообновление апстрима Runnin4ik/dpi-detector ──────────────────────
_UPSTREAM_REPO = "Runnin4ik/dpi-detector"
_UPSTREAM_URL  = f"https://github.com/{_UPSTREAM_REPO}"
# Runtime-копии свежих версий (в git-дереве установщика НЕ живут):
_RUNTIME_ROOT  = Path("/var/lib/xray-installer/dpi-detector")
_STATE_FILE    = Path("/var/lib/xray-installer/dpi_censor_check.json")

# Кэш проверки GitHub: юзер просил «каждый раз смотреть» — при живом GitHub
# проверяем на каждом входе в меню (5 мин — защита от холостого хождениия
# при быстром повторном входе); после НЕудачи пауза 10 мин, чтобы мёртвый
# GitHub не подвешивал вход в меню на таймаутах.
_LATEST_CACHE_TTL = 5 * 60
_LATEST_RETRY_TTL = 10 * 60
_LATEST_TIMEOUT   = 6      # сек, GitHub API (шапка меню не должна подвисать)
_LSREMOTE_TIMEOUT = 10     # сек, git ls-remote (фолбэк без API)

# Что НЕ копируем из tarball апстрима в runtime-копию — тот же список
# исключений, что и при вендоринге (см. VENDOR_INFO.md):
# images/ (~2 MB логотип+скриншот), Docker-обвязка, CI апстрима.
_COPY_EXCLUDE = {
    ".git", ".github", "images", "Dockerfile", "Dockerfile.web",
    "docker-compose.yml", ".gitignore",
}


def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{ts}] [{level}] [dpi_censor_check] {msg}\n")
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════
#  ВЕРСИИ: установленная (с диска) и последняя на GitHub
# ══════════════════════════════════════════════════════════════════════════

def _version_key(version: str) -> tuple:
    """Семвер-ключ версий dpi-detector: (числа, признак_релиза, суффикс).

    Реальные теги апстрима — vX.Y.Z (v4.1.0, v4.0.10, v4.0.3 …), суффиксов
    пока нет, но на будущее rc/beta поддержаны: "4.1.0rc1" < "4.1.0".

    Свойства:
      • числа сравниваются КАК ЧИСЛА: "4.0.10" > "4.0.9" > "4.0.3"
        (строчной сортировкой брать нельзя: "4.0.10" < "4.0.9" строкой);
      • "v"-префикс игнорируется: "v4.1.0" == "4.1.0";
      • мусор/пустая строка сортируются НИЖЕ любых версий.
    """
    v = str(version or "").strip().lower()
    if v.startswith("v"):
        v = v[1:]
    m = re.match(r"^(\d+(?:\.\d+)*)", v)
    if not m:
        return ((), 0, v)
    nums = tuple(int(x) for x in m.group(1).split("."))
    suffix = v[m.end(1):].lstrip("-")     # "" | "rc1" | "beta2"
    is_release = 1 if not suffix else 0
    return (nums, is_release, suffix)


def _parse_entry_version(entry: Path) -> str:
    """Читает CURRENT_VERSION из dpi_detector.py копии (факт с диска)."""
    try:
        text = Path(entry).read_text(errors="replace")[:20000]
    except Exception:
        return ""
    m = re.search(r'CURRENT_VERSION\s*=\s*["\']([^"\']+)["\']', text)
    if not m:
        return ""
    return m.group(1).strip().lstrip("vV")


def _vendor_version() -> str:
    """Версия вендорной копии (entry → VENDOR_INFO.md как фолбэк)."""
    v = _parse_entry_version(_ENTRY)
    if v:
        return v
    try:
        text = (_VENDOR_DIR / "VENDOR_INFO.md").read_text(errors="replace")
        m = re.search(r"Верси\w*\s*\|\s*v?(\d+(?:\.\d+)+)", text)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""


def _parse_dir_version(d: Path) -> str:
    """Читает CURRENT_VERSION из каталога копии dpi-detector.
    Проверяет несколько файлов — в v4.2+ CURRENT_VERSION переместилась
    из dpi_detector.py в app/banner.py.
    """
    for rel in ["dpi_detector.py", "app/banner.py", "core/__init__.py",
                "app/__init__.py", "__init__.py", "version.py"]:
        p = d / rel
        if p.is_file():
            v = _parse_entry_version(p)
            if v:
                return v
    return ""


def _runtime_copies() -> List[Tuple[Path, str]]:
    """Список (каталог, версия) runtime-копий в _RUNTIME_ROOT."""
    out: List[Tuple[Path, str]] = []
    try:
        if not _RUNTIME_ROOT.is_dir():
            return out
        for d in _RUNTIME_ROOT.iterdir():
            try:
                if not d.is_dir() or d.name.startswith(".staging"):
                    continue
                # FIX: в v4.2+ dpi_detector.py может не содержать CURRENT_VERSION
                # (перемещена в app/banner.py). Проверяем все возможные файлы.
                entry = d / "dpi_detector.py"
                if not entry.is_file():
                    # Maybe restructured — check if any .py files exist
                    if not any(d.glob("*.py")) and not any(d.glob("app/*.py")):
                        continue
                out.append((d, _parse_dir_version(d)))
            except OSError:
                continue
    except OSError:
        pass
    return out


def _installed_copy() -> dict:
    """АКТИВНАЯ копия — новейшая из (вендорная, runtime-*).

    Возвращает {} только если инструмента нет вообще (сломана установка
    Химеры). Ключи: dir, version, source ("vendor"|"runtime"), entry, reqs.
    """
    candidates = []
    if _ENTRY.is_file():
        vv = _vendor_version()
        candidates.append((_version_key(vv), _VENDOR_DIR, vv, "vendor"))
    for d, v in _runtime_copies():
        candidates.append((_version_key(v), d, v, "runtime"))
    if not candidates:
        return {}
    _, d, v, src = max(candidates, key=lambda c: c[0])
    # FIX: в v4.2+ dpi_detector.py может импортировать CURRENT_VERSION
    # из app/banner.py. Но точка входа для запуска — всё ещё dpi_detector.py
    # (если он есть). Если нет — ищем альтернативную точку входа.
    entry = d / "dpi_detector.py"
    if not entry.is_file():
        # Альтернативная точка входа (v5+ может иметь __main__.py)
        for alt in ["__main__.py", "main.py", "cli/__init__.py"]:
            alt_p = d / alt
            if alt_p.is_file():
                entry = alt_p
                break
    return {
        "dir": d, "version": v, "source": src,
        "entry": entry, "reqs": d / "requirements.txt",
    }


def _active_entry() -> Path:
    copy = _installed_copy()
    return copy.get("entry") or _ENTRY


def _active_reqs() -> Path:
    copy = _installed_copy()
    return copy.get("reqs") or _REQS


def _load_state() -> dict:
    try:
        return json.loads(_STATE_FILE.read_text())
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    try:
        _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _STATE_FILE.parent / (_STATE_FILE.name + ".tmp")
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2))
        tmp.replace(_STATE_FILE)
    except Exception as e:
        _log("WARN", f"не удалось записать state: {e}")


# ══════════════════════════════════════════════════════════════════════════
#  ПРОВЕРКА ПОСЛЕДНЕЙ ВЕРСИИ НА GITHUB (API → ls-remote, с кэшем)
# ══════════════════════════════════════════════════════════════════════════

def _fetch_latest_api(timeout: float = _LATEST_TIMEOUT) -> str:
    """GitHub API /releases/latest. '' при недоступности/rate-limit."""
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{_UPSTREAM_REPO}/releases/latest",
            headers={
                "User-Agent": "chimera-installer/5.0",
                "Accept": "application/vnd.github+json",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        tag = str(data.get("tag_name", "")).strip()
        return tag.lstrip("vV") or ""
    except Exception as e:
        _log("WARN", f"dpi-detector latest (API): {e}")
        return ""


def _fetch_latest_lsremote(timeout: float = _LSREMOTE_TIMEOUT) -> str:
    """Фолбэк без GitHub API: git ls-remote --tags (не rate-limited).

    Строки вида '<sha>\trefs/tags/v4.1.0'; аннотированные теги дают
    дополнительную строку '<sha>\trefs/tags/v4.1.0^{}' — пропускаем.
    Максимум ищем семвер-ключом (см. _version_key), не строкой.
    """
    try:
        r = subprocess.run(
            ["git", "ls-remote", "--tags", f"https://github.com/{_UPSTREAM_REPO}.git"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except Exception as e:
        _log("WARN", f"dpi-detector latest (ls-remote): {e}")
        return ""
    if r.returncode != 0:
        return ""
    best, best_key = "", None
    for line in r.stdout.splitlines():
        m = re.search(r"refs/tags/(.+)$", line)
        if not m:
            continue
        tag = m.group(1).strip()
        if tag.endswith("^{}") or not tag:
            continue
        v = tag.lstrip("vV")
        key = _version_key(v)
        if best_key is None or key > best_key:
            best, best_key = v, key
    return best if best_key else ""


def _latest_upstream_version(force: bool = False) -> str:
    """Последняя версия апстрима, с кэшем в state (БЕЗ сети при попадании).

    Кэш: успех → актуален 5 мин (юзер просил «каждый раз», но не дёргаем
    GitHub при быстром повторном входе); неудача → ретрай не раньше 10 мин,
    чтобы мёртвый GitHub не подвешивал каждый вход в меню.
    force=True — живая проверка (пункт [4] меню).
    """
    state = _load_state()
    cache = state.get("latest_check") or {}
    now = time.time()
    ttl = _LATEST_CACHE_TTL if cache.get("ok") else _LATEST_RETRY_TTL
    checked = float(cache.get("checked_at") or 0)
    if not force and checked and (now - checked) < ttl:
        return str(cache.get("latest") or "")

    latest = _fetch_latest_api()
    if not latest:
        latest = _fetch_latest_lsremote()
    state["latest_check"] = {
        "latest": latest, "checked_at": int(now), "ok": bool(latest),
    }
    _save_state(state)
    return latest


def _update_available(installed: str, latest: str) -> str:
    """Версия, если latest строго новее installed (иначе '')."""
    if not installed or not latest:
        return ""
    return latest if _version_key(latest) > _version_key(installed) else ""


# ══════════════════════════════════════════════════════════════════════════
#  СКАЧИВАНИЕ И УСТАНОВКА RUNTIME-КОПИИ (git-дерево НЕ трогаем)
# ══════════════════════════════════════════════════════════════════════════

def _codeload_url(version: str) -> str:
    v = str(version).strip().lstrip("vV")
    return f"https://codeload.github.com/{_UPSTREAM_REPO}/tar.gz/refs/tags/v{v}"


def _download_tarball(version: str, dest: Path) -> bool:
    """Скачивает tar.gz апстрима в dest. ~2 MB (включая images/, их не копируем)."""
    url = _codeload_url(version)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "chimera-installer/5.0"})
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = resp.read()
    except Exception as e:
        _log("ERROR", f"скачивание {url}: {e}")
        print(f"{RED}[ERR]{NC} Не удалось скачать {url}")
        print(f"{DIM}{e}{NC}")
        return False
    if len(data) < 1024:
        _log("ERROR", f"tarball подозрительно мал: {len(data)} байт")
        print(f"{RED}[ERR]{NC} Tarball подозрительно мал — обновление отменено.")
        return False
    try:
        dest.write_bytes(data)
    except Exception as e:
        _log("ERROR", f"запись {dest}: {e}")
        return False
    return True


def _extract_tarball(tar_path: Path, dest_dir: Path) -> Optional[Path]:
    """Распаковывает tar.gz; возвращает корень апстрима (каталог с dpi_detector.py)."""
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(
            ["tar", "-xzf", str(tar_path), "-C", str(dest_dir)],
            capture_output=True, text=True, timeout=120,
        )
    except Exception as e:
        _log("ERROR", f"tar: {e}")
        return None
    if r.returncode != 0:
        _log("ERROR", f"tar exit {r.returncode}: {r.stderr[:300]}")
        return None
    for cand in sorted(dest_dir.rglob("dpi_detector.py")):
        return cand.parent        # первый сверху = корень '<repo>-<tag>'
    return None


def _prune_runtime(keep: Path) -> None:
    """Чистит старые версии и staging-мусор в _RUNTIME_ROOT, кроме keep.

    Удаляем ТОЛЬКО каталоги с версионными именами (цифры и точки,
    опциональный префикс 'v') и .staging-* — чужие файлы не трогаем.
    """
    try:
        if not _RUNTIME_ROOT.is_dir():
            return
        for d in _RUNTIME_ROOT.iterdir():
            if d == keep or not d.is_dir():
                continue
            name = d.name
            version_like = re.fullmatch(r"v?\d+(?:\.\d+)*", name)
            if name.startswith(".staging-") or version_like:
                try:
                    shutil.rmtree(d)
                except OSError:
                    pass
    except OSError:
        pass


def _download_and_install(version: str) -> Tuple[bool, str]:
    """Ставит версию апстрима в runtime-копию. git-дерево НЕ трогает.

    Пайплайн: codeload tarball → tmp → проверка версии в архиве →
    копия в .staging-<v> (без images/Docker/CI) → rename в <v> →
    чистка старых версий → state. Любой сбой: staging удаляется,
    вендорная копия остаётся рабочей (инструмент запускаем как раньше).
    """
    v = str(version).strip().lstrip("vV")
    if not v:
        return False, "пустая версия"
    tmp_dir = Path(tempfile.mkdtemp(prefix="dpi-detector-upd-"))
    staging = _RUNTIME_ROOT / f".staging-{v}"
    final = _RUNTIME_ROOT / v
    try:
        if not _download_tarball(v, tmp_dir / "upstream.tar.gz"):
            return False, "не удалось скачать tarball с GitHub"
        root = _extract_tarball(tmp_dir / "upstream.tar.gz", tmp_dir / "extracted")
        if root is None:
            return False, "неожиданная структура архива (нет dpi_detector.py)"
        got = _parse_entry_version(root / "dpi_detector.py")
        if not got:
            # FIX: в v4.2+ CURRENT_VERSION переместилась из dpi_detector.py
            # в app/banner.py. Пробуем альтернативные пути.
            for alt in ["app/banner.py", "core/__init__.py", "app/__init__.py",
                        "__init__.py", "version.py"]:
                alt_path = root / alt
                if alt_path.exists():
                    got = _parse_entry_version(alt_path)
                    if got:
                        _log("INFO", f"CURRENT_VERSION найдена в {alt} "
                                     f"(не в dpi_detector.py)")
                        break
        if got != v:
            return False, f"в архиве версия {got or 'не определена'}, ожидалась {v}"

        # ── сборка runtime-копии ──
        # staging создаём ЯВНО до копирования. Раньше каталог
        # возникал неявно — первым скопированным copytree-директорией
        # (makedirs создаёт промежуточные пути). Если же первым в
        # iterdir() оказывался ФАЙЛ (например LICENSE), copy2 падал
        # FileNotFoundError: порядок readdir зависит от ФС (tmpfs —
        # порядок создания, ext4 — hash) и на проде файл запросто идёт
        # первым. Прод-репорт: .staging-4.1.0/LICENSE, Errno 2.
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(parents=True, exist_ok=True)
        for item in root.iterdir():
            if item.name in _COPY_EXCLUDE:
                continue
            if item.is_dir():
                shutil.copytree(item, staging / item.name,
                                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            else:
                shutil.copy2(item, staging / item.name)
        if not (staging / "dpi_detector.py").is_file():
            return False, "после копирования нет точки входа dpi_detector.py"

        # final может существовать как ФАЙЛ (мусор/обманка с именем
        # версии) — rmtree на нём падает NotADirectoryError; unlink и вперёд.
        if final.exists():
            if final.is_dir():
                shutil.rmtree(final)
            else:
                final.unlink()
        staging.rename(final)
        _prune_runtime(keep=final)

        state = _load_state()
        state["installed_version"] = v
        state["installed_dir"] = str(final)
        state["installed_at"] = int(time.time())
        _save_state(state)
        _log("SUCCESS", f"dpi-detector v{v} установлен в {final}")
        return True, str(final)
    except Exception as e:
        _log("ERROR", f"установка v{v}: {type(e).__name__}: {e}")
        return False, f"{type(e).__name__}: {e}"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        shutil.rmtree(staging, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════════
#  ПРОВЕРКА/УСТАНОВКА ЗАВИСИМОСТЕЙ (от АКТИВНОЙ копии)
# ══════════════════════════════════════════════════════════════════════════
def _deps_missing() -> List[str]:
    """Список недостающих пакетов. find_spec() не импортирует модуль —
    не тратит память основного процесса установщика на httpx/rich."""
    missing = []
    for mod in _REQUIRED_MODULES:
        try:
            found = importlib.util.find_spec(mod) is not None
        except Exception:
            found = False
        if not found:
            missing.append(mod)
    return missing


def _install_deps(reqs: Optional[Path] = None) -> bool:
    reqs = Path(reqs) if reqs else _active_reqs()
    if not reqs.exists():
        print(f"{RED}[ERR]{NC} requirements.txt не найден: {reqs}")
        return False
    print(f"{CYAN}Устанавливаю зависимости (httpx, rich, PyYAML)...{NC}")
    # --ignore-installed: на Debian/Ubuntu PyYAML (и иногда другие пакеты)
    # часто стоят системно через apt (python3-yaml) — у таких пакетов нет
    # файла RECORD, который pip требует для апгрейда/удаления, и без этого
    # флага установка падает с "Cannot uninstall ...: RECORD file not found".
    # Флаг просто ставит свою версию в обход системной, ничего не трогая
    # в apt — безопасно для основного интерпретатора установщика, так как
    # эти зависимости используются только в subprocess для вендоренного
    # dpi_detector, а не импортируются в _core.py.
    cmd = [sys.executable, "-m", "pip", "install", "--break-system-packages",
           "--ignore-installed", "-r", str(reqs)]
    try:
        r = subprocess.run(cmd, timeout=300)
    except Exception as e:
        print(f"{RED}[ERR]{NC} Не удалось запустить pip: {e}")
        _log("ERROR", f"pip install не запустился: {e}")
        return False
    if r.returncode != 0:
        print(f"{RED}[ERR]{NC} pip install завершился с ошибкой (код {r.returncode}).")
        print(f"{DIM}Если PyPI недоступен из-за блокировок — попробуйте вручную:{NC}")
        print(f"{DIM}  {sys.executable} -m pip install --break-system-packages --ignore-installed -r {reqs}{NC}")
        _log("ERROR", f"pip install exit code {r.returncode}")
        return False
    _log("SUCCESS", "зависимости dpi-detector установлены")
    return True


def _ensure_deps() -> bool:
    missing = _deps_missing()
    if not missing:
        return True
    print()
    print(f"{YELLOW}Для запуска нужны пакеты: {', '.join(missing)}{NC}")
    try:
        ans = input(f"{CYAN}Установить через pip сейчас? [Y/n]:{NC} ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False
    if ans in ("n", "no", "н", "нет"):
        return False
    return _install_deps()


# ══════════════════════════════════════════════════════════════════════════
#  ЗАПУСК АКТИВНОЙ (НОВЕЙШЕЙ) КОПИИ ИНСТРУМЕНТА
# ══════════════════════════════════════════════════════════════════════════
def _build_args(domains: Optional[List[str]], proxy: Optional[str],
                 output: Optional[str]) -> List[str]:
    args: List[str] = []
    if domains:
        for d in domains:
            args += ["-d", d]
    if proxy:
        args += ["-p", proxy]
    if output:
        args += ["-o", output]
    return args


def _run_vendor(args: List[str]) -> int:
    """Запускает dpi_detector.py АКТИВНОЙ копии отдельным процессом.

    stdin/stdout/stderr наследуются — апстрим сам рисует свой rich-интерфейс
    и сам ловит Ctrl+C (os._exit() в СВОЁМ процессе, установщик не задевает).
    Активная копия резолвится на момент запуска — если перед запуском
    Химера скачала обновление, запустится именно оно."""
    entry = _active_entry()
    cmd = [sys.executable, str(entry)] + args
    _log("INFO", f"запуск: {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd)
        return r.returncode
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(f"{RED}[ERR]{NC} Не удалось запустить dpi-detector: {e}")
        _log("ERROR", str(e))
        return 1


# ══════════════════════════════════════════════════════════════════════════
#  UI: строки шапки, пункт [4], предложение обновиться перед запуском
# ══════════════════════════════════════════════════════════════════════════

def _version_rows(installed: str, source: str,
                  latest: str) -> Tuple[str, str, str]:
    """Строки шапки меню: (Версия, Обновление, вид подсветки обновления).

    pure-функция без сети и печати — легко тестировать. kind:
    "yellow" — есть обновление; "green" — установлена последняя;
    "dim" — не проверено (GitHub недоступен).
    """
    src = "авто-обновление" if source == "runtime" else "вендорная копия"
    ver_row = f"  Версия: {installed or '—'} ({src})"
    if not latest:
        upd_row = "  Обновление: не проверено (GitHub недоступен) → [4]"
        kind = "dim"
    elif _version_key(latest) > _version_key(installed):
        upd_row = f"  Обновление: v{latest} доступна → [4] Обновить"
        kind = "yellow"
    else:
        upd_row = "  Обновление: нет — установлена последняя версия"
        kind = "green"
    return ver_row, upd_row, kind


def _update_item_label(latest: str, installed: str) -> str:
    """Подпись пункта [4] — зависит от того, что знаем о версиях."""
    if latest and _version_key(latest) > _version_key(installed):
        return f"⬇️  Обновить до v{latest} (скачать с GitHub)"
    if latest:
        return "🔄  Проверить обновления ещё раз"
    return "🔄  Проверить обновления (GitHub)"


def _offer_update_before_launch(update: str, installed: str) -> None:
    """Перед запуском теста: предлагаем скачать последнюю версию.

    Юзер просил: «каждый раз смотрела, какая версия установлена, и
    скачивала/запускала последнюю доступную». Отказ — осознанный escape
    (медленный канал/офлайн): запустится установленная версия.
    """
    if not update:
        return
    print()
    print(f"{YELLOW}Доступна новая версия dpi-detector: v{update} "
          f"(установлена: v{installed or '—'}).{NC}")
    print(f"{YELLOW}Автор апстрима часто релизит — новые тесты и фиксы.{NC}")
    try:
        ans = input(f"{CYAN}Скачать и запустить последнюю версию? [Y/n]:{NC} ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return
    if ans in ("n", "no", "н", "нет"):
        return
    ok, msg = _download_and_install(update)
    if ok:
        print(f"{GREEN}Обновлено до v{update} — запускаю обновлённую версию.{NC}")
    else:
        print(f"{YELLOW}Обновление не удалось: {msg}{NC}")
        print(f"{YELLOW}Запускаю установленную версию (v{installed or '—'}).{NC}")


def _do_update_action(installed: str) -> None:
    """Пункт [4]: живая проверка GitHub (force) + установка при обновлении."""
    print()
    print(f"{CYAN}Проверяю последнюю версию на GitHub (Runnin4ik/dpi-detector)...{NC}")
    latest = _latest_upstream_version(force=True)
    if not latest:
        print()
        _box_top("Обновление dpi-detector")
        _box_warn("Не удалось узнать последнюю версию — GitHub недоступен.")
        _box_row(f"  Попробуйте позже или скачайте вручную: {_UPSTREAM_URL}")
        _box_bottom()
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return
    upd = _update_available(installed, latest)
    if not upd:
        print()
        _box_top("Обновление dpi-detector")
        _box_ok(f"Установлена последняя версия: v{installed or '—'}")
        _box_bottom()
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return
    print(f"{CYAN}Скачиваю v{upd} с codeload.github.com (~2 MB)...{NC}")
    ok, msg = _download_and_install(upd)
    print()
    if ok:
        _box_top("Обновление dpi-detector")
        _box_ok(f"Установлена версия v{upd}")
        _box_row(f"  Каталог: {_RUNTIME_ROOT / upd}")
        _box_row("  Вендорная копия в git-дереве не тронута (офлайн-фолбэк).")
        _box_bottom()
    else:
        _box_top("Обновление dpi-detector")
        _box_warn(f"Обновление до v{upd} не удалось: {msg}")
        _box_row("  Текущая версия не тронута — инструмент работает как раньше.")
        _box_bottom()
    input(f"\n{BLUE}Нажмите Enter...{NC}")


# ── Публичная точка входа ────────────────────────────────────────────────────────
def do_dpi_censor_check_menu() -> None:
    """Главное меню. Вызывается из _core.py."""
    copy = _installed_copy()
    if not copy:
        print()
        _box_top("🔍  ПРОВЕРКА ЦЕНЗУРЫ ПРОВАЙДЕРА")
        _box_warn("dpi-detector не найден ни в вендорной копии, ни в runtime:")
        _box_row(f"  {_VENDOR_DIR}")
        _box_row(f"  {_RUNTIME_ROOT}")
        _box_info("Переустановите Химеру (git pull / повторная установка).")
        _box_bottom()
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    installed = copy["version"]
    source = copy["source"]

    # «Каждый раз смотрела, какая версия установлена»: версия — факт с диска;
    # проверка GitHub — тихая (кэш 5 мин, таймаут 6+10 сек в худшем случае).
    latest = _latest_upstream_version()
    upd = _update_available(installed, latest)

    os.system("clear")
    print()
    _box_top("🔍  ПРОВЕРКА ЦЕНЗУРЫ ПРОВАЙДЕРА  (Runnin4ik/dpi-detector)")
    _box_desc(
        "Сторонний инструмент: определяет блокировку TLS/TCP/HTTP/DNS, обрыв "
        "соединений на 16-20KB и подмену DNS-ответов провайдером. Не путать "
        "с пунктом «D» в разделе Безопасность — там анализ ИЗВНЕ, здесь — что "
        "блокирует провайдер."
    )
    _box_sep()
    ver_row, upd_row, kind = _version_rows(installed, source, latest)
    _box_row(ver_row)
    color = {"yellow": YELLOW, "green": GREEN, "dim": DIM}.get(kind, "")
    _box_row(f"{color}{upd_row}{NC}" if color else upd_row)
    _box_sep()
    _box_warn(
        "Если на этом сервере/клиенте уже работает zapret или GoodbyeDPI — "
        "результаты будут искажены. Отключите их перед проверкой."
    )
    _box_sep()
    _box_item("1", "🚀 Запустить (интерактивный выбор тестов, как у апстрима)")
    _box_item("2", "🌐 Проверить конкретные домены")
    _box_item("3", "🧦 Запустить через proxy (socks5/http)")
    _box_item("4", _update_item_label(latest, installed))
    _box_back()
    _box_bottom()

    try:
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return

    if ch not in ("1", "2", "3", "4"):
        return

    if ch == "4":
        _do_update_action(installed)
        return

    # Перед запуском теста: если есть обновление — предложить скачать
    # последнюю версию и запустить именно её (по умолчанию Y).
    if upd:
        _offer_update_before_launch(upd, installed)

    if not _ensure_deps():
        print(f"{YELLOW}Зависимости не установлены — запуск отменён.{NC}")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    domains: Optional[List[str]] = None
    proxy: Optional[str] = None

    if ch == "2":
        try:
            raw = input(f"{CYAN}Домены через пробел:{NC} ").strip()
        except (KeyboardInterrupt, EOFError):
            return
        domains = raw.split() if raw else None
    elif ch == "3":
        try:
            proxy = input(
                f"{CYAN}Proxy URL (напр. socks5://127.0.0.1:1080):{NC} "
            ).strip() or None
        except (KeyboardInterrupt, EOFError):
            return

    try:
        save = input(f"{CYAN}Сохранить отчёт в файл? [y/N]:{NC} ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        save = ""

    output = None
    if save in ("y", "yes", "д", "да"):
        try:
            _REPORT_DIR.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output = str(_REPORT_DIR / f"report_{ts}.txt")
        except Exception as e:
            print(f"{YELLOW}Не удалось создать {_REPORT_DIR}: {e}{NC}")
            output = None

    args = _build_args(domains, proxy, output)

    print()
    rc = _run_vendor(args)

    if output and Path(output).exists():
        print()
        _box_top("Отчёт сохранён")
        _box_row(f"  {output}")
        _box_bottom()
    elif rc not in (0, 130):
        print(f"{YELLOW}dpi-detector завершился с кодом {rc}.{NC}")

    input(f"\n{BLUE}Нажмите Enter...{NC}")


if __name__ == "__main__":
    # Автономный запуск для отладки модуля (вне установщика).
    do_dpi_censor_check_menu()
