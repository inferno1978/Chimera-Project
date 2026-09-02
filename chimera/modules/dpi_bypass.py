"""
chimera/modules/youtube_b4.py
───────────────────────────────────────────────────────────────────────────────
b4 (Bye Bye Big Bro) — DPI bypass на entry-ноде для YouTube.

КОНЦЕПЦИЯ (обсуждена с автором Chimera):
  ТСПУ, который душит YouTube, сидит между entry VPS и YouTube CDN —
  не между клиентом и entry. Трафик «клиент → entry» уже защищён
  Reality (это работает). Нужно защищать трафик «entry → YouTube».

  b4 ставится на entry VPS как systemd-сервис. nftables/iptables
  mangle перехватывает ИСХОДЯЩИЙ TCP-трафик от Xray к YouTube CDN:443
  и применяет DPI bypass:
    1. Фейковый DuckDouncego ClientHello (DPI читает, сервер отбросит)
    2. Фрагментация реального ClientHello (combo стратегия)
    3. (опционально) Fake RST для corrupt DPI state
    4. SNI-aware split (разрез в середине SNI)
  ТСПУ не может сопоставить → пропускает.

АРХИТЕКТУРА:
  Клиент (без изменений) → VLESS Reality → Entry VPS:
    Xray (inbound :443) → routing: geosite:youtube → outbound:direct
    → freedom outbound открывает TCP к youtube.com:443
    → iptables mangle OUTPUT → NFQUEUE
    → b4 daemon (Go, NFQUEUE worker)
      → SNI match → DROP original + inject fake+fragmented
      → raw socket → YouTube CDN
    → ТСПУ не видит SNI → пропускает → YouTube

ИНТЕГРАЦИЯ С CHIMERA:
  • youtube_route.py уже маршрутизирует geosite:youtube → direct на entry
    (TUI пункт Y). b4 работает поверх — перехватывает исходящий direct-
    трафик. Конфиг Xray НЕ ТРОГАЕТ.
  • Не конфликтует с UFW/iptables (b4 в mangle таблице, Chimera — filter).
  • Не конфликтует с ingress_geoip (b4 в OUTPUT, geoip в INPUT).
  • Discovery — b4 умеет сам подобрать рабочий сет под текущего провайдера.

ВАЖНО: b4 — статически слинкованный Go binary (17MB). Не требует
зависимостей. Установка = скачать + chmod + systemd-unit.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

# ── Цвета ─────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m',
            WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, WHITE, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'],
    _C['BOLD'], _C['DIM'], _C['WHITE'], _C['NC'],
)

# ── Логирование (единый формат с остальными модулями) ──────────────────────
_LOG_FILE = Path("/var/log/chimera.log")

def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        with _LOG_FILE.open("a") as f:
            f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [youtube_b4] [{level}] {clean}\n")
    except Exception:
        pass

def _info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");  _log("INFO", msg)
def _ok(msg: str)      -> None: print(f"{GREEN}[OK]{NC}    {msg}"); _log("OK", msg)
def _warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)
def _err(msg: str)     -> None: print(f"{RED}[ERR]{NC}   {msg}");   _log("ERR", msg)

# ── box_renderer (UI меню, общий для всех модулей) ────────────────────────
from chimera.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_item_exit,
    _box_back, _box_info, _box_warn, _box_ok, _box_link, _box_desc,
)

# ── Делегирование в _core.py ──────────────────────────────────────────────
def _core_module():
    import importlib
    return importlib.import_module("chimera._core")

def _core_call(func_name: str, *args, **kwargs):
    return getattr(_core_module(), func_name)(*args, **kwargs)

# ══════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════

# b4 binary — статически слинкованный Go binary, не требует зависимостей.
B4_VERSION = "1.78.0"
B4_BINARY_PATH = Path("/usr/local/bin/b4")
B4_CONFIG_DIR  = Path("/etc/b4")
B4_CONFIG_FILE = B4_CONFIG_DIR / "config.json"


# ── Geosite.dat для b4 (system.geo.sitedat_path) ──────────────────────────
# v75.1: путь geosite для b4 — ВСЕГДА собственный /etc/b4/geosite.dat
# («как это необходимо B4»). Web UI b4 берёт Destination Directory из
# dirname(sitedat_path) и качает туда базу при Update; auto_update b4
# пишет туда же. Наш systemd-юнит (ProtectSystem=strict +
# ReadWritePaths=/etc/b4) делает /usr read-only для процесса b4 — любой
# путь в /usr (легаси-хардкод Chimera /usr/share/xray или v72.4-«общий»
# /usr/local/share/xray) ломает Update геосайта: mkdir/write → EROFS →
# 500 (инциденты на трёх машинах: chimeravpn.online, x2, picaresque).
# Шарить один geosite.dat с Xray нельзя: чтение работает, Update — нет.
# Общий файл Xray остаётся только seed-источником первой копии
# (_seed_b4_geosite копирует, не линкует: Xray обновляет свой файл,
# b4 — свой).
B4_XRAY_GEOSITE_LEGACY  = "/usr/share/xray/geosite.dat"
B4_GEOSITE_SHARED_PATHS = ("/usr/local/share/xray/geosite.dat",
                           "/usr/share/xray/geosite.dat")
B4_GEOSITE_LOCAL_PATH   = str(B4_CONFIG_DIR / "geosite.dat")
# Источник geosite-базы — тот же, что Chimera ставит для Xray
# (runetfreedom/russia-v2ray-rules-dat, см. geo_mirrors/download_manager):
# seed-копия и автообновление b4 качают одну и ту же базу.
B4_GEOSITE_URL          = ("https://raw.githubusercontent.com/runetfreedom/"
                           "russia-v2ray-rules-dat/release/geosite.dat")
B4_GEOIP_URL            = ("https://github.com/DanielLavrushin/b4geoip/"
                           "releases/latest/download/geoip.dat")


def _b4_geosite_path() -> str:
    """Путь geosite.dat для system.geo.sitedat_path — всегда /etc/b4/geosite.dat.

    «Как это необходимо B4»: собственный записываемый каталог b4 —
    дефолтная Destination Directory Web UI b4 и единственный каталог
    гео-баз в ReadWritePaths systemd-юнита. B4_GEOSITE_LOCAL_PATH
    читается при вызове (тестируется патчем).
    """
    return B4_GEOSITE_LOCAL_PATH


def _seed_b4_geosite() -> bool:
    """Копирует geosite.dat Xray в /etc/b4, если базы у b4 ещё нет (seed).

    Копия, не ссылка: b4 обновляет свой файл через Web UI/auto_update,
    Xray — своим механизмом (geo-модули Chimera); шаринг одного файла
    ломал Update b4 (EROFS на /usr). Если общего файла Xray нет — не
    делаем ничего: базу скачает сам b4 (auto_update.on_startup, 45с
    после старта) или юзер через Web UI (Destination Directory
    по умолчанию — /etc/b4). B4_GEOSITE_SHARED_PATHS и
    B4_GEOSITE_LOCAL_PATH читаются при вызове (тестируются патчем).
    """
    local = Path(B4_GEOSITE_LOCAL_PATH)
    if local.exists():
        return False
    for src_path in B4_GEOSITE_SHARED_PATHS:
        src = Path(src_path)
        if src.is_file() and src.stat().st_size > 0:
            try:
                local.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, local)
                _info(f"Geosite-база посеяна: {src} → {local} "
                      f"({local.stat().st_size // 1024} KB)")
                return True
            except OSError as e:
                _warn(f"Не удалось скопировать geosite {src} → {local}: {e}")
    return False


def _b4_heal_geo_paths(geo: dict) -> bool:
    """Лечит мёртвые для b4 sitedat-пути in-place, True если были изменения.

    Мёртвые пути = легаси-хардкод Chimera /usr/share/xray/geosite.dat и
    «общие» пути Xray (B4_GEOSITE_SHARED_PATHS: /usr/local/share/xray,
    /usr/share/xray) — ДАЖЕ если файл там существует: /usr read-only
    для процесса b4 (ProtectSystem=strict), а Web UI b4 берёт
    Destination Directory из dirname(sitedat_path) → Update геосайта
    = mkdir/write в /usr → 500 EROFS. Переводим на собственный
    /etc/b4/geosite.dat; sitedat_url и auto_update дозаполняем только
    когда пусты (пользовательские значения не трогаем). Произвольные
    пользовательские пути sitedat_path не лечим.
    B4_GEOSITE_SHARED_PATHS/B4_GEOSITE_LOCAL_PATH читаются при вызове.
    """
    if not isinstance(geo, dict):
        return False
    dead = set(B4_GEOSITE_SHARED_PATHS) | {B4_XRAY_GEOSITE_LEGACY}
    if geo.get("sitedat_path") not in dead:
        return False
    geo["sitedat_path"] = B4_GEOSITE_LOCAL_PATH
    if not geo.get("sitedat_url"):
        geo["sitedat_url"] = B4_GEOSITE_URL
    if not geo.get("auto_update"):
        geo["auto_update"] = {"on_startup": True, "interval": "weekly"}
    return True


def _b4_geo_section() -> dict:
    """Секция system.geo для нового b4-конфига (пути geosite/geoip)."""
    return {
        "sitedat_path": _b4_geosite_path(),
        "sitedat_url": B4_GEOSITE_URL,
        "ipdat_path": str(B4_CONFIG_DIR / "geoip.dat"),
        "ipdat_url": B4_GEOIP_URL,
        # Нативное самовосстановление b4: если базы пропадут — перекачает
        # через ~45с после старта (5 мин ретраев); weekly — фоновый рефреш.
        "auto_update": {"on_startup": True, "interval": "weekly"},
    }
B4_SETS_DIR    = B4_CONFIG_DIR / "sets"
B4_LOG_DIR     = Path("/var/log/b4")
B4_UNIT_PATH   = Path("/etc/systemd/system/b4.service")

# iptables: b4 работает в mangle таблице, OUTPUT chain (исходящий трафик).
# Важно: не трогаем INPUT (там сидит UFW + ingress_geoip + split_tunnel).
# Queue number — уникальный, не должен конфликтовать с другими NFQUEUE
# пользователями (537 — дефолт b4, редко занят).
B4_QUEUE_NUM   = 537
B4_MARK         = 32768  # SO_MARK для raw socket пакетов (чтобы исключить ре-queue)
B4_IPT_COMMENT  = "chimera-youtube-b4"

# nginx front для b4 Web UI — по аналогии с User Portal и подпиской.
# b4 Web UI слушает 0.0.0.0:9700 (HTTP, без TLS). nginx front ставит
# TLS перед ним (LE или self-signed), доступ через браузер напрямую.
B4_NGINX_SITE_NAME   = "chimera-b4-nginx"
B4_NGINX_STATE_FILE  = Path("/var/lib/xray-installer/b4_nginx_front.json")
DEFAULT_B4_NGINX_PORT = 9743  # не конфликтует с 9443 (User Portal), 9444 (Subscription)

# Web UI b4 (для Discovery и управления через браузер).
# Default 7000, но может конфликтовать — переключаем на 9700.
B4_WEB_PORT     = 9700

# ══════════════════════════════════════════════════════════════════════════
#  ДЕФОЛТНЫЕ СЕТЫ
# ══════════════════════════════════════════════════════════════════════════

#  КАНОН QUIC-БЛОКА (b4 >= 1.79, docs: sets/udp.md + Web UI «Блокировать QUIC»):
#  per-set "udp": {"filter_quic": "all", "mode": "reject"}.
#  filter_quic и mode живут ТОЛЬКО внутри сета — верхнего уровня "udp"
#  в Config b4 нет (queue/system/sets/ui), значения "block" не существует:
#  NormalizeQUICFilter переименует всё, кроме "all", в "sni".
#  "reject" = дроп + ICMP port unreachable → мгновенный откат браузера
#  на TCP/HTTP2, где работают fake SNI + фрагментация.
_B4_QUIC_BLOCK_UDP = {
    "mode": "reject",
    "filter_quic": "all",
}

# Эталонный сет юзера (DuckDuckGo fake + combo fragmentation).
# Проверен на провайдере юзера — работает с b4 на роутере.
# На VPS может потребоваться Discovery для подбора под конкретного хостера.
DEFAULT_SET_YOUTUBE = {
    "id": "youtube",
    "name": "Youtube",
    "enabled": True,
    "tcp": {
        "seg2delay": 20,
        "seg2delay_max": 60,
    },
    "udp": dict(_B4_QUIC_BLOCK_UDP),
    "faking": {
        "ttl": 4,
        "sni_type": 3,  # DuckDuckGo preset
        # strategy по умолчанию "pastseq" (сервер отбрасывает по TCP-seq)
        # sni=true, sni_seq_length=1 — из defaults b4
    },
    "targets": {
        "sni_domains": [
            "youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com",
            "youtu.be", "youtube-nocookie.com", "youtubeeducation.com",
            "youtubei.googleapis.com", "youtube-googletag.com",
            "manifest.googlevideo.com", "i.ytimg.com", "wide.youtube.com",
            "accounts.youtube.com", "m.youtube.com", "tv.youtube.com",
            "gaming.youtube.com", "music.youtube.com", "studio.youtube.com",
            "ads.youtube.com", "creators.youtube.com",
            "developers.google.com", "cloud.youtube.com",
        ],
    },
    "dns": {
        "enabled": True,
        "doh_url": "https://1.1.1.1/dns-query",
    },
}

# Альтернативный сет — более агрессивный (Google fake + disorder + меньше delay).
# Может работать там, где DuckDuckGo-preset перестал работать.
AGGRESSIVE_SET_YOUTUBE = {
    "id": "youtube",
    "name": "Youtube-Aggressive",
    "enabled": True,
    "tcp": {
        "seg2delay": 10,
        "seg2delay_max": 30,
    },
    "udp": dict(_B4_QUIC_BLOCK_UDP),
    "faking": {
        "ttl": 4,
        "sni_type": 2,  # Google preset (www.google.com)
    },
    "targets": {
        "sni_domains": [
            "youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com",
            "youtu.be", "youtube-nocookie.com", "youtubeeducation.com",
            "youtubei.googleapis.com", "youtube-googletag.com",
            "manifest.googlevideo.com", "i.ytimg.com", "wide.youtube.com",
            "accounts.youtube.com", "m.youtube.com", "tv.youtube.com",
            "gaming.youtube.com", "music.youtube.com", "studio.youtube.com",
            "ads.youtube.com", "creators.youtube.com",
            "developers.google.com", "cloud.youtube.com",
        ],
    },
    "dns": {
        "enabled": True,
        "doh_url": "https://1.1.1.1/dns-query",
    },
}

# Лёгкий сет — без fake SNI, только фрагментация.
# Минимальный оверхед, для «поверхностного» DPI.
LIGHT_SET_YOUTUBE = {
    "id": "youtube",
    "name": "Youtube-Light",
    "enabled": True,
    "tcp": {
        "seg2delay": 30,
        "seg2delay_max": 80,
    },
    "udp": dict(_B4_QUIC_BLOCK_UDP),
    "faking": {
        # Fake SNI выключен — только фрагментация
        "sni": False,
    },
    "targets": {
        "sni_domains": [
            "youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com",
            "youtu.be", "youtube-nocookie.com", "youtubeeducation.com",
            "youtubei.googleapis.com", "youtube-googletag.com",
            "manifest.googlevideo.com", "i.ytimg.com", "wide.youtube.com",
            "accounts.youtube.com", "m.youtube.com", "tv.youtube.com",
            "gaming.youtube.com", "music.youtube.com", "studio.youtube.com",
            "ads.youtube.com", "creators.youtube.com",
            "developers.google.com", "cloud.youtube.com",
        ],
    },
    "dns": {
        "enabled": True,
        "doh_url": "https://1.1.1.1/dns-query",
    },
}

PRESETS = {
    "default":    ("Эталон (DuckDuckGo fake + combo)",        DEFAULT_SET_YOUTUBE),
    "aggressive": ("Агрессивный (Google fake + меньше delay)", AGGRESSIVE_SET_YOUTUBE),
    "light":      ("Лёгкий (только фрагментация, без fake)",   LIGHT_SET_YOUTUBE),
}

# ══════════════════════════════════════════════════════════════════════════
#  STATE / CONFIG
# ══════════════════════════════════════════════════════════════════════════

_STATE_FILE = Path("/var/lib/xray-installer/youtube_b4_state.json")

def _load_state() -> dict:
    if not _STATE_FILE.exists():
        return {"installed": False, "active_preset": None, "enabled": False}
    try:
        return json.loads(_STATE_FILE.read_text())
    except Exception as e:
        _warn(f"youtube_b4_state.json повреждён: {e}")
        return {"installed": False, "active_preset": None, "enabled": False}

def _save_state(state: dict) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    _STATE_FILE.chmod(0o600)

# ══════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА / УДАЛЕНИЕ B4
# ══════════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════════
#  ДЕТЕКТ УСТАНОВКИ (shared с youtube_b4.py)
# ══════════════════════════════════════════════════════════════════════════
def _detect_installed() -> bool:
    """Проверяет установлен ли b4 (binary + systemd-unit)."""
    return B4_BINARY_PATH.exists() and B4_UNIT_PATH.exists()


def _detect_service_active() -> bool:
    """Проверяет запущен ли сервис b4."""
    r = subprocess.run(["systemctl", "is-active", "b4"],
                       capture_output=True, text=True, check=False)
    return (r.returncode == 0 and r.stdout.strip() == "active")


def _detect_version() -> str:
    """Получает версию установленного b4 binary."""
    if not B4_BINARY_PATH.exists():
        return ""
    try:
        r = subprocess.run([str(B4_BINARY_PATH), "--version"],
                           capture_output=True, text=True, check=False, timeout=5)
        m = re.search(r'B4 version:\s*(\S+)', r.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""


def _detect_latest_version() -> str:
    """Проверяет последнюю версию b4 на GitHub."""
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/DanielLavrushin/b4/releases/latest",
            headers={"User-Agent": "chimera-installer/5.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        tag = data.get("tag_name", "")
        if tag.startswith("v"):
            tag = tag[1:]
        return tag
    except Exception as e:
        _log("WARN", f"check_latest_version: {e}")
        return ""


def _detect_sets() -> list:
    """Читает текущие set'ы из config.json b4."""
    if not B4_CONFIG_FILE.exists():
        return []
    try:
        cfg = json.loads(B4_CONFIG_FILE.read_text())
        sets = cfg.get("sets", [])
        result = []
        for s in sets:
            result.append({
                "id":       s.get("id", "?"),
                "name":     s.get("name", "?"),
                "enabled":  s.get("enabled", True),
                "domains":  s.get("targets", {}).get("sni_domains", []),
                "sni_type": s.get("faking", {}).get("sni_type", ""),
            })
        return result
    except Exception:
        return []


# ══════════════════════════════════════════════════════════════════════════
#  АВТООБНОВЛЕНИЕ B4 BINARY (release + pre-release)
# ══════════════════════════════════════════════════════════════════════════
#  Эти функции зеркалируют youtube_b4.py — оба модуля работают с одним
#  binary /usr/local/bin/b4, поэтому обновление из любого модуля видно
#  другому сразу (через общий config + binary + state).
# ══════════════════════════════════════════════════════════════════════════

def sync_b4_version_state() -> dict:
    """Синхронизация версии b4 между связанными модулями Chimera.

    Модули dpi_bypass.py (централизованный «DPI Bypass») и
    youtube_b4.py («YouTube через B4») работают с ОДНИМ binary
    (/usr/local/bin/b4) и ОДНИМ общим state-файлом
    (/var/lib/xray-installer/youtube_b4_state.json). Но b4 можно
    обновить и мимо Chimera — из собственного Web UI b4
    (Settings → Update), через install.sh или заменив binary вручную.
    В этом случае binary меняется, а state["version"] остаётся со
    старой версией — меню врут.

    Функция читает ФАКТИЧЕСКУЮ версию binary (`b4 --version`) и
    записывает её в общий state. Поскольку state один на оба модуля —
    после вызова оба меню (DPI Bypass и YouTube через B4) показывают
    одну и ту же актуальную версию.

    Вызывается:
      • при входе в раздел «Обновление Bye Bye Big Bro» (оба модуля);
      • после каждого успешного обновления (release / pre-release).

    Возвращает dict:
      {"synced": bool,          — была ли перезаписана версия в state
       "version": str,          — фактическая версия binary ("" если нет)
       "old_state_version": str — что было в state до синхронизации}
    """
    version = _detect_version()
    state = _load_state()
    old = state.get("version", "")
    # Пишем только если binary отдаёт версию и она отличается от state.
    if version and version != old:
        state["version"] = version
        _save_state(state)
        _log("INFO", f"sync_b4_version_state: {old or '—'} → {version} "
                     f"(общий state обновлён, видят оба модуля)")
        return {"synced": True, "version": version, "old_state_version": old}
    return {"synced": False, "version": version, "old_state_version": old}


def _detect_latest_prerelease_version() -> str:
    """Проверяет последнюю ПРЕ-релизную версию b4 на GitHub.

    GitHub API endpoint `/releases/latest` возвращает только стабильные
    релизы (prerelease=false). Для pre-release нужно использовать
    `/releases` (возвращает массив ВСЕХ релизов, включая pre-release) и
    отфильтровать где prerelease=true. Берём первый — он самый свежий.

    Возвращает "" если:
      - нет pre-release релизов (только стабильные)
      - сетевая ошибка / GitHub недоступен
    """
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/DanielLavrushin/b4/releases",
            headers={"User-Agent": "chimera-installer/5.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        # data — список релизов, отсортированных GitHub'ом от новых к старым.
        # Ищем первый где prerelease=true.
        for release in data:
            if release.get("prerelease", False):
                tag = release.get("tag_name", "")
                if tag.startswith("v"):
                    tag = tag[1:]
                return tag
        return ""  # Pre-release релизов нет
    except Exception as e:
        _log("WARN", f"check_latest_prerelease_version: {e}")
        return ""


def _do_b4_binary_update(old_version: str, target_version: str) -> dict:
    """Скачивает и устанавливает конкретную версию b4 binary.

    Общая логика для auto_update() (release) и auto_update_prerelease().
    НЕ делает проверку версии через GitHub API — caller передаёт уже
    известный target_version. Делает всё остальное:
      1. Архитектура
      2. Скачать tar.gz
      3. SHA256 verify (опционально — если .sha256 файл недоступен, skip)
      4. Распаковать
      5. Остановить сервис
      6. Backup + replace binary
      7. Запустить + verify (если не запустилась — откат)
      8. Обновить state.json (version)
      9. Cleanup

    Возвращает dict с ключами: updated, old_version, new_version, message.
    """
    arch = _detect_arch()
    if not arch:
        return {"updated": False, "old_version": old_version,
                "message": "Неподдерживаемая архитектура"}

    url = f"https://github.com/DanielLavrushin/b4/releases/download/v{target_version}/b4-linux-{arch}.tar.gz"
    tmp_tar = Path("/tmp/b4-update.tar.gz")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "chimera-installer/5.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            tmp_tar.write_bytes(resp.read())
    except Exception as e:
        return {"updated": False, "old_version": old_version,
                "message": f"Скачивание не удалось: {e}"}

    # SHA256 проверка.
    sha_url = url + ".sha256"
    try:
        req = urllib.request.Request(sha_url, headers={"User-Agent": "chimera-installer/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            expected_sha = resp.read().decode().strip().split()[0]
        import hashlib
        actual_sha = hashlib.sha256(tmp_tar.read_bytes()).hexdigest()
        if expected_sha and actual_sha != expected_sha:
            tmp_tar.unlink(missing_ok=True)
            return {"updated": False, "old_version": old_version,
                    "message": "SHA256 mismatch"}
        _ok(f"SHA256 проверен: {actual_sha[:16]}...")
    except Exception:
        _warn("SHA256 файл недоступен — пропуск проверки")

    # Распаковать.
    extract_dir = Path("/tmp/b4-update-extract")
    shutil.rmtree(extract_dir, ignore_errors=True)
    try:
        with tarfile.open(tmp_tar, "r:gz") as tf:
            tf.extractall(path=extract_dir)
    except Exception as e:
        tmp_tar.unlink(missing_ok=True)
        return {"updated": False, "old_version": old_version,
                "message": f"Распаковка не удалось: {e}"}

    new_binary = extract_dir / "b4"
    if not new_binary.exists():
        tmp_tar.unlink(missing_ok=True)
        return {"updated": False, "old_version": old_version,
                "message": "В архиве нет b4 binary"}

    # Остановить сервис.
    _info("Останавливаю b4...")
    subprocess.run(["systemctl", "stop", "b4"], capture_output=True, check=False)

    # Backup + replace.
    backup_path = B4_BINARY_PATH.with_suffix(".bak")
    try:
        shutil.copy2(B4_BINARY_PATH, backup_path)
    except Exception:
        pass
    try:
        shutil.copy2(new_binary, B4_BINARY_PATH)
        B4_BINARY_PATH.chmod(0o755)
    except Exception as e:
        if backup_path.exists():
            shutil.copy2(backup_path, B4_BINARY_PATH)
            B4_BINARY_PATH.chmod(0o755)
        return {"updated": False, "old_version": old_version,
                "message": f"Замена binary не удалась: {e}"}

    # Запустить + проверить.
    _info("Запускаю b4...")
    subprocess.run(["systemctl", "start", "b4"], capture_output=True, check=False)
    time.sleep(2)

    if not _detect_service_active():
        _err("Новая версия не запустилась — восстанавливаю предыдущую...")
        subprocess.run(["systemctl", "stop", "b4"], capture_output=True, check=False)
        if backup_path.exists():
            shutil.copy2(backup_path, B4_BINARY_PATH)
            B4_BINARY_PATH.chmod(0o755)
        subprocess.run(["systemctl", "start", "b4"], capture_output=True, check=False)
        time.sleep(2)
        return {"updated": False, "old_version": old_version,
                "message": "Новая версия не запустилась — восстановлена предыдущая"}

    # Обновить state.
    new_version = _detect_version()
    state = _load_state()
    state["version"] = new_version
    _save_state(state)

    # Cleanup.
    backup_path.unlink(missing_ok=True)
    shutil.rmtree(extract_dir, ignore_errors=True)
    tmp_tar.unlink(missing_ok=True)

    _ok(f"b4 обновлён: {old_version} → {new_version}")
    _info("Конфиг и set'ы сохранены без изменений.")
    return {"updated": True, "old_version": old_version,
            "new_version": new_version,
            "message": f"Обновлено: {old_version} → {new_version}"}


def auto_update(force: bool = False) -> dict:
    """Проверяет и обновляет b4 binary до последней СТАБИЛЬНОЙ версии.

    1. Проверка GitHub API /releases/latest → последняя стабильная версия.
    2. Сравнение с установленной.
    3. Скачать → SHA256 → stop → backup → replace → start → verify.
    4. Конфиг и set'ы НЕ затрагиваются.

    Параметр force (bool):
      False — если установленная версия совпадает с последней release,
              обновление не выполняется («уже актуальная версия»).
      True  — ПРИНУДИТЕЛЬНАЯ установка последней release-версии, даже
              если она совпадает с установленной. Полезно: переустановка
              поверх повреждённого binary, откат с pre-release на
              стабильную, восстановление после обновления мимо Chimera
              (Web UI b4 → Settings → Update, install.sh).

    Для PRE-RELEASE обновлений используйте auto_update_prerelease().
    """
    if not _detect_installed():
        return {"updated": False, "message": "b4 не установлен"}

    old_version = _detect_version()
    latest = _detect_latest_version()
    if not latest:
        return {"updated": False, "old_version": old_version,
                "message": "Не удалось проверить последнюю версию"}

    if old_version == latest and not force:
        return {"updated": False, "old_version": old_version,
                "new_version": latest, "message": f"Уже актуальная версия {old_version}"}

    if old_version == latest:
        _info(f"Принудительная переустановка release-версии: {latest}")
    else:
        _info(f"Обновление: {old_version} → {latest}")
    return _do_b4_binary_update(old_version, latest)


def auto_update_prerelease(confirm: bool = True, force: bool = False) -> dict:
    """Обновляет b4 binary до последней ПРЕ-релизной версии.

    Симметрична auto_update(), но использует GitHub API /releases для
    поиска pre-release версий (prerelease=true). Pre-release — это
    бета/RC версии, которые могут содержать баги и нестабильные изменения.

    Параметр confirm (bool):
      True  — печатает warning пользователю перед обновлением
              (используется в TUI-меню для интерактивного подтверждения).
      False — обновляет без подтверждения (для REST API / тестов).
              Warning ВСЕГДА печатается через _warn() — он попадает в лог,
              но не требует ответа пользователя.

    Параметр force (bool):
      False — если установлена та же pre-release версия — откат без
              переустановки.
      True  — ПРИНУДИТЕЛЬНАЯ переустановка той же pre-release версии
              (например, binary повреждён или заменён мимо Chimera).

    Возвращает тот же формат dict что и auto_update().
    """
    if not _detect_installed():
        return {"updated": False, "message": "b4 не установлен"}

    old_version = _detect_version()
    latest_pre = _detect_latest_prerelease_version()
    if not latest_pre:
        return {"updated": False, "old_version": old_version,
                "message": "Pre-release версии не найдены на GitHub"}

    if old_version == latest_pre and not force:
        return {"updated": False, "old_version": old_version,
                "new_version": latest_pre,
                "message": f"Уже установлена pre-release версия {old_version}"}

    # Warning всегда печатается (для лога).
    _warn(f"⚠  Установка PRE-RELEASE версии b4: {old_version} → {latest_pre}")
    _warn("Установка preprelease версии может привести к ошибкам и нестабильной работе.")

    if confirm:
        try:
            ans = input(
                f"{YELLOW}Вы точно хотите установить preprelease версию {latest_pre}? [y/N]:{NC} "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans not in ("y", "yes", "д", "да"):
            _info("Обновление до pre-release отменено пользователем.")
            return {"updated": False, "old_version": old_version,
                    "new_version": latest_pre,
                    "message": "Отменено пользователем"}

    _info(f"Обновление (PRE-RELEASE): {old_version} → {latest_pre}")
    return _do_b4_binary_update(old_version, latest_pre)


def do_b4_update_menu() -> None:
    """Раздел «Обновление Bye Bye Big Bro» — подменю с двумя подразделами.

      [1] Обновление до последней release версии
      [2] Обновление до prerelease версии

    Что делает раздел:
      • Показывает установленную версию binary и доступные версии
        (последняя release и последний pre-release с GitHub).
      • ПРИНУДИТЕЛЬНОЕ обновление: если установленная версия совпадает
        с выбранной — предлагает переустановку поверх той же версии
        (force). Полезно при повреждённом binary, для отката с
        pre-release на стабильную и после обновления мимо Chimera
        (Web UI b4 → Settings → Update, install.sh, ручная замена).
      • Синхронизация версии между связанными модулями: при входе в
        раздел фактическая версия binary записывается в общий state
        (sync_b4_version_state) — модули «DPI Bypass» и «YouTube через
        B4» работают с одним binary и одним state-файлом, поэтому
        оба показывают одну и ту же актуальную версию.
    """
    while True:
        os.system("clear")
        # Синхронизация версии binary → общий state (видят оба модуля).
        sync_b4_version_state()
        installed_version = _detect_version()
        # Доступные версии на GitHub (для сводки в шапке раздела).
        latest_stable = _detect_latest_version()
        latest_pre = _detect_latest_prerelease_version()

        _box_top("🔄  ОБНОВЛЕНИЕ BYE BYE BIG BRO")
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
        _box_row(f"  {DIM}Модули «DPI Bypass» и «YouTube через B4» работают с одним{NC}")
        _box_row(f"  {DIM}binary — версия общая и синхронизирована между ними.{NC}")
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
            # ── Подраздел 1: обновление до последней RELEASE версии ──────
            if not _detect_installed():
                _err("b4 не установлен. Сначала выполните установку.")
                input(f"\n{BOLD}Enter…{NC}")
                continue
            old = _detect_version()
            latest = _detect_latest_version()
            if not latest:
                _err("Не удалось проверить последнюю release-версию (GitHub недоступен).")
                input(f"\n{BOLD}Enter…{NC}")
                continue
            if old == latest:
                # Версии совпадают → ПРИНУДИТЕЛЬНАЯ переустановка.
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
                # Синхронизируем версию в общем state — второй модуль
                # (DPI Bypass ↔ YouTube через B4) увидит новую версию.
                sync_b4_version_state()
                _info("Версия синхронизирована между модулями B4 "
                      "(DPI Bypass + YouTube через B4).")
            else:
                _info(result["message"])
            input(f"\n{BOLD}Enter…{NC}")

        elif ch == "2":
            # ── Подраздел 2: обновление до PRE-RELEASE версии ───────────
            if not _detect_installed():
                _err("b4 не установлен. Сначала выполните установку.")
                input(f"\n{BOLD}Enter…{NC}")
                continue
            old = _detect_version()
            latest_pre = _detect_latest_prerelease_version()
            if not latest_pre:
                _err("Pre-release версии не найдены на GitHub.")
                input(f"\n{BOLD}Enter…{NC}")
                continue
            if old == latest_pre:
                # Версии совпадают → ПРИНУДИТЕЛЬНАЯ переустановка.
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
                # Пользователь только что подтвердил — второй вопрос не нужен.
                # Warning всё равно печатается через _warn() (в лог).
                result = auto_update_prerelease(confirm=False, force=True)
            else:
                # auto_update_prerelease(confirm=True) сама показывает
                # warning и спрашивает [y/N].
                result = auto_update_prerelease(confirm=True)
            if result.get("updated"):
                _ok(result["message"])
                sync_b4_version_state()
                _info("Версия синхронизирована между модулями B4 "
                      "(DPI Bypass + YouTube через B4).")
            else:
                _info(result["message"])
            input(f"\n{BOLD}Enter…{NC}")


def _detect_arch() -> str:
    """Возвращает 'amd64' / 'arm64' / 'armv7' / '386' / etc."""
    r = subprocess.run(["uname", "-m"], capture_output=True, text=True)
    m = r.stdout.strip()
    arch_map = {
        "x86_64":  "amd64",
        "amd64":   "amd64",
        "aarch64": "arm64",
        "arm64":   "arm64",
        "armv7l":  "armv7",
        "armv6l":  "armv6",
        "i386":    "386",
        "i686":    "386",
    }
    return arch_map.get(m, "")


def _download_b4_binary() -> bool:
    """Скачивает b4 binary с GitHub releases. Только Linux amd64/arm64."""
    arch = _detect_arch()
    if not arch:
        _err(f"Неподдерживаемая архитектура: {subprocess.run(['uname','-m'],capture_output=True,text=True).stdout.strip()}")
        return False
    url = f"https://github.com/DanielLavrushin/b4/releases/download/v{B4_VERSION}/b4-linux-{arch}.tar.gz"
    _info(f"Скачиваю b4 v{B4_VERSION} для linux-{arch}...")
    tmp_tar = Path("/tmp/b4-linux.tar.gz")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "chimera-installer/5.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            tmp_tar.write_bytes(resp.read())
    except Exception as e:
        _err(f"Не удалось скачать: {e}")
        return False
    _ok(f"Скачано {tmp_tar.stat().st_size // 1024} KB")
    # Распаковываем.
    try:
        with tarfile.open(tmp_tar, "r:gz") as tf:
            tf.extractall(path="/tmp/b4_extract")
    except Exception as e:
        _err(f"Не удалось распаковать: {e}")
        return False
    src = Path("/tmp/b4_extract/b4")
    if not src.exists():
        _err("В архиве нет b4 binary")
        return False
    shutil.copy2(src, B4_BINARY_PATH)
    B4_BINARY_PATH.chmod(0o755)
    shutil.rmtree("/tmp/b4_extract", ignore_errors=True)
    tmp_tar.unlink(missing_ok=True)
    _ok(f"b4 установлен: {B4_BINARY_PATH}")
    return True


def _write_empty_config() -> bool:
    """Создаёт ПУСТОЙ config.json без set'ов (clean install).

    Пользователь должен выбрать пресет через TUI ([2] Переключить preset)
    или подобрать через Discovery в Web UI. Это даёт гибкость — не всем
    подойдут встроенные пресеты (зависит от провайдера и ТСПУ).

    b4 запускается с пустым sets — работает в no-op режиме (не применяет
    DPI bypass), но Web UI, Discovery, API доступны.

    Формат — только живые поля b4 (Config = version/queue/system/sets/ui):
    никаких верхнеуровневых "udp"/"routing" (b4 их не читает и выкидывает
    при собственном сохранении конфига). QUIC-блок — per-set, живёт в
    каждом сете (см. _B4_QUIC_BLOCK_UDP).

    ВАЖНО: system.geo.sitedat_path нужен для сетов с geosite_categories
    (в т.ч. создаваемых через Discovery в Web UI): без него валидация b4
    отклоняет сет с 'geosite path must be configured'. Путь — всегда
    собственный /etc/b4/geosite.dat (_b4_geosite_path): это дефолтная
    Destination Directory Web UI b4 и единственный каталог гео-баз в
    ReadWritePaths юнита (шаринг с Xray ломал Update: 500 EROFS на
    read-only /usr). Если у Xray есть общий geosite.dat — копируем его
    в /etc/b4 (seed), категории работают сразу после установки.
    """
    B4_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    B4_SETS_DIR.mkdir(parents=True, exist_ok=True)
    B4_LOG_DIR.mkdir(parents=True, exist_ok=True)
    config = {
        "sets": [],
        "system": {
            "geo": _b4_geo_section(),
        },
    }
    B4_CONFIG_FILE.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    B4_CONFIG_FILE.chmod(0o644)
    # v75.1: сеем geosite-базу из общей копии Xray, если она есть —
    # категории geosite в сетах работают сразу, без Update в Web UI.
    _seed_b4_geosite()
    _ok(f"Конфиг создан (пустой): {B4_CONFIG_FILE}")
    return True


def _write_default_config() -> bool:
    """Создаёт дефолтный config.json с одним set "Youtube" (эталон).

    Формат: {"sets": [...]} — b4 требует массив sets, каждый с
    уникальным "id". Без "id" — ошибка "each set must have a unique
    non-empty ID". Без "sets" — "Loaded targets: 0 domains" (сет
    не загружен, b4 работает в no-op режиме).
    """
    B4_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    B4_SETS_DIR.mkdir(parents=True, exist_ok=True)
    B4_LOG_DIR.mkdir(parents=True, exist_ok=True)

    # Полный set из DEFAULT_SET_YOUTUBE (включает id, targets, faking, etc).
    youtube_set = dict(DEFAULT_SET_YOUTUBE)

    config = {
        "sets": [youtube_set],
        # Система (geosite/geoip пути для Discovery) — как в _write_empty_config.
        "system": {
            "geo": _b4_geo_section(),
        },
    }
    B4_CONFIG_FILE.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    B4_CONFIG_FILE.chmod(0o644)
    # v75.1: seed geosite-базы из общей копии Xray (см. _write_empty_config).
    _seed_b4_geosite()
    _ok(f"Конфиг создан: {B4_CONFIG_FILE}")
    return True


def _write_systemd_unit() -> bool:
    """Создаёт systemd-unit для b4.

    ВАЖНО: b4 сам управляет своими iptables-правилами (native mode, без
    --skip-tables). b4 создаёт `table inet b4_mangle` в nftables — эта
    таблица работает одновременно для IPv4 и IPv6 с фильтром
    `ct original packets < 20` (перехват только первых 20 пакетов).

    --verbose silent: b4 при `--verbose info` логирует КАЖДЫЙ перехваченный
    пакет (даже не-YouTube — exit-ноды, Telegram, mail.ru). Это ~1.1М
    строк/час в journald. Уровень `warn` не работает (баг b4 — фильтрует
    как info). `silent` отключает логирование пакетов, оставляя только
    критические ошибки. YouTube работает, Web UI работает, Discovery
    работает — логирование не влияет на перехват.
    """
    unit = f"""[Unit]
Description=b4 (Bye Bye Big Bro) — DPI bypass for YouTube on entry VPS
After=network-online.target xray.service
Wants=network-online.target

[Service]
Type=simple
ExecStart={B4_BINARY_PATH} --config {B4_CONFIG_FILE} \\
    --queue-num {B4_QUEUE_NUM} \\
    --mark {B4_MARK} \\
    --web-port {B4_WEB_PORT} \\
    --log-dir {B4_LOG_DIR} \\
    --verbose silent \\
    --ipv4 \\
    --ipv6
WorkingDirectory={B4_CONFIG_DIR}
Restart=always
RestartSec=3
StartLimitBurst=10
User=root
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
ReadWritePaths=/var/log/b4 /etc/b4 /var/lib/xray-installer

[Install]
WantedBy=multi-user.target
"""
    B4_UNIT_PATH.write_text(unit)
    _ok(f"systemd-unit создан: {B4_UNIT_PATH}")
    return True


def _iptables_apply() -> bool:
    """No-op: b4 сам управляет своими правилами через nftables (IPv4 + IPv6).

    ВАЖНО: Начиная с Chimera v5, b4 полностью сам управляет своими
    правилами перехвата. b4 создаёт `table inet b4_mangle` в nftables —
    эта таблица работает ОДНОВРЕМЕННО для IPv4 и IPv6 (inet = оба
    протокола). b4 использует умный фильтр `ct original packets < 20` —
    перехватывает только первые 20 пакетов соединения (ClientHello +
    пара пакетов), потом пропускает трафик напрямую. Это минимизирует
    нагрузку на NFQUEUE и логирует только YouTube-трафик.

    Chimera НЕ ставит НИКАКИХ правил — ни IPv4, ни IPv6. Раньше (до v5)
    Chimera ставила правила через `--skip-tables`, что приводило к:
      - Перехвату ВЕСЁГО 443-трафика (exit-ноды, google.com, etc.)
      - Лишнему трафику через NFQUEUE
      - Поломке Discovery (b4 применял preset к собственным тестовым пакетам)
      - "Дрисне" в логах b4 от не-YouTube трафика

    После перехода на native b4 rules:
      - Сервер без IPv6: только b4 native → логи чистые.
      - Сервер с IPv6: только b4 native (table inet) → логи чистые.
        Раньше Chimera'ные IPv6 правила (b4_mangle6) создавали ДВОЙНОЙ
        перехват — b4 получал каждый IPv6-пакет без фильтра < 20, что
        приводило к "дрисне" в логах. Теперь этого нет.

    Эта функция оставлена как no-op для обратной совместимости —
    install_b4() / enable() вызывают её, но она ничего не делает.
    Cleanup правил (старых Chimera'ных) делает _iptables_remove().
    """
    _info("iptables: b4 управляет своими правилами (native nftables, IPv4+IPv6)")
    return True


def _iptables_remove() -> None:
    """Удаляет СТАРЫЕ iptables/ip6tables правила Chimera (идемпотентно).

    ВАЖНО: Начиная с Chimera v5, b4 полностью сам управляет своими
    правилами через nftables `table inet b4_mangle` (IPv4 + IPv6).
    Chimera НЕ ставит НИКАКИХ правил. Эта функция нужна только для:
      1. Cleanup при uninstall_b4() — убрать старые правила Chimera.
      2. Cleanup при crash b4 (kill, OOM) — на случай если остались
         старые правила (до v5).
      3. Миграция со старого режима — _migrate_to_native_rules_if_needed()
         вызывает эту функцию, чтобы убрать старые Chimera'ные правила
         (b4_mangle для IPv4 + b4_mangle6 для IPv6).

    Все команды идемпотентны — если правил нет, -D/-F/-X просто вернут
    ошибку, мы её игнорируем через check=False.
    """
    # IPv4 — cleanup старых Chimera'ных правил (до v5) + на случай crash b4.
    subprocess.run(
        ["iptables", "-t", "mangle", "-D", "OUTPUT", "-j", "b4_mangle"],
        capture_output=True, check=False,
    )
    subprocess.run(
        ["iptables", "-t", "mangle", "-F", "b4_mangle"],
        capture_output=True, check=False,
    )
    subprocess.run(
        ["iptables", "-t", "mangle", "-X", "b4_mangle"],
        capture_output=True, check=False,
    )
    # IPv6 — Chimera'ные fallback правила, убираем всегда.
    subprocess.run(
        ["ip6tables", "-t", "mangle", "-D", "OUTPUT", "-j", "b4_mangle6"],
        capture_output=True, check=False,
    )
    subprocess.run(
        ["ip6tables", "-t", "mangle", "-F", "b4_mangle6"],
        capture_output=True, check=False,
    )
    subprocess.run(
        ["ip6tables", "-t", "mangle", "-X", "b4_mangle6"],
        capture_output=True, check=False,
    )
    _ok("iptables + ip6tables mangle правила b4 удалены")


# ══════════════════════════════════════════════════════════════════════════
#  NGINX FRONT ДЛЯ b4 WEB UI (прямой доступ по HTTPS из браузера)
# ══════════════════════════════════════════════════════════════════════════
# По аналогии с subscription.py → _sub_nginx_install/_sub_nginx_remove.
# Делегирует в chimera.modules.panel_nginx_front.

def _b4_nginx_status() -> dict:
    """Возвращает состояние nginx front для b4 Web UI."""
    if not B4_NGINX_STATE_FILE.exists():
        return {"enabled": False}
    try:
        return json.loads(B4_NGINX_STATE_FILE.read_text())
    except Exception:
        return {"enabled": False}


def _b4_nginx_install(port: int, use_self_signed: bool, domain) -> tuple:
    """Устанавливает nginx front с TLS для b4 Web UI."""
    from chimera.modules.panel_nginx_front import panel_nginx_front_install

    backend_port = B4_WEB_PORT  # b4 Web UI слушает на 9700

    ok, msg = panel_nginx_front_install(
        service_tag="chimera-b4-nginx",
        port=port,
        backend_port=backend_port,
        site_name=B4_NGINX_SITE_NAME,
        state_file=B4_NGINX_STATE_FILE,
        title="b4 Web UI",
        use_self_signed=use_self_signed,
        domain=domain,
        websocket_origin_rewrite=False,
        backend_http_scheme="http",  # b4 Web UI — HTTP (нет своего TLS)
        cert_name_slug="chimera-b4",
        mcp_proxy=True,  # v72.2: location /api/mcp с loopback-Host (go-sdk)
    )
    # Также закрываем прямой доступ к 9700 (только через nginx).
    if ok:
        try:
            subprocess.run(["ufw", "deny", f"{B4_WEB_PORT}/tcp",
                            "comment", "chimera-b4-direct-block"],
                           capture_output=True, check=False)
        except Exception:
            pass
    return ok, msg


def _b4_nginx_remove() -> tuple:
    """Удаляет nginx front + открывает 9700 обратно (для SSH-туннеля)."""
    from chimera.modules.panel_nginx_front import panel_nginx_front_remove

    if not _b4_nginx_status().get("enabled"):
        return True, "nginx front уже выключен"

    panel_nginx_front_remove(
        service_tag="chimera-b4-nginx",
        site_name=B4_NGINX_SITE_NAME,
        state_file=B4_NGINX_STATE_FILE,
        title="b4 Web UI",
    )
    # Возвращаем доступ к 9700 (для SSH-туннеля).
    try:
        subprocess.run(["ufw", "delete", "deny", f"{B4_WEB_PORT}/tcp"],
                       capture_output=True, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    return True, "nginx front удалён"


def _b4_nginx_get_url() -> Optional[str]:
    """Возвращает URL b4 Web UI через nginx front (если включён)."""
    st = _b4_nginx_status()
    if not st.get("enabled"):
        return None
    port = st.get("port", DEFAULT_B4_NGINX_PORT)
    domain = st.get("domain")
    if not domain:
        return None
    return f"https://{domain}:{port}"


def install_b4() -> bool:
    """Полная установка b4: binary + пустой config + systemd + port_registry.

    ВАЖНО: Начиная с v5, Chimera НЕ ставит IPv4 iptables-правила вручную.
    b4 сам управляет своими правилами (native mode, без --skip-tables).

    Конфиг создаётся ПУСТЫМ (без set'ов) — пользователь должен выбрать
    пресет через TUI ([2]) или Discovery в Web UI. Это даёт гибкость:
    не всем подойдут встроенные пресеты (зависит от провайдера/ТСПУ).
    """
    if not _download_b4_binary():
        return False
    if not _write_empty_config():
        return False
    if not _write_systemd_unit():
        return False
    # systemd daemon-reload.
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    #  Убираем старые Chimera'ные IPv4 правила (до v5) — на случай
    # миграции. b4 при старте создаст свои (native mode).
    _iptables_remove()
    # Применяем ТОЛЬКО IPv6 fallback правила (IPv4 — b4 сделает сам).
    _iptables_apply()
    # Регистрируем порты b4 в port_registry.
    try:
        from chimera.modules.port_registry import (
            port_register, SERVICE_B4_WEB, SERVICE_B4_DNS,
        )
        port_register(SERVICE_B4_WEB, B4_WEB_PORT, "tcp",
                      comment="b4 Web UI (loopback)", force=True)
        # b4 DNS TCP listener на 0.0.0.0:5453 — открывается самим b4,
        # регистрируем в port_registry для учёта (UFW не открываем —
        # это внутренний DNS-forwarder, не для внешнего доступа).
        port_register(SERVICE_B4_DNS, 5453, "tcp",
                      comment="b4 DNS TCP listener (internal)", force=True)
    except Exception:
        pass
    # Запускаем сервис — b4 сам создаст свои iptables-правила.
    r = subprocess.run(["systemctl", "enable", "--now", "b4"],
                       capture_output=True, text=True, check=False)
    if r.returncode != 0:
        _err(f"Не удалось запустить b4: {r.stderr.strip()}")
        _info("Проверьте логи: journalctl -u b4 -n 30")
        return False
    # Сохраняем state — preset=None (пустой конфиг, пользователь выберет).
    _save_state({
        "installed": True,
        "active_preset": None,
        "enabled": True,
        "version": B4_VERSION,
        "web_port": B4_WEB_PORT,
        "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    _ok("b4 установлен и запущен!")
    _info(f"Web UI: http://127.0.0.1:{B4_WEB_PORT} (только локально)")
    _info(f"Логи: journalctl -u b4 -f")
    _info(f"Config: {B4_CONFIG_FILE}")
    _warn("⚠  b4 установлен с ПУСТЫМ конфигом — DPI bypass неактивен!")
    _info("Выберите пресет через [2] или Discovery в Web UI [8].")
    return True


def uninstall_b4() -> bool:
    """Полное удаление b4."""
    # 1. Останавливаем + disable.
    subprocess.run(["systemctl", "stop", "b4"], capture_output=True, check=False)
    subprocess.run(["systemctl", "disable", "b4"], capture_output=True, check=False)
    # 2. Удаляем iptables правила.
    _iptables_remove()
    # 2b. Снимаем nginx front (если был включён) — закрывает порт nginx.
    try:
        _b4_nginx_remove()
    except Exception:
        pass
    # 2c. Снимаем регистрацию портов b4 из port_registry.
    try:
        from chimera.modules.port_registry import (
            port_unregister, SERVICE_B4_WEB, SERVICE_B4_DNS,
        )
        port_unregister(SERVICE_B4_WEB, B4_WEB_PORT, "tcp")
        port_unregister(SERVICE_B4_DNS, 5453, "tcp")
    except Exception:
        pass
    # 3. mask + remove unit.
    subprocess.run(["systemctl", "mask", "b4"], capture_output=True, check=False)
    B4_UNIT_PATH.unlink(missing_ok=True)
    subprocess.run(["systemctl", "unmask", "b4"], capture_output=True, check=False)
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "reset-failed", "b4"], capture_output=True, check=False)
    # 4. Удаляем binary + config.
    B4_BINARY_PATH.unlink(missing_ok=True)
    if B4_CONFIG_DIR.exists():
        shutil.rmtree(B4_CONFIG_DIR, ignore_errors=True)
    # 5. Логи оставляем (для диагностики) — пользователь может удалить вручную.
    # 6. State.
    _save_state({"installed": False, "active_preset": None, "enabled": False})
    _ok("b4 полностью удалён")
    return True


# ══════════════════════════════════════════════════════════════════════════
#  СТАТУС / УПРАВЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════

def _sets_match(a: dict, b: dict) -> bool:
    """Сравнивает ключевые поля двух b4 set'ов.

    Используется для детекта активного preset'а из config.json —
    сравнивает текущий set с встроенными пресетами (DEFAULT/AGGRESSIVE/LIGHT).

    Сравниваются только функциональные поля (домены, fake SNI, фрагментация).
    Не сравниваются: id, name, b4_version, enabled — они не влияют на работу
    b4, и Web UI может их менять без потери функциональности.

    Возвращает True если set'ы функционально идентичны.
    """
    # Домены (sni_domains) — сравниваем как множества (порядок не важен).
    a_domains = set(a.get("targets", {}).get("sni_domains", []))
    b_domains = set(b.get("targets", {}).get("sni_domains", []))
    if a_domains != b_domains:
        return False
    # Fake SNI — тип (DuckDuckGo=3, Google=2, и т.д.) и TTL.
    a_faking = a.get("faking", {})
    b_faking = b.get("faking", {})
    if a_faking.get("sni_type") != b_faking.get("sni_type"):
        return False
    if a_faking.get("ttl") != b_faking.get("ttl"):
        return False
    # SNI on/off (для light preset'а, где sni=False).
    if a_faking.get("sni", True) != b_faking.get("sni", True):
        return False
    # Фрагментация TCP.
    a_tcp = a.get("tcp", {})
    b_tcp = b.get("tcp", {})
    if a_tcp.get("seg2delay") != b_tcp.get("seg2delay"):
        return False
    if a_tcp.get("seg2delay_max") != b_tcp.get("seg2delay_max"):
        return False
    # QUIC-блок per-set (b4 >= 1.79): mode + filter_quic. Сет без
    # udp-секции (defaults b4: mode="fake", filter_quic="sni") — это
    # ДРУГОЕ поведение, чем квик-блок (mode="reject", filter_quic="all").
    a_udp = a.get("udp", {})
    b_udp = b.get("udp", {})
    if a_udp.get("mode") != b_udp.get("mode"):
        return False
    if a_udp.get("filter_quic") != b_udp.get("filter_quic"):
        return False
    return True


def _detect_active_preset_from_config() -> tuple:
    """Детектит активный preset из /etc/b4/config.json.

    Сравнивает текущий set[0] из config.json с встроенными пресетами
    (DEFAULT_SET_YOUTUBE / AGGRESSIVE_SET_YOUTUBE / LIGHT_SET_YOUTUBE).

    Возвращает кортеж (preset_name, set_name):
      preset_name: 'default'/'aggressive'/'light'/'custom'/'none'/'unknown'
      set_name: имя set'а из config.json (для отображения в UI), или None

    'none' — config.json существует, но sets пустой (clean install,
      пользователь ещё не выбрал пресет).
    'custom' — set не совпал ни с одним встроенным пресетом (правлен через
    Web UI / Discovery / импортирован).
    'unknown' — config.json отсутствует или повреждён.
    """
    if not B4_CONFIG_FILE.exists():
        return ("unknown", None)
    try:
        cfg = json.loads(B4_CONFIG_FILE.read_text())
        sets = cfg.get("sets", [])
        if not sets:
            return ("none", None)  # clean install, no preset selected
        current_set = sets[0]
        set_name = current_set.get("name")
        # Сравниваем с встроенными пресетами.
        for preset_name, (_, built_in_set) in PRESETS.items():
            if _sets_match(current_set, built_in_set):
                return (preset_name, set_name)
        return ("custom", set_name)
    except Exception:
        return ("unknown", None)


def _get_enabled_sets() -> list:
    """Возвращает список имён активных (enabled=true) сетов из config.json."""
    if not B4_CONFIG_FILE.exists():
        return []
    try:
        cfg = json.loads(B4_CONFIG_FILE.read_text())
        sets = cfg.get("sets", [])
        enabled = []
        for s in sets:
            if s.get("enabled", False):
                name = s.get("name", s.get("id", "?"))
                enabled.append(name)
        return enabled
    except Exception:
        return []


def _heal_b4_config() -> bool:
    """Авто-лечение мёртвых geosite-путей в config.json (v75.1).

    Машины, установленные до v72.4, несли хардкод
    system.geo.sitedat_path=/usr/share/xray/geosite.dat (источник —
    Chimera, НЕ b4: в Go-коде b4 пути /usr/share/xray нет, дефолт
    GeoSitePath="" + sanitize лечит только относительные пути).
    v72.4 чинил путь только при переключении пресета/импорте сета —
    если юзер после обновления Химеры ни того ни другого не делал,
    конфиг оставался сломанным: Update геосайта в Web UI b4 = 500
    EROFS (третья машина, picaresque.space). Теперь status()
    (меню модуля / REST-панели) проверяет конфиг при каждом вызове и
    при первом же касании лечит: перезапись + seed-базы + рестарт b4.
    Произвольные пользовательские пути не трогаем.
    """
    if not B4_CONFIG_FILE.exists():
        return False
    try:
        cfg = json.loads(B4_CONFIG_FILE.read_text())
    except Exception:
        return False  # Битый конфиг — юнит b4 сам ругнётся в journalctl
    if not isinstance(cfg, dict):
        return False
    system = cfg.get("system")
    geo = system.get("geo") if isinstance(system, dict) else None
    if not isinstance(geo, dict) or not _b4_heal_geo_paths(geo):
        return False
    try:
        B4_CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
        B4_CONFIG_FILE.chmod(0o644)
    except OSError as e:
        _err(f"Не удалось записать {B4_CONFIG_FILE}: {e}")
        return False
    _seed_b4_geosite()
    _ok(f"Гео-пути b4 вылечены: sitedat_path → {B4_GEOSITE_LOCAL_PATH} "
        f"(+URL/auto_update), b4 перезапущен")
    # b4 должен перечитать конфиг (пути гео-баз читаются при старте).
    subprocess.run(["systemctl", "restart", "b4"],
                   capture_output=True, check=False)
    return True


def status() -> dict:
    """Возвращает сводку состояния b4."""
    state = _load_state()
    installed = B4_BINARY_PATH.exists() and B4_UNIT_PATH.exists()
    if not installed:
        return {"installed": False, "service_active": False,
                "active_preset": None, "web_port": None}
    # Service status.
    r = subprocess.run(["systemctl", "is-active", "b4"],
                       capture_output=True, text=True, check=False)
    service_active = (r.returncode == 0 and r.stdout.strip() == "active")
    #  v75.1: авто-лечение мёртвых geosite-путей (легаси-хардкод и
    # «общие» пути Xray в read-only /usr). Конфиг, оставшийся от старой
    # Chimera, конвергирует при первом же открытии меню модуля —
    # даже если юзер никогда не переключал пресет/не импортировал сет.
    _heal_b4_config()
    # Version.
    version = state.get("version", "")
    if not version and B4_BINARY_PATH.exists():
        try:
            r = subprocess.run([str(B4_BINARY_PATH), "--version"],
                               capture_output=True, text=True, check=False, timeout=5)
            m = re.search(r'B4 version:\s*(\S+)', r.stdout)
            if m:
                version = m.group(1)
        except Exception:
            pass

    #  Авто-синхронизация active_preset с config.json.
    # Web UI b4 / Discovery меняют config.json, но не трогают state.json.
    # Детектим актуальный preset из config.json и обновляем state при
    # расхождении. Это делает подпись в меню честной: если set правлен
    # через Web UI — TUI покажет 'custom' вместо устаревшего имени preset'а.
    detected_preset, detected_set_name = _detect_active_preset_from_config()
    state_preset = state.get("active_preset")
    if detected_preset != "unknown" and detected_preset != state_preset:
        # Config был изменён внешне (Web UI / Discovery) — обновляем state.
        state["active_preset"] = detected_preset
        _save_state(state)
    active_preset = detected_preset if detected_preset != "unknown" else state_preset

    #  Получаем список всех активных (enabled) сетов из config.json.
    active_sets = _get_enabled_sets()

    # nginx front status.
    ng = _b4_nginx_status()
    nginx_url = _b4_nginx_get_url()
    return {
        "installed": True,
        "service_active": service_active,
        "active_preset": active_preset,
        "active_set_name": detected_set_name,
        "active_sets": active_sets,
        "version": version,
        "web_port": state.get("web_port", B4_WEB_PORT),
        "config_path": str(B4_CONFIG_FILE),
        "binary_path": str(B4_BINARY_PATH),
        "queue_num": B4_QUEUE_NUM,
        "mark": B4_MARK,
        "enabled": state.get("enabled", False),
        "nginx_front_enabled": ng.get("enabled", False),
        "nginx_front_port": ng.get("port", DEFAULT_B4_NGINX_PORT),
        "nginx_front_url": nginx_url,
    }



def enable() -> bool:
    """Запускает b4 сервис (если установлен).

    b4 сам ставит свои IPv4 iptables-правила при старте (native mode).
    IPv6 fallback правила ставит Chimera (на случай если b4 их не ставит).
    """
    if not B4_BINARY_PATH.exists():
        _err("b4 не установлен. Сначала выполните установку.")
        return False
    # IPv6 fallback — Chimera. IPv4 — b4 сам при старте.
    _iptables_apply()
    r = subprocess.run(["systemctl", "enable", "--now", "b4"],
                       capture_output=True, text=True, check=False)
    if r.returncode != 0:
        _err(f"Не удалось запустить: {r.stderr.strip()}")
        return False
    state = _load_state()
    state["enabled"] = True
    _save_state(state)
    _ok("b4 запущен")
    return True


def disable() -> bool:
    """Останавливает b4 сервис (без удаления).

    b4 сам убирает свои IPv4 iptables-правила при остановке.
    IPv6 fallback правила убирает Chimera.
    На случай если b4 упал без cleanup'а — _iptables_remove() подстрахует.
    """
    subprocess.run(["systemctl", "stop", "b4"], capture_output=True, check=False)
    subprocess.run(["systemctl", "disable", "b4"], capture_output=True, check=False)
    # Cleanup IPv4 (на случай crash b4) + IPv6 (Chimera'ные).
    _iptables_remove()
    state = _load_state()
    state["enabled"] = False
    _save_state(state)
    _ok("b4 остановлен (binary и config сохранены)")
    return True


def _migrate_to_native_rules_if_needed() -> bool:
    """Авто-миграция systemd-unit b4 на актуальный формат.

    Проверяет два условия и если хотя бы одно найдено — перезаписывает
    unit на актуальный (native b4 rules + --verbose silent):

    1. --skip-tables (старый режим, Chimera управляла iptables вручную).
       Миграция: убрать --skip-tables, b4 сам управляет через nftables.
    2. --verbose info или --verbose warn (b4 логирует каждый пакет —
       ~1.1М строк/час, засоряет journald). Миграция: --verbose silent.
       Уровень warn не работает (баг b4 — фильтрует как info).

    При миграции также:
      - Убирает старые Chimera'ные iptables правила (b4_mangle + b4_mangle6).
      - Перезапускает b4.

    Вызывается автоматически при открытии меню b4 (do_dpi_bypass_menu).
    Идемпотентна — если unit уже актуальный, ничего не делает.

    Возвращает True если миграция выполнена, False если не нужна.
    """
    if not B4_UNIT_PATH.exists():
        return False  # b4 не установлен — нечего мигрировать
    try:
        unit_content = B4_UNIT_PATH.read_text()
    except Exception:
        return False

    # Детектим что нужно мигрировать.
    needs_migration = False
    reasons = []
    if "--skip-tables" in unit_content:
        needs_migration = True
        reasons.append("--skip-tables → native b4 rules")
    if "--verbose info" in unit_content or "--verbose warn" in unit_content:
        needs_migration = True
        reasons.append("--verbose info/warn → --verbose silent (логи чистые)")

    if not needs_migration:
        return False  # Unit уже актуальный — миграция не нужна

    # Миграция нужна.
    _info("Обнаружен устаревший systemd-unit b4. Мигрирую:")
    for reason in reasons:
        _info(f"  • {reason}")

    # 1. Перезаписываем unit на актуальный (native + silent).
    if not _write_systemd_unit():
        _err("Не удалось перезаписать systemd-unit")
        return False
    # 2. daemon-reload.
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    # 3. Убираем старые Chimera'ные iptables правила (IPv4 + IPv6).
    _iptables_remove()
    # 4. Перезапускаем b4 — он создаст свои native nftables правила.
    r = subprocess.run(["systemctl", "restart", "b4"],
                       capture_output=True, text=True, check=False)
    if r.returncode == 0:
        _ok("Миграция завершена: b4 обновлён")
        _info("  • b4 сам управляет iptables (nftables table inet, IPv4+IPv6)")
        _info("  • --verbose silent — логи чистые (только ошибки)")
        _info("  • YouTube, Web UI, Discovery продолжают работать")
    else:
        _err(f"Не удалось перезапустить b4 после миграции: {r.stderr.strip()}")
        _info("Проверьте логи: journalctl -u b4 -n 30")
    return True


def _b4_clean_legacy_config_keys(cfg: dict) -> int:
    """Чистит legacy-поля b4-конфига in-place, возвращает число исправлений.

    b4 (проверено по исходникам 1.80rc1: src/config/config.go) читает
    только version/queue/system/sets/ui — остальные верхнеуровневые ключи
    игнорируются при загрузке и выкидываются при сохранении самим b4
    (MarshalSparse пишет только поля структур). Прежние версии Chimera
    писали мёртвые ключи:

      • верхнеуровневые "udp" (c filter_quic:"block") и "routing" —
        b4 их никогда не читал: QUIC-настройки живут per-set
        (sets[].udp), значения "block" не существует вовсе
        (NormalizeQUICFilter переписывает всё ≠ "all" в "sni");
      • "system.geosite_path" — правильное поле system.geo.sitedat_path
        (GeoDatConfig, json-тег sitedat_path);
      • "b4_version" внутри сета — не поле SetConfig, informational-мусор;
      • system.geo.sitedat_path — мёртвый для b4 путь (легаси-хардкод
        Chimera /usr/share/xray/geosite.dat или v72.4-«общий» путь Xray
        /usr/local/share/xray|/usr/share/xray): /usr read-only для b4
        (ProtectSystem=strict), Update геосайта в Web UI падает с 500 —
        путь переводится на собственный /etc/b4/geosite.dat (+URL,
        auto_update, если пусты).

    Вызывается перед записью config.json из switch_preset() и
    import_custom_set() — конфиг, написанный старой Chimera, конвергирует
    к живому формату при первом же переключении пресета / импорте сета.
    """
    fixed = 0
    if not isinstance(cfg, dict):
        return 0
    # 1. Мёртвые верхнеуровневые секции.
    for key in ("udp", "routing"):
        if key in cfg:
            del cfg[key]
            fixed += 1
    # 2. system.geosite_path → system.geo.sitedat_path.
    system = cfg.get("system")
    if isinstance(system, dict) and "geosite_path" in system:
        legacy_path = system.pop("geosite_path")
        fixed += 1
        geo = system.setdefault("geo", {})
        if isinstance(geo, dict) and not geo.get("sitedat_path") and legacy_path:
            geo["sitedat_path"] = legacy_path
    # 2b. Мёртвые для b4 geosite-пути (v75.1): легаси-хардкод Chimera
    # (/usr/share/xray/geosite.dat) и «общие» пути Xray
    # (B4_GEOSITE_SHARED_PATHS) — ДАЖЕ при живом файле: /usr read-only
    # для процесса b4 (ProtectSystem=strict), Web UI берёт Destination
    # Directory из dirname(sitedat_path) → Update геосайта = 500 EROFS
    # (mkdir /usr/...: read-only file system; три машины). Лечим на
    # собственный /etc/b4/geosite.dat (+ sitedat_url/auto_update,
    # если пусты) — _b4_heal_geo_paths.
    system = cfg.get("system")
    if isinstance(system, dict):
        geo = system.get("geo")
        if isinstance(geo, dict) and _b4_heal_geo_paths(geo):
            fixed += 1
    # 3. Мёртвое поле b4_version в сетах.
    sets = cfg.get("sets")
    if isinstance(sets, list):
        for s in sets:
            if isinstance(s, dict) and "b4_version" in s:
                del s["b4_version"]
                fixed += 1
    return fixed


def switch_preset(preset_name: str) -> bool:
    """Меняет активный preset (default/aggressive/light). Перезапускает b4."""
    if preset_name not in PRESETS:
        _err(f"Неизвестный preset: {preset_name}")
        return False
    label, set_data = PRESETS[preset_name]
    _info(f"Переключаю на preset «{label}»...")
    # Preset заменяет ВСЕ set'ы (семантика прежняя), но остальной конфиг
    # МЁРЖИМ с существующим: топ-уровневые секции queue (NFQUEUE/mark),
    # ui и system.webserver (порт Web UI, авторизация) обязаны
    # сохраниться — раньше конфиг перезаписывался минимальным шаблоном
    # и настройки сбрасывались на дефолты b4.
    # Глубокая копия: _normalize_set_domains мутирует targets.
    new_set = json.loads(json.dumps(set_data))
    _normalize_set_domains(new_set)  # на случай wildcard-записей в пресете
    existing_cfg = {}
    if B4_CONFIG_FILE.exists():
        try:
            parsed = json.loads(B4_CONFIG_FILE.read_text())
            if isinstance(parsed, dict):
                existing_cfg = parsed
        except Exception:
            pass  # Конфиг повреждён — начнём с чистого шаблона
    existing_cfg["sets"] = [new_set]
    # Секция system (geosite/geoip пути для Discovery) — обязательна.
    if not existing_cfg.get("system"):
        existing_cfg["system"] = {
            "geo": _b4_geo_section(),
        }
    # Чистим legacy-поля старого конфига (udp/routing, geosite_path, b4_version).
    legacy_fixed = _b4_clean_legacy_config_keys(existing_cfg)
    if legacy_fixed:
        _info(f"Чистка legacy-полей конфига b4: {legacy_fixed} исправлений "
              f"(udp/routing, geosite_path → geo.sitedat_path, b4_version)")
    B4_CONFIG_FILE.write_text(json.dumps(existing_cfg, indent=2, ensure_ascii=False))
    # Перезапускаем сервис.
    subprocess.run(["systemctl", "restart", "b4"], capture_output=True, check=False)
    state = _load_state()
    state["active_preset"] = preset_name
    _save_state(state)
    _ok(f"Preset «{label}» применён, b4 перезапущен")
    return True


# ══════════════════════════════════════════════════════════════════════════
#  XRAY ROUTING — домены set'а → outbound:direct (через b4 на entry)
# ══════════════════════════════════════════════════════════════════════════

_XRAY_RULE_PREFIX = "chimera-b4-route-"


def _get_xray_outbound_tag() -> str:
    """Возвращает outboundTag для b4-маршрутизации.

    Если включён AWG exit (Mode B) — используем 'direct-local'
    (freedom outbound с domainStrategy=UseIPv4).
    Иначе — 'direct'.
    """
    try:
        from chimera._core import AWG_EXIT_ENABLED, INSTALL_MODE
        if getattr(AWG_EXIT_ENABLED, "value", AWG_EXIT_ENABLED) and INSTALL_MODE == "B":
            return "direct-local"
    except Exception:
        pass
    return "direct"


def _ensure_direct_local_outbound(cfg: dict) -> None:
    """Если outboundTag='direct-local' — убеждаемся что такой outbound существует.
    Если нет — создаём freedom outbound с domainStrategy=UseIPv4.
    """
    outbounds = cfg.get("outbounds", [])
    has_direct_local = any(
        o.get("tag") == "direct-local" for o in outbounds
    )
    if not has_direct_local:
        outbounds.append({
            "protocol": "freedom",
            "tag": "direct-local",
            "settings": {"domainStrategy": "UseIPv4"},
        })
        cfg["outbounds"] = outbounds


def _xray_safe_restart() -> bool:
    """Безопасный restart Xray с валидацией config и rollback.
    Использует _xray_safe_apply_config если доступна, иначе raw restart.
    """
    try:
        from chimera.modules.xray_install import _xray_safe_apply_config
        return _xray_safe_apply_config()
    except ImportError:
        # Fallback — raw restart (менее безопасно, но лучше чем ничего).
        # v57 (start-limit-fix): reset-failed перед рестартом — импорт b4-сетов
        # делает несколько apply подряд (routing для каждого сета).
        subprocess.run(["systemctl", "reset-failed", "xray"],
                       capture_output=True, check=False)
        subprocess.run(["systemctl", "restart", "xray"],
                       capture_output=True, check=False)
        time.sleep(1)
        return True


def _set_xray_config_owner(cfg_path: Path) -> None:
    """Устанавливает правильные права на config.json (640 root:xray)."""
    try:
        from chimera._core import _set_config_owner
        _set_config_owner(cfg_path)
    except ImportError:
        try:
            cfg_path.chmod(0o644)
        except Exception:
            pass


def apply_routing_for_set(set_id: str, domains: list) -> bool:
    """Добавляет/обновляет Xray routing-правило: domain:[...] → outbound:direct.

    Домены b4-сета нормализуются под Xray: "*.example.com" →
    "domain:example.com" (Xray-матчер суффиксный — матчит и поддомены).
    Catch-all/regexp-записи b4 в Xray routing не транслируются.

    AWG-aware: если включён AWG exit — использует 'direct-local' outbound.
    Безопасный restart: использует _xray_safe_apply_config с валидацией.
    """
    if not domains:
        return False
    xray_domains = _xray_domain_entries_from_b4(domains)
    if not xray_domains:
        _warn(f"Xray routing для set'{set_id}': после нормализации не "
              f"осталось подходящих доменов (catch-all/regexp-записи в "
              f"Xray routing не транслируются)")
        return False
    comment = _XRAY_RULE_PREFIX + set_id
    outbound_tag = _get_xray_outbound_tag()
    new_rule = {
        "type": "field",
        "domain": xray_domains,
        "outboundTag": outbound_tag,
        "comment": comment,
    }
    written = set()
    ok = False
    for cfg_path in (Path("/usr/local/etc/xray/config.json"),
                     Path("/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            real = str(cfg_path.resolve())
        except Exception:
            real = str(cfg_path)
        if real in written:
            continue
        written.add(real)
        try:
            cfg = json.loads(cfg_path.read_text())
            # Если AWG — убеждаемся что direct-local outbound существует.
            if outbound_tag == "direct-local":
                _ensure_direct_local_outbound(cfg)
            routing = cfg.setdefault("routing", {})
            rules = routing.setdefault("rules", [])
            # Удаляем старое правило для этого set'а (идемпотентность).
            rules = [r for r in rules if r.get("comment") != comment]
            # Добавляем новое в начало (top-down eval, first match wins).
            routing["rules"] = [new_rule] + rules
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_xray_config_owner(cfg_path)
            ok = True
        except Exception as e:
            _log("WARN", f"apply_routing_for_set({set_id}): {e}")
    if ok:
        _info(f"Xray routing: {len(xray_domains)} доменов set'{set_id}' → {outbound_tag}")
        _xray_safe_restart()
    return ok


def remove_routing_for_set(set_id: str) -> bool:
    """Удаляет Xray routing-правило для set'а. Безопасный restart."""
    comment = _XRAY_RULE_PREFIX + set_id
    written = set()
    ok = False
    for cfg_path in (Path("/usr/local/etc/xray/config.json"),
                     Path("/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            real = str(cfg_path.resolve())
        except Exception:
            real = str(cfg_path)
        if real in written:
            continue
        written.add(real)
        try:
            cfg = json.loads(cfg_path.read_text())
            routing = cfg.get("routing", {})
            rules = routing.get("rules", [])
            before = len(rules)
            rules = [r for r in rules if r.get("comment") != comment]
            if len(rules) != before:
                routing["rules"] = rules
                cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                _set_xray_config_owner(cfg_path)
                ok = True
        except Exception as e:
            _log("WARN", f"remove_routing_for_set({set_id}): {e}")
    if ok:
        _info(f"Xray routing для set'{set_id}' удалён")
        _xray_safe_restart()
    return ok


def apply_routing_for_all_sets() -> dict:
    """Синхронизирует ВСЕ b4-сеты с Xray routing.

    Для каждого enabled set'а — создаёт/обновляет routing-правило.
    Для disabled/удалённых set'ов — удаляет stale правила.
    Домены нормализуются под Xray: "*.example.com" → "domain:example.com"
    (суффикс-матчер Xray матчит и поддомены — тот же эффект, что даёт
    опция «YouTube через RU Entry», но для доменов b4-сетов).
    Один restart Xray в конце (не N restarts).

    Returns:
        {"applied": int, "removed": int, "total_domains": int, "errors": list}
    """
    result = {"applied": 0, "removed": 0, "total_domains": 0, "errors": []}
    sets = _detect_sets()
    active_set_ids = set()
    all_domains = []
    outbound_tag = _get_xray_outbound_tag()

    # Собираем домены из всех enabled set'ов.
    for s in sets:
        sid = s.get("id", "")
        domains = s.get("domains", [])
        is_enabled = s.get("enabled", False)
        if sid and domains and is_enabled:
            active_set_ids.add(sid)
            all_domains.extend(domains)
            result["total_domains"] += len(domains)

    # Дедуплицируем домены.
    all_domains = sorted(set(all_domains))

    # Нормализуем под Xray: "*."-wildcard → apex (суффикс-матчер Xray),
    # catch-all/regexp-записи НЕ транслируем (пин всего трафика на
    # direct по catch-all сету уводил бы VPN-трафик мимо туннеля).
    xray_entries = _xray_domain_entries_from_b4(all_domains)

    # Находим stale правила (для disabled/удалённых set'ов).
    stale_comments = []
    for cfg_path in (Path("/usr/local/etc/xray/config.json"),
                     Path("/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            cfg = json.loads(cfg_path.read_text())
            routing = cfg.get("routing", {})
            rules = routing.get("rules", [])
            for r in rules:
                c = r.get("comment", "")
                if c.startswith(_XRAY_RULE_PREFIX):
                    sid = c[len(_XRAY_RULE_PREFIX):]
                    if sid not in active_set_ids:
                        stale_comments.append(c)
        except Exception:
            pass

    # Применяем изменения в config.json (один write на все set'ы).
    # ЕДИНОЕ правило пишем ТОЛЬКО если есть хотя бы один домен: правило
    # с пустым массивом domain в Xray матчит ВЕСЬ трафик и уводило бы
    # его на direct-outbound (мимо VPN-туннеля).
    comment_all = _XRAY_RULE_PREFIX + "all-synced"
    new_rule_all = {
        "type": "field",
        "domain": xray_entries,
        "outboundTag": outbound_tag,
        "comment": comment_all,
    } if xray_entries else None
    written = set()
    ok = False
    for cfg_path in (Path("/usr/local/etc/xray/config.json"),
                     Path("/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            real = str(cfg_path.resolve())
        except Exception:
            real = str(cfg_path)
        if real in written:
            continue
        written.add(real)
        try:
            cfg = json.loads(cfg_path.read_text())
            if outbound_tag == "direct-local":
                _ensure_direct_local_outbound(cfg)
            routing = cfg.setdefault("routing", {})
            rules = routing.setdefault("rules", [])
            # Удаляем все старые b4-правила (per-set и all-synced).
            rules = [r for r in rules
                     if not (r.get("comment", "").startswith(_XRAY_RULE_PREFIX))]
            # Добавляем единое правило (если есть домены).
            if new_rule_all is not None:
                routing["rules"] = [new_rule_all] + rules
            else:
                routing["rules"] = rules
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_xray_config_owner(cfg_path)
            ok = True
        except Exception as e:
            result["errors"].append(str(e))
            _log("WARN", f"apply_routing_for_all_sets: {e}")

    if ok:
        if xray_entries:
            result["applied"] = len(active_set_ids)
            _info(f"Xray routing синхронизирован: {len(active_set_ids)} set'ов, "
                  f"{len(xray_entries)} доменов → {outbound_tag}")
        else:
            result["applied"] = 0
            _info("Xray routing: переводимых доменов нет (catch-all/regexp "
                  "не транслируются) — b4-правила удалены")
        result["removed"] = len(stale_comments)
        if stale_comments:
            _info(f"Удалено stale-правил: {len(stale_comments)}")
        _xray_safe_restart()

    return result


# ══════════════════════════════════════════════════════════════════════════
#  НОРМАЛИЗАЦИЯ ДОМЕНОВ b4 + REST API (общий блок, зеркален в youtube_b4.py)
# ══════════════════════════════════════════════════════════════════════════

# b4 не поддерживает wildcard-записи вида "*.example.com": движок
# сни-матчинга (sni/domain.go ParseDomainEntry + MatchDomainEntry)
# сравнивает записи литерально — apex "whatsapp.com" покрывает и
# "web.whatsapp.com" (suffix-walk), а вот "*.whatsapp.com" не совпадает
# ни с одним реальным хостом. Собственный Web UI b4 при ручном вводе
# домена молча стриппит "*." (catchall.ts normalizeDomainEntry) и
# подсказывает «b4 и так совпадает с поддоменами» — но JSON-импорт
# (Web UI Import/Export, сторонние сеты, Chimera TUI) делал этого НЕ
# всегда. Из-за этого сторонние WA/FB/IG-сеты с "*.domain"-записями
# импортировались пустышками: трафик не матчился, бейджей в Traffic
# не было. Нормализуем те же семантики на стороне Chimera.
_B4_DOMAIN_ANY_SHORTHANDS = {"*", "**", "*.*", "any", "all", "0/0"}
_B4_DOMAIN_CATCH_ALL = "regexp:.*"


def _normalize_b4_domain_entry(raw) -> Optional[str]:
    """Нормализация доменной записи к семантикам движка b4.

    Зеркалит Web UI b4 (catchall.ts normalizeDomainEntry) и движок
    (ParseDomainEntry — lowercase/trim/точки):
      • "*.example.com"  → "example.com" (apex покрывает поддомены);
      • "*"/"**"/"any"/"all"/"0/0" → "regexp:.*" (catch-all);
      • "regexp:..."     → без изменений (регэксп-запись движка);
      • пустая запись    → None (выбрасывается).
    """
    value = str(raw or "").strip()
    if not value:
        return None
    low = value.lower()
    if low in _B4_DOMAIN_ANY_SHORTHANDS:
        return _B4_DOMAIN_CATCH_ALL
    if low.startswith("regexp:"):
        # Движок парсит регэкспы по lowercased-строке — зеркалим.
        return low
    normalized = value
    while normalized.startswith("*."):
        normalized = normalized[2:]
    normalized = normalized.strip(".").lower()
    return normalized or None


def _normalize_set_domains(custom_set: dict) -> int:
    """Нормализует targets.sni_domains сета in-place (wildcard → apex).

    Возвращает количество изменённых/удалённых записей (для лога).
    Дедуплицирует результат: "*.whatsapp.com" и "whatsapp.com" после
    нормализации — одна и та же запись.
    """
    targets = custom_set.get("targets")
    if not isinstance(targets, dict):
        return 0
    raw_domains = targets.get("sni_domains")
    if not isinstance(raw_domains, list):
        return 0
    normalized, seen, changed = [], set(), 0
    for raw in raw_domains:
        if not isinstance(raw, str):
            normalized.append(raw)  # мусор не трогаем — b4 сам валидирует
            continue
        norm = _normalize_b4_domain_entry(raw)
        if norm is None:
            changed += 1
            continue
        if norm != raw.strip().lower():
            changed += 1
        if norm not in seen:
            seen.add(norm)
            normalized.append(norm)
    targets["sni_domains"] = normalized
    return changed


def _xray_domain_entries_from_b4(domains: list) -> list:
    """Готовит domain-записи для Xray routing-правила из доменов b4-сета.

    Xray-матчер "domain:example.com" — суффиксный (матчит и поддомены),
    поэтому "*.example.com" нормализуем к apex. Catch-all ("regexp:.*")
    и регэксп-записи b4 в Xray routing НЕ транслируем: пинить ВЕСЬ
    трафик на direct-outbound по catch-all сету опасно (уводит VPN-трафик
    мимо туннеля), а литеральные "domain:*"/"domain:regexp:..." и раньше
    были no-op — сохраняем это поведение явно. Возвращает уникальные
    "domain:..." записи.
    """
    entries, seen = [], set()
    for d in (domains or []):
        if not isinstance(d, str):
            continue
        low = d.strip().lower()
        if not low or low.startswith("regexp:") or low in _B4_DOMAIN_ANY_SHORTHANDS:
            continue
        norm = _normalize_b4_domain_entry(d)
        if not norm or norm == _B4_DOMAIN_CATCH_ALL:
            continue
        if norm not in seen:
            seen.add(norm)
            entries.append(f"domain:{norm}")
    return entries


#  REST API b4 (Web UI backend, b4 >= 1.78): /api/sets — CRUD сетов с
#  hot-reload на стороне b4 (saveAndPushConfig: валидация конфига +
#  атомарное сохранение config.json + обновление живого состояния БЕЗ
#  рестарта сервиса). Импорт через REST не теряет топ-уровневые секции
#  config.json (queue / ui / system.webserver) — их пишет и читает сам
#  b4. Web-авторизация (v72.2): если администратор включил username/
#  password в b4 Web UI — Chimera логинится через /api/login и
#  отправляет Bearer-токен (учётка читается из config.json; токен
#  кэшируется до 401, затем перевыпускается).
_B4_REST_TIMEOUT = 5.0  # сек; API живёт на 127.0.0.1
_B4_REST_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_B4_API_TOKEN = {"value": None}  # кэш Bearer-токена REST API (web-auth b4)


def _b4_web_credentials() -> "Optional[tuple]":
    """(username, password) web-авторизации b4 из config.json.

    Chimera учётку не задаёт, но администратор может включить auth в
    b4 Web UI (Settings → Web Server) — при открытом наружу nginx front
    (порт 9743) это обязательная мера: без неё /api/config и /api/sets
    открыты всему интернету.
    """
    try:
        if not B4_CONFIG_FILE.exists():
            return None
        cfg = json.loads(B4_CONFIG_FILE.read_text())
        ws = (cfg.get("system") or {}).get("web_server")
        if not isinstance(ws, dict):
            return None
        u, p = str(ws.get("username") or ""), str(ws.get("password") or "")
        return (u, p) if u and p else None
    except Exception:
        return None


def _b4_api_token() -> "Optional[str]":
    """Bearer-токен REST API b4: POST /api/login → {"token": ...}.

    Токен живёт 24ч на стороне b4; кэшируем его в _B4_API_TOKEN,
    при 401 вызывающий код сбрасывает кэш и перевыпускает.
    Возвращает None, если web-auth выключена или логин не удался
    (вызывающий код тогда отправит запрос без токена — как раньше).
    """
    if _B4_API_TOKEN["value"]:
        return _B4_API_TOKEN["value"]
    creds = _b4_web_credentials()
    if not creds:
        return None
    try:
        port = _b4_web_port()
        if not port:
            return None
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/login",
            data=json.dumps({"username": creds[0], "password": creds[1]}).encode("utf-8"),
            method="POST")
        req.add_header("Content-Type", "application/json")
        with _B4_REST_OPENER.open(req, timeout=_B4_REST_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8", errors="replace") or "{}")
        token = body.get("token") if isinstance(body, dict) else None
        if token:
            _B4_API_TOKEN["value"] = token
        return token
    except Exception:
        return None


def _b4_web_port() -> Optional[int]:
    """Актуальный порт Web UI b4 (по убыванию приоритета):

    1. systemd-unit: флаг --web-port. Явно заданный флаг применяется
       ПОВЕРХ config.json (config/bind.go: ApplyFlags) — на
       Chimera-установках флаг ставится всегда, это фактический порт
       запущенного сервиса;
    2. config.json: system.web_server.port (json-тег WebServerConfig
       в структуре Config b4 — именно web_server, с подчёркиванием);
    3. state web_port (пишется установщиком Chimera);
    4. дефолт Chimera B4_WEB_PORT (9700).
    """
    # 1. Флаг --web-port из systemd-unit (фактический runtime-порт).
    try:
        if B4_UNIT_PATH.exists():
            m = re.search(r"--web-port[=\s]+(\d{1,5})\b", B4_UNIT_PATH.read_text())
            if m:
                port = int(m.group(1))
                if 0 < port < 65536:
                    return port
    except Exception:
        pass
    # 2. config.json: system.web_server.port.
    try:
        if B4_CONFIG_FILE.exists():
            cfg = json.loads(B4_CONFIG_FILE.read_text())
            if isinstance(cfg, dict):
                web_server = (cfg.get("system") or {}).get("web_server")
                port = web_server.get("port") if isinstance(web_server, dict) else None
                if isinstance(port, int) and 0 < port < 65536:
                    return port
    except Exception:
        pass
    # 3. state → 4. дефолт.
    try:
        port = _load_state().get("web_port")
        if isinstance(port, int) and 0 < port < 65536:
            return port
    except Exception:
        pass
    return B4_WEB_PORT


def _b4_rest_request(method: str, path: str, payload: Optional[dict] = None,
                     _retry_auth: bool = True):
    """HTTP-запрос к локальному REST API b4 (без прокси, 127.0.0.1).

    При включённой web-авторизации добавляет Authorization: Bearer
    (токен из _b4_api_token); при 401 перевыпускает токен и
    повторяет запрос один раз.

    Returns:
        (status_code, parsed_body | None) — при любом HTTP-ответе;
        None — если соединиться не удалось (b4 не запущен / API нет).
    """
    port = _b4_web_port()
    if not port:
        return None
    url = f"http://127.0.0.1:{port}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    token = _b4_api_token()
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with _B4_REST_OPENER.open(req, timeout=_B4_REST_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            try:
                return (resp.status, json.loads(body) if body.strip() else None)
            except json.JSONDecodeError:
                return (resp.status, None)
    except urllib.error.HTTPError as e:
        if e.code == 401 and _retry_auth:
            # Токен протух (TTL 24ч) или пароль сменили — перевыпускаем.
            _B4_API_TOKEN["value"] = None
            return _b4_rest_request(method, path, payload, _retry_auth=False)
        try:
            body = e.read().decode("utf-8", errors="replace")
            parsed = json.loads(body) if body.strip() else None
        except Exception:
            parsed = None
        return (e.code, parsed)
    except Exception:
        return None


def _b4_rest_import_set(custom_set: dict) -> Optional[bool]:
    """Импорт сета через REST API b4: PUT /api/sets/{id} (замена) или
    POST /api/sets (создание; id назначает сам b4).

    Замена ищется по id, затем по имени: POST назначает сету новый uuid,
    поэтому без сверки по имени повторный импорт того же JSON плодил бы
    дубликат сета.

    Returns:
        True  — b4 принял сет (hot-reload выполнен на его стороне);
        False — b4 явно отклонил сет (валидация); config.json НЕ трогаем;
        None  — API недоступен (не запущен / нет API / auth включён) —
                вызывающий код откатывается на запись config.json.
    """
    resp = _b4_rest_request("GET", "/api/sets")
    if resp is None:
        return None
    status, sets = resp
    if status == 401:
        _info("Web UI b4 под паролем — REST API требует авторизации, "
              "использую прямую запись config.json")
        return None
    if status != 200 or not isinstance(sets, list):
        return None

    set_id = str(custom_set.get("id") or "")
    name = str(custom_set.get("name") or "")
    target_id, matched_by = "", ""
    if set_id:
        for s in sets:
            if isinstance(s, dict) and s.get("id") == set_id:
                target_id, matched_by = str(s.get("id") or ""), "id"
                break
    if not target_id and name:
        for s in sets:
            if isinstance(s, dict) and s.get("name") == name:
                target_id, matched_by = str(s.get("id") or ""), "имени"
                break

    if target_id:
        _info(f"REST API: заменяю существующий сет (совпадение по {matched_by}, "
              f"id={target_id})")
        resp = _b4_rest_request("PUT", f"/api/sets/{target_id}", custom_set)
    else:
        resp = _b4_rest_request("POST", "/api/sets", custom_set)
    if resp is None:
        return None
    status, body = resp
    if status in (200, 201):
        return True
    detail = ""
    if isinstance(body, dict):
        detail = str(body.get("error") or body.get("message") or body)
    elif body is not None:
        detail = str(body)
    _err(f"b4 отклонил сет (HTTP {status}){': ' + detail[:300] if detail else ''}")
    return False


# ══════════════════════════════════════════════════════════════════════════
#  КАСТОМНЫЕ СЕТЫ (импорт из файла или вставка JSON)
# ══════════════════════════════════════════════════════════════════════════

def import_custom_set(json_str: str) -> bool:
    """Импортирует кастомный b4 set из JSON-строки.

    Принимает JSON в формате b4 (один объект сета ИЛИ {"sets": [...]}).
    Добавляет id если нет, нормализует wildcard-домены ("*.example.com" →
    apex "example.com" — движок b4 матчит поддомены суффикс-матчингом,
    wildcard-записи не поддерживает), импортирует через REST API b4
    (hot-reload: без рестарта сервиса и без перезаписи config.json).
    Если REST недоступен — откат на прямую запись config.json с МЁРЖЕМ
    (топ-уровневые секции queue/ui/system сохраняются).

    Используется:
      • TUI: пункт «Импортировать кастомный сет»
      • REST API: POST /api/b4/import-set
    """
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        _err(f"Невалидный JSON: {e}")
        return False

    # Если это {"sets": [...]} — берём первый set.
    if isinstance(data, dict) and "sets" in data:
        sets = data["sets"]
        if not sets:
            _err("Пустой массив sets")
            return False
        custom_set = sets[0]
    elif isinstance(data, dict):
        # Одиночный объект — обрабатываем как один set.
        custom_set = data
    else:
        _err("Ожидается JSON-объект с set")
        return False

    # Добавляем уникальный id если нет.
    # Используем uuid4 — каждый сет получает свой id, чтобы можно было
    # импортировать несколько сетов без замены.
    import uuid
    if not custom_set.get("id"):
        custom_set["id"] = f"custom-{uuid.uuid4().hex[:12]}"

    # Нормализация wildcard-доменов: "*.whatsapp.com" → "whatsapp.com".
    # Без этого сторонние сеты с wildcard-записями импортируются
    # пустышками: движок b4 сравнивает записи литерально, реальный
    # трафик (web.whatsapp.com и т.п.) не матчится — бейджей в
    # Traffic нет, DPI-обработка не применяется.
    changed_domains = _normalize_set_domains(custom_set)
    if changed_domains:
        _info(f"Нормализовано доменных записей: {changed_domains} "
              f'(wildcard "*.domain" → apex: b4 матчит поддомены '
              f"суффикс-матчингом, wildcard-записи движком не поддерживаются)")

    # Проверяем минимально-обязательные поля.
    targets = custom_set.get("targets", {})
    if not targets.get("sni_domains") and not targets.get("geosite_categories"):
        _err("В сете нет targets.sni_domains и нет geosite_categories — нечего матчить")
        return False

    # Импортируем сет ВКЛЮЧЁННЫМ: если в JSON нет поля enabled, b4
    # (Go-декодер) молча считает его false — сет импортировался
    # выключенным и не матчил трафик до ручного включения в Web UI.
    if "enabled" not in custom_set:
        custom_set["enabled"] = True

    # Мёртвое поле b4_version (не поле SetConfig — b4 его игнорирует
    # и выкидывает при сохранении). В сете может прийти из экспорта
    # конфига, написанного старой Chimera.
    if "b4_version" in custom_set:
        del custom_set["b4_version"]
        _info("Удалено legacy-поле b4_version из импортируемого сета")

    #  Основной путь: REST API b4 (b4 >= 1.78). b4 сам валидирует сет,
    #  применяет hot-reload (без systemctl restart — соединения не рвутся,
    #  Discovery-кеш и статистика не теряются) и сохраняет config.json,
    #  не теряя топ-уровневые секции (queue/ui/system.webserver).
    #  REST недоступен (b4 не запущен, старая версия, Web UI под паролем)
    #  → откат на прямую запись config.json ниже.
    rest_result = _b4_rest_import_set(custom_set)
    if rest_result is True:
        # Сохраняем state.
        state = _load_state()
        state["active_preset"] = "custom"
        _save_state(state)
        name = custom_set.get("name", "custom")
        _ok(f"Кастомный сет «{name}» импортирован через REST API "
            f"(hot-reload, без рестарта b4)")
        # Применяем Xray routing: домены сета → outbound:direct,
        # чтобы трафик шёл через entry VPS (где стоит b4), а не через exit.
        # Авто-синхронизация всех b4-сетов с Xray routing.
        _info("Авто-синхронизация b4 → Xray routing...")
        apply_routing_for_all_sets()
        return True
    if rest_result is False:
        # b4 явно отклонил сет (валидация) — НЕ пишем невалидный сет в
        # config.json: при следующем рестарте b4 не смог бы загрузить
        # конфиг. Пользователь видит причину отказа выше.
        return False

    #  ЛЕГАСИ-ПУТЬ: прямая запись config.json (b4 без REST API).
    #  Мультисетовый импорт: добавляем сет к существующим, не стирая.
    #  ВАЖНО: мёржим с существующим конфигом, а не перезаписываем
    #  минимальным шаблоном — топ-уровневые секции queue (NFQUEUE-номер,
    #  mark, ipv4/ipv6), ui и system.webserver (порт Web UI, auth) ранее
    #  терялись и сбрасывались на дефолты b4.
    existing_cfg = {}
    if B4_CONFIG_FILE.exists():
        try:
            parsed = json.loads(B4_CONFIG_FILE.read_text())
            if isinstance(parsed, dict):
                existing_cfg = parsed
        except Exception:
            pass  # Конфиг повреждён — начнём с чистого конфига

    existing_sets = existing_cfg.get("sets")
    if not isinstance(existing_sets, list):
        existing_sets = []

    # Проверяем, нет ли уже сета с таким id — если есть, заменяем.
    set_id = custom_set.get("id")
    replaced = False
    for i, s in enumerate(existing_sets):
        if isinstance(s, dict) and s.get("id") == set_id:
            existing_sets[i] = custom_set
            replaced = True
            break
    if not replaced:
        existing_sets.append(custom_set)

    _info(f"Сетов в конфиге: {len(existing_sets)} "
          f"({'заменён' if replaced else 'добавлен'} id={set_id})")

    existing_cfg["sets"] = existing_sets
    # Секция system (geosite/geoip пути для Discovery) — обязательна.
    # Если b4 уже создал свою (с sitedat_path, ipdat_url и т.д.) —
    # сохраняем её как есть.
    if not existing_cfg.get("system"):
        existing_cfg["system"] = {
            "geo": _b4_geo_section(),
        }
    # Чистим legacy-поля старого конфига (udp/routing, geosite_path, b4_version).
    legacy_fixed = _b4_clean_legacy_config_keys(existing_cfg)
    if legacy_fixed:
        _info(f"Чистка legacy-полей конфига b4: {legacy_fixed} исправлений "
              f"(udp/routing, geosite_path → geo.sitedat_path, b4_version)")
    try:
        B4_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        B4_CONFIG_FILE.write_text(json.dumps(existing_cfg, indent=2, ensure_ascii=False))
        B4_CONFIG_FILE.chmod(0o644)
    except OSError as e:
        _err(f"Не удалось записать {B4_CONFIG_FILE}: {e}")
        return False
    # Перезапускаем сервис.
    subprocess.run(["systemctl", "restart", "b4"], capture_output=True, check=False)
    # Сохраняем state.
    state = _load_state()
    state["active_preset"] = "custom"
    _save_state(state)
    name = custom_set.get("name", "custom")
    _ok(f"Кастомный сет «{name}» импортирован, b4 перезапущен")
    # Применяем Xray routing: домены сета → outbound:direct,
    # чтобы трафик шёл через entry VPS (где стоит b4), а не через exit.
    # Авто-синхронизация всех b4-сетов с Xray routing.
    # Раньше вызывалось apply_routing_for_set для одного сета — но это
    # создавало N restarts Xray при N сетах. Теперь — один bulk sync.
    _info("Авто-синхронизация b4 → Xray routing...")
    apply_routing_for_all_sets()
    return True


def import_custom_set_from_file(file_path: str) -> bool:
    """Импортирует кастомный сет из JSON-файла."""
    path = Path(file_path)
    if not path.exists():
        _err(f"Файл не найден: {file_path}")
        return False
    try:
        json_str = path.read_text()
    except Exception as e:
        _err(f"Не удалось прочитать файл: {e}")
        return False
    return import_custom_set(json_str)


def run_discovery(timeout_sec: int = 60) -> dict:
    """Запускает Discovery b4 — автоподбор рабочего сета под текущего провайдера.

    Discovery работает через Web API b4 (POST /api/discovery/start).
    Возвращает результат: подобранный сет + latency до YouTube.
    """
    web_port = status().get("web_port", B4_WEB_PORT)
    if not web_port:
        return {"error": "b4 не установлен"}
    _info(f"Запускаю Discovery (таймаут {timeout_sec}с)...")
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{web_port}/api/discovery/start",
            method="POST",
            data=json.dumps({"target": "youtube.com"}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout_sec + 10) as resp:
            data = json.loads(resp.read().decode())
        _ok(f"Discovery завершён: {data.get('status','?')}")
        return data
    except Exception as e:
        _err(f"Discovery failed: {e}")
        _info("Discovery можно запустить вручную через Web UI:")
        _info(f"  ssh -L {web_port}:127.0.0.1:{web_port} root@<server>")
        _info(f"  → http://localhost:{web_port}")
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════════════
#  HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════════

def health_check_youtube() -> dict:
    """Проверяет, работает ли YouTube (через curl с сервера).

    Делает 3 попытки:
      1. Прямой запрос к youtube.com (через b4 — должен работать)
      2. Запрос к googlevideo.com (CDN)
      3. Запрос к ytimg.com (статика)

    Важно: googlevideo.com и ytimg.com не отдают 200 на root URL — они
    возвращают 404 (это нормально, CDN без правильного пути). Поэтому
    принимаем любой HTTP-ответ (2xx/3xx/4xx) как «работает» — главное
    что TCP/TLS-handshake прошёл и сервер ответил. Если ТСПУ блокирует —
    curl получит timeout или connection reset, не HTTP-код.
    """
    results = {"targets": [], "all_ok": True}
    targets = [
        # youtube.com — главная страница (200 = OK).
        ("youtube.com", "https://www.youtube.com/"),
        # ytimg.com — CDN статики. Конкретный thumbnail точно работает.
        ("ytimg.com", "https://i.ytimg.com/vi/dQw4w9WgXcQ/default.jpg"),
        # googlevideo.com убран из health check: корневой домен
        # не резолвится (000 = DNS-fail). CDN-видео использует
        # динамические поддомены (r*.sn.*.googlevideo.com), которые
        # невозможно предсказать. Если youtube.com + ytimg.com работают —
        # b4 функционирует корректно.
    ]
    for label, url in targets:
        try:
            r = subprocess.run(
                ["curl", "-sI", "--max-time", "10", "-o", "/dev/null",
                 "-w", "%{http_code} %{time_total}", url],
                capture_output=True, text=True, check=False, timeout=15,
            )
            # OK = curl вернул любой HTTP-код (200/302/404/403 = сервер ответил).
            # FAIL = timeout, connection reset, DNS-fail (пустой stdout).
            http_code = r.stdout.strip().split()[0] if r.stdout.strip() else ""
            ok = (r.returncode == 0 and
                  http_code and http_code[0] in ("2", "3", "4"))
            results["targets"].append({
                "target": label,
                "ok": ok,
                "code": r.stdout.strip() if r.stdout else "TIMEOUT/RESET",
            })
            if not ok:
                results["all_ok"] = False
        except Exception as e:
            results["targets"].append({
                "target": label, "ok": False, "error": str(e),
            })
            results["all_ok"] = False
    return results


# ══════════════════════════════════════════════════════════════════════════
#  INFO ДЛЯ ПОРТАЛОВ (REST API)
# ══════════════════════════════════════════════════════════════════════════

def get_portal_info() -> dict:
    """Краткий статус для User Portal."""
    s = status()
    _preset_name = s.get("active_preset")
    _set_name = s.get("active_set_name")
    if _preset_name in PRESETS:
        _label = PRESETS[_preset_name][0]
    elif _preset_name == "custom" and _set_name:
        _label = f"custom ({_set_name})"
    elif _preset_name == "custom":
        _label = "custom"
    elif _preset_name == "none":
        _label = "не выбран"
    else:
        _label = None
    return {
        "installed": s["installed"],
        "active": s.get("service_active", False),
        "preset": _preset_name,
        "preset_label": _label,
        "active_set_name": _set_name,
    }


def get_admin_info() -> dict:
    """Полный статус для Admin Panel."""
    s = status()
    s["presets"] = [{"name": k, "label": v[0]} for k, v in PRESETS.items()]
    # Логи (последние 20 строк journalctl).
    s["logs"] = []
    try:
        r = subprocess.run(
            ["journalctl", "-u", "b4", "-n", "20", "--no-pager", "-o", "cat"],
            capture_output=True, text=True, check=False, timeout=5,
        )
        s["logs"] = r.stdout.splitlines()[-20:] if r.stdout else []
    except Exception:
        pass
    return s


# ══════════════════════════════════════════════════════════════════════════
#  TUI-МЕНЮ
# ══════════════════════════════════════════════════════════════════════════

def do_dpi_bypass_menu() -> None:
    """TUI-меню управления b4 для YouTube DPI bypass."""
    #  Авто-миграция со старого режима (--skip-tables) на native b4 rules.
    # Если обнаружен старый systemd-unit — мигрируем автоматически.
    _migrate_to_native_rules_if_needed()
    while True:
        os.system("clear")
        s = status()
        _box_top(f"📺  YOUTUBE VIA B4 (DPI BYPASS НА ENTRY)  {DIM}v{s.get('version', '?')}{NC}")
        _box_row()
        if not s["installed"]:
            _box_warn("b4 не установлен. YouTube DPI bypass неактивен.")
            _box_row(f"  {DIM}b4 — DPI bypass демон, ставится на entry VPS.{NC}")
            _box_row(f"  {DIM}Перехватывает исходящий трафик к YouTube CDN{NC}")
            _box_row(f"  {DIM}и применяет fake SNI + фрагментацию ClientHello.{NC}")
            _box_row(f"  {DIM}ТСПУ не может сопоставить SNI → пропускает.{NC}")
            _box_row()
            _box_row(f"  {DIM}Требования: ядро 3.13+, NFQUEUE, root.{NC}")
            _box_row(f"  {DIM}Совместим с UFW/iptables/ingress_geoip.{NC}")
            _box_row()
            _box_item("1", "🚀 Установить b4 (скачать + конфиг + systemd + iptables)")
            _box_row()
            _box_back()
            _box_bottom()
        else:
            status_col = GREEN if s.get("service_active") else RED
            status_str = "active" if s.get("service_active") else "stopped"
            _box_row(f"  Сервис:       {status_col}{status_str}{NC}")
            _box_row(f"  Версия:       {CYAN}{s.get('version', '?')}{NC}")
            #  Отображение активных сетов из config.json.
            # Показываем все активные (enabled=true) сеты с зелёными точками.
            _active_sets = s.get("active_sets", [])
            _preset_name = s.get("active_preset")
            if _active_sets:
                _dots = "  ".join(f"{GREEN}●{NC} {name}" for name in _active_sets)
                preset_label = _dots
            elif _preset_name == "none":
                preset_label = f"{YELLOW}НЕ ВЫБРАН — выберите [2] или Discovery{NC}"
            elif _preset_name in PRESETS:
                preset_label = PRESETS[_preset_name][0]
            elif _preset_name == "custom" and s.get("active_set_name"):
                preset_label = f"custom ({s.get('active_set_name')})"
            elif _preset_name == "custom":
                preset_label = "custom"
            else:
                preset_label = "—"
            _box_row(f"  Preset:       {preset_label}")
            _box_row(f"  Web UI:       {CYAN}http://127.0.0.1:{s.get('web_port')}{NC}")
            # Если nginx front включён — показываем прямой URL.
            ng_url = s.get("nginx_front_url")
            if ng_url:
                _box_row(f"  Web UI (TLS): {GREEN}{ng_url}{NC}")
            _box_row(f"  Queue:        {CYAN}NFQUEUE {s.get('queue_num')}{NC} (mark={s.get('mark')})")
            _box_row(f"  Config:       {DIM}{s.get('config_path')}{NC}")
            _box_row(f"  Binary:       {DIM}{s.get('binary_path')}{NC}")
            _box_row()
            _box_row(f"  {DIM}Как это работает:{NC}")
            _box_row(f"  {DIM}1. Xray на entry → geosite:youtube → outbound:direct{NC}")
            _box_row(f"  {DIM}2. freedom outbound открывает TCP к youtube.com:443{NC}")
            _box_row(f"  {DIM}3. iptables mangle → NFQUEUE {s.get('queue_num')}{NC}")
            _box_row(f"  {DIM}4. b4: fake DuckDuckGo ClientHello + фрагментация{NC}")
            _box_row(f"  {DIM}5. ТСПУ не видит SNI → пропускает → YouTube работает{NC}")
            _box_row()
            #  Предупреждение если пресет не выбран (clean install).
            # В централизованном модуле — только предупреждение, без списка
            # пресетов (список есть в youtube_b4 модуле).
            if s.get("active_preset") == "none":
                _box_warn("⚠  ПРЕСЕТ НЕ ВЫБРАН — DPI bypass неактивен!")
                _box_row()
                _box_row(f"  {DIM}Выберите пресет через [2] или Discovery в Web UI [4].{NC}")
                _box_row(f"  {DIM}Список пресетов с плюсами/минусами — в модуле{NC}")
                _box_row(f"  {DIM}YouTube через B4 (Главное меню → 3 → Y → B).{NC}")
                _box_row()
            #  Инструкция по импорту сета из Discovery (всегда показывается).
            _box_row(f"  {YELLOW}{BOLD}📋 ИМПОРТ СЕТА ИЗ DISCOVERY (Web UI → TUI):{NC}")
            _box_row(f"  {YELLOW}1. Найдите рабочую стратегию обхода в Web-UI B4{NC}")
            _box_row(f"  {YELLOW}2. Нажмите Use This Strategy{NC}")
            _box_row(f"  {YELLOW}3. Create Set{NC}")
            _box_row(f"  {YELLOW}4. На странице с сетами нажмите на три точки на карточке сета, затем нажмите Edit{NC}")
            _box_row(f"  {YELLOW}5. Перейдите в Import/Export{NC}")
            _box_row(f"  {YELLOW}6. Нажмите Copy JSON{NC}")
            _box_row(f"  {YELLOW}7. Удалите созданный сет{NC}")
            _box_row(f"  {YELLOW}8. Перейдите в TUI Chimera по пути Главное меню->3->Y->B{NC}")
            _box_row(f"  {YELLOW}9. Нажмите 3 - Импортировать кастомный сет (JSON){NC}")
            _box_row(f"  {YELLOW}10. Вставьте содержимое скопированного сета из п.6 и нажмите Enter.{NC}")
            _box_row(f"  {YELLOW}11. Перейдите в Web-UI во вкладку 'Sets', нажмите F5, чтобы перезагрузить страницу и убедитесь, что сет импортирован успешно.{NC}")
            _box_row()
            _box_sep()
            if s.get("service_active"):
                _box_item("1", "🛑 Остановить b4 (без удаления)")
            else:
                _box_item("1", "🚀 Запустить b4")
            _box_item("2", "🔄 Переключить preset")
            _box_item("3", "📥 Импортировать кастомный сет (JSON)")
            _box_item("4", "🔍 Discovery (автоподбор сета под провайдера)")
            _box_item("5", "🔄 Обновление Bye Bye Big Bro (release / pre-release)")
            _box_item("6", "🏥 Health check YouTube (работает ли?)")
            _box_item("7", "📋 Логи b4 (последние 30 строк)")
            _box_item("8", "🌐 Открыть Web UI (SSH-туннель инструкция)")
            # nginx front (TLS) для прямого доступа к Web UI из браузера.
            ng_st = _b4_nginx_status()
            if ng_st.get("enabled"):
                ng_url = _b4_nginx_get_url()
                _box_item("9", f"🌐 nginx front (TLS) — {YELLOW}выключить{NC}  {DIM}({ng_url}){NC}")
            else:
                _box_item("9", f"🌐 nginx front (TLS) — {DIM}включить прямой доступ к Web UI по HTTPS{NC}")
            _box_row()
            if s["installed"]:
                _box_item("S", f"🔁 Синхронизировать домены b4 → Xray routing  {DIM}(все активные сеты → direct){NC}")
                _box_row()
            _box_item("R", f"{RED}🗑️  Удалить b4 полностью{NC}")
            _box_row()
            _box_back()
            _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return

        if ch == "q" or ch == "0" or ch == "":
            return

        if not s["installed"] and ch == "1":
            # Установка.
            if install_b4():
                _info("YouTube DPI bypass активирован!")
                _info("Проверьте: Главное меню → 2 → Y → YouTube via RU = On")
                _info("  (b4 работает поверх routing geosite:youtube → direct)")
            input(f"\n{BOLD}Enter…{NC}")

        elif s["installed"] and ch == "1":
            # Запуск/остановка.
            if s.get("service_active"):
                disable()
            else:
                enable()
            input(f"\n{BOLD}Enter…{NC}")

        elif s["installed"] and ch == "2":
            # Переключить preset.
            print()
            for i, (name, (label, _)) in enumerate(PRESETS.items(), 1):
                marker = f" {GREEN}← текущий{NC}" if name == s.get("active_preset") else ""
                print(f"  {DIM}{i}.{NC} {label}{marker}")
            try:
                v = input(f"\n{CYAN}Выбор:{NC} ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            presets_list = list(PRESETS.keys())
            try:
                idx = int(v) - 1
                if 0 <= idx < len(presets_list):
                    switch_preset(presets_list[idx])
            except ValueError:
                _warn("Неверный ввод.")
            input(f"\n{BOLD}Enter…{NC}")

        elif s["installed"] and ch == "3":
            # Импорт кастомного сета.
            print()
            _box_top("📥  ИМПОРТ КАСТОМНОГО СЕТА")
            _box_row()
            _box_row(f"  {DIM}Вставьте JSON сета (из b4 Web UI, из файла, или{NC}")
            _box_row(f"  {DIM}написанный вручную). Формат:{NC}")
            _box_row(f"  {DIM}{{\"name\":\"...\",\"targets\":{{\"sni_domains\":[...]}},...}}{NC}")
            _box_row(f"  {DIM}Или: {{\"sets\":[...]}} — возьмётся первый set.{NC}")
            _box_row()
            _box_row(f"  {DIM}Вставьте JSON одной строкой или многострочно.{NC}")
            _box_row(f"  {DIM}Чтение закончится автоматически, когда глубина '{{...}}' = 0.{NC}")
            _box_row(f"  {DIM}Ctrl+C — отмена, Ctrl+D — конец ввода.{NC}")
            _box_bottom()
            # v4.26 FIX: readline-цикл через input() обрезает вставку на 4 КБ
            # из-за канонического режима TTY (N_TTY_BUF_SIZE = 4096 в Linux).
            # Большие сеты (Meta-facebook-v18-MAX и т.п., 8-15 КБ) падали с
            # «Unterminated string at: column 4092». Используем cbreak-режим
            # через termios — читаем посимвольно, без 4-КБ буфера.
            from chimera.modules._tty_json import read_long_json_stdin
            try:
                json_str = read_long_json_stdin()
            except KeyboardInterrupt:
                print()
                _warn("Отмена.")
                input(f"\n{BOLD}Enter…{NC}")
                continue
            if not json_str.strip():
                _warn("Пустой ввод.")
                input(f"\n{BOLD}Enter…{NC}")
                continue
            import_custom_set(json_str)
            input(f"\n{BOLD}Enter…{NC}")

        elif s["installed"] and ch == "4":
            # Discovery.
            result = run_discovery(timeout_sec=60)
            if "error" not in result:
                _info(f"Результат: {json.dumps(result, indent=2, ensure_ascii=False)}")
            input(f"\n{BOLD}Enter…{NC}")

        elif s["installed"] and ch == "5":
            # Раздел «Обновление Bye Bye Big Bro» — подменю с двумя
            # подразделами: release / pre-release + принудительное
            # обновление + синхронизация версии между связанными
            # модулями (общий binary + общий state).
            do_b4_update_menu()

        elif s["installed"] and ch == "u":
            # Скрытый алиас [U] (совместимость со старой привычкой):
            # раньше [U] сразу запускал pre-release обновление. Теперь
            # открывает раздел обновления, где pre-release — подраздел [2].
            do_b4_update_menu()

        elif s["installed"] and ch == "6":
            _info("Проверяю сайты (до 30с)...")
            result = health_check_youtube()
            for t in result["targets"]:
                col = GREEN if t["ok"] else RED
                status_str = f"{col}{'✓ OK' if t['ok'] else '✗ FAIL'}{NC}"
                code = t.get("code", t.get("error", ""))
                print(f"  {t['target']:<25} {status_str}  {DIM}{code}{NC}")
            if result["all_ok"]:
                _ok("Все цели доступны! b4 работает корректно.")
            else:
                _warn("Часть целей недоступна. Возможно, нужно переключить preset.")
                _info("Попробуйте: Discovery (пункт 3) или другой preset (пункт 2).")
            input(f"\n{BOLD}Enter…{NC}")

        elif s["installed"] and ch == "7":
            # Логи.
            os.system("clear")
            _box_top("📋  ЛОГИ B4 (ПОСЛЕДНИЕ 30 СТРОК)")
            _box_row()
            try:
                r = subprocess.run(
                    ["journalctl", "-u", "b4", "-n", "30", "--no-pager", "-o", "cat"],
                    capture_output=True, text=True, check=False, timeout=5,
                )
                raw = r.stdout or "(пусто)"
            except Exception as e:
                raw = f"Ошибка: {e}"
            # Усечение строк по ширине рамки (через _box_row — не ломает границы).
            from chimera.modules.box_renderer import _get_box_width as _gw
            _w = _gw() - 4  # -4 для отступа "  " + запас
            for line in raw.splitlines():
                _line = line if len(line) <= _w else line[:_w-3] + "..."
                _box_row(f"  {DIM}{_line}{NC}")
            _box_row()
            _box_row(f"  {DIM}Полные логи:{NC}")
            _box_row(f"    {CYAN}journalctl -u b4 -f{NC}  {DIM}(live режим){NC}")
            _box_row(f"    {CYAN}journalctl -u b4 -n 100 --no-pager{NC}  {DIM}(последние 100){NC}")
            _box_row(f"  {DIM}Файл логов:{NC} /var/log/b4/")
            _box_bottom()
            input(f"\n{BOLD}Enter…{NC}")

        elif s["installed"] and ch == "8":
            # Web UI инструкция.
            web_port = s.get("web_port", B4_WEB_PORT)
            os.system("clear")
            _box_top("🌐  WEB UI B4 (ИНСТРУКЦИЯ)")
            _box_row()
            _box_row(f"  Web UI b4 слушает только на 127.0.0.1:{web_port}")
            _box_row(f"  {DIM}(не открывается наружу — безопасность){NC}")
            _box_row()
            _box_row(f"  {BOLD}Доступ через SSH-туннель:{NC}")
            _box_row(f"    {CYAN}ssh -L {web_port}:127.0.0.1:{web_port} root@<server>{NC}")
            _box_row(f"  {BOLD}Затем в браузере:{NC}")
            _box_row(f"    {CYAN}http://localhost:{web_port}{NC}")
            _box_row()
            _box_row(f"  {DIM}В Web UI можно:{NC}")
            _box_row(f"  {DIM}• Управлять сетами (включить/выключить){NC}")
            _box_row(f"  {DIM}• Запустить Discovery (автоподбор сета){NC}")
            _box_row(f"  {DIM}• Смотреть статистику в реальном времени{NC}")
            _box_row(f"  {DIM}• Импортировать кастомные сеты{NC}")
            _box_row()
            _box_back()
            _box_bottom()
            input(f"\n{BOLD}Enter…{NC}")

        elif s["installed"] and ch == "9":
            # nginx front (TLS) для b4 Web UI.
            ng_st = _b4_nginx_status()
            if ng_st.get("enabled"):
                # Выключение.
                os.system("clear")
                _box_top("🌐  NGINX FRONT ДЛЯ B4 — ВЫКЛЮЧЕНИЕ")
                _box_row()
                _box_row(f"  {DIM}Будет удалён nginx vhost + закрыт порт {ng_st.get('port', DEFAULT_B4_NGINX_PORT)}.{NC}")
                _box_row(f"  {DIM}Доступ к Web UI вернётся на SSH-туннель.{NC}")
                _box_row()
                _box_back()
                _box_bottom()
                confirm = input(f"  {YELLOW}Выключить nginx front? [y/N]:{NC} ").strip().lower()
                if confirm == "y":
                    ok, msg = _b4_nginx_remove()
                    if ok:
                        _ok(msg)
                    else:
                        _err(msg)
                else:
                    _info("Отменено.")
            else:
                # Включение.
                state = _load_state()
                # Спрашиваем порт.
                try:
                    port_str = input(f"  Порт для nginx front [Enter={DEFAULT_B4_NGINX_PORT}]: ").strip()
                    ng_port = int(port_str) if port_str else DEFAULT_B4_NGINX_PORT
                except (ValueError, EOFError, KeyboardInterrupt):
                    ng_port = DEFAULT_B4_NGINX_PORT
                # Спрашиваем режим TLS.
                try:
                    from chimera.modules.panel_nginx_front import ask_tls_mode, ask_domain
                except ImportError:
                    _err("panel_nginx_front недоступен — не могу установить nginx front.")
                    input(f"\n{BOLD}Enter…{NC}")
                    continue
                use_self_signed, _ = ask_tls_mode("b4 Web UI")
                domain = None
                if not use_self_signed:
                    # Пытаемся взять домен из state.json.
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
                ok, msg = _b4_nginx_install(ng_port, use_self_signed, domain)
                if ok:
                    _ok(f"nginx front включён на порту {ng_port}.")
                    url = _b4_nginx_get_url()
                    if url:
                        _info(f"Web UI доступен: {url}")
                    _info(f"Прямой доступ к порту {B4_WEB_PORT} закрыт (только через nginx).")
                else:
                    _err(f"Не удалось установить nginx front: {msg}")
            input(f"\n{BOLD}Enter…{NC}")

        elif s["installed"] and ch == "s":
            # Синхронизация доменов b4 → Xray routing.
            os.system("clear")
            _box_top("🔁  СИНХРОНИЗАЦИЯ b4 → XRAY ROUTING")
            _box_row()
            _box_row(f"  {DIM}Читаю активные b4-сеты...{NC}")
            _box_bottom()
            print()
            try:
                result = apply_routing_for_all_sets()
                print()
                _box_top("🔁  РЕЗУЛЬТАТ СИНХРОНИЗАЦИИ")
                _box_row()
                _box_row(f"  Применено set'ов:    {GREEN}{result['applied']}{NC}")
                _box_row(f"  Всего доменов:       {GREEN}{result['total_domains']}{NC}")
                _box_row(f"  Удалено stale:       {YELLOW}{result['removed']}{NC}")
                if result.get("errors"):
                    _box_row(f"  Ошибки:              {RED}{len(result['errors'])}{NC}")
                    for e in result["errors"][:3]:
                        _box_row(f"    {DIM}• {e[:60]}{NC}")
                else:
                    _box_row(f"  Ошибки:              {GREEN}0{NC}")
                _box_row()
                _box_row(f"  {DIM}Все домены из активных b4-сетов теперь идут через{NC}")
                _box_row(f"  {DIM}direct (RU-сервер) → b4 → DPI bypass → целевой сайт.{NC}")
                _box_row(f"  {DIM}Каскад на exit-ноды для них отключён.{NC}")
                _box_bottom()
            except Exception as e:
                _box_top("🔁  СИНХРОНИЗАЦИЯ b4 → XRAY ROUTING")
                _box_row()
                _box_warn(f"Ошибка синхронизации: {e}")
                _box_bottom()
            input(f"\n{BOLD}Enter…{NC}")

        elif s["installed"] and ch == "r":
            # Удаление.
            confirm = input(f"  {RED}Удалить b4 полностью? (y/N):{NC} ").strip().lower()
            if confirm == "y":
                uninstall_b4()
            input(f"\n{BOLD}Enter…{NC}")


# ══════════════════════════════════════════════════════════════════════════
#  КЛИЕНТ CLI
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":  # pragma: no cover
    import sys
    if len(sys.argv) < 2:
        # Без аргументов — открываем интерактивное TUI-меню.
        # REGRESSION: раньше здесь стоял вызов функции меню соседнего
        # модуля youtube_b4 — её нет в пространстве имён dpi_bypass
        # (NameError при запуске без аргументов).
        do_dpi_bypass_menu()
    else:
        import argparse
        p = argparse.ArgumentParser(description="DPI Bypass (b4) — централизованный модуль")
        p.add_argument("cmd", choices=["install", "uninstall", "status", "enable",
                                       "disable", "health", "discovery",
                                       "update", "update-pre", "sync-version"])
        args = p.parse_args()
        if args.cmd == "install":
            install_b4()
        elif args.cmd == "uninstall":
            uninstall_b4()
        elif args.cmd == "status":
            print(json.dumps(status(), indent=2))
        elif args.cmd == "enable":
            enable()
        elif args.cmd == "disable":
            disable()
        elif args.cmd == "health":
            print(json.dumps(health_check_youtube(), indent=2))
        elif args.cmd == "discovery":
            print(json.dumps(run_discovery(), indent=2))
        elif args.cmd == "update":
            # Обновление до последней release-версии (force — вторым
            # аргументом CLI не задаётся, см. TUI-подменю).
            print(json.dumps(auto_update(), indent=2, ensure_ascii=False))
        elif args.cmd == "update-pre":
            print(json.dumps(auto_update_prerelease(confirm=False),
                             indent=2, ensure_ascii=False))
        elif args.cmd == "sync-version":
            print(json.dumps(sync_b4_version_state(), indent=2, ensure_ascii=False))
