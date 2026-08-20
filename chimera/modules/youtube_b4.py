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

# Эталонный сет юзера (DuckDuckGo fake + combo fragmentation).
# Проверен на провайдере юзера — работает с b4 на роутере.
# На VPS может потребоваться Discovery для подбора под конкретного хостера.
DEFAULT_SET_YOUTUBE = {
    "id": "youtube",
    "b4_version": B4_VERSION,
    "name": "Youtube",
    "enabled": True,
    "tcp": {
        "seg2delay": 20,
        "seg2delay_max": 60,
    },
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
    "b4_version": B4_VERSION,
    "name": "Youtube-Aggressive",
    "enabled": True,
    "tcp": {
        "seg2delay": 10,
        "seg2delay_max": 30,
    },
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
    "b4_version": B4_VERSION,
    "name": "Youtube-Light",
    "enabled": True,
    "tcp": {
        "seg2delay": 30,
        "seg2delay_max": 80,
    },
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


# ══════════════════════════════════════════════════════════════════════════
#  ДЕТЕКТ УСТАНОВКИ (shared с dpi_bypass.py)
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


# ══════════════════════════════════════════════════════════════════════════
#  АВТООБНОВЛЕНИЕ B4 BINARY (release + pre-release)
# ══════════════════════════════════════════════════════════════════════════
#  Эти функции зеркалируют dpi_bypass.py — оба модуля работают с одним
#  binary /usr/local/bin/b4, поэтому обновление из любого модуля видно
#  другому сразу (через общий config + binary + state).
# ══════════════════════════════════════════════════════════════════════════

def _detect_latest_version() -> str:
    """Проверяет последнюю СТАБИЛЬНУЮ версию b4 на GitHub.

    /releases/latest возвращает только стабильные релизы (prerelease=false).
    Для pre-release используйте _detect_latest_prerelease_version().
    """
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


def auto_update() -> dict:
    """Проверяет и обновляет b4 binary до последней СТАБИЛЬНОЙ версии.

    1. Проверка GitHub API /releases/latest → последняя стабильная версия.
    2. Сравнение с установленной.
    3. Скачать → SHA256 → stop → backup → replace → start → verify.
    4. Конфиг и set'ы НЕ затрагиваются.

    Для PRE-RELEASE обновлений используйте auto_update_prerelease().
    """
    if not _detect_installed():
        return {"updated": False, "message": "b4 не установлен"}

    old_version = _detect_version()
    latest = _detect_latest_version()
    if not latest:
        return {"updated": False, "old_version": old_version,
                "message": "Не удалось проверить последнюю версию"}

    if old_version == latest:
        return {"updated": False, "old_version": old_version,
                "new_version": latest, "message": f"Уже актуальная версия {old_version}"}

    _info(f"Обновление: {old_version} → {latest}")
    return _do_b4_binary_update(old_version, latest)


def auto_update_prerelease(confirm: bool = True) -> dict:
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

    Возвращает тот же формат dict что и auto_update().
    """
    if not _detect_installed():
        return {"updated": False, "message": "b4 не установлен"}

    old_version = _detect_version()
    latest_pre = _detect_latest_prerelease_version()
    if not latest_pre:
        return {"updated": False, "old_version": old_version,
                "message": "Pre-release версии не найдены на GitHub"}

    if old_version == latest_pre:
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


def _write_empty_config() -> bool:
    """Создаёт ПУСТОЙ config.json без set'ов (clean install).

    Пользователь должен выбрать пресет через TUI ([2] Переключить preset)
    или подобрать через Discovery в Web UI. Это даёт гибкость — не всем
    подойдут встроенные пресеты (зависит от провайдера и ТСПУ).

    b4 запускается с пустым sets — работает в no-op режиме (не применяет
    DPI bypass), но Web UI, Discovery, API доступны.

    ВАЖНО: geosite_path обязателен для Discovery в Web UI. Без него b4
    падает с 'geosite path not configured' при попытке создать set через
    Discovery (т.к. Discovery использует geosite_categories вместо
    sni_domains).
    """
    B4_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    B4_SETS_DIR.mkdir(parents=True, exist_ok=True)
    B4_LOG_DIR.mkdir(parents=True, exist_ok=True)
    config = {
        "sets": [],
        "routing": {"enabled": False},
        "udp": {
            "mode": "fake",
            "filter_quic": "block",
        },
        "system": {
            "geosite_path": "/usr/share/xray/geosite.dat",
            "geo": {
                "ipdat_path": "/etc/b4/geoip.dat",
                "ipdat_url": "https://github.com/DanielLavrushin/b4geoip/releases/latest/download/geoip.dat",
            },
        },
    }
    B4_CONFIG_FILE.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    B4_CONFIG_FILE.chmod(0o644)
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
        # Дополнительные поля для Chimera-специфики:
        "routing": {"enabled": False},  # Не SOCKS5-upstream — direct bypass
        "udp": {
            "mode": "fake",              # fake UDP packets (b4 default)
            "filter_quic": "block",      # Блокировать QUIC (UDP/443) — браузер
                                         # откатывается на TCP/HTTP2, где b4
                                         # применяет fake SNI + фрагментацию.
                                         # Без этого QUIC bypass-ит DPI bypass.
        },
    }
    B4_CONFIG_FILE.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    B4_CONFIG_FILE.chmod(0o644)
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
      - 1.4+ GB лишнего трафика через NFQUEUE
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
    from chimera.modules.port_registry import SERVICE_SUBSCRIPTION_NGINX

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

    # nginx front status.
    ng = _b4_nginx_status()
    nginx_url = _b4_nginx_get_url()
    return {
        "installed": True,
        "service_active": service_active,
        "active_preset": active_preset,
        "active_set_name": detected_set_name,
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

    Вызывается автоматически при открытии меню b4 (do_youtube_b4_menu).
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


def switch_preset(preset_name: str) -> bool:
    """Меняет активный preset (default/aggressive/light). Перезапускает b4."""
    if preset_name not in PRESETS:
        _err(f"Неизвестный preset: {preset_name}")
        return False
    label, set_data = PRESETS[preset_name]
    _info(f"Переключаю на preset «{label}»...")
    # Полностью пересоздаём конфиг в правильном формате {"sets": [...]}.
    # Раньше пытались делать config.update() на верхнем уровне — но b4
    # ожидает sets[0] с полями tcp/faking/targets/dns, а не на верхнем уровне.
    new_set = dict(set_data)  # копия (включает id, b4_version, name, и т.д.)
    config = {
        "sets": [new_set],
        "routing": {"enabled": False},
        "udp": {
            "mode": "fake",
            "filter_quic": "block",  # Блокировать QUIC — браузер на TCP/HTTP2.
        },
        "system": {
            "geosite_path": "/usr/share/xray/geosite.dat",
            "geo": {
                "ipdat_path": "/etc/b4/geoip.dat",
                "ipdat_url": "https://github.com/DanielLavrushin/b4geoip/releases/latest/download/geoip.dat",
            },
        },
    }
    B4_CONFIG_FILE.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    # Перезапускаем сервис.
    subprocess.run(["systemctl", "restart", "b4"], capture_output=True, check=False)
    state = _load_state()
    state["active_preset"] = preset_name
    _save_state(state)
    _ok(f"Preset «{label}» применён, b4 перезапущен")
    return True


# ══════════════════════════════════════════════════════════════════════════
#  КАСТОМНЫЕ СЕТЫ (импорт из файла или вставка JSON)
# ══════════════════════════════════════════════════════════════════════════

def import_custom_set(json_str: str) -> bool:
    """Импортирует кастомный b4 set из JSON-строки.

    Принимает JSON в формате b4 (один объект сета ИЛИ {"sets": [...]}).
    Оборачивает в правильный формат, добавляет id если нет, сохраняет
    как активный конфиг b4, перезапускает сервис.

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

    # Добавляем id если нет.
    if not custom_set.get("id"):
        custom_set["id"] = "youtube-custom"
    # Убираем geosite_categories если нет sni_domains — b4 требует geosite_path.
    # Если sni_domains есть — убираем geosite_categories (он не нужен, b4
    # использует sni_domains). geosite_categories нужен только для Discovery.
    targets = custom_set.get("targets", {})
    if targets.get("sni_domains") and targets.get("geosite_categories"):
        _info("Убран geosite_categories (есть sni_domains — он не нужен)")
        targets.pop("geosite_categories", None)

    # Проверяем минимально-обязательные поля.
    if not targets.get("sni_domains") and not targets.get("geosite_categories"):
        _err("В сете нет targets.sni_domains и нет geosite_categories — нечего матчить")
        return False

    # Сохраняем конфиг.
    config = {
        "sets": [custom_set],
        "routing": {"enabled": False},
        "udp": {
            "mode": "fake",
            "filter_quic": "block",  # Блокировать QUIC — браузер на TCP/HTTP2.
        },
        "system": {
            "geosite_path": "/usr/share/xray/geosite.dat",
            "geo": {
                "ipdat_path": "/etc/b4/geoip.dat",
                "ipdat_url": "https://github.com/DanielLavrushin/b4geoip/releases/latest/download/geoip.dat",
            },
        },
    }
    B4_CONFIG_FILE.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    # Перезапускаем сервис.
    subprocess.run(["systemctl", "restart", "b4"], capture_output=True, check=False)
    # Сохраняем state.
    state = _load_state()
    state["active_preset"] = "custom"
    _save_state(state)
    name = custom_set.get("name", "custom")
    _ok(f"Кастомный сет «{name}» импортирован, b4 перезапущен")
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

def do_youtube_b4_menu() -> None:
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
            #  Отображение preset: A+B подход.
            # A: детектим preset из config.json (через _detect_active_preset_from_config).
            # B: если preset='custom' — показываем и 'custom', и имя set'а из config.json.
            _preset_name = s.get("active_preset")
            _set_name = s.get("active_set_name")
            if _preset_name in PRESETS:
                preset_label = PRESETS[_preset_name][0]
            elif _preset_name == "custom" and _set_name:
                # Кастомный set — показываем имя из config.json.
                preset_label = f"custom ({_set_name})"
            elif _preset_name == "custom":
                preset_label = "custom"
            elif _preset_name == "none":
                # Clean install — пресет не выбран.
                preset_label = f"{YELLOW}НЕ ВЫБРАН — выберите [2] или Discovery{NC}"
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
            if s.get("active_preset") == "none":
                _box_warn("⚠  ПРЕСЕТ НЕ ВЫБРАН — DPI bypass неактивен!")
                _box_row()
                _box_row(f"  {BOLD}Выберите конфигурацию:{NC}")
                _box_row()
                _box_row(f"  {CYAN}[2] Эталон (DuckDuckGo fake + combo){NC}")
                _box_row(f"      {DIM}+ Стабильный, проверен на большинстве РТ-провайдеров{NC}")
                _box_row(f"      {DIM}- Может не сработать если ТСПУ режет DuckDuckGo SNI{NC}")
                _box_row()
                _box_row(f"  {CYAN}[2] Агрессивный (Google fake + меньше delay){NC}")
                _box_row(f"      {DIM}+ Пробивает там, где DuckDuckGo заблокирован{NC}")
                _box_row(f"      {DIM}- Выше нагрузка на CPU, больше latency{NC}")
                _box_row()
                _box_row(f"  {CYAN}[2] Лёгкий (только фрагментация, без fake){NC}")
                _box_row(f"      {DIM}+ Минимальный оверхед, для слабого DPI{NC}")
                _box_row(f"      {DIM}- Не пробивает ТСПУ с SNI-инспекцией{NC}")
                _box_row()
                _box_row(f"  {CYAN}[4] Discovery в Web UI{NC}")
                _box_row(f"      {DIM}+ Автоподбор под вашего провайдера{NC}")
                _box_row(f"      {DIM}- Занимает 1-5 минут, требует Web UI [8]{NC}")
                _box_row()
                _box_row(f"  {DIM}Нажмите [2] для выбора пресета или [8] для Web UI.{NC}")
                _box_row()
            _box_sep()
            if s.get("service_active"):
                _box_item("1", "🛑 Остановить b4 (без удаления)")
            else:
                _box_item("1", "🚀 Запустить b4")
            _box_item("2", "🔄 Переключить preset")
            _box_item("3", "📥 Импортировать кастомный сет (JSON)")
            _box_item("4", "🔍 Discovery (автоподбор сета под провайдера)")
            _box_item("5", "🔄 Проверить обновление b4 (stable)")
            _box_item("U", f"🧪 Обновить до pre-release версии  {YELLOW}(нестабильно!){NC}")
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
            _box_row(f"  {DIM}Вставьте JSON и нажмите Enter. Ctrl+C — отмена.{NC}")
            _box_bottom()
            lines = []
            try:
                while True:
                    line = input()
                    if not line.strip():
                        break
                    lines.append(line)
                    # Авто-завершение: если строка начинается с '{' и
                    # заканчивается '}' — это полный JSON в одну строку.
                    joined = "".join(lines).strip()
                    if joined.startswith("{") and joined.endswith("}"):
                        break
            except (KeyboardInterrupt, EOFError):
                print()
                _warn("Отмена.")
                input(f"\n{BOLD}Enter…{NC}")
                continue
            json_str = "\n".join(lines)
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
            # Автообновление b4 (stable release).
            _info("Проверяю обновления...")
            result = auto_update()
            if result.get("updated"):
                _ok(result["message"])
            else:
                _info(result["message"])
            input(f"\n{BOLD}Enter…{NC}")

        elif s["installed"] and ch == "u":
            # Обновление до PRE-RELEASE версии (с предупреждением).
            # auto_update_prerelease(confirm=True) сама показывает warning
            # и спрашивает [y/N]. Если пользователь ответил не "y" — откат.
            result = auto_update_prerelease(confirm=True)
            if result.get("updated"):
                _ok(result["message"])
            else:
                _info(result["message"])
            input(f"\n{BOLD}Enter…{NC}")

        elif s["installed"] and ch == "6":
            _info("Проверяю YouTube (3 запроса, до 30с)...")
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
        do_youtube_b4_menu()
    else:
        import argparse
        p = argparse.ArgumentParser(description="YouTube via b4 (DPI bypass на entry)")
        p.add_argument("cmd", choices=["install", "uninstall", "status", "enable",
                                       "disable", "health", "discovery"])
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
