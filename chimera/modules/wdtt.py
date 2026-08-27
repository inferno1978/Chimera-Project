"""
chimera/modules/wdtt.py
───────────────────────────────────────────────────────────────────────────────
qWDTT — WireGuard over TURN Tunnel.

Назначение:
  Альтернатива vk-turn-proxy для Android-клиентов (qWDTT).
  В отличие от vk-turn-proxy + VLESS, здесь используется WireGuard
  как внутренний протокол с парольной моделью доступа,
  Telegram-ботом для управления и hot reload ключей без перезапуска.

Схема трафика:
  Android (qWDTT APK)
    │  WRAP RTP AEAD/ChaCha20-Poly1305 поверх DTLS 1.2
    ▼
  TURN-серверы ВКонтакте  (трафик = медиа-поток звонка)
    │  UDP → VPS :56000
    ▼
  wdtt-server  (:56000/udp DTLS)
    │  WireGuard ← GETCONF  (:56001/udp внутренний WG)
    ▼
  WireGuard tun: wdtt0  (10.66.66.0/16)
    │
    ▼
  NAT → Интернет

Отличия от vk-turn-proxy (turntunnel.py):
  • Протокол:  WireGuard (не VLESS)
  • Аутентификация: парольная (не UUID)
    - Главный пароль (бессрочный)
    - До 10 временных паролей с TTL и лимитом устройств
  • Ключи WRAP выводятся из пароля через HKDF — не хранятся в APK
  • Telegram-бот для управления паролями прямо из телефона
  • Hot reload: новые/удалённые пароли применяются через SIGHUP без
    перезапуска службы и разрыва соединений
  • Деплой: wdtt-server + systemd + WireGuard NAT

Что модуль делает:
  • Проверяет наличие Go и собирает wdtt-server из исходников
    (либо скачивает prebuilt если доступен в релизах)
  • Настраивает /etc/wdtt/config.json (порты, главный пароль,
    Telegram admin_id + bot_token)
  • Создаёт systemd-сервис wdtt.service с After=network-online.target
  • Настраивает NAT через iptables (MASQUERADE для wdtt0)
  • Открывает UDP-порт 56000 в iptables
  • Генерирует qwdtt:// ссылку и .conf файл для клиента
  • Управление паролями: создание, список, удаление, статус устройств
  • Показывает гайд по использованию qWDTT

Что модуль НЕ трогает:
  • config.json Xray и VLESS-inbound
  • state.json инсталлера
  • iptables-правила других модулей
  • turntunnel.py и его конфиги
  • Любые другие службы

Точка входа из _core.py:
    from chimera.modules.wdtt import do_wdtt_menu
    do_wdtt_menu()

Интеграция в _core.py:
  1. Импорт:
       from chimera.modules.wdtt import do_wdtt_menu
  2. Пункт меню (10):
       _box_row(f"  {CYAN}10{NC}  🔒 {TITLE}qWDTT (WireGuard/TURN){NC}")
       _box_row(f"     {DIM}WireGuard через TURN ВКонтакте — парольная модель, Telegram-бот{NC}")
  3. Обработчик:
       elif choice == "10":
           try:
               do_wdtt_menu()
           except ImportError as _e:
               warn(f"Модуль qWDTT не найден: {_e}")
               time.sleep(2)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from chimera.modules.text_width import wlen as _wlen, plain as _plain

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from chimera.modules.proto_common import (
    ProtoCancelled, proto_load_state, proto_save_state,
    proto_ask, proto_gen_password, proto_ipt_persist, proto_ipt_rule_exists,
)
# _Cancelled aliases ProtoCancelled so existing `except _Cancelled:` and
# `raise _Cancelled` code works unchanged after the local class definition
# was removed in favour of proto_common.ProtoCancelled.
_Cancelled = ProtoCancelled

# ══════════════════════════════════════════════════════════════════════════════
#  ЦВЕТА
# ══════════════════════════════════════════════════════════════════════════════
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BOLD='\033[1m', DIM='\033[2m',
                WHITE='\033[0;30m', NC='\033[0m',
            )
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

# ══════════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════
_BIN_PATH         = Path("/usr/local/bin/wdtt-server")
_CFG_DIR          = Path("/etc/wdtt")
_CFG_FILE         = Path("/etc/wdtt/config.json")
_PASSWORDS_FILE   = Path("/etc/wdtt/passwords.json")
_SERVICE_FILE     = Path("/etc/systemd/system/wdtt.service")
_SERVICE_NAME     = "wdtt"
_MODULE_STATE     = Path("/var/lib/xray-installer/wdtt.json")

# GitHub
_GITHUB_REPO      = "SpaceNeuroX/proxy-turn-vk-android"
# _GITHUB_API — удалён при миграции на download_manager (был dead code,
# ни разу не использовался — модуль всегда собирает из master.tar.gz, а
# не из релизных артефактов).
# _SOURCE_URL — удалён при миграции. Теперь зеркала (прямой GitHub +
# codeload + 3 gh-proxy) собираются в wdtt_mirrors.get_wdtt_source_mirrors()
# и перебираются автоматически через fetch_package(WDTT_SOURCE_SPEC).

# Порты по умолчанию
_DEFAULT_DTLS_PORT = 56000   # входящий от TURN-сервера
_DEFAULT_WG_PORT   = 56001   # внутренний WireGuard
_DEFAULT_TUN_PORT  = 9000    # локальный порт на Android

# WireGuard сеть
_WG_SUBNET        = "10.66.66.0/16"
_WG_SERVER_IP     = "10.66.66.1"

_BOX_W = 66

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ
# ══════════════════════════════════════════════════════════════════════════════


def _box_top(title: str = "") -> None:
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    if title:
        pad  = _BOX_W - _wlen(title)
        lpad = pad // 2
        rpad = pad - lpad
        print(f"{CYAN}║{NC}{' ' * lpad}{BOLD}{WHITE}{title}{NC}{' ' * rpad}{CYAN}║{NC}")
        print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")

def _box_sep() -> None:
    print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")

def _box_bot() -> None:
    print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")

_ANSI_RE = re.compile(r'\033\[[0-9;]*m')

def _box_row(text: str = "") -> None:
    w = _wlen(text)
    if w > _BOX_W:
        # cut считался по plain-строке (без ANSI), а срез text[:cut]
        # применялся к оригинальной строке с ANSI-кодами — при наличии
        # цвета это рвало escape-последовательность посередине и портило
        # вывод (сдвигало правую границу ║). Обрезаем посимвольно, пропуская
        # ANSI-коды целиком и считая ширину только по видимым символам.
        import unicodedata as _ud
        acc = 0
        out = []
        i = 0
        n = len(text)
        while i < n:
            m = _ANSI_RE.match(text, i)
            if m:
                out.append(m.group(0))
                i = m.end()
                continue
            ch = text[i]
            cw = 2 if _ud.east_asian_width(ch) in ('W', 'F') else 1
            if acc + cw > _BOX_W - 1:
                break
            out.append(ch)
            acc += cw
            i += 1
        text = ''.join(out) + "…"
        w = _wlen(text)
    pad = max(0, _BOX_W - w)
    print(f"{CYAN}║{NC}{text}{' ' * pad}{CYAN}║{NC}")

def _box_item(key: str, label: str) -> None:
    col = RED + BOLD if key.strip().upper() in ("Q", "0") else WHITE + BOLD
    _box_row(f"  {DIM}[{NC}{col}{key}{NC}{DIM}]{NC}  {label}")

def _box_ok(msg: str)   -> None: _box_row(f"  {GREEN}✓{NC}  {msg}")
def _box_warn(msg: str) -> None: _box_row(f"  {YELLOW}⚠{NC}  {msg}")
def _box_info(msg: str) -> None: _box_row(f"  {CYAN}→{NC}  {msg}")
def _box_err(msg: str)  -> None: _box_row(f"  {RED}✗{NC}  {msg}")

def _box_kv(key: str, val: str, kw: int = 22) -> None:
    key_colored = f"{CYAN}{key}{NC}"
    key_pad = kw - _wlen(key_colored)
    _box_row(f"  {key_colored}{' ' * max(0, key_pad)}  {val}")

def _box_link(link: str, color: str = "") -> None:
    """Выводит длинную ссылку БЕЗ боковых границ ║ рамки — печатается
    обычным print() ниже/внутри блока, но не как строка рамки. Так длинный
    URL никогда не сдвигает и не ломает правую границу ║ (см. аналогичный
    _box_link в box_renderer.py). Разбивает по '&' (безопасные точки
    разрыва), без сокращения/обрезания текста — вся ссылка видна полностью,
    просто на нескольких строках."""
    if not color:
        color = YELLOW
    max_w = _BOX_W - 2  # 1 пробел слева, без правой границы

    tokens, buf = [], ""
    for ch in link:
        buf += ch
        if ch == "&":
            tokens.append(buf)
            buf = ""
    if buf:
        tokens.append(buf)

    lines, cur = [], ""
    for tok in tokens:
        if cur and _wlen(cur) + _wlen(tok) > max_w:
            lines.append(cur)
            cur = tok
        else:
            cur += tok
        while _wlen(cur) > max_w:
            acc, cut = 0, 0
            for ch in cur:
                import unicodedata as _ud
                acc += 2 if _ud.east_asian_width(ch) in ('W', 'F') else 1
                if acc > max_w:
                    break
                cut += 1
            lines.append(cur[:cut])
            cur = cur[cut:]
    if cur:
        lines.append(cur)

    for line in lines:
        print(f" {color}{line}{NC}")

def _save_link_file(link: str, filename: str) -> Path:
    """Сохраняет полную ссылку в файл в _CFG_DIR, чтобы её можно было
    открыть и скопировать целиком, даже если терминал её обрезает."""
    try:
        _CFG_DIR.mkdir(parents=True, exist_ok=True)
        path = _CFG_DIR / filename
        path.write_text(link + "\n", encoding="utf-8")
        try:
            path.chmod(0o600)
        except Exception:
            pass
        return path
    except Exception:
        return _CFG_DIR / filename

def _print_link_file_path(path: Path) -> None:
    print(f"  {DIM}📄 Полная ссылка сохранена в файл: {NC}{CYAN}{path}{NC}")
    print(f"  {DIM}   (cat {path}  — чтобы скопировать целиком){NC}")

# ══════════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ
# ══════════════════════════════════════════════════════════════════════════════
def _pause() -> None:
    try:
        print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True)
        input()
    except (KeyboardInterrupt, EOFError, UnicodeDecodeError):
        print()

def _run(cmd: list, capture: bool = False, check: bool = False,
         env: Optional[dict] = None, cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if env:
        kw["env"] = env
    if cwd:
        kw["cwd"] = cwd
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def _run_interactive(cmd: list, cwd: Optional[str] = None) -> int:
    kw: dict = {}
    if cwd:
        kw["cwd"] = cwd
    return subprocess.call(cmd, **kw)

def _get_server_ip() -> str:
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        pass
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            return r.read().decode().strip()
    except Exception:
        pass
    return "ВАШ_IP"

# ══════════════════════════════════════════════════════════════════════════════
#  СОСТОЯНИЕ МОДУЛЯ
# ══════════════════════════════════════════════════════════════════════════════
# State load/save, prompt, password-gen and iptables-persist helpers are
# imported from chimera.modules.proto_common (see top of file).
# Call sites use proto_load_state / proto_save_state / proto_ask /
# proto_gen_password / proto_ipt_persist directly.

def _is_installed() -> bool:
    return _BIN_PATH.exists() and _SERVICE_FILE.exists()

# ══════════════════════════════════════════════════════════════════════════════
#  КОНФИГ СЕРВЕРА
# ══════════════════════════════════════════════════════════════════════════════
def _load_cfg() -> dict:
    if not _CFG_FILE.exists():
        return {}
    try:
        return json.loads(_CFG_FILE.read_text())
    except Exception:
        return {}

def _save_cfg(cfg: dict) -> None:
    _CFG_DIR.mkdir(parents=True, exist_ok=True)
    _CFG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    _CFG_FILE.chmod(0o600)

def _load_passwords() -> dict:
    """Загружает passwords.json — база паролей wdtt-server."""
    if not _PASSWORDS_FILE.exists():
        return {"main_password": "", "admin_id": "", "bot_token": "",
                "passwords": {}, "devices": {}}
    try:
        return json.loads(_PASSWORDS_FILE.read_text())
    except Exception:
        return {}

def _save_passwords(data: dict) -> None:
    _CFG_DIR.mkdir(parents=True, exist_ok=True)
    _PASSWORDS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    _PASSWORDS_FILE.chmod(0o600)

def _hot_reload() -> bool:
    """Отправляет SIGHUP серверу — hot reload паролей без перезапуска."""
    r = _run(["pidof", "wdtt-server"], capture=True)
    pid = (r.stdout or "").strip()
    if not pid:
        return False
    _run(["kill", "-HUP", pid])
    return True


# ══════════════════════════════════════════════════════════════════════════════
#  SYNC CONTRACT (v4.25) — для реестра _SYNCABLE_PROTOCOLS в rest_api.py
#
#  WDTT — парольная модель доступа (НЕ per-user UUID как sing-box):
#    • Главный пароль (бессрочный) — для админа
#    • До 10 временных паролей с TTL и лимитом устройств — для юзеров
#
#  Bridge к VLESS users.json:
#    • Каждый VLESS-юзер получает ОДИН временный пароль WDTT.
#    • Связь через поле `owner_email` в password entry (аналогично AWG peers).
#    • При добавлении VLESS-юзера → создаётся WDTT-пароль (TTL=365д, 1 устройство).
#    • При удалении VLESS-юзера → WDTT-пароль удаляется.
#    • При rename → старый пароль удаляется, новый создаётся (пароль меняется).
#
#  Лимит 10 паролей — если у тебя >10 VLESS-юзеров, WDTT не для всех.
#  ensure_user_full вернёт False для 11-го юзера (с предупреждением в лог).
# ══════════════════════════════════════════════════════════════════════════════
def is_active() -> bool:
    """True если WDTT установлен И сервис запущен."""
    try:
        if not _is_installed():
            return False
        r = _run(["systemctl", "is-active", _SERVICE_NAME],
                 capture=True, check=False)
        return r.returncode == 0 and r.stdout.strip() == "active"
    except Exception:
        return False


def _find_password_by_owner(email: str) -> Optional[str]:
    """Находит WDTT-пароль по owner_email. Возвращает сам пароль или None."""
    if not email:
        return None
    data = _load_passwords()
    for pwd, info in data.get("passwords", {}).items():
        if info.get("owner_email") == email:
            return pwd
    return None


def ensure_user_full(user: dict) -> bool:
    """Создаёт WDTT-пароль для VLESS-юзера.

    Если пароль с этим owner_email уже есть — no-op (возвращает True).
    TTL=365 дней, max_devices=1. Пароль = случайная строка (proto_gen_password).

    Возвращает True если создан или уже существует. False — лимит 10 превышён
    или ошибка.
    """
    try:
        if not _is_installed():
            return True  # WDTT не установлен — пропускаем
        email = user.get("email", "") or ""
        if not email:
            return False
        # Если уже есть пароль для этого email — no-op.
        existing = _find_password_by_owner(email)
        if existing:
            return True
        data = _load_passwords()
        passwords = data.get("passwords", {})
        if len(passwords) >= 10:
            print(f"  {YELLOW}⚠{NC}  WDTT: лимит 10 паролей превышён — пропускаю {email}")
            return False
        # Генерируем новый пароль (TTL=365д, 1 устройство).
        new_pass = proto_gen_password()
        expires_at = int((datetime.now() + timedelta(days=365)).timestamp())
        passwords[new_pass] = {
            "device_ids":    [],
            "max_devices":   1,
            "expires_at":    expires_at,
            "down_bytes":    0,
            "up_bytes":      0,
            "vk_hash":       "",
            "ports":         "",
            "is_deactivated": False,
            "owner_email":   email,  # ← bridge к VLESS users.json
        }
        data["passwords"] = passwords
        _save_passwords(data)
        _hot_reload()
        return True
    except Exception as e:
        try:
            print(f"  {RED}✗{NC}  wdtt.ensure_user_full: {e}")
        except Exception:
            pass
        return False


def ensure_user(name: str) -> bool:
    """Legacy contract — name трактуется как email."""
    return ensure_user_full({"email": name, "name": name})


def remove_user_full(user: dict) -> bool:
    """Удаляет WDTT-пароль по owner_email (email юзера)."""
    try:
        if not _is_installed():
            return True
        email = user.get("email", "") or ""
        if not email:
            return False
        pwd = _find_password_by_owner(email)
        if not pwd:
            return True  # не было — идемпотентность
        data = _load_passwords()
        passwords = data.get("passwords", {})
        if pwd in passwords:
            del passwords[pwd]
            data["passwords"] = passwords
            _save_passwords(data)
            _hot_reload()
        return True
    except Exception as e:
        try:
            print(f"  {RED}✗{NC}  wdtt.remove_user_full: {e}")
        except Exception:
            pass
        return False


def remove_user(name: str) -> bool:
    """Legacy contract — name трактуется как email."""
    return remove_user_full({"email": name, "name": name})


def rename_user_full(old_user: dict, new_user: dict) -> bool:
    """Rename = remove + add (пароль меняется, TTL сбрасывается)."""
    try:
        ok1 = remove_user_full(old_user)
        ok2 = ensure_user_full(new_user)
        return ok1 and ok2
    except Exception:
        return False


def rename_user(old_name: str, new_name: str) -> bool:
    """Legacy contract — имена тракуются как emails."""
    return rename_user_full(
        {"email": old_name, "name": old_name},
        {"email": new_name, "name": new_name},
    )


# ══════════════════════════════════════════════════════════════════════════════
#  SUBSCRIPTION CONTRACT (v4.25) — для реестра _SUBSCRIBABLE_PROTOCOLS
#
#  Возвращает qwdtt:// ссылку для VLESS-юзера (по owner_email).
#  Используется subscription.py для включения qWDTT в единую подписку.
# ══════════════════════════════════════════════════════════════════════════════
def get_subscription_uris(user: dict) -> list:
    """Возвращает qwdtt:// ссылку для юзера (по owner_email).

    Формат ссылки:
      qwdtt://config?name=qWDTT-<ip>&peer=<ip>:<dtls_port>&hashes=<vk_hash>
        &workers=16&port=<tun_port>&pass=<password>

    Если у юзера нет пароля (не синхронизирован) — пустой список.
    VK-хеш берётся из password entry (если задан) или placeholder ВК_ХЕШ.
    """
    try:
        if not _is_installed():
            return []
        email = user.get("email", "") or ""
        if not email:
            return []
        pwd = _find_password_by_owner(email)
        if not pwd:
            return []
        # Проверяем что пароль не истёк и не деактивирован.
        data = _load_passwords()
        entry = data.get("passwords", {}).get(pwd, {})
        if not entry:
            return []
        if entry.get("is_deactivated", False):
            return []
        expires = entry.get("expires_at", 0)
        if expires > 0 and time.time() > expires:
            return []  # истёк
        # Собираем ссылку.
        state = proto_load_state(_MODULE_STATE)
        server_ip = _get_server_ip()
        dtls_port = state.get("dtls_port", _DEFAULT_DTLS_PORT)
        vk_hash = entry.get("vk_hash", "") or "ВК_ХЕШ"
        link = (
            f"qwdtt://config?name=qWDTT-{server_ip}"
            f"&peer={server_ip}:{dtls_port}"
            f"&hashes={vk_hash}"
            f"&workers=16&port={_DEFAULT_TUN_PORT}"
            f"&pass={pwd}"
        )
        return [link]
    except Exception:
        return []

# ══════════════════════════════════════════════════════════════════════════════
#  СБОРКА / УСТАНОВКА БИНАРНИКА
# ══════════════════════════════════════════════════════════════════════════════
def _check_go() -> Optional[str]:
    """Возвращает путь к go (предпочитая /usr/local/bin/go) или None."""
    go = "/usr/local/bin/go" if Path("/usr/local/bin/go").exists() else shutil.which("go")
    if go:
        r = _run([go, "version"], capture=True)
        if r.returncode == 0:
            return go
    return None

def _go_arch() -> str:
    r = _run(["uname", "-m"], capture=True)
    m = (r.stdout or "").strip() if r.returncode == 0 else ""
    return {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(m, "amd64")

def _ver_tuple(s: str) -> tuple:
    parts = re.findall(r"\d+", s)[:3]
    parts += ["0"] * (3 - len(parts))
    return tuple(int(p) for p in parts)

def _go_installed_version(go: str) -> Optional[tuple]:
    r = _run([go, "version"], capture=True)
    if r.returncode != 0:
        return None
    m = re.search(r"go(\d+\.\d+(?:\.\d+)?)", r.stdout or "")
    return _ver_tuple(m.group(1)) if m else None

def _go_required_version(gomod: Path) -> str:
    """Версия Go, требуемая go.mod исходников qWDTT (директива 'go X.Y.Z')."""
    if gomod.exists():
        try:
            m = re.search(r"^go\s+(\d+\.\d+(?:\.\d+)?)", gomod.read_text(), re.M)
            if m:
                return m.group(1)
        except Exception:
            pass
    return "1.21.0"

def _install_go_toolchain(required: str) -> Optional[str]:
    """
    Скачивает официальный архив Go через download_manager.fetch_package().

    МИГРАЦИЯ: раньше использовался _http_download() с ОДНИМ прямым URL
    (https://go.dev/dl/{version}.linux-{arch}.tar.gz) БЕЗ зеркал, БЕЗ
    fallback, БЕЗ проверки ручного размещения.

    Теперь используется fetch_package(GO_TOOLCHAIN_SPEC, version=..., arch=...)
    из download_manager.py. fetch_package сам:
      1. Проверяет /root/{version}.linux-{arch}.tar.gz (manual_incoming_dir
         из spec) — если найден, использует без сети (WinSCP-friendly).
      2. Иначе — перебирает 4 зеркала (go.dev + golang.google.cn +
         mirrors.aliyun.com + mirrors.tencent.com) по очереди через urllib.
      3. При успехе — post_install распаковывает в /usr/local/go и создаёт
         симлинки в /usr/local/bin/.
      4. При провале — print_manual_hint() с инструкцией.

    Версия Go разрешается динамически через go.dev/VERSION?m=text (API
    metadata — non-migration, остаётся здесь). Если запрос падает — fallback
    на go{required}.
    """
    from chimera.modules.download_manager import fetch_package
    from chimera.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC

    arch = _go_arch()
    try:
        with urllib.request.urlopen("https://go.dev/VERSION?m=text", timeout=15) as resp:
            version = resp.read().decode("utf-8", errors="replace").splitlines()[0].strip()
        if not version.startswith("go"):
            version = f"go{required}"
    except Exception:
        version = f"go{required}"

    print(f"  {CYAN}→{NC}  Скачиваю {version} ({arch}, через download_manager)...")
    ok = fetch_package(GO_TOOLCHAIN_SPEC, version=version, arch=arch)
    if not ok:
        print(f"  {RED}✗{NC}  Не удалось скачать Go {version} ({arch}).")
        return None

    go = _check_go()
    if not go:
        print(f"  {RED}✗{NC}  Go скачан и распакован, но /usr/local/bin/go не работает.")
        return None
    return go

def _ensure_go(required: str) -> Optional[str]:
    """Возвращает путь к go, удовлетворяющему required, ставя свежий Go при необходимости."""
    go = _check_go()
    if go and _go_installed_version(go) and _go_installed_version(go) >= _ver_tuple(required):
        return go
    print(f"  {CYAN}→{NC}  Нужен Go {required}+"
          f"{' (текущий старее)' if go else ' (не найден)'}, устанавливаю...")
    return _install_go_toolchain(required)

def _build_wdtt_server() -> bool:
    """
    Скачивает исходники qWDTT и собирает wdtt-server через
    download_manager.fetch_package().

    МИГРАЦИЯ: раньше использовался urllib.request.urlretrieve() с ОДНИМ
    прямым URL (https://github.com/SpaceNeuroX/proxy-turn-vk-android/
    archive/refs/heads/master.tar.gz) БЕЗ зеркал, БЕЗ fallback, БЕЗ
    проверки ручного размещения.

    Теперь используется fetch_package(WDTT_SOURCE_SPEC) из download_manager.py.
    fetch_package сам:
      1. Проверяет /root/proxy-turn-vk-android-master.tar.gz
         (manual_incoming_dir из spec) — если найден, использует без сети.
      2. Иначе — перебирает 9 зеркал (прямой GitHub + codeload + 7
         gh-proxy) по очереди через urllib.
      3. При успехе — post_install распаковывает, собирает через go build,
         atomic-replaces /usr/local/bin/wdtt-server.
      4. При провале — print_manual_hint() с инструкцией.

    Go toolchain устанавливается ОТДЕЛЬНО через _ensure_go() — это
    ответственность вызывающего кода, не WDTT_SOURCE_SPEC.post_install.

    Бинарник помещается в /usr/local/bin/wdtt-server.
    """
    from chimera.modules.download_manager import fetch_package
    from chimera.modules.wdtt_packages import WDTT_SOURCE_SPEC

    # Сначала убеждаемся что Go toolchain доступен — post_install WDTT_SOURCE_SPEC
    # будет звать go build и упадёт без Go.
    # _ensure_go() сам вызывает _install_go_toolchain → fetch_package(GO_TOOLCHAIN_SPEC)
    # если текущий Go старее требуемого или отсутствует.
    # Используем _go_required_version с пустым go.mod Path — вернёт дефолт "1.21.0".
    required = _go_required_version(Path("/nonexistent/go.mod"))
    go = _ensure_go(required)
    if not go:
        print(f"  {RED}✗{NC}  Не удалось установить подходящий Go ({required}+).")
        return False

    print(f"  {CYAN}→{NC}  Скачиваю исходники qWDTT (через download_manager)...")
    ok = fetch_package(WDTT_SOURCE_SPEC)
    if ok:
        print(f"  {GREEN}✓{NC}  wdtt-server установлен: {_BIN_PATH}")
    return ok

# ══════════════════════════════════════════════════════════════════════════════
#  IPTABLES
# ══════════════════════════════════════════════════════════════════════════════
# _ipt_rule_exists — вынесен в proto_common (proto_ipt_rule_exists).
def _ipt_rule_exists(table: str, chain: str, args: list) -> bool:
    return proto_ipt_rule_exists(table, chain, args)

def _fw_tool() -> str:
    """ufw, если он есть и активен — иначе raw iptables (fallback)."""
    if shutil.which("ufw"):
        r = _run(["ufw", "status"], capture=True, check=False)
        if "Status: active" in (r.stdout or ""):
            return "ufw"
    return "iptables"

def _ipt_open_udp(port: int) -> None:
    #  миграция на port_registry.
    try:
        from chimera.modules.port_registry import (
            ufw_open_port, port_register, SERVICE_WDTT,
        )
        port_register(SERVICE_WDTT, port, "udp",
                      comment="qWDTT DTLS", force=True)
        ufw_open_port(port, "udp", SERVICE_WDTT, comment="qWDTT DTLS")
        return
    except Exception:
        pass
    if _fw_tool() == "ufw":
        r = _run(["ufw", "status"], capture=True, check=False)
        if not re.search(rf'^{port}/udp\b.*ALLOW', r.stdout or "", re.MULTILINE):
            _run(["ufw", "allow", f"{port}/udp", "comment", "qWDTT DTLS"],
                 check=False)
        return
    args = ["-p", "udp", "--dport", str(port), "-j", "ACCEPT"]
    if not _ipt_rule_exists("filter", "INPUT", args):
        _run(["iptables", "-t", "filter", "-I", "INPUT", "1"] + args)

def _ipt_close_udp(port: int) -> None:
    #  миграция на port_registry (с legacy comment).
    try:
        from chimera.modules.port_registry import (
            ufw_close_port, port_unregister, SERVICE_WDTT,
        )
        ufw_close_port(port, "udp", SERVICE_WDTT, legacy_comments=["qWDTT DTLS"])
        port_unregister(SERVICE_WDTT, port, "udp")
    except Exception:
        pass
    if shutil.which("ufw"):
        _run(["ufw", "delete", "allow", f"{port}/udp"], check=False)
    args = ["-p", "udp", "--dport", str(port), "-j", "ACCEPT"]
    for _ in range(5):
        if not _ipt_rule_exists("filter", "INPUT", args):
            break
        _run(["iptables", "-t", "filter", "-D", "INPUT"] + args)

def _ipt_masquerade_exists() -> bool:
    r = _run(
        ["iptables", "-t", "nat", "-C", "POSTROUTING",
         "-s", _WG_SUBNET, "!", "-d", _WG_SUBNET, "-j", "MASQUERADE"],
        capture=True,
    )
    return r.returncode == 0

def _ipt_add_masquerade() -> None:
    if not _ipt_masquerade_exists():
        _run(["iptables", "-t", "nat", "-A", "POSTROUTING",
              "-s", _WG_SUBNET, "!", "-d", _WG_SUBNET, "-j", "MASQUERADE"])

def _ipt_remove_masquerade() -> None:
    for _ in range(3):
        if not _ipt_masquerade_exists():
            break
        _run(["iptables", "-t", "nat", "-D", "POSTROUTING",
              "-s", _WG_SUBNET, "!", "-d", _WG_SUBNET, "-j", "MASQUERADE"])

def _enable_ip_forward() -> None:
    """Включает IP forwarding — нужен для WireGuard NAT."""
    _run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    sysctl = Path("/etc/sysctl.d/99-wdtt.conf")
    sysctl.write_text("net.ipv4.ip_forward = 1\n")

# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEMD СЕРВИС
# ══════════════════════════════════════════════════════════════════════════════
def _install_service(dtls_port: int, wg_port: int, main_pass: str,
                     admin_id: str, bot_token: str) -> None:
    _SERVICE_FILE.write_text(
        "[Unit]\n"
        "Description=qWDTT — WireGuard over VK TURN\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={_BIN_PATH} "
        f"-config-dir {_CFG_DIR} "
        f"-password {main_pass} "
        f"-listen 0.0.0.0:{dtls_port} "
        f"-wg-port {wg_port} "
        + (f"-admin {admin_id} " if admin_id else "")
        + (f"-bot-token {bot_token} " if bot_token else "")
        + "\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "NoNewPrivileges=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", _SERVICE_NAME])

# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА
# ══════════════════════════════════════════════════════════════════════════════
def _run_install() -> None:
    try:
        _run_install_inner()
    except _Cancelled:
        print(f"\n  {YELLOW}Установка прервана.{NC}\n")
        _pause()

def _run_install_inner() -> None:
    os.system("clear")
    _box_top("🔒  УСТАНОВКА  •  qWDTT")
    _box_row()

    if _is_installed():
        _box_warn("qWDTT уже установлен.")
        _box_row()
        _box_item("1", "Переустановить (сохранить пароли и конфиг)")
        _box_item("2", f"Переустановить полностью  {YELLOW}(новый главный пароль){NC}")
        _box_item("Q", "← Отмена")
        _box_bot(); print()
        try:
            ch = proto_ask(f"{CYAN}Выбор [1/2/Q]: {NC}", c=True).strip().lower()
        except _Cancelled:
            return
        if ch == "q" or not ch:
            return
        if ch == "2":
            _full_uninstall(silent=True)

    # ── Конфигурация ──────────────────────────────────────────────────────────
    state = proto_load_state(_MODULE_STATE)
    old_pass  = state.get("main_password", "")
    old_dtls  = state.get("dtls_port", _DEFAULT_DTLS_PORT)
    old_wg    = state.get("wg_port",   _DEFAULT_WG_PORT)
    old_admin = state.get("admin_id",  "")
    old_bot   = state.get("bot_token", "")

    os.system("clear")
    _box_top("🔒  НАСТРОЙКА  •  qWDTT")
    _box_row()
    _box_info("Главный пароль — бессрочный доступ (для себя).")
    _box_info("Оставьте пустым — пароль сгенерируется автоматически.")
    _box_row()
    _box_info("Telegram-бот опционален — для управления временными паролями.")
    _box_info("Если не нужен — оставьте поля пустыми.")
    _box_row()
    _box_bot(); print()

    try:
        raw = proto_ask(
            f"  {CYAN}Главный пароль [{old_pass or 'авто'}]: {NC}",
            default=old_pass, c=True,
        )
        main_pass = raw if raw else (proto_gen_password() if not old_pass else old_pass)

        raw = proto_ask(
            f"  {CYAN}UDP порт DTLS [{old_dtls}]: {NC}",
            default=str(old_dtls), c=True,
        )
        dtls_port = int(raw) if raw.isdigit() else old_dtls

        raw = proto_ask(
            f"  {CYAN}UDP порт WireGuard [{old_wg}]: {NC}",
            default=str(old_wg), c=True,
        )
        wg_port = int(raw) if raw.isdigit() else old_wg

        admin_id = proto_ask(
            f"  {CYAN}Telegram Admin ID [{old_admin or 'пропустить'}]: {NC}",
            default=old_admin, c=True,
        )
        bot_token = ""
        if admin_id:
            bot_token = proto_ask(
                f"  {CYAN}Telegram Bot Token [{old_bot or 'пропустить'}]: {NC}",
                default=old_bot, c=True,
            )
    except _Cancelled:
        raise

    if not (1024 <= dtls_port <= 65535) or not (1024 <= wg_port <= 65535):
        print(f"  {RED}✗{NC}  Порты должны быть в диапазоне 1024–65535."); _pause(); return
    if dtls_port == wg_port:
        print(f"  {RED}✗{NC}  Порты DTLS и WireGuard не должны совпадать."); _pause(); return

    # ── Установка ─────────────────────────────────────────────────────────────
    os.system("clear")
    _box_top("🔒  УСТАНОВКА  •  qWDTT")
    _box_row()

    # 1. Бинарник
    _box_info("Сборка wdtt-server из исходников...")
    _box_bot(); print()

    if not _build_wdtt_server():
        print()
        _box_top("🔒  УСТАНОВКА  •  qWDTT")
        _box_err("Не удалось собрать wdtt-server.")
        _box_err("Убедитесь что доступен Go и интернет.")
        _box_bot(); _pause(); return

    print()
    # 2. Конфиг директория
    _CFG_DIR.mkdir(parents=True, exist_ok=True)

    # Инициализируем passwords.json если его нет
    if not _PASSWORDS_FILE.exists():
        _save_passwords({
            "main_password": main_pass,
            "admin_id": admin_id,
            "bot_token": bot_token,
            "passwords": {},
            "devices": {},
        })
    else:
        # Обновляем только служебные поля, пароли пользователей не трогаем
        data = _load_passwords()
        data["main_password"] = main_pass
        data["admin_id"] = admin_id
        data["bot_token"] = bot_token
        _save_passwords(data)

    print(f"  {GREEN}✓{NC}  Конфиг создан: {_CFG_DIR}")

    # 3. IP forwarding
    _enable_ip_forward()
    print(f"  {GREEN}✓{NC}  IP forwarding включён.")

    # 4. Firewall + NAT
    fw_tool = _fw_tool()
    _ipt_open_udp(dtls_port)
    _ipt_add_masquerade()
    proto_ipt_persist()
    print(f"  {GREEN}✓{NC}  {fw_tool}: UDP {dtls_port} открыт, NAT настроен.")

    # 5. Systemd
    _install_service(dtls_port, wg_port, main_pass, admin_id, bot_token)
    print(f"  {GREEN}✓{NC}  Systemd-сервис создан.")

    # 6. Запуск
    _run(["systemctl", "start", _SERVICE_NAME])
    time.sleep(2)
    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    if r.stdout.strip() == "active":
        print(f"  {GREEN}✓{NC}  wdtt-server запущен.")
    else:
        print(f"  {YELLOW}⚠{NC}  Сервис не запустился — проверьте логи (пункт 5).")

    # 7. Сохраняем состояние
    proto_save_state(_MODULE_STATE, {
        "installed":     True,
        "main_password": main_pass,
        "dtls_port":     dtls_port,
        "wg_port":       wg_port,
        "admin_id":      admin_id,
        "bot_token":     bot_token,
    })

    # v4.25: bulk-provisioning всех существующих VLESS-пользователей в WDTT.
    # Каждый VLESS-юзер получает временный пароль (TTL=365д, 1 устройство).
    # Лимит 10 паролей — если юзеров больше, лишние пропускаются с warning.
    try:
        from chimera.modules.rest_api import _sync_all_from_vless
        from chimera.modules.users_manager import _unified_load_users
        _vless_users = _unified_load_users()
        if _vless_users:
            print(f"  {CYAN}→{NC}  Синхронизирую {len(_vless_users)} VLESS-юзеров в qWDTT...")
            _stats = _sync_all_from_vless(_vless_users)
            _wdtt_stats = _stats.get("wdtt", {})
            if _wdtt_stats.get("created", 0) > 0:
                print(f"  {GREEN}✓{NC}  Добавлено паролей qWDTT: {_wdtt_stats['created']}")
    except Exception as _e:
        print(f"  {YELLOW}⚠{NC}  Sync VLESS-юзеров не удался: {_e}")

    # ── Итог ──────────────────────────────────────────────────────────────────
    server_ip = _get_server_ip()
    print()
    _box_top("✅  УСТАНОВКА ЗАВЕРШЕНА  •  qWDTT")
    _box_row()
    _box_ok("wdtt-server установлен и запущен.")
    _box_row()
    _box_kv("DTLS порт:",      f"{YELLOW}{dtls_port}/udp{NC}")
    _box_kv("WG порт:",        f"{DIM}{wg_port}/udp (внутренний){NC}")
    _box_kv("Главный пароль:", f"{YELLOW}{main_pass}{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Быстрая ссылка для qWDTT:{NC}")
    _box_row()
    qwdtt_link = (
        f"qwdtt://config?name=qWDTT-{server_ip}"
        f"&peer={server_ip}:{dtls_port}"
        f"&hashes=ВК_ХЕШ_ЗВОНКА"
        f"&workers=16&port={_DEFAULT_TUN_PORT}"
        f"&pass={main_pass}"
    )
    _box_link(qwdtt_link)
    _box_row()
    _box_warn("Замените ВК_ХЕШ_ЗВОНКА на хеш из ссылки vk.com/call/join/ХЕШ")
    _box_row()
    _box_sep()
    if admin_id and bot_token:
        _box_ok("Telegram-бот настроен. Команды: /new, /list")
    else:
        _box_info("Telegram-бот не настроен (можно добавить позже).")
    _box_bot()
    link_path = _save_link_file(qwdtt_link, "qwdtt_link.txt")
    _print_link_file_path(link_path)
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  УПРАВЛЕНИЕ ПАРОЛЯМИ
# ══════════════════════════════════════════════════════════════════════════════
def _passwords_menu() -> None:
    """Управление временными паролями без Telegram."""
    while True:
        os.system("clear")
        data = _load_passwords()
        passwords = data.get("passwords", {})
        state = proto_load_state(_MODULE_STATE)
        server_ip = _get_server_ip()
        dtls_port = state.get("dtls_port", _DEFAULT_DTLS_PORT)

        _box_top("🔑  УПРАВЛЕНИЕ ПАРОЛЯМИ  •  qWDTT")
        _box_row()
        _box_kv("Главный пароль:", f"{YELLOW}{data.get('main_password', '—')}{NC}")
        _box_kv("Временных паролей:",
                f"{YELLOW}{len(passwords)}{NC} / 10")
        _box_row(); _box_sep()

        active_list = []
        for pw, entry in passwords.items():
            if not entry:
                continue
            expires = entry.get("expires_at", 0)
            expired = expires > 0 and time.time() > expires
            active_list.append((pw, entry, expired))

        if active_list:
            _box_row(f"  {BOLD}{CYAN}{'Пароль':<18}{'Истекает':<14}{'Уст.':<6}{'Статус'}{NC}")
            _box_sep()
            for pw, entry, expired in active_list:
                exp = entry.get("expires_at", 0)
                if exp == 0:
                    exp_str = "бессрочный"
                else:
                    dt = datetime.fromtimestamp(exp)
                    exp_str = dt.strftime("%d.%m.%Y")
                devs = len(entry.get("device_ids", []) or
                           ([entry["device_id"]] if entry.get("device_id") else []))
                max_d = entry.get("max_devices", 1) or 1
                deact = entry.get("is_deactivated", False)
                if deact:
                    status = f"{RED}отключён{NC}"
                elif expired:
                    status = f"{YELLOW}истёк{NC}"
                else:
                    status = f"{GREEN}активен{NC}"
                pw_short = pw[:16]
                _box_row(
                    f"  {CYAN}{pw_short:<18}{NC}"
                    f"{DIM}{exp_str:<14}{NC}"
                    f"{devs}/{max_d:<4}  "
                    f"{status}"
                )
        else:
            _box_warn("Временных паролей нет.")

        _box_row(); _box_sep()
        _box_item("1", "➕  Создать временный пароль")
        _box_item("2", "🔗  Показать ссылку для пароля")
        _box_item("3", f"{RED}🗑️   Удалить пароль{NC}")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()

        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            try:
                _create_password()
            except _Cancelled:
                pass
        elif ch == "2":
            try:
                _show_password_link(passwords, server_ip, dtls_port)
            except _Cancelled:
                pass
        elif ch == "3":
            try:
                _delete_password(passwords)
            except _Cancelled:
                pass
        elif ch in ("q", ""):
            break

def _create_password() -> None:
    os.system("clear")
    _box_top("➕  СОЗДАТЬ ПАРОЛЬ  •  qWDTT")
    _box_row()
    _box_info("Временный пароль для передачи пользователю.")
    _box_row()
    _box_bot(); print()

    try:
        raw_days = proto_ask(
            f"  {CYAN}Дней действия (1-365, Enter=30): {NC}",
            default="30", c=True,
        )
        days = int(raw_days) if raw_days.isdigit() else 30
        days = max(1, min(365, days))

        raw_devs = proto_ask(
            f"  {CYAN}Макс. устройств (Enter=1): {NC}",
            default="1", c=True,
        )
        max_devs = int(raw_devs) if raw_devs.isdigit() else 1
        max_devs = max(1, min(10, max_devs))

        vk_hash = proto_ask(
            f"  {CYAN}VK хеш звонка (Enter=пропустить): {NC}",
            default="", c=True,
        ).strip()

    except _Cancelled:
        raise

    data = _load_passwords()
    passwords = data.get("passwords", {})
    if len(passwords) >= 10:
        print(f"  {RED}✗{NC}  Лимит: максимум 10 паролей."); _pause(); return

    new_pass = proto_gen_password()
    expires_at = int((datetime.now() + timedelta(days=days)).timestamp())

    passwords[new_pass] = {
        "device_ids":    [],
        "max_devices":   max_devs,
        "expires_at":    expires_at,
        "down_bytes":    0,
        "up_bytes":      0,
        "vk_hash":       vk_hash,
        "ports":         "",
        "is_deactivated": False,
    }
    data["passwords"] = passwords
    _save_passwords(data)

    # Hot reload
    _hot_reload()

    state = proto_load_state(_MODULE_STATE)
    server_ip = _get_server_ip()
    dtls_port = state.get("dtls_port", _DEFAULT_DTLS_PORT)

    print()
    _box_top("✅  ПАРОЛЬ СОЗДАН")
    _box_row()
    _box_kv("Пароль:",   f"{YELLOW}{new_pass}{NC}")
    _box_kv("Действует:", f"{days} дн. до {datetime.fromtimestamp(expires_at).strftime('%d.%m.%Y')}")
    _box_kv("Устройств:", str(max_devs))
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Ссылка qwdtt:// для клиента:{NC}")
    if not vk_hash:
        _box_warn("Замените ВК_ХЕШ на хеш из ссылки vk.com/call/join/ХЕШ")
    _box_bot()
    vk_part = vk_hash if vk_hash else "ВК_ХЕШ"
    link = (
        f"qwdtt://config?name=qWDTT-{server_ip}"
        f"&peer={server_ip}:{dtls_port}"
        f"&hashes={vk_part}"
        f"&workers=16&port={_DEFAULT_TUN_PORT}"
        f"&pass={new_pass}"
    )
    print()
    _box_link(link)
    print()
    link_path = _save_link_file(link, f"link_{new_pass[:8]}.txt")
    _print_link_file_path(link_path)
    _pause()

def _show_password_link(passwords: dict, server_ip: str, dtls_port: int) -> None:
    if not passwords:
        print(f"  {YELLOW}⚠{NC}  Паролей нет."); _pause(); return

    os.system("clear")
    _box_top("🔗  ССЫЛКА ДЛЯ ПАРОЛЯ  •  qWDTT")
    _box_row()
    pw_list = list(passwords.keys())
    for i, pw in enumerate(pw_list, 1):
        _box_row(f"  {DIM}{i}.{NC}  {CYAN}{pw[:16]:<18}{NC}"
                 f"{DIM}{passwords[pw].get('vk_hash', '—')[:20]}{NC}")
    _box_row(); _box_item("Q", "← Отмена"); _box_bot(); print()

    try:
        num = proto_ask(f"{CYAN}Номер: {NC}", c=True).strip()
    except _Cancelled:
        raise
    if num.lower() == "q" or not num:
        return
    try:
        idx = int(num) - 1
        pw = pw_list[idx]
    except (ValueError, IndexError):
        print(f"  {RED}✗{NC}  Неверный номер."); _pause(); return

    entry = passwords[pw]
    vk_hash = entry.get("vk_hash", "") or "ВК_ХЕШ"
    link = (
        f"qwdtt://config?name=qWDTT-{server_ip}"
        f"&peer={server_ip}:{dtls_port}"
        f"&hashes={vk_hash}"
        f"&workers=16&port={_DEFAULT_TUN_PORT}"
        f"&pass={pw}"
    )
    print()
    _box_top("🔗  ССЫЛКА ДЛЯ КЛИЕНТА")
    _box_row()
    if vk_hash == "ВК_ХЕШ":
        _box_warn("Хеш звонка не задан — замените ВК_ХЕШ вручную.")
    _box_bot()
    print()
    _box_link(link)
    print()
    link_path = _save_link_file(link, f"link_{pw[:8]}.txt")
    _print_link_file_path(link_path)
    _pause()

def _delete_password(passwords: dict) -> None:
    if not passwords:
        print(f"  {YELLOW}⚠{NC}  Паролей нет."); _pause(); return

    os.system("clear")
    _box_top("🗑️  УДАЛИТЬ ПАРОЛЬ  •  qWDTT")
    _box_row()
    pw_list = list(passwords.keys())
    for i, pw in enumerate(pw_list, 1):
        _box_row(f"  {DIM}{i}.{NC}  {CYAN}{pw[:16]}{NC}")
    _box_row(); _box_item("Q", "← Отмена"); _box_bot(); print()

    try:
        num = proto_ask(f"{CYAN}Номер: {NC}", c=True).strip()
    except _Cancelled:
        raise
    if num.lower() == "q" or not num:
        return
    try:
        idx = int(num) - 1
        pw = pw_list[idx]
    except (ValueError, IndexError):
        print(f"  {RED}✗{NC}  Неверный номер."); _pause(); return

    try:
        confirm = proto_ask(
            f"  {YELLOW}Удалить пароль {pw[:12]}...? [y/N]: {NC}",
            default="n", c=True,
        ).strip().lower()
    except _Cancelled:
        raise
    if confirm != "y":
        return

    data = _load_passwords()
    data["passwords"].pop(pw, None)
    _save_passwords(data)
    _hot_reload()
    print(f"  {GREEN}✓{NC}  Пароль удалён, hot reload выполнен.")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС
# ══════════════════════════════════════════════════════════════════════════════
def _show_status() -> None:
    os.system("clear")
    state = proto_load_state(_MODULE_STATE)
    _box_top("📊  СТАТУС  •  qWDTT")
    _box_row()

    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    svc_ok = r.stdout.strip() == "active"
    _box_kv("Сервис:",
            f"{GREEN}● активен{NC}" if svc_ok else f"{RED}● остановлен{NC}")
    _box_kv("Бинарник:",
            f"{GREEN}✓{NC}" if _BIN_PATH.exists() else f"{RED}✗ не найден{NC}")
    _box_kv("DTLS порт:", str(state.get("dtls_port", "—")))
    _box_kv("WG порт:",   str(state.get("wg_port", "—")))
    _box_row()

    data = _load_passwords()
    passwords = data.get("passwords", {})
    devices   = data.get("devices", {})
    _box_kv("Паролей:", str(len(passwords)))
    _box_kv("Устройств:", str(len(devices)))
    _box_row(); _box_sep()
    _box_row(f"  {BOLD}{WHITE}Последние 30 строк журнала:{NC}")
    _box_bot()  # рамка закрыта — длинные строки лога печатаются уже вне неё

    r2 = subprocess.run(
        ["journalctl", "-u", _SERVICE_NAME, "-n", "30",
         "--no-pager", "--output=short-monotonic"],
        capture_output=True, encoding="utf-8", errors="replace",
        env={**os.environ, "LANG": "C.UTF-8"},
    )
    max_w = _BOX_W + 12  # вне рамки можно чуть шире — просто по ширине терминала
    for line in (r2.stdout or r2.stderr or "Нет записей").splitlines():
        line = line.replace("\t", "    ")
        if _wlen(line) > max_w:
            acc, cut = 0, 0
            import unicodedata as _ud
            for ch in line:
                acc += 2 if _ud.east_asian_width(ch) in ('W', 'F') else 1
                if acc > max_w:
                    break
                cut += 1
            line = line[:cut] + "…"
        print(f"  {DIM}{line}{NC}")

    print()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ПОЛНОЕ УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _full_uninstall(silent: bool = False) -> bool:
    if not silent:
        os.system("clear")
        _box_top("🗑️  УДАЛЕНИЕ  •  qWDTT")
        _box_row()
        _box_warn("Будет удалено:")
        _box_row(f"  {DIM}  • Сервис systemd  (wdtt){NC}")
        _box_row(f"  {DIM}  • Бинарник        ({_BIN_PATH}){NC}")
        _box_row(f"  {DIM}  • Конфиги          ({_CFG_DIR}){NC}")
        _box_row(f"  {DIM}  • iptables UDP {_DEFAULT_DTLS_PORT} и MASQUERADE{NC}")
        _box_row(f"  {DIM}  • /var/lib/xray-installer/wdtt.json{NC}")
        _box_row()
        _box_warn("VLESS/Xray конфиги не затрагиваются.")
        _box_row()
        _box_item("Y", f"{RED}Да, удалить{NC}")
        _box_item("N", "Нет, отмена")
        _box_bot(); print()
        try:
            ans = proto_ask(f"{CYAN}Подтверждение [y/N]: {NC}", c=True).strip().lower()
        except _Cancelled:
            return False
        if ans != "y":
            print(f"  {DIM}Отменено.{NC}"); _pause(); return False

    state = proto_load_state(_MODULE_STATE)
    dtls_port = state.get("dtls_port", _DEFAULT_DTLS_PORT)

    _run(["systemctl", "stop",    _SERVICE_NAME])
    _run(["systemctl", "disable", _SERVICE_NAME])
    if _SERVICE_FILE.exists():
        _SERVICE_FILE.unlink()
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "reset-failed"], capture=True)

    if _BIN_PATH.exists():
        _BIN_PATH.unlink()

    if _CFG_DIR.exists():
        shutil.rmtree(_CFG_DIR, ignore_errors=True)

    _ipt_close_udp(dtls_port)
    _ipt_remove_masquerade()
    proto_ipt_persist()

    sysctl = Path("/etc/sysctl.d/99-wdtt.conf")
    if sysctl.exists():
        sysctl.unlink()

    try:
        if _MODULE_STATE.exists():
            _MODULE_STATE.unlink()
    except Exception:
        pass

    if not silent:
        print(f"  {GREEN}✓{NC}  qWDTT удалён.")
        _pause()
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  ГАЙД
# ══════════════════════════════════════════════════════════════════════════════
def _show_guide() -> None:
    while True:
        os.system("clear")
        _box_top("📖  ГАЙД  •  qWDTT + qWDTT Android")
        _box_row()
        _box_item("1", "Скачать приложение qWDTT на Android")
        _box_item("2", "Получить VK-хеш звонка")
        _box_item("3", "Подключиться по ссылке qwdtt://")
        _box_item("4", "Telegram-бот — управление паролями")
        _box_item("5", "Отличия от vk-turn-proxy (turntunnel)")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()

        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            _guide_install()
        elif ch == "2":
            _guide_vk_hash()
        elif ch == "3":
            _guide_connect()
        elif ch == "4":
            _guide_telegram()
        elif ch == "5":
            _guide_diff()
        elif ch in ("q", ""):
            break

def _guide_install() -> None:
    os.system("clear")
    _box_top("📱  СКАЧАТЬ qWDTT")
    _box_row()
    _box_info("qWDTT — форк нетРКН с поддержкой профилей и qwdtt:// ссылок.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Android (APK):{NC}")
    _box_row()
    _box_info("Скачайте APK с официального GitHub:")
    _box_row(f"  {YELLOW}github.com/SpaceNeuroX/proxy-turn-vk-android/releases{NC}")
    _box_row()
    _box_info("Установите, разрешив установку из неизвестных источников.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Требования:{NC}")
    _box_row()
    _box_info("Android 8.0+ (API 26)")
    _box_info("Архитектуры: arm64-v8a, armeabi-v7a, x86_64")
    _box_bot()
    _pause()

def _guide_vk_hash() -> None:
    os.system("clear")
    _box_top("🔑  ПОЛУЧИТЬ VK-ХЕШ ЗВОНКА")
    _box_row()
    _box_info("Хеш — часть ссылки после /join/ в приглашении на звонок ВКонтакте.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Шаги:{NC}")
    _box_row()
    _box_info("1. Откройте ВКонтакте")
    _box_info("2. Любая группа → Звонки → Новый звонок")
    _box_info("3. Скопируйте ссылку-приглашение:")
    _box_row(f"  {DIM}   https://vk.com/call/join/ХЕШЕ{NC}")
    _box_info("4. Хеш — это всё что после /join/")
    _box_row()
    _box_sep()
    _box_warn("Можно использовать до 4 хешей одновременно (через запятую)")
    _box_warn("для распределения нагрузки между несколькими звонками.")
    _box_row()
    _box_warn("При выходе нажимайте «Просто завершить», НЕ «Завершить для всех».")
    _box_bot()
    _pause()

def _guide_connect() -> None:
    os.system("clear")
    _box_top("🔗  ПОДКЛЮЧЕНИЕ ПО qwdtt://")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Формат ссылки:{NC}")
    _box_row()
    _box_row(f"  {CYAN}qwdtt://config?{NC}")
    _box_row(f"  {DIM}  name=  — название профиля{NC}")
    _box_row(f"  {DIM}  peer=  — IP:порт сервера (например 1.2.3.4:56000){NC}")
    _box_row(f"  {DIM}  hashes=— VK-хеш(и) через запятую{NC}")
    _box_row(f"  {DIM}  workers=16  (потоков на хеш, 16 оптимально){NC}")
    _box_row(f"  {DIM}  port=9000   (локальный порт Android){NC}")
    _box_row(f"  {DIM}  pass=  — пароль подключения{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Как импортировать:{NC}")
    _box_row()
    _box_info("1. Скопируйте ссылку из пункта [2] главного меню qWDTT")
    _box_info("2. В приложении qWDTT → «+» → вставьте ссылку")
    _box_info("3. Нажмите «Подключить»")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Или через QR-код:{NC}")
    _box_row()
    _box_info("Сгенерируйте QR из ссылки на любом сайте и отсканируйте.")
    _box_bot()
    _pause()

def _guide_telegram() -> None:
    os.system("clear")
    _box_top("🤖  TELEGRAM-БОТ  •  qWDTT")
    _box_row()
    _box_info("Бот позволяет управлять паролями прямо из Telegram.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Создать бота:{NC}")
    _box_row()
    _box_info("1. В Telegram найдите @BotFather")
    _box_info("2. /newbot → введите имя → получите токен")
    _box_info("3. Свой Chat ID узнайте через @userinfobot")
    _box_info("4. Укажите токен и ID при установке qWDTT")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Команды бота:{NC}")
    _box_row()
    _box_kv("  /new",  "Создать временный пароль", 12)
    _box_kv("  /list", "Список паролей + управление", 12)
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Через бота можно:{NC}")
    _box_row()
    _box_info("• Создать пароль с TTL и лимитом устройств")
    _box_info("• Получить готовый .conf файл для qWDTT")
    _box_info("• Получить qwdtt:// ссылку с VK-хешем")
    _box_info("• Деактивировать / активировать пароль")
    _box_info("• Отвязать устройства от пароля")
    _box_info("• Удалить пароль (hot reload без перезапуска)")
    _box_bot()
    _pause()

def _guide_diff() -> None:
    os.system("clear")
    _box_top("⚖️  qWDTT vs vk-turn-proxy")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}vk-turn-proxy (модуль turntunnel){NC}")
    _box_row()
    _box_info("Протокол: VLESS (Xray)")
    _box_info("Аутентификация: UUID")
    _box_info("Клиент: WireTurn (Android)")
    _box_info("Настройка: проще — вставить VLESS-ссылку")
    _box_info("Мультипользователи: через turntunnel_links.py")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}qWDTT (этот модуль){NC}")
    _box_row()
    _box_info("Протокол: WireGuard (встроенный)")
    _box_info("Аутентификация: пароль + HKDF (ключ не в APK)")
    _box_info("Клиент: qWDTT APK")
    _box_info("Настройка: qwdtt:// ссылка или .conf файл")
    _box_info("Мультипользователи: встроено (до 10 паролей + TTL)")
    _box_info("Telegram-бот: управление без SSH")
    _box_info("Hot reload: смена паролей без перезапуска")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Когда что выбрать:{NC}")
    _box_row()
    _box_info("vk-turn-proxy → хочу VLESS, минимум настроек")
    _box_info("qWDTT → нужны временные пароли, Telegram-управление")
    _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ МОДУЛЯ
# ══════════════════════════════════════════════════════════════════════════════
def do_wdtt_menu() -> None:
    """
    Точка входа из _core.py.
    Ctrl+C → возврат в главное меню VLESS.
    """
    while True:
        os.system("clear")
        installed = _is_installed()
        state     = proto_load_state(_MODULE_STATE)

        r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
        svc_ok = r.stdout.strip() == "active"

        svc_str = (
            f"{GREEN}● активен{NC}"  if svc_ok    else
            f"{RED}● остановлен{NC}" if installed else
            f"{YELLOW}● не установлен{NC}"
        )

        _box_top("qWDTT  •  WireGuard / TURN ВКонтакте")
        _box_row()
        _box_kv("Статус:", svc_str)

        if installed:
            data = _load_passwords()
            pw_count = len(data.get("passwords", {}))
            dev_count = len(data.get("devices", {}))
            _box_kv("DTLS порт:",   str(state.get("dtls_port", "—")))
            _box_kv("Паролей:",     str(pw_count))
            _box_kv("Устройств:",   str(dev_count))
            tg = "✓ настроен" if state.get("bot_token") else "не настроен"
            tg_col = GREEN if state.get("bot_token") else DIM
            _box_kv("Telegram-бот:", f"{tg_col}{tg}{NC}")

        _box_row(); _box_sep()

        if not installed:
            _box_item("1", "🚀  Установить qWDTT")
        else:
            _box_item("1", "🚀  Переустановить")
            _box_item("2", "🔑  Управление паролями")
            _box_item("3", "🔗  Показать ссылку (главный пароль)")
            _box_item("4", "🔄  Перезапустить сервис")
            _box_item("5", "📊  Статус / логи")
            _box_sep()
            _box_item("8", f"{RED}🗑️   Удалить qWDTT{NC}")

        _box_sep()
        _box_item("G", "📖  Гайд: установка, VK-хеш, Telegram-бот")
        _box_sep()
        _box_item("Q", "← Назад в главное меню VLESS")
        _box_bot(); print()

        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            _run_install()

        elif ch == "2" and installed:
            try:
                _passwords_menu()
            except _Cancelled:
                pass

        elif ch == "3" and installed:
            os.system("clear")
            state = proto_load_state(_MODULE_STATE)
            server_ip = _get_server_ip()
            dtls_port = state.get("dtls_port", _DEFAULT_DTLS_PORT)
            main_pass = state.get("main_password", "")
            _box_top("🔗  ССЫЛКА  •  ГЛАВНЫЙ ПАРОЛЬ")
            _box_row()
            _box_warn("Замените ВК_ХЕШ на хеш из vk.com/call/join/ХЕШ")
            _box_bot()
            link = (
                f"qwdtt://config?name=qWDTT-{server_ip}"
                f"&peer={server_ip}:{dtls_port}"
                f"&hashes=ВК_ХЕШ"
                f"&workers=16&port={_DEFAULT_TUN_PORT}"
                f"&pass={main_pass}"
            )
            print()
            _box_link(link)
            print()
            _pause()

        elif ch == "4" and installed:
            _run(["systemctl", "restart", _SERVICE_NAME])
            time.sleep(1)
            r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
            print(f"  {'✓' if r.stdout.strip()=='active' else '⚠'}  "
                  f"{'Перезапущен.' if r.stdout.strip()=='active' else 'Проверьте логи (пункт 5).'}")
            _pause()

        elif ch == "5" and installed:
            _show_status()

        elif ch == "8" and installed:
            try:
                _full_uninstall(silent=False)
            except _Cancelled:
                print(f"  {DIM}Отменено.{NC}"); _pause()

        elif ch == "g":
            try:
                _show_guide()
            except _Cancelled:
                pass

        elif ch in ("q", ""):
            break

# ══════════════════════════════════════════════════════════════════════════════
#  АВТОНОМНЫЙ ЗАПУСК (отладка)
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}"); sys.exit(1)
    try:
        do_wdtt_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}"); sys.exit(0)
