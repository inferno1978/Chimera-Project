"""
chimera/modules/csqtt.py
───────────────────────────────────────────────────────────────────────────────
CSQTT — Censorship-circumvention tunnel over TURN/RTP.

Назначение:
  Туннельный сервер, маскирующий трафик под зашифрованный RTP/TURN
  медиатрафик (видеозвонок). Android-клиент поднимает локальный TUN
  интерфейс, трафик идёт через TURN-серверы как медиапоток.

Схема трафика:
  Android (CSQTT APK)
    │  RTP AEAD / ChaCha20-Poly1305 поверх UDP/TURN
    ▼
  TURN-серверы (трафик = медиа-поток звонка)
    │  UDP → VPS :46000
    ▼
  csqtt-server  (:46000/udp data-plane)
    │  TUN: csqtt1  (10.66.67.0/24)
    │  NAT → Интернет
    ▼
  Web Panel: :46002 (HTTPS, axum + rustls)

Отличия от qWDTT:
  • Протокол: RTP/AEAD (не WireGuard)
  • Сервер: Rust/io_uring (не Go)
  • Web Panel: встроенная HTTPS панель (не нужен внешний nginx)
  • Туннель: TUN + NAT (не WireGuard)
  • Аутентификация: парольная (как qWDTT)

Что модуль делает:
  • Проверяет наличие Rust + Zig и собирает csqtt-server из исходников
  • Настраивает /etc/csqtt (config, passwords)
  • Создаёт systemd-сервис csqtt.service
  • Настраивает NAT через iptables (MASQUERADE для csqtt1)
  • Открывает UDP-порт 46000 в iptables
  • Открывает TCP-порт 46002 для Web Panel
  • Настраивает nginx front для Web Panel (TLS, по аналогии с b4)
  • Управление паролями: создание, список, удаление
  • Показывает гайд по использованию CSQTT

Что модуль НЕ трогает:
  • config.json Xray и VLESS-inbound
  • state.json инсталлера
  • iptables-правила других модулей
  • Любые другие службы

Точка входа из _core.py:
    from chimera.modules.csqtt import do_csqtt_menu
    do_csqtt_menu()
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
import time
import urllib.request
import urllib.parse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from chimera.modules.proto_common import (
    ProtoCancelled, proto_load_state, proto_save_state,
    proto_ask, proto_gen_password, proto_ipt_persist, proto_ipt_rule_exists,
)
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
_BIN_PATH         = Path("/usr/local/bin/csqtt-server")
_CFG_DIR          = Path("/etc/csqtt")
_CFG_FILE         = Path("/etc/csqtt/config.json")
_PASSWORDS_FILE   = Path("/etc/csqtt/passwords.json")
_SERVICE_FILE     = Path("/etc/systemd/system/csqtt.service")
_SERVICE_NAME     = "csqtt"
_MODULE_STATE     = Path("/var/lib/xray-installer/csqtt.json")

# GitHub
_GITHUB_REPO      = "amurcanov/csqtt"

# Порты по умолчанию
# CSQTT binary 2.0.0 использует хардкоднутые дефолты 46000/46002.
# Раньше (1.x) было 40000/40500 — см. CHANGELOG.
# Проверено через `ss -tlnp | grep csqtt` и `journalctl -u csqtt` 22.08.2026:
#   [INFO]  RTP AEAD: 0.0.0.0:46000   ← data-plane
#   [INFO]  Web: 0.0.0.0:46002        ← Web Panel
# Эти порты нельзя изменить через CLI — binary игнорирует --listen/--web-port
# при работе через systemd. Принимаем как есть.
_DEFAULT_DATA_PORT = 46000   # входящий UDP data-plane (RTP/TURN)
_DEFAULT_WEB_PORT  = 46002   # Web Panel (HTTPS, 0.0.0.0)
_DEFAULT_NGINX_PORT = 46443  # nginx front для Web Panel (TLS)

# TUN сеть
_TUN_SUBNET       = "10.66.67.0/24"
_TUN_SERVER_IP    = "10.66.67.1"

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
    if not color:
        color = YELLOW
    max_w = _BOX_W - 2
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

def _build_csqtt_v2_link(server_ip: str, data_port: int, password: str,
                         name: str = "", vk_hashes: str = "") -> str:
    """Строит корректный csqtt:// deep-link в формате v2.

    Формат (подтверждён из upstream amurcanov/csqtt Android-клиента,
    файл app/src/main/java/com/csqtt/client/ui/utils/UiUtils.kt):

        csqtt://connect?v=2&host=<ip>&peer=<port>&password=<пароль>

    Обязательные параметры:
      - v=2                  — версия формата (фиксированное значение)
      - host=<server_ip>     — IP или домен сервера
      - peer=<port>          — порт data-plane (46000 по умолчанию)
      - password=<password>  — пароль юзера или главный пароль

    Необязательные:
      - hashes=<vk_hashes>   — VK-хеши через запятую

    ВАЖНО: upstream-парсер (UiUtils.kt) отвергает ссылки с fragment
    (часть после '#'), поэтому name НЕ добавляется в ссылку —
    используйте параметр name только для отображения в UI Chimera.

    Старый формат csqtt://config?name=...&peer=ip:port&pass=...
    НЕ поддерживается клиентом в "роли участника" — выдаёт
    "неверная ссылка csqtt v2". Исправлено 22.08.2026 после баг-репорта
    от юзера SpecteR.
    """
    # URL-encode password — там могут быть спецсимволы
    host_enc = urllib.parse.quote(str(server_ip), safe="")
    port_enc = str(int(data_port))
    pwd_enc = urllib.parse.quote(str(password), safe="")

    # Базовый v2-формат
    link = f"csqtt://connect?v=2&host={host_enc}&peer={port_enc}&password={pwd_enc}"

    # Опциональные VK-хеши — только если реально есть значение.
    # Если передать пустой hashes — upstream-парсер вернёт null.
    if vk_hashes and vk_hashes.strip():
        link += f"&hashes={urllib.parse.quote(vk_hashes, safe=',')}"

    return link

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
    if not _PASSWORDS_FILE.exists():
        return {"main_password": "", "passwords": {}, "devices": {}}
    try:
        return json.loads(_PASSWORDS_FILE.read_text())
    except Exception:
        return {}

def _save_passwords(data: dict) -> None:
    _CFG_DIR.mkdir(parents=True, exist_ok=True)
    _PASSWORDS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    _PASSWORDS_FILE.chmod(0o600)

def _hot_reload() -> bool:
    """Отправляет SIGHUP серверу — hot reload паролей."""
    r = _run(["pidof", "csqtt-server"], capture=True)
    pid = (r.stdout or "").strip()
    if not pid:
        return False
    _run(["kill", "-HUP", pid])
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  SYNC CONTRACT — для реестра _SYNCABLE_PROTOCOLS в rest_api.py
# ══════════════════════════════════════════════════════════════════════════════
def is_active() -> bool:
    """True если CSQTT установлен И сервис запущен."""
    try:
        if not _is_installed():
            return False
        r = _run(["systemctl", "is-active", _SERVICE_NAME],
                 capture=True, check=False)
        return r.returncode == 0 and r.stdout.strip() == "active"
    except Exception:
        return False

def _find_password_by_owner(email: str) -> Optional[str]:
    if not email:
        return None
    data = _load_passwords()
    for pwd, info in data.get("passwords", {}).items():
        if info.get("owner_email") == email:
            return pwd
    return None

def ensure_user_full(user: dict) -> bool:
    """Создаёт CSQTT-пароль для VLESS-юзера."""
    try:
        if not _is_installed():
            return True
        email = user.get("email", "") or ""
        if not email:
            return False
        existing = _find_password_by_owner(email)
        if existing:
            return True
        data = _load_passwords()
        passwords = data.get("passwords", {})
        new_pass = proto_gen_password()
        expires_at = int((datetime.now() + timedelta(days=365)).timestamp())
        passwords[new_pass] = {
            "device_ids":    [],
            "max_devices":   1,
            "expires_at":    expires_at,
            "down_bytes":    0,
            "up_bytes":      0,
            "is_deactivated": False,
            "owner_email":   email,
        }
        data["passwords"] = passwords
        _save_passwords(data)
        _hot_reload()
        return True
    except Exception:
        return False

def ensure_user(name: str) -> bool:
    return ensure_user_full({"email": name, "name": name})

def remove_user_full(user: dict) -> bool:
    """Удаляет CSQTT-пароль по owner_email."""
    try:
        if not _is_installed():
            return True
        email = user.get("email", "") or ""
        if not email:
            return False
        pwd = _find_password_by_owner(email)
        if not pwd:
            return True
        data = _load_passwords()
        passwords = data.get("passwords", {})
        if pwd in passwords:
            del passwords[pwd]
            data["passwords"] = passwords
            _save_passwords(data)
            _hot_reload()
        return True
    except Exception:
        return False

def remove_user(name: str) -> bool:
    return remove_user_full({"email": name, "name": name})

def rename_user_full(old_user: dict, new_user: dict) -> bool:
    try:
        ok1 = remove_user_full(old_user)
        ok2 = ensure_user_full(new_user)
        return ok1 and ok2
    except Exception:
        return False

def rename_user(old_name: str, new_name: str) -> bool:
    return rename_user_full(
        {"email": old_name, "name": old_name},
        {"email": new_name, "name": new_name},
    )

# ══════════════════════════════════════════════════════════════════════════════
#  SUBSCRIPTION CONTRACT — для реестра _SUBSCRIBABLE_PROTOCOLS
# ══════════════════════════════════════════════════════════════════════════════
def get_subscription_uris(user: dict) -> list:
    """Возвращает csqtt:// ссылку для юзера (по owner_email)."""
    try:
        if not _is_installed():
            return []
        email = user.get("email", "") or ""
        if not email:
            return []
        pwd = _find_password_by_owner(email)
        if not pwd:
            return []
        data = _load_passwords()
        entry = data.get("passwords", {}).get(pwd, {})
        if not entry:
            return []
        if entry.get("is_deactivated", False):
            return []
        expires = entry.get("expires_at", 0)
        if expires > 0 and time.time() > expires:
            return []
        state = proto_load_state(_MODULE_STATE)
        server_ip = _get_server_ip()
        data_port = state.get("data_port", _DEFAULT_DATA_PORT)
        link = _build_csqtt_v2_link(server_ip, data_port, pwd)
        return [link]
    except Exception:
        return []

# ══════════════════════════════════════════════════════════════════════════════
#  СБОРКА / УСТАНОВКА БИНАРНИКА
# ══════════════════════════════════════════════════════════════════════════════
def _build_csqtt_server() -> bool:
    """Скачивает исходники CSQTT и собирает через download_manager."""
    from chimera.modules.download_manager import fetch_package
    from chimera.modules.csqtt_packages import CSQTT_SOURCE_SPEC

    print(f"  {CYAN}→{NC}  Скачиваю исходники CSQTT (через download_manager)...")
    ok = fetch_package(CSQTT_SOURCE_SPEC, progress_label="CSQTT")
    if ok:
        print(f"  {GREEN}✓{NC}  csqtt-server установлен: {_BIN_PATH}")
    return ok

# ══════════════════════════════════════════════════════════════════════════════
#  IPTABLES
# ══════════════════════════════════════════════════════════════════════════════
def _ipt_rule_exists(table: str, chain: str, args: list) -> bool:
    return proto_ipt_rule_exists(table, chain, args)

def _fw_tool() -> str:
    """Возвращает 'ufw' если UFW установлен и активен, иначе 'iptables'."""
    if shutil.which("ufw"):
        r = _run(["ufw", "status"], capture=True, check=False)
        if "Status: active" in (r.stdout or ""):
            return "ufw"
    return "iptables"

def _ipt_open_udp(port: int) -> None:
    """Открывает UDP-порт для CSQTT data-plane (46000).

    Алгоритм:
      1. Регистрируем в port_registry (JSON — для других модулей).
      2. Через ufw_open_port (если UFW активен) — с chimera-csqtt comment.
      3. Fallback на iptables если UFW недоступен.
      4. Логируем результат.
    """
    fw = _fw_tool()
    opened_via = ""
    try:
        from chimera.modules.port_registry import (
            ufw_open_port, port_register, SERVICE_CSQTT,
        )
        # Регистрируем в port_registry (всегда — даже если UFW inactive).
        port_register(SERVICE_CSQTT, port, "udp",
                      comment="CSQTT data-plane", force=True)
        # Пытаемся открыть через UFW.
        ufw_ok, ufw_msg = ufw_open_port(port, "udp", SERVICE_CSQTT,
                                         comment="CSQTT data-plane")
        if ufw_ok:
            opened_via = f"UFW ({ufw_msg})"
        else:
            # UFW недоступен/inactive — fallback на iptables.
            args = ["-p", "udp", "--dport", str(port), "-j", "ACCEPT"]
            if not _ipt_rule_exists("filter", "INPUT", args):
                _run(["iptables", "-t", "filter", "-I", "INPUT", "1"] + args)
                opened_via = "iptables (fallback — UFW недоступен)"
            else:
                opened_via = "iptables (уже открыт)"
    except Exception as _e:
        # port_registry недоступен — fallback на прямой iptables/ufw.
        if fw == "ufw":
            r = _run(["ufw", "status"], capture=True, check=False)
            if not re.search(rf'^{port}/udp\b.*ALLOW', r.stdout or "", re.MULTILINE):
                _run(["ufw", "allow", f"{port}/udp", "comment", "CSQTT data-plane"],
                     check=False)
            opened_via = "UFW (fallback — port_registry недоступен)"
        else:
            args = ["-p", "udp", "--dport", str(port), "-j", "ACCEPT"]
            if not _ipt_rule_exists("filter", "INPUT", args):
                _run(["iptables", "-t", "filter", "-I", "INPUT", "1"] + args)
            opened_via = f"iptables (fallback — port_registry error: {_e})"
    print(f"  {GREEN}✓{NC}  UDP {port} открыт ({opened_via})")

def _ipt_close_udp(port: int) -> None:
    """Закрывает UDP-порт CSQTT data-plane + снимает регистрацию."""
    closed_via = ""
    try:
        from chimera.modules.port_registry import (
            ufw_close_port, port_unregister, SERVICE_CSQTT,
        )
        ufw_close_port(port, "udp", SERVICE_CSQTT,
                       legacy_comments=["CSQTT data-plane"])
        port_unregister(SERVICE_CSQTT, port, "udp")
        closed_via = "UFW + port_registry"
    except Exception as _e:
        closed_via = f"fallback ({_e})"
    # Двойная проверка — снимаем orphaned правила (если port_registry не нашёл).
    if shutil.which("ufw") and _fw_tool() == "ufw":
        _run(["ufw", "delete", "allow", f"{port}/udp"], check=False)
    args = ["-p", "udp", "--dport", str(port), "-j", "ACCEPT"]
    for _ in range(5):
        if not _ipt_rule_exists("filter", "INPUT", args):
            break
        _run(["iptables", "-t", "filter", "-D", "INPUT"] + args)
    print(f"  {GREEN}✓{NC}  UDP {port} закрыт ({closed_via})")

def _ipt_open_tcp(port: int) -> None:
    """Открывает TCP-порт для Web Panel CSQTT (46002)."""
    fw = _fw_tool()
    opened_via = ""
    try:
        from chimera.modules.port_registry import (
            ufw_open_port, port_register, SERVICE_CSQTT_WEB,
        )
        port_register(SERVICE_CSQTT_WEB, port, "tcp",
                      comment="CSQTT Web Panel", force=True)
        ufw_ok, ufw_msg = ufw_open_port(port, "tcp", SERVICE_CSQTT_WEB,
                                         comment="CSQTT Web Panel")
        if ufw_ok:
            opened_via = f"UFW ({ufw_msg})"
        else:
            args = ["-p", "tcp", "--dport", str(port), "-j", "ACCEPT"]
            if not _ipt_rule_exists("filter", "INPUT", args):
                _run(["iptables", "-t", "filter", "-I", "INPUT", "1"] + args)
                opened_via = "iptables (fallback — UFW недоступен)"
            else:
                opened_via = "iptables (уже открыт)"
    except Exception as _e:
        if fw == "ufw":
            r = _run(["ufw", "status"], capture=True, check=False)
            if not re.search(rf'^{port}/tcp\b.*ALLOW', r.stdout or "", re.MULTILINE):
                _run(["ufw", "allow", f"{port}/tcp", "comment", "CSQTT Web Panel"],
                     check=False)
            opened_via = "UFW (fallback — port_registry недоступен)"
        else:
            args = ["-p", "tcp", "--dport", str(port), "-j", "ACCEPT"]
            if not _ipt_rule_exists("filter", "INPUT", args):
                _run(["iptables", "-t", "filter", "-I", "INPUT", "1"] + args)
            opened_via = f"iptables (fallback — port_registry error: {_e})"
    print(f"  {GREEN}✓{NC}  TCP {port} открыт ({opened_via})")

def _ipt_close_tcp(port: int) -> None:
    """Закрывает TCP-порт Web Panel CSQTT + снимает регистрацию."""
    closed_via = ""
    try:
        from chimera.modules.port_registry import (
            ufw_close_port, port_unregister, SERVICE_CSQTT_WEB,
        )
        ufw_close_port(port, "tcp", SERVICE_CSQTT_WEB,
                       legacy_comments=["CSQTT Web Panel"])
        port_unregister(SERVICE_CSQTT_WEB, port, "tcp")
        closed_via = "UFW + port_registry"
    except Exception as _e:
        closed_via = f"fallback ({_e})"
    if shutil.which("ufw") and _fw_tool() == "ufw":
        _run(["ufw", "delete", "allow", f"{port}/tcp"], check=False)
    args = ["-p", "tcp", "--dport", str(port), "-j", "ACCEPT"]
    for _ in range(5):
        if not _ipt_rule_exists("filter", "INPUT", args):
            break
        _run(["iptables", "-t", "filter", "-D", "INPUT"] + args)
    print(f"  {GREEN}✓{NC}  TCP {port} закрыт ({closed_via})")

def _ipt_masquerade_exists() -> bool:
    r = _run(
        ["iptables", "-t", "nat", "-C", "POSTROUTING",
         "-s", _TUN_SUBNET, "!", "-d", _TUN_SUBNET, "-j", "MASQUERADE"],
        capture=True,
    )
    return r.returncode == 0

def _ipt_add_masquerade() -> None:
    """Добавляет MASQUERADE для TUN-интерфейса csqtt1 (10.66.67.0/24).

    MASQUERADE — это NAT (не port opening), поэтому port_registry тут
    не используется (он для INPUT chain портов). Но логируем для видимости.
    """
    if not _ipt_masquerade_exists():
        _run(["iptables", "-t", "nat", "-A", "POSTROUTING",
              "-s", _TUN_SUBNET, "!", "-d", _TUN_SUBNET, "-j", "MASQUERADE"])
        print(f"  {GREEN}✓{NC}  MASQUERADE для {_TUN_SUBNET} добавлен")
    else:
        print(f"  {DIM}MASQUERADE для {_TUN_SUBNET} уже существует{NC}")

def _ipt_remove_masquerade() -> None:
    """Удаляет MASQUERADE для TUN-интерфейса csqtt1."""
    removed = 0
    for _ in range(3):
        if not _ipt_masquerade_exists():
            break
        _run(["iptables", "-t", "nat", "-D", "POSTROUTING",
              "-s", _TUN_SUBNET, "!", "-d", _TUN_SUBNET, "-j", "MASQUERADE"])
        removed += 1
    if removed:
        print(f"  {GREEN}✓{NC}  MASQUERADE для {_TUN_SUBNET} удалён "
              f"({removed} правил)")
    else:
        print(f"  {DIM}MASQUERADE для {_TUN_SUBNET} не найден{NC}")

def _enable_ip_forward() -> None:
    _run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    sysctl = Path("/etc/sysctl.d/99-csqtt.conf")
    sysctl.write_text("net.ipv4.ip_forward = 1\n")
    print(f"  {GREEN}✓{NC}  IP forwarding включён")

# ══════════════════════════════════════════════════════════════════════════════
#  NGINX FRONT для Web Panel
# ══════════════════════════════════════════════════════════════════════════════
_CSQTT_NGINX_STATE_FILE = Path("/var/lib/xray-installer/csqtt_nginx_front.json")

def _csqtt_nginx_status() -> dict:
    if not _CSQTT_NGINX_STATE_FILE.exists():
        return {"enabled": False}
    try:
        return json.loads(_CSQTT_NGINX_STATE_FILE.read_text())
    except Exception:
        return {"enabled": False}

def _csqtt_nginx_get_url() -> Optional[str]:
    st = _csqtt_nginx_status()
    if not st.get("enabled"):
        return None
    port = st.get("port", _DEFAULT_NGINX_PORT)
    domain = st.get("domain")
    if not domain:
        return None
    return f"https://{domain}:{port}"

def _csqtt_nginx_install(port: int, use_self_signed: bool, domain) -> tuple:
    from chimera.modules.panel_nginx_front import panel_nginx_front_install

    ok, msg = panel_nginx_front_install(
        service_tag="csqtt_nginx",
        port=port,
        backend_port=_DEFAULT_WEB_PORT,  # 46002 — реальный порт CSQTT web panel
        site_name="chimera-csqtt-nginx",
        state_file=_CSQTT_NGINX_STATE_FILE,
        title="CSQTT Web Panel",
        use_self_signed=use_self_signed,
        domain=domain,
        websocket_origin_rewrite=False,
        backend_http_scheme="https",  # CSQTT web panel уже HTTPS
        cert_name_slug="chimera-csqtt",
    )
    return ok, msg

def _csqtt_nginx_remove() -> tuple:
    from chimera.modules.panel_nginx_front import panel_nginx_front_remove

    if not _csqtt_nginx_status().get("enabled"):
        return True, "nginx front уже выключен"

    panel_nginx_front_remove(
        service_tag="csqtt_nginx",
        site_name="chimera-csqtt-nginx",
        state_file=_CSQTT_NGINX_STATE_FILE,
        title="CSQTT Web Panel",
    )
    return True, "nginx front удалён"

# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEMD СЕРВИС
# ══════════════════════════════════════════════════════════════════════════════
def _install_service(data_port: int, web_port: int, main_pass: str,
                     web_user: str, web_pass: str, dns: str) -> None:
    # CSQTT binary 2.0.0 использует встроенные дефолтные порты 46000/46002
    # (хардкод, нельзя изменить через CLI). Передаём только конфигурацию.
    _SERVICE_FILE.write_text(
        "[Unit]\n"
        "Description=CSQTT — RTP/TURN Tunnel Server\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={_BIN_PATH} "
        f"--config-dir {_CFG_DIR} "
        f"--password {main_pass} "
        f"--web-user {web_user} "
        f"--web-pass {web_pass} "
        + (f"--dns {dns} " if dns else "")
        + "\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "User=root\n"
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
    _box_top("🚀  УСТАНОВКА  •  CSQTT")
    _box_row()

    if _is_installed():
        _box_warn("CSQTT уже установлен.")
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

    state = proto_load_state(_MODULE_STATE)
    old_pass  = state.get("main_password", "")
    old_data  = state.get("data_port", _DEFAULT_DATA_PORT)
    old_web   = state.get("web_port", _DEFAULT_WEB_PORT)
    old_wuser = state.get("web_user", "admin")
    old_wpass = state.get("web_pass", "")
    old_dns   = state.get("dns", "")

    os.system("clear")
    _box_top("🚀  НАСТРОЙКА  •  CSQTT")
    _box_row()
    _box_info("Главный пароль — бессрочный доступ (для себя).")
    _box_info("Оставьте пустым — пароль сгенерируется автоматически.")
    _box_row()
    _box_info("Web Panel — встроенная HTTPS панель управления.")
    _box_info("Доступ: логин/пароль, по домену или IP через nginx front.")
    _box_row()
    _box_bot(); print()

    try:
        raw = proto_ask(
            f"  {CYAN}Главный пароль [{old_pass or 'авто'}]: {NC}",
            default=old_pass, c=True,
        )
        main_pass = raw if raw else (proto_gen_password() if not old_pass else old_pass)

        # CSQTT использует фиксированные порты (46000/46002) — не спрашиваем.
        data_port = _DEFAULT_DATA_PORT
        web_port = _DEFAULT_WEB_PORT

        web_user = proto_ask(
            f"  {CYAN}Web Panel логин [{old_wuser}]: {NC}",
            default=old_wuser, c=True,
        )

        raw_wpass = proto_ask(
            f"  {CYAN}Web Panel пароль [{old_wpass or 'авто'}]: {NC}",
            default=old_wpass, c=True,
        )
        web_pass = raw_wpass if raw_wpass else (proto_gen_password() if not old_wpass else old_wpass)

        dns = proto_ask(
            f"  {CYAN}DNS (через запятую, Enter=1.1.1.1): {NC}",
            default=old_dns or "1.1.1.1", c=True,
        ).strip()
    except _Cancelled:
        raise

    if not (1024 <= data_port <= 65535) or not (1024 <= web_port <= 65535):
        print(f"  {RED}✗{NC}  Порты должны быть в диапазоне 1024–65535."); _pause(); return
    if data_port == web_port:
        print(f"  {RED}✗{NC}  Порты data-plane и Web Panel не должны совпадать."); _pause(); return

    os.system("clear")
    _box_top("🚀  УСТАНОВКА  •  CSQTT")
    _box_row()

    # 1. Бинарник
    _box_info("Сборка csqtt-server из исходников (Rust + Zig)...")
    _box_bot(); print()

    if not _build_csqtt_server():
        print()
        _box_top("🚀  УСТАНОВКА  •  CSQTT")
        _box_err("Не удалось собрать csqtt-server.")
        _box_err("Убедитесь что доступны Rust, Zig и интернет.")
        _box_row()
        _box_row(f"  {DIM}Диагностика:{NC}")
        # Проверяем, есть ли файл в /root/
        manual_path = Path("/root/csqtt-main.tar.gz")
        if manual_path.exists():
            ms = manual_path.stat().st_size
            _box_row(f"  {DIM}  • /root/csqtt-main.tar.gz — найден ({ms} байт){NC}")
            _box_row(f"  {DIM}    файл есть, но сборка упала. Смотрите ошибку выше.{NC}")
            _box_row(f"  {DIM}    Запустите direct-build скрипт для подробных логов:{NC}")
            _box_row(f"  {CYAN}    bash <(curl -fsSL https://gitlab.com/netwalker071778/chimera-project/-/raw/chimera-v5/scripts/csqtt-direct-build.sh){NC}")
        else:
            _box_row(f"  {DIM}  • /root/csqtt-main.tar.gz — НЕ найден{NC}")
            _box_row(f"  {DIM}    Скачайте вручную:{NC}")
            _box_row(f"  {CYAN}    curl -fL \"https://github.com/amurcanov/csqtt/archive/refs/heads/main.tar.gz\" -o /root/csqtt-main.tar.gz{NC}")
            _box_row(f"  {DIM}    и повторите установку.{NC}")
        # Проверяем свободное место
        try:
            import shutil as _sh
            total, used, free = _sh.disk_usage("/root")
            free_mb = free // (1024 * 1024)
            if free_mb < 2048:
                _box_row(f"  {YELLOW}⚠ свободное место: {free_mb} MB (нужно ≥ 2048 MB для Rust-сборки){NC}")
            else:
                _box_row(f"  {DIM}  • свободное место: {free_mb} MB ✓{NC}")
        except Exception:
            pass
        # Проверяем RAM
        try:
            meminfo = Path("/proc/meminfo").read_text()
            mem_avail_kb = 0
            swap_total_kb = 0
            for line in meminfo.splitlines():
                if line.startswith("MemAvailable:"):
                    mem_avail_kb = int(line.split()[1])
                elif line.startswith("SwapTotal:"):
                    swap_total_kb = int(line.split()[1])
            total_mb = (mem_avail_kb + swap_total_kb) // 1024
            if total_mb < 1024:
                _box_row(f"  {YELLOW}⚠ RAM+swap: {total_mb} MB (мало для сборки, нужно ≥ 1024 MB){NC}")
                _box_row(f"  {DIM}    Добавьте swap: fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile{NC}")
            else:
                _box_row(f"  {DIM}  • RAM+swap: {total_mb} MB ✓{NC}")
        except Exception:
            pass
        _box_bot(); _pause(); return

    print()
    # 2. Конфиг директория
    _CFG_DIR.mkdir(parents=True, exist_ok=True)

    if not _PASSWORDS_FILE.exists():
        _save_passwords({
            "main_password": main_pass,
            "passwords": {},
            "devices": {},
        })
    else:
        data = _load_passwords()
        data["main_password"] = main_pass
        _save_passwords(data)

    print(f"  {GREEN}✓{NC}  Конфиг создан: {_CFG_DIR}")

    # 3. IP forwarding (логирование внутри _enable_ip_forward)
    _enable_ip_forward()

    # 4. Firewall + NAT (логирование внутри каждой функции)
    _ipt_open_udp(data_port)
    _ipt_open_tcp(web_port)  # Web Panel слушает на 0.0.0.0
    _ipt_add_masquerade()
    proto_ipt_persist()

    # 5. Systemd
    _install_service(data_port, web_port, main_pass, web_user, web_pass, dns)
    print(f"  {GREEN}✓{NC}  Systemd-сервис создан.")

    # 6. Запуск
    _run(["systemctl", "start", _SERVICE_NAME])
    time.sleep(2)
    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    if r.stdout.strip() == "active":
        print(f"  {GREEN}✓{NC}  csqtt-server запущен.")
    else:
        print(f"  {YELLOW}⚠{NC}  Сервис не запустился — проверьте логи (пункт 5).")

    # 7. Сохраняем состояние
    proto_save_state(_MODULE_STATE, {
        "installed":     True,
        "main_password": main_pass,
        "data_port":     data_port,
        "web_port":      web_port,
        "web_user":      web_user,
        "web_pass":      web_pass,
        "dns":           dns,
    })

    # 8. Bulk sync VLESS users
    try:
        from chimera.modules.rest_api import _sync_all_from_vless
        from chimera.modules.users_manager import _unified_load_users
        _vless_users = _unified_load_users()
        if _vless_users:
            print(f"  {CYAN}→{NC}  Синхронизирую {len(_vless_users)} VLESS-юзеров в CSQTT...")
            _stats = _sync_all_from_vless(_vless_users)
    except Exception as _e:
        print(f"  {YELLOW}⚠{NC}  Sync VLESS-юзеров не удался: {_e}")

    # ── Итог ──────────────────────────────────────────────────────────────────
    server_ip = _get_server_ip()
    print()
    _box_top("✅  УСТАНОВКА ЗАВЕРШЕНА  •  CSQTT")
    _box_row()
    _box_ok("csqtt-server установлен и запущен.")
    _box_row()
    _box_kv("Data порт:",    f"{YELLOW}{data_port}/udp{NC}")
    _box_kv("Web Panel:",    f"{YELLOW}https://127.0.0.1:{web_port}{NC}")
    _box_kv("Web логин:",    f"{CYAN}{web_user}{NC}")
    _box_kv("Web пароль:",   f"{YELLOW}{web_pass}{NC}")
    _box_kv("Главный пароль:", f"{YELLOW}{main_pass}{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Быстрая ссылка для CSQTT:{NC}")
    _box_row()
    csqtt_link = _build_csqtt_v2_link(server_ip, data_port, main_pass)
    _box_link(csqtt_link)
    _box_row()
    _box_info("Web Panel доступна через SSH-туннель:")
    _box_row(f"  {DIM}ssh -L {web_port}:127.0.0.1:{web_port} root@{server_ip}{NC}")
    _box_row(f"  {DIM}→ https://localhost:{web_port}{NC}")
    _box_bot()
    link_path = _save_link_file(csqtt_link, "csqtt_link.txt")
    _print_link_file_path(link_path)
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  УПРАВЛЕНИЕ ПАРОЛЯМИ
# ══════════════════════════════════════════════════════════════════════════════
def _passwords_menu() -> None:
    while True:
        os.system("clear")
        data = _load_passwords()
        passwords = data.get("passwords", {})
        state = proto_load_state(_MODULE_STATE)
        server_ip = _get_server_ip()
        data_port = state.get("data_port", _DEFAULT_DATA_PORT)

        _box_top("🔑  УПРАВЛЕНИЕ ПАРОЛЯМИ  •  CSQTT")
        _box_row()
        _box_kv("Главный пароль:", f"{YELLOW}{data.get('main_password', '—')}{NC}")
        _box_kv("Временных паролей:", f"{YELLOW}{len(passwords)}{NC}")
        _box_row(); _box_sep()

        active_list = []
        for pw, entry in passwords.items():
            if not entry:
                continue
            expires = entry.get("expires_at", 0)
            expired = expires > 0 and time.time() > expires
            active_list.append((pw, entry, expired))

        if active_list:
            _box_row(f"  {BOLD}{CYAN}{'Пароль':<18}{'Истекает':<14}{'Статус'}{NC}")
            _box_sep()
            for pw, entry, expired in active_list:
                exp = entry.get("expires_at", 0)
                if exp == 0:
                    exp_str = "бессрочный"
                else:
                    dt = datetime.fromtimestamp(exp)
                    exp_str = dt.strftime("%d.%m.%Y")
                deact = entry.get("is_deactivated", False)
                if deact:
                    status = f"{RED}отключён{NC}"
                elif expired:
                    status = f"{YELLOW}истёк{NC}"
                else:
                    status = f"{GREEN}активен{NC}"
                pw_short = pw[:16]
                _box_row(f"  {CYAN}{pw_short:<18}{NC}{DIM}{exp_str:<14}{NC}{status}")
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
            try: _create_password()
            except _Cancelled: pass
        elif ch == "2":
            try: _show_password_link(passwords, server_ip, data_port)
            except _Cancelled: pass
        elif ch == "3":
            try: _delete_password(passwords)
            except _Cancelled: pass
        elif ch in ("q", ""):
            break

def _create_password() -> None:
    os.system("clear")
    _box_top("➕  СОЗДАТЬ ПАРОЛЬ  •  CSQTT")
    _box_row()
    _box_info("Временный пароль для передачи пользователю.")
    _box_row()
    _box_bot(); print()

    try:
        raw_days = proto_ask(f"  {CYAN}Дней действия (1-365, Enter=30): {NC}",
                             default="30", c=True)
        days = int(raw_days) if raw_days.isdigit() else 30
        days = max(1, min(365, days))
    except _Cancelled:
        raise

    data = _load_passwords()
    passwords = data.get("passwords", {})

    new_pass = proto_gen_password()
    expires_at = int((datetime.now() + timedelta(days=days)).timestamp())

    passwords[new_pass] = {
        "device_ids":    [],
        "max_devices":   1,
        "expires_at":    expires_at,
        "down_bytes":    0,
        "up_bytes":      0,
        "is_deactivated": False,
    }
    data["passwords"] = passwords
    _save_passwords(data)
    _hot_reload()

    state = proto_load_state(_MODULE_STATE)
    server_ip = _get_server_ip()
    data_port = state.get("data_port", _DEFAULT_DATA_PORT)

    print()
    _box_top("✅  ПАРОЛЬ СОЗДАН")
    _box_row()
    _box_kv("Пароль:",   f"{YELLOW}{new_pass}{NC}")
    _box_kv("Действует:", f"{days} дн. до {datetime.fromtimestamp(expires_at).strftime('%d.%m.%Y')}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Ссылка csqtt:// для клиента:{NC}")
    _box_bot()
    link = _build_csqtt_v2_link(server_ip, data_port, new_pass)
    print()
    _box_link(link)
    print()
    link_path = _save_link_file(link, f"link_{new_pass[:8]}.txt")
    _print_link_file_path(link_path)
    _pause()

def _show_password_link(passwords: dict, server_ip: str, data_port: int) -> None:
    if not passwords:
        print(f"  {YELLOW}⚠{NC}  Паролей нет."); _pause(); return

    os.system("clear")
    _box_top("🔗  ССЫЛКА ДЛЯ ПАРОЛЯ  •  CSQTT")
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

    link = _build_csqtt_v2_link(server_ip, data_port, pw)
    print()
    _box_top("🔗  ССЫЛКА ДЛЯ КЛИЕНТА")
    _box_row()
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
    _box_top("🗑️  УДАЛИТЬ ПАРОЛЬ  •  CSQTT")
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
        confirm = proto_ask(f"  {YELLOW}Удалить пароль {pw[:12]}...? [y/N]: {NC}",
                            default="n", c=True).strip().lower()
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
    _box_top("📊  СТАТУС  •  CSQTT")
    _box_row()

    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    svc_ok = r.stdout.strip() == "active"
    _box_kv("Сервис:",
            f"{GREEN}● активен{NC}" if svc_ok else f"{RED}● остановлен{NC}")
    _box_kv("Бинарник:",
            f"{GREEN}✓{NC}" if _BIN_PATH.exists() else f"{RED}✗ не найден{NC}")
    _box_kv("Data порт:", str(state.get("data_port", "—")))
    _box_kv("Web Panel:", f"https://127.0.0.1:{state.get('web_port', '—')}")
    _box_row()

    data = _load_passwords()
    passwords = data.get("passwords", {})
    _box_kv("Паролей:", str(len(passwords)))
    _box_row()

    # nginx front status
    ng = _csqtt_nginx_status()
    ng_url = _csqtt_nginx_get_url()
    if ng.get("enabled"):
        _box_kv("Web Panel (TLS):", f"{GREEN}{ng_url}{NC}")
    _box_row(); _box_sep()
    _box_row(f"  {BOLD}{WHITE}Последние 30 строк журнала:{NC}")
    _box_bot()

    r2 = subprocess.run(
        ["journalctl", "-u", _SERVICE_NAME, "-n", "30",
         "--no-pager", "--output=short-monotonic"],
        capture_output=True, encoding="utf-8", errors="replace",
        env={**os.environ, "LANG": "C.UTF-8"},
    )
    max_w = _BOX_W + 12
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
    print(f"  {DIM}Полные логи:{NC}")
    print(f"    {CYAN}journalctl -u csqtt -f{NC}  {DIM}(live режим){NC}")
    print(f"    {CYAN}journalctl -u csqtt -n 100 --no-pager{NC}  {DIM}(последние 100){NC}")
    print()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ПОЛНОЕ УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _full_uninstall(silent: bool = False) -> bool:
    if not silent:
        os.system("clear")
        _box_top("🗑️  УДАЛЕНИЕ  •  CSQTT")
        _box_row()
        _box_warn("Будет удалено:")
        _box_row(f"  {DIM}  • Сервис systemd  (csqtt){NC}")
        _box_row(f"  {DIM}  • Бинарник        ({_BIN_PATH}){NC}")
        _box_row(f"  {DIM}  • Конфиги          ({_CFG_DIR}){NC}")
        _box_row(f"  {DIM}  • iptables UDP и MASQUERADE{NC}")
        _box_row(f"  {DIM}  • nginx front (если включён){NC}")
        _box_row(f"  {DIM}  • /var/lib/xray-installer/csqtt.json{NC}")
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
    data_port = state.get("data_port", _DEFAULT_DATA_PORT)

    # Удаляем nginx front если включён
    try:
        _csqtt_nginx_remove()
    except Exception:
        pass

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

    _ipt_close_udp(data_port)
    _ipt_close_tcp(state.get("web_port", _DEFAULT_WEB_PORT))
    _ipt_remove_masquerade()
    proto_ipt_persist()

    sysctl = Path("/etc/sysctl.d/99-csqtt.conf")
    if sysctl.exists():
        sysctl.unlink()

    try:
        if _MODULE_STATE.exists():
            _MODULE_STATE.unlink()
    except Exception:
        pass

    if not silent:
        print(f"  {GREEN}✓{NC}  CSQTT удалён.")
        _pause()
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  ГАЙД
# ══════════════════════════════════════════════════════════════════════════════
def _show_guide() -> None:
    while True:
        os.system("clear")
        _box_top("📖  ГАЙД  •  CSQTT")
        _box_row()
        _box_item("1", "📱 Скачать приложение CSQTT на Android")
        _box_item("2", "🔗 Подключиться по ссылке csqtt://")
        _box_item("3", "🌐 Web Panel — доступ через браузер")
        _box_item("4", "⚖️ Отличия от qWDTT")
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
            _guide_connect()
        elif ch == "3":
            _guide_webpanel()
        elif ch == "4":
            _guide_diff()
        elif ch in ("q", ""):
            break

def _guide_install() -> None:
    os.system("clear")
    _box_top("📱  СКАЧАТЬ CSQTT")
    _box_row()
    _box_info("CSQTT — туннель поверх TURN/RTP (маскировка под звонок).")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Android (APK):{NC}")
    _box_row()
    _box_info("Скачайте APK с официального GitHub:")
    _box_row(f"  {YELLOW}github.com/amurcanov/csqtt/releases{NC}")
    _box_row()
    _box_info("Доступны: arm64-v8a, armeabi-v7a, universal APK.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Требования:{NC}")
    _box_row()
    _box_info("Android 8.0+ (API 26)")
    _box_info("Архитектуры: arm64-v8a, armeabi-v7a")
    _box_bot()
    _pause()

def _guide_connect() -> None:
    os.system("clear")
    _box_top("🔗  ПОДКЛЮЧЕНИЕ ПО csqtt://")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Формат ссылки (v2):{NC}")
    _box_row()
    _box_row(f"  {CYAN}csqtt://connect?v=2&host=IP&peer=PORT&password=ПАРОЛЬ{NC}")
    _box_row()
    _box_row(f"  {DIM}  v=2          — версия формата (фиксировано){NC}")
    _box_row(f"  {DIM}  host=        — IP или домен сервера{NC}")
    _box_row(f"  {DIM}  peer=        — порт data-plane (46000 по умолчанию){NC}")
    _box_row(f"  {DIM}  password=    — пароль юзера или главный пароль{NC}")
    _box_row(f"  {DIM}  hashes=      — (опционально) VK-хеши через запятую{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Как импортировать:{NC}")
    _box_row()
    _box_info("1. Скопируйте ссылку из пункта [3] главного меню CSQTT")
    _box_info("2. В приложении CSQTT → «+» → вставьте ссылку")
    _box_info("3. Нажмите «Подключить»")
    _box_bot()
    _pause()

def _guide_webpanel() -> None:
    os.system("clear")
    state = proto_load_state(_MODULE_STATE)
    web_port = state.get("web_port", _DEFAULT_WEB_PORT)
    server_ip = _get_server_ip()
    ng_url = _csqtt_nginx_get_url()

    _box_top("🌐  WEB PANEL  •  CSQTT")
    _box_row()
    _box_info("Web Panel — встроенная HTTPS панель управления сервером.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Способ 1: SSH-туннель (безопасно){NC}")
    _box_row()
    _box_row(f"  {DIM}ssh -L {web_port}:127.0.0.1:{web_port} root@{server_ip}{NC}")
    _box_row(f"  {DIM}→ https://localhost:{web_port}{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Способ 2: nginx front (прямой доступ){NC}")
    _box_row()
    if ng_url:
        _box_ok(f"nginx front включён: {ng_url}")
    else:
        _box_info("nginx front не включён. Включите через пункт [9] в меню.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Возможности Web Panel:{NC}")
    _box_row()
    _box_info("• Статистика (трафик, CPU, соединения)")
    _box_info("• Управление клиентами и паролями")
    _box_info("• Логи в реальном времени")
    _box_info("• Настройки сервера")
    _box_info("• Профили локального SOCKS5 прокси")
    _box_bot()
    _pause()

def _guide_diff() -> None:
    os.system("clear")
    _box_top("⚖️  CSQTT vs qWDTT")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}qWDTT{NC}")
    _box_row()
    _box_info("Протокол: WireGuard over TURN")
    _box_info("Сервер: Go")
    _box_info("Маскировка: DTLS (зависит от TURN ВК)")
    _box_info("Web Panel: нет (только Telegram-бот)")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}CSQTT{NC}")
    _box_row()
    _box_info("Протокол: RTP/AEAD over TURN")
    _box_info("Сервер: Rust (io_uring, высокопроизводительный)")
    _box_info("Маскировка: RTP (медиа-трафик звонка)")
    _box_info("Web Panel: встроенная HTTPS панель")
    _box_info("Туннель: TUN + NAT (не WireGuard)")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Когда что выбрать:{NC}")
    _box_row()
    _box_info("qWDTT → нужен Telegram-бот, привычный WG")
    _box_info("CSQTT → нужна Web Panel, макс. производительность")
    _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ МОДУЛЯ
# ══════════════════════════════════════════════════════════════════════════════
def do_csqtt_menu() -> None:
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

        _box_top("CSQTT  •  RTP/TURN Tunnel")
        _box_row()
        _box_kv("Статус:", svc_str)

        if installed:
            data = _load_passwords()
            pw_count = len(data.get("passwords", {}))
            _box_kv("Data порт:",   str(state.get("data_port", "—")))
            _box_kv("Web Panel:",   f"https://127.0.0.1:{state.get('web_port', '—')}")
            _box_kv("Паролей:",     str(pw_count))
            # nginx front status
            ng_url = _csqtt_nginx_get_url()
            if ng_url:
                _box_kv("Web (TLS):", f"{GREEN}{ng_url}{NC}")

        _box_row(); _box_sep()

        if not installed:
            _box_item("1", "🚀  Установить CSQTT")
        else:
            _box_item("1", "🚀  Переустановить")
            _box_item("2", "🔑  Управление паролями")
            _box_item("3", "🔗  Показать ссылку (главный пароль)")
            _box_item("4", "🔄  Перезапустить сервис")
            _box_item("5", "📊  Статус / логи")
            _box_item("6", "🌐  Web UI (SSH-туннель инструкция)")
            # nginx front
            ng_st = _csqtt_nginx_status()
            if ng_st.get("enabled"):
                ng_url = _csqtt_nginx_get_url()
                _box_item("7", f"🌐 nginx front (TLS) — {YELLOW}выключить{NC}  {DIM}({ng_url}){NC}")
            else:
                _box_item("7", f"🌐 nginx front (TLS) — {DIM}включить прямой доступ к Web Panel по HTTPS{NC}")
            _box_sep()
            _box_item("8", f"{RED}🗑️   Удалить CSQTT{NC}")

        _box_sep()
        _box_item("G", "📖  Гайд: установка, подключение, Web Panel")
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
            try: _passwords_menu()
            except _Cancelled: pass

        elif ch == "3" and installed:
            os.system("clear")
            state = proto_load_state(_MODULE_STATE)
            server_ip = _get_server_ip()
            data_port = state.get("data_port", _DEFAULT_DATA_PORT)
            main_pass = state.get("main_password", "")
            # v58: guard — ссылка с ПУСТЫМ паролем (битый/усечённый state.json)
            # нерабоча и вводит в заблуждение; показываем ошибку вместо битой ссылки.
            if not main_pass:
                _box_top("🔗  ССЫЛКА  •  ГЛАВНЫЙ ПАРОЛЬ")
                _box_row()
                _box_bot()
                print()
                _box_warn("main_password отсутствует в state.json — ссылка не "
                          "может быть построена. Восстановите state.json из "
                          "бэкапа или переустановите модуль (пароль будет "
                          "переиспользован из конфига, если он цел).")
                print()
                _pause()
                continue
            _box_top("🔗  ССЫЛКА  •  ГЛАВНЫЙ ПАРОЛЬ")
            _box_row()
            _box_bot()
            link = _build_csqtt_v2_link(server_ip, data_port, main_pass)
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

        elif ch == "6" and installed:
            _guide_webpanel()

        elif ch == "7" and installed:
            # nginx front
            ng_st = _csqtt_nginx_status()
            if ng_st.get("enabled"):
                # Выключение
                os.system("clear")
                _box_top("🌐  NGINX FRONT ДЛЯ CSQTT — ВЫКЛЮЧЕНИЕ")
                _box_row()
                _box_row(f"  {DIM}Будет удалён nginx vhost + закрыт порт {ng_st.get('port', _DEFAULT_NGINX_PORT)}.{NC}")
                _box_row(f"  {DIM}Доступ к Web Panel вернётся на SSH-туннель.{NC}")
                _box_row()
                _box_item("Q", "← Назад")
                _box_bot()
                confirm = input(f"  {YELLOW}Выключить nginx front? [y/N]:{NC} ").strip().lower()
                if confirm == "y":
                    ok, msg = _csqtt_nginx_remove()
                    if ok:
                        print(f"  {GREEN}✓{NC}  {msg}")
                    else:
                        print(f"  {RED}✗{NC}  {msg}")
                else:
                    print(f"  {DIM}Отменено.{NC}")
                _pause()
            else:
                # Включение
                state = proto_load_state(_MODULE_STATE)
                os.system("clear")
                _box_top("🌐  NGINX FRONT ДЛЯ CSQTT — ВКЛЮЧЕНИЕ")
                _box_row()
                _box_row(f"  {DIM}nginx front ставит TLS перед Web Panel CSQTT.{NC}")
                _box_row(f"  {DIM}Доступ через браузер по HTTPS (домен или IP).{NC}")
                _box_row()
                # Спрашиваем порт
                try:
                    port_str = input(f"  Порт для nginx front [Enter={_DEFAULT_NGINX_PORT}]: ").strip()
                    ng_port = int(port_str) if port_str else _DEFAULT_NGINX_PORT
                except (ValueError, EOFError, KeyboardInterrupt):
                    ng_port = _DEFAULT_NGINX_PORT
                # Спрашиваем режим TLS
                try:
                    from chimera.modules.panel_nginx_front import ask_tls_mode, ask_domain
                except ImportError:
                    print(f"  {RED}✗{NC}  panel_nginx_front недоступен.")
                    _pause()
                    continue
                use_self_signed, _ = ask_tls_mode("CSQTT Web Panel")
                domain = None
                if not use_self_signed:
                    try:
                        core = None
                        try:
                            from chimera import _core
                            core = _core
                        except Exception:
                            pass
                        if core and not getattr(core, "PARAM_DOMAIN", ""):
                            if hasattr(core, "_load_state_into_globals"):
                                core._load_state_into_globals()
                        domain = ask_domain(default=getattr(core, "PARAM_DOMAIN", ""))
                    except Exception:
                        domain = ask_domain(default="")
                    if not domain:
                        print(f"  {YELLOW}⚠{NC}  Домен не указан — отмена. Используйте self-signed режим.")
                        _pause()
                        continue
                ok, msg = _csqtt_nginx_install(ng_port, use_self_signed, domain)
                if ok:
                    print(f"  {GREEN}✓{NC}  nginx front включён на порту {ng_port}.")
                    url = _csqtt_nginx_get_url()
                    if url:
                        print(f"  {CYAN}→{NC}  Web Panel доступен: {url}")
                else:
                    print(f"  {RED}✗{NC}  Не удалось установить nginx front: {msg}")
                _pause()

        elif ch == "8" and installed:
            try: _full_uninstall(silent=False)
            except _Cancelled: print(f"  {DIM}Отменено.{NC}"); _pause()

        elif ch == "g":
            try: _show_guide()
            except _Cancelled: pass

        elif ch in ("q", ""):
            break

# ══════════════════════════════════════════════════════════════════════════════
#  АВТОНОМНЫЙ ЗАПУСК (отладка)
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}"); sys.exit(1)
    try:
        do_csqtt_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}"); sys.exit(0)
