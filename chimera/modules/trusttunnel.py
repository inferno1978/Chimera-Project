"""
chimera/modules/trusttunnel.py
───────────────────────────────────────────────────────────────────────────────
TrustTunnel — референсная реализация протокола AdGuard VPN (HTTP/2+HTTP/3
поверх TLS). Апстрим: github.com/TrustTunnel/TrustTunnel (Rust, Apache 2.0,
open-source с января 2026).

Как это работает (в отличие от VLESS/REALITY — не подмена сертификата, а
HTTP/2-CONNECT-туннель с мультиплексированием TCP/UDP/ICMP поверх TLS):
  Клиент (TrustTunnel Flutter Client)
    │  HTTP/2 CONNECT (HTTP/3 over QUIC — резерв) поверх TLS
    │  Basic auth: base64(username:password) в proxy-authorization
    ▼
  trusttunnel_endpoint :8443  (TCP HTTP/2 + UDP HTTP/3 на одном порту)
    │  NAT/MASQUERADE на исходящий интерфейс сервера
    ▼
  Интернет

Установка — БЕЗ сборки из исходников: сервер ставится из официального
prebuilt-релиза (trusttunnel-v<ver>-linux-<arch>.tar.gz, GitHub Releases),
бинарники GPG-подписаны ключом AdGuard 28645AC9776EC4C00BCE2AFC0FE641E7235E2EC6.
Конфиг генерируется штатным `setup_wizard -m non-interactive` (апстримовский
генератор), дальше — свой systemd-юнит + credentials.toml, как и с остальными
протоколами в этом инсталляторе.

⚠️  ВАЖНО — апстрим НЕ поддерживает hot-reload credentials.toml:
  SIGHUP перезагружает ТОЛЬКО hosts.toml (TLS-хосты/сертификаты). Смена
  пользователей (add/remove/block/unblock) требует `systemctl restart
  trusttunnel`, что рвёт ВСЕ активные соединения ~на 1 секунду — не только
  у изменяемого юзера. Этот модуль компенсирует это через batch_context()
  в user_lifecycle.py: массовые cron-операции (TTL/лимиты) батчатся в один
  рестарт за проход. Ручное добавление через TUI/бота рестартует сразу —
  это задокументированное поведение (см. TROUBLESHOOTING.md).

⚠️  ВАЖНО — апстрим /metrics НЕ отдаёт per-user лейбл:
  Prometheus-endpoint на 127.0.0.1:1987 отдаёт счётчики только с лейблом
  protocol_type (http1/http2/http3), без username. Per-user биллинг
  потребовал бы патчить lib/src/metrics.rs и собирать из исходников, теряя
  GPG-верификацию. В текущей реализации трафик записывается агрегированно
  под синтетическим user_id "_aggregate" — аналогично FPTN/Hysteria2.

Пользователи и аутентификация:
  Ведутся в /opt/trusttunnel/credentials.toml (TOML, массив [[client]] с
  username + password + опционально max_http2_conns/max_http3_conns).
  Username = email пользователя (канонический ID проекта), password =
  SHA-256("trusttunnel-pass|" + uuid) — детерминированный, стабильный при
  переустановках.

Токен клиента — deep-link вида tt://?<base64url>, генерируется на чистом
Python (без вызова 17-МБ бинарника на каждый запрос бота):
  tt://?<base64url-no-padding TLV-payload>
  TLV: varint(tag) || varint(len) || value, varint = RFC 9000 §16 QUIC varint
  Теги: 0x01 hostname, 0x02 addresses (host:port), 0x05 username, 0x06
  password, 0x08 certificate (DER, только для self-signed), 0x09
  upstream_protocol (1=http2, 2=http3), 0x0C name, 0x0D dns_upstreams.

Что модуль делает:
  • Скачивает и распаковывает официальный prebuilt-релиз (GPG-верификация)
  • Получает Let's Encrypt сертификат через существующий ssl_certbot
  • Запускает setup_wizard --cert-type provided --cert-chain-path ...
  • Пишет systemd-юнит + ExecReload (для SIGHUP-reload при renew сертификата)
  • Устанавливает certbot deploy-hook (systemctl reload trusttunnel)
  • Устанавливает cron: --trusttunnel-health + --trusttunnel-stats (5 мин)
  • Открывает порт 8443/tcp + 8443/udp в UFW (или iptables fallback)
  • Управление пользователями через правку credentials.toml + restart
  • Генерация tt:// deep-link + QR для каждого пользователя
  • Статус/логи сервиса

Что модуль НЕ трогает:
  • Xray config.json и VLESS-inbound
  • state.json инсталлятора (только свой /var/lib/xray-installer/trusttunnel.json)
  • iptables-правила других модулей
  • nginx-конфиги других протоколов

Точка входа из _core.py:
    from chimera.modules.trusttunnel import do_trusttunnel_menu
    do_trusttunnel_menu()
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from chimera.modules.text_width import wlen as _wlen, plain as _plain

import base64
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union, List, Dict, Tuple

from chimera.modules.proto_common import (
    ProtoCancelled, proto_load_state, proto_save_state,
    proto_ask, proto_ipt_persist,
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
_STATE_FILE = Path("/var/lib/xray-installer/trusttunnel.json")
_INSTALL_DIR  = Path("/opt/trusttunnel")
_BINARY_PATH  = _INSTALL_DIR / "trusttunnel_endpoint"
_WIZARD_PATH  = _INSTALL_DIR / "setup_wizard"
_VPN_TOML     = _INSTALL_DIR / "vpn.toml"
_HOSTS_TOML   = _INSTALL_DIR / "hosts.toml"
_CREDS_TOML   = _INSTALL_DIR / "credentials.toml"
_RULES_TOML   = _INSTALL_DIR / "rules.toml"
_SERVICE_FILE = Path("/etc/systemd/system/trusttunnel.service")
_SERVICE_NAME = "trusttunnel"

# Cron — health check + traffic stats. Pattern follows hysteria2_watchdog.py
# (_CRON_FILE + _SCRIPT_FILE, install/remove pair, 5-min interval matches
# traffic-check conventions).
_CRON_FILE         = Path("/etc/cron.d/trusttunnel")
_SCRIPT_FILE       = Path("/usr/local/bin/trusttunnel_cron.sh")
_PROJECT_ROOT      = Path("/opt/chimera")  # bootstrap.sh installs here
_CRON_INTERVAL_MIN = 5

_DEFAULT_PORT = 8443
_METRICS_PORT = 1987
_GPG_KEY_ID   = "28645AC9776EC4C00BCE2AFC0FE641E7235E2EC6"
_GPG_KEY_SERVER = "keys.openpgp.org"
_VERSION_PIN  = "1.0.33"   # latest public release as of Phase 0
_BOX_W        = 66

# Backwards-compat aliases (other modules import these names directly).
_SYSTEMD_UNIT    = _SERVICE_FILE

_LOG_FILE = Path("/var/log/xray-trusttunnel.log")

# Deep-link TLV tags (upstream deeplink/src/types.rs).
_TT_VERSION = 1

# ══════════════════════════════════════════════════════════════════════════════
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py) — для логирования и port-registry
# ══════════════════════════════════════════════════════════════════════════════
def _core_module():
    """Возвращает модуль chimera._core (lazy import)."""
    import importlib
    return importlib.import_module("chimera._core")

# ══════════════════════════════════════════════════════════════════════════════
#  ЛОГИРОВАНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _log(level: str, msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [TRUSTTUNNEL] [{level}] {msg}"
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            f.write(line + "\n")
    except Exception:
        pass
    try:
        core = _core_module()
        if hasattr(core, "log_to_file"):
            core.log_to_file(level, f"trusttunnel: {msg}")
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ (самодостаточно, без общих модулей — как naiveproxy.py/mieru.py)
# ══════════════════════════════════════════════════════════════════════════════
def _box_top(title: str = "") -> None:
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    if title:
        pad = _BOX_W - _wlen(title); lpad = pad // 2; rpad = pad - lpad
        print(f"{CYAN}║{NC}{' ' * lpad}{BOLD}{WHITE}{title}{NC}{' ' * rpad}{CYAN}║{NC}")
        print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")

def _box_sep() -> None: print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")
def _box_bot() -> None: print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")

def _box_row(text: str = "") -> None:
    w = _wlen(text)
    if w > _BOX_W:
        acc, plain = 0, _plain(text); cut = 0
        for i, ch in enumerate(plain):
            import unicodedata as _ud
            acc += 2 if _ud.east_asian_width(ch) in ('W', 'F') else 1
            if acc > _BOX_W - 1: cut = i; break
        text = text[:cut] + "…"; w = _wlen(text)
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

def _box_log_line(line: str, indent: str = "  ") -> None:
    avail_1 = _BOX_W - _wlen(indent)
    cont_indent = indent + "↳ "
    avail_2 = _BOX_W - _wlen(cont_indent)
    if _wlen(line) <= avail_1:
        _box_row(f"{indent}{DIM}{line}{NC}")
        return
    first_part = line[:avail_1]
    rest       = line[avail_1:]
    if _wlen(rest) > avail_2:
        rest = rest[:max(0, avail_2 - 1)] + "…"
    _box_row(f"{indent}{DIM}{first_part}{NC}")
    _box_row(f"{cont_indent}{DIM}{rest}{NC}")

def _box_link(link: str, color: str = "") -> None:
    color = color or YELLOW
    max_w = _BOX_W - 2
    plain_link = _plain(link)
    i = 0
    while i < len(plain_link):
        chunk = plain_link[i:i + max_w]
        pad = max(0, _BOX_W - 2 - _wlen(chunk))
        print(f"{CYAN}║{NC}  {color}{chunk}{NC}{' ' * pad}{CYAN}║{NC}")
        i += max_w

def _print_qr(data: str, label: str = "") -> None:
    if not shutil.which("qrencode"):
        print(f"  {YELLOW}⚠{NC}  qrencode не установлен: apt install qrencode")
        return
    if label:
        print(f"  {CYAN}→{NC}  QR: {YELLOW}{label}{NC}")
    print()
    try:
        subprocess.run(["qrencode", "-t", "UTF8", "-m", "1", data], check=True)
    except Exception as e:
        print(f"  {RED}✗{NC}  QR ошибка: {e}")
    print()

# ══════════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ
# ══════════════════════════════════════════════════════════════════════════════
def _pause() -> None:
    try:
        print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True); input()
    except (KeyboardInterrupt, EOFError, UnicodeDecodeError):
        print()

def _run(cmd: list, capture: bool = False, check: bool = False,
         cwd: Optional[str] = None, input_text: Optional[str] = None,
         timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if cwd: kw["cwd"] = cwd
    if timeout: kw["timeout"] = timeout
    if capture or input_text is not None:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if input_text is not None:
        kw["input"] = input_text
    try:
        return subprocess.run(cmd, **kw)
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(cmd, 124, stdout="", stderr=str(e))

def _get_server_ip() -> str:
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80)); return s.getsockname()[0]
    except Exception: pass
    try:
        import urllib.request
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            return r.read().decode().strip()
    except Exception: pass
    return "ВАШ_IP"

# ══════════════════════════════════════════════════════════════════════════════
#  СОСТОЯНИЕ МОДУЛЯ
# ══════════════════════════════════════════════════════════════════════════════
def _is_installed() -> bool:
    """TrustTunnel установлен: state + бинарник + systemd-юнит."""
    state = proto_load_state(_STATE_FILE)
    return bool(state.get("installed")) and _BINARY_PATH.exists()

# Public API (используется user_lifecycle.TrustTunnelAdapter, linkqr_lib,
# trusttunnel_health, trusttunnel_stats). Имена сохранены для обратной
# совместимости — НЕ переименовывать без синхронной правки вызывающих модулей.

def trusttunnel_load_state() -> dict:
    """Load /var/lib/xray-installer/trusttunnel.json. Returns {} if missing."""
    return proto_load_state(_STATE_FILE)

def trusttunnel_save_state(state: dict) -> None:
    """Atomic write to trusttunnel.json with chmod 0o600."""
    proto_save_state(_STATE_FILE, state)

def trusttunnel_is_installed() -> bool:
    """True if state['installed'] is True AND binary exists."""
    return _is_installed()

# ══════════════════════════════════════════════════════════════════════════════
#  CREDENTIALS.TOML — CRUD (формат подтверждён в Phase 0 sanity-check)
# ══════════════════════════════════════════════════════════════════════════════
# credentials.toml — TOML, массив [[client]] таблиц:
#   [[client]]
#   username = "alice@example.com"
#   password = "<64-char hex>"
#   max_http2_conns = 16    # optional
#   max_http3_conns = 2     # optional
#
# Минимальный TOML-парсер/сериализатор без зависимости от Python 3.11+ tomllib.

def _parse_credentials_toml(text: str) -> List[Dict]:
    """Минимальный TOML-парсер для формата credentials.toml.
    Handles [[client]] blocks with username/password (strings) and
    max_http2_conns/max_http3_conns (ints). НЕ поддерживает полный TOML spec.
    """
    clients: List[Dict] = []
    current: Optional[Dict] = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[[client]]":
            if current is not None:
                clients.append(current)
            current = {}
            continue
        if current is None:
            continue
        m = re.match(r'^(\w+)\s*=\s*(.+)$', line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        if val.startswith('"') and val.endswith('"'):
            current[key] = val[1:-1]
        elif val.startswith("'") and val.endswith("'"):
            current[key] = val[1:-1]
        elif val.isdigit():
            current[key] = int(val)
    if current is not None:
        clients.append(current)
    return clients

def _format_credentials_toml(clients: List[Dict]) -> str:
    """Сериализация списка client-словарей обратно в credentials.toml формат."""
    lines: List[str] = []
    for c in clients:
        lines.append("[[client]]")
        lines.append(f'username = "{c.get("username", "")}"')
        lines.append(f'password = "{c.get("password", "")}"')
        if "max_http2_conns" in c and c["max_http2_conns"] is not None:
            lines.append(f'max_http2_conns = {int(c["max_http2_conns"])}')
        if "max_http3_conns" in c and c["max_http3_conns"] is not None:
            lines.append(f'max_http3_conns = {int(c["max_http3_conns"])}')
        lines.append("")
    return "\n".join(lines).rstrip() + "\n" if lines else ""

def _atomic_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    """Atomic write via temp file + rename. Sets file mode."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    try:
        tmp.chmod(mode)
    except Exception:
        pass
    tmp.replace(path)

def trusttunnel_list_users() -> List[Dict]:
    """Read credentials.toml, return list of client dicts.
    Returns [] if file missing or TrustTunnel not installed.
    """
    if not _CREDS_TOML.exists():
        return []
    try:
        return _parse_credentials_toml(_CREDS_TOML.read_text())
    except Exception as e:
        _log("ERROR", f"list_users: cannot read {_CREDS_TOML}: {e}")
        return []

def trusttunnel_user_exists(username: str) -> bool:
    """Check if a [[client]] block with the given username exists."""
    if not username:
        return False
    for c in trusttunnel_list_users():
        if c.get("username") == username:
            return True
    return False

def trusttunnel_add_user(username: str,
                          password: str,
                          max_http2_conns: Optional[int] = None,
                          max_http3_conns: Optional[int] = None) -> bool:
    """Add or update a user in credentials.toml. Idempotent.

    Если [[client]] с тем же username уже существует — ОБНОВЛЯЕТ его password
    и connection limits in place, НЕ создаёт дубликат-блок.

    НЕ рестартует сервис — это ответственность caller'а (batched через
    user_lifecycle.batch_context()).
    """
    if not username or not password:
        _log("ERROR", f"add_user: username and password required (got username={username!r})")
        return False
    try:
        clients = trusttunnel_list_users()
        found = False
        for c in clients:
            if c.get("username") == username:
                c["password"] = password
                if max_http2_conns is not None:
                    c["max_http2_conns"] = max_http2_conns
                elif "max_http2_conns" in c:
                    del c["max_http2_conns"]
                if max_http3_conns is not None:
                    c["max_http3_conns"] = max_http3_conns
                elif "max_http3_conns" in c:
                    del c["max_http3_conns"]
                found = True
                _log("INFO", f"add_user: updated existing entry for {username!r}")
                break
        if not found:
            new_entry: Dict = {"username": username, "password": password}
            if max_http2_conns is not None:
                new_entry["max_http2_conns"] = max_http2_conns
            if max_http3_conns is not None:
                new_entry["max_http3_conns"] = max_http3_conns
            clients.append(new_entry)
            _log("INFO", f"add_user: added new entry for {username!r}")
        _atomic_write_text(_CREDS_TOML, _format_credentials_toml(clients), mode=0o600)
        return True
    except Exception as e:
        _log("ERROR", f"add_user: exception for {username!r}: {e}")
        return False

def trusttunnel_remove_user(username: str) -> bool:
    """Remove a [[client]] block by username. Idempotent (no-op if not found).
    НЕ рестартует сервис — ответственность caller'а.
    """
    if not username:
        return False
    try:
        clients = trusttunnel_list_users()
        new_clients = [c for c in clients if c.get("username") != username]
        if len(new_clients) == len(clients):
            _log("INFO", f"remove_user: {username!r} not found, noop")
            return True
        _atomic_write_text(_CREDS_TOML, _format_credentials_toml(new_clients), mode=0o600)
        _log("INFO", f"remove_user: removed {username!r}")
        return True
    except Exception as e:
        _log("ERROR", f"remove_user: exception for {username!r}: {e}")
        return False

def trusttunnel_update_user(username: str, **fields) -> bool:
    """Update specific fields (password, max_http2_conns, max_http3_conns) on
    an existing [[client]] block. Returns False if user not found.
    """
    if not username:
        return False
    try:
        clients = trusttunnel_list_users()
        found = False
        for c in clients:
            if c.get("username") == username:
                for k, v in fields.items():
                    if v is None:
                        c.pop(k, None)
                    else:
                        c[k] = v
                found = True
                break
        if not found:
            _log("WARN", f"update_user: {username!r} not found")
            return False
        _atomic_write_text(_CREDS_TOML, _format_credentials_toml(clients), mode=0o600)
        return True
    except Exception as e:
        _log("ERROR", f"update_user: exception for {username!r}: {e}")
        return False

# ══════════════════════════════════════════════════════════════════════════════
#  ДЕТЕРМИНИРОВАННЫЙ ПАРОЛЬ (D8)
# ══════════════════════════════════════════════════════════════════════════════
def trusttunnel_derive_password(uuid_str: str) -> str:
    """Детерминированный per-user пароль = SHA-256("trusttunnel-pass|" + uuid).

    Стабилен при переустановках. Возвращает 64-символьную hex-строку.
    """
    if not uuid_str:
        raise ValueError("uuid is required to derive TrustTunnel password")
    return hashlib.sha256(b"trusttunnel-pass|" + uuid_str.encode("utf-8")).hexdigest()

# ══════════════════════════════════════════════════════════════════════════════
#  DEEP-LINK КОДЕК (чистый Python, upstream tt://?<base64url> TLV-формат)
# ══════════════════════════════════════════════════════════════════════════════
# TLV wire format (подтверждён в Phase 0 чтением deeplink/src/types.rs и
# декодированием реального deep-link'а через scripts/deeplink_to_config.py):
#   varint(Tag) || varint(Length) || Value[Length bytes]
#   varint = RFC 9000 §16 QUIC varint (2-bit length prefix, big-endian).
#
# Теги:
#   0x00 version, 0x01 hostname, 0x02 addresses (repeatable),
#   0x03 custom_sni, 0x04 has_ipv6, 0x05 username, 0x06 password,
#   0x07 skip_verification, 0x08 certificate (DER), 0x09 upstream_protocol,
#   0x0A anti_dpi, 0x0B client_random_prefix, 0x0C name, 0x0D dns_upstreams.

def _varint_encode(n: int) -> bytes:
    """RFC 9000 §16 QUIC varint encoding (2-bit length prefix, big-endian)."""
    if n < 0:
        raise ValueError("varint cannot be negative")
    if n < 64:
        return bytes([n])
    elif n < 16384:
        return bytes([0x40 | (n >> 8), n & 0xFF])
    elif n < 1073741824:
        return bytes([0x80 | (n >> 24), (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
    elif n < 4611686018427387904:
        return bytes([0xC0 | (n >> 56), (n >> 48) & 0xFF, (n >> 40) & 0xFF,
                      (n >> 32) & 0xFF, (n >> 24) & 0xFF, (n >> 16) & 0xFF,
                      (n >> 8) & 0xFF, n & 0xFF])
    else:
        raise ValueError("varint too large")

def _varint_decode(data: bytes, offset: int) -> Tuple[int, int]:
    """Decode a QUIC varint. Returns (value, new_offset)."""
    if offset >= len(data):
        raise ValueError("varint: unexpected end of data")
    first = data[offset]
    prefix = (first & 0xC0) >> 6
    if prefix == 0:
        return first & 0x3F, offset + 1
    elif prefix == 1:
        if offset + 1 >= len(data):
            raise ValueError("varint: truncated")
        return ((first & 0x3F) << 8) | data[offset + 1], offset + 2
    elif prefix == 2:
        if offset + 3 >= len(data):
            raise ValueError("varint: truncated")
        return (((first & 0x3F) << 24) | (data[offset+1] << 16) |
                (data[offset+2] << 8) | data[offset+3]), offset + 4
    else:
        if offset + 7 >= len(data):
            raise ValueError("varint: truncated")
        val = 0
        for i in range(8):
            if i == 0:
                val = (first & 0x3F) << (56 - i*8)
            else:
                val |= data[offset + i] << (56 - i*8)
        return val, offset + 8

def _tlv_encode(tag: int, value: bytes) -> bytes:
    """varint(tag) || varint(len) || value."""
    return _varint_encode(tag) + _varint_encode(len(value)) + value

def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def _b64url_decode_no_pad(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def trusttunnel_deeplink_encode(hostname: str,
                                addresses: List[str],
                                username: str,
                                password: str,
                                custom_sni: str = "",
                                has_ipv6: bool = True,
                                skip_verification: bool = False,
                                certificate_der: bytes = b"",
                                upstream_protocol: str = "http2",
                                anti_dpi: bool = False,
                                client_random_prefix: str = "",
                                name: str = "",
                                dns_upstreams: Optional[List[str]] = None) -> str:
    """Build a tt://?<base64url> deep-link URI (upstream TLV-формат).

    Pure-Python reimplementation of deeplink/src/encode.rs — позволяет
    linkqr_lib генерировать URI без спавна 17-МБ бинарника на каждый
    /config или /qr запрос бота.

    Для Let's Encrypt сертификатов (system-verifiable) certificate_der
    следует оставить пустым — апстрим опускает тег 0x08 в этом случае.
    """
    payload = b""
    payload += _tlv_encode(0x00, _varint_encode(_TT_VERSION))
    payload += _tlv_encode(0x01, hostname.encode("utf-8"))
    for addr in addresses:
        payload += _tlv_encode(0x02, addr.encode("utf-8"))
    if custom_sni:
        payload += _tlv_encode(0x03, custom_sni.encode("utf-8"))
    if not has_ipv6:
        payload += _tlv_encode(0x04, bytes([0]))
    payload += _tlv_encode(0x05, username.encode("utf-8"))
    payload += _tlv_encode(0x06, password.encode("utf-8"))
    if skip_verification:
        payload += _tlv_encode(0x07, bytes([1]))
    if certificate_der:
        payload += _tlv_encode(0x08, certificate_der)
    proto_val = 2 if upstream_protocol == "http3" else 1
    if proto_val != 1:
        payload += _tlv_encode(0x09, _varint_encode(proto_val))
    if anti_dpi:
        payload += _tlv_encode(0x0A, bytes([1]))
    if client_random_prefix:
        payload += _tlv_encode(0x0B, client_random_prefix.encode("utf-8"))
    if name:
        payload += _tlv_encode(0x0C, name.encode("utf-8"))
    if dns_upstreams:
        dns_blob = b""
        for dns in dns_upstreams:
            dns_bytes = dns.encode("utf-8")
            dns_blob += _varint_encode(len(dns_bytes)) + dns_bytes
        payload += _tlv_encode(0x0D, dns_blob)
    return "tt://?" + _b64url_no_pad(payload)

def trusttunnel_deeplink_decode(uri: str) -> Dict:
    """Decode a tt://?<base64url> URI into a dict of fields."""
    s = uri.strip()
    if s.startswith("tt://?"):
        s = s[len("tt://?"):]
    elif s.startswith("tt://"):
        s = s[len("tt://"):]
    else:
        raise ValueError(f"not a tt:// URI: {uri[:40]}...")
    data = _b64url_decode_no_pad(s)
    result: Dict = {
        "version": 0, "hostname": "", "addresses": [], "custom_sni": "",
        "has_ipv6": True, "username": "", "password": "",
        "skip_verification": False, "certificate_der": b"",
        "upstream_protocol": "http2", "anti_dpi": False,
        "client_random_prefix": "", "name": "", "dns_upstreams": [],
    }
    offset = 0
    while offset < len(data):
        tag, offset = _varint_decode(data, offset)
        length, offset = _varint_decode(data, offset)
        if offset + length > len(data):
            raise ValueError(f"TLV tag {tag}: length {length} exceeds remaining data")
        value = data[offset:offset + length]
        offset += length
        if tag == 0x00:
            v, _ = _varint_decode(value, 0); result["version"] = v
        elif tag == 0x01:
            result["hostname"] = value.decode("utf-8")
        elif tag == 0x02:
            result["addresses"].append(value.decode("utf-8"))
        elif tag == 0x03:
            result["custom_sni"] = value.decode("utf-8")
        elif tag == 0x04:
            result["has_ipv6"] = bool(value[0]) if value else False
        elif tag == 0x05:
            result["username"] = value.decode("utf-8")
        elif tag == 0x06:
            result["password"] = value.decode("utf-8")
        elif tag == 0x07:
            result["skip_verification"] = bool(value[0]) if value else False
        elif tag == 0x08:
            result["certificate_der"] = value
        elif tag == 0x09:
            v, _ = _varint_decode(value, 0)
            result["upstream_protocol"] = "http3" if v == 2 else "http2"
        elif tag == 0x0A:
            result["anti_dpi"] = bool(value[0]) if value else False
        elif tag == 0x0B:
            result["client_random_prefix"] = value.decode("utf-8")
        elif tag == 0x0C:
            result["name"] = value.decode("utf-8")
        elif tag == 0x0D:
            up = []; o = 0
            while o < len(value):
                slen, o = _varint_decode(value, o)
                if o + slen > len(value): break
                up.append(value[o:o+slen].decode("utf-8")); o += slen
            result["dns_upstreams"] = up
    return result

def trusttunnel_generate_deeplink(username: str,
                                  address: Optional[str] = None,
                                  state: Optional[dict] = None) -> str:
    """Generate deep-link вызовом endpoint-бинарника (ground truth path).

    Используется установщиком / status-экраном. Для высокочастотных
    /config /qr запросов бота — использовать trusttunnel_deeplink_for_user().

    Raises ValueError если пользователя нет в credentials.toml (D4:
    non-existent user protection — предотвращает Rust panic в бинарнике).
    """
    if not trusttunnel_user_exists(username):
        raise ValueError(
            f"TrustTunnel user {username!r} not found in credentials.toml — "
            f"refusing to invoke endpoint binary (would Rust panic)"
        )
    if state is None:
        state = trusttunnel_load_state()
    if not state.get("installed"):
        raise RuntimeError("TrustTunnel not installed")
    vpn_toml = state.get("vpn_toml", str(_VPN_TOML))
    hosts_toml = state.get("hosts_toml", str(_HOSTS_TOML))
    if not address:
        domain = state.get("domain", "")
        port = state.get("listen_port", _DEFAULT_PORT)
        address = f"{domain}:{port}" if domain else f"0.0.0.0:{port}"
    cmd = [str(_BINARY_PATH), vpn_toml, hosts_toml,
           "-c", username, "-a", address, "--format", "deeplink"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except Exception as e:
        raise RuntimeError(f"trusttunnel_endpoint invocation failed: {e}")
    if r.returncode != 0:
        raise RuntimeError(
            f"trusttunnel_endpoint exited {r.returncode}: {r.stderr.strip()[:200]}"
        )
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("tt://"):
            return line
    raise RuntimeError(f"no tt:// URI in endpoint output: {r.stdout[:200]}")

def trusttunnel_deeplink_for_user(email: str,
                                  uuid_str: str,
                                  state: Optional[dict] = None) -> str:
    """Pure-Python deep-link builder для linkqr_lib.

    Returns "" if TrustTunnel not installed or user not in credentials.toml.
    Для Let's Encrypt сертификатов certificate_der пустой — URI компактный.
    """
    if not email or not uuid_str:
        return ""
    if state is None:
        state = trusttunnel_load_state()
    if not state.get("installed"):
        return ""
    if not trusttunnel_user_exists(email):
        return ""
    password = trusttunnel_derive_password(uuid_str)
    hostname = state.get("domain", "")
    if not hostname:
        return ""
    port = state.get("listen_port", _DEFAULT_PORT)
    address = f"{hostname}:{port}"
    return trusttunnel_deeplink_encode(
        hostname=hostname, addresses=[address],
        username=email, password=password, upstream_protocol="http2",
    )

# ══════════════════════════════════════════════════════════════════════════════
#  СЕРВИС / CRON — управление
# ══════════════════════════════════════════════════════════════════════════════
def trusttunnel_restart_service() -> bool:
    """systemctl restart trusttunnel. Returns True on success."""
    r = _run(["systemctl", "restart", _SERVICE_NAME], capture=True, timeout=30)
    if r.returncode != 0:
        _log("ERROR", f"restart: systemctl failed: {r.stderr.strip()}")
        return False
    return True

def trusttunnel_reload_service() -> bool:
    """systemctl reload trusttunnel (SIGHUP — reloads hosts.toml only).
    Для cert renewal (D9): без рестарта, без разрыва активных сессий.
    """
    r = _run(["systemctl", "reload", _SERVICE_NAME], capture=True, timeout=10)
    if r.returncode != 0:
        _log("WARN", f"reload: systemctl failed: {r.stderr.strip()}")
        return False
    return True

def trusttunnel_service_active() -> bool:
    """systemctl is-active trusttunnel."""
    r = _run(["systemctl", "is-active", "--quiet", _SERVICE_NAME], timeout=5)
    return r.returncode == 0

# ── Cron ─────────────────────────────────────────────────────────────────────
# Pattern follows hysteria2_watchdog.py: /usr/local/bin wrapper + /etc/cron.d
# file. Две записи (health + stats) в одном файле, интервал 5 мин (как
# traffic-check). Используем wrapper-скрипт (не прямой вызов main.py в cron
# line) — так cron-файл короткий, и можно добавить PYTHONPATH/cwd в одном месте.

# Note: __MAIN_PY__ / __INTERVAL__ / __SCRIPT__ placeholders + .replace()
# вместо str.format() — bash-скрипт содержит ${1:-health}, которое .format()
# интерпретировал бы как positional arg.
_SCRIPT_TEMPLATE = """\
#!/bin/bash
# TrustTunnel cron wrapper — generated by Chimera Project
# Usage: trusttunnel_cron.sh {health|stats}
set -e
MODE="${1:-health}"
case "$MODE" in
    health)
        /usr/bin/python3 __MAIN_PY__ --trusttunnel-health 2>>/var/log/xray-trusttunnel.log
        ;;
    stats)
        /usr/bin/python3 __MAIN_PY__ --trusttunnel-stats 2>>/var/log/xray-trusttunnel.log
        ;;
    *)
        echo "Usage: $0 {health|stats}" >&2
        exit 1
        ;;
esac
"""

_CRON_TEMPLATE = """\
# TrustTunnel cron — Chimera Project
# Auto-generated; do not edit manually. Removed by trusttunnel_uninstall().
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

*/__INTERVAL__ * * * * root __SCRIPT__ health
*/__INTERVAL__ * * * * root __SCRIPT__ stats
"""

def _find_project_root() -> Path:
    """Найти корень проекта (где main.py).
    Пробует _PROJECT_ROOT, затем /opt/chimera, /opt/vless-installer,
    затем поднимается от расположения этого файла.
    """
    candidates = [
        _PROJECT_ROOT,
        Path("/opt/chimera"),
        Path("/opt/vless-installer"),
        Path(__file__).resolve().parent.parent.parent,
    ]
    for c in candidates:
        if (c / "main.py").exists():
            return c
    return _PROJECT_ROOT

def _install_cron() -> None:
    """Install cron jobs for --trusttunnel-health and --trusttunnel-stats.
    Creates /usr/local/bin/trusttunnel_cron.sh + /etc/cron.d/trusttunnel.
    Idempotent — перезаписывает существующие файлы.
    """
    project_root = _find_project_root()
    main_py = project_root / "main.py"
    if not main_py.exists():
        _log("WARN", f"_install_cron: main.py not found at {main_py}, cron will not work")
    script_text = _SCRIPT_TEMPLATE.replace("__MAIN_PY__", str(main_py))
    try:
        _SCRIPT_FILE.write_text(script_text)
        _SCRIPT_FILE.chmod(0o755)
    except Exception as e:
        _log("ERROR", f"_install_cron: cannot write {_SCRIPT_FILE}: {e}")
        return
    cron_text = (_CRON_TEMPLATE
                 .replace("__INTERVAL__", str(_CRON_INTERVAL_MIN))
                 .replace("__SCRIPT__", str(_SCRIPT_FILE)))
    try:
        _CRON_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CRON_FILE.write_text(cron_text)
        _CRON_FILE.chmod(0o644)
    except Exception as e:
        _log("ERROR", f"_install_cron: cannot write {_CRON_FILE}: {e}")
        return
    _log("INFO", f"_install_cron: installed {_CRON_FILE} (interval={_CRON_INTERVAL_MIN}min)")

def _remove_cron() -> None:
    """Remove cron jobs for TrustTunnel. Idempotent."""
    for f in (_CRON_FILE, _SCRIPT_FILE):
        if f.exists():
            try:
                f.unlink()
                _log("INFO", f"_remove_cron: removed {f}")
            except Exception as e:
                _log("WARN", f"_remove_cron: cannot remove {f}: {e}")

def trusttunnel_cron_installed() -> bool:
    """Check if the cron file is installed. Used by tests + status display."""
    return _CRON_FILE.exists() and _SCRIPT_FILE.exists()

# ══════════════════════════════════════════════════════════════════════════════
#  СЕРТИФИКАТ / ПОРТ / ДОМЕН — проверки
# ══════════════════════════════════════════════════════════════════════════════
def _check_domain_available(domain: str) -> str:
    """D7: проверка что домен не занят другим протоколом.
    Returns "" если свободен, строка с ошибкой если занят.
    """
    if not domain:
        return "домен обязателен"
    try:
        core = _core_module()
        vless_domain = getattr(core, "PARAM_DOMAIN", "")
        if vless_domain and vless_domain == domain:
            return f"домен {domain} уже используется VLESS (PARAM_DOMAIN)"
        for proto_file, proto_name in [
            ("/var/lib/xray-installer/naiveproxy.json", "NaiveProxy"),
            ("/var/lib/xray-installer/fptn.json", "FPTN"),
        ]:
            try:
                p = Path(proto_file)
                if p.exists():
                    st = json.loads(p.read_text())
                    if st.get("installed") and st.get("domain") == domain:
                        return f"домен {domain} уже используется {proto_name}"
            except Exception:
                pass
        telemt_toml = Path("/etc/telemt/telemt.toml")
        if telemt_toml.exists():
            try:
                text = telemt_toml.read_text()
                if f'"{domain}"' in text or f"'{domain}'" in text:
                    return f"домен {domain} уже используется MTProto/Telemt"
            except Exception:
                pass
    except Exception as e:
        _log("WARN", f"_check_domain_available: {e}")
    return ""

def _check_port_available(port: int) -> str:
    """D2: проверка что порт не занят другим протоколом.
    Returns "" если свободен, строка с ошибкой если занят.
    """
    try:
        core = _core_module()
        if hasattr(core, "check_port_used_by_other_protocol"):
            return core.check_port_used_by_other_protocol(port, exclude_module="trusttunnel")
    except Exception as e:
        _log("WARN", f"_check_port_available: {e}")
    return ""

def _ufw_is_active() -> bool:
    if not shutil.which("ufw"):
        return False
    r = _run(["ufw", "status"], capture=True)
    return "status: active" in (r.stdout or "").lower()

def _open_port(port: int) -> str:
    """Открыть TCP+UDP порт в ufw (или iptables fallback)."""
    if _ufw_is_active():
        for proto in ("tcp", "udp"):
            _run(["ufw", "allow", f"{port}/{proto}", "comment", "TRUSTTUNNEL"], capture=True)
        return f"UFW: TCP+UDP {port} открыты."
    try:
        for proto in ("tcp", "udp"):
            _run(["iptables", "-I", "INPUT", "1", "-p", proto,
                  "--dport", str(port), "-j", "ACCEPT"])
        proto_ipt_persist()
        return f"iptables: TCP+UDP {port} открыты."
    except Exception as e:
        _log("ERROR", f"_open_port: iptables failed: {e}")
        return f"ошибка: {e}"

def _close_port(port: int) -> None:
    """Закрыть TCP+UDP порт в ufw (или iptables fallback)."""
    if _ufw_is_active():
        for proto in ("tcp", "udp"):
            _run(["ufw", "delete", "allow", f"{port}/{proto}"], capture=True)
        return
    try:
        for proto in ("tcp", "udp"):
            _run(["iptables", "-D", "INPUT", "-p", proto,
                  "--dport", str(port), "-j", "ACCEPT"])
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════════
#  БИНАРНИКИ (prebuilt tarball → GPG verify → /opt/trusttunnel)
# ══════════════════════════════════════════════════════════════════════════════
def _download_and_install_binary() -> Tuple[bool, str]:
    """Скачать prebuilt TrustTunnel binaries через download_manager.
    Returns (success, version_or_errormsg).
    """
    try:
        from chimera.modules.download_manager import fetch_package
        from chimera.modules.trusttunnel_packages import TRUSTTUNNEL_SPEC
        ok = fetch_package(TRUSTTUNNEL_SPEC, tag=f"v{_VERSION_PIN}", dry_run=False)
        if not ok:
            return False, "fetch_package failed — см. лог выше для manual hint"
        if not _BINARY_PATH.exists():
            return False, f"бинарник не найден в {_BINARY_PATH} после fetch"
        _BINARY_PATH.chmod(0o755)
        if _WIZARD_PATH.exists():
            _WIZARD_PATH.chmod(0o755)
        try:
            r = _run([str(_BINARY_PATH), "--version"], capture=True, timeout=5)
            version = (r.stdout or "").strip() or _VERSION_PIN
        except Exception:
            version = _VERSION_PIN
        return True, version
    except Exception as e:
        return False, f"скачивание не удалось: {e}"

def _import_gpg_key() -> bool:
    """Импортировать AdGuard GPG key для верификации подписей бинарников."""
    try:
        r = _run(["gpg", "--keyserver", _GPG_KEY_SERVER,
                  "--recv-keys", _GPG_KEY_ID], capture=True, timeout=30)
        return r.returncode == 0
    except Exception as e:
        _log("WARN", f"_import_gpg_key: {e}")
        return False

def _verify_gpg_signature(binary_path: Path) -> bool:
    """Верифицировать GPG-подпись бинарника. Returns True если валидна."""
    sig_path = binary_path.with_suffix(binary_path.suffix + ".sig")
    if not sig_path.exists():
        _log("WARN", f"_verify_gpg_signature: no .sig file at {sig_path}")
        return False
    try:
        r = _run(["gpg", "--verify", str(sig_path), str(binary_path)],
                 capture=True, timeout=15)
        return r.returncode == 0
    except Exception as e:
        _log("WARN", f"_verify_gpg_signature: {e}")
        return False

# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEMD-ЮНИТ (D9: с ExecReload для SIGHUP-reload при cert renewal)
# ══════════════════════════════════════════════════════════════════════════════
_SYSTEMD_UNIT_TEMPLATE = """\
[Unit]
Description=TrustTunnel endpoint (Chimera Project)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={install_dir}
ExecStart={binary} vpn.toml hosts.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
StandardOutput=append:/var/log/trusttunnel-endpoint.log
StandardError=append:/var/log/trusttunnel-endpoint.log

[Install]
WantedBy=multi-user.target
"""

def _install_systemd_unit(install_dir: Path) -> None:
    """Написать systemd-юнит на основе template (D9: с ExecReload)."""
    unit_text = _SYSTEMD_UNIT_TEMPLATE.format(
        install_dir=install_dir, binary=_BINARY_PATH,
    )
    _SERVICE_FILE.write_text(unit_text)
    _run(["systemctl", "daemon-reload"], timeout=15)
    _run(["systemctl", "enable", _SERVICE_NAME], timeout=10)

def _remove_systemd_unit() -> None:
    """Stop, disable, remove systemd-юнит."""
    _run(["systemctl", "stop", _SERVICE_NAME], timeout=15)
    _run(["systemctl", "disable", _SERVICE_NAME], timeout=10)
    if _SERVICE_FILE.exists():
        try:
            _SERVICE_FILE.unlink()
        except Exception:
            pass
    _run(["systemctl", "daemon-reload"], timeout=15)

# ── Certbot deploy hook (D1: SIGHUP-reload при LE renewal, без рестарта) ─────
def _install_cert_renewal_hook() -> None:
    """Certbot deploy hook: systemctl reload trusttunnel при LE renewal.
    SIGHUP перезагружает hosts.toml (сертификаты) — без рестарта, без
    разрыва активных сессий.
    """
    hook_dir = Path("/etc/letsencrypt/renewal-hooks/deploy")
    try:
        hook_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        return
    hook_path = hook_dir / "trusttunnel-reload.sh"
    hook_path.write_text("#!/bin/sh\nsystemctl reload trusttunnel || true\n")
    try:
        hook_path.chmod(0o755)
    except Exception:
        pass

def _remove_cert_renewal_hook() -> None:
    """Убрать certbot deploy hook для TrustTunnel."""
    hook_path = Path("/etc/letsencrypt/renewal-hooks/deploy/trusttunnel-reload.sh")
    if hook_path.exists():
        try:
            hook_path.unlink()
        except Exception:
            pass

# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА
# ══════════════════════════════════════════════════════════════════════════════
def _run_install() -> None:
    try: _run_install_inner()
    except _Cancelled:
        print(f"\n  {YELLOW}Установка прервана.{NC}\n"); _pause()

def _run_install_inner() -> None:
    os.system("clear")
    _box_top("🔐  УСТАНОВКА  •  TRUSTTUNNEL")
    _box_row()

    reinstall_keep_users = False
    state = proto_load_state(_STATE_FILE)
    old_domain = state.get("domain", "")
    old_port = state.get("listen_port", _DEFAULT_PORT)

    if _is_installed():
        _box_warn("TrustTunnel уже установлен.")
        _box_row()
        _box_item("1", "Переустановить (сохранить пользователей и домен)")
        _box_item("2", f"Переустановить полностью  {YELLOW}(новый сертификат){NC}")
        _box_item("Q", "← Отмена")
        _box_bot(); print()
        try:
            ch = proto_ask(f"{CYAN}Выбор [1/2/Q]: {NC}", c=True).strip().lower()
        except _Cancelled: return
        if ch == "q" or not ch: return
        if ch == "1":
            reinstall_keep_users = True
        elif ch == "2":
            _full_uninstall(silent=True)
        else:
            return

    os.system("clear")
    _box_top("🔐  НАСТРОЙКА  •  TRUSTTUNNEL")
    _box_row()
    _box_info("TrustTunnel — референсная реализация протокола AdGuard VPN")
    _box_info("(HTTP/2+HTTP/3 поверх TLS). Официальный upstream-бинарник,")
    _box_info("GPG-подписан ключом AdGuard. НЕ форк и НЕ реимплементация.")
    _box_row()
    _box_warn("Смена пользователей требует рестарта сервиса (~1 c разрыв")
    _box_warn("ВСЕХ активных соединений). Массовые cron-операции батчатся.")
    _box_row()
    _box_warn("Per-user биллинг НЕ поддерживается — только агрегированный")
    _box_warn("трафик (апстрим /metrics не отдаёт per-user лейбл).")
    _box_bot(); print()

    try:
        while True:
            domain = proto_ask(
                f"  {CYAN}Домен (например tt.example.com){' [' + old_domain + ']' if old_domain else ''}: {NC}",
                default=old_domain, c=True,
            ).strip()
            if not domain:
                _box_warn("Домен обязателен."); continue
            err = _check_domain_available(domain)
            if err:
                _box_warn(err); continue
            break

        while True:
            raw_port = proto_ask(
                f"  {CYAN}Порт [Enter={_DEFAULT_PORT}]: {NC}",
                default=str(_DEFAULT_PORT), c=True,
            ).strip()
            port = int(raw_port) if raw_port.isdigit() else _DEFAULT_PORT
            err = _check_port_available(port)
            if err:
                _box_warn(f"Порт {port} занят: {err}"); continue
            break

        # v4.24: спрашиваем email первого пользователя (был хардкод 'admin').
        # Email — это Имя пользователя в TrustTunnel (username == email).
        # Пароль детерминированно выводится из UUID (через
        # trusttunnel_derive_password). Если у юзера нет UUID — генерируем
        # случайный (только для первого admin, потом можно привязать через
        # identity_map в подписке).
        while True:
            admin_email = proto_ask(
                f"  {CYAN}Email первого пользователя [admin@example.com]: {NC}",
                default="admin@example.com", c=True,
            ).strip()
            if not admin_email:
                admin_email = "admin@example.com"
            if "@" not in admin_email:
                _box_warn("Email должен содержать @ — это username для TrustTunnel.")
                continue
            break
        # UUID для derive пароля. Если Enter — генерируем случайный.
        _admin_uuid = proto_ask(
            f"  {CYAN}UUID для derive пароля {DIM}(Enter=авто):{NC} ",
            default="", c=True,
        ).strip()
        if not _admin_uuid:
            import uuid as _uuid_mod
            _admin_uuid = str(_uuid_mod.uuid4())

        acme_email = proto_ask(
            f"  {CYAN}Email для Let's Encrypt (Enter=пропустить): {NC}",
            default="", c=True,
        ).strip()
    except _Cancelled: raise

    # ── Установка ─────────────────────────────────────────────────────────
    os.system("clear")
    _box_top("🔐  УСТАНОВКА  •  TRUSTTUNNEL")
    _box_row()
    _box_info("Скачиваю официальный prebuilt-релиз (GPG-верификация)...")
    _box_bot(); print()

    ok, msg = _download_and_install_binary()
    if not ok:
        os.system("clear"); _box_top("🔐  УСТАНОВКА  •  TRUSTTUNNEL")
        _box_err(msg); _box_bot(); _pause(); return
    version = msg
    print(f"  {GREEN}✓{NC}  Бинарники установлены, версия {version}")

    _box_info("Импортирую AdGuard GPG key...")
    _import_gpg_key()
    if _verify_gpg_signature(_BINARY_PATH):
        print(f"  {GREEN}✓{NC}  GPG-подпись верифицирована")
    else:
        _box_warn("GPG-верификация не прошла — бинарник уже скачан, продолжаю")

    _box_info(f"Получаю Let's Encrypt сертификат для {domain}...")
    # v4.24: graceful fallback вместо sys.exit(1).
    # Раньше: obtain_ssl_cert() вызывала core.die() при DNS failure →
    # die() = sys.exit(1) → ВЕСЬ установщик падал. Теперь: перехватываем
    # SystemExit, генерируем self-signed cert, продолжаем установку.
    # TrustTunnel может работать с self-signed — клиенты принимают любой
    # сертификат TLS (pin через SNI, не через CA).
    _le_failed = False
    try:
        from chimera.modules.ssl_certbot import obtain_ssl_cert
        obtain_ssl_cert(domain=domain)
    except SystemExit as _se:
        # core.die() внутри obtain_ssl_cert → sys.exit(1). Перехватываем.
        _le_failed = True
        _box_warn(f"Let's Encrypt не получен: {_se}")
        _box_warn("Генерирую self-signed сертификат — продолжаю установку.")
    except Exception as e:
        _le_failed = True
        _box_warn(f"obtain_ssl_cert exception: {e}")
        _box_warn("Генерирую self-signed сертификат — продолжаю установку.")

    if _le_failed:
        # Генерируем self-signed cert в /etc/letsencrypt/live/<domain>/
        # (тот же путь что и LE, чтобы код ниже нашёл его без изменений).
        try:
            from chimera.modules.resources import generate_self_signed_cert
            generate_self_signed_cert(domain)
        except Exception as e:
            _box_err(f"Не удалось создать self-signed сертификат: {e}")
            _box_bot(); _pause(); return

    cert_chain = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
    cert_key = Path(f"/etc/letsencrypt/live/{domain}/privkey.pem")
    if not cert_chain.exists() or not cert_key.exists():
        _box_err(f"Сертификат не найден в {cert_chain}")
        _box_warn("Установка прервана — без TLS-сертификата TrustTunnel не стартует.")
        _box_bot(); _pause(); return
    print(f"  {GREEN}✓{NC}  Сертификат получен{' (self-signed)' if _le_failed else ''}")

    _box_info("Запускаю setup_wizard (non-interactive, --cert-type provided)...")
    listen_addr = f"0.0.0.0:{port}"
    # v4.24: используем email+UUID пользователя вместо хардкода
    # 'admin' + dummy UUID 00000000-... Пароль детерминированно выводится
    # из UUID (trusttunnel_derive_password).
    admin_pass = trusttunnel_derive_password(_admin_uuid)
    wizard_cmd = [
        str(_WIZARD_PATH), "-m", "non-interactive",
        "-a", listen_addr, "-c", f"{admin_email}:{admin_pass}", "-n", domain,
        "--cert-type", "provided",
        "--cert-chain-path", str(cert_chain),
        "--cert-key-path", str(cert_key),
        "--lib-settings", str(_VPN_TOML),
        "--hosts-settings", str(_HOSTS_TOML),
    ]
    r = _run(wizard_cmd, capture=True, timeout=60, cwd=str(_INSTALL_DIR))
    if r.returncode != 0:
        _box_err(f"setup_wizard exited {r.returncode}: {r.stderr[:300]}")
        _box_bot(); _pause(); return
    print(f"  {GREEN}✓{NC}  vpn.toml + hosts.toml + credentials.toml сгенерированы")
    print(f"  {GREEN}✓{NC}  Первый пользователь: {YELLOW}{admin_email}{NC}")
    print(f"  {DIM}    Пароль (derived from UUID): {admin_pass[:8]}...{NC}")

    # Включаем [metrics] блок для scrape через trusttunnel_stats
    try:
        with _VPN_TOML.open("a") as f:
            f.write(f"\n[metrics]\naddress = \"127.0.0.1:{_METRICS_PORT}\"\nrequest_timeout_secs = 3\n")
    except Exception as e:
        _log("WARN", f"cannot append [metrics] to vpn.toml: {e}")

    _box_info("Пишу systemd-юнит (с ExecReload для SIGHUP-reload)...")
    _install_systemd_unit(_INSTALL_DIR)
    print(f"  {GREEN}✓{NC}  systemd-юнит установлен")

    _box_info("Устанавливаю certbot deploy-hook (systemctl reload при renewal)...")
    _install_cert_renewal_hook()
    print(f"  {GREEN}✓{NC}  deploy-hook установлен")

    _box_info(f"Открываю порты {port}/tcp + {port}/udp...")
    _open_port(port)
    print(f"  {GREEN}✓{NC}  Порты открыты")

    _box_info("Устанавливаю cron (--trusttunnel-health + --trusttunnel-stats, 5 мин)...")
    _install_cron()
    print(f"  {GREEN}✓{NC}  Cron установлен")

    _box_info("Запускаю сервис...")
    _run(["systemctl", "start", _SERVICE_NAME], timeout=15)
    time.sleep(2)
    if trusttunnel_service_active():
        print(f"  {GREEN}✓{NC}  Сервис запущен")
    else:
        _box_warn("Сервис не стартовал — проверьте /var/log/trusttunnel-endpoint.log")

    # Сохраняем state
    new_state = {
        "installed":       True,
        "version":         version,
        "domain":          domain,
        "listen_address":  listen_addr,
        "listen_port":     port,
        "cert_type":       "provided",
        "cert_chain_path": str(cert_chain),
        "cert_key_path":   str(cert_key),
        "install_dir":     str(_INSTALL_DIR),
        "binary_path":     str(_BINARY_PATH),
        "wizard_path":     str(_WIZARD_PATH),
        "vpn_toml":        str(_VPN_TOML),
        "hosts_toml":      str(_HOSTS_TOML),
        "creds_toml":      str(_CREDS_TOML),
        "rules_toml":      str(_RULES_TOML),
        "metrics_port":    _METRICS_PORT,
        "installed_at":    datetime.now(timezone.utc).isoformat(),
    }
    proto_save_state(_STATE_FILE, new_state)

    _box_row(); _box_sep()
    _box_ok(f"TrustTunnel v{version} установлен.")
    _box_kv("Домен:", f"{YELLOW}{domain}{NC}")
    _box_kv("Порт:", f"{YELLOW}{port}/tcp+udp{NC}")
    _box_kv("Метрики:", f"{CYAN}http://127.0.0.1:{_METRICS_PORT}/metrics{NC}")
    _box_bot(); _pause()

# Public wrapper для вызова из тестов / внешних скриптов (сохранён API).
def trusttunnel_install(domain: str,
                        port: int = _DEFAULT_PORT,
                        acme_email: str = "") -> bool:
    """Full TrustTunnel install. Returns True on success.

    Это программный entry point (без TUI-промптов) — используется тестами
    и потенциально кастомными скриптами. Интерактивная установка через
    меню — _run_install_inner().
    """
    _log("INFO", f"install: domain={domain!r}, port={port}, acme_email={acme_email!r}")
    if not domain:
        _log("ERROR", "install: domain is required"); return False
    err = _check_domain_available(domain)
    if err:
        _log("ERROR", f"install: {err}"); return False
    err = _check_port_available(port)
    if err:
        _log("ERROR", f"install: {err}"); return False

    ok, version_or_err = _download_and_install_binary()
    if not ok:
        _log("ERROR", f"install: {version_or_err}"); return False
    version = version_or_err

    _import_gpg_key()
    if not _verify_gpg_signature(_BINARY_PATH):
        _log("WARN", "install: GPG verification failed — continuing (binary already downloaded)")

    try:
        from chimera.modules.ssl_certbot import obtain_ssl_cert
        obtain_ssl_cert(domain=domain)
    except Exception as e:
        _log("ERROR", f"install: obtain_ssl_cert failed: {e}"); return False
    cert_chain = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
    cert_key = Path(f"/etc/letsencrypt/live/{domain}/privkey.pem")
    if not cert_chain.exists() or not cert_key.exists():
        _log("ERROR", f"install: cert files missing at {cert_chain}"); return False

    listen_addr = f"0.0.0.0:{port}"
    admin_pass = trusttunnel_derive_password("00000000-0000-0000-0000-000000000000")
    wizard_cmd = [
        str(_WIZARD_PATH), "-m", "non-interactive",
        "-a", listen_addr, "-c", f"admin:{admin_pass}", "-n", domain,
        "--cert-type", "provided",
        "--cert-chain-path", str(cert_chain),
        "--cert-key-path", str(cert_key),
        "--lib-settings", str(_VPN_TOML),
        "--hosts-settings", str(_HOSTS_TOML),
    ]
    r = _run(wizard_cmd, capture=True, timeout=60, cwd=str(_INSTALL_DIR))
    if r.returncode != 0:
        _log("ERROR", f"install: setup_wizard exited {r.returncode}: {r.stderr[:300]}")
        return False

    try:
        with _VPN_TOML.open("a") as f:
            f.write(f"\n[metrics]\naddress = \"127.0.0.1:{_METRICS_PORT}\"\nrequest_timeout_secs = 3\n")
    except Exception as e:
        _log("WARN", f"install: cannot append [metrics] to vpn.toml: {e}")

    _install_systemd_unit(_INSTALL_DIR)
    _install_cert_renewal_hook()
    _open_port(port)
    _install_cron()
    _run(["systemctl", "start", _SERVICE_NAME], timeout=15)

    state = {
        "installed":       True,
        "version":         version,
        "domain":          domain,
        "listen_address":  listen_addr,
        "listen_port":     port,
        "cert_type":       "provided",
        "cert_chain_path": str(cert_chain),
        "cert_key_path":   str(cert_key),
        "install_dir":     str(_INSTALL_DIR),
        "binary_path":     str(_BINARY_PATH),
        "wizard_path":     str(_WIZARD_PATH),
        "vpn_toml":        str(_VPN_TOML),
        "hosts_toml":      str(_HOSTS_TOML),
        "creds_toml":      str(_CREDS_TOML),
        "rules_toml":      str(_RULES_TOML),
        "metrics_port":    _METRICS_PORT,
        "installed_at":    datetime.now(timezone.utc).isoformat(),
    }
    proto_save_state(_STATE_FILE, state)
    _log("INFO", f"install: done, version={version}, port={port}")
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _full_uninstall(silent: bool = False) -> bool:
    """Полное удаление TrustTunnel. Returns True on success."""
    if not silent:
        os.system("clear")
        _box_top("🔐  УДАЛЕНИЕ  •  TRUSTTUNNEL")
        _box_row()
        _box_warn("Будут удалены: бинарники, конфиги, systemd-юнит, cron,")
        _box_warn("certbot deploy-hook, ufw/iptables правила. Сертификат")
        _box_warn("Let's Encrypt останется (управляется certbot).")
        _box_row()
        _box_item("1", "Подтверждаю — удалить")
        _box_item("Q", "← Отмена")
        _box_bot(); print()
        try:
            ch = proto_ask(f"{CYAN}Выбор [1/Q]: {NC}", c=True).strip().lower()
        except _Cancelled: return False
        if ch != "1":
            print(f"  {DIM}Отменено.{NC}"); return False

    _log("INFO", "uninstall: starting")
    state = proto_load_state(_STATE_FILE)
    port = state.get("listen_port", _DEFAULT_PORT)

    _remove_systemd_unit()
    _close_port(port)
    _remove_cert_renewal_hook()
    _remove_cron()

    try:
        if _INSTALL_DIR.exists():
            shutil.rmtree(_INSTALL_DIR)
    except Exception as e:
        _log("WARN", f"uninstall: cannot remove {_INSTALL_DIR}: {e}")

    try:
        _STATE_FILE.unlink()
    except Exception:
        pass

    if not silent:
        _box_row(); _box_ok("TrustTunnel удалён."); _box_bot(); _pause()
    _log("INFO", "uninstall: done")
    return True

# Public wrapper (сохранён API для тестов / внешних скриптов).
def trusttunnel_uninstall() -> bool:
    """Full uninstall. Returns True on success. Без TUI-промптов."""
    _log("INFO", "uninstall: starting")
    state = proto_load_state(_STATE_FILE)
    port = state.get("listen_port", _DEFAULT_PORT)
    _remove_systemd_unit()
    _close_port(port)
    _remove_cert_renewal_hook()
    _remove_cron()
    try:
        if _INSTALL_DIR.exists():
            shutil.rmtree(_INSTALL_DIR)
    except Exception as e:
        _log("WARN", f"uninstall: cannot remove {_INSTALL_DIR}: {e}")
    try:
        _STATE_FILE.unlink()
    except Exception:
        pass
    _log("INFO", "uninstall: done")
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  ПОЛЬЗОВАТЕЛИ — меню
# ══════════════════════════════════════════════════════════════════════════════
def _users_menu() -> None:
    while True:
        os.system("clear")
        users = trusttunnel_list_users()
        _box_top("👥  ПОЛЬЗОВАТЕЛИ  •  TRUSTTUNNEL")
        _box_row()
        _box_kv("Всего:", str(len(users)))
        _box_row(); _box_sep()
        if users:
            for u in users:
                _box_row(f"  {CYAN}•{NC}  {u.get('username', '?')}")
            _box_row(); _box_sep()
        _box_item("1", "Добавить пользователя")
        _box_item("2", "Сгенерировать deep-link + QR")
        _box_item("3", "Удалить пользователя")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()

        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled: break

        if ch == "1":
            try: _add_user_dialog()
            except _Cancelled: pass
        elif ch == "2":
            try: _show_deeplink_dialog()
            except _Cancelled: pass
        elif ch == "3":
            try: _remove_user_dialog()
            except _Cancelled: pass
        elif ch in ("q", ""):
            break

def _add_user_dialog() -> None:
    os.system("clear")
    _box_top("➕  ДОБАВИТЬ ПОЛЬЗОВАТЕЛЯ  •  TRUSTTUNNEL")
    _box_row()
    try:
        email = proto_ask(f"  {CYAN}Email (username): {NC}", c=True).strip()
        if not email:
            _box_warn("Email обязателен."); _pause(); return
        uuid_str = proto_ask(f"  {CYAN}UUID (для derive пароля): {NC}", c=True).strip()
        if not uuid_str:
            _box_warn("UUID обязателен — нужен для детерминированного пароля.")
            _pause(); return
    except _Cancelled: raise

    password = trusttunnel_derive_password(uuid_str)
    if not trusttunnel_add_user(email, password):
        _box_err(f"Не удалось добавить {email}"); _box_bot(); _pause(); return

    # Одиночная операция — рестарт сразу (без batch_context).
    if trusttunnel_restart_service():
        _box_ok(f"Пользователь {email} добавлен, сервис перезапущен.")
    else:
        _box_warn(f"Пользователь добавлен в файл, но рестарт не удался — "
                  f"проверьте логи.")
    _box_bot(); _pause()

def _show_deeplink_dialog() -> None:
    os.system("clear")
    _box_top("🔗  DEEP-LINK  •  TRUSTTUNNEL")
    _box_row()
    try:
        email = proto_ask(f"  {CYAN}Email пользователя: {NC}", c=True).strip()
    except _Cancelled: raise
    if not email:
        _box_warn("Email обязателен."); _pause(); return

    try:
        link = trusttunnel_generate_deeplink(email)
    except ValueError as e:
        _box_err(str(e)); _box_bot(); _pause(); return
    except Exception as e:
        _box_err(f"Ошибка: {e}"); _box_bot(); _pause(); return

    _box_row()
    _box_link(link)
    _box_row(); _box_sep()
    qr_url = f"https://trusttunnel.org/qr.html#tt={link[len('tt://?'):]}"
    _box_info("QR (web):")
    _box_link(qr_url, color=CYAN)
    _box_row()
    _print_qr(link, label=email)
    _box_bot(); _pause()

def _remove_user_dialog() -> None:
    os.system("clear")
    _box_top("🗑️  УДАЛИТЬ ПОЛЬЗОВАТЕЛЯ  •  TRUSTTUNNEL")
    _box_row()
    try:
        email = proto_ask(f"  {CYAN}Email пользователя: {NC}", c=True).strip()
    except _Cancelled: raise
    if not email:
        _box_warn("Email обязателен."); _pause(); return
    if not trusttunnel_user_exists(email):
        _box_warn(f"Пользователь {email} не найден в credentials.toml.")
        _pause(); return
    if not trusttunnel_remove_user(email):
        _box_err(f"Не удалось удалить {email}"); _pause(); return
    if trusttunnel_restart_service():
        _box_ok(f"Пользователь {email} удалён, сервис перезапущен.")
    else:
        _box_warn("Удалён из файла, но рестарт не удался.")
    _box_bot(); _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС / ЛОГИ
# ══════════════════════════════════════════════════════════════════════════════
def _show_status() -> None:
    os.system("clear")
    state = proto_load_state(_STATE_FILE)
    _box_top("📊  СТАТУС  •  TRUSTTUNNEL")
    _box_row()

    svc_ok = trusttunnel_service_active()
    _box_kv("Сервис:", f"{GREEN}● активен{NC}" if svc_ok else f"{RED}● остановлен{NC}")
    _box_kv("Версия:", state.get("version", "—"))
    _box_kv("Домен:", state.get("domain", "—"))
    _box_kv("Порт:", f"{state.get('listen_port', '—')}/tcp+udp")
    _box_kv("Сертификат:", state.get("cert_chain_path", "—"))
    _box_kv("Метрики:", f"http://127.0.0.1:{state.get('metrics_port', _METRICS_PORT)}/metrics")
    _box_kv("Cron:", f"{GREEN}✓ установлен{NC}" if trusttunnel_cron_installed() else f"{YELLOW}⚠ не установлен{NC}")
    _box_kv("Пользователей:", str(len(trusttunnel_list_users())))

    _box_row(); _box_sep()
    _box_row(f"  {BOLD}{WHITE}Последние 30 строк журнала:{NC}")
    _box_row()
    r = subprocess.run(
        ["journalctl", "-u", _SERVICE_NAME, "-n", "30",
         "--no-pager", "--output=short-monotonic"],
        capture_output=True, encoding="utf-8", errors="replace",
        env={**os.environ, "LANG": "C.UTF-8"},
    )
    for line in (r.stdout or "Нет записей").splitlines():
        _box_log_line(line)
    _box_row(); _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ГАЙД
# ══════════════════════════════════════════════════════════════════════════════
def _show_guide() -> None:
    while True:
        os.system("clear")
        _box_top("📖  ГАЙД  •  TRUSTTUNNEL")
        _box_row()
        _box_item("1", "Как работает TrustTunnel")
        _box_item("2", "Клиентское приложение и deep-link")
        _box_item("3", "Сертификаты и порты")
        _box_item("4", f"{YELLOW}⚠  Ограничения (трафик, рестарты){NC}")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()

        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled: break

        if ch == "1":   _guide_how()
        elif ch == "2": _guide_client()
        elif ch == "3": _guide_certs()
        elif ch == "4": _guide_limits()
        elif ch in ("q", ""): break

def _guide_how() -> None:
    os.system("clear")
    _box_top("⚙️  КАК РАБОТАЕТ TRUSTTUNNEL")
    _box_row()
    _box_info("TrustTunnel — референсная реализация протокола AdGuard VPN")
    _box_info("(HTTP/2-over-TLS + HTTP/3-over-QUIC). Не инбаунд Xray, а")
    _box_info("самостоятельный Rust-бинарник от AdGuard (Apache 2.0).")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Транспорт:{NC}")
    _box_row()
    _box_info("HTTP/2 CONNECT (или HTTP/3 over QUIC) поверх TLS. Внутри")
    _box_info("туннеля мультиплексируются TCP/UDP/ICMP. Аутентификация —")
    _box_info("HTTP Basic: base64(username:password) в proxy-authorization.")
    _box_row()
    _box_sep()
    _box_row(f"  {CYAN}Клиент → TLS:8443 → trusttunnel_endpoint → NAT → интернет{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Порт 8443 (TCP+UDP):{NC}")
    _box_row()
    _box_info("Отдельный порт, НЕ 443 — 443 занят VLESS (TCP) + Hysteria2 (UDP).")
    _box_info("TrustTunnel слушает одновременно TCP (HTTP/2) и UDP (HTTP/3)")
    _box_info("на одном номере порта, не имеет SNI-dispatch и не умеет fallback.")
    _box_bot(); _pause()

def _guide_client() -> None:
    os.system("clear")
    _box_top("📱  КЛИЕНТ И DEEP-LINK  •  TRUSTTUNNEL")
    _box_row()
    _box_info("Официальный клиент: TrustTunnel Flutter Client —")
    _box_info("https://github.com/TrustTunnel/TrustTunnelClient")
    _box_info("iOS / Android / macOS. Импорт по tt:// ссылке или QR-коду.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Формат deep-link:{NC}")
    _box_row()
    _box_info("tt://?<base64url-no-padding TLV-payload>")
    _box_info("TLV: varint(tag) || varint(len) || value")
    _box_info("varint = RFC 9000 §16 QUIC varint (2-bit length prefix)")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Теги:{NC}")
    _box_row()
    _box_info("0x01 hostname (обязательно)")
    _box_info("0x02 addresses — host:port (обязательно, повторяется)")
    _box_info("0x05 username (обязательно)")
    _box_info("0x06 password (обязательно, cleartext после base64url)")
    _box_info("0x08 certificate (DER, только для self-signed)")
    _box_info("0x09 upstream_protocol (1=http2, 2=http3)")
    _box_bot(); _pause()

def _guide_certs() -> None:
    os.system("clear")
    _box_top("🔒  СЕРТИФИКАТЫ И ПОРТЫ  •  TRUSTTUNNEL")
    _box_row()
    _box_info("Сертификат — Let's Encrypt через существующий ssl_certbot.")
    _box_info("Feed в setup_wizard через --cert-type provided. Авто-renewal —")
    _box_info("через certbot cron + deploy-hook systemctl reload trusttunnel")
    _box_info("(SIGHUP перезагружает hosts.toml, без рестарта, без разрыва).")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Домен:{NC}")
    _box_row()
    _box_info("Должен отличаться от доменов VLESS/NaiveProxy/FPTN/MTProto.")
    _box_info("Проверка коллизий — _check_domain_available() при установке.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Порт:{NC}")
    _box_row()
    _box_info("8443 (TCP+UDP) по умолчанию. Проверка коллизий —")
    _box_info("core.check_port_used_by_other_protocol (PROTOCOL_PORT_REGISTRY).")
    _box_bot(); _pause()

def _guide_limits() -> None:
    os.system("clear")
    _box_top("⚠️  ОГРАНИЧЕНИЯ  •  TRUSTTUNNEL")
    _box_row()
    _box_row(f"  {YELLOW}1. Только агрегированный трафик, не per-user{NC}")
    _box_row()
    _box_info("Апстрим /metrics отдаёт счётчики только с лейблом protocol_type")
    _box_info("(http1/http2/http3) — БЕЗ username. Per-user биллинг потребует")
    _box_info("патчить lib/src/metrics.rs и собирать из исходников, теряя")
    _box_info("GPG-верификацию. Трафик записывается под _aggregate user_id.")
    _box_row()
    _box_sep()
    _box_row(f"  {YELLOW}2. Смена пользователей рестартует сервис{NC}")
    _box_row()
    _box_info("Апстрим НЕ поддерживает hot-reload credentials.toml (SIGHUP")
    _box_info("перезагружает только hosts.toml). Любой add/remove/block/unblock")
    _box_info("→ systemctl restart → ~1 c разрыв ВСЕХ активных соединений.")
    _box_row()
    _box_info("Массовые cron-операции батчатся через batch_context() в")
    _box_info("user_lifecycle.py — один рестарт за проход. Ручные операции")
    _box_info("через TUI/бота рестартуют сразу.")
    _box_row()
    _box_sep()
    _box_info("Подробнее: TROUBLESHOOTING.md → 'TrustTunnel — известные")
    _box_info("архитектурные ограничения'.")
    _box_bot(); _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════
def do_trusttunnel_menu() -> None:
    """Точка входа из _core.py (пункт 18 главного меню)."""
    while True:
        os.system("clear")
        installed = _is_installed()
        state = proto_load_state(_STATE_FILE)

        svc_ok = trusttunnel_service_active()
        svc_str = (
            f"{GREEN}● активен{NC}"  if svc_ok    else
            f"{RED}● остановлен{NC}" if installed else
            f"{YELLOW}● не установлен{NC}"
        )

        _box_top("🔐  TRUSTTUNNEL  •  AdGuard VPN protocol")
        _box_row()
        _box_kv("Статус:", svc_str)

        if installed:
            _box_kv("Версия:", state.get("version", "—"))
            _box_kv("Домен:", f"{YELLOW}{state.get('domain','—')}{NC}")
            _box_kv("Порт:", f"{state.get('listen_port','—')}/tcp+udp")
            _box_kv("Пользователей:", str(len(trusttunnel_list_users())))

        _box_row(); _box_sep()

        if not installed:
            _box_item("1", "🚀  Установить TrustTunnel")
        else:
            _box_item("1", "🚀  Переустановить")
            _box_item("2", "👥  Управление пользователями")
            _box_item("3", "🔄  Перезапустить сервис")
            _box_item("5", "📊  Статус / логи")
            _box_sep()
            _box_item("9", f"{RED}🗑️   Удалить TrustTunnel{NC}")

        _box_sep()
        _box_item("G", "📖  Гайд: как работает, клиент, ограничения")
        _box_sep()
        _box_item("Q", "← Назад в главное меню VLESS")
        _box_bot(); print()

        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled: break

        if ch == "1":
            _run_install()
        elif ch == "2" and installed:
            try: _users_menu()
            except _Cancelled: pass
        elif ch == "3" and installed:
            ok = trusttunnel_restart_service()
            print(f"\n  {'✓' if ok else '⚠'}  {'Перезапущен.' if ok else 'Проверьте логи.'}")
            _pause()
        elif ch == "5" and installed:
            _show_status()
        elif ch == "9" and installed:
            try: _full_uninstall(silent=False)
            except _Cancelled:
                print(f"  {DIM}Отменено.{NC}"); _pause()
        elif ch == "g":
            try: _show_guide()
            except _Cancelled: pass
        elif ch in ("q", ""):
            break

# ══════════════════════════════════════════════════════════════════════════════
#  АВТОНОМНЫЙ ЗАПУСК
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}"); sys.exit(1)
    try:
        do_trusttunnel_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}"); sys.exit(0)


# ============================================================================
#  PUBLIC API — для интеграции с subscription.py (единая подписка)
# ============================================================================

def get_subscription_uris(user: dict) -> list[str]:
    """Генерирует tt:// deep-link для VLESS-юзера, если TrustTunnel установлен.

    Матчинг по email (TrustTunnel username == email) + uuid (для derive password).
    Использует trusttunnel_deeplink_for_user() — детерминированный пароль
    из SHA-256("trusttunnel-pass|" + uuid).

    Никогда не бросает исключение — try/except внутри, возвращает [].
    """
    try:
        email = user.get("email", "")
        uuid_str = user.get("uuid", "")
        if not email or not uuid_str:
            return []
        uri = trusttunnel_deeplink_for_user(email, uuid_str)
        if uri:
            return [uri]
    except Exception:
        pass
    return []
