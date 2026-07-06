"""
vless_installer/modules/fptn.py
───────────────────────────────────────────────────────────────────────────────
FPTN — самостоятельный L3 VPN-протокол (свой TUN-туннель, Protobuf-транспорт,
не инбаунд Xray). Апстрим: github.com/fptn-project/fptn (MIT).

Как это работает (в отличие от Reality — не подмена сертификата, а honeypot-
прокси на живой контент):
  DPI/сканер стучится на порт → TLS-handshake не от FPTN-клиента → сервер
  САМ проксирует этот коннект на настоящий домен (DEFAULT_PROXY_DOMAIN /
  ALLOWED_SNI_LIST) — сканер видит живой сайт, а не отказ или голый TLS.
  Легитимный FPTN-клиент проходит аутентификацию в рамках того же
  TLS-соединения на том же порту (единая точка входа — нет отдельного
  админ-порта, в отличие от Telemt).

Схема трафика:
  Клиент (fptn-client, TUN-режим)
    │  Protobuf-туннель поверх TLS
    ▼
  fptn-server :443  (не-VPN коннекты → прозрачный прокси на живой домен)
    │  NAT/MASQUERADE на исходящий интерфейс сервера
    ▼
  Интернет

Установка — БЕЗ Docker: сервер ставится из официального .deb-релиза
(fptn-server-<version>-ubuntu*-<arch>.deb, GitHub Releases), бинарники
распаковываются через `dpkg-deb -x` (без dpkg -i — не трогаем систему
пакетов), дальше — свой systemd-юнит и свой server.conf, как и с
остальными протоколами в этом инсталляторе.

⚠️  ВАЖНО — fptn-server трогает iptables ГЛОБАЛЬНО:
  При КАЖДОМ старте сервис безусловно выполняет `iptables -P INPUT ACCEPT`,
  `-P FORWARD ACCEPT`, `-P OUTPUT ACCEPT` — и ТО ЖЕ САМОЕ для ip6tables
  (RouteManager::Apply(), вызывается синхронно и рано, до поднятия веб-
  сервера) — и это НЕ откатывается при остановке сервиса. Если на сервере
  настроена политика DROP по умолчанию (fail2ban/ipset-harden и т.п.) —
  она молча слетает при каждом старте/ребуте, причём для обоих стеков
  (IPv4 и IPv6) независимо. Этот модуль это компенсирует: при установке
  снимает "снимок" текущей политики INPUT/FORWARD для iptables И
  ip6tables в /etc/fptn/fw-baseline.env, и вешает ExecStartPost на сам
  fptn-server.service — /etc/fptn/fw-reconcile.sh дожидается (поллингом,
  не фиксированным sleep) появления правила FORWARD, которое сам
  fptn-server добавляет при старте, и только потом восстанавливает DROP
  (с explicit ACCEPT под порт FPTN) — после КАЖДОГО старта сервиса,
  включая автозапуск при ребуте. Снимок разовый (на момент установки) —
  если политику потом меняют вручную, нужно переустановить модуль, чтобы
  снять новый снимок. Политика OUTPUT сознательно не восстанавливается
  (риск заблокировать сам сервер) — см. Гайд, пункт 5.

Пользователи и аутентификация:
  Ведутся штатным `fptn-passwd` в /etc/fptn/users.list (username — только
  [A-Za-z0-9], sha256(password) + лимит по битрейту, файл читается
  fptn-server "на лету" при изменении mtime — рестарт сервиса не нужен).

Токен клиента — самодостаточная строка вида vless://, генерируется на
чистом Python (без вызова стороннего скрипта):
  fptn:<base64(json{version,service_name,username,password,servers:[{host,
  md5_fingerprint,port}],censored_zone_servers:[]})>
  md5_fingerprint — отпечаток server.crt (openssl x509 -fingerprint -md5).

Что модуль делает:
  • Скачивает и распаковывает официальный .deb (без docker/dpkg -i)
  • Генерирует самоподписанный сертификат (openssl, 4096 бит, 10 лет)
  • Пишет /etc/fptn/server.conf + systemd-юнит fptn-server.service
  • Открывает порт в UFW (если активен) или iptables
  • Восстанавливает строгую политику INPUT/FORWARD после каждого старта
    (см. предупреждение выше)
  • Управление пользователями через fptn-passwd: добавление, список, удаление
  • Генерация fptn:// токена + QR для каждого пользователя
  • Статус/логи сервиса

Что модуль НЕ трогает:
  • Xray config.json и VLESS-inbound
  • state.json инсталлера
  • iptables-правила других модулей (см. пункт про firewall выше — только
    восстанавливает то, что было ДО запуска FPTN, ничего лишнего не добавляет)

Точка входа из _core.py:
    from vless_installer.modules.fptn import do_fptn_menu
    do_fptn_menu()
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Optional

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
_BIN_SERVER   = Path("/usr/bin/fptn-server")
_BIN_PASSWD   = Path("/usr/bin/fptn-passwd")
_CFG_DIR      = Path("/etc/fptn")
_CFG_FILE     = _CFG_DIR / "server.conf"
_USERS_FILE   = _CFG_DIR / "users.list"
_CERT_FILE    = _CFG_DIR / "server.crt"
_KEY_FILE     = _CFG_DIR / "server.key"
_FW_BASELINE  = _CFG_DIR / "fw-baseline.env"
_FW_RECONCILE = _CFG_DIR / "fw-reconcile.sh"
_SERVICE_FILE = Path("/etc/systemd/system/fptn-server.service")
_SERVICE_NAME = "fptn-server"
_MODULE_STATE = Path("/var/lib/xray-installer/fptn.json")

_GITHUB_API   = "https://api.github.com/repos/fptn-project/fptn/releases/latest"

_DEFAULT_PORT           = 443
_DEFAULT_TUN_IFACE      = "fptn0"
_DEFAULT_PROXY_DOMAIN   = "www.wikipedia.org"
_DEFAULT_BANDWIDTH_MB   = 100
_DEFAULT_MAX_SESSIONS   = 3
_BOX_W                  = 66

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ (самодостаточно, без общих модулей — как naiveproxy.py/mieru.py)
# ══════════════════════════════════════════════════════════════════════════════
def _plain(s: str) -> str:
    return re.sub(r'\033\[[0-9;]*m', '', s)

def _wlen(s: str) -> int:
    import unicodedata as _ud
    plain = _plain(s)
    width, chars = 0, list(plain)
    i = 0
    while i < len(chars):
        ch = chars[i]; cp = ord(ch)
        next_cp = ord(chars[i + 1]) if i + 1 < len(chars) else 0
        if next_cp == 0xFE0F:
            width += 2; i += 2; continue
        if cp == 0x200D or (0x300 <= cp <= 0x36F) or (0xFE00 <= cp <= 0xFE0F):
            i += 1; continue
        eaw = _ud.east_asian_width(ch)
        if eaw in ('W', 'F'):
            width += 2
        elif eaw == 'N' and (0x1F300 <= cp <= 0x1FAFF or 0x2B00 <= cp <= 0x2BFF):
            width += 2
        else:
            width += 1
        i += 1
    return width

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
        pad = max(0, _BOX_W - 2 - len(chunk))
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
class _Cancelled(Exception):
    pass

def _pause() -> None:
    try:
        print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True); input()
    except (KeyboardInterrupt, EOFError, UnicodeDecodeError):
        print()

def _ask(prompt: str, default: str = "", c: bool = False) -> str:
    try:
        print(prompt, end="", flush=True)
        val = input().strip()
        return val if val else default
    except (EOFError, UnicodeDecodeError):
        print(); return default
    except KeyboardInterrupt:
        print()
        if c: raise _Cancelled()
        return default

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

def _gen_password(length: int = 20) -> str:
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
    return ''.join(secrets.choice(chars) for _ in range(length))

def _valid_username(username: str) -> bool:
    """fptn-passwd (CommonUserManager::ValidateUsername) допускает ТОЛЬКО
    [A-Za-z0-9] — ни дефисов, ни подчёркиваний, ни точек."""
    return bool(username) and username.isalnum()

def _get_server_ip() -> str:
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80)); return s.getsockname()[0]
    except Exception: pass
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            return r.read().decode().strip()
    except Exception: pass
    return "ВАШ_IP"

def _port_conflict(port: int, ignore_own: Optional[int] = None) -> str:
    """Возвращает непустую строку с описанием, если TCP-порт уже занят
    ЧУЖИМ процессом — например, Xray/VLESS на том же порту, который FPTN
    молча не может забиндить (или молча перехватывает чужой SNI-роутинг,
    как в кейсе с alert'ом unrecognized_name на общем 443).

    ignore_own — порт, на котором уже стоит НАШ СОБСТВЕННЫЙ fptn-server
    (при переустановке на тот же порт): в этом случае "занятость" —
    это сам сервис, который мы сейчас остановим/перезапустим, а не
    конфликт, так что проверку пропускаем.
    """
    if ignore_own is not None and port == ignore_own and _is_installed():
        return ""
    if shutil.which("ss"):
        r = _run(["ss", "-H", "-tlnp", "sport", "=", f":{port}"], capture=True)
        if r.returncode == 0:
            out = (r.stdout or "").strip()
            return out.splitlines()[0] if out else ""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
        return ""
    except OSError:
        return "(детали недоступны: ss не сработал/не установлен, но порт точно занят — bind не прошёл)"
    finally:
        s.close()

# ══════════════════════════════════════════════════════════════════════════════
#  СОСТОЯНИЕ МОДУЛЯ
# ══════════════════════════════════════════════════════════════════════════════
def _load_state() -> dict:
    if not _MODULE_STATE.exists(): return {}
    try: return json.loads(_MODULE_STATE.read_text())
    except Exception: return {}

def _save_state(data: dict) -> None:
    try:
        _MODULE_STATE.parent.mkdir(parents=True, exist_ok=True)
        _MODULE_STATE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        _MODULE_STATE.chmod(0o600)
    except Exception as e:
        print(f"  {YELLOW}⚠{NC}  Не удалось сохранить fptn.json: {e}")

def _is_installed() -> bool:
    return _BIN_SERVER.exists() and _SERVICE_FILE.exists() and _CFG_FILE.exists()

def _save_user_to_state(username: str, password: str, bandwidth: int) -> None:
    """Persist-ит пароль в открытом виде в fptn.json (0600, root-only) —
    users.list у fptn-passwd хранит только sha256-хэш, а subscription.py
    (как и для mieru.json/naiveproxy.json) нужен именно plaintext-пароль,
    чтобы собрать fptn:// токен в агрегированной подписке."""
    state = _load_state()
    users = state.get("users", [])
    users = [u for u in users if u.get("username") != username]
    users.append({"username": username, "password": password, "bandwidth": bandwidth})
    state["users"] = users
    _save_state(state)

def _remove_user_from_state(username: str) -> None:
    state = _load_state()
    users = [u for u in state.get("users", []) if u.get("username") != username]
    state["users"] = users
    _save_state(state)

# ══════════════════════════════════════════════════════════════════════════════
#  БИНАРНИКИ (.deb → dpkg-deb -x, БЕЗ dpkg -i и без Docker)
# ══════════════════════════════════════════════════════════════════════════════
def _detect_arch() -> Optional[str]:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "amd64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    return None

def _get_latest_release() -> Optional[dict]:
    try:
        req = urllib.request.Request(
            _GITHUB_API, headers={"User-Agent": "VLESS-Ultimate-Installer"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception:
        return None

def _pick_server_asset(release: dict, arch: str) -> Optional[str]:
    """Не завязываемся на конкретную "ubuntu22.04" в имени файла — она
    может смениться в будущих релизах. Ищем любой .deb-ассет, начинающийся
    на "fptn-server-" и заканчивающийся на нужную архитектуру."""
    for asset in release.get("assets", []):
        name = asset.get("name", "")
        if name.startswith("fptn-server-") and name.endswith(f"{arch}.deb"):
            return asset.get("browser_download_url")
    return None

def _download_binaries() -> tuple:
    """Возвращает (ok, message)."""
    arch = _detect_arch()
    if not arch:
        return False, f"Неподдерживаемая архитектура: {platform.machine()} (нужна amd64/arm64)."
    if not shutil.which("dpkg-deb"):
        return False, "dpkg-deb не найден — модуль расчитан на Debian/Ubuntu."

    release = _get_latest_release()
    if not release:
        return False, "Не удалось получить список релизов с GitHub API."
    url = _pick_server_asset(release, arch)
    if not url:
        return False, f"Не найден .deb пакет сервера для архитектуры {arch}."
    version = release.get("tag_name", "unknown")

    tmp_deb = Path(tempfile.mktemp(suffix=".deb"))
    tmp_dir = Path(tempfile.mkdtemp(prefix="fptn-extract-"))
    try:
        urllib.request.urlretrieve(url, str(tmp_deb))
        r = _run(["dpkg-deb", "-x", str(tmp_deb), str(tmp_dir)], capture=True)
        if r.returncode != 0:
            return False, f"dpkg-deb -x не смог распаковать пакет: {(r.stderr or '')[:200]}"

        server_bin = tmp_dir / "usr" / "bin" / "fptn-server"
        passwd_bin = tmp_dir / "usr" / "bin" / "fptn-passwd"
        if not server_bin.exists() or not passwd_bin.exists():
            return False, "В .deb не найдены /usr/bin/fptn-server и/или fptn-passwd."

        shutil.copy2(str(server_bin), str(_BIN_SERVER)); _BIN_SERVER.chmod(0o755)
        shutil.copy2(str(passwd_bin), str(_BIN_PASSWD)); _BIN_PASSWD.chmod(0o755)
        return True, f"fptn-server {version} ({arch}) установлен."
    except Exception as e:
        return False, f"Ошибка загрузки: {e}"
    finally:
        tmp_deb.unlink(missing_ok=True)
        shutil.rmtree(tmp_dir, ignore_errors=True)

# ══════════════════════════════════════════════════════════════════════════════
#  СЕРТИФИКАТ (самоподписанный — как hysteria2_cert_mgr.py)
# ══════════════════════════════════════════════════════════════════════════════
def _gen_selfsigned_cert(cn: str) -> bool:
    _CFG_DIR.mkdir(parents=True, exist_ok=True)
    r = _run([
        "openssl", "req", "-x509", "-newkey", "rsa:4096",
        "-keyout", str(_KEY_FILE),
        "-out",    str(_CERT_FILE),
        "-days",   "3650", "-nodes",
        "-subj",   f"/CN={cn}",
    ], capture=True, timeout=30)
    if r.returncode != 0:
        return False
    _CERT_FILE.chmod(0o644)
    _KEY_FILE.chmod(0o600)
    return True

def _cert_md5_fingerprint() -> str:
    r = _run(["openssl", "x509", "-noout", "-fingerprint", "-md5",
              "-in", str(_CERT_FILE)], capture=True)
    out = (r.stdout or "").strip()
    if r.returncode != 0 or "=" not in out:
        return ""
    return out.split("=", 1)[1].replace(":", "").lower()

# ══════════════════════════════════════════════════════════════════════════════
#  ТОКЕН КЛИЕНТА (чистый Python — воспроизводит формат token-generator
#  из официального docker-образа, без вызова стороннего скрипта)
# ══════════════════════════════════════════════════════════════════════════════
def _gen_fptn_token(username: str, password: str, server_ip: str,
                     service_name: str, port: int) -> str:
    import base64
    md5_fp = _cert_md5_fingerprint()
    token_data = {
        "version": 1,
        "service_name": service_name,
        "username": username,
        "password": password,
        "servers": [{
            "name": service_name, "host": server_ip,
            "md5_fingerprint": md5_fp, "port": port,
        }],
        "censored_zone_servers": [],
    }
    json_str = json.dumps(token_data, separators=(",", ":"))
    b64 = base64.b64encode(json_str.encode("utf-8")).decode("utf-8").rstrip("=")
    return f"fptn:{b64}"

# ══════════════════════════════════════════════════════════════════════════════
#  СЕТЬ / ИНТЕРФЕЙС
# ══════════════════════════════════════════════════════════════════════════════
def _detect_out_iface() -> str:
    r = _run(["ip", "-o", "-4", "route", "show", "to", "default"], capture=True)
    parts = (r.stdout or "").split()
    if "dev" in parts:
        try:
            return parts[parts.index("dev") + 1]
        except IndexError:
            pass
    return ""

# ══════════════════════════════════════════════════════════════════════════════
#  IPTABLES / UFW  (открытие порта — как naiveproxy.py/mieru.py)
# ══════════════════════════════════════════════════════════════════════════════
def _ipt_tcp_rule_exists(port: int) -> bool:
    r = _run(["iptables", "-t", "filter", "-C", "INPUT",
              "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"], capture=True)
    return r.returncode == 0

def _ipt_open_tcp(port: int) -> None:
    if not _ipt_tcp_rule_exists(port):
        _run(["iptables", "-t", "filter", "-I", "INPUT", "1",
              "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])

def _ipt_close_tcp(port: int) -> None:
    for _ in range(5):
        if not _ipt_tcp_rule_exists(port): break
        _run(["iptables", "-t", "filter", "-D", "INPUT",
              "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])

def _ipt_persist() -> None:
    if shutil.which("netfilter-persistent"):
        _run(["netfilter-persistent", "save"], capture=True); return
    rules_dir = Path("/etc/iptables")
    rules_dir.mkdir(parents=True, exist_ok=True)
    r = _run(["iptables-save"], capture=True)
    if r.returncode == 0 and r.stdout:
        (rules_dir / "rules.v4").write_text(r.stdout)

def _ufw_is_active() -> bool:
    if not shutil.which("ufw"):
        return False
    r = _run(["ufw", "status"], capture=True)
    return "status: active" in r.stdout.lower()

def _open_port(port: int) -> str:
    if _ufw_is_active():
        _run(["ufw", "allow", f"{port}/tcp", "comment", "FPTN"], capture=True)
        return f"UFW: TCP {port} открыт."
    _ipt_open_tcp(port)
    _ipt_persist()
    return f"iptables: TCP {port} открыт."

def _close_port(port: int) -> None:
    if _ufw_is_active():
        _run(["ufw", "delete", "allow", f"{port}/tcp"], capture=True)
    else:
        _ipt_close_tcp(port)
        _ipt_persist()

# ══════════════════════════════════════════════════════════════════════════════
#  ФАЙРВОЛ: снимок политики + автовосстановление после каждого старта
#  ─────────────────────────────────────────────────────────────────────
#  fptn-server (RouteManager::Apply(), см. исходники) при КАЖДОМ старте
#  безусловно делает iptables -P INPUT/FORWARD/OUTPUT ACCEPT и НЕ
#  откатывает это при остановке. Компенсируем через ExecStartPost-хук в
#  самом systemd-юните — тогда восстановление срабатывает и при обычном
#  рестарте, и при автозапуске после ребута сервера.
# ══════════════════════════════════════════════════════════════════════════════
def _get_chain_policy(chain: str, cmd: str = "iptables") -> str:
    r = _run([cmd, "-L", chain, "-n"], capture=True)
    first = (r.stdout or "").splitlines()[0] if r.stdout else ""
    if "DROP" in first: return "DROP"
    if "REJECT" in first: return "DROP"   # трактуем как «не ACCEPT по умолчанию»
    if "ACCEPT" in first: return "ACCEPT"
    return "UNKNOWN"

def _write_fw_reconcile_hook(port: int, tun_iface: str, out_iface: str,
                              prior_input: str, prior_forward: str,
                              prior_input6: str, prior_forward6: str) -> None:
    """
    ВАЖНО: fptn-server трогает И iptables, И ip6tables (см. RouteManager::
    Apply() — оба стека получают -P INPUT/FORWARD/OUTPUT ACCEPT). Более
    ранняя версия этого хука проверяла только iptables — если на сервере
    была строгая политика для ip6tables, она слетала и оставалась ACCEPT
    навсегда. Здесь снимаются и восстанавливаются оба стека независимо.

    Синхронизация со стартом FPTN — НЕ голый sleep. Apply() вызывается
    рано и синхронно (до поднятия веб-сервера), поэтому в норме укладывается
    в доли секунды, но полагаться на фиксированную паузу неверно: если
    iptables в этот момент занят другим процессом (например, тем же
    fail2ban) или система под нагрузкой — можно откатить политику ДО того,
    как FPTN её выставил, и она останется ACCEPT до следующего рестарта.
    Вместо этого скрипт ждёт (до 15 сек) появления конкретного правила
    FORWARD, которое сам fptn-server добавляет при Apply() — это прямой
    сигнал «маршрутизация уже поднята», а не догадка по таймауту.
    """
    _CFG_DIR.mkdir(parents=True, exist_ok=True)
    _FW_BASELINE.write_text(
        "# Снимок политики iptables/ip6tables ДО первой установки FPTN.\n"
        "# Используется /etc/fptn/fw-reconcile.sh — не редактируйте руками,\n"
        "# кроме FPTN_PORT при смене порта через меню инсталлятора.\n"
        f"PRIOR_INPUT_POLICY={prior_input}\n"
        f"PRIOR_FORWARD_POLICY={prior_forward}\n"
        f"PRIOR_INPUT6_POLICY={prior_input6}\n"
        f"PRIOR_FORWARD6_POLICY={prior_forward6}\n"
        f"FPTN_PORT={port}\n"
        f"FPTN_TUN_IFACE={tun_iface}\n"
        f"FPTN_OUT_IFACE={out_iface}\n"
    )
    _FW_RECONCILE.write_text(
        "#!/bin/bash\n"
        "# Автосоздано VLESS-Ultimate-Installer — модуль fptn.py\n"
        "# fptn-server при каждом старте безусловно выставляет\n"
        "# iptables/ip6tables -P INPUT/FORWARD/OUTPUT ACCEPT и не откатывает\n"
        "# это при остановке. Этот хук (ExecStartPost) запускается systemd\n"
        "# после КАЖДОГО старта сервиса — включая автозапуск при ребуте — и\n"
        "# восстанавливает исходную политику, если до установки FPTN она\n"
        "# была DROP.\n"
        "set -u\n"
        "source /etc/fptn/fw-baseline.env 2>/dev/null || exit 0\n"
        "IPT=$(command -v iptables || echo /sbin/iptables)\n"
        "IP6T=$(command -v ip6tables || echo /sbin/ip6tables)\n"
        "\n"
        "# Ждём явный сигнал, что RouteManager::Apply() отработал — правило\n"
        "# FORWARD tun→out, которое добавляет сам fptn-server — вместо того,\n"
        "# чтобы гадать по фиксированной паузе.\n"
        "for i in $(seq 1 30); do\n"
        '    "$IPT" -C FORWARD -i "$FPTN_TUN_IFACE" -o "$FPTN_OUT_IFACE" '
        '-j ACCEPT 2>/dev/null && break\n'
        "    sleep 0.5\n"
        "done\n"
        "\n"
        'if [ "$PRIOR_INPUT_POLICY" = "DROP" ]; then\n'
        '    "$IPT" -C INPUT -p tcp --dport "$FPTN_PORT" -j ACCEPT 2>/dev/null || \\\n'
        '        "$IPT" -I INPUT 1 -p tcp --dport "$FPTN_PORT" -j ACCEPT\n'
        '    "$IPT" -P INPUT DROP\n'
        "fi\n"
        "\n"
        'if [ "$PRIOR_FORWARD_POLICY" = "DROP" ]; then\n'
        "    # Правила ACCEPT для tun<->out интерфейсов добавляет сам\n"
        "    # fptn-server (RouteManager::Apply()) и не удаляет их до\n"
        "    # остановки сервиса — блокирующая политика FORWARD им не мешает.\n"
        '    "$IPT" -P FORWARD DROP\n'
        "fi\n"
        "\n"
        'if [ "$PRIOR_INPUT6_POLICY" = "DROP" ]; then\n'
        '    "$IP6T" -C INPUT -p tcp --dport "$FPTN_PORT" -j ACCEPT 2>/dev/null || \\\n'
        '        "$IP6T" -I INPUT 1 -p tcp --dport "$FPTN_PORT" -j ACCEPT\n'
        '    "$IP6T" -P INPUT DROP\n'
        "fi\n"
        "\n"
        'if [ "$PRIOR_FORWARD6_POLICY" = "DROP" ]; then\n'
        '    "$IP6T" -P FORWARD DROP\n'
        "fi\n"
    )
    _FW_RECONCILE.chmod(0o750)

def _update_fw_baseline_port(port: int) -> None:
    """Обновляет только FPTN_PORT в уже существующем baseline (смена порта
    без переустановки — снимок политики трогать не нужно)."""
    if not _FW_BASELINE.exists():
        return
    text = _FW_BASELINE.read_text()
    text = re.sub(r"(?m)^FPTN_PORT=.*$", f"FPTN_PORT={port}", text)
    _FW_BASELINE.write_text(text)

# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEMD
# ══════════════════════════════════════════════════════════════════════════════
def _install_service() -> None:
    _SERVICE_FILE.write_text(
        "[Unit]\n"
        "Description=FPTN Server\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "EnvironmentFile=" + str(_CFG_FILE) + "\n"
        f"ExecStart={_BIN_SERVER} "
        "--server-key=${SERVER_KEY} "
        "--server-crt=${SERVER_CRT} "
        "--out-network-interface=${OUT_NETWORK_INTERFACE} "
        "--server-port=${PORT} "
        "--tun-interface-name=${TUN_INTERFACE_NAME} "
        "--userfile=${USERFILE} "
        "--enable-detect-probing=${ENABLE_DETECT_PROBING} "
        "--default-proxy-domain=${DEFAULT_PROXY_DOMAIN} "
        "--allowed-sni-list=${ALLOWED_SNI_LIST} "
        "--disable-bittorrent=${DISABLE_BITTORRENT} "
        "--prometheus-access-key=${PROMETHEUS_SECRET_ACCESS_KEY} "
        "--use-remote-server-auth=${USE_REMOTE_SERVER_AUTH} "
        "--remote-server-auth-host=${REMOTE_SERVER_AUTH_HOST} "
        "--remote-server-auth-port=${REMOTE_SERVER_AUTH_PORT} "
        "--max-active-sessions-per-user=${MAX_ACTIVE_SESSIONS_PER_USER} "
        "--server-external-ips=${SERVER_EXTERNAL_IPS} "
        "--mtu-size=${MTU_SIZE}\n"
        # ExecStartPost — см. _write_fw_reconcile_hook(): восстанавливает
        # политику INPUT/FORWARD (v4 и v6) после КАЖДОГО старта (в т.ч. при
        # ребуте). Сам скрипт поллит появление правила FORWARD от fptn-server
        # вместо фиксированной паузы — см. докстринг функции.
        f"ExecStartPost={_FW_RECONCILE}\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "WorkingDirectory=" + str(_CFG_DIR) + "\n"
        "User=root\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", _SERVICE_NAME])

# ══════════════════════════════════════════════════════════════════════════════
#  server.conf
# ══════════════════════════════════════════════════════════════════════════════
def _write_server_conf(cfg: dict) -> None:
    _CFG_DIR.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Автоматически сгенерировано VLESS Ultimate Installer — модуль fptn.py",
        "# Формат — systemd EnvironmentFile (KEY=VALUE, без кавычек)",
        "",
        f"OUT_NETWORK_INTERFACE={cfg['out_iface']}",
        f"SERVER_KEY={_KEY_FILE}",
        f"SERVER_CRT={_CERT_FILE}",
        f"USERFILE={_USERS_FILE}",
        "",
        f"PORT={cfg['port']}",
        f"TUN_INTERFACE_NAME={cfg['tun_iface']}",
        f"MTU_SIZE={cfg.get('mtu', 1450)}",
        "",
        f"ENABLE_DETECT_PROBING={'true' if cfg.get('enable_detect_probing') else 'false'}",
        f"DEFAULT_PROXY_DOMAIN={cfg.get('default_proxy_domain', _DEFAULT_PROXY_DOMAIN)}",
        f"ALLOWED_SNI_LIST={cfg.get('allowed_sni_list', '')}",
        f"DISABLE_BITTORRENT={'true' if cfg.get('disable_bittorrent', True) else 'false'}",
        "",
        "# Мульти-серверная авторизация (мастер-нода) — не используется этим",
        "# инсталлятором, но флаг обязателен для fptn-server.",
        "USE_REMOTE_SERVER_AUTH=false",
        "REMOTE_SERVER_AUTH_HOST=",
        "REMOTE_SERVER_AUTH_PORT=443",
        "",
        f"PROMETHEUS_SECRET_ACCESS_KEY={cfg.get('prometheus_key', '')}",
        f"MAX_ACTIVE_SESSIONS_PER_USER={cfg.get('max_sessions', _DEFAULT_MAX_SESSIONS)}",
        f"SERVER_EXTERNAL_IPS={cfg.get('external_ips', '')}",
        "",
    ]
    _CFG_FILE.write_text("\n".join(lines) + "\n")
    _CFG_FILE.chmod(0o640)

# ══════════════════════════════════════════════════════════════════════════════
#  ПОЛЬЗОВАТЕЛИ (обёртка над fptn-passwd — username sha256(pass) bandwidth,
#  файл читается сервером "на лету" при изменении mtime, рестарт не нужен)
# ══════════════════════════════════════════════════════════════════════════════
def _passwd_add_user(username: str, password: str, bandwidth: int) -> tuple:
    if not _valid_username(username):
        return False, "Логин должен состоять только из латинских букв и цифр."
    r = _run(
        [str(_BIN_PASSWD), "--add-user", username,
         "--bandwidth", str(bandwidth), "--userfile", str(_USERS_FILE)],
        input_text=f"{password}\n{password}\n", timeout=15,
    )
    ok = r.returncode == 0 and "already exists" not in (r.stdout or "")
    if "already exists" in (r.stdout or ""):
        return False, f"Пользователь {username} уже существует."
    if not ok:
        return False, (r.stderr or r.stdout or "неизвестная ошибка")[:200]
    return True, "OK"

def _passwd_del_user(username: str) -> bool:
    r = _run(
        [str(_BIN_PASSWD), "--del-user", username, "--userfile", str(_USERS_FILE)],
        input_text="Y\n", timeout=15,
    )
    return r.returncode == 0

def _passwd_list_usernames() -> list:
    """Парсит `fptn-passwd --list` — формат: "username XXXXX bandwidth MB"
    (хэш пароля замаскирован сервером под X, поэтому берём только логин)."""
    if not _BIN_PASSWD.exists() or not _USERS_FILE.exists():
        return []
    r = _run([str(_BIN_PASSWD), "--list", "--userfile", str(_USERS_FILE)],
              capture=True, timeout=10)
    if r.returncode != 0:
        return []
    names = []
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        if parts:
            names.append(parts[0])
    return names

# ══════════════════════════════════════════════════════════════════════════════
#  ПРИМЕНЕНИЕ КОНФИГА / ПЕРЕЗАПУСК
# ══════════════════════════════════════════════════════════════════════════════
def _restart_and_reconcile() -> bool:
    """Перезапускает сервис. Восстановление firewall-политики выполняется
    самим systemd через ExecStartPost (см. _write_fw_reconcile_hook) —
    здесь только ждём и проверяем итоговый статус."""
    _run(["systemctl", "restart", _SERVICE_NAME])
    time.sleep(3)
    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    return r.stdout.strip() == "active"

# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА
# ══════════════════════════════════════════════════════════════════════════════
def _run_install() -> None:
    try: _run_install_inner()
    except _Cancelled:
        print(f"\n  {YELLOW}Установка прервана.{NC}\n"); _pause()

def _run_install_inner() -> None:
    os.system("clear")
    _box_top("🐙  УСТАНОВКА  •  FPTN")
    _box_row()

    arch = _detect_arch()
    if not arch:
        _box_err(f"Неподдерживаемая архитектура: {platform.machine()}")
        _box_bot(); _pause(); return
    if not shutil.which("dpkg-deb"):
        _box_err("dpkg-deb не найден — нужен Debian/Ubuntu.")
        _box_bot(); _pause(); return

    reinstall_keep_users = False
    if _is_installed():
        _box_warn("FPTN уже установлен.")
        _box_row()
        _box_item("1", "Переустановить (сохранить пользователей и baseline firewall)")
        _box_item("2", f"Переустановить полностью  {YELLOW}(новый сертификат, новые ключи){NC}")
        _box_item("Q", "← Отмена")
        _box_bot(); print()
        try:
            ch = _ask(f"{CYAN}Выбор [1/2/Q]: {NC}", c=True).strip().lower()
        except _Cancelled: return
        if ch == "q" or not ch: return
        if ch == "1":
            reinstall_keep_users = True
        elif ch == "2":
            _full_uninstall(silent=True)
        else:
            return

    state = _load_state()
    old_port    = state.get("port", _DEFAULT_PORT)
    old_service_name = state.get("service_name", "MyFptnServer")
    old_proxy_domain = state.get("default_proxy_domain", _DEFAULT_PROXY_DOMAIN)
    old_allowed_sni  = state.get("allowed_sni_list", "")

    os.system("clear")
    _box_top("🐙  НАСТРОЙКА  •  FPTN")
    _box_row()
    _box_info("FPTN — самостоятельный L3 VPN, отдельно от Xray/VLESS.")
    _box_info("Сканеры/зонды без FPTN-клиента прозрачно проксируются на")
    _box_info("указанный ниже 'легитимный' домен вместо отказа в соединении.")
    _box_row()
    _box_warn("Сервис при каждом старте временно трогает iptables (см. Гайд,")
    _box_warn("пункт 5) — этот модуль автоматически это компенсирует.")
    _box_bot(); print()

    try:
        while True:
            raw_port = _ask(f"  {CYAN}Порт [{old_port}]: {NC}", default=str(old_port), c=True)
            port = int(raw_port) if raw_port.isdigit() else old_port
            conflict = _port_conflict(port, ignore_own=old_port if reinstall_keep_users else None)
            if conflict:
                _box_warn(f"Порт {port} уже занят: {conflict}")
                _box_warn("Если там VLESS/Xray или другой протокол этого "
                          "инсталлятора — выберите другой порт.")
                continue
            break

        service_name = _ask(
            f"  {CYAN}Имя сервиса (для токена, любое) [{old_service_name}]: {NC}",
            default=old_service_name, c=True,
        ).strip() or old_service_name

        proxy_domain = _ask(
            f"  {CYAN}Домен для маскировки не-VPN трафика [{old_proxy_domain}]: {NC}",
            default=old_proxy_domain, c=True,
        ).strip() or old_proxy_domain

        allowed_sni = _ask(
            f"  {CYAN}Белый список SNI через запятую (Enter=пропустить, "
            f"пускать все на их собственный SNI) [{old_allowed_sni or '—'}]: {NC}",
            default=old_allowed_sni, c=True,
        ).strip()
    except _Cancelled: raise

    server_ip = _get_server_ip()

    # ── Установка ─────────────────────────────────────────────────────────
    os.system("clear")
    _box_top("🐙  УСТАНОВКА  •  FPTN")
    _box_row()
    _box_info("Скачиваю официальный .deb-релиз и распаковываю бинарники...")
    _box_bot(); print()

    ok, msg = _download_binaries()
    if not ok:
        os.system("clear"); _box_top("🐙  УСТАНОВКА  •  FPTN")
        _box_err(msg); _box_bot(); _pause(); return
    print(f"  {GREEN}✓{NC}  {msg}")

    out_iface = _detect_out_iface()
    if not out_iface:
        _box_warn("Не удалось автоопределить исходящий интерфейс — укажите вручную.")
        try:
            out_iface = _ask(f"  {CYAN}Исходящий сетевой интерфейс: {NC}", c=True).strip()
        except _Cancelled: raise
    print(f"  {GREEN}✓{NC}  Исходящий интерфейс: {out_iface}")

    # Снимок политики firewall — берём ОДИН раз, до первого старта сервиса,
    # чтобы не перепутать её с тем, что сам fptn-server потом выставит.
    # Снимаем оба стека (iptables и ip6tables — fptn-server трогает оба).
    if reinstall_keep_users and _FW_BASELINE.exists():
        print(f"  {DIM}→  Снимок политики firewall сохранён с прошлой установки.{NC}")
    else:
        prior_input    = _get_chain_policy("INPUT", "iptables")
        prior_forward  = _get_chain_policy("FORWARD", "iptables")
        prior_input6   = _get_chain_policy("INPUT", "ip6tables")
        prior_forward6 = _get_chain_policy("FORWARD", "ip6tables")
        _write_fw_reconcile_hook(port, _DEFAULT_TUN_IFACE, out_iface,
                                  prior_input, prior_forward, prior_input6, prior_forward6)
        print(f"  {GREEN}✓{NC}  Снимок политики firewall: "
              f"INPUT={prior_input}/{prior_input6}(v6), "
              f"FORWARD={prior_forward}/{prior_forward6}(v6)")
    _update_fw_baseline_port(port)

    # Сертификат
    if not _CERT_FILE.exists() or not reinstall_keep_users:
        if not _gen_selfsigned_cert(server_ip):
            _box_err("openssl не смог создать сертификат.")
            _pause(); return
        print(f"  {GREEN}✓{NC}  Самоподписанный сертификат создан.")
    else:
        print(f"  {DIM}→  Существующий сертификат сохранён.{NC}")

    cfg = {
        "out_iface": out_iface, "port": port, "tun_iface": _DEFAULT_TUN_IFACE,
        "default_proxy_domain": proxy_domain, "allowed_sni_list": allowed_sni,
        "disable_bittorrent": True, "external_ips": server_ip,
        "max_sessions": state.get("max_sessions", _DEFAULT_MAX_SESSIONS),
        "prometheus_key": state.get("prometheus_key", ""),
    }
    _write_server_conf(cfg)
    print(f"  {GREEN}✓{NC}  server.conf записан.")

    _install_service()
    print(f"  {GREEN}✓{NC}  systemd-юнит установлен.")

    # Первый пользователь
    existing_users = _passwd_list_usernames() if reinstall_keep_users else []
    first_user_created = None
    if not existing_users:
        first_user, first_pass = "admin", _gen_password()
        ok, msg2 = _passwd_add_user(first_user, first_pass, _DEFAULT_BANDWIDTH_MB)
        if ok:
            first_user_created = (first_user, first_pass)
            _save_user_to_state(first_user, first_pass, _DEFAULT_BANDWIDTH_MB)
            print(f"  {GREEN}✓{NC}  Создан первый пользователь: "
                  f"{YELLOW}{first_user}{NC} / {YELLOW}{first_pass}{NC}")
        else:
            print(f"  {YELLOW}⚠{NC}  Не удалось создать пользователя: {msg2}")

    fw_msg = _open_port(port)
    print(f"  {GREEN}✓{NC}  {fw_msg}")

    svc_ok = _restart_and_reconcile()

    _save_state({
        "installed": True, "port": port, "service_name": service_name,
        "default_proxy_domain": proxy_domain, "allowed_sni_list": allowed_sni,
        "out_iface": out_iface, "server_ip": server_ip,
        "max_sessions": cfg["max_sessions"], "prometheus_key": cfg["prometheus_key"],
    })

    os.system("clear")
    _box_top("✅  УСТАНОВКА ЗАВЕРШЕНА  •  FPTN")
    _box_row()
    _box_ok("fptn-server установлен и запущен." if svc_ok else
            "Установлен, но сервис не запустился — проверьте логи (пункт статуса).")
    _box_row()
    _box_kv("Порт:",   f"{YELLOW}{server_ip}:{port}{NC}")
    _box_kv("Маскировка:", f"{DIM}{proxy_domain}{NC}")
    _box_row()
    if first_user_created:
        u, p = first_user_created
        _box_sep()
        _box_row(f"  {BOLD}{WHITE}Первый пользователь:{NC}")
        _box_row()
        _box_kv("  Логин:", f"{YELLOW}{u}{NC}")
        _box_kv("  Пароль:", f"{YELLOW}{p}{NC}")
        _box_row()
        token = _gen_fptn_token(u, p, server_ip, service_name, port)
        _box_row(f"  {BOLD}{WHITE}Токен (для fptn-client):{NC}")
        _box_row()
        _box_link(token)
    _box_row()
    _box_sep()
    _box_info("Добавляйте пользователей через пункт [2] меню.")
    _box_bot()
    print()
    if first_user_created:
        _print_qr(token, f"fptn: токен для {first_user_created[0]}")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ПОЛЬЗОВАТЕЛИ — МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════
def _users_menu() -> None:
    while True:
        os.system("clear")
        state = _load_state()
        usernames = _passwd_list_usernames()
        server_ip = state.get("server_ip") or _get_server_ip()
        port = state.get("port", _DEFAULT_PORT)

        _box_top("👥  ПОЛЬЗОВАТЕЛИ  •  FPTN")
        _box_row()
        _box_kv("Пользователей:", str(len(usernames)))
        _box_kv("Сервер:", f"{server_ip}:{port}")
        _box_row(); _box_sep()

        if usernames:
            for i, u in enumerate(usernames, 1):
                _box_row(f"  {DIM}{i:<4}{NC}{CYAN}{u}{NC}")
        else:
            _box_warn("Пользователей нет.")

        _box_row(); _box_sep()
        _box_item("1", "➕  Добавить пользователя")
        _box_item("2", "🔗  Показать токен + QR для пользователя")
        _box_item("3", f"{RED}🗑️   Удалить пользователя{NC}")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled: break

        if ch == "1":
            try: _add_user_flow()
            except _Cancelled: pass
        elif ch == "2":
            try: _show_user_token(usernames, server_ip, port)
            except _Cancelled: pass
        elif ch == "3":
            try: _delete_user_flow(usernames)
            except _Cancelled: pass
        elif ch in ("q", ""): break

def _add_user_flow() -> None:
    os.system("clear")
    _box_top("➕  ДОБАВИТЬ ПОЛЬЗОВАТЕЛЯ  •  FPTN")
    _box_row()
    _box_info("Логин — только латинские буквы и цифры (без дефисов/точек).")
    _box_bot(); print()

    try:
        username = _ask(f"  {CYAN}Логин: {NC}", c=True).strip()
        if not username:
            print(f"  {RED}✗{NC}  Логин не может быть пустым."); _pause(); return
        if not _valid_username(username):
            print(f"  {RED}✗{NC}  Только латинские буквы и цифры."); _pause(); return

        raw_bw = _ask(
            f"  {CYAN}Лимит скорости, Мбит/с [{_DEFAULT_BANDWIDTH_MB}]: {NC}",
            default=str(_DEFAULT_BANDWIDTH_MB), c=True,
        )
        bandwidth = int(raw_bw) if raw_bw.isdigit() else _DEFAULT_BANDWIDTH_MB

        raw_pass = _ask(f"  {CYAN}Пароль (Enter=авто): {NC}", default="", c=True).strip()
        password = raw_pass or _gen_password()
    except _Cancelled: raise

    ok, msg = _passwd_add_user(username, password, bandwidth)
    if not ok:
        print(f"  {RED}✗{NC}  {msg}"); _pause(); return
    _save_user_to_state(username, password, bandwidth)

    state = _load_state()
    server_ip = state.get("server_ip") or _get_server_ip()
    port = state.get("port", _DEFAULT_PORT)
    service_name = state.get("service_name", "MyFptnServer")
    token = _gen_fptn_token(username, password, server_ip, service_name, port)

    os.system("clear")
    _box_top("✅  ПОЛЬЗОВАТЕЛЬ ДОБАВЛЕН  •  FPTN")
    _box_row()
    _box_kv("Логин:", f"{YELLOW}{username}{NC}")
    _box_kv("Пароль:", f"{YELLOW}{password}{NC}")
    _box_kv("Лимит:", f"{bandwidth} Мбит/с")
    _box_info("users.list читается сервером на лету — рестарт не нужен.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Токен:{NC}")
    _box_row()
    _box_link(token)
    _box_row()
    _box_bot()
    print()
    _print_qr(token, f"fptn: токен для {username}")
    _pause()

def _show_user_token(usernames: list, server_ip: str, port: int) -> None:
    if not usernames:
        print(f"  {YELLOW}⚠{NC}  Пользователей нет."); _pause(); return
    os.system("clear")
    _box_top("🔗  ТОКЕН ДЛЯ ПОЛЬЗОВАТЕЛЯ  •  FPTN")
    _box_row()
    for i, u in enumerate(usernames, 1):
        _box_row(f"  {DIM}{i}.{NC}  {CYAN}{u}{NC}")
    _box_row(); _box_item("Q", "← Отмена"); _box_bot(); print()

    try:
        num = _ask(f"{CYAN}Номер: {NC}", c=True).strip()
    except _Cancelled: raise
    if num.lower() == "q" or not num: return
    try:
        username = usernames[int(num) - 1]
    except (ValueError, IndexError):
        print(f"  {RED}✗{NC}  Неверный номер."); _pause(); return

    _box_warn("Пароль пользователя нигде не хранится в открытом виде после")
    _box_warn("создания (users.list содержит только sha256-хэш) — токен можно")
    _box_warn("перегенерировать только с НОВЫМ паролем, старый клиент придётся")
    _box_warn("переподключить заново.")
    try:
        confirm = _ask(
            f"  {YELLOW}Сгенерировать новый пароль для {username} и выдать новый токен? [y/N]: {NC}",
            default="n", c=True,
        ).strip().lower()
    except _Cancelled: raise
    if confirm != "y": return

    new_password = _gen_password()
    if not _passwd_del_user(username):
        print(f"  {RED}✗{NC}  Не удалось удалить старую запись."); _pause(); return
    ok, msg = _passwd_add_user(username, new_password, _DEFAULT_BANDWIDTH_MB)
    if not ok:
        print(f"  {RED}✗{NC}  {msg}"); _pause(); return
    _save_user_to_state(username, new_password, _DEFAULT_BANDWIDTH_MB)

    state = _load_state()
    service_name = state.get("service_name", "MyFptnServer")
    token = _gen_fptn_token(username, new_password, server_ip, service_name, port)

    os.system("clear")
    _box_top(f"🔗  {username}  •  FPTN")
    _box_row()
    _box_kv("Логин:", f"{YELLOW}{username}{NC}")
    _box_kv("Новый пароль:", f"{YELLOW}{new_password}{NC}")
    _box_row(); _box_sep()
    _box_link(token)
    _box_row(); _box_bot()
    print()
    _print_qr(token, f"fptn: токен для {username}")
    _pause()

def _delete_user_flow(usernames: list) -> None:
    if not usernames:
        print(f"  {YELLOW}⚠{NC}  Пользователей нет."); _pause(); return
    if len(usernames) == 1:
        print(f"  {RED}✗{NC}  Нельзя удалить последнего пользователя."); _pause(); return

    os.system("clear")
    _box_top("🗑️  УДАЛИТЬ ПОЛЬЗОВАТЕЛЯ  •  FPTN")
    _box_row()
    for i, u in enumerate(usernames, 1):
        _box_row(f"  {DIM}{i}.{NC}  {CYAN}{u}{NC}")
    _box_row(); _box_item("Q", "← Отмена"); _box_bot(); print()

    try:
        num = _ask(f"{CYAN}Номер: {NC}", c=True).strip()
    except _Cancelled: raise
    if num.lower() == "q" or not num: return
    try:
        username = usernames[int(num) - 1]
    except (ValueError, IndexError):
        print(f"  {RED}✗{NC}  Неверный номер."); _pause(); return

    try:
        confirm = _ask(
            f"  {YELLOW}Удалить {username}? [y/N]: {NC}", default="n", c=True,
        ).strip().lower()
    except _Cancelled: raise
    if confirm != "y": return

    if _passwd_del_user(username):
        _remove_user_from_state(username)
        print(f"  {GREEN}✓{NC}  Пользователь удалён (users.list подхватится сервером на лету).")
    else:
        print(f"  {RED}✗{NC}  Не удалось удалить пользователя.")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС
# ══════════════════════════════════════════════════════════════════════════════
def _show_status() -> None:
    os.system("clear")
    state = _load_state()
    _box_top("📊  СТАТУС  •  FPTN")
    _box_row()

    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    svc_ok = r.stdout.strip() == "active"
    _box_kv("Сервис:", f"{GREEN}● активен{NC}" if svc_ok else f"{RED}● остановлен{NC}")
    _box_kv("Порт:", f"{state.get('server_ip','—')}:{state.get('port','—')}")
    _box_kv("Пользователей:", str(len(_passwd_list_usernames())))

    if _FW_BASELINE.exists():
        try:
            baseline_text = _FW_BASELINE.read_text()
        except Exception:
            baseline_text = ""

        def _fw_note(policy_key: str, cmd: str, chain: str) -> str:
            m = re.search(rf"{policy_key}=(\w+)", baseline_text)
            prior = m.group(1) if m else "?"
            cur = _get_chain_policy(chain, cmd)
            if prior == "DROP" and cur == "DROP":
                return f"{GREEN}✓ восстановлена ({prior}){NC}"
            if prior != "DROP":
                return f"{DIM}не требовалось ({prior}){NC}"
            return f"{YELLOW}⚠ сейчас {cur}, ожидался DROP{NC}"

        _box_kv("Firewall INPUT v4:", _fw_note("PRIOR_INPUT_POLICY", "iptables", "INPUT"))
        _box_kv("Firewall INPUT v6:", _fw_note("PRIOR_INPUT6_POLICY", "ip6tables", "INPUT"))

    _box_row(); _box_sep()
    _box_row(f"  {BOLD}{WHITE}Последние 30 строк журнала:{NC}")
    _box_row()
    r2 = subprocess.run(
        ["journalctl", "-u", _SERVICE_NAME, "-n", "30",
         "--no-pager", "--output=short-monotonic"],
        capture_output=True, encoding="utf-8", errors="replace",
        env={**os.environ, "LANG": "C.UTF-8"},
    )
    for line in (r2.stdout or "Нет записей").splitlines():
        _box_log_line(line)
    _box_row(); _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ГАЙД
# ══════════════════════════════════════════════════════════════════════════════
def _show_guide() -> None:
    while True:
        os.system("clear")
        _box_top("📖  ГАЙД  •  FPTN")
        _box_row()
        _box_item("1", "Как работает FPTN")
        _box_item("2", "Клиентское приложение и токен")
        _box_item("3", "Требования (arch, dpkg-deb)")
        _box_item("4", "Пользователи и users.list")
        _box_item("5", f"{YELLOW}⚠  Firewall — что важно знать{NC}")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled: break

        if ch == "1":   _guide_how()
        elif ch == "2": _guide_client()
        elif ch == "3": _guide_requirements()
        elif ch == "4": _guide_users()
        elif ch == "5": _guide_firewall()
        elif ch in ("q", ""): break

def _guide_how() -> None:
    os.system("clear")
    _box_top("⚙️  КАК РАБОТАЕТ FPTN")
    _box_row()
    _box_info("FPTN — не инбаунд Xray, а самостоятельный L3 VPN (свой")
    _box_info("TUN-туннель, свой протокол на Protobuf поверх TLS).")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Анти-пробинг — honeypot-прокси, а не Reality:{NC}")
    _box_row()
    _box_info("Сканер без FPTN-клиента подключается на тот же порт →")
    _box_info("сервер САМ проксирует его TLS-сессию на живой домен")
    _box_info("(DEFAULT_PROXY_DOMAIN / ALLOWED_SNI_LIST) — сканер видит")
    _box_info("настоящий сайт, а не отказ или голый TLS-хэндшейк.")
    _box_row()
    _box_sep()
    _box_row(f"  {CYAN}Клиент → TLS:443 → fptn-server → (не свой? → сайт-прикрытие){NC}")
    _box_row(f"  {CYAN}                              → (свой? → TUN → NAT → интернет){NC}")
    _box_bot(); _pause()

def _guide_client() -> None:
    os.system("clear")
    _box_top("📱  КЛИЕНТ И ТОКЕН  •  FPTN")
    _box_row()
    _box_info("Официальный клиент fptn-client (GUI и CLI) — Windows/macOS/")
    _box_info("Linux/Android; поддерживает импорт токена целиком.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Формат токена:{NC}")
    _box_row()
    _box_row(f"  {DIM}fptn:<base64(json)>{NC}")
    _box_info("Внутри — сервер, порт, логин/пароль и md5-отпечаток")
    _box_info("сертификата (для сверки на клиенте — не полноценный TLS PKI,")
    _box_info("а pinning по самоподписанному сертификату).")
    _box_row()
    _box_sep()
    _box_warn("Пароль хранится только в users.list как sha256-хэш —")
    _box_warn("если токен потерян, проще выдать новый пароль (пункт [2]")
    _box_warn("меню пользователей), чем 'восстановить' старый.")
    _box_bot(); _pause()

def _guide_requirements() -> None:
    os.system("clear")
    _box_top("📋  ТРЕБОВАНИЯ  •  FPTN")
    _box_row()
    _box_row(f"  {BOLD}{WHITE}Что нужно:{NC}")
    _box_row()
    _box_info("1. Debian/Ubuntu-сервер с dpkg-deb (штатно есть везде)")
    _box_info("2. Архитектура amd64 или arm64")
    _box_info("3. Порт (по умолчанию 443/tcp) открыт")
    _box_info("4. Домен НЕ обязателен — сертификат самоподписанный, клиент")
    _box_info("   сверяет md5-отпечаток из токена, а не цепочку CA")
    _box_row()
    _box_sep()
    _box_info("Бинарники ставятся из официального .deb-релиза через")
    _box_info("`dpkg-deb -x` — БЕЗ `dpkg -i` (не трогаем систему пакетов) и")
    _box_info("БЕЗ Docker.")
    _box_bot(); _pause()

def _guide_users() -> None:
    os.system("clear")
    _box_top("👥  ПОЛЬЗОВАТЕЛИ  •  FPTN")
    _box_row()
    _box_info("Управление — через штатный fptn-passwd (не свой формат).")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}users.list:{NC}")
    _box_row()
    _box_row(f"  {DIM}username sha256(password) bandwidth_mbit{NC}")
    _box_row()
    _box_info("Логин — ТОЛЬКО [A-Za-z0-9], без дефисов/подчёркиваний/точек")
    _box_info("(так проверяет сам fptn-passwd).")
    _box_row()
    _box_info("Файл читается сервером 'на лету' при изменении mtime —")
    _box_info("добавление/удаление пользователя НЕ требует рестарта сервиса.")
    _box_bot(); _pause()

def _guide_firewall() -> None:
    os.system("clear")
    _box_top("⚠️  FIREWALL  •  FPTN")
    _box_row()
    _box_warn("fptn-server при КАЖДОМ старте безусловно выполняет:")
    _box_row(f"  {DIM}iptables  -P INPUT/FORWARD/OUTPUT ACCEPT{NC}")
    _box_row(f"  {DIM}ip6tables -P INPUT/FORWARD/OUTPUT ACCEPT{NC}")
    _box_row()
    _box_info("Это внутренняя логика самого fptn-server (RouteManager) —")
    _box_info("инсталлятор это НЕ настраивает и не может отключить флагом.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Как это компенсируется:{NC}")
    _box_row()
    _box_info("При установке снимается снимок текущей политики INPUT/")
    _box_info("FORWARD для ОБОИХ стеков (iptables и ip6tables) →")
    _box_info("/etc/fptn/fw-baseline.env")
    _box_info("В systemd-юнит добавлен ExecStartPost →")
    _box_info("/etc/fptn/fw-reconcile.sh — восстанавливает DROP (если она")
    _box_info("была) ПОСЛЕ каждого старта, включая автозапуск при ребуте.")
    _box_info("Скрипт ждёт (до 15 сек) появления правила FORWARD, которое")
    _box_info("сам fptn-server добавляет при старте — а не спит фиксированное")
    _box_info("время наугад.")
    _box_row()
    _box_sep()
    _box_warn("Политика OUTPUT сознательно НЕ восстанавливается — сделать")
    _box_warn("это безопасно автоматически нельзя (риск заблокировать сам")
    _box_warn("сервер). Если у вас была строгая OUTPUT-политика — проверьте")
    _box_warn("её вручную после установки FPTN.")
    _box_row()
    _box_warn("Снимок политики берётся ОДИН раз, при установке. Если после")
    _box_warn("установки FPTN вы вручную поменяете политику INPUT/FORWARD —")
    _box_warn("баланс не обновится сам; переустановите модуль (пункт [1] →")
    _box_warn("'переустановить полностью') чтобы снять новый снимок.")
    _box_bot(); _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _full_uninstall(silent: bool = False) -> bool:
    if not silent:
        os.system("clear")
        _box_top("🗑️  УДАЛЕНИЕ  •  FPTN")
        _box_row()
        _box_warn("Будет удалено:")
        _box_row(f"  {DIM}  • Сервис systemd  (fptn-server){NC}")
        _box_row(f"  {DIM}  • Бинарники       (fptn-server, fptn-passwd){NC}")
        _box_row(f"  {DIM}  • Конфиги          ({_CFG_DIR}){NC}")
        _box_row(f"  {DIM}  • Правило firewall для порта{NC}")
        _box_row()
        _box_warn("Xray, VLESS и другие службы не затрагиваются.")
        _box_row()
        _box_item("Y", f"{RED}Да, удалить{NC}")
        _box_item("N", "Нет, отмена")
        _box_bot(); print()
        try:
            ans = _ask(f"{CYAN}Подтверждение [y/N]: {NC}", c=True).strip().lower()
        except _Cancelled: return False
        if ans != "y":
            print(f"  {DIM}Отменено.{NC}"); _pause(); return False

    state = _load_state()
    port = state.get("port", _DEFAULT_PORT)

    _run(["systemctl", "stop", _SERVICE_NAME])
    _run(["systemctl", "disable", _SERVICE_NAME])
    if _SERVICE_FILE.exists(): _SERVICE_FILE.unlink()
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "reset-failed"], capture=True)

    for p in (_BIN_SERVER, _BIN_PASSWD):
        if p.exists(): p.unlink()
    if _CFG_DIR.exists():
        shutil.rmtree(_CFG_DIR, ignore_errors=True)

    _close_port(port)

    try:
        if _MODULE_STATE.exists(): _MODULE_STATE.unlink()
    except Exception: pass

    if not silent:
        print(f"  {GREEN}✓{NC}  FPTN полностью удалён.")
        _pause()
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════
def do_fptn_menu() -> None:
    """Точка входа из _core.py."""
    while True:
        os.system("clear")
        installed = _is_installed()
        state = _load_state()

        r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
        svc_ok = r.stdout.strip() == "active"

        svc_str = (
            f"{GREEN}● активен{NC}"  if svc_ok    else
            f"{RED}● остановлен{NC}" if installed else
            f"{YELLOW}● не установлен{NC}"
        )

        _box_top("FPTN  •  Protobuf/TLS L3-VPN, honeypot-прокси")
        _box_row()
        _box_kv("Статус:", svc_str)

        if installed:
            _box_kv("Порт:", f"{YELLOW}{state.get('server_ip','—')}:{state.get('port','—')}{NC}")
            _box_kv("Пользователей:", str(len(_passwd_list_usernames())))

        _box_row(); _box_sep()

        if not installed:
            _box_item("1", "🚀  Установить FPTN")
        else:
            _box_item("1", "🚀  Переустановить")
            _box_item("2", "👥  Управление пользователями")
            _box_item("3", "🔄  Перезапустить сервис")
            _box_item("5", "📊  Статус / логи")
            _box_sep()
            _box_item("9", f"{RED}🗑️   Удалить FPTN{NC}")

        _box_sep()
        _box_item("G", "📖  Гайд: как работает, клиент, firewall")
        _box_sep()
        _box_item("Q", "← Назад в главное меню VLESS")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled: break

        if ch == "1":
            _run_install()
        elif ch == "2" and installed:
            try: _users_menu()
            except _Cancelled: pass
        elif ch == "3" and installed:
            ok = _restart_and_reconcile()
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
        do_fptn_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}"); sys.exit(0)
