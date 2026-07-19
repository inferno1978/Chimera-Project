"""
chimera/modules/snell.py
───────────────────────────────────────────────────────────────────────────────
Snell v4 — Surge MTProto-подобный протокол (nssurge.com).

Закрытый бинарник от команды Surge, распространяется как готовый zip-архив
по прямой ссылке dl.nssurge.com. Лицензионных проблем нет (как с Hysteria2/
Xray — мы просто скачиваем и оборачиваем официальный релиз). Python-обвязка
написана с нуля, ориентируясь на стиль chimera/modules/naiveproxy.py и
chimera/modules/mieru.py.

Архитектура (per-user systemd template):
  - Один systemd template unit: snell-server@.service (%i = username)
  - Per-user конфиг: /etc/snell/<user>.conf (INI-формат)
  - Per-user порт из диапазона 30000-30999
  - Per-user PSK (32 байта, base64)
  - Per-user UFW/iptables правило на TCP-порт
  - Per-user traffic accounting через snell_stats.py (SNELL_STATS_IN/OUT chains)

obfs:
  - tls (по умолчанию) — маскировка под HTTPS, требует LE-сертификат на
    obfs-host. Реальный TLS-handshake, выглядит как настоящий HTTPS на
    домене-доноре. Устойчив к DPI-детекции.
  - http — маскировка под HTTP. Проще, но детектируется по отсутствию
    TLS-handshake.
  - off — без обфускации. Только для тестов или сетей без DPI-блокировки Snell.

Клиентская ссылка (формат для Clash Meta и совместимых):
  snell://<urlencoded_psk>@<server>:<port>?obfs=<tls|http|off>&obfs-host=<host>#<tag>

Интеграция в Chimera:
  - TUI-меню вызывается из _core.py как пункт "19"
  - rest_api.py: /api/portal/links добавляет snell:// ссылку
  - subscription.py: _build_snell_uris() добавляет ссылку в подписку
  - status_panel.py: _check_snell() в общем списке протоколов
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

from chimera.modules.text_width import wlen as _wlen, plain as _plain
from chimera.modules.proto_common import (
    ProtoCancelled, proto_load_state, proto_save_state,
    proto_ask, proto_gen_password, proto_ipt_persist,
    proto_get_latest_version, proto_get_installed_version,
)
_Cancelled = ProtoCancelled

from chimera.modules.snell_mirrors import (
    SNELL_DEFAULT_VERSION,
    SNELL_MIRRORS_COUNT,
    get_snell_mirrors,
    recommended_manual_path,
    find_manual_upload,
    print_snell_manual_download_hint,
    _snell_filename,
    _arch_suffix,
)
from chimera.modules.snell_packages import SNELL_SPEC, _SNELL_BIN

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
#  ПУТИ И КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════
# Бинарник snell-server — один на всех, просто /usr/local/bin/snell-server.
# Per-user инстансы запускают его с разными конфигами через %i.
BIN_PATH          = Path("/usr/local/bin/snell-server")

# Директория с per-user конфигами. Формат имени: <username>.conf
CONFIG_DIR        = Path("/etc/snell")

# systemd template unit: /etc/systemd/system/snell-server@.service
# Запуск инстанса: systemctl start snell-server@<username>
# %i в ExecStart подставляется systemd-ом автоматически.
SERVICE_TEMPLATE  = Path("/etc/systemd/system/snell-server@.service")
SERVICE_NAME      = "snell-server@"   # с @ — template, без @ — конкретный инстанс

# State — глобальный для модуля. Per-user данные в state["users"].
MODULE_STATE      = Path("/var/lib/xray-installer/snell.json")

# Диапазон per-user портов. 1000 слотов — достаточно для типичной установки.
# Не конфликтует ни с чем в Chimera (8443/443/10808-10811 заняты, 20000-20999
# зарезервированы под mieru port hopping, 30000-30999 — наш).
PORT_RANGE_START  = 30000
PORT_RANGE_END    = 30999

# obfs по умолчанию — tls (маскировка под HTTPS, требует LE-сертификат).
DEFAULT_OBFS      = "tls"

# Размер PSK в байтах (32 = 256 бит). Surge поддерживает произвольную длину,
# но 32 байта — стандарт для большинства клиентов.
PSK_BYTES         = 32

# Magic-домен для obfs-host по умолчанию. Реально должен быть домен с
# валидным LE-сертификатом — берётся из state.json (PARAM_DOMAIN).
DEFAULT_OBFS_HOST = "www.cloudflare.com"

# GitHub API для получения последней версии snell (через репак passeway/Snell).
GITHUB_API        = "https://api.github.com/repos/passeway/Snell/releases/latest"

# Box width — 66, как у mieru/naiveproxy (стандарт для protocol-модулей).
_BOX_W = 66

# ── Логирование ──────────────────────────────────────────────────────────────
LOG_FILE = Path("/var/log/chimera.log")

def _log(msg: str) -> None:
    """Пишет строку в общий лог Chimera с timestamp."""
    try:
        from datetime import datetime as _dt
        ts = _dt.now().strftime("%Y-%m-%d %H:%M:%S")
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"[{ts}] [SNELL] {msg}\n")
    except Exception:
        pass

def _info(msg: str) -> None: print(f"  {CYAN}→{NC}  {msg}"); _log(f"[INFO] {msg}")
def _ok(msg: str)   -> None: print(f"  {GREEN}✓{NC}  {msg}"); _log(f"[OK] {msg}")
def _warn(msg: str) -> None: print(f"  {YELLOW}⚠{NC}  {msg}"); _log(f"[WARN] {msg}")
def _err(msg: str)  -> None: print(f"  {RED}✗{NC}  {msg}"); _log(f"[ERR] {msg}")

# ══════════════════════════════════════════════════════════════════════════════
#  BOX RENDERING (в точности как в mieru/naiveproxy/mtproto — единый стиль)
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
        # Обрезаем длинные строки с добавлением …
        plain_str = _plain(text); cut = 0; acc = 0
        for i, ch in enumerate(plain_str):
            import unicodedata as _ud
            acc += 2 if _ud.east_asian_width(ch) in ('W', 'F') else 1
            if acc > _BOX_W - 1:
                cut = i; break
        text = text[:cut] + "…"
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
         cwd: Optional[str] = None):
    kw: dict = {"check": check}
    if cwd:
        kw["cwd"] = cwd
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def _get_server_ip() -> str:
    """Локальный IP или публичный — для генерации клиентской ссылки."""
    try:
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

def _get_state_domain() -> str:
    """Читает domain из основного state.json Chimera — нужно для obfs-host."""
    try:
        core_state = Path("/var/lib/xray-installer/state.json")
        if core_state.exists():
            st = json.loads(core_state.read_text())
            return st.get("domain", "") or st.get("PARAM_DOMAIN", "") or ""
    except Exception:
        pass
    return ""

def _is_installed() -> bool:
    """Snell установлен если есть бинарник + template unit + CONFIG_DIR."""
    return (BIN_PATH.exists() and SERVICE_TEMPLATE.exists()
            and CONFIG_DIR.exists())

def _is_amd64() -> bool:
    return platform.machine().lower() in ("x86_64", "amd64")

def _get_installed_version() -> Optional[str]:
    """Получает версию установленного бинарника через --version."""
    try:
        return proto_get_installed_version(BIN_PATH, version_arg="--version",
                                            strip_v=True)
    except Exception:
        return None

def _get_latest_version() -> str:
    """Получает latest версию с GitHub API (через репак passeway/Snell)."""
    try:
        return proto_get_latest_version(GITHUB_API, strip_v=True)
    except Exception:
        return SNELL_DEFAULT_VERSION

# ══════════════════════════════════════════════════════════════════════════════
#  UFW / IPTABLES (для per-user портов)
# ══════════════════════════════════════════════════════════════════════════════
def _ufw_is_active() -> bool:
    if not shutil.which("ufw"):
        return False
    r = _run(["ufw", "status"], capture=True)
    if not r.stdout:
        return False
    # "inactive" содержит "active" — проверяем точное "Status: active"
    return "status: active" in r.stdout.lower()

def _ufw_open_tcp(port: int, comment: str = "snell") -> None:
    if not _ufw_is_active():
        return
    _run(["ufw", "allow", f"{port}/tcp", "comment", comment], capture=True)

def _ufw_close_tcp(port: int) -> None:
    if not _ufw_is_active():
        return
    _run(["ufw", "delete", "allow", f"{port}/tcp"], capture=True)

def _ipt_tcp_rule_exists(port: int) -> bool:
    r = _run(
        ["iptables", "-t", "filter", "-C", "INPUT",
         "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
        capture=True,
    )
    return r.returncode == 0

def _ipt_open_tcp(port: int) -> None:
    if not _ipt_tcp_rule_exists(port):
        _run(["iptables", "-t", "filter", "-I", "INPUT", "1",
              "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])
        proto_ipt_persist()

def _ipt_close_tcp(port: int) -> None:
    for _ in range(5):
        if not _ipt_tcp_rule_exists(port):
            break
        _run(["iptables", "-t", "filter", "-D", "INPUT",
              "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])
    proto_ipt_persist()

def _open_port(port: int, username: str) -> str:
    """Открывает TCP-порт для конкретного юзера. Возвращает описание действия."""
    comment = f"snell-{username}"
    if _ufw_is_active():
        _ufw_open_tcp(port, comment)
        return f"UFW: TCP {port} открыт для {username}"
    _ipt_open_tcp(port)
    return f"iptables: TCP {port} открыт для {username}"

def _close_port(port: int) -> None:
    """Закрывает TCP-порт и в UFW, и в iptables (на всякий случай)."""
    _ufw_close_tcp(port)
    _ipt_close_tcp(port)

# ══════════════════════════════════════════════════════════════════════════════
#  PSK GENERATION
# ══════════════════════════════════════════════════════════════════════════════
def _generate_psk() -> str:
    """Генерирует PSK (Pre-Shared Key) — 32 байта, base64.

    Surge принимает PSK в виде произвольной строки. base64 от 32 случайных
    байт — стандартный выбор, даёт 44-символьную строку без спецсимволов.
    """
    return base64.b64encode(secrets.token_bytes(PSK_BYTES)).decode("ascii")

# ══════════════════════════════════════════════════════════════════════════════
#  PORT ALLOCATION
# ══════════════════════════════════════════════════════════════════════════════
def _allocated_ports(state: dict) -> set:
    """Возвращает множество уже занятых портов из state."""
    return {u.get("port", 0) for u in state.get("users", []) if u.get("port")}

def _allocate_port(state: dict) -> int:
    """Выделяет свободный порт из диапазона 30000-30999.

    Если все порты заняты — поднимает RuntimeError (1000 слотов кончились).
    """
    used = _allocated_ports(state)
    for port in range(PORT_RANGE_START, PORT_RANGE_END + 1):
        if port not in used:
            return port
    raise RuntimeError(
        f"Все порты {PORT_RANGE_START}-{PORT_RANGE_END} заняты. "
        f"Удалите ненужных пользователей или расширьте диапазон."
    )

# ══════════════════════════════════════════════════════════════════════════════
#  USERNAME VALIDATION
# ══════════════════════════════════════════════════════════════════════════════
def _validate_username(name: str) -> bool:
    """Имя юзера: латиница, 3-16 символов, [a-zA-Z][a-zA-Z0-9_-].

    Это ограничение нужно для безопасности systemd unit name (%i не может
    содержать спецсимволы) и для имени файла /etc/snell/<user>.conf.
    """
    return bool(re.match(r'^[a-zA-Z][a-zA-Z0-9_\-]{2,15}$', name))

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG FILE GENERATION (INI)
# ══════════════════════════════════════════════════════════════════════════════
def _write_user_config(username: str, port: int, psk: str,
                       obfs: str, obfs_host: str) -> Path:
    """Генерирует per-user INI-конфиг /etc/snell/<username>.conf.

    Формат:
      [snell-server]
      listen = 0.0.0.0:<port>
      psk = <psk>
      ipv6 = false
      obfs = <tls|http|off>
      obfs-host = <домен>

    Возвращает Path к записанному файлу.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    cfg_path = CONFIG_DIR / f"{username}.conf"
    lines = [
        "# Snell v4 server config — generated by Chimera Project",
        "[snell-server]",
        f"listen = 0.0.0.0:{port}",
        f"psk = {psk}",
        "ipv6 = false",
        f"obfs = {obfs}",
    ]
    if obfs in ("tls", "http"):
        lines.append(f"obfs-host = {obfs_host}")
    cfg_path.write_text("\n".join(lines) + "\n")
    cfg_path.chmod(0o640)
    return cfg_path

# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEMD TEMPLATE UNIT
# ══════════════════════════════════════════════════════════════════════════════
def _install_service_template() -> None:
    """Создаёт systemd template unit /etc/systemd/system/snell-server@.service.

    Шаблон (%i подставляется именем инстанса):
      [Service]
      ExecStart=/usr/local/bin/snell-server -c /etc/snell/%i.conf

    Это позволяет запускать per-user инстансы:
      systemctl start snell-server@alice
      systemctl start snell-server@bob
    Каждый инстанс подхватывает свой конфиг через %i.
    """
    SERVICE_TEMPLATE.write_text(
        "[Unit]\n"
        "Description=Snell v4 Proxy Server (instance: %i)\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={BIN_PATH} -c {CONFIG_DIR}/%i.conf\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "LimitNOFILE=1048576\n"
        "NoNewPrivileges=true\n"
        # Изоляция для безопасности — snell не должен иметь доступ к
        # критичным директориям. ReadWritePaths ограничивает запись.
        f"ReadWritePaths={CONFIG_DIR}\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _run(["systemctl", "daemon-reload"])

def _start_user_instance(username: str) -> bool:
    """Запускает systemd-инстанс snell-server@<username>.

    Возвращает True если инстанс успешно стартовал (или уже был активен)
    И порт действительно слушается.
    """
    instance = f"{SERVICE_NAME}{username}"
    _run(["systemctl", "enable", instance])
    _run(["systemctl", "start", instance])
    time.sleep(1)
    r = _run(["systemctl", "is-active", instance], capture=True)
    if r.returncode != 0 or r.stdout.strip() != "active":
        return False
    # Дополнительная проверка: порт действительно слушается.
    # systemd может показать "active" даже если binary упал после старта
    # (Type=simple, Restart=on-failure с RestartSec=5 — между падением и
    # рестартом есть окно где is-active может показать "active").
    # Проверяем через ss -tlnp что порт реально слушается.
    state = _load_state()
    user = _find_user(state, username)
    if user:
        port = user.get("port", 0)
        if port:
            r = _run(["ss", "-tlnp"], capture=True, check=False)
            if r.returncode == 0 and r.stdout:
                # Ищем строку с нашим портом — формат ":30000 " или "[::]:30000 "
                if f":{port} " not in r.stdout and f":{port}\n" not in r.stdout:
                    return False  # порт не слушается
    return True

def _stop_user_instance(username: str) -> None:
    """Останавливает и disable-ит инстанс snell-server@<username>."""
    instance = f"{SERVICE_NAME}{username}"
    _run(["systemctl", "stop", instance], capture=True)
    _run(["systemctl", "disable", instance], capture=True)

def _instance_active(username: str) -> bool:
    """Возвращает True если инстанс snell-server@<username> активен."""
    instance = f"{SERVICE_NAME}{username}"
    r = _run(["systemctl", "is-active", instance], capture=True)
    return r.returncode == 0 and r.stdout.strip() == "active"

# ══════════════════════════════════════════════════════════════════════════════
#  BINARY DOWNLOAD (через download_manager)
# ══════════════════════════════════════════════════════════════════════════════
def _download_binary(version: str = SNELL_DEFAULT_VERSION) -> bool:
    """Скачивает и устанавливает бинарник snell-server через PackageSpec.

    Делегирует в download_manager.fetch_package — он сам перебирает зеркала
    с фолбэком и при неудаче печатает подсказку про ручную загрузку.
    """
    from chimera.modules.download_manager import fetch_package
    try:
        arch = _arch_suffix()
    except ValueError as e:
        _err(str(e))
        return False
    _info(f"Скачиваю snell-server v{version} для {arch}...")
    ok = fetch_package(SNELL_SPEC, version=version, arch=arch,
                       progress_label="snell-server")
    if ok:
        _ok(f"Бинарник установлен: {BIN_PATH}")
    else:
        _err("Не удалось скачать бинарник автоматически.")
        print_snell_manual_download_hint(version=version, arch=arch)
    return ok

# ══════════════════════════════════════════════════════════════════════════════
#  LET'S ENCRYPT CERTIFICATE (для obfs=tls)
# ══════════════════════════════════════════════════════════════════════════════
def _ensure_le_cert(domain: str) -> bool:
    """Получает LE-сертификат для домена (если ещё нет).

    Делегирует в ssl_certbot.obtain_ssl_cert — он сам проверяет существование
    сертификата и при отсутствии вызывает certbot.
    """
    if not domain:
        _err("Не указан домен для LE-сертификата. "
             "Укажите домен с DNS-записью A, указывающей на этот сервер.")
        return False
    # Проверяем — вдруг сертификат уже есть.
    le_cert = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
    le_key  = Path(f"/etc/letsencrypt/live/{domain}/privkey.pem")
    if le_cert.exists() and le_key.exists():
        _info(f"LE-сертификат для {domain} уже существует — используем.")
        return True
    try:
        from chimera.modules.ssl_certbot import obtain_ssl_cert
        obtain_ssl_cert(domain=domain)
        # Проверяем что сертификат действительно появился.
        return le_cert.exists() and le_key.exists()
    except Exception as e:
        _err(f"Не удалось получить LE-сертификат для {domain}: {e}")
        return False

# ══════════════════════════════════════════════════════════════════════════════
#  CLIENT LINK GENERATION
# ══════════════════════════════════════════════════════════════════════════════
def _build_snell_link(server: str, port: int, psk: str,
                      obfs: str = "tls", obfs_host: str = "",
                      tag: str = "") -> str:
    """Генерирует клиентскую ссылку snell:// для Clash Meta и совместимых.

    Формат: snell://<urlencoded_psk>@<server>:<port>?obfs=<tls|http|off>&obfs-host=<host>#<tag>

    PSK URL-кодируется чтобы корректно обработать base64-символы '+', '/',
    '=', которые могут быть в нём. tag (после #) — имя узла в клиенте.
    """
    psk_q = urllib.parse.quote(psk, safe="")
    params = {"obfs": obfs}
    if obfs in ("tls", "http") and obfs_host:
        params["obfs-host"] = obfs_host
    query = urllib.parse.urlencode(params, safe="")
    link = f"snell://{psk_q}@{server}:{port}?{query}"
    if tag:
        link += f"#{urllib.parse.quote(tag, safe='')}"
    return link

def _gen_singbox_outbound(server: str, port: int, psk: str,
                          obfs: str = "tls", obfs_host: str = "") -> dict:
    """Генерирует sing-box outbound JSON для Snell.

    ВАЖНО: sing-box upstream НЕ поддерживает Snell в официальном релизе.
    Этот JSON формат работает только в сторонних форках sing-box с патчем
    Snell (например, Dress / sss-box-shadow). Если у пользователя официальный
    sing-box — outbound будет проигнорирован.
    """
    outbound = {
        "type": "snell",
        "tag": "snell-out",
        "server": server,
        "server_port": port,
        "password": psk,
    }
    if obfs in ("tls", "http"):
        outbound["obfs"] = {
            "type": obfs,
            "host": obfs_host or server,
        }
    return outbound

def _gen_clash_proxy(server: str, port: int, psk: str,
                     obfs: str = "tls", obfs_host: str = "",
                     name: str = "Snell") -> dict:
    """Генерирует Clash Meta proxy-узел (dict, потом конвертируется в YAML).

    Возвращает dict в формате, который clash-meta понимает как элемент
    массива proxies:.
    """
    proxy = {
        "name": name,
        "type": "snell",
        "server": server,
        "port": port,
        "psk": psk,
        "obfs-opts": {"mode": obfs},
    }
    if obfs in ("tls", "http") and obfs_host:
        proxy["obfs-opts"]["host"] = obfs_host
    return proxy

# ══════════════════════════════════════════════════════════════════════════════
#  USER MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════
def _load_state() -> dict:
    """Загружает модуль-state с дефолтами."""
    defaults = {
        "installed": False,
        "obfs": DEFAULT_OBFS,
        "obfs_host": "",
        "domain": "",
        "server_ip": "",
        "version": "",
        "users": [],
    }
    return proto_load_state(MODULE_STATE, defaults=defaults)

def _save_state(state: dict) -> None:
    proto_save_state(MODULE_STATE, state, name="snell")

def _find_user(state: dict, username: str) -> Optional[dict]:
    """Ищет юзера по имени в state["users"]. Возвращает dict или None."""
    for u in state.get("users", []):
        if u.get("username") == username:
            return u
    return None

def _add_user(username: str, psk: Optional[str] = None,
              obfs: Optional[str] = None, obfs_host: Optional[str] = None) -> dict:
    """Добавляет нового юзера. Создаёт конфиг, выделяет порт, запускает инстанс.

    Возвращает dict с данными созданного юзера.
    Raises ValueError если имя невалидно или уже существует.
    Raises RuntimeError если нет свободных портов или инстанс не стартовал.
    """
    if not _validate_username(username):
        raise ValueError(
            f"Имя '{username}' невалидно. Формат: [a-zA-Z][a-zA-Z0-9_-]{{2,15}}"
        )
    state = _load_state()
    if _find_user(state, username) is not None:
        raise ValueError(f"Юзер '{username}' уже существует")
    port = _allocate_port(state)
    user_psk = psk or _generate_psk()
    user_obfs = obfs or state.get("obfs", DEFAULT_OBFS)
    # obfs_host: приоритет — аргумент > state["obfs_host"] > domain из state.json
    user_obfs_host = (obfs_host or state.get("obfs_host", "")
                      or state.get("domain", "") or _get_state_domain())
    # 1. Пишем конфиг.
    _write_user_config(username, port, user_psk, user_obfs, user_obfs_host)
    # 2. Открываем порт.
    _open_port(port, username)
    # 3. Настраиваем iptables accounting.
    try:
        from chimera.modules.snell_stats import setup_user_accounting
        setup_user_accounting(username, port)
    except Exception:
        pass  # не критично — учёт трафика опционален
    # 4. Запускаем инстанс.
    if not _start_user_instance(username):
        # Откат: убираем порт, конфиг, accounting.
        _close_port(port)
        try:
            from chimera.modules.snell_stats import teardown_user_accounting
            teardown_user_accounting(username, port)
        except Exception:
            pass
        (CONFIG_DIR / f"{username}.conf").unlink(missing_ok=True)
        raise RuntimeError(f"Не удалось запустить snell-server@{username}")
    # 5. Сохраняем в state.
    user_record = {
        "username": username,
        "psk": user_psk,
        "port": port,
        "obfs": user_obfs,
        "obfs_host": user_obfs_host,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    state.setdefault("users", []).append(user_record)
    _save_state(state)
    return user_record

def _remove_user(username: str) -> bool:
    """Удаляет юзера. Останавливает инстанс, закрывает порт, убирает конфиг.

    Возвращает True если юзер был найден и удалён, False если не найден.
    """
    state = _load_state()
    user = _find_user(state, username)
    if user is None:
        return False
    port = user.get("port", 0)
    # 1. Останавливаем инстанс.
    _stop_user_instance(username)
    # 2. Закрываем порт.
    if port:
        _close_port(port)
    # 3. Убираем iptables accounting.
    try:
        from chimera.modules.snell_stats import teardown_user_accounting
        teardown_user_accounting(username, port)
    except Exception:
        pass
    # 4. Удаляем конфиг.
    (CONFIG_DIR / f"{username}.conf").unlink(missing_ok=True)
    # 5. Убираем из state.
    state["users"] = [u for u in state.get("users", [])
                      if u.get("username") != username]
    _save_state(state)
    return True


def rename_user(old_username: str, new_username: str) -> bool:
    """Переименовывает Snell-пользователя old_username → new_username.

    Сохраняет PSK, порт, obfs и obfs_host — старые клиентские ссылки
    продолжают работать (меняется только тэг имени, который юзер видит
    в клиенте, но psk+server+port+obfs не меняются, так что фактическое
    подключение работает без перенастройки).

    Шаги:
      1. Валидация new_username (формат [a-zA-Z][a-zA-Z0-9_-]{2,15}).
      2. Проверка что old_username существует в state.
      3. Проверка что new_username НЕ занят другим юзером
         (не перезаписываем чужой psk).
      4. Останавливаем systemd-инстанс snell-server@<old>.
      5. Перегенерируем конфиг под новым именем с тем же psk/port/obfs.
         (Простое переименование файла недостаточно — внутри конфига
         нет имени, но systemd %i берётся из имени unit'а, поэтому
         конфиг должен лежать по пути /etc/snell/<new>.conf.)
      6. Удаляем старый /etc/snell/<old>.conf.
      7. Запускаем snell-server@<new>.
         Если не стартует — откат: восстанавливаем старый конфиг,
         запускаем snell-server@<old>, возвращаем False.
      8. Обновляем username в state["users"], сохраняем state.

    Возвращает True если переименование успешно.
    Возвращает False БЕЗ изменений если:
      • old_username не найден в state
      • new_username уже занят другим юзером
      • new_username невалиден по спеке
      • snell-server@<new> не стартовал (с откатом к old)
      • old == new (no-op, возвращаем True — это не ошибка)
    """
    if not old_username or not new_username:
        return False
    if old_username == new_username:
        return True  # no-op, не ошибка
    if not _validate_username(new_username):
        return False
    state = _load_state()
    old_user = _find_user(state, old_username)
    if old_user is None:
        return False  # нечего переименовывать
    if _find_user(state, new_username) is not None:
        return False  # не перезаписываем чужой psk
    # Сохраняем старые данные для отката.
    port = old_user.get("port", 0)
    psk = old_user.get("psk", "")
    obfs = old_user.get("obfs", state.get("obfs", DEFAULT_OBFS))
    obfs_host = old_user.get("obfs_host", state.get("obfs_host", ""))
    old_cfg_path = CONFIG_DIR / f"{old_username}.conf"
    new_cfg_path = CONFIG_DIR / f"{new_username}.conf"
    # 1. Останавливаем старый инстанс.
    _stop_user_instance(old_username)
    # 2. Создаём новый конфиг с тем же psk/port/obfs.
    try:
        _write_user_config(new_username, port, psk, obfs, obfs_host)
    except Exception:
        # Откат: перезапускаем старый инстанс.
        _start_user_instance(old_username)
        return False
    # 3. Запускаем новый инстанс.
    if not _start_user_instance(new_username):
        # Откат: удаляем новый конфиг, запускаем старый.
        new_cfg_path.unlink(missing_ok=True)
        _start_user_instance(old_username)
        return False
    # 4. Удаляем старый конфиг.
    old_cfg_path.unlink(missing_ok=True)
    # 5. Обновляем username в state (psk/port/obfs/obfs_host не трогаем).
    old_user["username"] = new_username
    _save_state(state)
    # 6. Переносим iptables accounting со старого имени на новое
    # (порт остаётся тем же, но comment-тег меняется).
    if port:
        try:
            from chimera.modules.snell_stats import (
                teardown_user_accounting, setup_user_accounting,
            )
            teardown_user_accounting(old_username, port)
            setup_user_accounting(new_username, port)
        except Exception:
            pass  # не критично — учёт трафика опционален
    return True


# ══════════════════════════════════════════════════════════════════════════════
#  INSTALL / UNINSTALL
# ══════════════════════════════════════════════════════════════════════════════
def _run_install() -> None:
    """Полный flow установки Snell: скачивание бинарника + template unit."""
    os.system("clear")
    _box_top("🚀  УСТАНОВКА  •  SNELL V4")
    _box_row()
    _box_info("Скачиваю бинарник snell-server с официальных зеркал...")
    _box_row()
    _box_bot(); print()

    version = _get_latest_version()
    if not _download_binary(version):
        _err("Установка прервана: не удалось установить бинарник.")
        _pause()
        return

    # Проверяем что бинарник реально работает. Snell-server может
    # использовать --version или -v (зависит от сборки). Если ни один
    # флаг не сработал — не блокируем установку, просто предупреждаем
    # (бинарник может писать версию только в stderr или при запуске
    # с конфигом). Главный критерий — что он запускается без segfault.
    _info("Проверяю бинарник...")
    r = _run([str(BIN_PATH), "--version"], capture=True)
    if r.returncode != 0:
        # Пробуем короткий флаг -v.
        r = _run([str(BIN_PATH), "-v"], capture=True)
    if r.returncode != 0:
        _warn(f"Не удалось получить версию через --version/-v "
              f"(rc={r.returncode}). Продолжаю установку — бинарник "
              f"может использовать другой флаг. Проверьте вручную: "
              f"{BIN_PATH} --version")
    else:
        version_output = (r.stdout or r.stderr or "").strip()
        if version_output:
            _ok(f"Версия: {version_output}")

    # Устанавливаем template unit.
    _info("Создаю systemd template unit...")
    _install_service_template()
    _ok(f"Template unit: {SERVICE_TEMPLATE}")

    # Создаём CONFIG_DIR для per-user конфигов.
    # КРИТИЧНО: _is_installed() проверяет существование CONFIG_DIR —
    # без этого пункт меню '2. Управление пользователями' не появится
    # и юзер не сможет добавить ни одного пользователя (chicken-and-egg).
    _info("Создаю директорию для конфигов...")
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_DIR.chmod(0o755)
        _ok(f"Директория конфигов: {CONFIG_DIR}")
    except (OSError, PermissionError) as e:
        _err(f"Не удалось создать {CONFIG_DIR}: {e}")
        _pause()
        return

    # Спрашиваем obfs.
    obfs = _ask_obfs()
    if obfs is None:
        _warn("Установка отменена.")
        _pause()
        return

    # Для obfs=tls нужен LE-сертификат.
    obfs_host = ""
    if obfs in ("tls", "http"):
        obfs_host = _ask_obfs_host()
        if obfs_host is None:
            _warn("Установка отменена.")
            _pause()
            return
        if obfs == "tls":
            _info(f"Получаю LE-сертификат для {obfs_host}...")
            if not _ensure_le_cert(obfs_host):
                _warn("LE-сертификат не получен. obfs будет использовать "
                      "fake-TLS (менее устойчив к DPI).")
                # Продолжаем — fake-TLS тоже работает, просто менее стоек.

    # Сохраняем state.
    state = _load_state()
    state.update({
        "installed": True,
        "obfs": obfs,
        "obfs_host": obfs_host,
        "version": version,
        "server_ip": _get_server_ip(),
    })
    _save_state(state)

    _box_top("✅  УСТАНОВКА ЗАВЕРШЕНА")
    _box_row()
    _box_ok(f"Бинарник: {BIN_PATH}")
    _box_ok(f"Template: {SERVICE_TEMPLATE}")
    _box_ok(f"Конфиги: {CONFIG_DIR}/<user>.conf")
    _box_ok(f"Диапазон портов: {PORT_RANGE_START}-{PORT_RANGE_END}")
    _box_ok(f"obfs: {obfs}" + (f" (host: {obfs_host})" if obfs_host else ""))
    _box_row()
    _box_info("Добавьте пользователей через пункт '2' главного меню Snell.")
    _box_row()
    _box_bot(); print()
    _pause()

def _ask_obfs() -> Optional[str]:
    """Спрашивает режим obfs. Возвращает 'tls'/'http'/'off' или None (отмена)."""
    _box_top("🌐  ВЫБОР obfs")
    _box_row()
    _box_kv("tls", "Маскировка под HTTPS (рекомендуется)")
    _box_kv("http", "Маскировка под HTTP")
    _box_kv("off", "Без обфускации")
    _box_sep()
    _box_item("Q", "← Отмена")
    _box_bot(); print()
    try:
        ch = proto_ask(f"{CYAN}Выбор [tls/http/off, Enter=tls]: {NC}",
                       default="tls").strip().lower()
    except _Cancelled:
        return None
    if ch in ("q", ""):
        return None
    if ch not in ("tls", "http", "off"):
        _warn(f"Неверный выбор: {ch}. Использую tls.")
        return "tls"
    return ch

def _ask_obfs_host() -> Optional[str]:
    """Спрашивает домен для obfs-host. По умолчанию — domain из state.json."""
    default = _get_state_domain() or DEFAULT_OBFS_HOST
    try:
        host = proto_ask(
            f"{CYAN}Домен для obfs-host {DIM}(Enter={default}):{NC} ",
            default=default,
        ).strip().lower()
    except _Cancelled:
        return None
    if not host:
        host = default
    return host

def _full_uninstall(silent: bool = False) -> bool:
    """Полное удаление Snell. Останавливает все инстансы, удаляет конфиги."""
    if not silent:
        os.system("clear")
        _box_top("🗑️  УДАЛЕНИЕ  •  SNELL V4")
        _box_row()
        _box_warn("Будет удалено:")
        _box_row(f"  {DIM}  • Все systemd-инстансы snell-server@*{NC}")
        _box_row(f"  {DIM}  • Template unit {SERVICE_TEMPLATE}{NC}")
        _box_row(f"  {DIM}  • Бинарник {BIN_PATH}{NC}")
        _box_row(f"  {DIM}  • Все конфиги {CONFIG_DIR}/*.conf{NC}")
        _box_row(f"  {DIM}  • iptables-цепочки SNELL_STATS_IN/OUT{NC}")
        _box_row(f"  {DIM}  • Все UFW/iptables правила на порты 30000-30999{NC}")
        _box_row(f"  {DIM}  • State {MODULE_STATE}{NC}")
        _box_row()
        _box_warn("VLESS, Telemt и другие службы не затрагиваются.")
        _box_row()
        _box_item("Y", f"{RED}Да, удалить{NC}")
        _box_item("N", "Нет, отмена")
        _box_bot(); print()
        try:
            ans = proto_ask(f"{CYAN}Подтверждение [y/N]: {NC}", c=True).strip().lower()
        except _Cancelled:
            return False
        if ans != "y":
            print(f"  {DIM}Отменено.{NC}")
            _pause()
            return False

    state = _load_state()

    # 1. Останавливаем все per-user инстансы.
    for u in state.get("users", []):
        username = u.get("username", "")
        if username:
            _stop_user_instance(username)

    # 2. Закрываем все порты.
    for u in state.get("users", []):
        port = u.get("port", 0)
        if port:
            _close_port(port)

    # 3. Убираем iptables accounting.
    try:
        from chimera.modules.snell_stats import teardown_all_accounting
        teardown_all_accounting()
    except Exception:
        pass

    # 4. Удаляем template unit и daemon-reload.
    _run(["systemctl", "stop", f"{SERVICE_NAME}*"], capture=True)
    if SERVICE_TEMPLATE.exists():
        SERVICE_TEMPLATE.unlink()
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "reset-failed"], capture=True)

    # 5. Удаляем бинарник и конфиги.
    if BIN_PATH.exists():
        BIN_PATH.unlink()
    if CONFIG_DIR.exists():
        shutil.rmtree(CONFIG_DIR, ignore_errors=True)

    # 6. Удаляем state.
    try:
        if MODULE_STATE.exists():
            MODULE_STATE.unlink()
    except Exception:
        pass

    if not silent:
        print(f"  {GREEN}✓{NC}  Snell v4 полностью удалён.")
        _pause()
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  USERS MENU
# ══════════════════════════════════════════════════════════════════════════════
def _users_menu() -> None:
    """Управление пользователями: список, добавить, удалить, показать ссылки."""
    while True:
        os.system("clear")
        state = _load_state()
        users = state.get("users", [])

        _box_top("👥  УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ  •  SNELL V4")
        _box_row()
        if not users:
            _box_row(f"  {DIM}Нет пользователей. Добавьте через [1].{NC}")
        else:
            _box_row(f"  {DIM}{'#':<4} {'Имя':<18} {'Порт':<7} {'obfs':<6} Статус{NC}")
            _box_sep()
            for i, u in enumerate(users, 1):
                username = u.get("username", "?")
                port = u.get("port", 0)
                obfs = u.get("obfs", "?")
                active = _instance_active(username)
                status = f"{GREEN}●{NC}" if active else f"{RED}○{NC}"
                _box_row(f"  {DIM}{i:<4}{NC} {username:<18} {port:<7} {obfs:<6} {status}")
        _box_row(); _box_sep()
        _box_item("1", "➕  Добавить пользователя")
        _box_item("2", "➖  Удалить пользователя")
        _box_item("3", "🔗  Показать ссылки")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()

        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            _add_user_flow()
        elif ch == "2" and users:
            _remove_user_flow(users)
        elif ch == "3" and users:
            _show_links_flow(users)
        elif ch in ("q", ""):
            break

def _add_user_flow() -> None:
    """Flow добавления нового пользователя с TUI-диалогом."""
    try:
        name = proto_ask(f"{CYAN}Имя (3-16 симв, [a-zA-Z][a-zA-Z0-9_-]):{NC} ").strip()
    except _Cancelled:
        return
    if not name:
        return
    try:
        user = _add_user(name)
    except ValueError as e:
        _err(str(e))
        _pause()
        return
    except RuntimeError as e:
        _err(str(e))
        _pause()
        return
    _box_top("✅  ПОЛЬЗОВАТЕЛЬ ДОБАВЛЕН")
    _box_row()
    _box_kv("Имя:", user["username"])
    _box_kv("Порт:", str(user["port"]))
    _box_kv("obfs:", user["obfs"])
    _box_kv("obfs-host:", user.get("obfs_host", "—"))
    _box_row()
    server_ip = _get_server_ip()
    link = _build_snell_link(
        server=server_ip, port=user["port"], psk=user["psk"],
        obfs=user["obfs"], obfs_host=user.get("obfs_host", ""),
        tag=f"snell-{user['username']}",
    )
    _box_info("Клиентская ссылка:")
    for line in _wrap_link(link):
        _box_row(f"  {YELLOW}{line}{NC}")
    _box_row()
    _box_bot(); print()
    _pause()

def _remove_user_flow(users: list) -> None:
    """Flow удаления пользователя."""
    try:
        name = proto_ask(f"{CYAN}Имя для удаления:{NC} ").strip()
    except _Cancelled:
        return
    if not name:
        return
    if not _find_user(_load_state(), name):
        _err(f"Юзер '{name}' не найден.")
        _pause()
        return
    if _remove_user(name):
        _ok(f"Удалён: {name}")
    else:
        _err(f"Не удалось удалить: {name}")
    _pause()

def _show_links_flow(users: list) -> None:
    """Показывает клиентские ссылки для всех пользователей."""
    os.system("clear")
    _box_top("🔗  КЛИЕНТСКИЕ ССЫЛКИ  •  SNELL V4")
    _box_row()
    server_ip = _get_server_ip()
    state = _load_state()
    obfs = state.get("obfs", DEFAULT_OBFS)
    obfs_host = state.get("obfs_host", "") or _get_state_domain()
    for u in users:
        username = u.get("username", "?")
        port = u.get("port", 0)
        psk = u.get("psk", "")
        user_obfs = u.get("obfs", obfs)
        user_obfs_host = u.get("obfs_host", obfs_host)
        link = _build_snell_link(
            server=server_ip, port=port, psk=psk,
            obfs=user_obfs, obfs_host=user_obfs_host,
            tag=f"snell-{username}",
        )
        _box_row(f"  {BOLD}{username}{NC} (порт {port}, obfs={user_obfs}):")
        for line in _wrap_link(link):
            _box_row(f"  {YELLOW}{line}{NC}")
        _box_row()
    _box_sep()
    _box_item("Q", "← Назад")
    _box_bot(); print()
    try:
        proto_ask(f"{CYAN}Нажмите Enter...{NC}", c=True)
    except _Cancelled:
        pass

def _wrap_link(link: str, max_w: int = _BOX_W - 4) -> list:
    """Разбивает длинную ссылку на строки по max_w символов."""
    return [link[i:i+max_w] for i in range(0, len(link), max_w)]

# ══════════════════════════════════════════════════════════════════════════════
#  STATUS / GUIDE
# ══════════════════════════════════════════════════════════════════════════════
def _show_status() -> None:
    """Показывает статус Snell: активные инстансы, порты, версии."""
    os.system("clear")
    state = _load_state()
    users = state.get("users", [])
    version = _get_installed_version() or "?"

    _box_top("📊  СТАТУС  •  SNELL V4")
    _box_row()
    _box_kv("Версия бинарника:", version)
    _box_kv("Установлен:", "да" if _is_installed() else "нет")
    _box_kv("obfs (по умолчанию):", state.get("obfs", DEFAULT_OBFS))
    if state.get("obfs_host"):
        _box_kv("obfs-host:", state["obfs_host"])
    _box_kv("Пользователей:", str(len(users)))
    _box_kv("Диапазон портов:", f"{PORT_RANGE_START}-{PORT_RANGE_END}")
    active_count = sum(1 for u in users if _instance_active(u.get("username", "")))
    _box_kv("Активных инстансов:", f"{active_count}/{len(users)}")
    _box_row()
    if users:
        _box_row(f"  {DIM}Имя                Порт   obfs   Статус{NC}")
        _box_sep()
        for u in users:
            username = u.get("username", "?")
            port = u.get("port", 0)
            obfs = u.get("obfs", "?")
            active = _instance_active(username)
            status = f"{GREEN}active{NC}" if active else f"{RED}stopped{NC}"
            _box_row(f"  {username:<18} {port:<6} {obfs:<6} {status}")
        _box_row()
    _box_sep()
    _box_item("Q", "← Назад")
    _box_bot(); print()
    try:
        proto_ask(f"{CYAN}Нажмите Enter...{NC}", c=True)
    except _Cancelled:
        pass

def _show_guide() -> None:
    """Показывает гайд: как работает Snell, клиенты, особенности."""
    os.system("clear")
    _box_top("📖  ГАЙД  •  SNELL V4")
    _box_row()
    _box_row(f"  {BOLD}Что это:{NC}")
    _box_row(f"  Snell v4 — нишевый протокол от команды Surge (nssurge.com).")
    _box_row(f"  Закрытый бинарник, но лицензионных проблем нет — мы просто")
    _box_row(f"  скачиваем и оборачиваем официальный релиз.")
    _box_row()
    _box_row(f"  {BOLD}Архитектура:{NC}")
    _box_row(f"  • Per-user systemd template: snell-server@<username>")
    _box_row(f"  • Per-user конфиг: /etc/snell/<username>.conf")
    _box_row(f"  • Per-user порт из диапазона {PORT_RANGE_START}-{PORT_RANGE_END}")
    _box_row(f"  • Per-user PSK (32 байта, base64)")
    _box_row(f"  • Per-user iptables accounting (через snell_stats.py)")
    _box_row()
    _box_row(f"  {BOLD}obfs режимы:{NC}")
    _box_row(f"  • tls — маскировка под HTTPS (рекомендуется, требует LE)")
    _box_row(f"  • http — маскировка под HTTP (проще, менее стоек к DPI)")
    _box_row(f"  • off — без обфускации (только для тестов)")
    _box_row()
    _box_row(f"  {BOLD}Клиенты:{NC}")
    _box_row(f"  • Surge (macOS/iOS) — официальная поддержка")
    _box_row(f"  • Clash Meta / Mihomo — через snell:// ссылки")
    _box_row(f"  • NekoBox / v2rayN — через плагины/патчи")
    _box_row(f"  • sing-box (официальный) — НЕ поддерживает, нужен форк")
    _box_row()
    _box_row(f"  {BOLD}Ссылка формата:{NC}")
    _box_row(f"  snell://<psk>@<server>:<port>?obfs=tls&obfs-host=<host>#<tag>")
    _box_row()
    _box_sep()
    _box_item("Q", "← Назад")
    _box_bot(); print()
    try:
        proto_ask(f"{CYAN}Нажмите Enter...{NC}", c=True)
    except _Cancelled:
        pass

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN MENU ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
def do_snell_menu() -> None:
    """Точка входа из _core.py. Главное TUI-меню Snell."""
    while True:
        os.system("clear")
        installed = _is_installed()
        state = _load_state()
        users = state.get("users", [])
        active_count = sum(1 for u in users
                           if _instance_active(u.get("username", "")))

        if installed:
            svc_str = (f"{GREEN}● активен ({active_count}/{len(users)} инстансов){NC}"
                       if active_count else f"{YELLOW}● установлен, инстансов нет{NC}")
        else:
            svc_str = f"{YELLOW}● не установлен{NC}"

        _box_top("SNELL V4  •  Surge MTProto-подобный протокол")
        _box_row()
        _box_kv("Статус:", svc_str)
        if installed:
            _box_kv("obfs:", state.get("obfs", DEFAULT_OBFS))
            if state.get("obfs_host"):
                _box_kv("obfs-host:", state["obfs_host"])
            _box_kv("Пользователей:", str(len(users)))
            _box_kv("Диапазон портов:", f"{PORT_RANGE_START}-{PORT_RANGE_END}")
            version = _get_installed_version()
            if version:
                _box_kv("Версия:", version)
        _box_row(); _box_sep()

        if not installed:
            _box_item("1", "🚀  Установить Snell v4")
        else:
            _box_item("1", "🚀  Переустановить")
            _box_item("2", "👥  Управление пользователями")
            _box_item("3", "🔄  Перезапустить все инстансы")
            _box_item("4", "📊  Статус / логи")
            _box_item("5", "📈  Статистика трафика")
            _box_sep()
            _box_item("9", f"{RED}🗑️   Удалить Snell v4{NC}")

        _box_sep()
        _box_item("G", "📖  Гайд: как работает, клиенты, obfs")
        _box_sep()
        _box_item("Q", "← Назад в главное меню Chimera")
        _box_bot(); print()

        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            try:
                _run_install()
            except _Cancelled:
                print(f"  {DIM}Отменено.{NC}")
                _pause()
        elif ch == "2" and installed:
            try:
                _users_menu()
            except _Cancelled:
                pass
        elif ch == "3" and installed:
            # Перезапускаем все инстансы.
            for u in users:
                username = u.get("username", "")
                if username:
                    _stop_user_instance(username)
                    _start_user_instance(username)
            _ok(f"Перезапущено инстансов: {len(users)}")
            _pause()
        elif ch == "4" and installed:
            _show_status()
        elif ch == "5" and installed:
            try:
                from chimera.modules.snell_stats import get_all_users_traffic
                _show_traffic(get_all_users_traffic())
            except Exception as e:
                _err(f"Не удалось получить статистику: {e}")
                _pause()
        elif ch == "9" and installed:
            try:
                _full_uninstall(silent=False)
            except _Cancelled:
                print(f"  {DIM}Отменено.{NC}")
                _pause()
        elif ch == "g":
            try:
                _show_guide()
            except _Cancelled:
                pass
        elif ch in ("q", ""):
            break

def _show_traffic(all_traffic: dict) -> None:
    """Показывает per-user трафик из snell_stats.get_all_users_traffic()."""
    os.system("clear")
    _box_top("📈  СТАТИСТИКА ТРАФИКА  •  SNELL V4")
    _box_row()
    if not all_traffic:
        _box_row(f"  {DIM}Нет данных. Возможно, iptables-учёт не настроен.{NC}")
    else:
        _box_row(f"  {DIM}Имя                Входящий        Исходящий       Всего{NC}")
        _box_sep()
        for username, t in all_traffic.items():
            bi = t.get("bytes_in", 0)
            bo = t.get("bytes_out", 0)
            total = t.get("total_bytes", bi + bo)
            _box_row(f"  {username:<18} {_fmt_bytes(bi):>12}   "
                     f"{_fmt_bytes(bo):>12}   {_fmt_bytes(total):>12}")
        _box_row()
    _box_sep()
    _box_item("Q", "← Назад")
    _box_bot(); print()
    try:
        proto_ask(f"{CYAN}Нажмите Enter...{NC}", c=True)
    except _Cancelled:
        pass

def _fmt_bytes(n: int) -> str:
    """Форматирует байты в человекочитаемый вид (KB/MB/GB)."""
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n / (1024 * 1024 * 1024):.2f} GB"

# ══════════════════════════════════════════════════════════════════════════════
#  PUBLIC API — для интеграции с rest_api.py / subscription.py / status_panel.py
# ══════════════════════════════════════════════════════════════════════════════

def _ensure_port_open(port: int, username: str) -> bool:
    """Проверяет что порт открыт в UFW/iptables. Если закрыт — открывает.

    Defensive функция — вызывается при генерации клиентских конфигов
    (Clash/Singbox) чтобы гарантировать что порт доступен. Если порт
    был закрыт (например, UFW был включён после создания юзера и
    flush-нул iptables правила) — открывает его автоматически.

    Возвращает True если порт открыт (был или стал).
    """
    # Сначала проверяем — может порт уже открыт.
    if _ufw_is_active():
        r = _run(["ufw", "status"], capture=True, check=False)
        if r.returncode == 0 and r.stdout:
            # Ищем порт в выводе ufw status.
            if f"{port}/tcp" in r.stdout:
                return True  # уже открыт
        # Порт не найден в UFW — открываем.
        _ufw_open_tcp(port, f"snell-{username}")
        return True
    # UFW не активен — проверяем iptables.
    if _ipt_tcp_rule_exists(port):
        return True  # уже открыт
    _ipt_open_tcp(port)
    return True


def get_user_link(username: str, server_ip: str = "") -> Optional[str]:
    """Возвращает snell:// ссылку для конкретного юзера (или None если не найден).

    Используется из rest_api.py /api/portal/links и subscription.py.
    """
    state = _load_state()
    user = _find_user(state, username)
    if user is None:
        return None
    # Defensive: убедимся что порт открыт в файрволе. Если UFW был
    # включён после создания юзера и flush-нул iptables правила —
    # порт мог быть закрыт. Открываем при генерации ссылки.
    _ensure_port_open(user.get("port", 0), username)
    server = server_ip or state.get("server_ip", "") or _get_server_ip()
    obfs = user.get("obfs", state.get("obfs", DEFAULT_OBFS))
    obfs_host = user.get("obfs_host", state.get("obfs_host", ""))
    return _build_snell_link(
        server=server, port=user["port"], psk=user["psk"],
        obfs=obfs, obfs_host=obfs_host,
        tag=f"snell-{username}",
    )

def get_user_singbox_outbound(username: str, server_ip: str = "") -> Optional[dict]:
    """Возвращает sing-box outbound JSON для юзера (или None)."""
    state = _load_state()
    user = _find_user(state, username)
    if user is None:
        return None
    _ensure_port_open(user.get("port", 0), username)
    server = server_ip or state.get("server_ip", "") or _get_server_ip()
    obfs = user.get("obfs", state.get("obfs", DEFAULT_OBFS))
    obfs_host = user.get("obfs_host", state.get("obfs_host", ""))
    return _gen_singbox_outbound(
        server=server, port=user["port"], psk=user["psk"],
        obfs=obfs, obfs_host=obfs_host,
    )

def get_user_clash_proxy(username: str, server_ip: str = "") -> Optional[dict]:
    """Возвращает Clash Meta proxy-узел (dict) для юзера (или None)."""
    state = _load_state()
    user = _find_user(state, username)
    if user is None:
        return None
    _ensure_port_open(user.get("port", 0), username)
    server = server_ip or state.get("server_ip", "") or _get_server_ip()
    obfs = user.get("obfs", state.get("obfs", DEFAULT_OBFS))
    obfs_host = user.get("obfs_host", state.get("obfs_host", ""))
    return _gen_clash_proxy(
        server=server, port=user["port"], psk=user["psk"],
        obfs=obfs, obfs_host=obfs_host,
        name=f"Snell-{username}",
    )

def is_any_active() -> bool:
    """Возвращает True если Snell установлен И есть хотя бы один активный инстанс.

    Используется из rest_api.py для условной генерации ссылок (не отдаём
    битые ссылки если все инстансы остановлены).
    """
    if not _is_installed():
        return False
    state = _load_state()
    for u in state.get("users", []):
        if _instance_active(u.get("username", "")):
            return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
#  PUBLIC SYNC CONTRACT — is_active / ensure_user / remove_user / rename_user
# ══════════════════════════════════════════════════════════════════════════════
# Эти 4 функции — единый контракт автосинхронизации VLESS → Snell v4,
# вызываются из rest_api.py через обобщённый реестр _SYNCABLE_PROTOCOLS.
# Все 4 НИКОГДА не бросают исключение наружу — ловят всё внутри и
# возвращают bool. Это позволяет реестру диспетчеризовать вызовы безопасно.
#
# Внутренняя логика (валидация имён, лимит портов 30000-30999, отсутствие
# ограничения "нельзя удалить последнего" — у Snell каждый инстанс
# независим) — полностью инкапсулирована здесь.
#
# is_active() — обёртка над is_any_active() (alias для унификации контракта).
# ensure_user(name) — обёртка над _add_user(name) с подавлением исключений.
# remove_user(name) — обёртка над _remove_user(name) с подавлением исключений.
# rename_user(old, new) — уже существует как rename_user(), остаётся как есть.

def is_active() -> bool:
    """Возвращает True если Snell установлен И есть хотя бы один активный
    systemd-инстанс snell-server@<user>.

    Это alias для is_any_active() — введён для унификации контракта
    синхронизации (is_active/ensure_user/remove_user/rename_user).
    is_any_active() остаётся для обратной совместимости с rest_api.py.
    """
    return is_any_active()


def ensure_user(name: str) -> bool:
    """Создаёт Snell-пользователя с именем `name`, если его ещё нет.

    Возвращает True если пользователь создан или уже существует.
    Возвращает False если:
      • Snell не установлен (is_any_active() возвращает False)
      • Имя невалидно по Snell-спеке (^[a-zA-Z][a-zA-Z0-9_\\-]{2,15}$)
      • Нет свободных портов в диапазоне 30000-30999
      • Не удалось запустить systemd-инстанс
    Никогда не бросает исключение наружу — ловит ValueError/RuntimeError.
    """
    if not name:
        return False
    try:
        # Если Snell вообще не установлен — no-op (не создаём аккаунты
        # под неработающий сервис).
        if not is_any_active():
            return False
        # Если юзер уже есть — ничего делать не надо.
        state = _load_state()
        if _find_user(state, name) is not None:
            return True
        # Создаём — _add_user сам выделяет порт, пишет конфиг,
        # запускает systemd-инстанс, сохраняет state.
        # ValueError: имя невалидно или уже существует.
        # RuntimeError: нет свободных портов или инстанс не стартовал.
        _add_user(name)
        return True
    except (ValueError, RuntimeError):
        return False
    except Exception:
        return False


def remove_user(name: str) -> bool:
    """Удаляет Snell-пользователя с именем `name`, если он существует.

    Возвращает True если удалён или его не было. False — при ошибке.
    Никогда не падает с исключением — no-op на любой сбой.

    В отличие от Telemt, у Snell можно удалять последнего юзера —
    каждый инстанс независим (systemd template), никаких ограничений
    на пустой state. Это внутренняя политика протокола.
    """
    if not name:
        return False
    try:
        # _remove_user возвращает True если удалён, False если не найден.
        # Оба случая для нас "успех" с точки зрения контракта — аккаунта
        # больше нет. Но _remove_user может бросить исключение при сбое
        # systemd/iptables — ловим.
        return _remove_user(name)
    except Exception:
        return False


# rename_user(old, new) уже определён выше (строка ~701) — соответствует
# контракту: возвращает bool, не бросает исключение наружу (ловит всё
# внутри и делает откат при неудаче запуска нового инстанса).


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT (для запуска модуля standalone)
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}")
        sys.exit(1)
    try:
        do_snell_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}")
        sys.exit(0)
