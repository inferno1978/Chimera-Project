"""
chimera/modules/telemt_panel.py
───────────────────────────────────────────────────────────────────────────────
Модуль Telemt Panel — веб-панель управления для Telemt MTProxy
(https://github.com/amirotin/telemt_panel), Go-бинарник + встроенный React-фронт.

Точка входа из mtproto.py:
    from chimera.modules.telemt_panel import telemt_panel_menu
    telemt_panel_menu()

Принципы:
  • Полностью отдельный сервис/systemd-юнит/конфиг — panel и telemt друг с
    другом общаются только через HTTP API Telemt (127.0.0.1), файлы telemt
    напрямую не трогает.
  • config_edit_mode = "api" всегда (см. обоснование в шапке _generate_config) —
    так panel структурно не может задеть [server]/[network]/[access] в
    конфиге telemt (client_mss, MSS-clamp порты и т.д.), даже случайно.
  • [server.api]-секцию в конфиге telemt включает/обновляет mtproto.ensure_api_enabled() —
    единая точка правды для файла telemt.toml остаётся в mtproto.py.
  • Ctrl+C на любом шаге → возврат в меню (через _Cancelled).
───────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

from chimera.modules.text_width import wlen as _wlen, plain as _plain

import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional

from chimera.modules.telemt_mirrors import (
    get_telemt_panel_mirrors as _get_panel_mirror_urls,
    MANUAL_UPLOAD_PATHS as _TELEMT_MANUAL_PATHS,
    TELEMT_MIRRORS_COUNT,
    find_manual_upload as _find_telemt_manual_upload,
    print_telemt_manual_download_hint as _print_telemt_manual_hint,
    detect_arch_libc as _detect_arch_libc,
)

# ══════════════════════════════════════════════════════════════════════════════
#  ЦВЕТА
# ══════════════════════════════════════════════════════════════════════════════
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

# ══════════════════════════════════════════════════════════════════════════════
#  ПУТИ И КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════
BIN_PATH        = Path("/usr/local/bin/telemt-panel")
CONFIG_DIR      = Path("/etc/telemt-panel")
CONFIG_FILE     = CONFIG_DIR / "config.toml"
DATA_DIR        = Path("/var/lib/telemt-panel")
SERVICE_FILE    = Path("/etc/systemd/system/telemt-panel.service")
LOG_FILE        = Path("/var/log/telemt_panel_install.log")

SERVICE_NAME    = "telemt-panel"
SYSTEM_USER     = "telemt-panel"
GITHUB_API      = "https://api.github.com/repos/amirotin/telemt_panel/releases/latest"

# Адрес, на котором telemt должен отдавать свой собственный API —
# строго localhost, наружу это лезть не должно ни при каких обстоятельствах.
TELEMT_API_HOST = "127.0.0.1"
TELEMT_API_PORT = 9091

# На чём слушает сама панель (веб-интерфейс). По умолчанию тоже только
# localhost — наружу пробрасывается через существующий Reality-домен
# (reverse-proxy на подпуть) либо через SSH-туннень, см. меню "N".
# При включении "прямого доступа" (self-signed TLS через nginx) —
# слушает 0.0.0.0, а nginx терминирует TLS на PANEL_TLS_PORT.
PANEL_LISTEN_HOST = "127.0.0.1"
PANEL_LISTEN_PORT = 8080
PANEL_TLS_PORT    = 8444  # для self-signed прямого доступа (nginx front)

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ (1-в-1 со стилем mtproto.py/mieru.py)
# ══════════════════════════════════════════════════════════════════════════════
_BOX_W = 66



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

def _box_row(text: str = "") -> None:
    w = _wlen(text)
    if w > _BOX_W:
        acc, plain = 0, _plain(text)
        cut = 0
        for i, ch in enumerate(plain):
            import unicodedata as _ud
            acc += 2 if _ud.east_asian_width(ch) in ('W', 'F') else 1
            if acc > _BOX_W - 1:
                cut = i
                break
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
def _run(cmd: list, capture: bool = False, check: bool = False, input_data: str = None) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if input_data is not None:
        kw.update(input=input_data)
    if capture or input_data is not None:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def _log(msg: str) -> None:
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a") as f:
            f.write(_plain(msg) + "\n")
    except Exception:
        pass

def _ok(msg: str)   -> None: print(f"  {GREEN}✓{NC}  {msg}"); _log(f"[OK] {msg}")
def _warn(msg: str) -> None: print(f"  {YELLOW}⚠{NC}  {msg}"); _log(f"[WARN] {msg}")
def _info(msg: str) -> None: print(f"  {CYAN}→{NC}  {msg}"); _log(f"[INFO] {msg}")
def _err(msg: str)  -> None: print(f"  {RED}✗{NC}  {msg}"); _log(f"[ERR] {msg}")

class _Cancelled(Exception):
    """Пользователь нажал Ctrl+C — возврат в вызывающее меню."""

def _pause() -> None:
    try:
        print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True)
        input()
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

def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _is_installed() -> bool:
    return BIN_PATH.exists() and CONFIG_FILE.exists()

def _is_active() -> bool:
    r = _run(["systemctl", "is-active", "--quiet", SERVICE_NAME])
    return r.returncode == 0

# ══════════════════════════════════════════════════════════════════════════════
#  ИНТЕГРАЦИЯ С mtproto.py (единая точка правды для telemt.toml)
# ══════════════════════════════════════════════════════════════════════════════
def _get_mtproto_module():
    """Ленивый импорт, чтобы не тянуть mtproto.py при простом просмотре меню."""
    try:
        from chimera.modules import mtproto as _mp
        return _mp
    except Exception as e:
        _err(f"Не удалось импортировать модуль mtproto: {e}")
        return None

def _telemt_is_installed(mp) -> bool:
    return bool(mp) and mp.CONFIG_FILE.exists() and mp.BIN_PATH.exists()

# ══════════════════════════════════════════════════════════════════════════════
#  GEOIP — АВТОЗАГРУЗКА БЕЗ РЕГИСТРАЦИИ У MAXMIND
# ══════════════════════════════════════════════════════════════════════════════
# RIPE NCC (stat.ripe.net) отдаёт только announced-prefixes (CIDR ↔ ASN) —
# это не гео-база, там нет ни страны, ни города, ни формата MMDB, который
# ждёт GeoIP2-ридер панели. Поэтому вместо RIPE берём готовые .mmdb базы,
# зеркалируемые через jsDelivr CDN (проект wp-statistics): формат полностью
# совместим со схемой MaxMind, скачивание без ключей и аккаунта.
GEOIP_DIR = DATA_DIR / "geoip"
# GEOIP_SOURCES, _http_get, _geoip_fetch — удалены при финальном cleanup.
# URL'ы перенесены в telemt_geoip_mirrors.py, скачивание через fetch_package
# в _geoip_auto_download(). gzip-decompress делается в post_install
# TELEMT_GEOIP_*_SPEC.

def _geoip_auto_download(use_maxmind_mirror: bool = False) -> tuple:
    """Возвращает (city_mmdb_path, asn_mmdb_path); пустая строка при неудаче.

    МИГРАЦИЯ: раньше использовался _http_get (urllib.request.urlopen) с
    ОДНИМ прямым URL (cdn.jsdelivr.net/npm/...), БЕЗ зеркал, БЕЗ fallback,
    БЕЗ проверки ручного размещения. Прямой аналог geo_files.py (geoip.dat),
    который уже мигрирован.

    Теперь используется fetch_package(TELEMT_GEOIP_CITY_SPEC или
    TELEMT_GEOIP_CITY_MAXMIND_SPEC) и fetch_package(TELEMT_GEOIP_ASN_SPEC)
    из download_manager.py. fetch_package сам:
      1. Проверяет /root/{filename} (manual_incoming_dir из spec) — если
         найден, использует без сети (WinSCP-friendly).
      2. Иначе — перебирает 5 CDN зеркал по очереди через urllib.
      3. При успехе — post_install делает gzip-decompress + запись .mmdb
         в GEOIP_DIR + chown telemt:telemt.
      4. При провале — print_manual_hint() с инструкцией.
    """
    from chimera.modules.download_manager import fetch_package
    from chimera.modules.telemt_geoip_packages import (
        TELEMT_GEOIP_CITY_SPEC, TELEMT_GEOIP_CITY_MAXMIND_SPEC,
        TELEMT_GEOIP_ASN_SPEC,
        _DBIP_CITY_DEST_FILENAME, _MAXMIND_CITY_DEST_FILENAME, _ASN_DEST_FILENAME,
    )

    city_spec = TELEMT_GEOIP_CITY_MAXMIND_SPEC if use_maxmind_mirror else TELEMT_GEOIP_CITY_SPEC
    city_name = _MAXMIND_CITY_DEST_FILENAME if use_maxmind_mirror else _DBIP_CITY_DEST_FILENAME
    asn_name = _ASN_DEST_FILENAME
    city_dest = GEOIP_DIR / city_name
    asn_dest = GEOIP_DIR / asn_name

    _info(f"Скачиваю City-базу ({'MaxMind mirror' if use_maxmind_mirror else 'DB-IP Lite'})...")
    city_ok = fetch_package(city_spec, print_hint_on_failure=False)
    if city_ok:
        _ok(f"City-база сохранена: {city_dest}")
    else:
        _warn("Не удалось скачать City-базу.")

    _info("Скачиваю ASN-базу...")
    asn_ok = fetch_package(TELEMT_GEOIP_ASN_SPEC, print_hint_on_failure=False)
    if asn_ok:
        _ok(f"ASN-база сохранена: {asn_dest}")
    else:
        _warn("Не удалось скачать ASN-базу.")

    if GEOIP_DIR.exists():
        _run(["chown", "-R", f"{SYSTEM_USER}:{SYSTEM_USER}", str(GEOIP_DIR)], check=False)

    return (str(city_dest) if city_ok else "", str(asn_dest) if asn_ok else "")

def _geoip_patch_config(geoip_db: str, geoip_asn_db: str) -> None:
    """Правит только секцию [geoip] в уже существующем config.toml, не трогая остальное."""
    if not CONFIG_FILE.exists():
        return
    text = re.split(r"\n\[geoip\]\n.*", CONFIG_FILE.read_text(), flags=re.S)[0].rstrip() + "\n"
    if geoip_db:
        text += "\n[geoip]\n" + f'db_path = "{geoip_db}"\n'
        if geoip_asn_db:
            text += f'asn_db_path = "{geoip_asn_db}"\n'
    CONFIG_FILE.write_text(text)
    CONFIG_FILE.chmod(0o640)
    _run(["chown", f"{SYSTEM_USER}:{SYSTEM_USER}", str(CONFIG_FILE)], check=False)

def _geoip_update_flow() -> None:
    """Отдельное обновление GeoIP-баз без переустановки панели (пункт меню '5')."""
    if not _is_installed():
        _warn("Telemt Panel не установлена."); _pause(); return
    _box_top("GEOIP — ОБНОВЛЕНИЕ БАЗ")
    _box_row()
    _box_item("1", "DB-IP Lite (без регистрации, обновляется ежемесячно)")
    _box_item("2", "MaxMind GeoLite2 (стороннее CDN-зеркало)")
    _box_bot(); print()
    ch = _ask("  Выбор [1/2, Enter=1]: ", "1", c=True).strip()
    city_db, asn_db = _geoip_auto_download(use_maxmind_mirror=(ch == "2"))
    if not city_db:
        _pause(); return
    _geoip_patch_config(city_db, asn_db)
    _run(["systemctl", "restart", SERVICE_NAME])
    _ok("GeoIP базы обновлены, панель перезапущена.")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  СКАЧИВАНИЕ / УСТАНОВКА БИНАРНИКА ПАНЕЛИ
# ══════════════════════════════════════════════════════════════════════════════
def _get_latest_release() -> tuple:
    """Возвращает (tag, urls) — где urls это СПИСОК зеркал.

    МИГРАЦИЯ: api.github.com зависимость УБРАНА.
    tag всегда "latest" (GitHub сам делает редирект при скачивании),
    urls — список зеркал из telemt_packages.TELEMT_PANEL_SPEC.
    """
    from chimera.modules.telemt_packages import TELEMT_PANEL_SPEC
    urls = TELEMT_PANEL_SPEC.mirror_urls_builder(
        filename=TELEMT_PANEL_SPEC.filename_builder()
    )
    return "latest", urls


def _install_binary(url) -> bool:
    """Устанавливает бинарник telemt-panel из tar.gz-архива.

    МИГРАЦИЯ: использует fetch_package(TELEMT_PANEL_SPEC).
    Параметр `url` игнорируется (оставлен для обратной совместимости).
    """
    from chimera.modules.telemt_packages import TELEMT_PANEL_SPEC
    from chimera.modules.download_manager import fetch_package

    _info(f"Загрузка telemt-panel ({TELEMT_MIRRORS_COUNT} зеркал в fallback)...")
    return fetch_package(TELEMT_PANEL_SPEC, print_hint_on_failure=False)

def _create_system_user() -> None:
    r = _run(["id", SYSTEM_USER], capture=True)
    if r.returncode == 0:
        return
    # Явно создаём группу — не полагаемся на USERGROUPS_ENAB дистрибутива
    # (без неё chgrp в ensure_api_enabled() бьёт мимо несуществующей группы).
    _run(["groupadd", "--system", SYSTEM_USER], check=False)
    _run(["useradd", "--system", "--shell", "/usr/sbin/nologin",
          "--home", "/nonexistent", "--no-create-home",
          "--gid", SYSTEM_USER, SYSTEM_USER], check=False)
    _ok(f"Системный пользователь {SYSTEM_USER} создан")

def _hash_password(password: str) -> Optional[str]:
    r = _run([str(BIN_PATH), "hash-password"], input_data=password + "\n")
    if r.returncode != 0 or not r.stdout.strip():
        _err(f"Не удалось сгенерировать хеш пароля: {r.stderr.strip()}")
        return None
    return r.stdout.strip()

# ══════════════════════════════════════════════════════════════════════════════
#  КОНФИГ ПАНЕЛИ
# ══════════════════════════════════════════════════════════════════════════════
def _generate_config(username: str, password_hash: str, jwt_secret: str,
                      telemt_api_token: str, base_path: str = "",
                      geoip_db: str = "", geoip_asn_db: str = "",
                      telemt_bin_path: str = "", telemt_service_name: str = "") -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Telemt Panel — generated by Chimera Project (Chimera)",
        f'listen = "{PANEL_LISTEN_HOST}:{PANEL_LISTEN_PORT}"',
    ]
    if base_path:
        lines.append(f'base_path = "{base_path}"')
    lines += [
        "",
        "[telemt]",
        f'url = "http://{TELEMT_API_HOST}:{TELEMT_API_PORT}"',
        f'auth_header = "{telemt_api_token}"',
        # config_edit_mode оставляем "api" СОЗНАТЕЛЬНО и без права выбора из
        # меню — это единственный режим, при котором панель структурно не
        # может задеть [server]/[network]/[access] (client_mss, MSS-clamp
        # порты SYN-limiter/iOS-фикса и т.д.), см. шапку файла.
        'config_edit_mode = "api"',
    ]
    if telemt_bin_path:
        # Без этого поля панель по умолчанию считает, что Telemt лежит в
        # /bin/telemt (хардкод в internal/config/config.go самой панели) —
        # у нас он в /usr/local/bin/telemt, из-за чего self-update Telemt
        # из веб-UI бил мимо и падал на "no write access to /bin".
        lines.append(f'binary_path = "{telemt_bin_path}"')
    if telemt_service_name:
        lines.append(f'service_name = "{telemt_service_name}"')
    lines.append('github_repo = "telemt/telemt"')
    lines += [
        "",
        "[auth]",
        f'username = "{username}"',
        f'password_hash = "{password_hash}"',
        f'jwt_secret = "{jwt_secret}"',
        'session_ttl = "24h"',
        "",
        "[panel]",
        f'binary_path = "{BIN_PATH}"',
        f'service_name = "{SERVICE_NAME}"',
        'github_repo = "amirotin/telemt_panel"',
    ]
    if geoip_db:
        lines += ["", "[geoip]", f'db_path = "{geoip_db}"']
        if geoip_asn_db:
            lines.append(f'asn_db_path = "{geoip_asn_db}"')
    CONFIG_FILE.write_text("\n".join(lines) + "\n")
    CONFIG_FILE.chmod(0o640)
    _run(["chown", f"{SYSTEM_USER}:{SYSTEM_USER}", str(CONFIG_FILE)], check=False)
    _run(["chown", "-R", f"{SYSTEM_USER}:{SYSTEM_USER}", str(DATA_DIR)], check=False)

# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEMD
# ══════════════════════════════════════════════════════════════════════════════
def _install_service() -> None:
    SERVICE_FILE.write_text(f"""[Unit]
Description=Telemt Panel — web UI for Telemt MTProxy
After=network-online.target telemt.service
Wants=network-online.target

[Service]
Type=simple
User={SYSTEM_USER}
Group={SYSTEM_USER}
ExecStart={BIN_PATH} --config {CONFIG_FILE}
Restart=on-failure
RestartSec=3
# NoNewPrivileges сознательно НЕ ставим: панель обновляет бинарник Telemt
# (владелец root) через узкий sudoers drop-in (см. _install_sudoers ниже),
# а NoNewPrivileges блокирует sudo на уровне ядра целиком, без обхода —
# именно так это официально сделано в install.sh самого telemt_panel.
ProtectHome=true
PrivateTmp=true
ReadWritePaths={CONFIG_DIR} {DATA_DIR}

[Install]
WantedBy=multi-user.target
""")
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", SERVICE_NAME])
    _ok("systemd-юнит установлен и включён в автозапуск")

def _install_sudoers(mp) -> bool:
    """
    Узкий sudoers drop-in — повторяет схему официального install.sh проекта
    telemt_panel (install_sudoers_dropin() там же): NOPASSWD только на
    конкретные команды с конкретными путями (никакого 'ALL'/wildcard на
    сами команды) — cp/mv/chmod/rm строго по staging-файлам панели и
    Telemt, плюс перезапуск/логи обеих служб. Без этого self-update Telemt
    из веб-UI падает с "no write access ... sudo copy ... failed", т.к.
    NoNewPrivileges снят, но самого правила sudo ещё не было.
    """
    def _which(cmd: str) -> str:
        return shutil.which(cmd) or f"/usr/bin/{cmd}"

    cp, mv, chmod, rm = _which("cp"), _which("mv"), _which("chmod"), _which("rm")
    tee, systemctl, journalctl = _which("tee"), _which("systemctl"), _which("journalctl")

    staging = DATA_DIR / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    _run(["chown", f"{SYSTEM_USER}:{SYSTEM_USER}", str(staging)], check=False)

    panel_tmp    = BIN_PATH.parent / f".{BIN_PATH.name}.tmp"
    panel_backup = staging / f"{BIN_PATH.name}.bak"
    panel_stage  = staging / BIN_PATH.name

    telemt_bin    = mp.BIN_PATH
    telemt_name   = telemt_bin.name
    telemt_tmp    = telemt_bin.parent / f".{telemt_name}.tmp"
    telemt_backup = staging / f"{telemt_name}.bak"
    telemt_stage  = staging / telemt_name
    telemt_service = mp.SERVICE_NAME
    telemt_config  = mp.CONFIG_FILE

    rules = [
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: {cp} -f {BIN_PATH} {panel_backup}",
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: {cp} -f {telemt_bin} {telemt_backup}",
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: {cp} -f {panel_stage} {panel_tmp}",
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: {cp} -f {telemt_stage} {telemt_tmp}",
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: {chmod} 0755 {panel_tmp}",
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: {chmod} 0755 {telemt_tmp}",
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: {mv} -f {panel_tmp} {BIN_PATH}",
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: {mv} -f {telemt_tmp} {telemt_bin}",
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: {rm} -f {panel_tmp}",
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: {rm} -f {telemt_tmp}",
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: {systemctl} restart {SERVICE_NAME}",
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: {systemctl} restart {telemt_service}",
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: {systemctl} start {SERVICE_NAME}",
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: {systemctl} start {telemt_service}",
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: {journalctl} -u {telemt_service} -n * --no-pager -o short-iso",
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: {journalctl} -u {telemt_service} -n * --since * --no-pager -o short-iso",
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: {journalctl} -u {telemt_service} -f --no-pager -o short-iso",
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: {journalctl} -u {telemt_service} -f --since * --no-pager -o short-iso",
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: {tee} {telemt_config}",
    ]

    tmp = Path(tempfile.mkdtemp()) / "telemt-panel.sudoers"
    tmp.write_text("\n".join(rules) + "\n")

    visudo = shutil.which("visudo")
    if visudo:
        r = _run([visudo, "-cf", str(tmp)], capture=True)
        if r.returncode != 0:
            _err(f"Сгенерированный sudoers-файл невалиден: {r.stdout} {r.stderr}")
            shutil.rmtree(tmp.parent, ignore_errors=True)
            return False

    dest = Path("/etc/sudoers.d") / SERVICE_NAME
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(tmp), str(dest))
    dest.chmod(0o440)
    shutil.rmtree(tmp.parent, ignore_errors=True)
    _ok(f"sudoers drop-in установлен: {dest}")
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА
# ══════════════════════════════════════════════════════════════════════════════
def _run_install() -> None:
    mp = _get_mtproto_module()
    if not _telemt_is_installed(mp):
        _err("Telemt не установлен — панели нечего показывать.")
        _box_info("Сначала установите Telemt через пункт '1' в его собственном меню.")
        _pause()
        return

    if _is_installed():
        _box_warn("Telemt Panel уже установлена.")
        if _ask(f"  Переустановить поверх? (y/N): ", "n", c=True).lower() != "y":
            return

    _box_top("УСТАНОВКА TELEMT PANEL")
    _box_row()
    _box_info("Панель будет слушать только 127.0.0.1:8080 — наружу")
    _box_info("не светится. Доступ снаружи: SSH-туннель или reverse-proxy")
    _box_info("на подпуть через уже существующий Reality-домен.")
    _box_bot()
    print()

    # ── 1. Системный пользователь + группа — ДО включения [server.api], иначе
    #      chgrp внутри ensure_api_enabled() бьёт мимо ещё не созданной группы.
    _create_system_user()

    # ── 2. Включаем [server.api] в конфиге telemt (единая точка правды — mtproto.py)
    _info("Проверяю/включаю API у Telemt...")
    telemt_api_token = secrets.token_hex(24)
    ok, msg = mp.ensure_api_enabled(telemt_api_token, host=TELEMT_API_HOST, port=TELEMT_API_PORT,
                                     grant_read_to=SYSTEM_USER)
    if not ok:
        _err(f"Не удалось включить API Telemt: {msg}")
        _pause()
        return
    _ok(msg)

    # ── 3. Скачиваем бинарник панели
    tag, urls = _get_latest_release()
    if not urls:
        _pause(); return
    display_tag = "последней версии" if tag == "latest" else (tag or "?")
    _info(f"Последний релиз: {display_tag}")
    if not _install_binary(urls):
        # Показываем инструкцию для ручного скачивания (WinSCP-friendly)
        _print_telemt_manual_hint("panel")
        try:
            ans = input(f"  {CYAN}Разместили файлы вручную? Повторить установку? [Y/n]: {NC}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans != "n":
            if not _install_binary(urls):
                _err(f"Файлы не найдены в {', '.join(str(p) for p in _TELEMT_MANUAL_PATHS)}.")
                _pause(); return
        else:
            _pause(); return

    # ── 4. Учётные данные панели
    print()
    username = _ask(f"  Логин администратора [{CYAN}admin{NC}]: ", "admin", c=True)
    while True:
        password = _ask(f"  Пароль администратора (не короче 8 симв.): ", "", c=True)
        if len(password) >= 8:
            break
        _warn("Слишком короткий пароль.")

    password_hash = _hash_password(password)
    if not password_hash:
        _pause(); return
    jwt_secret = secrets.token_hex(32)

    base_path = _ask(f"  Base path за reverse-proxy (Enter — не использовать): ", "", c=True)

    # ── 4.5. GeoIP (необязательно) — страна/город клиентов по IP.
    print()
    _box_info("GeoIP (необязательно) — показывает страну/город по IP клиентов.")
    _box_item("1", "Скачать автоматически (DB-IP Lite, без регистрации)")
    _box_item("2", "Указать путь к своим .mmdb вручную")
    _box_item("3", "Пропустить (включить можно будет позже, пункт '5')")
    geoip_choice = _ask("  Выбор [1/2/3, Enter=1]: ", "1", c=True).strip()

    geoip_db, geoip_asn_db = "", ""
    if geoip_choice == "1":
        geoip_db, geoip_asn_db = _geoip_auto_download()
    elif geoip_choice == "2":
        geoip_db = _ask("  Путь к City .mmdb (Enter — пропустить): ", "", c=True)
        if geoip_db and not Path(geoip_db).is_file():
            _warn(f"Файл не найден: {geoip_db} — GeoIP не будет включён.")
            geoip_db = ""
        elif geoip_db:
            geoip_asn_db = _ask("  Путь к ASN .mmdb (Enter — пропустить): ", "", c=True)
            if geoip_asn_db and not Path(geoip_asn_db).is_file():
                _warn(f"Файл не найден: {geoip_asn_db} — ASN-данные не будут включены.")
                geoip_asn_db = ""

    # ── 5. Конфиг + systemd
    _generate_config(username, password_hash, jwt_secret, telemt_api_token, base_path,
                      geoip_db, geoip_asn_db,
                      telemt_bin_path=str(mp.BIN_PATH), telemt_service_name=mp.SERVICE_NAME)
    _install_service()
    if not _install_sudoers(mp):
        _warn("sudoers drop-in не встал — self-update Telemt/панели из веб-UI работать не будет,")
        _warn("остальной функционал панели это не затрагивает.")
    _run(["systemctl", "restart", SERVICE_NAME])

    if _is_active():
        _ok("Telemt Panel запущена")
    else:
        _err("Сервис не поднялся — смотри 'journalctl -u telemt-panel -n 50'")

    print()
    _box_top("ГОТОВО")
    _box_kv("URL (локально):", f"http://{PANEL_LISTEN_HOST}:{PANEL_LISTEN_PORT}")
    _box_kv("Логин:", username)
    _box_kv("Пароль:", "тот, что вы ввели — нигде не хранится в открытом виде")
    _box_row()
    _box_warn("Панель на 127.0.0.1 — прокиньте порт через:")
    _box_info(f"ssh -L {PANEL_LISTEN_PORT}:127.0.0.1:{PANEL_LISTEN_PORT} root@<ваш_сервер>")
    _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС / УПРАВЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _show_status() -> None:
    _box_top("СТАТУС TELEMT PANEL")
    if not _is_installed():
        _box_warn("Не установлена.")
        _box_bot(); _pause(); return
    _box_kv("Сервис:", f"{GREEN}активен{NC}" if _is_active() else f"{RED}остановлен{NC}")
    _box_kv("Бинарник:", str(BIN_PATH))
    _box_kv("Конфиг:", str(CONFIG_FILE))
    _box_kv("Слушает:", f"{PANEL_LISTEN_HOST}:{PANEL_LISTEN_PORT}")
    r = _run([str(BIN_PATH), "version"], capture=True)
    if r.returncode == 0:
        _box_kv("Версия:", r.stdout.strip())
    _box_bot()
    _pause()

def _update() -> None:
    if not _is_installed():
        _warn("Telemt Panel не установлена."); _pause(); return
    tag, urls = _get_latest_release()
    if not urls:
        _pause(); return
    display_tag = "последней версии" if tag == "latest" else (tag or "последней версии")
    _info(f"Обновляю до {display_tag}...")
    if _install_binary(urls):
        _run(["systemctl", "restart", SERVICE_NAME])
        _ok("Обновлено и перезапущено")
    else:
        # Показываем инструкцию для ручного скачивания (WinSCP-friendly)
        _print_telemt_manual_hint("panel")
        try:
            ans = input(f"  {CYAN}Разместили файлы вручную? Повторить? [Y/n]: {NC}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans != "n":
            if _install_binary(urls):
                _run(["systemctl", "restart", SERVICE_NAME])
                _ok("Обновлено и перезапущено (из ручного размещения)")
    _pause()

def _uninstall() -> None:
    if not _is_installed():
        _warn("Telemt Panel не установлена."); _pause(); return
    if _ask(f"  {RED}Точно удалить Telemt Panel полностью? (y/N): {NC}", "n", c=True).lower() != "y":
        return
    # Удаляем nginx front для telemt если был.
    _telemt_remove_direct_access()
    _run(["systemctl", "stop", SERVICE_NAME], check=False)
    _run(["systemctl", "disable", SERVICE_NAME], check=False)
    SERVICE_FILE.unlink(missing_ok=True)
    _run(["systemctl", "daemon-reload"])
    shutil.rmtree(CONFIG_DIR, ignore_errors=True)
    shutil.rmtree(DATA_DIR, ignore_errors=True)
    BIN_PATH.unlink(missing_ok=True)
    _run(["userdel", SYSTEM_USER], check=False)
    _ok("Telemt Panel полностью удалена.")
    _box_info("API у Telemt (секция [server.api] в telemt.toml) оставлена как есть —")
    _box_info("отключить можно из меню самого Telemt при необходимости.")
    _pause()


# ══════════════════════════════════════════════════════════════════════════════
#  ПРЯМОЙ ДОСТУП (self-signed TLS через nginx)
# ══════════════════════════════════════════════════════════════════════════════
TELEMT_NGINX_SITE = "chimera-telemt-panel-nginx"
TELEMT_NGINX_AVAILABLE = Path("/etc/nginx/sites-available") / TELEMT_NGINX_SITE
TELEMT_NGINX_ENABLED = Path("/etc/nginx/sites-enabled") / TELEMT_NGINX_SITE
TELEMT_NGINX_STATE = Path("/var/lib/xray-installer/telemt_panel_direct.json")


def _telemt_direct_status() -> dict:
    try:
        if TELEMT_NGINX_STATE.exists():
            return json.loads(TELEMT_NGINX_STATE.read_text())
    except Exception:
        pass
    return {"enabled": False}


def _telemt_setup_direct_access() -> bool:
    """Ставит nginx vhost с self-signed TLS для прямого доступа к Telemt Panel."""
    if not _is_installed():
        _warn("Сначала установите Telemt Panel.")
        return False

    public_ip = ""
    r = _run(["curl", "-s", "--max-time", "5", "ifconfig.me"], capture=True, check=False)
    if r.returncode == 0:
        public_ip = r.stdout.strip()

    # Self-signed TLS.
    ssl_dir = Path("/etc/nginx/ssl")
    ssl_dir.mkdir(parents=True, exist_ok=True)
    cert = ssl_dir / "telemt-panel-self-signed.crt"
    key  = ssl_dir / "telemt-panel-self-signed.key"
    r = _run([
        "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
        "-sha256", "-days", "825",
        "-keyout", str(key), "-out", str(cert),
        "-subj", "/CN=telemt-panel",
        "-addext", f"subjectAltName=IP:{public_ip or '127.0.0.1'},DNS:localhost",
    ], capture=True, check=False)
    if r.returncode != 0:
        _err("Не удалось сгенерировать TLS сертификат")
        return False
    key.chmod(0o600)
    cert.chmod(0o644)

    # nginx vhost.
    vhost = f"""# Chimera — nginx front для Telemt Panel (self-signed TLS).
server {{
    listen {PANEL_TLS_PORT} ssl http2;
    server_name _;

    ssl_certificate     {cert};
    ssl_certificate_key {key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    access_log /var/log/nginx/telemt-panel-access.log;
    error_log  /var/log/nginx/telemt-panel-error.log;

    location / {{
        proxy_pass http://127.0.0.1:{PANEL_LISTEN_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_connect_timeout 30s;
        proxy_read_timeout 60s;
    }}
}}
"""
    try:
        TELEMT_NGINX_AVAILABLE.parent.mkdir(parents=True, exist_ok=True)
        TELEMT_NGINX_AVAILABLE.write_text(vhost)
        if TELEMT_NGINX_ENABLED.exists() or TELEMT_NGINX_ENABLED.is_symlink():
            TELEMT_NGINX_ENABLED.unlink()
        TELEMT_NGINX_ENABLED.symlink_to(TELEMT_NGINX_AVAILABLE)
    except Exception as e:
        _err(f"Не удалось записать nginx vhost: {e}")
        return False

    # nginx -t + reload.
    nginx_bin = shutil.which("nginx")
    if not nginx_bin:
        _err("nginx не установлен")
        return False
    r = _run([nginx_bin, "-t"], capture=True, check=False)
    if r.returncode != 0:
        _err(f"nginx -t failed: {r.stderr.strip()[:300]}")
        TELEMT_NGINX_ENABLED.unlink(missing_ok=True)
        TELEMT_NGINX_AVAILABLE.unlink(missing_ok=True)
        return False
    _run(["systemctl", "reload", "nginx"], check=False)

    # UFW через port_registry.
    try:
        from chimera.modules.port_registry import (
            ufw_open_port, port_register,
        )
        port_register("telemt_panel_direct", PANEL_TLS_PORT, "tcp",
                      comment="Telemt Panel direct (TLS)", force=True)
        ufw_open_port(PANEL_TLS_PORT, "tcp", "telemt_panel_direct",
                      comment="Telemt Panel direct (TLS)")
    except Exception:
        pass

    # State.
    TELEMT_NGINX_STATE.parent.mkdir(parents=True, exist_ok=True)
    TELEMT_NGINX_STATE.write_text(json.dumps({
        "enabled": True,
        "port": PANEL_TLS_PORT,
        "url": f"https://{public_ip or 'SERVER_IP'}:{PANEL_TLS_PORT}",
    }, indent=2))

    _ok(f"Прямой доступ включён: https://{public_ip or 'SERVER_IP'}:{PANEL_TLS_PORT}")
    _box_warn("Браузер предупредит о self-signed TLS — это нормально.")
    return True


def _telemt_remove_direct_access() -> None:
    """Удаляет nginx vhost + закрывает порт для прямого доступа к Telemt Panel."""
    state = _telemt_direct_status()
    if not state.get("enabled"):
        return
    TELEMT_NGINX_ENABLED.unlink(missing_ok=True)
    TELEMT_NGINX_AVAILABLE.unlink(missing_ok=True)
    nginx_bin = shutil.which("nginx")
    if nginx_bin:
        _run([nginx_bin, "-t"], capture=True, check=False)
        _run(["systemctl", "reload", "nginx"], check=False)
    try:
        from chimera.modules.port_registry import (
            ufw_close_port, port_unregister,
        )
        ufw_close_port(PANEL_TLS_PORT, "tcp", "telemt_panel_direct",
                       legacy_comments=["Telemt Panel direct (TLS)"])
        port_unregister("telemt_panel_direct", PANEL_TLS_PORT, "tcp")
    except Exception:
        pass
    TELEMT_NGINX_STATE.unlink(missing_ok=True)
    _info("Прямой доступ к Telemt Panel отключён, порт закрыт.")


def _toggle_direct_access() -> None:
    """Включить/выключить прямой доступ к Telemt Panel."""
    state = _telemt_direct_status()
    if state.get("enabled"):
        _telemt_remove_direct_access()
        _ok("Прямой доступ выключен.")
    else:
        _telemt_setup_direct_access()
    _pause()


# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════
def telemt_panel_menu() -> None:
    while True:
        print()
        _box_top("TELEMT PANEL — веб-интерфейс для Telemt")
        _box_row()
        status = f"{GREEN}установлена, активна{NC}" if (_is_installed() and _is_active()) \
            else f"{YELLOW}установлена, остановлена{NC}" if _is_installed() \
            else f"{DIM}не установлена{NC}"
        _box_kv("Статус:", status)
        # Прямой доступ.
        direct = _telemt_direct_status()
        if direct.get("enabled"):
            _box_kv("Прямой доступ:", f"{GREEN}https://...:{direct.get('port', PANEL_TLS_PORT)}{NC}")
        _box_row(); _box_sep()
        _box_item("1", "🚀  Установить / переустановить")
        _box_item("2", "📋  Статус")
        _box_item("3", "🔄  Перезапустить сервис")
        _box_item("4", "⬆️   Проверить и обновить")
        _box_item("5", "🌍  Обновить GeoIP-базы")
        if _is_installed():
            if direct.get("enabled"):
                _box_item("6", f"{YELLOW}🔒  Выключить прямой доступ (TLS){NC}")
            else:
                _box_item("6", f"{GREEN}🌐  Включить прямой доступ (self-signed TLS){NC}")
        _box_item("8", f"{RED}🗑️   Полное удаление{NC}")
        _box_sep()
        _box_item("Q", "← Назад в меню Telemt")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            _run_install()
        elif ch == "2":
            _show_status()
        elif ch == "3":
            if not _is_installed():
                _warn("Не установлена."); _pause(); continue
            _run(["systemctl", "restart", SERVICE_NAME])
            _ok("Сервис перезапущен."); _pause()
        elif ch == "4":
            _update()
        elif ch == "5":
            _geoip_update_flow()
        elif ch == "6" and _is_installed():
            _toggle_direct_access()
        elif ch == "8":
            _uninstall()
        elif ch in ("q", ""):
            break
