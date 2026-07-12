"""
vless_installer/modules/singbox_common.py
───────────────────────────────────────────────────────────────────────────────
Общие утилиты для всех sing-box-модулей.

По образцу hysteria2_common.py:
  • Цвета и log_to_file
  • subprocess helper _run
  • Пути и константы
  • State load/save (делегирует в singbox_state.py, но дублирует API для совместимости)

Все sing-box модули (singbox_install, singbox_config, singbox_menu, etc.)
импортируют отсюда базовые вещи — не зависят напрямую от _core.py.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


# ============================================================================
#  КОНСТАНТЫ — пути
# ============================================================================
SINGBOX_BINARY         = Path("/usr/local/bin/sing-box")
SINGBOX_CONFIG_DIR     = Path("/etc/sing-box")
SINGBOX_CONFIG_FILE    = SINGBOX_CONFIG_DIR / "config.json"
SINGBOX_CERT_DIR       = Path("/etc/sing-box/certs")
SINGBOX_STATE_FILE     = Path("/var/lib/xray-installer/singbox_state.json")
SINGBOX_LOG_FILE       = Path("/var/log/singbox.log")
SINGBOX_INSTALL_LOG    = Path("/var/log/vless-install.log")
SINGBOX_SERVICE        = "sing-box"

# Регистрация в основном state.json (аналог awg_standalone_state.json).
# Основной state.json получает одну запись: "singbox_state_file": "/var/lib/..."
MAIN_STATE_FILE        = Path("/var/lib/xray-installer/state.json")

# Порты по умолчанию для каждого протокола.
# Внимание: TCP:443 зарезервирован под VLESS REALITY (или под SNI-dispatch).
# Sing-box inbound'ы слушают на loopback или отдельных портах, nginx stream{}
# (если включён SNI-dispatch) перенаправляет трафик с :443 на них.
DEFAULT_PORT_SHADOWTLS  = 8443   # TCP, loopback, handshaked к маскировочному домену
DEFAULT_PORT_ANYTLS      = 8444   # TCP, loopback
DEFAULT_PORT_TUIC        = 8443   # UDP (не конфликтует с TCP:8443)
# ^ TUIC использует UDP — порт 8443/udp не конфликтует с TCP:8443 ShadowTLS.
# Но чтобы избежать путаницы в firewall/диагностике, можно вынести на 443/udp
# (параллельно с TCP:443 — Reality или SNI-dispatch).
DEFAULT_PORT_TUIC_ALTERNATIVE = 443  # UDP/443 — параллельно с TCP/443

# Маскировочные домены для ShadowTLS (по умолчанию).
# ShadowTLS v3 делает честный TLS-handshake к этому домену, после чего
# переключается на внутренний Trojan. Цензор видит «настоящий» TLS-ответ.
DEFAULT_SHADOWTLS_HANDSHAKE_HOST = "www.cloudflare.com"
DEFAULT_SHADOWTLS_HANDSHAKE_PORT = 443

# Path к существующему LE-сертификату (если есть PARAM_DOMAIN).
# Используется ssl_certbot.py. ShadowTLS может использовать этот же сертификат.
LE_LIVE_DIR = Path("/etc/letsencrypt/live")


# ============================================================================
#  КОНСТАНТЫ — протоколы
# ============================================================================
# Какой протокол к какому sing-box inbound-type относится.
PROTOCOL_SHADOWTLS  = "shadowtls"
PROTOCOL_ANYTLS     = "anytls"
PROTOCOL_TUIC       = "tuic"
PROTOCOL_TROJAN     = "trojan"  # внутренний, под ShadowTLS

ALL_PROTOCOLS = (PROTOCOL_SHADOWTLS, PROTOCOL_ANYTLS, PROTOCOL_TUIC)


# ============================================================================
#  Цвета (как во всех модулях проекта)
# ============================================================================
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
            DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED    = _C['RED'];   GREEN  = _C['GREEN'];  YELLOW = _C['YELLOW']
CYAN   = _C['CYAN'];  BLUE   = _C['BLUE'];   BOLD   = _C['BOLD']
DIM    = _C['DIM'];   WHITE  = _C['WHITE'];  NC     = _C['NC']


# ============================================================================
#  Логирование
# ============================================================================
def _log(level: str, msg: str) -> None:
    try:
        SINGBOX_INSTALL_LOG.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        with SINGBOX_INSTALL_LOG.open("a") as f:
            f.write(f"[{ts}] [{level}] [SINGBOX] {clean}\n")
    except Exception:
        pass


def info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");    _log("INFO",    msg)
def success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}");   _log("SUCCESS", msg)
def warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}");  _log("WARN",    msg)
def error(msg: str)   -> None: print(f"{RED}[ERR]{NC}   {msg}");     _log("ERROR",   msg)
def log_to_file(level: str, msg: str) -> None: _log(level, msg)


# ============================================================================
#  subprocess helper
# ============================================================================
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False, timeout: int = 60) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8",
                  errors="replace", timeout=timeout)
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                  timeout=timeout)
    return subprocess.run(cmd, **kw)


# ============================================================================
#  State helpers — делегируют в singbox_state.py (для обратной совместимости
#  импортов внутри других sing-box модулей).
# ============================================================================
def _load_main_state() -> dict:
    """Читает основной state.json (для PATH_DOMAIN и др.)."""
    try:
        if not MAIN_STATE_FILE.exists():
            return {}
        return json.loads(MAIN_STATE_FILE.read_text())
    except Exception:
        return {}


def _save_main_state(st: dict) -> bool:
    """Атомарно обновляет основной state.json."""
    try:
        MAIN_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = MAIN_STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(st, indent=2, ensure_ascii=False))
        tmp.replace(MAIN_STATE_FILE)
        return True
    except Exception as e:
        error(f"Ошибка записи state.json: {e}")
        return False


def register_singbox_in_main_state() -> bool:
    """Регистрирует путь к singbox_state.json в основном state.json.
    Аналогично тому, как awg_standalone_state.json регистрируется в основном state.
    Идемпотентно — не перезаписывает если уже зарегистрирован.

    Возвращает True при успехе (записано или уже было зарегистрировано),
    False при ошибке записи в main_state.json.
    """
    st = _load_main_state()
    if st.get("singbox_state_file") == str(SINGBOX_STATE_FILE):
        return True  # уже зарегистрировано
    st["singbox_state_file"] = str(SINGBOX_STATE_FILE)
    return _save_main_state(st)


def unregister_singbox_from_main_state() -> None:
    """Удаляет регистрацию sing-box из основного state.json (при uninstall)."""
    st = _load_main_state()
    if "singbox_state_file" in st:
        st.pop("singbox_state_file")
        _save_main_state(st)


# ============================================================================
#  systemd helpers
# ============================================================================
def _systemctl(action: str, service: str = SINGBOX_SERVICE) -> bool:
    r = _run(["systemctl", action, service], quiet=True)
    return r.returncode == 0


def _service_active(service: str = SINGBOX_SERVICE) -> bool:
    r = _run(["systemctl", "is-active", "--quiet", service], quiet=True)
    return r.returncode == 0


def _service_enabled(service: str = SINGBOX_SERVICE) -> bool:
    r = _run(["systemctl", "is-enabled", service], capture=True, quiet=True)
    return r.stdout.strip() == "enabled"


# ============================================================================
#  Binary helpers
# ============================================================================
def _singbox_binary_exists() -> bool:
    return SINGBOX_BINARY.exists() and os.access(str(SINGBOX_BINARY), os.X_OK)


def _singbox_binary_version() -> str:
    """Возвращает версию sing-box или пустую строку."""
    if not _singbox_binary_exists():
        return ""
    try:
        r = _run([str(SINGBOX_BINARY), "version"], capture=True)
        # Вывод вида: "sing-box version 1.11.4\n\nEnvironment: ..."
        m = re.search(r'version\s+(\d+\.\d+\.\d+)', r.stdout)
        return m.group(1) if m else ""
    except Exception:
        return ""


# ============================================================================
#  Архитектура и GitHub API
# ============================================================================
def _detect_arch() -> str:
    """Возвращает архитектуру в формате sing-box release asset."""
    import platform
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    if machine in ("armv7l", "armv6l"):
        return "arm-7"
    if machine in ("i386", "i686"):
        return "386"
    return machine


_GH_API_LATEST = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"


def _get_latest_release_info() -> tuple[str, str]:
    """Возвращает (tag, tarball_filename) для последнего релиза sing-box.

    Returns:
      ("v1.13.14", "sing-box-1.13.14-linux-amd64.tar.gz")
      или ("", "") при ошибке.

    ВАЖНО: tag возвращается С префиксом "v" (как в GitHub tag_name), потому что
    реальные URL release assets используют /releases/download/v{tag}/.
    Если отрезать "v" (как делалось раньше в v4.22.0-v4.22.2), URL получается
    /releases/download/1.13.14/ и GitHub возвращает 404 — все 8 зеркал падали.

    Filename же строится БЕЗ v, потому что в asset name нет v:
    "sing-box-1.13.14-linux-amd64.tar.gz" (не "sing-box-v1.13.14-...").
    """
    arch = _detect_arch()
    try:
        r = _run(["curl", "-s", "--max-time", "15", _GH_API_LATEST], capture=True)
        if r.returncode != 0:
            return "", ""
        data = json.loads(r.stdout)
        # НЕ отрезаем "v" — tag нужен для URL как есть (v1.13.14)
        tag = data.get("tag_name", "")
        if not tag:
            return "", ""
        # Для построения filename нужна версия БЕЗ v
        version = tag.lstrip("v")
        # Ищем asset под нашу архитектуру: sing-box-{version}-linux-{arch}.tar.gz
        wanted = f"sing-box-{version}-linux-{arch}.tar.gz"
        for asset in data.get("assets", []):
            if asset.get("name") == wanted:
                return tag, wanted
        # Fallback: ищем по паттерну
        for asset in data.get("assets", []):
            name = asset.get("name", "")
            if name.startswith(f"sing-box-") and name.endswith(f"-linux-{arch}.tar.gz"):
                return tag, name
        return "", ""
    except Exception:
        return "", ""


# ============================================================================
#  Сертификаты — self-signed helpers (для TUIC, AnyTLS)
# ============================================================================
def generate_self_signed_cert(
    common_name: str = "sing-box",
    cert_path: Path = SINGBOX_CERT_DIR / "self-signed.crt",
    key_path: Path = SINGBOX_CERT_DIR / "self-signed.key",
    san_ip: str = "",
    san_dns: str = "",
    days: int = 3650,
) -> tuple[Path, Path]:
    """Генерирует self-signed сертификат с SAN (как у Hysteria2).

    Возвращает (cert_path, key_path).
    """
    cert_path.parent.mkdir(parents=True, exist_ok=True)

    subj = f"/CN={common_name}"
    addext_args = [
        "-addext", "basicConstraints=CA:FALSE",
        "-addext", "keyUsage=digitalSignature,keyEncipherment",
        "-addext", "extendedKeyUsage=serverAuth",
    ]
    if san_ip:
        addext_args += ["-addext", f"subjectAltName=IP:{san_ip}"]
    if san_dns:
        addext_args += ["-addext", f"subjectAltName=DNS:{san_dns}"]

    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:4096",
        "-keyout", str(key_path),
        "-out", str(cert_path),
        "-days", str(days), "-nodes",
        "-subj", subj,
    ] + addext_args

    _run(cmd, quiet=True)
    return cert_path, key_path


def cert_sha256_fingerprint(cert_path: Path) -> str:
    """Возвращает SHA256-отпечаток сертификата в hex (как у Hysteria2)."""
    try:
        r = _run(["openssl", "x509", "-noout", "-fingerprint", "-sha256",
                  "-in", str(cert_path)], capture=True)
        raw = r.stdout.split("=", 1)[-1].strip()
        return raw.replace(":", "").lower()
    except Exception:
        return ""
