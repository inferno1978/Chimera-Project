"""
chimera/modules/singbox_common.py
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
SINGBOX_INSTALL_LOG    = Path("/var/log/chimera.log")
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

# SNI-пресеты для ShadowTLS (адаптировано из HYDRA-ULTIMATE, gr33nimax)
# Курируемый список TLS 1.3 доменов для маскировки.
# Разделены на международные (Microsoft/Apple/Cloudflare/etc.) и
# российские (Яндекс/ВК/MAX/Дзен/Rutube/Ozon).
SHADOWTLS_SNI_PRESETS = (
    ("www.microsoft.com", "Международный · Microsoft"),
    ("www.apple.com", "Международный · Apple"),
    ("www.cloudflare.com", "Международный · Cloudflare"),
    ("www.amazon.com", "Международный · Amazon"),
    ("www.samsung.com", "Международный · Samsung"),
    ("www.adobe.com", "Международный · Adobe"),
    ("ya.ru", "Россия · Яндекс"),
    ("vk.com", "Россия · ВКонтакте"),
    ("max.ru", "Россия · MAX"),
    ("dzen.ru", "Россия · Дзен"),
    ("rutube.ru", "Россия · Rutube"),
    ("www.ozon.ru", "Россия · Ozon"),
)

# Path к существующему LE-сертификату (если есть PARAM_DOMAIN).
# Используется ssl_certbot.py. ShadowTLS может использовать этот же сертификат.
LE_LIVE_DIR = Path("/etc/letsencrypt/live")


# ============================================================================
#  VLESS-WS-CDN — порты и CDN-провайдеры (v4.23, fixed v4.23.1)
# ============================================================================
# ПРОВЕРКА ПОРТОВ CDN (web search 2026-07-12, перепроверено v4.23.1):
#
# Cloudflare (developers.cloudflare.com/fundamentals/reference/network-ports):
#   HTTP-порты, проксируемые CF: 80, 8080, 8880, 2052, 2082, 2086, 2095
#   HTTPS-порты: 443, 2053, 2083, 2087, 2096, 8443
#
#   v4.23.1: origin НЕ поднимает TLS (см. _build_vless_ws_cdn_inbound —
#   никакого tls{} блока). Поэтому CDN↔origin должен быть HTTP, не HTTPS.
#   Для Cloudflare это режим SSL = Flexible (CF↔client = HTTPS, CF↔origin = HTTP).
#   8443 — HTTPS-only порт в списке CF, НЕ подходит для HTTP origin pull.
#   Per-provider дефолт для Cloudflare: 8080 (из CF HTTP-списка).
#
# Gcore (gcore.com/docs/cdn/cdn-resource-options/general/specify-an-origin-and-the-origin-pull-protocol):
#   Origin Pull Protocol: HTTP / HTTPS / HTTP and HTTPS.
#   Кастомный порт указывается в origin URL: http://origin.example.com:8443
#   Для HTTP pull: default 80, кастомный — через URL.
#   8443 работает как кастомный origin port с HTTP scheme.
#
# Bunny.net (docs.bunny.net/api-reference/core/pull-zone/add-pull-zone):
#   Поле OriginPort в API/dashboard — поддерживает произвольный порт.
#   DnsOriginScheme: HTTP или HTTPS.
#   Для HTTP pull: OriginPort = 8443, scheme = HTTP.
#
# ИТОГ (v4.23.1): per-provider default port.
#   Cloudflare: 8080 (из CF HTTP port list — валиден для Flexible mode)
#   Gcore: 8443 (custom origin URL port, HTTP scheme)
#   Bunny: 8443 (OriginPort field, HTTP scheme)
#
# КРИТИЧНО: origin слушает НЕ по TLS. CDN обязан ходить к origin по HTTP (Flexible),
# а не HTTPS. Если поставить Full/Full(strict) — CF попытается TLS-handshake к
# origin, который не отвечает TLS → 521/525 ошибка на стороне CF.
DEFAULT_PORT_VLESS_WS_CDN = 8080   # Fallback default (Cloudflare HTTP port)


# Реестр поддерживаемых CDN-провайдеров.
# cdn_provider в state — это ключ из этого dict.
# Каждый провайдер содержит:
#   display_name  — для TUI
#   default_port  — рекомендуемый listen_port для этого CDN (v4.23.1)
#   instructions  — многострочный текст для вывода при enable
#   ip_source     — URL для live-fetch IP-диапазонов (allowlist, v4.23.1)
#   ip_format     — "plaintext" | "json_addresses" | "html_scrape"
CDN_PROVIDERS: dict = {
    "cloudflare": {
        "display_name": "Cloudflare",
        "default_port": 8080,   # из CF HTTP port list, валиден для Flexible mode
        "ip_source": "https://www.cloudflare.com/ips-v4",
        "ip_format": "plaintext",
        "instructions": [
            "1. В Cloudflare Dashboard → DNS → создайте A/AAAA-запись",
            "   для вашего домена (например vless.example.com) с IP сервера.",
            "   Включите оранжевое облако (Proxied) — это обязательно для CDN.",
            "",
            "2. SSL/TLS → Overview → установите режим 'Flexible'.",
            "   Flexible: CF↔client = HTTPS (CF cert), CF↔origin = HTTP (plain).",
            "   НЕ используйте 'Full' или 'Full (strict)' — origin не имеет TLS,",
            "   CF получит 521/525 ошибку при попытке HTTPS-handshake к origin.",
            "",
            "3. Rules → Origin Rules → создайте правило:",
            "   If hostname = vless.example.com, then Destination Port = 8080.",
            "   Это заставит CF подключаться к origin на порт 8080 (HTTP).",
            "",
            "4. SSL/TLS → Edge Certificates → убедитесь что WebSocket включён",
            "   (по умолчанию ON для всех планов).",
            "",
            "5. Network → убедитесь что WebSockets ON.",
            "",
            "6. Cloudflare терминирует TLS своим cert (CF↔client).",
            "   Origin (sing-box) слушает plain WS на порту 8080 (CF↔origin = HTTP).",
        ],
    },
    "gcore": {
        "display_name": "Gcore",
        "default_port": 8443,
        "ip_source": "https://api.gcore.com/cdn/public-ip-list",
        "ip_format": "json_addresses",
        "instructions": [
            "1. В Gcore Dashboard → CDN → Resources → Create CDN resource.",
            "",
            "2. Origin: укажите http://<IP-сервера>:8443",
            "   (или http://<your-domain>:8443 если есть A-запись).",
            "   Origin Pull Protocol: HTTP (НЕ HTTPS — origin не имеет TLS).",
            "",
            "3. В Settings → SSL — получите бесплатный SSL-сертификат",
            "   (Let's Encrypt через Gcore, автоматически)",
            "   для вашего CDN CNAME. Этот cert терминирует TLS клиент↔CDN.",
            "",
            "4. В Settings → WebSocket — включите (по умолчанию может быть OFF).",
            "",
            "5. Назначьте Custom Domain (CNAME на Gcore CDN hostname).",
            "   Создайте CNAME-запись в DNS вашего домена.",
            "",
            "6. Gcore терминирует TLS своим cert (CDN↔client = HTTPS).",
            "   Origin получает plain WS на порту 8443 (CDN↔origin = HTTP).",
        ],
    },
    "bunny": {
        "display_name": "Bunny.net",
        "default_port": 8443,
        # v4.23.2: правильный источник — CDN edge-серверы, не Magic Containers.
        # https://bunnycdn.com/api/system/edgeserverlist/plain — plain text,
        # один IPv4 на строку БЕЗ /32 суффикса (fetch_cdn_nets добавляет /32).
        # IPv6: https://bunnycdn.com/api/system/edgeserverlist/IPv6 — JSON array,
        # но listen = "0.0.0.0" (IPv4 only), IPv6 трафик не дойдёт до этого
        # инбаунда → IPv6 явно игнорируем, не тащим лишний код.
        "ip_source": "https://bunnycdn.com/api/system/edgeserverlist/plain",
        "ip_format": "plaintext",
        "instructions": [
            "1. В Bunny.net Dashboard → CDN → Pull Zones → Add Pull Zone.",
            "",
            "2. Origin URL: http://<IP-сервера>:8443",
            "   Origin Port: 8443 (поле OriginPort в API/dashboard).",
            "   Origin Scheme: HTTP (НЕ HTTPS — origin не имеет TLS).",
            "   Origin Type: URL.",
            "",
            "3. Bunny.net автоматически терминирует TLS своим cert",
            "   (бесплатный SSL через Let's Encrypt для CNAME).",
            "   Этот cert терминирует TLS клиент↔CDN.",
            "",
            "4. В Pull Zone → Settings → включите WebSocket (если есть toggle).",
            "",
            "5. Назначьте Custom Hostname (CNAME на bunny.net pull zone hostname).",
            "   Создайте CNAME-запись в DNS вашего домена.",
            "",
            "6. Bunny.net терминирует TLS своим cert (CDN↔client = HTTPS).",
            "   Origin получает plain WS на порту 8443 (CDN↔origin = HTTP).",
        ],
    },
}


# ============================================================================
#  КОНСТАНТЫ — протоколы
# ============================================================================
# Какой протокол к какому sing-box inbound-type относится.
PROTOCOL_SHADOWTLS  = "shadowtls"
PROTOCOL_ANYTLS     = "anytls"
PROTOCOL_TUIC       = "tuic"
PROTOCOL_TROJAN     = "trojan"  # внутренний, под ShadowTLS
PROTOCOL_VLESS_WS_CDN = "vless_ws_cdn"  # v4.23 — VLESS-WS за CDN

ALL_PROTOCOLS = (PROTOCOL_SHADOWTLS, PROTOCOL_ANYTLS, PROTOCOL_TUIC,
                 PROTOCOL_VLESS_WS_CDN)


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
#  Port helpers (v4.23.9)
# ============================================================================
# Pre-flight проверка listen-портов ДО systemctl restart.
# Без этого sing-box падает с EADDRINUSE, systemd уходит в crash-loop
# из 100+ рестартов (см. issue: ShadowTLS + Trojan / sing-box.service
# failed with result 'exit-code'). Ловим ошибку ДО запуска юнита.
def _is_port_free(port: int, listen: str = "127.0.0.1",
                  proto: str = "tcp") -> bool:
    """True если порт свободен для bind().

    proto: 'tcp' (SOCK_STREAM) или 'udp' (SOCK_DGRAM).
    Для listen='0.0.0.0' или '::' проверяет любой интерфейс.
    """
    import socket as _socket
    family = _socket.AF_INET6 if ":" in listen else _socket.AF_INET
    sock_type = _socket.SOCK_STREAM if proto == "tcp" else _socket.SOCK_DGRAM
    try:
        s = _socket.socket(family, sock_type)
        try:
            s.bind((listen, port))
        finally:
            s.close()
        return True
    except OSError:
        return False


def _who_owns_port(port: int, listen: str = "127.0.0.1",
                   proto: str = "tcp") -> str:
    """Возвращает строку 'pid=12345 (procname)' или '' если не удалось узнать.

    Использует ss -ltnp / ss -lunp. Требует root для просмотра pid чужих
    процессов.
    """
    flag = "-ltnp" if proto == "tcp" else "-lunp"
    r = _run(["ss", flag], capture=True, quiet=True)
    if r.returncode != 0:
        return ""
    needle = f":{port} "
    for line in (r.stdout + r.stderr).splitlines():
        if needle in line and "users:" in line:
            m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
            if m:
                return f"pid={m.group(2)} ({m.group(1)})"
    return ""


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
