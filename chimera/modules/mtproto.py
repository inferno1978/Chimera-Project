"""
chimera/modules/mtproto.py
───────────────────────────────────────────────────────────────────────────────
Модуль Telemt MTProxy — Telegram MTProto-прокси на Rust/Tokio.
Интегрируется в Chimera Project v4.11.3

Точка входа из _core.py:
    from chimera.modules.mtproto import mtproto_menu
    mtproto_menu()

Принципы:
  • Статистика вынесена в mtproto_stats.py
  • Ctrl+C на любом шаге → возврат в меню (через _Cancelled)
  • При переустановке предлагается полная очистка или поверх
  • iptables accounting настраивается при установке автоматически
───────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

from chimera.modules.text_width import wlen as _wlen, plain as _plain

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from chimera.modules.proto_common import (
    ProtoCancelled, proto_ask, proto_get_installed_version, proto_ipt_rule_exists,
)
from chimera.modules.telemt_mirrors import (
    get_telemt_mirrors as _get_telemt_mirror_urls,
    MANUAL_UPLOAD_PATHS as _TELEMT_MANUAL_PATHS,
    TELEMT_MIRRORS_COUNT,
    find_manual_upload as _find_telemt_manual_upload,
    print_telemt_manual_download_hint as _print_telemt_manual_hint,
    detect_arch_libc as _detect_arch_libc,
)
# _Cancelled aliases ProtoCancelled so existing `except _Cancelled:` and
# `raise _Cancelled` code works unchanged after the local class definition
# was removed in favour of proto_common.ProtoCancelled.
_Cancelled = ProtoCancelled

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
BIN_PATH        = Path("/usr/local/bin/telemt")
CONFIG_DIR      = Path("/etc/telemt")
CONFIG_FILE     = CONFIG_DIR / "telemt.toml"
WORK_DIR        = Path("/var/lib/telemt")
SERVICE_FILE    = Path("/etc/systemd/system/telemt.service")
LOG_FILE        = Path("/var/log/telemt_install.log")
OPTIMIZER_CONF  = Path("/etc/sysctl.d/99-telemt-performance.conf")
LIMITS_CONF     = Path("/etc/security/limits.d/99-telemt-limits.conf")
CRON_FILE       = Path("/etc/cron.d/telemt-stats")
LIMITS_FILE     = Path("/var/lib/xray-installer/telemt_limits.json")

# ── Бэкапы пользователей Telemt ──────────────────────────────────────────────
# Директория для ежедневных бэкапов telemt.toml (создаётся автоматически).
# Бэкапы создаются:
#   1. При каждом _save_users() — перед записью (snapshot перед изменением)
#   2. Cron-задачей раз в сутки — инкрементальный snapshot
# Ротация: хранятся последние TELEMT_BACKUP_KEEP бэкапов, старые удаляются.
TELEMT_BACKUP_DIR  = Path("/var/lib/xray-installer/telemt-backups")
TELEMT_BACKUP_KEEP = 14  # храним 14 дней бэкапов
TELEMT_BACKUP_CRON = Path("/etc/cron.d/telemt-users-backup")

SERVICE_NAME    = "telemt"
GITHUB_API      = "https://api.github.com/repos/telemt/telemt/releases/latest"

CHAIN_IN        = "TELEMT_STATS_IN"
CHAIN_OUT       = "TELEMT_STATS_OUT"

# ── Xray tproxy-интеграция ────────────────────────────────────────────────────
# Telemt (Rust, без поддержки SOCKS5-upstream) работает в режиме direct.
# Трафик к Telegram-подсетям перехватывается iptables REDIRECT и отправляется
# в dokodemo-door inbound xray, который уже настроен на cascade (VLESS или AWG).
# Схема:  Telemt → iptables REDIRECT → dokodemo :10811 → xray → exit VPS → TG
#
# Это работает одинаково для обоих транспортов:
#   VLESS: xray направляет по chain-exit outbound / balancer
#   AWG:   xray направляет через freedom+fwmark → awg0 → exit VPS
#          (dokodemo обрабатывается uid xray → fwmark проставляется корректно)
XRAY_TPROXY_TAG    = "tproxy-telemt"
XRAY_TPROXY_PORT   = 10811          # порт dokodemo-door; не конфликтует с 10808
XRAY_CONFIG_PATHS  = [
    Path("/etc/xray/config.json"),
    Path("/usr/local/etc/xray/config.json"),
]
XRAY_SERVICE_NAME  = "xray"

# Подсети Telegram — загружаются динамически из tg_nets.py
# Встроенный список (fallback) обновлён: добавлен AS42065 109.239.140.0/24
# Для обновления используйте меню Telemt → "Обновить подсети Telegram"
from chimera.modules.tg_nets import (
    get_tg_nets          as _get_tg_nets,
    update_tg_nets_interactive as _update_tg_nets_interactive,
    tg_nets_status_line  as _tg_nets_status_line,
)

# Telegram через WARP — для серверов в РФ, где Telemt стучится в Telegram
# напрямую (standalone) или Exit-узел каскада делает финальное соединение.
# См. шапку модуля telemt_warp_route.py — где это реально включать.
from chimera.modules.telemt_warp_route import (
    apply_telemt_warp_routing as _apply_telemt_warp_routing,
    refresh_telemt_warp_routing as _refresh_telemt_warp_routing,
    telemt_warp_status_line as _telemt_warp_status_line,
    is_enabled as _telemt_warp_is_enabled,
    do_telemt_warp_menu as _do_telemt_warp_menu,
)

# Гибридный fallback: Middle Proxy → Direct Mode (telemt_fallback.py)
# Импортируем lazy чтобы не замедлять старт при первом импорте mtproto.
def _get_fallback_module():
    """Lazy-import telemt_fallback — изолирует ошибки импорта."""
    try:
        from chimera.modules import telemt_fallback as _fb_mod
        return _fb_mod
    except ImportError:
        return None

# Веб-панель управления: telemt_panel.py
def _get_panel_module():
    """Lazy-import telemt_panel — изолирует ошибки импорта."""
    try:
        from chimera.modules import telemt_panel as _panel_mod
        return _panel_mod
    except ImportError:
        return None

# MSS-фрагментация против TSPU JA4: telemt_mss_selector.py
def _get_mss_module():
    """Lazy-import telemt_mss_selector — изолирует ошибки импорта."""
    try:
        from chimera.modules import telemt_mss_selector as _mss_mod
        return _mss_mod
    except ImportError:
        return None

# Per-IP SYN rate limiter: telemt_syn_limiter.py
def _get_syn_limiter_module():
    """Lazy-import telemt_syn_limiter — изолирует ошибки импорта."""
    try:
        from chimera.modules import telemt_syn_limiter as _sl_mod
        return _sl_mod
    except ImportError:
        return None

# iOS-фикс: MSS-clamp + redirect на отдельный порт (telemt_ios_fix.py)
def _get_ios_fix_module():
    """Lazy-import telemt_ios_fix — изолирует ошибки импорта."""
    try:
        from chimera.modules import telemt_ios_fix as _if_mod
        return _if_mod
    except ImportError:
        return None

def _TG_NETS_current() -> list:
    """Возвращает актуальный список подсетей TG (файл → встроенный)."""
    return _get_tg_nets()

# Для обратной совместимости с кодом, который обращается к _TG_NETS напрямую.
# Вычисляется один раз при импорте; для применения свежих данных используйте
# _TG_NETS_current() внутри функций, работающих с iptables.
_TG_NETS = _TG_NETS_current()

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ
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
        # Обрезаем по визуальной ширине чтобы не сломать рамку
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
def _box_warn(msg: str) -> None: _box_row(f"  {YELLOW}[!]{NC}  {msg}")
def _box_info(msg: str) -> None: _box_row(f"  {CYAN}→{NC}  {msg}")
def _box_err(msg: str)  -> None: _box_row(f"  {RED}✗{NC}  {msg}")

def _box_kv(key: str, val: str, kw: int = 22) -> None:
    key_colored = f"{CYAN}{key}{NC}"
    key_pad = kw - _wlen(key_colored)
    _box_row(f"  {key_colored}{' ' * max(0, key_pad)}  {val}")

# ══════════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ
# ══════════════════════════════════════════════════════════════════════════════
def _run(cmd: list, capture: bool = False, check: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
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
def _warn(msg: str) -> None: print(f"  {YELLOW}[!]{NC}  {msg}"); _log(f"[WARN] {msg}")
def _info(msg: str) -> None: print(f"  {CYAN}→{NC}  {msg}"); _log(f"[INFO] {msg}")
def _err(msg: str)  -> None: print(f"  {RED}✗{NC}  {msg}"); _log(f"[ERR] {msg}")

# _Cancelled was a local Exception subclass; it is now an alias for
# proto_common.ProtoCancelled (see the `_Cancelled = ProtoCancelled` line
# near the top of this file). proto_ask raises ProtoCancelled, and existing
# `except _Cancelled:` / `raise _Cancelled` code keeps working unchanged.

def _pause() -> None:
    try:
        print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True)
        input()
    except (KeyboardInterrupt, EOFError, UnicodeDecodeError):
        print()

# _ask — вынесен в proto_common (proto_ask). proto_ask raises ProtoCancelled,
# which is what local `_Cancelled` aliases to, so `except _Cancelled:` handlers
# and `raise _Cancelled` continue to work unchanged.

def _generate_secret() -> str:
    try:
        return os.urandom(16).hex()
    except Exception:
        import random
        return ''.join(f'{random.randint(0,255):02x}' for _ in range(16))

def _validate_username(name: str) -> bool:
    return bool(re.match(r'^[a-zA-Z][a-zA-Z0-9_\-]{2,15}$', name))

def _validate_domain(domain: str) -> bool:
    return bool(
        domain and '.' in domain and
        re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9.\-]{0,253}[a-zA-Z0-9])?$', domain)
    )


# ══════════════════════════════════════════════════════════════════════════════
#  OWN-SITE CONFIG (nginx fallback для Telemt mask)
# ────────────────────────────────────────────────────────────────────────────
# Возвращается из _select_domain() когда пользователь выбирает "свой домен +
# свой сайт (nginx fallback)". None означает donor-режим (текущее поведение).
# См. CHANGELOG — "Telemt nginx-fallback: собственный домен и сайт вместо
# чужого donor-домена".
# ────────────────────────────────────────────────────────────────────────────
@dataclass
class OwnSiteConfig:
    """Параметры локального nginx-сайта для маскировки Telemt.

    domain     — публичный домен (тот же, что и tls_domain в telemt.toml).
                 К нему привязан A-record → IP сервера; certbot выпускает
                 Let's Encrypt сертификат.
    mask_host  — хост, на который Telemt сплайсит failed handshakes.
                 Всегда "127.0.0.1" в этой итерации (TCP на localhost).
    mask_port  — TCP-порт nginx на 127.0.0.1 (НЕ должен конфликтовать с
                 портом самого Telemt). Подбирается helper'ом _pick_local_nginx_port.
    """
    domain: str
    mask_host: str = "127.0.0.1"
    mask_port: int = 0


# Диапазон кандидатов для mask_port. Нижняя граница 8444 — чуть выше
# дефолтного порта Telemt (8443), верхняя 9999 — ниже регистрационных
# портов xray/dokodemo (10808, 10811). Избегаем 9000 (часто занят php-fpm).
_MASK_PORT_CANDIDATES = list(range(8444, 9000)) + list(range(9001, 9999))


def _pick_local_nginx_port(telemt_port: int) -> int:
    """Подбирает свободный TCP-порт на 127.0.0.1 для nginx (mask_host backend).

    Критерии:
      • НЕ совпадает с портом самого Telemt (telemt_port) — иначе nginx и
        TelemtListener дерутся за один порт.
      • НЕ слушается другим процессом на 127.0.0.1 (проверка через ss).
      • Входит в предопределённый диапазон 8444-9998 (см. _MASK_PORT_CANDIDATES).

    Возвращает 0 если свободный порт не найден (в этом случае caller должен
    показать ошибку — без mask_port own-site режим не имеет смысла).
    """
    try:
        # Собираем уже занятые порты на loopback (v4+v6).
        r = _run(["ss", "-tlnH"], capture=True, check=False, quiet=True)
        listening: set[int] = set()
        for line in (r.stdout or "").splitlines():
            # Формат: "LISTEN 0  4096  0.0.0.0:8443  0.0.0.0:*"
            m = re.search(r'[:\]](\d+)\s', line)
            if m:
                listening.add(int(m.group(1)))
    except Exception:
        listening = set()
    for cand in _MASK_PORT_CANDIDATES:
        if cand == telemt_port:
            continue
        if cand in listening:
            continue
        return cand
    return 0


def _check_mask_backend_ready(mask_host: str, mask_port: int,
                              timeout: float = 2.0,
                              sni_hostname: str = "") -> bool:
    """Проверяет, что nginx уже слушает mask_host:mask_port И отдаёт валидный TLS-сертификат.

    v4.20.6: реальный TLS-handshake + проверка issuer != subject.
    v4.20.9: ИСПРАВЛЕНО — SNI должен быть ДОМЕН (server_name в nginx config),
             а не mask_host (который 127.0.0.1). Раньше wrap_socket(server_hostname="127.0.0.1")
             → nginx не находил matching server_name → отдаёт default_server → TLS-handshake
             падал, хотя nginx реально слушал порт. Теперь:
               1. Если sni_hostname передан (домен) — используем его для SNI
               2. Иначе fallback на mask_host (но это даст default_server в nginx)
               3. Если TLS-handshake падает — fallback на голый TCP-connect
                  (nginx слушает = OK, cert проверим отдельно через _is_cert_self_signed)

    КРИТИЧНО для tls_emulation=true (telemt/telemt issues #330, #713).

    Возвращает True если:
      • TCP-connect успешен И
      • (TLS-handshake успешен И issuer != subject) ИЛИ TLS-handshake упал но TCP зелёный
        (fallback — cert уже проверен _is_cert_self_signed на шаге 5)
    """
    import socket as _sock
    import ssl as _ssl
    # 1) TCP-connect
    try:
        raw = _sock.create_connection((mask_host, mask_port), timeout=timeout)
    except (OSError, _sock.timeout):
        return False
    # Если SNI не передан — нет смысла делать TLS-handshake с SNI=127.0.0.1
    # (nginx отдаст default_server, cert может не совпасть). Возвращаем True
    # на основе TCP-connect — cert уже проверен через _is_cert_self_signed.
    if not sni_hostname:
        raw.close()
        return True
    # 2) + 3) TLS-handshake + проверка cert-chain
    try:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        # SNI = sni_hostname (домен, НЕ 127.0.0.1) — для vhost-маршрутизации в nginx
        tls = ctx.wrap_socket(raw, server_hostname=sni_hostname)
        try:
            der_cert = tls.getpeercert(binary_form=True)
        finally:
            tls.close()
    except (OSError, _ssl.SSLError, ValueError):
        # TLS-handshake упал. Это МОЖЕТ быть ок если nginx отдаёт default_server
        # без cert (ssl_reject_handshake on). Fallback: TCP-connect прошёл = OK.
        # Cert уже проверен на шаге 5 (_is_cert_self_signed), здесь только
        # проверяем что listener готов.
        return True
    if not der_cert:
        # Сертификат не получен — но TCP-connect прошёл. Считаем готовым.
        return True
    # Парсим cert через openssl — проверяем issuer != subject.
    try:
        import tempfile as _tf
        with _tf.NamedTemporaryFile(suffix=".der", delete=False) as _tf_f:
            _tf_f.write(der_cert)
            _der_path = _tf_f.name
        try:
            r = _run(["openssl", "x509", "-issuer", "-subject", "-noout",
                      "-inform", "DER", "-in", _der_path],
                     capture=True, check=False)
        finally:
            try: os.unlink(_der_path)
            except OSError: pass
        out = (r.stdout or "") + (r.stderr or "")
        issuer = ""
        subject = ""
        for line in out.splitlines():
            line = line.strip()
            if line.lower().startswith("issuer="):
                issuer = line.split("=", 1)[1].strip()
            elif line.lower().startswith("subject="):
                subject = line.split("=", 1)[1].strip()
        if not issuer or not subject:
            # Не распарсилось — но TCP+TLS прошли. Считаем готовым.
            return True
        if issuer == subject:
            # Self-signed — own-site бессмысленен.
            return False
        return True
    except Exception:
        # openssl упал — но TCP+TLS прошли. Считаем готовым (fail-open для
        # TLS-handshake, fail-close уже отработал на шаге 5 _is_cert_self_signed).
        return True


def _is_cert_self_signed(domain: str) -> bool:
    """Проверяет, является ли сертификат для domain самоподписанным.

    Читает /etc/letsencrypt/live/{domain}/cert.pem (или fullchain.pem как
    fallback) через `openssl x509 -issuer -subject -noout` и сравнивает
    issuer с subject. Если они совпадают — сертификат self-signed.

    Используется в _setup_own_site() ПОСЛЕ obtain_ssl_cert() для fail-loud
    проверки: obtain_ssl_cert() имеет silent fallback на generate_self_signed_cert
    при провале certbot — для VLESS это осознанное поведение, но для own-site
    self-signed сертификат бессмысленен (вся фича — реальный LE-сертификат,
    иначе Telemt с tls_emulation=true будет отдавать self-signed, что для
    DPI/censor заметная аномалия ХУЖЕ исходного fake_cert_len=2048).

    Возвращает:
      True  — сертификат self-signed (провал own-site проверки)
      False — сертификат валидный LE (issuer != subject) ИЛИ файл не найден
              (в последнем случае _setup_own_site всё равно откатит через
              _check_mask_backend_ready или _is_cert_self_signed→True в
              следующем вызове, но мы не блокируем здесь — пусть решает caller)
    """
    cert_path = Path(f"/etc/letsencrypt/live/{domain}/cert.pem")
    if not cert_path.exists():
        cert_path = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
    if not cert_path.exists():
        # Сертификата нет вообще — это явно провал, возвращаем True
        # (treat as self-signed: caller откатит к donor-режиму).
        return True
    try:
        r = _run(["openssl", "x509", "-issuer", "-subject", "-noout", "-in", str(cert_path)],
                 capture=True, check=False)
        out = (r.stdout or "") + (r.stderr or "")
        # Парсим строки вида:
        #   issuer=C = US, O = Let's Encrypt, CN = R3
        #   subject=C = US, ST = ...
        issuer = ""
        subject = ""
        for line in out.splitlines():
            line = line.strip()
            if line.lower().startswith("issuer="):
                issuer = line.split("=", 1)[1].strip()
            elif line.lower().startswith("subject="):
                subject = line.split("=", 1)[1].strip()
        if not issuer or not subject:
            # Не удалось распарсить — считаем self-signed (fail-safe).
            return True
        return issuer == subject
    except Exception:
        # openssl упал — fail-safe, считаем self-signed.
        return True


def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} PiB"

# ══════════════════════════════════════════════════════════════════════════════
#  БАННЕР
# ══════════════════════════════════════════════════════════════════════════════
def _banner() -> None:
    os.system("clear")
    print(f"{CYAN}{BOLD}")
    print("  ████████╗███████╗██╗     ███████╗███╗   ███╗████████╗")
    print("     ██║   ██╔════╝██║     ██╔════╝████╗ ████║╚══██╔══╝")
    print("     ██║   █████╗  ██║     █████╗  ██╔████╔██║   ██║   ")
    print("     ██║   ██╔══╝  ██║     ██╔══╝  ██║╚██╔╝██║   ██║   ")
    print("     ██║   ███████╗███████╗███████╗██║ ╚═╝ ██║   ██║   ")
    print("     ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝     ╚═╝   ╚═╝   ")
    print(f"{NC}")
    print(f"  {DIM}Telegram MTProto Proxy  •  Telemt (Rust/Tokio)  •  VLESS Ultimate{NC}")
    print()

# ══════════════════════════════════════════════════════════════════════════════
#  IP И СЕТЬ
# ══════════════════════════════════════════════════════════════════════════════
def _get_local_primary_ipv4() -> str:
    """Return the primary non-loopback IPv4 address assigned to a local interface."""
    try:
        import socket
        # Connect to an external address (no data sent) to discover the outbound interface IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        pass
    # Fallback: parse `ip addr` for the first global inet address
    try:
        out = _run(["ip", "-4", "addr", "show", "scope", "global"], capture=True).stdout
        m = re.search(r'inet\s+([\d.]+)/', out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""

def _get_public_ip() -> tuple:
    """
    Возвращает (ipv4, ipv6) для использования в tg:// ссылках.

    Логика выбора IPv4:
      1. Читаем IP локального интерфейса (тот, на котором слушает telemt).
         Это единственно правильный адрес для tg:// ссылки — пользователь
         должен подключаться к ЭТОЙ машине, а не к exit-ноде.
      2. ВСЕГДА запрашиваем внешний IP через echo-сервис и сверяем с локальным.
         Именно сравнение (совпадает/не совпадает), а не is_private-эвристика,
         должно определять NAT — некоторые хостеры (cloud.ru, Azure и др.)
         используют NAT с адресами, которые выглядят как публичные, но
         публичными не являются (SDN/гипервизор 1:1 маппинг).
      3. IPv6 всегда через api6.ipify.org.
    """
    local_ip = _get_local_primary_ipv4()
    ipv4 = ""

    # Всегда запрашиваем внешний IP — is_private-эвристика ненадёжна
    # (некоторые хостеры используют NAT с адресами, которые выглядят
    # как публичные, но публичными не являются — см. issue с cloud.ru).
    external_ip = ""
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                external_ip = r.read().decode().strip()
            if external_ip:
                break
        except Exception:
            pass

    if external_ip and local_ip and external_ip == local_ip:
        # Внешний echo-сервис видит ровно тот же адрес, что и
        # локальный интерфейс — сервер реально имеет публичный IP,
        # NAT нет.
        ipv4 = local_ip
    elif external_ip:
        # Внешний IP отличается от локального — либо NAT (Режим A,
        # локальный интерфейс приватный/NAT-адрес), либо Режим B
        # (трафик уходит через exit-ноду). Используем существующую
        # проверку _is_direct_ip, чтобы различить эти два случая:
        ipv4 = external_ip if _is_direct_ip(external_ip) else (local_ip or external_ip)
    else:
        # Внешний IP получить не удалось (нет интернета/сервисы
        # недоступны) — используем локальный как единственный вариант.
        ipv4 = local_ip

    ipv6 = ""
    try:
        with urllib.request.urlopen("https://api6.ipify.org", timeout=5) as r:
            ipv6 = r.read().decode().strip()
    except Exception:
        pass
    return ipv4, ipv6


def _is_public_ip(ip: str) -> bool:
    """True если IP публичный (не RFC-1918, не loopback, не link-local)."""
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local)
    except ValueError:
        return False

def _is_direct_ip(ipv4: str) -> bool:
    if not ipv4: return False
    return ipv4 in _run(["ip", "addr"], capture=True).stdout

# ══════════════════════════════════════════════════════════════════════════════
#  ВЕРСИЯ И РЕЛИЗ
# ══════════════════════════════════════════════════════════════════════════════
def _get_installed_version() -> Optional[str]:
    # Delegated to proto_common.proto_get_installed_version.
    # telemt binary supports `--version`, output has no leading 'v'.
    return proto_get_installed_version(BIN_PATH, "--version")

def _get_latest_release() -> tuple:
    """Возвращает (tag, urls) — где urls это СПИСОК зеркал.

    МИГРАЦИЯ: api.github.com зависимость УБРАНА.
    Раньше: шёл в api.github.com за tag_name, при блокировке возвращал ('', []).
    Теперь: tag всегда "latest" (GitHub сам делает редирект при скачивании),
    urls — список зеркал из telemt_packages.TELEMT_SPEC. api.github.com
    больше не нужен — это убирает одну точку отказа.

    Возвращает (tag_str, urls_list) для обратной совместимости с вызывающим
    кодом. tag_str = "latest" (строка) — вызывающий код использует его
    только для отображения, не для построения URL.
    """
    from chimera.modules.telemt_packages import TELEMT_SPEC
    urls = TELEMT_SPEC.mirror_urls_builder(
        filename=TELEMT_SPEC.filename_builder()
    )
    return "latest", urls

# ══════════════════════════════════════════════════════════════════════════════
#  КОНФИГ
# ══════════════════════════════════════════════════════════════════════════════
def _make_tls_secret(base_secret: str, domain: str) -> str:
    return f"ee{base_secret}{domain.encode().hex()}"

def _get_port() -> int:
    if not CONFIG_FILE.exists(): return 8443
    m = re.search(r'^port\s*=\s*(\d+)', CONFIG_FILE.read_text(), re.MULTILINE)
    return int(m.group(1)) if m else 8443

def _get_domain() -> str:
    if not CONFIG_FILE.exists(): return ""
    m = re.search(r'^tls_domain\s*=\s*"(.+?)"', CONFIG_FILE.read_text(), re.MULTILINE)
    return m.group(1) if m else ""

def _load_users() -> dict:
    users: dict = {}
    if not CONFIG_FILE.exists(): return users
    in_sec = False
    for line in CONFIG_FILE.read_text().splitlines():
        if line.strip() == "[access.users]":
            in_sec = True; continue
        if in_sec and line.strip().startswith("["): break
        if in_sec:
            m = re.match(r'^([a-zA-Z][a-zA-Z0-9_\-]+)\s*=\s*"([a-f0-9]{32})"', line)
            if m: users[m.group(1)] = m.group(2)
    return users


# ══════════════════════════════════════════════════════════════════════════════
#  БЭКАП ПОЛЬЗОВАТЕЛЕЙ TELETM
# ══════════════════════════════════════════════════════════════════════════════
#  Проблема: юзеры Telemt хранятся в /etc/telemt/telemt.toml (секция
#  [access.users]). При (пере)установке, при _write_config(), при сбое
#  _save_users() — весь файл перезаписывается, и юзеры могут потеряться.
#  Один пользователь жаловался: "было 10 юзеров, зашёл — остался 1 admin".
#
#  Решение: перед каждой записью telemt.toml делаем snapshot в
#  /var/lib/xray-installer/telemt-backups/ с timestamp в имени.
#  Дополнительно — cron раз в сутки делает snapshot независимо от
#  изменений. Ротация: храним последние 14 snapshot'ов.

def _backup_telemt_users(reason: str = "save") -> bool:
    """
    Создаёт snapshot telemt.toml в TELEMT_BACKUP_DIR с timestamp.
    Вызывается перед каждым _save_users() и из cron-задачи раз в сутки.

    Параметр reason — короткая строка для имени файла
    ('save', 'write_config', 'cron', 'manual').
    Возвращает True при успехе, False при ошибке (но не бросает исключение).

    Имя файла: telemt-YYYYMMDD-HHMMSS-{reason}.toml
    Ротация: после создания удаляем старые, оставляя TELEMT_BACKUP_KEEP.
    """
    try:
        if not CONFIG_FILE.exists():
            return False
        TELEMT_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = TELEMT_BACKUP_DIR / f"telemt-{ts}-{reason}.toml"
        # Копируем содержимое (не symlink, не move — именно копируем)
        backup_path.write_text(CONFIG_FILE.read_text())
        backup_path.chmod(0o640)
        # Ротация: оставляем последние TELEMT_BACKUP_KEEP файлов
        all_backups = sorted(TELEMT_BACKUP_DIR.glob("telemt-*.toml"), reverse=True)
        for old in all_backups[TELEMT_BACKUP_KEEP:]:
            try:
                old.unlink()
            except Exception:
                pass
        return True
    except Exception:
        return False


def _install_telemt_users_backup_cron() -> bool:
    """
    Устанавливает cron-задачу для ежедневного бэкапа telemt.toml.
    Запуск: 0 3 * * * (каждый день в 03:00 ночи).
    Возвращает True при успехе.
    """
    try:
        import textwrap as _tw
        TELEMT_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        # Cron вызывает python3 с inline-скриптом, который импортирует
        # _backup_telemt_users из mtproto. Это надёжнее чем bash-cp,
        # потому что учитывает ротацию и логирование.
        cron_script = _tw.dedent(f"""\
            #!/bin/bash
            # Telemt users backup — daily snapshot of telemt.toml
            # Generated by Chimera Project. Do not edit manually.
            python3 -c "
            import sys
            sys.path.insert(0, '/opt/chimera')
            try:
                from chimera.modules.mtproto import _backup_telemt_users
                ok = _backup_telemt_users('cron')
                if not ok:
                    print('Telemt backup: no config file or error', file=sys.stderr)
            except Exception as e:
                print(f'Telemt backup error: {{e}}', file=sys.stderr)
            " >> /var/log/telemt-backup.log 2>&1
        """)
        script_path = Path("/usr/local/bin/telemt-users-backup.sh")
        script_path.write_text(cron_script)
        script_path.chmod(0o755)
        TELEMT_BACKUP_CRON.write_text(
            f"0 3 * * * root {script_path} >> /var/log/telemt-backup.log 2>&1\n"
        )
        TELEMT_BACKUP_CRON.chmod(0o644)
        return True
    except Exception:
        return False


def _remove_telemt_users_backup_cron() -> None:
    """Удаляет cron-задачу ежедневного бэкапа (при uninstall)."""
    try:
        TELEMT_BACKUP_CRON.unlink(missing_ok=True)
        Path("/usr/local/bin/telemt-users-backup.sh").unlink(missing_ok=True)
    except Exception:
        pass


def _list_telemt_user_backups() -> list:
    """Возвращает список бэкапов (Path, mtime, размер, кол-во юзеров) для меню."""
    result = []
    if not TELEMT_BACKUP_DIR.exists():
        return result
    for p in sorted(TELEMT_BACKUP_DIR.glob("telemt-*.toml"), reverse=True):
        try:
            stat = p.stat()
            # Считаем юзеров в бэкапе
            users_count = 0
            in_sec = False
            for line in p.read_text().splitlines():
                if line.strip() == "[access.users]":
                    in_sec = True; continue
                if in_sec and line.strip().startswith("["): break
                if in_sec and re.match(r'^[a-zA-Z][a-zA-Z0-9_\-]+\s*=\s*"[a-f0-9]{32}"', line):
                    users_count += 1
            result.append({
                "path": p,
                "name": p.name,
                "size": stat.st_size,
                "mtime": datetime.fromtimestamp(stat.st_mtime),
                "users": users_count,
            })
        except Exception:
            continue
    return result


def _restore_telemt_users_from_backup(backup_path) -> tuple:
    """
    Восстанавливает telemt.toml из бэкапа.
    Перед восстановлением делает snapshot текущего (возможно сломанного) файла.
    Возвращает (success: bool, message: str).
    """
    try:
        backup_path = Path(backup_path)
        if not backup_path.exists():
            return False, f"Бэкап не найден: {backup_path}"
        # Сначала бэкапим текущий файл (на случай если восстановление
        # сделает хуже — чтобы можно было откатиться)
        if CONFIG_FILE.exists():
            _backup_telemt_users("pre-restore")
        # Восстанавливаем
        CONFIG_FILE.write_text(backup_path.read_text())
        CONFIG_FILE.chmod(0o640)
        # Рестарт telemt
        _run(["systemctl", "restart", SERVICE_NAME], check=False)
        # Считаем сколько юзеров восстановлено
        users = _load_users()
        return True, f"Восстановлено пользователей: {len(users)}"
    except Exception as e:
        return False, f"Ошибка восстановления: {e}"


def _save_users(users: dict) -> None:
    if not CONFIG_FILE.exists(): return
    #  FIX: перед каждой записью делаем snapshot telemt.toml —
    # на случай если запись прервётся или перезапишет юзеров неправильно.
    # Это страховка от сценария "было 10 юзеров, после _save_users() остался 1".
    _backup_telemt_users("save")
    lines = CONFIG_FILE.read_text().splitlines()
    out, in_sec, written = [], False, False
    for line in lines:
        if line.strip() == "[access.users]":
            in_sec = True; out.append(line)
            for n, s in users.items(): out.append(f'{n} = "{s}"')
            written = True; continue
        if in_sec and line.strip().startswith("["): in_sec = False
        if in_sec: continue
        out.append(line)
    if not written:
        out += ["[access.users]"] + [f'{n} = "{s}"' for n, s in users.items()]
    CONFIG_FILE.write_text("\n".join(out) + "\n")
    CONFIG_FILE.chmod(0o640)
    arr = ", ".join(f'"{u}"' for u in users)
    content = re.sub(r'^show\s*=\s*\[.*?\]', f'show = [{arr}]',
                     CONFIG_FILE.read_text(), flags=re.MULTILINE)
    CONFIG_FILE.write_text(content)


# ══════════════════════════════════════════════════════════════════════════════
#  PUBLIC SYNC CONTRACT — is_active / ensure_user / remove_user / rename_user
# ══════════════════════════════════════════════════════════════════════════════
# Эти 4 функции — единый контракт автосинхронизации VLESS → Telemt,
# вызываются из rest_api.py через обобщённый реестр _SYNCABLE_PROTOCOLS.
# Все 4 НИКОГДА не бросают исключение наружу — ловят всё внутри и
# возвращают bool (кроме is_active, который тоже возвращает bool).
# Это позволяет реестру диспетчеризовать вызовы безопасно, не падая
# при сбое одного из протоколов.
#
# Внутренняя логика (валидация имён, "нельзя удалить последнего",
# генерация секрета, рестарт сервиса) — полностью инкапсулирована
# здесь, реестр про это ничего не знает.

def is_active() -> bool:
    """Возвращает True если служба telemt активна (systemctl is-active).

    Используется обобщённым реестром синхронизации чтобы решить,
    вызывать ли ensure_user/remove_user/rename_user для этого протокола.
    Если False — синхронизация пропускается (results[proto] = None).
    """
    try:
        r = _run(["systemctl", "is-active", SERVICE_NAME],
                 capture=True, check=False)
        return r.returncode == 0 and r.stdout.strip() == "active"
    except Exception:
        return False


def ensure_user(name: str) -> bool:
    """Создаёт Telemt-пользователя с именем `name`, если его ещё нет.

    Возвращает True если пользователь создан или уже существует.
    Возвращает False если:
      • Имя невалидно по Telemt-спеке (^[a-zA-Z][a-zA-Z0-9_\\-]{2,15}$)
      • Ошибка при сохранении/рестарте сервиса
    Никогда не бросает исключение наружу.
    """
    if not name:
        return False
    try:
        if not _validate_username(name):
            return False
        users = _load_users() or {}
        if name in users:
            return True  # уже есть — ничего делать не надо
        users[name] = _generate_secret()
        _save_users(users)
        # Рестарт telemt чтобы подхватил нового юзера (аналогично TUI-меню).
        _run(["systemctl", "restart", SERVICE_NAME], check=False)
        return True
    except Exception:
        return False


def remove_user(name: str) -> bool:
    """Удаляет Telemt-пользователя с именем `name`, если он существует.

    Возвращает True если удалён или его не было. False — при ошибке или
    если это последний пользователь (Telemt требует минимум одного —
    бинарник падает при пустом [access.users]).

    Это внутренняя политика протокола — реестр синхронизации про это
    ничего не знает, он просто получает bool и идёт дальше.
    """
    if not name:
        return False
    try:
        users = _load_users() or {}
        if name not in users:
            return True  # нет такого — уже "удалён"
        # Не удаляем последнего пользователя (Telemt требует минимум одного).
        # Это специфичная для Telemt политика, не часть общего контракта.
        if len(users) <= 1:
            return False
        del users[name]
        _save_users(users)
        _run(["systemctl", "restart", SERVICE_NAME], check=False)
        return True
    except Exception:
        return False


def rename_user(old_name: str, new_name: str) -> bool:
    """Переименовывает Telemt-пользователя old_name → new_name.

    Сохраняет секрет (MTProto-ссылка остаётся рабочей, меняется только имя).
    Возвращает False без изменений если:
      • new_name уже занят (не перезаписываем чужой секрет)
      • old_name не найден (но в этом случае fallback — создаём new_name
        с новым секретом, чтобы не ломать сценарий "переименовали в VLESS,
        но в Telemt такого не было")
      • new_name невалиден по спеке
    """
    if not old_name or not new_name:
        return False
    if old_name == new_name:
        return True
    try:
        if not _validate_username(new_name):
            return False
        users = _load_users() or {}
        if new_name in users:
            # Имя занято — не трогаем чужой секрет.
            return False
        if old_name in users:
            users[new_name] = users.pop(old_name)
        else:
            # Старого нет — создаём нового (fallback).
            users[new_name] = _generate_secret()
        _save_users(users)
        _run(["systemctl", "restart", SERVICE_NAME], check=False)
        return True
    except Exception:
        return False


def _write_config(port, ipv4, ipv6, tls_domain, users, use_middle_proxy,
                  socks5_port: int = 0, fallback_cfg=None,
                  client_mss: str = "",
                  client_mss_bulk: str = "",
                  mask_host: str = "",
                  mask_port: int = 0,
                  tls_emulation: bool = False) -> None:
    """
    socks5_port > 0  →  upstream через локальный SOCKS5 (xray), иначе direct.
    fallback_cfg     →  FallbackConfig (из telemt_fallback); None = не писать секцию.
    client_mss       →  пресет MSS для TSPU anti-JA4 ("tspu", "2in8", числовой или "").
    client_mss_bulk  →  опциональный MSS для bulk-фазы (после TLS-handshake).
                        Если задан — низкий client_mss применяется только на
                        handshake, а для данных MSS поднимается до client_mss_bulk.
                        Снижает packets-per-second в N раз (N = segment multiplier
                        handshake-MSS). Полезно на хостингах с PPS-based abuse.
                        Если пусто — прежнее поведение (handshake-MSS на всё
                        соединение). Требует telemt ≥ 3.5.x (на старых игнорируется).
    mask_host        →  censorship.mask_host: Telemt сплайсит failed handshakes на
                        локальный nginx с реальным Let's Encrypt сертификатом
                        (свой домен + свой сайт). Пустая строка = donor-режим
                        (поведение идентично предыдущему, byte-for-byte).
    mask_port        →  censorship.mask_port: TCP-порт nginx на 127.0.0.1.
                        Если 0 — не пишем (donor-режим использует захардкоженный
                        mask_port = 443 по умолчанию Telemt-бинарника).
    tls_emulation    →  censorship.tls_emulation = true: живой TLS-fetch реального
                        cert-chain с mask_host при старте Telemt (вместо synthetic
                        fake_cert_len=2048). Требует, чтобы nginx уже слушал
                        mask_host:mask_port ДО старта Telemt — иначе "early eof"
                        (telemt/telemt issues #330, #713).

    ВАЖНО: mask_host и mask_unix_sock взаимоисключающи по спецификации Telemt.
    В этой итерации поддерживается только TCP mask_host (см. CHANGELOG —
    "Почему не unix-сокет в первой итерации"). Unix-сокет не реализуем.
    """
    #  FIX: Перед перезаписью telemt.toml делаем snapshot —
    # на случай если _write_config() вызывается при (пере)установке
    # и перезапишет существующих юзеров. Если в текущем конфиге есть
    # юзеры, которых нет в переданном списке — MERGE, не теряем.
    _backup_telemt_users("write_config")
    if CONFIG_FILE.exists():
        existing_users = _load_users()
        if existing_users:
            # MERGE: если в переданном users есть юзер, которого нет в existing —
            # это новый юзер (добавлен при установке). Если в existing есть юзер,
            # которого нет в переданном — это существующий юзер, НЕ теряем.
            for name, secret in existing_users.items():
                if name not in users:
                    users[name] = secret
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    arr = ", ".join(f'"{u}"' for u in users)
    # network.ipv4 / network.ipv6 у telemt по умолчанию ЛОЖНЫ, если секция
    # [network] не указана явно — независимо от того, что реально настроено
    # на уровне ОС/листенеров. Без этого блока listener "::" (или "0.0.0.0")
    # будет молча пропущен на старте ("Skipping ... listener: ... disabled
    # by [network]"), и если это единственный листенер — telemt падает с
    # "No listeners. Exiting." и уходит в restart-loop systemd.
    # Поэтому всегда синхронизируем network.ipv4/ipv6 с фактически
    # включёнными листенерами.
    net_prefer = 6 if (ipv6 and not ipv4) else 4
    lines = [
        "# Telemt v3.x — generated by Chimera Project",
        "", "[general]", "prefer_ipv6 = false", "fast_mode = true",
        f"use_middle_proxy = {str(use_middle_proxy).lower()}",
        "", "[network]",
        f"ipv4 = {str(ipv4).lower()}",
        f"ipv6 = {str(ipv6).lower()}",
        f"prefer = {net_prefer}",
        "", "[general.modes]", "classic = false", "secure = false", "tls = true",
        "", "[general.links]", f"show = [{arr}]",
        "", "[server]", f"port = {port}", "",
    ]
    if ipv4: lines += ['[[server.listeners]]', 'ip = "0.0.0.0"', ""]
    if ipv6: lines += ['[[server.listeners]]', 'ip = "::"', ""]
    # ── Censorship-секция: два режима ────────────────────────────────────────
    # 1) donor-режим (mask_host=""): поведение byte-for-byte идентично
    #    предыдущему — Telemt отдаёт synthetic fake-cert (~2048 байт) и
    #    сплайсит на mask_host = tls_domain (т.е. на ЧУЖОЙ домен-донор).
    #    Вывод фиксирован: mask=true, mask_port=443, fake_cert_len=2048.
    # 2) own-site-режим (mask_host="127.0.0.1"): Telemt сплайсит failed
    #    handshakes на локальный nginx с реальным Let's Encrypt сертификатом
    #    того же домена (tls_domain). tls_emulation=true — живой TLS-fetch
    #    cert-chain с mask_host вместо synthetic fake-cert. Это убирает
    #    детектируемую аномалию fake_cert_len=2048.
    #
    # ВАЖНО: mask_host и mask_unix_sock взаимоисключающи (см. шапку функции).
    # mask_port пишем только в donor-режиме (443, hardcoded) либо в own-site
    # если явно передан (>0). В own-site при mask_port=0 — не пишем; Telemt
    # в этом случае использует свой internal default для mask_port.
    censorship_lines = [
        "[timeouts]", "client_handshake = 300", "client_keepalive = 60", "client_ack = 300",
        "", "[censorship]", f'tls_domain = "{tls_domain}"',
        "mask = true",
    ]
    if mask_host:
        # own-site-режим: добавляем mask_host + tls_emulation (+ mask_port если явно).
        # fake_cert_len=2048 оставляем — он игнорируется при tls_emulation=true,
        # но не мешает (Telemt-spec: ключи из donor-режима сохраняются для
        # обратной совместимости, активен только тот, что соответствует режиму).
        censorship_lines.append(f'mask_host = "{mask_host}"')
        if mask_port:
            censorship_lines.append(f'mask_port = {mask_port}')
        censorship_lines.append("fake_cert_len = 2048")
        censorship_lines.append(f'tls_emulation = {str(tls_emulation).lower()}')
    else:
        # donor-режим: byte-identical предыдущему выводу.
        censorship_lines.append("mask_port = 443")
        censorship_lines.append("fake_cert_len = 2048")
    if client_mss:
        # client_mss и client_mss_bulk принадлежат секции [server] (ServerConfig struct).
        # Тип всегда String — числа тоже в кавычках ("256", "tspu", "2in8" и т.д.)
        # Вставляем сразу после `port = N` — оба параметра рядом, для читаемости.
        _port_idx = lines.index(f'port = {port}')
        lines.insert(_port_idx + 1, f'client_mss = "{client_mss}"')
        if client_mss_bulk:
            # Bulk-MSS имеет смысл только при handshake-MSS (Telemt-спецификация).
            # mtproto.py это не валидирует — телемт сам проигнорирует bulk без handshake.
            # Но мы пишем его только если оба заданы, чтобы не плодить мусор в конфиге.
            lines.insert(_port_idx + 2, f'client_mss_bulk = "{client_mss_bulk}"')
    lines += censorship_lines
    lines += [
        "", "[access]", "replay_check_len = 65536", "ignore_time_skew = false",
        "", "[access.users]",
    ]
    for n, s in users.items(): lines.append(f'{n} = "{s}"')
    if socks5_port > 0:
        lines += [
            "", "[[upstreams]]",
            'type = "socks5"',
            f'addr = "127.0.0.1:{socks5_port}"',
            "enabled = true", "weight = 10",
        ]
    else:
        lines += ["", "[[upstreams]]", 'type = "direct"', "enabled = true", "weight = 10"]
    if not use_middle_proxy:
        lines += [
            "", "[dc_overrides]",
            '"1"   = "149.154.175.50:443"',
            '"2"   = "149.154.167.51:443"',
            '"3"   = "149.154.175.100:443"',
            '"4"   = "149.154.167.91:443"',
            '"5"   = "149.154.171.5:443"',
            '"203" = "91.105.192.100:443"',
        ]
    CONFIG_FILE.write_text("\n".join(lines) + "\n")
    CONFIG_FILE.chmod(0o640)

    # Записываем секцию [middle_proxy] с параметрами fallback (если передана).
    # ВАЖНО: это состояние инсталлера, а не Telemt — пишется в отдельный
    # файл (см. _FALLBACK_STATE_FILE в telemt_fallback.py), НЕ в telemt.toml,
    # иначе Telemt со strict_keys ругается на неизвестный ключ при загрузке.
    if fallback_cfg is not None:
        _fb_mod = _get_fallback_module()
        if _fb_mod is not None:
            try:
                _fb_mod.append_fallback_section(fallback_cfg)
            except Exception as _e:
                _warn(f"Не удалось записать [middle_proxy]: {_e}")


def ensure_api_enabled(token: str, host: str = "127.0.0.1", port: int = 9091,
                        grant_read_to: str = "") -> tuple:
    """
    Включает/обновляет секцию [server.api] в telemt.toml — единая точка
    правды для файла конфига Telemt (используется telemt_panel.py, чтобы не
    плодить вторую параллельную логику записи этого файла).

    ВАЖНО: реальная схема Telemt называет эту секцию именно "[server.api]"
    (устаревший алиас — "[server.admin_api]"); ключ верхнего уровня "[api]"
    telemt НЕ распознаёт вовсе. Раньше эта функция писала "[api]", из-за
    чего Telemt со strict_keys молча игнорировал всю секцию как неизвестный
    ключ ("key=api suggestion=api" в логах) и продолжал использовать
    встроенные дефолты "[server.api]" — а они таковы: enabled=true,
    listen="0.0.0.0:9091". Т.е. панель API включалась и торчала наружу на
    0.0.0.0:9091 совершенно независимо от host/port, переданных сюда.
    Явная запись "[server.api]" с host="127.0.0.1" — единственный способ
    реально ограничить бинд localhost'ом.

    Идемпотентно: если секция уже есть — просто обновляет enabled/listen/
    auth_header, ничего больше в файле не трогает (порядок остальных
    секций сохраняется). Заодно подчищает старую ошибочную секцию "[api]",
    если она осталась от прежних версий инсталлера.

    grant_read_to — если указано системное имя группы/пользователя (обычно
    telemt-panel), файлу назначается эта группа-владелец с правом чтения
    (0640) — иначе панель, читая конфиг напрямую в файловом режиме, падает
    с "permission denied" (владелец файла — root, группа по умолчанию тоже
    root, у непривилегированного юзера панели доступа нет).

    Возвращает (ok: bool, message: str).
    """
    if not CONFIG_FILE.exists():
        return False, "Telemt не установлен — нечего включать."

    text = CONFIG_FILE.read_text()

    # Подчищаем устаревшую ошибочную секцию "[api]" (писалась версиями
    # инсталлера до этого фикса) — telemt её никогда не читал, но оставлять
    # мусор в конфиге ни к чему.
    stale_pattern = re.compile(r"(?m)^\[api\]\n(?:(?!\n?\[)[^\n]*\n?)*")
    text = stale_pattern.sub("", text)

    new_section = (
        "[server.api]\n"
        "enabled = true\n"
        f'listen = "{host}:{port}"\n'
        f'auth_header = "{token}"\n'
    )

    if "[server.api]" in text or "[server.admin_api]" in text:
        # Заменяем существующую секцию целиком (до следующего заголовка [...]
        # или до конца файла), не трогая ничего вокруг. Учитываем оба
        # варианта названия секции (актуальное и устаревший алиас).
        pattern = re.compile(
            r"\[server\.(?:api|admin_api)\]\n(?:(?!\n?\[)[^\n]*\n?)*", re.MULTILINE
        )
        if not pattern.search(text):
            # На случай нестандартного форматирования — не рискуем ломать файл.
            return False, "Секция [server.api] найдена, но не удалось безопасно её заменить."
        text = pattern.sub(new_section, text, count=1)
        action = "обновлена"
    else:
        sep = "" if text.endswith("\n\n") else ("\n" if text.endswith("\n") else "\n\n")
        text = text.rstrip("\n") + "\n" + sep + new_section
        action = "добавлена"

    CONFIG_FILE.write_text(text)

    if grant_read_to:
        r_grp = _run(["chgrp", grant_read_to, str(CONFIG_FILE)])
        if r_grp.returncode == 0:
            CONFIG_FILE.chmod(0o640)

    r = _run(["systemctl", "restart", SERVICE_NAME])
    if r.returncode != 0:
        return False, f"Секция [server.api] {action}, но перезапуск Telemt не удался."
    return True, f"Секция [server.api] {action}, Telemt перезапущен ({host}:{port})."


# ══════════════════════════════════════════════════════════════════════════════
#  XRAY TPROXY-ИНТЕГРАЦИЯ  (dokodemo-door + iptables REDIRECT)
# ══════════════════════════════════════════════════════════════════════════════
#
#  Почему не SOCKS5:
#    Текущая версия telemt (Rust/Tokio) не поддерживает SOCKS5-upstream.
#    Используем обходной путь на уровне ядра:
#      1. Xray слушает dokodemo-door на 127.0.0.1:XRAY_TPROXY_PORT
#      2. iptables REDIRECT перехватывает TCP telemt → Telegram IP → :XRAY_TPROXY_PORT
#      3. Xray обрабатывает пакет под uid xray:
#           VLESS: → chain-exit outbound / balancer → exit VPS → Telegram
#           AWG:   → freedom+fwmark → awg0 → exit VPS → Telegram
#             (uid xray получает fwmark от policy routing → пакет идёт через awg0 ✓)
#
#  Схема одинакова для обоих транспортов — VLESS-цепочки и AWG 2.0.
# ──────────────────────────────────────────────────────────────────────────────

def _xray_config_path() -> Optional[Path]:
    """Возвращает первый найденный config.json xray, иначе None."""
    for p in XRAY_CONFIG_PATHS:
        if p.exists():
            return p
    return None


def _xray_cascade_mode() -> str:
    """
    Определяет режим каскада по state.json.
    Возвращает: "awg" | "vless" | "none"
    """
    state_file = Path("/var/lib/xray-installer/state.json")
    if not state_file.exists():
        return "none"
    try:
        state = json.loads(state_file.read_text())
        if state.get("awg_exit_enabled"):
            return "awg"
        mode = state.get("install_mode", state.get("mode", ""))
        if str(mode).upper() == "B":
            return "vless"
    except Exception:
        pass
    return "none"


def _find_xray_bin() -> Optional[str]:
    """Возвращает путь к бинарнику xray или None."""
    for candidate in ("/usr/local/bin/xray", "/usr/bin/xray"):
        if Path(candidate).exists():
            return candidate
    import shutil as _sh
    return _sh.which("xray")


def _xray_has_inbound(cfg: dict, tag: str) -> bool:
    """Проверяет наличие inbound с данным тегом."""
    return any(ib.get("tag") == tag for ib in cfg.get("inbounds", []))


def _xray_get_proxy_tag(cfg: dict) -> tuple:
    """
    Находит тег главного outbound/balancer каскада.
    Возвращает (tag: str, is_balancer: bool).

    Balancer (2+ нод) требует balancerTag в routing rule — это другое поле,
    не outboundTag; путать нельзя, xray не найдёт outboundTag среди outbounds.
    """
    for b in cfg.get("routing", {}).get("balancers", []):
        if "chain" in b.get("tag", ""):
            return b["tag"], True
    outbounds = cfg.get("outbounds", [])
    for prefer in ("chain-exit-1", "chain-exit"):
        if any(ob.get("tag") == prefer for ob in outbounds):
            return prefer, False
    # AWG-режим: freedom outbound с fwmark
    for ob in outbounds:
        tag = ob.get("tag", "")
        if tag in ("BLOCK", "xray-stats-api", "direct"):
            continue
        sm = ob.get("streamSettings", {}).get("sockopt", {}).get("mark", 0)
        if ob.get("protocol") == "freedom" and sm:
            return tag, False
        if ob.get("protocol") == "vless":
            return tag, False
    return "chain-exit", False


# ── Xray config: dokodemo-door inbound ───────────────────────────────────────

def _xray_inject_dokodemo(cfg: dict, port: int) -> bool:
    """
    Добавляет dokodemo-door inbound + routing rule в конфиг xray.
    followRedirect=True: принимает TCP переброшенные iptables REDIRECT.
    Возвращает True если конфиг изменён.
    """
    if _xray_has_inbound(cfg, XRAY_TPROXY_TAG):
        return False

    cfg.setdefault("inbounds", []).append({
        "tag":      XRAY_TPROXY_TAG,
        "port":     port,
        "listen":   "127.0.0.1",
        "protocol": "dokodemo-door",
        "settings": {"network": "tcp", "followRedirect": True},
        "sniffing": {"enabled": False},
    })

    proxy_tag, is_balancer = _xray_get_proxy_tag(cfg)
    rule: dict = {"type": "field", "inboundTag": [XRAY_TPROXY_TAG]}
    if is_balancer:
        rule["balancerTag"] = proxy_tag
    else:
        rule["outboundTag"] = proxy_tag

    rules: list = cfg.setdefault("routing", {}).setdefault("rules", [])
    rules.insert(0, rule)
    return True


def _xray_remove_dokodemo(cfg: dict) -> bool:
    """Удаляет dokodemo inbound и routing rule из конфига xray."""
    changed = False
    inbounds = cfg.get("inbounds", [])
    new_ib = [ib for ib in inbounds if ib.get("tag") != XRAY_TPROXY_TAG]
    if len(new_ib) != len(inbounds):
        cfg["inbounds"] = new_ib
        changed = True
    rules = cfg.get("routing", {}).get("rules", [])
    new_r = [r for r in rules if XRAY_TPROXY_TAG not in r.get("inboundTag", [])]
    if len(new_r) != len(rules):
        cfg["routing"]["rules"] = new_r
        changed = True
    return changed


def _xray_dokodemo_port(cfg: dict) -> int:
    """Возвращает порт dokodemo inbound если настроен, иначе 0."""
    for ib in cfg.get("inbounds", []):
        if ib.get("tag") == XRAY_TPROXY_TAG:
            return int(ib.get("port", 0))
    return 0


def _xray_write_and_test(cfg_path: Path, cfg: dict) -> Optional[str]:
    """
    Записывает конфиг и проверяет синтаксис через xray -test.
    Возвращает None при успехе, строку с ошибкой при неудаче.
    """
    try:
        cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
        cfg_path.chmod(0o640)
    except Exception as e:
        return f"Не удалось записать {cfg_path}: {e}"
    xray_bin = _find_xray_bin()
    if xray_bin:
        r = _run([xray_bin, "run", "-test", "-config", str(cfg_path)], capture=True)
        if r.returncode != 0:
            return f"xray -test провалился: {(r.stderr or r.stdout)[:300]}"
    return None


# ── iptables REDIRECT для Telegram-подсетей ───────────────────────────────────

# _ipt_rule_exists — вынесен в proto_common (proto_ipt_rule_exists).
# Выбор iptables vs ip6tables (по ":" в net) остаётся здесь — proto_common
# работает только с iptables. Для IPv6 вызываем _run напрямую.
def _ipt_rule_exists(net: str, port: int) -> bool:
    """Проверяет наличие REDIRECT-правила через iptables -C (не дублирует).

    КРИТИЧНО: iptables -C / ip6tables -C возвращают exit status 1 когда правило
    НЕ существует — это норма (man iptables: "If the rule does not exist, the
    exit code is 1"). _run с check=True (по умолчанию) бросает CalledProcessError
    на rc=1, что валило весь TUI-меню Telemt при открытии если хоть одна TG-подсеть
    не имела правила. Поэтому для IPv6 пути явно передаём check=False.
    IPv4 путь идёт через proto_ipt_rule_exists (там фикс отдельный).
    """
    v6  = ":" in net
    if v6:
        # IPv6 — ip6tables, не покрывается proto_ipt_rule_exists
        try:
            r = _run(["ip6tables", "-t", "nat", "-C", "OUTPUT",
                      "-d", net, "-p", "tcp",
                      "-j", "REDIRECT", "--to-port", str(port)],
                     capture=True, check=False)
            return r.returncode == 0
        except Exception:
            return False
    return proto_ipt_rule_exists("nat", "OUTPUT",
                                ["-d", net, "-p", "tcp",
                                 "-j", "REDIRECT", "--to-port", str(port)])


def _ipt_add_redirect(net: str, port: int) -> bool:
    """Добавляет REDIRECT-правило если ещё нет. Возвращает True при успехе."""
    if _ipt_rule_exists(net, port):
        return True
    v6  = ":" in net
    ipt = "ip6tables" if v6 else "iptables"
    r   = _run([ipt, "-t", "nat", "-A", "OUTPUT",
                "-d", net, "-p", "tcp",
                "-j", "REDIRECT", "--to-port", str(port)],
               capture=True)
    return r.returncode == 0


def _ipt_del_redirect(net: str, port: int) -> None:
    """Удаляет REDIRECT-правило (все копии, идемпотентно)."""
    for _ in range(5):
        if not _ipt_rule_exists(net, port):
            break
        v6  = ":" in net
        ipt = "ip6tables" if v6 else "iptables"
        _run([ipt, "-t", "nat", "-D", "OUTPUT",
              "-d", net, "-p", "tcp",
              "-j", "REDIRECT", "--to-port", str(port)],
             capture=True)


# ── RETURN-правила для ME-портов (исключения из REDIRECT) ────────────────────
# ME-серверы Telegram используют порты :8888 (основной) и :80 (health-check).
# Эти порты НЕ должны попадать под REDIRECT в xray-tproxy-интеграции, иначе
# telemt не может поднять Middle Proxy pool (RPC handshake проваливается,
# т.к. xray отдаёт plain TCP вместо MTProto-handshake).
#
# ВАЖНО: эти helper-функции работают с ОБЕИМ таблицами — iptables (IPv4)
# и ip6tables (IPv6) — т.к. ME-серверы доступны и по IPv4, и по IPv6.

#: ME-порты, которые исключаются из REDIRECT.
# ME-серверы Telegram используют порты :8888 (основной), :80 (health-check),
# :443 (fallback/альтернативный), :8443 (TLS-альтернативный). Все они должны
# быть исключены из REDIRECT, иначе ME-handshake проваливается.
#
# ВАЖНО: :443 и :8443 также используются TG-DC (Data Centers) для прямых
# подключений клиентов. Исключение этих портов означает, что TG-DC трафик
# тоже идёт напрямую (НЕ через xray cascade). Это приемлемо, когда:
#   • Middle Proxy работает (ME-pool поднят) — telemt не обращается к TG-DC
#     напрямую, ME-серверы делают это внутри себя.
#   • Хостер не блокирует TG-DC :443 (если блокирует — Direct Mode fallback
#     не будет работать через xray, но ME как primary режим работает).
# Если хостер блокирует TG-DC :443 и ME тоже не работает — нужно полностью
# отключать xray tproxy или менять архитектуру.
_ME_RETURN_PORTS: tuple = ("8888", "80", "443", "8443")


def _ipt_return_rule_exists(ipt: str, dport: str) -> bool:
    """Проверяет наличие RETURN-правила для dport в таблице ipt
    (iptables или ip6tables). Через iptables -C (check).
    """
    r = _run([ipt, "-t", "nat", "-C", "OUTPUT",
              "-p", "tcp", "--dport", dport, "-j", "RETURN"],
             capture=True, check=False)
    return r.returncode == 0


def _ipt_remove_all_return_rules(ipt: str, dport: str) -> int:
    """Удаляет ВСЕ RETURN-правила для dport в таблице ipt, сколько бы
    их ни было. Возвращает количество удалённых правил.

    Аналог _ipt_remove_all_jumps() для RETURN-правил ME-портов.
    Использует _ipt_return_rule_exists() для проверки after each removal,
    а не полагается на returncode -D (который удаляет только одно правило
    за вызов).

    Защита от бесконечного цикла — 20 итераций (больше дублей в
    реальной системе не бывает, обычно 1-2).
    """
    removed = 0
    for _ in range(20):
        if not _ipt_return_rule_exists(ipt, dport):
            break
        r = _run([ipt, "-t", "nat", "-D", "OUTPUT",
                  "-p", "tcp", "--dport", dport, "-j", "RETURN"],
                 capture=True, check=False)
        if r.returncode != 0:
            break
        removed += 1
    return removed


def _ipt_ensure_single_return_rule(ipt: str, dport: str) -> int:
    """Гарантирует, что в таблице ipt есть РОВНО ОДНО RETURN-правило
    для dport. Сначала удаляет все существующие (через
    _ipt_remove_all_return_rules), потом добавляет ровно одно через -I.

    Возвращает количество удалённых дублей (для логирования).
    """
    removed = _ipt_remove_all_return_rules(ipt, dport)
    _run([ipt, "-t", "nat", "-I", "OUTPUT",
          "-p", "tcp", "--dport", dport, "-j", "RETURN"],
         capture=True, check=False)
    return removed


def _ipt_owner_return_rule_exists(ipt: str, uid: int) -> bool:
    """Проверяет RETURN-правило по UID (для исключения xray UID 999
    из REDIRECT-петли).
    """
    r = _run([ipt, "-t", "nat", "-C", "OUTPUT",
              "-m", "owner", "--uid-owner", str(uid), "-j", "RETURN"],
             capture=True, check=False)
    return r.returncode == 0


def _ipt_remove_all_owner_return_rules(ipt: str, uid: int) -> int:
    """Удаляет ВСЕ RETURN-правила по UID в таблице ipt. Аналог
    _ipt_remove_all_return_rules, но для owner-match правил.
    """
    removed = 0
    for _ in range(20):
        if not _ipt_owner_return_rule_exists(ipt, uid):
            break
        r = _run([ipt, "-t", "nat", "-D", "OUTPUT",
                  "-m", "owner", "--uid-owner", str(uid), "-j", "RETURN"],
                 capture=True, check=False)
        if r.returncode != 0:
            break
        removed += 1
    return removed


def _ipt_ensure_single_owner_return(ipt: str, uid: int) -> int:
    """Гарантирует ровно одно RETURN-правило по UID в таблице ipt."""
    removed = _ipt_remove_all_owner_return_rules(ipt, uid)
    _run([ipt, "-t", "nat", "-I", "OUTPUT",
          "-m", "owner", "--uid-owner", str(uid), "-j", "RETURN"],
         capture=True, check=False)
    return removed


def _iptables_persist() -> None:
    """
    Сохраняет iptables-правила для выживания после ребута.
    Порядок попыток:
      1. netfilter-persistent save  (Debian/Ubuntu с iptables-persistent)
      2. iptables-save → /etc/iptables/rules.v4 + rules.v6
      3. systemd-сервис telemt-iptables (fallback)
    """
    if shutil.which("netfilter-persistent"):
        _run(["netfilter-persistent", "save"], capture=True)
        return
    rules_dir = Path("/etc/iptables")
    rules_dir.mkdir(parents=True, exist_ok=True)
    r4 = _run(["iptables-save"],  capture=True)
    if r4.returncode == 0 and r4.stdout:
        (rules_dir / "rules.v4").write_text(r4.stdout)
    r6 = _run(["ip6tables-save"], capture=True)
    if r6.returncode == 0 and r6.stdout:
        (rules_dir / "rules.v6").write_text(r6.stdout)
    _ensure_ipt_restore_service()


def _ensure_ipt_restore_service() -> None:
    """
    Создаёт systemd-сервис восстановления iptables при загрузке,
    если нет netfilter-persistent.
    """
    svc_path = Path("/etc/systemd/system/telemt-iptables.service")
    if svc_path.exists():
        # Пересоздаём чтобы обновить пути если изменились
        pass
    rules_v4 = Path("/etc/iptables/rules.v4")
    rules_v6 = Path("/etc/iptables/rules.v6")
    exec_lines = ""
    if rules_v4.exists():
        exec_lines += f"ExecStart=/bin/sh -c 'iptables-restore < {rules_v4}'\n"
    if rules_v6.exists():
        exec_lines += f"ExecStart=/bin/sh -c 'ip6tables-restore < {rules_v6}'\n"
    if not exec_lines:
        return
    svc_path.write_text(
        "[Unit]\n"
        "Description=Restore iptables REDIRECT rules for telemt tproxy\n"
        "Before=network-pre.target\n"
        "Wants=network-pre.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        + exec_lines +
        "\n[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _run(["systemctl", "daemon-reload"], capture=True)
    _run(["systemctl", "enable", "telemt-iptables.service"], capture=True)


# ── Публичный API ─────────────────────────────────────────────────────────────

def xray_enable_tproxy_for_telemt(port: int = XRAY_TPROXY_PORT) -> tuple:
    """
    Полная активация tproxy-интеграции (VLESS-цепочки и AWG 2.0).

    Шаги:
      1. dokodemo-door inbound → xray config.json
      2. routing rule: tproxy-telemt → balancer/chain-exit
      3. iptables REDIRECT всех Telegram-подсетей → port
      4. Persist iptables (netfilter-persistent / iptables-save / systemd)
      5. Перезапуск xray

    Идемпотентна: повторный вызов не дублирует правила.
    Возвращает (ok: bool, message: str).
    """
    cfg_path = _xray_config_path()
    if not cfg_path:
        return False, "xray config.json не найден — xray не установлен"

    cascade = _xray_cascade_mode()
    if cascade == "none":
        return False, (
            "xray не настроен в режиме каскада (Режим B). "
            "Сначала установите xray с Режимом B, затем повторите."
        )

    try:
        cfg = json.loads(cfg_path.read_text())
    except Exception as e:
        return False, f"Не удалось прочитать {cfg_path}: {e}"

    # Если порт поменялся — пересоздаём inbound
    existing_port = _xray_dokodemo_port(cfg)
    if existing_port and existing_port != port:
        _xray_remove_dokodemo(cfg)
        existing_port = 0

    xray_changed = False
    if not existing_port:
        xray_changed = _xray_inject_dokodemo(cfg, port)

    if xray_changed:
        err = _xray_write_and_test(cfg_path, cfg)
        if err:
            # Откат
            _xray_remove_dokodemo(cfg)
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            return False, err
        _run(["systemctl", "restart", XRAY_SERVICE_NAME])

    # ── iptables REDIRECT ─────────────────────────────────────────────────────
    # Исключение 1: xray (UID 999) не должен попадать в REDIRECT-петлю.
    # Гарантируем РОВНО ОДНО правило через _ipt_ensure_single_owner_return
    # (сначала удаляем все дубли, потом добавляем одно).
    _ipt_ensure_single_owner_return("iptables", 999)
    # Исключение 2: ME-серверы Telegram на портах 8888 и 80 не должны
    # попадать под REDIRECT (нужно для работы use_middle_proxy=true в
    # каскадной схеме). Telemt сам делает RPC handshake к ME-серверам
    # на :8888 (основной ME-порт) и :80 (health-check / fallback).
    # Без этого исключения REDIRECT перехватывает трафик к ME → xray
    # отдаёт plain TCP вместо MTProto-handshake → ME-pool не поднимается
    # → "me runtime ready: OFF" → fallback в Direct Mode.
    #
    # Применяем к ОБЕИМ таблицам: iptables (IPv4) и ip6tables (IPv6),
    # т.к. ME-серверы доступны и по IPv4 (91.108.x.x, 149.154.x.x),
    # и по IPv6 (2001:67c:4e8::, 2001:b28:f23d::, и т.д.).
    #
    # Гарантируем РОВНО ОДНО RETURN-правило на порт через
    # _ipt_ensure_single_return_rule — цикл удаления всех дублей
    # перед добавлением одного. Без этого при повторных вызовах
    # (через меню или при emergency_restore) правила накапливались
    # дубли, а при ручной чистке пользователь мог удалить все — и
    # ME-pool снова падал.
    for _ipt in ("iptables", "ip6tables"):
        for _me_port in _ME_RETURN_PORTS:
            _ipt_ensure_single_return_rule(_ipt, _me_port)
    tg_nets = _TG_NETS_current()
    failed = [net for net in tg_nets if not _ipt_add_redirect(net, port)]
    _iptables_persist()

    if failed:
        return False, f"iptables REDIRECT не удалось для: {', '.join(failed)}"

    mode_label = "AWG 2.0" if cascade == "awg" else "VLESS"
    status = "уже был настроен" if (existing_port and not xray_changed) else "добавлен"
    return True, (
        f"dokodemo-door {status} (:{port}), "
        f"iptables REDIRECT активен [{len(tg_nets)} подсетей], "
        f"транспорт: {mode_label}"
    )


def xray_disable_tproxy_for_telemt() -> tuple:
    """
    Полное отключение tproxy-интеграции:
      1. Удаляет dokodemo-door из xray config, перезапускает xray
      2. Удаляет iptables REDIRECT для всех Telegram-подсетей
      3. Сохраняет состояние iptables
    Возвращает (ok: bool, message: str).
    """
    cfg_path = _xray_config_path()
    if cfg_path:
        try:
            cfg = json.loads(cfg_path.read_text())
            port = _xray_dokodemo_port(cfg)
            if _xray_remove_dokodemo(cfg):
                cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                cfg_path.chmod(0o640)
                _run(["systemctl", "restart", XRAY_SERVICE_NAME])
        except Exception as e:
            return False, f"Не удалось обновить xray config: {e}"
    else:
        port = XRAY_TPROXY_PORT

    for net in _TG_NETS_current():
        _ipt_del_redirect(net, port or XRAY_TPROXY_PORT)

    # Удаляем ВСЕ исключения для ME-портов (:8888, :80) — больше не нужны
    # без REDIRECT. Обе таблицы (iptables + ip6tables). Через цикл
    # _ipt_remove_all_return_rules — удаляет ВСЕ дубли (а не одно правило
    # как одиночный -D).
    for _ipt in ("iptables", "ip6tables"):
        for _me_port in _ME_RETURN_PORTS:
            _ipt_remove_all_return_rules(_ipt, _me_port)
    # Удаляем ВСЕ исключения для UID 999 (xray) — аналогично через цикл
    _ipt_remove_all_owner_return_rules("iptables", 999)

    _iptables_persist()

    svc = Path("/etc/systemd/system/telemt-iptables.service")
    if svc.exists():
        _run(["systemctl", "disable", "--now", "telemt-iptables.service"], capture=True)
        svc.unlink(missing_ok=True)
        _run(["systemctl", "daemon-reload"], capture=True)

    return True, "tproxy-интеграция отключена: dokodemo удалён, iptables очищен"


def telemt_tproxy_emergency_restore() -> tuple:
    """
    Восстанавливает tproxy-интеграцию Telemt→Xray после аварийного восстановления.

    Вызывается из do_emergency_repair() в _core.py.
    Детектирует факт установки Telemt по бинарнику / systemd-сервису — без опоры
    на флаги в state.json (которых для tproxy нет).

    Логика:
      1. Если Telemt не установлен — возвращает (None, "не установлен"), вызывающий
         код выводит "пропуск". None сигнализирует: не ошибка, просто не применимо.
      2. Если Xray не в каскадном режиме (Режим B / AWG) — возвращает (None, причина).
         xray_enable_tproxy_for_telemt сама это проверит, но ранняя проверка позволяет
         вернуть корректный статус без лишних операций.
      3. Если dokodemo уже есть в config.json и все iptables-правила на месте —
         возвращает (True, "уже активна"). Функция идемпотентна.
      4. Иначе — вызывает xray_enable_tproxy_for_telemt() и возвращает её результат.

    Возвращает:
      (True,  сообщение) — интеграция восстановлена или уже была активна
      (False, сообщение) — ошибка при восстановлении
      (None,  сообщение) — Telemt не установлен или неприменимо (не ошибка)
    """
    # ── Детект установки Telemt ───────────────────────────────────────────────
    telemt_installed = BIN_PATH.exists() or SERVICE_FILE.exists()
    if not telemt_installed:
        # Дополнительная проверка через systemctl (на случай нестандартного пути)
        r_svc = _run(["systemctl", "is-active", SERVICE_NAME], capture=True, check=False)
        telemt_installed = r_svc.stdout.strip() in ("active", "inactive", "failed")

    if not telemt_installed:
        return None, "Telemt не установлен"

    # ── Проверка каскадного режима ────────────────────────────────────────────
    cascade = _xray_cascade_mode()
    if cascade == "none":
        return None, "xray-каскад (Режим B) не активен — tproxy неприменим"

    # ── Статус текущей интеграции ─────────────────────────────────────────────
    status = _xray_tproxy_status()
    if status["enabled"] and status["ipt_ok"]:
        return True, (
            f"tproxy-интеграция уже активна "
            f"(dokodemo :{status['port']}, "
            f"iptables {status['ipt_count']}/{status['ipt_total']} подсетей)"
        )

    # ── Применяем / восстанавливаем ───────────────────────────────────────────
    return xray_enable_tproxy_for_telemt(XRAY_TPROXY_PORT)


def _xray_tproxy_status() -> dict:
    """
    Возвращает dict со статусом tproxy-интеграции:
      enabled   – bool  (dokodemo inbound настроен)
      port      – int   (0 если нет)
      cascade   – str   ("awg" | "vless" | "none")
      proxy_tag – str
      ipt_ok    – bool  (все iptables-правила на месте)
      ipt_count – int   (сколько из len(_TG_NETS) правил активно)
    """
    cfg_path = _xray_config_path()
    cascade  = _xray_cascade_mode()
    base     = {"enabled": False, "port": 0, "cascade": cascade,
                "proxy_tag": "—", "ipt_ok": False, "ipt_count": 0,
                "ipt_total": len(_TG_NETS_current())}
    if not cfg_path:
        return base
    try:
        cfg = json.loads(cfg_path.read_text())
    except Exception:
        return base

    port = _xray_dokodemo_port(cfg)
    if not port:
        return base

    pt, is_bal   = _xray_get_proxy_tag(cfg)
    proxy_tag    = pt + (" [balancer]" if is_bal else "")
    tg_nets      = _TG_NETS_current()
    # Per-net resilience: если даже после фиксов proto_ipt_rule_exists /
    # _ipt_rule_exists какой-то отдельный net упадёт (например, iptables
    # временно недоступен), не роняем весь TUI-меню Telemt. Считаем что
    # для упавшего net правила нет (False), остальные подсети проверяются
    # нормально. ipt_ok = False если хоть одна не проверена/отсутствует.
    ipt_active = 0
    for n in tg_nets:
        try:
            if _ipt_rule_exists(n, port):
                ipt_active += 1
        except Exception:
            # Defensive: _ipt_rule_exists сам ловит исключения, но на всякий
            # случай — если что-то пробилось, считаем что правила нет.
            pass

    return {
        "enabled":   True,
        "port":      port,
        "cascade":   cascade,
        "proxy_tag": proxy_tag,
        "ipt_ok":    ipt_active == len(tg_nets),
        "ipt_count": ipt_active,
        "ipt_total": len(tg_nets),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА БИНАРНИКА
# ══════════════════════════════════════════════════════════════════════════════
def _install_binary(url) -> bool:
    """Устанавливает бинарник telemt из tar.gz-архива.

    МИГРАЦИЯ: использует fetch_package(TELEMT_SPEC) из download_manager.py.
    fetch_package сам:
      1. Проверяет /root/{filename} (manual_incoming_dir) — если найден,
         использует без сети (WinSCP-friendly).
      2. Иначе — перебирает зеркала через urllib (8 зеркал).
      3. При успехе — вызывает post_install (tar -xzf + copy2 в BIN_PATH).
      4. При провале — возвращает False.

    Параметр `url` игнорируется (оставлен для обратной совместимости со
    старыми вызовами _install_binary(urls)). Новый код использует
    TELEMT_SPEC.mirror_urls_builder внутри fetch_package.
    """
    from chimera.modules.telemt_packages import TELEMT_SPEC
    from chimera.modules.download_manager import fetch_package

    _info(f"Загрузка telemt ({TELEMT_MIRRORS_COUNT} зеркал в fallback)...")
    return fetch_package(TELEMT_SPEC, print_hint_on_failure=False)

# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEMD / UFW / ОПТИМИЗАЦИЯ
# ══════════════════════════════════════════════════════════════════════════════
def _install_service() -> None:
    SERVICE_FILE.write_text("""[Unit]
Description=Telemt MTProxy Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/telemt
ExecStart=/usr/local/bin/telemt /etc/telemt/telemt.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
TimeoutStartSec=90
TimeoutStopSec=10s
StartLimitIntervalSec=60s
StartLimitBurst=3
LimitNOFILE=1048576
LimitNPROC=infinity
Nice=-10
IOSchedulingClass=best-effort
IOSchedulingPriority=0

[Install]
WantedBy=multi-user.target
""")
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", SERVICE_NAME])

def _setup_ufw(port: int) -> None:
    #  миграция на port_registry.
    try:
        from chimera.modules.port_registry import (
            ufw_open_port, port_register, SERVICE_TELEMT_MTPROTO,
        )
        port_register(SERVICE_TELEMT_MTPROTO, port, "tcp",
                      comment="Telemt MTProxy", force=True)
        ok, msg = ufw_open_port(port, "tcp", SERVICE_TELEMT_MTPROTO,
                                comment="Telemt MTProxy")
        if ok:
            _ok(f"UFW: открыт порт {port}/tcp ({msg})")
            return
    except Exception:
        pass
    if not shutil.which("ufw"): return
    if "active" in _run(["ufw", "status"], capture=True).stdout.lower():
        _run(["ufw", "allow", f"{port}/tcp", "comment", "Telemt MTProxy"])
        _ok(f"UFW: открыт порт {port}/tcp")


def _mtproto_ufw_close(port: int) -> None:
    """ закрывает UFW-порт для Telemt MTProxy через port_registry
    с backward compat для legacy comment 'Telemt MTProxy'."""
    try:
        from chimera.modules.port_registry import (
            ufw_close_port, port_unregister, SERVICE_TELEMT_MTPROTO,
        )
        ufw_close_port(port, "tcp", SERVICE_TELEMT_MTPROTO,
                       legacy_comments=["Telemt MTProxy"])
        port_unregister(SERVICE_TELEMT_MTPROTO, port, "tcp")
        _box_ok(f"UFW: правило для порта {port}/tcp удалено.")
        return
    except Exception:
        pass
    if shutil.which("ufw") and "active" in _run(["ufw", "status"], capture=True).stdout.lower():
        _run(["ufw", "delete", "allow", f"{port}/tcp"])
        _box_ok(f"UFW: правило для порта {port}/tcp удалено.")

def _apply_optimizations() -> None:
    try:
        ram_mb = int(subprocess.check_output(
            ["awk", "/^MemTotal/{print int($2/1024)}", "/proc/meminfo"], text=True
        ).strip())
    except Exception:
        ram_mb = 1024
    conntrack = "2000000" if ram_mb >= 1024 else ("524288" if ram_mb >= 512 else "262144")
    file_max  = "2097152" if ram_mb >= 1024 else ("1048576" if ram_mb >= 512 else "524288")
    bbr = False
    try:
        kv = os.uname().release.split(".")
        if int(kv[0]) > 4 or (int(kv[0]) == 4 and int(kv[1]) >= 9):
            _run(["modprobe", "tcp_bbr"])
            bbr = "bbr" in _run(["sysctl", "net.ipv4.tcp_available_congestion_control"], capture=True).stdout
    except Exception:
        pass
    cc = ("net.ipv4.tcp_congestion_control = bbr\nnet.core.default_qdisc = fq"
          if bbr else "net.ipv4.tcp_congestion_control = cubic")
    # keepalive_time/intvl/probes занижены против дефолта (7200/75/9).
    # Контекст: iOS (и часть агрессивных Android-прошивок) сворачивает/душит
    # приложение без чистого закрытия сокета — сервер держит мёртвое
    # соединение часами. При возврате клиент пытается переподключиться и
    # залипает, пока старая половинка соединения не истечёт. 60/15/3 рвёт
    # мёртвый коннект за ~105 сек (60с тишины + проба каждые 15с × 3 попытки
    # → RST) вместо дефолтных ~2.1ч.
    OPTIMIZER_CONF.parent.mkdir(parents=True, exist_ok=True)
    OPTIMIZER_CONF.write_text(f"""# Telemt MTProxy — kernel optimizations
{cc}
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 250000
net.netfilter.nf_conntrack_max = {conntrack}
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.ip_local_port_range = 1024 65535
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
fs.file-max = {file_max}
vm.swappiness = 10
""")
    _run(["sysctl", "-p", str(OPTIMIZER_CONF)])
    LIMITS_CONF.parent.mkdir(parents=True, exist_ok=True)
    LIMITS_CONF.write_text("""* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
""")
    _ok(f"Оптимизация ядра (BBR: {'да' if bbr else 'нет'})")

# ══════════════════════════════════════════════════════════════════════════════
#  IPTABLES ACCOUNTING (делегируем в mtproto_stats.py)
# ══════════════════════════════════════════════════════════════════════════════
def _setup_accounting(port: int) -> bool:
    """Настраивает iptables-цепочки учёта. Возвращает True при успехе.

    Делегирует в mtproto_stats.setup_iptables_accounting(), которая теперь
    САМА постфактум-верифицирует факт создания цепочек и jump-правил через
    `iptables -L INPUT -v -n` / `iptables -L OUTPUT -v -n` (а не полагается
    на успешный returncode `iptables -I` — он с check=False не бросает
    исключений при провале, но и не гарантирует появления правила).

    try/except оставлен только для реального импорт-сбоя (модуль
    mtproto_stats недоступен) — это единственный случай, когда здесь может
    возникнуть Python-уровневое исключение.
    """
    try:
        from chimera.modules.mtproto_stats import setup_iptables_accounting
        return bool(setup_iptables_accounting(port))
    except Exception as _e:
        try:
            _warn(f"_setup_accounting: import mtproto_stats failed: {_e}")
        except Exception:
            pass
        return False

# ══════════════════════════════════════════════════════════════════════════════
#  ПОЛНОЕ УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _full_uninstall(silent: bool = False) -> bool:
    if not silent:
        _banner()
        _box_top("🗑️  ПОЛНОЕ УДАЛЕНИЕ  •  TELEMT")
        _box_row()
        _box_warn("Будет удалено ВСЁ:")
        _box_row()
        _box_row(f"  {DIM}  • Сервис systemd  ({SERVICE_NAME}){NC}")
        _box_row(f"  {DIM}  • Бинарник        ({BIN_PATH}){NC}")
        _box_row(f"  {DIM}  • Конфиги         ({CONFIG_DIR}){NC}")
        _box_row(f"  {DIM}  • Данные / стата  ({WORK_DIR}){NC}")
        _box_row(f"  {DIM}  • Журнал          ({LOG_FILE}){NC}")
        _box_row(f"  {DIM}  • iptables-цепочки (TELEMT_STATS_*){NC}")
        _box_row(f"  {DIM}  • Cron            ({CRON_FILE}){NC}")
        _box_row(f"  {DIM}  • Sysctl / limits  (99-telemt-*){NC}")
        _box_row()
        _box_warn("Это действие необратимо.")
        _box_warn("Все пользователи и ссылки будут удалены.")
        _box_row()
        _box_sep()
        _box_item("Y", f"{RED}Да, удалить полностью{NC}")
        _box_item("N", "Нет, отмена")
        _box_bot()
        print()
        ans = proto_ask(f"{CYAN}Подтверждение [y/N]: {NC}", c=True).strip().lower()
        if ans != "y":
            _info("Удаление отменено."); _pause(); return False

    _banner()
    _box_top("🗑️  УДАЛЕНИЕ TELEMT...")
    _box_row()

    _box_info("Останавливаю сервис...")
    _run(["systemctl", "stop", SERVICE_NAME])
    _run(["systemctl", "disable", SERVICE_NAME])
    _box_ok("Сервис остановлен и отключён.")

    _box_info("Удаляю iptables-правила...")
    port = _get_port()
    _run(["iptables", "-D", "INPUT",  "-p", "tcp", "--dport", str(port), "-j", CHAIN_IN])
    _run(["iptables", "-D", "OUTPUT", "-p", "tcp", "--sport", str(port), "-j", CHAIN_OUT])
    for chain in (CHAIN_IN, CHAIN_OUT):
        _run(["iptables", "-F", chain])
        _run(["iptables", "-X", chain])
    _box_ok("iptables-цепочки удалены.")

    #  миграция на port_registry (с legacy comment).
    _mtproto_ufw_close(port)

    _box_info("Удаляю файлы...")
    for t in [BIN_PATH, SERVICE_FILE, CONFIG_DIR, WORK_DIR,
              LOG_FILE, CRON_FILE, OPTIMIZER_CONF, LIMITS_CONF]:
        try:
            if t.is_dir(): shutil.rmtree(t)
            elif t.exists(): t.unlink()
        except Exception as e:
            _box_warn(f"Не удалось удалить {t}: {e}")
    _box_ok("Файлы удалены.")

    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "reset-failed"])
    _box_ok("systemd обновлён.")
    _run(["sysctl", "--system"])
    _box_ok("sysctl сброшен.")

    _box_row()
    _box_ok(f"{GREEN}{BOLD}Telemt полностью удалён с сервера.{NC}")
    _box_row(); _box_bot()

    if not silent: _pause()
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  ВЫБОР TLS-ДОМЕНА
# ══════════════════════════════════════════════════════════════════════════════
# Отметка доменов по поддержке постквантового гибридного key exchange (X25519+ML-KEM):
# без неё при insecure+pinSHA256 возможна блокировка iOS-клиентов при хендшейке.
# Списки — по данным стороннего SNI-чекера (@Sni_checker_bot, проект MEKO
# MTPROTO_FIX), нами напрямую не перепроверялись — при сомнении сверьте сами.
_PQ_RISKY = {
    "vk.com", "github.com", "habr.com", "yandex.ru", "amazon.com",
    "microsoft.com", "amazonaws.com", "mail.ru", "dzen.ru", "linkedin.com",
    "live.com", "office.com", "azure.com", "bing.com", "fastly.net",
    "netflix.com", "sharepoint.com", "skype.com", "gandi.net",
    "cloud.microsoft", "yahoo.com", "msn.com", "tiktok.com", "roblox.com",
    "spotify.com", "adobe.com", "ntp.org", "myfritz.net", "qq.com",
    "baidu.com", "nginx.org", "windows.com", "yandex.net", "tiktokv.com",
    "mozilla.org", "nic.ru", "opera.com", "samsung.com", "sentry.io",
}
_PQ_CONFIRMED = {
    "cloudflare.com", "rutube.ru", "my.aeza.ru", "wb.ru", "ozon.ru",
    "youtube.com", "apple.com", "openai.com", "anthropic.com", "meta.com",
    "facebook.com", "x.com", "wikipedia.org", "stackoverflow.com",
    "rust-lang.org", "crates.io", "docs.rs", "instagram.com", "fbcdn.net",
    "twitter.com", "googletagmanager.com", "whatsapp.net", "doubleclick.net",
    "googleusercontent.com", "appsflyersdk.com", "wordpress.org",
    "digicert.com", "youtu.be", "pinterest.com", "goo.gl", "whatsapp.com",
    "icloud.com", "googlesyndication.com", "cloudflare.net",
    "googledomains.com", "wa.me", "chatgpt.com", "vimeo.com", "zoom.us",
    "workers.dev", "cloudflare-dns.com", "wordpress.com", "reddit.com",
}

_DOMAINS: dict = {
    "1":  ("🔍 Поисковики и почта",
           ["yandex.ru", "ya.ru", "mail.ru", "rambler.ru", "maps.yandex.ru"]),
    "2":  ("🛒 Маркетплейсы",
           ["ozon.ru", "wildberries.ru", "wb.ru", "market.yandex.ru", "avito.ru"]),
    "3":  ("🎬 Онлайн-кино и ТВ",
           ["ivi.ru", "kinopoisk.ru", "okko.tv", "more.tv", "premier.one", "kion.ru"]),
    "4":  ("🎵 Музыка и подкасты",
           ["music.yandex.ru", "zvuk.com", "boom.ru", "podcasts.yandex.ru"]),
    "5":  ("🎮 Игры",
           ["vkplay.ru", "games.mail.ru", "wargaming.net", "worldoftanks.ru"]),
    "6":  ("📱 Операторы",
           ["mts.ru", "megafon.ru", "beeline.ru", "tele2.ru", "rostelecom.ru"]),
    "7":  ("🏦 Банки",
           ["sber.ru", "tbank.ru", "vtb.ru", "alfabank.ru", "raiffeisen.ru"]),
    "8":  ("🏛️  Госсервисы",
           ["gosuslugi.ru", "nalog.ru", "mos.ru", "pfr.gov.ru"]),
    "9":  ("💬 Соцсети",
           ["vk.com", "ok.ru", "odnoklassniki.ru", "tenchat.ru"]),
    "10": ("📰 Новости",
           ["ria.ru", "rbc.ru", "tass.ru", "kommersant.ru", "lenta.ru"]),
    "11": ("💻 IT",
           ["habr.com", "github.com", "selectel.ru", "timeweb.cloud", "reg.ru"]),
    "12": ("🌍 Международные",
           ["microsoft.com", "apple.com", "google.com", "cloudflare.com"]),
}

def _select_domain(telemt_port: int = 8443):
    """Возвращает выбранный домен. Бросает _Cancelled при Ctrl+C.

    Возвращаемое значение:
      • str            — donor-домен (текущее поведение: microsoft.com, ivi.ru и т.д.).
                         Caller записывает его в tls_domain без mask_host.
      • OwnSiteConfig  — own-site режим (новое): пользователь указал свой домен
                         и хочет nginx-fallback с реальным Let's Encrypt сертификатом.
                         Caller передаёт config.domain в tls_domain, а
                         config.mask_host/mask_port/tls_emulation=True — в _write_config().

    Параметр telemt_port нужен для подбора свободного mask_port (НЕ должен
    конфликтовать с портом самого Telemt). По умолчанию 8443 — стандартный
    порт Telemt; caller должен передать актуальный выбранный порт.
    """
    while True:
        _banner()
        _box_top("ВЫБОР FAKE TLS ДОМЕНА")
        _box_row()
        _box_info("Telemt маскируется под HTTPS сайта — DPI меньше подозревает.")
        _box_row(); _box_sep()
        for k, (label, _) in _DOMAINS.items():
            _box_item(k.rjust(2), label)
        _box_sep()
        _box_item("99", "✏️   Свой домен")
        _box_item(" Q", "← Назад (ivi.ru)")
        _box_bot(); print()

        cat = proto_ask(f"{CYAN}Категория: {NC}", c=True).strip()
        if cat.lower() == "q" or not cat:
            return "ivi.ru"
        if cat == "99":
            return _select_own_domain_submenu(telemt_port)
        if cat in _DOMAINS:
            label, doms = _DOMAINS[cat]
            _banner(); _box_top(label); _box_row()
            any_marked = False
            for i, d in enumerate(doms, 1):
                if d in _PQ_RISKY:
                    _box_item(str(i), f"{d}  {RED}[!]{NC}"); any_marked = True
                elif d in _PQ_CONFIRMED:
                    _box_item(str(i), f"{d}  {GREEN}✓{NC}"); any_marked = True
                else:
                    _box_item(str(i), d)
            if any_marked:
                _box_row()
                _box_row(f"  {DIM}{RED}возможен блок iOS без OpenSSL 3.5+, "
                         f"{GREEN}✓{NC}{DIM} подтверждено (не проверено нами){NC}")
            _box_sep(); _box_item("Q", "← Назад"); _box_bot(); print()
            p = proto_ask(f"{CYAN}Выбор [1-{len(doms)}]: {NC}", c=True).strip()
            if p.lower() == "q": continue
            try:
                idx = int(p) - 1
                if 0 <= idx < len(doms): return doms[idx]
            except ValueError:
                pass
            return doms[0]


def _select_own_domain_submenu(telemt_port: int):
    """Подменю 'Свой домен' — выбор между donor-режимом и own-site (nginx fallback).

    Возвращает:
      • str           — donor-режим (как было раньше): просто домен, без nginx.
      • OwnSiteConfig — own-site режим: домен + mask_host + mask_port; caller
                        поднимает nginx с Let's Encrypt сертификатом этого домена
                        и передаёт mask_* в _write_config().
    """
    _banner()
    _box_top("СВОЙ ДОМЕН — ВЫБОР РЕЖИМА")
    _box_row()
    _box_info("Donor-режим: Telemt отдаёт synthetic fake-cert (~2048 байт)")
    _box_info("и сплайсит на ЧУЖОЙ домен. Это детектируемая аномалия.")
    _box_row()
    _box_info(f"{GREEN}Own-site{NC}: Telemt сплайсит на локальный nginx с реальным")
    _box_info(f"Let's Encrypt сертификатом {GREEN}вашего{NC} домена — выглядит как")
    _box_info(f"настоящий HTTPS-сайт. Один IP, один домен, реальный сайт.")
    _box_row()
    _box_item("1", "Donor-домен (как раньше) — просто домен, без сайта")
    _box_item("2", f"{GREEN}Свой домен + свой сайт (nginx fallback){NC}  ✓ рекомендуется")
    _box_sep(); _box_item("Q", "← Назад")
    _box_bot(); print()

    mode = proto_ask(f"{CYAN}Режим [1/2] (Enter=1): {NC}", default="1", c=True).strip() or "1"

    # ── Ввод домена (общий для обоих режимов) ──────────────────────────────
    try:
        print(f"  {CYAN}Домен: {NC}", end="", flush=True)
        d = input().strip()
    except KeyboardInterrupt:
        print(); raise _Cancelled()

    if not _validate_domain(d):
        _warn(f"'{d}' не похож на домен — откат к donor-режиму с ivi.ru.")
        return "ivi.ru"
    if d in _PQ_RISKY:
        _box_warn(f"{d}: возможен блок iOS без OpenSSL 3.5+ (по стороннему тесту).")

    if mode == "2":
        # ── Own-site режим: подбор mask_port + вызов certbot/nginx_setup ───
        return _setup_own_site(d, telemt_port)

    # mode == "1" — donor-режим с пользовательским доменом (как раньше).
    return d


def _cleanup_own_site(domain: str) -> None:
    """Удаляет созданные для own-site домена файлы: nginx config, symlink, web_root.

    Используется при откате к donor-режиму: если own-site не взлетел (nginx не
    готов, certbot упал, и т.п.) — надо вернуть nginx в валидное состояние,
    иначе orphaned-файлы в NGINX_ENABLED_DIR могут ломать nginx -t.

    Сертификат Let's Encrypt НЕ удаляем — его отзыв не критичен и не тема этого фикса.
    """
    if not domain:
        return
    try:
        import importlib
        core = importlib.import_module("chimera._core")
    except ImportError:
        return

    NGINX_CONF_DIR = getattr(core, "NGINX_CONF_DIR", None)
    NGINX_ENABLED_DIR = getattr(core, "NGINX_ENABLED_DIR", None)
    _run = getattr(core, "_run", None)
    find_nginx_bin = getattr(core, "find_nginx_bin", None)
    _info = getattr(core, "info", None) or _info_local
    _warn = getattr(core, "warn", None) or _warn_local

    # 1) nginx config file
    if NGINX_CONF_DIR:
        cfg = NGINX_CONF_DIR / domain
        if cfg.exists():
            try:
                cfg.unlink()
                _info(f"Удалён nginx-конфиг: {cfg}")
            except Exception as e:
                _warn(f"Не удалось удалить {cfg}: {e}")

    # 2) nginx symlink in sites-enabled
    if NGINX_ENABLED_DIR:
        link = NGINX_ENABLED_DIR / domain
        if link.exists() or link.is_symlink():
            try:
                link.unlink()
                _info(f"Удалён nginx-симлинк: {link}")
            except Exception as e:
                _warn(f"Не удалось удалить {link}: {e}")

    # 3) web_root
    web_root = Path(f"/var/www/{domain}")
    if web_root.exists():
        try:
            import shutil
            shutil.rmtree(web_root)
            _info(f"Удалён web_root: {web_root}")
        except Exception as e:
            _warn(f"Не удалось удалить {web_root}: {e}")

    # 4) nginx -t + reload после cleanup — вернуть nginx в валидное состояние
    if _run and find_nginx_bin:
        nginx_bin = find_nginx_bin() or "/usr/sbin/nginx"
        r = _run([nginx_bin, "-t"], capture=True, check=False, quiet=True)
        if r.returncode == 0:
            _run(["systemctl", "reload", "nginx"], check=False, quiet=True)
            _info("nginx перезагружен после cleanup own-site")
        else:
            _run(["systemctl", "restart", "nginx"], check=False, quiet=True)
            _warn(f"nginx -t упал после cleanup, restart: {r.stderr}")


# Локальные fallback'и для _info/_warn если core недоступен (не должно случаться)
def _info_local(msg: str) -> None:
    print(f"  → {msg}")

def _warn_local(msg: str) -> None:
    print(f"  [!] {msg}")


def _setup_own_site(domain: str, telemt_port: int) -> OwnSiteConfig:
    """Поднимает nginx + Let's Encrypt сертификат для domain и возвращает OwnSiteConfig.

    Шаги:
      0. Проверка коллизии домена с VLESS-доменом (core.PARAM_DOMAIN).
      1. Подбирает свободный mask_port на 127.0.0.1 (НЕ == telemt_port).
      2. Спрашивает site_template (аналогично VLESS-инсталлятору).
      3. setup_nginx_temp(domain=domain) — временный HTTP:80 vhost для ACME.
         КРИТИЧНО: certbot'у нужен отвечающий HTTP:80 endpoint с
         /.well-known/acme-challenge/ — без этого vhost'а challenge уходит
         в дефолтный server и certbot получает 404 (v4.20.3 fix).
      4. obtain_ssl_cert(domain=domain) → Let's Encrypt сертификат.
      5. Self-signed detection: если сертификат self-signed (certbot упал,
         obtain_ssl_cert молча сделал generate_self_signed_cert) — откат.
         Для own-site self-signed бессмысленен: tls_emulation=true будет
         отдавать его живьём, что для DPI ХУЖЕ fake_cert_len=2048 (v4.20.3 fix).
      6. setup_nginx_final(domain=domain, port=mask_port, socket_path=None,
         protocol_mode="reality", awg_exit_enabled=False, site_template=tmpl).
      7. Проверяет, что nginx реально слушает mask_host:mask_port (TCP connect).

    При любой ошибке на этапах 3-7 вызывает _cleanup_own_site(domain) для
    удаления orphaned-файлов (nginx config, symlink, web_root) — иначе
    сломанный конфиг в NGINX_ENABLED_DIR может ронять nginx -t.

    Возвращает OwnSiteConfig с mask_port > 0 при успехе, mask_port=0 при отказе.
    """
    # 0) Проверка коллизии с VLESS-доменом — ДО любых действий.
    try:
        import importlib
        _core = importlib.import_module("chimera._core")
        _vless_domain = getattr(_core, "PARAM_DOMAIN", "")
        if _vless_domain and domain == _vless_domain:
            _err(f"Домен '{domain}' совпадает с VLESS-доменом сервера ({_vless_domain}).")
            _err("Own-site домен Telemt должен быть ОТЛИЧЕН — иначе nginx-конфиги конфликтуют.")
            return OwnSiteConfig(domain=domain, mask_host="127.0.0.1", mask_port=0)
    except ImportError:
        pass

    # 1) Подбор порта.
    mask_port = _pick_local_nginx_port(telemt_port)
    if not mask_port:
        _err(f"Не удалось подобрать свободный порт для nginx в диапазоне "
             f"{_MASK_PORT_CANDIDATES[0]}-{_MASK_PORT_CANDIDATES[-1]} "
             f"(конфликт с telemt_port={telemt_port}?). Откат к donor-режиму.")
        return OwnSiteConfig(domain=domain, mask_host="127.0.0.1", mask_port=0)
    _ok(f"Свободный порт nginx для маскировки: {mask_port}")

    # 2) Выбор шаблона сайта.
    _banner()
    _box_top("ШАБЛОН САЙТА ДЛЯ МАСКИРОВКИ")
    _box_row()
    _box_info("Nginx будет отдавать этот сайт для всех не-Telemt запросов.")
    _box_info("Шаблон можно сменить позже — файлы в /var/www/<домен>/.")
    _box_row()
    _box_item("1", "TechHub — IT-портал")
    _box_item("2", "NexCloud — облачное хранилище")
    _box_item("3", "Holm & Oak — хоумстейл")
    _box_item("4", "Ember & Grain — ресторан")
    _box_item("5", "NexHub — community + cloud")
    _box_item("6", "ByteForge — tech-форум")
    _box_sep(); _box_item("Q", "← Отмена (donor-режим)")
    _box_bot(); print()
    tmpl = proto_ask(f"{CYAN}Шаблон [1-6] (Enter=2): {NC}", default="2", c=True).strip() or "2"
    if tmpl.lower() == "q":
        _info("Откат к donor-режиму.")
        return OwnSiteConfig(domain=domain, mask_host="127.0.0.1", mask_port=0)

    # 3) Временный HTTP:80 vhost для certbot ACME challenge (v4.20.3).
    #    Без него certbot получает 404 — challenge уходит в дефолтный server,
    #    где нет /.well-known/acme-challenge/ root для Telemt-домена.
    #    obtain_ssl_cert() при этом молча падает в self-signed fallback.
    _info(f"Создаю временный HTTP:80 vhost для {domain} (certbot ACME)...")
    try:
        from chimera.modules.nginx_setup import setup_nginx_temp
        setup_nginx_temp(domain=domain)
    except Exception as _e:
        _err(f"setup_nginx_temp(domain={domain}) упал: {_e}")
        _err("Без временного vhost certbot не сможет выпустить сертификат.")
        _err("Откат к donor-режиму.")
        _cleanup_own_site(domain)
        return OwnSiteConfig(domain=domain, mask_host="127.0.0.1", mask_port=0)

    # 4) Let's Encrypt сертификат.
    _info(f"Запуск certbot для {domain}...")
    try:
        from chimera.modules.ssl_certbot import obtain_ssl_cert
        obtain_ssl_cert(domain=domain)
    except Exception as _e:
        _err(f"obtain_ssl_cert(domain={domain}) упал: {_e}")
        _err("Откат к donor-режиму — nginx-fallback без сертификата невозможен.")
        _cleanup_own_site(domain)
        return OwnSiteConfig(domain=domain, mask_host="127.0.0.1", mask_port=0)

    # 5) Self-signed detection (v4.20.3) — fail-loud для own-site.
    #    obtain_ssl_cert() имеет silent fallback на generate_self_signed_cert
    #    при провале certbot — для VLESS это осознанное поведение, но для
    #    own-site self-signed бессмысленен. _check_mask_backend_ready не ловит
    #    (TCP-connect ему всё равно, real LE или self-signed), ни один гвард
    #    v4.20.2 этот случай не покрывал. Теперь покрываем явно.
    if _is_cert_self_signed(domain):
        _err(f"Сертификат для {domain} — self-signed (certbot упал, obtain_ssl_cert")
        _err("сделал silent fallback на generate_self_signed_cert). Для own-site")
        _err("это бессмысленно: tls_emulation=true будет отдавать self-signed живьём,")
        _err("что для DPI/censor ЗАМЕТНЕЕ исходного fake_cert_len=2048.")
        _err("Откат к donor-режиму + cleanup orphaned-файлов.")
        _cleanup_own_site(domain)
        return OwnSiteConfig(domain=domain, mask_host="127.0.0.1", mask_port=0)
    _ok(f"Сертификат для {domain} — валидный LE (issuer != subject).")

    # 6) setup_nginx_final — генерирует статический HTTPS-сайт на TCP mask_port.
    #    protocol_mode="reality" + awg_exit_enabled=False — форсирует простую
    #    заглушку, независимо от VLESS-режима сервера (xhttp/reality/awg).
    #    socket_path=None (явно) → own-site TCP режим (см. _UNSET sentinel в
    #    nginx_setup.py). create_website вызывается ВНУТРИ setup_nginx_final
    #    с site_template=tmpl — НЕ вызываем отдельно (иначе двойной write).
    #    Временный vhost из шага 3 будет перезаписан финальным конфигом
    #    (HTTP:80 listener с ACME + HTTPS на mask_port).
    _info(f"Поднятие nginx-сайта {domain} на порту {mask_port}...")
    try:
        from chimera.modules.nginx_setup import setup_nginx_final
        setup_nginx_final(
            domain=domain,
            port=mask_port,
            socket_path=None,       # явно None → TCP-режим (не unix-сокет)
            protocol_mode="reality",# форсируем REALITY-ветку (не xhttp, не awg)
            awg_exit_enabled=False, # форсируем не-AWG (TLS терминирует nginx)
            site_template=tmpl,
        )
        # v4.20.8: явное логирование успеха setup_nginx_final в telemt_install.log
        # (раньше success/warn из nginx_setup.py писались в core.LOG_FILE, не в
        # telemt_install.log — мы не видели что произошло внутри setup_nginx_final).
        _ok(f"setup_nginx_final отработал для {domain}:{mask_port}")
    except Exception as _e:
        _err(f"setup_nginx_final(domain={domain}, port={mask_port}) упал: {_e}")
        _err("Откат к donor-режиму — nginx-fallback без сайта невозможен.")
        _cleanup_own_site(domain)
        return OwnSiteConfig(domain=domain, mask_host="127.0.0.1", mask_port=0)

    # v4.20.8: проверяем что конфиг реально создан и listener поднялся ДО retry.
    # Если конфига нет или listener не слушает после reload+sleep — выводим
    # диагностику (cat конфига + nginx -t stderr) чтобы понять root cause.
    try:
        import importlib
        _core_diag = importlib.import_module("chimera._core")
        _nginx_conf_path = getattr(_core_diag, "NGINX_CONF_DIR", Path("/etc/nginx/conf.d")) / domain
        _nginx_enabled_path = getattr(_core_diag, "NGINX_ENABLED_DIR", Path("/etc/nginx/sites-enabled")) / domain
        if not _nginx_conf_path.exists():
            _err(f"После setup_nginx_final конфиг НЕ создан: {_nginx_conf_path}")
            _err("Это означает что setup_nginx_final упал молча внутри (без exception).")
            _err("Откат к donor-режиму.")
            _cleanup_own_site(domain)
            return OwnSiteConfig(domain=domain, mask_host="127.0.0.1", mask_port=0)
        _ok(f"Конфиг создан: {_nginx_conf_path}")
        if not _nginx_enabled_path.exists() and not _nginx_enabled_path.is_symlink():
            _err(f"После setup_nginx_final симлинк НЕ создан: {_nginx_enabled_path}")
            _err("Возможно nginx -t упал внутри setup_nginx_final и hardening удалил symlink.")
            _err("Откат к donor-режиму.")
            _cleanup_own_site(domain)
            return OwnSiteConfig(domain=domain, mask_host="127.0.0.1", mask_port=0)
        _ok(f"Симлинк создан: {_nginx_enabled_path}")
    except Exception as _e:
        _warn(f"Диагностика конфига недоступна: {_e}")

    # 7) Проверка готовности nginx (КРИТИЧНО — см. _check_mask_backend_ready).
    #    v4.20.7: retry 3 попытки с паузами. reload nginx — async, может
    #    занять 1-3 сек чтобы поднять listener. Раньше одна попытка с
    #    timeout=3.0 — race condition, если nginx не успевал → откат в
    #    donor-режим. Теперь 3 попытки по 2 сек + диагностика при провале.
    _info(f"Проверяю, что nginx слушает 127.0.0.1:{mask_port} (3 попытки)...")
    _nginx_ready = False
    for _attempt in range(3):
        # v4.20.9: SNI = domain (НЕ 127.0.0.1) — иначе nginx отдаёт default_server
        # и TLS-handshake падает, хотя listener реально готов.
        if _check_mask_backend_ready("127.0.0.1", mask_port, timeout=3.0,
                                      sni_hostname=domain):
            _nginx_ready = True
            break
        _warn(f"Попытка {_attempt+1}/3: nginx ещё не готов на 127.0.0.1:{mask_port}, жду 2с...")
        time.sleep(2)
    if not _nginx_ready:
        _err(f"nginx НЕ слушает 127.0.0.1:{mask_port} после 3 попыток (6 сек).")
        _err("Без готового nginx tls_emulation=true приведёт к 'early eof' в Telemt.")
        # v4.20.7: диагностика — покажем что именно не так, чтобы пользователь
        # мог понять причину (конфликт портов, битый конфиг, nginx не запущен).
        # v4.20.8: ИСПРАВЛЕНО — mtproto._run не поддерживает quiet kwarg,
        # убрал quiet=True (был TypeError → диагностика не выводилась).
        _err("=== Диагностика ===")
        try:
            _ss_out = _run(["ss", "-tlnH"], capture=True, check=False)
            _ss_lines = [l for l in (_ss_out.stdout or "").splitlines() if f":{mask_port}" in l or "nginx" in l]
            _err(f"ss -tlnH (порт {mask_port} / nginx):")
            for l in (_ss_lines or ["(ничего не слушает)"]):
                _err(f"  {l}")
        except Exception as _e:
            _err(f"  ss недоступен: {_e}")
        try:
            _nt = _run(["nginx", "-t"], capture=True, check=False)
            _err(f"nginx -t: returncode={_nt.returncode}")
            for l in ((_nt.stderr or "")[-500:]).splitlines()[-5:]:
                _err(f"  {l}")
        except Exception as _e:
            _err(f"  nginx -t недоступен: {_e}")
        # v4.20.8: выводим содержимое конфига — если конфиг кривой, увидим
        try:
            import importlib
            _core_diag2 = importlib.import_module("chimera._core")
            _cfg_path = getattr(_core_diag2, "NGINX_CONF_DIR", Path("/etc/nginx/conf.d")) / domain
            if _cfg_path.exists():
                _err(f"=== Конфиг {_cfg_path} (первые 30 строк) ===")
                _cfg_text = _cfg_path.read_text()
                for l in _cfg_text.splitlines()[:30]:
                    _err(f"  {l}")
            else:
                _err(f"Конфиг {_cfg_path} НЕ существует (cleanup уже отработал?)")
        except Exception as _e:
            _err(f"  чтение конфига недоступно: {_e}")
        # v4.20.8: systemctl status nginx — если nginx в failed state
        try:
            _st = _run(["systemctl", "is-active", "nginx"], capture=True, check=False)
            _err(f"systemctl is-active nginx: {_st.stdout.strip() or '(пусто)'}")
        except Exception as _e:
            _err(f"  systemctl недоступен: {_e}")
        _err("Откат к donor-режиму + cleanup orphaned-файлов.")
        _cleanup_own_site(domain)
        return OwnSiteConfig(domain=domain, mask_host="127.0.0.1", mask_port=0)
    _ok(f"nginx готов: 127.0.0.1:{mask_port} отвечает real LE сертификатом.")

    return OwnSiteConfig(domain=domain, mask_host="127.0.0.1", mask_port=mask_port)


# ══════════════════════════════════════════════════════════════════════════════
#  МЕНЮ БЭКАПОВ ПОЛЬЗОВАТЕЛЕЙ
# ══════════════════════════════════════════════════════════════════════════════
def _menu_telemt_users_backup() -> None:
    """Просмотр и восстановление бэкапов telemt.toml."""
    while True:
        _banner()
        backups = _list_telemt_user_backups()

        _box_top("💾  БЭКАПЫ ПОЛЬЗОВАТЕЛЕЙ TELETM")
        if not backups:
            _box_row(f"  {DIM}Бэкапов нет{NC}")
            _box_row(f"  {DIM}Бэкапы создаются:{NC}")
            _box_row(f"    {DIM}• при каждом добавлении/удалении/переименовании юзера{NC}")
            _box_row(f"    {DIM}• автоматически раз в сутки (cron 03:00){NC}")
            _box_row(f"    {DIM}• хранятся последние {TELEMT_BACKUP_KEEP} бэкапов{NC}")
        else:
            _box_row(f"  {DIM}Директория: {TELEMT_BACKUP_DIR}{NC}")
            _box_row(f"  {DIM}Хранится: {len(backups)} / {TELEMT_BACKUP_KEEP} бэкапов{NC}")
            _box_sep()
            _box_row(f"  {BOLD}{'№':<4} {'Дата':<20} {'Юзеров':<8} {'Размер':<10} Причина{NC}")
            _box_row(f"  {'─'*18}  {'─'*16}  {'─'*7}  {'─'*9}  {'─'*10}")
            for i, b in enumerate(backups, 1):
                # Извлекаем reason из имени: telemt-YYYYMMDD-HHMMSS-reason.toml
                parts = b["name"].rsplit("-", 1)
                reason = parts[-1].replace(".toml", "") if len(parts) > 1 else "?"
                dt_str = b["mtime"].strftime("%Y-%m-%d %H:%M:%S")
                sz_str = f"{b['size']} Б" if b['size'] < 1024 else f"{b['size']//1024} КБ"
                _box_row(f"  {DIM}{i:<4}{NC} {dt_str:<20} {b['users']:<8} {sz_str:<10} {DIM}{reason}{NC}")
        _box_row(); _box_sep()
        _box_item("R", f"🔄  Восстановить из бэкапа")
        _box_item("B", f"💾  Создать бэкап вручную")
        _box_item("C", f"🗑️   Очистить все бэкапы")
        _box_sep(); _box_item("Q", "← Назад"); _box_bot(); print()

        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "r":
            if not backups:
                _warn("Нет бэкапов для восстановления.")
                _pause(); continue
            try:
                print(f"  {CYAN}Номер бэкапа для восстановления: {NC}", end="", flush=True)
                raw = input().strip()
            except KeyboardInterrupt:
                print(); continue
            if not raw.isdigit() or not (1 <= int(raw) <= len(backups)):
                _warn("Неверный номер."); _pause(); continue
            b = backups[int(raw) - 1]
            print(f"\n  {YELLOW}Внимание: текущий telemt.toml будет заменён на бэкап от{NC}")
            print(f"  {YELLOW}{b['mtime'].strftime('%Y-%m-%d %H:%M:%S')} ({b['users']} юзеров).{NC}")
            print(f"  {YELLOW}Перед этим текущий файл будет сохранён как бэкап 'pre-restore'.{NC}")
            try:
                print(f"  {CYAN}Продолжить? [y/N]: {NC}", end="", flush=True)
                ans = input().strip().lower()
            except KeyboardInterrupt:
                print(); continue
            if ans != "y":
                _info("Отменено."); _pause(); continue
            ok, msg = _restore_telemt_users_from_backup(b["path"])
            if ok:
                _ok(msg)
            else:
                _err(msg)
            _pause()

        elif ch == "b":
            ok = _backup_telemt_users("manual")
            if ok:
                _ok("Бэкап создан вручную.")
            else:
                _err("Не удалось создать бэкап (telemt.toml не существует?).")
            _pause()

        elif ch == "c":
            if not backups:
                _warn("Нет бэкапов для очистки."); _pause(); continue
            try:
                print(f"  {RED}Удалить ВСЕ {len(backups)} бэкапов? [y/N]: {NC}", end="", flush=True)
                ans = input().strip().lower()
            except KeyboardInterrupt:
                print(); continue
            if ans != "y":
                _info("Отменено."); _pause(); continue
            for b in backups:
                try:
                    b["path"].unlink()
                except Exception:
                    pass
            _ok(f"Удалено бэкапов: {len(backups)}")
            _pause()

        elif ch in ("q", ""):
            break


# ══════════════════════════════════════════════════════════════════════════════
#  УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ
# ══════════════════════════════════════════════════════════════════════════════
def _menu_users(server_ip: str) -> None:
    while True:
        _banner()
        users  = _load_users()
        port   = _get_port()
        domain = _get_domain()

        _box_top("УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ")
        _box_row()
        limits = _load_limits()
        from chimera.modules.awg_expires import awgs_expires_humanize
        _box_row(f"  {DIM}{'№':<4} {'Имя':<18} {'Секрет':<20} {'Квота':<14} {'Срок':<14}{NC}")
        _box_sep()
        for i, (n, s) in enumerate(users.items(), 1):
            entry = limits.get(n, {})
            quota = entry.get("quota_bytes")
            expires = entry.get("expires_at")
            if quota:
                used = _get_user_traffic_bytes(n)
                q_str = f"{_fmt_bytes_limits(used)}/{_fmt_bytes_limits(quota)}"
            else:
                q_str = f"{DIM}безлимит{NC}"
            e_str = awgs_expires_humanize(expires) if expires else f"{DIM}бессрочно{NC}"
            _box_row(f"  {DIM}{i:<4}{NC} {n:<18} {DIM}{s[:16]}…{NC} {q_str:<20} {e_str:<14}")
        _box_row(); _box_sep()
        _box_item("1", "➕  Добавить")
        _box_item("2", "➖  Удалить")
        _box_item("3", "✏️   Переименовать")
        _box_item("4", "🔗  Показать ссылки")
        _box_item("5", "⏱️   Лимиты (квота + срок)")
        _box_item("6", "💾  Бэкапы юзеров  (просмотр / восстановление)")
        _box_sep(); _box_item("Q", "← Назад"); _box_bot(); print()

        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "6":
            _menu_telemt_users_backup()
            continue

        if ch == "1":
            try:
                print(f"  {CYAN}Имя (3-16 символов): {NC}", end="", flush=True)
                n = input().strip()
            except KeyboardInterrupt:
                print(); continue
            if not _validate_username(n):
                _warn("Недопустимое имя.")
            elif n in users:
                _warn(f"'{n}' уже существует.")
            else:
                users[n] = _generate_secret()
                _save_users(users)
                _run(["systemctl", "restart", SERVICE_NAME])
                _ok(f"Добавлен '{n}'.")
            _pause()

        elif ch == "2":
            if len(users) <= 1:
                _warn("Нельзя удалить последнего.")
            else:
                try:
                    print(f"  {CYAN}Имя для удаления: {NC}", end="", flush=True)
                    n = input().strip()
                except KeyboardInterrupt:
                    print(); continue
                if n not in users:
                    _warn(f"'{n}' не найден.")
                else:
                    del users[n]
                    _save_users(users)
                    _run(["systemctl", "restart", SERVICE_NAME])
                    _ok(f"Удалён '{n}'.")
            _pause()

        elif ch == "3":
            try:
                print(f"  {CYAN}Текущее имя: {NC}", end="", flush=True)
                o = input().strip()
            except KeyboardInterrupt:
                print(); continue
            if o not in users:
                _warn(f"'{o}' не найден.")
            else:
                try:
                    print(f"  {CYAN}Новое имя: {NC}", end="", flush=True)
                    n = input().strip()
                except KeyboardInterrupt:
                    print(); continue
                if not _validate_username(n):
                    _warn("Недопустимое имя.")
                elif n in users:
                    _warn(f"'{n}' занято.")
                else:
                    users[n] = users.pop(o)
                    _save_users(users)
                    _run(["systemctl", "restart", SERVICE_NAME])
                    _ok(f"'{o}' → '{n}'.")
            _pause()

        elif ch == "4":
            print()
            if not domain or not server_ip:
                _warn("Нет данных. Выполните установку.")
            else:
                _if_mod = _get_ios_fix_module()
                _ios_st = _if_mod.status() if _if_mod is not None else {"enabled": False}
                for n, s in users.items():
                    sec  = _make_tls_secret(s, domain)
                    link = f"tg://proxy?server={server_ip}&port={port}&secret={sec}"
                    print(f"  {BOLD}{n}:{NC}")
                    print(f"  {YELLOW}{link}{NC}")
                    if _ios_st.get("enabled"):
                        ios_link = f"tg://proxy?server={server_ip}&port={_ios_st['ext_port']}&secret={sec}"
                        print(f"  {DIM}└─ iOS:{NC} {CYAN}{ios_link}{NC}")
                    print()
                from chimera.modules.box_renderer import _print_link_warning
                _print_link_warning(is_vless=False)
            _pause()

        elif ch == "5":
            _menu_limits(server_ip)

        elif ch in ("q", ""):
            break

# ══════════════════════════════════════════════════════════════════════════════
#  PER-USER ЛИМИТЫ (квота трафика + срок действия)
# ══════════════════════════════════════════════════════════════════════════════

def _load_limits() -> dict:
    """Загружает per-user лимиты из JSON.
    
    Формат: {username: {"quota_bytes": int|None, "expires_at": str|None,
                        "max_connections": int|None}}
    """
    if not LIMITS_FILE.exists():
        return {}
    try:
        return json.loads(LIMITS_FILE.read_text())
    except Exception:
        return {}


def _save_limits(limits: dict) -> None:
    """Сохраняет per-user лимиты в JSON."""
    LIMITS_FILE.parent.mkdir(parents=True, exist_ok=True)
    LIMITS_FILE.write_text(json.dumps(limits, ensure_ascii=False, indent=2))
    LIMITS_FILE.chmod(0o640)


def _get_user_traffic_bytes(username: str) -> int:
    """Возвращает накопленный трафик пользователя (rx+tx) из mtproto_stats.
    
    Переиспользует mtproto_stats._load_stats() — там per-user данные
    распределяются пропорционально от агрегатных iptables-счётчиков.
    """
    try:
        from chimera.modules.mtproto_stats import _load_stats
        stats = _load_stats()
        u = stats.get("users", {}).get(username, {})
        return int(u.get("rx", 0)) + int(u.get("tx", 0))
    except Exception:
        return 0


def mtproto_set_limits(username: str,
                       quota: Optional[str] = None,
                       expires_in: Optional[str] = None,
                       max_connections: Optional[int] = None
                       ) -> bool:
    """Устанавливает per-user лимиты для существующего Telemt-пользователя.
    
    Args:
      username: имя пользователя (должно существовать в telemt.toml)
      quota: строка вида "10G" / "500MB" / "1.5GiB" — парсится через
             traffic_accounting.parse_human_readable_bytes.
             None или пустая строка = безлимит.
      expires_in: строка вида "30d" / "6m" / "12h" — парсится через
                  awgs_expires_parse + awgs_expires_compute_iso.
                  None или пустая строка = бессрочно.
      max_connections: НЕ ПОДДЕРЖИВАЕТСЯ бинарником telemt — принимается
                       для API-совместимости, записывается в JSON, но
                       НЕ применяется к бинарнику. Документировано в TUI.
    
    Возвращает True если лимиты установлены.
    """
    # Проверяем что пользователь существует.
    users = _load_users()
    if username not in users:
        return False
    
    limits = _load_limits()
    entry = limits.get(username, {})
    
    # Квота трафика.
    if quota and quota.strip():
        try:
            from chimera.modules.traffic_accounting import parse_human_readable_bytes
            entry["quota_bytes"] = parse_human_readable_bytes(quota)
        except Exception:
            return False
    else:
        entry["quota_bytes"] = None
    
    # Срок действия.
    if expires_in and expires_in.strip():
        from chimera.modules.awg_expires import (
            awgs_expires_parse, awgs_expires_compute_iso,
        )
        delta = awgs_expires_parse(expires_in)
        if delta is None:
            return False
        entry["expires_at"] = awgs_expires_compute_iso(delta)
    else:
        entry["expires_at"] = None
    
    # max_connections — записываем, но не применяем (telemt не поддерживает).
    entry["max_connections"] = max_connections
    
    limits[username] = entry
    _save_limits(limits)
    return True


def mtproto_get_limits(username: str) -> dict:
    """Возвращает лимиты пользователя.
    
    Формат: {"quota_bytes": int|None, "expires_at": str|None,
             "max_connections": int|None, "used_bytes": int}
    """
    limits = _load_limits()
    entry = limits.get(username, {})
    return {
        "quota_bytes": entry.get("quota_bytes"),
        "expires_at": entry.get("expires_at"),
        "max_connections": entry.get("max_connections"),
        "used_bytes": _get_user_traffic_bytes(username),
    }


def mtproto_remove_limits(username: str) -> bool:
    """Удаляет лимиты пользователя (делает безлимитным)."""
    limits = _load_limits()
    if username in limits:
        del limits[username]
        _save_limits(limits)
        return True
    return False


def mtproto_check_limits() -> dict:
    """Периодическая проверка лимитов всех пользователей.
    
    Удаляет пользователей, у которых:
      - истёк срок действия (expires_at)
      - превышена квота трафика (used_bytes >= quota_bytes)
    
    Возвращает {"expired": N, "quota_exceeded": N} для вывода в TUI.
    """
    from chimera.modules.awg_expires import awgs_expires_is_expired, awgs_expires_humanize
    
    limits = _load_limits()
    if not limits:
        return {"expired": 0, "quota_exceeded": 0}
    
    users = _load_users()
    expired_count = 0
    quota_exceeded_count = 0
    to_remove = []
    
    for username, entry in limits.items():
        if username not in users:
            # Пользователь уже удалён — чистим лимит.
            to_remove.append(username)
            continue
        
        # Проверка срока действия.
        expires_at = entry.get("expires_at")
        if expires_at and awgs_expires_is_expired(expires_at):
            to_remove.append(username)
            expired_count += 1
            try:
                _log_telemt(f"LIMIT: пользователь '{username}' истёк "
                            f"({awgs_expires_humanize(expires_at)}) — удаляю")
            except Exception:
                pass
            continue
        
        # Проверка квоты трафика.
        quota_bytes = entry.get("quota_bytes")
        if quota_bytes and quota_bytes > 0:
            used = _get_user_traffic_bytes(username)
            if used >= quota_bytes:
                to_remove.append(username)
                quota_exceeded_count += 1
                try:
                    _log_telemt(f"LIMIT: пользователь '{username}' превысил квоту "
                                f"({used} >= {quota_bytes}) — удаляю")
                except Exception:
                    pass
                continue
    
    # Удаляем пользователей.
    for username in to_remove:
        # Чистим лимит.
        if username in limits:
            del limits[username]
        # Удаляем пользователя из telemt.toml (если ещё там).
        users = _load_users()
        if username in users:
            if len(users) > 1:
                del users[username]
                _save_users(users)
            else:
                # Нельзя удалить последнего — только чистим лимит.
                try:
                    _log_telemt(f"LIMIT: не могу удалить последнего "
                                f"пользователя '{username}'")
                except Exception:
                    pass
    
    _save_limits(limits)
    
    # Рестарт сервиса если были изменения.
    if to_remove:
        _run(["systemctl", "restart", SERVICE_NAME], check=False, quiet=True)
    
    return {"expired": expired_count, "quota_exceeded": quota_exceeded_count}


def _log_telemt(msg: str) -> None:
    """Записывает сообщение в лог Telemt."""
    try:
        from chimera._core import log_to_file
        log_to_file("INFO", f"telemt: {msg}")
    except Exception:
        pass


def _menu_limits(server_ip: str) -> None:
    """TUI-меню управления per-user лимитами."""
    while True:
        _banner()
        users = _load_users()
        limits = _load_limits()
        
        _box_top("⏱️   ЛИМИТЫ ПОЛЬЗОВАТЕЛЕЙ  •  TELETMT")
        _box_row()
        if not users:
            _box_row(f"  {DIM}Нет пользователей{NC}")
        else:
            _box_row(f"  {DIM}{'Имя':<18} {'Квота':<14} {'Срок':<16} {'Трафик':<14}{NC}")
            _box_sep()
            from chimera.modules.awg_expires import awgs_expires_humanize
            for n in users:
                entry = limits.get(n, {})
                quota = entry.get("quota_bytes")
                expires = entry.get("expires_at")
                used = _get_user_traffic_bytes(n)
                
                if quota:
                    q_str = f"{used / quota * 100:.0f}% ({_fmt_bytes_limits(used)}/{_fmt_bytes_limits(quota)})"
                    if used >= quota:
                        q_str = f"{RED}{q_str}{NC}"
                else:
                    q_str = f"{DIM}безлимит{NC}"
                
                e_str = awgs_expires_humanize(expires) if expires else f"{DIM}бессрочно{NC}"
                u_str = _fmt_bytes_limits(used)
                
                _box_row(f"  {n:<18} {q_str:<30} {e_str:<16} {u_str:<14}")
        _box_row(); _box_sep()
        _box_item("1", "⏱️   Задать лимиты пользователю")
        _box_item("2", "🗑️   Снять лимиты (безлимит)")
        _box_item("Q", "← Назад")
        _box_bot(); print()
        
        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break
        
        if ch == "1":
            try:
                print(f"  {CYAN}Имя пользователя: {NC}", end="", flush=True)
                uname = input().strip()
            except KeyboardInterrupt:
                print(); continue
            if uname not in users:
                _warn(f"'{uname}' не найден."); _pause(); continue
            
            # Квота
            try:
                print(f"  {CYAN}Квота трафика (10G, 500MB, пусто=безлимит): {NC}", end="", flush=True)
                quota_str = input().strip()
            except KeyboardInterrupt:
                print(); continue
            
            # Срок
            try:
                print(f"  {CYAN}Срок действия (30d, 6m, 12h, пусто=бессрочно): {NC}", end="", flush=True)
                expires_str = input().strip()
            except KeyboardInterrupt:
                print(); continue
            
            # max_connections — информируем что не поддерживается
            _info("max_connections: бинарник telemt не поддерживает — пропуск.")
            
            if mtproto_set_limits(uname, quota_str or None, expires_str or None):
                _ok(f"Лимиты установлены для '{uname}'.")
            else:
                _warn("Не удалось установить лимиты — проверьте формат.")
            _pause()
        
        elif ch == "2":
            try:
                print(f"  {CYAN}Имя пользователя: {NC}", end="", flush=True)
                uname = input().strip()
            except KeyboardInterrupt:
                print(); continue
            if mtproto_remove_limits(uname):
                _ok(f"Лимиты сняты для '{uname}' (безлимит).")
            else:
                _warn(f"Лимиты не были установлены для '{uname}'.")
            _pause()
        
        elif ch in ("q", ""):
            break


def _fmt_bytes_limits(b: int) -> str:
    """Форматирует байты для отображения в меню лимитов.
    
    Переиспользует существующую _fmt_bytes (строка 504) если доступна.
    """
    # _fmt_bytes определена выше в этом же модуле — Python найдёт её.
    return _fmt_bytes(b)
# ══════════════════════════════════════════════════════════════════════════════
def _menu_update() -> None:
    _info("Проверяю обновления...")
    cur = _get_installed_version()
    tag, urls = _get_latest_release()
    if not urls:
        _warn("Не удалось получить зеркала. Проверьте соединение."); _pause(); return
    # tag всегда "latest" после миграции (api.github.com убран).
    # Показываем "последней версии" вместо "latest" для человекочитаемости.
    display_tag = "последней версии" if tag == "latest" else tag
    print()
    _ok(f"Установлена:  {cur or '—'}")
    _ok(f"Последняя:    {display_tag}")
    if cur and display_tag != "последней версии" and cur == display_tag:
        print(); _info("Уже последняя версия."); _pause(); return
    print()
    if proto_ask(f"  {CYAN}Обновить до {display_tag}? [y/N]: {NC}", c=True).strip().lower() != "y":
        return
    _run(["systemctl", "stop", SERVICE_NAME])
    if _install_binary(urls):
        _run(["systemctl", "start", SERVICE_NAME])
        _ok(f"Обновлено до {display_tag}.")
    else:
        _err("Обновление не удалось.")
        # Показываем инструкцию для ручного скачивания (WinSCP-friendly)
        _print_telemt_manual_hint("telemt")
        try:
            ans = input(f"  {CYAN}Разместили файлы вручную? Повторить? [Y/n]: {NC}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans != "n":
            if _install_binary(urls):
                _run(["systemctl", "start", SERVICE_NAME])
                _ok(f"Обновлено до {display_tag} (из ручного размещения).")
            else:
                _err("Файлы не найдены в /root/ и других путях.")
        _run(["systemctl", "start", SERVICE_NAME])
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ПОЛНАЯ УСТАНОВКА
# ══════════════════════════════════════════════════════════════════════════════
def _run_install(server_ip: str, server_ipv6: str) -> None:
    """Обёртка: перехватывает _Cancelled и возвращает в меню."""
    try:
        _run_install_inner(server_ip, server_ipv6)
    except _Cancelled:
        print(f"\n  {YELLOW}Установка прервана — возврат в меню.{NC}\n")
        _pause()

def _run_install_inner(server_ip: str, server_ipv6: str) -> None:
    # ── Если уже установлено ──────────────────────────────────────────────────
    already_installed = (
        BIN_PATH.exists() or CONFIG_FILE.exists() or
        SERVICE_FILE.exists() or WORK_DIR.exists()
    )
    if already_installed:
        _banner()
        _box_top("ПЕРЕУСТАНОВКА  •  TELEMT")
        _box_row()
        _box_warn("Обнаружена существующая установка Telemt.")
        _box_row()
        _box_info("Выберите режим переустановки:")
        _box_row()
        _box_item("1", f"🗑️   Полная очистка + установка с нуля  {YELLOW}(рекомендуется){NC}")
        _box_item("2", "♻️   Переустановить поверх  (конфиг и данные сохраняются)")
        _box_item("0", "← Отмена  (Ctrl+C)")
        _box_bot(); print()
        ch = proto_ask(f"{CYAN}Выбор [1/2/0]: {NC}", c=True).strip()
        if ch in ("0", "Q", "q", ""): return
        if ch == "1":
            if not _full_uninstall(silent=True): return
            print()

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.write_text(f"=== Telemt Install {_now_str()} ===\n")

    # ── Сеть ──────────────────────────────────────────────────────────────────
    _banner(); _box_top("НАСТРОЙКА СЕТИ"); _box_row()
    _box_item("1", "IPv4 только")
    _box_item("2", "IPv6 только")
    _box_item("3", "DualStack IPv4+IPv6  ✓ рекомендуется")
    _box_row(); _box_sep()
    _box_item("A", "Порт 443")
    _box_item("B", "Порт 8443  ✓ рекомендуется")
    _box_item("C", "Свой порт...")
    _box_bot(); print()

    # v4.20.6: валидация ввода протокола. Раньше при вводе "q"/"0"/пусто/любой
    # другой символ оба флага (ipv4, ipv6) становились False → в telemt.toml
    # писалось "ipv4 = false\nipv6 = false" → Telemt падал с
    # "Config error: Both ipv4 and ipv6 are disabled in [network]".
    # Теперь переспрашиваем пока не будет валидный ввод.
    ipv4 = False
    ipv6 = False
    while True:
        proto = proto_ask(f"{CYAN}Протокол [1-3] (Enter=3): {NC}", default="3", c=True).strip() or "3"
        if proto in ("1", "2", "3"):
            ipv4 = proto in ("1", "3")
            ipv6 = proto in ("2", "3")
            break
        _warn(f"'{proto}' — недопустимый выбор. Введите 1, 2 или 3 (или Enter для 3).")

    # v4.20.6: аналогичная валидация для порта (A/B/C).
    port = 8443
    while True:
        pc = proto_ask(f"{CYAN}Порт [A/B/C] (Enter=B): {NC}", default="B", c=True).strip().upper() or "B"
        if pc == "A":
            port = 443
            break
        elif pc == "B":
            port = 8443
            break
        elif pc == "C":
            try:
                print(f"  {CYAN}Порт (1024-65535): {NC}", end="", flush=True)
                port = int(input())
                if 1024 <= port <= 65535:
                    break
                _warn(f"Порт {port} вне диапазона 1024-65535.")
            except ValueError:
                _warn("Нужно число.")
            except KeyboardInterrupt:
                print(); raise _Cancelled()
        else:
            _warn(f"'{pc}' — недопустимый выбор. Введите A, B или C (или Enter для B).")

    # ── Выбор fake-TLS домена ──────────────────────────────────────────────
    # Возвращает str (donor-домен) ИЛИ OwnSiteConfig (свой домен + nginx
    # fallback с реальным Let's Encrypt сертификатом). В последнем случае
    # _select_domain уже успел запустить certbot и поднять nginx на
    # mask_port — осталось только передать mask_* в _write_config и
    # проверить готовность nginx перед стартом Telemt.
    _domain_choice = _select_domain(telemt_port=port)
    if isinstance(_domain_choice, OwnSiteConfig):
        tls_domain = _domain_choice.domain
        _mask_host = _domain_choice.mask_host if _domain_choice.mask_port > 0 else ""
        _mask_port = _domain_choice.mask_port
        _tls_emulation = _domain_choice.mask_port > 0
    else:
        tls_domain = _domain_choice
        _mask_host = ""
        _mask_port = 0
        _tls_emulation = False

    # ── MSS-фрагментация против TSPU JA4 DPI ─────────────────────────────────
    # Шаг обязателен при сервере в РФ; safe skip для прочих регионов.
    # Модуль telemt_mss_selector изолирован — ошибка импорта не ломает установку.
    _client_mss = ""
    _client_mss_bulk = ""
    _mss_mod = _get_mss_module()
    if _mss_mod is not None:
        try:
            _client_mss = _mss_mod.mss_select_interactive()
        except Exception as _me:
            _warn(f"Шаг MSS пропущен: {_me}")
            _client_mss = ""
        # ── Bulk-MSS (двухуровневый режим) ───────────────────────────────────
        # Показываем только если выбран ненулевой handshake-MSS. Иначе нет
        # смысла — bulk без handshake-MSS не имеет эффекта (Telemt-спецификация).
        if _client_mss and _mss_mod is not None:
            try:
                _client_mss_bulk = _mss_mod.mss_bulk_select_interactive(_client_mss)
            except Exception as _me:
                _warn(f"Шаг bulk-MSS пропущен: {_me}")
                _client_mss_bulk = ""
    # ── Регион сервера: РФ / страна с блокировкой Telegram ─────────────────
    # _is_direct_ip() возвращает True если IP напрямую на интерфейсе (не NAT).
    # Это не означает доступность ME-серверов: в РФ они заблокированы.
    # Явный вопрос позволяет сразу ставить use_middle_proxy=false и
    # избежать варнингов "All ME servers for DC failed" в логах.
    _direct_ip = _is_direct_ip(server_ip)
    _banner()
    _box_top("РЕГИОН СЕРВЕРА")
    _box_row()
    _box_info("Telegram заблокирован в РФ и ряде других стран.")
    _box_info("В таком регионе Middle Proxy недоступен — нужен Direct Mode.")
    _box_row()
    _box_item("Y", f"Да, сервер в РФ / регионе с блокировкой  {GREEN}(Direct Mode){NC}")
    _box_item("N", f"Нет, Telegram доступен напрямую  {DIM}(Middle Proxy){NC}")
    _box_bot(); print()
    _region_blocked = proto_ask(
        f"{CYAN}Telegram заблокирован на этом сервере? [Y/n]: {NC}",
        default="y", c=True,
    ).strip().lower()
    # При блокировке — принудительно Direct; иначе — автоопределение по IP
    use_mp = False if _region_blocked in ("y", "") else _direct_ip

    # ── Настройка гибридного fallback (Middle Proxy → Direct) ────────────────
    # Шаг показывается только если use_mp=True (Middle Proxy актуален).
    # При use_mp=False сервер за NAT — Middle Proxy уже отключён, fallback не нужен.
    _fb_cfg = None
    if use_mp:
        _fb_mod = _get_fallback_module()
        if _fb_mod is not None:
            try:
                _banner()
                _box_top("HYBRID FALLBACK  •  MIDDLE PROXY → DIRECT")
                _box_row()
                _box_info("Telemt может автоматически переключаться в Direct Mode")
                _box_info("при деградации ME-серверов Telegram.")
                _box_row()
                _box_info("Переключение затрагивает только транспорт до Telegram DC.")
                _box_info("Порты, iptables и xray-интеграция не изменяются.")
                _box_row()
                _box_item("Y", f"Настроить fallback  {GREEN}(рекомендуется){NC}")
                _box_item("N", f"Пропустить (всегда Middle Proxy)")
                _box_bot(); print()
                _fb_ans = proto_ask(
                    f"{CYAN}Настроить hybrid fallback? [Y/n]: {NC}",
                    default="y", c=True,
                ).strip().lower()
                if _fb_ans in ("y", ""):
                    _fb_cfg = _fb_mod.me_probe_menu(CONFIG_FILE)
                else:
                    # Создаём конфиг с дефолтами (fallback разрешён, но без интерактива)
                    _fb_cfg = _fb_mod.FallbackConfig.defaults()
            except Exception as _fe:
                _warn(f"Модуль fallback недоступен: {_fe}")
                _fb_cfg = None

    # ── Xray tproxy-интеграция (dokodemo + iptables REDIRECT) ────────────────
    # Работает для VLESS-цепочек и AWG 2.0 — транспорт прозрачен для схемы.
    _xs       = _xray_tproxy_status()
    _cascade  = _xs["cascade"]
    _tproxy_already = _xs["enabled"]

    _banner()
    _box_top("ИНТЕГРАЦИЯ С XRAY (ОБХОД БЛОКИРОВКИ)")
    _box_row()
    if _cascade == "none":
        _box_warn("xray не обнаружен в режиме каскада (Режим B).")
        _box_info("Telemt будет работать в режиме direct — Telegram недоступен из РФ.")
        _box_info("Сначала установите xray в Режиме B, затем переустановите Telemt.")
    else:
        _cascade_label = "AWG 2.0" if _cascade == "awg" else "VLESS"
        _box_ok(f"Обнаружен xray-каскад: {_cascade_label}")
        _box_info(f"Схема: Telemt → iptables REDIRECT → dokodemo :{XRAY_TPROXY_PORT} → xray → exit VPS → Telegram")
        if _tproxy_already:
            ipt_str = f"{_xs['ipt_count']}/{_xs.get('ipt_total', len(_TG_NETS_current()))} подсетей"
            _box_ok(f"tproxy уже настроен (порт {_xs['port']}, iptables: {ipt_str})")
        _box_row()
        _box_item("Y", f"Направить трафик Telemt через xray ({_cascade_label})  ✓ рекомендуется")
        _box_item("N", "Прямое подключение (direct) — Telegram будет заблокирован в РФ")
    _box_bot()
    print()

    _use_tproxy = False
    if _cascade != "none":
        _use_xray = proto_ask(
            f"{CYAN}Использовать xray для проксирования? [Y/n]: {NC}",
            default="y", c=True,
        ).strip().lower()
        _use_tproxy = _use_xray in ("y", "")

    # ── Пользователи ─────────────────────────────────────────────────────────
    _banner(); _box_top("ПОЛЬЗОВАТЕЛИ"); _box_row()
    _box_info("Введите имя первого пользователя (Enter = user1).")
    _box_info("Допустимо: латиница, цифры, _ и - ; длина 3-16.")
    _box_info("Ctrl+C — отмена.")
    _box_bot(); print()
    while True:
        first_name = proto_ask(f"  {CYAN}Имя первого пользователя: {NC}", c=True).strip()
        if not first_name:
            first_name = "user1"; break
        if _validate_username(first_name): break
        _warn("Недопустимое имя. Попробуйте ещё раз.")
    users: dict = {first_name: _generate_secret()}
    _ok(f"Пользователь: {first_name}")
    print()
    while True:
        ans = proto_ask(f"  {CYAN}Добавить ещё пользователя? [y/N]: {NC}", c=True).strip().lower()
        if ans != "y": break
        try:
            print(f"  {CYAN}Имя (3-16): {NC}", end="", flush=True)
            n = input().strip()
        except KeyboardInterrupt:
            print(); raise _Cancelled()
        if _validate_username(n) and n not in users:
            users[n] = _generate_secret(); _ok(f"Добавлен: {n}")
        else:
            _warn("Недопустимое имя или уже есть.")

    # ── Установка ─────────────────────────────────────────────────────────────
    print()
    _info("Останавливаю старую установку...")
    _run(["systemctl", "stop", SERVICE_NAME])
    time.sleep(1)

    _info("Генерирую конфиг...")
    # telemt всегда в режиме direct — xray перехватывается на уровне iptables REDIRECT.
    # use_middle_proxy=True несовместим с каскадом: ME-серверы на :8888 попадают под REDIRECT.
    # Всегда передаём False независимо от ответа пользователя.
    # _mask_host/_mask_port/_tls_emulation — пустые для donor-режима (поведение
    # идентично предыдущему), заполненные для own-site режима (см. _select_domain).
    _write_config(port, ipv4, ipv6, tls_domain, users, False, socks5_port=0,
                  fallback_cfg=_fb_cfg, client_mss=_client_mss,
                  client_mss_bulk=_client_mss_bulk,
                  mask_host=_mask_host, mask_port=_mask_port,
                  tls_emulation=_tls_emulation)
    _ok(f"Конфиг: {CONFIG_FILE}")

    _info("Устанавливаю зависимости...")
    _run(["apt-get", "install", "-y", "-q",
          "curl", "wget", "ca-certificates", "openssl", "iproute2", "procps", "iptables"])

    _info("Получаю последнюю версию telemt...")
    tag, urls = _get_latest_release()
    if not urls:
        _err("Не удалось получить зеркала. Проверьте соединение."); _pause(); return
    # tag всегда "latest" после миграции (api.github.com убран).
    display_tag = "последней версии" if tag == "latest" else tag
    _info(f"Скачиваю telemt {display_tag}...")
    if not _install_binary(urls):
        # Показываем инструкцию для ручного скачивания (WinSCP-friendly)
        _print_telemt_manual_hint("telemt")
        try:
            ans = input(f"  {CYAN}Разместили файлы вручную? Повторить установку? [Y/n]: {NC}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans != "n":
            # Повторная попытка — _install_binary найдёт файл в /root/ через
            # fetch_package(manual_incoming_dir=/root/).
            if not _install_binary(urls):
                _err(f"Файлы не найдены в {', '.join(str(p) for p in _TELEMT_MANUAL_PATHS)}.")
                _pause(); return
        else:
            _pause(); return

    _info("Оптимизация ядра...")
    _apply_optimizations()

    _info("Установка systemd-сервиса...")
    _install_service()
    _setup_ufw(port)

    # ── Xray: dokodemo-door + iptables REDIRECT ───────────────────────────────
    tproxy_ok_msg = ""
    if _use_tproxy:
        _info("Настраиваю tproxy-интеграцию (dokodemo + iptables REDIRECT)...")
        _ok_tp, _msg_tp = xray_enable_tproxy_for_telemt(XRAY_TPROXY_PORT)
        if _ok_tp:
            _ok(_msg_tp)
            tproxy_ok_msg = _msg_tp
        else:
            _warn(f"Не удалось настроить tproxy: {_msg_tp}")
            _warn("Telemt будет работать в режиме direct (Telegram может быть заблокирован).")

    _info("Настройка учёта трафика (iptables)...")
    ipt_ok = _setup_accounting(port)
    if ipt_ok:
        _ok("Учёт трафика активирован.")
    else:
        _warn("Учёт трафика (iptables) НЕ настроен — traffic-квоты и "
              "статистика работать не будут. Включить вручную: меню Telemt "
              "→ Статистика → пункт 3.")

    # ── КРИТИЧНЫЙ GUARD: nginx готов ДО старта Telemt? ──────────────────────
    # Если включён own-site режим (tls_emulation=true), Telemt при старте
    # делает живой TLS-fetch cert-chain с mask_host:mask_port. Если nginx
    # ещё не слушает — fetch падает с "early eof" и Telemt уходит в
    # restart-loop (telemt/telemt issues #330, #713). Это будет silent
    # regression в духе AWG rotation no-op, поэтому проверяем явно.
    #
    # В donor-режиме (_mask_host="") guard пропускается — там нет
    # живого TLS-fetch, Telemt использует synthetic fake-cert.
    if _mask_host and _mask_port:
        _info(f"Проверка готовности nginx { _mask_host}:{_mask_port} перед стартом Telemt...")
        _nginx_ready = False
        for _attempt in range(5):
            if _check_mask_backend_ready(_mask_host, _mask_port, timeout=2.0):
                _nginx_ready = True
                break
            time.sleep(1)
        if not _nginx_ready:
            _err(f"nginx НЕ слушает {_mask_host}:{_mask_port} после 5 попыток.")
            _err("tls_emulation=true без готового nginx приведёт к 'early eof' в Telemt")
            _err("(telemt/telemt issues #330, #713). Отключаю own-site режим.")
            # Откатываемся к donor-режиму: переписываем конфиг без mask_host.
            # tls_domain остаётся тем же — это домен, к которому привязан
            # certbot-сертификат; Telemt просто использует synthetic fake-cert
            # вместо живого TLS-fetch.
            # ALSO: cleanup orphaned nginx-файлов (config, symlink, web_root),
            # иначе сломанный конфиг в NGINX_ENABLED_DIR может ронять nginx -t
            # и ломать уже работавший VLESS REALITY fallback.
            _cleanup_own_site(tls_domain)
            _mask_host = ""
            _mask_port = 0
            _tls_emulation = False
            _write_config(port, ipv4, ipv6, tls_domain, users, False, socks5_port=0,
                          fallback_cfg=_fb_cfg, client_mss=_client_mss,
                          client_mss_bulk=_client_mss_bulk,
                          mask_host="", mask_port=0, tls_emulation=False)
            _warn(f"Конфиг переписан в donor-режим: {CONFIG_FILE}")
        else:
            _ok(f"nginx готов: {_mask_host}:{_mask_port} отвечает — tls_emulation безопасен.")

    _info("Запуск telemt...")
    _run(["systemctl", "start", SERVICE_NAME])

    waited = 0
    while waited < 40:
        if f":{port}" in _run(["ss", "-tln"], capture=True).stdout:
            _ok(f"Порт {port} слушается ({waited}с)"); break
        time.sleep(2); waited += 2
    else:
        _warn(f"Порт не открылся за 40с — journalctl -u telemt -n 30")

    # ── Post-install: проверка ME-серверов и автоматический fallback ──────────
    # Выполняется только при use_mp=True и если fallback настроен.
    # Не блокирует установку при ошибке — предупреждает и продолжает.
    _fallback_triggered = False
    _fallback_msg = ""
    if use_mp and _fb_cfg is not None and getattr(_fb_cfg, "fallback_to_direct", False):
        _fb_mod = _get_fallback_module()
        if _fb_mod is not None:
            _info("Проверяю доступность ME-серверов (Telegram Middle Proxy)...")
            try:
                _fb_result = _fb_mod.run_post_install_fallback_check(
                    config_file=CONFIG_FILE,
                    service=SERVICE_NAME,
                    warmup_wait=8,
                )
                if _fb_result:
                    # Fallback сработал
                    _warn("Middle Proxy недоступен — активирован Direct Mode.")
                    _warn("Конфиг обновлён автоматически (telemt.toml не перезаписан).")
                    _fallback_triggered = True
                    _fallback_msg = _fb_result
                else:
                    _ok("Middle Proxy доступен — работаем в режиме Middle Proxy.")
            except Exception as _fe:
                _warn(f"Проверка ME-серверов не удалась: {_fe}")
    _banner(); _box_top("✅ УСТАНОВКА ЗАВЕРШЕНА"); _box_row()
    _box_ok(f"Версия:  telemt {tag}")
    _box_ok(f"Порт:    {port}")
    _box_ok(f"Домен:   {tls_domain}")
    _box_ok(f"IPv4:    {server_ip or '—'}")
    if server_ipv6: _box_ok(f"IPv6:    {server_ipv6}")
    if use_mp and not _fallback_triggered:
        _box_ok(f"Middle:  да (активен)")
    elif use_mp and _fallback_triggered:
        _box_warn(f"Middle:  отказ → Direct Mode (ME-серверы недоступны)")
    else:
        _box_ok(f"Middle:  нет (NAT / Direct)")
    # Статус fallback-настройки
    if _fb_cfg is not None:
        _fb_status = (
            f"включён (попыток: {_fb_cfg.fallback_after_attempts}, "
            f"timeout: {_fb_cfg.fallback_after_seconds}s)"
        )
        _box_ok(f"Fallback: {_fb_status}")
    _box_ok(f"Учёт:    {'активен (iptables)' if ipt_ok else 'journalctl'}")
    if _use_tproxy and tproxy_ok_msg:
        _cascade_label = "AWG 2.0" if _cascade == "awg" else "VLESS"
        _box_ok(f"Xray:    dokodemo :{XRAY_TPROXY_PORT} + iptables REDIRECT → {_cascade_label} ✓")
    else:
        _box_warn("Xray:    не используется (direct — Telegram может быть заблокирован)")
    # MSS anti-JA4 статус
    _mss_mod_summary = _get_mss_module()
    if _mss_mod_summary is not None:
        _box_ok(f"MSS:     {_mss_mod_summary.mss_status_line(_client_mss)}")
        if _client_mss_bulk:
            _box_ok(f"Bulk:    {_mss_mod_summary.mss_bulk_status_line(_client_mss_bulk, _client_mss)}")
    elif _client_mss:
        _box_ok(f"MSS:     {_client_mss}")
        if _client_mss_bulk:
            _box_ok(f"Bulk:    {_client_mss_bulk}")
    _box_row(); _box_sep()
    _box_row(f"  {DIM}journalctl -u telemt -f   # логи{NC}")
    _box_bot()
    print()
    print(f"  {BOLD}{CYAN}🔗 Ссылки для Telegram:{NC}")
    print()
    _if_mod = _get_ios_fix_module()
    _ios_st = _if_mod.status() if _if_mod is not None else {"enabled": False}
    for n, s in users.items():
        sec  = _make_tls_secret(s, tls_domain)
        link = f"tg://proxy?server={server_ip}&port={port}&secret={sec}"
        print(f"  {BOLD}{WHITE}{n}:{NC}")
        print(f"  {YELLOW}{link}{NC}")
        if _ios_st.get("enabled"):
            ios_link = f"tg://proxy?server={server_ip}&port={_ios_st['ext_port']}&secret={sec}"
            print(f"  {DIM}└─ iOS:{NC} {CYAN}{ios_link}{NC}")
        print()
    from chimera.modules.box_renderer import _print_link_warning
    _print_link_warning(is_vless=False)
    #  FIX: устанавливаем ежедневный cron-бэкап telemt.toml —
    # защита от потери юзеров при сбое или (пере)установке.
    try:
        if _install_telemt_users_backup_cron():
            _ok("Ежедневный бэкап юзеров Telemt активирован (cron 03:00)")
        else:
            _warn("Не удалось установить cron-бэкап юзеров Telemt")
    except Exception:
        pass
    # Создаём первый snapshot сразу — на случай если cron не отработает
    # до следующего инцидента.
    try:
        _backup_telemt_users("install")
    except Exception:
        pass
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ПОДМЕНЮ: XRAY SOCKS5-ИНТЕГРАЦИЯ
# ══════════════════════════════════════════════════════════════════════════════

def _menu_xray_integration() -> None:
    """
    Управление tproxy-интеграцией: dokodemo-door + iptables REDIRECT.
    Поддерживает VLESS+REALITY и AWG 2.0 без изменений логики.
    """
    while True:
        _banner()
        xs      = _xray_tproxy_status()
        cascade = xs["cascade"]
        enabled = xs["enabled"]

        _box_top("XRAY ИНТЕГРАЦИЯ  •  TELEMT → XRAY → EXIT VPS")
        _box_row()

        if cascade == "none":
            _box_err("xray-каскад (Режим B) не обнаружен на этом сервере.")
            _box_row()
            _box_info("Для работы интеграции необходимо:")
            _box_info("1. Установить xray через VLESS Ultimate (пункт 1 → Режим B)")
            _box_info("2. Вернуться в это меню и включить интеграцию.")
            _box_row(); _box_sep()
            _box_item("Q", "← Назад"); _box_bot(); print()
            proto_ask(f"{CYAN}Выбор: {NC}", c=True)
            break

        cascade_label = "AWG 2.0" if cascade == "awg" else "VLESS+REALITY"
        _box_kv("Каскад:", f"{GREEN}{cascade_label}{NC}")
        _box_kv("Proxy tag:", xs["proxy_tag"])

        if enabled:
            ipt_str = f"{xs['ipt_count']}/{xs.get('ipt_total', len(_TG_NETS_current()))}"
            ipt_col = GREEN if xs["ipt_ok"] else YELLOW
            _box_kv("dokodemo:", f"{GREEN}✓ активен  →  :{xs['port']}{NC}")
            _box_kv("iptables:", f"{ipt_col}REDIRECT {ipt_str} подсетей{NC}")
            _box_row()
            _box_info("Схема трафика:")
            _box_info(f"  Telemt → iptables REDIRECT → dokodemo :{xs['port']} → xray → {cascade_label} → exit VPS → Telegram")
            if not xs["ipt_ok"]:
                _box_warn(f"Не все iptables-правила на месте ({ipt_str}). Используйте [2] для восстановления.")
        else:
            _box_kv("tproxy:", f"{RED}✗ не настроен (telemt работает через direct){NC}")
            _box_row()
            _box_warn("Telegram недоступен с российских IP без интеграции с xray!")

        # Статус подсетей TG
        _box_kv("Подсети:", _tg_nets_status_line())

        _box_row(); _box_sep()
        if not enabled:
            _box_item("1", f"✅  Включить интеграцию (dokodemo :{XRAY_TPROXY_PORT} + iptables)")
        else:
            _box_item("1", f"🔄  Переприменить / восстановить правила")
            _box_item("2", f"❌  Отключить интеграцию (перейти на direct)")
        _box_item("3", "🔍  Проверить статус xray inbound + iptables")
        _box_item("N", "🌐  Обновить подсети Telegram + переприменить iptables")
        _box_sep()
        from chimera.modules.telemt_self_route import status as _sr_status
        _sr = _sr_status()
        if _sr["return_rule"] and _sr["after_xray"]:
            _box_item("R", f"🔁  Маршрут DC/ME трафика: {GREEN}ВКЛЮЧЁН{NC}  (after=xray + RETURN rule)")
        else:
            _box_item("R", f"🔁  Маршрут DC/ME трафика: {YELLOW}ВЫКЛЮЧЕН{NC}  (telemt стартует до iptables)")
        _box_sep()
        _box_item("Q", "← Назад"); _box_bot(); print()

        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            _info(f"Применяю tproxy-интеграцию (dokodemo :{XRAY_TPROXY_PORT})...")
            ok, msg = xray_enable_tproxy_for_telemt(XRAY_TPROXY_PORT)
            if ok:
                _ok(msg)
            else:
                _err(msg)
            _pause()

        elif ch == "2" and enabled:
            ok, msg = xray_disable_tproxy_for_telemt()
            if ok:
                _ok(msg)
            else:
                _err(msg)
            _pause()

        elif ch == "r":
            from chimera.modules.telemt_self_route import enable as _sr_enable, disable as _sr_disable, status as _sr_status
            _sr = _sr_status()
            print()
            if _sr["return_rule"] and _sr["after_xray"]:
                _info("Маршрутизация DC/ME уже включена. Отключить?")
                if proto_ask(f"{CYAN}Отключить? [y/N]: {NC}", c=True).strip().lower() == "y":
                    ok, msg = _sr_disable()
                    _ok(msg) if ok else _err(msg)
            else:
                _info("Включаю маршрутизацию DC/ME трафика Telemt через xray...")
                ok, msg = _sr_enable()
                if ok:
                    _ok(msg)
                else:
                    _err(msg)
            _pause()

        elif ch == "3":
            cfg_path = _xray_config_path()
            print()
            if not cfg_path:
                _warn("xray config.json не найден.")
            else:
                try:
                    cfg = json.loads(cfg_path.read_text())
                    # dokodemo inbound
                    inbounds = [ib for ib in cfg.get("inbounds", [])
                                if ib.get("tag") == XRAY_TPROXY_TAG]
                    rules    = [r for r in cfg.get("routing", {}).get("rules", [])
                                if XRAY_TPROXY_TAG in r.get("inboundTag", [])]
                    if inbounds:
                        _ok(f"dokodemo inbound: порт {inbounds[0].get('port')}, "
                            f"listen {inbounds[0].get('listen')}, "
                            f"followRedirect {inbounds[0].get('settings', {}).get('followRedirect')}")
                    else:
                        _warn("dokodemo inbound не найден в xray config.")
                    if rules:
                        dest = rules[0].get("outboundTag") or rules[0].get("balancerTag") or "?"
                        _ok(f"Routing rule: {XRAY_TPROXY_TAG} → {dest}")
                    else:
                        _warn("Routing rule не найден.")
                    # xray service
                    r = _run(["systemctl", "is-active", XRAY_SERVICE_NAME], capture=True)
                    svc = r.stdout.strip()
                    _ok(f"xray сервис: {svc}") if svc == "active" else _warn(f"xray сервис: {svc}")
                    # iptables
                    port = _xray_dokodemo_port(cfg) or XRAY_TPROXY_PORT
                    tg_nets_now = _TG_NETS_current()
                    active = sum(1 for n in tg_nets_now if _ipt_rule_exists(n, port))
                    total  = len(tg_nets_now)
                    col    = GREEN if active == total else YELLOW
                    _ok(f"iptables REDIRECT: {col}{active}/{total} подсетей{NC}")
                    if active < total:
                        missing = [n for n in tg_nets_now if not _ipt_rule_exists(n, port)]
                        for n in missing:
                            _warn(f"  отсутствует: {n}")
                except Exception as e:
                    _err(f"Ошибка: {e}")
            _pause()

        elif ch == "n":
            # ── Обновление подсетей + переприменение iptables ─────────────
            print()
            new_nets = _update_tg_nets_interactive()
            xs_now = _xray_tproxy_status()
            if xs_now["enabled"]:
                port = xs_now["port"]
                print()
                _info(f"Переприменяю iptables REDIRECT для {len(new_nets)} подсетей → :{port}...")
                failed = [n for n in new_nets if not _ipt_add_redirect(n, port)]
                _iptables_persist()
                if failed:
                    _warn(f"Не удалось добавить {len(failed)} правил")
                else:
                    _ok(f"iptables REDIRECT обновлён: {len(new_nets)} подсетей активны")
            else:
                _info("tproxy не активен — только файл обновлён.")
            if _telemt_warp_is_enabled():
                print()
                _refresh_telemt_warp_routing()
            _pause()

        elif ch in ("q", ""):
            break
def mtproto_menu() -> None:
    """
    Точка входа из _core.py → главное меню VLESS Ultimate → пункт 6.
    Ctrl+C внутри подменю → возврат сюда.
    Ctrl+C здесь → пробрасывается в _core.py (KeyboardInterrupt не ловим).
    """
    server_ip, server_ipv6 = "", ""

    while True:
        _banner()
        r         = _run(["systemctl", "is-active", SERVICE_NAME], capture=True)
        is_active = r.stdout.strip() == "active"
        installed = BIN_PATH.exists()
        ver       = _get_installed_version() if installed else None
        svc_str   = (f"{GREEN}● запущен   {ver or ''}{NC}" if is_active else
                     f"{RED}● остановлен{NC}"               if installed  else
                     f"{YELLOW}● не установлен{NC}")

        _box_top("TELEMT MTPROXY")
        _box_row(); _box_kv("Статус:", svc_str); _box_row()

        # tproxy-интеграция — статус одной строкой
        _xs  = _xray_tproxy_status()
        if _xs["enabled"]:
            _mode  = "AWG 2.0" if _xs["cascade"] == "awg" else "VLESS"
            ipt_s  = f"{_xs['ipt_count']}/{_xs.get('ipt_total', len(_TG_NETS_current()))}"
            ipt_c  = GREEN if _xs["ipt_ok"] else YELLOW
            _box_kv("Xray:", f"{GREEN}dokodemo :{_xs['port']} → {_mode}{NC}  iptables {ipt_c}{ipt_s}{NC}")
        elif _xs["cascade"] != "none":
            _box_kv("Xray:", f"{YELLOW}каскад есть, tproxy не настроен{NC}")
        else:
            _box_kv("Xray:", f"{RED}каскад не обнаружен (direct){NC}")

        # Статус подсетей Telegram
        _box_kv("Подсети:", _tg_nets_status_line())

        # Статус hybrid fallback одной строкой
        _fb_mod_for_status = _get_fallback_module()
        if _fb_mod_for_status is not None and CONFIG_FILE.exists():
            _box_kv("Fallback:", _fb_mod_for_status.fallback_status_line(CONFIG_FILE))

        # Статус SYN-лимитера одной строкой
        _sl_mod_for_status = _get_syn_limiter_module()
        if _sl_mod_for_status is not None and CONFIG_FILE.exists():
            _box_kv("SYN-limiter:", _sl_mod_for_status.syn_limiter_status_line())

        # Статус iOS-фикса одной строкой
        _if_mod_for_status = _get_ios_fix_module()
        if _if_mod_for_status is not None and CONFIG_FILE.exists():
            _box_kv("iOS-фикс:", _if_mod_for_status.ios_fix_status_line())

        # Статус Telegram → WARP одной строкой
        _box_kv("TG→WARP:", _telemt_warp_status_line())

        _box_row(); _box_sep()
        _box_item("1", "🚀  Установить / переустановить")
        _box_item("2", "👥  Управление пользователями")
        _box_item("3", "🔗  Показать ссылки")
        _box_item("4", "🔄  Перезапустить сервис")
        _box_item("5", "⬆️   Проверить и обновить")
        _box_item("6", "📊  Статистика трафика")
        _box_item("7", "📋  Статус / логи")
        _box_item("L", "⏱️   Лимиты пользователей (квота + срок)")
        _box_item("G", "🌍  Гео-блокировка по странам")
        _box_item("X", "🔗  Xray-интеграция (SOCKS5 ↔ каскад)")
        _box_item("F", "🔀  Hybrid Fallback (Middle Proxy → Direct)")
        _box_item("S", "🛡️   SYN-limiter (стабилизация подключения)")
        _box_item("I", "🍎  iOS-фикс (MSS + отдельный порт)")
        _box_item("N", "🌐  Обновить подсети Telegram (RIPE NCC)")
        _box_item("W", "🌀  Telegram через WARP (для RU-серверов)")
        _box_item("P", "🖥️   Telemt Panel (веб-интерфейс)")
        _box_item("8", f"{RED}🗑️   Полное удаление{NC}")
        _box_sep()
        _box_item("Q", "← Назад в главное меню VLESS")
        _box_bot(); print()

        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            if not server_ip:
                _info("Определяю внешний IP...")
                server_ip, server_ipv6 = _get_public_ip()
            _run_install(server_ip, server_ipv6)

        elif ch == "2":
            if not CONFIG_FILE.exists():
                _warn("Telemt не установлен."); _pause(); continue
            if not server_ip:
                server_ip, _ = _get_public_ip()
            _menu_users(server_ip)

        elif ch == "3":
            if not CONFIG_FILE.exists():
                _warn("Telemt не установлен."); _pause(); continue
            if not server_ip:
                server_ip, _ = _get_public_ip()
            users  = _load_users()
            port   = _get_port()
            domain = _get_domain()
            _if_mod = _get_ios_fix_module()
            _ios_st = _if_mod.status() if _if_mod is not None else {"enabled": False}
            print()
            for n, s in users.items():
                sec  = _make_tls_secret(s, domain)
                link = f"tg://proxy?server={server_ip}&port={port}&secret={sec}"
                print(f"  {BOLD}{n}:{NC}")
                print(f"  {YELLOW}{link}{NC}")
                if _ios_st.get("enabled"):
                    ios_link = f"tg://proxy?server={server_ip}&port={_ios_st['ext_port']}&secret={sec}"
                    print(f"  {DIM}└─ iOS:{NC} {CYAN}{ios_link}{NC}")
                print()
            from chimera.modules.box_renderer import _print_link_warning
            _print_link_warning(is_vless=False)
            _pause()

        elif ch == "4":
            _run(["systemctl", "restart", SERVICE_NAME])
            _ok("Сервис перезапущен."); _pause()

        elif ch == "5":
            try:
                _menu_update()
            except _Cancelled:
                pass

        elif ch == "6":
            try:
                from chimera.modules.mtproto_stats import stats_menu
                stats_menu()
            except ImportError as e:
                _err(f"Модуль статистики не найден: {e}"); _pause()

        elif ch == "7":
            os.system("clear")
            _box_top("СТАТУС И ЛОГИ  •  TELEMT"); _box_row()
            r1 = subprocess.run(
                ["systemctl", "status", SERVICE_NAME, "--no-pager"],
                capture_output=True, encoding="utf-8", errors="replace"
            )
            for line in (r1.stdout or r1.stderr or "Нет данных").splitlines():
                _box_row(f"  {DIM}{line[:_BOX_W - 4]}{NC}")
            _box_sep()
            _box_row(f"  {BOLD}{CYAN}Последние 30 строк журнала:{NC}"); _box_row()
            r2 = subprocess.run(
                ["journalctl", "-u", SERVICE_NAME, "-n", "30",
                 "--no-pager", "--output=short-monotonic"],
                capture_output=True, encoding="utf-8", errors="replace",
                env={**os.environ, "LANG": "C.UTF-8"}
            )
            for line in (r2.stdout or r2.stderr or "Нет записей").splitlines():
                _box_row(f"  {DIM}{line[:_BOX_W - 4]}{NC}")
            _box_row(); _box_bot(); _pause()

        elif ch == "l":
            if not CONFIG_FILE.exists():
                _warn("Telemt не установлен."); _pause(); continue
            if not server_ip:
                server_ip, _ = _get_public_ip()
            _menu_limits(server_ip)

        elif ch == "g":
            if not CONFIG_FILE.exists():
                _warn("Telemt не установлен."); _pause(); continue
            from chimera.modules.geoblock import geoblock_menu_telemt
            _telemt_port = _get_port()
            if _telemt_port:
                geoblock_menu_telemt(_telemt_port)
            else:
                _warn("Не удалось определить порт Telemt.")

        elif ch == "8":
            if not (BIN_PATH.exists() or CONFIG_FILE.exists() or SERVICE_FILE.exists()):
                _warn("Telemt не установлен — нечего удалять."); _pause(); continue
            try:
                _full_uninstall(silent=False)
            except _Cancelled:
                _info("Удаление отменено."); _pause()

        elif ch == "x":
            try:
                _menu_xray_integration()
            except _Cancelled:
                pass

        elif ch == "f":
            # ── Hybrid Fallback управление ────────────────────────────────────
            if not CONFIG_FILE.exists():
                _warn("Telemt не установлен."); _pause(); continue
            _fb_mod = _get_fallback_module()
            if _fb_mod is None:
                _warn("Модуль telemt_fallback недоступен."); _pause(); continue
            try:
                _banner()
                _box_top("🔀  HYBRID FALLBACK  •  MIDDLE PROXY → DIRECT")
                _box_row()
                _fb_now = _fb_mod.read_fallback_config()
                _mp_now = _fb_mod.read_runtime_middle_proxy(CONFIG_FILE)
                _box_kv("Текущий режим:",    f"{'Middle Proxy' if _mp_now else 'Direct'}")
                _box_kv("fallback_to_direct:",       f"{GREEN if _fb_now.fallback_to_direct else RED}{_fb_now.fallback_to_direct}{NC}")
                _box_kv("fallback_after_attempts:",  str(_fb_now.fallback_after_attempts))
                _box_kv("fallback_after_seconds:",   str(_fb_now.fallback_after_seconds))
                _box_kv("auto_revert_to_middle:",    f"{GREEN if _fb_now.auto_revert_to_middle else DIM}{_fb_now.auto_revert_to_middle}{NC}")
                _box_row(); _box_sep()
                _box_item("1", "⚙️   Изменить параметры fallback")
                _box_item("2", "🔍  Проверить ME-серверы сейчас")
                _box_item("3", "🔄  Применить reload (hot-reload конфига)")
                _box_item("4", f"→  Переключить в Direct Mode вручную")
                _box_item("5", f"←  Переключить в Middle Proxy вручную")
                _box_sep()
                _box_item("Q", "← Назад")
                _box_bot(); print()

                try:
                    fb_ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
                except _Cancelled:
                    fb_ch = "q"

                if fb_ch == "1":
                    new_fb_cfg = _fb_mod.me_probe_menu(CONFIG_FILE)
                    _fb_mod.append_fallback_section(new_fb_cfg)
                    _ok("Параметры fallback обновлены в конфиге.")
                    _pause()

                elif fb_ch == "2":
                    print()
                    _info("Проверяю ME-серверы...")
                    live = _fb_mod.fetch_live_me_endpoints()
                    src  = f"живой пул getProxyConfig ({len(live)} адресов)" if live else "статический fallback-список (getProxyConfig недоступен)"
                    _info(f"источник: {src}")
                    probe = _fb_mod.MiddleProxyProbe(live or _fb_mod._ME_ENDPOINTS)
                    ok_c, total_c = probe.probe_all()
                    ratio = ok_c / total_c if total_c else 0
                    if ratio >= _fb_mod._ME_QUORUM:
                        _ok(f"ME-серверы доступны: {ok_c}/{total_c} ({ratio:.0%})")
                    else:
                        _warn(f"ME-серверы НЕДОСТУПНЫ: {ok_c}/{total_c} ({ratio:.0%} < кворум)")
                    hits = _fb_mod.check_journal_for_me_failures()
                    if hits:
                        _warn(f"В журнале найдены сигналы отказа ME ({len(hits)} строк):")
                        for h in hits[:3]:
                            print(f"    {DIM}{h[:70]}{NC}")
                    else:
                        _ok("Журнал: сигналов отказа ME не найдено.")
                    _pause()

                elif fb_ch == "3":
                    _info("Выполняю hot-reload конфига...")
                    fb_orch = _fb_mod.FallbackOrchestrator(
                        fb_config=_fb_now, config_file=CONFIG_FILE, service=SERVICE_NAME,
                    )
                    result = fb_orch.apply_reload_config()
                    _ok(result)
                    _pause()

                elif fb_ch == "4":
                    _info("Переключаю в Direct Mode (runtime)...")
                    ok_p = _fb_mod._patch_config_middle_proxy(CONFIG_FILE, enable=False)
                    if ok_p:
                        applied, method = _fb_mod.apply_telemt_reload(SERVICE_NAME)
                        if applied:
                            how = "reload (SIGHUP)" if method == "reload" else "restart"
                            _ok(f"Переключено в Direct Mode. use_middle_proxy=false в конфиге, применено через {how}.")
                        else:
                            _err("Конфиг обновлён (use_middle_proxy=false), но telemt НЕ применил изменения "
                                 "(не сработали ни reload, ни restart). Проверьте: systemctl status telemt")
                    else:
                        _err("Не удалось обновить конфиг.")
                    _pause()

                elif fb_ch == "5":
                    _info("Переключаю в Middle Proxy (runtime)...")
                    ok_p = _fb_mod._patch_config_middle_proxy(CONFIG_FILE, enable=True)
                    if ok_p:
                        applied, method = _fb_mod.apply_telemt_reload(SERVICE_NAME)
                        if applied:
                            how = "reload (SIGHUP)" if method == "reload" else "restart"
                            _ok(f"Переключено в Middle Proxy. use_middle_proxy=true в конфиге, применено через {how}.")
                        else:
                            _err("Конфиг обновлён (use_middle_proxy=true), но telemt НЕ применил изменения "
                                 "(не сработали ни reload, ни restart). Проверьте: systemctl status telemt")
                    else:
                        _err("Не удалось обновить конфиг.")
                    _pause()

            except Exception as _fe:
                _err(f"Ошибка fallback-меню: {_fe}"); _pause()

        elif ch == "s":
            # ── SYN-limiter управление ────────────────────────────────────────
            if not CONFIG_FILE.exists():
                _warn("Telemt не установлен."); _pause(); continue
            _sl_mod = _get_syn_limiter_module()
            if _sl_mod is None:
                _warn("Модуль telemt_syn_limiter недоступен."); _pause(); continue
            try:
                _sl_mod.syn_limiter_menu()
            except _Cancelled:
                pass
            except Exception as _se:
                _err(f"Ошибка меню SYN-limiter: {_se}"); _pause()

        elif ch == "i":
            # ── iOS-фикс управление ────────────────────────────────────────────
            if not CONFIG_FILE.exists():
                _warn("Telemt не установлен."); _pause(); continue
            _if_mod = _get_ios_fix_module()
            if _if_mod is None:
                _warn("Модуль telemt_ios_fix недоступен."); _pause(); continue
            try:
                _if_mod.ios_fix_menu()
            except _Cancelled:
                pass
            except Exception as _ie:
                _err(f"Ошибка меню iOS-фикса: {_ie}"); _pause()

        elif ch == "n":
            # ── Обновление подсетей Telegram ──────────────────────────────
            _banner()
            _box_top("🌐  ОБНОВЛЕНИЕ ПОДСЕТЕЙ TELEGRAM")
            _box_row()
            _box_info("Источники: RIPE NCC stat.ripe.net")
            _box_info("ASN: AS62041, AS59930, AS44907, AS211157, AS42065")
            _box_row()
            _box_info("После обновления новые правила будут применены к iptables.")
            _box_row()
            _box_item("Y", "Обновить и применить")
            _box_item("N", "← Отмена")
            _box_bot(); print()
            try:
                ans = proto_ask(f"{CYAN}Выбор [Y/n]: {NC}", default="y", c=True).strip().lower()
            except _Cancelled:
                continue
            if ans not in ("y", ""):
                continue
            print()
            new_nets = _update_tg_nets_interactive()
            # Применяем к iptables если tproxy активен
            xs = _xray_tproxy_status()
            if xs["enabled"]:
                port = xs["port"]
                print()
                _info(f"Применяю iptables REDIRECT для {len(new_nets)} подсетей → :{port}...")
                failed = [n for n in new_nets if not _ipt_add_redirect(n, port)]
                _iptables_persist()
                if failed:
                    _warn(f"Не удалось добавить {len(failed)} правил: {', '.join(failed[:3])}{'…' if len(failed)>3 else ''}")
                else:
                    _ok(f"iptables REDIRECT обновлён: {len(new_nets)} подсетей")
            else:
                _info("tproxy не активен — iptables не обновляем.")
            if _telemt_warp_is_enabled():
                print()
                _refresh_telemt_warp_routing()
            _pause()

        elif ch == "w":
            # ── Telegram через WARP ────────────────────────────────────────
            try:
                _do_telemt_warp_menu()
            except _Cancelled:
                pass
            except Exception as _we:
                _err(f"Ошибка меню Telegram→WARP: {_we}"); _pause()

        elif ch == "p":
            # ── Telemt Panel (веб-интерфейс) ────────────────────────────────
            _panel_mod = _get_panel_module()
            if _panel_mod is None:
                _err("Модуль telemt_panel не найден (файл modules/telemt_panel.py)."); _pause()
                continue
            try:
                _panel_mod.telemt_panel_menu()
            except _Cancelled:
                pass
            except Exception as _pe:
                _err(f"Ошибка меню Telemt Panel: {_pe}"); _pause()

        elif ch in ("q", ""):
            break

# ══════════════════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════
#  УЧАСТИЕ В ОБЩЕМ БЭКАПЕ (единая автообнаружаемая система chimera.modules.backup_registry)
# ══════════════════════════════════════════════════════════════════════════════
def get_backup_paths() -> list[tuple[Path, str]]:
    """Возвращает [(реальный_путь, имя_в_архиве), ...] — всё необходимое для
    восстановления Telemt MTProto БЕЗ переиздания пользовательских секретов.

    Файлы:
      • /etc/telemt/telemt.toml — основной конфиг (секрет в нём, но он
        серверный — без него протокол не восстанавливается; не путать с
        пользовательскими MTProto-секретами, которых у этого протокола нет).
      • /etc/systemd/system/telemt.service — systemd unit (для авто-рестарта).
      • /var/lib/xray-installer/telemt_limits.json — лимиты трафика.

    Пустой список если протокол не установлен (файлы не существуют).
    Никогда не бросает исключение — любая внутренняя ошибка = пустой список.
    """
    try:
        candidates = [
            (CONFIG_FILE,  "telemt/telemt.toml"),
            (SERVICE_FILE, "etc/systemd/system/telemt.service"),
            (LIMITS_FILE,  "telemt/telemt_limits.json"),
        ]
        return [(p, arcname) for p, arcname in candidates if p.exists()]
    except Exception:
        return []


# ══════════════════════════════════════════════════════════════════════════════
#  АВТОНОМНЫЙ ЗАПУСК
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}"); sys.exit(1)
    try:
        mtproto_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}"); sys.exit(0)
