"""
chimera/modules/resolv_conf_fix.py
───────────────────────────────────────────────────────────────────────────────
Автоматическое исправление /etc/resolv.conf для предотвращения DNS-leak.

КОНТЕКСТ
========
DNS Leak Test (do_dns_leak_test в _core.py) может показать, что серверные
DNS-запросы уходят к провайдерским резолверам (например, Yandex LLC на
Ubuntu 24.04 VPS в РФ). Причины:

1. **systemd-resolved активен** (по умолчанию на Ubuntu 24.04, Fedora, и др.):
   `/etc/resolv.conf` — симлинк на `/run/systemd/resolve/stub-resolv.conf`.
   `systemd-resolved` берёт upstream DNS из:
     • `/etc/systemd/resolved.conf` (статичный)
     • `/etc/systemd/resolved.conf.d/*.conf` (drop-in overrides)
     • `/etc/netplan/*.yaml` (per-link DNS от сетевого конфига)
     • DHCP-ответов от провайдера (per-link)
   На RU-VPS провайдер через DHCP отдаёт свои DNS (Yandex, Selectel, Timeweb)
   — они попадают в per-link конфигурацию и используются по умолчанию.

2. **systemd-resolved НЕ активен** (Debian, минимальные cloud-образы):
   `/etc/resolv.conf` — статичный файл, прописанный cloud-init из user-data
   или метаданных провайдера. Содержит `nameserver <провайдерский DNS>`.

В обоих случаях серверные DNS-запросы уходят к провайдеру — это утечка.

РЕШЕНИЕ
=======
Модуль предоставляет функцию `do_fix_resolv_conf_interactive()` —
интерактивный экран, который:

  1. Диагностирует текущее состояние (что в resolv.conf, активен ли
     systemd-resolved, какой upstream, слушает ли DNSCrypt на 127.0.0.1).
  2. Предлагает автоматически направить серверный DNS на локальный
     DNSCrypt-proxy (127.0.0.1):
     • systemd-resolved: `resolvectl dns-global set 127.0.0.1` +
       `resolvectl dns-default-route set false` + drop-in override
       `/etc/systemd/resolved.conf.d/chimera-dns.conf` для persist после
       ребута.
     • Static resolv.conf: бэкап + перезапись на `nameserver 127.0.0.1`.
  3. Pre-flight checks: убеждается, что DNSCrypt действительно слушает
     127.0.0.1:5300 (или 53) — иначе фикс создаст black-hole.
  4. Rollback: кнопка "вернуть как было" — удаляет override, восстанавливает
     бэкап.

ИНТЕГРАЦИЯ
==========
- Из DNS Leak Test (do_dns_leak_test в _core.py): при обнаружении leak
  показывается prompt "Исправить автоматически? [Y/n]" → запускает функцию.
- Из меню Сеть → DNSCrypt → отдельный пункт "Исправить /etc/resolv.conf".

Публичное API:
  do_fix_resolv_conf_interactive() — TUI-экран (диагностика + fix + rollback)
  fix_resolv_conf_to_localhost()   — программный fix (без TUI), для вызова
                                     из других модулей. Возвращает dict с
                                     результатом.
  rollback_resolv_conf()           — программный rollback.
  diagnose_resolv_conf()           — только диагностика, возвращает dict.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any


# =============================================================================
#  Константы
# =============================================================================
_RESOLV_CONF          = Path("/etc/resolv.conf")
_BACKUP               = Path("/etc/resolv.conf.chimera.bak")
_RESOLVED_DROPIN_DIR  = Path("/etc/systemd/resolved.conf.d")
_RESOLVED_DROPIN_FILE = _RESOLVED_DROPIN_DIR / "chimera-dns.conf"
_STATE_FILE           = Path("/var/lib/xray-installer/resolv_conf_fix.json")
_LOG_FILE             = Path("/var/log/chimera.log")
_DNSCRYPT_TOML        = Path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml")
_DNSCRYPT_SERVICE     = "dnscrypt-proxy.service"
_LOCAL_DNS            = "127.0.0.1"

# systemd-сервис для persist per-link DNS override после ребута.
# Drop-in /etc/systemd/resolved.conf.d/ перебивает только Global DNS —
# per-link DNS от DHCP (ens3, eth0, ...) имеет приоритет. Поэтому после
# ребута systemd-resolved снова подхватит DHCP DNS. Сервис запускается
# после network-online.target и применяет `resolvectl dns LINK 127.0.0.1`
# для каждого активного link'а.
_PERSIST_SVC_NAME     = "chimera-dns-fix.service"
_PERSIST_SVC_PATH     = Path("/etc/systemd/system") / _PERSIST_SVC_NAME
_PERSIST_SCRIPT_PATH  = Path("/usr/local/bin/chimera-dns-fix-apply.sh")


# =============================================================================
#  Цвета (как в dns_redirect.py)
# =============================================================================
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        light = os.environ.get("VLESS_THEME", "").lower() == "light"
        if light:
            return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                        CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                        DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m')
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                    DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m')
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED=_C['RED']; GREEN=_C['GREEN']; YELLOW=_C['YELLOW']; CYAN=_C['CYAN']
BLUE=_C['BLUE']; BOLD=_C['BOLD']; DIM=_C['DIM']; WHITE=_C['WHITE']; NC=_C['NC']


# ── box_renderer ─────────────────────────────────────────────────────────────
from chimera.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item,
    _box_back, _box_info, _box_warn, _box_desc,
)


# =============================================================================
#  Логирование
# =============================================================================
def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        with _LOG_FILE.open("a") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                    f"[RESOLV-CONF-FIX] [{level}] {clean}\n")
    except Exception:
        pass

def _info(msg):  print(f"{CYAN}[INFO]{NC}  {msg}");  _log("INFO", msg)
def _ok(msg):    print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)
def _warn(msg):  print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)
def _err(msg):   print(f"{RED}[ERR]{NC}   {msg}");   _log("ERROR", msg)


def _run(cmd: list, capture: bool = False, quiet: bool = False,
         check: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    import importlib
    return importlib.import_module("chimera._core")


# =============================================================================
#  ДИАГНОСТИКА
# =============================================================================
def _is_systemd_resolved_active() -> bool:
    """Активен ли сервис systemd-resolved."""
    r = _run(["systemctl", "is-active", "systemd-resolved"],
             capture=True, check=False)
    return r.returncode == 0 and r.stdout.strip() == "active"


def _is_symlink_to_resolved_stub() -> bool:
    """/etc/resolv.conf — симлинк на systemd-resolved stub?

    Симлинк на /run/systemd/resolve/stub-resolv.conf — признак того, что
    systemd-resolved управляет DNS. Прямая правка такого файла бесполезна:
    systemd-resolved переписывает его при ребуте / per-link change.
    """
    try:
        target = os.readlink(str(_RESOLV_CONF))
        return "systemd/resolve" in target
    except OSError:
        return False


def _get_resolv_conf_nameservers() -> List[str]:
    """Парсит nameserver-ы из /etc/resolv.conf."""
    if not _RESOLV_CONF.exists():
        return []
    try:
        text = _RESOLV_CONF.read_text(errors="replace")
        return re.findall(r'^\s*nameserver\s+(\S+)', text, re.MULTILINE)
    except Exception:
        return []


def _get_resolved_global_dns() -> List[str]:
    """Глобальный DNS в systemd-resolved (через resolvectl dns)."""
    r = _run(["resolvectl", "dns"], capture=True, check=False)
    if r.returncode != 0:
        return []
    # Вывод: "Global: 8.8.8.8 1.1.1.1" или "Global: 127.0.0.1"
    m = re.search(r'^Global:\s*(.*)$', r.stdout, re.MULTILINE)
    if not m:
        return []
    line = m.group(1).strip()
    if not line or "not set" in line.lower():
        return []
    return line.split()


def _get_resolved_link_dns() -> List[tuple]:
    """Per-link DNS в systemd-resolved.

    Возвращает список (link_name, [dns_ips]).
    Пример вывода resolvectl dns:
        Link 2 (eth0): 5.45.240.203 37.140.169.116
    """
    r = _run(["resolvectl", "dns"], capture=True, check=False)
    if r.returncode != 0:
        return []
    results = []
    for m in re.finditer(r'^Link\s+\d+\s+\(([^)]+)\):\s*(.*)$', r.stdout, re.MULTILINE):
        link = m.group(1).strip()
        dns_str = m.group(2).strip()
        if dns_str and "not set" not in dns_str.lower():
            results.append((link, dns_str.split()))
    return results


def _get_all_links() -> List[str]:
    """Список всех сетевых link'ов, которые systemd-resolved знает о.

    Используется для per-link DNS override — нужно применить
    `resolvectl dns LINK 127.0.0.1` для каждого активного link'а,
    иначе DHCP-сервер провайдера продолжит подсовывать свой DNS.

    Источник: `resolvectl dns` выводит строки вида:
        Global: ...
        Link 2 (eth0): 8.8.8.8 1.1.1.1
        Link 3 (wg0): 10.0.0.1

    Также `networkctl list` даёт более полный список, но он может
    показать и не-DNS интерфейсы (loopback, docker0, etc.) —
    фильтруем по тем, что в `resolvectl dns`.
    """
    r = _run(["resolvectl", "dns"], capture=True, check=False)
    if r.returncode != 0:
        return []
    links = []
    for m in re.finditer(r'^Link\s+\d+\s+\(([^)]+)\):', r.stdout, re.MULTILINE):
        link = m.group(1).strip()
        if link and link not in links:
            # Пропускаем loopback — он не имеет DHCP DNS.
            if link == "lo":
                continue
            links.append(link)
    return links


def _resolvectl_dns_set(link: Optional[str], dns: str) -> tuple:
    """Выполняет `resolvectl dns [LINK] 127.0.0.1`.

    Возвращает (ok: bool, cmd_str: str, error: str | None).

    На Ubuntu 24.04+ (systemd 256+) синтаксис: `resolvectl dns 127.0.0.1`
    (для global) или `resolvectl dns LINK 127.0.0.1` (для per-link).
    Старый синтаксис `dns-global` был удалён — это была первопричина
    бага, когда фикс «применялся», но утечка оставалась.
    """
    if link:
        cmd = ["resolvectl", "dns", link, dns]
        cmd_str = f"resolvectl dns {link} {dns}"
    else:
        cmd = ["resolvectl", "dns", dns]
        cmd_str = f"resolvectl dns {dns}"
    r = _run(cmd, capture=True, check=False)
    if r.returncode == 0:
        return True, cmd_str, None
    return False, cmd_str, f"rc={r.returncode}, stderr={r.stderr.strip()[:120]}"


def _resolvectl_default_route_set(link: Optional[str], value: bool) -> tuple:
    """Выполняет `resolvectl default-route [LINK] false`.

    Возвращает (ok: bool, cmd_str: str, error: str | None).

    На Ubuntu 24.04+ синтаксис: `resolvectl default-route false` (global)
    или `resolvectl default-route LINK false` (per-link).
    Старый синтаксис `dns-default-route set false` был переименован —
    это была вторая первопричина бага.
    """
    val_str = "true" if value else "false"
    if link:
        cmd = ["resolvectl", "default-route", link, val_str]
        cmd_str = f"resolvectl default-route {link} {val_str}"
    else:
        cmd = ["resolvectl", "default-route", val_str]
        cmd_str = f"resolvectl default-route {val_str}"
    r = _run(cmd, capture=True, check=False)
    if r.returncode == 0:
        return True, cmd_str, None
    return False, cmd_str, f"rc={r.returncode}, stderr={r.stderr.strip()[:120]}"


def _write_persist_script_and_service() -> tuple:
    """Создаёт systemd-сервис + shell-скрипт для persist per-link DNS override.

    Сервис chimera-dns-fix.service запускается после network-online.target
    и выполняет shell-скрипт, который:
      1. Получает список всех link'ов через `resolvectl dns`.
      2. Для каждого link'а вызывает `resolvectl dns LINK 127.0.0.1`
         и `resolvectl default-route LINK false`.

    Возвращает (script_path, service_path, error: str | None).
    """
    # Shell-скрипт: применяет per-link DNS override для всех link'ов.
    # Используется bash, не sh, для подстановки процессов.
    #
    # ВАЖНО: global `resolvectl dns 127.0.0.1` НЕ вызываем — на Ubuntu 24.04
    # (systemd 256+) парсер интерпретирует `127.0.0.1` как имя интерфейса
    # и падает с `Failed to resolve interface "127.0.0.1": No such device`.
    # Global DNS задаётся через drop-in /etc/systemd/resolved.conf.d/chimera-dns.conf
    # с DNS=127.0.0.1 и Domains=~. — этого достаточно.
    script_content = """#!/bin/bash
# Chimera Project — persist per-link DNS override.
# Создан chimera/modules/resolv_conf_fix.py
#
# Drop-in /etc/systemd/resolved.conf.d/chimera-dns.conf задаёт Global DNS
# (127.0.0.1) и Domains=~. (перехват всех запросов). Этого достаточно для
# global — resolvectl dns 127.0.0.1 НЕ вызываем (на Ubuntu 24.04 парсер
# падает с "Failed to resolve interface").
#
# Per-link DNS от DHCP (ens3: 77.88.8.8 на Yandex VPS) имеет приоритет над
# Global. Этот скрипт перебивает per-link DNS на 127.0.0.1 для каждого link'а.
#
# Запускается:
#   1. После применения фикса (через systemctl start).
#   2. После ребута (через systemd-unit chimera-dns-fix.service).
#   3. После старта сети (After=network-online.target).

set -e

LOCAL_DNS="${1:-127.0.0.1}"

# Получаем список всех link'ов из `resolvectl dns`.
# Вывод: "Link 2 (eth0): 8.8.8.8 1.1.1.1" — берём имя link'а.
LINKS=$(resolvectl dns 2>/dev/null | \\
        sed -nE 's/^Link [0-9]+ \\(([^)]+)\\):.*/\\1/p' | \\
        grep -v '^lo$' | \\
        sort -u)

if [ -z "$LINKS" ]; then
    echo "[chimera-dns-fix] no network links found — skip"
    exit 0
fi

for LINK in $LINKS; do
    # Устанавливаем per-link DNS на 127.0.0.1.
    if resolvectl dns "$LINK" "$LOCAL_DNS" 2>/dev/null; then
        echo "[chimera-dns-fix] $LINK → DNS $LOCAL_DNS"
    else
        echo "[chimera-dns-fix] $LINK: resolvectl dns failed" >&2
    fi
    # Отключаем default-route для link'а — чтобы не использовался DHCP DNS.
    if resolvectl default-route "$LINK" false 2>/dev/null; then
        echo "[chimera-dns-fix] $LINK → default-route false"
    else
        echo "[chimera-dns-fix] $LINK: resolvectl default-route failed" >&2
    fi
done

# flush caches — не должно быть stale entries с провайдерским DNS.
resolvectl flush-caches 2>/dev/null || true

exit 0
"""
    try:
        _PERSIST_SCRIPT_PATH.parent.mkdir(parents=True, exist_ok=True)
        _PERSIST_SCRIPT_PATH.write_text(script_content)
        _PERSIST_SCRIPT_PATH.chmod(0o755)
    except PermissionError:
        return None, None, f"нет прав на {_PERSIST_SCRIPT_PATH} (нужен root)"
    except Exception as e:
        return None, None, f"не удалось создать {_PERSIST_SCRIPT_PATH}: {e}"

    # systemd-unit: запускается после старта сети.
    service_content = f"""[Unit]
Description=Chimera Project — persist per-link DNS override (DNS-leak fix)
Documentation=https://github.com/inferno1978/Chimera-Project
After=network-online.target systemd-resolved.service dnscrypt-proxy.service
Wants=network-online.target
Requires=systemd-resolved.service

[Service]
Type=oneshot
ExecStart={_PERSIST_SCRIPT_PATH} 127.0.0.1
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    try:
        _PERSIST_SVC_PATH.parent.mkdir(parents=True, exist_ok=True)
        _PERSIST_SVC_PATH.write_text(service_content)
    except PermissionError:
        return _PERSIST_SCRIPT_PATH, None, f"нет прав на {_PERSIST_SVC_PATH} (нужен root)"
    except Exception as e:
        return _PERSIST_SCRIPT_PATH, None, f"не удалось создать {_PERSIST_SVC_PATH}: {e}"

    return _PERSIST_SCRIPT_PATH, _PERSIST_SVC_PATH, None


def _enable_persist_service() -> tuple:
    """Активирует chimera-dns-fix.service (enable + start).

    Возвращает (ok: bool, error: str | None).
    """
    # daemon-reload чтобы подхватить новый unit
    _run(["systemctl", "daemon-reload"], capture=True, check=False)
    r = _run(["systemctl", "enable", _PERSIST_SVC_NAME],
             capture=True, check=False)
    if r.returncode != 0:
        return False, f"systemctl enable: rc={r.returncode}, stderr={r.stderr.strip()[:120]}"
    r = _run(["systemctl", "start", _PERSIST_SVC_NAME],
             capture=True, check=False)
    if r.returncode != 0:
        return False, f"systemctl start: rc={r.returncode}, stderr={r.stderr.strip()[:120]}"
    return True, None


def _disable_persist_service() -> tuple:
    """Деактивирует и удаляет chimera-dns-fix.service.

    Возвращает (ok: bool, error: str | None).
    """
    _run(["systemctl", "stop", _PERSIST_SVC_NAME],
         capture=True, check=False)
    _run(["systemctl", "disable", _PERSIST_SVC_NAME],
         capture=True, check=False)
    if _PERSIST_SVC_PATH.exists():
        try:
            _PERSIST_SVC_PATH.unlink()
        except Exception:
            pass
    if _PERSIST_SCRIPT_PATH.exists():
        try:
            _PERSIST_SCRIPT_PATH.unlink()
        except Exception:
            pass
    _run(["systemctl", "daemon-reload"], capture=True, check=False)
    return True, None


# =============================================================================
#  Отключение DHCP DNS от провайдера
# =============================================================================
# После применения per-link override + drop-in, systemd-resolved всё ещё
# показывает Global DNS 77.88.8.8 от DHCP. systemd-resolved отправляет
# запросы на все Global DNS параллельно (parallel queries) — поэтому
# DNS Leak Test видит Yandex LLC, хотя per-link ens3=127.0.0.1.
#
# Решение: отключить получение DNS от DHCP на уровне network manager.
# - systemd-networkd: drop-in .network.d/chimera.conf с UseDNS=false.
# - NetworkManager: nmcli ... ipv4.ignore-auto-dns yes + ipv6.ignore-auto-dns yes.
#
# Это убирает провайдерский DNS из Global DNS → остаётся только 127.0.0.1
# из drop-in → утечки точно нет.

def _detect_network_manager() -> str:
    """Определяет network manager: 'systemd-networkd' / 'NetworkManager' / 'none'.

    Логика:
      1. `systemctl is-active NetworkManager` → NetworkManager.
      2. `systemctl is-active systemd-networkd` → systemd-networkd.
      3. Иначе 'none' (static config без manager).
    """
    r_nm = _run(["systemctl", "is-active", "NetworkManager"],
                capture=True, check=False)
    if r_nm.returncode == 0 and r_nm.stdout.strip() == "active":
        return "NetworkManager"
    r_nwd = _run(["systemctl", "is-active", "systemd-networkd"],
                 capture=True, check=False)
    if r_nwd.returncode == 0 and r_nwd.stdout.strip() == "active":
        return "systemd-networkd"
    return "none"


def _networkd_find_link_files(link: str) -> List[Path]:
    """Находит .network файлы systemd-networkd для указанного link.

    Ищет в:
      - /etc/systemd/network/*.network (admin config, высший приоритет)
      - /run/systemd/network/*.network (runtime, генерируется netplan)
      - /lib/systemd/network/*.network (distro defaults)

    Match по [Match] секции: Name=ens3 / Name=ens3 e* / Name=e* /
    MACAddress=... (если link имеет тот же MAC) / [Network] DHCP=yes
    (без явного Name — fallback).

    Возвращает список путей. Обычно один файл на link.
    """
    import fnmatch

    results: List[Path] = []
    search_dirs = [
        Path("/etc/systemd/network"),
        Path("/run/systemd/network"),
        Path("/lib/systemd/network"),
    ]
    # Получаем MAC link'а для match по MACAddress=.
    link_mac = None
    try:
        mac_path = Path(f"/sys/class/net/{link}/address")
        if mac_path.exists():
            link_mac = mac_path.read_text().strip().lower()
    except Exception:
        pass

    for d in search_dirs:
        if not d.exists():
            continue
        for f in d.glob("*.network"):
            try:
                content = f.read_text(errors="replace")
                # Парсим [Match] секцию — собираем все Name= и MACAddress=.
                in_match = False
                name_patterns: List[str] = []
                mac_patterns: List[str] = []
                for line in content.splitlines():
                    ls = line.strip()
                    if ls.startswith("[") and ls.endswith("]"):
                        in_match = (ls == "[Match]")
                        continue
                    if not in_match:
                        continue
                    # Name= может быть "ens3" или "ens3 eth0" (через пробел).
                    if ls.startswith("Name=") or ls.startswith("Name ="):
                        val = ls.split("=", 1)[1].strip()
                        name_patterns.extend(val.split())
                    elif ls.startswith("MACAddress=") or ls.startswith("MACAddress ="):
                        val = ls.split("=", 1)[1].strip()
                        mac_patterns.extend(m.strip().lower() for m in val.split())
                # Match по Name (fnmatch для wildcard).
                matched = False
                for pattern in name_patterns:
                    if fnmatch.fnmatch(link, pattern):
                        matched = True
                        break
                # Match по MAC.
                if not matched and link_mac:
                    for pattern in mac_patterns:
                        if pattern == link_mac:
                            matched = True
                            break
                if matched:
                    results.append(f)
                    continue
                # Fallback: если в [Network] есть DHCP=yes и нет Name=,
                # считаем что это generic .network (редкий кейс).
                if not name_patterns and not mac_patterns:
                    if "DHCP=yes" in content or "DHCP=ipv4" in content:
                        results.append(f)
            except Exception:
                continue
    return results


def _networkd_create_link_network_file(link: str) -> Path:
    """Создаёт новый .network файл для link в /etc/systemd/network/.

    Используется как fallback если _networkd_find_link_files ничего не нашёл
    (например, на server-сборках без netplan, или если .network файлы в /run/
    удалены). Файл содержит минимальный [Match] Name=<link> + [Network]
    DHCP=yes — чтобы systemd-networkd продолжал управлять DHCP, но drop-in
    с UseDNS=false мог примениться.

    Имя файла: 10-chimera-<link>.network (в /etc/systemd/network/).
    """
    net_file = Path("/etc/systemd/network") / f"10-chimera-{link}.network"
    content = (
        f"# Chimera Project — .network файл для link {link}\n"
        f"# Создан chimera/modules/resolv_conf_fix.py как fallback\n"
        f"# (не найден существующий .network файл для этого link).\n"
        f"[Match]\n"
        f"Name={link}\n"
        f"\n"
        f"[Network]\n"
        f"DHCP=yes\n"
        f"\n"
        f"[DHCPv4]\n"
        f"UseDNS=false\n"
        f"UseDomains=false\n"
        f"\n"
        f"[DHCPv6]\n"
        f"UseDNS=false\n"
        f"UseDomains=false\n"
        f"\n"
        f"[IPv6AcceptRA]\n"
        f"UseDNS=false\n"
        f"UseDomains=false\n"
    )
    net_file.parent.mkdir(parents=True, exist_ok=True)
    net_file.write_text(content)
    return net_file


def _networkd_disable_dhcp_dns(link: str) -> tuple:
    """Создаёт drop-in для .network файла link'а с UseDNS=false.

    systemd-networkd читает drop-in'ы из /etc/systemd/network/<file>.d/*.conf.
    Drop-in перебивает DHCP DNS: `[DHCPv4] UseDNS=false` + `[DHCPv6] UseDNS=false`.

    Если .network файл не найден (редкий кейс на server-сборках без netplan) —
    создаёт новый .network файл в /etc/systemd/network/ через
    _networkd_create_link_network_file() (уже с UseDNS=false внутри).

    Возвращает (ok, dropin_path, error).
    """
    net_files = _networkd_find_link_files(link)
    if not net_files:
        # Fallback: создаём .network файл с [DHCPv4] UseDNS=false прямо внутри.
        try:
            net_file = _networkd_create_link_network_file(link)
        except PermissionError:
            return False, None, f"нет прав на /etc/systemd/network/ (нужен root)"
        except Exception as e:
            return False, None, f"не удалось создать .network файл: {e}"
        # Возвращаем путь к самому .network файлу — UseDNS=false уже внутри.
        return True, net_file, None

    # Берём первый найденный (обычно один на link).
    net_file = net_files[0]
    # Drop-in директория: /etc/systemd/network/<basename>.d/
    # Даже если .network файл в /run/ (от netplan), drop-in в /etc/ применяется.
    dropin_dir = Path("/etc/systemd/network") / f"{net_file.name}.d"
    dropin_file = dropin_dir / "chimera-dns.conf"
    dropin_content = (
        "# Chimera Project — отключение DHCP DNS для link " + link + "\n"
        "# Создан chimera/modules/resolv_conf_fix.py\n"
        "# Перебивает DHCP DNS от провайдера (Yandex, Selectel, Timeweb).\n"
        "# Без этого systemd-resolved видит Global DNS 77.88.8.8 от DHCP и\n"
        "# отправляет запросы параллельно на все Global DNS — DNS Leak Test\n"
        "# видит Yandex LLC.\n"
        "[DHCPv4]\n"
        "UseDNS=false\n"
        "UseDomains=false\n"
        "\n"
        "[DHCPv6]\n"
        "UseDNS=false\n"
        "UseDomains=false\n"
        "\n"
        "[IPv6AcceptRA]\n"
        "UseDNS=false\n"
        "UseDomains=false\n"
    )
    try:
        dropin_dir.mkdir(parents=True, exist_ok=True)
        dropin_file.write_text(dropin_content)
    except PermissionError:
        return False, None, f"нет прав на {dropin_file} (нужен root)"
    except Exception as e:
        return False, None, f"не удалось создать {dropin_file}: {e}"

    return True, dropin_file, None


def _networkd_enable_dhcp_dns(link: str) -> tuple:
    """Удаляет drop-in для .network файла link'а (возвращает DHCP DNS).

    Также удаляет fallback .network файлы (10-chimera-*.network) созданные
    _networkd_create_link_network_file() если не было найдено существующих.

    Возвращает (ok, error).
    """
    # Удаляем все chimera-dns.conf drop-in'ы для любого .network файла.
    # Это проще чем искать конкретный — drop-in'ов у нас только один тип.
    dropin_dir_glob = Path("/etc/systemd/network")
    if not dropin_dir_glob.exists():
        return True, None
    removed = False
    for d in dropin_dir_glob.glob("*.network.d"):
        dropin_file = d / "chimera-dns.conf"
        if dropin_file.exists():
            try:
                dropin_file.unlink()
                removed = True
            except Exception:
                pass
        # Если директория пуста — удаляем (чистота).
        try:
            if d.exists() and not any(d.iterdir()):
                d.rmdir()
        except Exception:
            pass
    # Также удаляем fallback .network файлы (10-chimera-*.network).
    for f in dropin_dir_glob.glob("10-chimera-*.network"):
        try:
            f.unlink()
            removed = True
        except Exception:
            pass
    return True, None if removed else "drop-in не найден (возможно уже удалён)"


def _nm_disable_dhcp_dns(link: str) -> tuple:
    """NetworkManager: ipv4.ignore-auto-dns yes + ipv6.ignore-auto-dns yes.

    Возвращает (ok, conn_name, error).
    """
    # Найти connection name для link.
    r = _run(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show"],
             capture=True, check=False)
    if r.returncode != 0:
        return False, None, f"nmcli connection show: rc={r.returncode}"
    conn_name = None
    for line in r.stdout.splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[1] == link:
            conn_name = parts[0]
            break
    if not conn_name:
        return False, None, f"NetworkManager: нет connection для link {link}"

    # Применяем ignore-auto-dns.
    for proto in ("ipv4", "ipv6"):
        r = _run(["nmcli", "connection", "modify", conn_name,
                  f"{proto}.ignore-auto-dns", "yes"],
                 capture=True, check=False)
        if r.returncode != 0:
            return False, conn_name, f"nmcli modify {proto}: rc={r.returncode}, stderr={r.stderr.strip()[:100]}"

    # Activate чтобы применить.
    r = _run(["nmcli", "connection", "up", conn_name],
             capture=True, check=False)
    if r.returncode != 0:
        return False, conn_name, f"nmcli connection up: rc={r.returncode}, stderr={r.stderr.strip()[:100]}"

    return True, conn_name, None


def _nm_enable_dhcp_dns(link: str) -> tuple:
    """NetworkManager: вернуть ignore-auto-dns no.

    Возвращает (ok, error).
    """
    r = _run(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show"],
             capture=True, check=False)
    if r.returncode != 0:
        return False, f"nmcli: rc={r.returncode}"
    conn_name = None
    for line in r.stdout.splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[1] == link:
            conn_name = parts[0]
            break
    if not conn_name:
        return True, "connection не найдена (возможно уже удалена)"

    for proto in ("ipv4", "ipv6"):
        _run(["nmcli", "connection", "modify", conn_name,
              f"{proto}.ignore-auto-dns", "no"],
             capture=True, check=False)
    _run(["nmcli", "connection", "up", conn_name],
         capture=True, check=False)
    return True, None


def disable_dhcp_dns_on_all_links() -> Dict[str, Any]:
    """Отключает DHCP DNS для всех активных link'ов.

    Определяет network manager (systemd-networkd / NetworkManager) и
    применяет соответствующий метод:
      - systemd-networkd: drop-in .network.d/chimera.conf с UseDNS=false.
      - NetworkManager: nmcli ... ignore-auto-dns yes.

    После применения: networkctl reload (для networkd) — БЕЗ reconfigure,
    или уже применено через nmcli connection up (для NM).

    Возвращает dict:
      {"ok": bool, "manager": str, "actions": [str, ...],
       "warnings": [str, ...], "dropin_paths": [str, ...], "error": str | None}
    """
    actions: List[str] = []
    warnings: List[str] = []
    dropin_paths: List[str] = []

    manager = _detect_network_manager()
    if manager == "none":
        return {"ok": False, "manager": "none", "actions": [],
                "warnings": [],
                "dropin_paths": [],
                "error": "не удалось определить network manager (ни systemd-networkd, ни NetworkManager не активны)"}

    links = _get_all_links()
    if not links:
        return {"ok": False, "manager": manager, "actions": [],
                "warnings": ["нет сетевых link'ов"],
                "dropin_paths": [],
                "error": "нет сетевых link'ов для настройки"}

    if manager == "systemd-networkd":
        for link in links:
            ok, dropin_path, err = _networkd_disable_dhcp_dns(link)
            if ok:
                actions.append(f"создан drop-in для {link}: {dropin_path}")
                dropin_paths.append(str(dropin_path))
            else:
                warnings.append(f"link {link}: {err}")
        # networkctl reload — перезагружает .network/.netdev/.link файлы.
        # БЕЗОПАСНО: не трогает интерфейсы, не сбрасывает IP.
        # Drop-in с UseDNS=false вступит в силу при следующем DHCP-renewal.
        # Немедленный эффект уже обеспечен через resolvectl dns LINK 127.0.0.1
        # + resolvectl default-route LINK false (per-link override).
        #
        # ВАЖНО: НЕ вызываем `networkctl reconfigure <link>` — это
        # ПОЛНОСТЬЮ переконфигурирует интерфейс (сбрасывает IP, пере-
        # запрашивает DHCP), что УБИВАЕТ SSH на удалённом сервере!
        # См. CHANGELOG: "resolv_conf_fix v6 — убрать networkctl reconfigure".
        r = _run(["networkctl", "reload"], capture=True, check=False)
        if r.returncode == 0:
            actions.append("networkctl reload")
        else:
            warnings.append(f"networkctl reload: rc={r.returncode}")

    elif manager == "NetworkManager":
        for link in links:
            ok, conn_name, err = _nm_disable_dhcp_dns(link)
            if ok:
                actions.append(f"nmcli: {conn_name} ignore-auto-dns yes (link {link})")
            else:
                warnings.append(f"link {link}: {err}")

    return {"ok": True, "manager": manager, "actions": actions,
            "warnings": warnings, "dropin_paths": dropin_paths,
            "error": None}


def enable_dhcp_dns_on_all_links() -> Dict[str, Any]:
    """Возвращает DHCP DNS (откат disable_dhcp_dns_on_all_links).

    Возвращает dict как disable_dhcp_dns_on_all_links().
    """
    actions: List[str] = []
    warnings: List[str] = []

    manager = _detect_network_manager()
    if manager == "none":
        return {"ok": False, "manager": "none", "actions": [],
                "warnings": [],
                "error": "не удалось определить network manager"}

    links = _get_all_links()

    if manager == "systemd-networkd":
        ok, err = _networkd_enable_dhcp_dns("")  # link не важен — удаляем все
        if ok:
            actions.append("удалены drop-in'ы /etc/systemd/network/*.network.d/chimera-dns.conf")
        r = _run(["networkctl", "reload"], capture=True, check=False)
        if r.returncode == 0:
            actions.append("networkctl reload")
        # НЕ вызываем networkctl reconfigure — см. комментарий в
        # disable_dhcp_dns_on_all_links (убивает SSH).

    elif manager == "NetworkManager":
        for link in links:
            ok, err = _nm_enable_dhcp_dns(link)
            if ok:
                actions.append(f"nmcli: {link} ignore-auto-dns no (restore)")
            else:
                warnings.append(f"link {link}: {err}")

    return {"ok": True, "manager": manager, "actions": actions,
            "warnings": warnings, "error": None}


def _get_dnscrypt_listen_addr_port() -> Optional[tuple]:
    """Читает listen_addresses из dnscrypt-proxy.toml.

    Возвращает (addr, port) или None если файл не найден / не распарсен.
    Формат в TOML: listen_addresses = ['127.0.0.1:5300', '[::1]:5300']
    """
    if not _DNSCRYPT_TOML.exists():
        return None
    try:
        text = _DNSCRYPT_TOML.read_text(errors="replace")
        # Ищем listen_addresses = ['127.0.0.1:5300', ...]
        m = re.search(
            r'listen_addresses\s*=\s*\[\s*[\'"]([^\'"]+)[\'"]',
            text, re.IGNORECASE,
        )
        if not m:
            return None
        addr_port = m.group(1)
        # Парсим '127.0.0.1:5300' или '[::1]:5300'
        if addr_port.startswith("["):
            # IPv6: [::1]:5300
            m6 = re.match(r'\[([^\]]+)\]:(\d+)', addr_port)
            if m6:
                return (m6.group(1), int(m6.group(2)))
        else:
            parts = addr_port.rsplit(":", 1)
            if len(parts) == 2:
                return (parts[0], int(parts[1]))
        return None
    except Exception:
        return None


def _is_dnscrypt_listening(addr: str, port: int) -> bool:
    """Проверяет, слушает ли dnscrypt-proxy на addr:port."""
    # Через ss -tlnu (TCP+UDP listening)
    r = _run(["ss", "-tlnu"], capture=True, check=False)
    if r.returncode != 0:
        return False
    # Ищем строку с addr:port (или :port)
    patterns = [
        f"{addr}:{port}",
        f"127.0.0.1:{port}",
        f"*:{port}",
        f"[::]:{port}",
        f":{port} ",
    ]
    for line in r.stdout.splitlines():
        for pat in patterns:
            if pat in line:
                return True
    return False


def _get_resolved_link_default_routes() -> List[tuple]:
    """Per-link default-route статус из systemd-resolved.

    Возвращает список (link_name, bool: default-route enabled).
    Пример вывода resolvectl default-route:
        Global: yes
        Link 2 (ens3): no
    """
    r = _run(["resolvectl", "default-route"], capture=True, check=False)
    if r.returncode != 0:
        return []
    results = []
    for m in re.finditer(r'^Link\s+\d+\s+\(([^)]+)\):\s*(\S+)', r.stdout, re.MULTILINE):
        link = m.group(1).strip()
        val_str = m.group(2).strip().lower()
        # "yes"/"no" → bool
        if val_str in ("yes", "true", "1"):
            results.append((link, True))
        elif val_str in ("no", "false", "0"):
            results.append((link, False))
    return results


def diagnose_resolv_conf() -> Dict[str, Any]:
    """Полная диагностика состояния DNS-резолвера.

    Главный критерий утечки — **per-link DNS**. Global DNS не критичен,
    потому что drop-in с `Domains=~.` перехватывает все запросы на 127.0.0.1,
    даже если global DNS содержит IP от DHCP (они просто не используются).

    Логика:
      - Если все link'и имеют DNS=127.0.0.1 И default-route=false → утечки нет.
      - Если есть link с внешним DNS (не 127.*) → утечка.
      - Если resolv.conf указывает на внешний DNS (без systemd-resolved) → утечка.

    Возвращает dict:
      {
        "resolv_conf_path": str,
        "resolv_conf_exists": bool,
        "resolv_conf_is_symlink": bool,
        "resolv_conf_symlink_target": str | None,
        "resolv_conf_nameservers": [str, ...],
        "resolv_conf_already_localhost": bool,
        "systemd_resolved_active": bool,
        "resolved_global_dns": [str, ...],
        "resolved_link_dns": [(link, [ip, ...]), ...],
        "resolved_link_default_routes": [(link, bool), ...],
        "per_link_overridden": bool,  # все link'и на 127.0.0.1 + default-route=false
        "dnscrypt_listen": (addr, port) | None,
        "dnscrypt_listening": bool,
        "dnscrypt_service_active": bool,
        "fix_needed": bool,
        "fix_method": "systemd_resolved" | "static_resolv_conf" | None,
        "leak_reasons": [str, ...],
      }
    """
    result: Dict[str, Any] = {
        "resolv_conf_path": str(_RESOLV_CONF),
        "resolv_conf_exists": _RESOLV_CONF.exists(),
        "resolv_conf_is_symlink": _RESOLV_CONF.is_symlink(),
        "resolv_conf_symlink_target": None,
        "resolv_conf_nameservers": [],
        "resolv_conf_already_localhost": False,
        "systemd_resolved_active": _is_systemd_resolved_active(),
        "resolved_global_dns": [],
        "resolved_link_dns": [],
        "resolved_link_default_routes": [],
        "per_link_overridden": False,
        "dnscrypt_listen": None,
        "dnscrypt_listening": False,
        "dnscrypt_service_active": False,
        "fix_needed": False,
        "fix_method": None,
        "leak_reasons": [],
    }

    # symlink target
    if result["resolv_conf_is_symlink"]:
        try:
            result["resolv_conf_symlink_target"] = os.readlink(str(_RESOLV_CONF))
        except OSError:
            pass

    # nameservers из resolv.conf
    result["resolv_conf_nameservers"] = _get_resolv_conf_nameservers()
    nss = result["resolv_conf_nameservers"]
    result["resolv_conf_already_localhost"] = bool(nss) and all(
        ip.startswith("127.") or ip == "::1" for ip in nss
    )

    # systemd-resolved state
    if result["systemd_resolved_active"]:
        result["resolved_global_dns"] = _get_resolved_global_dns()
        result["resolved_link_dns"] = _get_resolved_link_dns()
        result["resolved_link_default_routes"] = _get_resolved_link_default_routes()

    # DNSCrypt
    result["dnscrypt_listen"] = _get_dnscrypt_listen_addr_port()
    if result["dnscrypt_listen"]:
        addr, port = result["dnscrypt_listen"]
        result["dnscrypt_listening"] = _is_dnscrypt_listening(addr, port)
    r_svc = _run(["systemctl", "is-active", _DNSCRYPT_SERVICE],
                 capture=True, check=False)
    result["dnscrypt_service_active"] = (
        r_svc.returncode == 0 and r_svc.stdout.strip() == "active"
    )

    # ── Главный критерий: per-link override ────────────────────────────────
    # Если все link'и имеют DNS=127.0.0.1 И default-route=false → утечки нет.
    # Global DNS не критичен: drop-in с Domains=~. перехватывает все запросы
    # на 127.0.0.1, даже если global содержит 77.88.8.8 от DHCP.
    if result["systemd_resolved_active"] and result["resolved_link_dns"]:
        link_dns_ok = True
        link_dr_ok = True
        for link, dns in result["resolved_link_dns"]:
            if not all(ip.startswith("127.") or ip == "::1" for ip in dns):
                link_dns_ok = False
        for link, dr in result["resolved_link_default_routes"]:
            if dr:  # default-route=true — link может использоваться для запросов
                link_dr_ok = False
        result["per_link_overridden"] = link_dns_ok and link_dr_ok
    elif result["systemd_resolved_active"] and not result["resolved_link_dns"]:
        # Нет per-link DNS вообще — global DNS решает.
        result["per_link_overridden"] = False

    # Если DNSCrypt активен и слушает — есть смысл перенаправлять на него.
    dnscrypt_ready = (
        result["dnscrypt_service_active"]
        and result["dnscrypt_listen"] is not None
        and result["dnscrypt_listening"]
    )

    # ── Решение: нужен ли фикс? ────────────────────────────────────────────
    reasons: List[str] = []

    # Case 1: per-link override активен → утечки НЕТ, независимо от global DNS.
    if result["per_link_overridden"]:
        result["fix_needed"] = False
        result["fix_method"] = None
        result["leak_reasons"] = []
        # Если в global DNS есть внешние IP — это informational, не leak.
        # (drop-in с Domains=~. перехватывает запросы на 127.0.0.1)
        return result

    # Case 2: resolv.conf указывает на localhost и нет per-link DNS → OK.
    if result["resolv_conf_already_localhost"] and not result["resolved_link_dns"]:
        result["fix_needed"] = False
        result["fix_method"] = None
        return result

    # Case 3: resolv.conf указывает на внешние DNS → нужен фикс.
    if nss and not result["resolv_conf_already_localhost"]:
        reasons.append(
            f"/etc/resolv.conf → внешние NS: {', '.join(nss)}"
        )

    # Case 4: systemd-resolved: per-link DNS от провайдера → нужен фикс.
    if result["systemd_resolved_active"] and result["resolved_link_dns"]:
        for link, dns in result["resolved_link_dns"]:
            if not all(ip.startswith("127.") or ip == "::1" for ip in dns):
                reasons.append(
                    f"systemd-resolved: link {link} → DHCP DNS: {', '.join(dns)}"
                )

    # ВАЖНО: Global DNS больше НЕ считаем причиной утечки.
    # Если все link'и на 127.0.0.1 (per_link_overridden=True) — мы уже вышли
    # в Case 1. Если per-link есть внешние DNS — это причина (Case 4).
    # Global DNS может содержать 77.88.8.8 от DHCP, но с Domains=~. в drop-in
    # он не используется — это НЕ утечка.

    if reasons and dnscrypt_ready:
        result["fix_needed"] = True
        result["leak_reasons"] = reasons
        result["fix_method"] = (
            "systemd_resolved" if result["systemd_resolved_active"]
            else "static_resolv_conf"
        )
    elif reasons and not dnscrypt_ready:
        result["fix_needed"] = False
        result["leak_reasons"] = reasons + [
            "DNSCrypt не активен или не слушает — фикс отменён (black-hole risk)"
        ]
    else:
        result["leak_reasons"] = reasons

    return result


# =============================================================================
#  STATE I/O
# =============================================================================
def _state_load() -> dict:
    try:
        if _STATE_FILE.exists():
            data = json.loads(_STATE_FILE.read_text())
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {"fixed": False, "method": None, "applied_at": None,
            "backup_path": None, "dropin_path": None}


def _state_save(data: dict) -> None:
    try:
        _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _STATE_FILE.write_text(json.dumps(data, indent=2))
        _STATE_FILE.chmod(0o600)
    except Exception as e:
        _warn(f"Не удалось сохранить state: {e}")


# =============================================================================
#  FIX — программные функции (без TUI)
# =============================================================================
def fix_resolv_conf_to_localhost(dry_run: bool = False,
                                 force: bool = False) -> Dict[str, Any]:
    """Программно направляет серверный DNS на 127.0.0.1 (DNSCrypt).

    Шаги:
      1. diagnose_resolv_conf() — проверить, нужен ли фикс.
      2. Pre-flight: DNSCrypt активен и слушает.
      3. Если fix_method == "systemd_resolved":
         - mkdir /etc/systemd/resolved.conf.d/
         - написать drop-in chimera-dns.conf с DNS=127.0.0.1, FallbackDNS=
           (пустой), DNSOverTLS=opportunistic
         - resolvectl dns-global set 127.0.0.1
         - resolvectl dns-default-route set false  (отключить per-link DNS)
         - systemctl restart systemd-resolved
         - resolvectl flush-caches
      4. Если fix_method == "static_resolv_conf":
         - cp /etc/resolv.conf /etc/resolv.conf.chimera.bak (если нет бэкапа)
         - rm symlink если есть
         - написать `nameserver 127.0.0.1\noptions timeout:1 attempts:1\n`
      5. Сохранить state.

    Параметр force=True — переприменить фикс даже если diagnose говорит
    fix_needed=False (например, per-link уже OK, но Global DNS от DHCP
    нужно убрать). Используется кнопкой [U] в TUI для re-apply поверх
    старого фикса.

    Возвращает dict:
      {"ok": bool, "method": str, "actions": [str, ...],
       "warnings": [str, ...], "error": str | None}
    """
    actions: List[str] = []
    warnings: List[str] = []

    diag = diagnose_resolv_conf()

    # При force=True — продолжаем даже если fix_needed=False.
    # Это для случая когда per-link уже OK (старый фикс), но Global DNS
    # от DHCP нужно убрать (новый фикс v4 с disable_dhcp_dns).
    if not diag["fix_needed"] and not force:
        return {
            "ok": False,
            "method": None,
            "actions": [],
            "warnings": diag["leak_reasons"],
            "error": "fix not needed or not possible (see warnings). "
                     "Use force=True to re-apply.",
        }

    # При force=True и fix_needed=False — используем fix_method из diagnose,
    # или fallback на systemd_resolved если systemd-resolved активен.
    method = diag["fix_method"]
    if method is None and force:
        if diag["systemd_resolved_active"]:
            method = "systemd_resolved"
        else:
            method = "static_resolv_conf"
    if method is None:
        return {
            "ok": False,
            "method": None,
            "actions": [],
            "warnings": diag["leak_reasons"],
            "error": "no fix method available",
        }

    # Pre-flight: DNSCrypt должен быть готов
    if not diag["dnscrypt_service_active"]:
        return {
            "ok": False, "method": method, "actions": [],
            "warnings": diag["leak_reasons"],
            "error": f"DNSCrypt service ({_DNSCRYPT_SERVICE}) не активен",
        }
    if not diag["dnscrypt_listening"]:
        return {
            "ok": False, "method": method, "actions": [],
            "warnings": diag["leak_reasons"],
            "error": "DNSCrypt не слушает на listen_addresses — фикс создаст black-hole",
        }

    if dry_run:
        actions.append(f"[dry-run] method={method}")
        return {"ok": True, "method": method, "actions": actions,
                "warnings": [], "error": None}

    # dhcp_dropin_paths — для сохранения в state (для rollback).
    dhcp_dropin_paths: List[str] = []

    # ── METHOD 1: systemd-resolved ──────────────────────────────────────────
    if method == "systemd_resolved":
        # 1a. drop-in override — задаёт Global DNS = 127.0.0.1.
        #     ВАЖНО: drop-in НЕ перебивает per-link DNS от DHCP — для этого
        #     нужен per-link override (шаг 1c) и persist-сервис (шаг 1f).
        try:
            _RESOLVED_DROPIN_DIR.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            return {"ok": False, "method": method, "actions": actions,
                    "warnings": warnings,
                    "error": f"нет прав на {_RESOLVED_DROPIN_DIR} (нужен root)"}

        dropin_content = (
            "# Chimera Project — DNS leak fix\n"
            "# Перенаправляет серверный DNS на локальный DNSCrypt-proxy.\n"
            "# Файл создан chimera/modules/resolv_conf_fix.py\n"
            "[Resolve]\n"
            f"DNS={_LOCAL_DNS}\n"
            "FallbackDNS=\n"
            "Domains=~.\n"
            "DNSOverTLS=opportunistic\n"
            "DNSSEC=allow-downgrade\n"
            "MulticastDNS=no\n"
            "LLMNR=no\n"
        )
        try:
            _RESOLVED_DROPIN_FILE.write_text(dropin_content)
            actions.append(f"создан drop-in: {_RESOLVED_DROPIN_FILE}")
        except Exception as e:
            return {"ok": False, "method": method, "actions": actions,
                    "warnings": warnings,
                    "error": f"не удалось создать drop-in: {e}"}

        # 1b. Global DNS НЕ задаём через `resolvectl dns 127.0.0.1`.
        #     На Ubuntu 24.04 (systemd 256+) парсер resolvectl пытается
        #     интерпретировать `127.0.0.1` как имя интерфейса и падает с
        #     `Failed to resolve interface "127.0.0.1": No such device`.
        #     Drop-in (шаг 1a) уже задаёт Global DNS через [Resolve] DNS=127.0.0.1
        #     и `Domains=~.` для перехвата всех запросов. Этого достаточно.
        # Глобальный default-route тоже НЕ трогаем — drop-in с Domains=~.
        # перехватывает все запросы на 127.0.0.1, даже если global DNS
        # содержит другие IP от DHCP (они просто не используются).

        # 1c. PER-LINK override — КРИТИЧЕСКИЙ шаг.
        #     Drop-in и Global DNS не перебивают per-link DNS, который
        #     systemd-resolved получает от DHCP (ens3: 77.88.8.8 на Yandex VPS).
        #     Per-link DNS имеет ПРИОРИТЕТ над Global. Поэтому нужно явно
        #     выставить per-link DNS = 127.0.0.1 для каждого активного link'а.
        links = _get_all_links()
        if links:
            for link in links:
                ok_l, cmd_str_l, err_l = _resolvectl_dns_set(link, _LOCAL_DNS)
                if ok_l:
                    actions.append(cmd_str_l)
                else:
                    warnings.append(f"{cmd_str_l}: {err_l}")
                ok_l, cmd_str_l, err_l = _resolvectl_default_route_set(link, False)
                if ok_l:
                    actions.append(cmd_str_l)
                else:
                    warnings.append(f"{cmd_str_l}: {err_l}")
        else:
            warnings.append("не найдено ни одного сетевого link'а — "
                            "per-link override пропущен")

        # 1e. systemctl restart systemd-resolved (применяет drop-in)
        r = _run(["systemctl", "restart", "systemd-resolved"],
                 capture=True, check=False)
        if r.returncode == 0:
            actions.append("systemctl restart systemd-resolved")
        else:
            warnings.append(
                f"systemctl restart systemd-resolved: rc={r.returncode}, "
                f"stderr={r.stderr.strip()[:120]}"
            )

        # 1f. PER-LINK override снова — после restart настройки link'ов
        #     сбрасываются. Делаем повторный проход.
        for link in links:
            _resolvectl_dns_set(link, _LOCAL_DNS)
            _resolvectl_default_route_set(link, False)

        # 1g. flush caches
        r = _run(["resolvectl", "flush-caches"],
                 capture=True, check=False)
        if r.returncode == 0:
            actions.append("resolvectl flush-caches")

        # 1h. PERSIST после ребута — systemd-сервис.
        #     После ребута systemd-resolved снова подхватит DHCP DNS от
        #     провайдера. Сервис chimera-dns-fix.service запускается после
        #     network-online.target и применяет per-link override.
        script_path, svc_path, perr = _write_persist_script_and_service()
        if perr:
            warnings.append(f"persist-сервис не создан: {perr}")
        elif script_path and svc_path:
            ok_p, perr2 = _enable_persist_service()
            if ok_p:
                actions.append(f"создан и активирован persist-сервис: "
                               f"{_PERSIST_SVC_NAME}")
            else:
                warnings.append(f"persist-сервис создан, но не активирован: {perr2}")

        # 1i. ОТКЛЮЧЕНИЕ DHCP DNS — КРИТИЧЕСКИЙ шаг для устранения утечки.
        #     Per-link override + drop-in НЕ убирают Global DNS 77.88.8.8 от
        #     DHCP. systemd-resolved отправляет запросы на ВСЕ Global DNS
        #     параллельно (parallel queries) — DNS Leak Test видит Yandex LLC.
        #     Решение: отключить получение DNS от DHCP на уровне network manager.
        #     - systemd-networkd: drop-in .network.d/chimera.conf с UseDNS=false.
        #     - NetworkManager: nmcli ... ignore-auto-dns yes.
        #     Это убирает провайдерский DNS из Global DNS → остаётся только
        #     127.0.0.1 из drop-in → утечки точно нет.
        dhcp_result = disable_dhcp_dns_on_all_links()
        if dhcp_result["ok"]:
            actions.append(f"отключён DHCP DNS ({dhcp_result['manager']})")
            for a in dhcp_result["actions"]:
                actions.append(a)
            if dhcp_result["warnings"]:
                warnings.extend(dhcp_result["warnings"])
            # Сохраняем dropin_paths в state для rollback.
            dhcp_dropin_paths = dhcp_result.get("dropin_paths", [])
        else:
            warnings.append(f"не удалось отключить DHCP DNS: {dhcp_result.get('error')}")
            dhcp_dropin_paths = []

        # 1j. restart systemd-resolved + повторный per-link override — после
        #     networkctl reconfigure настройки link'ов могли сброситься.
        _run(["systemctl", "restart", "systemd-resolved"],
             capture=True, check=False)
        for link in links:
            _resolvectl_dns_set(link, _LOCAL_DNS)
            _resolvectl_default_route_set(link, False)
        _run(["resolvectl", "flush-caches"], capture=True, check=False)

    # ── METHOD 2: static resolv.conf ────────────────────────────────────────
    elif method == "static_resolv_conf":
        # 2a. backup
        if not _BACKUP.exists() and _RESOLV_CONF.exists():
            try:
                shutil.copy2(str(_RESOLV_CONF), str(_BACKUP))
                actions.append(f"бэкап: {_RESOLV_CONF} → {_BACKUP}")
            except Exception as e:
                return {"ok": False, "method": method, "actions": actions,
                        "warnings": warnings,
                        "error": f"не удалось создать бэкап: {e}"}
        elif _BACKUP.exists():
            actions.append(f"бэкап уже существует: {_BACKUP} (не перезаписываем)")

        # 2b. remove symlink if present
        if _RESOLV_CONF.is_symlink():
            try:
                _RESOLV_CONF.unlink()
                actions.append("удалён симлинк /etc/resolv.conf")
            except Exception as e:
                return {"ok": False, "method": method, "actions": actions,
                        "warnings": warnings,
                        "error": f"не удалось удалить симлинк: {e}"}

        # 2c. write new resolv.conf
        new_content = (
            "# Chimera Project — DNS leak fix\n"
            "# Серверный DNS направлен на локальный DNSCrypt-proxy.\n"
            "# Файл создан chimera/modules/resolv_conf_fix.py\n"
            "# Восстановление: удалите этот файл и переименуйте\n"
            f"# /etc/resolv.conf.chimera.bak → /etc/resolv.conf\n"
            f"nameserver {_LOCAL_DNS}\n"
            "options timeout:1 attempts:1\n"
        )
        try:
            _RESOLV_CONF.write_text(new_content)
            actions.append(f"записан новый /etc/resolv.conf → nameserver {_LOCAL_DNS}")
        except PermissionError:
            return {"ok": False, "method": method, "actions": actions,
                    "warnings": warnings,
                    "error": "нет прав на запись /etc/resolv.conf (нужен root)"}
        except Exception as e:
            return {"ok": False, "method": method, "actions": actions,
                    "warnings": warnings,
                    "error": f"не удалось записать resolv.conf: {e}"}

    else:
        return {"ok": False, "method": method, "actions": actions,
                "warnings": warnings,
                "error": f"неизвестный метод: {method}"}

    # ── Сохранить state ─────────────────────────────────────────────────────
    _state_save({
        "fixed": True,
        "method": method,
        "applied_at": datetime.now().isoformat(),
        "backup_path": str(_BACKUP) if _BACKUP.exists() else None,
        "dropin_path": str(_RESOLVED_DROPIN_FILE)
                       if method == "systemd_resolved" and _RESOLVED_DROPIN_FILE.exists()
                       else None,
        "persist_service": method == "systemd_resolved"
                           and _PERSIST_SVC_PATH.exists(),
        "dhcp_dns_disabled": bool(dhcp_dropin_paths) or
                             (method == "systemd_resolved" and
                              any("ignore-auto-dns" in a for a in actions)),
        "dhcp_dropin_paths": dhcp_dropin_paths,
    })

    _ok("DNS направлен на локальный DNSCrypt-proxy (127.0.0.1)")
    return {"ok": True, "method": method, "actions": actions,
            "warnings": warnings, "error": None}


def rollback_resolv_conf() -> Dict[str, Any]:
    """Откатывает изменения fix_resolv_conf_to_localhost().

    Шаги:
      1. Остановить и удалить persist-сервис chimera-dns-fix.service.
      2. Если есть drop-in /etc/systemd/resolved.conf.d/chimera-dns.conf —
         удалить, перезапустить systemd-resolved.
      3. Восстановить per-link default-route (вернуть true) для каждого link'а.
      4. Восстановить DHCP DNS (вернуть UseDNS=true / ignore-auto-dns no).
      5. Если есть бэкап /etc/resolv.conf.chimera.bak — восстановить.
      6. flush-caches.
      7. Обновить state.

    Возвращает dict как fix_resolv_conf_to_localhost().
    """
    actions: List[str] = []
    warnings: List[str] = []

    state = _state_load()
    if not state.get("fixed"):
        return {"ok": False, "method": None, "actions": [],
                "warnings": [],
                "error": "фикс не был применён (state.fixed=False)"}

    method = state.get("method")

    # 1. Остановить и удалить persist-сервис
    ok_ds, err_ds = _disable_persist_service()
    if ok_ds:
        actions.append(f"остановлен и удалён persist-сервис: {_PERSIST_SVC_NAME}")
    else:
        warnings.append(f"ошибка удаления persist-сервиса: {err_ds}")

    # 2. Удалить drop-in если есть
    if _RESOLVED_DROPIN_FILE.exists():
        try:
            _RESOLVED_DROPIN_FILE.unlink()
            actions.append(f"удалён drop-in: {_RESOLVED_DROPIN_FILE}")
        except Exception as e:
            warnings.append(f"не удалось удалить drop-in: {e}")

        # Перезапустить systemd-resolved чтобы он подхватил отсутствие drop-in
        r = _run(["systemctl", "restart", "systemd-resolved"],
                 capture=True, check=False)
        if r.returncode == 0:
            actions.append("systemctl restart systemd-resolved")
        else:
            warnings.append(
                f"systemctl restart systemd-resolved: rc={r.returncode}"
            )

        # Восстановить per-link default-route = true (вернуть DHCP DNS).
        for link in _get_all_links():
            ok_l, _, err_l = _resolvectl_default_route_set(link, True)
            if ok_l:
                actions.append(f"resolvectl default-route {link} true (restore)")
            else:
                warnings.append(f"default-route {link} true: {err_l}")

        # Global default-route = true
        ok_g, _, err_g = _resolvectl_default_route_set(None, True)
        if ok_g:
            actions.append("resolvectl default-route true (global restore)")

        # flush caches
        _run(["resolvectl", "flush-caches"], capture=True, check=False)

    # 3. Восстановить DHCP DNS — вернуть UseDNS=true / ignore-auto-dns no.
    #    Это откат disable_dhcp_dns_on_all_links() из fix-шага 1i.
    if state.get("dhcp_dns_disabled"):
        dhcp_result = enable_dhcp_dns_on_all_links()
        if dhcp_result["ok"]:
            actions.append(f"восстановлен DHCP DNS ({dhcp_result['manager']})")
            for a in dhcp_result["actions"]:
                actions.append(a)
            if dhcp_result["warnings"]:
                warnings.extend(dhcp_result["warnings"])
        else:
            warnings.append(f"не удалось восстановить DHCP DNS: {dhcp_result.get('error')}")

    # 4. Восстановить resolv.conf из бэкапа
    if _BACKUP.exists():
        try:
            # Если текущий resolv.conf — наш статичный файл, удалить.
            if _RESOLV_CONF.exists() and not _RESOLV_CONF.is_symlink():
                _RESOLV_CONF.unlink()
            shutil.copy2(str(_BACKUP), str(_RESOLV_CONF))
            actions.append(f"восстановлен /etc/resolv.conf из {_BACKUP}")
            # Не удаляем бэкап — пусть остаётся как evidence.
        except Exception as e:
            warnings.append(f"не удалось восстановить resolv.conf: {e}")

    # 4. Обновить state
    _state_save({
        "fixed": False,
        "method": None,
        "applied_at": None,
        "backup_path": str(_BACKUP) if _BACKUP.exists() else None,
        "dropin_path": None,
        "persist_service": False,
        "rolled_back_at": datetime.now().isoformat(),
    })

    _ok("DNS откачен к прежнему состоянию")
    return {"ok": True, "method": method, "actions": actions,
            "warnings": warnings, "error": None}


# =============================================================================
#  ИНТЕРАКТИВНЫЙ ЭКРАН (TUI)
# =============================================================================
def _print_diagnosis(diag: Dict[str, Any]) -> None:
    """Рисует диагностический блок (без _box_bottom — меню ниже дорисует)."""
    # /etc/resolv.conf
    _box_row(f"  {BOLD}/etc/resolv.conf:{NC}")
    if not diag["resolv_conf_exists"]:
        _box_row(f"    {RED}не существует{NC}")
    else:
        if diag["resolv_conf_is_symlink"]:
            _box_row(f"    {DIM}симлинк → {diag['resolv_conf_symlink_target']}{NC}")
        nss = diag["resolv_conf_nameservers"]
        if nss:
            for ip in nss:
                col = GREEN if (ip.startswith("127.") or ip == "::1") else RED
                _box_row(f"    nameserver {col}{ip}{NC}")
        else:
            _box_row(f"    {DIM}nameserver — не задан{NC}")
        if diag["resolv_conf_already_localhost"]:
            _box_row(f"    {GREEN}✓ уже на localhost{NC}")
    _box_row()

    # systemd-resolved
    _box_row(f"  {BOLD}systemd-resolved:{NC}")
    if diag["systemd_resolved_active"]:
        _box_row(f"    {GREEN}активен{NC}")
        # Global DNS — informational, не критичен (drop-in с Domains=~. перехватывает)
        gdns = diag["resolved_global_dns"]
        if gdns:
            for ip in gdns:
                col = GREEN if (ip.startswith("127.") or ip == "::1") else DIM
                _box_row(f"    Global:  {col}{ip}{NC}")
        else:
            _box_row(f"    Global:  {DIM}не задан{NC}")
        # Per-link DNS — ГЛАВНЫЙ критерий утечки
        for link, dns_list in diag["resolved_link_dns"]:
            for ip in dns_list:
                col = GREEN if (ip.startswith("127.") or ip == "::1") else RED
                _box_row(f"    Link {link}: {col}{ip}{NC}")
        # Per-link default-route
        for link, dr in diag.get("resolved_link_default_routes", []):
            col = GREEN if not dr else RED
            label = "false ✓" if not dr else "true ✗"
            _box_row(f"    Link {link} default-route: {col}{label}{NC}")
    else:
        _box_row(f"    {DIM}не активен (static /etc/resolv.conf){NC}")
    _box_row()

    # DNSCrypt
    _box_row(f"  {BOLD}DNSCrypt-proxy:{NC}")
    if diag["dnscrypt_service_active"]:
        _box_row(f"    сервис:  {GREEN}active{NC}")
    else:
        _box_row(f"    сервис:  {RED}не активен{NC}")
    if diag["dnscrypt_listen"]:
        addr, port = diag["dnscrypt_listen"]
        listen_str = f"{addr}:{port}"
        if diag["dnscrypt_listening"]:
            _box_row(f"    listen:  {GREEN}{listen_str} ✓ слушает{NC}")
        else:
            _box_row(f"    listen:  {RED}{listen_str} ✗ НЕ слушает{NC}")
    else:
        _box_row(f"    listen:  {DIM}не определён (TOML не найден){NC}")
    _box_sep()

    # Итог диагностики
    if diag["per_link_overridden"]:
        # Все link'и на 127.0.0.1 + default-route=false → per-link OK.
        # НО! Global DNS от DHCP всё ещё может вызывать утечку (parallel queries).
        ext_global = [ip for ip in diag["resolved_global_dns"]
                      if not (ip.startswith("127.") or ip == "::1")]
        if not ext_global:
            # Global DNS чист — утечки точно нет.
            _box_row(f"  {GREEN}✓ УТЕЧКИ НЕТ — per-link override активен,{NC}")
            _box_row(f"  {GREEN}  Global DNS чист (только 127.0.0.1).{NC}")
        else:
            # per-link OK, но Global DNS содержит внешние IP от DHCP.
            # systemd-resolved отправляет запросы на ВСЕ Global DNS параллельно
            # — DNS Leak Test видит Yandex LLC. Это утечка!
            _box_row(f"  {YELLOW}~ PER-LINK OK, НО Global DNS содержит внешние IP{NC}")
            _box_row(f"  {YELLOW}  от DHCP: {', '.join(ext_global)}{NC}")
            _box_row(f"  {YELLOW}  systemd-resolved отправляет запросы на все Global{NC}")
            _box_row(f"  {YELLOW}  DNS параллельно — DNS Leak Test видит Yandex.{NC}")
            _box_sep()
            _box_row(f"  {GREEN}✓ Можно исправить: отключить DHCP DNS на уровне{NC}")
            _box_row(f"  {GREEN}  network manager (systemd-networkd drop-in или{NC}")
            _box_row(f"  {GREEN}  NetworkManager ignore-auto-dns).{NC}")
    elif diag["fix_needed"]:
        _box_row(f"  {RED}⚠ УТЕЧКА DNS ОБНАРУЖЕНА{NC}")
        for reason in diag["leak_reasons"]:
            _box_row(f"    {RED}• {reason}{NC}")
        _box_sep()
        _box_row(f"  {GREEN}✓ Можно исправить автоматически{NC}")
        method_label = {
            "systemd_resolved": "systemd-resolved drop-in + resolvectl",
            "static_resolv_conf": "static /etc/resolv.conf rewrite",
        }.get(diag["fix_method"], diag["fix_method"])
        _box_row(f"    Метод:  {CYAN}{method_label}{NC}")
    elif diag["leak_reasons"]:
        _box_row(f"  {YELLOW}~ Утечка обнаружена, но авто-фикс невозможен:{NC}")
        for reason in diag["leak_reasons"]:
            _box_row(f"    {YELLOW}• {reason}{NC}")
    else:
        _box_row(f"  {GREEN}✓ Утечки не обнаружено — фикс не требуется{NC}")


def _print_fix_state_badge(state: dict) -> None:
    """Если фикс уже применён — рисует зелёную плашку об этом."""
    if not state.get("fixed"):
        return
    method = state.get("method", "?")
    applied = state.get("applied_at", "")
    if applied:
        applied_short = applied[:19].replace("T", " ")
    else:
        applied_short = "?"
    method_label = {
        "systemd_resolved": "systemd-resolved drop-in",
        "static_resolv_conf": "static /etc/resolv.conf",
    }.get(method, method)
    _box_row(f"  {GREEN}✓ Фикс применён:{NC} {CYAN}{method_label}{NC}  "
             f"{DIM}({applied_short}){NC}")
    _box_row(f"  {DIM}DNS сервера направлены на 127.0.0.1 (DNSCrypt-proxy){NC}")
    if state.get("persist_service"):
        _box_row(f"  {DIM}Persist: chimera-dns-fix.service активен (переживёт ребут){NC}")
    elif method == "systemd_resolved":
        _box_row(f"  {YELLOW}⚠ persist-сервис не активен — после ребута DHCP DNS может вернуться{NC}")


def _screen_fix_apply(diag: Dict[str, Any]) -> None:
    """Экран применения фикса с подтверждением и результатом."""
    os.system("clear")
    print()
    _box_top("🔧  ПРИМЕНЕНИЕ ФИКСА /etc/resolv.conf")
    _box_row()
    method_label = {
        "systemd_resolved": "systemd-resolved drop-in + resolvectl",
        "static_resolv_conf": "static /etc/resolv.conf rewrite",
    }.get(diag["fix_method"], diag["fix_method"])
    _box_row(f"  Метод:  {CYAN}{method_label}{NC}")
    _box_row(f"  Цель:   перенаправить серверный DNS на {CYAN}127.0.0.1{NC} "
             f"(DNSCrypt-proxy)")
    _box_row()
    if diag["fix_method"] == "systemd_resolved":
        _box_row(f"  {BOLD}Будет выполнено:{NC}")
        _box_row(f"    {DIM}• создать drop-in /etc/systemd/resolved.conf.d/chimera-dns.conf{NC}")
        _box_row(f"    {DIM}  (DNS=127.0.0.1, Domains=~. — Global DNS на DNSCrypt){NC}")
        _box_row(f"    {DIM}• для каждого сетевого link'а (ens3/eth0/...):{NC}")
        _box_row(f"    {DIM}    resolvectl dns LINK 127.0.0.1  (per-link override){NC}")
        _box_row(f"    {DIM}    resolvectl default-route LINK false{NC}")
        _box_row(f"    {DIM}• systemctl restart systemd-resolved{NC}")
        _box_row(f"    {DIM}• повторный per-link override (после restart){NC}")
        _box_row(f"    {DIM}• resolvectl flush-caches{NC}")
        _box_row(f"    {DIM}• создать и активировать persist-сервис{NC}")
        _box_row(f"    {DIM}  chimera-dns-fix.service (переживёт ребут){NC}")
        _box_sep()
        _box_row(f"  {YELLOW}Per-link override — КРИТИЧЕСКИЙ шаг.{NC}")
        _box_row(f"  {YELLOW}DHCP-сервер провайдера отдаёт per-link DNS (Yandex),{NC}")
        _box_row(f"  {YELLOW}который имеет приоритет над Global. Drop-in с Domains=~.{NC}")
        _box_row(f"  {YELLOW}перехватывает запросы, но per-link override гарантирует,{NC}")
        _box_row(f"  {YELLOW}что link не используется для default-route запросов.{NC}")
        _box_sep()
        _box_row(f"  {DIM}Global resolvectl dns/default-route НЕ вызываем — на Ubuntu 24.04{NC}")
        _box_row(f"  {DIM}парсер падает с 'Failed to resolve interface'. Global DNS{NC}")
        _box_row(f"  {DIM}задаётся через drop-in, этого достаточно.{NC}")
        _box_sep()
        _box_row(f"  {YELLOW}КРИТИЧЕСКИЙ шаг: отключение DHCP DNS{NC}")
        _box_row(f"  {YELLOW}  Per-link override НЕ убирает Global DNS 77.88.8.8 от DHCP.{NC}")
        _box_row(f"  {YELLOW}  systemd-resolved отправляет запросы на все Global DNS{NC}")
        _box_row(f"  {YELLOW}  параллельно — DNS Leak Test видит Yandex LLC.{NC}")
        _box_row(f"  {YELLOW}  Решение: drop-in .network.d/chimera.conf с UseDNS=false{NC}")
        _box_row(f"  {YELLOW}  (systemd-networkd) или nmcli ignore-auto-dns (NetworkManager).{NC}")
        _box_row(f"    {DIM}• определить network manager (systemd-networkd / NetworkManager){NC}")
        _box_row(f"    {DIM}• создать drop-in /etc/systemd/network/<file>.network.d/chimera-dns.conf{NC}")
        _box_row(f"    {DIM}  с [DHCPv4] UseDNS=false + [DHCPv6] UseDNS=false{NC}")
        _box_row(f"    {DIM}• networkctl reload (для networkd — без reconfigure, безопасно){NC}")
        _box_row(f"    {DIM}• или nmcli connection modify ... ignore-auto-dns yes (для NM){NC}")
    elif diag["fix_method"] == "static_resolv_conf":
        _box_row(f"  {BOLD}Будет выполнено:{NC}")
        _box_row(f"    {DIM}• бэкап /etc/resolv.conf → /etc/resolv.conf.chimera.bak{NC}")
        _box_row(f"    {DIM}• перезапись на nameserver 127.0.0.1{NC}")
    _box_row()
    _box_row(f"  {GREEN}Откат доступен в любой момент — кнопка R в меню.{NC}")
    _box_bottom()

    print()
    try:
        confirm = input(
            f"{CYAN}Применить фикс? [Y/n]: {NC}"
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        confirm = "n"
    if confirm not in ("", "y", "yes", "д", "да"):
        return

    print()
    _info("Применяем фикс...")
    result = fix_resolv_conf_to_localhost()
    print()
    if result["ok"]:
        _ok("Фикс применён успешно!")
        for action in result["actions"]:
            print(f"  {GREEN}✓{NC} {action}")
        if result["warnings"]:
            _warn("Предупреждения:")
            for w in result["warnings"]:
                print(f"  {YELLOW}•{NC} {w}")
        print()
        _info("Рекомендация: перезапустите DNS Leak Test для проверки.")
    else:
        _err(f"Фикс не удался: {result.get('error')}")
        for w in result.get("warnings", []):
            print(f"  {YELLOW}•{NC} {w}")
    print()
    input(f"{BLUE}Нажмите Enter для возврата в меню...{NC}")


def _screen_rollback() -> None:
    """Экран отката с подтверждением и результатом."""
    os.system("clear")
    print()
    _box_top("🔄  ОТКАТ ФИКСА /etc/resolv.conf")
    _box_row()
    _box_row(f"  {BOLD}Будет выполнено:{NC}")
    _box_row(f"    {DIM}• остановить и удалить persist-сервис chimera-dns-fix.service{NC}")
    _box_row(f"    {DIM}• удалить drop-in /etc/systemd/resolved.conf.d/chimera-dns.conf{NC}")
    _box_row(f"    {DIM}• для каждого link'а: resolvectl default-route LINK true{NC}")
    _box_row(f"    {DIM}  (вернуть per-link DHCP DNS){NC}")
    _box_row(f"    {DIM}• восстановить DHCP DNS: удалить .network.d/chimera-dns.conf{NC}")
    _box_row(f"    {DIM}  (systemd-networkd) или nmcli ignore-auto-dns no (NetworkManager){NC}")
    _box_row(f"    {DIM}• networkctl reload (для systemd-networkd — без reconfigure){NC}")
    _box_row(f"    {DIM}• systemctl restart systemd-resolved{NC}")
    _box_row(f"    {DIM}• восстановить /etc/resolv.conf из бэкапа (если есть){NC}")
    _box_row(f"    {DIM}• resolvectl flush-caches{NC}")
    _box_row()
    _box_row(f"  {YELLOW}После отката DNS снова будет идти через провайдера —{NC}")
    _box_row(f"  {YELLOW}возможна утечка DNS (как до фикса).{NC}")
    _box_bottom()

    print()
    try:
        confirm = input(
            f"{CYAN}Откатить фикс? [y/N]: {NC}"
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        confirm = "n"
    if confirm not in ("y", "yes", "д", "да"):
        return

    print()
    _info("Откатываем...")
    result = rollback_resolv_conf()
    print()
    if result["ok"]:
        _ok("Откат выполнен успешно!")
        for action in result["actions"]:
            print(f"  {GREEN}✓{NC} {action}")
        if result["warnings"]:
            _warn("Предупреждения:")
            for w in result["warnings"]:
                print(f"  {YELLOW}•{NC} {w}")
    else:
        _err(f"Откат не удался: {result.get('error')}")
        for w in result.get("warnings", []):
            print(f"  {YELLOW}•{NC} {w}")
    print()
    input(f"{BLUE}Нажмите Enter для возврата в меню...{NC}")


def _screen_fix_reapply(diag: Dict[str, Any]) -> None:
    """Экран переприменения фикса (re-apply) с подтверждением и результатом.

    Используется когда state.fixed=True (старый фикс применён), но
    diagnose показывает что есть внешние Global DNS от DHCP (parallel
    queries утечка). Вызывает fix_resolv_conf_to_localhost(force=True)
    — это применяет все шаги включая disable_dhcp_dns_on_all_links.
    """
    os.system("clear")
    print()
    _box_top("🔄  ПЕРЕПРИМЕНИТЬ ФИКС (RE-APPLY v4)")
    _box_row()
    _box_row(f"  {YELLOW}Фикс уже применён, но Global DNS содержит внешние IP{NC}")
    _box_row(f"  {YELLOW}от DHCP — это вызывает утечку (parallel queries).{NC}")
    _box_row()
    _box_row(f"  {BOLD}Будет переприменено (force=True):{NC}")
    _box_row(f"    {DIM}• drop-in /etc/systemd/resolved.conf.d/chimera-dns.conf{NC}")
    _box_row(f"    {DIM}• per-link override: resolvectl dns LINK 127.0.0.1{NC}")
    _box_row(f"    {DIM}• per-link default-route: resolvectl default-route LINK false{NC}")
    _box_row(f"    {DIM}• systemctl restart systemd-resolved{NC}")
    _box_row(f"    {DIM}• persist-сервис chimera-dns-fix.service{NC}")
    _box_row(f"    {GREEN}• ОТКЛЮЧИТЬ DHCP DNS (КРИТИЧЕСКИЙ шаг):{NC}")
    _box_row(f"    {GREEN}  - systemd-networkd: drop-in .network.d/chimera-dns.conf{NC}")
    _box_row(f"    {GREEN}  - NetworkManager: nmcli ignore-auto-dns yes{NC}")
    _box_row(f"    {GREEN}  - networkctl reload (безопасно, без reconfigure){NC}")
    _box_row()
    _box_row(f"  {GREEN}После re-apply Global DNS будет содержать только 127.0.0.1.{NC}")
    _box_row(f"  {GREEN}DNS Leak Test не должен видеть Yandex LLC.{NC}")
    _box_bottom()

    print()
    try:
        confirm = input(
            f"{CYAN}Переприменить фикс? [Y/n]: {NC}"
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        confirm = "n"
    if confirm not in ("", "y", "yes", "д", "да"):
        return

    print()
    _info("Переприменяем фикс (force=True)...")
    result = fix_resolv_conf_to_localhost(force=True)
    print()
    if result["ok"]:
        _ok("Фикс переприменён успешно!")
        for action in result["actions"]:
            print(f"  {GREEN}✓{NC} {action}")
        if result["warnings"]:
            _warn("Предупреждения:")
            for w in result["warnings"]:
                print(f"  {YELLOW}•{NC} {w}")
        print()
        _info("Рекомендация: перезапустите DNS Leak Test для проверки.")
    else:
        _err(f"Re-apply не удался: {result.get('error')}")
        for w in result.get("warnings", []):
            print(f"  {YELLOW}•{NC} {w}")
    print()
    input(f"{BLUE}Нажмите Enter для возврата в меню...{NC}")


def do_fix_resolv_conf_interactive() -> None:
    """Интерактивный TUI-экран управления /etc/resolv.conf.

    Зацикленный: после каждого действия экран перерисовывается с новой
    диагностикой. Структура (в едином стиле проекта):
      1. Заголовок + описание
      2. Блок диагностики (resolv.conf / systemd-resolved / DNSCrypt / итог)
      3. Плашка «фикс применён» (если есть)
      4. Меню действий в отдельной рамке:
         [F] Исправить автоматически  (только если fix_needed и не применён)
         [U] Переприменить фикс       (если применён, но Global DNS от DHCP)
         [R] Откатить фикс            (только если уже применён)
         [D] Повторить диагностику
         [Q] Выход
    """
    while True:
        os.system("clear")
        print()

        # ── Диагностика ──────────────────────────────────────────────────────
        diag = diagnose_resolv_conf()
        state = _state_load()
        already_fixed = state.get("fixed", False)

        # Определяем: есть ли внешние Global DNS от DHCP (нужен re-apply).
        ext_global = [ip for ip in diag["resolved_global_dns"]
                      if not (ip.startswith("127.") or ip == "::1")]
        needs_reapply = (already_fixed and bool(ext_global)
                         and diag["dnscrypt_service_active"]
                         and diag["dnscrypt_listening"])

        _box_top("🔧  ИСПРАВЛЕНИЕ /etc/resolv.conf (DNS LEAK FIX)")
        _box_desc(
            "Автоматическое перенаправление серверного DNS на локальный "
            "DNSCrypt-proxy (127.0.0.1). Решает проблему утечки DNS к "
            "провайдерским резолверам (Yandex, Selectel, Timeweb — "
            "отдаваемым через DHCP на Ubuntu 24.04 / Fedora)."
        )
        _box_sep()
        _print_diagnosis(diag)
        if already_fixed:
            _box_sep()
            _print_fix_state_badge(state)
        _box_bottom()

        print()

        # ── Меню действий ───────────────────────────────────────────────────
        _box_top("ДЕЙСТВИЯ")
        if diag["fix_needed"]:
            _box_item("F", f"{GREEN}Исправить автоматически{NC}  "
                           f"(направить DNS → 127.0.0.1 = DNSCrypt-proxy)")
        if needs_reapply:
            _box_item("U", f"{GREEN}Переприменить фикс (re-apply v4){NC}  "
                           f"{YELLOW}← отключить DHCP DNS{NC}")
        if already_fixed:
            _box_item("R", f"{YELLOW}Откатить фикс{NC}  "
                           f"(вернуть /etc/resolv.conf как было)")
        _box_item("D", "Повторить диагностику")
        _box_item("Q", f"{DIM}Выход в предыдущее меню{NC}")
        _box_bottom()

        print()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if ch == "f" and diag["fix_needed"]:
            _screen_fix_apply(diag)
        elif ch == "u" and needs_reapply:
            _screen_fix_reapply(diag)
        elif ch == "r" and already_fixed:
            _screen_rollback()
        elif ch == "d":
            # Перерисуемся на следующей итерации цикла (диагностика обновится).
            continue
        elif ch in ("q", "0", ""):
            return
        else:
            _warn("Неверный выбор")
            time.sleep(1)


# =============================================================================
#  Точка входа из _core.py
# =============================================================================
# (экспортируем публичные функции через __all__)
__all__ = [
    "diagnose_resolv_conf",
    "fix_resolv_conf_to_localhost",
    "rollback_resolv_conf",
    "do_fix_resolv_conf_interactive",
]
