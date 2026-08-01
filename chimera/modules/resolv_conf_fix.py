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


def diagnose_resolv_conf() -> Dict[str, Any]:
    """Полная диагностика состояния DNS-резолвера.

    Возвращает dict:
      {
        "resolv_conf_path": str,
        "resolv_conf_exists": bool,
        "resolv_conf_is_symlink": bool,
        "resolv_conf_symlink_target": str | None,
        "resolv_conf_nameservers": [str, ...],
        "resolv_conf_already_localhost": bool,  # все NS — 127.*
        "systemd_resolved_active": bool,
        "resolved_global_dns": [str, ...],
        "resolved_link_dns": [(link, [ip, ...]), ...],
        "dnscrypt_listen": (addr, port) | None,
        "dnscrypt_listening": bool,
        "dnscrypt_service_active": bool,
        "fix_needed": bool,            # есть ли утечка по диагностике
        "fix_method": "systemd_resolved" | "static_resolv_conf" | None,
        "leak_reasons": [str, ...],    # почему диагностика решила что fix_needed
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

    # Решение: нужен ли фикс?
    reasons: List[str] = []

    # Если DNSCrypt активен и слушает — есть смысл перенаправлять на него.
    dnscrypt_ready = (
        result["dnscrypt_service_active"]
        and result["dnscrypt_listen"] is not None
        and result["dnscrypt_listening"]
    )

    if result["resolv_conf_already_localhost"] and not result["resolved_link_dns"]:
        # Уже OK — resolv.conf указывает на localhost, per-link DNS нет.
        result["fix_needed"] = False
        result["fix_method"] = None
        return result

    # resolv.conf указывает на внешние DNS — нужен фикс
    if nss and not result["resolv_conf_already_localhost"]:
        reasons.append(
            f"/etc/resolv.conf → внешние NS: {', '.join(nss)}"
        )

    # systemd-resolved: per-link DNS от провайдера
    if result["systemd_resolved_active"] and result["resolved_link_dns"]:
        for link, dns in result["resolved_link_dns"]:
            if not all(ip.startswith("127.") or ip == "::1" for ip in dns):
                reasons.append(
                    f"systemd-resolved: link {link} → DHCP DNS: {', '.join(dns)}"
                )

    # systemd-resolved: global DNS — внешний
    if result["systemd_resolved_active"] and result["resolved_global_dns"]:
        if not all(ip.startswith("127.") or ip == "::1"
                   for ip in result["resolved_global_dns"]):
            reasons.append(
                f"systemd-resolved: global DNS → {', '.join(result['resolved_global_dns'])}"
            )

    if reasons and dnscrypt_ready:
        result["fix_needed"] = True
        result["leak_reasons"] = reasons
        # Метод: если systemd-resolved активен → его и настраиваем.
        # Иначе — статичная замена resolv.conf.
        result["fix_method"] = (
            "systemd_resolved" if result["systemd_resolved_active"]
            else "static_resolv_conf"
        )
    elif reasons and not dnscrypt_ready:
        # Утечка есть, но DNSCrypt не готов — фикс невозможен без black-hole.
        result["fix_needed"] = False  # не можем применить фикс
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
def fix_resolv_conf_to_localhost(dry_run: bool = False) -> Dict[str, Any]:
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

    Возвращает dict:
      {"ok": bool, "method": str, "actions": [str, ...],
       "warnings": [str, ...], "error": str | None}
    """
    actions: List[str] = []
    warnings: List[str] = []

    diag = diagnose_resolv_conf()

    if not diag["fix_needed"]:
        return {
            "ok": False,
            "method": None,
            "actions": [],
            "warnings": diag["leak_reasons"],
            "error": "fix not needed or not possible (see warnings)",
        }

    method = diag["fix_method"]
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

    # ── METHOD 1: systemd-resolved ──────────────────────────────────────────
    if method == "systemd_resolved":
        # 1a. drop-in override
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

        # 1b. resolvectl dns-global set 127.0.0.1
        r = _run(["resolvectl", "dns-global", "set", _LOCAL_DNS],
                 capture=True, check=False)
        if r.returncode == 0:
            actions.append(f"resolvectl dns-global set {_LOCAL_DNS}")
        else:
            warnings.append(
                f"resolvectl dns-global set: rc={r.returncode}, "
                f"stderr={r.stderr.strip()[:120]}"
            )

        # 1c. resolvectl dns-default-route set false
        #     отключает per-link DNS (чтобы DHCP провайдера не подсовывал свой)
        r = _run(["resolvectl", "dns-default-route", "set", "false"],
                 capture=True, check=False)
        if r.returncode == 0:
            actions.append("resolvectl dns-default-route set false")
        else:
            warnings.append(
                f"resolvectl dns-default-route set false: rc={r.returncode}, "
                f"stderr={r.stderr.strip()[:120]}"
            )

        # 1d. systemctl restart systemd-resolved (применяет drop-in)
        r = _run(["systemctl", "restart", "systemd-resolved"],
                 capture=True, check=False)
        if r.returncode == 0:
            actions.append("systemctl restart systemd-resolved")
        else:
            warnings.append(
                f"systemctl restart systemd-resolved: rc={r.returncode}, "
                f"stderr={r.stderr.strip()[:120]}"
            )

        # 1e. flush caches
        r = _run(["resolvectl", "flush-caches"],
                 capture=True, check=False)
        if r.returncode == 0:
            actions.append("resolvectl flush-caches")

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
    })

    _ok("DNS направлен на локальный DNSCrypt-proxy (127.0.0.1)")
    return {"ok": True, "method": method, "actions": actions,
            "warnings": warnings, "error": None}


def rollback_resolv_conf() -> Dict[str, Any]:
    """Откатывает изменения fix_resolv_conf_to_localhost().

    Шаги:
      1. Если есть drop-in /etc/systemd/resolved.conf.d/chimera-dns.conf —
         удалить, перезапустить systemd-resolved.
      2. Если есть бэкап /etc/resolv.conf.chimera.bak — восстановить.
      3. Снять resolvectl dns-default-route (вернуть в default).
      4. flush-caches.
      5. Обновить state.

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

    # 1. Удалить drop-in если есть
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

        # Снять dns-default-route (вернуть в default true)
        r = _run(["resolvectl", "dns-default-route", "set", "true"],
                 capture=True, check=False)
        if r.returncode == 0:
            actions.append("resolvectl dns-default-route set true (restore)")

        # flush caches
        _run(["resolvectl", "flush-caches"], capture=True, check=False)

    # 2. Восстановить resolv.conf из бэкапа
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

    # 3. Обновить state
    _state_save({
        "fixed": False,
        "method": None,
        "applied_at": None,
        "backup_path": str(_BACKUP) if _BACKUP.exists() else None,
        "dropin_path": None,
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
        # Global DNS
        gdns = diag["resolved_global_dns"]
        if gdns:
            for ip in gdns:
                col = GREEN if (ip.startswith("127.") or ip == "::1") else YELLOW
                _box_row(f"    Global:  {col}{ip}{NC}")
        else:
            _box_row(f"    Global:  {DIM}не задан{NC}")
        # Per-link DNS
        for link, dns_list in diag["resolved_link_dns"]:
            for ip in dns_list:
                col = GREEN if (ip.startswith("127.") or ip == "::1") else RED
                _box_row(f"    Link {link}: {col}{ip}{NC}")
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
    if diag["fix_needed"]:
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
        _box_row(f"    {DIM}• resolvectl dns-global set 127.0.0.1{NC}")
        _box_row(f"    {DIM}• resolvectl dns-default-route set false{NC}")
        _box_row(f"    {DIM}• systemctl restart systemd-resolved{NC}")
        _box_row(f"    {DIM}• resolvectl flush-caches{NC}")
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
    _box_row(f"    {DIM}• удалить drop-in /etc/systemd/resolved.conf.d/chimera-dns.conf{NC}")
    _box_row(f"    {DIM}• восстановить /etc/resolv.conf из бэкапа (если есть){NC}")
    _box_row(f"    {DIM}• resolvectl dns-default-route set true (вернуть DHCP DNS){NC}")
    _box_row(f"    {DIM}• systemctl restart systemd-resolved{NC}")
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


def do_fix_resolv_conf_interactive() -> None:
    """Интерактивный TUI-экран управления /etc/resolv.conf.

    Зацикленный: после каждого действия экран перерисовывается с новой
    диагностикой. Структура (в едином стиле проекта):
      1. Заголовок + описание
      2. Блок диагностики (resolv.conf / systemd-resolved / DNSCrypt / итог)
      3. Плашка «фикс применён» (если есть)
      4. Меню действий в отдельной рамке:
         [F] Исправить автоматически  (только если fix_needed)
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
