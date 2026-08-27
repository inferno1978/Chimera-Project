"""
chimera/modules/resolv_conf_fix.py
───────────────────────────────────────────────────────────────────────────────
Автоматическое исправление /etc/resolv.conf для предотвращения DNS-leak.

ПРИНЦИП БЕЗОПАСНОСТИ (v6 — полная переработка)
==============================================
Этот модль НЕ вызывает НИ ОДНОЙ команды, которая может затронуть сетевой
интерфейс:
  ✗ НЕТ networkctl reconfigure (УБИВАЕТ SSH — сбрасывает IP)
  ✗ НЕТ networkctl reload
  ✗ НЕТ .network файлов / drop-in'ов
  ✗ НЕТ nmcli connection up/down
  ✗ НЕТ dhclient
  ✗ НЕТ ifconfig / ip link

Только текстовые файлы + runtime resolvectl команды (не трогают интерфейсы):
  ✓ /etc/resolv.conf → статичный `nameserver 127.0.0.1`
  ✓ /etc/nsswitch.conf → убрать `resolve` (bypass systemd-resolved для glibc)
  ✓ /etc/systemd/resolved.conf.d/chimera-dns.conf → drop-in (опционально)
  ✓ resolvectl dns LINK 127.0.0.1 + default-route LINK false (runtime, safe)
  ✓ resolvectl flush-caches

ПОЧЕМУ ЭТО РАБОТАЕТ
===================
Проблема: systemd-resolved получает DHCP DNS от провайдера (77.88.8.8) и
отправляет запросы на все Global DNS параллельно — DNS Leak Test видит Yandex.

Решение: ПОЛНОСТЬЮ обойти systemd-resolved для системного DNS:
1. /etc/resolv.conf → `nameserver 127.0.0.1` — glibc (curl, dig, apt, ssh)
   использует этот файл напрямую, НЕ через systemd-resolved.
2. /etc/nsswitch.conf → убрать `resolve` из строки `hosts:` — nss-resolve
   модуль отключён, glibc использует `dns` (читает /etc/resolv.conf).
3. resolvectl dns LINK 127.0.0.1 + default-route LINK false — для приложений,
   которые используют D-Bus API systemd-resolved напрямую.

Всё, что использует glibc getaddrinfo() (curl, dig, apt, python, ssh),
идёт через /etc/resolv.conf → 127.0.0.1 → DNSCrypt. Утечки НЕТ.

ИНТЕГРАЦИЯ
==========
- Из DNS Leak Test: prompt "Исправить автоматически? [Y/n]".
- Из меню Сеть → DNSCrypt.

DNS-WATCHDOG (v46, <node-2>)
============================
AGH (владелец :53 после финализации) умер через ~час после установки
(креш/OOM) → :53 без слушателя, redirect 53→5300 уже снят, resolv.conf →
127.0.0.1 → системный DNS мёртв, git pull невозможен. _ensure_system_dns_alive
из aghome_setup работал только В МОМЕНТ операций — постоянного надзора не было.

Решение: chimera-dns-watchdog.timer (каждые 60с) → chimera-dns-watchdog.sh:
  0. probe 127.0.0.1:53 (dig rc=0 / getent), повтор через 3с (анти-флап);
  1. AGH активен → systemctl restart AdGuardHome → probe;
  2. dnscrypt-proxy (restart если лежит) + redirect 53→порт из TOML
     (udp+tcp, idempotent) → probe.
Живость важнее фильтрации: redirect при живом AGH лишь обходит фильтры
(внешние клиенты продолжают попадать в AGH), а без него — black-hole.
Действия пишутся в journal: journalctl -t chimera-dns-watchdog.
Установка: fix_resolv_conf_to_localhost() (шаг 10.5); rollback сносит
watchdog вместе с persist-сервисом (иначе борется с откатом).

Публичное API:
  do_fix_resolv_conf_interactive() — TUI-экран
  fix_resolv_conf_to_localhost()   — программный fix (+ watchdog)
  rollback_resolv_conf()           — программный rollback (− watchdog)
  diagnose_resolv_conf()           — диагностика
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

from chimera.modules.agh_probe import agh_probe_resolve


# =============================================================================
#  Константы
# =============================================================================
_RESOLV_CONF          = Path("/etc/resolv.conf")
_NSSWITCH_CONF        = Path("/etc/nsswitch.conf")
_BACKUP_RESOLV        = Path("/etc/resolv.conf.chimera.bak")
_BACKUP_NSSWITCH      = Path("/etc/nsswitch.conf.chimera.bak")
_RESOLVED_DROPIN_DIR  = Path("/etc/systemd/resolved.conf.d")
_RESOLVED_DROPIN_FILE = _RESOLVED_DROPIN_DIR / "chimera-dns.conf"
_STATE_FILE           = Path("/var/lib/xray-installer/resolv_conf_fix.json")
_LOG_FILE             = Path("/var/log/chimera.log")
_DNSCRYPT_TOML        = Path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml")
_DNSCRYPT_SERVICE     = "dnscrypt-proxy.service"
_LOCAL_DNS            = "127.0.0.1"
_DNS_PORT             = 53       # стандартный DNS порт (glibc отправляет сюда)
_IPTABLES_COMMENT     = "chimera-dns-fix"  # для идентификации правил при -D

# AdGuard Home (AGH) — DNS-сервер Chimera на 127.0.0.1:53 поверх dnscrypt.
# Когда AGH владеет :53, redirect 53→5300 НЕ нужен (и ВРЕДЕН — он ворует
# трафик у AGH). См. chimera/modules/aghome_setup.py.
_AGH_SERVICE          = "AdGuardHome.service"
_AGH_CONF             = Path("/opt/AdGuardHome/AdGuardHome.yaml")

# Persist-сервис — Python-скрипт (не bash), перезаписывает resolv.conf +
# nsswitch.conf после ребута если cloud-init их регенерировал.
# НЕ содержит НИ ОДНОЙ networkctl команды.
_PERSIST_SVC_NAME     = "chimera-dns-fix.service"
_PERSIST_SVC_PATH     = Path("/etc/systemd/system") / _PERSIST_SVC_NAME
_PERSIST_SCRIPT_PATH  = Path("/usr/local/bin/chimera-dns-fix-apply.py")

# DNS-WATCHDOG (v46, <node-2>) — systemd-timer каждую минуту пробует
# 127.0.0.1:53 (dig/getent). Мёртв → лестница: рестарт AGH (владелец :53)
# → dnscrypt + redirect 53→порт (оба протокола). Закрывает дыру v44/v45:
# _ensure_system_dns_alive работал только В МОМЕНТ операций, а AGH,
# умерший ЧАС спустя (OOM/креш-луп), уносил системный DNS с собой —
# redirect уже снят, resolv.conf → 127.0.0.1, слушателя нет → black-hole.
_WATCHDOG_SVC_NAME    = "chimera-dns-watchdog.service"
_WATCHDOG_TIMER_NAME  = "chimera-dns-watchdog.timer"
_WATCHDOG_SVC_PATH    = Path("/etc/systemd/system") / _WATCHDOG_SVC_NAME
_WATCHDOG_TIMER_PATH  = Path("/etc/systemd/system") / _WATCHDOG_TIMER_NAME
_WATCHDOG_SCRIPT_PATH = Path("/usr/local/bin/chimera-dns-watchdog.sh")


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
def _is_dnscrypt_service_active() -> bool:
    r = _run(["systemctl", "is-active", _DNSCRYPT_SERVICE],
             capture=True, check=False)
    return r.returncode == 0 and r.stdout.strip() == "active"


def _is_aghome_active() -> bool:
    """Служба AdGuardHome активна."""
    r = _run(["systemctl", "is-active", _AGH_SERVICE],
             capture=True, check=False)
    return r.returncode == 0 and r.stdout.strip() == "active"


def _is_aghome_serving_53() -> bool:
    """AGH активен И слушает :53 (udp) — «AGH владеет :53».

    Именно в этом состоянии redirect 53→dnscrypt_port ДОЛЖЕН БЫТЬ СНЯТ:
    правило REDIRECT в nat OUTPUT перехватывает запросы к 127.0.0.1:53
    и уводит их мимо AGH на dnscrypt:5300 — фильтры/кеш AGH молча
    обходятся. Проверка udp-порта через ss — фактическое состояние
    слушателя, а не только состояние юнита.
    """
    if not _is_aghome_active():
        return False
    r = _run(["ss", "-ulnp"], capture=True, check=False)
    if r.returncode != 0:
        return False
    for line in r.stdout.splitlines():
        # Ищем слушателя udp :53, принадлежащего AdGuardHome.
        if re.search(r':53\s', line):
            if "AdGuardHome" in line or "adguard" in line.lower():
                return True
    return False


def _get_dnscrypt_listen_addr_port() -> Optional[tuple]:
    """Читает listen_addresses из dnscrypt-proxy.toml."""
    if not _DNSCRYPT_TOML.exists():
        return None
    try:
        text = _DNSCRYPT_TOML.read_text(errors="replace")
        m = re.search(
            r'listen_addresses\s*=\s*\[\s*[\'"]([^\'"]+)[\'"]',
            text, re.IGNORECASE,
        )
        if not m:
            return None
        addr_port = m.group(1)
        if addr_port.startswith("["):
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
    r = _run(["ss", "-tlnu"], capture=True, check=False)
    if r.returncode != 0:
        return False
    patterns = [f"{addr}:{port}", f"127.0.0.1:{port}", f"*:{port}",
                f"[::]:{port}", f":{port} "]
    for line in r.stdout.splitlines():
        for pat in patterns:
            if pat in line:
                return True
    return False


def _dns_redirect_protos(dnscrypt_port: int) -> set:
    """Протоколы (подмножество {'udp','tcp'}), для которых в nat OUTPUT
    есть redirect 53→dnscrypt_port.

    Парсинг ПОСТРОЧНЫЙ: каждая строка вывода iptables -L — одно правило.
    Кросс-строчный поиск ("dpt:53 где-то" + "to:5300 где-то") считал
    активным состояние «только tcp» — при нём UDP-DNS на 127.0.0.1:53
    уходит в никуда, а git/curl падают с «Could not resolve host»
    (инцидент v43 на живом сервере).
    """
    r = _run(["iptables", "-t", "nat", "-L", "OUTPUT", "-n"],
             capture=True, check=False)
    if r.returncode != 0:
        return set()
    found = set()
    port = str(dnscrypt_port)
    for ln in r.stdout.splitlines():
        if "dpt:53" not in ln:
            continue
        # iptables выводит "... redir ports 5300" или "... to:5300"
        if not (f"to:{port}" in ln or f"ports {port}" in ln):
            continue
        # proto-токен именно в ЭТОЙ строке правила (не в соседней)
        padded = f"  {ln}  "
        for proto in ("udp", "tcp"):
            if f" {proto} " in padded:
                found.add(proto)
    return found


def _is_dns_redirect_active(dnscrypt_port: int) -> bool:
    """Проверяет, активен ли iptables redirect 53→dnscrypt_port для локальных запросов.

    Требуются ОБА правила — udp И tcp: glibc (curl, git, apt, python) шлёт
    DNS по UDP, TCP используется только как fallback при truncated-ответах.
    Состояние «только tcp» = UDP-запросы на 127.0.0.1:53 не перенаправляются
    → «Could not resolve host» → redirect НЕ активен, нужен re-fix.
    """
    if dnscrypt_port == _DNS_PORT:
        return True  # redirect не нужен — DNSCrypt уже на 53
    return {"udp", "tcp"} <= _dns_redirect_protos(dnscrypt_port)


def _any_dns_redirect_rule(dnscrypt_port: int) -> bool:
    """Есть ли ХОТЯ БЫ ОДНО redirect-правило 53→dnscrypt_port (любой протокол).

    Для AGH-режима: даже единственное tcp-правило уводит TCP-DNS мимо
    AdGuard Home — детект присутствия redirect'а должен срабатывать на
    любой протокол, чтобы «ворующий» redirect был замечен и снят.
    """
    if dnscrypt_port == _DNS_PORT:
        return False
    return bool(_dns_redirect_protos(dnscrypt_port))


def _apply_dns_redirect(dnscrypt_port: int) -> tuple:
    """Создаёт iptables NAT OUTPUT redirect 53→dnscrypt_port.

    glibc (curl, dig, apt, python, ssh) отправляет DNS-запросы на
    nameserver:53. DNSCrypt слушает на 5300. Без redirect — DNS мёртв.
    Redirect перехватывает ТОЛЬКО локальные запросы к 127.0.0.1:53 и
    перенаправляет на 5300. НЕ трогает интерфейсы, НЕ убивает SSH.

    Возвращает (ok, error).
    """
    if dnscrypt_port == _DNS_PORT:
        return True, None  # redirect не нужен

    # Удаляем старые правила если есть (idempotent).
    for proto in ("udp", "tcp"):
        _run(["iptables", "-t", "nat", "-D", "OUTPUT",
              "-p", proto, "-d", _LOCAL_DNS, "--dport", str(_DNS_PORT),
              "-j", "REDIRECT", "--to-ports", str(dnscrypt_port),
              "-m", "comment", "--comment", _IPTABLES_COMMENT],
             capture=True, check=False)

    # Добавляем новые.
    for proto in ("udp", "tcp"):
        r = _run(["iptables", "-t", "nat", "-A", "OUTPUT",
                  "-p", proto, "-d", _LOCAL_DNS, "--dport", str(_DNS_PORT),
                  "-j", "REDIRECT", "--to-ports", str(dnscrypt_port),
                  "-m", "comment", "--comment", _IPTABLES_COMMENT],
                 capture=True, check=False)
        if r.returncode != 0:
            return False, f"iptables -A OUTPUT {proto}: rc={r.returncode}, stderr={r.stderr.strip()[:120]}"

    return True, None


def _remove_dns_redirect(dnscrypt_port: int) -> tuple:
    """Удаляет iptables NAT OUTPUT redirect 53→dnscrypt_port.

    Возвращает (ok, error).
    """
    if dnscrypt_port == _DNS_PORT:
        return True, None
    for proto in ("udp", "tcp"):
        _run(["iptables", "-t", "nat", "-D", "OUTPUT",
              "-p", proto, "-d", _LOCAL_DNS, "--dport", str(_DNS_PORT),
              "-j", "REDIRECT", "--to-ports", str(dnscrypt_port),
              "-m", "comment", "--comment", _IPTABLES_COMMENT],
             capture=True, check=False)
    return True, None


def _get_resolv_conf_nameservers() -> List[str]:
    if not _RESOLV_CONF.exists():
        return []
    try:
        text = _RESOLV_CONF.read_text(errors="replace")
        return re.findall(r'^\s*nameserver\s+(\S+)', text, re.MULTILINE)
    except Exception:
        return []


def _is_stub_resolver(ip: str) -> bool:
    """Проверяет, является ли IP адресом systemd-resolved stub.

    systemd-resolved слушает на 127.0.0.53 (IPv4) и ::53 (IPv6).
    Запросы к stub-резолверу форвардятся на upstream DNS — который
    может включать DHCP DNS от провайдера (77.88.8.8 → Yandex).
    Это УТЕЧКА, даже хотя IP начинается с 127.

    127.0.0.1 — это DNSCrypt-proxy (НЕ stub) — утечки нет.
    127.0.0.53 — это systemd-resolved stub — УТЕЧКА.
    """
    return ip == "127.0.0.53" or ip == "::53"


def _nsswitch_has_resolve() -> bool:
    """Проверяет, есть ли `resolve` в строке hosts: файла /etc/nsswitch.conf."""
    if not _NSSWITCH_CONF.exists():
        return False
    try:
        for line in _NSSWITCH_CONF.read_text(errors="replace").splitlines():
            if line.strip().startswith("hosts:"):
                return "resolve" in line
        return False
    except Exception:
        return False


def diagnose_resolv_conf() -> Dict[str, Any]:
    """Диагностика состояния DNS.

    Главный критерий утечки: /etc/resolv.conf указывает на 127.0.0.1 И
    nsswitch.conf НЕ использует `resolve` (systemd-resolved bypassed).

    Возвращает dict с полями:
      resolv_conf_exists, resolv_conf_is_symlink, resolv_conf_nameservers,
      resolv_conf_on_localhost, nsswitch_has_resolve,
      dnscrypt_service_active, dnscrypt_listen, dnscrypt_listening,
      aghome_active, aghome_serving_53, dns_redirect_active,
      fix_needed, fix_method, leak_reasons
    """
    result: Dict[str, Any] = {
        "resolv_conf_exists": _RESOLV_CONF.exists(),
        "resolv_conf_is_symlink": _RESOLV_CONF.is_symlink(),
        "resolv_conf_nameservers": [],
        "resolv_conf_on_localhost": False,
        "resolv_conf_on_stub": False,
        "nsswitch_has_resolve": _nsswitch_has_resolve(),
        "dnscrypt_service_active": _is_dnscrypt_service_active(),
        "dnscrypt_listen": _get_dnscrypt_listen_addr_port(),
        "dnscrypt_listening": False,
        "aghome_active": _is_aghome_active(),
        "aghome_serving_53": False,
        "dns_redirect_active": True,  # default: не нужен (port == 53)
        # v55 (agh_probe): глубокий health-check — живая проба резолва
        # (end-to-end AGH → DNSCrypt → интернет), только при AGH на :53
        "agh_resolves": False,
        "agh_note": "",
        "fix_needed": False,
        "fix_method": None,
        "leak_reasons": [],
    }

    result["resolv_conf_nameservers"] = _get_resolv_conf_nameservers()
    nss = result["resolv_conf_nameservers"]
    # resolv_conf_on_localhost = True только если ALL nameservers = 127.0.0.1
    # (DNSCrypt-proxy). 127.0.0.53 (systemd-resolved stub) — НЕ localhost OK,
    # это stub-резолвер, который форвардит на upstream DNS (включая DHCP DNS
    # от провайдера → утечка).
    result["resolv_conf_on_localhost"] = bool(nss) and all(
        ip == _LOCAL_DNS for ip in nss
    )
    # resolv_conf_on_stub = True если есть 127.0.0.53 (systemd-resolved stub).
    result["resolv_conf_on_stub"] = any(_is_stub_resolver(ip) for ip in nss)

    if result["dnscrypt_listen"]:
        addr, port = result["dnscrypt_listen"]
        result["dnscrypt_listening"] = _is_dnscrypt_listening(addr, port)
        # Проверяем iptables redirect 53→port если port != 53.
        if result["dnscrypt_listening"] and port != _DNS_PORT:
            result["dns_redirect_active"] = _is_dns_redirect_active(port)
        else:
            result["dns_redirect_active"] = True  # не нужен если port == 53

    # AGH владеет :53? В этом состоянии redirect не нужен ВООБЩЕ.
    # v55 (agh_probe): глубокий health-check — живая проба резолва
    # (end-to-end AGH → DNSCrypt → интернет): отвечает на вопрос «работает
    # ли ВЕСЬ путь», который is-active/ss проверить не могут.
    result["aghome_serving_53"] = _is_aghome_serving_53()
    if result["aghome_serving_53"]:
        agh_ok, agh_note = agh_probe_resolve()
        result["agh_resolves"] = agh_ok
        result["agh_note"] = agh_note
        if agh_ok:
            # AGH жив: redirect может быть только ВРЕДНЫМ (ворует трафик у
            # AGH). «dns_redirect_active» в AGH-режиме означает «redirect-
            # правила отсутствуют» — это правильное состояние. Для детекта
            # достаточно ОДНОГО правила любого протокола (даже tcp-only
            # обходит AGH).
            if result["dnscrypt_listen"] and result["dnscrypt_listen"][1] != _DNS_PORT:
                result["dns_redirect_active"] = not _any_dns_redirect_rule(
                    result["dnscrypt_listen"][1])
            else:
                result["dns_redirect_active"] = not _any_dns_redirect_rule(5300)
        else:
            # AGH слушает :53, но НЕ резолвит (провал end-to-end пробы):
            # фактическое состояние iptables. Redirect есть → грин (DNS жив
            # через dnscrypt-обход сломанного AGH); нет → причина «DNS мёртв»
            # загорится ниже, и фикс создаст redirect как обход.
            if result["dnscrypt_listen"] and result["dnscrypt_listen"][1] != _DNS_PORT:
                result["dns_redirect_active"] = _is_dns_redirect_active(
                    result["dnscrypt_listen"][1])
            else:
                result["dns_redirect_active"] = _is_dns_redirect_active(5300)

    dnscrypt_ready = (
        result["dnscrypt_service_active"]
        and result["dnscrypt_listen"] is not None
        and result["dnscrypt_listening"]
    )

    # ── Решение: нужен ли фикс? ────────────────────────────────────────────
    reasons: List[str] = []

    # resolv.conf указывает на systemd-resolved stub (127.0.0.53) — УТЕЧКА.
    # stub форвардит на upstream DNS, включая DHCP DNS от провайдера.
    if result["resolv_conf_on_stub"]:
        reasons.append(
            f"/etc/resolv.conf → systemd-resolved stub ({', '.join(nss)}) — "
            f"запросы уходят на upstream DNS (включая DHCP DNS от провайдера)"
        )

    # resolv.conf указывает на внешние DNS (не 127.0.0.1 и не stub)
    if nss and not result["resolv_conf_on_localhost"] and not result["resolv_conf_on_stub"]:
        reasons.append(f"/etc/resolv.conf → внешние NS: {', '.join(nss)}")

    # nsswitch.conf использует resolve (systemd-resolved) — потенциальная утечка
    if result["nsswitch_has_resolve"]:
        reasons.append("/etc/nsswitch.conf использует `resolve` (systemd-resolved) — "
                        "DHCP DNS от провайдера может перехватывать запросы")

    # resolv.conf пуст или не существует
    if not nss and result["resolv_conf_exists"]:
        reasons.append("/etc/resolv.conf не содержит nameserver")

    # iptables redirect 53→dnscrypt_port НЕ активен — DNS мёртв.
    # resolv.conf → 127.0.0.1, но glibc идёт на порт 53, а DNSCrypt на 5300.
    # ИСКЛЮЧЕНИЕ: если AGH служит на :53 — glibc попадает в AGH, DNS жив,
    # redirect не нужен (причина не срабатывает).
    if (result["resolv_conf_on_localhost"]
            and not result.get("dns_redirect_active", True)
            and result["dnscrypt_listen"]
            and result["dnscrypt_listen"][1] != _DNS_PORT
            and not result["aghome_serving_53"]):
        reasons.append(
            f"iptables redirect 53→{result['dnscrypt_listen'][1]} НЕ активен — "
            f"DNS мёртв (glibc → 127.0.0.1:53, никто не слушает)"
        )

    # AGH владеет :53 И РЕЗОЛВИТ, но redirect 53→dnscrypt ВСЁ ЕЩЁ активен —
    # трафик воруется у AGH (фильтры/кеш/DoH молча обходятся). Нужен re-fix.
    # v55: guard agh_resolves — при сломанном AGH redirect не «вор» ,
    # а спасательный обход (см. ветку ниже в fix-flow).
    if (result["aghome_serving_53"]
            and result.get("agh_resolves")
            and result["resolv_conf_on_localhost"]
            and not result.get("dns_redirect_active", True)):
        reasons.append(
            "iptables redirect 53→dnscrypt активен при живом AdGuard Home — "
            "запросы обходят AGH (фильтры/кеш не работают)"
        )

    if reasons and dnscrypt_ready:
        result["fix_needed"] = True
        result["leak_reasons"] = reasons
        result["fix_method"] = "static_resolv_conf"
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
            "backup_resolv": None, "backup_nsswitch": None,
            "persist_service": False}


def _state_save(data: dict) -> None:
    try:
        _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _STATE_FILE.write_text(json.dumps(data, indent=2))
        _STATE_FILE.chmod(0o600)
    except Exception as e:
        _warn(f"Не удалось сохранить state: {e}")


# =============================================================================
#  PERSIST — Python-скрипт + systemd-сервис (БЕЗ networkctl!)
# =============================================================================
def _write_persist_script_and_service() -> tuple:
    """Создаёт persist-скрипт (Python) + systemd-сервис.

    Скрипт перезаписывает /etc/resolv.conf и /etc/nsswitch.conf после ребута
    если cloud-init их регенерировал. Также применяет per-link resolvectl
    override (runtime, safe — НЕ трогает интерфейсы).

    Возвращает (script_path, service_path, error).
    """
    # Python-скрипт — надёжнее bash, нет проблем с кавычками/экранированием.
    script_content = '''#!/usr/bin/env python3
"""Chimera Project — persist DNS-leak fix after reboot.

Created by chimera/modules/resolv_conf_fix.py.

This script does NOT touch network interfaces. It only:
  1. Rewrites /etc/resolv.conf → nameserver 127.0.0.1
  2. Removes `resolve` from /etc/nsswitch.conf hosts: line
  3. Applies per-link resolvectl dns LINK 127.0.0.1 (runtime, safe)
  4. Flushes DNS caches
"""
import os, re, sys, shutil, subprocess
from pathlib import Path

LOCAL_DNS = "127.0.0.1"
RESOLV_CONF = Path("/etc/resolv.conf")
NSSWITCH = Path("/etc/nsswitch.conf")

def log(msg):
    print(f"[chimera-dns-fix] {msg}", flush=True)

# 1. /etc/resolv.conf → 127.0.0.1
try:
    content = RESOLV_CONF.read_text(errors="replace") if RESOLV_CONF.exists() else ""
    if LOCAL_DNS not in content or not content.strip():
        if RESOLV_CONF.is_symlink():
            RESOLV_CONF.unlink()
        RESOLV_CONF.write_text(f"nameserver {LOCAL_DNS}\\noptions timeout:1 attempts:1\\n")
        log(f"resolv.conf → {LOCAL_DNS}")
    else:
        log("resolv.conf already OK")
except Exception as e:
    log(f"resolv.conf ERROR: {e}")

# 2. /etc/nsswitch.conf → убрать resolve
try:
    if NSSWITCH.exists():
        text = NSSWITCH.read_text(errors="replace")
        if "resolve" in text:
            # Убираем 'resolve' и '[!UNAVAIL=return]' из строки hosts:
            new_text = re.sub(
                r\'hosts:\\s*(.*?)(?:resolve\\s*(?:\\[!UNAVAIL=return\\]\\s*)?)(.*)\',
                r\'hosts: \\1\\2\',
                text
            )
            # cleanup multiple spaces
            new_text = re.sub(r\'hosts:\\s+\', \'hosts: \', new_text)
            new_text = re.sub(r\'\\s+\', \' \', new_text) if \'hosts:\' in new_text else new_text
            NSSWITCH.write_text(new_text)
            log("nsswitch.conf → resolve removed")
        else:
            log("nsswitch.conf already OK")
except Exception as e:
    log(f"nsswitch.conf ERROR: {e}")

# 3. Per-link resolvectl override (runtime, SAFE — не трогает интерфейсы)
try:
    r = subprocess.run(["resolvectl", "dns"], capture_output=True, text=True, timeout=5)
    if r.returncode == 0:
        for m in re.finditer(r\'^Link\\s+\\d+\\s+\\(([^)]+)\\):\', r.stdout, re.MULTILINE):
            link = m.group(1).strip()
            if link == "lo":
                continue
            subprocess.run(["resolvectl", "dns", link, LOCAL_DNS],
                         capture_output=True, timeout=5)
            subprocess.run(["resolvectl", "default-route", link, "false"],
                         capture_output=True, timeout=5)
            log(f"{link} → DNS {LOCAL_DNS}, default-route false")
except Exception as e:
    log(f"resolvectl ERROR: {e}")

# 4. Flush caches
try:
    subprocess.run(["resolvectl", "flush-caches"], capture_output=True, timeout=5)
    log("caches flushed")
except Exception:
    pass

# 5. iptables redirect 53→5300 (БЕЗОПАСНО — не трогает интерфейсы)
# glibc отправляет DNS на nameserver:53. DNSCrypt слушает на 5300.
# Без redirect — DNS мёртв после применения фикса.
#
# AGH-AWARE: если AdGuard Home активен и слушает :53 — redirect НЕ ставим
# и снимаем если висит (REDIRECT в nat OUTPUT перехватывает запросы к
# 127.0.0.1:53 и уводит их мимо AGH на dnscrypt — фильтры/кеш AGH молча
# обходятся). Пока AGH в wizard-режиме (не слушает :53) или не установлен —
# redirect ставится как раньше (dnscrypt страхует :53-трафик).
import time as _time
DNS_PORT = 53
DNSCRYPT_PORT = 5300  # default; можно переопределить из TOML

def _agh_serves_53():
    """AdGuardHome активен И слушает udp :53."""
    try:
        r = subprocess.run(["systemctl", "is-active", "AdGuardHome"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return False
        rr = subprocess.run(["ss", "-ulnp"], capture_output=True, timeout=5)
        out = rr.stdout.decode(errors="replace") if isinstance(rr.stdout, bytes) else rr.stdout
        for ln in out.splitlines():
            if re.search(r":53\\s", ln):
                if "AdGuardHome" in ln or "adguard" in ln.lower():
                    return True
        return False
    except Exception:
        return False

def _del_redirect(port):
    for proto in ("udp", "tcp"):
        subprocess.run(["iptables", "-t", "nat", "-D", "OUTPUT",
                        "-p", proto, "-d", LOCAL_DNS, "--dport", str(DNS_PORT),
                        "-j", "REDIRECT", "--to-ports", str(port),
                        "-m", "comment", "--comment", "chimera-dns-fix"],
                       capture_output=True, timeout=5)

def _add_redirect(port):
    for proto in ("udp", "tcp"):
        _del_redirect(port)  # idempotent
        subprocess.run(["iptables", "-t", "nat", "-A", "OUTPUT",
                        "-p", proto, "-d", LOCAL_DNS, "--dport", str(DNS_PORT),
                        "-j", "REDIRECT", "--to-ports", str(port),
                        "-m", "comment", "--comment", "chimera-dns-fix"],
                       capture_output=True, timeout=5)

try:
    # Читаем порт DNSCrypt из TOML.
    toml = Path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml")
    if toml.exists():
        m = re.search(r"listen_addresses\\s*=\\s*\\[\\s*['\\"]([^'\\"]+)['\\"]",
                      toml.read_text(errors="replace"), re.IGNORECASE)
        if m:
            addr_port = m.group(1)
            parts = addr_port.rsplit(":", 1)
            if len(parts) == 2:
                DNSCRYPT_PORT = int(parts[1])
    if DNSCRYPT_PORT != DNS_PORT:
        # Ждём до 20с пока AGH поднимется на буте (unit-ordering race:
        # chimera-dns-fix может стартовать раньше AdGuardHome).
        agh_ok = False
        for _ in range(20):
            agh_ok = _agh_serves_53()
            if agh_ok:
                break
            # AGH не активен/не установлен — не ждём.
            try:
                ra = subprocess.run(["systemctl", "is-active", "AdGuardHome"],
                                    capture_output=True, text=True, timeout=5)
                if (ra.stdout or "").strip() not in ("active", "activating"):
                    break
            except Exception:
                break
            _time.sleep(1)
        if agh_ok:
            _del_redirect(DNSCRYPT_PORT)
            log(f"AGH serves :{DNS_PORT} — redirect {DNS_PORT}\\u2192{DNSCRYPT_PORT} снят")
        else:
            _add_redirect(DNSCRYPT_PORT)
            log(f"iptables redirect {DNS_PORT}\\u2192{DNSCRYPT_PORT}")
except Exception as e:
    log(f"iptables redirect ERROR: {e}")

log("done")
'''
    try:
        _PERSIST_SCRIPT_PATH.parent.mkdir(parents=True, exist_ok=True)
        _PERSIST_SCRIPT_PATH.write_text(script_content)
        _PERSIST_SCRIPT_PATH.chmod(0o755)
    except PermissionError:
        return None, None, f"нет прав на {_PERSIST_SCRIPT_PATH} (нужен root)"
    except Exception as e:
        return None, None, f"не удалось создать {_PERSIST_SCRIPT_PATH}: {e}"

    service_content = f"""[Unit]
Description=Chimera Project — persist DNS-leak fix after reboot
Documentation=https://github.com/inferno1978/Chimera-Project
After=network-online.target systemd-resolved.service dnscrypt-proxy.service AdGuardHome.service
Wants=network-online.target
Requires=systemd-resolved.service

[Service]
Type=oneshot
ExecStart={_PERSIST_SCRIPT_PATH}
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


# =============================================================================
#  DNS-WATCHDOG (v46) — системный DNS не должен умирать НАДОЛГО
# =============================================================================
def _watchdog_script_content() -> str:
    """Bash-скрипт watchdog: probe → self-heal лестница.

    Порядок:
      0. probe 127.0.0.1:53 (dig rc=0 = ответ есть; fallback getent),
         повтор через 3с (анти-ложное-срабатывание на транзиент).
      1. AGH активен → restart AdGuardHome → probe (владелец :53).
      2. dnscrypt-proxy (restart если лежит) + redirect 53→порт
         (udp+tcp, idempotent -C/-A) → probe.
    Всё пишет в journal через logger -t chimera-dns-watchdog.
    """
    return """#!/bin/bash
# Chimera Project — DNS-watchdog: системный DNS не должен умирать надолго.
# Сгенерировано chimera/modules/resolv_conf_fix.py. НЕ редактировать вручную.
# Управление: systemctl list-timers | grep chimera-dns-watchdog

TAG="chimera-dns-watchdog"
PROBE_DOMAIN="ya.ru"

dns_alive() {
    if command -v dig >/dev/null 2>&1; then
        dig @127.0.0.1 "$PROBE_DOMAIN" +time=1 +tries=1 +short >/dev/null 2>&1
        return $?
    fi
    getent hosts "$PROBE_DOMAIN" >/dev/null 2>&1
}

add_redirect() {
    local port="$1" proto
    for proto in udp tcp; do
        iptables -t nat -C OUTPUT -p "$proto" -d 127.0.0.1 --dport 53 \\
            -j REDIRECT --to-ports "$port" -m comment --comment chimera-dns-fix \\
            2>/dev/null || \\
        iptables -t nat -A OUTPUT -p "$proto" -d 127.0.0.1 --dport 53 \\
            -j REDIRECT --to-ports "$port" -m comment --comment chimera-dns-fix \\
            2>/dev/null
    done
}

# 0. probe (двойной — транзиент не считается смертью)
if dns_alive; then
    exit 0
fi
sleep 3
if dns_alive; then
    exit 0
fi

logger -t "$TAG" "DNS 127.0.0.1:53 не отвечает — восстановление"

# 1. AdGuard Home — если активен, он владелец :53
if systemctl is-active --quiet AdGuardHome 2>/dev/null; then
    systemctl restart AdGuardHome
    sleep 5
    if dns_alive; then
        logger -t "$TAG" "DNS восстановлен: рестарт AdGuardHome"
        exit 0
    fi
    logger -t "$TAG" "рестарт AdGuardHome не помог — fallback dnscrypt"
fi

# 2. dnscrypt-proxy + redirect 53→порт (живость важнее фильтрации)
systemctl is-active --quiet dnscrypt-proxy 2>/dev/null || \\
    systemctl restart dnscrypt-proxy
sleep 2
PORT=5300
TOML=/etc/dnscrypt-proxy/dnscrypt-proxy.toml
if [ -f "$TOML" ]; then
    P=$(grep -oP "listen_addresses\\s*=\\s*\\[\\s*['\\\"][^'\\\"]*:\\K[0-9]+" "$TOML" 2>/dev/null | head -1)
    [ -n "$P" ] && [ "$P" != "53" ] && PORT="$P"
fi
add_redirect "$PORT"
sleep 1
if dns_alive; then
    logger -t "$TAG" "DNS восстановлен: redirect 53->$PORT (dnscrypt)"
else
    logger -t "$TAG" "КРИТИЧНО: DNS мёртв даже после redirect 53->$PORT — journalctl -u dnscrypt-proxy -n 30"
fi
exit 0
"""


def _write_dns_watchdog() -> "tuple[Path, Path, Path, Optional[str]]":
    """Пишет watchdog-скрипт + service + timer. Возвращает (script, svc,
    timer, err)."""
    script = _watchdog_script_content()
    try:
        _WATCHDOG_SCRIPT_PATH.parent.mkdir(parents=True, exist_ok=True)
        _WATCHDOG_SCRIPT_PATH.write_text(script)
        _WATCHDOG_SCRIPT_PATH.chmod(0o755)
    except PermissionError:
        return None, None, None, f"нет прав на {_WATCHDOG_SCRIPT_PATH} (нужен root)"
    except Exception as e:
        return None, None, None, f"не удалось создать {_WATCHDOG_SCRIPT_PATH}: {e}"

    svc = f"""[Unit]
Description=Chimera Project — DNS watchdog (probe 127.0.0.1:53, self-heal)
Documentation=https://github.com/inferno1978/Chimera-Project
After=network-online.target dnscrypt-proxy.service AdGuardHome.service

[Service]
Type=oneshot
ExecStart={_WATCHDOG_SCRIPT_PATH}
TimeoutStartSec=90s
StandardOutput=journal
StandardError=journal
"""
    timer = f"""[Unit]
Description=Chimera Project — DNS watchdog timer (каждую минуту)

[Timer]
OnBootSec=2min
OnUnitActiveSec=60s
AccuracySec=15s
Unit={_WATCHDOG_SVC_NAME}

[Install]
WantedBy=timers.target
"""
    try:
        _WATCHDOG_SVC_PATH.write_text(svc)
        _WATCHDOG_TIMER_PATH.write_text(timer)
    except PermissionError:
        return _WATCHDOG_SCRIPT_PATH, None, None, \
            f"нет прав на {_WATCHDOG_SVC_PATH} (нужен root)"
    except Exception as e:
        return _WATCHDOG_SCRIPT_PATH, None, None, \
            f"не удалось создать unit-файлы: {e}"
    return _WATCHDOG_SCRIPT_PATH, _WATCHDOG_SVC_PATH, _WATCHDOG_TIMER_PATH, None


def _ensure_dns_watchdog() -> tuple:
    """Устанавливает/обновляет watchdog-timer (идемпотентно).

    Возвращает (ok, err). err=None и ok=True — таймер активен.
    """
    script, svc, timer, err = _write_dns_watchdog()
    if err:
        # Нет прав (не root / песочница) — НЕ ломаем основной фикс,
        # watchdog не критичен для текущего запуска.
        return False, err
    _run(["systemctl", "daemon-reload"], capture=True, check=False)
    r = _run(["systemctl", "enable", "--now", _WATCHDOG_TIMER_NAME],
             capture=True, check=False)
    if r.returncode != 0:
        return False, (f"systemctl enable --now {_WATCHDOG_TIMER_NAME}: "
                       f"rc={r.returncode}, stderr={(r.stderr or '').strip()[:120]}")
    # Однократный прогон сразу — не ждём минуту до первого probe
    _run(["systemctl", "start", _WATCHDOG_SVC_NAME],
         capture=True, check=False)
    return True, None


def _remove_dns_watchdog() -> None:
    """Отключает и удаляет watchdog (rollback DNS-фикса)."""
    try:
        _run(["systemctl", "disable", "--now", _WATCHDOG_TIMER_NAME],
             capture=True, check=False)
        _run(["systemctl", "stop", _WATCHDOG_SVC_NAME],
             capture=True, check=False)
        _run(["systemctl", "daemon-reload"], capture=True, check=False)
    except Exception:
        pass
    for p in (_WATCHDOG_TIMER_PATH, _WATCHDOG_SVC_PATH,
              _WATCHDOG_SCRIPT_PATH):
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass


def _disable_persist_service() -> tuple:
    _run(["systemctl", "stop", _PERSIST_SVC_NAME], capture=True, check=False)
    _run(["systemctl", "disable", _PERSIST_SVC_NAME], capture=True, check=False)
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
#  FIX — программная функция (БЕЗ networkctl, БЕЗ .network файлов)
# =============================================================================
def fix_resolv_conf_to_localhost(dry_run: bool = False,
                                 force: bool = False) -> Dict[str, Any]:
    """Направляет серверный DNS на 127.0.0.1 (DNSCrypt).

    БЕЗОПАСНЫЙ подход (v6):
      1. Backup /etc/resolv.conf + /etc/nsswitch.conf
      2. /etc/resolv.conf → `nameserver 127.0.0.1` (bypass systemd-resolved)
      3. /etc/nsswitch.conf → убрать `resolve` из hosts: (bypass nss-resolve)
      4. Drop-in /etc/systemd/resolved.conf.d/chimera-dns.conf (defense-in-depth)
      5. Per-link resolvectl dns LINK 127.0.0.1 + default-route LINK false (runtime)
      6. resolvectl flush-caches
      7. Persist-сервис (Python, БЕЗ networkctl)

    НЕ ВЫЗЫВАЕТ: networkctl, ifconfig, ip link, dhclient, nmcli connection up.
    НЕ ТРОГАЕТ: сетевые интерфейсы, IP-адреса, DHCP-leases.

    Возвращает dict:
      {"ok": bool, "method": str, "actions": [str, ...],
       "warnings": [str, ...], "error": str | None}
    """
    actions: List[str] = []
    warnings: List[str] = []

    diag = diagnose_resolv_conf()

    if not diag["fix_needed"] and not force:
        return {
            "ok": False, "method": None, "actions": [],
            "warnings": diag["leak_reasons"],
            "error": "fix not needed. Use force=True to re-apply.",
        }

    # Pre-flight: DNSCrypt должен быть готов
    if not diag["dnscrypt_service_active"]:
        return {"ok": False, "method": None, "actions": [],
                "warnings": diag["leak_reasons"],
                "error": f"DNSCrypt service ({_DNSCRYPT_SERVICE}) не активен"}
    if not diag["dnscrypt_listening"]:
        return {"ok": False, "method": None, "actions": [],
                "warnings": diag["leak_reasons"],
                "error": "DNSCrypt не слушает — фикс создаст black-hole"}

    if dry_run:
        actions.append("[dry-run] method=static_resolv_conf")
        return {"ok": True, "method": "static_resolv_conf", "actions": actions,
                "warnings": [], "error": None}

    # ── 1. Backup /etc/resolv.conf ──────────────────────────────────────────
    if not _BACKUP_RESOLV.exists() and _RESOLV_CONF.exists():
        try:
            shutil.copy2(str(_RESOLV_CONF), str(_BACKUP_RESOLV))
            actions.append(f"бэкап: {_RESOLV_CONF} → {_BACKUP_RESOLV}")
        except Exception as e:
            warnings.append(f"не удалось создать бэкап resolv.conf: {e}")
    elif _BACKUP_RESOLV.exists():
        actions.append(f"бэкап resolv.conf уже существует: {_BACKUP_RESOLV}")

    # ── 2. Backup /etc/nsswitch.conf ────────────────────────────────────────
    if not _BACKUP_NSSWITCH.exists() and _NSSWITCH_CONF.exists():
        try:
            shutil.copy2(str(_NSSWITCH_CONF), str(_BACKUP_NSSWITCH))
            actions.append(f"бэкап: {_NSSWITCH_CONF} → {_BACKUP_NSSWITCH}")
        except Exception as e:
            warnings.append(f"не удалось создать бэкап nsswitch.conf: {e}")
    elif _BACKUP_NSSWITCH.exists():
        actions.append(f"бэкап nsswitch.conf уже существует: {_BACKUP_NSSWITCH}")

    # ── 3. /etc/resolv.conf → nameserver 127.0.0.1 ──────────────────────────
    try:
        if _RESOLV_CONF.is_symlink():
            _RESOLV_CONF.unlink()
            actions.append("удалён симлинк /etc/resolv.conf")
        new_resolv = (
            "# Chimera Project — DNS leak fix\n"
            "# Серверный DNS направлен на локальный DNSCrypt-proxy.\n"
            "# Восстановление: cp /etc/resolv.conf.chimera.bak /etc/resolv.conf\n"
            f"nameserver {_LOCAL_DNS}\n"
            "options timeout:1 attempts:1\n"
        )
        _RESOLV_CONF.write_text(new_resolv)
        actions.append(f"записан /etc/resolv.conf → nameserver {_LOCAL_DNS}")
    except PermissionError:
        return {"ok": False, "method": "static_resolv_conf", "actions": actions,
                "warnings": warnings,
                "error": "нет прав на запись /etc/resolv.conf (нужен root)"}
    except Exception as e:
        return {"ok": False, "method": "static_resolv_conf", "actions": actions,
                "warnings": warnings,
                "error": f"не удалось записать resolv.conf: {e}"}

    # ── 4. /etc/nsswitch.conf → убрать resolve ──────────────────────────────
    try:
        if _NSSWITCH_CONF.exists():
            text = _NSSWITCH_CONF.read_text(errors="replace")
            if "resolve" in text:
                # Заменяем 'resolve [!UNAVAIL=return] ' на пустую строку
                # в строке hosts:. Сохраняем остальное.
                new_text = text
                # Убираем 'resolve [!UNAVIL=return] ' или 'resolve '
                new_text = re.sub(
                    r'resolve\s*(?:\[!UNAVAIL=return\]\s*)?',
                    '', new_text
                )
                # Очищаем двойные пробелы в строке hosts:
                new_text = re.sub(
                    r'(hosts:\s*)\s+',
                    r'\1', new_text
                )
                _NSSWITCH_CONF.write_text(new_text)
                actions.append("nsswitch.conf → убран `resolve` (bypass systemd-resolved)")
    except PermissionError:
        warnings.append("нет прав на запись /etc/nsswitch.conf (нужен root)")
    except Exception as e:
        warnings.append(f"не удалось изменить nsswitch.conf: {e}")

    # ── 4.5. iptables redirect 53→dnscrypt_port ─────────────────────────────
    # КРИТИЧЕСКИЙ шаг: glibc отправляет DNS на nameserver:53. DNSCrypt слушает
    # на 5300. Без redirect — DNS мёртв (Could not resolve host).
    # iptables NAT OUTPUT redirect перехватывает ТОЛЬКО локальные запросы к
    # 127.0.0.1:53 → перенаправляет на 5300. НЕ трогает интерфейсы.
    #
    # AGH-AWARE ВЕТКА (v37): если AdGuard Home служит на :53, redirect НЕ НУЖЕН
    # и ВРЕДЕН (REDIRECT перехватывает запросы к 127.0.0.1:53 и уводит их
    # мимо AGH на dnscrypt:5300 — фильтры/кеш AGH молча обходятся).
    # В этом случае: СНЯТЬ существующие правила и НЕ ставить новые.
    # Пока AGH в wizard-режиме (не слушает :53) — redirect остаётся
    # страховкой (dnscrypt продолжает обслуживать :53-трафик).
    #
    # v55 (agh_probe): «служит на :53» теперь подтверждается живой пробой
    # резолва (diag['agh_resolves'], end-to-end AGH → DNSCrypt → интернет).
    # AGH на :53, но НЕ резолвит → redirect НЕ снимаем, а ставим: это обход
    # сломанного AGH (glibc → :53 DNAT → dnscrypt:5300 → интернет), DNS
    # остаётся живым, пока AGH чинят (проверьте upstream в AdGuardHome.yaml).
    dnscrypt_port = 5300  # default
    if diag["dnscrypt_listen"]:
        dnscrypt_port = diag["dnscrypt_listen"][1]
    agh_serving = diag.get("aghome_serving_53", False)
    agh_resolves = diag.get("agh_resolves", False)
    if agh_serving and agh_resolves:
        # AGH жив и резолвит: redirect может быть только вредным
        ok_r, err_r = _remove_dns_redirect(dnscrypt_port)
        if ok_r:
            actions.append(
                f"AGH служит на :53 и резолвит — iptables redirect 53→{dnscrypt_port} "
                f"снят (системный DNS → AdGuard Home)")
        else:
            warnings.append(f"AGH: не удалось снять redirect: {err_r}")
    elif agh_serving:
        # AGH на :53, но НЕ резолвит (провал пробы) — redirect как обход
        # сломанного AGH: glibc → :53 (DNAT) → dnscrypt:5300 → интернет
        ok_r, err_r = _apply_dns_redirect(dnscrypt_port)
        if ok_r:
            actions.append(f"iptables redirect 53→{dnscrypt_port} "
                           f"(AGH на :53 не резолвит — обход через DNSCrypt)")
        else:
            warnings.append(f"iptables redirect: {err_r}")
        warnings.append(f"AdGuardHome на 127.0.0.1:53 не резолвит "
                        f"({diag.get('agh_note', '')}) — локальный DNS идёт "
                        f"мимо AGH через redirect; проверьте upstream в "
                        f"AdGuardHome.yaml")
    elif dnscrypt_port != _DNS_PORT:
        ok_r, err_r = _apply_dns_redirect(dnscrypt_port)
        if ok_r:
            actions.append(f"iptables redirect 53→{dnscrypt_port} (локальные DNS → DNSCrypt)")
        else:
            warnings.append(f"iptables redirect: {err_r}")
            warnings.append("ВНИМАНИЕ: DNS может не работать без redirect! "
                           "Проверьте что DNSCrypt слушает на порту 53, либо "
                           "настройте iptables вручную.")

    # ── 5. Drop-in для systemd-resolved (defense-in-depth) ──────────────────
    try:
        _RESOLVED_DROPIN_DIR.mkdir(parents=True, exist_ok=True)
        dropin_content = (
            "# Chimera Project — DNS leak fix (defense-in-depth)\n"
            "# Перенаправляет Global DNS на локальный DNSCrypt-proxy.\n"
            "[Resolve]\n"
            f"DNS={_LOCAL_DNS}\n"
            "FallbackDNS=\n"
            "Domains=~.\n"
            "DNSOverTLS=opportunistic\n"
            "DNSSEC=allow-downgrade\n"
            "MulticastDNS=no\n"
            "LLMNR=no\n"
        )
        _RESOLVED_DROPIN_FILE.write_text(dropin_content)
        actions.append(f"создан drop-in: {_RESOLVED_DROPIN_FILE}")
    except Exception as e:
        warnings.append(f"не удалось создать drop-in: {e}")

    # ── 6. Per-link resolvectl override (runtime, SAFE) ─────────────────────
    # НЕ ТРОГАЕТ интерфейсы. Только перезаписывает per-link DNS в resolved.
    try:
        r = _run(["resolvectl", "dns"], capture=True, check=False)
        if r.returncode == 0:
            links = re.findall(
                r'^Link\s+\d+\s+\(([^)]+)\):', r.stdout, re.MULTILINE
            )
            for link in links:
                if link == "lo":
                    continue
                ok, _, _ = _resolvectl_dns_set(link, _LOCAL_DNS)
                if ok:
                    actions.append(f"resolvectl dns {link} {_LOCAL_DNS}")
                ok, _, _ = _resolvectl_default_route_set(link, False)
                if ok:
                    actions.append(f"resolvectl default-route {link} false")
    except Exception as e:
        warnings.append(f"per-link override: {e}")

    # ── 7. systemctl restart systemd-resolved ───────────────────────────────
    # SAFE: restart resolved не трогает сетевые интерфейсы.
    r = _run(["systemctl", "restart", "systemd-resolved"],
             capture=True, check=False)
    if r.returncode == 0:
        actions.append("systemctl restart systemd-resolved")
    else:
        warnings.append(f"restart systemd-resolved: rc={r.returncode}")

    # ── 8. flush caches ─────────────────────────────────────────────────────
    r = _run(["resolvectl", "flush-caches"], capture=True, check=False)
    if r.returncode == 0:
        actions.append("resolvectl flush-caches")

    # ── 9. Re-apply per-link override после restart ─────────────────────────
    try:
        r = _run(["resolvectl", "dns"], capture=True, check=False)
        if r.returncode == 0:
            links = re.findall(
                r'^Link\s+\d+\s+\(([^)]+)\):', r.stdout, re.MULTILINE
            )
            for link in links:
                if link == "lo":
                    continue
                _resolvectl_dns_set(link, _LOCAL_DNS)
                _resolvectl_default_route_set(link, False)
    except Exception:
        pass

    # ── 10. PERSIST — Python-скрипт + systemd-сервис ────────────────────────
    script_path, svc_path, perr = _write_persist_script_and_service()
    if perr:
        warnings.append(f"persist-сервис не создан: {perr}")
    elif script_path and svc_path:
        ok_p, perr2 = _enable_persist_service()
        if ok_p:
            actions.append(f"создан и активирован persist-сервис: {_PERSIST_SVC_NAME}")
        else:
            warnings.append(f"persist-сервис создан, но не активирован: {perr2}")

    # ── 10.5 WATCHDOG — DNS не должен умирать НАДОЛГО (v46) ─────────────────
    # AGH умер через час после финализации (креш/OOM) → :53 без слушателя,
    # redirect уже снят → системный DNS мёртв. Watchdog каждую минуту
    # пробует 127.0.0.1:53 и сам чинит (рестарт AGH → dnscrypt-redirect).
    try:
        wok, werr = _ensure_dns_watchdog()
    except Exception as e:
        wok, werr = False, str(e)
    if wok:
        actions.append(f"watchdog активен: {_WATCHDOG_TIMER_NAME} (probe каждую минуту)")
    else:
        warnings.append(f"watchdog не установлен: {werr}")

    # ── Сохранить state ─────────────────────────────────────────────────────
    _state_save({
        "fixed": True,
        "method": "static_resolv_conf",
        "applied_at": datetime.now().isoformat(),
        "backup_resolv": str(_BACKUP_RESOLV) if _BACKUP_RESOLV.exists() else None,
        "backup_nsswitch": str(_BACKUP_NSSWITCH) if _BACKUP_NSSWITCH.exists() else None,
        "persist_service": _PERSIST_SVC_PATH.exists(),
    })

    _ok("DNS направлен на локальный DNSCrypt-proxy (127.0.0.1)")
    return {"ok": True, "method": "static_resolv_conf", "actions": actions,
            "warnings": warnings, "error": None}


def _resolvectl_dns_set(link: Optional[str], dns: str) -> tuple:
    """Выполняет `resolvectl dns [LINK] 127.0.0.1`. Runtime, SAFE."""
    if link:
        cmd = ["resolvectl", "dns", link, dns]
    else:
        cmd = ["resolvectl", "dns", dns]
    r = _run(cmd, capture=True, check=False)
    return (r.returncode == 0, " ".join(cmd), None if r.returncode == 0
            else f"rc={r.returncode}")


def _resolvectl_default_route_set(link: Optional[str], value: bool) -> tuple:
    """Выполняет `resolvectl default-route [LINK] false`. Runtime, SAFE."""
    val_str = "true" if value else "false"
    if link:
        cmd = ["resolvectl", "default-route", link, val_str]
    else:
        cmd = ["resolvectl", "default-route", val_str]
    r = _run(cmd, capture=True, check=False)
    return (r.returncode == 0, " ".join(cmd), None if r.returncode == 0
            else f"rc={r.returncode}")


# =============================================================================
#  ROLLBACK
# =============================================================================
def rollback_resolv_conf() -> Dict[str, Any]:
    """Откатывает изменения fix_resolv_conf_to_localhost().

    Шаги:
      1. Остановить и удалить persist-сервис.
      2. Восстановить /etc/resolv.conf из бэкапа.
      3. Восстановить /etc/nsswitch.conf из бэкапа.
      4. Удалить drop-in /etc/systemd/resolved.conf.d/chimera-dns.conf.
      5. systemctl restart systemd-resolved + flush-caches.
      6. Обновить state.

    НЕ ВЫЗЫВАЕТ: networkctl, ifconfig, ip link, dhclient.
    """
    actions: List[str] = []
    warnings: List[str] = []

    state = _state_load()
    if not state.get("fixed"):
        return {"ok": False, "method": None, "actions": [],
                "warnings": [], "error": "фикс не был применён (state.fixed=False)"}

    # 1. Остановить persist-сервис
    ok_ds, err_ds = _disable_persist_service()
    if ok_ds:
        actions.append(f"остановлен и удалён persist-сервис: {_PERSIST_SVC_NAME}")
    else:
        warnings.append(f"ошибка удаления persist-сервиса: {err_ds}")

    # 1.5. Удалить DNS-watchdog (v46) — иначе он будет «чинить» 127.0.0.1:53
    # и бороться с откатом к внешнему DNS.
    try:
        _remove_dns_watchdog()
        actions.append(f"остановлен и удалён watchdog: {_WATCHDOG_TIMER_NAME}")
    except Exception as e:
        warnings.append(f"ошибка удаления watchdog: {e}")

    # 2. Восстановить /etc/resolv.conf из бэкапа
    if _BACKUP_RESOLV.exists():
        try:
            if _RESOLV_CONF.exists() and not _RESOLV_CONF.is_symlink():
                _RESOLV_CONF.unlink()
            shutil.copy2(str(_BACKUP_RESOLV), str(_RESOLV_CONF))
            actions.append(f"восстановлен /etc/resolv.conf из {_BACKUP_RESOLV}")
        except Exception as e:
            warnings.append(f"не удалось восстановить resolv.conf: {e}")

    # 3. Восстановить /etc/nsswitch.conf из бэкапа
    if _BACKUP_NSSWITCH.exists():
        try:
            shutil.copy2(str(_BACKUP_NSSWITCH), str(_NSSWITCH_CONF))
            actions.append(f"восстановлен /etc/nsswitch.conf из {_BACKUP_NSSWITCH}")
        except Exception as e:
            warnings.append(f"не удалось восстановить nsswitch.conf: {e}")

    # 4. Удалить drop-in
    if _RESOLVED_DROPIN_FILE.exists():
        try:
            _RESOLVED_DROPIN_FILE.unlink()
            actions.append(f"удалён drop-in: {_RESOLVED_DROPIN_FILE}")
        except Exception as e:
            warnings.append(f"не удалось удалить drop-in: {e}")

    # 4.5. Удалить iptables redirect 53→dnscrypt_port
    dnscrypt_port = 5300
    diag = diagnose_resolv_conf()
    if diag["dnscrypt_listen"]:
        dnscrypt_port = diag["dnscrypt_listen"][1]
    ok_r, _ = _remove_dns_redirect(dnscrypt_port)
    if ok_r and dnscrypt_port != _DNS_PORT:
        actions.append(f"удалён iptables redirect 53→{dnscrypt_port}")

    # 5. restart systemd-resolved + flush-caches
    _run(["systemctl", "restart", "systemd-resolved"], capture=True, check=False)
    actions.append("systemctl restart systemd-resolved")
    _run(["resolvectl", "flush-caches"], capture=True, check=False)
    actions.append("resolvectl flush-caches")

    # 6. Обновить state
    _state_save({
        "fixed": False, "method": None, "applied_at": None,
        "backup_resolv": str(_BACKUP_RESOLV) if _BACKUP_RESOLV.exists() else None,
        "backup_nsswitch": str(_BACKUP_NSSWITCH) if _BACKUP_NSSWITCH.exists() else None,
        "persist_service": False,
        "rolled_back_at": datetime.now().isoformat(),
    })

    _ok("DNS откачен к прежнему состоянию")
    return {"ok": True, "method": "static_resolv_conf", "actions": actions,
            "warnings": warnings, "error": None}


# =============================================================================
#  ИНТЕРАКТИВНЫЙ ЭКРАН (TUI)
# =============================================================================
def _print_diagnosis(diag: Dict[str, Any]) -> None:
    """Рисует диагностический блок."""
    # /etc/resolv.conf
    _box_row(f"  {BOLD}/etc/resolv.conf:{NC}")
    if not diag["resolv_conf_exists"]:
        _box_row(f"    {RED}не существует{NC}")
    else:
        if diag["resolv_conf_is_symlink"]:
            try:
                target = os.readlink(str(_RESOLV_CONF))
                _box_row(f"    {DIM}симлинк → {target}{NC}")
            except OSError:
                pass
        nss = diag["resolv_conf_nameservers"]
        if nss:
            for ip in nss:
                if _is_stub_resolver(ip):
                    _box_row(f"    nameserver {RED}{ip}{NC} {RED}← systemd-resolved stub (УТЕЧКА){NC}")
                elif ip == _LOCAL_DNS:
                    _box_row(f"    nameserver {GREEN}{ip}{NC} {GREEN}← DNSCrypt ✓{NC}")
                else:
                    _box_row(f"    nameserver {RED}{ip}{NC} {RED}← внешний DNS{NC}")
        else:
            _box_row(f"    {DIM}nameserver — не задан{NC}")
        if diag["resolv_conf_on_localhost"]:
            _box_row(f"    {GREEN}✓ указывает на DNSCrypt (127.0.0.1){NC}")
        elif diag["resolv_conf_on_stub"]:
            _box_row(f"    {RED}✗ указывает на systemd-resolved stub — утечка!{NC}")
    _box_row()

    # /etc/nsswitch.conf
    _box_row(f"  {BOLD}/etc/nsswitch.conf:{NC}")
    if diag["nsswitch_has_resolve"]:
        _box_row(f"    {YELLOW}⚠ использует `resolve` (systemd-resolved) — потенциальная утечка{NC}")
    else:
        _box_row(f"    {GREEN}✓ `resolve` убран — glibc использует /etc/resolv.conf напрямую{NC}")
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
            if port != _DNS_PORT:
                if diag.get("aghome_serving_53") and diag.get("agh_resolves"):
                    _box_row(f"    iptables redirect 53→{port}: {GREEN}не нужен — AGH на :53{NC}")
                else:
                    redirect_ok = _is_dns_redirect_active(port)
                    if redirect_ok:
                        _box_row(f"    iptables redirect 53→{port}: {GREEN}✓ активен{NC}")
                    else:
                        _box_row(f"    iptables redirect 53→{port}: {RED}✗ НЕ активен (DNS не будет работать!){NC}")
        else:
            _box_row(f"    listen:  {RED}{listen_str} ✗ НЕ слушает{NC}")
    else:
        _box_row(f"    listen:  {DIM}не определён (TOML не найден){NC}")
    _box_row()

    # AdGuardHome (стек «AGH:53 → DNSCrypt:5300»)
    if diag.get("aghome_active") or diag.get("aghome_serving_53"):
        _box_row(f"  {BOLD}AdGuardHome:{NC}")
        if diag.get("aghome_serving_53"):
            if diag.get("agh_resolves"):
                _box_row(f"    127.0.0.1:53: {GREEN}✓ AGH слушает и резолвит "
                         f"({diag.get('agh_note', '')}){NC}")
                _box_row(f"    {DIM}локальный DNS: glibc/Xray → AGH → DNSCrypt{NC}")
            else:
                _box_row(f"    127.0.0.1:53: {RED}✗ AGH слушает, но НЕ резолвит "
                         f"({diag.get('agh_note', '')}){NC}")
                _box_row(f"    {YELLOW}выполните фикс — redirect отведёт DNS на DNSCrypt{NC}")
        else:
            _box_row(f"    сервис:  {GREEN}active{NC} {DIM}(127.0.0.1:53 не держит — "
                     f"в DNS-цепочке не участвует){NC}")
        _box_row()
    _box_sep()

    # Итог
    if diag["fix_needed"]:
        _box_row(f"  {RED}⚠ УТЕЧКА DNS ОБНАРУЖЕНА{NC}")
        for reason in diag["leak_reasons"]:
            _box_row(f"    {RED}• {reason}{NC}")
        _box_sep()
        _box_row(f"  {GREEN}✓ Можно исправить автоматически{NC}")
        _box_row(f"    Метод:  {CYAN}static /etc/resolv.conf + nsswitch.conf{NC}")
    elif diag["leak_reasons"]:
        _box_row(f"  {YELLOW}~ Утечка обнаружена, но авто-фикс невозможен:{NC}")
        for reason in diag["leak_reasons"]:
            _box_row(f"    {YELLOW}• {reason}{NC}")
    else:
        _box_row(f"  {GREEN}✓ Утечки не обнаружено — фикс не требуется{NC}")
        _box_row(f"  {GREEN}  /etc/resolv.conf → 127.0.0.1, nsswitch без `resolve`{NC}")


def _print_fix_state_badge(state: dict) -> None:
    if not state.get("fixed"):
        return
    method = state.get("method", "?")
    applied = state.get("applied_at", "")
    applied_short = applied[:19].replace("T", " ") if applied else "?"
    _box_row(f"  {GREEN}✓ Фикс применён:{NC} {CYAN}{method}{NC}  "
             f"{DIM}({applied_short}){NC}")
    _box_row(f"  {DIM}DNS → 127.0.0.1 (DNSCrypt-proxy){NC}")
    if state.get("persist_service"):
        _box_row(f"  {DIM}Persist: {_PERSIST_SVC_NAME} активен (переживёт ребут){NC}")
    else:
        _box_row(f"  {YELLOW}⚠ persist-сервис не активен — после ребута фикс может сброситься{NC}")


def _screen_fix_apply(diag: Dict[str, Any]) -> None:
    os.system("clear")
    print()
    _box_top("🔧  ПРИМЕНЕНИЕ ФИКСА /etc/resolv.conf")
    _box_row()
    _box_row(f"  Метод:  {CYAN}static /etc/resolv.conf + nsswitch.conf{NC}")
    _box_row(f"  Цель:   перенаправить серверный DNS на {CYAN}127.0.0.1{NC} "
             f"(DNSCrypt-proxy)")
    _box_row()
    _box_row(f"  {BOLD}Будет выполнено (БЕЗОПАСНО — не трогает интерфейсы):{NC}")
    _box_row(f"    {DIM}• бэкап /etc/resolv.conf → /etc/resolv.conf.chimera.bak{NC}")
    _box_row(f"    {DIM}• бэкап /etc/nsswitch.conf → /etc/nsswitch.conf.chimera.bak{NC}")
    _box_row(f"    {DIM}• /etc/resolv.conf → nameserver 127.0.0.1{NC}")
    _box_row(f"    {DIM}  (glibc/curl/dig/apt/ssh используют этот файл напрямую){NC}")
    _box_row(f"    {DIM}• /etc/nsswitch.conf → убрать `resolve` из hosts:{NC}")
    _box_row(f"    {DIM}  (bypass systemd-resolved — DHCP DNS не перехватывает){NC}")
    _box_row(f"    {DIM}• drop-in /etc/systemd/resolved.conf.d/chimera-dns.conf{NC}")
    _box_row(f"    {DIM}  (defense-in-depth: Global DNS = 127.0.0.1){NC}")
    _box_row(f"    {DIM}• resolvectl dns LINK 127.0.0.1 + default-route LINK false{NC}")
    _box_row(f"    {DIM}  (per-link override, runtime, SAFE){NC}")
    _box_row(f"    {DIM}• systemctl restart systemd-resolved + flush-caches{NC}")
    _box_row(f"    {DIM}• persist-сервис chimera-dns-fix.service (Python){NC}")
    _box_row()
    _box_row(f"  {GREEN}НЕ ВЫЗЫВАЕТ: networkctl, ifconfig, ip link, dhclient{NC}")
    _box_row(f"  {GREEN}НЕ ТРОГАЕТ: сетевые интерфейсы, IP-адреса, DHCP-leases{NC}")
    _box_row()
    _box_row(f"  {GREEN}Откат доступен в любой момент — кнопка R в меню.{NC}")
    _box_bottom()

    print()
    try:
        confirm = input(f"{CYAN}Применить фикс? [Y/n]: {NC}").strip().lower()
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


def _screen_fix_reapply(diag: Dict[str, Any]) -> None:
    os.system("clear")
    print()
    _box_top("🔄  ПЕРЕПРИМЕНИТЬ ФИКС (RE-APPLY)")
    _box_row()
    _box_row(f"  {YELLOW}Фикс уже применён, но возможны остаточные проблемы.{NC}")
    _box_row(f"  {YELLOW}Переприменение обновит все файлы и resolvectl настройки.{NC}")
    _box_row()
    _box_row(f"  {BOLD}Будет переприменено (force=True, БЕЗОПАСНО):{NC}")
    _box_row(f"    {DIM}• /etc/resolv.conf → nameserver 127.0.0.1{NC}")
    _box_row(f"    {DIM}• /etc/nsswitch.conf → убрать `resolve`{NC}")
    _box_row(f"    {DIM}• drop-in /etc/systemd/resolved.conf.d/chimera-dns.conf{NC}")
    _box_row(f"    {DIM}• per-link resolvectl override (runtime, SAFE){NC}")
    _box_row(f"    {DIM}• persist-сервис chimera-dns-fix.service{NC}")
    _box_row()
    _box_row(f"  {GREEN}НЕ ВЫЗЫВАЕТ: networkctl, ifconfig, ip link{NC}")
    _box_bottom()

    print()
    try:
        confirm = input(f"{CYAN}Переприменить фикс? [Y/n]: {NC}").strip().lower()
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


def _screen_rollback() -> None:
    os.system("clear")
    print()
    _box_top("🔄  ОТКАТ ФИКСА /etc/resolv.conf")
    _box_row()
    _box_row(f"  {BOLD}Будет выполнено (БЕЗОПАСНО):{NC}")
    _box_row(f"    {DIM}• остановить и удалить persist-сервис{NC}")
    _box_row(f"    {DIM}• восстановить /etc/resolv.conf из бэкапа{NC}")
    _box_row(f"    {DIM}• восстановить /etc/nsswitch.conf из бэкапа{NC}")
    _box_row(f"    {DIM}• удалить drop-in /etc/systemd/resolved.conf.d/chimera-dns.conf{NC}")
    _box_row(f"    {DIM}• systemctl restart systemd-resolved + flush-caches{NC}")
    _box_row()
    _box_row(f"  {YELLOW}После отката DNS снова будет идти через провайдера —{NC}")
    _box_row(f"  {YELLOW}возможна утечка DNS (как до фикса).{NC}")
    _box_bottom()

    print()
    try:
        confirm = input(f"{CYAN}Откатить фикс? [y/N]: {NC}").strip().lower()
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

    Зацикленный: после каждого действия экран перерисовывается.
    Меню: [F] Fix / [U] Re-apply / [R] Rollback / [D] Diagnose / [Q] Exit.
    """
    while True:
        os.system("clear")
        print()

        diag = diagnose_resolv_conf()
        state = _state_load()
        already_fixed = state.get("fixed", False)

        # Нужен ли re-apply? Если фикс применён, но resolv.conf не на localhost
        # или nsswitch всё ещё имеет resolve.
        needs_reapply = (already_fixed
                         and (not diag["resolv_conf_on_localhost"]
                              or diag["nsswitch_has_resolve"])
                         and diag["dnscrypt_service_active"]
                         and diag["dnscrypt_listening"])

        _box_top("🔧  ИСПРАВЛЕНИЕ /etc/resolv.conf (DNS LEAK FIX)")
        _box_desc(
            "Безопасное перенаправление серверного DNS на локальный "
            "DNSCrypt-proxy (127.0.0.1). НЕ трогает сетевые интерфейсы, "
            "НЕ вызывает networkctl/ifconfig/ip link — SSH-соединение "
            "не пострадает."
        )
        _box_sep()
        _print_diagnosis(diag)
        if already_fixed:
            _box_sep()
            _print_fix_state_badge(state)
        _box_bottom()

        print()

        _box_top("ДЕЙСТВИЯ")
        if diag["fix_needed"]:
            _box_item("F", f"{GREEN}Исправить автоматически{NC}  "
                           f"(направить DNS → 127.0.0.1 = DNSCrypt-proxy)")
        if needs_reapply:
            _box_item("U", f"{GREEN}Переприменить фикс{NC}  "
                           f"{YELLOW}← обновить resolv.conf + nsswitch.conf{NC}")
        if already_fixed:
            _box_item("R", f"{YELLOW}Откатить фикс{NC}  "
                           f"(вернуть как было)")
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
            continue
        elif ch in ("q", "0", ""):
            return
        else:
            _warn("Неверный выбор")
            time.sleep(1)


# =============================================================================
#  Точка входа
# =============================================================================
__all__ = [
    "diagnose_resolv_conf",
    "fix_resolv_conf_to_localhost",
    "rollback_resolv_conf",
    "do_fix_resolv_conf_interactive",
]
