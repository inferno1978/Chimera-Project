"""
chimera/modules/agh_probe.py
───────────────────────────────────────────────────────────────────────────────
Health-check локального AdGuardHome и безопасное переключение DNS-пути Xray.

ЗАЧЕМ
=====
Стек: Xray → AdGuardHome (127.0.0.1:53) → DNSCrypt (127.0.0.1:5300) → интернет.
Генераторы xray-конфига, не знающие об AGH, указывают Xray на DNSCrypt:5300
напрямую — фильтрация и Query Log AGH молча обходятся. Этот модуль даёт
единый health-check «можно ли доверить локальному AGH DNS для Xray», который
используют:

  • generate_xray_config()                  (xray_install.py, Режим A REALITY)
  • generate_xray_config_xhttp()            (xray_install.py, Режим A xHTTP)
  • generate_xray_config_chain_entry()      (chain_nodes.py, Режим B single)
  • generate_xray_config_chain_entry_multi()(chain_nodes.py, Режим B multi)
  • do_emergency_repair()                   (emergency_repair.py — старт AGH
                                             до пересборки конфига)
  • fix_resolv_conf_to_localhost()          (resolv_conf_fix.py — AGH-guard
                                             для iptables redirect)

КРИТЕРИИ ЗДОРОВЬЯ (все три обязательны)
=======================================
1. Сервис AdGuardHome активен (systemctl is-active; имена юнитов, под которыми
   AGH ставят официально: adguardhome / AdGuardHome).
2. AGH владеет 127.0.0.1:53/udp (парсинг `ss -ulnp`) — а не dnscrypt-proxy
   и не systemd-resolved (127.0.0.53:53 не матчится — другой адрес).
3. AGH РЕАЛЬНО резолвит: живой A-запрос через UDP-сокет на 127.0.0.1:53
   (www.example.com, 2 попытки с таймаутом) — это end-to-end проверка всей
   цепочки AGH → upstream (dnscrypt/DoH) → интернет.

ПОБОЧНЫЙ ЭФФЕКТ: iptables redirect 53→5300
==========================================
resolv_conf_fix.py создаёт в nat OUTPUT redirect «-d 127.0.0.1 --dport 53 →
REDIRECT --to-ports 5300», когда DNSCrypt слушает не на 53. Если AGH занял
:53, этот redirect молча уносит ЛЮБОЙ локальный трафик (glibc, Xray, B4)
с AGH на DNSCrypt — AGH обходится, хотя «всё настроено». Поэтому после
подтверждения владения AGH портом :53 redirect снимается ДО пробы резолва
и восстанавливается, если проба провалилась — система никогда не остаётся
в худшем состоянии, чем была (rollback).

ПРИНЦИП БЕЗОПАСНОСТИ
====================
- Никаких правок сетевых интерфейсов/юнитов — только чтение состояния и
  точечные `iptables -D/-A` со спецификациями, идентичными resolv_conf_fix.py
  (comment "chimera-dns-fix").
- Любой сбой любого шага = «AGH недоступен» → вызывающий код обязан
  откатиться на прежний путь (DNSCrypt:5300). Это гарантируется тем, что
  функция возвращает (False, причина), а не бросает исключение наружу.

Публичное API:
  agh_dns_available(run, log_info, log_warn, autostart) → (ok, reason)
  agh_ensure_running(run, wait)                            → (ok, note)
  agh_service_active(run) / agh_owns_dns53(run)
  dns53_redirect_state(run) → int | None
  dns53_redirect_remove(run, port) / dns53_redirect_restore(run, port)
  xray_dns_path_report(run) → dict (фактический DNS-путь Xray — для
                             health-отчётов меню и emergency repair)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import random
import re
import socket
import struct
import subprocess
import time
from pathlib import Path
from typing import Callable, Optional, Tuple

# ─── Константы ───────────────────────────────────────────────────────────────
AGH_UNIT_CANDIDATES: Tuple[str, ...] = ("adguardhome", "AdGuardHome")
AGH_DNS_ADDR = "127.0.0.1"
AGH_DNS_PORT = 53
PROBE_DOMAIN = "www.example.com"     # нейтральный домен, не бывает в блок-листах
PROBE_ATTEMPTS = 2
PROBE_TIMEOUT = 2.0                  # сек на попытку (loopback — быстро)
AGH_START_WAIT = 5                   # сек ожидания старта сервиса (autostart)

# Спецификации iptables-правил — идентичны resolv_conf_fix.py
_IPTABLES_COMMENT = "chimera-dns-fix"

# Пути к config.json Xray (канонический Chimera + официальный установщик)
# — те же кандидаты, что и в финальной проверке do_full_install.
_XRAY_CONFIG_CANDIDATES: Tuple[Path, ...] = (
    Path("/etc/xray/config.json"),
    Path("/usr/local/etc/xray/config.json"),
)

# ─── Runner по умолчанию (когда core._run недоступен: юнит-тесты) ────────────
def _default_run(cmd, capture: bool = True, check: bool = False,
                 quiet: bool = True, **kw):
    """Минимальный аналог core._run: CompletedProcess-совместимый."""
    return subprocess.run(cmd, capture_output=capture, text=True, check=check)


# =============================================================================
#  ШАГ 1. СЕРВИС
# =============================================================================
def agh_service_active(run: Optional[Callable] = None) -> bool:
    """AdGuardHome-сервис активен? (пробует оба каноничных имени юнита)."""
    run = run or _default_run
    for unit in AGH_UNIT_CANDIDATES:
        r = run(["systemctl", "is-active", unit], capture=True, check=False)
        if getattr(r, "stdout", "") and r.stdout.strip().splitlines()[0] == "active":
            return True
    return False


def agh_ensure_running(run: Optional[Callable] = None,
                       wait: int = AGH_START_WAIT) -> Tuple[bool, str]:
    """Поднять AGH, если он установлен, но остановлен.

    Возвращает (ok, note):
      (False, "не установлен")  — юнита нет (обычный стек без AGH);
      (True,  "уже активен")    — ничего не делали;
      (True,  "запущен")        — стартовали и дождались active;
      (False, "не поднялся")    — старт не удался (вызывающий откатывается
                                  на DNSCrypt:5300).
    Используется emergency_repair'ом ДО пересборки xray-конфига: генераторы
    делают health-check и переключат DNS на 127.0.0.1:53 только у живого AGH.
    """
    run = run or _default_run
    if agh_service_active(run):
        return True, "уже активен"

    started_unit = None
    for unit in AGH_UNIT_CANDIDATES:
        # systemctl start несуществующего юнита безвреден (rc!=0, ignore)
        r = run(["systemctl", "start", unit], capture=True, check=False)
        if getattr(r, "returncode", 1) == 0:
            started_unit = unit
            break
    if started_unit is None:
        return False, "не установлен"

    deadline = time.time() + max(1, wait)
    while time.time() < deadline:
        if agh_service_active(run):
            return True, f"запущен ({started_unit})"
        time.sleep(0.5)
    return False, "не поднялся"


# =============================================================================
#  ШАГ 2. ВЛАДЕНИЕ 127.0.0.1:53/udp
# =============================================================================
def agh_owns_dns53(run: Optional[Callable] = None) -> bool:
    """Именно AdGuardHome слушает 127.0.0.1:53/udp?

    ss -ulnp (только listening-сокеты → колонка peer отсутствует):
        UNCONN 0 0 127.0.0.1:53 0.0.0.0:* users:(("AdGuardHome",pid=…,fd=6))
    Матчинг: имя процесса содержит "adguardhome" (case-insensitive) И адрес
    ровно 127.0.0.1:53 (граница слова после :53 отсекает :5300;
    127.0.0.53:53 не совпадает строкой — другой адрес).
    """
    run = run or _default_run
    r = run(["ss", "-ulnp"], capture=True, check=False)
    out = getattr(r, "stdout", "") or ""
    for line in out.splitlines():
        if "adguardhome" not in line.lower():
            continue
        if re.search(r"127\.0\.0\.1:53(?!\d)", line):
            return True
    return False


# =============================================================================
#  ШАГ 3. ПРОБА РЕЗОЛВА (живой DNS-запрос)
# =============================================================================
def _build_dns_query(domain: str, txid: int) -> bytes:
    """Минимальный DNS A-запрос (RFC 1035), без внешних зависимостей."""
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # RD=1, QDCOUNT=1
    qname = b""
    for label in domain.split("."):
        qname += bytes([len(label)]) + label.encode("ascii")
    qname += b"\x00"
    question = struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + qname + question


def _parse_dns_response(resp: bytes, txid: int) -> bool:
    """Ответ валиден? (txid совпал, QR=1, rcode=NOERROR, есть answers)."""
    if len(resp) < 12:
        return False
    r_txid, flags, _qd, an, _ns, _ar = struct.unpack(">HHHHHH", resp[:12])
    if r_txid != txid:
        return False
    if not (flags & 0x8000):        # QR-бит: это response
        return False
    if (flags & 0x000F) != 0:       # RCODE: 0 = NOERROR
        return False
    return an >= 1                  # хотя бы одна answer-запись


def agh_probe_resolve(timeout: float = PROBE_TIMEOUT,
                      domain: str = PROBE_DOMAIN,
                      attempts: int = PROBE_ATTEMPTS) -> Tuple[bool, str]:
    """Живой DNS-запрос к 127.0.0.1:53. Возвращает (ok, note).

    Это end-to-end проверка всей цепочки AGH → upstream → интернет:
    SERVFAIL/таймаут/битый ответ = цепочка не работает → вызывающий
    обязан откатиться на прежний путь (DNSCrypt:5300).
    """
    for attempt in range(1, max(1, attempts) + 1):
        txid = random.randint(0, 0xFFFF)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        t0 = time.monotonic()
        try:
            sock.sendto(_build_dns_query(domain, txid), (AGH_DNS_ADDR, AGH_DNS_PORT))
            resp, _ = sock.recvfrom(4096)
        except OSError as e:
            # socket.timeout — алиас/подкласс OSError (Py≥3.3): покрывает и
            # таймаут, и «connection refused», и прочие сбои сокета
            last_err = f"{type(e).__name__}: {e}"
            continue
        finally:
            sock.close()
        if _parse_dns_response(resp, txid):
            ms = (time.monotonic() - t0) * 1000
            ips = max(1, struct.unpack(">H", resp[6:8])[0])
            return True, f"{domain} → {ips} ответ(ов), {ms:.0f} мс"
        last_err = f"невалидный ответ (rcode/an-count), попытка {attempt}"
    return False, f"нет валидного ответа от {AGH_DNS_ADDR}:{AGH_DNS_PORT} ({last_err})"


# =============================================================================
#  IPTABLES REDIRECT 53→5300 (нейтрализация + rollback)
# =============================================================================
def dns53_redirect_state(run: Optional[Callable] = None) -> Optional[int]:
    """Порт, на который nat OUTPUT сейчас уводит 127.0.0.1:53 (или None).

    Пример строки iptables -t nat -L OUTPUT -n:
        REDIRECT  udp  --  0.0.0.0/0  127.0.0.1  udp dpt:53 redir ports 5300
    """
    run = run or _default_run
    r = run(["iptables", "-t", "nat", "-L", "OUTPUT", "-n"],
            capture=True, check=False)
    if getattr(r, "returncode", 1) != 0:
        return None
    out = getattr(r, "stdout", "") or ""
    for line in out.splitlines():
        if "REDIRECT" not in line or "dpt:53" not in line:
            continue
        m = re.search(r"(?:redir ports|to:)\s*(\d+)", line)
        if m:
            return int(m.group(1))
    return None


def _redirect_rule_specs(port: int):
    """Спецификации правил udp+tcp — зеркально resolv_conf_fix.py."""
    for proto in ("udp", "tcp"):
        yield (proto, [
            "-p", proto, "-d", AGH_DNS_ADDR, "--dport", str(AGH_DNS_PORT),
            "-j", "REDIRECT", "--to-ports", str(port),
            "-m", "comment", "--comment", _IPTABLES_COMMENT,
        ])


def dns53_redirect_remove(run: Optional[Callable] = None,
                          port: int = 5300) -> bool:
    """Снять redirect 53→port (idempotent, ошибки молча игнорируются)."""
    run = run or _default_run
    for _proto, spec in _redirect_rule_specs(port):
        run(["iptables", "-t", "nat", "-D", "OUTPUT", *spec],
            capture=True, check=False)
    return True


def dns53_redirect_restore(run: Optional[Callable] = None,
                           port: int = 5300) -> bool:
    """Вернуть redirect 53→port (rollback пробы; совместимо с resolv_conf_fix)."""
    run = run or _default_run
    ok = True
    for _proto, spec in _redirect_rule_specs(port):
        r = run(["iptables", "-t", "nat", "-A", "OUTPUT", *spec],
                capture=True, check=False)
        if getattr(r, "returncode", 1) != 0:
            ok = False
    return ok


# =============================================================================
#  ГЛАВНЫЙ HEALTH-CHECK
# =============================================================================
def agh_dns_available(run: Optional[Callable] = None,
                      log_info: Optional[Callable] = None,
                      log_warn: Optional[Callable] = None,
                      autostart: bool = False) -> Tuple[bool, str]:
    """Можно ли доверить локальному AdGuardHome DNS для Xray?

    Полная цепочка проверок (service → владение :53 → нейтрализация
    redirect → end-to-end проба резолва с rollback'ом). Возвращает
    (ok, reason); reason — человеческое объяснение для лога.

    Побочный эффект: при подтверждённом AGH на :53 redirect 53→5300
    снимается (он вреден: уводит glibc/Xray/B4 с AGH на DNSCrypt).
    Если проба резолва проваливается — redirect восстанавливается.

    autostart=True поднимает остановленный сервис перед проверкой
    (используется emergency_repair'ом; генераторы конфига работают
    с autostart=False — предсказуемо и без сюрпризов).
    """
    run = run or _default_run
    log_info = log_info or (lambda msg: None)
    log_warn = log_warn or (lambda msg: None)

    # Шаг 1: сервис
    if not agh_service_active(run):
        if autostart:
            ok_start, note = agh_ensure_running(run)
            if not ok_start:
                return False, f"сервис AGH: {note}"
            log_info(f"AdGuardHome: {note}")
        else:
            return False, "сервис adguardhome/AdGuardHome не активен"

    # Шаг 2: владение 127.0.0.1:53
    if not agh_owns_dns53(run):
        return False, "127.0.0.1:53/udp не принадлежит AdGuardHome"

    # Шаг 3: нейтрализуем redirect 53→X (иначе проба и будущие запросы
    # Xray/glibc молча уйдут на dnscrypt:X, минуя AGH)
    redir_port = dns53_redirect_state(run)
    if redir_port is not None:
        dns53_redirect_remove(run, redir_port)
        log_info(f"AdGuardHome держит 127.0.0.1:53 — снят iptables redirect "
                 f"53→{redir_port} (он уводил локальный DNS с AGH)")

    # Шаг 4: end-to-end проба резолва
    ok_probe, note = agh_probe_resolve()
    if ok_probe:
        # v65 (ratelimit-heal): санация ЖИВОГО конфига AGH. Эмпирика:
        # ratelimit>0 в AGH v0.107.79 = ТИХИЙ DROP сверх лимита (без
        # REFUSED и без логов), whitelist-поле мёртво, весь DNS Xray =
        # один /24-бакет 20 rps → EOF-шторм у клиентов. Проба на 1-2 qps
        # этого НЕ ловит — патчу конфиг при подтверждённо живом AGH.
        # Вызывается всеми 4 генераторами конфига + resolv-фиксом.
        try:
            from chimera.modules.aghome_setup import (
                aghome_fix_ratelimit_if_needed)
            healed, hnote = aghome_fix_ratelimit_if_needed(
                log_info=log_info, log_warn=log_warn)
            if healed:
                return True, note
            # Патч записан, но AGH не поднялся — :53 больше нельзя
            # доверять: возвращаем redirect (если снимали) и уходим
            # в fallback на DNSCrypt:5300.
            if redir_port is not None:
                dns53_redirect_restore(run, redir_port)
                log_warn(f"AGH не поднялся после санации ({hnote}) — "
                         f"redirect 53→{redir_port} восстановлен")
            return False, f"AGH не поднялся после санации ({hnote})"
        except Exception as _e:
            # Санация опциональна (проба уже прошла) — не блокируем путь.
            log_warn(f"AGH: санация ratelimit пропущена: {_e}")
        return True, note

    # Шаг 5: проба провалилась — откатываем redirect, чтобы не оставить
    # систему хуже исходного состояния (glibc продолжал ходить на dnscrypt)
    if redir_port is not None:
        dns53_redirect_restore(run, redir_port)
        log_warn(f"AdGuardHome не резолвит ({note}) — iptables redirect "
                 f"53→{redir_port} восстановлен")
    return False, f"не резолвит: {note}"


# =============================================================================
#  ФАКТИЧЕСКИЙ DNS-ПУТЬ XRAY (для health-отчётов и emergency repair)
# =============================================================================
def _xray_dns_servers_from_config() -> list:
    """dns.servers из ФАКТИЧЕСКОГО config.json Xray (первый найденный).

    Никаких предположений о том, ЧТО должен был сгенерировать генератор —
    читаем итоговый артефакт (те же кандидаты, что в финальной проверке
    do_full_install). Пустой список = конфига нет / без DNS-секции.
    """
    for p in _XRAY_CONFIG_CANDIDATES:
        try:
            if not p.exists():
                continue
            cfg = json.loads(p.read_text(errors="replace"))
            servers = (cfg.get("dns") or {}).get("servers") or []
            if servers:
                return servers
        except Exception:
            continue
    return []


def xray_dns_path_report(run: Optional[Callable] = None) -> dict:
    """v62: фактический DNS-путь Xray одной строкой — для health-отчёта
    меню (health.py / health_report.py) и emergency repair.

    Читает ФАКТИЧЕСКИЙ config.json (dns.servers[0] — генераторы ставят
    туда основной путь: AGH:53 / DNSCrypt:5300 / публичный DNS) и сверяет
    его с ЖИВЫМ состоянием стека: конфиг «через AGH» + мёртвый AGH =
    запросы Xray молча уходят в runtime-fallback, фильтры и кеш AGH
    обходятся — именно эту ситуацию отчёт обязан показать.

    Возвращает dict (plain text, без ANSI — пригоден для Telegram/лога):
      ok     — путь здоров (первый сервер реально работает)
      icon   — ✅ / ⚠️ / ℹ️ / ❌
      chain  — короткая цепочка: «Xray → AGH:53 → DNSCrypt:5300»
      line   — готовая строка «DNS-путь: …» (иконкой не начинается)

    Побочных эффектов нет (в отличие от agh_dns_available — iptables
    не трогаем: это диагностика, а не лечение).
    """
    run = run or _default_run
    servers = _xray_dns_servers_from_config()
    if not servers:
        return {"ok": False, "icon": "❌", "chain": "—",
                "line": "DNS-путь: config.json не найден или без DNS-секции"}

    first = servers[0] if isinstance(servers[0], dict) else {}
    addr = str(first.get("address", ""))
    try:
        port = int(first.get("port", 53))
    except (TypeError, ValueError):
        port = 53

    # Ветка 1: AGH (127.0.0.1:53) — критерии agh_dns_available без
    # побочных эффектов: сервис активен + владеет :53 + живая проба.
    if addr == AGH_DNS_ADDR and port == AGH_DNS_PORT:
        chain = "Xray → AGH:53 → DNSCrypt:5300"
        if agh_service_active(run) and agh_owns_dns53(run):
            probe_ok, note = agh_probe_resolve()
            if probe_ok:
                return {"ok": True, "icon": "✅", "chain": chain,
                        "line": f"DNS-путь: {chain} — AGH отвечает ({note})"}
            return {"ok": False, "icon": "⚠️", "chain": chain,
                    "line": f"DNS-путь: {chain} — AGH не резолвит ({note}); "
                            f"Xray идёт через fallback, фильтры AGH "
                            f"не применяются"}
        return {"ok": False, "icon": "⚠️", "chain": chain,
                "line": "DNS-путь: конфиг указывает на AGH:53, но сервис "
                        "AGH не активен/не владеет :53 — Xray идёт через "
                        "fallback, фильтры AGH не применяются"}

    # Ветка 2: DNSCrypt напрямую (127.0.0.1:<порт>)
    if addr == "127.0.0.1":
        chain = f"Xray → DNSCrypt:{port}"
        r = run(["systemctl", "is-active", "dnscrypt-proxy"],
                capture=True, check=False)
        if (getattr(r, "stdout", "") or "").strip() == "active":
            return {"ok": True, "icon": "✅", "chain": chain,
                    "line": f"DNS-путь: {chain} → интернет"}
        return {"ok": False, "icon": "⚠️", "chain": chain,
                "line": f"DNS-путь: {chain} — dnscrypt-proxy не активен"}

    # Ветка 3: публичный DNS напрямую (легитимный путь без локального стека)
    chain = f"Xray → {addr}:{port} (публичный DNS напрямую)"
    return {"ok": True, "icon": "ℹ️", "chain": chain,
            "line": f"DNS-путь: {chain}"}
