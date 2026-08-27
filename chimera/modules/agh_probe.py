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
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import random
import re
import socket
import struct
import subprocess
import time
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
        return True, note

    # Шаг 5: проба провалилась — откатываем redirect, чтобы не оставить
    # систему хуже исходного состояния (glibc продолжал ходить на dnscrypt)
    if redir_port is not None:
        dns53_redirect_restore(run, redir_port)
        log_warn(f"AdGuardHome не резолвит ({note}) — iptables redirect "
                 f"53→{redir_port} восстановлен")
    return False, f"не резолвит: {note}"
