#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chimera/modules/awg_b4_split.py — B4-сплит каскада AmneziaWG
───────────────────────────────────────────────────────────────────────────────
B4-сплит для AWG-каскада: выбранные домены (сеты b4 + ручные) напрямую
с RU-entry ноды через DPI-bypass b4, всё остальное — каскадом на exit.

ЗАЧЕМ: Google отключила рекламу для RU-IP → YouTube с RU-egress = без
рекламы. Каскад шлёт YouTube через exit (зарубежный IP) — реклама есть.

СХЕМА (entry-нода, интерфейсы awg0=клиенты, awg1=туннель к exit):

  клиент ──► awg0 ──┬── dst ∈ awg_b4_direct ──► БЕЗ mark 0x8200 ──► main
                    │   (mark НЕ ставится)      → WAN (MASQUERADE есть)
                    │   awg_b4exempt: без 0x8000 → b4 обрабатывает
                    │   (fake SNI + fragmentation + QUIC reject)
                    │   ЦЕЛЬ ВИДИТ RU-IP ноды ★
                    │
                    └── dst ∉ set ──► MARK 0x8200 (b4-exempt) ──► table 2000
                        → awg1 → exit (зарубежный IP) — как раньше

DNS (критично для «глазами RU-ноды» + без AAAA):
  udp/tcp 53 из awg0 ──► DNAT на public-IP:53 (AGH: dnscrypt DoH) ──► A-ответы
  AGH-ответы из awg0 (sport 53) ──► meta 0x8000 (b4 output не трогает)
  AAAA split-доменов ──► user_rules AGH «||domain^$dnstype=AAAA» (v6→каскад
  вернул бы рекламу — фильтр обязателен). v6-DNS из awg0 ──► REJECT (fallback v4).

ipset awg_b4_direct (iptables-исключение) + nft-сет awg_b4direct в таблице
awg_b4exempt (условный exempt) — ДВА представления одного списка IP.
ПОРЯДОК ОБНОВЛЕНИЯ: сначала nft-сет, потом ipset-swap (промежуточное
состояние консистентно-каскадное: direct-dest уедет в каскад, а не
уедет «напрямую без b4» под ТСПУ).

Fail-safe: пустой набор IP (сеть легла / резолвер умер) НЕ трогает старый
ipset — деградация в каскад (реклама вернётся, но ничего не сломается).

Образцы: mieru_cascade._b4set_refresh (живой кейс 01-02.10.2026,
двухплечевой сплит b4-exempt), dns_redirect, awgs_cascade_failover_setup.
"""
from __future__ import annotations

import base64
import concurrent.futures
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Константы (марки — из awg_constants, единый источник) ───────────────────
from .awg_constants import (
    AWGS_IPSET_NAME,
    AWGS_CASCADE_FWMARK,
    AWGS_B4_EXEMPT_BIT,
    AWGS_ROUTING_SCRIPT,
    AWGS_CASCADE_DIR,
)

MODULE_NAME    = "awg_b4_split"
_STATE_FILE    = Path("/var/lib/xray-installer/awg_b4_split.json")
_LOG_FILE      = Path("/root/awg/awg_b4_split.log")
_B4_CONFIG     = Path("/etc/b4/config.json")

_IPSET         = "awg_b4_direct"
_IPSET_TMP     = "awg_b4_direct_new"
_SNAPSHOT      = AWGS_CASCADE_DIR / "awg_b4_direct.snapshot"

_NFT_TABLE     = "awg_b4exempt"          # inet-таблица b4-exempt
_NFT_SET       = "awg_b4direct"          # named set ВНУТРИ таблицы

_AGH_YAML      = Path("/opt/AdGuardHome/AdGuardHome.yaml")
_AGH_BACKUP    = Path("/opt/AdGuardHome/AdGuardHome.yaml.bak-b4split")
_AGH_SERVICE   = "AdGuardHome"
_AGH_QLOG_PATHS = (Path("/opt/AdGuardHome/data/querylog.json"),
                   Path("/var/lib/AdGuardHome/data/querylog.json"))

_RULE_COMMENT  = "awg-b4-split"          # comment во всех наших iptables-правилах

_TIMER_SVC     = "/etc/systemd/system/awg-b4-split-refresh.service"
_TIMER_UNIT    = "/etc/systemd/system/awg-b4-split-refresh.timer"
_TIMER_SCRIPT  = Path("/usr/local/sbin/awg-b4-split-refresh.sh")
_TIMER_NAME    = "awg-b4-split-refresh.timer"

_REFRESH_INTERVALS = (30, 60, 300, 900, 3600)   # сек

# Порт резолва (порт из mieru_cascade, проверен в проде 02.10.2026)
_QLOG_TAIL_B      = 4 * 1024 * 1024      # хвост querylog.json за один тик
_QLOG_WINDOW_S    = 24 * 3600            # окно свежести записей
_RESOLVE_MAX_WORKERS = 8
_RESOLVE_OVERALL_S   = 25                # общий таймаут пула резолва

# Правило AAAA (см. _AAAA_ITEM_RE — AGH перезаписывает yaml и срезает
# комментарии, поэтому маркеры не используются)


# ══════════════════════════════════════════════════════════════════════════════
#  ЛОГ / RUN
# ══════════════════════════════════════════════════════════════════════════════

def _log(level: str, msg: str) -> None:
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [{level:5}] {msg}"
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _info(msg: str) -> None: _log("INFO", msg)
def _warn(msg: str) -> None: _log("WARN", msg)
def _err(msg: str)  -> None: _log("ERR",  msg)


def _run(cmd, capture: bool = False, check: bool = False,
         timeout: int = 60, input_text: Optional[str] = None):
    """subprocess.run-обёртка (cmd — list[str])."""
    try:
        r = subprocess.run(
            cmd, capture_output=capture, text=True, check=check,
            timeout=timeout, input=input_text)
        return r
    except subprocess.TimeoutExpired:
        class _T:  # минимальный заглушечный результат
            returncode = 124
            stdout = ""
            stderr = "timeout"
        return _T()
    except Exception:
        class _E:
            returncode = 1
            stdout = ""
            stderr = "exception"
        return _E()


def _bash(script: str, timeout: int = 60):
    """bash -c с подавлением шума; возвращает CompletedProcess."""
    return _run(["bash", "-c", script], capture=True, timeout=timeout)


# ══════════════════════════════════════════════════════════════════════════════
#  STATE
# ══════════════════════════════════════════════════════════════════════════════

def _state_default() -> dict:
    return {
        "enabled": False,
        "set_ids": [],            # выбранные сеты b4 (id из config.json)
        "extra_domains": [],      # ручные домены поверх сетов
        "dns_redirect": True,     # DNAT udp/tcp 53 из awg0 → AGH ноды
        "aaaa_filter": True,      # ||domain^$dnstype=AAAA в user_rules AGH
        "refresh_sec": 60,        # интервал таймера
        "last_stats": {},         # метрики последнего тика
        "aaaa_domains": [],       # последний записанный в AGH список (diff-детект)
        "installed_at": None,
    }


def state_load() -> dict:
    if not _STATE_FILE.exists():
        return _state_default()
    try:
        data = json.loads(_STATE_FILE.read_text())
        base = _state_default()
        base.update({k: v for k, v in data.items() if k in base})
        return base
    except Exception as e:
        _warn(f"state повреждён ({e}), использую дефолт")
        return _state_default()


def state_save(st: dict) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, indent=2, ensure_ascii=False))
    tmp.chmod(0o600)
    tmp.replace(_STATE_FILE)


def is_active() -> bool:
    """Сплит включён? (для хуков в awg_cascade — генерация правил)."""
    try:
        return bool(state_load().get("enabled"))
    except Exception:
        return False


def mark_rule_exclusion() -> str:
    """Доп. матч для каскадного mark-правила ('' когда сплит выключен).

    awg_cascade подставляет это в mangle PREROUTING и в boot-скрипт:
    '-m set ! --match-set awg_b4_direct dst' — direct-плечо НЕ маркируется
    (→ main → WAN → b4 → ТСПУ), каскадное плечо маркируется как раньше.
    """
    return f" -m set ! --match-set {_IPSET} dst" if is_active() else ""


# ══════════════════════════════════════════════════════════════════════════════
#  СЕТЫ B4 + ДОМЕНЫ
# ══════════════════════════════════════════════════════════════════════════════

def detect_sets() -> list:
    """Сеты из config.json b4: [{id,name,enabled,domain_count}].

    domain_count = len(targets.sni_domains) — сколько доменов сет даёт для
    сплита (сеты-стратегии с 0 доменов — вариации базового сета, для
    маршрутизации бесполезны: резолвить нечего).
    """
    if not _B4_CONFIG.exists():
        return []
    try:
        cfg = json.loads(_B4_CONFIG.read_text())
    except Exception:
        return []
    out = []
    for s in cfg.get("sets", []):
        domains = ((s.get("targets") or {}).get("sni_domains")) or []
        out.append({
            "id": s.get("id", "?"),
            "name": s.get("name", "?"),
            "enabled": bool(s.get("enabled", True)),
            "domain_count": len(domains),
        })
    return out


def _normalize_domain(raw) -> Optional[str]:
    """'*.X'/'X.'/'X' → 'x'; catch-all/shorthand → None (не резолвим).

    Семантики зеркалят движок b4 (ParseDomainEntry) и
    dpi_bypass._normalize_b4_domain_entry: apex покрывает поддомены.
    """
    d = (raw or "").strip().lower().rstrip(".")
    if not d:
        return None
    if d.startswith("*."):
        d = d[2:]
    if d in ("*", "**", "*.*", "any", "all", "0/0") or d.startswith("regexp:"):
        return None
    # голый IPv4/CIDR — не домен (резолвить нечего; SNI-сеты доменные)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", d) or "/" in d:
        return None
    if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?"
                    r"(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", d):
        return None                       # IP/CIDR/мусор — не домен
    return d


def collect_domains(st: dict) -> list:
    """Эффективные домены сплита: выбранные И включённые сеты + ручные.

    Сет участвует, если его id ∈ st['set_ids'] И enabled в config.json b4
    (выключенный в b4 сет не обрабатывается b4 — гнать его мимо каскада
    без DPI-bypass опасно). Нормализация + дедуп, сортировка для
    стабильных diff'ов (AAAA-правила пишем только при изменении).
    """
    selected = {sid for sid in (st.get("set_ids") or []) if sid}
    domains: set = set()
    if selected and _B4_CONFIG.exists():
        try:
            cfg = json.loads(_B4_CONFIG.read_text())
            for s in cfg.get("sets", []):
                if s.get("id") not in selected:
                    continue
                if not s.get("enabled", True):
                    continue
                for raw in ((s.get("targets") or {}).get("sni_domains")) or []:
                    d = _normalize_domain(raw)
                    if d:
                        domains.add(d)
        except Exception as e:
            _warn(f"collect_domains: {e}")
    for raw in st.get("extra_domains") or []:
        d = _normalize_domain(raw)
        if d:
            domains.add(d)
    return sorted(domains)


# ══════════════════════════════════════════════════════════════════════════════
#  РЕЗОЛВ: системный вид + харвест querylog AGH (порт из mieru_cascade)
# ══════════════════════════════════════════════════════════════════════════════

def _ip_ok(ip: str) -> bool:
    """Публичный IPv4 (0.0.0.0 «заблокировано» AGH / rebind — мимо ipset)."""
    try:
        p = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    return (p.version == 4 and not p.is_private and not p.is_loopback
            and not p.is_unspecified and not p.is_reserved)


def _resolve_system(domain: str) -> set:
    """Системный резолвер ноды (127.0.0.1 → AGH → dnscrypt DoH)."""
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        return {ip for ip in ips if _ip_ok(ip)}
    except Exception:
        return set()


def _qlog_path() -> Optional[Path]:
    for p in _AGH_QLOG_PATHS:
        try:
            if p.is_file():
                return p
        except Exception:
            continue
    return None


def _qlog_epoch(t: str) -> Optional[float]:
    """RFC3339 AGH (наносекунды/Z) → epoch; мусор → None."""
    if not t:
        return None
    try:
        return datetime.fromisoformat(t).timestamp()
    except ValueError:
        m = re.match(
            r"^(.*T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$", t)
        if not m:
            return None
        base, frac, tz = m.groups()
        tz = (tz or "").replace("Z", "+00:00")
        if tz and ":" not in tz:
            tz = tz[:3] + ":" + tz[3:]
        try:
            return datetime.fromisoformat(
                base + "." + ((frac or "") + "000000")[:6] + tz).timestamp()
        except ValueError:
            return None


def _qh_suffix_match(qh: str, domains: list) -> bool:
    """QH — сам домен или поддомен (граница метки: evilX ≠ X)."""
    qh = (qh or "").strip().lower().rstrip(".")
    if not qh:
        return False
    for d in domains:
        if qh == d or qh.endswith("." + d):
            return True
    return False


def _dns_skip_name(msg: bytes, i: int) -> int:
    while i < len(msg):
        n = msg[i]
        if n == 0:
            return i + 1
        if (n & 0xC0) == 0xC0:
            return i + 2
        i += 1 + n
    return -1


def _dns_a_records(msg: bytes) -> set:
    """Публичные IPv4 из A-записей DNS-ответа (wire); AAAA/CNAME — мимо."""
    out: set = set()
    if len(msg) < 12:
        return out
    try:
        qd = int.from_bytes(msg[4:6], "big")
        an = int.from_bytes(msg[6:8], "big")
        i = 12
        for _ in range(qd):
            i = _dns_skip_name(msg, i)
            if i < 0:
                return out
            i += 4
        for _ in range(an):
            i = _dns_skip_name(msg, i)
            if i < 0 or i + 10 > len(msg):
                return out
            rtype = int.from_bytes(msg[i:i + 2], "big")
            rdl = int.from_bytes(msg[i + 8:i + 10], "big")
            i += 10
            if i + rdl > len(msg):
                return out
            if rtype == 1 and rdl == 4:
                ip = ".".join(str(b) for b in msg[i:i + 4])
                if _ip_ok(ip):
                    out.add(ip)
            i += rdl
    except Exception:
        return out
    return out


def harvest_querylog(domains: list) -> tuple:
    """Клиентский вид: IP из querylog.json AGH (что клиенты РЕАЛЬНО получили).

    Критично для rr*.googlevideo.com: пер-видео имена в сетах отсутствуют,
    резолвятся в GGC-кэши провайдера — только querylog их видит.
    Возвращает (set(ipv4), stats); любые сбои → пусто (мягкая деградация).
    """
    stats = {"names": 0, "entries": 0, "ips": 0}
    ips: set = set()
    if not domains:
        return ips, stats
    path = _qlog_path()
    if path is None:
        return ips, stats
    try:
        with path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - _QLOG_TAIL_B))
            data = f.read()
    except Exception:
        return ips, stats
    if not data:
        return ips, stats
    if size > _QLOG_TAIL_B:
        nl = data.find(b"\n")
        data = data[nl + 1:] if nl >= 0 else b""
    lowered = [d for d in domains]
    floor = time.time() - _QLOG_WINDOW_S
    names: set = set()
    for line in data.decode("utf-8", "replace").splitlines():
        if '"QH"' not in line or '"Answer"' not in line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        qh = (rec.get("QH") or "").strip().lower().rstrip(".")
        if not qh or not _qh_suffix_match(qh, lowered):
            continue
        ts = _qlog_epoch(rec.get("T") or "")
        if ts is None or ts < floor:
            continue
        b64 = rec.get("Answer") or ""
        if not b64:
            continue
        try:
            wire = base64.b64decode(b64 + "===")
        except Exception:
            continue
        got = _dns_a_records(wire)
        if got:
            names.add(qh)
            stats["entries"] += 1
            ips |= got
    stats["names"] = len(names)
    stats["ips"] = len(ips)
    return ips, stats


def resolve_domains(domains: list) -> dict:
    """Все виды резолва → {'ips': set, 'stats': {...}} (guard — на вызывающем)."""
    stats = {"domains": len(domains), "sys_failed": 0,
             "qlog_names": 0, "qlog_entries": 0, "qlog_ips": 0}
    ips: set = set()
    if not domains:
        stats["ips"] = 0
        return {"ips": ips, "stats": stats}
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=_RESOLVE_MAX_WORKERS) as ex:
        futs = [ex.submit(_resolve_system, d) for d in domains]
        try:
            for f in concurrent.futures.as_completed(
                    futs, timeout=_RESOLVE_OVERALL_S):
                try:
                    ips |= f.result(timeout=1)
                except Exception:
                    stats["sys_failed"] += 1
        except concurrent.futures.TimeoutError:
            stats["sys_failed"] += sum(1 for f in futs if not f.done())
    try:
        harvested, hst = harvest_querylog(domains)
    except Exception:
        harvested, hst = set(), {"names": 0, "entries": 0, "ips": 0}
    stats["qlog_names"] = hst["names"]
    stats["qlog_entries"] = hst["entries"]
    stats["qlog_ips"] = hst["ips"]
    ips |= harvested
    stats["ips"] = len(ips)
    return {"ips": ips, "stats": stats}


# ══════════════════════════════════════════════════════════════════════════════
#  IPSET (iptables-исключение каскадной марки)
# ══════════════════════════════════════════════════════════════════════════════

def ipset_ensure() -> bool:
    if not shutil.which("ipset"):
        return False
    for name in (_IPSET, _IPSET_TMP):
        _run(["ipset", "create", name, "hash:ip", "hashsize", "1024",
              "maxelem", "65536", "-exist"], capture=True)
    return True


def ipset_restore_snapshot() -> bool:
    """Бут-восстановление из снапшота (если есть) — до первого тика."""
    if not _SNAPSHOT.exists():
        return False
    r = _run(["bash", "-c",
              f"grep -vE '^create|^swap|^flush' {_SNAPSHOT} | "
              f"ipset restore -exist"], capture=True, timeout=60)
    return r.returncode == 0


def ipset_apply(ips: set) -> bool:
    """Атомарный swap: tmp ← ips, swap(tmp, боевой). Пусто → НЕ трогаем."""
    if not ips:
        return False
    if not ipset_ensure():
        return False
    _run(["ipset", "flush", _IPSET_TMP], capture=True)
    try:
        subprocess.run(
            ["ipset", "restore", "-exist"],
            input="".join(f"add {_IPSET_TMP} {ip}\n" for ip in sorted(ips)),
            capture_output=True, text=True, check=False, timeout=30)
    except Exception:
        pass
    _run(["ipset", "swap", _IPSET_TMP, _IPSET], capture=True)
    _run(["ipset", "flush", _IPSET_TMP], capture=True)
    # снапшот для быстрого бут-восстановления (до первого тика таймера)
    try:
        r = _run(["ipset", "save", _IPSET], capture=True, timeout=30)
        if r.returncode == 0 and r.stdout:
            _SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
            _SNAPSHOT.write_text(r.stdout)
    except Exception:
        pass
    return True


def ipset_size() -> int:
    r = _run(["ipset", "list", _IPSET], capture=True)
    if r.returncode != 0:
        return -1
    m = re.search(r"Number of entries:\s+(\d+)", r.stdout or "")
    return int(m.group(1)) if m else 0


def ipset_destroy() -> None:
    _bash(f"ipset destroy {_IPSET_TMP} 2>/dev/null; "
          f"ipset destroy {_IPSET} 2>/dev/null; true")


# ══════════════════════════════════════════════════════════════════════════════
#  NFT: таблица awg_b4exempt (условный exempt + output-защита AGH-ответов)
# ══════════════════════════════════════════════════════════════════════════════

def _nft_ensure_base() -> bool:
    """Таблица + обе цепи + named set (idempotent, ошибку существования
    глотаем — батч ниже всё равно флешит и добавляет заново)."""
    r = _bash(
        f"nft add table inet {_NFT_TABLE} 2>/dev/null; "
        f"nft add chain inet {_NFT_TABLE} prerouting "
        f"'{{ type filter hook prerouting priority mangle - 10; policy accept; }}' 2>/dev/null; "
        f"nft add chain inet {_NFT_TABLE} output "
        f"'{{ type filter hook output priority mangle - 10; policy accept; }}' 2>/dev/null; "
        f"nft list set inet {_NFT_TABLE} {_NFT_SET} >/dev/null 2>&1 || "
        f"nft add set inet {_NFT_TABLE} {_NFT_SET} '{{ type ipv4_addr; }}'; "
        f"true")
    return r.returncode == 0


def nft_apply_split() -> bool:
    """Сплит-форма awg_b4exempt (АТОМАРНЫЙ nft-батч).

    prerouting: awg1 → exempt; awg0+@set → return (b4 обработает);
    awg0 → exempt (каскад). output: AGH-ответы (sport 53 → awg0) exempt —
    иначе b4 output (udp sport 53 → queue) перехватил бы их (неизвестное
    поведение на чужих ответах; dnscrypt-цепочка чистая — фикс не нужен).
    Порядок prerouting-правил критичен: @set-return ДО blanket-awg0.
    """
    if not _nft_ensure_base():
        return False
    batch = (
        f"flush chain inet {_NFT_TABLE} prerouting\n"
        f"add rule inet {_NFT_TABLE} prerouting iifname \"awg1\" "
        f"meta mark set meta mark or {AWGS_B4_EXEMPT_BIT:#x} "
        f"ct mark set ct mark or {AWGS_B4_EXEMPT_BIT:#x}\n"
        f"add rule inet {_NFT_TABLE} prerouting iifname \"awg0\" "
        f"ip daddr @{_NFT_SET} return\n"
        f"add rule inet {_NFT_TABLE} prerouting iifname \"awg0\" "
        f"meta mark set meta mark or {AWGS_B4_EXEMPT_BIT:#x} "
        f"ct mark set ct mark or {AWGS_B4_EXEMPT_BIT:#x}\n"
        f"flush chain inet {_NFT_TABLE} output\n"
        f"add rule inet {_NFT_TABLE} output oifname \"awg0\" udp sport 53 "
        f"meta mark set meta mark or {AWGS_B4_EXEMPT_BIT:#x}\n"
        f"add rule inet {_NFT_TABLE} output oifname \"awg0\" tcp sport 53 "
        f"meta mark set meta mark or {AWGS_B4_EXEMPT_BIT:#x}\n"
    )
    r = _run(["nft", "-f", "-"], input_text=batch, capture=True, timeout=15)
    if r.returncode != 0:
        _err(f"nft_apply_split: {getattr(r, 'stderr', '')}")
        return False
    return True


def nft_apply_blanket() -> bool:
    """blanket-форма (сплит выключен): blanket awg0/awg1, без сета/output-цепи."""
    if not _nft_ensure_base():
        return False
    batch = (
        f"flush chain inet {_NFT_TABLE} prerouting\n"
        f"add rule inet {_NFT_TABLE} prerouting iifname \"awg0\" "
        f"meta mark set meta mark or {AWGS_B4_EXEMPT_BIT:#x} "
        f"ct mark set ct mark or {AWGS_B4_EXEMPT_BIT:#x}\n"
        f"add rule inet {_NFT_TABLE} prerouting iifname \"awg1\" "
        f"meta mark set meta mark or {AWGS_B4_EXEMPT_BIT:#x} "
        f"ct mark set ct mark or {AWGS_B4_EXEMPT_BIT:#x}\n"
        f"flush chain inet {_NFT_TABLE} output\n"
        f"delete chain inet {_NFT_TABLE} output\n"
        f"flush set inet {_NFT_TABLE} {_NFT_SET}\n"
        f"delete set inet {_NFT_TABLE} {_NFT_SET}\n"
    )
    r = _run(["nft", "-f", "-"], input_text=batch, capture=True, timeout=15)
    if r.returncode != 0:
        _err(f"nft_apply_blanket: {getattr(r, 'stderr', '')}")
        return False
    return True


def nft_set_replace(ips: set) -> bool:
    """Атомарная замена элементов named-сета (flush+add одним батчем)."""
    if not ips:
        return False
    if not _nft_ensure_base():
        return False
    lines = [f"flush set inet {_NFT_TABLE} {_NFT_SET}"]
    sorted_ips = sorted(ips)
    CH = 500                                    # чанк-стейтменты в одном батче
    for i in range(0, len(sorted_ips), CH):
        chunk = ", ".join(sorted_ips[i:i + CH])
        lines.append(
            f"add element inet {_NFT_TABLE} {_NFT_SET} {{ {chunk} }}")
    r = _run(["nft", "-f", "-"], input_text="\n".join(lines) + "\n",
             capture=True, timeout=30)
    if r.returncode != 0:
        _err(f"nft_set_replace: {getattr(r, 'stderr', '')[:300]}")
        return False
    return True


def nft_set_size() -> int:
    r = _run(["nft", "list", "set", "inet", _NFT_TABLE, _NFT_SET],
             capture=True)
    if r.returncode != 0:
        return -1
    m = re.search(r"elements\s*\{", r.stdout or "")
    if not m:
        return 0
    body = (r.stdout or "")[m.end():]
    end = body.find("}")
    elems = [e for e in body[:end].split(",") if e.strip()]
    return len(elems)


# ══════════════════════════════════════════════════════════════════════════════
#  КАСКАДНАЯ МАРКА (mangle PREROUTING — добавить исключение/вернуть как было)
# ══════════════════════════════════════════════════════════════════════════════

def _mark_spec(excl: bool) -> list:
    """argv mark-правила после 'iptables -t mangle -A PREROUTING'."""
    spec = ["-i", "awg0", "-m", "set", "!", "--match-set",
            AWGS_IPSET_NAME, "dst"]
    if excl:
        spec += ["-m", "set", "!", "--match-set", _IPSET, "dst"]
    spec += ["-j", "MARK", "--set-mark", hex(AWGS_CASCADE_FWMARK)]
    return spec


def cascade_mark_sync(excl: bool) -> bool:
    """Синхронизировать каскадное mark-правило с формой сплита.

    Add-first-then-delete: пока оба правила существуют, последний MARK
    выигрывает → у direct-dest пакетов остаётся 0x8200 → каскад
    (fail-safe), утечки «напрямую без b4» нет. Удаление легаси-вариантов —
    как в _awgs_cascade_apply_iptables (while-loop).
    """
    new = _mark_spec(excl)
    old = _mark_spec(not excl)
    # 1) убедиться что нужная форма есть
    chk = ["iptables", "-t", "mangle", "-C", "PREROUTING"] + new
    add = ["iptables", "-t", "mangle", "-A", "PREROUTING"] + new
    if _run(chk, capture=True).returncode != 0:
        _run(add, capture=True)
    # 2) удалить другую форму (и легаси-марку)
    for other in (old,
                  ["-i", "awg0", "-m", "set", "!", "--match-set",
                   AWGS_IPSET_NAME, "dst", "-j", "MARK",
                   "--set-mark", hex(AWGS_CASCADE_FWMARK & ~AWGS_B4_EXEMPT_BIT)]):
        while _run(["iptables", "-t", "mangle", "-D", "PREROUTING"] + other,
                   capture=True).returncode == 0:
            pass
    return True


def routing_script_regen() -> bool:
    """Перегенерировать awg-routing.sh под текущее состояние сплита.

    Генератор awg_cascade сам спросит mark_rule_exclusion()/is_active()
    (хук B4-сплита) — здесь только подтягиваем параметры каскада из state.
    """
    try:
        from .awg_cascade import _awgs_cascade_create_routing_script
        from .awg_state import awgs_state_load
        from .awg_net_common import awg_v6_ula_from_subnet
        from .awg_constants import AWGS_DEFAULT_SUBNET
    except Exception as e:
        _warn(f"routing_script_regen: import fail {e}")
        return False
    st = awgs_state_load()
    subnet = st.get("cascade_subnet") or AWGS_DEFAULT_SUBNET
    v6 = awg_v6_ula_from_subnet(subnet) if st.get("allow_ipv6_tunnel") else ""
    _awgs_cascade_create_routing_script(subnet, subnet_v6=v6)
    return True


# ══════════════════════════════════════════════════════════════════════════════
#  DNS: DNAT udp/tcp 53 из awg0 → AGH (public-IP:53); v6-DNS → REJECT
# ══════════════════════════════════════════════════════════════════════════════

def _node_public_ip() -> Optional[str]:
    """Публичный IPv4 ноды (src маршрута наружу; AGH биндит именно его)."""
    r = _run(["ip", "-4", "route", "get", "1.1.1.1"], capture=True)
    m = re.search(r"src (\d{1,3}(?:\.\d{1,3}){3})", r.stdout or "")
    return m.group(1) if m else None


def _agh_dns_alive(pub_ip: str) -> bool:
    """AGH слушает pub:53 (udp)? — health перед DNAT (анти-блэкхол)."""
    r = _run(["bash", "-c",
              f"ss -lun | grep -q '{pub_ip}:53'"], capture=True)
    return r.returncode == 0


def dns_rules_apply() -> bool:
    """DNAT v4-DNS клиентов на AGH + INPUT-разрешение + v6-DNS REJECT.

    Локальная доставка не зависит от каскадной марки: DNAT в nat
    PREROUTING подменяет dst на public-IP, а local-таблица (ip rule pref 0)
    рассматривается РАНЬШЕ fwmark-правил → пакет уходит в INPUT к AGH.
    v6-DNS режем в FORWARD: клиент откатывается на v4 → DNAT → AGH.
    """
    pub = _node_public_ip()
    if not pub:
        _warn("dns_rules_apply: не определил публичный IP ноды")
        return False
    if not _agh_dns_alive(pub):
        _warn(f"dns_rules_apply: AGH не слушает {pub}:53 — DNAT не ставлю")
        return False
    c = _RULE_COMMENT
    rules = [
        # nat: перехват любого v4-DNS из туннеля (анти-DNS-leak)
        f"iptables -t nat -C PREROUTING -i awg0 -p udp --dport 53 -m comment --comment {c} -j DNAT --to-destination {pub}:53 2>/dev/null || "
        f"iptables -t nat -A PREROUTING -i awg0 -p udp --dport 53 -m comment --comment {c} -j DNAT --to-destination {pub}:53",
        f"iptables -t nat -C PREROUTING -i awg0 -p tcp --dport 53 -m comment --comment {c} -j DNAT --to-destination {pub}:53 2>/dev/null || "
        f"iptables -t nat -A PREROUTING -i awg0 -p tcp --dport 53 -m comment --comment {c} -j DNAT --to-destination {pub}:53",
        # filter INPUT: разрешить DNAT'нутый DNS ДО ufw-цепочек
        f"iptables -C INPUT -i awg0 -p udp --dport 53 -m comment --comment {c} -j ACCEPT 2>/dev/null || "
        f"iptables -I INPUT 1 -i awg0 -p udp --dport 53 -m comment --comment {c} -j ACCEPT",
        f"iptables -C INPUT -i awg0 -p tcp --dport 53 -m comment --comment {c} -j ACCEPT 2>/dev/null || "
        f"iptables -I INPUT 1 -i awg0 -p tcp --dport 53 -m comment --comment {c} -j ACCEPT",
        # v6: plain-DNS из туннеля → REJECT (fallback на v4 → AGH);
        # без этого AAAA-фильтр обходится через v6-резолвер → реклама вернётся
        f"ip6tables -C FORWARD -i awg0 -p udp --dport 53 -m comment --comment {c} -j REJECT 2>/dev/null || "
        f"ip6tables -I FORWARD 1 -i awg0 -p udp --dport 53 -m comment --comment {c} -j REJECT",
        f"ip6tables -C FORWARD -i awg0 -p tcp --dport 53 -m comment --comment {c} -j REJECT 2>/dev/null || "
        f"ip6tables -I FORWARD 1 -i awg0 -p tcp --dport 53 -m comment --comment {c} -j REJECT",
    ]
    ok = True
    for rule in rules:
        if _bash(rule).returncode != 0:
            ok = False
            _err(f"dns rule failed: {rule[:80]}")
    return ok


def dns_rules_remove() -> None:
    c = _RULE_COMMENT
    _bash(
        # DNAT-варианты под любым pub-IP: -S → grep наш коммент → -A мутируем в -D
        f"while iptables -t nat -S PREROUTING 2>/dev/null | grep -F -- '--comment {c}' | grep -F DNAT | head -1 | sed 's/^-A /iptables -t nat -D /' | bash 2>/dev/null; do :; done; "
        f"while iptables -S INPUT 2>/dev/null | grep -F -- '--comment {c}' | head -1 | sed 's/^-A /iptables -D /' | bash 2>/dev/null; do :; done; "
        f"while ip6tables -S FORWARD 2>/dev/null | grep -F -- '--comment {c}' | head -1 | sed 's/^-A /ip6tables -D /' | bash 2>/dev/null; do :; done; "
        f"true")


def dns_rules_present() -> bool:
    r = _run(["bash", "-c",
              f"iptables -t nat -S PREROUTING | grep -q '{_RULE_COMMENT}'"],
             capture=True)
    return r.returncode == 0


# ══════════════════════════════════════════════════════════════════════════════
#  AAAA-ФИЛЬТР (user_rules AGH — yaml-хирургия с бэкапом и верификацией)
# ══════════════════════════════════════════════════════════════════════════════

# Наше AAAA-правило в user_rules — опознаём по шаблону ($dnstype=AAAA
# достаточно специфичен; AGH сам перезаписывает yaml и СРЕЗАЕТ комментарии,
# так что маркеры-блоки не живут — см. кейс 05.10: дубли 174→348).
_AAAA_ITEM_RE = re.compile(
    r"^\s*-\s*['\"]\|\|[^'\"]+\^\$dnstype=AAAA['\"]\s*$")


def _user_rules_section(text: str):
    """Секция user_rules: (indent, start, end_excl, lines, had_inline_empty).

    Учитывает оба_layout'а (топ-уровень и вложенный в filtering:) и стиль
    AGH (элементы на уровне ключа или глубже). None — секции нет."""
    lines = text.splitlines(keepends=True)
    for i, ln in enumerate(lines):
        m = re.match(r"^([ \t]*)user_rules:[ \t]*(\[\])?[ \t]*\r?\n?$", ln)
        if not m:
            continue
        indent = m.group(1)
        j = i + 1
        while j < len(lines):
            l2 = lines[j]
            s2 = l2.strip()
            if not s2 or s2.startswith("#"):
                break                      # пустая/комментарий — конец секции
            cur_ind = len(l2) - len(l2.lstrip())
            if cur_ind > len(indent) or (cur_ind == len(indent)
                                         and s2.startswith("-")):
                j += 1
                continue
            break
        return indent, i, j, lines, bool(m.group(2))
    return None


def aaaa_rules_write(domains: list) -> bool:
    """||domain^$dnstype=AAAA для split-доменов в user_rules AGH.

    Бессмаркерная пересборка секции: строки с $dnstype=AAAA считаем НАШИМИ
    (заменяем целиком), остальные — чужими (сохраняем как есть, они выше —
    приоритетнее, AdGuard оценивает top-down). Идемпотентно: без изменений
    рестарта нет. ⚠ AGH при рестарте сам перезаписывает yaml (срезает
    комментарии и сортирует список) — поэтому НЕ полагаемся на маркеры.
    Бэкап + верификация сервиса + откат при падении (DNS ноды важнее).
    """
    if not _AGH_YAML.exists():
        _warn("aaaa_rules_write: AGH yaml не найден")
        return False
    try:
        text = _AGH_YAML.read_text()
    except Exception as e:
        _warn(f"aaaa_rules_write: {e}")
        return False

    sec = _user_rules_section(text)
    if sec is None:
        _warn("aaaa_rules_write: 'user_rules:' не найден в yaml")
        return False
    indent, i, j, lines, _inline = sec
    item_indent = indent + "  "

    items = [ln.rstrip("\n") for ln in lines[i + 1:j]]
    foreign = [it for it in items if not _AAAA_ITEM_RE.match(it)]
    ours_new = [f"{item_indent}- '||{d}^$dnstype=AAAA'" for d in domains]
    ours_new_dedup = list(dict.fromkeys(ours_new))
    existing_ours = [it for it in items if _AAAA_ITEM_RE.match(it)]

    # без изменений (множество совпадает, чужие на месте) — рестарт не нужен
    if (set(existing_ours) == set(ours_new_dedup)
            and len(existing_ours) == len(ours_new_dedup)
            and [it for it in items if it in foreign] == foreign):
        return True

    try:
        if not _AGH_BACKUP.exists():
            _AGH_BACKUP.write_text(text)
    except Exception:
        pass

    new_section = [f"{indent}user_rules:"] + \
        [it for it in foreign] + ours_new_dedup
    new_lines = lines[:i] + [s + "\n" for s in new_section] + lines[j:]
    new_text = "".join(new_lines)

    try:
        _AGH_YAML.write_text(new_text)
    except Exception as e:
        _warn(f"aaaa_rules_write: write fail {e}")
        return False

    # рестарт + верификация (упал → откат)
    _run(["systemctl", "restart", _AGH_SERVICE], capture=True, timeout=30)
    time.sleep(2)
    r = _run(["systemctl", "is-active", _AGH_SERVICE], capture=True)
    if (r.stdout or "").strip() != "active":
        _err("aaaa_rules_write: AGH не поднялся — ОТКАТ бэкапа")
        try:
            if _AGH_BACKUP.exists():
                _AGH_YAML.write_text(_AGH_BACKUP.read_text())
            _run(["systemctl", "restart", _AGH_SERVICE], capture=True)
        except Exception:
            pass
        return False
    _info(f"AAAA-фильтр: {len(ours_new_dedup)} доменов в user_rules AGH "
          f"(чужих правил сохранено: {len(foreign)})")
    return True


def aaaa_rules_remove() -> None:
    """Убрать ВСЕ наши $dnstype=AAAA-правила (чужие — остаются)."""
    if not _AGH_YAML.exists():
        return
    try:
        text = _AGH_YAML.read_text()
    except Exception:
        return
    sec = _user_rules_section(text)
    if sec is None:
        return
    indent, i, j, lines, _inline = sec
    items = [ln.rstrip("\n") for ln in lines[i + 1:j]]
    foreign = [it for it in items if not _AAAA_ITEM_RE.match(it)]
    if len(foreign) == len(items):
        return                           # наших строк и так нет
    new_section = [f"{indent}user_rules:"] + foreign
    new_text = "".join(lines[:i] + [s + "\n" for s in new_section] + lines[j:])
    try:
        _AGH_YAML.write_text(new_text)
        _run(["systemctl", "restart", _AGH_SERVICE], capture=True)
        time.sleep(2)
        r = _run(["systemctl", "is-active", _AGH_SERVICE], capture=True)
        if (r.stdout or "").strip() != "active" and _AGH_BACKUP.exists():
            _AGH_YAML.write_text(_AGH_BACKUP.read_text())
            _run(["systemctl", "restart", _AGH_SERVICE], capture=True)
    except Exception as e:
        _warn(f"aaaa_rules_remove: {e}")


def aaaa_rules_count() -> int:
    if not _AGH_YAML.exists():
        return -1
    try:
        return len(re.findall(r"\|\|[a-z0-9.\-]+\^\$dnstype=AAAA",
                              _AGH_YAML.read_text()))
    except Exception:
        return -1


# ══════════════════════════════════════════════════════════════════════════════
#  REFRESH TICK (минутный тик таймера: резолв → nft → ipset → self-heal)
# ══════════════════════════════════════════════════════════════════════════════

def refresh_tick(verbose: bool = False) -> dict:
    """Один цикл актуализации сплита. Идемпотентен, self-healing."""
    st = state_load()
    out = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "skipped": None}
    if not st.get("enabled"):
        out["skipped"] = "disabled"
        return out

    # 0. self-heal: nft-сплит-форма (другие пути могут вернуть blanket)
    nft_ok = nft_apply_split()

    # 1. b4 жив? (без b4 direct-плечо беззащитно перед ТСПУ — только warn)
    b4_active = (_run(["systemctl", "is-active", "b4"],
                      capture=True).stdout or "").strip() == "active"
    if not b4_active:
        _warn("refresh: сервис b4 не активен — direct-плечо без DPI-bypass!")

    # 2. DNS self-heal: правила должны соответствовать политике и живости AGH
    if st.get("dns_redirect"):
        pub = _node_public_ip()
        if pub and _agh_dns_alive(pub):
            if not dns_rules_present():
                dns_rules_apply()
        else:
            if dns_rules_present():
                _warn("refresh: AGH не слушает :53 — снимаю DNS-редирект "
                      "(DNS клиентов уйдёт в каскад — деградация, не блэкхол)")
                dns_rules_remove()

    # 3. AAAA-синхронизация при изменении списка доменов (рестарт AGH —
    #    только по факту изменения, не каждый тик; список, не hash() —
    #    питоний hash() нестабилен между процессами)
    domains = collect_domains(st)
    if st.get("aaaa_filter") and domains:
        if st.get("aaaa_domains") != domains:
            if aaaa_rules_write(domains):
                st["aaaa_domains"] = domains

    # 4. домены → IP
    out["domains"] = len(domains)
    if not domains:
        out["skipped"] = "no-domains"
        _warn("refresh: домены не выбраны — ipset не трогаю")
        st["last_stats"] = out
        state_save(st)
        return out
    res = resolve_domains(domains)
    ips, stats = res["ips"], res["stats"]
    out.update(stats)
    if not ips:
        # guard пустого результата: старый набор живее (mieru-паттерн)
        out["skipped"] = "empty-resolve"
        _warn("refresh: резолв дал 0 IP — ipset не трогаю (guard)")
        st["last_stats"] = out
        state_save(st)
        return out

    # 4. nft-сет ПЕРВЫМ (каскад-консистентное окно), затем ipset-swap
    nft_set_ok = nft_set_replace(ips)
    ipset_ok = ipset_apply(ips)
    out["applied"] = int(nft_set_ok and ipset_ok)
    out["nft_ok"] = nft_set_ok
    out["ipset_ok"] = ipset_ok
    out["nft_form_ok"] = nft_ok

    if verbose:
        print(f"  сплит: {len(ips)} IP ← {len(domains)} доменов "
              f"(sys fails {stats['sys_failed']}, qlog +{stats['qlog_ips']})")
    st["last_stats"] = out
    state_save(st)
    _info(f"tick: {len(ips)} IP / {len(domains)} доменов "
          f"(qlog +{stats['qlog_ips']}, applied={out['applied']})")
    return out


def refresh_tick_cli() -> None:
    refresh_tick(verbose=False)


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEMD-TIMER (паттерн awgs_cascade_failover_setup)
# ══════════════════════════════════════════════════════════════════════════════

def timer_install(refresh_sec: int = 60) -> bool:
    if refresh_sec not in _REFRESH_INTERVALS:
        refresh_sec = 60
    try:
        import importlib.util
        spec = importlib.util.find_spec("chimera")
        installer = (str(Path(list(spec.submodule_search_locations)[0]).parent)
                     if spec and spec.submodule_search_locations
                     else "/opt/chimera")
    except Exception:
        installer = "/opt/chimera"

    wrapper = (
        "#!/bin/bash\n"
        "# AWG B4-split refresh — резолв split-доменов → ipset/nft.\n"
        "mkdir -p /root/awg\n"
        f"export PYTHONPATH=\"{installer}:$PYTHONPATH\"\n"
        f"/usr/bin/python3 -c \"\n"
        f"import sys\n"
        f"sys.path.insert(0, '{installer}')\n"
        f"from chimera.modules.awg_b4_split import refresh_tick_cli\n"
        f"refresh_tick_cli()\n"
        f"\" >> /root/awg/awg_b4_split.log 2>&1\n"
    )
    _TIMER_SCRIPT.write_text(wrapper)
    _TIMER_SCRIPT.chmod(0o755)

    Path(_TIMER_SVC).write_text(
        "[Unit]\n"
        "Description=AWG B4-split refresh (resolve split domains)\n"
        "After=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={_TIMER_SCRIPT}\n"
    )
    Path(_TIMER_UNIT).write_text(
        "[Unit]\n"
        "Description=AWG B4-split refresh timer\n"
        "\n"
        "[Timer]\n"
        "OnBootSec=25s\n"
        f"OnUnitActiveSec={refresh_sec}s\n"
        "AccuracySec=5s\n"
        "Persistent=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", "--now", _TIMER_NAME], capture=True)
    r = _run(["systemctl", "is-active", _TIMER_NAME], capture=True)
    return (r.stdout or "").strip() == "active"


def timer_remove() -> None:
    for unit in (_TIMER_NAME, "awg-b4-split-refresh.service"):
        _run(["systemctl", "stop", unit], capture=True)
        _run(["systemctl", "disable", unit], capture=True)
    Path(_TIMER_UNIT).unlink(missing_ok=True)
    Path(_TIMER_SVC).unlink(missing_ok=True)
    _TIMER_SCRIPT.unlink(missing_ok=True)
    _run(["systemctl", "daemon-reload"])


def timer_active() -> bool:
    r = _run(["systemctl", "is-active", _TIMER_NAME], capture=True)
    return (r.stdout or "").strip() == "active"


# ══════════════════════════════════════════════════════════════════════════════
#  APPLY / DEACTIVATE
# ══════════════════════════════════════════════════════════════════════════════

def apply_all(verbose: bool = True) -> bool:
    """Включить сплит целиком (idempotent, self-healing на каждом тике)."""
    st = state_load()
    if not st.get("set_ids") and not st.get("extra_domains"):
        if verbose:
            print("  [!] не выбрано ни одного сета/домена — нечего сплитить")
        return False
    if not ipset_ensure():
        _err("apply: ipset не доступен")
        return False
    ok = True
    if not nft_apply_split():
        ok = False
    ipset_restore_snapshot()
    cascade_mark_sync(excl=True)
    if st.get("dns_redirect"):
        if not dns_rules_apply():
            _warn("apply: DNS-редирект не встал (AGH жив?) — тик донастроит")
    else:
        dns_rules_remove()
    domains = collect_domains(st)
    if st.get("aaaa_filter"):
        if domains and not aaaa_rules_write(domains):
            _warn("apply: AAAA-фильтр не записан")
        if domains:
            st["aaaa_domains"] = domains   # анти-двойная запись в тике
    else:
        aaaa_rules_remove()
    if not timer_install(st.get("refresh_sec", 60)):
        _warn("apply: таймер не поднялся")
    routing_script_regen()
    tick = refresh_tick(verbose=verbose)
    if tick.get("skipped") in ("empty-resolve", "no-domains") and verbose:
        print("  [!] первый тик пуст — таймер догонит (guard активен)")
    if not st.get("installed_at"):
        st["installed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    st["enabled"] = True
    state_save(st)
    _info("apply_all: сплит включён")
    return ok


def deactivate(verbose: bool = True) -> None:
    """Выключить сплит и вернуть каскад в blanket-форму (полный cleanup).

    Порядок важен:
      1. enabled=False ДО регена — иначе routing_script_regen()/генератор
         каскада увидят «включён» и запишут split-форму в boot-скрипт;
      2. mark-правило без исключения ДО ipset_destroy — иначе iptables
         держит reference и сет не сносится.
    """
    timer_remove()
    dns_rules_remove()
    aaaa_rules_remove()
    st = state_load()
    st["enabled"] = False
    st["last_stats"] = {}
    state_save(st)
    nft_apply_blanket()
    cascade_mark_sync(excl=False)
    ipset_destroy()
    _SNAPSHOT.unlink(missing_ok=True)
    routing_script_regen()
    _info("deactivate: сплит выключен, каскад в blanket-форме")
    if verbose:
        print("  [OK] сплит снят: blanket-exempt + mark без исключения")


# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС
# ══════════════════════════════════════════════════════════════════════════════

def status_info() -> dict:
    st = state_load()
    sets = detect_sets()
    sel = {s for s in st.get("set_ids") or []}
    domains = collect_domains(st)
    b4_active = (_run(["systemctl", "is-active", "b4"],
                      capture=True).stdout or "").strip() == "active"
    return {
        "enabled": st.get("enabled", False),
        "sets_total": len(sets),
        "sets_selected": len(sel),
        "sets": [s for s in sets if s["id"] in sel],
        "domains": len(domains),
        "extra_domains": len(st.get("extra_domains") or []),
        "ipset": ipset_size(),
        "nft_set": nft_set_size(),
        "b4_active": b4_active,
        "b4_installed": Path("/usr/local/bin/b4").exists(),
        "dns_redirect": st.get("dns_redirect", True),
        "dns_rules": dns_rules_present(),
        "aaaa_filter": st.get("aaaa_filter", True),
        "aaaa_rules": aaaa_rules_count(),
        "refresh_sec": st.get("refresh_sec", 60),
        "timer": timer_active(),
        "last_stats": st.get("last_stats") or {},
        "mark_excl": bool(mark_rule_exclusion()),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  TUI-МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════

def _core():
    import importlib
    return importlib.import_module("chimera._core")


def do_manage_awg_b4_split() -> None:
    """TUI: B4-сплит для AWG-каскада (Главное меню → 14 → 3 → 6)."""
    core = _core()
    _box_top, _box_row, _box_bottom = core._box_top, core._box_row, core._box_bottom
    _box_item, _box_desc, _box_sep = core._box_item, core._box_desc, core._box_sep
    _box_warn = core._box_warn
    GREEN, RED, YELLOW, CYAN, DIM, NC = (core.GREEN, core.RED, core.YELLOW,
                                         core.CYAN, core.DIM, core.NC)

    while True:
        import os
        os.system("clear")
        print()
        s = status_info()
        _box_top("B4-СPLИТ КАСКАДА: домены напрямую с RU-ноды")
        _box_row()
        en = (f"{GREEN}ВКЛЮЧЁН{NC}" if s["enabled"] else f"{RED}выключен{NC}")
        _box_row(f"  Состояние:    {en}")
        _box_row(f"  Сетов b4:     {s['sets_selected']} выбрано из "
                 f"{s['sets_total']} (доменов: {s['domains']}"
                 + (f" + {s['extra_domains']} ручных" if s["extra_domains"] else "")
                 + ")")
        ip_col = GREEN if s["ipset"] > 0 else (DIM if not s["enabled"] else RED)
        _box_row(f"  ipset/nft:    {ip_col}{s['ipset']}{NC} IP / "
                 f"{ip_col}{s['nft_set']}{NC} в nft-сете")
        b4_col = GREEN if s["b4_active"] else RED
        _box_row(f"  b4:           {b4_col}{'active' if s['b4_active'] else 'не активен'}{NC}"
                 + ("" if s["b4_installed"] else f" {RED}(не установлен!){NC}"))
        dns = f"{GREEN}on{NC}" if s["dns_redirect"] else f"{DIM}off{NC}"
        live = f"{GREEN}✓{NC}" if s["dns_rules"] else f"{RED}✗{NC}"
        _box_row(f"  DNS→AGH:      {dns} (правила: {live})")
        aaaa = f"{GREEN}on{NC}" if s["aaaa_filter"] else f"{DIM}off{NC}"
        _box_row(f"  AAAA-фильтр:  {aaaa} ({s['aaaa_rules']} правил в AGH)")
        tmr = f"{GREEN}active{NC}" if s["timer"] else f"{RED}off{NC}"
        _box_row(f"  Таймер:       {tmr} (каждые {s['refresh_sec']}с)")
        if s["last_stats"]:
            _box_row(f"  Последний тик: {DIM}{s['last_stats'].get('ts', '?')}"
                     f" — {s['last_stats'].get('ips', '?')} IP"
                     f"{', skip: ' + str(s['last_stats'].get('skipped')) if s['last_stats'].get('skipped') else ''}{NC}")
        if not s["b4_installed"]:
            _box_row()
            _box_warn("b4 не установлен! Сплит без b4 = домены напрямую без "
                      "DPI-bypass (ТСПУ). Установите: Главное меню → 3 → Y → B")
        if s["enabled"] and s["ipset"] == 0:
            _box_row()
            _box_warn("ipset пуст! (первый тик? резолв лёг?) — все домены "
                      "идут каскадом, ждите тика или [8]")
        _box_row()
        _box_row(f"  {DIM}Схема: домены сетов → b4 напрямую (RU-IP), "
                 f"остальное → каскад на exit{NC}")
        _box_row(f"  {DIM}Цель: YouTube и др. с RU-IP (без рекламы){NC}")
        _box_row()
        _box_item("1", "Включить/выключить сплит")
        _box_item("2", "Выбрать сеты b4")
        _box_desc("Какие сеты идут напрямую (домены сетов → ipset).")
        _box_item("3", "Дополнительные домены (поверх сетов)")
        _box_item("4", "DNS→AGH: редирект DNS клиентов на AGH ноды")
        _box_desc("DNAT udp/tcp 53 из awg0 на AGH (dnscrypt DoH) — резолв "
                  "«глазами RU-ноды», анти-DNS-leak.")
        _box_item("5", "AAAA-фильтр: ||domain^$dnstype=AAAA в AGH")
        _box_desc("Без него браузер уйдёт по v6 → каскад → реклама вернётся.")
        _box_item("6", "Интервал рефреша (30/60/300/900/3600 сек)")
        _box_item("7", "Полный статус (живые правила/сет/сет-лист)")
        _box_item("8", "Рефреш сейчас (ручной тик)")
        _box_item("9", f"{RED}Снять всё и выключить{NC}")
        _box_row()
        _box_item("0", "Назад")
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return
        if ch in ("q", "0", ""):
            return

        elif ch == "1":
            st = state_load()
            if st.get("enabled"):
                print("\n  Выключаю сплит (возврат к blanket-форме)...")
                deactivate()
            else:
                # валидация контекста
                try:
                    from .awg_state import awgs_state_load
                    role = awgs_state_load().get("cascade_role", "")
                except Exception:
                    role = ""
                if role != "entry":
                    print(f"\n  {RED}[!]{NC} Каскад не настроен как entry "
                          f"(role='{role or '—'}'). Сплит имеет смысл только "
                          f"на RU-entry с каскадом.")
                    input(f"\n{core.BLUE}Enter…{NC}")
                    continue
                if not st.get("set_ids") and not st.get("extra_domains"):
                    sets = detect_sets()
                    preselect = [s["id"] for s in sets
                                 if s["enabled"] and s["domain_count"] > 0
                                 and not s["name"].startswith("watchdog")]
                    if preselect:
                        print(f"\n  Сеты не выбраны — предвыбираю "
                              f"{len(preselect)} шт. с доменами "
                              f"(без watchdog-*).")
                        try:
                            ok = input("  Согласны? [Y/n]: ").strip().lower()
                        except EOFError:
                            ok = "y"
                        if ok in ("", "y", "yes", "д", "да"):
                            st["set_ids"] = preselect
                            state_save(st)
                print("\n  Включаю сплит...")
                apply_all()
            input(f"\n{core.BLUE}Enter…{NC}")

        elif ch == "2":
            _menu_sets()
            input(f"\n{core.BLUE}Enter…{NC}")

        elif ch == "3":
            _menu_extra_domains()
            input(f"\n{core.BLUE}Enter…{NC}")

        elif ch == "4":
            st = state_load()
            st["dns_redirect"] = not st.get("dns_redirect", True)
            state_save(st)
            if st.get("enabled"):
                if st["dns_redirect"]:
                    dns_rules_apply()
                else:
                    dns_rules_remove()
            print(f"  DNS→AGH: {'включён' if st['dns_redirect'] else 'выключен'}")

        elif ch == "5":
            st = state_load()
            st["aaaa_filter"] = not st.get("aaaa_filter", True)
            state_save(st)
            if st.get("enabled"):
                if st["aaaa_filter"]:
                    domains = collect_domains(st)
                    if domains:
                        aaaa_rules_write(domains)
                else:
                    aaaa_rules_remove()
            print(f"  AAAA-фильтр: {'включён' if st['aaaa_filter'] else 'выключен'}")

        elif ch == "6":
            st = state_load()
            print()
            for i, sec in enumerate(_REFRESH_INTERVALS, 1):
                mark = " ←" if sec == st.get("refresh_sec") else ""
                print(f"  {i}. {sec}с{mark}")
            try:
                v = input(f"\n{CYAN}Выбор:{NC} ").strip()
                idx = int(v) - 1
                if 0 <= idx < len(_REFRESH_INTERVALS):
                    st["refresh_sec"] = _REFRESH_INTERVALS[idx]
                    state_save(st)
                    if st.get("enabled"):
                        timer_install(st["refresh_sec"])
            except (ValueError, KeyboardInterrupt):
                pass

        elif ch == "7":
            _menu_full_status()
            input(f"\n{core.BLUE}Enter…{NC}")

        elif ch == "8":
            print("\n  Рефреш...")
            r = refresh_tick(verbose=True)
            if r.get("skipped"):
                print(f"  [!] пропуск: {r['skipped']}")
            input(f"\n{core.BLUE}Enter…{NC}")

        elif ch == "9":
            try:
                ok = input("\n  Точно снять всё? [y/N]: ").strip().lower()
            except EOFError:
                ok = ""
            if ok in ("y", "yes", "д", "да"):
                deactivate()
                input(f"\n{core.BLUE}Enter…{NC}")


def _menu_sets() -> None:
    """Чекбоксы сетов b4 (выбранные И enabled в b4 участвуют)."""
    core = _core()
    CYAN, GREEN, DIM, NC, YELLOW = core.CYAN, core.GREEN, core.DIM, core.NC, core.YELLOW
    while True:
        import os
        os.system("clear")
        print()
        sets = detect_sets()
        st = state_load()
        sel = set(st.get("set_ids") or [])
        print(f"  {YELLOW}СЕТЫ B4 (выбор для сплита){NC}")
        print(f"  {DIM}Участвуют: выбранные здесь И включённые в b4. "
              f"«0 доменов» — стратегия без своего списка (для сплита бесполезна).{NC}\n")
        for i, s in enumerate(sets, 1):
            mark = f"{GREEN}[x]{NC}" if s["id"] in sel else "[ ]"
            en = f"{GREEN}●{NC}" if s["enabled"] else f"{RED}○{NC}"
            dc = s["domain_count"]
            dc_s = (f"{GREEN}{dc}{NC} дом." if dc else f"{DIM}0 дом.{NC}")
            print(f"  {i:>2}. {mark} {en} {s['name']:<28} {dc_s}")
        print(f"\n  {DIM}номер/диапазон (1,3-5) = toggle, a = все, n = ничего, "
              f"s = сохранить, q = выход{NC}")
        try:
            v = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return
        if v in ("q", ""):
            return
        if v == "s":
            state_save(st)
            # сразу пересинхронизировать, если включён
            if st.get("enabled"):
                domains = collect_domains(st)
                if st.get("aaaa_filter") and domains:
                    aaaa_rules_write(domains)
                    st["aaaa_domains"] = domains
                    state_save(st)
                refresh_tick()
            return
        if v == "a":
            st["set_ids"] = [s["id"] for s in sets if s["enabled"]]
            continue
        if v == "n":
            st["set_ids"] = []
            continue
        # парс "1,3-5"
        idxs = set()
        try:
            for part in v.split(","):
                part = part.strip()
                if "-" in part:
                    a, b = part.split("-")
                    idxs.update(range(int(a), int(b) + 1))
                else:
                    idxs.add(int(part))
        except ValueError:
            continue
        cur = set(st.get("set_ids") or [])
        for i in idxs:
            if 1 <= i <= len(sets):
                sid = sets[i - 1]["id"]
                if sid in cur:
                    cur.discard(sid)
                else:
                    cur.add(sid)
        st["set_ids"] = sorted(cur)


def _menu_extra_domains() -> None:
    core = _core()
    CYAN, DIM, NC = core.CYAN, core.DIM, core.NC
    while True:
        import os
        os.system("clear")
        print()
        st = state_load()
        print(f"  ДОПОЛНИТЕЛЬНЫЕ ДОМЕНА (поверх сетов b4)\n")
        doms = st.get("extra_domains") or []
        if doms:
            for d in doms:
                print(f"    - {d}")
        else:
            print(f"  {DIM}(пусто){NC}")
        print(f"\n  {DIM}домен = добавить, 'del <домен>' = убрать, q = выход{NC}")
        try:
            v = input(f"{CYAN}Ввод:{NC} ").strip()
        except (KeyboardInterrupt, EOFError):
            return
        if v in ("q", ""):
            return
        if v.lower().startswith("del "):
            tgt = v[4:].strip().lower()
            st["extra_domains"] = [d for d in doms
                                   if d.strip().lower() != tgt]
        else:
            d = _normalize_domain(v)
            if not d:
                print("  [!] не похоже на домен")
                continue
            if d not in doms:
                doms.append(d)
                st["extra_domains"] = sorted(set(doms))
        state_save(st)


def _menu_full_status() -> None:
    core = _core()
    DIM, NC = core.DIM, core.NC
    s = status_info()
    print()
    print(f"  {DIM}── живые правила ──{NC}")
    r = _bash("iptables -t mangle -S PREROUTING | grep -E 'awg0' | head -5")
    for line in (r.stdout or "").strip().splitlines():
        print(f"    {line}")
    r = _bash(f"iptables -t nat -S PREROUTING | grep '{_RULE_COMMENT}'")
    print(f"\n  {DIM}── DNS-редирект ──{NC}")
    for line in (r.stdout or "").strip().splitlines() or ["    (нет)"]:
        print(f"    {line}")
    r = _run(["nft", "list", "table", "inet", _NFT_TABLE], capture=True)
    print(f"\n  {DIM}── nft {(_NFT_TABLE)} ──{NC}")
    for line in (r.stdout or "").strip().splitlines():
        print(f"    {line}")
    print(f"\n  {DIM}── выбранные сеты ──{NC}")
    for x in s["sets"]:
        print(f"    {x['name']} ({x['domain_count']} дом., "
              f"{'on' if x['enabled'] else 'OFF'})")
    ls = s["last_stats"]
    if ls:
        print(f"\n  {DIM}── последний тик ──{NC}")
        for k in ("ts", "domains", "ips", "sys_failed", "qlog_ips",
                  "applied", "skipped"):
            if k in ls:
                print(f"    {k}: {ls[k]}")

