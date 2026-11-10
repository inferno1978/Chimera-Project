"""
node_identity.py — единая точка человекочитаемых имён нод в уведомлениях.

Контекст (запрос владельца 10.11.2026): «все сообщения должны быть
человекочитаемыми, должен быть виден состав каскадов — IP, названия
нод по доменам, IP-адреса» — во всех режимах и во всех каскадах
(VLESS / AWG 2.0 / AWG 3.1 / Mieru / Naive). До этого каждый модуль
рендерил ноды по-своему: голый alias («NL»), голый host:port
(«node-nl.example.com:443»), код exit'а без адреса («de») — состав
каскада и адреса из уведы было не прочитать.

Единый формат метки ноды (node_label):
    «alias · домен [IP]»        — домен + резолв (VLESS-ноды)
    «alias · IP:порт»           — IP-хост с нестандартным портом
    «alias · IP»                — IP-хост, порт 443
    «домен [IP]» / «IP:порт»   — без алиаса
    «alias · домен [IP]:порт»   — домен + нестандартный порт

Источники данных:
  • алиасы — exit_traffic_watcher.json → "aliases" (host:port → имя;
    единый источник, настраивается в меню наблюдателя трафика [7]);
  • IP домена — DNS-резолв (getent ahostsv4, таймаут 3 c) с файловым
    кэшем /var/lib/xray-installer/node_dns_cache.json (TTL 6 ч,
    негативный — 30 мин) + in-memory кэш на процесс;
  • заголовок сервера (server_header) — telegram.json → server_name
    (ручное имя, напр. «RU1») + state.json → domain + telegram.json →
    server_ip: «RU1 · node-ru1.example.com · 203.0.113.10».

Точки применения (все TG-пути, все каскады; продолжение cc00f25):
  • tg_bot — заголовок всех событий + меню [8];
  • exit_traffic_watcher — все уведы, дайджест секциями с составом,
    метки источников VLESS/AWG/Mieru/Naive (в т.ч. naive_upstream_*);
  • exit_switch_watcher — set-change/switch/ip-change/снапшот;
  • smart_balancer — карантин/relay_failover/node_connect + метки
    релей-хопов (_sb_hop_label: «тег · домен [IP]»);
  • node_health_monitor — down/up/degraded + заголовок сервера;
  • chain_nodes — cascade_lb_change («все (N): метка, метка»);
  • awg_cascade — авто-failover «from → to» + all-dead составом;
  • awg_cascade_lb — _exit_label: здоровье/activate/set_exits/
    deactivate («de · домен [IP]» / «de · IP:порт»);
  • mieru_cascade_monitor — exit down/up, no_exits составом;
  • mieru_cascade — set_lb_exits: состав балансировки Exit-ов с
    метками + счётчик exits_word + {H}-заголовок;
  • dpi_detector — pinned-fallback/restore (key_label chain-ноды).

Модуль — лист дерева импортов (никаких chimera-импортов), безопасен
для вызова из cron-скриптов и TUI. Все функции не бросают исключений
и быстро деградируют (нет кэша/нет DNS → метка без IP).

Публичное API:
    is_ip_literal(host)            → bool
    resolve_host(host)             → str   (IP или "")
    aliases()                      → dict  (host:port → имя)
    alias_for(host, port)          → str
    node_label(alias, host, port)  → str   («alias · домен [IP]»)
    key_label(key)                 → str   (метка по «host:port»)
    server_header(tg_cfg=None)     → str   («RU1 · домен · IP»)
    ru_plural(n, one, few, many)   → str   (рус. множественное число)
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path

# ── Константы (прод-пути; в тестах изолируются через _env_isolation) ─────────
DNS_CACHE_FILE = Path("/var/lib/xray-installer/node_dns_cache.json")
ALIASES_FILE   = Path("/var/lib/xray-installer/exit_traffic_watcher.json")
STATE_FILE     = Path("/var/lib/xray-installer/state.json")
TG_FILE        = Path("/var/lib/xray-installer/telegram.json")

DNS_TTL_SEC        = 6 * 3600     # позитивный кэш резолва
DNS_TTL_NEG_SEC    = 30 * 60      # негативный (не мучаем резолвер)
DNS_TIMEOUT_SEC    = 3            # таймаут getent

# ── In-memory кэш на процесс ──────────────────────────────────────────────────
_MEM: dict = {"dns": None, "dns_ts": 0.0, "aliases": None, "aliases_ts": 0.0}

_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def is_ip_literal(host: str) -> bool:
    """True, если host — IP-литерал (IPv4 или IPv6). Чистая функция."""
    h = str(host or "").strip()
    if not h or "/" in h or h.count(".") > 3:
        return False
    if _IPV4_RE.match(h):
        return True
    # IPv6: содержит ':' и только hex-цифры/двоеточия/точки (v4-mapped)
    if ":" in h:
        return all(c in "0123456789abcdefABCDEF:.%" for c in h)
    return False


# ── DNS-резолв с файловым кэшем ───────────────────────────────────────────────


def _dns_read_cache() -> dict:
    """Чтение файлового кэша ({} при отсутствии/битом файле)."""
    if _MEM.get("dns") is not None and time.time() - _MEM.get("dns_ts", 0) < 30:
        return _MEM["dns"]
    data: dict = {}
    try:
        if DNS_CACHE_FILE.exists():
            parsed = json.loads(DNS_CACHE_FILE.read_text(encoding="utf-8"))
            if isinstance(parsed, dict):
                data = parsed
    except Exception:
        data = {}
    _MEM["dns"] = data
    _MEM["dns_ts"] = time.time()
    return data


def _dns_write_cache(cache: dict) -> None:
    """Атомарная запись кэша (tmp + replace; провал молчит)."""
    try:
        DNS_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = DNS_CACHE_FILE.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(cache, indent=1, ensure_ascii=False), encoding="utf-8")
        tmp.replace(DNS_CACHE_FILE)
        _MEM["dns"] = cache
        _MEM["dns_ts"] = time.time()
    except Exception:
        pass


def _getent_ipv4(host: str) -> str:
    """getent ahostsv4 → первый IPv4 (или ''; таймаут DNS_TIMEOUT_SEC)."""
    try:
        r = subprocess.run(
            ["getent", "ahostsv4", host],
            capture_output=True, text=True, timeout=DNS_TIMEOUT_SEC)
        if r.returncode == 0:
            for line in (r.stdout or "").splitlines():
                ip = line.split()[0].strip() if line.split() else ""
                if ip:
                    return ip
    except Exception:
        pass
    return ""


def resolve_host(host: str) -> str:
    """IPv4-адрес домена (кэш DNS_TTL_SEC; негатив — DNS_TTL_NEG_SEC).
    IP-литерал возвращается как есть. Неизвестно → ''. Не бросает."""
    h = str(host or "").strip()
    if not h:
        return ""
    if is_ip_literal(h):
        return h
    cache = _dns_read_cache()
    ent = cache.get(h)
    now = time.time()
    if isinstance(ent, dict):
        ip = str(ent.get("ip") or "")
        ts = float(ent.get("ts") or 0)
        ttl = DNS_TTL_SEC if ip else DNS_TTL_NEG_SEC
        if now - ts < ttl:
            return ip
    ip = _getent_ipv4(h)
    if h in cache or ip:
        cache[h] = {"ip": ip, "ts": now}
        _dns_write_cache(cache)
    return ip


# ── Алиасы (единый источник — конфиг наблюдателя трафика) ────────────────────


def aliases() -> dict:
    """Карта алиасов {host:port → имя} (пустая при отсутствии). Не бросает."""
    if _MEM.get("aliases") is not None \
            and time.time() - _MEM.get("aliases_ts", 0) < 30:
        return _MEM["aliases"]
    out: dict = {}
    try:
        if ALIASES_FILE.exists():
            parsed = json.loads(ALIASES_FILE.read_text(encoding="utf-8"))
            if isinstance(parsed, dict):
                out = parsed.get("aliases") or {}
    except Exception:
        out = {}
    _MEM["aliases"] = out
    _MEM["aliases_ts"] = time.time()
    return out


def alias_for(host: str, port=0) -> str:
    """Алиас для host[:port] (без алиаса — ''). Чистая по данным функцию."""
    h = str(host or "").strip()
    if not h:
        return ""
    al = aliases()
    if port:
        v = al.get(f"{h}:{int(port)}")
        if v:
            return str(v)
    return str(al.get(h) or "")


# ── Метки нод ─────────────────────────────────────────────────────────────────


def _host_part(host: str, port=0, resolve: bool = True) -> str:
    """Хост-часть метки: «домен [IP]» / «IP» (+ «:порт» если != 443)."""
    h = str(host or "").strip()
    if not h:
        return ""
    try:
        p = int(port or 0)
    except (TypeError, ValueError):
        p = 0
    base = h
    if not is_ip_literal(h) and resolve:
        ip = resolve_host(h)
        if ip:
            base = f"{h} [{ip}]"
    if p and p != 443:
        base = f"{base}:{p}"
    return base


def node_label(alias: str, host: str, port=0, resolve: bool = True) -> str:
    """Человекочитаемая метка ноды: «alias · домен [IP](:порт)».
    Алиас совпадает с хостом (или пуст) → только хост-часть.
    Не бросает; DNS-резолв только при resolve=True (кэш за ним)."""
    al = str(alias or "").strip()
    host = str(host or "").strip()
    hp = _host_part(host, port, resolve)
    if not al:
        return hp
    if not hp:
        return al
    if al.lower() == host.lower():
        # алиас и есть хост (напр. exit, названный по IP) — без дубля
        return hp
    return f"{al} · {hp}"


def _split_key(key: str) -> tuple:
    """'host:port' → (host, port); IPv6 в скобках понимает."""
    k = str(key or "").strip()
    if not k:
        return "", 0
    if k.startswith("["):                       # [v6]:port
        end = k.find("]")
        if end > 0:
            host = k[1:end]
            rest = k[end + 1:]
            port = int(rest[1:]) if rest.startswith(":") else 0
            return host, port
    if k.count(":") == 1:                        # host:port (v4/домен)
        host, _, ps = k.rpartition(":")
        try:
            return host, int(ps)
        except ValueError:
            return k, 0
    return k, 0                                  # голый host / v6 без порта


def key_label(key: str, resolve: bool = True) -> str:
    """Метка по ключу «host:port»: алиас подхватывается автоматически.
    («node-nl.example.com:443» → «NL · node-nl.example.com [203.0.113.40]»)."""
    host, port = _split_key(key)
    if not host:
        return str(key or "")
    return node_label(alias_for(host, port), host, port, resolve)


# ── Заголовок сервера (уведы «от кого») ───────────────────────────────────────


def _hostname() -> str:
    try:
        r = subprocess.run(["hostname", "-s"], capture_output=True,
                           text=True, timeout=5)
        return (r.stdout or "").strip() or "server"
    except Exception:
        return "server"


def server_header(tg_cfg: dict | None = None,
                  hostname: str | None = None) -> str:
    """Заголовок сервера для увед: «server_name · домен · IP»
    (каждая часть опциональна; фолбэк — hostname). Читает telegram.json
    и state.json, не бросает. hostname — внешняя подстановка (паттерн
    патчимых _hostname() в модулях-мониторах; None — свой hostname -s)."""
    cfg = tg_cfg
    if cfg is None:
        try:
            if TG_FILE.exists():
                cfg = json.loads(TG_FILE.read_text(encoding="utf-8"))
        except Exception:
            cfg = {}
    if not isinstance(cfg, dict):
        cfg = {}
    name = str(cfg.get("server_name") or "").strip() \
        or str(hostname or "").strip() or _hostname()
    parts = [name]
    domain = ""
    try:
        if STATE_FILE.exists():
            st = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            domain = str((st or {}).get("domain") or "").strip()
    except Exception:
        domain = ""
    if domain and domain.lower() not in (name.lower(),):
        parts.append(domain)
    ip = str(cfg.get("server_ip") or "").strip()
    if ip:
        parts.append(ip)
    return " · ".join(p for p in parts if p)


# ── Русское множественное число (для «N нод/ноды/нода») ──────────────────────


def ru_plural(n: int, one: str, few: str, many: str) -> str:
    """Форма русского множественного числа: ru_plural(2,'нода','ноды','нод')."""
    try:
        n = abs(int(n))
    except (TypeError, ValueError):
        n = 0
    if n % 10 == 1 and n % 100 != 11:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many


def nodes_word(n: int) -> str:
    """«нода»/«ноды»/«нод» для счётчика состава."""
    return ru_plural(n, "нода", "ноды", "нод")


def exits_word(n: int) -> str:
    """«exit»/«exit-ноды»/«exit-нод» для счётчика состава AWG/Mieru."""
    return ru_plural(n, "exit", "exit-ноды", "exit-нод")
