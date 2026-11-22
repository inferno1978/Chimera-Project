#!/usr/bin/env python3
"""
chimera/modules/wpp_user_geo.py
──────────────────────────────────────────────────────────────────────────────
Chimera-твик вкладки «Пользователи»: IP, страна, город и флаг клиента.

Источники «откуда клиент» (объединяются, побеждает самый свежий):
  1. GET /wpp-sub/<token> — каждое обновление подписки клиентским приложением
     (v2rayNG, Hiddify, Streisand…, интервал 6 ч из profile-update-interval,
     плюс ручные «обновить подписку»). Хук в wpp_panel_web.serve_subscription →
     record_subscription_seen(): {ip, ts, ua} по подписке (sub:<token>) и по
     устройству (dev:<token>:<hwid-hash>, X-HWID). Браузерный дашборд подписки
     идёт той же функцией — тоже учитывается.
  2. /var/log/xray/access.log (+ access.log.1) — РЕАЛЬНЫЕ подключения VLESS:
     строка «2026/10/27 03:53:45 from 192.0.2.20:52359 accepted tcp:…
     email: user@d» даёт (email → ip, ts). Парсинг — хвост TAIL_LINES строк,
     in-memory кэш SCAN_TTL (рендер не перечитывает лог на каждый опрос).

Гео по IP: ip-api.com (lang=ru, 2.5 с) → ipinfo.io (3 с) — те же функции и
таймауты, что у wpp_cascade_bridge (инцидент 22.11: синхронный резолв в
ренере вкладки «Ноды» висел 21.7 с). Кэш в wpp_user_geo.json: успешный резолв
— 7 дней, неудачный — 1 ч (негативный TTL). Рендер вкладки НИКОГДА не ходит в
сеть: stale-while-revalidate — refresh_geo_async() в daemon-потоке, дебаунс
GEO_REFRESH_MIN_INTERVAL против потока на каждый опрос.

Файлы (root-only 0600, атомарная замена через os.replace):
  /var/lib/xray-installer/wpp_user_seen.json  — {ключ: {ip, ts, ua}}
  /var/lib/xray-installer/wpp_user_geo.json   — {ip: {cc, country, city, ts, neg}}
Приватность: хранится только последний визит (без истории); файлы 0600.

Выживание обновлений: модуль и точки вызова — chimera-твики в форке
(inferno1978/Chimera-Project). Фронт-обновления WPP (wpp_panel_www из
апстрим-тарллов) их не затрагивают, синк порта с апстримом сохраняет твик
(паттерн HWID-подписок v2.9.1, commit 78b250c).
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ─── Пути (модуль-level константы — патчатся в тестах, паттерн
# connection_audit._ACCESS_LOG) ───────────────────────────────────────────────
SEEN_FILE = Path("/var/lib/xray-installer/wpp_user_seen.json")
GEO_FILE = Path("/var/lib/xray-installer/wpp_user_geo.json")
ACCESS_LOG = Path("/var/log/xray/access.log")
ACCESS_LOG_1 = Path("/var/log/xray/access.log.1")

# ─── TTL / лимиты ────────────────────────────────────────────────────────────
GEO_TTL = 7 * 86400            # успешный гео-резолв: IP не меняются часто
GEO_NEG_TTL = 3600             # неудачный: ретрай не чаще раза в час
SEEN_TTL = 30 * 86400          # «последний визит» старше 30 дней — забываем
SEEN_MAX_ENTRIES = 1000        # bounded-рост seen-файла (prune по ts)
SCAN_TTL = 30.0                # кэш парсинга access.log в памяти
TAIL_LINES = 20000             # хвост строк лога на один скан (текущий + .1)
GEO_BATCH_LIMIT = 30          # IP за один фоновый цикл (ip-api: 45 req/min)
GEO_REFRESH_MIN_INTERVAL = 60.0   # дебаунс фоновой гео-обновки (как ноды)

# ─── Парсинг access.log — проверенные правила из connection_audit.py ────────
# (копия, без импорта chimera._core: модуль живёт в процессе wpp-web,
#  тяжёлый CLI-корень туда тянуть нельзя)
_SKIP_LINE_MARKERS = ("observatory", "outbound")   # не клиентские соединения
_ACCESS_LINE_HEAD = re.compile(
    r'^(?P<date>\d{4}/\d{2}/\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+'
    r'(?:from\s+(?P<from_tok>\S+)\s+)?'
    r'(?P<action>\w+)'
)
_FROM_ADDR = re.compile(
    r'^(?:\[(?P<v6>[0-9a-fA-F:.]+)\]|(?P<v4>\d{1,3}(?:\.\d{1,3}){3})):(?P<port>\d+)$'
)
_EMAIL_FIELD = re.compile(r'email:\s*(\S+)')

_SEEN_LOCK = threading.Lock()
_SCAN_LOCK = threading.Lock()
_SCAN_CACHE = {"ts": 0.0, "by_email": {}}

_GEO_REFRESH_LOCK = threading.Lock()
_GEO_REFRESH_LAST = 0.0


# ─── JSON IO (atomic, 0600 — как wpp_panel_web.save) ─────────────────────────
def _load_json(path: Path, default):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, type(default)) else default
    except Exception:
        return default


def _write_json_atomic(path: Path, data) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = str(path) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, str(path))
        return True
    except Exception as exc:
        print(f"[WPP-USER-GEO] write {path} failed: {type(exc).__name__}: {exc}",
              file=sys.stderr, flush=True)
        return False


def _valid_ip(value) -> str:
    """Нормализованный IP ('' для мусора/None/'unknown'). IPv4-mapped → IPv4."""
    import ipaddress
    try:
        ip = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return ""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)
    return str(ip)


def _hwid_key(hwid: str) -> str:
    """Компактный стабильный ключ устройства из X-HWID (произвольная строка)."""
    import hashlib
    raw = str(hwid or "").strip()
    if not raw:
        return ""
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ─── 1. Seen: обновления подписок ────────────────────────────────────────────
def record_subscription_seen(token: str, ip: str, user_agent: str = "", hwid: str = "") -> bool:
    """Запомнить «подписку/устройство видели с этого IP в это время».

    Вызывается из serve_subscription ПОСЛЕ того, как токен признан валидным
    (до генерации ответа). Тихо глотает ошибки IO: выдача подписки важнее
    гео-твика.
    """
    ip = _valid_ip(ip)
    if not ip or not token:
        return False
    now = int(time.time())
    entry = {"ip": ip, "ts": now, "ua": str(user_agent or "")[:200]}
    try:
        with _SEEN_LOCK:
            seen = _load_json(SEEN_FILE, {})
            if not isinstance(seen, dict):
                seen = {}
            seen["sub:" + str(token)] = dict(entry)
            dev = _hwid_key(hwid)
            if dev:
                seen["dev:%s:%s" % (str(token), dev)] = dict(entry)
            # Prune: забываем визиты старше SEEN_TTL; при превышении лимита
            # записей выбрасываем самые старые (bounded file).
            if len(seen) > SEEN_MAX_ENTRIES:
                items = sorted(
                    ((k, int(v.get("ts", 0) or 0)) for k, v in seen.items() if isinstance(v, dict)),
                    key=lambda kv: kv[1],
                )
                for k, _ in items[:len(seen) - SEEN_MAX_ENTRIES]:
                    seen.pop(k, None)
            cutoff = now - SEEN_TTL
            stale = [k for k, v in seen.items()
                     if isinstance(v, dict) and int(v.get("ts", 0) or 0) < cutoff]
            for k in stale:
                seen.pop(k, None)
            return _write_json_atomic(SEEN_FILE, seen)
    except Exception as exc:
        print(f"[WPP-USER-GEO] record_seen failed: {type(exc).__name__}: {exc}",
              file=sys.stderr, flush=True)
        return False


# ─── 2. Access.log: реальные подключения VLESS ────────────────────────────────
def _client_ip_from_token(tok: str) -> str:
    """IP клиента из from-токена ('192.0.2.20:52359' | '[2001:db8::]:63698')."""
    m = _FROM_ADDR.match(tok)
    if not m:
        return ""
    ip = m.group("v6") or m.group("v4") or ""
    if ip.lower().startswith("::ffff:") and "." in ip:
        ip = ip[7:]
    return _valid_ip(ip)


def _parse_tail(lines) -> dict:
    """Хвост строк лога → {email: {"ip","ts"}}; позже — свежее (перетирает)."""
    out = {}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        low = line.lower()
        if any(marker in low for marker in _SKIP_LINE_MARKERS):
            continue
        m = _ACCESS_LINE_HEAD.match(line)
        if not m:
            continue
        from_tok = m.group("from_tok")
        if from_tok is None:
            continue  # легаси-формат без from: IP клиента неизвестен
        ip = _client_ip_from_token(from_tok)
        if not ip:
            continue  # «from DNS …» и пр. внутренние события
        em = _EMAIL_FIELD.search(line)
        if not em:
            continue
        email = em.group(1)
        try:
            dt = datetime.strptime(f"{m.group('date')} {m.group('time')}", "%Y/%m/%d %H:%M:%S")
            ts = int(dt.timestamp())
        except Exception:
            ts = 0
        prev = out.get(email)
        if prev is None or ts >= int(prev.get("ts", 0) or 0):
            out[email] = {"ip": ip, "ts": ts}
    return out


def _read_tail(path: Path, limit: int) -> list:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            if path.stat().st_size > limit * 512:
                f.seek(path.stat().st_size - limit * 512)
                f.readline()  # добить оборванную строку от seek
            return f.readlines()[-limit:]
    except Exception:
        return []


def _scan_access_log(force: bool = False) -> dict:
    """{email: {"ip","ts"}} по хвосту access.log (+.1), кэш SCAN_TTL."""
    now = time.time()
    with _SCAN_LOCK:
        if not force and now - _SCAN_CACHE.get("ts", 0.0) < SCAN_TTL:
            return _SCAN_CACHE["by_email"]
        by_email = {}
        for path in (ACCESS_LOG_1, ACCESS_LOG):   # старее → свежее
            if path.exists():
                by_email.update(_parse_tail(_read_tail(path, TAIL_LINES)))
        _SCAN_CACHE["ts"] = now
        _SCAN_CACHE["by_email"] = by_email
        return by_email


# ─── 3. Гео-кэш по IP ────────────────────────────────────────────────────────
def _geo_lookup(ip: str) -> dict:
    """ip-api.com (lang=ru) → ipinfo.io. Те же функции/таймауты, что у нод."""
    from chimera.modules import wpp_cascade_bridge as bridge
    geo = bridge._geolocate_ip(ip)          # ip-api.com, GEO_PRIMARY_TIMEOUT=2.5
    if bridge._is_empty_city(geo.get("city", "")):
        geo2 = bridge._geolocate_ipinfo(ip)  # ipinfo.io, timeout=3
        if not bridge._is_empty_city(geo2.get("city", "")):
            geo["city"] = geo2["city"]
            if geo.get("country_code") == "UN" and geo2.get("country_code"):
                geo["country_code"] = geo2["country_code"]
                geo["country_name"] = geo2.get("country_name", "Не указано")
    return geo


def _geo_entry_live(entry: dict, now: float) -> bool:
    """Кэш-запись не протухла (positive/negative TTL)."""
    age = now - int(entry.get("ts", 0) or 0)
    if age < 0:
        return False  # часы убежали вперёд — безопасный ретрай
    return age < (GEO_NEG_TTL if entry.get("neg") else GEO_TTL)


def _refresh_geo_worker(ips: list) -> None:
    """Фоновый резолв пачки IP (не больше GEO_BATCH_LIMIT за цикл)."""
    cache = _load_json(GEO_FILE, {})
    if not isinstance(cache, dict):
        cache = {}
    now = int(time.time())
    todo = []
    for ip in ips[:GEO_BATCH_LIMIT]:
        entry = cache.get(ip)
        if isinstance(entry, dict) and _geo_entry_live(entry, now):
            continue
        todo.append(ip)
    if not todo:
        return
    changed = False
    for ip in todo:
        try:
            geo = _geo_lookup(ip)
        except Exception as exc:
            print(f"[WPP-USER-GEO] lookup {ip} failed: {type(exc).__name__}: {exc}",
                  file=sys.stderr, flush=True)
            continue
        cc = str(geo.get("country_code", "UN") or "UN")
        neg = cc == "UN" or not str(geo.get("city", "") or "").strip()
        cache[ip] = {
            "cc": cc,
            "country": str(geo.get("country_name", "") or ""),
            "city": str(geo.get("city", "") or ""),
            "ts": int(time.time()),
            "neg": bool(neg),
        }
        changed = True
    if changed:
        _write_json_atomic(GEO_FILE, cache)


def refresh_geo_async(ips) -> bool:
    """Планирует фоновый гео-резолв. Неблокирующий, дебаунс 60 с.

    Возвращает True, если цикл реально запланирован (как
    wpp_panel_web._refresh_nodes_async после инцидента 22.11).
    """
    global _GEO_REFRESH_LAST
    unique = sorted({ip for ip in {str(i or "") for i in ips} if ip})
    if not unique:
        return False
    now = time.time()
    with _GEO_REFRESH_LOCK:
        if now - _GEO_REFRESH_LAST < GEO_REFRESH_MIN_INTERVAL:
            return False
        _GEO_REFRESH_LAST = now
    worker = threading.Thread(
        target=_refresh_geo_worker, args=(unique,),
        daemon=True, name="wpp-user-geo-refresh",
    )
    worker.start()
    return True


# ─── 4. Сборка для вкладки ────────────────────────────────────────────────────
def _best_event(candidates) -> dict | None:
    """Самое свежее {ip, ts} из кандидатов (sub/dev seen + access-log email)."""
    best = None
    for c in candidates:
        if not isinstance(c, dict) or not c.get("ip"):
            continue
        if best is None or int(c.get("ts", 0) or 0) > int(best.get("ts", 0) or 0):
            best = c
    return best


def client_geo(subs, profiles) -> dict:
    """{record_id: {"ip","ts","cc","country","city","pending"}} для users_ui.

    subs — подписки (subscription_registry(): с token);
    profiles — юзеры users() (с email и subscription_id).
    Рендер НЕ ходит в сеть: IP без живого гео-кэша получают pending=True,
    резолв уезжает в refresh_geo_async и появится при следующем опросе
    (pollClients дёргает /clients-state каждые 30 с).
    """
    scan = _scan_access_log()
    seen = _load_json(SEEN_FILE, {})
    if not isinstance(seen, dict):
        seen = {}
    emails_by_sub = {}
    for p in profiles or []:
        sid = p.get("subscription_id")
        email = str(p.get("email", "") or "")
        if sid and email:
            emails_by_sub.setdefault(str(sid), []).append(email)

    geo_cache = _load_json(GEO_FILE, {})
    if not isinstance(geo_cache, dict):
        geo_cache = {}
    now = time.time()
    needed = []

    def _with_geo(event) -> dict:
        ip = str(event.get("ip", ""))
        entry = geo_cache.get(ip)
        info = {
            "ip": ip,
            "ts": int(event.get("ts", 0) or 0),
            "cc": "",
            "country": "",
            "city": "",
            "pending": True,
        }
        if isinstance(entry, dict):
            info.update({
                "cc": str(entry.get("cc", "") or ""),
                "country": str(entry.get("country", "") or ""),
                "city": str(entry.get("city", "") or ""),
                "pending": not _geo_entry_live(entry, now),
            })
        if info["pending"]:
            needed.append(ip)
        return info

    result = {}
    # Подписки: token-seen + device-seen + access-log её email-устройств
    for s in subs or []:
        token = str(s.get("token", "") or "")
        sid = str(s.get("id", "") or "")
        if not token:
            continue
        candidates = [seen.get("sub:" + token)]
        prefix = "dev:" + token + ":"
        candidates += [v for k, v in seen.items() if k.startswith(prefix) and isinstance(v, dict)]
        candidates += [scan.get(e) for e in emails_by_sub.get(sid, [])]
        best = _best_event(candidates)
        if best:
            result[sid] = _with_geo(best)
    # Отдельные VLESS-подключения: только access-log по email
    # (клиент с прямой ссылкой подписку не запрашивает никогда)
    for p in profiles or []:
        if p.get("subscription_id"):
            continue  # учтён в своей подписке
        email = str(p.get("email", "") or "")
        if not email:
            continue  # MTProto/AWG/primary — своих логов с email нет
        best = scan.get(email)
        if best:
            result[str(p.get("id", ""))] = _with_geo(best)

    if needed:
        refresh_geo_async(needed)
    return result


if __name__ == "__main__":
    # Диагностика из CLI: python3 wpp_user_geo.py [ip] | без аргументов — дамп
    if len(sys.argv) > 1:
        print(json.dumps(_geo_lookup(sys.argv[1]), ensure_ascii=False, indent=2))
    else:
        print("seen:", json.dumps(_load_json(SEEN_FILE, {}), ensure_ascii=False)[:2000])
        print("geo:", json.dumps(_load_json(GEO_FILE, {}), ensure_ascii=False)[:2000])
