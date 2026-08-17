"""
chimera/modules/satellite_bindings.py
───────────────────────────────────────────────────────────────────────────────
Per-user binding layer for satellite protocols (Mieru / NaiveProxy / Telemt /
TrustTunnel / sing-box).

ПРОБЛЕМА:
  Раньше подписка сопоставляла UUID-пользователя с логином сателлита
  эвристикой по имени (subscription._match_by_name): device_label / name /
  email-local-part совпадает с логином сателлита (case-insensitive). Это
  работало, но:
    • Не давало чёткой per-user привязки (как у AWG owner_email).
    • При несовпадении имён админ должен был руками прописать
      subscription.json → identity_map[uuid].mieru = "login" — тоже
      workaround, не полноценный CRUD.
    • Admin/User Portal не показывал, какие сателлиты привязаны к юзеру.

РЕШЕНИЕ:
  Единый side-table /var/lib/xray-installer/satellite_bindings.json с
  CRUD API. Не трогает форматы state каждого сателлита (Telemt TOML,
  TrustTunnel TOML, Mieru/NaiveProxy/singbox JSON) — только отображение
  UUID→login. Каждый модуль сателлита НЕ модифицируется — binding живёт
  отдельно и опционально (без него подписка работает как раньше).

Совместимость:
  • Старая эвристика _match_by_name остаётся как fallback — все
    существующие инсталляции продолжают работать без миграции.
  • subscription.json → identity_map (legacy ручной override) тоже
    остаётся, приоритет ВЫШЕ side-table (для ручной правки edge-cases).
  • Новый side-table — canonический путь, Identity map — escape-hatch.

Приоритет разрешения login для (uuid, satellite):
  1. subscription.json → identity_map[uuid][satellite]  (manual override)
  2. satellite_bindings.json → find_login(uuid, satellite)  (CRUD, этот модуль)
  3. Эвристика по имени  (старый fallback в subscription._match_by_name)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Константы ─────────────────────────────────────────────────────────────
_STATE_FILE = Path("/var/lib/xray-installer/satellite_bindings.json")

# Поддерживаемые сателлиты (5 протоколов).
# Ключи используются в state-файле и в API — не менять без миграции.
SATELLITES = ("mieru", "naive", "telemt", "trusttunnel", "singbox")

# Удобные алиасы для отображения в UI.
SATELLITE_LABELS = {
    "mieru":       "Mieru",
    "naive":       "NaiveProxy",
    "telemt":      "Telemt (MTProto)",
    "trusttunnel": "TrustTunnel",
    "singbox":     "sing-box (ShadowTLS/AnyTLS/TUIC/VLESS-WS-CDN)",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Логирование (soft, как в остальных модулях) ────────────────────────────
import sys

_LOG_FILE = Path("/var/log/chimera.log")

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


def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime as _dt
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        with _LOG_FILE.open("a") as f:
            f.write(f"[{_dt.now():%Y-%m-%d %H:%M:%S}] [satellite_bindings] [{level}] {clean}\n")
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════
#  STATE I/O
# ══════════════════════════════════════════════════════════════════════════

def _load() -> dict:
    """Load state. Возвращает {"bindings": [...]} при пустом/битом файле."""
    if not _STATE_FILE.exists():
        return {"bindings": []}
    try:
        data = json.loads(_STATE_FILE.read_text())
        if not isinstance(data, dict):
            return {"bindings": []}
        data.setdefault("bindings", [])
        if not isinstance(data["bindings"], list):
            data["bindings"] = []
        return data
    except Exception as e:
        _log("WARN", f"state corrupted, starting fresh: {e}")
        return {"bindings": []}


def _save(state: dict) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    _STATE_FILE.chmod(0o600)


def _normalize_satellite(name: str) -> Optional[str]:
    """Алиасы сателлитов из UI/legacy → канонический ключ."""
    if not name:
        return None
    n = name.lower().strip()
    aliases = {
        "mieru": "mieru", "m": "mieru",
        "naive": "naive", "naiveproxy": "naive", "np": "naive",
        "telemt": "telemt", "mtproto": "telemt", "tg": "telemt", "t": "telemt",
        "trusttunnel": "trusttunnel", "tt": "trusttunnel",
        "singbox": "singbox", "sing-box": "singbox", "sb": "singbox",
        "shadowtls": "singbox", "anytls": "singbox", "tuic": "singbox",
        "vless_ws_cdn": "singbox",
    }
    return aliases.get(n)


# ══════════════════════════════════════════════════════════════════════════
#  CRUD
# ══════════════════════════════════════════════════════════════════════════

def find_login(owner_uuid: str, satellite: str) -> Optional[str]:
    """Канонический путь: вернуть login сателлита для UUID юзера.
    None — binding не найден, caller падает на эвристику."""
    sat = _normalize_satellite(satellite)
    if not sat or not owner_uuid:
        return None
    state = _load()
    for b in state["bindings"]:
        if (b.get("owner_uuid") == owner_uuid
                and b.get("satellite") == sat):
            return b.get("login") or None
    return None


def find_owner(login: str, satellite: str) -> Optional[dict]:
    """Обратный поиск: кто владеет этим логином в сателлите?
    Возвращает binding dict или None. Используется для диагностики."""
    sat = _normalize_satellite(satellite)
    if not sat or not login:
        return None
    state = _load()
    for b in state["bindings"]:
        if (b.get("login") == login
                and b.get("satellite") == sat):
            return b
    return None


def list_for_user(owner_uuid: str) -> list[dict]:
    """Все биндинги пользователя (для User Portal)."""
    if not owner_uuid:
        return []
    state = _load()
    return [b for b in state["bindings"] if b.get("owner_uuid") == owner_uuid]


def list_all() -> list[dict]:
    """Все биндинги (для Admin Panel)."""
    return _load()["bindings"]


def set_binding(satellite: str, login: str,
                owner_uuid: str, owner_email: str = "") -> bool:
    """Создать или обновить биндинг. Идемпотентно по (satellite, owner_uuid):
    если уже есть — обновляет login и owner_email, иначе добавляет.
    Возвращает True при успехе."""
    sat = _normalize_satellite(satellite)
    if not sat:
        return False
    if not login or not owner_uuid:
        return False
    login = login.strip()
    owner_email = (owner_email or "").strip()
    state = _load()
    # Ищем существующий по (satellite, owner_uuid) — канонический путь.
    for b in state["bindings"]:
        if (b.get("satellite") == sat
                and b.get("owner_uuid") == owner_uuid):
            b["login"] = login
            b["owner_email"] = owner_email
            b["updated_at"] = _utc_now()
            _save(state)
            return True
    # Также проверяем конфликт: тот же (satellite, login) уже занят другим UUID.
    for b in state["bindings"]:
        if (b.get("satellite") == sat
                and b.get("login") == login
                and b.get("owner_uuid") != owner_uuid):
            # Логин уже занят — перезаписываем owner на нового юзера
            # (это явная операция привязки, админ знает что делает).
            b["owner_uuid"] = owner_uuid
            b["owner_email"] = owner_email
            b["updated_at"] = _utc_now()
            _save(state)
            return True
    # Новый биндинг.
    state["bindings"].append({
        "satellite":    sat,
        "login":        login,
        "owner_uuid":   owner_uuid,
        "owner_email":  owner_email,
        "added_at":     _utc_now(),
        "updated_at":   _utc_now(),
    })
    _save(state)
    return True


def remove_binding(satellite: str, owner_uuid: str) -> bool:
    """Удалить биндинг (satellite, owner_uuid). Возвращает True если был удалён."""
    sat = _normalize_satellite(satellite)
    if not sat or not owner_uuid:
        return False
    state = _load()
    before = len(state["bindings"])
    state["bindings"] = [
        b for b in state["bindings"]
        if not (b.get("satellite") == sat
                and b.get("owner_uuid") == owner_uuid)
    ]
    if len(state["bindings"]) == before:
        return False
    _save(state)
    return True


def remove_user(owner_uuid: str) -> int:
    """Удалить ВСЕ биндинги пользователя (при удалении VLESS-юзера).
    Возвращает количество удалённых записей."""
    if not owner_uuid:
        return 0
    state = _load()
    before = len(state["bindings"])
    state["bindings"] = [
        b for b in state["bindings"]
        if b.get("owner_uuid") != owner_uuid
    ]
    removed = before - len(state["bindings"])
    if removed:
        _save(state)
    return removed


# ══════════════════════════════════════════════════════════════════════════
#  АВТО-СКАНИРОВАНИЕ (для TUI: «предложить привязку»)
# ══════════════════════════════════════════════════════════════════════════

def _scan_mieru() -> list[dict]:
    """[{"login": "alice", "satellite": "mieru"}, ...]"""
    path = Path("/var/lib/xray-installer/mieru.json")
    out = []
    if not path.exists():
        return out
    try:
        st = json.loads(path.read_text())
        for u in st.get("users", []):
            login = u.get("username")
            if login:
                out.append({"satellite": "mieru", "login": login})
    except Exception as e:
        _log("WARN", f"scan mieru: {e}")
    return out


def _scan_naive() -> list[dict]:
    path = Path("/var/lib/xray-installer/naiveproxy.json")
    out = []
    if not path.exists():
        return out
    try:
        st = json.loads(path.read_text())
        for u in st.get("users", []):
            login = u.get("username")
            if login:
                out.append({"satellite": "naive", "login": login})
    except Exception as e:
        _log("WARN", f"scan naive: {e}")
    return out


def _scan_telemt() -> list[dict]:
    path = Path("/etc/telemt/telemt.toml")
    out = []
    if not path.exists():
        return out
    try:
        # Минимальный TOML-парсер (как в subscription._parse_telemt_toml) —
        # не тянем tomllib ради одной секции.
        in_users = False
        for line in path.read_text().splitlines():
            s = line.strip()
            if s == "[access.users]":
                in_users = True
                continue
            if in_users:
                if s.startswith("["):
                    break
                m = re.match(r'^([a-zA-Z][a-zA-Z0-9_\-]+)\s*=\s*"([a-f0-9]{32})"', s)
                if m:
                    out.append({"satellite": "telemt", "login": m.group(1)})
    except Exception as e:
        _log("WARN", f"scan telemt: {e}")
    return out


def _scan_trusttunnel() -> list[dict]:
    path = Path("/var/lib/xray-installer/trusttunnel.json")
    out = []
    if not path.exists():
        return out
    try:
        st = json.loads(path.read_text())
        creds_path = Path(st.get("creds_toml", "") or "/opt/trusttunnel/credentials.toml")
        if not creds_path.exists():
            return out
        text = creds_path.read_text()
        # [[client]]\nusername = "alice@x.com"
        for m in re.finditer(r'username\s*=\s*"([^"]+)"', text):
            out.append({"satellite": "trusttunnel", "login": m.group(1)})
    except Exception as e:
        _log("WARN", f"scan trusttunnel: {e}")
    return out


def _scan_singbox() -> list[dict]:
    """Для sing-box user-identity — это UUID (а не login).
    Возвращаем login=uuid для всех уникальных UUID во всех включённых inbound'ах.
    Sing-box УЖЕ хранит per-user UUID — binding тут больше для отображения
    в Admin Panel, чем для матчинга (subscription.py для singbox уже
    находит по UUID)."""
    path = Path("/var/lib/xray-installer/singbox_state.json")
    out = []
    if not path.exists():
        return out
    try:
        st = json.loads(path.read_text())
        inbounds = st.get("inbounds", {})
        seen = set()
        for proto in ("shadowtls", "anytls", "tuic"):
            ib = inbounds.get(proto, {})
            if not ib.get("enabled"):
                continue
            for u in ib.get("users", []):
                uid = u.get("uuid")
                if uid and uid not in seen:
                    seen.add(uid)
                    out.append({"satellite": "singbox", "login": uid,
                                "name": u.get("name", "")})
    except Exception as e:
        _log("WARN", f"scan singbox: {e}")
    return out


_SCAN_FUNCS = {
    "mieru":       "_scan_mieru",
    "naive":       "_scan_naive",
    "telemt":      "_scan_telemt",
    "trusttunnel": "_scan_trusttunnel",
    "singbox":     "_scan_singbox",
}


def scan_all_satellites() -> dict:
    """Сканирует все 5 сателлитов, возвращает {satellite: [{login, ...}]}.
    Используется TUI для показа «доступных логинов» и User Portal для
    отображения несинхронизированных сателлитов.

    ВАЖНО: вызов функций через globals()[fn_name]() — не через словарь
    со ссылками на функции. Это позволяет патчить отдельные scan_* в
    тестах через patch.object (patch подменяет атрибут модуля, а
    предзаполненный словарь хранил бы старую ссылку)."""
    out = {}
    for sat, fn_name in _SCAN_FUNCS.items():
        try:
            fn = globals().get(fn_name)
            if fn is None:
                out[sat] = []
                continue
            out[sat] = fn()
        except Exception as e:
            _log("WARN", f"scan {sat}: {e}")
            out[sat] = []
    return out


def suggest_for_user(user: dict) -> list[dict]:
    """Авто-предложение привязок для пользователя.

    Для каждого сателлита ищет логин, который СОВПАДАЕТ с одним из
    кандидатов имени юзера (device_label / name / email-local-part /
    email / uuid). Возвращает список предложений:
      [{"satellite": "mieru", "login": "alice", "match": "email-local-part",
        "current_binding": None|"login"}]

    current_binding показывает, привязан ли уже этот сателлит к юзеру
    (и если да — к какому логину). Используется TUI для подсветки
    конфликтов и предложения обновления."""
    uuid_str = user.get("uuid", "")
    if not uuid_str:
        return []

    candidates = {
        (user.get("device_label") or "").strip().lower(),
        (user.get("name") or "").strip().lower(),
        (user.get("email") or "").strip().lower(),
        (user.get("email") or "").split("@")[0].strip().lower(),
        uuid_str.lower(),
    }
    candidates.discard("")

    suggestions = []
    scan = scan_all_satellites()
    for sat, logins in scan.items():
        current = find_login(uuid_str, sat)
        # Для sing-box login=UUID — сравниваем по UUID напрямую.
        match = None
        for entry in logins:
            login = entry.get("login", "")
            if sat == "singbox":
                # sing-box login=uuid, user.uuid=uuid → точное совпадение
                if login.lower() == uuid_str.lower():
                    match = entry
                    break
            else:
                if login.strip().lower() in candidates:
                    match = entry
                    break
        suggestions.append({
            "satellite":         sat,
            "satellite_label":   SATELLITE_LABELS[sat],
            "available_logins":  [e["login"] for e in logins],
            "matched_login":     match["login"] if match else None,
            "match_reason":      ("uuid" if sat == "singbox" and match else
                                  ("name" if match else None)),
            "current_binding":   current,
            "is_active":         bool(logins),  # сателлит установлен и имеет юзеров
        })
    return suggestions


# ══════════════════════════════════════════════════════════════════════════
#  ИНТЕГРАЦИЯ С subscription._match_by_name
# ══════════════════════════════════════════════════════════════════════════

def resolve_login(user: dict, satellite: str, pool_keys) -> Optional[str]:
    """Канонический резолвер login для (user, satellite).

    Параметр pool_keys — список/множество доступных логинов сателлита
    (передаётся из subscription._match_by_name — там уже загружены).
    Если вернёт None — subscription._match_by_name сделает старую
    эвристику по имени (100% обратная совместимость).

    Приоритет:
      1. subscription.json → identity_map[uuid][satellite]  (legacy override)
      2. satellite_bindings.json → find_login(uuid, satellite)  (этот модуль)
      3. None → caller делает эвристику по имени
    """
    sat = _normalize_satellite(satellite)
    if not sat:
        return None
    uuid_str = user.get("uuid", "")
    if not uuid_str:
        return None

    # 1. identity_map — читается в subscription.py, сюда не тащим зависимость.
    # (caller уже проверил identity_map ВЫЗЫВОМ _match_by_name — мы тут только
    #  для канонического пути bindings.json.)

    # 2. Side-table (этот модуль).
    login = find_login(uuid_str, sat)
    if login and (not pool_keys or login in pool_keys):
        return login
    return None


# ══════════════════════════════════════════════════════════════════════════
#  INFO ДЛЯ ПОРТАЛОВ
# ══════════════════════════════════════════════════════════════════════════

def get_user_satellites_info(user: dict) -> list[dict]:
    """Сводка привязок пользователя для User Portal (GET /api/portal/sat-info).

    Возвращает [{"satellite": "mieru", "label": "Mieru",
                 "login": "alice", "active": True}], где active=True если
    сателлит установлен и логин найден в его users."""
    uuid_str = user.get("uuid", "")
    if not uuid_str:
        return []
    bindings = list_for_user(uuid_str)
    scan = scan_all_satellites()
    out = []
    for b in bindings:
        sat = b.get("satellite", "")
        if sat not in SATELLITE_LABELS:
            continue
        logins_in_sat = scan.get(sat, [])
        login = b.get("login", "")
        active = any(l.get("login") == login for l in logins_in_sat)
        out.append({
            "satellite":      sat,
            "label":          SATELLITE_LABELS[sat],
            "login":          login,
            "active":         active,
            "owner_email":    b.get("owner_email", ""),
        })
    return out


def get_admin_satellites_info() -> dict:
    """Сводка для Admin Panel: все биндинги + все свободные логины."""
    scan = scan_all_satellites()
    bindings = list_all()
    return {
        "bindings": bindings,
        "available": {
            sat: scan.get(sat, [])
            for sat in SATELLITES
        },
        "satellite_labels": dict(SATELLITE_LABELS),
    }


# ══════════════════════════════════════════════════════════════════════════
#  КЛИЕНТ CLI (для тестирования)
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":  # pragma: no cover
    import argparse
    p = argparse.ArgumentParser(description="Satellite bindings CLI")
    p.add_argument("cmd", choices=["list", "scan", "suggest"])
    p.add_argument("--uuid", help="user UUID (for suggest)")
    args = p.parse_args()
    if args.cmd == "list":
        for b in list_all():
            print(f"  {b['satellite']:<12} {b['login']:<30} → {b.get('owner_email','?'):<30} [{b.get('owner_uuid','')[:8]}…]")
    elif args.cmd == "scan":
        for sat, logins in scan_all_satellites().items():
            print(f"\n{sat}:")
            for l in logins:
                extra = f"  ({l.get('name','')})" if l.get("name") else ""
                print(f"  {l['login']}{extra}")
    elif args.cmd == "suggest":
        if not args.uuid:
            print("Need --uuid"); exit(1)
        for s in suggest_for_user({"uuid": args.uuid}):
            print(f"  {s['satellite_label']:<40} matched={s['matched_login'] or '-'}  current={s['current_binding'] or '-'}  active={s['is_active']}")
