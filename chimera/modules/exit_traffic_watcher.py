"""
exit_traffic_watcher.py — наблюдатель ФАКТИЧЕСКОГО распределения трафика
по exit-нодам с TG-уведомлениями.

Контекст (живой кейс окт.2026 №8, продолжение): exit_switch_watcher
возвращает уведы об ИЗМЕНЕНИЯХ ротации (состав selector, стратегия, pin,
exit-IP) — но в балансировочных режимах (roundRobin / leastPing /
leastLoad / random) Xray выбирает outbound на каждое СОЕДИНЕНИЕ, поэтому
«активной ноды» не существует и вопрос владельца «через какую ноду
реально идёт мой трафик?» остаётся без ответа: события молчат, пока
состав не меняется. SmartBalancer шлёт node_connect только при собственных
переключениях (а после перехода ротации на нативный chain-balancer он
«только наблюдает» — патч адреса пропущен).

Этот модуль — второй наблюдатель поверх той же точки, но с другим
источником данных: не СОБЫТИЯ переключений, а СЧЁТЧИКИ трафика.
Xray Stats API (127.0.0.1:10085, секция api/stats уже встраивается в
chain-конфиги `_apply_stats_to_config` — chain_nodes.py) отдаёт
накопленные байты по каждому outbound-тегу:

    outbound>>>chain-exit-N>>>traffic>>>uplink / downlink

Дельты счётчиков между прогонами = фактический трафик через каждую
ноду за окно. Подход режим-агностичен по построению и работает во ВСЕХ
режимах: roundRobin / leastPing / leastLoad / random (нативный
chain-balancer), smartBalancer (патчит selector — счётчики честны),
pinned/single-pick (100% трафика на закреплённой ноде).

События (ключи фильтра в telegram.json, иконки в tg_bot.tg_notify_event):
  • traffic_dominant_change — доминирующая нода (по объёму за окно
    накопления) сменилась; пороги настраиваются (доля %, мин. объём);
  • traffic_snapshot        — периодический дайджест: распределение
    трафика по нодам (байты + %), стратегия, опционально разбор
    по пользователям (кто через какую ноду — из access.log);
  • traffic_node_starved    — нода в selector балансировщика не несёт
    трафик N часов, пока другие несут (roundRobin/leastPing может
    скипать ноду — сигнал, что что-то не так);
  • traffic_stats_error     — Stats API недоступен 3 прогона подряд
    (не чаще раза в сутки): xray упал или конфиг без секции api.

Отправка идёт через tg_bot.tg_notify_event() — событие уважает фильтр
из меню «Telegram-уведомления» (пункт «Включить/выключить отдельные
события») и ключ proxy в telegram.json. Fallback — прямая отправка
curl-ом (паттерн exit_switch_watcher / node_health_monitor).

Кастомизация — /var/lib/xray-installer/exit_traffic_watcher.json
(см. DEFAULTS): интервал cron, вкл/выкл каждого типа событий, пороги
доминирования (доля %, мин. объём), quiet-часы, анти-спам min_gap,
шаблоны сообщений с плейсхолдерами, отдельный chat_id, алиасы нод
(host:port → человекочитаемое имя в уведах), разбор по пользователям
(per_user, топ-N), пороги starve-детекта.

Публичный API:
    run_once()                        → dict   — одна итерация наблюдения
    load_cfg() / save_cfg()           → dict/None
    is_installed()                    → bool
    install_watcher(interval_min)     → (bool, str)
    uninstall_watcher()               → (bool, str)
    do_traffic_watcher_menu()         → None   — интерактивное меню
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

# ── Константы ─────────────────────────────────────────────────────────────────
STATE_FILE    = Path("/var/lib/xray-installer/state.json")
SB_STATE_FILE = Path("/var/lib/xray-installer/smart_balancer.json")
TW_CFG_FILE   = Path("/var/lib/xray-installer/exit_traffic_watcher.json")
TW_LOG_FILE   = Path("/var/log/xray-exit-traffic-watcher.log")
CRON_FILE     = Path("/etc/cron.d/xray-exit-traffic-watcher")
CRON_SCRIPT   = Path("/usr/local/bin/xray-exit-traffic-watcher.sh")
ACCESS_LOG    = Path("/var/log/xray/access.log")
XRAY_CFG_CANDIDATES = (Path("/etc/xray/config.json"),
                       Path("/usr/local/etc/xray/config.json"))

# Дубликат _core.XRAY_STATS_API_PORT (модуль самодостаточен — работает
# из cron без импорта монолита _core; паттерн exit_switch_watcher)
STATS_API_PORT = 10085

DEFAULT_INTERVAL    = 15   # минут
DEFAULT_SNAPSHOT_HOURS = 12
STATS_FAIL_THRESHOLD = 3    # прогонов подряд перед traffic_stats_error
STATS_ERROR_RETRY_SEC = 86400  # не чаще раза в сутки

# События наблюдателя (ключи фильтра в telegram.json)
EVENTS = ("traffic_dominant_change", "traffic_snapshot",
          "traffic_node_starved", "traffic_stats_error")

# Дефолтные шаблоны (HTML для parse_mode=HTML). Плейсхолдеры:
#   {host} — короткое имя этого сервера; {ts} — локальное время;
#   {detail} — тело события.
DEFAULT_TEMPLATES = {
    "traffic_dominant_change":
        "🧭 <b>[{host}]</b> Смена доминирующей exit-ноды\n{detail}\n<i>{ts}</i>",
    "traffic_snapshot":
        "📈 <b>[{host}]</b> Распределение трафика по exit-нодам\n{detail}\n<i>{ts}</i>",
    "traffic_node_starved":
        "💤 <b>[{host}]</b> Нода без трафика\n{detail}\n<i>{ts}</i>",
    "traffic_stats_error":
        "⚠️ <b>[{host}]</b> Stats API недоступен\n{detail}\n<i>{ts}</i>",
}

MB = 1024 * 1024

DEFAULTS = {
    "enabled":          True,
    "interval_min":     DEFAULT_INTERVAL,
    "notify":           {ev: True for ev in EVENTS},
    "snapshot_hours":   DEFAULT_SNAPSHOT_HOURS,   # 0 = дайджест выключен
    # Доминирование: смена «главной» ноды фиксируется, если её доля ≥
    # dominant_min_share_pct от трафика окна, а объём окна ≥ dominant_min_mb
    "dominant_min_share_pct": 60,
    "dominant_min_mb":  50,
    "min_gap_min":      10,        # анти-спам: мин. пауза между уведами типа
    "quiet_hours":      {"from": "", "to": ""},   # "" = нет тихих часов
    "chat_id_override": "",        # "" = chat_id из telegram.json
    "aliases":          {},        # host:port → имя в уведах ("RU1")
    "include_percent":  True,      # % в дайджесте
    "include_bytes":    True,      # байты в дайджесте
    # Разбор по пользователям (кто через какую ноду; access.log, loglevel=info)
    "per_user":         False,
    "per_user_top":     5,
    # Starve-детект: нода в selector без трафика starve_hours при живом
    # трафике на других (0 = выключен)
    "starve_hours":     0,
    "starve_min_total_mb": 50,
    "templates":        dict(DEFAULT_TEMPLATES),
}

# ── Цвета (импорт отложен — модуль работает и без TUI, из cron) ───────────────


def _colors() -> dict:
    try:
        from chimera.modules.box_renderer import GREEN, YELLOW, RED, CYAN, DIM, BOLD, NC
        return {"GREEN": GREEN, "YELLOW": YELLOW, "RED": RED,
                "CYAN": CYAN, "DIM": DIM, "BOLD": BOLD, "NC": NC}
    except Exception:
        return {"GREEN": "", "YELLOW": "", "RED": "",
                "CYAN": "", "DIM": "", "BOLD": "", "NC": ""}


# ── Чистые функции (тестируются без сервера) ──────────────────────────────────


def _tw_merge_cfg(defaults: dict, stored: dict) -> dict:
    """Глубокое слияние сохранённого конфига с дефолтами (паттерн
    exit_switch_watcher._ew_merge_cfg): отсутствующие ключи добираются
    из DEFAULTS (вложенные dict — рекурсивно; список notify всегда
    полный: новые типы событий по умолчанию ВКЛ).
    Чистая функция."""
    out = dict(defaults)
    for k, v in (stored or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _tw_merge_cfg(out[k], v)
        else:
            out[k] = v
    if isinstance(out.get("notify"), dict):
        nf = dict(out["notify"])
        for ev in EVENTS:
            nf.setdefault(ev, True)
        out["notify"] = nf
    return out


def _tw_hhmm_to_min(hhmm: str) -> int:
    h, m = str(hhmm).split(":")
    return int(h) * 60 + int(m)


def _tw_quiet(now_hhmm: str, quiet: dict) -> bool:
    """True, если сейчас тихие часы (уведы подавляются).
    Интервал через полночь поддерживается. Чистая функция."""
    qf = str((quiet or {}).get("from") or "").strip()
    qt = str((quiet or {}).get("to") or "").strip()
    if not qf or not qt or qf == qt:
        return False
    try:
        n = _tw_hhmm_to_min(now_hhmm)
        f = _tw_hhmm_to_min(qf)
        t = _tw_hhmm_to_min(qt)
    except (ValueError, TypeError):
        return False
    if f < t:
        return f <= n < t
    return n >= f or n < t


def _tw_gap_ok(last_ts: float, now_ts: float, gap_min) -> bool:
    """Анти-спам: True, если с last_ts прошло >= gap_min минут
    (gap_min <= 0 / нет last_ts — всегда True). Чистая функция."""
    try:
        gap = float(gap_min or 0)
    except (TypeError, ValueError):
        gap = 0.0
    if gap <= 0 or not last_ts:
        return True
    return (now_ts - float(last_ts)) >= gap * 60.0


def _tw_render(template: str, **kw) -> str:
    """Безопасный рендер шаблона: подставляет только известные
    плейсхолдеры, {фигурные} скобки без подстановки не ломает.
    Чистая функция."""
    out = str(template or "")
    for k, v in kw.items():
        out = out.replace("{" + k + "}", str(v))
    return out


# statsquery: {"stat": [{"name": "outbound>>>tag>>>traffic>>>uplink", ...}]}
_STAT_NAME_RE = re.compile(r'^outbound>>>([^>]+)>>>traffic>>>(uplink|downlink)$')


def _tw_parse_stats(text: str) -> dict:
    """Парсинг вывода `xray api statsquery` в {tag: {'up': int,
    'down': int}}. Битый вывод → {}. Чистая функция."""
    try:
        data = json.loads(str(text or ""))
    except Exception:
        return {}
    out: dict = {}
    for entry in (data.get("stat") or []) if isinstance(data, dict) else []:
        if not isinstance(entry, dict):
            continue
        m = _STAT_NAME_RE.match(str(entry.get("name") or ""))
        if not m:
            continue
        try:
            val = max(0, int(entry.get("value") or 0))
        except (TypeError, ValueError):
            continue
        d = out.setdefault(m.group(1), {"up": 0, "down": 0})
        if m.group(2) == "uplink":
            d["up"] = val
        else:
            d["down"] = val
    return out


def _tw_deltas(prev: dict, cur: dict) -> dict:
    """Дельты счётчиков между прогонами: {tag: {'up', 'down'}}.
    Рестарт xray сбрасывает счётчики (cur < prev) — в этом случае
    дельта = cur (трафик с момента рестарта), не отрицательное число.
    Чистая функция."""
    deltas: dict = {}
    for tag, c in (cur or {}).items():
        p = (prev or {}).get(tag) or {}
        dup = int(c.get("up") or 0) - int(p.get("up") or 0)
        ddn = int(c.get("down") or 0) - int(p.get("down") or 0)
        if dup < 0:
            dup = int(c.get("up") or 0)
        if ddn < 0:
            ddn = int(c.get("down") or 0)
        deltas[tag] = {"up": max(0, dup), "down": max(0, ddn)}
    return deltas


def _tw_acc_add(acc: dict, deltas: dict) -> dict:
    """Накопление дельт окна дайджеста: acc + deltas → новый acc
    (входы не мутируются). Чистая функция."""
    out = {t: dict(v) for t, v in (acc or {}).items()}
    for tag, d in (deltas or {}).items():
        o = out.setdefault(tag, {"up": 0, "down": 0})
        o["up"] += int(d.get("up") or 0)
        o["down"] += int(d.get("down") or 0)
    return out


def _tw_bytes_of(d: dict) -> int:
    return int((d or {}).get("up") or 0) + int((d or {}).get("down") or 0)


def _tw_total(deltas: dict) -> int:
    return sum(_tw_bytes_of(v) for v in (deltas or {}).values())


def _tw_dominant(acc: dict, min_share_pct=60,
                 min_total_bytes=50 * MB) -> dict | None:
    """Доминирующая нода окна: {'tag', 'bytes', 'total', 'share'} или
    None, если объём окна < min_total_bytes (анти-шум на пустых окнах)
    или доля лучшей ноды < min_share_pct (равномерное roundRobin-распределение
    не порождает «доминирующую» ноду — это корректное поведение).
    Чистая функция."""
    total = _tw_total(acc)
    if total < max(1, int(min_total_bytes or 0)):
        return None
    best_tag, best_val = None, -1
    for tag, v in (acc or {}).items():
        s = _tw_bytes_of(v)
        if s > best_val:
            best_tag, best_val = tag, s
    if not best_tag or best_val <= 0:
        return None
    share = 100.0 * best_val / total
    if share < float(min_share_pct or 0):
        return None
    return {"tag": best_tag, "bytes": best_val,
            "total": total, "share": share}


def _tw_starve_update(zero_since: dict, deltas: dict, selector: list,
                      now_ts: float, starve_sec: float,
                      min_total_bytes: int) -> tuple:
    """Starve-детект: обновляет карту zero_since (tag → ts первого окна
    без трафика). Нода из selector с нулевым трафиком за окно при живом
    трафике на других (total окна ≥ min_total_bytes) «голодает»
    starve_sec → попадает в starved; таймер перевзводится (следующее
    уведомление не раньше чем ещё starve_sec).
    Возвращает (new_zero_since, [starved_tags]). Чистая функция."""
    zs = dict(zero_since or {})
    starved: list = []
    total = _tw_total(deltas)
    for tag in (selector or []):
        traffic = _tw_bytes_of((deltas or {}).get(tag))
        if traffic > 0:
            zs.pop(tag, None)
            continue
        first = zs.get(tag)
        if first is None:
            zs[tag] = now_ts
        elif (now_ts - float(first)) >= float(starve_sec) \
                and total >= max(0, int(min_total_bytes or 0)):
            starved.append(tag)
            zs[tag] = now_ts
    return zs, starved


_UNITS = (("ТБ", 1024 ** 4), ("ГБ", 1024 ** 3),
          ("МБ", 1024 ** 2), ("КБ", 1024), ("Б", 1))


def _tw_fmt_bytes(n: int) -> str:
    """Человекочитаемые байты (рус. единицы). Чистая функция."""
    try:
        n = int(n or 0)
    except (TypeError, ValueError):
        n = 0
    if n < 0:
        n = 0
    for label, size in _UNITS:
        if n >= size:
            return f"{n / size:.1f} {label}".replace(".0 ", " ")
    return f"{n} Б"


def _tw_distribution_rows(acc: dict, names: dict, include_percent=True,
                          include_bytes=True) -> list:
    """Строки распределения (для дайджеста и меню): ноды по убыванию
    объёма, формат «• имя — 1.2 ГБ (63%)». Чистая функция."""
    total = _tw_total(acc)
    rows: list[str] = []
    items = sorted((acc or {}).items(),
                   key=lambda kv: -_tw_bytes_of(kv[1]))
    for tag, v in items:
        s = _tw_bytes_of(v)
        name = (names or {}).get(tag) or tag
        body = ""
        if include_bytes and include_percent and total > 0:
            body = f" — {_tw_fmt_bytes(s)} ({100.0 * s / total:.0f}%)"
        elif include_bytes:
            body = f" — {_tw_fmt_bytes(s)}"
        elif include_percent and total > 0:
            body = f" — {100.0 * s / total:.0f}%"
        rows.append(f"• <code>{name}</code>{body}")
    return rows


# access.log (loglevel=info): «… accepted tcp:dst:443 [chain-exit-2] email: u@d»
_ACC_TAG_RE  = re.compile(r'accepted\s+\S+\s+\[[^\]]*?([A-Za-z0-9\-_]+)\s*\]')
_EMAIL_RE    = re.compile(r'email:\s*(\S+)')


def _tw_parse_access_users(lines: list, tags_whitelist=None) -> dict:
    """Счётчик соединений по (пользователь × outbound-тег) из строк
    access.log. Возвращает {email: {tag: count}}. Строки без email
    (без аутентификации) и теги вне whitelist игнорируются.
    Чистая функция."""
    wl = set(tags_whitelist) if tags_whitelist is not None else None
    counts: dict = {}
    for line in lines or []:
        if "accepted" not in line:
            continue
        em = _EMAIL_RE.search(line)
        if not em:
            continue
        tm = _ACC_TAG_RE.search(line)
        if not tm:
            continue
        tag = tm.group(1)
        if wl is not None and tag not in wl:
            continue
        email = em.group(1)
        d = counts.setdefault(email, {})
        d[tag] = d.get(tag, 0) + 1
    return counts


def _tw_per_user_rows(counts: dict, names: dict, top_n=5) -> list:
    """Строки разбора по пользователям: «👤 email: имя 70%, имя 30%»
    (доли от соединений пользователя). Чистая функция."""
    if not counts:
        return []
    try:
        top_n = max(1, int(top_n))
    except (TypeError, ValueError):
        top_n = 5
    totals = {em: sum(d.values()) for em, d in counts.items()}
    rows: list[str] = []
    for em, _t in sorted(totals.items(), key=lambda kv: -kv[1])[:top_n]:
        parts = []
        for tag, c in sorted(counts[em].items(), key=lambda kv: -kv[1]):
            name = (names or {}).get(tag) or tag
            tot = totals[em]
            if tot > 0:
                parts.append(f"{name} {100.0 * c / tot:.0f}%")
            else:
                parts.append(name)
        rows.append(f"👤 <code>{em}</code>: " + ", ".join(parts))
    return rows


def _tw_snapshot_text(acc: dict, names: dict, strategy: str,
                      window_str: str, per_user_rows: list,
                      include_percent=True, include_bytes=True) -> str:
    """Текст дайджеста распределения. Чистая функция."""
    lines = []
    st = str(strategy or "").strip()
    lines.append(f"Стратегия: <b>{st or 'нет'}</b>")
    if window_str:
        lines.append(f"Окно: {window_str}, всего: <b>{_tw_fmt_bytes(_tw_total(acc))}</b>")
    else:
        lines.append(f"Всего за окно: <b>{_tw_fmt_bytes(_tw_total(acc))}</b>")
    rows = _tw_distribution_rows(acc, names, include_percent, include_bytes)
    if rows:
        lines.extend(rows)
    else:
        lines.append("Трафика через exit-ноды за окно не было")
    if per_user_rows:
        lines.append("Пользователи (соединений по нодам):")
        lines.extend(per_user_rows)
    return "\n".join(lines)


def _tw_tag_names(chain_nodes: list, aliases: dict | None = None) -> tuple:
    """Карты тегов: ({tag: отображаемое имя}, {tag: host:port}).
    chain-exit-N → нода с индексом N-1 (сопоставление как в
    _access_log_bytes_per_node). Чистая функция."""
    names: dict = {}
    keys: dict = {}
    for i, nd in enumerate(chain_nodes or []):
        host = str((nd or {}).get("host") or "").strip()
        if not host:
            continue
        port = int((nd or {}).get("port") or 443)
        tag = f"chain-exit-{i + 1}"
        key = f"{host}:{port}"
        alias = str((aliases or {}).get(key) or "").strip()
        names[tag] = alias or key
        keys[tag] = key
    return names, keys


# ── IO: конфиг / лог / чтение источников ──────────────────────────────────────


def load_cfg() -> dict:
    """Конфиг наблюдателя (слитый с дефолтами; битый файл = дефолты)."""
    stored = {}
    try:
        if TW_CFG_FILE.exists():
            stored = json.loads(TW_CFG_FILE.read_text(encoding="utf-8"))
    except Exception:
        stored = {}
    return _tw_merge_cfg(DEFAULTS, stored if isinstance(stored, dict) else {})


def save_cfg(cfg: dict) -> None:
    """Сохранение конфига (права 600, каталог создаётся)."""
    TW_CFG_FILE.parent.mkdir(parents=True, exist_ok=True)
    TW_CFG_FILE.write_text(
        json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    TW_CFG_FILE.chmod(0o600)


def _tw_log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        TW_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(TW_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{ts} {msg}\n")
    except Exception:
        pass


def _read_json(path: Path) -> dict:
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _load_state() -> dict:
    return _read_json(STATE_FILE)


def _tw_live_balancer() -> dict:
    """Нативный chain-balancer из живого Xray-конфига:
    {'selector': [tags], 'strategy': str} (пустой selector — балансировщика
    нет; значения по умолчанию: strategy='random')."""
    for p in XRAY_CFG_CANDIDATES:
        try:
            if not p.exists():
                continue
            cfg = json.loads(p.read_text(encoding="utf-8"))
            for b in (cfg.get("routing") or {}).get("balancers") or []:
                if str(b.get("tag") or "") != "chain-balancer":
                    continue
                sel = b.get("selector")
                strat = ((b.get("strategy") or {}).get("type")) or "random"
                return {"selector": list(sel) if isinstance(sel, list) else [],
                        "strategy": str(strat)}
        except Exception:
            continue
    return {"selector": [], "strategy": ""}


def _tw_stats_api_enabled() -> bool:
    """Секция api/stats присутствует в живом конфиге (для подсказок меню)."""
    for p in XRAY_CFG_CANDIDATES:
        try:
            if not p.exists():
                continue
            cfg = json.loads(p.read_text(encoding="utf-8"))
            if cfg.get("stats") and (cfg.get("api") or {}).get("services"):
                return True
        except Exception:
            continue
    return False


def _tw_find_xray() -> str:
    for p in ("/usr/local/bin/xray", "/usr/bin/xray"):
        if Path(p).exists():
            return p
    return shutil.which("xray") or ""


def _tw_query_stats(timeout: int = 8) -> dict | None:
    """Опрос Stats API: {tag: {'up','down'}} или None (xray нет, API
    недоступен, таймаут). Никогда не бросает."""
    xray = _tw_find_xray()
    if not xray:
        return None
    try:
        r = subprocess.run(
            [xray, "api", "statsquery",
             f"--server=127.0.0.1:{STATS_API_PORT}",
             "--pattern=outbound>>>", "--reset=false"],
            capture_output=True, text=True, timeout=timeout, check=False)
        if r.returncode != 0 or not (r.stdout or "").strip():
            return None
        return _tw_parse_stats(r.stdout)
    except Exception:
        return None


def _hostname() -> str:
    try:
        return subprocess.run(["hostname", "-s"], capture_output=True,
                              text=True, check=False).stdout.strip() or "server"
    except Exception:
        return "server"


def _now_str() -> str:
    return time.strftime("%d.%m.%Y %H:%M")


# ── Уведомления ───────────────────────────────────────────────────────────────


def _tw_notify_event(event: str, detail: str, cfg: dict) -> bool:
    """Отправка события. Основной путь — tg_bot.tg_notify_event
    (уважает фильтр событий меню «Telegram-уведомления» и ключ proxy);
    fallback — прямая отправка curl-ом (паттерн exit_switch_watcher),
    если tg_bot недоступен. Возвращает True при доставке."""
    notify_map = (cfg or {}).get("notify") or {}
    if notify_map.get(event, True) is False:
        return False

    chat_override = str((cfg or {}).get("chat_id_override") or "").strip()
    try:
        from chimera.modules import tg_bot
        if chat_override:
            tpl = (cfg.get("templates") or {}).get(event) \
                or DEFAULT_TEMPLATES.get(event, "{detail}")
            text = _tw_render(tpl, host=_hostname(), ts=_now_str(),
                              detail=detail)
            ok = tg_bot.tg_send(text, chat_id=chat_override)
            _tw_log(f"TG[{event}] direct-override -> {chat_override}: "
                    f"{'OK' if ok else 'FAIL'}")
            return ok
        tg_bot.tg_notify_event(event, detail)
        _tw_log(f"TG[{event}] sent (filter-respecting path)")
        return True
    except Exception as e:
        _tw_log(f"TG[{event}] tg_bot недоступен ({e}) — curl-fallback")

    tcfg = _read_json(Path("/var/lib/xray-installer/telegram.json"))
    token = str(tcfg.get("token") or "")
    chat_id = chat_override or str(tcfg.get("chat_id") or "")
    if not token or not chat_id:
        return False
    try:
        tpl = (cfg.get("templates") or {}).get(event) \
            or DEFAULT_TEMPLATES.get(event, "{detail}")
        text = _tw_render(tpl, host=_hostname(), ts=_now_str(),
                          detail=detail)
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
               "-m", "10"]
        px = str(tcfg.get("proxy") or "").strip()
        if px:
            cmd += ["-x", px]
        cmd += [f"https://api.telegram.org/bot{token}/sendMessage",
                "-d", f"chat_id={chat_id}",
                "-d", f"text={text}",
                "-d", "parse_mode=HTML"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        ok = (r.stdout or "").strip() == "200"
        _tw_log(f"TG[{event}] curl-fallback: {'OK' if ok else 'FAIL'}")
        return ok
    except Exception:
        return False


# ── Core: одна итерация наблюдения ────────────────────────────────────────────


def _tw_access_lines(max_lines: int = 20000) -> list:
    """Хвост access.log (последние max_lines строк) для per-user-разбора."""
    try:
        if not ACCESS_LOG.exists():
            return []
        return ACCESS_LOG.read_text(errors="replace").splitlines()[-max_lines:]
    except Exception:
        return []


def _tw_smart_balancer_line(names: dict, keys: dict) -> str:
    """Строка про SmartBalancer для дайджеста: активная нода, если SB
    включён и патчит ротацию (иначе пусто — ротацией владеет нативный
    chain-balancer, см. exit_switch_watcher)."""
    sb = _read_json(SB_STATE_FILE)
    if not sb.get("enabled"):
        return ""
    idx = sb.get("active_node_idx")
    if not isinstance(idx, int) or isinstance(idx, bool) or idx < 0:
        return ""
    tag = f"chain-exit-{idx + 1}"
    if tag not in names:
        return ""
    return (f"SmartBalancer: активная нода <code>{names[tag]}</code>"
            f" (наблюдает/патчит selector)")


def run_once(force: bool = False) -> dict:
    """Одна итерация наблюдения (вызывается из cron / меню).
    force=True — проигнорировать enabled и quiet-часы (ручной запуск).
    Возвращает {'acc', 'dominant', 'events': [отправленные],
    'stats_ok': bool}."""
    cfg = load_cfg()
    if not cfg.get("enabled", True) and not force:
        _tw_log("SKIP: наблюдатель выключен (enabled=false)")
        return {"acc": {}, "dominant": None, "events": [], "stats_ok": True}

    prev = _read_json(TW_CFG_FILE).get("__state__") or {}

    st = _load_state()
    chain_nodes = st.get("chain_nodes") or []
    if not chain_nodes:
        _tw_log("SKIP: exit-ноды не настроены (Режим B не развёрнут)")
        return {"acc": {}, "dominant": None, "events": [], "stats_ok": True}

    aliases = cfg.get("aliases") or {}
    names, keys = _tw_tag_names(chain_nodes, aliases)

    now = time.time()
    now_hhmm = time.strftime("%H:%M")
    quiet = _tw_quiet(now_hhmm, cfg.get("quiet_hours") or {})
    events_sent: list[str] = []

    def _emit(event: str, detail: str) -> None:
        """Отправка с учётом анти-спама (min_gap) и quiet-часов."""
        if not force and quiet:
            _tw_log(f"SKIP[{event}]: тихие часы")
            return
        if not force and not _tw_gap_ok(
                ((prev.get("last_notify") or {}).get(event)) or 0,
                now, cfg.get("min_gap_min")):
            _tw_log(f"SKIP[{event}]: анти-спам min_gap")
            return
        if _tw_notify_event(event, detail, cfg):
            events_sent.append(event)
            prev.setdefault("last_notify", {})[event] = now

    # ── Источник данных: Stats API ──
    stats = _tw_query_stats()
    if stats is None:
        fails = int(prev.get("stats_fails") or 0) + 1
        last_err = float(prev.get("last_stats_error_ts") or 0)
        if fails >= STATS_FAIL_THRESHOLD \
                and (now - last_err) >= STATS_ERROR_RETRY_SEC:
            _emit("traffic_stats_error",
                  "xray api statsquery недоступен "
                  f"({STATS_FAIL_THRESHOLD} прогона подряд). Проверьте: "
                  "xray запущен; в config.json есть секции stats/api "
                  "(пересборка конфига ставит их автоматически).")
            prev["last_stats_error_ts"] = now
        prev["stats_fails"] = fails
        _tw_save_state(prev)
        _tw_log(f"WARN: Stats API недоступен (fails={fails})")
        return {"acc": prev.get("acc") or {}, "dominant": None,
                "events": events_sent, "stats_ok": False}

    # Счётчики цепочки (служебные теги — мимо)
    stats_chain = {t: v for t, v in stats.items() if t in names}

    # ── Дельты за окно прогона + накопитель окна дайджеста ──
    deltas = _tw_deltas(prev.get("counters") or {}, stats_chain)
    acc = _tw_acc_add(prev.get("acc") or {}, deltas)

    # 1) Смена доминирующей ноды (пороги: доля %, мин. объём окна)
    try:
        dom_share = float(cfg.get("dominant_min_share_pct") or 60)
    except (TypeError, ValueError):
        dom_share = 60.0
    try:
        dom_min_b = float(cfg.get("dominant_min_mb") or 50) * MB
    except (TypeError, ValueError):
        dom_min_b = 50 * MB

    dominant = _tw_dominant(acc, dom_share, dom_min_b)
    prev_dom = prev.get("dominant_tag") or ""
    if dominant and prev_dom and dominant["tag"] != prev_dom:
        old_name = names.get(prev_dom) or prev_dom
        new_name = names.get(dominant["tag"]) or dominant["tag"]
        _emit("traffic_dominant_change",
              f"Трафик окна переехал: <code>{old_name}</code> → "
              f"<b><code>{new_name}</code></b> "
              f"({dominant['share']:.0f}% окна, "
              f"{_tw_fmt_bytes(dominant['bytes'])} из "
              f"{_tw_fmt_bytes(dominant['total'])})")
    if dominant:
        prev["dominant_tag"] = dominant["tag"]

    # 2) Starve-детект: нода в selector без трафика при живом окне
    try:
        starve_h = float(cfg.get("starve_hours") or 0)
    except (TypeError, ValueError):
        starve_h = 0.0
    if starve_h > 0:
        try:
            starve_min_b = float(cfg.get("starve_min_total_mb") or 50) * MB
        except (TypeError, ValueError):
            starve_min_b = 50 * MB
        live = _tw_live_balancer()
        selector = [t for t in (live.get("selector") or []) if t in names]
        zs, starved = _tw_starve_update(
            prev.get("zero_since") or {}, deltas, selector,
            now, starve_h * 3600.0, starve_min_b)
        prev["zero_since"] = zs
        for tag in starved:
            nm = names.get(tag) or tag
            _emit("traffic_node_starved",
                  f"Нода <code>{nm}</code> в selector балансировщика "
                  f"без трафика {starve_h:.0f} ч, при этом через другие "
                  f"ноды прошло {_tw_fmt_bytes(_tw_total(deltas))} за "
                  f"последнее окно — возможно, балансировщик её скипает")

    # 3) Периодический дайджест (только при базовой линии счётчиков:
    # первый прогон лишь фиксирует базу — пустой дайджест не шлём)
    snap_h = cfg.get("snapshot_hours") or 0
    try:
        snap_h = float(snap_h)
    except (TypeError, ValueError):
        snap_h = 0
    if snap_h > 0 and prev.get("counters") is not None:
        last_snap = float(prev.get("last_snapshot_ts") or 0)
        if now - last_snap >= snap_h * 3600 or (force and not last_snap):
            window_str = ""
            if last_snap:
                window_str = (time.strftime("%d.%m %H:%M",
                                            time.localtime(last_snap))
                              + " → " + time.strftime("%d.%m %H:%M"))
            per_user_rows: list = []
            if cfg.get("per_user"):
                lines = _tw_access_lines()
                counts = _tw_parse_access_users(lines, set(names))
                per_user_rows = _tw_per_user_rows(
                    counts, names, cfg.get("per_user_top") or 5)
            live = _tw_live_balancer()
            strategy = live.get("strategy") or ""
            sb_line = _tw_smart_balancer_line(names, keys)
            text = _tw_snapshot_text(
                acc, names, strategy, window_str, per_user_rows,
                bool(cfg.get("include_percent", True)),
                bool(cfg.get("include_bytes", True)))
            if sb_line:
                text += "\n" + sb_line
            _emit("traffic_snapshot", text)
            # окно дайджеста закрыто: накопитель и доминирование сброшены
            acc = {}
            prev["last_snapshot_ts"] = now
            prev["dominant_tag"] = ""

    # ── Сохраняем состояние (внутрь конфиг-файла, ключ __state__ —
    # эксплуатационные данные рядом с настройками, атомарно одним файлом)
    prev["counters"] = stats_chain
    prev["acc"] = acc
    prev["stats_fails"] = 0
    prev["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    _tw_save_state(prev)

    return {"acc": acc, "dominant": dominant, "events": events_sent,
            "stats_ok": True}


def _tw_save_state(state: dict) -> None:
    """Атомарное сохранение __state__ в конфиг-файл (паттерн
    exit_switch_watcher: настройки + состояние одним файлом)."""
    stored = _read_json(TW_CFG_FILE)
    # не протекаем в сохраняемые настройки
    clean = {k: v for k, v in (state or {}).items() if k != "__state__"}
    stored["__state__"] = clean
    try:
        TW_CFG_FILE.parent.mkdir(parents=True, exist_ok=True)
        TW_CFG_FILE.write_text(
            json.dumps(stored, indent=2, ensure_ascii=False),
            encoding="utf-8")
        TW_CFG_FILE.chmod(0o600)
    except Exception as e:
        _tw_log(f"WARN: не удалось сохранить состояние: {e}")


# ── Cron-установка ────────────────────────────────────────────────────────────


def is_installed() -> bool:
    return CRON_FILE.exists() and CRON_SCRIPT.exists()


def _installed_interval() -> int:
    try:
        if CRON_FILE.exists():
            for line in CRON_FILE.read_text().splitlines():
                if line.startswith("*/"):
                    return int(line.split()[0].replace("*/", ""))
    except Exception:
        pass
    return DEFAULT_INTERVAL


def _find_python() -> str:
    for p in ("/usr/bin/python3", "/usr/local/bin/python3", "python3"):
        if Path(p).exists():
            return p
    return "python3"


def _installer_path() -> str:
    """Каталог установки chimera (паттерн exit_switch_watcher:
    find_spec + фолбэк /opt/chimera)."""
    import importlib.util
    try:
        spec = importlib.util.find_spec("chimera")
    except (ValueError, ModuleNotFoundError):
        spec = None
    if spec and spec.submodule_search_locations:
        return str(Path(list(spec.submodule_search_locations)[0]).parent)
    return "/opt/chimera"


def install_watcher(interval_min: int = DEFAULT_INTERVAL) -> tuple:
    """Устанавливает cron-задачу наблюдателя (1-60 мин)."""
    try:
        interval_min = max(1, min(60, int(interval_min)))
        installer = _installer_path()
        python = _find_python()
        script = (
            "#!/bin/bash\n"
            "# xray-exit-traffic-watcher.sh — наблюдатель трафика exit-нод\n"
            "# Установлен Chimera Project (exit_traffic_watcher)\n"
            f"export PYTHONPATH=\"{installer}:$PYTHONPATH\"\n"
            f"{python} -c \"\n"
            "import sys\n"
            f"sys.path.insert(0, '{installer}')\n"
            "from chimera.modules.exit_traffic_watcher import run_once\n"
            "run_once()\n"
            "\" 2>>/var/log/xray-exit-traffic-watcher.log\n"
        )
        CRON_SCRIPT.write_text(script, encoding="utf-8")
        CRON_SCRIPT.chmod(0o750)
        CRON_FILE.write_text(
            f"# xray-exit-traffic-watcher — распределение трафика по "
            f"exit-нодам каждые {interval_min} мин\n"
            f"*/{interval_min} * * * * root {CRON_SCRIPT} "
            f">>/var/log/xray-exit-traffic-watcher.log 2>&1\n",
            encoding="utf-8")
        CRON_FILE.chmod(0o644)
        return True, f"Наблюдатель установлен (интервал: {interval_min} мин)"
    except Exception as e:
        return False, f"Ошибка установки: {e}"


def uninstall_watcher() -> tuple:
    """Удаляет cron-задачу (конфиг и накопленное состояние остаются)."""
    try:
        CRON_FILE.unlink(missing_ok=True)
        CRON_SCRIPT.unlink(missing_ok=True)
        return True, "Наблюдатель удалён (cron выключен)"
    except Exception as e:
        return False, f"Ошибка удаления: {e}"


# ── Интерактивное меню ────────────────────────────────────────────────────────


def _tw_menu_status_block() -> tuple:
    """(данные для меню) — cron/интервал/стратегия/текущее
    распределение поверх последнего накопителя + доминирующая нода."""
    cfg = load_cfg()
    installed = is_installed()
    interval = _installed_interval() if installed \
        else cfg.get("interval_min", DEFAULT_INTERVAL)
    st = _load_state()
    chain_nodes = st.get("chain_nodes") or []
    names, keys = _tw_tag_names(chain_nodes, cfg.get("aliases") or {})
    live = _tw_live_balancer()
    stats = _tw_query_stats()
    state = _read_json(TW_CFG_FILE).get("__state__") or {}
    acc = state.get("acc") or {}
    # если Stats API жив, но накопитель пуст (первый прогон) — покажем
    # мгновенные счётчики как справку «сколько всего прошло через ноды»
    rows = _tw_distribution_rows(
        acc if acc else {t: v for t, v in (stats or {}).items() if t in names},
        names, True, True) if names else []
    dom_tag = state.get("dominant_tag") or ""
    dominant_name = names.get(dom_tag) or dom_tag if dom_tag else ""
    return cfg, installed, interval, names, live, stats, rows, dominant_name


def do_traffic_watcher_menu() -> None:
    """Интерактивное меню наблюдателя (TUI)."""
    from chimera.modules.box_renderer import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_item, _box_back,
        _box_ok, _box_warn,
    )
    C = _colors()

    while True:
        os.system("clear")
        (cfg, installed, interval, names, live, stats, rows,
         dominant_name) = _tw_menu_status_block()
        status = f"{C['GREEN']}активен{C['NC']}" if installed \
            else f"{C['YELLOW']}не активен{C['NC']}"
        if not cfg.get("enabled", True):
            status += f" {C['RED']}(выключен в настройках){C['NC']}"
        api_ok = stats is not None
        api_cfg = _tw_stats_api_enabled()
        if api_ok:
            api_str = f"{C['GREEN']}OK{C['NC']}"
        elif api_cfg:
            api_str = f"{C['RED']}недоступен (xray упал?){C['NC']}"
        else:
            api_str = f"{C['RED']}нет в конфиге (пересоберите конфиг){C['NC']}"
        strategy = live.get("strategy") or "нет"

        print()
        _box_top("🧭  НАБЛЮДАТЕЛЬ ТРАФИКА EXIT-НОД")
        _box_row("  Уведомления о том, ЧЕРЕЗ КАКУЮ ноду реально идёт трафик.")
        _box_row("  Источник — счётчики Stats API (outbound>>>chain-exit-N):")
        _box_row("  работает во ВСЕХ режимах — roundRobin / leastPing /")
        _box_row("  leastLoad / random / smartBalancer / pinned.")
        _box_sep()
        _box_row(f"  Статус:     {status}")
        if installed:
            _box_row(f"  Интервал:   {C['BOLD']}{interval} мин{C['NC']}")
        _box_row(f"  Стратегия:  {strategy}")
        _box_row(f"  Stats API:  {api_str}")
        dom_str = (f"   (доминирует: {C['BOLD']}{dominant_name}{C['NC']})"
                   if dominant_name else "")
        _box_row(f"  Нод:        {C['BOLD']}{len(names)}{C['NC']}{dom_str}")
        _box_sep()
        if rows:
            _box_row(f"  {C['DIM']}Трафик по нодам "
                     f"(окно дайджеста / всего):{C['NC']}")
            for r in rows[:10]:
                _box_row(f"  {r}")
        elif names:
            _box_row(f"  {C['DIM']}Трафика через exit-ноды пока не было "
                     f"(или первый прогон){C['NC']}")
        else:
            _box_row(f"  {C['DIM']}Exit-ноды не настроены (только Режим B)"
                     f"{C['NC']}")
        _box_sep()
        nf = cfg.get("notify") or {}
        _box_row(f"  События: доминирование="
                 f"{'вкл' if nf.get('traffic_dominant_change', True) else 'выкл'}"
                 f"  дайджест="
                 f"{'вкл' if nf.get('traffic_snapshot', True) else 'выкл'}"
                 f"  голод ноды="
                 f"{'вкл' if nf.get('traffic_node_starved', True) else 'выкл'}"
                 f"  ошибка API="
                 f"{'вкл' if nf.get('traffic_stats_error', True) else 'выкл'}")
        qh = cfg.get("quiet_hours") or {}
        qh_str = f"{qh.get('from', '')}–{qh.get('to', '')}" \
            if qh.get("from") else "нет"
        _box_row(f"  Тихие часы: {qh_str}   мин.пауза: {cfg.get('min_gap_min')} мин"
                 f"   дайджест: раз в {cfg.get('snapshot_hours') or 0} ч")
        _box_row(f"  Доминирование: доля ≥ {cfg.get('dominant_min_share_pct')}%"
                 f" от {cfg.get('dominant_min_mb')} МБ"
                 f"   голод ноды: {cfg.get('starve_hours') or 0} ч"
                 f"   per-user: {'вкл' if cfg.get('per_user') else 'выкл'}")
        _box_sep()
        _box_item("C", "Проверить сейчас (без ожидания cron)")
        _box_item("T", "Тест-уведомление (все типы событий)")
        _box_item("S", "Настройки уведомлений (события / паузы / тихие часы)")
        _box_item("D", "Пороги детекции (доминирование / голод ноды)")
        _box_item("A", "Алиасы нод (имена в уведах) + пользователи")
        _box_item("M", "Шаблоны сообщений (кастомизация)")
        if not installed:
            _box_item("I", f"Установить cron (интервал {DEFAULT_INTERVAL} мин)")
            _box_item("I5",  "Установить - каждые 5 мин")
            _box_item("I10", "Установить - каждые 10 мин")
            _box_item("I30", "Установить - каждые 30 мин")
        else:
            _box_item("U", "Удалить cron")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{C['CYAN']}Выбор: {C['NC']}").strip().upper()
        except KeyboardInterrupt:
            return

        if ch in ("0", "Q", ""):
            return

        elif ch == "C":
            print(f"  {C['DIM']}Опрашиваю Stats API и считаю дельты...{C['NC']}")
            res = run_once(force=True)
            if res.get("events"):
                for ev in res["events"]:
                    _box_ok(f"Отправлено: {ev}")
            if not res.get("stats_ok"):
                _box_warn("Stats API недоступен — событие traffic_stats_error "
                          "уйдёт после 3-го неудачного прогона подряд")
            elif not res.get("events"):
                _box_ok("Изменений нет (счётчики и накопитель обновлены)")
            input(f"{C['CYAN']}Нажмите Enter...{C['NC']}")

        elif ch == "T":
            for ev, txt in (
                ("traffic_dominant_change",
                 "тест: трафик переехал node-a → node-b (70% окна)"),
                ("traffic_snapshot", "тест: дайджест распределения трафика"),
                ("traffic_node_starved", "тест: нода без трафика 6 ч"),
                ("traffic_stats_error", "тест: Stats API недоступен"),
            ):
                ok = _tw_notify_event(ev, f"🔔 Тест наблюдателя: {txt}", cfg)
                print(f"  {'✅' if ok else '⚠️'} {ev}")
            input(f"{C['CYAN']}Нажмите Enter...{C['NC']}")

        elif ch == "S":
            _menu_settings(cfg)
            save_cfg(cfg)

        elif ch == "D":
            _menu_thresholds(cfg)
            save_cfg(cfg)

        elif ch == "A":
            _menu_aliases(cfg)
            save_cfg(cfg)

        elif ch == "M":
            _menu_templates(cfg)
            save_cfg(cfg)

        elif ch in ("I", "I5"):
            ok, msg = install_watcher(5 if ch == "I5" else DEFAULT_INTERVAL)
            _box_ok(msg) if ok else _box_warn(msg)
            input(f"{C['CYAN']}Нажмите Enter...{C['NC']}")

        elif ch == "I10":
            ok, msg = install_watcher(10)
            _box_ok(msg) if ok else _box_warn(msg)
            input(f"{C['CYAN']}Нажмите Enter...{C['NC']}")

        elif ch == "I30":
            ok, msg = install_watcher(30)
            _box_ok(msg) if ok else _box_warn(msg)
            input(f"{C['CYAN']}Нажмите Enter...{C['NC']}")

        elif ch == "U" and installed:
            ok, msg = uninstall_watcher()
            _box_ok(msg) if ok else _box_warn(msg)
            input(f"{C['CYAN']}Нажмите Enter...{C['NC']}")


def _menu_settings(cfg: dict) -> None:
    """Настройки уведомлений: вкл/выкл типов, анти-спам, тихие часы,
    интервал дайджеста, отдельный chat_id, вкл/выкл наблюдателя."""
    from chimera.modules.box_renderer import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_back,
        _box_ok, _box_warn)
    C = _colors()
    labels = {
        "traffic_dominant_change": "Смена доминирующей ноды (трафик переехал)",
        "traffic_snapshot":        "Дайджест распределения трафика",
        "traffic_node_starved":    "Нода в ротации без трафика (голод)",
        "traffic_stats_error":     "Stats API недоступен",
    }
    while True:
        os.system("clear")
        nf = cfg.setdefault("notify", {})
        qh = cfg.setdefault("quiet_hours", {"from": "", "to": ""})
        print()
        _box_top("⚙️  НАСТРОЙКИ УВЕДОМЛЕНИЙ НАБЛЮДАТЕЛЯ ТРАФИКА")
        for i, ev in enumerate(EVENTS, 1):
            on = nf.get(ev, True)
            _box_row(f"  {C['GREEN'] if on else C['DIM']}"
                     f"{'[ВКЛ]' if on else '[ВЫКЛ]'}{C['NC']} {i}. {labels[ev]}")
        _box_sep()
        _box_row(f"  5. Анти-спам: мин. пауза между уведами — "
                 f"{C['BOLD']}{cfg.get('min_gap_min', 10)} мин{C['NC']}")
        _box_row(f"  6. Тихие часы: {qh.get('from') or '—'} … {qh.get('to') or '—'} "
                 f"{C['DIM']}(пусто = выкл){C['NC']}")
        _box_row(f"  7. Дайджест: раз в {C['BOLD']}{cfg.get('snapshot_hours', 0) or 0}"
                 f" ч{C['NC']} {C['DIM']}(0 = выкл){C['NC']}")
        _box_row(f"  8. Chat ID override: {cfg.get('chat_id_override') or 'основной'}")
        _box_row(f"  9. Наблюдатель: "
                 f"{'включён' if cfg.get('enabled', True) else 'выключен'}")
        _box_row(f"  10. Дайджест: проценты="
                 f"{'да' if cfg.get('include_percent', True) else 'нет'}"
                 f"  байты={'да' if cfg.get('include_bytes', True) else 'нет'}")
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{C['CYAN']}Выбор: {C['NC']}").strip()
        except KeyboardInterrupt:
            return
        if ch in ("0", "Q", ""):
            return
        if ch.isdigit() and 1 <= int(ch) <= 4:
            ev = EVENTS[int(ch) - 1]
            nf[ev] = not nf.get(ev, True)
        elif ch == "5":
            raw = input("  Мин. пауза, мин (Enter = без изменений): ").strip()
            if raw.isdigit():
                cfg["min_gap_min"] = int(raw)
        elif ch == "6":
            f = input("  Тихие часы — от (ЧЧ:ММ, Enter = выкл): ").strip()
            t = input("  Тихие часы — до (ЧЧ:ММ): ").strip()
            qh["from"], qh["to"] = (f if f else ""), (t if f else "")
        elif ch == "7":
            raw = input("  Интервал дайджеста, часов (0 = выкл): ").strip()
            if raw.isdigit():
                cfg["snapshot_hours"] = int(raw)
        elif ch == "8":
            raw = input("  Chat ID для уведов наблюдателя (Enter = основной): ").strip()
            cfg["chat_id_override"] = raw
        elif ch == "9":
            cfg["enabled"] = not cfg.get("enabled", True)
            _box_ok("Наблюдатель " + ("включён" if cfg["enabled"] else "выключен"))
            input(f"{C['CYAN']}Нажмите Enter...{C['NC']}")
        elif ch == "10":
            cfg["include_percent"] = not cfg.get("include_percent", True)
            cfg["include_bytes"] = not cfg.get("include_bytes", True)
            _box_ok(f"Дайджест: проценты="
                    f"{'да' if cfg['include_percent'] else 'нет'}, "
                    f"байты={'да' if cfg['include_bytes'] else 'нет'}")
            input(f"{C['CYAN']}Нажмите Enter...{C['NC']}")


def _menu_thresholds(cfg: dict) -> None:
    """Пороги детекции: доминирование (доля %, мин. объём окна),
    голод ноды (часы, мин. трафик окна)."""
    from chimera.modules.box_renderer import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_back, _box_ok)
    C = _colors()
    while True:
        os.system("clear")
        print()
        _box_top("🎚️  ПОРОГИ ДЕТЕКЦИИ")
        _box_row(f"  {C['DIM']}«Доминирующая» нода — её доля в трафике окна")
        _box_row(f"  {C['DIM']}дайджеста ≥ порога доли, объём окна ≥ порога объёма.")
        _box_row(f"  {C['DIM']}Равномерный roundRobin не порождает доминирования —")
        _box_row(f"  {C['DIM']}это корректно: увед приходит, когда трафик реально")
        _box_row(f"  {C['DIM']}сконцентрировался на одной ноде.{C['NC']}")
        _box_sep()
        _box_row(f"  1. Доля доминирования: {C['BOLD']}"
                 f"{cfg.get('dominant_min_share_pct', 60)}%{C['NC']} "
                 f"{C['DIM']}(50–100; 100 = только полная монополия){C['NC']}")
        _box_row(f"  2. Мин. объём окна: {C['BOLD']}"
                 f"{cfg.get('dominant_min_mb', 50)} МБ{C['NC']} "
                 f"{C['DIM']}(анти-шум на пустых окнах){C['NC']}")
        _box_row(f"  3. Голод ноды: {C['BOLD']}{cfg.get('starve_hours', 0) or 0} ч"
                 f"{C['NC']} {C['DIM']}(0 = выкл; нода в selector без трафика){C['NC']}")
        _box_row(f"  4. Мин. трафик окна для голода: {C['BOLD']}"
                 f"{cfg.get('starve_min_total_mb', 50)} МБ{C['NC']}")
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{C['CYAN']}Выбор: {C['NC']}").strip()
        except KeyboardInterrupt:
            return
        if ch in ("0", "Q", ""):
            return
        if ch == "1":
            raw = input("  Доля, % (50-100): ").strip()
            if raw.isdigit() and 50 <= int(raw) <= 100:
                cfg["dominant_min_share_pct"] = int(raw)
        elif ch == "2":
            raw = input("  Мин. объём окна, МБ (1-100000): ").strip()
            if raw.isdigit() and 1 <= int(raw) <= 100000:
                cfg["dominant_min_mb"] = int(raw)
        elif ch == "3":
            raw = input("  Голод ноды, часов (0 = выкл, 1-168): ").strip()
            if raw.isdigit() and 0 <= int(raw) <= 168:
                cfg["starve_hours"] = int(raw)
        elif ch == "4":
            raw = input("  Мин. трафик окна для голода, МБ (1-100000): ").strip()
            if raw.isdigit() and 1 <= int(raw) <= 100000:
                cfg["starve_min_total_mb"] = int(raw)


def _menu_aliases(cfg: dict) -> None:
    """Алиасы нод (host:port → имя в уведах) + per-user разбор."""
    from chimera.modules.box_renderer import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_back, _box_ok)
    C = _colors()
    while True:
        os.system("clear")
        st = _load_state()
        chain_nodes = st.get("chain_nodes") or []
        aliases = cfg.setdefault("aliases", {})
        print()
        _box_top("🏷️  АЛИАСЫ НОД И ПОЛЬЗОВАТЕЛИ")
        _box_row(f"  {C['DIM']}Алиас подставляется в уведы вместо host:port —")
        _box_row(f"  {C['DIM']}например «RU1», «дом-кино», «pl-fast».{C['NC']}")
        _box_sep()
        if chain_nodes:
            for i, nd in enumerate(chain_nodes, 1):
                host = str((nd or {}).get("host") or "").strip()
                port = int((nd or {}).get("port") or 443)
                if not host:
                    continue
                key = f"{host}:{port}"
                alias = aliases.get(key) or ""
                shown = f"{C['GREEN']}{alias}{C['NC']}" if alias \
                    else f"{C['DIM']}—{C['NC']}"
                _box_row(f"  {i}. <code>{key}</code> → {shown}")
        else:
            _box_row(f"  {C['DIM']}Exit-ноды не настроены (Режим B){C['NC']}")
        _box_sep()
        _box_row(f"  U. Разбор по пользователям (кто через какую ноду): "
                 f"{'вкл' if cfg.get('per_user') else 'выкл'}")
        _box_row(f"  N. Топ пользователей в дайджесте: "
                 f"{cfg.get('per_user_top', 5)}")
        _box_row(f"  {C['DIM']}Требует loglevel=info (access.log){C['NC']}")
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{C['CYAN']}Выбор (номер ноды / U / N): {C['NC']}").strip()
        except KeyboardInterrupt:
            return
        if ch in ("0", "Q", ""):
            return
        if ch.upper() == "U":
            cfg["per_user"] = not cfg.get("per_user", False)
        elif ch.upper() == "N":
            raw = input("  Топ-N пользователей (1-20): ").strip()
            if raw.isdigit() and 1 <= int(raw) <= 20:
                cfg["per_user_top"] = int(raw)
        elif ch.isdigit() and 1 <= int(ch) <= len(chain_nodes):
            nd = chain_nodes[int(ch) - 1]
            key = f"{nd.get('host')}:{nd.get('port') or 443}"
            cur = aliases.get(key) or ""
            print(f"  Текущий алиас: {cur or '—'}")
            raw = input("  Новый алиас (Enter = убрать): ").strip()
            if raw:
                aliases[key] = raw
                _box_ok(f"Алиас: {key} → {raw}")
            else:
                aliases.pop(key, None)
                _box_ok(f"Алиас снят: {key}")
            input(f"{C['CYAN']}Нажмите Enter...{C['NC']}")


def _menu_templates(cfg: dict) -> None:
    """Редактирование шаблонов сообщений (плейсхолдеры {host} {ts} {detail})."""
    from chimera.modules.box_renderer import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_back, _box_ok)
    C = _colors()
    tpl = cfg.setdefault("templates", dict(DEFAULT_TEMPLATES))
    while True:
        os.system("clear")
        print()
        _box_top("📝  ШАБЛОНЫ СООБЩЕНИЙ (HTML)")
        _box_row(f"  {C['DIM']}Плейсхолдеры: {{host}} {{ts}} {{detail}}{C['NC']}")
        _box_sep()
        for i, ev in enumerate(EVENTS, 1):
            _box_row(f"  {i}. {ev}")
            _box_row(f"     {C['DIM']}{str(tpl.get(ev))[:52]}{C['NC']}")
        _box_row("  R. Сбросить все к дефолтным")
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{C['CYAN']}Выбор: {C['NC']}").strip()
        except KeyboardInterrupt:
            return
        if ch in ("0", "Q", ""):
            return
        if ch.upper() == "R":
            tpl.clear()
            tpl.update(dict(DEFAULT_TEMPLATES))
            _box_ok("Шаблоны сброшены")
        elif ch.isdigit() and 1 <= int(ch) <= len(EVENTS):
            ev = EVENTS[int(ch) - 1]
            print(f"  Текущий: {tpl.get(ev)}")
            raw = input("  Новый шаблон (Enter = оставить): ").strip()
            if raw:
                tpl[ev] = raw
                _box_ok("Шаблон обновлён")
