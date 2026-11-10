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

Мультитранспортность (11.11.2026, продолжение трилогии): наблюдатель
охватывает не только VLESS-каскад (chain-exit-N через Stats API), но и
ОСТАЛЬНЫЕ каскады Chimera — источник счётчиков у каждого свой, события
и машина состояний общие:

  • VLESS-каскад (Режим B)      — Xray Stats API (как выше);
  • AWG-каскад (awg_cascade_lb) — слоты awg1..awgN ↔ exit-ноды; байты
        per-exit = счётчики интерфейсов `ip -s link show awgN` (RX+TX
        туннеля = весь трафик через exit; рестарт туннеля сбрасывает —
        дельта-логика «cur < prev → cur» уже покрывает). Состав/веса/
        health — awg_standalone_state.json (lb.slots_snapshot,
        lb.balance.shares, lb.probes от failover-тика раз в минуту);
  • Mieru-каскад (mieru_cascade) — байты per-exit двумя путями:
        a) IPAccounting systemd-юнитов mieru-hop@exit-* (точные
           IP-байты cgroup; включается из меню наблюдателя, по умолчанию
           выключено — изменение юнитов только явным действием);
        b) счётчики правил `iptables -t nat -L OUTPUT -v -x` (REDIRECT
           --to-ports 2308N): nat-таблица обходит правила только для
           НОВЫХ соединений — это честная метрика РАСПРЕДЕЛЕНИЯ по
           соединениям (балансировка и происходит на соединения), но
           не байты: дайджест/доминирование формулируются в
           «соединениях», starve-детект для неё недоступен.
        Выбор — cascades.mieru.bytes_source: auto|ipaccounting|conn.
  • Naive-каскад (naiveproxy)   — upstream ОДИН (Entry→Exit), счётчиков
        по нодам нет по построению; покрытие — минимальный
        upstream-watcher: TCP-проба host:port из upstream-URL
        (naiveproxy.json) + события naive_upstream_down /
        naive_upstream_up (машина состояний на probe_fails прогонов).

Осознанно вне скоупа: Hysteria2/AWG-транспорт-выходы (Режим B с одним
туннель-транспортом — один outbound-тег в config.json): «распределения
по нодам» там физически нет (одна труба; активную ноду выбирает
hysteria2_balancer/awg-transport watchdog, смена ноды уже алертится
ими: awg_failover / H2-балансировщик; per-node байты для H2 собирает
hysteria2_traffic в state.metrics). Дублировать их алерты — спам.

События (ключи фильтра в telegram.json, иконки в tg_bot.tg_notify_event):
  • traffic_dominant_change — доминирующая нода (по объёму за окно
    накопления) сменилась; заголовок человекочитаемый — «Режим:
    активная нода X. Переключение ноды: Y → X» (откуда/куда —
    полностью); пороги настраиваются (доля %, мин. объём);
  • traffic_snapshot        — периодический дайджест: распределение
    трафика по нодам (байты + %), стратегия, опционально разбор
    по пользователям (кто через какую ноду — из access.log);
  • traffic_node_starved    — нода в selector балансировщика не несёт
    трафик N часов, пока другие несут (roundRobin/leastPing может
    скипать ноду — сигнал, что что-то не так);
  • traffic_stats_error     — Stats API недоступен 3 прогона подряд
    (не чаще раза в сутки): xray упал или конфиг без секции api;
  • traffic_node_down       — 📴 активная TCP-проба ноды не проходит
    N прогонов подряд — нода недоступна (упала/порт закрыт);
    контекст: когда нода последний раз несла трафик + вердикт
    Health Monitor, если он это уже заметил;
  • traffic_node_degraded   — 🐌 проба проходит, но RTT выше порога
    M прогонов подряд — нода «тупит» (лагает, но жива);
  • traffic_node_up         — 🔌 восстановление: проба снова ОК
    после недоступности/деградации;
  • naive_upstream_down     — 📴 Naive-каскад: TCP-проба upstream
    (host:port из naiveproxy.json) не проходит N прогонов подряд —
    весь каскад Entry→Exit без выхода;
  • naive_upstream_up       — 🔌 восстановление upstream.

Активные пробы: помимо пассивных счётчиков трафика, модуль сам
TCP-пробует host:port КАЖДОЙ chain-ноды каждый прогон (stdlib socket,
create_connection + time.monotonic; таймаут и пороги в cfg). Отказ
ноды больше не «невидим» даже при молчащем/перераспределившемся
трафике. Guard локальной проблемы: если ВСЕ ноды разом не отвечают —
вероятна проблема на самом релее (сеть/DNS/исходящий трафик):
персональные уведы подавляются, шлётся один «локальный»
traffic_node_down и один traffic_node_up при восстановлении связи.
Пробы покрывают ВСЕ chain-ноды (не только selector — в отличие от
starve-детекта). Для Mieru-каскада пробы TCP host:port exit-нод
(mita-порт) включаются отдельно (cascades.mieru.probe; по умолчанию
выключено — health уже алертит mieru_cascade_monitor: mieru_exit_*).
Для AWG-каскада «пробы» — не TCP (порт UDP): watcher транслирует
переходы alive из lb.probes failover-тика в те же события проб
(cascades.awg.probe; по умолчанию выключено — failover уже шлёт
awg_failover). Naive upstream пробуется всегда, когда каскад
развёрнут (cascades.naive.probe).

Отправка идёт через tg_bot.tg_notify_event() — событие уважает фильтр
из меню «Telegram-уведомления» (пункт «Включить/выключить отдельные
события») и ключ proxy в telegram.json. Fallback — прямая отправка
curl-ом (паттерн exit_switch_watcher / node_health_monitor).

Кастомизация — /var/lib/xray-installer/exit_traffic_watcher.json
(см. DEFAULTS): интервал cron, вкл/выкл каждого типа событий, пороги
доминирования (доля %, мин. объём), quiet-часы, анти-спам min_gap,
шаблоны сообщений с плейсхолдерами, отдельный chat_id, алиасы нод
(host:port → человекочитаемое имя в уведах), разбор по пользователям
(per_user, топ-N), пороги starve-детекта, пороги активных проб
(таймаут, неудач подряд, порог RTT деградации) и ПОКРЫТИЕ КАСКАДОВ
(cascades): для каждого — вкл/выкл пассивного трафика и проб; для
Mieru — источник байтов (IPAccounting против соединений) и включение
IPAccounting на юнитах mieru-hop@* (явное действие из меню).

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
import socket
import subprocess
import time
import urllib.parse
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

# Вердикты Health Monitor (node_health_monitor.py) — обогащение
# down-уведы проб (ключ host:port → {'up': bool}); паттерн exit_switch_watcher
HM_STATE_FILE = Path("/var/lib/xray-installer/node-health-state.json")

# State-файлы остальных каскадов (мультитранспортность 11.11.2026):
#   awg_standalone_state.json — пишет awg_cascade/awg_cascade_lb (слоты,
#       веса, health-тик lb.probes раз в минуту);
#   mieru_cascade.json — пишет health-тик mieru_cascade (exits, healthy,
#       redsocks_port для матчинга iptables-счётчиков);
#   naiveproxy.json — naiveproxy (upstream URL Entry→Exit).
AWG_STATE_FILE   = Path("/var/lib/xray-installer/awg_standalone_state.json")
MIERU_STATE_FILE = Path("/var/lib/xray-installer/mieru_cascade.json")
NAIVE_STATE_FILE = Path("/var/lib/xray-installer/naiveproxy.json")

# Префиксы тегов нод в общих счётчиках/накопителе (vless-теги —
# прежние chain-exit-N без префикса: обратная совместимость state)
TAG_PREFIX_AWG   = "awg:"
TAG_PREFIX_MIERU = "mieru:"
TAG_PREFIX_NAIVE = "naive:"
CASCADE_KINDS    = ("vless", "awg", "mieru", "naive")

DEFAULT_INTERVAL    = 15   # минут
DEFAULT_SNAPSHOT_HOURS = 12
STATS_FAIL_THRESHOLD = 3    # прогонов подряд перед traffic_stats_error
STATS_ERROR_RETRY_SEC = 86400  # не чаще раза в сутки

# События наблюдателя (ключи фильтра в telegram.json)
EVENTS = ("traffic_dominant_change", "traffic_snapshot",
          "traffic_node_starved", "traffic_stats_error",
          "traffic_node_down", "traffic_node_degraded", "traffic_node_up",
          "naive_upstream_down", "naive_upstream_up")

# Дефолтные шаблоны (HTML для parse_mode=HTML). Плейсхолдеры:
#   {host} — короткое имя этого сервера; {ts} — локальное время;
#   {detail} — тело события (для смены ноды его первая строка уже
#   человекочитаемый заголовок «Режим: активная нода X»);
#   {strategy} / {node_from} / {node_to} — доп. поля события смены ноды
#   (метка режима балансировки, прежняя и новая нода).
DEFAULT_TEMPLATES = {
    "traffic_dominant_change":
        "🧭 <b>[{host}]</b> {detail}\n<i>{ts}</i>",
    "traffic_snapshot":
        "📈 <b>[{host}]</b> Распределение трафика по exit-нодам\n{detail}\n<i>{ts}</i>",
    "traffic_node_starved":
        "💤 <b>[{host}]</b> Нода без трафика\n{detail}\n<i>{ts}</i>",
    "traffic_stats_error":
        "⚠️ <b>[{host}]</b> Stats API недоступен\n{detail}\n<i>{ts}</i>",
    "traffic_node_down":
        "📴 <b>[{host}]</b> Нода недоступна\n{detail}\n<i>{ts}</i>",
    "traffic_node_degraded":
        "🐌 <b>[{host}]</b> Нода тупит\n{detail}\n<i>{ts}</i>",
    "traffic_node_up":
        "🔌 <b>[{host}]</b> Нода восстановлена\n{detail}\n<i>{ts}</i>",
    "naive_upstream_down":
        "📴 <b>[{host}]</b> Naive: upstream недоступен\n{detail}\n<i>{ts}</i>",
    "naive_upstream_up":
        "🔌 <b>[{host}]</b> Naive: upstream восстановлен\n{detail}\n<i>{ts}</i>",
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
    # Активные пробы нод (TCP host:port): недоступность/деградация
    "probe":                True,   # вкл/выкл активных проб
    "probe_timeout_sec":    5,      # таймаут TCP-пробы
    "probe_fails":          2,      # неудач подряд → traffic_node_down
    "probe_degraded_ms":    500,    # RTT выше порога → деградация (0 = выкл)
    "probe_degraded_fails": 2,      # медленных проб подряд → traffic_node_degraded
    # Покрытие каскадов (мультитранспортность): для каждого — пассивный
    # трафик (счётчики распределения) и пробы. Дефолты:
    #   vless: traffic+probe ВКЛ (прежнее поведение — ничего не меняется);
    #   awg:   traffic ВКЛ (ip -s link слотов), probe ВЫКЛ — переходы
    #          alive уже алертит failover-тик (awg_failover);
    #   mieru: traffic ВКЛ, probe ВЫКЛ — health уже алертит
    #          mieru_cascade_monitor (mieru_exit_down/up);
    #          bytes_source: auto | ipaccounting | conn — источник байтов
    #          (auto: IPAccounting, если включён у юнитов mieru-hop@*,
    #          иначе счётчики iptables = распределение по соединениям);
    #   naive: traffic ВЫКЛ (счётчиков по upstream нет по построению),
    #          probe ВКЛ — события naive_upstream_down/up.
    "cascades": {
        "vless": {"traffic": True,  "probe": True},
        "awg":   {"traffic": True,  "probe": False},
        "mieru": {"traffic": True,  "probe": False,
                  "bytes_source": "auto"},
        "naive": {"traffic": False, "probe": True},
    },
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


def _tw_tcp_probe(host: str, port: int, timeout_sec) -> dict:
    """TCP-проба host:port (socket.create_connection, время —
    time.monotonic): {'ok': bool, 'ms': int|None, 'err': str}.
    Отказ DNS (getaddrinfo внутри create_connection) → err='DNS';
    таймаут → 'timeout'; прочее — короткий текст исключения без
    префикса '[Errno N]' ('Connection refused'). Никогда не бросает."""
    t0 = time.monotonic()
    try:
        with socket.create_connection((str(host), int(port)),
                                      timeout=float(timeout_sec or 5)):
            pass
        return {"ok": True,
                "ms": int((time.monotonic() - t0) * 1000), "err": ""}
    except socket.gaierror:
        return {"ok": False, "ms": None, "err": "DNS"}
    except socket.timeout:
        return {"ok": False, "ms": None, "err": "timeout"}
    except Exception as e:
        msg = str(e) or type(e).__name__
        m = re.match(r"^\[Errno \d+\]\s*(.+)$", msg)
        if m:
            msg = m.group(1)
        return {"ok": False, "ms": None, "err": msg[:60] or "error"}


def _tw_probe_nodes(chain_nodes: list, cfg: dict) -> dict | None:
    """Активные TCP-пробы всех chain-нод (host:port каждой —
    сопоставление как в _tw_tag_names): {tag: результат _tw_tcp_probe}.
    Пробы последовательные, таймаут каждой — cfg['probe_timeout_sec'].
    Нет валидных нод → None. Модуль самодостаточен — stdlib socket."""
    try:
        timeout = int((cfg or {}).get("probe_timeout_sec") or 5)
    except (TypeError, ValueError):
        timeout = 5
    timeout = max(1, min(30, timeout))
    out: dict = {}
    for i, nd in enumerate(chain_nodes or []):
        host = str((nd or {}).get("host") or "").strip()
        if not host:
            continue
        port = int((nd or {}).get("port") or 443)
        out[f"chain-exit-{i + 1}"] = _tw_tcp_probe(host, port, timeout)
    return out or None


def _tw_probe_update(pstate: dict, results: dict | None, cfg: dict,
                     now_ts: float) -> tuple:
    """Активные пробы: машина состояний по результатам прогона.
    pstate — срез __state__ с ключами probe_fails {tag: неудач подряд},
    probe_slow {tag: медленных подряд}, probe_status {tag: последний
    статус}, all_probes_down (bool); отсутствующие ключи/None — норма.
    Логика: ok+быстрая проба → счётчики сброшены; ok+медленная
    (ms > probe_degraded_ms, при пороге > 0) → slow+1; отказ → fails+1.
    Статус: 'down' (fails ≥ probe_fails) / 'degraded' (slow ≥
    probe_degraded_fails) / 'ok'; событие — только на ПЕРЕХОДЕ статуса.
    Guard локальной проблемы: все пробы разом не прошли → персональные
    статусы/счётчики не трогаем, один 'local' traffic_node_down
    (единожды, пока all_probes_down) и traffic_node_up с
    local_recovery при рассасывании.
    Возвращает (new_pstate, events); переходы одного типа агрегированы
    в одно событие {'event', 'tags': [...], 'info': {tag: {...}}}.
    Чистая функция."""
    st = pstate or {}
    fails_map = dict(st.get("probe_fails") or {})
    slow_map = dict(st.get("probe_slow") or {})
    status_map = dict(st.get("probe_status") or {})
    all_down = bool(st.get("all_probes_down") or False)
    new = {"probe_fails": fails_map, "probe_slow": slow_map,
           "probe_status": status_map, "all_probes_down": all_down}
    events: list = []
    if not results:
        return new, events

    # Все пробы разом пали — вероятна локальная проблема на релее
    if all(not r.get("ok") for r in results.values()):
        if not all_down:
            events.append({"event": "traffic_node_down", "local": True,
                           "total": len(results)})
            new["all_probes_down"] = True
        return new, events

    if all_down:
        new["all_probes_down"] = False
        events.append({"event": "traffic_node_up", "local_recovery": True,
                       "ok_count": sum(1 for r in results.values()
                                       if r.get("ok")),
                       "total": len(results)})

    def _cfg_int(key: str, default: int) -> int:
        raw = (cfg or {}).get(key)
        if raw is None:
            return default
        try:
            return int(raw)
        except (TypeError, ValueError):
            return default

    fail_thr = max(1, _cfg_int("probe_fails", 2))
    deg_ms = _cfg_int("probe_degraded_ms", 500)
    deg_thr = max(1, _cfg_int("probe_degraded_fails", 2))

    trans = {ev: {"tags": [], "info": {}}
             for ev in ("traffic_node_down", "traffic_node_degraded",
                        "traffic_node_up")}
    for tag, r in results.items():
        ok = bool(r.get("ok"))
        ms = r.get("ms")
        fails = int(fails_map.get(tag) or 0)
        slow = int(slow_map.get(tag) or 0)
        if not ok:
            fails += 1
            slow = 0
        elif deg_ms > 0 and ms is not None and int(ms) > deg_ms:
            slow += 1
            fails = 0
        else:
            fails = 0
            slow = 0
        fails_map[tag] = fails
        slow_map[tag] = slow
        status = "down" if fails >= fail_thr else \
            ("degraded" if slow >= deg_thr else "ok")
        prev_status = str(status_map.get(tag) or "ok")
        status_map[tag] = status
        if status == prev_status:
            continue
        if status == "down":
            trans["traffic_node_down"]["tags"].append(tag)
            trans["traffic_node_down"]["info"][tag] = {
                "err": str(r.get("err") or ""), "fails": fails}
        elif status == "degraded":
            trans["traffic_node_degraded"]["tags"].append(tag)
            trans["traffic_node_degraded"]["info"][tag] = {
                "ms": ms, "threshold": deg_ms, "fails": slow}
        else:
            trans["traffic_node_up"]["tags"].append(tag)
            trans["traffic_node_up"]["info"][tag] = {
                "ms": ms, "prev": prev_status}

    # теги, которых больше нет в составе нод, — прочистка от роста
    for m in (fails_map, slow_map, status_map):
        for t in list(m):
            if t not in results:
                m.pop(t)

    for ev in ("traffic_node_down", "traffic_node_degraded",
               "traffic_node_up"):
        if trans[ev]["tags"]:
            events.append({"event": ev, "tags": trans[ev]["tags"],
                           "info": trans[ev]["info"]})
    return new, events


# ── Мультитранспортность: парсеры источников (чистые функции) ────────────────


def _tw_parse_ip_link(text: str) -> dict:
    """{'iface': {'rx': int, 'tx': int}} из вывода `ip -s link show ...`.
    Формат (проверен на живом entry 11.11.2026):

        14: awg1: <...> mtu 1280 ...
            link/none
            RX:  bytes packets errors dropped  missed   mcast
                 1214453   16253      0       0       0       0
            TX:  bytes packets errors dropped carrier collsns
                 12199154  106539     0       0       0       0

    Заголовки RX:/TX: и числа — в РАЗНЫХ строках; байты — первое число.
    Битый вывод → {}. Чистая функция."""
    out: dict = {}
    cur = ""
    section = ""
    for line in str(text or "").splitlines():
        m = re.match(r"^\s*\d+:\s+([\w.@\-]+):", line)
        if m:
            cur, section = m.group(1), ""
            continue
        s = line.strip()
        if not cur:
            continue
        if s.startswith("RX:"):
            section = "rx"
            continue
        if s.startswith("TX:"):
            section = "tx"
            continue
        if section:
            parts = s.split()
            if parts and parts[0].isdigit():
                out.setdefault(cur, {})[section] = int(parts[0])
                section = ""
    return out


def _tw_parse_systemctl_show(text: str) -> dict:
    """{'IPAccounting': bool, 'IPIngressBytes': int|None,
    'IPEgressBytes': int|None} из вывода `systemctl show <unit> -p
    IPAccounting -p IPIngressBytes -p IPEgressBytes`. Отсутствующие
    значения ('[no data]') → None. Чистая функция."""
    out: dict = {"IPAccounting": False,
                 "IPIngressBytes": None, "IPEgressBytes": None}
    for line in str(text or "").splitlines():
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip()
        if k == "IPAccounting":
            out["IPAccounting"] = (v.lower() == "yes")
        elif k in ("IPIngressBytes", "IPEgressBytes"):
            if v.isdigit():
                out[k] = int(v)
    return out


def _tw_parse_iptables_redir(text: str) -> dict:
    """{port: {'pkts': int, 'bytes': int}} из вывода
    `iptables -t nat -L OUTPUT -v -x` — строки REDIRECT с «redir ports N»
    (балансировочные правила mieru-каскада: statistic REDIRECT --to-ports
    2308N). Счётчик правила в nat-таблице растёт только на НОВЫЕ
    соединения — метрика распределения по соединениям. Чистая функция."""
    out: dict = {}
    for line in str(text or "").splitlines():
        if "REDIRECT" not in line or "redir ports" not in line:
            continue
        m = re.search(r"redir ports\s+(\d+)", line)
        parts = line.split()
        if m and len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            out[int(m.group(1))] = {"pkts": int(parts[0]),
                                    "bytes": int(parts[1])}
    return out


def _tw_parse_naive_upstream(url: str) -> dict | None:
    """{'host': str, 'port': int} из upstream-URL Naive-каскада
    (https://user:pass@exit-host:443/...; порт по умолчанию 443).
    Битый URL / без хоста → None. Чистая функция."""
    try:
        u = urllib.parse.urlsplit(str(url or ""))
        host = (u.hostname or "").strip()
        if not host:
            return None
        port = u.port or 443
        return {"host": host, "port": int(port)}
    except (ValueError, TypeError):
        return None


def _tw_cascades_cfg(cfg: dict) -> dict:
    """Нормализованная секция cascades (дефолты + сохранённое; старые
    конфиги без cascades получают дефолты — merge при load_cfg уже
    добирает вложенные ключи; здесь — защита от битых значений).
    Чистая функция."""
    stored = (cfg or {}).get("cascades")
    base = DEFAULTS["cascades"]
    if not isinstance(stored, dict):
        return {k: dict(v) for k, v in base.items()}
    out: dict = {}
    for kind in CASCADE_KINDS:
        d = dict(base.get(kind) or {})
        s = stored.get(kind)
        if isinstance(s, dict):
            for k, v in s.items():
                if v is not None:
                    d[k] = v
        out[kind] = d
    src = out.get("mieru", {}).get("bytes_source")
    if src not in ("auto", "ipaccounting", "conn"):
        out["mieru"]["bytes_source"] = "auto"
    return out


def _tw_cascade_acc(acc: dict, prefix: str) -> dict:
    """Срез накопителя/дельт по префиксу тега каскада ('' = vless:
    прежние chain-exit-N без префикса; 'awg:' / 'mieru:' / 'naive:').
    Чистая функция."""
    if prefix:
        return {t: v for t, v in (acc or {}).items()
                if t.startswith(prefix)}
    return {t: v for t, v in (acc or {}).items()
            if not (t.startswith(TAG_PREFIX_AWG)
                    or t.startswith(TAG_PREFIX_MIERU)
                    or t.startswith(TAG_PREFIX_NAIVE))}


def _tw_state_v2(state: dict) -> dict:
    """Миграция __state__ к мультитранспортному формату (чистая):
      • dominant_tag (str, vless) → dominant_tags {'vless': tag}
        (плоский dominant_tag продолжаем писать рядом — откат версии
        модуля ниже git читает его);
      • stats_fails (int, vless) → stats_fails_map {'vless': N}.
    Вход не мутируется. Чистая функция."""
    st = dict(state or {})
    dt = st.get("dominant_tags")
    if not isinstance(dt, dict):
        dt = {}
    if st.get("dominant_tag"):
        dt.setdefault("vless", st["dominant_tag"])
    st["dominant_tags"] = dt
    sf = st.get("stats_fails_map")
    if not isinstance(sf, dict):
        sf = {}
    if isinstance(st.get("stats_fails"), int) and not isinstance(
            st.get("stats_fails"), bool):
        sf.setdefault("vless", st["stats_fails"])
    st["stats_fails_map"] = sf
    return st


def _tw_fmt_metric(metric: str, value: int) -> str:
    """Человекочитательное значение метрики каскада: байты
    ('bytes') или соединения ('conn' — «3 456 соед.»). Чистая функция."""
    if str(metric) == "conn":
        try:
            n = int(value or 0)
        except (TypeError, ValueError):
            n = 0
        return f"{n:,} соед.".replace(",", " ")
    return _tw_fmt_bytes(value)


def _tw_metric_noun(metric: str) -> str:
    """Существительное для текстов доминирования: 'трафика окна' /
    'соединений окна'. Чистая функция."""
    return "соединений окна" if str(metric) == "conn" else "окна"


def _tw_naive_probe_update(pstate: dict, result: dict | None, cfg: dict,
                           now_ts: float) -> tuple:
    """Naive upstream-watcher: машина состояний по результату пробы.
    pstate — срез __state__ с ключами naive_fails (int), naive_status
    ('ok'|'down'); отсутствующие/None — норма (первое наблюдение
    молчит — паттерн _tw_probe_update). Логика: отказ → fails+1,
    ok → сброс; статус 'down' при fails ≥ probe_fails (порог общий
    с остальными пробами); событие — только на ПЕРЕХОДЕ статуса:
    naive_upstream_down / naive_upstream_up. Возвращает
    (new_pstate, [events]). Чистая функция."""
    st = pstate or {}
    fails = int(st.get("naive_fails") or 0)
    status = str(st.get("naive_status") or "")
    new = {"naive_fails": fails, "naive_status": status}
    events: list = []
    if result is None:
        return new, events
    try:
        thr = max(1, int((cfg or {}).get("probe_fails") or 2))
    except (TypeError, ValueError):
        thr = 2
    ok = bool(result.get("ok"))
    if ok:
        fails = 0
    else:
        fails += 1
    new["naive_fails"] = fails
    if fails >= thr:
        new_status = "down"
    elif ok:
        new_status = "ok"
    else:
        # не хватает неудач до порога: прошлый статус сохраняем
        # (down держится, «условно ок» не переворачивается в down)
        new_status = "down" if status == "down" else "ok"
    # первый прогон (пустой статус): фиксируем без события
    if status:
        if new_status == "down" and status != "down":
            events.append({"event": "naive_upstream_down",
                           "fails": fails,
                           "err": str(result.get("err") or "")})
        elif new_status == "ok" and status == "down":
            events.append({"event": "naive_upstream_up",
                           "ms": result.get("ms")})
    new["naive_status"] = new_status
    return new, events


def _tw_naive_event_text(event: dict, host_port: str) -> str:
    """Текст уведы событий Naive upstream. Чистая функция."""
    ev = str((event or {}).get("event") or "")
    if ev == "naive_upstream_down":
        return (f"Upstream <b><code>{host_port}</code></b> недоступен: "
                f"TCP-проба не проходит {int(event.get('fails') or 0)} "
                f"прогонов подряд "
                f"({str(event.get('err') or 'нет ответа')}). "
                f"Каскад Entry→Exit без выхода — клиенты без интернета.")
    if ev == "naive_upstream_up":
        ms = event.get("ms")
        ms_str = f"RTT {ms} мс" if ms is not None else "проба снова ОК"
        return (f"Upstream <b><code>{host_port}</code></b> восстановлен: "
                f"{ms_str}.")
    return ""



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
                          include_bytes=True, metric="bytes",
                          dead_nodes=None) -> list:
    """Строки распределения (для дайджеста и меню): ноды по убыванию
    объёма, формат «• имя — 1.2 ГБ (63%)» (при metric='conn' —
    «• имя — 3 456 соед. (63%)»; dead_nodes — {tag: true} дописок «·
    недоступна (health)» для нод, исключённых из ротации каскада).
    Чистая функция."""
    total = _tw_total(acc)
    rows: list[str] = []
    items = sorted((acc or {}).items(),
                   key=lambda kv: -_tw_bytes_of(kv[1]))
    for tag, v in items:
        s = _tw_bytes_of(v)
        name = (names or {}).get(tag) or tag
        body = ""
        val = _tw_fmt_metric(metric, s)
        if include_bytes and include_percent and total > 0:
            body = f" — {val} ({100.0 * s / total:.0f}%)"
        elif include_bytes:
            body = f" — {val}"
        elif include_percent and total > 0:
            body = f" — {100.0 * s / total:.0f}%"
        if (dead_nodes or {}).get(tag):
            body += " · недоступна (health)"
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
                      include_percent=True, include_bytes=True,
                      metric="bytes", dead_nodes=None) -> str:
    """Текст дайджеста распределения. Чистая функция."""
    lines = []
    st = str(strategy or "").strip()
    lines.append(f"Стратегия: <b>{st or 'нет'}</b>")
    total_str = _tw_fmt_metric(metric, _tw_total(acc))
    if window_str:
        lines.append(f"Окно: {window_str}, всего: <b>{total_str}</b>")
    else:
        lines.append(f"Всего за окно: <b>{total_str}</b>")
    rows = _tw_distribution_rows(acc, names, include_percent,
                                  include_bytes, metric, dead_nodes)
    if rows:
        lines.extend(rows)
    else:
        lines.append("Трафика через exit-ноды за окно не было")
    if per_user_rows:
        lines.append("Пользователи (соединений по нодам):")
        lines.extend(per_user_rows)
    return "\n".join(lines)


# Красивые имена стратегий chain-balancer для заголовков увед
_STRATEGY_PRETTY = {
    "roundRobin": "RoundRobin",
    "leastPing":  "LeastPing",
    "leastLoad":  "LeastLoad",
    "random":     "Random",
}


def _tw_strategy_label(live: dict, sb: dict) -> str:
    """Метка режима балансировки для заголовка уведы: «SmartBalancer»,
    если SB включён (он патчит selector и владеет ротацией); иначе —
    стратегия нативного chain-balancer (красивое имя); без
    балансировщика — «Каскад» (закреплённая нода / failover).
    Чистая функция."""
    if (sb or {}).get("enabled"):
        return "SmartBalancer"
    raw = str((live or {}).get("strategy") or "").strip()
    if not raw:
        return "Каскад"
    return _STRATEGY_PRETTY.get(raw, raw)


def _tw_dominant_change_text(strategy_label: str, old_name: str,
                             new_name: str, share_pct: float,
                             bytes_: int, total: int,
                             metric="bytes") -> str:
    """Текст уведы traffic_dominant_change: первая строка —
    человекочитаемый заголовок («Режим: активная нода X»), вторая —
    «Переключение ноды: Y → X» (откуда и куда — полностью), третья —
    доля окна (при metric='conn' — доля соединений, объёмы в
    соединениях). Чистая функция."""
    return (f"{strategy_label}: активная нода "
            f"<b><code>{new_name}</code></b>\n"
            f"Переключение ноды: <code>{old_name}</code> → "
            f"<b><code>{new_name}</code></b>\n"
            f"Доминирование: {share_pct:.0f}% {_tw_metric_noun(metric)} "
            f"({_tw_fmt_metric(metric, bytes_)} "
            f"из {_tw_fmt_metric(metric, total)})")


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


def _tw_probe_ago_str(last_ts, now_ts: float) -> str:
    """«N мин назад» / «N ч назад» для метки последнего трафика ноды
    (пусто, если метки нет). Чистая функция."""
    try:
        delta = max(0, float(now_ts) - float(last_ts))
    except (TypeError, ValueError):
        return ""
    if delta < 3600:
        return f"{int(delta // 60)} мин назад"
    return f"{int(delta // 3600)} ч назад"


def _tw_probe_down_line(alias: str, key: str, fails: int, err: str,
                        last_ts, now_ts: float, hm_down: bool) -> str:
    """Строка уведы traffic_node_down (одна нода): недоступна N
    прогонов подряд + контекст — когда нода последний раз несла
    трафик; вердикт HM (если уже DOWN) — доп. строка-довесок.
    Чистая функция."""
    txt = (f"Нода <b><code>{alias}</code></b> ({key}) недоступна: "
           f"TCP-проба не проходит {fails} прогонов подряд ({err}).")
    if hm_down:
        txt += " (Health Monitor: DOWN)"
    ago = _tw_probe_ago_str(last_ts, now_ts)
    if ago:
        txt += f"\nПоследний трафик через ноду: {ago}"
    else:
        txt += "\nТрафика через ноду в этом окне не было."
    return txt


def _tw_probe_degraded_line(alias: str, key: str, ms, threshold,
                            fails: int) -> str:
    """Строка уведы traffic_node_degraded (одна нода). Чистая
    функция."""
    return (f"Нода <b><code>{alias}</code></b> ({key}) тупит: "
            f"TCP-проба проходит, но RTT {ms} мс выше порога "
            f"{threshold} мс ({fails} прогонов подряд).")


def _tw_probe_up_line(alias: str, key: str, ms, prev: str) -> str:
    """Строка уведы traffic_node_up (одна нода): восстановление после
    отказа ('down') либо деградации. Чистая функция."""
    why = "после деградации" if str(prev or "") == "degraded" \
        else "после отказа"
    return (f"Нода <b><code>{alias}</code></b> ({key}) восстановлена: "
            f"RTT {ms} мс ({why}).")


def _tw_probe_event_text(event: dict, names: dict, keys: dict,
                         last_traffic: dict, now_ts: float,
                         hm_state: dict, hostname: str) -> str:
    """Текст уведы событий активных проб: down/degraded/up (строки
    нод агрегируются через \\n в одно сообщение — один тип = одна
    уведа) + локальные сценарии (все ноды разом / восстановление
    связи). alias — тот же механизм, что и в остальных уведах.
    Чистая функция."""
    ev = str((event or {}).get("event") or "")
    tags = (event or {}).get("tags") or []
    info = (event or {}).get("info") or {}
    if ev == "traffic_node_down" and (event or {}).get("local"):
        n = (event or {}).get("total") or 0
        return (f"Все {n} exit-нод недоступны одновременно — вероятна "
                f"локальная проблема на {hostname} "
                f"(сеть/DNS/исходящий трафик). "
                f"Уведы по отдельным нодам подавлены.")
    if ev == "traffic_node_up" and (event or {}).get("local_recovery"):
        m = (event or {}).get("ok_count") or 0
        n = (event or {}).get("total") or 0
        return f"Связь с exit-нодами восстановлена: {m} из {n} отвечают."
    lines: list[str] = []
    for tag in tags:
        key = (keys or {}).get(tag) or tag
        alias = (names or {}).get(tag) or key
        d = info.get(tag) or {}
        if ev == "traffic_node_down":
            lines.append(_tw_probe_down_line(
                alias, key, int(d.get("fails") or 0),
                str(d.get("err") or ""),
                (last_traffic or {}).get(tag), now_ts,
                ((hm_state or {}).get(key) or {}).get("up") is False))
        elif ev == "traffic_node_degraded":
            lines.append(_tw_probe_degraded_line(
                alias, key, d.get("ms"), d.get("threshold"),
                int(d.get("fails") or 0)))
        elif ev == "traffic_node_up":
            lines.append(_tw_probe_up_line(
                alias, key, d.get("ms"), str(d.get("prev") or "")))
    return "\n".join(lines)


def _tw_probe_event_extra(event: dict, names: dict, keys: dict) -> dict:
    """Доп. плейсхолдеры шаблона для событий проб: {node} — алиас
    первой затронутой ноды (паттерн {node_to} у смены ноды)."""
    tags = (event or {}).get("tags") or []
    if not tags:
        return {}
    t = tags[0]
    return {"node": (names or {}).get(t) or (keys or {}).get(t) or t}


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


# ── Мультитранспортность: источники каскадов (IO-обёртки; тесты патчат) ──────


def _tw_ip_link_stats(ifaces: list) -> dict:
    """Счётчики интерфейсов `ip -s link show` (одним вызовом — iproute2
    НЕ принимает несколько устройств в одном show: «Error: either "dev"
    is duplicate, or "awg2" is a garbage»): снимок всех ссылок, из него —
    только запрошенные {iface: {'rx': int, 'tx': int}}. Отказ/пустой
    вывод / отсутствующий интерфейс → пропущен. Никогда не бросает."""
    try:
        wanted = [str(i).strip() for i in (ifaces or []) if str(i).strip()]
        if not wanted:
            return {}
        r = subprocess.run(["ip", "-s", "link", "show"],
                           capture_output=True, text=True, timeout=10,
                           check=False)
        parsed = _tw_parse_ip_link(r.stdout or "")
        return {i: parsed[i] for i in wanted if parsed.get(i)}
    except Exception:
        return {}


def _tw_iptables_nat_output() -> dict:
    """Счётчики правил `iptables -t nat -L OUTPUT -v -x`:
    {redir_port: {'pkts', 'bytes'}} (правила mieru-каскада
    «REDIRECT --to-ports 2308N»). Отказ/нет прав → {}.
    Никогда не бросает."""
    try:
        r = subprocess.run(["iptables", "-t", "nat", "-L", "OUTPUT",
                            "-v", "-x"],
                           capture_output=True, text=True, timeout=10,
                           check=False)
        return _tw_parse_iptables_redir(r.stdout or "")
    except Exception:
        return {}


def _tw_systemctl_show_ipacct(unit: str) -> dict:
    """IPAccounting-свойства юнита (systemctl show -p ...):
    {'IPAccounting': bool, 'IPIngressBytes': int|None,
    'IPEgressBytes': int|None}. Отказ → IPAccounting=False.
    Никогда не бросает."""
    try:
        r = subprocess.run(
            ["systemctl", "show", str(unit), "--no-pager",
             "-p", "IPAccounting", "-p", "IPIngressBytes",
             "-p", "IPEgressBytes"],
            capture_output=True, text=True, timeout=10, check=False)
        return _tw_parse_systemctl_show(r.stdout or "")
    except Exception:
        return {"IPAccounting": False, "IPIngressBytes": None,
                "IPEgressBytes": None}


def _tw_awg_source() -> dict | None:
    """Источник AWG-каскада (awg_cascade / awg_cascade_lb):
    {'nodes': {tag: {'name','host','port','iface','key'}},
     'counters': {tag: {'up': tx, 'down': rx}} — ip -s link слотов
     (LB-режим) или активного awg1 (failover-режим);
     'strategy': метка, 'selector': [теги в ротации],
     'dead': {tag: True} — вне ротации (alive=false / не активный exit),
     'probe_results': {tag: {'ok': alive, 'ms': rtt}} — из lb.probes
     failover-тика (для cascades.awg.probe). Каскада нет / не entry →
     None. Никогда не бросает."""
    st = _read_json(AWG_STATE_FILE)
    if not st or str(st.get("cascade_role") or "") != "entry":
        return None
    exits = st.get("cascade_exits") or []
    if not isinstance(exits, list) or not exits:
        return None
    lb = st.get("lb") if isinstance(st.get("lb"), dict) else {}
    lb_mode = bool(st.get("lb_mode"))
    slots = lb.get("slots_snapshot") if isinstance(
        lb.get("slots_snapshot"), dict) else {}
    alive = lb.get("alive") if isinstance(lb.get("alive"), list) else []
    probes = lb.get("probes") if isinstance(lb.get("probes"), dict) else {}
    active_exit = str(st.get("cascade_active_exit") or "")
    pinned = str(st.get("lb_pinned") or "")

    nodes: dict = {}
    ifaces: list = []
    for ex in exits:
        if not isinstance(ex, dict):
            continue
        name = str(ex.get("name") or "").strip()
        host = str(ex.get("endpoint") or "").strip()
        port = int(ex.get("port") or 0)
        if not name or not host:
            continue
        slot = slots.get(name)
        iface = f"awg{int(slot)}" if isinstance(slot, int) else (
            "awg1" if not lb_mode else "")
        tag = TAG_PREFIX_AWG + name
        nodes[tag] = {"name": name, "host": host, "port": port,
                      "iface": iface, "key": f"{host}:{port}"}
        if iface and iface not in ifaces:
            ifaces.append(iface)

    link = _tw_ip_link_stats(ifaces) if ifaces else {}
    counters: dict = {}
    for tag, nd in nodes.items():
        c = link.get(nd["iface"]) or {}
        if c:
            counters[tag] = {"up": int(c.get("tx") or 0),
                             "down": int(c.get("rx") or 0)}

    # «В ротации»: LB — живые слоты (lb.alive); failover — активный exit
    if lb_mode:
        sel = [TAG_PREFIX_AWG + n for n in alive
               if TAG_PREFIX_AWG + n in nodes]
        dead = {t: True for t in nodes if t not in sel}
    else:
        sel = ([TAG_PREFIX_AWG + pinned] if pinned and
               TAG_PREFIX_AWG + pinned in nodes else
               ([TAG_PREFIX_AWG + active_exit] if
                TAG_PREFIX_AWG + active_exit in nodes else []))
        dead = {t: True for t in nodes if t not in sel}

    probe_results = {}
    for tag, nd in nodes.items():
        p = probes.get(nd["name"]) or {}
        if isinstance(p, dict) and "alive" in p:
            rtt = p.get("rtt_ms")
            probe_results[tag] = {
                "ok": bool(p.get("alive")),
                "ms": int(rtt) if isinstance(rtt, (int, float)) else None,
                "err": "" if p.get("alive") else "failover-тик: alive=false"}

    return {"nodes": nodes, "counters": counters,
            "strategy": _tw_awg_strategy_label(st),
            "selector": sel, "dead": dead,
            "probe_results": probe_results or None}


_AWG_STRATEGY_PRETTY = {
    "smart":      "AWG Smart",
    "rr":         "AWG RoundRobin",
    "random":     "AWG Random",
    "prio":       "AWG Prio (active-backup)",
    "clienthash": "AWG ClientHash",
    "leastping":  "AWG LeastPing",
    "leastload":  "AWG LeastLoad",
}


def _tw_awg_strategy_label(st: dict) -> str:
    """Метка стратегии AWG-каскада для заголовков (закреплённая нода /
    LB-стратегия / failover-режим). Чистая функция."""
    if not st:
        return "AWG-каскад"
    pinned = str(st.get("lb_pinned") or "").strip()
    if st.get("lb_mode") and pinned:
        return f"AWG Pinned ({pinned})"
    if st.get("lb_mode"):
        raw = str(st.get("lb_strategy") or "").strip()
        return _AWG_STRATEGY_PRETTY.get(raw, f"AWG {raw}" if raw
                                        else "AWG LB")
    return "AWG-каскад (failover)"


def _tw_mieru_source(bytes_source: str = "auto") -> dict | None:
    """Источник Mieru-каскада (mieru_cascade): {'nodes': {tag: {...}},
    'counters': {tag: {'up','down'}}, 'metric': 'bytes'|'conn',
    'strategy': метка, 'selector': [теги enabled+healthy],
    'dead': {tag: True} — выключенные/больные, 'probe_targets':
    [(host, port, tag)] — TCP-пробы mita-портов exit-нод}.
    Байты: a) IPAccounting юнитов mieru-hop@<id> (точные IP-байты cgroup,
    если включён у ВСЕХ юнитов — выбор bytes_source/auto/ipaccounting);
    b) счётчики iptables nat OUTPUT «REDIRECT --to-ports <redsocks_port>»
    (metric='conn': распределение по НОВЫМ соединениям). Каскада нет /
    не entry → None. Никогда не бросает."""
    st = _read_json(MIERU_STATE_FILE)
    if not st or str(st.get("role") or "") != "entry":
        return None
    exits = st.get("exits") or []
    if not isinstance(exits, list) or not exits:
        return None

    nodes: dict = {}
    sel: list = []
    dead: dict = {}
    probe_targets: list = []
    for ex in exits:
        if not isinstance(ex, dict) or not ex.get("enabled"):
            continue
        label = str(ex.get("label") or ex.get("id") or "").strip()
        host = str(ex.get("host") or "").strip()
        port = int(ex.get("port") or 0)
        if not label or not host or not port:
            continue
        tag = TAG_PREFIX_MIERU + label
        nodes[tag] = {"name": label, "host": host, "port": port,
                      "id": str(ex.get("id") or ""),
                      "redsocks_port": int(ex.get("redsocks_port") or 0),
                      "key": f"{host}:{port}"}
        if ex.get("healthy"):
            sel.append(tag)
        else:
            dead[tag] = True
        probe_targets.append((host, port, tag))

    if not nodes:
        return None

    metric = "conn"
    counters: dict = {}
    use_ipacct = (bytes_source == "ipaccounting")
    if bytes_source == "auto" or use_ipacct:
        ipacct: dict = {}
        all_yes = True
        for tag, nd in nodes.items():
            unit = f"mieru-hop@{nd['id']}.service" if nd["id"] else ""
            props = _tw_systemctl_show_ipacct(unit) if unit else \
                {"IPAccounting": False}
            if props.get("IPAccounting") and unit:
                ipacct[tag] = props
            else:
                all_yes = False
        if use_ipacct and not all_yes:
            _tw_log("WARN: mieru bytes_source=ipaccounting, но "
                    "IPAccounting включён не у всех юнитов mieru-hop@* — "
                    "часть нод без счётчиков")
        if ipacct and (all_yes or use_ipacct):
            metric = "bytes"
            for tag, props in ipacct.items():
                eg = props.get("IPEgressBytes")
                ig = props.get("IPIngressBytes")
                counters[tag] = {"up": int(eg or 0), "down": int(ig or 0)}
    if metric == "conn":
        redir = _tw_iptables_nat_output()
        for tag, nd in nodes.items():
            rp = nd["redsocks_port"]
            c = redir.get(rp) if rp else None
            if c:
                # pkts правила = новые соединения (nat обходит правила
                # только для NEW); bytes первых пакетов не показываем
                counters[tag] = {"up": int(c.get("pkts") or 0), "down": 0}

    raw = str(st.get("strategy") or "").strip()
    strategy = {"smart": "Mieru Smart"}.get(raw, f"Mieru {raw}" if raw
                                            else "Mieru-каскад")
    return {"nodes": nodes, "counters": counters, "metric": metric,
            "strategy": strategy, "selector": sel, "dead": dead,
            "probe_targets": probe_targets}


def _tw_naive_source() -> dict | None:
    """Источник Naive-каскада (naiveproxy): upstream ОДИН —
    {'nodes': {'naive:upstream': {'name','host','port','key'}}}.
    Каскада нет (upstream пуст) → None. Никогда не бросает."""
    st = _read_json(NAIVE_STATE_FILE)
    if not isinstance(st, dict):
        return None
    up = str(st.get("upstream") or "").strip()
    tgt = _tw_parse_naive_upstream(up)
    if not tgt:
        return None
    return {"nodes": {TAG_PREFIX_NAIVE + "upstream": {
        "name": tgt["host"], "host": tgt["host"],
        "port": tgt["port"], "key": f"{tgt['host']}:{tgt['port']}"}}}


def _tw_mieru_set_ipaccounting(enable: bool, exits: list | None = None) -> tuple:
    """Включение/выключение IPAccounting на юнитах mieru-hop@exit-*
    (точные IP-байты per-exit для источника Mieru). set-property —
    persist (drop-in в /etc/systemd/system.control/) — ЯВНОЕ действие
    из меню (не выполняется молча из cron). Возвращает
    (ok, сообщение). Никогда не бросает."""
    try:
        units = [str(u) for u in (exits or []) if str(u).strip()]
        if not units:
            st = _read_json(MIERU_STATE_FILE)
            units = [f"mieru-hop@{e.get('id')}.service"
                     for e in (st.get("exits") or [])
                     if isinstance(e, dict) and e.get("id")]
        if not units:
            return False, "Юниты mieru-hop@* не найдены (каскад не развёрнут)"
        val = "yes" if enable else "no"
        for u in units:
            r = subprocess.run(
                ["systemctl", "set-property", u, f"IPAccounting={val}"],
                capture_output=True, text=True, timeout=15, check=False)
            if r.returncode != 0:
                return False, (f"Ошибка set-property {u}: "
                               f"{(r.stderr or '').strip()[:120]}")
        action = "включён" if enable else "выключен"
        return True, (f"IPAccounting {action} на {len(units)} юнитах "
                      f"mieru-hop@* (счётчики байтов появятся со "
                      f"следующего прогона)")
    except Exception as e:
        return False, f"Ошибка: {e}"


def _hostname() -> str:
    try:
        return subprocess.run(["hostname", "-s"], capture_output=True,
                              text=True, check=False).stdout.strip() or "server"
    except Exception:
        return "server"


def _now_str() -> str:
    return time.strftime("%d.%m.%Y %H:%M")


# ── Уведомления ───────────────────────────────────────────────────────────────


def _tw_notify_event(event: str, detail: str, cfg: dict,
                     extra: dict | None = None) -> bool:
    """Отправка события. Основной путь — tg_bot.tg_notify_event
    (уважает фильтр событий меню «Telegram-уведомления» и ключ proxy;
    первая строка detail становится заголовком уведы);
    fallback — прямая отправка curl-ом (паттерн exit_switch_watcher),
    если tg_bot недоступен. extra — доп. плейсхолдеры шаблона
    ({strategy}/{node_from}/{node_to} для смены ноды).
    Возвращает True при доставке."""
    notify_map = (cfg or {}).get("notify") or {}
    if notify_map.get(event, True) is False:
        return False

    chat_override = str((cfg or {}).get("chat_id_override") or "").strip()
    try:
        from chimera.modules import tg_bot
        if chat_override:
            tpl = (cfg.get("templates") or {}).get(event) \
                or DEFAULT_TEMPLATES.get(event, "{detail}")
            kw = {"host": _hostname(), "ts": _now_str(), "detail": detail}
            if extra:
                kw.update(extra)
            text = _tw_render(tpl, **kw)
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
        kw = {"host": _hostname(), "ts": _now_str(), "detail": detail}
        if extra:
            kw.update(extra)
        text = _tw_render(tpl, **kw)
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
    'stats_ok': bool} (dominant — доминанта VLESS-каскада; acc — общий
    накопитель всех каскадов)."""
    cfg = load_cfg()
    if not cfg.get("enabled", True) and not force:
        _tw_log("SKIP: наблюдатель выключен (enabled=false)")
        return {"acc": {}, "dominant": None, "events": [], "stats_ok": True}

    prev = _tw_state_v2(_read_json(TW_CFG_FILE).get("__state__") or {})
    casc = _tw_cascades_cfg(cfg)

    st = _load_state()
    chain_nodes = st.get("chain_nodes") or []

    # ── Источники каскадов (мультитранспортность) ──
    awg_src = _tw_awg_source() if casc["awg"].get("traffic") else None
    mieru_src = (_tw_mieru_source(casc["mieru"].get("bytes_source"))
                 if casc["mieru"].get("traffic") else None)
    naive_src = _tw_naive_source()
    has_vless = bool(chain_nodes) and bool(casc["vless"].get("traffic"))
    if not has_vless and not awg_src and not mieru_src and not naive_src:
        _tw_log("SKIP: exit-ноды не настроены (каскады не развёрнуты)")
        return {"acc": {}, "dominant": None, "events": [], "stats_ok": True}

    aliases = cfg.get("aliases") or {}
    names, keys = _tw_tag_names(chain_nodes, aliases)
    # ноды остальных каскадов: алиас по каскадному ключу → host:port → имя
    for src in (awg_src, mieru_src, naive_src):
        for tag, nd in ((src or {}).get("nodes") or {}).items():
            nm = str(aliases.get(tag) or
                     aliases.get(nd.get("key")) or
                     nd.get("name") or tag).strip()
            names[tag] = nm or tag
            keys[tag] = nd.get("key") or tag

    now = time.time()
    now_hhmm = time.strftime("%H:%M")
    quiet = _tw_quiet(now_hhmm, cfg.get("quiet_hours") or {})
    events_sent: list[str] = []

    def _emit(event: str, detail: str,
              extra: dict | None = None) -> None:
        """Отправка с учётом анти-спама (min_gap) и quiet-часов."""
        if not force and quiet:
            _tw_log(f"SKIP[{event}]: тихие часы")
            return
        if not force and not _tw_gap_ok(
                ((prev.get("last_notify") or {}).get(event)) or 0,
                now, cfg.get("min_gap_min")):
            _tw_log(f"SKIP[{event}]: анти-спам min_gap")
            return
        if _tw_notify_event(event, detail, cfg, extra):
            events_sent.append(event)
            prev.setdefault("last_notify", {})[event] = now

    # ── Активные пробы нод (TCP host:port): недоступность/деградация.
    # Проба покрывает ВСЕ chain-ноды (не только selector — в отличие от
    # starve); события идут через общий _emit (фильтр/тихие/min_gap).
    # Мультитранспортность: в общий пул добавляются TCP-пробы exit-нод
    # Mieru (mita-порт) и health-вердикты AWG (lb.probes failover-тика);
    # Naive upstream — отдельная машина (naive_upstream_*) ──
    if cfg.get("probe", True):
        try:
            p_timeout = max(1, min(30, int(
                cfg.get("probe_timeout_sec") or 5)))
        except (TypeError, ValueError):
            p_timeout = 5
        results = {}
        if has_vless and casc["vless"].get("probe"):
            results.update(_tw_probe_nodes(chain_nodes, cfg) or {})
        if mieru_src and casc["mieru"].get("probe"):
            for host, port, tag in (mieru_src.get("probe_targets") or []):
                results[tag] = _tw_tcp_probe(host, port, p_timeout)
        if awg_src and casc["awg"].get("probe") \
                and awg_src.get("probe_results"):
            results.update(awg_src["probe_results"])
        pstate, probe_events = _tw_probe_update(
            {k: prev.get(k) for k in ("probe_fails", "probe_slow",
                                      "probe_status", "all_probes_down")
             if prev.get(k) is not None},
            results or None, cfg, now)
        prev.update(pstate)
        if probe_events:
            hm_state = _read_json(HM_STATE_FILE)
            last_traffic = dict(prev.get("last_traffic_ts") or {})
            for ev in probe_events:
                _emit(ev.get("event") or "",
                      _tw_probe_event_text(ev, names, keys, last_traffic,
                                           now, hm_state, _hostname()),
                      _tw_probe_event_extra(ev, names, keys))
        # Naive upstream-watcher: минимальная машина down/up
        if naive_src and casc["naive"].get("probe"):
            nd = naive_src["nodes"][TAG_PREFIX_NAIVE + "upstream"]
            nres = _tw_tcp_probe(nd["host"], nd["port"], p_timeout)
            nstate, naive_events = _tw_naive_probe_update(
                {"naive_fails": prev.get("naive_fails"),
                 "naive_status": prev.get("naive_status")},
                nres, cfg, now)
            prev.update(nstate)
            for nev in naive_events:
                _emit(nev.get("event") or "",
                      _tw_naive_event_text(nev, nd["key"]),
                      {"node": names.get(TAG_PREFIX_NAIVE + "upstream")
                       or nd["key"]})

    # ── Источник данных VLESS: Stats API ──
    stats_chain: dict = {}
    stats_ok = True
    fails_map = prev.get("stats_fails_map") or {}
    if has_vless:
        stats = _tw_query_stats()
        if stats is None:
            fails = int(fails_map.get("vless") or 0) + 1
            fails_map["vless"] = fails
            last_err = float(prev.get("last_stats_error_ts") or 0)
            if fails >= STATS_FAIL_THRESHOLD \
                    and (now - last_err) >= STATS_ERROR_RETRY_SEC:
                _emit("traffic_stats_error",
                      "xray api statsquery недоступен "
                      f"({STATS_FAIL_THRESHOLD} прогона подряд). Проверьте: "
                      "xray запущен; в config.json есть секции stats/api "
                      "(пересборка конфига ставит их автоматически).")
                prev["last_stats_error_ts"] = now
            prev["stats_fails_map"] = fails_map
            prev["stats_fails"] = fails
            _tw_log(f"WARN: Stats API недоступен (fails={fails})")
            if not awg_src and not mieru_src:
                # нет других источников: ранний выход (пробы уже
                # обработаны и сохранены — паттерн трилогии)
                _tw_save_state(prev)
                return {"acc": prev.get("acc") or {}, "dominant": None,
                        "events": events_sent, "stats_ok": False}
            stats_ok = bool(awg_src or mieru_src)
        else:
            # Счётчики цепочки (служебные теги — мимо)
            stats_chain = {t: v for t, v in stats.items() if t in names}
            fails_map["vless"] = 0
            prev["stats_fails"] = 0

    # ── Счётчики остальных каскадов + общий срез ──
    cur: dict = {}
    cur.update(stats_chain)
    cur.update((awg_src or {}).get("counters") or {})
    cur.update((mieru_src or {}).get("counters") or {})

    # ── Дельты за окно прогона + накопитель окна дайджеста ──
    deltas = _tw_deltas(prev.get("counters") or {}, cur)
    acc = _tw_acc_add(prev.get("acc") or {}, deltas)

    # Метки «когда нода последний раз несла трафик» — контекст в
    # down-уведе проб; теги вне текущего состава нод — прочистка
    lt = {t: v for t, v in (prev.get("last_traffic_ts") or {}).items()
          if t in names}
    for tag, d in deltas.items():
        if tag in names and _tw_bytes_of(d) > 0:
            lt[tag] = now
    prev["last_traffic_ts"] = lt

    # 1) Смена доминирующей ноды — ПО КАЖДОМУ каскаду отдельно
    # (пороги: доля %, мин. объём окна; для Mieru в conn-режиме объём
    # окна считается в соединениях: dominant_min_mb → мин. число коннектов)
    try:
        dom_share = float(cfg.get("dominant_min_share_pct") or 60)
    except (TypeError, ValueError):
        dom_share = 60.0
    try:
        dom_min_b = float(cfg.get("dominant_min_mb") or 50) * MB
    except (TypeError, ValueError):
        dom_min_b = 50 * MB

    dominant = None
    dominant_tags = prev.get("dominant_tags") or {}
    cascade_specs = [
        ("vless", "", None, "bytes"),
        ("awg", TAG_PREFIX_AWG, awg_src, "bytes"),
        ("mieru", TAG_PREFIX_MIERU, mieru_src,
         (mieru_src or {}).get("metric") or "bytes"),
    ]
    for kind, prefix, src, metric in cascade_specs:
        if kind == "vless" and not has_vless:
            continue
        if kind != "vless" and not src:
            continue
        if kind == "vless" and not stats_chain:
            continue
        min_total = dom_min_b
        if metric == "conn":
            try:
                min_total = max(10, float(cfg.get("dominant_min_mb")
                                          or 50))
            except (TypeError, ValueError):
                min_total = 50
        dom_k = _tw_dominant(_tw_cascade_acc(acc, prefix),
                             dom_share, min_total)
        prev_dom = dominant_tags.get(kind) or ""
        if dom_k and prev_dom and dom_k["tag"] != prev_dom:
            old_name = names.get(prev_dom) or prev_dom
            new_name = names.get(dom_k["tag"]) or dom_k["tag"]
            if kind == "vless":
                strat = _tw_strategy_label(_tw_live_balancer(),
                                           _read_json(SB_STATE_FILE))
            else:
                strat = str((src or {}).get("strategy") or
                            ("AWG-каскад" if kind == "awg"
                             else "Mieru-каскад"))
            _emit("traffic_dominant_change",
                  _tw_dominant_change_text(
                      strat, old_name, new_name, dom_k["share"],
                      dom_k["bytes"], dom_k["total"], metric),
                  extra={"strategy": strat, "node_from": old_name,
                         "node_to": new_name})
        if dom_k:
            dominant_tags[kind] = dom_k["tag"]
            if kind == "vless":
                dominant = dom_k
                prev["dominant_tag"] = dom_k["tag"]
    prev["dominant_tags"] = dominant_tags

    # 2) Starve-детект: нода в selector без трафика при живом окне
    # (для Mieru в conn-режиме недоступен: «объём окна» — соединения)
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
        selector += (awg_src or {}).get("selector") or []
        if mieru_src and mieru_src.get("metric") == "bytes":
            selector += mieru_src.get("selector") or []
        elif mieru_src:
            _tw_log("starve-детект для Mieru пропущен: "
                    "conn-метрика (включите IPAccounting для байтов)")
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
    # первый прогон лишь фиксирует базу — пустой дайджест не шлём).
    # Мультикаскадный прогон дайджест собирается СЕКЦИЯМИ по каскадам;
    # соло-VLESS — прежний формат без заголовка секции.
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
            incl_pct = bool(cfg.get("include_percent", True))
            incl_bytes = bool(cfg.get("include_bytes", True))
            multi = bool(awg_src or mieru_src)
            if not multi:
                live = _tw_live_balancer()
                strategy = live.get("strategy") or ""
                sb_line = _tw_smart_balancer_line(names, keys)
                text = _tw_snapshot_text(
                    acc, names, strategy, window_str, per_user_rows,
                    incl_pct, incl_bytes)
                if sb_line:
                    text += "\n" + sb_line
            else:
                sections: list[str] = []
                if has_vless and stats_chain:
                    live = _tw_live_balancer()
                    strategy = live.get("strategy") or ""
                    sb_line = _tw_smart_balancer_line(names, keys)
                    sec = _tw_snapshot_text(
                        _tw_cascade_acc(acc, ""), names, strategy,
                        window_str, per_user_rows, incl_pct, incl_bytes)
                    if sb_line:
                        sec += "\n" + sb_line
                    sections.append("VLESS-каскад\n" + sec)
                if awg_src:
                    sec = _tw_snapshot_text(
                        _tw_cascade_acc(acc, TAG_PREFIX_AWG), names,
                        str(awg_src.get("strategy") or ""),
                        window_str, [], incl_pct, incl_bytes,
                        "bytes", awg_src.get("dead") or None)
                    sections.append("AWG-каскад\n" + sec)
                if mieru_src:
                    sec = _tw_snapshot_text(
                        _tw_cascade_acc(acc, TAG_PREFIX_MIERU), names,
                        str(mieru_src.get("strategy") or ""),
                        window_str, [], incl_pct, incl_bytes,
                        mieru_src.get("metric") or "bytes",
                        mieru_src.get("dead") or None)
                    sections.append("Mieru-каскад\n" + sec)
                text = "\n────────────\n".join(sections)
            _emit("traffic_snapshot", text)
            # окно дайджеста закрыто: накопитель и доминирование сброшены
            acc = {}
            prev["last_snapshot_ts"] = now
            prev["dominant_tag"] = ""
            prev["dominant_tags"] = {}

    # ── Сохраняем состояние (внутрь конфиг-файла, ключ __state__ —
    # эксплуатационные данные рядом с настройками, атомарно одним файлом)
    prev["counters"] = cur
    prev["acc"] = acc
    prev["stats_fails_map"] = fails_map
    prev["stats_fails"] = int(fails_map.get("vless") or 0)
    prev["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    _tw_save_state(prev)

    return {"acc": acc, "dominant": dominant, "events": events_sent,
            "stats_ok": stats_ok}


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
    распределение поверх последнего накопителя + доминирующая нода
    + покрытие каскадов (мультитранспортность)."""
    cfg = load_cfg()
    installed = is_installed()
    interval = _installed_interval() if installed \
        else cfg.get("interval_min", DEFAULT_INTERVAL)
    st = _load_state()
    chain_nodes = st.get("chain_nodes") or []
    casc = _tw_cascades_cfg(cfg)
    awg_src = _tw_awg_source() if casc["awg"].get("traffic") else None
    mieru_src = (_tw_mieru_source(casc["mieru"].get("bytes_source"))
                 if casc["mieru"].get("traffic") else None)
    naive_src = _tw_naive_source()
    aliases = cfg.get("aliases") or {}
    names, keys = _tw_tag_names(chain_nodes, aliases)
    for src in (awg_src, mieru_src, naive_src):
        for tag, nd in ((src or {}).get("nodes") or {}).items():
            nm = str(aliases.get(tag) or aliases.get(nd.get("key"))
                     or nd.get("name") or tag).strip()
            names[tag] = nm or tag
            keys[tag] = nd.get("key") or tag
    live = _tw_live_balancer()
    stats = _tw_query_stats()
    state = _read_json(TW_CFG_FILE).get("__state__") or {}
    acc = state.get("acc") or {}
    # если Stats API жив, но накопитель пуст (первый прогон) — покажем
    # мгновенные счётчики как справку «сколько всего прошло через ноды»
    vless_acc = _tw_cascade_acc(acc, "")
    rows = _tw_distribution_rows(
        vless_acc if vless_acc else {
            t: v for t, v in (stats or {}).items() if t in names},
        names, True, True) if chain_nodes else []
    # секции остальных каскадов поверх накопителя (или счётчиков)
    if awg_src:
        a_acc = _tw_cascade_acc(acc, TAG_PREFIX_AWG) \
            or (awg_src.get("counters") or {})
        a_rows = _tw_distribution_rows(
            a_acc, names, True, True, "bytes",
            awg_src.get("dead") or None)
        if a_rows:
            rows.append("AWG-каскад ({0}):".format(
                awg_src.get("strategy") or "—"))
            rows.extend(a_rows)
    if mieru_src:
        m_acc = _tw_cascade_acc(acc, TAG_PREFIX_MIERU) \
            or (mieru_src.get("counters") or {})
        m_rows = _tw_distribution_rows(
            m_acc, names, True, True,
            mieru_src.get("metric") or "bytes",
            mieru_src.get("dead") or None)
        if m_rows:
            metric_lbl = "соединения" if mieru_src.get("metric") == "conn" \
                else "байты (IPAccounting)"
            rows.append("Mieru-каскад ({0}, {1}):".format(
                mieru_src.get("strategy") or "—", metric_lbl))
            rows.extend(m_rows)
    if naive_src:
        nd = naive_src["nodes"][TAG_PREFIX_NAIVE + "upstream"]
        rows.append(f"Naive-каскад: upstream {nd['key']} "
                    f"(проба TCP, без счётчиков)")
    dom_tag = state.get("dominant_tag") or ""
    dominant_name = names.get(dom_tag) or dom_tag if dom_tag else ""
    casc_info = {
        "vless": {"on": bool(chain_nodes) and bool(casc["vless"]["traffic"]),
                  "count": len(chain_nodes),
                  "strategy": _tw_strategy_label(
                      live, _read_json(SB_STATE_FILE))},
        "awg": {"on": bool(awg_src),
                "count": len((awg_src or {}).get("nodes") or {}),
                "strategy": (awg_src or {}).get("strategy") or ""},
        "mieru": {"on": bool(mieru_src),
                  "count": len((mieru_src or {}).get("nodes") or {}),
                  "strategy": (mieru_src or {}).get("strategy") or "",
                  "metric": (mieru_src or {}).get("metric") or ""},
        "naive": {"on": bool(naive_src), "count": 1 if naive_src else 0,
                  "strategy": "upstream"},
    }
    return (cfg, installed, interval, names, live, stats, rows,
            dominant_name, casc_info, casc)


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
         dominant_name, casc_info, casc) = _tw_menu_status_block()
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
        elif casc_info["awg"]["on"] or casc_info["mieru"]["on"] \
                or casc_info["naive"]["on"]:
            api_str = f"{C['DIM']}— (нет VLESS-каскада){C['NC']}"
        else:
            api_str = f"{C['RED']}нет в конфиге (пересоберите конфиг){C['NC']}"
        strategy = _tw_strategy_label(live, _read_json(SB_STATE_FILE))

        def _casc_cell(kind: str, label: str) -> str:
            ci = casc_info[kind]
            if ci["on"]:
                extra = ""
                if kind == "mieru" and ci.get("metric") == "conn":
                    extra = ", соед."
                return (f"{C['GREEN']}{label} ✓ {ci['count']}{extra}{C['NC']}")
            return f"{C['DIM']}{label} —{C['NC']}"

        print()
        _box_top("🧭  НАБЛЮДАТЕЛЬ ТРАФИКА EXIT-НОД")
        _box_row("  Уведомления о том, ЧЕРЕЗ КАКУЮ ноду реально идёт трафик.")
        _box_row("  Покрытие — ВСЕ каскады: VLESS (Stats API) · AWG (слоты")
        _box_row("  awg1..N, ip -s link) · Mieru (IPAccounting / соед.) ·")
        _box_row("  Naive (проба upstream). Режимы — roundRobin / leastPing /")
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
        _box_row(f"  Каскады:    {_casc_cell('vless', 'VLESS')} · "
                 f"{_casc_cell('awg', 'AWG')} · "
                 f"{_casc_cell('mieru', 'Mieru')} · "
                 f"{_casc_cell('naive', 'Naive')}")
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
            _box_row(f"  {C['DIM']}Exit-ноды не настроены (каскады не "
                     f"развёрнуты){C['NC']}")
        _box_sep()
        nf = cfg.get("notify") or {}
        _box_row(f"  События: доминирование="
                 f"{'вкл' if nf.get('traffic_dominant_change', True) else 'выкл'}"
                 f"  дайджест="
                 f"{'вкл' if nf.get('traffic_snapshot', True) else 'выкл'}"
                 f"  голод ноды="
                 f"{'вкл' if nf.get('traffic_node_starved', True) else 'выкл'}"
                 f"  ошибка API="
                 f"{'вкл' if nf.get('traffic_stats_error', True) else 'выкл'}"
                 f"  недоступна="
                 f"{'вкл' if nf.get('traffic_node_down', True) else 'выкл'}"
                 f"  тупит="
                 f"{'вкл' if nf.get('traffic_node_degraded', True) else 'выкл'}"
                 f"  восстановлена="
                 f"{'вкл' if nf.get('traffic_node_up', True) else 'выкл'}")
        qh = cfg.get("quiet_hours") or {}
        qh_str = f"{qh.get('from', '')}–{qh.get('to', '')}" \
            if qh.get("from") else "нет"
        _box_row(f"  Тихие часы: {qh_str}   мин.пауза: {cfg.get('min_gap_min')} мин"
                 f"   дайджест: раз в {cfg.get('snapshot_hours') or 0} ч")
        _box_row(f"  Доминирование: доля ≥ {cfg.get('dominant_min_share_pct')}%"
                 f" от {cfg.get('dominant_min_mb')} МБ"
                 f"   голод ноды: {cfg.get('starve_hours') or 0} ч"
                 f"   per-user: {'вкл' if cfg.get('per_user') else 'выкл'}")
        _box_row(f"  Пробы нод (TCP): "
                 f"{'вкл' if cfg.get('probe', True) else 'выкл'}"
                 f"   таймаут: {cfg.get('probe_timeout_sec', 5)} сек"
                 f"   недоступна после {cfg.get('probe_fails', 2)} неудач"
                 f"   RTT-порог: {cfg.get('probe_degraded_ms', 500)} мс")
        _box_sep()
        _box_item("C", "Проверить сейчас (без ожидания cron)")
        _box_item("T", "Тест-уведомление (все типы событий)")
        _box_item("K", "Каскады (VLESS/AWG/Mieru/Naive): вкл/выкл трафик/пробы")
        _box_item("S", "Настройки уведомлений (события / паузы / тихие часы)")
        _box_item("D", "Пороги детекции (доминирование / голод / пробы нод)")
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
            print(f"  {C['DIM']}Опрашиваю источники и считаю дельты...{C['NC']}")
            res = run_once(force=True)
            if res.get("events"):
                for ev in res["events"]:
                    _box_ok(f"Отправлено: {ev}")
            if not res.get("stats_ok"):
                _box_warn("Источники данных недоступны — событие "
                          "traffic_stats_error уйдёт после 3-го неудачного "
                          "прогона подряд")
            elif not res.get("events"):
                _box_ok("Изменений нет (счётчики и накопитель обновлены)")
            input(f"{C['CYAN']}Нажмите Enter...{C['NC']}")

        elif ch == "T":
            # тест-уведа смены ноды — ровно тот текст, что уйдёт в бою
            # (режим + откуда → куда из живых нод), помеченный как тест
            strat = _tw_strategy_label(live, _read_json(SB_STATE_FILE))
            nl = list(names.values())
            if len(nl) >= 2:
                dom_txt = _tw_dominant_change_text(
                    strat, nl[0], nl[-1], 72.0, 720 * MB, 1000 * MB)
                dom_txt += "\n<i>🔔 тест-уведомление (ноды условные)</i>"
            else:
                dom_txt = ("🔔 Тест наблюдателя: смена доминирующей ноды "
                           "(нужно ≥ 2 exit-ноды)")
            for ev, txt in (
                ("traffic_dominant_change", dom_txt),
                ("traffic_snapshot",
                 "🔔 Тест наблюдателя: дайджест распределения трафика"),
                ("traffic_node_starved",
                 "🔔 Тест наблюдателя: нода без трафика 6 ч"),
                ("traffic_stats_error",
                 "🔔 Тест наблюдателя: Stats API недоступен"),
                ("traffic_node_down",
                 "🔔 Тест наблюдателя: нода недоступна (TCP-проба)"),
                ("traffic_node_degraded",
                 "🔔 Тест наблюдателя: нода тупит (RTT выше порога)"),
                ("traffic_node_up",
                 "🔔 Тест наблюдателя: нода восстановлена"),
                ("naive_upstream_down",
                 "🔔 Тест наблюдателя: Naive upstream недоступен "
                 "(TCP-проба не проходит)"),
                ("naive_upstream_up",
                 "🔔 Тест наблюдателя: Naive upstream восстановлен"),
            ):
                ok = _tw_notify_event(ev, txt, cfg)
                print(f"  {'✅' if ok else '⚠️'} {ev}")
            input(f"{C['CYAN']}Нажмите Enter...{C['NC']}")

        elif ch == "S":
            _menu_settings(cfg)
            save_cfg(cfg)

        elif ch == "K":
            _menu_cascades(cfg)
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
        "traffic_dominant_change": "Смена доминирующей ноды (уведа: режим + откуда → куда)",
        "traffic_snapshot":        "Дайджест распределения трафика (все каскады)",
        "traffic_node_starved":    "Нода в ротации без трафика (голод)",
        "traffic_stats_error":     "Stats API недоступен",
        "traffic_node_down":       "Нода недоступна (TCP-проба не проходит)",
        "traffic_node_degraded":   "Нода тупит (RTT пробы выше порога)",
        "traffic_node_up":         "Нода восстановлена (проба снова ОК)",
        "naive_upstream_down":     "Naive: upstream недоступен (каскад без выхода)",
        "naive_upstream_up":       "Naive: upstream восстановлен",
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
        _box_row(f"  {len(EVENTS) + 1}. Анти-спам: мин. пауза между уведами — "
                 f"{C['BOLD']}{cfg.get('min_gap_min', 10)} мин{C['NC']}")
        _box_row(f"  {len(EVENTS) + 2}. Тихие часы: {qh.get('from') or '—'} … {qh.get('to') or '—'} "
                 f"{C['DIM']}(пусто = выкл){C['NC']}")
        _box_row(f"  {len(EVENTS) + 3}. Дайджест: раз в {C['BOLD']}{cfg.get('snapshot_hours', 0) or 0}"
                 f" ч{C['NC']} {C['DIM']}(0 = выкл){C['NC']}")
        _box_row(f"  {len(EVENTS) + 4}. Chat ID override: {cfg.get('chat_id_override') or 'основной'}")
        _box_row(f"  {len(EVENTS) + 5}. Наблюдатель: "
                 f"{'включён' if cfg.get('enabled', True) else 'выключен'}")
        _box_row(f"  {len(EVENTS) + 6}. Дайджест: проценты="
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
        if ch.isdigit() and 1 <= int(ch) <= len(EVENTS):
            ev = EVENTS[int(ch) - 1]
            nf[ev] = not nf.get(ev, True)
        elif ch == str(len(EVENTS) + 1):
            raw = input("  Мин. пауза, мин (Enter = без изменений): ").strip()
            if raw.isdigit():
                cfg["min_gap_min"] = int(raw)
        elif ch == str(len(EVENTS) + 2):
            f = input("  Тихие часы — от (ЧЧ:ММ, Enter = выкл): ").strip()
            t = input("  Тихие часы — до (ЧЧ:ММ): ").strip()
            qh["from"], qh["to"] = (f if f else ""), (t if f else "")
        elif ch == str(len(EVENTS) + 3):
            raw = input("  Интервал дайджеста, часов (0 = выкл): ").strip()
            if raw.isdigit():
                cfg["snapshot_hours"] = int(raw)
        elif ch == str(len(EVENTS) + 4):
            raw = input("  Chat ID для уведов наблюдателя (Enter = основной): ").strip()
            cfg["chat_id_override"] = raw
        elif ch == str(len(EVENTS) + 5):
            cfg["enabled"] = not cfg.get("enabled", True)
            _box_ok("Наблюдатель " + ("включён" if cfg["enabled"] else "выключен"))
            input(f"{C['CYAN']}Нажмите Enter...{C['NC']}")
        elif ch == str(len(EVENTS) + 6):
            cfg["include_percent"] = not cfg.get("include_percent", True)
            cfg["include_bytes"] = not cfg.get("include_bytes", True)
            _box_ok(f"Дайджест: проценты="
                    f"{'да' if cfg['include_percent'] else 'нет'}, "
                    f"байты={'да' if cfg['include_bytes'] else 'нет'}")
            input(f"{C['CYAN']}Нажмите Enter...{C['NC']}")


def _menu_thresholds(cfg: dict) -> None:
    """Пороги детекции: доминирование (доля %, мин. объём окна),
    голод ноды (часы, мин. трафик окна), активные пробы нод
    (TCP host:port — недоступность/деградация)."""
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
        _box_row(f"  5. Пробы нод (TCP): {C['BOLD']}"
                 f"{'вкл' if cfg.get('probe', True) else 'выкл'}{C['NC']} "
                 f"{C['DIM']}(недоступность/деградация — все chain-ноды){C['NC']}")
        _box_row(f"  6. Таймаут пробы: {C['BOLD']}"
                 f"{cfg.get('probe_timeout_sec', 5)} сек{C['NC']} "
                 f"{C['DIM']}(1-30){C['NC']}")
        _box_row(f"  7. Неудач подряд → «нода недоступна»: {C['BOLD']}"
                 f"{cfg.get('probe_fails', 2)}{C['NC']} {C['DIM']}(1-10){C['NC']}")
        _box_row(f"  8. Порог RTT деградации: {C['BOLD']}"
                 f"{cfg.get('probe_degraded_ms', 500)} мс{C['NC']} "
                 f"{C['DIM']}(0 = выкл; 0-5000){C['NC']}")
        _box_row(f"  9. Медленных проб подряд → деградация: {C['BOLD']}"
                 f"{cfg.get('probe_degraded_fails', 2)}{C['NC']} "
                 f"{C['DIM']}(1-10){C['NC']}")
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
        elif ch == "5":
            cfg["probe"] = not cfg.get("probe", True)
            _box_ok("Пробы нод " + ("включены" if cfg["probe"] else "выключены"))
        elif ch == "6":
            raw = input("  Таймаут TCP-пробы, сек (1-30): ").strip()
            if raw.isdigit() and 1 <= int(raw) <= 30:
                cfg["probe_timeout_sec"] = int(raw)
        elif ch == "7":
            raw = input("  Неудач проб подряд → «нода недоступна» (1-10): ").strip()
            if raw.isdigit() and 1 <= int(raw) <= 10:
                cfg["probe_fails"] = int(raw)
        elif ch == "8":
            raw = input("  Порог RTT деградации, мс (0 = выкл, 0-5000): ").strip()
            if raw.isdigit() and 0 <= int(raw) <= 5000:
                cfg["probe_degraded_ms"] = int(raw)
        elif ch == "9":
            raw = input("  Медленных проб подряд → деградация (1-10): ").strip()
            if raw.isdigit() and 1 <= int(raw) <= 10:
                cfg["probe_degraded_fails"] = int(raw)


def _menu_cascades(cfg: dict) -> None:
    """Покрытие каскадов (мультитранспортность): вкл/выкл пассивного
    трафика и проб для VLESS/AWG/Mieru/Naive; для Mieru — источник
    байтов (IPAccounting / соединения) и включение IPAccounting."""
    from chimera.modules.box_renderer import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_back,
        _box_ok, _box_warn)
    C = _colors()
    while True:
        os.system("clear")
        casc = _tw_cascades_cfg(cfg)
        cfg["cascades"] = casc
        awg_src = _tw_awg_source()
        mieru_src = _tw_mieru_source(casc["mieru"].get("bytes_source"))
        naive_src = _tw_naive_source()
        mieru_metric = (mieru_src or {}).get("metric") or ""
        print()
        _box_top("🛰  КАСКАДЫ НАБЛЮДАТЕЛЯ (ПОКРЫТИЕ)")
        _box_row(f"  {C['DIM']}Каждый каскад — свой источник счётчиков;")
        _box_row(f"  {C['DIM']}события/пороги/шаблоны — общие.{C['NC']}")
        _box_sep()
        v_traffic = casc["vless"]["traffic"]
        _box_row(f"  1. VLESS-каскад (Stats API):      "
                 f"трафик {C['GREEN'] if v_traffic else C['DIM']}"
                 f"{'вкл' if v_traffic else 'выкл'}{C['NC']}   "
                 f"пробы {'вкл' if casc['vless']['probe'] else 'выкл'}")
        awg_cnt = len((awg_src or {}).get("nodes") or {})
        _box_row(f"  2. AWG-каскад (ip -s link слотов): "
                 f"трафик {C['GREEN'] if casc['awg']['traffic'] else C['DIM']}"
                 f"{'вкл' if casc['awg']['traffic'] else 'выкл'}{C['NC']}   "
                 f"пробы {'вкл' if casc['awg']['probe'] else 'выкл'}"
                 f" {C['DIM']}({awg_cnt} нод){C['NC']}")
        mieru_cnt = len((mieru_src or {}).get("nodes") or {})
        src_lbl = {"auto": "auto", "ipaccounting": "IPAccounting",
                   "conn": "соединения"}.get(
                       casc["mieru"].get("bytes_source") or "auto", "auto")
        if mieru_metric == "conn":
            eff = f"{C['YELLOW']}соединения{C['NC']}"
        elif mieru_metric == "bytes":
            eff = f"{C['GREEN']}байты (IPAccounting){C['NC']}"
        else:
            eff = f"{C['DIM']}—{C['NC']}"
        _box_row(f"  3. Mieru-каскад (балансировка):   "
                 f"трафик {C['GREEN'] if casc['mieru']['traffic'] else C['DIM']}"
                 f"{'вкл' if casc['mieru']['traffic'] else 'выкл'}{C['NC']}   "
                 f"пробы {'вкл' if casc['mieru']['probe'] else 'выкл'}"
                 f" {C['DIM']}({mieru_cnt} exit){C['NC']}")
        _box_row(f"     источник байтов: {src_lbl} → фактически: {eff}")
        _box_row(f"  4. Naive-каскад (upstream):       "
                 f"пробы {C['GREEN'] if casc['naive']['probe'] else C['DIM']}"
                 f"{'вкл' if casc['naive']['probe'] else 'выкл'}{C['NC']} "
                 f"{C['DIM']}(naive_upstream_down/up; счётчиков нет){C['NC']}")
        if naive_src:
            nd = naive_src["nodes"][TAG_PREFIX_NAIVE + "upstream"]
            _box_row(f"     upstream: {C['BOLD']}{nd['key']}{C['NC']}")
        _box_row(f"  {C['DIM']}1P/2P/3P — тумблер проб соответствующего"
                 f" каскада{C['NC']}")
        _box_sep()
        _box_row(f"  5. Mieru: источник байтов — "
                 f"{casc['mieru'].get('bytes_source') or 'auto'} "
                 f"{C['DIM']}(auto/ipaccounting/conn){C['NC']}")
        _box_row(f"  6. Mieru: IPAccounting на юнитах mieru-hop@* — "
                 f"включить (точные байты)")
        _box_row(f"  7. Mieru: IPAccounting — выключить")
        _box_row(f"  {C['DIM']}IPAccounting — systemd set-property: изменение")
        _box_row(f"  {C['DIM']}конфигурации юнитов (persist drop-in), действие")
        _box_row(f"  {C['DIM']}явное и обратимое; starvation/starve-детект")
        _box_row(f"  {C['DIM']}Mieru работает только на байтах.{C['NC']}")
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{C['CYAN']}Выбор: {C['NC']}").strip().upper()
        except KeyboardInterrupt:
            return
        if ch in ("0", "Q", ""):
            return
        if ch == "1":
            casc["vless"]["traffic"] = not casc["vless"]["traffic"]
        elif ch == "2":
            casc["awg"]["traffic"] = not casc["awg"]["traffic"]
        elif ch == "3":
            casc["mieru"]["traffic"] = not casc["mieru"]["traffic"]
        elif ch == "4":
            casc["naive"]["probe"] = not casc["naive"]["probe"]
        elif ch == "2P":
            casc["awg"]["probe"] = not casc["awg"]["probe"]
        elif ch == "3P":
            casc["mieru"]["probe"] = not casc["mieru"]["probe"]
        elif ch == "1P":
            casc["vless"]["probe"] = not casc["vless"]["probe"]
        elif ch == "5":
            order = ["auto", "ipaccounting", "conn"]
            cur = order.index(
                casc["mieru"].get("bytes_source") or "auto")
            casc["mieru"]["bytes_source"] = order[(cur + 1) % len(order)]
            _box_ok(f"Источник байтов Mieru: "
                    f"{casc['mieru']['bytes_source']}")
            input(f"{C['CYAN']}Нажмите Enter...{C['NC']}")
        elif ch == "6":
            raw = input("  Включить IPAccounting на юнитах mieru-hop@*? "
                        "(y/N): ").strip().lower()
            if raw == "y":
                ok, msg = _tw_mieru_set_ipaccounting(True)
                _box_ok(msg) if ok else _box_warn(msg)
                input(f"{C['CYAN']}Нажмите Enter...{C['NC']}")
        elif ch == "7":
            raw = input("  Выключить IPAccounting? (y/N): ").strip().lower()
            if raw == "y":
                ok, msg = _tw_mieru_set_ipaccounting(False)
                _box_ok(msg) if ok else _box_warn(msg)
                input(f"{C['CYAN']}Нажмите Enter...{C['NC']}")


def _menu_aliases(cfg: dict) -> None:
    """Алиасы нод (host:port → имя в уведах) + per-user разбор.
    Ноды ВСЕХ каскадов: VLESS (host:port), AWG/Mieru/Naive (каскадный
    тег awg:pl1 / mieru:de1 / naive:upstream или host:port)."""
    from chimera.modules.box_renderer import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_back, _box_ok)
    C = _colors()
    while True:
        os.system("clear")
        st = _load_state()
        chain_nodes = st.get("chain_nodes") or []
        aliases = cfg.setdefault("aliases", {})
        # собираем ноды всех каскадов: [(ключ для aliases, отображение)]
        entries: list = []
        for i, nd in enumerate(chain_nodes, 1):
            host = str((nd or {}).get("host") or "").strip()
            if not host:
                continue
            port = int((nd or {}).get("port") or 443)
            entries.append((f"{host}:{port}", "VLESS"))
        casc = _tw_cascades_cfg(cfg)
        for tag, nd in ((_tw_awg_source() or {}).get("nodes") or {}).items():
            entries.append((tag, f"AWG · {nd.get('key')}"))
        for tag, nd in ((_tw_mieru_source(
                casc["mieru"].get("bytes_source")) or {}).get("nodes")
                or {}).items():
            entries.append((tag, f"Mieru · {nd.get('key')}"))
        for tag, nd in ((_tw_naive_source() or {}).get("nodes") or {}).items():
            entries.append((tag, f"Naive · {nd.get('key')}"))
        print()
        _box_top("🏷️  АЛИАСЫ НОД И ПОЛЬЗОВАТЕЛИ")
        _box_row(f"  {C['DIM']}Алиас подставляется в уведы вместо host:port —")
        _box_row(f"  {C['DIM']}например «RU1», «дом-кино», «pl-fast».{C['NC']}")
        _box_sep()
        if entries:
            for i, (key, hint) in enumerate(entries, 1):
                alias = aliases.get(key) or aliases.get(
                    key.split(" · ")[0]) or ""
                shown = f"{C['GREEN']}{alias}{C['NC']}" if alias \
                    else f"{C['DIM']}—{C['NC']}"
                _box_row(f"  {i}. <code>{key}</code> {C['DIM']}({hint})"
                         f"{C['NC']} → {shown}")
        else:
            _box_row(f"  {C['DIM']}Ноды каскадов не найдены{C['NC']}")
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
        elif ch.isdigit() and 1 <= int(ch) <= len(entries):
            key = entries[int(ch) - 1][0]
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
    """Редактирование шаблонов сообщений (плейсхолдеры {host} {ts}
    {detail}; для смены ноды также {strategy} {node_from} {node_to})."""
    from chimera.modules.box_renderer import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_back, _box_ok)
    C = _colors()
    tpl = cfg.setdefault("templates", dict(DEFAULT_TEMPLATES))
    while True:
        os.system("clear")
        print()
        _box_top("📝  ШАБЛОНЫ СООБЩЕНИЙ (HTML)")
        _box_row(f"  {C['DIM']}Плейсхолдеры: {{host}} {{ts}} {{detail}}; для смены")
        _box_row(f"  {C['DIM']}ноды ещё {{strategy}} {{node_from}} {{node_to}}{C['NC']}")
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
