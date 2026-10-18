"""
exit_switch_watcher.py — наблюдатель переключений exit-нод с TG-уведомлениями.

Контекст (живой кейс окт.2026 №8): раньше ротацией exit-нод владел
SmartBalancer — он патчил активную ноду и слал node_connect при каждом
переключении. После перехода на нативный chain-balancer Xray
(routing.balancers + selector из N тегов, стратегия roundRobin) ротацию
делает сам Xray-core, SmartBalancer только наблюдает («патч адреса
пропущен») — событие node_connect перестало возникать, и уведомления о
переключениях пропали. roundRobin выбирает outbound на каждое СОЕДИНЕНИЕ,
поэтому «переключение активной ноды» как единичное событие не существует —
осмысленные события описывают ИЗМЕНЕНИЯ СОСТАВА ротации и режимные
переключения. Этот модуль — единая точка наблюдения:

  • эффективный состав ротации = selector живого конфига ∩ chain_nodes,
    фильтруется по карантину SmartBalancer и последнему вердикту
    Health Monitor (DOWN-нода не участвует в ротации до восстановления);
  • exit_set_change   — нода выпала из ротации / вернулась (причина в тексте);
  • exit_switch       — режимное переключение: сменилась активная нода
    (single-pick режимы: pinned / без балансировщика), сменилась стратегия
    балансировки или pin снят/поставлен;
  • exit_ip_change    — (опционально, probe_exits) exit-IP ноды изменился
    (проверяется full-path зондом chain_relay, кейс №3: зонды честные
    REALITY, не бан-фуд);
  • exit_snapshot     — периодический дайджест: состав ротации, стратегия,
    статусы нод, латентности из проб балансировщика.

Отправка идёт через tg_bot.tg_notify_event() — событие уважает фильтр
из меню «Telegram-уведомления» (пункт «Включить/выключить отдельные
события») и ключ proxy в telegram.json. Fallback — прямая отправка
(паттерн node_health_monitor), если tg_bot недоступен.

Кастомизация — /var/lib/xray-installer/exit_switch_watcher.json
(см. DEFAULTS): интервал cron, вкл/выкл каждого типа событий, quiet-часы,
анти-спам min_gap, шаблоны сообщений с плейсхолдерами, отдельный chat_id.

Публичный API:
    run_once()                        → dict   — одна итерация наблюдения
    load_cfg() / save_cfg()           → dict/None
    is_installed()                    → bool
    install_watcher(interval_min)     → (bool, str)
    uninstall_watcher()               → (bool, str)
    do_exit_watcher_menu()            → None   — интерактивное меню
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

# ── Константы ─────────────────────────────────────────────────────────────────
STATE_FILE    = Path("/var/lib/xray-installer/state.json")
SB_STATE_FILE = Path("/var/lib/xray-installer/smart_balancer.json")
HM_STATE_FILE = Path("/var/lib/xray-installer/node-health-state.json")
EW_CFG_FILE   = Path("/var/lib/xray-installer/exit_switch_watcher.json")
EW_LOG_FILE   = Path("/var/log/xray-exit-switch-watcher.log")
CRON_FILE     = Path("/etc/cron.d/xray-exit-watcher")
CRON_SCRIPT   = Path("/usr/local/bin/xray-exit-watcher.sh")
XRAY_CFG_CANDIDATES = (Path("/etc/xray/config.json"),
                       Path("/usr/local/etc/xray/config.json"))

DEFAULT_INTERVAL = 15   # минут
DEFAULT_SNAPSHOT_HOURS = 12

# События, которые умеет слать наблюдатель (ключи фильтра в telegram.json)
EVENTS = ("exit_set_change", "exit_switch", "exit_ip_change", "exit_snapshot")

# Дефолтные шаблоны (HTML для parse_mode=HTML). Плейсхолдеры:
#   {host} — короткое имя этого сервера; {ts} — локальное время;
#   {detail} — тело события; {node} — нода, о которой событие.
DEFAULT_TEMPLATES = {
    "exit_set_change":
        "🔄 <b>[{host}]</b> Изменение состава ротации exit-нод\n{detail}\n<i>{ts}</i>",
    "exit_switch":
        "🔀 <b>[{host}]</b> Переключение exit-ноды\n{detail}\n<i>{ts}</i>",
    "exit_ip_change":
        "🌐 <b>[{host}]</b> Смена exit-IP ноды\n{detail}\n<i>{ts}</i>",
    "exit_snapshot":
        "📊 <b>[{host}]</b> Снапшот ротации exit-нод\n{detail}\n<i>{ts}</i>",
}

DEFAULTS = {
    "enabled":          True,
    "interval_min":     DEFAULT_INTERVAL,
    "notify":           {ev: True for ev in EVENTS},
    "snapshot_hours":   DEFAULT_SNAPSHOT_HOURS,   # 0 = дайджест выключен
    "probe_exits":      False,     # активные full-path зонды (exit_ip_change)
    "probe_timeout_sec": 15,
    "min_gap_min":      10,        # анти-спам: мин. пауза между уведами типа
    "quiet_hours":      {"from": "", "to": ""},   # "" = нет тихих часов
    "include_metrics":  True,      # латентности из проб балансировщика
    "chat_id_override": "",        # "" = chat_id из telegram.json
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

def _ew_merge_cfg(defaults: dict, stored: dict) -> dict:
    """Глубокое слияние сохранённого конфига с дефолтами: отсутствующие
    ключи добираются из DEFAULTS (вложенные dict — рекурсивно; список
    notify всегда полный: новые типы событий по умолчанию ВКЛ).
    Чистая функция."""
    out = dict(defaults)
    for k, v in (stored or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _ew_merge_cfg(out[k], v)
        else:
            out[k] = v
    # notify: гарантируем все типы событий (добавленные версиями позже)
    if isinstance(out.get("notify"), dict):
        nf = dict(out["notify"])
        for ev in EVENTS:
            nf.setdefault(ev, True)
        out["notify"] = nf
    return out


def _ew_quiet(now_hhmm: str, quiet: dict) -> bool:
    """True, если сейчас тихие часы (уведы подавляются).
    now_hhmm — 'HH:MM'. quiet = {'from': '23:00', 'to': '08:00'}
    ('' — выкл). Интервал через полночь поддерживается.
    Чистая функция."""
    qf = str((quiet or {}).get("from") or "").strip()
    qt = str((quiet or {}).get("to") or "").strip()
    if not qf or not qt or qf == qt:
        return False
    try:
        n = _hhmm_to_min(now_hhmm)
        f = _hhmm_to_min(qf)
        t = _hhmm_to_min(qt)
    except (ValueError, TypeError):
        return False
    if f < t:
        return f <= n < t
    # через полночь: 23:00-08:00 = [23:00..24:00) ∪ [00:00..08:00)
    return n >= f or n < t


def _hhmm_to_min(hhmm: str) -> int:
    h, m = str(hhmm).split(":")
    return int(h) * 60 + int(m)


def _ew_gap_ok(last_ts: float, now_ts: float, gap_min) -> bool:
    """Анти-спам: True, если с last_ts прошло >= gap_min минут
    (gap_min <= 0 / нет last_ts — всегда True). Чистая функция."""
    try:
        gap = float(gap_min or 0)
    except (TypeError, ValueError):
        gap = 0.0
    if gap <= 0 or not last_ts:
        return True
    return (now_ts - float(last_ts)) >= gap * 60.0


def _ew_render(template: str, **kw) -> str:
    """Безопасный рендер шаблона: подставляет только известные
    плейсхолдеры, {фигурные} скобки без подстановки не ломает.
    Чистая функция."""
    out = str(template or "")
    for k, v in kw.items():
        out = out.replace("{" + k + "}", str(v))
    return out


def _ew_effective_set(chain_nodes: list, selector_tags: list,
                      lb_nodes: list, quarantine: dict,
                      hm_state: dict, pinned_idx) -> dict:
    """Эффективный состав ротации.

    Возвращает dict: host:port → {'in_set': bool, 'reasons': [str], ...}
    для каждой chain-ноды. Нода ВНУТРИ состава, если:
      • она входит в selector живого конфига (когда selector задан;
        пустой selector = ротации нет вообще — все not_in_set);
      • если задан LB-состав (chain_lb_nodes) — только ноды из него;
      • не в карантине SmartBalancer (quarantine: host:port → True);
      • не DOWN по последнему вердикту HM (hm_state: host:port →
        {'up': False}) — вердикта нет (HM не ставили) = не исключаем.
    pinned_idx >= 0 — закреплённая нода: её индекс в полном списке,
    в этом случае состав = одна нода (плюс причины «pinned»).
    Чистая функция."""
    sel = {str(t).strip() for t in (selector_tags or []) if str(t).strip()}
    lb = {(h or "").strip().lower()
          for h in (lb_nodes or []) if (h or "").strip()}
    out: dict = {}

    for i, nd in enumerate(chain_nodes or []):
        host = str((nd or {}).get("host") or "").strip()
        port = int((nd or {}).get("port") or 443)
        if not host:
            continue
        key = f"{host}:{port}"
        reasons: list[str] = []

        if pinned_idx is not None and isinstance(pinned_idx, int) \
                and not isinstance(pinned_idx, bool) and pinned_idx >= 0:
            if i == pinned_idx:
                reasons.append("pinned")
            else:
                reasons.append("не активна (pinned-режим)")

        if sel and key not in sel and host not in sel:
            # selector содержит теги chain-exit-N, а не host:port —
            # сопоставляем по индексу (tag chain-exit-(i+1))
            if f"chain-exit-{i + 1}" not in sel:
                reasons.append("вне selector балансировщика")

        if lb and host.lower() not in lb:
            reasons.append("вне LB-состава (chain_lb_nodes)")

        if (quarantine or {}).get(key):
            reasons.append("карантин SmartBalancer")

        hm = (hm_state or {}).get(key) or {}
        if hm.get("up") is False:
            reasons.append("DOWN (Health Monitor)")

        in_set = not reasons or reasons == ["pinned"]
        out[key] = {"in_set": in_set, "reasons": reasons,
                    "host": host, "port": port, "idx": i,
                    "via": str((nd or {}).get("via") or "")}
    return out


def _ew_diff_set(old_set: dict, new_set: dict) -> list[dict]:
    """Изменения состава ротации между двумя снимками эффективного состава.
    Возвращает список {'key', 'kind': 'added'|'removed'|'reasons',
    'reasons': [str]} — только фактические изменения (added/removed);
    смена причин не-in_set нод (карантин→DOWN) не считается событием.
    Чистая функция."""
    changes = []
    for key, nd in (new_set or {}).items():
        was = (old_set or {}).get(key, {}).get("in_set", None)
        now = nd.get("in_set", False)
        if was is None or was == now:
            continue
        changes.append({"key": key, "kind": "added" if now else "removed",
                        "reasons": nd.get("reasons", [])})
    return changes


def _ew_switch_kind(prev: dict, cur: dict) -> str:
    """Классификация режимного переключения между снимками state
    ( {'strategy', 'active_node_idx', 'pinned', 'selector'} ):
    'active'  — сменилась активная нода (single-pick);
    'strategy'— сменилась стратегия балансировки;
    'pin'     — pin поставлен/снят;
    'selector'— сменился состав selector;
    ''        — изменений нет.
    Чистая функция."""
    if not prev and not cur:
        return ""
    if prev.get("strategy") != cur.get("strategy"):
        return "strategy"
    if bool(prev.get("pinned")) != bool(cur.get("pinned")):
        return "pin"
    if sorted(prev.get("selector") or []) != sorted(cur.get("selector") or []):
        return "selector"
    if prev.get("active_node_idx") != cur.get("active_node_idx"):
        return "active"
    return ""


def _ew_snapshot_text(eff_set: dict, mode: dict, metrics: dict,
                      include_metrics: bool) -> str:
    """Текст дайджеста: состав ротации + статусы нод + латентности.
    Чистая функция."""
    lines = []
    st = mode.get("strategy") or "нет"
    lines.append(f"Режим: стратегия <b>{st}</b>"
                 + (" (pinned)" if mode.get("pinned") else ""))
    in_set = [k for k, v in (eff_set or {}).items() if v.get("in_set")]
    lines.append(f"В ротации: <b>{len(in_set)}</b> из {len(eff_set or {})}")
    for k, v in sorted((eff_set or {}).items()):
        if v.get("in_set"):
            m = (metrics or {}).get(k) or {}
            lat = ""
            if include_metrics and m.get("lat_ms"):
                lat = f" — {m['lat_ms']:.0f} мс"
            lines.append(f"  ✅ <code>{k}</code>{lat}")
    excl = [(k, v) for k, v in sorted((eff_set or {}).items())
            if not v.get("in_set")]
    if excl:
        lines.append("Вне ротации:")
        for k, v in excl:
            why = ", ".join(v.get("reasons") or ["?"])
            lines.append(f"  ⛔ <code>{k}</code> — {why}")
    return "\n".join(lines)


# ── IO: конфиг / лог / чтение источников ──────────────────────────────────────

def load_cfg() -> dict:
    """Конфиг наблюдателя (слитый с дефолтами; битый файл = дефолты)."""
    stored = {}
    try:
        if EW_CFG_FILE.exists():
            stored = json.loads(EW_CFG_FILE.read_text(encoding="utf-8"))
    except Exception:
        stored = {}
    return _ew_merge_cfg(DEFAULTS, stored if isinstance(stored, dict) else {})


def save_cfg(cfg: dict) -> None:
    """Сохранение конфига (права 600, каталог создаётся)."""
    EW_CFG_FILE.parent.mkdir(parents=True, exist_ok=True)
    EW_CFG_FILE.write_text(
        json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    EW_CFG_FILE.chmod(0o600)


def _ew_log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        EW_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(EW_LOG_FILE, "a", encoding="utf-8") as f:
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


def _load_sb_state() -> dict:
    return _read_json(SB_STATE_FILE)


def _load_hm_state() -> dict:
    return _read_json(HM_STATE_FILE)


def _load_live_balancer() -> dict:
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


def _hostname() -> str:
    try:
        return subprocess.run(["hostname", "-s"], capture_output=True,
                              text=True, check=False).stdout.strip() or "server"
    except Exception:
        return "server"


# ── Уведомления ───────────────────────────────────────────────────────────────

def _notify_event(event: str, detail: str, cfg: dict) -> bool:
    """Отправка события. Основной путь — tg_bot.tg_notify_event
    (уважает фильтр событий меню «Telegram-уведомления» и ключ proxy);
    fallback — прямая отправка curl-ом (паттерн node_health_monitor),
    если tg_bot недоступен (битый деплой). Возвращает True при доставке."""
    # Локальный выключатель (в дополнение к общему фильтру telegram.json)
    notify_map = (cfg or {}).get("notify") or {}
    if notify_map.get(event, True) is False:
        return False

    chat_override = str((cfg or {}).get("chat_id_override") or "").strip()
    try:
        from chimera.modules import tg_bot
        if chat_override:
            # Рендерим сами и шлём напрямую в отдельный чат
            tpl = (cfg.get("templates") or {}).get(event) \
                or DEFAULT_TEMPLATES.get(event, "{detail}")
            text = _ew_render(tpl, host=_hostname(), ts=_now_str(),
                              detail=detail, node="", old="", new="")
            ok = tg_bot.tg_send(text, chat_id=chat_override)
            _ew_log(f"TG[{event}] direct-override -> {chat_override}: "
                    f"{'OK' if ok else 'FAIL'}")
            return ok
        tg_bot.tg_notify_event(event, detail)
        _ew_log(f"TG[{event}] sent (filter-respecting path)")
        return True
    except Exception as e:
        _ew_log(f"TG[{event}] tg_bot недоступен ({e}) — curl-fallback")

    # Fallback: прямой curl (как node_health_monitor._tg_send)
    tcfg = _read_json(Path("/var/lib/xray-installer/telegram.json"))
    token = str(tcfg.get("token") or "")
    chat_id = chat_override or str(tcfg.get("chat_id") or "")
    if not token or not chat_id:
        return False
    try:
        tpl = (cfg.get("templates") or {}).get(event) \
            or DEFAULT_TEMPLATES.get(event, "{detail}")
        text = _ew_render(tpl, host=_hostname(), ts=_now_str(),
                          detail=detail, node="", old="", new="")
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
        _ew_log(f"TG[{event}] curl-fallback: {'OK' if ok else 'FAIL'}")
        return ok
    except Exception:
        return False


def _now_str() -> str:
    return time.strftime("%d.%m.%Y %H:%M")


# ── Core: одна итерация наблюдения ────────────────────────────────────────────

def _ew_collect_snapshot() -> tuple:
    """Собирает (eff_set, mode, metrics) из всех источников. Только чтение."""
    st = _load_state()
    sb = _load_sb_state()
    hm = _load_hm_state()
    live = _load_live_balancer()

    chain_nodes = st.get("chain_nodes") or []
    lb_nodes = st.get("chain_lb_nodes") or []
    pinned = st.get("chain_pinned_node_index", -1)

    quarantine: dict = {}
    metrics: dict = {}
    for key, meta in ((sb.get("nodes_meta") or {}) or {}).items():
        if isinstance(meta, dict):
            quarantine[key] = bool(meta.get("quarantine_until", 0)
                                   and float(meta["quarantine_until"] or 0) > time.time())
            metrics[key] = {"lat_ms": meta.get("last_lat_ms"),
                            "bw_ms": meta.get("last_bw_ms"),
                            "score": meta.get("last_score")}

    eff_set = _ew_effective_set(chain_nodes, live.get("selector") or [],
                                lb_nodes, quarantine, hm, pinned)
    mode = {"strategy": live.get("strategy") or "",
            "selector": live.get("selector") or [],
            "pinned": isinstance(pinned, int) and not isinstance(pinned, bool)
            and pinned >= 0,
            "active_node_idx": sb.get("active_node_idx")}
    return eff_set, mode, metrics


def run_once(force: bool = False) -> dict:
    """Одна итерация наблюдения (вызывается из cron / меню).
    force=True — проигнорировать enabled и quiet-часы (ручной запуск).
    Возвращает {'set': eff_set, 'mode': mode, 'events': [отправленные]}."""
    cfg = load_cfg()
    if not cfg.get("enabled", True) and not force:
        _ew_log("SKIP: наблюдатель выключен (enabled=false)")
        return {"set": {}, "mode": {}, "events": []}

    prev = _read_json(EW_CFG_FILE).get("__state__") or {}
    eff_set, mode, metrics = _ew_collect_snapshot()
    events_sent: list[str] = []

    now = time.time()
    now_hhmm = time.strftime("%H:%M")
    quiet = _ew_quiet(now_hhmm, cfg.get("quiet_hours") or {})

    def _emit(event: str, detail: str) -> None:
        """Отправка с учётом анти-спама (min_gap) и quiet-часов."""
        if not force and quiet:
            _ew_log(f"SKIP[{event}]: тихие часы")
            return
        if not force and not _ew_gap_ok(
                ((prev.get("last_notify") or {}).get(event)) or 0,
                now, cfg.get("min_gap_min")):
            _ew_log(f"SKIP[{event}]: анти-спам min_gap")
            return
        if _notify_event(event, detail, cfg):
            events_sent.append(event)
            prev.setdefault("last_notify", {})[event] = now

    # 1) Изменение состава ротации
    if prev.get("eff_set") is not None:
        changes = _ew_diff_set(prev.get("eff_set") or {}, eff_set)
        if changes:
            lines = []
            for ch in changes:
                if ch["kind"] == "removed":
                    why = ", ".join(ch["reasons"]) or "причина неизвестна"
                    lines.append(f"⛔ <code>{ch['key']}</code> выпала ({why})")
                else:
                    lines.append(f"✅ <code>{ch['key']}</code> вернулась в ротацию")
            _emit("exit_set_change", "\n".join(lines))

    # 2) Режимное переключение (стратегия / pin / активная нода single-pick)
    if prev.get("mode") is not None:
        kind = _ew_switch_kind(prev.get("mode") or {}, mode)
        if kind:
            labels = {
                "active": "сменилась активная нода (single-pick)",
                "strategy": (f"стратегия балансировки: "
                             f"<b>{(prev.get('mode') or {}).get('strategy') or '?'}</b> → "
                             f"<b>{mode.get('strategy') or '?'}</b>"),
                "pin": ("pinned-режим " +
                        ("включён" if mode.get("pinned") else "снят")),
                "selector": "изменился состав selector балансировщика",
            }
            _emit("exit_switch", labels.get(kind, kind))

    # 3) Смена exit-IP (опционально, активные full-path зонды)
    if cfg.get("probe_exits") and cfg.get("notify", {}).get("exit_ip_change", True):
        _probe_exit_ips(eff_set, prev, cfg, _emit)

    # 4) Периодический дайджест
    snap_h = cfg.get("snapshot_hours") or 0
    try:
        snap_h = float(snap_h)
    except (TypeError, ValueError):
        snap_h = 0
    if snap_h > 0:
        last_snap = float(prev.get("last_snapshot_ts") or 0)
        if now - last_snap >= snap_h * 3600 or force and not last_snap:
            text = _ew_snapshot_text(eff_set, mode, metrics,
                                     bool(cfg.get("include_metrics", True)))
            _emit("exit_snapshot", text)
            prev["last_snapshot_ts"] = now

    # Сохраняем снимок состояния (внутрь конфиг-файла, ключ __state__ —
    # эксплуатационные данные рядом с настройками, атомарно одним файлом)
    stored = _read_json(EW_CFG_FILE)
    stored["__state__"] = {
        "eff_set": {k: {"in_set": v["in_set"], "reasons": v["reasons"]}
                    for k, v in eff_set.items()},
        "mode": mode,
        "last_notify": prev.get("last_notify") or {},
        "last_snapshot_ts": prev.get("last_snapshot_ts") or 0,
        "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "exit_ips": prev.get("exit_ips") or {},
    }
    try:
        EW_CFG_FILE.parent.mkdir(parents=True, exist_ok=True)
        EW_CFG_FILE.write_text(
            json.dumps(stored, indent=2, ensure_ascii=False),
            encoding="utf-8")
        EW_CFG_FILE.chmod(0o600)
    except Exception as e:
        _ew_log(f"WARN: не удалось сохранить состояние: {e}")

    return {"set": eff_set, "mode": mode, "events": events_sent}


def _probe_exit_ips(eff_set: dict, prev: dict, cfg: dict, emit) -> None:
    """Активные full-path зонды всех chain-нод: exit_ip + живость.
    Использует обкатанный механизм chain_relay (честный REALITY-хендшейк,
    не бан-фуд — живой кейс окт.2026 №3). Смена IP ноды → exit_ip_change."""
    try:
        from chimera.modules.chain_relay import (
            check_node_full_path, check_via_node_full_path,
            load_relay_hops, hop_via_tag_for)
    except Exception as e:
        _ew_log(f"WARN[probe]: chain_relay недоступен: {e}")
        return
    hops = load_relay_hops()
    timeout = int(cfg.get("probe_timeout_sec") or 15)
    prev_ips = (prev.get("exit_ips") or {})

    st = _load_state()
    by_host = {f"{nd.get('host')}:{nd.get('port')}": nd
               for nd in (st.get("chain_nodes") or [])}

    for key, nd_info in (eff_set or {}).items():
        nd = by_host.get(key)
        if not nd:
            continue
        try:
            if nd.get("via") and hop_via_tag_for(nd, hops):
                r = check_via_node_full_path(nd, hops, want_ip=True,
                                             curl_timeout=timeout,
                                             deep_diag=False)
            else:
                r = check_node_full_path(nd, want_ip=True,
                                         curl_timeout=timeout,
                                         deep_diag=False)
        except Exception as e:
            _ew_log(f"WARN[probe]: {key}: {e}")
            continue
        ip = str(r.get("exit_ip") or "").strip()
        if not ip or not r.get("ok"):
            continue
        old_ip = str(prev_ips.get(key) or "")
        prev.setdefault("exit_ips", {})[key] = ip
        if old_ip and old_ip != ip:
            emit("exit_ip_change",
                 f"Нода <code>{key}</code>: exit-IP "
                 f"<b>{old_ip}</b> → <b>{ip}</b>")


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
    """Каталог установки chimera (паттерн node_health_monitor:
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
            "# xray-exit-watcher.sh — наблюдатель переключений exit-нод\n"
            "# Установлен Chimera Project (exit_switch_watcher)\n"
            f"export PYTHONPATH=\"{installer}:$PYTHONPATH\"\n"
            f"{python} -c \"\n"
            "import sys\n"
            f"sys.path.insert(0, '{installer}')\n"
            "from chimera.modules.exit_switch_watcher import run_once\n"
            "run_once()\n"
            "\" 2>>/var/log/xray-exit-switch-watcher.log\n"
        )
        CRON_SCRIPT.write_text(script, encoding="utf-8")
        CRON_SCRIPT.chmod(0o750)
        CRON_FILE.write_text(
            f"# xray-exit-watcher — наблюдение за ротацией exit-нод "
            f"каждые {interval_min} мин\n"
            f"*/{interval_min} * * * * root {CRON_SCRIPT} "
            f">>/var/log/xray-exit-switch-watcher.log 2>&1\n",
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

def do_exit_watcher_menu() -> None:
    """Интерактивное меню наблюдателя (TUI)."""
    from chimera.modules.box_renderer import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_item, _box_back,
        _box_ok, _box_warn,
    )
    C = _colors()

    while True:
        os.system("clear")
        cfg = load_cfg()
        installed = is_installed()
        interval = _installed_interval() if installed else cfg.get("interval_min",
                                                                   DEFAULT_INTERVAL)
        eff_set, mode, _metrics = _ew_collect_snapshot()
        in_set = [k for k, v in eff_set.items() if v.get("in_set")]
        excl = [(k, v) for k, v in eff_set.items() if not v.get("in_set")]
        status = f"{C['GREEN']}активен{C['NC']}" if installed else f"{C['YELLOW']}не активен{C['NC']}"
        if not cfg.get("enabled", True):
            status += f" {C['RED']}(выключен в настройках){C['NC']}"
        strategy = mode.get("strategy") or "нет"
        pinned = "да" if mode.get("pinned") else "нет"

        print()
        _box_top("🔀  НАБЛЮДАТЕЛЬ ПЕРЕКЛЮЧЕНИЙ EXIT-НОД")
        _box_row("  Уведомления об изменениях ротации exit-нод (состав,")
        _box_row("  стратегии, pin, exit-IP). Единая точка наблюдения")
        _box_row("  поверх SmartBalancer / нативного chain-balancer.")
        _box_sep()
        _box_row(f"  Статус:     {status}")
        if installed:
            _box_row(f"  Интервал:   {C['BOLD']}{interval} мин{C['NC']}")
        _box_row(f"  Стратегия:  {strategy}   pinned: {pinned}")
        _box_row(f"  В ротации:  {C['GREEN']}{len(in_set)}{C['NC']} из {len(eff_set)}")
        _box_sep()
        if eff_set:
            for k in in_set:
                _box_row(f"  {C['GREEN']}✓{C['NC']} <code>{k}")
            for k, v in excl:
                why = ", ".join(v.get("reasons") or ["?"])
                _box_row(f"  {C['DIM']}✗ {k} — {why}{C['NC']}")
        else:
            _box_row(f"  {C['DIM']}Exit-ноды не настроены (только Режим B){C['NC']}")
        _box_sep()
        nf = cfg.get("notify") or {}
        _box_row(f"  События: состав={'вкл' if nf.get('exit_set_change', True) else 'выкл'}"
                 f"  переключение={'вкл' if nf.get('exit_switch', True) else 'выкл'}"
                 f"  IP={'вкл' if nf.get('exit_ip_change', True) else 'выкл'}"
                 f"  дайджест={'вкл' if nf.get('exit_snapshot', True) else 'выкл'}")
        qh = cfg.get("quiet_hours") or {}
        qh_str = f"{qh.get('from', '')}–{qh.get('to', '')}" if qh.get("from") else "нет"
        _box_row(f"  Тихие часы: {qh_str}   мин.пауза: {cfg.get('min_gap_min')} мин"
                 f"   дайджест: раз в {cfg.get('snapshot_hours') or 0} ч")
        _box_sep()
        _box_item("C", "Проверить сейчас (без ожидания cron)")
        _box_item("T", "Тест-уведомление (все типы событий)")
        _box_item("S", "Настройки уведомлений (события / паузы / тихие часы)")
        _box_item("P", "Настройки зондов exit-IP")
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
            print(f"  {C['DIM']}Проверяю изменения ротации...{C['NC']}")
            res = run_once(force=True)
            if res.get("events"):
                for ev in res["events"]:
                    _box_ok(f"Отправлено: {ev}")
            else:
                _box_ok("Изменений нет (снапшот обновлён)")
            input(f"{C['CYAN']}Нажмите Enter...{C['NC']}")

        elif ch == "T":
            for ev, txt in (
                ("exit_set_change", "⛔ <code>node-a.example.com:443</code> выпала (тест)"),
                ("exit_switch", "тест: сменилась активная нода (single-pick)"),
                ("exit_snapshot", "тест: снапшот ротации"),
            ):
                ok = _notify_event(ev, f"🔔 Тест наблюдателя: {txt}", cfg)
                print(f"  {'✅' if ok else '⚠️'} {ev}")
            input(f"{C['CYAN']}Нажмите Enter...{C['NC']}")

        elif ch == "S":
            _menu_settings(cfg)
            save_cfg(cfg)

        elif ch == "P":
            _menu_probes(cfg)
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
    интервал дайджеста, отдельный chat_id."""
    from chimera.modules.box_renderer import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_back,
        _box_ok, _box_warn)
    C = _colors()
    labels = {
        "exit_set_change": "Изменение состава ротации",
        "exit_switch":     "Режимные переключения (активная нода / стратегия / pin)",
        "exit_ip_change":  "Смена exit-IP ноды (нужны зонды)",
        "exit_snapshot":   "Периодический дайджест ротации",
    }
    while True:
        os.system("clear")
        nf = cfg.setdefault("notify", {})
        qh = cfg.setdefault("quiet_hours", {"from": "", "to": ""})
        print()
        _box_top("⚙️  НАСТРОЙКИ УВЕДОМЛЕНИЙ НАБЛЮДАТЕЛЯ")
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
            raw = input(f"  Мин. пауза, мин (Enter = без изменений): ").strip()
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


def _menu_probes(cfg: dict) -> None:
    """Настройки активных зондов exit-IP."""
    from chimera.modules.box_renderer import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_back, _box_ok)
    C = _colors()
    while True:
        os.system("clear")
        print()
        _box_top("🌐  ЗОНДЫ EXIT-IP")
        _box_row("  Активная проверка: поднимает полный путь до каждой ноды")
        _box_row("  (честный REALITY-зонд chain_relay) и фиксирует её exit-IP.")
        _box_row("  Дороже пассивного наблюдения — включайте при необходимости.")
        _box_sep()
        _box_row(f"  1. Зонды: {'включены' if cfg.get('probe_exits') else 'выключены'}")
        _box_row(f"  2. Таймаут зонда: {cfg.get('probe_timeout_sec', 15)} сек")
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{C['CYAN']}Выбор: {C['NC']}").strip()
        except KeyboardInterrupt:
            return
        if ch in ("0", "Q", ""):
            return
        if ch == "1":
            cfg["probe_exits"] = not cfg.get("probe_exits", False)
        elif ch == "2":
            raw = input("  Таймаут, сек (5-60): ").strip()
            if raw.isdigit() and 5 <= int(raw) <= 60:
                cfg["probe_timeout_sec"] = int(raw)


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
