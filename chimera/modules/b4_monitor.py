"""
chimera/modules/b4_monitor.py
───────────────────────────────────────────────────────────────────────────────
Ops-слой B4 — «как у VLESS-нод и Mieru-каскада», только для B4.

ЧТО УРАВНЯЛОСЬ С СУЩЕСТВУЮЩИМИ ФИШКАМИ (parity-таблица):

  Mieru-каскад                          → B4 (этот модуль)
  ─────────────────────────────────────────────────────────────────────────
  health_tick */1 мин (systemd timer)    → health_tick */1 мин (b4-health.timer)
  _ensure_local_services (self-heal)     → рестарт b4 при падении + репорт
  _probe_exit_ttfb (socks-проба)         → _probe_direct (TTFB прямого пути
                                           через NFQUEUE b4 — как видит юзер)
  _ema_metrics (α=0.35, 15 мин)          → EMA ttfb_ms (те же константы)
  fail_streak ≥ 2 → unhealthy            → fail_streak ≥ 2 → degraded
  WEIGHTS_REBUILD_COOLDOWN_S             → REMEDY_COOLDOWN_S (анти-флаппер)
  mieru_cascade_monitor (5 мин, TG)      → b4-monitor (5 мин, TG по смене)
  mieru_stalled                          → b4_stalled (тик не обновляется)
  b4set_refresh (ipset exempt)           → контроль: exempt пустой = алерт
                                           (сам рефреш остался в тике каскада)

  VLESS                                 → B4
  ─────────────────────────────────────────────────────────────────────────
  smart_balancer (пробы+score+автосвитч) → деградация → ремедия:
                                           пресеты (ротация default→
                                           aggressive→light) или Discovery
  dpi_detector pinning A/B               → pin: пользовательский пресет
                                           помнится; ротация при деградации,
                                           возврат не делаем (неактивный
                                           пресет b4 пробовать не умеет —
                                           аналог «пробы всех Exit-ов» это
                                           Discovery b4, он и вызывается)
  node_health_monitor / матрица нод      → matrix(): сервис+версия+сеты+
                                           счётчики очереди+TTFB+exempt

АРХИТЕКТУРА (двухслойная, как mieru_cascade + mieru_cascade_monitor):

  b4-health.timer (*/1 мин, systemd)
      └─ b4-health.sh (wrapper, PYTHONPATH-safe)
           └─ health_tick():
                • сервис: systemctl is-active b4; упал → рестарт (self-heal,
                  max 1 попытка/тик, лог в actions)
                • проба: 2 цели прямым путём (youtube.com + i.ytimg.com,
                  проходят через NFQUEUE b4 — ровно путь юзера);
                  ok = обе ответили любым HTTP-кодом (2/3/4xx, как
                  health_check_youtube); ttfb_ms = youtube.com
                • EMA ttfb (α=0.35, протухла >15 мин → быстрый старт)
                • fail_streak: 1 промах при прошлом healthy — «скорее жив»,
                  2 подряд → degraded (порог каскада)
                • очередь: nft table inet b4_mangle — счётчики out443/in443/
                  quic/dns + скорости (Δ/мин против прошлого тика)
                • exempt: ipset mieru_b4_direct — размер (пустой при
                  применимости = алерт в TG-слое)
                • ремедия при degraded (cooldown 600с, одно действие на окно):
                    - пресеты применимы (сет id "youtube" есть) → ротация
                      default→aggressive→light→… (по кругу, pin помнит
                      пользовательский выбор)
                    - иначе (кастомные сеты) → Discovery b4
                      (POST /api/discovery/start — автоподбор стратегий,
                      аналог проб всех Exit-ов каскада)
                • пишет b4_monitor_state.json

  /etc/cron.d/b4-monitor (*/5 мин)
      └─ b4-monitor.sh (wrapper)
           └─ check_b4_once(): читает b4_monitor_state.json БЕЗ проб
                (пробы делает тик — сеть не дублируем, паттерн mieru):
                • b4_down / b4_up            (сервис)
                • b4_degraded / b4_recovered (проба, streak ≥ 2)
                • b4_stalled                 (тик не обновляется >5 мин)
                • b4_exempt_empty / b4_exempt_ok (ipset пуст/заполнился)
                • новые actions: b4_restarted / b4_discovery / b4_preset
                Анти-спам: алерт ТОЛЬКО при смене состояния; первое
                наблюдение — молча. events.<event> в telegram.json
                (отсутствующий ключ = включено).

Публичный API:
    health_tick(verbose)          → dict
    health_tick_cli()             → None (для wrapper'а)
    check_b4_once()               → list[dict]
    matrix() / summary()          → dict (TUI/панели)
    install_b4_monitor(interval)  → (bool, str) — timer+cron
    uninstall_b4_monitor()        → (bool, str)
    is_monitor_installed()        → bool
    do_b4_monitor_menu()          → None (TUI)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path
from typing import Optional

# ── Пути (модульные константы: тесты патчат их в tmp) ──────────────────────
TICK_STATE   = Path("/var/lib/xray-installer/b4_monitor_state.json")
TG_STATE     = Path("/var/lib/xray-installer/b4-monitor-state.json")
TG_CONFIG    = Path("/var/lib/xray-installer/telegram.json")
MONITOR_LOG  = Path("/var/log/b4-monitor.log")

CRON_FILE    = Path("/etc/cron.d/b4-monitor")
TG_SCRIPT    = Path("/usr/local/bin/b4-monitor.sh")
TICK_SCRIPT  = Path("/usr/local/bin/b4-health.sh")
UNIT_TICK    = Path("/etc/systemd/system/b4-health.service")
UNIT_TIMER   = Path("/etc/systemd/system/b4-health.timer")

# ── Параметры ───────────────────────────────────────────────────────────────
DEFAULT_INTERVAL       = 5      # мин (TG-часть, как mieru-монитор)
STALE_AFTER            = 300    # сек: 5 пропущенных тиков
TG_TIMEOUT             = 10     # сек
PROBE_TIMEOUT_S        = 8      # curl --max-time на цель
EMA_ALPHA              = 0.35   # вес свежей пробы (как каскад, v5.5.4)
EMA_MAX_AGE_S          = 900    # история старше 15 мин — протухла
FAIL_STREAK_UNHEALTHY  = 2      # 2 подряд фейла → degraded (порог каскада)
REMEDY_COOLDOWN_S      = 600    # одно действие на окно (анти-флаппер)
ACTIONS_KEEP           = 20     # хвост журнала действий

# ipset исключений из каскада (см. mieru_cascade._B4_IPSET) и таблица
# нативных правил b4 (см. youtube_b4: с v5 b4 сам ставит table inet
# b4_mangle через nftables; Chimera правил НЕ ставит).
EXEMPT_IPSET  = "mieru_b4_direct"
NFT_TABLE     = "b4_mangle"

# Пробы прямого пути (как health_check_youtube: коды 2/3/4xx = сервер
# ответил; таймаут/резет/DNS-фейл = пустой вывод). Обе цели должны ответить.
PROBE_TARGETS = (
    ("youtube.com", "https://www.youtube.com/"),
    ("ytimg.com", "https://i.ytimg.com/vi/dQw4w9WgXcQ/default.jpg"),
)

# Ротация пресетов (порядок = ключи youtube_b4.PRESETS; для классических
# установок, где есть сет id "youtube"). Кастомные сеты (id-UUID) идут
# через Discovery b4.
PRESET_CHAIN  = ("default", "aggressive", "light")
DEFAULT_POLICY = {"restart": True, "discovery": True, "presets": True}

# ── События (метки для меню tg_bot; порядок синхронизирован) ───────────────
EVENT_KEYS = [
    "b4_down", "b4_up", "b4_degraded", "b4_recovered", "b4_stalled",
    "b4_restarted", "b4_discovery", "b4_preset",
    "b4_exempt_empty", "b4_exempt_ok",
]
EVENT_LABELS = {
    "b4_down":        "B4: сервис упал",
    "b4_up":          "B4: сервис восстановился",
    "b4_degraded":    "B4: прямой путь деградировал (2+ фейла)",
    "b4_recovered":   "B4: прямой путь восстановился",
    "b4_stalled":     "B4: health-tick не обновляется",
    "b4_restarted":   "B4: рестарт (self-heal)",
    "b4_discovery":   "B4: запущен Discovery (ремедия)",
    "b4_preset":      "B4: ротация пресета (ремедия)",
    "b4_exempt_empty": "B4: ipset exempt пуст (YouTube уйдёт в каскад)",
    "b4_exempt_ok":   "B4: ipset exempt заполнен",
}


# ── Вспомогательные ──────────────────────────────────────────────────────────

def _run(cmd, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _log(msg: str) -> None:
    try:
        MONITOR_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(MONITOR_LOG, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except Exception:
        pass


def _hostname() -> str:
    try:
        return _run(["hostname", "-s"]).stdout.strip() or "server"
    except Exception:
        return "server"


def _systemd_is_active(unit: str) -> str:
    """'active' | 'inactive' | ... — обёртка для тестов."""
    try:
        r = _run(["systemctl", "is-active", unit], timeout=10)
        return (r.stdout or "").strip() or "unknown"
    except Exception:
        return "unknown"


def _tg_send(msg: str, event: str = "") -> bool:
    """Отправка в TG с events-фильтром (паттерн v2-мониторов; отсутствующий
    ключ = включено). {H} — заголовок [host | ip] как в xray-tg-monitor v2."""
    try:
        if not TG_CONFIG.exists():
            return False
        cfg = json.loads(TG_CONFIG.read_text(encoding="utf-8"))
        token, chat = cfg.get("token", ""), cfg.get("chat_id", "")
        if not token or not chat:
            return False
        if event and not cfg.get("events", {}).get(event, True):
            return False
        host = _hostname()
        ip = cfg.get("server_ip", "")
        header = f"[{host} | {ip}]" if ip else f"[{host}]"
        text = msg.replace("{H}", header)
        r = _run([
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "-m", str(TG_TIMEOUT),
            f"https://api.telegram.org/bot{token}/sendMessage",
            "-d", f"chat_id={chat}",
            "-d", f"text={text}",
            "-d", "parse_mode=HTML",
        ])
        return (r.stdout or "").strip() == "200"
    except Exception:
        return False


# ── Ленивый youtube_b4 (нет жёсткой зависимости; b4_monitor живёт и без него) ─

def _ytb():
    from chimera.modules import youtube_b4
    return youtube_b4


def _b4_installed() -> bool:
    """Установлен ли b4 (binary + unit) — как youtube_b4.status()."""
    try:
        ytb = _ytb()
        return ytb.B4_BINARY_PATH.exists() and ytb.B4_UNIT_PATH.exists()
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════
#  ПРОБЫ
# ══════════════════════════════════════════════════════════════════════════

def _probe_service() -> bool:
    return _systemd_is_active("b4") == "active"


def _heal_restart() -> bool:
    """Рестарт b4 (self-heal, как _ensure_local_services каскада).
    Возвращает активность ПОСЛЕ рестарта. Вызывающий код логирует действие."""
    _run(["systemctl", "restart", "b4"], timeout=30)
    time.sleep(3)          # дать юниту подняться до повторной пробы
    return _probe_service()


def _probe_direct() -> dict:
    """TTFB-проба прямого пути (через NFQUEUE b4 — как видит юзер).

    Цели: youtube.com (главная, метрика ttfb) + i.ytimg.com (CDN-статика).
    ok = ОБЕ цели ответили любым HTTP-кодом 2xx/3xx/4xx (как
    health_check_youtube: CDN отдаёт 404 на корень — это ответ, а вот
    таймаут/резет от ТСПУ — это фейл). ttfb_ms = youtube.com в мс.
    """
    out = {"ok": True, "ttfb_ms": None, "targets": []}
    for label, url in PROBE_TARGETS:
        try:
            r = _run([
                "curl", "-s", "-o", "/dev/null",
                "-w", "%{http_code} %{time_total}",
                "--max-time", str(PROBE_TIMEOUT_S), url,
            ], timeout=PROBE_TIMEOUT_S + 4)
            parts = (r.stdout or "").split()
            code = parts[0] if parts else ""
            tsec = float(parts[1]) if len(parts) > 1 else None
            ok = (r.returncode == 0 and code
                  and code[0] in ("2", "3", "4"))
            out["targets"].append({
                "target": label, "ok": ok,
                "code": code or "TIMEOUT/RESET",
                "ms": round(tsec * 1000.0, 1) if tsec is not None else None,
            })
            if not ok:
                out["ok"] = False
            elif label == "youtube.com" and tsec is not None:
                out["ttfb_ms"] = round(tsec * 1000.0, 1)
        except Exception as e:
            out["targets"].append({"target": label, "ok": False, "err": str(e)})
            out["ok"] = False
    return out


_EMA_STATE_RE = re.compile(
    r"^(?P<proto>tcp|udp)\s+(?P<dir>dport|sport)\s+(?P<port>\d+)\b"
    r".*?counter\s+packets\s+(?P<pkts>\d+)\s+bytes\s+(?P<bytes>\d+)\b"
    r".*\bqueue\b")


def _parse_queue_native(nft_output: str) -> Optional[dict]:
    """Счётчики нативных правил b4 из `nft list ruleset` (plain text).

    Таблица table inet b4_mangle, правила вида:
      tcp dport 443 ct original packets < 20 counter packets 1896991
        bytes 359906609 queue flags bypass to 537-540
    Классификация (как в Web UI b4 / Metrics):
      out443 = tcp dport 443 (исходящий, ClientHello-фаза)
      in443  = tcp sport 443 (входящий: SYN-ACK, данные, RST)
      quic   = udp dport 443 (блок QUIC)
      dns    = udp 53 оба направления (hijack DNS)
    None = таблицы нет (b4 не ставил правила / не запущен).
    Чистая функция — тестируется на фикстуре с live-ноды.
    """
    if not nft_output or f"table inet {NFT_TABLE}" not in nft_output:
        return None
    # срез секции таблицы: от маркера до следующей "table ..." в колонке 0
    sec = nft_output.split(f"table inet {NFT_TABLE}", 1)[1]
    sec = sec.split("\ntable ", 1)[0]
    q = {"out443": {"pkts": 0, "bytes": 0},
         "in443":  {"pkts": 0, "bytes": 0},
         "quic":   {"pkts": 0, "bytes": 0},
         "dns":    {"pkts": 0, "bytes": 0}}
    found = False
    for line in sec.splitlines():
        m = _EMA_STATE_RE.match(line.strip())
        if not m:
            continue
        found = True
        proto, d, port = m.group("proto"), m.group("dir"), m.group("port")
        pkts, byts = int(m.group("pkts")), int(m.group("bytes"))
        key = None
        if proto == "tcp" and d == "dport" and port == "443":
            key = "out443"
        elif proto == "tcp" and d == "sport" and port == "443":
            key = "in443"
        elif proto == "udp" and d == "dport" and port == "443":
            key = "quic"
        elif proto == "udp" and port == "53":
            key = "dns"
        if key:
            q[key]["pkts"] += pkts
            q[key]["bytes"] += byts
    return q if found else None


def _queue_snapshot() -> Optional[dict]:
    """Живые счётчики очереди b4 (нативный nft). None = таблицы нет."""
    try:
        r = _run(["nft", "list", "ruleset"], timeout=10)
        return _parse_queue_native(r.stdout or "")
    except Exception:
        return None


def _queue_rates(prev: Optional[dict], cur: Optional[dict],
                 dt_s: float) -> dict:
    """Скорости (пакетов/мин) между двумя снапшотами счётчиков.

    Устойчиво к None/нулевому dt: без прошлого снапшота скорости не
    считаем (первый тик после установки — «прогрев»)."""
    out: dict = {}
    if not prev or not cur or dt_s <= 0:
        return out
    for key in ("out443", "in443", "quic", "dns"):
        a = (prev.get(key) or {}).get("pkts")
        b = (cur.get(key) or {}).get("pkts")
        if isinstance(a, int) and isinstance(b, int) and b >= a:
            out[key] = round((b - a) / dt_s * 60.0, 1)
    return out


def _exempt_snapshot() -> dict:
    """ipset исключений каскада (mieru_b4_direct, ставит mieru_cascade).

    applicable=False — сета нет (каскад/exempt не настроен на этой ноде):
    это НЕ ошибка, просто нечего мониторить. entries=None при applicable.
    """
    r = _run(["ipset", "list", EXEMPT_IPSET], timeout=10)
    if r.returncode != 0:
        return {"applicable": False, "entries": None}
    m = re.search(r"Number of entries:\s*(\d+)", r.stdout or "")
    return {"applicable": True,
            "entries": int(m.group(1)) if m else 0}


def _ema_update(hist: Optional[dict], fresh: Optional[float]) -> Optional[float]:
    """EMA-сглаживание ttfb_ms (порт _ema_metrics каскада, α=0.35).

    None/не-число → история не пишется. Протухшая история (>15 мин) —
    быстрый старт: возвращаем fresh как есть (семантика каскада)."""
    if fresh is None:
        return None
    if isinstance(hist, dict):
        try:
            age = time.time() - float(hist.get("ts") or 0)
        except (TypeError, ValueError):
            age = -1.0
        if 0 <= age <= EMA_MAX_AGE_S:
            h = hist.get("v")
            if isinstance(h, (int, float)) and not isinstance(h, bool):
                return round(EMA_ALPHA * fresh + (1 - EMA_ALPHA) * h, 1)
    return round(float(fresh), 1)


# ══════════════════════════════════════════════════════════════════════════
#  ПРЕСЕТЫ: применимость / текущий / переключение (ленивый youtube_b4)
# ══════════════════════════════════════════════════════════════════════════

_APPL_CACHE = {"ts": 0.0, "ok": None}


def _b4_sets() -> list:
    """Сеты b4: REST API (как _b4_rest_import_set), fallback config.json."""
    try:
        ytb = _ytb()
        resp = ytb._b4_rest_request("GET", "/api/sets")
        if resp is not None and resp[0] == 200 and isinstance(resp[1], list):
            return [s for s in resp[1] if isinstance(s, dict)]
    except Exception:
        pass
    try:
        ytb = _ytb()
        if ytb.B4_CONFIG_FILE.exists():
            cfg = json.loads(ytb.B4_CONFIG_FILE.read_text())
            sets = cfg.get("sets")
            if isinstance(sets, list):
                return [s for s in sets if isinstance(s, dict)]
    except Exception:
        pass
    return []


def _preset_applicable(max_age_s: float = 600.0) -> bool:
    """Есть ли сет id "youtube" (классическая установка youtube_b4).

    Только такие установки умеют ротацию пресетов (switch_preset меняет
    сет с id "youtube"). Кастомные сеты (id-UUID: Youtube-Fat-v1 и пр.)
    трогать нельзя — им ремедия через Discovery. Кэш 10 мин (REST по
    localhost на каждый тик — шум)."""
    now = time.time()
    if (_APPL_CACHE["ok"] is not None
            and now - _APPL_CACHE["ts"] <= max_age_s):
        return _APPL_CACHE["ok"]
    ok = any((s.get("id") or "") == "youtube" for s in _b4_sets())
    _APPL_CACHE.update({"ts": now, "ok": ok})
    return ok


def _current_preset() -> Optional[str]:
    """Активный пресет из config.json (без systemctl — его делает проба)."""
    try:
        preset, _name = _ytb()._detect_active_preset_from_config()
        return preset if preset != "unknown" else None
    except Exception:
        return None


def _switch_preset_to(name: str) -> bool:
    try:
        return bool(_ytb().switch_preset(name))
    except Exception:
        return False


def _run_discovery_remedy() -> dict:
    """Discovery b4 (ремедия для кастомных сетов).

    Discovery перебирает стратегии fake-SNI/фрагментации и подбирает
    рабочий сет под текущего провайдера — аналог «проб всех Exit-ов»
    каскада. Использует тот же вызов, что TUI [4] (run_discovery)."""
    try:
        return _ytb().run_discovery(timeout_sec=45) or {}
    except Exception as e:
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════════════
#  STATE (тик) + JOURNAL ДЕЙСТВИЙ
# ══════════════════════════════════════════════════════════════════════════

def _load_tick_state() -> dict:
    try:
        if TICK_STATE.exists():
            return json.loads(TICK_STATE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _save_tick_state(st: dict) -> None:
    try:
        TICK_STATE.parent.mkdir(parents=True, exist_ok=True)
        TICK_STATE.write_text(
            json.dumps(st, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def _action_append(st: dict, type_: str, detail: str) -> dict:
    """Журнал действий (self-heal / ремедии) — кап ACTIONS_KEEP.

    ts — epoch float: TG-слой детектит «новые» действия как
    ts > last_action_ts (одно действие = одно сообщение)."""
    a = {"ts": round(time.time(), 3), "type": type_, "detail": detail}
    actions = st.setdefault("actions", [])
    actions.append(a)
    if len(actions) > ACTIONS_KEEP:
        del actions[:-ACTIONS_KEEP]
    return a


# ══════════════════════════════════════════════════════════════════════════
#  HEALTH-TICK (ядро, */1 мин; вызывается из b4-health.sh)
# ══════════════════════════════════════════════════════════════════════════

def health_tick(verbose: bool = False) -> dict:
    """Один тик: сервис → проба → EMA → очередь → exempt → ремедия.

    Устойчив к «b4 не установлен» (тихий noop — как health_tick каскада
    на exit-нодах) и к любым сбоям проб: сбой = фейл пробы, не крэш тика.
    """
    result = {"installed": True, "service": None, "probe_ok": None,
              "healthy": None, "fail_streak": None, "changed": [],
              "remedy": None, "actions": []}
    if not _b4_installed():
        return {"installed": False}
    st = _load_tick_state()
    policy = st.get("policy") or dict(DEFAULT_POLICY)

    # ── 1. сервис + self-heal (как _ensure_local_services каскада) ──────
    service_active = _probe_service()
    if not service_active and policy.get("restart", True):
        ok = _heal_restart()
        _action_append(st, "restart",
                       "self-heal рестарт: " + ("ок, поднялся"
                                               if ok else "не поднялся"))
        result["actions"].append("restart")
        service_active = ok
    result["service"] = service_active

    # ── 2. проба прямого пути ───────────────────────────────────────────
    if service_active:
        probe = _probe_direct()
    else:
        probe = {"ok": False, "ttfb_ms": None, "targets": [],
                 "err": "service inactive"}
    prev_probe = st.get("probe") or {}
    prev_streak = int(prev_probe.get("fail_streak") or 0)
    prev_healthy = prev_probe.get("healthy")
    if probe["ok"]:
        fail_streak, healthy = 0, True
    else:
        fail_streak = prev_streak + 1
        # 1 промах при прошлом healthy — «скорельно жив» (кратковременный
        # сбой цели), 2 подряд → degraded. Порог = каскадный (fail_streak
        # ≥ 2 в _health_tick_locked).
        healthy = bool(prev_healthy) and fail_streak < FAIL_STREAK_UNHEALTHY

    # ── 3. EMA ttfb (α=0.35, протухла >15 мин → быстрый старт) ─────────
    ttfb_ema = _ema_update(st.get("ema", {}).get("ttfb_ms"),
                           probe.get("ttfb_ms"))
    st["ema"] = ({"ttfb_ms": {"ts": time.time(), "v": ttfb_ema}}
                 if ttfb_ema is not None else {})

    st["probe"] = {
        "healthy": healthy, "fail_streak": fail_streak,
        "ttfb_ms": probe.get("ttfb_ms"), "ttfb_ema": ttfb_ema,
        "last_code": (probe.get("targets") or [{}])[0].get("code")
        if probe.get("targets") else None,
        "last_check": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    result.update(probe_ok=probe["ok"], healthy=healthy,
                  fail_streak=fail_streak)

    # ── 4. очередь: счётчики + скорости Δ/мин ───────────────────────────
    prev_q = st.get("queue") or {}
    q = _queue_snapshot()
    now = time.time()
    try:
        dt = now - float(prev_q.get("ts") or 0)
    except (TypeError, ValueError):
        dt = 0.0
    rates = _queue_rates(prev_q.get("counters") if isinstance(
        prev_q, dict) else None, q, dt) if q else {}
    st["queue"] = {"ts": now, "counters": q,
                   "rates": rates, "mode": "nft-native" if q else None}

    # ── 5. exempt ipset ─────────────────────────────────────────────────
    ex = _exempt_snapshot()
    st["exempt"] = {"ts": now, "applicable": ex["applicable"],
                    "entries": ex["entries"]}

    # ── 6. ремедия при degraded (cooldown, одно действие на окно) ──────
    degraded = (not healthy) and service_active
    last_remedy = float(st.get("last_remedy_ts") or 0)
    remedy_ok_ts = (now - last_remedy) >= REMEDY_COOLDOWN_S
    remedy_type: Optional[str] = None
    if degraded and remedy_ok_ts:
        cur = _current_preset()
        if (policy.get("presets", True) and _preset_applicable()
                and cur in PRESET_CHAIN):
            # классическая установка: ротация пресета по кругу
            nxt = PRESET_CHAIN[(PRESET_CHAIN.index(cur) + 1)
                                % len(PRESET_CHAIN)]
            if _switch_preset_to(nxt):
                remedy_type = "preset"
                _action_append(st, "preset",
                               f"деградация (streak {fail_streak}): "
                               f"{cur} → {nxt} (ротация)")
                if not st.get("preset_pin"):
                    st["preset_pin"] = cur      # пользовательский выбор
                st["last_remedy_ts"] = now
        elif policy.get("discovery", True):
            # кастомные сеты (флот) или пресеты выключены: Discovery b4
            d = _run_discovery_remedy()
            ok = "error" not in d
            remedy_type = "discovery"
            _action_append(st, "discovery",
                           ("ок: " + json.dumps(d, ensure_ascii=False)[:200])
                           if ok else
                           f"ошибка: {str(d.get('error'))[:200]}")
            st["last_remedy_ts"] = now
    result["remedy"] = remedy_type

    # pin: пользовательский пресет помним, пока он здоров и менялся
    # вручную (наш тик действий по пресетам не делал)
    if remedy_type != "preset":
        cur2 = st.get("probe", {}).get("healthy") and _current_preset()
        if cur2 in PRESET_CHAIN:
            st["preset_pin"] = cur2

    # ── 7. сохранить + вернуть ─────────────────────────────────────────
    st["policy"] = policy
    st["ts"] = now
    _save_tick_state(st)
    # changed — действия ЭТОГО тика (рестарт/ремедия); TG-слой шлёт их
    # отдельно по журналу, здесь — для verbose/CLI-вызова
    result["changed"] = list(result["actions"])
    if verbose:
        ttfb = probe.get("ttfb_ms")
        print(f"  b4: сервис={'active' if service_active else 'DOWN'}"
              f" проба={'OK' if probe['ok'] else 'FAIL'}"
              f" (streak {fail_streak})"
              + (f" ttfb={ttfb:.0f}мс" if ttfb else "")
              + (f" ema={ttfb_ema:.0f}мс" if ttfb_ema else ""))
        if q:
            r_out = rates.get("out443")
            print(f"  очередь: out443 {q['out443']['pkts']} pkts"
                  + (f" (+{r_out}/мин)" if r_out is not None else ""))
        if ex["applicable"]:
            print(f"  exempt: {ex['entries']} IP")
        if remedy_type:
            print(f"  ремедия: {remedy_type}")
    return result


def health_tick_cli() -> None:
    """Точка входа wrapper'а b4-health.sh (тихий, вывод — в logger)."""
    health_tick(verbose=False)


# ══════════════════════════════════════════════════════════════════════════
#  TG-СЛОЙ (*/5 мин, cron; читает state БЕЗ проб — сеть не дублируем)
# ══════════════════════════════════════════════════════════════════════════

def _load_tg_state() -> dict:
    try:
        if TG_STATE.exists():
            return json.loads(TG_STATE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _save_tg_state(st: dict) -> None:
    try:
        TG_STATE.parent.mkdir(parents=True, exist_ok=True)
        TG_STATE.write_text(
            json.dumps(st, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def check_b4_once() -> list[dict]:
    """Разовая проверка (TG-слой). Алерты ТОЛЬКО при смене состояния.

    Читает b4_monitor_state.json (его пишет тик каждую минуту — пробы
    НЕ дублируем) + systemctl для сервиса. Первое наблюдение — молча
    (анти-спам по построению, как mieru_cascade_monitor).
    """
    results: list[dict] = []
    alerts: list[tuple[str, str]] = []
    if not TICK_STATE.exists():
        _log("нет b4_monitor_state.json — b4/монитор не настроен, выходим")
        return results
    try:
        st = json.loads(TICK_STATE.read_text(encoding="utf-8"))
    except Exception as exc:
        _log(f"b4_monitor_state.json не читается: {exc}")
        return results

    prev = _load_tg_state()
    ts = time.strftime("%d.%m.%Y %H:%M")

    # ── 1. stalled: тик не обновляет state ─────────────────────────────
    try:
        tick_ts = float(st.get("ts") or 0)
    except (TypeError, ValueError):
        tick_ts = 0.0
    stalled_now = tick_ts > 0 and (time.time() - tick_ts) > STALE_AFTER
    prev_stalled = bool(prev.get("stalled"))
    if stalled_now and not prev_stalled:
        alerts.append(("b4_stalled",
            "⚠️ <b>{H}</b> B4 health-tick не обновляется "
            f"(&gt;{STALE_AFTER // 60} мин)\n"
            "Проверь <code>systemctl status b4-health.timer</code>\n"
            f"<i>{ts}</i>"))
        _log("STALL: тик не обновляет state")
    elif not stalled_now and prev_stalled:
        alerts.append(("b4_stalled",
            "🟢 <b>{H}</b> B4 health-tick обновляется\n"
            f"<i>{ts}</i>"))
        _log("STALL снят")

    # ── 2. сервис ──────────────────────────────────────────────────────
    service_active = _probe_service()
    prev_service = prev.get("service", {}).get("active")
    if prev_service is True and not service_active:
        alerts.append(("b4_down",
            "🔴 <b>{H}</b> B4 не запущен!\n"
            "YouTube-DPI bypass неактивен (прямой путь без защиты)\n"
            f"<i>{ts}</i>"))
        _log("B4 DOWN")
    elif prev_service is False and service_active:
        alerts.append(("b4_up",
            "🟢 <b>{H}</b> B4 восстановился\n"
            f"<i>{ts}</i>"))
        _log("B4 UP")
    results.append({"id": "service", "label": "b4", "host": "local",
                    "healthy": service_active, "changed": False})

    # ── 3. проба (healthy из state тика; порог streak ≥ 2 — тот же) ────
    probe = st.get("probe") or {}
    healthy = bool(probe.get("healthy"))
    prev_h = prev.get("probe", {}).get("healthy")
    ema = probe.get("ttfb_ema")
    if prev_h is True and not healthy:
        streak = probe.get("fail_streak")
        alerts.append(("b4_degraded",
            "🟠 <b>{H}</b> B4: прямой путь деградировал\n"
            f"fail_streak {streak} — ТСПУ душит или очередь стоит\n"
            f"<i>{ts}</i>"))
        _log(f"DEGRADED (streak {streak})")
    elif prev_h is False and healthy:
        ms = f" — TTFB {ema:.0f} мс" if isinstance(ema, (int, float)) else ""
        alerts.append(("b4_recovered",
            "🟢 <b>{H}</b> B4: прямой путь восстановлен" + ms
            + "\n" + f"<i>{ts}</i>"))
        _log("RECOVERED")
    results.append({"id": "probe", "label": "direct-path", "host": "b4",
                    "healthy": healthy, "changed": False,
                    "fail_streak": probe.get("fail_streak"),
                    "ttfb_ema": ema})

    # ── 4. exempt ipset (пустой = YouTube уйдёт в каскад, RU-зона потеряна)
    ex = st.get("exempt") or {}
    ex_ok = bool(ex.get("applicable")) and int(ex.get("entries") or 0) > 0
    ex_empty = bool(ex.get("applicable")) and not ex_ok
    prev_ex = prev.get("exempt", {}).get("ok")
    if prev_ex is True and ex_empty:
        alerts.append(("b4_exempt_empty",
            "🟠 <b>{H}</b> B4: ipset exempt пуст\n"
            "route_domains не резолвятся — YouTube уйдёт в каскад "
            "(потеря RU-зоны и DPI-защиты)\n"
            f"<i>{ts}</i>"))
        _log("EXEMPT EMPTY")
    elif prev_ex is False and ex_ok:
        n = ex.get("entries")
        alerts.append(("b4_exempt_ok",
            "🟢 <b>{H}</b> B4: ipset exempt заполнен ({n} IP)\n"
            f"<i>{ts}</i>".replace("{n}", str(n))))
        _log("EXEMPT OK")
    results.append({"id": "exempt", "label": "exempt", "host": "ipset",
                    "healthy": ex_ok if ex.get("applicable") else None,
                    "entries": ex.get("entries")})

    # ── 5. новые действия тика (restart/discovery/preset) ──────────────
    try:
        last_action_ts = float(prev.get("last_action_ts") or 0)
    except (TypeError, ValueError):
        last_action_ts = 0.0
    new_actions = [a for a in (st.get("actions") or [])
                   if float(a.get("ts") or 0) > last_action_ts]
    for a in new_actions:
        ev = {"restart": "b4_restarted", "discovery": "b4_discovery",
              "preset": "b4_preset"}.get(a.get("type"))
        if not ev:
            continue
        icon = {"b4_restarted": "🔧", "b4_discovery": "🔍",
                "b4_preset": "🔄"}.get(ev, "•")
        head = {"b4_restarted": "рестарт (self-heal)",
                "b4_discovery": "запущен Discovery",
                "b4_preset": "ротация пресета"}[ev]
        # {H} — литерал-плейсхолдер (заменяет _tg_send); НЕ f-string,
        # иначе NameError по несуществующей переменной H (баг найден
        # тестом test_new_actions_alerted_once).
        alerts.append((ev,
            icon + " <b>{H}</b> B4: " + head
            + "\n" + str(a.get("detail", "")) + f"\n<i>{ts}</i>"))
        _log(f"ACTION {a.get('type')}: {a.get('detail', '')[:120]}")
        results.append({"id": "action", "label": a.get("type"),
                        "host": "tick", "healthy": True,
                        "changed": True, "detail": a.get("detail")})
    if new_actions:
        last_action_ts = max(float(a.get("ts") or 0) for a in new_actions)

    # ── отправка (после всех вычислений) ───────────────────────────────
    for event, msg in alerts:
        ok = _tg_send(msg, event)
        _log(f"TG[{event}] {'sent' if ok else 'SKIPPED/off'}: "
             + msg.replace("\n", " ")[:90])

    _save_tg_state({
        "service": {"active": service_active},
        "probe": {"healthy": healthy},
        "exempt": {"ok": ex_ok if ex.get("applicable") else None},
        "stalled": stalled_now,
        "last_action_ts": last_action_ts,
        "last_check": time.time(),
    })
    return results


# ══════════════════════════════════════════════════════════════════════════
#  МАТРИЦА (TUI / панели / rest_api)
# ══════════════════════════════════════════════════════════════════════════

def matrix() -> dict:
    """Сводка «как у нод VLESS» (do_node_health_matrix) — одним слоем:

    сервис/версия/пресет/сеты (youtube_b4.status) + очередь (счётчики и
    скорости из тика) + проба (healthy/streak/TTFB-EMA) + exempt + журнал
    действий + состояние монитора. Читает только локальные файлы и
    systemctl — сеть не трогает."""
    out: dict = {"installed": _b4_installed(), "monitor": {
        "installed": is_monitor_installed(),
        "interval": get_installed_interval(),
        "timer_active": _systemd_is_active("b4-health.timer") == "active",
    }}
    if out["installed"]:
        try:
            s = _ytb().status()
            out.update({
                "service": s.get("service_active"),
                "version": s.get("version"),
                "preset": s.get("active_preset"),
                "sets": s.get("active_sets") or [],
                "web_port": s.get("web_port"),
            })
        except Exception:
            out["service"] = _probe_service()
    st = _load_tick_state()
    out["queue"] = st.get("queue") or {}
    out["probe"] = st.get("probe") or {}
    out["exempt"] = st.get("exempt") or {}
    out["policy"] = st.get("policy") or dict(DEFAULT_POLICY)
    out["actions"] = (st.get("actions") or [])[-5:]
    out["tick_ts"] = st.get("ts")
    return out


def summary() -> dict:
    """Компакт для admin panel (get_admin_info): одна строка состояния."""
    st = _load_tick_state()
    probe = st.get("probe") or {}
    q = (st.get("queue") or {}).get("counters") or {}
    ex = st.get("exempt") or {}
    return {
        "installed": _b4_installed(),
        "service": _probe_service(),
        "healthy": probe.get("healthy"),
        "fail_streak": probe.get("fail_streak"),
        "ttfb_ema": probe.get("ttfb_ema"),
        "queue_out443_pkts": (q.get("out443") or {}).get("pkts"),
        "queue_rates": (st.get("queue") or {}).get("rates") or {},
        "exempt_entries": ex.get("entries"),
        "last_actions": [a.get("type") for a in (st.get("actions") or [])[-3:]],
        "monitor_installed": is_monitor_installed(),
    }


# ══════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА / УДАЛЕНИЕ (timer */1 мин + cron */5 мин)
# ══════════════════════════════════════════════════════════════════════════

def is_monitor_installed() -> bool:
    return (UNIT_TIMER.exists() and TICK_SCRIPT.exists()
            and CRON_FILE.exists() and TG_SCRIPT.exists())


def get_installed_interval() -> int:
    try:
        if CRON_FILE.exists():
            for line in CRON_FILE.read_text().splitlines():
                if line.startswith("*/"):
                    return int(line.split()[0].replace("*/", ""))
    except Exception:
        pass
    return DEFAULT_INTERVAL


def _find_installer_path() -> str:
    """Путь установки пакета chimera (паттерн mieru_cascade_monitor)."""
    try:
        import importlib.util
        spec = importlib.util.find_spec("chimera")
        if spec and spec.submodule_search_locations:
            return str(Path(list(spec.submodule_search_locations)[0]).parent)
    except Exception:
        pass
    return "/opt/chimera"


def _find_python() -> str:
    for p in ("/usr/bin/python3", "/usr/local/bin/python3"):
        if Path(p).exists():
            return p
    return "python3"


def install_b4_monitor(interval: int = DEFAULT_INTERVAL) -> tuple[bool, str]:
    """Timer b4-health (*/1 мин, systemd) + cron b4-monitor (*/5 мин).

    Wrapper'ы — PYTHONPATH-safe паттерн v5.1 (cron/timer стартует с
    произвольной cwd; bare python -c падает с ModuleNotFoundError).
    """
    try:
        interval = max(1, min(60, int(interval)))
        installer_path = _find_installer_path()
        python = _find_python()

        TICK_SCRIPT.write_text(
            f"""#!/bin/bash
# b4-health.sh — health-tick B4 (Chimera b4_monitor), вызывается timer'ом
# b4-health.timer каждые 60с. Пробы/самозалечивание/ремедии — в модуле.
export PYTHONPATH="{installer_path}:$PYTHONPATH"
{python} -c "
import sys
sys.path.insert(0, '{installer_path}')
from chimera.modules.b4_monitor import health_tick_cli
health_tick_cli()
" 2>&1 | logger -t b4-health
""", encoding="utf-8")
        TICK_SCRIPT.chmod(0o755)

        UNIT_TICK.write_text(
            "[Unit]\n"
            "Description=B4 health check + self-heal + remedy\n"
            "After=network-online.target\n"
            "\n"
            "[Service]\n"
            "Type=oneshot\n"
            f"ExecStart={TICK_SCRIPT}\n"
        )
        UNIT_TIMER.write_text(
            "[Unit]\n"
            "Description=B4 health timer (1/min)\n"
            "\n"
            "[Timer]\n"
            "OnCalendar=*:0/1\n"
            "AccuracySec=10s\n"
            "Persistent=true\n"
            "\n"
            "[Install]\n"
            "WantedBy=timers.target\n"
        )
        _run(["systemctl", "daemon-reload"])
        _run(["systemctl", "enable", "--now", "b4-health.timer"])

        TG_SCRIPT.write_text(
            f"""#!/bin/bash
# b4-monitor.sh — TG-монитор B4 (Chimera b4_monitor). Читает state тика
# (пробы НЕ дублирует — их делает тик), алерты при СМЕНЕ состояния.
export PYTHONPATH="{installer_path}:$PYTHONPATH"
{python} -c "
import sys
sys.path.insert(0, '{installer_path}')
from chimera.modules.b4_monitor import check_b4_once
check_b4_once()
" 2>>/var/log/b4-monitor.log
""", encoding="utf-8")
        TG_SCRIPT.chmod(0o755)
        CRON_FILE.write_text(
            f"""# b4-monitor — TG-монитор B4 каждые {interval} мин
*/{interval} * * * * root {TG_SCRIPT} >/dev/null 2>&1
""", encoding="utf-8")
        CRON_FILE.chmod(0o644)
        _log(f"установлен: timer 1/мин + cron */{interval}")
        return True, ("B4 мониторинг установлен: health-tick 1/мин "
                      f"+ TG-проверка каждые {interval} мин")
    except Exception as e:
        return False, f"Ошибка установки: {e}"


def uninstall_b4_monitor() -> tuple[bool, str]:
    try:
        _run(["systemctl", "disable", "--now", "b4-health.timer"])
        for p in (UNIT_TICK, UNIT_TIMER, TICK_SCRIPT, CRON_FILE,
                  TG_SCRIPT, TG_STATE):
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass
        _run(["systemctl", "daemon-reload"])
        _log("удалён (timer + cron + wrappers + tg-state)")
        return True, "B4 мониторинг удалён (timer+cron+скрипты+state)"
    except Exception as e:
        return False, f"Ошибка удаления: {e}"


# ══════════════════════════════════════════════════════════════════════════
#  TUI-МЕНЮ (вызывается из youtube_b4.do_youtube_b4_menu, пункт M)
# ══════════════════════════════════════════════════════════════════════════

def do_b4_monitor_menu() -> None:
    """Меню мониторинга B4 (паттерн do_cascade_monitor_menu)."""
    import os
    from chimera.modules import youtube_b4 as ytb

    RED, GREEN, YELLOW, CYAN, BOLD, DIM, NC = (
        ytb.RED, ytb.GREEN, ytb.YELLOW, ytb.CYAN,
        ytb.BOLD, ytb.DIM, ytb.NC)
    box = ytb
    while True:
        os.system("clear")
        mx = matrix()
        installed = mx["monitor"]["installed"]

        box._box_top("🩺  МОНИТОРИНГ B4 (HEALTH-TICK + TG)")
        box._box_row("  Ops-слой B4 — как у каскада: тик 1/мин (пробы,")
        box._box_row("  self-heal, ремедия) + TG 5/мин по смене состояния.")
        box._box_row("  Проба = прямой путь через NFQUEUE b4 (как видит юзер).")
        box._box_sep()
        if not mx["installed"]:
            box._box_warn("b4 не установлен — мониторить нечего.")
            box._box_row()
            box._box_back()
            box._box_bottom()
            try:
                ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                return
            if ch in ("q", "0", ""):
                return
            continue

        # ── сервис / пресет / сеты ──────────────────────────────────────
        svc = (f"{GREEN}active{NC}" if mx.get("service")
               else f"{RED}down{NC}")
        box._box_kv("Сервис:", f"{svc}  (v{mx.get('version') or '?'})")
        preset = mx.get("preset") or "—"
        sets = mx.get("sets") or []
        sets_str = ", ".join(sets[:4]) + (f" +{len(sets)-4}" if len(sets) > 4
                                         else "") if sets else "—"
        box._box_kv("Пресет:", str(preset))
        box._box_kv("Сеты:", sets_str or "—")
        # ── проба ───────────────────────────────────────────────────────
        pr = mx.get("probe") or {}
        healthy = pr.get("healthy")
        pr_str = ("—" if healthy is None else
                  f"{GREEN}OK{NC}" if healthy else f"{RED}DEGRADED{NC}")
        ema = pr.get("ttfb_ema")
        ema_str = f"TTFB {ema:.0f} мс (EMA)" if isinstance(
            ema, (int, float)) else "—"
        box._box_kv("Прямой путь:", f"{pr_str}  {ema_str}"
                    + (f"  streak {pr.get('fail_streak')}"
                       if pr.get("fail_streak") else ""))
        # ── очередь ─────────────────────────────────────────────────────
        qn = ((mx.get("queue") or {}).get("counters") or {}).get("out443")
        qr = (mx.get("queue") or {}).get("rates") or {}
        if qn:
            rate = qr.get("out443")
            rate_str = (f", +{rate}/мин" if rate is not None else "")
            box._box_kv("Очередь (out443):",
                        f"{qn['pkts']} pkts{rate_str}")
        else:
            box._box_kv("Очередь:", f"{DIM}нет нативных правил{NC}")
        # ── exempt ──────────────────────────────────────────────────────
        exm = mx.get("exempt") or {}
        if exm.get("applicable"):
            n = exm.get("entries")
            ex_str = (f"{GREEN}{n} IP{NC}" if n else
                      f"{YELLOW}пуст (алерт){NC}")
            box._box_kv("Exempt ipset:", ex_str)
        # ── монитор / политика ──────────────────────────────────────────
        box._box_sep()
        st_str = f"{GREEN}активен{NC}" if installed else f"{YELLOW}не активен{NC}"
        box._box_kv("Мониторинг:", st_str)
        pol = mx.get("policy") or {}
        pol_str = " ".join(
            f"{'✓' if pol.get(k, True) else '✗'}{lbl}"
            for k, lbl in (("restart", "рестарт"),
                           ("discovery", "discovery"),
                           ("presets", "пресеты")))
        box._box_kv("Политика:", pol_str)
        # ── журнал ──────────────────────────────────────────────────────
        acts = mx.get("actions") or []
        if acts:
            box._box_sep()
            box._box_row(f"  {BOLD}Последние действия:{NC}")
            for a in acts:
                when = time.strftime("%d.%m %H:%M",
                                     time.localtime(a.get("ts") or 0))
                box._box_row(f"  {DIM}{when}{NC} {a.get('type')}: "
                             f"{str(a.get('detail'))[:70]}")
        box._box_sep()
        box._box_item("T", "Прогнать тик сейчас (пробы + self-heal)")
        box._box_item("C", "Проверить сейчас (TG-слой, без проб)")
        box._box_item("P", "Политика: вкл/выкл рестарты / discovery / пресеты")
        if not installed:
            box._box_item("I", f"Установить (тик 1/мин + TG {DEFAULT_INTERVAL} мин)")
            box._box_item("I10", "Установить — TG каждые 10 мин")
            box._box_item("I30", "Установить — TG каждые 30 мин")
        else:
            box._box_item("U", "Удалить мониторинг")
        box._box_item("Q", "← Назад в меню b4")
        box._box_back()
        box._box_bottom()
        print()

        try:
            ch = input(f"{CYAN}Выбор: {NC}").strip().upper()
        except (KeyboardInterrupt, EOFError):
            return
        if ch in ("0", "Q", ""):
            return
        elif ch == "T":
            r = health_tick(verbose=True)
            if not r.get("installed"):
                box._box_warn("b4 не установлен")
            else:
                box._box_ok("Тик отработал"
                            + (f" (ремедия: {r['remedy']})" if r.get("remedy")
                               else ""))
            input(f"{CYAN}Enter...{NC}")
        elif ch == "C":
            rs = check_b4_once()
            if not rs:
                box._box_warn("Монитор не настроен — проверять нечего")
            else:
                for r in rs:
                    if r.get("id") == "action":
                        icon = f"{CYAN}⚡{NC}"
                        box._box_row(f"  {icon} действие: {r.get('label')}"
                                     f" — {str(r.get('detail'))[:60]}")
                        continue
                    h = r.get("healthy")
                    if h is None:
                        continue
                    icon = f"{GREEN}✓{NC}" if h else f"{RED}✗{NC}"
                    extra = ""
                    if r.get("id") == "probe" and r.get("ttfb_ema") is not None:
                        extra = f" — TTFB {r['ttfb_ema']:.0f} мс"
                    if r.get("id") == "exempt":
                        extra = f" — {r.get('entries')} IP"
                    box._box_row(f"  {icon} {r.get('label')}{extra}")
            input(f"{CYAN}Enter...{NC}")
        elif ch == "P":
            st = _load_tick_state()
            pol = st.get("policy") or dict(DEFAULT_POLICY)
            print()
            print(f"  1. Рестарты при падении:     "
                  f"{'✓ вкл' if pol.get('restart', True) else '✗ выкл'}")
            print(f"  2. Discovery при деградации: "
                  f"{'✓ вкл' if pol.get('discovery', True) else '✗ выкл'}")
            print(f"  3. Ротация пресетов:         "
                  f"{'✓ вкл' if pol.get('presets', True) else '✗ выкл'} "
                  "(только для установок с сетом id \"youtube\")")
            try:
                v = input(f"\n{CYAN}Переключить [1-3], Enter — выход:{NC} ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            key = {"1": "restart", "2": "discovery", "3": "presets"}.get(v)
            if key:
                pol[key] = not pol.get(key, True)
                st["policy"] = pol
                _save_tick_state(st)
                box._box_ok(f"{key}: {'вкл' if pol[key] else 'выкл'}")
                input(f"{CYAN}Enter...{NC}")
        elif ch in ("I", "I5"):
            ok, msg = install_b4_monitor(DEFAULT_INTERVAL)
            box._box_ok(msg) if ok else box._box_warn(msg)
            input(f"{CYAN}Enter...{NC}")
        elif ch == "I10":
            ok, msg = install_b4_monitor(10)
            box._box_ok(msg) if ok else box._box_warn(msg)
            input(f"{CYAN}Enter...{NC}")
        elif ch == "I30":
            ok, msg = install_b4_monitor(30)
            box._box_ok(msg) if ok else box._box_warn(msg)
            input(f"{CYAN}Enter...{NC}")
        elif ch == "U" and installed:
            ok, msg = uninstall_b4_monitor()
            box._box_ok(msg) if ok else box._box_warn(msg)
            input(f"{CYAN}Enter...{NC}")


# ══════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":  # pragma: no cover
    import argparse
    p = argparse.ArgumentParser(description="B4 monitor (health-tick + TG)")
    p.add_argument("cmd", choices=["tick", "check", "matrix",
                                   "install", "uninstall"])
    p.add_argument("interval", nargs="?", type=int, default=DEFAULT_INTERVAL)
    args = p.parse_args()
    if args.cmd == "tick":
        r = health_tick(verbose=True)
        print(json.dumps(r, indent=2, ensure_ascii=False, default=str))
    elif args.cmd == "check":
        for r in check_b4_once():
            print(f"  {r}")
    elif args.cmd == "matrix":
        print(json.dumps(matrix(), indent=2, ensure_ascii=False, default=str))
    elif args.cmd == "install":
        print(json.dumps(install_b4_monitor(args.interval)))
    elif args.cmd == "uninstall":
        print(json.dumps(uninstall_b4_monitor()))

