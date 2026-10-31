"""
chimera/modules/librechat_monitor.py
───────────────────────────────────────────────────────────────────────────────
Ops-слой LibreChat — «как у B4» (b4_monitor.py), паттерн v2-мониторов.

Parity-таблица (b4_monitor → librechat_monitor):

  b4_monitor                             → librechat_monitor (этот модуль)
  ─────────────────────────────────────────────────────────────────────────
  health_tick */1 мин (b4-health.timer)  → health_tick */1 мин
                                           (librechat-health.timer)
  systemctl b4 (сервис)                  → systemctl librechat + ПРОБА
                                           /api/config (юнит oneshot/
                                           RemainAfterExit: «active» не
                                           значит, что api жив — контейнеры
                                           могут умереть; проба ловит)
  _probe_direct (TTFB юзер-пути)         → _probe_front (TTFB фронта nginx,
                                           --resolve на 127.0.0.1 — без
                                           DNS/hairpin)
  _ema_metrics (α=0.35, 15 мин)          → EMA ttfb api + front (те же
                                           константы)
  fail_streak ≥ 2 → degraded             → fail_streak ≥ 2 → degraded
                                           (api и front независимо)
  _heal_restart (self-heal + репорт)     → рестарт librechat при падении
                                           сервиса ИЛИ сдохшем api
                                           (compose up пересоздаёт)
  REMEDY_COOLDOWN_S (анти-флаппер)       → тот же cooldown 600с
  —                                      → front-ремедия: nginx reload
                                           (api жив, фронт 2+ фейла)
  b4-monitor (5 мин, TG по смене)        → librechat-monitor (TG по смене)
  b4_stalled (тик не обновляется)        → librechat_stalled
  —                                      → cert-возраст LE-сертификата
                                           фронта (<14 дней — алерт)

Архитектура (как b4_monitor):

  librechat-health.timer (*/1 мин, systemd)
      └─ librechat-health.sh (wrapper, PYTHONPATH-safe)
           └─ health_tick(): пробы + EMA + self-heal + ремедии
                • systemctl librechat + GET /api/config (loopback,
                  --noproxy '*' — http_proxy в окружении не мешает)
                • GET https://front/api/config (--resolve домен:порт:
                  127.0.0.1 — как видит юзер, но без DNS/hairpin)
                • EMA ttfb (α=0.35), fail_streak ≥ 2 → degraded
                • self-heal: рестарт при упавшем сервисе / сдохшем api
                • ремедия фронта: nginx reload (cooldown 600с)
                • cert-дни LE-сертификата (openssl, <14 дней)
                • пишет librechat_monitor_state.json

  /etc/cron.d/librechat-monitor (*/5 мин)
      └─ librechat-monitor.sh (wrapper)
           └─ check_librechat_once(): читает state тика БЕЗ проб
                (пробы делает тик — сеть не дублируем, паттерн mieru):
                • librechat_down / librechat_up      (сервис)
                • librechat_degraded / recovered     (api, streak ≥ 2)
                • librechat_front_down / front_up    (фронт, streak ≥ 2)
                • librechat_stalled                  (тик не обновляется)
                • librechat_restarted / front_fix    (журнал действий)
                • librechat_cert_expire              (<14 дней, по смене
                  порога; восстановление >14 — тоже репорт)
                Анти-спам: алерт ТОЛЬКО при смене состояния; первое
                наблюдение — молча. events.<event> в telegram.json
                (отсутствующий ключ = включено).

Публичный API:
    health_tick(verbose)               → dict
    health_tick_cli()                  → None (для wrapper'а)
    check_librechat_once()             → list[dict]
    matrix() / summary()               → dict (TUI/панели)
    install_librechat_monitor(interval)→ (bool, str) — timer+cron
    uninstall_librechat_monitor()      → (bool, str)
    is_monitor_installed()             → bool
    do_librechat_monitor_menu()        → None (TUI, пункт M меню LibreChat)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Optional

# ── Пути (модульные константы: тесты патчат их в tmp) ──────────────────────
TICK_STATE   = Path("/var/lib/xray-installer/librechat_monitor_state.json")
TG_STATE     = Path("/var/lib/xray-installer/librechat-monitor-state.json")
TG_CONFIG    = Path("/var/lib/xray-installer/telegram.json")
MONITOR_LOG  = Path("/var/log/librechat-monitor.log")

CRON_FILE    = Path("/etc/cron.d/librechat-monitor")
TG_SCRIPT    = Path("/usr/local/bin/librechat-monitor.sh")
TICK_SCRIPT  = Path("/usr/local/bin/librechat-health.sh")
UNIT_TICK    = Path("/etc/systemd/system/librechat-health.service")
UNIT_TIMER   = Path("/etc/systemd/system/librechat-health.timer")

# ── Параметры (константы каскада/b4 — parity) ──────────────────────────────
DEFAULT_INTERVAL       = 5      # мин (TG-часть, как b4/mieru-мониторы)
STALE_AFTER            = 300    # сек: 5 пропущенных тиков
TG_TIMEOUT             = 10     # сек
PROBE_TIMEOUT_S        = 8      # curl --max-time на цель
EMA_ALPHA              = 0.35   # вес свежей пробы (как каскад/b4)
EMA_MAX_AGE_S          = 900    # история старше 15 мин — протухла
FAIL_STREAK_UNHEALTHY  = 2      # 2 подряд фейла → degraded (порог каскада)
REMEDY_COOLDOWN_S      = 600    # одно действие на окно (анти-флаппер)
ACTIONS_KEEP           = 20     # хвост журнала действий
CERT_WARN_DAYS         = 14     # LE-сертификат фронта: алерт ближе порога

# LE-сертификаты фронта (модульная константа — тесты патчат в tmp)
LE_CERT_DIR = Path("/etc/letsencrypt/live")

DEFAULT_POLICY = {"restart": True, "front_fix": True}

# ── События (метки для меню tg_bot; порядок синхронизирован) ───────────────
EVENT_KEYS = [
    "librechat_down", "librechat_up", "librechat_degraded",
    "librechat_recovered", "librechat_stalled", "librechat_restarted",
    "librechat_front_down", "librechat_front_up", "librechat_front_fix",
    "librechat_cert_expire",
]
EVENT_LABELS = {
    "librechat_down":        "LibreChat: сервис упал",
    "librechat_up":          "LibreChat: сервис восстановился",
    "librechat_degraded":    "LibreChat: api не отвечает (2+ фейла)",
    "librechat_recovered":   "LibreChat: api восстановился",
    "librechat_stalled":     "LibreChat: health-tick не обновляется",
    "librechat_restarted":   "LibreChat: рестарт (self-heal)",
    "librechat_front_down":  "LibreChat: nginx front недоступен",
    "librechat_front_up":    "LibreChat: nginx front доступен",
    "librechat_front_fix":   "LibreChat: nginx reload (ремедия)",
    "librechat_cert_expire": "LibreChat: сертификат фронта истекает",
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


def _tg_send(msg: str, event: str = "") -> bool:
    """Отправка в TG с events-фильтром (паттерн v2-мониторов; отсутствующий
    ключ = включено). {H} — заголовок [host | ip] как в b4_monitor."""
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
        _cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "-m", str(TG_TIMEOUT)]
        _px = str(cfg.get("proxy") or "").strip()
        if _px:
            _cmd += ["-x", _px]
        _cmd += [
            f"https://api.telegram.org/bot{token}/sendMessage",
            "-d", f"chat_id={chat}",
            "-d", f"text={text}",
            "-d", "parse_mode=HTML",
        ]
        r = _run(_cmd)
        return (r.stdout or "").strip() == "200"
    except Exception:
        return False


# ── Ленивый librechat (нет жёсткой зависимости — монитор живёт и без него) ──

def _lc():
    from chimera.modules import librechat
    return librechat


def _lc_state() -> dict:
    try:
        return _lc()._load_state()
    except Exception:
        return {}


def _lc_installed() -> bool:
    """Установлен ли LibreChat (state + compose-файл) — как меню модуля."""
    try:
        lc = _lc()
        st = lc._load_state()
        return bool(st.get("installed")) and \
            (lc._APP_DIR / "docker-compose.yml").exists()
    except Exception:
        return False


def _front_status() -> dict:
    """nginx front из librechat._nginx_status(): enabled/port/domain."""
    try:
        return _lc()._nginx_status() or {}
    except Exception:
        return {}


# ══════════════════════════════════════════════════════════════════════════
#  ПРОБЫ
# ══════════════════════════════════════════════════════════════════════════

def _probe_service() -> bool:
    try:
        return _lc()._service_active()
    except Exception:
        return False


def _curl_probe(url: str, resolve: "Optional[str]" = None,
                insecure: bool = False) -> dict:
    """GET-проба curl: {ok, code, ms}. ok = HTTP 2xx (api/config отдаёт
    ровно 200; на фронте 2xx — живой путь).

    --noproxy '*' — http_proxy в окружении не гоняет 127.0.0.1 через
    прокси (инцидент librechat._smoke_check). resolve домен:порт:127.0.0.1
    — фронт как видит юзер (SNI/домен совпадают с сертификатом), но без
    DNS-зависимости и hairpin-NAT."""
    cmd = ["curl", "-s", "-o", "/dev/null",
           "-w", "%{http_code} %{time_total}",
           "--noproxy", "*", "--max-time", str(PROBE_TIMEOUT_S)]
    if resolve:
        cmd += ["--resolve", resolve]
    if insecure:
        cmd += ["-k"]
    cmd.append(url)
    try:
        r = _run(cmd, timeout=PROBE_TIMEOUT_S + 4)
        parts = (r.stdout or "").split()
        code = parts[0] if parts else ""
        tsec = float(parts[1]) if len(parts) > 1 else None
        ok = (r.returncode == 0 and code.startswith("2"))
        return {"ok": ok,
                "code": code or "TIMEOUT/RESET",
                "ms": round(tsec * 1000.0, 1) if tsec is not None else None}
    except Exception as e:
        return {"ok": False, "code": "ERR", "err": str(e), "ms": None}


def _probe_api(port: int) -> dict:
    """Проба api на loopback-порту (то, что проверяет смоук установки)."""
    p = _curl_probe(f"http://127.0.0.1:{port}/api/config")
    return {"ok": p["ok"], "ttfb_ms": p["ms"],
            "code": p["code"], "err": p.get("err")}


def _front_url_domain(front: dict) -> "tuple[Optional[str], Optional[int], Optional[str]]":
    """(url, domain, port) для пробы фронта или (None,…) если выключен."""
    if not front.get("enabled"):
        return None, None, None
    port = int(front.get("port") or 0)
    if port <= 0:
        return None, None, None
    domain = front.get("domain")
    if domain:
        return f"https://{domain}:{port}/api/config", domain, port
    # self-signed без домена — пробуем по 127.0.0.1 (insecure)
    return f"https://127.0.0.1:{port}/api/config", None, port


def _probe_front(front: dict) -> dict:
    """Проба nginx front: applicable=False если фронт выключен."""
    url, domain, port = _front_url_domain(front)
    if url is None:
        return {"applicable": False, "ok": None}
    resolve = f"{domain}:{port}:127.0.0.1" if domain else None
    p = _curl_probe(url, resolve=resolve, insecure=domain is None)
    return {"applicable": True, "ok": p["ok"], "ttfb_ms": p["ms"],
            "code": p["code"], "err": p.get("err")}


def _heal_restart() -> bool:
    """Рестарт librechat (self-heal, как _heal_restart b4): compose up
    пересоздаёт сдохшие контейнеры. Возвращает активность ПОСЛЕ."""
    try:
        _lc()._run(["systemctl", "restart", _lc()._SERVICE_NAME],
                   capture=True, check=False, timeout=600)
    except Exception:
        pass
    time.sleep(5)          # дать юниту подняться до повторной пробы
    return _probe_service()


def _front_fix_reload() -> bool:
    """Ремедия фронта: nginx reload (конфиг-дрейф/умерший воркер; api жив).
    Reload не рвёт соединения — безопасная ремедия."""
    r = _run(["systemctl", "reload", "nginx"], timeout=30)
    return r.returncode == 0


def _cert_days(domain: "Optional[str]") -> "Optional[int]":
    """Дни до истечения LE-сертификата фронта (openssl). None = нет
    домена/сертификата (self-signed без LE) — нечего мониторить.

    Таймзону в notAfter отбрасываем (rsplit): strptime c %Z="GMT"
    даёт aware-datetime — вычитание наивного utcnow() кидало бы
    TypeError (поймано тестом test_parse_days)."""
    if not domain:
        return None
    cert = LE_CERT_DIR / domain / "fullchain.pem"
    if not cert.exists():
        return None
    r = _run(["openssl", "x509", "-enddate", "-noout", "-in", str(cert)],
             timeout=10)
    out = (r.stdout or "").strip()
    if r.returncode != 0 or "notAfter=" not in out:
        return None
    try:
        import datetime
        naive = out.split("notAfter=", 1)[1].strip().rsplit(None, 1)[0]
        expires = datetime.datetime.strptime(
            naive, "%b %d %H:%M:%S %Y")
        return int((expires - datetime.datetime.utcnow()).days)
    except Exception:
        return None


def _ema_update(hist: Optional[dict], fresh: Optional[float]) -> Optional[float]:
    """EMA-сглаживание ttfb_ms (порт _ema_metrics каскада/b4, α=0.35).

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


def _streak_update(prev: Optional[bool], prev_streak: int,
                   ok: bool) -> "tuple[bool, int]":
    """fail_streak/healthy (семантика b4 health_tick): 1 промах при
    прошлом healthy — «скорельно жив», 2 подряд → degraded."""
    if ok:
        return True, 0
    streak = prev_streak + 1
    healthy = bool(prev) and streak < FAIL_STREAK_UNHEALTHY
    return healthy, streak


# ══════════════════════════════════════════════════════════════════════════
#  HEALTH-TICK (ядро, */1 мин; вызывается из librechat-health.sh)
# ══════════════════════════════════════════════════════════════════════════

def health_tick(verbose: bool = False) -> dict:
    """Один тик: сервис → api-проба → фронт → EMA → self-heal/ремедия.

    Устойчив к «LibreChat не установлен» (тихий noop — как health_tick
    b4/каскада) и к любым сбоям проб: сбой = фейл пробы, не крэш тика.
    """
    result = {"installed": True, "service": None, "probe_ok": None,
              "healthy": None, "fail_streak": None, "front": None,
              "cert_days": None, "remedy": None, "actions": []}
    if not _lc_installed():
        return {"installed": False}
    st = _load_tick_state()
    policy = st.get("policy") or dict(DEFAULT_POLICY)
    now = time.time()

    # ── 1. сервис + self-heal при падении (как _heal_restart b4) ────────
    service_active = _probe_service()
    if not service_active and policy.get("restart", True):
        ok = _heal_restart()
        _action_append(st, "restart",
                       "self-heal рестарт: " + ("ок, поднялся"
                                                if ok else "не поднялся"))
        result["actions"].append("restart")
        service_active = ok
    result["service"] = service_active

    # ── 2. api-проба (loopback /api/config — ловит сдохшие контейнеры,
    #        которые systemd-oneshot «active» не видит) ───────────────────
    port = int(_lc_state().get("web_port") or _lc()._DEFAULT_PORT)
    probe = _probe_api(port) if service_active else \
        {"ok": False, "ttfb_ms": None, "code": "service inactive"}
    prev_probe = st.get("probe") or {}
    healthy, fail_streak = _streak_update(
        prev_probe.get("healthy"), int(prev_probe.get("fail_streak") or 0),
        probe["ok"])

    # ── 3. EMA ttfb api (α=0.35, протухла >15 мин → быстрый старт) ──────
    ttfb_ema = _ema_update((st.get("ema") or {}).get("api"),
                           probe.get("ttfb_ms"))
    st["probe"] = {
        "healthy": healthy, "fail_streak": fail_streak,
        "ttfb_ms": probe.get("ttfb_ms"), "ttfb_ema": ttfb_ema,
        "last_code": probe.get("code"),
        "last_check": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    result.update(probe_ok=probe["ok"], healthy=healthy,
                  fail_streak=fail_streak)

    # ── 4. фронт (если включён): проба + streak + EMA ───────────────────
    front_cfg = _front_status()
    front = _probe_front(front_cfg)
    prev_front = st.get("front") or {}
    if front.get("applicable"):
        f_prev_h = prev_front.get("healthy")
        f_prev_streak = int(prev_front.get("fail_streak") or 0)
        f_healthy, f_streak = _streak_update(f_prev_h, f_prev_streak,
                                             bool(front.get("ok")))
        f_ema = _ema_update((st.get("ema") or {}).get("front"),
                            front.get("ttfb_ms"))
        st["front"] = {"applicable": True, "healthy": f_healthy,
                       "fail_streak": f_streak,
                       "ttfb_ms": front.get("ttfb_ms"), "ttfb_ema": f_ema,
                       "last_code": front.get("code")}
        result["front"] = {"applicable": True, "healthy": f_healthy,
                           "fail_streak": f_streak,
                           "ttfb_ema": f_ema}
    else:
        st["front"] = {"applicable": False}
        result["front"] = {"applicable": False}
    st["ema"] = {}
    if ttfb_ema is not None:
        st["ema"]["api"] = {"ts": now, "v": ttfb_ema}
    if st["front"].get("ttfb_ema") is not None:
        st["ema"]["front"] = {"ts": now, "v": st["front"]["ttfb_ema"]}

    # ── 5. ремедии (cooldown 600с — одно действие на окно) ──────────────
    #    api сдох при живом сервисе → рестарт стека (compose up пересоздаёт)
    #    фронт сдох (streak ≥ 2) при живом api → nginx reload
    last_remedy = float(st.get("last_remedy_ts") or 0)
    remedy_ok_ts = (now - last_remedy) >= REMEDY_COOLDOWN_S
    remedy_type: Optional[str] = None
    if remedy_ok_ts:
        api_dead = (not healthy) and service_active
        front_dead = (bool(st["front"].get("applicable"))
                      and st["front"].get("healthy") is False)
        if api_dead and policy.get("restart", True):
            ok = _heal_restart()
            remedy_type = "restart"
            _action_append(st, "restart",
                           "api не отвечает (streak "
                           f"{fail_streak}): рестарт стека — "
                           + ("поднялся" if ok else "не поднялся"))
            result["actions"].append("restart")
            service_active = ok
        elif front_dead and policy.get("front_fix", True):
            ok = _front_fix_reload()
            remedy_type = "front_fix"
            _action_append(st, "front_fix",
                           "фронт не отвечает (streak "
                           f"{st['front'].get('fail_streak')}), api жив: "
                           "nginx reload — " + ("ок" if ok else "FAIL"))
            result["actions"].append("front_fix")
        if remedy_type:
            st["last_remedy_ts"] = now
    result["remedy"] = remedy_type

    # ── 6. сертификат фронта (LE): дни до истечения ─────────────────────
    cert_days = _cert_days(front_cfg.get("domain"))
    st["cert"] = {"ts": now, "days": cert_days}
    result["cert_days"] = cert_days

    # ── 7. сохранить + вернуть ──────────────────────────────────────────
    st["policy"] = policy
    st["ts"] = now
    _save_tick_state(st)
    # changed — действия ЭТОГО тика; TG-слой шлёт их отдельно по журналу,
    # здесь — для verbose/CLI-вызова
    result["changed"] = list(result["actions"])
    if verbose:
        ema_str = f" ema={ttfb_ema:.0f}мс" if ttfb_ema else ""
        ttfb = probe.get("ttfb_ms")
        print(f"  librechat: сервис="
              f"{'active' if service_active else 'DOWN'}"
              f" api={'OK' if probe['ok'] else 'FAIL'}"
              f" (streak {fail_streak})"
              + (f" ttfb={ttfb:.0f}мс" if ttfb else "") + ema_str)
        f = st["front"]
        if f.get("applicable"):
            f_ema = f.get("ttfb_ema")
            print(f"  фронт: {'OK' if f.get('healthy') else 'DEGRADED'}"
                  + (f" (streak {f.get('fail_streak')})")
                  + (f" ttfb_ema={f_ema:.0f}мс" if f_ema else ""))
        if cert_days is not None:
            print(f"  cert: {cert_days} дн.")
        if remedy_type:
            print(f"  ремедия: {remedy_type}")
    return result


def health_tick_cli() -> None:
    """Точка входа wrapper'а librechat-health.sh (тихий, вывод — logger)."""
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


def check_librechat_once() -> list:
    """Разовая проверка (TG-слой). Алерты ТОЛЬКО при смене состояния.

    Читает librechat_monitor_state.json (его пишет тик каждую минуту —
    пробы НЕ дублируем) + systemctl для сервиса. Первое наблюдение —
    молча (анти-спам по построению, как b4/mieru-мониторы).
    """
    results: list = []
    alerts: list = []
    if not TICK_STATE.exists():
        _log("нет librechat_monitor_state.json — LibreChat/монитор "
             "не настроен, выходим")
        return results
    try:
        st = json.loads(TICK_STATE.read_text(encoding="utf-8"))
    except Exception as exc:
        _log(f"librechat_monitor_state.json не читается: {exc}")
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
        alerts.append(("librechat_stalled",
                "⚠️ <b>{H}</b> LibreChat health-tick не обновляется "
                f"(&gt;{STALE_AFTER // 60} мин)\n"
                "Проверь <code>systemctl status "
                "librechat-health.timer</code>\n"
                f"<i>{ts}</i>"))
        _log("STALL: тик не обновляет state")
    elif not stalled_now and prev_stalled:
        alerts.append(("librechat_stalled",
                "🟢 <b>{H}</b> LibreChat health-tick обновляется\n"
                f"<i>{ts}</i>"))
        _log("STALL снят")

    # ── 2. сервис (systemctl) ──────────────────────────────────────────
    service_active = _probe_service()
    prev_service = prev.get("service", {}).get("active")
    if prev_service is True and not service_active:
        alerts.append(("librechat_down",
                "🔴 <b>{H}</b> LibreChat не запущен!\n"
                "AI-чат недоступен (пользователи не зайдут)\n"
                f"<i>{ts}</i>"))
        _log("LIBRECHAT DOWN")
    elif prev_service is False and service_active:
        alerts.append(("librechat_up",
                "🟢 <b>{H}</b> LibreChat восстановился\n"
                f"<i>{ts}</i>"))
        _log("LIBRECHAT UP")
    results.append({"id": "service", "label": "librechat",
                    "host": "local", "healthy": service_active,
                    "changed": False})

    # ── 3. api-проба (healthy из state тика; порог streak ≥ 2) ─────────
    probe = st.get("probe") or {}
    healthy = bool(probe.get("healthy"))
    prev_h = prev.get("probe", {}).get("healthy")
    ema = probe.get("ttfb_ema")
    if prev_h is True and not healthy:
        streak = probe.get("fail_streak")
        alerts.append(("librechat_degraded",
                "🟠 <b>{H}</b> LibreChat: api не отвечает\n"
                f"fail_streak {streak} — контейнер завис или упал\n"
                "Журнал: <code>journalctl -u librechat</code>\n"
                f"<i>{ts}</i>"))
        _log(f"API DEGRADED (streak {streak})")
    elif prev_h is False and healthy:
        ms = f" — TTFB {ema:.0f} мс" if isinstance(ema, (int, float)) else ""
        alerts.append(("librechat_recovered",
                "🟢 <b>{H}</b> LibreChat: api восстановлен" + ms
                + "\n" + f"<i>{ts}</i>"))
        _log("API RECOVERED")
    results.append({"id": "probe", "label": "api", "host": "librechat",
                    "healthy": healthy, "changed": False,
                    "fail_streak": probe.get("fail_streak"),
                    "ttfb_ema": ema})

    # ── 4. фронт (applicable только когда nginx front включён) ─────────
    front = st.get("front") or {}
    cert_days = (st.get("cert") or {}).get("days")
    if front.get("applicable"):
        f_h = bool(front.get("healthy"))
        prev_fh = prev.get("front", {}).get("healthy")
        f_ema = front.get("ttfb_ema")
        url = ""
        try:
            url = _lc()._nginx_url() or ""
        except Exception:
            pass
        if prev_fh is True and not f_h:
            alerts.append(("librechat_front_down",
                    "🟠 <b>{H}</b> LibreChat: nginx front недоступен"
                    " (2+ фейла)\n"
                    "api жив — проблема в nginx/TLS/сертификате\n"
                    + (f"<code>{url}</code>\n" if url else "")
                    + f"<i>{ts}</i>"))
            _log("FRONT DOWN")
        elif prev_fh is False and f_h:
            ms = (f" — TTFB {f_ema:.0f} мс"
                  if isinstance(f_ema, (int, float)) else "")
            alerts.append(("librechat_front_up",
                    "🟢 <b>{H}</b> LibreChat: nginx front доступен" + ms
                    + "\n" + f"<i>{ts}</i>"))
            _log("FRONT UP")
        results.append({"id": "front", "label": "front", "host": "nginx",
                        "healthy": f_h, "changed": False,
                        "fail_streak": front.get("fail_streak"),
                        "ttfb_ema": f_ema})
        # ── 5. сертификат: пересечение порога 14 дней (по смене) ────────
        prev_cert = prev.get("cert", {}).get("days")
        now_low = cert_days is not None and cert_days <= CERT_WARN_DAYS
        prev_low = (prev_cert is not None and prev_cert <= CERT_WARN_DAYS)
        if now_low and not prev_low:
            alerts.append(("librechat_cert_expire",
                    "📜 <b>{H}</b> LibreChat: сертификат фронта истекает "
                    f"({cert_days} дн.)\n"
                    "<code>certbot renew</code> не отработал?\n"
                    f"<i>{ts}</i>"))
            _log(f"CERT LOW: {cert_days} дн.")
        elif prev_low and cert_days is not None and not now_low:
            alerts.append(("librechat_cert_expire",
                    "🟢 <b>{H}</b> LibreChat: сертификат фронта продлён "
                    f"({cert_days} дн.)\n"
                    f"<i>{ts}</i>"))
            _log(f"CERT OK: {cert_days} дн.")

    # ── 6. новые действия тика (restart/front_fix) ─────────────────────
    try:
        last_action_ts = float(prev.get("last_action_ts") or 0)
    except (TypeError, ValueError):
        last_action_ts = 0.0
    new_actions = [a for a in (st.get("actions") or [])
                   if float(a.get("ts") or 0) > last_action_ts]
    for a in new_actions:
        ev = {"restart": "librechat_restarted",
              "front_fix": "librechat_front_fix"}.get(a.get("type"))
        if not ev:
            continue
        icon = {"librechat_restarted": "🔧",
                "librechat_front_fix": "🔁"}.get(ev, "•")
        head = {"librechat_restarted": "рестарт стека (self-heal)",
                "librechat_front_fix": "nginx reload (ремедия)"}[ev]
        # {H} — литерал-плейсхолдер (заменяет _tg_send); НЕ f-string
        # (паттерн b4: иначе NameError по несуществующей переменной H)
        alerts.append((ev,
                icon + " <b>{H}</b> LibreChat: " + head
                + "\n" + str(a.get("detail", "")) + f"\n<i>{ts}</i>"))
        _log(f"ACTION {a.get('type')}: {str(a.get('detail'))[:120]}")
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
        "front": {"healthy": (bool(front.get("healthy"))
                              if front.get("applicable") else None)},
        "cert": {"days": cert_days},
        "stalled": stalled_now,
        "last_action_ts": last_action_ts,
        "last_check": time.time(),
    })
    return results


# ══════════════════════════════════════════════════════════════════════════
#  МАТРИЦА (TUI / панели)
# ══════════════════════════════════════════════════════════════════════════

def matrix() -> dict:
    """Сводка «как у b4» одним слоем: сервис + api-проба (EMA) + фронт +
    сертификат + журнал действий + состояние монитора. Только локальные
    файлы и systemctl — сеть не трогает."""
    out: dict = {"installed": _lc_installed(), "monitor": {
        "installed": is_monitor_installed(),
        "interval": get_installed_interval(),
        "timer_active": _systemd_is_active("librechat-health.timer")
                        == "active",
    }}
    if out["installed"]:
        out["service"] = _probe_service()
        try:
            out["url"] = _lc()._nginx_url()
        except Exception:
            out["url"] = None
    st = _load_tick_state()
    out["probe"] = st.get("probe") or {}
    out["front"] = st.get("front") or {}
    out["cert"] = st.get("cert") or {}
    out["policy"] = st.get("policy") or dict(DEFAULT_POLICY)
    out["actions"] = (st.get("actions") or [])[-5:]
    out["tick_ts"] = st.get("ts")
    return out


def summary() -> dict:
    """Компакт для панелей: одна строка состояния."""
    st = _load_tick_state()
    probe = st.get("probe") or {}
    front = st.get("front") or {}
    return {
        "installed": _lc_installed(),
        "service": _probe_service(),
        "healthy": probe.get("healthy"),
        "fail_streak": probe.get("fail_streak"),
        "ttfb_ema": probe.get("ttfb_ema"),
        "front_healthy": (front.get("healthy")
                          if front.get("applicable") else None),
        "front_ttfb_ema": front.get("ttfb_ema"),
        "cert_days": (st.get("cert") or {}).get("days"),
        "last_actions": [a.get("type")
                         for a in (st.get("actions") or [])[-3:]],
        "monitor_installed": is_monitor_installed(),
    }


# ══════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА / УДАЛЕНИЕ (timer */1 мин + cron */5 мин)
# ══════════════════════════════════════════════════════════════════════════

def _systemd_is_active(unit: str) -> str:
    """'active' | 'inactive' | ... — обёртка для тестов."""
    try:
        r = _run(["systemctl", "is-active", unit], timeout=10)
        return (r.stdout or "").strip() or "unknown"
    except Exception:
        return "unknown"


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
    """Путь установки пакета chimera (паттерн b4_monitor)."""
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


def install_librechat_monitor(interval: int = DEFAULT_INTERVAL) -> tuple:
    """Timer librechat-health (*/1 мин, systemd) + cron librechat-monitor
    (*/5 мин). Wrapper'ы — PYTHONPATH-safe паттерн v5.1 (cron/timer
    стартует с произвольной cwd; bare python -c падает с
    ModuleNotFoundError)."""
    try:
        interval = max(1, min(60, int(interval)))
        installer_path = _find_installer_path()
        python = _find_python()

        TICK_SCRIPT.write_text(
            f"""#!/bin/bash
# librechat-health.sh — health-tick LibreChat (Chimera librechat_monitor),
# вызывается timer'ом librechat-health.timer каждые 60с. Пробы/
# самозалечивание/ремедии — в модуле.
export PYTHONPATH="{installer_path}:$PYTHONPATH"
{python} -c "
import sys
sys.path.insert(0, '{installer_path}')
from chimera.modules.librechat_monitor import health_tick_cli
health_tick_cli()
" 2>&1 | logger -t librechat-health
""", encoding="utf-8")
        TICK_SCRIPT.chmod(0o755)

        UNIT_TICK.write_text(
            "[Unit]\n"
            "Description=LibreChat health check + self-heal + remedy\n"
            "After=network-online.target docker.service\n"
            "\n"
            "[Service]\n"
            "Type=oneshot\n"
            f"ExecStart={TICK_SCRIPT}\n"
        )
        UNIT_TIMER.write_text(
            "[Unit]\n"
            "Description=LibreChat health timer (1/min)\n"
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
        _run(["systemctl", "enable", "--now", "librechat-health.timer"])

        TG_SCRIPT.write_text(
            f"""#!/bin/bash
# librechat-monitor.sh — TG-монитор LibreChat (Chimera librechat_monitor).
# Читает state тика (пробы НЕ дублирует — их делает тик), алерты при
# СМЕНЕ состояния.
export PYTHONPATH="{installer_path}:$PYTHONPATH"
{python} -c "
import sys
sys.path.insert(0, '{installer_path}')
from chimera.modules.librechat_monitor import check_librechat_once
check_librechat_once()
" 2>>/var/log/librechat-monitor.log
""", encoding="utf-8")
        TG_SCRIPT.chmod(0o755)
        CRON_FILE.write_text(
            f"""# librechat-monitor — TG-монитор LibreChat каждые {interval} мин
*/{interval} * * * * root {TG_SCRIPT} >/dev/null 2>&1
""", encoding="utf-8")
        CRON_FILE.chmod(0o644)
        _log(f"установлен: timer 1/мин + cron */{interval}")
        return True, ("LibreChat мониторинг установлен: health-tick "
                      f"1/мин + TG-проверка каждые {interval} мин")
    except Exception as e:
        return False, f"Ошибка установки: {e}"


def uninstall_librechat_monitor() -> tuple:
    try:
        _run(["systemctl", "disable", "--now", "librechat-health.timer"])
        for p in (UNIT_TICK, UNIT_TIMER, TICK_SCRIPT, CRON_FILE,
                  TG_SCRIPT, TG_STATE):
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass
        _run(["systemctl", "daemon-reload"])
        _log("удалён (timer + cron + wrappers + tg-state)")
        return True, "LibreChat мониторинг удалён (timer+cron+скрипты+state)"
    except Exception as e:
        return False, f"Ошибка удаления: {e}"


# ══════════════════════════════════════════════════════════════════════════
#  TUI-МЕНЮ (пункт M меню LibreChat)
# ══════════════════════════════════════════════════════════════════════════

def do_librechat_monitor_menu() -> None:
    """Меню мониторинга LibreChat (паттерн do_b4_monitor_menu)."""
    import os
    lc = _lc()

    RED, GREEN, YELLOW, CYAN, BOLD, DIM, NC = (
        lc.RED, lc.GREEN, lc.YELLOW, lc.CYAN, lc.BOLD, lc.DIM, lc.NC)
    box = lc
    while True:
        os.system("clear")
        mx = matrix()
        installed = mx["monitor"]["installed"]

        box._box_top("🩺  МОНИТОРИНГ LIBRECHAT (HEALTH-TICK + TG)")
        box._box_row("  Ops-слой — как у B4: тик 1/мин (пробы, self-heal,")
        box._box_row("  ремедия) + TG по смене состояния. Проба api =")
        box._box_row("  GET /api/config (юнит oneshot «active» ≠ api жив).")
        box._box_sep()
        if not mx["installed"]:
            box._box_warn("LibreChat не установлен — мониторить нечего.")
            box._box_row()
            box._box_back()
            box._box_bot()
            try:
                ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                return
            if ch in ("q", "0", ""):
                return
            continue

        # ── сервис ──────────────────────────────────────────────────────
        svc = (f"{GREEN}active{NC}" if mx.get("service")
               else f"{RED}down{NC}")
        box._box_kv("Сервис:", svc)
        # ── api-проба ───────────────────────────────────────────────────
        pr = mx.get("probe") or {}
        healthy = pr.get("healthy")
        pr_str = ("—" if healthy is None else
                  f"{GREEN}OK{NC}" if healthy else f"{RED}DEGRADED{NC}")
        ema = pr.get("ttfb_ema")
        ema_str = f"TTFB {ema:.0f} мс (EMA)" if isinstance(
            ema, (int, float)) else "—"
        box._box_kv("API (/api/config):", f"{pr_str}  {ema_str}"
                    + (f"  streak {pr.get('fail_streak')}"
                       if pr.get("fail_streak") else ""))
        # ── фронт ───────────────────────────────────────────────────────
        fr = mx.get("front") or {}
        if fr.get("applicable"):
            fh = fr.get("healthy")
            fr_str = ("—" if fh is None else
                      f"{GREEN}OK{NC}" if fh else f"{RED}DOWN{NC}")
            f_ema = fr.get("ttfb_ema")
            f_str = (f"TTFB {f_ema:.0f} мс (EMA)"
                     if isinstance(f_ema, (int, float)) else "")
            box._box_kv("Nginx front:", f"{fr_str}  {f_str}")
            cert = (mx.get("cert") or {}).get("days")
            if cert is not None:
                cert_str = (f"{GREEN}{cert} дн.{NC}" if cert > CERT_WARN_DAYS
                            else f"{RED}{cert} дн. (алерт){NC}")
                box._box_kv("Сертификат:", cert_str)
        else:
            box._box_kv("Nginx front:", f"{DIM}выключен{NC}")
        # ── монитор / политика ──────────────────────────────────────────
        box._box_sep()
        st_str = f"{GREEN}активен{NC}" if installed else \
            f"{YELLOW}не активен{NC}"
        box._box_kv("Мониторинг:", st_str)
        pol = mx.get("policy") or {}
        pol_str = " ".join(
            f"{'✓' if pol.get(k, True) else '✗'}{lbl}"
            for k, lbl in (("restart", "рестарты"),
                           ("front_fix", "nginx-reload")))
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
        box._box_item("P", "Политика: вкл/выкл рестарты / nginx-reload")
        if not installed:
            box._box_item("I", "Установить (тик 1/мин + TG "
                               f"{DEFAULT_INTERVAL} мин)")
            box._box_item("I10", "Установить — TG каждые 10 мин")
            box._box_item("I30", "Установить — TG каждые 30 мин")
        else:
            box._box_item("U", "Удалить мониторинг")
        box._box_item("Q", "← Назад в меню LibreChat")
        box._box_back()
        box._box_bot()
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
                box._box_warn("LibreChat не установлен")
            else:
                box._box_ok("Тик отработал"
                            + (f" (ремедия: {r['remedy']})"
                               if r.get("remedy") else ""))
            input(f"{CYAN}Enter...{NC}")
        elif ch == "C":
            rs = check_librechat_once()
            if not rs:
                box._box_warn("Монитор не настроен — проверять нечего")
            else:
                for r in rs:
                    if r.get("id") == "action":
                        box._box_row(f"  {CYAN}⚡{NC} действие: "
                                     f"{r.get('label')}"
                                     f" — {str(r.get('detail'))[:60]}")
                        continue
                    h = r.get("healthy")
                    if h is None:
                        continue
                    icon = f"{GREEN}✓{NC}" if h else f"{RED}✗{NC}"
                    extra = ""
                    if r.get("id") == "probe" and \
                            r.get("ttfb_ema") is not None:
                        extra = f" — TTFB {r['ttfb_ema']:.0f} мс"
                    if r.get("id") == "front":
                        extra = (f" — TTFB {r['ttfb_ema']:.0f} мс"
                                 if r.get("ttfb_ema") is not None else "")
                    box._box_row(f"  {icon} {r.get('label')}{extra}")
            input(f"{CYAN}Enter...{NC}")
        elif ch == "P":
            st = _load_tick_state()
            pol = st.get("policy") or dict(DEFAULT_POLICY)
            print()
            print(f"  1. Рестарты при падении/api-смерти: "
                  f"{'✓ вкл' if pol.get('restart', True) else '✗ выкл'}")
            print(f"  2. Nginx reload при смерти фронта:   "
                  f"{'✓ вкл' if pol.get('front_fix', True) else '✗ выкл'}")
            try:
                v = input(f"\n{CYAN}Переключить [1-2], "
                          "Enter — выход:{NC} ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            key = {"1": "restart", "2": "front_fix"}.get(v)
            if key:
                pol[key] = not pol.get(key, True)
                st["policy"] = pol
                _save_tick_state(st)
                box._box_ok(f"{key}: {'вкл' if pol[key] else 'выкл'}")
                input(f"{CYAN}Enter...{NC}")
        elif ch in ("I", "I5"):
            ok, msg = install_librechat_monitor(DEFAULT_INTERVAL)
            (box._box_ok if ok else box._box_warn)(msg)
            input(f"{CYAN}Enter...{NC}")
        elif ch == "I10":
            ok, msg = install_librechat_monitor(10)
            (box._box_ok if ok else box._box_warn)(msg)
            input(f"{CYAN}Enter...{NC}")
        elif ch == "I30":
            ok, msg = install_librechat_monitor(30)
            (box._box_ok if ok else box._box_warn)(msg)
            input(f"{CYAN}Enter...{NC}")
        elif ch == "U" and installed:
            ok, msg = uninstall_librechat_monitor()
            (box._box_ok if ok else box._box_warn)(msg)
            input(f"{CYAN}Enter...{NC}")


# ══════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":  # pragma: no cover
    import argparse
    p = argparse.ArgumentParser(
        description="LibreChat monitor (health-tick + TG)")
    p.add_argument("cmd", choices=["tick", "check", "matrix",
                                   "install", "uninstall"])
    p.add_argument("interval", nargs="?", type=int,
                   default=DEFAULT_INTERVAL)
    args = p.parse_args()
    if args.cmd == "tick":
        r = health_tick(verbose=True)
        print(json.dumps(r, indent=2, ensure_ascii=False, default=str))
    elif args.cmd == "check":
        for r in check_librechat_once():
            print(f"  {r}")
    elif args.cmd == "matrix":
        print(json.dumps(matrix(), indent=2, ensure_ascii=False,
                         default=str))
    elif args.cmd == "install":
        print(json.dumps(install_librechat_monitor(args.interval)))
    elif args.cmd == "uninstall":
        print(json.dumps(uninstall_librechat_monitor()))
