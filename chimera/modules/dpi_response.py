"""
chimera/modules/dpi_response.py
───────────────────────────────────────────────────────────────────────────────
DPI Response — автоматическая реакция на DPI-атаку (замыкает треугольник
dpi_detector → fragment_fuzzer → credential_rotation; идея «detect →
rotate without disconnect» из AIVPN, адаптация под оркестратор Химеры).

  • Входы: счётчики dpi_detector (зонды за окно), вердикты mask_gate
    (FAIL/SUSPECT) и dpi_gate (tunnel)
  • Уровни реакции (rule-based, без ML в рантайме):
      notify  — TG-уведомление оператору (всегда)
      fuzz    — авто-запуск fragment_fuzzer: поиск рабочих параметров
                TLS-фрагментации против текущего DPI
      rotate  — плановая ротация REALITY-ключей (credential_rotation)
                в окно минимальной нагрузки (ночь), с cooldown
  • Защиты: cooldown между ротациями (6 ч), max ротаций/сутки (2),
    ночной буфер 03:00–06:00, режим «только notify» при повторных
    неудачах, полный audit-trail в dpi_response.json
  • Анти-спам уведомлений: TG — событие (старт эпизода / эскалация
    уровня / скачок score против скользящей базы / напоминание при
    удержании уровня 2 дольше notify_cooldown_min), а не каждый
    5-минутный прогон крона. Фоновое зондирование (типично для
    RU-нод: счётчик постоянно выше минимального порога) молча
    пишется в лог/history; фаззер — не чаще fuzz_cooldown_min
  • Cron каждые 5 мин (main.py --dpi-response)

State: /var/lib/xray-installer/dpi_response.json
Точка входа из TUI: через меню DPI-детектора (пункт R) или напрямую
    from chimera.modules.dpi_response import do_manage_dpi_response
CLI (main.py): --dpi-response (cron-прогон), --dpi-response-status
"""
from __future__ import annotations

import copy
import json
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# ── Пути ──────────────────────────────────────────────────────────────────────
_LIB_DIR            = Path("/var/lib/xray-installer")
STATE_FILE          = _LIB_DIR / "dpi_response.json"
DPI_DETECTOR_STATE  = _LIB_DIR / "dpi_detector.json"
MASK_GATE_DIR       = _LIB_DIR / "mask_gate"
DPI_GATE_DIR        = _LIB_DIR / "dpi_gate"
XRAY_ERROR_LOG      = Path("/var/log/xray/error.log")
LOG_FILE            = Path("/var/log/chimera.log")
CRON_FILE           = Path("/etc/cron.d/chimera-dpi-response")

# ── Дефолты (консервативные: notify всегда, fuzz да, rotate — за тумблером
#    с ночным окном; включается оператором осознанно) ─────────────────────────
DEFAULTS = {
    "enabled": True,              # cron-прогон активен
    "probe_threshold": 3,         # зондов за окно → уровень 1 (подозрение)
    "probe_threshold_2": 300,     # score за окно → уровень 2 (атака)
    "window_min": 30,             # окно агрегации зондов, мин
    "action_notify": True,        # TG-уведомление (анти-спам — _notify_gate)
    "action_fuzz": True,          # уровень 1: авто-фаззер фрагментации
    "action_rotate": False,       # уровень 2: авто-ротация REALITY-ключей
    "notify_cooldown_min": 60,    # анти-спам: пауза повторных уведомлений
    "notify_spike_ratio": 4.0,    # score ≥ ratio×базы → уровень 2 (скачок)
    "fuzz_cooldown_min": 60,      # анти-спам ресурса: пауза авто-фаззера
    "spike_baseline_floor": 40,   # мин. база для детекта скачка (анти-шум)
    "rotate_window_start": 3,     # ночное окно: с 03:00
    "rotate_window_end": 6,       # до 06:00
    "rotate_cooldown_hours": 6,   # мин. пауза между ротациями
    "rotate_max_per_day": 2,      # предохранитель: не более 2 ротаций/сутки
    "history": [],                # журнал действий (последние 100)
    "stats": {"notifications": 0, "fuzz_runs": 0, "rotations": 0,
              "last_probe_score": 0,
              "score_history": [],   # скользящая база score (детект скачков)
              "last_notify": None,   # {ts, level, score} последнего TG
              "episode_start": None, # начало текущего эпизода (level ≥ 1)
              "active_episode": False,
              "quiet_runs": 0},      # тихих прогонов подряд (конец эпизода)
    "mode": "auto",               # auto | notify-only (после сбоев)
}
_MAX_HISTORY = 100
_SCORE_WINDOW = 12  # прогонов крона (по 5 мин) в скользящей базе score


def _log(level: str, msg: str) -> None:
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            import re
            clean = re.sub(r"\x1b\[[0-9;]*m", "", msg)
            f.write(f"[{ts}] [{level}] [dpi_response] {clean}\n")
    except Exception:
        pass


def state_load() -> dict:
    # deepcopy: DEFAULTS содержит мутируемые history/stats — поверхностная
    # копия "dict(DEFAULTS)" раздавала бы один и тот же список всем вызовам
    cfg = copy.deepcopy(DEFAULTS)
    try:
        raw = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            cfg.update({k: v for k, v in raw.items() if k in DEFAULTS})
            # stats/history — мердж по-глубже
            stats = dict(DEFAULTS["stats"])
            stats.update(raw.get("stats") or {})
            cfg["stats"] = stats
            cfg["history"] = list(raw.get("history") or [])[-_MAX_HISTORY:]
    except Exception:
        pass
    return cfg


def state_save(cfg: dict) -> None:
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(
            json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        STATE_FILE.chmod(0o600)
    except Exception as e:
        _log("WARN", f"state save failed: {e}")


def _history_append(cfg: dict, entry: dict) -> None:
    entry["ts"] = datetime.now().isoformat(timespec="seconds")
    cfg.setdefault("history", []).append(entry)
    cfg["history"] = cfg["history"][-_MAX_HISTORY:]


def _last_action_ts(history: list, action: str) -> Optional[str]:
    """ts последнего действия action в history (или None)."""
    for h in reversed(history or []):
        if isinstance(h, dict) and h.get("action") == action:
            return h.get("ts")
    return None


def _score_baseline(cfg: dict) -> float:
    """Средний score за последние _SCORE_WINDOW прогонов (база скачка)."""
    hist = (cfg.get("stats") or {}).get("score_history")
    if not isinstance(hist, list):
        return 0.0
    vals = [x for x in hist[-_SCORE_WINDOW:] if isinstance(x, (int, float))]
    return sum(vals) / len(vals) if vals else 0.0


# ══════════════════════════════════════════════════════════════════════════════
# 1. ВХОДЫ: сбор сигналов
# ══════════════════════════════════════════════════════════════════════════════
def collect_signals(cfg: dict) -> dict:
    """Собирает все сигналы за окно window_min.

    Возвращает {probe_score, mask_gate, dpi_gate, banned_now}:
      probe_score  — сумма весов DPI-зондов по IP за окно (error.log,
                     паттерны dpi_detector)
      mask_gate    — свежий вердикт mask_gate (PASS/SUSPECT/FAIL)
      dpi_gate     — свежий вердикт dpi_gate (tunnel/benign)
    """
    signals = {"probe_score": 0, "mask_gate": None, "dpi_gate": None,
               "banned_now": 0}
    window_start = time.time() - cfg["window_min"] * 60

    # 1) DPI-зонды из error.log (реиспользуем паттерны dpi_detector)
    try:
        from chimera.modules.dpi_detector import _DPI_PATTERNS
        if XRAY_ERROR_LOG.exists():
            cutoff = datetime.fromtimestamp(window_start)
            score = 0
            # читаем хвост лога (последние 2000 строк)
            lines = XRAY_ERROR_LOG.read_text(
                encoding="utf-8", errors="replace").splitlines()[-2000:]
            for line in lines:
                # грубая проверка времени строки (формат xray: 2026/10/28 21:00:00)
                m = line[:19]
                skip_ts = False
                try:
                    ts = datetime.strptime(m, "%Y/%m/%d %H:%M:%S")
                    if ts < cutoff:
                        skip_ts = True
                except ValueError:
                    skip_ts = False  # строка без даты — считаем свежей
                if skip_ts:
                    continue
                for pat, _desc, weight in _DPI_PATTERNS:
                    if pat.search(line):
                        score += weight
                        break
            signals["probe_score"] = score
    except Exception as e:
        _log("WARN", f"probe collection failed: {e}")

    # 2) Свежие баны dpi_detector (за окно)
    try:
        if DPI_DETECTOR_STATE.exists():
            det = json.loads(DPI_DETECTOR_STATE.read_text(encoding="utf-8"))
            last_run = det.get("last_run_ts") or det.get("last_run")
            if last_run:
                t = last_run if isinstance(last_run, (int, float)) else None
                if t and t >= window_start:
                    signals["banned_now"] = int(det.get("last_bans", 0))
    except Exception:
        pass

    # 3) mask_gate-вердикт (не старше 1 ч)
    try:
        mg = _latest_json_report(MASK_GATE_DIR, "mask_gate_", max_age=3600)
        if mg:
            signals["mask_gate"] = mg.get("verdict")
    except Exception:
        pass

    # 4) dpi_gate-вердикт (не старше 1 ч)
    try:
        dg = _latest_json_report(DPI_GATE_DIR, "dpi_gate_", max_age=3600)
        if dg:
            signals["dpi_gate"] = dg.get("overall")
    except Exception:
        pass

    return signals


def _latest_json_report(directory: Path, prefix: str,
                        max_age: int = 3600) -> Optional[dict]:
    d = Path(directory)
    if not d.is_dir():
        return None
    now = time.time()
    best = None
    for p in sorted(d.glob(f"{prefix}*.json")):
        try:
            if now - p.stat().st_mtime <= max_age:
                best = p
        except OSError:
            continue
    if best is None:
        return None
    try:
        return json.loads(best.read_text(encoding="utf-8"))
    except Exception:
        return None


def threat_level(cfg: dict, signals: dict) -> tuple:
    """0 — тишина, 1 — подозрение (фон зондирования), 2 — атака.

    Уровень 2: score ≥ probe_threshold_2 (порог атаки), скачок против
    скользящей базы (score ≥ notify_spike_ratio×базы) либо mask_gate
    FAIL. Фоновое зондирование (score выше минимального порога, но без
    скачка) — уровень 1: фиксируется в лог/history, не дёргает оператора.

    Возвращает (level, reasons[]).
    """
    reasons = []
    level = 0
    score = signals["probe_score"]
    if score >= cfg["probe_threshold"]:
        level = 1
        reasons.append(f"DPI-зонды: score {score} "
                       f"≥ порога {cfg['probe_threshold']}")
        t2 = int(cfg.get("probe_threshold_2", 300))
        if score >= t2:
            level = 2
            reasons.append(f"score {score} ≥ порога атаки ({t2})")
        else:
            base = _score_baseline(cfg)
            if base > 0:
                ratio = float(cfg.get("notify_spike_ratio", 4.0))
                floor = float(cfg.get("spike_baseline_floor", 40))
                if score >= ratio * max(base, floor):
                    level = 2
                    reasons.append(f"скачок: score {score} "
                                   f"≥ {ratio:g}× базы ({base:.0f})")
    if signals["mask_gate"] == "FAIL":
        level = max(level, 2)
        reasons.append("mask_gate: FAIL (трафик классифицируется как VPN)")
    elif signals["mask_gate"] == "SUSPECT":
        level = max(level, 1)
        reasons.append("mask_gate: SUSPECT")
    if signals["dpi_gate"] == "tunnel":
        level = max(level, 1)
        reasons.append("dpi_gate: UDP-маска палится (tunnel)")
    if signals["banned_now"] > 0:
        level = max(level, 1)
        reasons.append(f"dpi_detector забанил {signals['banned_now']} зондов")
    return level, reasons


# ══════════════════════════════════════════════════════════════════════════════
# 2. ДЕЙСТВИЯ
# ══════════════════════════════════════════════════════════════════════════════
def _notify_gate(cfg: dict, level: int) -> tuple:
    """Анти-спам: решает, слать ли TG-уведомление в этом прогоне.

    Слать, если:
      • episode_start — первое уведомление эпизода (после тишины);
      • escalate — уровень вырос относительно последнего уведомления;
      • reminder — уровень 2 держится дольше notify_cooldown_min
        (атака продолжается — оператору нужно напоминание).
    Тот же уровень в рамках cooldown — молчим (фон пишется в лог).

    Возвращает (send, why).
    """
    stats = cfg.get("stats") or {}
    last = stats.get("last_notify") or {}
    last_ts, last_lvl = last.get("ts"), int(last.get("level") or 0)
    if not last_ts:
        return True, "episode_start"
    try:
        dt = datetime.fromisoformat(str(last_ts))
    except ValueError:
        return True, "state_recovered"
    if level > last_lvl:
        return True, "escalate"
    if (level >= 2 and datetime.now() - dt >=
            timedelta(minutes=int(cfg.get("notify_cooldown_min", 60)))):
        return True, "reminder"
    return False, "cooldown"


def _tg_notify(message: str) -> bool:
    """TG-уведомление через ядро (не падает, если TG не настроен)."""
    try:
        import importlib
        core = importlib.import_module("chimera._core")
        fn = getattr(core, "_tg_notify_event", None)
        if fn:
            fn("dpi_response", message)
            return True
    except Exception:
        pass
    _log("WARN", f"TG-уведомление не отправлено: {message[:120]}")
    return False


def action_fuzz() -> dict:
    """Авто-запуск fragment_fuzzer (неинтерактивный режим, если возможен).

    Возвращает {ok, result|error}.
    """
    try:
        from chimera.modules import fragment_fuzzer
        # Неинтерактивный прогон: поднимает локальный клиент Xray и зондирует
        # сервер с разными параметрами фрагментации. Требует живой Xray.
        state = fragment_fuzzer._load_state()
        if not state:
            return {"ok": False, "error": "state.json недоступен"}
        result = fragment_fuzzer.run_fragment_fuzzer(state)
        if isinstance(result, dict):
            return {"ok": bool(result.get("ok", result.get("working"))),
                    "result": {k: result.get(k) for k in
                               ("ok", "working", "preset", "packets",
                                "length", "interval", "best")}}
        return {"ok": result is not None, "result": None}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def action_rotate(cfg: dict) -> dict:
    """Ротация REALITY-ключей с проверками окна/cooldown/лимита.

    Возвращает {ok, skipped|error|detail}.
    """
    now = datetime.now()
    stats = cfg.setdefault("stats", {})
    history = cfg.setdefault("history", [])

    # Ночное окно (плановая ротация — в минимальную нагрузку)
    if not (cfg["rotate_window_start"] <= now.hour < cfg["rotate_window_end"]):
        return {"ok": False, "skipped": "outside_window",
                "detail": f"вне окна {cfg['rotate_window_start']:02d}:00-"
                          f"{cfg['rotate_window_end']:02d}:00"}
    # Cooldown
    last_rot = None
    for h in reversed(history):
        if h.get("action") == "rotate":
            last_rot = h.get("ts")
            break
    if last_rot:
        try:
            dt = datetime.fromisoformat(last_rot)
            if datetime.now() - dt < timedelta(hours=cfg["rotate_cooldown_hours"]):
                return {"ok": False, "skipped": "cooldown",
                        "detail": f"последняя ротация {last_rot}"}
        except ValueError:
            pass
    # Лимит на сутки
    today = now.strftime("%Y-%m-%d")
    today_rotations = sum(
        1 for h in history
        if h.get("action") == "rotate" and str(h.get("ts", "")).startswith(today))
    if today_rotations >= cfg["rotate_max_per_day"]:
        return {"ok": False, "skipped": "daily_limit",
                "detail": f"уже {today_rotations} ротаций сегодня"}

    # Сама ротация
    try:
        from chimera.modules.credential_rotation import _rotate_reality_keys
        result = _rotate_reality_keys()
        if result:
            stats["rotations"] = int(stats.get("rotations", 0)) + 1
            return {"ok": True, "detail": "REALITY-ключи ротированы, "
                                          "ссылки перегенерированы"}
        return {"ok": False, "error": "ротация вернула пустой результат"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# 3. ГЛАВНЫЙ ЦИКЛ (cron каждые 5 мин)
# ══════════════════════════════════════════════════════════════════════════════
def dpi_response_run_once() -> dict:
    """Один прогон: collect → threat_level → actions → state.

    Вызывается cron'ом (main.py --dpi-response) и из меню.
    """
    cfg = state_load()
    if not cfg.get("enabled"):
        return {"ran": False, "reason": "disabled"}

    signals = collect_signals(cfg)
    stats = cfg["stats"]
    score = int(signals["probe_score"])
    stats["last_probe_score"] = score
    level, reasons = threat_level(cfg, signals)
    # скользящая база для детекта скачков — прошлые окна (без текущего)
    hist = stats.get("score_history")
    hist = list(hist) if isinstance(hist, list) else []
    hist.append(score)
    stats["score_history"] = hist[-_SCORE_WINDOW:]
    outcome = {"ran": True, "level": level, "reasons": reasons,
               "signals": signals, "actions": []}

    if level == 0:
        # Тишина: авто-возврат из notify-only в auto после 6 ч покоя
        if cfg.get("mode") == "notify-only":
            try:
                last_alert = next(h["ts"] for h in reversed(cfg["history"])
                                  if h.get("level", 0) > 0)
                if datetime.now() - datetime.fromisoformat(last_alert) > timedelta(hours=6):
                    cfg["mode"] = "auto"
                    _history_append(cfg, {"action": "auto-resume"})
            except (StopIteration, ValueError):
                pass
        # Конец эпизода: 2 тихих прогона подряд (анти-дребезг 1↔0) —
        # одно итоговое сообщение вместо потока «нормализовалось»
        stats["quiet_runs"] = int(stats.get("quiet_runs", 0)) + 1
        if stats.get("active_episode") and stats["quiet_runs"] >= 2:
            stats["active_episode"] = False
            if cfg.get("action_notify") and stats.get("last_notify"):
                dur = ""
                try:
                    if stats.get("episode_start"):
                        mins = ((datetime.now()
                                 - datetime.fromisoformat(str(stats["episode_start"])))
                                .total_seconds() // 60)
                        dur = f", эпизод ~{int(mins)} мин"
                except ValueError:
                    pass
                _tg_notify(f"✅ DPI-фон нормализовался (уровень 0/2, "
                           f"score={score}{dur})")
                stats["notifications"] = int(stats.get("notifications", 0)) + 1
                outcome["actions"].append("notify-ok")
            stats["last_notify"] = None
            stats["episode_start"] = None
        state_save(cfg)
        return outcome

    # ── уровень ≥ 1: эпизод активности (трекаем начало/конец) ──
    stats["quiet_runs"] = 0
    stats["active_episode"] = True
    if not stats.get("episode_start"):
        stats["episode_start"] = datetime.now().isoformat(timespec="seconds")

    # ── уведомление TG — событие, а не каждый прогон (анти-спам) ──
    if cfg.get("action_notify"):
        send, why = _notify_gate(cfg, level)
        if send:
            msg = (f"🛡️ DPI-активность (уровень {level}/2)\n"
                   + "\n".join(f"• {r}" for r in reasons)
                   + (f"\nprobe_score={signals['probe_score']}" ))
            _tg_notify(msg)
            stats["notifications"] = int(stats.get("notifications", 0)) + 1
            stats["last_notify"] = {
                "ts": datetime.now().isoformat(timespec="seconds"),
                "level": level, "score": score}
            outcome["actions"].append("notify")
        else:
            outcome["actions"].append(f"notify-skipped:{why}")
            _log("INFO", f"notify suppressed ({why}): "
                         f"level={level} score={score}")

    # ── уровень 1: фаззер (не чаще кулдауна — фон не должен молотить) ──
    fuzz_result = None
    if level >= 1 and cfg.get("action_fuzz") and cfg.get("mode") == "auto":
        last_fuzz = _last_action_ts(cfg["history"], "fuzz")
        fuzz_due = True
        if last_fuzz:
            try:
                if (datetime.now() - datetime.fromisoformat(str(last_fuzz)) <
                        timedelta(minutes=int(cfg.get("fuzz_cooldown_min", 60)))):
                    fuzz_due = False
            except ValueError:
                pass
        if fuzz_due:
            fuzz_result = action_fuzz()
            cfg["stats"]["fuzz_runs"] = int(cfg["stats"].get("fuzz_runs", 0)) + 1
            outcome["actions"].append("fuzz")
            _history_append(cfg, {"action": "fuzz", "level": level,
                                  "ok": fuzz_result.get("ok"),
                                  "detail": fuzz_result.get("detail") or fuzz_result.get("error") or ""})
        else:
            outcome["actions"].append("fuzz-skipped:cooldown")

    # ── уровень 2: ротация (если включена, фаззер не помог / не запускался) ──
    if (level >= 2 and cfg.get("action_rotate") and cfg.get("mode") == "auto"
            and not (fuzz_result and fuzz_result.get("ok"))):
        rot = action_rotate(cfg)
        outcome["actions"].append("rotate" if rot.get("ok") else f"rotate-skipped:{rot.get('skipped')}")
        if rot.get("ok"):
            _history_append(cfg, {"action": "rotate", "level": level,
                                  "detail": rot.get("detail", "")})
        elif rot.get("error"):
            # Ротация падала — включаем консервативный режим
            _history_append(cfg, {"action": "rotate-failed", "level": level,
                                  "detail": rot.get("error", "")})
            if cfg.get("mode") == "auto":
                cfg["mode"] = "notify-only"
                _tg_notify("⚠️ dpi_response: ротация не удалась — переключён "
                           "режим notify-only (оператор должен разобраться вручную)")

    if level >= 1:
        _history_append(cfg, {"action": "alert", "level": level,
                              "reasons": reasons[:3]})

    state_save(cfg)
    _log("INFO", f"run: level={level} actions={outcome['actions']} "
                 f"probe_score={signals['probe_score']}")
    return outcome


# ══════════════════════════════════════════════════════════════════════════════
# 4. CRON
# ══════════════════════════════════════════════════════════════════════════════
def _resolve_installer_path() -> str:
    """Путь main.py для cron-строки.

    sys.argv[0] валиден только при запуске скриптом (main.py --dpi-response).
    При `python -c "from ... import dpi_response; dpi_response.cron_install()"`
    argv[0] == '-c' — тогда main.py ищется рядом с пакетом (chimera/../main.py).
    """
    argv0 = sys.argv[0] if sys.argv else ""
    try:
        p = Path(argv0).resolve()
        if p.name == "main.py" and p.is_file():
            return str(p)
    except Exception:
        pass
    # fallback: main.py рядом с пакетом chimera/
    pkg_root = Path(__file__).resolve().parent.parent  # .../chimera
    for cand in (pkg_root / "main.py", pkg_root.parent / "main.py"):
        if cand.is_file():
            return str(cand)
    return "/opt/chimera/main.py"  # канонический путь установки


def cron_install() -> None:
    try:
        CRON_FILE.parent.mkdir(parents=True, exist_ok=True)
        installer = _resolve_installer_path()
        cron_line = (f"*/5 * * * * root /usr/bin/python3 {installer} "
                     f"--dpi-response >> /var/log/chimera.log 2>&1\n")
        CRON_FILE.write_text(
            "# chimera-dpi-response — авто-реакция на DPI-зондирование\n"
            "# Генерируется chimera/modules/dpi_response.py\n"
            "SHELL=/bin/bash\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
            f"{cron_line}",
            encoding="utf-8")
        CRON_FILE.chmod(0o644)
        _log("INFO", f"cron установлен (каждые 5 мин, installer={installer})")
    except Exception as e:
        _log("WARN", f"cron install failed: {e}")


def cron_remove() -> None:
    try:
        CRON_FILE.unlink(missing_ok=True)
        _log("INFO", "cron удалён")
    except Exception as e:
        _log("WARN", f"cron remove failed: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# 5. TUI-МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(RED='\033[31m', GREEN='\033[32m', YELLOW='\033[33m',
                    CYAN='\033[36m', BLUE='\033[34m', BOLD='\033[1m',
                    DIM='\033[2m', NC='\033[0m')
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BLUE', 'BOLD', 'DIM', 'NC')}


_C = _detect_colors()


def do_manage_dpi_response() -> None:
    """Интерактивное меню авто-реакции."""
    GREEN, CYAN, DIM, NC, BOLD, BLUE, YELLOW, RED = (
        _C['GREEN'], _C['CYAN'], _C['DIM'], _C['NC'],
        _C['BOLD'], _C['BLUE'], _C['YELLOW'], _C['RED'])
    while True:
        os.system("clear")
        cfg = state_load()
        cron_on = CRON_FILE.exists()
        stats = cfg.get("stats", {})
        print()
        print(f"  {BOLD}⚡  DPI RESPONSE — авто-реакция на DPI-атаку{NC}")
        print(f"  {DIM}Треугольник: dpi_detector (детект) → fragment_fuzzer{NC}")
        print(f"  {DIM}(подбор маскировки) → credential_rotation (ротация ключей).{NC}")
        print(f"  {DIM}Идея «rotate without disconnect» из AIVPN, rule-based.{NC}")
        print()
        mode_color = GREEN if cfg["mode"] == "auto" else YELLOW
        print(f"  Cron (5 мин):     {GREEN + 'ВКЛЮЧЁН' + NC if cron_on else DIM + 'ОТКЛЮЧЁН' + NC}")
        print(f"  Режим:            {mode_color}{cfg['mode']}{NC} "
              f"{DIM}(notify-only = авто-действия выключены до разбора){NC}")
        print(f"  Порог зондов:     {CYAN}{cfg['probe_threshold']}{NC} за {CYAN}{cfg['window_min']}{NC} мин "
              f"{DIM}(атака lvl2: ≥{cfg['probe_threshold_2']}, "
              f"спайк ×{cfg['notify_spike_ratio']:g} базы){NC}")
        print(f"  Уведомления TG:   {GREEN + 'да' + NC if cfg['action_notify'] else DIM + 'нет' + NC} "
              f"{DIM}(анти-спам: кулдаун {cfg['notify_cooldown_min']} мин, "
              f"эскалация/спайк — сразу){NC}")
        print(f"  Авто-фаззер:      {GREEN + 'да' + NC if cfg['action_fuzz'] else DIM + 'нет' + NC} "
              f"{DIM}(не чаще раза в {cfg['fuzz_cooldown_min']} мин){NC}")
        print(f"  Авто-ротация:     {GREEN + 'да' + NC if cfg['action_rotate'] else DIM + 'нет' + NC} "
              f"{DIM}(окно {cfg['rotate_window_start']:02d}-{cfg['rotate_window_end']:02d}, "
              f"cooldown {cfg['rotate_cooldown_hours']}ч, ≤{cfg['rotate_max_per_day']}/сутки){NC}")
        print(f"  Статистика:       {DIM}увед: {stats.get('notifications', 0)}, "
              f"фаззеров: {stats.get('fuzz_runs', 0)}, "
              f"ротаций: {stats.get('rotations', 0)}, "
              f"score: {stats.get('last_probe_score', 0)}{NC}")
        print()
        print(f"  {BOLD}1.{NC} {'Отключить' if cron_on else 'Включить'} cron")
        print(f"  {BOLD}2.{NC} Настроить пороги")
        print(f"  {BOLD}3.{NC} Переключить авто-фаззер ({'ВКЛ' if cfg['action_fuzz'] else 'ВЫКЛ'})")
        print(f"  {BOLD}4.{NC} Переключить авто-ротацию ({'ВКЛ' if cfg['action_rotate'] else 'ВЫКЛ'})")
        print(f"  {BOLD}5.{NC} Запустить прогон сейчас")
        print(f"  {BOLD}6.{NC} 📋 История (последние 15)")
        print(f"  {BOLD}0.{NC} ← Назад")
        print()
        try:
            ch = input(f"  {CYAN}Выбор:{NC} ").strip()
        except (KeyboardInterrupt, EOFError):
            break
        if ch == "1":
            if cron_on:
                cron_remove()
                cfg["enabled"] = False
            else:
                cron_install()
                cfg["enabled"] = True
            state_save(cfg)
            input(f"  {BLUE}Enter...{NC}")
        elif ch == "2":
            print()
            raw_t = input(f"  Порог зондов, уровень 1 [{cfg['probe_threshold']}]: ").strip()
            raw_t2 = input(f"  Порог атаки, уровень 2 [{cfg['probe_threshold_2']}]: ").strip()
            raw_w = input(f"  Окно, мин [{cfg['window_min']}]: ").strip()
            raw_cd = input(f"  Кулдаун TG-уведомлений, мин [{cfg['notify_cooldown_min']}]: ").strip()
            raw_fc = input(f"  Кулдаун авто-фаззера, мин [{cfg['fuzz_cooldown_min']}]: ").strip()
            if raw_t.isdigit() and int(raw_t) > 0:
                cfg["probe_threshold"] = int(raw_t)
            if raw_t2.isdigit() and int(raw_t2) > 0:
                cfg["probe_threshold_2"] = int(raw_t2)
            if raw_w.isdigit() and int(raw_w) > 0:
                cfg["window_min"] = int(raw_w)
            if raw_cd.isdigit() and int(raw_cd) >= 0:
                cfg["notify_cooldown_min"] = int(raw_cd)
            if raw_fc.isdigit() and int(raw_fc) >= 0:
                cfg["fuzz_cooldown_min"] = int(raw_fc)
            state_save(cfg)
            input(f"  {BLUE}Enter...{NC}")
        elif ch == "3":
            cfg["action_fuzz"] = not cfg["action_fuzz"]
            state_save(cfg)
            input(f"  {BLUE}Enter...{NC}")
        elif ch == "4":
            cfg["action_rotate"] = not cfg["action_rotate"]
            state_save(cfg)
            if cfg["action_rotate"]:
                print(f"\n  {YELLOW}⚠️ Ротация REALITY-ключей разрывает клиентов — "
                      f"они получат новые ссылки при следующем обновлении подписки.{NC}")
            input(f"  {BLUE}Enter...{NC}")
        elif ch == "5":
            print()
            outcome = dpi_response_run_once()
            print(f"  Уровень угрозы: {BOLD}{outcome['level']}/2{NC}")
            for r in outcome.get("reasons", []):
                print(f"    {DIM}•{NC} {r}")
            print(f"  Действия: {', '.join(outcome['actions']) or '—'}")
            input(f"  {BLUE}Enter...{NC}")
        elif ch == "6":
            print()
            for h in cfg.get("history", [])[-15:]:
                print(f"  {DIM}{h.get('ts', '?')}{NC} {h.get('action', '?'):<14} "
                      f"lvl={h.get('level', '-')} {h.get('detail', h.get('reasons', ''))}")
            if not cfg.get("history"):
                print(f"  {DIM}пусто{NC}")
            input(f"  {BLUE}Enter...{NC}")
        elif ch == "0":
            break


if __name__ == "__main__":
    dpi_response_run_once()
