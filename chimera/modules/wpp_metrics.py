#!/usr/bin/env python3
"""
chimera/modules/wpp_metrics.py
────────────────────────────────────────────────────────────────────────────────
Порт wpp_metrics.py из POLESNIESOVETI12/web-panel-proxy (MIT).
Independent VPS sampler — читает /proc/* + chimera traffic, хранит историю
в /var/lib/xray-installer/wpp_metrics.json для графиков dashboard.

Запуск:
  • systemd timer wpp-metrics.timer → wpp-metrics.service каждые 10 секунд
  • python3 -c "from chimera.modules.wpp_metrics import collect_once; collect_once()"

Архитектура (как в оригинале):
  • sample_metrics(traffic, previous) — сэмплит /proc/meminfo, /proc/stat,
    /proc/loadavg, /proc/uptime + диск; вычисляет CPU%, RAM%, uptime, load
  • make_sample вычисляет up_rate/down_rate (трафик delta / time delta)
  • history хранит до 8641 точек (24 часа при 10s интервале)
  • dashboard_data(hours) возвращает {latest, history, collector_error}

Отличия от оригинала:
  • State file: /var/lib/xray-installer/wpp_metrics.json (не /var/lib/tproxy-panel/metrics.json)
  • Traffic source: chimera._core._users_get_traffic_extended(email) вместо
    чтения /var/lib/tproxy-panel/traffic.json
  • Services: chimera's (xray, hysteria-server, awg-quick@awg0, telemt,
    openflux, nginx, wpp-web) вместо WPP's (web-panel-proxy-xray, etc.)
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Bootstrap корня проекта (должен быть на module-level, не внутри if)
_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ─── КОНСТАНТЫ ───────────────────────────────────────────────────────────────

STATE         = Path("/var/lib/xray-installer/wpp_metrics.json")
ERROR_FILE    = Path("/var/lib/xray-installer/wpp_metrics_error.json")
LOCK_FILE     = STATE.parent / "wpp_metrics.lock"
PROC           = Path("/proc")
HISTORY_LIMIT = 60481  # 7 days × 24 × 3600 / 10 = 60480 + 1 (extended from 24h to 7d for hourly pattern)
_MAIN_PY      = Path("/opt/chimera/main.py") if Path("/opt/chimera/main.py").exists() else _ROOT / "main.py"

# Chimera services (vs WPP's web-panel-proxy-xray.service и т.д.)
SERVICES = {
    "xray":     "xray.service",
    "panel":    "wpp-web.service",
    "nginx":    "nginx.service",
    "awg":      "awg-quick@awg0.service",
    "telemt":   "telemt.service",
    "openflux": "openflux.service",
}


# ─── ЛЕНИВЫЙ ДОСТУП К ЯДРУ ───────────────────────────────────────────────────

def _core_module():
    """Возвращает chimera._core (lazy)."""
    import importlib
    return importlib.import_module("chimera._core")


# ─── STATE I/O ───────────────────────────────────────────────────────────────

def read_state(path: Path | None = None) -> dict:
    """Читает metrics state file. Возвращает {} если нет/повреждён."""
    p = STATE if path is None else path
    try:
        value = json.loads(p.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def atomic_json(path: Path, value: dict) -> None:
    """Атомарная запись JSON через tmp + os.replace (как в оригинале)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(value, f, ensure_ascii=True, separators=(",", ":"))
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


# ─── /proc READING ───────────────────────────────────────────────────────────

def proc_text(name: str) -> str:
    """Читает /proc/<name>."""
    try:
        return (PROC / name).read_text(encoding="ascii").strip()
    except OSError:
        return ""


# ─── SERVICE SNAPSHOTS ───────────────────────────────────────────────────────

def _service_fields(unit: str) -> dict:
    """systemctl show для одного unit: state/memory/tasks/start_us."""
    try:
        r = subprocess.run(
            ["systemctl", "show", unit, "--no-pager",
             "-p", "ActiveState",
             "-p", "MemoryCurrent",
             "-p", "TasksCurrent",
             "-p", "ExecMainStartTimestampMonotonic"],
            capture_output=True, text=True, timeout=3,
            env={**os.environ, "LC_ALL": "C", "SYSTEMD_COLORS": "0"},
        )
        fields = dict(line.split("=", 1) for line in r.stdout.splitlines()
                      if "=" in line)
        def _num(key: str):
            v = fields.get(key, "")
            if v.isdigit() and int(v) < 2**63:
                return int(v)
            return None
        return {
            "state":   fields.get("ActiveState", "unknown"),
            "memory":  _num("MemoryCurrent"),
            "tasks":   _num("TasksCurrent"),
            "start_us": _num("ExecMainStartTimestampMonotonic"),
        }
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {"state": "unknown"}


def service_snapshot() -> dict:
    """Состояние всех сервисов."""
    out: dict[str, dict] = {}
    for key, unit in SERVICES.items():
        try:
            out[key] = _service_fields(unit)
        except (OSError, subprocess.TimeoutExpired, ValueError):
            out[key] = {"state": "unknown"}
    return out


# ─── TRAFFIC (chimera адаптация) ─────────────────────────────────────────────

def read_traffic() -> dict[str, dict]:
    """
    Возвращает {email: {up, down, updated_at, service_active, last_change}}
    по всем пользователям chimera. Делегирует в
    chimera._core._users_get_traffic_extended(email) (Xray Stats API).
    """
    out: dict[str, dict] = {}
    try:
        core = _core_module()
        # Список пользователей
        USERS_FILE = Path("/etc/xray/users.json")
        if not USERS_FILE.exists():
            return out
        users = json.loads(USERS_FILE.read_text())
        if not isinstance(users, list):
            users = users.get("users", []) if isinstance(users, dict) else []
        get_traffic = getattr(core, "_users_get_traffic_extended", None)
        if not get_traffic:
            return out
        now = int(time.time())
        for u in users:
            email = str(u.get("email") or "")
            if not email:
                continue
            try:
                t = get_traffic(email)
                if isinstance(t, (list, tuple)) and len(t) >= 2:
                    up, down = int(t[0] or 0), int(t[1] or 0)
                else:
                    up, down = 0, 0
                out[email] = {
                    "up":             up,
                    "down":           down,
                    "updated_at":     now,
                    "service_active": not u.get("disabled") and not u.get("blocked"),
                    "last_change":    now,
                }
            except Exception:
                out[email] = {
                    "up": 0, "down": 0, "updated_at": now,
                    "service_active": False, "last_change": now,
                }
    except Exception:
        pass
    return out


# ─── SAMPLE (одно измерение) ──────────────────────────────────────────────────

def make_sample(traffic: dict, previous: dict, now: int | None = None) -> dict:
    """
    Сэмплит CPU/RAM/disk/uptime/load + traffic rates. Возвращает dict как
    в оригинале (см. wpp_metrics.py:make_sample).
    """
    now = int(time.time()) if now is None else now

    # Memory
    mem: dict[str, int] = {}
    for line in proc_text("meminfo").splitlines():
        parts = line.split()
        if len(parts) > 1 and parts[1].isdigit():
            mem[parts[0].rstrip(":")] = int(parts[1]) * 1024  # kB → bytes

    # CPU
    cpu = proc_text("stat").splitlines()
    raw = [int(x) for x in cpu[0].split()[1:9]] if cpu and cpu[0].startswith("cpu ") else []
    total = sum(raw) if raw else 0
    idle = sum(raw[3:5]) if raw else 0  # idle + iowait

    # Boot ID
    boot = proc_text("sys/kernel/random/boot_id")

    # CPU %
    before = previous.get("cpu_ticks", [0, 0])
    delta = total - before[0]
    same_boot = bool(boot) and boot == previous.get("boot_id")
    if same_boot and delta > 0:
        cpu_percent = max(0, min(100, 100 * (1 - (idle - before[1]) / delta)))
    else:
        cpu_percent = None

    # Traffic
    up = sum(max(0, int(v.get("up", 0))) for v in traffic.values()
             if isinstance(v, dict))
    down = sum(max(0, int(v.get("down", 0))) for v in traffic.values()
               if isinstance(v, dict))
    dt = now - previous.get("time", now)

    # Traffic freshness
    observed = max((v.get("updated_at", 0) for v in traffic.values()
                    if isinstance(v, dict)), default=0)
    traffic_fresh = 0 <= now - observed <= 90 and observed > 0
    old_observed = previous.get("traffic_time", 0)
    traffic_dt = observed - old_observed
    rates_valid = (
        same_boot and traffic_fresh and old_observed > 0 and 0 < traffic_dt <= 120
        and 10 <= dt <= 120 and up >= previous.get("up", up) and down >= previous.get("down", down)
    )
    up_rate = (up - previous["up"]) / traffic_dt if rates_valid and "up" in previous else None
    down_rate = (down - previous["down"]) / traffic_dt if rates_valid and "down" in previous else None

    # Disk
    try:
        disk = shutil.disk_usage("/")
    except OSError:
        disk = None

    # Uptime
    try:
        uptime = float(proc_text("uptime").split()[0])
    except (ValueError, IndexError):
        uptime = None

    # Load avg
    try:
        load = [float(x) for x in proc_text("loadavg").split()[:3]]
    except ValueError:
        load = []

    return {
        "time":          now,
        "boot_id":       boot,
        "cpu_ticks":     [total, idle],
        "cpu":           cpu_percent,
        "cores":         os.cpu_count() or 1,
        "ram_total":     mem.get("MemTotal"),
        "ram_used":      max(0, mem["MemTotal"] - mem.get("MemAvailable", mem.get("MemFree", 0)))
                          if "MemTotal" in mem else None,
        "swap_total":    mem.get("SwapTotal"),
        "swap_used":     max(0, mem.get("SwapTotal", 0) - mem.get("SwapFree", 0))
                          if "SwapTotal" in mem else None,
        "disk_total":    disk.total if disk else None,
        "disk_used":     disk.used if disk else None,
        "uptime":        uptime,
        "load":          load,
        "up":            up,
        "down":          down,
        "traffic_time":  observed,
        "traffic_fresh": traffic_fresh,
        "up_rate":       up_rate,
        "down_rate":     down_rate,
        "services":      service_snapshot(),
    }


# ─── COLLECT ──────────────────────────────────────────────────────────────────

def sample_metrics(traffic: dict, force: bool = False) -> None:
    """Сэмплит и сохраняет метрики. Idempotent (rate-limited 25s без force)."""
    import fcntl
    STATE.parent.mkdir(parents=True, exist_ok=True)
    try:
        with (LOCK_FILE).open("a") as lock:
            os.chmod(lock.name, 0o600)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            data = read_state()
            now = int(time.time())
            if not force and 0 <= now - data.get("latest", {}).get("time", 0) < 25:
                return
            previous = data.get("latest", {})
            point = make_sample(traffic, previous, now)
            # First sample: re-read CPU after 0.15s для real delta
            if point.get("cpu") is None and point.get("cpu_ticks", [0])[0] > 0:
                ticks = point["cpu_ticks"]
                time.sleep(0.15)
                raw = proc_text("stat").splitlines()
                values = [int(x) for x in raw[0].split()[1:9]] if raw and raw[0].startswith("cpu ") else []
                delta = sum(values) - ticks[0]
                if delta > 0:
                    point["cpu"] = max(0, min(100, 100 * (1 - (sum(values[3:5]) - ticks[1]) / delta)))
            # Clean old history (24 hours)
            history = [h for h in data.get("history", [])
                       if now - 86400 <= h.get("time", 0) < now]
            history.append({k: point[k] for k in ("time", "up_rate", "down_rate", "cpu")})
            atomic_json(STATE, {"latest": point, "history": history[-HISTORY_LIMIT:]})
    except (OSError, PermissionError) as exc:
        # Логируем в stderr для journalctl, но не падаем — systemd timer
        # попробует снова через 10 секунд.
        print(f"[WPP-METRICS] sample_metrics failed: {type(exc).__name__}: {exc}",
              file=sys.stderr, flush=True)


def collect_once() -> None:
    """Entry point для systemd timer — раз в 10 секунд."""
    try:
        sample_metrics(read_traffic(), force=True)
        value = read_state().get("latest", {})
        if not value.get("ram_total") or not value.get("cpu_ticks", [0])[0]:
            raise RuntimeError("Required Linux /proc metrics are unavailable")
        if ERROR_FILE.exists():
            ERROR_FILE.unlink()
    except Exception as exc:
        # Записываем error info (без секретов)
        atomic_json(ERROR_FILE, {"time": int(time.time()), "kind": type(exc).__name__})
        raise


# ─── DASHBOARD DATA ───────────────────────────────────────────────────────────

# Try to import zoneinfo (Python 3.9+) for proper TZ-aware bucketing.
# Falls back to time.localtime (UTC on most servers) if unavailable.
try:
    from zoneinfo import ZoneInfo
    _HAS_ZONEINFO = True
except ImportError:
    _HAS_ZONEINFO = False
    ZoneInfo = None  # type: ignore


def _tzinfo(tz_name: str):
    """Return a zoneinfo.ZoneInfo for tz_name, or None on failure."""
    if not _HAS_ZONEINFO or not tz_name:
        return None
    try:
        return ZoneInfo(tz_name)
    except Exception:
        return None


def _hour_local(ts: int, tzinfo) -> tuple[int, str, int]:
    """Return (hour, date_key YYYY-MM-DD, day_of_week 0=Mon..6=Sun) for ts in given tz.

    If tzinfo is None, falls back to time.localtime (server tz, usually UTC).
    """
    if tzinfo is None:
        lt = time.localtime(ts)
        return (lt.tm_hour,
                "%04d-%02d-%02d" % (lt.tm_year, lt.tm_mon, lt.tm_mday),
                lt.tm_wday)
    try:
        from datetime import datetime
        dt = datetime.fromtimestamp(ts, tz=tzinfo)
        return (dt.hour,
                "%04d-%02d-%02d" % (dt.year, dt.month, dt.day),
                dt.weekday())  # Monday=0..Sunday=6 (same as tm_wday)
    except Exception:
        lt = time.localtime(ts)
        return (lt.tm_hour,
                "%04d-%02d-%02d" % (lt.tm_year, lt.tm_mon, lt.tm_mday),
                lt.tm_wday)


def dashboard_data(hours: int = 1, tz: str = "Europe/Moscow") -> dict:
    """Возвращает {latest, history, collector_error, hourly_pattern, hourly_heatmap} для dashboard_body."""
    data = read_state()
    cutoff = int(time.time()) - hours * 3600
    return {
        "latest":          data.get("latest", {}),
        "history":         [p for p in data.get("history", [])
                            if p.get("time", 0) >= cutoff],
        "collector_error": read_state(ERROR_FILE),
        "hourly_pattern":  hourly_pattern(days=7, tz=tz),
        "hourly_heatmap":  hourly_heatmap(days=7, tz=tz),
    }


def hourly_pattern(days: int = 7, tz: str = "Europe/Moscow") -> dict:
    """Aggregate traffic history by hour-of-day (0..23) over last `days` days.

    For each hour-of-day bucket, sums up_rate × 10s + down_rate × 10s for all
    samples whose localtime (in given tz) hour matches the bucket, then divides
    by the number of distinct calendar days observed in that bucket — giving
    average bytes per hour-of-day, smoothing out one-off spikes.

    Args:
      days: how many days back to look (default 7).
      tz: IANA timezone name (e.g. 'Europe/Moscow', 'UTC'). Samples are
         bucketed by local hour in this tz, so '19:00' on the chart means
         19:00 in user's wall clock, not UTC.

    Returns:
      {
        "buckets": [{"hour": 0, "up": 1234, "down": 5678, "days": 7, "avg_total": 6912}, ...],
        "days_observed": 7,
        "max_avg_total": 12345,
        "tz": "Europe/Moscow"
      }
    """
    data = read_state()
    history = data.get("history", [])
    empty = {"buckets": [{"hour": h, "up": 0, "down": 0, "days": 0, "avg_total": 0}
                          for h in range(24)],
             "days_observed": 0, "max_avg_total": 0, "tz": tz}
    if not history:
        return empty
    cutoff = int(time.time()) - days * 86400
    SAMPLE_SEC = 10  # matches wpp-metrics.timer interval
    tzinfo = _tzinfo(tz)
    # bucket[hour] = {up, down, days:set(YYYY-MM-DD)}
    buckets = {h: {"up": 0, "down": 0, "days": set()} for h in range(24)}
    for sample in history:
        ts = sample.get("time", 0)
        if ts < cutoff:
            continue
        hour, date_key, _ = _hour_local(ts, tzinfo)
        if not (0 <= hour <= 23):
            continue
        up_bytes = max(0, float(sample.get("up_rate", 0) or 0)) * SAMPLE_SEC
        down_bytes = max(0, float(sample.get("down_rate", 0) or 0)) * SAMPLE_SEC
        buckets[hour]["up"] += up_bytes
        buckets[hour]["down"] += down_bytes
        buckets[hour]["days"].add(date_key)
    out_buckets = []
    max_avg = 0
    for h in range(24):
        b = buckets[h]
        n_days = len(b["days"])
        avg_up = int(b["up"] / n_days) if n_days else 0
        avg_down = int(b["down"] / n_days) if n_days else 0
        avg_total = avg_up + avg_down
        if avg_total > max_avg:
            max_avg = avg_total
        out_buckets.append({
            "hour": h,
            "up": avg_up,
            "down": avg_down,
            "days": n_days,
            "avg_total": avg_total,
        })
    all_days = set()
    for b in buckets.values():
        all_days |= b["days"]
    return {
        "buckets": out_buckets,
        "days_observed": len(all_days),
        "max_avg_total": max_avg,
        "tz": tz,
    }


# Russian day-of-week short names (tm_wday: 0=Mon..6=Sun)
_DOW_RU = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"]


def hourly_heatmap(days: int = 7, tz: str = "Europe/Moscow") -> dict:
    """Build a 7×24 heatmap of total traffic per (day-of-week, hour-of-day).

    For each (dow, hour) cell, sums up_rate × 10s + down_rate × 10s for all
    samples matching that combination in given tz. Returns 7 rows (Mon..Sun)
    × 24 cells (00..23). Used for the calendar-style heatmap like GitHub
    contributions — helps spot weekly patterns (e.g. weekend evenings).

    Args:
      days: how many days back to look (default 7).
      tz: IANA timezone name.

    Returns:
      {
        "rows": [{"dow": 0, "name": "Пн", "cells": [{"hour":0,"up":X,"down":Y,"total":Z}, ...]}, ...],
        "max_total": 123456,
        "days_observed": 7,
        "tz": "Europe/Moscow"
      }
    """
    data = read_state()
    history = data.get("history", [])
    empty_rows = [{"dow": d, "name": _DOW_RU[d],
                   "cells": [{"hour": h, "up": 0, "down": 0, "total": 0}
                             for h in range(24)]}
                  for d in range(7)]
    if not history:
        return {"rows": empty_rows, "max_total": 0, "days_observed": 0, "tz": tz}
    cutoff = int(time.time()) - days * 86400
    SAMPLE_SEC = 10
    tzinfo = _tzinfo(tz)
    # cells[dow][hour] = {up, down, days:set()}
    cells = [[{"up": 0, "down": 0, "days": set()} for _ in range(24)] for _ in range(7)]
    for sample in history:
        ts = sample.get("time", 0)
        if ts < cutoff:
            continue
        hour, date_key, dow = _hour_local(ts, tzinfo)
        if not (0 <= hour <= 23) or not (0 <= dow <= 6):
            continue
        up_bytes = max(0, float(sample.get("up_rate", 0) or 0)) * SAMPLE_SEC
        down_bytes = max(0, float(sample.get("down_rate", 0) or 0)) * SAMPLE_SEC
        cells[dow][hour]["up"] += up_bytes
        cells[dow][hour]["down"] += down_bytes
        cells[dow][hour]["days"].add(date_key)
    rows = []
    max_total = 0
    all_days = set()
    for dow in range(7):
        row_cells = []
        for hour in range(24):
            c = cells[dow][hour]
            n_days = len(c["days"])
            # average per day for that (dow, hour) combination
            up_avg = int(c["up"] / n_days) if n_days else 0
            down_avg = int(c["down"] / n_days) if n_days else 0
            total = up_avg + down_avg
            if total > max_total:
                max_total = total
            all_days |= c["days"]
            row_cells.append({"hour": hour, "up": up_avg, "down": down_avg, "total": total})
        rows.append({"dow": dow, "name": _DOW_RU[dow], "cells": row_cells})
    return {
        "rows": rows,
        "max_total": max_total,
        "days_observed": len(all_days),
        "tz": tz,
    }


# ─── SYSTEMD TIMER INSTALL/REMOVE ───────────────────────────────────────────

_SERVICE_FILE = Path("/etc/systemd/system/wpp-metrics.service")
_TIMER_FILE   = Path("/etc/systemd/system/wpp-metrics.timer")
# _MAIN_PY уже определён на module-level (см. выше)


def install_timer() -> tuple[bool, str]:
    """Устанавливает systemd service + timer (раз в 10 секунд)."""
    if not _MAIN_PY.exists():
        return False, f"main.py не найден: {_MAIN_PY}"
    service_unit = f"""[Unit]
Description=WPP Metrics Collector (10s sampler for dashboard)
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -c "from chimera.modules.wpp_metrics import collect_once; collect_once()"
WorkingDirectory={_MAIN_PY.parent}
Environment=PYTHONPATH={_MAIN_PY.parent}
User=root
"""
    timer_unit = """[Unit]
Description=WPP Metrics Collector Timer (every 10s)

[Timer]
OnBootSec=15
OnUnitInactiveSec=10
AccuracySec=1

[Install]
WantedBy=timers.target
"""
    try:
        _SERVICE_FILE.write_text(service_unit)
        _SERVICE_FILE.chmod(0o644)
        _TIMER_FILE.write_text(timer_unit)
        _TIMER_FILE.chmod(0o644)
        subprocess.run(["systemctl", "daemon-reload"], timeout=15, check=False)
        subprocess.run(["systemctl", "enable", "--now", "wpp-metrics.timer"],
                       timeout=15, check=False)
        return True, "wpp-metrics.timer установлен (10s интервал)"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def remove_timer() -> tuple[bool, str]:
    """Останавливает и удаляет timer."""
    try:
        subprocess.run(["systemctl", "disable", "--now", "wpp-metrics.timer"],
                       timeout=15, check=False)
        _TIMER_FILE.unlink(missing_ok=True)
        _SERVICE_FILE.unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"], timeout=15, check=False)
        return True, "wpp-metrics.timer удалён"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: wpp_metrics.py [collect|install|remove|status|data]",
              file=sys.stderr)
        return 1
    cmd = sys.argv[1]
    if cmd == "collect":
        collect_once()
        print("collected")
        return 0
    elif cmd == "install":
        ok, msg = install_timer()
        print(("OK: " if ok else "FAIL: ") + msg)
        return 0 if ok else 1
    elif cmd == "remove":
        ok, msg = remove_timer()
        print(("OK: " if ok else "FAIL: ") + msg)
        return 0 if ok else 1
    elif cmd == "status":
        r = subprocess.run(["systemctl", "is-active", "wpp-metrics.timer"],
                           capture_output=True, text=True, timeout=5)
        print("timer:", r.stdout.strip())
        return 0
    elif cmd == "data":
        print(json.dumps(dashboard_data(1), indent=2, ensure_ascii=False, default=str))
        return 0
    else:
        print(f"Unknown: {cmd}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
