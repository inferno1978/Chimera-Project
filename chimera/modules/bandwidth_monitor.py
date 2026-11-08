#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chimera/modules/bandwidth_monitor.py
───────────────────────────────────────────────────────────────────────────────
Bandwidth монитор — периодический замер пропускной способности канала ноды
с алертами в Telegram при деградации и дневным отчётом.

Зачем: хостеры могут silently урезать канал (кейс 91.x: договор позволяет
50 Mbps вместо 1 Gbps). Без мониторинга это обнаруживается только когда
клиенты начинают жаловаться. Монитор ловит обрез за 30 минут.

Гибридный подход (не тыркать каждые N часов):
  1. Лёгкая проба (раз в 30 мин): 6 параллельных потоков суммарно ~60 MB
     + ping. Если скорость < порога → мгновенный alarm в TG.
  2. Полный замер (раз в 6 часов): 8 параллельных потоков суммарно
     ~760 MB (нижняя оценка порта) + опционально iperf3 / Ookla CLI →
     точный замер + отчёт в TG.
  3. Дневной отчёт (раз в день): сводка avg/min/max/latency + классификация.
  4. Алерт при деградации: если скорость упала > 50% от среднего за час
     → мгновенный alarm + полный замер.

Почему параллельные потоки (кейс №16, 08.11.2026): NL-выход с портом
16.5 Gbps (Ookla CLI: DL 16526 / UL 19675 Mbps) при ОДНОПОТОКОВОЙ пробе
95 MB стабильно показывал 578-681 Mbps — это потолок одиночного TCP-потока
и фазы slow start, а не порта: 100 MB на 16 Gbps = 0.05 c «по проводу»,
весь замер внутри разгона. Параллельные потоки дают честную нижнюю оценку
(≥ X Mbps); настоящее число — только Ookla (~16 соединений, десятки GB
трафика за прогон, поэтому opt-in через use_ookla).

Пороги (level_mode=absolute, по умолчанию — политика флота 08.11.2026):
  normal:    ≥ 1000 Mbps  (гигабит и выше — зелёный)
  degraded:  100-1000 Mbps (жёлтый: статус в отчётах, без мгновенного TG-пуша)
  critical:  < 100 Mbps  (красный: хостер обрезал канал → TG-алерт)
Мгновенные TG-алерты — только для critical; жёлтый пушится лишь при
alert_degraded=true (opt-in). Кейс DE 08.11.2026: auto-режим на 5G-порту
дал ⚠️ при 1564 Mbps (< 50% базлайна) — ложный сработ; политика владельца:
«уведы, только если ниже 100 Mbps».
Пороги (level_mode=auto, opt-in): относительно МЕДИАНЫ сэмплов за 24ч —
normal ≥ 50% базлайна, degraded ≥ 20%, ниже — critical. Ловит обрез
>1G-портов мгновенным алертом; жёлтая зона absolute (100-1000) покрывает
тот же кейс №16 видимость в отчётах: обрез 16.5G → 1G = 🟡 в отчёте.

Файлы:
  /var/lib/xray-installer/bandwidth-monitor.json     — конфиг
  /var/lib/xray-installer/bandwidth-monitor/         — данные
      samples/YYYY-MM-DD.jsonl                        — сэмплы (1 строка/тик)
      reports/YYYY-MM-DD.txt                          — копии отчётов
      tg-state.json                                   — стрики/кулдауны алертов
  /etc/cron.d/bandwidth-monitor                      — cron
  /usr/local/bin/bandwidth-sample.sh                 — wrapper пробы
  /usr/local/bin/bandwidth-report.sh                 — wrapper отчёта
  /var/log/bandwidth-monitor.log                     — лог

Публичный API:
    sample_once()                    → dict   — одна проба (cron */30 мин)
    send_periodic_report()           → str    — отчёт за период (cron */6ч)
    send_daily_report()              → str    — дневной отчёт (cron H:M)
    install_bandwidth_monitor(cfg)   → (bool, str)  — cron + wrappers
    uninstall_bandwidth_monitor()    → (bool, str)
    is_monitor_installed()           → bool
    do_bandwidth_monitor_menu()      → None   — TUI-меню
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime
from http.client import HTTPSConnection
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

# ══════════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════

BASE_DIR       = Path("/var/lib/xray-installer/bandwidth-monitor")
CONFIG_FILE    = Path("/var/lib/xray-installer/bandwidth-monitor.json")
SAMPLES_DIR    = BASE_DIR / "samples"
REPORTS_DIR    = BASE_DIR / "reports"
TG_STATE_FILE  = BASE_DIR / "tg-state.json"
LOG_FILE       = Path("/var/log/bandwidth-monitor.log")
CRON_FILE      = Path("/etc/cron.d/bandwidth-monitor")
SAMPLE_SCRIPT  = Path("/usr/local/bin/bandwidth-sample.sh")
REPORT_SCRIPT  = Path("/usr/local/bin/bandwidth-report.sh")
DAILY_SCRIPT   = Path("/usr/local/bin/bandwidth-daily.sh")
TG_CONFIG      = Path("/var/lib/xray-installer/telegram.json")
TG_BOT_CFG     = Path("/var/lib/xray-installer/tg_bot.json")

# Частоты
DEFAULT_SAMPLE_INTERVAL_MIN  = 30    # лёгкая проба каждые 30 мин
DEFAULT_REPORT_INTERVAL_HOURS = 6    # полный отчёт каждые 6 часов
DEFAULT_DAILY_HOUR           = 23    # дневной отчёт
DEFAULT_DAILY_MINUTE         = 50

# Таймауты
SMALL_DOWNLOAD_BYTES  = 10_000_000   # 10 MB для лёгкой пробы
BIG_DOWNLOAD_BYTES    = 95_000_000   # 95 MB — НИЖЕ потолка Cloudflare __down:
                                     # при 100_000_000 endpoint отвечает HTTP 403
                                     # с телом 1 байт (живой замер, окт.2026, кейс №15)
SMALL_DOWNLOAD_TIMEOUT = 30          # сек
BIG_DOWNLOAD_TIMEOUT   = 60          # сек
PING_COUNT             = 5
PING_TIMEOUT           = 3

# TG
TG_TIMEOUT       = 10
TG_RETRIES       = 3
TG_RETRY_PAUSE   = 2
TG_CHUNK_LIMIT   = 3900

# Пороги (Mbps)
DEFAULT_THRESHOLDS = {
    "normal_mbps":     1000.0,  # ≥ гигабита — зелёный (политика флота 08.11.2026)
    "degraded_mbps":    100.0,  # 100-1000 — жёлтый (статус в отчётах, без пуша)
    # < degraded_mbps — critical (красный: хостер обрезал → TG-алерт)
    "degradation_pct":  50.0,   # падение > 50% от среднего за час → alarm
    "alert_cooldown_min": 180,  # анти-спам: 3 часа между алертами одного уровня
    "alert_consecutive":  2,    # 2 сэмпла подряд < degraded → алерт
}

# Источники для download-теста (надёжные CDN)
DOWNLOAD_SOURCES = [
    # (url, name) — первый рабочий выигрывает
    ("https://cachefly.cachefly.net/100mb.test", "cachefly"),
    ("https://speed.cloudflare.com/__down?bytes={size}", "cloudflare"),
    ("https://dl.testdebit.info/{size_mb}M", "testdebit"),
]

# Цели для ping-теста
PING_TARGETS = ["1.1.1.1", "ya.ru", "8.8.8.8"]

# Параллельные потоки (кейс №16: однопотоковая проба мерила потолок
# одиночного TCP-потока, а не порт — см. докстринг модуля)
DEFAULT_PARALLEL_STREAMS_LIGHT = 6     # лёгкая проба: 6 × 10 MB
DEFAULT_PARALLEL_STREAMS_BIG   = 8     # полный замер: 8 × 95 MB
PROBE_MB_LIGHT = 60                    # суммарный бюджет лёгкой пробы
PROBE_MB_BIG   = 760                   # суммарный бюджет полного замера
STREAM_ACTIVE_CAP_LIGHT = 15           # сек на поток (лёгкая)
STREAM_ACTIVE_CAP_BIG   = 30           # сек на поток (полный)
RAMP_DISCARD_SEC = 0.5                 # разгон TCP не входит в среднюю
PEAK_WINDOW_SEC  = 1.0                 # окно расчёта пика
READ_BLOCK_BYTES = 65536

# Базлайн для level_mode=auto
BASELINE_WINDOW_HOURS = 24
BASELINE_MIN_SAMPLES  = 5

# Порядок источников для параллельного замера (отличается от легаси:
# cloudflare первым — точный {size} без привязки к фиксированным файлам)
PARALLEL_DOWNLOAD_SOURCES = [
    ("https://speed.cloudflare.com/__down?bytes={size}", "cloudflare"),
    ("https://cachefly.cachefly.net/100mb.test", "cachefly"),
    ("https://dl.testdebit.info/{size_mb}M", "testdebit"),
]

DEFAULT_CONFIG: dict = {
    "enabled": True,
    "sample_interval_min": DEFAULT_SAMPLE_INTERVAL_MIN,
    "report_interval_hours": DEFAULT_REPORT_INTERVAL_HOURS,
    "daily_hour": DEFAULT_DAILY_HOUR,
    "daily_minute": DEFAULT_DAILY_MINUTE,
    "node_label": "",                # имя ноды в отчётах; пусто = hostname
    "node_ip": "",                   # публичный IP; пусто = автодетект
    "alerts_enabled": True,
    "daily_report_enabled": True,
    "periodic_report_enabled": True,
    "thresholds": dict(DEFAULT_THRESHOLDS),
    "retention_days": 30,
    "tg_retries": TG_RETRIES,
    "use_iperf3": False,             # iperf3 для полного замера (если доступен)
    "iperf3_server": "ping.online.net",
    "iperf3_port": 5200,
    "parallel_streams": 0,           # 0 = авто (лёгкая 6 / полный 8); 1 = легаси-однопоток
    "probe_mb_light": PROBE_MB_LIGHT,
    "probe_mb_big": PROBE_MB_BIG,
    "use_ookla": False,              # полный замер через Ookla CLI (десятки GB трафика за прогон!)
    "level_mode": "absolute",        # absolute = пороги normal/degraded (политика флота);
                                     # auto = базлайн-медиана 24ч (opt-in)
    "baseline_normal_ratio": 0.5,    # auto: normal ≥ 50% базлайна
    "baseline_degraded_ratio": 0.2,  # auto: degraded ≥ 20% базлайна
    "alert_degraded": False,         # мгновенный TG-пуш для жёлтого (100-1000);
                                     # False = пуш только для critical < 100 Mbps
}


# ══════════════════════════════════════════════════════════════════════════════
#  ХЕЛПЕРЫ
# ══════════════════════════════════════════════════════════════════════════════

def _log(msg: str) -> None:
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except Exception:
        pass


def _run(cmd, capture: bool = False, timeout: int = 60):
    try:
        return subprocess.run(cmd, capture_output=capture, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        class _T:
            returncode = 124
            stdout = ""
            stderr = "timeout"
        return _T()
    except Exception:
        class _E:
            returncode = 1
            stdout = ""
            stderr = "exception"
        return _E()


def _find_installer_path() -> str:
    """Найти путь к chimera (для cron wrapper'а)."""
    try:
        import importlib.util
        spec = importlib.util.find_spec("chimera")
        if spec and spec.submodule_search_locations:
            return str(Path(list(spec.submodule_search_locations)[0]).parent)
    except Exception:
        pass
    for p in ("/opt/chimera", "/usr/local/lib/chimera"):
        if Path(p).is_dir():
            return p
    return "/opt/chimera"


def _find_python() -> str:
    return "/usr/bin/python3"


def _node_hostname() -> str:
    r = _run(["hostname"], capture=True, timeout=5)
    return (r.stdout or "").strip() or "unknown"


def _node_public_ip() -> str:
    r = _run(["curl", "-sS", "--max-time", "5", "-4", "ifconfig.me"],
             capture=True, timeout=10)
    ip = (r.stdout or "").strip()
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        return ip
    return "unknown"


def _node_label_fallback() -> str:
    """Метка ноды для отчётов: label из конфига или hostname."""
    cfg = load_config()
    label = (cfg.get("node_label") or "").strip()
    if label:
        return label
    return _node_hostname()


# ══════════════════════════════════════════════════════════════════════════════
#  КОНФИГ
# ══════════════════════════════════════════════════════════════════════════════

def load_config() -> dict:
    import copy
    if not CONFIG_FILE.exists():
        return copy.deepcopy(DEFAULT_CONFIG)
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg.update(data)
        # merge thresholds (deep, чтобы не мутировать DEFAULT_THRESHOLDS)
        th = copy.deepcopy(DEFAULT_THRESHOLDS)
        th.update(data.get("thresholds") or {})
        cfg["thresholds"] = th
        return cfg
    except Exception:
        return copy.deepcopy(DEFAULT_CONFIG)


def save_config(cfg: dict) -> None:
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False),
                           encoding="utf-8")


# ══════════════════════════════════════════════════════════════════════════════
#  ИЗМЕРЕНИЯ
# ══════════════════════════════════════════════════════════════════════════════

def _ping_latency(target: str, count: int = PING_COUNT,
                  timeout: int = PING_TIMEOUT) -> Optional[float]:
    """Средний RTT до target в мс, или None при ошибке."""
    r = _run(["ping", "-c", str(count), "-W", str(timeout), target],
             capture=True, timeout=timeout * count + 5)
    if r.returncode != 0:
        return None
    # --- rtt min/avg/max/mdev = 1.234/2.345/3.456/0.123 ms ---
    m = re.search(r"rtt min/avg/max/mdev\s*=\s*[\d.]+/([\d.]+)/",
                  r.stdout or "")
    if m:
        return float(m.group(1))
    return None


def _curl_download(url: str, timeout: int = 30) -> Optional[float]:
    """Download через curl, возвращает скорость в bytes/sec или None.

    Скорость <10 КБ/с считается отсутствием загрузки: 403/404 от CDN с
    телом в 1 байт даёт rc=0 и «скорость» ~30 Б/с — без порога это
    записалось бы как ложный успешный замер (кейс №15).
    """
    r = _run(["curl", "-sS", "-o", "/dev/null", "-w", "%{speed_download}",
              "--max-time", str(timeout), url],
             capture=True, timeout=timeout + 5)
    if r.returncode != 0:
        return None
    try:
        speed = float((r.stdout or "").strip())
    except (ValueError, TypeError):
        return None
    return speed if speed > 10_000 else None


def _try_download(sources: list, size_bytes: int, timeout: int) -> tuple:
    """Перебираем sources, возвращаем (speed_bytes_per_sec, source_name)."""
    for url_tpl, name in sources:
        url = url_tpl.format(size=size_bytes, size_mb=size_bytes // 1_000_000)
        speed = _curl_download(url, timeout=timeout)
        if speed and speed > 0:
            return speed, name
    return 0.0, "none"


def _iperf3_test(server: str, port: int = 5200, duration: int = 10) -> Optional[float]:
    """iperf3 download test, возвращает Mbps или None."""
    if not shutil.which("iperf3"):
        return None
    r = _run(["iperf3", "-c", server, "-p", str(port), "-t", str(duration),
              "-P", "4", "-R", "-J"], capture=True, timeout=duration + 15)
    if r.returncode != 0:
        return None
    try:
        d = json.loads(r.stdout or "{}")
        bps = d.get("end", {}).get("sum_received", {}).get("bits_per_second", 0)
        return bps / 1e6 if bps else None
    except Exception:
        return None


def _steady_and_peak(events: list, t0: float, duration: float,
                     ramp_discard_sec: float = RAMP_DISCARD_SEC,
                     peak_window_sec: float = PEAK_WINDOW_SEC) -> tuple:
    """Средняя скорость (после отброса разгона TCP) и пик в скользящем окне.

    events — отсортированный [(t, bytes_cum)]; t0 — старт замера; duration —
    полная длительность в сек. Возвращает (steady_bps, peak_bps).
    """
    total_bytes = events[-1][1]
    end_t = events[-1][0]
    ramp_t = t0 + ramp_discard_sec
    if end_t - ramp_t > 0.2:
        cum_at_ramp = 0
        for ts, cum in events:
            if ts <= ramp_t:
                cum_at_ramp = cum
            else:
                break
        steady_bps = (total_bytes - cum_at_ramp) / (end_t - ramp_t)
    else:
        steady_bps = (total_bytes / duration) if duration > 0 else 0.0

    peak_bps = 0.0
    j = 0
    for i in range(len(events)):
        while events[j][0] < events[i][0] - peak_window_sec:
            j += 1
        base = events[j - 1][1] if j > 0 else 0
        window_bps = (events[i][1] - base) / peak_window_sec
        if window_bps > peak_bps:
            peak_bps = window_bps
    return steady_bps, peak_bps


def _parallel_download_one(url: str, streams: int, budget_bytes: int,
                           active_cap: int) -> Optional[dict]:
    """Параллельная загрузка N потоками с одного URL.

    Каждый поток качает не больше budget_bytes//streams (читаем до бюджета
    или таймкапа и закрываем соединение — хвостовое добивание не качаем).
    Возвращает {speed_bps, peak_bps, total_bytes, duration, streams} или
    None, если ни один поток не получил ни байта.
    """
    per_stream = max(1_000_000, budget_bytes // max(1, streams))
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path + (("?" + parsed.query) if parsed.query else "")
    if not host:
        return None

    events = []          # [(t, bytes_cum_total)]
    lock = threading.Lock()
    total = [0]

    def _worker():
        conn = None
        got = 0
        t_start = time.time()
        try:
            conn = HTTPSConnection(host, timeout=active_cap + 10)
            conn.request("GET", path, headers={"Connection": "close"})
            resp = conn.getresponse()
            while got < per_stream and time.time() - t_start < active_cap:
                buf = resp.read(READ_BLOCK_BYTES)
                if not buf:
                    break
                got += len(buf)
                with lock:
                    total[0] += len(buf)
                    events.append((time.time(), total[0]))
        except Exception:
            pass
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    threads = [threading.Thread(target=_worker) for _ in range(streams)]
    t0 = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join(active_cap + 20)
    duration = time.time() - t0
    if not events:
        return None
    events.sort()
    steady_bps, peak_bps = _steady_and_peak(events, t0, duration)
    return {"speed_bps": steady_bps, "peak_bps": peak_bps,
            "total_bytes": events[-1][1], "duration": round(duration, 2),
            "streams": streams}


def _parallel_download(sources: list, streams: int, budget_bytes: int,
                       active_cap: int) -> Optional[dict]:
    """Перебираем sources (PARALLEL_DOWNLOAD_SOURCES), первый рабочий выигрывает."""
    per_stream = max(1_000_000, budget_bytes // max(1, streams))
    for url_tpl, name in sources:
        # {size_mb} округляем к существующим файлам testdebit (10/100);
        # фиксированные файлы (cachefly) читаем до бюджета и закрываем
        size_mb = 10 if per_stream <= 10_000_000 else 100
        url = url_tpl.format(size=min(per_stream, BIG_DOWNLOAD_BYTES),
                             size_mb=size_mb)
        res = _parallel_download_one(url, streams, budget_bytes, active_cap)
        if res and res.get("speed_bps", 0) > 0:
            res["source"] = name
            return res
    return None


def _ookla_test(timeout: int = 180) -> Optional[dict]:
    """Полный замер через Ookla speedtest CLI (кейс №16: единственный
    способ увидеть настоящее число на порту > 1 Gbps — ~16 параллельных
    соединений). Цена: десятки GB трафика за прогон — только opt-in.

    Возвращает {dl_mbps, ul_mbps, latency_ms, server} или None.
    """
    if not shutil.which("speedtest"):
        return None
    r = _run(["speedtest", "--accept-license", "--accept-gdpr", "-f", "json"],
             capture=True, timeout=timeout)
    if r.returncode != 0:
        return None
    try:
        data = json.loads(r.stdout or "{}")
        dl = data.get("download", {}).get("bandwidth", 0)
        ul = data.get("upload", {}).get("bandwidth", 0)
        if not dl:
            return None
        return {
            "dl_mbps": round(dl * 8 / 1e6, 2),
            "ul_mbps": round(ul * 8 / 1e6, 2) if ul else None,
            "latency_ms": data.get("ping", {}).get("latency"),
            "server": "{} — {}".format(
                data.get("server", {}).get("name", "?"),
                data.get("server", {}).get("location", "?")),
        }
    except Exception:
        return None


def _baseline_mbps(hours: int = BASELINE_WINDOW_HOURS,
                   min_samples: int = BASELINE_MIN_SAMPLES) -> Optional[float]:
    """Медиана download_mbps за последние N часов (вызывается ДО save_sample,
    так что текущий замер в базлайн не попадает). None, если сэмплов мало."""
    try:
        samples = read_samples(days=2)
    except Exception:
        return None
    cutoff = time.time() - hours * 3600
    vals = []
    for s in samples:
        try:
            if int(s.get("epoch", 0)) >= cutoff and float(s.get("download_mbps", 0)) > 0:
                vals.append(float(s["download_mbps"]))
        except (TypeError, ValueError):
            continue
    if len(vals) < min_samples:
        return None
    vals.sort()
    n = len(vals)
    if n % 2:
        return vals[n // 2]
    return (vals[n // 2 - 1] + vals[n // 2]) / 2.0


def _classify_level(download_mbps: float, cfg: dict) -> str:
    """Классификация замера.

    absolute (по умолчанию, политика флота 08.11.2026): фиксированные
    пороги thresholds.normal_mbps (1000) / degraded_mbps (100) —
    ≥1G зелёный, 100-1000 жёлтый, <100 красный. Кейс DE 08.11.2026:
    auto-режим дал ⚠️ при 1564 Mbps на 5G-порту (< 50% базлайна) —
    ложный сработ.
    auto (opt-in): относительно медианы-базлайна за 24ч — ловит обрез
    порта > 1 Gbps мгновенным алертом. Нет базлайна (< min_samples) —
    fallback на абсолютные пороги.
    """
    mode = str(cfg.get("level_mode", "absolute") or "absolute").strip().lower()
    th = cfg.get("thresholds") or {}
    if mode == "auto":
        baseline = _baseline_mbps()
        if baseline:
            if download_mbps >= baseline * float(cfg.get("baseline_normal_ratio", 0.5)):
                return "normal"
            if download_mbps >= baseline * float(cfg.get("baseline_degraded_ratio", 0.2)):
                return "degraded"
            return "critical"
    normal = float(th.get("normal_mbps", 100.0))
    degraded = float(th.get("degraded_mbps", 50.0))
    if download_mbps >= normal:
        return "normal"
    if download_mbps >= degraded:
        return "degraded"
    return "critical"


def _run_download_probe(cfg: dict, big: bool) -> dict:
    """Загрузочный тест согласно cfg. Единственная точка выбора методики:
    Ookla (opt-in, только полный) → параллельные потоки → легаси-однопоток.

    Возвращает {speed_bps, peak_bps, source, streams, probe_mb, ookla};
    speed_bps == 0.0 → скачать не удалось вовсе.
    """
    streams_cfg = int(cfg.get("parallel_streams", 0) or 0)
    if big:
        streams = streams_cfg if streams_cfg > 0 else DEFAULT_PARALLEL_STREAMS_BIG
        probe_mb = float(cfg.get("probe_mb_big", PROBE_MB_BIG))
        cap = STREAM_ACTIVE_CAP_BIG
    else:
        streams = streams_cfg if streams_cfg > 0 else DEFAULT_PARALLEL_STREAMS_LIGHT
        probe_mb = float(cfg.get("probe_mb_light", PROBE_MB_LIGHT))
        cap = STREAM_ACTIVE_CAP_LIGHT
    budget_bytes = int(probe_mb * 1_000_000)

    # Ookla: настоящее число вместо нижней оценки (десятки GB за прогон)
    if big and cfg.get("use_ookla"):
        ook = _ookla_test()
        if ook:
            return {"speed_bps": ook["dl_mbps"] / 8 * 1e6, "peak_bps": None,
                    "source": "ookla", "streams": 1, "probe_mb": 0.0,
                    "ookla": ook}

    if streams >= 2:
        res = _parallel_download(PARALLEL_DOWNLOAD_SOURCES, streams,
                                 budget_bytes, cap)
        if res and res.get("speed_bps", 0) > 0:
            return {"speed_bps": res["speed_bps"], "peak_bps": res["peak_bps"],
                    "source": res["source"], "streams": streams,
                    "probe_mb": probe_mb, "ookla": None,
                    "total_bytes": res.get("total_bytes", 0),
                    "duration": res.get("duration", 0.0)}

    # Легаси-путь: один curl (parallel_streams=1 или все источники упали)
    size = BIG_DOWNLOAD_BYTES if big else SMALL_DOWNLOAD_BYTES
    timeout = BIG_DOWNLOAD_TIMEOUT if big else SMALL_DOWNLOAD_TIMEOUT
    speed_bps, source = _try_download(DOWNLOAD_SOURCES, size, timeout)
    return {"speed_bps": speed_bps or 0.0, "peak_bps": None, "source": source,
            "streams": 1, "probe_mb": round(size / 1e6, 1), "ookla": None}


def measure_once(big: bool = False) -> dict:
    """Один замер. big=False — лёгкая проба (~60 MB, 6 потоков),
    big=True — полный (~760 MB, 8 потоков; или Ookla при use_ookla).

    Возвращает dict:
      {ts, label, ip, download_mbps, download_source, peak_mbps, streams,
       probe_mb, latency_ms, latency_target, level, big}
    """
    cfg = load_config()
    label = (cfg.get("node_label") or "").strip() or _node_hostname()
    ip = (cfg.get("node_ip") or "").strip() or _node_public_ip()

    # 1. Latency — первый рабочий target
    latency_ms = None
    latency_target = ""
    for target in PING_TARGETS:
        lat = _ping_latency(target)
        if lat is not None:
            latency_ms = lat
            latency_target = target
            break

    # 2. Download (Ookla → параллельные потоки → легаси-однопоток)
    probe = _run_download_probe(cfg, big)
    speed_bps = probe.get("speed_bps", 0.0)
    download_mbps = (speed_bps * 8 / 1e6) if speed_bps else 0.0
    peak_mbps = (probe.get("peak_bps") or 0) * 8 / 1e6

    # 3. iperf3 (только для big)
    iperf3_mbps = None
    if big and cfg.get("use_iperf3"):
        iperf3_mbps = _iperf3_test(cfg.get("iperf3_server", "ping.online.net"),
                                   int(cfg.get("iperf3_port", 5200)))

    # 4. Классификация (auto: относительно базлайна 24ч; см. _classify_level)
    level = _classify_level(download_mbps, cfg)

    sample = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "epoch": int(time.time()),
        "label": label,
        "ip": ip,
        "download_mbps": round(download_mbps, 2),
        "download_source": probe.get("source", "none"),
        "peak_mbps": round(peak_mbps, 2) if peak_mbps else None,
        "streams": probe.get("streams", 1),
        "probe_mb": probe.get("probe_mb", 0.0),
        "latency_ms": round(latency_ms, 2) if latency_ms else None,
        "latency_target": latency_target,
        "level": level,
        "big": big,
    }
    if probe.get("ookla"):
        ook = probe["ookla"]
        if ook.get("ul_mbps") is not None:
            sample["ookla_ul_mbps"] = ook["ul_mbps"]
        if ook.get("server"):
            sample["ookla_server"] = ook["server"]
    if iperf3_mbps is not None:
        sample["iperf3_mbps"] = round(iperf3_mbps, 2)
    return sample


# ══════════════════════════════════════════════════════════════════════════════
#  ХРАНЕНИЕ СЭМПЛОВ
# ══════════════════════════════════════════════════════════════════════════════

def _samples_file(date_str: Optional[str] = None) -> Path:
    if not date_str:
        date_str = time.strftime("%Y-%m-%d")
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    return SAMPLES_DIR / f"{date_str}.jsonl"


def save_sample(sample: dict) -> None:
    try:
        f = _samples_file()
        with f.open("a") as fh:
            fh.write(json.dumps(sample, ensure_ascii=False) + "\n")
    except Exception as e:
        _log(f"save_sample: {e}")


def read_samples(date_str: Optional[str] = None, days: int = 1) -> list:
    """Сэмплы за указанный день (или за последние N дней)."""
    samples = []
    if date_str:
        files = [_samples_file(date_str)]
    else:
        files = []
        for i in range(days):
            d = time.strftime("%Y-%m-%d", time.localtime(time.time() - i * 86400))
            files.append(_samples_file(d))
    for f in files:
        if not f.exists():
            continue
        try:
            for line in f.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    try:
                        samples.append(json.loads(line))
                    except Exception:
                        pass
        except Exception:
            pass
    return samples


def _cleanup_old_samples(retention_days: int) -> None:
    """Удалить сэмплы старше retention_days."""
    if retention_days <= 0:
        return
    cutoff = time.time() - retention_days * 86400
    if not SAMPLES_DIR.exists():
        return
    for f in SAMPLES_DIR.glob("*.jsonl"):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  TELEGRAM
# ══════════════════════════════════════════════════════════════════════════════

def _load_tg_config() -> tuple:
    """Загрузить (token, chat_id, proxy) из telegram.json или tg_bot.json.

    2026-10-13: добавлен proxy — на части нод (138.x) прямой доступ к
    api.telegram.org заблокирован TLS-ресетом, нужен mieru-прокси
    (127.0.0.1:25181). proxy берётся из telegram.json→"proxy"; в
    tg_bot.json поля proxy нет (там только token/admin_id/allowed_users).
    Паттерн тот же, что в steal_monitor._tg_send().
    """
    for path in (TG_CONFIG, TG_BOT_CFG):
        if not path.exists():
            continue
        try:
            cfg = json.loads(path.read_text(encoding="utf-8"))
            token = cfg.get("token", "")
            chat = cfg.get("chat_id") or cfg.get("admin_id", "")
            proxy = str(cfg.get("proxy") or "").strip()
            if token and chat:
                return token, str(chat), proxy
        except Exception:
            pass
    return "", "", ""


def _split_tg_chunks(msg: str, limit: int = TG_CHUNK_LIMIT) -> list:
    if len(msg) <= limit:
        return [msg]
    chunks = []
    cur = ""
    for line in msg.split("\n"):
        if len(cur) + len(line) + 1 > limit and cur:
            chunks.append(cur)
            cur = ""
        cur += line + "\n"
    if cur:
        chunks.append(cur)
    return chunks or [msg]


def _tg_send(msg: str, event: str = "") -> bool:
    """Отправка в TG с ретраями + опциональным прокси.

    Прокси: ключ "proxy" в telegram.json (напр. http://127.0.0.1:25181 —
    локальный mieru-HTTP-прокси). Нужен на нодах, откуда api.telegram.org
    недоступен напрямую (TLS-ресет). Без ключа — прямое подключение.
    """
    try:
        token, chat, proxy = _load_tg_config()
        if not token or not chat:
            _log("tg_send: нет token/chat в telegram.json или tg_bot.json")
            return False
        cfg = load_config()
        retries = max(1, min(5, int(cfg.get("tg_retries", TG_RETRIES))))
        chunks = _split_tg_chunks(msg)
        all_ok = True
        for chunk in chunks:
            ok_chunk = False
            for attempt in range(1, retries + 1):
                cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                       "-m", str(TG_TIMEOUT)]
                if proxy:
                    cmd += ["-x", proxy]
                cmd += [
                    f"https://api.telegram.org/bot{token}/sendMessage",
                    "-d", f"chat_id={chat}",
                    "-d", "parse_mode=HTML",
                    "--data-urlencode", f"text={chunk}",
                ]
                r = _run(cmd, capture=True, timeout=TG_TIMEOUT + 5)
                code = (r.stdout or "").strip()
                if code == "200":
                    ok_chunk = True
                    break
                _log(f"tg send: попытка {attempt}/{retries} — код {code} "
                     f"{'(via proxy ' + proxy + ')' if proxy else '(direct)'}")
                if attempt < retries:
                    time.sleep(TG_RETRY_PAUSE)
            all_ok = all_ok and ok_chunk
        return all_ok
    except Exception as e:
        _log(f"tg_send exception: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
#  АЛЕРТЫ ПРИ ДЕГРАДАЦИИ
# ══════════════════════════════════════════════════════════════════════════════

def _load_tg_state() -> dict:
    if not TG_STATE_FILE.exists():
        return {}
    try:
        return json.loads(TG_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_tg_state(state: dict) -> None:
    try:
        TG_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        TG_STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except Exception:
        pass


def _check_alert(sample: dict, cfg: dict) -> Optional[str]:
    """Проверить, нужен ли алерт. Возвращает текст алерта или None."""
    if not cfg.get("alerts_enabled", True):
        return None
    th = cfg.get("thresholds") or {}
    level = sample.get("level", "normal")
    if level == "normal":
        return None

    # Политика флота (08.11.2026): мгновенный TG-пуш только для critical
    # (< degraded_mbps, по умолчанию 100 Mbps). Жёлтый (degraded,
    # 100-1000) — статус в периодических/дневных отчётах без пуша;
    # пушится только при alert_degraded=true (opt-in). Кейс DE:
    # ⚠️-алерт при 1564 Mbps на 5G-порту = ложный сработ auto-режима.
    if level == "degraded" and not cfg.get("alert_degraded", False):
        return None

    # Anti-spam: cooldown
    state = _load_tg_state()
    now = int(time.time())
    cooldown = int(th.get("alert_cooldown_min", 180)) * 60
    last_alert = state.get("last_alert_epoch", 0)
    if now - last_alert < cooldown:
        return None

    # Consecutive check: N сэмплов подряд degraded/critical.
    # Смотрим level сэмплов, а не абсолютный Mbps: в auto-режиме порог —
    # базлайн ноды (кейс №16: обрез 16.5G → 1G даёт level=critical при
    # 950 Mbps, хотя абсолютный порог 50 Mbps пройден с запасом)
    consecutive_needed = int(th.get("alert_consecutive", 2))
    recent = read_samples(days=1)[-consecutive_needed:]
    if len(recent) < consecutive_needed:
        return None
    all_degraded = all(s.get("level") in ("degraded", "critical")
                       for s in recent)
    if not all_degraded:
        return None

    # Формируем алерт
    label = sample.get("label", "unknown")
    ip = sample.get("ip", "unknown")
    speed = sample.get("download_mbps", 0)
    latency = sample.get("latency_ms")
    level_emoji = "⚠️" if level == "degraded" else "🔴"
    level_text = "ВНИМАНИЕ" if level == "degraded" else "КРИТИЧНО"

    text = f"{level_emoji} <b>Bandwidth {level_text}</b>\n\n"
    text += f"Нода: <b>{label}</b> ({ip})\n"
    text += f"Скорость: <b>{speed} Mbps</b>\n"
    if latency:
        text += f"Latency: {latency} ms ({sample.get('latency_target', '')})\n"
    text += f"Время: {sample.get('ts', '')}\n\n"
    if level == "critical":
        crit_thr = float(th.get("degraded_mbps", 100.0))
        if speed is not None and speed < crit_thr:
            text += (f"🚨 Скорость ниже {crit_thr:.0f} Mbps — возможно, "
                     "хостер обрезал канал.\n")
            text += "Проверьте договор и условия тарифа.\n"
        else:
            text += "🚨 Падение > 80% от базлайна за 24ч — возможно, хостер обрезал канал.\n"
            text += "Проверьте договор и условия тарифа.\n"
    else:
        text += "⚠️ Скорость ниже нормы (базлайн/порог деградации).\n"
        text += "Возможно, временная деградация или нагрузка.\n"
    text += f"\n<i>Алерт отправлен раз в {cooldown // 60} мин.</i>"

    state["last_alert_epoch"] = now
    state["last_alert_level"] = level
    _save_tg_state(state)
    return text


# ══════════════════════════════════════════════════════════════════════════════
#  ОСНОВНЫЕ ФУНКЦИИ (вызываются cron'ом)
# ══════════════════════════════════════════════════════════════════════════════

def sample_once(verbose: bool = False) -> dict:
    """Лёгкая проба (cron */30 мин): 10 MB download + ping.

    Сохраняет сэмпл, проверяет алерт, отправляет в TG при деградации.
    """
    cfg = load_config()
    if not cfg.get("enabled", True):
        return {"skipped": "disabled"}

    sample = measure_once(big=False)
    save_sample(sample)

    # Проверка алерта
    alert_text = _check_alert(sample, cfg)
    if alert_text:
        _tg_send(alert_text, event="bandwidth_alert")
        _log(f"ALERT sent: level={sample['level']} speed={sample['download_mbps']}")

    # Cleanup старых сэмплов
    _cleanup_old_samples(int(cfg.get("retention_days", 30)))

    if verbose:
        print(f"  {sample['label']} ({sample['ip']}): "
              f"{sample['download_mbps']} Mbps [{sample['level']}] "
              f"latency={sample.get('latency_ms', '?')}ms")
    _log(f"sample: {sample['download_mbps']} Mbps [{sample['level']}] "
         f"src={sample['download_source']}")
    return sample


def send_periodic_report() -> str:
    """Периодический отчёт (cron */6 часов): полный замер + сводка."""
    cfg = load_config()
    if not cfg.get("periodic_report_enabled", True):
        return "skipped"

    # Полный замер
    big_sample = measure_once(big=True)
    save_sample(big_sample)

    # Проверка алерта для big-замера
    alert_text = _check_alert(big_sample, cfg)
    if alert_text:
        _tg_send(alert_text, event="bandwidth_alert")

    # Сводка за последние 6 часов
    now = int(time.time())
    recent = [s for s in read_samples(days=1)
              if now - int(s.get("epoch", 0)) <= 6 * 3600]
    speeds = [s.get("download_mbps", 0) for s in recent if not s.get("big")]
    big_speeds = [s.get("download_mbps", 0) for s in recent if s.get("big")]

    label = big_sample.get("label", "unknown")
    ip = big_sample.get("ip", "unknown")
    text = f"📊 <b>Bandwidth отчёт — {label}</b>\n"
    text += f"({ip})\n\n"

    if big_sample.get("download_source") == "ookla":
        text += "<b>Текущий замер (Ookla speedtest):</b>\n"
        text += f"  Скорость: <b>{big_sample['download_mbps']} Mbps</b>\n"
        if big_sample.get("ookla_ul_mbps"):
            text += f"  Upload: {big_sample['ookla_ul_mbps']} Mbps\n"
        if big_sample.get("ookla_server"):
            text += f"  Server: {big_sample['ookla_server']}\n"
    else:
        streams = big_sample.get("streams", 1) or 1
        probe_mb = big_sample.get("probe_mb", 0) or 0
        if streams > 1:
            text += f"<b>Текущий замер ({streams} потоков, ~{probe_mb:.0f} MB):</b>\n"
            text += (f"  Скорость: <b>≥ {big_sample['download_mbps']} Mbps</b>"
                     " (нижняя оценка)\n")
        else:
            text += "<b>Текущий замер (однопотоковый):</b>\n"
            text += f"  Скорость: <b>{big_sample['download_mbps']} Mbps</b>\n"
        if big_sample.get("peak_mbps"):
            text += f"  Пик (окно 1 с): {big_sample['peak_mbps']} Mbps\n"
    if big_sample.get("iperf3_mbps"):
        text += f"  iperf3 (4 потока): {big_sample['iperf3_mbps']} Mbps\n"
    if big_sample.get("latency_ms"):
        text += f"  Latency: {big_sample['latency_ms']} ms "
        text += f"({big_sample.get('latency_target', '')})\n"
    text += f"  Уровень: {_level_emoji(big_sample['level'])} {big_sample['level']}\n\n"

    if speeds:
        avg = sum(speeds) / len(speeds)
        mn = min(speeds)
        mx = max(speeds)
        text += f"<b>За 6 часов (лёгкие пробы, {len(speeds)} замеров):</b>\n"
        text += f"  avg: {avg:.1f} Mbps\n"
        text += f"  min: {mn:.1f} Mbps / max: {mx:.1f} Mbps\n"

    if big_speeds:
        avg_big = sum(big_speeds) / len(big_speeds)
        text += f"\n<b>Полные замеры ({len(big_speeds)}):</b>\n"
        text += f"  avg: {avg_big:.1f} Mbps\n"

    _tg_send(text, event="bandwidth_report")

    # Сохранить копию отчёта
    try:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        date_str = time.strftime("%Y-%m-%d_%H%M")
        (REPORTS_DIR / f"periodic_{date_str}.txt").write_text(
            text.replace("<b>", "").replace("</b>", "").replace("<i>", "").replace("</i>", ""),
            encoding="utf-8")
    except Exception:
        pass

    _log(f"periodic report sent: {big_sample['download_mbps']} Mbps")
    return text


def send_daily_report(date_str: Optional[str] = None, send_tg: bool = True) -> str:
    """Дневной отчёт (cron H:M): сводка за сутки."""
    cfg = load_config()
    if not cfg.get("daily_report_enabled", True):
        return "skipped"

    if not date_str:
        date_str = time.strftime("%Y-%m-%d")
    samples = read_samples(date_str=date_str)
    if not samples:
        return f"нет сэмплов за {date_str}"

    label = samples[-1].get("label", "unknown")
    ip = samples[-1].get("ip", "unknown")
    speeds = [s.get("download_mbps", 0) for s in samples]
    big_speeds = [s.get("download_mbps", 0) for s in samples if s.get("big")]
    small_speeds = [s.get("download_mbps", 0) for s in samples if not s.get("big")]
    latencies = [s.get("latency_ms") for s in samples if s.get("latency_ms")]

    avg = sum(speeds) / len(speeds) if speeds else 0
    mn = min(speeds) if speeds else 0
    mx = max(speeds) if speeds else 0
    avg_lat = sum(latencies) / len(latencies) if latencies else 0

    # Классификация дня: по полным замерам, если есть (лёгкая проба —
    # нижняя оценка: на широких портах занижает — NL 16.5G даёт ~830 Mbps
    # лёгкой пробой при 2.4G+ полной; классифицировать день по ней —
    # вечное «жёлтое ВНИМАНИЕ» на живом порту). Нет полных — по всем.
    th = cfg.get("thresholds") or {}
    normal = float(th.get("normal_mbps", 1000.0))
    degraded = float(th.get("degraded_mbps", 100.0))
    day_pool = big_speeds if big_speeds else speeds
    day_avg = (sum(day_pool) / len(day_pool)) if day_pool else 0.0
    if day_avg >= normal:
        day_level = "НОРМА"
        emoji = "🟢"
    elif day_avg >= degraded:
        day_level = "ВНИМАНИЕ"
        emoji = "🟡"
    else:
        day_level = "КРИТИЧНО"
        emoji = "🔴"

    text = f"{emoji} <b>Bandwidth дневной отчёт — {label}</b>\n"
    text += f"({ip}) — {date_str}\n\n"
    text += f"<b>Классификация: {day_level}</b>\n\n"
    text += f"<b>За сутки ({len(samples)} замеров):</b>\n"
    text += f"  avg: <b>{avg:.1f} Mbps</b>\n"
    text += f"  min: {mn:.1f} Mbps / max: {mx:.1f} Mbps\n\n"
    if small_speeds:
        text += f"Лёгкие пробы ({len(small_speeds)}): avg {sum(small_speeds)/len(small_speeds):.1f} Mbps\n"
    if big_speeds:
        text += f"Полные замеры ({len(big_speeds)}): avg {sum(big_speeds)/len(big_speeds):.1f} Mbps\n"
    if latencies:
        text += f"\nLatency: avg {avg_lat:.1f} ms\n"
    text += f"\n<i>Пороги: normal ≥ {normal} Mbps, degraded ≥ {degraded} Mbps"
    if str(cfg.get("level_mode", "absolute") or "absolute").lower() == "auto":
        text += " · auto: относительно базлайна 24ч"
    text += "</i>"

    if send_tg:
        _tg_send(text, event="bandwidth_daily")

    # Сохранить копию
    try:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        (REPORTS_DIR / f"daily_{date_str}.txt").write_text(
            text.replace("<b>", "").replace("</b>", "").replace("<i>", "").replace("</i>", ""),
            encoding="utf-8")
    except Exception:
        pass

    _log(f"daily report: avg={avg:.1f} Mbps [{day_level}]")
    return text


def _level_emoji(level: str) -> str:
    return {"normal": "🟢", "degraded": "🟡", "critical": "🔴"}.get(level, "⚪")


# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА / УДАЛЕНИЕ (cron)
# ══════════════════════════════════════════════════════════════════════════════

def is_monitor_installed() -> bool:
    return CRON_FILE.exists() and SAMPLE_SCRIPT.exists()


def install_bandwidth_monitor(cfg: Optional[dict] = None) -> tuple:
    """Установить cron: sampler */interval + periodic report */6h + daily H:M."""
    try:
        cfg = cfg or load_config()
        sample_interval = max(5, min(1440, int(cfg.get("sample_interval_min",
                                                         DEFAULT_SAMPLE_INTERVAL_MIN))))
        report_hours = max(1, min(24, int(cfg.get("report_interval_hours",
                                                   DEFAULT_REPORT_INTERVAL_HOURS))))
        daily_hour = max(0, min(23, int(cfg.get("daily_hour", DEFAULT_DAILY_HOUR))))
        daily_minute = max(0, min(59, int(cfg.get("daily_minute", DEFAULT_DAILY_MINUTE))))
        installer_path = _find_installer_path()
        python = _find_python()

        for p in (SAMPLE_SCRIPT, REPORT_SCRIPT, DAILY_SCRIPT, CRON_FILE):
            p.parent.mkdir(parents=True, exist_ok=True)

        SAMPLE_SCRIPT.write_text(f"""#!/bin/bash
# bandwidth-sample.sh — лёгкая проба (Chimera bandwidth_monitor)
export PYTHONPATH="{installer_path}:$PYTHONPATH"
{python} -c "
import sys
sys.path.insert(0, '{installer_path}')
from chimera.modules.bandwidth_monitor import sample_once
sample_once()
" 2>>/var/log/bandwidth-monitor.log
""", encoding="utf-8")
        SAMPLE_SCRIPT.chmod(0o755)

        REPORT_SCRIPT.write_text(f"""#!/bin/bash
# bandwidth-report.sh — периодический отчёт (Chimera bandwidth_monitor)
export PYTHONPATH="{installer_path}:$PYTHONPATH"
{python} -c "
import sys
sys.path.insert(0, '{installer_path}')
from chimera.modules.bandwidth_monitor import send_periodic_report
send_periodic_report()
" 2>>/var/log/bandwidth-monitor.log
""", encoding="utf-8")
        REPORT_SCRIPT.chmod(0o755)

        DAILY_SCRIPT.write_text(f"""#!/bin/bash
# bandwidth-daily.sh — дневной отчёт (Chimera bandwidth_monitor)
export PYTHONPATH="{installer_path}:$PYTHONPATH"
{python} -c "
import sys
sys.path.insert(0, '{installer_path}')
from chimera.modules.bandwidth_monitor import send_daily_report
send_daily_report()
" 2>>/var/log/bandwidth-monitor.log
""", encoding="utf-8")
        DAILY_SCRIPT.chmod(0o755)

        CRON_FILE.write_text(
            f"""# bandwidth-monitor — Chimera
*/{sample_interval} * * * * root {SAMPLE_SCRIPT} >/dev/null 2>&1
0 */{report_hours} * * * root {REPORT_SCRIPT} >/dev/null 2>&1
{daily_minute} {daily_hour} * * * root {DAILY_SCRIPT} >/dev/null 2>&1
""", encoding="utf-8")
        CRON_FILE.chmod(0o644)

        # Сохранить конфиг
        save_config(cfg)

        _log(f"установлен: sampler */{sample_interval} мин + report */{report_hours}ч + daily {daily_hour:02d}:{daily_minute:02d}")
        return True, (f"Bandwidth-мониторинг установлен:\n"
                      f"  • лёгкая проба: каждые {sample_interval} мин\n"
                      f"  • полный отчёт: каждые {report_hours} ч\n"
                      f"  • дневной отчёт: {daily_hour:02d}:{daily_minute:02d}\n"
                      f"  • алерты в TG при деградации")
    except Exception as e:
        return False, f"Ошибка установки: {e}"


def uninstall_bandwidth_monitor() -> tuple:
    """Удалить cron + wrappers. Данные сохраняются."""
    try:
        for p in (CRON_FILE, SAMPLE_SCRIPT, REPORT_SCRIPT, DAILY_SCRIPT):
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass
        _log("удалён (cron + wrappers; данные сохранены)")
        return True, "Bandwidth-мониторинг удалён (данные и конфиг сохранены)"
    except Exception as e:
        return False, f"Ошибка удаления: {e}"


# ══════════════════════════════════════════════════════════════════════════════
#  TUI-МЕНЮ (минимальное)
# ══════════════════════════════════════════════════════════════════════════════

def do_bandwidth_monitor_menu() -> None:
    """Интерактивное меню управления bandwidth-мониторингом."""
    try:
        core = __import__("chimera._core", fromlist=["_box_top", "_box_row",
                                                       "_box_bottom", "info",
                                                       "warn", "success",
                                                       "CYAN", "GREEN", "RED",
                                                       "YELLOW", "DIM", "NC"])
    except Exception:
        # fallback — простой print
        core = None

    def _print(s):
        print(s)

    cfg = load_config()
    installed = is_monitor_installed()

    if core:
        core._box_top("Bandwidth мониторинг канала")
        core._box_row(f"  Статус: {'🟢 установлен' if installed else '🔴 не установлен'}")
        core._box_row(f"  Проба: каждые {cfg.get('sample_interval_min', 30)} мин")
        core._box_row(f"  Отчёт: каждые {cfg.get('report_interval_hours', 6)} ч")
        core._box_row(f"  Дневной: {cfg.get('daily_hour', 23):02d}:{cfg.get('daily_minute', 50):02d}")
        th = cfg.get("thresholds", {})
        core._box_row(f"  Пороги: normal ≥ {th.get('normal_mbps', 1000)} Mbps, "
                      f"degraded ≥ {th.get('degraded_mbps', 100)} Mbps"
                      f" · режим: {cfg.get('level_mode', 'absolute')}")
        core._box_row(f"  Потоки: {'авто' if not cfg.get('parallel_streams') else cfg.get('parallel_streams')}"
                      f" · Ookla: {'вкл' if cfg.get('use_ookla') else 'выкл'}")
        core._box_row(f"  Алерты: {'вкл' if cfg.get('alerts_enabled') else 'выкл'}")
        core._box_bottom()
    else:
        _print("=== Bandwidth мониторинг ===")
        _print(f"  Статус: {'установлен' if installed else 'не установлен'}")
        _print(f"  Проба: каждые {cfg.get('sample_interval_min', 30)} мин")
        _print(f"  Отчёт: каждые {cfg.get('report_interval_hours', 6)} ч")

    print()
    print("  [1] Установить мониторинг")
    print("  [2] Удалить мониторинг")
    print("  [3] Замерить сейчас (лёгкая проба)")
    print("  [4] Замерить сейчас (полный замер)")
    print("  [5] Отправить отчёт сейчас")
    print("  [6] Показать историю за 24ч")
    print("  [7] Настройки (интервал, пороги)")
    print("  [0] Назад")
    choice = input("\n  Выбор: ").strip()

    if choice == "1":
        ok, msg = install_bandwidth_monitor(cfg)
        print(f"  {msg}")
    elif choice == "2":
        ok, msg = uninstall_bandwidth_monitor()
        print(f"  {msg}")
    elif choice == "3":
        print("  Замеряю...")
        s = sample_once(verbose=True)
        print(f"  Результат: {s.get('download_mbps', '?')} Mbps [{s.get('level', '?')}]")
    elif choice == "4":
        print("  Полный замер (параллельные потоки / Ookla)...")
        s = measure_once(big=True)
        print(f"  Результат: {s.get('download_mbps', '?')} Mbps [{s.get('level', '?')}]")
        save_sample(s)
    elif choice == "5":
        print("  Отправляю отчёт...")
        text = send_periodic_report()
        print("  Отчёт отправлен в TG.")
    elif choice == "6":
        samples = read_samples(days=1)
        if not samples:
            print("  Нет сэмплов за 24ч")
        else:
            print(f"  Сэмплов: {len(samples)}")
            for s in samples[-10:]:
                print(f"    {s.get('ts', '')} {s.get('download_mbps', '?')} Mbps "
                      f"[{s.get('level', '?')}] {'(big)' if s.get('big') else ''}")
    elif choice == "7":
        _settings_menu(cfg)
    elif choice == "0":
        return


def _settings_menu(cfg: dict) -> None:
    """Подменю настроек."""
    print("\n=== Настройки ===")
    print(f"  [1] Интервал пробы (мин): {cfg.get('sample_interval_min', 30)}")
    print(f"  [2] Интервал отчёта (ч): {cfg.get('report_interval_hours', 6)}")
    print(f"  [3] Порог normal (Mbps): {cfg.get('thresholds', {}).get('normal_mbps', 1000)}")
    print(f"  [4] Порог degraded (Mbps): {cfg.get('thresholds', {}).get('degraded_mbps', 100)}")
    print(f"  [5] Метка ноды: {cfg.get('node_label', '') or '(hostname)'}")
    print("  [0] Назад")
    choice = input("  Выбор: ").strip()

    if choice == "1":
        v = input(f"  Интервал пробы (5-1440 мин) [{cfg.get('sample_interval_min', 30)}]: ").strip()
        if v.isdigit():
            cfg["sample_interval_min"] = max(5, min(1440, int(v)))
            save_config(cfg)
            print("  Сохранено.")
    elif choice == "2":
        v = input(f"  Интервал отчёта (1-24 ч) [{cfg.get('report_interval_hours', 6)}]: ").strip()
        if v.isdigit():
            cfg["report_interval_hours"] = max(1, min(24, int(v)))
            save_config(cfg)
            print("  Сохранено.")
    elif choice == "3":
        v = input(f"  Порог normal (Mbps) [{cfg.get('thresholds', {}).get('normal_mbps', 1000)}]: ").strip()
        try:
            cfg.setdefault("thresholds", {})["normal_mbps"] = float(v)
            save_config(cfg)
            print("  Сохранено.")
        except ValueError:
            print("  Неверное значение.")
    elif choice == "4":
        v = input(f"  Порог degraded (Mbps) [{cfg.get('thresholds', {}).get('degraded_mbps', 100)}]: ").strip()
        try:
            cfg.setdefault("thresholds", {})["degraded_mbps"] = float(v)
            save_config(cfg)
            print("  Сохранено.")
        except ValueError:
            print("  Неверное значение.")
    elif choice == "5":
        v = input(f"  Метка ноды [{cfg.get('node_label', '') or '(hostname)'}]: ").strip()
        cfg["node_label"] = v
        save_config(cfg)
        print("  Сохранено.")


# ══════════════════════════════════════════════════════════════════════════════
#  CLI ENTRY POINT (для ручного запуска)
# ══════════════════════════════════════════════════════════════════════════════

def _cli() -> None:
    """CLI: python3 -m chimera.modules.bandwidth_monitor [sample|report|daily|status]"""
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "sample":
        s = sample_once(verbose=True)
        print(f"{s.get('download_mbps', '?')} Mbps [{s.get('level', '?')}]")
    elif cmd == "report":
        send_periodic_report()
        print("Report sent.")
    elif cmd == "daily":
        send_daily_report()
        print("Daily report sent.")
    elif cmd == "status":
        cfg = load_config()
        print(f"installed: {is_monitor_installed()}")
        print(f"sample_interval: {cfg.get('sample_interval_min', 30)} min")
        print(f"report_interval: {cfg.get('report_interval_hours', 6)} h")
        th = cfg.get("thresholds", {})
        print(f"thresholds: normal≥{th.get('normal_mbps', 1000)} degraded≥{th.get('degraded_mbps', 100)}")
        print(f"level_mode: {cfg.get('level_mode', 'absolute')} · "
              f"streams: {cfg.get('parallel_streams', 0) or 'авто'} · "
              f"ookla: {cfg.get('use_ookla', False)}")
        samples = read_samples(days=1)
        print(f"samples (24h): {len(samples)}")
        if samples:
            last = samples[-1]
            print(f"last: {last.get('ts', '')} {last.get('download_mbps', '?')} Mbps [{last.get('level', '?')}]")
    elif cmd == "install":
        ok, msg = install_bandwidth_monitor()
        print(msg)
    elif cmd == "uninstall":
        ok, msg = uninstall_bandwidth_monitor()
        print(msg)
    elif cmd == "menu":
        do_bandwidth_monitor_menu()
    else:
        print(f"Usage: {sys.argv[0]} [sample|report|daily|status|install|uninstall|menu]")


if __name__ == "__main__":
    _cli()
