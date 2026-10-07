"""
chimera/modules/steal_monitor.py
───────────────────────────────────────────────────────────────────────────────
CPU Steal монитор — периодический замер %steal (гипервизор забирает CPU у VM)
по /proc/stat с дневным отчётом в Telegram и рекомендациями.

Зачем: %steal >5–10% сутками = хронический оверселл провайдера — CPU-зависимые
роли (AWG-каскад с двойным шифрованием, TLS, сжатие) душатся всегда, а
TCP-relay (Mieru) терпит. Отчёт классифицирует ноду (НОРМА / ВНИМАНИЕ /
КРИТИЧНО), даёт рекомендации «делать/не делать» и тикет-блок с доказательствами
(копи-паст в тикет провайдеру).

Что делает:
  1. sample_once()        — один тик замера (cron */N мин):
       • локальная нода: /proc/stat (агрегат + per-core) + /proc/loadavg;
         дельта от прошлого тика → %steal/%busy/%iowait + boot-avg с бута;
       • peers (каскад, tg_bot.json→cascade_peers + extra_peers из конфига):
         тот же замер по SSH (BatchMode, ключ) + hostname peer'а, ошибки
         пишутся как err-сэмпл;
       • идентичность ноды (label · IP · hostname) пишется в каждый сэмпл
         и показывается в отчёте — видно, КТО именно, а не «local (vmNNN)»;
       • мгновенный алерт в TG при N сэмплах подряд ≥ crit_peak (anti-spam
         cooldown), событие "steal_alert".
  2. send_daily_report()  — дневной отчёт (cron H:M, по умолчанию 23:50):
       • шапка: монитор-нода (label · IP · hostname) + сводка флота с
         ярлыками нод: «Флот: 🔴 1 (NL) | 🟢 5 (RU-1, RU-2, ...)»;
       • per-node: «NL · 203.0.113.30 · vm134610 — КРИТИЧНО — есть
         проблемы», avg/p95/пик, busy, per-core разброс (SMT-сосед),
         boot-avg, украденная доля желаемого CPU (oversubscription),
         часовая динамика;
       • классификация НОРМА/ВНИМАНИЕ/КРИТИЧНО по порогам (настраиваются);
       • рекомендации «делать/не делать» по уровню;
       • развёрнутый черновик тикета провайдеру НА РУССКОМ (для КРИТИЧНО —
         требование миграции с доказательствами; для ВНИМАНИЕ — вежливая
         просьба проверить физхост) — копи-паст целиком;
       • копия отчёта: reports/YYYY-MM-DD.txt (вложение в тикет);
       • событие "steal_report"; чистка samples/reports старше retention.
  3. live_measure()       — быстрый замер (6 сек, 3 чтения) для меню.
  4. do_steal_monitor_menu() — TUI-меню (Диагностика и Мониторинг → ST):
       установка/удаление cron, интервал, время отчёта, пороги, состав
       отчёта, локальная нода + peers, замер сейчас, отчёт сейчас,
       история за 7 дней, конфиг.

Файлы:
  /var/lib/xray-installer/steal-monitor.json     — конфиг
  /var/lib/xray-installer/steal-monitor/         — данные
      samples/YYYY-MM-DD.jsonl                    — сэмплы (1 строка/тик/нода)
      reports/YYYY-MM-DD.txt                      — копии дневных отчётов
      prev.json                                   — прошлые счётчики (дельты)
      tg-state.json                               — стрики/кулдауны алертов
  /etc/cron.d/steal-monitor                       — sampler */N + отчёт H:M
  /usr/local/bin/steal-sample.sh, steal-report.sh — PYTHONPATH-safe wrappers
  /var/log/steal-monitor.log                      — лог

Публичный API:
    sample_once(verbose)          → dict         — один тик замера
    send_daily_report(date, tg)   → str          — дневной отчёт (+TG)
    build_report(date)            → str          — отчёт без отправки
    live_measure(dur, step)       → dict         — быстрый замер
    install_steal_monitor(cfg)    → (bool, str)  — cron + wrappers
    uninstall_steal_monitor()     → (bool, str)
    is_monitor_installed()        → bool
    load_config() / save_config() → dict / None
    classify_day(stats, thr)      → (str, list)  — ok|warn|crit|data
    _local_identity(cfg)          → dict         — label/ip/hostname ноды
    do_steal_monitor_menu()       → None         — TUI

Модуль standalone (без _core на уровне импорта — паттерн node_health_monitor):
cron-пути не тянут ядро; _core импортируется лениво только в меню.
TG-отправка — curl по telegram.json с events-фильтром (паттерн b4_monitor:
отсутствующий ключ events = событие ВКЛ).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# ── Пути (могут патчиться в тестах) ──────────────────────────────────────────
BASE_DIR      = Path("/var/lib/xray-installer/steal-monitor")
CONFIG_FILE   = Path("/var/lib/xray-installer/steal-monitor.json")
SAMPLES_DIR   = BASE_DIR / "samples"
REPORTS_DIR   = BASE_DIR / "reports"
PREV_FILE     = BASE_DIR / "prev.json"
TG_STATE_FILE = BASE_DIR / "tg-state.json"
LOG_FILE      = Path("/var/log/steal-monitor.log")
CRON_FILE     = Path("/etc/cron.d/steal-monitor")
SAMPLE_SCRIPT = Path("/usr/local/bin/steal-sample.sh")
REPORT_SCRIPT = Path("/usr/local/bin/steal-report.sh")
TG_CONFIG     = Path("/var/lib/xray-installer/telegram.json")
TG_BOT_CFG    = Path("/var/lib/xray-installer/tg_bot.json")

# ── Константы ────────────────────────────────────────────────────────────────
DEFAULT_INTERVAL_MIN   = 5      # минут между замерами
DEFAULT_REPORT_HOUR    = 23     # время дневного отчёта
DEFAULT_REPORT_MINUTE  = 50
TG_TIMEOUT             = 10     # сек
SSH_TIMEOUT            = 12     # сек на peer
MIN_SAMPLES_FOR_CLASSIFY = 10   # меньше — «недостаточно данных»
TG_CHUNK_LIMIT         = 3900   # запас до лимита TG 4096
TG_RETRIES = 3         # попыток отправки (DPI-ресет 1-го соединения)
TG_RETRY_PAUSE = 2     # сек между попытками

# Пороги по умолчанию откалиброваны по живому флоту (2026-10):
#   чистые ноды 0.0–0.1% (91, pl1, de) → НОРМА; fi1 avg 3.8/пик 7.7 → ВНИМАНИЕ
#   («тикет нецелесообразен, следить»); nl1 avg 7.9/пик 16/p95 12 → КРИТИЧНО
#   (тикет); 138 avg 20+/пик 60 → КРИТИЧНО (жёсткий тикет/миграция).
DEFAULT_CONFIG: dict = {
    "enabled": True,
    "sample_interval_min": DEFAULT_INTERVAL_MIN,
    "report_hour": DEFAULT_REPORT_HOUR,
    "report_minute": DEFAULT_REPORT_MINUTE,
    "monitor_local": True,
    "monitor_peers": False,          # peers = cascade_peers из tg_bot.json
    "extra_peers": [],               # [{host,user,port,name}] — свой список
    "peer_filter": [],               # [] = все; имена/хосты для выборки
    "peer_timeout_s": SSH_TIMEOUT,
    "node_label": "",                # имя локальной ноды в отчётах (напр. "RU-1");
                                     # пусто = hostname (криптичные vm134610 и т.п.)
    "node_ip": "",                   # публичный IP локальной ноды; пусто = автодетект
    "alerts_enabled": True,          # мгновенные алерты при серии ≥ crit_peak
    "thresholds": {
        "warn_avg": 3.0,             # дневной средний %steal
        "crit_avg": 8.0,
        "warn_peak": 8.0,            # разовый сэмпл
        "crit_peak": 15.0,
        "warn_p95": 5.0,             # 95-й перцентиль сэмплов
        "crit_p95": 10.0,
        "alert_consecutive": 3,      # сэмплов подряд ≥ crit_peak → алерт
        "alert_cooldown_min": 180,   # анти-спам per node
    },
    "report": {
        "include_hourly": True,      # часовая динамика
        "include_percpu": True,      # per-core разброс (SMT-сосед)
        "include_bootavg": True,     # среднее с бута (хроника, не только день)
        "include_recommendations": True,
        "include_ticket_block": True,  # блок доказательств для тикета
    },
    "retention_days": 30,
    "tg_retries": 3,      # попыток отправки TG (1-я часто reset по DPI)
}


# ══════════════════════════════════════════════════════════════════════════════
#  Мелкие хелперы
# ══════════════════════════════════════════════════════════════════════════════

def _log(msg: str) -> None:
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except Exception:
        pass


def _run(cmd: list, timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _hostname() -> str:
    try:
        return _run(["hostname", "-s"]).stdout.strip() or "server"
    except Exception:
        return "server"


def _is_private_ip(ip: str) -> bool:
    """Внутренний/не-маршрутизируемый адрес (NAT/link-local/loopback)."""
    if not ip or ip.count(".") != 3:
        return True  # не IPv4 (в т.ч. IPv6 ULA) — как «частный» не показываем
    try:
        a, b, _c, _d = (int(x) for x in ip.split("."))
    except ValueError:
        return True
    return (a == 10 or a == 127 or a == 0
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or (a == 169 and b == 254))


def _detect_local_ip() -> str:
    """Публичный IP локальной ноды без внешних сервисов.

    Порядок: src из `ip route get` (адрес исходящего интерфейса) →
    hostname -I (первый не-внутренний) → "". Внешние IP-эхо-сервисы
    сознательно не используем: из РФ они часто недоступны/медленны,
    а замер идёт по cron каждые 5 минут.
    """
    try:
        r = _run(["ip", "-4", "route", "get", "1.1.1.1"], timeout=6)
        toks = (r.stdout or "").split()
        if "src" in toks:
            ip = toks[toks.index("src") + 1]
            if ip and not _is_private_ip(ip):
                return ip
    except Exception:
        pass
    try:
        r = _run(["hostname", "-I"], timeout=6)
        for ip in (r.stdout or "").split():
            if not _is_private_ip(ip):
                return ip
    except Exception:
        pass
    return ""


def _local_identity(cfg: Optional[dict] = None) -> dict:
    """Идентичность локальной ноды для отчётов/алертов.

    {"label", "ip", "hostname"}: label из конфига (node_label, напр. "RU-1")
    или hostname; ip из конфига (node_ip) или автодетект. Именно эти три
    значения показываются в шапке отчёта и заголовке блока каждой ноды —
    чтобы по отчёту было сразу видно, КТО это (а не «local (vm134610)»).
    """
    cfg = cfg or load_config()
    hostname = _hostname()
    label = str(cfg.get("node_label") or "").strip() or hostname
    ip = str(cfg.get("node_ip") or "").strip() or _detect_local_ip()
    return {"label": label, "ip": ip, "hostname": hostname}


def _peer_identity(peer: dict, ssh_hostname: Optional[str] = None) -> dict:
    """Идентичность peer-ноды: label = имя из конфига, ip = host."""
    name = str(peer.get("name") or peer.get("host") or "?")
    host = str(peer.get("host") or "")
    return {"label": name, "ip": host, "hostname": ssh_hostname or ""}


def _deep_merge(base: dict, override: dict) -> dict:
    """Рекурсивный merge (override поверх base) — для конфига."""
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


# ══════════════════════════════════════════════════════════════════════════════
#  Конфиг
# ══════════════════════════════════════════════════════════════════════════════

def load_config() -> dict:
    """Конфиг с дефолтами; файл отсутствует/битый → дефолты."""
    try:
        if CONFIG_FILE.exists():
            user = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            if isinstance(user, dict):
                return _deep_merge(DEFAULT_CONFIG, user)
    except Exception as e:
        _log(f"config read error: {e}")
    return json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy


def save_config(cfg: dict) -> None:
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False),
                           encoding="utf-8")
    try:
        CONFIG_FILE.chmod(0o600)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  /proc/stat — парсинг и дельты
# ══════════════════════════════════════════════════════════════════════════════

def read_proc_stat(text: Optional[str] = None) -> Optional[dict]:
    """Парсит /proc/stat.

    Возвращает {"cpu": [8 ints], "percpu": [[8 ints], ...]} по первым 8 полям
    (user nice system idle iowait irq softirq steal) — семантика sar/top:
    guest уже внутри user/nice, отдельно не суммируем.
    """
    if text is None:
        try:
            text = Path("/proc/stat").read_text(encoding="utf-8")
        except Exception:
            return None
    cpu = None
    percpu: list = []
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "cpu" and cpu is None:
            try:
                cpu = [int(x) for x in parts[1:9]]
            except ValueError:
                return None
        elif parts[0].startswith("cpu") and parts[0][3:].isdigit():
            try:
                percpu.append([int(x) for x in parts[1:9]])
            except ValueError:
                continue
    if cpu is None:
        return None
    return {"cpu": cpu, "percpu": percpu}


def _ticks_busy(c: list) -> int:
    # user nice system irq softirq (+iowait учитываем в idle-пуле, как top)
    return c[0] + c[1] + c[2] + c[5] + c[6]


def _ticks_idle(c: list) -> int:
    return c[3] + c[4]


def _ticks_total(c: list) -> int:
    return _ticks_busy(c) + _ticks_idle(c) + c[7]


def compute_deltas(prev: Optional[dict], cur: dict) -> Optional[dict]:
    """Дельты между двумя замерами /proc/stat → проценты + тики.

    Возвращает {steal, busy, iowait, steal_t, busy_t, total_t} или None
    (нет prev / счётчики сброшены — ребут, wrap).
    """
    if not prev or "cpu" not in prev:
        return None
    p, c = prev["cpu"], cur["cpu"]
    total_d = _ticks_total(c) - _ticks_total(p)
    steal_d = c[7] - p[7]
    busy_d  = _ticks_busy(c) - _ticks_busy(p)
    iowait_d = c[4] - p[4]
    if total_d <= 0 or steal_d < 0 or busy_d < 0 or iowait_d < 0:
        return None  # ребут/сброс счётчиков — сэмпл пропускаем
    return {
        "steal":   round(100.0 * steal_d / total_d, 2),
        "busy":    round(100.0 * busy_d / total_d, 2),
        "iowait":  round(100.0 * iowait_d / total_d, 2),
        "steal_t": steal_d,
        "busy_t":  busy_d,
        "total_t": total_d,
    }


def percpu_steal(prev: Optional[dict], cur: dict) -> Optional[list]:
    """%steal по каждому ядру (дельта) — разброс = след SMT-соседа."""
    if not prev or not prev.get("percpu") or not cur.get("percpu"):
        return None
    if len(prev["percpu"]) != len(cur["percpu"]):
        return None
    out = []
    for p, c in zip(prev["percpu"], cur["percpu"]):
        t = _ticks_total(c) - _ticks_total(p)
        s = c[7] - p[7]
        if t <= 0 or s < 0:
            return None
        out.append(round(100.0 * s / t, 1))
    return out


def boot_averages(cur: dict) -> tuple:
    """Средние %steal/%busy с момента бута (кумулятивные счётчики).

    Это «хроника» — доказательство, что оверселл не разовый: гипервизор
    забирал CPU и в простой (см. кейс 138: steal с бута 20% при busy 13%).
    """
    c = cur["cpu"]
    total = _ticks_total(c)
    if total <= 0:
        return (0.0, 0.0)
    steal = round(100.0 * c[7] / total, 2)
    busy  = round(100.0 * _ticks_busy(c) / total, 2)
    return (steal, busy)


def read_loadavg(text: Optional[str] = None) -> Optional[float]:
    """loadavg 1min (локально или из вывода peers)."""
    if text is None:
        try:
            text = Path("/proc/loadavg").read_text(encoding="utf-8")
        except Exception:
            return None
    try:
        return round(float(text.split()[0]), 2)
    except (ValueError, IndexError):
        return None


def read_uptime(text: Optional[str] = None) -> Optional[float]:
    if text is None:
        try:
            text = Path("/proc/uptime").read_text(encoding="utf-8")
        except Exception:
            return None
    try:
        return round(float(text.split()[0]), 0)
    except (ValueError, IndexError):
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  Peers (SSH-семплинг каскада)
# ══════════════════════════════════════════════════════════════════════════════

def _load_peers(cfg: dict) -> list:
    """Список peers для SSH-замеров.

    Источники: tg_bot.json → cascade_peers (host/user/port/name/sudo — тот же
    список, которым TG-бот делает /status) + cfg['extra_peers']. Фильтр
    cfg['peer_filter'] (имя или хост, [] = все). Дедуп по host:port.
    """
    peers: list = []
    try:
        if TG_BOT_CFG.exists():
            bot = json.loads(TG_BOT_CFG.read_text(encoding="utf-8"))
            for p in bot.get("cascade_peers", []) or []:
                if isinstance(p, dict) and p.get("host"):
                    peers.append(p)
    except Exception:
        pass
    for p in cfg.get("extra_peers", []) or []:
        if isinstance(p, dict) and p.get("host"):
            peers.append(p)
    flt = [str(x).lower() for x in (cfg.get("peer_filter") or [])]
    if flt:
        peers = [p for p in peers
                 if str(p.get("name", "")).lower() in flt
                 or str(p.get("host", "")).lower() in flt]
    seen, out = set(), []
    for p in peers:
        key = f"{str(p.get('host','')).lower()}:{int(p.get('port', 22))}"
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def _ssh_proc_stat(peer: dict, timeout: int = SSH_TIMEOUT) -> Optional[dict]:
    """Замер /proc/stat + /proc/loadavg + /proc/uptime + hostname на peer.

    BatchMode (только ключ) — пароли не поддерживаем, как и везде в Chimera.
    /proc читается всеми — sudo не нужен. Hostname берём маркер-строкой
    (___HOSTNAME___...) для отчёта: «название машины» peer-ноды.
    """
    host = peer.get("host", "")
    if not host:
        return None
    user = peer.get("user", "root") or "root"
    port = int(peer.get("port", 22) or 22)
    target = f"{user}@{host}" if user != "root" else host
    cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=%d" % timeout,
        "-p", str(port),
        target,
        "cat /proc/stat /proc/loadavg /proc/uptime; "
        "echo ___HOSTNAME___$(hostname -s)",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 8)
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None
    if r.returncode != 0:
        return None
    out = (r.stdout or "")
    # маркер hostname вынимаем до общего парсинга
    hostname = None
    kept: list = []
    for ln in out.splitlines():
        if ln.startswith("___HOSTNAME___"):
            hostname = ln[len("___HOSTNAME___"):].strip() or None
        else:
            kept.append(ln)
    stat_lines = [ln for ln in kept if ln.startswith("cpu")]
    rest = [ln.strip() for ln in kept
            if ln.strip() and not ln.strip().startswith("cpu")]
    # хвост cat'а: /proc/stat после cpu-строк содержит intr/ctxt, а loadavg
    # и uptime — в самом конце. Берём с конца, иначе load1 парсится из intr.
    loadavg = read_loadavg(rest[-2]) if len(rest) >= 2 else None
    uptime = read_uptime(rest[-1]) if rest else None
    st = read_proc_stat("\n".join(stat_lines))
    if st is None:
        return None
    return {"stat": st, "load1": loadavg, "uptime_s": uptime,
            "hostname": hostname}


# ══════════════════════════════════════════════════════════════════════════════
#  Хранилище сэмплов (JSONL per день)
# ══════════════════════════════════════════════════════════════════════════════

def _samples_path(date: Optional[str] = None) -> Path:
    d = date or datetime.now().strftime("%Y-%m-%d")
    return SAMPLES_DIR / f"{d}.jsonl"


def _append_sample(rec: dict, date: Optional[str] = None) -> None:
    p = _samples_path(date)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def read_samples(date: Optional[str] = None) -> list:
    """Сэмплы дня: [{'ts','node','host','ok',...}, ...]; битые строки скипаем."""
    p = _samples_path(date)
    out = []
    if not p.exists():
        return out
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except Exception:
        return []
    return out


def _load_prev() -> dict:
    try:
        if PREV_FILE.exists():
            d = json.loads(PREV_FILE.read_text(encoding="utf-8"))
            if isinstance(d, dict):
                return d
    except Exception:
        pass
    return {}


def _save_prev(st: dict) -> None:
    try:
        PREV_FILE.parent.mkdir(parents=True, exist_ok=True)
        PREV_FILE.write_text(json.dumps(st, ensure_ascii=False),
                             encoding="utf-8")
    except Exception as e:
        _log(f"prev save error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  Telegram (events-aware, паттерн b4_monitor)
# ══════════════════════════════════════════════════════════════════════════════

def _split_tg_chunks(msg: str, limit: int = TG_CHUNK_LIMIT) -> list:
    """Делит сообщение на чанки ≤ limit, разрезая ПО ГРАНИЦА СТРОК.

    Хард-рез посимвольно мог разрезать тикет-черновик или HTML-тег
    посередине. Строку без переносов длиннее limit режем жёстко (некуда).
    """
    if len(msg) <= limit:
        return [msg]
    chunks: list = []
    cur = ""
    for line in msg.split("\n"):
        while len(line) > limit:          # гигантская строка без переносов
            chunks.append(line[:limit])
            line = line[limit:]
        if cur and len(cur) + 1 + len(line) > limit:
            chunks.append(cur)
            cur = line
        else:
            cur = f"{cur}\n{line}" if cur else line
    if cur:
        chunks.append(cur)
    return chunks or [msg]


def _tg_send(msg: str, event: str = "") -> bool:
    """Отправка в TG: events-фильтр, чанки (по строкам), ретраи.

    Ретраи нужны: на части сетей (RU-транзит) первое TLS-соединение к
    api.telegram.org сбрасывается DPI, повтор проходит (замерено на 45:
    попытка 1 — reset, попытка 2 — 200 за 0.3с). Число попыток —
    cfg["tg_retries"] из steal-monitor.json (1..5, дефолт TG_RETRIES).
    """
    try:
        if not TG_CONFIG.exists():
            return False
        cfg = json.loads(TG_CONFIG.read_text(encoding="utf-8"))
        token, chat = cfg.get("token", ""), cfg.get("chat_id", "")
        if not token or not chat:
            return False
        if event and not cfg.get("events", {}).get(event, True):
            return False
        try:
            retries = max(1, min(5, int(load_config().get("tg_retries",
                                                         TG_RETRIES))))
        except Exception:
            retries = TG_RETRIES
        chunks = _split_tg_chunks(msg)
        all_ok = True
        for c in chunks:
            ok_chunk = False
            for attempt in range(1, retries + 1):
                r = _run([
                    "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                    "-m", str(TG_TIMEOUT),
                    f"https://api.telegram.org/bot{token}/sendMessage",
                    "-d", f"chat_id={chat}",
                    "-d", f"text={c}",
                    "-d", "parse_mode=HTML",
                ], timeout=TG_TIMEOUT + 5)
                code = (r.stdout or "").strip()
                if code == "200":
                    ok_chunk = True
                    break
                _log(f"tg send: попытка {attempt}/{retries} — код "
                     f"{code or 'нет ответа'}")
                if attempt < retries:
                    time.sleep(TG_RETRY_PAUSE)
            all_ok = all_ok and ok_chunk
        return all_ok
    except Exception:
        return False

def _load_tg_state() -> dict:
    try:
        if TG_STATE_FILE.exists():
            d = json.loads(TG_STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(d, dict):
                return d
    except Exception:
        pass
    return {"nodes": {}}


def _save_tg_state(st: dict) -> None:
    try:
        TG_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        TG_STATE_FILE.write_text(json.dumps(st, ensure_ascii=False),
                                 encoding="utf-8")
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  Алерты (серия ≥ crit_peak подряд, cooldown per node)
# ══════════════════════════════════════════════════════════════════════════════

def _alert_check(node: str, host: str, steal: Optional[float],
                 cfg: dict, tgst: dict, ip: Optional[str] = None) -> Optional[str]:
    """Обновляет стрик; возвращает текст алерта или None.

    steal=None (ошибка замера) сбрасывает стрик — данные с дыркой не считаем
    серией. Алерт: streak >= alert_consecutive и прошёл cooldown.
    ip — публичный IP ноды (если известен), показывается в алерте вместо
    криптичного hostname.
    """
    thr = cfg.get("thresholds", {})
    nodes = tgst.setdefault("nodes", {})
    ns = nodes.get(node, {})
    crit_peak = float(thr.get("crit_peak", 15.0))
    consec = int(thr.get("alert_consecutive", 3))
    cooldown = float(thr.get("alert_cooldown_min", 180)) * 60.0
    now = time.time()

    if steal is None:
        ns["crit_streak"] = 0
        nodes[node] = ns
        return None
    if steal < crit_peak:
        ns["crit_streak"] = 0
        nodes[node] = ns
        return None

    ns["crit_streak"] = int(ns.get("crit_streak", 0)) + 1
    nodes[node] = ns
    if ns["crit_streak"] < consec:
        return None
    if now - float(ns.get("last_alert_ts", 0)) < cooldown:
        return None

    ns["last_alert_ts"] = now
    ns["crit_streak"] = 0  # после алерта — заново копить серию
    nodes[node] = ns
    ts = datetime.now().strftime("%d.%m.%Y %H:%M")
    return (
        f"🚨 <b>[{_local_identity(cfg)['label']}] CPU Steal критический</b>\n"
        f"🔴 <b>{node}</b> (<code>{ip or host}</code>): "
        f"steal <b>{steal:.1f}%</b> — {consec} замера подряд ≥ {crit_peak:.0f}%\n"
        f"<i>{ts}</i>\n\n"
        f"Дневной отчёт и доказательства: Диагностика → CPU Steal монитор.\n"
        f"Полные данные: <code>{BASE_DIR}</code>"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  Главный тик — sample_once()
# ══════════════════════════════════════════════════════════════════════════════

def _record_node_sample(node: str, host: str, cur: dict, load1: Optional[float],
                        uptime_s: Optional[float], prev_store: dict,
                        cfg: dict, tgst: dict, alerts: list,
                        ident: Optional[dict] = None) -> Optional[dict]:
    """Дельта против prev → сэмпл в JSONL (+алерт-проверка). Возвращает сэмпл.

    ident ("label"/"ip"/"hostname") пишется в сэмпл — отчёт показывает ноду
    как «RU-1 · 203.0.113.10 · srv-ru1», а не «local (vm134610)».
    """
    prev = prev_store.get(node)
    d = compute_deltas(prev, cur)
    per = percpu_steal(prev, cur)
    boot_steal, boot_busy = boot_averages(cur)
    ts = time.time()

    # prev обновляем ВСЕГДА (даже если дельта не посчиталась — ребут)
    prev_store[node] = {"ts": ts, "cpu": cur["cpu"], "percpu": cur["percpu"]}

    if d is None:
        return None  # первый замер или сброс счётчиков — только запомнили

    rec = {
        "ts": ts,
        "node": node,
        "host": host,
        "ok": True,
        "steal": d["steal"],
        "busy": d["busy"],
        "iowait": d["iowait"],
        "steal_t": d["steal_t"],
        "busy_t": d["busy_t"],
        "total_t": d["total_t"],
        "load1": load1,
        "ncpu": len(cur.get("percpu") or []),
        "boot_steal": boot_steal,
        "boot_busy": boot_busy,
        "uptime_s": uptime_s,
    }
    if ident:
        for k in ("label", "ip", "hostname"):
            if ident.get(k):
                rec[k] = ident[k]
    if per is not None:
        rec["core_max"] = max(per)
        rec["core_min"] = min(per)
    _append_sample(rec)

    if cfg.get("alerts_enabled", True):
        msg = _alert_check(node, host, d["steal"], cfg, tgst,
                           ip=(ident or {}).get("ip"))
        if msg:
            alerts.append(msg)
    return rec


def sample_once(verbose: bool = False) -> dict:
    """Один тик замера: локальная нода (+peers, если включены).

    Вызывается cron'ом каждые N минут. Возвращает сводку:
    {"local": {...}|None, "peers": [...], "alerts": [...]}.
    """
    cfg = load_config()
    prev_store = _load_prev()
    tgst = _load_tg_state()
    alerts: list = []
    result = {"local": None, "peers": [], "alerts": alerts}
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── локальная нода ────────────────────────────────────────────────────
    if cfg.get("monitor_local", True):
        cur = read_proc_stat()
        if cur is None:
            _log(f"{ts} sample: /proc/stat unreadable")
        else:
            ident = _local_identity(cfg)
            rec = _record_node_sample(
                "local", _hostname(), cur,
                read_loadavg(), read_uptime(),
                prev_store, cfg, tgst, alerts, ident=ident)
            result["local"] = rec

    # ── peers по SSH ──────────────────────────────────────────────────────
    if cfg.get("monitor_peers", False):
        for peer in _load_peers(cfg):
            name = str(peer.get("name") or peer.get("host", "?"))
            host = str(peer.get("host", "?"))
            timeout = int(cfg.get("peer_timeout_s", SSH_TIMEOUT))
            got = _ssh_proc_stat(peer, timeout)
            if got is None:
                _append_sample({"ts": time.time(), "node": name, "host": host,
                                "ok": False, "err": "ssh failed"})
                result["peers"].append({"node": name, "host": host, "ok": False})
                # ошибка = дырка в данных → стрик сброс
                _alert_check(name, host, None, cfg, tgst)
                if verbose:
                    print(f"  {name}: SSH FAIL")
                continue
            rec = _record_node_sample(
                name, host, got["stat"], got["load1"], got["uptime_s"],
                prev_store, cfg, tgst, alerts,
                ident=_peer_identity(peer, got.get("hostname")))
            result["peers"].append(rec or {"node": name, "host": host,
                                           "ok": False, "err": "no delta"})
            if verbose and rec:
                print(f"  {name}: steal {rec['steal']:.1f}% busy {rec['busy']:.1f}%")

    _save_prev(prev_store)
    _save_tg_state(tgst)

    for msg in alerts:
        if _tg_send(msg, "steal_alert"):
            _log(f"{ts} ALERT sent (see text)")
        else:
            _log(f"{ts} ALERT tg send FAILED (events gate or no config)")

    if verbose and result["local"]:
        r = result["local"]
        print(f"  local: steal {r['steal']:.1f}% busy {r['busy']:.1f}% "
              f"iowait {r['iowait']:.1f}%")
    _log(f"{ts} sample ok"
         + (f" local={result['local']['steal']}%" if result.get("local") else " local=skip")
         + (f" peers={len(result['peers'])}" if result["peers"] else ""))
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  Статистика дня и классификация
# ══════════════════════════════════════════════════════════════════════════════

def _p95(values: list) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = max(0, min(len(s) - 1, int(round(0.95 * (len(s) + 1))) - 1))
    return s[idx]


def compute_stats(samples: list) -> dict:
    """Статистика по сэмплам одной ноды за день."""
    ok = [s for s in samples if s.get("ok") and isinstance(s.get("steal"), (int, float))]
    st = {
        "n_total": len(samples),
        "n_ok": len(ok),
        "n_err": len(samples) - len(ok),
        "avg": 0.0, "p95": 0.0, "peak": 0.0, "peak_ts": None,
        "busy_avg": 0.0, "iowait_avg": 0.0, "load_max": None,
        "core_max": None, "core_min": None,
        "boot_steal": None, "boot_busy": None, "uptime_s": None,
        "steal_t": 0, "busy_t": 0, "hourly": {},
        "smt_spread": False,
    }
    if not ok:
        return st
    steals = [float(s["steal"]) for s in ok]
    st["avg"] = round(sum(steals) / len(steals), 2)
    st["p95"] = round(_p95(steals), 2)
    peak_i = max(range(len(steals)), key=lambda i: steals[i])
    st["peak"] = steals[peak_i]
    st["peak_ts"] = ok[peak_i].get("ts")
    st["busy_avg"] = round(sum(float(s.get("busy", 0)) for s in ok) / len(ok), 2)
    st["iowait_avg"] = round(sum(float(s.get("iowait", 0)) for s in ok) / len(ok), 2)
    loads = [s.get("load1") for s in ok if isinstance(s.get("load1"), (int, float))]
    st["load_max"] = max(loads) if loads else None
    cmax = [s.get("core_max") for s in ok if isinstance(s.get("core_max"), (int, float))]
    cmin = [s.get("core_min") for s in ok if isinstance(s.get("core_min"), (int, float))]
    if cmax:
        st["core_max"] = max(cmax)
        st["core_min"] = min(cmin)
        st["smt_spread"] = (st["core_max"] - st["core_min"]) >= 15.0
    last = ok[-1]
    st["boot_steal"] = last.get("boot_steal")
    st["boot_busy"] = last.get("boot_busy")
    st["uptime_s"] = last.get("uptime_s")
    st["steal_t"] = sum(int(s.get("steal_t", 0)) for s in ok)
    st["busy_t"] = sum(int(s.get("busy_t", 0)) for s in ok)
    # часовые корзины (локальное время ноды-монитора)
    hourly: dict = {}
    for s in ok:
        h = datetime.fromtimestamp(float(s.get("ts", 0))).strftime("%H")
        v = hourly.setdefault(h, [0.0, 0])
        v[0] += float(s["steal"])
        v[1] += 1
    st["hourly"] = {h: (round(v[0] / v[1], 1), v[1]) for h, v in sorted(hourly.items())}
    # доля желаемого CPU, которую забрал гипервизор (served/desired методика)
    desired = st["steal_t"] + st["busy_t"]
    st["stolen_share"] = round(100.0 * st["steal_t"] / desired, 1) if desired > 0 else 0.0
    return st


def classify_day(stats: dict, thr: dict) -> tuple:
    """(level, reasons): level ∈ ok|warn|crit|data.

    Пороги дефолтов откалиброваны по флоту (см. DEFAULT_CONFIG): чистые
    хостеры 0–0.1% → ok; fi1-уровень 3–8% → warn («следить»); nl1/138
    (avg 8–20+%, пик 15–60%) → crit (тикет/миграция).
    """
    reasons = []
    if stats.get("n_ok", 0) < MIN_SAMPLES_FOR_CLASSIFY:
        return "data", [f"сэмплов {stats.get('n_ok', 0)} < {MIN_SAMPLES_FOR_CLASSIFY}"]
    avg, peak, p95 = stats["avg"], stats["peak"], stats["p95"]
    is_crit = (avg >= thr.get("crit_avg", 8.0)
               or peak >= thr.get("crit_peak", 15.0)
               or p95 >= thr.get("crit_p95", 10.0))
    is_warn = (avg >= thr.get("warn_avg", 3.0)
               or peak >= thr.get("warn_peak", 8.0)
               or p95 >= thr.get("warn_p95", 5.0))
    if avg >= thr.get("crit_avg", 8.0):
        reasons.append(f"avg {avg:.1f}% ≥ crit {thr.get('crit_avg', 8.0):.0f}%")
    elif avg >= thr.get("warn_avg", 3.0):
        reasons.append(f"avg {avg:.1f}% ≥ warn {thr.get('warn_avg', 3.0):.0f}%")
    if peak >= thr.get("crit_peak", 15.0):
        reasons.append(f"пик {peak:.1f}% ≥ crit {thr.get('crit_peak', 15.0):.0f}%")
    elif peak >= thr.get("warn_peak", 8.0):
        reasons.append(f"пик {peak:.1f}% ≥ warn {thr.get('warn_peak', 8.0):.0f}%")
    if p95 >= thr.get("crit_p95", 10.0):
        reasons.append(f"p95 {p95:.1f}% ≥ crit {thr.get('crit_p95', 10.0):.0f}%")
    elif p95 >= thr.get("warn_p95", 5.0):
        reasons.append(f"p95 {p95:.1f}% ≥ warn {thr.get('warn_p95', 5.0):.0f}%")
    if is_crit:
        return "crit", reasons
    if is_warn:
        return "warn", reasons or ["пограничные значения"]
    return "ok", []

# ══════════════════════════════════════════════════════════════════════════════
#  Рекомендации (экспертные, из практики разбора флота 2026-10)
# ══════════════════════════════════════════════════════════════════════════════

def recommendations(level: str, stats: dict) -> list:
    """Список рекомендаций «делать/не делать» по уровню.

    Калибровка на живых кейсах: 138 (Hoster-A, steal 20-60%) — AWG-каскад
    с двойным шифрованием душится всегда, Mieru/TCP-relay терпит; nl1
    (hoster-b) — тикет с аргументом «соседние VM того же провайдера чистые»;
    fi1 (3.8%) — наблюдение, тикет нецелесообразен.
    """
    if level == "data":
        return ["Данных мало: подождите накопления сэмплов (минимум "
                f"{MIN_SAMPLES_FOR_CLASSIFY} замеров) — после этого появится "
                "классификация."]
    out = []
    if level == "ok":
        out.append("✅ Гипервизор ноду не душит — CPU-ресурс предсказуем.")
        out.append("Можно: CPU-зависимые роли (AWG-каскад/двойное шифрование, "
                   "TLS-терминация, сжатие), пиковые нагрузки.")
        return out
    if level == "warn":
        out.append("⚠️ Лёгкий оверселл. Наблюдать 2–3 суток: устойчивый дневной "
                   "паттерн = шумные соседи на физхосте.")
        out.append("Скоростные роли (AWG-плечи) в пиковые часы лучше держать "
                   "на чистых нодах; эта — под TCP-relay (Mieru) и штатный трафик.")
        if stats.get("smt_spread"):
            out.append(f"Per-core разброс (max {stats.get('core_max')}% / "
                       f"min {stats.get('core_min')}%) — похоже на соседа на "
                       "SMT-сиблинге: упомянуть в тикете.")
        out.append("Если avg держится >5% несколько суток — собрать историю "
                   "( sar -u ) и готовить вежливый тикет провайдеру.")
        return out
    # crit
    share = stats.get("stolen_share", 0.0)
    out.append(f"🚫 Хронический оверселл: гипервизор забирает ~{share:.0f}% "
               "желаемого CPU. Нода получает лишь "
               f"~{100 - share:.0f}% оплаченного.")
    out.append("НЕ размещать на этой ноде: AWG-каскад (шифрование ×2 — "
               "просадка скорости гарантирована), TLS-heavy роли, пиковые "
               "нагрузки. Терпимо: TCP-relay (Mieru), лёгкий трафик.")
    out.append("Открыть тикет провайдеру: приложить отчёт (файл ниже) и "
               "выгрузку sar -u; требовать МИГРАЦИЮ на неперегруженный "
               "физхост, НЕ ребут.")
    out.append("Ребут — не решение: счётчики с бута (boot-avg) доказывают "
               "хронику. Если у провайдера есть «чистые» же VM — приложить "
               "их цифры как аргумент (разница >10x = виноват физхост).")
    out.append("Нет реакции 3–5 дней — миграция на другого хостера: деплой "
               "Chimera скриптованный, воспроизводим за ~час.")
    if stats.get("smt_spread"):
        out.append(f"Per-core разброс {stats.get('core_max')}%/"
                   f"{stats.get('core_min')}% — vCPU спрессованы в треди "
                   "(SMT): попросить выделенные физические ядра.")
    return out


# ══════════════════════════════════════════════════════════════════════════════
#  Сборка отчёта
# ══════════════════════════════════════════════════════════════════════════════

_LEVEL_ICON = {"ok": "🟢", "warn": "🟡", "crit": "🔴", "data": "⚪️"}
_LEVEL_NAME = {"ok": "НОРМА", "warn": "ВНИМАНИЕ", "crit": "КРИТИЧНО",
               "data": "МАЛО ДАННЫХ"}
# Человекочитаемое пояснение статуса (запрос юзера: «есть проблемы —
# критично, нет проблем — норма, внимание — при пограничных состояниях»)
_LEVEL_DESC = {
    "ok": "НОРМА — проблем нет",
    "warn": "ВНИМАНИЕ — пограничное состояние",
    "crit": "КРИТИЧНО — есть проблемы",
    "data": "МАЛО ДАННЫХ",
}


def _display_title(ident: Optional[dict], node: str, host: str) -> str:
    """Заголовок блока ноды: label · IP · hostname (без дублей).

    Примеры: «NL · 203.0.113.30 · vm134610», «RU-2 · 203.0.113.20».
    Старые сэмплы без ident → «local (srv45)» как раньше.
    """
    ident = ident or {}
    label = str(ident.get("label") or "").strip() or node
    ip = str(ident.get("ip") or "").strip()
    hostname = str(ident.get("hostname") or "").strip()
    if not ip and not hostname:
        return f"<b>{label}</b>" + (f" ({host})" if host and host != label else "")
    parts = [f"<b>{label}</b>"]
    if ip and ip != label:
        parts.append(f"<code>{ip}</code>")
    if hostname and hostname != label and hostname != ip:
        parts.append(hostname)
    return " · ".join(parts)


def _fmt_uptime(sec) -> str:
    try:
        d = int(float(sec)) // 86400
        return f"{d}д" if d > 0 else f"{int(float(sec)) // 3600}ч"
    except (TypeError, ValueError):
        return "?"


def _hourly_lines(stats: dict) -> list:
    """Часовая динамика компактно: '00 0.5 01 0.3 ...' по 12 часов в строке."""
    if not stats.get("hourly"):
        return []
    out = []
    items = list(stats["hourly"].items())
    for i in range(0, len(items), 12):
        chunk = items[i:i + 12]
        out.append(" ".join(f"{h}:{v:.1f}" for h, (v, _n) in chunk))
    return out


def _worst_hours(stats: dict, top: int = 3) -> str:
    if not stats.get("hourly"):
        return "—"
    ranked = sorted(stats["hourly"].items(),
                    key=lambda kv: kv[1][0], reverse=True)[:top]
    return ", ".join(f"{h}:00 ({v:.1f}%)" for h, (v, _n) in ranked)


def _node_block(node: str, host: str, stats: dict, level: str, reasons: list,
                cfg: dict, ident: Optional[dict] = None) -> list:
    """HTML-блок одной ноды для дневного отчёта.

    Первая строка — идентификация и статус: «NL · IP · vm134610 —
    КРИТИЧНО — есть проблемы», чтобы по одному взгляду было ясно, КАКАЯ
    нода и что с ней (а не «local (vm134610) — КРИТИЧНО»).
    """
    rep = cfg.get("report", {})
    icon = _LEVEL_ICON[level]
    lines = [f"{icon} {_display_title(ident, node, host)} — "
             f"<b>{_LEVEL_DESC[level]}</b>"]
    if stats.get("n_ok"):
        lines.append(f"avg <b>{stats['avg']:.1f}%</b> | p95 {stats['p95']:.1f}% "
                     f"| пик {stats['peak']:.1f}%"
                     + (f" ({datetime.fromtimestamp(stats['peak_ts']).strftime('%H:%M')})"
                        if stats.get("peak_ts") else ""))
        lines.append(f"busy avg {stats['busy_avg']:.1f}% | load max "
                     f"{stats['load_max'] if stats['load_max'] is not None else '—'} "
                     f"| сэмплов {stats['n_ok']}"
                     + (f" (ошибок {stats['n_err']})" if stats.get("n_err") else ""))
        if rep.get("include_percpu", True) and stats.get("core_max") is not None:
            lines.append(f"per-core: max {stats['core_max']}% / min "
                         f"{stats['core_min']}%"
                         + (" — разброс: SMT-сосед" if stats.get("smt_spread") else ""))
        if rep.get("include_bootavg", True) and stats.get("boot_steal") is not None:
            lines.append(f"boot-avg: steal {stats['boot_steal']:.2f}% / busy "
                         f"{stats['boot_busy']:.1f}% "
                         f"(uptime {_fmt_uptime(stats.get('uptime_s'))})")
        if level in ("warn", "crit"):
            lines.append(f"худшие часы: {_worst_hours(stats)}")
        if stats.get("stolen_share", 0) >= 3.0:
            lines.append(f"гипервизор забрал ~{stats['stolen_share']:.0f}% "
                         "желаемого CPU (за день)")
    else:
        err = stats.get("n_err", 0)
        lines.append("нет данных"
                     + (f" ({err} ошибок замера — SSH?)" if err else ""))
    if reasons:
        lines.append(f"<i>триггеры: {'; '.join(reasons)}</i>")
    if rep.get("include_hourly", True) and stats.get("hourly"):
        for hl in _hourly_lines(stats):
            lines.append(f"<code>{hl}</code>")
    return lines


def _ticket_block(node: str, host: str, stats: dict, level: str,
                  ident: Optional[dict] = None,
                  date_str: Optional[str] = None) -> str:
    """Развёрнутый черновик тикета провайдеру на русском (копи-паст).

    Уровень crit — требование миграции с доказательствами; warn — вежливая
    просьба проверить физхост. Все цифры подставляются из фактов дня:
    avg/p95/пик/пиковое время, boot-avg (хроника), busy (собственная
    загрузка — доказывает невиновность наших нагрузок), stolen_share,
    худшие часы, per-core разброс (SMT), ошибки замера.

    Текст без символов «меньше/больше/амперсанд» — блок уходит в TG-HTML
    внутри <code>.
    """
    if not stats.get("n_ok"):
        return ""
    ident = ident or {}
    label = str(ident.get("label") or "").strip() or node
    ip = str(ident.get("ip") or "").strip() or host
    hostname = str(ident.get("hostname") or "").strip()
    dstr = date_str or datetime.now().strftime("%Y-%m-%d")
    try:
        dhuman = datetime.strptime(dstr, "%Y-%m-%d").strftime("%d.%m.%Y")
    except ValueError:
        dhuman = dstr
    vm = f"IP {ip}" + (f", hostname {hostname}" if hostname else "")
    peak_time = (datetime.fromtimestamp(stats["peak_ts"]).strftime("%H:%M")
                 if stats.get("peak_ts") else "—")

    # ── факты (общие для обоих уровней) ─────────────────────────────────
    facts = [f"• средний %steal за сутки: {stats['avg']:.1f}% "
             f"(собственная загрузка VM — busy {stats['busy_avg']:.1f}%)",
             f"• 95-й перцентиль: {stats['p95']:.1f}%, "
             f"пиковое значение: {stats['peak']:.1f}% в {peak_time}"]
    if stats.get("boot_steal") is not None:
        facts.append(f"• среднее с момента загрузки "
                     f"(uptime {_fmt_uptime(stats.get('uptime_s'))}): "
                     f"{stats['boot_steal']:.2f}% — проблема хроническая, "
                     "не разовый эпизод")
    if stats.get("stolen_share", 0) >= 3.0:
        facts.append(f"• суммарно за сутки гипервизор забрал "
                     f"~{stats['stolen_share']:.0f}% желаемого CPU-времени "
                     "(доля steal в steal+busy)")
    if stats.get("hourly"):
        facts.append(f"• худшие часы: {_worst_hours(stats)}")
    if stats.get("smt_spread"):
        facts.append(f"• разброс по ядрам (per-core): max {stats['core_max']}% "
                     f"при min {stats['core_min']}% — похоже на шумного соседа "
                     "на SMT-сиблинге")
    if stats.get("load_max") is not None:
        facts.append(f"• собственная нагрузка низкая: load max "
                     f"{stats['load_max']} — отнятие CPU не связано с нашими "
                     "процессами")

    L = []
    if level == "crit":
        L.append(f"Тема: Хронический CPU steal (оверселл физического хоста) "
                 f"на VM {label} ({ip}) — требуется миграция на другой хост")
        L.append("")
        L.append("Здравствуйте!")
        L.append("")
        L.append(f"На нашей виртуальной машине ({vm}) мониторинг фиксирует "
                 "хроническое отнятие процессорного времени гипервизором "
                 "(CPU steal, счётчик st ядра Linux в /proc/stat).")
        L.append("")
        L.append(f"Данные за {dhuman} ({stats['n_ok']} замеров, интервал "
                 "несколько минут, ядро Linux /proc/stat):")
        L.extend(facts)
        L.append("")
        L.append("Показатели устойчиво выше нормы: хронический steal при "
                 "низкой собственной загрузке означает перегрузку "
                 "(оверселлинг) физического хоста соседними VM.")
        L.append("")
        L.append("Просим:")
        L.append("1. Проверить загрузку физического хоста, на котором "
                 "размещена наша VM.")
        L.append("2. Перенести (мигрировать) нашу VM на неперегруженный "
                 "физический хост.")
        L.append("")
        L.append("Перезагрузка VM проблему не решает: кумулятивные счётчики "
                 "с момента загрузки (см. выше) подтверждают хронический "
                 "характер. Готовы приложить выгрузку sar -u и данные "
                 "мониторинга за другие дни.")
    else:  # warn — пограничное состояние
        L.append(f"Тема: Повышенный CPU steal на VM {label} ({ip}) — "
                 "просьба проверить загрузку физического хоста")
        L.append("")
        L.append("Здравствуйте!")
        L.append("")
        L.append(f"На нашей виртуальной машине ({vm}) в последние сутки "
                 "наблюдается повышенный CPU steal (отнятие процессорного "
                 "времени гипервизором, счётчик st ядра Linux).")
        L.append("")
        L.append(f"Данные за {dhuman} ({stats['n_ok']} замеров, ядро Linux "
                 "/proc/stat):")
        L.extend(facts)
        L.append("")
        L.append("Показатели пограничные: стабильной деградации ещё нет, но "
                 "хронический характер (особенно среднее с момента загрузки) "
                 "указывает на шумных соседей на физическом хосте.")
        L.append("")
        L.append("Просим проверить загрузку физического хоста и, если "
                 "соседние VM перегружают его, рассмотреть перенос наших "
                 "или их VM. Если показатели сохранятся или вырастут, мы "
                 "вернёмся с просьбой о миграции на менее загруженный хост.")
        L.append("")
        L.append("Готовы приложить выгрузку sar -u и данные мониторинга за "
                 "другие дни.")
    L.append("")
    L.append("Спасибо!")
    return "\n".join(L)


def _fleet_summary_line(node_data: list) -> str:
    """«Флот: 🔴 1 (NL) | 🟡 1 (RU-3) | 🟢 5 (RU-1, RU-2, DE, PL, EE)».

    Ярлыки problem-нод показываем всегда; для ok-нод — если строка не
    разрастается (иначе только счётчик).
    """
    levels: dict = {}
    for _nd, _host, _stats, level, _r, _ident in node_data:
        levels.setdefault(level, []).append((_nd, _ident))
    parts = []
    for level in ("crit", "warn", "ok", "data"):
        if not levels.get(level):
            continue
        entries = levels[level]
        base = f"{_LEVEL_ICON[level]} {len(entries)}"
        labels = [str((ident or {}).get("label") or "").strip() or nd
                  for nd, ident in entries]
        with_labels = base + f" ({', '.join(labels)})"
        if level in ("crit", "warn") or len(with_labels) <= 120:
            parts.append(with_labels)
        else:
            parts.append(base)
    return " | ".join(parts)


def build_report(date: Optional[str] = None) -> str:
    """Дневной отчёт (HTML для TG). Без отправки и без побочных эффектов."""
    cfg = load_config()
    thr = cfg.get("thresholds", {})
    dstr = date or datetime.now().strftime("%Y-%m-%d")
    dhuman = datetime.strptime(dstr, "%Y-%m-%d").strftime("%d.%m.%Y")
    samples = read_samples(dstr)

    # группировка по нодам (порядок: local первым, далее по алфавиту);
    # identity (label/ip/hostname) — из последних сэмплов ноды, для local
    # конфиг (node_label/node_ip) приоритетнее сохранённых значений
    by_node: dict = {}
    for s in samples:
        nd = str(s.get("node", "?"))
        ent = by_node.setdefault(nd, {"host": str(s.get("host", "?")),
                                      "rows": [], "ident": {}})
        ent["rows"].append(s)
        for k in ("label", "ip", "hostname"):
            if s.get(k):
                ent["ident"][k] = s.get(k)
    if "local" in by_node:
        li = _local_identity(cfg)
        by_node["local"]["ident"].update(
            {k: v for k, v in li.items() if v})
    ordered = sorted(by_node.keys(),
                     key=lambda n: (n != "local", n.lower()))

    ident_local = _local_identity(cfg)
    lines = [f"🧟 <b>CPU Steal Report</b> — {dhuman}",
             f"Монитор: {_display_title(ident_local, 'local', _hostname())}"]
    if not ordered:
        lines.append("")
        lines.append("Сэмплов нет — мониторинг не запущен или был выключен весь день.")
        return "\n".join(lines)

    # сводка флота
    node_data = []
    for nd in ordered:
        host = by_node[nd]["host"]
        stats = compute_stats(by_node[nd]["rows"])
        level, reasons = classify_day(stats, thr)
        node_data.append((nd, host, stats, level, reasons, by_node[nd]["ident"]))
    lines.append(f"Флот: {_fleet_summary_line(node_data)}")
    lines.append("")

    rep = cfg.get("report", {})
    for nd, host, stats, level, reasons, ident in node_data:
        lines.extend(_node_block(nd, host, stats, level, reasons, cfg,
                                 ident=ident))
        lines.append("")

    # рекомендации
    if rep.get("include_recommendations", True):
        lines.append("<b>Рекомендации</b>")
        # проблемные ноды всегда; одиночная ok-нода — тоже (подтверждение,
        # что всё чисто); уровень data — только если нода единственная
        single = len(node_data) == 1
        for nd, host, stats, level, reasons, ident in node_data:
            if level not in ("warn", "crit") and not single:
                continue
            short = (str((ident or {}).get("label") or "").strip() or nd)
            ip = str((ident or {}).get("ip") or "").strip()
            lines.append(f"<b>{_LEVEL_ICON[level]} {short}"
                         + (f" ({ip})" if ip else "") + ":</b>")
            for r in recommendations(level, stats):
                lines.append(f"  {r}")
            lines.append("")

    # черновики тикетов (только проблемные/пограничные ноды)
    if rep.get("include_ticket_block", True):
        tb = [(nd, host, stats, level, ident)
              for nd, host, stats, level, _r, ident in node_data
              if level in ("warn", "crit") and stats.get("n_ok")]
        if tb:
            lines.append("<b>🎫 Черновик тикета в поддержку (копи-паст)</b>")
            for nd, host, stats, level, ident in tb:
                short = (str((ident or {}).get("label") or "").strip() or nd)
                ip = str((ident or {}).get("ip") or "").strip() or host
                lines.append(f"— <b>{short}</b> (<code>{ip}</code>) — "
                             f"{_LEVEL_NAME[level]}")
                lines.append(f"<code>{_ticket_block(nd, host, stats, level, ident=ident, date_str=dstr)}</code>")
                lines.append("")

    lines.append(f"<i>Данные: {SAMPLES_DIR}/{dstr}.jsonl | отчёт: "
                 f"{REPORTS_DIR}/{dstr}.txt | пороги: "
                 f"warn {thr.get('warn_avg', 3)}/{thr.get('warn_peak', 8)}% "
                 f"crit {thr.get('crit_avg', 8)}/{thr.get('crit_peak', 15)}%</i>")
    return "\n".join(lines)


def _cleanup_retention(cfg: dict) -> int:
    """Удаляет samples/reports старше retention_days. Возвращает кол-во."""
    days = int(cfg.get("retention_days", 30))
    if days <= 0:
        return 0
    cutoff = datetime.now() - timedelta(days=days)
    removed = 0
    for d in (SAMPLES_DIR, REPORTS_DIR):
        try:
            for p in d.glob("*.jsonl" if d == SAMPLES_DIR else "*.txt"):
                try:
                    stamp = datetime.strptime(p.stem, "%Y-%m-%d")
                except ValueError:
                    continue
                if stamp < cutoff:
                    p.unlink(missing_ok=True)
                    removed += 1
        except Exception:
            continue
    return removed


def send_daily_report(date: Optional[str] = None, send_tg: bool = True) -> str:
    """Собирает дневной отчёт, сохраняет копию, шлёт в TG, чистит retention."""
    cfg = load_config()
    text = build_report(date)
    dstr = date or datetime.now().strftime("%Y-%m-%d")

    # копия отчёта — вложение в тикет (плюс машинный дамп для аудита)
    try:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        (REPORTS_DIR / f"{dstr}.txt").write_text(text, encoding="utf-8")
    except Exception as e:
        _log(f"report save error: {e}")

    removed = _cleanup_retention(cfg)
    if send_tg:
        if _tg_send(text, "steal_report"):
            _log(f"daily report {dstr} sent"
                 + (f" (retention -{removed})" if removed else ""))
        else:
            _log(f"daily report {dstr} TG send FAILED (gate/no config)")
    else:
        _log(f"daily report {dstr} built (no send)")
    return text


# ══════════════════════════════════════════════════════════════════════════════
#  Live-замер (для меню — как ручная диагностика)
# ══════════════════════════════════════════════════════════════════════════════

def live_measure(duration_s: int = 6, step_s: int = 2) -> dict:
    """Несколько коротких интервалов подряд — «что происходит прямо сейчас».

    Возвращает {"intervals": [{steal, busy, iowait, core_max, core_min}],
    "avg_steal": float}. Первый интервал прогревочный не считается? Нет —
    считаем все: счётчики уже живут с бута.
    """
    out = {"intervals": [], "avg_steal": 0.0, "error": None}
    prev = read_proc_stat()
    if prev is None:
        out["error"] = "/proc/stat недоступен"
        return out
    n = max(1, duration_s // max(1, step_s))
    steals = []
    for _ in range(n):
        time.sleep(max(1, step_s))
        cur = read_proc_stat()
        if cur is None:
            out["error"] = "/proc/stat пропал"
            break
        d = compute_deltas(prev, cur)
        per = percpu_steal(prev, cur)
        prev = cur
        if d is None:
            continue
        rec = {"steal": d["steal"], "busy": d["busy"], "iowait": d["iowait"]}
        if per:
            rec["core_max"] = max(per)
            rec["core_min"] = min(per)
        out["intervals"].append(rec)
        steals.append(d["steal"])
    if steals:
        out["avg_steal"] = round(sum(steals) / len(steals), 2)
    return out


# ══════════════════════════════════════════════════════════════════════════════
#  История (для меню)
# ══════════════════════════════════════════════════════════════════════════════

def last_days_stats(days: int = 7, node: str = "local") -> list:
    """[{date, n, avg, peak, level}] за последние N дней по ноде."""
    cfg = load_config()
    thr = cfg.get("thresholds", {})
    out = []
    for i in range(days - 1, -1, -1):
        d = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
        rows = [s for s in read_samples(d) if s.get("node") == node]
        if not rows:
            continue
        stats = compute_stats(rows)
        level, _ = classify_day(stats, thr)
        out.append({"date": d, "n": stats["n_ok"], "avg": stats["avg"],
                    "peak": stats["peak"], "p95": stats["p95"], "level": level})
    return out


# ══════════════════════════════════════════════════════════════════════════════
#  Установка / удаление (cron sampler + cron отчёт)
# ══════════════════════════════════════════════════════════════════════════════

def is_monitor_installed() -> bool:
    return CRON_FILE.exists() and SAMPLE_SCRIPT.exists() and REPORT_SCRIPT.exists()


def get_installed_interval() -> int:
    try:
        if CRON_FILE.exists():
            for line in CRON_FILE.read_text().splitlines():
                if line.startswith("*/"):
                    return int(line.split()[0].replace("*/", ""))
    except Exception:
        pass
    return DEFAULT_INTERVAL_MIN


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


def install_steal_monitor(cfg: Optional[dict] = None) -> tuple:
    """cron.d: sampler */interval + отчёт report_hour:report_minute.

    Wrapper'ы — PYTHONPATH-safe (паттерн v5.1: cron стартует с произвольной
    cwd, bare python -c падает с ModuleNotFoundError).
    """
    try:
        cfg = cfg or load_config()
        interval = max(1, min(60, int(cfg.get("sample_interval_min",
                                              DEFAULT_INTERVAL_MIN))))
        hour = max(0, min(23, int(cfg.get("report_hour", DEFAULT_REPORT_HOUR))))
        minute = max(0, min(59, int(cfg.get("report_minute",
                                            DEFAULT_REPORT_MINUTE))))
        installer_path = _find_installer_path()
        python = _find_python()

        for p in (SAMPLE_SCRIPT, REPORT_SCRIPT, CRON_FILE):
            p.parent.mkdir(parents=True, exist_ok=True)

        SAMPLE_SCRIPT.write_text(f"""#!/bin/bash
# steal-sample.sh — тик CPU Steal монитора (Chimera steal_monitor)
export PYTHONPATH="{installer_path}:$PYTHONPATH"
{python} -c "
import sys
sys.path.insert(0, '{installer_path}')
from chimera.modules.steal_monitor import sample_once
sample_once()
" 2>>/var/log/steal-monitor.log
""", encoding="utf-8")
        SAMPLE_SCRIPT.chmod(0o755)

        REPORT_SCRIPT.write_text(f"""#!/bin/bash
# steal-report.sh — дневной отчёт CPU Steal монитора (Chimera steal_monitor)
export PYTHONPATH="{installer_path}:$PYTHONPATH"
{python} -c "
import sys
sys.path.insert(0, '{installer_path}')
from chimera.modules.steal_monitor import send_daily_report
send_daily_report()
" 2>>/var/log/steal-monitor.log
""", encoding="utf-8")
        REPORT_SCRIPT.chmod(0o755)

        CRON_FILE.write_text(
            f"""# steal-monitor — CPU Steal монитор (Chimera)
*/{interval} * * * * root {SAMPLE_SCRIPT} >/dev/null 2>&1
{minute} {hour} * * * root {REPORT_SCRIPT} >/dev/null 2>&1
""", encoding="utf-8")
        CRON_FILE.chmod(0o644)
        _log(f"установлен: sampler */{interval} мин + отчёт {hour:02d}:{minute:02d}")
        return True, (f"Steal-мониторинг установлен: замер каждые {interval} мин, "
                      f"отчёт в {hour:02d}:{minute:02d}")
    except Exception as e:
        return False, f"Ошибка установки: {e}"


def uninstall_steal_monitor() -> tuple:
    """Удаляет cron + wrappers. Данные (samples/reports/конфиг) остаются."""
    try:
        for p in (CRON_FILE, SAMPLE_SCRIPT, REPORT_SCRIPT):
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass
        _log("удалён (cron + wrappers; данные сохранены)")
        return True, "Steal-мониторинг удалён (данные и конфиг сохранены)"
    except Exception as e:
        return False, f"Ошибка удаления: {e}"

# ══════════════════════════════════════════════════════════════════════════════
#  TUI-меню (Диагностика и Мониторинг → ST)
# ══════════════════════════════════════════════════════════════════════════════

def _ask_float(prompt: str, cur: float) -> float:
    raw = input(f"{prompt} [{cur}]: ").strip()
    if not raw:
        return cur
    try:
        return round(max(0.0, float(raw.replace(",", "."))), 2)
    except ValueError:
        return cur


def _ask_int(prompt: str, cur: int, lo: int, hi: int) -> int:
    raw = input(f"{prompt} [{cur}]: ").strip()
    if not raw:
        return cur
    try:
        return max(lo, min(hi, int(raw)))
    except ValueError:
        return cur


def _today_local_summary() -> str:
    """Одна строка статуса по локальной ноде за сегодня (для шапки меню)."""
    rows = [s for s in read_samples() if s.get("node") == "local"]
    if not rows:
        return "нет сэмплов (мониторинг выключен?)"
    stats = compute_stats(rows)
    level, _ = classify_day(stats, load_config().get("thresholds", {}))
    icon = _LEVEL_ICON[level]
    return (f"{icon} {_LEVEL_NAME[level]} — avg {stats['avg']:.1f}%, "
            f"пик {stats['peak']:.1f}%, сэмплов {stats['n_ok']}")


def _thresholds_menu(cfg: dict) -> None:
    from chimera._core import (_box_top, _box_row, _box_sep, _box_bottom,
                               _box_item, _box_back, _box_ok, CYAN, NC, GREEN,
                               YELLOW, DIM, BOLD, BLUE)
    thr = cfg.setdefault("thresholds", {})
    while True:
        os.system("clear")
        print()
        _box_top("🧟  STEAL-МОНИТОР — ПОРОГИ КЛАССИФИКАЦИИ")
        _box_row("  Классификация дня: КРИТИЧНО если любое из avg/p95/пик")
        _box_row("  ≥ crit-порога; ВНИМАНИЕ если ≥ warn-порога; иначе НОРМА.")
        _box_sep()
        _box_row(f"  {BOLD}avg за день{NC}:   warn {thr.get('warn_avg', 3.0)}% / "
                 f"crit {thr.get('crit_avg', 8.0)}%")
        _box_row(f"  {BOLD}пик (сэмпл){NC}: warn {thr.get('warn_peak', 8.0)}% / "
                 f"crit {thr.get('crit_peak', 15.0)}%")
        _box_row(f"  {BOLD}p95{NC}:          warn {thr.get('warn_p95', 5.0)}% / "
                 f"crit {thr.get('crit_p95', 10.0)}%")
        _box_row(f"  Мгновенные алерты: "
                 + (GREEN + "ВКЛ" + NC if cfg.get("alerts_enabled", True)
                    else YELLOW + "ВЫКЛ" + NC)
                 + f" — {thr.get('alert_consecutive', 3)} сэмпла подряд "
                 f"≥ crit_peak → TG (anti-spam {thr.get('alert_cooldown_min', 180)} мин)")
        _box_sep()
        _box_item("1", "Пороги avg (warn / crit)")
        _box_item("2", "Пороги пика (warn / crit)")
        _box_item("3", "Пороги p95 (warn / crit)")
        _box_item("4", "Серия для алерта (сэмплов подряд)")
        _box_item("5", "Кулдаун алертов (минут)")
        _box_item("6", f"Мгновенные алерты: "
                        f"{'ВЫКЛЮЧИТЬ' if cfg.get('alerts_enabled', True) else 'ВКЛЮЧИТЬ'}")
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор: {NC}").strip().lower()
        except KeyboardInterrupt:
            return
        if ch in ("0", "q", ""):
            return
        if ch == "1":
            thr["warn_avg"] = _ask_float("  warn avg %", thr.get("warn_avg", 3.0))
            thr["crit_avg"] = _ask_float("  crit avg %", thr.get("crit_avg", 8.0))
        elif ch == "2":
            thr["warn_peak"] = _ask_float("  warn peak %", thr.get("warn_peak", 8.0))
            thr["crit_peak"] = _ask_float("  crit peak %", thr.get("crit_peak", 15.0))
        elif ch == "3":
            thr["warn_p95"] = _ask_float("  warn p95 %", thr.get("warn_p95", 5.0))
            thr["crit_p95"] = _ask_float("  crit p95 %", thr.get("crit_p95", 10.0))
        elif ch == "4":
            thr["alert_consecutive"] = _ask_int(
                "  сэмплов подряд", thr.get("alert_consecutive", 3), 1, 100)
        elif ch == "5":
            thr["alert_cooldown_min"] = _ask_int(
                "  кулдаун, мин", thr.get("alert_cooldown_min", 180), 1, 10080)
        elif ch == "6":
            cfg["alerts_enabled"] = not cfg.get("alerts_enabled", True)
        else:
            continue
        cfg["thresholds"] = thr
        save_config(cfg)
        _box_ok("Пороги сохранены")


def _report_menu(cfg: dict) -> None:
    from chimera._core import (_box_top, _box_row, _box_sep, _box_bottom,
                               _box_item, _box_back, _box_ok, CYAN, NC, GREEN,
                               DIM)
    rep = cfg.setdefault("report", {})
    keys = [
        ("include_hourly", "Часовая динамика (24ч компактно)"),
        ("include_percpu", "Per-core разброс (детект SMT-соседа)"),
        ("include_bootavg", "Среднее с бута (хроника оверселла)"),
        ("include_recommendations", "Рекомендации делать/не делать"),
        ("include_ticket_block", "Тикет-блок (доказательства для провайдера)"),
    ]
    while True:
        os.system("clear")
        print()
        _box_top("🧟  STEAL-МОНИТОР — СОСТАВ ДНЕВНОГО ОТЧЁТА")
        for i, (k, label) in enumerate(keys, 1):
            on = rep.get(k, True)
            _box_row(f"  {GREEN}[{'x' if on else ' '}]{NC} {i}. {label}"
                     + ("" if on else DIM + "  (выкл)" + NC))
        _box_sep()
        _box_item("N", "Переключить пункт по номеру")
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор (номер / Q): {NC}").strip().lower()
        except KeyboardInterrupt:
            return
        if ch in ("0", "q", ""):
            return
        if ch.isdigit() and 1 <= int(ch) <= len(keys):
            k = keys[int(ch) - 1][0]
            rep[k] = not rep.get(k, True)
            cfg["report"] = rep
            save_config(cfg)
            _box_ok(f"{keys[int(ch)-1][1]}: {'ВКЛ' if rep[k] else 'ВЫКЛ'}")


def _nodes_menu(cfg: dict) -> None:
    from chimera._core import (_box_top, _box_row, _box_sep, _box_bottom,
                               _box_item, _box_back, _box_ok, _box_warn, CYAN,
                               NC, GREEN, YELLOW, DIM, BOLD, BLUE)
    while True:
        os.system("clear")
        peers = _load_peers(cfg)
        ident = _local_identity(cfg)
        print()
        _box_top("🧟  STEAL-МОНИТОР — НАБЛЮДАЕМЫЕ НОДЫ")
        _box_row(f"  Локальная нода: "
                 + (GREEN + " мониторится" + NC if cfg.get("monitor_local", True)
                    else YELLOW + " ВЫКЛЮЧЕНА" + NC))
        _box_row(f"  В отчётах:      {BOLD}{ident['label']}{NC} · "
                 f"{ident['ip'] or 'IP не определён'} · {ident['hostname']}")
        _box_row(f"  Peers по SSH:   "
                 + (GREEN + f" включено ({len(peers)})" + NC
                    if cfg.get("monitor_peers", False) and peers
                    else YELLOW + " выключено" + NC))
        _box_row(f"  {DIM}Peers = cascade_peers из tg_bot.json (как /status у"
                 f" TG-бота) + extra_peers. SSH только по ключу (BatchMode).{NC}")
        _box_sep()
        if peers:
            _box_row(f"  {'Нода':<16} {'Хост':<34} {'SSH'}")
            for p in peers:
                name = str(p.get("name", "?"))[:16]
                host = str(p.get("host", "?"))[:34]
                user = p.get("user", "root") or "root"
                _box_row(f"  {name:<16} {host:<34} {user}@:{p.get('port', 22)}")
        else:
            _box_row(f"  {DIM}peers не настроены (tg_bot.json cascade_peers"
                     f" пуст / фильтр исключил все){NC}")
        _box_sep()
        _box_item("1", f"Локальная нода: "
                       f"{'ВЫКЛЮЧИТЬ' if cfg.get('monitor_local', True) else 'ВКЛЮЧИТЬ'}")
        _box_item("2", f"Peers по SSH: "
                       f"{'ВЫКЛЮЧИТЬ' if cfg.get('monitor_peers', False) else 'ВКЛЮЧИТЬ'}")
        _box_item("3", "Добавить extra-peer (host user port name)")
        _box_item("4", "Удалить extra-peer")
        _box_item("5", "Фильтр peers (пусто = все)")
        _box_item("6", "Имя локальной ноды в отчётах (label / IP)")
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор: {NC}").strip().lower()
        except KeyboardInterrupt:
            return
        if ch in ("0", "q", ""):
            return
        if ch == "1":
            cfg["monitor_local"] = not cfg.get("monitor_local", True)
            save_config(cfg)
            _box_ok("Сохранено")
        elif ch == "2":
            if not cfg.get("monitor_peers", False) and not peers:
                _box_warn("Нет peers для наблюдения — сначала добавьте [3]")
            else:
                cfg["monitor_peers"] = not cfg.get("monitor_peers", False)
                save_config(cfg)
                _box_ok("Сохранено")
        elif ch == "3":
            host = input("  host (IP/домен): ").strip()
            if not host:
                continue
            user = input("  SSH user [root]: ").strip() or "root"
            port = _ask_int("  SSH port", 22, 1, 65535)
            name = input("  имя ноды (для отчёта): ").strip() or host
            extra = cfg.setdefault("extra_peers", [])
            if any(str(x.get("host")) == host for x in extra):
                _box_warn("Такой host уже есть в extra_peers")
            else:
                extra.append({"host": host, "user": user, "port": port,
                              "name": name})
                save_config(cfg)
                _box_ok(f"Добавлен {name} ({user}@{host}:{port})")
        elif ch == "4":
            extra = cfg.get("extra_peers", [])
            if not extra:
                _box_warn("extra_peers пуст")
                continue
            for i, x in enumerate(extra, 1):
                _box_row(f"  {i}. {x.get('name','?')} ({x.get('user','root')}@{x.get('host','?')}:{x.get('port',22)})")
            raw = input("  номер для удаления: ").strip()
            if raw.isdigit() and 1 <= int(raw) <= len(extra):
                gone = extra.pop(int(raw) - 1)
                save_config(cfg)
                _box_ok(f"Удалён {gone.get('name','?')}")
        elif ch == "5":
            cur = ",".join(str(x) for x in cfg.get("peer_filter", []))
            raw = input(f"  имена/хосты через запятую, пусто = все [{cur}]: ").strip()
            cfg["peer_filter"] = [x.strip() for x in raw.split(",") if x.strip()] if raw else []
            save_config(cfg)
            _box_ok("Фильтр сохранён")
        elif ch == "6":
            ident = _local_identity(cfg)
            print(f"\n  Текущее: label={ident['label']} ip={ident['ip'] or '-'} "
                  f"hostname={ident['hostname']}")
            raw = input(f"  короткое имя для отчётов, напр. RU-1 "
                        f"[пусто = {cfg.get('node_label') or 'hostname'}]: ").strip()
            if raw == "-":
                cfg["node_label"] = ""
            elif raw:
                cfg["node_label"] = raw
            raw = input(f"  публичный IP ноды [пусто = авто-детект "
                        f"({cfg.get('node_ip') or ident['ip'] or '?'})]: ").strip()
            if raw == "-":
                cfg["node_ip"] = ""
            elif raw:
                cfg["node_ip"] = raw
            save_config(cfg)
            ident = _local_identity(cfg)
            _box_ok(f"Отчёты покажут: {ident['label']} · "
                    f"{ident['ip'] or 'IP?'} · {ident['hostname']}")


def do_steal_monitor_menu() -> None:
    """TUI-меню CPU Steal монитора (пункт ST в «Диагностика и Мониторинг»)."""
    from chimera._core import (_box_top, _box_row, _box_sep, _box_bottom,
                               _box_item, _box_back, _box_ok, _box_warn,
                               CYAN, NC, GREEN, YELLOW, RED, DIM, BOLD, BLUE)
    while True:
        os.system("clear")
        cfg = load_config()
        installed = is_monitor_installed()
        interval = get_installed_interval() if installed else cfg.get("sample_interval_min", DEFAULT_INTERVAL_MIN)
        rh = int(cfg.get("report_hour", DEFAULT_REPORT_HOUR))
        rm = int(cfg.get("report_minute", DEFAULT_REPORT_MINUTE))
        peers = _load_peers(cfg)

        print()
        _box_top("🧟  CPU STEAL-МОНИТОР (оверселл гипервизора)")
        _box_row("  %steal = сколько CPU забирает гипервизор у VM. Хронические")
        _box_row("  >5–10% = оверселл провайдера: CPU-роли (AWG-каскад, TLS)")
        _box_row("  душатся, TCP-relay (Mieru) терпит. Отчёт — в конце суток.")
        _box_sep()
        ident = _local_identity(cfg)
        _box_row(f"  Нода в отчётах: {ident['label']} · "
                 f"{ident['ip'] or 'IP не определён'} · {ident['hostname']}")
        _box_row(f"  Мониторинг:    "
                 + (GREEN + f"АКТИВЕН (cron */{interval} мин)" + NC if installed
                    else YELLOW + "не установлен" + NC)
                 + f"  | отчёт {rh:02d}:{rm:02d}")
        _box_row(f"  Наблюдение:    локальная нода "
                 + (GREEN + "✓" + NC if cfg.get("monitor_local", True) else RED + "✗" + NC)
                 + f" + peers по SSH "
                 + (GREEN + f"✓ ({len(peers)})" + NC if cfg.get("monitor_peers", False) and peers
                    else DIM + "✗" + NC))
        _box_row(f"  Сегодня (local): {_today_local_summary()}")
        _box_row(f"  Алерты: {'ВКЛ' if cfg.get('alerts_enabled', True) else 'ВЫКЛ'}"
                 f" при {cfg['thresholds'].get('alert_consecutive', 3)} сэмплах подряд"
                 f" ≥ {cfg['thresholds'].get('crit_peak', 15.0)}%")
        _box_row(f"  {DIM}Конфиг: {CONFIG_FILE}{NC}")
        _box_sep()
        _box_item("1", f"{'Переустановить' if installed else 'Установить'} мониторинг"
                       f" (cron замер + отчёт)")
        _box_item("2", f"Интервал замеров  {DIM}(сейчас {interval} мин){NC}")
        _box_item("3", f"Время дневного отчёта  {DIM}(сейчас {rh:02d}:{rm:02d}){NC}")
        _box_item("4", "Пороги и алерты (warn/crit, серия, кулдаун)")
        _box_item("5", "Состав отчёта (часовая, per-core, тикет-блок...)")
        _box_item("6", "Наблюдаемые ноды (локальная + peers по SSH)")
        _box_item("7", "🩺 Замер сейчас (live 6 сек)")
        _box_item("8", "Показать отчёт за сегодня (без отправки)")
        _box_item("9", "Отправить отчёт в Telegram сейчас")
        _box_item("10", "История за 7 дней (local)")
        _box_item("11", "Хранение данных / лог")
        _box_sep()
        _box_item("R", "Сбросить конфиг к дефолтам")
        _box_item("U", "Удалить мониторинг (данные остаются)")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор: {NC}").strip().lower()
        except KeyboardInterrupt:
            break
        if ch in ("0", "q", ""):
            break

        def _reinstall_if_active():
            if is_monitor_installed():
                ok, msg = install_steal_monitor(load_config())
                if ok:
                    _box_ok(f"cron обновлён: {msg}")

        if ch == "1":
            ok, msg = install_steal_monitor(cfg)
            _box_ok(msg) if ok else _box_warn(msg)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            cfg["sample_interval_min"] = _ask_int(
                "  интервал, мин (1-60)", int(cfg.get("sample_interval_min", 5)), 1, 60)
            save_config(cfg)
            _reinstall_if_active()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            hour = _ask_int("  час отчёта (0-23)", rh, 0, 23)
            minute = _ask_int("  минута (0-59)", rm, 0, 59)
            cfg["report_hour"], cfg["report_minute"] = hour, minute
            save_config(cfg)
            _reinstall_if_active()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            _thresholds_menu(cfg)
        elif ch == "5":
            _report_menu(cfg)
        elif ch == "6":
            _nodes_menu(cfg)
        elif ch == "7":
            print()
            info = live_measure(duration_s=6, step_s=2)
            if info.get("error"):
                _box_warn(info["error"])
            else:
                _box_top("Live-замер (интервалы по 2 сек)")
                for i, r in enumerate(info["intervals"], 1):
                    per = (f" | per-core {r['core_max']}/{r['core_min']}%"
                           if "core_max" in r else "")
                    _box_row(f"  {i}: steal {r['steal']:.1f}% | busy "
                             f"{r['busy']:.1f}% | iowait {r['iowait']:.1f}%{per}")
                _box_row(f"  {'—'*8}")
                _box_row(f"  avg steal: {info['avg_steal']:.1f}%")
                _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "8":
            text = build_report()
            import re as _re
            print()
            print(_re.sub(r"<[^>]+>", "", text))
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "9":
            text = send_daily_report(send_tg=True)
            if _tg_configured():
                _box_ok("Отчёт отправлен (см. Telegram)")
            else:
                _box_warn("TG не настроен (telegram.json) — отчёт только сохранён:")
                import re as _re
                print(_re.sub(r"<[^>]+>", "", text))
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "10":
            rows = last_days_stats(7)
            print()
            _box_top("История steal (local, 7 дней)")
            if rows:
                _box_row(f"  {'Дата':<12} {'avg%':>6} {'p95%':>6} {'пик%':>6} {'n':>4}  уровень")
                _box_sep()
                for r in rows:
                    _box_row(f"  {r['date']:<12} {r['avg']:>6.1f} {r['p95']:>6.1f} "
                             f"{r['peak']:>6.1f} {r['n']:>4}  "
                             f"{_LEVEL_ICON[r['level']]} {_LEVEL_NAME[r['level']]}")
            else:
                _box_row("  данных пока нет")
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "11":
            print()
            _box_top("Данные и хранение")
            _box_row(f"  Сэмплы:     {SAMPLES_DIR}/YYYY-MM-DD.jsonl")
            _box_row(f"  Отчёты:     {REPORTS_DIR}/YYYY-MM-DD.txt (вложение в тикет)")
            _box_row(f"  Хранение:   {cfg.get('retention_days', 30)} дней"
                     f"  {DIM}(retention_days в конфиге){NC}")
            _box_row(f"  Лог:        {LOG_FILE}")
            try:
                n = len(list(SAMPLES_DIR.glob('*.jsonl'))) if SAMPLES_DIR.exists() else 0
                sz = sum(f.stat().st_size for f in SAMPLES_DIR.glob('*.jsonl')) if SAMPLES_DIR.exists() else 0
                _box_row(f"  Сейчас:     {n} файлов, {sz // 1024} КБ")
            except Exception:
                pass
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "r":
            raw = input(f"  {RED}Сбросить ВСЕ настройки к дефолтам? [y/N]: {NC}").strip().lower()
            if raw == "y":
                save_config(json.loads(json.dumps(DEFAULT_CONFIG)))
                _reinstall_if_active()
                _box_ok("Конфиг сброшен к дефолтам")
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "u" and installed:
            raw = input(f"  {RED}Удалить cron-мониторинг? (данные останутся) [y/N]: {NC}").strip().lower()
            if raw == "y":
                ok, msg = uninstall_steal_monitor()
                _box_ok(msg) if ok else _box_warn(msg)
            input(f"{BLUE}Нажмите Enter...{NC}")


def _tg_configured() -> bool:
    try:
        if TG_CONFIG.exists():
            cfg = json.loads(TG_CONFIG.read_text(encoding="utf-8"))
            return bool(cfg.get("token") and cfg.get("chat_id"))
    except Exception:
        pass
    return False
