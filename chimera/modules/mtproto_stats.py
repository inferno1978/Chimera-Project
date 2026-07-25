"""
chimera/modules/mtproto_stats.py
───────────────────────────────────────────────────────────────────────────────
Статистика трафика Telemt MTProxy — зрелая реализация.

Принцип работы:
  1. iptables ACCOUNTING: цепочки TELEMT_STATS_IN / TELEMT_STATS_OUT считают
     байты на порту telemt. Cron сбрасывает счётчики в 00:00.
  2. Суточные данные сохраняются в stats.json (накапливаются, не теряются
     после ночного сброса счётчиков).
  3. Суммарный трафик = сумма по всем дням в stats.json.
  4. Per-user статистика: journalctl логи telemt (сессии + last_seen),
     байты распределяются пропорционально сессиям.

Публичные точки входа:
    stats_menu()                   ← вызывается из mtproto.py
    setup_iptables_accounting(port) ← вызывается из mtproto.py при установке
───────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

from chimera.modules.text_width import wlen as _wlen, plain as _plain

import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Пути ─────────────────────────────────────────────────────────────────────
STATS_FILE   = Path("/var/lib/telemt/stats.json")
CONFIG_FILE  = Path("/etc/telemt/telemt.toml")
CRON_FILE    = Path("/etc/cron.d/telemt-stats")
CHAIN_IN     = "TELEMT_STATS_IN"
CHAIN_OUT    = "TELEMT_STATS_OUT"
SERVICE_NAME = "telemt"

# ── Цвета (из mtproto.py или собственные) ────────────────────────────────────
try:
    from chimera.modules.mtproto import (
        RED, GREEN, YELLOW, CYAN, BOLD, DIM, WHITE, NC,
        _run, _plain, _wlen,
        _box_top, _box_sep, _box_bot, _box_row, _box_item,
        _box_ok, _box_warn, _box_info, _box_kv,
        _fmt_bytes, _now_str, _today, _get_port, _load_users,
        _Cancelled, _ask, _pause,
    )
    _COLORS_FROM_PARENT = True
except ImportError:
    _COLORS_FROM_PARENT = False
    def _dc() -> dict:
        if sys.stdout.isatty():
            return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                        CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m',
                        WHITE='\033[1;37m', NC='\033[0m')
        return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BOLD','DIM','WHITE','NC')}
    _C = _dc()
    RED=_C['RED']; GREEN=_C['GREEN']; YELLOW=_C['YELLOW']; CYAN=_C['CYAN']
    BOLD=_C['BOLD']; DIM=_C['DIM']; WHITE=_C['WHITE']; NC=_C['NC']

    def _run(cmd, capture=False, check=False):
        kw = {"check": check}
        if capture:
            kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
        else:
            kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return subprocess.run(cmd, **kw)

    def _plain(s): return re.sub(r'\033\[[0-9;]*m', '', s)
    
    _BOX_W = 68
    def _box_top(title=""):
        print(f"{CYAN}╔{'═'*_BOX_W}╗{NC}")
        if title:
            pad = _BOX_W - _wlen(title); lpad = pad//2; rpad = pad-lpad
            print(f"{CYAN}║{NC}{' '*lpad}{BOLD}{WHITE}{title}{NC}{' '*rpad}{CYAN}║{NC}")
            print(f"{CYAN}╠{'═'*_BOX_W}║{NC}")
    def _box_sep(): print(f"{CYAN}╠{'═'*_BOX_W}║{NC}")
    def _box_bot(): print(f"{CYAN}╚{'═'*_BOX_W}╝{NC}")
    def _box_row(text=""):
        import unicodedata as _ud, re as _re
        w = _wlen(text)
        if w > _BOX_W:
            plain = _re.sub(r'\033\[[0-9;]*m', '', text)
            acc = 0
            for cut, ch in enumerate(plain):
                acc += 2 if _ud.east_asian_width(ch) in ('W','F') else 1
                if acc > _BOX_W - 1:
                    text = text[:cut] + '…'; break
            w = _wlen(text)
        pad = max(0, _BOX_W - w)
        print(f"{CYAN}║{NC}{text}{' '*pad}{CYAN}║{NC}")
    def _box_item(key, label):
        col = RED+BOLD if key.strip().upper() in ("Q","0") else WHITE+BOLD
        _box_row(f"  {DIM}[{NC}{col}{key}{NC}{DIM}]{NC}  {label}")
    def _box_ok(msg):   _box_row(f"  {GREEN}✓{NC}  {msg}")
    def _box_warn(msg): _box_row(f"  {YELLOW}⚠{NC}  {msg}")
    def _box_info(msg): _box_row(f"  {CYAN}→{NC}  {msg}")
    def _box_kv(key, val, kw=22):
        _box_row(f"  {CYAN}{key}{NC}{' '*max(0, kw-_wlen(key))}  {val}")
    def _fmt_bytes(n):
        for u in ("B","KiB","MiB","GiB","TiB"):
            if n < 1024: return f"{n:.1f} {u}" if u != "B" else f"{n} B"
            n /= 1024
        return f"{n:.1f} PiB"
    def _now_str(): return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    def _today():   return datetime.now().strftime("%Y-%m-%d")
    def _get_port():
        if not CONFIG_FILE.exists(): return 8443
        m = re.search(r'^port\s*=\s*(\d+)', CONFIG_FILE.read_text(), re.MULTILINE)
        return int(m.group(1)) if m else 8443
    def _load_users():
        users = {}
        if not CONFIG_FILE.exists(): return users
        in_sec = False
        for line in CONFIG_FILE.read_text().splitlines():
            if line.strip() == "[access.users]": in_sec = True; continue
            if in_sec and line.strip().startswith("["): break
            if in_sec:
                m = re.match(r'^([a-zA-Z][a-zA-Z0-9_\-]+)\s*=\s*"([a-f0-9]{32})"', line)
                if m: users[m.group(1)] = m.group(2)
        return users
    class _Cancelled(Exception): pass
    def _pause():
        try:
            print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True); input()
        except (KeyboardInterrupt, EOFError): print()
    def _ask(prompt, default="", c=False):
        try:
            print(prompt, end="", flush=True)
            val = input().strip()
            return val if val else default
        except (EOFError, UnicodeDecodeError):
            print(); return default
        except KeyboardInterrupt:
            print()
            if c: raise _Cancelled()
            return default

# ══════════════════════════════════════════════════════════════════════════════
#  IPTABLES ACCOUNTING
# ══════════════════════════════════════════════════════════════════════════════
def _ipt_chain_exists(chain: str) -> bool:
    return _run(["iptables", "-L", chain, "-n"], capture=True).returncode == 0


def _ipt_jump_exists(parent: str, chain: str, port: int, direction: str) -> bool:
    """Проверяет что в parent-цепочке (INPUT/OUTPUT) реально стоит
    jump-правило `-j chain` для порта port.

    direction="dport" для INPUT (входящий — dport),
    direction="sport" для OUTPUT (исходящий — sport).

    Не полагается на успешный returncode `-D`+`-I` — эти команды с check=False
    не бросают исключений, но и не гарантируют появления правила (например,
    если iptables не имеет CAP_NET_ADMIN в контейнере, или ядро без
    netfilter-модуля). Реально проверяем `iptables -L parent -v -n` и ищем
    цепочку по имени в колонке target.
    """
    r = _run(["iptables", "-L", parent, "-v", "-n"], capture=True)
    if r.returncode != 0:
        return False
    for line in r.stdout.splitlines():
        parts = line.split()
        # Формат: pkts bytes target prot opt in out source destination ...
        # Нужно: target == chain, протокол tcp, и в строке есть порт.
        if len(parts) < 10:
            continue
        target = parts[2]
        if target != chain:
            continue
        prot = parts[3]
        if prot != "tcp":
            continue
        # Ищем опцию dport/sport в строке (могут быть на разных позициях
        # в зависимости от версии iptables).
        line_lower = line.lower()
        if direction == "dport" and f"dpt:{port}" not in line_lower:
            continue
        if direction == "sport" and f"spt:{port}" not in line_lower:
            continue
        return True
    return False


def setup_iptables_accounting(port: int) -> bool:
    """
    Публичная функция — вызывается из mtproto.py при установке.
    Создаёт цепочки TELEMT_STATS_IN / TELEMT_STATS_OUT.
    Каждый вызов сначала очищает цепочки (flush), потом добавляет одно
    правило — так избегаем дублирования счётчиков.

    Возвращает True только если ВСЕ четыре проверки постфактум подтверждают
    факт установки:
      • цепочка CHAIN_IN существует
      • цепочка CHAIN_OUT существует
      • jump-правило из INPUT в CHAIN_IN для порта port стоит
      • jump-правило из OUTPUT в CHAIN_OUT для порта port стоит

    Раньше возвращала None (implicit) и не проверяла результат — все
    iptables-команды идут с check=False и не бросают исключений при провале,
    поэтому try/except в mtproto._setup_accounting() почти никогда не
    срабатывал, и установщик рапортовал «Учёт трафика активирован» даже
    когда цепочки физически не создались (контейнер без CAP_NET_ADMIN,
    ядро без netfilter, и т.п.).
    """
    _fail_reasons: list[str] = []

    def _warn_local(msg: str) -> None:
        _fail_reasons.append(msg)
        # Также логируем в chimera.log через _core, если доступен
        try:
            import importlib
            core = importlib.import_module("chimera._core")
            if hasattr(core, "log_to_file"):
                core.log_to_file("WARN", f"mtproto_stats.setup_iptables_accounting: {msg}")
        except Exception:
            pass

    for chain in (CHAIN_IN, CHAIN_OUT):
        if not _ipt_chain_exists(chain):
            _run(["iptables", "-N", chain])

    # INPUT → CHAIN_IN
    _run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "-j", CHAIN_IN])
    _run(["iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(port), "-j", CHAIN_IN])
    _run(["iptables", "-F", CHAIN_IN])
    _run(["iptables", "-A", CHAIN_IN, "-p", "tcp", "--dport", str(port),
          "-m", "comment", "--comment", "telemt-rx", "-j", "RETURN"])

    # OUTPUT → CHAIN_OUT
    _run(["iptables", "-D", "OUTPUT", "-p", "tcp", "--sport", str(port), "-j", CHAIN_OUT])
    _run(["iptables", "-I", "OUTPUT", "1", "-p", "tcp", "--sport", str(port), "-j", CHAIN_OUT])
    _run(["iptables", "-F", CHAIN_OUT])
    _run(["iptables", "-A", CHAIN_OUT, "-p", "tcp", "--sport", str(port),
          "-m", "comment", "--comment", "telemt-tx", "-j", "RETURN"])

    # ── Постфактум-верификация ───────────────────────────────────────────────
    # Все 4 проверки обязаны пройти. Если хотя бы одна не прошла — возвращаем
    # False и логируем конкретную причину, чтобы администратор мог
    # диагностировать (а не получить молчаливое «учёт активирован»).
    if not _ipt_chain_exists(CHAIN_IN):
        _warn_local(f"chain {CHAIN_IN} does not exist after iptables -N")
    if not _ipt_chain_exists(CHAIN_OUT):
        _warn_local(f"chain {CHAIN_OUT} does not exist after iptables -N")
    if not _ipt_jump_exists("INPUT", CHAIN_IN, port, "dport"):
        _warn_local(f"INPUT jump-rule to {CHAIN_IN} for dport={port} not found")
    if not _ipt_jump_exists("OUTPUT", CHAIN_OUT, port, "sport"):
        _warn_local(f"OUTPUT jump-rule to {CHAIN_OUT} for sport={port} not found")

    if _fail_reasons:
        # Не Critical-fail cron-установку и persist — эти шаги могут
        # пригодиться при ручной починке iptables. Но возвращаем False,
        # чтобы mtproto.py показал честный warn, а не фейковый success.
        pass

    # Cron: сброс счётчиков в 00:00 + проверка лимитов каждые 5 мин
    try:
        CRON_FILE.write_text(
            f"0 0 * * * root iptables -Z {CHAIN_IN} && iptables -Z {CHAIN_OUT}"
            f"  # telemt-stats\n"
            f"*/5 * * * * root /usr/bin/python3 -c \""
            f"from chimera.modules.mtproto import mtproto_check_limits; "
            f"mtproto_check_limits()\" # telemt-limits-check\n"
        )
        CRON_FILE.chmod(0o644)
    except Exception:
        pass

    # ── Persist ──────────────────────────────────────────────────────────────
    # Без этого шага цепочки TELEMT_STATS_IN/OUT и джамп-правила в INPUT/OUTPUT
    # живут только в runtime-таблице iptables и пропадают после любого ребута
    # сервера (обновление ядра, рестарт VPS) — учёт трафика "перестаёт
    # работать", хотя сам код _collect()/_read_chain_bytes() ни в чём не
    # виноват. SYN-limiter и iOS-фикс уже сохраняют свои правила аналогично —
    # учёт трафика был единственным исключением.
    _persist_accounting_rules()

    return len(_fail_reasons) == 0

def _persist_accounting_rules() -> None:
    """
    Сохраняет текущие iptables-правила (включая TELEMT_STATS_IN/OUT) тем же
    best-effort способом, что используется в telemt_syn_limiter.py /
    telemt_ios_fix.py: netfilter-persistent, либо iptables-save в rules.v4.
    """
    if shutil.which("netfilter-persistent"):
        _run(["netfilter-persistent", "save"])
        return
    rules_path = Path("/etc/iptables/rules.v4")
    if rules_path.parent.exists():
        try:
            r = _run(["iptables-save"], capture=True)
            if r.returncode == 0 and r.stdout:
                rules_path.write_text(r.stdout)
        except Exception:
            pass

def _read_chain_bytes(chain: str) -> int:
    """
    Читает байты из цепочки iptables.
    Берём ТОЛЬКО первую строку правила (pkts bytes target …),
    чтобы не задваивать при дублях.
    """
    r = _run(["iptables", "-L", chain, "-v", "-n", "-x"], capture=True)
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].isdigit() and parts[1].isdigit():
            return int(parts[1])
    return 0

def _reset_accounting() -> None:
    for chain in (CHAIN_IN, CHAIN_OUT):
        _run(["iptables", "-Z", chain])

def _accounting_active() -> bool:
    return _ipt_chain_exists(CHAIN_IN) and _ipt_chain_exists(CHAIN_OUT)

# ══════════════════════════════════════════════════════════════════════════════
#  ПАРСИНГ JOURNALCTL — per-user сессии
# ══════════════════════════════════════════════════════════════════════════════
_RE_BYTES = re.compile(
    r'(?:rx|bytes_in)[=:\s]+(\d+).*?(?:tx|bytes_out)[=:\s]+(\d+)',
    re.IGNORECASE
)

def _parse_journal(since: Optional[str] = None) -> dict:
    """
    Парсит journalctl telemt.
    Возвращает: {username: {sessions, last_seen}}
    """
    cmd = ["journalctl", "-u", SERVICE_NAME, "--no-pager", "-o", "short-iso"]
    if since:
        cmd += ["--since", since]
    r = _run(cmd, capture=True)

    result: dict = {}

    def _ensure(name):
        if name not in result:
            result[name] = {"sessions": 0, "last_seen": "—"}

    for line in r.stdout.splitlines():
        m_user = re.search(
            r'(?:user[=:\[]\s*|client[=:\[]\s*)([a-zA-Z][a-zA-Z0-9_\-]+)',
            line, re.IGNORECASE
        )
        if not m_user:
            continue
        uname = m_user.group(1)
        if uname.lower() in ("root", "telemt", "system", "service"):
            continue
        _ensure(uname)

        ts_m = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
        if ts_m:
            result[uname]["last_seen"] = ts_m.group(1).replace("T", " ")

        if re.search(r'connect|new.?client|auth.?ok', line, re.IGNORECASE):
            result[uname]["sessions"] += 1

    return result

# ══════════════════════════════════════════════════════════════════════════════
#  ХРАНИЛИЩЕ СТАТИСТИКИ
# ══════════════════════════════════════════════════════════════════════════════
def _load_stats() -> dict:
    if STATS_FILE.exists():
        try:
            return json.loads(STATS_FILE.read_text())
        except Exception:
            pass
    return {
        "total":  {"rx": 0, "tx": 0, "updated": "", "since": _now_str()},
        "daily":  {},
        "users":  {},
        "ipt_ok": False,
    }

def _save_stats(d: dict) -> None:
    STATS_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATS_FILE.write_text(json.dumps(d, ensure_ascii=False, indent=2))

def _collect(d: dict) -> dict:
    """
    Обновляет d из живых источников.

    Ключевые исправления vs старой реализации:
    1. _read_chain_bytes берёт только первую строку правила — без дублирования.
    2. Суточные данные пишутся в d["daily"][today] = текущие iptables-счётчики
       (они сбрасываются cron'ом в 00:00, поэтому это трафик за сегодня).
    3. d["total"] = сумма всех дней из d["daily"] — НЕ перезаписывается
       текущим iptables-значением. Это гарантирует что ночной сброс счётчиков
       не обнуляет накопленную статистику.
    4. Байты per-user распределяются пропорционально числу сессий.
    """
    today = _today()

    # ── iptables: трафик с последнего сброса (= трафик за сегодня) ───────────
    ipt_rx, ipt_tx = 0, 0
    try:
        ipt_rx = _read_chain_bytes(CHAIN_IN)
        ipt_tx = _read_chain_bytes(CHAIN_OUT)
        d["ipt_ok"] = True
    except Exception:
        d["ipt_ok"] = False

    # ── Суточная статистика ───────────────────────────────────────────────────
    if today not in d["daily"]:
        d["daily"][today] = {"rx": 0, "tx": 0}
    if d["ipt_ok"]:
        d["daily"][today]["rx"] = ipt_rx
        d["daily"][today]["tx"] = ipt_tx

    # ── Суммарный трафик = сумма всех дней (накапливается в JSON) ────────────
    if d["ipt_ok"]:
        d["total"]["rx"] = sum(v["rx"] for v in d["daily"].values())
        d["total"]["tx"] = sum(v["tx"] for v in d["daily"].values())

    # ── Per-user: journalctl ──────────────────────────────────────────────────
    since = d["total"].get("since", "")
    sessions = _parse_journal(since=since if since else None)

    for uname, udata in sessions.items():
        if uname not in d["users"]:
            d["users"][uname] = {"sessions": 0, "rx": 0, "tx": 0, "last_seen": "—"}
        cur = d["users"][uname]
        cur["sessions"] = max(cur["sessions"], udata["sessions"])
        if udata["last_seen"] != "—":
            cur["last_seen"] = udata["last_seen"]

    for uname in _load_users():
        if uname not in d["users"]:
            d["users"][uname] = {"sessions": 0, "rx": 0, "tx": 0, "last_seen": "—"}

    # ── Распределение байт пропорционально сессиям ───────────────────────────
    total_rx = d["total"].get("rx", 0)
    total_tx = d["total"].get("tx", 0)
    if d["ipt_ok"] and (total_rx > 0 or total_tx > 0):
        users_list = list(d["users"].keys())
        total_sessions = sum(d["users"][u]["sessions"] for u in users_list)
        if total_sessions > 0:
            for uname in users_list:
                ratio = d["users"][uname]["sessions"] / total_sessions
                d["users"][uname]["rx"] = int(total_rx * ratio)
                d["users"][uname]["tx"] = int(total_tx * ratio)
        else:
            active = [u for u in users_list if d["users"][u]["last_seen"] != "—"] or users_list
            n = max(len(active), 1)
            for i, uname in enumerate(active):
                d["users"][uname]["rx"] = (total_rx - (total_rx // n) * (n-1)) if i == n-1 else total_rx // n
                d["users"][uname]["tx"] = (total_tx - (total_tx // n) * (n-1)) if i == n-1 else total_tx // n

    d["total"]["updated"] = _now_str()
    return d

# ══════════════════════════════════════════════════════════════════════════════
#  ОТОБРАЖЕНИЕ СТАТИСТИКИ
# ══════════════════════════════════════════════════════════════════════════════
def _render_stats(d: dict, realtime: bool = False) -> None:
    if realtime:
        os.system("clear")

    total  = d["total"]
    users  = d.get("users", {})
    daily  = d.get("daily", {})
    ipt_ok = d.get("ipt_ok", False)

    ts    = total.get("updated", "—")
    since = total.get("since",   "—")
    rx    = total.get("rx",      0)
    tx    = total.get("tx",      0)

    r       = _run(["systemctl", "is-active", SERVICE_NAME], capture=True)
    svc_ok  = r.stdout.strip() == "active"
    svc_str = f"{GREEN}● запущен{NC}" if svc_ok else f"{RED}● остановлен{NC}"

    _box_top("СТАТИСТИКА ТРАФИКА  •  TELEMT MTPROXY")
    _box_row()
    _box_kv("Сервис:", svc_str)
    _box_kv("Обновлено:", ts)
    _box_kv("Учёт с:", since)
    _box_kv("Accounting:", (f"{GREEN}iptables активен{NC}" if ipt_ok
                           else f"{YELLOW}нет (journalctl){NC}"))
    _box_row(); _box_sep()

    # ── Суммарный трафик ──────────────────────────────────────────────────────
    _box_row(f"  {BOLD}{CYAN}📊 Суммарный трафик{NC}")
    _box_row()
    _box_kv("  ↓ Входящий  (rx):", f"{GREEN}{_fmt_bytes(rx)}{NC}")
    _box_kv("  ↑ Исходящий (tx):", f"{CYAN}{_fmt_bytes(tx)}{NC}")
    _box_kv("  ⇅ Итого:",          f"{BOLD}{_fmt_bytes(rx + tx)}{NC}")
    _box_row(); _box_sep()

    # ── По дням (последние 7) ─────────────────────────────────────────────────
    _box_row(f"  {BOLD}{CYAN}📅 По дням (последние 7){NC}"); _box_row()
    today = _today()
    sorted_days = sorted(daily.keys(), reverse=True)[:7]
    if sorted_days:
        hdr = f"  {'Дата':<12}  {'↓ RX':>10}  {'↑ TX':>10}  {'⇅ Итого':>10}"
        _box_row(f"{DIM}{hdr}{NC}")
        _box_row(f"  {DIM}{'─'*12}  {'─'*10}  {'─'*10}  {'─'*10}{NC}")
        for day in sorted_days:
            dv   = daily[day]
            d_rx = dv.get("rx", 0)
            d_tx = dv.get("tx", 0)
            mark = f" {YELLOW}← сегодня{NC}" if day == today else ""
            _box_row(
                f"  {CYAN}{day}{NC}  "
                f"{GREEN}{_fmt_bytes(d_rx):>10}{NC}  "
                f"{CYAN}{_fmt_bytes(d_tx):>10}{NC}  "
                f"{BOLD}{_fmt_bytes(d_rx + d_tx):>10}{NC}"
                f"{mark}"
            )
    else:
        _box_row(f"  {DIM}Данных пока нет — статистика накапливается{NC}")
    _box_row(); _box_sep()

    # ── По пользователям ──────────────────────────────────────────────────────
    _box_row(f"  {BOLD}{CYAN}👥 По пользователям{NC}"); _box_row()
    if not ipt_ok:
        _box_row(f"  {YELLOW}⚠  RX/TX — оценочно, пропорционально сессиям{NC}")
        _box_row()
    if users:
        hdr = f"  {'Имя':<16}  {'Сесс':>5}  {'↓ RX ≈':>10}  {'↑ TX ≈':>10}  Последний вход"
        _box_row(f"{DIM}{hdr}{NC}")
        _box_row(f"  {DIM}{'─'*16}  {'─'*5}  {'─'*10}  {'─'*10}  {'─'*14}{NC}")
        for uname, udata in sorted(users.items()):
            u_rx   = udata.get("rx",       0)
            u_tx   = udata.get("tx",       0)
            u_ses  = udata.get("sessions", 0)
            u_seen = (udata.get("last_seen") or "—")[:14]
            active = u_rx > 0 or u_tx > 0 or u_ses > 0
            nc     = f"{GREEN}{uname:<16}{NC}" if active else f"{DIM}{uname:<16}{NC}"
            _box_row(
                f"  {nc}  "
                f"{u_ses:>5}  "
                f"{GREEN}{_fmt_bytes(u_rx):>10}{NC}  "
                f"{CYAN}{_fmt_bytes(u_tx):>10}{NC}  "
                f"{DIM}{u_seen}{NC}"
            )
    else:
        _box_row(f"  {DIM}Пользователи не найдены. Установите Telemt.{NC}")
    _box_row(); _box_sep()

    if realtime:
        _box_row(f"  {DIM}Обновление каждые 5с  •  Ctrl+C — выход{NC}")
        _box_bot()
    else:
        _box_item("1", "🔄  Обновить сейчас")
        _box_item("2", "📡  Режим реального времени (5с)")
        _box_item("3", "⚡  Включить / переинициализировать учёт iptables")
        _box_item("4", "🗑️   Сбросить статистику")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot()

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ СТАТИСТИКИ  ←  точка входа из mtproto.py
# ══════════════════════════════════════════════════════════════════════════════
def stats_menu() -> None:
    """
    Точка входа из mtproto.py:
        from chimera.modules.mtproto_stats import stats_menu
        stats_menu()
    """
    if not CONFIG_FILE.exists():
        print(f"\n  {RED}✗  Telemt не установлен. Сначала выполните установку.{NC}\n")
        _pause()
        return

    d = _load_stats()

    while True:
        os.system("clear")
        d = _collect(d)
        _save_stats(d)
        _render_stats(d, realtime=False)
        print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            continue

        elif ch == "2":
            try:
                while True:
                    d = _collect(d)
                    _save_stats(d)
                    _render_stats(d, realtime=True)
                    time.sleep(5)
            except KeyboardInterrupt:
                print(f"\n  {GREEN}Выход из режима реального времени.{NC}\n")
            d = _load_stats()

        elif ch == "3":
            port = _get_port()
            try:
                ipt_ok = setup_iptables_accounting(port)
                if ipt_ok:
                    d["ipt_ok"] = True
                    d["total"]["since"] = _now_str()
                    _save_stats(d)
                    print(f"\n  {GREEN}✓  iptables-учёт активирован.{NC}")
                    print(f"  {GREEN}✓  Cron-сброс счётчиков в 00:00 установлен.{NC}")
                else:
                    # setup_iptables_accounting вернула False — постфактум-
                    # верификация обнаружила что цепочки или jump-правила
                    # не появились. Детали уже залогированы в chimera.log.
                    d["ipt_ok"] = False
                    _save_stats(d)
                    print(f"\n  {YELLOW}⚠  iptables-учёт НЕ активирован.{NC}")
                    print(f"  {YELLOW}  Постфактум-верификация обнаружила, что цепочки "
                          f"TELEMT_STATS_IN/OUT{NC}")
                    print(f"  {YELLOW}  или jump-правила из INPUT/OUTPUT не создались.{NC}")
                    print(f"  {DIM}  Возможные причины: контейнер без CAP_NET_ADMIN, "
                          f"ядро без netfilter-модуля,{NC}")
                    print(f"  {DIM}  iptables-nft vs iptables-legacy конфликт, или "
                          f"правила уже существуют в другой таблице.{NC}")
                    print(f"  {DIM}  Подробности — в /var/log/chimera.log "
                          f"(WARN от mtproto_stats.setup_iptables_accounting).{NC}")
            except Exception as e:
                print(f"\n  {YELLOW}⚠  Не удалось настроить iptables: {e}{NC}")
            _pause()

        elif ch == "4":
            ans = _ask(f"\n  {YELLOW}Сбросить всю статистику? [y/N]: {NC}", c=True).strip().lower()
            if ans == "y":
                _reset_accounting()
                d = {
                    "total":  {"rx": 0, "tx": 0, "updated": _now_str(), "since": _now_str()},
                    "daily":  {},
                    "users":  {},
                    "ipt_ok": d.get("ipt_ok", False),
                }
                _save_stats(d)
                print(f"\n  {GREEN}✓  Статистика сброшена.{NC}")
            _pause()

        elif ch in ("q", ""):
            break

# ══════════════════════════════════════════════════════════════════════════════
#  АВТОНОМНЫЙ ЗАПУСК
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}"); sys.exit(1)
    try:
        stats_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}"); sys.exit(0)
