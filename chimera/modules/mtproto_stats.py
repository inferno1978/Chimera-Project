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
# v5.1: wrapper bash-скрипт для cron-проверки лимитов (PYTHONPATH-safe).
# Bare `python3 -c "from chimera..."` в cron НЕ работает — cron
# запускается с произвольной cwd и без PYTHONPATH, поэтому
# `from chimera...` падает с ModuleNotFoundError. Wrapper-скрипт
# экспорит PYTHONPATH перед вызовом python3 (тот же паттерн, что в
# node_health_monitor.py::install_health_monitor и geo_files.py).
LIMITS_CHECK_SCRIPT = Path("/usr/local/sbin/telemt-limits-check.sh")
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
# УРОК НА БУДУЩЕЕ: при парсинге вывода iptables/ip/nft с флагом -n значения
# полей могут быть числовыми вместо текстовых. Для iptables -L -n это в
# первую очередь ПОЛЕ ПРОТОКОЛА: вместо текстового "tcp" стоит "6"
# (IPPROTO_TCP). IP-адреса также становятся числовыми, но они нас тут не
# касаются (мы не сравниваем их со строкой).
#
# Любой будущий парсинг вывода iptables/ip/nft с флагом -n должен либо не
# использовать -n для полей, которые сравниваются со строкой, либо явно
# принимать оба представления (текстовое и числовое). См. _TCP_PROTO_TOKENS
# ниже — этот набор был введён после ложноположительного отказа на реальном
# сервере (commit после 0b412e3): jump-правило реально стояло и работало
# (счётчики 119 пакетов / 15936 байт), но старый код ждал буквально "tcp" и
# всегда возвращал False из-за "6" в выводе -n.
_TCP_PROTO_TOKENS = frozenset({"tcp", "6"})


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

    ВАЖНО про флаг -n: он делает числовым не только IP-адреса, но и ПОЛЕ
    ПРОТОКОЛА — вместо текстового "tcp" в этой колонке стоит "6"
    (IPPROTO_TCP). Реальный вывод с сервера:
        119 15936 TELEMT_STATS_IN  6  --  *  *  0.0.0.0/0  0.0.0.0/0  tcp dpt:5000
    Поэтому принимаем оба варианта через _TCP_PROTO_TOKENS = {"tcp", "6"}.
    См. УРОК НА БУДУЩЕЕ выше.
    """
    r = _run(["iptables", "-L", parent, "-v", "-n"], capture=True)
    if r.returncode != 0:
        return False
    for line in r.stdout.splitlines():
        parts = line.split()
        # Формат: pkts bytes target prot opt in out source destination ...
        # Нужно: target == chain, протокол tcp (или "6" при -n), и в строке
        # есть порт.
        if len(parts) < 10:
            continue
        target = parts[2]
        if target != chain:
            continue
        prot = parts[3]
        if prot not in _TCP_PROTO_TOKENS:
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


def _ipt_remove_all_jumps(parent: str, chain: str, port: int,
                          direction: str) -> int:
    """Удаляет ВСЕ jump-правила parent → chain для порта, независимо
    от того, сколько их накопилось. Возвращает количество удалённых
    правил (для лога). Использует `_ipt_jump_exists()` для проверки
    after each removal, а не полагается на returncode -D.

    Зачем это нужно: пункт [3] «Включить / переинициализировать учёт
    iptables» может нажиматься многократно (при диагностике). Текущий
    код делал ОДИН вызов `-D ... -j CHAIN` перед ОДНИМ `-I ... -j CHAIN`
    — это снижало риск дублирования, но не гарантировало его отсутствие:
    `-D` удаляет только ОДНО совпадающее правило за вызов, не проверяет
    результат, и если по какой-то причине правило встретилось дважды
    (например, из-за более ранней версии кода без `-D` вообще, или
    ручного вмешательства) — одно из дублей останется висеть, а после
    `-I` добавится ещё одна свежая копия — правила будут накапливаться
    с каждым нажатием [3].

    Цикл удаления до исчерпания (с защитным лимитом 50 итераций на случай
    непредвиденного поведения iptables — штатно никогда не достигается)
    гарантирует, что после `_ipt_remove_all_jumps` останется РОВНО 0
    jump-правил, и последующий единственный `-I` приведёт к РОВНО 1
    правилу в финальном состоянии, сколько бы раз [3] ни нажимали.
    """
    removed = 0
    opt = "--dport" if direction == "dport" else "--sport"
    # Защита от бесконечного цикла — 50 итераций хватит на любой реальный
    # сценарий (даже если в INPUT скопилось 50 дублей из-за ручной правки).
    for _ in range(50):
        if not _ipt_jump_exists(parent, chain, port, direction):
            break
        r = _run(["iptables", "-D", parent, "-p", "tcp", opt, str(port),
                  "-j", chain])
        if r.returncode != 0:
            break
        removed += 1
    return removed


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

    Идемпотентность: при повторных вызовах (пункт [3] меню статистики
    может нажиматься многократно при диагностике) — ГАРАНТИРОВАННО
    удаляются ВСЕ ранее установленные jump-правила в INPUT/OUTPUT через
    _ipt_remove_all_jumps() (цикл до исчерпания), и только потом
    создаётся ровно одно новое. Не полагаемся на единственный -D.
    Если удалено >1 правила — логируем как сигнал, что раньше копилось
    дублирование (полезно для диагностики).
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

    def _info_local(msg: str) -> None:
        # Информационные сообщения (не повод возвращать False) — только в лог
        try:
            import importlib
            core = importlib.import_module("chimera._core")
            if hasattr(core, "log_to_file"):
                core.log_to_file("INFO", f"mtproto_stats.setup_iptables_accounting: {msg}")
        except Exception:
            pass

    for chain in (CHAIN_IN, CHAIN_OUT):
        if not _ipt_chain_exists(chain):
            _run(["iptables", "-N", chain])

    # ── ИДЕМПОТЕНТНАЯ ОЧИСТКА старых jump-правил ─────────────────────────────
    # Удаляем ВСЕ ранее установленные jump-правила (сколько бы их ни было —
    # 0, 1 или больше) перед созданием нового. Цикл до исчерпания через
    # _ipt_jump_exists(), а не один -D. Если >1 — логируем как сигнал
    # копившегося дублирования (полезно для диагностики).
    removed_in = _ipt_remove_all_jumps("INPUT", CHAIN_IN, port, "dport")
    removed_out = _ipt_remove_all_jumps("OUTPUT", CHAIN_OUT, port, "sport")
    if removed_in > 1:
        _info_local(
            f"removed {removed_in} duplicate INPUT jump-rules to "
            f"{CHAIN_IN} (dport={port}) — pre-existing duplication detected"
        )
    if removed_out > 1:
        _info_local(
            f"removed {removed_out} duplicate OUTPUT jump-rules to "
            f"{CHAIN_OUT} (sport={port}) — pre-existing duplication detected"
        )

    # INPUT → CHAIN_IN (ровно одно новое правило)
    _run(["iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(port), "-j", CHAIN_IN])
    _run(["iptables", "-F", CHAIN_IN])
    _run(["iptables", "-A", CHAIN_IN, "-p", "tcp", "--dport", str(port),
          "-m", "comment", "--comment", "telemt-rx", "-j", "RETURN"])

    # OUTPUT → CHAIN_OUT (ровно одно новое правило)
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

    # Cron: сброс счётчиков в 00:00 + проверка лимитов каждые 5 мин.
    #
    # v5.1: проверка лимитов раньше шла через bare `python3 -c "from
    # chimera.modules.mtproto import mtproto_check_limits; ..."` — это
    # НЕ работало, потому что cron запускается с произвольной cwd и без
    # PYTHONPATH, и `from chimera...` падал с ModuleNotFoundError
    # (подтверждено трейсбеком с реального сервера пользователя zvshka).
    # Квоты/expiry Telemt НИКОГДА реально не проверялись через cron.
    #
    # Паттерн исправления — wrapper bash-скрипт (как в
    # node_health_monitor.py::install_health_monitor и
    # geo_files.py::setup_geo_autoupdate): находим путь установки
    # chimera, экспорим PYTHONPATH, вызываем python -c с
    # sys.path.insert(0, ...). Cron-файл просто вызывает wrapper.

    # Находим путь установки chimera (тот же способ, что в
    # node_health_monitor.py::install_health_monitor).
    try:
        import importlib.util
        spec = importlib.util.find_spec("chimera")
        if spec and spec.submodule_search_locations:
            installer_path = str(
                Path(list(spec.submodule_search_locations)[0]).parent
            )
        else:
            installer_path = "/opt/chimera"
    except Exception:
        installer_path = "/opt/chimera"

    # Wrapper bash-скрипт: export PYTHONPATH + sys.path.insert + python -c.
    # Ошибки записи wrapper-скрипта НЕ должны блокировать запись cron-файла
    # (могут быть разные причины: read-only fs, отсутствие /usr/local/sbin и пр.)
    try:
        script_content = (
            "#!/bin/bash\n"
            f"# Telemt limits check (wrapper для cron; v5.1: PYTHONPATH-safe).\n"
            f"export PYTHONPATH=\"{installer_path}:$PYTHONPATH\"\n"
            f"/usr/bin/python3 -c \"\n"
            f"import sys\n"
            f"sys.path.insert(0, '{installer_path}')\n"
            f"from chimera.modules.mtproto import mtproto_check_limits\n"
            f"mtproto_check_limits()\n"
            f"\" # telemt-limits-check\n"
        )
        LIMITS_CHECK_SCRIPT.write_text(script_content)
        LIMITS_CHECK_SCRIPT.chmod(0o755)
    except Exception:
        pass

    # Cron-файл: сброс iptables-счётчиков в 00:00 (pure shell, без python)
    # + проверка лимитов каждые 5 мин (через wrapper-скрипт).
    try:
        CRON_FILE.write_text(
            f"0 0 * * * root iptables -Z {CHAIN_IN} && iptables -Z {CHAIN_OUT}"
            f"  # telemt-stats\n"
            f"*/5 * * * * root {LIMITS_CHECK_SCRIPT} # telemt-limits-check\n"
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
#  ДИАГНОСТИКА TELEMT API (для панели telemt_panel)
# ══════════════════════════════════════════════════════════════════════════════
# Telemt Panel (отдельный Go-бинарник) берёт статистику из HTTP API telemt
# (127.0.0.1:9091, секция [server.api] в telemt.toml). Если панель показывает
# 0 traffic / 0 connections, хотя TUI Chimera (через iptables-цепочки
# TELEMT_STATS_IN/OUT) видит трафик — это значит, что API telemt возвращает 0.
#
# Возможные причины:
#   1. Telemt был недавно перезапущен — внутренние счётчики обнулились
#      (uptime < времени с последнего подключения). iptables-счётчики при
#      этом НЕ обнуляются, поэтому TUI Chimera продолжает показывать трафик.
#   2. telemt-бинарник собран без stats-feature (build profile = "unknown"
#      в System Info панели — подозрительный признак).
#   3. telemt считает только соединения на основном порту, а iOS Fix
#      (iptables NAT REDIRECT с внешнего порта на основной) может
#      приводить к тому, что telemt теряет per-connection tracking.
#   4. Баг upstream telemt (не в Chimera).
#
# Эта функция проверяет первые 3 пункта и возвращает диагностику для TUI.

def _telemt_api_section_configured() -> tuple[bool, str]:
    """Проверяет что в telemt.toml включена секция [server.api].

    Returns:
      (ok, detail): ok=True если секция присутствует и enabled=true.
                    detail — человекочитаемое описание для TUI.
    """
    if not CONFIG_FILE.exists():
        return False, "telemt.toml не найден — Telemt не установлен"
    try:
        text = CONFIG_FILE.read_text()
    except Exception as e:
        return False, f"не удалось прочитать telemt.toml: {e}"

    # Ищем секцию [server.api] (или устаревший [server.admin_api])
    m = re.search(
        r'\[server\.(?:api|admin_api)\]\s*\n(.*?)(?=\n\[|\Z)',
        text, re.DOTALL
    )
    if not m:
        return False, "секция [server.api] отсутствует в telemt.toml"
    section = m.group(1)
    if not re.search(r'^\s*enabled\s*=\s*true\s*$', section, re.MULTILINE):
        return False, "секция [server.api] есть, но enabled=false (или отсутствует)"
    return True, "секция [server.api] включена"


def _telemt_api_probe(timeout: float = 3.0) -> tuple[bool, str, dict]:
    """Делает запрос к telemt API (без auth_header) чтобы проверить что API
    отвечает.

    Возвращает (reachable, detail, response_dict):
      reachable: True если HTTP-запрос вернул любой ответ (даже 401/403 —
                 это значит API слушает, просто нужен auth).
      detail: человекочитаемое описание.
      response_dict: JSON-ответ если удалось распарсить, иначе {}.

    Не использует auth_header (мы его не знаем — он в конфиге панели).
    Это нормально для диагностики — нам важно понять, слушает ли API вообще.
    """
    import urllib.request
    import urllib.error

    # Сначала проверяем что telemt вообще запущен
    r = _run(["systemctl", "is-active", SERVICE_NAME], capture=True)
    if r.returncode != 0 or r.stdout.strip() != "active":
        return False, f"сервис {SERVICE_NAME} не активен", {}

    # Пытаемся достучаться до API. Telemt API обычно отдаёт info на
    # корневом endpoint или на /v1/info. Используем /v1/info как
    # наиболее вероятный (стандартный для Rust-приложений с axum/actix).
    # Если API требует auth — вернёт 401/403, и это OK для нашей проверки
    # (значит API работает, просто нужен auth_header).
    urls_to_try = [
        "http://127.0.0.1:9091/v1/info",
        "http://127.0.0.1:9091/info",
        "http://127.0.0.1:9091/",
    ]
    for url in urls_to_try:
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                try:
                    data = json.loads(body) if body else {}
                except Exception:
                    data = {}
                return True, f"API отвечает на {url} (HTTP {resp.status})", data
        except urllib.error.HTTPError as e:
            # 401/403 — API работает, но нужен auth. Это GOOD для нашей
            # проверки — значит API слушает.
            if e.code in (401, 403):
                return True, f"API отвечает на {url} (HTTP {e.code} — auth required, это нормально)", {}
            # Другие HTTP-ошибки — продолжаем пробовать
            continue
        except urllib.error.URLError as e:
            # Connection refused и т.п. — пробуем следующий URL
            continue
        except Exception:
            continue

    return False, "API не отвечает ни на одном из проверенных URL", {}


def diagnose_telemt_api_for_panel() -> dict:
    """Полная диагностика: почему Telemt Panel может показывать 0 traffic.

    Возвращает dict с ключами:
      api_section_configured: bool — [server.api] есть в telemt.toml
      api_section_detail: str
      api_reachable: bool — API отвечает на HTTP-запрос
      api_reachable_detail: str
      api_response: dict — JSON-ответ если есть
      telemt_uptime_sec: int — uptime процесса telemt (если получилось узнать)
      recommendations: list[str] — список рекомендаций для пользователя
    """
    result = {
        "api_section_configured": False,
        "api_section_detail": "",
        "api_reachable": False,
        "api_reachable_detail": "",
        "api_response": {},
        "telemt_uptime_sec": 0,
        "telemt_uptime_detail": "",
        "recommendations": [],
    }

    # 1. Проверяем секцию [server.api] в telemt.toml
    ok, detail = _telemt_api_section_configured()
    result["api_section_configured"] = ok
    result["api_section_detail"] = detail
    if not ok:
        result["recommendations"].append(
            "Включите [server.api] в telemt.toml (через меню Telemt → "
            "Telemt Panel → установка панели, или вручную mtproto."
            "ensure_api_enabled())."
        )

    # 2. Пробуем достучаться до API
    reachable, reach_detail, api_data = _telemt_api_probe()
    result["api_reachable"] = reachable
    result["api_reachable_detail"] = reach_detail
    result["api_response"] = api_data
    if not reachable:
        result["recommendations"].append(
            "API telemt не отвечает на 127.0.0.1:9091. Проверьте: "
            "systemctl status telemt, journalctl -u telemt -n 30, "
            "ss -tlnp | grep 9091."
        )

    # 3. Uptime telemt — если telemt недавно перезапущен, его внутренние
    # счётчики обнулились. iptables-счётчики при этом НЕ обнуляются,
    # поэтому TUI Chimera может показывать трафик, а Panel — нет.
    r = _run(["systemctl", "show", SERVICE_NAME,
              "--property=ActiveEnterTimestampMonotonic"], capture=True)
    if r.returncode == 0 and r.stdout:
        m = re.search(r'=(\d+)', r.stdout)
        if m:
            enter_mono_us = int(m.group(1))  # микросекунды monotonic
            # Получаем текущий monotonic timestamp
            try:
                import time as _time
                # clock_gettime CLOCK_MONOTONIC = время с boot
                # monotonic в systemctl — это микросекунды с boot
                # Нельзя напрямую сравнить с time.time() (wall clock),
                # но можно через /proc/uptime
                with open("/proc/uptime") as f:
                    uptime_sec = float(f.read().split()[0])
                enter_sec = enter_mono_us / 1_000_000
                telemt_uptime = max(0, int(uptime_sec - enter_sec))
                result["telemt_uptime_sec"] = telemt_uptime
                if telemt_uptime < 600:  # < 10 минут
                    result["telemt_uptime_detail"] = (
                        f"{telemt_uptime}s (< 10 минут — счётчики telemt "
                        f"могли обнулиться при недавнем рестарте)"
                    )
                    result["recommendations"].append(
                        f"Telemt перезапущен {telemt_uptime}s назад. Внутренние "
                        f"счётчики telemt обнуляются при рестарте, поэтому Panel "
                        f"может показывать 0 даже если трафик был. iptables-"
                        f"счётчики (TUI Chimera) НЕ обнуляются при рестарте "
                        f"telemt — поэтому TUI и Panel могут расходиться. "
                        f"Подождите 5-10 минут после рестарта и попробуйте "
                        f"подключиться снова — счётчики telemt должны начать "
                        f"расти."
                    )
                else:
                    result["telemt_uptime_detail"] = f"{telemt_uptime}s"
            except Exception:
                pass

    # 4. Дополнительная рекомендация если всё настроено но трафика нет
    if (result["api_section_configured"] and result["api_reachable"]
            and not result["recommendations"]):
        result["recommendations"].append(
            "API telemt настроен и отвечает, но Panel показывает 0. "
            "Возможные причины: (а) telemt-бинарник собран без stats-"
            "feature (проверьте 'build profile' в System Info панели — "
            "если 'unknown', это подозрительно); (б) telemt считает только "
            "соединения на основном порту, а iOS Fix через iptables NAT "
            "REDIRECT может приводить к потере per-connection tracking; "
            "(в) баг upstream telemt (не в Chimera). TUI Chimera считает "
            "трафик через iptables-цепочки TELEMT_STATS_IN/OUT — это "
            "надёжный источник, не зависящий от telemt API."
        )

    return result


def _render_telemt_api_diagnosis(diag: dict) -> None:
    """Рендерит диагностику Telemt API для TUI (вызывается из stats_menu)."""
    _box_row(f"  {BOLD}{CYAN}🔍 Диагностика Telemt API (для панели){NC}")
    _box_row()
    _box_kv("Секция [server.api]:",
            f"{GREEN}✓{NC} {diag['api_section_detail']}"
            if diag["api_section_configured"]
            else f"{RED}✗{NC} {diag['api_section_detail']}")
    _box_kv("API отвечает:",
            f"{GREEN}✓{NC} {diag['api_reachable_detail']}"
            if diag["api_reachable"]
            else f"{RED}✗{NC} {diag['api_reachable_detail']}")
    if diag["telemt_uptime_sec"] > 0:
        _box_kv("Uptime telemt:", diag["telemt_uptime_detail"])
    _box_row()
    if diag["recommendations"]:
        _box_row(f"  {YELLOW}⚠ Рекомендации:{NC}")
        for rec in diag["recommendations"]:
            # Wrap long lines
            for line in _wrap_text(rec, _BOX_W - 4):
                _box_row(f"  {DIM}{line}{NC}")
        _box_row()
    _box_sep()


def _wrap_text(text: str, width: int) -> list:
    """Простой word-wrap для длинных строк в TUI."""
    import textwrap
    return textwrap.wrap(text, width=width,
                         break_long_words=False,
                         break_on_hyphens=False)


# ══════════════════════════════════════════════════════════════════════════════
#  ПАРСИНГ JOURNALCTL — per-user сессии
# ══════════════════════════════════════════════════════════════════════════════
_RE_BYTES = re.compile(
    r'(?:rx|bytes_in)[=:\s]+(\d+).*?(?:tx|bytes_out)[=:\s]+(\d+)',
    re.IGNORECASE
)

def _parse_journal(since: Optional[str] = None, max_days: int = 1) -> dict:
    """
    Парсит journalctl telemt.
    Возвращает: {username: {sessions, last_seen}}

    Формат вывода journalctl -o short-iso:
        2026-07-26T12:34:56+0300 host telemt[1234]: <message>
    Telemt (Rust, tracing crate) пишет в message свои строки, например:
        user=alice connected from 1.2.3.4
        new client user=bob
        client alice authenticated
        session started for user=carol

    Поддержка нескольких сценариев:
      1. Стандартный short-iso: timestamp в начале строки, дальше message.
      2. Multiline-сообщения: journald может разрывать длинные сообщения
         на несколько строк; continuation-строки не имеют timestamp.
         Запоминаем последний timestamp и применяем его к continuation-строкам
         с user= (это фикс «Последний вход: —» для пользователей, чьё имя
         оказалось на continuation-строке).
      3. timestamp с пробелом вместо T (если кто-то изменил формат
         journalctl или используется short-full): принимаем оба варианта.
      4. session-паттерн расширен: connect | new.?client | auth.?ok |
         session.?start | accepted | login | handshake.?ok | client.?ok.
         Раньше узкий паттерн пропускал много реальных сообщений telemt,
         из-за чего sessions=0 даже для активных пользователей.

    ВАЖНО (FIX OOM):
      Раньше использовалось _run(cmd, capture=True) — это загружает ВЕСЬ
      вывод journalctl в память через subprocess.run(capture_output=True).
      На сервере с долго работающим telemt журнал может быть сотни MB,
      и процесс убивается OOM killer'ом («killed» в консоли).

      Теперь используем subprocess.Popen с потоковым чтением построчно —
      память не накапливается, обрабатываем строки по мере поступления.

    Также: если since пустой — ограничиваем последние N дней, чтобы
    не читать весь журнал с момента установки (может быть огромным).

    ВАЖНО (FIX CPU 95%): даже если since указан (например "2026-07-15"),
    ограничиваем максимум последними N дней. Иначе journalctl читает
    журнал за месяцы — CPU 95% в течение 10+ минут на серверах с
    активным telemt. Для last_seen и sessions счётчика N дней достаточно.

    Args:
      since: исходная дата начала учёта (из stats.json). Если старше
             max_days — заменяется на "{max_days} days ago".
      max_days: максимум дней для чтения журнала (по умолчанию 1 = 24 часа).
                Можно увеличить до 7 если нужна недельная статистика.
    """
    from datetime import datetime, timedelta
    
    # ЖЁСТКИЙ ЛИМИТ: максимум max_days дней, независимо от since.
    # Это фикс зависания journalctl на больших журналах.
    # Если since указан и старше max_days дней — используем "N days ago".
    max_since_date = datetime.now() - timedelta(days=max_days)
    
    if since:
        # Пытаемся распарсить since в формате "YYYY-MM-DD HH:MM:SS".
        try:
            since_dt = datetime.strptime(since, "%Y-%m-%d %H:%M:%S")
            if since_dt < max_since_date:
                since = f"{max_days} days ago"
        except (ValueError, TypeError):
            # Если since в другом формате (например "yesterday") —
            # оставляем как есть, journalctl сам разберётся.
            pass
    else:
        since = f"{max_days} days ago"

    cmd = ["journalctl", "-u", SERVICE_NAME, "--no-pager", "-o", "short-iso",
           "--since", since]

    result: dict = {}
    # Запоминаем последний timestamp из предыдущей строки — для
    # continuation-строк без timestamp в начале (multiline-сообщения).
    last_ts: Optional[str] = None

    def _ensure(name):
        if name not in result:
            result[name] = {"sessions": 0, "last_seen": "—"}

    def _extract_ts(line: str) -> Optional[str]:
        """Извлекает timestamp из начала строки.

        Принимает оба варианта разделителя между датой и временем:
          • T (стандартный short-iso): 2026-07-26T12:34:56+0300
          • пробел (short-full / другие): 2026-07-26 12:34:56
        Возвращает 'YYYY-MM-DD HH:MM:SS' или None.
        """
        m = re.match(r'^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})', line)
        if m:
            return f"{m.group(1)} {m.group(2)}"
        return None

    # Расширенный паттерн «соединение установлено» — покрывает реальные
    # сообщения от tracing-логгера telemt. Буквы после `auth`/`connect`
    # могут быть: `auth.ok`, `auth_ok`, `authenticated`, `connect from`,
    # `new client`, `client connected`, `session started`, `accepted`,
    # `handshake ok`, `client ok`, `login`, и т.п.
    _SESSION_RE = re.compile(
        r'connect|new.?client|auth(?:\.|_)?(?:ok|enticated)|'
        r'session.?start|accepted|login|handshake.?ok|client.?ok',
        re.IGNORECASE
    )

    # Потоковое чтение через Popen — НЕ загружает весь вывод в память.
    # Это фикс OOM killer: раньше _run(capture=True) грузило весь журнал.
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        # Читаем построчно — память не накапливается.
        for line in proc.stdout:
            line = line.rstrip("\n\r")
            if not line:
                continue

            # Сначала пытаемся извлечь timestamp из текущей строки
            ts = _extract_ts(line)
            if ts:
                last_ts = ts

            m_user = re.search(
                r'(?:user[=:\[]\s*|client[=:\[]\s*|username[=:]\s*|name[=:]\s*)'
                r'(["\']?)([a-zA-Z][a-zA-Z0-9_\-]+)\1',
                line, re.IGNORECASE
            )
            if not m_user:
                continue
            uname = m_user.group(2)
            if uname.lower() in ("root", "telemt", "system", "service", "client"):
                continue
            _ensure(uname)

            # last_seen обновляем: либо из текущей строки, либо из last_ts
            # (для continuation-строк multiline-сообщений).
            if ts:
                result[uname]["last_seen"] = ts
            elif last_ts:
                # continuation-строка без своего timestamp — используем
                # последний известный. Это НЕ идеально (timestamp может быть
                # из предыдущего log-entry), но лучше чем "—" для активных
                # пользователей. Только обновляем если текущий last_seen = "—".
                if result[uname]["last_seen"] == "—":
                    result[uname]["last_seen"] = last_ts

            if _SESSION_RE.search(line):
                result[uname]["sessions"] += 1

        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        # journalctl завис — убиваем.
        proc.kill()
        proc.wait()
    except Exception:
        # Fallback: если Popen не сработал — пробуем старый способ,
        # но с жёстким лимитом строк.
        try:
            cmd_fallback = cmd + ["--lines", "10000"]
            r = _run(cmd_fallback, capture=True)
            for line in r.stdout.splitlines():
                ts = _extract_ts(line)
                if ts:
                    last_ts = ts
                m_user = re.search(
                    r'(?:user[=:\[]\s*|client[=:\[]\s*|username[=:]\s*|name[=:]\s*)'
                    r'(["\']?)([a-zA-Z][a-zA-Z0-9_\-]+)\1',
                    line, re.IGNORECASE
                )
                if not m_user:
                    continue
                uname = m_user.group(2)
                if uname.lower() in ("root", "telemt", "system", "service", "client"):
                    continue
                _ensure(uname)
                if ts:
                    result[uname]["last_seen"] = ts
                elif last_ts:
                    if result[uname]["last_seen"] == "—":
                        result[uname]["last_seen"] = last_ts
                if _SESSION_RE.search(line):
                    result[uname]["sessions"] += 1
        except Exception:
            pass

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

def _collect(d: dict, max_days: int = 1) -> dict:
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
    sessions = _parse_journal(since=since if since else None, max_days=max_days)

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

    # ── Fallback для last_seen: если у пользователя есть трафик (rx>0 или
    # tx>0) но last_seen="—" (ни одна строка journalctl не сматчилась на
    # user=<name> с timestamp) — используем d["total"]["updated"] как
    # приблизительное время последней активности. Это лучше чем "—" для
    # активных пользователей, чьи логи telemt пишутся в формате, который
    # не распознаётся текущим парсером (например, multiline-сообщения,
    # или format без явного user= в строке с timestamp).
    #
    # ВАЖНО: fallback применяется ТОЛЬКО к пользователям с ненулевым
    # трафиком. Если rx=0 и tx=0 — пользователь никогда не подключался,
    # оставляем "—" (не выдумываем время для пустого пользователя).
    #
    # Применяется ПОСЛЕ распределения байт, чтобы распределённый трафик
    # тоже учитывался в условии rx>0/tx>0 (для пользователей, у которых
    # трафик не был явно установлен ранее).
    _total_updated = d["total"].get("updated", "") or _now_str()
    for uname, udata in d["users"].items():
        if (udata.get("last_seen", "—") == "—"
                and (udata.get("rx", 0) > 0 or udata.get("tx", 0) > 0)):
            udata["last_seen"] = _total_updated

    d["total"]["updated"] = _now_str()
    return d

# ══════════════════════════════════════════════════════════════════════════════
#  ОТОБРАЖЕНИЕ СТАТИСТИКИ
# ══════════════════════════════════════════════════════════════════════════════
def _render_stats(d: dict, realtime: bool = False, max_days: int = 1) -> None:
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
    _box_row(f"  {BOLD}{CYAN}👥 По пользователям{NC}")
    # Показываем текущий период чтения журнала.
    _box_row(f"  {DIM}Журнал: последние {max_days} дн.{NC}")
    _box_row()
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
        _box_item("5", "🔍  Диагностика Telemt API (для панели)")
        _box_sep()
        # Показываем текущий период и предлагаем сменить.
        period_label = {1: "24 часа", 3: "3 дня", 7: "7 дней"}.get(max_days, f"{max_days} дн.")
        _box_row(f"  {DIM}Период журнала: {period_label}{NC}")
        _box_item("6", "📅  Изменить период журнала (1/3/7 дней)")
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
    # Период чтения журнала (дней). По умолчанию 1 = 24 часа (быстро).
    # Пользователь может сменить через пункт [6].
    max_days = 1

    while True:
        os.system("clear")
        d = _collect(d, max_days=max_days)
        _save_stats(d)
        _render_stats(d, realtime=False, max_days=max_days)
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
                    d = _collect(d, max_days=max_days)
                    _save_stats(d)
                    _render_stats(d, realtime=True, max_days=max_days)
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

        elif ch == "5":
            # Диагностика Telemt API — почему Telemt Panel может показывать
            # 0 traffic / 0 connections, хотя TUI Chimera видит трафик.
            # Panel берёт статистику из HTTP API telemt (127.0.0.1:9091),
            # а TUI Chimera — из iptables-цепочек TELEMT_STATS_IN/OUT. Это
            # независимые источники: TUI работает даже если API telemt не
            # считает трафик.
            os.system("clear")
            print()
            _box_top("🔍  ДИАГНОСТИКА TELEMT API (ДЛЯ ПАНЕЛИ)")
            _box_row()
            _box_row(f"  {DIM}Panel (веб-панель) берёт статистику из HTTP API telemt{NC}")
            _box_row(f"  {DIM}(127.0.0.1:9091). TUI Chimera — из iptables-цепочек{NC}")
            _box_row(f"  {DIM}TELEMT_STATS_IN/OUT. Это независимые источники.{NC}")
            _box_row(f"  {DIM}Если TUI видит трафик, а Panel — нет, проблема в API telemt.{NC}")
            _box_row()
            try:
                diag = diagnose_telemt_api_for_panel()
                _render_telemt_api_diagnosis(diag)
            except Exception as e:
                _box_row(f"  {RED}✗ Ошибка диагностики: {e}{NC}")
                _box_sep()
            _box_bot()
            _pause()

        elif ch == "6":
            # Смена периода чтения журнала.
            os.system("clear")
            print()
            _box_top("📅  ПЕРИОД ЧТЕНИЯ ЖУРНАЛА")
            _box_row()
            _box_row(f"  {DIM}Журнал telemt читается для last_seen и sessions.{NC}")
            _box_row(f"  {DIM}Больше период — больше данных, но дольше загрузка.{NC}")
            _box_sep()
            cur_label = {1: "24 часа (быстро)", 3: "3 дня", 7: "7 дней (медленно)"}.get(max_days, f"{max_days} дн.")
            _box_row(f"  Текущий: {GREEN}{cur_label}{NC}")
            _box_sep()
            _box_item("1", "24 часа  {DIM}(быстро, по умолчанию){NC}")
            _box_item("2", "3 дня   {DIM}(средне){NC}")
            _box_item("3", "7 дней  {DIM}(медленно, максимум){NC}")
            _box_sep()
            _box_item("Q", "← Отмена")
            _box_bot()
            try:
                pch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
            except _Cancelled:
                continue
            if pch == "1":
                max_days = 1
                print(f"\n  {GREEN}✓ Период: 24 часа{NC}")
            elif pch == "2":
                max_days = 3
                print(f"\n  {GREEN}✓ Период: 3 дня{NC}")
            elif pch == "3":
                max_days = 7
                print(f"\n  {GREEN}✓ Период: 7 дней{NC}")
            else:
                continue
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
