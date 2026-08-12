"""
chimera/modules/mtproto_stats.py
───────────────────────────────────────────────────────────────────────────────
Статистика трафика Telemt MTProxy — зрелая реализация.

Принцип работы (мигрировано с iptables на nftables, этап 1.5):
  1. nftables ACCOUNTING: regular-цепочки `telemt_stats_in` / `telemt_stats_out`
     в таблице `inet chimera` считают байты на порту telemt (через правила
     вида `tcp dport <port> counter return comment "telemt-stats-counter"`).
     Jump-правила из `input`/`output` направляют трафик в эти цепочки.
     Cron сбрасывает счётчики в 00:00 (re-create chain = `flush` + re-add
     counter rule).
  2. Суточные данные сохраняются в stats.json (накапливаются, не теряются
     после ночного сброса счётчиков).
  3. Суммарный трафик = сумма по всем дням в stats.json.
  4. Per-user статистика: journalctl логи telemt (сессии + last_seen),
     байты распределяются пропорционально сессиям.

Публичные точки входа:
    stats_menu()                   ← вызывается из mtproto.py
    setup_iptables_accounting(port) ← вызывается из mtproto.py при установке
                                     (имя сохранено для обратной совместимости
                                     с mtproto._setup_accounting; внутри делегирует
                                     в nft_common.nft_chain_ensure / nft_rule_add /
                                     nft_rule_counter_read).
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

# nftables — централизованная обёртка над `nft` CLI (этап 1.5 миграции).
# Заменяет прямые вызовы `iptables -N/-A/-I/-D/-L/-Z/-F` на идемпотентные
# функции с JSON-парсингом. Семантика: считаются те же байты на том же порту,
# только через counter-выражение в правиле nftables вместо отдельной цепочки
# `iptables -L TELEMT_STATS_IN -v -n -x` парсинга.
from .nft_common import (
    nft_chain_ensure, nft_chain_exists, nft_chain_flush,
    nft_rule_add, nft_rule_insert, nft_rule_exists,
    nft_rule_delete_by_comment, nft_rule_counter_read,
    nft_persist, _nft_available,
)
from .nft_constants import (
    NFT_TABLE_NAME, NFT_TABLE_FAMILY,
    NFT_CHAIN_INPUT, NFT_CHAIN_OUTPUT,
    NFT_CHAIN_TELEMT_STATS_IN, NFT_CHAIN_TELEMT_STATS_OUT,
    NFT_PERSIST_FILE,
)

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
# Wrapper bash-скрипт для cron-сброса nftables счётчиков в 00:00 (этап 1.5:
# раньше был bare `iptables -Z CHAIN_IN && iptables -Z CHAIN_OUT` — теперь
# нужен Python для вызова nft_chain_flush + nft_rule_add, т.к. counter в nft
# встроен в правило и не имеет команды `nft counter zero` для rule-counter'ов).
RESET_COUNTERS_SCRIPT = Path("/usr/local/sbin/telemt-stats-reset.sh")
# Legacy имена цепочек (для сохранения совместимости с внешним кодом и
# документацией в stats.json). Реальные nftables цепочки живут в таблице
# `inet chimera` с именами из nft_constants: telemt_stats_in / telemt_stats_out.
CHAIN_IN     = "TELEMT_STATS_IN"   # legacy alias; nft chain = NFT_CHAIN_TELEMT_STATS_IN
CHAIN_OUT    = "TELEMT_STATS_OUT"  # legacy alias; nft chain = NFT_CHAIN_TELEMT_STATS_OUT
SERVICE_NAME = "telemt"

# ── Comment-tags для nftables правил ─────────────────────────────────────────
# Counter-правила в цепочках telemt_stats_in/out несут один и тот же
# comment-tag (одинаковый для обоих направлений) — `nft_rule_counter_read`
# различает rx/tx по имени цепочки, а не по comment. Это упрощает cleanup.
_COMMENT_STATS_COUNTER = "telemt-stats-counter"  # counter rule in telemt_stats_in/out
_COMMENT_JUMP_IN       = "telemt-stats-jump-in"  # jump INPUT → telemt_stats_in
_COMMENT_JUMP_OUT      = "telemt-stats-jump-out"  # jump OUTPUT → telemt_stats_out

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
#  NFTABLES ACCOUNTING (мигрировано с iptables, этап 1.5)
# ══════════════════════════════════════════════════════════════════════════════
# ИСТОРИЧЕСКАЯ СПРАВКА (для аудита миграции):
# Раньше (iptables) учёт шёл через цепочки TELEMT_STATS_IN / TELEMT_STATS_OUT
# в table=filter, jump-правила в INPUT/OUTPUT. Counter был implicit per-rule,
# парсинг `iptables -L <chain> -v -n -x` извлекал колонку `bytes`.
#
# Известный баг iptables: `iptables -L -n` выводил протокол числом ("6" вместо
# "tcp"), что ломало парсер jump-правил на реальном сервере. Раньше это обходили
# через `_TCP_PROTO_TOKENS = frozenset({"tcp", "6"})`. В nftables JSON такой
# проблемы НЕТ — протокол всегда строка "tcp".
#
# Теперь (nftables, этап 1.5):
#   • regular-цепочки `telemt_stats_in` / `telemt_stats_out` в `inet chimera`
#     (создаются через nft_chain_ensure без hook — аналог `iptables -N`).
#   • jump-правила в `input` / `output` направляют трафик на нужный порт в
#     эти цепочки (через nft_rule_insert с comment-tag).
#   • Внутри цепочки одно правило с embedded-counter:
#       `tcp dport <port> counter return comment "telemt-stats-counter"`
#     Counter инкрементируется при проходе пакета через правило.
#   • Чтение counter — через `nft_rule_counter_read(table, chain, comment=...)`
#     → JSON-парсинг `nft -j list chain inet chimera telemt_stats_in`.
#   • Ночной сброс (cron 00:00) — flush цепочки + re-add counter-rule
#     (counter в nftables не имеет команды `zero` для rule-counter'ов, только
#     для named counters; пересоздание правила эквивалентно `iptables -Z`).
def _nft_chain_for(direction: str) -> str:
    """Возвращает имя nft-цепочки для направления ('in' / 'out').

    Args:
      direction: "in" для входящего (CHAIN_IN, dport) или "out" для
                 исходящего (CHAIN_OUT, sport).

    Returns:
      NFT_CHAIN_TELEMT_STATS_IN или NFT_CHAIN_TELEMT_STATS_OUT.
    """
    return NFT_CHAIN_TELEMT_STATS_IN if direction == "in" else NFT_CHAIN_TELEMT_STATS_OUT


def _nft_jump_comment(direction: str) -> str:
    """Comment-tag для jump-правила (INPUT→telemt_stats_in или OUTPUT→..._out)."""
    return _COMMENT_JUMP_IN if direction == "in" else _COMMENT_JUMP_OUT


def _nft_chain_exists(chain: str) -> bool:
    """Проверяет существование nft-цепочки в таблице chimera.

    Заменяет: `iptables -L <chain> -n` (returncode==0 означал существование).
    Теперь: nft_chain_exists(table, chain) через `nft list chain inet chimera <chain>`.
    """
    return nft_chain_exists(table=NFT_TABLE_NAME, chain=chain, family=NFT_TABLE_FAMILY)


def _nft_jump_exists(direction: str, port: int) -> bool:
    """Проверяет наличие jump-правила INPUT→telemt_stats_in (или OUTPUT→..._out).

    Заменяет: парсинг `iptables -L INPUT -v -n` с поиском строки вида
              `tcp dpt:PORT  --  target=CHAIN_IN`. Требовало _TCP_PROTO_TOKENS
              из-за бага `iptables -L -n` (протокол числом).
    Теперь: nft_rule_exists(comment="telemt-stats-jump-in"/"-out") через
            `nft -j list chain` — без проблем с числовым протоколом.
    """
    return nft_rule_exists(
        table=NFT_TABLE_NAME,
        chain=NFT_CHAIN_INPUT if direction == "in" else NFT_CHAIN_OUTPUT,
        comment=_nft_jump_comment(direction),
        family=NFT_TABLE_FAMILY,
    )


def _nft_remove_all_jumps(direction: str) -> int:
    """Удаляет ВСЕ jump-правила указанного направления (in/out).

    Заменяет: цикл `iptables -D INPUT -p tcp --dport <port> -j CHAIN_IN` до
              returncode!=0 (с защитным лимитом 50 итераций).
    Теперь: один вызов nft_rule_delete_by_comment(table, "input"/"output",
            comment=_nft_jump_comment(direction), max_iterations=50).
    Возвращает количество удалённых правил.
    """
    parent_chain = NFT_CHAIN_INPUT if direction == "in" else NFT_CHAIN_OUTPUT
    return nft_rule_delete_by_comment(
        table=NFT_TABLE_NAME, chain=parent_chain,
        comment=_nft_jump_comment(direction),
        family=NFT_TABLE_FAMILY, max_iterations=50,
    )


# Legacy aliases — сохранены для обратной совместимости со старыми тестами
# и любым внешним кодом, который мог импортировать эти имена. Делегируют в
# новые nft-функции. Больше не делают прямых subprocess-вызовов `iptables`.
def _ipt_chain_exists(chain: str) -> bool:
    """DEPRECATED (этап 1.5): alias для _nft_chain_exists.

    Исторически проверял существование iptables-цепочки через
    `iptables -L <chain> -n`. Теперь проверяет nft-цепочку.
    """
    # chain — legacy имя (CHAIN_IN/CHAIN_OUT = "TELEMT_STATS_IN/OUT").
    # Мапируем на актуальное nft-имя.
    nft_chain = (NFT_CHAIN_TELEMT_STATS_IN
                 if chain == CHAIN_IN
                 else NFT_CHAIN_TELEMT_STATS_OUT if chain == CHAIN_OUT
                 else chain)
    return _nft_chain_exists(nft_chain)


def _ipt_jump_exists(parent: str, chain: str, port: int, direction: str) -> bool:
    """DEPRECATED (этап 1.5): alias для _nft_jump_exists(direction).

    Сигнатура сохранена для совместимости с тестами. Параметры parent/chain/port
    игнорируются — теперь поиск идёт по comment-tag, а не по парсингу вывода.
    direction: "dport" → "in", "sport" → "out".
    """
    direction_norm = "in" if direction == "dport" else "out"
    return _nft_jump_exists(direction_norm, port)


def _ipt_remove_all_jumps(parent: str, chain: str, port: int,
                          direction: str) -> int:
    """DEPRECATED (этап 1.5): alias для _nft_remove_all_jumps(direction).

    Сигнатура сохранена для совместимости со старыми тестами. Параметры
    parent/chain/port игнорируются.
    """
    direction_norm = "in" if direction == "dport" else "out"
    return _nft_remove_all_jumps(direction_norm)


def setup_iptables_accounting(port: int) -> bool:
    """
    Публичная функция — вызывается из mtproto.py при установке.
    Создаёт nft-цепочки `telemt_stats_in` / `telemt_stats_out` в таблице
    `inet chimera`, добавляет jump-правила из `input`/`output` и counter-правила
    внутри этих цепочек.

    Каждый вызов сначала очищает counter-цепочки и удаляет все jump-правила
    (через nft_rule_delete_by_comment с max_iterations=50), потом добавляет
    ровно по одному новому — так избегаем дублирования счётчиков.

    Возвращает True только если ВСЕ четыре проверки постфактум подтверждают
    факт установки:
      • цепочка telemt_stats_in существует
      • цепочка telemt_stats_out существует
      • jump-правило из input в telemt_stats_in для порта port стоит
      • jump-правило из output в telemt_stats_out для порта port стоит

    Миграция (этап 1.5):
      • `iptables -N TELEMT_STATS_IN` → nft_chain_ensure("chimera", "telemt_stats_in")
      • `iptables -I INPUT 1 -p tcp --dport <port> -j TELEMT_STATS_IN`
        → nft_rule_insert("chimera", "input", "tcp dport <port> jump telemt_stats_in",
          comment="telemt-stats-jump-in")
      • `iptables -F TELEMT_STATS_IN`
        → nft_chain_flush("chimera", "telemt_stats_in")
      • `iptables -A TELEMT_STATS_IN -p tcp --dport <port> -j RETURN`
        → nft_rule_add("chimera", "telemt_stats_in",
          "tcp dport <port> counter return", comment="telemt-stats-counter")
      • Постфактум-верификация через nft_chain_exists + nft_rule_exists(comment=...).
        ВАЖНО: больше НЕ нужен _TCP_PROTO_TOKENS = {"tcp", "6"} — в nftables JSON
        протокол всегда строка "tcp" (баг iptables -L -n исправлен переходом на nft).
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

    # Если nft недоступен — немедленно возвращаем False (бессмысленно пытаться).
    if not _nft_available():
        _warn_local("nft binary not available — cannot setup accounting")
        return False

    # ── Создаём regular-цепочки (аналог `iptables -N CHAIN`) ────────────────
    nft_chain_ensure(table=NFT_TABLE_NAME, chain=NFT_CHAIN_TELEMT_STATS_IN,
                     family=NFT_TABLE_FAMILY)
    nft_chain_ensure(table=NFT_TABLE_NAME, chain=NFT_CHAIN_TELEMT_STATS_OUT,
                     family=NFT_TABLE_FAMILY)

    # ── ИДЕМПОТЕНТНАЯ ОЧИСТКА старых jump-правил ─────────────────────────────
    # Удаляем ВСЕ ранее установленные jump-правила (сколько бы их ни было —
    # 0, 1 или больше) перед созданием новых. Цикл до исчерпания через
    # nft_rule_delete_by_comment (ищет все правила с comment=tag и удаляет
    # по handle). Если >1 — логируем как сигнал копившегося дублирования.
    removed_in = _nft_remove_all_jumps("in")
    removed_out = _nft_remove_all_jumps("out")
    if removed_in > 1:
        _info_local(
            f"removed {removed_in} duplicate input jump-rules to "
            f"{NFT_CHAIN_TELEMT_STATS_IN} (dport={port}) — pre-existing "
            f"duplication detected"
        )
    if removed_out > 1:
        _info_local(
            f"removed {removed_out} duplicate output jump-rules to "
            f"{NFT_CHAIN_TELEMT_STATS_OUT} (sport={port}) — pre-existing "
            f"duplication detected"
        )

    # input → telemt_stats_in (одно новое jump-правило с comment-tag)
    nft_rule_insert(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        rule_spec=f"tcp dport {port} jump {NFT_CHAIN_TELEMT_STATS_IN}",
        comment=_COMMENT_JUMP_IN, family=NFT_TABLE_FAMILY, idempotent=False,
    )
    # output → telemt_stats_out
    nft_rule_insert(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_OUTPUT,
        rule_spec=f"tcp sport {port} jump {NFT_CHAIN_TELEMT_STATS_OUT}",
        comment=_COMMENT_JUMP_OUT, family=NFT_TABLE_FAMILY, idempotent=False,
    )

    # ── Flush + counter-rules в самих цепочках ───────────────────────────────
    # flush убирает старые counter-правила (если были), потом добавляем ровно
    # одно новое. Counter встроен в правило (не named counter), поэтому
    # `nft_chain_flush` + `nft_rule_add` эквивалентно `iptables -F && iptables -A`.
    nft_chain_flush(table=NFT_TABLE_NAME, chain=NFT_CHAIN_TELEMT_STATS_IN,
                    family=NFT_TABLE_FAMILY)
    nft_chain_flush(table=NFT_TABLE_NAME, chain=NFT_CHAIN_TELEMT_STATS_OUT,
                    family=NFT_TABLE_FAMILY)
    nft_rule_add(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_TELEMT_STATS_IN,
        rule_spec=f"tcp dport {port} counter return",
        comment=_COMMENT_STATS_COUNTER, family=NFT_TABLE_FAMILY, idempotent=False,
    )
    nft_rule_add(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_TELEMT_STATS_OUT,
        rule_spec=f"tcp sport {port} counter return",
        comment=_COMMENT_STATS_COUNTER, family=NFT_TABLE_FAMILY, idempotent=False,
    )

    # ── Постфактум-верификация ───────────────────────────────────────────────
    # Все 4 проверки обязаны пройти. Если хотя бы одна не прошла — возвращаем
    # False и логируем конкретную причину.
    if not _nft_chain_exists(NFT_CHAIN_TELEMT_STATS_IN):
        _warn_local(f"chain {NFT_CHAIN_TELEMT_STATS_IN} does not exist after nft_chain_ensure")
    if not _nft_chain_exists(NFT_CHAIN_TELEMT_STATS_OUT):
        _warn_local(f"chain {NFT_CHAIN_TELEMT_STATS_OUT} does not exist after nft_chain_ensure")
    if not _nft_jump_exists("in", port):
        _warn_local(f"input jump-rule to {NFT_CHAIN_TELEMT_STATS_IN} for dport={port} not found")
    if not _nft_jump_exists("out", port):
        _warn_local(f"output jump-rule to {NFT_CHAIN_TELEMT_STATS_OUT} for sport={port} not found")

    if _fail_reasons:
        # Не Critical-fail cron-установку и persist — эти шаги могут
        # пригодиться при ручной починке nftables. Но возвращаем False,
        # чтобы mtproto.py показал честный warn, а не фейковый success.
        pass

    # Cron: сброс счётчиков в 00:00 + проверка лимитов каждые 5 мин.
    #
    # v5.1: проверка лимитов раньше шла через bare `python3 -c "from
    # chimera.modules.mtproto import mtproto_check_limits; ..."` — это
    # НЕ работало, потому что cron запускается с произвольной cwd и без
    # PYTHONPATH, и `from chimera...` падал с ModuleNotFoundError.
    # Паттерн исправления — wrapper bash-скрипт (как в
    # node_health_monitor.py::install_health_monitor и geo_files.py).
    #
    # v6 (этап 1.5): nightly counter-reset тоже делается через wrapper
    # bash-скрипт, потому что counter в nftables встроен в правило (нет
    # отдельной команды `nft counter zero` для rule-counter'ов) — нужно
    # flush + re-add rule. Bare `nft` команда в cron слишком сложна для
    # одной строки, поэтому вызываем Python.

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

    # Wrapper bash-скрипт для проверки лимитов (как раньше).
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

    # Wrapper bash-скрипт для nightly counter-reset (новый в этапе 1.5).
    # Вызывает _reset_accounting() — flush + re-add counter rules.
    try:
        reset_content = (
            "#!/bin/bash\n"
            f"# Telemt stats counter reset (wrapper для cron; v6/этап-1.5: PYTHONPATH-safe).\n"
            f"# Заменяет bare `iptables -Z TELEMT_STATS_IN && iptables -Z TELEMT_STATS_OUT`.\n"
            f"# nftables counter встроен в правило, поэтому нужен Python для flush+re-add.\n"
            f"export PYTHONPATH=\"{installer_path}:$PYTHONPATH\"\n"
            f"/usr/bin/python3 -c \"\n"
            f"import sys\n"
            f"sys.path.insert(0, '{installer_path}')\n"
            f"from chimera.modules.mtproto_stats import _reset_accounting\n"
            f"_reset_accounting()\n"
            f"\" # telemt-stats-reset\n"
        )
        RESET_COUNTERS_SCRIPT.write_text(reset_content)
        RESET_COUNTERS_SCRIPT.chmod(0o755)
    except Exception:
        pass

    # Cron-файл: nightly reset счётчиков через wrapper (00:00)
    # + проверка лимитов каждые 5 мин через wrapper (как раньше).
    try:
        CRON_FILE.write_text(
            f"0 0 * * * root {RESET_COUNTERS_SCRIPT} # telemt-stats-reset\n"
            f"*/5 * * * * root {LIMITS_CHECK_SCRIPT} # telemt-limits-check\n"
        )
        CRON_FILE.chmod(0o644)
    except Exception:
        pass

    # ── Persist ──────────────────────────────────────────────────────────────
    # Сохраняем nft ruleset в /etc/nftables.conf через единый nftables.service.
    # Заменяет netfilter-persistent save + iptables-save > /etc/iptables/rules.v4.
    _persist_accounting_rules()

    return len(_fail_reasons) == 0

def _persist_accounting_rules() -> None:
    """
    Сохраняет текущий nft ruleset (включая telemt_stats_in/out, jump-правила
    и counter-rules) в /etc/nftables.conf через единый nftables.service.

    Заменяет (best-effort persist-логика):
      • `netfilter-persistent save` (если установлен)
      • Fallback: `iptables-save > /etc/iptables/rules.v4`
    Теперь: один вызов `nft_persist()` → `nft list ruleset > /etc/nftables.conf`
            + включение встроенного `nftables.service` через
            `nft_persist_enable_systemd()`. При ребуте системы стандартный
            nftables.service читает /etc/nftables.conf через `nft -f` и
            восстанавливает ВСЕ правила Chimera.

    Не падает, если nft недоступен — правило просто не переживёт перезагрузку,
    что некритично (модуль можно повторно активировать через меню).
    """
    if not _nft_available():
        return
    try:
        nft_persist(NFT_PERSIST_FILE)
        from .nft_common import nft_persist_enable_systemd
        nft_persist_enable_systemd()
    except Exception:
        pass

def _read_chain_bytes(chain: str) -> int:
    """
    Читает байты из counter-правила в nft-цепочке.

    Заменяет: парсинг `iptables -L <chain> -v -n -x` с извлечением 2-й колонки
              (bytes) первой строки правила.
    Теперь: nft_rule_counter_read(table, <nft_chain>, comment="telemt-stats-counter")
            → JSON-парсинг `nft -j list chain inet chimera <chain>` → counter expr.

    Берёт ТОЛЬКО первое правило с comment=telemt-stats-counter (chain flush
    перед добавлением гарантирует, что такое правило ровно одно — без
    дублирования при повторных вызовах setup_iptables_accounting).

    Args:
      chain: legacy имя цепочки (CHAIN_IN="TELEMT_STATS_IN" или
             CHAIN_OUT="TELEMT_STATS_OUT"). Мапируется на актуальное
             nft-имя из nft_constants.
    """
    nft_chain = (NFT_CHAIN_TELEMT_STATS_IN
                 if chain == CHAIN_IN
                 else NFT_CHAIN_TELEMT_STATS_OUT if chain == CHAIN_OUT
                 else chain)
    cnt = nft_rule_counter_read(
        table=NFT_TABLE_NAME, chain=nft_chain,
        comment=_COMMENT_STATS_COUNTER, family=NFT_TABLE_FAMILY,
    )
    return int(cnt.get("bytes", 0))

def _reset_accounting() -> None:
    """Сбрасывает counter-правила в telemt_stats_in/out (аналог `iptables -Z`).

    Реализация: nft_chain_flush + nft_rule_add повторно для каждой цепочки.
    Counter в nftables встроен в правило (не named counter), поэтому
    отдельной команды `nft counter zero` для rule-counter'ов нет — пересоздание
    правила даёт тот же эффект (counter снова начинает считать с 0).

    Порт telemt берётся из CONFIG_FILE (если доступен), иначе fallback 8443.
    """
    if not _nft_available():
        return
    port = _get_port()
    # Flush обеих цепочек
    nft_chain_flush(table=NFT_TABLE_NAME, chain=NFT_CHAIN_TELEMT_STATS_IN,
                    family=NFT_TABLE_FAMILY)
    nft_chain_flush(table=NFT_TABLE_NAME, chain=NFT_CHAIN_TELEMT_STATS_OUT,
                    family=NFT_TABLE_FAMILY)
    # Re-add counter rules (counter снова начинает считать с 0)
    nft_rule_add(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_TELEMT_STATS_IN,
        rule_spec=f"tcp dport {port} counter return",
        comment=_COMMENT_STATS_COUNTER, family=NFT_TABLE_FAMILY, idempotent=False,
    )
    nft_rule_add(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_TELEMT_STATS_OUT,
        rule_spec=f"tcp sport {port} counter return",
        comment=_COMMENT_STATS_COUNTER, family=NFT_TABLE_FAMILY, idempotent=False,
    )

def _accounting_active() -> bool:
    """Проверяет что nft-цепочки учёта существуют.

    Заменяет: `_ipt_chain_exists(CHAIN_IN) and _ipt_chain_exists(CHAIN_OUT)`.
    Теперь: nft_chain_exists для обоих nft-имён.
    """
    return (_nft_chain_exists(NFT_CHAIN_TELEMT_STATS_IN)
            and _nft_chain_exists(NFT_CHAIN_TELEMT_STATS_OUT))


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
    _box_kv("Accounting:", (f"{GREEN}nftables активен{NC}" if ipt_ok
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
        _box_item("3", "⚡  Включить / переинициализировать учёт nftables")
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
                    print(f"\n  {GREEN}✓  nftables-учёт активирован.{NC}")
                    print(f"  {GREEN}✓  Cron-сброс счётчиков в 00:00 установлен.{NC}")
                else:
                    # setup_iptables_accounting вернула False — постфактум-
                    # верификация обнаружила что цепочки или jump-правила
                    # не появились. Детали уже залогированы в chimera.log.
                    d["ipt_ok"] = False
                    _save_stats(d)
                    print(f"\n  {YELLOW}⚠  nftables-учёт НЕ активирован.{NC}")
                    print(f"  {YELLOW}  Постфактум-верификация обнаружила, что цепочки "
                          f"telemt_stats_in/out{NC}")
                    print(f"  {YELLOW}  или jump-правила из input/output не создались.{NC}")
                    print(f"  {DIM}  Возможные причины: контейнер без CAP_NET_ADMIN, "
                          f"ядро без netfilter-модуля,{NC}")
                    print(f"  {DIM}  nft binary недоступен или /etc/nftables.conf "
                          f"нечитаем.{NC}")
                    print(f"  {DIM}  Подробности — в /var/log/chimera.log "
                          f"(WARN от mtproto_stats.setup_iptables_accounting).{NC}")
            except Exception as e:
                print(f"\n  {YELLOW}⚠  Не удалось настроить nftables: {e}{NC}")
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
