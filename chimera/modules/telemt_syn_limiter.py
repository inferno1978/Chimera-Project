"""
chimera/modules/telemt_syn_limiter.py
───────────────────────────────────────────────────────────────────────────────
Per-IP лимитер входящих SYN-пакетов для Telemt — стабилизация TCP-рукопожатия.

Контекст
────────
Симптом: клиент Telegram у части пользователей зависает в статусе
"Подключение..." на неопределённое время, либо подключается и затем рвётся —
причём `client_mss` (фрагментация ClientHello против TSPU/JA4, см.
telemt_mss_selector.py) здесь не помогает, потому что это другая проблема:

  • client_mss решает детект DPI по TLS-фингерпринту.
  • Зависание в "Подключение..." часто вызвано ретрай-штормом SYN: клиент
    в нестабильной сети (мобильный интернет, агрессивный NAT) не получает
    SYN/ACK вовремя и шлёт повторные SYN, которые накладываются на старое
    полуоткрытое соединение. Сервер видит лавину SYN с одного IP и либо
    тратит ресурсы на обработку дублей, либо conntrack/backlog не успевает —
    клиент закономерно не может завершить handshake.

Решение — секционировать SYN-трафик по клиентскому IP так, чтобы один
"шумный" клиент не создавал нагрузку, которая мешает остальным, и чтобы
дублирующиеся SYN от одного и того же клиента отбрасывались, давая TCP-стеку
шанс довести до конца уже начатое соединение.

Механизм (мигрировано с iptables `hashlimit` на nftables `meter`, этап 1.4):

  Раньше (iptables + hashlimit):
    iptables -A INPUT -p tcp --dport <PORT> --syn \
        -m hashlimit --hashlimit-name telemt_syn \
        --hashlimit-mode srcip --hashlimit-srcmask 32 \
        --hashlimit-upto <RATE>/sec --hashlimit-burst <BURST> \
        --hashlimit-htable-expire <EXPIRE_MS> \
        -j ACCEPT -m comment --comment telemt-syn-limit
    iptables -A INPUT -p tcp --dport <PORT> --syn -j REJECT --reject-with tcp-reset \
        -m comment --comment telemt-syn-limit

  Теперь (nftables + meter — более мощный аналог hashlimit):
    nft add rule inet chimera input tcp dport <PORT> tcp flags syn / syn,rst \
        meter telemt_syn_limit { ip saddr limit rate <RATE>/second burst <BURST> packets } \
        accept comment "telemt-syn-limit-accept"
    nft add rule inet chimera input tcp dport <PORT> tcp flags syn / syn,rst \
        reject with tcp reset comment "telemt-syn-limit-reject"

Первое правило пропускает SYN в пределах лимита на src-IP (через meter —
динамический набор элементов с per-IP счётчиком), второе — отбрасывает всё,
что превысило лимит для данного IP, сразу с TCP RST (а не тихим DROP), чтобы
клиент не ждал таймаут и реконнектился мгновенно. Не-SYN пакеты (уже
установленные соединения) правило не трогает.

`meter` в nftables превосходит `hashlimit` из iptables тем, что:
  • Не требует `--hashlimit-htable-expire` — элементы meter истекают по
    таймауту самого limit (по умолчанию 1 секунда после последнего пакета).
  • Поддерживает более сложные условия (например, набор адресов через set).
  • Имеет нативный JSON-вывод через `nft -j list chain` — счётчики
    accept/reject читаются напрямую без парсинга текста.

Пресеты (по аналогии с mtpr.sh, адаптированы под nftables meter):
  • жёсткий   — 1/sec  burst 1   (рекомендуется по умолчанию)
  • средний   — 1/sec  burst 3
  • мягкий    — 2/sec  burst 5
  • свой      — произвольные rate/burst

Гарантии совместимости
──────────────────────
  • Модуль работает только с правилами INPUT для порта Telemt — не трогает
    REDIRECT-правила xray/tproxy (другая chain-логика, другой match).
  • Все правила маркируются комментарием `telemt-syn-limit-accept` /
    `telemt-syn-limit-reject` (из nft_constants) — отключение модуля удаляет
    ТОЛЬКО эти правила, ничего больше.
  • persist делается через единый `nft_persist()` → /etc/nftables.conf
    + встроенный `nftables.service` (заменяет `netfilter-persistent save` +
    `iptables-save` + кастомные restore-unit'ы).
  • Установка/удаление идемпотентны: повторный enable() не плодит дубликаты
    правил — сначала disable(), потом добавление актуальных.

Интеграция с mtproto.py
───────────────────────
  Vызывается из mtproto_menu() через lazy-import (как telemt_fallback):
      from chimera.modules.telemt_syn_limiter import syn_limiter_menu
      syn_limiter_menu()

  Не требует параметров от mtproto.py — порт читается из telemt.toml
  напрямую (тот же паттерн регулярки, что в _get_port()).
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
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

# nftables — централизованная обёртка над `nft` CLI (этап 1.4 миграции)
from .nft_common import (
    nft_syn_limiter, nft_rule_exists, nft_rule_delete_by_comment,
    nft_rule_counter_read, nft_persist, _nft_available,
)
from .nft_constants import (
    NFT_TABLE_NAME, NFT_TABLE_FAMILY, NFT_CHAIN_INPUT,
    COMMENT_SYN_LIMIT_ACCEPT, COMMENT_SYN_LIMIT_REJECT,
    NFT_PERSIST_FILE,
)

# ══════════════════════════════════════════════════════════════════════════════
#  ПУТИ И КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════
_CONFIG_FILE   = Path("/etc/telemt/telemt.toml")
_SERVICE_NAME  = "telemt"
_STATE_FILE    = Path("/var/lib/xray-installer/telemt_syn_limiter.json")
# Comment-tags для nft-правил (раньше — один "telemt-syn-limit" на оба правила
# iptables; теперь два отдельных: accept и reject, для более точного cleanup).
_COMMENT_TAG_ACCEPT = COMMENT_SYN_LIMIT_ACCEPT   # "telemt-syn-limit-accept"
_COMMENT_TAG_REJECT = COMMENT_SYN_LIMIT_REJECT   # "telemt-syn-limit-reject"
# Базовый comment, передаваемый в nft_syn_limiter — функция сама добавит
# суффиксы "-accept" / "-reject".
_COMMENT_TAG_BASE   = "telemt-syn-limit"
# Legacy alias для отображения в TUI (одно имя, без -accept/-reject).
_COMMENT_TAG   = _COMMENT_TAG_BASE
# Legacy: имя meter (в iptables это был --hashlimit-name telemt_syn).
# В nftables meter_name = base_comment.replace("-", "_") = "telemt_syn_limit".
_HASHLIMIT_NAME = "telemt_syn"

# ══════════════════════════════════════════════════════════════════════════════
#  ЦВЕТА (self-contained, как в telemt_mss_selector.py)
# ══════════════════════════════════════════════════════════════════════════════
def _colors() -> dict:
    if sys.stdout.isatty():
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m',
            WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, WHITE, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'],
    _C['BOLD'], _C['DIM'], _C['WHITE'], _C['NC'],
)

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ (идентичен стилю telemt_mss_selector.py)
# ══════════════════════════════════════════════════════════════════════════════
_BOX_W = 66



def _box_top(title: str = "") -> None:
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    if title:
        pad  = _BOX_W - _wlen(title)
        lpad = pad // 2
        rpad = pad - lpad
        print(f"{CYAN}║{NC}{' ' * lpad}{BOLD}{WHITE}{title}{NC}{' ' * rpad}{CYAN}║{NC}")
        print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")

def _box_sep() -> None: print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")
def _box_bot() -> None: print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")

def _box_row(text: str = "") -> None:
    w = _wlen(text)
    if w > _BOX_W:
        acc = 0
        plain = _plain(text)
        cut = 0
        import unicodedata as _ud
        for i, ch in enumerate(plain):
            acc += 2 if _ud.east_asian_width(ch) in ("W", "F") else 1
            if acc > _BOX_W - 1:
                cut = i; break
        text = text[:cut] + "…"
        w = _wlen(text)
    pad = max(0, _BOX_W - w)
    print(f"{CYAN}║{NC}{text}{chr(32) * pad}{CYAN}║{NC}")

def _box_wrap(text: str, indent: str = "  ") -> None:
    max_w = _BOX_W
    words = _plain(text).split()
    line = indent
    line_w = _wlen(indent)
    indent_w = _wlen(indent)
    for word in words:
        ww = _wlen(word)
        sep_w = 1 if line_w > indent_w else 0
        if line_w + sep_w + ww > max_w:
            pad = max(0, max_w - line_w)
            print(f"{CYAN}║{NC}{line}{chr(32) * pad}{CYAN}║{NC}")
            line = indent + word
            line_w = indent_w + ww
        else:
            if line_w > indent_w:
                line += " "
                line_w += 1
            line += word
            line_w += ww
    if _plain(line).strip():
        pad = max(0, max_w - line_w)
        print(f"{CYAN}║{NC}{line}{chr(32) * pad}{CYAN}║{NC}")

def _box_item(key: str, label: str) -> None:
    col = RED + BOLD if key.strip().upper() in ("Q", "0") else WHITE + BOLD
    _box_row(f"  {DIM}[{NC}{col}{key}{NC}{DIM}]{NC}  {label}")

def _box_ok(msg: str)   -> None: _box_row(f"  {GREEN}✓{NC}  {msg}")
def _box_warn(msg: str) -> None: _box_row(f"  {YELLOW}⚠{NC}  {msg}")
def _box_info(msg: str) -> None: _box_row(f"  {CYAN}→{NC}  {msg}")
def _box_err(msg: str)  -> None: _box_row(f"  {RED}✗{NC}  {msg}")

def _box_kv(key: str, val: str, kw: int = 24) -> None:
    key_col = f"{CYAN}{key}{NC}"
    pad = kw - _wlen(key_col)
    _box_row(f"  {key_col}{' ' * max(0, pad)}  {val}")

# ══════════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ
# ══════════════════════════════════════════════════════════════════════════════
class _Cancelled(Exception):
    pass

def _pause() -> None:
    try:
        print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True); input()
    except (KeyboardInterrupt, EOFError):
        print()

def _ask(prompt: str, default: str = "", c: bool = False) -> str:
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

def _run(cmd: list, capture: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        return subprocess.run(cmd, **kw)
    except Exception:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="error")

def _get_telemt_port() -> int:
    """Читает текущий порт Telemt из telemt.toml. Тот же паттерн, что _get_port() в mtproto.py."""
    if not _CONFIG_FILE.exists():
        return 0
    m = re.search(r'^port\s*=\s*(\d+)', _CONFIG_FILE.read_text(), re.MULTILINE)
    return int(m.group(1)) if m else 0

# ══════════════════════════════════════════════════════════════════════════════
#  ПРЕСЕТЫ
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class SynLimiterConfig:
    enabled: bool = False
    port: int = 0
    rate_per_sec: int = 1
    burst: int = 1
    htable_expire_ms: int = 60000   # 60 сек — время жизни записи в hash-таблице
    preset_name: str = "hard"

_PRESETS = {
    "1": ("hard",   1, 1, "Жёсткий",  "1/sec burst 1 — рекомендуется при нестабильных подключениях", True),
    "2": ("medium", 1, 3, "Средний",  "1/sec burst 3 — если жёсткий режим режет легитимные ретраи", False),
    "3": ("soft",   2, 5, "Мягкий",   "2/sec burst 5 — мягкая защита для серверов с большим числом клиентов", False),
}

# ══════════════════════════════════════════════════════════════════════════════
#  STATE — храним применённую конфигурацию отдельно от telemt.toml
# ══════════════════════════════════════════════════════════════════════════════
def _load_state() -> SynLimiterConfig:
    if not _STATE_FILE.exists():
        return SynLimiterConfig()
    try:
        data = json.loads(_STATE_FILE.read_text())
        return SynLimiterConfig(**{k: data[k] for k in SynLimiterConfig.__dataclass_fields__ if k in data})
    except Exception:
        return SynLimiterConfig()

def _save_state(cfg: SynLimiterConfig) -> None:
    try:
        _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _STATE_FILE.write_text(json.dumps(asdict(cfg), ensure_ascii=False, indent=2))
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════════
#  NFTABLES — управление правилами (замена iptables hashlimit, этап 1.4)
# ══════════════════════════════════════════════════════════════════════════════
def _rule_exists() -> bool:
    """Проверяет, есть ли уже правило с нашим comment-tag в nft chain input.

    Заменяет: `iptables -S INPUT` + поиск `_COMMENT_TAG` в выводе.
    Теперь: nft_rule_exists(comment=...) — ищет правила через `nft -j list chain`.

    Проверяем ОБА comment-tag (accept и reject), т.к. nft_syn_limiter создаёт
    их парой. Достаточно наличия одного из них (другой создаётся в той же
    транзакции, но проверка обоих устойчива к частичным состояниям).
    """
    return (
        nft_rule_exists(
            table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
            comment=_COMMENT_TAG_ACCEPT, family=NFT_TABLE_FAMILY,
        )
        or nft_rule_exists(
            table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
            comment=_COMMENT_TAG_REJECT, family=NFT_TABLE_FAMILY,
        )
    )

def _remove_rules() -> int:
    """
    Удаляет ВСЕ правила INPUT с нашими comment-tag'ами (accept и reject).
    Безопасно вызывать многократно — если правил нет, просто ничего не делает.
    Возвращает количество удалённых правил.

    Заменяет: цикл `iptables -S INPUT` → парсинг строк с comment →
              `iptables -D INPUT ...` для каждой найденной строки (10 итераций).
    Теперь: два вызова nft_rule_delete_by_comment (по одному на каждый тег),
            каждый находит ВСЕ правила с этим comment через `nft -a -j list
            chain` → handles → `nft delete rule ... handle <N>`.
    """
    removed_accept = nft_rule_delete_by_comment(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        comment=_COMMENT_TAG_ACCEPT, family=NFT_TABLE_FAMILY, max_iterations=20,
    )
    removed_reject = nft_rule_delete_by_comment(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        comment=_COMMENT_TAG_REJECT, family=NFT_TABLE_FAMILY, max_iterations=20,
    )
    return removed_accept + removed_reject

def _apply_rules(cfg: SynLimiterConfig) -> tuple[bool, str]:
    """
    Применяет правила meter (per-IP SYN rate limit) для текущего cfg.
    Идемпотентно: сначала удаляет старые правила с нашими тегами, потом
    добавляет новые. Порядок ACCEPT-затем-REJECT важен — nft проходит
    правила по порядку, поэтому ACCEPT (в пределах лимита) должен идти первым.

    Заменяет:
      iptables -I INPUT 1 -p tcp --dport <port> --syn -m hashlimit ... -j ACCEPT
      iptables -I INPUT 2 -p tcp --dport <port> --syn -j REJECT --reject-with tcp-reset
    Теперь: один вызов nft_syn_limiter(port, rate_per_sec, burst, comment=...),
            который внутри себя создаёт ОБА правила (accept + reject) в
            правильном порядке через nft_rule_insert (position=1, потом
            ещё раз position=1 — reject оказывается на позиции 2 после accept).
    """
    if cfg.port <= 0:
        return False, "Не удалось определить порт Telemt — конфиг telemt.toml не найден."

    _remove_rules()  # чистим перед применением — гарантия идемпотентности

    # nft_syn_limiter создаёт пару правил с comment-tag:
    #   "telemt-syn-limit-accept" — ACCEPT при в пределах лимита (meter).
    #   "telemt-syn-limit-reject" — REJECT с tcp-reset при превышении.
    # htable_expire_ms больше не нужен (meter имеет свой таймаут элементов).
    ok = nft_syn_limiter(
        port=cfg.port,
        rate_per_sec=cfg.rate_per_sec,
        burst=cfg.burst,
        comment=_COMMENT_TAG_BASE,  # функция добавит -accept / -reject
        family=NFT_TABLE_FAMILY,
        table=NFT_TABLE_NAME,
        chain=NFT_CHAIN_INPUT,
        idempotent=False,  # уже почистили выше
    )
    if not ok:
        return False, "Ошибка применения правил nft syn limiter (см. логи)."

    return True, "Правила meter (per-IP SYN limit) применены."

def _persist_rules() -> None:
    """
    Сохраняет nft ruleset в /etc/nftables.conf.

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

def _get_drop_counter(port: int) -> tuple[int, int]:
    """Возвращает (packets, bytes) для REJECT-правила нашего тега (счётчик
    'отброшенных' SYN, превысивших лимит).

    Заменяет: парсинг `iptables -L INPUT -n -v -x` + поиск строки с REJECT и
              нашим comment, извлечение 2-й и 3-й колонок (pkts, bytes).
    Теперь: nft_rule_counter_read(table, "input", "telemt-syn-limit-reject")
            → JSON-парсинг `nft -j list chain` → counter expr → {packets, bytes}.
    """
    cnt = nft_rule_counter_read(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        comment=_COMMENT_TAG_REJECT, family=NFT_TABLE_FAMILY,
    )
    return cnt.get("packets", 0), cnt.get("bytes", 0)

def _get_accept_counter(port: int) -> tuple[int, int]:
    """Возвращает (packets, bytes) для ACCEPT-правила нашего тега (счётчик
    'принятых' SYN, уложившихся в лимит).

    Заменяет: парсинг `iptables -L INPUT -n -v -x` + поиск строки с ACCEPT и
              нашим comment, извлечение 2-й и 3-й колонок (pkts, bytes).
    Теперь: nft_rule_counter_read(table, "input", "telemt-syn-limit-accept").
    """
    cnt = nft_rule_counter_read(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        comment=_COMMENT_TAG_ACCEPT, family=NFT_TABLE_FAMILY,
    )
    return cnt.get("packets", 0), cnt.get("bytes", 0)

# ══════════════════════════════════════════════════════════════════════════════
#  ПУБЛИЧНЫЙ API
# ══════════════════════════════════════════════════════════════════════════════
def status() -> dict:
    """Возвращает текущее состояние лимитера для отображения в mtproto_menu()."""
    cfg = _load_state()
    active = _rule_exists()
    return {
        "enabled": cfg.enabled and active,
        "configured_but_inactive": cfg.enabled and not active,
        "rate": cfg.rate_per_sec,
        "burst": cfg.burst,
        "preset": cfg.preset_name,
        "port": cfg.port,
    }

def syn_limiter_status_line() -> str:
    """Однострочный статус для главного меню mtproto_menu()."""
    st = status()
    if st["enabled"]:
        return f"{GREEN}● активен{NC}  {DIM}{st['rate']}/sec burst {st['burst']} (port {st['port']}){NC}"
    if st["configured_but_inactive"]:
        return f"{YELLOW}⚠ включён в конфиге, но правил нет в nftables{NC}"
    return f"{DIM}не активен{NC}"

# ══════════════════════════════════════════════════════════════════════════════
#  ИНТЕРАКТИВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════
def _show_preset_picker() -> Optional[tuple]:
    """Возвращает (preset_key, rate, burst, name) либо None при ручном вводе/отмене."""
    os.system("clear")
    _box_top("ЗАЩИТА ОТ SYN-ШТОРМОВ  •  PER-IP RATE LIMIT")
    _box_row()
    _box_info("Симптом: клиент зависает в 'Подключение...' или подключается и рвётся.")
    _box_info("Причина часто не в DPI, а в ретраях SYN от нестабильного клиента —")
    _box_info("повторные SYN от одного IP накладываются на уже начатый handshake.")
    _box_info("Лимитер режет дубли SYN per-IP, не трогая уже установленные соединения.")
    _box_row()
    _box_sep()

    for key, (pname, rate, burst, label, detail, recommended) in _PRESETS.items():
        star = f" {GREEN}★ рекомендуется{NC}" if recommended else ""
        key_col = WHITE + BOLD
        _box_row(f"  {DIM}[{NC}{key_col}{key}{NC}{DIM}]{NC}  {BOLD}{label}{NC}{star}")
        _box_row(f"       {DIM}{rate}/sec, burst {burst}{NC}")
        _box_wrap(detail, indent="       ")
        _box_row()

    _box_sep()
    _box_row(f"  {DIM}[{NC}{WHITE}{BOLD}C{NC}{DIM}]{NC}  ✏️   Свой rate/burst")
    _box_row(f"  {DIM}[{NC}{RED}{BOLD}Q{NC}{DIM}]{NC}  ← Отмена")
    _box_bot(); print()

    while True:
        raw = _ask(f"{CYAN}Выбор [1-3/C/Q] (Enter=1): {NC}", default="1", c=True).strip().lower()
        if raw == "":
            raw = "1"
        if raw == "q":
            return None
        if raw == "c":
            try:
                rate_s = _ask(f"  {CYAN}Rate (пакетов/сек, 1-50): {NC}", c=True).strip()
                burst_s = _ask(f"  {CYAN}Burst (1-20): {NC}", c=True).strip()
                rate, burst = int(rate_s), int(burst_s)
                if not (1 <= rate <= 50 and 1 <= burst <= 20):
                    _box_warn("Значения вне диапазона. Повторите."); continue
                return ("custom", rate, burst, "Свой")
            except (ValueError, _Cancelled):
                _box_warn("Нужны целые числа. Повторите."); continue
        if raw in _PRESETS:
            pname, rate, burst, label, detail, _ = _PRESETS[raw]
            return (pname, rate, burst, label)
        _box_warn(f"Неверный выбор: '{raw}'.")

def _show_live_counter(cfg: SynLimiterConfig) -> None:
    """Живой просмотр счётчика DROP/ACCEPT с обновлением каждые 2 сек. Ctrl+C — выход."""
    print(f"\n  {CYAN}Живой просмотр счётчика — Ctrl+C для выхода{NC}\n")
    try:
        while True:
            os.system("clear")
            acc_p, acc_b = _get_accept_counter(cfg.port)
            drop_p, drop_b = _get_drop_counter(cfg.port)
            total = acc_p + drop_p
            drop_pct = (drop_p / total * 100) if total else 0.0

            _box_top(f"📡  SYN-LIMITER — LIVE  [{cfg.rate_per_sec}/sec burst {cfg.burst}]")
            _box_row()
            _box_kv("Принято SYN:", f"{GREEN}{acc_p:,}{NC} пакетов")
            _box_kv("Отброшено SYN:", f"{RED}{drop_p:,}{NC} пакетов")
            _box_kv("Процент дропа:", f"{YELLOW if drop_pct > 30 else DIM}{drop_pct:.1f}%{NC}")
            _box_row()
            _box_sep()
            if drop_p == 0:
                _box_info("Дропов нет — либо лимит не достигается, либо клиентов пока нет.")
            elif drop_pct > 50:
                _box_warn("Высокий процент дропа — возможно лимит слишком жёсткий для")
                _box_warn("легитимных ретраев. Попробуйте пресет 'Средний' или 'Мягкий'.")
            else:
                _box_ok("Лимитер активно отсеивает дублирующиеся SYN.")
            _box_sep()
            _box_row(f"  {DIM}Обновление каждые 2 сек...  Ctrl+C — выход{NC}")
            _box_bot()
            time.sleep(2)
    except KeyboardInterrupt:
        pass

def syn_limiter_menu() -> None:
    """
    Точка входа — вызывается из mtproto_menu() в mtproto.py.
    """
    while True:
        os.system("clear")
        cfg = _load_state()
        active = _rule_exists()
        port_now = _get_telemt_port()

        _box_top("🛡️   SYN-LIMITER  •  СТАБИЛИЗАЦИЯ ПОДКЛЮЧЕНИЯ")
        _box_row()

        if not _CONFIG_FILE.exists():
            _box_warn("Telemt не установлен — лимитер недоступен.")
            _box_row(); _box_bot(); _pause(); return

        status_str = (
            f"{GREEN}● активен{NC}  {cfg.rate_per_sec}/sec burst {cfg.burst} (port {cfg.port})"
            if active and cfg.enabled else
            f"{YELLOW}⚠ включён в конфиге, но правил в nftables нет{NC}"
            if cfg.enabled and not active else
            f"{DIM}не активен{NC}"
        )
        _box_kv("Статус:", status_str)
        _box_kv("Порт Telemt:", str(port_now) if port_now else f"{RED}не определён{NC}")

        if active:
            acc_p, _ = _get_accept_counter(cfg.port)
            drop_p, _ = _get_drop_counter(cfg.port)
            _box_kv("Принято / отброшено:", f"{GREEN}{acc_p:,}{NC} / {RED}{drop_p:,}{NC} SYN")

        _box_row(); _box_sep()
        _box_item("1", "🚀  Включить / изменить пресет")
        _box_item("2", "📊  Живой счётчик (Ctrl+C — выход)")
        _box_item("3", f"{RED}⏹️   Выключить и удалить правила{NC}")
        _box_sep()
        _box_item("Q", "← Назад в меню Telemt")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            picked = _show_preset_picker()
            if picked is None:
                continue
            pname, rate, burst, label = picked
            port = _get_telemt_port()
            if port <= 0:
                _box_err("Не удалось определить порт Telemt из telemt.toml.")
                _pause(); continue

            new_cfg = SynLimiterConfig(
                enabled=True, port=port, rate_per_sec=rate, burst=burst,
                htable_expire_ms=60000, preset_name=pname,
            )
            ok, msg = _apply_rules(new_cfg)
            if ok:
                _persist_rules()
                _save_state(new_cfg)
                print()
                _box_ok(f"Лимитер включён: {label} ({rate}/sec burst {burst}) на порту {port}.")
                _box_info("Дайте серверу поработать 10-30 минут, затем проверьте")
                _box_info("живой счётчик [2] — если дропы растут, лимитер работает.")
            else:
                print()
                _box_err(msg)
            _pause()

        elif ch == "2":
            if not active:
                _box_warn("Лимитер не активен — нечего отслеживать."); _pause(); continue
            _show_live_counter(cfg)

        elif ch == "3":
            if not active and not cfg.enabled:
                _box_info("Лимитер уже не активен."); _pause(); continue
            removed = _remove_rules()
            _persist_rules()
            new_cfg = SynLimiterConfig(enabled=False)
            _save_state(new_cfg)
            print()
            if removed:
                _box_ok(f"Удалено правил: {removed}. Лимитер выключен.")
            else:
                _box_info("Правил для удаления не найдено — лимитер уже выключен.")
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
        syn_limiter_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}")
