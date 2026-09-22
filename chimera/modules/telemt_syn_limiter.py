"""
chimera/modules/telemt_syn_limiter.py
───────────────────────────────────────────────────────────────────────────────
Per-IP лимитер входящих SYN-пакетов для Telemt — стабилизация TCP-рукопожатия.

Поддержаны три режима работы (портированы + адаптированы из
MTPROTO_FIX_By_MEKO, https://github.com/Mekotofeuka/MTPROTO_FIX_By_MEKO):

  1. V3 (u32 iOS-фингерпринт) — РЕКОМЕНДУЕТСЯ
     • mangle PREROUTING: u32 match iOS ClientHello → MARK 0x400
     • INPUT: ACCEPT для mark=0x400 БЕЗ лимита (iOS пропускается мгновенно)
     • INPUT: hashlimit 54/min (~0.9/sec) per-IP для остальных + REJECT tcp-reset
     • Плюс: iOS имеет отличные от Android/Desktop паттерны подключений
       (мобильный клиент делает несколько SYN для multipath). Без разделения
       iOS и non-iOS мешают друг другу в одном лимите — iOS пользователей
       приходится выносить на отдельный порт (костыль telemt_ios_fix.py).
       V3 решает эту проблему на одном порту.

  2. V2 (TTL+Length) — FALLBACK для старых kernel без u32 match
     • INPUT: ACCEPT для length=64 + ttl<65 (iOS fingerprint по размеру пакета)
     • INPUT: hashlimit 54/min per-IP для остальных + REJECT tcp-reset
     • Минус: TTL нестабилен через балансировщики — может дать ложное срабатывание

  3. SIMPLE (без iOS detection) — исходный Chimera режим
     • INPUT: hashlimit 1/sec per-IP burst 1 + REJECT tcp-reset
     • Минус: iOS режется наравне со всеми → зависания в "Подключение..."
       при нестабильной мобильной сети

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
шанс довести до конца уже начатое соединение. Дополнительно в режимах V3/V2
iOS-клиенты пропускаются без лимита — у них паттерн SYN действительно требует
нескольких попыток (это не ретраи, а multipath).

Механизм: iptables `hashlimit` (НЕ nftables — проект целиком на iptables,
смешивать backend'ы на одном сервере рискованно из-за разделяемых
conntrack-таблиц и нет смысла тащить новую зависимость).

Пример для V3 (рекомендуется):

    # mangle PREROUTING — маркировка iOS SYN по u32 фингерпринту
    iptables -t mangle -A PREROUTING -m u32 \
        --u32 "32 & 0x000FFFFF = 0x0002FFFF && 40 & 0xFF000000 = 0x02000000 && \
                44 & 0xFFFF0000 = 0x01030000 && 48 & 0xFFFFFF00 = 0x01010800 && \
                60 & 0xFFFFFFFF = 0x04020000" \
        -j MARK --set-mark 0x400

    # INPUT — iOS без лимита (по марке)
    iptables -A INPUT -p tcp --dport <PORT> --syn -m mark --mark 0x400 -j ACCEPT

    # INPUT — все остальные в рамках лимита
    iptables -A INPUT -p tcp --dport <PORT> --syn \
        -m hashlimit --hashlimit-name telemt_syn \
        --hashlimit-mode srcip --hashlimit-srcmask 32 \
        --hashlimit-upto 54/minute --hashlimit-burst 1 \
        --hashlimit-htable-expire 60000 \
        -j ACCEPT

    # INPUT — over-limit → REJECT tcp-reset
    iptables -A INPUT -p tcp --dport <PORT> --syn \
        -j REJECT --reject-with tcp-reset

iOS u32 фингерпринт (стандартный SYN от iOS-устройства):
  • offset 32: TCP window=0xFFFF + flags=SYN (0x02)
  • offset 40: TCP option MSS (kind=0x02, len=0x04)
  • offset 44: TCP option Window Scale (kind=0x03, len=0x01, value=0x01)
  • offset 48: NOP (kind=0x01) + NOP (kind=0x01) + Timestamp (kind=0x08, len=0x08)
  • offset 60: SACK Permitted (kind=0x04, len=0x02)

Этот фингерпринт стабилен для iOS-клиентов Telegram и не встречается у
Android/Desktop. Подробности: data/dictionary.md в MTPROTO_FIX_By_MEKO.

Гарантии совместимости
──────────────────────
  • Модуль работает с правилами INPUT (filter table) и PREROUTING (mangle
    table) для порта Telemt — не трогает REDIRECT-правила xray/tproxy
    (другая chain-логика, другой match).
  • Все правила маркируются комментарием `--comment "telemt-syn-limit"` —
    отключение модуля удаляет ТОЛЬКО эти правила, ничего больше.
  • persist делается тем же механизмом, что и для остальных iptables-правил
    проекта (см. _iptables_persist() в mtproto.py) — НЕ дублируем его здесь,
    а сохраняем правила через netfilter-persistent/iptables-save напрямую
    с тем же безопасным паттерном (best-effort, без падения при отсутствии).
  • Установка/удаление идемпотентны: повторный enable() не плодит дубликаты
    правил — сначала disable(), потом добавление актуальных.
  • При переключении между режимами (v3 → v2 → simple) модуль сначала
    удаляет ВСЕ правила предыдущего режима (включая mangle PREROUTING),
    затем добавляет правила нового режима.

Интеграция с mtproto.py
───────────────────────
  Вызывается из mtproto_menu() через lazy-import (как telemt_fallback):
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

# ══════════════════════════════════════════════════════════════════════════════
#  ПУТИ И КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════
_CONFIG_FILE   = Path("/etc/telemt/telemt.toml")
_SERVICE_NAME  = "telemt"
_STATE_FILE    = Path("/var/lib/xray-installer/telemt_syn_limiter.json")
_COMMENT_TAG   = "telemt-syn-limit"
_HASHLIMIT_NAME = "telemt_syn"

# ── iOS-фингерпринт для V3 режима (u32 match в mangle PREROUTING) ──────────
# Портировано из MTPROTO_FIX_By_MEKO/data/rules.sh (preset "new"/v3).
# Соответствует стандартному SYN-пакету iOS-устройства (Telegram client):
#   • TCP window=0xFFFF + flags=SYN (offset 32)
#   • TCP option MSS=0x02 len=0x04 (offset 40)
#   • TCP option Window Scale=0x03 len=0x01 value=0x01 (offset 44)
#   • NOP + NOP + Timestamp=0x08 len=0x08 (offset 48)
#   • SACK Permitted=0x04 len=0x02 (offset 60)
# Подробное объяснение каждого байта: data/dictionary.md в MTPROTO_FIX_By_MEKO
_IOS_U32_MATCH = (
    "32 & 0x000FFFFF = 0x0002FFFF && "
    "40 & 0xFF000000 = 0x02000000 && "
    "44 & 0xFFFF0000 = 0x01030000 && "
    "48 & 0xFFFFFF00 = 0x01010800 && "
    "60 & 0xFFFFFFFF = 0x04020000"
)
# Марка, которой mangle помечает iOS-пакеты; потом INPUT цепочка делает
# ACCEPT для пакетов с этой маркой без лимита.
_IOS_MARK = 0x400

# ── iOS-фингерпринт для V2 режима (length + ttl в INPUT, fallback если нет u32) ──
# Портировано из MTPROTO_FIX_By_MEKO/data/rules.sh (preset "old"/v2).
# iOS Telegram SYN пакет имеет длину 64 байта и TTL<65 (мобильная сеть).
# Менее надёжно чем V3: TTL может быть изменён балансировщиками в пути.
_IOS_PKT_LENGTH = 64
_IOS_TTL_LT     = 65

# Режимы работы лимитера
_MODE_V3     = "v3_u32"      # u32 iOS fingerprint + MARK
_MODE_V2     = "v2_ttl"      # length=64 + ttl<65 (fallback)
_MODE_SIMPLE = "simple"      # без iOS detection (исходный Chimera режим)

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
    """Конфигурация лимитера, сохраняемая в /var/lib/xray-installer/telemt_syn_limiter.json.

    Поля `rate_unit` и `mode` добавлены в той же минорной версии, что и поддержка
    V3/V2 пресетов. Для обратной совместимости со старыми state-файлами:
      • если `rate_unit` отсутствует → дефолт "sec"
      • если `mode` отсутствует → дефолт "simple" (старый hard/medium/soft)
    """
    enabled: bool = False
    port: int = 0
    rate_per_sec: int = 1            # raw число (1, 54, и т.д.)
    rate_unit: str = "sec"           # "sec" или "minute" (для hashlimit-upto)
    burst: int = 1
    htable_expire_ms: int = 60000   # 60 сек — время жизни записи в hash-таблице
    preset_name: str = "hard"
    mode: str = _MODE_SIMPLE         # "v3_u32" | "v2_ttl" | "simple"

# Структура tuple в _PRESETS (8 элементов):
#   (preset_name, rate_per_sec, rate_unit, burst, label, detail, recommended, mode)
_PRESETS = {
    # ── V3 (РЕКОМЕНДУЕТСЯ) — u32 iOS fingerprint + MARK ───────────────────────
    "1": ("v3",     54, "minute", 1, "V3 iptables (MEKO)",
          "u32 iOS-фингерпринт в mangle + 54/мин per-IP. iOS без лимита, остальные 54/мин. "
          "Стандартный фикс MTPROTO_FIX v3 — один порт для всех устройств без конфликтов.",
          True, _MODE_V3),
    # ── V2 — TTL+Length (fallback для kernel без u32) ─────────────────────────
    "2": ("v2_ttl", 54, "minute", 1, "V2 iptables (TTL+Length)",
          "length=64 + ttl<65 для iOS. Универсальный fallback для старых kernel "
          "без xt_u32 модуля. Менее надёжен: TTL может меняться балансировщиками.",
          False, _MODE_V2),
    # ── SIMPLE (исходный Chimera режим, без iOS detection) ───────────────────
    "3": ("hard",    1, "sec",     1, "Жёсткий (без iOS detection)",
          "1/sec per-IP burst 1, REJECT tcp-reset. Простой per-IP лимитер без "
          "iOS fingerprint — режет iOS наравне со всеми. Только если u32 не работает.",
          False, _MODE_SIMPLE),
    "4": ("medium",  1, "sec",     3, "Средний (без iOS detection)",
          "1/sec burst 3 — менее строгий, для серверов с большим числом клиентов.",
          False, _MODE_SIMPLE),
    "5": ("soft",    2, "sec",     5, "Мягкий (без iOS detection)",
          "2/sec burst 5 — мягкая защита для загруженных серверов.",
          False, _MODE_SIMPLE),
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
#  IPTABLES — управление правилами
# ══════════════════════════════════════════════════════════════════════════════
def _rule_exists() -> bool:
    """Проверяет, есть ли уже правило с нашим комментарием в INPUT."""
    r = _run(["iptables", "-S", "INPUT"], capture=True)
    return _COMMENT_TAG in (r.stdout or "")

def _remove_rules() -> int:
    """
    Удаляет ВСЕ правила INPUT с нашим тегом, независимо от порта/rate,
    А ТАКЖЕ правило mangle PREROUTING (u32 MARK для iOS, если есть).
    Безопасно вызывать многократно — если правил нет, просто ничего не делает.
    Возвращает количество удалённых правил.
    """
    removed = 0
    # ── Чистим filter INPUT ────────────────────────────────────────────────────
    for _ in range(20):  # защита от бесконечного цикла, если что-то пошло не так
        r = _run(["iptables", "-S", "INPUT"], capture=True)
        lines = [l for l in (r.stdout or "").splitlines() if _COMMENT_TAG in l]
        if not lines:
            break
        # Берём первую строку, конвертируем "-A INPUT ..." → "-D INPUT ..." и выполняем
        line = lines[0]
        if not line.startswith("-A INPUT"):
            break
        del_args = ["iptables", "-D", "INPUT"] + line.split()[2:]
        r2 = _run(del_args, capture=True)
        if r2.returncode != 0:
            break
        removed += 1
    # ── Чистим mangle PREROUTING (u32 MARK для V3 режима) ─────────────────────
    # Аналогичный цикл: ищем правила с нашим тегом в mangle PREROUTING,
    # удаляем по одному. Безопасно если правил нет.
    for _ in range(20):
        r = _run(["iptables", "-t", "mangle", "-S", "PREROUTING"], capture=True)
        lines = [l for l in (r.stdout or "").splitlines() if _COMMENT_TAG in l]
        if not lines:
            break
        line = lines[0]
        if not line.startswith("-A PREROUTING"):
            break
        # Конвертация: "-A PREROUTING ..." → "-D PREROUTING ..."
        del_args = ["iptables", "-t", "mangle", "-D", "PREROUTING"] + line.split()[2:]
        r2 = _run(del_args, capture=True)
        if r2.returncode != 0:
            break
        removed += 1
    return removed

def _apply_rules(cfg: SynLimiterConfig) -> tuple[bool, str]:
    """
    Применяет правила hashlimit для текущего cfg.

    Поддерживаются 3 режима (см. docstring сверху):
      • v3_u32 — mangle PREROUTING u32 MARK + INPUT ACCEPT-marked (iOS без лимита)
                + INPUT hashlimit (остальные) + INPUT REJECT
      • v2_ttl — INPUT ACCEPT length=64+ttl<65 (iOS) + INPUT hashlimit + INPUT REJECT
      • simple — INPUT hashlimit + INPUT REJECT (без iOS detection, исходный Chimera режим)

    Идемпотентно: сначала удаляет старые правила с нашим тегом (включая mangle),
    потом добавляет новые. Порядок ACCEPT-затем-DROP важен — iptables проходит
    правила по порядку, поэтому iOS-ACCEPT (V3/V2) должен идти первым,
    ACCEPT-hashlimit вторым, REJECT последним.
    """
    if cfg.port <= 0:
        return False, "Не удалось определить порт Telemt — конфиг telemt.toml не найден."

    _remove_rules()  # чистим перед применением — гарантия идемпотентности

    rate_arg = f"{cfg.rate_per_sec}/{cfg.rate_unit}"

    # ══════════════════════════════════════════════════════════════════════════
    # V3: mangle PREROUTING — маркировка iOS SYN по u32 фингерпринту
    # ══════════════════════════════════════════════════════════════════════════
    if cfg.mode == _MODE_V3:
        # mangle MARK — iOS пакеты получат марку 0x400, которая затем
        # обрабатывается в INPUT цепочке ACCEPT-правилом без лимита.
        mangle_cmd = [
            "iptables", "-t", "mangle", "-A", "PREROUTING",
            "-m", "u32", "--u32", _IOS_U32_MATCH,
            "-j", "MARK", "--set-mark", str(_IOS_MARK),
            "-m", "comment", "--comment", _COMMENT_TAG,
        ]
        r_mangle = _run(mangle_cmd, capture=True)
        if r_mangle.returncode != 0:
            # Не致命но — V3 может не работать на kernel без xt_u32, откатываемся
            # к поведению SIMPLE (без iOS detection), но пишем warning в лог.
            # Правила mangle нет → INPUT-ACCEPT для mark не сработает → останется
            # только hashlimit + REJECT (как в SIMPLE). Это безопасно.
            err_msg = r_mangle.stderr.strip()[:200] if r_mangle.stderr else ""
            print(f"{YELLOW}⚠ V3 u32 MARK failed (kernel without xt_u32?): {err_msg}{NC}")
            # Фолбэк к SIMPLE-логике (без mangle ACCEPT-marked правила)
            cfg_v3_fallback = SynLimiterConfig(
                enabled=cfg.enabled, port=cfg.port,
                rate_per_sec=cfg.rate_per_sec, rate_unit=cfg.rate_unit,
                burst=cfg.burst, htable_expire_ms=cfg.htable_expire_ms,
                preset_name=cfg.preset_name, mode=_MODE_SIMPLE,
            )
            return _apply_rules(cfg_v3_fallback)

    # ══════════════════════════════════════════════════════════════════════════
    # V3: INPUT ACCEPT для iOS-маркированных пакетов (без лимита)
    # ══════════════════════════════════════════════════════════════════════════
    insert_pos = 1
    if cfg.mode == _MODE_V3:
        ios_accept_cmd = [
            "iptables", "-I", "INPUT", str(insert_pos),
            "-p", "tcp", "--dport", str(cfg.port), "--syn",
            "-m", "mark", "--mark", str(_IOS_MARK),
            "-m", "comment", "--comment", _COMMENT_TAG,
            "-j", "ACCEPT",
        ]
        r_ios = _run(ios_accept_cmd, capture=True)
        if r_ios.returncode != 0:
            _remove_rules()  # откатываем mangle MARK если не получилось добавить INPUT ACCEPT
            return False, f"Ошибка V3 iOS ACCEPT: {r_ios.stderr.strip()[:120]}"
        insert_pos += 1

    # ══════════════════════════════════════════════════════════════════════════
    # V2: INPUT ACCEPT для length=64 + ttl<65 (iOS fingerprint по размеру+TTL)
    # ══════════════════════════════════════════════════════════════════════════
    if cfg.mode == _MODE_V2:
        ios_accept_cmd = [
            "iptables", "-I", "INPUT", str(insert_pos),
            "-p", "tcp", "--dport", str(cfg.port), "--syn",
            "-m", "tcp", "--tcp-flags", "SYN", "SYN",
            "-m", "length", "--length", str(_IOS_PKT_LENGTH),
            "-m", "ttl", "--ttl-lt", str(_IOS_TTL_LT),
            "-m", "comment", "--comment", _COMMENT_TAG,
            "-j", "ACCEPT",
        ]
        r_ios = _run(ios_accept_cmd, capture=True)
        if r_ios.returncode != 0:
            err_msg = r_ios.stderr.strip()[:200] if r_ios.stderr else ""
            print(f"{YELLOW}⚠ V2 length+ttl match failed (xt_length/xt_ttl missing?): {err_msg}{NC}")
            # Фолбэк к SIMPLE
            cfg_v2_fallback = SynLimiterConfig(
                enabled=cfg.enabled, port=cfg.port,
                rate_per_sec=cfg.rate_per_sec, rate_unit=cfg.rate_unit,
                burst=cfg.burst, htable_expire_ms=cfg.htable_expire_ms,
                preset_name=cfg.preset_name, mode=_MODE_SIMPLE,
            )
            _remove_rules()
            return _apply_rules(cfg_v2_fallback)
        insert_pos += 1

    # ══════════════════════════════════════════════════════════════════════════
    # ALL MODES: INPUT hashlimit для остальных (не iOS) пакетов
    # ══════════════════════════════════════════════════════════════════════════
    accept_cmd = [
        "iptables", "-I", "INPUT", str(insert_pos),
        "-p", "tcp", "--dport", str(cfg.port), "--syn",
        "-m", "hashlimit",
        "--hashlimit-name", _HASHLIMIT_NAME,
        "--hashlimit-mode", "srcip",
        "--hashlimit-srcmask", "32",
        "--hashlimit-upto", rate_arg,
        "--hashlimit-burst", str(cfg.burst),
        "--hashlimit-htable-expire", str(cfg.htable_expire_ms),
        "-m", "comment", "--comment", _COMMENT_TAG,
        "-j", "ACCEPT",
    ]
    # REJECT+tcp-reset вместо DROP: DROP молча топит пакет → клиент ждёт
    # таймаут (3-5 сек) и только потом ретраит с бэкоффом. RST даёт клиенту
    # мгновенный сигнал "соединение разорвано" → реконнект без ожидания.
    reject_cmd = [
        "iptables", "-I", "INPUT", str(insert_pos + 1),
        "-p", "tcp", "--dport", str(cfg.port), "--syn",
        "-m", "comment", "--comment", _COMMENT_TAG,
        "-j", "REJECT", "--reject-with", "tcp-reset",
    ]

    r1 = _run(accept_cmd, capture=True)
    if r1.returncode != 0:
        return False, f"Ошибка применения ACCEPT-правила: {r1.stderr.strip()[:120]}"

    r2 = _run(reject_cmd, capture=True)
    if r2.returncode != 0:
        # откатываем ACCEPT-правило, чтобы не оставить половинчатое состояние
        _remove_rules()
        return False, f"Ошибка применения REJECT-правила: {r2.stderr.strip()[:120]}"

    return True, "Правила применены."

def _persist_rules() -> None:
    """
    Сохраняет iptables-правила тем же best-effort способом, что и остальной
    проект (netfilter-persistent / iptables-save в rules.v4, если доступно).
    Не падает, если механизм persist отсутствует — правило просто не
    переживёт перезагрузку, что некритично (модуль можно повторно
    активировать через меню).
    """
    if shutil.which("netfilter-persistent"):
        _run(["netfilter-persistent", "save"])
        return
    # Fallback: iptables-save → /etc/iptables/rules.v4 (Debian/Ubuntu типичный путь)
    rules_path = Path("/etc/iptables/rules.v4")
    if rules_path.parent.exists():
        try:
            r = _run(["iptables-save"], capture=True)
            if r.returncode == 0 and r.stdout:
                rules_path.write_text(r.stdout)
        except Exception:
            pass

def _get_drop_counter(port: int) -> tuple[int, int]:
    """Возвращает (packets, bytes) для REJECT-правила нашего тега (счётчик 'отброшенных' SYN)."""
    r = _run(["iptables", "-L", "INPUT", "-n", "-v", "-x"], capture=True)
    for line in (r.stdout or "").splitlines():
        if _COMMENT_TAG in line and "REJECT" in line:
            parts = line.split()
            if len(parts) >= 2 and parts[0].isdigit():
                return int(parts[0]), int(parts[1])
    return 0, 0

def _get_accept_counter(port: int) -> tuple[int, int]:
    """Возвращает (packets, bytes) для ACCEPT-правила нашего тега."""
    r = _run(["iptables", "-L", "INPUT", "-n", "-v", "-x"], capture=True)
    for line in (r.stdout or "").splitlines():
        if _COMMENT_TAG in line and "ACCEPT" in line:
            parts = line.split()
            if len(parts) >= 2 and parts[0].isdigit():
                return int(parts[0]), int(parts[1])
    return 0, 0

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
        "rate_unit": cfg.rate_unit,
        "burst": cfg.burst,
        "preset": cfg.preset_name,
        "mode": cfg.mode,
        "port": cfg.port,
    }

def syn_limiter_status_line() -> str:
    """Однострочный статус для главного меню mtproto_menu()."""
    st = status()
    if st["enabled"]:
        mode_tag = {
            _MODE_V3: "V3-u32",
            _MODE_V2: "V2-ttl",
            _MODE_SIMPLE: "simple",
        }.get(st["mode"], st["mode"])
        return (f"{GREEN}● активен{NC}  "
                f"{DIM}{st['rate']}/{st['rate_unit']} burst {st['burst']} "
                f"[{mode_tag}] (port {st['port']}){NC}")
    if st["configured_but_inactive"]:
        return f"{YELLOW}⚠ включён в конфиге, но правил нет в iptables{NC}"
    return f"{DIM}не активен{NC}"

# ══════════════════════════════════════════════════════════════════════════════
#  ИНТЕРАКТИВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════
def _show_preset_picker() -> Optional[tuple]:
    """Возвращает (preset_name, rate, rate_unit, burst, label, mode) либо None при ручном вводе/отмене."""
    os.system("clear")
    _box_top("ЗАЩИТА ОТ SYN-ШТОРМОВ  •  PER-IP RATE LIMIT")
    _box_row()
    _box_info("Симптом: клиент зависает в 'Подключение...' или подключается и рвётся.")
    _box_info("Причина часто не в DPI, а в ретраях SYN от нестабильного клиента —")
    _box_info("повторные SYN от одного IP накладываются на уже начатый handshake.")
    _box_info("V3/V2 режимы дополнительно пропускают iOS без лимита (у iOS свой")
    _box_info("паттерн SYN — multipath). Один порт для всех устройств без конфликтов.")
    _box_row()
    _box_sep()

    for key, (pname, rate, rate_unit, burst, label, detail, recommended, mode) in _PRESETS.items():
        star = f" {GREEN}★ рекомендуется{NC}" if recommended else ""
        mode_tag = {
            _MODE_V3: f"{CYAN}V3{NC}",
            _MODE_V2: f"{YELLOW}V2{NC}",
            _MODE_SIMPLE: f"{DIM}SIMPLE{NC}",
        }.get(mode, mode)
        key_col = WHITE + BOLD
        _box_row(f"  {DIM}[{NC}{key_col}{key}{NC}{DIM}]{NC}  {BOLD}{label}{NC} {DIM}[{NC}{mode_tag}{DIM}]{NC}{star}")
        _box_row(f"       {DIM}{rate}/{rate_unit}, burst {burst}{NC}")
        _box_wrap(detail, indent="       ")
        _box_row()

    _box_sep()
    _box_row(f"  {DIM}[{NC}{WHITE}{BOLD}C{NC}{DIM}]{NC}  ✏️   Свой rate/burst (mode=simple)")
    _box_row(f"  {DIM}[{NC}{RED}{BOLD}Q{NC}{DIM}]{NC}  ← Отмена")
    _box_bot(); print()

    while True:
        raw = _ask(f"{CYAN}Выбор [1-5/C/Q] (Enter=1): {NC}", default="1", c=True).strip().lower()
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
                return ("custom", rate, "sec", burst, "Свой", _MODE_SIMPLE)
            except (ValueError, _Cancelled):
                _box_warn("Нужны целые числа. Повторите."); continue
        if raw in _PRESETS:
            pname, rate, rate_unit, burst, label, _, _, mode = _PRESETS[raw]
            return (pname, rate, rate_unit, burst, label, mode)
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

        mode_tag = {
            _MODE_V3: f"{CYAN}V3-u32{NC}",
            _MODE_V2: f"{YELLOW}V2-ttl{NC}",
            _MODE_SIMPLE: f"{DIM}simple{NC}",
        }.get(cfg.mode, cfg.mode)
        status_str = (
            f"{GREEN}● активен{NC}  {cfg.rate_per_sec}/{cfg.rate_unit} burst {cfg.burst} "
            f"[{mode_tag}] (port {cfg.port})"
            if active and cfg.enabled else
            f"{YELLOW}⚠ включён в конфиге, но правил в iptables нет{NC}"
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
            pname, rate, rate_unit, burst, label, mode = picked
            port = _get_telemt_port()
            if port <= 0:
                _box_err("Не удалось определить порт Telemt из telemt.toml.")
                _pause(); continue

            new_cfg = SynLimiterConfig(
                enabled=True, port=port,
                rate_per_sec=rate, rate_unit=rate_unit, burst=burst,
                htable_expire_ms=60000, preset_name=pname, mode=mode,
            )
            ok, msg = _apply_rules(new_cfg)
            if ok:
                _persist_rules()
                _save_state(new_cfg)
                print()
                _box_ok(f"Лимитер включён: {label} ({rate}/{rate_unit} burst {burst}, mode={mode}) на порту {port}.")
                if mode == _MODE_V3:
                    _box_info("V3 режим: mangle u32 MARK iOS → INPUT ACCEPT без лимита для iOS.")
                    _box_info("INPUT hashlimit 54/мин для остальных, REJECT tcp-reset по превышению.")
                elif mode == _MODE_V2:
                    _box_info("V2 режим: INPUT length=64+ttl<65 для iOS (fallback для kernel без u32).")
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
