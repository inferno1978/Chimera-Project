"""
chimera/modules/ingress_geoip.py
───────────────────────────────────────────────────────────────────────────────
Блокировка входящих соединений из РФ через nftables (миграция с iptables/ipset).

  • Применяет через nft: DROP входящих на SERVER_PORT из РФ подсетей
  • Использует nft sets (inet chimera ingress_block_v4 / _v6) для эффективной
    фильтрации 5000+ CIDR (замена ipset hash:net)
  • Загружает актуальный список РФ подсетей из RIPE NCC
  • Поддерживает IPv4 и IPv6 в одной таблице inet (без дублирования ip6tables)
  • Whitelist для SSH и управляющих IP (через nft_rule_insert на позицию 1)
  • Cron для еженедельного обновления

МИГРАЦИЯ (этап 1.2 — Task ID: 1.2-ingress):
  Раньше использовалась связка `ipset hash:net` (xray_ru_block / xray_ru_block6)
  + `iptables -A INPUT -m set --match-set ...` + `ip6tables -A INPUT ...`.
  Теперь всё живет в единой таблице `inet chimera` (covers both IPv4 + IPv6 без
  дублирования) и использует централизованные примитивы из
  `chimera/modules/nft_common.py`:

    • `nft_set_create(name, ..., flags=["interval"], maxelem=N)` — замена
      `ipset create <name> hash:net family inet maxelem N -exist`.
    • `nft_set_atomic_swap(name, new_elements, ...)` — замена последовательности
      `ipset flush <name>` + `ipset restore -! -f <tmpfile>`. Атомарная транзакция
      `nft -f -` (flush set + add element в одном batch).
    • `nft_rule_add(table, chain, rule_spec, family, comment=...)` — замена
      `iptables -D ... -A ... -m set --match-set ... -m comment --comment ...`
      (идемпотентно по comment-tag, не требует ручного -D перед -A).
    • `nft_rule_delete_by_comment(table, chain, comment)` — замена цикла
      `iptables -D INPUT ...` до rc!=0. Один вызов находит все правила с указанным
      comment и удаляет их через handle.
    • `nft_set_destroy(name, table, family)` — замена `ipset destroy <name>`.
    • `nft_rule_insert(table, chain, spec, comment=...)` — замена
      `iptables -I INPUT 1 -s <ip> -j ACCEPT` для per-IP whitelist.
    • `nft_persist()` — замена `ipset save` → /etc/ipset.conf. Теперь единый
      `/etc/nftables.conf` для всех правил Chimera (nft list ruleset).
    • `nft_persist_enable_systemd()` — замена кастомного
      `xray-ipset-restore.service` на встроенный `nftables.service`, который
      читает /etc/nftables.conf при `systemctl start nftables`.

  Comment-tag `xray-ru-ingress-block` сохранён для совместимости с аудитом
  правил в `nft list ruleset`. Имена nft sets (`ingress_block_v4` / `_v6`)
  мигрированы с ipset `xray_ru_block` / `xray_ru_block6` (см.
  LEGACY_IPSET_NAME_MAP в nft_constants для обратной совместимости).
  Семантика идентична: что блокировалось — то и блокируется.

Точка входа из _core.py:
    from chimera.modules.ingress_geoip import do_manage_ingress_geoip
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import textwrap
import time
import urllib.request as _ur2
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# nftables — централизованная обёртка над `nft` CLI (этап 1.2 миграции)
from .nft_common import (
    nft_set_create, nft_set_destroy, nft_set_atomic_swap,
    nft_set_count, nft_set_list_elements,
    nft_rule_add, nft_rule_insert, nft_rule_delete_by_comment,
    nft_persist, nft_persist_enable_systemd, _nft_available,
)
from .nft_constants import (
    NFT_TABLE_NAME, NFT_TABLE_FAMILY, NFT_CHAIN_INPUT,
    NFT_SET_INGRESS_BLOCK_V4, NFT_SET_INGRESS_BLOCK_V6,
    COMMENT_INGRESS_GEO_BLOCK, COMMENT_INGRESS_WL_PREFIX,
    NFT_PERSIST_FILE,
)

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if __import__("sys").stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
        else:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m',
            )
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED    = _C['RED'];   GREEN  = _C['GREEN'];  YELLOW = _C['YELLOW']
CYAN   = _C['CYAN'];  BLUE   = _C['BLUE'];   BOLD   = _C['BOLD']
DIM    = _C['DIM'];   WHITE  = _C['WHITE'];  NC     = _C['NC']

# ── Логирование ────────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/chimera.log")

def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime as _dt
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = _dt.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [{level}] {clean}\n")
    except Exception:
        pass

def info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");   _log("INFO",    msg)
def success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}");   _log("SUCCESS", msg)
def warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}");  _log("WARN",    msg)
def log_to_file(level: str, msg: str) -> None: _log(level, msg)

# ── Вспомогательные ───────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

# ── Константы ─────────────────────────────────────────────────────────────────
INGRESS_GEOIP_FILE  = Path("/var/lib/xray-installer/ingress_geoip.json")
# Имена nft sets теперь берутся из nft_constants (мигрировано с ipset-имён
# `xray_ru_block` / `xray_ru_block6`). Сохраняем переменные INGRESS_IPSET_NAME /
# INGRESS_IPSET6_NAME как aliases для обратной совместимости — на них могут
# ссылаться другие модули (например, emergency_repair.py, ipset_persist.py).
# См. LEGACY_IPSET_NAME_MAP в nft_constants для обратной совместимости со
# старым state.json.
INGRESS_IPSET_NAME  = NFT_SET_INGRESS_BLOCK_V4   # "ingress_block_v4"
INGRESS_IPSET6_NAME = NFT_SET_INGRESS_BLOCK_V6   # "ingress_block_v6"
# Comment-tag для nft-правил: `xray-ru-ingress-block` (префикс из nft_constants).
# Используем централизованный COMMENT_INGRESS_GEO_BLOCK чтобы не разойтись с
# реестром comment-тегов Chimera.
_INGRESS_COMMENT    = COMMENT_INGRESS_GEO_BLOCK    # "xray-ru-ingress-block"
# Пер-IP whitelist comment prefix: `xray-ru-wl-<ip>` (с заменой `/` на `_`).
_INGRESS_WL_PREFIX  = COMMENT_INGRESS_WL_PREFIX   # "xray-ru-wl-"
# nft persist file (заменяет /etc/ipset.conf + /etc/iptables/rules.v4).
# Один единый файл для всех правил Chimera.
_INGRESS_PERSIST    = Path(NFT_PERSIST_FILE)       # "/etc/nftables.conf"
INGRESS_CRON_SCRIPT = Path("/usr/local/bin/xray-ingress-geoip-update.sh")
INGRESS_CRON_FILE   = Path("/etc/cron.d/xray-ingress-geoip")
INGRESS_LOG         = Path("/var/log/xray-ingress-geoip.log")

_STATE_FILE = Path("/var/lib/xray-installer/state.json")

# ── Telegram уведомление (no-op если недоступно) ───────────────────────────────
def _tg_notify_event(event: str, detail: str = "") -> None:
    try:
        import importlib
        _core = importlib.import_module("chimera._core")
        _core._tg_notify_event(event, detail)
    except Exception:
        pass

# ── Импорты из других модулей ─────────────────────────────────────────────────
from chimera.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_back,
)
from chimera.modules.tui import tui_confirm
from chimera.modules.ripe_file_age import check_ripe_file_age, ripe_file_age_banner

# NOTE: `ipset_persist` модуль пока НЕ мигрирован (этап 4 миграции — persist).
# Нужные нам функции (сохранение ruleset + установка systemd-юнита для boot
# restore) теперь реализованы напрямую через nft_common:
#   • ipset_save()               → nft_persist()  (nft list ruleset → /etc/nftables.conf)
#   • ipset_restore_unit_install → nft_persist_enable_systemd() (nftables.service)
# Временно оставляем legacy-импорты для совместимости, но НЕ используем их
# в коде — они deprecated и будут удалены после миграции ipset_persist.py.


def _fetch_ru_subnets_ripe() -> list:
    """Загружает список РФ подсетей — делегирует в _core._fetch_ru_subnets_from_ripe."""
    try:
        import importlib
        _core = importlib.import_module("chimera._core")
        return _core._fetch_ru_subnets_from_ripe()
    except Exception as e:
        warn(f"Не удалось загрузить список РФ подсетей: {e}")
        return []

def _ingress_state_load() -> dict:
    try:
        if INGRESS_GEOIP_FILE.exists():
            return json.loads(INGRESS_GEOIP_FILE.read_text())
    except Exception:
        pass
    return {"enabled": False, "port": 0, "cidrs_v4": 0, "cidrs_v6": 0,
            "updated_at": "", "method": ""}


def _ingress_state_save(data: dict) -> None:
    INGRESS_GEOIP_FILE.parent.mkdir(parents=True, exist_ok=True)
    INGRESS_GEOIP_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    INGRESS_GEOIP_FILE.chmod(0o600)


def _ingress_ipset_available() -> bool:
    """Алиас для обратной совместимости (миграция на nftables, этап 1.2).

    Раньше проверял `shutil.which("ipset")`. Теперь проверяет наличие
    `nft` binary (nftables поддерживает sets нативно — ipset больше не нужен).
    """
    return _nft_available()


def _ingress_iptables_available() -> bool:
    """Алиас для обратной совместимости (миграция на nftables, этап 1.2).

    Раньше проверял `shutil.which("iptables")`. Теперь проверяет наличие
    `nft` binary — nftables заменяет и iptables, и ip6tables одной утилитой
    (семейство таблицы `inet` покрывает v4+v6).
    """
    return _nft_available()


def _ingress_get_cidrs() -> "tuple[list[str], list[str]]":
    """
    Возвращает (v4_cidrs, v6_cidrs).
    Источники приоритетов:
      1. /etc/xray/ru_subnets_ripe.txt (уже скачан split-tunnel модулем)
      2. Свежая загрузка через _fetch_ru_subnets_ripe()
    """
    ru_file = Path("/etc/xray/ru_subnets_ripe.txt")
    if ru_file.exists() and ru_file.stat().st_size > 1000:
        try:
            lines = [l.strip() for l in ru_file.read_text().splitlines()
                     if l.strip() and not l.startswith("#")]
            v4 = [l for l in lines if ":" not in l]
            v6 = [l for l in lines if ":" in l]
            if v4:
                info(f"Используем существующий файл РФ подсетей: {len(v4)} v4, {len(v6)} v6")
                return v4, v6
        except Exception:
            pass
    info("Загружаем РФ подсети с RIPE NCC...")
    all_cidrs = _fetch_ru_subnets_ripe()
    v4 = [c for c in all_cidrs if ":" not in c]
    v6 = [c for c in all_cidrs if ":" in c]
    return v4, v6


def _ingress_apply_ipset(port: int, v4: list, v6: list) -> bool:
    """
    Применяет блокировку через nft sets (эффективно для 5000+ CIDR).
    Создаёт/обновляет nft sets ingress_block_v4 / _v6 и добавляет DROP-правила
    в цепочку `input` таблицы `inet chimera`.

    Заменяет (миграция этапа 1.2):
      ipset create xray_ru_block hash:net family inet maxelem 500000 -exist
      ipset flush xray_ru_block
      ipset restore -! -f /tmp/xray_ingress_v4.ipset
      iptables -D INPUT -p tcp --dport <port> -m set --match-set xray_ru_block src \
          -j DROP
      iptables -A INPUT -p tcp --dport <port> -m set --match-set xray_ru_block src \
          -j DROP -m comment --comment xray-ru-ingress-block
      (и зеркально для IPv6: ipset create family inet6 + ip6tables -A)

    Теперь:
      nft_set_create("ingress_block_v4", set_type="ipv4_addr",
                     flags=["interval"], maxelem=500000)
      nft_set_atomic_swap("ingress_block_v4", v4)  # flush+add в одной транзакции
      nft_rule_add(table="chimera", chain="input",
                   rule_spec=f"tcp dport {port} ip saddr @ingress_block_v4 drop",
                   comment="xray-ru-ingress-block")
      (аналогично для IPv6: set_type="ipv6_addr", "ip6 saddr @ingress_block_v6")

    Имя функции сохранено как `_ingress_apply_ipset` для обратной совместимости
    (внешние импортеры могут ссылаться). Внутри всё работает через nft_common.
    """
    info(f"Применяю nftables блокировку ({len(v4)} IPv4 + {len(v6)} IPv6 CIDR)...")

    # ── IPv4 ──
    # nft set inet chimera ingress_block_v4 { type ipv4_addr; flags interval; size 500000; }
    nft_set_create(
        INGRESS_IPSET_NAME, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY,
        set_type="ipv4_addr", flags=["interval"], maxelem=500000,
    )
    # Атомарно заменяем содержимое set на v4 (flush+add одной транзакцией).
    # Заменяет `ipset flush` + `ipset restore -! -f <tmpfile>`. Между flush и add
    # нет окна видимости — это улучшение над ipset.
    if not nft_set_atomic_swap(
        INGRESS_IPSET_NAME, v4, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY,
    ):
        warn(f"nft_set_atomic_swap v4 failed ({INGRESS_IPSET_NAME})")
        return False

    # nft add rule inet chimera input tcp dport <port> ip saddr @ingress_block_v4
    #     drop comment "xray-ru-ingress-block"
    # Идемпотентно по comment-tag — повторный вызов не дублирует правило.
    if not nft_rule_add(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        rule_spec=f"tcp dport {port} ip saddr @{INGRESS_IPSET_NAME} drop",
        family=NFT_TABLE_FAMILY, comment=_INGRESS_COMMENT, idempotent=True,
    ):
        warn(f"nft_rule_add v4 failed (DROP :{port})")
        return False
    success(f"IPv4: {len(v4)} CIDR → nft set {INGRESS_IPSET_NAME} → DROP :{port}")

    # ── IPv6 ──
    if v6:
        # nft set inet chimera ingress_block_v6 { type ipv6_addr; flags interval; size 100000; }
        nft_set_create(
            INGRESS_IPSET6_NAME, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY,
            set_type="ipv6_addr", flags=["interval"], maxelem=100000,
        )
        nft_set_atomic_swap(
            INGRESS_IPSET6_NAME, v6, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY,
        )
        # nft add rule inet chimera input tcp dport <port>
        #     ip6 saddr @ingress_block_v6 drop comment "xray-ru-ingress-block"
        nft_rule_add(
            table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
            rule_spec=f"tcp dport {port} ip6 saddr @{INGRESS_IPSET6_NAME} drop",
            family=NFT_TABLE_FAMILY, comment=_INGRESS_COMMENT, idempotent=True,
        )
        success(f"IPv6: {len(v6)} CIDR → nft set {INGRESS_IPSET6_NAME} → DROP :{port}")

    return True


def _ingress_apply_iptables_plain(port: int, v4: list) -> bool:
    """Deprecated: бывший fallback-режим без ipset (iptables custom chain
    XRU_BLOCK + по одному правилу -s <cidr> -j DROP).

    В nftables sets поддерживаются нативно (nft_set_create + nft_set_add) —
    fallback больше не нужен. Функция сохранена для обратной совместимости и
    просто делегирует в `_ingress_apply_ipset` (IPv6 берётся как []).
    """
    return _ingress_apply_ipset(port, v4, [])


def _ingress_remove() -> None:
    """Удаляет все правила блокировки входящих РФ, включая whitelist ACCEPT.

    Заменяет (миграция этапа 1.2):
      iptables -D INPUT -p tcp --dport <port> -m set --match-set xray_ru_block src \
          -j DROP -m comment --comment xray-ru-ingress-block  (цикл до rc!=0)
      ip6tables -D INPUT ... -m set --match-set xray_ru_block6 src -j DROP
      ipset destroy xray_ru_block / xray_ru_block6
      iptables -F XRU_BLOCK; iptables -X XRU_BLOCK  (если был fallback-режим)

    Теперь:
      nft_rule_delete_by_comment(table="chimera", chain="input",
                                  comment="xray-ru-ingress-block")
        — один вызов находит ВСЕ правила с этим comment (v4 и v6 вместе,
          потому что у них одинаковый comment-tag) и удаляет через handle.
      nft_set_destroy("ingress_block_v4",  table="chimera", family="inet")
      nft_set_destroy("ingress_block_v6",  table="chimera", family="inet")
    """
    state = _ingress_state_load()
    port  = state.get("port", 0)
    meth  = state.get("method", "")

    #  сначала убираем per-user IP whitelist правило (если было).
    # Не трогаем nft sets и users.json — данные сохраняются для повторного включения.
    try:
        from chimera.modules.user_ip_whitelist import (
            remove_iptables_rule as _wl_remove,
            remove_cron as _wl_cron_remove,
        )
        if port:
            _wl_remove(port)
        _wl_cron_remove()
    except Exception:
        pass  # модуль недоступен — не критично

    # Сначала убираем ACCEPT-правила whitelist
    for _wip in state.get("whitelist", []):
        _ingress_whitelist_remove(_wip, port)

    # Удаляем все nft-правила с comment="xray-ru-ingress-block" из цепочки input
    # таблицы chimera. Заменяет цикл `iptables -D` (нужно было по одному -D на
    # каждое правило — для IPv4 и IPv6 отдельно). Здесь один вызов покрывает оба.
    # ВАЖНО: удаляем в любом случае (даже если state.method=plain) — на случай
    # если state.json устарел или рассинхронизирован с реальным ruleset.
    nft_rule_delete_by_comment(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        comment=_INGRESS_COMMENT, family=NFT_TABLE_FAMILY, max_iterations=20,
    )

    # Уничтожаем nft sets (v4 + v6) — это два разных set, надо удалить оба.
    # Заменяет `ipset destroy xray_ru_block` / `xray_ru_block6`.
    nft_set_destroy(INGRESS_IPSET_NAME,  table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY)
    nft_set_destroy(INGRESS_IPSET6_NAME, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY)

    # Сохраняем обновлённый ruleset в /etc/nftables.conf
    try:
        nft_persist()
    except Exception:
        pass

    # ── Очищаем UFW deny-правила накопленные autoban/honeypot/dpi-detector ───
    # Пока geo-блокировка работала, эти модули могли добавлять ufw deny from <ip>
    # для РФ-адресов. При полном удалении блокировки чистим их тоже.
    _ingress_flush_autoban_ufw()

    _ingress_state_save({"enabled": False, "port": 0, "cidrs_v4": 0,
                          "cidrs_v6": 0, "updated_at": "", "method": "",
                          "whitelist": state.get("whitelist", [])})
    INGRESS_CRON_FILE.unlink(missing_ok=True)
    INGRESS_CRON_SCRIPT.unlink(missing_ok=True)
    success("Блокировка входящих РФ удалена")


def _ingress_flush_autoban_ufw() -> None:
    """
    Удаляет из UFW все deny-правила добавленные autoban/honeypot/dpi-detector.
    Вызывается при полном удалении geo-блокировки.
    Не трогает allow-правила (SSH, порты сервисов).
    """
    if not shutil.which("ufw"):
        return
    try:
        r = _run(["ufw", "status", "numbered"], capture=True, check=False)
        lines = r.stdout.splitlines()
        # Собираем номера правил DENY with autoban/honeypot/dpi comments
        # ufw numbered output: "[ N] DENY IN   anywhere   COMMENT"
        targets = []
        for line in lines:
            low = line.lower()
            if ("deny" in low and
                    any(tag in low for tag in (
                        "xray-autoban", "xray-dpi-detector", "honeypot",
                        "xray-ru-ingress"
                    ))):
                import re as _re2
                m = _re2.match(r'\s*\[\s*(\d+)\]', line)
                if m:
                    targets.append(int(m.group(1)))
        # Удаляем в обратном порядке (нумерация сдвигается после каждого удаления)
        for num in sorted(targets, reverse=True):
            _run(["ufw", "--force", "delete", str(num)], check=False, quiet=True)
        if targets:
            success(f"UFW: удалено {len(targets)} накопленных deny-правил (autoban/honeypot/dpi)")
        else:
            info("UFW: накопленных deny-правил не найдено")
    except Exception as e:
        warn(f"UFW очистка: {e}")


def _ingress_whitelist_apply(ip: str, port: int) -> None:
    """
    Добавляет nft-правило ACCEPT для конкретного IP/CIDR — вставляет его
    в начало цепочки input (position=1) чтобы whitelist работал
    для всех портов: SSH (22), порт Xray и любых других сервисов.
    Помечает правило комментарием xray-ru-wl-<ip> для управления.

    Заменяет (миграция этапа 1.2):
      iptables -D INPUT -s <ip> -j ACCEPT -m comment --comment "xray-ru-wl-<ip>"
      iptables -I INPUT 1 -s <ip> -j ACCEPT -m comment --comment "xray-ru-wl-<ip>"
      (и зеркально для IPv6 через ip6tables если ip содержит `:`)

    Теперь:
      nft_rule_insert(table="chimera", chain="input",
                     rule_spec=f"ip saddr {ip} accept",
                     comment=f"xray-ru-wl-{ip-with-slashes-replaced}")
      (для IPv6 через `ip6 saddr {ip} accept` — тот же comment)

    В nft таблица inet chimera покрывает и v4, и v6 одновременно. nft_rule_insert
    с idempotent=True проверяет существование правила по comment перед вставкой.
    """
    comment = f"{_INGRESS_WL_PREFIX}{ip.replace('/', '_')}"
    # IPv6 CIDR содержит `:`, IPv4 — нет. В nft inet таблице можно использовать
    # как `ip saddr`, так и `ip6 saddr` (nft сам определит формат адреса).
    # Используем ip6 saddr для IPv6 CIDR, ip saddr для IPv4.
    if ":" in ip:
        spec = f"ip6 saddr {ip} accept"
    else:
        spec = f"ip saddr {ip} accept"
    # insert (position=1) — whitelist должен быть ПЕРЕД любыми DROP.
    # idempotent=True — если правило с таким comment уже есть, повторно не ставится.
    nft_rule_insert(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        rule_spec=spec, family=NFT_TABLE_FAMILY,
        comment=comment, idempotent=True,
    )


def _ingress_whitelist_remove(ip: str, port: int) -> None:
    """Удаляет ACCEPT-правило whitelist для IP/CIDR.

    Заменяет (миграция этапа 1.2):
      iptables -D INPUT -s <ip> -j ACCEPT -m comment --comment "xray-ru-wl-<ip>"
      ip6tables -D INPUT -s <ip> -j ACCEPT -m comment --comment "xray-ru-wl-<ip>"

    Теперь: один вызов nft_rule_delete_by_comment — находит все правила с
    указанным comment и удаляет через handle (nft -a list chain → handles →
    delete rule ... handle N).
    """
    comment = f"{_INGRESS_WL_PREFIX}{ip.replace('/', '_')}"
    nft_rule_delete_by_comment(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        comment=comment, family=NFT_TABLE_FAMILY, max_iterations=5,
    )


def _ingress_whitelist_apply_all(state: dict, port: int) -> None:
    """Применяет ACCEPT-правила для всех IP из whitelist в state."""
    for ip in state.get("whitelist", []):
        _ingress_whitelist_apply(ip, port)


def _ingress_enable(port: int) -> None:
    """Основной вызов: скачать CIDR, применить, сохранить состояние, поставить cron.

    После миграции на nftables (этап 1.2) больше нет ветвления ipset vs plain
    (nft поддерживает sets нативно). `_ingress_iptables_available` теперь
    эквивалентен `_nft_available()` — проверяет наличие `nft` binary.
    """
    if not _ingress_iptables_available():
        warn("nft не найден — невозможно применить правила. Установите: apt install nftables")
        return

    # Проверяем возраст RIPE-файла перед apply
    if not check_ripe_file_age(interactive=True):
        return
    v4, v6 = _ingress_get_cidrs()
    if not v4:
        warn("Список РФ подсетей пуст — проверьте доступность RIPE NCC")
        return

    # nftables поддерживает sets нативно — fallback-режим (`_ingress_apply_iptables_plain`)
    # больше не нужен. Ветка `plain` оставлена в state.json для обратной совместимости
    # со старыми state-файлами, но в коде всегда используем nft set path.
    ok = _ingress_apply_ipset(port, v4, v6)
    method = "nft"  # мигрировано с "ipset" / "plain"
    if ok:
        # Сохраняем nft ruleset в /etc/nftables.conf (заменяет `ipset save`).
        # Восстановление при boot — через `nftables.service` (заменяет
        # кастомный `xray-ipset-restore.service`).
        try:
            nft_persist()
        except Exception:
            pass

    #  интеграция с per-user IP whitelist (user_ip_whitelist.py).
    # Ставим ACCEPT-правило для nft set clients_wl ПЕРЕД DROP-правилом РФ,
    # чтобы пользователи с РФ-IP могли подключаться к VLESS на 443.
    # Это делается ПОСЛЕ _ingress_apply_ipset (который ставит DROP через
    # nft_rule_add в конец цепочки), через nft_rule_insert (position=1) —
    # приоритет над DROP.
    # Если user_ip_whitelist не установлен или nft недоступен —
    # просто пропускаем (блокировка РФ продолжит работать, но без whitelist).
    try:
        from chimera.modules.user_ip_whitelist import (
            apply_iptables_rule as _wl_apply,
            install_cron as _wl_cron,
        )
        if _wl_apply(port):
            success("Per-user IP whitelist: ACCEPT правило применено "
                    "(nft set clients_wl → ACCEPT на :%d)" % port)
            # Устанавливаем cron для автообновления nft set clients_wl.
            _wl_cron()
        else:
            info("Per-user IP whitelist: nft недоступен или нет пользователей — "
                 "пропускаю. Клиенты с РФ-IP будут заблокированы.")
    except Exception as e:
        warn(f"Per-user IP whitelist: не удалось применить ({e})")

    if not ok:
        warn("Не удалось применить правила — проверьте лог")
        return

    # Применяем whitelist ACCEPT-правила (вставляются перед DROP)
    _state_for_wl = _ingress_state_load()
    _ingress_whitelist_apply_all(_state_for_wl, port)
    wl_count = len(_state_for_wl.get("whitelist", []))
    if wl_count:
        success(f"Whitelist: {wl_count} IP защищены (ACCEPT до DROP)")

    # Сохраняем состояние — whitelist ОБЯЗАТЕЛЬНО переносим из предыдущего state,
    # иначе при каждом enable/restore он обнуляется и ACCEPT-правила теряются
    _ingress_state_save({
        "enabled":    True,
        "port":       port,
        "cidrs_v4":   len(v4),
        "cidrs_v6":   len(v6),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "method":     method,
        "whitelist":  _state_for_wl.get("whitelist", []),
    })

    # Устанавливаем cron для автообновления (еженедельно по воскресеньям в 03:00)
    _ingress_install_cron(port)
    # Включаем systemd `nftables.service` для восстановления правил при reboot.
    # Заменяет кастомный `xray-ipset-restore.service` (legacy, не нужен при nft).
    try:
        nft_persist_enable_systemd()
    except Exception:
        pass

    log_to_file("INFO",
        f"Ingress GeoIP block enabled: port={port}, "
        f"v4={len(v4)}, v6={len(v6)}, method={method}"
    )
    _tg_notify_event(
        "ingress_geoip",
        f"🛡 Блокировка входящих РФ <b>включена</b>: "
        f"порт {port}, {len(v4)} IPv4 CIDR, метод: {method}"
    )


def _ingress_install_cron(port: int) -> None:
    """Cron: еженедельное обновление списка РФ-подсетей и переприменение правил."""
    script = textwrap.dedent(f"""\
        #!/bin/bash
        # Xray Ingress GeoIP Block — weekly update (VLESS Installer)
        LOG="{INGRESS_LOG}"
        DATE=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$DATE] Ingress GeoIP update start" >> "$LOG"
        python3 {Path(__file__).resolve()} --ingress-geoip-update >> "$LOG" 2>&1
        echo "[$DATE] Ingress GeoIP update done (exit $?)" >> "$LOG"
    """)
    INGRESS_CRON_SCRIPT.write_text(script)
    INGRESS_CRON_SCRIPT.chmod(0o750)
    INGRESS_CRON_FILE.write_text(
        f"0 3 * * 0 root {INGRESS_CRON_SCRIPT} >> {INGRESS_LOG} 2>&1\n"
    )
    INGRESS_CRON_FILE.chmod(0o644)
    success(f"Cron обновления установлен: еженедельно вс 03:00 → {INGRESS_CRON_SCRIPT}")


def do_manage_ingress_geoip() -> None:
    """
    Меню: блокировка входящих подключений из РФ на уровне nftables
    (мигрировано с iptables/ipset, этап 1.2).
    Предназначено для Режима B — Entry Node в РФ, пользователи за рубежом.
    """
    while True:
        os.system("clear")
        print()
        state = _ingress_state_load()
        enabled  = state.get("enabled", False)
        port     = state.get("port", 0)
        cidrs_v4 = state.get("cidrs_v4", 0)
        cidrs_v6 = state.get("cidrs_v6", 0)
        updated  = state.get("updated_at", "")[:16].replace("T", " ")
        method   = state.get("method", "—")
        cron_ok  = INGRESS_CRON_FILE.exists()

        # Читаем текущий порт из state.json если не задан
        cur_port = port
        if not cur_port and _STATE_FILE.exists():
            try:
                cur_port = json.loads(_STATE_FILE.read_text()).get("server_port", 443)
            except Exception:
                cur_port = 443

        nft_ok = _nft_available()

        _box_top("БЛОКИРОВКА ВХОДЯЩИХ ИЗ РФ (nftables)")
        _box_row()

        wl_ips = state.get("whitelist", [])

        if enabled:
            _box_row(f"  Статус:   {GREEN}ВКЛЮЧЕНО{NC}")
            _box_row(f"  Порт:     {CYAN}{port}{NC}")
            _box_row(f"  IPv4:     {CYAN}{cidrs_v4} CIDR{NC}")
            _box_row(f"  IPv6:     {CYAN}{cidrs_v6} CIDR{NC}")
            _box_row(f"  Метод:    {CYAN}{method}{NC}")
            _box_row(f"  Обновлено:{CYAN} {updated or '—'}{NC}")
            _box_row(f"  Cron:     "
                     f"{''+GREEN+'вс 03:00'+NC if cron_ok else ''+YELLOW+'отключён'+NC}")
            _box_row(f"  {ripe_file_age_banner()}")
        else:
            _box_row(f"  Статус:   {YELLOW}ОТКЛЮЧЕНО{NC}")
            _box_row(f"  Порт Entry Node: {CYAN}{cur_port}{NC}")
            _box_row()
            _box_row(f"  {DIM}Блокирует входящие TCP на порт Xray с российских IP.{NC}")
            _box_row(f"  {DIM}РФ-подсети RIPE NCC (тот же список что split-tunnel).{NC}")
            _box_row(f"  {DIM}Режим B: Entry Node в РФ, пользователи за рубежом.{NC}")

        _box_sep()
        _box_row(f"  nft:   {''+GREEN+'доступен'+NC if nft_ok else ''+YELLOW+'НЕТ (apt install nftables)'+NC}")
        # Whitelist — показываем всегда
        if wl_ips:
            _box_row(f"  {BOLD}Whitelist (всегда разрешены — SSH/управление):{NC}")
            for _wip in wl_ips:
                _box_row(f"    {GREEN}✓{NC} {_wip}")
        else:
            _box_row(f"  {YELLOW}Whitelist пуст{NC} — добавьте ваш IP управления!")
        _box_sep()

        if enabled:
            _box_item("1", "Обновить список РФ подсетей и переприменить")
            _box_item("2", f"{RED}Отключить блокировку (удалить правила){NC}")
        else:
            _box_item("1", f"{GREEN}Включить блокировку входящих из РФ{NC}")

        _box_item("3", "Проверить текущие правила nftables")
        _box_item("4", f"Управление whitelist {DIM}(ваш IP, SSH-источники){NC}")
        _box_item("5", f"🧹 Очистить накопленные UFW deny (autoban/honeypot/dpi)")
        _box_row()
        _box_row(f"  {YELLOW}⚠{NC} {DIM}Добавьте свой IP в whitelist перед включением!{NC}")
        _box_row(f"  {DIM}  Иначе потеряете SSH если ваш провайдер — РФ.{NC}")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch == "1":
            if enabled:
                # Обновить
                print()
                info("Обновляю список РФ-подсетей и переприменяю правила...")
                _ingress_remove()
                _ingress_enable(cur_port if not port else port)
                input(f"{BLUE}Нажмите Enter...{NC}")
            else:
                # Включить — сначала проверяем/предлагаем добавить whitelist
                print()
                _box_top("Включение блокировки входящих из РФ")
                _box_row()
                _box_row(
                    f"  {YELLOW}ПРЕДУПРЕЖДЕНИЕ:{NC} После включения IP-адреса из РФ"
                )
                _box_row(f"  не смогут подключиться на порт {CYAN}{cur_port}{NC}.")
                _box_row()
                if wl_ips:
                    _box_row(f"  {GREEN}Whitelist:{NC}")
                    for _wip in wl_ips:
                        _box_row(f"    {GREEN}✓{NC} {_wip}  {DIM}(будет разрешён){NC}")
                else:
                    _box_row(f"  {RED}Whitelist пуст!{NC}")
                    _box_row(f"  {DIM}Если вы управляете сервером с РФ-IP —{NC}")
                    _box_row(f"  {DIM}вы потеряете SSH доступ!{NC}")
                    _box_row()
                    _box_row(f"  {DIM}Рекомендуется сначала добавить ваш IP (пункт 4).{NC}")
                _box_row()
                _box_bottom()
                print()
                if tui_confirm("Применить блокировку?", default=False):
                    _ingress_enable(cur_port)
                input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2" and enabled:
            print()
            if tui_confirm("Удалить все правила блокировки входящих из РФ?", default=False):
                _ingress_remove()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            print()
            _box_top("Текущие правила nftables (inet chimera input)")
            _box_row()
            # Заменяет `iptables -L INPUT -n --line-numbers`.
            # `nft list chain inet chimera input` выводит правила Chimera в input.
            # Включает comment-tag rules (видно комментарий xray-ru-ingress-block
            # и xray-ru-wl-<ip>).
            r = _run(["nft", "list", "chain", NFT_TABLE_FAMILY, NFT_TABLE_NAME,
                      NFT_CHAIN_INPUT], check=False, capture=True)
            for line in r.stdout.splitlines():
                # Фильтруем: показываем только строки с нашими comment-тегами,
                # заголовки цепочек и общую статистику set size.
                if ("xray-ru-ingress" in line or "xray-ru-wl" in line
                        or line.strip().startswith("chain")
                        or line.strip().startswith("table")
                        or line.strip().startswith("type")
                        or "@" + INGRESS_IPSET_NAME in line
                        or "@" + INGRESS_IPSET6_NAME in line):
                    _box_row(f"  {line}")
            if nft_ok:
                _box_row()
                # Количество элементов в nft set (без вывода 5000 IP).
                # Заменяет `ipset list <name> -t` (заголовок без members).
                cnt_v4 = nft_set_count(INGRESS_IPSET_NAME,
                                       table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY)
                cnt_v6 = nft_set_count(INGRESS_IPSET6_NAME,
                                       table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY)
                _box_row(f"  nft set @{INGRESS_IPSET_NAME}: {cnt_v4} elements")
                _box_row(f"  nft set @{INGRESS_IPSET6_NAME}: {cnt_v6} elements")
            _box_row()
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "4":
            # Управление whitelist
            print()
            _box_top("Whitelist — разрешённые IP (SSH / управление)")
            _box_row(f"  {DIM}IP из этого списка всегда пропускаются — до правил блокировки.{NC}")
            _box_row(f"  {DIM}Добавьте сюда ваш IP провайдера чтобы не потерять SSH.{NC}")
            _box_sep()
            if wl_ips:
                for i, _wip in enumerate(wl_ips, 1):
                    _box_item(str(i), f"{GREEN}{_wip}{NC}")
            else:
                _box_row(f"  {DIM}Список пуст{NC}")
            _box_sep()
            _box_item("+", "Добавить IP")
            _box_item("-", "Удалить IP")
            _box_item("D", f"Определить мой текущий IP автоматически")
            _box_bottom()
            wl_act = input("  Действие [+/-/D/Enter]: ").strip().lower()

            if wl_act == "d":
                # Автоопределение внешнего IP
                _my_ip = ""
                for _url in ("https://api.ipify.org", "https://ifconfig.me/ip",
                             "https://icanhazip.com"):
                    try:
                        import urllib.request as _ur2
                        with _ur2.urlopen(_url, timeout=5) as _r2:
                            _my_ip = _r2.read().decode().strip()
                        if _my_ip:
                            break
                    except Exception:
                        continue
                if _my_ip:
                    print()
                    print(f"  {GREEN}Ваш внешний IP:{NC} {CYAN}{_my_ip}{NC}")
                    if tui_confirm(f"Добавить {_my_ip} в whitelist?", default=True):
                        wl_act = "+"
                        _prefill_ip = _my_ip
                    else:
                        _prefill_ip = ""
                else:
                    warn("Не удалось определить внешний IP — введите вручную")
                    wl_act = "+"
                    _prefill_ip = ""
            else:
                _prefill_ip = ""

            if wl_act == "+":
                new_ip = _prefill_ip or input("  IP или CIDR для whitelist: ").strip()
                if new_ip and new_ip not in wl_ips:
                    wl_ips.append(new_ip)
                    state["whitelist"] = wl_ips
                    _ingress_state_save(state)
                    success(f"Добавлен: {new_ip}")
                    # Если блокировка уже включена — сразу применяем ACCEPT правило
                    if enabled:
                        _ingress_whitelist_apply(new_ip, port)
                        success(f"ACCEPT правило для {new_ip} применено немедленно")
                elif new_ip in wl_ips:
                    warn(f"{new_ip} уже в whitelist")

            elif wl_act == "-":
                if not wl_ips:
                    warn("Список пуст")
                else:
                    raw_n = input("  Номер для удаления: ").strip()
                    if raw_n.isdigit() and 1 <= int(raw_n) <= len(wl_ips):
                        removed_ip = wl_ips.pop(int(raw_n) - 1)
                        state["whitelist"] = wl_ips
                        _ingress_state_save(state)
                        success(f"Удалён: {removed_ip}")
                        # Если блокировка включена — убираем ACCEPT правило
                        if enabled:
                            _ingress_whitelist_remove(removed_ip, port)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            print()
            info("Очищаю накопленные UFW deny-правила (autoban/honeypot/dpi-detector)...")
            _ingress_flush_autoban_ufw()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


# =============================================================================
#  МОДУЛЬ 11: КАСТОМНЫЕ DNS ПРАВИЛА (Xray hosts + DNSCrypt static)
#
#  Позволяет задать:
#    • domain → IP(s)   через секцию hosts{} в Xray config
#    • domain → outbound через dns-routing правила (domain → direct/proxy)
#    • Просмотр текущих hosts и dns-правил
#    • Совместимость с DNSCrypt-proxy (blocked-names.txt)
# dns_rules — перенесено в chimera/modules/dns_rules.py
# honeypot — перенесено в chimera/modules/honeypot.py
# =============================================================================

