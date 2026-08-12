"""
chimera/modules/port_hopping.py
───────────────────────────────────────────────────────────────────────────────
Port Hopping — приём подключений на диапазон портов без изменения конфига Xray.

Принцип:
    Xray продолжает слушать ОДИН порт (SERVER_PORT, обычно 443).
    nftables PREROUTING REDIRECT перенаправляет трафик с любого порта из
    заданного диапазона → на SERVER_PORT.

    Клиент может подключаться на любой порт диапазона — работает любой.
    ТСПУ заблокировала 443? Клиент переключается на 8443, 10443, etc.

    config.json Xray НЕ меняется. Nginx НЕ меняется. Сервисы НЕ перезапускаются.
    UFW при включённом firewall: добавляется allow на диапазон.

Совместимость:
    Режим A  (одиночный сервер):        ✓ полная
    Режим B  (каскад Entry→Exit AWG):   ✓ только на entry-ноде
    Режим B Multi (мульти-каскад):      ✓ только на entry-ноде
    Протокол REALITY:                   ✓
    Протокол xHTTP:                     ✓

Хранение состояния:
    /var/lib/xray-installer/port_hopping.json
    {
        "enabled": true,
        "real_port": 443,
        "range_start": 10000,
        "range_end":   20000,
        "proto": "tcp"        # tcp | udp | both
    }

АРХИТЕКТУРА (мигрировано с iptables на nftables, этап 1.4):
    • nft rules: table=inet chimera, chain=prerouting,
      <proto> dport <range_start>-<range_end> redirect to :<real_port>
      comment "xray-port-hopping"
    • Идемпотентность: через comment-tag (nft_rule_add с idempotent=True
      проверяет существование правила с этим comment перед добавлением через
      nft -j list chain) — заменяет -C перед -A паттерн iptables
    • Persist после reboot: единый nftables.service (читает /etc/nftables.conf
      через `nft -f` при старте системы) — заменяет кастомный
      xray-port-hopping.service (раньше запускал `iptables -t nat -A ...`).

Правила nftables:
    Помечаются комментарием "xray-port-hopping" для безопасного удаления.
    При отключении — удаляются только свои правила, остальные не трогаются.

Публичное API:
    do_port_hopping_menu()   — интерактивное меню
    ph_status() -> dict      — текущее состояние (для health/status команд)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

# nftables — централизованная обёртка над `nft` CLI (этап 1.4 миграции)
from .nft_common import (
    nft_nat_redirect, nft_rule_exists, nft_rule_delete_by_comment,
    nft_persist, _nft_available,
)
from .nft_constants import (
    NFT_TABLE_NAME, NFT_TABLE_FAMILY, NFT_CHAIN_PREROUTING,
    COMMENT_PORT_HOPPING, NFT_PERSIST_FILE,
)

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        light = os.environ.get("VLESS_THEME", "").lower() == "light"
        if light:
            return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                        CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                        DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m')
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                    DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m')
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED=_C['RED']; GREEN=_C['GREEN']; YELLOW=_C['YELLOW']; CYAN=_C['CYAN']
BLUE=_C['BLUE']; BOLD=_C['BOLD']; DIM=_C['DIM']; WHITE=_C['WHITE']; NC=_C['NC']

# ── Константы ─────────────────────────────────────────────────────────────────
_STATE_FILE  = Path("/var/lib/xray-installer/state.json")
_PH_FILE     = Path("/var/lib/xray-installer/port_hopping.json")
_LOG_FILE    = Path("/var/log/chimera.log")
# Метка для правил nftables (раньше — iptables). Используется для идемпотентного
# добавления и безопасного удаления правил (nft_rule_delete_by_comment).
_COMMENT     = COMMENT_PORT_HOPPING  # "xray-port-hopping"
# Единый persist-файл (заменяет /etc/iptables/rules.v4 + кастомный systemd unit)
_NFT_CONF    = Path(NFT_PERSIST_FILE)  # "/etc/nftables.conf"

# ── Логирование ────────────────────────────────────────────────────────────────
def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        with _LOG_FILE.open("a") as f:
            from datetime import datetime
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [PORT-HOP] [{level}] {clean}\n")
    except Exception:
        pass

def _info(msg: str):  print(f"{CYAN}[INFO]{NC}  {msg}");    _log("INFO",    msg)
def _ok(msg: str):    print(f"{GREEN}[OK]{NC}    {msg}");   _log("SUCCESS", msg)
def _warn(msg: str):  print(f"{YELLOW}[WARN]{NC}  {msg}");  _log("WARN",    msg)
def _err(msg: str):   print(f"{RED}[ERR]{NC}   {msg}");     _log("ERROR",   msg)

# ── box_renderer ───────────────────────────────────────────────────────────────
from chimera.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item,
    _box_back, _box_info, _box_warn, _box_desc,
)

# ── Вспомогательные ───────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)


def _load_ph() -> dict:
    try:
        if _PH_FILE.exists():
            return json.loads(_PH_FILE.read_text())
    except Exception:
        pass
    return {"enabled": False}


def _save_ph(cfg: dict) -> None:
    _PH_FILE.parent.mkdir(parents=True, exist_ok=True)
    _PH_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    _PH_FILE.chmod(0o600)


def _load_state() -> dict:
    try:
        if _STATE_FILE.exists():
            return json.loads(_STATE_FILE.read_text())
    except Exception:
        pass
    return {}


def _real_port() -> int:
    """Читает реальный порт Xray из state.json."""
    return int(_load_state().get("server_port", 443))


def _ufw_active() -> bool:
    try:
        r = _run(["ufw", "status"], capture=True, quiet=False)
        return "active" in r.stdout.lower()
    except Exception:
        return False


def _iptables_available() -> bool:
    """Алиас для обратной совместимости. Теперь проверяет наличие `nft` binary.

    Заменяет: shutil.which("iptables") / `iptables --version`.
    Теперь:    _nft_available() из nft_common (проверяет `nft` в PATH).
    """
    return _nft_available()

# ── Ядро: управление правилами nftables ───────────────────────────────────────

def _rules_exist(proto: str = "tcp") -> bool:
    """Проверяет, есть ли наши правила в nft chain prerouting.

    Заменяет: цикл `iptables -t nat -C PREROUTING -p <proto> --dport 1:65534 ...`
              + парсинг `iptables -t nat -L PREROUTING -n` на наличие comment.
    Теперь: nft_rule_exists(comment="xray-port-hopping") — comment-tag
            однозначно идентифицирует наши правила.
    """
    return nft_rule_exists(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_PREROUTING,
        comment=_COMMENT, family=NFT_TABLE_FAMILY
    )


def _add_rules(range_start: int, range_end: int, real_port: int, proto: str) -> bool:
    """Добавляет nft правила PREROUTING REDIRECT. Возвращает True при успехе.

    Заменяет:
        iptables -t nat -A PREROUTING -p <proto> --dport <rs>:<re> \
            -j REDIRECT --to-port <real_port> -m comment --comment xray-port-hopping
    Теперь (nft, диапазон через дефис вместо двоеточия):
        nft add rule inet chimera prerouting <proto> dport <rs>-<re> \
            redirect to :<real_port> comment "xray-port-hopping"

    Для proto="both" добавляет два правила (tcp и udp). Каждое идемпотентно
    через comment-tag (повторный вызов НЕ создаёт дубликаты).
    """
    protos = ["tcp", "udp"] if proto == "both" else [proto]
    # nft использует диапазон портов через дефис ('10000-20000'), а не
    # двоеточие как iptables ('10000:20000').
    dport_range = f"{range_start}-{range_end}"
    ok = True
    for p in protos:
        added = nft_nat_redirect(
            prerouting=True,
            proto=p,
            dport=dport_range,
            to_port=real_port,
            comment=_COMMENT,
        )
        if not added:
            _err(f"Не удалось добавить правило nft для {p}")
            ok = False
    return ok


def _remove_rules() -> bool:
    """Удаляет все правила с комментарием xray-port-hopping. Безопасно — только свои.

    Заменяет: цикл `iptables -t nat -L PREROUTING -n --line-numbers` →
              парсинг номера правила с нашим comment → `iptables -t nat -D`.
    Теперь: один вызов nft_rule_delete_by_comment находит ВСЕ правила с этим
            comment в цепочке prerouting (через `nft -a -j list chain` → handles)
            и удаляет их через `nft delete rule ... handle <N>`.
    """
    nft_rule_delete_by_comment(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_PREROUTING,
        comment=_COMMENT, family=NFT_TABLE_FAMILY, max_iterations=50
    )
    return True


def _ufw_allow_range(range_start: int, range_end: int, proto: str) -> None:
    """Добавляет правило UFW для диапазона портов.

     миграция на port_registry (с backward compat fallback).
    """
    protos = ["tcp", "udp"] if proto == "both" else [proto]
    #  сначала port_registry.
    try:
        from chimera.modules.port_registry import (
            ufw_open_port_range, port_register, SERVICE_PORT_HOPPING,
        )
        for p in protos:
            for port in range(range_start, range_end + 1):
                port_register(SERVICE_PORT_HOPPING, port, p,
                              comment="port hopping range", force=True)
            ufw_open_port_range(range_start, range_end, p, SERVICE_PORT_HOPPING,
                                comment="port hopping range")
        return
    except Exception:
        pass
    for p in protos:
        _run([
            "ufw", "allow", f"{range_start}:{range_end}/{p}",
            "comment", f"{_COMMENT}"
        ], quiet=True)


def _ufw_delete_range(range_start: int, range_end: int, proto: str) -> None:
    """Удаляет правило UFW для диапазона портов.

     миграция на port_registry (с legacy comment для backward compat).
    """
    protos = ["tcp", "udp"] if proto == "both" else [proto]
    #  сначала port_registry.
    try:
        from chimera.modules.port_registry import (
            ufw_close_port_range, port_unregister, SERVICE_PORT_HOPPING,
        )
        for p in protos:
            ufw_close_port_range(range_start, range_end, p, SERVICE_PORT_HOPPING,
                                 legacy_comments=[_COMMENT])
            for port in range(range_start, range_end + 1):
                port_unregister(SERVICE_PORT_HOPPING, port, p)
        return
    except Exception:
        pass
    for p in protos:
        _run([
            "ufw", "delete", "allow", f"{range_start}:{range_end}/{p}"
        ], quiet=True)


def _persist_iptables() -> None:
    """Сохраняет nft ruleset для восстановления после перезагрузки.

    Заменяет (3 разных механизма, существовавших раньше):
      • Метод 1: iptables-save > /etc/iptables/rules.v4 (если /etc/iptables/ существует)
      • Метод 2: rc.local с `iptables-restore < /etc/iptables/rules.v4`
      • Метод 3: кастомный systemd oneshot `xray-port-hopping.service`,
        который при старте системы делал `iptables -t nat -A PREROUTING ...`.
    Теперь: один вызов `nft_persist()` → `nft list ruleset > /etc/nftables.conf`.
            Стандартный `nftables.service` (Debian/Ubuntu package) читает этот
            файл через `nft -f /etc/nftables.conf` при загрузке системы и
            восстанавливает ВСЕ правила Chimera (port hopping + dns_redirect +
            ingress_geoip + ipban + ...).
    """
    if not _nft_available():
        return
    try:
        # Сохраняем весь ruleset в /etc/nftables.conf
        nft_persist(NFT_PERSIST_FILE)
        # Включаем встроенный nftables.service
        from .nft_common import nft_persist_enable_systemd
        nft_persist_enable_systemd()
        _log("INFO", f"nft ruleset saved to {NFT_PERSIST_FILE}, nftables.service enabled")
    except Exception as e:
        _log("WARN", f"cannot persist nft ruleset: {e}")


def _enable_hopping(range_start: int, range_end: int, real_port: int, proto: str) -> bool:
    """Включает port hopping. Возвращает True при успехе."""
    # Сначала чистим старые правила (если были)
    _remove_rules()

    # Добавляем новые
    if not _add_rules(range_start, range_end, real_port, proto):
        return False

    # UFW если активен
    if _ufw_active():
        _ufw_allow_range(range_start, range_end, proto)
        _info("UFW: добавлено правило для диапазона портов")

    # Сохраняем состояние
    cfg = {
        "enabled": True,
        "real_port": real_port,
        "range_start": range_start,
        "range_end": range_end,
        "proto": proto,
    }
    _save_ph(cfg)

    # Персистим
    _persist_iptables()

    _log("INFO", f"Port hopping enabled: {range_start}-{range_end} → {real_port} ({proto})")
    return True


def _disable_hopping() -> bool:
    """Отключает port hopping, удаляет правила."""
    ph = _load_ph()
    _remove_rules()

    if _ufw_active() and ph.get("range_start") and ph.get("range_end"):
        _ufw_delete_range(ph["range_start"], ph["range_end"], ph.get("proto", "tcp"))
        _info("UFW: правило диапазона удалено")

    cfg = {"enabled": False}
    _save_ph(cfg)
    _persist_iptables()  # обновим — сервис отключится

    _log("INFO", "Port hopping disabled")
    return True

# ── Публичное API ─────────────────────────────────────────────────────────────

def ph_status() -> dict:
    """Возвращает текущее состояние port hopping (для status/health команд)."""
    ph = _load_ph()
    if not ph.get("enabled"):
        return {"enabled": False}

    # Проверяем, реально ли правила в nftables (через comment-tag).
    # Заменяет: парсинг `iptables -t nat -L PREROUTING -n` на наличие comment.
    rules_active = nft_rule_exists(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_PREROUTING,
        comment=_COMMENT, family=NFT_TABLE_FAMILY,
    )

    return {
        "enabled": True,
        "rules_active": rules_active,
        "real_port": ph.get("real_port", 443),
        "range_start": ph.get("range_start", 10000),
        "range_end": ph.get("range_end", 20000),
        "proto": ph.get("proto", "tcp"),
    }


def do_port_hopping_menu() -> None:
    """Главное меню Port Hopping. Вызывается из _core.py."""

    if not _iptables_available():
        print()
        _box_top("⚡  PORT HOPPING")
        _box_warn("nftables не найден на этой системе")
        _box_info("Установите: apt install nftables")
        _box_bottom()
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    while True:
        os.system("clear")
        ph = _load_ph()
        enabled = ph.get("enabled", False)
        real_port = ph.get("real_port", _real_port())

        # Проверяем активность правил в nftables (через comment-tag).
        # Заменяет: `iptables -t nat -L PREROUTING -n` + поиск comment в выводе.
        rules_active = False
        if enabled:
            rules_active = nft_rule_exists(
                table=NFT_TABLE_NAME, chain=NFT_CHAIN_PREROUTING,
                comment=_COMMENT, family=NFT_TABLE_FAMILY,
            )

        print()
        _box_top("⚡  PORT HOPPING — приём подключений на диапазон портов")
        _box_desc(
            "Xray слушает один порт. nftables перенаправляет любой порт из диапазона "
            "на него. Клиент выбирает любой свободный порт — ТСПУ не может заблокировать их все."
        )
        _box_sep()

        if enabled:
            status_str = f"{GREEN}ВКЛЮЧЁН{NC}" if rules_active else f"{YELLOW}ВКЛЮЧЁН (правила не найдены в nftables!){NC}"
        else:
            status_str = f"{DIM}ОТКЛЮЧЁН{NC}"

        _box_row(f"  Статус:       {status_str}")
        _box_row(f"  Реальный порт Xray: {CYAN}{real_port}{NC}")
        if enabled:
            _box_row(f"  Диапазон:     {CYAN}{ph.get('range_start')}–{ph.get('range_end')}{NC}  ({ph.get('proto','tcp').upper()})")
            _box_row()
            _box_info("Клиенты могут подключаться на ЛЮБОЙ порт из диапазона")
        _box_sep()

        _box_item("1", f"{'Изменить диапазон / перенастроить' if enabled else 'Включить port hopping'}")
        if enabled:
            _box_item("2", f"{RED}Отключить port hopping{NC}")
            _box_item("3", "Проверить правила nftables")
            _box_item("4", "Показать готовые ссылки для клиентов")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            return

        if ch == "1":
            _menu_configure(real_port)
        elif ch == "2" and enabled:
            _menu_disable()
        elif ch == "3" and enabled:
            _menu_show_rules()
        elif ch == "4" and enabled:
            _menu_show_links(ph)
        elif ch in ("q", "Q", "0", ""):
            return
        else:
            _warn("Неверный выбор")
            time.sleep(1)


def _menu_configure(real_port: int) -> None:
    """Настройка и включение port hopping."""
    os.system("clear")
    print()
    _box_top("⚡  PORT HOPPING — настройка")
    _box_row()
    _box_row(f"  Реальный порт Xray: {CYAN}{real_port}{NC}  (менять не нужно)")
    _box_row()
    _box_desc(
        "Выберите диапазон портов. Клиенты смогут подключаться на любой из них. "
        "Рекомендуется: широкий диапазон в верхней части (10000–60000)."
    )
    _box_sep()
    _box_item("1", f"10000–20000  {GREEN}(рекомендуется){NC}")
    _box_item("2", f"20000–40000")
    _box_item("3", f"10000–60000  {DIM}(максимальный охват){NC}")
    _box_item("4", f"Задать вручную")
    _box_sep()
    _box_item("P", "Протокол: TCP / UDP / оба")
    _box_back()
    _box_bottom()

    ph = _load_ph()
    proto = ph.get("proto", "tcp")

    try:
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return

    ranges = {
        "1": (10000, 20000),
        "2": (20000, 40000),
        "3": (10000, 60000),
    }

    if ch in ranges:
        rs, re_ = ranges[ch]
    elif ch == "4":
        try:
            rs_str = input(f"  Начало диапазона [{GREEN}10000{NC}]: ").strip() or "10000"
            re_str = input(f"  Конец диапазона  [{GREEN}20000{NC}]: ").strip() or "20000"
            rs, re_ = int(rs_str), int(re_str)
        except ValueError:
            _warn("Некорректный ввод")
            time.sleep(1)
            return
        if rs >= re_ or rs < 1024 or re_ > 65535:
            _warn("Некорректный диапазон (1024–65535, начало < конца)")
            time.sleep(1)
            return
        if rs <= real_port <= re_:
            _warn(f"Диапазон включает реальный порт Xray ({real_port}) — это конфликт!")
            time.sleep(2)
            return
    elif ch == "p":
        _menu_change_proto(ph)
        return
    elif ch in ("q", "Q", "0", ""):
        return
    else:
        _warn("Неверный выбор")
        time.sleep(1)
        return

    if rs <= real_port <= re_:
        _warn(f"Диапазон включает реальный порт Xray ({real_port}) — выберите другой диапазон")
        time.sleep(2)
        return

    print()
    _info(f"Настраиваю port hopping: {rs}–{re_} ({proto.upper()}) → {real_port}")

    if not _enable_hopping(rs, re_, real_port, proto):
        _err("Не удалось настроить port hopping")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    _ok(f"Port hopping включён: {rs}–{re_} → {real_port}")
    print()
    _box_top("📋  Как использовать клиентам")
    _box_desc(
        f"Вместо порта {real_port} можно использовать ЛЮБОЙ порт из диапазона {rs}–{re_}. "
        f"Например: 12345, 15000, 19999 — все работают."
    )
    _box_info("В NekoBox/v2rayNG: измените порт в настройках подключения")
    _box_info("Ссылка vless://... — замените порт на любой из диапазона")
    _box_bottom()

    input(f"\n{BLUE}Нажмите Enter...{NC}")


def _menu_change_proto(ph: dict) -> None:
    """Смена протокола (TCP/UDP/both)."""
    print()
    _box_top("Протокол port hopping")
    _box_item("1", f"TCP  {GREEN}(рекомендуется для VLESS/REALITY){NC}")
    _box_item("2", f"UDP  {DIM}(для UDP-протоколов){NC}")
    _box_item("3", f"TCP + UDP  {DIM}(оба){NC}")
    _box_back()
    _box_bottom()
    try:
        ch = input(f"{CYAN}Выбор:{NC} ").strip()
    except KeyboardInterrupt:
        return
    proto_map = {"1": "tcp", "2": "udp", "3": "both"}
    if ch in proto_map:
        ph["proto"] = proto_map[ch]
        _save_ph(ph)
        _ok(f"Протокол изменён на: {proto_map[ch].upper()}")
    time.sleep(1)


def _menu_disable() -> None:
    """Подтверждение и отключение."""
    print()
    try:
        ans = input(f"  {YELLOW}Отключить port hopping и удалить правила nftables? [y/N]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return
    if ans != "y":
        return
    _info("Удаляю правила nftables...")
    _disable_hopping()
    _ok("Port hopping отключён")
    input(f"\n{BLUE}Нажмите Enter...{NC}")


def _menu_show_rules() -> None:
    """Показывает текущие правила nftables с нашим комментарием.

    Заменяет: `iptables -t nat -L PREROUTING -n -v --line-numbers` +
              фильтрация по comment в выводе.
    Теперь: `nft list chain inet chimera prerouting` +
           `nft -a list chain inet chimera prerouting` (с handles для аудита).
    """
    os.system("clear")
    print()
    _box_top("🔍  Правила nftables (Port Hopping)")
    _box_bottom()
    print()
    r = _run(["nft", "list", "chain", "inet", "chimera", "prerouting"],
             capture=True)
    lines = (r.stdout or "").splitlines()
    found = False
    for line in lines:
        if _COMMENT in line or line.startswith("chain") or line.startswith("\t"):
            print(f"  {line}")
            if _COMMENT in line:
                found = True
    if not found:
        _warn("Правила с меткой xray-port-hopping не найдены!")
    print()
    input(f"{BLUE}Нажмите Enter...{NC}")


def _menu_show_links(ph: dict) -> None:
    """Показывает примеры ссылок с альтернативными портами."""
    os.system("clear")
    state = _load_state()
    domain = state.get("domain", "") or state.get("server_ip", "YOUR_SERVER")
    uuid = state.get("uuid", "YOUR-UUID")
    proto = state.get("protocol_mode", "reality")
    rs = ph.get("range_start", 10000)
    re_ = ph.get("range_end", 20000)
    real_port = ph.get("real_port", 443)

    import random as _rnd
    sample_ports = sorted(_rnd.sample(range(rs, re_+1), min(5, re_-rs+1)))

    print()
    _box_top("📋  Примеры ссылок с альтернативными портами")
    _box_desc(f"Диапазон {rs}–{re_}. Можно использовать любой порт вместо {real_port}.")
    _box_sep()
    for p in sample_ports:
        _box_row(f"  Порт {CYAN}{p}{NC}:  {domain}:{p}")
    _box_sep()
    _box_info("В клиенте просто замените порт в настройках соединения")
    _box_info("UUID и все остальные параметры остаются прежними")
    _box_bottom()
    print()
    input(f"{BLUE}Нажмите Enter...{NC}")
