"""
vless_installer/modules/port_hopping.py
───────────────────────────────────────────────────────────────────────────────
Port Hopping — приём подключений на диапазон портов без изменения конфига Xray.

Принцип:
    Xray продолжает слушать ОДИН порт (SERVER_PORT, обычно 443).
    iptables PREROUTING REDIRECT перенаправляет трафик с любого порта из
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

Правила iptables:
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
_LOG_FILE    = Path("/var/log/vless-install.log")
_COMMENT     = "xray-port-hopping"  # метка для правил iptables
_PERSIST_DIR = Path("/etc/iptables")

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
from vless_installer.modules.box_renderer import (
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
    try:
        r = _run(["iptables", "--version"], capture=True, quiet=False)
        return r.returncode == 0
    except Exception:
        return False

# ── Ядро: управление правилами iptables ───────────────────────────────────────

def _rules_exist(proto: str = "tcp") -> bool:
    """Проверяет, есть ли наши правила в PREROUTING."""
    protos = ["tcp", "udp"] if proto == "both" else [proto]
    for p in protos:
        r = _run(
            ["iptables", "-t", "nat", "-C", "PREROUTING",
             "-p", p, "--dport", "1:65534",
             "-m", "comment", "--comment", _COMMENT,
             "-j", "REDIRECT", "--to-port", "1"],
            capture=True, quiet=False
        )
        if r.returncode == 0:
            return True
    # Ищем по комментарию в выводе -L
    r = _run(["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "--line-numbers"], capture=True)
    return _COMMENT in r.stdout


def _add_rules(range_start: int, range_end: int, real_port: int, proto: str) -> bool:
    """Добавляет правила PREROUTING REDIRECT. Возвращает True при успехе."""
    protos = ["tcp", "udp"] if proto == "both" else [proto]
    ok = True
    for p in protos:
        port_range = f"{range_start}:{range_end}"
        r = _run([
            "iptables", "-t", "nat", "-A", "PREROUTING",
            "-p", p, "--dport", port_range,
            "-m", "comment", "--comment", _COMMENT,
            "-j", "REDIRECT", "--to-port", str(real_port),
        ], quiet=True)
        if r.returncode != 0:
            _err(f"Не удалось добавить правило iptables для {p}")
            ok = False
    return ok


def _remove_rules() -> bool:
    """Удаляет все правила с комментарием xray-port-hopping. Безопасно — только свои."""
    removed = 0
    for table_chain in [("nat", "PREROUTING")]:
        table, chain = table_chain
        while True:
            r = _run(
                ["iptables", "-t", table, "-L", chain, "-n", "--line-numbers"],
                capture=True
            )
            lines = r.stdout.splitlines()
            target_line = None
            for line in lines:
                if _COMMENT in line:
                    # Первая колонка — номер правила
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        target_line = parts[0]
                        break
            if target_line is None:
                break
            _run(["iptables", "-t", table, "-D", chain, target_line], quiet=True)
            removed += 1
            if removed > 50:  # защита от бесконечного цикла
                break
    return True


def _ufw_allow_range(range_start: int, range_end: int, proto: str) -> None:
    """Добавляет правило UFW для диапазона портов."""
    protos = ["tcp", "udp"] if proto == "both" else [proto]
    for p in protos:
        _run([
            "ufw", "allow", f"{range_start}:{range_end}/{p}",
            "comment", f"{_COMMENT}"
        ], quiet=True)


def _ufw_delete_range(range_start: int, range_end: int, proto: str) -> None:
    """Удаляет правило UFW для диапазона портов."""
    protos = ["tcp", "udp"] if proto == "both" else [proto]
    for p in protos:
        _run([
            "ufw", "delete", "allow", f"{range_start}:{range_end}/{p}"
        ], quiet=True)


def _persist_iptables() -> None:
    """Сохраняет правила iptables для восстановления после перезагрузки."""
    # Метод 1: iptables-persistent / netfilter-persistent
    if Path("/etc/iptables").exists():
        try:
            r = _run(["iptables-save"], capture=True)
            if r.returncode == 0:
                Path("/etc/iptables/rules.v4").write_text(r.stdout)
        except Exception:
            pass

    # Метод 2: rc.local как fallback
    rc_local = Path("/etc/rc.local")
    restore_cmd = f"iptables-restore < /etc/iptables/rules.v4"
    if rc_local.exists():
        content = rc_local.read_text()
        if restore_cmd not in content:
            # Вставляем перед последней строкой (обычно "exit 0")
            lines = content.rstrip().splitlines()
            if lines and lines[-1].strip() == "exit 0":
                lines.insert(-1, restore_cmd)
            else:
                lines.append(restore_cmd)
            rc_local.write_text("\n".join(lines) + "\n")
    else:
        rc_local.write_text(
            "#!/bin/sh -e\n"
            f"# Restored by vless-installer port-hopping\n"
            f"{restore_cmd}\n"
            "exit 0\n"
        )
        rc_local.chmod(0o755)

    # Метод 3: systemd oneshot service (наиболее надёжный)
    svc_path = Path("/etc/systemd/system/xray-port-hopping.service")
    ph = _load_ph()
    if ph.get("enabled"):
        rs = ph.get("range_start", 10000)
        re_ = ph.get("range_end", 20000)
        rp = ph.get("real_port", 443)
        proto = ph.get("proto", "tcp")
        protos = ["tcp", "udp"] if proto == "both" else [proto]
        cmds = []
        for p in protos:
            cmds.append(
                f"ExecStart=/sbin/iptables -t nat -A PREROUTING "
                f"-p {p} --dport {rs}:{re_} "
                f"-m comment --comment {_COMMENT} "
                f"-j REDIRECT --to-port {rp}"
            )
        svc_content = (
            "[Unit]\n"
            "Description=Xray Port Hopping iptables rules\n"
            "After=network.target\n"
            "Before=xray.service\n\n"
            "[Service]\n"
            "Type=oneshot\n"
            "RemainAfterExit=yes\n"
        )
        for c in cmds:
            svc_content += c + "\n"
        svc_content += (
            "\n[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        svc_path.write_text(svc_content)
        _run(["systemctl", "daemon-reload"], quiet=True)
        _run(["systemctl", "enable", "xray-port-hopping.service"], quiet=True)
    else:
        # Отключаем сервис при выключении
        if svc_path.exists():
            _run(["systemctl", "disable", "--now", "xray-port-hopping.service"], quiet=True)
            svc_path.unlink(missing_ok=True)
            _run(["systemctl", "daemon-reload"], quiet=True)


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

    # Проверяем, реально ли правила в iptables
    r = _run(["iptables", "-t", "nat", "-L", "PREROUTING", "-n"], capture=True)
    rules_active = _COMMENT in r.stdout

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
        _box_warn("iptables не найден на этой системе")
        _box_info("Установите: apt install iptables")
        _box_bottom()
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    while True:
        os.system("clear")
        ph = _load_ph()
        enabled = ph.get("enabled", False)
        real_port = ph.get("real_port", _real_port())

        # Проверяем активность правил в iptables
        rules_active = False
        if enabled:
            r = _run(["iptables", "-t", "nat", "-L", "PREROUTING", "-n"], capture=True)
            rules_active = _COMMENT in r.stdout

        print()
        _box_top("⚡  PORT HOPPING — приём подключений на диапазон портов")
        _box_desc(
            "Xray слушает один порт. iptables перенаправляет любой порт из диапазона "
            "на него. Клиент выбирает любой свободный порт — ТСПУ не может заблокировать их все."
        )
        _box_sep()

        if enabled:
            status_str = f"{GREEN}ВКЛЮЧЁН{NC}" if rules_active else f"{YELLOW}ВКЛЮЧЁН (правила не найдены в iptables!){NC}"
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
            _box_item("3", "Проверить правила iptables")
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
        ans = input(f"  {YELLOW}Отключить port hopping и удалить правила iptables? [y/N]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return
    if ans != "y":
        return
    _info("Удаляю правила iptables...")
    _disable_hopping()
    _ok("Port hopping отключён")
    input(f"\n{BLUE}Нажмите Enter...{NC}")


def _menu_show_rules() -> None:
    """Показывает текущие правила iptables с нашим комментарием."""
    os.system("clear")
    print()
    _box_top("🔍  Правила iptables (Port Hopping)")
    _box_bottom()
    print()
    r = _run(["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v", "--line-numbers"], capture=True)
    lines = r.stdout.splitlines()
    found = False
    for line in lines:
        if _COMMENT in line or line.startswith("Chain") or line.startswith("num"):
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
