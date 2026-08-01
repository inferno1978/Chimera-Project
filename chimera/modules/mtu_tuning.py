"""
chimera/modules/mtu_tuning.py
───────────────────────────────────────────────────────────────────────────────
MTU/MSS-тюнинг сети и диагностика Path MTU.

  • _mtu_probe()              — бинарный поиск максимального MTU (ICMP DF)
  • _mtu_get_iface()          — основной сетевой интерфейс
  • _mtu_apply()              — ip link set mtu + iptables MSS clamping
  • _mtu_remove_rules()       — удаление MSS-правил
  • _mtu_state_load/save()    — собственный state в /var/lib/xray-installer/mtu_tuning.json
  • do_mtu_tuning()           — меню автотюнинга MTU/MSS
  • _mtu_persist()            — netplan /etc/network/interfaces rc.local
  • do_mtu_tracepath_diag()   — диагностика MTU по маршруту (tracepath + ping sweep)
  • _mtu_tracepath_one()      — один хост диагностики

Никаких mutations глобалей _core. Чтение state.json напрямую. Запись в
собственный _MTU_STATE_FILE. Читает AWG_EXIT_HOST / _nodes_from_state /
_log_change из ядра через _core_module().

Точки входа из _core.py:
    from chimera.modules.mtu_tuning import (
        _MTU_STATE_FILE,
        _mtu_probe, _mtu_get_iface, _mtu_apply, _mtu_remove_rules,
        _mtu_state_load, _mtu_state_save,
        do_mtu_tuning, _mtu_persist,
        do_mtu_tracepath_diag, _mtu_tracepath_one,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Константы ─────────────────────────────────────────────────────────────────
_MTU_STATE_FILE = Path("/var/lib/xray-installer/mtu_tuning.json")


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль chimera._core (импорт лениво)."""
    import importlib
    return importlib.import_module("chimera._core")


# ============================================================================
#  PROBE / IFACE / APPLY / REMOVE
# ============================================================================
def _mtu_resolve_host(host: str) -> str:
    """Резолв hostname → IPv4 через DoH + fallback на системный резолвер.

    DoH идёт напрямую к Cloudflare/Google, минуя локальный DNS-кэш
    (/etc/hosts, systemd-resolved, nscd, dnsmasq) — это важно, чтобы
    MTU-пинг и iptables-правила сработали для АКТУАЛЬНОГО IP exit-ноды,
    а не для устаревшей кэш-записи (баг с blackshadows.ru).
    Возвращает IP-строку или '' при ошибке.
    """
    try:
        from chimera.modules.chain_nodes import _resolve_host_fresh
        ip = _resolve_host_fresh(host)
        if ip:
            return ip
    except Exception:
        pass
    try:
        return socket.gethostbyname(host)
    except Exception:
        return ""


def _mtu_probe(host: str, max_mtu: int = 1500, min_mtu: int = 576) -> int:
    """
    Бинарный поиск максимального MTU до хоста через ICMP ping с DF-битом.
    Возвращает найденный MTU или 0 при ошибке.
    """
    core = _core_module()
    _run = core._run
    ip = _mtu_resolve_host(host)
    if not ip:
        return 0

    lo, hi = min_mtu, max_mtu
    best = 0

    while lo <= hi:
        mid = (lo + hi) // 2
        # ping -M do  — не фрагментировать (DF bit)
        # -s (mid-28): payload = MTU - 20 (IP) - 8 (ICMP)
        payload = mid - 28
        if payload < 0:
            lo = mid + 1
            continue
        r = _run(
            ["ping", "-c", "1", "-W", "2", "-M", "do", "-s", str(payload), ip],
            capture=True, check=False,
        )
        if r.returncode == 0:
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1

    return best


def _mtu_get_iface() -> str:
    """Возвращает основной сетевой интерфейс (не lo)."""
    core = _core_module()
    _run = core._run
    r = _run(["ip", "route", "show", "default"], capture=True, check=False)
    for line in r.stdout.splitlines():
        parts = line.split()
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return "eth0"


def _mtu_apply(iface: str, mtu: int, nodes: list) -> None:
    """
    Применяет MTU на интерфейс и ограничение MSS в iptables
    для каждой exit-ноды (только для трафика каскада).
    """
    core = _core_module()
    _run = core._run

    # 1. Устанавливаем MTU на интерфейсе
    _run(["ip", "link", "set", iface, "mtu", str(mtu)], check=False, quiet=True)

    # 2. MSS clamping для каждой exit-ноды
    mss = mtu - 40  # TCP/IP заголовки: 20 IP + 20 TCP
    for nd in nodes:
        host = nd.get("host", "")
        port = str(nd.get("port", 443))
        if not host:
            continue
        ip = _mtu_resolve_host(host)
        if not ip:
            continue
        # Удалим старое правило если есть, потом добавим новое
        _run([
            "iptables", "-t", "mangle", "-D", "FORWARD",
            "-d", ip, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
            "-j", "TCPMSS", "--set-mss", str(mss),
        ], check=False, quiet=True)
        _run([
            "iptables", "-t", "mangle", "-A", "FORWARD",
            "-d", ip, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
            "-j", "TCPMSS", "--set-mss", str(mss),
        ], check=False, quiet=True)

    # 3. Общий FORWARD MSS clamping
    _run([
        "iptables", "-t", "mangle", "-C", "FORWARD",
        "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
        "-j", "TCPMSS", "--clamp-mss-to-pmtu",
    ], check=False, quiet=True)


def _mtu_remove_rules(nodes: list) -> None:
    """Удаляет MSS-правила iptables для всех нод."""
    core = _core_module()
    _run = core._run
    for nd in nodes:
        host = nd.get("host", "")
        if not host:
            continue
        ip = _mtu_resolve_host(host)
        if not ip:
            continue
        _run([
            "iptables", "-t", "mangle", "-D", "FORWARD",
            "-d", ip, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
            "-j", "TCPMSS", "--set-mss", "1400",
        ], check=False, quiet=True)


# ============================================================================
#  STATE
# ============================================================================
def _mtu_state_load() -> dict:
    try:
        if _MTU_STATE_FILE.exists():
            return json.loads(_MTU_STATE_FILE.read_text())
    except Exception:
        pass
    return {}


def _mtu_state_save(data: dict) -> None:
    try:
        _MTU_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _MTU_STATE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    except Exception:
        pass


# ============================================================================
#  МЕНЮ ТЮНИНГА
# ============================================================================
def do_mtu_tuning() -> None:
    """
    Интерактивный MTU/MSS автотюнинг.
    Зондирует MTU до каждой exit-ноды, выбирает оптимальное значение
    и применяет его через ip link + iptables MSS clamping.
    """
    core = _core_module()
    _run          = core._run
    _box_top      = core._box_top
    _box_row      = core._box_row
    _box_sep      = core._box_sep
    _box_bottom   = core._box_bottom
    _box_back     = core._box_back
    _box_warn     = core._box_warn
    _box_ok       = core._box_ok
    _box_info     = core._box_info
    _BOX_W        = core._BOX_W
    warn          = core.warn
    info          = core.info
    success       = core.success
    log_to_file   = core.log_to_file
    STATE_FILE    = core.STATE_FILE
    AWG_EXIT_HOST = getattr(core, "AWG_EXIT_HOST", "")
    _nodes_from_state = core._nodes_from_state
    BLUE = core.BLUE
    BOLD = core.BOLD
    CYAN = core.CYAN
    DIM = core.DIM
    GREEN = core.GREEN
    NC = core.NC
    RED = core.RED
    YELLOW = core.YELLOW
    CYAN, NC, DIM, GREEN, YELLOW, RED, BOLD, BLUE = (
        core.CYAN, core.NC, core.DIM, core.GREEN, core.YELLOW, core.RED,
        core.BOLD, core.BLUE
    )

    os.system("clear")
    print()
    _box_top("📡  MTU / MSS АВТОТЮНИНГ")
    _box_row(f"  {DIM}Определяет максимальный MTU до exit-нод через ICMP Path MTU Discovery{NC}")
    _box_row(f"  {DIM}Затем применяет оптимальное значение на интерфейс + MSS clamping{NC}")
    _box_sep()

    # Загружаем state
    if not STATE_FILE.exists():
        _box_warn("state.json не найден — сначала выполните установку")
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    try:
        state = json.loads(STATE_FILE.read_text())
    except Exception as e:
        _box_warn(f"Не удалось прочитать state.json: {e}")
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    install_mode = state.get("install_mode", "A")
    nodes = _nodes_from_state(state)
    _awg_on = state.get("awg_exit_enabled", False)

    # AWG-режим: зондируем до exit-VPS через awg0
    if install_mode == "B" and _awg_on:
        _awg_host = state.get("awg_exit_host", AWG_EXIT_HOST or "")
        probe_targets = []
        if _awg_host:
            probe_targets.append({"host": _awg_host, "label": f"AWG exit-VPS ({_awg_host})", "port": state.get("awg_exit_port", 51820)})
        probe_targets += [
            {"host": "1.1.1.1", "label": "Cloudflare DNS", "port": 443},
            {"host": "8.8.8.8", "label": "Google DNS",     "port": 443},
        ]
        _box_row(f"  {CYAN}Режим AWG: зондирование через туннель awg0{NC}")
        _box_row(f"  {DIM}Рекомендуемый MTU для AWG: 1280 (уже задан в конфиге){NC}")
    # Режим A — тестируем до общих внешних узлов
    elif install_mode == "A" or not nodes:
        probe_targets = [
            {"host": "1.1.1.1",   "label": "Cloudflare DNS",   "port": 443},
            {"host": "8.8.8.8",   "label": "Google DNS",       "port": 443},
            {"host": "208.67.222.222", "label": "OpenDNS",     "port": 443},
        ]
        _box_row(f"  {YELLOW}Режим A: зондирование до общих внешних узлов{NC}")
    else:
        probe_targets = [
            {"host": nd.get("host", ""), "label": f"Exit нода {i+1}", "port": nd.get("port", 443)}
            for i, nd in enumerate(nodes) if nd.get("host")
        ]
        _box_row(f"  {GREEN}Режим B: зондирование до {len(probe_targets)} exit-нод{NC}")

    iface = _mtu_get_iface()
    _box_row(f"  Интерфейс: {CYAN}{iface}{NC}")

    # Текущий MTU интерфейса
    try:
        r = _run(["cat", f"/sys/class/net/{iface}/mtu"], capture=True, check=False)
        current_mtu = int(r.stdout.strip()) if r.stdout.strip().isdigit() else 1500
    except Exception:
        current_mtu = 1500
    _box_row(f"  Текущий MTU: {CYAN}{current_mtu}{NC}")

    # Предыдущий тюнинг
    prev = _mtu_state_load()
    if prev:
        prev_ts  = prev.get("timestamp", "—")
        prev_mtu = prev.get("applied_mtu", "—")
        _box_row(f"  {DIM}Последний тюнинг: {prev_ts}  →  MTU {prev_mtu}{NC}")

    _box_sep()
    _box_row(f"  {CYAN}[1]{NC}  Запустить зондирование и применить")
    _box_row(f"  {CYAN}[2]{NC}  Только зондирование (без применения)")
    _box_row(f"  {CYAN}[3]{NC}  Сбросить — восстановить MTU 1500 и удалить MSS-правила")
    _box_row(f"  {CYAN}[4]{NC}  Показать текущие MSS-правила iptables")
    _box_row(f"  {CYAN}[5]{NC}  Диагностика MTU по маршруту  {DIM}(tracepath + ping sweep){NC}")

    _box_row()
    _box_back()
    _box_bottom()

    try:
        ch = input(f"{CYAN}Выбор:{NC} ").strip()
    except KeyboardInterrupt:
        return

    if ch == "5":
        do_mtu_tracepath_diag()
        return

    if ch in ("q", ""):
        return

    if ch == "3":
        # Сброс
        os.system("clear")
        print()
        _box_top("📡  MTU — СБРОС")
        _run(["ip", "link", "set", iface, "mtu", "1500"], check=False, quiet=True)
        _mtu_remove_rules(nodes)
        _MTU_STATE_FILE.unlink(missing_ok=True)
        _box_ok(f"MTU {iface} восстановлен → 1500, MSS-правила удалены")
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    if ch == "4":
        os.system("clear")
        print()
        _box_top("📡  MSS-ПРАВИЛА IPTABLES")
        r = _run(["iptables", "-t", "mangle", "-L", "FORWARD", "-n", "-v"],
                 capture=True, check=False)
        if r.stdout.strip():
            max_w = _BOX_W - 4
            for line in r.stdout.strip().splitlines():
                if "TCPMSS" in line or "target" in line.lower():
                    if len(line) > max_w:
                        line = line[:max_w - 1] + "…"
                    _box_row(f"  {DIM}{line}{NC}")
        else:
            _box_row(f"  {DIM}Правил не найдено{NC}")
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    # ── Зондирование ─────────────────────────────────────────────────────────
    os.system("clear")
    print()
    _box_top("📡  ЗОНДИРОВАНИЕ MTU")
    _box_row(f"  {DIM}Бинарный поиск максимального MTU с DF-битом (не фрагментировать){NC}")
    _box_row(f"  {DIM}Диапазон: 576–1500 байт  |  ~12 ping-пробов на хост{NC}")
    _box_sep()

    results = []
    for target in probe_targets:
        host  = target["host"]
        label = target["label"]
        _box_row(f"  Зондирую {CYAN}{label}{NC}  ({DIM}{host}{NC})...")

        mtu = _mtu_probe(host, max_mtu=1500, min_mtu=576)
        if mtu > 0:
            col = GREEN if mtu >= 1400 else YELLOW if mtu >= 1200 else RED
            _box_row(f"    {col}MTU = {mtu}{NC}  {DIM}(MSS = {mtu-40}){NC}")
            results.append(mtu)
        else:
            _box_row(f"    {RED}Недоступен / ICMP заблокирован{NC}")

    _box_sep()

    if not results:
        _box_warn("Ни один хост не ответил на ICMP DF-probe.")
        _box_row(f"  {DIM}Возможные причины: файрволл блокирует ICMP на стороне хоста{NC}")
        _box_row(f"  {DIM}Рекомендуется использовать стандартный MTU 1420 для VPN-туннелей{NC}")
        optimal = 1420
    else:
        # Берём минимальный из всех нод — гарантирует отсутствие фрагментации
        optimal = min(results)
        _box_row(f"  Результаты: {DIM}{results}{NC}")

    _box_row(f"  {BOLD}Оптимальный MTU: {GREEN}{optimal}{NC}  {DIM}(MSS = {optimal - 40}){NC}")

    if ch == "2":
        # Только показ, без применения
        _box_row()
        _box_row(f"  {DIM}Режим «только зондирование» — изменения не применены{NC}")
        _box_row(f"  {DIM}Для применения выберите пункт [1]{NC}")
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    # ── Применение ───────────────────────────────────────────────────────────
    _box_row()
    _box_row(f"  Применяю MTU {CYAN}{optimal}{NC} на интерфейс {CYAN}{iface}{NC}...")
    _mtu_apply(iface, optimal, nodes if nodes else [])

    # Делаем изменение постоянным через /etc/network/interfaces или netplan
    _mtu_persist(iface, optimal)

    # Сохраняем в state
    _mtu_state_save({
        "applied_mtu":   optimal,
        "interface":     iface,
        "mss":           optimal - 40,
        "probed_hosts":  [t["host"] for t in probe_targets],
        "probe_results": results,
        "timestamp":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })

    _box_ok(f"MTU {iface} = {optimal}  |  MSS clamping = {optimal - 40}")
    _box_row(f"  {DIM}Изменение сохранено в {_MTU_STATE_FILE}{NC}")
    _box_bottom()

    log_to_file("INFO", f"MTU tuning: iface={iface}, mtu={optimal}, mss={optimal-40}, hosts={[t['host'] for t in probe_targets]}")
    input(f"{BLUE}Нажмите Enter...{NC}")


# ============================================================================
#  PERSIST MTU (netplan / interfaces / rc.local)
# ============================================================================
def _mtu_persist(iface: str, mtu: int) -> None:
    """
    Сохраняет MTU постоянно:
    - netplan (Ubuntu 18+): /etc/netplan/*.yaml
    - /etc/network/interfaces (Debian/Ubuntu без netplan)
    - rc.local fallback
    """
    core = _core_module()
    _run = core._run

    # Пробуем netplan
    netplan_dir = Path("/etc/netplan")
    if netplan_dir.exists():
        yamls = list(netplan_dir.glob("*.yaml")) + list(netplan_dir.glob("*.yml"))
        for yf in yamls:
            try:
                txt = yf.read_text()
                if iface in txt and "mtu" not in txt:
                    # Добавляем mtu под блок интерфейса
                    new_txt = re.sub(
                        r'((?:ethernets|wifis|bonds|vlans):\s*\n\s+' + re.escape(iface) + r':.*?\n)',
                        lambda m: m.group(0) + f"      mtu: {mtu}\n",
                        txt, flags=re.DOTALL
                    )
                    if new_txt != txt:
                        yf.write_text(new_txt)
                        _run(["netplan", "apply"], check=False, quiet=True)
                        return
            except Exception:
                pass

    # /etc/network/interfaces
    interfaces_file = Path("/etc/network/interfaces")
    if interfaces_file.exists():
        try:
            txt = interfaces_file.read_text()
            if f"iface {iface}" in txt and "mtu" not in txt:
                # Заменяем строку "iface <iface> ..." целиком,
                # добавляя mtu на следующей строке с отступом.
                # Корректно для Debian 12/13: iface ens3 inet static → +mtu строка
                new_txt = re.sub(
                    r'(iface ' + re.escape(iface) + r'[^\n]*)',
                    lambda m: m.group(0) + f"\n    mtu {mtu}",
                    txt,
                )
                if new_txt != txt:
                    interfaces_file.write_text(new_txt)
                    return
        except Exception:
            pass

    # rc.local fallback
    rc = Path("/etc/rc.local")
    cmd_line = f"ip link set {iface} mtu {mtu}\n"
    try:
        existing = rc.read_text() if rc.exists() else "#!/bin/bash\nexit 0\n"
        if cmd_line.strip() not in existing:
            new_rc = existing.replace("exit 0", cmd_line + "exit 0")
            rc.write_text(new_rc)
            rc.chmod(0o755)
    except Exception:
        pass


# ============================================================================
#  ДИАГНОСТИКА MTU ПО МАРШРУТУ (tracepath + ping sweep)
# ============================================================================
def do_mtu_tracepath_diag() -> None:
    """
    Детальная MTU-диагностика маршрута до цели.
    Запускает tracepath для выявления хопов с уменьшенным MTU,
    затем уточняет бинарным ping-зондом вокруг проблемных хопов.
    Не меняет никаких настроек — только диагностика.
    """
    core = _core_module()
    _run          = core._run
    _box_top      = core._box_top
    _box_row      = core._box_row
    _box_sep      = core._box_sep
    _box_bottom   = core._box_bottom
    _box_back     = core._box_back
    _box_warn     = core._box_warn
    warn          = core.warn
    STATE_FILE    = core.STATE_FILE
    _nodes_from_state = core._nodes_from_state
    BLUE = core.BLUE
    BOLD = core.BOLD
    CYAN = core.CYAN
    DIM = core.DIM
    GREEN = core.GREEN
    NC = core.NC
    RED = core.RED
    YELLOW = core.YELLOW
    CYAN, NC, DIM, GREEN, YELLOW, RED, BOLD, BLUE = (
        core.CYAN, core.NC, core.DIM, core.GREEN, core.YELLOW, core.RED,
        core.BOLD, core.BLUE
    )

    os.system("clear")
    print()
    _box_top("📡  MTU TRACEPATH — ДИАГНОСТИКА МАРШРУТА")
    _box_row(f"  {DIM}Показывает MTU на каждом хопе до цели. Помогает найти узкое место.{NC}")
    _box_row(f"  {DIM}Не изменяет настройки — только анализ.{NC}")
    _box_sep()

    # Определяем цели из state.json или предлагаем ввод
    targets = []
    if STATE_FILE.exists():
        try:
            st = json.loads(STATE_FILE.read_text())
            nodes = _nodes_from_state(st)
            for nd in nodes:
                h = nd.get("host", "")
                if h:
                    targets.append({"host": h, "label": f"Exit нода ({h})"})
            # При AWG — добавляем exit-VPS как отдельную цель
            if st.get("awg_exit_enabled") and st.get("install_mode") == "B":
                _awg_h = st.get("awg_exit_host", "")
                if _awg_h and not any(t["host"] == _awg_h for t in targets):
                    targets.insert(0, {"host": _awg_h, "label": f"AWG exit-VPS ({_awg_h})"})
        except Exception:
            pass

    if not targets:
        # При AWG — добавляем exit-VPS как основную цель
        if STATE_FILE.exists():
            try:
                st = json.loads(STATE_FILE.read_text())
                if st.get("awg_exit_enabled") and st.get("install_mode") == "B":
                    _awg_h = st.get("awg_exit_host", "")
                    if _awg_h:
                        targets.append({"host": _awg_h, "label": f"AWG exit-VPS ({_awg_h})"})
            except Exception:
                pass
        targets += [
            {"host": "1.1.1.1",  "label": "Cloudflare (1.1.1.1)"},
            {"host": "8.8.8.8",  "label": "Google DNS (8.8.8.8)"},
        ]

    _box_row(f"  Цели для диагностики:")
    for i, t in enumerate(targets, 1):
        _box_row(f"    {CYAN}[{i}]{NC} {t['label']}")
    _box_row(f"    {CYAN}[M]{NC} Ввести хост вручную")
    _box_row(f"    {CYAN}[A]{NC} Все цели подряд")
    _box_row()
    _box_back()
    _box_bottom()

    try:
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return

    if ch in ("q", ""):
        return

    selected = []
    if ch == "a":
        selected = targets
    elif ch == "m":
        raw = input("  Хост или IP: ").strip()
        if raw:
            selected = [{"host": raw, "label": raw}]
        else:
            return
    elif ch.isdigit() and 1 <= int(ch) <= len(targets):
        selected = [targets[int(ch) - 1]]
    else:
        warn("Неверный выбор")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    for tgt in selected:
        _mtu_tracepath_one(tgt["host"], tgt["label"])

    input(f"{BLUE}Нажмите Enter...{NC}")


def _mtu_tracepath_one(host: str, label: str) -> None:
    """Диагностика MTU-маршрута до одного хоста."""
    core = _core_module()
    _run           = core._run
    _box_top       = core._box_top
    _box_row       = core._box_row
    _box_sep       = core._box_sep
    _box_bottom    = core._box_bottom
    _box_warn      = core._box_warn
    command_exists = core.command_exists
    _log_change    = core._log_change
    BOLD = core.BOLD
    CYAN = core.CYAN
    DIM = core.DIM
    GREEN = core.GREEN
    NC = core.NC
    RED = core.RED
    YELLOW = core.YELLOW
    CYAN, NC, DIM, GREEN, YELLOW, RED, BOLD = (
        core.CYAN, core.NC, core.DIM, core.GREEN, core.YELLOW, core.RED, core.BOLD
    )

    os.system("clear")
    print()
    _box_top(f"📡  MTU МАРШРУТ → {label}")
    _box_sep()

    # Шаг 1: tracepath (встроенный Path MTU Discovery, не нужен root)
    if command_exists("tracepath"):
        _box_row(f"  {CYAN}[1/3] tracepath -n {host}{NC}")
        _box_row(f"  {DIM}Запуск... (до 15 сек){NC}")
        r = _run(["tracepath", "-n", "-m", "20", host],
                 capture=True, check=False)
        hops = []
        min_pmtu = 1500
        if r.returncode == 0 or r.stdout.strip():
            for line in r.stdout.strip().splitlines():
                _box_row(f"  {DIM}{line[:80]}{NC}")
                # tracepath печатает "pmtu NNNN" при обнаружении меньшего MTU
                m = re.search(r'pmtu\s+(\d+)', line)
                if m:
                    pmtu_val = int(m.group(1))
                    if pmtu_val < min_pmtu:
                        min_pmtu = pmtu_val
                    hops.append(pmtu_val)
        else:
            _box_row(f"  {YELLOW}tracepath не дал результата (ICMP может быть заблокирован){NC}")
        _box_sep()
        if hops:
            _box_row(f"  {BOLD}Минимальный PMTU по маршруту: {GREEN}{min_pmtu}{NC}")
        else:
            _box_row(f"  {DIM}PMTU-ограничений на маршруте не обнаружено (или ICMP заблокирован){NC}")
    else:
        _box_warn("tracepath не установлен (apt install iputils-tracepath)")
        min_pmtu = 1500

    _box_sep()

    # Шаг 2: Бинарный ping-зонд (собственная реализация, как в do_mtu_tuning)
    _box_row(f"  {CYAN}[2/3] Бинарный ping-зонд (DF-bit){NC}")
    _box_row(f"  {DIM}Точный поиск максимального MTU...{NC}")
    probed_mtu = _mtu_probe(host, max_mtu=1500, min_mtu=576)
    if probed_mtu > 0:
        col = GREEN if probed_mtu >= 1400 else YELLOW if probed_mtu >= 1200 else RED
        _box_row(f"  Ping-зонд: максимальный MTU = {col}{probed_mtu}{NC}  "
                 f"{DIM}(MSS = {probed_mtu - 40}){NC}")
    else:
        _box_row(f"  {YELLOW}Ping-зонд не дал результата (ICMP DF заблокирован){NC}")
        probed_mtu = 0

    _box_sep()

    # Шаг 3: MTU-зонд по контрольным значениям (быстрый sweep)
    _box_row(f"  {CYAN}[3/3] Проверка стандартных MTU-значений{NC}")
    check_values = [1500, 1492, 1480, 1460, 1440, 1420, 1400, 1380, 1280, 1024, 576]
    results_sweep = []
    for mtu_val in check_values:
        payload = mtu_val - 28
        if payload < 1:
            continue
        ip = _mtu_resolve_host(host)
        if not ip:
            _box_warn(f"  Не удалось разрешить {host}")
            break
        r = _run(
            ["ping", "-c", "1", "-W", "1", "-M", "do", "-s", str(payload), ip],
            capture=True, check=False
        )
        ok = r.returncode == 0
        col = GREEN if ok else RED
        mark = "✓" if ok else "✗"
        results_sweep.append((mtu_val, ok))
        _box_row(f"  {col}{mark}{NC}  MTU {mtu_val:>5}  "
                 f"{DIM}(payload {payload}){NC}")

    # Итог
    _box_sep()
    max_ok = max((v for v, ok in results_sweep if ok), default=0)
    if max_ok:
        col = GREEN if max_ok >= 1400 else YELLOW if max_ok >= 1200 else RED
        _box_row(f"  {BOLD}Максимальный рабочий MTU: {col}{max_ok}{NC}")

        # Рекомендация
        recommend = max_ok
        if max_ok >= 1500:
            _box_row(f"  {GREEN}✓ Маршрут не ограничивает MTU — фрагментации нет{NC}")
        elif max_ok >= 1400:
            _box_row(f"  {YELLOW}⚠ Есть ограничение MTU. Рекомендуется применить MTU {recommend} в тюнере{NC}")
        else:
            _box_row(f"  {RED}✗ Значительное ограничение MTU! Рекомендуется MTU {recommend}{NC}")
            _box_row(f"  {DIM}Используйте пункт [1] в MTU-тюнере для применения{NC}")

        _log_change("mtu_diag", f"tracepath {host}: max_ok={max_ok}, probed={probed_mtu}")
    else:
        _box_row(f"  {YELLOW}Все ping DF-зонды заблокированы (ICMP фильтруется){NC}")
        _box_row(f"  {DIM}Для VPN-туннелей безопасно использовать MTU 1420{NC}")

    _box_bottom()
