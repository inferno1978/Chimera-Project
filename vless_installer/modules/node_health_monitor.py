"""
node_health_monitor.py — периодический health check exit-нод с уведомлением в Telegram.

Проверяет TCP-доступность каждой exit-ноды каждые N минут.
При падении ноды — отправляет уведомление в Telegram (если настроен).
При восстановлении — отправляет уведомление о восстановлении.
Состояние нод хранится в /var/lib/xray-installer/node-health-state.json,
чтобы не спамить повторными уведомлениями.

Публичный API:
    check_nodes_once()              → list[dict]   — разовая проверка всех нод
    install_health_monitor(interval)→ (bool, str)  — установить cron
    uninstall_health_monitor()      → (bool, str)  — удалить cron
    is_monitor_installed()          → bool
    do_health_monitor_menu()        → None         — интерактивное меню
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from pathlib import Path

# ── Константы ─────────────────────────────────────────────────────────────────
STATE_FILE       = Path("/var/lib/xray-installer/state.json")
HEALTH_STATE     = Path("/var/lib/xray-installer/node-health-state.json")
HEALTH_LOG       = Path("/var/log/xray-node-health.log")
CRON_FILE        = Path("/etc/cron.d/xray-node-health")
CHECK_SCRIPT     = Path("/usr/local/bin/xray-node-health-check.sh")
DEFAULT_INTERVAL = 5   # минут
TCP_TIMEOUT      = 5   # секунд

# ── Цвета ─────────────────────────────────────────────────────────────────────
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
NC     = "\033[0m"


# ── Вспомогательные ───────────────────────────────────────────────────────────

def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _load_nodes() -> list[dict]:
    """Читает список exit-нод из state.json."""
    try:
        if not STATE_FILE.exists():
            return []
        state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        nodes = state.get("chain_nodes", [])
        if not nodes:
            # legacy формат
            host = state.get("CHAIN_EXIT_HOST", "")
            port = state.get("CHAIN_EXIT_PORT", 443)
            if host:
                nodes = [{"host": host, "port": port, "sni": host}]
        return nodes
    except Exception:
        return []


def _load_health_state() -> dict:
    """Загружает сохранённое состояние нод (up/down, время последнего изменения)."""
    try:
        if HEALTH_STATE.exists():
            return json.loads(HEALTH_STATE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _save_health_state(state: dict) -> None:
    HEALTH_STATE.parent.mkdir(parents=True, exist_ok=True)
    HEALTH_STATE.write_text(json.dumps(state, indent=2, ensure_ascii=False),
                            encoding="utf-8")


def _log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} {msg}\n"
    try:
        HEALTH_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(HEALTH_LOG, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


def _tcp_ping(host: str, port: int, timeout: int = TCP_TIMEOUT) -> tuple[bool, float]:
    """
    TCP-пинг к хосту. Возвращает (доступен, время_мс).
    """
    try:
        ip = socket.gethostbyname(host)
        start = time.time()
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        ms = (time.time() - start) * 1000
        return True, ms
    except Exception:
        return False, 0.0


def _tg_send(msg: str) -> bool:
    """Отправляет сообщение в Telegram через сохранённый конфиг."""
    TG_CONFIG = Path("/var/lib/xray-installer/telegram.json")
    try:
        if not TG_CONFIG.exists():
            return False
        cfg = json.loads(TG_CONFIG.read_text(encoding="utf-8"))
        token   = cfg.get("token", "")
        chat_id = cfg.get("chat_id", "")
        if not token or not chat_id:
            return False

        # Проверяем включено ли событие node_down
        events = cfg.get("events", {})
        if not events.get("node_down", True):
            return False

        r = _run([
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "-m", "10",
            f"https://api.telegram.org/bot{token}/sendMessage",
            "-d", f"chat_id={chat_id}",
            "-d", f"text={msg}",
            "-d", "parse_mode=HTML",
        ])
        return r.stdout.strip() == "200"
    except Exception:
        return False


def _hostname() -> str:
    try:
        return _run(["hostname", "-s"], check=False).stdout.strip()
    except Exception:
        return "server"


# ── Публичный API ─────────────────────────────────────────────────────────────

def check_nodes_once() -> list[dict]:
    """
    Разовая проверка всех exit-нод.
    Отправляет Telegram-уведомления при изменении статуса.
    Возвращает список результатов:
      [{'host': str, 'port': int, 'up': bool, 'ms': float, 'changed': bool}, ...]
    """
    nodes = _load_nodes()
    if not nodes:
        return []

    prev_state = _load_health_state()
    new_state  = {}
    results    = []
    host_name  = _hostname()
    ts         = time.strftime("%d.%m.%Y %H:%M")

    for nd in nodes:
        host = nd.get("host", "")
        port = int(nd.get("port", 443))
        sni  = nd.get("sni", host)
        if not host:
            continue

        up, ms = _tcp_ping(host, port)
        key    = f"{host}:{port}"

        prev_up      = prev_state.get(key, {}).get("up", None)
        changed      = (prev_up is not None) and (prev_up != up)
        first_seen   = (prev_up is None)

        new_state[key] = {
            "up":          up,
            "last_check":  time.time(),
            "last_change": time.time() if (changed or first_seen) else prev_state.get(key, {}).get("last_change", time.time()),
            "ms":          round(ms, 1),
            "host":        host,
            "port":        port,
        }

        results.append({
            "host": host, "port": port, "sni": sni,
            "up": up, "ms": ms, "changed": changed,
        })

        status_str = f"up ({ms:.0f}ms)" if up else "DOWN"
        _log(f"[{key}] {status_str}" + (" [CHANGED]" if changed else ""))

        # Telegram уведомление только при изменении статуса (не при первой проверке)
        if changed and not first_seen:
            if not up:
                msg = (f"📡 <b>[{host_name}]</b> Exit-нода недоступна\n"
                       f"🔴 <code>{host}:{port}</code>\n"
                       f"<i>{ts}</i>")
                _tg_send(msg)
                _log(f"TG: уведомление об отказе ноды {key}")
            else:
                msg = (f"📡 <b>[{host_name}]</b> Exit-нода восстановлена\n"
                       f"🟢 <code>{host}:{port}</code> — {ms:.0f} мс\n"
                       f"<i>{ts}</i>")
                _tg_send(msg)
                _log(f"TG: уведомление о восстановлении ноды {key}")

    _save_health_state(new_state)
    return results


def is_monitor_installed() -> bool:
    return CRON_FILE.exists() and CHECK_SCRIPT.exists()


def _get_installed_interval() -> int:
    """Читает интервал из cron-файла."""
    try:
        if CRON_FILE.exists():
            content = CRON_FILE.read_text()
            for line in content.splitlines():
                if line.startswith("*/"):
                    return int(line.split()[0].replace("*/", ""))
    except Exception:
        pass
    return DEFAULT_INTERVAL


def _find_python() -> str:
    """Находит python3."""
    for p in ["/usr/bin/python3", "/usr/local/bin/python3", "python3"]:
        if Path(p).exists():
            return p
    return "python3"


def install_health_monitor(interval: int = DEFAULT_INTERVAL) -> tuple[bool, str]:
    """
    Устанавливает cron-задачу для периодической проверки нод.
    interval — интервал в минутах (1-60).
    """
    try:
        # Находим путь установки
        import importlib.util
        spec = importlib.util.find_spec("vless_installer")
        if spec and spec.submodule_search_locations:
            installer_path = str(Path(list(spec.submodule_search_locations)[0]).parent)
        else:
            installer_path = "/root/VLESS-Ultimate-Installer"

        python = _find_python()

        # Пишем скрипт проверки
        script_content = f"""#!/bin/bash
# xray-node-health-check.sh — периодическая проверка exit-нод
export PYTHONPATH="{installer_path}:$PYTHONPATH"
{python} -c "
import sys
sys.path.insert(0, '{installer_path}')
from vless_installer.modules.node_health_monitor import check_nodes_once
check_nodes_once()
" 2>>/var/log/xray-node-health.log
"""
        CHECK_SCRIPT.write_text(script_content, encoding="utf-8")
        CHECK_SCRIPT.chmod(0o755)

        # Пишем cron
        cron_content = f"""# xray-node-health — проверка exit-нод каждые {interval} мин
*/{interval} * * * * root {CHECK_SCRIPT} >/dev/null 2>&1
"""
        CRON_FILE.write_text(cron_content, encoding="utf-8")
        CRON_FILE.chmod(0o644)

        return True, f"Health monitor установлен (интервал: {interval} мин)"
    except Exception as e:
        return False, f"Ошибка установки: {e}"


def uninstall_health_monitor() -> tuple[bool, str]:
    """Удаляет cron-задачу и скрипт проверки."""
    try:
        CRON_FILE.unlink(missing_ok=True)
        CHECK_SCRIPT.unlink(missing_ok=True)
        return True, "Health monitor удалён"
    except Exception as e:
        return False, f"Ошибка удаления: {e}"


# ── Интерактивное меню ────────────────────────────────────────────────────────

def do_health_monitor_menu() -> None:
    """Интерактивное меню управления health monitor."""
    from vless_installer._core import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_item, _box_back,
        _box_ok, _box_warn,
    )

    while True:
        os.system("clear")
        installed = is_monitor_installed()
        interval  = _get_installed_interval() if installed else DEFAULT_INTERVAL
        nodes     = _load_nodes()
        health    = _load_health_state()
        status    = f"{GREEN}активен{NC}" if installed else f"{YELLOW}не активен{NC}"

        _box_top("📡  HEALTH MONITOR EXIT-НОД")
        _box_row("  Периодическая проверка доступности exit-нод.")
        _box_row("  При падении/восстановлении ноды — уведомление в Telegram.")
        _box_sep()
        _box_row(f"  Статус:    {status}")
        if installed:
            _box_row(f"  Интервал:  {BOLD}{interval} мин{NC}")
        _box_sep()

        if nodes:
            _box_row(f"  {'Нода':<32} {'Статус':<12} {'RTT':>8}  {'Последняя проверка'}")
            _box_sep()
            for nd in nodes:
                host = nd.get("host", "")
                port = int(nd.get("port", 443))
                key  = f"{host}:{port}"
                h    = health.get(key, {})
                if h:
                    up      = h.get("up", None)
                    ms      = h.get("ms", 0)
                    lc      = h.get("last_check", 0)
                    lc_str  = time.strftime("%d.%m %H:%M", time.localtime(lc)) if lc else "—"
                    st_str  = f"{GREEN}UP{NC}" if up else f"{RED}DOWN{NC}"
                    ms_str  = f"{ms:.0f} мс" if up else "—"
                else:
                    st_str  = f"{DIM}нет данных{NC}"
                    ms_str  = "—"
                    lc_str  = "—"
                _box_row(f"  {host:<32} {st_str:<12} {ms_str:>8}  {lc_str}")
        else:
            _box_row(f"  {DIM}Exit-ноды не настроены (только Режим B){NC}")

        _box_sep()
        _box_item("C", "Проверить сейчас")
        if not installed:
            _box_item("I", f"Установить (интервал {DEFAULT_INTERVAL} мин)")
            _box_item("I5",  "Установить — каждые 5 мин")
            _box_item("I10", "Установить — каждые 10 мин")
            _box_item("I30", "Установить — каждые 30 мин")
        else:
            _box_item("U", "Удалить")
        _box_back()
        _box_bottom()

        ch = input(f"{CYAN}Выбор: {NC}").strip().upper()

        if ch in ("0", "Q", ""):
            break

        elif ch == "C":
            _box_row(f"  {DIM}Проверяю ноды...{NC}")
            results = check_nodes_once()
            if not results:
                _box_warn("Нет exit-нод для проверки")
            else:
                for r in results:
                    icon = f"{GREEN}✓{NC}" if r["up"] else f"{RED}✗{NC}"
                    ms_s = f"{r['ms']:.0f} мс" if r["up"] else "недоступна"
                    _box_row(f"  {icon} {r['host']}:{r['port']} — {ms_s}")
            input(f"{CYAN}Нажмите Enter...{NC}")

        elif ch in ("I", "I5"):
            ok, msg = install_health_monitor(5)
            _box_ok(msg) if ok else _box_warn(msg)
            input(f"{CYAN}Нажмите Enter...{NC}")

        elif ch == "I10":
            ok, msg = install_health_monitor(10)
            _box_ok(msg) if ok else _box_warn(msg)
            input(f"{CYAN}Нажмите Enter...{NC}")

        elif ch == "I30":
            ok, msg = install_health_monitor(30)
            _box_ok(msg) if ok else _box_warn(msg)
            input(f"{CYAN}Нажмите Enter...{NC}")

        elif ch == "U" and installed:
            ok, msg = uninstall_health_monitor()
            _box_ok(msg) if ok else _box_warn(msg)
            input(f"{CYAN}Нажмите Enter...{NC}")
