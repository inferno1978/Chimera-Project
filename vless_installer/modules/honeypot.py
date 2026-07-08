"""
vless_installer/modules/honeypot.py
───────────────────────────────────────────────────────────────────────────────
Honeypot-порт — ловушка для сканеров портов и DPI-зондов.

Слушает TCP-порт через socat/netcat. Каждого подключившегося сразу банит
через UFW. Эффективная ловушка для сканеров портов и DPI-зондов.

Точка входа из _core.py:
    from vless_installer.modules.honeypot import do_manage_honeypot
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
import time
import textwrap

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
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
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BLUE', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED    = _C['RED']
GREEN  = _C['GREEN']
YELLOW = _C['YELLOW']
CYAN   = _C['CYAN']
BLUE   = _C['BLUE']
BOLD   = _C['BOLD']
DIM    = _C['DIM']
WHITE  = _C['WHITE']
NC     = _C['NC']

# ── Логирование ────────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/vless-install.log")

def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\033\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [{level}] {clean}\n")
    except Exception:
        pass

def _success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)
def _warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)

# ── Вспомогательные ───────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

# ── Путь к state.json (не импортируем из _core) ───────────────────────────────
_STATE_FILE = Path("/var/lib/xray-installer/state.json")


# _tg_notify_event — Telegram-уведомление; пробуем импортировать из _core,
# если недоступно (circular) — используем no-op заглушку
def _tg_notify_event(event: str, detail: str = "") -> None:
    try:
        import importlib
        _core = importlib.import_module("vless_installer._core")
        _core._tg_notify_event(event, detail)
    except Exception:
        pass  # TG не настроен или недоступен

from vless_installer.modules.box_renderer import (
    _box_top, _box_bottom, _box_sep, _box_row, _box_item, _box_back,
)


# =============================================================================
#  МОДУЛЬ: HONEYPOT-ПОРТ  (v4.11.3)
#  Слушает TCP-порт через socat/netcat, каждого подключившегося сразу банит
#  через UFW. Эффективная ловушка для сканеров портов и DPI-зондов.
# =============================================================================

_HONEYPOT_STATE_FILE = Path("/var/lib/xray-installer/honeypot.json")
_HONEYPOT_LOG        = Path("/var/log/xray-honeypot.log")
_HONEYPOT_SERVICE    = Path("/etc/systemd/system/xray-honeypot.service")
_HONEYPOT_SCRIPT     = Path("/usr/local/bin/xray-honeypot.py")


def _honeypot_state_load() -> dict:
    try:
        if _HONEYPOT_STATE_FILE.exists():
            return json.loads(_HONEYPOT_STATE_FILE.read_text())
    except Exception:
        pass
    return {"enabled": False, "port": 9999, "whitelist": ["127.0.0.1", "::1"], "banned": {}}


def _honeypot_state_save(data: dict) -> None:
    _HONEYPOT_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _HONEYPOT_STATE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    _HONEYPOT_STATE_FILE.chmod(0o600)


def _honeypot_write_script(port: int, whitelist: list) -> None:
    """
    Записывает автономный Python-скрипт honeypot, который:
    - Слушает TCP-порт (socket, без внешних зависимостей)
    - При каждом подключении логирует IP и банит через UFW
    - Уважает whitelist
    - Работает как systemd-сервис (бесконечный цикл)
    """
    wl_repr = repr(whitelist)
    # Формируем скрипт конкатенацией — без f-string, чтобы не конфликтовать
    # с фигурными скобками Python внутри тела скрипта (format-строки Xray-honeypot)
    script = (
        "#!/usr/bin/env python3\n"
        f"# xray-honeypot.py — автономный honeypot, порт {port}\n"
        "# Генерируется установщиком VLESS v4.11. Не редактируйте вручную.\n"
        "import socket, subprocess, json, time, os\n"
        "from pathlib import Path\n"
        "from datetime import datetime\n"
        "\n"
        f"PORT      = {port}\n"
        f"WHITELIST = set({wl_repr})\n"
        'LOG       = Path("/var/log/xray-honeypot.log")\n'
        'STATE     = Path("/var/lib/xray-installer/honeypot.json")\n'
        "LOG.parent.mkdir(parents=True, exist_ok=True)\n"
        "\n"
        "def log(msg):\n"
        '    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")\n'
        "    try:\n"
        '        with LOG.open("a") as f:\n'
        '            f.write(f"[{ts}] {msg}\\n")\n'
        "    except Exception:\n"
        "        pass\n"
        "\n"
        "def ban(ip):\n"
        "    try:\n"
        "        r = subprocess.run(\n"
        '            ["ufw", "deny", "from", ip, "to", "any", "comment", "honeypot"],\n'
        "            capture_output=True, timeout=10\n"
        "        )\n"
        "        ok = r.returncode == 0\n"
        "    except Exception:\n"
        "        ok = False\n"
        "    log(f\"BAN {ip} — ufw={'OK' if ok else 'FAIL'}\")\n"
        "    try:\n"
        "        if STATE.exists():\n"
        "            data = json.loads(STATE.read_text())\n"
        "        else:\n"
        "            data = {}\n"
        '        banned = data.setdefault("banned", {})\n'
        "        if ip not in banned:\n"
        '            banned[ip] = {"banned_at": datetime.now().isoformat(), "source": "honeypot"}\n'
        "        STATE.write_text(json.dumps(data, indent=2, ensure_ascii=False))\n"
        "    except Exception:\n"
        "        pass\n"
        "    return ok\n"
        "\n"
        "srv = socket.socket(socket.AF_INET6 if socket.has_ipv6 else socket.AF_INET, socket.SOCK_STREAM)\n"
        "srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "try:\n"
        "    srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)\n"
        "except Exception:\n"
        "    pass\n"
        'srv.bind(("", PORT))\n'
        "srv.listen(64)\n"
        "srv.settimeout(5)\n"
        'log(f"Honeypot слушает порт {PORT}")\n'
        "\n"
        "while True:\n"
        "    try:\n"
        "        conn, addr = srv.accept()\n"
        '        ip = addr[0].replace("::ffff:", "")  # убираем IPv4-mapped prefix\n'
        "        conn.close()\n"
        "        if ip in WHITELIST:\n"
        '            log(f"SKIP {ip} (whitelist)")\n'
        "            continue\n"
        '        log(f"CONNECT {ip}:{addr[1]}")\n'
        "        ban(ip)\n"
        "    except socket.timeout:\n"
        "        continue\n"
        "    except Exception as e:\n"
        '        log(f"ERROR {e}")\n'
        "        time.sleep(1)\n"
    )
    _HONEYPOT_SCRIPT.write_text(script)
    _HONEYPOT_SCRIPT.chmod(0o755)


def _honeypot_install_service(port: int, whitelist: list) -> bool:
    """Устанавливает и запускает systemd-сервис honeypot."""
    _honeypot_write_script(port, whitelist)

    svc = textwrap.dedent(f"""\
        [Unit]
        Description=VLESS Honeypot Port {port}
        After=network.target

        [Service]
        Type=simple
        ExecStart=/usr/bin/python3 {_HONEYPOT_SCRIPT}
        Restart=always
        RestartSec=5
        User=root
        StandardOutput=journal
        StandardError=journal

        [Install]
        WantedBy=multi-user.target
    """)
    _HONEYPOT_SERVICE.write_text(svc)

    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    _run(["systemctl", "enable", "--now", "xray-honeypot"], check=False, quiet=True)
    time.sleep(1)
    r = _run(["systemctl", "is-active", "xray-honeypot"], capture=True, check=False)
    return r.stdout.strip() == "active"


def _honeypot_remove_service() -> None:
    _run(["systemctl", "disable", "--now", "xray-honeypot"], check=False, quiet=True)
    _HONEYPOT_SERVICE.unlink(missing_ok=True)
    _HONEYPOT_SCRIPT.unlink(missing_ok=True)
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)


def do_manage_honeypot() -> None:
    """Интерактивное управление Honeypot-портом."""
    while True:
        os.system("clear")
        print()
        cfg     = _honeypot_state_load()
        port    = cfg.get("port", 9999)
        wl      = cfg.get("whitelist", ["127.0.0.1", "::1"])
        banned  = cfg.get("banned", {})

        # Проверяем реальный статус сервиса
        r = _run(["systemctl", "is-active", "xray-honeypot"], capture=True, check=False)
        active = r.stdout.strip() == "active"

        _box_top("🍯  HONEYPOT-ПОРТ")
        _box_row(f"  {DIM}Слушает TCP-порт и мгновенно банит любого подключившегося через UFW.{NC}")
        _box_row(f"  {DIM}Идеален для ловли сканеров портов и активных DPI-зондов.{NC}")
        _box_sep()
        _box_row(f"  Сервис:    {''+GREEN+'● активен'+NC if active else ''+DIM+'○ остановлен'+NC}")
        _box_row(f"  Порт:      {CYAN}{port}{NC}")
        _box_row(f"  Забанено:  {RED if banned else DIM}{len(banned)}{NC} IP")
        _box_sep()
        _box_item("1", f"{'Остановить' if active else 'Запустить'} Honeypot")
        _box_item("2", f"Изменить порт {DIM}(текущий: {port}){NC}")
        _box_item("3", f"Управление whitelist {DIM}({len(wl)} IP){NC}")
        _box_item("4", f"Список пойманных IP {DIM}({len(banned)} шт.){NC}")
        _box_item("5", f"Разбанить IP")
        _box_item("6", f"📋 Последние 30 строк лога")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch == "1":
            if active:
                _honeypot_remove_service()
                cfg["enabled"] = False
                _honeypot_state_save(cfg)
                _success("Honeypot остановлен")
            else:
                ok = _honeypot_install_service(port, wl)
                cfg["enabled"] = ok
                _honeypot_state_save(cfg)
                if ok:
                    _success(f"Honeypot запущен на порту {port}")
                    _tg_notify_event("install_complete",
                        f"🍯 Honeypot активирован на порту <b>{port}</b>")
                else:
                    _warn("Не удалось запустить сервис — проверьте journalctl -u xray-honeypot")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            print()
            raw = input(f"  Новый порт [{port}]: ").strip()
            if raw.isdigit() and 1 <= int(raw) <= 65535:
                new_port = int(raw)
                # Предупреждение о конфликте с Xray
                if _STATE_FILE.exists():
                    try:
                        st = json.loads(_STATE_FILE.read_text())
                        xray_port = st.get("server_port", 443)
                        if new_port == xray_port:
                            _warn(f"Порт {new_port} занят Xray! Выберите другой.")
                            input(f"{BLUE}Нажмите Enter...{NC}")
                            continue
                    except Exception:
                        pass
                cfg["port"] = new_port
                _honeypot_state_save(cfg)
                if active:
                    # Перезапускаем с новым портом
                    _honeypot_remove_service()
                    _honeypot_install_service(new_port, wl)
                    cfg["enabled"] = True
                    _honeypot_state_save(cfg)
                _success(f"Порт изменён → {new_port}")
            else:
                _warn("Некорректный порт")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            print()
            _box_top("Whitelist Honeypot")
            for i, ip in enumerate(wl, 1):
                _box_item(str(i), ip)
            _box_sep()
            _box_item("+", "Добавить")
            _box_item("-", "Удалить")
            _box_bottom()
            act = input("  Действие [+/-/Enter]: ").strip()
            if act == "+":
                new_ip = input("  IP: ").strip()
                if new_ip and new_ip not in wl:
                    wl.append(new_ip)
                    cfg["whitelist"] = wl
                    _honeypot_state_save(cfg)
                    if active:
                        _honeypot_write_script(port, wl)
                        _run(["systemctl", "restart", "xray-honeypot"], check=False, quiet=True)
                    _success(f"Добавлен: {new_ip}")
            elif act == "-":
                raw_n = input("  Номер для удаления: ").strip()
                if raw_n.isdigit() and 1 <= int(raw_n) <= len(wl):
                    removed = wl.pop(int(raw_n) - 1)
                    cfg["whitelist"] = wl
                    _honeypot_state_save(cfg)
                    if active:
                        _honeypot_write_script(port, wl)
                        _run(["systemctl", "restart", "xray-honeypot"], check=False, quiet=True)
                    _success(f"Удалён: {removed}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "4":
            print()
            _box_top(f"Пойманные IP ({len(banned)})")
            if not banned:
                _box_row(f"  {DIM}Список пуст{NC}")
            else:
                _box_row(f"  {BOLD}{'IP':<22} {'Забанен':<20} Источник{NC}")
                _box_sep()
                for ip, meta in list(banned.items())[-30:]:
                    ts  = meta.get("banned_at", "?")[:16].replace("T", " ")
                    src = meta.get("source", "honeypot")
                    _box_row(f"  {RED}{ip:<22}{NC} {DIM}{ts:<20}{NC} {src}")
                if len(banned) > 30:
                    _box_row(f"  {DIM}... и ещё {len(banned)-30}{NC}")
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            if not banned:
                _warn("Список пуст")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            print()
            ban_list = list(banned.keys())
            _box_top("Выберите IP для разбана")
            for i, ip in enumerate(ban_list[-20:], 1):
                _box_item(str(i), ip)
            _box_bottom()
            raw = input("  Номер или IP: ").strip()
            target = ""
            if raw.isdigit() and 1 <= int(raw) <= min(len(ban_list), 20):
                target = ban_list[-(20 - int(raw) + 1)] if len(ban_list) > 20 else ban_list[int(raw) - 1]
            elif raw in banned:
                target = raw
            if target:
                _run(["ufw", "delete", "deny", "from", target, "to", "any"],
                     check=False, quiet=True)
                del banned[target]
                cfg["banned"] = banned
                _honeypot_state_save(cfg)
                _success(f"Разбанен: {target}")
            else:
                _warn("IP не найден")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "6":
            print()
            if _HONEYPOT_LOG.exists():
                lines = _HONEYPOT_LOG.read_text(errors="replace").splitlines()[-30:]
                _box_top("📋 Лог Honeypot (последние 30 строк)")
                for line in lines:
                    col = RED if "BAN" in line else YELLOW if "CONNECT" in line else DIM
                    _box_row(f"  {col}{line[:100]}{NC}")
                _box_bottom()
            else:
                _warn("Лог пуст или не создан")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", ""):
            break
        else:
            _warn("Неверный выбор")
            time.sleep(1)


# =============================================================================
#  МОДУЛЬ: MTU TRACEPATH-ДИАГНОСТИКА  (v3.99)
#  Расширяет do_mtu_tuning() опцией детальной диагностики маршрута:
#  tracepath по каждому хопу + ping с разными MTU, показ узкого места.
# =============================================================================


