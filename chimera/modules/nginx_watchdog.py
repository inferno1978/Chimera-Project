"""
chimera/modules/nginx_watchdog.py
───────────────────────────────────────────────────────────────────────────────
Watchdog для nginx — аналог xray-watchdog.timer, который уже есть в проекте.

Зачем: Xray живёт, но nginx упал (OOM / истёк сертификат / обновление systemd)
→ клиенты получают EOF на Reality unix-socket.

Systemd timer каждые 2 минуты:
  • Проверяет systemctl is-active nginx
  • Fallback: curl 127.0.0.1 (на случай рассинхрона systemd)
  • [NEW] Проверяет доступность VLESS-порта локально (127.0.0.1:port).
    Детектит firewall/knocking блоки: nginx активен, но порт закрыт
    iptables/UFW/knocking — клиенты не могут подключиться.
  • [NEW] Проверяет xray unix-сокет (Reality-режим, если state.json
    содержит поле "socket")
  • Перезапускает nginx при падении
  • В Reality-режиме: systemctl reload xray (пересоздание unix-socket)
  • Telegram-уведомление если настроен tg_bot_token в state.json

Точки входа из _core.py:
    from chimera.modules.nginx_watchdog import (
        nginx_watchdog_install, nginx_watchdog_remove, do_manage_nginx_watchdog,
        _nginx_watchdog_run,
    )

CLI (cron/systemd-timer):
    python3 main.py --nginx-watchdog-run
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import textwrap
import time
from datetime import datetime
from pathlib import Path

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m', NC='\033[0m')
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'], _C['BOLD'], _C['DIM'], _C['NC'],
)

# ── Пути ──────────────────────────────────────────────────────────────────────
_SCRIPT   = Path('/usr/local/bin/nginx-watchdog.sh')
_SERVICE  = Path('/etc/systemd/system/nginx-watchdog.service')
_TIMER    = Path('/etc/systemd/system/nginx-watchdog.timer')
_LOG      = Path('/var/log/nginx-watchdog.log')
_LOGROTATE = Path('/etc/logrotate.d/nginx-watchdog')
_STATE    = Path('/var/lib/xray-installer/state.json')


# ── Внутренние хелперы ────────────────────────────────────────────────────────
def _ok(msg: str)   -> None: print(f'  {GREEN}✓{NC} {msg}')
def _warn(msg: str) -> None: print(f'  {YELLOW}⚠{NC}  {msg}')
def _info(msg: str) -> None: print(f'  {CYAN}•{NC} {msg}')

def _run(cmd: list) -> int:
    return subprocess.run(cmd, capture_output=True).returncode

def _protocol_mode() -> str:
    try:
        return json.loads(_STATE.read_text()).get('protocol_mode', 'reality')
    except Exception:
        return 'reality'

def _is_active(unit: str) -> bool:
    r = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True)
    return r.stdout.strip() == 'active'

def _is_enabled(unit: str) -> bool:
    r = subprocess.run(['systemctl', 'is-enabled', unit], capture_output=True, text=True)
    return 'enabled' in r.stdout


# ── Логирование ───────────────────────────────────────────────────────────────
def _log(level: str, msg: str) -> None:
    """Логирует в _LOG файл и печатает в stdout.

    Уровни: INFO, WARN, ERROR, OK. Формат: [ts] [LEVEL] msg.
    Используется watchdog-проверкой (_nginx_watchdog_run) для записи
    событий в лог и одновременного вывода в консоль при ручном запуске.
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level}] {msg}"
    try:
        with _LOG.open("a") as f:
            f.write(line + "\n")
    except Exception:
        pass
    prefixes = {
        "INFO":  f"  {CYAN}[INFO]{NC}",
        "WARN":  f"  {YELLOW}[WARN]{NC}",
        "ERROR": f"  {RED}[ERROR]{NC}",
        "OK":    f"  {GREEN}[OK]{NC}",
    }
    print(f"{prefixes.get(level, '  [*]')} {msg}")


# ── Port-availability check (NEW) ─────────────────────────────────────────────
def _check_port_accessible(port, timeout=2):
    """Check if port is accessible from localhost (127.0.0.1).

    Returns True if connection succeeds, False if refused/timeout.
    This detects firewall blocks (knocking, UFW, iptables) that make
    the port inaccessible even though the service is running.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(("127.0.0.1", port))
        s.close()
        return True
    except Exception:
        return False


def _check_xray_socket(socket_path, timeout=2):
    """Проверяет доступность unix-сокета xray (Reality-режим).

    Returns True if connection succeeds, False if refused/timeout/error.
    Используется в Reality-режиме, где xray слушает unix-socket вместо
    TCP-порта. Проверка через socket.AF_UNIX.
    """
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(socket_path)
        s.close()
        return True
    except Exception:
        return False


def _get_state_value(key, default=None):
    """Читает значение из state.json по ключу.

    Возвращает default если файл отсутствует/повреждён/ключа нет.
    """
    try:
        data = json.loads(_STATE.read_text())
        return data.get(key, default)
    except Exception:
        return default


def _get_vless_port() -> int:
    """Возвращает порт VLESS из state.json (default 443)."""
    port = _get_state_value("server_port", 443)
    try:
        return int(port)
    except (TypeError, ValueError):
        return 443


def _get_xray_socket() -> str:
    """Возвращает путь к xray unix-сокету из state.json (пустая строка если нет)."""
    return _get_state_value("socket", "") or ""


def _hostname() -> str:
    """Возвращает короткое имя хоста для TG-уведомлений."""
    try:
        r = subprocess.run(["hostname", "-s"], capture_output=True, text=True)
        return r.stdout.strip() or "localhost"
    except Exception:
        return "localhost"


def _curl_localhost_http() -> str:
    """Возвращает HTTP-код ответа от 127.0.0.1, или пустую строку при ошибке."""
    try:
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", "3", "http://127.0.0.1/"],
            capture_output=True, text=True,
        )
        return r.stdout.strip()
    except Exception:
        return ""


def _tg_event(event: str, detail: str) -> None:
    """Безопасная обёртка над _tg_notify_event (не падает при отсутствии TG).

    Делегирует в chimera.modules.tg_bot._tg_notify_event (уважает фильтр
    событий из telegram.json). Все исключения подавляются — watchdog не должен
    падать из-за проблем с TG.
    """
    try:
        from chimera.modules.tg_bot import _tg_notify_event
        _tg_notify_event(event, detail)
    except Exception as e:
        _log("WARN", f"TG notify failed: {event} — {e}")


# ── Главная функция проверки watchdog (NEW, Python-level) ─────────────────────
def _nginx_watchdog_run() -> None:
    """Одна итерация watchdog с port-availability check.

    Вызывается:
      • Из меню (пункт 2 — ручная проверка)
      • Из cron/systemd-timer через `python3 main.py --nginx-watchdog-run`

    Логика:
      1. systemctl is-active nginx → если active, переходим к port-check
      2. [NEW] port-check: если порт недоступен локально → TG-уведомление
         port_blocked + restart nginx + recheck. Детектит firewall/knocking
         блоки, которые делают порт недоступным даже при active nginx.
      3. [NEW] xray unix-socket check (Reality-режим, если state.json
         содержит поле "socket")
      4. curl 127.0.0.1 fallback (рассинхрон systemd) → если HTTP 2xx-4xx, exit
      5. nginx упал → restart + TG-уведомление
    """
    mode = _protocol_mode()
    port = _get_vless_port()

    # ── Проверка 1: systemctl is-active nginx ─────────────────────────────
    if _is_active("nginx"):
        # ── Проверка 1b (NEW): доступность порта VLESS локально ───────────
        # nginx активен, но порт может быть заблокирован iptables/UFW/knocking.
        # Это детектит случаи, когда клиенты не могут подключиться, хотя
        # systemctl показывает "active".
        if not _check_port_accessible(port):
            _log("WARN", f"Port {port} is not accessible locally — "
                         f"possible firewall/knocking issue")
            # TG-уведомление через _tg_notify_event (уважает фильтр событий)
            _tg_event("port_blocked",
                f"Port {port} недоступен — возможно knocking/firewall "
                f"блокирует. nginx активен но порт закрыт.")
            # Пытаемся restart nginx на случай если он сам перестал слушать
            # (хотя systemctl показывает active). Если проблема в iptables,
            # restart не поможет, но мы хотя бы попробуем.
            _run(["systemctl", "restart", "nginx"])
            time.sleep(3)
            # Повторная проверка порта
            if _check_port_accessible(port):
                _log("OK", f"Port {port} доступен после restart nginx")
            else:
                _log("ERROR", f"Port {port} всё ещё недоступен после restart "
                              f"— проверьте iptables/ufw/knocking")
            return

        # ── Проверка 1c (NEW): xray unix-socket (Reality-режим) ───────────
        sock_path = _get_xray_socket()
        if sock_path and not _check_xray_socket(sock_path):
            _log("WARN", f"Xray unix-socket {sock_path} недоступен — "
                         f"возможно нужно reload xray")
            if _run(["systemctl", "reload", "xray"]) != 0:
                _run(["systemctl", "restart", "xray"])

        # Всё хорошо — выходим без записей в лог (как в исходном bash-скрипте)
        return

    # ── systemctl: nginx НЕ активен — fallback через curl ─────────────────
    http = _curl_localhost_http()
    if http and http.startswith(("2", "3", "4")):
        # nginx на самом деле жив — рассинхрон systemd. Выходим.
        return

    # ── nginx упал — restart + TG-уведомление ─────────────────────────────
    _log("WARN", f"nginx упал (status=down http={http}) — перезапуск")
    _run(["systemctl", "restart", "nginx"])
    time.sleep(3)

    if _is_active("nginx"):
        _log("OK", "nginx перезапущен")
        _tg_event("xray_up",
                  f"🔄 nginx-watchdog: nginx перезапущен на {_hostname()}")
        if mode == "reality":
            # Reality: nginx перезапустился — пересоздаём unix-socket xray
            if _run(["systemctl", "reload", "xray"]) != 0:
                _run(["systemctl", "restart", "xray"])
    else:
        _log("ERROR", "nginx не поднялся")
        _tg_event("xray_down",
                  f"🚨 nginx-watchdog: nginx НЕ запустился на {_hostname()}")
        # Логируем последние строки journalctl для диагностики
        try:
            r = subprocess.run(
                ["journalctl", "-u", "nginx", "-n", "20", "--no-pager"],
                capture_output=True, text=True, timeout=10,
            )
            if r.stdout:
                _log("INFO", f"nginx journal (tail):\n{r.stdout}")
        except Exception:
            pass


# ── Генерация скрипта ─────────────────────────────────────────────────────────
def _installer_path() -> str:
    """Возвращает путь установки chimera (для запуска main.py из bash).

    Канонический путь: /opt/chimera (см. bootstrap.sh, INSTALL.md).
    Fallback: динамическое определение через importlib.
    """
    try:
        import importlib.util
        spec = importlib.util.find_spec("chimera")
        if spec and spec.submodule_search_locations:
            return str(Path(list(spec.submodule_search_locations)[0]).parent)
    except Exception:
        pass
    return "/opt/chimera"


def _build_watchdog_script() -> str:
    mode = _protocol_mode()
    installer_path = _installer_path()
    main_py = f"{installer_path}/main.py"
    xray_reload = ''
    if mode == 'reality':
        xray_reload = textwrap.dedent("""\
            # Reality: nginx перезапустился — пересоздаём unix-socket xray
            systemctl reload xray 2>/dev/null || systemctl restart xray 2>/dev/null
        """)

    return textwrap.dedent(f"""\
        #!/bin/bash
        # nginx-watchdog.sh — Chimera Project
        # Автоматически создан. Управляется через меню установщика.
        LOG="{_LOG}"
        DATE=$(date '+%Y-%m-%d %H:%M:%S')

        _notify_tg() {{
            local MSG="$1"
            local STATE="{_STATE}"
            [[ ! -f "$STATE" ]] && return
            BOT=$(python3 -c "import json; d=json.load(open('$STATE')); print(d.get('tg_bot_token',''))" 2>/dev/null)
            CID=$(python3 -c "import json; d=json.load(open('$STATE')); print(d.get('tg_chat_id',''))"   2>/dev/null)
            [[ -z "$BOT" || -z "$CID" ]] && return
            curl -s -X POST "https://api.telegram.org/bot${{BOT}}/sendMessage" \\
                --data-urlencode "chat_id=${{CID}}" \\
                --data-urlencode "text=${{MSG}}" \\
                --data-urlencode "parse_mode=HTML" >/dev/null 2>&1
        }}

        # Проверка 1: systemd
        STATUS=$(systemctl is-active nginx 2>/dev/null)
        if [[ "$STATUS" == "active" ]]; then
            # Проверка 1b (NEW): доступность порта VLESS локально.
            # nginx активен, но порт может быть заблокирован iptables/UFW/knocking.
            # Это детектит случаи, когда клиенты не могут подключиться, хотя
            # systemctl показывает "active".
            PORT=$(python3 -c "import json; d=json.load(open('{_STATE}')); print(d.get('server_port', 443))" 2>/dev/null)
            [[ -z "$PORT" ]] && PORT=443
            if ! python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2); exit(0 if s.connect_ex(('127.0.0.1', $PORT))==0 else 1)" 2>/dev/null; then
                echo "[$DATE] WARN Port $PORT is not accessible locally — possible firewall/knocking issue" >> "$LOG"
                # TG-уведомление: через main.py --tg-event (уважает фильтр) с fallback на _notify_tg
                if [[ -x "{main_py}" ]]; then
                    PYTHONPATH="{installer_path}:$PYTHONPATH" python3 "{main_py}" --tg-event port_blocked "Port $PORT недоступен — возможно knocking/firewall блокирует. nginx активен но порт закрыт." 2>/dev/null
                else
                    _notify_tg "🚫 nginx-watchdog: порт $PORT недоступен — возможно firewall/knocking блокирует"
                fi
                # Пытаемся restart nginx на случай если он сам перестал слушать
                systemctl restart nginx 2>&1 | tee -a "$LOG"
                sleep 3
                # Повторная проверка порта
                if python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2); exit(0 if s.connect_ex(('127.0.0.1', $PORT))==0 else 1)" 2>/dev/null; then
                    echo "[$DATE] OK Port $PORT доступен после restart nginx" >> "$LOG"
                else
                    echo "[$DATE] ERROR Port $PORT всё ещё недоступен после restart — проверьте iptables/ufw/knocking" >> "$LOG"
                fi
            fi
            exit 0
        fi

        # Проверка 2: curl fallback (рассинхрон systemd)
        HTTP=$(curl -s -o /dev/null -w "%{{http_code}}" --max-time 3 http://127.0.0.1/ 2>/dev/null || true)
        [[ "$HTTP" =~ ^[2-4] ]] && exit 0

        echo "[$DATE] WARN nginx упал (status=$STATUS http=$HTTP) — перезапуск" >> "$LOG"
        systemctl restart nginx 2>&1 | tee -a "$LOG"
        sleep 3

        STATUS2=$(systemctl is-active nginx 2>/dev/null)
        if [[ "$STATUS2" == "active" ]]; then
            echo "[$DATE] OK nginx перезапущен" >> "$LOG"
            _notify_tg "🔄 nginx-watchdog: nginx перезапущен на $(hostname)"
            {xray_reload}
        else
            echo "[$DATE] ERROR nginx не поднялся" >> "$LOG"
            _notify_tg "🚨 nginx-watchdog: nginx НЕ запустился на $(hostname)"
            journalctl -u nginx -n 20 --no-pager >> "$LOG" 2>/dev/null
        fi
    """)


# ── Публичный API ─────────────────────────────────────────────────────────────
def nginx_watchdog_install() -> None:
    """Устанавливает nginx watchdog: скрипт + systemd timer (каждые 2 минуты)."""
    _SCRIPT.write_text(_build_watchdog_script())
    _SCRIPT.chmod(0o755)

    _SERVICE.write_text(textwrap.dedent(f"""\
        [Unit]
        Description=nginx Watchdog (VLESS Ultimate)
        After=nginx.service

        [Service]
        Type=oneshot
        ExecStart={_SCRIPT}
        StandardOutput=append:{_LOG}
        StandardError=append:{_LOG}
    """))

    _TIMER.write_text(textwrap.dedent("""\
        [Unit]
        Description=nginx Watchdog Timer (VLESS Ultimate)
        After=nginx.service

        [Timer]
        OnBootSec=90
        OnUnitActiveSec=2min
        AccuracySec=30

        [Install]
        WantedBy=timers.target
    """))

    _LOGROTATE.write_text(textwrap.dedent(f"""\
        {_LOG} {{
            daily
            rotate 7
            compress
            delaycompress
            missingok
            notifempty
            create 0640 root root
        }}
    """))

    _run(['systemctl', 'daemon-reload'])
    _run(['systemctl', 'enable', '--now', 'nginx-watchdog.timer'])
    _ok('nginx-watchdog.timer установлен (каждые 2 минуты)')
    _info(f'Лог: {_LOG}')


def nginx_watchdog_remove() -> None:
    """Удаляет nginx watchdog."""
    _run(['systemctl', 'disable', '--now', 'nginx-watchdog.timer'])
    for f in (_TIMER, _SERVICE, _SCRIPT, _LOGROTATE):
        f.unlink(missing_ok=True)
    _run(['systemctl', 'daemon-reload'])
    _ok('nginx-watchdog удалён')


def do_manage_nginx_watchdog() -> None:
    """Интерактивное меню управления nginx watchdog."""
    import os
    from chimera._core import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_item, _box_back,
    )
    while True:
        os.system('clear')
        active  = _is_active('nginx-watchdog.timer')
        enabled = _is_enabled('nginx-watchdog.timer')
        status_str = f'{GREEN}активен{NC}' if active else f'{YELLOW}не активен{NC}'

        _box_top('🔁  NGINX WATCHDOG')
        _box_row(f'  Статус:  {status_str}')
        _box_row(f'  Таймер:  {"enabled" if enabled else "disabled"}')
        _box_row(f'  Режим:   {_protocol_mode()}')
        _box_row(f'  Порт:    {_get_vless_port()}')
        sock = _get_xray_socket()
        if sock:
            _box_row(f'  Socket:  {DIM}{sock}{NC}')
        if _LOG.exists():
            lines = _LOG.read_text(errors='replace').splitlines()[-4:]
            if lines:
                _box_sep()
                for line in lines:
                    _box_row(f'  {DIM}{line[:68]}{NC}')
        _box_sep()
        if active:
            _box_item('1', 'Отключить watchdog')
        else:
            _box_item('1', 'Включить watchdog')
            _box_row(f'     {DIM}(timer каждые 2 минуты){NC}')
        _box_item('2', 'Запустить проверку вручную (с port-check)')
        _box_item('3', 'Показать полный лог')
        _box_back()
        _box_bottom()

        try:
            ch = input(f'{CYAN}Выбор:{NC} ').strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if ch == '1':
            from chimera._core import _box_top, _box_row, _box_bottom
            if active:
                nginx_watchdog_remove()
                _box_top("🔁  NGINX WATCHDOG — ОТКЛЮЧЁН")
                _box_row(f"  {YELLOW}Watchdog остановлен и удалён.{NC}")
                _box_bottom()
            else:
                nginx_watchdog_install()
                _box_top("🔁  NGINX WATCHDOG — ВКЛЮЧЁН")
                _box_row(f"  {GREEN}Watchdog установлен,{NC}")
                _box_row(f"  {GREEN}timer активен (каждые 2 мин).{NC}")
                _box_bottom()
            input(f'{CYAN}Нажмите Enter...{NC}')

        elif ch == '2':
            from chimera._core import _box_top, _box_row, _box_bottom
            _box_top("🔁  РУЧНАЯ ПРОВЕРКА NGINX (с port-check)")
            _box_row(f"  {CYAN}Запуск...{NC}")
            _box_bottom()
            try:
                _nginx_watchdog_run()
            except Exception as e:
                print(f"  {RED}Ошибка: {e}{NC}")
            input(f'{CYAN}Нажмите Enter...{NC}')

        elif ch == '3':
            from chimera._core import _box_top, _box_row, _box_sep, _box_bottom
            _box_top("🔁  ЛОГ NGINX WATCHDOG")
            if _LOG.exists():
                lines = _LOG.read_text(errors='replace').splitlines()[-20:]
                for line in lines:
                    _box_row(f"  {DIM}{line[:68]}{NC}")
            else:
                _box_row(f"  {YELLOW}Лог пуст или ещё не создан.{NC}")
            _box_bottom()
            input(f'{CYAN}Нажмите Enter...{NC}')

        elif ch in ('q', ''):
            break
