"""
chimera/modules/fail2ban_setup.py
───────────────────────────────────────────────────────────────────────────────
Fail2ban-конфигурация и Xray watchdog (systemd timer каждые 2 минуты).

  • setup_fail2ban()       — пишет /etc/fail2ban/jail.d/xray-reality.conf
                              + фильтры, перезапускает fail2ban.
                              Вызывается из do_full_install (группа install
                              orchestration, остаётся в _core.py).

  • _watchdog_install()    — ставит systemd-timer xray-watchdog.timer +
                              скрипт /usr/local/bin/xray-watchdog.sh.
  • _watchdog_remove()     — удаляет watchdog.
  • do_manage_watchdog()   — меню управления watchdog.

Все функции — pure file-template writers. Никаких state.json мутаций
(setup_fail2ban читает SERVER_PORT из globals ядра; _watchdog_install
читает server_port из state.json напрямую).

Точки входа из _core.py:
    from chimera.modules.fail2ban_setup import (
        FAIL2BAN_CONF, _WATCHDOG_TIMER, _WATCHDOG_SERVICE, _WATCHDOG_SCRIPT,
        setup_fail2ban, _watchdog_install, _watchdog_remove, do_manage_watchdog,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import sys
import textwrap
import time
from pathlib import Path
from typing import Optional

# ── Константы ─────────────────────────────────────────────────────────────────
FAIL2BAN_CONF        = Path("/etc/fail2ban/jail.d/xray-reality.conf")
_WATCHDOG_TIMER      = Path("/etc/systemd/system/xray-watchdog.timer")
_WATCHDOG_SERVICE    = Path("/etc/systemd/system/xray-watchdog.service")
_WATCHDOG_SCRIPT     = Path("/usr/local/bin/xray-watchdog.sh")


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль chimera._core (импорт лениво)."""
    import importlib
    return importlib.import_module("chimera._core")


# ============================================================================
#  FAIL2BAN SETUP
# ============================================================================
def setup_fail2ban() -> None:
    core = _core_module()
    command_exists = core.command_exists
    warn           = core.warn
    info           = core.info
    success        = core.success
    _run           = core._run
    SERVER_PORT    = core.SERVER_PORT

    if not command_exists("fail2ban-server"):
        warn("Fail2ban не установлен, пропускаем")
        return
    info("Настройка Fail2ban...")

    FAIL2BAN_CONF.parent.mkdir(parents=True, exist_ok=True)
    Path("/etc/fail2ban/filter.d").mkdir(parents=True, exist_ok=True)

    FAIL2BAN_CONF.write_text(textwrap.dedent(f"""\
        [xray-reality]
        enabled = true
        port = {SERVER_PORT}
        filter = xray-reality
        logpath = /var/log/xray/*.log
        maxretry = 5
        bantime = 3600
        findtime = 600

        [sshd]
        enabled = true
        port = 22
        backend = systemd
        logpath = %(sshd_log)s
        maxretry = 5
        bantime = 3600

        [nginx-http-auth]
        enabled = true
        port = http,https
        logpath = /var/log/nginx/*error.log
        maxretry = 5
        bantime = 3600

        [nginx-limit-req]
        enabled = true
        port = http,https
        filter = nginx-limit-req
        logpath = /var/log/nginx/*error.log
        maxretry = 5
        bantime = 3600
    """))

    Path("/etc/fail2ban/filter.d/xray-reality.conf").write_text(textwrap.dedent("""\
        [Definition]
        failregex = ^.*Failed authentication.*$|^.*Invalid user.*$|^.*TLS handshake failed.*$|^.*<HOST>.*blocked.*$
        ignoreregex =
    """))

    Path("/etc/fail2ban/filter.d/nginx-limit-req.conf").write_text(textwrap.dedent("""\
        [Definition]
        failregex = limiting requests, excess:.* by zone.*client: <HOST>
        ignoreregex =
    """))

    # Гарантируем наличие файлов логов xray до старта fail2ban,
    # иначе fail2ban падает с "Have not found any log file for xray-reality jail"
    xray_log_dir = Path("/var/log/xray")
    xray_log_dir.mkdir(parents=True, exist_ok=True)
    for log_file in ("access.log", "error.log"):
        lp = xray_log_dir / log_file
        lp.touch(exist_ok=True)
        try:
            import pwd
            xray_uid = pwd.getpwnam("xray").pw_uid
            xray_gid = pwd.getpwnam("xray").pw_gid
            os.chown(str(lp), xray_uid, xray_gid)
        except Exception:
            pass
        lp.chmod(0o644)
    xray_log_dir.chmod(0o755)

    info("Перезапуск fail2ban: stop → start → restart...")
    _run(["systemctl", "stop",    "fail2ban"], check=False, quiet=True); time.sleep(1)
    _run(["systemctl", "start",   "fail2ban"], check=False, quiet=True); time.sleep(2)
    _run(["systemctl", "restart", "fail2ban"], check=False, quiet=True); time.sleep(2)

    r = _run(["systemctl", "is-active", "fail2ban"], capture=True, check=False)
    if r.stdout.strip() == "active":
        success("Fail2ban настроен и активен (IPv4+IPv6)")
    else:
        warn("Fail2ban запущен, но не перешёл в активное состояние")


# ============================================================================
#  XRAY WATCHDOG (systemd timer каждые 2 минуты)
# ============================================================================
def _watchdog_install() -> None:
    """Устанавливает watchdog: скрипт + systemd timer каждые 2 минуты."""
    core = _core_module()
    _run        = core._run
    success     = core.success
    STATE_FILE  = core.STATE_FILE

    # Определяем порт из state
    port = 443
    try:
        if STATE_FILE.exists():
            port = json.loads(STATE_FILE.read_text()).get("server_port", 443)
    except Exception:
        pass

    script = textwrap.dedent(f"""\
        #!/bin/bash
        # Xray Watchdog (установлено VLESS Installer)
        LOG="/var/log/xray-watchdog.log"
        DATE=$(date '+%Y-%m-%d %H:%M:%S')
        PORT={port}

        is_active=$(systemctl is-active xray 2>/dev/null)
        port_listening=$(ss -tlnp 2>/dev/null | grep -q ":$PORT " && echo yes || echo no)

        # Не вмешиваться если xray в процессе перезапуска балансировщиком
        if [ "$is_active" = "reloading" ]; then
            exit 0
        fi

        if [ "$is_active" != "active" ] || [ "$port_listening" != "yes" ]; then
            echo "[$DATE] WATCHDOG: xray=$is_active port=$PORT listening=$port_listening — перезапуск" >> "$LOG"
            python3 {sys.argv[0]} --tg-event xray_down "🔴 Watchdog: xray=$is_active port=$PORT — перезапуск" >> "$LOG" 2>&1 || true
            systemctl restart xray >> "$LOG" 2>&1
            sleep 5
            is_active2=$(systemctl is-active xray 2>/dev/null)
            echo "[$DATE] WATCHDOG: после перезапуска xray=$is_active2" >> "$LOG"
            if [ "$is_active2" = "active" ]; then
                python3 {sys.argv[0]} --tg-event xray_up "🟢 Watchdog: Xray восстановлен (порт $PORT)" >> "$LOG" 2>&1 || true
                # ВАЖНО: restart, не reload — только restart пересоздаёт Unix-сокет
                # /dev/shm/XXXX.socket который xray удаляет при старте через ExecStartPre.
                nginx_active=$(systemctl is-active nginx 2>/dev/null)
                if [ "$nginx_active" = "active" ]; then
                    systemctl restart nginx >> "$LOG" 2>&1 \\
                        && echo "[$DATE] WATCHDOG: nginx restart — OK" >> "$LOG" \\
                        || echo "[$DATE] WATCHDOG: nginx restart — FAIL" >> "$LOG"
                fi
            else
                python3 {sys.argv[0]} --tg-event xray_down "🔴 Watchdog: Xray НЕ запустился после перезапуска!" >> "$LOG" 2>&1 || true
            fi
        fi
    """)
    _WATCHDOG_SCRIPT.write_text(script)
    _WATCHDOG_SCRIPT.chmod(0o750)

    _WATCHDOG_SERVICE.write_text(textwrap.dedent("""\
        [Unit]
        Description=Xray Watchdog (VLESS Installer)
        After=network.target

        [Service]
        Type=oneshot
        ExecStart=/usr/local/bin/xray-watchdog.sh
    """))

    _WATCHDOG_TIMER.write_text(textwrap.dedent("""\
        [Unit]
        Description=Xray Watchdog Timer

        [Timer]
        OnBootSec=2min
        OnUnitActiveSec=2min
        Unit=xray-watchdog.service

        [Install]
        WantedBy=timers.target
    """))

    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    _run(["systemctl", "enable", "--now", "xray-watchdog.timer"],
         check=False, quiet=True)
    success("Watchdog установлен: systemd timer каждые 2 минуты")
    success(f"Лог: /var/log/xray-watchdog.log")


def _watchdog_remove() -> None:
    core = _core_module()
    _run     = core._run
    success  = core.success

    _run(["systemctl", "disable", "--now", "xray-watchdog.timer"],
         check=False, quiet=True)
    for p in (_WATCHDOG_TIMER, _WATCHDOG_SERVICE, _WATCHDOG_SCRIPT):
        p.unlink(missing_ok=True)
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    success("Watchdog удалён")


def do_manage_watchdog() -> None:
    """Меню управления watchdog."""
    core = _core_module()
    _run     = core._run
    warn     = core.warn
    _box_top  = core._box_top
    _box_row  = core._box_row
    _box_item = core._box_item
    _box_bottom = core._box_bottom
    _BOX_W   = core._BOX_W
    BLUE = core.BLUE
    CYAN = core.CYAN
    DIM = core.DIM
    GREEN = core.GREEN
    NC = core.NC
    YELLOW = core.YELLOW
    GREEN, YELLOW, NC, CYAN, BLUE, DIM = (
        core.GREEN, core.YELLOW, core.NC, core.CYAN, core.BLUE, core.DIM
    )

    while True:
        os.system("clear")
        active = _WATCHDOG_TIMER.exists()
        r = _run(["systemctl", "is-active", "xray-watchdog.timer"],
                 capture=True, check=False)
        timer_status = r.stdout.strip() if r.returncode == 0 else "неактивен"

        print()
        _box_top(f"Watchdog авторестарт Xray")
        _box_row(f"  Статус:  {GREEN if timer_status == 'active' else YELLOW}{timer_status}{NC}")
        if active:
            wlog = Path("/var/log/xray-watchdog.log")
            if wlog.exists():
                lines = wlog.read_text().splitlines()[-5:]
                if lines:
                    _box_row(f"  {DIM}Последние события:{NC}")
                    max_line_w = _BOX_W - 6
                    for l in lines:
                        if len(l) > max_line_w:
                            l = l[:max_line_w - 1] + "…"
                        _box_row(f"    {DIM}{l}{NC}")
        _box_item("1", f"{'Отключить watchdog' if active else 'Включить watchdog (timer каждые 2 мин)'}")
        _box_item("2", f"Запустить проверку вручную прямо сейчас")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            if active:
                _watchdog_remove()
            else:
                _watchdog_install()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            if _WATCHDOG_SCRIPT.exists():
                _run(["bash", str(_WATCHDOG_SCRIPT)], check=False, quiet=False)
            else:
                warn("Watchdog не установлен — сначала включите его")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)
