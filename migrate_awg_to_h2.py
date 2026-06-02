#!/usr/bin/env python3
"""
migrate_awg_to_h2.py — Миграционный скрипт AWG → Hysteria2
════════════════════════════════════════════════════════════════════════════

Что делает скрипт:
  1. Читает текущие настройки AWG из state.json
  2. Создаёт бэкап текущего state.json
  3. Добавляет секцию hysteria2 с Exit-нодой из AWG конфига
  4. НЕ трогает AWG — всё аддитивно
  5. Устанавливает Hysteria2 на Exit-ноду через SSH (опционально)

Запуск:
  sudo python3 migrate_awg_to_h2.py [--install-exit]

Флаги:
  --install-exit    Установить H2 сервер на удалённую Exit-ноду через SSH
  --dry-run         Показать что будет сделано, без применения

AWG продолжает работать параллельно.
Транспорт можно переключить в меню: Hysteria2 → Выбор транспорта.
"""

import json
import sys
import os
import shutil
from datetime import datetime
from pathlib import Path

# ── Цвета ─────────────────────────────────────────────────────────────────────
if sys.stdout.isatty():
    RED    = '\033[0;31m'; GREEN  = '\033[0;32m'; YELLOW = '\033[1;33m'
    CYAN   = '\033[0;36m'; BOLD   = '\033[1m';    DIM    = '\033[2m'
    NC     = '\033[0m'
else:
    RED = GREEN = YELLOW = CYAN = BOLD = DIM = NC = ''

def info(m):    print(f"{CYAN}[INFO]{NC}  {m}")
def success(m): print(f"{GREEN}[OK]{NC}    {m}")
def warn(m):    print(f"{YELLOW}[WARN]{NC}  {m}")
def error(m):   print(f"{RED}[ERR]{NC}   {m}")

STATE_FILE = Path("/var/lib/xray-installer/state.json")
BACKUP_DIR = Path("/var/backups/vless-installer")

DRY_RUN      = "--dry-run"      in sys.argv
INSTALL_EXIT = "--install-exit" in sys.argv


def backup_state() -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = BACKUP_DIR / f"state_before_h2_migration_{ts}.json"
    shutil.copy2(str(STATE_FILE), str(dst))
    success(f"Бэкап state.json → {dst}")
    return dst


def load_state() -> dict:
    if not STATE_FILE.exists():
        error(f"state.json не найден: {STATE_FILE}")
        sys.exit(1)
    return json.loads(STATE_FILE.read_text())


def save_state(st: dict) -> None:
    STATE_FILE.write_text(json.dumps(st, indent=2, ensure_ascii=False))


def main():
    print()
    print(f"{CYAN}{'═'*64}{NC}")
    print(f"  {BOLD}Миграция AWG → Hysteria2{NC}  "
          f"{'(DRY RUN)' if DRY_RUN else ''}")
    print(f"{CYAN}{'═'*64}{NC}")
    print()

    if os.geteuid() != 0:
        error("Требуются права root: sudo python3 migrate_awg_to_h2.py")
        sys.exit(1)

    st = load_state()

    # ── Читаем AWG параметры ───────────────────────────────────────────────────
    awg_host = st.get("awg_exit_host", "")
    awg_port = st.get("awg_exit_port", 51820)
    mode     = st.get("install_mode", "A")
    awg_on   = st.get("awg_exit_enabled", False)

    print(f"  Режим установки:   {CYAN}{mode}{NC}")
    print(f"  AWG Exit enabled:  {CYAN}{awg_on}{NC}")
    print(f"  AWG Exit host:     {CYAN}{awg_host or '—'}{NC}")
    print(f"  AWG Exit port:     {CYAN}{awg_port}{NC}")
    print()

    if mode != "B":
        warn("Установка выполнена в режиме A — каскад не настроен.")
        warn("Hysteria2 требует Режим B (Entry → Exit).")
        warn("Скрипт добавит секцию hysteria2, но без exit-ноды.")

    # ── Проверяем, нет ли уже H2 ──────────────────────────────────────────────
    h2_existing = st.get("hysteria2", {})
    if h2_existing.get("enabled"):
        warn("Секция hysteria2 уже существует и включена.")
        try:
            ans = input("  Перезаписать? [y/N]: ").strip().lower()
        except KeyboardInterrupt:
            sys.exit(0)
        if ans != "y":
            info("Миграция отменена.")
            sys.exit(0)

    # ── Формируем секцию H2 ───────────────────────────────────────────────────
    h2_section = {
        "enabled": False,   # будет True после установки Exit
        "transport_only": False,
        "active_transport": "awg",
        "_active_node_ip": "",
        "_wd_fail_count": 0,
        "exit_nodes": [],
        "cert": {
            "crt": "/etc/xray/hysteria.crt",
            "key": "/etc/xray/hysteria.key",
            "domain": "",
            "auto_renew": True,
            "expire_date": "",
            "ipv6_support": True,
        },
        "health_check": {
            "interval_sec": 60,
            "timeout_sec": 5,
            "method": "quic_ping",
            "fail_threshold": 3,
        },
        "firewall": {
            "udp_ports": [443],
            "ip6tables_rules": True,
            "fallback_ports": [8443, 2083, 2087, 2096, 4433],
            "auto_configure": True,
        },
        "balancer": {
            "strategy": "weightedRandom",
            "switch_threshold": 0.5,
            "current_weights": {},
            "ipv4_weight": 1.0,
            "ipv6_weight": 1.0,
        },
        "auto_update": {
            "enabled": True,
            "check_interval_hours": 24,
        },
    }

    # Если AWG настроен — добавляем его хост как pending-ноду H2
    if awg_host:
        h2_section["exit_nodes"].append({
            "ip":      awg_host,
            "ports":   [443],
            "auth":    "",   # заполняется при установке H2 на Exit
            "weight":  1.0,
            "status":  "pending",
            "ipstack": "ipv4",
            "version": "",
            "ssh_port": 22,
            "metrics": {"rtt_ms": 0, "loss_pct": 0.0, "speed_mbps": 0},
            "_migrated_from_awg": True,
        })
        info(f"Добавлена Exit-нода из AWG: {awg_host}")

    # ── Применяем ─────────────────────────────────────────────────────────────
    if DRY_RUN:
        print()
        print(f"{YELLOW}[DRY RUN] Будет добавлена секция hysteria2:{NC}")
        print(json.dumps(h2_section, indent=2, ensure_ascii=False))
        print()
        info("DRY RUN завершён, изменения не применены")
        return

    backup_state()
    st["hysteria2"] = h2_section
    save_state(st)
    success("Секция hysteria2 добавлена в state.json")

    # ── Установка Exit-ноды через SSH ─────────────────────────────────────────
    if INSTALL_EXIT and awg_host:
        print()
        info(f"Установка H2 на {awg_host}...")
        try:
            # Добавляем путь проекта в sys.path
            project_root = Path(__file__).parent
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))

            from vless_installer.modules.hysteria2_exit_mgr import (
                h2_exit_remote_install
            )
            import getpass
            ssh_key  = input(f"  SSH-ключ (пусто = пароль): ").strip() or None
            ssh_pass = getpass.getpass("  SSH-пароль root: ") if not ssh_key else None
            raw_pwd  = input("  Пароль H2 (пусто = авто): ").strip()

            import secrets
            auth = raw_pwd or secrets.token_urlsafe(24)

            ok = h2_exit_remote_install(
                host=awg_host,
                ssh_key=ssh_key,
                ssh_pass=ssh_pass,
                ports=[443],
                auth_password=auth,
            )
            if ok:
                success(f"H2 установлен на {awg_host}!")
                print()
                print(f"  {BOLD}Следующий шаг:{NC}")
                print(f"  Запустите установщик: sudo python3 main.py")
                print(f"  Меню: Hysteria2 → Выбор транспорта → Hysteria2")
            else:
                warn("Установка завершилась с ошибками. Проверьте лог.")

        except (ImportError, Exception) as e:
            error(f"Не удалось установить H2: {e}")
            warn("Запустите установщик вручную: sudo python3 main.py → Hysteria2")
    else:
        print()
        print(f"{BOLD}Миграция завершена!{NC}")
        print()
        print(f"  {DIM}Следующие шаги:{NC}")
        print(f"  1. Запустите: {CYAN}sudo python3 main.py{NC}")
        print(f"  2. Меню: {CYAN}Hysteria2 → Exit-нода → Установить на удалённую ноду{NC}")
        print(f"  3. После установки: {CYAN}Hysteria2 → Выбор транспорта → Hysteria2{NC}")
        if awg_host:
            print(f"  4. SSH-доступ к {CYAN}{awg_host}{NC} потребуется для шага 2")
        print()
        print(f"  {DIM}AWG продолжает работать параллельно — переключение в любой момент.{NC}")


if __name__ == "__main__":
    main()
