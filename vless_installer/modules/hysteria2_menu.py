"""
vless_installer/modules/hysteria2_menu.py
───────────────────────────────────────────────────────────────────────────────
Главное меню «Управление транспортом Hysteria2».

Вызывается из _core.py одним вызовом:
    from vless_installer.modules.hysteria2_menu import do_hysteria2_menu
    do_hysteria2_menu()

Стиль меню идентичен остальным разделам _core.py.
Ни один существующий файл не изменяется.

Интеграция в _core.py:
    • В main_menu() добавить пункт «7  📡 Hysteria2 транспорт»
    • В _menu_network() добавить пункт «H  🚀 Hysteria2 транспорт»
    • В CLI (main.py) добавить обработку --h2-* флагов

Подменю:
  1  Exit-нода    (hysteria2_exit_mgr.do_h2_exit_menu)
  2  Транспорт    (hysteria2_transport.h2_select_transport)
  3  Балансировщик(hysteria2_balancer.do_h2_balancer_menu)
  4  Health Check (hysteria2_health.do_h2_health_menu)
  5  Watchdog     (hysteria2_watchdog.do_h2_watchdog_menu)
  6  Трафик       (hysteria2_traffic.do_h2_traffic_menu)
  7  Сертификаты  (hysteria2_cert_mgr.do_h2_cert_menu)
  8  Обновление   (hysteria2_auto_update.do_h2_update_menu)
  9  Кластер      (hysteria2_cluster.do_h2_cluster_menu)
  B  Бэкап        (hysteria2_backup.do_h2_backup_menu)
  D  DPI детектор (hysteria2_dpi.do_h2_dpi_menu)
  Q  Качество     (hysteria2_quality.do_h2_quality_menu)
  S  Smoke Test   (hysteria2_smoke_test.do_h2_smoke_test_menu)
  0  ← Назад
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from vless_installer.modules.hysteria2_common import (
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
    info, success, warn, error,
    _load_h2_state, _ensure_h2_state,
    _service_active, _h2_binary_version, _h2_binary_exists,
    H2_SERVICE,
)


def _h2_status_line() -> str:
    """Возвращает однострочный статус H2 для шапки меню."""
    h2      = _load_h2_state()
    enabled = h2.get("enabled", False)
    active  = _service_active(H2_SERVICE)
    ver     = _h2_binary_version() if _h2_binary_exists() else "—"
    nodes   = h2.get("exit_nodes", [])
    n_live  = sum(1 for n in nodes if n.get("status") == "active")
    n_total = len(nodes)
    transport = h2.get("active_transport", "—")

    if not enabled:
        return f"{YELLOW}не установлен{NC}"

    svc_col = GREEN if active else RED
    svc_str = f"{svc_col}{'активен' if active else 'DOWN'}{NC}"
    return (
        f"v{ver}  │  Сервис: {svc_str}  │  "
        f"Ноды: {GREEN}{n_live}{NC}/{n_total}  │  "
        f"Транспорт: {CYAN}{transport}{NC}"
    )


def do_hysteria2_menu() -> None:
    """
    Главное интерактивное меню Hysteria2.
    Вызывается из _core.py → main_menu() или _menu_network().
    """
    _ensure_h2_state()   # инициализируем секцию если первый запуск

    while True:
        os.system("clear")
        print()
        # Шапка в стиле проекта
        print(f"{CYAN}{'═'*64}{NC}")
        print(f"  {BOLD}📡  Hysteria2 — Управление транспортом{NC}")
        print(f"{CYAN}{'═'*64}{NC}")
        print(f"  {DIM}{_h2_status_line()}{NC}")
        print(f"{CYAN}{'─'*64}{NC}")
        print()

        # ── Exit-нода ──────────────────────────────────────────────────────────
        print(f"  {CYAN}1{NC}  🖥️  Exit-нода           "
              f"{DIM}Установка/управление H2 сервером{NC}")
        print(f"  {CYAN}2{NC}  🔀 Выбор транспорта     "
              f"{DIM}AWG / Hysteria2 / Оба + веса{NC}")
        print(f"  {CYAN}3{NC}  ⚖️  Балансировщик нод    "
              f"{DIM}Стратегия, веса, автопереключение{NC}")
        print()

        # ── Мониторинг ─────────────────────────────────────────────────────────
        print(f"  {CYAN}4{NC}  🩺 Health Check         "
              f"{DIM}QUIC-пинг, RTT, потери{NC}")
        print(f"  {CYAN}5{NC}  🔄 Watchdog             "
              f"{DIM}Авторестарт при падении{NC}")
        print(f"  {CYAN}6{NC}  📊 Трафик               "
              f"{DIM}RX/TX через iptables/ss{NC}")
        print(f"  {CYAN}Q{NC}  📈 Качество соединения   "
              f"{DIM}RTT/потери/скорость + TG-отчёт{NC}")
        print()

        # ── Инфраструктура ────────────────────────────────────────────────────
        print(f"  {CYAN}7{NC}  🔒 Сертификаты          "
              f"{DIM}certbot / самоподписанный + мониторинг{NC}")
        print(f"  {CYAN}8{NC}  ⬆️  Обновление           "
              f"{DIM}Автообновление бинарника H2{NC}")
        print(f"  {CYAN}9{NC}  🖧  Кластер SSH          "
              f"{DIM}Управление несколькими Exit-нодами{NC}")
        print(f"  {CYAN}B{NC}  💾 Бэкап               "
              f"{DIM}Резервное копирование + миграция из AWG{NC}")
        print()

        # ── Диагностика ───────────────────────────────────────────────────────
        print(f"  {CYAN}D{NC}  🔍 DPI Детектор         "
              f"{DIM}Тест блокировки UDP + авто-фолбэк порта{NC}")
        print(f"  {CYAN}S{NC}  🔬 Smoke Test           "
              f"{DIM}Полная проверка после установки{NC}")
        print(f"  {CYAN}L{NC}  📋 Логи H2              "
              f"{DIM}Просмотр /var/log/hysteria.log{NC}")
        print()
        print(f"  {DIM}[0]{NC}  ← Назад в главное меню")
        print()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch == "0" or ch == "":
            break

        elif ch == "1":
            try:
                from vless_installer.modules.hysteria2_exit_mgr import do_h2_exit_menu
                do_h2_exit_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}")
                time.sleep(2)

        elif ch == "2":
            try:
                from vless_installer.modules.hysteria2_transport import h2_select_transport
                h2_select_transport()
            except ImportError as e:
                error(f"Модуль недоступен: {e}")
                time.sleep(2)

        elif ch == "3":
            try:
                from vless_installer.modules.hysteria2_balancer import do_h2_balancer_menu
                do_h2_balancer_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}")
                time.sleep(2)

        elif ch == "4":
            try:
                from vless_installer.modules.hysteria2_health import do_h2_health_menu
                do_h2_health_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}")
                time.sleep(2)

        elif ch == "5":
            try:
                from vless_installer.modules.hysteria2_watchdog import do_h2_watchdog_menu
                do_h2_watchdog_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}")
                time.sleep(2)

        elif ch == "6":
            try:
                from vless_installer.modules.hysteria2_traffic import do_h2_traffic_menu
                do_h2_traffic_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}")
                time.sleep(2)

        elif ch == "7":
            try:
                from vless_installer.modules.hysteria2_cert_mgr import do_h2_cert_menu
                do_h2_cert_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}")
                time.sleep(2)

        elif ch == "8":
            try:
                from vless_installer.modules.hysteria2_auto_update import do_h2_update_menu
                do_h2_update_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}")
                time.sleep(2)

        elif ch == "9":
            try:
                from vless_installer.modules.hysteria2_cluster import do_h2_cluster_menu
                do_h2_cluster_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}")
                time.sleep(2)

        elif ch == "B":
            try:
                from vless_installer.modules.hysteria2_backup import do_h2_backup_menu
                do_h2_backup_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}")
                time.sleep(2)

        elif ch == "D":
            try:
                from vless_installer.modules.hysteria2_dpi import do_h2_dpi_menu
                do_h2_dpi_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}")
                time.sleep(2)

        elif ch == "Q":
            try:
                from vless_installer.modules.hysteria2_quality import do_h2_quality_menu
                do_h2_quality_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}")
                time.sleep(2)

        elif ch == "S":
            try:
                from vless_installer.modules.hysteria2_smoke_test import do_h2_smoke_test_menu
                do_h2_smoke_test_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}")
                time.sleep(2)

        elif ch == "L":
            _show_h2_logs()

        else:
            warn("Неверный выбор")
            time.sleep(0.8)


def _show_h2_logs() -> None:
    """Показывает последние 60 строк лога H2."""
    log_paths = [
        Path("/var/log/hysteria.log"),
        Path("/var/log/hysteria-watchdog.log"),
        Path("/var/log/hysteria-health.log"),
    ]
    print()
    for lp in log_paths:
        if lp.exists():
            print(f"{CYAN}── {lp} ──{NC}")
            from vless_installer.modules.hysteria2_common import _run
            r = _run(["tail", "-n", "20", str(lp)], capture=True)
            print(r.stdout or "(пуст)")
            print()
    input(f"{BLUE}Нажмите Enter...{NC}")


"""
─────────────────────────────────────────────────────────────
ИНТЕГРАЦИЯ В _core.py (АДДИТИВНО — только вызовы по имени)
─────────────────────────────────────────────────────────────

1) В блоке import-ов _core.py добавить:
   from vless_installer.modules.hysteria2_menu import do_hysteria2_menu

2) В main_menu() — добавить пункт (не изменяя существующие):
   _box_row()
   _box_row(f"  {CYAN}7{NC}  📡 {TITLE}Hysteria2 транспорт{NC}")
   _box_row(f"     {DIM}Exit-нода, Балансировщик, Health, DPI, Cert{NC}")

   В обработчике выбора:
   elif choice == "7":
       do_hysteria2_menu()

3) В _menu_network() — добавить пункт:
   _box_item("H", f"🚀 Hysteria2 транспорт  {DIM}(Режим B, Exit-нода){NC}")

   В обработчике:
   elif ch.lower() == "h":
       do_hysteria2_menu()

ИНТЕГРАЦИЯ В main.py (АДДИТИВНО):
───────────────────────────────────────────────────────────

if "--h2-install-exit" in sys.argv:
    from vless_installer.modules.hysteria2_exit_mgr import h2_exit_install
    ports_raw = sys.argv[sys.argv.index("--h2-port") + 1] \\
        if "--h2-port" in sys.argv else "443"
    ports = [int(p) for p in ports_raw.split(",")]
    h2_exit_install(ports=ports)
    sys.exit(0)

if "--h2-status" in sys.argv:
    from vless_installer.modules.hysteria2_exit_mgr import h2_exit_status
    import json; print(json.dumps(h2_exit_status(), indent=2))
    sys.exit(0)

if "--h2-health" in sys.argv:
    from vless_installer.modules.hysteria2_health import h2_health_check_cron
    h2_health_check_cron(); sys.exit(0)

if "--h2-traffic" in sys.argv:
    from vless_installer.modules.hysteria2_traffic import h2_traffic_report
    print(h2_traffic_report()); sys.exit(0)

if "--h2-quality-report" in sys.argv:
    from vless_installer.modules.hysteria2_quality import h2_quality_report
    print(h2_quality_report(send_tg="--tg" in sys.argv)); sys.exit(0)

if "--h2-logs" in sys.argv:
    import subprocess
    subprocess.run(["tail", "-n", "100", "/var/log/hysteria.log"])
    sys.exit(0)

if "--h2-cluster" in sys.argv:
    idx = sys.argv.index("--h2-cluster")
    op  = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else "status"
    from vless_installer.modules.hysteria2_cluster import h2_cluster_run
    h2_cluster_run(op); sys.exit(0)

if "--h2-cert-monitor" in sys.argv:
    from vless_installer.modules.hysteria2_cert_mgr import h2_cert_monitor
    h2_cert_monitor(); sys.exit(0)

if "--h2-autoupdate" in sys.argv:
    from vless_installer.modules.hysteria2_auto_update import h2_autoupdate_cron
    h2_autoupdate_cron(); sys.exit(0)

if "--h2-watchdog-run" in sys.argv:
    from vless_installer.modules.hysteria2_watchdog import h2_watchdog_run
    h2_watchdog_run(); sys.exit(0)

if "--h2-transport" in sys.argv:
    idx = sys.argv.index("--h2-transport")
    val = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else "h2"
    if val == "awg":
        from vless_installer.modules.hysteria2_transport import h2_transport_remove
        h2_transport_remove()
    else:
        from vless_installer.modules.hysteria2_transport import h2_transport_apply
        h2_transport_apply()
    sys.exit(0)
"""
