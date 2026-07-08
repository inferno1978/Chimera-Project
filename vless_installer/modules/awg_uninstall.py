"""
vless_installer/modules/awg_uninstall.py
───────────────────────────────────────────────────────────────────────────────
Полное удаление AmneziaWG standalone.

Удаляет:
  • awg-quick@awg0.service (stop + disable)
  • /etc/amnezia/amneziawg/awg0.conf (и awg1.conf если каскад)
  • /root/awg/keys/ (клиентские конфиги)
  • /root/awg/backups/ (backup'ы)
  • /var/lib/xray-installer/awg_standalone_state.json
  • /etc/cron.d/awg-standalone-expires
  • /etc/cron.d/awg-cascade-ru-update (если каскад)
  • awg-cascade-routing.service (если каскад)
  • /etc/awg-cascade/ (ru.zone, routing script)
  • UFW-правило для AWG-порта
  • ipset awg_ru_networks (если каскад)
  • iptables-правила каскада (если были)

НЕ удаляет (как договорились в Q4=b):
  • Fail2Ban (используется другими сервисами)
  • sysctl-настройки (могут использоваться VLESS)
  • SSH hardening
  • DKMS-модуль amnezia (если используется chain Mode B)
  • Пакет amneziawg-tools (можно удалить отдельно при необходимости)
"""
from __future__ import annotations

from pathlib import Path

from .awg_constants import (
    AWGS_INTERFACE, AWGS_BIN, AWGS_QUICK_BIN, AWGS_SYSTEMD_AWG_QUICK,
    AWGS_CONF_DIR, AWGS_SERVER_CONF, AWGS_AWG_DIR, AWGS_KEYS_DIR,
    AWGS_BACKUP_DIR, AWGS_LOG_FILE, AWGS_INIT_FILE,
    AWGS_STATE_FILE, AWGS_CRON_EXPIRES, AWGS_CRON_RU_UPDATE,
    AWGS_SYSTEMD_CASCADE, AWGS_CASCADE_DIR, AWGS_IPSET_NAME,
    AWGS_DEFAULT_PORT,
)
from .awg_state import awgs_state_load, awgs_state_is_installed
from .awg_standalone import awgs_stop_systemd


def _core_module():
    import importlib
    return importlib.import_module("vless_installer._core")


# ── Удаление ────────────────────────────────────────────────────────────────

def awgs_uninstall_full(keep_backups: bool = True) -> bool:
    """
    Полное удаление standalone AWG.
    keep_backups: если True — сохраняет /root/awg/backups/ (чтобы можно было восстановить)
    """
    core = _core_module()
    info = core.info
    success = core.success
    warn = core.warn
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    GREEN, NC, YELLOW, DIM = core.GREEN, core.NC, core.YELLOW, core.DIM

    _box_top(f"Удаление AmneziaWG 2.0 (standalone)")
    _box_row()
    _box_bottom()

    if not awgs_state_is_installed():
        warn("Standalone AWG не установлен (state.json не найден)")
        # Всё равно продолжаем — могут быть осиротевшие файлы

    state = awgs_state_load()
    port = state.get("port", AWGS_DEFAULT_PORT)
    is_cascade = bool(state.get("cascade_role"))

    # 1. Останавливаем сервисы
    info("Остановка сервисов...")
    awgs_stop_systemd()
    if is_cascade:
        # Каскад: останавливаем awg1 + routing
        core._run(["systemctl", "stop", "awg-quick@awg1"],
                  check=False, quiet=True, timeout=30)
        core._run(["systemctl", "disable", "awg-quick@awg1"],
                  check=False, quiet=True)
        core._run(["systemctl", "stop", "awg-cascade-routing"],
                  check=False, quiet=True, timeout=30)
        core._run(["systemctl", "disable", "awg-cascade-routing"],
                  check=False, quiet=True)

    # 2. Удаляем systemd-юниты
    info("Удаление systemd-юнитов...")
    core._run(["systemctl", "disable", AWGS_SYSTEMD_AWG_QUICK],
              check=False, quiet=True)
    if AWGS_SYSTEMD_CASCADE.exists():
        AWGS_SYSTEMD_CASCADE.unlink(missing_ok=True)
    core._run(["systemctl", "daemon-reload"], check=False, quiet=True)

    # 3. Удаляем cron-файлы
    info("Удаление cron-задач...")
    AWGS_CRON_EXPIRES.unlink(missing_ok=True)
    AWGS_CRON_RU_UPDATE.unlink(missing_ok=True)

    # 4. Удаляем конфиги
    info("Удаление конфигов...")
    # awg0.conf и awg1.conf
    for conf_name in ("awg0.conf", "awg1.conf"):
        p = AWGS_CONF_DIR / conf_name
        p.unlink(missing_ok=True)
    # Если директория пустая — удаляем
    try:
        if AWGS_CONF_DIR.exists() and not any(AWGS_CONF_DIR.iterdir()):
            AWGS_CONF_DIR.rmdir()
    except Exception:
        pass

    # 5. Удаляем ключи и клиентские конфиги
    info("Удаление ключей и клиентских конфигов...")
    if AWGS_KEYS_DIR.exists():
        for f in AWGS_KEYS_DIR.iterdir():
            if f.is_file():
                f.unlink()

    # 6. Backup'ы (опционально)
    if not keep_backups:
        info("Удаление backup'ов...")
        if AWGS_BACKUP_DIR.exists():
            import shutil
            shutil.rmtree(AWGS_BACKUP_DIR, ignore_errors=True)
    else:
        if AWGS_BACKUP_DIR.exists():
            info(f"Backup'ы сохранены: {AWGS_BACKUP_DIR}")

    # 7. Cascade-файлы
    if is_cascade:
        info("Удаление cascade-файлов...")
        import shutil
        if AWGS_CASCADE_DIR.exists():
            shutil.rmtree(AWGS_CASCADE_DIR, ignore_errors=True)
        # Удаляем ipset
        core._run(["ipset", "destroy", AWGS_IPSET_NAME],
                  check=False, quiet=True)
        # Удаляем iptables-правила (best-effort)
        _awgs_uninstall_cleanup_iptables()

    # 8. UFW-правило
    info(f"Удаление UFW-правила для UDP {port}...")
    core._run(["ufw", "delete", "allow", f"{port}/udp"],
              check=False, quiet=True)

    # 9. Init-файл и лог
    AWGS_INIT_FILE.unlink(missing_ok=True)
    # Лог оставляем — может пригодиться для разбора полётов
    if AWGS_LOG_FILE.exists():
        info(f"Лог сохранён: {AWGS_LOG_FILE}")

    # 10. State
    info("Удаление state...")
    AWGS_STATE_FILE.unlink(missing_ok=True)

    # 11. Если /root/awg/ пустой — удаляем
    try:
        if AWGS_AWG_DIR.exists():
            remaining = list(AWGS_AWG_DIR.iterdir())
            # Оставляем лог, удаляем директорию только если в ней только лог
            if not remaining or (
                len(remaining) == 1 and remaining[0].name == AWGS_LOG_FILE.name
            ):
                AWGS_LOG_FILE.unlink(missing_ok=True)
                AWGS_AWG_DIR.rmdir()
    except Exception:
        pass

    # 12. DKMS-модуль — НЕ удаляем (может использоваться chain Mode B)
    # Пользователь может удалить отдельно: apt remove amneziawg-dkms

    print()
    success("Удаление AmneziaWG 2.0 завершено!")
    print()
    _box_top(f"Готово")
    _box_row(f"  {GREEN}Удалено:{NC}")
    _box_row(f"    • awg-quick@awg0.service (stop + disable)")
    if is_cascade:
        _box_row(f"    • awg-quick@awg1.service")
        _box_row(f"    • awg-cascade-routing.service")
        _box_row(f"    • ipset {AWGS_IPSET_NAME}")
        _box_row(f"    • {AWGS_CASCADE_DIR}/")
    _box_row(f"    • {AWGS_SERVER_CONF}")
    _box_row(f"    • {AWGS_KEYS_DIR}/")
    _box_row(f"    • {AWGS_STATE_FILE}")
    _box_row(f"    • cron-задачи")
    _box_row(f"    • UFW-правило (UDP {port})")
    if keep_backups and AWGS_BACKUP_DIR.exists():
        _box_row(f"  {YELLOW}Сохранено:{NC}")
        _box_row(f"    • {AWGS_BACKUP_DIR}/ (для возможного restore)")
        _box_row(f"    • {AWGS_LOG_FILE}")
    _box_row(f"  {DIM}Не удалено (может использоваться другими сервисами):{NC}")
    _box_row(f"    {DIM}• DKMS-модуль amnezia (apt remove amneziawg-dkms для удаления){NC}")
    _box_row(f"    {DIM}• Fail2Ban, sysctl, SSH hardening{NC}")
    _box_bottom()
    return True


def _awgs_uninstall_cleanup_iptables() -> None:
    """Best-effort удаление iptables-правил каскада."""
    core = _core_module()
    from .awg_constants import AWGS_CASCADE_FWMARK
    # Список правил для удаления (best-effort, игнорируем ошибки)
    rules = [
        ("iptables", "-t", "mangle", "-D", "OUTPUT", "-m", "set", "!",
         "--match-set", AWGS_IPSET_NAME, "dst", "-j", "MARK",
         "--set-mark", str(AWGS_CASCADE_FWMARK)),
        ("iptables", "-t", "mangle", "-D", "OUTPUT", "-m", "conntrack",
         "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"),
        ("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", "awg1", "-j", "MASQUERADE"),
        ("iptables", "-D", "FORWARD", "-i", "awg0", "-o", "awg1", "-j", "ACCEPT"),
        ("iptables", "-D", "FORWARD", "-i", "awg1", "-o", "awg0",
         "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"),
        ("iptables", "-D", "FORWARD", "-i", "awg0", "-m", "set",
         "--match-set", AWGS_IPSET_NAME, "dst", "-j", "ACCEPT"),
    ]
    for rule in rules:
        core._run(list(rule), check=False, quiet=True)
    # Policy routing
    core._run(["ip", "rule", "del", "fwmark", str(AWGS_CASCADE_FWMARK), "lookup", "2000"],
              check=False, quiet=True)
    core._run(["ip", "route", "del", "default", "table", "2000"],
              check=False, quiet=True)


# ── TUI-МЕНЮ ────────────────────────────────────────────────────────────────

def do_awg_uninstall_menu() -> None:
    """TUI-меню удаления."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    warn = core.warn
    info = core.info
    CYAN, NC, YELLOW, RED = core.CYAN, core.NC, core.YELLOW, core.RED

    print()
    _box_top(f"Удаление AmneziaWG 2.0 (standalone)")
    _box_row()
    _box_row(f"  {YELLOW}Внимание!{NC} Это удалит:")
    _box_row(f"    • Все клиенты и их конфиги")
    _box_row(f"    • Серверный конфиг awg0.conf")
    _box_row(f"    • Systemd-сервисы awg-quick@awg0 (и awg1 если каскад)")
    _box_row(f"    • State, cron-задачи, UFW-правила")
    _box_row()
    _box_row(f"  {CYAN}Не будет удалено:{NC}")
    _box_row(f"    • DKMS-модуль amnezia (apt remove amneziawg-dkms отдельно)")
    _box_row(f"    • Fail2Ban, sysctl, SSH hardening")
    _box_row(f"    • Backup'ы (можно удалить вручную или оставить для restore)")
    _box_bottom()

    if not awgs_state_is_installed():
        warn("Standalone AWG не установлен. Удалять нечего.")
        ch = input(f"{CYAN}Всё равно продолжить (для очистки осиротевших файлов)? [y/N]: {NC}").strip().lower()
        if ch not in ("y", "yes", "д", "да"):
            return
    else:
        ch = input(f"{RED}Точно удалить standalone AWG? [y/N]: {NC}").strip().lower()
        if ch not in ("y", "yes", "д", "да"):
            info("Отмена")
            return

    # Спрашиваем про backup'ы
    keep_ch = input(f"{CYAN}Сохранить backup'ы (для возможного restore)? [Y/n]: {NC}").strip().lower()
    keep_backups = keep_ch not in ("n", "no", "н", "нет")

    print()
    awgs_uninstall_full(keep_backups=keep_backups)
