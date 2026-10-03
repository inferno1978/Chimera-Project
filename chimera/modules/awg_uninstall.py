"""
chimera/modules/awg_uninstall.py
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

import json
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
    return importlib.import_module("chimera._core")


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

    from .awg_state import awgs_state_get_protocol_version
    from .awg_protocol import awg_protocol_label
    _box_top(f"Удаление {awg_protocol_label(awgs_state_get_protocol_version())} (standalone)")
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
        # Каскад: останавливаем awg1 + routing + failover-таймер (v5.5.3)
        core._run(["systemctl", "stop", "awg-quick@awg1"],
                  check=False, quiet=True)
        core._run(["systemctl", "disable", "awg-quick@awg1"],
                  check=False, quiet=True)
        core._run(["systemctl", "stop", "awg-cascade-routing"],
                  check=False, quiet=True)
        core._run(["systemctl", "disable", "awg-cascade-routing"],
                  check=False, quiet=True)
        # v5.5.3: мульти-exit failover (таймер + сервис + wrapper)
        from .awg_cascade import awgs_cascade_failover_teardown
        awgs_cascade_failover_teardown()
    # NAT-юнит (если создавался при установке)
    core._run(["systemctl", "stop", "awg-nat.service"],
              check=False, quiet=True)
    core._run(["systemctl", "disable", "awg-nat.service"],
              check=False, quiet=True)

    # 2. Удаляем systemd-юниты
    info("Удаление systemd-юнитов...")
    core._run(["systemctl", "disable", AWGS_SYSTEMD_AWG_QUICK],
              check=False, quiet=True)
    # awg-nat.service
    awg_nat_unit = Path("/etc/systemd/system/awg-nat.service")
    awg_nat_unit.unlink(missing_ok=True)
    if AWGS_SYSTEMD_CASCADE.exists():
        AWGS_SYSTEMD_CASCADE.unlink(missing_ok=True)
    # v5.5.3: failover-юниты (на случай запуска uninstall без cascade_role)
    for _u in ("/etc/systemd/system/awg-cascade-failover.timer",
               "/etc/systemd/system/awg-cascade-failover.service"):
        Path(_u).unlink(missing_ok=True)
    Path("/usr/local/sbin/awg-cascade-failover.sh").unlink(missing_ok=True)
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

    # 8. UFW-правило ( через port_registry с legacy comment backward compat)
    info(f"Удаление UFW-правила для UDP {port}...")
    _awg_uninstall_ufw_close(core, port)

    # 8.1 NAT iptables правила (если создавались при установке)
    info("Удаление iptables NAT правил...")
    subnet = state.get("subnet", "10.66.66.0/24")
    # v5.4.5: MASQUERADE ставится С "-o <WAN>" (build_nat_idempotent_shell),
    # поэтому -D обязан включать тот же "-o <WAN>" — иначе iptables молча
    # НЕ матчит правило и MASQUERADE переживает uninstall (подтверждено
    # E2E 2026-10-03 на de1: правило -s 10.66.66.0/24 -o ens3 осталось).
    # Используем тот же cleanup-сниппет, что и PostDown в awg0.conf —
    # гарантирует симметрию установка/удаление (MASQ + оба FORWARD).
    from .awg_net_common import build_nat_cleanup_shell
    cleanup_cmd = (
        "WAN=$(ip route show default | awk '{print $5; exit}'); "
        + build_nat_cleanup_shell(subnet, AWGS_INTERFACE, "$WAN")
    )
    core._run(["bash", "-c", cleanup_cmd], check=False, quiet=True)
    # Fallback: продетектить WAN и повторить (если ip route упал в момент uninstall)
    wan_iface = ""
    try:
        wan_iface = core._run(
            ["bash", "-c", "ip route show default | awk '{print $5; exit}'"],
            capture=True, check=False).stdout.strip()
    except Exception:
        pass
    if wan_iface:
        core._run(
            ["iptables", "-t", "nat", "-D", "POSTROUTING",
             "-s", subnet, "-o", wan_iface, "-j", "MASQUERADE"],
            check=False, quiet=True,
        )
        core._run(
            ["iptables", "-D", "FORWARD", "-i", AWGS_INTERFACE, "-j", "ACCEPT"],
            check=False, quiet=True,
        )
        core._run(
            ["iptables", "-D", "FORWARD", "-o", AWGS_INTERFACE, "-m", "state",
             "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            check=False, quiet=True,
        )

    # 8.2 v5.4.5: артефакты, которые раньше переживали uninstall
    # (подтверждено E2E 2026-10-03 на de1: wrapper, PPA sources+keyring, sysctl)
    info("Удаление wrapper-скриптов и PPA...")
    # helper NAT-скрипт (создаётся awgs_setup_nat_and_routing с v5.4.5)
    Path("/usr/local/sbin/awg-nat-rules.sh").unlink(missing_ok=True)
    # wrapper cron-задачи expires (создаётся awgs_setup_expires_cron)
    Path("/usr/local/sbin/awg-expires-check.sh").unlink(missing_ok=True)
    # PPA amnezia (обе вариации имени: DEB822 .sources и legacy .list)
    for ppa_file in ("/etc/apt/sources.list.d/amnezia-ppa.sources",
                     "/etc/apt/sources.list.d/amnezia-ppa.list",
                     "/etc/apt/keyrings/amnezia-ppa.gpg"):
        Path(ppa_file).unlink(missing_ok=True)

    # 8.3 sysctl-конфиг: ip_forward может использоваться chain Mode B —
    # если активен режим B с AWG-exit, сохраняем ip_forward=1 (файл
    # переписываем минимально), иначе удаляем файл целиком.
    try:
        sysctl_file = Path("/etc/sysctl.d/99-awg-standalone.conf")
        if sysctl_file.exists():
            chain_active = False
            try:
                main_state = json.loads(
                    Path("/var/lib/xray-installer/state.json").read_text())
                chain_active = (
                    main_state.get("install_mode") == "B"
                    and bool(main_state.get("awg_exit_enabled"))
                )
            except Exception:
                chain_active = False
            if chain_active:
                sysctl_file.write_text(
                    "# v5.4.5: сохранён ip_forward для chain Mode B "
                    "(awg_exit_enabled)\nnet.ipv4.ip_forward = 1\n")
                info("sysctl ip_forward сохранён (используется chain Mode B)")
            else:
                sysctl_file.unlink(missing_ok=True)
                # вернуть runtime ip_forward=0 не можем безопасно —
                # другие сервисы могли включить его сами; файл удалён,
                # после reboot вернётся системное значение
    except Exception:
        pass

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
            # v5.4.5: пустую keys/ тоже убираем (после удаления файлов
            # директория-призрак оставалась — E2E de1)
            if AWGS_KEYS_DIR.exists() and not any(AWGS_KEYS_DIR.iterdir()):
                AWGS_KEYS_DIR.rmdir()
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
    success("Удаление AmneziaWG завершено!")
    print()
    _box_top(f"Готово")
    _box_row(f"  {GREEN}Удалено:{NC}")
    _box_row(f"    • awg-quick@awg0.service (stop + disable)")
    if is_cascade:
        _box_row(f"    • awg-quick@awg1.service")
        _box_row(f"    • awg-cascade-routing.service")
        _box_row(f"    • awg-cascade-failover.timer/.service (v5.5.3)")
        _box_row(f"    • ipset {AWGS_IPSET_NAME}")
        _box_row(f"    • {AWGS_CASCADE_DIR}/")
    _box_row(f"    • {AWGS_SERVER_CONF}")
    _box_row(f"    • {AWGS_KEYS_DIR}/")
    _box_row(f"    • {AWGS_STATE_FILE}")
    _box_row(f"    • cron-задачи")
    _box_row(f"    • UFW-правило (UDP {port})")
    _box_row(f"    • NAT iptables (MASQUERADE -o WAN + FORWARD)")
    _box_row(f"    • wrapper-скрипты (/usr/local/sbin/awg-*)")
    _box_row(f"    • PPA amnezia (sources + keyring)")
    _box_row(f"    • sysctl 99-awg-standalone.conf (ip_forward если не chain Mode B)")
    if keep_backups and AWGS_BACKUP_DIR.exists():
        _box_row(f"  {YELLOW}Сохранено:{NC}")
        _box_row(f"    • {AWGS_BACKUP_DIR}/ (для возможного restore)")
        _box_row(f"    • {AWGS_LOG_FILE}")
    _box_row(f"  {DIM}Не удалено (может использоваться другими сервисами):{NC}")
    _box_row(f"    {DIM}• DKMS-модуль amnezia (apt remove amneziawg-dkms для удаления){NC}")
    _box_row(f"    {DIM}• Пакеты amneziawg-tools/wireguard-tools/qrencode{NC}")
    _box_row(f"    {DIM}• Fail2Ban, SSH hardening{NC}")
    _box_bottom()
    return True


def _awgs_uninstall_cleanup_iptables() -> None:
    """Best-effort удаление iptables-правил каскада.

    v5.4.5:
      • MARK теперь в PREROUTING (главный фикс каскада) — удаляем его;
        старые FORWARD/OUTPUT-варианты тоже подчищаем (эволюция бага).
      • Добавлены TCPMSS-правила (двойное туннелирование).
      • Правила удаляются ЦИКЛИЧЕСКИ (дубли от старых прогонов —
        E2E: после нескольких setup висело по 2-3 копии).
    """
    core = _core_module()
    from .awg_constants import AWGS_CASCADE_FWMARK
    # Список правил для удаления (best-effort, игнорируем ошибки).
    # Эволюция MARK-правила: OUTPUT (SSH-lockout, 33970c2) → FORWARD
    # (после route decision — транзит не работал) → PREROUTING (v5.4.5).
    rules = [
        # Текущее: PREROUTING-MARK (v5.4.5)
        ("iptables", "-t", "mangle", "-D", "PREROUTING", "-i", "awg0",
         "-m", "set", "!", "--match-set", AWGS_IPSET_NAME, "dst",
         "-j", "MARK", "--set-mark", str(AWGS_CASCADE_FWMARK)),
        # Легаси: FORWARD-MARK (промежуточная версия)
        ("iptables", "-t", "mangle", "-D", "FORWARD", "-i", "awg0",
         "-m", "set", "!", "--match-set", AWGS_IPSET_NAME, "dst",
         "-j", "MARK", "--set-mark", str(AWGS_CASCADE_FWMARK)),
        # Легаси: OUTPUT-MARK (изначальная версия, SSH-lockout)
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
        # v5.4.5: TCPMSS clamp
        ("iptables", "-t", "mangle", "-D", "FORWARD", "-i", "awg0", "-o", "awg1",
         "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS",
         "--set-mss", "1140"),
        ("iptables", "-t", "mangle", "-D", "FORWARD", "-i", "awg1", "-o", "awg0",
         "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS",
         "--set-mss", "1140"),
    ]
    # Циклическое удаление — убирает ВСЕ копии (дубли от старых прогонов)
    for rule in rules:
        for _ in range(10):
            r = core._run(list(rule), check=False, quiet=True)
            if r.returncode != 0:
                break
    # Policy routing — тоже циклом (дубли fwmark-правил)
    for _ in range(10):
        r = core._run(["ip", "rule", "del", "fwmark", str(AWGS_CASCADE_FWMARK),
                       "lookup", "2000"], check=False, quiet=True)
        if r.returncode != 0:
            break
    core._run(["ip", "route", "del", "default", "table", "2000"],
              check=False, quiet=True)
    core._run(["ip", "route", "del", "172.16.61.0/24", "dev", "awg1", "table", "2000"],
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
    from .awg_state import awgs_state_get_protocol_version
    from .awg_protocol import awg_protocol_label
    _box_top(f"Удаление {awg_protocol_label(awgs_state_get_protocol_version())} (standalone)")
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


#  helper для закрытия UFW-порта AWG через port_registry
# с backward compat для legacy comment "AWG standalone".
def _awg_uninstall_ufw_close(core, port: int) -> None:
    """Закрывает UDP-порт AWG в UFW.

    Сначала через port_registry (новый style с chimera-awg_standalone),
    затем fallback на прямой ufw delete (для старых правил без comment).
    """
    try:
        from chimera.modules.port_registry import (
            ufw_close_port, port_unregister, SERVICE_AWG_STANDALONE,
        )
        ufw_close_port(port, "udp", SERVICE_AWG_STANDALONE,
                       legacy_comments=["AWG standalone"])
        port_unregister(SERVICE_AWG_STANDALONE, port, "udp")
    except Exception:
        pass
    # Fallback: прямой ufw delete для правил без comment.
    core._run(["ufw", "delete", "allow", f"{port}/udp"],
              check=False, quiet=True)
