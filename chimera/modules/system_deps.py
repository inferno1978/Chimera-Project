"""
chimera/modules/system_deps.py
───────────────────────────────────────────────────────────────────────────────
Менеджер системных пакетов и стартовая установка зависимостей (Tier-3).

7 функций + 2 постоянных словаря, вынесенные из _core.py:

  • _init_pkg_mgr()               — определение apt/dnf, мутация core.PKG_MGR
  • _pkg_install(*pkgs)           — обёртка над apt-get install / dnf install
  • _pkg_update()                 — apt-get update / dnf check-update
  • _find_pkg_for_missing_cmd(c)  — поиск пакета по имени отсутствующей команды
  • _smart_recover(exc)           — обработка FileNotFoundError: предложить
                                     и установить недостающий пакет
  • _wait_apt_lock_startup()      — ожидание снятия apt-блокировки на старте
  • ensure_startup_dependencies() — единая установка всех системных зависимостей
                                     (bootstrap + sys + nginx + certbot + optional)

Постоянные словари (модульные константы, НЕ биндятся к core):
  • _CMD_TO_PKG  — карта «команда → (apt_pkg, dnf_pkg)»
  • _PKG_TO_CMDS — обратная карта «пакет → [команды]» (для сообщений)

PKG_MGR — это глобал _core.py (см. _core.PKG_MGR: str = "").
_init_pkg_mgr() мутирует его через setattr(core, "PKG_MGR", ...).
Остальные функции читают через getattr(core, "PKG_MGR", "apt").

Точки входа из _core.py:
    from chimera.modules.system_deps import (
        _CMD_TO_PKG, _PKG_TO_CMDS,
        _init_pkg_mgr, _pkg_install, _pkg_update,
        _find_pkg_for_missing_cmd, _smart_recover,
        _wait_apt_lock_startup, ensure_startup_dependencies,
    )

Доступ к helpers ядра (_run, _box_*, info/warn/success/dim, colors,
log_to_file, command_exists, find_nginx_bin, die, datetime, PROGRESS) —
через importlib (lazy binding), как и в других извлечённых модулях
(standalone_screens.py, asn_cache.py и т.д.).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль chimera._core, импортируя его лениво.

    При запуске через cron (python -c 'from ... import ...') модуль ещё не
    загружен — importlib полноценно его импортирует. При вызове из
    интерактивного инсталлятора модуль уже в sys.modules — это просто lookup.
    """
    import importlib
    return importlib.import_module("chimera._core")


# =============================================================================
#  КАРТА КОМАНДА → APT/DNF ПАКЕТ  (используется умным обработчиком ошибок)
# =============================================================================
# Ключ  — имя исполняемого файла, который скрипт вызывает через subprocess.
# Значение — (apt_pkg, dnf_pkg) или просто строка если имя совпадает.
_CMD_TO_PKG: dict[str, tuple[str, str]] = {
    # bootstrap
    "fuser":           ("psmisc",          "psmisc"),
    "killall":         ("psmisc",          "psmisc"),
    "gpg":             ("gnupg",           "gnupg2"),
    "gpg2":            ("gnupg",           "gnupg2"),
    "lsb_release":     ("lsb-release",     "redhat-lsb-core"),
    "modprobe":        ("kmod",            "kmod"),
    # сеть / загрузка
    "curl":            ("curl",            "curl"),
    "wget":            ("wget",            "wget"),
    "unzip":           ("unzip",           "unzip"),
    "tar":             ("tar",             "tar"),
    # криптография / идентификаторы
    "openssl":         ("openssl",         "openssl"),
    "uuidgen":         ("uuid-runtime",    "util-linux"),
    "sha256sum":       ("coreutils",       "coreutils"),
    # системные утилиты
    "timeout":         ("coreutils",       "coreutils"),
    "date":            ("coreutils",       "coreutils"),
    "df":              ("coreutils",       "coreutils"),
    "uname":           ("coreutils",       "coreutils"),
    "id":              ("coreutils",       "coreutils"),
    "tail":            ("coreutils",       "coreutils"),
    "ip":              ("iproute2",        "iproute"),
    "ss":              ("iproute2",        "iproute"),
    "tc":              ("iproute2",        "iproute"),
    "sysctl":          ("procps",          "procps-ng"),
    "pgrep":           ("procps",          "procps-ng"),
    "free":            ("procps",          "procps-ng"),
    "hostname":        ("hostname",        "hostname"),
    "file":            ("file",            "file"),
    "useradd":         ("passwd",          "shadow-utils"),
    "journalctl":      ("systemd",         "systemd"),
    # сеть / файрволл
    "ufw":             ("ufw",             "ufw"),
    "iptables":        ("iptables",        "iptables"),
    "ip6tables":       ("iptables",        "iptables"),
    "iptables-save":   ("iptables",        "iptables"),
    "ip6tables-save":  ("iptables",        "iptables"),
    "ipset":           ("ipset",           "ipset"),
    "ping6":           ("iputils-ping",    "iputils"),
    # DNS
    "dig":             ("dnsutils",        "bind-utils"),
    "nslookup":        ("dnsutils",        "bind-utils"),
    # cron / логи
    "crontab":         ("cron",            "cronie"),
    "logrotate":       ("logrotate",       "logrotate"),
    # мониторинг
    "htop":            ("htop",            "htop"),
    "jq":              ("jq",              "jq"),
    "zstd":            ("zstd",            "zstd"),
    "irqbalance":      ("irqbalance",      "irqbalance"),
    # SSH
    "sshd":            ("openssh-server",  "openssh-server"),
    # QR
    "qrencode":        ("qrencode",        "qrencode"),
}

# Обратный маппинг: пакет → список команд (для сообщений пользователю)
_PKG_TO_CMDS: dict[str, list[str]] = {}
for _c, (_a, _d) in _CMD_TO_PKG.items():
    _PKG_TO_CMDS.setdefault(_a, []).append(_c)


def _init_pkg_mgr() -> None:
    """Определяет пакетный менеджер (apt/dnf) и сохраняет его в core.PKG_MGR."""
    core = _core_module()
    command_exists = core.command_exists
    die = core.die
    if command_exists("apt-get"):
        setattr(core, "PKG_MGR", "apt")
    elif command_exists("dnf"):
        setattr(core, "PKG_MGR", "dnf")
    else:
        die("Поддерживаются только apt / dnf системы")


def _pkg_install(*pkgs: str) -> None:
    """Устанавливает пакеты через apt-get install / dnf install."""
    core = _core_module()
    _run = core._run
    PKG_MGR = getattr(core, "PKG_MGR", "apt")
    if PKG_MGR == "apt":
        _run(["apt-get", "install", "-y", "-q", *pkgs],
             env={"DEBIAN_FRONTEND": "noninteractive"}, check=False, quiet=True)
    else:
        _run(["dnf", "install", "-y", "-q", *pkgs], check=False, quiet=True)


def _pkg_update() -> None:
    """Обновляет индекс пакетов: apt-get update / dnf check-update."""
    core = _core_module()
    _run = core._run
    PKG_MGR = getattr(core, "PKG_MGR", "apt")
    if PKG_MGR == "apt":
        _run(["apt-get", "update", "-q"], check=False, quiet=True)
    else:
        _run(["dnf", "check-update", "-q"], check=False, quiet=True)


def _find_pkg_for_missing_cmd(cmd: str) -> tuple[str, str] | None:
    """
    По имени команды возвращает (apt_pkg, dnf_pkg) или None если неизвестна.
    Также пробует dpkg-query / dnf provides как fallback.
    """
    if cmd in _CMD_TO_PKG:
        return _CMD_TO_PKG[cmd]
    # Fallback: спросить пакетный менеджер
    core = _core_module()
    _run = core._run
    PKG_MGR = getattr(core, "PKG_MGR", "apt")
    if PKG_MGR == "apt" and shutil.which("apt-file"):
        r = _run(["apt-file", "search", f"bin/{cmd}"], capture=True, check=False)
        if r.stdout:
            first = r.stdout.splitlines()[0].split(":")[0].strip()
            if first:
                return (first, first)
    return None


def _smart_recover(exc: FileNotFoundError) -> bool:
    """
    Вызывается при перехвате FileNotFoundError.
    Определяет отсутствующую команду, находит нужный пакет,
    спрашивает пользователя (или устанавливает автоматически),
    возвращает True если пакет установлен и можно попробовать повторить.
    """
    import traceback as _tb

    core = _core_module()
    info = core.info
    warn = core.warn
    success = core.success
    _run = core._run
    log_to_file = core.log_to_file
    PKG_MGR = getattr(core, "PKG_MGR", "apt")
    RED    = core.RED
    BOLD   = core.BOLD
    NC     = core.NC
    YELLOW = core.YELLOW
    CYAN   = core.CYAN
    DIM    = core.DIM
    WHITE  = core.WHITE

    # Извлекаем имя команды из исключения
    missing_cmd = ""
    if exc.filename:
        missing_cmd = os.path.basename(str(exc.filename))
    elif exc.args:
        m = re.search(r"'([^']+)'", str(exc.args))
        if m:
            missing_cmd = os.path.basename(m.group(1))

    tb_str = _tb.format_exc()

    # ── СУЖЕНИЕ ОБЛАСТИ СРАБАТЫВАНИЯ APT-GET ВЕТКИ ────────────────────────────
    # FileNotFoundError кидается не только при отсутствии системной команды,
    # но и при попытке прочитать/записать несуществующий файл (например,
    # shutil.copy2 в несуществующую поддиректорию). В этом случае missing_cmd
    # — это имя ФАЙЛА (telemt.toml, server.json, ...), а не команда.
    # Предлагать "apt-get install telemt.toml" — бессмысленно и сбивает с толку.
    #
    # Эвристика: если missing_cmd не входит в _CMD_TO_PKG (справочник известных
    # системных команд) И имеет расширение, не характерное для исполняемых
    # файлов — считаем это файловой ошибкой, а не отсутствием пакета.
    _FILE_EXT_HINTS = (
        ".toml", ".json", ".txt", ".service", ".crt", ".key",
        ".yaml", ".yml", ".pem", ".conf", ".cfg", ".ini", ".env",
        ".sock", ".socket", ".log", ".db", ".sqlite",
    )
    _looks_like_file = (
        missing_cmd
        and missing_cmd not in _CMD_TO_PKG
        and any(missing_cmd.lower().endswith(ext) for ext in _FILE_EXT_HINTS)
    )
    if _looks_like_file:
        # Это FileNotFoundError по ФАЙЛУ, а не по команде. Не предлагаем
        # apt-get install — это не поможет и только запутает пользователя.
        print()
        print(f"{RED}{'═'*64}{NC}")
        print(f"{RED}  💥 ОШИБКА ФАЙЛОВОЙ СИСТЕМЫ: {BOLD}{missing_cmd}{NC}")
        print(f"{RED}{'═'*64}{NC}")
        print(f"{DIM}  Файл или директория не найдены — это не связано с "
              f"отсутствующим системным пакетом.{NC}")
        print()
        print(f"{DIM}  Трассировка:{NC}")
        for line in tb_str.strip().splitlines()[-6:]:
            print(f"  {DIM}{line}{NC}")
        print()
        log_to_file("ERROR",
                    f"FileNotFoundError (file-system): '{missing_cmd}' "
                    f"(not a known system command, no apt-get recovery)")
        log_to_file("ERROR", tb_str)
        return False

    # ── СТАНДАРТНАЯ ВЕТКА: похоже на отсутствующую системную команду ──────────
    print()
    print(f"{RED}{'═'*64}{NC}")
    print(f"{RED}  💥 КОМАНДА НЕ НАЙДЕНА: {BOLD}{missing_cmd or '?'}{NC}")
    print(f"{RED}{'═'*64}{NC}")

    pkg_info = _find_pkg_for_missing_cmd(missing_cmd) if missing_cmd else None
    apt_pkg  = pkg_info[0] if pkg_info else None
    dnf_pkg  = pkg_info[1] if pkg_info else None
    install_pkg = apt_pkg if PKG_MGR == "apt" else dnf_pkg

    if install_pkg:
        print(f"{YELLOW}  Пакет для установки:{NC} {CYAN}{install_pkg}{NC}")
    else:
        print(f"{YELLOW}  Пакет для '{missing_cmd}' неизвестен.{NC}")
        print(f"{DIM}  Попробуйте: apt-get install -y $(apt-file search bin/{missing_cmd} | head -1 | cut -d: -f1){NC}")

    print()
    print(f"{DIM}  Трассировка:{NC}")
    for line in tb_str.strip().splitlines()[-6:]:
        print(f"  {DIM}{line}{NC}")
    print()
    log_to_file("ERROR", f"FileNotFoundError: команда '{missing_cmd}', пакет '{install_pkg}'")
    log_to_file("ERROR", tb_str)

    if not install_pkg:
        return False

    # Предлагаем авто-установку
    print(f"{YELLOW}  Что делать?{NC}")
    print(f"  {DIM}[{NC}{WHITE}{BOLD}A{NC}{DIM}]{NC}  Установить {CYAN}{install_pkg}{NC} автоматически")
    print(f"  {DIM}[{NC}{WHITE}{BOLD}S{NC}{DIM}]{NC}  Пропустить (продолжить без этого пакета)")
    print(f"  {DIM}[{NC}{RED}{BOLD}Q{NC}{DIM}]{NC}  Выйти из скрипта")
    print()
    try:
        choice = input(f"{CYAN}  Выбор [A/S/Q]:{NC} ").strip().upper()
    except (KeyboardInterrupt, EOFError):
        print()
        return False

    if choice == "Q":
        print(f"{YELLOW}Выход.{NC}")
        sys.exit(1)
    elif choice == "S":
        warn(f"Пропускаем установку {install_pkg} — скрипт продолжает работу")
        return False
    else:
        # Авто-установка
        print()
        info(f"Устанавливаю {install_pkg}...")
        try:
            if PKG_MGR == "apt":
                _run(["apt-get", "install", "-y", "-q", install_pkg],
                     env={"DEBIAN_FRONTEND": "noninteractive"}, check=False, quiet=True)
            else:
                _run(["dnf", "install", "-y", "-q", install_pkg], check=False, quiet=True)
            if shutil.which(missing_cmd) or _run(
                    ["dpkg", "-l", install_pkg], capture=True, check=False
               ).stdout and any(
                    l.startswith("ii") for l in _run(
                        ["dpkg", "-l", install_pkg], capture=True, check=False
                    ).stdout.splitlines()):
                success(f"{install_pkg} установлен успешно")
                return True
            else:
                warn(f"Пакет {install_pkg} установлен, но команда '{missing_cmd}' всё ещё не найдена")
                return False
        except Exception as e2:
            warn(f"Не удалось установить {install_pkg}: {e2}")
            return False


def _wait_apt_lock_startup() -> None:
    """
    Ожидание снятия блокировки apt (используется при стартовой проверке).
    Безопасно работает даже если fuser (psmisc) ещё не установлен:
    в этом случае проверяет блокировку через /proc напрямую.
    """
    core = _core_module()
    info = core.info
    warn = core.warn
    _run = core._run
    PKG_MGR = getattr(core, "PKG_MGR", "apt")

    if PKG_MGR != "apt":
        return

    import glob as _glob

    def _lock_held() -> bool:
        lock = "/var/lib/dpkg/lock-frontend"
        if shutil.which("fuser"):
            r = _run(["fuser", lock], capture=True, check=False)
            return r.returncode == 0
        # Fallback без fuser: смотрим /proc/*/fd/*
        try:
            lock_real = os.path.realpath(lock)
            for fd_path in _glob.glob("/proc/*/fd/*"):
                try:
                    if os.path.realpath(fd_path) == lock_real:
                        return True
                except (OSError, PermissionError):
                    pass
        except Exception:
            pass
        return False

    waited = 0
    while _lock_held():
        if waited == 0:
            warn("apt заблокирован — ждём освобождения...")
        time.sleep(2)
        waited += 2
        if waited >= 60:
            warn("apt lock не освободился за 60с — продолжаем")
            return
    if waited > 0:
        info(f"apt lock освобождён ({waited}с)")


def ensure_startup_dependencies() -> None:
    """
    Проверка и установка ВСЕХ зависимостей, необходимых для работы скрипта
    и устанавливаемого им ПО. Вызывается единожды при старте, ДО любых операций.

    Сюда вынесены все пакеты/модули, которые ранее могли устанавливаться
    разбросанно по ходу скрипта (в install_dependencies, отдельных шагах и т.д.).

    Перед фактической установкой пользователю показывается полный список
    пакетов и запрашивается подтверждение (один раз — согласие сохраняется
    в /var/lib/xray-installer/.deps_consent, чтобы retry-попытки после сбоя
    не спрашивали повторно).
    """
    core = _core_module()
    info            = core.info
    warn            = core.warn
    success         = core.success
    _run            = core._run
    command_exists  = core.command_exists
    find_nginx_bin  = core.find_nginx_bin
    log_to_file     = core.log_to_file
    die             = core.die
    datetime        = core.datetime
    PROGRESS        = getattr(core, "PROGRESS", None)   # noqa: F841 (singleton)
    BOLD            = core.BOLD
    CYAN            = core.CYAN
    NC              = core.NC
    DIM             = core.DIM
    YELLOW          = core.YELLOW
    PKG_MGR         = getattr(core, "PKG_MGR", "apt")

    # ── Живой прогресс-бар ───────────────────────────────────────────────────
    # Единый бар на всю функцию. Фазы и их веса (в условных "единицах"):
    #   [apt-update]   5   [bootstrap]  5   [sys-pkgs] 50
    #   [nginx]        10  [certbot]   10   [optional] 15  [checks] 5  = 100
    _BAR_W    = 40          # ширина заполняемой части
    _TOTAL_W  = 100         # 100 условных единиц = 100%
    _progress = [0]         # текущий вес
    _cur_pkg  = [""]        # имя текущего пакета/этапа

    def _bar_draw(force_pct: int | None = None) -> None:
        pct    = force_pct if force_pct is not None else int(_progress[0] / _TOTAL_W * 100)
        pct    = min(pct, 100)
        filled = int(_BAR_W * pct / 100)
        bar    = f"\033[96m{'█' * filled}\033[2;96m{'░' * (_BAR_W - filled)}\033[0m"
        label  = _cur_pkg[0][:28].ljust(28)
        line   = (f"  \033[96m[\033[0m{bar}\033[96m]\033[0m"
                  f" \033[1;96m{pct:3d}%\033[0m  \033[2m{label}\033[0m")
        sys.stdout.write(f"\r{line:<90}")
        sys.stdout.flush()

    def _bar_advance(weight: int, label: str = "") -> None:
        if label:
            _cur_pkg[0] = label
        _progress[0] = min(_progress[0] + weight, _TOTAL_W)
        _bar_draw()

    def _bar_set_label(label: str) -> None:
        _cur_pkg[0] = label
        _bar_draw()

    def _is_pkg(pkg: str) -> bool:
        if command_exists(pkg):
            return True
        if PKG_MGR == "apt":
            r = _run(["dpkg", "-l", pkg], capture=True, check=False)
            return any(line.startswith("ii")
                       for line in (r.stdout or "").splitlines())
        else:
            r = _run(["rpm", "-q", pkg], capture=True, check=False)
            return r.returncode == 0

    # ── Экран подтверждения зависимостей (один раз за установку) ────────────
    _consent_flag = Path("/var/lib/xray-installer/.deps_consent")
    if not _consent_flag.exists():
        _all_pkgs_apt = (
            ["psmisc", "gnupg", "lsb-release", "kmod"] +
            ["curl", "wget", "unzip", "tar", "openssl", "uuid-runtime",
             "coreutils", "iproute2", "procps", "jq",
             "ufw", "dnsutils", "zstd", "htop",
             "ipset", "iptables",
             "logrotate", "hostname", "iputils-ping",
             "cron", "file", "openssh-server", "passwd",
             "git", "make", "golang-go"] +
            ["nginx", "certbot", "python3-certbot-nginx"] +
            ["fail2ban", "qrencode", "python3-pip",
             "irqbalance", "unattended-upgrades"]
        )
        _all_pkgs_dnf = (
            ["psmisc", "gnupg2", "redhat-lsb-core", "kmod"] +
            ["curl", "wget", "unzip", "tar", "openssl", "util-linux",
             "coreutils", "iproute", "procps-ng", "jq",
             "ipset", "iptables",
             "logrotate", "hostname", "iputils",
             "cronie", "file", "openssh-server", "shadow-utils",
             "git", "make", "golang"] +
            ["nginx", "certbot", "python3-certbot-nginx"] +
            ["fail2ban", "qrencode", "python3-pip", "irqbalance"]
        )
        _all_pkgs = _all_pkgs_apt if PKG_MGR == "apt" else _all_pkgs_dnf
        # Уже установленные пакеты не показываем отдельно от тех, что
        # будут ставиться — используем ту же _is_pkg(), что и сама установка.
        _already    = [p for p in _all_pkgs if _is_pkg(p)]
        _to_install = [p for p in _all_pkgs if not _is_pkg(p)]

        print()
        print(f"  {BOLD}{CYAN}Перед началом установки скрипт поставит следующие зависимости:{NC}")
        print()
        if _to_install:
            for i in range(0, len(_to_install), 4):
                row = _to_install[i:i+4]
                print("    " + "  ".join(f"{DIM}•{NC} {p}" for p in row))
        else:
            print(f"    {DIM}все необходимые пакеты уже установлены{NC}")
        print()
        if _already:
            print(f"  {DIM}Уже установлены и не будут переустанавливаться: "
                  f"{', '.join(_already)}{NC}")
            print()
        print(f"  {YELLOW}Среди них есть пакеты, включающие системные службы "
              f"(fail2ban, irqbalance,{NC}")
        print(f"  {YELLOW}unattended-upgrades) — они нужны для работы защиты fail2ban, "
              f"автообновлений{NC}")
        print(f"  {YELLOW}безопасности и балансировки прерываний между ядрами CPU.{NC}")
        print()

        _answer = input(f"  {BOLD}Продолжить установку зависимостей? [Y/n]: {NC}").strip().lower()
        if _answer in ("n", "no", "н", "нет"):
            print()
            info("Установка отменена пользователем. Зависимости не установлены.")
            info("Запустите скрипт повторно, когда будете готовы продолжить.")
            sys.exit(0)

        try:
            _consent_flag.parent.mkdir(parents=True, exist_ok=True)
            _consent_flag.write_text(datetime.now().isoformat())
        except Exception:
            pass
        print()

    # Печатаем заголовок и пустую строку для бара
    info("Проверка и установка зависимостей скрипта...")
    sys.stdout.write("\n")
    sys.stdout.flush()
    _bar_draw()

    # ── 1. Обновляем индекс пакетов ──────────────────────────────────────────
    _bar_set_label("apt-get update...")
    _wait_apt_lock_startup()
    _pkg_update()
    _wait_apt_lock_startup()
    _bar_advance(5, "индекс пакетов обновлён")

    # ── 2. Bootstrap-пакеты ──────────────────────────────────────────────────
    bootstrap_apt = ["psmisc", "gnupg", "lsb-release", "kmod"]
    bootstrap_dnf = ["psmisc", "gnupg2", "redhat-lsb-core", "kmod"]
    boot_pkgs    = bootstrap_apt if PKG_MGR == "apt" else bootstrap_dnf
    boot_missing = [p for p in boot_pkgs if not _is_pkg(p)]
    if boot_missing:
        for pkg in boot_missing:
            _bar_set_label(f"bootstrap: {pkg}")
            _pkg_install(pkg)
    _bar_advance(5, "bootstrap OK")
    _wait_apt_lock_startup()

    # ── 3. Системные пакеты (основная волна) ─────────────────────────────────
    sys_apt = [
        "curl", "wget", "unzip", "tar", "openssl", "uuid-runtime",
        "coreutils", "iproute2", "procps", "jq",
        "ufw", "dnsutils", "zstd", "htop",
        "ipset", "iptables",
        "logrotate", "hostname", "iputils-ping",
        "cron", "file", "openssh-server", "passwd",
        "git", "make", "golang-go",
    ]
    sys_dnf = [
        "curl", "wget", "unzip", "tar", "openssl", "util-linux",
        "coreutils", "iproute", "procps-ng", "jq",
        "ipset", "iptables",
        "logrotate", "hostname", "iputils",
        "cronie", "file", "openssh-server", "shadow-utils",
        "git", "make", "golang",
    ]
    pkgs        = sys_apt if PKG_MGR == "apt" else sys_dnf
    missing_sys = [p for p in pkgs if not _is_pkg(p)]

    if missing_sys:
        total_sys = len(missing_sys)
        _bar_set_label(f"системные пакеты (0/{total_sys})")
        _wait_apt_lock_startup()

        import subprocess as _sp_deps
        cmd_deps = (
            ["apt-get", "install", "-y", "--no-install-recommends", *missing_sys]
            if PKG_MGR == "apt"
            else ["dnf", "install", "-y", *missing_sys]
        )
        env_deps = {**os.environ,
                    "DEBIAN_FRONTEND": "noninteractive",
                    "LANGUAGE": "C", "LC_ALL": "C", "LANG": "C"}

        _sys_done  = [0]
        _sys_total = total_sys
        # вес волны B = 50 единиц
        _SYS_WEIGHT = 50

        proc_deps = _sp_deps.Popen(
            cmd_deps,
            stdout=_sp_deps.PIPE, stderr=_sp_deps.STDOUT,
            text=True, env=env_deps, bufsize=1,
        )
        for _line in proc_deps.stdout:  # type: ignore[union-attr]
            _line = _line.rstrip()
            _pkg = ""
            if _line.startswith("Unpacking "):
                _parts = _line.split()
                _pkg = _parts[1].split(":")[0] if len(_parts) >= 2 else ""
            elif _line.startswith("Setting up "):
                _parts = _line.split()
                _pkg = _parts[2].split(":")[0] if len(_parts) >= 3 else ""
                if _pkg in missing_sys:
                    _sys_done[0] += 1
                    _progress[0] = 10 + int(_sys_done[0] / _sys_total * _SYS_WEIGHT)
            elif _line.startswith("E:") or _line.startswith("Err:"):
                log_to_file("WARN", f"apt: {_line}")
                continue
            else:
                continue
            if _pkg:
                _cur_pkg[0] = f"{_pkg} ({_sys_done[0]}/{_sys_total})"
            _bar_draw()

        proc_deps.wait()

        _progress[0] = 10 + _SYS_WEIGHT   # = 60
        _cur_pkg[0]  = f"пакеты ({total_sys}/{total_sys})"
        _bar_draw()

        if proc_deps.returncode != 0:
            warn(f"\napt-get завершился с кодом {proc_deps.returncode} — часть пакетов могла не установиться")
        # success без newline — бар ещё не завершён
    else:
        _progress[0] = 60
        _cur_pkg[0]  = "системные пакеты: уже установлены"
        _bar_draw()

    # ── 4. nginx ──────────────────────────────────────────────────────────────
    nginx_ok = find_nginx_bin() is not None
    if not nginx_ok:
        _bar_set_label("nginx: установка...")
        _wait_apt_lock_startup()
        if PKG_MGR == "apt":
            r = _run(["apt-get", "install", "-y", "-q", "nginx"],
                     env={"DEBIAN_FRONTEND": "noninteractive"},
                     capture=True, check=False)
            if "E:" in (r.stderr or ""):
                _bar_set_label("nginx: исправление зависимостей...")
                _run(["apt-get", "install", "-f", "-y", "-q"],
                     env={"DEBIAN_FRONTEND": "noninteractive"},
                     check=False, quiet=True)
                _pkg_install("nginx")
        else:
            _pkg_install("nginx")
        nginx_ok = find_nginx_bin() is not None
        if not nginx_ok and PKG_MGR == "apt":
            _bar_set_label("nginx: официальный репозиторий...")
            try:
                r = _run(["lsb_release", "-cs"], capture=True, check=False)
                codename = r.stdout.strip() or "focal"
            except Exception:
                codename = "focal"
            _run(["curl", "-fsSL", "https://nginx.org/keys/nginx_signing.key",
                  "-o", "/tmp/nginx_key.gpg"], check=False, quiet=True)
            _run(["gpg", "--dearmor", "-o",
                  "/usr/share/keyrings/nginx-archive-keyring.gpg",
                  "/tmp/nginx_key.gpg"], check=False, quiet=True)
            Path("/etc/apt/sources.list.d/nginx.list").write_text(
                f"deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] "
                f"http://nginx.org/packages/ubuntu {codename} nginx\n"
            )
            _run(["apt-get", "update", "-q"], check=False, quiet=True)
            _pkg_install("nginx")
    _bar_advance(10, "nginx OK")

    # Чиним битый симлинк /usr/local/bin/nginx
    nginx_lbin = Path("/usr/local/bin/nginx")
    _real_nginx = find_nginx_bin()
    if _real_nginx and Path(_real_nginx) != nginx_lbin:
        try:
            if nginx_lbin.is_symlink() and not nginx_lbin.exists():
                nginx_lbin.unlink()
            if not nginx_lbin.exists():
                nginx_lbin.symlink_to(_real_nginx)
        except Exception:
            pass

    # ── 5. certbot ────────────────────────────────────────────────────────────
    certbot_ok = (command_exists("certbot")
                  or Path("/usr/bin/certbot").exists()
                  or Path("/snap/bin/certbot").exists())
    if not certbot_ok:
        _bar_set_label("certbot: установка...")
        _wait_apt_lock_startup()
        if PKG_MGR == "apt":
            _run(["apt-get", "install", "-y", "-q", "certbot", "python3-certbot-nginx"],
                 env={"DEBIAN_FRONTEND": "noninteractive"},
                 check=False, quiet=True)
        else:
            _pkg_install("certbot", "python3-certbot-nginx")
        certbot_ok = (command_exists("certbot")
                      or Path("/usr/bin/certbot").exists()
                      or Path("/snap/bin/certbot").exists())
        if not certbot_ok and command_exists("snap"):
            _bar_set_label("certbot: snap fallback...")
            _run(["timeout", "60", "snap", "install", "--classic", "certbot"],
                 check=False, quiet=True)
            snap_bin = Path("/snap/bin/certbot")
            usr_bin  = Path("/usr/bin/certbot")
            if snap_bin.exists() and not usr_bin.exists():
                try:
                    usr_bin.symlink_to(snap_bin)
                except Exception:
                    pass
    _bar_advance(10, "certbot OK")

    # ── 6. Опциональные пакеты ────────────────────────────────────────────────
    opt_apt = ["fail2ban", "qrencode", "python3-pip",
               "irqbalance", "unattended-upgrades"]
    opt_dnf = ["fail2ban", "qrencode", "python3-pip", "irqbalance"]
    opt_list = opt_apt if PKG_MGR == "apt" else opt_dnf
    for _i, pkg in enumerate(opt_list):
        if not _is_pkg(pkg):
            _bar_set_label(f"опц: {pkg} ({_i+1}/{len(opt_list)})")
            _pkg_install(pkg)
    _bar_advance(10, "опциональные пакеты OK")

    if PKG_MGR == "apt":
        _run(["systemctl", "enable", "--now", "unattended-upgrades"],
             check=False, quiet=True)

    # fail2ban — повторная попытка если не поднялся
    if not command_exists("fail2ban-server"):
        _bar_set_label("fail2ban: повторная попытка...")
        _wait_apt_lock_startup()
        _pkg_install("fail2ban")

    # qrencode — fallback через python3-qrcode
    if not command_exists("qrencode"):
        _bar_set_label("qrencode: pip fallback...")
        for pip_cmd in (["pip3"], ["python3", "-m", "pip"]):
            if command_exists(pip_cmd[0]):
                _run([*pip_cmd, "install", "--break-system-packages",
                      "--quiet", "qrcode[pil]"], check=False, quiet=True)
                break

    # ── 7. Python stdlib ──────────────────────────────────────────────────────
    try:
        import unicodedata  # noqa: F401
    except ImportError:
        warn("\nМодуль unicodedata недоступен — отрисовка меню может быть нарушена")

    # ── 8. Финальная проверка критичных зависимостей ──────────────────────────
    _bar_advance(5, "финальная проверка...")
    critical_missing: list[str] = []
    if not find_nginx_bin():
        critical_missing.append("nginx")
    if not (command_exists("certbot") or Path("/usr/bin/certbot").exists()
            or Path("/snap/bin/certbot").exists()):
        critical_missing.append("certbot")
    for cmd in ("curl", "openssl", "jq"):
        if not (command_exists(cmd) or Path(f"/usr/bin/{cmd}").exists()):
            critical_missing.append(cmd)

    if critical_missing:
        _bar_draw(force_pct=100)
        sys.stdout.write("\n\n")
        sys.stdout.flush()
        print(file=sys.stderr)
        print(f"\033[31m[ERROR]\033[0m Не удалось установить: {' '.join(critical_missing)}",
              file=sys.stderr)
        print(f"\033[33m[HINT]\033[0m  Попробуйте вручную:", file=sys.stderr)
        for pkg in critical_missing:
            print(f"         apt-get install -y {pkg}", file=sys.stderr)
        log_to_file("ERROR",
                    f"Стартовая проверка: недоступны {' '.join(critical_missing)}")
        die("Запуск прерван: критичные зависимости отсутствуют.")

    # Завершаем бар на 100% и переходим на новую строку
    _bar_draw(force_pct=100)
    sys.stdout.write("\n\n")
    sys.stdout.flush()

    success("Все зависимости проверены и готовы к работе")
