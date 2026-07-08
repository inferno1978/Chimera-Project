"""
vless_installer/modules/ingress_geoip.py
───────────────────────────────────────────────────────────────────────────────
Блокировка входящих соединений из РФ через iptables/ipset.

  • Применяет через iptables/ip6tables: DROP входящих на SERVER_PORT из РФ подсетей
  • Использует ipset для эффективной фильтрации (hash:net)
  • Загружает актуальный список РФ подсетей из RIPE NCC
  • Поддерживает IPv4 и IPv6
  • Whitelist для SSH и управляющих IP
  • Cron для еженедельного обновления

Точка входа из _core.py:
    from vless_installer.modules.ingress_geoip import do_manage_ingress_geoip
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import textwrap
import time
import urllib.request as _ur2
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if __import__("sys").stdout.isatty():
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
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED    = _C['RED'];   GREEN  = _C['GREEN'];  YELLOW = _C['YELLOW']
CYAN   = _C['CYAN'];  BLUE   = _C['BLUE'];   BOLD   = _C['BOLD']
DIM    = _C['DIM'];   WHITE  = _C['WHITE'];  NC     = _C['NC']

# ── Логирование ────────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/vless-install.log")

def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime as _dt
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = _dt.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [{level}] {clean}\n")
    except Exception:
        pass

def info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");   _log("INFO",    msg)
def success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}");   _log("SUCCESS", msg)
def warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}");  _log("WARN",    msg)
def log_to_file(level: str, msg: str) -> None: _log(level, msg)

# ── Вспомогательные ───────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

# ── Константы ─────────────────────────────────────────────────────────────────
INGRESS_GEOIP_FILE  = Path("/var/lib/xray-installer/ingress_geoip.json")
INGRESS_IPSET_NAME  = "xray_ru_block"
INGRESS_IPSET6_NAME = "xray_ru_block6"
INGRESS_CRON_SCRIPT = Path("/usr/local/bin/xray-ingress-geoip-update.sh")
INGRESS_CRON_FILE   = Path("/etc/cron.d/xray-ingress-geoip")
INGRESS_LOG         = Path("/var/log/xray-ingress-geoip.log")

_STATE_FILE = Path("/var/lib/xray-installer/state.json")

# ── Telegram уведомление (no-op если недоступно) ───────────────────────────────
def _tg_notify_event(event: str, detail: str = "") -> None:
    try:
        import importlib
        _core = importlib.import_module("vless_installer._core")
        _core._tg_notify_event(event, detail)
    except Exception:
        pass

# ── Импорты из других модулей ─────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_back,
)
from vless_installer.modules.tui import tui_confirm
from vless_installer.modules.ipset_persist import ipset_save, ipset_restore_unit_install
from vless_installer.modules.ripe_file_age import check_ripe_file_age, ripe_file_age_banner


def _fetch_ru_subnets_ripe() -> list:
    """Загружает список РФ подсетей — делегирует в _core._fetch_ru_subnets_from_ripe."""
    try:
        import importlib
        _core = importlib.import_module("vless_installer._core")
        return _core._fetch_ru_subnets_from_ripe()
    except Exception as e:
        warn(f"Не удалось загрузить список РФ подсетей: {e}")
        return []

def _ingress_state_load() -> dict:
    try:
        if INGRESS_GEOIP_FILE.exists():
            return json.loads(INGRESS_GEOIP_FILE.read_text())
    except Exception:
        pass
    return {"enabled": False, "port": 0, "cidrs_v4": 0, "cidrs_v6": 0,
            "updated_at": "", "method": ""}


def _ingress_state_save(data: dict) -> None:
    INGRESS_GEOIP_FILE.parent.mkdir(parents=True, exist_ok=True)
    INGRESS_GEOIP_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    INGRESS_GEOIP_FILE.chmod(0o600)


def _ingress_ipset_available() -> bool:
    return bool(shutil.which("ipset"))


def _ingress_iptables_available() -> bool:
    return bool(shutil.which("iptables"))


def _ingress_get_cidrs() -> "tuple[list[str], list[str]]":
    """
    Возвращает (v4_cidrs, v6_cidrs).
    Источники приоритетов:
      1. /etc/xray/ru_subnets_ripe.txt (уже скачан split-tunnel модулем)
      2. Свежая загрузка через _fetch_ru_subnets_ripe()
    """
    ru_file = Path("/etc/xray/ru_subnets_ripe.txt")
    if ru_file.exists() and ru_file.stat().st_size > 1000:
        try:
            lines = [l.strip() for l in ru_file.read_text().splitlines()
                     if l.strip() and not l.startswith("#")]
            v4 = [l for l in lines if ":" not in l]
            v6 = [l for l in lines if ":" in l]
            if v4:
                info(f"Используем существующий файл РФ подсетей: {len(v4)} v4, {len(v6)} v6")
                return v4, v6
        except Exception:
            pass
    info("Загружаем РФ подсети с RIPE NCC...")
    all_cidrs = _fetch_ru_subnets_ripe()
    v4 = [c for c in all_cidrs if ":" not in c]
    v6 = [c for c in all_cidrs if ":" in c]
    return v4, v6


def _ingress_apply_ipset(port: int, v4: list, v6: list) -> bool:
    """
    Применяет блокировку через ipset (эффективно для 5000+ CIDR).
    Создаёт/обновляет set и добавляет одно правило iptables.
    """
    info(f"Применяю ipset блокировку ({len(v4)} IPv4 + {len(v6)} IPv6 CIDR)...")

    # ── IPv4 ──
    cmds_v4 = [
        ["ipset", "create", INGRESS_IPSET_NAME, "hash:net",
         "family", "inet", "maxelem", "500000", "-exist"],
        ["ipset", "flush",  INGRESS_IPSET_NAME],
    ]
    for cmd in cmds_v4:
        r = _run(cmd, check=False, quiet=True)
        if r.returncode != 0:
            warn(f"ipset error: {r.stderr.strip()}")
            return False

    # batch-добавление через временный файл restore
    restore_v4 = "\n".join(
        [f"add {INGRESS_IPSET_NAME} {cidr}" for cidr in v4]
    )
    tmp_v4 = Path("/tmp/xray_ingress_v4.ipset")
    tmp_v4.write_text(restore_v4)
    r = _run(["ipset", "restore", "-!", "-f", str(tmp_v4)], check=False, quiet=True)
    tmp_v4.unlink(missing_ok=True)
    if r.returncode != 0:
        warn(f"ipset restore v4 failed: {r.stderr.strip()[:200]}")

    # правило iptables: DROP входящих из ru_set на SERVER_PORT.
    # ВАЖНО: вставляем через -A (в конец), а не -I 1 (в начало).
    # Правила ESTABLISHED,RELATED и lo-ACCEPT должны стоять ВЫШЕ,
    # иначе уже установленные соединения клиентов будут обрываться.
    _run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
          "-m", "set", "--match-set", INGRESS_IPSET_NAME, "src", "-j", "DROP"],
         check=False, quiet=True)
    r = _run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port),
              "-m", "set", "--match-set", INGRESS_IPSET_NAME, "src",
              "-j", "DROP", "-m", "comment", "--comment", "xray-ru-ingress-block"],
             check=False, quiet=True)
    if r.returncode != 0:
        warn(f"iptables v4 rule error: {r.stderr.strip()}")
        return False
    success(f"IPv4: {len(v4)} CIDR → ipset {INGRESS_IPSET_NAME} → DROP :{port}")

    # ── IPv6 ──
    if v6:
        _run(["ipset", "create", INGRESS_IPSET6_NAME, "hash:net",
              "family", "inet6", "maxelem", "100000", "-exist"],
             check=False, quiet=True)
        _run(["ipset", "flush", INGRESS_IPSET6_NAME], check=False, quiet=True)
        restore_v6 = "\n".join(
            [f"add {INGRESS_IPSET6_NAME} {cidr}" for cidr in v6]
        )
        tmp_v6 = Path("/tmp/xray_ingress_v6.ipset")
        tmp_v6.write_text(restore_v6)
        _run(["ipset", "restore", "-!", "-f", str(tmp_v6)], check=False, quiet=True)
        tmp_v6.unlink(missing_ok=True)

        _run(["ip6tables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
              "-m", "set", "--match-set", INGRESS_IPSET6_NAME, "src", "-j", "DROP"],
             check=False, quiet=True)
        # Аналогично IPv4 — через -A, а не -I 1
        _run(["ip6tables", "-A", "INPUT", "-p", "tcp", "--dport", str(port),
              "-m", "set", "--match-set", INGRESS_IPSET6_NAME, "src",
              "-j", "DROP", "-m", "comment", "--comment", "xray-ru-ingress-block"],
             check=False, quiet=True)
        success(f"IPv6: {len(v6)} CIDR → ipset {INGRESS_IPSET6_NAME} → DROP :{port}")

    return True


def _ingress_apply_iptables_plain(port: int, v4: list) -> bool:
    """
    Fallback без ipset: добавляет отдельное правило на каждый CIDR.
    Медленно, но работает везде. Рекомендуется только при < 500 CIDR.
    """
    if len(v4) > 500:
        warn(f"Fallback-режим (без ipset): {len(v4)} правил — это медленно!")
        warn("Установите ipset: apt install ipset")

    info(f"Применяю iptables правила ({len(v4)} CIDR)...")
    # Удаляем старые правила с комментарием
    while True:
        r = _run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
                  "-m", "comment", "--comment", "xray-ru-ingress-block",
                  "-j", "DROP"], check=False, quiet=True)
        if r.returncode != 0:
            break

    # Создаём новую цепочку XRU для компактности
    _run(["iptables", "-N", "XRU_BLOCK"], check=False, quiet=True)
    _run(["iptables", "-F", "XRU_BLOCK"], check=False, quiet=True)
    for cidr in v4:
        _run(["iptables", "-A", "XRU_BLOCK", "-s", cidr, "-j", "DROP"],
             check=False, quiet=True)
    _run(["iptables", "-A", "XRU_BLOCK", "-j", "RETURN"], check=False, quiet=True)

    # Привязываем цепочку к INPUT через -A (в конец, НЕ -I 1).
    # Правила ESTABLISHED,RELATED и whitelist ACCEPT уже стоят выше —
    # вставка через -I 1 перекрыла бы их и порвала активные сессии.
    _run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
          "-j", "XRU_BLOCK"], check=False, quiet=True)
    r = _run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port),
              "-j", "XRU_BLOCK", "-m", "comment", "--comment", "xray-ru-ingress-block"],
             check=False, quiet=True)
    if r.returncode != 0:
        warn(f"Ошибка iptables: {r.stderr.strip()}")
        return False

    success(f"iptables plain: {len(v4)} правил → DROP :{port}")
    return True


def _ingress_remove() -> None:
    """Удаляет все правила блокировки входящих РФ, включая whitelist ACCEPT."""
    state = _ingress_state_load()
    port  = state.get("port", 0)
    meth  = state.get("method", "")

    # Сначала убираем ACCEPT-правила whitelist
    for _wip in state.get("whitelist", []):
        _ingress_whitelist_remove(_wip, port)

    if meth == "ipset":
        if port:
            _run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
                  "-m", "set", "--match-set", INGRESS_IPSET_NAME, "src", "-j", "DROP"],
                 check=False, quiet=True)
            _run(["ip6tables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
                  "-m", "set", "--match-set", INGRESS_IPSET6_NAME, "src", "-j", "DROP"],
                 check=False, quiet=True)
        _run(["ipset", "destroy", INGRESS_IPSET_NAME],  check=False, quiet=True)
        _run(["ipset", "destroy", INGRESS_IPSET6_NAME], check=False, quiet=True)
    elif meth == "plain" and port:
        _run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
              "-j", "XRU_BLOCK"], check=False, quiet=True)
        _run(["iptables", "-F", "XRU_BLOCK"], check=False, quiet=True)
        _run(["iptables", "-X", "XRU_BLOCK"], check=False, quiet=True)

    # ── Очищаем UFW deny-правила накопленные autoban/honeypot/dpi-detector ───
    # Пока geo-блокировка работала, эти модули могли добавлять ufw deny from <ip>
    # для РФ-адресов. При полном удалении блокировки чистим их тоже.
    _ingress_flush_autoban_ufw()

    _ingress_state_save({"enabled": False, "port": 0, "cidrs_v4": 0,
                          "cidrs_v6": 0, "updated_at": "", "method": "",
                          "whitelist": state.get("whitelist", [])})
    INGRESS_CRON_FILE.unlink(missing_ok=True)
    INGRESS_CRON_SCRIPT.unlink(missing_ok=True)
    success("Блокировка входящих РФ удалена")


def _ingress_flush_autoban_ufw() -> None:
    """
    Удаляет из UFW все deny-правила добавленные autoban/honeypot/dpi-detector.
    Вызывается при полном удалении geo-блокировки.
    Не трогает allow-правила (SSH, порты сервисов).
    """
    if not shutil.which("ufw"):
        return
    try:
        r = _run(["ufw", "status", "numbered"], capture=True, check=False)
        lines = r.stdout.splitlines()
        # Собираем номера правил DENY with autoban/honeypot/dpi comments
        # ufw numbered output: "[ N] DENY IN   anywhere   COMMENT"
        targets = []
        for line in lines:
            low = line.lower()
            if ("deny" in low and
                    any(tag in low for tag in (
                        "xray-autoban", "xray-dpi-detector", "honeypot",
                        "xray-ru-ingress"
                    ))):
                import re as _re2
                m = _re2.match(r'\s*\[\s*(\d+)\]', line)
                if m:
                    targets.append(int(m.group(1)))
        # Удаляем в обратном порядке (нумерация сдвигается после каждого удаления)
        for num in sorted(targets, reverse=True):
            _run(["ufw", "--force", "delete", str(num)], check=False, quiet=True)
        if targets:
            success(f"UFW: удалено {len(targets)} накопленных deny-правил (autoban/honeypot/dpi)")
        else:
            info("UFW: накопленных deny-правил не найдено")
    except Exception as e:
        warn(f"UFW очистка: {e}")


def _ingress_whitelist_apply(ip: str, port: int) -> None:
    """
    Добавляет правило ACCEPT для конкретного IP/CIDR — вставляет его
    перед DROP-правилом (позиция 1 в INPUT), чтобы whitelist работал
    для всех портов: SSH (22), порт Xray и любых других сервисов.
    Помечает правило комментарием xray-ru-wl для управления.
    """
    comment = f"xray-ru-wl-{ip.replace('/', '_')}"
    # Удаляем старое правило если было (idempotent)
    _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "ACCEPT",
          "-m", "comment", "--comment", comment],
         check=False, quiet=True)
    # Вставляем ACCEPT самым первым — до всех DROP
    _run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "ACCEPT",
          "-m", "comment", "--comment", comment],
         check=False, quiet=True)
    # IPv6 если это CIDR с двоеточием
    if ":" in ip:
        _run(["ip6tables", "-D", "INPUT", "-s", ip, "-j", "ACCEPT",
              "-m", "comment", "--comment", comment],
             check=False, quiet=True)
        _run(["ip6tables", "-I", "INPUT", "1", "-s", ip, "-j", "ACCEPT",
              "-m", "comment", "--comment", comment],
             check=False, quiet=True)


def _ingress_whitelist_remove(ip: str, port: int) -> None:
    """Удаляет ACCEPT-правило whitelist для IP/CIDR."""
    comment = f"xray-ru-wl-{ip.replace('/', '_')}"
    _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "ACCEPT",
          "-m", "comment", "--comment", comment],
         check=False, quiet=True)
    if ":" in ip:
        _run(["ip6tables", "-D", "INPUT", "-s", ip, "-j", "ACCEPT",
              "-m", "comment", "--comment", comment],
             check=False, quiet=True)


def _ingress_whitelist_apply_all(state: dict, port: int) -> None:
    """Применяет ACCEPT-правила для всех IP из whitelist в state."""
    for ip in state.get("whitelist", []):
        _ingress_whitelist_apply(ip, port)


def _ingress_enable(port: int) -> None:
    """Основной вызов: скачать CIDR, применить, сохранить состояние, поставить cron."""
    if not _ingress_iptables_available():
        warn("iptables не найден — невозможно применить правила")
        return

    # Проверяем возраст RIPE-файла перед apply
    if not check_ripe_file_age(interactive=True):
        return
    v4, v6 = _ingress_get_cidrs()
    if not v4:
        warn("Список РФ подсетей пуст — проверьте доступность RIPE NCC")
        return

    use_ipset = _ingress_ipset_available()
    if use_ipset:
        ok = _ingress_apply_ipset(port, v4, v6)
        method = "ipset"
        if ok:
            ipset_save()  # persist ipset для boot-restore
    else:
        warn("ipset не установлен — используем plain iptables (медленнее)")
        warn("Рекомендуется: apt install ipset")
        ok = _ingress_apply_iptables_plain(port, v4)
        method = "plain"

    if not ok:
        warn("Не удалось применить правила — проверьте лог")
        return

    # Применяем whitelist ACCEPT-правила (вставляются перед DROP)
    _state_for_wl = _ingress_state_load()
    _ingress_whitelist_apply_all(_state_for_wl, port)
    wl_count = len(_state_for_wl.get("whitelist", []))
    if wl_count:
        success(f"Whitelist: {wl_count} IP защищены (ACCEPT до DROP)")

    # Сохраняем состояние — whitelist ОБЯЗАТЕЛЬНО переносим из предыдущего state,
    # иначе при каждом enable/restore он обнуляется и ACCEPT-правила теряются
    _ingress_state_save({
        "enabled":    True,
        "port":       port,
        "cidrs_v4":   len(v4),
        "cidrs_v6":   len(v6),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "method":     method,
        "whitelist":  _state_for_wl.get("whitelist", []),
    })

    # Устанавливаем cron для автообновления (еженедельно по воскресеньям в 03:00)
    _ingress_install_cron(port)
    # Устанавливаем systemd-юнит восстановления ipset при reboot
    ipset_restore_unit_install()

    log_to_file("INFO",
        f"Ingress GeoIP block enabled: port={port}, "
        f"v4={len(v4)}, v6={len(v6)}, method={method}"
    )
    _tg_notify_event(
        "ingress_geoip",
        f"🛡 Блокировка входящих РФ <b>включена</b>: "
        f"порт {port}, {len(v4)} IPv4 CIDR, метод: {method}"
    )


def _ingress_install_cron(port: int) -> None:
    """Cron: еженедельное обновление списка РФ-подсетей и переприменение правил."""
    script = textwrap.dedent(f"""\
        #!/bin/bash
        # Xray Ingress GeoIP Block — weekly update (VLESS Installer)
        LOG="{INGRESS_LOG}"
        DATE=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$DATE] Ingress GeoIP update start" >> "$LOG"
        python3 {Path(__file__).resolve()} --ingress-geoip-update >> "$LOG" 2>&1
        echo "[$DATE] Ingress GeoIP update done (exit $?)" >> "$LOG"
    """)
    INGRESS_CRON_SCRIPT.write_text(script)
    INGRESS_CRON_SCRIPT.chmod(0o750)
    INGRESS_CRON_FILE.write_text(
        f"0 3 * * 0 root {INGRESS_CRON_SCRIPT} >> {INGRESS_LOG} 2>&1\n"
    )
    INGRESS_CRON_FILE.chmod(0o644)
    success(f"Cron обновления установлен: еженедельно вс 03:00 → {INGRESS_CRON_SCRIPT}")


def do_manage_ingress_geoip() -> None:
    """
    Меню: блокировка входящих подключений из РФ на уровне iptables.
    Предназначено для Режима B — Entry Node в РФ, пользователи за рубежом.
    """
    while True:
        os.system("clear")
        print()
        state = _ingress_state_load()
        enabled  = state.get("enabled", False)
        port     = state.get("port", 0)
        cidrs_v4 = state.get("cidrs_v4", 0)
        cidrs_v6 = state.get("cidrs_v6", 0)
        updated  = state.get("updated_at", "")[:16].replace("T", " ")
        method   = state.get("method", "—")
        cron_ok  = INGRESS_CRON_FILE.exists()

        # Читаем текущий порт из state.json если не задан
        cur_port = port
        if not cur_port and _STATE_FILE.exists():
            try:
                cur_port = json.loads(_STATE_FILE.read_text()).get("server_port", 443)
            except Exception:
                cur_port = 443

        ipset_ok = _ingress_ipset_available()

        _box_top("БЛОКИРОВКА ВХОДЯЩИХ ИЗ РФ (iptables)")
        _box_row()

        wl_ips = state.get("whitelist", [])

        if enabled:
            _box_row(f"  Статус:   {GREEN}ВКЛЮЧЕНО{NC}")
            _box_row(f"  Порт:     {CYAN}{port}{NC}")
            _box_row(f"  IPv4:     {CYAN}{cidrs_v4} CIDR{NC}")
            _box_row(f"  IPv6:     {CYAN}{cidrs_v6} CIDR{NC}")
            _box_row(f"  Метод:    {CYAN}{method}{NC}")
            _box_row(f"  Обновлено:{CYAN} {updated or '—'}{NC}")
            _box_row(f"  Cron:     "
                     f"{''+GREEN+'вс 03:00'+NC if cron_ok else ''+YELLOW+'отключён'+NC}")
            _box_row(f"  {ripe_file_age_banner()}")
        else:
            _box_row(f"  Статус:   {YELLOW}ОТКЛЮЧЕНО{NC}")
            _box_row(f"  Порт Entry Node: {CYAN}{cur_port}{NC}")
            _box_row()
            _box_row(f"  {DIM}Блокирует входящие TCP на порт Xray с российских IP.{NC}")
            _box_row(f"  {DIM}РФ-подсети RIPE NCC (тот же список что split-tunnel).{NC}")
            _box_row(f"  {DIM}Режим B: Entry Node в РФ, пользователи за рубежом.{NC}")

        _box_sep()
        _box_row(f"  ipset: {''+GREEN+'доступен'+NC if ipset_ok else ''+YELLOW+'НЕТ (apt install ipset)'+NC}")
        # Whitelist — показываем всегда
        if wl_ips:
            _box_row(f"  {BOLD}Whitelist (всегда разрешены — SSH/управление):{NC}")
            for _wip in wl_ips:
                _box_row(f"    {GREEN}✓{NC} {_wip}")
        else:
            _box_row(f"  {YELLOW}Whitelist пуст{NC} — добавьте ваш IP управления!")
        _box_sep()

        if enabled:
            _box_item("1", "Обновить список РФ подсетей и переприменить")
            _box_item("2", f"{RED}Отключить блокировку (удалить правила){NC}")
        else:
            _box_item("1", f"{GREEN}Включить блокировку входящих из РФ{NC}")

        _box_item("3", "Проверить текущие правила iptables")
        _box_item("4", f"Управление whitelist {DIM}(ваш IP, SSH-источники){NC}")
        _box_item("5", f"🧹 Очистить накопленные UFW deny (autoban/honeypot/dpi)")
        _box_row()
        _box_row(f"  {YELLOW}⚠{NC} {DIM}Добавьте свой IP в whitelist перед включением!{NC}")
        _box_row(f"  {DIM}  Иначе потеряете SSH если ваш провайдер — РФ.{NC}")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch == "1":
            if enabled:
                # Обновить
                print()
                info("Обновляю список РФ-подсетей и переприменяю правила...")
                _ingress_remove()
                _ingress_enable(cur_port if not port else port)
                input(f"{BLUE}Нажмите Enter...{NC}")
            else:
                # Включить — сначала проверяем/предлагаем добавить whitelist
                print()
                _box_top("Включение блокировки входящих из РФ")
                _box_row()
                _box_row(
                    f"  {YELLOW}ПРЕДУПРЕЖДЕНИЕ:{NC} После включения IP-адреса из РФ"
                )
                _box_row(f"  не смогут подключиться на порт {CYAN}{cur_port}{NC}.")
                _box_row()
                if wl_ips:
                    _box_row(f"  {GREEN}Whitelist:{NC}")
                    for _wip in wl_ips:
                        _box_row(f"    {GREEN}✓{NC} {_wip}  {DIM}(будет разрешён){NC}")
                else:
                    _box_row(f"  {RED}Whitelist пуст!{NC}")
                    _box_row(f"  {DIM}Если вы управляете сервером с РФ-IP —{NC}")
                    _box_row(f"  {DIM}вы потеряете SSH доступ!{NC}")
                    _box_row()
                    _box_row(f"  {DIM}Рекомендуется сначала добавить ваш IP (пункт 4).{NC}")
                _box_row()
                _box_bottom()
                print()
                if tui_confirm("Применить блокировку?", default=False):
                    _ingress_enable(cur_port)
                input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2" and enabled:
            print()
            if tui_confirm("Удалить все правила блокировки входящих из РФ?", default=False):
                _ingress_remove()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            print()
            _box_top("Текущие правила iptables (INPUT)")
            _box_row()
            r = _run(["iptables", "-L", "INPUT", "-n", "--line-numbers"],
                     check=False, capture=True)
            for line in r.stdout.splitlines():
                if "xray-ru-ingress" in line or "XRU_BLOCK" in line \
                   or line.startswith("num") or line.startswith("Chain"):
                    _box_row(f"  {line}")
            if ipset_ok:
                _box_row()
                r2 = _run(["ipset", "list", INGRESS_IPSET_NAME,
                            "-t"],  # только заголовок, без 5000 IP
                           check=False, capture=True)
                for line in r2.stdout.splitlines():
                    _box_row(f"  {line}")
            _box_row()
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "4":
            # Управление whitelist
            print()
            _box_top("Whitelist — разрешённые IP (SSH / управление)")
            _box_row(f"  {DIM}IP из этого списка всегда пропускаются — до правил блокировки.{NC}")
            _box_row(f"  {DIM}Добавьте сюда ваш IP провайдера чтобы не потерять SSH.{NC}")
            _box_sep()
            if wl_ips:
                for i, _wip in enumerate(wl_ips, 1):
                    _box_item(str(i), f"{GREEN}{_wip}{NC}")
            else:
                _box_row(f"  {DIM}Список пуст{NC}")
            _box_sep()
            _box_item("+", "Добавить IP")
            _box_item("-", "Удалить IP")
            _box_item("D", f"Определить мой текущий IP автоматически")
            _box_bottom()
            wl_act = input("  Действие [+/-/D/Enter]: ").strip().lower()

            if wl_act == "d":
                # Автоопределение внешнего IP
                _my_ip = ""
                for _url in ("https://api.ipify.org", "https://ifconfig.me/ip",
                             "https://icanhazip.com"):
                    try:
                        import urllib.request as _ur2
                        with _ur2.urlopen(_url, timeout=5) as _r2:
                            _my_ip = _r2.read().decode().strip()
                        if _my_ip:
                            break
                    except Exception:
                        continue
                if _my_ip:
                    print()
                    print(f"  {GREEN}Ваш внешний IP:{NC} {CYAN}{_my_ip}{NC}")
                    if tui_confirm(f"Добавить {_my_ip} в whitelist?", default=True):
                        wl_act = "+"
                        _prefill_ip = _my_ip
                    else:
                        _prefill_ip = ""
                else:
                    warn("Не удалось определить внешний IP — введите вручную")
                    wl_act = "+"
                    _prefill_ip = ""
            else:
                _prefill_ip = ""

            if wl_act == "+":
                new_ip = _prefill_ip or input("  IP или CIDR для whitelist: ").strip()
                if new_ip and new_ip not in wl_ips:
                    wl_ips.append(new_ip)
                    state["whitelist"] = wl_ips
                    _ingress_state_save(state)
                    success(f"Добавлен: {new_ip}")
                    # Если блокировка уже включена — сразу применяем ACCEPT правило
                    if enabled:
                        _ingress_whitelist_apply(new_ip, port)
                        success(f"ACCEPT правило для {new_ip} применено немедленно")
                elif new_ip in wl_ips:
                    warn(f"{new_ip} уже в whitelist")

            elif wl_act == "-":
                if not wl_ips:
                    warn("Список пуст")
                else:
                    raw_n = input("  Номер для удаления: ").strip()
                    if raw_n.isdigit() and 1 <= int(raw_n) <= len(wl_ips):
                        removed_ip = wl_ips.pop(int(raw_n) - 1)
                        state["whitelist"] = wl_ips
                        _ingress_state_save(state)
                        success(f"Удалён: {removed_ip}")
                        # Если блокировка включена — убираем ACCEPT правило
                        if enabled:
                            _ingress_whitelist_remove(removed_ip, port)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            print()
            info("Очищаю накопленные UFW deny-правила (autoban/honeypot/dpi-detector)...")
            _ingress_flush_autoban_ufw()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


# =============================================================================
#  МОДУЛЬ 11: КАСТОМНЫЕ DNS ПРАВИЛА (Xray hosts + DNSCrypt static)
#
#  Позволяет задать:
#    • domain → IP(s)   через секцию hosts{} в Xray config
#    • domain → outbound через dns-routing правила (domain → direct/proxy)
#    • Просмотр текущих hosts и dns-правил
#    • Совместимость с DNSCrypt-proxy (blocked-names.txt)
# dns_rules — перенесено в vless_installer/modules/dns_rules.py
# honeypot — перенесено в vless_installer/modules/honeypot.py
# =============================================================================

