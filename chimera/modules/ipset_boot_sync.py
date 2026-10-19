"""
ipset_boot_sync.py — бут-восстановление ipset-определений до iptables-restore.

Проблема (живой кейс окт.2026 №10, RU-нода, первый ребут за 50 дней):
telemt-iptables.service (Before=network-pre.target) восстанавливает
/etc/iptables/rules.v4/v6 в самом начале загрузки, но дамп ссылается на
ipset-ы (--match-set / --add-set: awg_ru_networks, clients_wl_*, xray_ru_block,
xray_manual_ban, xray_knocked, mieru_b4_direct), которые создаются их
владельцами ПОЗЖЕ:
  • xray-ipset-restore.service — After=network-pre (позже telemt-iptables);
  • awg-routing.sh — после network.target;
  • clients-wl cron — до +5 минут (а после ребута сеты не существуют вовсе);
  • xray_knocked(6)/clients_wl(4/6) — при буте не воссоздавал никто.
iptables-restore умирает на первом же --match-set («Set … doesn't exist») →
юнит failed, дамп НЕ применяется: теряются port-knopping :443, clients-wl
ACCEPT, awg-цепочки, telemt-syn-limit, Telegram-DC REDIRECT, awg_lb6 (v6).

Решение: рядом с дампом правил держим /etc/iptables/ipset-boot.conf —
`ipset save` ВСЕХ сетов, на которые ссылается дамп. telemt-iptables.service
восстанавливает его ПЕРВЫМ ExecStart (`ipset restore -! -f` — идемпотентно:
существующие сеты не пересоздаются, дубликаты элементов игнорируются,
владельцы сетов позже наполняют их по-своему). rc.local (fallback-рестор)
получает ту же guard-строку перед iptables-restore (port_hopping).

Синхронизация вызывается из persist-точек (mtproto/proto_common/
port_knocking/port_hopping) — после каждого сохранения rules.v4/v6
boot-файл соответствует последнему дампу. Заменяет собой legacy-механику
port_knocking (аппенд в /etc/iptables/ipsets — файл никто не читал при
загрузке, а повторные аппенды дублировали create-строки).

Модуль намеренно не зависит от остального chimera (только stdlib) — его
безопасно лениво импортировать из любого места.

Публичный API:
    sync_ipset_boot_conf()    — собрать и записать ipset-boot.conf
    restore_ipset_boot_conf() — восстановить (ручной запуск/тесты)
    IPSET_RESTORE_CMD_SHELL   — canonical guard-строка для юнитов/rc.local
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

# ── Константы ─────────────────────────────────────────────────────────────────
IPSET_BOOT_CONF = Path("/etc/iptables/ipset-boot.conf")
RULES_V4 = Path("/etc/iptables/rules.v4")
RULES_V6 = Path("/etc/iptables/rules.v6")

# Guard-строка для ExecStart=/bin/sh -c '…' (telemt-iptables) и rc.local:
# файл существует и непуст → восстановить; иначе — молча пропустить.
IPSET_RESTORE_CMD_SHELL = (
    "test -s /etc/iptables/ipset-boot.conf && "
    "ipset restore -! -f /etc/iptables/ipset-boot.conf || true"
)

# Ссылки на сеты в выводе iptables-save:
#   -m set --match-set NAME src / -j SET --add-set NAME src / --del/--query-set
_SET_REF_RE = re.compile(r"--(?:match|add|del|query)-set\s+([A-Za-z0-9_.\-]+)")


# ── Внутренние ─────────────────────────────────────────────────────────────────
def _run(cmd: list, timeout: int = 300) -> subprocess.CompletedProcess:
    """Единая точка запуска (для моков в тестах)."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _ipset_available() -> bool:
    return shutil.which("ipset") is not None


# ── Публичный API ─────────────────────────────────────────────────────────────
def collect_referenced_sets(*rules_files) -> "list[str]":
    """Имена сетов, на которые ссылаются файлы дампа (уникальные, sorted).

    Args:
        *rules_files: пути (str/Path) к rules.v4/rules.v6; отсутствующие
            файлы молча пропускаются.
    """
    names: set = set()
    for rf in rules_files:
        p = Path(rf)
        try:
            if not p.exists():
                continue
            names.update(_SET_REF_RE.findall(p.read_text()))
        except OSError:
            continue
    return sorted(names)


def sync_ipset_boot_conf(rules_v4=None, rules_v6=None) -> "tuple[bool, str]":
    """Собрать и записать ipset-boot.conf по set-ссылкам дампа правил.

    Best-effort: нет ipset-бинарника → (False, …); нет set-ссылок →
    устаревший boot-файл удаляется (восстанавливать нечего); сет из
    ссылок не существует в ядре — пропускаем (свежий дамп таких ссылок
    не содержит: iptables-save выводит только живые правила).

    Returns:
        (ok, msg) — ok=True если файл записан (или корректно не нужен).
    """
    if not _ipset_available():
        return False, "ipset не установлен — синхронизация пропущена"
    v4 = Path(rules_v4) if rules_v4 else RULES_V4
    v6 = Path(rules_v6) if rules_v6 else RULES_V6
    refs = collect_referenced_sets(v4, v6)
    if not refs:
        IPSET_BOOT_CONF.unlink(missing_ok=True)
        return True, "set-ссылок в rules.v4/v6 нет — ipset-boot.conf не нужен"
    parts: list = []
    saved: list = []
    for name in refs:
        try:
            r = _run(["ipset", "save", name], timeout=120)
        except Exception:
            continue
        if r.returncode == 0 and r.stdout.strip():
            parts.append(r.stdout.strip() + "\n")
            saved.append(name)
    if not saved:
        return False, f"ни один из сетов не сохранён ({', '.join(refs)})"
    tmp = IPSET_BOOT_CONF.with_name(IPSET_BOOT_CONF.name + ".tmp")
    try:
        tmp.write_text("".join(parts))
        tmp.replace(IPSET_BOOT_CONF)
    except OSError as e:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False, f"не удалось записать {IPSET_BOOT_CONF}: {e}"
    return True, f"ipset-boot.conf: {len(saved)} сет(ов) ({', '.join(saved)})"


def restore_ipset_boot_conf() -> bool:
    """Восстановить сеты из ipset-boot.conf (идемпотентно, -! = force).

    Для ручного запуска и тестов; при загрузке то же самое делает
    telemt-iptables.service первым ExecStart.
    """
    if not IPSET_BOOT_CONF.exists():
        return False
    try:
        r = _run(["ipset", "restore", "-!", "-f", str(IPSET_BOOT_CONF)])
    except Exception:
        return False
    return r.returncode == 0
