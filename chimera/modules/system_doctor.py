"""
chimera/modules/system_doctor.py
───────────────────────────────────────────────────────────────────────────────
System Doctor — медосмотр ОС-уровня ноды + БЕЗОПАСНЫЕ авто-фиксы по расписанию.

Контекст (живой кейс окт.2026 №13, флот-аудит 5 exit-нод + 2 RU-entry):
одинаковые «хронические болячки» всплывали на каждой ноде независимо —
битый rc.local от vless-installer, фантомный netplan-конфиг с enp1s0
(→ systemd-networkd-wait-online таймаутит 2 мин на каждом буте → xray
стартует с задержкой), uncapped journald (4.0G на NL, 1.2G на DE),
crash-loop hysteria-server (207865 рестартов, лог 342MB), лог-файлы,
которые сервис-юзер не может писать (dnscrypt на DE), 30-50 накопившихся
apt-апдейтов без unattended-upgrades, pingtunnel-логи по 16MB/день в /root.
Всё это — класс «гигиена ОС», которого нет ни в health.py (Xray/Nginx/SSL/
порты), ни в emergency_repair.py (восстановление стека после сбоя),
ни в steal_monitor (оверселл CPU). Этот модуль закрывает класс целиком:
детект + кастомизируемый авто-фикс, идемпотентный и безопасный по дизайнy.

Принципы безопасности:
  • разделение check/fix: каждый пункт независимо выключается
    (checks.<id>.check / checks.<id>.fix в конфиге);
  • опасные фиксы (apt full-upgrade, purge ядер, отключение сервисов,
    unattended-upgrades) по умолчанию ВЫКЛЮЧЕНЫ — только по явному
    согласию владельца; sshd/ufw/xray-сервис НИКОГДА не правятся —
    только аудит-отчёт;
  • каждое изменение файла — с бэкапом в /var/backups/system-doctor/;
  • dry-run показывает команды/записи без применения;
  • всё идемпотентно: повторный проход по уже здоровой ноде = no-op.

Состав (23 пункта, группы: journal/logs, boot/units, apt/kernel,
services, security-audit, fleet):
  journald_cap, big_logs, logrotate_coverage, unit_log_perms,
  failed_units, rc_local, phantom_netplan, crash_loops,
  apt_cache, old_kernels, updates_pending, reboot_flag, unattended,
  timesync, fail2ban, disk_usage,
  xray_version, cert_expiry, steal_snapshot, tunnels,
  ssh_audit, ufw_audit, dns_check

Режимы (main.py --system-doctor [--fix] [--only id,id] [--dry-run]
[--install] / TUI «Диагностика → SD» / cron /etc/cron.d/system-doctor):
  check — только сверка, отчёт в консоль/лог (+TG при критичных);
  fix    — check + авто-фиксы разрешённых пунктов, сводка применённого
           уходит в TG (событие doctor_fixed).

Файлы:
  /var/lib/xray-installer/system-doctor.json        — конфиг (тумблеры)
  /var/lib/xray-installer/system-doctor-last.json   — последний отчёт
  /var/log/system-doctor.log                        — журнал
  /var/backups/system-doctor/<TS>/<name>            — бэкапы правок
  /etc/cron.d/system-doctor                         — cron (день, 05:40)
  /usr/local/bin/system-doctor.sh                   — cron-обёртка

Публичный API:
    run_once(mode, only, dry_run) → dict  — один проход (check/fix)
    load_cfg() / save_cfg()       → dict/None
    is_installed()                → bool
    install_system_doctor(cfg)    → (bool, str)
    uninstall_system_doctor()     → (bool, str)
    do_system_doctor_menu()       → None  — TUI-меню

Чистые функции (тестируются без сервера): parse_rc_local_issues,
parse_netplan_ifaces, classify_reboot_required, parse_nrestarts,
parse_unit_log_rules, parse_journal_usage_mb, parse_kernel_pkgs,
parse_listening_ports, parse_ufw_allowed, extract_cert_paths,
parse_xray_version, human_mb, merge_cfg, build_logrotate_stanza.
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

# ── Пути ──────────────────────────────────────────────────────────────────────
BASE_DIR      = Path("/var/lib/xray-installer")
CONFIG_FILE   = BASE_DIR / "system-doctor.json"
LAST_FILE     = BASE_DIR / "system-doctor-last.json"
TG_BOT_CFG    = BASE_DIR / "tg_bot.json"
LOG_FILE      = Path("/var/log/system-doctor.log")
BACKUP_ROOT   = Path("/var/backups/system-doctor")
CRON_FILE     = Path("/etc/cron.d/system-doctor")
CRON_SCRIPT   = Path("/usr/local/bin/system-doctor.sh")
JOURNALD_DROPIN = Path("/etc/systemd/journald.conf.d/90-chimera-doctor.conf")
LOGROTATE_FILE  = Path("/etc/logrotate.d/chimera-doctor")
XRAY_CFG_CANDIDATES = (Path("/etc/xray/config.json"),
                       Path("/usr/local/etc/xray/config.json"))

# ── Каталог проверок ──────────────────────────────────────────────────────────
# danger: 1 = безопасно менять самому, 2 = менять можно, но это политика
# владельца, 3 = менять нельзя без владельца (только отчёт).
CHECK_CATALOG: dict = {
    # id: (заголовок, danger, fixable, def_check, def_fix, описание)
    "journald_cap": ("Кэп journald", 1, True, True, True,
                     "SystemMaxUse + vacuum: журнал не должен съедать ГБ"),
    "big_logs": ("Раздутые лог-файлы", 1, True, True, True,
                 "файлы >N MB вне logrotate: gzip-копия + truncate"),
    "logrotate_coverage": ("Логи без logrotate", 1, True, True, True,
                           "известные логи chimera/fleet: drop-in ротации"),
    "unit_log_perms": ("Права на логи юнитов", 1, True, True, True,
                       "StandardOutput=append: файл должен принадлежать User= юнита"),
    "failed_units": ("Failed-юниты", 1, True, True, True,
                     "systemctl --failed: reset-failed после разбора"),
    "rc_local": ("Битый /etc/rc.local", 1, True, True, True,
                 "редиректы в несуществующие файлы: закомментировать строку"),
    "phantom_netplan": ("Фантомные netplan-конфиги", 1, True, True, True,
                        "yaml ссылается на несуществующие NIC → карантин файла"),
    "crash_loops": ("Crash-loop сервисы", 2, True, True, False,
                    "NRestarts > порога: отчёт; disable только по allowlist"),
    "apt_cache": ("Кэш apt", 1, True, True, True,
                  "/var/cache/apt: apt-get clean"),
    "old_kernels": ("Старые ядра", 2, True, True, False,
                    "ядра сверх running+keep: purge (по умолчанию выкл)"),
    "updates_pending": ("Накопившиеся апдейты", 2, True, True, False,
                        "apt upgradable/security: отчёт; апгрейд только вручную"),
    "reboot_flag": ("Требуется ребут", 2, True, True, True,
                    "reboot-required: отчёт + чистка мусорных строк"),
    "unattended": ("Unattended-upgrades", 2, True, True, False,
                   "авто-патчи безопасности: отчёт; включение вручную"),
    "timesync": ("Синхронизация времени", 1, True, True, True,
                 "NTP не активен → timedatectl set-ntp true"),
    "fail2ban": ("Fail2ban", 1, True, True, True,
                 "установлен, но остановлен → start+enable"),
    "disk_usage": ("Место на диске", 1, True, True, True,
                   "пороги warn/crit; при crit — экстренная чистка кэшей"),
    "xray_version": ("Версия Xray", 3, False, True, False,
                      "дрифт версии против xray_target_version: отчёт"),
    "cert_expiry": ("Сертификаты Xray", 3, False, True, False,
                    "срок TLS-сертификатов из конфига Xray: отчёт"),
    "steal_snapshot": ("CPU Steal (мгнов.)", 3, False, True, False,
                        "быстрый замер %steal — хроника оверселла (детально: steal_monitor)"),
    "tunnels": ("Каскадные туннели", 3, False, True, False,
                "ping до внутренних адресов AWG-каскада: отчёт"),
    "ssh_audit": ("Аудит SSH", 3, False, True, False,
                  "PermitRootLogin/PasswordAuth/порт + отпечаток ключа хоста: отчёт"),
    "ufw_audit": ("Аудит UFW/порты", 3, False, True, False,
                  "слушающие порты вне ufw allow: отчёт"),
    "dns_check": ("Резолв DNS", 3, False, True, False,
                  "getent на тестовый хост: отчёт"),
}

CHECK_ORDER = list(CHECK_CATALOG.keys())

DEFAULT_CONFIG: dict = {
    "enabled": True,
    "node_label": "",                    # имя ноды в уведe (пусто = hostname)
    "cron_hour": 5,                      # ежедневный проход
    "cron_minute": 40,
    "cron_mode": "fix",                  # что делает cron: check | fix
    # ── пороги/политики ──
    "journald_cap_mb": 500,              # SystemMaxUse
    "big_log_mb": 100,                   # порог «раздутого» лога
    "big_log_dirs": ["/var/log"],        # где искать (PL: + /root)
    "big_log_keep_copies": 1,            # сколько doctor-gzip копий хранить
    "logrotate_watch": ["/var/log/hysteria.log", "/var/log/steal-monitor.log",
                        "/var/log/system-doctor.log", "/var/log/users-watchdog.log",
                        "/var/log/xray-exit-switch-watcher.log",
                        "/var/log/dnscrypt-proxy-blocked.log",
                        "/var/log/pingtunnel/*.log"],
    "crash_restarts_threshold": 50,      # NRestarts ≥ порога = crash-loop
    "crash_disable_allowlist": [],       # юниты, которые МОЖНО отключать
    "keep_old_kernels": 1,               # доп. ядер сверх running+newest
    "apt_full_upgrade": False,           # авто full-upgrade (опасно, выкл)
    "kernel_purge": False,               # авто purge старых ядер (выкл)
    "enable_unattended": False,          # авто вкл unattended-upgrades (выкл)
    "auto_reboot": False,                # НИКОГДА не ребутить автоматически
    "disk_warn_pct": 80,
    "disk_crit_pct": 90,
    "xray_target_version": "",           # "" = не сверять дрифт
    "tunnel_targets": [],                # напр. ["172.16.91.3", "172.16.91.4"]
    "tunnel_handshake_max_s": 180,       # свежесть хендшейка AWG/WG-пира
    "dns_test_host": "debian.org",
    # ── тумблеры по пунктам (check/fix) ──
    "checks": {cid: {"check": meta[3], "fix": meta[4]}
               for cid, meta in CHECK_CATALOG.items()},
    # ── уведомления ──
    "tg_notify": {
        "alerts": True,    # crit/ошибки фиксов → doctor_alert
        "fixed": True,     # сводка применённых фиксов → doctor_fixed
        "report": False,   # полный дайджест каждого прохода → doctor_report
        "quiet_hours": {"from": "", "to": ""},
    },
    "chat_id_override": "",
}

# ── Мелкие хелперы ────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except Exception:
        pass


def _run(cmd, timeout: int = 30, input_text: str = "") -> subprocess.CompletedProcess:
    """Запуск команды (никогда не бросает исключение наружу)."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, input=input_text or None)
    except Exception as e:  # FileNotFoundError, TimeoutExpired, ...
        return subprocess.CompletedProcess(cmd, 124, "", str(e))


def _hostname() -> str:
    try:
        return _run(["hostname", "-s"], timeout=6).stdout.strip() or "server"
    except Exception:
        return "server"


def _now_str() -> str:
    return datetime.now().strftime("%d.%m.%Y %H:%M")


def human_mb(mb) -> str:
    """MB → человекочитаемо ('476M' / '1.2G'). Чистая функция."""
    try:
        mb = float(mb)
    except (TypeError, ValueError):
        return "?"
    if mb >= 1024:
        return f"{mb / 1024:.1f}G"
    return f"{mb:.0f}M"


def merge_cfg(defaults: dict, stored: dict) -> dict:
    """Глубокое слияние конфига с дефолтами: новые ключи версий добираются
    из DEFAULT_CONFIG, значения владельца не перетираются. Чистая функция."""
    out = dict(defaults)
    for k, v in (stored or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = merge_cfg(out[k], v)
        else:
            out[k] = v
    # checks: гарантируем все пункты каталога (новые пункты будущих версий
    # получают дефолт каталога, если владелец не задал явно)
    checks = out.get("checks") if isinstance(out.get("checks"), dict) else {}
    fixed = {}
    for cid, meta in CHECK_CATALOG.items():
        cur = checks.get(cid) if isinstance(checks.get(cid), dict) else {}
        fixed[cid] = {"check": bool(cur.get("check", meta[3])),
                      "fix": bool(cur.get("fix", meta[4]))}
    out["checks"] = fixed
    # fixes для нефиксируемых пунктов (danger=3) принудительно выкл
    for cid, meta in CHECK_CATALOG.items():
        if not meta[2]:
            fixed[cid]["fix"] = False
    return out


def load_cfg() -> dict:
    stored = {}
    try:
        if CONFIG_FILE.exists():
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                stored = data
    except Exception:
        stored = {}
    return merge_cfg(DEFAULT_CONFIG, stored)


def save_cfg(cfg: dict) -> None:
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False),
                           encoding="utf-8")
    CONFIG_FILE.chmod(0o600)


# ── Контекст прохода (бэкапы/dry-run/действия) ───────────────────────────────

LEVEL_ICON = {"ok": "✅", "info": "ℹ️", "warn": "⚠️", "crit": "🚨"}


class DoctorCtx:
    """Состояние одного прохода: режим, dry-run, журнал найденного
    и применённого. Все мутации идут через ctx.write/ctx.cmd —
    в dry-run они только протоколируются."""

    def __init__(self, cfg: dict, mode: str = "check", dry_run: bool = False,
                 only=None):
        self.cfg = cfg
        self.mode = "fix" if mode == "fix" else "check"
        self.dry_run = bool(dry_run)
        self.only = {str(x).strip() for x in (only or []) if str(x).strip()}
        self.findings = []      # [{check, level, msg, unit}]
        self.fixed = []         # [{check, msg}]
        self.fix_errors = []    # [{check, msg}]
        self.actions = []       # протокол (вкл. dry-run намётки)
        self.stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    # ── тумблеры ──
    def check_enabled(self, cid: str) -> bool:
        if self.only:
            return cid in self.only
        return bool((self.cfg.get("checks") or {}).get(cid, {}).get("check"))

    def fix_enabled(self, cid: str) -> bool:
        if self.mode != "fix":
            return False
        if self.only and cid not in self.only:
            return False
        return bool((self.cfg.get("checks") or {}).get(cid, {}).get("fix"))

    # ── запись находок ──
    def record(self, cid: str, level: str, msg: str) -> None:
        self.findings.append({"check": cid, "level": level, "msg": msg})

    # ── мутации (dry-run aware) ──
    def _backup(self, path) -> bool:
        try:
            src = Path(path)
            if not src.exists():
                return True
            dst_dir = BACKUP_ROOT / self.stamp
            dst_dir.mkdir(parents=True, exist_ok=True)
            dst = dst_dir / (src.name + ".orig")
            i = 1
            while dst.exists():
                dst = dst_dir / f"{src.name}.orig.{i}"
                i += 1
            shutil.copy2(src, dst)
            return True
        except Exception as e:
            self.actions.append(f"backup FAIL {path}: {e}")
            return False

    def write(self, path, text: str, chmod=None) -> bool:
        """Запись файла (с бэкапом существующего)."""
        p = Path(path)
        label = f"write {p}"
        if self.dry_run:
            self.actions.append(f"[DRY] {label} ({len(text)} bytes)")
            return True
        if p.exists():
            if not self._backup(p):
                return False
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
            if chmod is not None:
                p.chmod(chmod)
            self.actions.append(label)
            return True
        except Exception as e:
            self.actions.append(f"{label} FAIL: {e}")
            return False

    def cmd(self, cmd, timeout: int = 120) -> subprocess.CompletedProcess:
        """Мутирующая команда (в dry-run — только протокол)."""
        pretty = " ".join(str(c) for c in cmd)
        if self.dry_run:
            self.actions.append(f"[DRY] cmd: {pretty}")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        r = _run(cmd, timeout=timeout)
        self.actions.append(f"cmd: {pretty}" + (f" (rc={r.returncode})" if r.returncode else ""))
        return r

    def move_to_backup(self, path) -> bool:
        """Перенос файла в карантин бэкап-каталога (netplan-фантомы и т.п.)."""
        p = Path(path)
        if self.dry_run:
            self.actions.append(f"[DRY] quarantine {p}")
            return True
        if not p.exists():
            return True
        dst_dir = BACKUP_ROOT / self.stamp / "quarantine"
        dst_dir.mkdir(parents=True, exist_ok=True)
        try:
            shutil.move(str(p), str(dst_dir / p.name))
            self.actions.append(f"quarantine {p} → {dst_dir}")
            return True
        except Exception as e:
            self.actions.append(f"quarantine {p} FAIL: {e}")
            return False


# ══════════════════════════════════════════════════════════════════════════════
#  Чистые функции парсинга (тестируются без сервера)
# ══════════════════════════════════════════════════════════════════════════════

_REDIR_RE = re.compile(r"<\s+(\S+)")
_PKG_LINE_RE = re.compile(r"^[a-z0-9][a-z0-9+.:~-]*(:[a-z0-9-]+)?$")


def parse_rc_local_issues(text: str, exists) -> list:
    """Строки rc.local с редиректом `< файл`, где файла нет (битый
    iptables-restore и т.п.). exists — callable(path)->bool.
    Возвращает [{'line_no', 'line', 'path'}]. Чистая функция."""
    issues = []
    for i, line in enumerate((text or "").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for m in _REDIR_RE.finditer(line):
            path = m.group(1).strip("'\"")
            if path.startswith("-") or path.startswith("$"):
                continue
            try:
                ok = exists(path)
            except Exception:
                ok = True
            if not ok:
                issues.append({"line_no": i, "line": line.rstrip(),
                               "path": path})
    return issues


_NETPLAN_SECTION_RE = re.compile(
    r"^\s{2,}(ethernets|bonds|bridges|vlans|wifis|modems|tunnels):\s*$")
_NETPLAN_IFACE_RE = re.compile(r"^\s{4,}([A-Za-z0-9._-]+):\s*(#.*)?$")
# ключи ВНУТРИ описания интерфейса, которые парсер не должен принимать
# за имя интерфейса (кейс RU-2: 'match:' в ens3 дал ложный фантом)
_NETPLAN_IFACE_KEYWORDS = {
    "match", "set-name", "wakeonlan", "optional", "mtu", "addresses",
    "routes", "routing-policy", "nameservers", "dhcp4", "dhcp6",
    "dhcp-overrides", "link-local", "optional-addresses", "accept-ra",
    "ipv6-address-generation", "gateway4", "gateway6", "renderer",
    "interfaces", "parameters", "modes", "regulatory-domain", "access-points",
    "auth", "dhcp-identifier",
}


def parse_netplan_ifaces(yaml_text: str) -> list:
    """Имена интерфейсов из netplan-yaml (без PyYAML — ручной разбор
    секций ethernets/bonds/bridges/vlans/wifis/modems/tunnels; ключи
    вроде match:/addresses: отсекаются по словарю ключей).
    Чистая функция."""
    ifaces, in_section = [], False
    for line in (yaml_text or "").splitlines():
        if _NETPLAN_SECTION_RE.match(line):
            in_section = True
            continue
        m = _NETPLAN_IFACE_RE.match(line)
        if in_section and m and m.group(1) not in _NETPLAN_IFACE_KEYWORDS:
            ifaces.append(m.group(1))
            continue
        if in_section and line and not line.startswith((" ", "\t", "#")):
            in_section = False
    return ifaces


def classify_reboot_required(lines) -> tuple:
    """Разбор /var/run/reboot-required: (валидные строки, мусор).
    Валид: заголовок '*** System restart required ***' и имена пакетов.
    Мусор: всё остальное (кейс PL/FI: чей-то скрипт аппендил листинг /root).
    Чистая функция."""
    valid, garbage = [], []
    for raw in lines or []:
        s = str(raw).rstrip()
        if not s:
            continue
        if s.strip() == "*** System restart required ***":
            valid.append(s)
        elif _PKG_LINE_RE.match(s.strip()):
            valid.append(s)
        else:
            garbage.append(s)
    return valid, garbage


def parse_nrestarts(text: str) -> dict:
    """Вывод `systemctl show '*.service' -p Id -p NRestarts --no-legend`
    (пары строк Id=/NRestarts=) → {unit: restarts}. Чистая функция."""
    out, cur_id = {}, None
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("Id="):
            cur_id = line[3:]
        elif line.startswith("NRestarts=") and cur_id:
            try:
                out[cur_id] = int(line[10:])
            except ValueError:
                pass
    return out


def parse_unit_log_rules(text: str) -> list:
    """Вывод `systemctl show '*.service' -p Id -p User -p StandardOutput
    -p StandardError --no-legend` → [{'unit','user','paths'}] для юнитов
    с append:/append:file логами. Чистая функция (кейс DE: dnscrypt)."""
    rules, cur = [], {}

    def _flush():
        if cur.get("unit") and cur.get("paths"):
            rules.append({"unit": cur["unit"],
                          "user": cur.get("user") or "root",
                          "paths": sorted(set(cur["paths"]))})
        cur.clear()

    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("Id="):
            _flush()
            cur["unit"] = line[3:]
        elif line.startswith("User="):
            cur["user"] = line[5:] or "root"
        elif line.startswith(("StandardOutput=", "StandardError=")):
            val = line.split("=", 1)[1]
            m = re.match(r"^(?:append|file):(.+)$", val)
            if m:
                cur.setdefault("paths", []).append(m.group(1))
    _flush()
    return rules


def parse_journal_usage_mb(text: str):
    """'Archived and active journals take up 476.0M...' → 476.0 (MB).
    Чистая функция."""
    m = re.search(r"take up\s+([\d.]+)\s*([KMG]?)", text or "")
    if not m:
        return None
    try:
        val = float(m.group(1))
    except ValueError:
        return None
    unit = (m.group(2) or "M").upper()
    return val / 1024.0 if unit == "K" else (val * 1024.0 if unit == "G" else val)


def _ver_key(v: str) -> tuple:
    """Ключ сортировки версий ядер: '6.8.0-147-generic' → (6,8,0,147,'generic')
    — численно, а не лексикографически ('35' не больше '147'). Чистая."""
    toks = re.split(r"[.\-]", str(v))
    return tuple(int(t) if t.isdigit() else t for t in toks)


def _kernel_family(v: str) -> str:
    """Семейство ядра '6.8.0-generic' (без ABI-номера) — для отбора
    откатных ядер той же серии. Чистая."""
    m = re.match(r"^(\d+\.\d+\.\d+)-\d+-([a-z]+)$", str(v))
    return f"{m.group(1)}-{m.group(2)}" if m else str(v)


def parse_kernel_pkgs(dpkg_lines, running: str, keep_extra: int = 1) -> dict:
    """dpkg -l linux-image-* → {'running','installed':[ver...],
    'newest','keep':[ver...], 'purge_candidates':[ver...]}.
    running — '6.8.0-147-generic'. keep = running + новейшее + keep_extra
    численно-соседних ядер той же серии (откатные). Чистая функция."""
    installed = set()
    for line in dpkg_lines or []:
        if line.startswith("ii  linux-image-") and "linux-image-unsigned" not in line:
            m = re.match(r"ii\s+linux-image-([0-9][^\s]+)\s", line)
            if m:
                installed.add(m.group(1))
    all_sorted = sorted(installed, key=_ver_key)
    newest = all_sorted[-1] if all_sorted else running
    fam = _kernel_family(running)
    same_series = sorted((v for v in installed
                          if _kernel_family(v) == fam), key=_ver_key)
    keep = {running, newest}
    if running in same_series:
        idx = same_series.index(running)
        for j in (list(range(max(0, idx - keep_extra), idx))
                  + list(range(idx + 1, min(len(same_series), idx + keep_extra + 1)))):
            keep.add(same_series[j])
    else:
        for v in same_series[:keep_extra]:
            keep.add(v)
    purge = sorted((v for v in installed if v not in keep), key=_ver_key)
    return {"running": running, "installed": all_sorted,
            "newest": newest, "keep": sorted(keep, key=_ver_key),
            "purge_candidates": purge}


def parse_listening_ports(ss_text: str) -> list:
    """`ss -tlnp`/`ss -tulnp` → уникальные [(proto, port)]. Чистая функция."""
    out = set()
    for line in (ss_text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("State") or line.startswith("Netid"):
            continue
        parts = line.split()
        proto = "tcp" if line.startswith("tcp") else ("udp" if line.startswith("udp") else "")
        if not proto:
            continue
        for tok in parts:
            if tok.startswith(("[", "*:")) or ":" in tok:
                addr = tok
                break
        else:
            continue
        m = re.search(r":(\d+)$", addr.strip("[]"))
        if m:
            out.add((proto, int(m.group(1))))
    return sorted(out)


def parse_ufw_allowed(ufw_text: str) -> tuple:
    """`ufw status` → (singles, ranges): singles = {(proto, port)},
    ranges = [(proto, lo, hi)] (напр. port-hopping 10000:20000/tcp).
    Чистая функция."""
    singles, ranges = set(), []
    for line in (ufw_text or "").splitlines():
        m = re.match(r"^(\S+)\s+ALLOW\b", line)
        if not m:
            continue
        for tok in m.group(1).split(","):
            tok = tok.strip()
            if not tok:
                continue
            proto = "tcp"
            port = tok
            if "/" in tok:
                port, proto = tok.split("/", 1)
                if proto == "*":
                    _ufw_tok_add(port, "tcp", singles, ranges)
                    _ufw_tok_add(port, "udp", singles, ranges)
                    continue
            _ufw_tok_add(port, proto, singles, ranges)
    return singles, ranges


def _ufw_tok_add(port: str, proto: str, singles: set, ranges: list) -> None:
    """Внутренний хелпер parse_ufw_allowed: одиночный порт или диапазон."""
    if ":" in port or "-" in port:
        sep = ":" if ":" in port else "-"
        try:
            lo, hi = (int(x) for x in port.split(sep, 1))
            if lo <= hi:
                ranges.append((proto, lo, hi))
        except ValueError:
            pass
        return
    try:
        singles.add((proto, int(port)))
    except ValueError:
        pass


def extract_cert_paths(xray_cfg: dict) -> list:
    """Пути сертификатов из JSON-конфига Xray (inbounds → streamSettings →
    tlsSettings/realitySettings → certificates[].certificateFile).
    Чистая функция."""
    paths = []
    try:
        for ib in (xray_cfg or {}).get("inbounds") or []:
            ss = ib.get("streamSettings") or {}
            for sect in ("tlsSettings", "realitySettings"):
                for cert in ((ss.get(sect) or {}).get("certificates")) or []:
                    cf = cert.get("certificateFile")
                    if cf:
                        paths.append(cf)
    except Exception:
        pass
    return sorted(set(paths))


def parse_wg_dump(text: str) -> list:
    """`wg/awg show all dump` → [{'iface','endpoint','allowed_ips',
    'handshake_ts','rx','tx'}] по пирам (строки с 5+ полями; ts=0 —
    хендшейка не было). Чистая функция."""
    peers = []
    for line in (text or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        # interface-line: iface, privkey, pubkey, listen-port — 4 поля
        try:
            ts = int(parts[5])
        except ValueError:
            continue
        try:
            rx, tx = int(parts[6]), int(parts[7])
        except ValueError:
            rx = tx = 0
        peers.append({"iface": parts[0], "endpoint": parts[3],
                      "allowed_ips": parts[4].split(","),
                      "handshake_ts": ts, "rx": rx, "tx": tx})
    return peers


def peer_for_target(dump: list, ip: str):
    """Пир, чьи allowed-ips покрывают цель (172.16.91.3 → пир RU-ноды).
    Чистая функция."""
    ip = str(ip).strip()
    for p in dump or []:
        for a in p.get("allowed_ips") or []:
            a = a.strip()
            if a and (a == ip or a.endswith("/32") and a[:-3] == ip):
                return p
    return None


def parse_xray_version(text: str) -> str:
    """'Xray 26.10.17 (Xray, Penetrates Everything.) ...' → '26.10.17'.
    Чистая функция."""
    m = re.search(r"Xray\s+v?([\d][\w.\-]*)", text or "")
    return m.group(1) if m else ""


def build_logrotate_stanza(paths) -> str:
    """Текст drop-in logrotate для набора логов (copytruncate — сервисы
    держат FD; missingok/notifempty/compress/weekly/rotate 4).
    Чистая функция."""
    lines = ["# chimera system-doctor: ротация логов, не покрытых своими",
             "# logrotate-конфигами (copytruncate — FD процесса не рвётся)"]
    for p in paths:
        lines.append("")
        lines.append(str(p) + " {")
        lines.append("    su root root")   # logrotate 3.21: без su — отказ из-за 1777 на /var/log
        lines.append("    weekly")
        lines.append("    rotate 4")
        lines.append("    size 50M")
        lines.append("    missingok")
        lines.append("    notifempty")
        lines.append("    compress")
        lines.append("    delaycompress")
        lines.append("    copytruncate")
        lines.append("}")
    return "\n".join(lines) + "\n"


def in_quiet_hours(now_hhmm: str, quiet: dict) -> bool:
    """Тихие часы (см. exit_switch_watcher._ew_quiet). Чистая функция."""
    qf = str((quiet or {}).get("from") or "").strip()
    qt = str((quiet or {}).get("to") or "").strip()
    if not qf or not qt or qf == qt:
        return False
    try:
        def m(s):
            h, mm = s.split(":")
            return int(h) * 60 + int(mm)
        n, f, t = m(now_hhmm), m(qf), m(qt)
    except (ValueError, TypeError):
        return False
    if f < t:
        return f <= n < t
    return n >= f or n < t


# ══════════════════════════════════════════════════════════════════════════════
#  Проверки (read-only; находки — в ctx.findings)
# ══════════════════════════════════════════════════════════════════════════════

_COMPRESSED_EXT = (".gz", ".xz", ".zst", ".bz2", ".zip", ".old", ".1", ".doctor-")


def chk_journald_cap(ctx: DoctorCtx) -> None:
    r = _run(["journalctl", "--disk-usage"], timeout=30)
    usage = parse_journal_usage_mb(r.stdout)
    if usage is None:
        ctx.record("journald_cap", "info", "journalctl недоступен — пропуск")
        return
    cap = float(ctx.cfg.get("journald_cap_mb") or 500)
    if usage > cap:
        ctx.record("journald_cap", "warn",
                   f"журнал {human_mb(usage)} > кэпа {human_mb(cap)} — нужна "
                   f"ротация/vacuum (фикс: drop-in SystemMaxUse + vacuum)")
    else:
        ctx.record("journald_cap", "ok", f"журнал {human_mb(usage)} ≤ {human_mb(cap)}")


def _find_big_logs(ctx: DoctorCtx) -> list:
    """Раздутые лог-файлы (>big_log_mb) в настроенных каталогах."""
    thr_mb = float(ctx.cfg.get("big_log_mb") or 100)
    found = []
    for d in (ctx.cfg.get("big_log_dirs") or ["/var/log"]):
        d = str(d)
        if not os.path.isdir(d):
            continue
        for root, dirs, files in os.walk(d):
            # journal — управляется journald сам, не трогаем
            dirs[:] = [x for x in dirs if os.path.join(root, x) != "/var/log/journal"]
            for f in files:
                if f.endswith(_COMPRESSED_EXT):
                    continue
                p = os.path.join(root, f)
                try:
                    if os.path.getsize(p) > thr_mb * 1024 * 1024:
                        found.append((p, os.path.getsize(p)))
                except OSError:
                    continue
    return sorted(found, key=lambda x: -x[1])


def chk_big_logs(ctx: DoctorCtx) -> None:
    found = _find_big_logs(ctx)
    if not found:
        ctx.record("big_logs", "ok", "раздутых логов нет")
        return
    for p, size in found:
        ctx.record("big_logs", "warn",
                   f"{p} — {human_mb(size / 1048576)} (фикс: gzip-копия + truncate)")


def _existing_log_files(cfg: dict) -> list:
    out = []
    for pat in (cfg.get("logrotate_watch") or []):
        for p in glob.glob(str(pat)):
            if os.path.isfile(p):
                out.append(p)
    return sorted(set(out))


def _logrotate_covered_basenames(include_own: bool = False) -> set:
    """Базовые имена, уже покрытые logrotate-конфигами.
    include_own=False — наш chimera-doctor НЕ считается (для пересборки
    фиксом: список того, что должен вести наш файл);
    include_own=True — считается (для проверки: покрытое нашим файлом
    не должно давать warn — иначе вечный цикл warn/no-op)."""
    tokens = set()
    for conf in ["/etc/logrotate.conf"] + glob.glob("/etc/logrotate.d/*"):
        if not include_own and os.path.basename(conf) == LOGROTATE_FILE.name:
            continue
        try:
            with open(conf, encoding="utf-8", errors="replace") as f:
                for tok in f.read().split():
                    tokens.add(os.path.basename(tok.rstrip("{")))
        except OSError:
            continue
    return tokens


def chk_logrotate_coverage(ctx: DoctorCtx) -> None:
    files = _existing_log_files(ctx.cfg)
    if not files:
        ctx.record("logrotate_coverage", "ok", "наблюдаемых логов нет")
        return
    covered = _logrotate_covered_basenames(include_own=True)
    uncovered = [p for p in files if os.path.basename(p) not in covered]
    if not uncovered:
        ctx.record("logrotate_coverage", "ok",
                   f"все {len(files)} наблюдаемых логов под ротацией")
        return
    for p in uncovered:
        ctx.record("logrotate_coverage", "warn",
                   f"{p} без logrotate (фикс: drop-in chimera-doctor)")


def _unit_log_rules() -> list:
    r = _run(["systemctl", "show", "*.service", "-p", "Id", "-p", "User",
              "-p", "StandardOutput", "-p", "StandardError", "--no-legend",
              "--no-pager"], timeout=40)
    return parse_unit_log_rules(r.stdout)


def chk_unit_log_perms(ctx: DoctorCtx) -> None:
    import pwd
    rules = _unit_log_rules()
    if not rules:
        ctx.record("unit_log_perms", "ok", "юнитов с file/append-логами нет")
        return
    problems = 0
    for rule in rules:
        user = str(rule.get("user") or "root")
        try:
            pw = pwd.getpwnam(user)
        except KeyError:
            continue
        for path in rule["paths"]:
            if not path.startswith("/var/"):
                continue  # /run, /tmp и пр. — вне зоны фикса
            if not os.path.exists(path):
                ctx.record("unit_log_perms", "warn",
                           f"{rule['unit']}: лог {path} не существует — юнит "
                           f"({user}) не сможет его создать (фикс: создать + chown)")
                problems += 1
                continue
            try:
                owner = pwd.getpwuid(os.stat(path).st_uid).pw_name
            except KeyError:
                continue
            if owner != user:
                ctx.record("unit_log_perms", "warn",
                           f"{rule['unit']}: лог {path} принадлежит {owner}, "
                           f"а пишет {user} (фикс: chown {user})")
                problems += 1
    if not problems:
        ctx.record("unit_log_perms", "ok",
                   f"права на логи юнитов в порядке ({len(rules)} юнит(ов))")


def chk_failed_units(ctx: DoctorCtx) -> None:
    r = _run(["systemctl", "--failed", "--no-legend", "--plain",
              "--no-pager"], timeout=30)
    lines = [l for l in (r.stdout or "").splitlines() if l.strip()]
    if not lines:
        ctx.record("failed_units", "ok", "failed-юнитов нет")
        return
    for l in lines:
        parts = l.split()
        ctx.record("failed_units", "crit",
                   f"failed: {parts[0]} ({' '.join(parts[1:3])}) "
                   f"(фикс: reset-failed; причину смотреть journalctl -u {parts[0]})")


def chk_rc_local(ctx: DoctorCtx) -> None:
    path = Path("/etc/rc.local")
    if not path.exists():
        ctx.record("rc_local", "ok", "/etc/rc.local отсутствует — нечего ломать")
        return
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        ctx.record("rc_local", "warn", f"не читается: {e}")
        return
    issues = parse_rc_local_issues(text, os.path.exists)
    if not issues:
        ctx.record("rc_local", "ok", "редиректы rc.local целы")
        return
    for iss in issues:
        ctx.record("rc_local", "crit",
                   f"строка {iss['line_no']}: < {iss['path']} — файла нет "
                   f"(rc-local.service падает на каждом буте; фикс: закомментировать)")


def chk_phantom_netplan(ctx: DoctorCtx) -> None:
    np_dir = Path("/etc/netplan")
    if not (Path("/usr/sbin/netplan").exists() or Path("/bin/netplan").exists()) \
            or not np_dir.is_dir():
        ctx.record("phantom_netplan", "ok", "netplan не установлен/не используется")
        return
    yamls = sorted(list(np_dir.glob("*.yaml")) + list(np_dir.glob("*.yml")))
    if not yamls:
        ctx.record("phantom_netplan", "ok", "netplan-конфигов нет")
        return
    r = _run(["ip", "-o", "link", "show"], timeout=15)
    live = set(re.findall(r"\d+:\s+([A-Za-z0-9._-]+)@", r.stdout or ""))
    live |= set(re.findall(r"\d+:\s+([A-Za-z0-9._-]+):", r.stdout or ""))
    for y in yamls:
        try:
            ifaces = parse_netplan_ifaces(y.read_text(encoding="utf-8",
                                                      errors="replace"))
        except OSError:
            continue
        if not ifaces:
            continue
        phantom = [i for i in ifaces if i not in live]
        if phantom and len(phantom) == len(ifaces):
            ctx.record("phantom_netplan", "warn",
                       f"{y.name}: ВСЕ интерфейсы ({', '.join(phantom)}) не "
                       f"существуют — конфиг-фантом (wait-online таймаутит; "
                       f"фикс: карантин файла + netplan generate)")
        elif phantom:
            ctx.record("phantom_netplan", "warn",
                       f"{y.name}: фантомные интерфейсы ({', '.join(phantom)}) "
                       f"вперемешку с живыми — разбор вручную (авто-фикс не тронет)")


def chk_crash_loops(ctx: DoctorCtx) -> None:
    r = _run(["systemctl", "show", "*.service", "-p", "Id", "-p", "NRestarts",
              "--no-legend", "--no-pager"], timeout=40)
    restarts = parse_nrestarts(r.stdout)
    thr = int(ctx.cfg.get("crash_restarts_threshold") or 50)
    allow = set(ctx.cfg.get("crash_disable_allowlist") or [])
    loops = {u: n for u, n in restarts.items() if n >= thr}
    if not loops:
        ctx.record("crash_loops", "ok", f"crash-loop'ов нет (порог {thr})")
        return
    for unit, n in sorted(loops.items(), key=lambda x: -x[1]):
        short = unit.replace(".service", "")
        if short in allow:
            ctx.record("crash_loops", "warn",
                       f"{unit}: {n} рестартов — в allowlist (фикс: disable --now)")
        else:
            ctx.record("crash_loops", "crit",
                       f"{unit}: {n} рестартов — crash-loop; авто-disable "
                       f"запрещён (добавьте '{short}' в crash_disable_allowlist, "
                       f"если сервис не нужен)")


def chk_apt_cache(ctx: DoctorCtx) -> None:
    r = _run(["du", "-sm", "/var/cache/apt"], timeout=30)
    m = re.match(r"(\d+)", r.stdout or "")
    if not m:
        ctx.record("apt_cache", "info", "кэш apt не измерить")
        return
    mb = int(m.group(1))
    if mb > 100:
        ctx.record("apt_cache", "warn",
                   f"/var/cache/apt — {human_mb(mb)} (фикс: apt-get clean)")
    else:
        ctx.record("apt_cache", "ok", f"/var/cache/apt — {human_mb(mb)}")


def _running_kernel() -> str:
    return _run(["uname", "-r"], timeout=10).stdout.strip() or "unknown"


def chk_old_kernels(ctx: DoctorCtx) -> None:
    r = _run(["dpkg", "-l"], timeout=40)
    info = parse_kernel_pkgs((r.stdout or "").splitlines(), _running_kernel(),
                             int(ctx.cfg.get("keep_old_kernels") or 1))
    cands = info["purge_candidates"]
    if info["running"] != info["newest"]:
        ctx.record("old_kernels", "warn",
                   f"работает {info['running']}, новейшая {info['newest']} — "
                   f"сначала ребут; purge заблокирован до перезагрузки")
    if cands:
        ctx.record("old_kernels", "info",
                   f"кандидаты на purge (авто ВЫКЛ): {', '.join(cands)}")
    else:
        ctx.record("old_kernels", "ok",
                   f"ядра: {info['running']} (+откатные {info['keep']})")


def chk_updates_pending(ctx: DoctorCtx) -> None:
    n, sec = None, 0
    r = _run(["/usr/lib/update-notifier/apt-check", "--human-readable"],
             timeout=120)
    m = re.search(r"(\d+) обновлени|^(\d+);(\d+)", r.stdout or "")
    m2 = re.search(r"^(\d+);(\d+)$", (r.stdout or "").strip())
    if m2:
        n, sec = int(m2.group(1)), int(m2.group(2))
    elif r.stdout and "0 пакетов можно обновить" in r.stdout:
        n = 0
    elif m:
        n = int(m.group(1) or m.group(2))
    else:
        s = _run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"],
                 timeout=180)
        n = sum(1 for l in (s.stdout or "").splitlines() if l.startswith("Inst "))
    if n is None:
        ctx.record("updates_pending", "info", "не удалось посчитать апдейты")
        return
    if sec:
        ctx.record("updates_pending", "crit",
                   f"апдейтов {n}, из них security {sec} (фикс вкл. вручную: "
                   f"apt_full_upgrade или unattended-upgrades)")
    elif n:
        ctx.record("updates_pending", "warn",
                   f"накопилось апдейтов: {n} (авто-апгрейд выключен — политика)")
    else:
        ctx.record("updates_pending", "ok", "система актуальна")


def chk_reboot_flag(ctx: DoctorCtx) -> None:
    rr = Path("/var/run/reboot-required")
    if not rr.exists():
        ctx.record("reboot_flag", "ok", "ребут не требуется")
        return
    try:
        lines = rr.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []
    valid, garbage = classify_reboot_required(lines)
    pkgs = ""
    pk = Path("/var/run/reboot-required.pkgs")
    if pk.exists():
        try:
            pkgs = ", ".join(pk.read_text().split()[:6])
        except OSError:
            pass
    ctx.record("reboot_flag", "warn",
               "требуется ребут" + (f" ({pkgs})" if pkgs else "") +
               (f" — авто-ребут {'ВКЛ' if ctx.cfg.get('auto_reboot') else 'ВЫКЛ'}"))
    if garbage:
        ctx.record("reboot_flag", "warn",
                   f"reboot-required засорён {len(garbage)} посторонн(их) "
                   f"строк(ами) — пример: {garbage[0][:60]!r} (фикс: чистка "
                   f"файла; источник дописывает какой-то скрипт)")


def chk_unattended(ctx: DoctorCtx) -> None:
    r = _run(["systemctl", "is-enabled", "unattended-upgrades"], timeout=15)
    if "not-found" in (r.stdout + r.stderr):
        ctx.record("unattended", "warn",
                   "unattended-upgrades не установлен — патчи безопасности "
                   "не применяются сами (вкл. вручную, fix выключен)")
        return
    if r.stdout.strip() == "enabled":
        ctx.record("unattended", "ok", "unattended-upgrades включён")
    else:
        ctx.record("unattended", "warn",
                   "unattended-upgrades установлен, но выключен (fix выключен "
                   "по умолчанию)")


def chk_timesync(ctx: DoctorCtx) -> None:
    r = _run(["timedatectl", "show", "-p", "NTPServiceActive",
              "-p", "NTPSynchronized", "--value"], timeout=20)
    vals = dict(l.split("=", 1) for l in (r.stdout or "").splitlines()
                if "=" in l)
    if vals.get("NTPServiceActive") == "no":
        ctx.record("timesync", "warn",
                   "NTP-сервис неактивен — часы уплывут (фикс: set-ntp true)")
    elif vals.get("NTPSynchronized") == "no":
        ctx.record("timesync", "info", "NTP активен, но ещё не синхронизирован")
    else:
        ctx.record("timesync", "ok", "время синхронизировано (NTP)")


def chk_fail2ban(ctx: DoctorCtx) -> None:
    r = _run(["systemctl", "is-active", "fail2ban"], timeout=15)
    state = r.stdout.strip()
    if state == "active":
        ctx.record("fail2ban", "ok", "fail2ban активен")
        return
    cat = _run(["systemctl", "cat", "fail2ban"], timeout=15)
    if cat.returncode != 0 or "not-found" in (cat.stdout + cat.stderr):
        ctx.record("fail2ban", "info",
                   "fail2ban не установлен (установка руками: chimera меню)")
        return
    ctx.record("fail2ban", "warn",
               f"fail2ban установлен, но {state or 'остановлен'} "
               f"(фикс: enable --now)")


def _parse_df(text: str) -> dict:
    out = {}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 6 or not parts[0].startswith("/dev"):
            continue
        try:
            out[parts[5]] = int(parts[4].rstrip("%"))
        except ValueError:
            continue
    return out


def chk_disk_usage(ctx: DoctorCtx) -> None:
    r = _run(["df", "-P"], timeout=20)
    mounts = _parse_df(r.stdout)
    if not mounts:
        ctx.record("disk_usage", "info", "df не разобрать")
        return
    warn = int(ctx.cfg.get("disk_warn_pct") or 80)
    crit = int(ctx.cfg.get("disk_crit_pct") or 90)
    worst = 0
    for mnt, pct in sorted(mounts.items()):
        worst = max(worst, pct)
        if pct >= crit:
            ctx.record("disk_usage", "crit",
                       f"{mnt}: {pct}% ≥ {crit}% (фикс: экстренная чистка кэшей)")
        elif pct >= warn:
            ctx.record("disk_usage", "warn", f"{mnt}: {pct}% (порог {warn}%)")
    if worst < warn:
        ctx.record("disk_usage", "ok",
                   f"диски в норме (худший {worst}% < {warn}%)")


def chk_xray_version(ctx: DoctorCtx) -> None:
    r = _run(["xray", "version"], timeout=20)
    ver = parse_xray_version(r.stdout)
    if not ver:
        ctx.record("xray_version", "info", "xray не найден — пропуск")
        return
    target = str(ctx.cfg.get("xray_target_version") or "").strip()
    if target and ver != target:
        ctx.record("xray_version", "warn",
                   f"Xray {ver} ≠ цели {target} (дрифт версий по флоту; "
                   f"обновление — руками владельца)")
    else:
        ctx.record("xray_version", "ok",
                   f"Xray {ver}" + (f" = цели {target}" if target else ""))


def chk_cert_expiry(ctx: DoctorCtx) -> None:
    cfg_json = {}
    for p in XRAY_CFG_CANDIDATES:
        if p.exists():
            try:
                cfg_json = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                cfg_json = {}
            break
    cert_paths = extract_cert_paths(cfg_json)
    if not cert_paths:
        ctx.record("cert_expiry", "ok", "файловых сертификатов в конфиге нет")
        return
    for cp in cert_paths:
        if not os.path.exists(cp):
            ctx.record("cert_expiry", "warn", f"{cp}: файла нет")
            continue
        end = _run(["openssl", "x509", "-noout", "-enddate", "-in", cp],
                   timeout=15).stdout.strip()
        m = re.search(r"notAfter=(.+)", end)
        if not m:
            ctx.record("cert_expiry", "info", f"{cp}: срок не разобрать")
            continue
        try:
            exp = datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            ctx.record("cert_expiry", "info", f"{cp}: {m.group(1).strip()}")
            continue
        days = (exp - datetime.now()).days
        if days < 0:
            ctx.record("cert_expiry", "crit", f"{cp}: ИСТЁК {days} дн. назад")
        elif days < 30:
            ctx.record("cert_expiry", "warn", f"{cp}: осталось {days} дн.")
        else:
            ctx.record("cert_expiry", "ok", f"{cp}: {days} дн. запаса")


def chk_steal_snapshot(ctx: DoctorCtx) -> None:
    def _read():
        try:
            with open("/proc/stat") as f:
                return f.readline().split()[1:]
        except OSError:
            return None
    a = _read()
    if not a:
        ctx.record("steal_snapshot", "info", "/proc/stat недоступен")
        return
    time.sleep(1.0)
    b = _read()
    try:
        a = [int(x) for x in a]
        b = [int(x) for x in b]
    except (ValueError, TypeError):
        ctx.record("steal_snapshot", "info", "/proc/stat не разобрать")
        return
    dt = sum(b) - sum(a)
    if dt <= 0:
        ctx.record("steal_snapshot", "info", "нулевая дельта CPU")
        return
    steal = (b[8] - a[8]) / dt * 100.0  # колонка 9 = steal
    if steal >= 15:
        ctx.record("steal_snapshot", "crit",
                   f"%steal {steal:.1f} — гипервизор забирает CPU (см. steal_monitor)")
    elif steal >= 5:
        ctx.record("steal_snapshot", "warn", f"%steal {steal:.1f}")
    else:
        ctx.record("steal_snapshot", "ok", f"%steal {steal:.1f}")


def chk_tunnels(ctx: DoctorCtx) -> None:
    """Каскадные туннели: честный сигнал — свежесть AWG/WG-хендшейка
    пира (ICMP через AmneziaWG может не ходить при живом туннеле —
    кейс NL: ping мёртв, handshake 11с назад, трафик течёт)."""
    targets = ctx.cfg.get("tunnel_targets") or []
    if not targets:
        ctx.record("tunnels", "ok", "цели туннелей не настроены — пропуск")
        return
    max_s = int(ctx.cfg.get("tunnel_handshake_max_s") or 180)
    dump = []
    for tool in ("awg", "wg"):
        r = _run([tool, "show", "all", "dump"], timeout=20)
        if r.returncode == 0 and r.stdout.strip():
            dump = parse_wg_dump(r.stdout)
            if dump:
                break
    now = time.time()
    for t in targets:
        peer = peer_for_target(dump, t) if dump else None
        if peer is not None:
            age = now - peer["handshake_ts"] if peer["handshake_ts"] else None
            if age is None:
                ctx.record("tunnels", "crit",
                           f"{t}: пир {peer['endpoint']} без хендшейка")
            elif age <= max_s:
                ctx.record("tunnels", "ok",
                           f"{t} — туннель жив (handshake {int(age)} c назад)")
            else:
                ctx.record("tunnels", "crit",
                           f"{t}: хендшейк {int(age)} c назад (> {max_s} c) — "
                           f"туннель к {peer['endpoint']} мёртв?")
            continue
        # пира нет в дампе (или нет wg/awg) — фолбэк на ping
        r = _run(["ping", "-c", "1", "-W", "2", str(t)], timeout=8)
        if r.returncode == 0:
            ctx.record("tunnels", "ok", f"{t} доступен (ping)")
        elif dump:
            ctx.record("tunnels", "crit",
                       f"{t}: пира нет в AWG/WG-дампе и ping не проходит")
        else:
            ctx.record("tunnels", "crit",
                       f"{t} НЕ пингуется — туннель/маршрут мёртв?")


def chk_ssh_audit(ctx: DoctorCtx) -> None:
    r = _run(["sshd", "-T"], timeout=20)
    if r.returncode != 0:
        r = _run(["sshd", "-T", "-C", "user=root,host=localhost,addr=127.0.0.1"],
                 timeout=20)
    vals = {}
    for line in (r.stdout or "").splitlines():
        if " " in line:
            k, v = line.split(None, 1)
            vals[k] = v
    port = vals.get("port", "?")
    prl = vals.get("permitrootlogin", "?")
    pauth = vals.get("passwordauthentication", "?")
    ctx.record("ssh_audit", "info",
               f"SSH: порт {port}, PermitRootLogin={prl}, "
               f"PasswordAuthentication={pauth} (аудит — правки только руками)")
    fp = _run(["ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub"],
              timeout=15).stdout.strip()
    if fp:
        ctx.record("ssh_audit", "info", f"host-key ed25519: {fp[:70]}")


def chk_ufw_audit(ctx: DoctorCtx) -> None:
    r = _run(["ufw", "status"], timeout=20)
    if "inactive" in (r.stdout or ""):
        ctx.record("ufw_audit", "warn",
                   "ufw НЕ активен — все порты открыты (политика владельца)")
        return
    singles, ranges = parse_ufw_allowed(r.stdout)
    ss = _run(["ss", "-tulnp"], timeout=20)
    listening = parse_listening_ports(ss.stdout)
    exposed = []
    for proto, port in listening:
        if (proto, port) in singles:
            continue
        if any(p == proto and lo <= port <= hi for p, lo, hi in ranges):
            continue
        exposed.append(f"{proto}/{port}")
    if exposed:
        ctx.record("ufw_audit", "info",
                   f"слушают без явного ufw allow: {', '.join(exposed[:12])}"
                   + (" …" if len(exposed) > 12 else "")
                   + " (аудит; часть — легитимные локальные)")
    else:
        ctx.record("ufw_audit", "ok", "все слушающие порты покрыты ufw")


def chk_dns_check(ctx: DoctorCtx) -> None:
    host = str(ctx.cfg.get("dns_test_host") or "debian.org")
    r = _run(["getent", "hosts", host], timeout=15)
    if r.returncode == 0 and r.stdout.strip():
        ctx.record("dns_check", "ok", f"DNS: {host} резолвится")
    else:
        ctx.record("dns_check", "warn",
                   f"DNS: {host} НЕ резолвится (resolv.conf/upstream?)")


CHECKS = {cid.replace("chk_", ""): fn for cid, fn in list(globals().items())
          if cid.startswith("chk_")}


# ══════════════════════════════════════════════════════════════════════════════
#  Фиксы (идемпотентные; все мутации — через ctx.write/ctx.cmd — dry-run aware)
#  Возврат: (True, msg) — применили; (None, "") — нечего; (False, err) — ошибка
# ══════════════════════════════════════════════════════════════════════════════

def fix_journald_cap(ctx: DoctorCtx):
    cap = int(ctx.cfg.get("journald_cap_mb") or 500)
    desired = f"[Journal]\nSystemMaxUse={cap}M\n"
    changed = False
    try:
        current = JOURNALD_DROPIN.read_text(encoding="utf-8") \
            if JOURNALD_DROPIN.exists() else ""
    except OSError:
        current = ""
    if current != desired:
        if not ctx.write(JOURNALD_DROPIN, desired):
            return False, f"не удалось записать {JOURNALD_DROPIN}"
        ctx.cmd(["systemctl", "restart", "systemd-journald"])
        changed = True
    r = _run(["journalctl", "--disk-usage"], timeout=30)
    usage = parse_journal_usage_mb(r.stdout)
    if usage is not None and usage > cap:
        ctx.cmd(["journalctl", f"--vacuum-size={cap}M"], timeout=120)
        changed = True
    if not changed:
        return None, ""
    return True, f"journald: кэп {cap}M (drop-in + vacuum, было {human_mb(usage)})"


def fix_big_logs(ctx: DoctorCtx):
    found = _find_big_logs(ctx)
    if not found:
        return None, ""
    keep = max(0, int(ctx.cfg.get("big_log_keep_copies") or 1))
    done = []
    for p, _size in found:
        copy = f"{p}.doctor-{ctx.stamp}.gz"
        r = ctx.cmd(["/bin/sh", "-c", f"gzip -9 -c '{p}' > '{copy}'"],
                    timeout=300)
        if r.returncode != 0:
            return False, f"gzip {p}: rc={r.returncode}"
        ctx.cmd(["truncate", "-s", "0", p])
        # старые doctor-копии сверх keep — снести
        olds = sorted(glob.glob(p + ".doctor-*.gz"))
        for old in olds[:-keep] if keep else olds:
            ctx.cmd(["rm", "-f", old])
        done.append(os.path.basename(p))
    return True, (f"big_logs: сжаты {', '.join(done)} "
                  f"(gzip-копия + truncate)")


def fix_logrotate_coverage(ctx: DoctorCtx):
    files = _existing_log_files(ctx.cfg)
    covered = _logrotate_covered_basenames()
    uncovered = [p for p in files if os.path.basename(p) not in covered]
    if not uncovered:
        return None, ""
    stanza = build_logrotate_stanza(uncovered)
    try:
        current = LOGROTATE_FILE.read_text(encoding="utf-8") \
            if LOGROTATE_FILE.exists() else ""
    except OSError:
        current = ""
    if current == stanza:
        return None, ""
    if not ctx.write(LOGROTATE_FILE, stanza, chmod=0o644):
        return False, f"не удалось записать {LOGROTATE_FILE}"
    r = _run(["logrotate", "--debug", str(LOGROTATE_FILE)], timeout=30)
    if r.returncode != 0:
        return False, f"logrotate отверг конфиг: {r.stderr[:200]}"
    return True, (f"logrotate: drop-in на {len(uncovered)} лог(ов) "
                  f"({', '.join(os.path.basename(p) for p in uncovered[:5])})")


def fix_unit_log_perms(ctx: DoctorCtx):
    import grp
    import pwd
    rules = _unit_log_rules()
    fixed = []
    for rule in rules:
        user = str(rule.get("user") or "root")
        try:
            pw = pwd.getpwnam(user)
            grp_name = grp.getgrgid(pw.pw_gid).gr_name
        except KeyError:
            continue
        for path in rule["paths"]:
            if not path.startswith("/var/"):
                continue
            if not os.path.exists(path):
                r = ctx.cmd(["install", "-o", user, "-g", grp_name,
                             "-m", "0640", "/dev/null", path])
                if r.returncode == 0:
                    fixed.append(f"создан {path} ({user})")
            else:
                try:
                    owner = pwd.getpwuid(os.stat(path).st_uid).pw_name
                except KeyError:
                    continue
                if owner != user:
                    r = ctx.cmd(["chown", f"{user}:{grp_name}", path])
                    if r.returncode == 0:
                        fixed.append(f"chown {user} {path}")
    if not fixed:
        return None, ""
    return True, "unit_log_perms: " + "; ".join(fixed[:5])


def fix_failed_units(ctx: DoctorCtx):
    r = _run(["systemctl", "--failed", "--no-legend", "--plain",
              "--no-pager"], timeout=30)
    lines = [l for l in (r.stdout or "").splitlines() if l.strip()]
    if not lines:
        return None, ""
    ctx.cmd(["systemctl", "reset-failed"], timeout=60)
    return True, f"failed_units: reset-failed ({len(lines)} юнит(ов) очищено)"


def fix_rc_local(ctx: DoctorCtx):
    path = Path("/etc/rc.local")
    if not path.exists():
        return None, ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return False, f"rc.local не читается: {e}"
    issues = parse_rc_local_issues(text, os.path.exists)
    if not issues:
        return None, ""
    broken_lines = sorted({iss["line_no"] for iss in issues}, reverse=True)
    lines = text.splitlines(keepends=True)
    for ln in broken_lines:
        idx = ln - 1
        if 0 <= idx < len(lines):
            why = next(i["path"] for i in issues if i["line_no"] == ln)
            body = lines[idx].rstrip("\n")
            lines[idx] = (f"# [system-doctor {ctx.stamp}] выключено: "
                          f"нет файла {why}\n#{body}\n")
    new_text = "".join(lines)
    # валидация синтаксиса до записи
    tmp = Path(f"/tmp/.doctor-rc-local-{ctx.stamp}")
    try:
        tmp.write_text(new_text, encoding="utf-8")
        vr = _run(["bash", "-n", str(tmp)], timeout=15)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
    if vr.returncode != 0:
        return False, f"bash -n отверг новый rc.local: {vr.stderr[:150]}"
    if not ctx.write(path, new_text):
        return False, "не удалось записать rc.local"
    return True, (f"rc.local: закомментировано строк {len(broken_lines)} "
                  f"(битые редиректы)")


def fix_phantom_netplan(ctx: DoctorCtx):
    np_dir = Path("/etc/netplan")
    if not np_dir.is_dir():
        return None, ""
    r = _run(["ip", "-o", "link", "show"], timeout=15)
    live = set(re.findall(r"\d+:\s+([A-Za-z0-9._-]+)@", r.stdout or ""))
    live |= set(re.findall(r"\d+:\s+([A-Za-z0-9._-]+):", r.stdout or ""))
    quarantined = []
    for y in sorted(list(np_dir.glob("*.yaml")) + list(np_dir.glob("*.yml"))):
        try:
            ifaces = parse_netplan_ifaces(y.read_text(encoding="utf-8",
                                                      errors="replace"))
        except OSError:
            continue
        if ifaces and all(i not in live for i in ifaces):
            if not ctx.move_to_backup(y):
                return False, f"не удалось убрать {y}"
            quarantined.append(y.name)
    if not quarantined:
        return None, ""
    g = ctx.cmd(["netplan", "generate"], timeout=60)
    if g.returncode != 0:
        return False, f"netplan generate rc={g.returncode}: {g.stderr[:150]}"
    return True, (f"phantom_netplan: в карантин {', '.join(quarantined)} "
                  f"(бэкап: {BACKUP_ROOT}/{ctx.stamp}/quarantine/)")


def fix_crash_loops(ctx: DoctorCtx):
    allow = set(ctx.cfg.get("crash_disable_allowlist") or [])
    if not allow:
        return None, ""
    r = _run(["systemctl", "show", "*.service", "-p", "Id", "-p", "NRestarts",
              "--no-legend", "--no-pager"], timeout=40)
    restarts = parse_nrestarts(r.stdout)
    thr = int(ctx.cfg.get("crash_restarts_threshold") or 50)
    disabled = []
    for unit, n in restarts.items():
        short = unit.replace(".service", "")
        if n >= thr and short in allow:
            d = ctx.cmd(["systemctl", "disable", "--now", unit], timeout=60)
            if d.returncode == 0:
                disabled.append(f"{short} ({n} рест.)")
    if not disabled:
        return None, ""
    return True, "crash_loops: отключены " + ", ".join(disabled)


def fix_apt_cache(ctx: DoctorCtx):
    r = _run(["du", "-sm", "/var/cache/apt"], timeout=30)
    m = re.match(r"(\d+)", r.stdout or "")
    if not m or int(m.group(1)) <= 100:
        return None, ""
    ctx.cmd(["apt-get", "clean"], timeout=120)
    return True, f"apt_cache: clean ({m.group(1)}M кэша снесено)"


def fix_old_kernels(ctx: DoctorCtx):
    if not ctx.cfg.get("kernel_purge"):
        return None, ""
    r = _run(["dpkg", "-l"], timeout=40)
    info = parse_kernel_pkgs((r.stdout or "").splitlines(), _running_kernel(),
                             int(ctx.cfg.get("keep_old_kernels") or 1))
    if not info["purge_candidates"]:
        return None, ""
    if info["running"] != info["newest"]:
        return False, (f"работает {info['running']} ≠ новейшей "
                       f"{info['newest']} — сначала ребут, purge отменён")
    pkgs = [f"linux-image-{v}" for v in info["purge_candidates"]]
    r2 = ctx.cmd(["apt-get", "purge", "-y"] + pkgs, timeout=900)
    if r2.returncode != 0:
        return False, f"purge rc={r2.returncode}: {r2.stderr[:150]}"
    return True, f"old_kernels: purged {', '.join(info['purge_candidates'])}"


def fix_updates_pending(ctx: DoctorCtx):
    if not ctx.cfg.get("apt_full_upgrade"):
        return None, ""
    if ctx.dry_run:
        ctx.actions.append("[DRY] cmd: apt-get update + full-upgrade")
        return True, "apt: полный апгрейд (dry-run)"
    u = _run(["apt-get", "update"], timeout=900)
    if u.returncode != 0:
        return False, f"apt-get update rc={u.returncode}"
    g = _run(["/bin/sh", "-c",
              "DEBIAN_FRONTEND=noninteractive apt-get -y "
              "-o Dpkg::Options::=--force-confold full-upgrade"], timeout=3600)
    if g.returncode != 0:
        return False, f"full-upgrade rc={g.returncode}: {g.stderr[:200]}"
    return True, "apt: full-upgrade выполнен"


def fix_reboot_flag(ctx: DoctorCtx):
    rr = Path("/var/run/reboot-required")
    if not rr.exists():
        return None, ""
    try:
        lines = rr.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None, ""
    valid, garbage = classify_reboot_required(lines)
    changed = False
    if garbage:
        if ctx.write(rr, "\n".join(valid) + ("\n" if valid else "")):
            changed = True
    if ctx.cfg.get("auto_reboot") is True and not ctx.dry_run:
        ctx.cmd(["shutdown", "-r", "+1",
                 "system-doctor: перезагрузка в новое ядро"], timeout=30)
        return True, "reboot_flag: запланирован ребут через 1 мин"
    if not changed:
        return None, ""
    return True, f"reboot_flag: вычищено {len(garbage)} мусорных строк"


def fix_unattended(ctx: DoctorCtx):
    if not ctx.cfg.get("enable_unattended"):
        return None, ""
    r = _run(["systemctl", "is-enabled", "unattended-upgrades"], timeout=15)
    if "not-found" in (r.stdout + r.stderr):
        inst = ctx.cmd(["apt-get", "install", "-y", "unattended-upgrades"],
                       timeout=600)
        if inst.returncode != 0:
            return False, "unattended-upgrades не установился"
    ctx.cmd(["systemctl", "enable", "--now", "unattended-upgrades"], timeout=60)
    auto = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    ctx.write(auto,
              'APT::Periodic::Update-Package-Lists "1";\n'
              'APT::Periodic::Unattended-Upgrade "1";\n', chmod=0o644)
    return True, "unattended-upgrades: включён (пакеты безопасности)"


def fix_timesync(ctx: DoctorCtx):
    r = _run(["timedatectl", "show", "-p", "NTPServiceActive", "--value"],
             timeout=20)
    if (r.stdout or "").strip() != "no":
        return None, ""
    ctx.cmd(["timedatectl", "set-ntp", "true"], timeout=30)
    return True, "timesync: NTP включён"


def fix_fail2ban(ctx: DoctorCtx):
    r = _run(["systemctl", "is-active", "fail2ban"], timeout=15)
    if r.stdout.strip() == "active":
        return None, ""
    cat = _run(["systemctl", "cat", "fail2ban"], timeout=15)
    if cat.returncode != 0 or "not-found" in (cat.stdout + cat.stderr):
        return None, ""
    ctx.cmd(["systemctl", "enable", "--now", "fail2ban"], timeout=60)
    return True, "fail2ban: запущен и включён"


def fix_disk_usage(ctx: DoctorCtx):
    r = _run(["df", "-P"], timeout=20)
    mounts = _parse_df(r.stdout)
    crit = int(ctx.cfg.get("disk_crit_pct") or 90)
    hot = {m: p for m, p in mounts.items() if p >= crit}
    if not hot:
        return None, ""
    ctx.cmd(["apt-get", "clean"], timeout=120)
    cap = int(ctx.cfg.get("journald_cap_mb") or 500)
    ctx.cmd(["journalctl", f"--vacuum-size={cap // 2}M"], timeout=120)
    return True, (f"disk_usage: экстренная чистка при {hot} "
                  f"(apt cache + journal → {cap // 2}M)")


FIXES = {cid.replace("fix_", ""): fn for cid, fn in list(globals().items())
         if cid.startswith("fix_")}


# ══════════════════════════════════════════════════════════════════════════════
#  Прогон: check → (fix) → отчёт → TG
# ══════════════════════════════════════════════════════════════════════════════

def _node_label(cfg: dict) -> str:
    return str(cfg.get("node_label") or "").strip() or _hostname()


def run_once(mode: str = "check", only=None, dry_run: bool = False,
             cfg: dict = None) -> dict:
    """Один проход доктора. mode: 'check' | 'fix'. Возвращает отчёт-словарь:
    {'counts': {...}, 'findings': [...], 'fixed': [...], 'fix_errors': [...],
     'actions': [...], 'dry_run': bool, 'label': str}."""
    cfg = cfg or load_cfg()
    if not cfg.get("enabled", True):
        return {"skipped": True, "reason": "выключен в конфиге",
                "counts": {}, "findings": [], "fixed": [], "fix_errors": [],
                "actions": [], "dry_run": dry_run, "label": _node_label(cfg)}
    ctx = DoctorCtx(cfg, mode=mode, dry_run=dry_run, only=only)
    for cid in CHECK_ORDER:
        if not ctx.check_enabled(cid):
            continue
        try:
            CHECKS[cid](ctx)
        except Exception as e:  # ни одна проверка не должна ронять проход
            ctx.record(cid, "warn", f"ошибка проверки: {e}")
        if ctx.fix_enabled(cid) and cid in FIXES:
            try:
                ok, msg = FIXES[cid](ctx)
                if ok is True:
                    ctx.fixed.append({"check": cid, "msg": msg})
                elif ok is False:
                    ctx.fix_errors.append({"check": cid, "msg": msg})
            except Exception as e:
                ctx.fix_errors.append({"check": cid, "msg": f"фикс упал: {e}"})
    counts = {"ok": 0, "info": 0, "warn": 0, "crit": 0}
    for f in ctx.findings:
        counts[f["level"]] = counts.get(f["level"], 0) + 1
    report = {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mode": ctx.mode, "dry_run": ctx.dry_run,
        "label": _node_label(cfg), "hostname": _hostname(),
        "counts": counts, "findings": ctx.findings,
        "fixed": ctx.fixed, "fix_errors": ctx.fix_errors,
        "actions": ctx.actions,
        "only": sorted(ctx.only),
    }
    if not dry_run:
        try:
            LAST_FILE.parent.mkdir(parents=True, exist_ok=True)
            LAST_FILE.write_text(json.dumps(report, ensure_ascii=False,
                                            indent=1), encoding="utf-8")
        except Exception:
            pass
    _log(f"[{ctx.mode}{'/dry' if dry_run else ''}] "
         f"ok={counts.get('ok')} info={counts.get('info')} "
         f"warn={counts.get('warn')} crit={counts.get('crit')} "
         f"fixed={len(ctx.fixed)} errs={len(ctx.fix_errors)}")
    if not dry_run:
        _notify_report(report, cfg)
    return report


def build_console_report(report: dict) -> str:
    """Человекочитаемый отчёт для консоли/лога. Чистая функция."""
    lines = []
    label = report.get("label") or "?"
    mode = "FIX" if report.get("mode") == "fix" else "CHECK"
    if report.get("dry_run"):
        mode += "/DRY"
    c = report.get("counts") or {}
    lines.append(f"== system-doctor [{label}] {mode} {report.get('ts', '')} ==")
    lines.append(f"итог: ok={c.get('ok', 0)} info={c.get('info', 0)} "
                 f"warn={c.get('warn', 0)} crit={c.get('crit', 0)}"
                 + (f" | исправлено: {len(report.get('fixed') or [])}"
                    if report.get("fixed") else "")
                 + (f" | ОШИБКИ ФИКСОВ: {len(report.get('fix_errors') or [])}"
                    if report.get("fix_errors") else ""))
    by_check = {}
    for f in report.get("findings") or []:
        by_check.setdefault(f["check"], []).append(f)
    for cid in CHECK_ORDER:
        items = by_check.get(cid)
        if not items:
            continue
        title = CHECK_CATALOG.get(cid, (cid,))[0]
        lines.append(f"── {cid} ({title})")
        for f in items:
            lines.append(f"   {LEVEL_ICON.get(f['level'], '•')} {f['msg']}")
    for fx in report.get("fixed") or []:
        lines.append(f"   🛠️  [fixed/{fx['check']}] {fx['msg']}")
    for fe in report.get("fix_errors") or []:
        lines.append(f"   ❌ [fix-error/{fe['check']}] {fe['msg']}")
    if report.get("dry_run") and report.get("actions"):
        lines.append("── план действий (dry-run)")
        for a in report["actions"][:40]:
            lines.append(f"   → {a}")
    return "\n".join(lines)


def build_tg_text(report: dict) -> str:
    """Компактный HTML-текст для TG. Чистая функция."""
    label = report.get("label") or "?"
    mode = "FIX" if report.get("mode") == "fix" else "CHECK"
    c = report.get("counts") or {}
    head = (f"🩺 <b>[{label}] System Doctor</b> — {mode}\n"
            f"ok {c.get('ok', 0)} · info {c.get('info', 0)} · "
            f"⚠️ {c.get('warn', 0)} · 🚨 {c.get('crit', 0)}")
    body = []
    for f in report.get("findings") or []:
        if f["level"] in ("warn", "crit"):
            body.append(f"{LEVEL_ICON[f['level']]} {f['msg']}")
    fixed = report.get("fixed") or []
    if fixed:
        body.append("🛠️ Починено:")
        body.extend(f"  • {fx['msg']}" for fx in fixed[:8])
    errs = report.get("fix_errors") or []
    if errs:
        body.append("❌ Фиксы не удались:")
        body.extend(f"  • {fe['msg']}" for fe in errs[:5])
    text = head + ("\n" + "\n".join(body[:24]) if body else "")
    if len(text) > 3800:
        text = text[:3790] + "\n…"
    return text


def _tg_send_event(event: str, detail: str, cfg: dict) -> bool:
    """Отправка через tg_bot.tg_notify_event (уважает фильтр событий);
    fallback — curl напрямую (паттерн exit_switch_watcher)."""
    chat_override = str((cfg or {}).get("chat_id_override") or "").strip()
    try:
        from chimera.modules import tg_bot
        if chat_override:
            ok = tg_bot.tg_send(detail, chat_id=chat_override)
            _log(f"TG[{event}] direct → {chat_override}: "
                 f"{'OK' if ok else 'FAIL'}")
            return bool(ok)
        tg_bot.tg_notify_event(event, detail)
        _log(f"TG[{event}] sent (filter-respecting)")
        return True
    except Exception as e:
        _log(f"TG[{event}] tg_bot недоступен ({e}) — curl-fallback")
    # curl-fallback по telegram.json
    try:
        tcfg = Path("/var/lib/xray-installer/telegram.json")
        if not tcfg.exists():
            return False
        t = json.loads(tcfg.read_text(encoding="utf-8"))
        token = t.get("token") or ""
        chat = chat_override or t.get("chat_id") or ""
        if not token or not chat:
            return False
        import urllib.request
        import urllib.parse
        api = f"https://api.telegram.org/bot{token}/sendMessage"
        data = urllib.parse.urlencode({
            "chat_id": chat, "text": detail, "parse_mode": "HTML",
        }).encode()
        req = urllib.request.Request(api, data=data)
        urllib.request.urlopen(req, timeout=15)
        _log(f"TG[{event}] curl-fallback OK")
        return True
    except Exception as e:
        _log(f"TG[{event}] curl-fallback FAIL: {e}")
        return False


def _notify_report(report: dict, cfg: dict) -> None:
    """Правила уведомлений: alert (crit/ошибки), fixed (починено), report."""
    tgn = cfg.get("tg_notify") or {}
    if in_quiet_hours(datetime.now().strftime("%H:%M"),
                      tgn.get("quiet_hours") or {}):
        _log("TG: тихие часы — уведы подавлены")
        return
    c = report.get("counts") or {}
    if tgn.get("alerts", True) and (c.get("crit") or report.get("fix_errors")):
        _tg_send_event("doctor_alert", build_tg_text(report), cfg)
        return
    if tgn.get("fixed", True) and report.get("fixed"):
        _tg_send_event("doctor_fixed", build_tg_text(report), cfg)
        return
    if tgn.get("report", False) and report.get("findings"):
        _tg_send_event("doctor_report", build_tg_text(report), cfg)


# ══════════════════════════════════════════════════════════════════════════════
#  Установка cron (паттерн steal_monitor: PYTHONPATH-safe обёртки)
# ══════════════════════════════════════════════════════════════════════════════

def _find_python() -> str:
    for p in ("/usr/bin/python3", "/usr/local/bin/python3", "python3"):
        if Path(p).exists() or p == "python3":
            return p
    return "python3"


def _installer_path() -> str:
    """Каталог установки chimera (find_spec + фолбэк /opt/chimera)."""
    import importlib.util
    try:
        spec = importlib.util.find_spec("chimera")
    except (ValueError, ModuleNotFoundError):
        spec = None
    if spec and spec.submodule_search_locations:
        return str(Path(list(spec.submodule_search_locations)[0]).parent)
    return "/opt/chimera"


def is_installed() -> bool:
    return CRON_FILE.exists()


def install_system_doctor(cfg: dict = None) -> tuple:
    """cron.d: ежедневный проход в cron_hour:cron_minute режимом cron_mode."""
    try:
        cfg = cfg or load_cfg()
        hour = max(0, min(23, int(cfg.get("cron_hour", 5))))
        minute = max(0, min(59, int(cfg.get("cron_minute", 40))))
        mode = "fix" if str(cfg.get("cron_mode") or "fix") == "fix" else "check"
        installer = _installer_path()
        python = _find_python()
        CRON_SCRIPT.parent.mkdir(parents=True, exist_ok=True)
        CRON_FILE.parent.mkdir(parents=True, exist_ok=True)
        CRON_SCRIPT.write_text(f"""#!/bin/bash
# system-doctor.sh — медосмотр ОС (Chimera system_doctor)
export PYTHONPATH="{installer}:$PYTHONPATH"
{python} -c "
import sys
sys.path.insert(0, '{installer}')
from chimera.modules.system_doctor import run_once
run_once(mode='{mode}')
" 2>>/var/log/system-doctor.log
""", encoding="utf-8")
        CRON_SCRIPT.chmod(0o750)
        CRON_FILE.write_text(
            f"# system-doctor — медосмотр ОС + безопасные авто-фиксы (Chimera)\n"
            f"{minute} {hour} * * * root {CRON_SCRIPT} "
            f">>/var/log/system-doctor.log 2>&1\n",
            encoding="utf-8")
        CRON_FILE.chmod(0o644)
        _log(f"установлен: cron {hour:02d}:{minute:02d} режим {mode}")
        return True, (f"System Doctor установлен: ежедневно "
                      f"{hour:02d}:{minute:02d}, режим {mode}")
    except Exception as e:
        return False, f"Ошибка установки: {e}"


def uninstall_system_doctor() -> tuple:
    """Удаляет cron + обёртку (конфиг/отчёты/бэкапы остаются)."""
    try:
        for p in (CRON_FILE, CRON_SCRIPT):
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass
        _log("удалён (cron + обёртка; данные сохранены)")
        return True, "System Doctor удалён (конфиг и бэкапы сохранены)"
    except Exception as e:
        return False, f"Ошибка удаления: {e}"


# ══════════════════════════════════════════════════════════════════════════════
#  TUI-меню (Диагностика и Мониторинг → SD)
# ══════════════════════════════════════════════════════════════════════════════

def _colors() -> dict:
    try:
        from chimera.modules.box_renderer import (GREEN, YELLOW, RED, CYAN,
                                                  DIM, BOLD, NC)
        return {"GREEN": GREEN, "YELLOW": YELLOW, "RED": RED,
                "CYAN": CYAN, "DIM": DIM, "BOLD": BOLD, "NC": NC}
    except Exception:
        return {"GREEN": "", "YELLOW": "", "RED": "",
                "CYAN": "", "DIM": "", "BOLD": "", "NC": ""}


def _last_run_summary() -> str:
    try:
        if not LAST_FILE.exists():
            return "нет данных (ещё не запускался)"
        r = json.loads(LAST_FILE.read_text(encoding="utf-8"))
        c = r.get("counts") or {}
        return (f"{r.get('ts', '?')} [{r.get('mode', '?')}] "
                f"ok={c.get('ok', 0)} warn={c.get('warn', 0)} "
                f"crit={c.get('crit', 0)} fixed={len(r.get('fixed') or [])}")
    except Exception:
        return "нет данных"


def _menu_toggles(cfg: dict) -> None:
    """Тумблеры check/fix по каждому пункту каталога."""
    from chimera.modules.box_renderer import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_back, _box_ok)
    C = _colors()
    checks = cfg.setdefault("checks", {})
    ids = list(CHECK_CATALOG.keys())
    while True:
        os.system("clear")
        print()
        _box_top("🩺  SYSTEM DOCTOR — СОСТАВ ПРОВЕРОК")
        _box_row("  Формат: [check|fix] — что делаем / что чиним")
        _box_row(f"  {C['DIM']}danger: 1=безопасно 2=политика 3=только отчёт{C['NC']}")
        _box_sep()
        for i, cid in enumerate(ids, 1):
            title, danger, fixable, _, _, _ = CHECK_CATALOG[cid]
            st = checks.get(cid, {})
            ck = "✓" if st.get("check", True) else " "
            fx = "✓" if st.get("fix", False) else " "
            fx_cell = f"{fx}" if fixable else f"{C['DIM']}·{C['NC']}"
            _box_row(f"  {i:2d}. [{ck}|{fx_cell}] {title} "
                     f"{C['DIM']}({cid}, danger {danger}){C['NC']}")
        _box_row(f"  {C['DIM']}N — переключить check | F — переключить fix | "
                 f"0 — выход{C['NC']}")
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{C['CYAN']}Выбор (N / N.f / Q): {C['NC']}").strip().lower()
        except KeyboardInterrupt:
            return
        if ch in ("0", "q", ""):
            return
        parts = ch.split(".")
        if parts[0].isdigit() and 1 <= int(parts[0]) <= len(ids):
            cid = ids[int(parts[0]) - 1]
            st = checks.setdefault(cid, {"check": True, "fix": False})
            if len(parts) == 2 and parts[1] == "f":
                if CHECK_CATALOG[cid][2]:  # fixable
                    st["fix"] = not st.get("fix", False)
                else:
                    continue
            else:
                st["check"] = not st.get("check", True)
            save_cfg(cfg)
            _box_ok(f"{cid}: check={'ВКЛ' if st.get('check') else 'ВЫКЛ'}, "
                    f"fix={'ВКЛ' if st.get('fix') else 'ВЫКЛ'}")


def _menu_settings(cfg: dict) -> None:
    """Пороги и политики."""
    from chimera.modules.box_renderer import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_back, _box_ok)
    C = _colors()
    while True:
        os.system("clear")
        print()
        _box_top("⚙️  SYSTEM DOCTOR — НАСТРОЙКИ")
        _box_row(f"  1. Кэп journald: {C['BOLD']}{cfg.get('journald_cap_mb')}M{C['NC']}")
        _box_row(f"  2. Порог большого лога: {C['BOLD']}{cfg.get('big_log_mb')}M{C['NC']}"
                 f"  (каталоги: {', '.join(cfg.get('big_log_dirs') or [])})")
        _box_row(f"  3. Порог crash-loop (рестартов): "
                 f"{C['BOLD']}{cfg.get('crash_restarts_threshold')}{C['NC']}")
        _box_row(f"  4. Allowlist на disable: "
                 f"{C['BOLD']}{', '.join(cfg.get('crash_disable_allowlist') or []) or '—'}{C['NC']}")
        _box_row(f"  5. Xray target-версия: "
                 f"{C['BOLD']}{cfg.get('xray_target_version') or '—'}{C['NC']}")
        _box_row(f"  6. Цели туннелей: "
                 f"{C['BOLD']}{', '.join(cfg.get('tunnel_targets') or []) or '—'}{C['NC']}")
        _box_row(f"  7. Cron: {cfg.get('cron_hour'):02d}:{cfg.get('cron_minute'):02d}"
                 f" режим {cfg.get('cron_mode')}")
        _box_sep()
        _box_row(f"  8. apt full-upgrade: "
                 f"{'ВКЛ ⚠️' if cfg.get('apt_full_upgrade') else 'выкл'}")
        _box_row(f"  9. purge старых ядер: "
                 f"{'ВКЛ ⚠️' if cfg.get('kernel_purge') else 'выкл'}")
        _box_row(f" 10. unattended-upgrades: "
                 f"{'ВКЛ' if cfg.get('enable_unattended') else 'выкл'}")
        _box_row(f" 11. авто-ребут: {'ВКЛ ⚠️' if cfg.get('auto_reboot') else 'выкл (рекоменд.)'}")
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{C['CYAN']}Выбор: {C['NC']}").strip()
        except KeyboardInterrupt:
            return
        if ch in ("0", "q", ""):
            return
        if ch == "1":
            raw = input(f"  Кэп journald, MB [{cfg.get('journald_cap_mb')}]: ").strip()
            if raw.isdigit():
                cfg["journald_cap_mb"] = int(raw)
        elif ch == "2":
            raw = input(f"  Порог, MB [{cfg.get('big_log_mb')}]: ").strip()
            if raw.isdigit():
                cfg["big_log_mb"] = int(raw)
        elif ch == "3":
            raw = input(f"  Рестартов [{cfg.get('crash_restarts_threshold')}]: ").strip()
            if raw.isdigit():
                cfg["crash_restarts_threshold"] = int(raw)
        elif ch == "4":
            raw = input("  Юниты через запятую (напр. hysteria-server): ").strip()
            cfg["crash_disable_allowlist"] = [
                x.strip() for x in raw.split(",") if x.strip()]
        elif ch == "5":
            raw = input(f"  Версия [{cfg.get('xray_target_version') or ''}]: ").strip()
            cfg["xray_target_version"] = raw
        elif ch == "6":
            raw = input("  IP через запятую (напр. 172.16.91.3,172.16.91.4): ").strip()
            cfg["tunnel_targets"] = [x.strip() for x in raw.split(",") if x.strip()]
        elif ch == "7":
            raw = input("  ЧЧ ММ (напр. 05 40): ").strip().split()
            if len(raw) == 2 and all(x.isdigit() for x in raw):
                cfg["cron_hour"], cfg["cron_minute"] = int(raw[0]), int(raw[1])
                cfg["cron_mode"] = input("  Режим (check/fix) [fix]: ").strip() or "fix"
                if is_installed():
                    install_system_doctor(cfg)
        elif ch == "8":
            cfg["apt_full_upgrade"] = not cfg.get("apt_full_upgrade")
        elif ch == "9":
            cfg["kernel_purge"] = not cfg.get("kernel_purge")
        elif ch == "10":
            cfg["enable_unattended"] = not cfg.get("enable_unattended")
        elif ch == "11":
            cfg["auto_reboot"] = not cfg.get("auto_reboot")
        else:
            continue
        save_cfg(cfg)
        _box_ok("Сохранено")


def _menu_notify(cfg: dict) -> None:
    """Уведомления TG."""
    from chimera.modules.box_renderer import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_back, _box_ok)
    C = _colors()
    tgn = cfg.setdefault("tg_notify", {})
    qh = tgn.setdefault("quiet_hours", {"from": "", "to": ""})
    while True:
        os.system("clear")
        print()
        _box_top("🔔  SYSTEM DOCTOR — УВЕДОМЛЕНИЯ")
        _box_row(f"  1. Алерты (crit/ошибки фиксов): "
                 f"{'ВКЛ' if tgn.get('alerts', True) else 'ВЫКЛ'}")
        _box_row(f"  2. Сводки починки (doctor_fixed): "
                 f"{'ВКЛ' if tgn.get('fixed', True) else 'ВЫКЛ'}")
        _box_row(f"  3. Полный дайджест каждого прохода: "
                 f"{'ВКЛ' if tgn.get('report') else 'ВЫКЛ (анти-спам)'}")
        _box_row(f"  4. Тихие часы: {qh.get('from') or '—'} … {qh.get('to') or '—'}")
        _box_row(f"  5. Chat ID override: {cfg.get('chat_id_override') or 'основной'}")
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{C['CYAN']}Выбор: {C['NC']}").strip()
        except KeyboardInterrupt:
            return
        if ch in ("0", "q", ""):
            return
        if ch == "1":
            tgn["alerts"] = not tgn.get("alerts", True)
        elif ch == "2":
            tgn["fixed"] = not tgn.get("fixed", True)
        elif ch == "3":
            tgn["report"] = not tgn.get("report", False)
        elif ch == "4":
            f = input("  От (ЧЧ:ММ, Enter = выкл): ").strip()
            t = input("  До (ЧЧ:ММ): ").strip()
            qh["from"], qh["to"] = (f if f else ""), (t if f else "")
        elif ch == "5":
            raw = input("  Chat ID (Enter = основной): ").strip()
            cfg["chat_id_override"] = raw
        else:
            continue
        save_cfg(cfg)
        _box_ok("Сохранено")


def do_system_doctor_menu() -> None:
    """Интерактивное меню System Doctor (TUI)."""
    from chimera.modules.box_renderer import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_item, _box_back,
        _box_ok, _box_warn)
    C = _colors()
    while True:
        os.system("clear")
        cfg = load_cfg()
        installed = is_installed()
        status = (f"{C['GREEN']}cron активен{C['NC']}" if installed
                  else f"{C['YELLOW']}не установлен{C['NC']}")
        if not cfg.get("enabled", True):
            status += f" {C['RED']}(выключен в конфиге){C['NC']}"
        n_fix = sum(1 for c in (cfg.get("checks") or {}).values() if c.get("fix"))
        print()
        _box_top("🩺  SYSTEM DOCTOR — МЕДОСМОТР ОС + АВТО-ФИКСЫ")
        _box_row("  Гигиена ОС-уровня: journald/логи/rc.local/netplan-фантомы,")
        _box_row("  crash-loop'ы, права на логи юнитов, apt/ядра, время, диск.")
        _box_row("  Опасные действия выключены по умолчанию; sshd/ufw —")
        _box_row("  только аудит. Всё идемпотентно, с бэкапами и dry-run.")
        _box_sep()
        _box_row(f"  Статус: {status}   авто-фиксов включено: {C['BOLD']}{n_fix}{C['NC']}/{len(CHECK_CATALOG)}")
        _box_row(f"  Последний проход: {_last_run_summary()}")
        _box_sep()
        _box_item("C", "Проверить сейчас (check — без правок)")
        _box_item("F", "Проверить и починить (fix по тумблерам)")
        _box_item("D", "Dry-run (показать план фиксов, ничего не менять)")
        _box_item("T", "Состав проверок (тумблеры check/fix)")
        _box_item("S", "Настройки (пороги, allowlist, cron, политики)")
        _box_item("N", "Уведомления (алерты/сводки/тихие часы)")
        if installed:
            _box_item("U", "Удалить cron")
        else:
            _box_item("I", "Установить cron (ежедневно, режим из настроек)")
        _box_item("G", "Тест-уведомление в TG")
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{C['CYAN']}Выбор: {C['NC']}").strip().upper()
        except KeyboardInterrupt:
            return
        if ch in ("0", "Q", ""):
            return
        if ch == "C":
            rep = run_once(mode="check")
            print(build_console_report(rep))
            input(f"{C['CYAN']}Enter...{C['NC']}")
        elif ch == "F":
            rep = run_once(mode="fix")
            print(build_console_report(rep))
            input(f"{C['CYAN']}Enter...{C['NC']}")
        elif ch == "D":
            rep = run_once(mode="fix", dry_run=True)
            print(build_console_report(rep))
            input(f"{C['CYAN']}Enter...{C['NC']}")
        elif ch == "T":
            _menu_toggles(cfg)
        elif ch == "S":
            _menu_settings(cfg)
        elif ch == "N":
            _menu_notify(cfg)
        elif ch == "I" and not installed:
            ok, msg = install_system_doctor(cfg)
            _box_ok(msg) if ok else _box_warn(msg)
            input(f"{C['CYAN']}Enter...{C['NC']}")
        elif ch == "U" and installed:
            ok, msg = uninstall_system_doctor()
            _box_ok(msg) if ok else _box_warn(msg)
            input(f"{C['CYAN']}Enter...{C['NC']}")
        elif ch == "G":
            demo = {"label": _node_label(cfg), "mode": "TEST", "dry_run": False,
                    "counts": {"ok": 1, "info": 1, "warn": 1, "crit": 0},
                    "findings": [
                        {"check": "demo", "level": "warn",
                         "msg": "тестовая находка — уведы доктора работают"}],
                    "fixed": [], "fix_errors": []}
            ok = _tg_send_event("doctor_fixed", build_tg_text(demo), cfg)
            _box_ok("Увед отправлено") if ok else _box_warn("Не отправлено — см. лог")
            input(f"{C['CYAN']}Enter...{C['NC']}")




