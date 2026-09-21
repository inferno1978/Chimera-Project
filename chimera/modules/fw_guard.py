"""
chimera/modules/fw_guard.py
───────────────────────────────────────────────────────────────────────────────
FW Guard — автоматический контроль и восстановление правил фаервола.

Кейс <node-2> (2026-09-21): после «смерти» VPS сервисы поднялись, а правила
фаервола исчезли — ufw-правила портов пропали, raw-iptables правила
(ACCEPT ipset clients_wl / DROP ipset xray_ru_block) не пережили reboot.
Клиенты молча не могли подключиться, пока владелец вручную не прогнал
«Аварийное восстановление». FW Guard закрывает эту дыру: проверка каждые
2 минуты (systemd timer) + авто-восстановление + TG-уведомление.

Что НЕ восстанавливалось само (до FW Guard):
  • ufw-правила портов (chimera-*) — только вручную;
  • iptables ACCEPT ipset clients_wl → порт VLESS (cron клиентов
    пересобирает ТОЛЬКО ipset, но не само правило);
  • iptables DROP ipset xray_ru_block (ipset_persist возвращает СЕТ,
    но не использующее его iptables-правило);
  • флаг ufw active.

Модель — SNAPSHOT («как до сбоя»):
  Guard запоминает ЗДОРОВОЕ состояние: свои ufw-правила (по comment-маркеру
  «chimera-*») и факт «ufw был активен». При пропаже восстанавливает
  ЗАПОМНЕННОЕ, а не выдумывает новое. Новые правила изучаются на лету
  (learn), сервисы, исчезнувшие из port_registry, забываются (forget).
  Чужие (не «chimera-*) ufw-правила никогда не трогаем и не восстанавливаем.
  Для clients_wl / ru_block источник ожидания — флаги самих фич
  (cron-файл клиентов / ingress state), снапшот не нужен.

Публичный API:
    fw_guard_check()                — проверить состояние (без изменений)
    fw_guard_heal(report, full)     — восстановить пропавшее
    fw_guard_run()                  — вход для таймера (check+heal+log+notify)
    fw_guard_install()/remove()     — systemd service + timer
    do_manage_fw_guard()            — интерактивное меню
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ── Пути и константы (патчатся в тестах) ─────────────────────────────────────
STATE_FILE   = Path("/var/lib/xray-installer/fw_guard_state.json")
LOG_FILE     = Path("/var/log/xray-fw-guard.log")
SCRIPT_FILE  = Path("/usr/local/bin/xray-fw-guard.sh")
SERVICE_FILE = Path("/etc/systemd/system/xray-fw-guard.service")
TIMER_FILE   = Path("/etc/systemd/system/xray-fw-guard.timer")
TG_CONFIG    = Path("/var/lib/xray-installer/telegram.json")

# Переиспользуем пути соседних модулей (без импорта тяжёлого _core).
INSTALLED_STATE = Path("/var/lib/xray-installer/state.json")
PORT_REGISTRY   = Path("/var/lib/xray-installer/port_registry.json")
INGRESS_STATE   = Path("/var/lib/xray-installer/ingress.json")
CLIENTS_WL_CRON = Path("/etc/cron.d/chimera-clients-wl")
RU_SUBNETS_FILE = Path("/etc/xray/ru_subnets_ripe.txt")

# Comment-маркеры правил (совпадают с модулями-источниками).
WL_COMMENT     = "chimera-clients-wl"        # user_ip_whitelist.IPTABLES_COMMENT
INGRESS_COMMENT = "xray-ru-ingress-block"    # ingress_geoip._INGRESS_IPT_COMMENT
SSH_GUARD_COMMENT = "chimera-fw-guard-ssh"

WL_V4_SET = "clients_wl_v4"
RU_V4_SET = "xray_ru_block"

TIMER_INTERVAL_SEC = 120      # OnUnitActiveSec
NOTIFY_REPEAT_SEC  = 6 * 3600 # повторный алерт о неустранённой проблеме
LOG_MAX_BYTES      = 512 * 1024

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


# ── Вспомогательные ───────────────────────────────────────────────────────────
def _run(cmd: list, timeout: int = 30) -> subprocess.CompletedProcess:
    """subprocess.run без исключений (таймаут/отсутствие бинарника → rc!=0)."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              check=False, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return subprocess.CompletedProcess(cmd, 126, "", "")


def _ok(msg: str)   -> None: print(f'  {GREEN}✓{NC} {msg}')
def _warn(msg: str) -> None: print(f'  {YELLOW}⚠{NC}  {msg}')
def _info(msg: str) -> None: print(f'  {CYAN}•{NC} {msg}')


def _state_load() -> dict:
    """Снапшот-состояние guard: ufw_active_seen + rules_seen (spec → meta)."""
    default = {"ufw_active_seen": False, "rules_seen": {},
               "last_signature": "", "last_notify_ts": 0.0,
               "last_run": "", "heals_total": 0}
    try:
        if STATE_FILE.exists():
            data = json.loads(STATE_FILE.read_text())
            if isinstance(data, dict):
                default.update({k: data.get(k, v) for k, v in default.items()})
                if not isinstance(default["rules_seen"], dict):
                    default["rules_seen"] = {}
    except Exception:
        pass
    return default


def _state_save(st: dict) -> None:
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(st, indent=2, ensure_ascii=False))
        STATE_FILE.chmod(0o600)
    except Exception:
        pass


def _log_line(msg: str) -> None:
    """Одна строка в лог с защитой от разрастания."""
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > LOG_MAX_BYTES:
            keep = LOG_FILE.read_text(errors="replace").splitlines()[-1000:]
            LOG_FILE.write_text("\n".join(keep) + "\n")
        with LOG_FILE.open("a") as f:
            f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}\n")
    except Exception:
        pass


def _ssh_ports() -> list[int]:
    """Порты SSH из sshd_config (+drop-ins) — для страховки при ufw enable."""
    ports: list[int] = []
    candidates = [Path("/etc/ssh/sshd_config")]
    dropin = Path("/etc/ssh/sshd_config.d")
    if dropin.is_dir():
        candidates += sorted(dropin.glob("*.conf"))
    for cfg in candidates:
        try:
            for line in cfg.read_text(errors="replace").splitlines():
                m = re.match(r"^\s*Port\s+(\d+)\s*$", line, re.I)
                if m:
                    p = int(m.group(1))
                    if p not in ports:
                        ports.append(p)
        except Exception:
            continue
    return ports or [22]


def _notify_tg(msg: str) -> None:
    """Лёгкое TG-уведомление (как в cron-скрипте автобана): telegram.json + curl."""
    try:
        if not TG_CONFIG.exists():
            return
        c = json.loads(TG_CONFIG.read_text())
        t, ch = c.get("token"), c.get("chat_id")
        if t and ch:
            _run(["curl", "-s", "-o", "/dev/null", "-m", "10",
                  f"https://api.telegram.org/bot{t}/sendMessage",
                  "-d", f"chat_id={ch}", "-d", f"text={msg}"], timeout=15)
    except Exception:
        pass


# ── Разбор состояния фаервола ─────────────────────────────────────────────────
def _ufw_status_parse() -> "tuple[bool, list[dict]]":
    """ОДИН вызов `ufw status numbered` → (active, наши/все ALLOW-правила).

    Возвращает список правил: {spec, proto, port_start, port_end, comment}.
    v6-дубликаты схлопываются (та же спецификация порта).
    """
    if not shutil.which("ufw"):
        return False, []
    r = _run(["ufw", "status", "numbered"], timeout=30)
    if r.returncode != 0:
        return False, []
    out = r.stdout or ""
    active = "Status: active" in out
    rules: list[dict] = []
    seen: set[str] = set()
    for line in out.splitlines():
        m = re.match(r"^\s*\[\s*(\d+)\s*\]\s+(\S+)(?:\s+\(v6\))?\s+ALLOW", line)
        if not m:
            continue
        spec = m.group(2)
        if spec in seen:
            continue
        if not re.match(r"^\d+([:]\d+)?(/[a-z]+)?$", spec):
            continue  # «Anywhere», IPv6-адреса DENY-правил и пр.
        seen.add(spec)
        proto = "tcp"
        port_part = spec
        if "/" in spec:
            port_part, proto = spec.rsplit("/", 1)
        comment = ""
        if "#" in line:
            comment = line.split("#", 1)[1].strip()
        if ":" in port_part:
            a, b = port_part.split(":", 1)
            if a.isdigit() and b.isdigit():
                rules.append({"spec": spec, "proto": proto,
                              "port_start": int(a), "port_end": int(b),
                              "comment": comment})
                continue
        if port_part.isdigit():
            rules.append({"spec": spec, "proto": proto,
                          "port_start": int(port_part), "port_end": int(port_part),
                          "comment": comment})
    return active, rules


def _registry_entries() -> list[dict]:
    """Лёгкое чтение port_registry.json (без импорта port_registry)."""
    try:
        if PORT_REGISTRY.exists():
            data = json.loads(PORT_REGISTRY.read_text())
            if isinstance(data, list):
                return [e for e in data if isinstance(e, dict)]
    except Exception:
        pass
    return []


def _ingress_state() -> dict:
    try:
        if INGRESS_STATE.exists():
            data = json.loads(INGRESS_STATE.read_text())
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _server_port() -> int:
    try:
        if INSTALLED_STATE.exists():
            d = json.loads(INSTALLED_STATE.read_text())
            p = d.get("SERVER_PORT")
            if isinstance(p, int) and 1 <= p <= 65535:
                return p
    except Exception:
        pass
    return 443


def _ipset_info(name: str) -> "tuple[bool, int]":
    """(сет существует, число записей)."""
    r = _run(["ipset", "list", name], timeout=15)
    if r.returncode != 0:
        return False, 0
    m = re.search(r"Number of entries:\s*(\d+)", r.stdout or "")
    return True, (int(m.group(1)) if m else 0)


def _ipt_rule_exists(port: int, comment: str, jump: str, set_name: str,
                     ipt_bin: str = "iptables") -> bool:
    """Проверка наличия правила коммент-маркером (iptables -C)."""
    cmd = [ipt_bin, "-C", "INPUT", "-p", "tcp", "--dport", str(port),
           "-m", "set", "--match-set", set_name, "src", "-j", jump,
           "-m", "comment", "--comment", comment]
    return _run(cmd, timeout=15).returncode == 0


# ── Проверка (без изменений) ──────────────────────────────────────────────────
def fw_guard_check() -> dict:
    """Собирает отчёт о состоянии фаервола. Ничего не меняет."""
    st = _state_load()
    ufw_installed = bool(shutil.which("ufw"))
    ufw_active, rules = _ufw_status_parse()
    registry = _registry_entries()
    reg_services = {e.get("service") for e in registry}

    our_rules = [r for r in rules if r.get("comment", "").startswith("chimera-")]

    # Пропавшие ufw-правила: из снапшота, сервис которых ещё жив в реестре
    # (или сервис неизвестен — например, ssh-guard).
    now_specs = {r["spec"] for r in our_rules}
    missing_rules = []
    for spec, meta in (st.get("rules_seen") or {}).items():
        if spec in now_specs:
            continue
        svc = meta.get("service")
        if svc and svc not in reg_services and registry:
            continue  # сервис деинсталлирован — забудем (learn), не восстанавливаем
        missing_rules.append({"spec": spec, "proto": meta.get("proto", "tcp"),
                              "port_start": meta.get("port_start"),
                              "port_end": meta.get("port_end"),
                              "service": svc})

    # clients_wl: фича включена (cron-файл) → правило + ipset обязаны быть
    ing = _ingress_state()
    wl_port = ing.get("port") if ing.get("enabled") else _server_port()
    wl_feature = CLIENTS_WL_CRON.exists()
    wl_ipset_ok, wl_entries = _ipset_info(WL_V4_SET)
    wl_rule_ok = _ipt_rule_exists(wl_port, WL_COMMENT, "ACCEPT", WL_V4_SET) \
        if (wl_feature and shutil.which("iptables")) else False
    wl_problem = None
    if wl_feature:
        if not wl_ipset_ok:
            wl_problem = f"clients_wl: ipset {WL_V4_SET} отсутствует"
        elif not wl_rule_ok:
            wl_problem = f"clients_wl: нет ACCEPT-правила на :{wl_port}"

    # ru_block: ingress включён → DROP-правило + непустой ipset
    ru_feature = bool(ing.get("enabled"))
    ru_port = ing.get("port") or _server_port()
    ru_ipset_ok, ru_entries = _ipset_info(RU_V4_SET)
    ru_rule_ok = _ipt_rule_exists(ru_port, INGRESS_COMMENT, "DROP", RU_V4_SET) \
        if (ru_feature and shutil.which("iptables")) else False
    ru_file_ok = RU_SUBNETS_FILE.exists() and RU_SUBNETS_FILE.stat().st_size > 1000
    ru_problem = None
    if ru_feature:
        if not ru_ipset_ok or ru_entries == 0:
            ru_problem = f"ru_block: ipset {RU_V4_SET} пуст/отсутствует ({ru_entries})"
        elif not ru_rule_ok:
            ru_problem = f"ru_block: нет DROP-правила на :{ru_port}"
        elif not ru_file_ok:
            ru_problem = "ru_block: нет локального файла подсетей (RIPE) — авто-восстановление невозможно"

    problems: list[str] = []
    if ufw_installed and not ufw_active and st.get("ufw_active_seen"):
        problems.append("ufw не активен (был активен — восстанавливаем)")
    problems += [f"ufw: пропало правило {m['spec']} ({m['service'] or 'наше'})" for m in missing_rules]
    if wl_problem:
        problems.append(wl_problem)
    if ru_problem:
        problems.append(ru_problem)

    return {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "ufw_installed": ufw_installed,
        "ufw_active": ufw_active,
        "our_rules": our_rules,
        "missing_rules": missing_rules,
        "registry_count": len(registry),
        "clients_wl": {"feature": wl_feature, "port": wl_port,
                       "ipset_ok": wl_ipset_ok, "entries": wl_entries,
                       "rule_ok": wl_rule_ok, "problem": wl_problem},
        "ru_block": {"feature": ru_feature, "port": ru_port,
                     "ipset_ok": ru_ipset_ok, "entries": ru_entries,
                     "rule_ok": ru_rule_ok, "file_ok": ru_file_ok,
                     "problem": ru_problem},
        "problems": problems,
    }


# ── Восстановление ────────────────────────────────────────────────────────────
def _ufw_allow(port: int, comment: str) -> bool:
    r = _run(["ufw", "allow", f"{port}/tcp", "comment", comment], timeout=60)
    return r.returncode == 0


def _registry_open(spec_meta: dict) -> "tuple[bool, str]":
    """Открывает пропавшее правило через port_registry (идемпотентно)."""
    try:
        from chimera.modules import port_registry
        svc = spec_meta.get("service") or "fw-guard"
        ps, pe = spec_meta.get("port_start"), spec_meta.get("port_end")
        proto = spec_meta.get("proto", "tcp")
        if ps is not None and pe is not None and ps != pe:
            return port_registry.ufw_open_port_range(ps, pe, proto, svc)
        return port_registry.ufw_open_port(int(ps or pe or 0), proto, svc)
    except Exception as e:
        return False, f"port_registry недоступен: {e}"


def _heal_clients_wl(port: int) -> "tuple[bool, str]":
    try:
        from chimera.modules.user_ip_whitelist import apply_iptables_rule
        return apply_iptables_rule(port), "apply_iptables_rule"
    except Exception as e:
        return False, f"user_ip_whitelist недоступен: {e}"


def _heal_ru_block(port: int) -> "tuple[bool, str]":
    try:
        from chimera.modules.ingress_geoip import _ingress_apply_ipset
        from chimera.modules.ipset_persist import ipset_save
        v4: list[str] = []
        v6: list[str] = []
        for line in RU_SUBNETS_FILE.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            (v6 if ":" in line else v4).append(line)
        if not v4:
            return False, "файл подсетей пуст"
        ok = _ingress_apply_ipset(port, v4, v6)
        if ok:
            try:
                ipset_save()
            except Exception:
                pass
        return ok, "_ingress_apply_ipset"
    except Exception as e:
        return False, f"ingress_geoip недоступен: {e}"


def fw_guard_heal(report: "dict | None" = None, full: bool = False) -> list[str]:
    """Восстанавливает пропавшее. Возвращает список действий (лог-строки).

    full=True (ручной режим из меню): дополнительно открывает ufw-правила
    для ВСЕХ сервисов реестра, отсутствующих в снапшоте (для «уже
    сломанного» сервера, когда снапшот пуст/неполон). Диапазоны (port
    hopping) в full-режиме открываются min-max одной записью.
    """
    if report is None:
        report = fw_guard_check()
    st = _state_load()
    actions: list[str] = []

    # 1) ufw выключен, хотя был активен → страховка SSH + enable
    if (report["ufw_installed"] and not report["ufw_active"]
            and st.get("ufw_active_seen")):
        now_specs = {r["spec"] for r in report.get("our_rules", [])}
        for p in _ssh_ports():
            if f"{p}/tcp" not in now_specs and str(p) not in now_specs:
                if _ufw_allow(p, SSH_GUARD_COMMENT):
                    actions.append(f"ufw: открыт SSH-порт {p}/tcp (страховка)")
        r = _run(["ufw", "--force", "enable"], timeout=60)
        if r.returncode == 0:
            actions.append("ufw: активирован (был выключен)")
        else:
            actions.append(f"ufw: НЕ активирован ({(r.stderr or '').strip()[:80]})")

    # 2) пропавшие ufw-правила из снапшота
    for meta in report.get("missing_rules", []):
        ok, msg = _registry_open(meta)
        actions.append(f"ufw: {'восстановлено' if ok else 'НЕ восстановлено'} "
                       f"{meta['spec']} — {msg}")

    # 3) full: правила сервисов реестра, которых нет в снапшоте
    if full:
        snap_specs = set((st.get("rules_seen") or {}).keys())
        now_specs = {r["spec"] for r in report.get("our_rules", [])}
        by_service: dict[str, list[dict]] = {}
        for e in _registry_entries():
            by_service.setdefault(e.get("service") or "?", []).append(e)
        for svc, entries in by_service.items():
            protos = {e.get("proto", "tcp") for e in entries}
            for proto in protos:
                ports = sorted(int(e["port"]) for e in entries
                               if e.get("proto", "tcp") == proto
                               and isinstance(e.get("port"), int))
                if not ports:
                    continue
                # покрыт снапшотом/текущим состоянием?
                covered = any(
                    r.get("comment", "").startswith(f"chimera-{svc}")
                    for r in report.get("our_rules", []))
                if covered:
                    continue
                if len(ports) > 50:
                    ok, msg = _registry_open(
                        {"service": svc, "proto": proto,
                         "port_start": ports[0], "port_end": ports[-1]})
                    actions.append(f"ufw(full): {'открыт диапазон' if ok else 'НЕ открыт'} "
                                   f"{ports[0]}:{ports[-1]}/{proto} ({svc}) — {msg}")
                else:
                    for p in ports:
                        ok, msg = _registry_open(
                            {"service": svc, "proto": proto,
                             "port_start": p, "port_end": p})
                        actions.append(f"ufw(full): {'открыт' if ok else 'НЕ открыт'} "
                                       f"{p}/{proto} ({svc}) — {msg}")

    # 4) clients_wl / ru_block — по флагам фич
    if report["clients_wl"]["feature"] and report["clients_wl"]["problem"]:
        port = report["clients_wl"]["port"]
        ok, msg = _heal_clients_wl(port)
        actions.append(f"clients_wl: {'восстановлено' if ok else 'НЕ восстановлено'} "
                       f"ACCEPT на :{port} — {msg}")
    if report["ru_block"]["feature"] and report["ru_block"]["problem"]:
        port = report["ru_block"]["port"]
        if report["ru_block"].get("file_ok"):
            ok, msg = _heal_ru_block(port)
            actions.append(f"ru_block: {'восстановлено' if ok else 'НЕ восстановлено'} "
                           f"DROP на :{port} — {msg}")
        else:
            actions.append("ru_block: авто-восстановление невозможно — "
                           "нет файла подсетей (запустите GeoIP/ingress обновление)")

    return actions


# ── Обучение снапшота ─────────────────────────────────────────────────────────
def _learn(st: dict, report: dict) -> None:
    """Запоминаем здоровое состояние и забываем деинсталлированные сервисы."""
    if report["ufw_active"]:
        st["ufw_active_seen"] = True
    rules_seen: dict = st.get("rules_seen") or {}
    registry = _registry_entries()
    reg_services = {e.get("service") for e in registry} if registry else None
    # learn: всё наше и присутствующее сейчас
    for r in report.get("our_rules", []):
        comment = r.get("comment", "")
        service = comment.split()[0][len("chimera-"):] if comment.startswith("chimera-") else None
        rules_seen[r["spec"]] = {"proto": r["proto"], "port_start": r["port_start"],
                                 "port_end": r["port_end"], "service": service}
    # forget: сервисы, исчезнувшие из реестра (реестр непуст — иначе не знаем)
    if reg_services is not None and reg_services:
        for spec in list(rules_seen.keys()):
            svc = rules_seen[spec].get("service")
            if svc and svc not in reg_services:
                del rules_seen[spec]
    st["rules_seen"] = rules_seen


# ── Точка входа таймера ───────────────────────────────────────────────────────
def fw_guard_run(full: bool = False, notify: bool = True) -> dict:
    """Check → heal (если есть проблемы) → повторный check → learn → log → notify."""
    st = _state_load()
    before = fw_guard_check()
    actions: list[str] = []
    after = before
    if before["problems"] or full:
        actions = fw_guard_heal(before, full=full)
        after = fw_guard_check()
    _learn(st, after)

    sig = "|".join(sorted(before["problems"]))
    if before["problems"]:
        _log_line(f"PROBLEMS ({len(before['problems'])}): " + "; ".join(before["problems"]))
        for a in actions:
            _log_line(f"  HEAL {a}")
        if after["problems"]:
            _log_line(f"  STILL BROKEN: {'; '.join(after['problems'])}")
        else:
            _log_line("  OK: всё восстановлено")
    else:
        _log_line("OK: 0 проблем" + (f" (+{len(actions)} действий full-режима)" if actions else ""))

    # TG-уведомление: при лечении, с троттлингом (смена подписи проблем или 6ч)
    if notify and (actions or after["problems"]):
        now = time.time()
        sig_changed = sig != st.get("last_signature")
        timeout_passed = now - (st.get("last_notify_ts") or 0) > NOTIFY_REPEAT_SEC
        if sig_changed or timeout_passed:
            host = " ".join(_run(["hostname"]).stdout.split()) or "vps"
            if actions:
                _notify_tg(f"🧯 FW Guard ({host}): восстановлено {len(actions)} — " +
                           "; ".join(actions[:5]))
            else:
                _notify_tg(f"🚨 FW Guard ({host}): проблемы без авто-лечения: " +
                           "; ".join(after["problems"][:5]))
            st["last_notify_ts"] = now
    st["last_signature"] = sig
    st["last_run"] = datetime.now().isoformat(timespec="seconds")
    if actions:
        st["heals_total"] = st.get("heals_total", 0) + len(actions)
    _state_save(st)
    return {"before": before, "after": after, "actions": actions}


# ── Установка / удаление systemd юнитов ───────────────────────────────────────
def _installer_path() -> str:
    try:
        from chimera.modules.cold_boot_restore import _find_installer_path
        return _find_installer_path()
    except Exception:
        return "/opt/chimera"


def _build_script() -> str:
    python_bin = sys.executable or "/usr/bin/python3"
    return (
        "#!/bin/bash\n"
        "# xray-fw-guard.sh — авто-генерировано FW Guard (Chimera Project).\n"
        "# Управляется через меню: Безопасность → FW Guard.\n"
        f"{python_bin} -c '\n"
        "import sys\n"
        f"sys.path.insert(0, \"{_installer_path()}\")\n"
        "from chimera.modules.fw_guard import fw_guard_run\n"
        "fw_guard_run()\n"
        "' >> " + str(LOG_FILE) + " 2>&1\n"
    )


def fw_guard_install() -> "tuple[bool, str]":
    """Ставит скрипт + service + timer (каждые 2 минуты)."""
    try:
        SCRIPT_FILE.parent.mkdir(parents=True, exist_ok=True)
        SCRIPT_FILE.write_text(_build_script())
        SCRIPT_FILE.chmod(0o750)

        SERVICE_FILE.write_text(
            "[Unit]\n"
            "Description=FW Guard - firewall rules auto-restore (Chimera Project)\n"
            "After=network.target\n\n"
            "[Service]\n"
            "Type=oneshot\n"
            f"ExecStart={SCRIPT_FILE}\n"
        )
        TIMER_FILE.write_text(
            "[Unit]\n"
            "Description=FW Guard timer (firewall rules auto-restore)\n\n"
            "[Timer]\n"
            "OnBootSec=120\n"
            f"OnUnitActiveSec={TIMER_INTERVAL_SEC}s\n"
            "AccuracySec=30\n\n"
            "[Install]\n"
            "WantedBy=timers.target\n"
        )
        _run(["systemctl", "daemon-reload"], timeout=30)
        r = _run(["systemctl", "enable", "--now", "xray-fw-guard.timer"], timeout=60)
        if r.returncode != 0:
            return False, f"systemctl enable: {(r.stderr or '').strip()[:120]}"
        # Первый прогон немедленно: учим снапшот здорового состояния
        try:
            fw_guard_run(notify=False)
        except Exception:
            pass
        return True, "FW Guard установлен (каждые 2 мин)"
    except Exception as e:
        return False, f"Ошибка установки: {e}"


def fw_guard_remove() -> "tuple[bool, str]":
    """Снимает таймер (снапшот-файл НЕ удаляем — пригодится при повторной установке)."""
    _run(["systemctl", "disable", "--now", "xray-fw-guard.timer"], timeout=60)
    TIMER_FILE.unlink(missing_ok=True)
    SERVICE_FILE.unlink(missing_ok=True)
    SCRIPT_FILE.unlink(missing_ok=True)
    _run(["systemctl", "daemon-reload"], timeout=30)
    return True, "FW Guard удалён"


def _timer_status() -> "tuple[bool, bool]":
    """(active, enabled) таймера."""
    a = _run(["systemctl", "is-active", "xray-fw-guard.timer"], timeout=15)
    e = _run(["systemctl", "is-enabled", "xray-fw-guard.timer"], timeout=15)
    return (a.returncode == 0), ("enabled" in (e.stdout or ""))


def _last_log_lines(n: int = 15) -> list[str]:
    try:
        if LOG_FILE.exists():
            return LOG_FILE.read_text(errors="replace").splitlines()[-n:]
    except Exception:
        pass
    return []


# ── Интерактивное меню ────────────────────────────────────────────────────────
def do_manage_fw_guard() -> None:
    """Меню: статус таймера, установка, проверка, полное восстановление, лог."""
    import os
    from chimera._core import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_item, _box_back,
    )
    while True:
        os.system("clear")
        active, enabled = _timer_status()
        st = _state_load()
        rules_seen = len(st.get("rules_seen") or {})
        status = (f"{GREEN}активен{NC}" if active and enabled
                  else f"{YELLOW}не установлен{NC}" if not enabled
                  else f"{YELLOW}таймер выключен{NC}")
        snap = (f"{GREEN}да{NC} ({rules_seen} правил)" if st.get("ufw_active_seen")
                else f"{YELLOW}нет{NC}")
        last_run = st.get("last_run") or "—"
        heals = st.get("heals_total", 0)

        print()
        _box_top("🧯  FW GUARD — АВТО-ВОССТАНОВЛЕНИЕ ПРАВИЛ")
        _box_row("  Проверяет ufw/ipset/iptables каждые 2 минуты и")
        _box_row("  возвращает пропавшие правила (модель «как до сбоя»).")
        _box_sep()
        _box_row(f"  Таймер:        {status}")
        _box_row(f"  Снапшот:       {snap}")
        _box_row(f"  Прошлый прогон: {DIM}{last_run}{NC}")
        _box_row(f"  Всего лечений: {heals}")
        _box_sep()
        if not (active and enabled):
            _box_item("1", "Установить (timer + первый прогон-снапшот)")
        else:
            _box_item("1", "Удалить")
        _box_item("2", "Проверить сейчас (без изменений)")
        _box_item("3", "Полное восстановление по реестру портов")
        _box_row(f"     {DIM}(снапшот + все сервисы port_registry; для «уже сломанного» сервера){NC}")
        _box_item("4", "Лог (последние строки)")
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор: {NC}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if ch in ("0", "q", ""):
            break
        elif ch == "1":
            if active and enabled:
                ok, msg = fw_guard_remove()
            else:
                ok, msg = fw_guard_install()
            ( _ok if ok else _warn)(msg)
            input(f"{CYAN}Нажмите Enter...{NC}")
        elif ch == "2":
            rep = fw_guard_check()
            print()
            if not rep["problems"]:
                _ok(f"Проблем нет: ufw {'активен' if rep['ufw_active'] else 'не активен'}, "
                    f"наших правил: {len(rep['our_rules'])}, реестр: {rep['registry_count']}")
            else:
                _warn(f"Проблемы ({len(rep['problems'])}):")
                for p in rep["problems"]:
                    print(f"    {YELLOW}•{NC} {p}")
            input(f"{CYAN}Нажмите Enter...{NC}")
        elif ch == "3":
            _info("Полное восстановление (снапшот + реестр + фичи)...")
            res = fw_guard_run(full=True, notify=False)
            print()
            if res["actions"]:
                for a in res["actions"]:
                    print(f"    {GREEN}✓{NC} {a}")
            if res["after"]["problems"]:
                _warn("Остались проблемы:")
                for p in res["after"]["problems"]:
                    print(f"    {YELLOW}•{NC} {p}")
            else:
                _ok("Состояние восстановлено, проблем не осталось")
            input(f"{CYAN}Нажмите Enter...{NC}")
        elif ch == "4":
            print()
            lines = _last_log_lines()
            if lines:
                _box_top("🧯  FW GUARD — ЛОГ")
                for line in lines:
                    _box_row(f"  {DIM}{line[:70]}{NC}")
                _box_bottom()
            else:
                _warn("Лог пуст")
            input(f"{CYAN}Нажмите Enter...{NC}")
