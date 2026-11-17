"""
chimera/modules/smartdns.py
───────────────────────────────────────────────────────────────────────────────
SmartDNS-нода: оркестратор. DoH/DoT stealth + SNI-прокси в двух режимах
(решение владельца 17.11.2026: совмещаем в одном инструменте; третий
вариант «общий IP» отвергнут — максимум риска, нулевая изоляция).

  РЕЖИМЫ:
    standalone — отдельный VPS: полный стек, nginx целиком (если чисто),
      публичные порты wildcard, ufw как у bash-установщика;
    companion  — тот же VPS с Химерой + ВТОРОЙ IP ($1-3/мес):
      всё неймспейснуто (smartdns-*.service, /opt/smartdns, свой юзер),
      nginx ТОЛЬКО drop-in'ами (конфиг Химеры не трогаем, кроме
      stream-include-хука), NAT-редиректы и DROP-правила скоуплены на
      bind_ip (VLESS 443 / User Portal 9443 / Subscription 9444 Химеры
      продолжают работать), ufw только per-IP, движок — oxidns
      (AGH Химеры не трогаем).

  Паттерн интеграции — модуль B4 (dpi_bypass.py):
    загрузки — download_manager (авто-latest GitHub release при первичной
    установке + фолбэк-теги при недоступном GitHub);
    порты — port_registry (SERVICE_SMARTDNS_*, IP-осознанные записи);
    обновление — руками (CLI/TUI «Update») + сводка «доступно новое»
    в шапке меню (кэш latest, TTL 6ч — как _refresh_b4_latest_cache).

Слои:
    smartdns.py (этот) — режимы/визард/оркестрация/TUI/CLI/state;
    smartdns_stack.py  — компоненты: бинарники, конфиги xray/движка,
                         nginx, сертификат, Cloudflare, юниты, geo-списки;
    smartdns_firewall.py — iptables/ipset/ufw per-IP, ватчеры, whitelist.

ВЫЗОВ:
    TUI:  Настройки сети → SD → SmartDNS
    CLI:  python3 -m chimera.modules.smartdns install --mode companion \
              --bind-ip 203.0.113.7 --domain example.com \
              --cf-token TOKEN [--engine oxidns] [--non-interactive]
          python3 -m chimera.modules.smartdns update|status|uninstall|\
              preflight|backup|rollback|menu
          python3 -m chimera.modules.smartdns whitelist \
              add|remove|flush|toggle|mode|status [аргумент]
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
from pathlib import Path
from typing import Optional

from chimera.modules import smartdns_firewall as fw
from chimera.modules import smartdns_stack as st
from chimera.modules.box_renderer import (
    BOLD, CYAN, DIM, GREEN, NC, RED, YELLOW,
    _box_ask, _box_bottom, _box_desc, _box_info, _box_input, _box_item,
    _box_item_exit, _box_kv, _box_ok, _box_row, _box_sep, _box_top,
    _box_warn,
)
from chimera.modules.smartdns_stack import (
    AGH_FALLBACK_TAG, OXIDNS_FALLBACK_TAG, PORT_DOH, PORT_DOHLOC, PORT_DOT,
    PORT_DOTHERM, PORT_ENGINE, PORT_HTTP, PORT_STEALTH, PORT_WEB,
    STACK_VERSION, XRAY_FALLBACK_TAG, version_key,
)

# ── state / settings / secrets ──────────────────────────────────────────────
STATE_FILE = Path("/var/lib/xray-installer/smartdns_state.json")
DEFAULT_STATE = {
    "installed": False, "mode": None, "engine": None, "bind_ip": None,
    "domain": None, "dot_host": None, "whitelist_enabled": "false",
    "whitelist_mode": "shared", "versions": {},
    "installed_at": None, "stack_version": None,
}
_LATEST_TTL_OK = 6 * 3600      # как B4_LATEST_CACHE_TTL
_LATEST_TTL_FAIL = 30 * 60     # как B4_LATEST_RETRY_TTL


def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime
        p = Path("/var/log/chimera.log")
        p.parent.mkdir(parents=True, exist_ok=True)
        clean = re.sub(r"\x1b\[[0-9;]*m", "", msg)
        with p.open("a") as f:
            f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [smartdns] "
                    f"[{level}] {clean}\n")
    except Exception:
        pass


def _info(msg): print(f"  [INFO]  {msg}"); _log("INFO", msg)
def _ok(msg):   print(f"  [OK]    {msg}"); _log("OK", msg)
def _warn(msg): print(f"  [WARN]  {msg}"); _log("WARN", msg)
def _err(msg):  print(f"  [ERR]   {msg}"); _log("ERR", msg)


def _load_state() -> dict:
    if not STATE_FILE.exists():
        return dict(DEFAULT_STATE)
    try:
        s = json.loads(STATE_FILE.read_text())
        base = dict(DEFAULT_STATE)
        base.update(s)
        return base
    except Exception as e:
        _warn(f"smartdns_state.json повреждён: {e}")
        return dict(DEFAULT_STATE)


def _save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    STATE_FILE.chmod(0o600)


def load_settings() -> Optional[dict]:
    """Читает settings.json стека (для таймеров smartdns_stack CLI)."""
    try:
        return json.loads(st.SETTINGS_FILE.read_text())
    except Exception:
        return None


def save_settings(cfg: dict) -> None:
    """settings.json (без секретов — они в secrets.json 0600)."""
    st.STATE_DIR.mkdir(parents=True, exist_ok=True)
    keys = ["mode", "bind_ip", "engine", "domain", "dot_host",
            "whitelist_enabled", "whitelist_mode", "exclude_google_sys",
            "include_xbox_ipify", "server_ipv4", "server_ipv6"]
    data = {k: cfg.get(k) for k in keys if cfg.get(k) is not None}
    data["stack_version"] = STACK_VERSION
    st._atomic_write(st.SETTINGS_FILE,
                     json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                     mode=0o640)


def save_secrets(cfg: dict) -> None:
    """secrets.json: CF-токен, креды AGH-панели. 0600, root-only."""
    st.STATE_DIR.mkdir(parents=True, exist_ok=True)
    data = {}
    for k in ("cf_api_token", "acme_email", "agh_admin_user",
              "agh_admin_pass"):
        if cfg.get(k):
            data[k] = cfg[k]
    st._atomic_write(st.SECRETS_FILE,
                     json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                     mode=0o600)


def load_secrets() -> dict:
    try:
        return json.loads(st.SECRETS_FILE.read_text())
    except Exception:
        return {}


# ══════════════════════════════════════════════════════════════════════════
#  ОКРУЖЕНИЕ / ДЕТЕКТ (companion-режим: Химера + второй IP)
# ══════════════════════════════════════════════════════════════════════════

CHIMERA_MARKERS = [
    Path("/var/lib/xray-installer/state.json"),
    Path("/var/lib/xray-installer/telegram.json"),
    Path("/usr/local/bin/xray"),
    Path("/etc/xray/config.json"),
]


def detect_environment() -> dict:
    """Снимок окружения: ОС, ресурсы, интерфейсы/IP, детект Химеры,
    кандидаты второго IP (глобальные IPv4 ≠ основному)."""
    env = {"os_pretty": "", "os_id": "", "os_codename": "", "arch": "",
           "cores": 1, "mem_mb": 0, "disk_mb": 0, "primary_iface": "",
           "server_ipv4": "", "server_ipv6": "", "all_ips": [],
           "second_ip_candidates": [], "chimera_detected": False,
           "nginx_present": False, "docker": False, "iptables_backend": ""}
    try:
        with open("/etc/os-release") as f:
            txt = f.read()
        env["os_pretty"] = (re.search(r'^PRETTY_NAME="?([^"\n]+)',
                                      txt, re.M) or [None, ""])[1]
        env["os_id"] = (re.search(r'^ID="?(\w+)', txt, re.M) or [None, ""])[1]
        env["os_codename"] = (re.search(r'^VERSION_CODENAME="?(\w+)',
                                        txt, re.M) or [None, ""])[1]
    except Exception:
        pass
    env["arch"] = os.uname().machine
    try:
        env["cores"] = os.cpu_count() or 1
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    env["mem_mb"] = int(line.split()[1]) // 1024
                    break
    except Exception:
        pass
    try:
        r = subprocess.run(["df", "-Pm", "/"], capture_output=True, text=True,
                           check=False)
        env["disk_mb"] = int(r.stdout.splitlines()[1].split()[3])
    except Exception:
        pass
    try:
        r = subprocess.run(["ip", "-4", "route", "show", "default"],
                           capture_output=True, text=True, check=False)
        parts = (r.stdout or "").split()
        if len(parts) >= 5:
            env["primary_iface"] = parts[4]
    except Exception:
        pass
    try:
        r = subprocess.run(["ip", "-4", "-o", "addr", "show", "scope",
                            "global"], capture_output=True, text=True,
                           check=False)
        for line in (r.stdout or "").splitlines():
            cols = line.split()
            if len(cols) >= 4:
                ip = cols[2].split(":", 1)[0]
                env["all_ips"].append(ip)
                if cols[0] == env["primary_iface"] and not env["server_ipv4"]:
                    env["server_ipv4"] = ip
    except Exception:
        pass
    env["second_ip_candidates"] = [ip for ip in env["all_ips"]
                                   if ip != env["server_ipv4"]]
    try:
        r = subprocess.run(["ip", "-6", "-o", "addr", "show", "dev",
                            env["primary_iface"], "scope", "global"],
                           capture_output=True, text=True, check=False)
        for line in (r.stdout or "").splitlines():
            cols = line.split()
            if len(cols) >= 4:
                env["server_ipv6"] = cols[3].split("/")[0]
                break
    except Exception:
        pass
    env["chimera_detected"] = any(p.exists() for p in CHIMERA_MARKERS)
    env["nginx_present"] = bool(shutil.which("nginx"))
    env["docker"] = bool(shutil.which("docker"))
    try:
        r = subprocess.run(["iptables", "--version"], capture_output=True,
                           text=True, check=False)
        env["iptables_backend"] = ("iptables-nft"
                                   if "nf_tables" in (r.stdout or "")
                                   else "iptables-legacy")
    except Exception:
        pass
    return env


def validate_domain(fqdn: str) -> bool:
    return bool(fqdn) and len(fqdn) <= 253 and bool(
        re.match(r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
                 r"[a-zA-Z]{2,63}$", fqdn))


def validate_bind_ip(cfg: dict, env: dict) -> "tuple[bool, str]":
    """companion: bind_ip обязан лежать на интерфейсе ОС (хостер уже выдал
    и адрес поднят). Инсталлятор НЕ настраивает чужой netplan."""
    ip = str(cfg.get("bind_ip") or "")
    if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
        return False, f"Некорректный IPv4: {ip}"
    if ip not in env["all_ips"]:
        return False, (f"IP {ip} не поднят в ОС (найдены: "
                       f"{', '.join(env['all_ips'])}). Закажите второй IP у "
                       "хостера и поднимите его в netplan/interfaces — "
                       "инсталлятор чужую сеть не настраивает.")
    if ip == env["server_ipv4"]:
        return False, ("bind_ip совпадает с основным IP — для companion "
                       "нужен ВТОРОЙ адрес (основной остаётся Химере)")
    return True, ""


# ══════════════════════════════════════════════════════════════════════════
#  ПОРТЫ: план + регистрация (port_registry, IP-осознанно)
# ══════════════════════════════════════════════════════════════════════════

def port_plan(cfg: dict) -> list:
    """[(tag, port, proto, comment, public)] — публичные порты получают
    bind_ip в companion-режиме, loopback — всегда wildcard."""
    bind = cfg.get("bind_ip") if cfg.get("mode") == "companion" else None
    plan = [
        ("smartdns_http", PORT_HTTP, "tcp",
         "nginx: HTTP→HTTPS redirect (smartdns)", True),
        ("smartdns_dot", PORT_DOT, "tcp",
         "xray DoT dokodemo-door (smartdns)", True),
        ("smartdns_doh", PORT_DOH, "tcp",
         "xray DoH stealth dokodemo (smartdns)", True),
        ("smartdns_web", PORT_WEB, "tcp",
         "nginx cover-site TLS (smartdns)", True),
        ("smartdns_engine", PORT_ENGINE, "tcp",
         "DNS-движок loopback (smartdns)", False),
        ("smartdns_engine", PORT_ENGINE, "udp",
         "DNS-движок loopback (smartdns)", False),
        ("smartdns_doh_local", PORT_DOHLOC, "tcp",
         "DNS-движок DoH loopback (smartdns)", False),
        ("smartdns_dot_term", PORT_DOTHERM, "tcp",
         "nginx stream DoT-терминатор loopback (smartdns)", False),
        ("smartdns_stealth", PORT_STEALTH, "tcp",
         "nginx stealth-фронт loopback proxy_protocol (smartdns)", False),
    ]
    return [(tag, port, proto, comment, bind if public else None)
            for tag, port, proto, comment, public in plan]


def register_ports(cfg: dict) -> int:
    """Регистрирует порты стека в port_registry (force=True — наши сервисы
    к этому моменту уже слушают; паттерн install_b4)."""
    from chimera.modules.port_registry import port_register
    n = 0
    for tag, port, proto, comment, bind in port_plan(cfg):
        ok, msg = port_register(tag, port, proto, comment=comment,
                                force=True, bind_ip=bind)
        if ok:
            n += 1
        else:
            _warn(f"port_registry: {msg}")
    _ok(f"port_registry: зарегистрировано {n} портов "
        f"({'bind ' + cfg['bind_ip'] if cfg.get('mode') == 'companion' else 'wildcard'})")
    return n


def unregister_ports(cfg: dict) -> None:
    from chimera.modules.port_registry import port_unregister
    for tag, port, proto, _c, _b in port_plan(cfg):
        port_unregister(tag, port, proto)


def check_ports_free(cfg: dict) -> "tuple[bool, list[str]]":
    """Preflight-проверка портов: IP-осознанный конфликт-детект (до старта
    сервисов). wildcard-слушатель Химеры на 80/9443 не мешает companion
    bind'у на втором IP (ядро допускает сосуществование)."""
    from chimera.modules.port_registry import port_is_free
    problems = []
    for tag, port, proto, _c, bind in port_plan(cfg):
        if bind is None and cfg.get("mode") == "companion":
            continue    # loopback-порты в companion не проверяем по ss
        ok, conflicts = port_is_free(port, proto, exclude_service=tag,
                                     bind_ip=bind)
        if not ok:
            problems.append(f"{port}/{proto}"
                            + (f"@{bind}" if bind else "")
                            + ": " + "; ".join(conflicts))
    return (not problems), problems


# ══════════════════════════════════════════════════════════════════════════
#  PREFLIGHT
# ══════════════════════════════════════════════════════════════════════════

def preflight(cfg: dict, quiet: bool = False) -> "tuple[bool, list[str]]":
    """Проверки: ОС Debian 12/13, Ubuntu 22.04/24.04; RAM ≥512; диск ≥1500;
    IPv4; companion — второй IP в ОС + движок oxidns + nginx присутствует;
    порты свободны (IP-осознанно). Возвращает (ok, отчёт)."""
    env = detect_environment()
    rep = []
    ok = True

    def _fail(msg):
        nonlocal ok
        ok = False
        rep.append(f"[FAIL] {msg}")

    def _pass(msg):
        rep.append(f"[ OK ] {msg}")

    supported = ((env["os_id"], env["os_codename"]) in (
        ("debian", "bookworm"), ("debian", "trixie"),
        ("ubuntu", "jammy"), ("ubuntu", "noble")))
    (_pass if supported else _fail)(f"ОС: {env['os_pretty'] or 'неизвестна'}")
    (_pass if env["mem_mb"] >= 512 else _fail)(
        f"RAM: {env['mem_mb']} МБ (мин. 512)")
    (_pass if env["disk_mb"] >= 1500 else _fail)(
        f"Диск: {env['disk_mb']} МБ (мин. 1500)")
    (_pass if env["server_ipv4"] else _fail)(
        f"Основной IPv4: {env['server_ipv4'] or 'не найден'}")
    rep.append(f"[INFO] Химера на ноде: "
               f"{'обнаружена' if env['chimera_detected'] else 'не обнаружена'}")
    rep.append(f"[INFO] Firewall backend: {env['iptables_backend'] or '—'}")

    if cfg.get("mode") == "companion":
        ok_ip, why = validate_bind_ip(cfg, env)
        (_pass if ok_ip else _fail)(
            f"Второй IP (bind): {cfg.get('bind_ip')} "
            + ("" if ok_ip else f" — {why}"))
        if env["chimera_detected"]:
            _pass("Companion: стек Химеры обнаружен — разводка по IP активна")
        else:
            rep.append("[WARN] Companion: маркеры Химеры не найдены — "
                       "режим всё равно допустим (второй IP будет "
                       "зарезервирован за smartdns)")
        if cfg.get("engine") != "oxidns":
            _fail("Companion-режим требует движок oxidns (AGH конфликтует "
                  "с AdGuard Home Химеры)")
        if env["arch"] != "x86_64":
            _fail(f"oxidns: официальные сборки только x86_64 "
                  f"(архитектура {env['arch']})")
        ptr = "— выставьте PTR у хостера на DOT_HOST для чистого DoT-handshake"
        rep.append(f"[INFO] PTR второго IP: инсталлятор не проверяет ({ptr})")
    else:
        if cfg.get("engine") == "adguardhome" and env["arch"] != "x86_64":
            rep.append(f"[INFO] AGH поддерживает {env['arch']}")

    ports_ok, problems = check_ports_free(cfg)
    for p in problems:
        rep.append(f"[FAIL] порт {p}")
    if not ports_ok:
        ok = False
    else:
        _pass("Порты: конфликтов нет (IP-осознанная проверка port_registry)")

    if not quiet:
        _box_top("SmartDNS — Preflight")
        for line in rep:
            if line.startswith("[FAIL]"):
                _box_row(f"{RED}{line}{NC}")
            elif line.startswith("[WARN]"):
                _box_row(f"{YELLOW}{line}{NC}")
            elif line.startswith("[ OK ]"):
                _box_row(f"{GREEN}{line}{NC}")
            else:
                _box_row(f"{DIM}{line}{NC}")
        _box_row()
        _box_row(f"ИТОГ: {'СЕРВЕР ГОТОВ' if ok else 'ЕСТЬ БЛОКЕРЫ'} — "
                 f"режим {cfg.get('mode') or '—'}")
        _box_bottom()
    return ok, rep


# ══════════════════════════════════════════════════════════════════════════
#  ВИЗАРД (боксы; авто-детект режимов; non-interactive для CLI/SSH)
# ══════════════════════════════════════════════════════════════════════════

def run_wizard(cfg: dict) -> bool:
    """Интерактивный визард (Chimera-стиль). Заполняет cfg; False — отмена."""
    env = detect_environment()
    cfg.setdefault("mode", None)
    cfg.setdefault("engine", "oxidns")
    cfg.setdefault("bind_ip", None)

    _box_top("SmartDNS Setup Wizard — DoH/DoT Stealth + SNI Proxy")
    _box_desc("Публичный DNS-резолвер со маскировкой под обычный сайт: DoH "
              "в корне домена (/resolve/<SECRET>), DoT на 853, DoH-клиенты "
              "проходят через SNI-прокси прозрачно.")
    _box_sep()

    # 1) Режим (авто-детект: Химера + второй IP → companion по умолчанию)
    default_mode = "standalone"
    if env["chimera_detected"] and env["second_ip_candidates"]:
        default_mode = "companion"
    _box_desc(f"Обнаружено: Химера — "
              f"{'ДА' if env['chimera_detected'] else 'нет'}; "
              f"вторые IP — "
              f"{', '.join(env['second_ip_candidates']) or 'нет'}")
    _box_item("1", f"Отдельный VPS (standalone)  {DIM}— полный стек, "
                   f"порты wildcard{NC}")
    _box_item("2", f"Этот VPS + второй IP (companion)  {DIM}— изоляция по "
                   f"bind_ip, nginx/фаервол Химеры не трогаем{NC}")
    _box_row()
    ch = _box_ask("Режим", default="2" if default_mode == "companion"
                  else "1")
    cfg["mode"] = "companion" if ch == "2" else "standalone"
    _box_bottom()

    if cfg["mode"] == "companion":
        _box_top("Companion: второй IP")
        if env["second_ip_candidates"]:
            for i, ip in enumerate(env["second_ip_candidates"], 1):
                _box_item(str(i), ip)
            ch = _box_ask("IP для smartdns",
                          default=env["second_ip_candidates"][0])
            if ch.isdigit() and 1 <= int(ch) <= len(env["second_ip_candidates"]):
                cfg["bind_ip"] = env["second_ip_candidates"][int(ch) - 1]
            else:
                cfg["bind_ip"] = ch
        else:
            cfg["bind_ip"] = _box_input(
                "Второй IP (должен быть уже поднят в ОС)")
        ok, why = validate_bind_ip(cfg, env)
        if not ok:
            _box_warn(why)
            return False
        cfg["engine"] = "oxidns"
        _box_info("Движок зафиксирован: OxiDNS (AGH занят стеком Химеры)")
        _box_bottom()

    # 2) Движок (только standalone)
    if cfg["mode"] == "standalone":
        _box_top("DNS-движок")
        _box_item("1", f"OxiDNS  {DIM}— Rust, geosite-блокировки, только "
                       f"x86_64{NC}")
        _box_item("2", f"AdGuardHome  {DIM}— панель на 127.0.0.1:8053, все "
                       f"архитектуры{NC}")
        _box_row()
        ch = _box_ask("Движок", default="1")
        cfg["engine"] = "adguardhome" if ch == "2" else "oxidns"
        if cfg["engine"] == "oxidns" and env["arch"] != "x86_64":
            _box_warn(f"OxiDNS недоступен для {env['arch']} — беру AdGuardHome")
            cfg["engine"] = "adguardhome"
        _box_bottom()

    # 3) Домены
    _box_top("Домены и Cloudflare")
    while True:
        cfg["domain"] = _box_input("Основной домен (ROOT_DOMAIN)",
                                   default=cfg.get("domain") or "").lower()
        if validate_domain(cfg["domain"]):
            break
        _box_warn("Некорректный домен (пример: example.com)")
    default_dot = f"{st._random_lower(10)}.{cfg['domain']}"
    while True:
        cfg["dot_host"] = _box_input(
            f"Поддомен DoT (DOT_HOST, по умолчанию {default_dot})",
            default=default_dot).lower()
        if (validate_domain(cfg["dot_host"])
                and cfg["dot_host"].endswith("." + cfg["domain"])
                and cfg["dot_host"] != cfg["domain"]):
            break
        _box_warn(f"DOT_HOST должен быть валидным поддоменом *.{cfg['domain']}")
    import secrets as _s
    import string as _str
    cfg["doh_path"] = "".join(
        _s.choice(_str.ascii_letters + _str.digits) for _ in range(52))
    _box_info(f"Секретный путь DoH/web-auth сгенерирован "
              f"({len(cfg['doh_path'])} символов)")
    cfg["whitelist_enabled"] = "false"
    cfg["whitelist_mode"] = "shared"
    ans = _box_ask("Включить DoT IP-whitelist (853 только для "
                   "авторизованных)?", default="n")
    if ans.lower().startswith("y"):
        cfg["whitelist_enabled"] = "true"
        ans = _box_ask("Режим whitelist: 1-shared (общий с DoH) / "
                       "2-separate (отдельный для DoT)", default="1")
        cfg["whitelist_mode"] = "separate" if ans == "2" else "shared"
    cfg.setdefault("exclude_google_sys", True)
    ans = _box_ask("Добавить системные домены Google в GeoHide-список?",
                   default="y")
    cfg["exclude_google_sys"] = not ans.lower().startswith("y")
    cfg.setdefault("include_xbox_ipify", False)
    ans = _box_ask("Добавить домены Xbox/ipify?", default="n")
    cfg["include_xbox_ipify"] = ans.lower().startswith("y")

    # 4) Cloudflare
    secrets_ = load_secrets()
    cfg["cf_api_token"] = cfg.get("cf_api_token") or secrets_.get(
        "cf_api_token", "")
    if not cfg["cf_api_token"]:
        while True:
            cfg["cf_api_token"] = _box_input(
                "Cloudflare API Token (Zone:DNS:Edit)", reopen=False)
            if len(cfg["cf_api_token"]) >= 20:
                break
            _box_warn("Токен слишком короткий (<20)")
    cfg["acme_email"] = cfg.get("acme_email") or secrets_.get(
        "acme_email") or f"admin@{cfg['domain']}"
    cfg["acme_email"] = _box_input("ACME e-mail", default=cfg["acme_email"])
    cfg["server_ipv4"] = (cfg["bind_ip"] if cfg["mode"] == "companion"
                          else env["server_ipv4"])
    cfg["server_ipv6"] = "" if cfg["mode"] == "companion" else env.get(
        "server_ipv6", "")
    _box_bottom()

    # Сводка + подтверждение
    _box_top("Сводка установки SmartDNS")
    _box_kv("Режим", cfg["mode"] + (f" @ {cfg['bind_ip']}"
                                    if cfg.get("bind_ip") else ""))
    _box_kv("Движок", cfg["engine"])
    _box_kv("Домен", cfg["domain"])
    _box_kv("DoT-хост", cfg["dot_host"])
    _box_kv("Whitelist", f"{cfg['whitelist_enabled']} / "
                         f"{cfg['whitelist_mode']}")
    _box_kv("Порты", f"80, {PORT_DOT}, {PORT_DOH}, {PORT_WEB} + loopback")
    _box_row()
    _box_desc("На DoH-хост (это же cover-site) уйдут A/AAAA записи "
              "Cloudflare; выпускается wildcard-сертификат (DNS-01).")
    ans = _box_ask("Подтвердить установку", default="y")
    _box_bottom()
    return ans.lower().startswith("y")


# ══════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА / ОБНОВЛЕНИЕ / УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════

def install(cfg: dict) -> bool:
    """Полная транзакционная установка. Порядок как в bash run_install;
    провал любого шага → откат к бэкапу (rollback_backup)."""
    state = _load_state()
    if state.get("installed"):
        _err("SmartDNS уже установлен (см. status/uninstall)")
        return False
    ok, _rep = preflight(cfg)
    if not ok:
        _err("Preflight НЕ пройден — установка отменена")
        return False

    backup_dir = create_backup()
    try:
        _info(f"Установка SmartDNS v{STACK_VERSION} "
              f"({cfg['mode']}, движок {cfg['engine']})…")
        if not st.install_system_packages(
                companion=cfg["mode"] == "companion"):
            raise RuntimeError("packages")
        if not st.setup_users_and_dirs(cfg):
            raise RuntimeError("users")
        versions = st.install_binaries(cfg)
        if not versions:
            raise RuntimeError("binaries")
        cfg["_versions"] = versions
        save_settings(cfg)
        save_secrets(cfg)

        _info("Синхронизация DNS-записей Cloudflare…")
        st.sync_cloudflare_records(cfg, cfg["server_ipv4"],
                                   cfg.get("server_ipv6", "") or "")
        if not st.issue_wildcard_certificate(cfg):
            raise RuntimeError("certificate")

        if not st.write_xray_config(cfg):
            raise RuntimeError("xray-config")
        if not st.update_geosite(cfg):
            _warn("geosite.dat не скачался — таймер догонит ночью")
        if not st.update_geohide(cfg):
            raise RuntimeError("geohide")
        if not st.write_engine_config(cfg):
            raise RuntimeError("engine-config")
        save_secrets(cfg)     # agh_admin_user/pass могли появиться выше

        st.generate_cover_site(cfg)
        ok_nginx, why = st.apply_nginx(cfg)
        if not ok_nginx:
            raise RuntimeError(f"nginx: {why}")

        if not fw.write_watcher_scripts(cfg):
            raise RuntimeError("watchers")
        if not st.write_systemd_units(cfg):
            raise RuntimeError("units")
        if not st.enable_and_start(cfg):
            raise RuntimeError("start")
        if not fw.apply_firewall(cfg):
            raise RuntimeError("firewall")

        register_ports(cfg)

        ok_dns, report = st.verify_dns_backend(cfg)
        for line in report:
            _info(f"verify: {line}")
        if not ok_dns:
            _warn("Верификация движка не сошлась — см. отчёт выше "
                  "(фильтры могут собираться дольше минуты)")

        _save_state({
            **DEFAULT_STATE,
            "installed": True, "mode": cfg["mode"], "engine": cfg["engine"],
            "bind_ip": cfg.get("bind_ip"), "domain": cfg["domain"],
            "dot_host": cfg["dot_host"],
            "whitelist_enabled": cfg.get("whitelist_enabled", "false"),
            "whitelist_mode": cfg.get("whitelist_mode", "shared"),
            "versions": {k: v for k, v in versions.items() if v},
            "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                          time.gmtime()),
            "stack_version": STACK_VERSION,
        })
        _ok("SmartDNS установлен и запущен!")
        _print_install_summary(cfg, versions)
        return True
    except Exception as e:
        _err(f"Установка не удалась ({e}) — откат к состоянию до установки")
        st._log("ERR", f"install failed: {e}")
        rollback_backup(backup_dir)
        return False


def _print_install_summary(cfg: dict, versions: dict) -> None:
    doh_url = f"https://{cfg['domain']}/resolve/{cfg['doh_path']}"
    auth_url = f"https://{cfg['domain']}/auth/{cfg['doh_path']}"
    host = cfg["dot_host"]
    _box_top("SmartDNS — итоги установки")
    _box_kv("DoH", f"{doh_url}")
    _box_kv("Web-auth", f"{auth_url}  {DIM}(закладка: IP на 24ч){NC}")
    _box_kv("DoT", f"{host}:853 (TLS)")
    _box_kv("Версии", f"xray {versions.get('xray', '?')}, "
                      f"движок {versions.get(cfg['engine'], '?')}")
    if cfg.get("bind_ip"):
        _box_kv("Bind IP", cfg["bind_ip"])
    _box_row()
    _box_desc("Клиент: DNS приложения → DoH-URL выше (или Private DNS: "
              "hostname DoT). Хром/Android-Private-DNS-пользователям "
              "сначала открыть web-auth ссылку из нужной сети.")
    _box_bottom()


def update() -> bool:
    """Ручное обновление (CLI/TUI): компоненты к последнему release
    (сравнение версий — как auto_update B4), geo-списки, сертификат,
    перегенерация firewall-скрипта (настройки могли измениться)."""
    state = _load_state()
    if not state.get("installed"):
        _err("SmartDNS не установлен")
        return False
    cfg = load_settings() or {}
    cfg.update({k: state.get(k) for k in
                ("mode", "engine", "bind_ip", "domain", "dot_host",
                 "whitelist_enabled", "whitelist_mode")})
    cfg.update(load_secrets())
    cfg.setdefault("server_ipv4", detect_environment()["server_ipv4"])
    create_backup()

    _info("Обновление компонентов к последним release-версиям…")
    latest = st.resolve_component_versions(net_probe=True)
    installed = state.get("versions", {})
    engine_key = "oxidns" if cfg.get("engine") == "oxidns" else "agh"
    changed = []
    for comp, tag in latest.items():
        if comp not in ("xray", engine_key):
            continue            # не наш движок (agh при oxidns и наоборот)
        if not tag:
            continue            # oxidns на не-x86_64 — резолвер вернул ''
        old = installed.get(comp, "")
        if not (not old or version_key(old) < version_key(tag)):
            continue            # установленное свежее или равно
        ok = (st.install_xray_binary(tag) if comp == "xray"
              else st.install_oxidns_binary(tag) if comp == "oxidns"
              else st.install_agh_binary(tag))
        if ok:
            changed.append(f"{comp}: {old or '—'} → {tag}")

    st.update_geosite(cfg)
    st.update_geohide(cfg)
    st.issue_wildcard_certificate(cfg)
    st.write_xray_config(cfg)
    st.write_engine_config(cfg)
    fw.write_watcher_scripts(cfg)
    st.enable_and_start(cfg)

    new_versions = dict(installed)
    for comp, tag in latest.items():
        if tag:
            new_versions[comp] = tag
    state["versions"] = new_versions
    state["stack_version"] = STACK_VERSION
    _save_state(state)

    _box_top("SmartDNS — Update")
    if changed:
        for line in changed:
            _box_row(f"  {GREEN}{line}{NC}")
    else:
        _box_row(f"  {GREEN}Компоненты актуальны{NC}"
                 f"  {DIM}(xray {installed.get('xray', '?')}){NC}")
    _box_bottom()
    return True


def uninstall(purge: bool = False) -> bool:
    """Остановка и снятие стека. Порт/правила/юниты/drop-in'ы — всегда;
    файлы (binaries/конфиги/state/бэкапы) — только при purge=True."""
    state = _load_state()
    if not state.get("installed"):
        _err("SmartDNS не установлен")
        return False
    cfg = load_settings() or {}
    cfg.update({k: state.get(k) for k in
                ("mode", "engine", "bind_ip", "whitelist_enabled",
                 "whitelist_mode")})

    _info("Удаление SmartDNS-стека…")
    create_backup()
    st.stop_and_disable(cfg)
    st.remove_units()
    fw.remove_firewall(cfg)
    st.remove_nginx_dropins()
    unregister_ports(cfg)
    if purge:
        for d in (st.SMARTDNS_BASE, st.CONF_ROOT, st.CERT_DIR, st.WEB_ROOT,
                  st.ASSETS_DIR, st.XRAY_LOG_DIR):
            shutil.rmtree(d, ignore_errors=True)
        STATE_FILE.unlink(missing_ok=True)
        st.SETTINGS_FILE.unlink(missing_ok=True)
        st.SECRETS_FILE.unlink(missing_ok=True)
        _ok("Файлы стека удалены (бэкапы: "
            f"{st.BACKUP_ROOT})")
    else:
        _save_state({**state, "installed": False})
        _ok(f"Стек остановлен и снят (файлы сохранены; бэкапы: "
            f"{st.BACKUP_ROOT})")
    return True


# ══════════════════════════════════════════════════════════════════════════
#  BACKUP / ROLLBACK
# ══════════════════════════════════════════════════════════════════════════

def create_backup() -> Optional[Path]:
    """tar.gz конфигураций стека: settings/secrets/units/xray/engine/
    nginx-dropins/cert. Возвращает путь к архиву (для rollback)."""
    ts = time.strftime("%Y%m%d-%H%M%S")
    st.BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    out = st.BACKUP_ROOT / f"smartdns-{ts}.tar.gz"
    sources = []
    for p in (st.SETTINGS_FILE, st.SECRETS_FILE, STATE_FILE,
              st.NGINX_HTTP_DROPIN, st.NGINX_STREAM_DROPIN,
              st.XRAY_CONF_DIR, st.XRAY_RULES_DIR, st.OXIDNS_CONF_DIR,
              st.AGH_CONF_DIR, st.CERT_DIR, st.IPSET_SAVE_FILE):
        if p.exists():
            sources.append(p)
    try:
        with tarfile.open(out, "w:gz") as tf:
            for p in sources:
                tf.add(str(p), arcname=str(p).lstrip("/"), recursive=True)
        os.chmod(out, 0o600)
        _ok(f"Бэкап: {out}")
        return out
    except Exception as e:
        _warn(f"Бэкап не создан: {e}")
        return None


def rollback_backup(archive: Optional[Path] = None) -> bool:
    """Восстановление из бэкапа (последний или указанный)."""
    if archive is None:
        archives = sorted(st.BACKUP_ROOT.glob("smartdns-*.tar.gz"))
        if not archives:
            _warn("Бэкапов нет — откатывать нечего")
            return False
        archive = archives[-1]
    if not Path(archive).exists():
        _err(f"Архив не найден: {archive}")
        return False
    try:
        with tarfile.open(archive, "r:gz") as tf:
            tf.extractall("/")     # пути абсолютные (без ведущего /)
        _ok(f"Откат выполнен из {archive}")
        return True
    except Exception as e:
        _err(f"Откат не удался: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════
#  STATUS / LATEST-КЭШ (паттерн B4: сводка «доступно новое» в шапке)
# ══════════════════════════════════════════════════════════════════════════

def _refresh_latest_cache(force: bool = False) -> dict:
    """Кэш latest-версий компонентов (TTL 6ч ok / 30м fail — как B4)."""
    state = _load_state()
    ttl = _LATEST_TTL_OK if state.get("latest_check_ok") else _LATEST_TTL_FAIL
    checked_at = float(state.get("latest_checked_at", 0) or 0)
    if (not force and checked_at and 0 <= time.time() - checked_at < ttl):
        return state
    if not state.get("installed"):
        return state
    latest = {"xray": st.github_latest_tag(*st.XRAY_REPO),
              "oxidns": st.github_latest_tag(*st.OXIDNS_REPO),
              "agh": st.github_latest_tag(*st.AGH_REPO)}
    ok = any(latest.values())
    if ok:
        state["latest_versions"] = latest
    state["latest_checked_at"] = time.time()
    state["latest_check_ok"] = ok
    _save_state(state)
    return state


def update_availability(state: "Optional[dict]" = None) -> dict:
    """Сводка «есть ли что обновлять» (без сети, по кэшу)."""
    state = state or _load_state()
    installed = state.get("versions", {})
    latest = state.get("latest_versions", {})
    if not latest:
        return {"known": False, "updates": []}
    updates = []
    for comp, tag in latest.items():
        old = installed.get(comp, "")
        if tag and (not old or version_key(old) < version_key(tag)):
            updates.append(f"{comp} {old or '?'} → {tag}")
    return {"known": True, "updates": updates}


def _services_state(cfg: dict) -> list:
    from chimera.modules import smartdns_stack as _st
    engine = _st._engine_unit(cfg) if cfg.get("engine") else _st.UNIT_OXIDNS
    units = [engine, _st.UNIT_XRAY, "nginx", _st.UNIT_FW,
             _st.UNIT_DOH_WATCH, _st.UNIT_DOT_WATCH,
             _st.UNIT_GEOSITE_TMR, _st.UNIT_GEOHIDE_TMR]
    out = []
    for u in units:
        r = subprocess.run(["systemctl", "is-active", u],
                           capture_output=True, text=True, check=False)
        out.append((u, (r.stdout or "").strip() or "inactive"))
    return out


def show_status() -> None:
    """Box-статус: режим, сервисы, порты+bind, версии, whitelist, сертификат."""
    state = _load_state()
    cfg = load_settings() or {}
    cfg.update({k: state.get(k) for k in
                ("mode", "engine", "bind_ip", "whitelist_enabled",
                 "whitelist_mode", "domain", "dot_host")})
    state = _refresh_latest_cache()
    avail = update_availability(state)

    _box_top("SmartDNS — Status")
    if not state.get("installed"):
        _box_row(f"  Стек: {RED}не установлен{NC}  "
                 f"{DIM}(установка — пункт меню [1] / install){NC}")
        _box_bottom()
        return
    _box_kv("Режим", f"{state['mode']}"
            + (f"  {DIM}bind {state['bind_ip']}{NC}" if state.get("bind_ip")
               else ""))
    _box_kv("Домены", f"{state.get('domain', '?')} / "
                      f"{state.get('dot_host', '?')}")
    _box_row()
    for unit, active in _services_state(cfg):
        color = GREEN if active == "active" else RED
        _box_row(f"  {unit:<44} {color}{active}{NC}")
    _box_row()
    bind = f"@{state['bind_ip']}" if state.get("bind_ip") else ""
    _box_kv("Порты", f"80{bind}, 853{bind}, 8444{bind}, 9443{bind} "
                     f"{DIM}+ loopback 5353/8053/8853/9444{NC}")
    v = state.get("versions", {})
    _box_kv("Версии", f"xray {v.get('xray', '?')} · движок "
                      f"{v.get(state.get('engine') or 'oxidns', '?')}")
    _box_kv("Стек", f"v{state.get('stack_version', '?')} "
                    f"(установлен {state.get('installed_at', '?')})")
    if avail["known"]:
        if avail["updates"]:
            _box_row(f"  Обновление:   {YELLOW}{BOLD}"
                     f"{'; '.join(avail['updates'])}{NC}  {DIM}→ [3]{NC}")
        else:
            _box_row(f"  Обновление:   {GREEN}нет — актуально{NC}")
    else:
        _box_row(f"  Обновление:   {DIM}не проверено{NC}")
    cert = st.CERT_DIR / "fullchain.pem"
    if cert.exists():
        r = subprocess.run(["openssl", "x509", "-in", str(cert), "-noout",
                            "-enddate"], capture_output=True, text=True,
                           check=False)
        exp = (r.stdout or "").strip().replace("notAfter=", "")
        _box_kv("Сертификат", exp or "?")
    wl = fw.whitelist_status(cfg)
    _box_kv("Whitelist", f"{wl['enabled']} / {wl['mode']} · "
                         f"IPv4: {len(wl['v4'])}, IPv6: {len(wl['v6'])}")
    _box_bottom()


# ══════════════════════════════════════════════════════════════════════════
#  TUI-МЕНЮ
# ══════════════════════════════════════════════════════════════════════════

def do_smartdns_menu() -> None:
    """Меню модуля (вызов из _core.py: Настройки сети → SD)."""
    while True:
        state = _refresh_latest_cache()
        avail = update_availability(state)
        _box_top("SmartDNS — DoH/DoT Stealth + SNI Proxy")
        _box_row(f"  Стек: "
                 f"{'установлен' if state.get('installed') else 'не установлен'}"
                 f"  {DIM}v{state.get('stack_version', STACK_VERSION)}"
                 f"{'' if state.get('installed') else ' — режимы: standalone/'}"
                 f"{'companion' if not state.get('installed') else ''}{NC}")
        if avail["known"] and avail["updates"]:
            _box_row(f"  Обновление: {YELLOW}{BOLD}"
                     f"{'; '.join(avail['updates'])}{NC}  {DIM}→ [3]{NC}")
        _box_sep()
        _box_item("1", "🛰  Установить  "
                       f"{DIM}(режимы: отдельный VPS / второй IP){NC}")
        _box_item("2", "📋 Статус стека")
        _box_item("3", "🔄 Обновить компоненты")
        _box_item("4", "🔐 DoT/DoH whitelist  "
                       f"{DIM}(добавить/убрать/режим){NC}")
        _box_item("5", "🗄  Бэкап / откат")
        _box_item("6", "🧹 Удалить стек")
        _box_row()
        _box_desc("DoH: https://<domain>/resolve/<SECRET> · DoT: 853/TLS · "
                  "маскировка: cover-site + SNI-прокси 8444")
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            break
        if ch in ("q", "0", ""):
            break
        elif ch == "1":
            cfg = {"mode": None, "engine": "oxidns"}
            if run_wizard(cfg):
                install(cfg)
            input(f"{CYAN}Enter — продолжить{NC}")
        elif ch == "2":
            show_status()
            input(f"{CYAN}Enter — продолжить{NC}")
        elif ch == "3":
            update()
            _refresh_latest_cache(force=True)
            input(f"{CYAN}Enter — продолжить{NC}")
        elif ch == "4":
            _whitelist_menu()
        elif ch == "5":
            _backup_menu()
        elif ch == "6":
            ans = _box_ask("Точно удалить стек SmartDNS?", default="n")
            if ans.lower().startswith("y"):
                purge = _box_ask("Удалить и файлы (binaries/конфиги)?",
                                 default="n").lower().startswith("y")
                uninstall(purge=purge)
            input(f"{CYAN}Enter — продолжить{NC}")
        else:
            _box_warn("Неверный выбор")
            time.sleep(1)


def _whitelist_menu() -> None:
    state = _load_state()
    cfg = load_settings() or {}
    cfg.update({k: state.get(k) for k in
                ("mode", "engine", "bind_ip", "whitelist_enabled",
                 "whitelist_mode")})
    while True:
        wl = fw.whitelist_status(cfg)
        _box_top("SmartDNS — DoT/DoH Whitelist (ipset, TTL 24ч)")
        _box_kv("Фильтр 853", wl["enabled"])
        _box_kv("Режим", wl["mode"])
        _box_kv("IPv4", f"{len(wl['v4'])} адрес(ов)")
        for ip in wl["v4"][:10]:
            _box_row(f"    {ip}")
        if len(wl["v4"]) > 10:
            _box_row(f"    {DIM}… и ещё {len(wl['v4']) - 10}{NC}")
        _box_kv("IPv6", f"{len(wl['v6'])} адрес(ов)")
        _box_sep()
        _box_item("1", "➕ Добавить IP (24ч)")
        _box_item("2", "➖ Удалить IP")
        _box_item("3", "🧽 Очистить всё")
        _box_item("4", f"⏯  Фильтр 853: вкл/выкл")
        _box_item("5", f"🔀 Режим: shared/separate")
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return
        if ch in ("q", "0", ""):
            return
        if ch == "1":
            ip = _box_input("IPv4/IPv6")
            fw.whitelist_add(cfg, ip)
        elif ch == "2":
            ip = _box_input("IPv4/IPv6")
            fw.whitelist_remove(cfg, ip)
        elif ch == "3":
            fw.whitelist_flush(cfg)
        elif ch == "4":
            on = str(wl["enabled"]).lower() != "true"
            fw.whitelist_toggle(cfg, on)
            cfg["whitelist_enabled"] = "true" if on else "false"
        elif ch == "5":
            m = _box_ask("Режим (shared|separate)",
                         default="shared" if wl["mode"] != "separate"
                         else "separate")
            fw.whitelist_set_mode(cfg, m)
            cfg["whitelist_mode"] = m
        time.sleep(1)


def _backup_menu() -> None:
    while True:
        archives = sorted(st.BACKUP_ROOT.glob("smartdns-*.tar.gz"))
        _box_top("SmartDNS — Бэкап / Откат")
        _box_desc(f"Каталог: {st.BACKUP_ROOT} · архивов: {len(archives)}")
        for a in archives[-5:]:
            _box_row(f"    {a.name}  {DIM}{a.stat().st_size // 1024} KB{NC}")
        _box_sep()
        _box_item("1", "💾 Создать бэкап сейчас")
        if archives:
            _box_item("2", f"⏪ Откат к последнему "
                           f"({archives[-1].name.split('-')[1]})")
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return
        if ch in ("q", "0", ""):
            return
        if ch == "1":
            create_backup()
        elif ch == "2" and archives:
            ans = _box_ask(f"Откатить {archives[-1].name}?", default="n")
            if ans.lower().startswith("y"):
                rollback_backup(archives[-1])
        time.sleep(1)


# ══════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════

_USAGE = """Использование: python3 -m chimera.modules.smartdns <команда> [аргументы]

Команды:
  install [--mode standalone|companion] [--bind-ip IP] [--domain DOM]
          [--dot-host HOST] [--engine oxidns|adguardhome]
          [--cf-token TOKEN] [--acme-email EMAIL] [--non-interactive]
                                        Установка (без флагов — интерактивный визард)
  preflight [--mode ...] [--bind-ip IP]   Проверка готовности (read-only)
  status                                  Текущее состояние стека
  update                                  Обновить компоненты к последним release
  uninstall [--purge]                     Снять стек (с файлами при --purge)
  backup | rollback [PATH]                Бэкап конфигураций / откат
  whitelist add|remove IP | flush | toggle [on|off] | mode [shared|separate] | status
  menu                                    Интерактивное TUI-меню

Пример (companion на ноде Химеры со вторым IP):
  python3 -m chimera.modules.smartdns install --mode companion \\
      --bind-ip 203.0.113.7 --domain example.com --cf-token TOKEN --non-interactive
"""


def _cli() -> int:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(_USAGE)
        return 0
    cmd = args[0]
    if os.geteuid() != 0 and cmd not in ("status", "menu"):
        print("[ERR] Требуется root (sudo)")
        return 1

    if cmd == "menu":
        do_smartdns_menu()
        return 0
    if cmd == "status":
        show_status()
        return 0
    if cmd == "backup":
        return 0 if create_backup() else 1
    if cmd == "rollback":
        return 0 if rollback_backup(
            Path(args[1]) if len(args) > 1 else None) else 1

    if cmd == "whitelist":
        state = _load_state()
        if not state.get("installed"):
            print("[ERR] SmartDNS не установлен")
            return 1
        cfg = load_settings() or {}
        cfg.update({k: state.get(k) for k in
                    ("mode", "engine", "bind_ip", "whitelist_enabled",
                     "whitelist_mode")})
        sub = args[1] if len(args) > 1 else "status"
        if sub == "add" and len(args) > 2:
            return 0 if fw.whitelist_add(cfg, args[2]) else 1
        if sub == "remove" and len(args) > 2:
            return 0 if fw.whitelist_remove(cfg, args[2]) else 1
        if sub == "flush":
            return 0 if fw.whitelist_flush(cfg) else 1
        if sub == "toggle":
            on = (args[2].lower().startswith("y") if len(args) > 2
                  and args[2].lower().startswith(("y", "n"))
                  else str(cfg.get("whitelist_enabled")).lower() != "true")
            return 0 if fw.whitelist_toggle(cfg, on) else 1
        if sub == "mode":
            m = args[2] if len(args) > 2 else ""
            if m not in ("shared", "separate"):
                print("[ERR] mode: shared|separate")
                return 1
            return 0 if fw.whitelist_set_mode(cfg, m) else 1
        if sub == "status":
            wl = fw.whitelist_status(cfg)
            print(json.dumps(wl, indent=2, ensure_ascii=False))
            return 0
        print(_USAGE)
        return 2

    if cmd == "update":
        return 0 if update() else 1
    if cmd == "uninstall":
        return 0 if uninstall(purge="--purge" in args) else 1

    if cmd in ("install", "preflight"):
        cfg = {"engine": "oxidns", "mode": None}
        i = 1
        while i < len(args):
            a = args[i]
            def _val(j: int = i + 1) -> str:
                return args[j] if j < len(args) else ""
            if a == "--mode":
                cfg["mode"] = _val()
            elif a == "--bind-ip":
                cfg["bind_ip"] = _val()
            elif a == "--domain":
                cfg["domain"] = _val()
            elif a == "--dot-host":
                cfg["dot_host"] = _val()
            elif a == "--engine":
                cfg["engine"] = _val()
            elif a == "--cf-token":
                cfg["cf_api_token"] = _val()
            elif a == "--acme-email":
                cfg["acme_email"] = _val()
            i += 1
        non_interactive = "--non-interactive" in args

        if cfg["mode"] == "companion":
            cfg["engine"] = "oxidns"       # AGH запрещён в companion
        if non_interactive:
            if not cfg.get("domain") or not validate_domain(cfg["domain"]):
                print("[ERR] --domain обязателен и должен быть валиден")
                return 1
            if cfg["mode"] == "companion" and not cfg.get("bind_ip"):
                print("[ERR] companion требует --bind-ip")
                return 1
            if not cfg.get("cf_api_token"):
                print("[ERR] --cf-token обязателен (--non-interactive)")
                return 1
            cfg.setdefault("dot_host",
                           f"{st._random_lower(10)}.{cfg['domain']}")
            import secrets as _s
            import string as _str
            cfg["doh_path"] = "".join(
                _s.choice(_str.ascii_letters + _str.digits)
                for _ in range(52))
            cfg.setdefault("whitelist_enabled", "false")
            cfg.setdefault("whitelist_mode", "shared")
            cfg.setdefault("exclude_google_sys", True)
            cfg.setdefault("include_xbox_ipify", False)
            env = detect_environment()
            ok_ip, why = validate_bind_ip(cfg, env)
            if cfg["mode"] == "companion" and not ok_ip:
                print(f"[ERR] {why}")
                return 1
            cfg["server_ipv4"] = (cfg["bind_ip"]
                                  if cfg["mode"] == "companion"
                                  else env["server_ipv4"])
            cfg["server_ipv6"] = ("" if cfg["mode"] == "companion"
                                  else env.get("server_ipv6", ""))
            cfg.setdefault("acme_email", f"admin@{cfg['domain']}")
        else:
            if not run_wizard(cfg):
                print("Отменено")
                return 1

        if cmd == "preflight":
            ok, rep = preflight(cfg, quiet=False)
            return 0 if ok else 1
        return 0 if install(cfg) else 1

    print(_USAGE)
    return 2


if __name__ == "__main__":
    raise SystemExit(_cli())
