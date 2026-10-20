#!/usr/bin/env python3
"""chimera-remote-cmd.py — standalone command executor for cascade admin.

Используется primary admin-ботом (chimera/modules/tg_bot.py) для
выполнения команд на remote-серверах через SSH. Возвращает результат
как JSON-строку на stdout.

Usage:
    chimera-remote-cmd.py <command> [args...]

Commands (whitelist — безопасные, без shutdown/reboot):
    ban <ip|cidr|mask>       — ban IP/CIDR/маски (176.9.*.*) в xray_manual_ban(_6)
    unban <ip|cidr|mask>     — unban (тот же формат)
    banlist                 — список забаненных (v4+v6, IP и CIDR)
    whitelist               — whitelist: clients_wl_v4/v6 + autoban.json
    wl_add <ip|cidr|mask>   — dual-write: clients_wl_* + autoban whitelist
    wl_del <ip|cidr|mask>   — удалить из обоих
    geo                     — geoip status (ipset counts + iptables rule)
    f2b                     — fail2ban status (jails + banned counts)
    restart <service>       — systemctl restart (whitelist: xray/nginx/
                              dnscrypt/agh/adguardhome/fail2ban/warp)
    reload_nginx            — nginx -s reload
    logs <service> [n]      — tail -n N from log
                              services: xray, xray_acc, nginx, nginx_acc,
                              chimera, fail2ban, dnscrypt, system
    users                   — list users (from /etc/xray/config.json)
    users_active            — active users (from /var/log/xray/access.log)
    user <email>            — user details (UUID, flow, TTL, limits)
    traffic [n]             — top N users by access.log email mentions
    status                  — same as chimera-remote-status.py (host+xray+state)
    version                 — git commit + hostname + uptime

Output: single JSON line on stdout:
    {"ok": true, "output": "<result_string>"}
    {"ok": false, "error": "<error_message>"}

Exit codes:
    0 — command executed (check 'ok' field for success)
    1 — invalid usage / unknown command
    2 — argument validation failed
"""
import ipaddress
import json
import os
import subprocess
import sys
from pathlib import Path

# Whitelist сервисов для /restart (безопасные — никаких shutdown/reboot).
ALLOWED_RESTART_SERVICES = {
    "xray":         ("systemctl", "restart", "xray"),
    "nginx":        ("systemctl", "restart", "nginx"),
    "dnscrypt":     ("systemctl", "restart", "dnscrypt-proxy"),
    "agh":          ("systemctl", "restart", "AdGuardHome"),
    "adguardhome":  ("systemctl", "restart", "AdGuardHome"),
    "fail2ban":     ("systemctl", "restart", "fail2ban"),
    "warp":         ("systemctl", "restart", "wg-quick@wg-warp"),
}

LOG_PATHS = {
    "xray":     "/var/log/xray/error.log",
    "xray_acc": "/var/log/xray/access.log",
    "nginx":    "/var/log/nginx/error.log",
    "nginx_acc":"/var/log/nginx/access.log",
    "chimera":  "/var/log/chimera.log",
    "fail2ban": "/var/log/fail2ban.log",
    "dnscrypt": "/var/log/dnscrypt-proxy.log",
    "system":   "/var/log/syslog",
}

STATE_FILE = Path("/var/lib/xray-installer/state.json")
AUTOBAN_FILE = Path("/var/lib/xray-installer/autoban.json")

# Актуальные имена ipset-сетов (user_ip_whitelist создаёт clients_wl_v4/v6;
# старый monolithic clients_wl больше не существует — TG-команды wl_* раньше
# писали в осиротевший сет, фикс ipmask-1).
WL_V4 = "clients_wl_v4"
WL_V6 = "clients_wl_v6"
BAN_V4 = "xray_manual_ban"
BAN_V6 = "xray_manual_ban6"


def _normalize_ip_input(ip_str):
    """IP / CIDR / wildcard-маска → канонический токен или None.

    Маска хвостовых октетов (звёздочка = «этот и все следующие октеты не
    фиксированы»): 176.9.*.* → 176.9.0.0/16, 152.65.*.* →
    152.65.0.0/16, 176.9.40.* → 176.9.40.0/24, 176.9.* → 176.9.0.0/16,
    176.* → 176.0.0.0/8.
    Значения октетов — любые (0-255), примеры не хардкодятся.
    Запрещены: *.*.*.* (весь интернет), звёздочки в середине (176.*.9.1),
    IPv6-маски, пустые октеты (176..9.*.*).
    SYNC: chimera/modules/ip_mask.py (канонические правила) +
          chimera/modules/tg_bot.py (_normalize_ip_input в шаблоне бота).
    """
    if not ip_str or not isinstance(ip_str, str):
        return None
    v = ip_str.strip()
    if not v:
        return None
    if "*" in v:
        if ":" in v or "/" in v:
            return None
        parts = v.split(".")
        if len(parts) > 4:
            return None
        parts = parts + ["*"] * (4 - len(parts))
        base = []
        for p in parts:
            if p == "*":
                break
            if not p.isdigit() or int(p) > 255:
                return None
            base.append(int(p))
        if not base or len(base) >= 4:
            return None
        if any(p != "*" for p in parts[len(base):]):
            return None
        return (".".join(str(x) for x in base) +
                ".0" * (4 - len(base)) + "/" + str(8 * len(base)))
    try:
        if "/" in v:
            return str(ipaddress.ip_network(v, strict=False))
        return str(ipaddress.ip_address(v))
    except ValueError:
        return None


def _validate_ip(ip_str):
    """Валидация IP / CIDR / маски (176.9.*.*). True/False."""
    return _normalize_ip_input(ip_str) is not None


def _is_v6(token):
    """True если токен — IPv6 (CIDR или адрес)."""
    return ":" in token


def _parse_member_line(line):
    """Строка из `ipset list` → (token, is_v6) или None.

    Принимает IP и CIDR (v4+v6) — раньше фильтр был строгим IPv4-regex и
    CIDR-баны из TUI не были видны в TG /banlist (фикс ipmask-1, баг #2).
    Строки заголовка ipset (Name:/Type:/Header:/members:) не парсятся
    как сети → отсекаются.
    """
    tok = line.strip()
    if not tok:
        return None
    try:
        net = ipaddress.ip_network(tok, strict=False)
    except ValueError:
        return None
    # Одиночный адрес показываем без навязанного /32 (читаемость в TG)
    if "/" not in tok and net.num_addresses == 1:
        return str(net.network_address), net.version == 6
    return str(net), net.version == 6


def _load_state():
    try:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text())
    except Exception:
        pass
    return {}


def _run(cmd, timeout=30):
    """Запуск команды, возвращает (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except Exception as e:
        return -1, "", str(e)


def _save_ipset():
    """Сохраняет все ipset в /etc/ipset.conf."""
    subprocess.run("ipset save > /etc/ipset.conf", shell=True, timeout=10,
                   stdout=open("/dev/null", "w"), stderr=open("/dev/null", "w"))


# ── Команды ───────────────────────────────────────────────────────────────────

def _ban_set_for(token):
    """xray_manual_ban (v4) или xray_manual_ban6 (v6) по токену."""
    return BAN_V6 if _is_v6(token) else BAN_V4


def cmd_ban(ip):
    token = _normalize_ip_input(ip)
    if not token:
        return False, (f"Invalid IP/CIDR/mask: {ip} "
                       f"(примеры: 1.2.3.4, 10.0.0.0/24, 176.9.*.*)")
    target = _ban_set_for(token)
    rc, out, err = _run(["ipset", "add", target, token, "-exist"], timeout=10)
    if rc == 0:
        _save_ipset()
        return True, f"{token} added to {target} (saved to /etc/ipset.conf)"
    if "already in set" in err.lower():
        return True, f"{token} already in {target}"
    return False, f"ipset add failed (exit={rc}): {err.strip()[:200]}"


def cmd_unban(ip):
    token = _normalize_ip_input(ip)
    if not token:
        return False, (f"Invalid IP/CIDR/mask: {ip} "
                       f"(примеры: 1.2.3.4, 10.0.0.0/24, 176.9.*.*)")
    target = _ban_set_for(token)
    rc, out, err = _run(["ipset", "del", target, token], timeout=10)
    if rc == 0:
        _save_ipset()
        return True, f"{token} removed from {target}"
    if "not in set" in err.lower():
        return True, f"{token} not in {target} (already unban)"
    return False, f"ipset del failed (exit={rc}): {err.strip()[:200]}"


def cmd_banlist():
    """Оба сета (v4+v6), члены — IP и CIDR (фикс ipmask-1, баг #2)."""
    entries = []
    for name in (BAN_V4, BAN_V6):
        rc, out, err = _run(["ipset", "list", name], timeout=10)
        if rc != 0:
            continue  # сета нет (например, v6 не создан) — не ошибка
        for l in out.split("\n"):
            parsed = _parse_member_line(l)
            if parsed:
                entries.append(f"{parsed[0]}  [{name}]")
    if not entries:
        return True, f"{BAN_V4}/{BAN_V6}: empty (no banned entries)"
    out_top = "\n".join(entries[:50])
    suffix = f"\n... and {len(entries)-50} more" if len(entries) > 50 else ""
    return True, f"manual ban ({len(entries)} entries):\n{out_top}{suffix}"


def _wl_set_for(token):
    """clients_wl_v4 или clients_wl_v6 по токену."""
    return WL_V6 if _is_v6(token) else WL_V4


def _autoban_wl_read():
    """Читает whitelist из autoban.json (для dual-write wl_add)."""
    try:
        if AUTOBAN_FILE.exists():
            cfg = json.loads(AUTOBAN_FILE.read_text())
            wl = cfg.get("whitelist")
            if isinstance(wl, list):
                return cfg, [str(x) for x in wl]
    except Exception:
        pass
    return {}, []


def _autoban_wl_write(cfg, wl):
    """Аккуратно дописывает whitelist в autoban.json (не трогая остальные поля)."""
    try:
        if AUTOBAN_FILE.exists():
            base = json.loads(AUTOBAN_FILE.read_text())
        else:
            base = cfg if isinstance(cfg, dict) else {}
        if not isinstance(base.get("whitelist"), list):
            base["whitelist"] = ["127.0.0.1", "::1"]
        base["whitelist"] = sorted(set(str(x) for x in wl))
        AUTOBAN_FILE.write_text(json.dumps(base, indent=2, ensure_ascii=False))
        return True
    except Exception:
        return False


def cmd_whitelist():
    """Whitelist: клиенты (clients_wl_v4/v6) + autoban-защита (autoban.json).

    Фикс ipmask-1 (баг #1): раньше читался осиротевший сет clients_wl.
    """
    lines = []
    total = 0
    for name in (WL_V4, WL_V6):
        rc, out, err = _run(["ipset", "list", name], timeout=10)
        if rc != 0:
            continue
        members = []
        for l in out.split("\n"):
            parsed = _parse_member_line(l)
            if parsed:
                members.append(parsed[0])
        if members:
            lines.append(f"{name} ({len(members)}):")
            lines.extend("  " + m for m in members)
            total += len(members)
    cfg, ab_wl = _autoban_wl_read()
    if ab_wl:
        lines.append(f"autoban-whitelist ({len(ab_wl)}):")
        lines.extend("  " + m for m in ab_wl)
        total += len(ab_wl)
    if not lines:
        return True, "whitelist: empty (no clients_wl_*, no autoban entries)"
    return True, f"whitelist ({total} entries):\n" + "\n".join(lines)


def cmd_wl_add(ip):
    """Dual-write: clients_wl_v4/v6 (доступ к порту xray) + autoban.json
    whitelist (защита от автобана — как обещает /help бота).

    Нюанс: клиенты-сеть пересобирается cron'ом из users.json
    (per-user whitelist) — прямая ipset-запись может уйти при пересборке;
    autoban-запись персистентна.
    """
    token = _normalize_ip_input(ip)
    if not token:
        return False, (f"Invalid IP/CIDR/mask: {ip} "
                       f"(примеры: 1.2.3.4, 10.0.0.0/24, 176.9.*.*)")
    target = _wl_set_for(token)
    msgs = []
    rc, out, err = _run(["ipset", "add", target, token, "-exist"], timeout=10)
    if rc == 0 or "already" in err.lower():
        _save_ipset()
        msgs.append(f"{token} added to {target}")
    else:
        # Сет может не существовать (модуль per-user WL не ставился) — создаём.
        family = "inet6" if _is_v6(token) else "inet"
        rc2, out2, err2 = _run(["ipset", "create", target, "hash:net",
                                "family", family, "maxelem", "100000", "-exist"],
                               timeout=10)
        rc3, out3, err3 = _run(["ipset", "add", target, token, "-exist"], timeout=10)
        if rc3 == 0:
            _save_ipset()
            msgs.append(f"{token} added to {target} (set created)")
        else:
            msgs.append(f"WARN ipset: {err3.strip()[:120]}")
    cfg, ab_wl = _autoban_wl_read()
    if token not in ab_wl:
        ab_wl.append(token)
        if _autoban_wl_write(cfg, ab_wl):
            msgs.append("autoban-whitelist: добавлено (персистентно)")
        else:
            msgs.append("WARN autoban.json: не записан")
    else:
        msgs.append("autoban-whitelist: уже есть")
    return True, "\n".join(msgs)


def cmd_wl_del(ip):
    token = _normalize_ip_input(ip)
    if not token:
        return False, (f"Invalid IP/CIDR/mask: {ip} "
                       f"(примеры: 1.2.3.4, 10.0.0.0/24, 176.9.*.*)")
    target = _wl_set_for(token)
    msgs = []
    rc, out, err = _run(["ipset", "del", target, token], timeout=10)
    if rc == 0:
        _save_ipset()
        msgs.append(f"{token} removed from {target}")
    else:
        msgs.append(f"{target}: not present")
    cfg, ab_wl = _autoban_wl_read()
    if token in ab_wl:
        ab_wl.remove(token)
        _autoban_wl_write(cfg, ab_wl)
        msgs.append("autoban-whitelist: удалено")
    return True, "\n".join(msgs)


def cmd_geo():
    # IPv4 count
    rc4, out4, _ = _run(["ipset", "list", "xray_ru_block"], timeout=10)
    v4_count = sum(1 for l in out4.split("\n") if _parse_member_line(l)) if rc4 == 0 else 0
    # IPv6 count
    rc6, out6, _ = _run(["ipset", "list", "xray_ru_block6"], timeout=10)
    v6_count = sum(1 for l in out6.split("\n")
                   if _parse_member_line(l) and _parse_member_line(l)[1]) if rc6 == 0 else 0
    # iptables rule
    rc_ipt, out_ipt, _ = _run(["iptables", "-S", "INPUT"], timeout=10)
    has_rule = "xray_ru_block" in out_ipt if rc_ipt == 0 else False
    return True, (f"Ingress GeoIP:\n"
                  f"  IPv4 blocked: {v4_count} CIDR\n"
                  f"  IPv6 blocked: {v6_count} CIDR\n"
                  f"  iptables rule: {'✅ installed' if has_rule else '❌ MISSING'}")


def cmd_f2b():
    rc, out, err = _run(["fail2ban-client", "status"], timeout=15)
    if rc != 0:
        return False, f"fail2ban-client not running: {err.strip()[:200]}"
    try:
        jails = out.strip().split(",")[-1].strip().split()
    except Exception:
        jails = []
    lines = [f"fail2ban status:"]
    for jail in jails[:5]:
        rj_rc, rj_out, _ = _run(["fail2ban-client", "status", jail], timeout=10)
        if rj_rc == 0:
            banned = "?"
            total = "?"
            for line in rj_out.split("\n"):
                if "Currently banned" in line:
                    banned = line.split(":")[-1].strip()
                elif "Total banned" in line:
                    total = line.split(":")[-1].strip()
            lines.append(f"  {jail}: banned={banned} (total={total})")
    return True, "\n".join(lines)


def cmd_restart(service):
    svc = service.lower()
    if svc not in ALLOWED_RESTART_SERVICES:
        return False, f"Unknown service: {svc}\nAllowed: {', '.join(sorted(ALLOWED_RESTART_SERVICES.keys()))}"
    cmd = list(ALLOWED_RESTART_SERVICES[svc])
    rc, out, err = _run(cmd, timeout=30)
    if rc == 0:
        return True, f"Service {svc} restarted OK"
    return False, f"restart {svc} failed (exit={rc}): {err.strip()[:200]}"


def cmd_reload_nginx():
    rc, out, err = _run(["nginx", "-s", "reload"], timeout=15)
    if rc == 0:
        return True, "nginx reloaded OK"
    return False, f"nginx reload failed (exit={rc}): {err.strip()[:200]}"


def cmd_logs(service, n_lines=20):
    svc = service.lower()
    log_path = LOG_PATHS.get(svc)
    if not log_path:
        return False, f"Unknown log: {svc}\nAvailable: {', '.join(sorted(LOG_PATHS.keys()))}"
    if not Path(log_path).exists():
        return False, f"Log file not found: {log_path}"
    rc, out, err = _run(["tail", f"-n{n_lines}", log_path], timeout=10)
    if rc == 0 and out.strip():
        content = out.strip()
        if len(content) > 3800:
            content = "..." + content[-3800:]
        return True, f"Last {n_lines} lines of {svc}:\n{content}"
    return False, f"Log {svc} empty or unreadable"


def cmd_users():
    cfg_paths = [Path("/usr/local/etc/xray/config.json"), Path("/etc/xray/config.json")]
    for p in cfg_paths:
        if p.exists():
            try:
                cfg = json.loads(p.read_text())
                users = []
                for ib in cfg.get("inbounds", []):
                    for c in ib.get("settings", {}).get("clients", []):
                        email = c.get("email", "—")
                        uid_short = c.get("id", "")[:8] + "..."
                        users.append(f"  • {email}  {uid_short}")
                if users:
                    return True, f"Users ({len(users)}):\n" + "\n".join(users)
                return True, "config.json found but no users in inbounds"
            except Exception as e:
                return False, f"config.json parse error: {e}"
    return False, "config.json not found"


def cmd_users_active():
    log_path = Path("/var/log/xray/access.log")
    if not log_path.exists():
        return False, "access.log not found"
    rc, out, err = _run(
        f"tail -n 5000 {log_path} 2>/dev/null | "
        f"grep -oE 'email: [^]]+' | sort -u",
        shell=True, timeout=15)
    if rc == 0 and out.strip():
        count = len(out.strip().split("\n"))
        return True, f"Active users ({count}) in last 5000 log lines:\n{out.strip()}"
    return True, "No active users in access.log"


def cmd_user(email):
    cfg_paths = [Path("/usr/local/etc/xray/config.json"), Path("/etc/xray/config.json")]
    for p in cfg_paths:
        if p.exists():
            try:
                cfg = json.loads(p.read_text())
                found = None
                for ib in cfg.get("inbounds", []):
                    for c in ib.get("settings", {}).get("clients", []):
                        if c.get("email") == email:
                            found = c
                            break
                if found:
                    uuid_short = found.get("id", "")[:8] + "..."
                    lines = [f"User: {email}",
                             f"  UUID: {uuid_short}",
                             f"  Flow: {found.get('flow', '—')}",
                             f"  Level: {found.get('level', 0)}"]
                    # TTL
                    ttl_path = Path("/var/lib/xray-installer/ttl_users.json")
                    if ttl_path.exists():
                        try:
                            ttl_data = json.loads(ttl_path.read_text())
                            if email in ttl_data:
                                lines.append(f"  TTL: {ttl_data[email]}")
                        except Exception:
                            pass
                    # Limits
                    limits_path = Path("/var/lib/xray-installer/traffic_limits.json")
                    if limits_path.exists():
                        try:
                            limits_data = json.loads(limits_path.read_text())
                            if email in limits_data:
                                lines.append(f"  Limit: {limits_data[email]}")
                        except Exception:
                            pass
                    return True, "\n".join(lines)
            except Exception:
                pass
    return False, f"User {email} not found in config.json"


def cmd_traffic(n=10):
    n = min(int(n), 50) if str(n).isdigit() else 10
    log_path = Path("/var/log/xray/access.log")
    if not log_path.exists():
        return False, "access.log not found"
    rc, out, err = _run(
        f"tail -n 10000 {log_path} 2>/dev/null | "
        f"grep -oE '\\[(email:)?[^]]*\\]' | sort | uniq -c | sort -rn | head -{n}",
        shell=True, timeout=15)
    if rc == 0 and out.strip():
        return True, f"Top {n} by connections (last 10000 log lines):\n{out.strip()}"
    return True, "access.log empty or no connections"


def cmd_status():
    """Same as chimera-remote-status.py — for unified interface."""
    st = _load_state()
    try:
        host = subprocess.check_output(["hostname", "-s"], text=True).strip()
    except Exception:
        host = "?"
    try:
        r = subprocess.run(["systemctl", "is-active", "xray"],
                           capture_output=True, text=True, timeout=5)
        xs = r.stdout.strip()
    except Exception:
        xs = "unknown"
    try:
        up = subprocess.check_output(["uptime", "-p"], text=True,
                                     stderr=subprocess.DEVNULL).strip()
    except Exception:
        up = ""
    return True, json.dumps({
        "host": host,
        "xray": xs,
        "proto": st.get("protocol_mode", "?"),
        "port": st.get("server_port", "?"),
        "mode": st.get("install_mode", "?"),
        "uptime": up,
    })


def cmd_version():
    try:
        r = subprocess.run(["git", "-C", "/opt/chimera", "log", "--oneline", "-1"],
                           capture_output=True, text=True, timeout=10)
        commit = r.stdout.strip() if r.returncode == 0 else "??"
    except Exception:
        commit = "??"
    try:
        host = subprocess.check_output(["hostname", "-s"], text=True).strip()
    except Exception:
        host = "?"
    return True, f"Git: {commit}\nHost: {host}"


def cmd_config():
    """Возвращает VLESS-ссылку + метаданные ноды как JSON.

    Используется cascade-админ-ботом и клиентским ботом для multi-node /config.
    Строит VLESS-ссылку из state.json (без linkqr_lib — базовая ссылка).
    """
    st = _load_state()
    domain    = st.get("domain", "")
    port      = st.get("server_port", 443)
    uuid_val  = st.get("uuid", "")
    proto     = st.get("protocol_mode", "reality")
    pub_key   = st.get("public_key", "")
    short_id  = st.get("short_id", "")
    fp        = st.get("fingerprint", "chrome") or "chrome"
    xtls_flow = st.get("xtls_flow", "xtls-rprx-vision") or ""
    xhttp_path = st.get("xhttp_path", "/")
    xhttp_mode = st.get("xhttp_mode", "stream-up")
    install_mode = st.get("install_mode", "A")
    awg_exit  = st.get("awg_exit_enabled", False)
    sni = domain
    if proto in ("reality", "xhttp_reality") and awg_exit and install_mode == "B":
        sni = (st.get("reality_dest", domain) or domain).split(":")[0]

    vless_link = ""
    if domain and uuid_val:
        if proto == "xhttp_reality":
            import urllib.parse as _up
            path_enc = _up.quote(xhttp_path, safe="/")
            vless_link = (f"vless://{uuid_val}@{domain}:{port}"
                          f"?encryption=none&security=reality&sni={sni}"
                          f"&fp={fp}&pbk={pub_key}&sid={short_id}"
                          f"&type=xhttp&path={path_enc}&mode={xhttp_mode}#VLESS-xHTTP-REALITY")
        elif proto == "xhttp":
            vless_link = (f"vless://{uuid_val}@{domain}:{port}"
                          f"?type=xhttp&security=tls&path={xhttp_path}"
                          f"&sni={sni}&fp={fp}#VLESS-xHTTP")
        else:
            flow_part = f"&flow={xtls_flow}" if xtls_flow else ""
            vless_link = (f"vless://{uuid_val}@{domain}:{port}"
                          f"?type=tcp&security=reality"
                          f"&pbk={pub_key}&sid={short_id}&sni={sni}&fp={fp}"
                          f"{flow_part}#VLESS-REALITY")

    # Public IP
    try:
        import socket as _sock
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        pub_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pub_ip = ""

    # IPv6
    try:
        import socket as _sock
        info = _sock.getaddrinfo(hostname_ref(), 80, _sock.AF_INET6)
        pub_v6 = info[0][4][0] if info else ""
    except Exception:
        pub_v6 = ""

    # AWG basic info (from awg0.conf)
    awg_info = {}
    awg_conf = Path("/etc/amnezia/amneziawg/awg0.conf")
    if awg_conf.exists():
        try:
            for line in awg_conf.read_text().splitlines():
                if line.startswith("ListenPort"):
                    awg_info["port"] = line.split("=")[1].strip()
                elif line.startswith("PrivateKey"):
                    pass  # don't expose private key
            # Get public key via awg
            r = subprocess.run(["awg", "show", "awg0", "public-key"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                awg_info["public_key"] = r.stdout.strip()
        except Exception:
            pass

    # Mieru info
    mieru_info = {}
    mieru_state = Path("/var/lib/xray-installer/mieru.json")
    if mieru_state.exists():
        try:
            m = json.loads(mieru_state.read_text())
            mieru_info = {
                "port_start": m.get("port_start", ""),
                "port_end": m.get("port_end", ""),
            }
            for u in m.get("users", []):
                if u.get("username") == "user":
                    mieru_info["username"] = "user"
                    mieru_info["password"] = u.get("password", "")
                    break
        except Exception:
            pass

    try:
        host = subprocess.check_output(["hostname", "-s"], text=True, timeout=5).strip()
    except Exception:
        host = "?"

    result = {
        "host": host,
        "ip": pub_ip,
        "ipv6": pub_v6,
        "vless": vless_link,
        "proto": proto,
        "port": port,
        "domain": domain,
        "awg": awg_info,
        "mieru": mieru_info,
    }
    return True, json.dumps(result)


def hostname_ref():
    """Return short hostname (used by cmd_config for IPv6 lookup)."""
    try:
        return subprocess.check_output(["hostname", "-s"], text=True, timeout=5).strip()
    except Exception:
        return "localhost"


# ── Dispatcher ───────────────────────────────────────────────────────────────

COMMANDS = {
    "ban":          (cmd_ban,         1, "<ip>"),
    "unban":        (cmd_unban,       1, "<ip>"),
    "banlist":      (cmd_banlist,     0, ""),
    "whitelist":    (cmd_whitelist,   0, ""),
    "wl_add":       (cmd_wl_add,      1, "<ip>"),
    "wl_del":       (cmd_wl_del,     1, "<ip>"),
    "geo":          (cmd_geo,         0, ""),
    "f2b":          (cmd_f2b,         0, ""),
    "restart":      (cmd_restart,    1, "<service>"),
    "reload_nginx": (cmd_reload_nginx, 0, ""),
    "logs":         (cmd_logs,        2, "<service> [n]"),  # n optional
    "users":        (cmd_users,       0, ""),
    "users_active": (cmd_users_active, 0, ""),
    "user":         (cmd_user,        1, "<email>"),
    "traffic":      (cmd_traffic,     1, "[n]"),  # n optional
    "status":       (cmd_status,      0, ""),
    "version":      (cmd_version,     0, ""),
    "config":       (cmd_config,      0, ""),
}


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"ok": False, "error": "Usage: chimera-remote-cmd.py <command> [args...]"}))
        print(f"Available commands: {', '.join(sorted(COMMANDS.keys()))}", file=sys.stderr)
        sys.exit(1)

    cmd_name = sys.argv[1]
    cmd_args = sys.argv[2:]

    if cmd_name not in COMMANDS:
        print(json.dumps({"ok": False, "error": f"Unknown command: {cmd_name}"}))
        print(f"Available: {', '.join(sorted(COMMANDS.keys()))}", file=sys.stderr)
        sys.exit(1)

    func, min_args, usage = COMMANDS[cmd_name]
    if len(cmd_args) < min_args:
        print(json.dumps({"ok": False, "error": f"Usage: {cmd_name} {usage}"}))
        sys.exit(2)

    # Dispatch
    if cmd_name == "logs":
        # Special: 1 required (service), 2nd optional (n)
        service = cmd_args[0]
        n = int(cmd_args[1]) if len(cmd_args) > 1 and cmd_args[1].isdigit() else 20
        ok, output = cmd_logs(service, n)
    elif cmd_name == "traffic":
        # 1 optional (n)
        n = cmd_args[0] if cmd_args else "10"
        ok, output = cmd_traffic(n)
    else:
        ok, output = func(*cmd_args[:min_args + 5])  # cap args

    print(json.dumps({"ok": ok, "output": output}))
    sys.exit(0 if ok else 0)  # always 0 exit — check 'ok' field


if __name__ == "__main__":
    main()
