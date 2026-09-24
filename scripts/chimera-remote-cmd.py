#!/usr/bin/env python3
"""chimera-remote-cmd.py — standalone command executor for cascade admin.

Используется primary admin-ботом (chimera/modules/tg_bot.py) для
выполнения команд на remote-серверах через SSH. Возвращает результат
как JSON-строку на stdout.

Usage:
    chimera-remote-cmd.py <command> [args...]

Commands (whitelist — безопасные, без shutdown/reboot):
    ban <ip>                — ban IP в xray_manual_ban ipset
    unban <ip>              — unban IP
    banlist                 — list banned IPs (xray_manual_ban)
    whitelist               — list whitelist IPs (clients_wl)
    wl_add <ip>             — add IP to whitelist
    wl_del <ip>             — del IP from whitelist
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
import json
import os
import re
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


def _validate_ip(ip_str):
    """IPv4 валидация."""
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_str))


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

def cmd_ban(ip):
    if not _validate_ip(ip):
        return False, f"Invalid IPv4: {ip}"
    rc, out, err = _run(["ipset", "add", "xray_manual_ban", ip], timeout=10)
    if rc == 0:
        _save_ipset()
        return True, f"IP {ip} added to xray_manual_ban (saved to /etc/ipset.conf)"
    if "already in set" in err.lower():
        return True, f"IP {ip} already in xray_manual_ban"
    return False, f"ipset add failed (exit={rc}): {err.strip()[:200]}"


def cmd_unban(ip):
    if not _validate_ip(ip):
        return False, f"Invalid IPv4: {ip}"
    rc, out, err = _run(["ipset", "del", "xray_manual_ban", ip], timeout=10)
    if rc == 0:
        _save_ipset()
        return True, f"IP {ip} removed from xray_manual_ban"
    return False, f"ipset del failed (exit={rc}): {err.strip()[:200]}"


def cmd_banlist():
    rc, out, err = _run(["ipset", "list", "xray_manual_ban"], timeout=10)
    if rc != 0:
        return False, f"ipset list failed (exit={rc})"
    lines = [l.strip() for l in out.split("\n") if _validate_ip(l.strip())]
    if not lines:
        return True, "xray_manual_ban: empty (no banned IPs)"
    out_top = "\n".join(lines[:50])
    suffix = f"\n... and {len(lines)-50} more" if len(lines) > 50 else ""
    return True, f"xray_manual_ban ({len(lines)} IPs):\n{out_top}{suffix}"


def cmd_whitelist():
    rc, out, err = _run(["ipset", "list", "clients_wl"], timeout=10)
    if rc != 0:
        return False, f"ipset list failed (exit={rc})"
    lines = [l.strip() for l in out.split("\n") if _validate_ip(l.strip())]
    if not lines:
        return True, "clients_wl: empty"
    return True, f"clients_wl ({len(lines)} IPs):\n" + "\n".join(lines)


def cmd_wl_add(ip):
    if not _validate_ip(ip):
        return False, f"Invalid IPv4: {ip}"
    rc, out, err = _run(["ipset", "add", "clients_wl", ip], timeout=10)
    if rc == 0 or "already" in err.lower():
        _save_ipset()
        return True, f"IP {ip} added to clients_wl"
    return False, f"ipset add failed: {err.strip()[:200]}"


def cmd_wl_del(ip):
    if not _validate_ip(ip):
        return False, f"Invalid IPv4: {ip}"
    rc, out, err = _run(["ipset", "del", "clients_wl", ip], timeout=10)
    if rc == 0:
        _save_ipset()
        return True, f"IP {ip} removed from clients_wl"
    return False, f"ipset del failed: {err.strip()[:200]}"


def cmd_geo():
    # IPv4 count
    rc4, out4, _ = _run(["ipset", "list", "xray_ru_block"], timeout=10)
    v4_count = sum(1 for l in out4.split("\n") if _validate_ip(l.strip())) if rc4 == 0 else 0
    # IPv6 count
    rc6, out6, _ = _run(["ipset", "list", "xray_ru_block6"], timeout=10)
    v6_count = 0
    if rc6 == 0:
        v6_count = sum(1 for l in out6.split("\n")
                       if l.strip() and ":" in l and not l.startswith(("Name", "Type", "Header", "Size", "Revision")) and l != "members:")
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
