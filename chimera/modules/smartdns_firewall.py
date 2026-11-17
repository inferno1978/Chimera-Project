"""
chimera/modules/smartdns_firewall.py
───────────────────────────────────────────────────────────────────────────────
Firewall-слой SmartDNS-ноды: iptables/ipset/ufw + ватчеры авторизации.

Паритет с bash configure_firewall_and_sysctl + install_ipset_watchers
(smartdns-installer v2.10.0), переработано для двух режимов (v3.0.0):

  standalone (отдельный VPS):
    — как bash: цепочки SMARTDNS_* на wildcard, NAT 443→8444/9443,
      ufw allow 80/443/853 + ufw --force enable;

  companion (тот же VPS с Химерой + второй IP) — КРИТИЧНАЯ разводка:
    — NAT-редиректы 443 скоуплены «-d <BIND_IP>»: трафик Химеры на основном
      IP через PREROUTING проходит НЕтронутым (VLESS/REALITY 443 живой);
    — DROP/ACCEPT по 9443/9444/8444/8853/5353/8053/3000 скоуплены «-d
      <BIND_IP>»: порты 9443 (User Portal Химеры) и 9444 (Subscription
      Химеры) на ОСНОВНОМ IP продолжают работать;
    — правила 853 скоуплены на <BIND_IP> (не душить AGH-DoT Химеры);
    — ufw: только per-IP allow (to <IP> port …), НИКОГДА не --force enable
      и не default-политики — firewall Химеры не трогаем;
    — ufw-правило 443 НЕ добавляем (443 основного IP — Химеры; на втором
      IP пакеты после REDIRECT приходят уже на 8444/9443).

Публичный API (для smartdns.py):
    build_iptables_rules(cfg) -> dict        # чистый builder (тесты)
    build_ufw_commands(cfg) -> list          # чистый builder (тесты)
    apply_firewall(cfg) -> bool              # ipset + chains + ufw + sysctl
    remove_firewall(cfg) -> bool             # полное снятие правил
    seed_admin_ip(cfg) -> bool               # whitelist IP админа (SSH-сессия)
    write_watcher_scripts(cfg) -> bool       # /opt/smartdns/bin/*watcher*.py
    whitelist_status(cfg) / whitelist_add(cfg, ip) / whitelist_remove(cfg, ip)
    whitelist_flush(cfg) / whitelist_toggle(cfg, on) / whitelist_set_mode(cfg, m)
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path
from typing import Optional

from chimera.modules.smartdns_stack import (
    BIN_DIR, IPSET_SAVE_FILE, LOG_DIR, PORT_DOH, PORT_DOT, PORT_ENGINE,
    PORT_DOHLOC, PORT_DOTHERM, PORT_STEALTH, PORT_WEB, STATE_DIR,
    UNIT_FW, UNIT_XRAY, _atomic_write, _info, _ok, _warn, _err, _log,
)

# ── ipset-наборы (паритет bash) ─────────────────────────────────────────────
IPSET_V4 = "smartdns_clients"
IPSET_V4_SEC = "dot_clients"
IPSET_V6 = "smartdns_clients6"
IPSET_V6_SEC = "dot_clients6"

# Цепочки (неймспейс сохранён — SMARTDNS_* не конфликтует с Химерой)
CHAIN_NAT_V4 = "SMARTDNS_PREROUTING"
CHAIN_IN_V4 = "SMARTDNS_INPUT"
CHAIN_OUT_V4 = "SMARTDNS_OUTPUT"
CHAIN_NAT_V6 = "SMARTDNS6_PREROUTING"
CHAIN_IN_V6 = "SMARTDNS6_INPUT"
CHAIN_OUT_V6 = "SMARTDNS6_OUTPUT"

IPT = "/usr/sbin/iptables"
IPT6 = "/usr/sbin/ip6tables"

_SYSCTL_CONF = Path("/etc/sysctl.d/90-smartdns-keepalive.conf")


def _is_companion(cfg: dict) -> bool:
    return cfg.get("mode") == "companion" and bool(cfg.get("bind_ip"))


def _dst_scope(cfg: dict) -> list:
    """Аргументы скоупа адреса назначения: companion → ['-d', BIND_IP],
    standalone → [] (wildcard, как bash)."""
    if _is_companion(cfg):
        return ["-d", str(cfg["bind_ip"])]
    return []


# ══════════════════════════════════════════════════════════════════════════
#  ЧИСТЫЕ BUILDERS (тесты)
# ══════════════════════════════════════════════════════════════════════════

def _build_nat_prerouting_v4(cfg: dict) -> list:
    """NAT PREROUTING (443 → 8444/9443). Компаньон: -d BIND_IP на каждом
    REDIRECT-правиле — трафик основного IP (VLESS Химеры) не трогаем."""
    rules = []
    private = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
               "100.64.0.0/10", "169.254.0.0/16", f"{cfg['server_ipv4']}/32"]
    for cidr in private:
        rules.append([IPT, "-t", "nat", "-A", CHAIN_NAT_V4, "-s", cidr,
                      "-j", "RETURN"])
    # Источник whitelist (DoH/DoT/web-auth авторизованные) → stealth DoH
    rules.append([IPT, "-t", "nat", "-A", CHAIN_NAT_V4, *_dst_scope(cfg),
                  "-p", "tcp", "--dport", "443", "-m", "set",
                  "--match-set", IPSET_V4, "src", "-j", "REDIRECT",
                  "--to-ports", str(PORT_DOH)])
    if cfg.get("whitelist_mode") == "separate":
        rules.append([IPT, "-t", "nat", "-A", CHAIN_NAT_V4, *_dst_scope(cfg),
                      "-p", "tcp", "--dport", "443", "-m", "set",
                      "--match-set", IPSET_V4_SEC, "src", "-j", "REDIRECT",
                      "--to-ports", str(PORT_DOH)])
    # Все прочие → cover-site (прозрачная маскировка)
    rules.append([IPT, "-t", "nat", "-A", CHAIN_NAT_V4, *_dst_scope(cfg),
                  "-p", "tcp", "--dport", "443", "-j", "REDIRECT",
                  "--to-ports", str(PORT_WEB)])
    rules.append([IPT, "-t", "nat", "-C", "PREROUTING", "-j", CHAIN_NAT_V4])
    return rules


def _build_input_v4(cfg: dict) -> list:
    """INPUT: защита 853 (rate-limit/whitelist), 9443/9444/внутренние порты —
    только DNAT-трафик; прямые пробы — DROP. Companion: всё скоуплено -d
    BIND_IP (9443/9444 на основном IP — User Portal/Subscription Химеры!)."""
    rules = []
    d = _dst_scope(cfg)
    wl_on = str(cfg.get("whitelist_enabled", "false")).lower() == "true"
    sec = cfg.get("whitelist_mode") == "separate"
    dot_set = IPSET_V4_SEC if sec else IPSET_V4

    rules.append([IPT, "-t", "filter", "-A", CHAIN_IN_V4, "-p", "tcp",
                  "!", "--syn", "-m", "conntrack", "--ctstate", "INVALID",
                  "-j", "REJECT", "--reject-with", "tcp-reset"])
    rules.append([IPT, "-t", "filter", "-A", CHAIN_IN_V4, "-m", "conntrack",
                  "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    if wl_on:
        rules.append([IPT, "-t", "filter", "-A", CHAIN_IN_V4, *d,
                      "-p", "tcp", "--dport", str(PORT_DOT), "-m", "set",
                      "--match-set", dot_set, "src", "-m", "hashlimit",
                      "--hashlimit-name", "dot_v4_rate",
                      "--hashlimit-mode", "srcip", "--hashlimit-upto",
                      "30/min", "--hashlimit-burst", "40", "-j", "ACCEPT"])
        rules.append([IPT, "-t", "filter", "-A", CHAIN_IN_V4, *d,
                      "-p", "tcp", "--dport", str(PORT_DOT), "-j", "DROP"])
    else:
        rules.append([IPT, "-t", "filter", "-A", CHAIN_IN_V4, *d,
                      "-p", "tcp", "--dport", str(PORT_DOT), "--syn",
                      "-m", "hashlimit", "--hashlimit-name", "dot_v4_rate",
                      "--hashlimit-mode", "srcip", "--hashlimit-above",
                      "30/min", "--hashlimit-burst", "40", "-j", "DROP"])
        rules.append([IPT, "-t", "filter", "-A", CHAIN_IN_V4, *d,
                      "-p", "tcp", "--dport", str(PORT_DOT), "-j", "ACCEPT"])
    rules.append([IPT, "-t", "filter", "-A", CHAIN_IN_V4, "-i", "lo",
                  "-j", "ACCEPT"])
    # 9443: только redirected (DNAT ctorigdstport 443)
    rules.append([IPT, "-t", "filter", "-A", CHAIN_IN_V4, *d,
                  "-p", "tcp", "--dport", str(PORT_WEB), "-m", "conntrack",
                  "--ctstate", "DNAT", "--ctorigdstport", "443", "-j", "ACCEPT"])
    rules.append([IPT, "-t", "filter", "-A", CHAIN_IN_V4, *d,
                  "-p", "tcp", "--dport", str(PORT_WEB), "-j", "DROP"])
    # Внутренние порты — только loopback (см. -i lo выше)
    rules.append([IPT, "-t", "filter", "-A", CHAIN_IN_V4, *d,
                  "-p", "tcp", "-m", "multiport",
                  "--dports", f"8443,{PORT_STEALTH},{PORT_DOTHERM},"
                              f"{PORT_ENGINE},{PORT_DOHLOC},3000",
                  "-j", "DROP"])
    rules.append([IPT, "-t", "filter", "-A", CHAIN_IN_V4, *d,
                  "-p", "udp", "--dport", str(PORT_ENGINE), "-j", "DROP"])
    # 8444: только redirected + whitelist
    rules.append([IPT, "-t", "filter", "-A", CHAIN_IN_V4, *d,
                  "-p", "tcp", "--dport", str(PORT_DOH), "-m", "conntrack",
                  "--ctstate", "DNAT", "--ctorigdstport", "443", "-m", "set",
                  "--match-set", IPSET_V4, "src", "-j", "ACCEPT"])
    if sec:
        rules.append([IPT, "-t", "filter", "-A", CHAIN_IN_V4, *d,
                      "-p", "tcp", "--dport", str(PORT_DOH), "-m", "conntrack",
                      "--ctstate", "DNAT", "--ctorigdstport", "443", "-m",
                      "set", "--match-set", IPSET_V4_SEC, "src",
                      "-j", "ACCEPT"])
    rules.append([IPT, "-t", "filter", "-A", CHAIN_IN_V4, *d,
                  "-p", "tcp", "--dport", str(PORT_DOH), "-j", "DROP"])
    rules.append([IPT, "-t", "filter", "-C", "INPUT", "-j", CHAIN_IN_V4])
    return rules


def _build_output_v4(cfg: dict, xray_uid: int) -> list:
    """OUTPUT anti-loop/anti-SSRF для пользователя xray-стека (паритет bash;
    companion: скоуп не нужен — uid уникален для стека)."""
    rules = []
    rules.append([IPT, "-t", "filter", "-A", CHAIN_OUT_V4, "-m", "conntrack",
                  "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    rules.append([IPT, "-t", "filter", "-A", CHAIN_OUT_V4,
                  "-m", "owner", "--uid-owner", str(xray_uid),
                  "-d", "127.0.0.1/32", "-p", "tcp", "-m", "multiport",
                  "--dports", f"9443,{PORT_STEALTH},{PORT_DOTHERM}",
                  "-j", "ACCEPT"])
    for cidr in [f"{cfg['server_ipv4']}/32", "127.0.0.0/8", "10.0.0.0/8",
                 "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                 "169.254.0.0/16"]:
        rules.append([IPT, "-t", "filter", "-A", CHAIN_OUT_V4,
                      "-m", "owner", "--uid-owner", str(xray_uid),
                      "-p", "tcp", "-d", cidr, "-j", "REJECT",
                      "--reject-with", "tcp-reset"])
        rules.append([IPT, "-t", "filter", "-A", CHAIN_OUT_V4,
                      "-m", "owner", "--uid-owner", str(xray_uid),
                      "-d", cidr, "-j", "DROP"])
    rules.append([IPT, "-t", "filter", "-C", "OUTPUT", "-j", CHAIN_OUT_V4])
    return rules


def _build_nat_prerouting_v6(cfg: dict) -> list:
    rules = []
    for cidr in ["::1/128", "fe80::/10", "fc00::/7"]:
        rules.append([IPT6, "-t", "nat", "-A", CHAIN_NAT_V6, "-s", cidr,
                      "-j", "RETURN"])
    if cfg.get("server_ipv6"):
        rules.append([IPT6, "-t", "nat", "-A", CHAIN_NAT_V6, "-s",
                      f"{cfg['server_ipv6']}/128", "-j", "RETURN"])
    rules.append([IPT6, "-t", "nat", "-A", CHAIN_NAT_V6, "-p", "tcp",
                  "--dport", "443", "-m", "set", "--match-set", IPSET_V6,
                  "src", "-j", "REDIRECT", "--to-ports", str(PORT_DOH)])
    if cfg.get("whitelist_mode") == "separate":
        rules.append([IPT6, "-t", "nat", "-A", CHAIN_NAT_V6, "-p", "tcp",
                      "--dport", "443", "-m", "set", "--match-set",
                      IPSET_V6_SEC, "src", "-j", "REDIRECT",
                      "--to-ports", str(PORT_DOH)])
    rules.append([IPT6, "-t", "nat", "-A", CHAIN_NAT_V6, "-p", "tcp",
                  "--dport", "443", "-j", "REDIRECT", "--to-ports",
                  str(PORT_WEB)])
    rules.append([IPT6, "-t", "nat", "-C", "PREROUTING", "-j", CHAIN_NAT_V6])
    return rules


def _build_input_v6(cfg: dict) -> list:
    rules = []
    wl_on = str(cfg.get("whitelist_enabled", "false")).lower() == "true"
    sec = cfg.get("whitelist_mode") == "separate"
    dot_set = IPSET_V6_SEC if sec else IPSET_V6
    rules.append([IPT6, "-t", "filter", "-A", CHAIN_IN_V6, "-p", "tcp",
                  "!", "--syn", "-m", "conntrack", "--ctstate", "INVALID",
                  "-j", "REJECT", "--reject-with", "tcp-reset"])
    rules.append([IPT6, "-t", "filter", "-A", CHAIN_IN_V6, "-m", "conntrack",
                  "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    if wl_on:
        rules.append([IPT6, "-t", "filter", "-A", CHAIN_IN_V6, "-p", "tcp",
                      "--dport", str(PORT_DOT), "-m", "set", "--match-set",
                      dot_set, "src", "-m", "hashlimit",
                      "--hashlimit-name", "dot_v6_rate",
                      "--hashlimit-mode", "srcip", "--hashlimit-upto",
                      "30/min", "--hashlimit-burst", "40", "-j", "ACCEPT"])
        rules.append([IPT6, "-t", "filter", "-A", CHAIN_IN_V6, "-p", "tcp",
                      "--dport", str(PORT_DOT), "-j", "DROP"])
    else:
        rules.append([IPT6, "-t", "filter", "-A", CHAIN_IN_V6, "-p", "tcp",
                      "--dport", str(PORT_DOT), "--syn", "-m", "hashlimit",
                      "--hashlimit-name", "dot_v6_rate",
                      "--hashlimit-mode", "srcip", "--hashlimit-above",
                      "30/min", "--hashlimit-burst", "40", "-j", "DROP"])
        rules.append([IPT6, "-t", "filter", "-A", CHAIN_IN_V6, "-p", "tcp",
                      "--dport", str(PORT_DOT), "-j", "ACCEPT"])
    rules.append([IPT6, "-t", "filter", "-A", CHAIN_IN_V6, "-i", "lo",
                  "-j", "ACCEPT"])
    rules.append([IPT6, "-t", "filter", "-A", CHAIN_IN_V6, "-p", "tcp",
                  "--dport", str(PORT_WEB), "-m", "conntrack", "--ctstate",
                  "DNAT", "--ctorigdstport", "443", "-j", "ACCEPT"])
    rules.append([IPT6, "-t", "filter", "-A", CHAIN_IN_V6, "-p", "tcp",
                  "--dport", str(PORT_WEB), "-j", "DROP"])
    rules.append([IPT6, "-t", "filter", "-A", CHAIN_IN_V6, "-p", "tcp",
                  "-m", "multiport",
                  "--dports", f"8443,{PORT_STEALTH},{PORT_DOTHERM},"
                              f"{PORT_ENGINE},{PORT_DOHLOC},3000",
                  "-j", "DROP"])
    rules.append([IPT6, "-t", "filter", "-A", CHAIN_IN_V6, "-p", "tcp",
                  "--dport", str(PORT_DOH), "-m", "conntrack", "--ctstate",
                  "DNAT", "--ctorigdstport", "443", "-m", "set",
                  "--match-set", IPSET_V6, "src", "-j", "ACCEPT"])
    if sec:
        rules.append([IPT6, "-t", "filter", "-A", CHAIN_IN_V6, "-p", "tcp",
                      "--dport", str(PORT_DOH), "-m", "conntrack",
                      "--ctstate", "DNAT", "--ctorigdstport", "443", "-m",
                      "set", "--match-set", IPSET_V6_SEC, "src", "-j",
                      "ACCEPT"])
    rules.append([IPT6, "-t", "filter", "-A", CHAIN_IN_V6, "-p", "tcp",
                  "--dport", str(PORT_DOH), "-j", "DROP"])
    rules.append([IPT6, "-t", "filter", "-A", CHAIN_IN_V6, "-p", "udp",
                  "--dport", str(PORT_ENGINE), "-j", "DROP"])
    rules.append([IPT6, "-t", "filter", "-C", "INPUT", "-j", CHAIN_IN_V6])
    return rules


def _build_output_v6(cfg: dict, xray_uid: int) -> list:
    rules = []
    rules.append([IPT6, "-t", "filter", "-A", CHAIN_OUT_V6, "-m", "conntrack",
                  "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    for cidr in ["::1/128", "fe80::/10", "fc00::/7"]:
        rules.append([IPT6, "-t", "filter", "-A", CHAIN_OUT_V6,
                      "-m", "owner", "--uid-owner", str(xray_uid),
                      "-p", "tcp", "-d", cidr, "-j", "REJECT",
                      "--reject-with", "tcp-reset"])
        rules.append([IPT6, "-t", "filter", "-A", CHAIN_OUT_V6,
                      "-m", "owner", "--uid-owner", str(xray_uid),
                      "-d", cidr, "-j", "DROP"])
    if cfg.get("server_ipv6"):
        rules.append([IPT6, "-t", "filter", "-A", CHAIN_OUT_V6,
                      "-m", "owner", "--uid-owner", str(xray_uid),
                      "-p", "tcp", "-d", f"{cfg['server_ipv6']}/128",
                      "-j", "REJECT", "--reject-with", "tcp-reset"])
        rules.append([IPT6, "-t", "filter", "-A", CHAIN_OUT_V6,
                      "-m", "owner", "--uid-owner", str(xray_uid),
                      "-d", f"{cfg['server_ipv6']}/128", "-j", "DROP"])
    rules.append([IPT6, "-t", "filter", "-C", "OUTPUT", "-j", CHAIN_OUT_V6])
    return rules


def build_iptables_rules(cfg: dict, xray_uid: int = 0) -> dict:
    """Полный набор правил стека (чистая функция). xray_uid=0 → заглушка
    (правила OUTPUT не собираются — для тестов/превью)."""
    return {
        "nat_v4": _build_nat_prerouting_v4(cfg),
        "in_v4": _build_input_v4(cfg),
        "out_v4": _build_output_v4(cfg, xray_uid) if xray_uid else [],
        "nat_v6": _build_nat_prerouting_v6(cfg),
        "in_v6": _build_input_v6(cfg),
        "out_v6": _build_output_v6(cfg, xray_uid) if xray_uid else [],
    }


def build_ufw_commands(cfg: dict) -> list:
    """UFW-команды. standalone: как bash (ssh/80/443/853 + --force enable).
    companion: ТОЛЬКО per-IP allow на втором IP; 443 НЕ открываем (это порт
    Химеры на основном IP; на втором IP пакеты после REDIRECT приходят на
    8444/9443); --force enable НЕ зовём — firewall Химеры неприкосновенен."""
    cmds = []
    if _is_companion(cfg):
        ip = str(cfg["bind_ip"])
        for port, note in ((80, "smartdns-http"), (PORT_DOT, "smartdns-dot"),
                           (PORT_DOH, "smartdns-doh"),
                           (PORT_WEB, "smartdns-web")):
            cmds.append(["ufw", "allow", "proto", "tcp", "from", "any",
                         "to", ip, "port", str(port), "comment", note])
        return cmds
    ssh_port = _detect_ssh_port()
    cmds.append(["ufw", "allow", f"{ssh_port}/tcp", "comment", "SSH Access"])
    cmds.append(["ufw", "allow", "80/tcp", "comment", "HTTP Redirect"])
    cmds.append(["ufw", "allow", "443/tcp", "comment",
                 "SmartDNS HTTPS / SNI Proxy"])
    cmds.append(["ufw", "allow", f"{PORT_DOT}/tcp", "comment",
                 "SmartDNS DoT"])
    cmds.append(["ufw", "--force", "enable"])
    return cmds


def _detect_ssh_port() -> str:
    try:
        r = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True,
                           check=False)
        for line in (r.stdout or "").splitlines():
            if "sshd" in line:
                return line.split()[3].rsplit(":", 1)[-1]
    except Exception:
        pass
    return "22"


def build_ufw_commands_cli() -> list:
    """No-arg превью ufw-команд стека (smoke/диагностика): читает
    settings.json напрямую (без импорта smartdns — иначе цикл); нет
    настроек → нейтральный standalone-превью. Команды НЕ выполняет."""
    try:
        cfg = json.loads((STATE_DIR / "settings.json").read_text())
    except Exception:
        cfg = {"mode": "standalone", "server_ipv4": "0.0.0.0",
               "whitelist_enabled": "false", "whitelist_mode": "shared"}
    return build_ufw_commands(cfg)


# ══════════════════════════════════════════════════════════════════════════
#  ПРИМЕНЕНИЕ / СНЯТИЕ
# ══════════════════════════════════════════════════════════════════════════

def _run(cmd: list, check: bool = False) -> bool:
    r = subprocess.run(cmd, capture_output=True, check=False)
    if check and r.returncode != 0:
        return False
    return r.returncode == 0


def _chain_reset(binary: str, table: str, chain: str) -> None:
    """Пересоздать цепочку чистой (N || F)."""
    if not _run([binary, "-t", table, "-N", chain]):
        _run([binary, "-t", table, "-F", chain])


def _apply_rule_list(rules: list) -> int:
    """Применяет список правил; правила с '-C' — это «ensure hook» (проверка
    наличия jump'а): провал → вставка jump в начало. Возвращает кол-во
    применённых."""
    applied = 0
    for cmd in rules:
        if "-C" in cmd:
            hook = [x for x in cmd if x != "-C"]
            insert = hook[:4] + ["-I", hook[5], "1", "-j", hook[7]]
            # cmd: [IPT, -t, nat, -C, PREROUTING, -j, CHAIN] → вставка
            # [IPT, -t, nat, -I, PREROUTING, 1, -j, CHAIN]
            binary, t_flag, table, _c, parent, _j, chain = cmd
            if not _run(cmd):
                _run([binary, t_flag, table, "-I", parent, "1",
                      "-j", chain])
            applied += 1
            continue
        _run(cmd)
        applied += 1
    return applied


def _uid_of(user: str) -> int:
    r = subprocess.run(["id", "-u", user], capture_output=True, text=True,
                       check=False)
    try:
        return int(r.stdout.strip())
    except Exception:
        return 0


def apply_firewall(cfg: dict) -> bool:
    """sysctl + ipset + цепочки + ufw + seed-админ (вызывается из install и
    из smartdns-firewall.service через render_firewall_apply_script)."""
    _info("Применение firewall-правил SmartDNS…")
    _SYSCTL_CONF.parent.mkdir(parents=True, exist_ok=True)
    _SYSCTL_CONF.write_text(
        "net.ipv4.tcp_keepalive_time = 120\n"
        "net.ipv4.tcp_keepalive_intvl = 30\n"
        "net.ipv4.tcp_keepalive_probes = 4\n"
        "net.ipv4.tcp_mtu_probing = 1\n")
    subprocess.run(["sysctl", "--system"], capture_output=True, check=False)

    _ensure_ipsets()
    if IPSET_SAVE_FILE.exists() and IPSET_SAVE_FILE.stat().st_size > 0:
        with open(IPSET_SAVE_FILE, "rb") as f:
            subprocess.run(["ipset", "restore", "-!"], stdin=f,
                           capture_output=True, check=False)

    xray_uid = _uid_of("smartdns")
    rules = build_iptables_rules(cfg, xray_uid)
    _chain_reset(IPT, "nat", CHAIN_NAT_V4)
    _chain_reset(IPT, "filter", CHAIN_IN_V4)
    _chain_reset(IPT, "filter", CHAIN_OUT_V4)
    _chain_reset(IPT6, "nat", CHAIN_NAT_V6)
    _chain_reset(IPT6, "filter", CHAIN_IN_V6)
    _chain_reset(IPT6, "filter", CHAIN_OUT_V6)
    n = sum(_apply_rule_list(rules[k]) for k in
            ("nat_v4", "in_v4", "out_v4", "nat_v6", "in_v6", "out_v6"))

    for cmd in build_ufw_commands(cfg):
        subprocess.run(cmd, capture_output=True, check=False)

    seed_admin_ip(cfg)
    _save_ipsets()
    _ok(f"Firewall: {n} правил применено "
        f"({'companion per-IP ' + str(cfg.get('bind_ip')) if _is_companion(cfg) else 'standalone wildcard'})")
    return True


def _ensure_ipsets() -> None:
    for name, family in ((IPSET_V4, "inet"), (IPSET_V6, "inet6"),
                         (IPSET_V4_SEC, "inet"), (IPSET_V6_SEC, "inet6")):
        _run(["ipset", "create", name, "hash:ip", "family", family,
              "timeout", "86400", "-exist"])


def _save_ipsets() -> None:
    try:
        r = subprocess.run(["ipset", "save"], capture_output=True,
                           text=True, check=False)
        tmp = IPSET_SAVE_FILE.with_suffix(".tmp")
        tmp.write_text(r.stdout or "")
        tmp.replace(IPSET_SAVE_FILE)
    except Exception:
        pass


def remove_firewall(cfg: dict) -> bool:
    """Полное снятие: jump'ы, цепочки, ipset'ы, ufw-правила стека."""
    _info("Снятие firewall-правил SmartDNS…")
    for binary, nat_ch, in_ch, out_ch in (
            (IPT, CHAIN_NAT_V4, CHAIN_IN_V4, CHAIN_OUT_V4),
            (IPT6, CHAIN_NAT_V6, CHAIN_IN_V6, CHAIN_OUT_V6)):
        for table, chain in (("nat", nat_ch), ("filter", in_ch),
                             ("filter", out_ch)):
            _run([binary, "-t", table, "-D",
                  "PREROUTING" if table == "nat" else "INPUT", "-j", chain])
            _run([binary, "-t", table, "-D",
                  "PREROUTING" if table == "nat" else "OUTPUT", "-j", chain])
            _run([binary, "-t", table, "-F", chain])
            _run([binary, "-t", table, "-X", chain])
    for name in (IPSET_V4, IPSET_V6, IPSET_V4_SEC, IPSET_V6_SEC):
        _run(["ipset", "destroy", name])

    if _is_companion(cfg):
        ip = str(cfg["bind_ip"])
        for port in (80, PORT_DOT, PORT_DOH, PORT_WEB):
            _run(["ufw", "delete", "allow", "proto", "tcp", "from", "any",
                  "to", ip, "port", str(port)])
    else:
        for rule in (f"{PORT_DOT}/tcp", "443/tcp", "80/tcp"):
            _run(["ufw", "delete", "allow", rule])
    _ok("Firewall-правила SmartDNS сняты")
    return True


def seed_admin_ip(cfg: dict) -> bool:
    """IP текущей SSH-сессии → ipset whitelist (первичная авторизация
    владельца, TTL 24ч — как bash seed_initial_admin_ip)."""
    admin_ip = ""
    client = __import__("os").environ.get("SSH_CLIENT", "").split()
    if client:
        admin_ip = client[0]
    if not admin_ip:
        return False
    return whitelist_add(cfg, admin_ip, quiet=True)


# ══════════════════════════════════════════════════════════════════════════
#  WHITELIST (DoT/DoH-авторизация через ipset)
# ══════════════════════════════════════════════════════════════════════════

def _valid_ip(ip: str) -> str:
    """'v4' | 'v6' | '' — валидация одиночного IP (паритет bash)."""
    ip = ip.strip()
    if not ip or "/" in ip:
        return ""
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
        o = [int(x) for x in ip.split(".")]
        return "v4" if all(x <= 255 for x in o) else ""
    if ":" in ip and re.match(r"^[0-9a-fA-F:]+$", ip):
        return "v6"
    return ""


def whitelist_add(cfg: dict, ip: str, ttl: int = 86400,
                  quiet: bool = False) -> bool:
    kind = _valid_ip(ip)
    if not kind:
        if not quiet:
            _err(f"Невалидный IP: {ip}")
        return False
    _ensure_ipsets()
    base, sec = ((IPSET_V4, IPSET_V4_SEC) if kind == "v4"
                 else (IPSET_V6, IPSET_V6_SEC))
    ok = _run(["ipset", "add", base, ip, "timeout", str(ttl), "-exist"])
    if cfg.get("whitelist_mode") == "separate":
        _run(["ipset", "add", sec, ip, "timeout", str(ttl), "-exist"])
    _save_ipsets()
    if not quiet:
        _ok(f"{ip} авторизован (TTL {ttl}s)")
    return ok


def whitelist_remove(cfg: dict, ip: str) -> bool:
    kind = _valid_ip(ip)
    if not kind:
        _err(f"Невалидный IP: {ip}")
        return False
    base, sec = ((IPSET_V4, IPSET_V4_SEC) if kind == "v4"
                 else (IPSET_V6, IPSET_V6_SEC))
    ok = _run(["ipset", "del", base, ip, "-exist"])
    _run(["ipset", "del", sec, ip, "-exist"])
    _save_ipsets()
    _ok(f"{ip} удалён из whitelist")
    return ok


def whitelist_flush(cfg: dict) -> bool:
    _ensure_ipsets()
    for name in (IPSET_V4, IPSET_V6, IPSET_V4_SEC, IPSET_V6_SEC):
        _run(["ipset", "flush", name])
    _save_ipsets()
    _ok("Whitelist очищен")
    return True


def whitelist_set_mode(cfg: dict, mode: str) -> bool:
    """shared | separate. separate: копирует smartdns_* → dot_* (чтобы
    активные клиенты не выпали при переключении)."""
    if mode not in ("shared", "separate"):
        _err("Режим: shared | separate")
        return False
    _ensure_ipsets()
    if mode == "separate":
        for base, sec in ((IPSET_V4, IPSET_V4_SEC), (IPSET_V6, IPSET_V6_SEC)):
            r = subprocess.run(["ipset", "list", base, "output", "plain"],
                               capture_output=True, text=True, check=False)
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                if _valid_ip(line) and " " not in line:
                    _run(["ipset", "add", sec, line, "timeout", "86400",
                          "-exist"])
    cfg["whitelist_mode"] = mode
    _apply_firewall_service(cfg)
    _ok(f"Режим whitelist: {mode}")
    return True


def whitelist_toggle(cfg: dict, on: bool) -> bool:
    cfg["whitelist_enabled"] = "true" if on else "false"
    _apply_firewall_service(cfg)
    _ok(f"DoT IP-whitelist: {'ВКЛЮЧЁН' if on else 'ВЫКЛЮЧЕН'}")
    return True


def _apply_firewall_service(cfg: dict) -> None:
    """Перезаписывает runtime-скрипт правилами текущего cfg и перезапускает
    smartdns-firewall.service (правила применяются на живую)."""
    render_firewall_apply_script(cfg)
    subprocess.run(["systemctl", "restart", UNIT_FW],
                   capture_output=True, check=False)


def whitelist_status(cfg: dict) -> dict:
    _ensure_ipsets()
    out = {"enabled": cfg.get("whitelist_enabled", "false"),
           "mode": cfg.get("whitelist_mode", "shared"), "v4": [], "v6": []}
    for key, name in (("v4", IPSET_V4), ("v6", IPSET_V6)):
        r = subprocess.run(["ipset", "list", name],
                           capture_output=True, text=True, check=False)
        members = False
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if line.startswith("Members:"):
                members = True
                continue
            if members and line:
                out[key].append(line)
    return out


# ══════════════════════════════════════════════════════════════════════════
#  RUNTIME-СКРИПТЫ (self-contained: systemd запускает их напрямую)
# ══════════════════════════════════════════════════════════════════════════

def render_firewall_apply_script(cfg: dict) -> Path:
    """/opt/smartdns/bin/smartdns-firewall-apply.py: применяет ПРЕРЕНДЕРЕННЫЙ
    набор правил (данные от build_iptables_rules на момент генерации) +
    ipset restore/save. Идемпотентен; smartdns-firewall.service oneshot."""
    rules = build_iptables_rules(cfg, _uid_of("smartdns"))
    payload = json.dumps(rules, indent=1, ensure_ascii=False)
    script = BIN_DIR / "smartdns-firewall-apply.py"
    script_text = f'''#!/usr/bin/env python3
# managed by smartdns-installer (chimera) — НЕ редактировать вручную.
# Правила перегенерируются при изменении настроек (whitelist/mode/bind).
import subprocess, sys
from pathlib import Path

RULES = {payload}
IPSET_SAVE = {str(IPSET_SAVE_FILE)!r}


def _run(cmd):
    subprocess.run(cmd, capture_output=True)


def main():
    for name, family in (("smartdns_clients", "inet"), ("smartdns_clients6", "inet6"),
                         ("dot_clients", "inet"), ("dot_clients6", "inet6")):
        _run(["ipset", "create", name, "hash:ip", "family", family,
              "timeout", "86400", "-exist"])
    p = Path(IPSET_SAVE)
    if p.exists() and p.stat().st_size > 0:
        with p.open("rb") as f:
            subprocess.run(["ipset", "restore", "-!"], stdin=f,
                           capture_output=True)
    for group in ("nat_v4", "in_v4", "out_v4", "nat_v6", "in_v6", "out_v6"):
        for cmd in RULES.get(group, []):
            if "-C" in cmd:
                binary, t_flag, table, _c, parent, _j, chain = cmd
                chk = [binary, t_flag, table, "-C", parent, "-j", chain]
                r = subprocess.run(chk, capture_output=True)
                if r.returncode != 0:
                    _run([binary, t_flag, table, "-I", parent, "1", "-j", chain])
                continue
            _run(cmd)
    _run(["ipset", "save"])
    try:
        r = subprocess.run(["ipset", "save"], capture_output=True, text=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(r.stdout or "")
        tmp.replace(p)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    script.write_text(script_text)
    script.chmod(0o755)
    return script


def render_watcher_scripts() -> "tuple[Path, Path]":
    """Ватчеры авторизации (self-contained Python; паритет bash-ватчеров):
    doh: хвост smartdns-auth.log nginx → 200+dns-message/web-auth-verified
    → ipset add 24ч; dot: хвост access.log xray [dot-in → dot-backend]."""
    common_head = '''#!/usr/bin/env python3
# managed by smartdns-installer (chimera) — НЕ редактировать вручную.
import re, subprocess, sys, time

IPSET_SAVE = {ipset_save!r}
LOG_FW = {log_fw!r}
SETTINGS = {settings!r}


def _run(cmd):
    return subprocess.run(cmd, capture_output=True)


def valid_ip(ip):
    ip = ip.strip()
    if not ip or "/" in ip:
        return ""
    if re.match(r"^(\\d{{1,3}}\\.){{3}}\\d{{1,3}}$", ip):
        o = [int(x) for x in ip.split(".")]
        return "v4" if all(x <= 255 for x in o) else ""
    if ":" in ip and re.match(r"^[0-9a-fA-F:]+$", ip):
        return "v6"
    return ""


def private(ip):
    return ip.startswith(("127.", "10.", "192.168.", "169.254.")) or \\
        ip in ("::1",) or ip.startswith(("fe80:", "fc00:", "fd00:", "::ffff:127."))


def ipset_add(sets, ip, ttl=86400):
    ok = False
    for s in sets:
        r = _run(["ipset", "add", s, ip, "timeout", str(ttl), "-exist"])
        ok = ok or r.returncode == 0
    return ok


def persist(state, now):
    if now - state.get("last_persist", 0) < 30:
        return
    try:
        r = subprocess.run(["ipset", "save"], capture_output=True, text=True)
        from pathlib import Path
        p = Path(IPSET_SAVE)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(r.stdout or "")
        tmp.replace(p)
        state["last_persist"] = now
    except Exception:
        pass


def log(msg):
    try:
        with open(LOG_FW, "a") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%S") + " " + msg + "\\n")
    except Exception:
        pass
'''
    doh = common_head + '''

def main():
    log_file = "/var/log/nginx/smartdns-auth.log"
    subprocess.run(["touch", log_file], capture_output=True)
    state = {{"last_persist": 0}}
    last_seen = {{}}
    proc = subprocess.Popen(["tail", "-n", "0", "-F", log_file],
                            stdout=subprocess.PIPE, text=True)
    for line in proc.stdout:
        parts = line.rstrip("\\n").split("|")
        if len(parts) < 6:
            continue
        ts, client_ip, status, up_status, ctype, sent = parts[:6]
        if status != "200" or up_status != "200":
            continue
        if ctype not in ("application/dns-message", "web-auth-verified"):
            continue
        if not re.match(r"^\\d+$", sent) or int(sent) < 12:
            continue
        client_ip = client_ip.replace("::ffff:", "")
        kind = valid_ip(client_ip)
        if not kind or private(client_ip):
            continue
        now = time.time()
        key = ctype + ":" + client_ip
        if ctype != "web-auth-verified" and now - last_seen.get(key, 0) < 60:
            continue
        sets = ["smartdns_clients" if kind == "v4" else "smartdns_clients6"]
        if ctype == "web-auth-verified":
            sets.append("dot_clients" if kind == "v4" else "dot_clients6")
        if ipset_add(sets, client_ip):
            last_seen[key] = now
            tag = "WEB-AUTH" if ctype == "web-auth-verified" else "DOH-AUTH"
            log(f"[{{tag}}] Авторизован {{client_ip}} (TTL 86400s)")
        persist(state, now)


if __name__ == "__main__":
    main()
'''
    dot = common_head + '''

def main():
    log_file = {xray_access!r}
    subprocess.run(["touch", log_file], capture_output=True)
    state = {{"last_persist": 0}}
    last_seen = {{}}
    mode = "shared"
    try:
        with open(SETTINGS) as f:
            import json
            mode = json.load(f).get("whitelist_mode", "shared")
    except Exception:
        pass
    proc = subprocess.Popen(["tail", "-n", "0", "-F", log_file],
                            stdout=subprocess.PIPE, text=True)
    for line in proc.stdout:
        if "[dot-in -> dot-backend]" not in line and \\
                "[dot-in >> dot-backend]" not in line:
            continue
        src = ""
        for i, tok in enumerate(line.split()):
            if tok == "from" and i + 1 < len(line.split()):
                src = line.split()[i + 1]
                break
        if not src:
            continue
        src = src.replace("tcp:", "")
        client_ip = src.rsplit(":", 1)[0].strip("[]").replace("::ffff:", "")
        kind = valid_ip(client_ip)
        if not kind or private(client_ip):
            continue
        now = time.time()
        if now - last_seen.get(client_ip, 0) < 60:
            continue
        sets = ["smartdns_clients" if kind == "v4" else "smartdns_clients6"]
        if mode == "separate":
            sets.append("dot_clients" if kind == "v4" else "dot_clients6")
        if ipset_add(sets, client_ip):
            last_seen[client_ip] = now
            log(f"[DOT-AUTH] Авторизован {{client_ip}} (TTL 86400s, режим {{mode}})")
        persist(state, now)


if __name__ == "__main__":
    main()
'''
    p_doh = BIN_DIR / "smartdns-doh-watcher.py"
    p_dot = BIN_DIR / "smartdns-dot-watcher.py"
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    p_doh.write_text(doh.format(ipset_save=str(IPSET_SAVE_FILE),
                                log_fw=str(LOG_DIR / "firewall.log"),
                                settings=str(STATE_DIR / "settings.json")))
    p_dot.write_text(dot.format(ipset_save=str(IPSET_SAVE_FILE),
                                log_fw=str(LOG_DIR / "firewall.log"),
                                settings=str(STATE_DIR / "settings.json"),
                                xray_access=str(
                                    Path("/var/log/smartdns/xray/access.log"))))
    p_doh.chmod(0o755)
    p_dot.chmod(0o755)
    return p_doh, p_dot


def write_watcher_scripts(cfg: dict) -> bool:
    render_watcher_scripts()
    render_firewall_apply_script(cfg)
    _ok("Ватчеры + firewall-apply скрипты записаны "
        f"({BIN_DIR}/smartdns-{{doh,dot}}-watcher.py)")
    return True
