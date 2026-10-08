#!/usr/bin/env python3
"""leak_guard — защита репозитория от утечки чувствительных данных.

Запуск:
    python3 scripts/leak_guard.py                 # все tracked-файлы
    python3 scripts/leak_guard.py path1 path2      # конкретные файлы
    python3 scripts/leak_guard.py --staged         # добавленные строки индекса (pre-commit)
    python3 scripts/leak_guard.py --diff HEAD      # незакоммиченные добавленные строки
    python3 scripts/leak_guard.py --msg-file FILE  # текст commit-message (commit-msg)

Классы находок:
    LEAK  — публичный IPv4 вне allowlist; токены/ключи/креды
            (glpat-, ghp_, gho_, xox, AKIA, PRIVATE KEY, JWT,
             Telegram-бот токен, SSH-пароль в конфиг-форме).
            Код возврата 1 — коммит/пуш ЗАПРЕЩЁН.
    WARN  — UUID (возможно фикстура, возможно прод-ключ), домен вне
            известного публичного списка. Код возврата 0, но список
            печатается для ревью глазами.

Allowlist IP: loopback/private/CGNAT/link-local/multicast, TEST-NET
(192.0.2.x, 198.51.100.x, 203.0.113.x), публичные DNS-резолверы,
Cloudflare (WARP/CDN, 162.159.0.0/16, 104.16.0.0/12, 172.64.0.0/13,
188.114.0.0/15), Telegram DC (149.154.160.0/20, 91.108.0.0/16),
документированные кейс-стади и строки-версии, совпадающие по формату
с IPv4. Политика: docs/faq/SECURITY_LEAK_POLICY.md.
"""
import ipaddress
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

IP_ALLOW = [
    ipaddress.ip_network(n) for n in (
        "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.0.2.0/24", "192.168.0.0/16",
        "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
        "224.0.0.0/4", "255.255.255.255/32", "100.64.0.0/10",
        # канонические doc-example адреса
        "1.2.3.0/24", "5.6.7.0/24", "5.6.8.0/24",
        # публичные DNS
        "1.1.1.1/32", "1.0.0.1/32", "8.8.8.8/32", "8.8.4.4/32",
        "9.9.9.9/32", "149.112.112.112/32", "94.140.14.14/32",
        "94.140.15.15/32", "208.67.222.222/32", "208.67.220.220/32",
        # Cloudflare (WARP endpoints, CDN edge)
        "162.159.0.0/16", "104.16.0.0/12", "172.64.0.0/13",
        "188.114.0.0/15", "104.20.23.154/32", "172.66.147.243/32",
        # Telegram DC
        "149.154.160.0/20", "91.108.0.0/16", "91.105.192.0/23",
        # кейс-стади сторонней инфраструктуры (docs, не наша)
        "194.67.71.0/24",
        # публичные DNS/DoH-резолверы в коде и доках проекта
        "77.88.8.8/32", "77.88.8.1/32",          # Yandex DNS
        "223.5.5.5/32",                            # AliDNS
        "93.184.216.34/32",                        # example.com (A-запись)
        "195.208.5.1/32",                          # НСДИ (RKN NSDI)
        "188.40.167.82/32",                        # 2ip.ru
        # публичные DNSCrypt-резолверы (каталог dnscrypt_advanced)
        "185.228.168.10/32", "185.228.168.168/32", "193.70.85.11/32",
        "41.185.28.195/32", "76.76.2.1/32", "1.1.1.3/32", "149.112.112.10/32",
        "193.34.145.92/32", "194.242.2.3/32", "194.242.2.4/32", "194.242.2.5/32",
        "194.242.2.9/32", "208.67.222.123/32", "216.18.214.193/32", "217.169.20.23/32",
        "45.11.45.11/32", "5.9.164.112/32", "80.241.218.68/32", "92.38.135.1/32",
        # сети интернет-сканеров (geoip_block: Censys/Rapid7/Shodan и др.)
        "198.20.69.74/31", "198.20.69.96/27", "198.20.99.130/31", "198.20.99.132/30",
        "162.142.125.0/24", "167.248.133.0/24", "45.83.66.0/24", "45.83.67.0/24",
        "71.6.135.131/32", "71.6.167.142/32", "71.6.199.23/32", "104.131.0.69/32",
        "45.129.14.0/24", "45.129.15.0/24", "176.119.7.0/24", "207.241.224.0/20",
        # канонические фикстуры тестов (публичные примеры, не наша инфра)
        "2.2.2.2/32", "3.3.3.3/32", "9.10.11.12/32", "99.99.99.99/32",
        "142.250.185.78/32", "142.250.74.14/32",  # Google (fixtures)
        "85.249.244.49/32", "81.27.242.141/32",  # googlevideo CDN (DNS-фикстуры)
        "157.240.0.174/32", "157.240.253.174/32",  # Meta (vendor-тесты)
        "94.189.76.227/32", "178.130.140.98/32", "85.233.150.240/32",  # vendor b4
        # публичные константы/фикстуры: Google/Meta/Cloudflare/TG/Bunny/M247,
        # warp-scan pools, iperf-списки network_bench, doc-константы диапазонов
        # (полная атрибуция — аудит Task 16, 2026-10-08; здесь только точные строки)
        "1.0.0.0/32", "103.21.244.0/32", "103.22.200.0/32", "103.31.4.0/32",
        "103.4.96.0/32", "109.239.140.0/32", "109.61.83.105/32", "120.0.0.0/32",
        "128.0.0.0/32", "13.224.1.0/32", "140.82.121.4/32", "142.250.190.5/32",
        "142.251.38.142/32", "157.240.0.0/32", "157.240.13.14/32", "157.240.13.19/32",
        "157.240.15.19/32", "157.240.205.21/32", "173.194.0.0/32", "173.194.222.101/32",
        "185.102.218.1/32", "185.102.219.93/32", "185.152.67.2/32", "185.59.223.8/32",
        "185.76.151.0/32", "195.128.1.10/32", "2.0.0.0/32", "207.223.160.0/32",
        "209.85.128.0/32", "216.239.32.0/32", "216.58.192.0/32", "223.0.0.0/32",
        "240.0.0.0/32", "3.0.0.0/32", "31.13.24.0/32", "31.13.32.0/32", "4.1.0.1/32",
        "49.205.75.2/32", "57.144.14.141/32", "57.144.144.128/32", "57.144.144.129/32",
        "57.144.150.128/32", "57.144.150.144/32", "57.144.150.33/32", "57.144.150.5/32",
        "57.144.152.3/32", "57.144.152.33/32", "57.144.160.33/32", "57.144.160.5/32",
        "57.144.186.3/32", "57.144.186.35/32", "57.144.64.1/32", "57.144.64.128/32",
        "57.144.64.141/32", "57.144.64.144/32", "57.144.98.141/32", "64.233.160.0/32",
        "66.102.0.0/32", "66.249.64.0/32", "72.14.192.0/32", "74.125.0.0/32",
        "77.88.55.77/32", "8.34.146.0/32", "8.34.70.0/32", "8.34.70.148/32",
        "8.35.211.0/32", "8.39.125.0/32", "8.39.204.0/32", "8.39.214.0/32",
        "8.47.69.0/32", "8.6.112.0/32", "8.6.112.1/32", "81.27.242.142/32",
        "84.17.57.129/32", "89.187.160.1/32", "89.187.162.1/32", "89.187.162.249/32",
        "89.187.188.227/32", "89.187.188.228/32", "9.0.0.1/32", "9.9.9.0/32",
        "91.105.200.0/32", "92.223.124.39/32", "92.223.76.26/32", "94.176.183.13/32",
        "95.161.64.0/32",
    )
]

IP_EXTRA_ALLOW = {
    # строки-версии ПО, совпадающие по формату с IPv4
    "5.11.28.3", "5.0.1.5", "5.5.5.5", "5.5.11.3", "5.167.99.99",
}

TOKEN_PATTERNS = [
    ("gitlab-token", re.compile(r"glpat-[A-Za-z0-9_\-]{10,}")),
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("aws-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.")),
    ("tg-bot-token", re.compile(r"\b\d{8,12}:[A-Za-z0-9_\-]{30,}\b")),
    ("ssh-pass-inline", re.compile(
        r"(?i)\b(?:password|passwd|pass)\b\s*[:=]\s*[\"']?"
        r"(?!\{|document|window|getElementById|this\b|self\b|none\b|null\b"
        r"|true\b|false\b|undefined\b|value\b|str\b|\$|<|%"
        r"|Optional\b|None\b|bool\b|int\b|bytes\b|float\b|dict\b|list\b"
        r"|password\b|passwd\b|pass\b"
        r"|secret|token|getpass|raw_pass|proto_gen|_s\.|curCfg|_cfg|pwd"
        r"|trusttunnel_derive|_get_effective|singbox_gen|_gen_admin"
        r"|_get_creds|user\.get|form\.get|user_pass|new_pass|line\.split"
        r"|derive|generate|_gen_|gen_pw"
        r"|alice-|bob-|carol-|s3cret|shadow_pw|p@ss|new-pass|with:colons"
        r"|anytls_pw|anytls-|reapplypw|mypassword|fallback|proto_ask"
        r"|node\.get|state\.get|user_record|decoded\.partition|users_by_name"
        r"|_generate|_tt_pass|active_node|body\.get|PublicKey|NEWPUB"
        r"|v2\.6-public|добавление|OldMaster123"
        r")[^\s\"'<>{ }()=]{8,}")),
    ("ssh-user-host", re.compile(
        r"\b(?:ssh|scp|sftp)\s+(?:-\S+\s+)*[A-Za-z0-9_.-]+@\s*\d{1,3}(?:\.\d{1,3}){3}")),
]

IP_RE = re.compile(r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])")
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9][a-z0-9-]{1,61}\.){1,2}(?:com|net|org|io|dev|app|me|ru|su|"
    r"is|to|xyz|cc|info|biz|club|online|site|store|tech|pro|ai|co)\b")

# Публичные домены, встречающиеся в коде/доках проекта (DPI-листы, ссылки).
# НОВЫЕ домены в коммите → WARN: проверь, что это не твой VPS/панель/DDNS.
DOMAIN_KNOWN = {
    "example.com", "example.net", "example.org", "github.com",
    "gitlab.com", "raw.githubusercontent.com", "githubusercontent.com",
    "npmjs.org", "cloudflare.com", "cloudflareclient.com",
    "telegram.org", "google.com", "googlevideo.com", "ytimg.com",
    "golang.org", "opencollective.com", "jsdelivr.net", "yandex.ru",
    "yandex.net", "vk.com", "whatsapp.com", "facebook.com",
    "instagram.com", "meduza.io", "2gis.com", "ip-api.com",
    "youtube.com", "b4core.app", "ghproxy.net", "quad9.net",
    "adguard.com", "nginx.org", "adguard.net", "serverfault.com",
    "stackoverflow.com", "superuser.com", "wikipedia.org",
}


SKIP_EXT = {
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff",
    ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".zip", ".gz",
    ".bin", ".lock", ".pdf", "",
}

# Vendored сторонние деревья (публичные апстрим-проекты, не наша инфра):
# полный аудит их не сканирует; хуки --staged/--diff на новые строки работают везде.
PATH_ALLOW_PREFIXES = (
    "vendor/b4/",
    "chimera/modules/_vendor/",
    "vless_installer/",  # легаси-копия установщика (сверяется отдельными аудитами)
)


def _ip_allowed(ip: str) -> bool:
    if ip in IP_EXTRA_ALLOW:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True  # не IP (переполнение октета) — regex не дал бы
    return any(a in net for net in IP_ALLOW)


def scan_text(text: str, origin: str, leaks: list, warns: list,
              is_doc: bool = False) -> None:
    for m in IP_RE.finditer(text):
        if not _ip_allowed(m.group(1)):
            leaks.append((origin, f"публичный IP {m.group(1)}"))
    for name, rx in TOKEN_PATTERNS:
        for m in rx.finditer(text):
            frag = m.group(0)
            # docstring-примеры вида password=ПАРОЛЬ в *.md — WARN,
            # в коде/конфигах — LEAK
            target = warns if (is_doc and name == "ssh-pass-inline") else leaks
            target.append((origin, f"{name}: {frag[:40]}..."))
    for m in UUID_RE.finditer(text):
        warns.append((origin, f"UUID {m.group(0)} (фикстура или прод-ключ?)"))
    for m in DOMAIN_RE.finditer(text):
        d = m.group(0).lower().lstrip(".")
        sld = ".".join(d.split(".")[-2:])
        base = d.removeprefix("www.")
        if base not in DOMAIN_KNOWN and sld not in DOMAIN_KNOWN:
            if not base.endswith(".example.com") and ".example." not in base:
                warns.append((origin, f"домен {d} вне публичного списка"))


def tracked_files() -> list:
    out = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files"],
        capture_output=True, text=True).stdout.splitlines()
    return [REPO_ROOT / f for f in out if f]


def added_lines(ref: str) -> str:
    diff = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "diff", ref, "--no-color", "-U0"],
        capture_output=True, text=True).stdout
    return "\n".join(l[1:] for l in diff.splitlines() if l.startswith("+")
                     and not l.startswith("+++"))


def staged_lines() -> str:
    diff = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "diff", "--cached", "--no-color", "-U0"],
        capture_output=True, text=True).stdout
    return "\n".join(l[1:] for l in diff.splitlines() if l.startswith("+")
                     and not l.startswith("+++"))


def main() -> int:
    args = sys.argv[1:]
    leaks, warns = [], []
    if not args:
        for f in tracked_files():
            rel = str(f.relative_to(REPO_ROOT))
            if f.suffix.lower() in SKIP_EXT:
                continue
            if any(rel.startswith(p) for p in PATH_ALLOW_PREFIXES):
                continue
            try:
                scan_text(f.read_text(encoding="utf-8", errors="replace"),
                          rel, leaks, warns,
                          is_doc=f.suffix.lower() == ".md")
            except OSError:
                pass
    elif args[0] == "--staged":
        scan_text(staged_lines(), "STAGED (+lines)", leaks, warns)
    elif args[0] == "--diff":
        scan_text(added_lines(args[1] if len(args) > 1 else "HEAD"),
                  f"DIFF {args[1] if len(args) > 1 else 'HEAD'} (+lines)",
                  leaks, warns)
    elif args[0] == "--msg-file":
        scan_text(Path(args[1]).read_text(encoding="utf-8", errors="replace"),
                  "COMMIT-MSG", leaks, warns)
    else:
        for p in map(Path, args):
            if p.exists():
                scan_text(p.read_text(encoding="utf-8", errors="replace"),
                          str(p), leaks, warns)

    for origin, what in leaks:
        print(f"LEAK  [{origin}] {what}")
    for origin, what in warns:
        print(f"WARN  [{origin}] {what}")
    if leaks:
        print(f"\nleak_guard: {len(leaks)} LEAK — коммит/пуш запрещён. "
              "См. docs/faq/SECURITY_LEAK_POLICY.md")
        return 1
    print(f"leak_guard: чисто (LEAK: 0, WARN: {len(warns)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
