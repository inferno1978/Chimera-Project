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
        "149.154.160.0/20", "91.108.0.0/16",
        # кейс-стади сторонней инфраструктуры (docs, не наша)
        "194.67.71.0/24",
    )
]

IP_EXTRA_ALLOW = {
    # строки-версии ПО, совпадающие по формату с IPv4
    "5.11.28.3", "5.0.1.5",
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
        r"|true\b|false\b|undefined\b|value\b|str\b|\$|<|%)[^\s\"'<>{ }()=]{8,}")),
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
            if f.suffix.lower() in SKIP_EXT:
                continue
            try:
                scan_text(f.read_text(encoding="utf-8", errors="replace"),
                          str(f.relative_to(REPO_ROOT)), leaks, warns,
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
