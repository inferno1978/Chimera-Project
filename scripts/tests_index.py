#!/usr/bin/env python3
"""tests_index — генератор/чекер docs/TESTS_INDEX.md.

Плоский layout tests/ — нагрузочная архитектура: 299+ файлов считают
_PROJECT_ROOT как Path(__file__).resolve().parent.parent, ci_gate.txt
хранит module-пути tests.test_*, ci_suite.sh full строит список через
ls tests/test_*.py. Перенос в подкаталоги = правка ~300 файлов без
функциональной выгоды; вместо переноса — ЭТОТ индекс по семействам.

Запуск:
    python3 scripts/tests_index.py            # записать docs/TESTS_INDEX.md
    python3 scripts/tests_index.py --check    # сверить (exit 1 — устарел)

Правила свежести (проверяет tests/test_tests_index.py в CI):
  - добавлен/удалён тест-файл → regenerate;
  - изменилась первая строка докстринга теста → regenerate;
  - тест добавлен/убран из tests/ci_gate.txt → regenerate.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"
INDEX = REPO_ROOT / "docs" / "TESTS_INDEX.md"
GATE = TESTS_DIR / "ci_gate.txt"

# ── семейства: префикс имени файла (после test_) → раздел индекса ───────────
FAMILY_BY_PREFIX: list[tuple[str, str]] = [
    # (префикс, название семейства) — первое совпадение побеждает
    ("awg", "AmneziaWG (transport Mode B + standalone 2.0)"),
    ("hysteria2", "Hysteria2"),
    ("singbox", "sing-box / мульти-протокольные ядра"),
    ("xhttp", "xHTTP + REALITY"),
    ("xray", "Установка/конфиг Xray"),
    ("mieru", "Mieru"),
    ("fragment", "Фрагментация TLS (fragment-стек)"),
    ("telemt", "Telemt (телеметрия)"),
    ("mtproto", "Telemt (телеметрия)"),
    ("warp", "Cloudflare WARP"),
    ("subscription", "Подписки (subscription)"),
    ("satellite", "Подписки (subscription)"),
    ("ios", "Клиентские ссылки/конфиги"),
    ("client", "Клиентские ссылки/конфиги"),
    ("users", "Пользователи и доступ"),
    ("user", "Пользователи и доступ"),
    ("ttl", "Пользователи и доступ"),
    ("credential", "Пользователи и доступ"),
    ("geo", "Маршрутизация и GeoIP"),
    ("split", "Маршрутизация и GeoIP"),
    ("ru_subnets", "Маршрутизация и GeoIP"),
    ("ripe", "Маршрутизация и GeoIP"),
    ("as_direct", "Маршрутизация и GeoIP"),
    ("asn", "Маршрутизация и GeoIP"),
    ("dpi", "DPI-детекторы и гейты"),
    ("mask", "DPI-детекторы и гейты"),
    ("tg", "Telegram-боты и уведомления"),
    ("port", "Порты (port_registry, knocking, hopping)"),
    ("dns", "DNS (DNSCrypt, правила, редирект)"),
    ("chain", "Каскад и ноды (Mode B)"),
    ("agh", "AdGuard Home"),
    ("youtube", "YouTube/b4 (DPI bypass)"),
    ("b4", "YouTube/b4 (DPI bypass)"),
    ("wpp", "WPP: веб-панели и REST API"),
    ("admin", "WPP: веб-панели и REST API"),
    ("rest", "WPP: веб-панели и REST API"),
    ("triple", "WPP: веб-панели и REST API"),
    ("panel", "WPP: веб-панели и REST API"),
    ("naiveproxy", "Альтернативные протоколы"),
    ("fptn", "Альтернативные протоколы"),
    ("wdtt", "Альтернативные протоколы"),
    ("turntunnel", "Альтернативные протоколы"),
    ("turnable", "Альтернативные протоколы"),
    ("webdav", "Альтернативные протоколы"),
    ("trusttunnel", "Альтернативные протоколы"),
    ("olcrtc", "Альтернативные протоколы"),
    ("csqtt", "Альтернативные протоколы"),
    ("slipgate", "Альтернативные протоколы"),
    ("vk", "Альтернативные протоколы"),
    ("traffic", "Мониторинг и трафик"),
    ("health", "Мониторинг и трафик"),
    ("status", "Мониторинг и трафик"),
    ("speed", "Мониторинг и трафик"),
    ("network", "Сеть и системный слой"),
    ("system", "Сеть и системный слой"),
    ("cold_boot", "Сеть и системный слой"),
    ("fw_", "Сеть и системный слой"),
    ("iptables", "Сеть и системный слой"),
    ("ipset", "Сеть и системный слой"),
    ("autoban", "Безопасность и баны"),
    ("ipban", "Безопасность и баны"),
    ("honeypot", "Безопасность и баны"),
    ("ssh", "Безопасность и баны"),
    ("fail2ban", "Безопасность и баны"),
    ("icmp", "Безопасность и баны"),
    ("leak", "Гигиена репо и CI"),
    ("py_compat", "Гигиена репо и CI"),
    ("const_default", "Гигиена репо и CI"),
    ("fstring", "Гигиена репо и CI"),
    ("release_notes", "Гигиена репо и CI"),
    ("tests_index", "Гигиена репо и CI"),
    ("secure_bootstrap", "Установка/bootstrap"),
    ("bootstrap", "Установка/bootstrap"),
    ("install", "Установка/bootstrap"),
    ("uninstall", "Установка/bootstrap"),
    ("ssl", "Установка/bootstrap"),
    ("nginx", "Установка/bootstrap"),
    ("emergency", "Установка/bootstrap"),
    ("backup", "Бэкап и восстановление"),
    ("config_backup", "Бэкап и восстановление"),
    ("migration", "Бэкап и восстановление"),
    ("rollback", "Бэкап и восстановление"),
    ("core", "Ядро и TUI"),
    ("main", "Ядро и TUI"),
    ("menu", "Ядро и TUI"),
    ("ui", "Ядро и TUI"),
    ("box", "Ядро и TUI"),
    ("tui", "Ядро и TUI"),
    ("smoke", "Ядро и TUI"),
    ("resources", "Ядро и TUI"),
    ("scheduler", "Ядро и TUI"),
    ("tty", "Ядро и TUI"),
    ("text_width", "Ядро и TUI"),
    ("cron", "Ядро и TUI"),
    ("env_isolation", "Ядро и TUI"),
    ("test_runner", "Ядро и TUI"),
    ("updater", "Ядро и TUI"),
    ("download", "Ядро и TUI"),
    ("mirrors", "Зеркала и апстримы"),
    ("mirror", "Зеркала и апстримы"),
    ("upstream", "Зеркала и апстримы"),
    ("stale_mirror", "Зеркала и апстримы"),
    ("openflux", "Зеркала и апстримы"),
    ("github", "Зеркала и апстримы"),
    ("entry_mirrors", "Зеркала и апстримы"),
    ("cluster", "Каскад и ноды (Mode B)"),
    ("failover", "Каскад и ноды (Mode B)"),
    ("node_health", "Каскад и ноды (Mode B)"),
    ("exit_switch", "Каскад и ноды (Mode B)"),
    ("smart_balancer", "Каскад и ноды (Mode B)"),
    ("balancer", "Каскад и ноды (Mode B)"),
    ("ingress", "Маршрутизация и GeoIP"),
    ("diagnostics", "Мониторинг и трафик"),
    ("connection_audit", "Мониторинг и трафик"),
    ("bandwidth", "Мониторинг и трафик"),
    ("steal", "Мониторинг и трафик"),
    ("domain_strategy", "Установка/конфиг Xray"),
    ("domain", "Мониторинг и трафик"),
    ("certmon", "Мониторинг и трафик"),
    ("logrotate", "Мониторинг и трафик"),
    ("server_fragment", "Фрагментация TLS (fragment-стек)"),
    ("fingerprint", "Пользователи и доступ"),
    ("identity", "Пользователи и доступ"),
    ("access", "Пользователи и доступ"),
    ("hybrid_addon", "Альтернативные протоколы"),
    ("proto", "Альтернативные протоколы"),
    ("no_streamup", "Альтернативные протоколы"),
    ("pq_vless", "Клиентские ссылки/конфиги"),
    ("linkqr", "Клиентские ссылки/конфиги"),
    ("mtu", "Клиентские ссылки/конфиги"),
    ("cdn_masking", "Клиентские ссылки/конфиги"),
    ("ip_mask", "Безопасность и баны"),
    ("sni", "Установка/конфиг Xray"),
    ("min_client", "Установка/конфиг Xray"),
    ("tfo", "Установка/конфиг Xray"),
    ("resolv", "Сеть и системный слой"),
    ("enable_dns", "Сеть и системный слой"),
    ("fake_login", "Гигиена репо и CI"),
    ("clean_install", "Гигиена репо и CI"),
    ("all_specs", "Гигиена репо и CI"),
    ("wave", "Гигиена репо и CI"),
    ("turn", "Зеркала и апстримы"),
    ("no_streamup", "xHTTP + REALITY"),
]
FALLBACK = "Прочее"


def family_of(test_file: str) -> str:
    name = test_file[len("test_"):] if test_file.startswith("test_") else test_file
    for prefix, family in FAMILY_BY_PREFIX:
        if name.startswith(prefix):
            return family
    return FALLBACK


def docstring_first_line(path: Path) -> str:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return "—"
    doc = ast.get_docstring(tree)
    if not doc:
        return "—"
    fname_re = path.name
    for line in doc.splitlines()[:12]:
        s = line.strip()
        if not s or s == fname_re or s.endswith(fname_re):
            continue  # заголовок-имя файла
        if set(s) <= set("─═-—= "):
            continue  # линейка-разделитель
        return s[:110]
    return "—"


def gate_modules() -> set[str]:
    mods = set()
    if GATE.exists():
        for line in GATE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                mods.add(line.removeprefix("tests.").replace(".", "/") + ".py")
    return mods


def build_index() -> str:
    files = sorted(p.name for p in TESTS_DIR.glob("test_*.py"))
    gate = gate_modules()
    families: dict[str, list[tuple[str, str, bool]]] = {}
    for f in files:
        fam = family_of(f)
        families.setdefault(fam, []).append(
            (f, docstring_first_line(TESTS_DIR / f), f in gate))

    out = ["# Chimera — индекс тестов по семействам\n",
           "> Сгенерировано `scripts/tests_index.py` (миграция 2026-10-29). "
           "Плоский layout tests/ — намеренный: 299+ файлов считают "
           "`_PROJECT_ROOT = Path(__file__).resolve().parent.parent`, "
           "ci_gate.txt хранит module-пути `tests.test_*`, ci_suite.sh full "
           "строит список через `ls tests/test_*.py` — перенос в подкаталоги "
           "= правка ~300 файлов без функциональной выгоды. Навигация — "
           "этот индекс.\n",
           f"Всего тест-модулей: **{len(files)}** (гейт-манифест: "
           f"**{len(gate)}**; каждый test_*.py обязан быть в "
           "tests/ci_gate.txt — сверяется tests/test_tests_index.py).\n"]

    for fam in sorted(families, key=lambda f: -len(families[f])):
        rows = families[fam]
        out.append(f"\n## {fam} ({len(rows)})\n")
        out.append("| Тест | Что покрывает (первая строка докстринга) | ci_gate |")
        out.append("|---|---|---|")
        for name, desc, ingate in rows:
            esc = desc.replace("|", "\\|")
            out.append(f"| [`{name}`](../tests/{name}) | {esc} | {'✓' if ingate else '—'} |")
    return "\n".join(out) + "\n"


def main() -> int:
    if "--check" in sys.argv[1:]:
        if not INDEX.exists():
            print("STALE: docs/TESTS_INDEX.md отсутствует", file=sys.stderr)
            return 1
        current = INDEX.read_text(encoding="utf-8")
        fresh = build_index()
        if current != fresh:
            print("STALE: docs/TESTS_INDEX.md отличается от сгенерированного — "
                  "запустите python3 scripts/tests_index.py", file=sys.stderr)
            return 1
        print(f"FRESH: docs/TESTS_INDEX.md ({len(current.splitlines())} строк)")
        return 0
    INDEX.write_text(build_index(), encoding="utf-8")
    print(f"записан docs/TESTS_INDEX.md ({len(INDEX.read_text(encoding='utf-8').splitlines())} строк)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
