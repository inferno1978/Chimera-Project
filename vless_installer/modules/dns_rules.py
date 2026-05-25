"""
vless_installer/modules/dns_rules.py
───────────────────────────────────────────────────────────────────────────────
Кастомные DNS-правила для Xray — управление hosts и dns-routing из меню.

Позволяет:
  • domain → IP(s)   через секцию hosts{} в Xray config
  • domain → outbound через dns-routing правила (domain → direct/proxy)
  • Просмотр текущих hosts и dns-правил
  • Совместимость с DNSCrypt-proxy (blocked-names.txt)

Точка входа из _core.py:
    from vless_installer.modules.dns_rules import do_manage_dns_rules
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
import time
import textwrap
from vless_installer.modules.tui import tui_form, tui_select, tui_confirm, TuiField

# _set_config_owner — устанавливает владельца конфига; no-op если недоступна
def _set_config_owner(path) -> None:
    try:
        import shutil, pwd
        shutil.chown(str(path), user="root", group="root")
    except Exception:
        pass

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
        else:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m',
            )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BLUE', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED    = _C['RED']
GREEN  = _C['GREEN']
YELLOW = _C['YELLOW']
CYAN   = _C['CYAN']
BLUE   = _C['BLUE']
BOLD   = _C['BOLD']
DIM    = _C['DIM']
WHITE  = _C['WHITE']
NC     = _C['NC']

# ── Логирование ────────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/vless-install.log")

def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\033\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [{level}] {clean}\n")
    except Exception:
        pass

def _success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)
def _warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)

# ── Вспомогательные ───────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

# ── Пути (дублируем константы из _core.py, не импортируя их) ─────────────────
_CONFIG_DIR          = Path("/etc/xray")
_DIAG_CONFIG_FILE    = _CONFIG_DIR / "config.json"
_DIAG_ALT_CONFIG     = Path("/usr/local/etc/xray/config.json")


from vless_installer.modules.box_renderer import (
    _box_top, _box_bottom, _box_sep, _box_row, _box_item, _box_back,
)


# =============================================================================
#  МОДУЛЬ 11: КАСТОМНЫЕ DNS ПРАВИЛА (Xray hosts + DNSCrypt static)
#
#  Позволяет задать:
#    • domain → IP(s)   через секцию hosts{} в Xray config
#    • domain → outbound через dns-routing правила (domain → direct/proxy)
#    • Просмотр текущих hosts и dns-правил
#    • Совместимость с DNSCrypt-proxy (blocked-names.txt)
# =============================================================================

DNS_RULES_FILE  = Path("/var/lib/xray-installer/dns_rules.json")


def _dns_rules_load() -> dict:
    try:
        if DNS_RULES_FILE.exists():
            return json.loads(DNS_RULES_FILE.read_text())
    except Exception:
        pass
    return {"hosts": {}, "routing": []}


def _dns_rules_save(data: dict) -> None:
    DNS_RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    DNS_RULES_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    DNS_RULES_FILE.chmod(0o600)


def _dns_get_xray_config() -> "tuple[Path | None, dict]":
    for p in (_CONFIG_DIR / "config.json",
              Path("/usr/local/etc/xray/config.json")):
        if p.exists():
            try:
                return p, json.loads(p.read_text())
            except Exception:
                pass
    return None, {}


def _dns_apply_hosts(hosts: dict) -> bool:
    """
    Записывает dict {domain: [ip, ...]} в секцию dns.hosts Xray конфига.
    Merges с уже существующими записями.
    """
    cfg_path, cfg = _dns_get_xray_config()
    if not cfg_path:
        _warn("Xray конфиг не найден")
        return False
    try:
        dns_sec  = cfg.setdefault("dns", {})
        existing = dns_sec.get("hosts", {})
        existing.update(hosts)
        dns_sec["hosts"] = existing
        cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
        _set_config_owner(cfg_path)
        return True
    except Exception as e:
        _warn(f"Ошибка записи hosts: {e}")
        return False


def _dns_remove_host(domain: str) -> bool:
    cfg_path, cfg = _dns_get_xray_config()
    if not cfg_path:
        return False
    try:
        hosts = cfg.get("dns", {}).get("hosts", {})
        if domain in hosts:
            del hosts[domain]
            cfg.setdefault("dns", {})["hosts"] = hosts
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(cfg_path)
            return True
    except Exception as e:
        _warn(f"Ошибка удаления hosts: {e}")
    return False


def _dns_apply_routing_rule(domain: str, outbound: str) -> bool:
    """
    Добавляет routing-правило: domain → outbound (direct/proxy/block).
    Размещает перед остальными правилами.
    """
    cfg_path, cfg = _dns_get_xray_config()
    if not cfg_path:
        return False
    try:
        routing = cfg.setdefault("routing", {})
        rules   = routing.setdefault("rules", [])
        # Удаляем старое правило для этого домена если есть
        rules = [r for r in rules
                 if not (r.get("comment", "").startswith("dns_custom:")
                         and domain in r.get("domain", []))]
        new_rule = {
            "type":       "field",
            "domain":     [domain],
            "outboundTag": outbound,
            "comment":    f"dns_custom:{domain}",
        }
        routing["rules"] = [new_rule] + rules
        cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
        _set_config_owner(cfg_path)
        return True
    except Exception as e:
        _warn(f"Ошибка добавления dns routing: {e}")
        return False


def _dns_remove_routing_rule(domain: str) -> bool:
    cfg_path, cfg = _dns_get_xray_config()
    if not cfg_path:
        return False
    try:
        rules = cfg.get("routing", {}).get("rules", [])
        new_rules = [r for r in rules
                     if not (r.get("comment", "").startswith("dns_custom:")
                             and domain in r.get("domain", []))]
        cfg["routing"]["rules"] = new_rules
        cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
        _set_config_owner(cfg_path)
        return True
    except Exception as e:
        _warn(f"Ошибка удаления dns routing: {e}")
        return False


def _dns_reload_xray() -> None:
    # Xray 26.x не поддерживает SIGHUP reload — используем restart напрямую
    r = _run(["systemctl", "restart", "xray"], check=False, quiet=True)
    time.sleep(1)
    ok = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
    if ok.stdout.strip() == "active":
        _success("Xray перезапущен с новыми DNS правилами")
    else:
        _warn("Xray не запустился — проверьте конфиг!")


def _dns_validate_ip(text: str) -> "str | None":
    """Проверяет что текст — одиночный IP или список IP через запятую."""
    if not text:
        return "Введите IP-адрес"
    for part in text.split(","):
        p = part.strip()
        # IPv4
        parts4 = p.split(".")
        if len(parts4) == 4:
            if all(x.isdigit() and 0 <= int(x) <= 255 for x in parts4):
                continue
        # IPv6 — упрощённая проверка
        if ":" in p and len(p) <= 39:
            continue
        return f"Неверный IP: '{p}'"
    return None


def _dns_validate_domain(text: str) -> "str | None":
    if not text:
        return "Введите домен"
    # Базовая проверка — содержит точку, нет пробелов
    if " " in text:
        return "Домен не должен содержать пробелы"
    if "." not in text and not text.startswith("domain:") \
       and not text.startswith("geosite:"):
        return "Введите домен (напр.: example.com) или geosite:ru"
    return None


def do_manage_dns_rules() -> None:
    """
    Меню управления кастомными DNS правилами.
    """
    while True:
        os.system("clear")
        data     = _dns_rules_load()
        hosts    = data.get("hosts", {})
        rt_rules = data.get("routing", [])

        # Читаем актуальные hosts прямо из конфига
        _, cfg = _dns_get_xray_config()
        live_hosts    = cfg.get("dns", {}).get("hosts", {})
        live_rt_rules = [r for r in cfg.get("routing", {}).get("rules", [])
                         if r.get("comment", "").startswith("dns_custom:")]

        _box_top("🌐  КАСТОМНЫЕ DNS ПРАВИЛА")
        _box_row()

        # ── Hosts (domain → IP) ──
        _box_row(f"  {BOLD}Hosts (domain → IP):  {DIM}{len(live_hosts)} записей{NC}")
        if live_hosts:
            _box_sep()
            for dom, ips in list(live_hosts.items())[:8]:
                ip_str = ", ".join(ips) if isinstance(ips, list) else str(ips)
                line   = f"  {CYAN}{dom:<30}{NC} → {GREEN}{ip_str}{NC}"
                _box_row(line)
            if len(live_hosts) > 8:
                _box_row(f"  {DIM}... ещё {len(live_hosts)-8} записей{NC}")

        _box_sep()

        # ── Routing правила (domain → outbound) ──
        _box_row(
            f"  {BOLD}DNS routing (domain → outbound):  "
            f"{DIM}{len(live_rt_rules)} правил{NC}"
        )
        if live_rt_rules:
            _box_sep()
            for r in live_rt_rules[:6]:
                doms = ", ".join(r.get("domain", [])[:2])
                out  = r.get("outboundTag", "?")
                col  = GREEN if out == "direct" else CYAN if out == "proxy" else RED
                _box_row(f"  {DIM}{doms:<30}{NC} → {col}{out}{NC}")
            if len(live_rt_rules) > 6:
                _box_row(f"  {DIM}... ещё {len(live_rt_rules)-6} правил{NC}")

        _box_sep()
        _box_row()
        _box_item("1", f"Добавить host: domain → IP(s)")
        _box_item("2", f"Удалить host")
        _box_item("3", f"Добавить routing: domain → direct/proxy/block")
        _box_item("4", f"Удалить routing-правило")
        _box_item("5", f"Показать все DNS-правила из конфига")
        _box_item("6", f"Перезапустить Xray (применить изменения)")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        # ── 1: Добавить host ──────────────────────────────────────────────
        if ch == "1":
            print()
            result = tui_form("Добавить DNS host", [
                TuiField(
                    key="domain", label="Домен",
                    required=True, validator=_dns_validate_domain,
                    hint="Напр.: example.com  или  domain:google.com",
                ),
                TuiField(
                    key="ips", label="IP-адрес(а)",
                    required=True, validator=_dns_validate_ip,
                    hint="Один или несколько через запятую: 1.2.3.4, 5.6.7.8",
                ),
            ])
            if result:
                domain = result["domain"].strip().lower()
                ips    = [ip.strip() for ip in result["ips"].split(",") if ip.strip()]
                if _dns_apply_hosts({domain: ips}):
                    # Сохраняем в наш файл для учёта
                    data = _dns_rules_load()
                    data.setdefault("hosts", {})[domain] = ips
                    _dns_rules_save(data)
                    _success(f"Host добавлен: {domain} → {', '.join(ips)}")
                    _dns_reload_xray()
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── 2: Удалить host ───────────────────────────────────────────────
        elif ch == "2":
            if not live_hosts:
                _warn("Нет hosts для удаления")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            domains = list(live_hosts.keys())
            idx = tui_select(
                "Выберите домен для удаления",
                [f"{d}  →  {', '.join(live_hosts[d]) if isinstance(live_hosts[d],list) else live_hosts[d]}"
                 for d in domains],
            )
            if idx is not None:
                domain = domains[idx]
                if tui_confirm(f"Удалить host '{domain}'?", default=False):
                    _dns_remove_host(domain)
                    data = _dns_rules_load()
                    data.get("hosts", {}).pop(domain, None)
                    _dns_rules_save(data)
                    _success(f"Host '{domain}' удалён")
                    _dns_reload_xray()
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── 3: Добавить routing ───────────────────────────────────────────
        elif ch == "3":
            print()
            outbound_idx = tui_select(
                "Куда направить трафик домена?",
                [
                    f"direct  — напрямую (обход прокси)",
                    f"proxy   — через прокси/exit-ноду",
                    f"block   — заблокировать (blackhole)",
                ],
                default=0,
            )
            if outbound_idx is None:
                continue
            outbound_map = {0: "direct", 1: "proxy", 2: "block"}
            outbound = outbound_map[outbound_idx]

            result = tui_form(f"Routing: домен → {outbound}", [
                TuiField(
                    key="domain", label="Домен / паттерн",
                    required=True, validator=_dns_validate_domain,
                    hint="Напр.: ads.example.com  или  geosite:category-ads-all",
                ),
            ])
            if result:
                domain = result["domain"].strip().lower()
                if _dns_apply_routing_rule(domain, outbound):
                    data = _dns_rules_load()
                    data.setdefault("routing", []).append(
                        {"domain": domain, "outbound": outbound}
                    )
                    _dns_rules_save(data)
                    col = GREEN if outbound == "direct" else CYAN if outbound == "proxy" else RED
                    _success(f"Routing: {domain} → {col}{outbound}{NC}")
                    _dns_reload_xray()
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── 4: Удалить routing ────────────────────────────────────────────
        elif ch == "4":
            if not live_rt_rules:
                _warn("Нет кастомных routing-правил")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            options = [
                f"{', '.join(r.get('domain',[])[:2])}  →  {r.get('outboundTag','?')}"
                for r in live_rt_rules
            ]
            idx = tui_select("Выберите правило для удаления", options)
            if idx is not None:
                rule   = live_rt_rules[idx]
                domain = rule.get("domain", ["?"])[0]
                if tui_confirm(f"Удалить routing '{domain}'?", default=False):
                    _dns_remove_routing_rule(domain)
                    data = _dns_rules_load()
                    data["routing"] = [
                        r for r in data.get("routing", [])
                        if r.get("domain") != domain
                    ]
                    _dns_rules_save(data)
                    _success(f"Routing правило '{domain}' удалено")
                    _dns_reload_xray()
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── 5: Показать все DNS из конфига ────────────────────────────────
        elif ch == "5":
            os.system("clear")
            print()
            _box_top("DNS конфигурация Xray (dns секция)")
            dns_section = cfg.get("dns", {})
            if not dns_section:
                _box_row(f"  {DIM}Секция dns не найдена в конфиге{NC}")
            else:
                servers = dns_section.get("servers", [])
                _box_row(f"  {BOLD}DNS Servers:{NC}")
                for s in servers:
                    if isinstance(s, str):
                        _box_row(f"    {CYAN}{s}{NC}")
                    elif isinstance(s, dict):
                        addr    = s.get("address", "")
                        domains = s.get("domains", [])
                        dom_str = ", ".join(domains[:3]) + ("..." if len(domains)>3 else "")
                        _box_row(f"    {CYAN}{addr}{NC}  {DIM}→ {dom_str}{NC}")
                _box_sep()
                _box_row(f"  {BOLD}Hosts ({len(live_hosts)} записей):{NC}")
                for dom, ips in live_hosts.items():
                    ip_str = ", ".join(ips) if isinstance(ips, list) else str(ips)
                    _box_row(f"    {dom:<35} → {ip_str}")
                _box_sep()
                _box_row(f"  {BOLD}Кастомные routing ({len(live_rt_rules)} правил):{NC}")
                for r in live_rt_rules:
                    doms = ", ".join(r.get("domain", []))
                    out  = r.get("outboundTag", "?")
                    _box_row(f"    {doms:<35} → {out}")
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── 6: Перезапустить Xray ─────────────────────────────────────────
        elif ch == "6":
            print()
            _dns_reload_xray()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", ""):
            break
        else:
            _warn("Неверный выбор")
            time.sleep(1)



