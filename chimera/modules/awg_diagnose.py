"""
chimera/modules/awg_diagnose.py
───────────────────────────────────────────────────────────────────────────────
Диагностика AmneziaWG standalone.

Проверки:
  1. Kernel module: lsmod amnezia, awg --version
  2. Sysctl: ip_forward, BBR, буферы (idempotent check)
  3. UFW: наличие правила для AWG-порта
  4. Service: systemctl is-active awg-quick@awg0
  5. Tunnel: awg show (peers + handshakes + transfer)
  6. Carrier-compare: сравнение текущих JC/JMIN/JMAX/I1 с профилем оператора
  7. NAT/Routing: проверка nftables MASQUERADE + FORWARD правил
     (мигрировано с iptables -t nat -L на nft list chain inet chimera, этап 1.6)
"""
from __future__ import annotations

import re
from pathlib import Path

from .awg_constants import (
    AWGS_BIN, AWGS_QUICK_BIN, AWGS_INTERFACE, AWGS_SYSTEMD_AWG_QUICK,
    AWGS_SERVER_CONF, AWGS_SYSCTL_TARGETS, AWGS_DEFAULT_PORT,
)
from .awg_state import awgs_state_load, awgs_state_is_installed
from .awg_presets import awgs_presets_compare_with_carrier, awgs_presets_list
from .awg_apply import awgs_service_status, awgs_show_handshakes
from .awg_hw_tuning import awgs_sysctl_get

# ЭТАП 1.6 МИГРАЦИИ: nftables helpers для диагностики NAT/MASQUERADE/FORWARD.
# Раньше: `iptables -t nat -L POSTROUTING -n -v` → парсинг строк.
# Теперь: `nft_rule_exists(comment=...)` через `nft -j list chain` JSON.
from .nft_common import nft_rule_exists
from .nft_constants import (
    NFT_TABLE_NAME, NFT_TABLE_FAMILY,
    NFT_CHAIN_FORWARD, NFT_CHAIN_POSTROUTING,
    COMMENT_AWG_MASQ,
)


def _core_module():
    import importlib
    return importlib.import_module("chimera._core")


# ── Отдельные проверки ──────────────────────────────────────────────────────

def _diag_kernel_module() -> dict:
    """Проверка DKMS-модуля."""
    core = _core_module()
    r = core._run(["lsmod"], capture=True, check=False)
    has_module = "amnezia" in r.stdout
    # Версия
    r2 = core._run([AWGS_BIN, "--version"], capture=True, check=False)
    version = r2.stdout.strip() if r2.returncode == 0 else ""
    return {
        "ok":       has_module,
        "status":   "OK" if has_module else "FAIL",
        "module":   "amnezia" if has_module else "не загружен",
        "version":  version,
    }


def _diag_sysctl() -> list:
    """Проверка sysctl-настроек."""
    core = _core_module()
    results = []
    for key, target in AWGS_SYSCTL_TARGETS.items():
        # IPv6 forwarding — пропускаем если IPv6 выключен
        if key == "net.ipv6.conf.all.forwarding":
            r = core._run(["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"],
                          capture=True, check=False)
            if r.stdout.strip() == "1":
                results.append({
                    "key":     key,
                    "current": "n/a (IPv6 disabled)",
                    "target":  str(target),
                    "status":  "SKIP",
                })
                continue
        current = awgs_sysctl_get(key)
        ok = str(current) == str(target)
        results.append({
            "key":     key,
            "current": current or "(не задано)",
            "target":  str(target),
            "status":  "OK" if ok else "WARN",
        })
    return results


def _diag_ufw(port: int) -> dict:
    """Проверка UFW-правила для AWG-порта."""
    core = _core_module()
    r = core._run(["ufw", "status"], capture=True, check=False)
    if r.returncode != 0 or "inactive" in r.stdout.lower():
        return {"ok": True, "status": "SKIP", "msg": "UFW неактивен"}
    has_rule = f"{port}/udp" in r.stdout
    return {
        "ok":      has_rule,
        "status":  "OK" if has_rule else "WARN",
        "msg":     f"UFW {'разрешён' if has_rule else 'НЕ разрешён'} UDP {port}",
    }


def _diag_service() -> dict:
    """Проверка статуса awg-quick@awg0."""
    status = awgs_service_status()
    return {
        "ok":      status["active"],
        "status":  "OK" if status["active"] else "FAIL",
        "active":  status["active"],
        "enabled": status["enabled"],
    }


def _diag_tunnel() -> dict:
    """Проверка туннеля (через awg show)."""
    output = awgs_show_handshakes()
    if not output:
        return {"ok": False, "status": "WARN", "msg": "awg show пуст"}
    # Считаем peers с handshake
    peer_count = output.count("peer: ")
    handshake_count = output.count("latest handshake")
    return {
        "ok":          True,
        "status":      "OK",
        "peers":       peer_count,
        "handshakes":  handshake_count,
        "raw":         output[:500],  # обрезаем для отчёта
    }


def _diag_nat_routing() -> dict:
    """
    Проверка NAT/MASQUERADE + ip_forward + маршрутизации.
    КРИТИЧНО: без этого 'подключение есть, но интернета нет'.

    ЭТАП 1.6 МИГРАЦИИ:
      • MASQUERADE проверяется через `nft_rule_exists(comment="awg-masquerade")`
        вместо парсинга `iptables -t nat -L POSTROUTING -n -v`.
      • FORWARD проверяется через `nft_rule_exists(comment="awg-forward-in")`
        вместо парсинга `iptables -L FORWARD -n -v`.
      • ip_forward / route / rp_filter — без изменений (это sysctl + iproute2,
        не netfilter).
    """
    core = _core_module()
    from .awg_constants import AWGS_INTERFACE
    from .awg_state import awgs_state_load
    state = awgs_state_load()
    subnet = state.get("subnet", "10.66.66.0/24")

    checks = []

    # 1. ip_forward
    r = core._run(["sysctl", "-n", "net.ipv4.ip_forward"],
                  capture=True, check=False)
    ip_fwd = r.stdout.strip()
    checks.append({
        "name":    "ip_forward",
        "ok":      ip_fwd == "1",
        "status":  "OK" if ip_fwd == "1" else "FAIL",
        "msg":     f"net.ipv4.ip_forward = {ip_fwd} (нужно 1)",
    })

    # 2. MASQUERADE правило (мигрировано: nft_rule_exists по comment-tag)
    # Раньше: `iptables -t nat -L POSTROUTING -n -v` → поиск "MASQUERADE" + subnet
    # Теперь: `nft_rule_exists(table="chimera", chain="postrouting",
    #                        comment="awg-masquerade")` через JSON `nft -j list chain`
    try:
        has_masq = nft_rule_exists(
            table=NFT_TABLE_NAME, chain=NFT_CHAIN_POSTROUTING,
            comment=COMMENT_AWG_MASQ, family=NFT_TABLE_FAMILY,
        )
    except Exception:
        has_masq = False
    checks.append({
        "name":    "MASQUERADE",
        "ok":      has_masq,
        "status":  "OK" if has_masq else "FAIL",
        "msg":     f"MASQUERADE для {subnet}: {'есть' if has_masq else 'ОТСУТСТВУЕТ — клиенты не получат интернет!'}",
    })

    # 3. FORWARD правило (awg0 → anywhere) — nft_rule_exists по comment "awg-forward-in"
    # Раньше: `iptables -L FORWARD -n -v` → поиск AWGS_INTERFACE + ACCEPT
    # Теперь: `nft_rule_exists(comment="awg-forward-in")` в chain=forward
    try:
        has_fwd = nft_rule_exists(
            table=NFT_TABLE_NAME, chain=NFT_CHAIN_FORWARD,
            comment="awg-forward-in", family=NFT_TABLE_FAMILY,
        )
    except Exception:
        has_fwd = False
    checks.append({
        "name":    "FORWARD",
        "ok":      has_fwd,
        "status":  "OK" if has_fwd else "WARN",
        "msg":     f"FORWARD через {AWGS_INTERFACE}: {'разрешён' if has_fwd else 'не найден (может быть в дефолтной политике)'}",
    })

    # 4. Маршрут к подсети awg0 (НЕ ТРОГАТЬ — это iproute2, не netfilter)
    r = core._run(["ip", "route", "show"], capture=True, check=False)
    has_route = subnet in r.stdout or AWGS_INTERFACE in r.stdout
    checks.append({
        "name":    "Route awg0",
        "ok":      has_route,
        "status":  "OK" if has_route else "FAIL",
        "msg":     f"Маршрут {subnet} dev {AWGS_INTERFACE}: {'есть' if has_route else 'ОТСУТСТВУЕТ — проверьте Address в awg0.conf (должен быть /24 не /32)'}",
    })

    # 5. rp_filter (предупреждение, не блок) — НЕ ТРОГАТЬ (sysctl, не netfilter)
    r = core._run(["sysctl", "-n", f"net.ipv4.conf.{AWGS_INTERFACE}.rp_filter"],
                  capture=True, check=False)
    rp = r.stdout.strip() if r.returncode == 0 else "?"
    checks.append({
        "name":    "rp_filter",
        "ok":      rp in ("0", "2"),
        "status":  "OK" if rp in ("0", "2") else "WARN",
        "msg":     f"rp_filter {AWGS_INTERFACE} = {rp} (0 или 2 — OK, 1 — может ломать NAT)",
    })

    has_fail = any(c["status"] == "FAIL" for c in checks)
    has_warn = any(c["status"] == "WARN" for c in checks)
    return {
        "ok":      not has_fail,
        "status":  "FAIL" if has_fail else ("WARN" if has_warn else "OK"),
        "checks":  checks,
    }


def _diag_carrier_compare(carrier: str) -> dict:
    """Сравнение текущих параметров с профилем оператора."""
    state = awgs_state_load()
    params = state.get("params", {})
    return awgs_presets_compare_with_carrier(params, carrier)


# ── Полный diagnostic-отчёт ────────────────────────────────────────────────

def awgs_diagnose_full(carrier: str = "") -> dict:
    """
    Полный diagnostic-отчёт.
    Возвращает dict со всеми проверками.
    """
    core = _core_module()
    state = awgs_state_load()
    port = state.get("port", AWGS_DEFAULT_PORT)

    report = {
        "installed":     awgs_state_is_installed(),
        "kernel":        _diag_kernel_module(),
        "sysctl":        _diag_sysctl(),
        "ufw":           _diag_ufw(port),
        "service":       _diag_service(),
        "nat_routing":   _diag_nat_routing(),
        "tunnel":        _diag_tunnel(),
    }

    if carrier:
        report["carrier_compare"] = _diag_carrier_compare(carrier)

    return report


# ── TUI-МЕНЮ ────────────────────────────────────────────────────────────────

def do_awg_diagnose_menu() -> None:
    """TUI-меню диагностики."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_sep = core._box_sep
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    info = core.info
    warn = core.warn
    GREEN, NC, RED, YELLOW, CYAN, DIM, BOLD = (
        core.GREEN, core.NC, core.RED, core.YELLOW, core.CYAN, core.DIM, core.BOLD
    )

    print()
    info("Запуск диагностики AmneziaWG standalone...")
    print()

    # Спрашиваем carrier для сравнения
    print(f"{CYAN}Сравнить с оператором?{NC} (Enter = пропустить)")
    presets = awgs_presets_list()
    for i, p in enumerate(presets, 1):
        print(f"  [{i}] {p}")
    carrier_ch = input(f"{CYAN}Выбор: {NC}").strip()
    carrier = ""
    if carrier_ch:
        try:
            idx = int(carrier_ch) - 1
            if 0 <= idx < len(presets):
                carrier = presets[idx]
        except ValueError:
            pass

    report = awgs_diagnose_full(carrier=carrier)

    # Вывод отчёта
    _box_top(f"Diagnostic report")
    _box_row()

    # Installed
    if report["installed"]:
        _box_row(f"  {GREEN}●{NC} Standalone AWG установлен")
    else:
        _box_row(f"  {RED}●{NC} Standalone AWG НЕ установлен")
    _box_sep()

    # Kernel
    k = report["kernel"]
    icon = "✅" if k["ok"] else "❌"
    _box_row(f"  {icon} Kernel module: {k['module']} {k.get('version', '')}")
    _box_sep()

    # Sysctl
    _box_row(f"  {BOLD}Sysctl:{NC}")
    for s in report["sysctl"]:
        if s["status"] == "OK":
            icon = "✅"
            color = GREEN
        elif s["status"] == "WARN":
            icon = "⚠️"
            color = YELLOW
        else:
            icon = "⏭️"
            color = DIM
        _box_row(f"    {icon} {s['key']}: {color}{s['current']}{NC} (target: {s['target']})")
    _box_sep()

    # UFW
    u = report["ufw"]
    if u["status"] == "SKIP":
        _box_row(f"  ⏭️ UFW: {u['msg']}")
    else:
        icon = "✅" if u["ok"] else "⚠️"
        _box_row(f"  {icon} UFW: {u['msg']}")
    _box_sep()

    # Service
    s = report["service"]
    icon = "✅" if s["ok"] else "❌"
    state_str = "active" if s["active"] else "INACTIVE"
    enabled_str = "enabled" if s["enabled"] else "DISABLED"
    _box_row(f"  {icon} Service awg-quick@awg0: {state_str}, {enabled_str}")
    _box_sep()

    # Tunnel
    t = report["tunnel"]
    if t["status"] == "OK":
        _box_row(f"  ✅ Tunnel: peers={t['peers']}, handshakes={t['handshakes']}")
    else:
        _box_row(f"  ⚠️ Tunnel: {t.get('msg', 'нет данных')}")
    _box_sep()

    # NAT / Routing (КРИТИЧНО для интернета у клиентов)
    nr = report["nat_routing"]
    _box_row(f"  {BOLD}NAT / Routing:{NC} {'✅' if nr['ok'] else '❌'}")
    for c in nr["checks"]:
        if c["status"] == "OK":
            icon = "✅"
            color = GREEN
        elif c["status"] == "WARN":
            icon = "⚠️"
            color = YELLOW
        else:
            icon = "❌"
            color = RED
        _box_row(f"    {icon} {color}{c['name']}{NC}: {c['msg']}")
    _box_sep()

    # Carrier compare (если выбран)
    if "carrier_compare" in report:
        cc = report["carrier_compare"]
        if cc.get("ok"):
            _box_row(f"  {BOLD}Carrier compare ({cc['carrier']}):{NC} {GREEN}{cc['status']}{NC}")
        else:
            _box_row(f"  {BOLD}Carrier compare ({cc.get('carrier', '?')}):{NC} {RED}{cc.get('status', 'ERROR')}{NC}")
        if "error" in cc:
            _box_row(f"    {RED}{cc['error']}{NC}")
        else:
            for name, status, msg in cc.get("checks", []):
                if status == "OK":
                    icon = "✅"
                    color = GREEN
                elif status == "WARN":
                    icon = "⚠️"
                    color = YELLOW
                else:
                    icon = "❌"
                    color = RED
                _box_row(f"    {icon} {color}{name}{NC}: {msg}")
        _box_sep()

    # Подсказки
    _box_row(f"  {DIM}Подсказки:{NC}")
    _box_row(f"    {DIM}• Лог: journalctl -u {AWGS_SYSTEMD_AWG_QUICK} -n 50{NC}")
    _box_row(f"    {DIM}• Конфиг: {AWGS_SERVER_CONF}{NC}")
    _box_row(f"    {DIM}• Awg show: {AWGS_BIN} show {AWGS_INTERFACE}{NC}")
    _box_bottom()
