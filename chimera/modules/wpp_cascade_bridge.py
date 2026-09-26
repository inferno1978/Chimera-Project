#!/usr/bin/env python3
"""
chimera/modules/wpp_cascade_bridge.py
────────────────────────────────────────────────────────────────────────────────
Bridge: chimera's cascade nodes (state.json chain_nodes) → WPP nodes.json.

Создаёт синтетические WPP-записи нод из chimera's cascade конфигурации,
чтобы они отображались на странице /nodes в WPP панели.

Архитектура:
  • chimera cascade — это Xray outbounds (VLESS+REALITY), не HTTP API серверы
  • WPP federation — это HTTP API (controller → agent через HTTPS)
  • Bridge создаёт display-only записи (без token) — federation-вызовы
    (sync/delete/purge) будут пропущены для cascade-нод

Вызывается перед рендерингом /nodes страницы.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

STATE_FILE  = Path("/var/lib/xray-installer/state.json")
NODES_FILE  = Path("/var/lib/xray-installer/nodes.json")
LOCATION_FILE = Path("/var/lib/xray-installer/location.json")

# TLD → country code mapping (same as in wpp_panel_web.py)
_TLD_COUNTRY = {
    "fi": ("FI", "Финляндия", "Хельсинки"),
    "de": ("DE", "Германия", "Франкфурт"),
    "nl": ("NL", "Нидерланды", "Амстердам"),
    "fr": ("FR", "Франция", "Париж"),
    "gb": ("GB", "Великобритания", "Лондон"),
    "uk": ("GB", "Великобритания", "Лондон"),
    "us": ("US", "США", "Нью-Йорк"),
    "ru": ("RU", "Россия", "Москва"),
    "ua": ("UA", "Украина", "Киев"),
    "pl": ("PL", "Польша", "Варшава"),
    "se": ("SE", "Швеция", "Стокгольм"),
    "no": ("NO", "Норвегия", "Осло"),
    "cz": ("CZ", "Чехия", "Прага"),
    "at": ("AT", "Австрия", "Вена"),
    "ch": ("CH", "Швейцария", "Цюрих"),
    "es": ("ES", "Испания", "Мадрид"),
    "it": ("IT", "Италия", "Милан"),
    "lt": ("LT", "Литва", "Вильнюс"),
    "lv": ("LV", "Латвия", "Рига"),
    "ee": ("EE", "Эстония", "Таллин"),
    "jp": ("JP", "Япония", "Токио"),
    "sg": ("SG", "Сингапур", "Сингапур"),
    "hk": ("HK", "Гонконг", "Гонконг"),
    "ae": ("AE", "ОАЭ", "Дубай"),
    "dk": ("DK", "Дания", "Копенгаген"),
    "is": ("IS", "Исландия", "Рейкьявик"),
    "ie": ("IE", "Ирландия", "Дублин"),
    "be": ("BE", "Бельгия", "Брюссель"),
    "ca": ("CA", "Канада", "Торонто"),
    "ro": ("RO", "Румыния", "Бухарест"),
    "bg": ("BG", "Болгария", "София"),
    "tr": ("TR", "Турция", "Стамбул"),
    "kz": ("KZ", "Казахстан", "Алматы"),
}


def _country_from_hostname(host: str) -> tuple[str, str, str]:
    """Detect country code/name/city from hostname TLD or subdomain."""
    if not host:
        return ("UN", "Не указано", "—")
    parts = host.split(".")
    # Try TLD first
    if len(parts) >= 2:
        tld = parts[-1].lower()
        if tld in _TLD_COUNTRY:
            return _TLD_COUNTRY[tld]
    # Try subdomain (first part)
    if len(parts) >= 2:
        sub = parts[0].lower()
        if sub in _TLD_COUNTRY:
            return _TLD_COUNTRY[sub]
    return ("UN", "Не указано", host)


def _stable_id(host: str) -> str:
    """Generate stable node ID from hostname (deterministic, not random)."""
    import hashlib
    return hashlib.sha256(host.encode()).hexdigest()[:16]


def cascade_to_wpp_nodes(chain_nodes: list[dict]) -> list[dict]:
    """Transform chimera chain_nodes → WPP node format."""
    out = []
    for n in chain_nodes:
        host = n.get("host", "")
        if not host:
            continue
        port = n.get("port", 443)
        cc, country, city = _country_from_hostname(host)
        proto = n.get("proto", "reality")
        out.append({
            "id":            _stable_id(host),
            "url":           f"https://{host}",
            "country_code":  cc,
            "country_name":  country,
            "name":          city,
            "enabled":       True,
            "version":       f"cascade-{proto}",
            "_cascade":      True,  # marker — federation calls skip these
        })
    return out


def refresh_nodes_file() -> int:
    """
    Read chimera's state.json chain_nodes and write to nodes.json in WPP format.
    Returns number of nodes written.
    """
    try:
        if not STATE_FILE.exists():
            return 0
        state = json.loads(STATE_FILE.read_text())
        chain = state.get("chain_nodes", []) or []
        if not chain and state.get("chain_exit_host"):
            # Legacy single-node format
            chain = [{
                "host": state.get("chain_exit_host", ""),
                "port": state.get("chain_exit_port", 443),
                "proto": state.get("protocol_mode", "reality"),
            }]
        wpp_nodes = cascade_to_wpp_nodes(chain)
        # Atomic write
        NODES_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = str(NODES_FILE) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(wpp_nodes, f, ensure_ascii=False, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, str(NODES_FILE))
        return len(wpp_nodes)
    except Exception as exc:
        print(f"[WPP-CASCADE-BRIDGE] refresh failed: {type(exc).__name__}: {exc}",
              file=sys.stderr, flush=True)
        return 0


if __name__ == "__main__":
    n = refresh_nodes_file()
    print(f"Refreshed {n} cascade nodes → {NODES_FILE}")
