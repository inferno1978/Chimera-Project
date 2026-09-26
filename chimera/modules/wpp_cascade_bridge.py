#!/usr/bin/env python3
"""
chimera/modules/wpp_cascade_bridge.py
────────────────────────────────────────────────────────────────────────────────
Bridge: chimera's cascade nodes (state.json chain_nodes) → WPP nodes.json.

Определяет РЕАЛЬНОЕ местоположение нод через IP геолокацию (ip-api.com).
Кэширует результат в nodes.json чтобы не дёргать API на каждый рендер.

Вызывается перед рендерингом /nodes страницы.
"""
from __future__ import annotations

import json
import os
import re
import hashlib
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

STATE_FILE    = Path("/var/lib/xray-installer/state.json")
NODES_FILE    = Path("/var/lib/xray-installer/nodes.json")
LOCATION_FILE = Path("/var/lib/xray-installer/location.json")
GEO_CACHE_TTL = 7 * 86400  # 7 дней — IP не меняются часто

# WPP node country names (ISO 3166-1 alpha-2 → Russian name)
# Совпадает с wpp_nodes.py COUNTRY_NAMES для консистентности
COUNTRY_NAMES = {
    "FI": "Финляндия", "DE": "Германия", "NL": "Нидерланды", "FR": "Франция",
    "GB": "Великобритания", "US": "США", "CA": "Канада", "SE": "Швеция",
    "NO": "Норвегия", "DK": "Дания", "PL": "Польша", "CZ": "Чехия",
    "AT": "Австрия", "CH": "Швейцария", "ES": "Испания", "IT": "Италия",
    "RO": "Румыния", "BG": "Болгария", "TR": "Турция", "KZ": "Казахстан",
    "RU": "Россия", "UA": "Украина", "JP": "Япония", "SG": "Сингапур",
    "HK": "Гонконг", "AE": "ОАЭ", "LT": "Литва", "LV": "Латвия",
    "EE": "Эстония", "IS": "Исландия", "IE": "Ирландия", "BE": "Бельгия",
}


def _stable_id(host: str) -> str:
    """Deterministic node ID from hostname."""
    return hashlib.sha256(host.encode()).hexdigest()[:16]


def _resolve_ip(host: str) -> str:
    """Resolve hostname to IPv4 via system DNS."""
    try:
        results = socket.getaddrinfo(host, None, socket.AF_INET)
        for r in results:
            ip = r[4][0]
            if ip and not ip.startswith("127."):
                return ip
    except Exception:
        pass
    return ""


def _geolocate_ip(ip: str) -> dict:
    """
    Geolocate IP via ip-api.com (free, no API key, 45 req/min).
    Returns {country_code, country_name, city} or defaults.
    """
    try:
        url = f"http://ip-api.com/json/{ip}?fields=countryCode,country,city&lang=ru"
        req = urllib.request.Request(url, headers={"User-Agent": "chimera-cascade-bridge/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        cc = data.get("countryCode", "UN")
        country = data.get("country", "Не указано")
        city = data.get("city", "") or "—"
        # Use Russian country name from our map if available
        country = COUNTRY_NAMES.get(cc, country)
        return {"country_code": cc, "country_name": country, "city": city}
    except Exception:
        return {"country_code": "UN", "country_name": "Не указано", "city": "—"}


def _geolocate_host(host: str, cached: dict | None = None) -> dict:
    """
    Get geolocation for a hostname. Uses cache if fresh (< GEO_CACHE_TTL).
    Falls back to TLD detection if IP resolution or API fails.
    """
    now = int(time.time())
    # Check cache
    if cached and cached.get("geo_time") and now - cached.get("geo_time", 0) < GEO_CACHE_TTL:
        if cached.get("country_code"):
            return {
                "country_code":  cached["country_code"],
                "country_name":  cached.get("country_name", "Не указано"),
                "city":          cached.get("city", "—"),
            }
    
    # Resolve hostname to IP
    ip = _resolve_ip(host)
    if not ip:
        return {"country_code": "UN", "country_name": "Не указано", "city": host}
    
    # Geolocate IP
    geo = _geolocate_ip(ip)
    return geo


def cascade_to_wpp_nodes(chain_nodes: list[dict], existing_nodes: list[dict] | None = None) -> list[dict]:
    """
    Transform chimera chain_nodes → WPP node format with REAL geolocation.
    
    Args:
        chain_nodes: chimera's state.json chain_nodes list
        existing_nodes: previously cached nodes (for geo cache reuse)
    """
    # Build cache lookup from existing nodes
    cache_by_host = {}
    if existing_nodes:
        for n in existing_nodes:
            url = n.get("url", "")
            host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
            cache_by_host[host] = n
    
    out = []
    for n in chain_nodes:
        host = n.get("host", "")
        if not host:
            continue
        port = n.get("port", 443)
        proto = n.get("proto", "reality")
        
        # Get cached entry for this host (if exists)
        cached = cache_by_host.get(host, {})
        
        # Geolocate (uses cache if fresh)
        geo = _geolocate_host(host, cached)
        
        out.append({
            "id":            _stable_id(host),
            "url":           f"https://{host}",
            "country_code":  geo["country_code"],
            "country_name":  geo["country_name"],
            "name":          geo["city"],
            "enabled":       True,
            "version":       f"cascade-{proto}",
            "geo_time":      int(time.time()),  # cache timestamp
            "_cascade":      True,  # marker — federation calls skip these
        })
    return out


def refresh_nodes_file() -> int:
    """
    Read chimera's state.json chain_nodes, geolocate each node's IP,
    write to nodes.json in WPP format. Caches geolocation for GEO_CACHE_TTL.
    
    Returns number of nodes written.
    """
    try:
        if not STATE_FILE.exists():
            return 0
        state = json.loads(STATE_FILE.read_text())
        chain = state.get("chain_nodes", []) or []
        if not chain and state.get("chain_exit_host"):
            chain = [{
                "host": state.get("chain_exit_host", ""),
                "port": state.get("chain_exit_port", 443),
                "proto": state.get("protocol_mode", "reality"),
            }]
        
        # Load existing nodes for geo cache
        existing = []
        if NODES_FILE.exists():
            try:
                existing = json.loads(NODES_FILE.read_text())
                if not isinstance(existing, list):
                    existing = []
            except Exception:
                existing = []
        
        wpp_nodes = cascade_to_wpp_nodes(chain, existing)
        
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
    # Show what was written
    if NODES_FILE.exists():
        data = json.loads(NODES_FILE.read_text())
        for node in data:
            print(f"  {node.get('url','')} → {node.get('country_code','')} / {node.get('country_name','')} / {node.get('name','')}")
