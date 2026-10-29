"""
chimera/modules/cdn_ranges.py
───────────────────────────────────────────────────────────────────────────────
CDN/прокси-сети, которые авто-бан Химеры НЕ баним НИКОГДА.

ИНЦИДЕНТ (2026-10-29, живая нода): домен/подписки стоят за Cloudflare-прокси
(оранжевое облако). Сканеры бьют в CF-домен мусорным TLS → CF-edge сам
коннектится к origin → error.log Xray пишет источником EDGE-IP Cloudflare →
авто-бан (порог 10 ошибок/10 мин) банил edge-IP, CF ротирует пулы → 950
забаненных IP, все AS13335/AS14789 Cloudflare. Итог: self-DoS — легитимные
клиенты, маршрутизируемые через забаненные edge, получали refuse, а реальный
источник атаки (за CF) не банился вообще.

Правило: IP из CDN-диапазонов не баним и не считаем кандидатами; уже
поставленные баны снимаем автоматически (auto-heal, см. autoban.py).

Диапазоны — официальные опубликованные списки (cloudflare.com/ips),
зафиксировано 2026-10-29. CF меняет их редко (последнее расширение
131.0.72.0/22 — 2023-й); при обновлении списка правим здесь — тесты
tests/test_cdn_ranges.py держат константы и инцидентные IP.

Экспорт:
    CLOUDFLARE_V4 / CLOUDFLARE_V6   — списки CIDR (строки)
    CDN_NETWORKS                    — {провайдер: [CIDR]}
    cdn_cidrs_compact()             — плоский список всех CIDR
    cdn_network_objects()           — распарсенные ip_network (кеш)
    ip_in_cdn(ip)                   — IP принадлежит CDN-диапазону?
    cdn_provider_for(ip)            — имя провайдера ('cloudflare') или None

Точки использования:
    • chimera/modules/autoban.py — гард _fw_ban, skip в сканах
      (TUI _autoban_run_once + standalone cron-скрипт), auto-heal,
      пункт меню [C], статус «CDN-защита» в TUI.
"""
from __future__ import annotations

import ipaddress
from typing import Optional

# ── Официальные v4-диапазоны Cloudflare (cloudflare.com/ips-v4) ─────────────
CLOUDFLARE_V4: list[str] = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

# ── Официальные v6-диапазоны Cloudflare (cloudflare.com/ips-v6) ─────────────
CLOUDFLARE_V6: list[str] = [
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
]

# Реестр: имя провайдера → сети (v4+v6). Для отчётов/TG-сообщений и
# для встраивания в standalone cron-скрипт (autoban не может import'ить
# модуль из cron-окружения — список интерполируется в шаблон при установке).
CDN_NETWORKS: dict[str, list[str]] = {
    "cloudflare": CLOUDFLARE_V4 + CLOUDFLARE_V6,
}

# Кеш распарсенных сетей: (провайдер, ip_network) — парсим один раз,
# проверка вхождения — адресной арифметикой (быстро на 950 IP).
_NETS_CACHE: Optional[list[tuple[str, "ipaddress._BaseNetwork"]]] = None


def cdn_cidrs_compact() -> list[str]:
    """Плоский список всех CDN CIDR (для встраивания в cron-шаблон)."""
    out: list[str] = []
    for nets in CDN_NETWORKS.values():
        out.extend(nets)
    return out


def cdn_network_objects() -> list[tuple[str, "ipaddress._BaseNetwork"]]:
    """[(провайдер, ip_network), ...] — с ленивым кешем на первый вызов."""
    global _NETS_CACHE
    if _NETS_CACHE is None:
        cache: list[tuple[str, "ipaddress._BaseNetwork"]] = []
        for provider, nets in CDN_NETWORKS.items():
            for cidr in nets:
                try:
                    cache.append((provider, ipaddress.ip_network(cidr, strict=False)))
                except ValueError:
                    # Битый CIDR в константах не должен ронять автобан —
                    # молча пропускаем (тесты ловят такие на этапе CI).
                    continue
        _NETS_CACHE = cache
    return _NETS_CACHE


def ip_in_cdn(ip: str) -> bool:
    """True, если IP принадлежит одному из CDN-диапазонов.

    Некорректный IP → False (не исключаем — но и не падаем).
    """
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    for _provider, net in cdn_network_objects():
        # TypeError невозможен после ip_address(); try — на случай
        # нестандартных объектов сетей в кеше.
        try:
            if addr in net:
                return True
        except TypeError:
            continue
    return False


def cdn_provider_for(ip: str) -> Optional[str]:
    """Имя провайдера ('cloudflare') для IP из CDN-диапазона, иначе None."""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return None
    for provider, net in cdn_network_objects():
        try:
            if addr in net:
                return provider
        except TypeError:
            continue
    return None


def cdn_providers_label() -> str:
    """Человекочитаемый список провайдеров для TUI/логов ('Cloudflare')."""
    names = {
        "cloudflare": "Cloudflare",
    }
    return ", ".join(names.get(p, p) for p in CDN_NETWORKS)
