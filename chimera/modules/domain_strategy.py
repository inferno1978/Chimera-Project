"""
chimera/modules/domain_strategy.py
───────────────────────────────────────────────────────────────────────────────
Смена domainStrategy на живом /etc/xray/config.json (меню «Настройки сети → 6»).

Зачем отдельный модуль: логика патча — чистая функция над dict, тестируется
без тяжёлого _core (конвенция репо: чистые хелперы в modules, _core — только
IO/меню-обвязка).

Кейс (стенд 2026-10-26): сервер установлен «в режиме IPv6» (шаг 8/11 →
UseIPv6v4), IPv6 на хостинге отвалился. Xray продолжает резолвить AAAA и
звонить по мёртвому v6 → сайты виснут/EOF у клиентов. Лечение без
переустановки: перевести исходящие на UseIPv4.

ЧТО ПРАВИТСЯ (apply_domain_strategy_to_config):
  • freedom-outbound'ы (direct / direct-local, кроме xray-stats-api):
    settings.domainStrategy = new_ds;
  • dns.queryStrategy = new_ds — именно это управляет A/AAAA-приоритетом
    встроенного DNS Xray: freedom c UseIPv6v4 при queryStrategy=UseIPv4
    получает только A-записи и звонит по IPv4 (сам freedom-флаг при этом
    безвреден);
  • при new_ds == "UseIPv4": из dns.servers вычищаются IPv6-адреса —
    мёртвый v6 превращает DNS-запросы в таймауты (v6-серверы стоят первыми
    с skipFallback=False). Если после фильтра не осталось ни одного
    primary (skipFallback=False) — первым становится лучший v4-сервер;
    если серверов не осталось совсем — подставляется v4-fallback как в
    генераторе xray_install (ветка IS_IPV6_AVAILABLE=False):
    1.1.1.1 / 8.8.8.8 / 9.9.9.9. Локальные резолверы (127.0.0.1 AGH,
    dnscrypt:5300) и DoH/DoT-URL не трогаются — двоеточий в адресе нет.

ЧТО НЕ ПРАВИТСЯ (осознанно, баг-фикс):
  • routing.domainStrategy — ДРУГАЯ настройка (AsIs / IPIfNonMatch /
    IPOnDemand): она регулирует резолв доменов ДЛЯ ПРАВИЛ маршрутизации,
    а не IPv4/IPv6-приоритет исходящих. Прежний код меню писал туда
    UseIPv4: Xray 26.x молча принимает неизвестное значение как AsIs
    (default-ветка парсера infra/conf/router.go; проверено на 26.10.21
    через `xray run -test` — конфиг «OK», но семантика тихо другая) →
    IPIfNonMatch деградирует до AsIs → ip/geoip-правила (geoip:ru,
    RIPE-префиксы РФ-direct) перестают матчить доменный трафик.

Точки входа из _core.py (do_change_domain_strategy):
    from chimera.modules.domain_strategy import (
        apply_domain_strategy_to_config,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import re
from typing import Any

# v4-fallback для dns.servers (зеркалит ветку IS_IPV6_AVAILABLE=False
# генераторов xray_install: первичный + запасной + skipFallback-хвост).
V4_DNS_FALLBACK: list[dict[str, Any]] = [
    {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": False},
    {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": False},
    {"address": "9.9.9.9", "port": 53, "network": "udp", "skipFallback": True},
]

# IPv6-литерал: только hex/двоеточия/точки/скобки И хотя бы одно двоеточие.
# Не матчит v4 («1.1.1.1»), домены («dns.google») и URL («https://…», «udp://…» —
# есть слэши/буквы вне hex).
_V6_LITERAL_RE = re.compile(r"^[\[\]:.0-9a-fA-F]+$")


def _is_v6_address(addr: Any) -> bool:
    """True, если адрес — IPv6-литерал (а не v4/домен/URL)."""
    if not isinstance(addr, str) or ":" not in addr:
        return False
    return bool(_V6_LITERAL_RE.match(addr))


def apply_domain_strategy_to_config(config: dict[str, Any],
                                    new_ds: str) -> list[str]:
    """
    Патчит config.json (в in-place) под новую domainStrategy.

    :param config: разобранный JSON конфига Xray (mutated)
    :param new_ds: UseIPv6v4 | UseIPv4v6 | UseIP | UseIPv4
    :return: список человекочитаемых изменений (для лога меню); пустой —
             конфиг уже соответствовал стратегии.
    """
    changes: list[str] = []

    # 1) freedom-outbound'ы (кроме служебного xray-stats-api)
    for ob in config.get("outbounds", []) or []:
        if not isinstance(ob, dict) or ob.get("protocol") != "freedom":
            continue
        if ob.get("tag") in ("xray-stats-api",):
            continue
        cur = (ob.get("settings") or {}).get("domainStrategy", "")
        if cur != new_ds:
            ob.setdefault("settings", {})["domainStrategy"] = new_ds
            changes.append(
                f"outbound «{ob.get('tag', '?')}»: domainStrategy "
                f"{cur or '(не задан)'} → {new_ds}")

    # 2) dns.queryStrategy (+ 3) v4-only: вычистить мёртвые IPv6-DNS)
    dns = config.get("dns")
    if isinstance(dns, dict):
        cur_q = dns.get("queryStrategy", "")
        if cur_q != new_ds:
            dns["queryStrategy"] = new_ds
            changes.append(
                f"dns.queryStrategy: {cur_q or '(не задан)'} → {new_ds}")

        if new_ds == "UseIPv4":
            servers = dns.get("servers")
            if isinstance(servers, list) and servers:
                kept: list[Any] = []
                for s in servers:
                    addr = s.get("address") if isinstance(s, dict) else s
                    if _is_v6_address(addr):
                        continue
                    kept.append(s)
                removed = len(servers) - len(kept)
                if not kept:
                    dns["servers"] = [dict(s) for s in V4_DNS_FALLBACK]
                    changes.append(
                        "dns.servers: все серверы были IPv6 — подставлен "
                        "v4-fallback (1.1.1.1 / 8.8.8.8 / 9.9.9.9)")
                elif removed:
                    # Хотя бы один primary (skipFallback=False) должен
                    # остаться — иначе весь список «fallback-only».
                    dict_kept = [s for s in kept if isinstance(s, dict)]
                    if dict_kept and all(s.get("skipFallback") for s in dict_kept):
                        first = dict_kept[0]
                        first["skipFallback"] = False
                    dns["servers"] = kept
                    changes.append(
                        f"dns.servers: удалено {removed} IPv6-сервер(ов), "
                        f"осталось {len(kept)}")

    return changes
