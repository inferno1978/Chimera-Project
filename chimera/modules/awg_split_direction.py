"""
chimera/modules/awg_split_direction.py
───────────────────────────────────────────────────────────────────────────────
Split-direction: пара однонаправленных туннелей entry↔exit («честный»
вариант для сред, где двунаправленный туннель живёт только в одну
сторону).

Кейс «Виталий»: AWG 3.1 между двумя своими VPS при блокировке 16k —
«работоспособности туннеля добился только в одну сторону (отправить
можем, а принять нет); на выходе собралась конфигурация, где поднимается
2 туннеля — один отправляет, другой принимает». Модуль оформляет эту
схему ШТАТНО, без ручного извращения — и добавляет то, чего ручной
схеме не хватало: раздельный health-check каждого направления, e2e-
верификацию ДО переключения трафика и авто-откат на штатный туннель.

Схема (транзит клиентов каскада):

    Клиент ──► awg0 (entry, RU)
                 │  не-RU транзит: mangle PREROUTING -i awg0
                 │  MARK 0x8402 → table 2402
                 ▼
           awg-split-out ──(исходящее: запросы)──► exit: awg-split-out
                 (туннель 1, endpoint exit:52840)     │ FORWARD → WAN, MASQ
                                                      │ connmark 0x8403
                  ответные пакеты из WAN ─────────────┘
                 ▲                                        mangle: connmark
                 │                                        → MARK 0x8403
                 │                                        → table 2403
           awg-split-in ◄──(входящее: ответы)──── exit: awg-split-in
                 (туннель 2, endpoint exit:52841)  (AllowedIPs пира
                 │                                  содержит адрес entry
                 │  FORWARD → awg0 (de-SNAT по      НА OUT-ПОДСЕТИ —
                 │  conntrack: асимметрия легальна) (dst-роутинг WG)
                 ▼
              Клиент

Оба туннеля — штатные AWG-интерфейсы (awg-quick@awg-split-out /
@awg-split-in на entry; на exit — серверные awg-split-out/in.conf со
своими ListenPort). Физически каждый туннель дуплексен (handshake +
keepalive ходят в оба), но ТРАНЗИТ ходит по одному направлению через
каждый — это и есть «один отправляет, другой принимает». Асимметрия
легальна на IP-уровне: TCP не требует симметричного пути, seq/ack
корректны; SNAT/de-SNAT срабатывают по conntrack, который не привязан
к интерфейсу (nf_conntrack strict mode выключен по умолчанию).

Ключевые инварианты:
  • Штатный awg1 НЕ трогается: продолжает жить как горячий fallback
    (failover-таймер каскада продолжает его охранять). Откат на штатный
    режим — мгновенный (смена mark-правила).
  • Обфускация (Jc/Jmin/Jmax/S1-S4/H1-H4/I1-I5 + 3.1-директивы)
    синхронна на всех четырёх концах — из бокса exit (тот же класс
    бага, что E2E 2026-10-03 в awg_cascade: свои случайные пресеты =
    мёртвый handshake).
  • fwmark/таблицы 0x8402/0x8403 → 2402/2403 не пересекаются с
    каскадом (0x8200 → 2000) и слотами LB (0x8201..0x8210 → 2001..2016).
  • RU-исключение и b4-сплит-исключение зеркалят актуальную форму
    каскадного mark-правила (включая режим exit-all).
  • Health-check по направлениям раздельный: handshake + transfer
    каждого туннеля; e2e-зонд (ping -m 0x8402 через ОБА плеча) — с
    кулдауном. Смерть обоих плеч N тиков подряд → авто-откат на штатный
    awg1 + TG-уведомление.

Уведомления (tg_notify_event, канон каскадных событий):
  awg_split_on        — режим включён (оба плеча верифицированы)
  awg_split_dir_dead  — умерло одно из направлений (рестарт-лестница)
  awg_split_off       — авто-откат на штатный туннель (оба плеча мертвы)
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .awg_constants import (
    AWGS_SPLIT_OUT_IFACE, AWGS_SPLIT_IN_IFACE,
    AWGS_SPLIT_OUT_CONF, AWGS_SPLIT_IN_CONF,
    AWGS_SPLIT_OUT_SUBNET, AWGS_SPLIT_IN_SUBNET,
    AWGS_SPLIT_PORT_OUT, AWGS_SPLIT_PORT_IN,
    AWGS_SPLIT_FWMARK_OUT, AWGS_SPLIT_FWMARK_IN,
    AWGS_SPLIT_TABLE_OUT, AWGS_SPLIT_TABLE_IN,
    AWGS_SPLIT_STATE_KEY,
    AWGS_SPLIT_STALE_SEC, AWGS_SPLIT_PROBE_SEC,
    AWGS_SPLIT_E2E_INTERVAL_SEC, AWGS_SPLIT_FAIL_LIMIT,
    AWGS_PROBE_PING_SIZE, AWGS_PROBE_HOST,
    AWGS_SPLIT_SCRIPT, AWGS_SPLIT_SVC, AWGS_SPLIT_TIMER,
    AWGS_SPLIT_ENTRY_SCRIPT, AWGS_SPLIT_ENTRY_SVC,
    AWGS_SPLIT_EXIT_SCRIPT, AWGS_SPLIT_EXIT_SVC,
    AWGS_CASCADE_FWMARK, AWGS_DEFAULT_MTU,
)
from .awg_state import awgs_state_load, awgs_state_save

from .awg_link_probe import (
    link_parse_awg_show, link_parse_ping_loss,
)


def _core_module():
    import importlib
    return importlib.import_module("chimera._core")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _time_sleep(sec: float) -> None:
    """Обёртка для тестируемости (мокается в юнит-тестах — лестница
    health-тика не должна реально спать секунды в тестах)."""
    time.sleep(sec)


def _notify(event: str, detail: str) -> None:
    """Best-effort TG-уведомление (не бросает исключений — канон каскада)."""
    try:
        from .tg_bot import tg_notify_event
        tg_notify_event(event, detail)
    except Exception:
        pass


# ============================================================================
#  STATE
# ============================================================================

def split_state_get(state: Optional[dict] = None) -> dict:
    """Бокс split-режима из state (пустой dict = режим не настроен)."""
    if state is None:
        state = awgs_state_load()
    box = state.get(AWGS_SPLIT_STATE_KEY) or {}
    return box if isinstance(box, dict) else {}


def split_is_on(state: Optional[dict] = None) -> bool:
    """Режим включён (активная маршрутизация транзита через плечи)."""
    return bool(split_state_get(state).get("enabled"))


def _split_state_update(mutate) -> bool:
    """Read-modify-write с честным результатом сохранения (канон
    register_exit FIX 09.11: молчаливая потеря = враньё success)."""
    state = awgs_state_load()
    box = split_state_get(state)
    mutate(box)
    state[AWGS_SPLIT_STATE_KEY] = box
    return awgs_state_save(state)


# ============================================================================
#  КОНФИГИ (чистые генераторы — тестируются без сервера)
# ============================================================================

def _obfuscation_lines(params: dict, protocol_version: str) -> list:
    """Строки Jc..H4/I1-I5 (+3.1-директивы) — СИНХРОННЫ на всех концах
    (правило: непустые как есть, пустые комментируются — канон
    _awgs_cascade_build_awg1_conf)."""
    from .awg_protocol import awg_is_31, awg_render_31_lines
    p = params or {}
    lines = [
        f"Jc = {p.get('jc', 4)}",
        f"Jmin = {p.get('jmin', 40)}",
        f"Jmax = {p.get('jmax', 70)}",
        f"S1 = {p.get('s1', 0)}",
        f"S2 = {p.get('s2', 0)}",
        f"S3 = {p.get('s3', 0)}",
        f"S4 = {p.get('s4', 0)}",
        f"H1 = {p.get('h1', 1)}",
        f"H2 = {p.get('h2', 2)}",
        f"H3 = {p.get('h3', 3)}",
        f"H4 = {p.get('h4', 4)}",
    ]
    for key in ("i1", "i2", "i3", "i4", "i5"):
        val = p.get(key, "")
        lines.append(f"{key.upper()} = {val}" if val else f"# {key.upper()} = ")
    if awg_is_31(protocol_version):
        lines.append(awg_render_31_lines(p))
    return lines


def split_build_client_conf(direction: str,
                            endpoint: str,
                            port: int,
                            server_pubkey: str,
                            client_privkey: str,
                            client_addr: str,
                            params: dict,
                            protocol_version: str = "2.0",
                            psk: str = "",
                            mtu: int = AWGS_DEFAULT_MTU) -> str:
    """Конфиг клиентского плеча на entry (awg-split-out/in.conf).

    По канону _awgs_cascade_build_awg1_conf: Address /32, Table=off
    (маршрутизация — fwmark+policy routing, авто-маршрут 0.0.0.0/0 от
    awg-quick недопустим: уведёт весь трафик сервера), AllowedIPs
    0.0.0.0/0 (клиентский пир: любой src принимаем из туннеля — для
    in-плеча это реальные сайты; dst-роутинг в туннель ведёт fwmark).
    """
    lines = [
        "[Interface]",
        f"PrivateKey = {client_privkey}",
        f"Address = {client_addr}/32",
        f"MTU = {mtu}",
        "Table = off",
    ]
    lines += _obfuscation_lines(params, protocol_version)
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {server_pubkey}",
        f"Endpoint = {endpoint}:{port}",
        "AllowedIPs = 0.0.0.0/0",
        "PersistentKeepalive = 25",
    ]
    if psk:
        lines.append(f"PresharedKey = {psk}")
    return "\n".join(lines) + "\n"


def split_build_server_conf(direction: str,
                            server_privkey: str,
                            port: int,
                            server_addr: str,
                            entry_pubkey: str,
                            allowed_ips: str,
                            params: dict,
                            protocol_version: str = "2.0",
                            mtu: int = AWGS_DEFAULT_MTU) -> str:
    """Конфиг серверного плеча на exit (awg-split-out/in.conf).

    Серверная сторона: Address <base>.1/<prefix> (НЕ /32 — ядро должно
    повесить on-link маршрут подсети, канон awgs_build_server_conf),
    ListenPort свой на каждое плечо.

    КЛЮЧЕВАЯ деталь — AllowedIPs пира:
      • out-плечо (приём транзита от entry): адрес entry на out-подсети;
      • in-плечо (отправка транзита к entry): ДОЛЖЕН включать адрес
        entry на OUT-подсети — WG выбирает пира по dst пакета, а ответы
        транзита несут dst=<entry-out-addr> (de-MASQ на exit возвращает
        исходный dst). Без out-адреса в AllowedIPs пира in-плеча
        маршрутизатор exit просто не найдёт туннель для возврата.
    """
    lines = [
        "[Interface]",
        f"PrivateKey = {server_privkey}",
        f"Address = {server_addr}",
        f"ListenPort = {port}",
        f"MTU = {mtu}",
    ]
    lines += _obfuscation_lines(params, protocol_version)
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {entry_pubkey}",
        f"AllowedIPs = {allowed_ips}",
    ]
    return "\n".join(lines) + "\n"


def split_out_server_allowed_ips() -> str:
    """AllowedIPs пира out-плеча на exit (приём транзита от entry)."""
    return "172.16.62.2/32"


def split_in_server_allowed_ips() -> str:
    """AllowedIPs пира in-плеча на exit (отправка транзита к entry):
    out-адрес entry (dst ответов после de-MASQ) + служебная in-подсеть."""
    return "172.16.62.2/32, 172.16.63.2/32"


def split_build_exit_routing_script(out_iface: str = AWGS_SPLIT_OUT_IFACE,
                                    in_iface: str = AWGS_SPLIT_IN_IFACE,
                                    fwmark_in: int = AWGS_SPLIT_FWMARK_IN,
                                    table_in: int = AWGS_SPLIT_TABLE_IN) -> str:
    """Bash-скрипт маршрутизации exit-стороны (идемпотентный, канон
    awg-routing.sh: -C || -A, while-del для чужих форм, переживает ребут).

    Логика: транзит из out-плеча → WAN (FORWARD + MASQ); ответы из WAN
    → in-плечо. Возврат в in-плечо — по connmark: весь флоу, пришедший
    из out-интерфейса, помечаем ct=0x8403; для пакетов этого флоу,
    приходящих из WAN (PREROUTING до route decision), восстанавливаем
    метку в fwmark → table 2403 → default dev awg-split-in.
    """
    return f"""#!/bin/bash
# AWG split-direction EXIT routing — возврат транзита через in-плечо.
# Автоматически сгенерировано chimera/modules/awg_split_direction.py
# Идемпотентно: безопасен при многократном запуске (-C || -A, replace).

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# 1. FORWARD: транзит out-плечо → WAN, ответы WAN → in-плечо
iptables -C FORWARD -i {out_iface} -j ACCEPT 2>/dev/null || \\
    iptables -A FORWARD -i {out_iface} -j ACCEPT
iptables -C FORWARD -i {in_iface} -j ACCEPT 2>/dev/null || \\
    iptables -A FORWARD -i {in_iface} -j ACCEPT
iptables -C FORWARD -o {out_iface} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \\
    iptables -A FORWARD -o {out_iface} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -C FORWARD -o {in_iface} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \\
    iptables -A FORWARD -o {in_iface} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 2. NAT: транзит out-плеча уходит в WAN с адресом exit
iptables -t nat -C POSTROUTING -o {out_iface} -j MASQUERADE 2>/dev/null || \\
    iptables -t nat -A POSTROUTING -o {out_iface} -j MASQUERADE

# 3. Connmark: флоу, вошедший из out-плеча, возвращается через in-плечо.
#    save при входе (первый пакет флоу), restore для последующих
#    пакетов из WAN — МАРКА ДО route decision.
iptables -t mangle -C PREROUTING -i {out_iface} -m conntrack --ctstate NEW -j CONNMARK --set-mark {fwmark_in} 2>/dev/null || \\
    iptables -t mangle -A PREROUTING -i {out_iface} -m conntrack --ctstate NEW -j CONNMARK --set-mark {fwmark_in}
iptables -t mangle -C PREROUTING -i {in_iface} -j CONNMARK --save-mark 2>/dev/null || \\
    iptables -t mangle -A PREROUTING -i {in_iface} -j CONNMARK --save-mark
iptables -t mangle -C PREROUTING -m connmark --mark {fwmark_in} -j CONNMARK --restore-mark 2>/dev/null || \\
    iptables -t mangle -A PREROUTING -m connmark --mark {fwmark_in} -j CONNMARK --restore-mark

# 4. Policy routing: помеченные ответы → in-плечо
ip route replace default dev {in_iface} table {table_in}
while ip rule del fwmark {fwmark_in} lookup {table_in} 2>/dev/null; do :; done
ip rule add fwmark {fwmark_in} lookup {table_in}

# 5. TCPMSS clamp (двойное туннелирование: транзит MTU 1280 внутри AWG)
iptables -t mangle -C FORWARD -i {out_iface} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240 2>/dev/null || \\
    iptables -t mangle -A FORWARD -i {out_iface} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
iptables -t mangle -C FORWARD -o {in_iface} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240 2>/dev/null || \\
    iptables -t mangle -A FORWARD -o {in_iface} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240

echo "AWG split-direction exit routing started"
"""


def split_build_entry_routing_script(ru_excl: str = "",
                                     b4_excl: str = "",
                                     out_iface: str = AWGS_SPLIT_OUT_IFACE,
                                     in_iface: str = AWGS_SPLIT_IN_IFACE,
                                     fwmark_out: int = AWGS_SPLIT_FWMARK_OUT,
                                     table_out: int = AWGS_SPLIT_TABLE_OUT,
                                     out_gw: str = "172.16.62.1",
                                     out_net: str = "172.16.62.0/24") -> str:
    """Bash-скрипт маршрутизации entry-стороны (ставится ПОСЛЕ каскадного
    awg-routing.sh, живёт отдельным юнитом — каскадный скрипт не патчим).

    Логика: клиентский не-RU транзит (форма RU/b4-исключений — ЗЕРКАЛО
    актуальной формы каскада, включая exit-all) уходит в out-плечо;
    ответы приезжают из in-плеча и форвардятся клиентам (de-SNAT по
    conntrack). Каскадная марка 0x8200 снимается — иначе две MARK-цепи
    конкурируют (последняя в цепочке затирает fwmark — класс бага
    легаси-марки, см. _awgs_cascade_apply_iptables).
    """
    return f"""#!/bin/bash
# AWG split-direction ENTRY routing — исходящий транзит через out-плечо.
# Автоматически сгенерировано chimera/modules/awg_split_direction.py
# Идемпотентно: безопасен при многократном запуске.

# 1. Каскадную марку транзита — снять (split берёт транзит на себя;
#    штатный awg1 остаётся горячим fallback-путём)
while iptables -t mangle -D PREROUTING -i awg0{ru_excl}{b4_excl} -j MARK --set-mark {AWGS_CASCADE_FWMARK} 2>/dev/null; do :; done
while iptables -t mangle -D PREROUTING -i awg0 -j MARK --set-mark {AWGS_CASCADE_FWMARK} 2>/dev/null; do :; done

# 2. Split-марка: клиентский не-RU транзит → out-плечо (PREROUTING —
#    ДО route decision, канон каскада; формы RU/b4 — зеркало каскада)
iptables -t mangle -C PREROUTING -i awg0{ru_excl}{b4_excl} -j MARK --set-mark {fwmark_out} 2>/dev/null || \\
    iptables -t mangle -A PREROUTING -i awg0{ru_excl}{b4_excl} -j MARK --set-mark {fwmark_out}

# 3. NAT: транзит уходит в out-плечо с адресом entry на out-подсети
iptables -t nat -C POSTROUTING -o {out_iface} -j MASQUERADE 2>/dev/null || \\
    iptables -t nat -A POSTROUTING -o {out_iface} -j MASQUERADE

# 4. FORWARD: клиенты → out-плечо; in-плечо → клиенты
iptables -C FORWARD -i awg0 -o {out_iface} -j ACCEPT 2>/dev/null || \\
    iptables -A FORWARD -i awg0 -o {out_iface} -j ACCEPT
iptables -C FORWARD -i {in_iface} -o awg0 -j ACCEPT 2>/dev/null || \\
    iptables -A FORWARD -i {in_iface} -o awg0 -j ACCEPT

# 5. Policy routing: on-link подсеть out перед default (канон: gateway
#    обязан быть on-link, иначе "Nexthop has invalid gateway")
ip route replace {out_net} dev {out_iface} table {table_out}
ip route replace default via {out_gw} dev {out_iface} table {table_out}
while ip rule del fwmark {fwmark_out} lookup {table_out} 2>/dev/null; do :; done
ip rule add fwmark {fwmark_out} lookup {table_out}

# 6. TCPMSS clamp (1240 = MTU 1280 − 40, канон каскада)
iptables -t mangle -C FORWARD -i awg0 -o {out_iface} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240 2>/dev/null || \\
    iptables -t mangle -A FORWARD -i awg0 -o {out_iface} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
iptables -t mangle -C FORWARD -i {in_iface} -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240 2>/dev/null || \\
    iptables -t mangle -A FORWARD -i {in_iface} -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240

echo "AWG split-direction entry routing started"
"""


# ============================================================================
#  ВАЛИДАЦИЯ БОКСА (канон awgs_cascade_register_exit)
# ============================================================================

def split_box_validate(box: dict) -> tuple:
    """Валидация бокса данных с exit → (ok, причина).

    Проверки: endpoint/port/pubkey/privkey непусты; порты различны;
    подсети плеч не пересекаются с подсетью awg0 И каскадным линком;
    версия протокола совпадает с локальной (3.1-директивы синхронны на
    всех концах — расхождение = мёртвый handshake, канон setup_awg0);
    обфускация передана (иначе handshake не сойдётся — E2E 2026-10-03).
    """
    from .awg_protocol import awg_normalize_version, awg_protocol_label

    if not (box.get("endpoint") or "").strip():
        return False, "Endpoint host exit обязателен"
    for key in ("port_out", "port_in"):
        try:
            p = int(box.get(key) or 0)
        except (TypeError, ValueError):
            p = 0
        if not (1 <= p <= 65535):
            return False, f"Порт {key} вне диапазона 1-65535"
    if int(box.get("port_out") or 0) == int(box.get("port_in") or 0):
        return False, "Порты плеч обязаны различаться (ListenPort на exit)"
    for key in ("server_pubkey_out", "server_pubkey_in",
                "peer_privkey_out", "peer_privkey_in"):
        if not (box.get(key) or "").strip():
            return False, f"Поле {key} обязательно (бокс с exit)"

    protocol_version = awg_normalize_version(box.get("protocol_version"))
    state = awgs_state_load()
    _own_pv = awg_normalize_version(state.get("protocol_version", "2.0"))
    if _own_pv != protocol_version:
        return False, (f"Версии протокола не совпадают: этот сервер — "
                       f"{awg_protocol_label(_own_pv)}, exit — "
                       f"{awg_protocol_label(protocol_version)}")

    # Подсети плеч против локальных подсетей (анти-«маршрутная каша»)
    _own_subnet = (state.get("subnet") or "").strip()
    _cascade_subnet = (state.get("cascade_subnet") or "").strip()
    for label, sub in (("out", AWGS_SPLIT_OUT_SUBNET),
                       ("in", AWGS_SPLIT_IN_SUBNET)):
        if _own_subnet and _own_subnet == sub:
            return False, f"Подсеть {label}-плеча ({sub}) совпадает с awg0"
        if _cascade_subnet and _cascade_subnet == sub:
            return False, (f"Подсеть {label}-плеча ({sub}) совпадает с "
                           f"подсетью каскадного линка")

    if not box.get("params"):
        return False, ("Обфускация не передана — handshake не сойдётся "
                       "(обфускация обязана совпадать на всех концах)")
    return True, ""


# ============================================================================
#  EXIT-СТОРОНА (меню НА exit-ноде: два серверных плеча + бокс данных)
# ============================================================================

def split_setup_exit(protocol_version: str = "2.0",
                     port_out: int = AWGS_SPLIT_PORT_OUT,
                     port_in: int = AWGS_SPLIT_PORT_IN) -> bool:
    """Настраивает exit-сторону split-direction (запускать НА exit).

    Что делает:
      1. Ключи: серверные пары на оба плеча + клиентские пары entry;
      2. Конфиги /etc/amnezia/amneziawg/awg-split-{out,in}.conf —
         серверные, с одним пиром (entry) и синхронной обфускацией;
      3. systemd awg-quick@awg-split-{out,in} + routing-юнит
         awg-split-exit-routing (connmark → in-плечо);
      4. Печатает БОКС данных для entry (канон setup_awg1).

    Обфускация: из state ЭТОГО exit (если standalone AWG установлен) —
    обфускация уже синхронна с каскадом awg0 exit; иначе дефолтная.
    """
    core = _core_module()
    info, warn, success = core.info, core.warn, core.success
    from .awg_protocol import awg_normalize_version, awg_protocol_label
    from .awg_standalone import awgs_generate_keys

    protocol_version = awg_normalize_version(protocol_version)
    state = awgs_state_load()
    params = state.get("params") or {}

    try:
        port_out = int(port_out)
        port_in = int(port_in)
    except (TypeError, ValueError):
        warn("Порты плеч обязаны быть числами")
        return False
    if port_out == port_in:
        warn("Порты плеч обязаны различаться")
        return False

    info("Генерация ключей split-плеч (2 серверные + 2 клиентские пары)...")
    srv_out_priv, srv_out_pub = awgs_generate_keys()
    srv_in_priv, srv_in_pub = awgs_generate_keys()
    ent_out_priv, ent_out_pub = awgs_generate_keys()
    ent_in_priv, ent_in_pub = awgs_generate_keys()
    if not all((srv_out_priv, srv_in_priv, ent_out_priv, ent_in_priv)):
        warn("Не удалось сгенерировать ключи")
        return False

    info("Генерация конфигов серверных плеч...")
    out_conf = split_build_server_conf(
        "out", srv_out_priv, port_out, f"{AWGS_SPLIT_OUT_SUBNET.split('/')[0].rsplit('.', 1)[0]}.1/24",
        ent_out_pub, split_out_server_allowed_ips(),
        params, protocol_version)
    in_conf = split_build_server_conf(
        "in", srv_in_priv, port_in, f"{AWGS_SPLIT_IN_SUBNET.split('/')[0].rsplit('.', 1)[0]}.1/24",
        ent_in_pub, split_in_server_allowed_ips(),
        params, protocol_version)
    AWGS_SPLIT_OUT_CONF.parent.mkdir(parents=True, exist_ok=True)
    AWGS_SPLIT_OUT_CONF.write_text(out_conf)
    AWGS_SPLIT_OUT_CONF.chmod(0o600)
    AWGS_SPLIT_IN_CONF.write_text(in_conf)
    AWGS_SPLIT_IN_CONF.chmod(0o600)

    # Запуск туннелей (restart — канон: повторная настройка = no-op у start)
    for iface in (AWGS_SPLIT_OUT_IFACE, AWGS_SPLIT_IN_IFACE):
        core._run(["systemctl", "enable", f"awg-quick@{iface}"],
                  check=False, quiet=True)
        r = core._run(["systemctl", "restart", f"awg-quick@{iface}"],
                      capture=True, check=False)
        if r.returncode != 0:
            warn(f"{iface} не запустился: {r.stderr}")
            return False

    # Routing-скрипт + юнит (connmark → in-плечо)
    info("Установка exit-маршрутизации (возврат через in-плечо)...")
    AWGS_SPLIT_EXIT_SCRIPT.parent.mkdir(parents=True, exist_ok=True)
    AWGS_SPLIT_EXIT_SCRIPT.write_text(split_build_exit_routing_script())
    AWGS_SPLIT_EXIT_SCRIPT.chmod(0o755)
    AWGS_SPLIT_EXIT_SVC.write_text(
        "[Unit]\n"
        "Description=AWG split-direction exit routing (return via in)\n"
        f"After=awg-quick@{AWGS_SPLIT_OUT_IFACE}.service awg-quick@{AWGS_SPLIT_IN_IFACE}.service\n"
        f"Wants=awg-quick@{AWGS_SPLIT_OUT_IFACE}.service awg-quick@{AWGS_SPLIT_IN_IFACE}.service\n"
        f"PartOf=awg-quick@{AWGS_SPLIT_OUT_IFACE}.service awg-quick@{AWGS_SPLIT_IN_IFACE}.service\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={AWGS_SPLIT_EXIT_SCRIPT}\n"
        "RemainAfterExit=yes\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n")
    core._run(["systemctl", "daemon-reload"], check=False, quiet=True)
    core._run(["systemctl", "enable", "awg-split-exit-routing"],
              check=False, quiet=True)
    r = core._run(["systemctl", "restart", "awg-split-exit-routing"],
                  capture=True, check=False)
    if r.returncode != 0:
        warn(f"awg-split-exit-routing не запустился: {r.stderr}")

    try:
        endpoint = state.get("endpoint") or core.get_server_ip("4")
    except Exception:
        endpoint = state.get("endpoint", "?")

    print()
    success("Split-плечи exit настроены!")
    print()
    core._box_top("Данные для настройки split-direction на ENTRY")
    core._box_row()
    core._box_row(f"  {core.GREEN}Endpoint host:{core.NC}       {endpoint}")
    core._box_row(f"  {core.GREEN}Port OUT (исходящее):{core.NC} {port_out}")
    core._box_row(f"  {core.GREEN}Port IN (входящее):{core.NC}  {port_in}")
    core._box_row(f"  {core.GREEN}Server pubkey OUT:{core.NC}   {srv_out_pub}")
    core._box_row(f"  {core.GREEN}Server pubkey IN:{core.NC}    {srv_in_pub}")
    core._box_row(f"  {core.GREEN}Entry privkey OUT:{core.NC}")
    core._box_row(f"  {ent_out_priv}")
    core._box_row(f"  {core.GREEN}Entry privkey IN:{core.NC}")
    core._box_row(f"  {ent_in_priv}")
    core._box_row(f"  {core.GREEN}Protocol version:{core.NC}    {awg_protocol_label(protocol_version)}")
    core._box_row(f"  {core.GREEN}Obfuscation (JSON):{core.NC}")
    core._box_row(f"  {json.dumps(params, ensure_ascii=False)}")
    core._box_bottom()
    print()
    info("Передайте бокс на entry: меню split-direction → «Включить».")
    return True


# ============================================================================
#  ENTRY-СТОРОНА (включение/выключение режима)
# ============================================================================

def _split_ru_excl(state: Optional[dict] = None) -> str:
    """RU-исключение split-правила — ЗЕРКАЛО каскадного (включая
    exit-all: снимается каскадной awgs_cascade_exit_all)."""
    try:
        from .awg_cascade import awgs_cascade_exit_all, _awgs_cascade_ru_excl
        return _awgs_cascade_ru_excl(state)
    except Exception:
        return ""


def _split_b4_excl() -> str:
    """B4-сплит-исключение — зеркало каскадного (домены сплита идут
    через b4 даже в split-режиме; «split не ломает b4-сплит»)."""
    try:
        from .awg_cascade import _awgs_cascade_b4_split_excl
        return _awgs_cascade_b4_split_excl()
    except Exception:
        return ""


def split_iface_probe(iface: str) -> dict:
    """Показания одного плеча: handshake age + transfer (чистый парсер
    awg_link_probe, живой вызов)."""
    core = _core_module()
    r = core._run(["awg", "show", iface], capture=True, check=False)
    if r.returncode != 0:
        return {"up": False, "handshake_age": None, "tx": 0, "rx": 0}
    data = link_parse_awg_show(r.stdout or "")
    data["up"] = True
    return data


def split_handshake_alive(probe: dict, stale_sec: int = AWGS_SPLIT_STALE_SEC) -> bool:
    """Плечо живо по handshake (age не старше stale_sec)."""
    age = probe.get("handshake_age")
    return age is not None and age <= stale_sec


def split_e2e_probe(probe_host: str = "", count: int = 16) -> dict:
    """E2E-зонд: ping -m 0x8402 через ОБА плеча (запрос уходит в
    out-плечо по split-марке, ответ обязан вернуться через in-плечо —
    иначе ответ потерян: это ровно семантика «оба направления живы»).

    Возвращает {ok, loss_pct|None, supported} (канон link_probe_ping_big).
    """
    core = _core_module()
    host = probe_host or AWGS_PROBE_HOST
    r = core._run(
        ["ping", "-n", "-m", str(AWGS_SPLIT_FWMARK_OUT), "-s",
         str(AWGS_PROBE_PING_SIZE),
         "-c", str(count), "-W", "2", host],
        capture=True, check=False)
    if r.returncode not in (0, 1) or "usage" in (r.stderr or "").lower():
        return {"ok": False, "loss_pct": None, "supported": False}
    loss = link_parse_ping_loss((r.stdout or "") + (r.stderr or ""))
    return {"ok": r.returncode == 0 and loss is not None and loss <= 25,
            "loss_pct": loss, "supported": True}


def split_setup_entry(box: dict, probe_host: str = "",
                      verify: bool = True) -> bool:
    """Включает split-direction на entry (бокс данных с exit).

    Лестница (безопасность: транзит переключается ТОЛЬКО после
    верификации обоих плеч):
      1. Валидация бокса (split_box_validate);
      2. Конфиги awg-split-out/in.conf + подъём туннелей;
      3. Ожидание handshake обоих плеч (probe_timeout);
      4. E2E-верификация: ping через оба плеча (mark 0x8402) — провал =
         ОТКАТ: туннели стоп, транзит не переключался, штатный awg1
         продолжает нести трафик (пользователи ничего не заметили);
      5. Переключение транзита: mark-правило 0x8200→0x8402 (entry-скрипт
         + юнит), state.enabled=True, TG-увед «режим включён».
    """
    core = _core_module()
    info, warn, success = core.info, core.warn, core.success

    state = awgs_state_load()
    if state.get("cascade_role") != "entry":
        warn("Split-direction включается на entry-ноде каскада "
             "(этот сервер принимает клиентов)")
        return False
    if not state.get("cascade_peer_host") and not state.get("cascade_exits"):
        warn("Каскад не настроен (нет exit) — сначала штатный каскад, "
             "потом split-direction (штатный awg1 — fallback-путь)")
        return False

    ok, reason = split_box_validate(box)
    if not ok:
        warn(f"Бокс данных невалиден: {reason}")
        return False

    from .awg_protocol import awg_normalize_version
    protocol_version = awg_normalize_version(box.get("protocol_version"))
    endpoint = box.get("endpoint", "")
    params = box.get("params") or {}

    # 1. Конфиги плеч
    info("Генерация конфигов плеч (awg-split-out / awg-split-in)...")
    out_conf = split_build_client_conf(
        "out", endpoint, int(box["port_out"]), box["server_pubkey_out"],
        box["peer_privkey_out"], "172.16.62.2", params, protocol_version)
    in_conf = split_build_client_conf(
        "in", endpoint, int(box["port_in"]), box["server_pubkey_in"],
        box["peer_privkey_in"], "172.16.63.2", params, protocol_version)
    AWGS_SPLIT_OUT_CONF.parent.mkdir(parents=True, exist_ok=True)
    AWGS_SPLIT_OUT_CONF.write_text(out_conf)
    AWGS_SPLIT_OUT_CONF.chmod(0o600)
    AWGS_SPLIT_IN_CONF.write_text(in_conf)
    AWGS_SPLIT_IN_CONF.chmod(0o600)

    # 2. Подъём туннелей
    for iface in (AWGS_SPLIT_OUT_IFACE, AWGS_SPLIT_IN_IFACE):
        core._run(["systemctl", "enable", f"awg-quick@{iface}"],
                  check=False, quiet=True)
        r = core._run(["systemctl", "restart", f"awg-quick@{iface}"],
                      capture=True, check=False)
        if r.returncode != 0:
            warn(f"{iface} не запустился: {r.stderr}")
            split_tunnels_stop()
            return False

    # 3. Ожидание handshake обоих плеч
    info("Ожидание handshake обоих плеч "
         f"({AWGS_SPLIT_PROBE_SEC} сек)...")
    deadline = time.time() + AWGS_SPLIT_PROBE_SEC
    both = False
    while time.time() < deadline:
        _time_sleep(3)
        p_out = split_iface_probe(AWGS_SPLIT_OUT_IFACE)
        p_in = split_iface_probe(AWGS_SPLIT_IN_IFACE)
        if p_out.get("handshake_age") is not None \
                and p_in.get("handshake_age") is not None:
            both = True
            break
    if not both:
        warn("Handshake не сошёлся на одном из плеч — обфускация/версия "
             "расходятся с exit? Откат: туннели остановлены, транзит НЕ "
             "переключался (штатный awg1 работает)")
        split_tunnels_stop()
        return False
    info("Handshake обоих плеч: сошёлся")

    # 4. E2E-верификация ДО переключения транзита
    if verify:
        info("E2E-верификация: пинг через оба плеча (запрос out / "
             "ответ обязан вернуться in)...")
        e2e = split_e2e_probe(probe_host)
        if e2e.get("supported") is False:
            warn("ping без -m: e2e-зонд недоступен — проверьте плечи "
                 "вручную (статус split). Включаю без верификации "
                 "(осторожно!)")
        elif not e2e.get("ok"):
            _loss = e2e.get("loss_pct")
            warn(f"E2E-зонд не прошёл (потери {_loss}%) — пара плеч не "
                 "работает в обе стороны. Откат: туннели остановлены, "
                 "транзит НЕ переключался (штатный awg1 работает)")
            split_tunnels_stop()
            return False
        else:
            info(f"E2E: потери {e2e.get('loss_pct')}% — оба плеча живы")

    # 5. Переключение транзита
    if not split_apply_entry():
        warn("Не удалось применить split-маршрутизацию (см. лог) — "
             "туннели остановлены, транзит на штатном awg1")
        split_tunnels_stop()
        return False

    st = awgs_state_load()
    st[AWGS_SPLIT_STATE_KEY] = {
        "enabled": True,
        "endpoint": endpoint,
        "port_out": int(box["port_out"]),
        "port_in": int(box["port_in"]),
        "protocol_version": protocol_version,
        "params": params,
        "probe_host": probe_host or AWGS_PROBE_HOST,
        "applied_at": _now_iso(),
        "fail_count": 0,
        "last_e2e": {"ok": True, "ts": _now_iso()},
    }
    if not awgs_state_save(st):
        warn("State НЕ сохранён — режим не зафиксирован (см. лог)")
        return False

    success("Split-direction ВКЛЮЧЁН: исходящее → awg-split-out, "
            "входящее ← awg-split-in; штатный awg1 — горячий fallback")
    _notify("awg_split_on",
            "Split-direction: пара однонаправленных туннелей включена "
            f"(out→<b>{endpoint}:{box['port_out']}</b>, "
            f"in←<b>{endpoint}:{box['port_in']}</b>); e2e верифицирована")
    return True


def split_apply_entry() -> bool:
    """Переключает транзит на split-плечи (правила + юнит; идемпотентно).

    Форма RU/b4-исключений — зеркало актуальной каскадной (включая
    exit-all): split наследует режим разделения трафика, а не диктует
    свой.
    """
    core = _core_module()
    state = awgs_state_load()

    _ru = _split_ru_excl(state)
    _b4 = _split_b4_excl()
    out_base = AWGS_SPLIT_OUT_SUBNET.split("/")[0].rsplit(".", 1)[0]

    script = split_build_entry_routing_script(
        ru_excl=_ru, b4_excl=_b4,
        out_gw=f"{out_base}.1", out_net=f"{out_base}.0/24")
    AWGS_SPLIT_ENTRY_SCRIPT.parent.mkdir(parents=True, exist_ok=True)
    AWGS_SPLIT_ENTRY_SCRIPT.write_text(script)
    AWGS_SPLIT_ENTRY_SCRIPT.chmod(0o755)
    AWGS_SPLIT_ENTRY_SVC.write_text(
        "[Unit]\n"
        "Description=AWG split-direction entry routing (out via split)\n"
        f"After=awg-quick@{AWGS_SPLIT_OUT_IFACE}.service awg-quick@{AWGS_SPLIT_IN_IFACE}.service\n"
        f"Wants=awg-quick@{AWGS_SPLIT_OUT_IFACE}.service awg-quick@{AWGS_SPLIT_IN_IFACE}.service\n"
        f"PartOf=awg-quick@{AWGS_SPLIT_OUT_IFACE}.service awg-quick@{AWGS_SPLIT_IN_IFACE}.service\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={AWGS_SPLIT_ENTRY_SCRIPT}\n"
        "RemainAfterExit=yes\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n")
    core._run(["systemctl", "daemon-reload"], check=False, quiet=True)
    core._run(["systemctl", "enable", "awg-split-entry-routing"],
              check=False, quiet=True)
    r = core._run(["systemctl", "restart", "awg-split-entry-routing"],
                  capture=True, check=False)
    if r.returncode != 0:
        core.log_to_file("WARN",
                         f"split_apply_entry: юнит не запустился: {r.stderr}")
        return False
    return True


def split_tunnels_stop() -> None:
    """Стопает и disable'ит туннели плеч (конфиги остаются — быстрое
    повторное включение без пересоздания ключей)."""
    core = _core_module()
    for iface in (AWGS_SPLIT_OUT_IFACE, AWGS_SPLIT_IN_IFACE):
        core._run(["systemctl", "disable", "--now", f"awg-quick@{iface}"],
                  check=False, quiet=True)


def split_rules_remove() -> None:
    """Сносит split-правила и возвращает транзит штатному каскадному
    mark-правилу (перезапуск каскадного routing-юнита пересоздаёт его
    live-набор — канон: активация exit после LB-leftover)."""
    core = _core_module()
    out_base = AWGS_SPLIT_OUT_SUBNET.split("/")[0].rsplit(".", 1)[0]
    core._run(["bash", "-c",
               f"while iptables -t mangle -D PREROUTING -i awg0 -j MARK --set-mark {AWGS_SPLIT_FWMARK_OUT} 2>/dev/null; do :; done; "
               f"while iptables -t mangle -D PREROUTING -i awg0 -m set ! --match-set awg_ru_networks dst -j MARK --set-mark {AWGS_SPLIT_FWMARK_OUT} 2>/dev/null; do :; done; "
               f"while iptables -t nat -D POSTROUTING -o {AWGS_SPLIT_OUT_IFACE} -j MASQUERADE 2>/dev/null; do :; done; "
               f"while iptables -D FORWARD -i awg0 -o {AWGS_SPLIT_OUT_IFACE} -j ACCEPT 2>/dev/null; do :; done; "
               f"while iptables -D FORWARD -i {AWGS_SPLIT_IN_IFACE} -o awg0 -j ACCEPT 2>/dev/null; do :; done; "
               f"while iptables -t mangle -D FORWARD -i awg0 -o {AWGS_SPLIT_OUT_IFACE} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240 2>/dev/null; do :; done; "
               f"while iptables -t mangle -D FORWARD -i {AWGS_SPLIT_IN_IFACE} -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240 2>/dev/null; do :; done; "
               f"while ip rule del fwmark {AWGS_SPLIT_FWMARK_OUT} lookup {AWGS_SPLIT_TABLE_OUT} 2>/dev/null; do :; done; "
               f"ip route flush table {AWGS_SPLIT_TABLE_OUT} 2>/dev/null; true"],
              check=False, quiet=True)


def split_off(reason: str = "", auto: bool = False) -> bool:
    """Выключает split-direction: правила снесены, туннели стоп,
    транзит вернулся штатному awg1 (рестарт каскадного routing-юнита).

    auto=True — аварийный откат watchdog'а (оба плеча мертвы): в
    уведе прямо сказано, что произошло и куда вернулись.
    """
    core = _core_module()
    info, success = core.info, core.success

    split_rules_remove()
    split_tunnels_stop()
    core._run(["systemctl", "disable", "--now", "awg-split-entry-routing"],
              check=False, quiet=True)
    # Штатный каскадный mark-путь: рестарт юнита пересоздаёт live-набор
    core._run(["systemctl", "restart", "awg-cascade-routing"],
              check=False, quiet=True)

    def _mut(box):
        box["enabled"] = False
        box["disabled_at"] = _now_iso()
        box["disabled_reason"] = reason

    if not _split_state_update(_mut):
        core.warn("State НЕ сохранён — режим мог остаться в state "
                  "включённым (см. лог)")
        return False
    if auto:
        success("Split-direction ОТКЛЮЧЁН (авто-откат): оба плеча мертвы — "
                "транзит вернулся на штатный awg1")
    else:
        success("Split-direction выключен: транзит на штатном awg1")
    _notify("awg_split_off",
            ("Split-direction ОТКЛЮЧЁН (авто-откат: оба плеча мертвы) — "
             "транзит вернулся на штатный туннель awg1"
             if auto else
             "Split-direction выключен вручную — транзит на штатном "
             "туннеле awg1")
            + (f". Причина: {reason}" if reason else ""))
    return True


# ============================================================================
#  HEALTH-CHECK / WATCHDOG (канон awgs_cascade_failover_check)
# ============================================================================

def split_health_tick() -> str:
    """Health-тик split-direction (таймер раз в минуту).

    Возвращает строку-действие (для логов/тестов):
      off              — режим выключен (тик ничего не делает)
      out-dead / in-dead / both-dead:<stage> — диагноз плеч
      restart:<iface>  — рестарт мёртвого плеча помог
      recovered        — рестарты спасли оба плеча
      rollback         — лестница исчерпана: авто-откат на штатный awg1
      ok / ok:e2e      — плечи живы (e2e-зонд по кулдауну прошёл)

    Лестница (двухступенчатая защита от ложных срабатываний — канон
    failover_check): handshake живой → дешёвая проверка; handshake
    несвежий у ОДНОГО плеча → рестарт этого плеча → пере-проба; оба
    плеча немёртвые, но e2e (по кулдауну) валится → рестарт обоих;
    N неудачных тиков подряд (fail_count) → откат на штатный awg1.
    """
    core = _core_module()

    state = awgs_state_load()
    box = split_state_get(state)
    if not box.get("enabled"):
        return "off"

    p_out = split_iface_probe(AWGS_SPLIT_OUT_IFACE)
    p_in = split_iface_probe(AWGS_SPLIT_IN_IFACE)
    out_alive = split_handshake_alive(p_out)
    in_alive = split_handshake_alive(p_in)

    if out_alive and in_alive:
        # E2E по кулдауну: дешёвый тик — только handshake; дорогой
        # пинг через оба плеча — не чаще AWGS_SPLIT_E2E_INTERVAL_SEC.
        _now = datetime.now(timezone.utc)
        _last = box.get("last_e2e") or {}
        _last_ts = _last.get("ts", "")
        _need_e2e = True
        if _last_ts:
            try:
                _need_e2e = (_now - datetime.fromisoformat(_last_ts)
                             ).total_seconds() >= AWGS_SPLIT_E2E_INTERVAL_SEC
            except (ValueError, TypeError):
                _need_e2e = True
        if not _need_e2e:
            _split_state_update(lambda b: b.update({"fail_count": 0}))
            return "ok"
        e2e = split_e2e_probe(box.get("probe_host", ""))

        def _ok_mut(b):
            b["fail_count"] = 0
            b["last_e2e"] = {"ok": True, "ts": _now_iso()}

        if e2e.get("ok"):
            _split_state_update(_ok_mut)
            return "ok:e2e"
        # e2e валится при живых handshake — «тихая смерть направления»:
        # данные не проходят, though keepalive живёт. Лечится рестартом
        # обоих плеч; если не помогло — копим fail_count.
        core.log_to_file("WARN",
                         "split_health_tick: e2e не прошёл при живых "
                         f"handshake (loss={e2e.get('loss_pct')}%) — "
                         "рестарт обоих плеч")
        split_restart_tunnel(AWGS_SPLIT_OUT_IFACE)
        split_restart_tunnel(AWGS_SPLIT_IN_IFACE)
        _split_state_update(lambda b: b.update({"fail_count": 1}))
        return "both-dead:e2e-restart"

    # Какое-то плечо немёртвое по handshake → рестарт-лестница
    restarted = []
    if not out_alive:
        split_restart_tunnel(AWGS_SPLIT_OUT_IFACE)
        restarted.append(AWGS_SPLIT_OUT_IFACE)
    if not in_alive:
        split_restart_tunnel(AWGS_SPLIT_IN_IFACE)
        restarted.append(AWGS_SPLIT_IN_IFACE)

    # даём рестартнутым плечам пере-handshake'нуться перед пере-пробой
    _time_sleep(5)
    p_out2 = split_iface_probe(AWGS_SPLIT_OUT_IFACE)
    p_in2 = split_iface_probe(AWGS_SPLIT_IN_IFACE)
    out2 = split_handshake_alive(p_out2)
    in2 = split_handshake_alive(p_in2)

    if out2 and in2:
        _split_state_update(lambda b: b.update(
            {"fail_count": 0, "last_recovered": _now_iso()}))
        _notify("awg_split_dir_dead",
                "Split-direction: плечо умирало, рестарт спас — "
                + ", ".join(restarted))
        return "recovered" if restarted else "ok"

    # Лестница не спасла: копим неудачи и откатываемся на штатный awg1
    fail = int(box.get("fail_count") or 0) + 1
    dead = ("out" if not out2 else "") + ("in" if not in2 else "")
    core.log_to_file(
        "ERROR",
        f"split_health_tick: плечи не ожили ({dead or 'e2e'}), "
        f"неудача #{fail}/{AWGS_SPLIT_FAIL_LIMIT}")
    if fail >= AWGS_SPLIT_FAIL_LIMIT:
        split_off(reason=f"health-тик #{fail}: плечи ({dead or 'e2e'}) "
                         "не отвечали после рестартов", auto=True)
        return "rollback"
    _split_state_update(lambda b: b.update({"fail_count": fail}))
    return f"both-dead:pending-{fail}"


def split_restart_tunnel(iface: str) -> None:
    """Рестарт одного плеча (канон: restart перечитывает конфиг)."""
    core = _core_module()
    core._run(["systemctl", "restart", f"awg-quick@{iface}"],
              capture=True, check=False, quiet=True)


def split_watchdog_setup() -> bool:
    """Создаёт и запускает split-таймер (ежеминутный health-тик).

    Wrapper-скрипт PYTHONPATH-safe — тот же паттерн, что
    awgs_cascade_failover_setup (bare python3 -c из-под systemd падает
    с ModuleNotFoundError)."""
    core = _core_module()
    try:
        import importlib.util
        spec = importlib.util.find_spec("chimera")
        if spec and spec.submodule_search_locations:
            installer_path = str(
                Path(list(spec.submodule_search_locations)[0]).parent)
        else:
            installer_path = "/opt/chimera"
    except Exception:
        installer_path = "/opt/chimera"

    wrapper = (
        "#!/bin/bash\n"
        "# AWG split-direction health-тик (watchdog направлений).\n"
        "mkdir -p /root/awg\n"
        f"export PYTHONPATH=\"{installer_path}:$PYTHONPATH\"\n"
        f"/usr/bin/python3 -c \"\n"
        f"import sys\n"
        f"sys.path.insert(0, '{installer_path}')\n"
        f"from chimera.modules.awg_split_direction import split_health_tick\n"
        f"split_health_tick()\n"
        f"\" >> /root/awg/awg_standalone.log 2>&1\n"
    )
    AWGS_SPLIT_SCRIPT.write_text(wrapper)
    AWGS_SPLIT_SCRIPT.chmod(0o755)

    AWGS_SPLIT_SVC.write_text(
        "[Unit]\n"
        "Description=AWG split-direction health check\n"
        f"After=awg-quick@{AWGS_SPLIT_OUT_IFACE}.service awg-quick@{AWGS_SPLIT_IN_IFACE}.service\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={AWGS_SPLIT_SCRIPT}\n"
    )
    AWGS_SPLIT_TIMER.write_text(
        "[Unit]\n"
        "Description=AWG split-direction watchdog (health-тик каждую минуту)\n"
        "\n"
        "[Timer]\n"
        "OnCalendar=*:0/1\n"
        "AccuracySec=10s\n"
        "Persistent=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )
    core._run(["systemctl", "daemon-reload"], check=False, quiet=True)
    core._run(["systemctl", "enable", "--now", "awg-split-direction.timer"],
              capture=True, check=False)
    r = core._run(["systemctl", "is-active", "awg-split-direction.timer"],
                  capture=True, check=False)
    return (r.stdout or "").strip() == "active"


def split_watchdog_teardown() -> bool:
    """Останавливает и удаляет split-таймер/сервис/wrapper."""
    core = _core_module()
    for unit in ("awg-split-direction.timer",
                 "awg-split-direction.service"):
        core._run(["systemctl", "stop", unit], check=False, quiet=True)
        core._run(["systemctl", "disable", unit], check=False, quiet=True)
    AWGS_SPLIT_TIMER.unlink(missing_ok=True)
    AWGS_SPLIT_SVC.unlink(missing_ok=True)
    AWGS_SPLIT_SCRIPT.unlink(missing_ok=True)
    core._run(["systemctl", "daemon-reload"], check=False, quiet=True)
    return True


# ============================================================================
#  СТАТУС + TUI-МЕНЮ
# ============================================================================

def split_status_info(state: Optional[dict] = None) -> dict:
    """Краткие данные статуса для меню (не бросает исключений)."""
    core = _core_module()
    box = split_state_get(state)
    out = {
        "enabled": bool(box.get("enabled")),
        "endpoint": box.get("endpoint", ""),
        "out": split_iface_probe(AWGS_SPLIT_OUT_IFACE),
        "in": split_iface_probe(AWGS_SPLIT_IN_IFACE),
    }
    try:
        r = core._run(["systemctl", "is-active", "awg-split-direction.timer"],
                      capture=True, check=False)
        out["watchdog"] = (r.stdout or "").strip() == "active"
    except Exception:
        out["watchdog"] = False
    return out


def _split_status_screen() -> None:
    """Бокс статуса split-direction (направления + watchdog)."""
    core = _core_module()
    _box_top, _box_row, _box_bottom = (core._box_top, core._box_row,
                                       core._box_bottom)
    GREEN, RED, DIM, NC, CYAN = (core.GREEN, core.RED, core.DIM, core.NC,
                                 core.CYAN)
    st = split_status_info()
    print()
    _box_top("СТАТУС SPLIT-DIRECTION")
    _box_row()
    if not st.get("endpoint"):
        _box_row(f"  {DIM}не настроен{NC}")
        _box_bottom()
        return
    _box_row(f"  Режим: "
             + (f"{GREEN}ВКЛЮЧЁН{NC}" if st["enabled"] else f"{DIM}выключен{NC}")
             + f"   exit: {st['endpoint']}")
    for label, probe in (("исходящее (out)", st["out"]),
                         ("входящее (in)", st["in"])):
        if probe.get("up") and probe.get("handshake_age") is not None:
            age = probe["handshake_age"]
            col = GREEN if age <= AWGS_SPLIT_STALE_SEC else RED
            _box_row(f"  {label}: {col}handshake {age} сек назад{NC}   "
                     f"↑{_fmt_bytes(probe.get('tx'))} ↓{_fmt_bytes(probe.get('rx'))}")
        else:
            _box_row(f"  {label}: {RED}не жив{NC}")
    _box_row(f"  Watchdog: "
             + (f"{GREEN}active{NC}" if st.get("watchdog")
                else f"{DIM}off{NC}"))
    _box_bottom()


def _fmt_bytes(n: int) -> str:
    """Байты → человекочитаемо (КиБ/МиБ) — для статус-строк."""
    n = int(n or 0)
    if n >= 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} МиБ"
    if n >= 1024:
        return f"{n / 1024:.1f} КиБ"
    return f"{n} Б"


def do_manage_awg_split_direction() -> None:
    """TUI-меню split-direction (вызывается из меню каскада, п.8)."""
    core = _core_module()
    _box_top, _box_row, _box_bottom = (core._box_top, core._box_row,
                                       core._box_bottom)
    _box_item, _box_desc, _box_kv = (core._box_item, core._box_desc,
                                     core._box_kv)
    info, warn, success = core.info, core.warn, core.success
    CYAN, NC, GREEN, YELLOW, DIM = (core.CYAN, core.NC, core.GREEN,
                                    core.YELLOW, core.DIM)

    while True:
        import os
        os.system("clear")
        print()
        state = awgs_state_load()
        role = state.get("cascade_role", "")
        split_on = split_is_on(state)

        _box_top("Split-direction • пара однонаправленных туннелей")
        _box_row()
        _box_desc("Клиент ──► awg0 ──► [out] awg-split-out ──► exit ──► мир")
        _box_desc("Клиент ◄── awg0 ◄── [in] awg-split-in ◄── exit ◄── мир")
        _box_desc("Кейс: двунаправленный туннель живёт только в одну сторону")
        _box_desc("(«отправить можем — принять нет»); штатный awg1 — fallback.")
        _box_row()
        _st = split_state_get(state)
        if _st.get("endpoint"):
            _box_row(f"  Режим: "
                     + (f"{GREEN}ВКЛЮЧЁН{NC}" if split_on else f"{DIM}выключен{NC}")
                     + f"  exit: {_st.get('endpoint')} "
                     f"(out:{_st.get('port_out', '?')} in:{_st.get('port_in', '?')})")
        else:
            _box_row(f"  {DIM}Плечи не настроены{NC}")
        if role:
            _box_row(f"  Роль этой ноды: {CYAN}{role}{NC}")
        _box_row()
        _box_item("1", "Зонд плеча: портрет поля + вердикт + рекомендация")
        _box_desc("Лестница L0-L2: handshake/счётчики → шлюз → большой "
                  "поток 50+ КБ через fwmark-путь. Матрица «симптом → "
                  "пресет» скажет, лечится ли ваше поле split-режимом.")
        _box_item("2", "Настроить ЭТУ ноду как exit (создаст оба плеча)")
        _box_desc("Запускать на зарубежной exit-ноде: два серверных "
                  "туннеля + возврат через in-плечо + бокс данных для entry.")
        _box_item("3", "Включить на ЭТОЙ ноде (бокс данных с exit)")
        _box_desc("Entry-нода: два клиентских плеча, e2e-верификация ДО "
                  "переключения транзита, откат при провале.")
        _box_item("4", "Выключить (вернуть транзит на штатный awg1)")
        _box_item("5", "Статус направлений")
        _box_item("6", "Watchdog: включить (health-тик каждую минуту)")
        _box_item("7", "Watchdog: выключить")
        _box_item("Q", "Назад")
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if ch == "1":
            from .awg_link_probe import do_link_probe_interactive
            do_link_probe_interactive()
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            _pv = core._box_ask("Версия протокола плеч [1=2.0, 2=3.1, Enter=2.0]")
            protocol_version = "3.1" if _pv == "2" else "2.0"
            _po = core._box_ask("UDP-порт out-плеча (исходящее)",
                                str(AWGS_SPLIT_PORT_OUT))
            _pi = core._box_ask("UDP-порт in-плеча (входящее)",
                                str(AWGS_SPLIT_PORT_IN))
            split_setup_exit(protocol_version=protocol_version,
                             port_out=int(_po), port_in=int(_pi))
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            _split_menu_entry_setup()
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            if not split_is_on():
                warn("Split-direction не включён")
            else:
                ok = input("\n  Выключить split-direction "
                           "(транзит → штатный awg1)? [y/N]: ").strip().lower()
                if ok in ("y", "yes", "д", "да"):
                    split_off(reason="выключен вручную")
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            _split_status_screen()
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "6":
            if split_watchdog_setup():
                success("Watchdog включён (таймер каждую минуту)")
            else:
                warn("Не удалось включить watchdog (см. лог)")
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "7":
            split_watchdog_teardown()
            info("Watchdog выключен, юниты удалены")
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch in ("q", ""):
            break


def _split_menu_entry_setup() -> None:
    """Промпты включения split на entry (бокс данных с exit)."""
    core = _core_module()
    info, warn = core.info, core.warn
    _box_top, _box_row, _box_kv, _box_bottom = (core._box_top, core._box_row,
                                                core._box_kv, core._box_bottom)
    DIM, NC = core.DIM, core.NC

    print()
    _box_top("ВКЛЮЧЕНИЕ SPLIT-DIRECTION • ENTRY")
    _box_row()
    _box_row(f"  {DIM}Все данные — из бокса «Данные для настройки{NC}")
    _box_row(f"  {DIM}split-direction на ENTRY» на exit-ноде (пункт 2).{NC}")
    _box_row(f"  {DIM}Обфускация и версия протокола синхронны на всех{NC}")
    _box_row(f"  {DIM}четырёх концах — иначе handshake не сойдётся.{NC}")
    _box_row()
    _box_kv("Endpoint host", "IP/домен exit")
    _box_kv("Port OUT / Port IN", "52840 / 52841")
    _box_kv("Server pubkey OUT / IN", "строки из бокса exit")
    _box_kv("Entry privkey OUT / IN", "строки из бокса exit")
    _box_kv("Версия протокола", "1=2.0, 2=3.1 (как на exit)")
    _box_kv("Obfuscation JSON", "строка из бокса exit (обязательна)")
    _box_bottom()

    endpoint = core._box_ask("Endpoint host exit")
    if not endpoint:
        warn("Endpoint обязателен")
        return
    port_out = int(core._box_ask("Port OUT", str(AWGS_SPLIT_PORT_OUT))
                   or AWGS_SPLIT_PORT_OUT)
    port_in = int(core._box_ask("Port IN", str(AWGS_SPLIT_PORT_IN))
                  or AWGS_SPLIT_PORT_IN)
    server_pubkey_out = core._box_ask("Server pubkey OUT")
    server_pubkey_in = core._box_ask("Server pubkey IN")
    peer_privkey_out = core._box_ask("Entry privkey OUT")
    peer_privkey_in = core._box_ask("Entry privkey IN")
    _pv = core._box_ask("Версия протокола [1=2.0, 2=3.1, Enter=2.0]")
    protocol_version = "3.1" if _pv == "2" else "2.0"
    params = None
    _params_raw = core._box_ask("Obfuscation JSON с exit (обязателен)")
    if _params_raw:
        try:
            params = json.loads(_params_raw)
        except Exception as e:
            warn(f"Некорректный JSON ({e})")
            return
    else:
        warn("Obfuscation JSON обязателен — обфускация обязана совпадать "
             "на всех концах")
        return

    confirm = core._box_ask(
        f"Включить split-direction: {endpoint} "
        f"(out:{port_out}/in:{port_in})? [y/N]").lower()
    if confirm not in ("y", "yes", "д", "да"):
        return

    split_setup_entry({
        "endpoint": endpoint,
        "port_out": port_out,
        "port_in": port_in,
        "server_pubkey_out": server_pubkey_out,
        "server_pubkey_in": server_pubkey_in,
        "peer_privkey_out": peer_privkey_out,
        "peer_privkey_in": peer_privkey_in,
        "protocol_version": protocol_version,
        "params": params,
    })
