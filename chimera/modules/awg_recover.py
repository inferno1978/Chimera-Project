"""
chimera/modules/awg_recover.py
───────────────────────────────────────────────────────────────────────────────
Восстановление awg_standalone_state.json из ЖИВОЙ системы.

ИНЦИДЕНТ 09.11.2026 (репорт пользователя, кейс «AWG 3.1 пропал после
обновления»): конкурентная запись в общий фиксированный .tmp портила
state-файл (перемешанный JSON двух процессов), следом read-modify-write
писатель закреплял {} — панель показывала «Не установлен» при ЖИВОМ
туннеле (awg-quick@awg0 active, peers=39, handshakes=38), каскад
работал. Клиентов/каскад/backup редактировать было невозможно — всё
это читает state. (Фиксы гонок — awg_state/awg_cascade/awg_cascade_lb;
этот модуль — восстановление ПОСЛЕ уже случившейся потери.)

ЧТО ВОССТАНАВЛИВАЕТСЯ (источники переживают потерю state — их пишет
install/peer_add, удаляет только uninstall):
  • /etc/amnezia/amneziawg/awg0.conf  — серверный ключ, подсеть, порт,
    MTU, параметры обфускации (2.0 Jc/Jmin/Jmax/S*/H*/I* + 3.1-директивы
    → protocol_version), пиры: имя (комментарий # <name>), PublicKey,
    AllowedIPs (v4/v6), PresharedKey
  • /root/awg/keys/<name>.conf        — приватные ключи клиентов
    (client_privkey) — иначе конфиги клиентов невосстановимы
  • /etc/amnezia/amneziawg/awg1.conf  — каскад entry: активный exit
    (Endpoint/PublicKey/подсеть линка + peer_privkey) → cascade_exits[0]
  • /etc/amnezia/amneziawg/awg{2..N}.conf — прочие слоты мульти-exit
    каскада / LB (FIX 11.11: раньше восстанавливался только awg1 —
    мульти-exit топология и lb-поддерево терялись; теперь все слоты
    с дедупом по endpoint:port → cascade_exits + lb.slots_snapshot,
    lb_mode остаётся ВЫКЛ — решение за оператором)
  • exit-сторона: спец-пир «cascade_entry» в awg0.conf → cascade_role
    = "exit"

ЧЕГО НЕТ в живой системе (честно помечаем в результате):
  • owner_email пиров, added_at, expires_at — хранились только в state
    (expires_at="" = бессрочный — НЕ выкидываем чужих клиентов);
  • имена exit'ов (восстанавливаются по endpoint — raw IP) и lb-режим
    (lb_mode/strategy/pinned) — реактивация LB в меню каскада;
  • endpoint_host — берём текущий публичный IP сервера.

КОНТРАКТ: rebuild НЕ трогает awg0.conf/awg1.conf/keys/ — только строит
state и сохраняет его (старый файл — если был — копируется в
.lost.<ts> рядом). Перед записью — самопроверка: количество пиров в
новом state == количеству [Peer] в awg0.conf (минус cascade-спец-пир).
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .awg_constants import (
    AWGS_STATE_FILE, AWGS_INTERFACE, AWGS_SERVER_CONF, AWGS_AWG1_CONF,
    AWGS_KEYS_DIR, AWGS_DEFAULT_PARAMS, AWGS_DEFAULT_MTU,
    AWGS_DEFAULT_SUBNET, AWGS_DEFAULT_SUBNET_V6,
    AWGS_CASCADE_ENTRY_PEER, AWGS_CONF_DIR, AWGS_LB_MAX_SLOTS,
)
from .awg_state import awgs_state_load, awgs_state_save, awgs_state_integrity
from .awg_protocol import AWG31_DIRECTIVE_NAMES


# Конфиг-имя → params-ключ для директив 3.1 (обратная карта к
# AWG31_DIRECTIVE_NAMES: строим на импорте, не дублируем руками).
_AW31_CONF_TO_PARAM = {conf: key for key, conf in AWG31_DIRECTIVE_NAMES.items()}

# params-ключи обфускации 2.0 в конфиг-именах (как в awgs_build_server_conf)
_PARAMS_20_CONF = {
    "jc": "Jc", "jmin": "Jmin", "jmax": "Jmax",
    "s1": "S1", "s2": "S2", "s3": "S3", "s4": "S4",
    "h1": "H1", "h2": "H2", "h3": "H3", "h4": "H4",
    "i1": "I1", "i2": "I2", "i3": "I3", "i4": "I4", "i5": "I5",
}


def _core_module():
    """Ленивый импорт _core (как во всех модулях проекта)."""
    import importlib
    return importlib.import_module("chimera._core")


# ── Парсер AWG-конфигов ─────────────────────────────────────────────────────

def _parse_awg_conf(path: Path) -> tuple[dict, list]:
    """Парсит awg-конфиг в (interface: dict, peers: list[dict]).

    Секции [Interface]/[Peer]; «# Key = » (пустое, закомментированное)
    пропускаем; комментарий ПЕРЕД [Peer]-парами («# <name>» — пиры
    пишет awgs_build_server_conf) становится peer["_comment"].
    Возвращает ({}, []) если файла нет.
    """
    interface: dict = {}
    peers: list = []
    if not path.exists():
        return interface, peers
    section = ""
    pending_comment = ""
    try:
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip().lower()
                if section == "peer":
                    # _comment заполняется СТРОКОЙ «# <name>» ВНУТРИ секции;
                    # наследовать с прошлого пира НЕЛЬЗЯ (безымянный хвост
                    # дублировал бы имя предыдущего клиента)
                    peers.append({"_comment": ""})
                pending_comment = ""
                continue
            if line.startswith("#"):
                # «# Key =» — закомментированная пустая директива: пропускаем
                body = line.lstrip("#").strip()
                if "=" in body:
                    continue
                # обычный комментарий — кандидат имени пира. Шумовые
                # служебные («cascade exit …»-легаси, wireguard-заголовки)
                # НЕ становятся именем; «cascade_entry» — становится
                # (это спец-пир, отсеем его в rebuild по имени).
                if section == "peer" and peers:
                    txt = body.strip()
                    if txt and not txt.lower().startswith(
                            ("cascade exit", "wireguard")):
                        pending_comment = txt
                        peers[-1]["_comment"] = txt
                continue
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()
            if not key or not val:
                continue
            if section == "interface":
                interface.setdefault(key, val)   # первый Address v4 главный
            elif section == "peer" and peers:
                # AllowedIPs может быть ДВЕ строки (v4 /32 + v6 /128) —
                # склеиваем через запятую (как один аргумент AllowedIPs)
                if key in peers[-1]:
                    peers[-1][key] = f"{peers[-1][key]},{val}"
                else:
                    peers[-1][key] = val
    except Exception:
        return interface, peers
    return interface, peers


def _net_from_addr(addr: str) -> tuple[str, str]:
    """'10.66.66.1/24' → ('10.66.66.0/24', '10.66.66.1').

    Сеть = хост-октет в 0 (серверный Address всегда .1 в /24-подсети
    Chimera; для awg1-линка — .2, сеть та же /24). IPv6: 'fd66:66:66::1/64'
    → ('fd66:66:66::/64', 'fd66:66:66::1').
    """
    try:
        ip_part, _, prefix = addr.partition("/")
        if not prefix:
            return addr, ip_part
        prefix = int(prefix)
        if ":" in ip_part:   # IPv6: сеть = база + ::/prefix
            base = ip_part.split("::")[0]
            return f"{base}::/{prefix}", ip_part
        parts = ip_part.split(".")
        if len(parts) != 4:
            return addr, ip_part
        net = ".".join(parts[:3]) + f".0/{prefix}"
        return net, ip_part
    except Exception:
        return addr, addr


# ── Деривация pubkey из privkey (pure-Python X25519) ───────────────────────

def _derive_pubkey(privkey_b64: str) -> str:
    """pubkey = X25519(priv, basepoint 9) — тот же примитив, что в
    awg_standalone._awgs_py_keygen_pair (без wg/awg-бинарников)."""
    try:
        from .awg_standalone import _awgs_x25519
        priv = bytearray(base64.b64decode(privkey_b64, validate=True))
        if len(priv) != 32:
            return ""
        priv[0] &= 248
        priv[31] &= 127
        priv[31] |= 64
        pub = _awgs_x25519(bytes(priv), b"\x09" + b"\x00" * 31)
        return base64.b64encode(pub).decode()
    except Exception:
        return ""


# ── Основной rebuild ────────────────────────────────────────────────────────

def _is_cascade_special_peer(comment: str) -> bool:
    """Спец-пиры каскада — НЕ клиенты: текущий 'cascade_entry' (exit-сторона)
    и легаси 'cascade exit peer' (до LB-residue guard 13.10)."""
    c = (comment or "").strip().lower()
    return c == AWGS_CASCADE_ENTRY_PEER or c.startswith("cascade exit")


def awgs_recover_preview() -> dict:
    """Сухой прогон: что можно восстановить (БЕЗ записи state).

    Возвращает dict:
      conf_found / keys_found / awg1_found / exit_role   — источники
      peers_total / peers_with_privkey                   — числа
      protocol_version / subnet / port                   — из awg0.conf
      already_ok                                         — state уже валиден
    """
    iface, peers = _parse_awg_conf(AWGS_SERVER_CONF)
    conf_found = bool(iface.get("PrivateKey"))
    # спец-пир каскадного входа на ЭТОЙ стороне (мы — exit)
    exit_role = any(_is_cascade_special_peer(p.get("_comment"))
                    for p in peers)
    client_peers = [p for p in peers
                    if not _is_cascade_special_peer(p.get("_comment"))]
    with_priv = 0
    for p in client_peers:
        name = (p.get("_comment") or "").strip()
        if name and (AWGS_KEYS_DIR / f"{name}.conf").exists():
            with_priv += 1
    params31 = [c for c in _AW31_CONF_TO_PARAM
                if c in iface and iface[c]]
    return {
        "already_ok": awgs_state_integrity() == "ok"
                      and awgs_state_load().get("installed"),
        "conf_found": conf_found,
        "keys_found": AWGS_KEYS_DIR.exists(),
        "awg1_found": AWGS_AWG1_CONF.exists(),
        "exit_role": exit_role,
        "peers_total": len(client_peers),
        "peers_with_privkey": with_priv,
        "protocol_version": "3.1" if params31 else "2.0",
        "subnet": _net_from_addr(iface.get("Address", ""))[0]
                  if iface.get("Address") else "",
        "port": iface.get("ListenPort", ""),
    }


def awgs_recover_state(apply: bool = False) -> dict:
    """Восстанавливает state из живой системы.

    apply=False — только построить и вернуть {"ok", "state", "report"};
    apply=True  — плюс: карантин-копия старого state (.lost.<ts>),
    запись нового, самопроверка. Никакие конфиги не трогаются.
    """
    core = _core_module()
    report: list = []

    iface, peers = _parse_awg_conf(AWGS_SERVER_CONF)
    if not iface.get("PrivateKey"):
        return {"ok": False, "state": None,
                "report": ["awg0.conf не найден/без PrivateKey — "
                           "восстанавливать не из чего"]}

    # ── параметры обфускации + версия протокола ────────────────────────────
    params = dict(AWGS_DEFAULT_PARAMS)
    for pkey, conf_name in _PARAMS_20_CONF.items():
        if conf_name in iface:
            raw = iface[conf_name]
            try:
                params[pkey] = int(raw)
            except ValueError:
                params[pkey] = raw
    params31_found = []
    for conf_name, pkey in _AW31_CONF_TO_PARAM.items():
        if conf_name in iface and str(iface[conf_name]).strip():
            params[pkey] = iface[conf_name]
            params31_found.append(conf_name)
    protocol_version = "3.1" if params31_found else "2.0"

    # ── подсеть / v6 / порт / mtu ──────────────────────────────────────────
    subnet, _server_ip = _net_from_addr(iface.get("Address", ""))
    subnet_v6 = ""
    for line in AWGS_SERVER_CONF.read_text().splitlines():
        s = line.strip()
        if s.startswith("Address") and "=" in s and ":" in s.split("=", 1)[1]:
            subnet_v6, _ = _net_from_addr(s.split("=", 1)[1].strip())
            break
    try:
        port = int(iface.get("ListenPort", 51820))
    except ValueError:
        port = 51820
    try:
        mtu = int(iface.get("MTU", AWGS_DEFAULT_MTU))
    except ValueError:
        mtu = AWGS_DEFAULT_MTU

    # ── пиры ────────────────────────────────────────────────────────────────
    now_iso = datetime.now(timezone.utc).isoformat()
    server_privkey = iface["PrivateKey"]
    server_pubkey = _derive_pubkey(server_privkey)
    if not server_pubkey:
        report.append("WARN: не удалось вычислить server_pubkey "
                      "(конфиги клиентов будут строиться с пустым "
                      "pubkey — перегенерируйте или восстановите из backup)")

    recovered_peers = []
    lost_privkeys = []
    for p in peers:
        name = (p.get("_comment") or "").strip()
        if not name or _is_cascade_special_peer(name):
            continue    # спец-пир каскада не является клиентом
        if not p.get("PublicKey"):
            continue
        client_ip = ""
        client_ipv6 = ""
        for a in (p.get("AllowedIPs") or "").split(","):
            a = a.strip()
            if not a:
                continue
            if ":" in a:
                client_ipv6 = a.split("/")[0]
            elif "." in a:
                client_ip = a.split("/")[0]
        client_privkey = ""
        keys_conf = AWGS_KEYS_DIR / f"{name}.conf"
        if keys_conf.exists():
            kiface, _kp = _parse_awg_conf(keys_conf)
            client_privkey = kiface.get("PrivateKey", "")
        if not client_privkey:
            lost_privkeys.append(name)
        recovered_peers.append({
            "name": name,
            "client_privkey": client_privkey,
            "client_pubkey": p.get("PublicKey", ""),
            "client_ip": client_ip,
            "client_ipv6": client_ipv6,
            "preshared_key": p.get("PresharedKey", ""),
            "added_at": now_iso,           # оригинал утерян вместе со state
            "expires_at": "",              # НЕ истекаем чужих клиентов
            "dns1": "1.1.1.1",
            "dns2": "8.8.8.8",
            "owner_email": "",             # привязка к VLESS утеряна
        })

    # ── каскад ──────────────────────────────────────────────────────────────
    # FIX 11.11 (эхо инцидента 08.11 «AWG 3.1 пропал»): раньше читался
    # ТОЛЬКО awg1.conf — восстановление теряло мульти-exit топологию
    # (остальные exit'ы «добавьте заново») и lb-поддерево целиком
    # (slots_snapshot). Живая система при этом несла все туннели
    # awg1..awgN и LB-диспетчер — state расходился с реальностью
    # (наблюдатель честно-неверно атрибутировал слоты активному exit).
    # Теперь: читаем ВСЕ слоты awg1..awgN (существующие конфиги),
    # дедуп по endpoint:port (держим низший слот — повторный endpoint
    # бывает после переключения failover-ом awg1 на уже существующий
    # exit, живой кейс RU2: awg1=de, awg2=de, awg3=nl1), каждому
    # восстановленному exit'у — его ФИЗИЧЕСКИЙ слот в lb.slots_snapshot.
    cascade_role = ""
    cascade_exits: list = []
    active_exit = ""
    lb_slots: dict = {}
    for slot in range(1, AWGS_LB_MAX_SLOTS + 1):
        slot_conf = AWGS_CONF_DIR / f"awg{slot}.conf"
        if not slot_conf.exists():
            continue
        a1iface, a1peers = _parse_awg_conf(slot_conf)
        a1peer = a1peers[0] if a1peers else {}
        endpoint = a1peer.get("Endpoint", "")
        if not (endpoint and a1iface.get("PrivateKey")):
            continue
        host, _, port_s = endpoint.rpartition(":")
        try:
            exit_port = int(port_s)
        except ValueError:
            exit_port = 51820
        # дедуп по endpoint:port — туннель к одному exit'у в нескольких
        # слотах (failover переключал awg1 на чужой endpoint)
        if any(b.get("endpoint") == host and int(b.get("port") or 0)
               == exit_port for b in cascade_exits):
            continue
        link_net, peer_ip = _net_from_addr(a1iface.get("Address", ""))
        # параметры обфускации линка — из awg{N}.conf (обе стороны
        # каскада обязаны совпадать; конфиг слота несёт полный набор)
        exit_params = dict(AWGS_DEFAULT_PARAMS)
        for pkey, conf_name in _PARAMS_20_CONF.items():
            if conf_name in a1iface:
                raw = a1iface[conf_name]
                try:
                    exit_params[pkey] = int(raw)
                except ValueError:
                    exit_params[pkey] = raw
        for conf_name, pkey in _AW31_CONF_TO_PARAM.items():
            if conf_name in a1iface and str(a1iface[conf_name]).strip():
                exit_params[pkey] = a1iface[conf_name]
        if not cascade_role:
            cascade_role = "entry"
        exit_name = host or "recovered-exit"
        box = {
            "name": exit_name,
            "endpoint": host,
            "port": exit_port,
            "server_pubkey": a1peer.get("PublicKey", ""),
            "peer_privkey": a1iface["PrivateKey"],
            "peer_psk": a1peer.get("PresharedKey", ""),
            "peer_ip": peer_ip,
            "subnet": link_net,
            "protocol_version": protocol_version,
            "params": exit_params,
            "mtu": mtu,
            "added_at": now_iso,
        }
        cascade_exits.append(box)
        lb_slots[exit_name] = slot
        if not active_exit:
            active_exit = exit_name      # слот 1 = активный (failover-форма)

    # exit-сторона (мы — зарубежный AWG1): спец-пир в awg0.conf
    if not cascade_role:
        for p in peers:
            if (p.get("_comment") or "").strip() == AWGS_CASCADE_ENTRY_PEER:
                cascade_role = "exit"
                break

    # ── endpoint_host: текущий публичный IP (оригинал утерян) ──────────────
    endpoint_host = ""
    try:
        endpoint_host = core.get_server_ip("4") or ""
    except Exception:
        pass

    # ── сборка state (по схеме awgs_state_init) ────────────────────────────
    state = {
        "installed": True,
        "version": "1.0.0",
        "rebuilt_at": now_iso,           # маркер восстановления
        "installed_at": now_iso,
        "interface": AWGS_INTERFACE,
        "port": port,
        "subnet": subnet or AWGS_DEFAULT_SUBNET,
        "subnet_v6": subnet_v6,
        "mtu": mtu,
        "endpoint": endpoint_host,
        "endpoint_host": endpoint_host,
        "server_privkey": server_privkey,
        "server_pubkey": server_pubkey,
        "params": params,
        "carrier_preset": "",
        "peers": recovered_peers,
        "cascade_role": cascade_role,
        "cascade_peer_host": cascade_exits[0]["endpoint"] if cascade_exits else "",
        "cascade_peer_port": cascade_exits[0]["port"] if cascade_exits else 0,
        "cascade_peer_pubkey": cascade_exits[0]["server_pubkey"] if cascade_exits else "",
        "cascade_peer_privkey": cascade_exits[0]["peer_privkey"] if cascade_exits else "",
        "cascade_subnet": cascade_exits[0]["subnet"] if cascade_exits else "",
        "allow_ipv6_tunnel": bool(subnet_v6),
        "protocol_version": protocol_version,
    }
    if cascade_exits:
        from .awg_constants import (
            AWGS_CASCADE_EXITS_KEY, AWGS_CASCADE_ACTIVE_KEY,
        )
        state[AWGS_CASCADE_EXITS_KEY] = cascade_exits
        state[AWGS_CASCADE_ACTIVE_KEY] = active_exit
        # lb-поддерево: физические слоты туннелей (FIX 11.11 — раньше
        # восстановление теряло его целиком). lb_mode намеренно НЕ
        # включаем: режим работы — операторское решение (failover —
        # безопасный дефолт после утери state; для возврата LB — меню
        # каскада → Балансировка, диспетчер пересоберётся сам)
        if len(cascade_exits) >= 2:
            state["lb"] = {"slots_snapshot": lb_slots}

    # ── самопроверка ────────────────────────────────────────────────────────
    n_conf = len([p for p in peers
                  if (p.get("_comment") or "").strip()
                  and not _is_cascade_special_peer(p.get("_comment"))
                  and p.get("PublicKey")])
    if len(recovered_peers) != n_conf:
        return {"ok": False, "state": None,
                "report": report + [
                    f"САМОПРОВЕРКА: пиров в awg0.conf={n_conf}, "
                    f"восстановлено={len(recovered_peers)} — отказ "
                    f"(ничего не записано)"]}

    report.append(f"state собран: {awg_protocol_label_safe(protocol_version)}, "
                  f"подсеть {state['subnet']}, порт {port}, "
                  f"пиров {len(recovered_peers)}")
    if lost_privkeys:
        report.append(f"WARN: у {len(lost_privkeys)} пира(ов) НЕ найден "
                      f"приватный ключ в {AWGS_KEYS_DIR}/ (конфиг этим "
                      f"клиентам не выдать — ключи придётся перегенерировать): "
                      f"{', '.join(lost_privkeys[:10])}"
                      + (" …" if len(lost_privkeys) > 10 else ""))
    if recovered_peers:
        report.append("NOTE: owner_email и сроки (expires_at) пиров утеряны "
                      "вместе со state — при необходимости перепривяжите "
                      "владельцев в панели")
    if cascade_role == "entry":
        if len(cascade_exits) >= 2:
            slots_s = ", ".join(f"{n}→awg{s}" for n, s in lb_slots.items())
            report.append(f"NOTE: каскад entry восстановлен по слотам "
                          f"конфигов: {len(cascade_exits)} exit'а "
                          f"({slots_s}); lb.slots_snapshot записан, "
                          f"lb_mode оставлен ВЫКЛ — если до утери state "
                          f"работала балансировка, реактивируйте её "
                          f"(меню каскада → Балансировка; если живая "
                          f"система несёт leftover-диспетчер awg_lb — "
                          f"он будет снят при первой активации exit)")
        else:
            report.append(f"NOTE: каскад entry восстановлен: активный "
                          f"exit '{active_exit}' из awg1.conf")
    if cascade_role == "exit":
        report.append("NOTE: роль каскада exit (спец-пир "
                      f"'{AWGS_CASCADE_ENTRY_PEER}' в awg0.conf)")

    if not apply:
        return {"ok": True, "state": state, "report": report}

    # ── запись: карантин старого + save + контрольное чтение ────────────────
    if AWGS_STATE_FILE.exists():
        try:
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            lost = AWGS_STATE_FILE.with_suffix(f".lost.{ts}")
            lost.write_bytes(AWGS_STATE_FILE.read_bytes())
            report.append(f"прежний state сохранён: {lost.name}")
        except Exception:
            report.append("WARN: не удалось сохранить копию прежнего state")
    if not awgs_state_save(state):
        return {"ok": False, "state": None,
                "report": report + ["НЕ УДАЛОСЬ записать state (см. лог)"]}
    check = awgs_state_load()
    if not check.get("installed") or len(check.get("peers", [])) != len(recovered_peers):
        return {"ok": False, "state": None,
                "report": report + ["КОНТРОЛЬНОЕ ЧТЕНИЕ разошлось с "
                                    "записанным — state НЕ восстановлен"]}
    report.append(f"state восстановлен и проверен "
                  f"(peers={len(check.get('peers', []))})")
    try:
        core.log_to_file("INFO",
                         f"awg_recover: state rebuilt из живой системы "
                         f"(peers={len(recovered_peers)}, "
                         f"protocol={protocol_version}, "
                         f"cascade_role={cascade_role or '—'})")
    except Exception:
        pass
    return {"ok": True, "state": check, "report": report}


def awg_protocol_label_safe(version: str) -> str:
    try:
        from .awg_protocol import awg_protocol_label
        return awg_protocol_label(version)
    except Exception:
        return f"AmneziaWG {version}"


# ── TUI ─────────────────────────────────────────────────────────────────────

def do_awg_recover_menu() -> None:
    """Диалог восстановления state (вызывается из AWG-меню, пункт 9)."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    warn = core.warn
    success = core.success
    info = core.info
    CYAN, NC, YELLOW, DIM = core.CYAN, core.NC, core.YELLOW, core.DIM

    print()
    _box_top("ВОССТАНОВЛЕНИЕ STATE ИЗ ЖИВОЙ СИСТЕМЫ")
    _box_row()
    integrity = awgs_state_integrity()
    if integrity == "ok" and awgs_state_load().get("installed"):
        _box_row(f"  {DIM}state уже валиден — восстановление не требуется.{NC}")
        _box_row(f"  {DIM}(Пунктом 9 пользуются после потери state:{NC}")
        _box_row(f"  {DIM}«AWG не установлен» при живом туннеле.){NC}")
        _box_bottom()
        return

    pv = awgs_recover_preview()
    _box_row(f"  Источники: awg0.conf "
             f"{'✓' if pv['conf_found'] else '✗ НЕТ'}"
             f" | keys/ {'✓' if pv['keys_found'] else '✗'}"
             f" | awg1.conf {'✓' if pv['awg1_found'] else '—'}")
    _box_row(f"  Пиры в awg0.conf: {pv['peers_total']} "
             f"(с приватными ключами: {pv['peers_with_privkey']})")
    if pv["peers_total"]:
        _box_row(f"  Протокол: {pv['protocol_version']}, подсеть "
                 f"{pv['subnet'] or '?'}, порт {pv['port']}")
    _box_row()
    _box_row(f"  {YELLOW}owner_email, сроки пиров и НЕактивные exit'ы каскада{NC}")
    _box_row(f"  {YELLOW}восстановлению не подлежат (жили только в state).{NC}")
    _box_row()
    _box_bottom()

    if not pv["conf_found"]:
        warn("awg0.conf не найден — восстановление невозможно "
             "(нужен установленный AWG)")
        return
    ch = core._box_ask("Восстановить state? [y/N]").lower()
    if ch not in ("y", "yes", "д", "да"):
        info("Отменено")
        return
    res = awgs_recover_state(apply=True)
    for line in res.get("report", []):
        (success if line.startswith("state ") else warn)(line)
    if res.get("ok"):
        success("Готово. Проверьте клиентов/каскад и сделайте backup!")
