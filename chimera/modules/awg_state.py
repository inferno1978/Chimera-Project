"""
chimera/modules/awg_state.py
───────────────────────────────────────────────────────────────────────────────
State management для AmneziaWG 2.0 standalone-режима.

Полностью автономный state-файл /var/lib/xray-installer/awg_standalone_state.json
НЕ смешивается с основным state.json (который относится к VLESS-установке).

Структура state:
{
  "installed": true,
  "version": "1.0.0",
  "installed_at": "2026-07-09T12:00:00Z",
  "interface": "awg0",
  "port": 51820,
  "subnet": "10.66.66.0/24",
  "subnet_v6": "fd66:66:66::/64",
  "mtu": 1280,
  "endpoint": "203.0.113.5",        # публичный IP сервера
  "endpoint_host": "",               # если задан --endpoint (для NAT)
  "server_privkey": "...",
  "server_pubkey":  "...",
  "params": {                        # текущие параметры обфускации
    "jc": 4, "jmin": 40, "jmax": 70,
    "s1": 0, "s2": 0, "s3": 0, "s4": 0,
    "h1": 1, "h2": 2, "h3": 3, "h4": 4,
    "i1": "", "i2": "", "i3": "", "i4": "", "i5": ""
  },
  "carrier_preset": "default",       # применённый carrier-пресет
  "peers": [                         # список клиентов
    {
      "name": "alice",
      "client_privkey": "...",
      "client_pubkey":  "...",
      "client_ip":      "10.66.66.2",
      "client_ipv6":    "fd66:66:66::2",
      "preshared_key":  "",          # опционально
      "added_at":       "2026-07-09T12:00:00Z",
      "expires_at":     "",          # ISO или пусто (бессрочный)
      "dns1":           "1.1.1.1",
      "dns2":           "8.8.8.8",
      "owner_email":    ""           # email VLESS-юзера-владельца ("" = технический/неразобранный)
    }
  ],
  "cascade_role": "",                # "entry" | "exit" | "" (не каскад)
  "cascade_peer_host": "",           # для entry: host exit-VPS
  "cascade_peer_port": 0,
  "cascade_peer_pubkey": "",
  "cascade_peer_privkey": "",        # клиентский ключ для подключения к exit
  "cascade_subnet": "",              # подсеть exit-VPS (например 172.16.61.0/24)
  "allow_ipv6_tunnel": false
}
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .awg_constants import AWGS_STATE_FILE, AWGS_INTERFACE, AWGS_DEFAULT_PORT
from .awg_constants import AWGS_DEFAULT_SUBNET, AWGS_DEFAULT_SUBNET_V6, AWGS_DEFAULT_MTU
from .awg_constants import AWGS_DEFAULT_PARAMS, AWGS_DEFAULT_PROTOCOL_VERSION
from .awg_protocol import awg_normalize_version, awg_state_protocol_version


def _core_module():
    """Ленивый импорт _core (как во всех модулях проекта)."""
    import importlib
    return importlib.import_module("chimera._core")


# ── State load/save ──────────────────────────────────────────────────────────

def awgs_state_load() -> dict:
    """Загружает state. Возвращает {} если файл не существует или corrupt."""
    try:
        if not AWGS_STATE_FILE.exists():
            return {}
        return json.loads(AWGS_STATE_FILE.read_text())
    except Exception as e:
        try:
            core = _core_module()
            core.log_to_file("WARN", f"awgs_state_load: {e}")
        except Exception:
            pass
        return {}


def awgs_state_save(state: dict) -> bool:
    """Атомарно сохраняет state. Возвращает True при успехе."""
    try:
        AWGS_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Атомарная запись через tmp + rename
        tmp = AWGS_STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False))
        tmp.replace(AWGS_STATE_FILE)
        # Права 0600 — внутри state есть приватные ключи
        AWGS_STATE_FILE.chmod(0o600)
        return True
    except Exception as e:
        try:
            core = _core_module()
            core.log_to_file("ERROR", f"awgs_state_save: {e}")
        except Exception:
            pass
        return False


def awgs_state_update(**kwargs: Any) -> dict:
    """Частичное обновление state (merge top-level keys). Возвращает обновлённый state."""
    state = awgs_state_load()
    state.update(kwargs)
    awgs_state_save(state)
    return state


# ── State initialization ────────────────────────────────────────────────────

def awgs_state_init(
    server_privkey: str,
    server_pubkey: str,
    port: int = AWGS_DEFAULT_PORT,
    subnet: str = AWGS_DEFAULT_SUBNET,
    subnet_v6: str = AWGS_DEFAULT_SUBNET_V6,
    mtu: int = AWGS_DEFAULT_MTU,
    endpoint: str = "",
    endpoint_host: str = "",
    params: Optional[dict] = None,
    carrier_preset: str = "default",
    allow_ipv6_tunnel: bool = False,
    protocol_version: str = AWGS_DEFAULT_PROTOCOL_VERSION,
) -> dict:
    """Создаёт начальный state при первой установке.

    protocol_version — "2.0" (дефолт, обратная совместимость) или "3.1"
    (AWG 3.1: transport protection — HeaderProtectionKey/ContentPaddingAddition/
    Rekey*/RejectAfterTime/KeepaliveTimeout/MaxHandshakeAttempts/
    RandomTrailers/DisableCookies в params).
    """
    state = {
        "installed":         True,
        "version":           "1.0.0",
        "installed_at":      datetime.now(timezone.utc).isoformat(),
        "interface":         AWGS_INTERFACE,
        "port":              port,
        "subnet":            subnet,
        "subnet_v6":         subnet_v6,
        "mtu":               mtu,
        "endpoint":          endpoint,
        "endpoint_host":     endpoint_host,
        "server_privkey":    server_privkey,
        "server_pubkey":     server_pubkey,
        "params":            params or dict(AWGS_DEFAULT_PARAMS),
        "carrier_preset":    carrier_preset,
        "peers":             [],
        "cascade_role":      "",
        "cascade_peer_host": "",
        "cascade_peer_port": 0,
        "cascade_peer_pubkey": "",
        "cascade_peer_privkey": "",
        "cascade_subnet":    "",
        "allow_ipv6_tunnel": allow_ipv6_tunnel,
        "protocol_version":  awg_normalize_version(protocol_version),
    }
    awgs_state_save(state)
    return state


# ── Версия протокола (2.0 / 3.1) ────────────────────────────────────────────

def awgs_state_get_protocol_version() -> str:
    """Возвращает protocol_version из state ("2.0" | "3.1").

    Отсутствие ключа (старые установки до v5.5) = "2.0" — миграция
    не требуется: awg_protocol.awg_state_protocol_version нормализует.
    """
    return awg_state_protocol_version(awgs_state_load())


def awgs_state_set_protocol_version(version: str) -> bool:
    """Устанавливает protocol_version в state. Возвращает True при успехе.

    ВНИМАНИЕ: смена версии задним числом НЕ меняет params — для реального
    перехода 2.0 → 3.1 нужна переустановка/ротация обфускации с новым
    набором параметров (иначе state будет обещать 3.1 без 3.1-директив).
    Вызывается только из флоу установки/ротации.
    """
    awgs_state_update(protocol_version=awg_normalize_version(version))
    return True


# ── Peers management (вспомогательные функции для state) ────────────────────

def awgs_state_peers_get() -> list:
    """Возвращает список пиров из state."""
    return awgs_state_load().get("peers", [])


def awgs_state_peer_add(peer: dict) -> bool:
    """Добавляет пира в state. Возвращает True при успехе."""
    state = awgs_state_load()
    peers = state.get("peers", [])
    # Проверка на дубликат по имени
    if any(p.get("name") == peer.get("name") for p in peers):
        return False
    peers.append(peer)
    state["peers"] = peers
    return awgs_state_save(state)


def awgs_state_peer_remove(name: str) -> Optional[dict]:
    """Удаляет пира по имени. Возвращает удалённый dict или None."""
    state = awgs_state_load()
    peers = state.get("peers", [])
    for i, p in enumerate(peers):
        if p.get("name") == name:
            removed = peers.pop(i)
            state["peers"] = peers
            awgs_state_save(state)
            return removed
    return None


def awgs_state_peer_find(name: str) -> Optional[dict]:
    """Находит пира по имени. Возвращает dict или None."""
    for p in awgs_state_peers_get():
        if p.get("name") == name:
            return p
    return None


def awgs_state_peer_update(name: str, **fields) -> bool:
    """Обновляет поля пира по имени."""
    state = awgs_state_load()
    peers = state.get("peers", [])
    for p in peers:
        if p.get("name") == name:
            p.update(fields)
            state["peers"] = peers
            return awgs_state_save(state)
    return False


def awgs_state_ensure_peer_owner_field() -> None:
    """
    Миграция: гарантирует что у каждого пира есть поле owner_email.
    Если поле отсутствует в существующем state.json (создано до введения
    owner_email) — добавляет его со значением "" (технический/неразобранный пир).
    Идемпотентно: ничего не делает если все пиры уже имеют поле.
    """
    state = awgs_state_load()
    peers = state.get("peers", [])
    if not peers:
        return
    dirty = False
    for p in peers:
        if "owner_email" not in p:
            p["owner_email"] = ""
            dirty = True
    if dirty:
        state["peers"] = peers
        awgs_state_save(state)


def awgs_state_find_peer_by_owner(owner_email: str) -> Optional[dict]:
    """
    Находит пира по owner_email (для user-портала).
    Возвращает dict или None. Если несколько пиров привязаны к одному email —
    возвращает первый (по порядку в state.json). Это нормальная ситуация
    только в edge-case когда админ перевыдал пира без отвязки старого.
    """
    if not owner_email:
        return None
    for p in awgs_state_peers_get():
        if p.get("owner_email", "") == owner_email:
            return p
    return None


# ── IP allocation ────────────────────────────────────────────────────────────

def awgs_state_next_ip(subnet: str = "") -> Optional[str]:
    """
    Находит следующий свободный IP в подсети.
    Подсеть берётся из state или из аргумента. Формат: '10.66.66.0/24'.
    Возвращает IP без префикса (например '10.66.66.5') или None если все заняты.
    """
    state = awgs_state_load()
    subnet = subnet or state.get("subnet", AWGS_DEFAULT_SUBNET)
    # Парсим подсеть: '10.66.66.0/24' → base='10.66.66', /24
    try:
        parts = subnet.split("/")
        if len(parts) != 2:
            return None
        base_parts = parts[0].split(".")
        if len(base_parts) != 4:
            return None
        base = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}"
        # Собираем занятые IP
        used_ips = {p.get("client_ip", "") for p in state.get("peers", [])}
        used_ips.add(state.get("server_ip", ""))  # серверный .1 не отдавать
        # Сканируем .2 .. .254
        for last_octet in range(2, 255):
            candidate = f"{base}.{last_octet}"
            if candidate not in used_ips:
                return candidate
    except Exception:
        return None
    return None


def awgs_state_next_ipv6(subnet_v6: str = "") -> Optional[str]:
    """
    Находит следующий свободный IPv6 в ULA-подсети.
    Формат подсети: 'fd66:66:66::/64'. Возвращает IPv6 без префикса.
    Простая аллокация: ::2, ::3, ... ::ff (254 клиента).
    """
    state = awgs_state_load()
    subnet_v6 = subnet_v6 or state.get("subnet_v6", AWGS_DEFAULT_SUBNET_V6)
    try:
        # 'fd66:66:66::/64' → base='fd66:66:66'
        base = subnet_v6.split("::")[0].rstrip(":")
        used_ipv6 = {p.get("client_ipv6", "") for p in state.get("peers", [])}
        # ::2 .. ::ff
        for n in range(2, 256):
            candidate = f"{base}::{n:x}"
            if candidate not in used_ipv6:
                return candidate
    except Exception:
        return None
    return None


# ── Cascade state ───────────────────────────────────────────────────────────

def awgs_state_set_cascade_role(role: str, **kwargs) -> bool:
    """Устанавливает роль каскада: 'entry' или 'exit'."""
    if role not in ("entry", "exit", ""):
        return False
    state = awgs_state_load()
    state["cascade_role"] = role
    state.update(kwargs)
    return awgs_state_save(state)


# ── Helpers ──────────────────────────────────────────────────────────────────

def awgs_state_is_installed() -> bool:
    """Была ли установка standalone AWG."""
    return bool(awgs_state_load().get("installed", False))


def awgs_state_get_params() -> dict:
    """Возвращает текущие параметры обфускации."""
    return awgs_state_load().get("params", dict(AWGS_DEFAULT_PARAMS))


def awgs_state_get_endpoint() -> str:
    """Возвращает публичный endpoint (для генерации клиентских конфигов)."""
    state = awgs_state_load()
    return state.get("endpoint_host") or state.get("endpoint", "")


def awgs_state_get_server_pubkey() -> str:
    return awgs_state_load().get("server_pubkey", "")


def awgs_state_get_server_privkey() -> str:
    return awgs_state_load().get("server_privkey", "")


def awgs_state_get_port() -> int:
    return awgs_state_load().get("port", AWGS_DEFAULT_PORT)


def awgs_state_get_subnet() -> str:
    return awgs_state_load().get("subnet", AWGS_DEFAULT_SUBNET)


def awgs_state_get_subnet_v6() -> str:
    return awgs_state_load().get("subnet_v6", AWGS_DEFAULT_SUBNET_V6)


def awgs_state_get_mtu() -> int:
    return awgs_state_load().get("mtu", AWGS_DEFAULT_MTU)
