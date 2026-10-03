"""
chimera/modules/awg_peers.py
───────────────────────────────────────────────────────────────────────────────
Управление пирами (клиентами) AmneziaWG standalone.

Команды (как в bivlked manage_amneziawg.sh):
  • add <name> [--expires=7d] [--psk]
  • remove <name>
  • list [-v] [--json]
  • stats [--json]
  • regen <name>
  • modify <name> <param> <value>

Все изменения применяются через awg syncconf (без даунтайма).
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from .awg_constants import (
    AWGS_KEYS_DIR, AWGS_BIN, AWGS_DEFAULT_PARAMS,
)
from .awg_state import (
    awgs_state_load, awgs_state_save, awgs_state_peer_add, awgs_state_peer_remove,
    awgs_state_peer_find, awgs_state_peer_update,
    awgs_state_next_ip, awgs_state_next_ipv6,
    awgs_state_get_params, awgs_state_get_server_pubkey,
    awgs_state_get_port, awgs_state_get_endpoint,
)
from .awg_apply import awgs_apply
from .awg_standalone import awgs_generate_keys, awgs_generate_preshared_key, awgs_build_server_conf, awgs_write_server_conf
from .awg_qr import awgs_qr_export_peer
from .awg_expires import (
    awgs_expires_parse, awgs_expires_compute_iso, awgs_expires_humanize,
)


def _core_module():
    import importlib
    return importlib.import_module("chimera._core")


# ── Валидация имени ─────────────────────────────────────────────────────────

def _validate_peer_name(name: str) -> bool:
    """Имя пира: 1-32 символа, [a-zA-Z0-9_-], не начинается с цифры."""
    if not name or len(name) > 32:
        return False
    if name[0].isdigit():
        return False
    import re
    return bool(re.match(r"^[a-zA-Z0-9_-]+$", name))


# ── Валидация email ─────────────────────────────────────────────────────────

_EMAIL_RE = None


def _validate_email(email: str) -> bool:
    """
    Простая валидация формата email.
    Пустая строка допустима (снимает привязку owner_email).
    НЕ проверяет что такой VLESS-юзер физически существует в users.json —
    админ может привязать пира к любому email (это не обязано совпадать с
    существующими юзерами, UI лишь подсказывает существующих).
    """
    if not email:
        return True  # пустая строка = снять привязку — допустимо
    global _EMAIL_RE
    if _EMAIL_RE is None:
        import re
        # Простая regex: локальная часть @ домен с точкой
        _EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    return bool(_EMAIL_RE.match(email))


# ── Перестроение awg0.conf из state ─────────────────────────────────────────

def awg_peer_rebuild_conf(apply: bool = True, params_override: dict = None) -> bool:
    """
    Перестраивает awg0.conf из state (все пиры) и применяет через syncconf.
    Вызывается после любого изменения набора пиров.

    params_override: если передан (не None), используется вместо
        state.get("params", ...) при построении конфига. Состояние state
        на диске при этом НЕ меняется — только конфиг строится с этими
        параметрами. Это нужно для awgs_rotate_obfuscation(): apply должен
        выполниться с NEW_PARAMS (не со старыми из state), но state на
        диске должен коммититься только при подтверждённом успехе apply.
        Без params_override rebuild_conf читает state с диска и строит
        конфиг со СТАРЫМИ параметрами — ротация ничего не ротирует, но
        репортит успех (регрессия, внесённая 225c2ba, исправлена).
    """
    core = _core_module()
    state = awgs_state_load()
    # Anti-Empty Identity Guard — при битом/пустом awg-state.json
    # server_privkey="" молча попадал в awg0.conf (PrivateKey = ) → конфиг
    # с пустым ключом ПЕРЕЗАПИСЫВАЛ рабочий awg0.conf и валил всех AWG-
    # клиентов. Пустой ключ = отказ от rebuild, рабочий конфиг не трогаем.
    _server_privkey = state.get("server_privkey", "")
    if not _server_privkey:
        core.warn("AWG identity-guard: server_privkey пуст в awg-state.json "
                  "— отказ от перезаписи awg0.conf (существующий конфиг "
                  "сохранён). Восстановите awg-state.json из бэкапа.")
        return False
    # params_override имеет приоритет — позволяет строить конфиг с новыми
    # параметрами ДО того, как они записаны в state.
    params = params_override if params_override is not None \
        else state.get("params", AWGS_DEFAULT_PARAMS)
    conf_content = awgs_build_server_conf(
        server_privkey=_server_privkey,
        port=state.get("port", 51820),
        subnet=state.get("subnet", "10.66.66.0/24"),
        subnet_v6=state.get("subnet_v6", ""),
        mtu=state.get("mtu", 1280),
        params=params,
        peers=state.get("peers", []),
        endpoint_host=state.get("endpoint_host", ""),
        cascade_role=state.get("cascade_role", ""),
        cascade_peer={
            "pubkey":         state.get("cascade_peer_pubkey", ""),
            "subnet":         state.get("cascade_subnet", ""),
            "endpoint":       f"{state.get('cascade_peer_host', '')}:{state.get('cascade_peer_port', 0)}",
            "preshared_key":  "",
        } if state.get("cascade_role") == "entry" else None,
        # v5.5: версия протокола из state — 3.1-установки получают
        # awg0.conf с 9 транспортными директивами; отсутствие ключа
        # (старые state) = "2.0" = байт-в-байт прежнее поведение.
        protocol_version=state.get("protocol_version", "2.0"),
    )
    if not awgs_write_server_conf(conf_content):
        return False
    if apply:
        return awgs_apply()
    return True


# ── ADD ─────────────────────────────────────────────────────────────────────

def awg_peer_add(
    name: str,
    expires: str = "",
    psk: bool = False,
    apply: bool = True,
    save_state: bool = True,
    show_qr: bool = True,
    owner_email: str = "",
) -> bool:
    """
    Добавляет нового клиента.
    name: имя пира
    expires: duration string ('7d', '12h', пусто = бессрочный)
    psk: генерировать PresharedKey
    apply: применить через syncconf
    save_state: сохранить в state.json
    show_qr: показать QR-код после добавления
    owner_email: email VLESS-юзера-владельца ("" = технический/неразобранный,
                 виден только админу; непустое — попадёт в user-портал этого юзера)
    """
    core = _core_module()
    info = core.info
    success = core.success
    warn = core.warn

    if not _validate_peer_name(name):
        warn(f"Имя '{name}' невалидно (1-32 символа, [a-zA-Z0-9_-], не с цифры)")
        return False

    if awgs_state_peer_find(name):
        warn(f"Пир '{name}' уже существует")
        return False

    # Валидация owner_email (простой формат, НЕ проверяем существование юзера)
    owner_email = (owner_email or "").strip()
    if not _validate_email(owner_email):
        warn(f"Невалидный owner_email='{owner_email}'")
        return False

    # Парсим expires
    expires_at = ""
    if expires:
        delta = awgs_expires_parse(expires)
        if delta is None:
            warn(f"Невалидный --expires='{expires}'. Примеры: 1h, 12h, 7d, 30d, 4w")
            return False
        expires_at = awgs_expires_compute_iso(delta)
        info(f"Срок действия: {expires} (до {expires_at})")

    # Генерируем ключи клиента
    info(f"Генерация ключей для '{name}'...")
    client_priv, client_pub = awgs_generate_keys()
    if not client_priv or not client_pub:
        warn("Не удалось сгенерировать ключи клиента")
        return False

    # Аллоцируем IP
    client_ip = awgs_state_next_ip()
    if not client_ip:
        warn("Нет свободных IP в подсети (максимум 253 клиента)")
        return False
    # IPv6 (если включён)
    state = awgs_state_load()
    client_ipv6 = ""
    if state.get("allow_ipv6_tunnel"):
        client_ipv6 = awgs_state_next_ipv6()
        if not client_ipv6:
            client_ipv6 = ""

    # PresharedKey (опционально)
    preshared_key = ""
    if psk:
        preshared_key = awgs_generate_preshared_key()
        if not preshared_key:
            warn("Не удалось сгенерировать PresharedKey")
            return False

    # Создаём peer-запись
    peer = {
        "name":            name,
        "client_privkey":  client_priv,
        "client_pubkey":   client_pub,
        "client_ip":       client_ip,
        "client_ipv6":     client_ipv6,
        "preshared_key":   preshared_key,
        "added_at":        datetime.now(timezone.utc).isoformat(),
        "expires_at":      expires_at,
        "dns1":            "1.1.1.1",
        "dns2":            "8.8.8.8",
        "owner_email":     owner_email,
    }

    # Сохраняем в state
    if save_state:
        if not awgs_state_peer_add(peer):
            warn(f"Не удалось сохранить пира в state")
            return False

    # Перестраиваем awg0.conf и применяем
    info("Применение изменений (syncconf)...")
    if apply:
        if not awg_peer_rebuild_conf(apply=True):
            warn("syncconf не удался — откат state")
            if save_state:
                awgs_state_peer_remove(name)
            return False

    # Сохраняем клиентский .conf + показываем QR
    if show_qr:
        result = awgs_qr_export_peer(peer)
        success(f"Пир '{name}' добавлен: {client_ip}")
        if result.get("conf_path"):
            info(f"Конфиг клиента: {result['conf_path']}")
        if result.get("uri_path"):
            info(f"vpn:// URI: {result['uri_path']}")
        if result.get("png_path"):
            info(f"QR-код (PNG, vpn://): {result['png_path']}")
        if result.get("png_conf_path"):
            info(f"QR-код (PNG, .conf): {result['png_conf_path']}")
    else:
        success(f"Пир '{name}' добавлен: {client_ip}")

    return True


# ── REMOVE ──────────────────────────────────────────────────────────────────

def awg_peer_remove(
    name: str,
    apply: bool = True,
    save_state: bool = True,
) -> bool:
    """Удаляет пира по имени."""
    core = _core_module()
    info = core.info
    success = core.success
    warn = core.warn

    peer = awgs_state_peer_find(name)
    if not peer:
        warn(f"Пир '{name}' не найден")
        return False

    if save_state:
        removed = awgs_state_peer_remove(name)
        if not removed:
            warn(f"Не удалось удалить пира из state")
            return False

    # Удаляем файлы клиента
    for ext in (".conf", ".vpnuri", "_qr.png"):
        p = AWGS_KEYS_DIR / f"{name}{ext}"
        p.unlink(missing_ok=True)

    # Перестраиваем конфиг
    if apply:
        info("Применение изменений (syncconf)...")
        awg_peer_rebuild_conf(apply=True)

    success(f"Пир '{name}' удалён")
    return True


# ══════════════════════════════════════════════════════════════════════════════
#  SYNC CONTRACT (v4.25) — для реестра _SYNCABLE_PROTOCOLS в rest_api.py
#
#  AWG (AmneziaWG) — peer-based модель:
#    • Каждый peer = пара ключей (private+public) + IP в подсети AWG.
#    • Identity: peer.name (уникальное, [a-zA-Z0-9_-], не с цифры).
#    • Bridge к VLESS: через peer.owner_email (email VLESS-юзера).
#    • Лимит: 253 пира (по числу IP в /24 подсети).
#
#  Контракт:
#    ensure_user_full(user): если у юзера уже есть peer (по owner_email) —
#      no-op. Иначе генерируем имя пира из email (sanitized), создаём peer
#      с owner_email = user.email.
#    remove_user_full(user): находим peer по owner_email, удаляем.
#    rename_user_full: remove + add (ключи меняются — AWG не поддерживает
#      rename in-place).
# ══════════════════════════════════════════════════════════════════════════════
def _peer_name_from_email(email: str) -> str:
    """Генерирует имя пира из email: alice@x.com → alice.
    Если имя занято — добавляет суффикс _2, _3, ...
    Валидируется через _validate_peer_name."""
    import re as _re
    base = (email or "").split("@")[0].strip().lower()
    # Заменяем недопустимые символы на _
    base = _re.sub(r'[^a-zA-Z0-9_-]', '_', base)
    # Не должно начинаться с цифры
    if base and base[0].isdigit():
        base = "u_" + base
    if not base:
        base = "user"
    # Уникальность
    name = base
    suffix = 2
    while awgs_state_peer_find(name):
        name = f"{base}_{suffix}"
        suffix += 1
        if suffix > 100:
            return ""  # слишком много коллизий
    return name


def is_active() -> bool:
    """True если AWG standalone установлен И сервис запущен."""
    try:
        from chimera.modules.awg_state import awgs_state_is_installed
        if not awgs_state_is_installed():
            return False
        # Проверяем что сервис amneziawg или awg запущен.
        for svc in ("amneziawg", "awg"):
            r = _run(["systemctl", "is-active", svc],
                     capture=True, check=False, quiet=True)
            if r.returncode == 0 and r.stdout.strip() == "active":
                return True
        return False
    except Exception:
        return False


def ensure_user_full(user: dict) -> bool:
    """Создаёт AWG peer для VLESS-юзера (привязка через owner_email).

    Если у юзера уже есть peer (по owner_email) — no-op.
    Иначе генерируем имя из email, создаём peer с owner_email = user.email.
    """
    try:
        from chimera.modules.awg_state import (
            awgs_state_is_installed, awgs_state_find_peer_by_owner,
        )
        if not awgs_state_is_installed():
            return True  # AWG не установлен — пропускаем
        email = user.get("email", "") or ""
        if not email:
            return False
        # Если уже есть peer для этого email — no-op.
        existing = awgs_state_find_peer_by_owner(email)
        if existing:
            return True
        # Генерируем уникальное имя пира.
        name = _peer_name_from_email(email)
        if not name:
            return False
        # Создаём peer с owner_email.
        return awg_peer_add(
            name=name,
            expires="",  # бессрочный
            psk=False,
            apply=True,
            save_state=True,
            show_qr=False,
            owner_email=email,
        )
    except Exception as e:
        try:
            core = _core_module()
            core.warn(f"awg.ensure_user_full: {e}")
        except Exception:
            print(f"awg.ensure_user_full: {e}")
        return False


def ensure_user(name: str) -> bool:
    """Legacy contract — name трактуется как email."""
    return ensure_user_full({"email": name, "name": name})


def remove_user_full(user: dict) -> bool:
    """Удаляет AWG peer по owner_email (email юзера)."""
    try:
        from chimera.modules.awg_state import (
            awgs_state_is_installed, awgs_state_find_peer_by_owner,
        )
        if not awgs_state_is_installed():
            return True
        email = user.get("email", "") or ""
        if not email:
            return False
        peer = awgs_state_find_peer_by_owner(email)
        if not peer:
            return True  # не было — идемпотентность
        return awg_peer_remove(peer.get("name", ""), apply=True, save_state=True)
    except Exception as e:
        try:
            core = _core_module()
            core.warn(f"awg.remove_user_full: {e}")
        except Exception:
            print(f"awg.remove_user_full: {e}")
        return False


def remove_user(name: str) -> bool:
    """Legacy contract — name трактуется как email."""
    return remove_user_full({"email": name, "name": name})


def rename_user_full(old_user: dict, new_user: dict) -> bool:
    """Rename = remove + add (AWG не поддерживает rename in-place —
    ключи пересоздаются, клиент получает новый .conf)."""
    try:
        ok1 = remove_user_full(old_user)
        ok2 = ensure_user_full(new_user)
        return ok1 and ok2
    except Exception:
        return False


def rename_user(old_name: str, new_name: str) -> bool:
    """Legacy contract — имена тракуются как emails."""
    return rename_user_full(
        {"email": old_name, "name": old_name},
        {"email": new_name, "name": new_name},
    )


# ══════════════════════════════════════════════════════════════════════════════
#  SUBSCRIPTION CONTRACT (v4.25) — для реестра _SUBSCRIBABLE_PROTOCOLS
#
#  Возвращает vpn:// URI (Amnezia VPN deep-link) для AWG peer юзера
#  (по owner_email). Используется subscription.py для включения AWG
#  в единую подписку.
# ══════════════════════════════════════════════════════════════════════════════
def get_subscription_uris(user: dict) -> list:
    """Возвращает vpn:// URI для AWG peer юзера (по owner_email).

    Формат — Amnezia VPN deep-link (vpn:// + base64 JSON с конфигом).
    Генерируется через awgs_qr_build_vpn_uri из awg_qr.py.

    Если у юзера нет peer (не синхронизирован) — пустой список.
    """
    try:
        from chimera.modules.awg_state import (
            awgs_state_is_installed, awgs_state_find_peer_by_owner,
            awgs_state_load,
        )
        if not awgs_state_is_installed():
            return []
        email = user.get("email", "") or ""
        if not email:
            return []
        peer = awgs_state_find_peer_by_owner(email)
        if not peer:
            return []
        # Проверяем что peer не истёк.
        expires = peer.get("expires_at", "")
        if expires:
            try:
                from datetime import datetime as _dt, timezone as _tz
                exp_dt = _dt.fromisoformat(expires.replace("Z", "+00:00"))
                if _dt.now(_tz.utc) > exp_dt:
                    return []  # истёк
            except Exception:
                pass  # не парсится — считаем валидным
        # Генерируем vpn:// URI.
        from chimera.modules.awg_qr import awgs_qr_build_vpn_uri
        server_state = awgs_state_load()
        uri = awgs_qr_build_vpn_uri(peer, server_state)
        return [uri] if uri else []
    except Exception:
        return []


# ── LIST ────────────────────────────────────────────────────────────────────

def awg_peer_list(verbose: bool = False, json_output: bool = False) -> None:
    """Показывает список пиров."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_sep = core._box_sep
    _box_bottom = core._box_bottom
    BOLD, NC, CYAN, DIM, YELLOW, GREEN, RED = core.BOLD, core.NC, core.CYAN, core.DIM, core.YELLOW, core.GREEN, core.RED

    state = awgs_state_load()
    peers = state.get("peers", [])

    if json_output:
        # Машиночитаемый JSON
        print(json.dumps({
            "peers": [
                {
                    "name":          p.get("name"),
                    "client_ip":     p.get("client_ip"),
                    "client_ipv6":   p.get("client_ipv6", ""),
                    "added_at":      p.get("added_at"),
                    "expires_at":    p.get("expires_at", ""),
                    "has_psk":       bool(p.get("preshared_key")),
                }
                for p in peers
            ],
            "total": len(peers),
        }, indent=2, ensure_ascii=False))
        return

    print()
    _box_top(f"Клиенты AmneziaWG (всего: {len(peers)})")
    _box_row()
    if not peers:
        _box_row(f"  {DIM}Пока нет клиентов. Добавьте через 'add'.{NC}")
    else:
        _box_row(f"  {BOLD}{'Имя':<20} {'IP':<18} {'Срок':<18} {'PSK':<5}{NC}")
        _box_sep()
        for p in sorted(peers, key=lambda x: x.get("added_at", "")):
            name = p.get("name", "?")[:20]
            ip = p.get("client_ip", "?")
            expires = awgs_expires_humanize(p.get("expires_at", ""))
            # Цвет в зависимости от срока
            if p.get("expires_at"):
                from .awg_expires import awgs_expires_remaining
                rem = awgs_expires_remaining(p.get("expires_at", ""))
                if rem is not None and rem.total_seconds() < 3600:
                    expires_colored = f"{RED}{expires}{NC}"
                elif rem is not None and rem.total_seconds() < 86400:
                    expires_colored = f"{YELLOW}{expires}{NC}"
                else:
                    expires_colored = f"{GREEN}{expires}{NC}"
            else:
                expires_colored = f"{DIM}{expires}{NC}"
            psk_col = "✓" if p.get("preshared_key") else "—"
            _box_row(f"  {CYAN}{name:<20}{NC} {ip:<18} {expires_colored:<35} {psk_col}")
            if verbose:
                pubkey = p.get("client_pubkey", "")[:32] + "..."
                added = p.get("added_at", "")[:19].replace("T", " ")
                _box_row(f"    {DIM}pubkey: {pubkey}{NC}")
                _box_row(f"    {DIM}added:  {added}{NC}")
                if p.get("client_ipv6"):
                    _box_row(f"    {DIM}ipv6:   {p['client_ipv6']}{NC}")
    _box_bottom()


# ── STATS ───────────────────────────────────────────────────────────────────

def awg_peer_stats(json_output: bool = False) -> None:
    """Показывает статистику трафика по клиентам (через `awg show`)."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_sep = core._box_sep
    _box_bottom = core._box_bottom
    BOLD, NC, CYAN, DIM = core.BOLD, core.NC, core.CYAN, core.DIM

    # `awg show` выводит что-то вроде:
    # interface: awg0
    #   peer: <pubkey>
    #     endpoint: 1.2.3.4:54321
    #     allowed ips: 10.66.66.2/32
    #     latest handshake: 5 seconds ago
    #     transfer: 1.23 MiB received, 4.56 MiB sent
    from .awg_apply import awgs_show_dump
    dump = awgs_show_dump()

    state = awgs_state_load()
    peers = state.get("peers", [])

    # Парсим dump
    # Формат: interface\tprivkey\tport\t...
    #          peer\tpubkey\tpsk\tendpoint\tallowed_ips\thandshake\trx\ttx
    peer_stats = {}
    for line in dump:
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] == "peer":
            pubkey = parts[1]
            # Ищем в allowd_ips IP для матчинга с нашим state
            allowed_ips = parts[4] if len(parts) > 4 else ""
            rx_bytes = int(parts[6]) if len(parts) > 6 and parts[6].isdigit() else 0
            tx_bytes = int(parts[7]) if len(parts) > 7 and parts[7].isdigit() else 0
            handshake = parts[5] if len(parts) > 5 else "0"
            # Матчим по pubkey
            for p in peers:
                if p.get("client_pubkey") == pubkey:
                    peer_stats[p.get("name")] = {
                        "rx_bytes":       rx_bytes,
                        "tx_bytes":       tx_bytes,
                        "handshake_ago":  handshake,
                        "endpoint":       parts[3] if len(parts) > 3 else "",
                    }
                    break

    if json_output:
        print(json.dumps({
            "peers": [
                {"name": name, **stats}
                for name, stats in peer_stats.items()
            ]
        }, indent=2, ensure_ascii=False))
        return

    print()
    _box_top(f"Статистика трафика")
    _box_row()
    if not peer_stats:
        _box_row(f"  {DIM}Нет данных. Возможно, ни один клиент не подключался.{NC}")
    else:
        _box_row(f"  {BOLD}{'Имя':<20} {'Rx':<12} {'Tx':<12} {'Handshake':<20}{NC}")
        _box_sep()
        for name, stats in peer_stats.items():
            rx = _format_bytes(stats["rx_bytes"])
            tx = _format_bytes(stats["tx_bytes"])
            hs = _format_handshake(stats["handshake_ago"])
            _box_row(f"  {CYAN}{name[:20]:<20}{NC} {rx:<12} {tx:<12} {hs:<20}")
    _box_bottom()


def _format_bytes(b: int) -> str:
    """Форматирует байты в читаемый вид."""
    if b == 0:
        return "0 B"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PiB"


def awg_collect_peer_traffic() -> dict:
    """
    Собирает raw rx+tx байты per-peer из `awg show all dump` и feed'ит
    в traffic_accounting.record_traffic_sample() с baseline-offset.

    Защищает от сброса счётчика при `systemctl restart awg-quick@awg0`
    или reboot — накопленный трафик сохраняется в state.json.

    Формат `awg show all dump` (TSV, как `wg show all dump`):
      interface-строка: <iface>\t<private-key>\t<listen-port>\t<fwmark>
                        (4 поля)
      peer-строка:      <iface>\t<pubkey>\t<preshared-key>\t<endpoint>\t
                        <allowed-ips>\t<handshake>\t<rx>\t<tx>\t<keepalive>
                        (9 полей)

    Отличаем peer от interface по количеству полей (>= 8 = peer), а НЕ
    по несуществующему литералу "peer" в первом поле — в реальном выводе
    там имя интерфейса (awg0), а не "peer".

    Returns:
      dict — {owner_email: accumulated_bytes} для всех пиров с owner_email.
      Пиры без owner_email (технические) пропускаются.
    """
    try:
        from chimera.modules.traffic_accounting import record_traffic_sample
    except Exception:
        return {}

    try:
        from .awg_apply import awgs_show_dump
        dump = awgs_show_dump()
    except Exception:
        return {}

    state = awgs_state_load()
    peers = state.get("peers", [])

    # Матчим pubkey → peer → owner_email
    result = {}
    for line in dump:
        parts = line.split("\t")
        # peer-строка имеет 9 полей, interface-строка — 4 поля.
        # Берём >= 8 для устойчивости (некоторые версии wg/awg могут
        # не выводить persistent-keepalive = 8 полей вместо 9).
        if len(parts) < 8:
            continue
        # parts[0] = interface name (awg0), parts[1] = pubkey
        pubkey = parts[1]
        # transfer-rx = parts[6], transfer-tx = parts[7]
        rx_bytes = int(parts[6]) if parts[6].isdigit() else 0
        tx_bytes = int(parts[7]) if parts[7].isdigit() else 0
        raw_total = rx_bytes + tx_bytes

        # Находим peer по pubkey
        peer = None
        for p in peers:
            if p.get("client_pubkey") == pubkey:
                peer = p
                break
        if not peer:
            continue

        owner_email = peer.get("owner_email", "")
        if not owner_email:
            # Технический пир без owner_email — пропускаем
            continue

        # Feed в traffic_accounting с baseline-offset
        accumulated = record_traffic_sample(owner_email, "awg", raw_total)
        result[owner_email] = accumulated

    return result


def awg_get_peer_traffic_accumulated(owner_email: str) -> int:
    """
    Возвращает накопленный трафик AWG-пира по owner_email.
    Не делает новый снимок — читает из state.

    Args:
      owner_email: email VLESS-пользователя-владельца пира

    Returns:
      int — accumulated bytes (или 0 если записей нет)
    """
    try:
        from chimera.modules.traffic_accounting import get_accumulated_bytes
        return get_accumulated_bytes(owner_email, "awg")
    except Exception:
        return 0


def _format_handshake(ts_str: str) -> str:
    """Форматирует timestamp handshake в человекочитаемый вид."""
    if not ts_str or ts_str == "0":
        return "никогда"
    try:
        ts = int(ts_str)
        ago = int(time.time()) - ts
        if ago < 60:
            return f"{ago} сек назад"
        if ago < 3600:
            return f"{ago // 60} мин назад"
        if ago < 86400:
            return f"{ago // 3600} ч назад"
        return f"{ago // 86400} дн назад"
    except (ValueError, TypeError):
        return ts_str


# ── REGEN ───────────────────────────────────────────────────────────────────

def awg_peer_regen(name: str) -> bool:
    """Перегенерирует ключи пира (IP сохраняется)."""
    core = _core_module()
    info = core.info
    success = core.success
    warn = core.warn

    peer = awgs_state_peer_find(name)
    if not peer:
        warn(f"Пир '{name}' не найден")
        return False

    info(f"Перегенерация ключей для '{name}'...")
    new_priv, new_pub = awgs_generate_keys()
    if not new_priv or not new_pub:
        warn("Не удалось сгенерировать новые ключи")
        return False

    # Обновляем state (IP сохраняем)
    awgs_state_peer_update(
        name,
        client_privkey=new_priv,
        client_pubkey=new_pub,
    )

    # Перестраиваем конфиг
    awg_peer_rebuild_conf(apply=True)

    # Перегенерируем клиентские файлы
    updated_peer = awgs_state_peer_find(name)
    if updated_peer:
        awgs_qr_export_peer(updated_peer)

    success(f"Ключи для '{name}' перегенерированы")
    return True


# ── MODIFY ──────────────────────────────────────────────────────────────────

def awg_peer_modify(name: str, param: str, value: str) -> bool:
    """
    Изменяет параметр пира.
    Поддерживаемые параметры: dns1, dns2, expires_at, owner_email
    """
    core = _core_module()
    warn = core.warn

    peer = awgs_state_peer_find(name)
    if not peer:
        warn(f"Пир '{name}' не найден")
        return False

    if param in ("dns1", "dns2"):
        # Простая валидация IP
        import re
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", value):
            warn(f"Невалидный IP: {value}")
            return False
        awgs_state_peer_update(name, **{param: value})
    elif param == "expires_at":
        if not value:
            # Снимаем срок
            awgs_state_peer_update(name, expires_at="")
        else:
            delta = awgs_expires_parse(value)
            if delta is None:
                warn(f"Невалидный duration: {value}")
                return False
            awgs_state_peer_update(name, expires_at=awgs_expires_compute_iso(delta))
    elif param == "owner_email":
        # value="" — снять привязку (допустимо).
        # value=непустое — простая валидация формата email.
        # НЕ проверяем существование такого VLESS-юзера физически —
        # админ может привязать пира к любому email.
        value = (value or "").strip()
        if not _validate_email(value):
            warn(f"Невалидный owner_email='{value}'")
            return False
        awgs_state_peer_update(name, owner_email=value)
    else:
        warn(f"Неподдерживаемый параметр: {param}. "
             f"Допустимые: dns1, dns2, expires_at, owner_email")
        return False

    # Перегенерируем клиентский конфиг
    updated_peer = awgs_state_peer_find(name)
    if updated_peer:
        awgs_qr_export_peer(updated_peer)

    return True


# ── TUI-МЕНЮ ────────────────────────────────────────────────────────────────

def do_manage_awg_peers() -> None:
    """TUI-меню управления пирами."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    warn = core.warn
    info = core.info
    CYAN, NC, BLUE = core.CYAN, core.NC, core.BLUE

    while True:
        import os
        os.system("clear")
        print()
        # Сначала показываем список
        awg_peer_list()
        print()
        _box_top(f"Управление клиентами")
        _box_row()
        _box_item("1", f"Добавить клиента")
        _box_item("2", f"Удалить клиента")
        _box_item("3", f"Перегенерировать ключи (regen)")
        _box_item("4", f"Статистика трафика")
        _box_item("5", f"Изменить параметр (dns/expires)")
        _box_item("6", f"Показать QR-код клиента")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            _awgs_peers_menu_add()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            name = input(f"{CYAN}Имя клиента для удаления: {NC}").strip()
            if name:
                confirm = input(f"{core.YELLOW}Удалить '{name}'? [y/N]: {NC}").strip().lower()
                if confirm in ("y", "yes", "д", "да"):
                    awg_peer_remove(name)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            name = input(f"{CYAN}Имя клиента для regen: {NC}").strip()
            if name:
                awg_peer_regen(name)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            awg_peer_stats()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            name = input(f"{CYAN}Имя клиента: {NC}").strip()
            param = input(f"{CYAN}Параметр (dns1/dns2/expires_at/owner_email): {NC}").strip()
            value = input(f"{CYAN}Значение (пусто = снять expires_at/owner_email): {NC}").strip()
            if name and param:
                awg_peer_modify(name, param, value)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "6":
            name = input(f"{CYAN}Имя клиента: {NC}").strip()
            if name:
                peer = awgs_state_peer_find(name)
                if peer:
                    awgs_qr_export_peer(peer)
                else:
                    warn(f"Пир '{name}' не найден")
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch in ("q", ""):
            break


def _awgs_peers_menu_add() -> None:
    """Подменю добавления клиента."""
    core = _core_module()
    info = core.info
    warn = core.warn
    CYAN, NC = core.CYAN, core.NC

    print()
    name = input(f"{CYAN}Имя клиента (1-32 симв, [a-zA-Z0-9_-]): {NC}").strip()
    if not name:
        return

    expires = input(f"{CYAN}Срок действия (1h/12h/7d/30d/4w, пусто = бессрочно): {NC}").strip()
    psk_ch = input(f"{CYAN}Сгенерировать PresharedKey? [y/N]: {NC}").strip().lower()
    psk = psk_ch in ("y", "yes", "д", "да")

    print()
    awg_peer_add(name, expires=expires, psk=psk)
