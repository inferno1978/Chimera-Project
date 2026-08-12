"""
chimera/modules/singbox_cdn_nets.py
───────────────────────────────────────────────────────────────────────────────
CDN IP-allowlist для VLESS-WS-CDN (v4.23.1, fixed v4.23.2).

Защита origin от прямого доступа: listen_port vless_ws_cdn открыт ТОЛЬКО
для IP-диапазонов активного CDN-провайдера. Без этого origin достижим
напрямую по IP:port, что ломает заявленную защиту ("заблокировать CDN =
заблокировать всё").

Источники IP-диапазонов (live-fetch, не хардкод — IP меняются):

  Cloudflare: https://www.cloudflare.com/ips-v4
    Plain text, одна CIDR на строку. Официальный, актуальный, без auth.

  Gcore: https://api.gcore.com/cdn/public-ip-list
    JSON {"addresses": ["ip/32", ...]}. Без auth (подтверждено в документации:
    "This request does not require authorization").

  Bunny.net: https://bunnycdn.com/api/system/edgeserverlist/plain
    Plain text, один IPv4 на строку БЕЗ /32 суффикса (добавляем /32 при парсинге).
    IPv6: https://bunnycdn.com/api/system/edgeserverlist/IPv6 — JSON array,
    но listen = "0.0.0.0" (IPv4 only) → IPv6 игнорируем.

Архитектура (по образцу tg_nets.py + ingress_geoip.py + ipset_persist.py):
  1. fetch_cdn_nets(provider) — live-fetch через urllib.request
  2. apply_cdn_allowlist(provider, port) — nft set + nft rule + persist
  3. remove_cdn_allowlist(port) — cleanup nft rule + nft set + persist

nftables-подход (мигрировано с ipset/iptables, этап 1.7):
  - nft set inet chimera singbox_cdn_<port> { type ipv4_addr; flags interval; size 100000; }
  - nft add element inet chimera singbox_cdn_<port> { cidr1, cidr2, ... } (atomic swap)
  - nft insert rule inet chimera input tcp dport <port> ip saddr != @singbox_cdn_<port> drop
    (DROP всего, что НЕ из CDN-диапазона, В НАЧАЛЕ цепочки INPUT — insert position=1)
  - comment tag: "chimera-singbox-cdn-<port>" для безопасного удаления
    (соответствует COMMENT_SINGBOX_CDN_PREFIX из nft_constants)

Persistence (этап 1.7):
  - nft_persist() → /etc/nftables.conf (замена ipset save + iptables-save)
  - systemd unit singbox-cdn-ipset-restore.service сохранён для обратной
    совместимости, но теперь обновляется для запуска `nft -f /etc/nftables.conf`
    через стандартный nftables.service (если ещё не включён).

Границы: только vless_ws_cdn listen_port. НЕ трогает правила других протоколов.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import textwrap
import urllib.request
from pathlib import Path
from typing import Optional

from chimera.modules.singbox_common import (
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
    info, success, warn, error, log_to_file,
    _run, CDN_PROVIDERS,
)
# nftables — централизованная обёртка (этап 1.7 миграции).
from chimera.modules.nft_common import (
    nft_set_create, nft_set_exists, nft_set_atomic_swap,
    nft_set_destroy, nft_set_count, nft_set_list_elements,
    nft_rule_add, nft_rule_exists, nft_rule_delete_by_comment,
    nft_persist, nft_persist_enable_systemd, _nft_available,
)
from chimera.modules.nft_constants import (
    NFT_TABLE_NAME, NFT_TABLE_FAMILY, NFT_CHAIN_INPUT,
    COMMENT_SINGBOX_CDN_PREFIX, singbox_cdn_set_name, NFT_PERSIST_FILE,
)


# ============================================================================
#  Константы
# ============================================================================
_IPSET_PREFIX = "singbox_cdn_allowlist"  # legacy alias (для backward compat с state)
_IPTABLES_COMMENT_PREFIX = "singbox-cdn-allowlist"  # legacy alias
_HTTP_TIMEOUT = 15
_UA = "Chimera-Project"

# Persistence paths (по образцу ipset_persist.py — сохранены для compat)
_IPSET_CONF = Path("/etc/ipset-singbox-cdn.conf")  # legacy, не используется после миграции
_RESTORE_SVC = Path("/etc/systemd/system/singbox-cdn-ipset-restore.service")
_RESTORE_LOG = Path("/var/log/singbox-cdn-ipset-restore.log")


def _ipset_name(port: int) -> str:
    """Имя nft set для данного порта (мигрировано с ipset <port>).

    Возвращает singbox_cdn_<port> (через singbox_cdn_set_name из nft_constants).
    Имя функции сохранено для совместимости со старыми callers и state.json.
    """
    return singbox_cdn_set_name(port)


def _iptables_comment(port: int) -> str:
    """Comment-tag для nft-правил (для безопасного удаления).

    Возвращает chimera-singbox-cdn-<port> (через COMMENT_SINGBOX_CDN_PREFIX).
    Имя функции сохранено для совместимости со старыми callers.
    """
    return f"{COMMENT_SINGBOX_CDN_PREFIX}{port}"


# ============================================================================
#  HTTP fetch (по образцу tg_nets.py::_http_get)
# ============================================================================
def _http_get(url: str, timeout: int = _HTTP_TIMEOUT) -> Optional[bytes]:
    """GET запрос. Возвращает None при ошибке."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception:
        return None


# ============================================================================
#  Валидация CIDR
# ============================================================================
def _valid_cidr(cidr: str) -> bool:
    """Проверяет, что строка — валидный CIDR."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except (ValueError, TypeError):
        return False


# ============================================================================
#  fetch_cdn_nets — live-fetch IP-диапазонов CDN
# ============================================================================
def fetch_cdn_nets(cdn_provider: str) -> tuple[list[str], str]:
    """Live-fetch IP-диапазонов CDN-провайдера.

    Args:
      cdn_provider: "cloudflare" | "gcore" | "bunny"

    Returns:
      (cidrs, status_msg) — список валидных CIDR и строка статуса.
      При ошибке — ([], "описание ошибки").
    """
    meta = CDN_PROVIDERS.get(cdn_provider)
    if not meta:
        return [], f"Неизвестный CDN-провайдер: {cdn_provider}"

    url = meta.get("ip_source", "")
    fmt = meta.get("ip_format", "")
    if not url or not fmt:
        return [], f"Для {cdn_provider} не настроен источник IP-диапазонов"

    raw = _http_get(url)
    if raw is None:
        return [], f"Не удалось получить {url}"

    text = raw.decode("utf-8", errors="replace")
    cidrs: list[str] = []

    if fmt == "plaintext":
        # Cloudflare: CIDR на строку (xxx.xxx.xxx.xxx/xx)
        # Bunny: plain IP на строку (xxx.xxx.xxx.xxx, БЕЗ /32) → добавляем /32
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if "/" in line:
                # Уже CIDR — Cloudflare
                if _valid_cidr(line):
                    cidrs.append(line)
            else:
                # Plain IP — Bunny CDN edge servers → добавляем /32
                if _valid_cidr(f"{line}/32"):
                    cidrs.append(f"{line}/32")

    elif fmt == "json_addresses":
        # Gcore: {"addresses": ["ip/32", ...]}
        try:
            data = json.loads(text)
            for addr in data.get("addresses", []):
                if _valid_cidr(addr):
                    cidrs.append(addr)
        except json.JSONDecodeError as e:
            return [], f"JSON parse error: {e}"

    else:
        return [], f"Неизвестный формат IP: {fmt}"

    # Дедупликация
    cidrs = list(dict.fromkeys(cidrs))
    return cidrs, f"{len(cidrs)} CIDR из {url}"


# ============================================================================
#  Persistence helpers (этап 1.7: миграция с ipset на nft_persist)
# ============================================================================
def _ipset_save_port(port: int) -> bool:
    """Сохраняет nftables ruleset в /etc/nftables.conf (этап 1.7 миграции).

    Бывшая функция сохраняла ipset в /etc/ipset-singbox-cdn.conf через
    `ipset save`. Теперь этот шаг не нужен — nft_persist() сохраняет весь
    ruleset (включая nft set singbox_cdn_<port>) в /etc/nftables.conf одним
    вызовом. Имя функции сохранено для совместимости со старыми callers.
    """
    try:
        nft_persist(NFT_PERSIST_FILE)
        nft_persist_enable_systemd()
        return True
    except Exception as e:
        warn(f"Не удалось сохранить nftables ruleset: {e}")
        return False


def _ipset_remove_from_persist(port: int) -> None:
    """Обновляет persisted state после удаления CDN allowlist для порта.

    Бывшая функция удаляла записи для данного ipset из /etc/ipset-singbox-cdn.conf.
    Теперь просто перезаписывает /etc/nftables.conf через nft_persist() —
    в нём уже нет удалённого nft set (мы его уничтожили в remove_cdn_allowlist).
    """
    try:
        nft_persist(NFT_PERSIST_FILE)
    except Exception:
        pass


def _iptables_persist() -> None:
    """Сохраняет nftables через nft_persist() (этап 1.7 миграции).

    Заменяет: proto_ipt_persist() (netfilter-persistent save / iptables-save).
    Теперь: nft_persist() → /etc/nftables.conf + nft_persist_enable_systemd().
    """
    try:
        nft_persist(NFT_PERSIST_FILE)
        nft_persist_enable_systemd()
    except Exception:
        pass


def _ipset_restore_unit_install() -> None:
    """Устанавливает systemd unit для restore nftables ruleset при boot.

    После миграции (этап 1.7) этот unit делегирует в стандартный nftables.service
    — он читает /etc/nftables.conf и восстанавливает ВСЕ правила Chimera.
    Legacy ipset-based restore больше не используется, но unit сохранён
    для обратной совместимости (старые системы могут ссылаться на него).
    """
    if _RESTORE_SVC.exists():
        return  # уже установлен
    _RESTORE_SVC.write_text(textwrap.dedent(f"""\
        [Unit]
        Description=Restore sing-box CDN allowlist (via nftables.service, VLESS Ultimate)
        DefaultDependencies=no
        Before=sing-box.service
        Before=netfilter-persistent.service
        After=local-fs.target
        ConditionPathExists={NFT_PERSIST_FILE}

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        # Этап 1.7:restore теперь через стандартный `nft -f /etc/nftables.conf`,
        # который читает весь nftables ruleset (включая singbox_cdn_<port> set).
        # Legacy ipset restore удалён — он больше не нужен.
        ExecStart=/bin/bash -c 'nft -f {NFT_PERSIST_FILE} 2>&1 | \\
            tee -a {_RESTORE_LOG} && \\
            echo "singbox-cdn nft ruleset restored" \\
            >> {_RESTORE_LOG}'
        StandardOutput=journal
        StandardError=journal

        [Install]
        WantedBy=multi-user.target
    """))
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    subprocess.run(["systemctl", "enable", "singbox-cdn-ipset-restore.service"],
                   capture_output=True)


# ============================================================================
#  apply_cdn_allowlist — nft set + nft rule + persist (этап 1.7)
# ============================================================================
def apply_cdn_allowlist(cdn_provider: str, port: int) -> bool:
    """Применяет CDN allowlist на listen_port.

    Мигрировано с ipset/iptables на nftables (этап 1.7). Шаги:
      1. Fetch CIDRs через fetch_cdn_nets()
      2. Создаёт nft set singbox_cdn_<port> (type ipv4_addr, flags interval)
      3. Atomic swap — заменяет содержимое set на новый список CIDR
      4. Добавляет nft rule в начало INPUT: DROP всего, что НЕ из CDN-диапазона
         (insert position=1, чтобы DROP был раньше других ACCEPT-правил)
      5. Persist — nft_persist() + nft_persist_enable_systemd()

    Returns:
      True если allowlist применён.
      False если fetch провалился или nft недоступен.
      В случае False вызывается warn() — НЕ молчит.
    """
    meta = CDN_PROVIDERS.get(cdn_provider)
    if not meta:
        error(f"Неизвестный CDN-провайдер: {cdn_provider}")
        return False

    # 1. Fetch CIDRs
    cidrs, status = fetch_cdn_nets(cdn_provider)
    if not cidrs:
        warn(f"Не удалось получить IP-диапазоны CDN {meta['display_name']}: {status}")
        warn(f"Порт {port} останется ОТКРЫТ всем интернету — нет allowlist!")
        return False

    info(f"CDN allowlist: {meta['display_name']} → {len(cidrs)} CIDR на порт {port}")

    ipset = _ipset_name(port)  # теперь это singbox_cdn_<port>
    comment = _iptables_comment(port)  # теперь это chimera-singbox-cdn-<port>

    # 2. Создаём nft set singbox_cdn_<port> (type ipv4_addr; flags interval; size 100000;)
    if not _nft_available():
        warn("nft binary не установлен — CDN allowlist не может быть применён")
        return False
    nft_set_create(
        ipset, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY,
        set_type="ipv4_addr", flags=["interval"], maxelem=100000,
    )

    # 3. Atomic swap содержимого set (flush + add element в одной транзакции)
    valid_cidrs = [c for c in cidrs if _valid_cidr(c)]
    if not valid_cidrs:
        warn("Нет валидных CIDR для добавления в nft set")
        return False
    nft_set_atomic_swap(
        ipset, valid_cidrs, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY,
    )

    # 4. nft rule: DROP всего, что НЕ из CDN-диапазона на этот порт
    # Сначала удаляем старое правило (если есть) — idempotent
    nft_rule_delete_by_comment(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        comment=comment, family=NFT_TABLE_FAMILY, max_iterations=10,
    )
    # Insert на позицию 1 — правило всегда первое в INPUT
    # nft spec: tcp dport <port> ip saddr != @<set> drop
    rule_spec = f"tcp dport {port} ip saddr != @{ipset} drop"
    from chimera.modules.nft_common import nft_rule_insert
    r_ok = nft_rule_insert(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        rule_spec=rule_spec, family=NFT_TABLE_FAMILY,
        comment=comment,
    )
    if not r_ok:
        warn(f"nft rule failed для порта {port}")
        warn(f"Порт {port} останется ОТКРЫТ всем интернету — нет allowlist!")
        return False

    # 5. Persist — nft list ruleset > /etc/nftables.conf + enable nftables.service
    _ipset_save_port(port)
    _ipset_restore_unit_install()
    _iptables_persist()

    success(f"CDN allowlist применён: {meta['display_name']} → порт {port} защищён")
    log_to_file("INFO", f"CDN allowlist applied: {cdn_provider} on port {port} "
                        f"({len(cidrs)} CIDR)")
    return True


# ============================================================================
#  remove_cdn_allowlist — cleanup + persist (этап 1.7)
# ============================================================================
def remove_cdn_allowlist(port: int) -> bool:
    """Удаляет CDN allowlist для данного порта.

    Мигрировано с ipset/iptables на nftables (этап 1.7). Шаги:
      1. Удаляет nft rule (через nft_rule_delete_by_comment)
      2. Уничтожает nft set (через nft_set_destroy)
      3. Обновляет persisted state (nft_persist перезаписывает /etc/nftables.conf)

    Returns:
      True при успехе (даже если правил не было — idempotent).
    """
    ipset = _ipset_name(port)  # singbox_cdn_<port>
    comment = _iptables_comment(port)  # chimera-singbox-cdn-<port>

    # 1. Удаляем nft rule (по comment-tag)
    nft_rule_delete_by_comment(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        comment=comment, family=NFT_TABLE_FAMILY, max_iterations=10,
    )

    # 2. Уничтожаем nft set
    nft_set_destroy(ipset, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY)

    # 3. Обновляем persisted state
    _ipset_remove_from_persist(port)
    _iptables_persist()

    log_to_file("INFO", f"CDN allowlist removed from port {port}")
    return True


# ============================================================================
#  get_cdn_allowlist_status — для TUI (этап 1.7: nft-based)
# ============================================================================
def get_cdn_allowlist_status(port: int) -> dict:
    """Возвращает статус allowlist для порта (мигрировано с ipset/iptables на nftables).
    """
    ipset = _ipset_name(port)  # singbox_cdn_<port>
    comment = _iptables_comment(port)  # chimera-singbox-cdn-<port>

    # Проверяем nft rule через nft_rule_exists (по comment-tag)
    nft_rule_active = nft_rule_exists(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        comment=comment, family=NFT_TABLE_FAMILY,
    )

    # Проверяем nft set и считаем его элементы
    nft_set_active = nft_set_exists(ipset, table=NFT_TABLE_NAME,
                                     family=NFT_TABLE_FAMILY)
    nft_set_entries = 0
    if nft_set_active:
        nft_set_entries = nft_set_count(ipset, table=NFT_TABLE_NAME,
                                         family=NFT_TABLE_FAMILY)

    return {
        "port": port,
        "iptables_rule_active": nft_rule_active,  # legacy field name (для TUI compat)
        "nft_rule_active": nft_rule_active,
        "ipset_active": nft_set_active,  # legacy field name
        "nft_set_active": nft_set_active,
        "ipset_entries": nft_set_entries,  # legacy field name
        "nft_set_entries": nft_set_entries,
        "ipset_name": ipset,  # legacy field name (для TUI display)
        "nft_set_name": ipset,
    }
