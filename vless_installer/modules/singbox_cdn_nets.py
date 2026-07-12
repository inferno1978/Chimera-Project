"""
vless_installer/modules/singbox_cdn_nets.py
───────────────────────────────────────────────────────────────────────────────
CDN IP-allowlist для VLESS-WS-CDN (v4.23.1).

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

  Bunny.net: https://docs.bunny.net/magic-containers/ip-addresses
    HTML-страница с IP-адресами (немного, ~3 IP). Парсим regex'ом.
    Если страница изменится — fetch вернёт пустой список, warn будет показан.

Архитектура (по образцу tg_nets.py + ingress_geoip.py):
  1. fetch_cdn_nets(provider) — live-fetch через urllib.request
  2. apply_cdn_allowlist(provider, port) — ipset + iptables
  3. remove_cdn_allowlist(port) — cleanup iptables + ipset

iptables-подход (аналог ingress_geoip.py):
  - ipset create singbox_cdn_allowlist_<port> hash:net
  - ipset add singbox_cdn_allowlist_<port> <cidr> (для каждого CIDR)
  - iptables -A INPUT -p tcp --dport <port> \
      -m set ! --match-set singbox_cdn_allowlist_<port> src -j DROP
    (DROP всего, что НЕ из CDN-диапазона)
  - comment tag: "singbox-cdn-allowlist-<port>" для безопасного удаления

Границы: только vless_ws_cdn listen_port. НЕ трогает правила других протоколов.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import ipaddress
import json
import re
import urllib.request
from pathlib import Path
from typing import Optional

from vless_installer.modules.singbox_common import (
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
    info, success, warn, error, log_to_file,
    _run, CDN_PROVIDERS,
)


# ============================================================================
#  Константы
# ============================================================================
_IPSET_PREFIX = "singbox_cdn_allowlist"
_IPTABLES_COMMENT_PREFIX = "singbox-cdn-allowlist"
_HTTP_TIMEOUT = 15
_UA = "VLESS-Ultimate-Installer"


def _ipset_name(port: int) -> str:
    """Имя ipset для данного порта."""
    return f"{_IPSET_PREFIX}_{port}"


def _iptables_comment(port: int) -> str:
    """Comment-tag для iptables-правил (для безопасного удаления)."""
    return f"{_IPTABLES_COMMENT_PREFIX}-{port}"


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
        # Cloudflare: одна CIDR на строку
        for line in text.splitlines():
            line = line.strip()
            if line and _valid_cidr(line):
                cidrs.append(line)

    elif fmt == "json_addresses":
        # Gcore: {"addresses": ["ip/32", ...]}
        try:
            data = json.loads(text)
            for addr in data.get("addresses", []):
                if _valid_cidr(addr):
                    cidrs.append(addr)
        except json.JSONDecodeError as e:
            return [], f"JSON parse error: {e}"

    elif fmt == "html_scrape":
        # Bunny.net: HTML-страница, ищем IP-адреса regex'ом
        # Сначала ищем CIDR (xxx.xxx.xxx.xxx/xx), потом plain IP
        found_cidrs = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b', text)
        for c in found_cidrs:
            if _valid_cidr(c):
                cidrs.append(c)
        if not cidrs:
            # Fallback: plain IP → добавляем как /32
            found_ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)
            # Дедупликация
            seen = set()
            for ip in found_ips:
                if ip not in seen and _valid_cidr(f"{ip}/32"):
                    cidrs.append(f"{ip}/32")
                    seen.add(ip)

    else:
        return [], f"Неизвестный формат IP: {fmt}"

    # Дедупликация
    cidrs = list(dict.fromkeys(cidrs))
    return cidrs, f"{len(cidrs)} CIDR из {url}"


# ============================================================================
#  apply_cdn_allowlist — ipset + iptables
# ============================================================================
def apply_cdn_allowlist(cdn_provider: str, port: int) -> bool:
    """Применяет CDN allowlist на listen_port.

    1. Fetch CIDRs через fetch_cdn_nets()
    2. Создаёт ipset singbox_cdn_allowlist_<port>
    3. Добавляет все CIDR в ipset
    4. Добавляет iptables rule: DROP всего, что НЕ из CDN-диапазона

    Returns:
      True если allowlist применён.
      False если fetch провалился или iptables недоступен.
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

    ipset = _ipset_name(port)
    comment = _iptables_comment(port)

    # 2. Создаём/очищаем ipset
    _run(["ipset", "create", ipset, "hash:net", "maxelem", "100000", "-exist"],
         quiet=True)
    _run(["ipset", "flush", ipset], quiet=True)

    # 3. Добавляем CIDR через ipset restore (эффективнее, чем по одному)
    restore_lines = [f"add {ipset} {c}" for c in cidrs if _valid_cidr(c)]
    if not restore_lines:
        warn("Нет валидных CIDR для добавления в ipset")
        return False

    # Записываем во временный файл для ipset restore
    tmp_file = Path(f"/tmp/_singbox_cdn_ipset_{port}.restore")
    try:
        tmp_file.write_text("\n".join(restore_lines) + "\n")
        r = _run(["ipset", "restore", "-!", "-f", str(tmp_file)],
                 capture=True, quiet=True)
        if r.returncode != 0:
            warn(f"ipset restore failed: {r.stderr[:200] if r.stderr else 'unknown'}")
    finally:
        tmp_file.unlink(missing_ok=True)

    # 4. iptables: DROP всего, что НЕ из CDN-диапазона на этот порт
    # Сначала удаляем старое правило (если есть) — idempotent
    _run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
          "-m", "set", "!", "--match-set", ipset, "src", "-j", "DROP",
          "-m", "comment", "--comment", comment],
         check=False, quiet=True)

    r = _run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port),
              "-m", "set", "!", "--match-set", ipset, "src", "-j", "DROP",
              "-m", "comment", "--comment", comment],
             check=False, quiet=True)
    if r.returncode != 0:
        warn(f"iptables rule failed: {r.stderr[:200] if r.stderr else 'unknown'}")
        warn(f"Порт {port} останется ОТКРЫТ всем интернету — нет allowlist!")
        return False

    success(f"CDN allowlist применён: {meta['display_name']} → порт {port} защищён")
    log_to_file("INFO", f"CDN allowlist applied: {cdn_provider} on port {port} "
                        f"({len(cidrs)} CIDR)")
    return True


# ============================================================================
#  remove_cdn_allowlist — cleanup
# ============================================================================
def remove_cdn_allowlist(port: int) -> bool:
    """Удаляет CDN allowlist для данного порта.

    1. Удаляет iptables rule
    2. Уничтожает ipset

    Returns:
      True при успехе (даже если правил не было — idempotent).
    """
    ipset = _ipset_name(port)
    comment = _iptables_comment(port)

    # 1. Удаляем iptables rule
    _run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
          "-m", "set", "!", "--match-set", ipset, "src", "-j", "DROP",
          "-m", "comment", "--comment", comment],
         check=False, quiet=True)

    # 2. Уничтожаем ipset
    _run(["ipset", "destroy", ipset], check=False, quiet=True)

    log_to_file("INFO", f"CDN allowlist removed from port {port}")
    return True


# ============================================================================
#  get_cdn_allowlist_status — для TUI
# ============================================================================
def get_cdn_allowlist_status(port: int) -> dict:
    """Возвращает статус allowlist для порта."""
    ipset = _ipset_name(port)
    comment = _iptables_comment(port)

    # Проверяем iptables rule
    r = _run(["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(port),
              "-m", "set", "!", "--match-set", ipset, "src", "-j", "DROP",
              "-m", "comment", "--comment", comment],
             quiet=True)
    iptables_active = (r.returncode == 0)

    # Проверяем ipset
    r2 = _run(["ipset", "list", ipset], capture=True, quiet=True)
    ipset_active = (r2.returncode == 0)
    ipset_count = 0
    if ipset_active and r2.stdout:
        # Парсим количество записей
        for line in r2.stdout.splitlines():
            if line.startswith("Number of entries:"):
                try:
                    ipset_count = int(line.split(":")[1].strip())
                except (ValueError, IndexError):
                    pass

    return {
        "port": port,
        "iptables_rule_active": iptables_active,
        "ipset_active": ipset_active,
        "ipset_entries": ipset_count,
        "ipset_name": ipset,
    }
