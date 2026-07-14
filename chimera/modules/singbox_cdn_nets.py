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
  2. apply_cdn_allowlist(provider, port) — ipset + iptables + persist
  3. remove_cdn_allowlist(port) — cleanup iptables + ipset + persist

iptables-подход (v4.23.2: -I INPUT 1 вместо -A, по образцу fptn.py:494):
  - ipset create singbox_cdn_allowlist_<port> hash:net
  - ipset add singbox_cdn_allowlist_<port> <cidr> (для каждого CIDR)
  - iptables -I INPUT 1 -p tcp --dport <port> \
      -m set ! --match-set singbox_cdn_allowlist_<port> src -j DROP
    (DROP всего, что НЕ из CDN-диапазона, В НАЧАЛЕ цепочки INPUT)
  - comment tag: "singbox-cdn-allowlist-<port>" для безопасного удаления

Persistence (v4.23.2, по образцу ipset_persist.py + proto_common.py):
  - ipset save → /etc/ipset-singbox-cdn.conf
  - iptables persist через proto_ipt_persist() (netfilter-persistent или iptables-save)
  - systemd unit singbox-cdn-ipset-restore.service для restore при boot

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


# ============================================================================
#  Константы
# ============================================================================
_IPSET_PREFIX = "singbox_cdn_allowlist"
_IPTABLES_COMMENT_PREFIX = "singbox-cdn-allowlist"
_HTTP_TIMEOUT = 15
_UA = "Chimera-Project"

# Persistence paths (по образцу ipset_persist.py)
_IPSET_CONF = Path("/etc/ipset-singbox-cdn.conf")
_RESTORE_SVC = Path("/etc/systemd/system/singbox-cdn-ipset-restore.service")
_RESTORE_LOG = Path("/var/log/singbox-cdn-ipset-restore.log")


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
#  Persistence helpers (v4.23.2, по образцу ipset_persist.py)
# ============================================================================
def _ipset_save_port(port: int) -> bool:
    """Сохраняет ipset для данного порта в /etc/ipset-singbox-cdn.conf.

    По образцу ipset_persist.py::ipset_save(), но для singbox_cdn_allowlist_<port>.
    Дописывает в общий файл (не перезаписывает чужие ipset-записи).
    """
    ipset = _ipset_name(port)
    r = subprocess.run(["ipset", "save", ipset], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        return False

    # Читаем существующий файл и фильтруем старые записи для этого ipset
    existing = ""
    if _IPSET_CONF.exists():
        existing = _IPSET_CONF.read_text()
        # Удаляем старые строки для этого ipset
        lines = [l for l in existing.splitlines()
                 if not l.startswith(f"add {ipset} ") and not l.startswith(f"create {ipset} ")]
        existing = "\n".join(lines) + "\n" if lines else ""

    content = existing + r.stdout.strip() + "\n"
    try:
        _IPSET_CONF.parent.mkdir(parents=True, exist_ok=True)
        _IPSET_CONF.write_text(content)
        _IPSET_CONF.chmod(0o600)
    except Exception as e:
        warn(f"Не удалось записать {_IPSET_CONF}: {e}")
        return False
    return True


def _ipset_remove_from_persist(port: int) -> None:
    """Удаляет ipset для данного порта из персистентного файла."""
    ipset = _ipset_name(port)
    if not _IPSET_CONF.exists():
        return
    content = _IPSET_CONF.read_text()
    lines = [l for l in content.splitlines()
             if not l.startswith(f"add {ipset} ") and not l.startswith(f"create {ipset} ")]
    try:
        if lines:
            _IPSET_CONF.write_text("\n".join(lines) + "\n")
        else:
            _IPSET_CONF.unlink()
    except Exception:
        pass


def _iptables_persist() -> None:
    """Сохраняет iptables через proto_ipt_persist() (netfilter-persistent или iptables-save).

    Переиспользует существующий хелпер из proto_common.py — НЕ изобретает новый механизм.
    """
    try:
        from chimera.modules.proto_common import proto_ipt_persist
        proto_ipt_persist()
    except ImportError:
        # Fallback: прямой iptables-save
        import shutil
        if shutil.which("netfilter-persistent"):
            subprocess.run(["netfilter-persistent", "save"],
                           capture_output=True, text=True)
        else:
            rules_dir = Path("/etc/iptables")
            rules_dir.mkdir(parents=True, exist_ok=True)
            r = subprocess.run(["iptables-save"], capture_output=True, text=True)
            if r.returncode == 0 and r.stdout:
                (rules_dir / "rules.v4").write_text(r.stdout)


def _ipset_restore_unit_install() -> None:
    """Устанавливает systemd unit для restore ipset при boot.

    По образцу ipset_persist.py::ipset_restore_unit_install(), но с другим
    именем юнита (singbox-cdn-ipset-restore) чтобы не конфликтовать с xray-ipset-restore.

    v4.23.3: Before=netfilter-persistent.service добавлено.
    v4.23.4: Убран After=network-pre.target — создавал ordering cycle
    (Debian bug #832802). Наш юнит After=network-pre.target, но
    netfilter-persistent Before=network-pre.target → транзитивный цикл.
    systemd резолвит такие циклы, молча выкидывая одно из рёбер — какое
    именно выживет не гарантировано, Before=netfilter-persistent мог вылететь.

    Решение v4.23.4:
    - Убрать After=network-pre.target — ipset restore чисто локальная kernel-
      операция, сеть ему не нужна, строка давала только цикл.
    - DefaultDependencies=no — иначе implicit-зависимости от DefaultDependencies=yes
      (через basic.target/sysinit.target) могут снова создать цикл (Debian bug #832802).
      Тот же паттерн что у netfilter-persistent.service в реальной поставке Debian.
    - After=local-fs.target — ConditionPathExists читает файл с диска (/etc/ipset-
      singbox-cdn.conf), local-fs.target должен быть смонтирован. local-fs.target
      не имеет Before на netfilter-persistent — цикла не создаёт.
      (Проверено: netfilter-persistent.service тоже After=local-fs.target, но
      это параллельная зависимость, не создающая цикл.)

    Граф зависимостей после фикса (проверено эмпирически через systemd-analyze):
      singbox-cdn-ipset-restore.service
        → Before → sing-box.service
        → Before → netfilter-persistent.service
        → After  → local-fs.target
      netfilter-persistent.service (реальная поставка Debian/Ubuntu):
        → Before → network-pre.target
        → Before → shutdown.target
        → After  → systemd-modules-load.service
        → After  → local-fs.target
      Цикла нет: все рёбра идут в одном направлении (local-fs.target → ... →
      singbox-cdn-ipset-restore → netfilter-persistent → network-pre.target).
    """
    if _RESTORE_SVC.exists():
        return  # уже установлен
    _RESTORE_SVC.write_text(textwrap.dedent(f"""\
        [Unit]
        Description=Restore ipset for sing-box CDN allowlist (VLESS Ultimate)
        DefaultDependencies=no
        Before=sing-box.service
        Before=netfilter-persistent.service
        After=local-fs.target
        ConditionPathExists={_IPSET_CONF}

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/bin/bash -c 'ipset restore -! -f {_IPSET_CONF} 2>&1 | \\
            tee -a {_RESTORE_LOG} && \\
            echo "singbox-cdn ipset restored: $(grep -c ^add {_IPSET_CONF} 2>/dev/null || echo 0) rules" \\
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
#  apply_cdn_allowlist — ipset + iptables + persist (v4.23.2)
# ============================================================================
def apply_cdn_allowlist(cdn_provider: str, port: int) -> bool:
    """Применяет CDN allowlist на listen_port.

    1. Fetch CIDRs через fetch_cdn_nets()
    2. Создаёт ipset singbox_cdn_allowlist_<port>
    3. Добавляет все CIDR в ipset
    4. Добавляет iptables rule: DROP всего, что НЕ из CDN-диапазона
       v4.23.2: -I INPUT 1 (в НАЧАЛО цепочки, по образцу fptn.py:494)
    5. v4.23.2: Persist — ipset save + iptables save + systemd unit для restore

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
    # v4.23.2: -I INPUT 1 (в НАЧАЛО цепочки, не -A в конец).
    # По образцу fptn.py:494 — правило должно быть ПЕРВЫМ в INPUT,
    # чтобы чужие ACCEPT-правила не перехватили трафик раньше DROP.
    # Сначала удаляем старое правило (если есть) — idempotent
    _run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
          "-m", "set", "!", "--match-set", ipset, "src", "-j", "DROP",
          "-m", "comment", "--comment", comment],
         check=False, quiet=True)

    # Insert на позицию 1 — правило всегда первое в INPUT
    r = _run(["iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(port),
              "-m", "set", "!", "--match-set", ipset, "src", "-j", "DROP",
              "-m", "comment", "--comment", comment],
             check=False, quiet=True)
    if r.returncode != 0:
        warn(f"iptables rule failed: {r.stderr[:200] if r.stderr else 'unknown'}")
        warn(f"Порт {port} останется ОТКРЫТ всем интернету — нет allowlist!")
        return False

    # 5. v4.23.2: Persist — ipset save + iptables save + systemd unit
    # Без этого правила не переживут reboot (ipset уничтожается, iptables-restore
    # не знает про ссылку на несуществующий ipset).
    _ipset_save_port(port)
    _ipset_restore_unit_install()
    _iptables_persist()

    success(f"CDN allowlist применён: {meta['display_name']} → порт {port} защищён")
    log_to_file("INFO", f"CDN allowlist applied: {cdn_provider} on port {port} "
                        f"({len(cidrs)} CIDR)")
    return True


# ============================================================================
#  remove_cdn_allowlist — cleanup + persist (v4.23.2)
# ============================================================================
def remove_cdn_allowlist(port: int) -> bool:
    """Удаляет CDN allowlist для данного порта.

    1. Удаляет iptables rule
    2. Уничтожает ipset
    3. v4.23.2: Обновляет persisted state (иначе после reboot правило "воскреснет")

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

    # 3. v4.23.2: Обновляем persisted state
    _ipset_remove_from_persist(port)
    _iptables_persist()

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
