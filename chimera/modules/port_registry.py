"""
chimera/modules/port_registry.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр портов Chimera с detection конфликтов.

Проблема:
  В проекте 15+ сервисов (VLESS, Hysteria2, AWG, NaiveProxy, Mieru, TrustTunnel,
  Telemt, FPTN, WDTT, Web Panel, Subscription, и т.д.). Каждый имеет свой порт.
  Раньше каждый сервис сам открывал UFW-правила и никто не проверял конфликты.
  Результат: можно было случайно поставить два сервиса на один порт, или
  открыть порт в UFW для сервиса, который потом удалили — правило оставалось.

Решение:
  Единый реестр портов в /var/lib/xray-installer/port_registry.json.
  Каждый сервис при установке регистрирует свой порт.
  При удалении — разрегистрирует.
  Перед установкой можно проверить конфликты.

  Конфликт определяется если порт занят:
    1. Другим сервисом в реестре (с другим service_tag)
    2. Активным системным слушателем (ss / netstat)
    3. UFW-правилом, которое НЕ принадлежит этому сервису
    4. /etc/services (well-known port)

API:
  port_register(service_tag, port, proto, comment, force=False) -> (bool, str)
  port_unregister(service_tag, port=None, proto=None) -> bool
  port_get_conflicts(port, proto, exclude_service=None) -> list[dict]
  port_list_all() -> list[dict]
  port_check_system(port, proto) -> list[str]
  port_is_free(port, proto, exclude_service=None) -> tuple[bool, list[str]]

Сервис-теги (canonical names):
  SERVICE_VLESS           — VLESS Reality/xHTTP (443 или настраиваемый)
  SERVICE_WEB_PANEL       — rest_api.py web panel (8443 по умолчанию, loopback)
  SERVICE_WEB_PANEL_NGINX — nginx front для web panel с TLS (настраиваемый)
  SERVICE_NAIVEPROXY      — NaiveProxy
  SERVICE_MIERU           — Mieru
  SERVICE_TRUSTTUNNEL     — TrustTunnel
  SERVICE_TELEMT          — Telemt
  SERVICE_FPTN            — FPTN
  SERVICE_WDTT            — WDTT
  SERVICE_AWG_STANDALONE  — AmneziaWG standalone
  SERVICE_AWG_EXIT        — AmneziaWG exit (remote)
  SERVICE_SINGBOX         — sing-box (любой протокол)
  SERVICE_SUBSCRIPTION    — Subscription server
  SERVICE_SUBSCRIPTION_NGINX — nginx front для subscription с TLS (настраиваемый)
  SERVICE_HYSTERIA2       — Hysteria2
  SERVICE_B4_WEB          — b4 Web UI (loopback, 9700)
  SERVICE_B4_NGINX        — nginx front для b4 Web UI (TLS, 9743)
  SERVICE_CSQTT           — CSQTT data-plane (UDP, 46000)
  SERVICE_CSQTT_WEB       — CSQTT Web Panel (loopback, 46002)
  SERVICE_CSQTT_NGINX     — nginx front для CSQTT Web Panel (TLS)
  SERVICE_DNSCRYPT        — dnscrypt-proxy (loopback, 5300 — upstream для AGH)
  SERVICE_AGHOME          — AdGuard Home DNS (:53, loopback+public bind)
  SERVICE_AGHOME_WEB      — AdGuard Home Web UI (:3000)
  SERVICE_AGHOME_DOH      — AdGuard Home DoH (:30443/tcp)
  SERVICE_AGHOME_DOT      — AdGuard Home DoT (:853/tcp)
  SERVICE_AGHOME_DOQ      — AdGuard Home DoQ (:853/udp)
  SERVICE_OPENFLUX        — OpenFlux exit (carrier-канал, исходящий — без портов)
  SERVICE_OPENFLUX_BRIDGE — OpenFlux bridge SOCKS5 на этой VPS (loopback default)

Паттерн использования (на примере нового сервиса):
  from chimera.modules.port_registry import (
      port_register, port_unregister, port_get_conflicts,
      SERVICE_WEB_PANEL_NGINX,
  )

  # При установке:
  ok, msg = port_register(SERVICE_WEB_PANEL_NGINX, port=9443, proto="tcp",
                          comment="nginx front для User Portal (TLS)")
  if not ok:
      warn(f"Не удалось занять порт 9443: {msg}")
      return False
  # ... открыть UFW, запустить сервис ...

  # При удалении:
  port_unregister(SERVICE_WEB_PANEL_NGINX)
  # ... закрыть UFW, остановить сервис ...

Паттерн НЕ рефакторит существующие сервисы — они продолжают работать как есть.
Новые сервисы (и при рефакторинге старых) должны использовать port_registry.

Точка входа из TUI:
    from chimera.modules.port_registry import do_manage_port_registry
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль chimera._core (lazy import)."""
    import importlib
    return importlib.import_module("chimera._core")


# ── Константы ────────────────────────────────────────────────────────────────
PORT_REGISTRY_FILE = Path("/var/lib/xray-installer/port_registry.json")

#  файловая блокировка для атомарного read-modify-write.
# fcntl.flock — POSIX advisory lock, не требует доп. зависимостей.
LOCK_FILE = PORT_REGISTRY_FILE.with_suffix(".lock")

# Таймаут ожидания лока (секунды). Если другой процесс держит лок дольше —
# возвращаем ошибку вместо зависания.
_LOCK_TIMEOUT_SEC = 10

# ⏱ Таймауты на внешние вызовы (ufw/ss): КАЖДЫЙ запуск ufw берёт
# БЛОКИРУЮЩИЙ fcntl-лок /run/ufw.lock (ufw/util.py create_lock) —
# зависший держатель лока (ufw-процесс от оборванной сессии в
# D-состоянии) раньше вешал удаление/установку модулей НАВСЕГДА
# («зависание при освобождении порта»). Теперь ждём не дольше
# _UFW_TIMEOUT_SEC и возвращаем честную ошибку/пустой результат.
_UFW_TIMEOUT_SEC = 60   # allow/delete (внутри iptables-restore)
_UFW_STATUS_TIMEOUT_SEC = 30  # status numbered
_SS_TIMEOUT_SEC = 15    # ss -ltnp

# Канонические service_tag — короткие строки, без пробелов.
SERVICE_VLESS           = "vless"
SERVICE_WEB_PANEL       = "web_panel"
SERVICE_WEB_PANEL_NGINX = "web_panel_nginx"
SERVICE_NAIVEPROXY      = "naiveproxy"
SERVICE_MIERU           = "mieru"
SERVICE_TRUSTTUNNEL     = "trusttunnel"
SERVICE_TELEMT          = "telemt"
SERVICE_TELEMT_MTPROTO  = "telemt_mtproto"
SERVICE_TELEMT_IOS_FIX  = "telemt_ios_fix"
SERVICE_TELEMT_PANEL_DIRECT = "telemt_panel_direct"
SERVICE_TELEMT_PANEL_WEB   = "telemt_panel_web"   # Telemt Panel backend (loopback, 8080)
SERVICE_FPTN            = "fptn"
SERVICE_WDTT            = "wdtt"
SERVICE_AWG_STANDALONE  = "awg_standalone"
SERVICE_AWG_EXIT        = "awg_exit"
SERVICE_SINGBOX         = "singbox"
SERVICE_SUBSCRIPTION    = "subscription"
SERVICE_SUBSCRIPTION_NGINX = "subscription_nginx"
SERVICE_HYSTERIA2       = "hysteria2"
SERVICE_WEBDAV_TUNNEL  = "webdav_tunnel"
SERVICE_PORT_HOPPING   = "port_hopping"
SERVICE_OLCRTC_MANAGER = "olcrtc_manager"
SERVICE_B4_WEB         = "b4_web"          # b4 Web UI (loopback, 9700)
# значение = фактический service_tag, которым b4-модули (dpi_bypass.py,
# youtube_b4.py) регистрируют nginx-front в panel_nginx_front (исторический
# литерал; константа раньше расходилась с реальностью и нигде не использовалась).
SERVICE_B4_NGINX       = "chimera-b4-nginx"   # nginx front для b4 Web UI (TLS, 9743)
SERVICE_B4_DNS         = "b4_dns"          # b4 DNS TCP listener (0.0.0.0:5453)
SERVICE_CSQTT          = "csqtt"           # CSQTT data-plane (UDP, 46000)
SERVICE_CSQTT_WEB      = "csqtt_web"       # CSQTT Web Panel (loopback, 46002)
SERVICE_CSQTT_NGINX    = "csqtt_nginx"     # nginx front для CSQTT Web Panel (TLS)
# DNS-стек: dnscrypt-proxy (шифрованный upstream) + AdGuard Home (:53)
SERVICE_HYBRID_ADDON   = "hybrid_addon"    # Mieru hybrid addon (mita перед Xray; tcp+udp)
SERVICE_DNSCRYPT       = "dnscrypt"        # dnscrypt-proxy (loopback, 5300 — upstream для AGH)
SERVICE_AGHOME         = "aghome"          # AdGuard Home DNS :53 (loopback+public bind)
SERVICE_AGHOME_WEB     = "aghome_web"      # AdGuard Home Web UI (:3000)
SERVICE_AGHOME_DOH     = "aghome_doh"      # AdGuard Home DoH (:30443/tcp)
SERVICE_AGHOME_DOT     = "aghome_dot"      # AdGuard Home DoT (:853/tcp)
SERVICE_AGHOME_DOQ     = "aghome_doq"      # AdGuard Home DoQ (:853/udp)
# OpenFlux: exit-нода — ИСХОДЯЩИЙ carrier-канал (инбаундов нет, порты
# не регистрирует); bridge — локальный SOCKS5-сервер клиента OpenFlux
# на самой VPS (по умолчанию loopback 1080), его порт живёт в реестре:
# проверка занятости на установке/активации, закрытие при
# деактивации/удалении.
SERVICE_OPENFLUX        = "openflux"          # exit-нода (исходящий WSS)
SERVICE_OPENFLUX_BRIDGE = "openflux_bridge"   # bridge SOCKS5 (loopback default)


# ── Чтение/запись реестра ────────────────────────────────────────────────────

@contextlib.contextmanager
def _registry_lock(timeout: float = _LOCK_TIMEOUT_SEC):
    """POSIX advisory lock (fcntl.flock) для защиты read-modify-write цикла.

     обёртывает ВЕСЬ цикл read-modify-write в port_register()/
    port_unregister() одной блокировкой. Без этого два параллельных
    процесса могут прочитать одинаковый список, каждый модифицирует свой
    экземпляр, и второй перезаписывает первый → потеря данных.

    Таймаут: если лок не получен за timeout секунд — raises TimeoutError.
    Использует LOCK_EX | LOCK_NB в цикле с retry (100мс интервал) —
    не блокирует поток бесконечно.

    Чтение (port_list_all и т.д.) НЕ использует лок — благодаря атомарной
    записи через os.replace (см. _registry_save), read всегда получает
    консистентный снапшот.
    """
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    f = open(LOCK_FILE, "w")
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break  # лок получен
            except (BlockingIOError, OSError):
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"port_registry: не удалось получить лок за {timeout}с — "
                        "другой процесс держит реестр"
                    )
                time.sleep(0.1)
        try:
            yield
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    finally:
        f.close()


def _registry_load() -> list[dict]:
    """Загружает реестр. Возвращает [] если файла нет или повреждён.

    Не использует лок — благодаря атомарной записи (os.replace) в
    _registry_save(), read всегда получает консистентный снапшот.
    """
    if not PORT_REGISTRY_FILE.exists():
        return []
    try:
        data = json.loads(PORT_REGISTRY_FILE.read_text())
        if isinstance(data, list):
            return data
        # Старый формат (dict) — конвертируем.
        if isinstance(data, dict) and "ports" in data:
            return data["ports"]
    except Exception:
        pass
    return []


def _registry_save(entries: list[dict]) -> None:
    """Сохраняет реестр атомарно (tempfile + os.replace).

     не пишет напрямую в PORT_REGISTRY_FILE — сначала пишет во
    временный файл (.tmp), затем os.replace (атомарная операция на уровне
    ОС). Защищает от повреждения файла при обрыве процесса посреди записи:
    если процесс упал после write, но до replace — оригинальный файл
    остаётся нетронутым, .tmp можно проигнорировать.
    """
    PORT_REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = PORT_REGISTRY_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(entries, indent=2, ensure_ascii=False))
    try:
        tmp.chmod(0o600)
    except Exception:
        pass
    os.replace(tmp, PORT_REGISTRY_FILE)  # атомарно на POSIX


# ── Проверка системных слушателей ────────────────────────────────────────────

def _ss_available() -> bool:
    return bool(shutil.which("ss"))


def port_check_system(port: int, proto: str = "tcp") -> list[str]:
    """Проверяет, занят ли порт в системе (active listeners).

    Возвращает список описаний кто слушает порт (process name + pid).
    Пустой список = порт свободен.

    Использует `ss` (iproute2) — стандарт в современных Linux.
    """
    if not _ss_available():
        return []
    proto_flag = "-t" if proto == "tcp" else "-u"
    # -ltnp = listening, tcp, numeric, processes
    try:
        r = subprocess.run(
            ["ss", proto_flag + "lnp"],
            capture_output=True, text=True, check=False,
            timeout=_SS_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        return []
    if r.returncode != 0:
        return []
    results: list[str] = []
    # Формат ss:
    # State   Recv-Q  Send-Q Local Address:Port  Peer Address:Port Process
    # LISTEN  0       511    0.0.0.0:443         0.0.0.0:*         users:(("nginx",pid=1234,fd=8))
    # LISTEN  0       511    [::]:443            [::]:*
    port_str = f":{port} "
    port_str_end = f":{port}\n"
    for line in r.stdout.splitlines():
        # Ищем ":<port> " или ":<port>\n" чтобы не матчить 4430 как 443.
        if port_str in line or line.rstrip().endswith(f":{port}"):
            # Парсим process — последняя колонка.
            parts = line.split()
            proc_info = parts[-1] if parts else ""
            if proc_info.startswith("users:"):
                # "users:(("nginx",pid=1234,fd=8))"
                m = re.search(r'\("([^"]+)",pid=(\d+)', proc_info)
                if m:
                    results.append(f"{m.group(1)} (pid={m.group(2)})")
                else:
                    results.append(proc_info)
            else:
                results.append("(unknown process)")
    return results


def _check_etc_services(port: int, proto: str = "tcp") -> "Optional[str]":
    """Проверяет /etc/services на well-known port. Возвращает имя сервиса или None."""
    try:
        with open("/etc/services") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                # Формат: "https  443/tcp  http  # description"
                port_proto = parts[1]
                if "/" in port_proto:
                    p, pr = port_proto.split("/", 1)
                    if p == str(port) and pr == proto:
                        return parts[0]
    except Exception:
        pass
    return None


def _check_ufw_rules(port: int, proto: str = "tcp") -> list[dict]:
    """Возвращает UFW-правила для port/proto. Каждое — {num, comment, raw}."""
    if not shutil.which("ufw"):
        return []
    try:
        r = subprocess.run(
            ["ufw", "status", "numbered"],
            capture_output=True, text=True, check=False,
            timeout=_UFW_STATUS_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        return []
    if r.returncode != 0:
        return []
    rules: list[dict] = []
    for line in r.stdout.splitlines():
        m = re.match(r'^\s*\[\s*(\d+)\s*\]\s*(.+)', line)
        if not m:
            continue
        num = int(m.group(1))
        rest = m.group(2)
        # Ищем "<port>/<proto>"
        if f"{port}/{proto}" in rest:
            # Парсим комментарий после #.
            comment = ""
            if "#" in rest:
                comment = rest.split("#", 1)[1].strip()
            rules.append({"num": num, "comment": comment, "raw": rest.strip()})
    return rules


# ── Публичный API ────────────────────────────────────────────────────────────

def port_get_conflicts(port: int, proto: str = "tcp",
                       exclude_service: "Optional[str]" = None) -> list[dict]:
    """Возвращает список конфликтов для порта.

    Каждый конфликт — dict:
      {"type": "registry"|"system"|"ufw"|"etc_services",
       "detail": str,
       "service": str (для registry/ufw — кто занял)}

    exclude_service — сервис, который проверяет порт для себя (его собственные
    записи в реестре/UFW игнорируются — это нормально, что он видит свой порт).
    """
    conflicts: list[dict] = []

    # 1. Реестр port_registry.json
    entries = _registry_load()
    for e in entries:
        if e.get("port") == port and e.get("proto", "tcp") == proto:
            if exclude_service and e.get("service") == exclude_service:
                continue
            conflicts.append({
                "type": "registry",
                "service": e.get("service", "?"),
                "detail": f"Зарегистрирован за сервисом '{e.get('service', '?')}'"
                          f" ({e.get('comment', '')})",
            })

    # 2. Активные системные слушатели (ss)
    sys_listeners = port_check_system(port, proto)
    for listener in sys_listeners:
        conflicts.append({
            "type": "system",
            "service": listener,
            "detail": f"Порт уже слушается процессом: {listener}",
        })

    # 3. UFW-правила (если порт открыт в UFW, но не нами)
    ufw_rules = _check_ufw_rules(port, proto)
    for r in ufw_rules:
        # Если правило принадлежит exclude_service — не считаем конфликтом.
        if exclude_service and exclude_service in r.get("comment", ""):
            continue
        conflicts.append({
            "type": "ufw",
            "service": r.get("comment", ""),
            "detail": f"UFW правило #{r['num']}: {r['raw']}",
        })

    # 4. /etc/services (well-known ports — только информационно, не блокируем)
    svc_name = _check_etc_services(port, proto)
    if svc_name:
        # Не добавляем как конфликт, но возвращаем как info.
        # Некоторые well-known порты (https=443) нормально занимать если
        # пользователь явно этого хочет.
        pass

    return conflicts


def port_is_free(port: int, proto: str = "tcp",
                 exclude_service: "Optional[str]" = None) -> "tuple[bool, list[str]]":
    """Проверяет, свободен ли порт.

    Возвращает (is_free, conflict_descriptions).
    is_free = True если конфликтов типа registry/system/ufw нет.
    /etc_services НЕ считается конфликтом (только info).

    exclude_service — сервис, для которого проверяем (его собственные правила
    не считаются конфликтом).
    """
    conflicts = port_get_conflicts(port, proto, exclude_service)
    # Фильтруем — /etc_services не блокирующий.
    blocking = [c for c in conflicts if c["type"] != "etc_services"]
    if not blocking:
        return True, []
    return False, [c["detail"] for c in blocking]


def port_register(service_tag: str, port: int, proto: str = "tcp",
                  comment: str = "", force: bool = False) -> "tuple[bool, str]":
    """Регистрирует порт за сервисом.

    Args:
      service_tag: канонический тег (SERVICE_VLESS, SERVICE_WEB_PANEL_NGINX, ...)
      port: номер порта (1-65535)
      proto: "tcp" или "udp"
      comment: человекочитаемое описание
      force: если True — не проверять конфликты (ОСТОРОЖНО)

    Returns:
      (success, message)

     весь read-modify-write цикл обёрнут в _registry_lock() —
    защищает от гонки при конкурентном доступе (install одного сервиса
    пересекается с cron-задачей другого).
    """
    # Валидация (до локировки — не требует доступа к файлу).
    if not isinstance(port, int) or port < 1 or port > 65535:
        return False, f"Невалидный порт: {port}"
    if proto not in ("tcp", "udp"):
        return False, f"Невалидный proto: {proto} (нужно tcp/udp)"
    if not service_tag or not isinstance(service_tag, str):
        return False, "service_tag не указан"

    # Проверка конфликтов (до локировки — использует ss/ufw, не реестр).
    if not force:
        is_free, conflict_descs = port_is_free(port, proto,
                                                exclude_service=service_tag)
        if not is_free:
            return False, (f"Порт {port}/{proto} занят: "
                           + "; ".join(conflict_descs))

    # read-modify-write под локом.
    try:
        with _registry_lock():
            entries = _registry_load()
            existing_idx = None
            for i, e in enumerate(entries):
                if (e.get("service") == service_tag
                    and e.get("port") == port
                    and e.get("proto", "tcp") == proto):
                    existing_idx = i
                    break

            entry = {
                "service":      service_tag,
                "port":         port,
                "proto":        proto,
                "comment":      comment,
                "registered_at": datetime.now(timezone.utc).isoformat(),
            }

            if existing_idx is not None:
                entries[existing_idx] = entry
            else:
                entries.append(entry)

            _registry_save(entries)
    except TimeoutError as e:
        return False, str(e)
    return True, f"Порт {port}/{proto} зарегистрирован за '{service_tag}'"


def port_register_range(service_tag: str, port_start: int, port_end: int,
                        proto: str = "tcp", comment: str = "",
                        ) -> "tuple[bool, str]":
    """Массовая регистрация диапазона портов за сервисом (port hopping, Mieru).

    поэлементный вызов port_register() на диапазон 10000-20000
    это 10001 итераций «lock + полный read/parse + полный dump/write
    реестра», файл при этом растёт → O(N^2): минуты «зависания» TUI
    без единой строчки вывода (bench: 3000 итераций = 24с и замедление).
    Здесь — ОДИН lock, ОДИН load, append недостающих записей, ОДИН save →
    O(N), 10001 порт регистрируется за доли секунды.

    force-семантика (как port_register(force=True)): конфликты по каждому
    порту НЕ проверяются — диапазон port hopping это REDIRECT в PREROUTING,
    порты не занимают слушателей. Конфликт-детект для одиночных портов
    (port_get_conflicts) после регистрации работает как обычно: каждый
    порт диапазона виден в реестре занятым сервисом.

    Идемпотентно: существующие записи (service, port, proto) не дублируются.
    """
    if port_start > port_end:
        port_start, port_end = port_end, port_start
    if (not isinstance(port_start, int) or not isinstance(port_end, int)
            or port_start < 1 or port_end > 65535):
        return False, f"Невалидный диапазон: {port_start}-{port_end}"
    if proto not in ("tcp", "udp"):
        return False, f"Невалидный proto: {proto} (нужно tcp/udp)"
    if not service_tag or not isinstance(service_tag, str):
        return False, "service_tag не указан"

    now = datetime.now(timezone.utc).isoformat()
    added = 0
    try:
        with _registry_lock():
            entries = _registry_load()
            existing = {
                (e.get("service"), e.get("port"), e.get("proto", "tcp"))
                for e in entries
                if isinstance(e, dict)
            }
            for port in range(port_start, port_end + 1):
                if (service_tag, port, proto) in existing:
                    continue
                entries.append({
                    "service":      service_tag,
                    "port":         port,
                    "proto":        proto,
                    "comment":      comment,
                    "registered_at": now,
                })
                added += 1
            if added:
                _registry_save(entries)
    except TimeoutError as e:
        return False, str(e)
    return True, (f"Диапазон {port_start}-{port_end}/{proto} "
                  f"зарегистрирован за '{service_tag}' (+{added} записей)")


def port_unregister(service_tag: str, port: "Optional[int]" = None,
                    proto: "Optional[str]" = None) -> bool:
    """Снимает регистрацию порта(ов) за сервисом.

    Если port/proto не указаны — снимает ВСЕ записи для этого сервиса.
    Возвращает True если что-то было снято, False если записей не было.

     весь read-modify-write цикл обёрнут в _registry_lock().
    """
    try:
        with _registry_lock():
            entries = _registry_load()
            initial_count = len(entries)
            new_entries = [
                e for e in entries
                if not (
                    e.get("service") == service_tag
                    and (port is None or e.get("port") == port)
                    and (proto is None or e.get("proto", "tcp") == proto)
                )
            ]
            if len(new_entries) == initial_count:
                return False  # ничего не удалено
            _registry_save(new_entries)
    except TimeoutError:
        return False
    return True


def port_unregister_range(service_tag: str, port_start: int, port_end: int,
                          proto: "Optional[str]" = None) -> bool:
    """Снимает регистрацию диапазона портов за сервисом одним заходом.

    парная к port_register_range(). Раньше отключение port hopping
    (смена диапазона / disable) звало port_unregister() на каждый порт —
    тот же O(N^2): 10001 итераций полного rewrite реестра, «TUI завис».
    Здесь — ОДИН lock + ОДИН load + фильтр + ОДИН save.

    proto=None (как в port_unregister) снимает записи обоих протоколов
    в диапазоне. Возвращает True если что-то было снято.
    """
    if port_start > port_end:
        port_start, port_end = port_end, port_start
    try:
        with _registry_lock():
            entries = _registry_load()
            initial_count = len(entries)
            new_entries = [
                e for e in entries
                if not (
                    e.get("service") == service_tag
                    and isinstance(e.get("port"), int)
                    and port_start <= e.get("port") <= port_end
                    and (proto is None or e.get("proto", "tcp") == proto)
                )
            ]
            if len(new_entries) == initial_count:
                return False  # ничего не удалено
            _registry_save(new_entries)
    except TimeoutError:
        return False
    return True


def port_list_all() -> list[dict]:
    """Возвращает все записи реестра (копия)."""
    return list(_registry_load())


def port_list_for_service(service_tag: str) -> list[dict]:
    """Возвращает все порты, зарегистрированные за сервисом."""
    return [e for e in _registry_load() if e.get("service") == service_tag]


# ── UFW helpers (используют реестр для проверки) ─────────────────────────────

def ufw_open_port(port: int, proto: str, service_tag: str,
                  comment: "Optional[str]" = None) -> "tuple[bool, str]":
    """Открывает порт в UFW с комментарием-тегом сервиса.

    Идемпотентно: если уже открыто нашим правилом — не дублирует.
    Если открыто чужим правилом — warn, не трогает.

    Comment формата: "chimera-<service_tag> [<custom>]"
    """
    if not shutil.which("ufw"):
        return False, "ufw не установлен"
    if comment is None:
        comment = f"chimera-{service_tag}"
    else:
        comment = f"chimera-{service_tag} {comment}"

    # Проверяем существующие правила.
    existing = _check_ufw_rules(port, proto)
    ours = [r for r in existing if f"chimera-{service_tag}" in r.get("comment", "")]
    if ours:
        return True, f"Уже открыто нашим правилом"
    foreign = [r for r in existing if f"chimera-" not in r.get("comment", "")]
    if foreign:
        return False, (f"Порт {port}/{proto} уже открыт чужим UFW-правилом "
                       f"(#{foreign[0]['num']}) — не трогаем")

    try:
        r = subprocess.run(
            ["ufw", "allow", f"{port}/{proto}", "comment", comment],
            capture_output=True, text=True, check=False,
            input="y\n", timeout=_UFW_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        return False, (f"ufw allow {port}/{proto}: таймаут "
                       f"{_UFW_TIMEOUT_SEC}с (лок /run/ufw.lock занят?)")
    if r.returncode != 0:
        return False, f"ufw allow failed: {r.stderr.strip()}"
    return True, f"Порт {port}/{proto} открыт в UFW"


def ufw_close_port(port: int, proto: str, service_tag: str,
                   legacy_comments: "Optional[list[str]]" = None) -> "tuple[bool, str]":
    """Закрывает порт в UFW, удаляя наши правила (chimera-<service_tag>).

    Чужие правила НЕ трогает.

     legacy_comments — список старых комментариев (без 'chimera-' prefix),
    которые тоже нужно удалить. Используется при миграции существующих сервисов
    на port_registry: на серверах, где сервис был установлен ДО миграции, UFW
    правила имеют старый comment (например "NaiveProxy"). После миграции
    ufw_close_port ищет "chimera-naiveproxy" — не находит, и без legacy_comments
    оставил бы orphaned rule. С legacy_comments=["NaiveProxy"] правило будет
    найдено и удалено.
    """
    if not shutil.which("ufw"):
        return False, "ufw не установлен"

    existing = _check_ufw_rules(port, proto)
    # Ищем правила с нашим новым comment (chimera-<service_tag>).
    ours = [r for r in existing if f"chimera-{service_tag}" in r.get("comment", "")]
    #  также ищем legacy comments (старые правила до миграции).
    if legacy_comments:
        for lc in legacy_comments:
            if not lc:
                continue
            ours.extend([r for r in existing
                        if lc in r.get("comment", "")
                        and f"chimera-{service_tag}" not in r.get("comment", "")])
    if not ours:
        return True, "Нет нашего правила — нечего закрывать"

    # Удаляем с конца (старшие номера первыми).
    deleted = 0
    for r in sorted(ours, key=lambda x: x["num"], reverse=True):
        try:
            result = subprocess.run(
                ["ufw", "delete", str(r["num"])],
                capture_output=True, text=True, check=False,
                input="y\n", timeout=_UFW_TIMEOUT_SEC,
            )
        except subprocess.TimeoutExpired:
            break  # лок занят — остальные правила снимет повторный запуск
        if result.returncode == 0:
            deleted += 1
    return True, f"Удалено {deleted} правил для порта {port}/{proto}"


def ufw_open_port_range(port_start: int, port_end: int, proto: str,
                        service_tag: str,
                        comment: "Optional[str]" = None) -> "tuple[bool, str]":
    """Открывает диапазон портов в UFW (для Mieru, port_hopping).

    Идемпотентно. Comment: "chimera-<service_tag> [<custom>]".
    """
    if not shutil.which("ufw"):
        return False, "ufw не установлен"
    if port_start > port_end:
        port_start, port_end = port_end, port_start
    if comment is None:
        comment_str = f"chimera-{service_tag}"
    else:
        comment_str = f"chimera-{service_tag} {comment}"

    try:
        r = subprocess.run(
            ["ufw", "allow", f"{port_start}:{port_end}/{proto}", "comment", comment_str],
            capture_output=True, text=True, check=False,
            input="y\n", timeout=_UFW_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        return False, (f"ufw allow range {port_start}-{port_end}/{proto}: "
                       f"таймаут {_UFW_TIMEOUT_SEC}с")
    if r.returncode != 0:
        return False, f"ufw allow range failed: {r.stderr.strip()}"
    return True, f"Диапазон {port_start}-{port_end}/{proto} открыт в UFW"


def ufw_close_port_range(port_start: int, port_end: int, proto: str,
                         service_tag: str,
                         legacy_comments: "Optional[list[str]]" = None) -> "tuple[bool, str]":
    """Закрывает диапазон портов в UFW.

     legacy_comments — старые комментарии для backward compat.
    """
    if not shutil.which("ufw"):
        return False, "ufw не установлен"
    if port_start > port_end:
        port_start, port_end = port_end, port_start

    # Пробуем удалить по comment (новый style + legacy).
    comments_to_try = [f"chimera-{service_tag}"]
    if legacy_comments:
        comments_to_try.extend(legacy_comments)

    deleted = 0
    for c in comments_to_try:
        if not c:
            continue
        try:
            r = subprocess.run(
                ["ufw", "delete", "allow", f"{port_start}:{port_end}/{proto}",
                 "comment", c],
                capture_output=True, text=True, check=False,
                input="y\n", timeout=_UFW_TIMEOUT_SEC,
            )
        except subprocess.TimeoutExpired:
            continue
        if r.returncode == 0:
            deleted += 1

    # Также ищем по номерам (для правил созданных без comment).
    existing = _check_ufw_rules_range(port_start, port_end, proto)
    for r in sorted(existing, key=lambda x: x["num"], reverse=True):
        # Только наши (chimera- или legacy).
        comment = r.get("comment", "")
        if any(c in comment for c in comments_to_try if c):
            try:
                result = subprocess.run(
                    ["ufw", "delete", str(r["num"])],
                    capture_output=True, text=True, check=False,
                    input="y\n", timeout=_UFW_TIMEOUT_SEC,
                )
            except subprocess.TimeoutExpired:
                continue
            if result.returncode == 0:
                deleted += 1

    return True, f"Удалено {deleted} range-правил для {port_start}-{port_end}/{proto}"


def _check_ufw_rules_range(port_start: int, port_end: int,
                           proto: str = "tcp") -> list[dict]:
    """Возвращает UFW-правила для диапазона портов."""
    if not shutil.which("ufw"):
        return []
    try:
        r = subprocess.run(
            ["ufw", "status", "numbered"],
            capture_output=True, text=True, check=False,
            timeout=_UFW_STATUS_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        return []
    if r.returncode != 0:
        return []
    rules: list[dict] = []
    range_str = f"{port_start}:{port_end}/{proto}"
    for line in r.stdout.splitlines():
        m = re.match(r'^\s*\[\s*(\d+)\s*\]\s*(.+)', line)
        if not m:
            continue
        num = int(m.group(1))
        rest = m.group(2)
        if range_str in rest:
            comment = ""
            if "#" in rest:
                comment = rest.split("#", 1)[1].strip()
            rules.append({"num": num, "comment": comment, "raw": rest.strip()})
    return rules


# ── TUI ──────────────────────────────────────────────────────────────────────

def do_manage_port_registry() -> None:
    """TUI-меню просмотра реестра портов."""
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_bottom = core._box_bottom
    _box_item   = core._box_item
    _box_info   = core._box_info
    _box_warn   = core._box_warn
    _box_back   = core._box_back
    CYAN   = core.CYAN
    NC     = core.NC
    GREEN  = core.GREEN
    YELLOW = core.YELLOW
    RED    = core.RED
    DIM    = core.DIM
    BLUE   = core.BLUE
    info    = core.info
    warn    = core.warn
    success = core.success

    while True:
        entries = port_list_all()
        print()
        _box_top("📋  Реестр портов Chimera")
        _box_row()
        if not entries:
            _box_row(f"  {YELLOW}Реестр пуст.{NC}")
            _box_row(f"  {DIM}Сервисы регистрируют порты при установке.{NC}")
        else:
            _box_row(f"  {'Сервис':<22} {'Порт':<12} {'Proto':<6} {'Комментарий':<30}")
            _box_row(f"  {'-'*22} {'-'*12} {'-'*6} {'-'*30}")
            for e in entries:
                svc = e.get("service", "?")[:22]
                port = str(e.get("port", "?"))[:12]
                proto = e.get("proto", "tcp")[:6]
                comment = (e.get("comment", "") or "")[:30]
                _box_row(f"  {svc:<22} {CYAN}{port:<12}{NC} {proto:<6} {DIM}{comment}{NC}")
        _box_sep()

        _box_item("1", "Проверить порт на конфликты")
        _box_item("2", "Показать системных слушателей (ss)")
        _box_item("3", "Очистить реестр (ТОЛЬКО для разработки/дебага)")
        _box_row()
        _box_row(f"  {DIM}Реестр хранится в {PORT_REGISTRY_FILE}{NC}")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            print()
            return

        if ch == "q" or ch == "":
            return

        if ch == "1":
            print()
            try:
                port_str = input(f"{CYAN}  Порт для проверки:{NC} ").strip()
                port = int(port_str)
            except (ValueError, EOFError, KeyboardInterrupt):
                continue
            is_free, descs = port_is_free(port, "tcp")
            print()
            if is_free:
                _box_info(f"  Порт {port}/tcp СВОБОДЕН (конфликтов нет)")
            else:
                _box_warn(f"  Порт {port}/tcp ЗАНЯТ:")
                for d in descs:
                    _box_warn(f"    • {d}")
            input(f"\n{BLUE}  Нажмите Enter...{NC}")

        elif ch == "2":
            print()
            if not _ss_available():
                _box_warn("  ss не установлен")
            else:
                _box_top("Активные слушатели (ss -ltnp)")
                _box_row()
                try:
                    r = subprocess.run(["ss", "-ltnp"], capture_output=True,
                                      text=True, check=False,
                                      timeout=_SS_TIMEOUT_SEC)
                except subprocess.TimeoutExpired:
                    r = None
                if r:
                    for line in r.stdout.splitlines()[:30]:
                        _box_row(f"  {DIM}{line}{NC}")
                _box_bottom()
            input(f"\n{BLUE}  Нажмите Enter...{NC}")

        elif ch == "3":
            print()
            _box_warn("  Очистка реестра — только для разработки!")
            _box_warn("  В продакшене это сломает conflict detection.")
            try:
                confirm = input(f"{BLUE}  Введите RESET для подтверждения:{NC} ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if confirm == "RESET":
                _registry_save([])
                success("  Реестр очищен.")
            else:
                print("  Отменено.")
            input(f"\n{BLUE}  Нажмите Enter...{NC}")
