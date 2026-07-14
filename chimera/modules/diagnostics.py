"""
chimera/modules/diagnostics.py
───────────────────────────────────────────────────────────────────────────────
Диагностический движок: split-tunneling diagnostics + live traffic dashboard +
мастер полной диагностики.

Содержит 30 функций + 3 константы, вынесенных из _core.py:

Block A — split tunneling diagnostics (28 функций + 3 константы):
  • _DIAG_BLOCKED_DOMAINS / _DIAG_RUSSIAN_DOMAINS / _DIAG_STATS_API_ADDR —
    константы для тестов маршрутизации и Stats API.
  • _diag_ok / _diag_err / _diag_head / _diag_warn — адаптеры логирования
    (ok/err/head/warn) вокруг _box_wrap_msg / _box_top / _box_row.
  • _diag_make_counters / _diag_chk — счётчики [total, passed, warn, err]
    и единый валидатор chk(condition, ok_msg, fail_msg).
  • _diag_run — обёртка над subprocess.run с timeout-обработкой.
  • _diag_fmt_bytes — форматирование байтов в КБ/МБ/ГБ.
  • _diag_resolve_config — поиск config.json по стандартным путям.
  • _diag_stats_api_available / _diag_get_stats_via_api / _diag_hint_stats_api —
    работа с Xray Stats API (gRPC, порт 10085).
  • _diag_render_traffic_table / _diag_print_traffic_from_ss /
    _diag_print_traffic_volume — три метода получения статистики трафика
    с fallback-цепочкой (Stats API → access.log → ss -tni).
  • _diag_check_xray_service / _diag_check_geo_files /
    _diag_check_config_structure / _diag_check_outbounds /
    _diag_check_routing_live / _diag_check_access_log /
    _diag_check_error_log / _diag_top_hosts / _diag_check_state /
    _diag_check_geo_autoupdate / _diag_print_summary — пошаговые проверки.
  • run_split_tunnel_diagnostics() — точка входа, вызывает все _diag_check_*.

Block B — live traffic dashboard (1 функция):
  • do_live_traffic_dashboard() — real-time статистика по outbound-тегам
    (Stats API или ss -tni fallback), обновление каждые 3 сек.

Block C — мастер полной диагностики (1 функция):
  • do_full_diagnostic() — пошаговый wizard (14 шагов): unit tests, сервисы,
    связь, порт, TLS/REALITY, конфиг, Stats API, split tunnel, домен, exit-ноды,
    скорость, TTFB, DNS Leak + итоговый отчёт с рекомендациями.

Точки входа из _core.py:
    from chimera.modules.diagnostics import (
        _DIAG_BLOCKED_DOMAINS, _DIAG_RUSSIAN_DOMAINS, _DIAG_STATS_API_ADDR,
        _diag_ok, _diag_err, _diag_head, _diag_warn, _diag_make_counters,
        _diag_chk, _diag_run, _diag_fmt_bytes, _diag_resolve_config,
        _diag_stats_api_available, _diag_get_stats_via_api, _diag_hint_stats_api,
        _diag_render_traffic_table, _diag_print_traffic_from_ss,
        _diag_print_traffic_volume, _diag_check_xray_service,
        _diag_check_geo_files, _diag_check_config_structure,
        _diag_check_outbounds, _diag_check_routing_live, _diag_check_access_log,
        _diag_check_error_log, _diag_top_hosts, _diag_check_state,
        _diag_check_geo_autoupdate, _diag_print_summary,
        run_split_tunnel_diagnostics, do_live_traffic_dashboard, do_full_diagnostic,
    )

Доступ к helpers ядра (_box_*, цвета, _run, info/warn/success/dim, STATE_FILE,
CONFIG_DIR, XRAY_BIN, XRAY_STATS_API_PORT, GEOSITE_DAT/GEOIP_DAT, DIAG_*,
LOG_FILE, TG_CONFIG_FILE, _BOX_W, _wcslen, log_to_file, verify_connectivity,
check_exit_geo, do_speed_test, do_dns_leak_test, run_unit_tests,
do_check_domain_external, _awg_diagnostic_all_nodes, AWG_*) — через importlib
(lazy binding), как и в других извлечённых модулях (warp.py, smart_balancer.py,
standalone_screens.py, split_tunnel.py и т.д.).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль chimera._core, импортируя его лениво.

    При запуске через cron (python -c 'from ... import ...') модуль ещё не
    загружен — importlib полноценно его импортирует. При вызове из
    интерактивного инсталлятора модуль уже в sys.modules — это просто lookup.
    """
    import importlib
    return importlib.import_module("chimera._core")



# Домены для тестирования маршрутизации
_DIAG_BLOCKED_DOMAINS = [
    "instagram.com", "facebook.com", "x.com", "youtube.com", "discord.com",
]
_DIAG_RUSSIAN_DOMAINS = [
    "ya.ru", "vk.com", "gosuslugi.ru", "sberbank.ru", "mail.ru",
]

# Порт Stats API xray (gRPC)
_DIAG_STATS_API_ADDR = "127.0.0.1:10085"

# Адаптеры логирования: в диагностике используются ok/err/head —
# которых нет в установщике. Определяем их как module-level функции
# с префиксом _diag_, чтобы не конфликтовать с success/die/info/warn/dim.
def _diag_ok(msg: str) -> None:
    """Логирование OK-сообщения в рамке."""
    core = _core_module()
    _box_wrap_msg = core._box_wrap_msg
    GREEN, NC = core.GREEN, core.NC
    _box_wrap_msg(f"{GREEN}[OK]{NC}    ", 8, msg)
def _diag_err(msg: str) -> None:
    """Логирование ERR-сообщения в рамке. НЕ делает sys.exit."""
    core = _core_module()
    _box_wrap_msg = core._box_wrap_msg
    RED, NC = core.RED, core.NC
    _box_wrap_msg(f"{RED}[ERR]{NC}   ", 7, msg)
def _diag_head(msg: str) -> None:
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    print()
    _box_top(msg)
    _box_row()
def _diag_warn(counters: list, msg: str) -> None:
    core = _core_module()
    _box_wrap_msg = core._box_wrap_msg
    YELLOW, NC = core.YELLOW, core.NC
    _box_wrap_msg(f"{YELLOW}[WARN]{NC}  ", 7, msg)
    counters[2] += 1  # предупреждение — не фатально

# Счётчики — не глобальные, передаются через список-обёртку [total, passed, warn, err]
def _diag_make_counters() -> list:
    return [0, 0, 0, 0]  # [total, passed, warnings, errors]

def _diag_chk(counters: list, condition: bool,
               ok_msg: str, fail_msg: str, is_warn: bool = False) -> bool:
    core = _core_module()
    _box_warn = core._box_warn
    counters[0] += 1
    if condition:
        _diag_ok(ok_msg)
        counters[1] += 1
        return True
    else:
        if is_warn:
            _box_warn(fail_msg)
            counters[2] += 1
        else:
            _diag_err(fail_msg)
            counters[3] += 1
        return False

# _run в диагностике вызывается с позиционными аргументами и check=False —
# это совместимо с _run установщика (capture и check — keyword args с дефолтами).
# Единственное отличие: диагностика ожидает timeout=15, которого нет в _run
# установщика. Оборачиваем, чтобы не сломать сигнатуру.
def _diag_run(args, capture=True, check=False, timeout=60):
    """Запускает команду с таймаутом. Возвращает CompletedProcess или объект-заглушку при таймауте."""
    core = _core_module()
    _box_warn = core._box_warn
    try:
        return subprocess.run(args, capture_output=capture, text=True,
                              check=check, timeout=timeout)
    except subprocess.TimeoutExpired:
        _box_warn(f"Таймаут ({timeout}с) при выполнении: {' '.join(str(a) for a in args[:3])}...")
        # Возвращаем объект-заглушку чтобы не ломать вызывающий код
        return subprocess.CompletedProcess(args, returncode=1, stdout="", stderr="timeout")
    except FileNotFoundError:
        _box_warn(f"Команда не найдена: {args[0]}")
        return subprocess.CompletedProcess(args, returncode=1, stdout="", stderr="not found")


# --------------------------------------------------------------------------- #
#  Утилиты
# --------------------------------------------------------------------------- #

def _diag_fmt_bytes(n: int) -> str:
    if n < 1024:        return f"{n} Б"
    if n < 1024 ** 2:   return f"{n/1024:.1f} КБ"
    if n < 1024 ** 3:   return f"{n/1024**2:.1f} МБ"
    return f"{n/1024**3:.2f} ГБ"


def _diag_resolve_config() -> tuple:
    core = _core_module()
    DIAG_CONFIG_FILE     = core.DIAG_CONFIG_FILE
    DIAG_ALT_CONFIG_FILE = core.DIAG_ALT_CONFIG_FILE
    for candidate in (DIAG_CONFIG_FILE, DIAG_ALT_CONFIG_FILE):
        real = candidate.resolve() if candidate.exists() else None
        if real and real.exists():
            try:
                cfg = json.loads(real.read_text())
                return real, cfg
            except json.JSONDecodeError as e:
                _diag_err(f"Конфиг {candidate} — ошибка JSON: {e}")
                return candidate, {}
    return None, {}


# --------------------------------------------------------------------------- #
#  Статистика трафика: три метода с fallback-цепочкой
# --------------------------------------------------------------------------- #

def _diag_stats_api_available() -> bool:
    host, port = _DIAG_STATS_API_ADDR.rsplit(":", 1)
    r = subprocess.run(
        ["bash", "-c",
         f"timeout 2 bash -c 'echo >/dev/tcp/{host}/{port}' 2>/dev/null && echo ok || echo fail"],
        capture_output=True, text=True
    )
    return r.stdout.strip() == "ok"


def _diag_get_stats_via_api() -> dict | None:
    """
    Получает статистику трафика через Xray Stats API.

    Совместимо с Xray 1.8+ и новыми версиями (26.x+), где записи с нулевым
    значением не содержат поля "value" в JSON-выводе.

    Возвращает dict {tag: bytes} если API доступен и настроен (даже если все
    счётчики нулевые — возвращает пустой dict {}, а не None).
    Возвращает None только если API недоступен или xray не найден.
    """
    core = _core_module()
    XRAY_BIN = core.XRAY_BIN
    xray_bin = shutil.which("xray") or str(XRAY_BIN)
    if not Path(xray_bin).exists():
        return None
    if not _diag_stats_api_available():
        return None
    try:
        r = subprocess.run(
            [xray_bin, "api", "statsquery",
             f"--server={_DIAG_STATS_API_ADDR}",
             "--pattern=outbound>>>",
             "--reset=false"],
            capture_output=True, text=True, timeout=10
        )
    except Exception:
        return None
    if r.returncode != 0 or not r.stdout.strip():
        return None

    raw = r.stdout.strip()

    # --- Попытка 1: JSON-парсинг (современный формат Xray 26.x) ---
    # Формат: {"stat":[{"name":"outbound>>>tag>>>traffic>>>uplink","value":12345}, ...]}
    # Записи с value=0 выводятся БЕЗ поля "value" — считаем их нулями.
    try:
        data = json.loads(raw)
        stat_list = data.get("stat") or []
        if isinstance(stat_list, list):
            bytes_by_tag: dict[str, int] = {}
            pat_name = re.compile(
                r'^outbound>>>([^>]+)>>>traffic>>>(uplink|downlink)$'
            )
            # Сначала регистрируем все теги (включая нулевые)
            for entry in stat_list:
                name = entry.get("name", "")
                m = pat_name.match(name)
                if m:
                    tag = m.group(1)
                    # Теги-служебные пропускаем в таблице, но регистрируем
                    val = int(entry.get("value") or 0)
                    bytes_by_tag[tag] = bytes_by_tag.get(tag, 0) + val
            # Возвращаем dict (может быть пустым если все нули, но API настроен)
            return bytes_by_tag
    except (json.JSONDecodeError, ValueError, TypeError):
        pass

    # --- Попытка 2: построчный парсинг (старый текстовый формат) ---
    bytes_by_tag = {}
    pat_name_re  = re.compile(r'name:\s*"outbound>>>([^>]+)>>>traffic>>>(uplink|downlink)"')
    pat_value_re = re.compile(r'value:\s*(\d+)')
    pat_oneline  = re.compile(r'outbound>>>([^>]+)>>>traffic>>>(uplink|downlink)\s+(\d+)')

    lines = raw.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        m = pat_oneline.search(line)
        if m:
            bytes_by_tag[m.group(1)] = bytes_by_tag.get(m.group(1), 0) + int(m.group(3))
            i += 1
            continue
        m = pat_name_re.search(line)
        if m:
            tag = m.group(1)
            # Тег регистрируем даже если value не найдено (нулевой счётчик)
            if tag not in bytes_by_tag:
                bytes_by_tag[tag] = 0
            for j in range(i + 1, min(i + 4, len(lines))):
                mv = pat_value_re.search(lines[j])
                if mv:
                    bytes_by_tag[tag] = bytes_by_tag.get(tag, 0) + int(mv.group(1))
                    break
        i += 1
    return bytes_by_tag


def _diag_hint_stats_api() -> None:
    core = _core_module()
    _box_row  = core._box_row
    _box_info = core._box_info
    _box_row()
    _box_info("── Как включить точную статистику через Xray Stats API ──")
    _box_info('Добавьте в config.json секции: "stats":{}, "api":{tag,services}, "policy":{system:{statsOutbound*}}')
    _box_info(f'И inbound на {_DIAG_STATS_API_ADDR} (dokodemo-door). После перезапуска xray статистика накапливается.')
    _box_row()


def _diag_render_traffic_table(bytes_by_tag: dict, source_label: str) -> None:
    core = _core_module()
    _box_warn = core._box_warn
    _box_info = core._box_info
    _box_row  = core._box_row
    _box_dim  = core._box_dim
    CYAN = core.CYAN
    DIM = core.DIM
    GREEN = core.GREEN
    NC = core.NC
    RED = core.RED
    YELLOW = core.YELLOW
    CYAN, GREEN, RED, YELLOW, DIM, NC = (
        core.CYAN, core.GREEN, core.RED, core.YELLOW, core.DIM, core.NC)
    # Служебные теги исключаем из пользовательской статистики
    _SERVICE_TAGS = {"xray-stats-api", "freedom"}
    data = {k: v for k, v in bytes_by_tag.items() if k not in _SERVICE_TAGS}

    total_bytes = sum(data.values())
    if total_bytes == 0:
        _box_warn("Все счётчики равны нулю — трафика не было с момента старта xray")
        _box_info("  Подождите несколько минут после подключения клиента и повторите")
        return

    proxy_bytes  = sum(v for k, v in data.items()
                       if "chain-exit" in k or "balancer" in k)
    direct_bytes = data.get("direct", 0)
    block_bytes  = data.get("BLOCK", 0)
    other_bytes  = total_bytes - proxy_bytes - direct_bytes - block_bytes

    _diag_ok(f"Источник данных: {source_label}")
    _diag_ok(f"Суммарный трафик: {_diag_fmt_bytes(total_bytes)}")

    W = 24  # ширина полосы в символах
    def _bar(val, total, color):
        if total == 0:
            return f"{DIM}{'░' * W}{NC}"
        filled = max(0, min(W, int(val / total * W)))
        empty  = W - filled
        return f"{color}{'▓' * filled}{NC}{DIM}{'░' * empty}{NC}"

    _box_row(f"  {'Направление':<24} {'Объём':>10}  {'Доля':>6}  Визуализация")
    _box_row(f"  {'-'*24} {'-'*10}  {'-'*6}  {'-'*W}")
    rows = [
        ("→ chain-exit (proxy)",  proxy_bytes,  CYAN),
        ("→ direct (РФ трафик)",  direct_bytes, GREEN),
        ("→ BLOCK",               block_bytes,  RED),
    ]
    if other_bytes > 0:
        rows.append(("→ другие теги", other_bytes, YELLOW))
    for label, val, color in rows:
        pct = val / total_bytes * 100 if total_bytes else 0
        _box_row(f"  {label:<24} {_diag_fmt_bytes(val):>10}  {pct:5.1f}%  {_bar(val, total_bytes, color)}")
    _box_row()

    # Детализация по exit-нодам (показываем всегда если есть хоть одна нода)
    exit_node_bytes = {k: v for k, v in data.items()
                       if "chain-exit" in k or "balancer" in k}
    if exit_node_bytes:
        label_txt = "Распределение по exit-нодам (балансировщик):" if len(exit_node_bytes) > 1 \
                    else "Exit-нода:"
        _box_info(label_txt)
        for tag, val in sorted(exit_node_bytes.items(), key=lambda x: -x[1]):
            pct = val / proxy_bytes * 100 if proxy_bytes else 0
            _box_dim(f"    {tag:<28} {_diag_fmt_bytes(val):>10}  {pct:5.1f}%")
        _box_row()

    if proxy_bytes and direct_bytes:
        ratio = proxy_bytes / (proxy_bytes + direct_bytes) * 100
        _diag_ok(f"Split tunneling по объёму: {ratio:.1f}% proxy / {100-ratio:.1f}% direct")
    elif proxy_bytes and not direct_bytes:
        _box_info("Весь трафик идёт через proxy (direct = 0) — split tunneling не разделяет или только заблокированный трафик")
    elif direct_bytes and not proxy_bytes:
        _box_warn("Весь трафик direct — split tunneling не работает или нет заблокированных сайтов в трафике")


def _diag_print_traffic_from_ss() -> None:
    core = _core_module()
    _box_warn = core._box_warn
    _box_row  = core._box_row
    _box_info = core._box_info
    DIM = core.DIM
    NC = core.NC
    try:
        r = _diag_run(["ss", "-tni"])
        lines = r.stdout.splitlines()
    except Exception:
        _box_warn("ss недоступен — статистику получить не удалось")
        return

    total_sent = 0
    total_recv = 0
    conn_count = 0
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("ESTAB"):
            stats_line = ""
            for j in range(i + 1, min(i + 5, len(lines))):
                if "bytes_sent" in lines[j] or "bytes_acked" in lines[j]:
                    stats_line = lines[j]
                    break
            if stats_line:
                ms = re.search(r'bytes_(?:sent|acked):(\d+)', stats_line)
                mr = re.search(r'bytes_received:(\d+)', stats_line)
                sent = int(ms.group(1)) if ms else 0
                recv = int(mr.group(1)) if mr else 0
                if sent or recv:
                    total_sent += sent
                    total_recv += recv
                    conn_count += 1
        i += 1

    if conn_count == 0:
        _box_warn("Активных TCP-соединений с данными о трафике не найдено")
        _box_warn("Возможно, нет подключённых клиентов в данный момент")
        _box_row()
        _diag_hint_stats_api()
        return

    _diag_ok(f"Активные TCP-соединения: {conn_count} шт.")
    _diag_ok(f"  Отправлено (upload):   {_diag_fmt_bytes(total_sent)}")
    _diag_ok(f"  Получено   (download): {_diag_fmt_bytes(total_recv)}")
    _diag_ok(f"  Итого:                 {_diag_fmt_bytes(total_sent + total_recv)}")
    _box_info("Примечание: данные только активных соединений в момент проверки — не накопленная статистика")
    _box_info("Примечание: разбивки proxy/direct нет (ss не знает о тегах xray)")


def _diag_print_traffic_volume(bytes_by_tag: dict) -> None:
    core = _core_module()
    _box_info = core._box_info
    _box_ok   = core._box_ok
    _diag_head("6.5. Объём трафика по направлениям")

    _box_info("Метод 1/3: Xray Stats API...")
    api_data = _diag_get_stats_via_api()
    if api_data is None:
        # API недоступен или xray не найден
        if not _diag_stats_api_available():
            _box_info(f"Stats API недоступен (порт {_DIAG_STATS_API_ADDR} не слушает) — метод 1 пропущен")
            _box_info('  Добавьте в config.json: "stats":{}, "api":{...}, inbound на 127.0.0.1:10085')
        else:
            _box_info("Stats API не отвечает или xray не найден — метод 1 пропущен")
    else:
        # API настроен и отвечает (даже если трафика пока нет)
        has_traffic = any(v > 0 for v in api_data.values())
        if not has_traffic:
            _box_ok("Stats API настроен корректно (порт 10085, секции stats/api/policy найдены)")
            _box_info("Трафика с момента последнего запуска xray ещё нет — счётчики нулевые")
            _box_info("  Подключите клиента к VPN и повторите диагностику")
            tags_known = [t for t in api_data if t not in ("BLOCK", "xray-stats-api")]
            if tags_known:
                _box_info(f"  Отслеживаемые outbound-теги: {', '.join(sorted(tags_known))}")
        else:
            display_data = {k: v for k, v in api_data.items()
                            if k not in ("xray-stats-api",)}
            _diag_ok("Stats API доступен — используем точные накопленные данные")
            _diag_render_traffic_table(display_data, "Xray Stats API (накопленная статистика)")
        return

    _box_info("Метод 2/3: данные из access.log (парсинг байтов)...")
    if bytes_by_tag:
        _diag_ok("Байты найдены в access.log — используем данные из лога")
        _diag_render_traffic_table(bytes_by_tag, "access.log (loglevel=info)")
        _box_info("Совет: Stats API даст более точную статистику без зависимости от loglevel")
        _diag_hint_stats_api()
        return
    else:
        _box_info("В access.log нет данных о байтах (loglevel=info не включён) — метод 2 пропущен")
        _box_info("  Включить: в config.json → log.loglevel = 'info', перезапустить xray")

    _box_info("Метод 3/3: сетевая статистика ядра (ss -tni)...")
    _diag_print_traffic_from_ss()


# --------------------------------------------------------------------------- #
#  Проверочные функции
# --------------------------------------------------------------------------- #

def _diag_check_xray_service(counters: list) -> None:
    _diag_head("1. Состояние Xray")
    r = _diag_run(["systemctl", "is-active", "xray"])
    _diag_chk(counters, r.stdout.strip() == "active",
              "Xray активен",
              "Xray не запущен — дальнейшие проверки могут быть неточными")
    r = _diag_run(["systemctl", "is-enabled", "xray"])
    _diag_chk(counters, r.stdout.strip() == "enabled",
              "Xray включён в автозапуск",
              "Xray не добавлен в автозапуск", is_warn=True)
    dropin = Path("/etc/systemd/system/xray.service.d")
    # Файлы, которые создаёт сам установщик и которые не являются ошибкой
    KNOWN_DROPINS = {"cold-boot-restore.conf", "override.conf"}
    if dropin.exists() and any(dropin.iterdir()):
        files = [f.name for f in dropin.iterdir()]
        unknown = [f for f in files if f not in KNOWN_DROPINS]
        if unknown:
            _diag_err(f"Drop-in файлы systemd: {unknown} — переопределяют конфиг, удалите директорию")
            counters[3] += 1
        else:
            _diag_ok(f"Drop-in файлы systemd: {files} — установлены установщиком (OK)")
    else:
        _diag_ok("Drop-in директория xray.service.d отсутствует (нет конфликтов)")


def _diag_check_geo_files(counters: list) -> None:
    core = _core_module()
    _box_warn   = core._box_warn
    GEOSITE_DAT = core.GEOSITE_DAT
    GEOIP_DAT   = core.GEOIP_DAT
    _diag_head("2. Geo-файлы")
    for path, label in [
        (GEOSITE_DAT,                              "geosite.dat (основной)"),
        (GEOIP_DAT,                                "geoip.dat   (основной)"),
        (Path("/usr/local/share/xray/geosite.dat"), "geosite.dat (share)"),
        (Path("/usr/local/share/xray/geoip.dat"),   "geoip.dat   (share)"),
    ]:
        if path.exists():
            size_kb  = path.stat().st_size // 1024
            age_days = (time.time() - path.stat().st_mtime) / 86400
            age_str  = f"{age_days:.0f} дн."
            if age_days > 14:
                _box_warn(f"{label}: {size_kb} КБ, возраст {age_str} — рекомендуется обновить")
                counters[2] += 1
            else:
                _diag_ok(f"{label}: {size_kb} КБ, возраст {age_str}")
        else:
            _diag_err(f"{label}: НЕ НАЙДЕН")
            counters[3] += 1


def _diag_check_config_structure(counters: list) -> tuple:
    core = _core_module()
    _box_info = core._box_info
    _box_warn = core._box_warn
    XRAY_BIN                 = core.XRAY_BIN
    STATE_FILE               = core.STATE_FILE
    CONFIG_DIR               = core.CONFIG_DIR
    SPLIT_TUNNEL_CUSTOM_FILE = core.SPLIT_TUNNEL_CUSTOM_FILE
    _diag_head("3. Структура конфига Xray")
    cfg_path, cfg = _diag_resolve_config()
    if not cfg_path:
        _diag_err("Конфиг не найден ни по одному из стандартных путей")
        return None, {}
    if cfg_path.is_symlink():
        _diag_ok(f"Конфиг: {cfg_path} → {cfg_path.resolve()}")
    else:
        _diag_ok(f"Конфиг: {cfg_path}")
    if not cfg:
        _diag_err("Конфиг пустой или не парсится")
        return cfg_path, cfg

    # xray -test с большим конфигом (13000+ правил RIPE) может занимать до 60 секунд
    _box_info("Проверка конфига (xray -test)... это может занять до 60 секунд при большом числе RIPE-правил")
    r = _diag_run([str(XRAY_BIN), "run", "-test", "-config", str(cfg_path)], timeout=90)
    if r.stderr == "timeout":
        _diag_warn(counters, "Проверка конфига (xray -test) превысила таймаут 90с — конфиг скорее всего валиден, но очень большой")
    else:
        _diag_chk(counters, r.returncode == 0,
                  "Конфиг валиден (xray -test)",
                  f"Конфиг НЕ валиден: {r.stderr.strip()[:200]}")

    routing = cfg.get("routing", {})
    rules   = routing.get("rules", [])
    _diag_chk(counters, bool(rules),
              f"Routing rules: {len(rules)} правил",
              "Routing rules отсутствуют")

    ds = routing.get("domainStrategy", "—")
    _box_info(f"domainStrategy: {ds}")
    if ds not in ("IPIfNonMatch", "IPOnDemand", "AsIs"):
        _box_warn(f"Нестандартная domainStrategy: {ds}")

    # --- geoDataBasePath: предупреждение только если geo-файлы физически отсутствуют ---
    gdp = routing.get("geoDataBasePath", "")
    if gdp:
        _diag_ok(f"geoDataBasePath: {gdp}")
    else:
        # Дефолтный путь Xray — /usr/local/share/xray/
        _default_geo = Path("/usr/local/share/xray")
        geo_present = (
            (_default_geo / "geosite.dat").exists() or
            (_default_geo / "geoip.dat").exists() or
            (CONFIG_DIR / "geosite.dat").exists() or
            (CONFIG_DIR / "geoip.dat").exists()
        )
        if geo_present:
            _box_info("geoDataBasePath не задан — xray использует /usr/local/share/xray/ (файлы найдены)")
        else:
            _box_warn("geoDataBasePath не задан и geo-файлы не найдены в стандартных путях")

    # --- Читаем split_tunnel из state.json + split_tunnel_custom.json ---
    # Статус split tunneling может расходиться: state.json обновляется только при
    # полной установке (п.1), а split_tunnel_custom.json — при каждом изменении в меню [S].
    # Считаем split tunneling включённым, если хотя бы один из файлов говорит «включено».
    split_tunnel_enabled = False
    try:
        if STATE_FILE.exists():
            _st = json.loads(STATE_FILE.read_text())
            split_tunnel_enabled = _st.get("split_tunnel", False)
            install_mode         = _st.get("install_mode", "A")
        else:
            install_mode = "A"
    except Exception:
        install_mode = "A"
    # Также проверяем split_tunnel_custom.json — он обновляется меню [S]
    try:
        if SPLIT_TUNNEL_CUSTOM_FILE.exists():
            _custom = json.loads(SPLIT_TUNNEL_CUSTOM_FILE.read_text())
            if _custom.get("enabled", False):
                split_tunnel_enabled = True
    except Exception:
        pass

    has_geo_rules = False
    has_direct    = False
    has_block     = False
    has_split     = False
    proxy_tags    = set()
    for rule in rules:
        tag     = rule.get("outboundTag", rule.get("balancerTag", ""))
        domains = rule.get("domain", [])
        ips     = rule.get("ip", [])
        for d in domains + ips:
            if "geosite:" in str(d) or "geoip:" in str(d):
                has_geo_rules = True
        if "ru-blocked" in str(domains) or "ru-blocked" in str(ips):
            has_split = True
        if tag == "direct":     has_direct = True
        elif tag == "BLOCK":    has_block  = True
        elif tag:               proxy_tags.add(tag)

    # Geo-правила: ошибка только если split tunneling включён в state
    if split_tunnel_enabled:
        _diag_chk(counters, has_geo_rules,
                  "Geo-правила (geosite/geoip) найдены в routing",
                  "Geo-правил нет — split tunneling включён в state, но правила отсутствуют в конфиге")
    else:
        if has_geo_rules:
            _diag_ok("Geo-правила (geosite/geoip) найдены в routing")
        else:
            _box_info("Geo-правил в routing нет — split tunneling выключен (нормально)")

    # ru-blocked правила убраны как избыточные (дефолт tcp,udp → chain-balancer покрывает их)

    # direct outbound: предупреждение только если split tunneling включён
    if split_tunnel_enabled:
        _diag_chk(counters, has_direct,
                  "Outbound 'direct' присутствует в правилах",
                  "Outbound 'direct' отсутствует — российский трафик не идёт напрямую",
                  is_warn=True)
    else:
        if has_direct:
            _diag_ok("Outbound 'direct' присутствует в правилах")
        else:
            _box_info(f"Outbound 'direct' отсутствует — split tunneling выключен, Режим {install_mode} (нормально)")

    _diag_chk(counters, has_block,
              "Outbound 'BLOCK' присутствует (bittorrent блокируется)",
              "BLOCK outbound не задан", is_warn=True)
    if proxy_tags:
        _diag_ok(f"Proxy outbound теги: {', '.join(sorted(proxy_tags))}")
    return cfg_path, cfg


def _diag_check_outbounds(cfg: dict, counters: list) -> None:
    core = _core_module()
    _box_warn = core._box_warn
    _box_info = core._box_info
    _box_dim  = core._box_dim
    _diag_head("4. Outbound-ы и балансировщик")
    if not cfg:
        _box_warn("Конфиг не загружен, пропуск")
        return

    outbounds = cfg.get("outbounds", [])
    tags = {ob.get("tag"): ob.get("protocol") for ob in outbounds}
    _box_info(f"Всего outbound-ов: {len(outbounds)}")
    for tag, proto in tags.items():
        _box_dim(f"  • {tag:30s} [{proto}]")

    exit_tags = [t for t in tags if t and t.startswith("chain-exit")]
    if exit_tags:
        _diag_ok(f"Exit-ноды в конфиге: {len(exit_tags)} шт. — {', '.join(exit_tags)}")
    else:
        _box_warn("chain-exit теги не найдены (Режим A или нет exit-нод)")

    balancers = cfg.get("routing", {}).get("balancers", [])
    if balancers:
        for bal in balancers:
            tag      = bal.get("tag", "?")
            selector = bal.get("selector", [])
            strategy = bal.get("strategy", {}).get("type", "?")
            _diag_ok(f"Балансировщик '{tag}': стратегия={strategy}, нод={len(selector)}")
    else:
        if len(exit_tags) > 1:
            _box_warn("Несколько exit-нод, но балансировщик не задан")
        else:
            _box_info("Балансировщик не нужен (одна нода или Режим A)")

    obs = cfg.get("observatory")
    if obs:
        _diag_ok(f"Observatory (leastPing/leastLoad): probe={obs.get('probeUrl','?')}, interval={obs.get('probeInterval','?')}")
    elif balancers and any(b.get("strategy", {}).get("type") in ("leastPing", "leastLoad") for b in balancers):
        _diag_err("Стратегия leastPing/leastLoad, но observatory не задан — деградирует до random")
        counters[3] += 1

    if "direct" in tags:
        _diag_ok("Outbound 'direct' (freedom) присутствует")
    else:
        _box_info("Outbound 'direct' отсутствует (нормально для Режима B без split tunneling)")


def _diag_check_routing_live(cfg: dict, counters: list) -> None:
    core = _core_module()
    _box_warn = core._box_warn
    _box_info = core._box_info
    _diag_head("5. Тест маршрутизации (TCP ping exit-нод)")
    if not cfg:
        _box_warn("Конфиг не загружен, пропуск")
        return
    _box_info("Проверяем доступность exit-нод напрямую (TCP ping)...")
    outbounds = cfg.get("outbounds", [])
    for ob in outbounds:
        tag = ob.get("tag", "")
        if not tag.startswith("chain-exit"):
            continue
        for vn in ob.get("settings", {}).get("vnext", []):
            host = vn.get("address", "")
            port = vn.get("port", 443)
            if not host:
                continue
            r = subprocess.run(
                ["bash", "-c",
                 f"timeout 5 bash -c 'echo > /dev/tcp/{host}/{port}' 2>/dev/null && echo ok || echo fail"],
                capture_output=True, text=True
            )
            alive = r.stdout.strip() == "ok"
            _diag_chk(counters, alive,
                      f"Exit-нода [{tag}] {host}:{port} — TCP достижима",
                      f"Exit-нода [{tag}] {host}:{port} — НЕДОСТУПНА (timeout или rejected)")


def _diag_check_access_log(counters: list) -> dict:
    """Анализирует access.log. Возвращает bytes_by_tag для _diag_print_traffic_volume."""
    core = _core_module()
    _box_warn = core._box_warn
    _box_info = core._box_info
    _box_dim  = core._box_dim
    DIAG_ACCESS_LOG = core.DIAG_ACCESS_LOG
    BOLD, NC        = core.BOLD, core.NC
    _diag_head("6. Анализ access.log (реальный трафик)")
    bytes_by_tag: dict[str, int] = {}

    if not DIAG_ACCESS_LOG.exists():
        _box_warn(f"{DIAG_ACCESS_LOG} не существует — лог не настроен или нет подключений")
        return bytes_by_tag
    size = DIAG_ACCESS_LOG.stat().st_size
    if size == 0:
        _box_warn("access.log пустой — нет подключений")
        return bytes_by_tag

    try:
        r = _diag_run(["tail", "-n", "50000", str(DIAG_ACCESS_LOG)])
        lines = r.stdout.splitlines()
    except Exception as e:
        _box_warn(f"Не удалось прочитать лог: {e}")
        return bytes_by_tag

    _box_info(f"Анализируем последние {len(lines)} строк access.log ({_diag_fmt_bytes(size)})...")

    via_direct: list = []
    via_exit:   list = []
    via_block:  list = []
    via_other:  list = []

    pat_accepted = re.compile(r'accepted\s+\S+:(\S+):(\d+)\s+\[([^\]]+)\]')
    pat_bytes_a  = re.compile(r'\[([^\]]+)\]\s+(\d+)\s+bytes?\s+upload,?\s+(\d+)\s+bytes?\s+download', re.IGNORECASE)
    pat_bytes_b  = re.compile(r'>>\s+([\w\-]+)\s+\|\s+(\d+)\s+(\d+)\s+\|')
    pat_bytes_c  = re.compile(r'\[([^\]]+)\s*->\s*([^\]]+)\]\s+(\d+)\s+(\d+)')
    pat_bytes_d  = re.compile(r'(chain-exit-\d+|direct|BLOCK)\s+\|\s+(\d+)\s+\|\s+(\d+)')

    for line in lines:
        m = pat_accepted.search(line)
        if m:
            host, port, routing = m.group(1), m.group(2), m.group(3)
            if "->" not in routing:
                continue
            out_tag = routing.split("->")[-1].strip()
            if out_tag == "direct":                              via_direct.append((host, port))
            elif "chain-exit" in out_tag or "balancer" in out_tag: via_exit.append((host, port, out_tag))
            elif out_tag == "BLOCK":                             via_block.append((host, port))
            else:                                                via_other.append((host, port, out_tag))
            continue

        m = pat_bytes_a.search(line)
        if m:
            tag = m.group(1).split("->")[-1].strip()
            bytes_by_tag[tag] = bytes_by_tag.get(tag, 0) + int(m.group(2)) + int(m.group(3))
            continue
        m = pat_bytes_b.search(line)
        if m:
            tag = m.group(1).strip()
            bytes_by_tag[tag] = bytes_by_tag.get(tag, 0) + int(m.group(2)) + int(m.group(3))
            continue
        m = pat_bytes_c.search(line)
        if m:
            tag = m.group(2).strip()
            bytes_by_tag[tag] = bytes_by_tag.get(tag, 0) + int(m.group(3)) + int(m.group(4))
            continue
        m = pat_bytes_d.search(line)
        if m:
            tag = m.group(1).strip()
            bytes_by_tag[tag] = bytes_by_tag.get(tag, 0) + int(m.group(2)) + int(m.group(3))

    total_conn = len(via_direct) + len(via_exit) + len(via_block) + len(via_other)
    if total_conn == 0 and not bytes_by_tag:
        _box_warn("В access.log нет распарсенных записей маршрутизации")
        _box_warn("Возможно, loglevel=warning (access=none) или нестандартный формат")
        _box_info("Включить: config.json → log.access = '/var/log/xray/access.log'")
        return bytes_by_tag

    if total_conn > 0:
        _diag_ok(f"Всего соединений в выборке: {total_conn}")
        if via_exit:
            from collections import Counter
            _diag_ok(f"Через chain-exit (proxy): {len(via_exit)} соед.")
            for tag, cnt in Counter(t for _, _, t in via_exit).most_common():
                _box_dim(f"    {tag}: {cnt} ({cnt/len(via_exit)*100:.0f}%)")
        else:
            _box_warn("Через chain-exit (proxy): 0 соединений")
        if via_direct:
            _diag_ok(f"Напрямую (direct): {len(via_direct)} соед.")
            for h, p in via_direct[:5]:
                _box_dim(f"    direct: {h}:{p}")
            if len(via_direct) > 5:
                _box_dim(f"    ... и ещё {len(via_direct)-5}")
        else:
            _box_info(f"{BOLD}Напрямую (direct): 0 соединений{NC}")
            _box_info(f"  Если split tunneling включён, российский трафик должен идти direct")
        if via_block:
            _box_info(f"Заблокировано (BLOCK): {len(via_block)} соед.")
        if via_exit and via_direct:
            ratio = len(via_exit) / (len(via_direct) + len(via_exit)) * 100
            _diag_ok(f"Split tunneling: {ratio:.0f}% proxy / {100-ratio:.0f}% direct")
        elif via_exit and not via_direct:
            _box_info(f"{BOLD}Все соединения через proxy — split tunneling выключен или только заблокированный трафик{NC}")
        elif via_direct and not via_exit:
            _box_info(f"{BOLD}Все соединения direct — только российский трафик или split tunneling не работает{NC}")

    return bytes_by_tag


def _diag_check_error_log(counters: list) -> None:
    core = _core_module()
    _box_info = core._box_info
    _box_warn = core._box_warn
    _box_dim  = core._box_dim
    DIAG_ERROR_LOG = core.DIAG_ERROR_LOG
    _BOX_W         = core._BOX_W
    BOLD, NC       = core.BOLD, core.NC
    _diag_head("7. Анализ error.log (последние ошибки)")
    if not DIAG_ERROR_LOG.exists():
        _box_info("error.log не найден")
        return
    try:
        r = _diag_run(["tail", "-n", "100", str(DIAG_ERROR_LOG)])
        lines = [l for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        _box_warn("Не удалось прочитать error.log")
        return
    if not lines:
        _diag_ok("error.log пустой — ошибок нет")
        return

    # Известные штатные события — не являются реальными проблемами
    _BENIGN_PATTERNS = [
        "xtls rejected udp",          # QUIC/UDP на 443 — клиент откатится на TCP
        "broken pipe",                 # клиент закрыл соединение раньше сервера
        "connection reset by peer",    # RST от удалённого хоста — норма
        "splice: connection ends",     # zero-copy завершение соединения
        "proxy/freedom: connection ends",
        "use of closed network connection",
        "authentication failed",       # сканеры/боты стучатся не с тем UUID — норма
        "validation criteria not met", # то же — REALITY отверг неизвестное подключение
        "tcp_user_timeout",            # ядро не поддерживает опцию — не критично
        "failed to set tcp_user_timeout",
        "failed to apply socket options",
        "protocol not available",      # сопутствует TCP_USER_TIMEOUT на старых ядрах
    ]

    def _is_benign(line: str) -> bool:
        low = line.lower()
        return any(p in low for p in _BENIGN_PATTERNS)

    def _print_log_line(line: str) -> None:
        """Выводит строку лога целиком с переносом по ширине рамки. Без обрезания и маркеров."""
        indent = "  "
        wrap_w = max(_BOX_W - len(indent), 40)
        chunks = [line[i:i + wrap_w] for i in range(0, max(len(line), 1), wrap_w)]
        for chunk in chunks:
            _box_dim(f"{indent}{chunk}")

    geo_errs = [l for l in lines if "geosite" in l.lower() or "geoip" in l.lower()]
    if geo_errs:
        _diag_err(f"Ошибки geo-файлов ({len(geo_errs)} строк):")
        for line in geo_errs[-3:]:
            _print_log_line(line)
        counters[3] += 1
    else:
        _diag_ok("Ошибок geo-файлов не обнаружено")

    critical = [l for l in lines
                if ("failed" in l.lower() or "error" in l.lower())
                and not _is_benign(l)
                and l not in geo_errs]
    benign   = [l for l in lines if _is_benign(l)]

    if benign:
        _box_info(f"Штатные события (не ошибки): {len(benign)} строк — игнорируются")
        for pattern_note in [
            ("xtls rejected udp",              "XTLS rejected UDP/443 — клиент использует QUIC, xray переключит на TCP"),
            ("broken pipe",                    "broken pipe — клиент закрыл соединение первым"),
            ("connection reset by peer",       "connection reset — RST от удалённого хоста"),
            ("authentication failed",          "authentication failed — боты/сканеры стучатся с чужим UUID (норма)"),
            ("validation criteria not met",    "REALITY отверг постороннее подключение (норма)"),
            ("tcp_user_timeout",               "TCP_USER_TIMEOUT — ядро не поддерживает опцию (не критично)"),
            ("protocol not available",         "protocol not available — сопутствует TCP_USER_TIMEOUT на старых ядрах"),
        ]:
            if any(pattern_note[0] in l.lower() for l in benign):
                _box_dim(f"  · {pattern_note[1]}")

    if critical:
        _box_info(f"{BOLD}Нештатные ошибки: {len(critical)} строк (последние 3):{NC}")
        for line in critical[-3:]:
            _print_log_line(line)
        counters[2] += 1
    elif not geo_errs:
        _diag_ok(f"Нештатных ошибок нет (проверено {len(lines)} строк)")


def _diag_top_hosts(n: int = 15) -> None:
    """
    Топ хостов из access.log по направлениям: direct и chain-exit (proxy).
    Парсит последние 2000 строк лога — быстро и не нагружает диск.
    """
    core = _core_module()
    _box_info = core._box_info
    _box_warn = core._box_warn
    _box_row  = core._box_row
    _box_dim  = core._box_dim
    DIAG_ACCESS_LOG = core.DIAG_ACCESS_LOG
    BOLD = core.BOLD
    CYAN = core.CYAN
    DIM = core.DIM
    GREEN = core.GREEN
    NC = core.NC
    RED = core.RED
    YELLOW = core.YELLOW
    BOLD, NC, YELLOW, GREEN, DIM, CYAN, RED = (
        core.BOLD, core.NC, core.YELLOW, core.GREEN, core.DIM, core.CYAN, core.RED)
    _diag_head("8. Топ хостов по маршрутизации")
    if not DIAG_ACCESS_LOG.exists():
        _box_info("access.log не найден — топ недоступен")
        return
    try:
        r = _diag_run(["tail", "-n", "2000", str(DIAG_ACCESS_LOG)])
        lines = [l for l in r.stdout.splitlines() if "accepted" in l]
    except Exception:
        _box_warn("Не удалось прочитать access.log")
        return
    if not lines:
        _box_info("В access.log нет записей accepted — нет подключений или loglevel слишком высокий")
        return

    # Формат строки: ... accepted tcp:HOST:PORT [inbound-vless -> OUTTAG] ...
    pat = re.compile(
        r'accepted \w+:([^\s:]+):(\d+)\s+\[.*?->\s*([\w-]+)\]'
    )

    from collections import Counter
    direct_hosts:  Counter = Counter()
    proxy_hosts:   Counter = Counter()
    blocked_hosts: Counter = Counter()

    for line in lines:
        m = pat.search(line)
        if not m:
            continue
        host, port, tag = m.group(1), m.group(2), m.group(3)
        # Пропускаем служебные соединения к Stats API
        if host == "127.0.0.1":
            continue
        label = f"{host}:{port}" if port not in ("80", "443") else host
        if tag == "direct":
            direct_hosts[label] += 1
        elif "chain-exit" in tag or "balancer" in tag:
            proxy_hosts[label] += 1
        elif tag == "BLOCK":
            blocked_hosts[label] += 1

    total_direct = sum(direct_hosts.values())
    total_proxy  = sum(proxy_hosts.values())
    total_block  = sum(blocked_hosts.values())
    grand_total  = total_direct + total_proxy + total_block

    if grand_total == 0:
        _box_info("Соединений не найдено в последних 2000 строках лога")
        return

    _box_info(f"Последние 2000 строк лога | direct: {total_direct}  proxy: {total_proxy}  block: {total_block}")
    _box_row()

    def _print_top(counter: Counter, label: str, color: str) -> None:
        if not counter:
            return
        total = sum(counter.values())
        _box_row(f"  {color}{BOLD}{label}{NC}  ({total} соединений)")
        _box_row(f"  {'─'*44}")
        _max = counter.most_common(1)[0][1]
        for host, cnt in counter.most_common(n):
            bar_w   = 20
            pct     = cnt / total * 100
            # Цвет по % от максимума секции: яркий → бледный
            if cnt / _max >= 0.75:   bcol = color
            elif cnt / _max >= 0.40: bcol = YELLOW
            else:                    bcol = DIM + GREEN
            filled  = int(cnt / _max * bar_w)
            bar     = f"{bcol}{'▓' * filled}{NC}{DIM}{'░' * (bar_w - filled)}{NC}"
            _box_row(f"  {host:<32} {cnt:>5}  {pct:5.1f}%  {bar}")
        if len(counter) > n:
            _box_dim(f"  ... и ещё {len(counter) - n} хостов")
        _box_row()

    _print_top(proxy_hosts,   "→ PROXY (chain-exit)", CYAN)
    _print_top(direct_hosts,  "→ DIRECT (РФ / обход)", GREEN)
    _print_top(blocked_hosts, "→ BLOCK",              RED)

    # Вывод итогового split-ratio по соединениям
    if total_proxy and total_direct:
        ratio = total_proxy / (total_proxy + total_direct) * 100
        _diag_ok(f"Split по соединениям: {ratio:.1f}% proxy / {100-ratio:.1f}% direct")
    elif total_proxy and not total_direct:
        _box_info("Все соединения через proxy (direct = 0) — split tunneling не разделяет или только заблокированный трафик")
    elif total_direct and not total_proxy:
        _box_warn("Все соединения direct — split tunneling не работает или нет заблокированных сайтов в трафике")


def _diag_check_state(counters: list) -> None:
    core = _core_module()
    _box_warn = core._box_warn
    _box_info = core._box_info
    STATE_FILE               = core.STATE_FILE
    SPLIT_TUNNEL_CUSTOM_FILE = core.SPLIT_TUNNEL_CUSTOM_FILE
    BOLD = core.BOLD
    DIM = core.DIM
    GREEN = core.GREEN
    NC = core.NC
    YELLOW = core.YELLOW
    _diag_head("9. State файл установки")
    if not STATE_FILE.exists():
        _box_warn(f"{STATE_FILE} не найден — установка через скрипт не выполнялась?")
        return
    try:
        state = json.loads(STATE_FILE.read_text())
    except Exception as e:
        _diag_err(f"Не удалось разобрать state.json: {e}")
        return

    mode         = state.get("install_mode", "?")
    protocol     = state.get("protocol_mode", "?")
    split_on     = state.get("split_tunnel", False)
    # split_tunnel_custom.json обновляется меню [S] и имеет приоритет над state.json
    try:
        if SPLIT_TUNNEL_CUSTOM_FILE.exists():
            _custom = json.loads(SPLIT_TUNNEL_CUSTOM_FILE.read_text())
            if _custom.get("enabled", False):
                split_on = True
    except Exception:
        pass
    n_nodes      = len(state.get("chain_nodes", []))
    balancer_str = state.get("chain_balancer_strategy", "—")

    _box_info(f"Режим установки:      {mode}")
    _box_info(f"Протокол:             {protocol}")
    _box_info(f"Split tunneling:      {'ВКЛЮЧЕНО' if split_on else 'ОТКЛЮЧЕНО'}")
    if mode == "B":
        _box_info(f"Количество exit-нод:  {n_nodes}")
        _box_info(f"Стратегия балансира:  {balancer_str}")
        nodes = state.get("chain_nodes", [])
        if not nodes and state.get("chain_exit_host"):
            nodes = [{"host": state["chain_exit_host"],
                      "port": state.get("chain_exit_port", 443),
                      "sni":  state.get("chain_exit_sni", "")}]
        for i, nd in enumerate(nodes):
            _box_dim(f"  Нода #{i+1}: {nd.get('host','?')}:{nd.get('port','?')}  SNI={nd.get('sni','?')}")

    if split_on:
        _diag_ok("Split tunneling включён (российский трафик идёт напрямую)")
    else:
        _box_info("Split tunneling выключен — весь трафик через proxy (нормально для Режима B)")


def _diag_check_geo_autoupdate(counters: list) -> None:
    core = _core_module()
    _box_warn   = core._box_warn
    _box_bottom = core._box_bottom
    _diag_head("10. Автообновление geo-файлов")
    found = False
    for cron_path in Path("/etc/cron.d").glob("*"):
        try:
            content = cron_path.read_text()
            if "geosite" in content or "geoip" in content:
                _diag_ok(f"Cron задача найдена: {cron_path}")
                found = True
        except Exception:
            pass
    r = _diag_run(["systemctl", "list-timers", "--no-legend"])
    if "xray" in r.stdout and "geo" in r.stdout.lower():
        _diag_ok("Systemd timer для geo-обновления найден")
        found = True
    update_script = Path("/usr/local/bin/xray-geo-update.sh")
    if update_script.exists():
        _diag_ok(f"Скрипт обновления: {update_script}")
        found = True
    if not found:
        _box_warn("Автообновление geo-файлов не настроено")
        _box_warn("  Включите: пункт [S] → Управление split tunneling")
        counters[2] += 1
    _box_bottom()


def _diag_print_summary(counters: list) -> None:
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_bottom = core._box_bottom
    GREEN, YELLOW, RED, BOLD, DIM, NC = (
        core.GREEN, core.YELLOW, core.RED, core.BOLD, core.DIM, core.NC)
    LOG_FILE        = core.LOG_FILE
    DIAG_ACCESS_LOG = core.DIAG_ACCESS_LOG
    total, passed, warnings, errors = counters
    _box_top("ИТОГ ДИАГНОСТИКИ")
    _box_row(f"  Всего проверок:  {total}")
    _box_row(f"  {GREEN}Пройдено:        {passed}{NC}")
    if warnings:
        _box_row(f"  {YELLOW}Предупреждений:  {warnings}{NC}")
    if errors:
        _box_row(f"  {RED}Ошибок:          {errors}{NC}")
    _box_sep()
    if errors == 0 and warnings == 0:
        _box_row(f"{GREEN}{BOLD}  ✓ Split tunneling работает корректно{NC}")
    elif errors == 0:
        _box_row(f"{YELLOW}{BOLD}  ⚠ Split tunneling работает, есть замечания{NC}")
    else:
        _box_row(f"{RED}{BOLD}  ✗ Обнаружены проблемы — см. [ERR] выше{NC}")
    _box_row(f"{DIM}Лог установщика: {LOG_FILE}{NC}")
    _box_row(f"{DIM}Access log:      {DIAG_ACCESS_LOG}{NC}")
    _box_bottom()


# --------------------------------------------------------------------------- #
#  Точка входа диагностики — вызывается из меню установщика
# --------------------------------------------------------------------------- #

def run_split_tunnel_diagnostics() -> None:
    """
    Полная диагностика split tunneling.
    Вызывается из main_menu() или do_full_diagnostic().
    Не делает sys.exit(), не меняет глобальные переменные установщика.
    """
    core = _core_module()
    _box_row = core._box_row
    BOLD = core.BOLD
    DIM = core.DIM
    GREEN = core.GREEN
    NC = core.NC
    RED = core.RED
    YELLOW = core.YELLOW
    _box_row()

    counters = _diag_make_counters()

    _, cfg = _diag_resolve_config()

    _diag_check_xray_service(counters)
    _diag_check_geo_files(counters)
    cfg_path, cfg = _diag_check_config_structure(counters)
    _diag_check_outbounds(cfg, counters)
    _diag_check_routing_live(cfg, counters)
    bytes_by_tag = _diag_check_access_log(counters)
    _diag_print_traffic_volume(bytes_by_tag)
    _diag_check_error_log(counters)
    _diag_top_hosts()
    _diag_check_state(counters)
    _diag_check_geo_autoupdate(counters)
    _diag_print_summary(counters)
    _box_row()


def do_live_traffic_dashboard() -> None:
    """
    Отображает статистику трафика по outbound-тегам в реальном времени.
    Обновление каждые 3 секунды. Выход — Ctrl+C или 'q'.
    Использует Xray Stats API (порт 10085) если доступен,
    иначе fallback на 'ss -tni'.
    """
    core = _core_module()
    _box_top    = core._box_top
    _box_warn   = core._box_warn
    _box_row    = core._box_row
    _box_bottom = core._box_bottom
    info        = core.info
    warn        = core.warn
    success     = core.success
    XRAY_BIN            = core.XRAY_BIN
    XRAY_STATS_API_PORT = core.XRAY_STATS_API_PORT
    _BOX_W              = core._BOX_W
    CYAN = core.CYAN
    DIM = core.DIM
    GREEN = core.GREEN
    NC = core.NC
    WHITE = core.WHITE
    YELLOW = core.YELLOW
    CYAN, NC, DIM, GREEN, YELLOW, WHITE = (
        core.CYAN, core.NC, core.DIM, core.GREEN, core.YELLOW, core.WHITE)
    xray_bin = shutil.which("xray") or str(XRAY_BIN)

    def _fmt(n: int) -> str:
        if n < 1024:      return f"{n} Б"
        if n < 1048576:   return f"{n/1024:.1f} КБ"
        if n < 1073741824: return f"{n/1048576:.1f} МБ"
        return f"{n/1073741824:.2f} ГБ"

    def _get_stats_api() -> dict | None:
        try:
            r = subprocess.run(
                [xray_bin, "api", "statsquery",
                 f"--server=127.0.0.1:{XRAY_STATS_API_PORT}",
                 "--pattern=outbound>>>", "--reset=false"],
                capture_output=True, text=True, timeout=5
            )
            if r.returncode != 0 or not r.stdout.strip():
                return None
            data = json.loads(r.stdout.strip())
            stat_list = data.get("stat") or []
            result: dict[str, dict] = {}
            pat = re.compile(r'^outbound>>>([^>]+)>>>traffic>>>(uplink|downlink)$')
            for entry in stat_list:
                name = entry.get("name", "")
                val  = int(entry.get("value") or 0)
                m = pat.match(name)
                if m:
                    tag, direction = m.group(1), m.group(2)
                    result.setdefault(tag, {"up": 0, "down": 0})
                    result[tag]["up" if direction == "uplink" else "down"] += val
            return result
        except Exception:
            return None

    def _get_ss_stats() -> dict | None:
        try:
            r = subprocess.run(["ss", "-tni"], capture_output=True, text=True, timeout=5)
            total_sent = total_recv = 0
            lines = r.stdout.splitlines()
            for i, line in enumerate(lines):
                if line.startswith("ESTAB"):
                    for j in range(i+1, min(i+5, len(lines))):
                        sl = lines[j]
                        if "bytes_sent" in sl or "bytes_acked" in sl:
                            ms = re.search(r'bytes_(?:sent|acked):(\d+)', sl)
                            mr = re.search(r'bytes_received:(\d+)', sl)
                            total_sent += int(ms.group(1)) if ms else 0
                            total_recv += int(mr.group(1)) if mr else 0
                            break
            return {"kernel-tcp": {"up": total_sent, "down": total_recv}} if (total_sent or total_recv) else None
        except Exception:
            return None

    info("Live Dashboard запущен. Для выхода нажмите Ctrl+C")
    time.sleep(1)

    # Проверяем доступность Stats API
    api_ok = False
    try:
        r = subprocess.run(
            ["bash", "-c",
             f"timeout 2 bash -c 'echo >/dev/tcp/127.0.0.1/{XRAY_STATS_API_PORT}' 2>/dev/null && echo ok || echo fail"],
            capture_output=True, text=True
        )
        api_ok = r.stdout.strip() == "ok"
    except Exception:
        pass

    if not api_ok:
        warn("Stats API недоступен — используется fallback (ss -tni)")
        warn("Для полной статистики: убедитесь что xray запущен и stats API включён")

    interval = 3
    prev: dict = {}

    try:
        while True:
            os.system("clear")
            now = datetime.now().strftime('%H:%M:%S')
            _box_top(f"LIVE TRAFFIC DASHBOARD ── {now}  (Ctrl+C = выход)")

            stats = _get_stats_api() if api_ok else _get_ss_stats()

            if stats is None:
                _box_warn("Нет данных от Xray или ss. Xray запущен?")
            else:
                # Колонки: Tag адаптивный, Upload=10, Download=10, SpUp=10, SpDn=10
                # Итого доступно: _BOX_W - 2(отступ) - 4(пробелы между колонками) = inner
                # Tag = inner - 10 - 10 - 10 - 10
                _TW = max(12, _BOX_W - 2 - 4 - 10 - 10 - 10 - 10)
                _sep = "  " + "─" * (_BOX_W - 2)
                _box_row(f"  {'Тег':<{_TW}} {'↑ Upload':>10} {'↓ Download':>10} {'↑ Скор':>10} {'↓ Скор':>10}")
                _box_row(_sep)
                total_up = total_down = 0
                for tag, vals in sorted(stats.items()):
                    if tag in ("xray-stats-api",):
                        continue
                    up, down = vals.get("up", 0), vals.get("down", 0)
                    total_up   += up
                    total_down += down
                    prev_vals = prev.get(tag, {"up": 0, "down": 0})
                    up_speed   = max(0, up   - prev_vals.get("up",   0)) // interval
                    down_speed = max(0, down - prev_vals.get("down", 0)) // interval
                    sp_up   = f"{_fmt(up_speed)}/с"   if up_speed   else "—"
                    sp_down = f"{_fmt(down_speed)}/с" if down_speed else "—"
                    tag_d  = tag if len(tag) <= _TW else tag[:_TW-1] + "…"
                    colour = CYAN if "chain-exit" in tag or "direct" in tag else WHITE
                    _box_row(f"  {colour}{tag_d:<{_TW}}{NC} {_fmt(up):>10} {_fmt(down):>10} {GREEN}{sp_up:>10}{NC} {YELLOW}{sp_down:>10}{NC}")
                _box_row(_sep)
                _box_row(f"  {'ИТОГО':<{_TW}} {_fmt(total_up):>10} {_fmt(total_down):>10}")
                prev = {t: dict(v) for t, v in stats.items()}

            _box_row()
            src = "Stats API (точная накопленная)" if api_ok else "ss -tni (только активные соединения)"
            _box_row(f"  {DIM}Источник: {src} | Обновление каждые {interval}с{NC}")
            _box_bottom()
            time.sleep(interval)
    except KeyboardInterrupt:
        print()
        success("Dashboard завершён")


def do_full_diagnostic() -> None:
    """
    Объединённый пошаговый мастер диагностики.
    Шаги из оригинальной «одной кнопки»:
      Unit Tests, статус сервисов, связь, гео IP, split tunnel,
      внешняя проверка домена, тест скорости, DNS Leak.
    Дополнительные шаги wizard-а:
      Доступность порта снаружи (TCP), TLS/REALITY, конфиг xray -test,
      Stats API, exit-ноды latency, TTFB.
    В конце: итоговый отчёт с рекомендациями + отправка в поддержку.
    """
    core = _core_module()
    # ── Box helpers ──
    _box_top    = core._box_top
    _box_bottom = core._box_bottom
    _box_info   = core._box_info
    _box_row    = core._box_row
    _box_warn   = core._box_warn
    _box_ok     = core._box_ok
    _box_dim    = core._box_dim
    _box_sep    = core._box_sep
    _box_item   = core._box_item
    _run        = core._run
    info        = core.info
    warn        = core.warn
    success     = core.success
    # ── Functions ──
    verify_connectivity       = core.verify_connectivity
    check_exit_geo            = core.check_exit_geo
    do_speed_test             = core.do_speed_test
    do_dns_leak_test          = core.do_dns_leak_test
    run_unit_tests            = core.run_unit_tests
    do_check_domain_external  = core.do_check_domain_external
    _awg_diagnostic_all_nodes = core._awg_diagnostic_all_nodes
    _wcslen                   = core._wcslen
    log_to_file               = core.log_to_file
    # ── Constants ──
    STATE_FILE          = core.STATE_FILE
    PARAM_DOMAIN        = core.PARAM_DOMAIN
    SERVER_PORT         = core.SERVER_PORT
    PROTOCOL_MODE       = core.PROTOCOL_MODE
    CHAIN_NODES         = core.CHAIN_NODES
    CHAIN_EXIT_HOST     = core.CHAIN_EXIT_HOST
    CHAIN_EXIT_PORT     = core.CHAIN_EXIT_PORT
    INSTALL_MODE        = core.INSTALL_MODE
    CONFIG_DIR          = core.CONFIG_DIR
    XRAY_BIN            = core.XRAY_BIN
    XRAY_STATS_API_PORT = core.XRAY_STATS_API_PORT
    LOG_FILE            = core.LOG_FILE
    BOLD = core.BOLD
    CYAN = core.CYAN
    DIM = core.DIM
    GREEN = core.GREEN
    NC = core.NC
    RED = core.RED
    YELLOW = core.YELLOW
    TG_CONFIG_FILE      = getattr(core, "TG_CONFIG_FILE", None)
    AWG_INTERFACE       = core.AWG_INTERFACE
    AWG_FWMARK          = core.AWG_FWMARK
    AWG_ROUTE_TABLE     = core.AWG_ROUTE_TABLE
    AWG_EXIT_HOST       = core.AWG_EXIT_HOST
    AWG_EXIT_PORT       = core.AWG_EXIT_PORT
    AWG_BIN             = core.AWG_BIN
    _BOX_W              = core._BOX_W
    # ── Colors ──
    CYAN, NC, DIM, GREEN, RED, YELLOW, BOLD = (
        core.CYAN, core.NC, core.DIM, core.GREEN, core.RED, core.YELLOW, core.BOLD)
    import io as _io
    import socket as _socket

    os.system("clear")

    ts          = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = Path(f"/root/xray-diagnostic-{ts}.txt")

    # ── Tee: дублируем stdout в буфер (без ANSI) ────────────────────────────
    _orig_stdout = sys.stdout
    _report_buf  = _io.StringIO()

    class _Tee:
        def write(self, data):
            _orig_stdout.write(data)
            _report_buf.write(re.sub(r'\033\[[0-9;]*m', '', data))
        def flush(self):
            _orig_stdout.flush()
        def isatty(self):
            return _orig_stdout.isatty() if hasattr(_orig_stdout, 'isatty') else False

    sys.stdout = _Tee()

    # ── Вспомогательные функции ──────────────────────────────────────────────
    def _section(title: str) -> None:
        _box_bottom()
        _box_top(title)

    def _run_safe(fn) -> None:
        try:
            fn()
        except Exception as e:
            _box_warn(f"Ошибка: {e}")

    def _pause(label: str = "Для продолжения нажмите Enter...") -> None:
        """Пауза — выводится вне Tee, не попадает в отчёт."""
        sys.stdout = _orig_stdout
        try:
            print()
            print(f"  {DIM}{'─' * max(_BOX_W - 2, 10)}{NC}")
            input(f"  {CYAN}{label}{NC} ")
            print(f"  {DIM}{'─' * max(_BOX_W - 2, 10)}{NC}")
            print()
        except (KeyboardInterrupt, EOFError):
            pass
        sys.stdout = _Tee()

    # Статусные маркеры для итогового отчёта
    _PASS = "✔ PASS"
    _FAIL = "✖ FAIL"
    _WARN = "⚠ WARN"
    _SKIP = "- SKIP"
    _results: list[tuple[str, str, str]] = []  # (шаг, статус, рекомендация)

    def _res(step: str, status: str, rec: str = "") -> None:
        _results.append((step, status, rec))

    def _wiz_hint(msg: str) -> None:
        _box_row(f"  {YELLOW}→{NC} {DIM}{msg}{NC}")

    # ── Сохраняем _BOX_W — будем восстанавливать после диагностики ──────────
    # Все барграфики внутри функции рассчитывают свою ширину через _BOX_W,
    # поэтому не трогаем его значение — только сохраняем для restore в finally.
    _saved_BOX_W = _BOX_W

    # ── Загрузка state ───────────────────────────────────────────────────────
    _state: dict = {}
    try:
        if STATE_FILE.exists():
            _state = json.loads(STATE_FILE.read_text())
    except Exception:
        pass

    _domain      = _state.get("domain", PARAM_DOMAIN or "")
    _server_port = int(_state.get("server_port", SERVER_PORT or 443))
    _proto_mode  = _state.get("protocol_mode", PROTOCOL_MODE or "reality")
    _nodes: list[dict] = _state.get("chain_nodes", CHAIN_NODES or [])
    _exit_host = _state.get("chain_exit_host", CHAIN_EXIT_HOST or "")
    _exit_port = int(_state.get("chain_exit_port", CHAIN_EXIT_PORT or 443))
    if not _nodes and _exit_host:
        _nodes = [{"host": _exit_host, "port": _exit_port}]

    # ════════════════════════════════════════════════════════════════════════
    try:
        print()
        _box_top("🔬  Мастер полной диагностики")
        _box_info(f"Отчёт будет сохранён в: {report_path}")
        _box_row(f"  Дата    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        _box_row(f"  Домен   : {CYAN}{_domain or '(не задан)'}{NC}")
        _box_row(f"  Порт    : {CYAN}{_server_port}{NC}")
        _box_row(f"  Протокол: {CYAN}{_proto_mode.upper()}{NC}")
        _box_row(f"  {DIM}Всего шагов: 14. После каждого шага — пауза.{NC}")
        _box_bottom()
        _pause("Готово. Enter — начать диагностику...")

        # ── 1. Unit Tests ────────────────────────────────────────────────────
        _box_top("1 / 14  ·  Unit Tests")
        _run_safe(run_unit_tests)
        _box_bottom()
        _pause("Шаг 1 завершён. Enter — продолжить...")

        # ── 2. Статус сервисов (расширенный) ────────────────────────────────
        _box_top("2 / 14  ·  Статус сервисов")
        _svc_issues: list[str] = []
        # При AWG добавляем amneziawg-awg0 в список обязательных сервисов
        _awg_mode = _state.get("awg_exit_enabled", False) and _state.get("install_mode") == "B"
        _svcs_to_check = ["xray", "nginx", "dnscrypt-proxy"]
        if _awg_mode:
            _svcs_to_check.insert(1, "amneziawg-awg0")
        for _svc in _svcs_to_check:
            _ra  = _run(["systemctl", "is-active",  _svc], capture=True, check=False)
            _re2 = _run(["systemctl", "is-enabled", _svc], capture=True, check=False)
            _active   = _ra.stdout.strip()  == "active"
            _enabled  = _re2.stdout.strip() in ("enabled", "static")
            # ИСПРАВЛЕНИЕ: amneziawg-awg0 — Type=oneshot RemainAfterExit=yes.
            # Если ExecStart завершился с ошибкой (напр. модуль ядра не загрузился),
            # systemctl is-active = inactive, но интерфейс awg0 мог остаться
            # поднятым с предыдущего сеанса или быть поднят другим способом.
            # Реальный признак работы туннеля — наличие интерфейса awg0.
            if _svc == "amneziawg-awg0" and not _active:
                _r_link = _run(["ip", "link", "show", AWG_INTERFACE],
                               capture=True, check=False)
                if _r_link.returncode == 0 and AWG_INTERFACE in (_r_link.stdout or ""):
                    _active = True  # туннель жив, сервис просто не отслеживает
            # ИСПРАВЛЕНИЕ: dnscrypt-proxy опционален всегда (не каждый ставит).
            # amneziawg-awg0 обязателен только в AWG-режиме.
            # Для опциональных сервисов не показываем красный цвет при inactive —
            # это не ошибка, просто «не используется».
            _optional = (_svc == "dnscrypt-proxy") or (
                _svc == "amneziawg-awg0" and not _awg_mode
            )
            # Цвет dot и строки: для опциональных inactive — серый, не красный
            if _active:
                _dot     = f"{GREEN}●{NC}"
                _act_str = f"{GREEN}active{NC}"
            elif _optional:
                _dot     = f"{DIM}○{NC}"
                _act_str = f"{DIM}inactive{NC}"
            else:
                _dot     = f"{RED}○{NC}"
                _act_str = f"{RED}inactive{NC}"
            if _enabled:
                _ena_str = f"{GREEN}enabled{NC}"
            elif _optional and not _active:
                # Опциональный и не запущен — не пугаем жёлтым "disabled"
                _ena_str = f"{DIM}disabled{NC}"
            else:
                _ena_str = f"{YELLOW}disabled{NC}"
            # Пометка "(опц.)" для dnscrypt чтобы не вводило в заблуждение
            _svc_label = f"{_svc} {DIM}(опц.){NC}" if _optional else _svc
            _box_row(f"  {_dot}  {_svc_label:<22} {_act_str}  |  {_ena_str}")
            if not _active and not _optional:
                _svc_issues.append(_svc)
                _wiz_hint(f"systemctl start {_svc} && systemctl enable {_svc}")
                _rj = _run(["journalctl", "-u", _svc, "-n", "5", "--no-pager"],
                           capture=True, check=False)
                if _rj.stdout.strip():
                    _box_sep()
                    _box_dim(f"  Последние записи журнала {_svc}:")
                    for _jl in _rj.stdout.strip().splitlines()[-5:]:
                        _box_dim(f"    {_jl[:_BOX_W - 6]}")
        if _svc_issues:
            _box_warn(f"Не запущены: {', '.join(_svc_issues)}")
            _res("2. Сервисы", _FAIL, f"Не запущены: {', '.join(_svc_issues)}")
        else:
            _box_ok("Все обязательные сервисы активны")
            _res("2. Сервисы", _PASS)
        _box_bottom()
        _pause("Шаг 2 завершён. Enter — продолжить...")

        # ── 3. Проверка связи ────────────────────────────────────────────────
        _box_top("3 / 14  ·  Проверка связи")
        _run_safe(verify_connectivity)
        _box_bottom()
        _pause("Шаг 3 завершён. Enter — продолжить...")

        # ── 4. Доступность порта снаружи (TCP) ──────────────────────────────
        _box_top("4 / 14  ·  Доступность порта снаружи (TCP)")
        _box_info(f"  Проверяем {_domain or 'сервер'}:{_server_port} (таймаут 8 с)...")
        if not _domain:
            _box_warn("Домен не задан — пропуск")
            _res("4. Порт снаружи", _SKIP, "Домен не задан")
        else:
            try:
                _t0   = time.time()
                _sock = _socket.create_connection((_domain, _server_port), timeout=8)
                _sock.close()
                _tcp_ms = int((time.time() - _t0) * 1000)
                _ms_col = GREEN if _tcp_ms < 200 else YELLOW if _tcp_ms < 500 else RED
                _box_ok(f"Порт {_server_port} отвечает ({_ms_col}{_tcp_ms} ms{NC})")
                _res("4. Порт снаружи", _PASS)
            except _socket.timeout:
                _box_warn(f"Порт {_server_port} — таймаут")
                _wiz_hint(f"ufw status | grep {_server_port}")
                _wiz_hint(f"ss -tlnp | grep {_server_port}")
                _res("4. Порт снаружи", _FAIL,
                     f"Таймаут на {_server_port}. Проверьте UFW/iptables.")
            except ConnectionRefusedError:
                _box_warn(f"Порт {_server_port} — Connection Refused")
                _wiz_hint(f"ss -tlnp | grep {_server_port}  — xray не слушает?")
                _res("4. Порт снаружи", _FAIL, "Connection Refused")
            except Exception as _pe:
                _box_warn(f"Порт {_server_port} — ошибка: {_pe}")
                _res("4. Порт снаружи", _FAIL, str(_pe))
        _box_bottom()
        _pause("Шаг 4 завершён. Enter — продолжить...")

        # ── 5. Геопроверка выходного IP ──────────────────────────────────────
        # check_exit_geo(silent=False) сама открывает и закрывает все боксы
        _run_safe(lambda: check_exit_geo(silent=False))
        _pause("Шаг 5 завершён. Enter — продолжить...")

        # ── 6. TLS / REALITY ─────────────────────────────────────────────────
        _box_top("6 / 14  ·  TLS-сертификат / REALITY")
        if _proto_mode == "reality":
            _sni = (_state.get("reality_sni") or _state.get("sni") or
                    _domain or "www.google.com")
            _box_info(f"  Режим REALITY: проверяем SNI-цель ({_sni})...")
            _rc = _run(
                ["bash", "-c",
                 f"echo Q | timeout 8 openssl s_client "
                 f"-connect {_sni}:443 -servername {_sni} 2>/dev/null "
                 f"| openssl x509 -noout -dates -subject 2>/dev/null"],
                capture=True, check=False
            )
            if _rc.returncode == 0 and _rc.stdout.strip():
                # ИСПРАВЛЕНИЕ: строки сертификата (особенно subject=) могут быть очень
                # длинными и уезжать за границу бокса. Разбиваем на части по _BOX_W-6.
                _cert_col_w = max(20, _BOX_W - 6)
                for _ln in _rc.stdout.strip().splitlines():
                    _ln_s = _ln.strip()
                    if len(_ln_s) <= _cert_col_w:
                        _box_row(f"  {DIM}{_ln_s}{NC}")
                    else:
                        # Разбиваем длинную строку на несколько строк бокса
                        # Первая строка — ключ (до '=') + начало значения
                        _prefix, _, _rest = _ln_s.partition("=")
                        _prefix = (_prefix + "=").strip() if _ else ""
                        _first_val_w = _cert_col_w - len(_prefix) - 1
                        if _prefix and _first_val_w > 8:
                            _box_row(f"  {DIM}{_prefix} {_rest[:_first_val_w]}{NC}")
                            _rest = _rest[_first_val_w:]
                            _indent = " " * (len(_prefix) + 1)
                        else:
                            _indent = "  "
                            _rest = _ln_s
                        while _rest:
                            _chunk_w = _cert_col_w - len(_indent)
                            _box_row(f"  {DIM}{_indent}{_rest[:_chunk_w]}{NC}")
                            _rest = _rest[_chunk_w:]
                _box_ok(f"SNI-цель ({_sni}) доступна и сертификат валиден")
                _res("6. TLS/REALITY", _PASS)
            else:
                _box_warn(f"Не удалось получить сертификат от {_sni}:443")
                _wiz_hint("SNI-домен должен быть доступен с сервера")
                _res("6. TLS/REALITY", _WARN, f"SNI-цель {_sni} недоступна")
        else:
            _cert_path = Path(f"/etc/letsencrypt/live/{_domain}/fullchain.pem") if _domain else None
            if not _cert_path or not _cert_path.exists():
                _box_warn(f"Сертификат не найден: {_cert_path}")
                _wiz_hint(f"certbot certonly --nginx -d {_domain or 'ваш_домен'}")
                _res("6. TLS-сертификат", _FAIL, "Файл сертификата не найден")
            else:
                _rcc = _run(["openssl", "x509", "-in", str(_cert_path),
                             "-noout", "-enddate", "-subject", "-issuer"],
                            capture=True, check=False)
                _expiry_raw = ""
                for _ln in _rcc.stdout.strip().splitlines():
                    _box_row(f"  {DIM}{_ln}{NC}")
                    if _ln.startswith("notAfter="):
                        _expiry_raw = _ln.split("=", 1)[1]
                try:
                    _rd = _run(["date", "-d", _expiry_raw, "+%s"], capture=True, check=False)
                    _days_left = (int(_rd.stdout.strip()) - int(time.time())) // 86400
                    if _days_left < 0:
                        _box_warn(f"Сертификат ИСТЁК {abs(_days_left)} дней назад!")
                        _wiz_hint("certbot renew --force-renewal")
                        _res("6. TLS-сертификат", _FAIL, f"Истёк {abs(_days_left)} дн.")
                    elif _days_left < 14:
                        _box_warn(f"Сертификат истекает через {_days_left} дней!")
                        _wiz_hint("certbot renew")
                        _res("6. TLS-сертификат", _WARN, f"Истекает через {_days_left} дн.")
                    else:
                        _box_ok(f"Сертификат действителен ещё {_days_left} дней")
                        _res("6. TLS-сертификат", _PASS)
                except Exception:
                    _box_ok("Сертификат найден (срок не вычислен)")
                    _res("6. TLS-сертификат", _PASS)
        _box_bottom()
        _pause("Шаг 6 завершён. Enter — продолжить...")

        # ── 7. Конфиг Xray (-test) + REALITY ключи ──────────────────────────
        _box_top("7 / 14  ·  Конфиг Xray (xray -test)")
        _cfg_path_d, _cfg_d = _diag_resolve_config()
        if not _cfg_d:
            _box_warn("Конфиг Xray не найден")
            _wiz_hint(f"{CONFIG_DIR}/config.json")
            _res("7. Конфиг/REALITY", _FAIL, "config.json не найден")
        else:
            _box_info(f"  Конфиг: {_cfg_path_d}")
            _rt = _run([str(XRAY_BIN), "run", "-test", "-config", str(_cfg_path_d)],
                       capture=True, check=False)
            if _rt.returncode == 0:
                _box_ok("xray -test: конфиг валиден")
                _cfg_ok = True
            else:
                _stderr_tail = (_rt.stderr or _rt.stdout or "")[-600:]
                _box_warn("xray -test: ошибки в конфиге!")
                for _el in _stderr_tail.splitlines()[-6:]:
                    _box_row(f"  {RED}{DIM}{_el[:_BOX_W - 4]}{NC}")
                _wiz_hint("Исправьте конфиг и перезапустите: systemctl restart xray")
                _cfg_ok = False
                _res("7. Конфиг/REALITY", _FAIL, "xray -test вернул ошибки")
            if _cfg_ok and _proto_mode == "reality":
                _box_sep()
                _box_info("  Проверяем realitySettings в inbounds...")
                _reality_found = False
                for _ib in _cfg_d.get("inbounds", []):
                    _rs = _ib.get("streamSettings", {}).get("realitySettings", {})
                    if not _rs:
                        continue
                    _reality_found = True
                    _priv      = _rs.get("privateKey", "")
                    _short_ids = _rs.get("shortIds", [])
                    _sni_list  = _rs.get("serverNames", [])
                    _flow_val  = (_ib.get("settings", {})
                                  .get("clients", [{}])[0].get("flow", ""))
                    if _priv and _short_ids:
                        _box_ok(f"REALITY: privateKey задан ({'*' * 8 + _priv[-4:]})")
                        _box_ok(f"REALITY: shortIds — {len(_short_ids)} шт.: "
                                f"{', '.join(_short_ids[:3])}")
                        _box_ok(f"REALITY: serverNames — {', '.join(_sni_list[:3])}")
                        if _flow_val:
                            _box_ok(f"REALITY: flow = {_flow_val}")
                        else:
                            _box_warn("flow не задан — рекомендуется xtls-rprx-vision")
                        _res("7. Конфиг/REALITY", _PASS)
                    else:
                        _box_warn("REALITY: privateKey или shortIds пустые!")
                        _wiz_hint("xray x25519  — сгенерируйте новые ключи")
                        _res("7. Конфиг/REALITY", _FAIL,
                             "privateKey или shortIds пусты")
                    break
                if not _reality_found:
                    _box_info("  realitySettings не найден (возможно, xHTTP)")
                    if _cfg_ok:
                        _res("7. Конфиг/REALITY", _PASS)
            elif _cfg_ok:
                _res("7. Конфиг/REALITY", _PASS)
        _box_bottom()
        _pause("Шаг 7 завершён. Enter — продолжить...")

        # ── 8. Stats API ──────────────────────────────────────────────────────
        _box_top("8 / 14  ·  Stats API (gRPC)")
        _box_info(f"  Проверяем 127.0.0.1:{XRAY_STATS_API_PORT}...")
        _stats_ok = _diag_stats_api_available()
        if _stats_ok:
            _box_ok(f"Stats API доступен на 127.0.0.1:{XRAY_STATS_API_PORT}")
            _api_data = _diag_get_stats_via_api()
            if _api_data:
                _total_bytes = sum(_api_data.values())
                _box_ok(f"Статистика: {_diag_fmt_bytes(_total_bytes)} "
                        f"по {len(_api_data)} тегам")
                _max_stat_val = max(_api_data.values()) or 1  # защита от деления на ноль
                for _tag, _byt in list(_api_data.items())[:5]:
                    # ширина бара: BOX_W минус фиксированная часть
                    # '  ' + tag(28) + '  ' + bar + '  ' + bytes(~10) = 2+28+2+2+10 = 44
                    _BAR_W8 = max(10, _BOX_W - 44)
                    _bw = min(_BAR_W8, int(_byt / _max_stat_val * _BAR_W8))
                    _bar = f"{GREEN}{'▓' * _bw}{'░' * (_BAR_W8 - _bw)}{NC}"
                    _box_row(f"  {DIM}{_tag:<28}{NC}  {_bar}  {_diag_fmt_bytes(_byt)}")
            else:
                _box_info("  API доступен, данных пока нет")
            _res("8. Stats API", _PASS)
        else:
            _box_warn(f"Stats API недоступен на 127.0.0.1:{XRAY_STATS_API_PORT}")
            _wiz_hint("В config.json нужны секции: 'stats', 'api', 'policy'")
            _wiz_hint("Меню → Диагностика → [P] Патч Stats API")
            _res("8. Stats API", _WARN, "gRPC недоступен — статистика не работает")
        _box_bottom()
        _pause("Шаг 8 завершён. Enter — продолжить...")

        # ── 9. Диагностика split tunneling ───────────────────────────────────
        _box_top("9 / 14  ·  Диагностика split tunneling")
        try:
            _run_safe(run_split_tunnel_diagnostics)
        except NameError:
            _box_warn("Функция split tunneling недоступна")
        _box_bottom()
        _pause("Шаг 9 завершён. Enter — продолжить...")

        # ── 10. Внешняя проверка домена ───────────────────────────────────────
        _box_top("10 / 14  ·  Внешняя проверка домена")
        _run_safe(do_check_domain_external)
        _box_bottom()
        _pause("Шаг 10 завершён. Enter — продолжить...")

        # ── 11. Exit-ноды — latency ───────────────────────────────────────────
        _box_top("11 / 14  ·  Exit-ноды: latency")
        _awg_diag = _state.get("awg_exit_enabled", False) and _state.get("install_mode") == "B"
        if _awg_diag:
            # === PATCH v2: если есть мульти-ноды — используем расширенную диагностику ===
            if _state.get("awg_nodes") and len(_state.get("awg_nodes", [])) > 1:
                _awg_diagnostic_all_nodes(_state)
                _res("11. AWG Multi-Node", _PASS if _state.get("awg_nodes") else _WARN)
            else:
                # Оригинальная одиночная диагностика awg0
                _box_info("  Режим AWG 2.0 — проверяем туннель awg0...")
                _r_awg_if = _run(["ip", "link", "show", "awg0"], capture=True, check=False)
                _awg_if_ok = _r_awg_if.returncode == 0
                if _awg_if_ok:
                    _box_ok("Интерфейс awg0 присутствует")
                else:
                    _box_warn("awg0 не найден — туннель не поднят!")
                    _wiz_hint("systemctl status amneziawg-awg0")
                _r_rule = _run(["ip", "rule", "show"], capture=True, check=False)
                # ИСПРАВЛЕНИЕ: ядро может выводить fwmark как decimal ("1000") или
                # hex ("0x3e8") — проверяем оба варианта.
                _rule_out = _r_rule.stdout or ""
                _fwmark_in_rule = (
                    f"fwmark {AWG_FWMARK}"       in _rule_out or
                    f"fwmark 0x{AWG_FWMARK:x}"  in _rule_out or
                    f"fwmark 0x{AWG_FWMARK:X}"  in _rule_out
                )
                if _fwmark_in_rule:
                    _box_ok(f"ip rule fwmark {AWG_FWMARK} присутствует")
                else:
                    _box_warn(f"ip rule fwmark {AWG_FWMARK} ОТСУТСТВУЕТ — маршрутизация через awg0 не работает!")
                    _wiz_hint("Аварийное восстановление из меню → восстановит маршруты")
                    _wiz_hint(f"ip rule add fwmark {AWG_FWMARK} lookup {AWG_ROUTE_TABLE}")
                # Пинг через awg0 до exit-VPS
                _awg_host = _state.get("awg_exit_host", AWG_EXIT_HOST or "")
                _awg_port = int(_state.get("awg_exit_port", AWG_EXIT_PORT))
                if _awg_host:
                    # ИСПРАВЛЕНИЕ: AWG использует UDP — TCP-проверка через socket.create_connection()
                    # всегда даёт Connection Refused / timeout, даже при рабочем туннеле.
                    # Вместо этого проверяем реальный признак работы туннеля:
                    # наличие handshake в выводе `awg show` (latest handshake не нулевой)
                    # и доступность маршрута через awg0 (ping до внутреннего AWG-адреса).
                    _awg_alive = False
                    _awg_latency_ms = -1

                    # 1. Проверяем handshake через awg/wg show
                    # ИСПРАВЛЕНИЕ: AWG_BIN — глобальная константа пути, но бинарь
                    # мог быть установлен в другое место. Ищем динамически.
                    _awg_bin_candidates = [
                        str(AWG_BIN),
                        "/usr/local/bin/awg",
                        "/usr/bin/awg",
                        "awg",
                        "wg",
                    ]
                    _awg_bin_d = next(
                        (b for b in _awg_bin_candidates
                         if _run(["which", b] if "/" not in b else ["test", "-x", b],
                                 capture=True, check=False).returncode == 0),
                        None
                    )
                    if _awg_bin_d:
                        try:
                            _r_show = _run([_awg_bin_d, "show", AWG_INTERFACE,
                                            "latest-handshakes"],
                                           capture=True, check=False)
                            if _r_show.returncode == 0 and _r_show.stdout.strip():
                                for _hs_line in _r_show.stdout.strip().splitlines():
                                    _hs_parts = _hs_line.split()
                                    if len(_hs_parts) >= 2:
                                        _hs_ts = int(_hs_parts[-1])
                                        if _hs_ts > 0:
                                            _awg_alive = True
                                            _hs_ago = int(time.time()) - _hs_ts
                                            _hs_ago_str = (f"{_hs_ago}с" if _hs_ago < 120
                                                           else f"{_hs_ago // 60}м")
                                            _box_ok(f"AWG handshake: {_hs_ago_str} назад")
                                        else:
                                            _box_warn("AWG: нет handshake — туннель не установлен")
                            else:
                                _box_row(f"  {DIM}awg show: нет данных о пирах{NC}")
                        except Exception as _hs_e:
                            _box_row(f"  {DIM}awg show недоступен: {_hs_e}{NC}")
                    else:
                        _box_row(f"  {DIM}awg/wg бинарник не найден — handshake не проверен{NC}")

                    # 2. Ping до AWG-адреса exit-VPS через awg0 (внутренний адрес туннеля)
                    _awg_server_ip = _state.get("awg_server_ip", "")
                    if _awg_server_ip:
                        _r_ping = _run(
                            ["ping", "-c", "1", "-W", "3", "-I", AWG_INTERFACE, _awg_server_ip],
                            capture=True, check=False
                        )
                        if _r_ping.returncode == 0:
                            import re as _re_ping
                            _m = _re_ping.search(r"time=([\d.]+)", _r_ping.stdout)
                            if _m:
                                _awg_latency_ms = int(float(_m.group(1)))
                                _lc = GREEN if _awg_latency_ms < 150 else YELLOW if _awg_latency_ms < 300 else RED
                                _box_ok(f"Ping через awg0 → {_awg_server_ip}: {_lc}{_awg_latency_ms} мс{NC}")
                                _awg_alive = True
                            else:
                                _box_ok(f"Ping через awg0 → {_awg_server_ip}: OK")
                                _awg_alive = True
                        else:
                            _box_warn(f"Ping через awg0 → {_awg_server_ip}: нет ответа")
                    else:
                        # Нет внутреннего IP — проверяем только через handshake
                        _box_row(f"  {DIM}awg_server_ip не задан — ping через awg0 пропущен{NC}")

                    # 3. Итог
                    # ИСПРАВЛЕНИЕ: если handshake не проверен (нет бинаря, нет awg_server_ip),
                    # но awg0 поднят И ip rule fwmark присутствует — это достаточный признак
                    # работы туннеля. Не выдаём WARN/FAIL в этом случае.
                    if not _awg_alive and _awg_if_ok and _fwmark_in_rule:
                        _awg_alive = True
                        _box_ok("AWG: интерфейс и маршрут активны (handshake не проверен)")
                    _lat_str = f", latency {_awg_latency_ms} мс" if _awg_latency_ms >= 0 else ""
                    if _awg_alive:
                        _res("11. AWG-туннель", _PASS,
                             f"awg0 активен, rule OK, exit {_awg_host}{_lat_str}")
                    else:
                        _box_warn(f"AWG-туннель к {_awg_host}:{_awg_port}/udp не установлен")
                        _res("11. AWG-туннель", _WARN if _awg_if_ok else _FAIL,
                             f"Нет handshake с {_awg_host}")
                else:
                    _res("11. AWG-туннель", _PASS if (_awg_if_ok and _fwmark_in_rule) else _FAIL)
        # === END PATCH v2: мульти-нодовый else закрыт ===
        elif not _nodes:
            _box_info("  Нет exit-нод (одиночный сервер) — шаг пропущен")
            _res("11. Exit-ноды", _SKIP, "Нет exit-нод (режим A)")
        else:
            _node_fails: list[str] = []
            _max_lat = 0
            for _ni, _nd in enumerate(_nodes, 1):
                _nh = _nd.get("host", "")
                _np = int(_nd.get("port", 443))
                if not _nh:
                    continue
                # Одна строка: [N/M] → host:port     Xms  (ms выровнен вправо)
                # host:port обрезается и выравнивается ljust до _HP_W символов,
                # затем латентность правым краем через rjust.
                # _HP_W = 32 (достаточно для большинства hostname)
                _HP_W = 32
                _hp   = f"{_nh}:{_np}"[:_HP_W]   # host:port, обрезанный
                _idx  = f"[{_ni}/{len(_nodes)}] → "
                try:
                    _t0 = time.time()
                    _ns = _socket.create_connection((_nh, _np), timeout=8)
                    _ns.close()
                    _lat_ms = int((time.time() - _t0) * 1000)
                    _max_lat = max(_max_lat, _lat_ms)
                    _lc = GREEN if _lat_ms < 150 else YELLOW if _lat_ms < 300 else RED
                    _lat_str = f"{_lc}{_lat_ms:>4}ms{NC}"
                    _box_info(f"  {_idx}{_hp:<{_HP_W}}  {_lat_str}")
                    if _lat_ms >= 300:
                        _wiz_hint(f"Высокая latency к {_nh} — попробуй: mtr {_nh}")
                except _socket.timeout:
                    _box_info(f"  {_idx}{_hp:<{_HP_W}}  {RED}timeout{NC}")
                    _wiz_hint(f"Firewall exit-сервера {_nh}: порт {_np} открыт?")
                    _node_fails.append(f"{_nh}:{_np}")
                except Exception as _ne:
                    _box_info(f"  {_idx}{_hp:<{_HP_W}}  {RED}{str(_ne)[:12]}{NC}")
                    _node_fails.append(f"{_nh}:{_np}")
            if _node_fails:
                _box_warn(f"Недоступны: {', '.join(_node_fails)}")
                _res("11. Exit-ноды", _FAIL, f"Недоступны: {', '.join(_node_fails)}")
            elif _max_lat >= 300:
                _box_warn(f"Все ноды доступны, max latency = {_max_lat} ms")
                _res("11. Exit-ноды", _WARN, f"Высокая latency ({_max_lat} ms)")
            else:
                _box_ok(f"Все {len(_nodes)} exit-нод(ы) доступны")
                _res("11. Exit-ноды", _PASS)
        _box_bottom()
        _pause("Шаг 11 завершён. Enter — продолжить...")

        # ── 12. Тест скорости ────────────────────────────────────────────────
        _box_top("12 / 14  ·  Тест скорости")
        _run_safe(lambda: do_speed_test(auto_mode=True))
        _box_bottom()
        _pause("Шаг 12 завершён. Enter — продолжить...")

        # ── 13. TTFB ─────────────────────────────────────────────────────────
        _box_top("13 / 14  ·  TTFB — время до первого байта")
        _ttfb_vals: list[int] = []
        for _tname, _turl in [
            ("Google",     "https://www.google.com"),
            ("Cloudflare", "https://1.1.1.1"),
            ("Yandex",     "https://ya.ru"),
            ("GitHub",     "https://github.com"),
            ("Quad9",      "https://9.9.9.9"),
        ]:
            _tr = _run(
                ["curl", "-s", "-o", "/dev/null",
                 "-w", "%{time_starttransfer} %{http_code} %{time_connect}",
                 "--max-time", "10", "--connect-timeout", "5", _turl],
                capture=True, check=False
            )
            _parts = _tr.stdout.strip().split()
            if _tr.returncode == 0 and _parts:
                try:
                    _ttfb_ms   = int(float(_parts[0]) * 1000)
                    _http_code = _parts[1] if len(_parts) > 1 else "?"
                    _conn_ms   = int(float(_parts[2]) * 1000) if len(_parts) > 2 else 0
                    _tc = GREEN if _ttfb_ms < 200 else YELLOW if _ttfb_ms < 500 else RED
                    # ширина бара: BOX_W минус '  ' + tname(14) + ' ' + bar + ' ' + ttfb(5) + ' мс' = 2+14+1+1+5+3 = 26
                    # суффикс '  TCP N мс  HTTP 200' (~20 символов) выносим на отдельную строку
                    _BAR_W13 = max(10, _BOX_W - 26)
                    _bw = min(_BAR_W13, _ttfb_ms // 30)
                    _bar = f"{_tc}{'▓' * _bw}{'░' * (_BAR_W13 - _bw)}{NC}"
                    _box_row(f"  {_tname:<14} {_bar} {_tc}{_ttfb_ms:>5} ms{NC}")
                    _box_row(f"  {' ' * 14}  {DIM}TCP {_conn_ms} ms  HTTP {_http_code}{NC}")
                    _ttfb_vals.append(_ttfb_ms)
                except (ValueError, IndexError):
                    _box_row(f"  {_tname:<14} {YELLOW}ошибка парсинга{NC}")
            else:
                _box_row(f"  {_tname:<14} {RED}недоступен{NC}")
        _box_sep()
        if _ttfb_vals:
            _avg_ttfb = sum(_ttfb_vals) // len(_ttfb_vals)
            _ac = GREEN if _avg_ttfb < 200 else YELLOW if _avg_ttfb < 500 else RED
            _box_row(f"  {BOLD}Средний TTFB: {_ac}{_avg_ttfb} ms{NC}  "
                     f"{DIM}(по {len(_ttfb_vals)} целям){NC}")
            if _avg_ttfb < 200:
                _box_ok("Отличное время отклика")
                _res("13. TTFB", _PASS, f"Средний {_avg_ttfb} ms")
            elif _avg_ttfb < 500:
                _box_warn(f"TTFB {_avg_ttfb} ms — приемлемо")
                _wiz_hint("sysctl net.ipv4.tcp_congestion_control")
                _res("13. TTFB", _WARN, f"Средний {_avg_ttfb} мс")
            else:
                _box_warn(f"Высокий TTFB {_avg_ttfb} ms")
                _wiz_hint("mtr 8.8.8.8")
                _res("13. TTFB", _FAIL, f"Средний {_avg_ttfb} мс — слишком высокий")
        else:
            _box_warn("Все TTFB-цели недоступны")
            _res("13. TTFB", _FAIL, "Все цели недоступны")
        _box_bottom()
        _pause("Шаг 13 завершён. Enter — продолжить...")

        # ── 14. DNS Leak Test ─────────────────────────────────────────────────
        _box_top("14 / 14  ·  DNS Leak Test")
        _run_safe(do_dns_leak_test)
        _box_bottom()

    finally:
        sys.stdout = _orig_stdout
        core._BOX_W = _saved_BOX_W  # восстанавливаем глобальную ширину рамки

    # ── Сохранение отчёта ────────────────────────────────────────────────────
    try:
        report_path.write_text(_report_buf.getvalue())
        report_path.chmod(0o640)
    except Exception as _e:
        warn(f"Не удалось сохранить отчёт: {_e}")

    log_to_file("INFO", f"Full diagnostic completed → {report_path}")

    # ── Итоговый отчёт с рекомендациями ──────────────────────────────────────
    print()
    _pass_c = sum(1 for _, s, _ in _results if s == _PASS)
    _fail_c = sum(1 for _, s, _ in _results if s == _FAIL)
    _warn_c = sum(1 for _, s, _ in _results if s == _WARN)
    _skip_c = sum(1 for _, s, _ in _results if s == _SKIP)

    if _fail_c == 0 and _warn_c == 0:
        _verdict = f"{GREEN}{BOLD}✔  СИСТЕМА РАБОТАЕТ НОРМАЛЬНО{NC}"
    elif _fail_c == 0:
        _verdict = f"{YELLOW}{BOLD}⚠  РАБОТАЕТ С ПРЕДУПРЕЖДЕНИЯМИ{NC}"
    else:
        _verdict = f"{RED}{BOLD}✖  ОБНАРУЖЕНЫ КРИТИЧЕСКИЕ ПРОБЛЕМЫ{NC}"

    _box_top("📋  ИТОГОВЫЙ ОТЧЁТ")
    _box_bottom()
    # Вердикт и счётчики — вне рамки (кириллица не ломает границы)
    print(f"  {_verdict}")
    print()
    print(f"  {GREEN}Пройдено:{NC} {_pass_c}   "
          f"{RED}Ошибок:{NC} {_fail_c}   "
          f"{YELLOW}Внимание:{NC} {_warn_c}   "
          f"{DIM}Пропущено:{NC} {_skip_c}")
    print()
    for _sname, _sstatus, _srec in _results:
        _sc = GREEN if _sstatus == _PASS else RED if _sstatus == _FAIL else YELLOW if _sstatus == _WARN else DIM
        _sw = _wcslen(_sstatus)
        print(f"  {_sc}{_sstatus}{' ' * max(0, 8 - _sw)}{NC}  {_sname}")
        if _srec:
            print(f"    {YELLOW}→{NC} {DIM}{_srec}{NC}")
    print()
    _box_top()
    _recs = [(n, r) for n, s, r in _results if r and s in (_FAIL, _WARN)]
    if _recs:
        _box_row(f"  {BOLD}{YELLOW}Рекомендации:{NC}")
        for _rn, _rt in _recs:
            _box_row(f"  {YELLOW}•{NC} {BOLD}[{_rn}]{NC}  {DIM}{_rt[:_BOX_W - 16]}{NC}")
    else:
        _box_row(f"  {GREEN}Рекомендаций нет — всё работает корректно.{NC}")
    _box_sep()
    _box_ok(f"Отчёт сохранён: {report_path}")
    _box_row(f"  {DIM}Просмотр: cat {report_path}{NC}")
    _box_bottom()

    # ── Отправка отчёта в поддержку ──────────────────────────────────────────
    print()
    _box_top("📤  Отправить отчёт в поддержку?")
    _box_row()
    _box_info("Отчёт не содержит паролей и приватных ключей.")
    _box_row()
    _tg_cfg: dict = {}
    try:
        if TG_CONFIG_FILE.exists():
            _tg_cfg = json.loads(TG_CONFIG_FILE.read_text())
    except Exception:
        pass
    _tg_ready = bool(_tg_cfg.get("token") and _tg_cfg.get("chat_id"))
    if _tg_ready:
        _box_item("1", f"📨 Отправить в Telegram  {DIM}(бот настроен){NC}")
    else:
        _box_row(f"  {DIM}[1]  📨 Telegram — {YELLOW}не настроен{NC}"
                 f"{DIM} (меню → Безопасность → Telegram){NC}")
    _box_item("2", f"📋 Показать в терминале  {DIM}(постранично){NC}")
    _box_item("3", f"📦 Команды для копирования  {DIM}(scp / base64){NC}")
    _box_item("Q", "Пропустить")
    _box_bottom()
    try:
        _sch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
    except (KeyboardInterrupt, EOFError):
        _sch = "Q"

    if _sch == "1" and _tg_ready:
        _token   = _tg_cfg["token"]
        _chat_id = _tg_cfg["chat_id"]
        try:
            _txt = report_path.read_text()
            _header = (f"🩺 Диагностический отчёт\n"
                       f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")
            _r = _run([
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "-m", "15",
                f"https://api.telegram.org/bot{_token}/sendMessage",
                "-d", f"chat_id={_chat_id}",
                "--data-urlencode", f"text={_header + _txt[:3800]}",
            ], capture=True, check=False)
            _box_top("Telegram")
            if _r.stdout.strip() == "200":
                _box_ok("Сообщение отправлено ✓")
                if len(_txt) > 3800:
                    _rf = _run([
                        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                        "-m", "20",
                        f"https://api.telegram.org/bot{_token}/sendDocument",
                        "-F", f"chat_id={_chat_id}",
                        "-F", f"document=@{report_path}",
                        "-F", "caption=Полный отчёт (файл)",
                    ], capture=True, check=False)
                    if _rf.stdout.strip() == "200":
                        _box_ok("Полный файл также отправлен ✓")
                    else:
                        _box_warn(f"Файл не отправился (HTTP {_rf.stdout.strip()})")
            else:
                _box_warn(f"Ошибка отправки (HTTP {_r.stdout.strip()})")
                _box_info(f"Отправьте вручную: cat {report_path}")
            _box_bottom()
        except Exception as _te:
            _box_top("Telegram")
            _box_warn(f"Ошибка: {_te}")
            _box_bottom()

    elif _sch == "2":
        print()
        try:
            _lines = report_path.read_text().splitlines()
            for _i in range(0, len(_lines), 40):
                for _l in _lines[_i:_i + 40]:
                    print(f"  {_l}")
                if _i + 40 < len(_lines):
                    try:
                        if input(f"\n  {DIM}[Enter] далее  [Q] выход: {NC}").strip().upper() == "Q":
                            break
                    except (KeyboardInterrupt, EOFError):
                        break
        except Exception as _re:
            warn(f"Не удалось прочитать отчёт: {_re}")

    elif _sch == "3":
        _box_top("Команды для копирования отчёта")
        _box_row(f"  {BOLD}SCP с локальной машины:{NC}")
        _box_row(f"    {CYAN}scp root@<IP>:{report_path} ./diag.txt{NC}")
        _box_row()
        _box_row(f"  {BOLD}Base64 прямо в терминале:{NC}")
        _box_row(f"    {CYAN}base64 {report_path}{NC}")
        _box_row()
        _box_row(f"  {BOLD}Просмотр:{NC}")
        _box_row(f"    {CYAN}cat {report_path}{NC}")
        _box_bottom()
