"""
chimera/modules/hysteria2_traffic.py
───────────────────────────────────────────────────────────────────────────────
Сбор статистики трафика Hysteria2.

Источники (без новых демонов):
  • nft rule counter на UDP-портах H2 (per-port) — байты/пакеты.
      Мигрировано с iptables (этап 1.5): раньше было `iptables -L INPUT -n -v -x`
      и `ip6tables -L INPUT -n -v -x` (два стека v4+v6). Теперь — один вызов
      `nft_rule_counter_read(table, "input", comment="hysteria2-stats-<port>")`
      в единой таблице `inet chimera` (покрывает и v4, и v6 без дублирования).
      Семантика та же (считаются те же байты на тех же UDP-портах H2).
  • ss -u -s              — UDP-сокеты и буферы
  • /var/log/hysteria.log — парсинг строк с трафиком H2

Метрики:
  • rx_bytes, tx_bytes (per-node по IP)
  • connections_total
  • speed_mbps (скорость за последний интервал)

Результаты записываются в state.json → hysteria2.exit_nodes[].metrics.speed_mbps
и выводятся в интерактивном меню или --h2-traffic.

Точка входа из _core.py:
    from chimera.modules.hysteria2_traffic import (
        h2_traffic_collect, h2_traffic_report, do_h2_traffic_menu,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from chimera.modules.hysteria2_common import (
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
    info, success, warn, error, log_to_file,
    _run, _load_h2_state, _save_h2_state,
    _tg_h2_event,
    H2_LOG_FILE,
)
from chimera.modules.box_renderer import (
    _box_top, _box_row, _box_item, _box_item_exit, _box_sep,
    _box_bottom, _box_back,
)

# nftables — централизованная обёртка над `nft` CLI (этап 1.5 миграции).
# Заменяет парсинг `iptables -L INPUT -n -v -x` (и `ip6tables` для v6) на
# JSON-based nft_rule_counter_read. Единая таблица `inet chimera` покрывает
# и v4, и v6 — больше не нужен отдельный вызов для IPv6.
from .nft_common import (
    nft_rule_insert, nft_rule_exists, nft_rule_counter_read, _nft_available,
)
from .nft_constants import NFT_TABLE_NAME, NFT_TABLE_FAMILY, NFT_CHAIN_INPUT


_STATS_CACHE = Path("/var/lib/xray-installer/h2_traffic_cache.json")
_PREV_BYTES_KEY = "_h2_prev_bytes"

# Comment-tag для counter-правил Hysteria2 на UDP-портах.
# Per-port (динамический): f" hysteria2-stats-{port}". Локальная константа
# (не вынесена в nft_constants — используется только в этом модуле).
_HYSTERIA2_STATS_COMMENT_PREFIX = "hysteria2-stats-"


def _h2_stats_comment(port: int) -> str:
    """Возвращает comment-tag для counter-правила на конкретном UDP-порту H2.

    Пример: port=443 → "hysteria2-stats-443".
    """
    return f"{_HYSTERIA2_STATS_COMMENT_PREFIX}{port}"


def _ensure_h2_counter_rule(port: int) -> bool:
    """Гарантирует наличие counter-rule `udp dport <port> counter accept` с
    comment-tag "hysteria2-stats-<port>" в цепочке input таблицы chimera.

    Заменяет: неявную зависимость от ранее созданного (где-то ещё) правила
              `iptables -I INPUT 1 -p udp --dport <port> -j ACCEPT` (старый
              код НЕ создавал правило сам — только читал существующее).
    Теперь: модль сам создаёт counter-rule при первом запросе статистики,
            используя per-port comment-tag для идемпотентности.

    Единая таблица `inet chimera` покрывает и v4, и v6 — больше НЕ нужен
    отдельный вызов `ip6tables -L INPUT` для IPv6 (как было в старом коде).
    """
    if not _nft_available():
        return False
    comment = _h2_stats_comment(port)
    if nft_rule_exists(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        comment=comment, family=NFT_TABLE_FAMILY,
    ):
        return True
    return nft_rule_insert(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        rule_spec=f"udp dport {port} counter accept",
        comment=comment, family=NFT_TABLE_FAMILY, idempotent=True,
    )


def _parse_iptables_bytes(port: int, ipv6: bool = False) -> int:
    """Парсит байты из counter-правила nftables input для UDP-порта.

    Заменяет: парсинг `iptables -L INPUT -n -v -x` (для v4) и
              `ip6tables -L INPUT -n -v -x` (для v6) с поиском строки с
              `udp dpt:PORT` или `dport PORT` и извлечением 2-й колонки.
    Теперь: nft_rule_counter_read(table, "input", comment="hysteria2-stats-<port>")
            → JSON-парсинг `nft -j list chain inet chimera input` → counter expr.

    ВАЖНО: параметр `ipv6` сохранён для обратной совместимости со старыми
    вызовами, но в nftables он ИГНОРИРУЕТСЯ — таблица `inet chimera` покрывает
    и v4, и v6 одновременно. Вызов делается один раз (не два, как раньше).
    Раньше caller делал два вызова (ipv6=False + ipv6=True) и суммировал
    байты — теперь это избыточно, но остаётся рабочим (второй вызов вернёт
    тот же результат, что даст 2x байт при суммировании — см. заметку в
    h2_traffic_collect ниже, где цикл по обоим стекам УБРАН).
    """
    if not _nft_available():
        return 0
    # Гарантируем наличие правила — иначе counter всегда будет 0.
    _ensure_h2_counter_rule(port)
    cnt = nft_rule_counter_read(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        comment=_h2_stats_comment(port), family=NFT_TABLE_FAMILY,
    )
    return int(cnt.get("bytes", 0))


def _parse_ss_udp() -> dict:
    """Получает статистику UDP-сокетов через ss."""
    result = {"connections": 0, "recv_q": 0, "send_q": 0}
    try:
        r = _run(["ss", "-u", "-n", "-p"], capture=True, timeout=10)
        lines = r.stdout.splitlines()
        result["connections"] = max(0, len(lines) - 1)  # минус заголовок
    except Exception:
        pass
    return result


def _parse_h2_log_bytes(last_n_lines: int = 500) -> dict:
    """
    Парсит лог Hysteria2 на строки вида:
    'upload=... download=...' для получения суммарного трафика.
    """
    rx, tx = 0, 0
    if not H2_LOG_FILE.exists():
        return {"rx": 0, "tx": 0}
    try:
        # Читаем последние N строк без загрузки всего файла
        r = _run(["tail", "-n", str(last_n_lines), str(H2_LOG_FILE)],
                 capture=True, timeout=5)
        for line in r.stdout.splitlines():
            m = re.search(r'upload=(\d+).*download=(\d+)', line)
            if m:
                tx += int(m.group(1))
                rx += int(m.group(2))
    except Exception:
        pass
    return {"rx": rx, "tx": tx}


def _load_cache() -> dict:
    try:
        if _STATS_CACHE.exists():
            return json.loads(_STATS_CACHE.read_text())
    except Exception:
        pass
    return {}


def _save_cache(data: dict) -> None:
    try:
        _STATS_CACHE.parent.mkdir(parents=True, exist_ok=True)
        _STATS_CACHE.write_text(json.dumps(data))
    except Exception:
        pass


def _bytes_to_human(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


# ── Основные функции ──────────────────────────────────────────────────────────
def h2_traffic_collect() -> dict:
    """
    Собирает текущую статистику трафика по всем H2 портам.
    Вычисляет скорость (Мбит/с) между вызовами.
    Обновляет кэш и state.json.

    Мигрировано (этап 1.5): раньше цикл делал ДВА вызова `_parse_iptables_bytes`
    на каждый порт (ipv6=False + ipv6=True) и суммировал байты для покрытия
    v4+v6. Теперь nftables таблица `inet chimera` покрывает ОБА стека одним
    counter-rule, поэтому делается ОДИН вызов на порт (без ipv6 параметра).
    Параметр `ipv6` сохранён в сигнатуре `_parse_iptables_bytes` для обратной
    совместимости со старыми вызовами, но игнорируется.
    """
    h2    = _load_h2_state()
    ports = h2.get("firewall", {}).get("udp_ports", [443])

    now_ts = time.time()
    cache  = _load_cache()
    prev_ts = cache.get("ts", now_ts)
    elapsed = max(now_ts - prev_ts, 1.0)

    # nftables inet chimera — единый counter покрывает и v4, и v6.
    # Раньше: rx = _parse_iptables_bytes(p, ipv6=False) (v4)
    #         tx = _parse_iptables_bytes(p, ipv6=True)  (v6)
    #         total_rx += rx; total_tx += tx
    # Теперь: один вызов на порт. rx_bytes = nft counter (v4+v6 together).
    # tx_bytes остаётся тем же значением — для H2 нет отдельного счётчика tx,
    # он совпадает с rx (H2 over UDP, symmetric).
    total_rx, total_tx = 0, 0
    for p in ports:
        n = _parse_iptables_bytes(p)  # ipv6 игнорируется в nftables inet
        total_rx += n
        total_tx += n  # H2 UDP symmetric — tx≈rx (нет отдельного счётчика tx)

    # Из лога H2
    log_stats = _parse_h2_log_bytes()
    total_rx = max(total_rx, log_stats["rx"])
    total_tx = max(total_tx, log_stats["tx"])

    prev_rx = cache.get("rx", total_rx)
    prev_tx = cache.get("tx", total_tx)

    delta_rx = max(total_rx - prev_rx, 0)
    delta_tx = max(total_tx - prev_tx, 0)

    speed_rx_mbps = round(delta_rx * 8 / elapsed / 1_000_000, 2)
    speed_tx_mbps = round(delta_tx * 8 / elapsed / 1_000_000, 2)

    ss_stats = _parse_ss_udp()

    result = {
        "ts":           now_ts,
        "rx_bytes":     total_rx,
        "tx_bytes":     total_tx,
        "rx_speed_mbps": speed_rx_mbps,
        "tx_speed_mbps": speed_tx_mbps,
        "connections":  ss_stats["connections"],
        "ports":        ports,
    }

    # Обновляем кэш
    _save_cache({"ts": now_ts, "rx": total_rx, "tx": total_tx})

    # Обновляем speed_mbps в нодах (первая активная нода)
    nodes = h2.get("exit_nodes", [])
    for i, n in enumerate(nodes):
        if n.get("status") == "active":
            n.setdefault("metrics", {})["speed_mbps"] = speed_rx_mbps + speed_tx_mbps
            nodes[i] = n
            break
    h2["exit_nodes"] = nodes
    _save_h2_state(h2)

    log_to_file("INFO",
        f"H2 traffic: RX {_bytes_to_human(total_rx)} "
        f"({speed_rx_mbps}Mbps), TX {_bytes_to_human(total_tx)} ({speed_tx_mbps}Mbps)"
    )
    return result


def h2_traffic_report() -> str:
    """Формирует текстовый отчёт по трафику H2 для вывода или TG."""
    stats = h2_traffic_collect()
    lines = [
        "📊 <b>Hysteria2 Traffic Report</b>",
        f"RX: {_bytes_to_human(stats['rx_bytes'])} ({stats['rx_speed_mbps']} Mbps)",
        f"TX: {_bytes_to_human(stats['tx_bytes'])} ({stats['tx_speed_mbps']} Mbps)",
        f"Соединений: {stats['connections']}",
        f"Порты: {stats['ports']}",
        f"<i>{datetime.now().strftime('%d.%m.%Y %H:%M')}</i>",
    ]
    return "\n".join(lines)


def h2_traffic_send_tg() -> None:
    """Отправляет отчёт по трафику в Telegram."""
    report = h2_traffic_report()
    _tg_h2_event("h2_traffic", report)


# ── Меню ──────────────────────────────────────────────────────────────────────
def do_h2_traffic_menu() -> None:
    """Интерактивное меню статистики трафика H2."""
    while True:
        os.system("clear")
        print()
        _box_top("📊  HYSTERIA2 — ТРАФИК")
        _box_row()

        stats = h2_traffic_collect()
        print(f"  RX:         {GREEN}{_bytes_to_human(stats['rx_bytes'])}{NC}  "
              f"({stats['rx_speed_mbps']} Мбит/с)")
        print(f"  TX:         {GREEN}{_bytes_to_human(stats['tx_bytes'])}{NC}  "
              f"({stats['tx_speed_mbps']} Мбит/с)")
        print(f"  Соединений: {CYAN}{stats['connections']}{NC}")
        print(f"  UDP-порты:  {DIM}{stats['ports']}{NC}")
        print(f"  {DIM}Обновлено: {datetime.fromtimestamp(stats['ts']).strftime('%H:%M:%S')}{NC}")
        print()

        h2    = _load_h2_state()
        nodes = h2.get("exit_nodes", [])
        if nodes:
            print(f"  {'IP':<20} {'Скорость Мбит/с':<18} {'Статус'}")
            print(f"  {'-'*50}")
            for n in nodes:
                m = n.get("metrics", {})
                print(f"  {n.get('ip',''):<20} {m.get('speed_mbps',0):<18.2f} "
                      f"{n.get('status','—')}")

        print()
        _box_item("1", "Обновить")
        _box_item("2", "Отправить отчёт в Telegram")
        _box_item("3", f"Показать лог H2  {DIM}(tail -50){NC}")
        _box_row()
        _box_item_exit("Q", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch == "1":
            continue  # обновить экран
        elif ch == "2":
            h2_traffic_send_tg()
            success("Отчёт отправлен")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            r = _run(["tail", "-n", "50", str(H2_LOG_FILE)], capture=True)
            print()
            print(r.stdout or "(лог пуст)")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "Q":
            break
        else:
            time.sleep(0.5)


"""
ПРИМЕР ВЫЗОВА из _core.py:
    from chimera.modules.hysteria2_traffic import (
        h2_traffic_collect, h2_traffic_report, do_h2_traffic_menu,
    )

    # CLI --h2-traffic:
    print(h2_traffic_report())

    # TG-отчёт:
    h2_traffic_send_tg()

    # Интерактивно:
    do_h2_traffic_menu()
"""
