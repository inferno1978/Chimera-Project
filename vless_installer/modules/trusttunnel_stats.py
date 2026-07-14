"""
vless_installer/modules/trusttunnel_stats.py
───────────────────────────────────────────────────────────────────────────────
Сборщик трафика для TrustTunnel. Вызывается из cron через
`main.py --trusttunnel-stats` (каждые 5 минут, install_cron()).

⚠️  ИЗВЕСТНОЕ ОГРАНИЧЕНИЕ (D5, из Phase 0):
  Апстримовский /metrics endpoint (Prometheus, 127.0.0.1:1987) отдаёт
  счётчики трафика ТОЛЬКО с лейблом protocol_type (http1/http2/http3) —
  БЕЗ username. Per-user биллинг невозможен без патча lib/src/metrics.rs
  и сборки из исходников (теряет GPG-верификацию официальных релизов).

  Этот модуль записывает АГРЕГИРОВАННЫЙ трафик (сумма по всем protocol_type)
  под синтетическим user_id "_aggregate" через traffic_accounting.
  record_traffic_sample(). Аналогично FPTN ("нет per-user byte counter")
  и Hysteria2 ("per-exit-node, не per-user").

Точка входа из main.py:
    from vless_installer.modules.trusttunnel_stats import (
        trusttunnel_collect_traffic, trusttunnel_stats_cron,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from vless_installer.modules.trusttunnel import (
    trusttunnel_load_state,
    _METRICS_PORT,
    _log,
)


def _parse_prometheus_metrics(text: str) -> dict:
    """Парсер Prometheus /metrics response в dict metric_name → value.
    Суммирует значения по label-вариантам — для inbound_traffic_bytes
    {protocol_type="..."} это даёт общий трафик по всем protocol_type.
    """
    result: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+([0-9eE+\-.]+)\s*$', line)
        if not m:
            continue
        name = m.group(1)
        try:
            val = float(m.group(3))
        except ValueError:
            continue
        result[name] = result.get(name, 0) + val
    return result


def trusttunnel_collect_traffic() -> int:
    """Scrape /metrics и вернуть агрегированные байты (inbound + outbound).
    Returns 0 если TrustTunnel не установлен, /metrics недоступен, или
    парсинг не удался.
    """
    state = trusttunnel_load_state()
    if not state.get("installed"):
        return 0
    metrics_port = state.get("metrics_port", _METRICS_PORT)
    try:
        r = subprocess.run(
            ["curl", "-s", "-m", "5",
             f"http://127.0.0.1:{metrics_port}/metrics"],
            capture_output=True, text=True, timeout=8,
        )
        if r.returncode != 0 or not r.stdout:
            return 0
    except Exception:
        return 0
    metrics = _parse_prometheus_metrics(r.stdout)
    inbound = metrics.get("inbound_traffic_bytes", 0)    # клиент → endpoint
    outbound = metrics.get("outbound_traffic_bytes", 0)  # endpoint → клиент
    return int(inbound + outbound)


def trusttunnel_stats_cron() -> None:
    """Cron entrypoint. Scrape /metrics, записать агрегированный трафик
    через traffic_accounting.record_traffic_sample под user_id "_aggregate".
    """
    try:
        from vless_installer.modules.traffic_accounting import record_traffic_sample
    except Exception as e:
        _log("ERROR", f"stats_cron: cannot import traffic_accounting: {e}")
        return
    raw = trusttunnel_collect_traffic()
    if raw <= 0:
        return  # сервиса нет или трафика ещё не было
    try:
        # Aggregate-only (D5): per-user атрибуция невозможна с upstream
        # /metrics. Записываем под синтетическим "_aggregate" user_id.
        record_traffic_sample("_aggregate", "trusttunnel", raw)
        _log("INFO", f"stats_cron: recorded aggregate={raw} bytes")
    except Exception as e:
        _log("ERROR", f"stats_cron: record_traffic_sample failed: {e}")
