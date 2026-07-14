"""
vless_installer/modules/trusttunnel_stats.py
───────────────────────────────────────────────────────────────────────────────
Traffic collector for TrustTunnel.

KNOWN LIMITATION (D5, from Phase 0):
  Upstream TrustTunnel's Prometheus /metrics endpoint exposes traffic counters
  ONLY with a `protocol_type` label (http1/http2/http3) — NO `username` label.
  Per-user traffic accounting is therefore NOT possible without patching the
  upstream Rust source and rebuilding from source.

  This module records AGGREGATE traffic (sum across all protocol_types) under
  a synthetic user_id "_aggregate" via traffic_accounting.record_traffic_sample().
  This matches the precedent of FPTN ("нет per-user byte counter") and
  Hysteria2 ("per-exit-node, не per-user").

  If per-user billing becomes a hard requirement in the future, options are:
    (a) Run a separate endpoint process per user (heavy: 17 MB binary × N users)
    (b) Patch lib/src/metrics.rs to add a `username` label, build from source
        (loses GPG-verified release binaries)

Public API:
    trusttunnel_collect_traffic() -> int   # returns aggregate bytes, or 0
    trusttunnel_stats_cron() -> None       # cron entrypoint
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
    """Parse a Prometheus /metrics response into a dict of metric_name → value.
    Only handles simple `name{labels} value` and `name value` lines.
    Returns the LAST seen value for each metric name (good enough for counters).
    """
    result: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # name{labels} value  OR  name value
        m = re.match(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+([0-9eE+\-.]+)\s*$', line)
        if not m:
            continue
        name = m.group(1)
        try:
            val = float(m.group(3))
        except ValueError:
            continue
        # Sum across label variants — for `inbound_traffic_bytes{protocol_type="..."}`,
        # we want the total across all protocol_types.
        result[name] = result.get(name, 0) + val
    return result


def trusttunnel_collect_traffic() -> int:
    """Scrape /metrics and return aggregate bytes (inbound + outbound).

    Returns 0 if TrustTunnel not installed, /metrics unreachable, or parse fails.
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
    # inbound_traffic_bytes = client→endpoint (upload)
    # outbound_traffic_bytes = endpoint→client (download)
    inbound = metrics.get("inbound_traffic_bytes", 0)
    outbound = metrics.get("outbound_traffic_bytes", 0)
    return int(inbound + outbound)


def trusttunnel_stats_cron() -> None:
    """Cron entrypoint. Scrapes /metrics, records aggregate bytes via
    traffic_accounting.record_traffic_sample under synthetic user_id "_aggregate".
    """
    try:
        from vless_installer.modules.traffic_accounting import record_traffic_sample
    except Exception as e:
        _log("ERROR", f"stats_cron: cannot import traffic_accounting: {e}")
        return
    raw = trusttunnel_collect_traffic()
    if raw <= 0:
        return  # nothing to record (service down or no traffic yet)
    try:
        # Aggregate-only (D5): no per-user attribution possible with upstream
        # /metrics. Record under synthetic "_aggregate" user_id.
        record_traffic_sample("_aggregate", "trusttunnel", raw)
        _log("INFO", f"stats_cron: recorded aggregate={raw} bytes")
    except Exception as e:
        _log("ERROR", f"stats_cron: record_traffic_sample failed: {e}")
