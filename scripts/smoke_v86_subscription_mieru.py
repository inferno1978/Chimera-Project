#!/usr/bin/env python3
"""
scripts/smoke_v86_subscription_mieru.py
───────────────────────────────────────────────────────────────────────────────
Смоук v86: подписка видит mieru как юзер nyamebox/karing.

Сценарий — кейс юзера: Hybrid Addon, транспорт both (TCP 443 + UDP 444),
домен cdn.example, DNS panel.example, traffic-pattern blob.
Проверяется БЕЗ живого сервера: state-файлы пишутся в tmp, патчим константы.

  1. mierus://-ссылки (base64-подписка) — две, с доменом, не с IP
  2. singbox-формат (nyamebox): два mieru-outbound'а (TCP/UDP), домен,
     domain_resolver, traffic_pattern; VLESS исключён; DNS-блок custom-dns
     через туннель + правила на домен сервера; route.final = первый mieru
  3. Смоук Karing-ссылки гибрида: РОВНО ОДИН traffic-pattern= при blob
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _fake_core():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    from unittest.mock import patch as _p
    with _p.object(Path, "mkdir", lambda self, *a, **kw: None), \
         _p.object(Path, "touch", lambda self, *a, **kw: None), \
         _p.object(Path, "chmod", lambda self, *a, **kw: None), \
         _p("os.chown", lambda *a, **kw: None), \
         _p("os.geteuid", return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake = types.ModuleType("chimera._core")
    fake.__dict__.update(g)
    sys.modules["chimera._core"] = fake


def main() -> int:
    _fake_core()
    tmp = Path(tempfile.mkdtemp())

    hst = tmp / "hybrid_mieru_state.json"
    hst.write_text(json.dumps({
        "transport": "both", "tcp_port": 443, "udp_port": 444,
        "client_server_addr": "cdn.example",
        "client_dns": "panel.example",
        "traffic_pattern_blob": "GgQIARAFIgIIAQ==",
    }))
    mcfg = tmp / "hybrid_server_config.json"
    mcfg.write_text(json.dumps({
        "portBindings": [{"port": 443, "protocol": "TCP"},
                          {"port": 444, "protocol": "UDP"}],
        "users": [{"name": "u_d106fd33", "password": "goep167KyRYE2u76w9sv-Sr3"}],
    }))
    nope = tmp / "nope.json"

    user = {"uuid": "uuid-smoke", "email": "u_d106fd33@x.com"}
    checks = []

    from chimera.modules import subscription as sub

    # ── 1. mierus://-ссылки base64-подписки ────────────────────────────
    with patch.object(sub, "_HYBRID_STATE", hst), \
         patch.object(sub, "_MITA_HYBRID_CFG", mcfg), \
         patch.object(sub, "_MIERU_STATE", nope):
        links = sub._build_mieru_uris(user, "203.0.113.103")
    checks.append(("две mierus://-ссылки (TCP+UDP)", len(links) == 2))
    checks.append(("ссылки несут домен, не IP",
                   all("@cdn.example" in l for l in links)
                   and not any("203.0.113.103" in l for l in links)))
    protos = sorted(l.split("protocol=")[1].split("&")[0] for l in links)
    checks.append((f"транспорты {protos}", protos == ["TCP", "UDP"]))

    # ── 2. singbox-формат (nyamebox: UA → singbox) ────────────────────
    import chimera.modules.rest_api as rest_api
    with patch.object(sub, "_HYBRID_STATE", hst), \
         patch.object(sub, "_MITA_HYBRID_CFG", mcfg), \
         patch.object(sub, "_MIERU_STATE", nope), \
         patch.object(sub, "_get_server_ip", return_value="203.0.113.103"), \
         patch.object(sub, "_load_state", return_value={}), \
         patch.object(sub, "_collect_registry_json_outbounds", return_value=[]), \
         patch.object(rest_api, "_generate_singbox_config", return_value=""):
        cfg = json.loads(sub.build_subscription_singbox_config(user))

    mieru_obs = [ob for ob in cfg["outbounds"] if ob.get("type") == "mieru"]
    checks.append(("mieru-outbound'ы в singbox: 2", len(mieru_obs) == 2))
    checks.append(("VLESS исключён (hybrid)",
                   all(ob.get("type") != "vless" for ob in cfg["outbounds"])))
    checks.append(("домен в server + domain_resolver",
                   all(ob["server"] == "cdn.example"
                       and ob["domain_resolver"] == "local" for ob in mieru_obs)))
    checks.append(("traffic_pattern из blob",
                   all(ob.get("traffic_pattern") == "GgQIARAFIgIIAQ=="
                       for ob in mieru_obs)))
    tags = [ob["tag"] for ob in mieru_obs]
    checks.append((f"уникальные теги {tags}",
                   len(set(tags)) == 2 and tags[0] == "mieru-u_d106fd33"))
    checks.append(("route.final = первый mieru",
                   cfg["route"]["final"] == "mieru-u_d106fd33"))
    custom = cfg.get("dns", {}).get("servers", [{}])[0]
    checks.append(("custom-dns через туннель",
                   custom.get("tag") == "custom-dns"
                   and custom.get("address") == "panel.example"
                   and custom.get("detour") == "mieru-u_d106fd33"))
    checks.append(("правило на домен сервера",
                   cfg.get("dns", {}).get("rules")
                   == [{"domain": ["cdn.example"], "server": "local"}]))

    # ── 3. Karing-ссылка гибрида: один traffic-pattern ────────────────
    from chimera.modules import hybrid_addon as ha
    from chimera.modules import mieru
    captured = []
    creds = {"tcp": {"port": 443, "login": "u_d106fd33",
                     "password": "goep167KyRYE2u76w9sv-Sr3"}}

    class _FakePath:
        def __init__(self, p):
            self._p = str(p)
        def write_text(self, data, encoding=None):
            pass
        def __str__(self):
            return self._p

    with patch.object(ha, "Path", _FakePath), \
         patch.object(ha, "_box_link", lambda s: captured.append(s)), \
         patch.object(ha, "box_header", lambda *a, **k: None), \
         patch.object(ha, "_box_row", lambda *a, **k: None), \
         patch.object(ha, "_box_bottom", lambda *a, **k: None), \
         patch.object(mieru, "_print_qr", lambda *a, **k: None):
        ha._show_mieru_client_links(creds, "cdn.example",
                                    client_dns="panel.example",
                                    traffic_pattern_blob="GgQIARAFIgIIAQ==")
    karing = [l for l in captured
              if l.startswith("mierus://") and "protocol=" in l]
    checks.append(("Karing-ссылка: ОДИН traffic-pattern=",
                   karing and karing[0].count("traffic-pattern=") == 1))

    ok = True
    for name, res in checks:
        print(f"  {'✓' if res else '✗'}  {name}")
        ok = ok and res
    print(f"\n{'SMOKE v86 OK' if ok else 'SMOKE v86 FAILED'} "
          f"({sum(1 for _, r in checks if r)}/{len(checks)})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
