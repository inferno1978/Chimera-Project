#!/usr/bin/env python3
"""
hysteria2_main_patch.py
══════════════════════════════════════════════════════════════════════════════
АДДИТИВНЫЙ ПАТЧ для main.py — обработка CLI-флагов Hysteria2.

ИНСТРУКЦИЯ ПО ИНТЕГРАЦИИ:
Вставить этот блок в main.py ПЕРЕД строкой:
    # =============================================================================
    #  ОСНОВНОЙ ИНТЕРАКТИВНЫЙ ЗАПУСК
    # =============================================================================

Все блоки независимы, порядок между ними не важен.
Существующие флаги (--smart-balance, --autoban и т.д.) не трогаются.
══════════════════════════════════════════════════════════════════════════════
"""

# ─── Hysteria2: установка Exit-ноды ─────────────────────────────────────────
if "--h2-install-exit" in sys.argv:
    if os.geteuid() != 0:
        print("ERROR: требуются права root", file=sys.stderr)
        sys.exit(1)
    from vless_installer.modules.hysteria2_exit_mgr import h2_exit_install
    _h2_raw_ports = ""
    if "--h2-port" in sys.argv:
        _idx = sys.argv.index("--h2-port")
        _h2_raw_ports = sys.argv[_idx + 1] if _idx + 1 < len(sys.argv) else "443"
    _h2_ports = [int(p.strip()) for p in _h2_raw_ports.split(",")
                 if p.strip().isdigit()] if _h2_raw_ports else [443]
    h2_exit_install(ports=_h2_ports)
    sys.exit(0)

# ─── Hysteria2: статус ───────────────────────────────────────────────────────
if "--h2-status" in sys.argv:
    from vless_installer.modules.hysteria2_exit_mgr import h2_exit_status
    _st = h2_exit_status()
    print(json.dumps(_st, indent=2, ensure_ascii=False))
    sys.exit(0)

# ─── Hysteria2: health check (cron) ─────────────────────────────────────────
if "--h2-health" in sys.argv:
    if os.geteuid() != 0:
        print("ERROR: требуются права root", file=sys.stderr)
        sys.exit(1)
    from vless_installer.modules.hysteria2_health import h2_health_check_cron
    h2_health_check_cron()
    sys.exit(0)

# ─── Hysteria2: статистика трафика ──────────────────────────────────────────
if "--h2-traffic" in sys.argv:
    from vless_installer.modules.hysteria2_traffic import h2_traffic_report
    print(h2_traffic_report())
    sys.exit(0)

# ─── Hysteria2: отчёт качества ──────────────────────────────────────────────
if "--h2-quality-report" in sys.argv:
    from vless_installer.modules.hysteria2_quality import h2_quality_report
    _send_tg = "--tg" in sys.argv
    print(h2_quality_report(send_tg=_send_tg))
    sys.exit(0)

# ─── Hysteria2: просмотр логов ──────────────────────────────────────────────
if "--h2-logs" in sys.argv:
    import subprocess as _subp
    for _lf in ("/var/log/hysteria.log",
                "/var/log/hysteria-watchdog.log",
                "/var/log/hysteria-health.log"):
        if Path(_lf).exists():
            print(f"\n=== {_lf} ===")
            _subp.run(["tail", "-n", "60", _lf])
    sys.exit(0)

# ─── Hysteria2: кластерные операции ─────────────────────────────────────────
if "--h2-cluster" in sys.argv:
    if os.geteuid() != 0:
        print("ERROR: требуются права root", file=sys.stderr)
        sys.exit(1)
    _idx = sys.argv.index("--h2-cluster")
    _op  = sys.argv[_idx + 1] if _idx + 1 < len(sys.argv) else "status"
    from vless_installer.modules.hysteria2_cluster import h2_cluster_run
    h2_cluster_run(_op)
    sys.exit(0)

# ─── Hysteria2: мониторинг сертификата (cron еженедельно) ───────────────────
if "--h2-cert-monitor" in sys.argv:
    from vless_installer.modules.hysteria2_cert_mgr import h2_cert_monitor
    h2_cert_monitor()
    sys.exit(0)

# ─── Hysteria2: автообновление бинарника (cron ежесуточно) ──────────────────
if "--h2-autoupdate" in sys.argv:
    if os.geteuid() != 0:
        print("ERROR: требуются права root", file=sys.stderr)
        sys.exit(1)
    from vless_installer.modules.hysteria2_auto_update import h2_autoupdate_cron
    h2_autoupdate_cron()
    sys.exit(0)

# ─── Hysteria2: watchdog (cron каждые 2 минуты) ─────────────────────────────
if "--h2-watchdog-run" in sys.argv:
    if os.geteuid() != 0:
        sys.exit(1)
    from vless_installer.modules.hysteria2_watchdog import h2_watchdog_run
    h2_watchdog_run()
    sys.exit(0)

# ─── Hysteria2: переключение транспорта ─────────────────────────────────────
if "--h2-transport" in sys.argv:
    if os.geteuid() != 0:
        print("ERROR: требуются права root", file=sys.stderr)
        sys.exit(1)
    _idx = sys.argv.index("--h2-transport")
    _val = sys.argv[_idx + 1] if _idx + 1 < len(sys.argv) else "h2"
    if _val.lower() == "awg":
        from vless_installer.modules.hysteria2_transport import h2_transport_remove
        h2_transport_remove()
    elif _val.lower() == "h2":
        from vless_installer.modules.hysteria2_transport import h2_transport_apply
        h2_transport_apply()
    else:
        print(f"Неверный транспорт: {_val}. Используйте: awg | h2", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)

# ─── Hysteria2: настройка весов балансировщика ──────────────────────────────
if "--h2-weights" in sys.argv:
    # Формат: --h2-weights 1.2.3.4:1.5,5.6.7.8:0.5
    _idx = sys.argv.index("--h2-weights")
    _raw = sys.argv[_idx + 1] if _idx + 1 < len(sys.argv) else ""
    if _raw:
        from vless_installer.modules.hysteria2_common import _load_h2_state, _save_h2_state
        _h2 = _load_h2_state()
        for _pair in _raw.split(","):
            if ":" in _pair:
                _parts = _pair.rsplit(":", 1)
                _ip, _w = _parts[0].strip(), _parts[1].strip()
                for _n in _h2.get("exit_nodes", []):
                    if _n.get("ip") == _ip:
                        try:
                            _n["weight"] = float(_w)
                            print(f"Вес {_ip} → {_w}")
                        except ValueError:
                            pass
        _save_h2_state(_h2)
    sys.exit(0)

# ─── Hysteria2: smoke test ───────────────────────────────────────────────────
if "--h2-smoke" in sys.argv:
    from vless_installer.modules.hysteria2_smoke_test import h2_smoke_test
    _ok = h2_smoke_test(verbose=True)
    sys.exit(0 if _ok else 1)

# ─── Hysteria2: DPI авто-фолбэк (из cron) ───────────────────────────────────
if "--h2-dpi-check" in sys.argv:
    if os.geteuid() != 0:
        sys.exit(1)
    from vless_installer.modules.hysteria2_dpi import h2_dpi_auto_fallback
    _switched = h2_dpi_auto_fallback()
    if _switched:
        print("[H2-DPI] Порт переключён")
    sys.exit(0)
