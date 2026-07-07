#!/usr/bin/env python3
# === v4.12.10 ===
"""
VLESS + TCP + REALITY + xHTTP TLS — Ultimate Installer v4.12.10
Python 3.12+ port

Поддержка: Ubuntu 20.04/22.04/24.04, Debian 11/12/13
Режимы протокола: VLESS+TCP+REALITY | VLESS+xHTTP+TLS
Балансировка (Режим B): Round Robin | Least Ping | Least Load | Random
Новое в v3.99: AutoBan | CertBot Monitor | TTFB Test | Config Changelog | Telegram | Traffic Limits | Health Report | Migration | GeoIP Block | Audit
"""

# =============================================================================
#  STDLIB IMPORTS
# =============================================================================
import sys
import os
import re


# ---------------------------------------------------------------------------
# Safe input: protection against UnicodeDecodeError in non-standard terminals.
# Monkey-patches built-in input() globally so all 277 call sites are covered.
# ---------------------------------------------------------------------------
import builtins as _builtins
_builtin_input_orig = _builtins.input

def _safe_input(prompt: str = "") -> str:
    try:
        sys.stdout.write(prompt)
        sys.stdout.flush()
        raw = sys.stdin.buffer.readline()
        if not raw:
            raise EOFError
        return raw.decode("utf-8", errors="replace").rstrip("\n\r")
    except UnicodeDecodeError:
        return ""
    except (EOFError, OSError):
        raise EOFError

_builtins.input = _safe_input
# ---------------------------------------------------------------------------

import json
import time
import uuid
import random
import string
import shutil
import socket
import subprocess
import tempfile
import textwrap
import grp
import pwd
from pathlib import Path
from datetime import datetime, timezone
from typing import Any
import getpass

# ── Модули v4.12.9 ──────────────────────────────────────────────────────────────
from vless_installer.modules.smoke_test      import smoke_test_xray
from vless_installer.modules.xray_safe_apply import xray_apply_with_smoke
from vless_installer.modules.nginx_watchdog  import (
    nginx_watchdog_install, nginx_watchdog_remove, do_manage_nginx_watchdog,
)
from vless_installer.modules.ipset_persist   import (
    ipset_save, ipset_restore_unit_install, ipset_restore_unit_remove,
    do_manage_ipset_persist,
)
from vless_installer.modules.ipban import do_manage_ipban
from vless_installer.modules.vkturn_menu import do_vkturn_menu
from vless_installer.modules.slipgate import do_slipgate_menu
from vless_installer.modules.wdtt import do_wdtt_menu
from vless_installer.modules.naiveproxy import do_naiveproxy_menu
from vless_installer.modules.mieru import do_mieru_menu
from vless_installer.modules.webdav_tunnel import do_webdav_tunnel_menu
from vless_installer.modules.hybrid_addon import do_hybrid_addon_menu
from vless_installer.modules.ripe_file_age   import (
    check_ripe_file_age, ripe_file_age_banner,
)
from vless_installer.modules.cluster_ops import do_cluster_menu, load_exit_nodes
from vless_installer.modules.box_renderer import (
    _get_box_width, _plain, _wcslen,
    _box_line_top, _box_line_sep, _box_line_bot,
    _box_row, _box_row_auto, _box_link, _box_top, _box_sep, _box_bottom,
    _box_item, _box_item_exit, _box_back, _box_desc,
    _box_wrap_msg, _box_info, _box_warn, _box_ok, _box_dim, _box_input,
    _submenu_header, _submenu_item, _submenu_back,
)
import vless_installer.modules.box_renderer as _br
_BOX_W = _br._BOX_W  # алиас для совместимости с кодом в _core.py
from vless_installer.modules.logrotate  import do_manage_logrotate
from vless_installer.modules.dns_rules         import do_manage_dns_rules
from vless_installer.modules.fingerprint_manager import (
    XRAY_FP_LIST  as _FM_FP_LIST,
    prompt_fingerprint as _fm_prompt_fingerprint,
)
from vless_installer.modules.dnscrypt_selector import do_dnscrypt_selector_menu
from vless_installer.modules.honeypot      import do_manage_honeypot
from vless_installer.modules.fail2ban_manager import do_manage_fail2ban
from vless_installer.modules.scheduler     import render_scheduler_menu
from vless_installer.modules.warp          import do_manage_warp
from vless_installer.modules.smart_balancer import (
    do_manage_smart_balancer, _smart_balancer_run_once,
    PROBE_INTERVAL_MIN,
    _AUTO_FALLBACK_CRON, _AUTO_FALLBACK_SCRIPT, _AUTO_FALLBACK_LOGFILE,
    _AWG_WATCHDOG_CRON, _AWG_WATCHDOG_SCRIPT, _AWG_WATCHDOG_LOG, _AWG_WATCHDOG_STATE,
)
from vless_installer.modules.health import (
    health_check_xray, health_check_nginx, health_check_ssl,
    health_check_ports, run_full_health_check, do_check_tls_cert,
    HEALTH_CHECK_FILE,
)
from vless_installer.modules.dpi_detector import do_manage_dpi_detector
from vless_installer.modules.ingress_geoip import (
    do_manage_ingress_geoip,
    _ingress_state_load, _ingress_enable,
    INGRESS_CRON_FILE, INGRESS_CRON_SCRIPT,
    INGRESS_GEOIP_FILE, INGRESS_IPSET_NAME, INGRESS_IPSET6_NAME, INGRESS_LOG,
)
from vless_installer.modules.tui        import (
    tui_input, tui_confirm, tui_select, tui_progress, tui_form,
)
# ── Модули фрагментации v4.12 ─────────────────────────────────────────────────
from vless_installer.modules.fragment_config     import do_fragment_config_menu
from vless_installer.modules.fragment_fuzzer     import do_fragment_fuzzer_menu
from vless_installer.modules.fragment_log_viewer import do_fragment_log_viewer_menu
from vless_installer.modules.fragment_link       import do_fragment_link_menu
from vless_installer.modules.fragment_presets    import do_fragment_presets_menu
from vless_installer.modules.fragment_guide      import do_fragment_guide_menu
from vless_installer.modules.fragment_noise      import do_fragment_noise_menu
from vless_installer.modules.fragment_mux        import do_fragment_mux_menu
from vless_installer.modules.fragment_watchdog   import do_fragment_watchdog_menu
from vless_installer.modules.fragment_stats      import do_fragment_stats_menu
from vless_installer.modules.fragment_share      import do_fragment_share_menu
from vless_installer.modules.port_hopping        import do_port_hopping_menu, ph_status
from vless_installer.modules.tg_bot              import do_tg_bot_menu, do_manage_telegram, _tg_notify_event, _tg_load, tg_send
# ── Hysteria2 transport (аддитивно, v4.12.9+) ────────────────────────────────
from vless_installer.modules.hysteria2_menu      import do_hysteria2_menu
# ── Новые модули (бэкап, cold boot, health monitor) ──────────────────────────
from vless_installer.modules.config_backup       import backup_xray_config, do_backup_menu
from vless_installer.modules.cold_boot_restore   import do_cold_boot_menu
from vless_installer.modules.node_health_monitor import do_health_monitor_menu
# ── Новые модули (DPI-цензура снаружи + бенчмарк сервера) ────────────────────
from vless_installer.modules.dpi_censor_check    import do_dpi_censor_check_menu
from vless_installer.modules.network_bench       import do_network_bench_menu
# ── Tier-1 рефакторинг: ASN cache + IP→ASN lookup ────────────────────────────
from vless_installer.modules.asn_cache import (
    ASN_CACHE_DB, ASN_CACHE_MAX_AGE_DAYS,
    _asn_cache_connect, _asn_cache_save, _asn_cache_load,
    _asn_cache_delete, _asn_cache_info,
    _lookup_asn, _fmt_asn_short,
)
# ── Tier-1 рефакторинг: Standalone UI-экраны ─────────────────────────────────
from vless_installer.modules.standalone_screens import (
    check_exit_geo, do_view_logs, do_check_domain_external, do_system_dashboard,
)
# ── Tier-1 рефакторинг: Fail2ban + Xray watchdog ─────────────────────────────
from vless_installer.modules.fail2ban_setup import (
    FAIL2BAN_CONF, _WATCHDOG_TIMER, _WATCHDOG_SERVICE, _WATCHDOG_SCRIPT,
    setup_fail2ban, _watchdog_install, _watchdog_remove, do_manage_watchdog,
)
# ── Tier-1 рефакторинг: SSH hardening ────────────────────────────────────────
from vless_installer.modules.ssh_hardening import (
    _SSHD_CONFIG, _SSHD_BACKUP, _ssh_2fa_install, do_ssh_hardening,
)
# ── Tier-1 рефакторинг: фундаментальные хелперы (resources) ──────────────────
from vless_installer.modules.resources import (
    _get_total_ram_mb, _get_total_cpu,
    gen_uuid, gen_hex, gen_spiderx,
    get_server_ip, country_flag_emoji,
    get_server_country, get_server_country_cached,
    get_adaptive_value, generate_self_signed_cert,
)
# ── Tier-1 рефакторинг: MTU/MSS тюнинг + tracepath-диагностика ───────────────
from vless_installer.modules.mtu_tuning import (
    _MTU_STATE_FILE,
    _mtu_probe, _mtu_get_iface, _mtu_apply, _mtu_remove_rules,
    _mtu_state_load, _mtu_state_save,
    do_mtu_tuning, _mtu_persist,
    do_mtu_tracepath_diag, _mtu_tracepath_one,
)
# ── Tier-1 рефакторинг: GeoIP-блокировка + аудит подключений ─────────────────
from vless_installer.modules.geoip_block import (
    do_manage_geoip_block,
    _geoip_block_get_rules, _geoip_apply_routing,
    _geoip_set_allowlist, _geoip_add_country_block, _geoip_add_scanner_block,
    _geoip_remove_all,
)
from vless_installer.modules.connection_audit import (
    do_connection_audit,
    _parse_access_log,
    _audit_user_summary, _audit_recent_connections,
    _audit_suspicious, _audit_active_now,
)
# ── Tier-2 рефакторинг: Backup/rollback/unit tests/connectivity ──────────────
from vless_installer.modules.backup_rollback import (
    create_backup, perform_rollback, run_unit_tests, verify_connectivity,
)
# ── Tier-2 рефакторинг: DNSCrypt setup ───────────────────────────────────────
from vless_installer.modules.dnscrypt_setup import (
    _get_dnscrypt_port, install_dnscrypt, apply_dnscrypt_tuning,
)
# ── Tier-2 рефакторинг: Networking / sysctl / firewall ───────────────────────
from vless_installer.modules.network_setup import (
    configure_firewall, apply_network_optimizations, apply_sysctl_and_limits,
)
# ── Tier-2 рефакторинг: GeoIP/GeoSite files ──────────────────────────────────
from vless_installer.modules.geo_files import (
    download_geo_files, setup_geo_autoupdate, do_manage_geo_update,
)
# ── Tier-2 рефакторинг: SSL / certbot ────────────────────────────────────────
from vless_installer.modules.ssl_certbot import (
    _CERTBOT_MONITOR_CRON, _CERTBOT_MONITOR_SCRIPT,
    obtain_ssl_cert, fix_letsencrypt_permissions,
    ensure_cert_fix_script, setup_cert_renewal,
    _certbot_renew_and_notify, _certbot_install_monitor_cron,
    do_manage_certbot_monitor,
)
# ── Tier-2 рефакторинг: Failover + auto-fallback ─────────────────────────────
from vless_installer.modules.failover import (
    _FAILOVER_LOG, _FAILOVER_SCRIPT, _FAILOVER_CRON, _FAILOVER_STATE,
    _failover_load, _failover_save, _failover_install, do_failover_status,
    _auto_fallback_install, _auto_fallback_set_flag, do_manage_auto_fallback,
)
# ── Tier-2 рефакторинг: Client config export + share + uninstall ─────────────
from vless_installer.modules.client_config_export import (
    do_generate_client_config, do_export_client_config, do_share_config_server,
)
from vless_installer.modules.uninstall import do_uninstall
# ── Tier-2 рефакторинг: TTL users + blocked ──────────────────────────────────
from vless_installer.modules.ttl_users import (
    TTL_FILE, TTL_CRON_SCRIPT, TTL_CRON_FILE, TTL_LOG, BLOCKED_FILE,
    _ttl_load, _ttl_save, _ttl_expires_str, _ttl_is_expired,
    _ttl_expires_within_hours, _ttl_set, _ttl_remove,
    _blocked_load, _blocked_save, _ttl_block_user, _ttl_unblock_user,
    _ttl_is_blocked, _ttl_check_and_expire, _ttl_install_cron,
    _ttl_remove_cron, _ttl_cron_active, do_manage_ttl_users,
)
# ── Tier-2 рефакторинг: Key & credential rotation ────────────────────────────
from vless_installer.modules.credential_rotation import (
    _UUID_CRON_TAG, _UUID_CRON_SCRIPT,
    _uuid_rotate_now, _uuid_install_cron, do_manage_uuid_rotation,
    _rotate_reality_keys, do_manage_reality_keys, _menu_rotation,
)
# ── Tier-2 рефакторинг: Health report + traffic tracking ─────────────────────
from vless_installer.modules.health_report import (
    do_health_report, _health_report_install_cron, do_manage_health_report,
)
from vless_installer.modules.traffic_tracking import (
    TRAFFIC_LIMITS_FILE,
    _limits_load, _limits_save, _query_user_traffic_bytes,
    _stats_api_is_configured, _check_traffic_limits_once,
    do_manage_traffic_limits,
)
# ── Tier-3 рефакторинг: System / startup / package manager ───────────────────
from vless_installer.modules.system_deps import (
    _CMD_TO_PKG, _PKG_TO_CMDS,
    _init_pkg_mgr, _pkg_install, _pkg_update,
    _find_pkg_for_missing_cmd, _smart_recover,
    _wait_apt_lock_startup, ensure_startup_dependencies,
)
# ── Tier-3 рефакторинг: Nginx / sites ────────────────────────────────────────
from vless_installer.modules.nginx_setup import (
    setup_nginx_rate_limit, create_website,
    _create_techhub, _create_nexcloud, _create_simple_site,
    _ensure_nginx_sites_enabled_include,
    setup_nginx_temp, setup_nginx_final, setup_nginx_systemd_override,
)
# ─────────────────────────────────────────────────────────────────────────────
# ── Tier-3 рефакторинг: RU subnets + AS-direct routing ───────────────────────
from vless_installer.modules.ru_subnets import (
    RU_SUBNETS_FILE, RU_SUBNETS_TIMER, RU_SUBNETS_SERVICE,
    RIPE_DELEGATED_URL, RIPE_DELEGATED_URL_MIRROR, _RU_SUBNET_RULE_COMMENT,
    _fetch_ru_subnets_from_ripe, _ru_subnets_apply_to_xray,
    _ru_subnets_remove_from_xray, _ru_subnets_install_timer,
    _ru_subnets_remove_timer, _ru_subnets_cli_update,
    do_manage_ru_subnet_direct, _ru_subnets_restore_if_needed,
)
from vless_installer.modules.as_direct import (
    AS_DIRECT_DIR, AS_DIRECT_LIST_FILE, AS_DIRECT_TIMER, AS_DIRECT_SERVICE,
    RIPE_STAT_PREFIXES_URL,
    _as_normalize, _resolve_asn_from_input, _as_validate, _as_direct_file,
    _as_direct_list_load, _as_direct_list_save, _fetch_prefixes_for_asn,
    _as_direct_save, _as_direct_apply_to_xray, _as_direct_remove_from_xray,
    _as_suggest_server_asn, _as_direct_install_timer, _as_direct_remove_timer,
    _as_direct_cli_update, _as_ask_action, _as_action_label, do_manage_as_direct,
    _as_direct_restore_if_needed,
)
# ── Tier-3 рефакторинг: AutoBan (TLS handshake error autoban) ────────────────
from vless_installer.modules.autoban import (
    _XRAY_BAN_STATE, _XRAY_BAN_CRON, _XRAY_BAN_SCRIPT, _XRAY_BAN_LOG,
    _XRAY_BAN_REPORT, _BAN_THRESHOLD_DEFAULT, _BAN_WINDOW_MINUTES,
    _BAN_WHITELIST_DEFAULT, _BAN_REPORT_TTL_DAYS,
    _ban_report_rotate, _ban_report_append, _ban_report_show_in_box,
    _autoban_load, _autoban_save, _autoban_get_chain_ips,
    _autoban_run_once, _autoban_install_cron, do_manage_autoban,
)
# ── Tier-3 рефакторинг: Backup manager + status + speed + reconfig + mode ────
from vless_installer.modules.backup_manager import (
    _SCHEDULED_BACKUP_CRON, _scheduled_backup_run, do_manage_scheduled_backup,
)
from vless_installer.modules.speed_test import do_speed_test
from vless_installer.modules.reconfigure import do_reconfigure
from vless_installer.modules.migration import (
    do_full_migration_export, do_full_migration_import,
)
from vless_installer.modules.quick_status import (
    _STATS_SORT_KEYS, _TTFB_TARGETS,
    do_quick_status, do_connection_quality_test,
)
from vless_installer.modules.switch_mode import switch_mode_ab
from vless_installer.modules.traffic_history import (
    TRAFFIC_HISTORY_FILE,
    _traffic_snapshot_save, _install_traffic_snapshot_cron, do_traffic_history,
)
# ── Tier-3 рефакторинг: Split tunnel ─────────────────────────────────────────
from vless_installer.modules.split_tunnel import (
    prompt_split_tunnel, _save_split_tunnel_custom, _load_split_tunnel_custom,
    build_split_tunnel_routing_rules, _xray_count_ru_subnet_rules,
    _show_xray_routing_rules, do_manage_split_tunnel,
    _apply_split_tunnel_config_from_state,
)
# ── Tier-4 рефакторинг: Diagnostics engine ───────────────────────────────────
from vless_installer.modules.diagnostics import (
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
# ── Tier-4 рефакторинг: Xray install / update / geo / config ─────────────────
from vless_installer.modules.xray_install import (
    _verify_sha256, _xray_print_manual_download_hint, _xray_try_local_zip,
    install_xray, _parse_x25519_keys, _parse_x25519_field,
    generate_reality_keys, _detect_xhttp_mode_support,
    generate_xray_config, generate_xray_config_xhttp, create_xray_service,
    _xray_get_release_info, _xray_version_norm, _xray_current_version,
    _xray_geo_is_runetfreedom, _geo_print_manual_download_hint,
    _xray_update_geo_runetfreedom, _xray_do_upgrade, _xray_restart_all_services,
    _nginx_restart_if_reality, _xray_find_config, _xray_config_rollback,
    _xray_safe_apply_config, _xray_rollback, do_xray_update_interactive,
    setup_xray_autoupdate, _install_autoupdate_service,
)
# ── Tier-4 рефакторинг: Install prompts ──────────────────────────────────────
from vless_installer.modules.install_prompts import (
    prompt_parameters, prompt_install_mode, prompt_protocol_mode,
    prompt_awg_exit_mode,
)
# ── Tier-4 рефакторинг: Users manager ────────────────────────────────────────
from vless_installer.modules.users_manager import (
    _users_load, _users_save, _users_get_config, _users_apply_config,
    _users_apply_to_config, _users_patch_config_no_restart, _users_gen_link,
    do_user_list, do_user_add, do_user_delete, do_user_show_link, do_user_menu,
    _show_qr, _gen_vless_link, generate_client_links,
    _unified_load_users, _unified_save_users, _unified_show_links,
    _do_user_stats_screen, _do_user_stats_screen_v2,
)
# ── Tier-4 рефакторинг: Emergency repair ─────────────────────────────────────
from vless_installer.modules.emergency_repair import do_emergency_repair
# ─────────────────────────────────────────────────────────────────────────────


def _set_config_owner(path) -> None:
    """
    Устанавливает права 640 root:xray на файл конфига.
    Xray-сервис запускается под User=xray, поэтому без этого
    он получает 'permission denied' и падает с кодом 23.
    Использует числовой GID — не зависит от наличия chown в PATH.
    """
    try:
        xray_gid = grp.getgrnam("xray").gr_gid
        os.chown(str(path), 0, xray_gid)
        os.chmod(str(path), 0o640)
    except KeyError:
        # Группы xray нет — ставим 644 чтобы xray мог читать как other
        try:
            os.chmod(str(path), 0o644)
        except Exception:
            pass
    except Exception:
        pass


# =============================================================================
#  ЦВЕТА И ФОРМАТИРОВАНИЕ
#  Переменная окружения VLESS_THEME=light — светлый фон (белый терминал)
# =============================================================================
_LIGHT_THEME = os.environ.get("VLESS_THEME", "").lower() == "light"

if _LIGHT_THEME:
    RED     = '\033[0;31m'
    GREEN   = '\033[0;32m'
    YELLOW  = '\033[0;33m'
    CYAN    = '\033[0;34m'   # синий вместо циана — лучше на белом фоне
    BLUE    = '\033[0;35m'   # пурпурный вместо синего
    MAGENTA = '\033[0;35m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    WHITE   = '\033[0;30m'   # чёрный — виден на белом фоне
    BGBLUE  = '\033[44m'
    NC      = '\033[0m'
    TITLE   = '\033[1;37m'   # ярко-белый — для заголовков на тёмном фоне бокса
else:
    RED     = '\033[0;31m'
    GREEN   = '\033[0;32m'
    YELLOW  = '\033[1;33m'
    CYAN    = '\033[0;36m'
    BLUE    = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    WHITE   = '\033[1;37m'
    BGBLUE  = '\033[44m'
    NC      = '\033[0m'
    TITLE   = WHITE  # в тёмной теме TITLE = WHITE, без изменений

# =============================================================================
#  ЛОГИРОВАНИЕ
# =============================================================================
LOG_FILE          = Path("/var/log/vless-install.log")
BACKUP_DIR        = Path("/var/backups/xray")
HEALTH_CHECK_FILE = Path("/var/lib/xray-installer/health.status")
STATE_FILE        = Path("/var/lib/xray-installer/state.json")
INSTALL_START_TIME = time.time()

for _d in (LOG_FILE.parent, BACKUP_DIR, HEALTH_CHECK_FILE.parent):
    _d.mkdir(parents=True, exist_ok=True)
try:
    LOG_FILE.touch()
    LOG_FILE.chmod(0o600)
except Exception:
    pass


def log_to_file(level: str, msg: str) -> None:
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        with LOG_FILE.open('a') as f:
            f.write(f"[{ts}] [{level}] {msg}\n")
    except Exception:
        pass


def info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");    log_to_file("INFO",    msg)
def success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}");   log_to_file("SUCCESS", msg)
def warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}");  log_to_file("WARN",    msg)
def dim(msg: str)     -> None: print(f"{DIM}{msg}{NC}")

def die(msg: str) -> None:
    print(f"{RED}[ERROR]{NC} {msg}", file=sys.stderr)
    log_to_file("ERROR", msg)
    sys.exit(1)


log_to_file("INFO", "=== Запуск VLESS Ultimate Installer v4.12.10 ===")
log_to_file("INFO", f"Время начала: {datetime.now()}")

# =============================================================================
#  БАННЕР
# =============================================================================
def _make_banner(show_ram_warning: bool = True) -> str:
    _OW = 64   # внутренняя ширина внешней рамки
    _IW = _OW - 6  # внутренняя ширина вложенной рамки (58)
    _blank  = "║" + " " * _OW + "║"
    _top    = "╔" + "═" * _OW + "╗"
    _bot    = "╚" + "═" * _OW + "╝"
    _itop   = "║  ╔" + "═" * _IW + "╗  ║"
    _ibot   = "║  ╚" + "═" * _IW + "╝  ║"
    def _art(a):
        return "║  " + a + " " * (_OW - 2 - len(a)) + "║"
    def _irow(t):
        return "║  ║ " + t + " " * (_OW - 8 - len(t)) + " ║  ║"
    _art_lines = [
        "██╗   ██╗██╗     ███████╗███████╗███████╗",
        "██║   ██║██║     ██╔════╝██╔════╝██╔════╝",
        "██║   ██║██║     █████╗  ███████╗███████╗",
        "╚██╗ ██╔╝██║     ██╔══╝  ╚════██║╚════██║",
        " ╚████╔╝ ███████╗███████╗███████║███████║",
        "  ╚═══╝  ╚══════╝╚══════╝╚══════╝╚══════╝",
    ]
    _info_lines = [
        "VLESS REALITY + xHTTP TLS INSTALLER v4.12.10",
        "IPv6 DualStack | 6 Templates | SHA256 Verify",
        "Balancer: RoundRobin | LeastPing | LeastLoad",
        "Dashboard | FP Rotate | GeoCheck | Multi-User",
    ]
    # Строки предупреждения о RAM (красные + жирные через ANSI)
    _BOLD_RED = '\033[1;31m'
    _NC_LOC   = '\033[0m'
    _ram_lines = [
        f"{_BOLD_RED}⚠  ВНИМАНИЕ: для корректной работы всех функций   {_NC_LOC}",
        f"{_BOLD_RED}⚠  рекомендуется ОЗУ VPS от 2 ГБ!                 {_NC_LOC}",
        f"{_BOLD_RED}⚠  При меньшем объёме работа скрипта и ПО          {_NC_LOC}",
        f"{_BOLD_RED}⚠  НЕ ГАРАНТИРУЕТСЯ.                               {_NC_LOC}",
    ]
    # Вспомогательная функция: строка рамки с ANSI (учитываем скрытые символы)
    def _irow_ansi(raw: str) -> str:
        """Строка внутренней рамки. raw уже содержит ANSI — ширина вычисляется по видимым символам."""
        import re as _re
        visible = _re.sub(r'\033\[[0-9;]*m', '', raw)
        pad = _OW - 8 - len(visible)
        return "║  ║ " + raw + " " * max(pad, 0) + " ║  ║"
    _ram_sep = "║  ║" + "─" * _IW + "║  ║"
    _ram_block = (
        [_ram_sep] + [_irow_ansi(rl) for rl in _ram_lines]
        if show_ram_warning else []
    )
    _rows = (
        [_top, _blank]
        + [_art(a) for a in _art_lines]
        + [_blank, _itop]
        + [_irow(il) for il in _info_lines]
        + _ram_block
        + [_ibot, _blank, _bot]
    )
    return "\n" + "\n".join(_rows) + "\n"

# Сохраняем глобальную BANNER для обратной совместимости (verify.py и
# любой другой код, ожидающий готовую строку с баннером). Это статичный
# вариант "по умолчанию" — с RAM-предупреждением, как раньше.
BANNER = _make_banner(show_ram_warning=True)

# Порог ОЗУ (МБ), ниже которого показывается предупреждение в баннере.
# 2048 МБ заявлено как рекомендуемый минимум в самом тексте плашки.
_RAM_WARNING_THRESHOLD_MB = 2048

def print_banner() -> None:
    # К моменту вызова print_banner() (из main.py или из меню) модуль
    # уже полностью импортирован, TOTAL_RAM определён ниже по файлу —
    # переменная доступна в момент вызова функции.
    _low_ram = TOTAL_RAM < _RAM_WARNING_THRESHOLD_MB
    print(_make_banner(show_ram_warning=_low_ram))

# =============================================================================
#  ПРОГРЕСС-БАР
# =============================================================================
class Progress:
    def __init__(self) -> None:
        self.total:   int = 100
        self.current: int = 0
        self.label:   str = ""

    def init(self, total: int = 100, label: str = "Установка") -> None:
        self.total   = total
        self.current = 0
        self.label   = label
        print()

    def update(self, increment: int = 1, label: str = "") -> None:
        if label:
            self.label = label
        self.current = min(self.current + increment, self.total)
        percent = self.current * 100 // self.total
        width   = 40
        filled  = percent * width // 100
        empty   = width - filled
        # Цвет градиентом по прогрессу
        if percent >= 100:   col = WHITE
        elif percent >= 75:  col = GREEN
        elif percent >= 40:  col = CYAN
        else:                col = BLUE
        bar_fill  = f"{col}{'▓' * filled}{NC}"
        bar_empty = f"{DIM}{'░' * empty}{NC}"
        print(
            f"\r{CYAN}[{self.label:<15}]{NC} "
            f"{bar_fill}{bar_empty} {col}{percent:3d}%{NC}\033[K",
            end="", flush=True
        )
        if percent == 100:
            print()


PROGRESS = Progress()

# =============================================================================
#  СИСТЕМНЫЕ ПЕРЕМЕННЫЕ
# =============================================================================
CONFIG_DIR           = Path("/etc/xray")
NGINX_CONF_DIR       = Path("/etc/nginx/sites-available")
NGINX_ENABLED_DIR    = Path("/etc/nginx/sites-enabled")
XRAY_BIN             = Path("/usr/local/bin/xray")
XRAY_SERVICE         = Path("/etc/systemd/system/xray.service")
OPTIMIZER_CONF       = Path("/etc/sysctl.d/99-vless-performance.conf")
LIMITS_CONF          = Path("/etc/security/limits.d/99-vless-limits.conf")
SYSTEMD_CONF         = Path("/etc/systemd/system.conf.d/99-vless-limits.conf")
# FAIL2BAN_CONF is now imported from vless_installer.modules.fail2ban_setup (see top of file).
NGINX_RATE_LIMIT_CONF= Path("/etc/nginx/conf.d/rate-limit.conf")
LOCK_FILE            = CONFIG_DIR / ".vless_installed"
UFW_MARK_FILE        = Path("/var/lib/xray-installer/ufw-rules")
XRAY_BACKUP_DIR      = BACKUP_DIR / "binaries"

# Пути для модуля диагностики (check_split_tunnel)
DIAG_CONFIG_FILE     = CONFIG_DIR / "config.json"
DIAG_ALT_CONFIG_FILE = Path("/usr/local/etc/xray/config.json")
DIAG_ACCESS_LOG      = Path("/var/log/xray/access.log")
DIAG_ERROR_LOG       = Path("/var/log/xray/error.log")

# Порт Stats API (должен совпадать с _DIAG_STATS_API_ADDR в модуле диагностики)
XRAY_STATS_API_PORT = 10085


def _xray_log_block() -> dict:
    """
    Возвращает секцию "log" для конфига Xray.
    loglevel=info нужен чтобы xray писал объём трафика в access.log —
    это позволяет диагностике (метод 2) считать байты по тегам.
    """
    return {
        "loglevel": "info",
        "access":   "/var/log/xray/access.log",
        "error":    "/var/log/xray/error.log",
    }


def _xray_stats_blocks() -> dict:
    """
    Возвращает dict с секциями stats, api, policy и inbound для Stats API.
    Вставляется в config верхнего уровня через config.update(_xray_stats_blocks()).

    Stats API позволяет диагностике (метод 1) получать точные накопленные
    байты по каждому outbound-тегу через 'xray api statsquery'.

    Возвращает:
        stats   — включает механизм счётчиков
        api     — gRPC-сервис на порту XRAY_STATS_API_PORT (только localhost)
        policy  — разрешает считать байты для outbound
        _stats_inbound — готовый inbound-блок для вставки в config["inbounds"]
    """
    return {
        "stats": {},
        "api": {
            "tag":      "xray-stats-api",
            "services": ["StatsService", "HandlerService"],
        },
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink":   True,
                    "statsUserDownlink": True,
                },
            },
            "system": {
                "statsOutboundUplink":   True,
                "statsOutboundDownlink": True,
                "statsUserUplink":       True,
                "statsUserDownlink":     True,
            },
        },
        "_stats_inbound": {
            "listen":   "127.0.0.1",
            "port":     XRAY_STATS_API_PORT,
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1"},
            "tag":      "xray-stats-api",
        },
    }


def _apply_stats_to_config(config: dict) -> None:
    """
    Встраивает Stats API в уже собранный dict конфига xray на месте.
    Добавляет: stats, api, policy, inbound на 127.0.0.1:XRAY_STATS_API_PORT,
    routing-правило (первым) чтобы API-трафик не попал в основные outbound.
    Идемпотентен: повторный вызов не дублирует блоки.
    """
    blocks = _xray_stats_blocks()

    # Верхнеуровневые секции
    config.setdefault("stats", blocks["stats"])
    config.setdefault("api",   blocks["api"])
    # policy.system — мержим принудительно, чтобы statsUser* всегда попадали
    # даже если секция policy уже существует (setdefault её не обновит)
    policy_dict = config.setdefault("policy", {})
    policy_sys = policy_dict.setdefault("system", {})
    policy_sys["statsOutboundUplink"]   = True
    policy_sys["statsOutboundDownlink"] = True
    policy_sys["statsUserUplink"]       = True
    policy_sys["statsUserDownlink"]     = True
    # policy.levels."0" — без этого xray не считает трафик пользователей,
    # т.к. все соединения проходят через level 0, где сбор должен быть включён явно
    policy_lvl0 = policy_dict.setdefault("levels", {}).setdefault("0", {})
    policy_lvl0["statsUserUplink"]   = True
    policy_lvl0["statsUserDownlink"] = True

    # Inbound — добавляем только если ещё нет с таким тегом
    inbound = blocks["_stats_inbound"]
    inbounds = config.setdefault("inbounds", [])
    if not any(ib.get("tag") == "xray-stats-api" for ib in inbounds):
        inbounds.append(inbound)

    # Routing rule — направляем API inbound на api outbound (первым правилом)
    routing = config.setdefault("routing", {})
    rules   = routing.setdefault("rules", [])
    api_rule = {
        "type":        "field",
        "inboundTag":  ["xray-stats-api"],
        "outboundTag": "xray-stats-api",
    }
    if not any(r.get("inboundTag") == ["xray-stats-api"] for r in rules):
        rules.insert(0, api_rule)

    # Outbound для api (xray требует outbound с тегом == api.tag)
    outbounds = config.setdefault("outbounds", [])
    if not any(ob.get("tag") == "xray-stats-api" for ob in outbounds):
        outbounds.append({"protocol": "freedom", "tag": "xray-stats-api"})

# (_get_total_ram_mb, _get_total_cpu вынесены в vless_installer.modules.resources;
#  импорт — в верхней секции этого файла.)

TOTAL_RAM = _get_total_ram_mb()
TOTAL_CPU = _get_total_cpu()

IS_IPV6_AVAILABLE: bool = False
IPV6_PREFLIGHT:    str  = ""
IPV6_ROUTE_OK:     bool = False

PARAM_UUID:            str  = ""
PARAM_DOMAIN:          str  = ""
PARAM_SHORTID:         str  = ""
PARAM_PUBLIC_KEY:      str  = ""
PARAM_PRIVATE_KEY:     str  = ""
PARAM_EMAIL:           str  = ""
PARAM_SPIDERX:         str  = ""
PARAM_SOCKET_PATH:     str  = ""
PARAM_REALITY_DEST:    str  = ""   # dest/sni для REALITY при AWG-транспорте (чужой сайт, напр. www.microsoft.com)
PARAM_DOMAIN_STRATEGY: str  = ""
PARAM_SITE_TEMPLATE:   str  = ""
PARAM_FINGERPRINT:     str  = "chrome"   # TLS/uTLS fingerprint, выбирается при установке
PRIVATE_KEY_MODE:      str  = "auto"

ROLLBACK_AVAILABLE: bool = False
BACKUP_TIMESTAMP:   str  = ""
INSTALL_STARTED:    bool = False
STAGE_UFW_DONE:     bool = False
STAGE_XRAY_DONE:    bool = False
STAGE_NGINX_DONE:   bool = False

# DNSCrypt-proxy globals
DNSCRYPT_BIN         = Path("/usr/local/bin/dnscrypt-proxy")
DNSCRYPT_CONF_DIR    = Path("/etc/dnscrypt-proxy")
DNSCRYPT_CONF        = DNSCRYPT_CONF_DIR / "dnscrypt-proxy.toml"
DNSCRYPT_SERVICE     = Path("/etc/systemd/system/dnscrypt-proxy.service")
DNSCRYPT_LISTEN_ADDR = "127.0.0.1"
DNSCRYPT_LISTEN_PORT = 5300
DNSCRYPT_INSTALLED:  bool = False
PARAM_USE_DNSCRYPT:  bool = False

# =============================================================================
#  CLOUDFLARE WARP GLOBALS
# =============================================================================
WARP_INSTALLED:      bool = False
WARP_CONNECTED:      bool = False

# Режим маршрутизации WARP:
#   "full"      — весь трафик через WARP (кроме SSH-клиента)
#   "selective" — только указанные пользователем IP/домены
#   "runet"     — заблокированные РФ ресурсы (списки runetfreedom)
WARP_MODE:           str  = "full"

# IP SSH-клиента — всегда исключается из WARP для защиты доступа
WARP_SSH_CLIENT_IP:  str  = ""

# Пользовательские ресурсы для selective-режима
WARP_CUSTOM_IPS:     list[str] = []
WARP_CUSTOM_DOMAINS: list[str] = []

# Путь к конфигу WARP MDM (для переопределения настроек)
WARP_MDM_FILE = Path("/var/lib/cloudflare-warp/mdm.xml")

PKG_MGR: str = ""

# =============================================================================
#  РЕЖИМ УСТАНОВКИ (A = одиночный сервер, B = каскад / chained proxy)
# =============================================================================
INSTALL_MODE: str = "A"   # "A" или "B"

# Параметры для Режима B (российский VPS → зарубежный VPS)
CHAIN_EXIT_HOST:    str  = ""   # IP / домен зарубежного VPS
CHAIN_EXIT_PORT:    int  = 443  # порт, на котором зарубежный VPS слушает VLESS
CHAIN_EXIT_UUID:    str  = ""   # UUID зарубежного VPS
CHAIN_EXIT_PUBKEY:  str  = ""   # PublicKey зарубежного VPS
CHAIN_EXIT_SHORTID: str  = ""   # ShortID зарубежного VPS
CHAIN_EXIT_SNI:     str  = ""   # SNI зарубежного VPS (его домен)
CHAIN_EXIT_FP:      str  = "chrome"

# Список всех exit-нод для мульти-каскада (Режим B, до 10 нод)
# Каждый элемент — dict: {host, port, uuid, pubkey, shortid, sni, fp}
CHAIN_NODES: list[dict] = []

MAX_CHAIN_NODES: int = 10

# Стратегия балансировки между exit-нодами (Режим B, только при 2+ нодах)
# "roundRobin" — по очереди, равномерно
# "leastPing"  — к ноде с наименьшим RTT (нужен observatory)
# "leastLoad"  — к ноде с наименьшей нагрузкой (нужен observatory)
# "random"     — случайный выбор при каждом подключении
CHAIN_BALANCER_STRATEGY: str = "roundRobin"

# Индекс "прикреплённой" exit-ноды (0-based). -1 = балансировщик активен (авто).
# При значении >= 0 весь трафик идёт только через эту ноду, балансировщик отключён.
CHAIN_PINNED_NODE_INDEX: int = -1

# =============================================================================
#  AWG 2.0 (AmneziaWG) — параметры для Режима B
# =============================================================================
AWG_EXIT_ENABLED:    bool = False  # True если выбран AWG как транспорт exit
# ── Hysteria2 транспорт (Режим B, аддитивно) ──────────────────────────────────
H2_EXIT_ENABLED:     bool = False  # True если выбран Hysteria2 как транспорт exit
# При H2_EXIT_ENABLED=True: AWG_EXIT_ENABLED=False, prompt_chain_params_multi() пропускается.
# Xray конфиг генерируется стандартным generate_xray_config_chain_entry_multi() без изменений.
# После установки вызывается h2_exit_install_local() из hysteria2_exit_mgr.
# ──────────────────────────────────────────────────────────────────────────────
AWG_EXIT_HOST:       str  = ""     # IP зарубежного VPS с AWG-сервером
AWG_EXIT_PORT:       int  = 51820  # UDP-порт AWG-сервера
AWG_CLIENT_LISTEN_PORT: int = 11100  # UDP-порт на котором слушает AWG-клиент (entry-нода)
AWG_INTERFACE:       str  = "awg0" # имя WG-интерфейса на RU-сервере
AWG_SUBNET:          str  = "10.66.66.0/24"
AWG_CLIENT_IP:       str  = "10.66.66.2/32"
AWG_SERVER_IP:       str  = "10.66.66.1/32"
# AWG 2.0 — IPv6 Dual-Stack (ULA-подсеть, не конфликтует с глобальными адресами)
AWG_SUBNET_V6:       str  = "fd66:66:66::/64"
AWG_CLIENT_IPv6:     str  = "fd66:66:66::2/128"
AWG_SERVER_IPv6:     str  = "fd66:66:66::1/128"
AWG_MTU:             int  = 1280
AWG_INSTALLED:       bool = False
# Ключи — заполняются в awg_generate_keys()
AWG_SERVER_PRIVKEY:  str  = ""
AWG_SERVER_PUBKEY:   str  = ""
AWG_CLIENT_PRIVKEY:  str  = ""
AWG_CLIENT_PUBKEY:   str  = ""
AWG_PRESHARED_KEY:   str  = ""
# Параметры обфускации AmneziaWG
AWG_JC:   int = 4       # Junk packet count  (4-10 рекоменд.)
AWG_JMIN: int = 40      # Junk packet min size
AWG_JMAX: int = 70      # Junk packet max size
AWG_S1:   int = 0       # Init packet junk size
AWG_S2:   int = 0       # Response packet junk size
AWG_H1:   int = 1       # Init packet magic header
AWG_H2:   int = 2       # Response packet magic header
AWG_H3:   int = 3       # Under load packet magic header
AWG_H4:   int = 4       # Transport packet magic header
# Routing mark для policy routing
AWG_FWMARK:      int = 1000
AWG_ROUTE_TABLE: int = 1000

# === PATCH v2: globals ===
AWG_NODES: list = []            # [] → одна нода (совместимость с одиночным режимом)
AWG_ACTIVE_NODE_INDEX: int = 0  # индекс активной ноды в AWG_NODES
AWG_PREFER_INDEX: int = 0       # предпочтительная нода (для возврата после failover)
_AWG_SSH_CLIENT_IP: str = ""    # IP SSH-клиента — исключается из AWG-маршрутизации
# === END PATCH v2: globals ===
# Бинарники AWG
AWG_BIN:       str = "awg"
AWG_QUICK_BIN: str = "awg-quick"

# =============================================================================
#  РЕЖИМ ПРОТОКОЛА (REALITY / xHTTP_TLS)
# =============================================================================
# "reality"  — VLESS + TCP + REALITY (xtls-rprx-vision)  — классический
# "xhttp"    — VLESS + xHTTP + TLS   (H2/HTTPS маскировка)
PROTOCOL_MODE: str = "reality"   # "reality" | "xhttp"

# Режим XTLS-flow (только для PROTOCOL_MODE == "reality")
# "xtls-rprx-vision"  — Vision (умолчание, лучшая совместимость, рекомендуется)
# "xtls-rprx-splice"  — Splice (меньше копирований в ядре, выше скорость на Linux)
# ""                  — без flow (fallback для старых клиентов / отладки)
XTLS_FLOW: str = "xtls-rprx-vision"

# Режим работы xHTTP (только для PROTOCOL_MODE == "xhttp")
# "streamup" | "streamone" | "packetup"
XHTTP_MODE: str = "streamup"

# Порт прослушивания Xray (общий для REALITY и xHTTP, по умолчанию 443)
# Пользователь может выбрать любой порт 1–65535 при установке.
SERVER_PORT: int = 443
XHTTP_PORT:  int = 443   # backward-compat alias, всегда == SERVER_PORT

# Путь (path) xHTTP endpoint
XHTTP_PATH: str = ""   # авто-генерируется если пусто
XHTTP_MODE_SUPPORTED: bool = False  # True только после _detect_xhttp_mode_support(); безопасный дефолт — False

# Пресет производительности xHTTP (smux / sockopt / TLS)
# "auto"    — умолчания Xray, без дополнительных параметров
# "speed"   — максимальная пропускная способность (32 потока, tcpNoDelay, TLS 1.3)
# "balance" — компромисс скорость/стабильность (16 потоков, tcpNoDelay, TLS 1.2+)
XHTTP_PERF_PRESET: str = "auto"

# =============================================================================
#  ДОПОЛНИТЕЛЬНЫЕ ПАРАМЕТРЫ ОПТИМИЗАЦИИ xHTTP (по документации XHTTP: Beyond REALITY)
# =============================================================================
# xPaddingBytes — размер padding в заголовках запросов/ответов.
#   Диапазон "min-max" (рекомендуется "100-1000"), каждый раз случайный.
#   Уменьшает fingerprint по фиксированной длине заголовка.
XHTTP_PADDING_BYTES: str = "100-1000"

# noSSEHeader — отключить Content-Type: text/event-stream в ответе сервера.
#   false = SSE-заголовок включён (по умолчанию, лучшая совместимость).
#   true  = отключить (если CDN блокирует SSE).
XHTTP_NO_SSE_HEADER: bool = False

# scStreamUpServerSecs — только для stream-up, только сервер.
#   Сервер каждые N секунд отправляет xPaddingBytes байт для поддержания соединения.
#   Диапазон "20-80" (по умолч.), предотвращает разрыв CF/CDN через 100 с без данных.
#   -1 = отключить механизм.
XHTTP_SC_STREAM_UP_SERVER_SECS: str = "20-80"

# scMaxEachPostBytes — только для packet-up.
#   Максимальный объём данных в одном POST-запросе клиента.
#   Должно быть меньше лимита CDN/middlebox. По умолчанию 1000000 (1 МБ).
#   Поддерживает диапазон: "500000-1000000".
XHTTP_SC_MAX_EACH_POST_BYTES: str = "1000000"

# scMaxBufferedPosts — только для packet-up, только сервер.
#   Максимальное количество буферизованных POST-запросов на сервере (на одну сессию).
#   При превышении соединение разрывается. По умолчанию 30.
XHTTP_SC_MAX_BUFFERED_POSTS: int = 30

# =============================================================================
#  ДОПОЛНИТЕЛЬНЫЕ ПАРАМЕТРЫ xHTTP (блок extra, новая структура документации)
# =============================================================================
# host — заголовок Host HTTP-запросов клиента. Отдельно от SNI.
#   Нужен при CDN/domain fronting, когда SNI и Host различаются.
#   Пустая строка = использовать SNI из tlsSettings.
XHTTP_HOST: str = ""

# noGRPCHeader — отключить Content-Type: application/grpc в upload-запросах (клиент).
#   false = заголовок grpc включён (маскировка под gRPC, умолчание).
#   true  = отключить (если gRPC фильтруется провайдером/CDN).
XHTTP_NO_GRPC_HEADER: bool = False

# scMinPostsIntervalMs — только для packet-up, только клиент.
#   Минимальный интервал в мс между POST-запросами клиента в одном соединении.
#   По умолч. 30 мс. Диапазон "10-50" снижает fingerprint.
#   Слишком малый — перегружает буфер сервера; слишком большой — снижает скорость.
XHTTP_SC_MIN_POSTS_INTERVAL_MS: str = "30"

# xmux — мультиплексирование proxy-потоков внутри одного HTTP/2 соединения (клиент).
#   Существенно повышает пропускную способность при H2, особенно на высоком RTT.
#   Применяется в основном для streamup / streamone / auto.
XHTTP_XMUX_ENABLED: bool = False
XHTTP_XMUX_MAX_CONCURRENCY:   str = "16-32"   # параллельных proxy-потоков на соединение
XHTTP_XMUX_MAX_CONNECTIONS:   int = 0          # 0 = без лимита
XHTTP_XMUX_C_MAX_REUSE_TIMES: str = "0"        # переиспользований соединения; 0 = без лимита
XHTTP_XMUX_H_MAX_REQUEST_TIMES: str = "600-900" # запросов через H2-соединение до замены
XHTTP_XMUX_H_MAX_REUSABLE_SECS: str = "1800-3000" # время жизни соединения (сек)
XHTTP_XMUX_H_KEEP_ALIVE_PERIOD: int = 0        # keepalive период (сек); 0 = выкл

# enableSessionResumption — возобновление TLS-сессий (tlsSettings, сервер+клиент).
#   При включении TLS-хендшейк при переподключении не требует повторной передачи сертификата.
XHTTP_ENABLE_SESSION_RESUMPTION: bool = False

# tcpNoDelay — отключить алгоритм Nagle для xhttp sockopt (снижает латентность).
#   В пресете speed/balance уже включён, здесь — явное управление.
XHTTP_TCP_NO_DELAY: bool = False

# INSTALL_COMPLETED — сигнализирует EXIT TRAP что работа завершена нормально
INSTALL_COMPLETED: bool = False

# =============================================================================
#  РАЗДЕЛЬНОЕ ТУННЕЛИРОВАНИЕ (SPLIT TUNNELING)
# =============================================================================
# Если True — заблокированный в РФ трафик идёт через proxy, остальной — direct
SPLIT_TUNNEL_ENABLED: bool = False

# Пути к dat-файлам на диске
GEOSITE_DAT = CONFIG_DIR / "geosite.dat"
GEOIP_DAT   = CONFIG_DIR / "geoip.dat"

# URL актуальных списков runetfreedom (регулярно обновляются)
GEOSITE_URL = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat"
GEOIP_URL   = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat"

# Дополнительные домены/IP, добавленные вручную пользователем
# Формат: список строк — домен ("example.com") или CIDR ("1.2.3.0/24")
SPLIT_TUNNEL_EXTRA_DOMAINS: list[str] = []
SPLIT_TUNNEL_EXTRA_IPS:     list[str] = []

# Конфигурационный файл с пользовательскими дополнениями
SPLIT_TUNNEL_CUSTOM_FILE = Path("/etc/xray/split_tunnel_custom.json")

# =============================================================================
#  EXIT TRAP
# =============================================================================
import atexit

def _on_exit() -> None:
    global INSTALL_STARTED, STAGE_XRAY_DONE, STAGE_NGINX_DONE
    # Если установка завершена успешно — ничего не делаем
    if INSTALL_COMPLETED:
        return
    # Если установка ещё не начиналась (выход из меню) — ничего не делаем
    if not INSTALL_STARTED:
        return
    print()
    print(f"{RED}[ERROR]{NC} Скрипт завершился с ошибкой.")
    print(f"{YELLOW}[WARN]{NC}  Система может быть в неполном состоянии.")
    if shutil.which("ufw"):
        _run(["ufw", "allow", "22/tcp", "comment", "SSH (emergency restore)"],
             check=False, quiet=True)
    if STAGE_XRAY_DONE:
        _run(["systemctl", "stop",    "xray"], check=False, quiet=True)
        _run(["systemctl", "disable", "xray"], check=False, quiet=True)
    if STAGE_NGINX_DONE:
        _run(["systemctl", "stop", "nginx"], check=False, quiet=True)
    print(f"{YELLOW}[WARN]{NC}  Полный лог: {LOG_FILE}")

atexit.register(_on_exit)

# =============================================================================
#  УТИЛИТЫ
# =============================================================================
def command_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def find_nginx_bin() -> str | None:
    """Возвращает полный путь к бинарнику nginx, проверяя реальное существование файла."""
    found = shutil.which("nginx")
    if found:
        try:
            if Path(found).resolve().exists():
                return found
        except Exception:
            pass
    for p in ("/usr/sbin/nginx", "/usr/bin/nginx",
              "/usr/local/sbin/nginx", "/usr/local/bin/nginx",
              "/opt/nginx/sbin/nginx"):
        try:
            pp = Path(p)
            if pp.exists() and pp.resolve().exists():
                return p
        except Exception:
            pass
    try:
        import subprocess as _sp
        r = _sp.run(
            ["find", "/usr", "/opt", "/snap", "-name", "nginx",
             "-type", "f", "-executable"],
            capture_output=True, text=True, timeout=5
        )
        for line in r.stdout.splitlines():
            if line.strip():
                return line.strip()
    except Exception:
        pass
    return None

def _run(
    args: list[str],
    check: bool = True,
    quiet: bool = False,
    capture: bool = False,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
    cwd: str = None,  # <-- ДОБАВИТЬ ЭТУ СТРОКУ
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    try:
        result = subprocess.run(
            args,
            capture_output=(capture or quiet),
            text=True,
            input=input_text,
            env=merged_env,
            cwd=cwd,
        )
    except FileNotFoundError:
        if check:
            raise
        # check=False: команда не найдена — возвращаем фиктивный результат с кодом 127
        return subprocess.CompletedProcess(args, 127, stdout="", stderr=f"command not found: {args[0]}")
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, args,
                                            result.stdout, result.stderr)
    return result


# (get_adaptive_value, gen_uuid, gen_hex, gen_spiderx, get_server_ip,
#  country_flag_emoji, get_server_country, get_server_country_cached,
#  _SERVER_CC/_SERVER_NAME/_SERVER_FLAG cache, generate_self_signed_cert —
#  вынесены в vless_installer.modules.resources; импорт — в верхней секции
#  этого файла.)

# =============================================================================
#  ПРОВЕРКА РЕСУРСОВ
# =============================================================================
def _check_resources() -> None:
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable"):
                    mem_free_mb = int(line.split()[1]) // 1024
                    break
            else:
                mem_free_mb = 0
    except Exception:
        mem_free_mb = 0

    if mem_free_mb < 256:
        warn(f"Мало свободной RAM: {mem_free_mb} МБ (рекомендуется ≥ 256 МБ)")
        ans = input(f"{YELLOW}Продолжить? [y/N]:{NC} ").strip().lower()
        if ans != 'y':
            info("Отменено.")
            sys.exit(0)
    else:
        info(f"RAM: {mem_free_mb} МБ — OK | CPU: {TOTAL_CPU} ядер")

    try:
        r = _run(["df", "-BG", "/"], capture=True, check=False)
        parts = r.stdout.splitlines()[1].split()
        disk_free_gb = int(parts[3].rstrip('G'))
    except Exception:
        disk_free_gb = 0

    if disk_free_gb < 1:
        warn(f"Мало места на диске: {disk_free_gb} ГБ (рекомендуется ≥ 1 ГБ)")
        ans = input(f"{YELLOW}Продолжить? [y/N]:{NC} ").strip().lower()
        if ans != 'y':
            info("Отменено.")
            sys.exit(0)
    else:
        info(f"Диск: {disk_free_gb} ГБ свободно — OK")

# =============================================================================
#  IPV6 PREFLIGHT
# =============================================================================
def _check_ipv6_preflight() -> None:
    global IS_IPV6_AVAILABLE, IPV6_PREFLIGHT, IPV6_ROUTE_OK

    try:
        r = _run(["ip", "-6", "addr", "show", "scope", "global"],
                 capture=True, check=False)
        addrs = re.findall(r'inet6\s+([0-9a-f:]+)/', r.stdout)
        addrs = [a for a in addrs if not a.startswith('fe80')]
        IPV6_PREFLIGHT = addrs[0] if addrs else ""
    except Exception:
        IPV6_PREFLIGHT = ""

    if not IPV6_PREFLIGHT:
        warn("Публичный IPv6 не обнаружен — только IPv4.")
        IS_IPV6_AVAILABLE = False
        return

    info(f"IPv6-адрес: {IPV6_PREFLIGHT}")

    try:
        r = _run(["ip", "-6", "route", "show", "default"], capture=True, check=False)
        if "default" not in r.stdout:
            warn("IPv6-адрес есть, но маршрут по умолчанию отсутствует.")
            IS_IPV6_AVAILABLE = False
            return
    except Exception:
        IS_IPV6_AVAILABLE = False
        return

    ipv6_conn = False
    if command_exists("ping6"):
        r = _run(["ping6", "-c1", "-W2", "2001:4860:4860::8888"],
                 check=False, quiet=True)
        if r.returncode == 0:
            ipv6_conn = True

    if not ipv6_conn:
        r = _run(["curl", "-6", "-s", "--connect-timeout", "4",
                  "https://ipv6.icanhazip.com"],
                 check=False, quiet=True)
        if r.returncode == 0:
            ipv6_conn = True

    if not ipv6_conn:
        warn("IPv6-адрес и маршрут есть, но связность не подтверждена.")
        IS_IPV6_AVAILABLE = False
    else:
        IPV6_ROUTE_OK     = True
        IS_IPV6_AVAILABLE = True
        success(f"IPv6: {IPV6_PREFLIGHT} — маршрут и связность OK (dual-stack активен)")

# =============================================================================
#  МЕНЕДЖЕР ПАКЕТОВ
# =============================================================================
# (System / startup / package manager — _init_pkg_mgr, _pkg_install, _pkg_update,
#  _find_pkg_for_missing_cmd, _smart_recover, _wait_apt_lock_startup,
#  ensure_startup_dependencies, _CMD_TO_PKG, _PKG_TO_CMDS — вынесены в
#  vless_installer.modules.system_deps; импорт — в верхней секции этого файла.)


# (backup/rollback — create_backup, perform_rollback, run_unit_tests,
#  verify_connectivity — вынесены в vless_installer.modules.backup_rollback;
#  импорт — в верхней секции этого файла.)

# =============================================================================
#  ИНТЕРАКТИВНЫЙ ЗАПРОС ПАРАМЕТРОВ
# =============================================================================
# (prompt_parameters — вынесена в vless_installer.modules.install_prompts;
#  импорт — в верхней секции этого файла.)


# =============================================================================
#  ВЫБОР РЕЖИМА УСТАНОВКИ (A / B)
# =============================================================================
# (prompt_install_mode, prompt_protocol_mode — вынесены в
#  vless_installer.modules.install_prompts; импорт — в верхней секции этого файла.)



def _build_sockopt(tcp_no_delay: bool | None = None) -> dict:
    """
    Возвращает словарь sockopt с полным набором TCP-оптимизаций.
    Применяется ко всем протоколам (REALITY и xHTTP).
    tcp_no_delay: None → использовать глобальный XHTTP_TCP_NO_DELAY
    """
    no_delay = tcp_no_delay if tcp_no_delay is not None else XHTTP_TCP_NO_DELAY
    opt: dict = {
        "tcpFastOpen":        True,
        "tcpKeepAliveInterval": 15,
        "tcpKeepAliveIdle":   60,
        "tcpUserTimeout":     10000,
        "tcpCongestion":      "bbr",
    }
    if no_delay:
        opt["tcpNoDelay"] = True
    return opt


def _build_xhttp_settings(mode: str, path: str, preset: str | None = None) -> tuple[dict, dict]:
    """
    Возвращает (xhttpSettings, sockopt) согласно актуальной структуре документации
    XHTTP: Beyond REALITY (https://github.com/XTLS/Xray-core/discussions/4113).
    Все параметры оптимизации размещаются во вложенном объекте 'extra',
    как требует текущая версия документации.
    preset: "auto" | "speed" | "balance" | None → "auto"
    """
    p = preset or XHTTP_PERF_PRESET

    # --- Верхний уровень xhttpSettings ---
    xhttp: dict = {}
    if XHTTP_MODE_SUPPORTED:
        xhttp["mode"] = mode
    xhttp["path"] = path

    # host: заголовок Host запросов. Нужен при CDN / domain fronting.
    if XHTTP_HOST:
        xhttp["host"] = XHTTP_HOST

    # --- sockopt ---
    sockopt = _build_sockopt()

    # tcpNoDelay снижает задержку за счёт немедленной отправки сегментов.
    # В speed/balance включён принудительно, иначе — по выбору пользователя.
    if p in ("speed", "balance"):
        sockopt["tcpNoDelay"] = True

    # --- Объект extra: все параметры оптимизации ---
    extra: dict = {}

    # xPaddingBytes: случайный padding заголовков запросов/ответов.
    extra["xPaddingBytes"] = XHTTP_PADDING_BYTES

    # noGRPCHeader (клиент, stream-up/one): отключить Content-Type: application/grpc.
    # По умолчанию false — маскировка под gRPC.
    extra["noGRPCHeader"] = XHTTP_NO_GRPC_HEADER

    # noSSEHeader (сервер): отключить Content-Type: text/event-stream.
    if XHTTP_NO_SSE_HEADER:
        extra["noSSEHeader"] = True
    else:
        extra["noSSEHeader"] = False

    # Параметры stream-up (только сервер): keepalive против разрыва CDN/CF через 100 с.
    if mode in ("streamup", "streamone", "auto"):
        extra["scStreamUpServerSecs"] = XHTTP_SC_STREAM_UP_SERVER_SECS

    # Параметры packet-up (клиент + сервер).
    if mode in ("packetup", "auto"):
        # scMaxEachPostBytes: макс. данных в одном POST (клиент + сервер).
        extra["scMaxEachPostBytes"] = XHTTP_SC_MAX_EACH_POST_BYTES
        # scMinPostsIntervalMs: мин. интервал между POST-запросами клиента (мс).
        extra["scMinPostsIntervalMs"] = XHTTP_SC_MIN_POSTS_INTERVAL_MS
        # scMaxBufferedPosts: макс. буферизованных POST на сервере на сессию.
        extra["scMaxBufferedPosts"] = XHTTP_SC_MAX_BUFFERED_POSTS

    # xmux: мультиплексирование proxy-потоков внутри HTTP/2 соединения (клиент).
    if XHTTP_XMUX_ENABLED:
        extra["xmux"] = {
            "maxConcurrency":    XHTTP_XMUX_MAX_CONCURRENCY,
            "maxConnections":    XHTTP_XMUX_MAX_CONNECTIONS,
            "cMaxReuseTimes":    XHTTP_XMUX_C_MAX_REUSE_TIMES,
            "hMaxRequestTimes":  XHTTP_XMUX_H_MAX_REQUEST_TIMES,
            "hMaxReusableSecs":  XHTTP_XMUX_H_MAX_REUSABLE_SECS,
            "hKeepAlivePeriod":  XHTTP_XMUX_H_KEEP_ALIVE_PERIOD,
        }

    # maxConcurrentStreams (пресет): лимит параллельных H2-стримов.
    if p == "speed":
        extra["xmux"] = extra.get("xmux") or {}
        extra["xmux"]["maxConcurrency"] = "32-64"
    elif p == "balance":
        extra["xmux"] = extra.get("xmux") or {}
        extra["xmux"]["maxConcurrency"] = "16-32"

    xhttp["extra"] = extra

    return xhttp, sockopt


def _build_tls_settings_xhttp(domain: str, cert_file: str, key_file: str,
                               preset: str | None = None) -> dict:
    """
    Возвращает tlsSettings для xHTTP inbound с учётом пресета.
    Всегда minVersion=1.2 для совместимости с клиентами на старых Android/iOS.
    speed → добавляем приоритетные быстрые cipher suites (ECDSA/AES-GCM/ChaCha20).
    """
    p = preset or XHTTP_PERF_PRESET
    tls: dict = {
        "serverName":   domain,
        "certificates": [{"certificateFile": cert_file, "keyFile": key_file}],
        "alpn":         ["h2", "http/1.1"],
        "minVersion":   "1.2",
    }
    if XHTTP_ENABLE_SESSION_RESUMPTION:
        # Возобновление TLS-сессии: при переподключении не требует повторной
        # передачи сертификата — экономит время хендшейка.
        tls["enableSessionResumption"] = True
    if p == "speed":
        tls["cipherSuites"] = (
            "TLS_AES_128_GCM_SHA256:"
            "TLS_AES_256_GCM_SHA384:"
            "TLS_CHACHA20_POLY1305_SHA256:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256"
        )
    return tls


def _prompt_xhttp_options() -> None:
    """Дополнительные параметры xHTTP TLS."""
    global XHTTP_MODE, XHTTP_PATH, XHTTP_PORT

    _box_top(f"Режим xHTTP")
    _box_row()
    _box_row()
    _box_item("1", f"streamup   — однонаправленный стриминг (Upload-stream) {GREEN}(рекомендуется){NC}")
    _box_desc(f"Клиент стримит данные серверу как один длинный POST.")
    _box_desc(f"Хорошо обходит глубокую инспекцию, поддерживает большинство CDN.")
    _box_row()
    _box_item("2", f"streamone  — один двунаправленный поток")
    _box_desc(f"Полный HTTP/2 stream multiplex. Для CDN и продвинутого камуфляжа.")
    _box_row()
    _box_item("3", f"packetup   — пакетный режим (Upload-packet)")
    _box_desc(f"Каждый фрагмент данных — отдельный HTTP-запрос.")
    _box_desc(f"{YELLOW}⚠ Может не поддерживаться вашей версией Xray-core.{NC}")
    _box_row()
    _box_bottom()
    while True:
        choice = input(f"  {CYAN}Выбор [1]: {NC}").strip() or "1"
        if choice == "1":
            XHTTP_MODE = "streamup"
            break
        elif choice == "2":
            XHTTP_MODE = "streamone"
            break
        elif choice == "3":
            XHTTP_MODE = "packetup"
            warn("packetup выбран — убедитесь что ваша версия Xray-core его поддерживает")
            break
        else:
            warn("Введите 1, 2 или 3")
    success(f"xHTTP режим: {XHTTP_MODE}")

    # Путь endpoint
    auto_path = "/" + gen_hex(4)
    _box_top(f"xHTTP path (путь endpoint)")
    _box_row()
    _box_item("1", f"Авто: {DIM}{auto_path}{NC}")
    _box_item("2", f"Ввести вручную")
    _box_row()
    _box_bottom()
    while True:
        ch = input("  Выбор [1/2]: ").strip() or "1"
        if ch == "1":
            XHTTP_PATH = auto_path
            break
        elif ch == "2":
            while True:
                v = input("  Path (начинается с /): ").strip()
                if v.startswith("/"):
                    XHTTP_PATH = v
                    break
                warn("  Путь должен начинаться с /")
            break
        else:
            warn("Введите 1 или 2")
    success(f"xHTTP path: {XHTTP_PATH}")

    # Пресет производительности (smux / sockopt / TLS)
    global XHTTP_PERF_PRESET
    _box_top(f"Пресет производительности xHTTP")
    _box_row()
    _box_row()
    _box_item("1", f"auto    — умолчания Xray, без изменений {GREEN}(безопасный выбор){NC}")
    _box_item("2", f"speed   — максимальная скорость")
    _box_desc(f"{DIM}maxConcurrentStreams=32, tcpNoDelay, приоритет быстрых шифров{NC}")
    _box_item("3", f"balance — скорость + стабильность")
    _box_desc(f"{DIM}maxConcurrentStreams=16, tcpNoDelay{NC}")
    _box_row()
    _box_bottom()
    while True:
        ch = input(f"  {CYAN}Выбор [1]: {NC}").strip() or "1"
        if ch == "1":
            XHTTP_PERF_PRESET = "auto"
            break
        elif ch == "2":
            XHTTP_PERF_PRESET = "speed"
            break
        elif ch == "3":
            XHTTP_PERF_PRESET = "balance"
            break
        else:
            warn("Введите 1, 2 или 3")
    success(f"Пресет производительности: {XHTTP_PERF_PRESET}")

    # ── Дополнительные параметры оптимизации xHTTP (по официальной документации) ──
    global XHTTP_PADDING_BYTES, XHTTP_NO_SSE_HEADER
    global XHTTP_SC_STREAM_UP_SERVER_SECS
    global XHTTP_SC_MAX_EACH_POST_BYTES, XHTTP_SC_MAX_BUFFERED_POSTS
    global XHTTP_HOST, XHTTP_NO_GRPC_HEADER, XHTTP_SC_MIN_POSTS_INTERVAL_MS
    global XHTTP_XMUX_ENABLED, XHTTP_XMUX_MAX_CONCURRENCY, XHTTP_XMUX_MAX_CONNECTIONS
    global XHTTP_XMUX_C_MAX_REUSE_TIMES, XHTTP_XMUX_H_MAX_REQUEST_TIMES
    global XHTTP_XMUX_H_MAX_REUSABLE_SECS, XHTTP_XMUX_H_KEEP_ALIVE_PERIOD
    global XHTTP_TCP_NO_DELAY, XHTTP_ENABLE_SESSION_RESUMPTION

    _box_top(f"Расширенные параметры оптимизации xHTTP")
    _box_row()
    _box_row(f"  {DIM}(по официальной документации XHTTP: Beyond REALITY){NC}")
    _box_row()
    _box_row(f"  Каждый параметр влияет на маскировку трафика и стабильность соединения.")
    _box_row(f"  Если сомневаетесь — выбирайте рекомендуемые значения (вариант [1]).")
    _box_row()

    # --- xPaddingBytes ---
    # Документация: "xPaddingBytes": "100-1000" — рекомендуемое значение по умолчанию.
    # Диапазон: "0" (отключено) до "100-2000". Уменьшает fingerprint.
    _box_row(f"{BOLD}{BLUE}[A] xPaddingBytes{NC} — случайный мусорный padding в HTTP-заголовках")
    _box_row(f"  {DIM}Что делает:{NC} Добавляет случайное количество байт в заголовки каждого")
    _box_row(f"  HTTP-запроса (Referer) и ответа (X-Padding). Это устраняет fingerprint")
    _box_row(f"  по фиксированной длине заголовка — одну из главных примет прокси-трафика.")
    _box_row(f"  {DIM}Применяется:{NC} во всех режимах (streamup, streamone, packetup).")
    _box_row(f"  {DIM}Формат:{NC} \"MIN-MAX\" — случайное значение в диапазоне, либо фиксированное число.")
    _box_row()
    _box_item("1", f'{GREEN}"100-1000"{NC} — рекомендуется: padding 100–1000 байт')
    _box_item("2", '"100-300"  — минимальный: для медленных каналов')
    _box_item("3", '"500-2000" — максимальный: повышенная маскировка')
    _box_item("4", '"0"        — отключить (не рекомендуется)')
    _box_item("5", f"Ввести вручную (диапазон MIN-MAX или фиксированное число)")
    _box_bottom()
    while True:
        ch = input(f"  {CYAN}Выбор [1]: {NC}").strip() or "1"
        if ch == "1":
            XHTTP_PADDING_BYTES = "100-1000"
            break
        elif ch == "2":
            XHTTP_PADDING_BYTES = "100-300"
            break
        elif ch == "3":
            XHTTP_PADDING_BYTES = "500-2000"
            break
        elif ch == "4":
            XHTTP_PADDING_BYTES = "0"
            warn("xPaddingBytes=0: padding отключён — повышает заметность трафика")
            break
        elif ch == "5":
            _box_bottom()
            while True:
                v = input("  Введите значение (например 100-1000 или 500): ").strip()
                if re.match(r'^\d+(-\d+)?$', v):
                    XHTTP_PADDING_BYTES = v
                    break
                warn("  Формат: число или диапазон MIN-MAX (только цифры)")
            break
        else:
            warn("Введите 1–5")
    success(f"xPaddingBytes: {XHTTP_PADDING_BYTES}")

    # --- noSSEHeader ---
    # Документация: noSSEHeader — только сервер. По умолчанию false (SSE включён).
    # Если CDN блокирует SSE (Content-Type: text/event-stream) — включить (true).
    _box_row(f"{BOLD}{BLUE}[B] noSSEHeader{NC} — управление SSE-заголовком в ответах сервера")
    _box_row(f"  {DIM}Что делает:{NC} По умолчанию сервер добавляет заголовок")
    _box_row(f"  Content-Type: text/event-stream в ответы, маскируясь под Server-Sent Events.")
    _box_row(f"  Это улучшает совместимость с CDN и middlebox-ами, которые пропускают SSE.")
    _box_row(f"  Включите (true), если ваш CDN или обратный прокси блокирует SSE-соединения.")
    _box_row(f"  {DIM}Применяется:{NC} только сервер, режимы streamup и streamone.")
    _box_sep()
    _box_item("1", f"false — SSE-заголовок включён {GREEN}(рекомендуется){NC}")
    _box_desc(f"Маскировка под Server-Sent Events, лучшая совместимость с CDN")
    _box_item("2", f"true  — SSE-заголовок отключён")
    _box_desc(f"Использовать если CDN/прокси блокирует SSE-соединения")
    _box_bottom()
    while True:
        ch = input(f"  {CYAN}Выбор [1]: {NC}").strip() or "1"
        if ch == "1":
            XHTTP_NO_SSE_HEADER = False
            break
        elif ch == "2":
            XHTTP_NO_SSE_HEADER = True
            info("noSSEHeader=true: SSE-маскировка отключена")
            break
        else:
            warn("Введите 1 или 2")
    success(f"noSSEHeader: {XHTTP_NO_SSE_HEADER}")

    # --- scStreamUpServerSecs (только для stream-up / auto) ---
    # Документация: "scStreamUpServerSecs": "20-80" — рекомендуемое значение по умолчанию.
    # Сервер каждые N секунд отправляет xPaddingBytes байт для поддержания соединения.
    # Предотвращает разрыв CF/CDN при отсутствии данных > 100 с.
    # Значение -1 отключает механизм (поведение старых версий Xray).
    if XHTTP_MODE in ("streamup", "streamone") or XHTTP_MODE == "auto":
        _box_row(f"{BOLD}{BLUE}[C] scStreamUpServerSecs{NC} — интервал keepalive для stream-up (только сервер)")
        _box_row(f"  {DIM}Что делает:{NC} Cloudflare и многие CDN разрывают HTTP-соединение,")
        _box_row(f"  если в течение 100 секунд не было реальных данных. Этот параметр")
        _box_row(f"  заставляет сервер каждые N секунд отправлять клиенту несколько байт")
        _box_row(f"  padding-а (xPaddingBytes), чтобы CDN «видел» активное соединение.")
        _box_row(f"  Значение -1 отключает механизм (поведение Xray до введения этого параметра).")
        _box_row(f"  {DIM}Применяется:{NC} только сервер, режим streamup (и auto при TLS H2).")
        _box_row(f"  {DIM}Формат:{NC} \"MIN-MAX\" сек — случайный интервал, либо фиксированное число.")
        _box_sep()
        _box_item("1", f'{GREEN}"20-80"{NC}  — рекомендуется: интервал 20–80 с')
        _box_item("2", '"10-30" — агрессивное: короткий интервал')
        _box_item("3", '"40-80" — консервативное: реже пинговать')
        _box_item("4", f"-1     — отключить keepalive (соединение может разорваться через 100 с)")
        _box_item("5", f"Ввести вручную (диапазон MIN-MAX, число секунд, или -1)")
        _box_bottom()
        while True:
            ch = input(f"  {CYAN}Выбор [1]: {NC}").strip() or "1"
            if ch == "1":
                XHTTP_SC_STREAM_UP_SERVER_SECS = "20-80"
                break
            elif ch == "2":
                XHTTP_SC_STREAM_UP_SERVER_SECS = "10-30"
                break
            elif ch == "3":
                XHTTP_SC_STREAM_UP_SERVER_SECS = "40-80"
                break
            elif ch == "4":
                XHTTP_SC_STREAM_UP_SERVER_SECS = "-1"
                warn("scStreamUpServerSecs=-1: keepalive отключён")
                break
            elif ch == "5":
                _box_bottom()
                while True:
                    v = input("  Введите значение (например 20-80 или 30 или -1): ").strip()
                    if re.match(r'^-1$|^\d+(-\d+)?$', v):
                        XHTTP_SC_STREAM_UP_SERVER_SECS = v
                        break
                    warn("  Формат: число, диапазон MIN-MAX или -1")
                break
            else:
                warn("Введите 1–5")
        success(f"scStreamUpServerSecs: {XHTTP_SC_STREAM_UP_SERVER_SECS}")

    # --- scMaxEachPostBytes и scMaxBufferedPosts (только для packet-up / auto) ---
    # Документация:
    #   scMaxEachPostBytes: макс. объём данных в одном POST. По умолч. 1000000 (1 МБ).
    #     Должно быть меньше лимита CDN. Поддерживает диапазон "500000-1000000".
    #   scMaxBufferedPosts: макс. кол-во буферизованных POST на сервере (на сессию).
    #     По умолч. 30. При превышении сервер разрывает соединение.
    if XHTTP_MODE in ("packetup",) or XHTTP_MODE == "auto":
        _box_row(f"{BOLD}{BLUE}[D] scMaxEachPostBytes{NC} — максимальный объём данных в одном POST-запросе (packet-up)")
        _box_row(f"  {DIM}Что делает:{NC} В режиме packet-up каждый фрагмент исходящего трафика")
        _box_row(f"  отправляется отдельным HTTP POST-запросом. Этот параметр ограничивает")
        _box_row(f"  максимальный размер тела одного POST. Значение должно быть меньше лимита,")
        _box_row(f"  который допускает ваш CDN или промежуточный прокси (обычно 1–10 МБ).")
        _box_row(f"  Сервер также отклоняет POST, превышающий этот лимит.")
        _box_row(f"  Диапазон \"MIN-MAX\" снижает fingerprint: размер каждого POST случаен.")
        _box_row(f"  {DIM}Применяется:{NC} клиент и сервер, только режим packetup (и auto).")
        _box_sep()
        _box_item("1", f"{GREEN}1000000{NC}         — 1 МБ, стандарт {GREEN}(рекомендуется){NC}")
        _box_item("2", '"500000-1000000" — 0.5–1 МБ случайный диапазон')
        _box_item("3", f"524288           — 512 КБ, консервативно для строгих CDN")
        _box_item("4", f"Ввести вручную (байты: число или диапазон MIN-MAX)")
        _box_bottom()
        while True:
            ch = input(f"  {CYAN}Выбор [1]: {NC}").strip() or "1"
            if ch == "1":
                XHTTP_SC_MAX_EACH_POST_BYTES = "1000000"
                break
            elif ch == "2":
                XHTTP_SC_MAX_EACH_POST_BYTES = "500000-1000000"
                break
            elif ch == "3":
                XHTTP_SC_MAX_EACH_POST_BYTES = "524288"
                break
            elif ch == "4":
                _box_bottom()
                while True:
                    v = input("  Введите значение (байты, например 1000000 или 500000-1000000): ").strip()
                    if re.match(r'^\d+(-\d+)?$', v):
                        XHTTP_SC_MAX_EACH_POST_BYTES = v
                        break
                    warn("  Формат: число или диапазон MIN-MAX (только цифры)")
                break
            else:
                warn("Введите 1–4")
        success(f"scMaxEachPostBytes: {XHTTP_SC_MAX_EACH_POST_BYTES}")

        _box_row(f"{BOLD}{BLUE}[E] scMaxBufferedPosts{NC} — максимум буферизованных POST на сервере (packet-up)")
        _box_row(f"  {DIM}Что делает:{NC} В режиме packet-up POST-запросы от клиента могут приходить")
        _box_row(f"  не по порядку (сеть переупорядочивает пакеты). Сервер буферизует их")
        _box_row(f"  и собирает в правильном порядке по номеру seq. Этот параметр задаёт")
        _box_row(f"  максимум одновременно буферизованных POST на одну сессию. При превышении")
        _box_row(f"  лимита сервер разрывает соединение, защищаясь от атаки на память.")
        _box_row(f"  Счётчик независим для каждой сессии (sub-connection).")
        _box_row(f"  {DIM}Применяется:{NC} только сервер, только режим packetup (и auto).")
        _box_row(f"  {DIM}Рекомендуемый диапазон по документации:{NC} 10–100.")
        _box_sep()
        _box_item("1", f"30 — стандарт {GREEN}(рекомендуется){NC}")
        _box_item("2", f"50 — увеличенный буфер (быстрые каналы с большими потерями пакетов)")
        _box_item("3", f"15 — уменьшенный буфер (медленные каналы / экономия памяти сервера)")
        _box_item("4", f"Ввести вручную (целое число, 10–100)")
        _box_bottom()
        while True:
            ch = input(f"  {CYAN}Выбор [1]: {NC}").strip() or "1"
            if ch == "1":
                XHTTP_SC_MAX_BUFFERED_POSTS = 30
                break
            elif ch == "2":
                XHTTP_SC_MAX_BUFFERED_POSTS = 50
                break
            elif ch == "3":
                XHTTP_SC_MAX_BUFFERED_POSTS = 15
                break
            elif ch == "4":
                _box_bottom()
                while True:
                    v = input("  Введите значение (10–100): ").strip()
                    if v.isdigit() and 10 <= int(v) <= 100:
                        XHTTP_SC_MAX_BUFFERED_POSTS = int(v)
                        break
                    warn("  Введите целое число от 10 до 100")
                break
            else:
                warn("Введите 1–4")
        success(f"scMaxBufferedPosts: {XHTTP_SC_MAX_BUFFERED_POSTS}")

    # ──────────────────────────────────────────────────────────────────────────
    # --- scMinPostsIntervalMs (только для packet-up, только клиент) ---
    # Документация: мин. интервал в мс между POST-запросами клиента в одном
    # прокси-соединении. По умолч. 30 мс. Диапазон "10-50" снижает fingerprint.
    if XHTTP_MODE in ("packetup",) or XHTTP_MODE == "auto":
        _box_row(f"{BOLD}{BLUE}[F] scMinPostsIntervalMs{NC} — мин. интервал между POST-запросами клиента (packet-up)")
        _box_row(f"  {DIM}Что делает:{NC} Задаёт минимальный промежуток в миллисекундах между")
        _box_row(f"  последовательными POST-запросами, которые клиент отправляет серверу")
        _box_row(f"  в рамках одного прокси-соединения (режим packet-up). Слишком малый")
        _box_row(f"  интервал перегружает серверный буфер (scMaxBufferedPosts) и разрывает")
        _box_row(f"  соединение. Слишком большой — снижает скорость upload. Диапазон")
        _box_row(f"  \"MIN-MAX\" снижает fingerprint по фиксированному интервалу.")
        _box_row(f"  {DIM}Применяется:{NC} только клиент, только режим packetup (и auto).")
        _box_sep()
        _box_item("1", f"{GREEN}30{NC}      — стандарт: 30 мс {GREEN}(рекомендуется){NC}")
        _box_item("2", '"10-50" — случайный диапазон (меньше fingerprint)')
        _box_item("3", f"10      — агрессивный: быстрее, больше риск перегрузки буфера")
        _box_item("4", f"50      — консервативный: надёжнее при нестабильной сети")
        _box_item("5", f"Ввести вручную (мс или диапазон MIN-MAX)")
        _box_bottom()
        while True:
            ch = input(f"  {CYAN}Выбор [1]: {NC}").strip() or "1"
            if ch == "1":
                XHTTP_SC_MIN_POSTS_INTERVAL_MS = "30"
                break
            elif ch == "2":
                XHTTP_SC_MIN_POSTS_INTERVAL_MS = "10-50"
                break
            elif ch == "3":
                XHTTP_SC_MIN_POSTS_INTERVAL_MS = "10"
                break
            elif ch == "4":
                XHTTP_SC_MIN_POSTS_INTERVAL_MS = "50"
                break
            elif ch == "5":
                _box_bottom()
                while True:
                    v = input("  Введите значение (мс или диапазон MIN-MAX): ").strip()
                    if re.match(r'^\d+(-\d+)?$', v):
                        XHTTP_SC_MIN_POSTS_INTERVAL_MS = v
                        break
                    warn("  Формат: число или диапазон MIN-MAX (только цифры)")
                break
            else:
                warn("Введите 1–5")
        success(f"scMinPostsIntervalMs: {XHTTP_SC_MIN_POSTS_INTERVAL_MS}")

    # --- noGRPCHeader (stream-up / stream-one, только клиент) ---
    # Документация: по умолчанию false — каждый upload-запрос несёт заголовок
    # Content-Type: application/grpc для маскировки под gRPC. true — отключить.
    if XHTTP_MODE in ("streamup", "streamone") or XHTTP_MODE == "auto":
        _box_row(f"{BOLD}{BLUE}[G] noGRPCHeader{NC} — управление gRPC-маскировкой upload-запросов (клиент)")
        _box_row(f"  {DIM}Что делает:{NC} По умолчанию каждый upload-запрос клиента несёт заголовок")
        _box_row(f"  Content-Type: application/grpc — маскировка под gRPC-трафик. Это помогает")
        _box_row(f"  проходить через провайдеров, которые пропускают gRPC. Включите 'true',")
        _box_row(f"  если ваш CDN или провайдер блокирует gRPC или он создаёт проблемы.")
        _box_row(f"  {DIM}Применяется:{NC} только клиент, режимы streamup и streamone.")
        _box_sep()
        _box_item("1", f"false — gRPC-маскировка включена {GREEN}(рекомендуется){NC}")
        _box_desc(f"Upload-запросы выглядят как gRPC — лучше проходит у большинства провайдеров")
        _box_item("2", f"true  — gRPC-маскировка отключена")
        _box_desc(f"Использовать если CDN/провайдер блокирует gRPC")
        _box_bottom()
        while True:
            ch = input(f"  {CYAN}Выбор [1]: {NC}").strip() or "1"
            if ch == "1":
                XHTTP_NO_GRPC_HEADER = False
                break
            elif ch == "2":
                XHTTP_NO_GRPC_HEADER = True
                info("noGRPCHeader=true: gRPC-маскировка отключена")
                break
            else:
                warn("Введите 1 или 2")
        success(f"noGRPCHeader: {XHTTP_NO_GRPC_HEADER}")

    # --- host (для всех режимов, клиент) ---
    # Документация: заголовок Host HTTP-запросов. Нужен при CDN/domain fronting.
    _box_row(f"{BOLD}{BLUE}[H] host{NC} — Host-заголовок HTTP-запросов (для CDN / domain fronting)")
    _box_row(f"  {DIM}Что делает:{NC} Позволяет задать Host-заголовок HTTP-запросов отдельно")
    _box_row(f"  от SNI. Обязателен при CDN / domain fronting, когда IP-адрес соединения")
    _box_row(f"  и SNI различаются. Пустая строка — использовать значение из serverName.")
    _box_row(f"  Пример: SNI = example.com, Host = cdn-node.example.com")
    _box_row(f"  {DIM}Применяется:{NC} клиент, все режимы.")
    _box_sep()
    _box_item("1", f"Пусто — использовать SNI {GREEN}(рекомендуется для большинства){NC}")
    _box_item("2", f"Ввести вручную (домен или IP)")
    _box_bottom()
    while True:
        ch = input(f"  {CYAN}Выбор [1]: {NC}").strip() or "1"
        if ch == "1":
            XHTTP_HOST = ""
            break
        elif ch == "2":
            v = input("  Host (например cdn.example.com): ").strip()
            XHTTP_HOST = v
            break
        else:
            warn("Введите 1 или 2")
    if XHTTP_HOST:
        success(f"host: {XHTTP_HOST}")
    else:
        info("host: не задан (используется SNI)")

    # --- xmux — мультиплексирование (клиент, H2 / все режимы) ---
    # Документация: несколько proxy-потоков мультиплексируются внутри одного
    # HTTP/2 соединения. Существенно увеличивает пропускную способность при H2.
    _box_row(f"{BOLD}{BLUE}[I] xmux{NC} — мультиплексирование потоков внутри H2-соединения (клиент)")
    _box_row(f"  {DIM}Что делает:{NC} Позволяет нескольким proxy-потокам использовать одно")
    _box_row(f"  HTTP/2 TCP-соединение вместо создания отдельного на каждый поток.")
    _box_row(f"  Это существенно увеличивает пропускную способность при высоком RTT,")
    _box_row(f"  снижает overhead на TLS-хендшейки и количество соединений к серверу.")
    _box_row(f"  Рекомендуется при режимах streamup / streamone / auto и H2.")
    _box_row(f"  {DIM}Применяется:{NC} только клиент.")
    _box_sep()
    _box_item("1", f"Отключить xmux {GREEN}(умолчание, совместимо со всеми клиентами){NC}")
    _box_item("2", f"Включить с рекомендуемыми параметрами (16-32 потока)")
    _box_item("3", f"Включить с параметрами для высокой нагрузки (32-64 потока)")
    _box_item("4", f"Настроить вручную")
    _box_bottom()
    while True:
        ch = input(f"  {CYAN}Выбор [1]: {NC}").strip() or "1"
        if ch == "1":
            XHTTP_XMUX_ENABLED = False
            break
        elif ch == "2":
            XHTTP_XMUX_ENABLED = True
            XHTTP_XMUX_MAX_CONCURRENCY    = "16-32"
            XHTTP_XMUX_MAX_CONNECTIONS    = 0
            XHTTP_XMUX_C_MAX_REUSE_TIMES  = "0"
            XHTTP_XMUX_H_MAX_REQUEST_TIMES = "600-900"
            XHTTP_XMUX_H_MAX_REUSABLE_SECS = "1800-3000"
            XHTTP_XMUX_H_KEEP_ALIVE_PERIOD = 0
            break
        elif ch == "3":
            XHTTP_XMUX_ENABLED = True
            XHTTP_XMUX_MAX_CONCURRENCY    = "32-64"
            XHTTP_XMUX_MAX_CONNECTIONS    = 0
            XHTTP_XMUX_C_MAX_REUSE_TIMES  = "32-64"
            XHTTP_XMUX_H_MAX_REQUEST_TIMES = "300000-600000"
            XHTTP_XMUX_H_MAX_REUSABLE_SECS = "1800-3000"
            XHTTP_XMUX_H_KEEP_ALIVE_PERIOD = 30
            break
        elif ch == "4":
            XHTTP_XMUX_ENABLED = True
            _box_row(f"  {CYAN}maxConcurrency{NC} — макс. параллельных proxy-потоков на одно H2-соединение.")
            _box_row(f"    Диапазон «MIN-MAX» рандомизирует количество (снижает fingerprint).")
            v = input(f"    [{GREEN}16-32{NC}]: ").strip() or "16-32"
            XHTTP_XMUX_MAX_CONCURRENCY = v

            _box_row(f"  {CYAN}maxConnections{NC} — макс. одновременных H2-соединений к серверу. 0 = без лимита.")
            v = input(f"    [{GREEN}0{NC}]: ").strip() or "0"
            XHTTP_XMUX_MAX_CONNECTIONS = int(v) if v.isdigit() else 0

            _box_row(f"  {CYAN}cMaxReuseTimes{NC} — сколько раз переиспользовать одно соединение. 0 = без лимита.")
            v = input(f"    [{GREEN}0{NC}]: ").strip() or "0"
            XHTTP_XMUX_C_MAX_REUSE_TIMES = v

            _box_row(f"  {CYAN}hMaxRequestTimes{NC} — кол-во запросов через H2-соединение до его замены.")
            v = input(f"    [{GREEN}600-900{NC}]: ").strip() or "600-900"
            XHTTP_XMUX_H_MAX_REQUEST_TIMES = v

            _box_row(f"  {CYAN}hMaxReusableSecs{NC} — макс. время жизни H2-соединения (секунд).")
            v = input(f"    [{GREEN}1800-3000{NC}]: ").strip() or "1800-3000"
            XHTTP_XMUX_H_MAX_REUSABLE_SECS = v

            _box_row(f"  {CYAN}hKeepAlivePeriod{NC} — интервал keepalive между клиентом и сервером (сек). 0 = выкл.")
            v = input(f"    [{GREEN}0{NC}]: ").strip() or "0"
            XHTTP_XMUX_H_KEEP_ALIVE_PERIOD = int(v) if v.isdigit() else 0
            break
        else:
            warn("Введите 1–4")

    if XHTTP_XMUX_ENABLED:
        success(f"xmux: включён (maxConcurrency={XHTTP_XMUX_MAX_CONCURRENCY})")
    else:
        info("xmux: отключён")

    # --- tcpNoDelay (sockopt) ---
    # Отключает алгоритм Nagle для немедленной отправки TCP-сегментов.
    # Снижает задержку, особенно полезно на интерактивных соединениях.
    _box_row(f"{BOLD}{BLUE}[J] tcpNoDelay{NC} — отключить алгоритм Nagle в TCP (снизить задержку)")
    _box_row(f"  {DIM}Что делает:{NC} Алгоритм Nagle объединяет мелкие пакеты перед отправкой,")
    _box_row(f"  снижая overhead, но увеличивая задержку. tcpNoDelay=true отключает его —")
    _box_row(f"  каждый пакет отправляется немедленно. Полезно для интерактивного трафика,")
    _box_row(f"  снижает задержку ценой небольшого увеличения числа пакетов.")
    _box_row(f"  {DIM}Примечание:{NC} В пресетах speed/balance включён автоматически.")
    _box_sep()
    _box_item("1", f"false — алгоритм Nagle включён {GREEN}(по умолчанию){NC}")
    _box_item("2", f"true  — tcpNoDelay, снижает задержку")
    _box_bottom()
    while True:
        ch = input(f"  {CYAN}Выбор [1]: {NC}").strip() or "1"
        if ch == "1":
            XHTTP_TCP_NO_DELAY = False
            break
        elif ch == "2":
            XHTTP_TCP_NO_DELAY = True
            break
        else:
            warn("Введите 1 или 2")
    success(f"tcpNoDelay: {XHTTP_TCP_NO_DELAY}")

    # --- enableSessionResumption (tlsSettings) ---
    # Документация: при включении TLS-хендшейк при переподключении не требует
    # повторной передачи сертификата. Экономит время хендшейка.
    _box_row(f"{BOLD}{BLUE}[K] enableSessionResumption{NC} — возобновление TLS-сессий (ускорение переподключения)")
    _box_row(f"  {DIM}Что делает:{NC} При включении на обоих концах (сервер + клиент) TLS-хендшейк")
    _box_row(f"  при переподключении не требует повторной передачи сертификата. Это уменьшает")
    _box_row(f"  задержку при восстановлении соединения (например, после обрыва). Разница")
    _box_row(f"  невелика, но бесплатна. Требует поддержки на стороне клиента.")
    _box_row(f"  {DIM}Примечание:{NC} Это не TLS 0-RTT — RTT хендшейка не уменьшается.")
    _box_sep()
    _box_item("1", f"false — выключено {GREEN}(умолчание){NC}")
    _box_item("2", f"true  — включить возобновление TLS-сессий")
    _box_bottom()
    while True:
        ch = input(f"  {CYAN}Выбор [1]: {NC}").strip() or "1"
        if ch == "1":
            XHTTP_ENABLE_SESSION_RESUMPTION = False
            break
        elif ch == "2":
            XHTTP_ENABLE_SESSION_RESUMPTION = True
            break
        else:
            warn("Введите 1 или 2")
    _box_bottom()


def parse_vless_link(link: str) -> dict | None:
    """
    Парсит VLESS-ссылку и возвращает dict с параметрами ноды.
    Поддерживает REALITY и xHTTP TLS.
    Формат: vless://UUID@host:port?params#name
    Возвращает None при ошибке парсинга.
    """
    import urllib.parse
    link = link.strip()
    if not link.startswith("vless://"):
        return None
    try:
        # Разбиваем: vless://UUID@host:port?params#name
        rest = link[len("vless://"):]
        # Извлекаем fragment (#name) — необязателен
        if "#" in rest:
            rest, _frag = rest.rsplit("#", 1)
        # UUID — до первого @
        at_pos = rest.find("@")
        if at_pos < 0:
            return None
        uid = rest[:at_pos]
        rest = rest[at_pos + 1:]
        # host:port?params
        if "?" in rest:
            hostport, qs = rest.split("?", 1)
        else:
            hostport, qs = rest, ""
        # IPv6 адрес в []
        if hostport.startswith("["):
            br = hostport.find("]")
            host = hostport[1:br]
            port_part = hostport[br + 1:]
            port = int(port_part.lstrip(":")) if port_part.lstrip(":") else 443
        else:
            parts = hostport.rsplit(":", 1)
            host = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 443

        params = dict(urllib.parse.parse_qsl(qs))

        security   = params.get("security", "")
        net_type   = params.get("type", "tcp")
        pbk        = params.get("pbk", "")
        sid        = params.get("sid", "")
        sni        = params.get("sni", host)
        fp         = params.get("fp", "chrome")
        flow       = params.get("flow", "")
        path       = params.get("path", "/")
        xhttp_mode = params.get("mode", "streamup")

        # Валидация UUID
        if not re.match(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', uid
        ):
            return None

        # Определяем тип протокола
        if security == "reality":
            proto = "reality"
        elif security in ("tls", "") and net_type in ("xhttp", "http"):
            proto = "xhttp"
        elif security == "tls":
            proto = "xhttp"  # TLS без уточнения — считаем xHTTP
        else:
            proto = "reality"  # fallback

        return {
            "host":       host,
            "port":       port,
            "uuid":       uid,
            "pubkey":     pbk,
            "shortid":    sid,
            "sni":        sni,
            "fp":         fp,
            "flow":       flow,
            "path":       path,
            "xhttp_mode": xhttp_mode,
            "security":   security,
            "net_type":   net_type,
            "proto":      proto,
        }
    except Exception:
        return None


def prompt_chain_params() -> None:
    """Ввод параметров зарубежного (exit) VPS для Режима B.
    Устарела — используется только для совместимости. Новый код вызывает prompt_chain_params_multi()."""
    global CHAIN_EXIT_HOST, CHAIN_EXIT_PORT, CHAIN_EXIT_UUID
    global CHAIN_EXIT_PUBKEY, CHAIN_EXIT_SHORTID, CHAIN_EXIT_SNI, CHAIN_EXIT_FP

    _box_top(f"Параметры зарубежного VPS (Exit Node)")
    _box_row()
    _box_row(f"  {YELLOW}На зарубежном VPS должен быть установлен этот же скрипт в Режиме A.{NC}")
    _box_row(f"  После его установки вы получите все необходимые параметры.")
    _box_row()

    # IP / домен
    _box_row(f"{BLUE}[E1] IP или домен зарубежного VPS:{NC}")
    _box_bottom()
    while True:
        try:
            v = input("   IP или домен: ").strip()
        except KeyboardInterrupt:
            print()
            raise
        if v:
            CHAIN_EXIT_HOST = v
            success(f"   Exit host: {CHAIN_EXIT_HOST}")
            break
        warn("   Не может быть пустым")

    # Порт
    _box_row(f"{BLUE}[E2] Порт зарубежного VPS [{CHAIN_EXIT_PORT}]:{NC}")
    _box_bottom()
    while True:
        try:
            v = input(f"   Порт [443]: ").strip() or "443"
        except KeyboardInterrupt:
            print()
            raise
        if v.isdigit() and 1 <= int(v) <= 65535:
            CHAIN_EXIT_PORT = int(v)
            success(f"   Порт: {CHAIN_EXIT_PORT}")
            break
        warn("   Некорректный порт (1-65535)")

    # UUID
    _box_row(f"{BLUE}[E3] UUID пользователя на зарубежном VPS:{NC}")
    _box_bottom()
    while True:
        try:
            v = input("   UUID: ").strip()
        except KeyboardInterrupt:
            print()
            raise
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', v):
            CHAIN_EXIT_UUID = v
            success(f"   UUID: {CHAIN_EXIT_UUID}")
            break
        warn("   Неверный формат UUID")

    # Public Key
    _box_row(f"{BLUE}[E4] Public Key (pbk) зарубежного VPS:{NC}")
    _box_bottom()
    while True:
        try:
            v = input("   Public Key: ").strip()
        except KeyboardInterrupt:
            print()
            raise
        if len(v) >= 40:
            CHAIN_EXIT_PUBKEY = v
            success(f"   PublicKey: {v[:20]}...")
            break
        warn("   Слишком короткий (мин 40 символов)")

    # Short ID
    _box_row(f"{BLUE}[E5] ShortID зарубежного VPS:{NC}")
    _box_bottom()
    while True:
        try:
            v = input("   ShortID (hex): ").strip()
        except KeyboardInterrupt:
            print()
            raise
        if re.match(r'^[0-9a-f]{2,16}$', v) and len(v) % 2 == 0:
            CHAIN_EXIT_SHORTID = v
            success(f"   ShortID: {CHAIN_EXIT_SHORTID}")
            break
        warn("   Неверный ShortID")

    # SNI
    _box_row(f"{BLUE}[E6] SNI (домен) зарубежного VPS:{NC}")
    _box_bottom()
    while True:
        try:
            v = input("   SNI/домен: ").strip()
        except KeyboardInterrupt:
            print()
            raise
        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z]{2,}$', v):
            CHAIN_EXIT_SNI = v
            success(f"   SNI: {CHAIN_EXIT_SNI}")
            break
        warn("   Некорректный домен")

    # Fingerprint
    global CHAIN_EXIT_FP
    _box_row(f"{BLUE}[E7] Fingerprint браузера:{NC}")
    _box_bottom()
    CHAIN_EXIT_FP = _fm_prompt_fingerprint(label="Exit Node", current=CHAIN_EXIT_FP or "chrome")

    _box_row(f"{BOLD}Параметры Exit Node:{NC}")
    _box_row(f"  Host:    {CHAIN_EXIT_HOST}:{CHAIN_EXIT_PORT}")
    _box_row(f"  UUID:    {CHAIN_EXIT_UUID}")
    _box_row(f"  PubKey:  {CHAIN_EXIT_PUBKEY[:20]}...")
    _box_row(f"  ShortID: {CHAIN_EXIT_SHORTID}")
    _box_row(f"  SNI:     {CHAIN_EXIT_SNI}")
    _box_row(f"  FP:      {CHAIN_EXIT_FP}")
    _box_bottom()
    try:
        ans = input(f"{YELLOW}Параметры верны? [y/N]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        print()
        raise
    if ans != 'y':
        info("Повторите ввод параметров Exit Node.")
        prompt_chain_params()


def _prompt_balancer_strategy() -> None:
    """
    Спрашивает стратегию балансировки между exit-нодами.
    Вызывается из prompt_chain_params_multi() после ввода нод.
    При одной ноде — балансировщик не нужен, пропускаем.
    """
    global CHAIN_BALANCER_STRATEGY

    if len(CHAIN_NODES) < 2:
        # При одной ноде balancer не задействован — оставляем roundRobin как дефолт,
        # конфиг будет генерироваться без секции balancers.
        CHAIN_BALANCER_STRATEGY = "roundRobin"
        return

    _box_top(f"Стратегия балансировки между нодами")
    _box_row()
    _box_item("1", f"🔄 Round Robin {GREEN}(рекомендуется){NC}")
    _box_desc(f"Подключения распределяются по кругу: нода 1 → нода 2 → нода 1 → ...")
    _box_desc(f"Равномерная нагрузка. Именно этот режим работает у вас сейчас.")
    _box_desc(f"IP меняется при каждом новом подключении — это нормально.")
    _box_row()
    _box_item("2", f"⚡ Least Ping")
    _box_desc(f"Xray замеряет RTT до каждой ноды и выбирает самую быструю.")
    _box_desc(f"Трафик идёт через ту ноды, у которой меньше задержка в данный момент.")
    _box_desc(f"Требует включения observatory (мониторинг нод) — добавляет ~1-2% overhead.")
    _box_desc(f"IP меняется реже — только при смене «лидера» по пингу.")
    _box_row()
    _box_item("3", f"📊 Least Load")
    _box_desc(f"Xray выбирает ноду с наименьшей текущей нагрузкой (активные соединения).")
    _box_desc(f"Учитывает RTT и количество соединений одновременно — лучший баланс.")
    _box_desc(f"Требует observatory. Оптимально при неравномерном трафике.")
    _box_row()
    _box_item("4", f"🎲 Random")
    _box_desc(f"При каждом подключении нода выбирается случайно.")
    _box_desc(f"Поведение похоже на Round Robin, но без строгой очерёдности.")
    _box_desc(f"IP меняется непредсказуемо — хорошо для анонимности.")
    _box_row()
    _box_item("5", f"⚖️  Smart Balancer {GREEN}(авто){NC}")
    _box_desc(f"Автоматически выбирает лучшую ноду по задержке, нагрузке и пропускной способности.")
    _box_desc(f"Cron запускается каждые {PROBE_INTERVAL_MIN} мин и переключает ноду при необходимости.")
    _box_desc(f"Не требует ручной настройки — включается сразу после установки.")
    _box_row()

    strategy_map = {
        "1": "roundRobin",
        "2": "leastPing",
        "3": "leastLoad",
        "4": "random",
        "5": "smartBalancer",
    }
    _box_bottom()
    while True:
        try:
            choice = input(f"  {CYAN}Выбор [1]: {NC}").strip() or "1"
        except KeyboardInterrupt:
            print()
            raise
        if choice in strategy_map:
            CHAIN_BALANCER_STRATEGY = strategy_map[choice]
            break
        warn("  Введите 1, 2, 3, 4 или 5")

    labels = {"roundRobin": "Round Robin", "leastPing": "Least Ping", "leastLoad": "Least Load", "random": "Random", "smartBalancer": "Smart Balancer"}
    success(f"Стратегия балансировки: {labels[CHAIN_BALANCER_STRATEGY]}")


def prompt_chain_params_multi() -> None:
    """
    Ввод параметров exit-нод для Режима B во время установки.
    Позволяет добавить от 1 до MAX_CHAIN_NODES нод.
    После ввода заполняет CHAIN_NODES и обновляет legacy CHAIN_EXIT_* переменные.
    """
    global CHAIN_NODES
    global CHAIN_EXIT_HOST, CHAIN_EXIT_PORT, CHAIN_EXIT_UUID
    global CHAIN_EXIT_PUBKEY, CHAIN_EXIT_SHORTID, CHAIN_EXIT_SNI, CHAIN_EXIT_FP
    global CHAIN_BALANCER_STRATEGY

    CHAIN_NODES = []

    _box_top(f"Настройка Exit Node(ов) для Режима B")
    _box_row()
    _box_wrap_msg(f"  {YELLOW}", 2, f"Вы можете добавить от 1 до {MAX_CHAIN_NODES} exit-нод.{NC}")
    _box_wrap_msg(f"  {YELLOW}", 2, f"При нескольких нодах трафик распределяется между ними по выбранной стратегии (Round Robin / Least Ping / Random).{NC}")
    _box_wrap_msg(f"  {YELLOW}", 2, f"На каждом зарубежном VPS должен быть установлен этот скрипт в Режиме A.{NC}")
    _box_row()

    while len(CHAIN_NODES) < MAX_CHAIN_NODES:
        idx = len(CHAIN_NODES) + 1

        _box_row()
        _box_bottom()
        _box_top(f"Exit Node #{idx}")
        _box_row()

        nd = _prompt_one_node(idx)
        if nd is None:
            # Пользователь ввёл 0 — прерываем ввод текущей ноды
            if not CHAIN_NODES:
                _box_warn("Нужна хотя бы одна exit-нода. Попробуйте снова.")
                continue
            else:
                _box_info("Ввод нод завершён.")
                break

        CHAIN_NODES.append(nd)
        _box_ok(f"Exit Node #{idx} добавлена: {nd['host']}:{nd['port']}")

        if len(CHAIN_NODES) >= MAX_CHAIN_NODES:
            _box_info(f"Достигнут максимум ({MAX_CHAIN_NODES} нод).")
            break

        _box_row()
        _box_row(f"  Добавлено нод: {len(CHAIN_NODES)}/{MAX_CHAIN_NODES}")
        try:
            ans = input(f"  {CYAN}Добавить ещё одну exit-ноду? [y/N]:{NC} ").strip().lower()
        except KeyboardInterrupt:
            print()
            raise
        if ans != 'y':
            break

    # Итоговый список
    _box_row()
    _box_row(f"{BOLD}Итого exit-нод: {len(CHAIN_NODES)}{NC}")
    for i, nd in enumerate(CHAIN_NODES):
        _box_row(f"  {CYAN}#{i+1}{NC}  {nd['host']}:{nd['port']}  SNI={nd['sni']}")
    _box_row()

    # --- Стратегия балансировки (только если нод больше одной) ---
    _prompt_balancer_strategy()

    # Если выбран Smart Balancer (п.5) — сразу устанавливаем cron
    if CHAIN_BALANCER_STRATEGY == "smartBalancer":
        try:
            _sb_install_cron(PROBE_INTERVAL_MIN)
            success(f"Smart Balancer: cron активирован (каждые {PROBE_INTERVAL_MIN} мин)")
        except Exception as _sb_err:
            warn(f"Smart Balancer: не удалось установить cron: {_sb_err}")
        # Для xray используем roundRobin как базовую стратегию —
        # Smart Balancer управляет переключением нод через state-файл
        CHAIN_BALANCER_STRATEGY = "roundRobin"

    _box_row()
    _box_bottom()
    # Синхронизируем legacy-переменные с первой нодой
    if CHAIN_NODES:
        n = CHAIN_NODES[0]
        CHAIN_EXIT_HOST    = n["host"]
        CHAIN_EXIT_PORT    = n["port"]
        CHAIN_EXIT_UUID    = n["uuid"]
        CHAIN_EXIT_PUBKEY  = n["pubkey"]
        CHAIN_EXIT_SHORTID = n["shortid"]
        CHAIN_EXIT_SNI     = n["sni"]
        CHAIN_EXIT_FP      = n["fp"]


# =============================================================================
#  ВЫБОР РЕЖИМА EXIT-НОДЫ ДЛЯ РЕЖИМА B: VLESS или AWG
# =============================================================================
# Глобальные параметры SSH-аутентификации для удалённой настройки AWG.
# Заполняются в prompt_awg_exit_mode(), потребляются awg_setup_remote_server().
AWG_SSH_AUTH_METHOD: str = "key"    # "key" | "password"
AWG_SSH_PASSWORD:    str = ""       # хранится только до конца сессии настройки


# (prompt_awg_exit_mode — вынесена в vless_installer.modules.install_prompts;
#  импорт — в верхней секции этого файла.)



# =============================================================================
#  ГЕНЕРАЦИЯ КОНФИГА XRAY ДЛЯ РЕЖИМА B — российский (entry) VPS
# =============================================================================
def _assert_reality_dest_sane() -> None:
    """
    BUGFIX: защита от невалидного realitySettings.serverNames/dest.

    Если AWG_EXIT_ENABLED=True, а PARAM_REALITY_DEST пуст (рассинхрон между
    транспортным флагом и параметром camouflage-домена — например, после
    ручного переключения режима без полного сброса состояния), генераторы
    конфига ниже соберут:
        "dest": ":443", "serverNames": [""]
    Это не ловится `xray run -test` как синтаксическая ошибка, но ломает
    REALITY-хендшейк для абсолютно любого клиента (домен/IPv4/IPv6 — не важно,
    хост один и тот же битый inbound). Лучше упасть здесь с понятной ошибкой,
    чем молча выкатить нерабочий config.json.
    """
    if AWG_EXIT_ENABLED and not PARAM_REALITY_DEST:
        die(
            "AWG_EXIT_ENABLED=True, но PARAM_REALITY_DEST пуст — "
            "конфиг получился бы с serverNames=[\"\"] и dest=':443' "
            "(REALITY не будет работать ни для одного клиента). "
            "Запустите prompt_awg_exit_mode() заново или проверьте "
            "reality_dest в state.json."
        )


def generate_xray_config_chain_entry() -> None:
    """
    Режим B, Entry node (российский VPS):
    • Принимает VLESS+REALITY от клиента на порту 443
    • Исходящий — VLESS+REALITY → зарубежный VPS (exit node)
    """
    global DNSCRYPT_LISTEN_PORT
    _assert_reality_dest_sane()
    info("Режим B: создание конфига Entry Node (российский VPS)...")
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    # ПАТЧ: гарантируем создание группы/пользователя xray ДО chown.
    # Если установка Xray прервалась раньше — chown root:xray упадёт с "invalid group".
    _run(["groupadd", "-f", "xray"], check=False, quiet=True)
    _run(["useradd", "-r", "-g", "xray", "-s", "/sbin/nologin", "xray"],
         check=False, quiet=True)
    # ПАТЧ: права на директорию — root должен мочь писать config.json
    try:
        os.chmod(str(CONFIG_DIR), 0o755)
        _run(["chown", "root:xray", str(CONFIG_DIR)], check=False, quiet=True)
    except Exception:
        pass

    # DNS серверы — аналогично generate_xray_config()
    r_active = _run(["systemctl", "is-active", "dnscrypt-proxy"],
                    capture=True, check=False)
    dnscrypt_running = (DNSCRYPT_INSTALLED or r_active.stdout.strip() == "active")

    if dnscrypt_running:
        dns_servers = [
            {"address": DNSCRYPT_LISTEN_ADDR, "port": DNSCRYPT_LISTEN_PORT,
             "network": "udp", "skipFallback": False},
            {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": True},
            {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": True},
        ]
    else:
        dns_servers = [
            {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": False},
            {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": False},
        ]

    query_strategy = "UseIPv6v4" if IS_IPV6_AVAILABLE else "UseIPv4"

    if PROTOCOL_MODE == "xhttp":
        cert_path_str = f"/etc/letsencrypt/live/{PARAM_DOMAIN}/fullchain.pem"
        key_path_str  = f"/etc/letsencrypt/live/{PARAM_DOMAIN}/privkey.pem"
        _xhttp_s, _sockopt_s = _build_xhttp_settings(XHTTP_MODE, XHTTP_PATH)
        inbound_block = {
            "tag":      "inbound-xhttp",
            "port":     SERVER_PORT,
            "listen":   "::",
            "protocol": "vless",
            "settings": {
                "clients": [{
                    "id":    PARAM_UUID,
                    "email": f"user@{PARAM_DOMAIN}",
                }],
                "decryption": "none",
            },
            "sniffing": {
                "enabled":      True,
                "destOverride": ["http", "tls"],
                "metadataOnly": False,
                "routeOnly":    False,
            },
            "streamSettings": {
                "network":       "xhttp",
                "security":      "tls",
                "sockopt":       _sockopt_s,
                "tlsSettings":   _build_tls_settings_xhttp(
                                     PARAM_DOMAIN, cert_path_str, key_path_str),
                "xhttpSettings": _xhttp_s,
            },
        }
    else:
        inbound_block = {
            "tag":      "inbound-vless",
            "port":     SERVER_PORT,
            "listen":   "::",
            "protocol": "vless",
            "settings": {
                "clients": [{
                    "id":    PARAM_UUID,
                    "email": f"user@{PARAM_DOMAIN}",
                    **( {"flow": XTLS_FLOW} if XTLS_FLOW else {} ),
                }],
                "decryption": "none",
            },
            "sniffing": {
                "enabled":      True,
                "destOverride": ["http", "tls"],
                # AWG использует маршрутизацию ядра — sniffing доменов не нужен (metadataOnly=True).
                # Базовый VLESS/REALITY: metadataOnly=False обязателен — xray должен читать SNI/Host
                # чтобы freedom мог резолвить домены и применять UseIPv6v4 domainStrategy.
                "metadataOnly": True if AWG_EXIT_ENABLED else False,
                "routeOnly":    False,
            },
            "streamSettings": {
                "network": "tcp",
                "sockopt": _build_sockopt(),
                "security": "reality",
                "realitySettings": {
                    "show":        False,
                    "dest":        (PARAM_REALITY_DEST + ":443") if AWG_EXIT_ENABLED else PARAM_SOCKET_PATH,
                    # xver=1 (Proxy Protocol) только в классическом режиме VLESS-каскада:
                    # Nginx слушает на socket с proxy_protocol и шлёт PP-заголовок.
                    # xver=0 при AWG: Xray слушает напрямую на TCP, PP-заголовка нет.
                    "xver":        0 if AWG_EXIT_ENABLED else 1,
                    "spiderX":     PARAM_SPIDERX,
                    "serverNames": [PARAM_REALITY_DEST if AWG_EXIT_ENABLED else PARAM_DOMAIN],
                    "privateKey":  PARAM_PRIVATE_KEY,
                    "publicKey":   PARAM_PUBLIC_KEY,
                    "shortIds":    [PARAM_SHORTID],
                },
            },
        }

    config: dict[str, Any] = {
        "log": _xray_log_block(),
        "dns": {
            "servers": dns_servers,
            "hosts": {
                "dns.google":         "8.8.8.8",
                "dns.cloudflare.com": "1.1.1.1",
                "localhost":          "127.0.0.1",
            },
            "disableCache":           False,
            "queryStrategy":          query_strategy,
            "disableFallback":        False,
            "disableFallbackIfMatch": True,
        },
        "inbounds": [inbound_block],
        "outbounds": [
            # Главный исходящий: VLESS → AWG туннель → exit-VPS
            # domainStrategy здесь не применяется к клиентскому трафику —
            # он применяется только к самому соединению RU→exit (по IP, не домену).
            # IPv6 для клиентов обеспечивается Xray на exit-VPS (UseIPv6v4 там).
            {
                "tag":      "chain-exit",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": CHAIN_EXIT_HOST,
                        "port":    CHAIN_EXIT_PORT,
                        "users":   [{
                            "id":         CHAIN_EXIT_UUID,
                            "encryption": "none",
                            **( {"flow": XTLS_FLOW} if XTLS_FLOW else {} ),
                        }],
                    }],
                },
                "streamSettings": {
                    "network":  "tcp",
                    "security": "reality",
                    "sockopt":  {**_build_sockopt(), **({"mark": AWG_FWMARK} if AWG_EXIT_ENABLED else {})},  # ПАТЧ: AWG mark
                    "realitySettings": {
                        "show":        False,
                        "fingerprint": CHAIN_EXIT_FP,
                        "serverName":  CHAIN_EXIT_SNI,
                        "publicKey":   CHAIN_EXIT_PUBKEY,
                        "shortId":     CHAIN_EXIT_SHORTID,
                        "spiderX":     "/",
                    },
                },
            },
            {"protocol": "blackhole", "tag": "BLOCK"},
            # ИСПРАВЛЕНИЕ: direct outbound нужен ВСЕГДА — не только при AWG.
            # Xray резолвит домены через встроенный DNS (IPIfNonMatch), запросы идут
            # к 127.0.0.1:5300 (DNSCrypt-proxy). Без direct outbound они попадают
            # в chain-exit (VLESS TCP) и получают "read response: EOF".
            # При AWG добавляем fwmark для корректной маршрутизации.
            {
                "protocol": "freedom",
                "tag":      "direct",
                "settings": {"domainStrategy": "UseIPv6v4"},
                **({"streamSettings": {"sockopt": {"mark": AWG_FWMARK}}} if AWG_EXIT_ENABLED else {}),
            },
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                # ИСПРАВЛЕНИЕ: loopback → direct ВСЕГДА (не только при AWG).
                # DNS-запросы Xray к 127.0.0.1:5300 (DNSCrypt) должны идти через
                # direct (loopback), иначе попадают в chain-exit → EOF.
                {"type": "field", "ip": ["127.0.0.1/8", "::1/128"], "outboundTag": "direct"},
                # Блокируем торренты
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "BLOCK"},
                # Всё остальное — через exit node
                {"type": "field", "network": "tcp,udp", "outboundTag": "chain-exit"},
            ],
        },
    }

    # === MERGE FROM install_split.py: split tunnel block (generate_xray_config_chain_entry) ===
    if SPLIT_TUNNEL_ENABLED and not AWG_EXIT_ENABLED:
        if not any(ob.get("tag") == "direct" for ob in config.get("outbounds", [])):
            config["outbounds"].insert(0, {
                "protocol": "freedom",
                "tag":      "direct",
                "settings": {"domainStrategy": "UseIP"},
            })
        st_rules = build_split_tunnel_routing_rules(proxy_tag="chain-exit", direct_tag="direct")
        if st_rules:
            config["routing"]["rules"] = st_rules + config["routing"]["rules"]
            config["routing"]["geoDataBasePath"] = str(CONFIG_DIR)
            info(f"Split tunneling: добавлено {len(st_rules)} правил (Режим B, одиночная нода)")
    # === END MERGE ===

    cfg_file = CONFIG_DIR / "config.json"
    _apply_stats_to_config(config)
    cfg_file.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    _set_config_owner(cfg_file)

    # Симлинк
    alt_dir = Path("/usr/local/etc/xray")
    if alt_dir.exists():
        alt_cfg = alt_dir / "config.json"
        alt_cfg.unlink(missing_ok=True)
        try:
            alt_cfg.symlink_to(cfg_file)
        except Exception:
            pass

    # Валидация
    r = _run([str(XRAY_BIN), "run", "-test", "-config", str(cfg_file)],
             capture=True, check=False)
    if r.returncode == 0:
        success("Конфиг Entry Node (Режим B) создан и валиден")
    else:
        warn("Конфигурация создана с предупреждением")
        log_to_file("WARN", r.stderr[-1000:] if r.stderr else "")


# =============================================================================
#  ГЕНЕРАЦИЯ КОНФИГА XRAY ДЛЯ РЕЖИМА B — зарубежный (exit) VPS
# =============================================================================
def _build_exit_xhttp_settings(nd: dict) -> dict:
    """
    Строит xhttpSettings (inbound, сервер) для exit-ноды с правильной
    структурой extra согласно документации XHTTP: Beyond REALITY.
    Используется в конфиге exit-VPS (серверная сторона).
    """
    mode = nd.get("xhttp_mode", "streamup")
    xhttp: dict = {}
    if XHTTP_MODE_SUPPORTED:
        xhttp["mode"] = mode
    xhttp["path"] = nd.get("path", "/")
    if XHTTP_HOST:
        xhttp["host"] = XHTTP_HOST

    extra: dict = {
        "xPaddingBytes": XHTTP_PADDING_BYTES,
        "noGRPCHeader":  XHTTP_NO_GRPC_HEADER,
        "noSSEHeader":   XHTTP_NO_SSE_HEADER,
    }
    if mode in ("streamup", "streamone", "auto"):
        extra["scStreamUpServerSecs"] = XHTTP_SC_STREAM_UP_SERVER_SECS
    if mode in ("packetup", "auto"):
        extra["scMaxEachPostBytes"]    = XHTTP_SC_MAX_EACH_POST_BYTES
        extra["scMinPostsIntervalMs"]  = XHTTP_SC_MIN_POSTS_INTERVAL_MS
        extra["scMaxBufferedPosts"]    = XHTTP_SC_MAX_BUFFERED_POSTS
    if XHTTP_XMUX_ENABLED:
        extra["xmux"] = {
            "maxConcurrency":   XHTTP_XMUX_MAX_CONCURRENCY,
            "maxConnections":   XHTTP_XMUX_MAX_CONNECTIONS,
            "cMaxReuseTimes":   XHTTP_XMUX_C_MAX_REUSE_TIMES,
            "hMaxRequestTimes": XHTTP_XMUX_H_MAX_REQUEST_TIMES,
            "hMaxReusableSecs": XHTTP_XMUX_H_MAX_REUSABLE_SECS,
            "hKeepAlivePeriod": XHTTP_XMUX_H_KEEP_ALIVE_PERIOD,
        }
    xhttp["extra"] = extra
    return xhttp


def _build_exit_xhttp_outbound_settings(nd: dict) -> dict:
    """
    Строит xhttpSettings (outbound, клиент) для исходящего соединения
    entry-ноды к exit-ноде. Используется в конфиге entry-VPS (клиентская сторона).
    """
    mode = nd.get("xhttp_mode", "streamup")
    xhttp: dict = {}
    if XHTTP_MODE_SUPPORTED:
        xhttp["mode"] = mode
    xhttp["path"] = nd.get("path", "/")
    if XHTTP_HOST:
        xhttp["host"] = XHTTP_HOST

    extra: dict = {
        "xPaddingBytes": XHTTP_PADDING_BYTES,
        "noGRPCHeader":  XHTTP_NO_GRPC_HEADER,
    }
    if mode in ("packetup", "auto"):
        extra["scMaxEachPostBytes"]   = XHTTP_SC_MAX_EACH_POST_BYTES
        extra["scMinPostsIntervalMs"] = XHTTP_SC_MIN_POSTS_INTERVAL_MS
    if XHTTP_XMUX_ENABLED:
        extra["xmux"] = {
            "maxConcurrency":   XHTTP_XMUX_MAX_CONCURRENCY,
            "maxConnections":   XHTTP_XMUX_MAX_CONNECTIONS,
            "cMaxReuseTimes":   XHTTP_XMUX_C_MAX_REUSE_TIMES,
            "hMaxRequestTimes": XHTTP_XMUX_H_MAX_REQUEST_TIMES,
            "hMaxReusableSecs": XHTTP_XMUX_H_MAX_REUSABLE_SECS,
            "hKeepAlivePeriod": XHTTP_XMUX_H_KEEP_ALIVE_PERIOD,
        }
    xhttp["extra"] = extra
    return xhttp


def _make_exit_node_config(nd: dict) -> dict:
    """Строит словарь конфига Xray для одной exit-ноды."""
    nd_proto = nd.get("proto", "reality")

    if nd_proto == "xhttp":
        inbound = {
            "tag":      "inbound-xhttp",
            "port":     nd["port"],
            "listen":   "::",
            "protocol": "vless",
            "settings": {
                "clients": [{
                    "id":    nd["uuid"],
                    "email": "entry@chain",
                }],
                "decryption": "none",
            },
            "sniffing": {
                "enabled":      True,
                "destOverride": ["http", "tls"],
                "metadataOnly": False,
                "routeOnly":    False,
            },
            "streamSettings": {
                "network":  "xhttp",
                "security": "tls",
                "sockopt":  {
                    "tcpFastOpen":        True,
                    "tcpKeepAliveInterval": 15,
                    "tcpKeepAliveIdle":   60,
                    "tcpUserTimeout":     10000,
                    "tcpCongestion":      "bbr",
                    **({"tcpNoDelay": True} if XHTTP_TCP_NO_DELAY else {}),
                },
                "tlsSettings": {
                    "serverName":   nd.get("sni", ""),
                    "certificates": [{
                        "certificateFile": f"/etc/letsencrypt/live/{nd.get('sni', 'example.com')}/fullchain.pem",
                        "keyFile":         f"/etc/letsencrypt/live/{nd.get('sni', 'example.com')}/privkey.pem",
                    }],
                    "alpn":       ["h2", "http/1.1"],
                    "minVersion": "1.2",
                    **({"enableSessionResumption": True} if XHTTP_ENABLE_SESSION_RESUMPTION else {}),
                },
                "xhttpSettings": _build_exit_xhttp_settings(nd),
            },
        }
        comment = (
            "Этот конфиг предназначен для ЗАРУБЕЖНОГО VPS (exit node, xHTTP TLS). "
            "Скопируйте его в /etc/xray/config.json на зарубежном сервере."
        )
    else:
        inbound = {
            "tag":      "inbound-chain-entry",
            "port":     nd["port"],
            "listen":   "::",
            "protocol": "vless",
            "settings": {
                "clients": [{
                    "id":    nd["uuid"],
                    "email": "entry@chain",
                    **( {"flow": XTLS_FLOW} if XTLS_FLOW else {} ),
                }],
                "decryption": "none",
            },
            "sniffing": {
                "enabled":      True,
                "destOverride": ["http", "tls"],
                "metadataOnly": False,
                "routeOnly":    False,
            },
            "streamSettings": {
                "network":  "tcp",
                "sockopt":  _build_sockopt(),
                "security": "reality",
                "realitySettings": {
                    "show":        False,
                    "dest":        f"{nd['sni']}:443",
                    "xver":        0,
                    "spiderX":     "/",
                    "serverNames": [nd["sni"]],
                    # ВАЖНО: privateKey нужно вставить вручную после: xray x25519
                    "privateKey":  "<ВСТАВЬТЕ_PRIVATE_KEY_EXIT_NODE>",
                    "publicKey":   nd["pubkey"],
                    "shortIds":    [nd["shortid"]],
                },
            },
        }
        comment = (
            "Этот конфиг предназначен для ЗАРУБЕЖНОГО VPS (exit node, REALITY). "
            "Скопируйте его в /etc/xray/config.json на зарубежном сервере."
        )

    return {
        "_comment": comment,
        "log": {
            "loglevel": "info",
            "access": "/var/log/xray/access.log",
            "error": "/var/log/xray/error.log"
        },
        "dns": {
            "servers": [
                # IPv6-capable DNS
                {"address": "2606:4700:4700::1111", "port": 53, "network": "udp", "skipFallback": True},
                {"address": "1.1.1.1",              "port": 53, "network": "udp", "skipFallback": False},
                {"address": "2001:4860:4860::8888", "port": 53, "network": "udp", "skipFallback": True},
                {"address": "8.8.8.8",              "port": 53, "network": "udp", "skipFallback": False},
            ],
            # UseIPv6v4: резолвим AAAA сначала — ключевое для видимости IPv6 клиентом
            "queryStrategy": "UseIPv6v4",
        },
        "inbounds": [inbound],
        "outbounds": [
            {
                "protocol": "freedom",
                "tag":      "direct",
                # UseIPv6v4: Xray предпочитает IPv6 при исходящем соединении
                "settings": {"domainStrategy": "UseIPv6v4"},
            },
            {"protocol": "blackhole", "tag": "BLOCK"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "protocol": ["bittorrent"],        "outboundTag": "BLOCK"},
                {"type": "field", "ip": ["127.0.0.1/32", "::1/128"], "outboundTag": "direct"},
                {"type": "field", "network": "tcp,udp",              "outboundTag": "direct"},
            ],
        },
    }


def generate_xray_config_chain_exit() -> None:
    """
    Генерирует конфиг(и) для зарубежных (exit) VPS Режима B.
    Файлы НЕ применяются к текущему серверу — только сохраняются для
    ручного копирования на зарубежные VPS.
    При нескольких нодах создаётся отдельный файл для каждой:
      /root/xray_config_exit_node_1.json, _2.json, ...
    При одной ноде — /root/xray_config_exit_node.json (совместимость).
    """
    nodes = CHAIN_NODES if CHAIN_NODES else []
    if not nodes and CHAIN_EXIT_HOST:
        nodes = [{
            "host":    CHAIN_EXIT_HOST,
            "port":    CHAIN_EXIT_PORT,
            "uuid":    CHAIN_EXIT_UUID,
            "pubkey":  CHAIN_EXIT_PUBKEY,
            "shortid": CHAIN_EXIT_SHORTID,
            "sni":     CHAIN_EXIT_SNI,
            "fp":      CHAIN_EXIT_FP,
        }]

    if not nodes:
        warn("Нет exit-нод для генерации конфигов.")
        return

    info(f"Режим B: генерация конфигов Exit Node(ов) ({len(nodes)} шт.)...")

    for i, nd in enumerate(nodes):
        cfg = _make_exit_node_config(nd)
        if len(nodes) == 1:
            path = Path("/root/xray_config_exit_node.json")
        else:
            path = Path(f"/root/xray_config_exit_node_{i+1}.json")
        path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
        path.chmod(0o600)
        nd_proto = nd.get("proto", "reality")
        success(f"  Конфиг Exit Node #{i+1} ({nd['host']}, {nd_proto.upper()}): {path}")

    info("Скопируйте каждый файл на соответствующий зарубежный VPS: /etc/xray/config.json")
    # Подсказки зависят от протокола нод
    has_reality_nodes = any(nd.get("proto", "reality") == "reality" for nd in nodes)
    has_xhttp_nodes   = any(nd.get("proto", "reality") == "xhttp"   for nd in nodes)
    if has_reality_nodes:
        info("REALITY exit nodes: сгенерируйте ключи: xray x25519")
        info("И прописать приватный ключ вместо <ВСТАВЬТЕ_PRIVATE_KEY_EXIT_NODE>")
    if has_xhttp_nodes:
        info("xHTTP exit nodes: получите сертификат Let's Encrypt на exit VPS")
        info("certbot certonly --standalone -d <ваш_домен> --non-interactive --agree-tos -m admin@<домен>")


# =============================================================================
#  ДОП. КЛИЕНТ ДЛЯ УЖЕ РАЗВЁРНУТОЙ EXIT-НОДЫ (для резервной Entry-ноды)
# =============================================================================
def do_generate_chain_exit_additional_client() -> None:
    """
    generate_xray_config_chain_exit() перезаписывает inbounds[0].settings.clients
    ОДНИМ клиентом — это ломает доступ уже работающей entry-ноды, если
    сгенерировать конфиг заново под вторую (резервную) entry. Эта функция
    вместо полной перегенерации выдаёт JSON-сниппет с ОДНИМ новым клиентом
    (новый UUID) — его нужно вручную добавить ЕЩЁ ОДНИМ элементом в уже
    существующий массив clients на exit-VPS, не трогая остальные.

    Если exit-нода — это обычная установка данного инсталлятора в Режиме A
    (вариант "вставить VLESS-ссылку" при добавлении ноды, а не шаблон из
    generate_xray_config_chain_exit()) — специальный сниппет не нужен:
    проще добавить обычного пользователя через "Менеджер пользователей"
    (меню 2 → 1) прямо на exit-VPS и взять его vless-ссылку.
    """
    global CHAIN_NODES
    _load_chain_nodes_from_state()

    print()
    _box_top("Доп. клиент для существующей Exit-ноды (резервная Entry)")
    _box_row(f"  {DIM}Для entry-ноды, форвардящей трафик в УЖЕ развёрнутый exit —")
    _box_row(f"  {DIM}не переписывает существующего клиента, только добавляет нового.{NC}")
    _box_row()

    nd: dict | None = None
    if CHAIN_NODES:
        for i, cnd in enumerate(CHAIN_NODES):
            _box_row(f"  [{i+1}] {cnd['host']}:{cnd['port']}  SNI={cnd['sni']}")
        _box_row(f"  [0] Ввести параметры exit-ноды вручную")
        _box_bottom()
        try:
            v = input("  Номер exit-ноды (0 = вручную): ").strip()
        except (KeyboardInterrupt, EOFError):
            print(); return
        if v.isdigit() and 1 <= int(v) <= len(CHAIN_NODES):
            nd = CHAIN_NODES[int(v) - 1]
    else:
        _box_row(f"  {DIM}Список нод этой entry пуст — введите параметры exit-ноды вручную.{NC}")
        _box_bottom()

    if nd is None:
        try:
            host = input("  Host exit-ноды: ").strip()
            if not host:
                warn("Host обязателен."); return
            port_raw = input("  Порт [443]: ").strip()
            port = int(port_raw) if port_raw else 443
            proto = (input("  Протокол [reality/xhttp, по умолчанию reality]: ").strip().lower() or "reality")
            sni = input("  SNI: ").strip()
        except (KeyboardInterrupt, EOFError):
            print(); return
        nd = {"host": host, "port": port, "sni": sni, "proto": proto}

    try:
        label = input("  Метка нового клиента [entry-backup]: ").strip() or "entry-backup"
    except (KeyboardInterrupt, EOFError):
        print(); return

    new_uuid = str(uuid.uuid4())
    client_obj: dict = {"id": new_uuid, "email": f"{label}@chain"}
    if nd.get("proto", "reality") != "xhttp" and XTLS_FLOW:
        client_obj["flow"] = XTLS_FLOW

    snippet_path = Path(f"/root/exit_add_client_{new_uuid[:8]}.json")
    snippet_path.write_text(json.dumps(client_obj, indent=2, ensure_ascii=False))
    snippet_path.chmod(0o600)

    print()
    success(f"Сниппет клиента сохранён: {snippet_path}")
    _box_top("Что сделать дальше")
    _box_row(f"  1. Скопируйте файл на exit-VPS ({nd['host']}):")
    _box_row(f"     {CYAN}scp {snippet_path} root@{nd['host']}:/root/{NC}")
    _box_row(f"  2. На exit-VPS откройте /etc/xray/config.json,")
    _box_row(f"     найдите inbounds[0].settings.clients (это список) и")
    _box_row(f"     добавьте туда содержимое {snippet_path.name}")
    _box_row(f"     ЕЩЁ ОДНИМ элементом через запятую — существующего")
    _box_row(f"     клиента (основную entry) НЕ трогайте и не удаляйте.")
    _box_row(f"  3. Перезапустите Xray на exit-VPS:")
    _box_row(f"     {CYAN}systemctl restart xray{NC}")
    _box_row()
    _box_row(f"  {BOLD}Параметры для резервной entry-ноды{NC} {DIM}(ввести при настройке")
    _box_row(f"  {DIM}её cascade / добавлении этой exit-ноды в её CHAIN_NODES):{NC}")
    _box_row(f"     Host:      {nd['host']}")
    _box_row(f"     Port:      {nd['port']}")
    _box_row(f"     UUID:      {new_uuid}")
    if nd.get("pubkey"):
        _box_row(f"     PublicKey: {nd['pubkey']}")
    if nd.get("shortid"):
        _box_row(f"     ShortID:   {nd['shortid']}")
    _box_row(f"     SNI:       {nd.get('sni', '')}")
    _box_row(f"     FP:        {nd.get('fp', 'chrome')}")
    if not nd.get("pubkey") or not nd.get("shortid"):
        _box_row()
        _box_row(f"  {YELLOW}PublicKey/ShortID exit-ноды не были указаны — возьмите их{NC}")
        _box_row(f"  {YELLOW}из исходной VLESS-ссылки этой exit-ноды.{NC}")
    _box_bottom()
    input(f"{BLUE}Нажмите Enter...{NC}")


# =============================================================================
#  МУЛЬТИ-КАСКАД: ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (до 10 exit-нод)
# =============================================================================

def _nodes_from_state(state: dict) -> list[dict]:
    """
    Загружает список нод из state.json.
    Поддерживает как новый формат (chain_nodes: [...]),
    так и старый (chain_exit_host/port/uuid/...) — для обратной совместимости.
    """
    if "chain_nodes" in state and isinstance(state["chain_nodes"], list):
        return state["chain_nodes"]
    # Старый формат — одна нода
    host = state.get("chain_exit_host", "")
    if host:
        return [{
            "host":    host,
            "port":    state.get("chain_exit_port",    443),
            "uuid":    state.get("chain_exit_uuid",    ""),
            "pubkey":  state.get("chain_exit_pubkey",  ""),
            "shortid": state.get("chain_exit_shortid", ""),
            "sni":     state.get("chain_exit_sni",     ""),
            "fp":      state.get("chain_exit_fp",      "chrome"),
        }]
    return []


def _load_chain_nodes_from_state() -> None:
    """Загружает CHAIN_NODES (и legacy CHAIN_EXIT_*) из STATE_FILE."""
    global CHAIN_NODES, CHAIN_BALANCER_STRATEGY
    global CHAIN_EXIT_HOST, CHAIN_EXIT_PORT, CHAIN_EXIT_UUID
    global CHAIN_EXIT_PUBKEY, CHAIN_EXIT_SHORTID, CHAIN_EXIT_SNI, CHAIN_EXIT_FP
    if not STATE_FILE.exists():
        return
    try:
        state = json.loads(STATE_FILE.read_text())
        CHAIN_NODES = _nodes_from_state(state)
        CHAIN_BALANCER_STRATEGY = state.get("chain_balancer_strategy", "roundRobin")
        if CHAIN_NODES:
            n = CHAIN_NODES[0]
            CHAIN_EXIT_HOST    = n.get("host",    CHAIN_EXIT_HOST)
            CHAIN_EXIT_PORT    = n.get("port",    CHAIN_EXIT_PORT)
            CHAIN_EXIT_UUID    = n.get("uuid",    CHAIN_EXIT_UUID)
            CHAIN_EXIT_PUBKEY  = n.get("pubkey",  CHAIN_EXIT_PUBKEY)
            CHAIN_EXIT_SHORTID = n.get("shortid", CHAIN_EXIT_SHORTID)
            CHAIN_EXIT_SNI     = n.get("sni",     CHAIN_EXIT_SNI)
            CHAIN_EXIT_FP      = n.get("fp",      CHAIN_EXIT_FP)
    except Exception:
        pass


def _save_chain_nodes_to_state() -> None:
    """Записывает CHAIN_NODES обратно в STATE_FILE, не затрагивая остальные поля."""
    if not STATE_FILE.exists():
        warn("state.json не найден — сначала выполните установку (пункт 1).")
        return
    try:
        state = json.loads(STATE_FILE.read_text())
    except Exception:
        state = {}
    state["chain_nodes"] = CHAIN_NODES
    state["chain_balancer_strategy"] = CHAIN_BALANCER_STRATEGY
    state["chain_pinned_node_index"] = CHAIN_PINNED_NODE_INDEX
    # Обновляем и legacy-поля первой ноды для совместимости
    if CHAIN_NODES:
        n = CHAIN_NODES[0]
        state["chain_exit_host"]    = n["host"]
        state["chain_exit_port"]    = n["port"]
        state["chain_exit_uuid"]    = n["uuid"]
        state["chain_exit_pubkey"]  = n["pubkey"]
        state["chain_exit_shortid"] = n["shortid"]
        state["chain_exit_sni"]     = n["sni"]
        state["chain_exit_fp"]      = n["fp"]
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))


def _prompt_one_node(index: int) -> dict | None:
    """
    Запрашивает параметры одной exit-ноды.
    Поддерживает два режима ввода:
      [L] — вставить VLESS-ссылку (парсинг автоматически)
      [M] — ввод параметров вручную по полям
    Возвращает dict или None, если пользователь отменил.
    """
    _box_top(f"Параметры Exit Node #{index}")
    _box_row(f"  {YELLOW}На зарубежном VPS должен быть установлен этот же скрипт в Режиме A.{NC}")
    _box_row(f"  Введите {CYAN}0{NC} для отмены.")
    _box_row()
    _box_item("L", f"Вставить VLESS-ссылку (сгенерированную на exit VPS) {GREEN}(рекомендуется){NC}")
    _box_item("M", f"Ввести параметры вручную по полям")
    _box_row()
    _box_back()
    _box_bottom()
    while True:
        try:
            mode = input("  Выбор [L/M]: ").strip().lower()
        except KeyboardInterrupt:
            print()
            raise
        if mode == "0":
            return None
        if mode in ("l", ""):
            return _prompt_one_node_from_link(index)
        elif mode == "m":
            return _prompt_one_node_manual(index)
        warn("  Введите L или M")


def _prompt_one_node_from_link(index: int) -> dict | None:
    """Ввод параметров exit-ноды через VLESS-ссылку."""
    _box_top(f"Ввод Exit Node #{index} через VLESS-ссылку")
    _box_row()
    _box_wrap_msg(f"  {DIM}Пример: {NC}", 10, f"vless://UUID@host:443?type=tcp&security=reality&pbk=...&sid=...&sni=domain.com&flow=xtls-rprx-vision")
    _box_wrap_msg(f"  {DIM}Или:    {NC}", 10, f"vless://UUID@host:443?type=xhttp&security=tls&sni=domain.com&path=/abc")
    _box_row()

    _box_bottom()
    while True:
        try:
            raw = input("  VLESS ссылка (0=отмена): ").strip()
        except KeyboardInterrupt:
            print()
            raise
        if raw == "0":
            return None
        if not raw:
            warn("  Ссылка не может быть пустой")
            continue
        parsed = parse_vless_link(raw)
        if parsed is None:
            warn("  Не удалось разобрать ссылку. Проверьте формат.")
            warn("  Ссылка должна начинаться с vless://")
            try:
                ans = input("  Попробовать ещё раз? [Y/n]: ").strip().lower()
            except KeyboardInterrupt:
                print()
                raise
            if ans == "n":
                return None
            continue

        # Показываем разобранные параметры
        _box_row(f"{BOLD}Разобрана Exit Node #{index}:{NC}")
        _box_row(f"  Host:     {parsed['host']}:{parsed['port']}")
        _box_row(f"  UUID:     {parsed['uuid']}")
        if parsed['proto'] == 'reality':
            pubkey_info = f"PubKey: {parsed['pubkey'][:20]}..." if parsed['pubkey'] else "PubKey: не найден!"
            _box_row(f"  Proto:    {parsed['proto'].upper()} ({pubkey_info})")
            _box_row(f"  ShortID:  {parsed['shortid']}")
        else:
            _box_row(f"  Proto:    {parsed['proto'].upper()} (xhttp mode: {parsed['xhttp_mode']}, path: {parsed['path']})")
        _box_row(f"  SNI:      {parsed['sni']}")
        _box_row(f"  FP:       {parsed['fp']}")

        # Проверка обязательных полей
        warnings = []
        if parsed['proto'] == 'reality':
            if not parsed['pubkey']:
                warnings.append("PublicKey отсутствует в ссылке!")
            if not parsed['shortid']:
                warnings.append("ShortID отсутствует в ссылке!")
        if not parsed['sni']:
            warnings.append("SNI (домен) не указан в ссылке!")
        if warnings:
            for w in warnings:
                warn(f"  ⚠ {w}")
            _box_sep()
            _box_item("F", f"Дозаполнить недостающие поля вручную")
            _box_item("R", f"Ввести ссылку заново")
            _box_item_exit("0", f"Отмена")
            _box_bottom()
            while True:
                try:
                    fix = input("  Выбор [F/R/0]: ").strip().lower()
                except KeyboardInterrupt:
                    print()
                    raise
                if fix == "0":
                    return None
                elif fix == "r":
                    break  # повтор внешнего цикла
                elif fix in ("f", ""):
                    return _fix_node_fields(index, parsed)
                warn("Введите F, R или 0")
            continue  # повтор ввода ссылки

        _box_bottom()
        try:
            ans = input(f"{YELLOW}Параметры верны? [Y/n]: {NC}").strip().lower()
        except KeyboardInterrupt:
            print()
            raise
        if ans == "n":
            try:
                ans2 = input("  Ввести ссылку заново? [Y/n]: ").strip().lower()
            except KeyboardInterrupt:
                print()
                raise
            if ans2 != "n":
                continue
            return _prompt_one_node_manual(index)

        # Строим финальный словарь ноды
        node = {
            "host":       parsed["host"],
            "port":       parsed["port"],
            "uuid":       parsed["uuid"],
            "pubkey":     parsed["pubkey"],
            "shortid":    parsed["shortid"],
            "sni":        parsed["sni"],
            "fp":         parsed["fp"],
            "flow":       parsed.get("flow", "xtls-rprx-vision") or "xtls-rprx-vision",
            "proto":      parsed["proto"],
            "path":       parsed.get("path", "/"),
            "xhttp_mode": parsed.get("xhttp_mode", "streamup"),
        }
        return node


def _fix_node_fields(index: int, parsed: dict) -> dict | None:
    """Дозаполнение отсутствующих полей exit-ноды."""
    _box_top(f"Дозаполнение полей Exit Node #{index}")
    _box_row()

    if parsed['proto'] == 'reality':
        if not parsed['pubkey']:
            _box_bottom()
            while True:
                try:
                    v = input("  Public Key (pbk): ").strip()
                except KeyboardInterrupt:
                    print()
                    raise
                if v == "0":
                    return None
                if len(v) >= 40:
                    parsed['pubkey'] = v
                    break
                warn("  Слишком короткий (мин 40 символов)")

        if not parsed['shortid']:
            _box_bottom()
            while True:
                try:
                    v = input("  ShortID (hex, чётная длина 2-16): ").strip()
                except KeyboardInterrupt:
                    print()
                    raise
                if v == "0":
                    return None
                if re.match(r'^[0-9a-f]{2,16}$', v) and len(v) % 2 == 0:
                    parsed['shortid'] = v
                    break
                warn("  Неверный ShortID")

    if not parsed['sni']:
        _box_bottom()
        while True:
            try:
                v = input("  SNI/домен: ").strip()
            except KeyboardInterrupt:
                print()
                raise
            if v == "0":
                return None
            if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z]{2,}$', v):
                parsed['sni'] = v
                break
            warn("  Некорректный домен")

    _box_bottom()
    return {
        "host":       parsed["host"],
        "port":       parsed["port"],
        "uuid":       parsed["uuid"],
        "pubkey":     parsed["pubkey"],
        "shortid":    parsed["shortid"],
        "sni":        parsed["sni"],
        "fp":         parsed.get("fp", "chrome"),
        "flow":       parsed.get("flow", "xtls-rprx-vision") or "xtls-rprx-vision",
        "proto":      parsed["proto"],
        "path":       parsed.get("path", "/"),
        "xhttp_mode": parsed.get("xhttp_mode", "streamup"),
    }


def _prompt_one_node_manual(index: int) -> dict | None:
    """Ввод параметров exit-ноды вручную по полям."""
    _box_top(f"Ручной ввод Exit Node #{index}")
    _box_row(f"  Введите {CYAN}0{NC} в любом поле для отмены.")
    _box_row()

    # Host
    _box_row(f"{BLUE}[E1] IP или домен зарубежного VPS:{NC}")
    _box_bottom()
    while True:
        try:
            v = input("   IP или домен (0=отмена): ").strip()
        except KeyboardInterrupt:
            print()
            raise
        if v == "0":
            return None
        if v:
            host = v
            break
        warn("   Не может быть пустым")

    # Port
    _box_row(f"{BLUE}[E2] Порт зарубежного VPS [443]:{NC}")
    _box_bottom()
    while True:
        try:
            v = input("   Порт [443]: ").strip() or "443"
        except KeyboardInterrupt:
            print()
            raise
        if v == "0":
            return None
        if v.isdigit() and 1 <= int(v) <= 65535:
            port = int(v)
            break
        warn("   Некорректный порт (1–65535)")

    # UUID
    _box_row(f"{BLUE}[E3] UUID пользователя на зарубежном VPS:{NC}")
    _box_bottom()
    while True:
        try:
            v = input("   UUID: ").strip()
        except KeyboardInterrupt:
            print()
            raise
        if v == "0":
            return None
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', v):
            node_uuid = v
            break
        warn("   Неверный формат UUID")

    # Тип протокола exit-ноды
    _box_row(f"{BLUE}[E4] Протокол exit-ноды:{NC}")
    _box_row(f"   {CYAN}[1]{NC} VLESS + TCP + REALITY (xtls-rprx-vision) {GREEN}(рек.){NC}")
    _box_row(f"   {CYAN}[2]{NC} VLESS + xHTTP + TLS")
    _box_bottom()
    while True:
        try:
            v = input("   Выбор [1]: ").strip() or "1"
        except KeyboardInterrupt:
            print()
            raise
        if v == "0":
            return None
        if v == "1":
            exit_proto = "reality"
            break
        elif v == "2":
            exit_proto = "xhttp"
            break
        warn("   Введите 1 или 2")

    pubkey = ""
    shortid = ""
    xhttp_mode_val = "streamup"
    path_val = "/"
    flow_val = XTLS_FLOW

    if exit_proto == "reality":
        # Public Key
        _box_row(f"{BLUE}[E5] Public Key (pbk) зарубежного VPS:{NC}")
        _box_bottom()
        while True:
            try:
                v = input("   Public Key: ").strip()
            except KeyboardInterrupt:
                print()
                raise
            if v == "0":
                return None
            if len(v) >= 40:
                pubkey = v
                break
            warn("   Слишком короткий (мин 40 символов)")

        # Short ID
        _box_row(f"{BLUE}[E6] ShortID зарубежного VPS:{NC}")
        _box_bottom()
        while True:
            try:
                v = input("   ShortID (hex): ").strip()
            except KeyboardInterrupt:
                print()
                raise
            if v == "0":
                return None
            if re.match(r'^[0-9a-f]{2,16}$', v) and len(v) % 2 == 0:
                shortid = v
                break
            warn("   Неверный ShortID (чётное число hex-символов, 2–16)")
    else:
        # xHTTP параметры
        _box_row(f"{BLUE}[E5] xHTTP режим:{NC}")
        _box_row(f"   {CYAN}[1]{NC} streamup {GREEN}(рек.){NC}  {CYAN}[2]{NC} streamone  {CYAN}[3]{NC} packetup {YELLOW}(⚠ проверьте версию Xray){NC}")
        _box_bottom()
        while True:
            try:
                v = input("   Выбор [1]: ").strip() or "1"
            except KeyboardInterrupt:
                print()
                raise
            if v == "0":
                return None
            if v == "1":
                xhttp_mode_val = "streamup"
                break
            elif v == "2":
                xhttp_mode_val = "streamone"
                break
            elif v == "3":
                xhttp_mode_val = "packetup"
                warn("packetup выбран — убедитесь что ваша версия Xray-core его поддерживает")
                break
            warn("   Введите 1, 2 или 3")

        auto_path = "/" + gen_hex(4)
        _box_row(f"{BLUE}[E6] xHTTP path [{auto_path}]:{NC}")
        try:
            v = input(f"   Path [{auto_path}]: ").strip()
        except KeyboardInterrupt:
            print()
            raise
        if v == "0":
            return None
        path_val = v if v.startswith("/") else auto_path
        flow_val = ""  # xHTTP не использует flow

    # SNI
    _box_row(f"{BLUE}[E7] SNI / домен зарубежного VPS:{NC}")
    _box_bottom()
    while True:
        try:
            v = input("   SNI/домен: ").strip()
        except KeyboardInterrupt:
            print()
            raise
        if v == "0":
            return None
        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z]{2,}$', v):
            sni = v
            break
        warn("   Некорректный домен")

    # Fingerprint
    _box_row(f"{BLUE}[E8] Fingerprint браузера:{NC}")
    _box_bottom()
    fp = _fm_prompt_fingerprint(label=f"Exit Node #{index}", current="chrome")

    node = {
        "host":       host,
        "port":       port,
        "uuid":       node_uuid,
        "pubkey":     pubkey,
        "shortid":    shortid,
        "sni":        sni,
        "fp":         fp,
        "flow":       flow_val,
        "proto":      exit_proto,
        "path":       path_val,
        "xhttp_mode": xhttp_mode_val,
    }

    _box_row(f"{BOLD}Параметры Exit Node #{index}:{NC}")
    _box_row(f"  Host:     {host}:{port}")
    _box_row(f"  UUID:     {node_uuid}")
    _box_row(f"  Proto:    {exit_proto.upper()}")
    if exit_proto == "reality":
        _box_row(f"  PubKey:   {pubkey[:20]}...")
        _box_row(f"  ShortID:  {shortid}")
    else:
        _box_row(f"  xHTTP:    {xhttp_mode_val}, path={path_val}")
    _box_row(f"  SNI:      {sni}")
    _box_row(f"  FP:       {fp}")
    _box_bottom()
    try:
        ans = input(f"{YELLOW}Параметры верны? [y/N]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        print()
        raise
    if ans != 'y':
        info("Повторный ввод параметров ноды.")
        return _prompt_one_node_manual(index)

    return node


def _h2_reapply_transport_if_active() -> None:
    """
    BUGFIX: generate_xray_config_chain_entry_multi() / generate_xray_config() /
    generate_xray_config_xhttp() полностью перезаписывают config.json, включая
    outbounds и routing. Если на момент вызова транспорт Hysteria2 уже был
    активирован пользователем через меню 7 (h2_transport_apply), такая
    перезапись "осиротевала" H2-outbound и откатывала catch-all routing-правило
    обратно на "direct"/"chain-exit" — трафик начинал молча течь с Entry-ноды
    напрямую, минуя Exit, до следующего ручного переключения транспорта.
    Эта функция не меняет поведение, если H2 не был активен — это no-op.
    """
    try:
        from vless_installer.modules.hysteria2_common import _load_h2_state
        h2 = _load_h2_state()
        if h2.get("active_transport") != "hysteria2":
            return
        nodes = [n for n in h2.get("exit_nodes", []) if n.get("status") == "active"]
        if not nodes:
            return
        from vless_installer.modules.hysteria2_transport import h2_transport_apply
        node = nodes[0]
        ok = h2_transport_apply(
            exit_ip=node["ip"],
            exit_port=node.get("ports", [443])[0],
            auth_password=node.get("auth", ""),
        )
        if ok:
            info("Hysteria2-транспорт переприменён после регенерации config.json")
    except Exception as e:
        warn(f"Не удалось переприменить Hysteria2-транспорт после регенерации: {e}")


def generate_xray_config_chain_entry_multi() -> None:
    """
    Аналог generate_xray_config_chain_entry(), но поддерживает несколько
    exit-нод через механизм balancer Xray-core с выбранной стратегией
    (roundRobin / leastPing / random).
    Если нода одна — конфиг идентичен оригинальному (без balancer).
    """
    global DNSCRYPT_LISTEN_PORT
    _assert_reality_dest_sane()
    nodes = CHAIN_NODES if CHAIN_NODES else []
    if not nodes:
        # Fallback на legacy-переменные
        if CHAIN_EXIT_HOST:
            nodes = [{
                "host":    CHAIN_EXIT_HOST,
                "port":    CHAIN_EXIT_PORT,
                "uuid":    CHAIN_EXIT_UUID,
                "pubkey":  CHAIN_EXIT_PUBKEY,
                "shortid": CHAIN_EXIT_SHORTID,
                "sni":     CHAIN_EXIT_SNI,
                "fp":      CHAIN_EXIT_FP,
            }]
        elif AWG_EXIT_ENABLED:
            # AWG-режим: exit-нод нет (трафик идёт через AWG-туннель).
            # Для xHTTP вызываем generate_xray_config_xhttp() — она не содержит
            # realitySettings и не требует REALITY-ключей (используется TLS Let's Encrypt).
            # Для REALITY-режимов вызываем generate_xray_config() с AWG fwmark.
            if PROTOCOL_MODE == "xhttp":
                info("Mode B + AWG + xHTTP: нет VLESS exit-нод, используем xHTTP-конфиг...")
                generate_xray_config_xhttp()
            else:
                info("Mode B + AWG: нет VLESS exit-нод, используем AWG-конфиг...")
                generate_xray_config()
            return
        elif H2_EXIT_ENABLED:
            # H2-режим: как и в AWG-ветке выше, exit-нод для VLESS-цепочки нет —
            # Hysteria2-туннель на exit-VPS настраивается отдельно через меню 7
            # и патчит outbound (тег "proxy") уже ПОСЛЕ того, как этот стандартный
            # конфиг записан. Раньше для H2 эта ветка отсутствовала, и установка
            # проваливалась в "Нет exit-нод — конфиг Entry Node не может быть
            # создан", оставляя ноду вообще без config.json.
            if PROTOCOL_MODE == "xhttp":
                info("Mode B + H2 + xHTTP: нет VLESS exit-нод, используем xHTTP-конфиг...")
                generate_xray_config_xhttp()
            else:
                info("Mode B + H2: нет VLESS exit-нод, используем стандартный конфиг "
                     "(outbound будет переключён на H2 через меню 7)...")
                generate_xray_config()
            _h2_reapply_transport_if_active()
            return
        else:
            warn("Нет exit-нод — конфиг Entry Node не может быть создан.")
            return

    n_nodes = len(nodes)
    info(f"Режим B: создание конфига Entry Node ({n_nodes} exit-нод)...")
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    # ПАТЧ: гарантируем создание группы/пользователя xray ДО chown.
    _run(["groupadd", "-f", "xray"], check=False, quiet=True)
    _run(["useradd", "-r", "-g", "xray", "-s", "/sbin/nologin", "xray"],
         check=False, quiet=True)
    # ПАТЧ: права на директорию
    try:
        os.chmod(str(CONFIG_DIR), 0o755)
        _run(["chown", "root:xray", str(CONFIG_DIR)], check=False, quiet=True)
    except Exception:
        pass

    r_active = _run(["systemctl", "is-active", "dnscrypt-proxy"],
                    capture=True, check=False)
    dnscrypt_running = (DNSCRYPT_INSTALLED or r_active.stdout.strip() == "active")

    if dnscrypt_running:
        dns_servers = [
            {"address": DNSCRYPT_LISTEN_ADDR, "port": DNSCRYPT_LISTEN_PORT,
             "network": "udp", "skipFallback": False},
            {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": True},
            {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": True},
        ]
    else:
        dns_servers = [
            {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": False},
            {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": False},
        ]

    query_strategy = "UseIPv6v4" if IS_IPV6_AVAILABLE else "UseIPv4"

    # Строим список outbound-ов для exit-нод
    outbounds_exit = []
    outbound_tags  = []
    for i, nd in enumerate(nodes):
        tag = f"chain-exit-{i+1}"
        outbound_tags.append(tag)
        nd_proto = nd.get("proto", "reality")

        if nd_proto == "xhttp":
            # xHTTP TLS исходящий к exit-ноде
            out = {
                "tag":      tag,
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": nd["host"],
                        "port":    nd["port"],
                        "users":   [{
                            "id":         nd["uuid"],
                            "encryption": "none",
                            # xHTTP не использует flow xtls-rprx-vision
                        }],
                    }],
                },
                "streamSettings": {
                    "network":  "xhttp",
                    "security": "tls",
                    "sockopt":  {
                        "tcpFastOpen":        True,
                        "tcpKeepAliveInterval": 15,
                        "tcpKeepAliveIdle":   60,
                        "tcpUserTimeout":     10000,
                        "tcpCongestion":      "bbr",
                        **({"tcpNoDelay": True} if XHTTP_TCP_NO_DELAY else {}),
                    },
                    "tlsSettings": {
                        "serverName":  nd.get("sni", nd["host"]),
                        "fingerprint": nd.get("fp", "chrome"),
                        "alpn":        ["h2", "http/1.1"],
                        **({"enableSessionResumption": True} if XHTTP_ENABLE_SESSION_RESUMPTION else {}),
                    },
                    "xhttpSettings": _build_exit_xhttp_outbound_settings(nd),
                },
            }
        else:
            # REALITY TCP исходящий к exit-ноде (стандарт)
            out = {
                "tag":      tag,
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": nd["host"],
                        "port":    nd["port"],
                        "users":   [{
                            "id":         nd["uuid"],
                            "encryption": "none",
                            "flow":       nd.get("flow", "xtls-rprx-vision") or "xtls-rprx-vision",
                        }],
                    }],
                },
                "streamSettings": {
                    "network":  "tcp",
                    "security": "reality",
                    "sockopt":  {**_build_sockopt(), **({"mark": AWG_FWMARK} if AWG_EXIT_ENABLED else {})},  # ПАТЧ: AWG mark
                    "realitySettings": {
                        "show":        False,
                        "fingerprint": nd.get("fp", "chrome"),
                        "serverName":  nd.get("sni", ""),
                        "publicKey":   nd.get("pubkey", ""),
                        "shortId":     nd.get("shortid", ""),
                        "spiderX":     "/",
                    },
                },
            }
        outbounds_exit.append(out)

    # Inbound от клиента — зависит от PROTOCOL_MODE
    if PROTOCOL_MODE == "xhttp":
        cert_path = f"/etc/letsencrypt/live/{PARAM_DOMAIN}/fullchain.pem"
        key_path  = f"/etc/letsencrypt/live/{PARAM_DOMAIN}/privkey.pem"
        _xhttp_s2, _sockopt_s2 = _build_xhttp_settings(XHTTP_MODE, XHTTP_PATH)
        client_inbound = {
            "tag":      "inbound-xhttp",
            "port":     SERVER_PORT,
            "listen":   "::",
            "protocol": "vless",
            "settings": {
                "clients": [{
                    "id":    PARAM_UUID,
                    "email": f"user@{PARAM_DOMAIN}",
                }],
                "decryption": "none",
            },
            "sniffing": {
                "enabled":      True,
                "destOverride": ["http", "tls"],
                "metadataOnly": False,
                "routeOnly":    False,
            },
            "streamSettings": {
                "network":       "xhttp",
                "security":      "tls",
                "sockopt":       _sockopt_s2,
                "tlsSettings":   _build_tls_settings_xhttp(
                                     PARAM_DOMAIN, cert_path, key_path),
                "xhttpSettings": _xhttp_s2,
            },
        }
    else:
        # REALITY inbound (стандарт)
        client_inbound = {
            "tag":      "inbound-vless",
            "port":     SERVER_PORT,
            "listen":   "::",
            "protocol": "vless",
            "settings": {
                "clients": [{
                    "id":    PARAM_UUID,
                    "email": f"user@{PARAM_DOMAIN}",
                    **( {"flow": XTLS_FLOW} if XTLS_FLOW else {} ),
                }],
                "decryption": "none",
            },
            "sniffing": {
                "enabled":      True,
                "destOverride": ["http", "tls"],
                # AWG использует маршрутизацию ядра — sniffing доменов не нужен (metadataOnly=True).
                # Базовый VLESS/REALITY: metadataOnly=False обязателен — xray должен читать SNI/Host
                # чтобы freedom мог резолвить домены и применять UseIPv6v4 domainStrategy.
                "metadataOnly": True if AWG_EXIT_ENABLED else False,
                "routeOnly":    False,
            },
            "streamSettings": {
                "network": "tcp",
                "sockopt": _build_sockopt(),
                "security": "reality",
                "realitySettings": {
                    "show":        False,
                    "dest":        (PARAM_REALITY_DEST + ":443") if AWG_EXIT_ENABLED else PARAM_SOCKET_PATH,
                    # xver=1 (Proxy Protocol) только в классическом режиме VLESS-каскада:
                    # Nginx слушает на socket с proxy_protocol и шлёт PP-заголовок.
                    # xver=0 при AWG: Xray слушает напрямую на TCP, PP-заголовка нет.
                    "xver":        0 if AWG_EXIT_ENABLED else 1,
                    "spiderX":     PARAM_SPIDERX,
                    "serverNames": [PARAM_REALITY_DEST if AWG_EXIT_ENABLED else PARAM_DOMAIN],
                    "privateKey":  PARAM_PRIVATE_KEY,
                    "publicKey":   PARAM_PUBLIC_KEY,
                    "shortIds":    [PARAM_SHORTID],
                },
            },
        }

    # Балансировка: одна нода, несколько нод, или принудительное закрепление (pinned)
    pinned = CHAIN_PINNED_NODE_INDEX
    if n_nodes == 1 or (0 <= pinned < n_nodes):
        # Одна нода или pinned-режим — прямой outbound без балансировщика
        effective_tag = outbound_tags[pinned] if (0 <= pinned < n_nodes) else outbound_tags[0]
        if 0 <= pinned < n_nodes and n_nodes > 1:
            info(f"Pinned-режим: весь трафик → нода #{pinned+1} ({nodes[pinned]['host']})")
        balancers   = []
        observatory = None
        routing_rules = [
            # ИСПРАВЛЕНИЕ: loopback → direct ВСЕГДА (не только при AWG).
            # Без этого DNS-запросы Xray к 127.0.0.1:5300 (DNSCrypt-proxy) попадают
            # в exit-outbound (VLESS TCP) и получают "read response: EOF",
            # т.к. UDP к loopback невозможно туннелировать через VLESS.
            {"type": "field", "ip": ["127.0.0.1/8", "::1/128"], "outboundTag": "direct"},
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "BLOCK"},
            {"type": "field", "network": "tcp,udp",       "outboundTag": effective_tag},
        ]
    else:
        # Несколько нод — балансировщик с выбранной стратегией
        strategy = CHAIN_BALANCER_STRATEGY  # "roundRobin" | "leastPing" | "random"
        balancers = [{
            "tag":      "chain-balancer",
            "selector": outbound_tags,
            "strategy": {"type": strategy},
        }]
        routing_rules = [
            # ИСПРАВЛЕНИЕ: loopback → direct ВСЕГДА (не только при AWG).
            # Xray резолвит домены клиентов через встроенный DNS (IPIfNonMatch),
            # запросы идут к 127.0.0.1:5300 (DNSCrypt-proxy) — они должны уходить
            # через direct (loopback), а не через balancer/VLESS → EOF.
            {"type": "field", "ip": ["127.0.0.1/8", "::1/128"], "outboundTag": "direct"},
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "BLOCK"},
            {"type": "field", "network": "tcp,udp",       "balancerTag": "chain-balancer"},
        ]
        # leastPing / leastLoad требуют observatory — без него деградирует до random
        if strategy in ("leastPing", "leastLoad"):
            observatory = {
                "subjectSelector":       ["chain-exit-"],
                "probeUrl":              "https://1.1.1.1/cdn-cgi/trace",
                "probeInterval":         "30s",
                "enableConcurrency":     True,
            }
        else:
            observatory = None

    config: dict[str, Any] = {
        "log": _xray_log_block(),
        "dns": {
            "servers": dns_servers,
            "hosts": {
                "dns.google":         "8.8.8.8",
                "dns.cloudflare.com": "1.1.1.1",
                "localhost":          "127.0.0.1",
            },
            "disableCache":           False,
            "queryStrategy":          query_strategy,
            "disableFallback":        False,
            "disableFallbackIfMatch": True,
        },
        "inbounds": [client_inbound],
        "outbounds": outbounds_exit + [
            {"protocol": "blackhole", "tag": "BLOCK"},
            # ИСПРАВЛЕНИЕ: direct outbound нужен ВСЕГДА — не только при AWG.
            # Правило 127.0.0.1/8 → direct (выше в routing) требует этого outbound,
            # иначе xray упадёт с ошибкой "unknown outbound tag".
            # При AWG добавляем fwmark для корректной маршрутизации через AWG-таблицу.
            {
                "protocol": "freedom",
                "tag":      "direct",
                "settings": {"domainStrategy": "UseIPv6v4"},
                **({"streamSettings": {"sockopt": {"mark": AWG_FWMARK}}} if AWG_EXIT_ENABLED else {}),
            },
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules":          routing_rules,
        },
    }

    if balancers:
        config["routing"]["balancers"] = balancers

    # observatory нужен только для leastPing и leastLoad
    if observatory:
        config["observatory"] = observatory

    # ── Split tunneling (Режим B — Entry Node) ────────────────────────────────
    # В Режиме B заблокированный трафик идёт через exit-ноду (proxy_tag),
    # российский трафик идёт напрямую (direct), не проксируется.
    if SPLIT_TUNNEL_ENABLED:
        # В Режиме B "direct" = прямой выход с Entry Node (российский VPS),
        # proxy_tag = первая exit-нода (или балансировщик)
        if not any(ob.get("tag") == "direct" for ob in config.get("outbounds", [])):
            config["outbounds"].insert(0, {
                "protocol": "freedom",
                "tag":      "direct",
                "settings": {"domainStrategy": "UseIP"},
            })
        proxy_t = "chain-balancer" if balancers else (outbound_tags[0] if outbound_tags else "direct")
        st_rules = build_split_tunnel_routing_rules(proxy_tag=proxy_t, direct_tag="direct")
        if st_rules:
            config["routing"]["rules"] = st_rules + config["routing"]["rules"]
            config["routing"]["geoDataBasePath"] = str(CONFIG_DIR)
            info(f"Split tunneling: добавлено {len(st_rules)} правил (Режим B, Entry Node)")

    cfg_file = CONFIG_DIR / "config.json"
    _apply_stats_to_config(config)
    cfg_file.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    _set_config_owner(cfg_file)

    alt_dir = Path("/usr/local/etc/xray")
    if alt_dir.exists():
        alt_cfg = alt_dir / "config.json"
        alt_cfg.unlink(missing_ok=True)
        try:
            alt_cfg.symlink_to(cfg_file)
        except Exception:
            pass

    r = _run([str(XRAY_BIN), "run", "-test", "-config", str(cfg_file)],
             capture=True, check=False)
    strategy_label = {"roundRobin": "Round Robin", "leastPing": "Least Ping", "leastLoad": "Least Load", "random": "Random"}.get(
        CHAIN_BALANCER_STRATEGY, CHAIN_BALANCER_STRATEGY
    )
    if r.returncode == 0:
        if n_nodes == 1:
            success(f"Конфиг Entry Node (Режим B, 1 нода) создан и валиден")
        else:
            success(f"Конфиг Entry Node (Режим B, {n_nodes} нод, стратегия: {strategy_label}) создан и валиден")
    else:
        warn("Конфигурация создана с предупреждением")
        log_to_file("WARN", r.stderr[-1000:] if r.stderr else "")
    _h2_reapply_transport_if_active()


def do_change_domain_strategy() -> None:
    """
    Изменить стратегию исходящих соединений (domainStrategy) без переустановки.
    Доступно из главного меню [O] для любого режима (A и B).
    Патчит живой config.json и сохраняет в state.json.
    """
    global PARAM_DOMAIN_STRATEGY

    _box_top(f"Стратегия исходящих соединений (domainStrategy)")

    # Определяем текущее значение — приоритет:
    # 1. state.json["strategy"]  (там хранится UseIPv6v4 / UseIPv4 / ...)
    # 2. freedom-outbound в config.json (domainStrategy внутри settings)
    # 3. глобальная переменная PARAM_DOMAIN_STRATEGY
    _cur_ds = ""
    _cfg_f = CONFIG_DIR / "config.json"

    if STATE_FILE.exists():
        try:
            _cur_ds = json.loads(STATE_FILE.read_text()).get("strategy", "")
        except Exception:
            pass

    if not _cur_ds and _cfg_f.exists():
        try:
            _c = json.loads(_cfg_f.read_text())
            for _ob in _c.get("outbounds", []):
                if _ob.get("protocol") == "freedom" and _ob.get("tag") not in ("xray-stats-api",):
                    _ds_val = _ob.get("settings", {}).get("domainStrategy", "")
                    if _ds_val:
                        _cur_ds = _ds_val
                        break
        except Exception:
            pass

    if not _cur_ds:
        _cur_ds = PARAM_DOMAIN_STRATEGY

    # Показываем текущую стратегию
    _ds_label_map = {
        "UseIPv6v4": "UseIPv6v4 (IPv6→IPv4)",
        "UseIPv4v6": "UseIPv4v6 (IPv4→IPv6)",
        "UseIP":     "UseIP (системный DNS)",
        "UseIPv4":   "UseIPv4 (только IPv4)",
    }
    _cur_label = _ds_label_map.get(_cur_ds, _cur_ds if _cur_ds else "не определена")
    _box_row(f"  {DIM}Текущая стратегия:{NC} {CYAN}{_cur_label}{NC}")

    # Показываем IPv6 статус
    if IS_IPV6_AVAILABLE or IPV6_PREFLIGHT:
        _box_row(f"   {GREEN}ℹ IPv6 обнаружен на сервере{NC}")

    _ds_opts = {
        "1": ("UseIPv6v4", "UseIPv6v4 — сначала IPv6, fallback IPv4 (рекомендуется при IPv6)"),
        "2": ("UseIPv4v6", "UseIPv4v6 — сначала IPv4, fallback IPv6"),
        "3": ("UseIP",     "UseIP     — системный DNS (без предпочтения)"),
        "4": ("UseIPv4",   "UseIPv4   — только IPv4"),
    }
    for k, (val, desc) in _ds_opts.items():
        marker = f"  {GREEN}◀ текущая{NC}" if val == _cur_ds else ""
        _box_row(f"   {CYAN}[{k}]{NC} {desc}{marker}")

    _box_bottom()
    v = input(f"   {CYAN}Выбор [Enter = отмена]:{NC} ").strip()
    if v not in _ds_opts:
        info("Изменение отменено.")
        return

    new_ds, new_ds_desc = _ds_opts[v]
    PARAM_DOMAIN_STRATEGY = new_ds

    # Сохраняем в state.json
    if STATE_FILE.exists():
        try:
            _st = json.loads(STATE_FILE.read_text())
            _st["strategy"] = new_ds
            STATE_FILE.write_text(json.dumps(_st, indent=2, ensure_ascii=False))
            log_to_file("INFO", f"domainStrategy изменена → {new_ds}")
        except Exception as e:
            warn(f"Не удалось сохранить в state.json: {e}")

    # Патчим живой config.json напрямую
    if _cfg_f.exists():
        try:
            _c2 = json.loads(_cfg_f.read_text())
            _c2.setdefault("routing", {})["domainStrategy"] = new_ds
            # Обновляем domainStrategy во всех freedom-outbound (direct)
            for _ob in _c2.get("outbounds", []):
                if _ob.get("protocol") == "freedom" and _ob.get("tag") not in ("xray-stats-api",):
                    _ob.setdefault("settings", {})["domainStrategy"] = new_ds
            _cfg_f.write_text(json.dumps(_c2, indent=2, ensure_ascii=False))
            success(f"domainStrategy изменена → {new_ds_desc}")
        except Exception as e2:
            warn(f"Не удалось обновить config.json: {e2}")
            return
    else:
        warn("config.json не найден — выполните установку (пункт 1).")
        return

    ans = input(f"{YELLOW}Перезапустить Xray для применения? [y/N]:{NC} ").strip().lower()
    if ans == 'y':
        _run(["systemctl", "restart", "xray"], check=False, quiet=True)
        time.sleep(3)
        rs = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
        if rs.stdout.strip() == "active":
            success("Xray активен — новая domainStrategy применена")
        else:
            warn("Xray не запустился — проверьте: journalctl -u xray -n 30")


def _rebuild_and_restart_xray(ok_msg: str = "Xray активен") -> None:
    """
    Пересоздаёт конфиг Xray (с учётом режима A/B и протокола),
    восстанавливает пользователей и RIPE-правила, затем перезапускает сервис.
    Единая точка пересборки — вызывается из всех мест меню нод и split tunnel.
    """
    # Бэкап текущего конфига перед пересборкой
    _bk_ok, _bk_path = backup_xray_config()
    if _bk_ok:
        info(f"Бэкап конфига: {_bk_path}")
    else:
        info(f"Бэкап конфига: {_bk_path}")

    if INSTALL_MODE == "B":
        generate_xray_config_chain_entry_multi()
    elif PROTOCOL_MODE == "xhttp":
        generate_xray_config_xhttp()
    else:
        generate_xray_config()

    # Восстанавливаем пользователей (generate_* пишет только PARAM_UUID)
    if USERS_FILE.exists():
        try:
            _uu = json.loads(USERS_FILE.read_text())
            if _uu:
                _users_patch_config_no_restart(_uu)
                info(f"Восстановлено {len(_uu)} пользователей в конфиг")
        except Exception as _e:
            warn(f"Не удалось восстановить пользователей: {_e}")

    # Восстанавливаем RIPE-правила (generate_* перезаписывает routing полностью)
    _ru_subnets_restore_if_needed(silent=False)

    # Восстанавливаем AS-direct правила (if any)
    _as_direct_restore_if_needed(silent=False)

    # Восстанавливаем Telemt tproxy-интеграцию (если установлен).
    # generate_* перезаписывает config.json целиком — dokodemo inbound и
    # iptables-правила теряются. Переинжектируем ДО рестарта xray, чтобы
    # inbound уже был в конфиге к моменту запуска.
    try:
        from vless_installer.modules.mtproto import telemt_tproxy_emergency_restore
        _tp_result, _tp_msg = telemt_tproxy_emergency_restore()
        if _tp_result is True:
            info(f"Telemt tproxy: {_tp_msg}")
        elif _tp_result is False:
            warn(f"Telemt tproxy: {_tp_msg}")
        # None = не установлен / неприменимо — молчим
    except ImportError:
        pass
    except Exception as _tp_e:
        warn(f"Telemt tproxy восстановление: {_tp_e}")

    # Восстанавливаем экспериментальный постквантовый VLESS-инбаунд (если
    # был включён). Та же причина, что и у Telemt выше — generate_*
    # стирает любые дополнительные инбаунды. Восстанавливает СОХРАНЁННЫМИ
    # ключами, никогда не генерирует новые — иначе уже выданные клиентам
    # ссылки сломаются. Полностью изолирован от остальной генерации
    # REALITY-конфига — свой порт, тот же dest/ключи с другим shortId.
    try:
        from vless_installer.modules.pq_vless import restore_pq_vless_if_enabled
        _pq_result = restore_pq_vless_if_enabled(
            domain=PARAM_DOMAIN, reality_dest=PARAM_REALITY_DEST,
            private_key=PARAM_PRIVATE_KEY, public_key=PARAM_PUBLIC_KEY,
            spiderx=PARAM_SPIDERX, xtls_flow=XTLS_FLOW, primary_uuid=PARAM_UUID,
        )
        if _pq_result is not None:
            _pq_ok, _pq_msg = _pq_result
            (info if _pq_ok else warn)(f"PQ VLESS: {_pq_msg}")
        # None = фича не была включена — молчим
    except ImportError:
        pass
    except Exception as _pq_e:
        warn(f"PQ VLESS восстановление: {_pq_e}")

    # Финальный рестарт
    _run(["systemctl", "restart", "xray"], check=False, quiet=True)
    time.sleep(3)
    rs = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
    if rs.stdout.strip() == "active":
        success(ok_msg)
    else:
        warn("Xray не запустился — проверьте: journalctl -u xray -n 30")

    # BUGFIX: при REALITY+Unix-сокет xray пересоздаёт /dev/shm/XXXX.socket при каждом
    # старте. nginx держит upstream к старому (уже несуществующему) сокету — все
    # клиентские соединения получают EOF немедленно. Нужно дождаться нового сокета
    # и перезапустить nginx чтобы он подхватил его.
    # BUGFIX: nginx создаёт unix-сокет при своём bind; ждать сокет ДО restart nginx —
    # deadlock. Сначала перезапускаем nginx, потом ждём подтверждения сокета.
    if PROTOCOL_MODE == "reality" and PARAM_SOCKET_PATH and not AWG_EXIT_ENABLED:
        rn = _run(["systemctl", "is-active", "nginx"], capture=True, check=False)
        if rn.stdout.strip() == "active":
            _run(["systemctl", "restart", "nginx"], check=False, quiet=True)
            for _i in range(20):
                if Path(PARAM_SOCKET_PATH).is_socket():
                    break
                time.sleep(1)
            info("nginx перезапущен, Unix-сокет готов")


def do_manage_nodes() -> None:
    """
    Пункт [E] главного меню: управление exit-нодами каскада (Режим B).
    Позволяет добавить, удалить ноду и пересобрать конфиг Xray.
    """
    global CHAIN_NODES, INSTALL_MODE, CHAIN_BALANCER_STRATEGY, CHAIN_PINNED_NODE_INDEX
    global PARAM_DOMAIN, PARAM_UUID, PARAM_PUBLIC_KEY, PARAM_SHORTID
    global PARAM_PRIVATE_KEY, PARAM_SOCKET_PATH, PARAM_SPIDERX
    global PROTOCOL_MODE, SERVER_PORT, XHTTP_PORT, XHTTP_MODE, XHTTP_PATH, XHTTP_PERF_PRESET
    global PARAM_DOMAIN_STRATEGY
    global SPLIT_TUNNEL_ENABLED, SPLIT_TUNNEL_EXTRA_DOMAINS, SPLIT_TUNNEL_EXTRA_IPS
    global AWG_EXIT_ENABLED, PARAM_REALITY_DEST

    # Загружаем state
    if not STATE_FILE.exists():
        warn("state.json не найден. Сначала выполните установку (пункт 1).")
        return

    try:
        state = json.loads(STATE_FILE.read_text())
        INSTALL_MODE      = state.get("install_mode",  "A")
        PARAM_DOMAIN      = state.get("domain",        PARAM_DOMAIN)
        PARAM_UUID        = state.get("uuid",          PARAM_UUID)
        PARAM_PUBLIC_KEY  = state.get("public_key",    PARAM_PUBLIC_KEY)
        PARAM_SHORTID     = state.get("short_id",      PARAM_SHORTID)
        PARAM_PRIVATE_KEY = state.get("private_key",   PARAM_PRIVATE_KEY)
        PARAM_SOCKET_PATH = state.get("socket",        PARAM_SOCKET_PATH)
        PARAM_SPIDERX     = state.get("spiderx",       PARAM_SPIDERX)
        # Критично для пересборки конфига: без этих переменных generate_xray_config_chain_entry_multi()
        # использует глобальные дефолты ("reality", 443, "") и собирает неверный конфиг.
        PROTOCOL_MODE     = state.get("protocol_mode", PROTOCOL_MODE)
        SERVER_PORT       = state.get("server_port",   SERVER_PORT)
        XHTTP_PORT        = SERVER_PORT
        XHTTP_MODE        = state.get("xhttp_mode",   XHTTP_MODE)
        XHTTP_PATH        = state.get("xhttp_path",   XHTTP_PATH)
        XHTTP_PERF_PRESET = state.get("xhttp_perf_preset", XHTTP_PERF_PRESET)
        CHAIN_NODES = _nodes_from_state(state)
        CHAIN_BALANCER_STRATEGY = state.get("chain_balancer_strategy", CHAIN_BALANCER_STRATEGY)
        CHAIN_PINNED_NODE_INDEX = state.get("chain_pinned_node_index", -1)
        AWG_EXIT_ENABLED  = state.get("awg_exit_enabled", False)
        H2_EXIT_ENABLED   = state.get("h2_exit_enabled",  False)
        PARAM_REALITY_DEST = state.get("reality_dest",    PARAM_REALITY_DEST)
    except Exception as e:
        warn(f"Не удалось прочитать state.json: {e}")
        return

    # Загружаем настройки split tunnel — они должны сохраняться при любых
    # операциях с нодами (добавление, удаление, пересборка конфига).
    _load_split_tunnel_custom()

    # BUGFIX: определяем поддержку "mode" для установленной версии Xray.
    # Без этого вызова XHTTP_MODE_SUPPORTED остаётся False (дефолт),
    # и "mode": "streamup" не пишется в конфиг — или пишется неверно.
    _detect_xhttp_mode_support()

    if INSTALL_MODE != "B":
        warn("Установка выполнена в Режиме A — управление нодами недоступно.")
        warn("Для каскадного прокси выберите Режим B при установке (пункт 1).")
        return

    # ── AWG-режим: нет VLESS exit-нод для управления ────────────────────────
    if AWG_EXIT_ENABLED:
        print()
        _box_top("Управление Exit-нодами каскада (Режим B)")
        _box_warn("Транспорт AWG 2.0 активен — VLESS exit-ноды не используются.")
        _box_row(f"  {DIM}Выход осуществляется через туннель awg0 → {AWG_EXIT_HOST or 'exit-VPS'}.{NC}")
        _box_row(f"  {DIM}Для настройки туннеля используйте пункт установки AWG.{NC}")
        _box_row(f"  {DIM}Для мониторинга: Безопасность → [W] AWG Tunnel Watchdog{NC}")
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    while True:
        os.system("clear")
        print()
        print(f"{BOLD}{CYAN}══ Управление Exit-нодами каскада (Режим B) ══{NC}")
        print(f"  Entry Node (этот сервер): {CYAN}{PARAM_DOMAIN}:{SERVER_PORT}{NC}")
        print()

        # ── Текущие настройки (статус) ─────────────────────────────────────────
        _strat_labels = {
            "roundRobin": "Round Robin",
            "leastPing":  "Least Ping",
            "leastLoad":  "Least Load",
            "random":     "Random",
        }
        _ds_labels = {
            "UseIPv6v4": "UseIPv6v4 (IPv6→IPv4)",
            "UseIPv4v6": "UseIPv4v6 (IPv4→IPv6)",
            "UseIP":     "UseIP (системный DNS)",
            "UseIPv4":   "UseIPv4 (только IPv4)",
        }
        # Читаем стратегию из живого конфига если возможно
        _live_ds = PARAM_DOMAIN_STRATEGY
        _live_cfg_file = CONFIG_DIR / "config.json"
        if not _live_ds and _live_cfg_file.exists():
            try:
                _c = json.loads(_live_cfg_file.read_text())
                _live_ds = _c.get("routing", {}).get("domainStrategy", "")
            except Exception:
                pass
        if not _live_ds and STATE_FILE.exists():
            try:
                _live_ds = json.loads(STATE_FILE.read_text()).get("strategy", "")
            except Exception:
                pass

        _ds_label = _ds_labels.get(_live_ds, _live_ds or "—")
        _bal_label = _strat_labels.get(CHAIN_BALANCER_STRATEGY, CHAIN_BALANCER_STRATEGY)

        print(f"  {DIM}Стратегия исходящих (domainStrategy):{NC} {CYAN}{_ds_label}{NC}")
        if len(CHAIN_NODES) >= 2:
            print(f"  {DIM}Стратегия балансировки:{NC}                {CYAN}{_bal_label}{NC}")
        print()
        # ────────────────────────────────────────────────────────────────────────

        if not CHAIN_NODES:
            print(f"  {YELLOW}Нод пока нет.{NC}")
        else:
            print(f"  Текущие exit-ноды ({len(CHAIN_NODES)}/{MAX_CHAIN_NODES}):")
            for i, nd in enumerate(CHAIN_NODES):
                print(f"    {CYAN}[{i+1}]{NC} {nd['host']}:{nd['port']}  "
                      f"SNI={nd['sni']}  FP={nd['fp']}")
        print()
        _box_top("Действия")
        _box_item("A", f"Добавить ноду")
        if CHAIN_NODES:
            _box_item("D", f"Удалить ноду")
            _box_item("R", f"Пересобрать конфиг Xray и перезапустить")
            _box_item("S", f"Показать сводку и ссылку")
            _box_item("T", f"Пинг всех Exit Node")
            pinned_label = (
                f"нода #{CHAIN_PINNED_NODE_INDEX+1} ({CHAIN_NODES[CHAIN_PINNED_NODE_INDEX]['host']})"
                if 0 <= CHAIN_PINNED_NODE_INDEX < len(CHAIN_NODES)
                else "выкл (балансировщик)"
            )
            _box_item("P", f"Закрепить exit-ноду  [{pinned_label}]")
            if len(CHAIN_NODES) >= 2:
                _box_item("B", f"Изменить стратегию балансировки  [{_bal_label}]")
        _box_item("O", f"Изменить стратегию исходящих соединений  [{_ds_label}]")
        _box_item("N", f"Доп. клиент для резервной Entry-ноды  {DIM}(на уже развёрнутый exit){NC}")
        _box_item_exit("0", f"Назад в главное меню")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            print()
            break

        if ch == "0" or ch == "":
            break

        elif ch == "a":
            if len(CHAIN_NODES) >= MAX_CHAIN_NODES:
                warn(f"Достигнут максимум нод ({MAX_CHAIN_NODES}).")
                time.sleep(2)
                continue
            idx = len(CHAIN_NODES) + 1
            nd = _prompt_one_node(idx)
            if nd is None:
                info("Добавление ноды отменено.")
                time.sleep(1)
                continue
            CHAIN_NODES.append(nd)
            _save_chain_nodes_to_state()
            success(f"Нода #{idx} добавлена: {nd['host']}:{nd['port']}")
            # Предложим сразу пересобрать конфиг
            ans = input(f"{YELLOW}Пересобрать конфиг Xray и перезапустить сейчас? [y/N]:{NC} ").strip().lower()
            if ans == 'y':
                _rebuild_and_restart_xray("Xray активен — нода добавлена")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "d" and CHAIN_NODES:
            print()
            _box_top(f"Удалить ноду  (0 = отмена)")
            for i, nd in enumerate(CHAIN_NODES):
                _box_item(f"{i+1}", f"{nd['host']}:{nd['port']}  SNI={nd['sni']}")
            _box_bottom()
            v = input(f"  Номер: ").strip()
            if not v.isdigit() or int(v) == 0:
                info("Удаление отменено.")
                time.sleep(1)
                continue
            idx = int(v) - 1
            if idx < 0 or idx >= len(CHAIN_NODES):
                warn("Нет такой ноды.")
                time.sleep(1)
                continue
            removed = CHAIN_NODES.pop(idx)
            _save_chain_nodes_to_state()
            success(f"Нода {removed['host']}:{removed['port']} удалена.")
            if CHAIN_NODES:
                ans = input(f"{YELLOW}Пересобрать конфиг Xray и перезапустить сейчас? [y/N]:{NC} ").strip().lower()
                if ans == 'y':
                    _rebuild_and_restart_xray("Xray активен — нода удалена")
            else:
                warn("Список нод пуст. Трафик некуда отправлять!")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "r" and CHAIN_NODES:
            if not CHAIN_NODES:
                warn("Нет нод — нечего применять.")
                time.sleep(2)
                continue
            _rebuild_and_restart_xray("Xray активен — конфиг применён")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "s" and CHAIN_NODES:
            generate_chain_summary()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "t" and CHAIN_NODES:
            print()
            _box_top("Пинг Exit Node")
            _box_row(f"  {DIM}TCP-латентность до каждой ноды:{NC}")
            _box_sep()
            for i, nd in enumerate(CHAIN_NODES):
                host, port = nd["host"], nd["port"]
                _box_row(f"  {CYAN}[{i+1}]{NC} {host}:{port}  →  измеряю...")
                lat = _speed_test_node_latency(host, port)
                flag_str = ""
                try:
                    import socket as _s
                    ip = _s.gethostbyname(host)
                    r = _run(["curl", "-s", "--max-time", "4",
                              f"http://ip-api.com/json/{ip}?fields=countryCode"],
                             capture=True, check=False)
                    if r.returncode == 0:
                        import json as _j
                        cc = _j.loads(r.stdout.strip()).get("countryCode", "")
                        if cc:
                            flag_str = f"  {country_flag_emoji(cc)}"
                except Exception:
                    pass
                # Перерисовываем строку с результатом
                _box_row(f"  {CYAN}[{i+1}]{NC} {host}:{port}{flag_str}  →  {lat}")
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "p" and CHAIN_NODES:
            print()
            _box_top(f"Закрепить exit-ноду  (0 = отключить)")
            _box_row(f"  {DIM}Весь трафик идёт только через выбранную ноду; балансировщик выключен.{NC}")
            _box_sep()
            for i, nd in enumerate(CHAIN_NODES):
                marker = f"  {GREEN}◀ активна{NC}" if i == CHAIN_PINNED_NODE_INDEX else ""
                _box_item(f"{i+1}", f"{nd['host']}:{nd['port']}  SNI={nd['sni']}{marker}")
            _box_item("0", f"Отключить закрепление (включить балансировщик)")
            _box_bottom()
            v = input(f"  Выбор: ").strip()
            if v == "0":
                CHAIN_PINNED_NODE_INDEX = -1
                info("Pinned-режим отключён. Активен балансировщик.")
            elif v.isdigit() and 1 <= int(v) <= len(CHAIN_NODES):
                CHAIN_PINNED_NODE_INDEX = int(v) - 1
                nd = CHAIN_NODES[CHAIN_PINNED_NODE_INDEX]
                success(f"Закреплена нода #{CHAIN_PINNED_NODE_INDEX+1}: {nd['host']}:{nd['port']}")
            else:
                warn("Неверный выбор.")
                time.sleep(1)
                continue
            _save_chain_nodes_to_state()
            ans = input(f"{YELLOW}Пересобрать конфиг и перезапустить Xray? [y/N]:{NC} ").strip().lower()
            if ans == 'y':
                _rebuild_and_restart_xray("Xray активен — pinned-режим применён")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "b" and len(CHAIN_NODES) >= 2:
            # ── Изменить стратегию балансировки без переустановки ─────────────
            print()
            print()
            _box_top(f"Изменить стратегию балансировки")
            _b_map = {
                "roundRobin": "Round Robin  — по очереди, равномерно",
                "leastPing":  "Least Ping   — к ноде с наименьшим RTT (нужен observatory)",
                "leastLoad":  "Least Load   — к ноде с наименьшей нагрузкой (нужен observatory)",
                "random":     "Random       — случайный выбор при каждом подключении",
            }
            _b_keys = list(_b_map.keys())
            for idx2, k in enumerate(_b_keys, 1):
                marker = f"  {GREEN}◀ текущая{NC}" if k == CHAIN_BALANCER_STRATEGY else ""
                _box_item(f"{idx2}", f"{_b_map[k]}{marker}")
            _box_bottom()
            v = input(f"  {CYAN}Выбор [Enter = отмена]:{NC} ").strip()
            if v.isdigit() and 1 <= int(v) <= len(_b_keys):
                new_strat = _b_keys[int(v) - 1]
                CHAIN_BALANCER_STRATEGY = new_strat
                _save_chain_nodes_to_state()
                _stl = {"roundRobin": "Round Robin", "leastPing": "Least Ping",
                        "leastLoad": "Least Load", "random": "Random"}
                success(f"Стратегия балансировки изменена → {_stl.get(new_strat, new_strat)}")
                ans = input(f"{YELLOW}Пересобрать конфиг Xray и перезапустить? [y/N]:{NC} ").strip().lower()
                if ans == 'y':
                    _rebuild_and_restart_xray("Xray активен — новая стратегия балансировки применена")
            else:
                info("Изменение отменено.")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "o":
            # ── Изменить domainStrategy без переустановки ──────────────────────
            print()
            print()
            _box_top(f"Изменить стратегию исходящих соединений")
            # Определяем текущее: state.json → freedom-outbound → глобальная переменная
            _cur_ds = ""
            _cfg_f = CONFIG_DIR / "config.json"
            if STATE_FILE.exists():
                try:
                    _cur_ds = json.loads(STATE_FILE.read_text()).get("strategy", "")
                except Exception:
                    pass
            if not _cur_ds and _cfg_f.exists():
                try:
                    _c = json.loads(_cfg_f.read_text())
                    for _ob in _c.get("outbounds", []):
                        if _ob.get("protocol") == "freedom" and _ob.get("tag") not in ("xray-stats-api",):
                            _ds_val = _ob.get("settings", {}).get("domainStrategy", "")
                            if _ds_val:
                                _cur_ds = _ds_val
                                break
                except Exception:
                    pass
            if not _cur_ds:
                _cur_ds = PARAM_DOMAIN_STRATEGY
            # Показываем текущую стратегию
            _ds_lbl_map = {
                "UseIPv6v4": "UseIPv6v4 (IPv6→IPv4)",
                "UseIPv4v6": "UseIPv4v6 (IPv4→IPv6)",
                "UseIP":     "UseIP (системный DNS)",
                "UseIPv4":   "UseIPv4 (только IPv4)",
            }
            _cur_lbl = _ds_lbl_map.get(_cur_ds, _cur_ds if _cur_ds else "не определена")
            _box_row(f"  {DIM}Текущая стратегия:{NC} {CYAN}{_cur_lbl}{NC}")
            _ds_opts = {
                "1": ("UseIPv6v4", "UseIPv6v4 — сначала IPv6, fallback IPv4"),
                "2": ("UseIPv4v6", "UseIPv4v6 — сначала IPv4, fallback IPv6"),
                "3": ("UseIP",     "UseIP     — системный DNS"),
                "4": ("UseIPv4",   "UseIPv4   — только IPv4"),
            }
            for k2, (val, desc) in _ds_opts.items():
                marker = f"  {GREEN}◀ текущая{NC}" if val == _cur_ds else ""
                _box_item(f"{k2}", f"{desc}{marker}")
            _box_bottom()
            v = input(f"  {CYAN}Выбор [Enter = отмена]:{NC} ").strip()
            if v in _ds_opts:
                new_ds, new_ds_desc = _ds_opts[v]
                PARAM_DOMAIN_STRATEGY = new_ds
                # Сохраняем в state.json
                if STATE_FILE.exists():
                    try:
                        _st2 = json.loads(STATE_FILE.read_text())
                        _st2["strategy"] = new_ds
                        STATE_FILE.write_text(json.dumps(_st2, indent=2, ensure_ascii=False))
                    except Exception as _e2:
                        warn(f"Не удалось сохранить в state.json: {_e2}")
                # Патчим живой конфиг напрямую (быстро, без полной пересборки)
                if _cfg_f.exists():
                    try:
                        _c2 = json.loads(_cfg_f.read_text())
                        _c2.setdefault("routing", {})["domainStrategy"] = new_ds
                        # Обновляем domainStrategy в freedom-outbound (direct/UseIP)
                        for _ob in _c2.get("outbounds", []):
                            if _ob.get("protocol") == "freedom" and _ob.get("tag") not in ("xray-stats-api",):
                                _ob.setdefault("settings", {})["domainStrategy"] = new_ds
                        _cfg_f.write_text(json.dumps(_c2, indent=2, ensure_ascii=False))
                        success(f"domainStrategy изменена → {new_ds_desc}")
                    except Exception as _e3:
                        warn(f"Не удалось обновить config.json: {_e3}")
                ans = input(f"{YELLOW}Перезапустить Xray для применения? [y/N]:{NC} ").strip().lower()
                if ans == 'y':
                    _run(["systemctl", "restart", "xray"], check=False, quiet=True)
                    time.sleep(3)
                    rs = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
                    if rs.stdout.strip() == "active":
                        success("Xray активен — новая domainStrategy применена")
                    else:
                        warn("Xray не запустился — проверьте: journalctl -u xray -n 30")
            else:
                info("Изменение отменено.")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "n":
            do_generate_chain_exit_additional_client()

        else:
            warn("Неверный выбор.")
            time.sleep(1)


# =============================================================================
#  ГЕНЕРАЦИЯ ИТОГОВЫХ ФАЙЛОВ ДЛЯ РЕЖИМА B
# =============================================================================
def generate_chain_summary() -> None:
    """Записывает сводный файл с инструкцией и ссылкой для Режима B.
    Поддерживает как одну, так и несколько exit-нод. При AWG — сводку туннеля."""
    global _BOX_W
    _BOX_W = _get_box_width()

    # ── AWG-режим: показываем сводку туннеля вместо VLESS chain ─────────────
    if AWG_EXIT_ENABLED and INSTALL_MODE == "B":
        print()
        _box_top("Сводка AWG 2.0 туннеля (Режим B)")
        _box_row(f"  Транспорт:      {CYAN}AmneziaWG 2.0{NC}")
        _box_row(f"  Entry-сервер:   {CYAN}{PARAM_DOMAIN or SERVER_IP}{NC}:{SERVER_PORT}")
        _box_row(f"  AWG exit-VPS:   {CYAN}{AWG_EXIT_HOST}:{AWG_EXIT_PORT}/udp{NC}")
        _box_row(f"  Интерфейс:      {CYAN}{AWG_INTERFACE}{NC}")
        _box_row(f"  Подсеть IPv4:   {CYAN}{AWG_SUBNET}{NC}")
        _box_row(f"  Подсеть IPv6:   {CYAN}{AWG_SUBNET_V6}{NC}")
        _box_row()
        _r_awg = _run(["ip", "link", "show", AWG_INTERFACE], capture=True, check=False)
        _awg_up = _r_awg.returncode == 0
        _awg_col = GREEN if _awg_up else RED
        _awg_label = "активен" if _awg_up else "НЕ ПОДНЯТ"
        _box_row(f"  Туннель:        {_awg_col}{_awg_label}{NC}")
        _box_row()
        _box_row(f"  {DIM}Трафик: Xray → fwmark {AWG_FWMARK} → ip rule → "
                 f"table {AWG_ROUTE_TABLE} → awg0 → exit-VPS{NC}")
        _box_bottom()
        return

    entry_host = PARAM_DOMAIN  # Патч: ссылка по домену вместо IP

    # Собираем актуальный список нод
    nodes = CHAIN_NODES if CHAIN_NODES else []
    if not nodes and CHAIN_EXIT_HOST:
        nodes = [{
            "host":    CHAIN_EXIT_HOST,
            "port":    CHAIN_EXIT_PORT,
            "uuid":    CHAIN_EXIT_UUID,
            "pubkey":  CHAIN_EXIT_PUBKEY,
            "shortid": CHAIN_EXIT_SHORTID,
            "sni":     CHAIN_EXIT_SNI,
            "fp":      CHAIN_EXIT_FP,
        }]

    # Клиентская ссылка — подключаться к entry (российскому) VPS
    import urllib.parse as _uparse
    _, _, _chain_flag = get_server_country_cached()
    _chain_flag_prefix = f"{_chain_flag} " if _chain_flag and _chain_flag != "🌐" else ""
    _chain_label = _chain_flag_prefix + _uparse.quote(f"{PARAM_DOMAIN}-chain")
    proto = PROTOCOL_MODE
    if proto == "xhttp":
        _path_enc = _uparse.quote(XHTTP_PATH, safe="/")
        _cs_fp = PARAM_FINGERPRINT or _fp_from_state()
        link = (
            f"vless://{PARAM_UUID}@{entry_host}:{SERVER_PORT}"
            f"?type=xhttp&security=tls&sni={PARAM_DOMAIN}"
            f"&path={_path_enc}&mode={XHTTP_MODE}"
            f"&fp={_cs_fp}#{_chain_label}"
        )
    else:
        _reality_sni = PARAM_REALITY_DEST if AWG_EXIT_ENABLED else PARAM_DOMAIN
        _cs_fp = PARAM_FINGERPRINT or _fp_from_state()
        link = (
            f"vless://{PARAM_UUID}@{entry_host}:{SERVER_PORT}"
            f"?type=tcp&security=reality&pbk={PARAM_PUBLIC_KEY}"
            f"&fp={_cs_fp}&sni={_reality_sni}&sid={PARAM_SHORTID}"
            f"&flow=xtls-rprx-vision#{_chain_label}"
        )

    # Определяем метку стратегии ДО цикла — она нужна внутри него
    strategy_labels = {
        "roundRobin": "Round Robin",
        "leastPing":  "Least Ping",
        "leastLoad":  "Least Load",
        "random":     "Random",
    }
    strategy_label = strategy_labels.get(CHAIN_BALANCER_STRATEGY, CHAIN_BALANCER_STRATEGY)

    n_label = f"{len(nodes)} нод" if len(nodes) > 1 else "1 нода"

    # Строим текст для exit-нод
    nodes_text = ""
    for i, nd in enumerate(nodes):
        nd_proto = nd.get("proto", "reality")
        if len(nodes) > 1:
            lbl = f"балансировка {strategy_label}"
        else:
            lbl = "единственная нода"
        if nd_proto == "xhttp":
            nodes_text += f"""
## ─── Exit Node #{i+1} ({lbl}, xHTTP TLS) ──
Адрес:      {nd['host']}
Порт:       {nd['port']}
UUID:       {nd['uuid']}
xHTTP mode: {nd.get('xhttp_mode', 'streamup')}
xHTTP path: {nd.get('path', '/')}
SNI:        {nd.get('sni', '')}
FP:         {nd.get('fp', 'chrome')}
"""
        else:
            nodes_text += f"""
## ─── Exit Node #{i+1} ({lbl}, VLESS+REALITY) ──
Адрес:      {nd['host']}
Порт:       {nd['port']}
UUID:       {nd['uuid']}
PublicKey:  {nd.get('pubkey', '')}
ShortID:    {nd.get('shortid', '')}
SNI:        {nd.get('sni', '')}
Flow:       xtls-rprx-vision
FP:         {nd.get('fp', 'chrome')}
"""

    scp_cmds = "\n".join(
        f"   scp /root/xray_config_exit_node_{i+1}.json root@{nd['host']}:/etc/xray/config.json"
        for i, nd in enumerate(nodes)
    ) if nodes else "   (нет нод)"
    balancer_note = (
        f"\nПримечание: при нескольких Exit Node трафик распределяется"
        f" между ними по алгоритму {strategy_label} (Xray balancer)."
        if len(nodes) > 1 else ""
    )
    proto = PROTOCOL_MODE
    entry_proto_str = (
        f"xHTTP TLS (mode={XHTTP_MODE}, path={XHTTP_PATH})"
        if proto == "xhttp"
        else "VLESS+TCP+REALITY (xtls-rprx-vision)"
    )

    summary = f"""# ═══════════════════════════════════════════════════════
# VLESS — Режим B (Chained Proxy / Каскад)
# Схема: Клиент → Entry VPS (RU) → Exit VPS × {len(nodes)} → Интернет
# ═══════════════════════════════════════════════════════
{balancer_note}
## ─── Entry Node (российский VPS) ───────────────────────
Адрес:      {entry_host}
Порт:       {SERVER_PORT}
UUID:       {PARAM_UUID}
Протокол:   {entry_proto_str}
PublicKey:  {PARAM_PUBLIC_KEY if proto == 'reality' else 'n/a (xHTTP TLS)'}
ShortID:    {PARAM_SHORTID if proto == 'reality' else 'n/a (xHTTP TLS)'}
SNI:        {PARAM_REALITY_DEST if (AWG_EXIT_ENABLED and PARAM_REALITY_DEST) else PARAM_DOMAIN}
{nodes_text}
## ─── Клиентская ссылка (подключаться к Entry Node) ─────
{link}

## ─── Файлы ──────────────────────────────────────────────
/etc/xray/config.json              — конфиг Entry Node (уже применён)
/root/xray_config_exit_node_N.json — конфиги Exit Node (скопировать на каждый зарубежный VPS)
/root/vless_link.txt               — клиентская ссылка (Entry Node)
/root/vless_qr_chain.png           — QR-код для подключения клиента

## ─── Инструкция по настройке Exit Node ─────────────────
1. Скопируйте конфиг на каждый зарубежный VPS:
{scp_cmds}

2. На каждом зарубежном VPS сгенерируйте ключи REALITY:
   xray x25519

3. Запишите PrivateKey в /etc/xray/config.json (заменить <ВСТАВЬТЕ_PRIVATE_KEY_EXIT_NODE>).

4. Откройте нужный порт на каждом зарубежном VPS:
   ufw allow <PORT>/tcp

5. Перезапустите Xray на каждом зарубежном VPS:
   systemctl restart xray

6. Клиент подключается ТОЛЬКО к Entry Node (российскому VPS) по ссылке выше.
   Распределение по Exit Node происходит автоматически на стороне Entry Node.
"""

    summary_path = Path("/root/vless_chain_summary.txt")
    summary_path.write_text(summary)
    summary_path.chmod(0o600)
    success(f"Сводка Режима B ({n_label}): {summary_path}")

    # Записываем клиентскую ссылку
    link_path = Path("/root/vless_link.txt")
    link_path.write_text(link)
    link_path.chmod(0o600)

    # Консольный вывод
    print()
    n_title = f"РЕЖИМ B: КАСКАДНЫЙ ПРОКСИ — {n_label.upper()}"
    _box_top(n_title)
    if len(nodes) > 1:
        _box_row(f"  Схема: Клиент → {CYAN}Entry RU{NC} → {GREEN}[{strategy_label}]{NC} → {GREEN}Exit ×{len(nodes)}{NC} → Интернет")
    else:
        _box_row(f"  Схема: Клиент → {CYAN}Entry RU{NC} → {GREEN}Exit Abroad{NC} → Интернет")
    _box_row()
    _box_row(f"  {YELLOW}Entry Node (этот сервер, RU):{NC}")
    _box_row(f"    Адрес:   {CYAN}{entry_host}:{SERVER_PORT}{NC}")
    _box_row(f"    UUID:    {CYAN}{PARAM_UUID}{NC}")
    _box_row(f"    PubKey:  {CYAN}{PARAM_PUBLIC_KEY[:30]}...{NC}")
    _box_row(f"    ShortID: {CYAN}{PARAM_SHORTID}{NC}")
    _sni_display = PARAM_REALITY_DEST if (AWG_EXIT_ENABLED and PARAM_REALITY_DEST) else PARAM_DOMAIN
    _box_row(f"    SNI:     {CYAN}{_sni_display}{NC}")
    for i, nd in enumerate(nodes):
        _box_row()
        lbl = f"Exit Node #{i+1}" if len(nodes) > 1 else "Exit Node"
        _box_row(f"  {GREEN}{lbl}:{NC}")
        _box_row(f"    Host:    {CYAN}{nd['host']}:{nd['port']}{NC}")
        _box_row(f"    UUID:    {CYAN}{nd['uuid']}{NC}")
        _box_row(f"    SNI:     {CYAN}{nd['sni']}{NC}")
    _box_sep()
    print(f"  {MAGENTA}Клиентская ссылка (Entry Node):{NC}")
    _box_link(link)
    print()
    _box_top(f"Файлы")
    # Определяем самый длинный путь для правильного выравнивания
    _has_multi_nodes = len(nodes) > 1
    _max_path_w = len("/root/xray_config_exit_node_1.json") if _has_multi_nodes else len("/root/xray_config_exit_node.json")
    _col_w = max(_max_path_w, len("/root/vless_chain_summary.txt"))
    _box_row(f"    {'/root/vless_link.txt':<{_col_w}}  — клиентская ссылка")
    _box_row(f"    {'/root/vless_qr_chain.png':<{_col_w}}  — QR-код для клиента")
    for i in range(len(nodes)):
        suffix = f"_{i+1}" if _has_multi_nodes else ""
        _path = f"/root/xray_config_exit_node{suffix}.json"
        _box_row(f"    {_path:<{_col_w}}  — конфиг Exit Node #{i+1}")
    _box_row(f"    {'/root/vless_chain_summary.txt':<{_col_w}}  — полная инструкция")
    _box_bottom()
    _show_qr(link, f"{entry_host}-chain", "/root/vless_qr_chain.png")


# =============================================================================
#  ШАГ 1: ЗАВИСИМОСТИ
# =============================================================================
def install_dependencies() -> None:
    """
    Все пакеты и зависимости уже были проверены и установлены при старте
    скрипта функцией ensure_startup_dependencies(). Здесь — только действия,
    специфичные для шага полной установки: активация nginx как сервиса.
    """
    info("Зависимости: все пакеты уже проверены при старте скрипта")
    PROGRESS.update(2, "Зависимости")

    # Активируем и запускаем nginx (он нужен для следующих шагов установки)
    _run(["systemctl", "enable", "nginx"], check=False, quiet=True)
    _run(["systemctl", "start",  "nginx"], check=False, quiet=True)

    PROGRESS.update(3, "Зависимости")
    success("Зависимости готовы")

# (DNSCrypt — _get_dnscrypt_port, install_dnscrypt, apply_dnscrypt_tuning —
#  вынесены в vless_installer.modules.dnscrypt_setup; импорт — в верхней
#  секции этого файла.)

# (Сеть / файрволл / sysctl — configure_firewall, apply_network_optimizations —
#  вынесены в vless_installer.modules.network_setup; импорт — в верхней
#  секции этого файла.)

# =============================================================================
#  ШАГ 4: УСТАНОВКА XRAY + SHA256
# =============================================================================
# (Xray install/update/geo/config — _verify_sha256, _xray_print_manual_download_hint,
#  _xray_try_local_zip, install_xray, _parse_x25519_keys/field, generate_reality_keys,
#  _detect_xhttp_mode_support, generate_xray_config, generate_xray_config_xhttp,
#  create_xray_service, _xray_get_release_info, _xray_version_norm/current_version,
#  _xray_geo_is_runetfreedom, _geo_print_manual_download_hint,
#  _xray_update_geo_runetfreedom, _xray_do_upgrade, _xray_restart_all_services,
#  _nginx_restart_if_reality, _xray_find_config, _xray_config_rollback,
#  _xray_safe_apply_config, _xray_rollback, do_xray_update_interactive,
#  setup_xray_autoupdate, _install_autoupdate_service — вынесены в
#  vless_installer.modules.xray_install; импорт — в верхней секции этого файла.)


# =============================================================================
#  УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ
# =============================================================================
def _fp_from_state() -> str:
    """Возвращает fingerprint из state.json (или глобального PARAM_FINGERPRINT).

    Используется при генерации ссылок постфактум (добавление пользователей,
    вывод ссылок), когда PARAM_FINGERPRINT может быть не заполнен (например,
    при запуске installer.py не в режиме установки).
    """
    if PARAM_FINGERPRINT:
        return PARAM_FINGERPRINT
    try:
        _st = json.loads(STATE_FILE.read_text())
        return _st.get("fingerprint", "chrome") or "chrome"
    except Exception:
        return "chrome"


# (_users_get_config, _users_apply_config, _users_gen_link, do_user_list,
#  do_user_add, do_user_delete, do_user_show_link, do_user_menu, _show_qr,
#  _gen_vless_link, generate_client_links — вынесены в
#  vless_installer.modules.users_manager; импорт — в верхней секции этого файла.)


# =============================================================================
#  УДАЛЕНИЕ
# =============================================================================
# (do_uninstall вынесен в vless_installer.modules.uninstall;
#  импорт — в верхней секции этого файла.)


# (Split tunnel — prompt_split_tunnel, _save/_load_split_tunnel_custom,
#  build_split_tunnel_routing_rules, _xray_count_ru_subnet_rules,
#  _show_xray_routing_rules, do_manage_split_tunnel,
#  _apply_split_tunnel_config_from_state — вынесены в
#  vless_installer.modules.split_tunnel; импорт — в верхней секции этого файла.)


# (download_geo_files, setup_geo_autoupdate вынесены в
#  vless_installer.modules.geo_files; импорт — в верхней секции этого файла.)


def setup_logrotate() -> None:
    """
    Настраивает logrotate для /var/log/xray/*.log и вспомогательных логов.

    Стратегия:
      - Ежедневная ротация (daily) — предотвращает разрастание access.log,
        который при loglevel=info может генерировать сотни МБ в сутки.
      - Хранение 14 архивов (две недели истории) — достаточно для диагностики.
      - Сжатие через gzip (compress + delaycompress) — экономия места в 5–10×.
      - postrotate: сигнал USR1 → Xray переоткрывает файл без перезапуска.
      - Дополнительные конфиги для xray-autoupdate.log и xray-geo-update.log
        с недельной ротацией (rotate 4).
    """
    LOGROTATE_XRAY = Path("/etc/logrotate.d/xray")
    LOGROTATE_XRAY_AUX = Path("/etc/logrotate.d/xray-aux")

    # --- Основной конфиг: access.log + error.log ---
    LOGROTATE_XRAY.write_text(textwrap.dedent("""\
        # Ротация логов Xray-core
        # Создано автоматически установщиком VLESS Ultimate Installer
        /var/log/xray/access.log
        /var/log/xray/error.log {
            daily
            rotate 14
            compress
            delaycompress
            missingok
            notifempty
            create 0640 xray xray
            sharedscripts
            postrotate
                # Сигнал USR1: Xray переоткрывает лог-файл без перезапуска
                systemctl kill -s USR1 xray 2>/dev/null || true
            endscript
        }
    """))
    LOGROTATE_XRAY.chmod(0o644)

    # --- Вспомогательные логи: autoupdate + geo-update ---
    aux_entries: list[str] = []
    if Path("/var/log/xray-autoupdate.log").parent.exists() or True:
        aux_entries.append("/var/log/xray-autoupdate.log")
    if SPLIT_TUNNEL_ENABLED:
        aux_entries.append("/var/log/xray-geo-update.log")

    aux_block = "\n".join(aux_entries)
    LOGROTATE_XRAY_AUX.write_text(textwrap.dedent(f"""\
        # Ротация вспомогательных логов Xray
        # Создано автоматически установщиком VLESS Ultimate Installer
        {aux_block} {{
            weekly
            rotate 4
            compress
            delaycompress
            missingok
            notifempty
            create 0600 root root
        }}
    """))
    LOGROTATE_XRAY_AUX.chmod(0o644)

    # --- ИСПРАВЛЕНИЕ: лог инсталлятора (log_to_file()) и логи cron-модулей
    # (autoban/watchdog) раньше НЕ входили ни в один logrotate-конфиг, хотя
    # меню "Ротация логов" в logrotate.py показывало их размер, создавая
    # ложное впечатление, что они под ротацией. vless-install.log пишется
    # непрерывно (info()/success()/warn() на каждое действие) и без ротации
    # рос неограниченно вплоть до полного заполнения диска. Здесь — daily +
    # maxsize как аварийный триггер (если между суточными прогонами
    # logrotate файл распухнет раньше срока, ротация всё равно сработает).
    LOGROTATE_XRAY_HEAVY = Path("/etc/logrotate.d/xray-heavy")
    heavy_entries = [
        "/var/log/vless-install.log",
        "/var/log/xray-autoban.log",
        "/var/log/xray-watchdog.log",
    ]
    heavy_block = "\n".join(heavy_entries)
    LOGROTATE_XRAY_HEAVY.write_text(textwrap.dedent(f"""\
        # Лог инсталлятора и cron-модулей (autoban/watchdog)
        # Создано автоматически установщиком VLESS Ultimate Installer
        # missingok — не все три файла обязательно существуют на любой системе
        {heavy_block} {{
            daily
            rotate 14
            compress
            delaycompress
            missingok
            notifempty
            maxsize 50M
            create 0600 root root
        }}
    """))
    LOGROTATE_XRAY_HEAVY.chmod(0o644)

    # Проверяем синтаксис (не фатально — logrotate сам сообщит об ошибке)
    r = _run(["logrotate", "--debug", str(LOGROTATE_XRAY)],
             check=False, quiet=True)
    if r.returncode != 0:
        warn("logrotate: проверьте конфиг вручную: /etc/logrotate.d/xray")
    else:
        success("logrotate настроен: /etc/logrotate.d/xray (daily, 14 дней, gzip)")
    r2 = _run(["logrotate", "--debug", str(LOGROTATE_XRAY_HEAVY)],
              check=False, quiet=True)
    if r2.returncode != 0:
        warn("logrotate: проверьте конфиг вручную: /etc/logrotate.d/xray-heavy")
    dim("  access.log + error.log: ежедневно, 14 архивов")
    dim("  autoupdate/geo-update:  еженедельно, 4 архива")
    dim("  vless-install/autoban/watchdog: ежедневно, 14 архивов, maxsize 50M")


# =============================================================================
#  ПОЛНАЯ УСТАНОВКА
# =============================================================================
def _wait_service_active(svc: str, max_sec: int = 30, silent: bool = False) -> bool:
    """Ждёт активации сервиса. silent=True подавляет прямой вывод (для вызовов внутри рамки)."""
    for i in range(1, max_sec + 1):
        r = _run(["systemctl", "is-active", svc], capture=True, check=False)
        if r.stdout.strip() == "active":
            if not silent:
                success(f"  ✓ {svc} активен ({i}с)")
            log_to_file("SUCCESS", f"{svc} активен ({i}с)")
            return True
        r2 = _run(["systemctl", "is-failed", svc], capture=True, check=False)
        if r2.stdout.strip() == "failed":
            if not silent:
                warn(f"  ✗ {svc} перешёл в failed")
            log_to_file("WARN", f"{svc} перешёл в failed")
            try:
                logs = _run(["journalctl", "-u", svc, "-n", "15", "--no-pager"],
                            capture=True, check=False).stdout
                log_to_file("WARN", logs[-2000:])
            except Exception:
                pass
            return False
        time.sleep(1)
    if not silent:
        warn(f"  ✗ {svc} не запустился за {max_sec}с")
    log_to_file("WARN", f"{svc} не запустился за {max_sec}с")
    return False



# =============================================================================
#  AWG 2.0 (AmneziaWG) — ПОЛНАЯ УСТАНОВКА И НАСТРОЙКА
# =============================================================================

_AWG_CONF_DIR        = Path("/etc/amnezia/amneziawg")
_AWG_SERVER_CONF     = _AWG_CONF_DIR / "awg0.conf"          # серверный конфиг (для exit-VPS)
_AWG_CLIENT_CONF     = _AWG_CONF_DIR / "awg0-client.conf"   # клиентский конфиг (RU-VPS)
_AWG_ACTIVE_CONF     = _AWG_CONF_DIR / "awg0.conf"          # используется awg-quick на RU
_AWG_REMOTE_CONF_PATH = "/etc/amnezia/amneziawg/awg0.conf"


def awg_check_tool(binary: str) -> bool:
    """Проверяет наличие бинарника AWG в PATH."""
    return shutil.which(binary) is not None


def awg_generate_keys() -> bool:
    """
    Генерирует пары ключей сервера и клиента + pre-shared key.
    Заполняет глобальные AWG_*_PRIVKEY, AWG_*_PUBKEY, AWG_PRESHARED_KEY.
    Возвращает True при успехе.
    """
    global AWG_SERVER_PRIVKEY, AWG_SERVER_PUBKEY
    global AWG_CLIENT_PRIVKEY, AWG_CLIENT_PUBKEY, AWG_PRESHARED_KEY

    info("AWG: генерация ключей...")

    awg_bin = AWG_BIN if awg_check_tool(AWG_BIN) else ("wg" if awg_check_tool("wg") else None)
    if not awg_bin:
        warn("AWG: бинарник awg/wg не найден — генерация ключей невозможна")
        return False

    def _genkey() -> tuple[str, str]:
        priv_r = _run([awg_bin, "genkey"], capture=True, check=False)
        if priv_r.returncode != 0:
            raise RuntimeError(f"{awg_bin} genkey: {priv_r.stderr}")
        priv = priv_r.stdout.strip()
        pub_r = subprocess.run(
            [awg_bin, "pubkey"],
            input=priv, capture_output=True, text=True
        )
        if pub_r.returncode != 0:
            raise RuntimeError(f"{awg_bin} pubkey: {pub_r.stderr}")
        return priv, pub_r.stdout.strip()

    try:
        AWG_SERVER_PRIVKEY, AWG_SERVER_PUBKEY = _genkey()
        AWG_CLIENT_PRIVKEY, AWG_CLIENT_PUBKEY = _genkey()
        psk_r = _run([awg_bin, "genpsk"], capture=True, check=False)
        if psk_r.returncode != 0:
            raise RuntimeError(f"{awg_bin} genpsk: {psk_r.stderr}")
        AWG_PRESHARED_KEY = psk_r.stdout.strip()
        success(f"AWG: server pubkey = {AWG_SERVER_PUBKEY[:20]}...")
        success(f"AWG: client pubkey = {AWG_CLIENT_PUBKEY[:20]}...")
        return True
    except Exception as exc:
        warn(f"AWG: ошибка генерации ключей: {exc}")
        log_to_file("ERROR", f"awg_generate_keys: {exc}")
        return False


def awg_install_local() -> bool:
    """
    Устанавливает amneziawg-tools на локальный (RU) VPS.
    ПАТЧ: На Ubuntu 24.04 / ядро 6.x PPA недоступен с RU-серверов и DKMS не работает.
    Используем: 1) zip с GitHub releases, 2) сборка amneziawg-go из исходников.
    """
    info("AWG: установка amneziawg-tools на RU-VPS...")

    if awg_check_tool(AWG_BIN) and awg_check_tool(AWG_QUICK_BIN):
        success("AWG: инструменты уже установлены")
        return True

    # Шаг 1: пробуем скачать готовые бинарники с GitHub releases
    # ПАТЧ: определяем архитектуру — ubuntu-22.04 совместимы с 24.04 для amd64;
    # для arm64 используем отдельный asset. Захардкоженный amd64 ломает ARM VPS.
    info("AWG: загрузка amneziawg-tools с GitHub releases...")
    _run(["apt-get", "install", "-y", "-q", "curl", "unzip"], check=False, quiet=True)
    _awg_arch_raw = _run(["uname", "-m"], capture=True, check=False).stdout.strip()
    if _awg_arch_raw == "x86_64":
        _awg_zip_suffix = "ubuntu-22.04-amneziawg-tools.zip"
    elif _awg_arch_raw == "aarch64":
        _awg_zip_suffix = "ubuntu-22.04-arm64-amneziawg-tools.zip"
    else:
        warn(f"AWG: неподдерживаемая архитектура {_awg_arch_raw} — переходим к сборке из исходников")
        _awg_zip_suffix = ""
    try:
        r_tag = _run(
            ["curl", "-fsSL", "--connect-timeout", "15",
             "https://api.github.com/repos/amnezia-vpn/amneziawg-tools/releases/latest"],
            capture=True, check=False
        )
        import json as _json
        tag = _json.loads(r_tag.stdout).get("tag_name", "")
        if tag and _awg_zip_suffix:
            zip_url = (f"https://github.com/amnezia-vpn/amneziawg-tools/releases/download/"
                       f"{tag}/{_awg_zip_suffix}")
            zip_tmp = Path("/tmp/awg-tools.zip")
            r_dl = _run(
                ["curl", "-fsSL", "--connect-timeout", "30", "--retry", "3",
                 zip_url, "-o", str(zip_tmp)],
                check=False, quiet=True
            )
            if r_dl.returncode == 0 and zip_tmp.exists() and zip_tmp.stat().st_size > 1000:
                extract_dir = Path("/tmp/awg-tools-extracted")
                extract_dir.mkdir(exist_ok=True)
                _run(["unzip", "-o", str(zip_tmp), "-d", str(extract_dir)],
                     check=False, quiet=True)
                # Ищем бинарники в извлечённой директории
                for sub in [extract_dir] + list(extract_dir.iterdir()):
                    awg_bin = sub / "awg" if sub.is_dir() else None
                    awg_quick_bin = sub / "awg-quick" if sub.is_dir() else None
                    if awg_bin and awg_bin.exists() and awg_quick_bin and awg_quick_bin.exists():
                        import shutil as _shutil
                        _shutil.copy2(str(awg_bin), "/usr/local/bin/awg")
                        _shutil.copy2(str(awg_quick_bin), "/usr/local/bin/awg-quick")
                        os.chmod("/usr/local/bin/awg", 0o755)
                        os.chmod("/usr/local/bin/awg-quick", 0o755)
                        zip_tmp.unlink(missing_ok=True)
                        success(f"AWG: amneziawg-tools установлены из GitHub releases ({tag})")
                        break
                zip_tmp.unlink(missing_ok=True)
    except Exception as exc:
        warn(f"AWG: не удалось загрузить из GitHub releases: {exc}")

    if awg_check_tool(AWG_BIN) and awg_check_tool(AWG_QUICK_BIN):
        # Бинарники есть — теперь нужен amneziawg-go для userspace режима
        return _awg_install_go_version_binary_only()

    # Шаг 2: полная сборка amneziawg-go (включает awg и awg-quick как stubs)
    warn("AWG: GitHub releases недоступны — собираем amneziawg-go из исходников...")
    return _awg_install_go_version()


def _awg_install_go_version_binary_only() -> bool:
    """Устанавливает только amneziawg-go (userspace бинарник) без stub-обёрток awg/awg-quick."""
    info("AWG: сборка amneziawg-go (userspace модуль ядра)...")
    _run(["apt-get", "install", "-y", "-q", "git", "make", "golang-go"],
         check=False, quiet=True)
    if not shutil.which("go"):
        warn("AWG: Go не доступен — userspace режим недоступен")
        return awg_check_tool(AWG_BIN)  # бинарники уже есть, продолжаем

    awg_go_bin = Path("/usr/local/bin/amneziawg-go")
    if awg_go_bin.exists():
        success("AWG: amneziawg-go уже установлен")
        return True

    build_dir = Path("/tmp/awg-go-build")
    build_dir.mkdir(exist_ok=True)
    src = build_dir / "amneziawg-go"
    r_clone = _run(
        ["git", "clone", "--depth=1",
         "https://github.com/amnezia-vpn/amneziawg-go.git", str(src)],
        check=False, quiet=True
    )
    if r_clone.returncode != 0 or not src.exists():
        warn("AWG: не удалось клонировать amneziawg-go")
        return awg_check_tool(AWG_BIN)
    r_make = _run(["make"], check=False, quiet=True, cwd=str(src),
                  env={**os.environ, "HOME": str(Path.home())})
    bin_path = src / "amneziawg-go"
    if bin_path.exists():
        shutil.copy2(str(bin_path), str(awg_go_bin))
        os.chmod(str(awg_go_bin), 0o755)
        success("AWG: amneziawg-go установлен (userspace)")
        shutil.rmtree(str(build_dir), ignore_errors=True)
        return True
    warn(f"AWG: сборка amneziawg-go не удалась (rc={r_make.returncode})")
    shutil.rmtree(str(build_dir), ignore_errors=True)
    return awg_check_tool(AWG_BIN)


def _awg_install_go_version() -> bool:
    """Fallback: устанавливает userspace amneziawg-go через go build + stub-обёртки awg/awg-quick."""
    info("AWG: попытка установки userspace amneziawg-go...")
    _run(["apt-get", "install", "-y", "-q", "git", "make", "golang-go"],
         check=False, quiet=True)

    if not shutil.which("go"):
        warn("AWG: Go не доступен — невозможно собрать amneziawg-go")
        return False

    # Используем постоянную директорию вместо tempdir — make падает в /tmp с некоторыми настройками
    build_dir = Path("/tmp/awg-go-build")
    build_dir.mkdir(exist_ok=True)
    src = build_dir / "amneziawg-go"
    try:
        r_clone = _run(
            ["git", "clone", "--depth=1",
             "https://github.com/amnezia-vpn/amneziawg-go.git", str(src)],
            check=False, quiet=True
        )
        if r_clone.returncode != 0 or not src.exists():
            warn("AWG: не удалось клонировать amneziawg-go")
            return False
        # ВАЖНО: передаём cwd=src чтобы make работал в правильной директории
        r_make = _run(["make"], check=False, quiet=True, cwd=str(src),
                      env={**os.environ, "HOME": str(Path.home())})
        bin_path = src / "amneziawg-go"
        if bin_path.exists():
            shutil.copy2(str(bin_path), "/usr/local/bin/amneziawg-go")
            os.chmod("/usr/local/bin/amneziawg-go", 0o755)
            _awg_create_userspace_stubs()
            success("AWG: amneziawg-go установлен (userspace режим)")
            shutil.rmtree(str(build_dir), ignore_errors=True)
            return True
        warn(f"AWG: сборка amneziawg-go не удалась (rc={r_make.returncode})")
        shutil.rmtree(str(build_dir), ignore_errors=True)
        return False
    except Exception as exc:
        warn(f"AWG: ошибка сборки amneziawg-go: {exc}")
        shutil.rmtree(str(build_dir), ignore_errors=True)
        return False


def _awg_detect_implementation() -> str:
    """
    Автоматически определяет доступность модуля ядра amnezia-wg/amneziawg
    и возвращает путь к userspace-реализации (amneziawg-go) или пустую
    строку если модуль ядра загружен и работает.

    Логика выбора:
      1. Если модуль amneziawg/amnezia-wg загружен (lsmod) → ядро, возврат ""
      2. Если можно создать тестовый интерфейс type amneziawg → ядро, возврат ""
      3. Если amneziawg-go доступен → userspace, возврат пути к бинарю
      4. Иначе → userspace как fallback (пустая строка, awg-quick сам разберётся)

    Возвращает строку для подстановки в:
      WG_QUICK_USERSPACE_IMPLEMENTATION=<result>
    Если возвращает "" — переменную не нужно выставлять (ядро само обработает).
    """
    # Шаг 1: проверяем lsmod
    _r_lsmod = _run(["lsmod"], capture=True, check=False)
    _lsmod_out = (_r_lsmod.stdout or "").lower()
    if "amneziawg" in _lsmod_out or "amnezia_wg" in _lsmod_out or "amnezia-wg" in _lsmod_out:
        log_to_file("INFO", "AWG impl: kernel module loaded (lsmod)")
        return ""

    # Шаг 2: пробуем создать тестовый интерфейс
    _test_iface = "awg_probe_tmp0"
    _r_add = _run(
        ["ip", "link", "add", _test_iface, "type", "amneziawg"],
        capture=True, check=False
    )
    if _r_add.returncode == 0:
        _run(["ip", "link", "delete", _test_iface], check=False, quiet=True)
        log_to_file("INFO", "AWG impl: kernel module available (ip link probe)")
        return ""

    # Шаг 3: модуля нет — ищем amneziawg-go
    _go_candidates = [
        "/usr/local/bin/amneziawg-go",
        "/usr/bin/amneziawg-go",
    ]
    for _gc in _go_candidates:
        if Path(_gc).exists() and os.access(_gc, os.X_OK):
            log_to_file("INFO", f"AWG impl: userspace amneziawg-go at {_gc}")
            return _gc

    # Шаг 4: пробуем загрузить модуль принудительно
    for _mod in ("amneziawg", "amnezia-wg", "wireguard"):
        _r_mp = _run(["modprobe", _mod], capture=True, check=False)
        if _r_mp.returncode == 0:
            log_to_file("INFO", f"AWG impl: kernel module loaded via modprobe {_mod}")
            return ""

    # Ничего не найдено — возвращаем путь по умолчанию как fallback
    log_to_file("WARN", "AWG impl: neither kernel module nor amneziawg-go found, using default path")
    return "/usr/local/bin/amneziawg-go"


def _awg_create_userspace_stubs() -> None:
    """Создаёт stub-обёртки awg и awg-quick для userspace режима."""
    stub_awg = (
        "#!/bin/bash\n"
        "exec /usr/local/bin/amneziawg-go \"$@\"\n"
    )
    stub_quick = (
        "#!/bin/bash\n"
        "set -e\n"
        "IFACE=\"$2\"\n"
        "CONF=\"/etc/amnezia/amneziawg/${IFACE}.conf\"\n"
        "case \"$1\" in\n"
        "  up)\n"
        "    /usr/local/bin/amneziawg-go \"$IFACE\" &\n"
        "    sleep 1\n"
        "    ip link set \"$IFACE\" up\n"
        "    awg setconf \"$IFACE\" \"$CONF\"\n"
        "    ;;\n"
        "  down)\n"
        "    ip link delete \"$IFACE\" 2>/dev/null || true\n"
        "    ;;\n"
        "esac\n"
    )
    for path, body in [
        ("/usr/local/bin/awg",       stub_awg),
        ("/usr/local/bin/awg-quick", stub_quick),
    ]:
        Path(path).write_text(body.replace("\\n", "\n").replace('\"', '"'))
        os.chmod(path, 0o755)


def _awg_server_conf_text() -> str:
    """Формирует текст конфига AWG-сервера (для exit-VPS). Dual-Stack IPv4+IPv6."""
    default_iface_cmd = "$(ip route | awk '/default/ {print $5; exit}')"
    return (
        f"[Interface]\n"
        f"PrivateKey = {AWG_SERVER_PRIVKEY}\n"
        f"Address = {AWG_SERVER_IP}, {AWG_SERVER_IPv6}\n"
        f"ListenPort = {AWG_EXIT_PORT}\n"
        f"MTU = {AWG_MTU}\n"
        f"Jc = {AWG_JC}\n"
        f"Jmin = {AWG_JMIN}\n"
        f"Jmax = {AWG_JMAX}\n"
        f"S1 = {AWG_S1}\n"
        f"S2 = {AWG_S2}\n"
        f"H1 = {AWG_H1}\n"
        f"H2 = {AWG_H2}\n"
        f"H3 = {AWG_H3}\n"
        f"H4 = {AWG_H4}\n"
        f"PostUp = iptables -A FORWARD -i awg0 -j ACCEPT; "
        f"iptables -A FORWARD -o awg0 -j ACCEPT; "
        f"iptables -t nat -A POSTROUTING -o {default_iface_cmd} -j MASQUERADE; "
        f"ip6tables -A FORWARD -i awg0 -j ACCEPT; "
        f"ip6tables -A FORWARD -o awg0 -j ACCEPT; "
        f"ip6tables -t nat -A POSTROUTING -o {default_iface_cmd} -j MASQUERADE\n"
        f"PostDown = iptables -D FORWARD -i awg0 -j ACCEPT; "
        f"iptables -D FORWARD -o awg0 -j ACCEPT; "
        f"iptables -t nat -D POSTROUTING -o {default_iface_cmd} -j MASQUERADE; "
        f"ip6tables -D FORWARD -i awg0 -j ACCEPT; "
        f"ip6tables -D FORWARD -o awg0 -j ACCEPT; "
        f"ip6tables -t nat -D POSTROUTING -o {default_iface_cmd} -j MASQUERADE\n"
        f"\n"
        f"[Peer]\n"
        f"# RU-VPS (Xray client)\n"
        f"PublicKey = {AWG_CLIENT_PUBKEY}\n"
        f"PresharedKey = {AWG_PRESHARED_KEY}\n"
        f"AllowedIPs = {AWG_CLIENT_IP}, {AWG_CLIENT_IPv6}\n"
    )


def _awg_client_conf_text() -> str:
    """Формирует текст конфига AWG-клиента (для RU-VPS). Dual-Stack IPv4+IPv6."""
    return (
        f"[Interface]\n"
        f"PrivateKey = {AWG_CLIENT_PRIVKEY}\n"
        f"Address = {AWG_CLIENT_IP}, {AWG_CLIENT_IPv6}\n"
        f"ListenPort = {AWG_CLIENT_LISTEN_PORT}\n"
        f"MTU = {AWG_MTU}\n"
        f"Jc = {AWG_JC}\n"
        f"Jmin = {AWG_JMIN}\n"
        f"Jmax = {AWG_JMAX}\n"
        f"S1 = {AWG_S1}\n"
        f"S2 = {AWG_S2}\n"
        f"H1 = {AWG_H1}\n"
        f"H2 = {AWG_H2}\n"
        f"H3 = {AWG_H3}\n"
        f"H4 = {AWG_H4}\n"
        f"DNS = 1.1.1.1, 8.8.8.8, 2606:4700:4700::1111\n"
        f"Table = off\n"
        f"\n"
        f"[Peer]\n"
        f"# Зарубежный VPS (AWG-сервер)\n"
        f"PublicKey = {AWG_SERVER_PUBKEY}\n"
        f"PresharedKey = {AWG_PRESHARED_KEY}\n"
        f"Endpoint = {AWG_EXIT_HOST}:{AWG_EXIT_PORT}\n"
        f"AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"PersistentKeepalive = 25\n"
    )


def _awg_systemd_unit_text(xray_uid: int) -> str:
    """Формирует текст systemd unit для AWG-клиента."""
    pr_up = (
        # ── IPv4 policy routing ────────────────────────────────────────────────
        # ip rule — policy routing fwmark (idempotent)
        f"ip rule show | grep -q 'fwmark {AWG_FWMARK}' || "
        f"ip rule add fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE} priority 100 2>/dev/null || true; "
        # ip route в таблице AWG (idempotent)
        f"ip route show table {AWG_ROUTE_TABLE} | grep -q default || "
        f"ip route add default dev {AWG_INTERFACE} table {AWG_ROUTE_TABLE} 2>/dev/null || true; "
        # iptables OUTPUT mark (idempotent через -C)
        f"iptables -t mangle -C OUTPUT -m owner --uid-owner {xray_uid} "
        f"-j MARK --set-mark {AWG_FWMARK} 2>/dev/null || "
        f"iptables -t mangle -A OUTPUT -m owner --uid-owner {xray_uid} "
        f"-j MARK --set-mark {AWG_FWMARK} 2>/dev/null || true; "
        # ИСПРАВЛЕНИЕ: маркируем трафик dnscrypt-proxy (uid dnscrypt) тем же fwmark.
        # dnscrypt-proxy делает исходящие соединения к DNS upstream — они должны
        # идти через AWG, иначе провайдер блокирует DoT/DNSCrypt на порту 443.
        f"DC_UID=$(id -u dnscrypt 2>/dev/null); "
        f"[ -n \"$DC_UID\" ] && ("
        f"iptables -t mangle -C OUTPUT -m owner --uid-owner \"$DC_UID\" "
        f"-j MARK --set-mark {AWG_FWMARK} 2>/dev/null || "
        f"iptables -t mangle -A OUTPUT -m owner --uid-owner \"$DC_UID\" "
        f"-j MARK --set-mark {AWG_FWMARK} 2>/dev/null || true"
        f") || true; "
        # iptables FORWARD MSS clamp (idempotent через -C)
        f"iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN "
        f"-j TCPMSS --set-mss {AWG_MTU - 40} 2>/dev/null || "
        f"iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN "
        f"-j TCPMSS --set-mss {AWG_MTU - 40} 2>/dev/null || true; "
        # sysctl rp_filter
        f"sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1; "
        f"sysctl -w net.ipv4.conf.{AWG_INTERFACE}.rp_filter=0 >/dev/null 2>&1; "
        # ── IPv6 policy routing (применяем если IPv6-стек доступен) ───────────
        f"ip -6 route show 2>/dev/null | grep -q . && ("
        # ip6 rule fwmark (idempotent)
        f"ip -6 rule show | grep -q 'fwmark {AWG_FWMARK}' || "
        f"ip -6 rule add fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE} priority 100 2>/dev/null || true; "
        # ip6 route default через awg0 (idempotent)
        f"ip -6 route show table {AWG_ROUTE_TABLE} 2>/dev/null | grep -q default || "
        f"ip -6 route add default dev {AWG_INTERFACE} table {AWG_ROUTE_TABLE} 2>/dev/null || true; "
        # ip6tables OUTPUT mangle mark (idempotent через -C)
        f"ip6tables -t mangle -C OUTPUT -m owner --uid-owner {xray_uid} "
        f"-j MARK --set-mark {AWG_FWMARK} 2>/dev/null || "
        f"ip6tables -t mangle -A OUTPUT -m owner --uid-owner {xray_uid} "
        f"-j MARK --set-mark {AWG_FWMARK} 2>/dev/null || true; "
        # ip6tables FORWARD MSS clamp (idempotent через -C)
        f"ip6tables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN "
        f"-j TCPMSS --set-mss {AWG_MTU - 40} 2>/dev/null || "
        f"ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN "
        f"-j TCPMSS --set-mss {AWG_MTU - 40} 2>/dev/null || true; "
        # ip6tables FORWARD ACCEPT (idempotent через -C)
        f"ip6tables -C FORWARD -i {AWG_INTERFACE} -j ACCEPT 2>/dev/null || "
        f"ip6tables -A FORWARD -i {AWG_INTERFACE} -j ACCEPT 2>/dev/null || true; "
        f"ip6tables -C FORWARD -o {AWG_INTERFACE} -j ACCEPT 2>/dev/null || "
        f"ip6tables -A FORWARD -o {AWG_INTERFACE} -j ACCEPT 2>/dev/null || true; "
        # ip6tables NAT MASQUERADE (idempotent через проверку)
        f"IFACE6=$(ip -6 route | awk '/default/ {{print $5; exit}}'); "
        f"[ -n \"$IFACE6\" ] && ("
        f"ip6tables -t nat -C POSTROUTING -o \"$IFACE6\" -j MASQUERADE 2>/dev/null || "
        f"ip6tables -t nat -A POSTROUTING -o \"$IFACE6\" -j MASQUERADE 2>/dev/null || true"
        f") || true"
        f") || true"
    )
    pr_down = (
        # ── IPv4 cleanup ───────────────────────────────────────────────────────
        f"ip route del default dev {AWG_INTERFACE} table {AWG_ROUTE_TABLE} 2>/dev/null || true; "
        f"ip rule del fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE} 2>/dev/null || true; "
        f"iptables -t mangle -D OUTPUT -m owner --uid-owner {xray_uid} "
        f"-j MARK --set-mark {AWG_FWMARK} 2>/dev/null || true; "
        f"iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN "
        f"-j TCPMSS --set-mss {AWG_MTU - 40} 2>/dev/null || true; "
        # ── IPv6 cleanup (идемпотентно — ошибки игнорируем) ───────────────────
        f"ip -6 route del default dev {AWG_INTERFACE} table {AWG_ROUTE_TABLE} 2>/dev/null || true; "
        f"ip -6 rule del fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE} 2>/dev/null || true; "
        f"ip6tables -t mangle -D OUTPUT -m owner --uid-owner {xray_uid} "
        f"-j MARK --set-mark {AWG_FWMARK} 2>/dev/null || true; "
        f"ip6tables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN "
        f"-j TCPMSS --set-mss {AWG_MTU - 40} 2>/dev/null || true; "
        f"ip6tables -D FORWARD -i {AWG_INTERFACE} -j ACCEPT 2>/dev/null || true; "
        f"ip6tables -D FORWARD -o {AWG_INTERFACE} -j ACCEPT 2>/dev/null || true; "
        f"IFACE6=$(ip -6 route | awk '/default/ {{print $5; exit}}'); "
        f"[ -n \"$IFACE6\" ] && ip6tables -t nat -D POSTROUTING -o \"$IFACE6\" -j MASQUERADE 2>/dev/null || true"
    )
    # АВТООПРЕДЕЛЕНИЕ реализации: если модуль ядра amneziawg доступен —
    # WG_QUICK_USERSPACE_IMPLEMENTATION не нужен (ядро само всё сделает).
    # Если ядра нет — используем amneziawg-go (userspace).
    _awg_impl = _awg_detect_implementation()
    # Строка для Environment= (пустая если ядро)
    _env_line  = f"Environment=WG_QUICK_USERSPACE_IMPLEMENTATION={_awg_impl}\n" if _awg_impl else ""
    # Префикс для ExecStart/ExecStop inline env
    _impl_pfx  = f"WG_QUICK_USERSPACE_IMPLEMENTATION={_awg_impl} " if _awg_impl else ""
    # ExecStartPre: пробуем загрузить модуль ядра; если не выйдет — userspace подхватит
    _pre_modprobe = (
        "lsmod | grep -qiE 'amneziawg|amnezia.wg' || "
        "/sbin/modprobe amneziawg 2>/dev/null || "
        "/sbin/modprobe amnezia-wg 2>/dev/null || "
        "/sbin/modprobe wireguard 2>/dev/null || true"
    )
    return (
        f"[Unit]\n"
        f"Description=AmneziaWG 2.0 client (awg0) + policy routing for Xray\n"
        f"After=network-online.target\n"
        f"Wants=network-online.target\n"
        f"\n"
        f"[Service]\n"
        f"Type=oneshot\n"
        f"RemainAfterExit=yes\n"
        f"{_env_line}"
        f"ExecStartPre=/bin/bash -c '{_pre_modprobe}'\n"
        f"ExecStart=/bin/bash -c 'AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
        f"{_impl_pfx}$AWG_BIN up /etc/amnezia/amneziawg/awg0.conf'\n"
        f"ExecStartPost=/bin/bash -c '{pr_up}'\n"
        f"ExecStop=/bin/bash -c '{pr_down}'\n"
        f"ExecStop=/bin/bash -c 'AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
        f"{_impl_pfx}$AWG_BIN down /etc/amnezia/amneziawg/awg0.conf'\n"
        f"\n"
        f"[Install]\n"
        f"WantedBy=multi-user.target\n"
    )


def ensure_amneziawg_ready(remote_host: str = None, ssh_fn=None) -> None:
    """
    Подготавливает систему к работе с AmneziaWG:
      - Очищает зависшие интерфейсы и сервисы (ЭТАП 0)
      - Проверяет, загружен ли уже модуль ядра (ЭТАП 1)
      - Устанавливает модуль через официальный PPA (ЭТАП 2)
      - Если PPA недоступен — добавляет репозиторий вручную (ЭТАП 3)
      - Финальный fallback: DKMS-сборка из исходников (ЭТАП 4)

    Аргументы:
      remote_host — IP удалённого сервера (str) или None для локального режима.
      ssh_fn      — callable(cmd, capture, check) для удалённых команд.
                    Обязателен если remote_host указан. Передавать _ssh из
                    awg_setup_remote_server() явно, чтобы избежать NameError.

    При неустранимой ошибке бросает Exception, останавливая установку.
    """

    # Метка для логов: показываем, где работаем
    _where = f"[{remote_host}]" if remote_host else "[local]"

    # -------------------------------------------------------------------------
    # Вспомогательная функция: выполнить команду локально или удалённо.
    # Возвращает subprocess.CompletedProcess. capture=True наполняет .stdout.
    # -------------------------------------------------------------------------
    def _exec(cmd: str, check: bool = False, capture: bool = False):
        if remote_host:
            # ssh_fn передаётся явно из awg_setup_remote_server() — нет NameError
            if ssh_fn is None:
                raise RuntimeError(
                    "ensure_amneziawg_ready: remote_host указан, но ssh_fn не передан!"
                )
            return ssh_fn(cmd, capture=capture, check=check)
        else:
            return _run(["bash", "-c", cmd], check=check, capture=capture)

    # =========================================================================
    # ЭТАП 0: ОЧИСТКА — удаляем все следы предыдущих неудачных попыток.
    # Выполняется ВСЕГДА, независимо от состояния модуля.
    # =========================================================================
    info(f"AWG {_where} ЭТАП 0: очистка зависших интерфейсов и сервисов...")

    # Останавливаем все связанные сервисы (ошибки игнорируем — сервиса может не быть)
    _exec(
        "systemctl stop amneziawg-awg0 2>/dev/null || true; "
        "systemctl stop wg-quick@awg0 2>/dev/null || true; "
        "systemctl stop amneziawg-tools 2>/dev/null || true",
        check=False,
    )

    # Удаляем основной интерфейс awg0, если существует
    _exec(
        "ip link show awg0 >/dev/null 2>&1 && ip link delete dev awg0 2>/dev/null || true",
        check=False,
    )

    # Удаляем тестовый интерфейс, если завис с прошлой попытки
    _exec(
        "ip link show test_awg0 >/dev/null 2>&1 && ip link delete dev test_awg0 2>/dev/null || true",
        check=False,
    )

    # Принудительная очистка всех интерфейсов типа amneziawg
    # (может не поддерживаться на старых ядрах — игнорируем ошибку)
    _exec("ip -s link flush type amneziawg 2>/dev/null || true", check=False)

    info(f"AWG {_where}: сетевые интерфейсы очищены")

    # =========================================================================
    # ЭТАП 1: ПРОВЕРКА — может, модуль уже загружен?
    # Сначала lsmod, затем реальный функциональный тест через ip link.
    # =========================================================================
    info(f"AWG {_where} ЭТАП 1: проверка наличия модуля amneziawg в ядре...")

    # Проверка 1а: lsmod
    r_lsmod = _exec(
        "lsmod | grep -q amneziawg && echo LOADED || echo NOT_LOADED",
        capture=True, check=False,
    )
    _lsmod_ok = "LOADED" in (r_lsmod.stdout or "")

    # Проверка 1б: функциональный тест — создаём и сразу удаляем тестовый интерфейс
    r_iftest = _exec(
        "ip link add test_awg0 type amneziawg 2>/dev/null && "
        "ip link delete dev test_awg0 2>/dev/null && echo TYPE_OK || echo TYPE_FAIL",
        capture=True, check=False,
    )
    _type_ok = "TYPE_OK" in (r_iftest.stdout or "")

    if _lsmod_ok and _type_ok:
        success(f"AWG {_where} ЭТАП 1: модуль уже загружен и готов — пропускаем установку")
        return  # Всё хорошо, выходим немедленно

    warn(f"AWG {_where} ЭТАП 1: модуль не обнаружен (lsmod={_lsmod_ok}, iftest={_type_ok})")

    # =========================================================================
    # ЭТАП 2: УСТАНОВКА ЧЕРЕЗ ОФИЦИАЛЬНЫЙ PPA (приоритетная попытка)
    # Использует add-apt-repository ppa:amnezia/ppa
    # =========================================================================
    info(f"AWG {_where} ЭТАП 2: установка через официальный PPA amnezia/ppa...")

    # Устанавливаем зависимости для работы с PPA и сборки модуля ядра
    _exec(
        "export DEBIAN_FRONTEND=noninteractive && "
        "apt-get update -q 2>/dev/null && "
        "apt-get install -y -q "
        "  software-properties-common "
        "  python3-launchpadlib "
        "  gnupg2 "
        "  linux-headers-$(uname -r) "
        "  build-essential "
        "2>/dev/null",
        check=False,
    )

    # Добавляем PPA и проверяем результат
    r_ppa = _exec(
        "add-apt-repository ppa:amnezia/ppa -y 2>/dev/null && echo PPA_ADDED || echo PPA_FAILED",
        capture=True, check=False,
    )
    _ppa_added = "PPA_ADDED" in (r_ppa.stdout or "")

    if _ppa_added:
        # Обновляем индексы и устанавливаем пакет amneziawg
        r_inst = _exec(
            "export DEBIAN_FRONTEND=noninteractive && "
            "apt-get update -q 2>/dev/null && "
            "apt-get install -y -q amneziawg 2>/dev/null && "
            "echo AWG_PKG_OK || echo AWG_PKG_FAIL",
            capture=True, check=False,
        )
        if "AWG_PKG_OK" in (r_inst.stdout or ""):
            # Загружаем модуль в ядро и проверяем функционально
            _exec("modprobe amneziawg 2>/dev/null || true", check=False)
            r_v = _exec(
                "ip link add test_awg0 type amneziawg 2>/dev/null && "
                "ip link delete dev test_awg0 2>/dev/null && echo OK || echo FAIL",
                capture=True, check=False,
            )
            if "OK" in (r_v.stdout or ""):
                success(f"AWG {_where} ЭТАП 2: модуль установлен через PPA — готово!")
                success(f"AWG {_where}: [OK] Модуль AmneziaWG установлен и готов")
                return
            else:
                warn(f"AWG {_where} ЭТАП 2: пакет установлен, но интерфейс не создаётся — продолжаем")
        else:
            warn(f"AWG {_where} ЭТАП 2: пакет amneziawg не найден в PPA")
    else:
        warn(f"AWG {_where} ЭТАП 2: add-apt-repository не сработал")

    # =========================================================================
    # ЭТАП 3: РУЧНОЕ ДОБАВЛЕНИЕ PPA
    # Fallback для серверов без launchpadlib или с заблокированным launchpad.
    # Прямая запись в sources.list.d + импорт GPG-ключа.
    # =========================================================================
    info(f"AWG {_where} ЭТАП 3: ручное добавление репозитория PPA в sources.list...")

    r_mppa = _exec(
        # Импортируем GPG-ключ репозитория
        "gpg --no-default-keyring "
        "  --keyring /usr/share/keyrings/amnezia-ppa.gpg "
        "  --keyserver keyserver.ubuntu.com "
        "  --recv-keys 57290828 2>/dev/null && "
        # Прописываем репозиторий с привязкой к keyring
        "echo 'deb [signed-by=/usr/share/keyrings/amnezia-ppa.gpg] "
        "  https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu noble main' "
        "  > /etc/apt/sources.list.d/amnezia-ppa.list && "
        "echo MANUAL_PPA_OK || echo MANUAL_PPA_FAIL",
        capture=True, check=False,
    )

    if "MANUAL_PPA_OK" in (r_mppa.stdout or ""):
        r_inst2 = _exec(
            "export DEBIAN_FRONTEND=noninteractive && "
            "apt-get update -q 2>/dev/null && "
            "apt-get install -y -q amneziawg 2>/dev/null && "
            "echo AWG_PKG2_OK || echo AWG_PKG2_FAIL",
            capture=True, check=False,
        )
        if "AWG_PKG2_OK" in (r_inst2.stdout or ""):
            _exec("modprobe amneziawg 2>/dev/null || true", check=False)
            r_v2 = _exec(
                "ip link add test_awg0 type amneziawg 2>/dev/null && "
                "ip link delete dev test_awg0 2>/dev/null && echo OK || echo FAIL",
                capture=True, check=False,
            )
            if "OK" in (r_v2.stdout or ""):
                success(f"AWG {_where} ЭТАП 3: модуль установлен через ручной PPA — готово!")
                success(f"AWG {_where}: [OK] Модуль AmneziaWG установлен и готов")
                return
            else:
                warn(f"AWG {_where} ЭТАП 3: пакет установлен, но интерфейс не создаётся — продолжаем")
        else:
            warn(f"AWG {_where} ЭТАП 3: пакет amneziawg не найден и через ручной PPA")
    else:
        warn(f"AWG {_where} ЭТАП 3: не удалось добавить репозиторий вручную")

    # =========================================================================
    # ЭТАП 4: DKMS-СБОРКА ИЗ ИСХОДНИКОВ (финальный fallback)
    # Клонируем официальный репозиторий и собираем модуль через DKMS.
    # =========================================================================
    info(f"AWG {_where} ЭТАП 4: сборка модуля из исходников через DKMS...")

    # Устанавливаем зависимости для сборки: dkms, заголовки ядра, git
    r_dkms_deps = _exec(
        "export DEBIAN_FRONTEND=noninteractive && "
        "apt-get install -y -q dkms linux-headers-$(uname -r) build-essential git 2>/dev/null && "
        "echo DKMS_DEPS_OK || echo DKMS_DEPS_FAIL",
        capture=True, check=False,
    )

    if "DKMS_DEPS_FAIL" in (r_dkms_deps.stdout or ""):
        warn(f"AWG {_where} ЭТАП 4: не удалось установить зависимости для DKMS")
    else:
        # Клонируем репозиторий с модулем ядра во временную директорию
        # Сначала пробуем dkms-install.sh, если нет — make && make install
        r_dkms = _exec(
            "TMPDIR=$(mktemp -d) && "
            "git clone --depth=1 "
            "  https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git "
            "  $TMPDIR/awg-kmod 2>/dev/null && "
            "cd $TMPDIR/awg-kmod && "
            "(bash ./dkms-install.sh 2>/dev/null || "
            " (make 2>/dev/null && make install 2>/dev/null)) && "
            "echo DKMS_BUILD_OK || echo DKMS_BUILD_FAIL",
            capture=True, check=False,
        )

        if "DKMS_BUILD_OK" in (r_dkms.stdout or ""):
            # Загружаем только что собранный модуль
            _exec("modprobe amneziawg 2>/dev/null || true", check=False)
            r_v3 = _exec(
                "ip link add test_awg0 type amneziawg 2>/dev/null && "
                "ip link delete dev test_awg0 2>/dev/null && echo OK || echo FAIL",
                capture=True, check=False,
            )
            if "OK" in (r_v3.stdout or ""):
                success(f"AWG {_where} ЭТАП 4: модуль собран через DKMS — готово!")
                success(f"AWG {_where}: [OK] Модуль AmneziaWG установлен и готов")
                return
            else:
                warn(f"AWG {_where} ЭТАП 4: DKMS-сборка прошла, но ip link type amneziawg не работает")
        else:
            warn(f"AWG {_where} ЭТАП 4: DKMS-сборка не удалась")

    # =========================================================================
    # ЭТАП 5: ВСЕ СПОСОБЫ ИСЧЕРПАНЫ — останавливаем установку
    # =========================================================================
    raise Exception(
        f"AWG {_where}: не удалось установить модуль ядра AmneziaWG ни одним из методов.\n"
        f"  Попробуйте вручную:\n"
        f"    1) add-apt-repository ppa:amnezia/ppa -y && apt-get update && apt-get install -y amneziawg\n"
        f"    2) или DKMS: git clone https://github.com/amnezia-vpn/amneziawg-linux-kernel-module "
        f"&& cd amneziawg-linux-kernel-module && bash dkms-install.sh\n"
        f"  После ручной установки перезапустите скрипт."
    )


def awg_setup_local_client() -> bool:
    """
    Настраивает AWG-клиент на RU-VPS:
    1. Устанавливает amneziawg-tools
    2. Генерирует ключи
    3. Записывает конфиги клиента и шаблон сервера
    4. Создаёт systemd unit с policy routing
    Возвращает True при успехе.
    """
    global AWG_INSTALLED

    info("AWG: настройка клиента на RU-VPS...")

    # 1. Подготовка модуля ядра AmneziaWG (очистка + установка при необходимости)
    try:
        ensure_amneziawg_ready()  # None = работаем локально на RU-VPS
    except Exception as _e:
        warn(f"AWG: модуль ядра недоступен: {_e}")
        return False

    # 2. Установка инструментов (awg, awg-quick, amneziawg-go)
    if not awg_install_local():
        warn("AWG: не удалось установить amneziawg-tools")
        return False

    # 2. Генерация ключей
    if not awg_generate_keys():
        warn("AWG: не удалось сгенерировать ключи")
        return False

    # 3. Директории
    _AWG_CONF_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(str(_AWG_CONF_DIR), 0o700)

    # 4. Конфиги — ВАЖНО: клиентский конфиг = awg0.conf (используется awg-quick)
    client_conf = _awg_client_conf_text()
    _AWG_ACTIVE_CONF.write_text(client_conf)
    os.chmod(str(_AWG_ACTIVE_CONF), 0o600)
    success(f"AWG: клиентский конфиг → {_AWG_ACTIVE_CONF}")

    # --- БАГ-FIX 1: симлинк для awg-quick -----------------------------------
    # awg-quick (как wg-quick) по умолчанию ищет конфиги в /etc/wireguard/.
    # Без симлинка сервис падает: "Cannot find device 'awg0'".
    # Создаём: /etc/wireguard/awg0.conf → /etc/amnezia/amneziawg/awg0.conf
    _wg_dir = Path("/etc/wireguard")
    _wg_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(str(_wg_dir), 0o700)
    _wg_link = _wg_dir / "awg0.conf"
    try:
        if _wg_link.exists() or _wg_link.is_symlink():
            _wg_link.unlink()
        _wg_link.symlink_to(_AWG_ACTIVE_CONF)
        success(f"AWG: симлинк создан: {_wg_link} → {_AWG_ACTIVE_CONF}")
    except Exception as _sym_err:
        warn(f"AWG: не удалось создать симлинк {_wg_link}: {_sym_err}")
        warn("AWG: awg-quick будет вызываться с полным путём к конфигу")
    # -------------------------------------------------------------------------

    # Сохраняем серверный конфиг рядом (для scp на exit-VPS)
    log_to_file("DEBUG", f"AWG template: generating server conf text "
                         f"(server_pubkey={AWG_SERVER_PUBKEY[:16] if AWG_SERVER_PUBKEY else 'EMPTY'}, "
                         f"client_pubkey={AWG_CLIENT_PUBKEY[:16] if AWG_CLIENT_PUBKEY else 'EMPTY'}, "
                         f"psk={'SET' if AWG_PRESHARED_KEY else 'EMPTY'})")
    server_conf = _awg_server_conf_text()
    _server_conf_save = _AWG_CONF_DIR / "awg0-server-template.conf"
    log_to_file("DEBUG", f"AWG template: writing to {_server_conf_save} ({len(server_conf)} bytes)")
    _server_conf_save.write_text(server_conf)
    os.chmod(str(_server_conf_save), 0o600)
    log_to_file("DEBUG", f"AWG template: written OK, exists={_server_conf_save.exists()}, "
                         f"size={_server_conf_save.stat().st_size}")
    success(f"AWG: серверный конфиг (шаблон для exit-VPS) → {_server_conf_save}")

    # 5. UID пользователя xray
    try:
        xray_uid = pwd.getpwnam("xray").pw_uid
    except KeyError:
        xray_uid = 0
        warn("AWG: пользователь xray не найден — policy routing будет по uid=0")

    # 6. Systemd unit
    unit_path = Path("/etc/systemd/system/amneziawg-awg0.service")
    unit_path.write_text(_awg_systemd_unit_text(xray_uid))
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    _run(["systemctl", "enable", "amneziawg-awg0.service"], check=False, quiet=True)
    success("AWG: systemd unit amneziawg-awg0.service создан и включён")

    # BUGFIX: открываем входящий UDP порт AWG на entry-ноде.
    # Некоторые провайдеры (например AEZA) ставят INPUT policy DROP по умолчанию,
    # и без этого правила ответные пакеты от exit-ноды не проходят —
    # туннель односторонний (sent > 0, received = 0).
    import subprocess as _sp2
    _lport = str(AWG_CLIENT_LISTEN_PORT)
    _chk2 = _sp2.run(
        ["iptables", "-C", "INPUT", "-p", "udp", "--dport", _lport, "-j", "ACCEPT"],
        capture_output=True
    )
    if _chk2.returncode != 0:
        _sp2.run(
            ["iptables", "-A", "INPUT", "-p", "udp", "--dport", _lport, "-j", "ACCEPT"],
            capture_output=True
        )
        success(f"AWG: открыт входящий UDP/{_lport} на entry-ноде")
    # Сохраняем правило если доступен iptables-persistent
    _sp2.run(
        ["bash", "-c",
         "which netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save 2>/dev/null || "
         "mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4 2>/dev/null || true"],
        capture_output=True
    )

    return True


def awg_apply_policy_routing() -> None:
    """
    Немедленно применяет policy routing (без перезагрузки):
    пакеты процесса xray помечаются → роутятся через awg0.
    """
    info("AWG: применение policy routing...")

    try:
        xray_uid = pwd.getpwnam("xray").pw_uid
    except KeyError:
        xray_uid = 0
        warn("AWG: xray uid не найден, используем 0")

    # ── Проверяем наличие IPv6-стека на сервере (graceful fallback) ───────────
    _ipv6_available = False
    try:
        r_v6 = _run(["ip", "-6", "route", "show"], capture=True, check=False, quiet=True)
        _ipv6_available = r_v6.returncode == 0
        if not _ipv6_available:
            warn("AWG: IPv6-стек недоступен на RU-сервере — пропускаем IPv6-правила (IPv4-only режим)")
        else:
            info("AWG: IPv6-стек обнаружен — применяем Dual-Stack policy routing")
    except Exception:
        warn("AWG: не удалось проверить IPv6-стек — пропускаем IPv6 (IPv4-only режим)")

    sysctl_cmds = [
        ["sysctl", "-w", "net.ipv4.ip_forward=1"],
        ["sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"],
        ["sysctl", "-w", f"net.ipv4.conf.{AWG_INTERFACE}.rp_filter=0"],
    ]
    routing_cmds = [
        ["ip", "route", "add", "default", "dev", AWG_INTERFACE,
         "table", str(AWG_ROUTE_TABLE)],
        ["ip", "rule", "add", "fwmark", str(AWG_FWMARK),
         "table", str(AWG_ROUTE_TABLE), "priority", "100"],
        ["iptables", "-t", "mangle", "-A", "OUTPUT",
         "-m", "owner", "--uid-owner", str(xray_uid),
         "-j", "MARK", "--set-mark", str(AWG_FWMARK)],
        # ИСПРАВЛЕНИЕ: dnscrypt-proxy тоже должен идти через AWG.
        # Получаем uid пользователя dnscrypt динамически.
    ]
    try:
        import pwd as _pwd_dc
        _dc_uid = _pwd_dc.getpwnam("dnscrypt").pw_uid
        routing_cmds.append(
            ["iptables", "-t", "mangle", "-A", "OUTPUT",
             "-m", "owner", "--uid-owner", str(_dc_uid),
             "-j", "MARK", "--set-mark", str(AWG_FWMARK)]
        )
    except KeyError:
        pass  # dnscrypt не установлен — ничего не добавляем
    routing_cmds += [
        # MSS clamping — убираем фрагментацию под MTU AWG
        ["iptables", "-t", "mangle", "-A", "FORWARD",
         "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
         "-j", "TCPMSS", "--set-mss", str(AWG_MTU - 40)],
    ]

    # ── IPv6 policy routing (только если стек доступен) ───────────────────────
    if _ipv6_available:
        routing_cmds += [
            # ip6 rule: трафик Xray по fwmark → таблица AWG
            ["ip", "-6", "rule", "add", "fwmark", str(AWG_FWMARK),
             "table", str(AWG_ROUTE_TABLE), "priority", "100"],
            # ip6 route: дефолтный маршрут через awg0 в таблице AWG
            ["ip", "-6", "route", "add", "default", "dev", AWG_INTERFACE,
             "table", str(AWG_ROUTE_TABLE)],
            # ip6tables OUTPUT: маркируем трафик xray
            ["ip6tables", "-t", "mangle", "-A", "OUTPUT",
             "-m", "owner", "--uid-owner", str(xray_uid),
             "-j", "MARK", "--set-mark", str(AWG_FWMARK)],
            # ip6tables MSS clamping
            ["ip6tables", "-t", "mangle", "-A", "FORWARD",
             "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
             "-j", "TCPMSS", "--set-mss", str(AWG_MTU - 40)],
            # ip6tables FORWARD ACCEPT: разрешаем форвардинг IPv6 через туннель
            ["ip6tables", "-A", "FORWARD", "-i", AWG_INTERFACE, "-j", "ACCEPT"],
            ["ip6tables", "-A", "FORWARD", "-o", AWG_INTERFACE, "-j", "ACCEPT"],
        ]
        # ip6tables NAT MASQUERADE: IPv6-пакеты из туннеля выходят с адресом RU-сервера.
        # Используем bash-обёртку т.к. нужна shell-подстановка для определения интерфейса.
        _run(
            ["bash", "-c",
             "IFACE6=$(ip -6 route | awk '/default/ {print $5; exit}'); "
             "[ -n \"$IFACE6\" ] && ip6tables -t nat -A POSTROUTING -o \"$IFACE6\" -j MASQUERADE 2>/dev/null || "
             f"ip6tables -t nat -A POSTROUTING -s {AWG_SUBNET_V6} -j MASQUERADE 2>/dev/null || true"],
            check=False, quiet=True
        )

    # ПАТЧ: добавляем исключения из AWG маршрутизации для exit-VPS и самого сервера.
    # Без этих правил SSH к exit-VPS и исходящий трафик сервера попадают в AWG петлю.
    _server_ip  = get_server_ip("4") or ""
    _server_ip6 = (get_server_ip("6") or "") if _ipv6_available else ""
    _exit_ip    = AWG_EXIT_HOST if AWG_EXIT_HOST else ""

    if _server_ip:
        _run(["ip", "rule", "add", "from", f"{_server_ip}/32",
              "lookup", "main", "priority", "49"], check=False, quiet=True)
        info(f"AWG: исключение из AWG маршрутизации для сервера {_server_ip}")
    if _server_ip6 and _ipv6_available:
        _run(["ip", "-6", "rule", "add", "from", f"{_server_ip6}/128",
              "lookup", "main", "priority", "49"], check=False, quiet=True)
        info(f"AWG: IPv6 исключение для сервера {_server_ip6}")
    if _exit_ip:
        _run(["ip", "rule", "add", "to", f"{_exit_ip}/32",
              "lookup", "main", "priority", "50"], check=False, quiet=True)
        # Маршрут к exit-VPS через физический интерфейс (не через AWG)
        _run(["bash", "-c",
              f"ip route add {_exit_ip}/32 dev $(ip route | awk '/default/ {{print $5; exit}}') 2>/dev/null || true"],
             check=False, quiet=True)
        info(f"AWG: исключение из AWG маршрутизации для exit-VPS {_exit_ip}")
        # Если exit-IP сам является IPv6 — добавляем и ip6 rule
        if _ipv6_available and ":" in _exit_ip:
            _run(["ip", "-6", "rule", "add", "to", f"{_exit_ip}/128",
                  "lookup", "main", "priority", "50"], check=False, quiet=True)

    for cmd in sysctl_cmds + routing_cmds:
        r = _run(cmd, check=False, quiet=True)
        if r.returncode not in (0, 2):  # 2 = правило уже существует
            log_to_file("WARN", f"AWG routing cmd failed: {' '.join(cmd)} → {r.stderr.strip()}")

    # ── Сохраняем правила iptables (с гарантией восстановления после ребута) ─
    rules_dir = Path("/etc/iptables")
    rules_dir.mkdir(parents=True, exist_ok=True)
    r_save = _run(["iptables-save"], capture=True, check=False)
    if r_save.returncode == 0:
        rules_v4 = rules_dir / "rules.v4"
        rules_v4.write_text(r_save.stdout)
        os.chmod(str(rules_v4), 0o600)
        success("AWG: iptables сохранены → /etc/iptables/rules.v4")

    # ── Сохраняем ip6tables (только если IPv6 применялся) ────────────────────
    if _ipv6_available:
        r_save6 = _run(["ip6tables-save"], capture=True, check=False)
        if r_save6.returncode == 0:
            rules_v6 = rules_dir / "rules.v6"
            rules_v6.write_text(r_save6.stdout)
            os.chmod(str(rules_v6), 0o600)
            success("AWG: ip6tables сохранены → /etc/iptables/rules.v6")
        else:
            warn("AWG: ip6tables-save не удался — IPv6 правила не сохранены на диск")

    # ── БАГ-FIX 2: установка и включение netfilter-persistent ────────────────
    # Без netfilter-persistent правила iptables НЕ восстанавливаются после ребута.
    # Просто сохранить в rules.v4 недостаточно — нужен сервис который их грузит.
    _nfp_installed = False
    if command_exists("netfilter-persistent") or command_exists("iptables-restore"):
        # Попробуем сохранить через netfilter-persistent
        r_nfp = _run(["netfilter-persistent", "save"], check=False, quiet=True)
        if r_nfp.returncode == 0:
            success("AWG: netfilter-persistent save — OK")
            _nfp_installed = True
    if not _nfp_installed:
        info("AWG: устанавливаем netfilter-persistent для сохранения iptables...")
        # БАГ-FIX: iptables-persistent задаёт интерактивные вопросы через debconf
        # ("Save current IPv4/IPv6 rules?"), что вешает скрипт навсегда.
        # Решение: предварительно выставляем пресиды debconf + DEBIAN_FRONTEND=noninteractive.
        _run(
            ["bash", "-c",
             "export DEBIAN_FRONTEND=noninteractive && "
             "echo 'iptables-persistent iptables-persistent/autosave_v4 boolean true' "
             "  | debconf-set-selections 2>/dev/null; "
             "echo 'iptables-persistent iptables-persistent/autosave_v6 boolean true' "
             "  | debconf-set-selections 2>/dev/null; "
             "apt-get install -y -q netfilter-persistent iptables-persistent 2>/dev/null"],
            check=False, quiet=True
        )
        r_nfp2 = _run(["netfilter-persistent", "save"], check=False, quiet=True)
        if r_nfp2.returncode == 0:
            success("AWG: netfilter-persistent установлен и правила сохранены")
            _nfp_installed = True
        else:
            warn("AWG: netfilter-persistent недоступен — будет использован fallback через cron")

    # Включаем netfilter-persistent в systemd (автозапуск)
    _run(["systemctl", "enable", "netfilter-persistent"], check=False, quiet=True)

    # ── Сохраняем sysctl постоянно ────────────────────────────────────────────
    sysctl_conf = Path("/etc/sysctl.d/99-awg.conf")
    _sysctl_content = (
        "net.ipv4.ip_forward=1\n"
        "net.ipv4.conf.all.rp_filter=0\n"
    )
    if _ipv6_available:
        # forwarding=1 нужен на RU-сервере для маршрутизации через awg0
        _sysctl_content += "net.ipv6.conf.all.forwarding=1\n"
    sysctl_conf.write_text(_sysctl_content)
    _run(["sysctl", "--system"], check=False, quiet=True)

    # ── БАГ-FIX 2 (продолжение): cron @reboot — полное восстановление ────────
    # Восстанавливаем И ip rule/route, И iptables (fallback если netfilter-persistent
    # по какой-то причине не отработал — двойная защита).
    _v6_reboot = ""
    if _ipv6_available:
        _v6_reboot = (
            f"test -f /etc/iptables/rules.v6 && ip6tables-restore < /etc/iptables/rules.v6 2>/dev/null; "
            f"ip -6 rule show | grep -q 'fwmark {AWG_FWMARK}' || "
            f"ip -6 rule add fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE} priority 100 2>/dev/null; "
            f"ip -6 route show table {AWG_ROUTE_TABLE} | grep -q default || "
            f"ip -6 route add default dev {AWG_INTERFACE} table {AWG_ROUTE_TABLE} 2>/dev/null; "
        )
        if _server_ip6:
            _v6_reboot += (
                f"ip -6 rule show | grep -q 'from {_server_ip6}' || "
                f"ip -6 rule add from {_server_ip6}/128 lookup main priority 49 2>/dev/null; "
            )

    reboot_script = (
        "# AWG policy routing + iptables restore — автогенерировано vless-installer\n"
        f"@reboot root "
        # 1. iptables из сохранённого дампа (жёсткий fallback)
        f"test -f /etc/iptables/rules.v4 && iptables-restore < /etc/iptables/rules.v4 2>/dev/null; "
        # 2. ip6tables restore (Dual-Stack, если был применён)
        + _v6_reboot +
        # 3. ip rule исключение для самого сервера (приоритет 49)
        f"ip rule show | grep -q 'from {_server_ip}' || "
        f"ip rule add from {_server_ip}/32 lookup main priority 49 2>/dev/null; "
        # 4. ip rule исключение для exit-VPS (приоритет 50)
        f"ip rule show | grep -q 'to {_exit_ip}' || "
        f"ip rule add to {_exit_ip}/32 lookup main priority 50 2>/dev/null; "
        # 5. маршрут к exit-VPS через физический интерфейс
        f"ip route show | grep -q '{_exit_ip}' || "
        f"ip route add {_exit_ip}/32 dev $(ip route | awk '/default/ {{print $5; exit}}') 2>/dev/null; "
        # 6. ip rule (policy routing fwmark)
        f"ip rule show | grep -q 'fwmark {AWG_FWMARK}' || "
        f"ip rule add fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE} priority 100 2>/dev/null; "
        # 7. ip route в таблице AWG
        f"ip route show table {AWG_ROUTE_TABLE} | grep -q default || "
        f"ip route add default dev {AWG_INTERFACE} table {AWG_ROUTE_TABLE} 2>/dev/null"
    )
    cron_path = Path("/etc/cron.d/awg-routing")
    cron_path.write_text(reboot_script + "\n")
    os.chmod(str(cron_path), 0o644)
    _v6_status = "Dual-Stack (IPv4+IPv6)" if _ipv6_available else "IPv4-only"
    success(f"AWG: policy routing применён и сохранён ({_v6_status}, iptables + ip rule/route при ребуте)")


def _awg_ensure_sshpass() -> bool:
    """
    Проверяет наличие sshpass. При отсутствии предлагает установить через apt.
    Возвращает True если sshpass доступен после вызова, иначе False.
    """
    if command_exists("sshpass"):
        return True
    warn("AWG: sshpass не найден — он нужен для SSH-аутентификации по паролю.")
    print()
    _box_top("Установка sshpass")
    _box_row(f"  {YELLOW}sshpass не установлен. Установить автоматически?{NC}")
    _box_item("Y", "Да — apt install sshpass")
    _box_item("N", "Нет — показать инструкцию ручной настройки")
    _box_bottom()
    try:
        _ans = input(f"  {CYAN}Установить sshpass? [Y/N, Enter=Y]:{NC} ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        _ans = "n"
    if _ans in ("", "y"):
        info("AWG: установка sshpass...")
        _r = _run(["apt-get", "install", "-y", "-q", "sshpass"],
                  check=False, quiet=True)
        if _r.returncode == 0 and command_exists("sshpass"):
            success("AWG: sshpass установлен")
            return True
        warn("AWG: не удалось установить sshpass автоматически")
    return False


def awg_setup_remote_server(
    auth_method: str = "",
    ssh_password: str = "",
) -> bool:
    """
    Устанавливает AWG-сервер на exit-VPS по SSH.

    Методы аутентификации:
      auth_method="key"      — SSH-ключ (~/.ssh/id_*), BatchMode=yes.
      auth_method="password" — пароль через sshpass; передаётся только через
                               переменную окружения SSHPASS (env=), никогда
                               не попадает в cmdline, лог или stdout.

    Если параметры не переданы — берутся из глобальных
    AWG_SSH_AUTH_METHOD / AWG_SSH_PASSWORD (заполняются prompt_awg_exit_mode).

    Логика fallback:
      ключ не сработал  → предлагает ввести пароль интерактивно.
      пароль тоже нет   → _awg_print_manual_guide() + return False.

    Пароль очищается из памяти сразу после использования.
    Возвращает True при успехе, False при недоступности SSH.
    """
    _auth   = auth_method  if auth_method  else AWG_SSH_AUTH_METHOD
    _passwd = ssh_password if ssh_password else AWG_SSH_PASSWORD

    info(f"AWG: установка сервера на exit-VPS {AWG_EXIT_HOST} (auth={_auth})...")
    log_to_file("INFO", f"awg_setup_remote_server host={AWG_EXIT_HOST} auth={_auth}")

    # === FIX EXTRA: сброс зависших интерфейсов на exit-VPS перед установкой ===
    _awg_cleanup_stale_interfaces(target="remote", remote_host=AWG_EXIT_HOST)
    # === END FIX EXTRA ===

    # ── Ищем SSH-ключ ─────────────────────────────────────────────────────────
    ssh_key = None
    for _cand in ["~/.ssh/id_ed25519", "~/.ssh/id_rsa",
                  "~/.ssh/id_ecdsa",   "~/.ssh/id_dsa"]:
        _kp = Path(_cand).expanduser()
        if _kp.exists():
            ssh_key = str(_kp)
            break

    # ── Общие SSH-опции ────────────────────────────────────────────────────────
    _common = [
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=15",
        "-o", "LogLevel=ERROR",
        "-o", "UserKnownHostsFile=/dev/null",
    ]

    # ── Готовим sshpass если нужен ────────────────────────────────────────────
    if _auth == "password" and _passwd and not _awg_ensure_sshpass():
        warn("AWG: sshpass недоступен — откат к SSH-ключу")
        _auth   = "key"
        _passwd = ""

    # ── Строим ssh/scp команды ────────────────────────────────────────────────
    if _auth == "password" and _passwd:
        # Пароль только через env SSHPASS — не в аргументах процесса
        _env      = {**os.environ, "SSHPASS": _passwd}
        _pw_extra = ["-o", "PasswordAuthentication=yes", "-o", "BatchMode=no"]
        _ssh_base = ["sshpass", "-e", "ssh", *_common, *_pw_extra]
        _scp_base = ["sshpass", "-e", "scp", *_common, *_pw_extra]
    else:
        _env      = None
        _k_extra  = (["-i", ssh_key] if ssh_key else []) + ["-o", "BatchMode=yes"]
        _ssh_base = ["ssh", *_common, *_k_extra]
        _scp_base = ["scp", *_common, *_k_extra]

    def _ssh(cmd: str, capture: bool = False, check: bool = True, quiet: bool = False) -> subprocess.CompletedProcess:
        """SSH к exit-VPS. Логирует только rc, не содержимое команды."""
        # timeout=120: защита от зависания при firewall-дропе пакетов.
        # ConnectTimeout=15 покрывает только фазу соединения — без общего timeout
        # subprocess может висеть бесконечно при зависшей сессии.
        try:
            _res = subprocess.run(
                [*_ssh_base, f"root@{AWG_EXIT_HOST}", cmd],
                capture_output=True, text=True, env=_env,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            log_to_file("WARN", f"AWG ssh timeout (120s) для команды на {AWG_EXIT_HOST}")
            return subprocess.CompletedProcess([], 124, stdout="", stderr="timeout")
        log_to_file("DEBUG", f"AWG ssh rc={_res.returncode}")
        return _res

    def _scp(local: str, remote: str) -> subprocess.CompletedProcess:
        """SCP файла на exit-VPS."""
        _res = subprocess.run(
            [*_scp_base, local, f"root@{AWG_EXIT_HOST}:{remote}"],
            capture_output=True, text=True, env=_env,
        )
        log_to_file("DEBUG", f"AWG scp rc={_res.returncode} src={local}")
        return _res

    # ── Проверка SSH-доступа ──────────────────────────────────────────────────
    info(f"AWG: проверка SSH-соединения с {AWG_EXIT_HOST} (auth={_auth})...")
    r_test = _ssh("echo AWG_SSH_TEST_OK")
    if "AWG_SSH_TEST_OK" not in (r_test.stdout or ""):
        # Выводим причину отказа — помогает пользователю понять проблему
        _ssh_err = (r_test.stderr or "").strip()
        _ssh_rc  = r_test.returncode
        if _ssh_err:
            warn(f"AWG: SSH ошибка (rc={_ssh_rc}): {_ssh_err[:200]}")
        else:
            warn(f"AWG: SSH не ответил (rc={_ssh_rc}, stdout пуст)")
        log_to_file("WARN", f"AWG ssh test failed rc={_ssh_rc} stderr={_ssh_err[:500]!r}")

        # Единый диалог fallback для обоих методов (key и password)
        _fail_reason = "по SSH-ключу" if _auth == "key" else "по паролю"
        warn(f"AWG: SSH-подключение к {AWG_EXIT_HOST} не удалось ({_fail_reason})")
        _box_top("AWG: SSH-подключение не удалось")
        _box_row()
        _box_wrap_msg(f"  {YELLOW}", 2,
            f"Не удалось подключиться к {AWG_EXIT_HOST} {_fail_reason}.{NC}")
        if _ssh_err:
            _box_row(f"  {DIM}Причина: {_ssh_err[:120]}{NC}")
        _box_row()
        _box_item("K", f"Попробовать SSH-{GREEN}ключ{NC} (BatchMode=yes, ~/.ssh/id_*)")
        _box_item("P", f"Ввести {CYAN}пароль{NC} root и попробовать через sshpass")
        _box_item("M", "Показать инструкцию ручной настройки и продолжить")
        _box_bottom()
        try:
            _fb = input(f"  {CYAN}Выбор [K/P/M, Enter=M]:{NC} ").strip().upper()
        except (KeyboardInterrupt, EOFError):
            _fb = "M"

        if _fb == "K":
            # Повторяем с явным ключом — сбрасываем пароль
            return awg_setup_remote_server("key", "")

        if _fb == "P":
            if not _awg_ensure_sshpass():
                warn("AWG: sshpass недоступен — установите вручную: apt-get install sshpass")
            else:
                try:
                    _tp = getpass.getpass(f"  Пароль для root@{AWG_EXIT_HOST}: ")
                except (KeyboardInterrupt, EOFError):
                    _tp = ""
                if _tp:
                    _ok = awg_setup_remote_server("password", _tp)
                    _tp = ""   # очищаем сразу
                    return _ok

        # M или любой другой ввод — показываем ручную инструкцию
        warn(f"AWG: нет SSH-доступа к {AWG_EXIT_HOST}")
        _awg_print_manual_guide()
        _passwd = ""
        return False

    info(f"AWG: SSH к {AWG_EXIT_HOST} — OK (auth={_auth})")

    # ── Подготовка модуля ядра AmneziaWG на exit-VPS ─────────────────────────
    # ВАЖНО: _ssh передаётся явным параметром ssh_fn — ensure_amneziawg_ready()
    # является глобальной функцией и не видит _ssh из closure напрямую.
    info(f"AWG: подготовка модуля ядра на exit-VPS {AWG_EXIT_HOST}...")
    try:
        ensure_amneziawg_ready(remote_host=AWG_EXIT_HOST, ssh_fn=_ssh)
    except Exception as _e:
        warn(f"AWG Remote: модуль ядра недоступен на {AWG_EXIT_HOST}: {_e}")
        _awg_print_manual_guide()
        _passwd = ""
        return False

    info("AWG: установка пакетов на exit-VPS (1-2 мин)...")
    # _remote_setup включает git clone + make amneziawg-go — может занять до 5 минут.
    # _ssh() имеет timeout=120; для сборки Go выполняем в два этапа чтобы не упасть по таймауту.
    _remote_setup_pkg = (
        "export DEBIAN_FRONTEND=noninteractive && "
        "apt-get update -q 2>/dev/null && "
        "apt-get install -y -q curl git make golang-go unzip 2>/dev/null && "
        "ARCH=$(uname -m) && "
        "if [ \"$ARCH\" = 'x86_64' ]; then AWG_ARCH_SUFFIX='ubuntu-22.04-amneziawg-tools.zip'; "
        "elif [ \"$ARCH\" = 'aarch64' ]; then AWG_ARCH_SUFFIX='ubuntu-22.04-arm64-amneziawg-tools.zip'; "
        "else echo \"[AWG] WARN: unknown arch $ARCH, trying amd64 asset\"; AWG_ARCH_SUFFIX='ubuntu-22.04-amneziawg-tools.zip'; fi && "
        "AWG_TAG=$(curl -fsSL --connect-timeout 15 https://api.github.com/repos/amnezia-vpn/amneziawg-tools/releases/latest 2>/dev/null | grep tag_name | cut -d'\"' -f4) && "
        "if [ -n \"$AWG_TAG\" ]; then "
        "  curl -fsSL --connect-timeout 30 --retry 3 "
        "  https://github.com/amnezia-vpn/amneziawg-tools/releases/download/${AWG_TAG}/${AWG_ARCH_SUFFIX} "
        "  -o /tmp/awg-tools.zip && "
        "  unzip -o /tmp/awg-tools.zip -d /tmp/awg-tools-ex && "
        "  find /tmp/awg-tools-ex -name 'awg' -exec cp {} /usr/local/bin/awg \\; && "
        "  find /tmp/awg-tools-ex -name 'awg-quick' -exec cp {} /usr/local/bin/awg-quick \\; && "
        "  chmod +x /usr/local/bin/awg /usr/local/bin/awg-quick && "
        "  rm -rf /tmp/awg-tools.zip /tmp/awg-tools-ex; "
        "fi && "
        "sysctl -w net.ipv4.ip_forward=1 && "
        "sysctl -w net.ipv6.conf.all.forwarding=1 && "
        "echo net.ipv4.ip_forward=1 > /etc/sysctl.d/99-awg.conf && "
        "echo net.ipv6.conf.all.forwarding=1 >> /etc/sysctl.d/99-awg.conf && "
        "mkdir -p /etc/amnezia/amneziawg && chmod 700 /etc/amnezia/amneziawg"
    )
    _remote_setup_go = (
        # Сборка amneziawg-go вынесена отдельно — может занять до 3-4 минут
        "if [ ! -f /usr/local/bin/amneziawg-go ]; then "
        "  mkdir -p /tmp/awg-go-build && "
        "  git clone --depth=1 https://github.com/amnezia-vpn/amneziawg-go.git /tmp/awg-go-build/src && "
        "  cd /tmp/awg-go-build/src && make && "
        "  cp /tmp/awg-go-build/src/amneziawg-go /usr/local/bin/amneziawg-go && "
        "  chmod +x /usr/local/bin/amneziawg-go && "
        "  rm -rf /tmp/awg-go-build; "
        "fi"
    )
    _ssh(_remote_setup_pkg)
    info("AWG: сборка amneziawg-go на exit-VPS (может занять 3-4 мин)...")
    # Для сборки Go увеличиваем таймаут до 360 секунд через отдельный subprocess
    try:
        subprocess.run(
            [*_ssh_base, f"root@{AWG_EXIT_HOST}", _remote_setup_go],
            capture_output=True, text=True, env=_env, timeout=360,
        )
    except subprocess.TimeoutExpired:
        warn("AWG: сборка amneziawg-go превысила 6 мин — продолжаем (может не работать userspace)")

    # ── Копируем серверный конфиг (scp → base64 fallback) ────────────────────
    import base64 as _b64
    _srv_tmpl = _AWG_CONF_DIR / "awg0-server-template.conf"

    # FIX: файл мог быть удалён awg_rollback() при предыдущей неудачной попытке.
    # Если шаблона нет — пересоздаём его через генератор (те же ключи уже в globals).
    log_to_file("DEBUG", f"AWG remote: checking template {_srv_tmpl}: "
                         f"exists={_srv_tmpl.exists()}, "
                         f"server_pubkey={AWG_SERVER_PUBKEY[:16] + '...' if AWG_SERVER_PUBKEY else 'EMPTY'}, "
                         f"client_pubkey={AWG_CLIENT_PUBKEY[:16] + '...' if AWG_CLIENT_PUBKEY else 'EMPTY'}, "
                         f"psk={'SET' if AWG_PRESHARED_KEY else 'EMPTY'}")
    if not _srv_tmpl.exists():
        warn("AWG: awg0-server-template.conf не найден — пересоздаём из текущих параметров...")
        log_to_file("WARN", f"AWG remote: template missing, regenerating "
                            f"(pubkeys: server={AWG_SERVER_PUBKEY[:16] + '...' if AWG_SERVER_PUBKEY else 'EMPTY'}, "
                            f"client={AWG_CLIENT_PUBKEY[:16] + '...' if AWG_CLIENT_PUBKEY else 'EMPTY'})")
        try:
            _AWG_CONF_DIR.mkdir(parents=True, exist_ok=True)
            os.chmod(str(_AWG_CONF_DIR), 0o700)
            _srv_tmpl.write_text(_awg_server_conf_text())
            os.chmod(str(_srv_tmpl), 0o600)
            log_to_file("DEBUG", f"AWG remote: template regenerated OK, size={_srv_tmpl.stat().st_size}")
            success(f"AWG: серверный конфиг пересоздан → {_srv_tmpl}")
        except Exception as _regen_err:
            log_to_file("ERROR", f"AWG remote: template regen failed: {_regen_err}")
            warn(f"AWG: не удалось пересоздать серверный конфиг: {_regen_err}")
            _awg_print_manual_guide()
            _passwd = ""
            return False
    else:
        log_to_file("DEBUG", f"AWG remote: template OK, size={_srv_tmpl.stat().st_size}")

    log_to_file("DEBUG", f"AWG remote: starting scp {_srv_tmpl} → root@{AWG_EXIT_HOST}:{_AWG_REMOTE_CONF_PATH}")
    r_scp = _scp(str(_srv_tmpl), _AWG_REMOTE_CONF_PATH)
    log_to_file("DEBUG", f"AWG remote: scp rc={r_scp.returncode}, "
                         f"stderr={r_scp.stderr[:300] if r_scp.stderr else ''}")
    if r_scp.returncode != 0:
        info("AWG: scp не удался — передаём через base64/stdin...")
        log_to_file("WARN", f"AWG remote: scp failed (rc={r_scp.returncode}), falling back to base64. "
                            f"scp stderr: {r_scp.stderr[:500] if r_scp.stderr else '(empty)'}")
        try:
            _cfg_b64 = _b64.b64encode(_srv_tmpl.read_bytes()).decode()
            log_to_file("DEBUG", f"AWG remote: base64 payload ready ({len(_cfg_b64)} chars)")
        except FileNotFoundError:
            log_to_file("ERROR", f"AWG remote: template vanished between exists-check and read_bytes: {_srv_tmpl}")
            warn("AWG: серверный конфиг недоступен для передачи через base64")
            _awg_print_manual_guide()
            _passwd = ""
            return False
        r_hd = _ssh(
            f"printf '%s' '{_cfg_b64}' | base64 -d > {_AWG_REMOTE_CONF_PATH}"
            f" && chmod 600 {_AWG_REMOTE_CONF_PATH}"
        )
        log_to_file("DEBUG", f"AWG remote: base64 transfer rc={r_hd.returncode}, "
                             f"stderr={r_hd.stderr[:300] if r_hd.stderr else ''}")
        if r_hd.returncode != 0:
            log_to_file("ERROR", f"AWG remote: base64 transfer failed: {r_hd.stderr[:500]}")
            warn("AWG: не удалось передать конфиг ни через scp, ни через base64")
            _awg_print_manual_guide()
            _passwd = ""
            return False
        success("AWG: конфиг передан через base64")
    else:
        _ssh(f"chmod 600 {_AWG_REMOTE_CONF_PATH}")
        log_to_file("DEBUG", "AWG remote: scp succeeded")
        success(f"AWG: серверный конфиг скопирован → {_AWG_REMOTE_CONF_PATH}")

    # ── Systemd unit на exit-VPS (передаём через base64) ─────────────────────
    # АВТООПРЕДЕЛЕНИЕ: проверяем доступность модуля ядра на exit-VPS через SSH.
    # Если модуль загружен — WG_QUICK_USERSPACE_IMPLEMENTATION не нужен.
    _r_remote_kmod = _ssh(
        "lsmod | grep -qiE 'amneziawg|amnezia.wg' && echo KMOD_OK || "
        "ip link add awg_probe type amneziawg 2>/dev/null && "
        "ip link delete awg_probe 2>/dev/null && echo KMOD_OK || echo KMOD_NO",
        capture=True, check=False
    )
    _remote_has_kmod = "KMOD_OK" in (_r_remote_kmod.stdout or "")
    _remote_impl = "" if _remote_has_kmod else "amneziawg-go"
    _remote_env_line = (
        f"Environment=WG_QUICK_USERSPACE_IMPLEMENTATION={_remote_impl}"
        if _remote_impl else ""
    )
    _remote_impl_pfx = f"WG_QUICK_USERSPACE_IMPLEMENTATION={_remote_impl} " if _remote_impl else ""
    _remote_pre = (
        "lsmod | grep -qiE 'amneziawg|amnezia.wg' || "
        "/sbin/modprobe amneziawg 2>/dev/null || "
        "/sbin/modprobe amnezia-wg 2>/dev/null || "
        "/sbin/modprobe wireguard 2>/dev/null || true"
    )
    if _remote_has_kmod:
        success("AWG remote: модуль ядра доступен на exit-VPS — используем kernel mode")
    else:
        info("AWG remote: модуль ядра недоступен на exit-VPS — используем userspace (amneziawg-go)")
    _unit_lines_base = [
        "[Unit]",
        "Description=AmneziaWG 2.0 server (awg0)",
        "After=network.target",
        "",
        "[Service]",
        "Type=oneshot",
        "RemainAfterExit=yes",
    ]
    if _remote_env_line:
        _unit_lines_base.append(_remote_env_line)
    _unit_lines = _unit_lines_base + [
        f"ExecStartPre=/bin/bash -c '{_remote_pre}'",
        "ExecStart=/bin/bash -c 'AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
        f"{_remote_impl_pfx}$AWG_BIN up /etc/amnezia/amneziawg/awg0.conf'",
        "ExecStop=/bin/bash -c 'AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
        f"{_remote_impl_pfx}$AWG_BIN down /etc/amnezia/amneziawg/awg0.conf'",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
    ]
    _unit_b64 = _b64.b64encode("\n".join(_unit_lines).encode()).decode()
    r_unit = _ssh(
        f"printf '%s' '{_unit_b64}' | base64 -d"
        f" > /etc/systemd/system/amneziawg-awg0.service"
        f" && chmod 644 /etc/systemd/system/amneziawg-awg0.service"
    )
    if r_unit.returncode != 0:
        warn("AWG: не удалось создать systemd unit на exit-VPS (продолжаем)")
    else:
        success("AWG: systemd unit создан на exit-VPS")

    # ── Открываем UDP-порт ────────────────────────────────────────────────────
    _ssh(f"ufw allow {AWG_EXIT_PORT}/udp 2>/dev/null || true")
    _ssh(
        f"iptables -C INPUT -p udp --dport {AWG_EXIT_PORT} -j ACCEPT 2>/dev/null ||"
        f" iptables -A INPUT -p udp --dport {AWG_EXIT_PORT} -j ACCEPT 2>/dev/null || true"
    )
    success(f"AWG: UDP/{AWG_EXIT_PORT} открыт на exit-VPS")

    # ── Запуск AWG-сервера ────────────────────────────────────────────────────
    # BUGFIX: отключаем стандартный awg-quick@awg0.service если он есть —
    # он конкурирует с amneziawg-awg0.service за интерфейс awg0 и при старте
    # выдаёт "awg0 already exists", после чего awg show пуст (обычный wg
    # вместо amneziawg поднимает интерфейс без Jc/Jmin/Jmax параметров).
    _ssh(
        "systemctl stop awg-quick@awg0.service 2>/dev/null || true; "
        "systemctl disable awg-quick@awg0.service 2>/dev/null || true; "
        "ip link delete awg0 2>/dev/null || true"
    )
    r_start = _ssh(
        "systemctl daemon-reload && "
        "systemctl enable amneziawg-awg0.service && "
        "systemctl start amneziawg-awg0.service"
    )
    if r_start.returncode != 0:
        warn("AWG: systemd старт не удался — пробуем awg-quick напрямую...")
        r_alt = _ssh(
            "AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
            + (f"WG_QUICK_USERSPACE_IMPLEMENTATION={_remote_impl} " if _remote_impl else "")
            + "$AWG_BIN up /etc/amnezia/amneziawg/awg0.conf 2>&1"
        )
        if r_alt.returncode != 0:
            warn(f"AWG: сервер не запустился: {(r_alt.stdout or '')[:300]}")
            log_to_file("ERROR", f"AWG remote start: {(r_alt.stdout or '')[:500]}")
            _passwd = ""
            return False

    # =============================================================================
    # ПАТЧ: Включение NAT (Masquerade) на Exit-Node (КРИТИЧНО!)
    # Без этого интернет через туннель работать не будет.
    # =============================================================================
    info("AWG Remote: включение NAT (Masquerade) для выхода в интернет...")
    
    try:
        # 1. Определяем внешний интерфейс на удаленном сервере
        get_iface_cmd = "ip -4 route | grep default | awk '{print $5}'"
        r_iface = _ssh(get_iface_cmd, capture=True, check=False)
        
        exit_iface = ""
        if r_iface.returncode == 0 and r_iface.stdout.strip():
            exit_iface = r_iface.stdout.strip()
            info(f"AWG Remote: обнаружен внешний интерфейс: {exit_iface}")
        else:
            exit_iface = "eth0" # Стандартный fallback
            warn(f"AWG Remote: не удалось определить интерфейс автоматически, используем стандартный: {exit_iface}")

        # 2. Включаем IP Forwarding (пересылку пакетов IPv4 + IPv6)
        fwd_cmd = "sysctl -w net.ipv4.ip_forward=1 && sysctl -w net.ipv6.conf.all.forwarding=1"
        _ssh(fwd_cmd, check=False, quiet=True)
        info("AWG Remote: IP Forwarding (IPv4+IPv6) включен")

        # 3. Добавляем правило IPv4 NAT (Masquerade)
        nat_cmd = f"iptables -t nat -A POSTROUTING -o {exit_iface} -j MASQUERADE"
        r_nat = _ssh(nat_cmd, check=False)

        if r_nat.returncode == 0:
            success(f"AWG Remote: IPv4 NAT успешно включен на интерфейсе {exit_iface}")
        else:
            warn(f"AWG Remote: Не удалось включить IPv4 NAT через iptables (код {r_nat.returncode}). Пробуем альтернативу...")
            # Альтернативный вариант: маскировать конкретно подсеть туннеля
            alt_nat_cmd = f"iptables -t nat -A POSTROUTING -s {AWG_SUBNET} -j MASQUERADE"
            r_alt = _ssh(alt_nat_cmd, check=False)
            if r_alt.returncode == 0:
                success("AWG Remote: IPv4 NAT включен через подсеть туннеля.")
            else:
                warn("AWG Remote: КРИТИЧЕСКАЯ ОШИБКА! IPv4 NAT не включен ни одним способом. Интернет работать не будет!")
                warn("Рекомендуется вручную выполнить команду iptables на exit-VPS.")

        # 3b. IPv6 NAT (Masquerade) — graceful: не ломаем установку при недоступности
        r_ip6check = _ssh("ip -6 route show default 2>/dev/null | head -1", capture=True, check=False, quiet=True)
        _exit_has_ipv6 = r_ip6check.returncode == 0 and bool((r_ip6check.stdout or "").strip())
        if _exit_has_ipv6:
            # Определяем IPv6 внешний интерфейс (может отличаться от IPv4)
            r_iface6 = _ssh("ip -6 route | awk '/default/ {print $5; exit}'", capture=True, check=False, quiet=True)
            exit_iface6 = (r_iface6.stdout or "").strip() or exit_iface
            nat6_cmd = f"ip6tables -t nat -A POSTROUTING -o {exit_iface6} -j MASQUERADE"
            r_nat6 = _ssh(nat6_cmd, check=False, quiet=True)
            if r_nat6.returncode == 0:
                success(f"AWG Remote: IPv6 NAT включен на интерфейсе {exit_iface6}")
            else:
                # Fallback: по ULA-подсети туннеля
                alt_nat6_cmd = f"ip6tables -t nat -A POSTROUTING -s {AWG_SUBNET_V6} -j MASQUERADE"
                r_alt6 = _ssh(alt_nat6_cmd, check=False, quiet=True)
                if r_alt6.returncode == 0:
                    success("AWG Remote: IPv6 NAT включен через подсеть туннеля.")
                else:
                    warn("AWG Remote: IPv6 NAT не включён — туннель будет работать в IPv4-only режиме")
        else:
            warn("AWG Remote: IPv6 недоступен на exit-VPS — пропускаем ip6tables NAT (IPv4-only)")

        # 4. Сохраняем правила iptables + ip6tables, чтобы они пережили перезагрузку
        _save_v6 = " && ip6tables-save > /etc/iptables/rules.v6" if _exit_has_ipv6 else ""
        save_commands = [
            "command -v netfilter-persistent >/dev/null && netfilter-persistent save",
            f"mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4{_save_v6}",
        ]
        
        saved = False
        for cmd in save_commands:
            r_save = _ssh(cmd, check=False, quiet=True)
            if r_save.returncode == 0:
                info(f"AWG Remote: правила iptables сохранены ({cmd.split()[0]})")
                saved = True
                break
        
        if not saved:
            warn("AWG Remote: не удалось сохранить правила iptables автоматически. Они могут сброситься после ребута.")

    except Exception as e:
        warn(f"AWG Remote: Ошибка при настройке NAT: {e}")
        warn("Проверьте работу NAT вручную на exit-VPS.")
    
    # =============================================================================
    # Конец патча NAT
    # =============================================================================

    # ── Верификация ───────────────────────────────────────────────────────────
    r_ver = _ssh(
        "ip link show awg0 2>/dev/null && echo IFACE_OK || echo IFACE_MISSING"
    )
    _iface_ok = "IFACE_OK" in (r_ver.stdout or "")
    if _iface_ok:
        success(f"AWG: сервер активен на {AWG_EXIT_HOST}:{AWG_EXIT_PORT}/udp")
    else:
        warn("AWG: интерфейс awg0 не обнаружен на exit-VPS после запуска")
        log_to_file("WARN", f"AWG remote iface check: {r_ver.stdout!r}")

    _passwd = ""   # очищаем пароль из памяти независимо от результата
    return _iface_ok


def _awg_print_manual_guide() -> None:
    """Выводит инструкцию по ручной настройке AWG на exit-VPS."""
    srv_tmpl = _AWG_CONF_DIR / "awg0-server-template.conf"
    print()
    _box_top("AWG: Ручная настройка exit-VPS")
    _box_row()
    _box_row(f"  {YELLOW}Выполните на зарубежном VPS ({AWG_EXIT_HOST}):{NC}")
    _box_row()
    _box_row(f"  {CYAN}1. Установите AmneziaWG (без PPA — через GitHub releases):{NC}")
    _box_row_auto("     apt-get install -y curl unzip git make golang-go", cont_indent="       ")
    _box_row_auto('     TAG=$(curl -fsSL https://api.github.com/repos/amnezia-vpn/amneziawg-tools/releases/latest | grep tag_name | cut -d\'"\' -f4)', cont_indent="       ")
    _box_row_auto('     curl -fsSL https://github.com/amnezia-vpn/amneziawg-tools/releases/download/${TAG}/ubuntu-22.04-amneziawg-tools.zip -o /tmp/awg.zip', cont_indent="       ")
    _box_row_auto("     unzip -o /tmp/awg.zip -d /tmp/awg-ex && find /tmp/awg-ex -name 'awg' -exec cp {} /usr/local/bin/awg \\;", cont_indent="       ")
    _box_row_auto("     find /tmp/awg-ex -name 'awg-quick' -exec cp {} /usr/local/bin/awg-quick \\; && chmod +x /usr/local/bin/awg /usr/local/bin/awg-quick", cont_indent="       ")
    _box_row_auto("     git clone --depth=1 https://github.com/amnezia-vpn/amneziawg-go.git /tmp/awg-go && cd /tmp/awg-go && make", cont_indent="       ")
    _box_row_auto("     cp /tmp/awg-go/amneziawg-go /usr/local/bin/amneziawg-go && chmod +x /usr/local/bin/amneziawg-go", cont_indent="       ")
    _box_row()
    _box_row(f"  {CYAN}2. Скопируйте серверный конфиг с RU-VPS:{NC}")
    _box_row_auto(f"     scp root@<RU-VPS-IP>:{srv_tmpl} /etc/amnezia/amneziawg/awg0.conf", cont_indent="       ")
    _box_row()
    _box_row(f"  {CYAN}3. Откройте порт и запустите AWG:{NC}")
    _box_row(f"     ufw allow {AWG_EXIT_PORT}/udp")
    _box_row_auto("     # Если модуль ядра amneziawg загружен:", cont_indent="       ")
    _box_row_auto("     awg-quick up /etc/amnezia/amneziawg/awg0.conf", cont_indent="       ")
    _box_row_auto("     # Если модуль ядра недоступен (userspace):", cont_indent="       ")
    _box_row_auto("     WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go awg-quick up /etc/amnezia/amneziawg/awg0.conf", cont_indent="       ")
    _box_row("     systemctl enable --now amneziawg-awg0.service")
    _box_row()
    _box_row(f"  {CYAN}4. Включите IP forwarding:{NC}")
    _box_row("     sysctl -w net.ipv4.ip_forward=1")
    _box_row("     echo net.ipv4.ip_forward=1 >> /etc/sysctl.d/99-awg.conf")
    _box_bottom()


def awg_rollback() -> None:
    """Откат всех изменений AWG при ошибке установки."""
    warn("AWG: rollback — удаляем правила и конфиги...")

    try:
        xray_uid = pwd.getpwnam("xray").pw_uid
    except KeyError:
        xray_uid = 0

    for cmd in [
        ["systemctl", "stop",    "amneziawg-awg0.service"],
        ["systemctl", "disable", "amneziawg-awg0.service"],
        ["ip", "link", "delete", AWG_INTERFACE],
        ["ip", "rule", "del", "fwmark", str(AWG_FWMARK),
         "table", str(AWG_ROUTE_TABLE)],
        ["ip", "route", "flush", "table", str(AWG_ROUTE_TABLE)],
        ["iptables", "-t", "mangle", "-D", "OUTPUT",
         "-m", "owner", "--uid-owner", str(xray_uid),
         "-j", "MARK", "--set-mark", str(AWG_FWMARK)],
    ]:
        _run(cmd, check=False, quiet=True)

    for p in [
        _AWG_ACTIVE_CONF,
        _AWG_CONF_DIR / "awg0-server-template.conf",
        Path("/etc/systemd/system/amneziawg-awg0.service"),
        Path("/etc/cron.d/awg-routing"),
        Path("/etc/sysctl.d/99-awg.conf"),
    ]:
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass

    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    warn("AWG: rollback завершён")
    log_to_file("WARN", "AWG rollback completed")


def awg_verify_tunnel() -> bool:
    """
    Проверяет работоспособность AWG-туннеля послойно:
      1. Интерфейс существует (ip link show)
      2. Handshake (awg show latest-handshakes)
      3. Трафик двусторонний (awg show transfer: sent > 0 и received > 0)
      4. Ping через интерфейс до внутреннего IP exit-VPS
      5. Policy routing: ip rule fwmark + маршрут в таблице + iptables mangle
    Выводит итоговый бокс с диагнозом по каждому слою.
    Возвращает True если туннель функционален (интерфейс + routing),
    False если интерфейс не поднят.
    """
    info("AWG: верификация туннеля...")
    log_to_file("DEBUG", f"awg_verify_tunnel: iface={AWG_INTERFACE} fwmark={AWG_FWMARK} "
                         f"table={AWG_ROUTE_TABLE} server_ip={AWG_SERVER_IP}")

    _ok   = f"{GREEN}✓{NC}"
    _warn = f"{YELLOW}✗{NC}"
    _skip = f"{DIM}−{NC}"

    results: list[str] = []   # строки для итогового бокса

    # ── 1. Интерфейс ─────────────────────────────────────────────────────────
    r_link = _run(["ip", "link", "show", AWG_INTERFACE], capture=True, check=False)
    iface_ok = r_link.returncode == 0
    if iface_ok:
        results.append(f"  {_ok}  Интерфейс {AWG_INTERFACE} поднят")
        log_to_file("DEBUG", f"awg_verify: iface OK")
    else:
        results.append(f"  {_warn}  Интерфейс {AWG_INTERFACE} НЕ существует")
        log_to_file("WARN", f"awg_verify: iface {AWG_INTERFACE} missing")

    # ── 2. Handshake ─────────────────────────────────────────────────────────
    handshake_ok   = False
    handshake_str  = ""
    awg_bin = AWG_BIN if awg_check_tool(AWG_BIN) else ("wg" if awg_check_tool("wg") else None)

    if iface_ok and awg_bin:
        try:
            r_hs = _run([awg_bin, "show", AWG_INTERFACE, "latest-handshakes"],
                        capture=True, check=False)
            if r_hs.returncode == 0 and r_hs.stdout.strip():
                for _line in r_hs.stdout.strip().splitlines():
                    _parts = _line.split()
                    if len(_parts) >= 2:
                        try:
                            _ts = int(_parts[-1])
                        except ValueError:
                            continue
                        if _ts > 0:
                            _ago = int(time.time()) - _ts
                            _ago_str = f"{_ago}с" if _ago < 120 else f"{_ago // 60}м {_ago % 60}с"
                            handshake_ok  = True
                            handshake_str = _ago_str
                            break
                if handshake_ok:
                    _hc = GREEN if int(time.time()) - _ts < 180 else YELLOW
                    results.append(f"  {_ok}  Handshake: {_hc}{handshake_str} назад{NC}")
                    log_to_file("DEBUG", f"awg_verify: handshake OK, {handshake_str} ago")
                else:
                    results.append(f"  {_warn}  Handshake: не установлен "
                                   f"{DIM}(peer подключён?){NC}")
                    log_to_file("WARN", "awg_verify: no handshake yet")
            else:
                results.append(f"  {_warn}  Handshake: нет данных от awg show")
                log_to_file("WARN", f"awg_verify: awg show rc={r_hs.returncode}")
        except Exception as _e:
            results.append(f"  {_skip}  Handshake: ошибка ({_e})")
            log_to_file("WARN", f"awg_verify: handshake check error: {_e}")
    elif not awg_bin:
        results.append(f"  {_skip}  Handshake: awg/wg бинарник не найден")
        log_to_file("WARN", "awg_verify: no awg/wg binary for handshake check")
    else:
        results.append(f"  {_skip}  Handshake: пропущен (интерфейс не поднят)")

    # ── 3. Transfer (sent > 0 и received > 0) ────────────────────────────────
    transfer_sent = transfer_recv = 0
    if iface_ok and awg_bin:
        try:
            r_tr = _run([awg_bin, "show", AWG_INTERFACE, "transfer"],
                        capture=True, check=False)
            if r_tr.returncode == 0 and r_tr.stdout.strip():
                for _line in r_tr.stdout.strip().splitlines():
                    _parts = _line.split()
                    # формат: <pubkey> <received_bytes> <sent_bytes>
                    if len(_parts) >= 3:
                        try:
                            transfer_recv += int(_parts[1])
                            transfer_sent += int(_parts[2])
                        except ValueError:
                            pass
                def _fmt_bytes(b: int) -> str:
                    if b >= 1024 * 1024:
                        return f"{b / (1024*1024):.1f} МБ"
                    if b >= 1024:
                        return f"{b / 1024:.1f} КБ"
                    return f"{b} Б"
                if transfer_sent > 0 and transfer_recv > 0:
                    results.append(f"  {_ok}  Трафик: ↑{_fmt_bytes(transfer_sent)} "
                                   f"↓{_fmt_bytes(transfer_recv)} {DIM}(двусторонний){NC}")
                    log_to_file("DEBUG", f"awg_verify: transfer OK sent={transfer_sent} recv={transfer_recv}")
                elif transfer_sent > 0 and transfer_recv == 0:
                    results.append(f"  {_warn}  Трафик: ↑{_fmt_bytes(transfer_sent)} ↓0 "
                                   f"{YELLOW}(односторонний — закрыт входящий UDP?){NC}")
                    log_to_file("WARN", f"awg_verify: one-way tunnel sent={transfer_sent} recv=0")
                else:
                    results.append(f"  {_skip}  Трафик: нет данных "
                                   f"{DIM}(handshake ещё не прошёл){NC}")
                    log_to_file("DEBUG", "awg_verify: no transfer data yet")
        except Exception as _e:
            results.append(f"  {_skip}  Трафик: ошибка ({_e})")
            log_to_file("WARN", f"awg_verify: transfer check error: {_e}")
    else:
        results.append(f"  {_skip}  Трафик: пропущен")

    # ── 4. Ping до внутреннего IP exit-VPS через awg0 ────────────────────────
    _server_ip_raw = AWG_SERVER_IP.split("/")[0] if AWG_SERVER_IP else ""
    if iface_ok and _server_ip_raw:
        try:
            r_ping = _run(
                ["ping", "-c", "2", "-W", "3", "-I", AWG_INTERFACE, _server_ip_raw],
                capture=True, check=False
            )
            if r_ping.returncode == 0:
                _m = re.search(r"time=([\d.]+)", r_ping.stdout)
                _lat = f"{int(float(_m.group(1)))} мс" if _m else "OK"
                _lc  = GREEN if _m and float(_m.group(1)) < 150 else                        YELLOW if _m and float(_m.group(1)) < 300 else RED
                results.append(f"  {_ok}  Ping → {_server_ip_raw}: {_lc}{_lat}{NC}")
                log_to_file("DEBUG", f"awg_verify: ping {_server_ip_raw} OK lat={_lat}")
            else:
                results.append(f"  {_warn}  Ping → {_server_ip_raw}: нет ответа "
                               f"{DIM}(туннель не двусторонний?){NC}")
                log_to_file("WARN", f"awg_verify: ping {_server_ip_raw} failed rc={r_ping.returncode}")
        except Exception as _e:
            results.append(f"  {_skip}  Ping: ошибка ({_e})")
            log_to_file("WARN", f"awg_verify: ping error: {_e}")
    elif _server_ip_raw:
        results.append(f"  {_skip}  Ping: пропущен (интерфейс не поднят)")
    else:
        results.append(f"  {_skip}  Ping: AWG_SERVER_IP не задан")

    # ── 5. Policy routing ─────────────────────────────────────────────────────
    # 5a. ip rule fwmark
    r_rule = _run(["ip", "rule", "show"], capture=True, check=False)
    _rule_txt = r_rule.stdout or ""
    fwmark_rule_ok = str(AWG_FWMARK) in _rule_txt
    if fwmark_rule_ok:
        results.append(f"  {_ok}  ip rule fwmark {AWG_FWMARK} → table {AWG_ROUTE_TABLE}")
        log_to_file("DEBUG", f"awg_verify: fwmark rule OK")
    else:
        results.append(f"  {_warn}  ip rule: fwmark {AWG_FWMARK} не найдено")
        log_to_file("WARN", f"awg_verify: fwmark {AWG_FWMARK} missing from ip rule show")

    # 5b. Маршрут в таблице
    r_rt = _run(["ip", "route", "show", "table", str(AWG_ROUTE_TABLE)],
                capture=True, check=False)
    route_ok = r_rt.returncode == 0 and bool((r_rt.stdout or "").strip())
    if route_ok:
        results.append(f"  {_ok}  Маршрут в таблице {AWG_ROUTE_TABLE}: "
                       f"{DIM}{(r_rt.stdout or '').strip()[:40]}{NC}")
        log_to_file("DEBUG", f"awg_verify: route table {AWG_ROUTE_TABLE} OK")
    else:
        results.append(f"  {_warn}  Маршрут в таблице {AWG_ROUTE_TABLE}: отсутствует")
        log_to_file("WARN", f"awg_verify: no route in table {AWG_ROUTE_TABLE}")

    # 5c. iptables mangle OUTPUT (uid xray)
    try:
        _xray_uid = pwd.getpwnam("xray").pw_uid
        r_ipt = _run(
            ["iptables", "-t", "mangle", "-C", "OUTPUT",
             "-m", "owner", "--uid-owner", str(_xray_uid),
             "-j", "MARK", "--set-mark", str(AWG_FWMARK)],
            capture=True, check=False
        )
        if r_ipt.returncode == 0:
            results.append(f"  {_ok}  iptables mangle: uid(xray={_xray_uid}) → "
                           f"mark {AWG_FWMARK}")
            log_to_file("DEBUG", "awg_verify: iptables mangle rule OK")
        else:
            results.append(f"  {_warn}  iptables mangle: правило для uid(xray) не найдено")
            log_to_file("WARN", "awg_verify: iptables mangle rule missing")
    except KeyError:
        results.append(f"  {_skip}  iptables mangle: пользователь xray не найден")
        log_to_file("WARN", "awg_verify: xray user not found for iptables check")
    except Exception as _e:
        results.append(f"  {_skip}  iptables mangle: ошибка проверки ({_e})")
        log_to_file("WARN", f"awg_verify: iptables check error: {_e}")

    # ── Итоговый бокс ─────────────────────────────────────────────────────────
    print()
    _box_top("AWG: результаты верификации")
    for _line in results:
        _box_row(_line)
    _box_sep()

    # Диагностические подсказки при проблемах
    _hints: list[str] = []
    if not iface_ok:
        _hints.append(f"journalctl -u amneziawg-awg0 -n 30")
        _hints.append(f"awg-quick up {_AWG_ACTIVE_CONF}")
    if iface_ok and not fwmark_rule_ok:
        _hints.append(f"ip rule add fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE} priority 100")
    if iface_ok and not route_ok:
        _hints.append(f"ip route add default dev {AWG_INTERFACE} table {AWG_ROUTE_TABLE}")
    if transfer_sent > 0 and transfer_recv == 0:
        _hints.append(f"# На exit-VPS: проверьте входящий UDP/{AWG_EXIT_PORT}")
        _hints.append(f"iptables -A INPUT -p udp --dport {AWG_EXIT_PORT} -j ACCEPT")

    if _hints:
        _box_warn("Команды для ручного исправления:")
        for _h in _hints:
            _box_row(f"  {DIM}{_h}{NC}")
    else:
        _box_ok("Все слои верификации пройдены")

    _box_bottom()

    if not iface_ok:
        log_to_file("WARN", "awg_verify_tunnel: FAILED — interface not up")
        return False

    log_to_file("DEBUG", "awg_verify_tunnel: OK")
    return True


# === FIX EXTRA: принудительный сброс зависших AWG-интерфейсов ===
def _awg_cleanup_stale_interfaces(target: str = "local", remote_host: str = None) -> None:
    """
    Принудительно удаляет все зависшие AWG-интерфейсы и очищает связанные
    ip rule/route, чтобы избежать "Interface already exists" / "File exists"
    при повторных установках.

    target="local"  — выполняется локально.
    target="remote" — выполняется на remote_host через встроенную SSH-обёртку
                      (использует AWG_SSH_AUTH_METHOD / AWG_SSH_PASSWORD, как
                      в awg_setup_remote_server).
    Абсолютно идемпотентна: все команды с 2>/dev/null || true.
    """
    _cleanup_bash = (
        # 1. Останавливаем сервисы
        "for i in $(seq 0 9); do "
        "systemctl stop amneziawg-awg${i}.service wg-quick@awg${i}.service 2>/dev/null || true; "
        "done; "
        # 2. Удаляем интерфейсы
        "for i in $(seq 0 9); do "
        "ip link delete dev awg${i} 2>/dev/null || true; "
        "done; "
        # 3. Flush через тип (fallback-safe)
        "ip -s link flush type amneziawg 2>/dev/null || true; "
        # 4. Удаляем конфиги и симлинки
        "rm -f /etc/amnezia/amneziawg/awg*.conf /etc/wireguard/awg*.conf 2>/dev/null || true; "
        # 5. Чистим ip rule / ip route для таблиц 1000-1009
        "for i in $(seq 0 9); do "
        "ip rule del fwmark $((1000 + i)) 2>/dev/null || true; "
        "ip -6 rule del fwmark $((1000 + i)) 2>/dev/null || true; "
        "ip route flush table $((1000 + i)) 2>/dev/null || true; "
        "ip -6 route flush table $((1000 + i)) 2>/dev/null || true; "
        "done"
    )

    if target == "remote":
        if not remote_host:
            log_to_file("WARN", "_awg_cleanup_stale_interfaces: remote_host не задан — пропуск")
            return
        info(f"AWG: очистка зависших интерфейсов на {remote_host}...")
        # Используем ту же SSH-логику что и awg_setup_remote_server:
        # строим _ssh_base из глобальных AWG_SSH_AUTH_METHOD / AWG_SSH_PASSWORD
        _auth   = AWG_SSH_AUTH_METHOD
        _passwd = AWG_SSH_PASSWORD
        _common = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=15",
            "-o", "LogLevel=ERROR",
            "-o", "UserKnownHostsFile=/dev/null",
        ]
        _env = None
        if _auth == "password" and _passwd and _awg_ensure_sshpass():
            _env      = {**os.environ, "SSHPASS": _passwd}
            _ssh_base = ["sshpass", "-e", "ssh", *_common,
                         "-o", "PasswordAuthentication=yes", "-o", "BatchMode=no"]
        else:
            ssh_key = None
            for _cand in ["~/.ssh/id_ed25519", "~/.ssh/id_rsa",
                          "~/.ssh/id_ecdsa",   "~/.ssh/id_dsa"]:
                _kp = Path(_cand).expanduser()
                if _kp.exists():
                    ssh_key = str(_kp)
                    break
            _k_extra  = (["-i", ssh_key] if ssh_key else []) + ["-o", "BatchMode=yes"]
            _ssh_base = ["ssh", *_common, *_k_extra]

        try:
            r = subprocess.run(
                [*_ssh_base, f"root@{remote_host}", f"bash -c '{_cleanup_bash}'"],
                capture_output=True, text=True, env=_env, timeout=60,
            )
            if r.returncode == 0:
                success(f"AWG: remote cleanup на {remote_host} — OK")
            else:
                log_to_file("WARN",
                    f"_awg_cleanup_stale_interfaces remote rc={r.returncode}: {r.stderr[:200]}")
        except subprocess.TimeoutExpired:
            log_to_file("WARN", f"_awg_cleanup_stale_interfaces remote timeout на {remote_host}")
        except Exception as e:
            log_to_file("WARN", f"_awg_cleanup_stale_interfaces remote error: {e}")
    else:
        info("AWG: очистка зависших интерфейсов (local)...")
        r = _run(["bash", "-c", _cleanup_bash], check=False, quiet=True)
        if r.returncode == 0:
            success("AWG: local cleanup — OK")
        else:
            log_to_file("WARN",
                f"_awg_cleanup_stale_interfaces local rc={r.returncode}: {r.stderr[:200]}")
# === END FIX EXTRA ===


def awg_full_setup() -> None:
    """
    Точка входа — полная установка AWG в Режиме B.
    Вызывается из do_full_install() при AWG_EXIT_ENABLED == True.

    Порядок действий:
    1. Настройка клиента на RU-VPS (установка + генерация ключей + конфиги)
    2. Установка и запуск AWG-сервера на exit-VPS по SSH
    3. Поднятие AWG-туннеля (awg-quick up awg0)
    4. Применение policy routing (Xray uid → fwmark → awg0)
    5. Перезапуск Xray
    6. Верификация туннеля
    """
    global AWG_INSTALLED

    if not AWG_EXIT_ENABLED:
        return

    # === FIX EXTRA: сброс зависших интерфейсов перед установкой ===
    _awg_cleanup_stale_interfaces(target="local")
    # === END FIX EXTRA ===

    # ── Заголовочный бокс: голубая рамка, жёлтый жирный заголовок ────────
    print()
    _AWG_TITLE       = "AmneziaWG 2.0 — Установка"
    _AWG_TITLE_COLOR = '\033[1;33m'   # жёлтый + жирный
    _title_lpad = (_BOX_W - len(_AWG_TITLE)) // 2
    _title_rpad = _BOX_W - len(_AWG_TITLE) - _title_lpad
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    print(f"{CYAN}║{NC}{' ' * _title_lpad}{_AWG_TITLE_COLOR}{_AWG_TITLE}{NC}{' ' * _title_rpad}{CYAN}║{NC}")
    _scheme_text = f"  Схема: Клиент → Xray(RU) → awg0 → {AWG_EXIT_HOST} → Интернет"
    _scheme_pad  = max(0, _BOX_W - _wcslen(_scheme_text))
    print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")
    print(f"{CYAN}║{NC}{_scheme_text}{' ' * _scheme_pad}{CYAN}║{NC}")
    print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")
    print()

    try:
        # === PATCH v2 п.6: мульти-нодовый путь (реальный код вместо заглушки) ===
        if len(AWG_NODES) > 1:
            print(f"  {YELLOW}[1/6]{NC} Установка {len(AWG_NODES)} AWG-нод (Multi-Node)...")
            if not awg_setup_all_nodes():
                warn("AWG Multi-Node: ни одна нода не настроена — прерываем")
                return

            print(f"  {YELLOW}[3/6]{NC} Поднятие всех туннелей...")
            _awg_bring_up_all_tunnels()

            print(f"  {YELLOW}[4/6]{NC} Настройка policy routing для всех нод...")
            _awg_apply_policy_routing_all_nodes()

            print(f"  {YELLOW}[4.5/6]{NC} Установка Multi-Node Watchdog...")
            try:
                awg_multinode_watchdog_install()
            except Exception as _wde:
                warn(f"AWG Multi-Node Watchdog: {_wde}")

            # === PATCH v2 п.7: строгий порядок запуска сервисов ===
            print(f"  {YELLOW}[5/6]{NC} Последовательный запуск сервисов...")
            _awg_ifaces = [n["interface"] for n in AWG_NODES]
            _start_services_sequentially(
                dnscrypt_enabled=PARAM_USE_DNSCRYPT,
                awg_interfaces=_awg_ifaces,
                xray_restart=True,
            )

            print(f"  {YELLOW}[6/6]{NC} Верификация туннелей...")
            _awg_verify_all_tunnels()
            AWG_INSTALLED = True
            return   # выходим: финальный бокс single-node не нужен

        # ── SINGLE-NODE PATH (оригинальный код) ───────────────────────────────
        # ── Шаг 1: клиент на RU-VPS ───────────────────────────────────────
        print(f"  {YELLOW}[1/6]{NC} Установка AWG-клиента на RU-VPS...")
        if not awg_setup_local_client():
            warn("AWG: не удалось настроить клиент — AWG пропускается")
            return

        # ── Шаг 2: сервер на exit-VPS ─────────────────────────────────────
        print(f"  {YELLOW}[2/6]{NC} Установка AWG-сервера на {AWG_EXIT_HOST}...")
        remote_ok = awg_setup_remote_server()

        # ── Шаг 3: поднимаем туннель ──────────────────────────────────────
        print(f"  {YELLOW}[3/6]{NC} Поднятие туннеля awg0...")
        _up_impl = _awg_detect_implementation()
        _up_impl_pfx = f"WG_QUICK_USERSPACE_IMPLEMENTATION={_up_impl} " if _up_impl else ""
        r_up = _run(
            ["bash", "-c",
             "AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
             f"{_up_impl_pfx}"
             "$AWG_BIN up /etc/amnezia/amneziawg/awg0.conf"],
            check=False, quiet=True
        )
        if r_up.returncode == 0:
            success("AWG: туннель awg0 поднят")
        else:
            r_chk = _run(["ip", "link", "show", "awg0"], capture=True, check=False)
            if r_chk.returncode == 0:
                success("AWG: туннель awg0 уже активен")
            else:
                warn(f"AWG: awg-quick up → rc={r_up.returncode}: {r_up.stderr[:150]}")
                log_to_file("WARN", f"awg-quick up awg0: {r_up.stderr}")

        # ── Шаг 4: policy routing ─────────────────────────────────────────
        print(f"  {YELLOW}[4/6]{NC} Настройка policy routing...")
        awg_apply_policy_routing()

        # ── Шаг 4.5: AWG Tunnel Watchdog ──────────────────────────────────
        print(f"  {YELLOW}[4.5/6]{NC} Установка watchdog мониторинга туннеля awg0...")
        try:
            awg_watchdog_install()
        except Exception as _wde:
            warn(f"AWG Watchdog: установка не критична, пропуск: {_wde}")

        # ── Шаг 5: перезапуск Xray ────────────────────────────────────────
        print(f"  {YELLOW}[5/6]{NC} Перезапуск Xray...")
        _xray_cfg_exists = (
            (CONFIG_DIR / "config.json").exists()
            or Path("/usr/local/etc/xray/config.json").exists()
        )
        if _xray_cfg_exists:
            _run(["systemctl", "restart", "xray"], check=False, quiet=True)
            time.sleep(2)
            r_xray = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
            if r_xray.stdout.strip() == "active":
                success("AWG: Xray активен")
            else:
                warn("AWG: Xray не запустился — проверьте: journalctl -u xray -n 30")
        else:
            warn(
                f"AWG: конфиг Xray не найден ({CONFIG_DIR / 'config.json'}) — "
                "пропускаем перезапуск. Выполните установку Xray (пункт 1 меню) "
                "и затем перезапустите: systemctl restart xray"
            )

        # ── Шаг 6: верификация ────────────────────────────────────────────
        print(f"  {YELLOW}[6/6]{NC} Верификация...")
        awg_verify_tunnel()

        AWG_INSTALLED = True

        # ── Финальный бокс — полностью зелёный ───────────────────────────
        print()
        _AWG_DONE     = "AmneziaWG 2.0 установлен и настроен"
        _done_lpad    = (_BOX_W - len(_AWG_DONE)) // 2
        _done_rpad    = _BOX_W - len(_AWG_DONE) - _done_lpad
        print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
        print(f"{CYAN}║{NC}{' ' * _done_lpad}{GREEN}{BOLD}{_AWG_DONE}{NC}{' ' * _done_rpad}{CYAN}║{NC}")
        print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")
        # детали — через _box_row (голубые ║)
        _box_row_auto(f"  Клиентский конфиг RU-VPS:  {_AWG_ACTIVE_CONF}", cont_indent="    ")
        _box_row_auto(f"  Серверный шаблон exit-VPS: {_AWG_CONF_DIR}/awg0-server-template.conf", cont_indent="    ")
        _box_row(f"  Интерфейс:   {AWG_INTERFACE}")
        _box_row_auto(f"  Policy:      uid(xray) → mark {AWG_FWMARK} → table {AWG_ROUTE_TABLE} → {AWG_INTERFACE}", cont_indent="               ")
        if not remote_ok:
            _box_sep()
            _box_warn("Exit-VPS требует РУЧНОЙ НАСТРОЙКИ (SSH недоступен)!")
            _box_wrap_msg(
                f"  {YELLOW}", 2,
                f"Следуйте инструкции выше или запустите скрипт снова после настройки SSH.{NC}"
            )
        _box_bottom()

    except Exception as exc:
        warn(f"AWG: критическая ошибка: {exc}")
        log_to_file("ERROR", f"awg_full_setup exception: {exc}")
        try:
            awg_rollback()
        except Exception as rb:
            warn(f"AWG: ошибка rollback: {rb}")

def do_full_install() -> None:
    global INSTALL_STARTED, PARAM_USE_DNSCRYPT, DNSCRYPT_INSTALLED
    global SPLIT_TUNNEL_ENABLED, SPLIT_TUNNEL_EXTRA_DOMAINS, SPLIT_TUNNEL_EXTRA_IPS
    global H2_EXIT_ENABLED

    PROGRESS.init(100, "Установка")

    _check_resources()
    _check_ipv6_preflight()
    PROGRESS.update(3, "Проверки")
    print()  # завершить строку прогресс-бара перед отрисовкой бокса

    # ── Выбор режима ──────────────────────────────────────────────────────────
    try:
        prompt_install_mode()

        # ── Выбор протокола (REALITY / xHTTP TLS) ────────────────────────────────
        prompt_protocol_mode()

        # ── Общие параметры (UUID, ключи, домен, ...) ────────────────────────────
        prompt_parameters()

        # ── Для Режима B — сначала выбираем транспорт, потом (если VLESS) ноды ───
        if INSTALL_MODE == "B":
            # Шаг 1: выбор транспорта (VLESS, AWG или Hysteria2).
            # AWG_EXIT_ENABLED / H2_EXIT_ENABLED устанавливаются внутри prompt_awg_exit_mode().
            prompt_awg_exit_mode()
            # Шаг 2: VLESS-ноды нужны ТОЛЬКО при VLESS-транспорте.
            # При AWG или H2 ввод exit-нод пропускается полностью (никаких фейковых данных).
            if not AWG_EXIT_ENABLED and not H2_EXIT_ENABLED:
                prompt_chain_params_multi()

        # ── Раздельное туннелирование (split tunneling) ──────────────────────────
        prompt_split_tunnel()

    except KeyboardInterrupt:
        print()
        print(f"{YELLOW}[Отмена]{NC} Настройка установки прервана — возврат в меню.")
        log_to_file("INFO", "do_full_install: прервано пользователем (Ctrl+C) на этапе настройки")
        return

    if LOCK_FILE.exists():
        print()
        _box_top(f"Обнаружена предыдущая установка")
        _box_warn(f"Файл {LOCK_FILE} уже существует.")
        _box_item("C", f"Продолжить (перезаписать)")
        _box_item("Q", f"Выйти")
        _box_bottom()
        while True:
            choice = input("  Выбор [C/Q]: ").strip().lower()
            if choice == 'c':
                break
            elif choice in ('q', ''):
                sys.exit(0)
            warn("Введите C или Q")

    create_backup()
    INSTALL_STARTED = True

    install_dependencies();         PROGRESS.update(5,  "Зависимости")
    install_dnscrypt();             PROGRESS.update(5,  "DNSCrypt")
    if PARAM_USE_DNSCRYPT:
        apply_dnscrypt_tuning()
    configure_firewall();           PROGRESS.update(5,  "Файрволл")

    # Проверяем доступность порта снаружи — только предупреждение, не блокировка.
    # Если провайдер управляет файрволом на уровне гипервизора (AEZA и др.),
    # iptables правил скрипта может быть недостаточно.
    try:
        import socket as _sock
        _s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        _s.settimeout(3)
        _local_ip = _sock.gethostbyname(_sock.gethostname())
        _res = _s.connect_ex((_local_ip, SERVER_PORT))
        _s.close()
        if _res != 0:
            warn(f"Порт {SERVER_PORT}/tcp может быть недоступен снаружи.")
            warn(f"Если клиент не подключается — откройте порт {SERVER_PORT}/tcp")
            warn(f"в панели управления вашего провайдера.")
    except Exception:
        pass

    apply_network_optimizations();  PROGRESS.update(5,  "Оптимизация")
    install_xray();                 PROGRESS.update(10, "Xray")
    generate_reality_keys();        PROGRESS.update(3,  "Ключи")

    # ── Загрузка geo-файлов (всегда — нужны для маршрутизации Xray) ─────────
    if not download_geo_files():
        warn("Не удалось загрузить geo-файлы — geosite/geoip правила будут недоступны")
    if SPLIT_TUNNEL_ENABLED:
        setup_geo_autoupdate()
    PROGRESS.update(3, "Geo-файлы")

    # ── Генерация конфига Xray в зависимости от режима и протокола ───────────
    if INSTALL_MODE == "B":
        generate_xray_config_chain_entry_multi()   # Entry node (все ноды, balancer, REALITY или xHTTP)
        generate_xray_config_chain_exit()           # Шаблоны конфигов для каждого exit VPS
        PROGRESS.update(5, "Конфиг Xray (chain)")
        
        # -- AWG 2.0: установка клиента на RU-сервере и сервера на exit-VPS -----
        if AWG_EXIT_ENABLED:
            awg_full_setup()
            PROGRESS.update(8, "AmneziaWG 2.0")
            # BUGFIX: после awg_full_setup() конфиг xray нужно перегенерировать
            # с корректными PARAM_REALITY_DEST (dest/serverNames).
            info("Mode B + AWG: повторная генерация config.json с AWG-параметрами...")
            generate_xray_config_chain_entry_multi()
            PROGRESS.update(2, "Конфиг Xray (AWG patch)")
        # ← НИКАКОГО else! Не перезаписываем конфиг каскада!

        # -- Hysteria2: информирование — реальная установка через меню 7 ---------
        # Xray-конфиг уже сгенерирован выше (generate_xray_config_chain_entry_multi).
        # H2 не меняет конфиг Xray, не трогает сервисы — только сохраняет флаг.
        if H2_EXIT_ENABLED:
            PROGRESS.update(2, "Hysteria2 (отмечен)")
            info("Mode B + H2: транспорт Hysteria2 выбран — настройте exit-ноду через меню 7.")
        
    elif INSTALL_MODE == "A":
        if AWG_EXIT_ENABLED:
            awg_full_setup()
            PROGRESS.update(8, "AmneziaWG 2.0")
        
        if PROTOCOL_MODE == "xhttp":
            generate_xray_config_xhttp()           # Режим A, xHTTP TLS
        else:
            generate_xray_config()                 # Режим А, REALITY (стандарт)
        PROGRESS.update(5, "Конфиг Xray")
    create_xray_service();          PROGRESS.update(3,  "Systemd")
    setup_fail2ban();               PROGRESS.update(3,  "Fail2ban")
    setup_nginx_temp();             PROGRESS.update(3,  "Nginx temp")
    obtain_ssl_cert();              PROGRESS.update(10, "SSL")

    # xHTTP TLS: пересоздаём конфиг Xray после получения сертификата,
    # т.к. при первой генерации сертификат ещё не существовал и xray -test падал.
    if PROTOCOL_MODE == "xhttp" and INSTALL_MODE != "B":
        info("xHTTP TLS: повторная генерация конфига Xray (сертификат теперь на месте)...")
        generate_xray_config_xhttp()
    elif PROTOCOL_MODE == "xhttp" and INSTALL_MODE == "B":
        info("xHTTP TLS (Режим B): повторная генерация конфига Entry Node...")
        generate_xray_config_chain_entry_multi()

    setup_nginx_rate_limit();       PROGRESS.update(2,  "Rate limit")
    setup_nginx_final();            PROGRESS.update(5,  "Nginx final")
    setup_nginx_systemd_override(); PROGRESS.update(2,  "Nginx override")
    setup_cert_renewal();           PROGRESS.update(2,  "Cert renewal")
    setup_logrotate();              PROGRESS.update(2,  "Logrotate")
    setup_xray_autoupdate();        PROGRESS.update(5,  "Autoupdate")

    info("Запуск сервисов в правильном порядке...")
    PROGRESS.update(5, "Запуск")

    # Шаг 1: DNSCrypt-proxy
    if PARAM_USE_DNSCRYPT:
        info("Шаг 1/3: запуск DNSCrypt-proxy...")
        _run(["systemctl", "stop",  "dnscrypt-proxy"], check=False, quiet=True)
        time.sleep(1)
        _run(["systemctl", "start", "dnscrypt-proxy"], check=False, quiet=True)
        if _wait_service_active("dnscrypt-proxy", 30):
            dc_port_ok = False
            for _ in range(5):
                r = _run(["ss", "-ulnp"], capture=True, check=False)
                if f":{DNSCRYPT_LISTEN_PORT} " in r.stdout:
                    dc_port_ok = True
                    break
                time.sleep(1)
            if dc_port_ok:
                success(f"  DNSCrypt-proxy слушает на :{DNSCRYPT_LISTEN_PORT}")
            else:
                warn(f"  DNSCrypt-proxy активен но порт :{DNSCRYPT_LISTEN_PORT} ещё не слушает")
        else:
            warn("  DNSCrypt-proxy не запустился — Xray будет использовать публичный DNS")
            DNSCRYPT_INSTALLED = False
            info("  Обновляем конфиг Xray для публичного DNS...")
            PARAM_USE_DNSCRYPT = False
            if INSTALL_MODE == "B":
                generate_xray_config_chain_entry_multi()
            else:
                if PROTOCOL_MODE == "xhttp":
                    generate_xray_config_xhttp()
                else:
                    generate_xray_config()
    else:
        info("Шаг 1/3: DNSCrypt-proxy пропущен (не выбран)")

    # Шаг 2: Xray ПЕРВЫМ — очищает старый сокет, создаёт новый
    info("Шаг 2/3: запуск Xray...")
    sock_parent = Path(PARAM_SOCKET_PATH).parent
    sock_parent.mkdir(parents=True, exist_ok=True)
    _run(["chown", "xray:xray", str(sock_parent)], check=False, quiet=True)
    sock_parent.chmod(0o755)
    _run(["usermod", "-aG", "xray", "www-data"], check=False, quiet=True)

    if PROTOCOL_MODE == "xhttp":
        fix_letsencrypt_permissions(PARAM_DOMAIN)

    _run(["systemctl", "stop",  "xray"], check=False, quiet=True)
    time.sleep(1)
    _run(["systemctl", "start", "xray"], check=False, quiet=True)

    xray_started = False
    if _wait_service_active("xray", 20):
        xray_started = True
    else:
        warn("  Повторный запуск Xray...")
        _run(["systemctl", "stop",  "xray"], check=False, quiet=True)
        time.sleep(3)
        _run(["systemctl", "start", "xray"], check=False, quiet=True)
        if _wait_service_active("xray", 15):
            xray_started = True

    if not xray_started:
        warn("Xray не запустился — проверьте: journalctl -u xray -n 30")

    # Шаг 3: Nginx ВТОРЫМ — подключается к сокету созданному xray
    info("Шаг 3/3: запуск Nginx...")
    # === FIX 4: Ожидание socket только в классическом режиме (не AWG) ===
    # В AWG-режиме Xray слушает напрямую на TCP-порту, unix socket не создаётся.
    # Без этой проверки цикл ждёт 30 секунд зря при каждой AWG-установке.
    if PROTOCOL_MODE == "reality" and xray_started and not AWG_EXIT_ENABLED:
        info("  Ожидание Unix-сокета от Xray...")
        for i in range(1, 31):
            if Path(PARAM_SOCKET_PATH).is_socket():
                success(f"  Сокет готов: {PARAM_SOCKET_PATH}")
                break
            time.sleep(1)
        else:
            warn("  Сокет не появился — проверьте journalctl -u xray -n 20")
    elif AWG_EXIT_ENABLED:
        info("  AWG-режим: unix socket не используется, Xray слушает TCP напрямую")
    # === END FIX 4 ===

    _run(["systemctl", "stop",  "nginx"], check=False, quiet=True)
    time.sleep(1)
    _run(["systemctl", "start", "nginx"], check=False, quiet=True)
    if not _wait_service_active("nginx", 15):
        warn("  Nginx не запустился — journalctl -u nginx -n 20")
    else:
        success("  Nginx активен")

    PROGRESS.update(5, "Проверки")

    time.sleep(3)
    run_full_health_check()
    _box_top("Проверка сетевой доступности")
    verify_connectivity()
    _box_bottom()

    # Сохранение state.json
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    state = {
        "installed":      True,
        "install_mode":   INSTALL_MODE,
        "protocol_mode":  PROTOCOL_MODE,
        "xhttp_mode":     XHTTP_MODE,
        "xhttp_path":     XHTTP_PATH,
        "xhttp_perf_preset": XHTTP_PERF_PRESET,
        "xhttp_padding_bytes":           XHTTP_PADDING_BYTES,
        "xhttp_no_sse_header":           XHTTP_NO_SSE_HEADER,
        "xhttp_no_grpc_header":          XHTTP_NO_GRPC_HEADER,
        "xhttp_host":                    XHTTP_HOST,
        "xhttp_sc_stream_up_server_secs": XHTTP_SC_STREAM_UP_SERVER_SECS,
        "xhttp_sc_max_each_post_bytes":  XHTTP_SC_MAX_EACH_POST_BYTES,
        "xhttp_sc_min_posts_interval_ms": XHTTP_SC_MIN_POSTS_INTERVAL_MS,
        "xhttp_sc_max_buffered_posts":   XHTTP_SC_MAX_BUFFERED_POSTS,
        "xhttp_xmux_enabled":            XHTTP_XMUX_ENABLED,
        "xhttp_xmux_max_concurrency":    XHTTP_XMUX_MAX_CONCURRENCY,
        "xhttp_xmux_max_connections":    XHTTP_XMUX_MAX_CONNECTIONS,
        "xhttp_xmux_c_max_reuse_times":  XHTTP_XMUX_C_MAX_REUSE_TIMES,
        "xhttp_xmux_h_max_request_times": XHTTP_XMUX_H_MAX_REQUEST_TIMES,
        "xhttp_xmux_h_max_reusable_secs": XHTTP_XMUX_H_MAX_REUSABLE_SECS,
        "xhttp_xmux_h_keep_alive_period": XHTTP_XMUX_H_KEEP_ALIVE_PERIOD,
        "xhttp_tcp_no_delay":            XHTTP_TCP_NO_DELAY,
        "xhttp_enable_session_resumption": XHTTP_ENABLE_SESSION_RESUMPTION,
        "server_port":    SERVER_PORT,
        "domain":         PARAM_DOMAIN,
        "uuid":           PARAM_UUID,
        "public_key":     PARAM_PUBLIC_KEY,
        "private_key":    PARAM_PRIVATE_KEY,
        "short_id":       PARAM_SHORTID,
        "spiderx":        PARAM_SPIDERX,
        "socket":         PARAM_SOCKET_PATH,
        "strategy":       PARAM_DOMAIN_STRATEGY,
        "template":       PARAM_SITE_TEMPLATE,
        "email":          PARAM_EMAIL,
        "ipv6":           IPV6_PREFLIGHT,
        "use_dnscrypt":   PARAM_USE_DNSCRYPT,
        "fingerprint":    PARAM_FINGERPRINT,
        "split_tunnel":   SPLIT_TUNNEL_ENABLED,
        "split_extra_domains": SPLIT_TUNNEL_EXTRA_DOMAINS,
        "split_extra_ips":     SPLIT_TUNNEL_EXTRA_IPS,
        "installed_at":   datetime.now(timezone.utc).isoformat(),
    }
    if INSTALL_MODE == "B":
        state.update({
            "chain_exit_host":        CHAIN_EXIT_HOST,
            "chain_exit_port":        CHAIN_EXIT_PORT,
            "chain_exit_uuid":        CHAIN_EXIT_UUID,
            "chain_exit_pubkey":      CHAIN_EXIT_PUBKEY,
            "chain_exit_shortid":     CHAIN_EXIT_SHORTID,
            "chain_exit_sni":         CHAIN_EXIT_SNI,
            "chain_exit_fp":          CHAIN_EXIT_FP,
            "chain_nodes":            CHAIN_NODES,   # новый формат (мульти-нод)
            "chain_balancer_strategy": CHAIN_BALANCER_STRATEGY,
            # AWG 2.0
            "awg_exit_enabled":  AWG_EXIT_ENABLED,
            "awg_exit_host":     AWG_EXIT_HOST,
            "awg_exit_port":     AWG_EXIT_PORT,
            "awg_client_listen_port": AWG_CLIENT_LISTEN_PORT,
            "awg_interface":     AWG_INTERFACE,
            "awg_subnet":        AWG_SUBNET,
            "awg_subnet_v6":     AWG_SUBNET_V6,
            "awg_client_ipv6":   AWG_CLIENT_IPv6,
            "awg_server_ipv6":   AWG_SERVER_IPv6,
            "awg_installed":     AWG_INSTALLED,
            "awg_client_pubkey": AWG_CLIENT_PUBKEY,
            "awg_server_pubkey": AWG_SERVER_PUBKEY,
            "awg_fwmark":        AWG_FWMARK,
            "awg_route_table":   AWG_ROUTE_TABLE,
            # === PATCH v2: multi-node state fields ===
            "awg_nodes":             [{k: v for k, v in n.items() if k != "ssh_password"}
                                      for n in AWG_NODES] if AWG_NODES else [],
            "awg_active_node_index": AWG_ACTIVE_NODE_INDEX,
            "awg_ssh_client_ip":     _AWG_SSH_CLIENT_IP,
            # === END PATCH v2 ===
            "reality_dest":      PARAM_REALITY_DEST,
            # Hysteria2 транспорт
            "h2_exit_enabled":   H2_EXIT_ENABLED,
        })
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))

    # ── Финальная проверка: /etc/xray/config.json должен существовать ─────────
    _cfg_final = CONFIG_DIR / "config.json"
    _alt_cfg_final = Path("/usr/local/etc/xray/config.json")
    _config_creation_failed = False
    if not _cfg_final.exists() and not _alt_cfg_final.exists():
        _config_creation_failed = True
        log_to_file("ERROR",
            f"config.json НЕ СОЗДАН после установки! "
            f"Ожидался: {_cfg_final}. "
            f"INSTALL_MODE={INSTALL_MODE} AWG_EXIT_ENABLED={AWG_EXIT_ENABLED} "
            f"PROTOCOL_MODE={PROTOCOL_MODE}")
        warn(f"[КРИТИЧНО] {_cfg_final} не создан — установка НЕ СЧИТАЕТСЯ УСПЕШНОЙ!")
        warn("  Попробуйте вручную: из меню → пункт 'Пересоздать конфиг Xray'")
    else:
        _found = _cfg_final if _cfg_final.exists() else _alt_cfg_final
        log_to_file("INFO", f"config.json присутствует: {_found}")
        success(f"config.json создан: {_found}")

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    LOCK_FILE.write_text(
        f"{datetime.now().isoformat()} domain={PARAM_DOMAIN} mode={INSTALL_MODE}\n"
    )

    PROGRESS.update(10, "Готово")

    install_end  = time.time()
    install_dur  = int(install_end - INSTALL_START_TIME)
    ipv4_show    = get_server_ip("4")
    tmpl_names   = ["", "TechHub", "NexCloud", "Holm & Oak",
                    "Ember & Grain", "NexHub", "ByteForge"]

    try:
        r = _run(["sysctl", "-n", "net.ipv4.tcp_congestion_control"],
                 capture=True, check=False)
        bbr_status = r.stdout.strip()
    except Exception:
        bbr_status = "?"

    print()
    _box_top("УСТАНОВКА ЗАВЕРШЕНА УСПЕШНО ✓")
    if PROTOCOL_MODE == "xhttp":
        proto_label = f"VLESS + xHTTP + TLS (mode={XHTTP_MODE}, path={XHTTP_PATH})"
    else:
        proto_label = "VLESS + TCP + REALITY (xtls-rprx-vision)"
    _box_row(f"  Протокол:     {CYAN}{proto_label}{NC}")
    mode_label = "Обычный сервер (A)" if INSTALL_MODE == "A" else "Каскадный прокси (B) — Entry Node"
    _box_row(f"  Режим:        {CYAN}{mode_label}{NC}")
    _box_row(f"  SNI/Домен:    {CYAN}{PARAM_DOMAIN}{NC}")
    _box_row(f"  Порт:         {CYAN}{SERVER_PORT}{NC}")
    _box_sep()
    _box_row(f"  {YELLOW}Чувствительные параметры (сохраните!):{NC}")
    _box_row(f"  UUID:         {CYAN}{PARAM_UUID}{NC}")
    if PROTOCOL_MODE == "reality":
        _box_row(f"  Private Key:  {CYAN}{PARAM_PRIVATE_KEY}{NC}")
        _box_row(f"  Public Key:   {CYAN}{PARAM_PUBLIC_KEY}{NC}")
        _box_row(f"  Short ID:     {CYAN}{PARAM_SHORTID}{NC}")
        _box_row(f"  SpiderX:      {CYAN}{PARAM_SPIDERX}{NC}")
        _box_row(f"  Socket:       {CYAN}{PARAM_SOCKET_PATH}{NC}")
    else:
        _box_row(f"  xHTTP mode:   {CYAN}{XHTTP_MODE}{NC}")
        _box_row(f"  xHTTP path:   {CYAN}{XHTTP_PATH}{NC}")
        _box_row(f"  TLS cert:     {CYAN}/etc/letsencrypt/live/{PARAM_DOMAIN}/fullchain.pem{NC}")
    if INSTALL_MODE == "B":
        _box_sep()
        _box_row(f"  {GREEN}Exit Node(s) (зарубежный VPS, первый):{NC}")
        first_nd = CHAIN_NODES[0] if CHAIN_NODES else {}
        nd_host   = first_nd.get("host",    CHAIN_EXIT_HOST)
        nd_port   = first_nd.get("port",    CHAIN_EXIT_PORT)
        nd_uuid   = first_nd.get("uuid",    CHAIN_EXIT_UUID)
        nd_proto  = first_nd.get("proto",   "reality")
        nd_pubkey = first_nd.get("pubkey",  CHAIN_EXIT_PUBKEY)
        nd_sid    = first_nd.get("shortid", CHAIN_EXIT_SHORTID)
        nd_sni    = first_nd.get("sni",     CHAIN_EXIT_SNI)
        _box_row(f"  Host:         {CYAN}{nd_host}:{nd_port}{NC}")
        _box_row(f"  UUID:         {CYAN}{nd_uuid}{NC}")
        _box_row(f"  Proto:        {CYAN}{nd_proto.upper()}{NC}")
        if nd_proto == "reality" and nd_pubkey:
            _box_row(f"  PubKey:       {CYAN}{nd_pubkey[:30]}...{NC}")
            _box_row(f"  ShortID:      {CYAN}{nd_sid}{NC}")
        _box_row(f"  SNI:          {CYAN}{nd_sni}{NC}")
        if len(CHAIN_NODES) > 1:
            _box_row(f"  {DIM}(+ ещё {len(CHAIN_NODES)-1} нод в round-robin){NC}")
    _box_sep()
    _box_row(f"  Настройки:")
    if DNSCRYPT_INSTALLED:
        _box_row(f"  DNS:          {CYAN}DNSCrypt-proxy ({DNSCRYPT_LISTEN_ADDR}:{DNSCRYPT_LISTEN_PORT}) → fallback 1.1.1.1/8.8.8.8{NC}")
    elif IS_IPV6_AVAILABLE:
        _box_row(f"  DNS:          {CYAN}AdGuard IPv6 → CF IPv6 → Google IPv6 → fallback IPv4{NC}")
    else:
        _box_row(f"  DNS:          {CYAN}1.1.1.1 → 8.8.8.8 → 9.9.9.9 (IPv4){NC}")
    _box_row(f"  Strategy:     {CYAN}{PARAM_DOMAIN_STRATEGY}{NC}")
    if IS_IPV6_AVAILABLE:
        _box_row(f"  IPv6:         {GREEN}{IPV6_PREFLIGHT} (dual-stack активен){NC}")
    else:
        _box_row(f"  IPv6:         {YELLOW}не обнаружен (IPv4-only){NC}")
    _box_row(f"  Шаблон:       {CYAN}{tmpl_names[int(PARAM_SITE_TEMPLATE)]}{NC}")
    _box_row(f"  BBR:          {CYAN}{bbr_status}{NC}")
    _box_sep()
    _box_row(f"  IPv4:         {CYAN}{ipv4_show or 'н/д'}{NC}")
    if IS_IPV6_AVAILABLE:
        _box_row(f"  IPv6:         {CYAN}{IPV6_PREFLIGHT}{NC}")
    _box_sep()
    _box_row(f"  Файлы:")
    # Вычисляем ширину самого длинного пути для правильного выравнивания
    _f_paths = ["/root/vless_link.txt"]
    if IS_IPV6_AVAILABLE and INSTALL_MODE == "A":
        _f_paths.append("/root/vless_link_ipv6.txt")
    if INSTALL_MODE == "A":
        _f_paths += ["/root/vless_qr.png", "/root/vless_qr_ipv4.png"]
    if INSTALL_MODE == "B":
        if len(CHAIN_NODES) > 1:
            for _fi in range(len(CHAIN_NODES)):
                _f_paths.append(f"/root/xray_config_exit_node_{_fi+1}.json")
        else:
            _f_paths.append("/root/xray_config_exit_node.json")
        _f_paths.append("/root/vless_chain_summary.txt")
    _f_paths += [f"{CONFIG_DIR}/config.json", str(STATE_FILE)]
    _fcol_w = max(len(p) for p in _f_paths)
    _box_row(f"    {'/root/vless_link.txt':<{_fcol_w}}  — клиентская ссылка")
    if IS_IPV6_AVAILABLE and INSTALL_MODE == "A":
        _box_row(f"    {'/root/vless_link_ipv6.txt':<{_fcol_w}}  — ссылка IPv6")
    if INSTALL_MODE == "A":
        _box_row(f"    {'/root/vless_qr.png':<{_fcol_w}}  — QR-код")
        _box_row(f"    {'/root/vless_qr_ipv4.png':<{_fcol_w}}  — QR-код IPv4")
    if INSTALL_MODE == "B":
        if len(CHAIN_NODES) > 1:
            for i in range(len(CHAIN_NODES)):
                _p = f"/root/xray_config_exit_node_{i+1}.json"
                _box_row(f"    {_p:<{_fcol_w}}  — конфиг для exit VPS #{i+1}")
        else:
            _box_row(f"    {'/root/xray_config_exit_node.json':<{_fcol_w}}  — конфиг для exit VPS")
        _box_row(f"    {'/root/vless_chain_summary.txt':<{_fcol_w}}  — инструкция по каскаду")
    _box_row(f"    {str(CONFIG_DIR) + '/config.json':<{_fcol_w}}  — конфиг Xray")
    _box_row(f"    {str(STATE_FILE):<{_fcol_w}}  — параметры")
    _box_sep()
    _box_row(f"  Время установки: {install_dur} сек")
    _box_bottom()

    if INSTALL_MODE == "B":
        generate_chain_summary()
        # При AWG клиентам всё равно нужны VLESS-ссылки entry-ноды для подключения
        if AWG_EXIT_ENABLED:
            print()
            _box_row(f"  {CYAN}Ссылки для подключения клиентов (entry-нода):{NC}")
            generate_client_links()
    else:
        generate_client_links()

    # Синхронизируем начального пользователя в единый users.json
    try:
        existing = _unified_load_users()
        if not any(u.get("uuid") == PARAM_UUID for u in existing):
            existing.append({
                "uuid":    PARAM_UUID,
                "email":   PARAM_EMAIL or "default@xray",
                "name":    (PARAM_EMAIL or "default@xray").split("@")[0],
                "created": datetime.now(timezone.utc).isoformat(),
                "source":  INSTALL_MODE,
            })
            _users_save([{
                "uuid":    u["uuid"],
                "email":   u.get("email", ""),
                "name":    u.get("name", ""),
                "created": u.get("created", ""),
            } for u in existing])
    except Exception:
        pass

    print()
    _box_row(f"{GREEN}Сайт-заглушка: {BOLD}https://{PARAM_DOMAIN}{NC}")

    if _config_creation_failed:
        # Раньше тут безусловно печаталось "завершена успешно", даже когда
        # чуть выше уже было сказано [КРИТИЧНО] config.json не создан —
        # пользователь не понимал, что установка реально провалилась.
        error(f"=== Установка Режима {INSTALL_MODE} ПРЕРВАНА: config.json не создан "
              f"(см. [КРИТИЧНО] выше) за {install_dur}с ===")
        log_to_file("ERROR", f"=== Установка ПРЕРВАНА (config.json не создан) "
                              f"за {install_dur}с (Режим {INSTALL_MODE}, {PROTOCOL_MODE}) ===")
    else:
        log_to_file("SUCCESS", f"=== Установка завершена успешно за {install_dur}с (Режим {INSTALL_MODE}, {PROTOCOL_MODE}) ===")

    # Сигнализируем exit-trap что установка завершена нормально
    global INSTALL_COMPLETED
    INSTALL_COMPLETED = True

# =============================================================================
#  DRY-RUN РЕЖИМ УСТАНОВКИ
#  Показывает план всех изменений без реального выполнения.
# =============================================================================

def do_dry_run() -> None:
    """
    Dry-run: сбор параметров и отображение полного плана установки
    без единого реального изменения системы.
    """
    global INSTALL_MODE, PROTOCOL_MODE, XHTTP_MODE, XHTTP_PATH, XHTTP_PERF_PRESET
    global PARAM_DOMAIN, PARAM_UUID, PARAM_PUBLIC_KEY, PARAM_PRIVATE_KEY
    global PARAM_SHORTID, PARAM_SPIDERX, PARAM_EMAIL, PARAM_SOCKET_PATH
    global PARAM_DOMAIN_STRATEGY, PARAM_SITE_TEMPLATE, PARAM_USE_DNSCRYPT
    global SERVER_PORT, IS_IPV6_AVAILABLE, IPV6_PREFLIGHT, CHAIN_NODES
    global SPLIT_TUNNEL_ENABLED, SPLIT_TUNNEL_EXTRA_DOMAINS, SPLIT_TUNNEL_EXTRA_IPS

    os.system("clear")
    print()
    _box_top("🔍  DRY-RUN — ПРЕДПРОСМОТР УСТАНОВКИ")
    _box_row(f"  {YELLOW}Режим симуляции: никаких изменений в системе не будет{NC}")
    _box_row(f"  {DIM}Сбор параметров → план действий → файлы-конфиги для проверки{NC}")
    _box_bottom()
    print()

    # ── Шаг 1: сбор параметров (те же диалоги что и при реальной установке) ──
    try:
        prompt_install_mode()
        prompt_protocol_mode()
        prompt_parameters()
        if INSTALL_MODE == "B":
            prompt_chain_params_multi()
        prompt_split_tunnel()
    except KeyboardInterrupt:
        print()
        warn("Dry-run прерван пользователем.")
        return

    # ── Шаг 2: определяем что будет сделано ──────────────────────────────────
    os.system("clear")
    print()
    _box_top("🔍  ПЛАН УСТАНОВКИ (DRY-RUN)")
    _box_row(f"  {BOLD}Что будет выполнено:{NC}")
    _box_sep()

    # --- Пакеты ---
    _box_row(f"  {CYAN}[1] Зависимости (apt){NC}")
    pkgs = ["curl", "wget", "unzip", "nginx", "fail2ban", "ufw",
            "openssl", "cron", "logrotate", "qrencode"]
    if PARAM_DOMAIN and not PARAM_DOMAIN.replace(".", "").isdigit():
        pkgs += ["certbot", "python3-certbot-nginx"]
    _box_row(f"      apt install: {DIM}{' '.join(pkgs)}{NC}")

    # --- DNSCrypt ---
    _box_row()
    _box_row(f"  {CYAN}[2] DNSCrypt-proxy{NC}")
    if PARAM_USE_DNSCRYPT:
        _box_row(f"      {GREEN}✓ Будет установлен{NC} → {DIM}/usr/local/sbin/dnscrypt-proxy{NC}")
        _box_row(f"      {DIM}Конфиг: /etc/dnscrypt-proxy/dnscrypt-proxy.toml{NC}")
    else:
        _box_row(f"      {DIM}○ Пропуск (не выбран){NC}")

    # --- Файрволл ---
    _box_row()
    _box_row(f"  {CYAN}[3] Файрволл (ufw){NC}")
    _box_row(f"      ufw allow 22/tcp    {DIM}(SSH){NC}")
    _box_row(f"      ufw allow 80/tcp    {DIM}(HTTP / certbot){NC}")
    _box_row(f"      ufw allow 443/tcp   {DIM}(HTTPS / Nginx){NC}")
    _box_row(f"      ufw allow {SERVER_PORT}/tcp  {DIM}(Xray){NC}")
    _box_row(f"      ufw enable")

    # --- Sysctl / оптимизации ---
    _box_row()
    _box_row(f"  {CYAN}[4] Сетевые оптимизации (sysctl){NC}")
    _box_row(f"      {DIM}/etc/sysctl.d/99-xray.conf{NC}  ← BBR, буферы, conntrack, ip_forward")
    _box_row(f"      {DIM}/etc/security/limits.d/xray.conf{NC}  ← nofile 1048576")

    # --- Xray ---
    _box_row()
    _box_row(f"  {CYAN}[5] Xray-core{NC}")
    _box_row(f"      {DIM}Загрузка: https://github.com/XTLS/Xray-core/releases/latest{NC}")
    _box_row(f"      {DIM}/usr/local/bin/xray{NC}  + SHA256-верификация")
    _box_row(f"      {DIM}/etc/systemd/system/xray.service{NC}")

    # --- Конфиг Xray ---
    _box_row()
    _box_row(f"  {CYAN}[6] Конфиг Xray{NC}")
    proto_label = (
        f"VLESS + xHTTP + TLS  (mode={XHTTP_MODE}, path={XHTTP_PATH})"
        if PROTOCOL_MODE == "xhttp"
        else "VLESS + TCP + REALITY (xtls-rprx-vision)"
    )
    mode_label = "Обычный сервер (A)" if INSTALL_MODE == "A" else "Каскадный Entry Node (B)"
    _box_row(f"      Протокол:  {CYAN}{proto_label}{NC}")
    _box_row(f"      Режим:     {CYAN}{mode_label}{NC}")
    _box_row(f"      Домен/SNI: {CYAN}{PARAM_DOMAIN}{NC}")
    _box_row(f"      Порт:      {CYAN}{SERVER_PORT}{NC}")
    _box_row(f"      UUID:      {CYAN}{PARAM_UUID}{NC}")
    _box_row(f"      {DIM}/etc/xray/config.json{NC}")

    if INSTALL_MODE == "B" and CHAIN_NODES:
        _box_row()
        _box_row(f"  {CYAN}[6b] Exit-ноды ({len(CHAIN_NODES)} шт.):{NC}")
        for i, nd in enumerate(CHAIN_NODES):
            _box_row(f"      {DIM}Нода {i+1}: {nd.get('host','?')}:{nd.get('port','?')}"
                     f"  ({nd.get('proto','?').upper()}){NC}")
        _box_row(f"      {DIM}Балансировка: {CHAIN_BALANCER_STRATEGY}{NC}")

    # --- Nginx ---
    _box_row()
    _box_row(f"  {CYAN}[7] Nginx + SSL{NC}")
    _box_row(f"      certbot --nginx -d {PARAM_DOMAIN}  {DIM}(Let's Encrypt){NC}")
    _box_row(f"      {DIM}/etc/nginx/sites-available/xray-vless{NC}")
    _box_row(f"      {DIM}/etc/nginx/conf.d/rate_limit.conf{NC}")

    # --- Split tunnel ---
    _box_row()
    _box_row(f"  {CYAN}[8] Split tunneling{NC}")
    if SPLIT_TUNNEL_ENABLED:
        _box_row(f"      {GREEN}✓ Включён{NC}  — РФ-подсети через прямой маршрут")
        _box_row(f"      {DIM}Cron: /etc/cron.d/xray-geo-update  (Вс 03:00){NC}")
    else:
        _box_row(f"      {DIM}○ Выключен (весь трафик через Xray){NC}")

    # --- Systemd units & cron ---
    _box_row()
    _box_row(f"  {CYAN}[9] Автоматизация{NC}")
    units = [
        ("/etc/systemd/system/xray.service",       "Xray сервис"),
        ("/etc/systemd/system/xray-watchdog.*",     "Watchdog-таймер"),
        ("/etc/systemd/system/xray-autoupdate.*",   "Авто-обновление Xray"),
        ("/etc/logrotate.d/xray",                   "Logrotate"),
        ("/etc/fail2ban/jail.d/xray.conf",          "Fail2ban"),
    ]
    for path, label in units:
        _box_row(f"      {DIM}{path}{NC}  ← {label}")

    # --- Выходные файлы ---
    _box_sep()
    _box_row(f"  {BOLD}Файлы, которые будут созданы в /root/:{NC}")
    out_files = [
        ("vless_link.txt",            "клиентская VLESS-ссылка"),
        ("vless_qr.png",              "QR-код"),
        ("xray_config_exit_node.json","конфиг exit VPS (только Режим B)"),
    ]
    for fname, desc in out_files:
        _box_row(f"      {GREEN}{fname}{NC}  — {DIM}{desc}{NC}")

    # --- Итог: ничего не было изменено ---
    _box_sep()

    # Подсчёт диска
    disk_mb = 80  # базовая оценка
    if PARAM_USE_DNSCRYPT:
        disk_mb += 15
    _box_row(f"  {BOLD}Оценка:{NC}")
    _box_row(f"      Время установки:   {DIM}~3–8 мин (зависит от скорости APT){NC}")
    _box_row(f"      Доп. дисковое место: {DIM}~{disk_mb} МБ{NC}")
    _box_row(f"      RAM в работе:      {DIM}~50–150 МБ (Xray + Nginx){NC}")
    _box_row()
    _box_row(f"  {GREEN}✓ Dry-run завершён — ни одного реального изменения не сделано{NC}")
    _box_row(f"  {DIM}Для реальной установки выберите пункт 1 → Установить{NC}")
    _box_bottom()

    log_to_file("INFO", f"dry-run выполнен: mode={INSTALL_MODE}, proto={PROTOCOL_MODE}, domain={PARAM_DOMAIN}")
    input(f"\n{BLUE}Нажмите Enter для возврата в меню...{NC}")


# (MTU-модуль — _mtu_probe, _mtu_get_iface, _mtu_apply, _mtu_remove_rules,
#  _mtu_state_load, _mtu_state_save, do_mtu_tuning, _mtu_persist,
#  _MTU_STATE_FILE — вынесены в vless_installer.modules.mtu_tuning;
#  импорт — в верхней секции этого файла.)


# (Diagnostics engine — _diag_ok/err/head/warn/make_counters/chk/run/fmt_bytes/
#  resolve_config/stats_api_available/get_stats_via_api/hint_stats_api/
#  render_traffic_table/print_traffic_from_ss/print_traffic_volume/
#  check_xray_service/geo_files/config_structure/outbounds/routing_live/
#  access_log/error_log/top_hosts/state/geo_autoupdate/print_summary,
#  run_split_tunnel_diagnostics, _DIAG_BLOCKED_DOMAINS/_DIAG_RUSSIAN_DOMAINS/
#  _DIAG_STATS_API_ADDR — вынесены в vless_installer.modules.diagnostics;
#  импорт — в верхней секции этого файла.)

# =============================================================================
#  CLOUDFLARE WARP — МОДУЛЬ
#  Поддерживает 3 режима маршрутизации:
#    full      — весь трафик через WARP (SSH-клиент исключается автоматически)
#    selective — только указанные пользователем IP/домены через WARP
#    runet     — заблокированные РФ ресурсы (списки runetfreedom)
#  SSH изолирован через network namespace (SSH Namespace) — SSH никогда не
#  попадает в WARP-туннель, даже в режиме full.
# =============================================================================

WARP_SSH_NAMESPACE   = "ssh_ns"          # имя netns для SSH-трафика
WARP_SSH_VETH_HOST   = "veth-ssh-host"   # veth-пара: сторона хоста
WARP_SSH_VETH_NS     = "veth-ssh-ns"     # veth-пара: сторона netns
WARP_SSH_NS_IP       = "10.200.200.1"    # IP в namespace (sshd слушает здесь тоже)
WARP_SSH_HOST_IP     = "10.200.200.2"    # IP хоста внутри пары
WARP_SSH_NS_NET      = "10.200.200.0/30"
WARP_SERVICE_FILE    = Path("/etc/systemd/system/warp-svc.service")
# warp — перенесено в vless_installer/modules/warp.py
# (do_live_traffic_dashboard вынесен в vless_installer.modules.diagnostics;
#  импорт — в верхней секции этого файла.)

# ---------------------------------------------------------------------------
#  2. АВТО-СМЕНА TLS FINGERPRINT ПО РАСПИСАНИЮ
# ---------------------------------------------------------------------------
_FP_LIST = _FM_FP_LIST  # единый авторитетный список из fingerprint_manager.py

_FP_SCHEDULE_FILE = Path("/etc/xray/fp_schedule.json")
_FP_CRON_SCRIPT   = Path("/usr/local/bin/xray-fp-rotate.sh")
_FP_CRON_TAG      = "xray-fp-rotate"


def _fp_get_current() -> str:
    """Читает текущий fingerprint из config.json."""
    cfg_path = Path("/usr/local/etc/xray/config.json")
    if not cfg_path.exists():
        cfg_path = CONFIG_DIR / "config.json"
    try:
        cfg = json.loads(cfg_path.read_text())
        outbounds = cfg.get("outbounds", [])
        for ob in outbounds:
            st = ob.get("streamSettings", {})
            fp = st.get("realitySettings", {}).get("fingerprint", "")
            if fp:
                return fp
            fp = st.get("tlsSettings", {}).get("fingerprint", "")
            if fp:
                return fp
    except Exception:
        pass
    return "неизвестен"


def _fp_patch_config(new_fp: str) -> bool:
    """Меняет fingerprint во всех outbound в config.json и обновляет state.json."""
    for cfg_path in (Path("/usr/local/etc/xray/config.json"), CONFIG_DIR / "config.json"):
        if not cfg_path.exists():
            continue
        try:
            cfg = json.loads(cfg_path.read_text())
            changed = False
            for ob in cfg.get("outbounds", []):
                st = ob.get("streamSettings", {})
                for tls_key in ("realitySettings", "tlsSettings"):
                    if tls_key in st:
                        st[tls_key]["fingerprint"] = new_fp
                        changed = True
            if changed:
                cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                cfg_path.chmod(0o640)
        except Exception as e:
            warn(f"Ошибка патча конфига {cfg_path}: {e}")
            return False

    # Синхронизируем fingerprint в state.json
    if STATE_FILE.exists():
        try:
            st = json.loads(STATE_FILE.read_text())
            st["fingerprint"] = new_fp
            if "chain_nodes" in st and isinstance(st["chain_nodes"], list):
                for node in st["chain_nodes"]:
                    if isinstance(node, dict) and "fp" in node:
                        node["fp"] = new_fp
            if "chain_exit_fp" in st:
                st["chain_exit_fp"] = new_fp
            STATE_FILE.write_text(json.dumps(st, indent=2, ensure_ascii=False))
        except Exception as e:
            warn(f"Не удалось обновить state.json: {e}")

    return True


def _fp_install_cron(interval_hours: int) -> None:
    """Устанавливает cron-скрипт для ротации fingerprint."""
    _FP_ROTATE_EXCLUDE = {"random", "randomized", "none"}
    fp_list_str = " ".join(fp for fp in _FP_LIST if fp not in _FP_ROTATE_EXCLUDE)  # только реальные браузеры
    script_content = textwrap.dedent(f"""\
        #!/bin/bash
        # Авто-смена TLS fingerprint для Xray (установлено VLESS Installer)
        FP_LIST=({fp_list_str})
        NEW_FP="${{FP_LIST[$RANDOM % ${{#FP_LIST[@]}}]}}"
        LOG="/var/log/xray-fp-rotate.log"
        DATE=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$DATE] Смена fingerprint → $NEW_FP" >> "$LOG"

        # Патч всех конфигов
        for CONF in /usr/local/etc/xray/config.json /etc/xray/config.json; do
            [ -f "$CONF" ] || continue
            python3 -c "
import json, sys
with open('$CONF') as f: c = json.load(f)
changed = False
for ob in c.get('outbounds', []):
    st = ob.get('streamSettings', {{}})
    for k in ('realitySettings', 'tlsSettings'):
        if k in st:
            st[k]['fingerprint'] = sys.argv[1]
            changed = True
if changed:
    with open('$CONF', 'w') as f: json.dump(c, f, indent=2, ensure_ascii=False)
    print('Обновлён: $CONF')
" "$NEW_FP" >> "$LOG" 2>&1
        done

        # Валидация и применение конфига
        if /usr/local/bin/xray -test -config /usr/local/etc/xray/config.json >> "$LOG" 2>&1; then
            # Xray 26.x не поддерживает горячий reload через SIGHUP — используем restart.
            if systemctl is-active --quiet xray 2>/dev/null; then
                systemctl restart xray >> "$LOG" 2>&1 \
                    && echo "[$DATE] Xray перезапущен (fp=$NEW_FP)" >> "$LOG" \
                    || echo "[$DATE] ОШИБКА перезапуска Xray" >> "$LOG"
            else
                systemctl start xray >> "$LOG" 2>&1 \
                    && echo "[$DATE] Xray запущен (fp=$NEW_FP)" >> "$LOG" \
                    || echo "[$DATE] ОШИБКА запуска Xray" >> "$LOG"
            fi
        else
            echo "[$DATE] Конфиг невалиден — fingerprint не применён!" >> "$LOG"
        fi
    """)
    _FP_CRON_SCRIPT.write_text(script_content)
    _FP_CRON_SCRIPT.chmod(0o750)

    # Добавляем в /etc/cron.d
    cron_path = Path(f"/etc/cron.d/{_FP_CRON_TAG}")
    cron_path.write_text(
        f"0 */{interval_hours} * * * root {_FP_CRON_SCRIPT}\n"
    )
    cron_path.chmod(0o644)
    success(f"Cron установлен: каждые {interval_hours} ч → {_FP_CRON_SCRIPT}")


def _fp_remove_cron() -> None:
    cron_path = Path(f"/etc/cron.d/{_FP_CRON_TAG}")
    cron_path.unlink(missing_ok=True)
    _FP_CRON_SCRIPT.unlink(missing_ok=True)
    success("Авто-ротация fingerprint отключена")


def do_manage_fingerprint() -> None:
    """Меню управления авто-сменой TLS fingerprint."""
    cron_path = Path(f"/etc/cron.d/{_FP_CRON_TAG}")

    while True:
        os.system("clear")
        current_fp   = _fp_get_current()
        cron_active  = cron_path.exists()
        cron_str     = ""
        if cron_active:
            try:
                cron_str = cron_path.read_text().strip()
            except Exception:
                pass

        print()
        _box_top(f"Авто-смена TLS Fingerprint")
        _box_row(f"  Текущий fingerprint:  {CYAN}{current_fp}{NC}")
        _box_row(f"  Авто-ротация:         {''+GREEN+'ВКЛЮЧЕНА'+NC if cron_active else ''+YELLOW+'ОТКЛЮЧЕНА'+NC}")
        if cron_str:
            _box_row(f"  Cron:                 {DIM}{cron_str}{NC}")
        _box_item("1", f"Сменить fingerprint вручную прямо сейчас")
        _box_item("2", f"{'Отключить' if cron_active else 'Включить'} авто-ротацию по расписанию")
        _box_item("3", f"Показать доступные fingerprint'ы")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            print()
            _box_top(f"Доступные fingerprint'ы")
            for i, fp in enumerate(_FP_LIST, 1):
                marker = f" {GREEN}← текущий{NC}" if fp == current_fp else ""
                _box_item(f"{i}", f"{fp}{marker}")
            _box_bottom()
            raw = input(f"  Выбор (1-{len(_FP_LIST)}) или введите имя: ").strip()
            new_fp = ""
            if raw.isdigit() and 1 <= int(raw) <= len(_FP_LIST):
                new_fp = _FP_LIST[int(raw) - 1]
            elif raw in _FP_LIST:
                new_fp = raw
            if not new_fp:
                warn("Неверный выбор")
                time.sleep(1)
                continue
            if new_fp == "random":
                _fp_real = [fp for fp in _FP_LIST if fp not in {"random", "randomized", "none"}]
                new_fp = random.choice(_fp_real)
                info(f"Random → выбран: {new_fp}")

            # Патчим конфиг
            ok = _fp_patch_config(new_fp)
            if not ok:
                warn("Не удалось обновить конфиг")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            # Валидация
            val = _run([str(XRAY_BIN), "-test", "-config",
                        "/usr/local/etc/xray/config.json"],
                       capture=True, check=False, quiet=True)
            if val.returncode != 0:
                warn("Конфиг невалиден — fingerprint не применён")
                warn((val.stdout + val.stderr)[:200])
            else:
                _run(["systemctl", "restart", "xray"], check=False, quiet=True)
                time.sleep(2)
                success(f"Fingerprint изменён на: {new_fp}, Xray перезапущен")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            if cron_active:
                _fp_remove_cron()
            else:
                print()
                _box_top("Интервал ротации")
                _box_item("1", f"Каждые 6 часов")
                _box_item("2", f"Каждые 12 часов")
                _box_item("3", f"Каждые 24 часа {GREEN}(рекомендуется){NC}")
                _box_bottom()
                iv_choice = input("  Выбор [3]: ").strip() or "3"
                iv_map = {"1": 6, "2": 12, "3": 24}
                interval_h = iv_map.get(iv_choice, 24)
                _fp_install_cron(interval_h)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            print()
            for fp in _FP_LIST:
                marker = f"  {GREEN}← текущий{NC}" if fp == current_fp else ""
                print(f"    • {fp}{marker}")
            print()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


# (check_exit_geo вынесен в vless_installer.modules.standalone_screens;
#  импорт — в верхней секции этого файла.)


# ---------------------------------------------------------------------------
#  4. МЕНЕДЖЕР МНОЖЕСТВЕННЫХ ПОЛЬЗОВАТЕЛЕЙ
# ---------------------------------------------------------------------------
USERS_FILE = CONFIG_DIR / "users.json"


# (_users_load, _users_save, _users_patch_config_no_restart,
#  _users_apply_to_config — вынесены в vless_installer.modules.users_manager;
#  импорт — в верхней секции этого файла.)



def _users_get_traffic(uuid_val: str) -> tuple[int, int]:
    """Получает трафик пользователя через Stats API по email (up, down)."""
    up, down, _, _ = _users_get_traffic_extended(uuid_val)
    return up, down


def _users_get_traffic_extended(email_or_uuid: str) -> tuple[int, int, int, int]:
    """
    Возвращает (up, down, proxy_bytes, direct_bytes) для пользователя.
    Статистика по пользователю берётся через user>>> паттерн,
    статистика по направлениям — через outbound>>> паттерн.
    """
    try:
        xray_bin = shutil.which("xray") or str(XRAY_BIN)
        srv = f"--server=127.0.0.1:{XRAY_STATS_API_PORT}"

        # Трафик пользователя (user>>>email>>>traffic>>>up/downlink)
        r = subprocess.run(
            [xray_bin, "api", "statsquery", srv,
             f"--pattern=user>>>{email_or_uuid}", "--reset=false"],
            capture_output=True, text=True, timeout=5
        )
        up = down = 0
        if r.returncode == 0 and r.stdout.strip():
            try:
                data = json.loads(r.stdout.strip())
                for entry in (data.get("stat") or []):
                    val = int(entry.get("value") or 0)
                    name = entry.get("name", "")
                    if "uplink" in name:
                        up += val
                    elif "downlink" in name:
                        down += val
            except Exception:
                pass

        # Outbound-разбивка (direct vs proxy) — суммарная по серверу
        r2 = subprocess.run(
            [xray_bin, "api", "statsquery", srv,
             "--pattern=outbound>>>", "--reset=false"],
            capture_output=True, text=True, timeout=5
        )
        proxy_bytes = direct_bytes = 0
        if r2.returncode == 0 and r2.stdout.strip():
            try:
                data2 = json.loads(r2.stdout.strip())
                pat = re.compile(r'^outbound>>>([^>]+)>>>traffic>>>(uplink|downlink)$')
                for entry in (data2.get("stat") or []):
                    val = int(entry.get("value") or 0)
                    m = pat.match(entry.get("name", ""))
                    if not m:
                        continue
                    tag = m.group(1)
                    if tag in ("xray-stats-api",):
                        continue
                    if "direct" in tag:
                        direct_bytes += val
                    elif tag not in ("BLOCK", "block"):
                        proxy_bytes += val
            except Exception:
                pass

        return up, down, proxy_bytes, direct_bytes
    except Exception:
        return 0, 0, 0, 0


def _users_get_outbound_breakdown() -> dict[str, int]:
    """
    Возвращает {tag: bytes} для всех outbound-тегов через Stats API.
    Служебные теги (xray-stats-api) исключаются.
    """
    try:
        xray_bin = shutil.which("xray") or str(XRAY_BIN)
        r = subprocess.run(
            [xray_bin, "api", "statsquery",
             f"--server=127.0.0.1:{XRAY_STATS_API_PORT}",
             "--pattern=outbound>>>", "--reset=false"],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode != 0 or not r.stdout.strip():
            return {}
        data = json.loads(r.stdout.strip())
        result: dict[str, int] = {}
        pat = re.compile(r'^outbound>>>([^>]+)>>>traffic>>>(uplink|downlink)$')
        for entry in (data.get("stat") or []):
            val = int(entry.get("value") or 0)
            m = pat.match(entry.get("name", ""))
            if m and m.group(1) not in ("xray-stats-api",):
                tag = m.group(1)
                result[tag] = result.get(tag, 0) + val
        return result
    except Exception:
        return {}


def _users_get_connections_by_email(email: str) -> int:
    """Считает активные TCP-соединения через ss (grpc/xray порт)."""
    try:
        r = subprocess.run(
            ["ss", "-tn", "state", "established"],
            capture_output=True, text=True, timeout=5
        )
        # Грубая эвристика: считаем строки с портом сервера
        count = sum(1 for line in r.stdout.splitlines()
                    if f":{SERVER_PORT}" in line or ":443" in line)
        return count
    except Exception:
        return 0


def do_manage_users() -> None:
    """Меню управления множественными пользователями Xray."""
    while True:
        users = _users_load()
        os.system("clear")
        _box_top(f"Менеджер пользователей")
        if not users:
            _box_row(f"  {YELLOW}Пользователей нет.{NC}")
        else:
            _box_row(f"  {'#':<4} {'Имя':<20} {'UUID (сокр.)':<14} {'Email':<30}")
            _box_row(f"  {'-'*4} {'-'*20} {'-'*14} {'-'*30}")
            for i, u in enumerate(users, 1):
                uuid_short = u['uuid'][:8] + "..."
                _box_row(f"  {i:<4} {u.get('name','—'):<20} {CYAN}{uuid_short:<14}{NC} {u.get('email','—'):<30}")
        _box_item("1", f"Добавить пользователя")
        _box_item("2", f"Удалить пользователя")
        _box_item("3", f"Показать ссылку / QR для пользователя")
        _box_item("4", f"Показать трафик пользователей (Stats API)")
        _box_item("5", f"Применить список к Xray (сохранить + перезапустить)")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            print()
            name  = input(f"  Имя пользователя (например, Alice): ").strip() or "user"
            email = input(f"  Email (для статистики, например alice@vpn): ").strip()
            if not email:
                email = f"{name.lower().replace(' ', '_')}@xray"
            new_uuid = gen_uuid()
            print(f"  {DIM}UUID сгенерирован: {new_uuid}{NC}")
            users.append({
                "uuid":    new_uuid,
                "email":   email,
                "name":    name,
                "created": datetime.now(timezone.utc).isoformat(),
            })
            _users_save(users)
            success(f"Пользователь '{name}' добавлен (UUID: {new_uuid[:16]}...)")
            warn("Не забудьте применить список [5] и показать ссылку [3]")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            if not users:
                warn("Нет пользователей для удаления")
                time.sleep(1)
                continue
            raw = input(f"  Номер пользователя для удаления: ").strip()
            if raw.isdigit() and 1 <= int(raw) <= len(users):
                removed = users.pop(int(raw) - 1)
                _users_save(users)
                success(f"Удалён: {removed.get('name')} ({removed['uuid'][:16]}...)")
                warn("Не забудьте применить список [5]")
            else:
                warn("Неверный номер")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            if not users:
                warn("Нет пользователей")
                time.sleep(1)
                continue
            raw = input(f"  Номер пользователя: ").strip()
            if not (raw.isdigit() and 1 <= int(raw) <= len(users)):
                warn("Неверный номер")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            u = users[int(raw) - 1]
            print()
            # Генерируем ссылку используя параметры из state
            if STATE_FILE.exists():
                try:
                    st = json.loads(STATE_FILE.read_text())
                    domain    = st.get("domain", "")
                    port      = st.get("server_port", 443)
                    proto     = st.get("protocol_mode", "reality")
                    pub_key   = st.get("public_key", "")
                    short_id  = st.get("short_id", "")
                    spiderx   = st.get("spiderx", "/")
                    xhttp_path = st.get("xhttp_path", "/")
                    server_ip = get_server_ip("4")
                    # SNI: при Mode B + AWG — домен маскировки, иначе собственный домен
                    _ul_install_mode = st.get("install_mode", "A")
                    _ul_awg = st.get("awg_exit_enabled", False) and _ul_install_mode == "B"
                    _ul_reality_dest = st.get("reality_dest", "")
                    if proto == "reality" and _ul_awg and _ul_reality_dest:
                        _ul_sni = _ul_reality_dest
                    else:
                        _ul_sni = domain

                    if proto == "reality":
                        _ul_fp = st.get("fingerprint", "chrome") or "chrome"
                        link = (
                            f"vless://{u['uuid']}@{server_ip}:{port}"
                            f"?encryption=none&flow=xtls-rprx-vision"
                            f"&security=reality&sni={_ul_sni}"
                            f"&fp={_ul_fp}&pbk={pub_key}&sid={short_id}"
                            f"&spx={spiderx}&type=tcp"
                            f"#{u.get('name','user')}"
                        )
                    else:
                        link = (
                            f"vless://{u['uuid']}@{domain}:{port}"
                            f"?encryption=none&security=tls&sni={domain}"
                            f"&alpn=h2&type=xhttp&path={xhttp_path}"
                            f"#{u.get('name','user')}"
                        )
                    print(f"  {BOLD}Ссылка для {u.get('name')}:{NC}")
                    print(f"  {CYAN}{link}{NC}")
                    print()
                    # QR в терминале если qrencode доступен
                    if command_exists("qrencode"):
                        # ГОЛУБОЙ QR: пробуем с --foreground, fallback без него
                        import subprocess as _sp_qr
                        _r_qr = _sp_qr.run(
                            ["qrencode", "-t", "ANSIUTF8", "-m", "1",
                             "--foreground=00BFFF", "--background=000000", link],
                            capture_output=True, text=True
                        )
                        if not _r_qr.stdout.strip():
                            _r_qr = _sp_qr.run(
                                ["qrencode", "-t", "ANSIUTF8", "-m", "1", link],
                                capture_output=True, text=True
                            )
                        _QR_C = "\033[96m"; _QR_R = "\033[0m"
                        for _ql in _r_qr.stdout.splitlines():
                            if "\033[" not in _ql:
                                print(f"  {_QR_C}{_ql}{_QR_R}")
                            else:
                                print(f"  {_ql}")
                    else:
                        info("Установите qrencode для отображения QR: apt install qrencode")
                except Exception as e:
                    warn(f"Не удалось сгенерировать ссылку: {e}")
            else:
                warn("state.json не найден — сначала выполните установку")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "4":
            _box_top("Статистика трафика")
            _box_row(f"  {BOLD}{'Имя':<20} {'UUID':<14} {'Upload':>12} {'Download':>12}{NC}")
            _box_sep()
            for u in users:
                up, down = _users_get_traffic(u["uuid"])
                def _fmt(n: int) -> str:
                    if n < 1048576: return f"{n/1024:.1f} КБ"
                    if n < 1073741824: return f"{n/1048576:.1f} МБ"
                    return f"{n/1073741824:.2f} ГБ"
                _box_row(f"  {u.get('name','—'):<20} {DIM}{u['uuid'][:8]+'...':<14}{NC} {GREEN}{_fmt(up):>12}{NC} {CYAN}{_fmt(down):>12}{NC}")
            _box_sep()
            _box_row(f"  {DIM}Данные из Xray Stats API (могут быть нулевыми если нет трафика){NC}")
            _box_row()
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            print()
            info(f"Применение {len(users)} пользователей к Xray...")
            if _users_apply_to_config(users):
                success(f"Готово — {len(users)} пользователей применено, Xray перезапущен")
            else:
                warn("Применение не удалось — см. лог")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


# ---------------------------------------------------------------------------
#  ЕДИНЫЙ МЕНЕДЖЕР ПОЛЬЗОВАТЕЛЕЙ (объединяет режимы A и B)
# ---------------------------------------------------------------------------

# (_unified_load_users, _unified_save_users — вынесены в
#  vless_installer.modules.users_manager; импорт — в верхней секции этого файла.)


def _unified_gen_link(u: dict) -> str:
    """Оставлен для совместимости. Используй _unified_show_links."""
    links = _unified_show_links(u, print_output=False)
    return links[0] if links else ""


# (_unified_show_links — вынесена в vless_installer.modules.users_manager;
#  импорт — в верхней секции этого файла.)


def _fmt_bytes_ru(n: int) -> str:
    if n < 1024:        return f"{n} Б"
    if n < 1024 ** 2:   return f"{n/1024:.1f} КБ"
    if n < 1024 ** 3:   return f"{n/1024**2:.1f} МБ"
    return f"{n/1024**3:.2f} ГБ"


def _gradient_bar(val: int, total: int, width: int = 20, force_color: str = "") -> str:
    """Блочный прогресс-бар с градиентом цвета по заполненности.
    Использует символы ▓ (заполнено) и ░ (пусто).
    Цвет зависит от процента: <40% зелёный, 40-70% голубой, >70% жёлтый, 100% белый.
    force_color — если задан, использует этот цвет вместо градиента."""
    if total == 0:
        return f"{DIM}{'░' * width}{NC}"
    pct = val / total
    filled = max(0, min(width, int(pct * width)))
    empty  = width - filled
    if force_color:
        col = force_color
    else:
        if pct >= 1.0:      col = WHITE
        elif pct >= 0.70:   col = YELLOW
        elif pct >= 0.40:   col = CYAN
        else:               col = GREEN
    return f"{col}{'▓' * filled}{NC}{DIM}{'░' * empty}{NC}"


def _bar_mini(val: int, total: int, width: int = 20, force_color: str = "") -> str:
    """Блочный прогресс-бар для использования внутри _box_row."""
    return _gradient_bar(val, total, width, force_color)


def _device_icon(label: str) -> str:
    """
    Возвращает ASCII/Emoji-иконку по метке устройства.
    Xray-статистика в терминале: emoji поддерживаются в большинстве современных SSH-клиентов.
    """
    if not label:
        return "  "
    low = label.lower()
    if any(k in low for k in ("iphone", "ios", "phone", "mobile", "смартфон")):
        return "📱"
    if any(k in low for k in ("ipad", "tablet", "планшет")):
        return "📲"
    if any(k in low for k in ("macbook", "laptop", "ноутбук", "notebook")):
        return "💻"
    if any(k in low for k in ("pc", "desktop", "work", "home", "пк", "компьютер")):
        return "🖥️"
    if any(k in low for k in ("router", "routeur", "маршрутизатор")):
        return "📡"
    if any(k in low for k in ("tv", "смарт", "smart", "appletv", "firetv")):
        return "📺"
    if any(k in low for k in ("watch", "часы")):
        return "⌚"
    if any(k in low for k in ("android", "samsung", "pixel", "xiaomi", "huawei")):
        return "📱"
    if any(k in low for k in ("mac", "apple")):
        return "🍎"
    if any(k in low for k in ("win", "windows")):
        return "🪟"
    if any(k in low for k in ("linux", "ubuntu", "debian")):
        return "🐧"
    return "📦"


# (_do_user_stats_screen — вынесена в vless_installer.modules.users_manager;
#  импорт — в верхней секции этого файла.)


def _do_export_users_zip(users: list, install_mode: str) -> None:
    """
    Экспортирует всех пользователей в ZIP-архив:
    - каждый пользователь: ссылка (.txt) + QR-код (.png)
    - README.txt с инструкцией
    Архив сохраняется в /root/vless_users_export_<дата>.zip
    """
    import zipfile, tempfile
    from datetime import datetime as _dt

    qrencode = shutil.which("qrencode")
    if not qrencode:
        warn("qrencode не найден — QR-коды не будут созданы. Установите: apt install qrencode")

    print()
    _box_top("Экспорт пользователей в ZIP")
    _box_row(f"  Пользователей: {CYAN}{len(users)}{NC}")
    _box_sep()

    # Загружаем параметры сервера
    _state = {}
    if STATE_FILE.exists():
        try:
            _state = json.loads(STATE_FILE.read_text())
        except Exception:
            pass

    _, _, _flag = get_server_country_cached()

    zip_name = f"/root/vless_users_export_{_dt.now().strftime('%Y%m%d_%H%M%S')}.zip"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        readme_lines = [
            "VLESS VPN — Ссылки для подключения",
            "=" * 40,
            f"Сервер: {_state.get('domain', '?')}",
            f"Протокол: {_state.get('protocol_mode', 'reality').upper()}",
            f"Страна: {_flag} {_state.get('domain', '')}",
            f"Дата экспорта: {_dt.now().strftime('%d.%m.%Y %H:%M')}",
            "",
            "Как подключиться:",
            "  1. Откройте v2rayNG / Hiddify / Nekobox",
            "  2. Нажмите '+' → Сканировать QR или Импорт из буфера",
            "  3. Вставьте ссылку из .txt файла или отсканируйте QR",
            "",
            "Файлы:",
        ]

        with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as zf:
            for u in users:
                if u.get("disabled"):
                    continue
                email    = u.get("email", "user")
                name     = u.get("name", email)
                label    = u.get("device_label") or name
                name_safe = re.sub(r"[^\w\-.]", "_", email)

                # Генерируем ссылку
                link = None
                try:
                    link = _gen_vless_link(
                        host      = _state.get("domain", ""),
                        uuid_str  = u["uuid"],
                        pbk       = _state.get("public_key", ""),
                        sid       = _state.get("short_id", ""),
                        domain    = _state.get("domain", ""),
                        proto     = _state.get("protocol_mode", "reality"),
                        xhttp_path= _state.get("xhttp_path", "/"),
                        xhttp_mode= _state.get("xhttp_mode", "streamup"),
                        port      = _state.get("server_port", 443),
                    )
                except Exception as ex:
                    _box_warn(f"  Не удалось сгенерировать ссылку для {email}: {ex}")
                    continue

                # .txt с ссылкой
                txt_name = f"{name_safe}.txt"
                txt_content = (
                    f"Пользователь: {name}\n"
                    f"Email: {email}\n"
                    f"Устройство: {label}\n\n"
                    f"Ссылка для подключения:\n{link}\n"
                )
                zf.writestr(txt_name, txt_content)
                readme_lines.append(f"  {name_safe}.txt / {name_safe}.png  →  {name} ({label})")

                # QR PNG
                if qrencode:
                    png_tmp = str(tmp / f"{name_safe}.png")
                    r = _run([qrencode, "-t", "PNG", "-o", png_tmp,
                               "-s", "8", "-m", "4", link],
                              check=False, quiet=True)
                    if r.returncode == 0:
                        zf.write(png_tmp, f"{name_safe}.png")

                _box_row(f"  {GREEN}✓{NC}  {name:<20}  {DIM}{email}{NC}")

            # README
            zf.writestr("README.txt", "\n".join(readme_lines))

    _box_sep()
    _box_ok(f"Архив сохранён: {zip_name}")
    _box_row(f"  {DIM}Скачайте через: scp root@<сервер>:{zip_name} ./{NC}")
    _box_bottom()


def do_unified_user_manager() -> None:
    """
    Единый менеджер пользователей — работает в обоих режимах A и B.
    Читает и сохраняет пользователей сразу в xray config.json и users.json.
    """
    global _BOX_W

    # Определяем режим установки из state.json
    install_mode = "A"
    if STATE_FILE.exists():
        try:
            install_mode = json.loads(STATE_FILE.read_text()).get("install_mode", "A")
        except Exception:
            pass

    # Колонки таблицы — фиксированные, определяют минимальную ширину бокса
    # 2+3+2+18+2+10+2+22+2+10+2+3 = 78
    _C_IDX, _C_LBL, _C_NAME, _C_EMAIL, _C_UUID = 3, 18, 10, 22, 13
    _DATA_MIN_W = 2 + _C_IDX + 2 + _C_LBL + 2 + _C_NAME + 2 + _C_EMAIL + 2 + _C_UUID
    # BOX_W не может быть меньше ширины строки данных
    _saved_BOX_W = _BOX_W
    _BOX_W = max(_DATA_MIN_W, _get_box_width())

    try:
        while True:
            users = _unified_load_users()
            os.system("clear")
            mode_hint = f"Режим {'B — каскад' if install_mode == 'B' else 'A — стандарт'}"
            _box_top(f"Менеджер пользователей ({mode_hint})")
            if not users:
                _box_row(f"  {YELLOW}Пользователей нет.{NC}")
            else:
                # Анти-ANSI выравнивание для метки с emoji
                ansi_re_hdr = re.compile(r'\x1b\[[0-9;]*m')
                def _pad_hdr(text: str, w: int) -> str:
                    """Выравнивание с учётом реальной ширины emoji/кириллицы через _wcslen."""
                    return text + ' ' * max(0, w - _wcslen(ansi_re_hdr.sub('', text)))
                _box_row(f"  {BOLD}{'#':<{_C_IDX}}  {'Метка устройства':<{_C_LBL}}  {'Имя':<{_C_NAME}}  {'Email':<{_C_EMAIL}}  {'UUID' + '.' * (_C_UUID - 4)}{NC}")
                _box_row(f"  {'─'*_C_IDX}  {'─'*_C_LBL}  {'─'*_C_NAME}  {'─'*_C_EMAIL}  {'─'*_C_UUID}")
                for i, u in enumerate(users, 1):
                    uuid_short   = u["uuid"][:8] + "~"
                    src_tag      = u.get("source", "?")
                    device_label = u.get("device_label", "")
                    icon         = _device_icon(device_label)
                    if device_label:
                        label_raw = f"{icon} {device_label}"
                    else:
                        label_raw = f"{DIM}— нет метки —{NC}"
                    _name  = u.get('name', '—')[:_C_NAME]
                    _email = u.get('email', '—')[:_C_EMAIL]
                    _box_row(f"  {i:<{_C_IDX}}  {_pad_hdr(label_raw, _C_LBL)}  "
                          f"{_name:<{_C_NAME}}  "
                          f"{_email:<{_C_EMAIL}}  "
                          f"{CYAN}{uuid_short}{NC} [{src_tag}]")
            _box_row()
            _box_item("1", f"Добавить пользователя")
            _box_item("2", f"Удалить пользователя")
            _box_item("3", f"Показать ссылку / QR для пользователя")
            _box_item("4", f"Статистика трафика (детально)")
            _box_item("5", f"Применить список к Xray (синхронизировать)")
            _box_item("6", f"Изменить метку устройства")
            _box_item("7", f"Отключить / Восстановить пользователя")
            _box_item("8", f"Редактировать пользователя (имя / email)")
            _box_item("E", f"Экспорт всех пользователей (ZIP с QR-кодами)")
            _box_item("Q", f"Назад")
            _box_bottom()
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

            if ch == "1":
                print()
                name  = input("  Имя пользователя (например, Alice): ").strip() or "user"
                email = input(f"  Email (для статистики, например alice@vpn): ").strip()
                if not email:
                    email = f"{name.lower().replace(' ', '_')}@xray"
                # Проверка дубликатов
                if any(u.get("email") == email for u in users):
                    warn(f"Пользователь с email '{email}' уже существует")
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue
                # Метка устройства
                print()
                print(f"  {DIM}Метка устройства помогает узнавать устройство в статистике трафика.{NC}")
                print(f"  {DIM}Примеры: iPhone-Ivan, PC-Work, iPad-Child, MacBook-Anna{NC}")
                device_label = input(f"  Метка устройства (Enter = пропустить): ").strip()
                new_uuid = gen_uuid()
                print(f"  {DIM}UUID сгенерирован: {new_uuid}{NC}")
                users.append({
                    "uuid":         new_uuid,
                    "email":        email,
                    "name":         name,
                    "device_label": device_label,
                    "created":      datetime.now(timezone.utc).isoformat(),
                    "source":       install_mode,
                })
                _unified_save_users(users)
                _log_change("user_add", f"Добавлен: {name} ({email}), метка: {device_label or '—'}")
                success(f"Пользователь '{name}' добавлен (UUID: {new_uuid[:16]}...)")
                if device_label:
                    success(f"Метка устройства: {device_label}")
                # Показываем все ссылки сразу (IPv4 / IPv6 / Domain)
                _unified_show_links({"uuid": new_uuid, "email": email, "name": name},
                                     print_output=True)
                warn("Не забудьте применить список [5] чтобы Xray подхватил нового пользователя")
                input(f"{BLUE}Нажмите Enter...{NC}")

            elif ch == "2":
                if not users:
                    warn("Нет пользователей для удаления")
                    time.sleep(1)
                    continue
                raw = input("  Номер пользователя для удаления: ").strip()
                if raw.isdigit() and 1 <= int(raw) <= len(users):
                    removed = users.pop(int(raw) - 1)
                    _unified_save_users(users)
                    _log_change("user_del", f"Удалён: {removed.get('name','?')} ({removed.get('email','')})")
                    success(f"Удалён: {removed.get('name')} ({removed['uuid'][:16]}...)")
                    # Чистим файлы ссылок
                    for p in (f"/root/vless_link_{removed.get('name','')}.txt",
                               f"/root/vless_qr_{removed.get('name','')}.png"):
                        Path(p).unlink(missing_ok=True)
                    warn("Не забудьте применить список [5]")
                else:
                    warn("Неверный номер")
                input(f"{BLUE}Нажмите Enter...{NC}")

            elif ch == "3":
                if not users:
                    warn("Нет пользователей")
                    time.sleep(1)
                    continue
                raw = input("  Номер пользователя: ").strip()
                if not (raw.isdigit() and 1 <= int(raw) <= len(users)):
                    warn("Неверный номер")
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue
                u = users[int(raw) - 1]
                links = _unified_show_links(u, print_output=True)
                if not links:
                    warn("Не удалось сгенерировать ссылки — проверьте state.json")
                input(f"{BLUE}Нажмите Enter...{NC}")

            elif ch == "4":
                _do_user_stats_sorted()

            elif ch == "5":
                print()
                info(f"Синхронизация {len(users)} пользователей в xray config.json + users.json...")
                _unified_save_users(users)
                # Определяем реальный путь к конфигу (CONFIG_DIR первичен)
                _cfg_candidates = [
                    CONFIG_DIR / "config.json",
                    Path("/usr/local/etc/xray/config.json"),
                ]
                _cfg_to_test = next(
                    (str(p) for p in _cfg_candidates if p.exists()), None
                )
                if _cfg_to_test is None:
                    warn("Конфиг Xray не найден — Xray не перезапущен.")
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue
                # Валидация: используем "run -test" (работает во всех версиях Xray)
                val = _run(
                    [str(XRAY_BIN), "run", "-test", "-config", _cfg_to_test],
                    capture=True, check=False, quiet=True
                )
                if val.returncode == 0:
                    _run(["systemctl", "restart", "xray"], check=False, quiet=True)
                    time.sleep(2)
                    r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
                    if r.stdout.strip() == "active":
                        success(f"Готово — {len(users)} пользователей применено, Xray перезапущен")
                    else:
                        # Xray не стартовал — выводим последние строки journalctl
                        warn("Xray не запустился после обновления пользователей!")
                        r_jnl = _run(
                            ["journalctl", "-u", "xray", "-n", "10", "--no-pager"],
                            capture=True, check=False, quiet=True
                        )
                        if r_jnl.stdout.strip():
                            print(f"{DIM}{r_jnl.stdout.strip()}{NC}")
                else:
                    warn("Конфиг невалиден — Xray не перезапущен.")
                    err_out = (val.stdout + val.stderr).strip()
                    if err_out:
                        print(f"{DIM}{err_out[:400]}{NC}")
                input(f"{BLUE}Нажмите Enter...{NC}")

            elif ch == "6":
                if not users:
                    warn("Нет пользователей")
                    time.sleep(1)
                    continue
                print()
                _box_top("Выберите пользователя")
                for i, u in enumerate(users, 1):
                    icon  = _device_icon(u.get("device_label", ""))
                    label = u.get("device_label") or f"{DIM}нет метки{NC}"
                    _box_item(f"{i}", f"{u.get('name','—'):<16} {icon} {label}")
                _box_bottom()
                raw = input("  Номер пользователя: ").strip()
                if not (raw.isdigit() and 1 <= int(raw) <= len(users)):
                    warn("Неверный номер")
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue
                u = users[int(raw) - 1]
                cur_label = u.get("device_label", "")
                print()
                if cur_label:
                    print(f"  Текущая метка: {_device_icon(cur_label)} {cur_label}")
                print(f"  {DIM}Примеры: iPhone-Ivan, PC-Work, iPad-Child, Router-Home{NC}")
                new_label = input("  Новая метка (Enter = очистить): ").strip()
                users[int(raw) - 1]["device_label"] = new_label
                _unified_save_users(users)
                if new_label:
                    success(f"Метка изменена: {_device_icon(new_label)} {new_label}")
                else:
                    success("Метка удалена")
                input(f"{BLUE}Нажмите Enter...{NC}")

            elif ch == "7":
                if not users:
                    warn("Нет пользователей")
                    time.sleep(1)
                    continue
                print()
                _box_top("Вкл/Выкл пользователя")
                for i, u in enumerate(users, 1):
                    disabled = u.get("disabled", False)
                    status   = f"{RED}[ОТКЛ]{NC}" if disabled else f"{GREEN}[акт]{NC}"
                    icon     = _device_icon(u.get("device_label", ""))
                    label    = u.get("device_label") or u.get("name", "—")
                    _box_item(f"{i}", f"{status} {icon} {label:<20} {DIM}{u.get('email','')}{NC}")
                _box_bottom()
                raw = input("  Номер пользователя для переключения: ").strip()
                if not (raw.isdigit() and 1 <= int(raw) <= len(users)):
                    warn("Неверный номер")
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue
                idx     = int(raw) - 1
                now_dis = _user_toggle_disabled(users, idx)
                u       = users[idx]
                label   = u.get("device_label") or u.get("name", u.get("email",""))
                if now_dis:
                    warn(f"Пользователь '{label}' ОТКЛЮЧЁН (UUID сохранён)")
                else:
                    success(f"Пользователь '{label}' ВОССТАНОВЛЕН")
                input(f"{BLUE}Нажмите Enter...{NC}")

            elif ch == "8":
                # Редактирование имени и email пользователя
                if not users:
                    warn("Нет пользователей")
                    time.sleep(1)
                    continue
                print()
                _box_top("Редактировать пользователя")
                for i, u in enumerate(users, 1):
                    icon  = _device_icon(u.get("device_label", ""))
                    _box_item(f"{i}", f"{u.get('name','—'):<16} {icon}  {DIM}{u.get('email','')}{NC}")
                _box_bottom()
                raw = input("  Номер пользователя: ").strip()
                if not (raw.isdigit() and 1 <= int(raw) <= len(users)):
                    warn("Неверный номер")
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue
                idx = int(raw) - 1
                u   = users[idx]
                print()
                print(f"  {BOLD}Текущие данные:{NC}")
                print(f"    Имя:   {u.get('name','—')}")
                print(f"    Email: {u.get('email','—')}")
                print()
                print(f"  {DIM}Оставьте поле пустым чтобы не менять его.{NC}")
                new_name  = input(f"  Новое имя  [{u.get('name','')}]: ").strip()
                new_email = input(f"  Новый email [{u.get('email','')}]: ").strip()

                if not new_name and not new_email:
                    warn("Ничего не изменено")
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue

                # Проверяем уникальность нового email
                if new_email and new_email != u.get("email"):
                    if any(uu.get("email") == new_email for j, uu in enumerate(users) if j != idx):
                        warn(f"Email '{new_email}' уже занят другим пользователем")
                        input(f"{BLUE}Нажмите Enter...{NC}")
                        continue

                old_email = u.get("email", "")
                if new_name:
                    users[idx]["name"]  = new_name
                if new_email:
                    users[idx]["email"] = new_email

                # Синхронно сохраняем в users.json и xray config.json
                _unified_save_users(users)
                _log_change("user_edit",
                    f"Изменён: {u.get('name','?')} → name='{new_name or '(без изм.)'}'"
                    f" email='{new_email or '(без изм.)'}'")
                success("Данные пользователя обновлены")
                if new_email:
                    info(f"Email изменён: {old_email} → {new_email} (обновлено в xray config + users.json)")
                warn("Не забудьте применить список [5] чтобы Xray подхватил изменение email")
                input(f"{BLUE}Нажмите Enter...{NC}")

            elif ch == "e":
                if not users:
                    warn("Нет пользователей для экспорта")
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue
                _do_export_users_zip(users, install_mode)
                input(f"{BLUE}Нажмите Enter...{NC}")

            elif ch in ("q", ""):
                break
            else:
                warn("Неверный выбор")
                time.sleep(1)
    finally:
        _BOX_W = _saved_BOX_W


# (do_manage_geo_update вынесен в vless_installer.modules.geo_files;
#  импорт — в верхней секции этого файла.)


# ---------------------------------------------------------------------------
#  6. ЭКСПОРТ / ИМПОРТ КОНФИГУРАЦИИ
# ---------------------------------------------------------------------------
EXPORT_INCLUDE = [
    (CONFIG_DIR / "config.json",        "config.json"),
    (Path("/usr/local/etc/xray/config.json"), "config_usr_local.json"),
    (STATE_FILE,                        "state.json"),
    (USERS_FILE,                        "users.json"),
    (SPLIT_TUNNEL_CUSTOM_FILE,          "split_tunnel_custom.json"),
    (GEOSITE_DAT,                       "geosite.dat"),
    (GEOIP_DAT,                         "geoip.dat"),
    (Path("/root/vless_link.txt"),       "vless_link.txt"),
    (Path("/root/vless_chain_summary.txt"), "vless_chain_summary.txt"),
    # AS-routing (патч: задача #6)
    (Path("/etc/xray/as_direct_list.json"), "as_direct_list.json"),
]


def _patch_imported_config_socket(cfg_path: Path) -> bool:
    """
    После импорта config.json из бэкапа патчит socket-путь в realitySettings.dest
    и в nginx-конфиге, заменяя старый /dev/shm/XXXX.socket на текущий из state.json.

    Проблема: при переустановке генерируется новый socket path (hex-имя).
    Если поверх нового config.json наложить бэкап со старым путём —
    Xray пытается подключиться к несуществующему сокету и падает с:
      "failed to dial dest: dial unix /dev/shm/OLDNAME.socket: no such file"

    Возвращает True если патч был применён.
    """
    if not STATE_FILE.exists():
        return False
    try:
        state = json.loads(STATE_FILE.read_text())
    except Exception:
        return False

    current_socket = state.get("socket", "")
    if not current_socket:
        return False  # не REALITY — патч не нужен

    if not cfg_path.exists():
        return False

    try:
        cfg = json.loads(cfg_path.read_text())
    except Exception as e:
        warn(f"  Не удалось прочитать {cfg_path} для патча сокета: {e}")
        return False

    patched = False
    for inb in cfg.get("inbounds", []):
        rs = inb.get("streamSettings", {}).get("realitySettings", {})
        old_dest = rs.get("dest", "")
        if old_dest and old_dest != current_socket and old_dest.endswith(".socket"):
            rs["dest"] = current_socket
            patched = True
            info(f"  socket: {old_dest!r} → {current_socket!r}")

    if patched:
        cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
        _set_config_owner(cfg_path)
        success(f"  Патч socket применён в {cfg_path.name}")

        # Патчим nginx.conf если там тоже прописан старый сокет
        _patch_nginx_socket(old_dest, current_socket)

    return patched


def _patch_nginx_socket(old_sock: str, new_sock: str) -> None:
    """Заменяет старый socket-путь в nginx-конфигах на новый."""
    nginx_dirs = [
        Path("/etc/nginx/sites-enabled"),
        Path("/etc/nginx/conf.d"),
        Path("/etc/nginx"),
    ]
    for nginx_dir in nginx_dirs:
        if not nginx_dir.is_dir():
            continue
        for conf in nginx_dir.rglob("*.conf"):
            try:
                text = conf.read_text()
                if old_sock in text:
                    conf.write_text(text.replace(old_sock, new_sock))
                    info(f"  nginx: {conf.name} пропатчен ({old_sock!r} → {new_sock!r})")
            except Exception:
                pass


def _import_users_only(archive_path: Path) -> bool:
    """
    Импортирует ТОЛЬКО пользователей (users.json) из архива бэкапа.
    Не трогает config.json, state.json и другие системные файлы —
    тем самым избегает проблемы несовпадения socket-пути.

    Применяет импортированных пользователей к текущему конфигу Xray.
    Возвращает True при успехе.
    """
    import tarfile

    if not tarfile.is_tarfile(archive_path):
        warn("Файл не является tar-архивом")
        return False

    with tempfile.TemporaryDirectory(prefix="xray_userimport_") as tmpdir:
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(tmpdir)

        candidates = list(Path(tmpdir).rglob("users.json"))
        if not candidates:
            warn("users.json не найден в архиве")
            return False

        try:
            imported_users: list[dict] = json.loads(candidates[0].read_text())
        except Exception as e:
            warn(f"Не удалось прочитать users.json из архива: {e}")
            return False

    if not imported_users:
        warn("Список пользователей в архиве пуст")
        return False

    # Объединяем с текущими пользователями (добавляем только новых)
    current_users = _users_load()
    current_emails = {u.get("email") for u in current_users}
    current_uuids  = {u.get("uuid")  for u in current_users}

    added = []
    skipped = []
    for u in imported_users:
        if u.get("email") in current_emails or u.get("uuid") in current_uuids:
            skipped.append(u.get("email", u.get("uuid", "?")))
        else:
            # Очищаем поля блокировки — пользователь должен быть активен
            u.pop("blocked",      None)
            u.pop("blocked_at",   None)
            u.pop("block_reason", None)
            current_users.append(u)
            added.append(u.get("email", u.get("uuid", "?")))
            current_emails.add(u.get("email"))
            current_uuids.add(u.get("uuid"))

    if not added:
        if skipped:
            info(f"Все {len(skipped)} пользователей из бэкапа уже есть в системе")
        return True

    _users_save(current_users)
    success(f"Добавлено пользователей: {len(added)}")
    for e in added:
        dim(f"  + {e}")
    if skipped:
        dim(f"  (пропущено дублей: {len(skipped)})")

    # Применяем к Xray только незаблокированных
    active = [u for u in current_users if not u.get("blocked") and not u.get("disabled")]
    ok = _users_apply_to_config(active)
    if ok:
        success("Пользователи применены в Xray")
    else:
        warn("Не удалось применить пользователей в Xray — проверьте конфиг")
    return ok


def _backup_encrypt(archive_path: Path, password: str) -> Path | None:
    """
    Шифрует tar.gz архив через openssl AES-256-CBC → .tar.gz.enc
    Возвращает путь к зашифрованному файлу или None при ошибке.
    """
    enc_path = archive_path.with_suffix(".gz.enc")
    r = _run([
        "openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "310000",
        "-in",  str(archive_path),
        "-out", str(enc_path),
        "-pass", f"pass:{password}",
    ], capture=True, check=False)
    if r.returncode != 0:
        warn(f"openssl enc завершился с ошибкой: {r.stderr[:200]}")
        return None
    enc_path.chmod(0o600)
    return enc_path


def _backup_decrypt(enc_path: Path, password: str, out_path: Path) -> bool:
    """
    Расшифровывает .tar.gz.enc → tar.gz через openssl.
    Возвращает True при успехе.
    """
    r = _run([
        "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "310000",
        "-in",  str(enc_path),
        "-out", str(out_path),
        "-pass", f"pass:{password}",
    ], capture=True, check=False)
    if r.returncode != 0:
        warn(f"Расшифровка не удалась: {r.stderr[:200]}")
        return False
    return True


def do_export_config(encrypt: bool = False) -> None:
    """Упаковывает ключевые файлы конфигурации в tar.gz архив.
    При encrypt=True дополнительно шифрует AES-256-CBC через openssl.
    """
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    archive_name = f"xray-backup-{ts}.tar.gz"
    archive_path = Path(f"/root/{archive_name}")

    info(f"Экспорт конфигурации → {archive_path}")

    # Базовый список + AWG-конфиги при AWG-режиме
    _export_list = list(EXPORT_INCLUDE)
    try:
        if STATE_FILE.exists():
            _st = json.loads(STATE_FILE.read_text())
            if _st.get("awg_exit_enabled") and _st.get("install_mode") == "B":
                _awg_dir = Path("/etc/amnezia/amneziawg")
                if _awg_dir.exists():
                    for _af in _awg_dir.glob("*.conf"):
                        _export_list.append((_af, f"awg_{_af.name}"))
                _awg_svc = Path("/etc/systemd/system/amneziawg-awg0.service")
                if _awg_svc.exists():
                    _export_list.append((_awg_svc, "amneziawg-awg0.service"))
    except Exception:
        pass

    # AS-routing: кеш префиксов для каждого активного ASN (патч: задача #6)
    try:
        for _as_entry in _as_direct_list_load():
            _as_cache_f = _as_direct_file(_as_entry["asn"])
            if _as_cache_f.exists():
                _export_list.append((_as_cache_f, f"as_prefix_{_as_entry['asn']}.txt"))
    except Exception:
        pass

    with tempfile.TemporaryDirectory(prefix="xray_export_") as tmpdir:
        tmp = Path(tmpdir)
        copied = []

        for src, dest_name in _export_list:
            if src.exists():
                shutil.copy2(src, tmp / dest_name)
                copied.append(dest_name)
                dim(f"  + {dest_name}")
            else:
                dim(f"  - {dest_name} (не найден, пропущен)")

        if not copied:
            warn("Нечего экспортировать — файлы конфигурации не найдены")
            return

        # Добавляем README с инструкцией
        readme = tmp / "README.txt"
        readme.write_text(textwrap.dedent(f"""\
            VLESS Ultimate Installer — архив конфигурации
            Создан: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            Включает: {', '.join(copied)}
            {'Зашифрован: AES-256-CBC (openssl enc -d -aes-256-cbc -pbkdf2)' if encrypt else 'Не зашифрован'}

            Для восстановления:
              1. Запустите install_pinned_nodes_warp.py
              2. Выберите [I] Импорт конфигурации из архива
              3. Укажите путь к этому файлу
        """))

        import tarfile
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(tmpdir, arcname="xray-backup")

    archive_path.chmod(0o600)
    size_kb = archive_path.stat().st_size // 1024
    success(f"Архив создан: {archive_path} ({size_kb} КБ)")

    if encrypt:
        import getpass as _getpass
        print()
        _box_row(f"  {BOLD}Шифрование архива (AES-256-CBC){NC}")
        _box_row(f"  {DIM}Пароль используется только для шифрования — не хранится нигде.{NC}")
        try:
            pwd1 = _getpass.getpass("  Пароль для шифрования: ")
            pwd2 = _getpass.getpass("  Повтор пароля:         ")
        except Exception:
            # Fallback если getpass недоступен (нет TTY)
            pwd1 = input("  Пароль для шифрования: ").strip()
            pwd2 = input("  Повтор пароля:         ").strip()
        if pwd1 != pwd2:
            warn("Пароли не совпадают — архив сохранён без шифрования")
        elif len(pwd1) < 8:
            warn("Пароль слишком короткий (минимум 8 символов) — без шифрования")
        else:
            enc_path = _backup_encrypt(archive_path, pwd1)
            if enc_path:
                archive_path.unlink()   # удаляем незашифрованный
                enc_size_kb = enc_path.stat().st_size // 1024
                success(f"Зашифрованный архив: {enc_path} ({enc_size_kb} КБ)")
                _box_row(f"  {GREEN}Для расшифровки:{NC}")
                _box_row(f"    openssl enc -d -aes-256-cbc -pbkdf2 -iter 310000 \\")
                _box_row(f"      -in {enc_path.name} -out backup.tar.gz")
                archive_path = enc_path
            else:
                warn("Шифрование не удалось — архив сохранён без шифрования")

    info(f"Скопируйте файл: scp root@SERVER:/root/{archive_path.name} ./")


def do_import_config() -> None:
    """Восстанавливает конфигурацию из tar.gz архива."""
    archive_raw = input(f"  Путь к архиву (.tar.gz): ").strip()
    archive_path = Path(archive_raw)

    if not archive_path.exists():
        warn(f"Файл не найден: {archive_path}")
        return

    import tarfile
    if not tarfile.is_tarfile(archive_path):
        warn("Файл не является tar-архивом")
        return

    print()
    _box_top("Режим импорта")
    _box_row(f"  {BOLD}[1]{NC}  Полный импорт  {DIM}(конфиг + пользователи + state){NC}")
    _box_row(f"  {BOLD}[2]{NC}  Только пользователи  {DIM}(безопасно при переустановке){NC}")
    _box_row(f"  {DIM}Совет: выбирайте [2] если переустанавливали сервер с нуля.{NC}")
    _box_row(f"  {DIM}Полный импорт копирует старый config.json со старым socket-путём{NC}")
    _box_row(f"  {DIM}и может сломать Xray если socket изменился после переустановки.{NC}")
    _box_bottom()
    mode_ch = input(f"{CYAN}Выбор [1/2]:{NC} ").strip()

    if mode_ch == "2":
        print()
        info("Импорт только пользователей из архива...")
        _import_users_only(archive_path)
        return

    if mode_ch != "1":
        info("Отменено")
        return

    warn("ВНИМАНИЕ: импорт перезапишет текущие файлы конфигурации!")
    ans = input(f"{YELLOW}Продолжить? [y/N]:{NC} ").strip().lower()
    if ans != "y":
        info("Отменено")
        return

    restore_map = {dest_name: src for src, dest_name in EXPORT_INCLUDE}

    with tempfile.TemporaryDirectory(prefix="xray_import_") as tmpdir:
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(tmpdir)

        tmp = Path(tmpdir)
        restored = []

        # Ищем файлы рекурсивно (архив может иметь вложенную папку)
        for name, dst_path in restore_map.items():
            candidates = list(tmp.rglob(name))
            if not candidates:
                dim(f"  - {name} (не найден в архиве)")
                continue
            src_file = candidates[0]
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_file, dst_path)
            try:
                dst_path.chmod(0o640)
            except Exception:
                pass
            restored.append(name)
            dim(f"  + {name} → {dst_path}")

        # AS-routing: восстановление кеш-файлов префиксов (патч: задача #6)
        for _as_cache_src in tmp.rglob("as_prefix_AS*.txt"):
            _asn_name = _as_cache_src.stem.replace("as_prefix_", "")
            _as_dst = Path("/etc/xray") / f"as_direct_{_asn_name}.txt"
            _as_dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(_as_cache_src, _as_dst)
            try:
                _as_dst.chmod(0o640)
            except Exception:
                pass
            restored.append(_as_cache_src.name)
            dim(f"  + {_as_cache_src.name} → {_as_dst}")

    if not restored:
        warn("Ни один файл не был восстановлен")
        return

    success(f"Восстановлено файлов: {len(restored)}")

    # ── ПАТЧ СОКЕТА ─────────────────────────────────────────────────────────
    # После полного импорта в config.json может остаться старый socket-путь
    # из бэкапа (например /dev/shm/21fb4451.socket), тогда как новая
    # установка использует другой путь. Патчим автоматически.
    print()
    info("Проверка socket-пути в импортированном конфиге...")
    socket_patched = False
    for cfg_path in (CONFIG_DIR / "config.json",
                     Path("/usr/local/etc/xray/config.json")):
        if _patch_imported_config_socket(cfg_path):
            socket_patched = True
    if not socket_patched:
        dim("  socket-путь совпадает или патч не требуется")

    # Перезапуск Xray
    print()
    val = _run([str(XRAY_BIN), "run", "-test", "-config",
                str(CONFIG_DIR / "config.json")],
               capture=True, check=False, quiet=True)
    if val.returncode == 0:
        _run(["systemctl", "restart", "xray"], check=False, quiet=True)
        time.sleep(2)
        r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
        if r.stdout.strip() == "active":
            success("Xray перезапущен с восстановленным конфигом")
        else:
            warn("Xray не запустился — journalctl -u xray -n 20")
            r_jnl = _run(["journalctl", "-u", "xray", "-n", "10", "--no-pager"],
                         capture=True, check=False, quiet=True)
            if r_jnl.stdout.strip():
                print(f"{DIM}{r_jnl.stdout.strip()}{NC}")
    else:
        warn("Конфиг из архива невалиден — Xray не перезапускался")
        warn((val.stdout + val.stderr)[:300])


def do_manage_backup() -> None:
    """Меню экспорта/импорта конфигурации."""
    while True:
        os.system("clear")
        _box_top(f"Экспорт / Импорт конфигурации")

        # Список существующих бэкапов
        backups = sorted(Path("/root").glob("xray-backup-*.tar.gz"), reverse=True)
        if backups:
            _box_row(f"  {BOLD}Существующие архивы в /root/:{NC}")
            for bp in backups[:5]:
                sz = bp.stat().st_size // 1024
                _box_row(f"    {DIM}{bp.name}{NC}  ({sz} КБ)")
        else:
            _box_row(f"  {DIM}Архивов в /root/ не найдено{NC}")

        _box_item("1", f"📦 Экспортировать конфигурацию (создать архив)")
        _box_item("2", f"🔐 Экспортировать с шифрованием  {DIM}(AES-256-CBC){NC}")
        _box_item("3", f"📂 Импортировать конфигурацию (полный или только пользователи)")
        _box_item("4", f"👥 Импорт только пользователей из архива  {DIM}(безопасно после переустановки){NC}")
        _box_item("5", f"🗑️  Удалить старые архивы (оставить последние 3)")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            do_export_config(encrypt=False)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            do_export_config(encrypt=True)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            # Поддержка .enc файлов — расшифровываем перед импортом
            archive_raw = input(f"  Путь к архиву (.tar.gz или .gz.enc): ").strip()
            ap = Path(archive_raw)
            if not ap.exists():
                warn(f"Файл не найден: {ap}")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            if ap.suffix == ".enc":
                import getpass as _getpass
                try:
                    pwd = _getpass.getpass("  Пароль для расшифровки: ")
                except Exception:
                    pwd = input("  Пароль для расшифровки: ").strip()
                dec_path = ap.with_suffix("").with_suffix(".tar.gz")
                if not _backup_decrypt(ap, pwd, dec_path):
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue
                info(f"Расшифровано → {dec_path}")
                ap = dec_path
            do_import_config()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            print()
            archive_raw = input(f"  Путь к архиву (.tar.gz): ").strip()
            ap = Path(archive_raw)
            if not ap.exists():
                warn(f"Файл не найден: {ap}")
            else:
                _import_users_only(ap)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            to_del = sorted(Path("/root").glob("xray-backup-*"), reverse=True)[3:]
            if not to_del:
                info("Нечего удалять (архивов ≤ 3)")
            else:
                for f in to_del:
                    f.unlink()
                    dim(f"  Удалён: {f.name}")
                success(f"Удалено {len(to_del)} старых архивов")
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)



# (Scheduled backup — _SCHEDULED_BACKUP_CRON, _scheduled_backup_run,
#  do_manage_scheduled_backup — вынесены в vless_installer.modules.backup_manager;
#  импорт — в верхней секции этого файла.)


# ---------------------------------------------------------------------------
#  7. ТЕСТ СКОРОСТИ ЧЕРЕЗ EXIT-НОДЫ (все ноды по очереди)
# ---------------------------------------------------------------------------
def _speed_test_node_latency(host: str, port: int) -> str:
    """
    Измеряет TCP-латентность до хоста через прямое подключение (socket).
    Возвращает строку с результатом.
    """
    try:
        start = time.time()
        ip = socket.gethostbyname(host)
        s = socket.create_connection((ip, port), timeout=5)
        s.close()
        ms = (time.time() - start) * 1000
        return f"{GREEN}{ms:.0f} мс{NC}"
    except socket.timeout:
        return f"{RED}таймаут{NC}"
    except Exception as e:
        return f"{RED}ошибка ({e}){NC}"


def _speed_test_node_geo(host: str) -> tuple[str, str, str, str, str]:
    """
    Возвращает (ip, country_cc, country, city, isp) для хоста через ip-api.com.
    """
    try:
        ip = socket.gethostbyname(host)
        r = _run(
            ["curl", "-s", "--max-time", "8",
             f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,query"],
            capture=True, check=False
        )
        if r.returncode != 0 or not r.stdout.strip():
            return ip, "??", "неизвестно", "?", "?"
        data = json.loads(r.stdout.strip())
        if data.get("status") != "success":
            return ip, "??", "неизвестно", "?", "?"
        return (
            data.get("query", ip),
            data.get("countryCode", "??"),
            data.get("country", "неизвестно"),
            data.get("city", "?"),
            data.get("isp", "?"),
        )
    except Exception:
        return host, "??", "неизвестно", "?", "?"


def _speed_test_download(resolve_host: str, resolve_ip: str, port: int, size_mb_target: int = 10) -> str:
    """
    Измеряет скорость загрузки с Cloudflare.
    size_mb_target — размер файла в МБ (10 / 100 / 500 / 1000).
    Возвращает строку с результатом.
    """
    bytes_count = size_mb_target * 1024 * 1024
    timeout = max(60, size_mb_target * 8)
    url = f"https://speed.cloudflare.com/__down?bytes={bytes_count}"
    try:
        r = _run(
            ["curl", "-s", "-o", "/dev/null", "--max-time", str(timeout),
             "-w", "%{size_download} %{time_total} %{speed_download}",
             url],
            capture=True, check=False
        )
        parts = r.stdout.strip().split()
        if r.returncode != 0 or len(parts) < 3:
            return f"{RED}ошибка curl (код {r.returncode}){NC}"
        size_b     = int(parts[0])
        time_s     = float(parts[1])
        speed_bs   = float(parts[2])
        if size_b < 1024:
            return f"{YELLOW}Cloudflare недоступен с сервера — тестируйте на клиенте (fast.com){NC}"
        speed_mbit = speed_bs * 8 / 1_000_000
        size_mb    = size_b / 1_048_576
        colour     = GREEN if speed_mbit > 100 else YELLOW if speed_mbit > 20 else RED
        return f"{colour}{speed_mbit:.1f} Мбит/с{NC} ({size_mb:.0f} МБ за {time_s:.1f}с)"
    except Exception as e:
        return f"{RED}ошибка: {e}{NC}"


def _speed_test_mode_a(auto_mode: bool = False) -> None:
    """
    Тест скорости с Exit-ноды (Режим A) напрямую до интернета.
    Измеряет: GeoIP самого сервера, TCP latency до Cloudflare, Download с Cloudflare.
    auto_mode=True — пропускает интерактивный ввод, берёт дефолт 10 МБ.
    """
    print()
    print()
    _box_top(f"Тест скорости Exit-ноды (Режим A)")
    _box_row()
    _box_row(f"  {DIM}Сервер работает как Exit-нода — тест выполняется напрямую в интернет{NC}")
    _box_row()

    # --- GeoIP самого сервера ---
    _box_info("  Определение GeoIP этого сервера...")
    try:
        r_geo = _run(
            ["curl", "-s", "--max-time", "8",
             "http://ip-api.com/json/?fields=status,country,countryCode,city,isp,query"],
            capture=True, check=False
        )
        if r_geo.returncode == 0 and r_geo.stdout.strip():
            geo = json.loads(r_geo.stdout.strip())
            if geo.get("status") == "success":
                ip      = geo.get("query", "?")
                cc      = geo.get("countryCode", "??")
                country = geo.get("country", "неизвестно")
                city    = geo.get("city", "?")
                isp     = geo.get("isp", "?")
            else:
                ip, cc, country, city, isp = "?", "??", "неизвестно", "?", "?"
        else:
            ip, cc, country, city, isp = "?", "??", "неизвестно", "?", "?"
    except Exception:
        ip, cc, country, city, isp = "?", "??", "неизвестно", "?", "?"

    cc_colour = RED if cc == "RU" else GREEN
    _box_row(f"    IP:      {CYAN}{ip}{NC}")
    _geo_flag = country_flag_emoji(cc)
    _cty_tr   = country[:24]
    # Флаг + страна — вне рамки
    print(f"  {_geo_flag}  {cc_colour}{_cty_tr} ({cc}){NC}")
    if cc == "RU":
        _box_row(f"    {RED}⚠  Сервер в России — трафик не будет обходить блокировки!{NC}")
    else:
        _box_row(f"    {GREEN}✓  Сервер за пределами России — Exit-нода работает корректно{NC}")
    _box_row()

    # --- TCP latency до Cloudflare 1.1.1.1 ---
    _box_info("  Измерение TCP-латентности до Cloudflare (1.1.1.1:443)...")
    try:
        start = time.time()
        s = socket.create_connection(("1.1.1.1", 443), timeout=5)
        s.close()
        ms = (time.time() - start) * 1000
        lat_str = f"{GREEN}{ms:.0f} мс{NC}"
    except socket.timeout:
        lat_str = f"{RED}таймаут{NC}"
    except Exception as e:
        lat_str = f"{RED}ошибка ({e}){NC}"
    _box_row(f"    TCP latency → 1.1.1.1:443: {lat_str}")
    _box_row()

    # --- Проверка доступности Cloudflare и выбор размера ---
    _box_info("  Проверка доступности Cloudflare SpeedTest...")
    _probe = _run(
        ["curl", "-s", "-o", "/dev/null", "--max-time", "15",
         "-w", "%{size_download}",
         "https://speed.cloudflare.com/__down?bytes=1048576"],
        capture=True, check=False
    )
    _probe_ok = _probe.returncode == 0 and int(_probe.stdout.strip() or 0) > 500_000

    if _probe_ok:
        if auto_mode:
            dl_size_mb = 10
            _box_info("  Авто-режим: размер файла 10 МБ")
        else:
            SIZE_OPTIONS = {"1": 10, "2": 100, "3": 500, "4": 1000}
            _box_row(f"  {BOLD}Выберите размер файла для Download-теста:{NC}")
            _box_row(f"    {CYAN}1{NC}) 10 МБ   — быстро  (~1с на 1 Гбит/с)")
            _box_row(f"    {CYAN}2{NC}) 100 МБ  — оптимально")
            _box_row(f"    {CYAN}3{NC}) 500 МБ  — точно")
            _box_row(f"    {CYAN}4{NC}) 1000 МБ — максимально точно")
            _box_bottom()
            sz_choice = input(f"  {CYAN}Выбор [1-4, Enter = 2]:{NC} ").strip()
            dl_size_mb = SIZE_OPTIONS.get(sz_choice, 100)
            _box_top(f"Тест скорости Exit-ноды (Режим A)")
    else:
        _box_warn("  Cloudflare SpeedTest недоступен — проверьте сетевое подключение сервера")
        dl_size_mb = 0

    if dl_size_mb > 0:
        _box_row()
        _box_info(f"  Тест загрузки {dl_size_mb} МБ с Cloudflare (прямое подключение)...")
        dl = _speed_test_download("speed.cloudflare.com", "1.1.1.1", 443, dl_size_mb)
        _box_row(f"    Download (→ Cloudflare): {dl}")
        _box_row()
        log_to_file("INFO", f"SpeedTest Режим A: IP={ip}, CC={cc}, latency={lat_str}, DL={dl}")
    else:
        log_to_file("WARN", f"SpeedTest Режим A: IP={ip}, CC={cc} — Cloudflare недоступен")

    _box_row()
    _box_row(f"  {GREEN}✓ Тест скорости Exit-ноды завершён{NC}")
    _box_row()
    _box_bottom()


# =============================================================================
#  МАТРИЦА СОСТОЯНИЯ EXIT-НОД
# =============================================================================

def _access_log_bytes_per_node(nodes: list[dict], hours: int = 24) -> dict[str, int]:
    """
    Парсит /var/log/xray/access.log за последние `hours` часов.
    Возвращает dict: host → суммарные байты (upload+download).
    Сопоставление: ищем тег «chain-exit-N» в записях routing и связываем
    с нодой по индексу (chain-exit-1 → nodes[0], chain-exit-2 → nodes[1] …).
    """
    result: dict[str, int] = {nd["host"]: 0 for nd in nodes}
    if not DIAG_ACCESS_LOG.exists():
        return result

    cutoff = time.time() - hours * 3600

    # Паттерны байт (те же что в _diag_check_access_log)
    pat_ts      = re.compile(r'^(\d{4}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})')
    pat_bytes_a = re.compile(
        r'\[([^\]]+)\]\s+(\d+)\s+bytes?\s+upload,?\s+(\d+)\s+bytes?\s+download',
        re.IGNORECASE)
    pat_bytes_b = re.compile(r'>>\s+([\w\-]+)\s+\|\s+(\d+)\s+(\d+)\s+\|')
    pat_bytes_c = re.compile(r'\[([^\]]+)\s*->\s*([^\]]+)\]\s+(\d+)\s+(\d+)')
    pat_bytes_d = re.compile(r'(chain-exit-\d+)\s+\|\s+(\d+)\s+\|\s+(\d+)')

    # Индекс нод: "chain-exit-1" → nodes[0]
    tag_to_host: dict[str, str] = {}
    for i, nd in enumerate(nodes):
        tag_to_host[f"chain-exit-{i+1}"] = nd["host"]
        # Балансировщик часто пишет просто "balancer" или "chain-balancer"
        tag_to_host["balancer"]       = nd["host"]
        tag_to_host["chain-balancer"] = nd["host"]

    try:
        lines = DIAG_ACCESS_LOG.read_text(errors="replace").splitlines()[-60000:]
    except Exception:
        return result

    for line in lines:
        # Фильтр по времени
        ts_m = pat_ts.match(line)
        if ts_m:
            try:
                ts = datetime.strptime(
                    f"{ts_m.group(1)} {ts_m.group(2)}", "%Y/%m/%d %H:%M:%S"
                ).timestamp()
                if ts < cutoff:
                    continue
            except Exception:
                pass

        def _add(tag: str, up: int, dn: int) -> None:
            host = tag_to_host.get(tag)
            if host and host in result:
                result[host] += up + dn

        m = pat_bytes_a.search(line)
        if m:
            tag = m.group(1).split("->")[-1].strip()
            _add(tag, int(m.group(2)), int(m.group(3)))
            continue
        m = pat_bytes_b.search(line)
        if m:
            _add(m.group(1).strip(), int(m.group(2)), int(m.group(3)))
            continue
        m = pat_bytes_c.search(line)
        if m:
            _add(m.group(2).strip(), int(m.group(3)), int(m.group(4)))
            continue
        m = pat_bytes_d.search(line)
        if m:
            _add(m.group(1).strip(), int(m.group(2)), int(m.group(3)))

    return result


def do_node_health_matrix() -> None:
    """
    Матрица состояния всех exit-нод (Режим B / каскад).
    Для каждой ноды в одной таблице:
      • TCP ping (прямое подключение с этого сервера)
      • HTTP latency через ноду (curl --connect-to)
      • Трафик за 24ч (из access.log)
      • Роль: pinned / balancer / dead
    """
    os.system("clear")
    print()
    _box_top("🗺️   МАТРИЦА СОСТОЯНИЯ EXIT-НОД")
    _box_row(f"  {DIM}Проверяет все ноды каскада параллельно и выводит сводную таблицу.{NC}")
    _box_row()

    # ── Загрузка нод из state ────────────────────────────────────────────────
    nodes: list[dict] = []
    pinned_idx  = -1
    install_mode = "A"
    try:
        if STATE_FILE.exists():
            st = json.loads(STATE_FILE.read_text())
            nodes        = st.get("chain_nodes", [])
            pinned_idx   = st.get("chain_pinned_node_index", -1)
            install_mode = st.get("install_mode", "A")
    except Exception:
        pass

    if install_mode != "B" or not nodes:
        # Проверяем, не AWG-режим ли это
        _awg_on = False
        try:
            if STATE_FILE.exists():
                _awg_on = json.loads(STATE_FILE.read_text()).get("awg_exit_enabled", False)
        except Exception:
            pass
        if _awg_on:
            _box_info("  Режим AWG: матрица нод недоступна — выход через туннель awg0")
            _box_row(f"  {DIM}В режиме AWG нет VLESS exit-нод. Используйте AWG Watchdog{NC}")
            _box_row(f"  {DIM}(Меню → Безопасность → [W] AWG Tunnel Watchdog){NC}")
            # Покажем статус awg0 интерфейса
            _r_awg = _run(["ip", "link", "show", "awg0"], capture=True, check=False)
            if _r_awg.returncode == 0:
                _box_row(f"  {GREEN}● awg0 интерфейс активен{NC}")
            else:
                _box_row(f"  {RED}✗ awg0 не найден — туннель не поднят!{NC}")
            _r_rule = _run(["ip", "rule", "show"], capture=True, check=False)
            _fwmark_ok = str(AWG_FWMARK) in (_r_rule.stdout or "")
            if _fwmark_ok:
                _box_row(f"  {GREEN}● ip rule fwmark {AWG_FWMARK} присутствует{NC}")
            else:
                _box_row(f"  {RED}✗ ip rule fwmark {AWG_FWMARK} ОТСУТСТВУЕТ{NC}")
        else:
            _box_warn("Режим B (каскад) не настроен — нет exit-нод для проверки")
            _box_row(f"  {DIM}Матрица доступна только в Режиме B (chain-proxy).{NC}")
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    _box_row(f"  Нод в каскаде: {CYAN}{len(nodes)}{NC}  |  "
             f"Pinned: {CYAN}{'нода #'+str(pinned_idx+1) if pinned_idx >= 0 else 'нет (балансировщик)'}{NC}")
    _box_row()
    _box_info(f"Проверяем {len(nodes)} нод(у)...")

    # ── Динамические ширины колонок ──────────────────────────────────────────
    # "  " + № + " " + Host + " " + TCP + " " + HTTP + " " + Traffic + " " + Role
    _W_NUM     = 3
    _W_TCP     = 9   # "999 мс" / "таймаут"
    _W_HTTP    = 9
    _W_TRAFFIC = 9   # "1023 МБ"
    _W_ROLE    = 10  # "pinned" / "balancer" / "dead"
    _W_HOST    = (_BOX_W
                  - 2              # indent "  "
                  - _W_NUM - 1    # № + пробел
                  - _W_TCP - 1    # TCP + пробел
                  - _W_HTTP - 1   # HTTP + пробел
                  - _W_TRAFFIC - 1  # 24ч + пробел
                  - _W_ROLE - 1   # Роль + ведущий пробел
                  )
    _W_HOST    = max(16, _W_HOST)

    def _fmt_bytes(b: int) -> str:
        if b == 0:
            return f"{DIM}—{NC}"
        if b < 1024:
            return f"{b} Б"
        if b < 1024 ** 2:
            return f"{b//1024} КБ"
        if b < 1024 ** 3:
            return f"{b//1024**2} МБ"
        return f"{b//1024**3:.1f} ГБ"

    def _tcp_ms(host: str, port: int) -> tuple[int, str]:
        """Возвращает (ms_int, formatted_str). ms=-1 при недоступности."""
        try:
            t0 = time.time()
            ip = socket.gethostbyname(host)
            s  = socket.create_connection((ip, port), timeout=5)
            s.close()
            ms = int((time.time() - t0) * 1000)
            col = GREEN if ms < 150 else YELLOW if ms < 400 else RED
            return ms, f"{col}{ms} мс{NC}"
        except Exception:
            return -1, f"{RED}▼ down{NC}"

    def _http_ms(host: str, port: int) -> str:
        """HTTP latency через curl --connect-to (имитирует реальный клиент)."""
        try:
            r = _run([
                "curl", "-s", "-o", "/dev/null",
                "-w", "%{time_connect}",
                "--max-time", "8",
                "--connect-to", f"{host}:{port}:{host}:{port}",
                f"https://{host}:{port}/",
            ], capture=True, check=False)
            if r.returncode != 0 or not r.stdout.strip():
                return f"{DIM}—{NC}"
            ms = int(float(r.stdout.strip()) * 1000)
            col = GREEN if ms < 200 else YELLOW if ms < 500 else RED
            return f"{col}{ms} мс{NC}"
        except Exception:
            return f"{DIM}—{NC}"

    # ── Параллельный сбор данных ─────────────────────────────────────────────
    import threading

    n = len(nodes)
    tcp_results:  list[tuple[int, str]] = [(-1, "")] * n
    http_results: list[str]             = [""] * n

    def _probe(i: int, nd: dict) -> None:
        host = nd.get("host", "")
        port = int(nd.get("port", 443))
        tcp_results[i]  = _tcp_ms(host, port)
        http_results[i] = _http_ms(host, port)

    threads = [threading.Thread(target=_probe, args=(i, nd), daemon=True)
               for i, nd in enumerate(nodes)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=12)

    # Трафик из access.log (24ч)
    bytes_per_host = _access_log_bytes_per_node(nodes, hours=24)

    # ── Вывод таблицы ────────────────────────────────────────────────────────
    _box_row()
    _box_sep()

    # Заголовок
    hdr = (f"  {'№':{_W_NUM}}"
           f" {'Хост':{_W_HOST}}"
           f" {'TCP':>{_W_TCP}}"
           f" {'HTTP':>{_W_HTTP}}"
           f" {'24ч':>{_W_TRAFFIC}}"
           f" {'Роль':{_W_ROLE}}")
    _box_row(f"{BOLD}{hdr}{NC}")
    sep = (f"  {'─'*_W_NUM} {'─'*_W_HOST}"
           f" {'─'*_W_TCP} {'─'*_W_HTTP}"
           f" {'─'*_W_TRAFFIC} {'─'*_W_ROLE}")
    _box_row(sep)

    dead_count = 0
    for i, nd in enumerate(nodes):
        host     = nd.get("host", "?")
        port     = int(nd.get("port", 443))
        tcp_ms_v, tcp_str = tcp_results[i]
        http_str          = http_results[i]
        traffic_b         = bytes_per_host.get(host, 0)
        traffic_str       = _fmt_bytes(traffic_b)

        # Роль ноды
        is_dead   = tcp_ms_v < 0
        is_pinned = (i == pinned_idx)
        if is_dead:
            dead_count += 1
            role_str = f"{RED}dead{NC}"
        elif is_pinned:
            role_str = f"{CYAN}pinned{NC}"
        else:
            role_str = f"{DIM}balancer{NC}"

        host_disp = host if len(host) <= _W_HOST else host[:_W_HOST - 1] + "…"

        def _pad_ansi(s: str, width: int) -> str:
            """Дополняет строку с ANSI до видимой ширины width."""
            return s + " " * max(0, width - _wcslen(s))

        line = (f"  {BOLD}{i+1:>{_W_NUM}}{NC}"
                f" {CYAN if not is_dead else DIM}{host_disp:{_W_HOST}}{NC}"
                f" {_pad_ansi(tcp_str,  _W_TCP)}"
                f" {_pad_ansi(http_str, _W_HTTP)}"
                f" {_pad_ansi(traffic_str, _W_TRAFFIC)}"
                f" {_pad_ansi(role_str, _W_ROLE)}")
        _box_row(line)

    _box_row(sep)

    # ── Итог ─────────────────────────────────────────────────────────────────
    alive = len(nodes) - dead_count
    _box_row()
    if dead_count == 0:
        _box_row(f"  {GREEN}✓ Все {len(nodes)} нод(а) доступны{NC}")
    elif alive == 0:
        _box_row(f"  {RED}✗ Все ноды недоступны! Xray не может использовать каскад{NC}")
    else:
        _box_row(f"  {YELLOW}⚠  Доступно: {alive}/{len(nodes)}  |  "
                 f"Недоступно: {dead_count}/{len(nodes)}{NC}")

    log_bytes = sum(bytes_per_host.values())
    if log_bytes > 0:
        _box_row(f"  {DIM}Трафик за 24ч (из access.log): {_fmt_bytes(log_bytes)} суммарно{NC}")
    else:
        _box_row(f"  {DIM}Трафик: нет данных в access.log (нужен loglevel=info){NC}")

    _box_row()
    _box_bottom()
    input(f"{BLUE}Нажмите Enter...{NC}")


# =============================================================================
#  ОБНАРУЖЕНИЕ БЛОКИРОВКИ ПОРТА ПРОВАЙДЕРОМ (ВНЕШНЯЯ ПРОВЕРКА)
# =============================================================================

def do_port_block_detect() -> None:
    """
    Проверяет доступность порта сервера снаружи через check-host.net API.
    Запрашивает TCP-check с нескольких точек (RU, EU, Asia) одновременно,
    ждёт результата и показывает таблицу: точка → доступен/нет.

    Отвечает на вопрос «видит ли меня Россия/Европа?» — то, что нельзя
    проверить изнутри сервера.
    """
    global _BOX_W
    _BOX_W = _get_box_width()   # пересчитываем под актуальный размер терминала
    os.system("clear")
    print()
    _box_top("🔌  ПРОВЕРКА ДОСТУПНОСТИ ПОРТА СНАРУЖИ")
    _box_row(f"  {DIM}Проверяет, не заблокирован ли ваш порт российским провайдером.{NC}")
    _box_row(f"  {DIM}Запросы идут с внешних нод check-host.net (RU, EU, Asia).{NC}")
    _box_row()

    # ── Получаем домен и порт из state ──────────────────────────────────────
    domain = ""
    port   = 443
    try:
        if STATE_FILE.exists():
            st     = json.loads(STATE_FILE.read_text())
            domain = st.get("domain", "")
            port   = int(st.get("server_port", 443))
    except Exception:
        pass

    if not domain:
        domain = _box_input("Домен или IP сервера", reopen=True)
    if not domain:
        _box_warn("Домен не указан")
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    # Разрешаем порт интерактивно если нужно
    raw_port = _box_input(f"Порт [{port}]", default=str(port), reopen=False)
    if raw_port.isdigit():
        port = int(raw_port)

    # Бокс уже закрыт после _box_input(reopen=False)
    print()

    # ── Узлы check-host.net для проверки ─────────────────────────────────────
    # Выбираем узлы: приоритет на RU (главный вопрос), плюс EU и Asia для картины
    CHECK_NODES = [
        # RU — ключевые (блокировки обычно только в России)
        ("ru1.node.check-host.net",  "RU Москва"),
        ("ru2.node.check-host.net",  "RU Москва-2"),
        ("ru3.node.check-host.net",  "RU СПб"),
        ("ru4.node.check-host.net",  "RU Екатеринбург"),
        ("ru5.node.check-host.net",  "RU Новосибирск"),
        # EU
        ("de1.node.check-host.net",  "DE Франкфурт"),
        ("nl1.node.check-host.net",  "NL Амстердам"),
        ("fi1.node.check-host.net",  "FI Хельсинки"),
        ("pl1.node.check-host.net",  "PL Варшава"),
        # Asia / other
        ("tr2.node.check-host.net",  "TR Стамбул"),
        ("il1.node.check-host.net",  "IL Тель-Авив"),
        ("us1.node.check-host.net",  "US Ашберн"),
    ]

    CH_API   = "https://check-host.net"
    CH_HDR   = ["Accept: application/json"]

    # Открываем второй бокс — результаты (сразу, до запроса)
    _box_top(f"Результаты TCP-проверки {domain}:{port}")
    _box_info(f"Отправляем запрос на {len(CHECK_NODES)} нод check-host.net...")

    # Шаг 1: создаём задачу (request_id)
    nodes_param = "&".join(f"node={n}" for n, _ in CHECK_NODES)
    check_url   = (f"{CH_API}/check-tcp"
                   f"?host={domain}&port={port}&max_nodes={len(CHECK_NODES)}"
                   f"&{nodes_param}")
    r_init = _run(
        ["curl", "-s", "--max-time", "20",
         "-H", "Accept: application/json",
         check_url],
        capture=True, check=False
    )

    request_id = ""
    if r_init.returncode == 0 and r_init.stdout.strip().startswith("{"):
        try:
            init_data  = json.loads(r_init.stdout.strip())
            request_id = init_data.get("request_id", "")
        except Exception:
            pass

    if not request_id:
        _box_warn("check-host.net не ответил — проверяем запасным методом")
        _port_block_fallback(domain, port, CHECK_NODES)
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    _box_row(f"  {DIM}request_id: {request_id}{NC}")
    _box_info("Ждём результатов (до 15 сек)...")

    # Шаг 2: поллинг результатов (до 30 сек — дальним нодам нужно больше времени)
    result_data: dict = {}
    for attempt in range(10):
        time.sleep(3)
        r_res = _run(
            ["curl", "-s", "--max-time", "15",
             "-H", "Accept: application/json",
             f"{CH_API}/check-result/{request_id}"],
            capture=True, check=False
        )
        if r_res.returncode == 0 and r_res.stdout.strip().startswith("{"):
            try:
                raw = json.loads(r_res.stdout.strip())
                # API может вернуть {"ok":1, "nodes":{...}} или сразу плоский dict
                if isinstance(raw, dict) and "nodes" in raw:
                    result_data = raw["nodes"]
                else:
                    result_data = raw
                ready = sum(1 for v in result_data.values() if v is not None)
                if ready >= len(CHECK_NODES) // 2:
                    break
            except Exception:
                pass

    if not result_data:
        _box_warn("Не удалось получить результаты — используем резервный метод")
        _port_block_fallback(domain, port, CHECK_NODES)
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    # ── Вывод таблицы результатов ─────────────────────────────────────────────
    # Ширины: "  " + Label + " " + Status + " " + Latency
    # "заблокирован" = 12 символов → _W_STAT=12
    _W_STAT  = 12
    _W_LABEL = min(22, _BOX_W - 2 - 1 - _W_STAT - 1 - 6)
    _W_LAT   = _BOX_W - 2 - _W_LABEL - 1 - _W_STAT - 1

    # Вспомогательные функции с ANSI-aware padding
    def _tr(s: str, w: int) -> str:
        return s + " " * max(0, w - _wcslen(s))

    def _tl(s: str, w: int) -> str:
        return " " * max(0, w - _wcslen(s)) + s

    _box_row()
    # Заголовок — через _tr/_tl чтобы BOLD/NC не ломали питоновский :{w}
    _box_row(f"  {_tr(BOLD+'Точка'+NC, _W_LABEL)} {_tl(BOLD+'Статус'+NC, _W_STAT)} {_tl(BOLD+'Задержка'+NC, _W_LAT)}")
    _box_row(f"  {'─'*_W_LABEL} {'─'*_W_STAT} {'─'*_W_LAT}")

    ru_ok    = 0
    ru_total = 0
    eu_ok    = 0
    eu_total = 0

    # node_id → label: check-host может вернуть полное имя или короткое
    node_label: dict[str, str] = {}
    for n, lbl in CHECK_NODES:
        node_label[n] = lbl
        node_label[n.split(".")[0]] = lbl

    for node_id, res_list in result_data.items():
        short_id = node_id.split(".")[0]
        label    = node_label.get(node_id) or node_label.get(short_id) or short_id.upper()
        is_ru    = short_id.startswith("ru")
        is_eu    = any(short_id.startswith(c) for c in ("de", "nl", "fi", "pl"))

        if res_list is None:
            stat_str = f"{DIM}ожидание{NC}"
            lat_str  = f"{DIM}—{NC}"
        else:
            # [[1, "ip", latency_s]] — успех; [[0, "ip", null]] — отклонено; [null] — таймаут
            first = res_list[0] if isinstance(res_list, list) and res_list else None
            if first and isinstance(first, list) and len(first) >= 1:
                try:
                    code = int(first[0])
                except (TypeError, ValueError):
                    code = 0
                lat_s = first[2] if len(first) > 2 and first[2] else None
                ok    = (code == 1)
                stat_str = f"{GREEN}открыт{NC}" if ok else f"{RED}заблокирован{NC}"
                try:
                    lat_str = f"{int(float(lat_s)*1000)} мс" if lat_s else f"{DIM}—{NC}"
                except (TypeError, ValueError):
                    lat_str = f"{DIM}—{NC}"
                if is_ru:
                    ru_total += 1
                    if ok: ru_ok += 1
                if is_eu:
                    eu_total += 1
                    if ok: eu_ok += 1
            else:
                # таймаут [null] — считаем как недоступен
                stat_str = f"{YELLOW}нет ответа{NC}"
                lat_str  = f"{DIM}—{NC}"
                if is_ru: ru_total += 1
                if is_eu: eu_total += 1

        _box_row(f"  {_tr(label[:_W_LABEL], _W_LABEL)}"
                 f" {_tr(stat_str, _W_STAT)}"
                 f" {_tl(lat_str, _W_LAT)}")

    _box_row(f"  {'─'*_W_LABEL} {'─'*_W_STAT} {'─'*_W_LAT}")
    _box_row()

    # ── Вердикт ──────────────────────────────────────────────────────────────
    _box_row(f"  {BOLD}Итог:{NC}")
    _box_row()

    if ru_total > 0:
        if ru_ok == ru_total:
            _box_row(f"  {GREEN}✓ Порт {port} открыт из России ({ru_ok}/{ru_total} нод){NC}")
        elif ru_ok == 0:
            _box_row(f"  {RED}✗ Порт {port} ЗАБЛОКИРОВАН из России (0/{ru_total} нод){NC}")
            _box_row(f"  {YELLOW}  Рекомендации:{NC}")
            _box_row(f"  {YELLOW}  • Смените порт (443 → 8443 или 2053){NC}")
            _box_row(f"  {YELLOW}  • Проверьте UFW / iptables на этом сервере{NC}")
            _box_row(f"  {YELLOW}  • Уточните у хостера, не блокирует ли он входящие{NC}")
        else:
            _box_row(f"  {YELLOW}⚠  Частичная блокировка из России: "
                  f"{ru_ok}/{ru_total} нод видят порт{NC}")
            _box_row(f"  {DIM}  Возможна нестабильная работа у части пользователей{NC}")
    else:
        _box_row(f"  {YELLOW}⚠  Нет данных от российских нод — проверьте результаты EU{NC}")

    if eu_total > 0:
        eu_str = f"{GREEN}открыт{NC}" if eu_ok == eu_total else f"{YELLOW}частично{NC}"
        _box_row(f"  {DIM}Из Европы: {eu_str} ({eu_ok}/{eu_total} нод){NC}")

    log_to_file("INFO",
        f"port-block-detect: {domain}:{port} → RU {ru_ok}/{ru_total} OK, "
        f"EU {eu_ok}/{eu_total} OK")

    _box_row()
    _box_bottom()
    input(f"{BLUE}Нажмите Enter...{NC}")


def _port_block_fallback(domain: str, port: int,
                         check_nodes: list[tuple[str, str]]) -> None:
    """
    Резервный метод когда check-host.net API недоступен:
    прямые TCP-пробы с текущего сервера (показывает только «изнутри»,
    но хоть что-то лучше пустого экрана).
    """
    _box_sep()
    _box_row(f"  {YELLOW}Резервный метод: TCP-пробы с этого сервера (не снаружи){NC}")
    _box_row()

    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        ip = domain

    for attempt in range(3):
        try:
            t0 = time.time()
            s  = socket.create_connection((ip, port), timeout=5)
            s.close()
            ms = int((time.time() - t0) * 1000)
            _box_row(f"  {GREEN}✓ TCP {domain}:{port} доступен с сервера ({ms} ms){NC}")
            _box_row(f"  {DIM}  Если клиенты не подключаются — проблема на стороне их провайдера{NC}")
            return
        except Exception:
            time.sleep(1)

    _box_row(f"  {RED}✗ TCP {domain}:{port} недоступен даже с самого сервера{NC}")
    _box_row(f"  {RED}  Проверьте UFW (ufw status) и что Xray запущен{NC}")


# (do_speed_test — вынесен в vless_installer.modules.speed_test;
#  импорт — в верхней секции этого файла.)


# (do_reconfigure — вынесен в vless_installer.modules.reconfigure;
#  импорт — в верхней секции этого файла.)


# (SSH Hardening — _ssh_2fa_install, do_ssh_hardening, _SSHD_CONFIG, _SSHD_BACKUP —
#  вынесен в vless_installer.modules.ssh_hardening; импорт — в верхней секции
#  этого файла.)


# (UUID rotation — _uuid_rotate_now, _uuid_install_cron, do_manage_uuid_rotation,
#  _UUID_CRON_TAG, _UUID_CRON_SCRIPT — вынесены в
#  vless_installer.modules.credential_rotation; импорт — в верхней секции
#  этого файла.)


# (REALITY keys rotation — _rotate_reality_keys, do_manage_reality_keys —
#  вынесены в vless_installer.modules.credential_rotation; импорт — в
#  верхней секции этого файла.)


# (watchdog — _watchdog_install, _watchdog_remove, do_manage_watchdog —
#  вынесен в vless_installer.modules.fail2ban_setup; импорт — в верхней
#  секции этого файла.)


# (do_view_logs вынесен в vless_installer.modules.standalone_screens;
#  импорт — в верхней секции этого файла.)


# (do_check_domain_external вынесен в vless_installer.modules.standalone_screens;
#  импорт — в верхней секции этого файла.)


# (Failover — _failover_load/save/install, do_failover_status, _FAILOVER_*
#  — вынесены в vless_installer.modules.failover; импорт — в верхней секции
#  этого файла.)


# =============================================================================
#  ГЕНЕРАЦИЯ CLASH META / SING-BOX КОНФИГА
# =============================================================================
# (do_generate_client_config, do_export_client_config вынесены в
#  vless_installer.modules.client_config_export; импорт — в верхней
#  секции этого файла.)


# =============================================================================
#  ДАШБОРД СИСТЕМНЫХ РЕСУРСОВ
# =============================================================================
# (do_generate_client_config, do_export_client_config вынесены в
#  vless_installer.modules.client_config_export; импорт — в верхней
#  секции этого файла.)


# (do_system_dashboard вынесен в vless_installer.modules.standalone_screens;
#  импорт — в верхней секции этого файла.)


# (do_full_diagnostic — мастер полной диагностики, ~800 строк, wizard — вынесен
#  в vless_installer.modules.diagnostics; импорт — в верхней секции этого файла.)

# =============================================================================

# (Traffic limits — TRAFFIC_LIMITS_FILE, _limits_load/save,
#  _query_user_traffic_bytes, _stats_api_is_configured,
#  _check_traffic_limits_once, do_manage_traffic_limits — вынесены в
#  vless_installer.modules.traffic_tracking; импорт — в верхней секции
#  этого файла.)


# (TTL users + blocked — TTL_FILE/CRON_SCRIPT/CRON_FILE/LOG, BLOCKED_FILE,
#  _ttl_load/save/expires_str/is_expired/expires_within_hours/set/remove,
#  _blocked_load/save, _ttl_block_user/unblock_user/is_blocked,
#  _ttl_check_and_expire, _ttl_install_cron/remove_cron/cron_active,
#  do_manage_ttl_users — вынесены в vless_installer.modules.ttl_users;
#  импорт — в верхней секции этого файла.)


# (do_share_config_server вынесен в vless_installer.modules.client_config_export;
#  импорт — в верхней секции этого файла.)


# (Health report — do_health_report, _health_report_install_cron,
#  do_manage_health_report — вынесены в vless_installer.modules.health_report;
#  импорт — в верхней секции этого файла.)


# (Full migration — TG_CONFIG_FILE, do_full_migration_export,
#  do_full_migration_import — вынесены в vless_installer.modules.migration;
#  импорт — в верхней секции этого файла.)


# (Traffic history — TRAFFIC_HISTORY_FILE, _traffic_snapshot_save,
#  _install_traffic_snapshot_cron, do_traffic_history — вынесены в
#  vless_installer.modules.traffic_history; импорт — в верхней секции этого файла.)


# (GeoIP-блокировка — do_manage_geoip_block, _geoip_block_get_rules,
#  _geoip_apply_routing, _geoip_set_allowlist, _geoip_add_country_block,
#  _geoip_add_scanner_block — вынесены в vless_installer.modules.geoip_block;
#  импорт — в верхней секции этого файла.)


# =============================================================================
# (RU subnets + AS-direct routing — _fetch_ru_subnets_from_ripe,
#  _ru_subnets_apply_to_xray/remove_from_xray/install_timer/remove_timer,
#  _ru_subnets_cli_update, do_manage_ru_subnet_direct,
#  _as_normalize/validate/action_label/ask_action, _resolve_asn_from_input,
#  _as_direct_file/list_load/list_save/save/apply_to_xray/remove_from_xray,
#  _fetch_prefixes_for_asn, _as_suggest_server_asn,
#  _as_direct_install_timer/remove_timer/cli_update, do_manage_as_direct,
#  RU_SUBNETS_*, RIPE_DELEGATED_*, _RU_SUBNET_RULE_COMMENT, AS_DIRECT_*,
#  RIPE_STAT_PREFIXES_URL — вынесены в vless_installer.modules.ru_subnets
#  и vless_installer.modules.as_direct; импорт — в верхней секции этого файла.)


# (_geoip_remove_all вынесен в vless_installer.modules.geoip_block;
#  импорт — в верхней секции этого файла.)


# (Аудит подключений — do_connection_audit, _parse_access_log,
#  _audit_user_summary, _audit_recent_connections, _audit_suspicious,
#  _audit_active_now — вынесены в vless_installer.modules.connection_audit;
#  импорт — в верхней секции этого файла.)

# (AutoBan — _ban_report_rotate/append/show_in_box, _autoban_load/save/
#  get_chain_ips/run_once/install_cron, do_manage_autoban,
#  _XRAY_BAN_STATE/CRON/SCRIPT/LOG/REPORT, _BAN_THRESHOLD_DEFAULT,
#  _BAN_WINDOW_MINUTES, _BAN_WHITELIST_DEFAULT, _BAN_REPORT_TTL_DAYS —
#  вынесены в vless_installer.modules.autoban; импорт — в верхней секции
#  этого файла.)


# (Certbot monitor — _certbot_renew_and_notify, _certbot_install_monitor_cron,
#  do_manage_certbot_monitor, _CERTBOT_MONITOR_CRON, _CERTBOT_MONITOR_SCRIPT —
#  вынесены в vless_installer.modules.ssl_certbot; импорт — в верхней секции
#  этого файла.)


# (Quick status — do_quick_status — вынесен в vless_installer.modules.quick_status;
#  импорт — в верхней секции этого файла.)


# =============================================================================
#  ФИЧА 4: СОРТИРОВКА В СТАТИСТИКЕ ПОЛЬЗОВАТЕЛЕЙ
# =============================================================================
# (интегрируется в _do_user_stats_screen через аргумент sort_key)
# Реализована как отдельная обёртка, которая вызывается из меню U→4

# (_STATS_SORT_KEYS — вынесен в vless_installer.modules.quick_status;
#  импорт — в верхней секции этого файла.)


def _do_user_stats_sorted() -> None:
    """Выбор сортировки перед открытием статистики."""
    os.system("clear")
    print()
    _box_top(f"Статистика: выбор сортировки")
    _box_row()
    for k, (_, label) in _STATS_SORT_KEYS.items():
        _box_item(k, label)
    _box_item("Enter", "По умолчанию (по трафику)")
    _box_bottom()
    print()
    ch = input(f"{CYAN}Сортировка:{NC} ").strip()
    sort_key = _STATS_SORT_KEYS.get(ch, ("traffic", ""))[0]
    _do_user_stats_screen_v2(sort_key)


# (_do_user_stats_screen_v2 — вынесена в vless_installer.modules.users_manager;
#  импорт — в верхней секции этого файла.)



# =============================================================================
#  ФИЧА 5: ЭКСПОРТ СТАТИСТИКИ В CSV
# =============================================================================
def _export_stats_csv(rows: list) -> None:
    """Сохраняет таблицу статистики в CSV-файл."""
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path(f"/root/xray-stats-{ts}.csv")
    try:
        with path.open("w", encoding="utf-8") as f:
            f.write("№,Метка устройства,Имя,Email,↑ Отправлено (байт),↓ Получено (байт),"
                    "↑ Отправлено,↓ Получено,IP подключения,Последний визит\n")
            for i, row in enumerate(rows, 1):
                u     = row["user"]
                label = u.get("device_label", "")
                name  = u.get("name", "")
                email = row["email"]
                up_b  = row["up"]
                dn_b  = row["down"]
                ip    = row["ip"] or "—"
                ls    = row["last"]
                ts_s  = ls.strftime("%Y-%m-%d %H:%M") if ls else "—"
                f.write(
                    f'{i},"{label}","{name}","{email}",'
                    f'{up_b},{dn_b},'
                    f'"{_fmt_bytes_ru(up_b)}","{_fmt_bytes_ru(dn_b)}",'
                    f'"{ip}","{ts_s}"\n'
                )
        path.chmod(0o640)
        success(f"CSV сохранён: {path}")
        info(f"Скопируйте: scp root@SERVER:{path} ./")
        _log_change("stats_export", f"Статистика экспортирована в {path}")
    except Exception as e:
        warn(f"Ошибка создания CSV: {e}")


# =============================================================================
#  ФИЧА 6: ВРЕМЕННОЕ ОТКЛЮЧЕНИЕ ПОЛЬЗОВАТЕЛЯ (БЕЗ УДАЛЕНИЯ)
# =============================================================================
def _user_toggle_disabled(users: list, idx: int) -> bool:
    """
    Переключает флаг disabled у пользователя и применяет к Xray.
    Возвращает True = пользователь отключён, False = восстановлен.
    """
    u = users[idx]
    was_disabled = u.get("disabled", False)
    u["disabled"] = not was_disabled
    if not was_disabled:
        u["disabled_at"] = datetime.now(timezone.utc).isoformat()
    else:
        u.pop("disabled_at", None)

    # В конфиг Xray попадают только активные пользователи
    active_users = [usr for usr in users if not usr.get("disabled")]
    _unified_save_users(users)            # users.json хранит всех (с флагом)
    _users_apply_to_config(active_users)  # Xray получает только активных

    action = "отключён" if u["disabled"] else "восстановлен"
    label  = u.get("device_label") or u.get("name", u["email"])
    log_to_file("INFO", f"User {action}: {label} ({u['email']})")
    _log_change("user_toggle",
        f"Пользователь {action}: {label} ({u['email']})")
    _tg_notify_event(
        "user_connect" if not u["disabled"] else "xray_down",
        f"Пользователь <b>{label}</b> {'восстановлен ✅' if not u['disabled'] else 'временно отключён 🚫'}"
    )
    return u["disabled"]


# (Connection quality test — _TTFB_TARGETS, do_connection_quality_test —
#  вынесены в vless_installer.modules.quick_status; импорт — в верхней секции
#  этого файла.)


# =============================================================================
#  ФИЧА 8: ЛОГ ИЗМЕНЕНИЙ КОНФИГА
# =============================================================================
CHANGES_LOG_FILE = Path("/var/log/xray-changes.log")
CHANGES_DB_FILE  = Path("/var/lib/xray-installer/changes.json")


def _log_change(action: str, detail: str, user: str = "root") -> None:
    """
    Записывает изменение конфигурации в лог и JSON-базу.
    Вызывается из любого места скрипта при изменении настроек.
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Текстовый лог
    try:
        CHANGES_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with CHANGES_LOG_FILE.open("a") as f:
            f.write(f"[{ts}] [{action.upper():<20}] {detail}\n")
        CHANGES_LOG_FILE.chmod(0o640)
    except Exception:
        pass
    # JSON-база (последние 500 записей)
    try:
        CHANGES_DB_FILE.parent.mkdir(parents=True, exist_ok=True)
        try:
            db = json.loads(CHANGES_DB_FILE.read_text()) if CHANGES_DB_FILE.exists() else []
        except Exception:
            db = []
        db.append({"ts": ts, "action": action, "detail": detail, "user": user})
        # Ротация: оставляем последние 500
        db = db[-500:]
        CHANGES_DB_FILE.write_text(json.dumps(db, indent=2, ensure_ascii=False))
        CHANGES_DB_FILE.chmod(0o600)
    except Exception:
        pass


def do_view_changes_log() -> None:
    """Интерактивный просмотр лога изменений конфигурации."""
    while True:
        os.system("clear")
        print()
        _box_top(f"Лог изменений конфигурации")

        try:
            db = json.loads(CHANGES_DB_FILE.read_text()) if CHANGES_DB_FILE.exists() else []
        except Exception:
            db = []

        if not db:
            _box_row(f"  {DIM}Изменений пока не записано.{NC}")
            _box_row(f"  {DIM}Лог заполняется автоматически при изменении конфига.{NC}")
        else:
            _box_row(f"  Всего записей: {CYAN}{len(db)}{NC}")
            # Иконки по типу действия
            icons = {
                "user_add":       "👤+",
                "user_del":       "👤-",
                "user_toggle":    "👤⏸",
                "certbot_renew":  "🔒",
                "stats_export":   "📊",
                "geoip":          "🛡️",
                "tg":             "📬",
                "uuid_rotate":    "🔑",
                "reconfigure":    "🔄",
                "install":        "🚀",
                "ssh_hardening":  "🔒",
                "migration":      "📦",
                "as_routing":     "🔀",
            }
            # Группировка по дате
            by_date: dict = {}
            for entry in db:
                date = entry["ts"][:10]
                by_date.setdefault(date, []).append(entry)

            dates = sorted(by_date.keys(), reverse=True)
            for date in dates[:7]:  # последние 7 дней
                entries = by_date[date]
                _box_row(f"  {BOLD}{CYAN}{date}{NC}  {DIM}({len(entries)} изменений){NC}")
                for e in reversed(entries[-20:]):  # последние 20 за день
                    action = e.get("action", "")
                    icon   = next((v for k, v in icons.items()
                                   if k in action.lower()), "⚙️")
                    ts_short = e["ts"][11:16]
                    detail   = e.get("detail", "")[:60]
                    _box_row(f"  {DIM}{ts_short}{NC}  {icon}  {detail}")

        _box_item("1", f"Показать полный лог (tail)")
        _box_item("2", f"Фильтр по типу действия")
        _box_item("3", f"Очистить лог")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            if CHANGES_LOG_FILE.exists():
                lines = CHANGES_LOG_FILE.read_text().splitlines()[-50:]
                print()
                for line in lines:
                    print(f"  {DIM}{line}{NC}")
            else:
                warn("Лог-файл пуст")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            print()
            raw_filter = input("  Тип действия (например: user, cert, geoip): ").strip().lower()
            if raw_filter and db:
                filtered = [e for e in db if raw_filter in e.get("action", "").lower()
                            or raw_filter in e.get("detail", "").lower()]
                print()
                for e in filtered[-30:]:
                    print(f"  {DIM}{e['ts']}{NC}  [{e['action']}]  {e['detail'][:60]}")
                if not filtered:
                    warn("Ничего не найдено")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            ans = input(f"  {YELLOW}Очистить лог изменений? [y/N]:{NC} ").strip().lower()
            if ans == "y":
                CHANGES_LOG_FILE.unlink(missing_ok=True)
                CHANGES_DB_FILE.unlink(missing_ok=True)
                success("Лог очищен")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


#  ГЛАВНОЕ МЕНЮ
# =============================================================================

def do_patch_stats_api() -> None:
    """
    Патчит существующий config.json на месте: добавляет/обновляет секции
    stats, api, policy (statsUserUplink/Downlink + statsOutbound*), inbound и
    routing-правило для Stats API. Перезапускает Xray.
    Используется когда установка была сделана до патча statsUser* —
    без переустановки возвращает статистику трафика по пользователям.
    """
    print()
    print()
    _box_top(f"Патч Stats API (statsUserUplink/Downlink)")

    cfg_paths = [CONFIG_DIR / "config.json",
                 Path("/usr/local/etc/xray/config.json")]
    patched_any = False
    seen_real: set = set()

    for cfg_path in cfg_paths:
        if not cfg_path.exists():
            continue
        try:
            real = cfg_path.resolve()
        except Exception:
            real = cfg_path
        if real in seen_real:
            # симлинк на уже обработанный файл — пропускаем
            continue
        seen_real.add(real)
        try:
            cfg = json.loads(cfg_path.read_text())
            _apply_stats_to_config(cfg)
            # Явно гарантируем statsUser* и levels."0" — без обоих xray не считает трафик
            policy_dict_patch = cfg.setdefault("policy", {})
            policy_sys = policy_dict_patch.setdefault("system", {})
            policy_sys["statsOutboundUplink"]   = True
            policy_sys["statsOutboundDownlink"] = True
            policy_sys["statsUserUplink"]       = True
            policy_sys["statsUserDownlink"]     = True
            policy_lvl0 = policy_dict_patch.setdefault("levels", {}).setdefault("0", {})
            policy_lvl0["statsUserUplink"]   = True
            policy_lvl0["statsUserDownlink"] = True
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(cfg_path)
            _box_ok(f"Патч применён: {cfg_path}")
            patched_any = True
        except Exception as e:
            _box_warn(f"Ошибка патча {cfg_path}: {e}")

    if not patched_any:
        _box_warn("config.json не найден — сначала выполните установку (пункт 1)")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    # Валидируем и перезапускаем
    for test_path in (Path("/usr/local/etc/xray/config.json"),
                      CONFIG_DIR / "config.json"):
        if test_path.exists():
            val = _run([str(XRAY_BIN), "-test", "-config", str(test_path)],
                       capture=True, check=False, quiet=True)
            if val.returncode != 0:
                _box_warn("Xray конфиг невалиден после патча!")
                _box_warn((val.stdout + val.stderr)[:400])
                input(f"{BLUE}Нажмите Enter...{NC}")
                return
            break

    _run(["systemctl", "restart", "xray"], check=False, quiet=True)
    time.sleep(3)
    _r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
    _r2 = _run(["pgrep", "-x", "xray"], capture=True, check=False)
    if _r.stdout.strip() == "active" and _r2.returncode == 0:
        _box_ok("Xray: OK")
        _box_ok("Xray перезапущен. Статистика по пользователям будет накапливаться с этого момента.")
        _box_info("Откройте U → 4 (Статистика трафика детально) после прохождения трафика.")
    else:
        _box_warn("Xray не запустился после патча — проверьте логи: journalctl -u xray -n 50")
    _box_row()
    _box_bottom()
    input(f"{BLUE}Нажмите Enter...{NC}")


# =============================================================================
#  ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ: ОТРИСОВКА МЕНЮ В СТИЛЕ БАННЕРА VLESS
# box_renderer — перенесено в vless_installer/modules/box_renderer.py
# (do_emergency_repair — вынесена в vless_installer.modules.emergency_repair;
#  импорт — в верхней секции этого файла.)



# =============================================================================
#  ПОДМЕНЮ: 1 — УСТАНОВКА И СИСТЕМА
# =============================================================================
def _menu_install_system() -> None:
    while True:
        os.system("clear")
        print()
        _box_top("⚙️  УСТАНОВКА И СИСТЕМА")
        _box_row()
        _box_item("1", f"🚀 Установить / Переустановить  {DIM}(режим A или B){NC}")
        _box_item("D", f"🔍 Dry-run  {DIM}(предпросмотр — без изменений системы){NC}")
        _box_item("2", f"🔀 Переключить режим A ↔ B  {DIM}(без переустановки){NC}")
        _box_item("3", f"📦 Миграция  {DIM}(Экспорт / Импорт конфигурации){NC}")
        _box_item("4", f"⚡ Оптимизация системы  {DIM}(Sysctl / Limits){NC}")
        _box_item("5", "🔧 Обновить Xray-core")
        _box_item("6", f"🛠️  Аварийное восстановление  {DIM}(из state.json, без переустановки){NC}")
        _box_item("7", "🗑️  Удалить установку")
        _box_item("8", "🧪 Запустить unit-тесты")
        _box_item("9", f"🔀 Mieru Hybrid Addon  {DIM}(Mieru поверх Xray на Entry-ноде, SOCKS-петля){NC}")
        _box_row()
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break
        if ch == "1":
            do_full_install()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch.lower() == "d":
            do_dry_run()
        elif ch == "2":
            switch_mode_ab()
        elif ch == "3":
            _menu_migration()
        elif ch == "4":
            info("Применение оптимизаций sysctl/limits...")
            apply_sysctl_and_limits()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            do_xray_update_interactive()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "6":
            do_emergency_repair()
        elif ch == "7":
            ans = input(f"{RED}Удалить установку? [y/N]:{NC} ").strip().lower()
            if ans == 'y':
                do_uninstall()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "8":
            run_unit_tests()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "9":
            try:
                _load_state_into_globals()
                do_hybrid_addon_menu(default_port=SERVER_PORT)
            except ImportError as _e:
                warn(f"Модуль Mieru Hybrid Addon не найден: {_e}")
                time.sleep(2)
        elif ch.lower() == "q" or ch == "":
            break
        else:
            warn("Неверный выбор.")
            time.sleep(1)


def _menu_migration() -> None:
    """Подменю миграции (экспорт/импорт)."""
    while True:
        os.system("clear")
        print()
        _box_top("📦  МИГРАЦИЯ КОНФИГУРАЦИИ")
        _box_row()
        _box_item("1", f"📤 Экспорт  {DIM}(зашифрованный архив){NC}")
        _box_item("2", f"📥 Импорт  {DIM}(восстановить из .tar.gz или .tar.gz.enc){NC}")
        _box_item("3", f"📄 Стандартный экспорт  {DIM}(без шифрования){NC}")
        _box_row()
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break
        if ch == "1":
            do_full_migration_export()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            do_full_migration_import()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            do_export_config()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch.lower() == "q" or ch == "":
            break
        else:
            warn("Неверный выбор.")
            time.sleep(1)


# =============================================================================
#  ПОДМЕНЮ: 2 — УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ
# =============================================================================
def _menu_users() -> None:
    while True:
        os.system("clear")
        print()
        # Считаем TTL-пользователей для бейджа в заголовке меню
        _ttl_data   = _ttl_load()
        _ttl_expiring = sum(
            1 for r in _ttl_data.values()
            if _ttl_expires_within_hours(r.get("expires_at", ""), 24)
            and not _ttl_is_expired(r.get("expires_at", ""))
        )
        _ttl_badge = (
            f"  {YELLOW}⚠ {_ttl_expiring} истекают < 24ч{NC}" if _ttl_expiring else ""
        )

        _box_top("👥  УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ")
        _box_row()
        _box_item("1", f"👤 Менеджер пользователей  {DIM}(Добавление / Удаление){NC}")
        _box_item("2", "🔗 Показать ссылки + QR-коды")
        _box_item("3", f"📲 Разовая ссылка + QR  {DIM}(для передачи конфига){NC}")
        _box_item("4", "📊 Лимиты трафика на пользователя")
        _box_item("5", "📋 Генерация Clash Meta / Sing-box конфига")
        _box_item(
            "6",
            f"⏱  Временные пользователи (TTL)"
            f"  {DIM}({len(_ttl_data)} записей){NC}{_ttl_badge}"
        )
        _box_item("E", f"📤 Экспорт конфига клиента  {DIM}(файл / SFTP / QR){NC}")
        _box_item("F", f"🔀 Ссылка + конфиг с фрагментацией  {DIM}(обход DPI){NC}")
        _box_item("G", f"📲 Поделиться конфигом  {DIM}(QR → скачать без scp){NC}")
        _box_item("H", f"🔁 Единая подписка  {DIM}(все транспорты в одном URL){NC}")
        _box_item("M", f"🪞 Entry Mirrors  {DIM}(резервные точки входа){NC}")
        _box_row()
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break
        if ch == "1":
            do_unified_user_manager()
        elif ch == "2":
            _load_state_into_globals()
            if not PARAM_DOMAIN:
                warn("Параметры не найдены. Сначала установите (раздел 1).")
                time.sleep(2)
                continue
            if INSTALL_MODE == "B":
                generate_chain_summary()
                # При AWG entry-нода существует — показываем ссылки для клиентов
                if AWG_EXIT_ENABLED:
                    print()
                    generate_client_links()
            else:
                generate_client_links()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            do_share_config_server()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            do_manage_traffic_limits()
        elif ch == "5":
            do_generate_client_config()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "6":
            do_manage_ttl_users()
        elif ch.lower() == "e":
            do_export_client_config()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch.lower() == "f":
            do_fragment_link_menu()
        elif ch.lower() == "g":
            do_fragment_share_menu()
        elif ch.lower() == "h":
            try:
                from vless_installer.modules.subscription import do_subscription_menu
                do_subscription_menu()
            except ImportError as _e:
                warn(f"Модуль Единой подписки не найден: {_e}")
                time.sleep(2)
        elif ch.lower() == "m":
            try:
                from vless_installer.modules.entry_mirrors import do_entry_mirrors_menu
                do_entry_mirrors_menu()
            except ImportError as _e:
                warn(f"Модуль Entry Mirrors не найден: {_e}")
                time.sleep(2)
        elif ch.lower() == "q" or ch == "":
            break
        else:
            warn("Неверный выбор.")
            time.sleep(1)


# =============================================================================
#  ПОДМЕНЮ: 3 — НАСТРОЙКИ СЕТИ
# =============================================================================

# =============================================================================
#  УПРАВЛЕНИЕ XTLS-FLOW (Vision / Splice / none)
# =============================================================================
def do_manage_xtls_flow() -> None:
    """
    Позволяет переключить XTLS-flow режим для VLESS+REALITY без переустановки.

    Режимы:
      xtls-rprx-vision  — Vision (рекомендуется): обфускация TLS inner handshake,
                          работает на всех платформах и клиентах.
      xtls-rprx-splice  — Splice (только Linux server): splice(2) syscall вместо
                          userspace-копирования, ~10-30% выше пропускная способность
                          на VPS с высоким трафиком. Клиент указывает тот же flow.
      (пусто)           — без flow: совместимость со старыми клиентами / отладка.
                          Трафик не обфусцирован на уровне XTLS.
    """
    global XTLS_FLOW

    print()
    _box_top("⚡  XTLS-Flow режим  (VLESS + REALITY)")
    _box_row()
    _box_row(f"  Текущий режим: {CYAN}{XTLS_FLOW or '(нет flow)'}{NC}")
    _box_row()

    # Проверяем версию Xray — Splice требует 1.8.0+
    xray_ver = ""
    try:
        rv = _run([str(XRAY_BIN), "version"], capture=True, check=False, quiet=True)
        m = re.search(r'Xray[\s/]+([0-9]+\.([0-9]+))', rv.stdout + rv.stderr)
        if m:
            xray_ver = m.group(1)
    except Exception:
        pass

    splice_ok = True
    if xray_ver:
        try:
            major, minor = int(xray_ver.split(".")[0]), int(xray_ver.split(".")[1])
            if (major, minor) < (1, 8):
                splice_ok = False
        except Exception:
            pass

    # Проверяем, что это Linux (Splice работает только на Linux)
    import platform as _platform
    is_linux = _platform.system() == "Linux"
    splice_available = splice_ok and is_linux

    _box_sep()
    _box_row(f"  {CYAN}[1]{NC}  xtls-rprx-{BOLD}vision{NC}  — Рекомендуется. Работает везде.")
    _box_row(f"       {DIM}Обфускация TLS inner handshake, совместим со всеми клиентами.{NC}")
    _box_row()

    if splice_available:
        _box_row(f"  {CYAN}[2]{NC}  xtls-rprx-{BOLD}splice{NC}  — Высокая пропускная способность (Linux).")
        _box_row(f"       {DIM}Использует splice(2): меньше копирований, +10-30% скорости.{NC}")
        _box_row(f"       {DIM}Требует Xray 1.8+ на сервере и поддержку в клиенте.{NC}")
    else:
        reason = "Xray < 1.8" if not splice_ok else "не Linux"
        _box_row(f"  {DIM}[2]  xtls-rprx-splice  — Недоступно ({reason}){NC}")

    _box_row()
    _box_row(f"  {CYAN}[3]{NC}  {DIM}(без flow){NC}    — Отключить XTLS-flow.")
    _box_row(f"       {DIM}Для совместимости со старыми клиентами. Меньше безопасности.{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {DIM}[{NC}{RED}{BOLD}Q{NC}{DIM}]{NC}  {DIM}Назад без изменений{NC}")
    _box_bottom()

    try:
        ch = input(f"{CYAN}  Выбор [1/2/3/Q]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        print()
        return

    if ch == "1":
        new_flow = "xtls-rprx-vision"
    elif ch == "2":
        if not splice_available:
            warn("Splice недоступен на этой системе.")
            time.sleep(2)
            return
        new_flow = "xtls-rprx-splice"
    elif ch == "3":
        new_flow = ""
    else:
        return

    if new_flow == XTLS_FLOW:
        info("Режим не изменился.")
        time.sleep(1)
        return

    old_flow = XTLS_FLOW
    XTLS_FLOW = new_flow

    # ── Патчим конфиг напрямую (без пересоздания) ───────────────────────────
    patched = False
    for cfg_path in (CONFIG_DIR / "config.json",
                     Path("/usr/local/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            real = str(cfg_path.resolve())
        except Exception:
            real = str(cfg_path)
        try:
            cfg = json.loads(cfg_path.read_text())
            changed = False
            for inb in cfg.get("inbounds", []):
                st = inb.get("streamSettings", {})
                if "realitySettings" not in st:
                    continue
                settings = inb.get("settings", {})
                for client in settings.get("clients", []):
                    if new_flow:
                        client["flow"] = new_flow
                    else:
                        client.pop("flow", None)
                    changed = True
            if changed:
                cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                _set_config_owner(cfg_path)
                patched = True
                info(f"Конфиг обновлён: {cfg_path}")
        except Exception as e:
            warn(f"Ошибка патча {cfg_path}: {e}")

    if not patched:
        warn("Конфиг Xray не найден — обновите вручную.")
        XTLS_FLOW = old_flow
        time.sleep(2)
        return

    # ── Сохраняем в state.json ───────────────────────────────────────────────
    try:
        if STATE_FILE.exists():
            state = json.loads(STATE_FILE.read_text())
            state["xtls_flow"] = new_flow
            STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    except Exception as e:
        warn(f"Не удалось обновить state.json: {e}")

    # ── Валидация и перезапуск ───────────────────────────────────────────────
    cfg_to_test = next(
        (str(p) for p in (CONFIG_DIR / "config.json",
                           Path("/usr/local/etc/xray/config.json"))
         if p.exists()), None
    )
    if cfg_to_test:
        val = _run([str(XRAY_BIN), "run", "-test", "-config", cfg_to_test],
                   capture=True, check=False, quiet=True)
        if val.returncode != 0:
            warn("Конфиг невалиден! Откатываю изменение.")
            warn((val.stdout + val.stderr)[:300])
            XTLS_FLOW = old_flow
            # Откат: восстанавливаем старый flow
            for cfg_path in (CONFIG_DIR / "config.json",
                              Path("/usr/local/etc/xray/config.json")):
                if not cfg_path.exists():
                    continue
                try:
                    cfg = json.loads(cfg_path.read_text())
                    for inb in cfg.get("inbounds", []):
                        st = inb.get("streamSettings", {})
                        if "realitySettings" not in st:
                            continue
                        for client in inb.get("settings", {}).get("clients", []):
                            if old_flow:
                                client["flow"] = old_flow
                            else:
                                client.pop("flow", None)
                    cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                    _set_config_owner(cfg_path)
                except Exception:
                    pass
            time.sleep(2)
            return

    _run(["systemctl", "restart", "xray"], check=False, quiet=True)
    time.sleep(2)
    r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
    if r.stdout.strip() == "active":
        flow_label = new_flow if new_flow else "(без flow)"
        success(f"XTLS-flow изменён: {old_flow or '(нет)'} → {flow_label}")
        _box_row()
        if new_flow == "xtls-rprx-splice":
            _box_info("Напомните клиентам обновить flow на xtls-rprx-splice в их конфигах.")
        elif new_flow == "xtls-rprx-vision":
            _box_info("Vision активен. Клиентам нужен flow=xtls-rprx-vision.")
        else:
            _box_warn("Flow отключён. Убедитесь, что клиенты также убрали flow.")
        _log_change("xtls_flow", f"{old_flow or 'none'} -> {new_flow or 'none'}")
    else:
        warn("Xray не запустился! Проверьте журнал:")
        _run(["journalctl", "-u", "xray", "-n", "20", "--no-pager"],
             check=False, quiet=True)

    input(f"\n{BLUE}  Нажмите Enter...{NC}")

def _menu_network() -> None:
    while True:
        os.system("clear")
        print()
        _box_top("🌐  НАСТРОЙКИ СЕТИ")
        _box_row()
        _box_item("1", f"🔀 Раздельное туннелирование  {DIM}(РФ подсети){NC}")
        _box_item("2", "🔍 Диагностика split tunneling")
        _box_item("3", f"🔒 DNSCrypt-proxy  {DIM}(управление и оптимизация){NC}")
        _box_item("R", f"🔍 DNSCrypt: выбор резолверов  {DIM}(замер latency → server_names){NC}")
        _box_item("4", f"☁️  Cloudflare WARP  {DIM}(управление туннелем){NC}")
        _box_item("5", f"🔄 Сменить домен / порт  {DIM}(без переустановки){NC}")
        _box_item("6", f"🌍 Стратегия исходящих  {DIM}(domainStrategy){NC}")
        _box_item("7", f"📡 Exit-ноды каскада  {DIM}(Режим B, до 10 нод){NC}")
        _box_item("8", f"🔗 Сводка каскадного прокси  {DIM}(Режим B){NC}")
        _box_item("9", "🌐 Внешняя проверка домена / порта")
        _box_item("0", "🌐 Геопроверка выходного IP")
        _box_sep()
        _box_item("D", f"🌐 Кастомные DNS правила  {DIM}(hosts / routing override){NC}")
        _box_item("M", f"📏 MTU/MSS автотюнинг  {DIM}(оптимизация для exit-нод){NC}")
        _box_item("X", f"⚡ XTLS-flow режим  {DIM}(Vision / Splice / none — только REALITY){NC}")
        _box_item("P", f"🧪 Постквантовый VLESS  {DIM}(экспериментально, отдельный порт){NC}")
        _box_sep()
        _box_item("H", f"🚀 Hysteria2 транспорт  {DIM}(Режим B, Exit-нода, Балансировщик, DPI){NC}")
        _box_row()
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break
        if ch == "1":
            do_manage_split_tunnel()
        elif ch == "2":
            _box_top("Split Tunnel Diagnostics — VLESS Installer")
            run_split_tunnel_diagnostics()
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            info("Применение оптимизированного конфига DNSCrypt-proxy...")
            apply_dnscrypt_tuning()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            do_manage_warp()
        elif ch == "5":
            do_reconfigure()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "6":
            do_change_domain_strategy()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "7":
            _load_state_into_globals()
            if AWG_EXIT_ENABLED and INSTALL_MODE == "B":
                warn("Транспорт AWG активен — управление VLESS нодами недоступно.")
                warn("Выход через туннель awg0. Используйте AWG Watchdog (Безопасность → W).")
                time.sleep(2)
            else:
                do_manage_nodes()
        elif ch == "8":
            _load_state_into_globals()
            if INSTALL_MODE != "B":
                warn("Установка выполнена в Режиме A — каскад не настроен.")
                time.sleep(2)
                continue
            if AWG_EXIT_ENABLED:
                # AWG: показываем статус туннеля вместо VLESS-сводки
                print()
                _box_top("Сводка AWG 2.0 туннеля (Режим B)")
                _box_row(f"  Транспорт:     {CYAN}AmneziaWG 2.0{NC}")
                _box_row(f"  Exit-VPS:      {CYAN}{AWG_EXIT_HOST}:{AWG_EXIT_PORT}/udp{NC}")
                _box_row(f"  Интерфейс:     {CYAN}{AWG_INTERFACE}{NC}")
                _box_row(f"  Подсеть IPv4:  {CYAN}{AWG_SUBNET}{NC}")
                _box_row(f"  Подсеть IPv6:  {CYAN}{AWG_SUBNET_V6}{NC}")
                _r_awg = _run(["ip", "link", "show", AWG_INTERFACE], capture=True, check=False)
                _awg_up = _r_awg.returncode == 0
                _box_row(f"  Туннель:       {GREEN+'активен'+NC if _awg_up else RED+'не поднят'+NC}")
                _box_row()
                _box_row(f"  {DIM}Конфиг клиента: /etc/amnezia/amneziawg/awg0.conf{NC}")
                _box_bottom()
                input(f"{BLUE}Нажмите Enter...{NC}")
            elif not CHAIN_EXIT_HOST:
                warn("Параметры Exit Node не найдены. Переустановите в Режиме B.")
                time.sleep(2)
                continue
            else:
                generate_chain_summary()
                input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "9":
            _box_top("Внешняя проверка домена")
            do_check_domain_external()
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "0":
            check_exit_geo(silent=False)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch.lower() == "r":
            do_dnscrypt_selector_menu()
        elif ch.lower() == "d":
            do_manage_dns_rules()
        elif ch.lower() == "m":
            do_mtu_tuning()
        elif ch.lower() == "x":
            _load_state_into_globals()
            if PROTOCOL_MODE != "reality":
                warn("XTLS-flow доступен только для REALITY (Режим A/B с REALITY).")
                time.sleep(2)
            else:
                do_manage_xtls_flow()
        elif ch.lower() == "p":
            _load_state_into_globals()
            if PROTOCOL_MODE != "reality":
                warn("Постквантовый VLESS доступен только для REALITY (Режим A/B с REALITY).")
                time.sleep(2)
            else:
                try:
                    from vless_installer.modules.pq_vless import do_manage_pq_vless
                    _, _, _pq_flag = get_server_country_cached()
                    do_manage_pq_vless(
                        domain=PARAM_DOMAIN, reality_dest=PARAM_REALITY_DEST,
                        private_key=PARAM_PRIVATE_KEY, public_key=PARAM_PUBLIC_KEY,
                        spiderx=PARAM_SPIDERX, xtls_flow=XTLS_FLOW,
                        server_ip=get_server_ip("4"), country_flag=_pq_flag,
                        fingerprint=PARAM_FINGERPRINT, primary_uuid=PARAM_UUID,
                    )
                except ImportError as e:
                    warn(f"Модуль pq_vless не найден: {e}")
                    time.sleep(2)
        elif ch.lower() == "h":
            do_hysteria2_menu()
        elif ch.lower() == "q" or ch == "":
            break
        else:
            warn("Неверный выбор.")
            time.sleep(1)


# =============================================================================
#  DNS LEAK TEST
# =============================================================================
def do_dns_leak_test() -> None:
    """
    DNS Leak Test — проверяет, через какие DNS-серверы уходят запросы.

    Логика теста:
      1. Генерирует уникальный токен и делает серию DNS-запросов к
         <token>.dns-leak.com и whoami.akamai.net через dig / nslookup.
      2. Параллельно запрашивает публичные API (dnsleaktest.com, ipleak.net,
         browserleaks.com/dns) — каждый возвращает IP DNS-резолверов,
         которые до них «дошли».
      3. Определяет GeoIP каждого найденного резолвера через ip-api.com (batch).
      4. Сравнивает страны резолверов с ожидаемой (страна exit-ноды или
         страна сервера если Режим A).
      5. Если найден резолвер в RU — предупреждение об утечке.
      6. Проверяет что настроенный DNS (DNSCrypt / AdGuard / 1.1.1.1) совпадает
         с реально используемым резолвером.

    Не требует клиента — всё выполняется на стороне сервера.
    """
    os.system("clear")
    print()
    _box_top("🔍  DNS LEAK TEST")
    _box_row(f"  {DIM}Проверяет, через какие DNS-серверы уходят запросы с этого сервера.{NC}")
    _box_row(f"  {DIM}Утечка DNS = запросы попадают к провайдеру / российским серверам.{NC}")
    _box_row()

    resolvers_found: list[dict] = []  # {ip, source, country, cc, isp}

    # ── Метод 1: dnsleaktest.com API ─────────────────────────────────────────
    _box_info("Метод 1/4: dnsleaktest.com API...")
    try:
        import uuid as _uuid
        token = _uuid.uuid4().hex[:12]
        # Шаг 1 — инициализация сессии (получаем id)
        r_init = _run(
            ["curl", "-s", "--max-time", "10",
             f"https://www.dnsleaktest.com/"],
            capture=True, check=False
        )
        # Прямой запрос к API endpoint
        r_api = _run(
            ["curl", "-s", "--max-time", "15",
             "-H", "Accept: application/json",
             "https://www.dnsleaktest.com/api/v1/leak-test/start"],
            capture=True, check=False
        )
        if r_api.returncode == 0 and r_api.stdout.strip().startswith("{"):
            api_data = json.loads(r_api.stdout.strip())
            test_id = api_data.get("id") or api_data.get("test_id", "")
            if test_id:
                time.sleep(3)
                r_res = _run(
                    ["curl", "-s", "--max-time", "15",
                     f"https://www.dnsleaktest.com/api/v1/leak-test/{test_id}/results"],
                    capture=True, check=False
                )
                if r_res.returncode == 0 and r_res.stdout.strip():
                    try:
                        res_data = json.loads(r_res.stdout.strip())
                        servers = res_data if isinstance(res_data, list) else res_data.get("servers", [])
                        for srv in servers:
                            ip = srv.get("ip", "")
                            if ip:
                                resolvers_found.append({
                                    "ip": ip,
                                    "source": "dnsleaktest.com",
                                    "country": srv.get("country", "?"),
                                    "cc": srv.get("country_code", "?"),
                                    "isp": srv.get("isp", "?"),
                                })
                        if resolvers_found:
                            _box_row(f"  {GREEN}✓ dnsleaktest.com: найдено {len(resolvers_found)} резолвер(ов){NC}")
                    except Exception:
                        pass
    except Exception:
        pass
    if not any(r["source"] == "dnsleaktest.com" for r in resolvers_found):
        _box_row(f"  {DIM}dnsleaktest.com API недоступен — пропускаем{NC}")

    # ── Метод 2: ipleak.net API ───────────────────────────────────────────────
    _box_info("Метод 2/4: ipleak.net...")
    try:
        r2 = _run(
            ["curl", "-s", "--max-time", "12",
             "https://ipleak.net/json/"],
            capture=True, check=False
        )
        if r2.returncode == 0 and r2.stdout.strip():
            d2 = json.loads(r2.stdout.strip())
            # ipleak.net возвращает один объект с полем dns_servers или inline IP
            dns_list = d2.get("dns_servers") or d2.get("dns") or []
            if isinstance(dns_list, list):
                for entry in dns_list:
                    ip = entry if isinstance(entry, str) else entry.get("ip", "")
                    if ip and not any(r["ip"] == ip for r in resolvers_found):
                        resolvers_found.append({
                            "ip": ip,
                            "source": "ipleak.net",
                            "country": "?",
                            "cc": "?",
                            "isp": "?",
                        })
            # Иногда возвращает только один IP — тоже берём
            elif d2.get("ip"):
                ip = d2["ip"]
                if not any(r["ip"] == ip for r in resolvers_found):
                    resolvers_found.append({
                        "ip": ip,
                        "source": "ipleak.net (query IP)",
                        "country": d2.get("country_name", "?"),
                        "cc": d2.get("country_code", "?"),
                        "isp": d2.get("isp", d2.get("org", "?")),
                    })
            _box_row(f"  {GREEN}✓ ipleak.net: данные получены{NC}")
    except Exception:
        _box_row(f"  {DIM}ipleak.net недоступен{NC}")

    # ── Метод 3: dig / nslookup к whoami-резолверам ───────────────────────────
    _box_info("Метод 3/4: dig whoami-запросы (локальный резолвер)...")
    _whoami_targets = [
        ("whoami.akamai.net",  "akamai"),
        ("whoami.ipv4.akamai.net", "akamai-v4"),
        ("o-o.myaddr.l.google.com", "google-myaddr"),
    ]

    dig_ips: set[str] = set()
    for fqdn, label in _whoami_targets:
        # dig TXT возвращает IP клиента (= наш резолвер)
        for rec_type in ("TXT", "A"):
            r_dig = _run(
                ["dig", "+short", rec_type, fqdn],
                capture=True, check=False
            )
            if r_dig.returncode == 0 and r_dig.stdout.strip():
                for raw in r_dig.stdout.strip().splitlines():
                    # TXT-запись приходит в кавычках: "1.2.3.4"
                    candidate = raw.strip().strip('"')
                    ip_m = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', candidate)
                    if ip_m:
                        dig_ips.add(ip_m.group(1))
            if dig_ips:
                break  # нашли через TXT — не нужен A

    for ip in dig_ips:
        if not any(r["ip"] == ip for r in resolvers_found):
            resolvers_found.append({
                "ip": ip,
                "source": "dig/whoami",
                "country": "?",
                "cc": "?",
                "isp": "?",
            })
    if dig_ips:
        _box_row(f"  {GREEN}✓ dig: найден(ы) резолвер(ы): {', '.join(dig_ips)}{NC}")
    else:
        # Fallback: nslookup
        r_ns = _run(["nslookup", "whoami.akamai.net"], capture=True, check=False)
        if r_ns.returncode == 0:
            for line in r_ns.stdout.splitlines():
                ip_m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_m and "Server" not in line and "Address" in line:
                    ip = ip_m.group(1)
                    if not any(r["ip"] == ip for r in resolvers_found):
                        resolvers_found.append({
                            "ip": ip,
                            "source": "nslookup/whoami",
                            "country": "?",
                            "cc": "?",
                            "isp": "?",
                        })
        _box_row(f"  {DIM}dig не дал результата — использован nslookup{NC}")

    # ── Метод 4: /etc/resolv.conf — что сервер считает своим DNS ─────────────
    _box_info("Метод 4/4: /etc/resolv.conf + systemd-resolved...")
    configured_resolvers: list[str] = []
    try:
        resolv = Path("/etc/resolv.conf").read_text(errors="replace")
        for line in resolv.splitlines():
            if line.strip().startswith("nameserver"):
                ns_ip = line.split()[-1].strip()
                configured_resolvers.append(ns_ip)
    except Exception:
        pass
    # systemd-resolved
    r_sd = _run(["resolvectl", "status"], capture=True, check=False)
    if r_sd.returncode == 0:
        for line in r_sd.stdout.splitlines():
            if "DNS Servers" in line or "Current DNS Server" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    for tok in parts[1].split():
                        ip_m = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', tok.strip())
                        if ip_m and ip_m.group(1) not in configured_resolvers:
                            configured_resolvers.append(ip_m.group(1))

    if configured_resolvers:
        _box_row(f"  {DIM}Настроен DNS: {', '.join(configured_resolvers)}{NC}")
    else:
        _box_row(f"  {DIM}Не удалось определить настроенный DNS{NC}")

    # ── GeoIP для резолверов без страны ──────────────────────────────────────
    needs_geo = [r for r in resolvers_found if r["cc"] == "?"]
    if needs_geo:
        _box_info(f"Определяем GeoIP для {len(needs_geo)} резолвер(ов)...")
        # ip-api.com batch: до 100 IP за раз
        batch_ips = [r["ip"] for r in needs_geo[:50]]
        try:
            batch_payload = json.dumps([
                {"query": ip, "fields": "status,query,country,countryCode,isp"}
                for ip in batch_ips
            ])
            r_geo = _run(
                ["curl", "-s", "--max-time", "15",
                 "-X", "POST",
                 "-H", "Content-Type: application/json",
                 "-d", batch_payload,
                 "http://ip-api.com/batch"],
                capture=True, check=False
            )
            if r_geo.returncode == 0 and r_geo.stdout.strip().startswith("["):
                geo_list = json.loads(r_geo.stdout.strip())
                geo_map = {g["query"]: g for g in geo_list if g.get("status") == "success"}
                for r in resolvers_found:
                    if r["ip"] in geo_map:
                        g = geo_map[r["ip"]]
                        r["country"] = g.get("country", "?")
                        r["cc"]      = g.get("countryCode", "?")
                        r["isp"]     = g.get("isp", "?")
        except Exception:
            pass

    # ── Вывод результатов ────────────────────────────────────────────────────
    # Закрываем верхний бокс (INFO-лог) перед таблицей
    _box_bottom()
    print()

    if not resolvers_found:
        _box_top("Найденные DNS-резолверы")
        _box_warn("Не удалось определить DNS-резолверы — проверьте доступность сети")
        _box_bottom()
        print()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    leak_detected    = False
    ru_resolvers     = []
    foreign_resolvers = []

    # ── Вычисляем ширины колонок динамически под _BOX_W ──────────────────────
    # Структура строки: "  " + IP + " " + Страна + " " + ISP + " " + Источник
    # Левый отступ = 2, разделители между колонками = 1 каждый (3 штуки)
    # Итого служебных: 2 + 3 = 5
    _TBL_INDENT = 2
    _TBL_SEPS   = 3
    _avail = _BOX_W - _TBL_INDENT - _TBL_SEPS   # доступно для данных

    # Фиксированные ширины: IP=15, Источник=14 (max "nslookup/whoami")
    _W_IP  = 15
    _W_SRC = 14
    # Остаток делим: 40% Страна, 60% ISP
    _rem = _avail - _W_IP - _W_SRC
    _W_CC  = max(10, _rem * 38 // 100)
    _W_ISP = _avail - _W_IP - _W_SRC - _W_CC

    def _tbl_row(ip_s: str, cc_s: str, isp_s: str, src_s: str,
                 ip_col: str = "", cc_col: str = "", isp_col: str = "",
                 src_col: str = "") -> None:
        """Печатает строку таблицы внутри рамки через _box_row — правая граница ║ выровнена точно."""
        def _pad(raw: str, col: str, width: int) -> str:
            visible = _wcslen(raw)
            pad = max(0, width - visible)
            return f"{col}{raw}{NC}{' ' * pad}" if col else f"{raw}{' ' * pad}"

        line = (
            " " * _TBL_INDENT
            + _pad(ip_s,  ip_col,  _W_IP)
            + " "
            + _pad(cc_s,  cc_col,  _W_CC)
            + " "
            + _pad(isp_s, isp_col, _W_ISP)
            + " "
            + _pad(src_s, src_col, _W_SRC)
        )
        _box_row(line)

    # ── Заголовок таблицы — в боксе (IP / Страна / ISP / Источник) ──────────
    _box_top("Найденные DNS-резолверы")
    _box_row(f"  {BOLD}{'IP':<{_W_IP}} {'Страна':<{_W_CC}} {'ISP':<{_W_ISP}} {'Источник':<{_W_SRC}}{NC}")
    _sep_line = "  " + "─" * _W_IP + " " + "─" * _W_CC + " " + "─" * _W_ISP + " " + "─" * _W_SRC
    _box_row(_sep_line)
    _box_bottom()
    print()

    # ── Строки резолверов — вне рамки (plain print), флаги не ломают границы ─
    for r in resolvers_found:
        ip      = r["ip"]
        cc      = r["cc"]
        country = r["country"]
        isp     = r["isp"]
        source  = r["source"]

        flag = country_flag_emoji(cc) if cc not in ("?", "") else ""
        # Обрезаем country чтобы уместить флаг(2) + " "(1) + country + " (CC)"(5) в _W_CC
        _cc_label    = f" ({cc})"                      # " (FI)" = 5 символов
        _flag_prefix = f"{flag} " if flag else "   "   # флаг+пробел = 3 или 3 пробела
        _cty_max     = _W_CC - len(_flag_prefix) - len(_cc_label)
        country_trunc = country[:max(0, _cty_max)] if country != "?" else "?"
        _cc_field    = f"{_flag_prefix}{country_trunc}{_cc_label}"
        # Паддинг поля Страна до _W_CC (флаг = 2 кол, Python len = 2 для пары RI)
        _cc_pad      = max(0, _W_CC - len(_flag_prefix) - len(country_trunc) - len(_cc_label))

        isp_trunc = isp[:_W_ISP] if isp != "?" else "?"
        src_trunc = source[:_W_SRC]

        if cc == "RU":
            leak_detected = True
            ru_resolvers.append(r)
            row_col = RED
        elif cc in ("?", ""):
            row_col = YELLOW
        else:
            foreign_resolvers.append(r)
            row_col = GREEN

        # Строка с теми же отступами что и заголовок: 2 + _W_IP + 1 + _W_CC + 1 + _W_ISP + 1 + _W_SRC
        print(
            f"  "
            f"{row_col}{ip:<{_W_IP}}{NC} "
            f"{_cc_field}{' ' * _cc_pad} "
            f"{DIM}{isp_trunc:<{_W_ISP}}{NC} "
            f"{DIM}{src_trunc}{NC}"
        )

    print()

    # ── Итог — отдельный бокс ────────────────────────────────────────────────
    _box_top("Итог")

    if leak_detected:
        _box_row(f"  {RED}⚠  DNS LEAK ОБНАРУЖЕНА!{NC}")
        _box_row(f"  {RED}   Резолвер(ы) в России: "
                 f"{', '.join(r['ip'] for r in ru_resolvers)}{NC}")
        _box_row(f"  {YELLOW}   DNS-запросы видит российский провайдер — это утечка!{NC}")
        _box_row()
        _box_row(f"  {BOLD}Рекомендации:{NC}")
        # Определяем что настроено
        dnscrypt_active = _run(
            ["systemctl", "is-active", "dnscrypt-proxy"],
            capture=True, check=False
        ).stdout.strip() == "active"
        if not dnscrypt_active:
            _box_row(f"  {CYAN}  1. Включите DNSCrypt-proxy: меню Сеть → DNSCrypt{NC}")
        else:
            _box_row(f"  {CYAN}  1. DNSCrypt активен — проверьте listen-address в конфиге{NC}")
        _box_row(f"  {CYAN}  2. Убедитесь что Xray routing не отправляет DNS напрямую{NC}")
        _box_row(f"  {CYAN}  3. Проверьте /etc/resolv.conf — должен указывать на 127.0.0.1{NC}")
        log_to_file("WARN", f"DNS leak test: LEAK detected, RU resolvers: "
                    f"{[r['ip'] for r in ru_resolvers]}")
    elif not foreign_resolvers and resolvers_found:
        _box_row(f"  {YELLOW}~ Страна резолвер(ов) не определена — возможна утечка{NC}")
        _box_row(f"  {DIM}  Проверьте вручную: dig +short TXT whoami.akamai.net{NC}")
        log_to_file("INFO", "DNS leak test: resolvers found but geo unknown")
    else:
        _box_row(f"  {GREEN}✓ DNS-утечки не обнаружено{NC}")
        _box_row(f"  {GREEN}  Резолверы находятся за пределами России{NC}")
        log_to_file("INFO", f"DNS leak test: OK — resolvers: "
                    f"{[r['ip'] for r in resolvers_found]}")

    _box_row()
    _box_bottom()

    # ── Сверка с настроенным DNS — отдельный бокс ───────────────────────────
    if configured_resolvers:
        print()
        _box_top("Сверка конфигурации")
        is_loopback = any(ip.startswith("127.") or ip == "::1"
                          for ip in configured_resolvers)
        if is_loopback:
            ns_str = ", ".join(configured_resolvers)
            line1 = f"  {GREEN}✓ /etc/resolv.conf → localhost — DNS проксируется локально{NC}"
            line2 = f"    {DIM}({ns_str}){NC}"
            _box_row(line1)
            _box_row(line2)
        else:
            _box_row(f"  {YELLOW}⚠ /etc/resolv.conf → внешний DNS "
                     f"({', '.join(configured_resolvers)}){NC}")
            _box_row(f"  {YELLOW}  DNS-запросы уходят напрямую, минуя Xray tunnel{NC}")
        # DNSCrypt
        dnscrypt_active = _run(
            ["systemctl", "is-active", "dnscrypt-proxy"],
            capture=True, check=False
        ).stdout.strip() == "active"
        dc_str = f"{GREEN}активен{NC}" if dnscrypt_active else f"{DIM}не запущен{NC}"
        _box_row(f"  DNSCrypt-proxy: {dc_str}")
        _box_row()
        _box_bottom()

    print()
    input(f"{BLUE}Нажмите Enter...{NC}")


# =============================================================================
#  ПОДМЕНЮ: 4 — ДИАГНОСТИКА И МОНИТОРИНГ
# =============================================================================
def _menu_diagnostics() -> None:
    while True:
        os.system("clear")
        _load_state_into_globals()
        _awg = AWG_EXIT_ENABLED and INSTALL_MODE == "B"
        _speed_note = f"  {DIM}(AWG: тест через awg0){NC}" if _awg else ""
        _matrix_note = f"  {DIM}(AWG: статус туннеля){NC}" if _awg else ""
        print()
        _box_top("📊  ДИАГНОСТИКА И МОНИТОРИНГ")
        _box_row()
        _box_item("1", f"📊 Live Traffic Dashboard  {DIM}(реальное время){NC}")
        _box_item("2", f"📈 История трафика по дням  {DIM}(ASCII-гистограмма){NC}")
        _box_item("3", f"📡 Тест качества соединения  {DIM}(TTFB){NC}")
        _box_item("4", f"⚡ Тест скорости через exit-ноду{_speed_note}")
        _box_item("5", f"🔍 Аудит подключений  {DIM}(кто / когда / откуда){NC}")
        _box_item("6", "📋 Лог изменений конфигурации")
        _box_item("7", f"🩺 Ежедневный Health-отчёт  {DIM}(cron 08:00){NC}")
        _box_item("8", "🩺 Полная диагностика одной кнопкой")
        _box_item("9", f"💻 Системный дашборд  {DIM}(CPU / RAM / Disk){NC}")
        _box_item("NB", f"🚀 Бенчмарк сервера  {DIM}(CPU/RAM/Disk + iperf3 RU/EU/NA/APAC){NC}")
        _box_sep()
        _box_item("M", f"🗺️   Матрица exit-нод / туннель{_matrix_note}")
        _box_item("B", f"🔌 Проверка порта снаружи  {DIM}(заблокирован ли провайдером){NC}")
        _box_sep()
        _box_item("S", "🧪 Проверить статус и сеть")
        _box_item("L", "📋 Просмотр логов")
        _box_item("P", f"🔧 Патч Stats API  {DIM}(починить статистику трафика){NC}")
        _box_item("N", f"🔍 DNS Leak Test  {DIM}(проверить утечку DNS-запросов){NC}")
        _box_item("T", f"🔒 Проверка TLS-сертификата  {DIM}(цепочка, срок, SAN){NC}")
        _box_sep()
        _box_item("F1", f"🔀 Генератор конфига с фрагментацией  {DIM}(один пресет){NC}")
        _box_item("F2", f"🔬 Тест связности с VPS  {DIM}(Fuzzer — ориентировочно){NC}")
        _box_item("F3", f"📊 Визуализация фрагментации в логах")
        _box_item("F4", f"📦 Сгенерировать ВСЕ конфиги с фрагментацией  {DIM}(рекомендуется){NC}")
        _box_item("F5", f"📖 Гайд: как тестировать фрагментацию на своём устройстве")
        _box_item("F6", f"🔊 Фрагментация + Noise  {DIM}(шум перед ClientHello){NC}")
        _box_item("F7", f"🔀 Фрагментация + Mux  {DIM}(мультиплексирование потоков){NC}")
        _box_item("F8", f"🔄 Watchdog  {DIM}(автопереключение пресетов при RST){NC}")
        _box_item("F9", f"📈 Статистика эффективности фрагментации")
        _box_row()
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break
        if ch == "1":
            do_live_traffic_dashboard()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            do_traffic_history()
        elif ch == "3":
            do_connection_quality_test()
        elif ch == "4":
            do_speed_test()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            do_connection_audit()
        elif ch == "6":
            do_view_changes_log()
        elif ch == "7":
            do_manage_health_report()
        elif ch == "8":
            do_full_diagnostic()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "9":
            do_system_dashboard()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch.lower() == "nb":
            do_network_bench_menu()
        elif ch.lower() == "s":
            print()
            print(f"{BOLD}Статус сервисов:{NC}")
            svcs = ["xray", "nginx"]
            r = _run(["systemctl", "is-enabled", "dnscrypt-proxy"],
                     capture=True, check=False)
            if r.returncode == 0:
                svcs = ["dnscrypt-proxy", "xray", "nginx"]
            for svc in svcs:
                rs = _run(["systemctl", "is-active", svc], capture=True, check=False)
                if rs.stdout.strip() == "active":
                    success(f"{svc}: ● активен")
                else:
                    warn(f"{svc}: ○ неактивен")
            r2 = _run(["systemctl", "is-active", "dnscrypt-proxy"],
                      capture=True, check=False)
            if r2.stdout.strip() == "active":
                r3 = _run([str(DNSCRYPT_BIN), "--version"], capture=True, check=False)
                dc_ver = r3.stdout.splitlines()[0] if r3.stdout else ""
                info(f"DNSCrypt слушает на {DNSCRYPT_LISTEN_ADDR}:{DNSCRYPT_LISTEN_PORT} | {dc_ver}")
            _box_top("Проверка сетевой доступности")
            verify_connectivity()
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch.lower() == "l":
            do_view_logs()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch.lower() == "p":
            do_patch_stats_api()
        elif ch.lower() == "n":
            do_dns_leak_test()
        elif ch.lower() == "t":
            do_check_tls_cert()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch.lower() == "m":
            do_node_health_matrix()
        elif ch.lower() == "b":
            do_port_block_detect()
        elif ch.lower() in ("f1",):
            do_fragment_config_menu()
        elif ch.lower() in ("f2",):
            do_fragment_fuzzer_menu()
        elif ch.lower() in ("f3",):
            do_fragment_log_viewer_menu()
        elif ch.lower() in ("f4",):
            do_fragment_presets_menu()
        elif ch.lower() in ("f5",):
            do_fragment_guide_menu()
        elif ch.lower() in ("f6",):
            do_fragment_noise_menu()
        elif ch.lower() in ("f7",):
            do_fragment_mux_menu()
        elif ch.lower() in ("f8",):
            do_fragment_watchdog_menu()
        elif ch.lower() in ("f9",):
            do_fragment_stats_menu()
        elif ch.lower() == "q" or ch == "":
            break
        else:
            warn("Неверный выбор.")
            time.sleep(1)


# =============================================================================
#  ПОДМЕНЮ: 5 — БЕЗОПАСНОСТЬ И АВТОМАТИЗАЦИЯ
# logrotate — перенесено в vless_installer/modules/logrotate.py
def do_scheduler_menu() -> None:
    """
    Единый планировщик задач — все cron/systemd задачи в одном месте.
    Показывает статус каждой задачи и позволяет включить/выключить одним нажатием.
    """

    # ── Описание всех задач ────────────────────────────────────────────────────
    # Формат: (ключ, метка, расписание_описание, cron_path или None, systemd_unit или None,
    #           fn_install, fn_remove)

    def _cron_exists(p: str) -> bool:
        return Path(p).exists()

    def _systemd_active(unit: str) -> bool:
        r = _run(["systemctl", "is-active", unit], capture=True, check=False)
        return r.stdout.strip() == "active"

    def _systemd_enabled(unit: str) -> bool:
        r = _run(["systemctl", "is-enabled", unit], capture=True, check=False)
        return r.stdout.strip() == "enabled"

    def _task_status(cron: str | None, unit: str | None) -> bool:
        if cron:
            return _cron_exists(cron)
        if unit:
            return _systemd_enabled(unit)
        return False

    def _next_run(cron_file: str | None, unit: str | None) -> str:
        """Возвращает строку с временем следующего запуска."""
        if unit:
            r = _run(["systemctl", "list-timers", unit, "--no-legend"],
                     capture=True, check=False)
            if r.stdout.strip():
                parts = r.stdout.strip().split()
                # "NEXT" колонка — первые два слова (дата + время)
                if len(parts) >= 2:
                    return f"{parts[0]} {parts[1]}"
        if cron_file and Path(cron_file).exists():
            try:
                line = [l for l in Path(cron_file).read_text().splitlines()
                        if l and not l.startswith("#")]
                if line:
                    return line[0].split()[:5].__str__().strip("[]").replace("'", "")
            except Exception:
                pass
        return "—"

    # Определяем задачи
    TASKS = [
        {
            "id":       "geo",
            "emoji":    "🗺️",
            "label":    "Обновление GeoIP / GeoSite",
            "schedule": "Вс 03:00",
            "cron":     "/etc/cron.d/xray-geo-update",
            "unit":     None,
            "log":      "/var/log/xray-geo-update.log",
            "fn_on":    lambda: _run(["/usr/local/bin/xray-geo-update.sh"],
                                     check=False, quiet=True) if Path("/usr/local/bin/xray-geo-update.sh").exists()
                                else do_manage_geo_update(),
            "fn_toggle": None,  # управляется через do_manage_geo_update
            "configure": do_manage_geo_update,
        },
        {
            "id":       "watchdog",
            "emoji":    "🐕",
            "label":    "Watchdog (авторестарт Xray)",
            "schedule": "каждые 2 мин",
            "cron":     None,
            "unit":     "xray-watchdog.timer",
            "log":      "/var/log/xray-watchdog.log",
            "configure": do_manage_watchdog,
        },
        {
            "id":       "health",
            "emoji":    "❤️",
            "label":    "Ежедневный Health-отчёт",
            "schedule": "08:00 ежедневно",
            "cron":     "/etc/cron.d/xray-health-report",
            "unit":     None,
            "log":      "/var/log/xray-health-report.log",
            "configure": do_manage_health_report,
        },
        {
            "id":       "tg",
            "emoji":    "📬",
            "label":    "Telegram мониторинг",
            "schedule": "каждые 5 мин",
            "cron":     "/etc/cron.d/xray-tg-monitor",
            "unit":     None,
            "log":      None,
            "configure": do_manage_telegram,
        },
        {
            "id":       "certbot",
            "emoji":    "🔒",
            "label":    "Мониторинг SSL-сертификата",
            "schedule": "03:00 и 15:00",
            "cron":     "/etc/cron.d/xray-certbot-monitor",
            "unit":     None,
            "log":      "/var/log/xray-certbot-monitor.log",
            "configure": do_manage_certbot_monitor,
        },
        {
            "id":       "autoban",
            "emoji":    "🚫",
            "label":    "AutoBan (защита от брутфорса)",
            "schedule": "каждые 5 мин",
            "cron":     "/etc/cron.d/xray-autoban",
            "unit":     None,
            "log":      "/var/log/xray-autoban.log",
            "configure": do_manage_autoban,
        },
        {
            "id":       "fp",
            "emoji":    "🔑",
            "label":    "Ротация Fingerprint",
            "schedule": "настраивается",
            "cron":     f"/etc/cron.d/{_FP_CRON_TAG}",
            "unit":     None,
            "log":      None,
            "configure": do_manage_fingerprint,
        },
        {
            "id":       "uuid",
            "emoji":    "🔄",
            "label":    "Ротация UUID",
            "schedule": "настраивается",
            "cron":     f"/etc/cron.d/{_UUID_CRON_TAG}",
            "unit":     None,
            "log":      None,
            "configure": do_manage_uuid_rotation,
        },
        {
            "id":       "limits",
            "emoji":    "📊",
            "label":    "Лимиты трафика",
            "schedule": "каждые 5 мин",
            "cron":     "/etc/cron.d/xray-traffic-limits",
            "unit":     None,
            "log":      None,
            "configure": do_manage_traffic_limits,
        },
        {
            "id":       "ttl",
            "emoji":    "⏱️",
            "label":    "TTL пользователей (авто-откл.)",
            "schedule": "ежедневно",
            "cron":     str(TTL_CRON_FILE),
            "unit":     None,
            "log":      None,
            "configure": do_manage_ttl_users,
        },
        {
            "id":       "snapshot",
            "emoji":    "📈",
            "label":    "Снимки трафика (история)",
            "schedule": "каждый час",
            "cron":     "/etc/cron.d/xray-traffic-snapshot",
            "unit":     None,
            "log":      None,
            "configure": do_traffic_history,
        },
        {
            "id":       "fallback",
            "emoji":    "🔀",
            "label":    "Авто-фолбэк (Режим B → A)",
            "schedule": "каждую минуту",
            "cron":     str(_AUTO_FALLBACK_CRON),
            "unit":     None,
            "log":      None,
            "configure": do_manage_auto_fallback,
        },
        {
            "id":       "ingress",
            "emoji":    "🛡️",
            "label":    "Ingress GeoIP блокировка",
            "schedule": "настраивается",
            "cron":     str(INGRESS_CRON_FILE),
            "unit":     None,
            "log":      None,
            "configure": do_manage_ingress_geoip,
        },
        {
            "id":       "autoupdate",
            "emoji":    "⬆️",
            "label":    "Авто-обновление Xray",
            "schedule": "ежедневно 03:30",
            "cron":     None,
            "unit":     "xray-autoupdate.timer",
            "log":      None,
            "configure": None,  # управляется в меню установки
        },
        {
            "id":       "rusubnets",
            "emoji":    "RU",
            "label":    "Обновление РУ-подсетей",
            "schedule": "настраивается",
            "cron":     None,
            "unit":     "xray-ru-subnets.timer",
            "log":      None,
            "configure": do_manage_ru_subnet_direct,
        },
        {
            "id":       "asdirect",
            "emoji":    "AS",
            "label":    "AS-провайдер → direct",
            "schedule": "настраивается",
            "cron":     None,
            "unit":     "xray-as-direct.timer",
            "log":      None,
            "configure": do_manage_as_direct,
        },
        {
            "id":       "logrotate",
            "emoji":    "📋",
            "label":    "Ротация логов Xray (logrotate)",
            "schedule": "ежедневно (системный cron)",
            "cron":     "/etc/logrotate.d/xray",
            "unit":     None,
            "log":      "/var/log/xray/access.log",
            "configure": do_manage_logrotate,
        },
        {
            "id":       "backup",
            "emoji":    "📦",
            "label":    "Автобэкап конфигурации",
            "schedule": "настраивается",
            "cron":     str(_SCHEDULED_BACKUP_CRON),
            "unit":     None,
            "log":      "/var/log/xray-scheduled-backup.log",
            "configure": do_manage_scheduled_backup,
        },
    ]

    render_scheduler_menu(TASKS)

def _menu_security() -> None:
    while True:
        os.system("clear")
        _load_state_into_globals()
        _awg = AWG_EXIT_ENABLED and INSTALL_MODE == "B"
        _awg_na = f"  {DIM}(AWG: недоступно — нет VLESS-нод){NC}" if _awg else f"  {DIM}(Режим B){NC}"
        _awg_na7 = f"  {DIM}(AWG: недоступно){NC}" if _awg else f"  {DIM}(при отказе всех нод){NC}"
        _bal_na  = f"  {DIM}(AWG: недоступно){NC}" if _awg else f"  {DIM}(latency + bandwidth + load){NC}"
        _box_top("🛡️  БЕЗОПАСНОСТЬ И АВТОМАТИЗАЦИЯ")
        _box_item("1", f"🚫 AutoBan  {DIM}(защита от перебора / TLS-ошибки){NC}")
        _box_item("2", f"🛡️  GeoIP Block  {DIM}(allowlist / blocklist / сканеры){NC}")
        _box_item("3", "🗺️  Управление GeoIP / GeoSite файлами")
        _box_item("4", "🔑 Ротация UUID и Fingerprint")
        _box_item("5", f"📬 Telegram-уведомления  {DIM}(бот + мониторинг){NC}")
        _box_item("TB", f"🤖 Telegram Config Bot  {DIM}(раздача конфигов пользователям){NC}")
        _box_item("PH", f"⚡ Port Hopping  {DIM}(диапазон портов против блокировки){NC}")
        _box_sep()
        _box_item("6", f"📡 Failover статус exit-нод{_awg_na}")
        _box_item("7", f"🔀 Авто-фолбэк в Режим A{_awg_na7}")
        _box_item("8",  "🐕 Watchdog авторестарт Xray")
        _box_item("NW", f"🔁 nginx Watchdog  {DIM}(перезапуск nginx при падении){NC}")
        _box_item("W",  f"🔌 AWG Tunnel Watchdog  {DIM}(fallback при падении awg0){NC}")
        _box_item("N",  f"🌐 AWG Multi-Node  {DIM}(ноды, failover, SSH-защита){NC}")
        _box_item("IP", f"📦 ipset Persist  {DIM}(восстановление ipset при reboot){NC}")
        _box_item("IB", f"🚫 IP-Бан  {DIM}(iptables/ipset: IP / подсеть / диапазон / ASN){NC}")
        _box_item("FB", f"🛡️  Fail2ban  {DIM}(банит за подбор пароля / лишние запросы){NC}")
        _box_item("CL", f"🔗 Кластер Exit Nodes  {DIM}(все Exit Nodes по SSH){NC}")
        _box_item("9", f"🔒 Мониторинг certbot renew  {DIM}(алерт при истечении){NC}")
        _box_item("H", f"🔒 SSH Hardening  {DIM}(порт / ключи / AllowUsers){NC}")
        _box_sep()
        _box_item("P", f"🍯 Honeypot-порт  {DIM}(ловушка для сканеров){NC}")
        _box_item("D", f"🔍 DPI-детектор  {DIM}(блокировка зондирования){NC}")
        _box_item("CS", f"🛰️  Проверка цензуры провайдера  {DIM}(TLS/TCP/HTTP/DNS снаружи){NC}")
        _box_item("B", f"⚡ Smart Balancer{_bal_na}")
        _box_item("S", f"🗓️  Планировщик задач  {DIM}(все cron/systemd в одном месте){NC}")
        _box_sep()
        # Показываем статус ingress-блокировки прямо в меню
        _ing = _ingress_state_load()
        _ing_on = _ing.get("enabled")
        _ing_str = (
            f"{GREEN}вкл  порт {_ing.get('port','')}  {_ing.get('cidrs_v4',0)} CIDR{NC}"
            if _ing_on else f"{DIM}выкл{NC}"
        )
        _box_item("G", f"🛡️  Блокировка входящих из РФ  {_ing_str}")
        _box_sep()
        _box_item("BK", f"💾 Бэкапы конфига Xray  {DIM}(история конфигов, откат){NC}")
        _box_item("CB", f"🔄 Cold Boot Restore  {DIM}(авто-восстановление после reboot){NC}")
        _box_item("HM", f"📡 Health Monitor нод  {DIM}(проверка exit-нод по расписанию){NC}")
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break
        if ch == "1":
            do_manage_autoban()
        elif ch == "2":
            do_manage_geoip_block()
        elif ch == "3":
            do_manage_geo_update()
        elif ch == "4":
            _menu_rotation()
        elif ch == "5":
            do_manage_telegram()
        elif ch.lower() == "tb":
            do_tg_bot_menu()
        elif ch.lower() == "ph":
            do_port_hopping_menu()
        elif ch == "6":
            do_failover_status()
        elif ch == "7":
            do_manage_auto_fallback()
        elif ch == "8":
            do_manage_watchdog()
        elif ch.lower() == "nw":
            do_manage_nginx_watchdog()
        elif ch.lower() == "w":
            do_manage_awg_watchdog()
        elif ch.lower() == "ip":
            do_manage_ipset_persist()
        elif ch.lower() == "ib":
            do_manage_ipban()
        elif ch.lower() == "fb":
            do_manage_fail2ban()
        elif ch.lower() == "cl":
            do_cluster_menu()
        elif ch.lower() == "n":
            # === PATCH v2: AWG Multi-Node Management ===
            do_manage_awg_nodes()
        elif ch == "9":
            do_manage_certbot_monitor()
        elif ch.lower() == "h":
            do_ssh_hardening()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch.lower() == "p":
            do_manage_honeypot()
        elif ch.lower() == "d":
            do_manage_dpi_detector()
        elif ch.lower() == "cs":
            do_dpi_censor_check_menu()
        elif ch.lower() == "b":
            do_manage_smart_balancer()
        elif ch.lower() == "s":
            do_scheduler_menu()
        elif ch.lower() == "g":
            do_manage_ingress_geoip()
        elif ch.lower() == "bk":
            do_backup_menu()
        elif ch.lower() == "cb":
            do_cold_boot_menu()
        elif ch.lower() == "hm":
            do_health_monitor_menu()
        elif ch.lower() == "q" or ch == "":
            break
        else:
            warn("Неверный выбор.")
            time.sleep(1)


# (_menu_rotation вынесен в vless_installer.modules.credential_rotation;
#  импорт — в верхней секции этого файла.)


# =============================================================================
#  ВСПОМОГАТЕЛЬНАЯ: загрузка state.json в глобальные переменные
# =============================================================================
def _load_state_into_globals() -> None:
    global PARAM_DOMAIN, PARAM_UUID, PARAM_PUBLIC_KEY, PARAM_PRIVATE_KEY, PARAM_SHORTID
    global IS_IPV6_AVAILABLE, IPV6_PREFLIGHT, PARAM_USE_DNSCRYPT
    global INSTALL_MODE, PROTOCOL_MODE, XHTTP_MODE, XHTTP_PATH, XHTTP_PERF_PRESET
    global AWG_EXIT_ENABLED, AWG_INSTALLED, AWG_EXIT_HOST, AWG_EXIT_PORT, PARAM_REALITY_DEST
    global H2_EXIT_ENABLED
    global XTLS_FLOW
    global PARAM_FINGERPRINT
    # === FIX 1: объявление глобалей для multi-node полей ===
    global AWG_NODES, AWG_ACTIVE_NODE_INDEX, _AWG_SSH_CLIENT_IP
    # === END FIX 1 ===
    global XHTTP_PADDING_BYTES, XHTTP_NO_SSE_HEADER, XHTTP_NO_GRPC_HEADER, XHTTP_HOST
    global XHTTP_SC_STREAM_UP_SERVER_SECS, XHTTP_SC_MAX_EACH_POST_BYTES
    global XHTTP_SC_MIN_POSTS_INTERVAL_MS, XHTTP_SC_MAX_BUFFERED_POSTS
    global XHTTP_XMUX_ENABLED, XHTTP_XMUX_MAX_CONCURRENCY, XHTTP_XMUX_MAX_CONNECTIONS
    global XHTTP_XMUX_C_MAX_REUSE_TIMES, XHTTP_XMUX_H_MAX_REQUEST_TIMES
    global XHTTP_XMUX_H_MAX_REUSABLE_SECS, XHTTP_XMUX_H_KEEP_ALIVE_PERIOD
    global XHTTP_TCP_NO_DELAY, XHTTP_ENABLE_SESSION_RESUMPTION
    global SERVER_PORT, XHTTP_PORT, CHAIN_BALANCER_STRATEGY
    global CHAIN_EXIT_HOST, CHAIN_EXIT_PORT, CHAIN_EXIT_UUID
    global CHAIN_EXIT_PUBKEY, CHAIN_EXIT_SHORTID, CHAIN_EXIT_SNI, CHAIN_EXIT_FP
    global CHAIN_NODES
    if not STATE_FILE.exists():
        return
    try:
        state = json.loads(STATE_FILE.read_text())
        PARAM_DOMAIN     = state.get("domain",      PARAM_DOMAIN)
        PARAM_UUID       = state.get("uuid",        PARAM_UUID)
        PARAM_PUBLIC_KEY = state.get("public_key",  PARAM_PUBLIC_KEY)
        PARAM_PRIVATE_KEY = state.get("private_key", PARAM_PRIVATE_KEY)
        PARAM_SHORTID    = state.get("short_id",    PARAM_SHORTID)
        PARAM_FINGERPRINT = state.get("fingerprint", PARAM_FINGERPRINT) or "chrome"
        IPV6_PREFLIGHT   = state.get("ipv6",        IPV6_PREFLIGHT)
        INSTALL_MODE     = state.get("install_mode", "A")
        if IPV6_PREFLIGHT:
            IS_IPV6_AVAILABLE = True
        PARAM_USE_DNSCRYPT = state.get("use_dnscrypt", False)
        PROTOCOL_MODE = state.get("protocol_mode", "reality")
        XTLS_FLOW     = state.get("xtls_flow",      "xtls-rprx-vision")
        XHTTP_MODE    = state.get("xhttp_mode",    "streamup")
        XHTTP_PATH    = state.get("xhttp_path",    "/")
        XHTTP_PERF_PRESET = state.get("xhttp_perf_preset", "auto")
        XHTTP_PADDING_BYTES             = state.get("xhttp_padding_bytes",            "100-1000")
        XHTTP_NO_SSE_HEADER             = state.get("xhttp_no_sse_header",            False)
        XHTTP_NO_GRPC_HEADER            = state.get("xhttp_no_grpc_header",           False)
        XHTTP_HOST                      = state.get("xhttp_host",                     "")
        XHTTP_SC_STREAM_UP_SERVER_SECS  = state.get("xhttp_sc_stream_up_server_secs", "20-80")
        XHTTP_SC_MAX_EACH_POST_BYTES    = state.get("xhttp_sc_max_each_post_bytes",   "1000000")
        XHTTP_SC_MIN_POSTS_INTERVAL_MS  = state.get("xhttp_sc_min_posts_interval_ms", "30")
        XHTTP_SC_MAX_BUFFERED_POSTS     = state.get("xhttp_sc_max_buffered_posts",    30)
        XHTTP_XMUX_ENABLED              = state.get("xhttp_xmux_enabled",             False)
        XHTTP_XMUX_MAX_CONCURRENCY      = state.get("xhttp_xmux_max_concurrency",     "16-32")
        XHTTP_XMUX_MAX_CONNECTIONS      = state.get("xhttp_xmux_max_connections",     0)
        XHTTP_XMUX_C_MAX_REUSE_TIMES    = state.get("xhttp_xmux_c_max_reuse_times",   "0")
        XHTTP_XMUX_H_MAX_REQUEST_TIMES  = state.get("xhttp_xmux_h_max_request_times", "600-900")
        XHTTP_XMUX_H_MAX_REUSABLE_SECS  = state.get("xhttp_xmux_h_max_reusable_secs", "1800-3000")
        XHTTP_XMUX_H_KEEP_ALIVE_PERIOD  = state.get("xhttp_xmux_h_keep_alive_period", 0)
        XHTTP_TCP_NO_DELAY              = state.get("xhttp_tcp_no_delay",             False)
        XHTTP_ENABLE_SESSION_RESUMPTION = state.get("xhttp_enable_session_resumption", False)
        SERVER_PORT   = state.get("server_port",   443)
        XHTTP_PORT    = SERVER_PORT
        CHAIN_EXIT_HOST    = state.get("chain_exit_host",    CHAIN_EXIT_HOST)
        CHAIN_EXIT_PORT    = state.get("chain_exit_port",    CHAIN_EXIT_PORT)
        CHAIN_EXIT_UUID    = state.get("chain_exit_uuid",    CHAIN_EXIT_UUID)
        CHAIN_EXIT_PUBKEY  = state.get("chain_exit_pubkey",  CHAIN_EXIT_PUBKEY)
        CHAIN_EXIT_SHORTID = state.get("chain_exit_shortid", CHAIN_EXIT_SHORTID)
        CHAIN_EXIT_SNI     = state.get("chain_exit_sni",     CHAIN_EXIT_SNI)
        CHAIN_EXIT_FP      = state.get("chain_exit_fp",      CHAIN_EXIT_FP)
        CHAIN_NODES = _nodes_from_state(state)
        CHAIN_BALANCER_STRATEGY = state.get("chain_balancer_strategy", "roundRobin")
        # AWG 2.0 — критически важно для корректной генерации xray config
        AWG_EXIT_ENABLED = state.get("awg_exit_enabled",  False)
        AWG_INSTALLED    = state.get("awg_installed",     AWG_EXIT_ENABLED)
        AWG_EXIT_HOST    = state.get("awg_exit_host",     AWG_EXIT_HOST)
        AWG_EXIT_PORT    = state.get("awg_exit_port",     AWG_EXIT_PORT)
        AWG_CLIENT_LISTEN_PORT = state.get("awg_client_listen_port", AWG_CLIENT_LISTEN_PORT)
        PARAM_REALITY_DEST = state.get("reality_dest",   PARAM_REALITY_DEST)
        # Hysteria2 транспорт
        H2_EXIT_ENABLED  = state.get("h2_exit_enabled",  False)
        # === FIX 1: загрузка multi-node полей ===
        AWG_NODES             = state.get("awg_nodes",             [])
        AWG_ACTIVE_NODE_INDEX = state.get("awg_active_node_index", 0)
        _AWG_SSH_CLIENT_IP    = state.get("awg_ssh_client_ip",     "")
        # === END FIX 1 ===
    except Exception:
        pass


# =============================================================================
#  ГЛАВНОЕ МЕНЮ (НОВАЯ ВЕРСИЯ — ГРУППЫ ПО 5 РАЗДЕЛАМ)
# =============================================================================
def main_menu() -> None:
    global PARAM_DOMAIN, PARAM_UUID, PARAM_PUBLIC_KEY, PARAM_SHORTID
    global IS_IPV6_AVAILABLE, IPV6_PREFLIGHT, PARAM_USE_DNSCRYPT, DNSCRYPT_INSTALLED
    global INSTALL_MODE
    global PROTOCOL_MODE, XHTTP_MODE, XHTTP_PATH, XHTTP_PERF_PRESET
    global _BOX_W
    global XHTTP_PADDING_BYTES, XHTTP_NO_SSE_HEADER
    global XHTTP_NO_GRPC_HEADER, XHTTP_HOST, XHTTP_SC_MIN_POSTS_INTERVAL_MS
    global XHTTP_XMUX_ENABLED, XHTTP_XMUX_MAX_CONCURRENCY, XHTTP_XMUX_MAX_CONNECTIONS
    global XHTTP_XMUX_C_MAX_REUSE_TIMES, XHTTP_XMUX_H_MAX_REQUEST_TIMES
    global XHTTP_XMUX_H_MAX_REUSABLE_SECS, XHTTP_XMUX_H_KEEP_ALIVE_PERIOD
    global XHTTP_TCP_NO_DELAY, XHTTP_ENABLE_SESSION_RESUMPTION
    global XHTTP_SC_STREAM_UP_SERVER_SECS, XHTTP_SC_MAX_EACH_POST_BYTES
    global XHTTP_SC_MAX_BUFFERED_POSTS
    global CHAIN_EXIT_HOST, CHAIN_EXIT_PORT, CHAIN_EXIT_UUID
    global CHAIN_EXIT_PUBKEY, CHAIN_EXIT_SHORTID, CHAIN_EXIT_SNI, CHAIN_EXIT_FP
    global CHAIN_NODES

    while True:
        try:
            _BOX_W = _get_box_width()
            os.system("clear")
            print_banner()
            print()

            # Панель "Состояние" — см. status_panel.py. Единственная точка
            # сопряжения: этот вызов. Сам модуль ни во что в _core.py не
            # лезет, только читает то, что ему нужно, через свои функции.
            try:
                from vless_installer.modules.status_panel import render as _render_status_panel
                _render_status_panel()
                print()
            except Exception:
                pass

            current_mode = "—"
            if STATE_FILE.exists():
                try:
                    _st = json.loads(STATE_FILE.read_text())
                    current_mode = _st.get("install_mode", "A")
                except Exception:
                    pass

            mode_color = GREEN if current_mode in ("A", "B") else DIM
            mode_str   = f"{mode_color}Режим {current_mode}{NC}"

            print()
            # Главное меню фиксируется по ширине баннера (64 символа)
            _BOX_W_saved = _BOX_W
            _BOX_W = 64
            _box_top()
            _box_row(f"  {BOLD}{TITLE}VLESS Ultimate Installer v4.12.10{NC}  {DIM}│{NC}  {mode_str}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}1{NC}  ⚙️  {TITLE}Установка и Система{NC}")
            _box_row(f"     {DIM}Установка, Миграция, Оптимизация, Обновление{NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}2{NC}  👥 {TITLE}Управление пользователями{NC}")
            _box_row(f"     {DIM}Пользователи, Ссылки/QR, Лимиты, Конфиги{NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}3{NC}  🌐 {TITLE}Настройки сети{NC}")
            _box_row(f"     {DIM}Split Tunnel, DNSCrypt, WARP, Домен/Порт, Ноды{NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}4{NC}  📊 {TITLE}Диагностика и Мониторинг{NC}")
            _box_row(f"     {DIM}Трафик, TTFB, Аудит, Логи, Health, Дашборд{NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}5{NC}  🛡️  {TITLE}Безопасность и Автоматизация{NC}")
            _box_row(f"     {DIM}AutoBan, GeoIP, Ротация, Telegram, Watchdog, SSH{NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}6{NC}  📡 {TITLE}Telemt MTProxy{NC}")
            _box_row(f"     {DIM}Telegram MTProto-прокси (Rust/Tokio){NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}7{NC}  🚀 {TITLE}Hysteria2 транспорт{NC}")
            _box_row(f"     {DIM}Exit-нода, Балансировщик, Health, DPI, Cert{NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}8{NC}  📲 {TITLE}VK Turn Tunnel{NC}")
            _box_row(f"     {DIM}FreeTurn (vk-turn-proxy) · WireTurn (Turnable){NC}")
            _box_row()
            _box_sep()
            _box_row(f"  {CYAN}9{NC}  🌐 {TITLE}SlipGate / SlipNet{NC}")
            _box_row(f"     {DIM}DNS-туннели (DNSTT, NoizDNS, Slipstream) — обход полных блокировок{NC}")
            _box_row()
            _box_sep()
            _box_row(f"  {CYAN}10{NC} 🔒 {TITLE}qWDTT (WireGuard/TURN){NC}")
            _box_row(f"     {DIM}WireGuard через TURN ВКонтакте — пароли, TTL, Telegram-бот{NC}")
            _box_row()
            _box_sep()
            _box_row(f"  {CYAN}11{NC} 🔐 {TITLE}NaiveProxy{NC}")
            _box_row(f"     {DIM}HTTPS/HTTP2 + Chromium fingerprint + probe resistance{NC}")
            _box_row()
            _box_sep()
            _box_row(f"  {CYAN}12{NC} 🔒 {TITLE}Mieru{NC}")
            _box_row(f"     {DIM}mTLS + random padding — маскировка без домена{NC}")
            _box_row()
            _box_sep()
            _box_row(f"  {CYAN}13{NC} 📹 {TITLE}olcRTC{NC}  {DIM}(Beta){NC}")
            _box_row(f"     {DIM}TCP-over-WebRTC — туннель под видеозвонок (Jitsi/Телемост/WB Stream){NC}")
            _box_row()
            _box_sep()
            _box_row(f"  {CYAN}14{NC} ☁️  {TITLE}WebDAV Tunnel{NC}")
            _box_row(f"     {DIM}TCP/SOCKS5 поверх WebDAV-файлов — маскировка под облако{NC}")
            _box_row()
            _box_sep()
            _box_row(f"  {CYAN}15{NC} 🐙 {TITLE}FPTN{NC}  {DIM}(Beta){NC}")
            _box_row(f"     {DIM}Свой L3 VPN (Protobuf/TLS) — honeypot-прокси вместо отказа зондам{NC}")
            _box_row()
            _box_sep()
            _box_row(f"  {DIM}[{NC}{TITLE}{BOLD}0{NC}{DIM}]{NC}  🚪 Выход")
            _box_bottom()
            _BOX_W = _BOX_W_saved
            print()
            choice = input(f"{CYAN}Выбор (1–15 / 0):{NC} ").strip()
        except KeyboardInterrupt:
            print()
            print(f"{GREEN}До свидания! 👋{NC}")
            log_to_file("INFO", "Скрипт завершён пользователем (Ctrl+C)")
            sys.exit(0)

        if not choice:
            continue

        if choice == "1":
            _menu_install_system()

        elif choice == "2":
            _load_state_into_globals()
            _menu_users()

        elif choice == "3":
            _load_state_into_globals()
            _menu_network()

        elif choice == "4":
            _menu_diagnostics()

        elif choice == "5":
            _menu_security()

        elif choice == "6":
            try:
                from vless_installer.modules.mtproto import mtproto_menu
                mtproto_menu()
            except ImportError as _e:
                warn(f"Модуль MTProxy не найден: {_e}")
                time.sleep(2)

        elif choice == "7":
            do_hysteria2_menu()

        elif choice == "8":
            try:
                do_vkturn_menu()
            except ImportError as _e:
                warn(f"Модуль VK Turn Tunnel не найден: {_e}")
                time.sleep(2)

        elif choice == "9":
            try:
                do_slipgate_menu()
            except ImportError as _e:
                warn(f"Модуль SlipGate не найден: {_e}")
                time.sleep(2)

        elif choice == "10":
            try:
                do_wdtt_menu()
            except ImportError as _e:
                warn(f"Модуль qWDTT не найден: {_e}")
                time.sleep(2)

        elif choice == "11":
            try:
                do_naiveproxy_menu()
            except ImportError as _e:
                warn(f"Модуль NaiveProxy не найден: {_e}")
                time.sleep(2)

        elif choice == "12":
            try:
                do_mieru_menu()
            except ImportError as _e:
                warn(f"Модуль Mieru не найден: {_e}")
                time.sleep(2)

        elif choice == "13":
            try:
                from vless_installer.modules.olcrtc import do_olcrtc_menu
                do_olcrtc_menu()
            except ImportError as _e:
                warn(f"Модуль olcRTC не найден: {_e}")
                time.sleep(2)

        elif choice == "14":
            try:
                do_webdav_tunnel_menu()
            except ImportError as _e:
                warn(f"Модуль WebDAV Tunnel не найден: {_e}")
                time.sleep(2)

        elif choice == "15":
            try:
                from vless_installer.modules.fptn import do_fptn_menu
                do_fptn_menu()
            except ImportError as _e:
                warn(f"Модуль FPTN не найден: {_e}")
                time.sleep(2)

        elif choice == "0":
            print(f"{GREEN}До свидания! 👋{NC}")
            log_to_file("INFO", "Скрипт завершён пользователем")
            sys.exit(0)

        else:
            warn(f"Неверный выбор: {choice}")
            time.sleep(1)


# (apply_sysctl_and_limits вынесен в vless_installer.modules.network_setup;
#  импорт — в верхней секции этого файла.)


# Удалён дублирующий пункт [2] «Управление пользователями» —
# он полностью совпадал с пунктом [U] «Менеджер пользователей».
# Теперь оба объединены в разделе 2 главного меню.

def _DELETED_old_main_menu_handlers() -> None:
    """
    Заглушка — старые обработчики главного меню перенесены в подменю:
      _menu_install_system(), _menu_users(), _menu_network(),
      _menu_diagnostics(), _menu_security()
    Эта функция никогда не вызывается.
    """
    pass


# =============================================================================
#  ПЕРЕКЛЮЧЕНИЕ РЕЖИМА A ↔ B БЕЗ ПЕРЕУСТАНОВКИ
# =============================================================================

# (switch_mode_ab — вынесен в vless_installer.modules.switch_mode;
#  импорт — в верхней секции этого файла.)



# =============================================================================
#  SMART BALANCER — composite latency + bandwidth + load
# smart_balancer — перенесено в vless_installer/modules/smart_balancer.py
def awg_watchdog_install(check_host: str = "1.1.1.1") -> None:
    """
    Создаёт Bash-скрипт мониторинга туннеля awg0 и cron-задачу (каждую минуту).

    Логика watchdog:
      - Туннель UP:   убеждается, что ip rule fwmark AWG_FWMARK table AWG_ROUTE_TABLE существует.
      - Туннель DOWN: удаляет это правило → трафик Xray идёт напрямую (Direct Mode).
      - Восстановление: добавляет правило обратно, логирует событие.

    Не затрагивает конфиг Xray, не перезапускает сервисы, не меняет install_mode.
    Не конфликтует с существующим xray-auto-fallback (нодовый фолбэк).
    """
    info("AWG Watchdog: генерация скрипта мониторинга туннеля awg0...")

    script_content = textwrap.dedent(f"""\
        #!/bin/bash
        # =============================================================================
        # AWG Tunnel Fallback Watchdog
        # Автосгенерирован VLESS Ultimate Installer (install_final.py)
        #
        # Проверяет ping через {AWG_INTERFACE} каждую минуту (из cron).
        # Туннель UP   → гарантирует наличие: ip rule fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE}
        # Туннель DOWN → удаляет это правило → Xray выходит напрямую (Direct Mode)
        # Восстановление → возвращает правило обратно.
        # =============================================================================

        AWG_IFACE="{AWG_INTERFACE}"
        AWG_FWMARK={AWG_FWMARK}
        AWG_ROUTE_TABLE={AWG_ROUTE_TABLE}
        RULE_PRIORITY=100
        CHECK_HOST="{check_host}"
        CHECK_TIMEOUT=3
        LOG="{_AWG_WATCHDOG_LOG}"
        STATE_FILE="{_AWG_WATCHDOG_STATE}"
        PING_COUNT=2

        ts()  {{ date '+%Y-%m-%d %H:%M:%S'; }}
        log() {{ echo "[$(ts)] $*" >> "$LOG"; }}

        # Проверка наличия ip rule (совместимо с разными версиями iproute2)
        rule_exists() {{
            ip rule show 2>/dev/null | grep -qE "fwmark (0x)?${{AWG_FWMARK}}(/0x[0-9a-f]+)? +lookup ${{AWG_ROUTE_TABLE}}"
        }}

        rule_add() {{
            if ! rule_exists; then
                ip rule add fwmark ${{AWG_FWMARK}} table ${{AWG_ROUTE_TABLE}} priority ${{RULE_PRIORITY}} 2>/dev/null
                log "RULE ADDED: ip rule add fwmark=${{AWG_FWMARK}} table=${{AWG_ROUTE_TABLE}} priority=${{RULE_PRIORITY}}"
            fi
        }}

        rule_del() {{
            if rule_exists; then
                ip rule del fwmark ${{AWG_FWMARK}} table ${{AWG_ROUTE_TABLE}} priority ${{RULE_PRIORITY}} 2>/dev/null || \\
                ip rule del fwmark ${{AWG_FWMARK}} table ${{AWG_ROUTE_TABLE}} 2>/dev/null
                log "RULE DELETED: ip rule del fwmark=${{AWG_FWMARK}} table=${{AWG_ROUTE_TABLE}}"
            fi
        }}

        current_state() {{
            [ -f "$STATE_FILE" ] && cat "$STATE_FILE" || echo "unknown"
        }}

        set_state() {{ echo "$1" > "$STATE_FILE"; }}

        # Проверка: интерфейс существует + ping проходит строго через него
        tunnel_ok() {{
            ip link show "${{AWG_IFACE}}" &>/dev/null || return 1
            ping -I "${{AWG_IFACE}}" -c ${{PING_COUNT}} -W ${{CHECK_TIMEOUT}} -q "${{CHECK_HOST}}" &>/dev/null
        }}

        # ── Основная логика ──────────────────────────────────────────────────

        PREV_STATE=$(current_state)

        if tunnel_ok; then
            # Туннель работает
            if [ "$PREV_STATE" != "up" ]; then
                log "TUNNEL UP — восстановление (предыдущее состояние: ${{PREV_STATE}})"
                rule_add
                set_state "up"
                log "DIRECT MODE OFF — трафик Xray снова маршрутизируется через ${{AWG_IFACE}}"
            else
                # Уже был up — idempotent-проверка правила
                if ! rule_exists; then
                    rule_add
                    log "RULE RESTORED (state=up, но правило отсутствовало)"
                fi
            fi
        else
            # Туннель недоступен
            if [ "$PREV_STATE" != "down" ]; then
                log "TUNNEL DOWN — ${{AWG_IFACE}} не отвечает, переключение в Direct Mode"
                rule_del
                set_state "down"
                log "DIRECT MODE ON — правило fwmark ${{AWG_FWMARK}} удалено, Xray идёт напрямую"
            fi
            # Уже был down — правило и так отсутствует, ничего не делаем
        fi
    """)

    try:
        _AWG_WATCHDOG_SCRIPT.write_text(script_content)
        _AWG_WATCHDOG_SCRIPT.chmod(0o750)
        success(f"AWG Watchdog: скрипт → {_AWG_WATCHDOG_SCRIPT}")
    except Exception as e:
        warn(f"AWG Watchdog: ошибка записи скрипта: {e}")
        return

    # Cron: каждую минуту, от root, stderr в /dev/null
    cron_line = (
        f"# AWG Tunnel Fallback Watchdog — VLESS Ultimate Installer\n"
        f"* * * * * root {_AWG_WATCHDOG_SCRIPT} 2>/dev/null\n"
    )
    try:
        _AWG_WATCHDOG_CRON.write_text(cron_line)
        _AWG_WATCHDOG_CRON.chmod(0o644)
        success(f"AWG Watchdog: cron → {_AWG_WATCHDOG_CRON} (каждую минуту)")
    except Exception as e:
        warn(f"AWG Watchdog: ошибка записи cron: {e}")
        return

    # Инициализируем лог
    try:
        _AWG_WATCHDOG_LOG.touch(exist_ok=True)
        _AWG_WATCHDOG_LOG.chmod(0o640)
    except Exception:
        pass

    # Сохраняем флаг в state.json
    _awg_watchdog_set_flag(True)

    info(f"AWG Watchdog: лог    → {_AWG_WATCHDOG_LOG}")
    info(f"AWG Watchdog: state  → {_AWG_WATCHDOG_STATE}")
    info(f"AWG Watchdog: ping IP  → {check_host}")


def awg_watchdog_remove() -> None:
    """Удаляет AWG Tunnel Watchdog (скрипт + cron + state-файл)."""
    for p in (_AWG_WATCHDOG_CRON, _AWG_WATCHDOG_SCRIPT, _AWG_WATCHDOG_STATE):
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass
    _awg_watchdog_set_flag(False)
    success("AWG Tunnel Watchdog отключён и удалён.")


def _awg_watchdog_set_flag(enabled: bool) -> None:
    """Записывает флаг awg_tunnel_watchdog_enabled в state.json."""
    if not STATE_FILE.exists():
        return
    try:
        state = json.loads(STATE_FILE.read_text())
        state["awg_tunnel_watchdog_enabled"] = enabled
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    except Exception as e:
        warn(f"AWG Watchdog: ошибка записи state.json: {e}")


def do_manage_awg_watchdog() -> None:
    """
    Меню управления AWG Tunnel Watchdog.
    Доступно из _menu_security() → пункт 'W'.
    """
    while True:
        os.system("clear")
        print()
        _box_top("🔌 AWG Tunnel Watchdog — мониторинг туннеля awg0")
        _box_row()

        cron_active   = _AWG_WATCHDOG_CRON.exists()
        script_exists = _AWG_WATCHDOG_SCRIPT.exists()
        flag_enabled  = False
        cur_state     = "нет данных"

        try:
            cur_state = _AWG_WATCHDOG_STATE.read_text().strip() \
                if _AWG_WATCHDOG_STATE.exists() else "нет данных"
        except Exception:
            pass

        try:
            st = json.loads(STATE_FILE.read_text())
            flag_enabled  = st.get("awg_tunnel_watchdog_enabled", False)
            install_mode  = st.get("install_mode", "?")
        except Exception:
            install_mode  = "?"

        # Текущее состояние ip rule
        rule_present = False
        try:
            r = subprocess.run(
                ["ip", "rule", "show"], capture_output=True, text=True, check=False
            )
            rule_present = (
                str(AWG_FWMARK) in r.stdout and str(AWG_ROUTE_TABLE) in r.stdout
            )
        except Exception:
            pass

        state_color = GREEN if cur_state == "up" else (RED if cur_state == "down" else DIM)
        rule_color  = GREEN if rule_present else RED

        _box_row_auto(f"  Watchdog cron:       "
                 f"{GREEN+'активен'+NC if cron_active else YELLOW+'отключён'+NC}")
        _box_row_auto(f"  Туннель (last check):{state_color} {cur_state}{NC}")
        _box_row_auto(f"  ip rule fwmark {AWG_FWMARK}:  "
                 f"{rule_color}{'присутствует' if rule_present else 'ОТСУТСТВУЕТ (Direct Mode)'}{NC}")
        _box_row(f"  Режим Xray:          {CYAN}{install_mode}{NC}")
        _box_row_auto(f"  Флаг state.json:     "
                 f"{GREEN+'ВКЛ'+NC if flag_enabled else YELLOW+'ВЫКЛ'+NC}")
        _box_row()
        _box_row_auto(f"  {DIM}Лог: {_AWG_WATCHDOG_LOG}{NC}")
        _box_sep()

        _box_item("1", f"{'Отключить и удалить' if cron_active else 'Установить'} AWG Tunnel Watchdog")
        _box_item("2", f"Восстановить ip rule вручную  {GREEN}(включить туннельный маршрут){NC}")
        _box_item("3", f"Удалить ip rule вручную  {YELLOW}(перейти в Direct Mode){NC}")
        _box_item("T", "Запустить проверку вручную прямо сейчас")
        _box_item("L", f"Показать последние 40 строк лога")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch == "1":
            if cron_active:
                awg_watchdog_remove()
            else:
                if install_mode != "B":
                    warn("AWG Tunnel Watchdog актуален только при Режиме B (awg0 активен).")
                else:
                    awg_watchdog_install()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            info("Восстанавливаем ip rule вручную...")
            r = subprocess.run(
                ["ip", "rule", "add", "fwmark", str(AWG_FWMARK),
                 "table", str(AWG_ROUTE_TABLE), "priority", "100"],
                capture_output=True, text=True, check=False
            )
            try:
                _AWG_WATCHDOG_STATE.write_text("up")
            except Exception:
                pass
            if r.returncode == 0 or "File exists" in r.stderr:
                success(f"ip rule add fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE} priority 100 — OK")
            else:
                warn(f"ip rule add: {r.stderr.strip()}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            warn(f"Удаляем ip rule fwmark {AWG_FWMARK} — Xray перейдёт в Direct Mode!")
            subprocess.run(
                ["ip", "rule", "del", "fwmark", str(AWG_FWMARK),
                 "table", str(AWG_ROUTE_TABLE)],
                check=False
            )
            try:
                _AWG_WATCHDOG_STATE.write_text("down")
            except Exception:
                pass
            success(f"ip rule del fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE} — OK")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "t":
            if script_exists:
                info("Запускаю watchdog вручную (bash)...")
                subprocess.run(["bash", str(_AWG_WATCHDOG_SCRIPT)], check=False)
                time.sleep(0.5)
                # Показываем последние 5 строк лога
                if _AWG_WATCHDOG_LOG.exists():
                    lines = _AWG_WATCHDOG_LOG.read_text().splitlines()[-5:]
                    print()
                    for ln in lines:
                        print(f"  {DIM}{ln}{NC}")
            else:
                warn("Скрипт watchdog не установлен. Сначала установите (пункт 1).")
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "l":
            if _AWG_WATCHDOG_LOG.exists():
                lines = _AWG_WATCHDOG_LOG.read_text().splitlines()[-40:]
                print()
                print("\n".join(f"  {DIM}{ln}{NC}" for ln in lines) or "  (лог пуст)")
            else:
                print("  Лог-файл не найден.")
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор.")
            time.sleep(1)


# =============================================================================
# === PATCH v2: AWG MULTI-NODE — вспомогательные функции и watchdog ===
# =============================================================================

def _awg_node_subnets(node_index: int) -> dict:
    """Уникальные сетевые параметры для ноды node_index (0-based)."""
    n = node_index
    return {
        "interface":    f"awg{n}",
        "subnet_v4":    f"10.66.{n}.0/24",
        "client_ip":    f"10.66.{n}.2/32",
        "server_ip":    f"10.66.{n}.1/32",
        "subnet_v6":    f"fd66:{n}::/48",
        "client_ip_v6": f"fd66:{n}::2/128",
        "server_ip_v6": f"fd66:{n}::1/128",
        "fwmark":       1000 + n,
        "route_table":  1000 + n,
    }


def _ensure_ssh_protection() -> None:
    """
    Извлекает IP SSH-клиента и добавляет ip rule priority 49 lookup main.
    Гарантирует что SSH-сессия не разорвётся при изменении маршрутов AWG.
    Вызывать ДО любых изменений ip rule/ip route. Идемпотентна.
    """
    global _AWG_SSH_CLIENT_IP

    raw = os.environ.get("SSH_CLIENT", "") or os.environ.get("SSH_CONNECTION", "")
    ssh_ip = raw.split()[0] if raw else ""

    if not ssh_ip:
        try:
            r = subprocess.run(["who"], capture_output=True, text=True, check=False)
            for line in r.stdout.splitlines():
                for p in line.split():
                    p = p.strip("()")
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", p):
                        ssh_ip = p
                        break
                if ssh_ip:
                    break
        except Exception:
            pass

    if not ssh_ip:
        log_to_file("WARN", "_ensure_ssh_protection: SSH_CLIENT не определён")
        return

    _AWG_SSH_CLIENT_IP = ssh_ip
    info(f"AWG: SSH-клиент: {ssh_ip} — добавляем защитное правило маршрутизации")

    _run(
        ["ip", "rule", "add", "from", f"{ssh_ip}/32", "lookup", "main", "priority", "49"],
        check=False, quiet=True
    )
    if ":" in ssh_ip:
        _run(
            ["ip", "-6", "rule", "add", "from", f"{ssh_ip}/128", "lookup", "main", "priority", "49"],
            check=False, quiet=True
        )
    _run(
        ["bash", "-c",
         f"PHYS=$(ip route | awk '/default/ {{print $5; exit}}'); "
         f"[ -n \"$PHYS\" ] && ip route show | grep -q '{ssh_ip}' || "
         f"ip route add {ssh_ip}/32 dev $PHYS 2>/dev/null || true"],
        check=False, quiet=True
    )
    _awg_persist_ssh_exclusion(ssh_ip)
    success(f"AWG: SSH-защита активна для {ssh_ip}")


def _awg_persist_ssh_exclusion(ssh_ip: str) -> None:
    """Сохраняет SSH-исключение в /etc/cron.d/awg-ssh-protection (переживёт ребут)."""
    if not ssh_ip:
        return
    cron_path = Path("/etc/cron.d/awg-ssh-protection")
    line = (
        f"# AWG SSH client protection — vless-installer\n"
        f"@reboot root "
        f"ip rule show | grep -q 'from {ssh_ip}' || "
        f"ip rule add from {ssh_ip}/32 lookup main priority 49 2>/dev/null\n"
    )
    try:
        cron_path.write_text(line)
        cron_path.chmod(0o644)
    except Exception as e:
        log_to_file("WARN", f"_awg_persist_ssh_exclusion: {e}")


def _awg_node_from_globals(index: int = 0) -> dict:
    """Создаёт запись ноды из текущих глобальных AWG_* переменных (fallback)."""
    return {
        "host":             AWG_EXIT_HOST,
        "port":             AWG_EXIT_PORT,
        "pubkey":           AWG_SERVER_PUBKEY,
        "preshared_key":    AWG_PRESHARED_KEY,
        "interface":        f"awg{index}",
        "client_ip":        f"10.66.{index}.2/32",
        "server_ip":        f"10.66.{index}.1/32",
        "client_ip_v6":     f"fd66:{index}::2/128",
        "server_ip_v6":     f"fd66:{index}::1/128",
        "subnet_v4":        f"10.66.{index}.0/24",
        "subnet_v6":        f"fd66:{index}::/48",
        "fwmark":           1000 + index,
        "route_table":      1000 + index,
        "status":           "unknown",
        "last_check":       "",
        "ssh_auth_method":  AWG_SSH_AUTH_METHOD,
    }


def _awg_load_nodes_from_state() -> list:
    """Загружает AWG_NODES из state.json."""
    if not STATE_FILE.exists():
        return []
    try:
        st = json.loads(STATE_FILE.read_text())
        return st.get("awg_nodes", [])
    except Exception:
        return []


def _awg_save_nodes_to_state(nodes: list) -> None:
    """
    Записывает AWG_NODES в state.json через merge.
    PATCH v2: использует json.loads → dict.update → json.dumps
    чтобы не затирать другие поля state.json.
    """
    if not STATE_FILE.exists():
        return
    try:
        st = json.loads(STATE_FILE.read_text())
        safe = [{k: v for k, v in n.items() if k != "ssh_password"} for n in nodes]
        st.update({
            "awg_nodes":             safe,
            "awg_active_node_index": AWG_ACTIVE_NODE_INDEX,
            "awg_ssh_client_ip":     _AWG_SSH_CLIENT_IP,
        })
        STATE_FILE.write_text(json.dumps(st, indent=2, ensure_ascii=False))
    except Exception as e:
        warn(f"AWG: ошибка сохранения нод в state.json: {e}")


def _awg_client_conf_for_node(node: dict) -> str:
    """Генерирует текст клиентского конфига AWG для конкретной ноды."""
    cli_ip   = node["client_ip"]
    cli_ip6  = node["client_ip_v6"]
    srv_pub  = node.get("pubkey", AWG_SERVER_PUBKEY)
    psk      = node.get("preshared_key", AWG_PRESHARED_KEY)
    cli_priv = node.get("client_privkey", AWG_CLIENT_PRIVKEY)
    endpoint = f"{node['host']}:{node['port']}"
    return (
        f"[Interface]\n"
        f"PrivateKey = {cli_priv}\n"
        f"Address = {cli_ip}, {cli_ip6}\n"
        f"MTU = {AWG_MTU}\n"
        f"Jc = {AWG_JC}\n"
        f"Jmin = {AWG_JMIN}\n"
        f"Jmax = {AWG_JMAX}\n"
        f"S1 = {AWG_S1}\n"
        f"S2 = {AWG_S2}\n"
        f"H1 = {AWG_H1}\n"
        f"H2 = {AWG_H2}\n"
        f"H3 = {AWG_H3}\n"
        f"H4 = {AWG_H4}\n"
        f"DNS = 1.1.1.1, 8.8.8.8, 2606:4700:4700::1111\n"
        f"Table = off\n\n"
        f"[Peer]\n"
        f"# Зарубежный VPS — AWG-сервер ({node['host']})\n"
        f"PublicKey = {srv_pub}\n"
        f"PresharedKey = {psk}\n"
        f"Endpoint = {endpoint}\n"
        f"AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"PersistentKeepalive = 25\n"
    )


def _awg_server_conf_for_node(node: dict) -> str:
    """Генерирует текст серверного конфига AWG (для exit-VPS)."""
    iface    = node["interface"]
    srv_ip   = node["server_ip"]
    srv_ip6  = node["server_ip_v6"]
    srv_priv = node.get("server_privkey", AWG_SERVER_PRIVKEY)
    cli_pub  = node.get("client_pubkey", AWG_CLIENT_PUBKEY)
    psk      = node.get("preshared_key", AWG_PRESHARED_KEY)
    cli_ip   = node["client_ip"]
    cli_ip6  = node["client_ip_v6"]
    lport    = node["port"]
    dif = "$(ip route | awk '/default/ {print $5; exit}')"
    return (
        f"[Interface]\n"
        f"PrivateKey = {srv_priv}\n"
        f"Address = {srv_ip}, {srv_ip6}\n"
        f"ListenPort = {lport}\n"
        f"MTU = {AWG_MTU}\n"
        f"Jc = {AWG_JC}\nJmin = {AWG_JMIN}\nJmax = {AWG_JMAX}\n"
        f"S1 = {AWG_S1}\nS2 = {AWG_S2}\n"
        f"H1 = {AWG_H1}\nH2 = {AWG_H2}\nH3 = {AWG_H3}\nH4 = {AWG_H4}\n"
        f"PostUp = iptables -A FORWARD -i {iface} -j ACCEPT; "
        f"iptables -A FORWARD -o {iface} -j ACCEPT; "
        f"iptables -t nat -A POSTROUTING -o {dif} -j MASQUERADE; "
        f"ip6tables -A FORWARD -i {iface} -j ACCEPT; "
        f"ip6tables -A FORWARD -o {iface} -j ACCEPT; "
        f"ip6tables -t nat -A POSTROUTING -o {dif} -j MASQUERADE\n"
        f"PostDown = iptables -D FORWARD -i {iface} -j ACCEPT; "
        f"iptables -D FORWARD -o {iface} -j ACCEPT; "
        f"iptables -t nat -D POSTROUTING -o {dif} -j MASQUERADE; "
        f"ip6tables -D FORWARD -i {iface} -j ACCEPT; "
        f"ip6tables -D FORWARD -o {iface} -j ACCEPT; "
        f"ip6tables -t nat -D POSTROUTING -o {dif} -j MASQUERADE\n\n"
        f"[Peer]\n# RU-VPS (Xray client)\n"
        f"PublicKey = {cli_pub}\n"
        f"PresharedKey = {psk}\n"
        f"AllowedIPs = {cli_ip}, {cli_ip6}\n"
    )


def _awg_systemd_unit_for_node(node: dict, xray_uid: int) -> str:
    """Генерирует systemd unit для конкретной AWG-ноды с policy routing и SSH-защитой."""
    iface   = node["interface"]
    fwmark  = node["fwmark"]
    rtable  = node["route_table"]
    mss     = AWG_MTU - 40
    conf    = f"/etc/amnezia/amneziawg/{iface}.conf"
    ssh_excl = ""
    if _AWG_SSH_CLIENT_IP:
        ssh_excl = (
            f"ip rule show | grep -q 'from {_AWG_SSH_CLIENT_IP}' || "
            f"ip rule add from {_AWG_SSH_CLIENT_IP}/32 lookup main priority 49 2>/dev/null || true; "
        )
    pr_up = (
        f"{ssh_excl}"
        f"ip rule show | grep -q 'fwmark {fwmark}' || "
        f"ip rule add fwmark {fwmark} table {rtable} priority 100 2>/dev/null || true; "
        f"ip route show table {rtable} | grep -q default || "
        f"ip route add default dev {iface} table {rtable} 2>/dev/null || true; "
        f"iptables -t mangle -C OUTPUT -m owner --uid-owner {xray_uid} "
        f"-j MARK --set-mark {fwmark} 2>/dev/null || "
        f"iptables -t mangle -A OUTPUT -m owner --uid-owner {xray_uid} "
        f"-j MARK --set-mark {fwmark} 2>/dev/null || true; "
        f"DC_UID=$(id -u dnscrypt 2>/dev/null); "
        f"[ -n \"$DC_UID\" ] && (iptables -t mangle -C OUTPUT -m owner --uid-owner \"$DC_UID\" "
        f"-j MARK --set-mark {fwmark} 2>/dev/null || "
        f"iptables -t mangle -A OUTPUT -m owner --uid-owner \"$DC_UID\" "
        f"-j MARK --set-mark {fwmark} 2>/dev/null || true) || true; "
        f"sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1; "
        f"sysctl -w net.ipv4.conf.{iface}.rp_filter=0 >/dev/null 2>&1"
    )
    pr_down = (
        f"ip route del default dev {iface} table {rtable} 2>/dev/null || true; "
        f"ip rule del fwmark {fwmark} table {rtable} 2>/dev/null || true; "
        f"iptables -t mangle -D OUTPUT -m owner --uid-owner {xray_uid} "
        f"-j MARK --set-mark {fwmark} 2>/dev/null || true"
    )
    _awg_impl = _awg_detect_implementation()
    _env_line = f"Environment=WG_QUICK_USERSPACE_IMPLEMENTATION={_awg_impl}\n" if _awg_impl else ""
    _impl_pfx = f"WG_QUICK_USERSPACE_IMPLEMENTATION={_awg_impl} " if _awg_impl else ""
    _pre = (
        "lsmod | grep -qiE 'amneziawg|amnezia.wg' || "
        "/sbin/modprobe amneziawg 2>/dev/null || "
        "/sbin/modprobe amnezia-wg 2>/dev/null || "
        "/sbin/modprobe wireguard 2>/dev/null || true"
    )
    return (
        f"[Unit]\n"
        f"Description=AmneziaWG 2.0 client ({iface}) + policy routing\n"
        f"After=network-online.target\nWants=network-online.target\n\n"
        f"[Service]\nType=oneshot\nRemainAfterExit=yes\n{_env_line}"
        f"ExecStartPre=/bin/bash -c '{_pre}'\n"
        f"ExecStart=/bin/bash -c 'AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
        f"{_impl_pfx}$AWG_BIN up {conf}'\n"
        f"ExecStartPost=/bin/bash -c '{pr_up}'\n"
        f"ExecStop=/bin/bash -c '{pr_down}'\n"
        f"ExecStop=/bin/bash -c 'AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
        f"{_impl_pfx}$AWG_BIN down {conf}'\n\n"
        f"[Install]\nWantedBy=multi-user.target\n"
    )


def awg_setup_all_nodes() -> bool:
    """
    Настраивает все AWG-ноды из AWG_NODES.
    PATCH v2: _ensure_ssh_protection() вызывается ПЕРВОЙ.
    """
    global AWG_NODES, AWG_ACTIVE_NODE_INDEX
    global AWG_SERVER_PRIVKEY, AWG_SERVER_PUBKEY
    global AWG_CLIENT_PRIVKEY, AWG_CLIENT_PUBKEY, AWG_PRESHARED_KEY

    if not AWG_NODES:
        AWG_NODES = [_awg_node_from_globals(0)]

    def _sync_globals_from_node(n: dict) -> None:
        global AWG_EXIT_HOST, AWG_EXIT_PORT, AWG_INTERFACE
        global AWG_SUBNET, AWG_CLIENT_IP, AWG_SERVER_IP
        global AWG_SUBNET_V6, AWG_CLIENT_IPv6, AWG_SERVER_IPv6
        global AWG_FWMARK, AWG_ROUTE_TABLE
        AWG_EXIT_HOST   = n["host"]
        AWG_EXIT_PORT   = n["port"]
        AWG_INTERFACE   = n["interface"]
        AWG_SUBNET      = n["subnet_v4"]
        AWG_CLIENT_IP   = n["client_ip"]
        AWG_SERVER_IP   = n["server_ip"]
        AWG_SUBNET_V6   = n["subnet_v6"]
        AWG_CLIENT_IPv6 = n["client_ip_v6"]
        AWG_SERVER_IPv6 = n["server_ip_v6"]
        AWG_FWMARK      = n["fwmark"]
        AWG_ROUTE_TABLE = n["route_table"]

    # PATCH v2 п.3: SSH-защита ДО любых изменений маршрутов
    _ensure_ssh_protection()

    try:
        ensure_amneziawg_ready()
    except Exception as e:
        warn(f"AWG: модуль ядра недоступен: {e}")
        return False

    if not awg_install_local():
        warn("AWG: не удалось установить amneziawg-tools")
        return False

    try:
        xray_uid = pwd.getpwnam("xray").pw_uid
    except KeyError:
        xray_uid = 0
        warn("AWG: пользователь xray не найден — uid=0")

    _AWG_CONF_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(str(_AWG_CONF_DIR), 0o700)
    _wg_dir = Path("/etc/wireguard")
    _wg_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(str(_wg_dir), 0o700)

    any_ok = False
    for idx, node in enumerate(AWG_NODES):
        iface = node["interface"]
        info(f"AWG: настройка ноды {idx} ({iface} → {node['host']}:{node['port']})...")

        if not awg_generate_keys():
            warn(f"AWG: нода {idx}: ключи не сгенерированы — пропуск")
            continue

        node.update({
            "server_privkey": AWG_SERVER_PRIVKEY,
            "server_pubkey":  AWG_SERVER_PUBKEY,
            "client_privkey": AWG_CLIENT_PRIVKEY,
            "client_pubkey":  AWG_CLIENT_PUBKEY,
            "preshared_key":  AWG_PRESHARED_KEY,
            "pubkey":         AWG_SERVER_PUBKEY,
        })

        cli_conf_path = _AWG_CONF_DIR / f"{iface}.conf"
        cli_conf_path.write_text(_awg_client_conf_for_node(node))
        os.chmod(str(cli_conf_path), 0o600)
        success(f"AWG: клиентский конфиг → {cli_conf_path}")

        _wg_link = _wg_dir / f"{iface}.conf"
        try:
            if _wg_link.exists() or _wg_link.is_symlink():
                _wg_link.unlink()
            _wg_link.symlink_to(cli_conf_path)
        except Exception as sym_err:
            warn(f"AWG: симлинк {_wg_link}: {sym_err}")

        srv_conf_path = _AWG_CONF_DIR / f"{iface}-server-template.conf"
        srv_conf_path.write_text(_awg_server_conf_for_node(node))
        os.chmod(str(srv_conf_path), 0o600)

        svc_name = f"amneziawg-{iface}.service"
        unit_path = Path(f"/etc/systemd/system/{svc_name}")
        unit_path.write_text(_awg_systemd_unit_for_node(node, xray_uid))
        _run(["systemctl", "daemon-reload"], check=False, quiet=True)
        _run(["systemctl", "enable", svc_name], check=False, quiet=True)
        success(f"AWG: systemd unit {svc_name} создан и включён")

        _sync_globals_from_node(node)
        AWG_CLIENT_PUBKEY   = node["client_pubkey"]
        AWG_SERVER_PRIVKEY  = node["server_privkey"]
        AWG_PRESHARED_KEY   = node["preshared_key"]
        AWG_SSH_AUTH_METHOD = node.get("ssh_auth_method", "key")
        AWG_SSH_PASSWORD    = node.get("ssh_password", "")

        info(f"AWG: нода {idx}: установка сервера на {node['host']} по SSH...")
        node["remote_ok"] = awg_setup_remote_server()
        any_ok = True

    _awg_save_nodes_to_state(AWG_NODES)

    # === FIX 4: защита от IndexError при обращении к AWG_NODES[AWG_ACTIVE_NODE_INDEX] ===
    if AWG_NODES and 0 <= AWG_ACTIVE_NODE_INDEX < len(AWG_NODES):
        _sync_globals_from_node(AWG_NODES[AWG_ACTIVE_NODE_INDEX])
    else:
        AWG_ACTIVE_NODE_INDEX = 0
        if AWG_NODES:
            _sync_globals_from_node(AWG_NODES[0])
    # === END FIX 4 ===

    return any_ok


def _awg_bring_up_all_tunnels() -> None:
    """Поднимает все AWG-туннели."""
    nodes = AWG_NODES if AWG_NODES else [_awg_node_from_globals(0)]
    for node in nodes:
        iface = node["interface"]
        conf  = f"/etc/amnezia/amneziawg/{iface}.conf"
        _up_impl = _awg_detect_implementation()
        _up_pfx  = f"WG_QUICK_USERSPACE_IMPLEMENTATION={_up_impl} " if _up_impl else ""
        r = _run(
            ["bash", "-c",
             f"AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
             f"{_up_pfx}$AWG_BIN up {conf}"],
            check=False, quiet=True
        )
        if r.returncode == 0:
            success(f"AWG: туннель {iface} поднят")
        else:
            r_chk = _run(["ip", "link", "show", iface], capture=True, check=False)
            if r_chk.returncode == 0:
                success(f"AWG: туннель {iface} уже активен")
            else:
                warn(f"AWG: awg-quick up {iface} → rc={r.returncode}: {r.stderr[:120]}")


def _awg_apply_policy_routing_all_nodes() -> None:
    """
    Применяет policy routing для ВСЕХ нод.
    PATCH v2 п.3: _ensure_ssh_protection() вызывается первой.
    """
    nodes = AWG_NODES if AWG_NODES else [_awg_node_from_globals(0)]
    active_idx = AWG_ACTIVE_NODE_INDEX

    # PATCH v2 п.3: SSH-защита ДО изменений маршрутов
    _ensure_ssh_protection()

    _server_ip  = get_server_ip("4") or ""
    _server_ip6 = get_server_ip("6") or ""
    if _server_ip:
        _run(["ip", "rule", "add", "from", f"{_server_ip}/32",
              "lookup", "main", "priority", "49"], check=False, quiet=True)
    if _server_ip6:
        _run(["ip", "-6", "rule", "add", "from", f"{_server_ip6}/128",
              "lookup", "main", "priority", "49"], check=False, quiet=True)

    try:
        xray_uid = pwd.getpwnam("xray").pw_uid
    except KeyError:
        xray_uid = 0

    _ipv6_ok = _run(["ip", "-6", "route", "show"], capture=True, check=False, quiet=True).returncode == 0

    for idx, node in enumerate(nodes):
        iface  = node["interface"]
        fwmark = node["fwmark"]
        rtable = node["route_table"]
        host   = node["host"]

        _run(["ip", "rule", "add", "fwmark", str(fwmark),
              "table", str(rtable), "priority", "100"], check=False, quiet=True)
        _run(["ip", "route", "add", "default", "dev", iface,
              "table", str(rtable)], check=False, quiet=True)
        if _ipv6_ok:
            _run(["ip", "-6", "rule", "add", "fwmark", str(fwmark),
                  "table", str(rtable), "priority", "100"], check=False, quiet=True)
            _run(["ip", "-6", "route", "add", "default", "dev", iface,
                  "table", str(rtable)], check=False, quiet=True)
        if host:
            _run(["ip", "rule", "add", "to", f"{host}/32",
                  "lookup", "main", "priority", "50"], check=False, quiet=True)
            _run(["bash", "-c",
                  f"ip route add {host}/32 dev $(ip route | awk '/default/ {{print $5; exit}}') 2>/dev/null || true"],
                 check=False, quiet=True)

        # iptables mangle mark — только для АКТИВНОЙ ноды
        if idx == active_idx:
            _run(["iptables", "-t", "mangle", "-A", "OUTPUT",
                  "-m", "owner", "--uid-owner", str(xray_uid),
                  "-j", "MARK", "--set-mark", str(fwmark)], check=False, quiet=True)
            if _ipv6_ok:
                _run(["ip6tables", "-t", "mangle", "-A", "OUTPUT",
                      "-m", "owner", "--uid-owner", str(xray_uid),
                      "-j", "MARK", "--set-mark", str(fwmark)], check=False, quiet=True)
            try:
                dc_uid = pwd.getpwnam("dnscrypt").pw_uid
                _run(["iptables", "-t", "mangle", "-A", "OUTPUT",
                      "-m", "owner", "--uid-owner", str(dc_uid),
                      "-j", "MARK", "--set-mark", str(fwmark)], check=False, quiet=True)
            except KeyError:
                pass

        _run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False, quiet=True)
        _run(["sysctl", "-w", f"net.ipv4.conf.{iface}.rp_filter=0"], check=False, quiet=True)

    rules_dir = Path("/etc/iptables")
    rules_dir.mkdir(parents=True, exist_ok=True)
    r4 = _run(["iptables-save"], capture=True, check=False)
    if r4.returncode == 0:
        (rules_dir / "rules.v4").write_text(r4.stdout)
    if _ipv6_ok:
        r6 = _run(["ip6tables-save"], capture=True, check=False)
        if r6.returncode == 0:
            (rules_dir / "rules.v6").write_text(r6.stdout)
    _run(["netfilter-persistent", "save"], check=False, quiet=True)
    success(f"AWG Multi-Node: policy routing применён для {len(nodes)} нод(ы)")


def _awg_verify_all_tunnels() -> None:
    """
    Проверяет статус всех AWG-туннелей (multi-node).
    Для каждой ноды: интерфейс + handshake + ping до внутреннего IP.
    Обновляет node["status"] и сохраняет в state.
    """
    nodes = AWG_NODES if AWG_NODES else [_awg_node_from_globals(0)]
    awg_bin = AWG_BIN if awg_check_tool(AWG_BIN) else ("wg" if awg_check_tool("wg") else None)

    _ok   = f"{GREEN}✓{NC}"
    _warn = f"{YELLOW}✗{NC}"
    _skip = f"{DIM}−{NC}"

    print()
    _box_top("AWG Multi-Node: результаты верификации")

    for node in nodes:
        iface      = node["interface"]
        server_ip  = node.get("server_ip", "").split("/")[0]
        exit_host  = node.get("host", "")
        fwmark     = node.get("fwmark", AWG_FWMARK)
        route_tbl  = node.get("route_table", AWG_ROUTE_TABLE)

        _box_row(f"  {DIM}Нода: {iface} → {exit_host}{NC}")

        # Интерфейс
        r_link = _run(["ip", "link", "show", iface], capture=True, check=False)
        iface_ok = r_link.returncode == 0
        if iface_ok:
            _box_row(f"    {_ok}  Интерфейс {iface} активен")
            node["status"] = "up"
            log_to_file("DEBUG", f"_awg_verify_all: {iface} up")
        else:
            _box_row(f"    {_warn}  Интерфейс {iface} НЕ поднят")
            node["status"] = "down"
            log_to_file("WARN", f"_awg_verify_all: {iface} not found")

        # Handshake
        if iface_ok and awg_bin:
            try:
                r_hs = _run([awg_bin, "show", iface, "latest-handshakes"],
                            capture=True, check=False)
                if r_hs.returncode == 0 and r_hs.stdout.strip():
                    _hs_ok = False
                    for _line in r_hs.stdout.strip().splitlines():
                        _parts = _line.split()
                        if len(_parts) >= 2:
                            try:
                                _ts = int(_parts[-1])
                            except ValueError:
                                continue
                            if _ts > 0:
                                _ago = int(time.time()) - _ts
                                _ago_str = (f"{_ago}с" if _ago < 120
                                            else f"{_ago // 60}м {_ago % 60}с")
                                _hc = GREEN if _ago < 180 else YELLOW
                                _box_row(f"    {_ok}  Handshake: "
                                         f"{_hc}{_ago_str} назад{NC}")
                                log_to_file("DEBUG",
                                    f"_awg_verify_all: {iface} handshake {_ago_str} ago")
                                _hs_ok = True
                                break
                    if not _hs_ok:
                        _box_row(f"    {_warn}  Handshake: не установлен")
                        log_to_file("WARN", f"_awg_verify_all: {iface} no handshake")
                else:
                    _box_row(f"    {_skip}  Handshake: нет данных")
            except Exception as _e:
                _box_row(f"    {_skip}  Handshake: ошибка ({_e})")
                log_to_file("WARN", f"_awg_verify_all: {iface} handshake error: {_e}")

        # Ping до внутреннего IP exit-VPS
        if iface_ok and server_ip:
            try:
                r_ping = _run(
                    ["ping", "-c", "2", "-W", "3", "-I", iface, server_ip],
                    capture=True, check=False
                )
                if r_ping.returncode == 0:
                    _m = re.search(r"time=([\d.]+)", r_ping.stdout)
                    _lat = f"{int(float(_m.group(1)))} мс" if _m else "OK"
                    _lc  = GREEN if _m and float(_m.group(1)) < 150 else                            YELLOW if _m and float(_m.group(1)) < 300 else RED
                    _box_row(f"    {_ok}  Ping → {server_ip}: {_lc}{_lat}{NC}")
                    log_to_file("DEBUG", f"_awg_verify_all: {iface} ping {server_ip} OK")
                else:
                    _box_row(f"    {_warn}  Ping → {server_ip}: нет ответа")
                    log_to_file("WARN",
                        f"_awg_verify_all: {iface} ping {server_ip} failed")
            except Exception as _e:
                _box_row(f"    {_skip}  Ping: ошибка ({_e})")
                log_to_file("WARN", f"_awg_verify_all: {iface} ping error: {_e}")
        elif iface_ok:
            _box_row(f"    {_skip}  Ping: server_ip не задан")

        # Policy routing
        r_rule = _run(["ip", "rule", "show"], capture=True, check=False)
        if str(fwmark) in (r_rule.stdout or ""):
            _box_row(f"    {_ok}  ip rule fwmark {fwmark} → table {route_tbl}")
        else:
            _box_row(f"    {_warn}  ip rule: fwmark {fwmark} не найдено")
            log_to_file("WARN", f"_awg_verify_all: {iface} fwmark {fwmark} missing")

        node["last_check"] = datetime.now(timezone.utc).isoformat()
        _box_sep()

    _box_bottom()
    _awg_save_nodes_to_state(nodes)


def _start_services_sequentially(
    dnscrypt_enabled: bool = False,
    awg_interfaces: list = None,
    xray_restart: bool = True,
    timeout: int = 15,
) -> bool:
    """
    PATCH v2 п.7: строгий порядок запуска сервисов.
    DNSCrypt → AWG-туннели → Xray → Nginx.
    Возвращает True если Xray успешно запустился.
    """
    info("AWG: последовательный запуск сервисов...")

    if dnscrypt_enabled:
        _run(["systemctl", "start", "dnscrypt-proxy"], check=False, quiet=True)
        ok = _wait_service_active("dnscrypt-proxy", max_sec=timeout, silent=True)
        if ok:
            success("  ✓ DNSCrypt-proxy активен")
        else:
            warn("  ✗ DNSCrypt-proxy не запустился (таймаут)")

    ifaces_to_check = awg_interfaces or ["awg0"]
    for iface in ifaces_to_check:
        svc = f"amneziawg-{iface}.service"
        _run(["systemctl", "start", svc], check=False, quiet=True)
    for iface in ifaces_to_check:
        for _ in range(timeout):
            r = subprocess.run(
                ["ip", "link", "show", iface], capture_output=True, text=True, check=False
            )
            if r.returncode == 0:
                success(f"  ✓ Интерфейс {iface} активен")
                break
            time.sleep(1)
        else:
            warn(f"  ✗ Интерфейс {iface} не поднялся за {timeout}с")

    xray_ok = False
    if xray_restart:
        _run(["systemctl", "restart", "xray"], check=False, quiet=True)
        xray_ok = _wait_service_active("xray", max_sec=timeout, silent=True)
        if xray_ok:
            success("  ✓ Xray активен")
        else:
            warn("  ✗ Xray не запустился — journalctl -u xray -n 30")

    if subprocess.run(
        ["systemctl", "list-units", "--type=service", "--no-legend", "nginx.service"],
        capture_output=True, text=True, check=False
    ).stdout.strip():
        _run(["systemctl", "start", "nginx"], check=False, quiet=True)

    for svc in ("fail2ban", "irqbalance"):
        _run(["systemctl", "start", svc], check=False, quiet=True)

    return xray_ok


_AWG_MULTINODE_WATCHDOG_SCRIPT = Path("/usr/local/bin/awg-multinode-watchdog.sh")
_AWG_MULTINODE_WATCHDOG_CRON   = Path("/etc/cron.d/awg-multinode-watchdog")
_AWG_MULTINODE_WATCHDOG_LOG    = Path("/var/log/awg-multinode-watchdog.log")
_AWG_MULTINODE_FAILOVER_LOG    = Path("/var/log/awg-failover-history.log")


def awg_multinode_watchdog_install() -> None:
    """
    Создаёт bash-скрипт мультинодового watchdog и cron-задачу.
    PATCH v2 п.2: при 1 ноде вызывает оригинальный awg_watchdog_install() — не дублирует.
    PATCH v2 п.4: switch_active_node() обновляет fwmark Xray в iptables mangle.
    """
    nodes = AWG_NODES if AWG_NODES else [_awg_node_from_globals(0)]

    # PATCH v2: при одной ноде — оригинальный watchdog, без дублирования
    if len(nodes) <= 1:
        awg_watchdog_install()
        return

    info(f"AWG Multi-Node Watchdog: генерация скрипта для {len(nodes)} нод...")

    hosts_arr   = " ".join(f'"{n["host"]}"'       for n in nodes)
    ifaces_arr  = " ".join(f'"{n["interface"]}"'  for n in nodes)
    fwmarks_arr = " ".join(str(n["fwmark"])        for n in nodes)
    rtables_arr = " ".join(str(n["route_table"])   for n in nodes)

    tg_cmd = (
        "TG_TOKEN=$(python3 -c \"import json; s=json.load(open('/etc/xray/state.json')); "
        "print(s.get('tg_bot_token',''))\" 2>/dev/null); "
        "TG_CHAT=$(python3 -c \"import json; s=json.load(open('/etc/xray/state.json')); "
        "print(s.get('tg_chat_id',''))\" 2>/dev/null); "
        "[ -n \"$TG_TOKEN\" ] && [ -n \"$TG_CHAT\" ] && "
        "curl -sS \"https://api.telegram.org/bot${TG_TOKEN}/sendMessage\" "
        "--data-urlencode \"chat_id=${TG_CHAT}\" "
        "--data-urlencode \"text=${TG_MSG}\" >/dev/null 2>&1 || true"
    )

    script = textwrap.dedent(f"""\
        #!/bin/bash
        # AWG Multi-Node Failover Watchdog — VLESS Ultimate Installer (patch v2)
        set -euo pipefail

        HOSTS=({hosts_arr})
        IFACES=({ifaces_arr})
        FWMARKS=({fwmarks_arr})
        RTABLES=({rtables_arr})
        NODE_COUNT=${{#HOSTS[@]}}

        ACTIVE_IDX_FILE="/var/run/awg-active-node"
        FAIL_COUNT_DIR="/var/run/awg-fail-counts"
        LOG="{_AWG_MULTINODE_WATCHDOG_LOG}"
        FAILOVER_LOG="{_AWG_MULTINODE_FAILOVER_LOG}"
        FAIL_THRESHOLD=2
        PING_COUNT=2
        PING_TIMEOUT=3

        mkdir -p "$FAIL_COUNT_DIR"
        ts()    {{ date '+%Y-%m-%d %H:%M:%S'; }}
        log()   {{ echo "[$(ts)] $*" | tee -a "$LOG"; }}
        flog()  {{ echo "[$(ts)] $*" | tee -a "$FAILOVER_LOG" >> "$LOG"; }}

        get_active() {{ [ -f "$ACTIVE_IDX_FILE" ] && cat "$ACTIVE_IDX_FILE" || echo "0"; }}
        set_active() {{ echo "$1" > "$ACTIVE_IDX_FILE"; }}

        get_fail() {{ [ -f "$FAIL_COUNT_DIR/$1" ] && cat "$FAIL_COUNT_DIR/$1" || echo "0"; }}
        set_fail() {{ echo "$2" > "$FAIL_COUNT_DIR/$1"; }}
        inc_fail() {{ local c; c=$(get_fail "$1"); set_fail "$1" $(( c + 1 )); echo $(( c + 1 )); }}
        reset_fail() {{ set_fail "$1" 0; }}

        tunnel_ok() {{
            local idx=$1
            ip link show "${{IFACES[$idx]}}" &>/dev/null || return 1
            ping -I "${{IFACES[$idx]}}" -c $PING_COUNT -W $PING_TIMEOUT -q "${{HOSTS[$idx]}}" &>/dev/null 2>&1 || \
            ping -I "${{IFACES[$idx]}}" -c $PING_COUNT -W $PING_TIMEOUT -q "1.1.1.1" &>/dev/null 2>&1
        }}

        # PATCH v2 п.4: switch_active_node обновляет fwmark Xray
        switch_active_node() {{
            local old_idx=$1 new_idx=$2
            local old_fwmark="${{FWMARKS[$old_idx]}}"
            local new_fwmark="${{FWMARKS[$new_idx]}}"
            local new_iface="${{IFACES[$new_idx]}}"
            local new_rtable="${{RTABLES[$new_idx]}}"

            flog "FAILOVER: нода $old_idx (fwmark=$old_fwmark) → нода $new_idx (fwmark=$new_fwmark)"

            # === FIX 3: идемпотентный ip rule replace вместо add (не даёт RTNETLINK: File exists) ===
            ip rule show | grep -q "fwmark ${{new_fwmark}}" || \
                ip rule replace fwmark "$new_fwmark" table "$new_rtable" priority 100 2>/dev/null || true
            ip route show table "$new_rtable" 2>/dev/null | grep -q default || \
                ip route add default dev "$new_iface" table "$new_rtable" 2>/dev/null || true
            ip -6 rule show 2>/dev/null | grep -q "fwmark ${{new_fwmark}}" || \
                ip -6 rule replace fwmark "$new_fwmark" table "$new_rtable" priority 100 2>/dev/null || true
            # === END FIX 3 ===

            XRAY_UID=$(id -u xray 2>/dev/null || echo 0)
            DC_UID=$(id -u dnscrypt 2>/dev/null || echo "")

            # Удаляем старый fwmark для xray
            iptables -t mangle -D OUTPUT -m owner --uid-owner "$XRAY_UID" \
                -j MARK --set-mark "$old_fwmark" 2>/dev/null || true
            ip6tables -t mangle -D OUTPUT -m owner --uid-owner "$XRAY_UID" \
                -j MARK --set-mark "$old_fwmark" 2>/dev/null || true
            [ -n "$DC_UID" ] && {{
                iptables -t mangle -D OUTPUT -m owner --uid-owner "$DC_UID" \
                    -j MARK --set-mark "$old_fwmark" 2>/dev/null || true
            }} || true

            # Добавляем новый fwmark для xray
            iptables -t mangle -C OUTPUT -m owner --uid-owner "$XRAY_UID" \
                -j MARK --set-mark "$new_fwmark" 2>/dev/null || \
            iptables -t mangle -A OUTPUT -m owner --uid-owner "$XRAY_UID" \
                -j MARK --set-mark "$new_fwmark" 2>/dev/null || true
            ip6tables -t mangle -C OUTPUT -m owner --uid-owner "$XRAY_UID" \
                -j MARK --set-mark "$new_fwmark" 2>/dev/null || \
            ip6tables -t mangle -A OUTPUT -m owner --uid-owner "$XRAY_UID" \
                -j MARK --set-mark "$new_fwmark" 2>/dev/null || true
            [ -n "$DC_UID" ] && {{
                iptables -t mangle -C OUTPUT -m owner --uid-owner "$DC_UID" \
                    -j MARK --set-mark "$new_fwmark" 2>/dev/null || \
                iptables -t mangle -A OUTPUT -m owner --uid-owner "$DC_UID" \
                    -j MARK --set-mark "$new_fwmark" 2>/dev/null || true
            }} || true

            set_active "$new_idx"

            # Обновляем state.json через merge
            python3 -c "
import json, sys
try:
    with open('/etc/xray/state.json') as f: s = json.load(f)
    s['awg_active_node_index'] = $new_idx
    with open('/etc/xray/state.json', 'w') as f: json.dump(s, f, indent=2)
except Exception as e: sys.stderr.write(str(e))
" 2>/dev/null || true

            TG_MSG="AWG Failover: нода $old_idx (${{HOSTS[$old_idx]}}) → нода $new_idx (${{HOSTS[$new_idx]}})"
            {tg_cmd}
            flog "FAILOVER DONE → активна нода $new_idx ($new_iface)"
        }}

        ACTIVE=$(get_active)
        declare -a NODE_STATUS

        for (( i=0; i<NODE_COUNT; i++ )); do
            if tunnel_ok "$i"; then
                NODE_STATUS[$i]="up"; reset_fail "$i"
            else
                fails=$(inc_fail "$i")
                if [ "$fails" -ge "$FAIL_THRESHOLD" ]; then
                    NODE_STATUS[$i]="down"
                    log "WARN: нода $i (${{HOSTS[$i]}}) провал $fails/$FAIL_THRESHOLD"
                else
                    NODE_STATUS[$i]="warn"
                fi
            fi
        done

        if [ "${{NODE_STATUS[$ACTIVE]}}" = "down" ]; then
            log "FAILOVER TRIGGER: активная нода $ACTIVE упала"
            for (( i=0; i<NODE_COUNT; i++ )); do
                if [ "$i" -ne "$ACTIVE" ] && [ "${{NODE_STATUS[$i]}}" = "up" ]; then
                    switch_active_node "$ACTIVE" "$i"
                    ACTIVE="$i"
                    break
                fi
            done
        fi

        if [ "${{NODE_STATUS[$ACTIVE]}}" = "up" ]; then
            FWMARK="${{FWMARKS[$ACTIVE]}}"
            RTABLE="${{RTABLES[$ACTIVE]}}"
            # === FIX 3: идемпотентный replace вместо add ===
            ip rule show | grep -qE "fwmark (0x)?${{FWMARK}}.*lookup ${{RTABLE}}" || {{
                ip rule replace fwmark "$FWMARK" table "$RTABLE" priority 100 2>/dev/null || true
                log "RULE RESTORED: fwmark=$FWMARK table=$RTABLE"
            }}
            # === END FIX 3 ===
        fi
    """)

    try:
        _AWG_MULTINODE_WATCHDOG_SCRIPT.write_text(script)
        _AWG_MULTINODE_WATCHDOG_SCRIPT.chmod(0o750)
        success(f"AWG Multi-Node Watchdog: скрипт → {_AWG_MULTINODE_WATCHDOG_SCRIPT}")
    except Exception as e:
        warn(f"AWG Multi-Node Watchdog: ошибка записи скрипта: {e}")
        return

    cron_line = (
        f"# AWG Multi-Node Failover Watchdog — VLESS Ultimate Installer\n"
        f"* * * * * root {_AWG_MULTINODE_WATCHDOG_SCRIPT} 2>/dev/null\n"
    )
    try:
        _AWG_MULTINODE_WATCHDOG_CRON.write_text(cron_line)
        _AWG_MULTINODE_WATCHDOG_CRON.chmod(0o644)
        success(f"AWG Multi-Node Watchdog: cron → {_AWG_MULTINODE_WATCHDOG_CRON}")
    except Exception as e:
        warn(f"AWG Multi-Node Watchdog: ошибка cron: {e}")
        return

    _AWG_MULTINODE_WATCHDOG_LOG.touch(exist_ok=True)
    _AWG_MULTINODE_FAILOVER_LOG.touch(exist_ok=True)
    _awg_watchdog_set_flag(True)
    success("AWG Multi-Node Watchdog установлен")


def do_manage_awg_nodes() -> None:
    """TUI: управление пулом AWG exit-нод. Вход из _menu_security() → [N]."""
    while True:
        os.system("clear")
        print()
        _box_top("🌐 AWG Multi-Node — Управление нодами и Failover")
        _box_row()

        nodes = _awg_load_nodes_from_state() or AWG_NODES or []
        active_idx = AWG_ACTIVE_NODE_INDEX
        try:
            st = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
            active_idx = st.get("awg_active_node_index", 0)
        except Exception:
            pass

        watchdog_data = {}
        try:
            wp = Path("/var/run/awg-multinode-state.json")
            if wp.exists():
                watchdog_data = json.loads(wp.read_text())
        except Exception:
            pass

        if not nodes:
            _box_warn("AWG-ноды не настроены. Запустите установку (Режим B + AWG).")
        else:
            _box_row(f"  Всего нод: {CYAN}{len(nodes)}{NC}   Активная: {GREEN}нода {active_idx}{NC}")
            _box_sep()
            for idx, node in enumerate(nodes):
                iface  = node.get("interface", f"awg{idx}")
                host   = node.get("host", "?")
                port   = node.get("port", 51820)
                fwmark = node.get("fwmark", 1000 + idx)
                rtable = node.get("route_table", 1000 + idx)
                r_link = subprocess.run(
                    ["ip", "link", "show", iface], capture_output=True, text=True, check=False
                )
                iface_up = r_link.returncode == 0
                wd_status = "—"
                for wn in watchdog_data.get("nodes", []):
                    if wn.get("index") == idx:
                        wd_status = wn.get("status", "—")
                        break
                is_active = (idx == active_idx)
                active_mark = f" {GREEN}[АКТИВНАЯ]{NC}" if is_active else ""
                link_col = GREEN if iface_up else RED
                link_lbl = "UP" if iface_up else "DOWN"
                _box_row(
                    f"  {CYAN}[{idx}]{NC} {iface} → {host}:{port}"
                    f"  {link_col}{link_lbl}{NC}  watchdog:{wd_status}{active_mark}"
                )
                _box_row(f"      fwmark={fwmark}  table={rtable}  {node.get('subnet_v4','?')}")

        _box_sep()
        _box_item("S", "Переключить активную ноду вручную")
        _box_item("P", "Пинг / проверка связи через каждую ноду")
        _box_item("F", "Показать историю failover")
        _box_item("W", "Управление Multi-Node Watchdog")
        _box_item("R", "Восстановить ip rule/route для всех нод")
        _box_item("I", "SSH-защита: статус и IP SSH-клиента")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch in ("b", "0", "q", ""):
            break
        elif ch == "s":
            if not nodes:
                warn("Нет нод."); input(f"{BLUE}Enter...{NC}"); continue
            _box_top("Переключение активной ноды")
            for idx, n in enumerate(nodes):
                mark = " ← активная" if idx == active_idx else ""
                _box_row(f"  [{idx}] {n.get('interface','?')} → {n.get('host','?')}{mark}")
            _box_bottom()
            try:
                raw = input(f"  {CYAN}Номер ноды [0-{len(nodes)-1}]:{NC} ").strip()
                new_idx = int(raw)
                if 0 <= new_idx < len(nodes):
                    _awg_manual_switch(active_idx, new_idx, nodes)
                    success(f"Переключено на ноду {new_idx}")
                else:
                    warn("Неверный номер ноды")
            except (ValueError, KeyboardInterrupt):
                warn("Отмена")
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "p":
            _awg_ping_all_nodes(nodes); input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "f":
            _awg_show_failover_log(); input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "w":
            do_manage_awg_watchdog()
        elif ch == "r":
            info("Восстановление ip rule/route...")
            _awg_apply_policy_routing_all_nodes()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "i":
            _awg_show_ssh_protection_status(); input(f"{BLUE}Нажмите Enter...{NC}")


def _awg_manual_switch(old_idx: int, new_idx: int, nodes: list) -> None:
    """Ручное переключение активной ноды: обновляет iptables mangle + state.json."""
    global AWG_ACTIVE_NODE_INDEX
    if old_idx == new_idx or new_idx >= len(nodes):
        return
    old_fwmark = nodes[old_idx]["fwmark"]
    new_fwmark = nodes[new_idx]["fwmark"]
    new_rtable = nodes[new_idx]["route_table"]
    new_iface  = nodes[new_idx]["interface"]
    try:
        xray_uid = pwd.getpwnam("xray").pw_uid
    except KeyError:
        xray_uid = 0
    _run(["iptables", "-t", "mangle", "-D", "OUTPUT",
          "-m", "owner", "--uid-owner", str(xray_uid),
          "-j", "MARK", "--set-mark", str(old_fwmark)], check=False, quiet=True)
    _run(["ip6tables", "-t", "mangle", "-D", "OUTPUT",
          "-m", "owner", "--uid-owner", str(xray_uid),
          "-j", "MARK", "--set-mark", str(old_fwmark)], check=False, quiet=True)
    _run(["iptables", "-t", "mangle", "-A", "OUTPUT",
          "-m", "owner", "--uid-owner", str(xray_uid),
          "-j", "MARK", "--set-mark", str(new_fwmark)], check=False, quiet=True)
    _run(["ip6tables", "-t", "mangle", "-A", "OUTPUT",
          "-m", "owner", "--uid-owner", str(xray_uid),
          "-j", "MARK", "--set-mark", str(new_fwmark)], check=False, quiet=True)
    _run(["ip", "rule", "add", "fwmark", str(new_fwmark),
          "table", str(new_rtable), "priority", "100"], check=False, quiet=True)
    _run(["ip", "route", "add", "default", "dev", new_iface,
          "table", str(new_rtable)], check=False, quiet=True)
    AWG_ACTIVE_NODE_INDEX = new_idx
    _awg_save_nodes_to_state(nodes)
    try:
        Path("/var/run/awg-active-node").write_text(str(new_idx))
    except Exception:
        pass


def _awg_ping_all_nodes(nodes: list) -> None:
    """Пингует каждую ноду через её интерфейс, выводит latency."""
    print()
    _box_top("AWG: проверка связи через все туннели")
    for idx, node in enumerate(nodes):
        iface = node.get("interface", f"awg{idx}")
        host  = node.get("host", "")
        if not host:
            continue
        _box_row(f"  Нода {idx} ({iface} → {host}):")
        r4 = subprocess.run(
            ["ping", "-I", iface, "-c", "3", "-W", "3", "-q", host],
            capture_output=True, text=True, check=False
        )
        if r4.returncode == 0:
            for line in r4.stdout.splitlines():
                if "rtt" in line or "avg" in line:
                    _box_row(f"    {GREEN}IPv4 OK{NC}  {line.strip()}")
                    break
        else:
            _box_row(f"    {RED}IPv4 FAIL{NC}")
    _box_bottom()


def _awg_show_failover_log() -> None:
    """Последние 50 строк лога failover."""
    print()
    _box_top(f"История Failover — {_AWG_MULTINODE_FAILOVER_LOG}")
    try:
        if _AWG_MULTINODE_FAILOVER_LOG.exists():
            for line in _AWG_MULTINODE_FAILOVER_LOG.read_text().splitlines()[-50:]:
                _box_row(f"  {line}")
        else:
            _box_row("  Лог пуст или отсутствует.")
    except Exception as e:
        _box_row(f"  Ошибка чтения лога: {e}")
    _box_bottom()


def _awg_show_ssh_protection_status() -> None:
    """Статус SSH-защиты."""
    print()
    _box_top("🔒 AWG SSH-защита — статус")
    ssh_ip = _AWG_SSH_CLIENT_IP
    cron_p = Path("/etc/cron.d/awg-ssh-protection")
    if not ssh_ip and cron_p.exists():
        try:
            m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", cron_p.read_text())
            if m:
                ssh_ip = m.group(1)
        except Exception:
            pass
    if ssh_ip:
        _box_row(f"  SSH-клиент IP: {GREEN}{ssh_ip}{NC}")
        r = subprocess.run(["ip", "rule", "show"], capture_output=True, text=True, check=False)
        rule_ok = f"from {ssh_ip}" in r.stdout
        col = GREEN if rule_ok else RED
        lbl = "ПРИСУТСТВУЕТ (priority 49)" if rule_ok else "ОТСУТСТВУЕТ — SSH может разорваться!"
        _box_row(f"  ip rule: {col}{lbl}{NC}")
    else:
        _box_warn("SSH-клиент IP не определён — защита не применена.")
    _box_row(f"  Cron (@reboot): {(GREEN+'активен'+NC) if cron_p.exists() else (YELLOW+'отсутствует'+NC)}")
    _box_bottom()


def _awg_diagnostic_all_nodes(state: dict) -> None:
    """Диагностика всех AWG-нод. Вызывается из do_full_diagnostic()."""
    nodes = state.get("awg_nodes", [])
    active_idx = state.get("awg_active_node_index", 0)
    if not nodes:
        nodes = [{
            "interface":   state.get("awg_interface", "awg0"),
            "host":        state.get("awg_exit_host", ""),
            "fwmark":      state.get("awg_fwmark", 1000),
            "route_table": state.get("awg_route_table", 1000),
        }]
    _box_sep()
    _box_row(f"  {CYAN}AWG Multi-Node Диагностика ({len(nodes)} нод){NC}")
    for idx, node in enumerate(nodes):
        iface  = node.get("interface", f"awg{idx}")
        host   = node.get("host", "")
        fwmark = node.get("fwmark", 1000 + idx)
        rtable = node.get("route_table", 1000 + idx)
        mark = f" {GREEN}[ACT]{NC}" if idx == active_idx else ""
        r_link = subprocess.run(
            ["ip", "link", "show", iface], capture_output=True, text=True, check=False
        )
        iface_ok = r_link.returncode == 0
        iface_col = GREEN if iface_ok else RED
        _box_row(f"  Нода {idx} ({iface}){mark}: {iface_col}{'UP' if iface_ok else 'DOWN'}{NC}")
        r_rule = subprocess.run(["ip", "rule", "show"], capture_output=True, text=True, check=False)
        rule_ok = str(fwmark) in r_rule.stdout and str(rtable) in r_rule.stdout
        _box_row(f"    ip rule fwmark {fwmark}→table {rtable}: {(GREEN+'OK'+NC) if rule_ok else (RED+'MISSING'+NC)}")
        r_route = subprocess.run(
            ["ip", "route", "show", "table", str(rtable)],
            capture_output=True, text=True, check=False
        )
        _box_row(f"    ip route table {rtable}: {(GREEN+'OK'+NC) if 'default' in r_route.stdout else (RED+'MISSING'+NC)}")
        if host and iface_ok:
            r_ping = subprocess.run(
                ["ping", "-I", iface, "-c", "2", "-W", "3", "-q", host],
                capture_output=True, text=True, check=False
            )
            if r_ping.returncode == 0:
                for line in r_ping.stdout.splitlines():
                    if "rtt" in line or "avg" in line:
                        _box_row(f"    latency: {GREEN}{line.strip()}{NC}")
                        break
            else:
                _box_row(f"    latency: {RED}нет ответа{NC}")
    r_dc = subprocess.run(
        ["systemctl", "is-active", "dnscrypt-proxy"],
        capture_output=True, text=True, check=False
    )
    _box_row(
        f"  DNSCrypt-proxy: "
        f"{(GREEN+'активен'+NC) if r_dc.stdout.strip() == 'active' else (YELLOW+'не активен'+NC)}"
    )
    ssh_ip = state.get("awg_ssh_client_ip", "") or _AWG_SSH_CLIENT_IP
    if ssh_ip:
        r_ssh = subprocess.run(["ip", "rule", "show"], capture_output=True, text=True, check=False)
        ssh_ok = f"from {ssh_ip}" in r_ssh.stdout
        _box_row(f"  SSH-защита ({ssh_ip}): {(GREEN+'OK'+NC) if ssh_ok else (RED+'ОТСУТСТВУЕТ'+NC)}")


def _prompt_awg_additional_nodes() -> None:
    """
    Задаёт вопрос о добавлении дополнительных AWG-нод.
    Вызывается из prompt_awg_exit_mode() после success("Параметры AWG сохранены").
    """
    global AWG_NODES, AWG_ACTIVE_NODE_INDEX

    node0: dict = {
        "host":            AWG_EXIT_HOST,
        "port":            AWG_EXIT_PORT,
        "pubkey":          "",
        "preshared_key":   "",
        "interface":       "awg0",
        "client_ip":       "10.66.0.2/32",
        "server_ip":       "10.66.0.1/32",
        "client_ip_v6":    "fd66:0::2/128",
        "server_ip_v6":    "fd66:0::1/128",
        "subnet_v4":       "10.66.0.0/24",
        "subnet_v6":       "fd66:0::/48",
        "fwmark":          1000,
        "route_table":     1000,
        "status":          "unknown",
        "last_check":      "",
        "ssh_auth_method": AWG_SSH_AUTH_METHOD,
    }
    AWG_NODES = [node0]

    print()
    _box_top("Дополнительные AWG exit-ноды (Multi-Node Failover)")
    _box_row(f"  {DIM}Нода 0 уже добавлена: {AWG_EXIT_HOST}:{AWG_EXIT_PORT}{NC}")
    _box_row()
    _box_row(f"  {CYAN}Хотите добавить ещё одну или несколько exit-нод?{NC}")
    _box_row(f"  {DIM}При падении активной ноды watchdog автоматически переключится.{NC}")
    _box_bottom()

    while True:
        try:
            ans = input(f"  {CYAN}Добавить ещё одну AWG exit-ноду? [y/N]:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break
        if ans not in ("y", "yes", "д", "да"):
            break

        n = len(AWG_NODES)
        subnets = _awg_node_subnets(n)
        print()
        _box_top(f"AWG Exit-нода №{n} (awg{n})")
        _box_row(f"  {DIM}IPv4: {subnets['subnet_v4']}  IPv6: {subnets['subnet_v6']}{NC}")
        _box_row(f"  {DIM}fwmark/table: {subnets['fwmark']}/{subnets['route_table']}{NC}")
        _box_bottom()

        new_host = ""
        while not new_host:
            try:
                new_host = input(f"  {CYAN}[N{n}-1] IP зарубежного VPS для ноды {n}:{NC} ").strip()
            except KeyboardInterrupt:
                break
        if not new_host:
            break

        raw_port = ""
        try:
            raw_port = input(f"  {CYAN}[N{n}-2] UDP-порт [{AWG_EXIT_PORT}]:{NC} ").strip()
        except KeyboardInterrupt:
            pass
        new_port = int(raw_port) if raw_port.isdigit() else AWG_EXIT_PORT

        new_ssh_method = AWG_SSH_AUTH_METHOD
        new_ssh_password = ""
        try:
            ssh_ans = input(
                f"  {CYAN}[N{n}-3] SSH-аутентификация (1=ключ, 2=пароль):{NC} "
            ).strip()
            if ssh_ans == "2":
                new_ssh_method = "password"
                new_ssh_password = getpass.getpass(f"  Пароль для root@{new_host}: ")
        except KeyboardInterrupt:
            pass

        AWG_NODES.append({
            **subnets,
            "host":            new_host,
            "port":            new_port,
            "pubkey":          "",
            "preshared_key":   "",
            "status":          "unknown",
            "last_check":      "",
            "ssh_auth_method": new_ssh_method,
            "ssh_password":    new_ssh_password,
        })
        success(f"   Нода {n} добавлена: {new_host}:{new_port}/udp  ({subnets['interface']})")

        try:
            more = input(f"  {CYAN}Добавить ещё одну ноду? [y/N]:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break
        if more not in ("y", "yes", "д", "да"):
            break

    AWG_ACTIVE_NODE_INDEX = 0
    total = len(AWG_NODES)
    if total > 1:
        success(f"AWG Multi-Node: {total} нод(ы) настроено (failover включён)")
    else:
        info("AWG: одна нода (стандартный режим)")


def _awg_emergency_restore_all_nodes() -> None:
    """Аварийное восстановление всех AWG-нод из state.json."""
    global AWG_NODES, AWG_ACTIVE_NODE_INDEX, _AWG_SSH_CLIENT_IP

    if not STATE_FILE.exists():
        warn("AWG Emergency: state.json не найден")
        return
    try:
        st = json.loads(STATE_FILE.read_text())
    except Exception as e:
        warn(f"AWG Emergency: ошибка чтения state.json: {e}")
        return

    nodes = st.get("awg_nodes", [])
    if not nodes:
        warn("AWG Emergency: awg_nodes пустой — одиночный режим")
        return

    AWG_NODES = nodes
    AWG_ACTIVE_NODE_INDEX = st.get("awg_active_node_index", 0)
    _AWG_SSH_CLIENT_IP = st.get("awg_ssh_client_ip", "")

    info(f"AWG Emergency: восстанавливаем {len(nodes)} нод(ы)...")
    _ensure_ssh_protection()

    try:
        xray_uid = pwd.getpwnam("xray").pw_uid
    except KeyError:
        xray_uid = 0

    for idx, node in enumerate(nodes):
        iface = node.get("interface", f"awg{idx}")
        conf  = f"/etc/amnezia/amneziawg/{iface}.conf"

        if node.get("client_privkey") and node.get("server_pubkey"):
            try:
                Path(conf).write_text(_awg_client_conf_for_node(node))
                Path(conf).chmod(0o600)
                success(f"AWG Emergency: конфиг {conf} восстановлен")
            except Exception as e:
                warn(f"AWG Emergency: {conf}: {e}")
        else:
            warn(f"AWG Emergency: нода {idx} — ключи не найдены")

        svc = f"amneziawg-{iface}.service"
        unit_path = Path(f"/etc/systemd/system/{svc}")
        if not unit_path.exists():
            unit_path.write_text(_awg_systemd_unit_for_node(node, xray_uid))
            _run(["systemctl", "daemon-reload"], check=False, quiet=True)
            _run(["systemctl", "enable", svc], check=False, quiet=True)
            success(f"AWG Emergency: unit {svc} восстановлен")

        _up_impl = _awg_detect_implementation()
        _up_pfx  = f"WG_QUICK_USERSPACE_IMPLEMENTATION={_up_impl} " if _up_impl else ""
        _run(
            ["bash", "-c",
             f"AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
             f"{_up_pfx}$AWG_BIN up {conf}"],
            check=False, quiet=True
        )

    _awg_apply_policy_routing_all_nodes()
    success(f"AWG Emergency: завершено ({len(nodes)} нод)")


# === END PATCH v2: AWG MULTI-NODE ===


# (Auto-fallback — _auto_fallback_install, _auto_fallback_set_flag,
#  do_manage_auto_fallback — вынесены в vless_installer.modules.failover;
#  импорт — в верхней секции этого файла.)


# =============================================================================
#  МОДУЛЬ 9: TUI — ИНТЕРАКТИВНЫЙ ВВОД (stdlib curses, без зависимостей)
#
#  Не требует rich/textual. Реализует:
#    • tui_input()      — строка ввода с валидацией на лету
#    • tui_confirm()    — [Y/n] диалог с подсветкой
#    • tui_select()     — выбор из списка стрелками (↑↓ + Enter)
#    • tui_progress()   — прогресс-бар внутри рамки
#    • tui_form()       — многополевая форма с переходом Tab/Enter
#
#  Все функции graceful-деградируют на обычный input() если терминал не TTY
#  (например, при запуске из cron/pipe).
# tui_input/tui_confirm/tui_select/tui_progress/tui_form
# — перенесено в vless_installer/modules/tui.py
# =============================================================================
#  МОДУЛЬ 10: GEOIP БЛОКИРОВКА ВХОДЯЩИХ ЧЕРЕЗ IPTABLES (РЕЖИМ B)
#
#  Логика:
#    • Читает РФ-подсети из уже существующего ru_subnets_ripe.txt
#      (тот же файл, что использует split-tunnel модуль)
#    • Если файла нет — скачивает свежий список с RIPE NCC через
#      уже существующую функцию _fetch_ru_subnets_from_ripe()
#    • Применяет через iptables/ip6tables: DROP входящих на SERVER_PORT
#      с российских IP (ipset для эффективности, fallback на цепочку правил)
#    • Обновление через существующий systemd-таймер РФ подсетей
#      или отдельный cron
#    • Состояние хранится в /var/lib/xray-installer/ingress_geoip.json
# ingress_geoip — перенесено в vless_installer/modules/ingress_geoip.py
# INGRESS_* константы импортируются из модуля
# =============================================================================

# (do_mtu_tracepath_diag, _mtu_tracepath_one вынесены в
#  vless_installer.modules.mtu_tuning; импорт — в верхней секции этого файла.)


# =============================================================================
#  МОДУЛЬ: DPI-ДЕТЕКТОР  (v3.99)
#  Анализирует xray/error.log на паттерны активного зондирования:
#  - TLS Client Hello без SNI
#  - нестандартные TLS client_random
#  - повторные хендшейки с разными параметрами (fingerprint sweep)
#  - HTTP-запросы к Xray (не-TLS трафик на TLS-порт)
#  Забаненные IP интегрируются в существующий AutoBan (autoban.json)
# dpi_detector — перенесено в vless_installer/modules/dpi_detector.py
