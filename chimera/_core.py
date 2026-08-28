#!/usr/bin/env python3
# === main core ===
"""
VLESS + TCP + REALITY + xHTTP TLS — Ultimate Installer
Python 3.12+ port

Поддержка: Ubuntu 20.04/22.04/24.04, Debian 11/12/13
Режимы протокола: VLESS+TCP+REALITY | VLESS+xHTTP+TLS
Балансировка (Режим B): Round Robin | Least Ping | Least Load | Random
Новое в v3.99: AutoBan | CertBot Monitor | TTFB Test | Config Changelog | Telegram | Traffic Limits | Health Report | Migration | GeoIP Block | Audit

Версия проекта: см. chimera.__version__ (динамически, не хардкод).
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
from typing import Any, Optional
import getpass

# ── Модули v4.12.9 ──────────────────────────────────────────────────────────────
from chimera.modules.smoke_test      import smoke_test_xray
from chimera.modules.xray_safe_apply import xray_apply_with_smoke
from chimera.modules.nginx_watchdog  import (
    nginx_watchdog_install, nginx_watchdog_remove, do_manage_nginx_watchdog,
)
from chimera.modules.ipset_persist   import (
    ipset_save, ipset_restore_unit_install, ipset_restore_unit_remove,
    do_manage_ipset_persist,
)
from chimera.modules.ipban import do_manage_ipban
from chimera.modules.vk_bypass_menu import do_vk_bypass_menu
from chimera.modules.slipgate import do_slipgate_menu
from chimera.modules.naiveproxy import do_naiveproxy_menu
from chimera.modules.mieru import do_mieru_menu
from chimera.modules.webdav_tunnel import do_webdav_tunnel_menu
from chimera.modules.hybrid_addon import do_hybrid_addon_menu
from chimera.modules.ripe_file_age   import (
    check_ripe_file_age, ripe_file_age_banner,
)
from chimera.modules.cluster_ops import do_cluster_menu, load_exit_nodes
from chimera.modules.box_renderer import (
    _get_box_width, _plain, _wcslen,
    _box_line_top, _box_line_sep, _box_line_bot,
    _box_row, _box_row_auto, _box_link, _box_top, _box_sep, _box_bottom,
    _box_item, _box_item_exit, _box_back, _box_desc,
    _box_wrap_msg, _box_info, _box_warn, _box_ok, _box_dim, _box_input,
    _submenu_header, _submenu_item, _submenu_back,
)
import chimera.modules.box_renderer as _br
_BOX_W = _br._BOX_W  # алиас для совместимости с кодом в _core.py
from chimera.modules.logrotate  import do_manage_logrotate
from chimera.modules.dns_rules         import do_manage_dns_rules
from chimera.modules.fingerprint_manager import (
    XRAY_FP_LIST  as _FM_FP_LIST,
    prompt_fingerprint as _fm_prompt_fingerprint,
)
from chimera.modules.dnscrypt_selector import do_dnscrypt_selector_menu
from chimera.modules.dnscrypt_advanced import do_dnscrypt_advanced_menu
from chimera.modules.honeypot      import do_manage_honeypot
from chimera.modules.fail2ban_manager import do_manage_fail2ban
from chimera.modules.scheduler     import render_scheduler_menu
from chimera.modules.warp          import do_manage_warp
from chimera.modules.smart_balancer import (
    do_manage_smart_balancer, _smart_balancer_run_once,
    PROBE_INTERVAL_MIN,
    _AUTO_FALLBACK_CRON, _AUTO_FALLBACK_SCRIPT, _AUTO_FALLBACK_LOGFILE,
    _AWG_WATCHDOG_CRON, _AWG_WATCHDOG_SCRIPT, _AWG_WATCHDOG_LOG, _AWG_WATCHDOG_STATE,
    _awg_guard_cron,
)
from chimera.modules.health import (
    health_check_xray, health_check_nginx, health_check_ssl,
    health_check_ports, run_full_health_check, do_check_tls_cert,
    HEALTH_CHECK_FILE,
)
from chimera.modules.dpi_detector import do_manage_dpi_detector, _dpi_run_once, _pinned_node_check_and_fallback
from chimera.modules.ingress_geoip import (
    do_manage_ingress_geoip,
    _ingress_state_load, _ingress_enable, _ingress_remove,
    INGRESS_CRON_FILE, INGRESS_CRON_SCRIPT,
    INGRESS_GEOIP_FILE, INGRESS_IPSET_NAME, INGRESS_IPSET6_NAME, INGRESS_LOG,
)
from chimera.modules.tui        import (
    tui_input, tui_confirm, tui_select, tui_progress, tui_form,
)
# ── Модули фрагментации v4.12 ─────────────────────────────────────────────────
from chimera.modules.fragment_config     import do_fragment_config_menu
from chimera.modules.fragment_fuzzer     import do_fragment_fuzzer_menu
from chimera.modules.fragment_log_viewer import do_fragment_log_viewer_menu
from chimera.modules.fragment_link       import do_fragment_link_menu
from chimera.modules.fragment_presets    import do_fragment_presets_menu
from chimera.modules.fragment_guide      import do_fragment_guide_menu
from chimera.modules.fragment_noise      import do_fragment_noise_menu
from chimera.modules.fragment_mux        import do_fragment_mux_menu
from chimera.modules.fragment_watchdog   import do_fragment_watchdog_menu
from chimera.modules.fragment_stats      import do_fragment_stats_menu
from chimera.modules.fragment_share      import do_fragment_share_menu
# ── Server-side TLS fragmentation (v4.21 — anti-DPI symmetry) ────────────────
from chimera.modules.server_fragment     import (
    do_server_fragment_menu,
    server_fragment_reapply_after_rebuild,
    server_fragment_status,
)
from chimera.modules.port_hopping        import do_port_hopping_menu, ph_status
from chimera.modules.tg_bot              import do_tg_bot_menu, do_manage_telegram, _tg_notify_event, _tg_load, tg_send
from chimera.modules.tg_client_bot       import do_tg_client_bot_menu
from chimera.modules.dns_redirect        import do_manage_dns_redirect, health_check_dns_redirect
# ── DNS-leak fix (/etc/resolv.conf auto-repair) ─────────────────────────────
from chimera.modules.resolv_conf_fix     import (
    do_fix_resolv_conf_interactive,
    fix_resolv_conf_to_localhost,
    rollback_resolv_conf,
    diagnose_resolv_conf,
)
# ── Hysteria2 transport (аддитивно, v4.12.9+) ────────────────────────────────
from chimera.modules.hysteria2_menu      import do_hysteria2_menu
# ── Новые модули (бэкап, cold boot, health monitor) ──────────────────────────
from chimera.modules.config_backup       import backup_xray_config, do_backup_menu
from chimera.modules.cold_boot_restore   import do_cold_boot_menu
from chimera.modules.node_health_monitor import do_health_monitor_menu
# ── Новые модули (DPI-цензура снаружи + бенчмарк сервера) ────────────────────
from chimera.modules.dpi_censor_check    import do_dpi_censor_check_menu
from chimera.modules.network_bench       import do_network_bench_menu
# ── Tier-1 рефакторинг: ASN cache + IP→ASN lookup ────────────────────────────
from chimera.modules.asn_cache import (
    ASN_CACHE_DB, ASN_CACHE_MAX_AGE_DAYS,
    _asn_cache_connect, _asn_cache_save, _asn_cache_load,
    _asn_cache_delete, _asn_cache_info,
    _lookup_asn, _fmt_asn_short,
)
# ── Tier-1 рефакторинг: Standalone UI-экраны ─────────────────────────────────
from chimera.modules.standalone_screens import (
    check_exit_geo, do_view_logs, do_check_domain_external, do_system_dashboard,
)
# ── Tier-1 рефакторинг: Fail2ban + Xray watchdog ─────────────────────────────
from chimera.modules.fail2ban_setup import (
    FAIL2BAN_CONF, _WATCHDOG_TIMER, _WATCHDOG_SERVICE, _WATCHDOG_SCRIPT,
    setup_fail2ban, _watchdog_install, _watchdog_remove, do_manage_watchdog,
)
# ── Tier-1 рефакторинг: SSH hardening ────────────────────────────────────────
from chimera.modules.ssh_hardening import (
    _SSHD_CONFIG, _SSHD_BACKUP, _ssh_2fa_install, do_ssh_hardening,
)
# ── Tier-1 рефакторинг: фундаментальные хелперы (resources) ──────────────────
from chimera.modules.resources import (
    _get_total_ram_mb, _get_total_cpu,
    gen_uuid, gen_hex, gen_spiderx,
    get_server_ip, country_flag_emoji,
    get_server_country, get_server_country_cached,
    get_adaptive_value, generate_self_signed_cert,
)
# ── Tier-1 рефакторинг: MTU/MSS тюнинг + tracepath-диагностика ───────────────
from chimera.modules.mtu_tuning import (
    _MTU_STATE_FILE,
    _mtu_probe, _mtu_get_iface, _mtu_apply, _mtu_remove_rules,
    _mtu_state_load, _mtu_state_save,
    do_mtu_tuning, _mtu_persist,
    do_mtu_tracepath_diag, _mtu_tracepath_one,
)
# ── Tier-1 рефакторинг: GeoIP-блокировка + аудит подключений ─────────────────
from chimera.modules.geoip_block import (
    do_manage_geoip_block,
    _geoip_block_get_rules, _geoip_apply_routing,
    _geoip_set_allowlist, _geoip_add_country_block, _geoip_add_scanner_block,
    _geoip_remove_all,
)
from chimera.modules.connection_audit import (
    do_connection_audit,
    _parse_access_log,
    _audit_user_summary, _audit_recent_connections,
    _audit_suspicious, _audit_active_now,
)
# ── Tier-2 рефакторинг: Backup/rollback/unit tests/connectivity ──────────────
from chimera.modules.backup_rollback import (
    create_backup, perform_rollback, run_unit_tests, verify_connectivity,
)
# ── Tier-2 рефакторинг: DNSCrypt setup ───────────────────────────────────────
from chimera.modules.dnscrypt_setup import (
    _get_dnscrypt_port, install_dnscrypt, apply_dnscrypt_tuning,
)
# ── Tier-2 рефакторинг: Networking / sysctl / firewall ───────────────────────
from chimera.modules.network_setup import (
    configure_firewall, apply_network_optimizations, apply_sysctl_and_limits,
)
# ── Tier-2 рефакторинг: GeoIP/GeoSite files ──────────────────────────────────
from chimera.modules.geo_files import (
    download_geo_files, setup_geo_autoupdate, do_manage_geo_update,
)
# ── Tier-2 рефакторинг: SSL / certbot ────────────────────────────────────────
from chimera.modules.ssl_certbot import (
    _CERTBOT_MONITOR_CRON, _CERTBOT_MONITOR_SCRIPT,
    obtain_ssl_cert, fix_letsencrypt_permissions,
    ensure_cert_fix_script, setup_cert_renewal,
    _certbot_renew_and_notify, _certbot_install_monitor_cron,
    do_manage_certbot_monitor,
)
# ── Tier-2 рефакторинг: Failover + auto-fallback ─────────────────────────────
from chimera.modules.failover import (
    _FAILOVER_LOG, _FAILOVER_SCRIPT, _FAILOVER_CRON, _FAILOVER_STATE,
    _failover_load, _failover_save, _failover_install, do_failover_status,
    _auto_fallback_install, _auto_fallback_set_flag, do_manage_auto_fallback,
)
# ── Tier-2 рефакторинг: Client config export + share + uninstall ─────────────
from chimera.modules.client_config_export import (
    do_generate_client_config, do_export_client_config, do_share_config_server,
)
from chimera.modules.uninstall import do_uninstall
# ── Tier-2 рефакторинг: TTL users + blocked ──────────────────────────────────
from chimera.modules.ttl_users import (
    TTL_FILE, TTL_CRON_SCRIPT, TTL_CRON_FILE, TTL_LOG, BLOCKED_FILE,
    _ttl_load, _ttl_save, _ttl_expires_str, _ttl_is_expired,
    _ttl_expires_within_hours, _ttl_set, _ttl_remove,
    _blocked_load, _blocked_save, _ttl_block_user, _ttl_unblock_user,
    _ttl_is_blocked, _ttl_check_and_expire, _ttl_install_cron,
    _ttl_remove_cron, _ttl_cron_active, do_manage_ttl_users,
)
# ── Tier-2 рефакторинг: Key & credential rotation ────────────────────────────
from chimera.modules.credential_rotation import (
    _UUID_CRON_TAG, _UUID_CRON_SCRIPT,
    _uuid_rotate_now, _uuid_install_cron, do_manage_uuid_rotation,
    _rotate_reality_keys, do_manage_reality_keys, _menu_rotation,
)
# ── Tier-2 рефакторинг: Health report + traffic tracking ─────────────────────
from chimera.modules.health_report import (
    do_health_report, _health_report_install_cron, do_manage_health_report,
)
from chimera.modules.traffic_tracking import (
    TRAFFIC_LIMITS_FILE,
    _limits_load, _limits_save, _query_user_traffic_bytes,
    _stats_api_is_configured, _check_traffic_limits_once,
    do_manage_traffic_limits,
)
# ── Tier-3 рефакторинг: System / startup / package manager ───────────────────
from chimera.modules.system_deps import (
    _CMD_TO_PKG, _PKG_TO_CMDS,
    _init_pkg_mgr, _pkg_install, _pkg_update,
    _find_pkg_for_missing_cmd, _smart_recover,
    _wait_apt_lock_startup, ensure_startup_dependencies,
)
# ── Tier-3 рефакторинг: Nginx / sites ────────────────────────────────────────
from chimera.modules.nginx_setup import (
    setup_nginx_rate_limit, create_website,
    _create_techhub, _create_nexcloud, _create_simple_site,
    _ensure_nginx_sites_enabled_include,
    setup_nginx_temp, setup_nginx_final, setup_nginx_systemd_override,
)
# ─────────────────────────────────────────────────────────────────────────────
# ── Tier-3 рефакторинг: RU subnets + AS-direct routing ───────────────────────
from chimera.modules.ru_subnets import (
    RU_SUBNETS_FILE, RU_SUBNETS_TIMER, RU_SUBNETS_SERVICE,
    RIPE_DELEGATED_URL, RIPE_DELEGATED_URL_MIRROR, _RU_SUBNET_RULE_COMMENT,
    _fetch_ru_subnets_from_ripe, _ru_subnets_apply_to_xray,
    _ru_subnets_remove_from_xray, _ru_subnets_install_timer,
    _ru_subnets_remove_timer, _ru_subnets_cli_update,
    do_manage_ru_subnet_direct, _ru_subnets_restore_if_needed,
)
from chimera.modules.as_direct import (
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
from chimera.modules.autoban import (
    _XRAY_BAN_STATE, _XRAY_BAN_CRON, _XRAY_BAN_SCRIPT, _XRAY_BAN_LOG,
    _XRAY_BAN_REPORT, _BAN_THRESHOLD_DEFAULT, _BAN_WINDOW_MINUTES,
    _BAN_WHITELIST_DEFAULT, _BAN_REPORT_TTL_DAYS,
    _ban_report_rotate, _ban_report_append, _ban_report_show_in_box,
    _autoban_load, _autoban_save, _autoban_get_chain_ips,
    _autoban_run_once, _autoban_install_cron, do_manage_autoban,
)
# ── Tier-3 рефакторинг: Backup manager + status + speed + reconfig + mode ────
from chimera.modules.backup_manager import (
    _SCHEDULED_BACKUP_CRON, _scheduled_backup_run, do_manage_scheduled_backup,
)
from chimera.modules.speed_test import do_speed_test
from chimera.modules.reconfigure import do_reconfigure
from chimera.modules.migration import (
    do_full_migration_export, do_full_migration_import,
)
from chimera.modules.quick_status import (
    _STATS_SORT_KEYS, _TTFB_TARGETS,
    do_quick_status, do_connection_quality_test,
)
from chimera.modules.switch_mode import switch_mode_ab
from chimera.modules.traffic_history import (
    TRAFFIC_HISTORY_FILE,
    _traffic_snapshot_save, _install_traffic_snapshot_cron, do_traffic_history,
)
# ── Tier-3 рефакторинг: Split tunnel ─────────────────────────────────────────
from chimera.modules.split_tunnel import (
    prompt_split_tunnel, _save_split_tunnel_custom, _load_split_tunnel_custom,
    build_split_tunnel_routing_rules, _xray_count_ru_subnet_rules,
    _show_xray_routing_rules, do_manage_split_tunnel,
    _apply_split_tunnel_config_from_state,
)
# ── Tier-4 рефакторинг: Diagnostics engine ───────────────────────────────────
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
# ── Tier-4 рефакторинг: Xray install / update / geo / config ─────────────────
from chimera.modules.xray_install import (
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
from chimera.modules.install_prompts import (
    prompt_parameters, prompt_install_mode, prompt_protocol_mode,
    prompt_awg_exit_mode,
)
# ── Tier-4 рефакторинг: Users manager ────────────────────────────────────────
from chimera.modules.users_manager import (
    _users_load, _users_save, _users_get_config, _users_apply_config,
    _users_apply_to_config, _users_patch_config_no_restart, _users_gen_link,
    do_user_list, do_user_add, do_user_delete,
    do_user_show_link_ios_by_uuid,
    _show_qr, _gen_vless_link, generate_client_links, generate_client_links_ios,
    _unified_load_users, _unified_save_users, _unified_show_links,
    _do_user_stats_screen, _do_user_stats_screen_v2,
)
# ── Tier-4 рефакторинг: Emergency repair ─────────────────────────────────────
from chimera.modules.emergency_repair import do_emergency_repair
# ── Tier-4 рефакторинг: AWG transport (Mode B) ───────────────────────────────
from chimera.modules.awg_transport import (
    awg_check_tool, awg_generate_keys, awg_install_local,
    _awg_install_go_version_binary_only, _awg_install_go_version,
    _awg_detect_implementation, _awg_create_userspace_stubs,
    _awg_server_conf_text, _awg_client_conf_text, _awg_systemd_unit_text,
    ensure_amneziawg_ready, awg_setup_local_client, awg_apply_policy_routing,
    _awg_ensure_sshpass, awg_setup_remote_server,
    _awg_print_manual_guide, awg_rollback, awg_verify_tunnel,
    _awg_cleanup_stale_interfaces, awg_full_setup,
    awg_watchdog_install, awg_watchdog_remove, _awg_watchdog_set_flag,
    do_manage_awg_watchdog,
    _awg_node_subnets, _awg_persist_ssh_exclusion, _awg_node_from_globals,
    _awg_load_nodes_from_state, _awg_save_nodes_to_state,
    _awg_client_conf_for_node, _awg_server_conf_for_node,
    _awg_systemd_unit_for_node, awg_setup_all_nodes,
    _awg_bring_up_all_tunnels, _awg_apply_policy_routing_all_nodes,
    _awg_verify_all_tunnels, awg_multinode_watchdog_install,
    do_manage_awg_nodes, _awg_manual_switch, _awg_ping_all_nodes,
    _awg_show_failover_log, _awg_show_ssh_protection_status,
    _awg_diagnostic_all_nodes, _prompt_awg_additional_nodes,
    _awg_emergency_restore_all_nodes,
)
# ── Tier-4 рефакторинг: Chain/Nodes (Mode B) ─────────────────────────────────
from chimera.modules.chain_nodes import (
    prompt_chain_params, _prompt_balancer_strategy, prompt_chain_params_multi,
    generate_xray_config_chain_entry, _make_exit_node_config,
    generate_xray_config_chain_exit, do_generate_chain_exit_additional_client,
    _nodes_from_state, _load_chain_nodes_from_state, _save_chain_nodes_to_state,
    _prompt_one_node, _prompt_one_node_from_link, _fix_node_fields,
    _prompt_one_node_manual, _h2_reapply_transport_if_active,
    generate_xray_config_chain_entry_multi, do_manage_nodes,
    generate_chain_summary, _speed_test_node_latency, _speed_test_node_geo,
    _access_log_bytes_per_node, do_node_health_matrix,
)
# ── Веб-панель + REST API + User Portal ──────────────────────────────────────
from chimera.modules.rest_api import do_manage_web_panel
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
LOG_FILE          = Path("/var/log/chimera.log")
# Legacy-путь лога до переименования в Chimera Project (v4.x).
# Если у пользователя установка была сделана старой версией — логи писались сюда.
# При первом запуске Chimera Project v5.0+ создаём symlink, чтобы:
#   - администратор мог найти старые логи по привычному пути
#   - cron-задачи со старым путём в команде продолжали работать
#   - logrotate-конфиги со старым путём продолжали ротировать
_LEGACY_LOG_FILE  = Path("/var/log/vless-install.log")
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

# Создаём symlink legacy-лога → новый лог, если:
#   - старого файла нет (свежая установка) — symlink создаётся сразу
#   - старый файл существует и это regular file (не symlink) — переносим содержимое
#     в новый лог, затем заменяем старый файл на symlink
#   - старый файл уже symlink — ничего не делаем (already migrated)
try:
    if _LEGACY_LOG_FILE.is_symlink():
        pass  # уже мигрировано
    elif _LEGACY_LOG_FILE.exists() and _LEGACY_LOG_FILE.is_file():
        # Старый лог существует как regular file — переносим содержимое
        if not LOG_FILE.exists() or LOG_FILE.stat().st_size == 0:
            # Новый лог пуст — переносим старое содержимое
            import shutil as _shutil_for_log
            _shutil_for_log.copy2(str(_LEGACY_LOG_FILE), str(LOG_FILE))
        # Делаем backup старого лога (на всякий случай), затем заменяем на symlink
        _backup_legacy = _LEGACY_LOG_FILE.with_suffix('.log.pre-chimera.bak')
        if not _backup_legacy.exists():
            _LEGACY_LOG_FILE.rename(_backup_legacy)
        else:
            _LEGACY_LOG_FILE.unlink()
        _LEGACY_LOG_FILE.symlink_to(str(LOG_FILE))
    else:
        # Старого файла нет — просто создаём symlink
        if not _LEGACY_LOG_FILE.exists():
            _LEGACY_LOG_FILE.symlink_to(str(LOG_FILE))
except (OSError, PermissionError):
    # symlink может не сработать без root или на некоторых FS — не критично
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


# ── Динамическая версия проекта ──────────────────────────────────────────────
# Берётся из chimera.__version__ (defined в __init__.py).
# Кэшируется после первого вызова в _CACHED_VERSION, чтобы не импортировать
# повторно при каждом вызове _get_version() (баннер/лог/меню вызываются часто).
# По той же схеме работает honeypot.py и main.py — при бампе версии в
# __init__.py все три файла автоматически подхватывают новое значение.
_CACHED_VERSION: str = ""

def _get_version() -> str:
    """Возвращает версию проекта из chimera.__version__.
    При первом вызове — импортирует и кэширует. При ошибке — fallback "unknown".
    """
    global _CACHED_VERSION
    if _CACHED_VERSION:
        return _CACHED_VERSION
    try:
        from chimera import __version__ as _v
        _CACHED_VERSION = _v
    except Exception:
        _CACHED_VERSION = "unknown"
    return _CACHED_VERSION


log_to_file("INFO", f"=== Запуск Chimera Project v{_get_version()} ===")
log_to_file("INFO", f"Время начала: {datetime.now()}")

# =============================================================================
#  БАННЕР
# =============================================================================

# ── Поддержка цвета в терминале ──────────────────────────────────────────────
# Уважаем стандарт de-facto для современных CLI:
#   - NO_COLOR (https://no-color.org/) — явный запрет цвета
#   - TERM=dumb — терминал без ANSI
#   - не TTY (перенаправление в файл/пайп) — цвет только засоряет вывод
# На Windows 10 1607+ / Windows Terminal / PowerShell 7+ ANSI поддерживается
# из коробки без всякой инициализации, поэтому отдельный код не нужен.
_ANSI_RE = re.compile(r'\033\[[0-9;]*m')


def _ansi_supported() -> bool:
    """Возвращает True, если текущий stdout способен отображать ANSI-цвета."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    if not sys.stdout.isatty():
        return False
    return True


def _gradient_rgb(t: float) -> tuple:
    """Возвращает RGB-цвет (R,G,B) для параметра t ∈ [0.0, 1.0].
    Палитра: фиолетовый → голубой → зелёный → жёлтый → оранжевый → красный.
    Truecolor (24-bit) — поддерживается в Windows Terminal, PowerShell 7+,
    cmd.exe на Win10 1607+, iTerm2, GNOME Terminal, kitty и др.
    """
    # Контрольные точки палитры (R, G, B)
    stops = [
        (138,  43, 226),  # фиолетовый  (BlueViolet)
        ( 30, 144, 255),  # голубой     (DodgerBlue)
        (  0, 200, 120),  # зелёный
        (255, 215,   0),  # жёлтый      (Gold)
        (255, 140,   0),  # оранжевый   (DarkOrange)
        (220,  40,  60),  # красный     (Crimson)
    ]
    if t <= 0.0:
        return stops[0]
    if t >= 1.0:
        return stops[-1]
    seg = t * (len(stops) - 1)
    i = int(seg)
    frac = seg - i
    r1, g1, b1 = stops[i]
    r2, g2, b2 = stops[i + 1]
    return (
        int(r1 + (r2 - r1) * frac),
        int(g1 + (g2 - g1) * frac),
        int(b1 + (b2 - b1) * frac),
    )


def _colorize_gradient(text: str) -> str:
    """Применяет горизонтальный truecolor-градиент к строке.
    Каждый символ получает свой цвет по позиции. Если цвет не поддерживается —
    возвращает строку как есть.
    """
    if not _ansi_supported() or not text:
        return text
    out = []
    n = len(text) - 1
    for i, ch in enumerate(text):
        t = i / n if n > 0 else 0.0
        r, g, b = _gradient_rgb(t)
        out.append(f"\033[38;2;{r};{g};{b}m{ch}")
    out.append("\033[0m")
    return "".join(out)


def _visible_len(s: str) -> int:
    """Длина строки без учёта ANSI escape-последовательностей."""
    return len(_ANSI_RE.sub('', s))


def _make_banner(show_ram_warning: bool = True) -> str:
    _OW = 67   # внутренняя ширина внешней рамки (CHIMERA ansi_shadow art=54, info=59 → max+pad)
    _IW = _OW - 6  # внутренняя ширина вложенной рамки (61)
    _blank  = "║" + " " * _OW + "║"
    _top    = "╔" + "═" * _OW + "╗"
    _bot    = "╚" + "═" * _OW + "╝"
    _itop   = "║  ╔" + "═" * _IW + "╗  ║"
    _ibot   = "║  ╚" + "═" * _IW + "╝  ║"

    def _art(a):
        # Применяем градиент к ASCII-арту CHIMERA. После этого строка
        # содержит ANSI-коды, поэтому длину считаем по видимым символам.
        colored = _colorize_gradient(a)
        pad = _OW - 2 - _visible_len(colored)
        return "║  " + colored + " " * max(pad, 0) + "║"

    def _irow(t):
        return "║  ║ " + t + " " * (_OW - 8 - len(t)) + " ║  ║"
    _art_lines = [
        " ██████╗██╗  ██╗██╗███╗   ███╗███████╗██████╗  █████╗ ",
        "██╔════╝██║  ██║██║████╗ ████║██╔════╝██╔══██╗██╔══██╗",
        "██║     ███████║██║██╔████╔██║█████╗  ██████╔╝███████║",
        "██║     ██╔══██║██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║",
        "╚██████╗██║  ██║██║██║ ╚═╝ ██║███████╗██║  ██║██║  ██║",
        " ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝",
    ]
    _info_lines = [
        f"Chimera Project — Multi-Protocol Anti-DPI Installer v{_get_version()}",
        "VLESS · Hysteria2 · AmneziaWG · TrustTunnel · MTProto",
        "NaiveProxy · Mieru · FPTN · Slipgate · WARP · WDTT · +more",
        "Anti-DPI: REALITY · xHTTP · Fragmentation · Port Hopping",
        "Cluster: RoundRobin · LeastPing · LeastLoad · Failover A↔B",
        "Dashboard · REST API · TG Bot · Admin Panel · User Portal",
    ]
    # Строки предупреждения о RAM (красные + жирные через ANSI)
    _BOLD_RED = '\033[1;31m'
    _NC_LOC   = '\033[0m'
    _ram_lines = [
        f"{_BOLD_RED}⚠  ВНИМАНИЕ: для корректной работы всех функций     {_NC_LOC}",
        f"{_BOLD_RED}⚠  рекомендуется ОЗУ VPS от 2 ГБ!                   {_NC_LOC}",
        f"{_BOLD_RED}⚠  При меньшем объёме работа скрипта и ПО            {_NC_LOC}",
        f"{_BOLD_RED}⚠  НЕ ГАРАНТИРУЕТСЯ.                                 {_NC_LOC}",
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
# FAIL2BAN_CONF is now imported from chimera.modules.fail2ban_setup (see top of file).
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

# (_get_total_ram_mb, _get_total_cpu вынесены в chimera.modules.resources;
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
# Email/имя администратора — спрашиваются при установке (install_prompts.py
# [1/12]/[2/12]). Используются в users.json (email + name), User Portal,
# Admin Panel, QR-кодах, подписке. Раньше создавался безымянный дефолтный
# юзер с email из PARAM_EMAIL (LE-email) — это путало админов при удалении
# и замене. PARAM_EMAIL остаётся для LE, отдельно — PARAM_USER_EMAIL для
# идентификации юзера.
PARAM_USER_EMAIL:      str  = ""
PARAM_USER_NAME:       str  = ""
PARAM_SPIDERX:         str  = ""
PARAM_SOCKET_PATH:     str  = ""
PARAM_REALITY_DEST:    str  = ""   # dest/sni для REALITY при AWG-транспорте (чужой сайт, напр. www.cloudflare.com)
PARAM_DOMAIN_STRATEGY: str  = ""
PARAM_SITE_TEMPLATE:   str  = "0"   # индекс шаблона сайта (0-15), дефолт "0" — должен быть int-конвертируемой строкой
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

# AdGuard Home globals (DNS-сервер :53 поверх DNSCrypt — см. modules/aghome_setup.py)
AGHOME_BIN           = Path("/usr/local/bin/AdGuardHome")
AGHOME_WORK_DIR      = Path("/opt/AdGuardHome")
AGHOME_CONF          = AGHOME_WORK_DIR / "AdGuardHome.yaml"
AGHOME_SERVICE       = Path("/etc/systemd/system/AdGuardHome.service")
AGHOME_WEB_PORT:     int = 3000    # Web UI (plain HTTP, loopback/публично)
AGHOME_DNS_PORT:     int = 53      # DNS — AGH владеет :53
AGHOME_DOH_PORT:     int = 30443   # DoH + Web UI HTTPS (native TLS AGH)
AGHOME_DOT_PORT:     int = 853     # DoT (tcp) / DoQ (udp)
AGHOME_INSTALLED:    bool = False
PARAM_USE_AGHOME:    bool = False

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
# S3/S4 добавлены — нужны для полного набора AWG 2.0
# (Keenetic и др. строгие парсеры падают на отсутствии этих полей).
# По умолчанию 0 (как в bivlked), но теперь persist'ятся в state.
AWG_S3:   int = 0       # Under-load packet junk size (0-64)
AWG_S4:   int = 0       # Transport packet junk size (0-32)
AWG_H1:   int = 1       # Init packet magic header
AWG_H2:   int = 2       # Response packet magic header
AWG_H3:   int = 3       # Under load packet magic header
AWG_H4:   int = 4       # Transport packet magic header
# I1-I5 добавлены — опциональные decoy CPS-пакеты.
# I1 — hex-строка (48-64 hex символов при i1_mode=random), I2-I5 обычно пустые.
# По умолчанию пустые строки — не пишутся в конфиг если непустые (см. _awg_*_conf_text).
AWG_I1:   str = ""      # Init packet junk allowed IP (hex)
AWG_I2:   str = ""      # Response packet junk allowed IP (hex)
AWG_I3:   str = ""      # Under-load packet junk allowed IP (hex)
AWG_I4:   str = ""      # Transport packet junk allowed IP (hex)
AWG_I5:   str = ""      # Transport packet junk IPv6 allowed IP (hex)
# Источник параметров обфускации — для диагностики при жалобах
# вроде "Keenetic не импортирует" (zvshka-кейс). Возможные значения:
#   "preset:tele2_krasnoyarsk" | "preset:default" | ... (готовый пресет)
#   "manual"  (пользователь ввёл параметры вручную через _awgs_menu_custom_params)
#   "auto_full"  (авто-генерация через awgs_generate_full_manual_params)
#   "default"  (старый хардкод 4/40/70/0/0/1/2/3/4 — для обратной совместимости
#               с установками до введения полного набора параметров)
AWG_OBFUSCATION_SOURCE: str = "default"
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

# YouTube routing toggle (youtube_route.py).
# True = весь YouTube-трафик выходит через RU entry-ноду (outbound: direct
#       или direct-local в AWG-режиме). Правило geosite:youtube → direct
#       prepended в routing.rules.
# False = (default) YouTube идёт через каскад exit-нод (catch-all routing).
# Derived/legacy: True когда youtube_route_target=="ru" (state["youtube_via_ru"]).
# Основной ключ — state["youtube_route_target"] (str: "ru"|"off"|"chain-exit-N"),
# управляется через youtube_route.py. Этот bool — для обратной совместимости.
YOUTUBE_VIA_RU: bool = False

# Режим работы xHTTP (только для PROTOCOL_MODE == "xhttp")
# "stream-up" | "stream-one" | "packet-up"
XHTTP_MODE: str = "stream-up"

# Порт прослушивания Xray (общий для REALITY и xHTTP, по умолчанию 443)
# Пользователь может выбрать любой порт 1–65535 при установке.
SERVER_PORT: int = 443
XHTTP_PORT:  int = 443   # backward-compat alias, всегда == SERVER_PORT

# Loopback-порт Xray, на который Nginx проксирует xHTTP-трафик в режиме
# PROTOCOL_MODE == "xhttp". См. setup_nginx_final() / generate_xray_config_xhttp().
#
# Контекст: механизм fallbacks в Xray-core НЕ поддерживается для xHTTP
# (задокументированное ограничение XHTTP: Beyond REALITY). Поэтому заглушка
# реализуется схемой Nginx → Xray:
#   • Nginx терминирует TLS на SERVER_PORT (по умолч. 443), отдаёт сайт-заглушку
#     для пути "/" и проксирует xhttp path на 127.0.0.1:XHTTP_BACKEND_PORT.
#   • Xray принимает xHTTP на loopback-порту с security: none (TLS не нужен —
#     трафик уже расшифрован Nginx).
# Это позволяет сохранить рабочий сайт-заглушку и прокси одновременно.
XHTTP_BACKEND_PORT: int = 8443

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
#   Применяется в основном для stream-up / stream-one / auto.
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

# ── CDN masking (профиль для обхода белых списков через Beeline CDN) ─────────
# Если True — активируется экспертный профиль XHTTP с расширенными extra-полями
# (xPaddingHeaders, session/seq keys, xmux.maxConcurrency=1 и т.д.) и
# одностраничная fake-login заглушка. Активируется только через скрытое меню
# (ввод кода доступа). Не затрагивает простой XHTTP-режим — это отдельный
# профиль, параллельный дефолтному.
XHTTP_CDN_MASKING: bool = False

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


# =============================================================================
#  GENERIC PORT-CONFLICT CHECK AGAINST OTHER PROTOCOL MODULES
# =============================================================================
# Реестр известных автономных протокол-модулей и их state-файлов.
# Используется check_port_used_by_other_protocol() для обнаружения конфликтов
# по порту между модулями (например: AWG standalone хочет UDP/51820, а
# Hysteria2 уже слушает UDP/51820 — нужно явно сообщить пользователю).
#
# Структура записи:
#   "proto_key": {
#       "label":      "человекочитаемое имя протокола",
#       "state_file": Path — путь к JSON state-файлу модуля,
#       "extractor":  функция(state_dict) -> list[int] портов, которые
#                     этот модуль слушает (внешние, не loopback).
#                     Возвращает [] если модуль не установлен или
#                     state-файл отсутствует/битый.
#   }
# Если state_file хранится внутри общего state.json (например hysteria2),
# extractor получает весь state.json, а не отдельный файл.

def _extract_hysteria2_ports(st: dict) -> list:
    """Порты Hysteria2: firewall.udp_ports + fallback_ports + exit_nodes[].ports.
    Hysteria2 хранит свой state внутри общего state.json под ключом 'hysteria2'."""
    h2 = st.get("hysteria2", {}) if isinstance(st, dict) else {}
    if not h2:
        return []
    ports = []
    fw = h2.get("firewall", {}) or {}
    ports.extend(fw.get("udp_ports", []) or [])
    ports.extend(fw.get("fallback_ports", []) or [])
    for node in (h2.get("exit_nodes", []) or []):
        node_ports = node.get("ports", []) or []
        ports.extend(node_ports)
    # Фильтруем демоны/не-числа, уникализируем
    return sorted({int(p) for p in ports if isinstance(p, (int, str)) and str(p).isdigit()})


def _extract_mieru_ports(st: dict) -> list:
    """Mieru: state.json (m.json) — port_start..port_end диапазон (TCP или UDP).
    Возвращаем весь диапазон как набор портов."""
    if not isinstance(st, dict) or not st.get("installed"):
        return []
    start = st.get("port_start")
    end = st.get("port_end")
    if not (isinstance(start, int) and isinstance(end, int)):
        return []
    if end < start:
        start, end = end, start
    return list(range(start, end + 1))


def _extract_naiveproxy_ports(st: dict) -> list:
    """NaiveProxy: TCP-порт (HTTPS-обратный-прокси). state['port']."""
    if not isinstance(st, dict) or not st.get("installed"):
        return []
    p = st.get("port")
    return [int(p)] if isinstance(p, (int, str)) and str(p).isdigit() else []


def _extract_wdtt_ports(st: dict) -> list:
    """WDTT: dtls_port + wg_port (оба UDP)."""
    if not isinstance(st, dict) or not st.get("installed"):
        return []
    ports = []
    for k in ("dtls_port", "wg_port"):
        v = st.get(k)
        if isinstance(v, (int, str)) and str(v).isdigit():
            ports.append(int(v))
    return ports


def _extract_turntunnel_ports(st: dict) -> list:
    """TurnTunnel (FreeTurn): listen_port (UDP)."""
    if not isinstance(st, dict) or not st.get("installed"):
        return []
    p = st.get("listen_port")
    return [int(p)] if isinstance(p, (int, str)) and str(p).isdigit() else []


def _extract_turnable_ports(st: dict) -> list:
    """Turnable (vk-turn): listen_port (UDP)."""
    if not isinstance(st, dict) or not st.get("installed"):
        return []
    p = st.get("listen_port")
    return [int(p)] if isinstance(p, (int, str)) and str(p).isdigit() else []


def _extract_olcrtc_ports(st: dict) -> list:
    """OLCrtc: socks_port — это локальный loopback-порт для Xray listener.
    Внешних портов не открывает (туннели через публичные Jitsi/Телемост/WB).
    Возвращаем [] — конфликтов по внешним портам нет."""
    return []


def _extract_slipgate_ports(st: dict) -> list:
    """SlipGate: не имеет фиксированного порта — управляет DNS/HTTP-туннелями
    через внешний установщик. Внешние порты определяются конфигом туннеля,
    не module state. Возвращаем [] — формальный конфликт не детектируется."""
    return []


def _extract_fptn_ports(st: dict) -> list:
    """FPTN: TCP-порт (TLS-туннель). state['port']."""
    if not isinstance(st, dict) or not st.get("installed"):
        return []
    p = st.get("port")
    return [int(p)] if isinstance(p, (int, str)) and str(p).isdigit() else []


def _extract_trusttunnel_ports(st: dict) -> list:
    """TrustTunnel: TCP+UDP порт (HTTP/2 over TLS + HTTP/3 over QUIC).
    state['listen_port']."""
    if not isinstance(st, dict) or not st.get("installed"):
        return []
    p = st.get("listen_port")
    return [int(p)] if isinstance(p, (int, str)) and str(p).isdigit() else []


def _extract_csqtt_ports(st: dict) -> list:
    """CSQTT: UDP data_port + TCP web_port."""
    if not isinstance(st, dict) or not st.get("installed"):
        return []
    ports = []
    for k in ("data_port", "web_port"):
        v = st.get(k)
        if isinstance(v, (int, str)) and str(v).isdigit():
            ports.append(int(v))
    return ports


def _extract_subscription_ports(st: dict) -> list:
    """Chimera subscription endpoint: TCP-порт HTTPS-хендлера подписки.
    state['listen_port'] (default 8443). Условие: state['enabled'] is True."""
    if not isinstance(st, dict) or not st.get("enabled"):
        return []
    p = st.get("listen_port", 8443)
    return [int(p)] if isinstance(p, (int, str)) and str(p).isdigit() else []


def _extract_vless_state_ports(st: dict) -> list:
    """VLESS/REALITY основной state.json — порты xray/awg из Mode B chain.
    AWG_EXIT_PORT (UDP) и AWG_CLIENT_LISTEN_PORT (UDP) — могут конфликтовать
    с standalone AWG (тоже UDP)."""
    if not isinstance(st, dict):
        return []
    ports = []
    for k in ("awg_exit_port", "awg_client_listen_port"):
        v = st.get(k)
        if isinstance(v, (int, str)) and str(v).isdigit():
            ports.append(int(v))
    return ports


# Реестр модулей. Порядок важен только для детерминированного вывода.
# state_file = None означает "читаем из основного state.json".
PROTOCOL_PORT_REGISTRY = [
    {
        "key": "vless_state",
        "label": "Chimera VLESS (Mode B chain: AWG exit/client)",
        "state_file": None,  # основной state.json
        "extractor": _extract_vless_state_ports,
    },
    {
        "key": "hysteria2",
        "label": "Hysteria2 (UDP)",
        "state_file": None,  # внутри state.json под ключом "hysteria2"
        "extractor": _extract_hysteria2_ports,
    },
    {
        "key": "mieru",
        "label": "Mieru (TCP/UDP)",
        "state_file": Path("/var/lib/xray-installer/mieru.json"),
        "extractor": _extract_mieru_ports,
    },
    {
        "key": "naiveproxy",
        "label": "NaiveProxy (TCP)",
        "state_file": Path("/var/lib/xray-installer/naiveproxy.json"),
        "extractor": _extract_naiveproxy_ports,
    },
    {
        "key": "wdtt",
        "label": "WDTT (UDP: DTLS+WG)",
        "state_file": Path("/var/lib/xray-installer/wdtt.json"),
        "extractor": _extract_wdtt_ports,
    },
    {
        "key": "turntunnel",
        "label": "TurnTunnel / FreeTurn (UDP)",
        "state_file": Path("/var/lib/xray-installer/turntunnel.json"),
        "extractor": _extract_turntunnel_ports,
    },
    {
        "key": "turnable",
        "label": "Turnable / vk-turn (UDP)",
        "state_file": Path("/var/lib/xray-installer/turnable.json"),
        "extractor": _extract_turnable_ports,
    },
    {
        "key": "olcrtc",
        "label": "OLCrtc (WebRTC, без внешних портов)",
        "state_file": Path("/var/lib/xray-installer/olcrtc.json"),
        "extractor": _extract_olcrtc_ports,
    },
    {
        "key": "slipgate",
        "label": "SlipGate (DNS/HTTP tunnels)",
        "state_file": Path("/var/lib/xray-installer/slipgate.json"),
        "extractor": _extract_slipgate_ports,
    },
    {
        "key": "fptn",
        "label": "FPTN (TCP/TLS)",
        "state_file": Path("/var/lib/xray-installer/fptn.json"),
        "extractor": _extract_fptn_ports,
    },
    {
        "key": "trusttunnel",
        "label": "TrustTunnel (TCP+UDP, HTTP/2+HTTP/3)",
        "state_file": Path("/var/lib/xray-installer/trusttunnel.json"),
        "extractor": _extract_trusttunnel_ports,
    },
    {
        "key": "csqtt",
        "label": "CSQTT (UDP data-plane + TCP Web Panel)",
        "state_file": Path("/var/lib/xray-installer/csqtt.json"),
        "extractor": _extract_csqtt_ports,
    },
    {
        "key": "subscription",
        "label": "Chimera subscription endpoint (TCP)",
        "state_file": Path("/var/lib/xray-installer/subscription.json"),
        "extractor": _extract_subscription_ports,
    },
]


def check_port_used_by_other_protocol(port: int,
                                      exclude_module: str = "") -> str:
    """
    Проверяет, занят ли порт другим автономным протокол-модулем проекта.

    Идёт по реестру PROTOCOL_PORT_REGISTRY, читает state-файл каждого
    модуля (или секцию в основном state.json), извлекает порты, которые
    модуль слушает, и сравнивает с запрошенным `port`.

    Параметры:
      • port           — порт для проверки (int).
      • exclude_module — ключ модуля в реестре, который ПРОПУСКАЕМ
                         (чтобы модуль не конфликтовал сам с собой).
                         Например "vless_state" для AWG standalone
                         (т.к. awg_exit_port хранится в VLESS state.json,
                         но это Mode B chain — отдельный deployment).

    Возвращает:
      • пустую строку "" если конфликтов нет;
      • читаемую русскую строку с описанием конфликта (готовую для
        добавления в список conflicts) если порт занят другим модулем.
    """
    if not isinstance(port, int) or port <= 0 or port > 65535:
        return ""

    # Загружаем основной state.json один раз (используется несколькими
    # модулями в реестре — vless_state, hysteria2).
    main_state = {}
    try:
        if STATE_FILE.exists():
            main_state = json.loads(STATE_FILE.read_text())
    except Exception:
        main_state = {}

    for entry in PROTOCOL_PORT_REGISTRY:
        key = entry["key"]
        if exclude_module and key == exclude_module:
            continue

        state_data = {}
        if entry["state_file"] is None:
            state_data = main_state
        else:
            sf = entry["state_file"]
            if not sf.exists():
                continue
            try:
                state_data = json.loads(sf.read_text())
            except Exception:
                continue

        try:
            ports = entry["extractor"](state_data) or []
        except Exception:
            ports = []

        if port in ports:
            return (
                f"UDP/TCP-порт {port} уже занят другим модулем: "
                f"{entry['label']}. Укажите другой порт для AWG standalone "
                f"(доступные: 51820-51830, избегайте 11100 — занят chain)."
            )

    return ""


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
#  вынесены в chimera.modules.resources; импорт — в верхней секции
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
def _verify_ipv6_connectivity_quick() -> bool:
    """
    Быстрая проверка (≤5 сек) реальной IPv6-связности.
    Используется в _load_state_into_globals() чтобы не доверять state.json
    вслепую — IPv6-адрес мог быть сохранён при установке, а позже маршрут
    мог пропасть (ISP, reboot, изменение routes).

    Возвращает True только если хотя бы одна из проверок успешна:
      1. ping6 -c1 -W2 2001:4860:4860::8888 (Google Public DNS)
      2. curl -6 --connect-timeout 4 https://ipv6.icanhazip.com
    """
    # 1) ping6 — быстрый и не требует внешних утилит кроме iputils-ping.
    if command_exists("ping6"):
        r = _run(["ping6", "-c1", "-W2", "2001:4860:4860::8888"],
                 check=False, quiet=True)
        if r.returncode == 0:
            return True

    # 2) curl -6 — fallback если ping6 не установлен или заблокирован.
    try:
        r = _run(["curl", "-6", "-s", "--connect-timeout", "4",
                  "https://ipv6.icanhazip.com"],
                 check=False, quiet=True)
        if r.returncode == 0 and r.stdout.strip():
            return True
    except Exception:
        pass

    return False


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
#  chimera.modules.system_deps; импорт — в верхней секции этого файла.)


# (backup/rollback — create_backup, perform_rollback, run_unit_tests,
#  verify_connectivity — вынесены в chimera.modules.backup_rollback;
#  импорт — в верхней секции этого файла.)

# =============================================================================
#  ИНТЕРАКТИВНЫЙ ЗАПРОС ПАРАМЕТРОВ
# =============================================================================
# (prompt_parameters — вынесена в chimera.modules.install_prompts;
#  импорт — в верхней секции этого файла.)


# =============================================================================
#  ВЫБОР РЕЖИМА УСТАНОВКИ (A / B)
# =============================================================================
# (prompt_install_mode, prompt_protocol_mode — вынесены в
#  chimera.modules.install_prompts; импорт — в верхней секции этого файла.)



def _build_sockopt(tcp_no_delay: bool | None = None) -> dict:
    """
    Возвращает словарь sockopt с полным набором TCP-оптимизаций.
    Применяется ко всем протоколам (REALITY и xHTTP).
    tcp_no_delay: None → использовать глобальный XHTTP_TCP_NO_DELAY
    """
    no_delay = tcp_no_delay if tcp_no_delay is not None else XHTTP_TCP_NO_DELAY
    # tcpUserTimeout=30s: при 10s ядро убивало соединение RST-ом после любого
    # стога тракта длиннее 10с (потеря ACK окном) — с mux-клиентами один RST
    # ронял ВСЕ мультиплексированные стримы разом (волна EOF у клиентов).
    # 30с даёт TCP-ретрансмиссии время вылечить соединение самостоятельно.
    opt: dict = {
        "tcpFastOpen":        True,
        "tcpKeepAliveInterval": 15,
        "tcpKeepAliveIdle":   60,
        "tcpUserTimeout":     30000,
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
    if mode in ("stream-up", "stream-one", "auto"):
        extra["scStreamUpServerSecs"] = XHTTP_SC_STREAM_UP_SERVER_SECS

    # Параметры packet-up (клиент + сервер).
    if mode in ("packet-up", "auto"):
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
    # CDN masking — читаем флаг, чтобы пропустить вопрос о path
    # (path уже сгенерирован скрытым меню и выставлен в XHTTP_PATH).
    global XHTTP_CDN_MASKING

    _box_top(f"Режим xHTTP")
    _box_row()
    _box_row()
    _box_item("1", f"stream-up   — однонаправленный стриминг (Upload-stream) {GREEN}(рекомендуется){NC}")
    _box_desc(f"Клиент стримит данные серверу как один длинный POST.")
    _box_desc(f"Хорошо обходит глубокую инспекцию, поддерживает большинство CDN.")
    _box_row()
    _box_item("2", f"stream-one  — один двунаправленный поток")
    _box_desc(f"Полный HTTP/2 stream multiplex. Для CDN и продвинутого камуфляжа.")
    _box_row()
    _box_item("3", f"packet-up   — пакетный режим (Upload-packet)")
    _box_desc(f"Каждый фрагмент данных — отдельный HTTP-запрос.")
    _box_desc(f"{YELLOW}⚠ Может не поддерживаться вашей версией Xray-core.{NC}")
    _box_row()
    _box_item("4", f"auto        — автоматический выбор (Xray сам решает)")
    _box_desc(f"Xray выбирает stream-up или packet-up по HTTP-методу запроса.")
    _box_desc(f"Удобно для CDN: один инбаунд обслуживает uplink (POST) + download (GET).")
    _box_row()
    _box_bottom()

    # CDN masking: mode уже выставлен в "auto" скрытым меню через
    # setattr(core, "XHTTP_MODE", _CDN_MASKING_XHTTP_MODE) в
    # run_cdn_masking_install(). НЕ переспрашиваем — это критично:
    # server config использует _CDN_MASKING_XHTTP_MODE ("auto") из
    # build_xhttp_cdn_masking_inbound(), и client link должен получить
    # то же значение. Если пользователь выберет "stream-up" здесь,
    # client link получит mode=stream-up, а server config останется
    # mode=auto → рассинхрон → клиент не подключится.
    if globals().get("XHTTP_CDN_MASKING", False):
        if not XHTTP_MODE:
            XHTTP_MODE = "auto"
        info(f"CDN masking: использую mode из скрытого меню: {GREEN}{XHTTP_MODE}{NC}")
        info(f"           (не переспрашиваю — mode должен совпадать на сервере и клиенте)")
    else:
        while True:
            choice = input(f"  {CYAN}Выбор [1]: {NC}").strip() or "1"
            if choice == "1":
                XHTTP_MODE = "stream-up"
                break
            elif choice == "2":
                XHTTP_MODE = "stream-one"
                break
            elif choice == "3":
                XHTTP_MODE = "packet-up"
                warn("packet-up выбран — убедитесь что ваша версия Xray-core его поддерживает")
                break
            elif choice == "4":
                XHTTP_MODE = "auto"
                break
            else:
                warn("Введите 1, 2, 3 или 4")
    success(f"xHTTP режим: {XHTTP_MODE}")

    # Путь endpoint
    # CDN masking: path уже сгенерирован скрытым меню через
    # xhttp_path_gen.generate_decoy_path() и выставлен в core.XHTTP_PATH.
    # НЕ переспрашиваем — это критично: path уже должен быть вбит в
    # Rewrite панели Beeline CDN, и любое изменение сломает связку.
    # См. chimera/modules/xhttp_cdn_masking.py:run_cdn_masking_install()
    # которая делает setattr(core, "XHTTP_PATH", _path) ДО вызова do_full_install().
    if globals().get("XHTTP_CDN_MASKING", False):
        if not XHTTP_PATH:
            # Edge-case: флаг выставлен, но path пуст (создание из
            # командной строки без скрытого меню). Генерируем через
            # тот же генератор, что и скрытое меню — формат /api/v2/static.ts.
            try:
                from chimera.modules.xhttp_path_gen import generate_decoy_path
                XHTTP_PATH = generate_decoy_path()
            except ImportError:
                XHTTP_PATH = "/" + gen_hex(4)  # fallback на старый формат
        info(f"CDN masking: использую path из скрытого меню: {GREEN}{XHTTP_PATH}{NC}")
        info(f"           (не переспрашиваю — path уже должен быть в Rewrite Beeline CDN)")
    else:
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
    _box_row(f"  {DIM}Применяется:{NC} во всех режимах (stream-up, stream-one, packet-up).")
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
    _box_row(f"  {DIM}Применяется:{NC} только сервер, режимы stream-up и stream-one.")
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
    if XHTTP_MODE in ("stream-up", "stream-one") or XHTTP_MODE == "auto":
        _box_row(f"{BOLD}{BLUE}[C] scStreamUpServerSecs{NC} — интервал keepalive для stream-up (только сервер)")
        _box_row(f"  {DIM}Что делает:{NC} Cloudflare и многие CDN разрывают HTTP-соединение,")
        _box_row(f"  если в течение 100 секунд не было реальных данных. Этот параметр")
        _box_row(f"  заставляет сервер каждые N секунд отправлять клиенту несколько байт")
        _box_row(f"  padding-а (xPaddingBytes), чтобы CDN «видел» активное соединение.")
        _box_row(f"  Значение -1 отключает механизм (поведение Xray до введения этого параметра).")
        _box_row(f"  {DIM}Применяется:{NC} только сервер, режим stream-up (и auto при TLS H2).")
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
    if XHTTP_MODE in ("packet-up",) or XHTTP_MODE == "auto":
        _box_row(f"{BOLD}{BLUE}[D] scMaxEachPostBytes{NC} — максимальный объём данных в одном POST-запросе (packet-up)")
        _box_row(f"  {DIM}Что делает:{NC} В режиме packet-up каждый фрагмент исходящего трафика")
        _box_row(f"  отправляется отдельным HTTP POST-запросом. Этот параметр ограничивает")
        _box_row(f"  максимальный размер тела одного POST. Значение должно быть меньше лимита,")
        _box_row(f"  который допускает ваш CDN или промежуточный прокси (обычно 1–10 МБ).")
        _box_row(f"  Сервер также отклоняет POST, превышающий этот лимит.")
        _box_row(f"  Диапазон \"MIN-MAX\" снижает fingerprint: размер каждого POST случаен.")
        _box_row(f"  {DIM}Применяется:{NC} клиент и сервер, только режим packet-up (и auto).")
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
        _box_row(f"  {DIM}Применяется:{NC} только сервер, только режим packet-up (и auto).")
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
    if XHTTP_MODE in ("packet-up",) or XHTTP_MODE == "auto":
        _box_row(f"{BOLD}{BLUE}[F] scMinPostsIntervalMs{NC} — мин. интервал между POST-запросами клиента (packet-up)")
        _box_row(f"  {DIM}Что делает:{NC} Задаёт минимальный промежуток в миллисекундах между")
        _box_row(f"  последовательными POST-запросами, которые клиент отправляет серверу")
        _box_row(f"  в рамках одного прокси-соединения (режим packet-up). Слишком малый")
        _box_row(f"  интервал перегружает серверный буфер (scMaxBufferedPosts) и разрывает")
        _box_row(f"  соединение. Слишком большой — снижает скорость upload. Диапазон")
        _box_row(f"  \"MIN-MAX\" снижает fingerprint по фиксированному интервалу.")
        _box_row(f"  {DIM}Применяется:{NC} только клиент, только режим packet-up (и auto).")
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
    if XHTTP_MODE in ("stream-up", "stream-one") or XHTTP_MODE == "auto":
        _box_row(f"{BOLD}{BLUE}[G] noGRPCHeader{NC} — управление gRPC-маскировкой upload-запросов (клиент)")
        _box_row(f"  {DIM}Что делает:{NC} По умолчанию каждый upload-запрос клиента несёт заголовок")
        _box_row(f"  Content-Type: application/grpc — маскировка под gRPC-трафик. Это помогает")
        _box_row(f"  проходить через провайдеров, которые пропускают gRPC. Включите 'true',")
        _box_row(f"  если ваш CDN или провайдер блокирует gRPC или он создаёт проблемы.")
        _box_row(f"  {DIM}Применяется:{NC} только клиент, режимы stream-up и stream-one.")
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
    _box_row(f"  Рекомендуется при режимах stream-up / stream-one / auto и H2.")
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
        xhttp_mode = params.get("mode", "stream-up")

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


# (Chain/Nodes — prompt_chain_params, _prompt_balancer_strategy, prompt_chain_params_multi — вынесены в
#  chimera.modules.chain_nodes; импорт — в верхней секции этого файла.)


# =============================================================================
#  ВЫБОР РЕЖИМА EXIT-НОДЫ ДЛЯ РЕЖИМА B: VLESS или AWG
# =============================================================================
# Глобальные параметры SSH-аутентификации для удалённой настройки AWG.
# Заполняются в prompt_awg_exit_mode(), потребляются awg_setup_remote_server().
AWG_SSH_AUTH_METHOD: str = "key"    # "key" | "password"
AWG_SSH_PASSWORD:    str = ""       # хранится только до конца сессии настройки


# (prompt_awg_exit_mode — вынесена в chimera.modules.install_prompts;
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


# (Chain/Nodes — generate_xray_config_chain_entry — вынесены в
#  chimera.modules.chain_nodes; импорт — в верхней секции этого файла.)


# =============================================================================
#  ГЕНЕРАЦИЯ КОНФИГА XRAY ДЛЯ РЕЖИМА B — зарубежный (exit) VPS
# =============================================================================
def _build_exit_xhttp_settings(nd: dict) -> dict:
    """
    Строит xhttpSettings (inbound, сервер) для exit-ноды с правильной
    структурой extra согласно документации XHTTP: Beyond REALITY.
    Используется в конфиге exit-VPS (серверная сторона).
    """
    mode = nd.get("xhttp_mode", "stream-up")
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
    if mode in ("stream-up", "stream-one", "auto"):
        extra["scStreamUpServerSecs"] = XHTTP_SC_STREAM_UP_SERVER_SECS
    if mode in ("packet-up", "auto"):
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
    mode = nd.get("xhttp_mode", "stream-up")
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
    if mode in ("packet-up", "auto"):
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


# (Chain/Nodes — _make_exit_node_config, generate_xray_config_chain_exit — вынесены в
#  chimera.modules.chain_nodes; импорт — в верхней секции этого файла.)


# =============================================================================
#  ДОП. КЛИЕНТ ДЛЯ УЖЕ РАЗВЁРНУТОЙ EXIT-НОДЫ (для резервной Entry-ноды)
# =============================================================================
# (Chain/Nodes — do_generate_chain_exit_additional_client — вынесены в
#  chimera.modules.chain_nodes; импорт — в верхней секции этого файла.)


# =============================================================================
#  МУЛЬТИ-КАСКАД: ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (до 10 exit-нод)
# =============================================================================

# (Chain/Nodes — _nodes_from_state, _load_chain_nodes_from_state, _save_chain_nodes_to_state, _prompt_one_node, _prompt_one_node_from_link, _fix_node_fields, _prompt_one_node_manual, _h2_reapply_transport_if_active, generate_xray_config_chain_entry_multi — вынесены в
#  chimera.modules.chain_nodes; импорт — в верхней секции этого файла.)


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
        # v56: безопасный рестарт — см. _xray_safe_restart()
        if _xray_safe_restart():
            success("Xray активен — новая domainStrategy применена")
        else:
            warn("Xray не запустился — проверьте: journalctl -u xray -n 30")


def _xray_safe_restart(wait_active: int = 45, attempts: int = 2) -> bool:
    """
    v56 (start-limit-fix): безопасный перезапуск xray, устойчивый к
    systemd start-rate-limit.

    ПРОБЛЕМА (репродукция 2026-08-27, <node-2>): юнит xray.service,
    который пишет chimera, содержит ``StartLimitIntervalSec=60s`` +
    ``StartLimitBurst=3``. Поток пересборки конфига
    (``_rebuild_and_restart_xray``) делает 3-5 рестартов ПОДРЯД за
    несколько секунд: YouTube-restore → IP-pin restore → Telemt tproxy →
    финальный рестарт. Четвёртый start внутри 60 секунд systemd
    ОТКАЗЫВАЕТСЯ запускать: «Start request repeated too quickly» →
    failed (start-limit-hit) → xray остаётся мёртвым ПРИ ВАЛИДНОМ
    конфиге (журнал: Started → Reading config → Warning → Stopping,
    три раза подряд, затем start-limit-hit).

    РЕШЕНИЕ: ``systemctl reset-failed xray`` перед рестартом — он
    сбрасывает и failed-состояние, и счётчик start-rate-limit
    (ratelimit_reset внутри unit_reset_failed), после чего start
    принимается. Плюс одна повторная попытка с паузой — на случай
    реальных проблем с конфигом (тогда wait-цикл честно выйдет по
    таймауту и вернёт False).

    Используется во всех точках рестарта цепочки пересборки
    (_core/youtube_route/youtube_ip_pin/ru_subnets/as_direct/
    chain_nodes); mtproto патчится инлайн-``reset-failed`` (модуль
    самодостаточен, без привязки к _core).

    :param wait_active: сколько секунд ждать is-active после рестарта
                        (90 — для конфигов с 13 000+ RIPE-правил)
    :param attempts:    число попыток (каждая с reset-failed)
    :return: True если сервис активен после рестарта
    """
    for _attempt in range(1, attempts + 1):
        # Сброс failed-состояния И счётчика start-rate-limit юнита.
        # Для не-failed юнита команда безвредна (тихо игнорируем код).
        _run(["systemctl", "reset-failed", "xray"], check=False, quiet=True)
        _run(["systemctl", "restart", "xray"], check=False, quiet=True)
        _r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
        for _ in range(wait_active):
            if _r.stdout.strip() == "active":
                return True
            time.sleep(1)
            _r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
        if _attempt < attempts:
            warn(f"Xray не активен после рестарта "
                 f"(попытка {_attempt}/{attempts}) — повторяем с reset-failed...")
            time.sleep(2)
    return False


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

    # Восстанавливаем YouTube→RU правило если оно было включено
    # (state["youtube_via_ru"] = True). generate_* перезаписывает routing
    # целиком — без restore пользователь потерял бы переключатель после
    # любого rebuild xray-config (пункт 5b, смена домена/порта и т.д.).
    try:
        from chimera.modules.youtube_route import restore_youtube_rule_if_needed
        restore_youtube_rule_if_needed(silent=False)
    except ImportError:
        pass
    except Exception:
        pass  # не критично — это best-effort restore

    # Восстанавливаем Telemt tproxy-интеграцию (если установлен).
    # generate_* перезаписывает config.json целиком — dokodemo inbound и
    # iptables-правила теряются. Переинжектируем ДО рестарта xray, чтобы
    # inbound уже был в конфиге к моменту запуска.
    try:
        from chimera.modules.mtproto import telemt_tproxy_emergency_restore
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
        from chimera.modules.pq_vless import restore_pq_vless_if_enabled
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

    # Восстанавливаем server-side TLS fragment (v4.21 — anti-DPI symmetry).
    # generate_* полностью переписывает config.json, поэтому sockopt.fragment
    # на REALITY inbound теряется. Если в state включён — пере-применяем.
    try:
        server_fragment_reapply_after_rebuild()
    except Exception as _sf_e:
        warn(f"Server fragment восстановление: {_sf_e}")

    # v4.23.8: SNI-dispatch patch (если включён auto_configured=True).
    # generate_* перезаписывает config.json — REALITY-инбаунд возвращается
    # на публичный :443, конфликт с nginx stream{}. Пере-применяем патч
    # ДО рестарта xray. nginx НЕ трогаем — он уже настроен отдельным
    # потоком auto_enable_sni_dispatch() и не зависит от regenerate.
    # Порядок: sni_dispatch_reapply идёт ПОСЛЕ server_fragment (оба патчат
    # sockopt одного и того же inbound, но разные поля — fragment vs
    # acceptProxyProtocol/listen/port — конфликта нет).
    try:
        from chimera.modules.singbox_nginx import sni_dispatch_reapply_after_rebuild
        sni_dispatch_reapply_after_rebuild()
    except ImportError:
        pass
    except Exception as _sd_e:
        warn(f"SNI-dispatch восстановление: {_sd_e}")

    # Финальный рестарт
    # v56 (start-limit-fix): раньше здесь был голый `systemctl restart xray`.
    # Выше по этому же flow YouTube-restore, IP-pin и Telemt tproxy уже
    # сделали по рестарту каждый — при StartLimitBurst=3/60s юнита xray
    # финальный start отклонялся (start-limit-hit) и xray оставался в
    # failed при валидном конфиге. Безопасный рестарт сбрасывает лимит.
    if _xray_safe_restart():
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


def do_rebuild_xray_config() -> None:
    """Перегенерировать /etc/xray/config.json из state.json без переустановки.

    Полезно когда:
      • Обновился Xray-core до новой мажорной версии и в код инсталлятора добавили
        новые обязательные поля (например minClientVer для Xray 26.7.11+).
        В уже существующем config.json этих полей нет, а полная переустановка
        не нужна — нужен только rebuild конфига.
      • Конфиг был повреждён / частично изменён вручную и нужно вернуть его
        к каноническому виду с сохранением всех параметров из state.json.

    Делает:
      1. Бэкап текущего /etc/xray/config.json (через backup_xray_config()).
      2. Загружает state.json в глобали (PARAM_DOMAIN, PARAM_PRIVATE_KEY и т.д.).
      3. Вызывает _rebuild_and_restart_xray() — та сама пересоздаёт конфиг
         (через generate_xray_config / generate_xray_config_xhttp /
         generate_xray_config_chain_entry_multi в зависимости от режима),
         восстанавливает пользователей / RIPE-правила / Telemt / PQ-VLESS /
         server-fragment / SNI-dispatch и перезапускает Xray + Nginx.

    Точки входа:
        Вызывается из _menu_install_system() — пункт "5b".
    """
    print()
    _box_top("🔧  Перегенерация конфига Xray")
    _box_row()
    _box_row(f"  Пересоздаёт {CYAN}/etc/xray/config.json{NC} из {CYAN}state.json{NC}")
    _box_row(f"  с текущими параметрами (домен, ключи REALITY, UUID).")
    _box_row()
    _box_row(f"  Применение — добавить поля, которых нет в старом конфиге,")
    _box_row(f"  но которые теперь обязательны (напр. {BOLD}minClientVer{NC} для Xray 26.7.11+).")
    _box_row()
    _box_row(f"  {YELLOW}⚠  Текущий config.json будет забэкаплен и заменён.{NC}")
    _box_row(f"  {DIM}Пользователи, RIPE-правила, Telemt tproxy, PQ-VLESS, fragment{NC}")
    _box_row(f"  {DIM}будут восстановлены автоматически.{NC}")
    _box_row()
    _box_bottom()
    try:
        ans = input(f"{CYAN}Перегенерировать конфиг? [y/N]:{NC} ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        ans = ""
    if ans != "y":
        info("Отменено.")
        return

    if not STATE_FILE.exists():
        warn(f"state.json не найден ({STATE_FILE}) — сначала выполните установку (пункт 1).")
        return

    _load_state_into_globals()
    info("Параметры загружены из state.json.")
    info(f"  Режим: {INSTALL_MODE}, протокол: {PROTOCOL_MODE}, домен: {PARAM_DOMAIN}")
    # Если PARAM_SOCKET_PATH пустой — что-то не так с state.json.
    if PROTOCOL_MODE == "reality" and not AWG_EXIT_ENABLED and not PARAM_SOCKET_PATH:
        warn("PARAM_SOCKET_PATH пуст — в state.json нет ключа 'socket'.")
        warn("Проверьте: jq '.socket' /var/lib/xray-installer/state.json")
        return

    # _rebuild_and_restart_xray() внутри делает бэкап, регенерацию, восстановление
    # пользователей/RIPE/Telemt/PQ-VLESS/fragment/SNI-dispatch и рестарт Xray+Nginx.
    try:
        _rebuild_and_restart_xray("Xray перезапущен — конфиг перегенерирован")
    except Exception as e:
        warn(f"Ошибка перегенерации: {e}")
        warn(f"Восстановите из бэкапа: ls /var/backups/xray/configs/")
        return

    # Показать что minClientVer действительно появился (если REALITY-режим)
    if PROTOCOL_MODE == "reality" and PROTOCOL_MODE != "xhttp":
        try:
            cfg = json.loads((CONFIG_DIR / "config.json").read_text())
            for ib in cfg.get("inbounds", []):
                rs = ib.get("streamSettings", {}).get("realitySettings", {})
                if rs:
                    mcv = rs.get("minClientVer", "")
                    if mcv:
                        success(f"minClientVer = {mcv}  ✓  (совместимость с Xray 26.7.11+)")
                    else:
                        warn("minClientVer отсутствует — проверьте generate_xray_config()")
                    break
        except Exception:
            pass


# (Chain/Nodes — do_manage_nodes — вынесены в
#  chimera.modules.chain_nodes; импорт — в верхней секции этого файла.)


# =============================================================================
#  ГЕНЕРАЦИЯ ИТОГОВЫХ ФАЙЛОВ ДЛЯ РЕЖИМА B
# =============================================================================
# (Chain/Nodes — generate_chain_summary — вынесены в
#  chimera.modules.chain_nodes; импорт — в верхней секции этого файла.)


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
#  вынесены в chimera.modules.dnscrypt_setup; импорт — в верхней
#  секции этого файла.)

# (Сеть / файрволл / sysctl — configure_firewall, apply_network_optimizations —
#  вынесены в chimera.modules.network_setup; импорт — в верхней
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
#  chimera.modules.xray_install; импорт — в верхней секции этого файла.)


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
#  do_user_add, do_user_delete, _show_qr, _gen_vless_link,
#  generate_client_links — вынесены в
#  chimera.modules.users_manager; импорт — в верхней секции этого файла.
#  do_user_show_link и do_user_menu удалены в патче №5 — мёртвый код,
#  строго подмножество do_unified_user_manager.)


# =============================================================================
#  УДАЛЕНИЕ
# =============================================================================
# (do_uninstall вынесен в chimera.modules.uninstall;
#  импорт — в верхней секции этого файла.)


# (Split tunnel — prompt_split_tunnel, _save/_load_split_tunnel_custom,
#  build_split_tunnel_routing_rules, _xray_count_ru_subnet_rules,
#  _show_xray_routing_rules, do_manage_split_tunnel,
#  _apply_split_tunnel_config_from_state — вынесены в
#  chimera.modules.split_tunnel; импорт — в верхней секции этого файла.)


# (download_geo_files, setup_geo_autoupdate вынесены в
#  chimera.modules.geo_files; импорт — в верхней секции этого файла.)


def _logrotate_debug_ok(cfg_path: "Path") -> bool:
    """Валидность logrotate-конфига через `logrotate --debug`.

    v60: критерий — отсутствие строк 'error:' в выводе (реальная
    невалидность конфига ВСЕГДА сопровождается 'error: <файл>:
    <строка> ...'). Голый rc!=0 ненадёжен: часть сборок logrotate
    возвращает ненулевой код на валидных конфигах (warning-строки,
    отсутствующие логи с missingok) — инцидент переустановки
    203.0.113.109: [WARN] «проверьте конфиг вручную: xray-heavy» на
    валидном конфиге. Отсутствие logrotate в системе = не ошибка
    конфига (пакет доустановится, конфиг уже корректен).
    """
    try:
        r = _run(["logrotate", "--debug", str(cfg_path)],
                 check=False, quiet=True)
    except Exception:
        return True
    if r.returncode == 127:
        # logrotate не установлен — конфиг не проверяем, но и не
        # ругаемся: синтаксис генерируем сами.
        return True
    out = (r.stdout or "") + (r.stderr or "")
    return not re.search(r'(?im)^\s*error\s*:', out)


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
        # Создано автоматически установщиком Chimera Project
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
        # Создано автоматически установщиком Chimera Project
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
    # ложное впечатление, что они под ротацией. chimera.log пишется
    # непрерывно (info()/success()/warn() на каждое действие) и без ротации
    # рос неограниченно вплоть до полного заполнения диска. Здесь — daily +
    # maxsize как аварийный триггер (если между суточными прогонами
    # logrotate файл распухнет раньше срока, ротация всё равно сработает).
    LOGROTATE_XRAY_HEAVY = Path("/etc/logrotate.d/xray-heavy")
    heavy_entries = [
        "/var/log/chimera.log",
        "/var/log/xray-autoban.log",
        "/var/log/xray-watchdog.log",
    ]
    heavy_block = "\n".join(heavy_entries)
    LOGROTATE_XRAY_HEAVY.write_text(textwrap.dedent(f"""\
        # Лог инсталлятора и cron-модулей (autoban/watchdog)
        # Создано автоматически установщиком Chimera Project
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

    # v60: логи autoban/watchdog создаются позже их cron-скриптами —
    # создаём пустые заранее: часть сборок logrotate в --debug возвращает
    # rc!=0 на отсутствующих логах даже с missingok (инцидент
    # переустановки 203.0.113.109: [WARN] «проверьте конфиг вручную»
    # на полностью валидном xray-heavy).
    for _lf in heavy_entries:
        try:
            _lp = Path(_lf)
            if not _lp.exists():
                _lp.touch()
        except Exception:
            pass

    # Проверяем синтаксис: logrotate --debug валиден, если в выводе НЕТ
    # строк 'error:' (реальная невалидность конфига всегда сопровождается
    # 'error: <файл>: <строка> ...'). Голый rc!=0 ненадёжен — бывает и на
    # валидных конфигах (warning-строки, особенности отдельных сборок).
    if _logrotate_debug_ok(LOGROTATE_XRAY):
        success("logrotate настроен: /etc/logrotate.d/xray (daily, 14 дней, gzip)")
    else:
        warn("logrotate: проверьте конфиг вручную: /etc/logrotate.d/xray")
    if _logrotate_debug_ok(LOGROTATE_XRAY_HEAVY):
        success("logrotate настроен: /etc/logrotate.d/xray-heavy "
                "(chimera/autoban/watchdog, daily, maxsize 50M)")
    else:
        warn("logrotate: проверьте конфиг вручную: /etc/logrotate.d/xray-heavy")
    dim("  access.log + error.log: ежедневно, 14 архивов")
    dim("  autoupdate/geo-update:  еженедельно, 4 архива")
    dim("  chimera/autoban/watchdog: ежедневно, 14 архивов, maxsize 50M")


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


# (AWG transport — awg_check_tool, awg_generate_keys, awg_install_local, _awg_install_go_version_binary_only, _awg_install_go_version, _awg_detect_implementation, _awg_create_userspace_stubs, _awg_server_conf_text, _awg_client_conf_text, _awg_systemd_unit_text, ensure_amneziawg_ready, awg_setup_local_client, awg_apply_policy_routing, _awg_ensure_sshpass, awg_setup_remote_server, _awg_print_manual_guide, awg_rollback, awg_verify_tunnel, _awg_cleanup_stale_interfaces, awg_full_setup — вынесены в
#  chimera.modules.awg_transport; импорт — в верхней секции этого файла.)

def do_full_install() -> None:
    global INSTALL_STARTED, PARAM_USE_DNSCRYPT, DNSCRYPT_INSTALLED
    global PARAM_USE_AGHOME, AGHOME_INSTALLED
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
    # AdGuard Home (v37): DNS-сервер :53 поверх DNSCrypt — после
    # установки dnscrypt (upstream-требование). Внутри install_aghome:
    # миграция dnscrypt с :53 → wizard (:3000, ждём до 5 мин) → финализация
    # (секции dns/tls/filters, снятие redirect 53→5300). Пока мастер не
    # завершён — DNS страхует redirect → dnscrypt:5300.
    if PARAM_USE_AGHOME and PARAM_USE_DNSCRYPT:
        try:
            from chimera.modules.aghome_setup import install_aghome, aghome_dns_ready
            if install_aghome(interactive=True):
                AGHOME_INSTALLED = aghome_dns_ready()
                if AGHOME_INSTALLED:
                    PARAM_USE_AGHOME = True
                PROGRESS.update(3, "AdGuard Home")
            else:
                AGHOME_INSTALLED = False
                PARAM_USE_AGHOME = False
                warn("AdGuard Home не установлен — DNS остаётся на DNSCrypt")
        except ImportError as _e:
            warn(f"Модуль aghome_setup недоступен: {_e}")
            PARAM_USE_AGHOME = False
        except Exception as _e:
            warn(f"AdGuard Home: ошибка установки: {_e} — DNS остаётся на DNSCrypt")
            PARAM_USE_AGHOME = False
            AGHOME_INSTALLED = False
    elif PARAM_USE_AGHOME and not PARAM_USE_DNSCRYPT:
        warn("AdGuard Home требует DNSCrypt-proxy — AGH пропущен")
        PARAM_USE_AGHOME = False
    configure_firewall();           PROGRESS.update(5,  "Файрволл")

    # v60: убран ложный ранний чек «порт SERVER_PORT может быть недоступен
    # снаружи» — он выполнялся ДО запуска xray (порт ещё не слушался) и
    # проверял connect к IP hostname (на Ubuntu это 127.0.1.1), т.е. на
    # чистой установке предупреждал ВСЕГДА. Реальная внешняя проверка
    # портов уже есть в финальной «Проверке сетевой доступности».

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
    # CDN masking: передаём cdn_masking_mode=True если профиль активен.
    # В simple-XHTTP-режиме (по умолчанию) flag=False → поведение идентично
    # предыдущей версии (без параметра), ни одного байта вывода не меняется.
    setup_nginx_final(cdn_masking_mode=bool(globals().get("XHTTP_CDN_MASKING", False)))
    PROGRESS.update(5,  "Nginx final")
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

    # Шаг 1.5: AdGuard Home — ПОСЛЕ dnscrypt (upstream), ДО xray (клиент :53).
    # Порядок boot: dnscrypt-proxy.service → AdGuardHome.service → xray
    # (задан в systemd-unit'ах через After=/Before=).
    if PARAM_USE_AGHOME:
        info("Шаг 1.5: запуск AdGuard Home...")
        try:
            from chimera.modules.aghome_setup import (
                is_aghome_installed, is_aghome_active, aghome_dns_ready,
                aghome_wizard_pending, finalize_aghome_config,
            )
            if is_aghome_installed() and not is_aghome_active():
                _run(["systemctl", "restart", "AdGuardHome"],
                     check=False, quiet=True)
                _wait_service_active("AdGuardHome", 30)
            if aghome_dns_ready():
                success("  AdGuard Home активен на :53 (upstream → dnscrypt)")
            elif aghome_wizard_pending():
                info("  AdGuard Home в режиме мастера — DNS на dnscrypt redirect")
                info("  Завершите мастер: Сеть → AdGuard Home (A) → 2")
            elif is_aghome_installed() and AGH_CONF.exists():
                # установлен с конфигом, но DNS не готов — переприменяем
                info("  AdGuard Home: переприменяю канонический конфиг...")
                if finalize_aghome_config(interactive=False):
                    success("  AdGuard Home активен на :53")
                else:
                    warn("  AdGuard Home не поднялся на :53 — DNS на dnscrypt")
                    warn("  Проверьте: journalctl -u AdGuardHome -n 30")
            else:
                warn("  AdGuard Home не установлен/не настроен — DNS на dnscrypt")
        except ImportError as _e:
            warn(f"  Модуль aghome_setup недоступен: {_e}")
        except Exception as _e:
            warn(f"  AdGuard Home: {_e}")

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

    # Шаг 3: Nginx ВТОРЫМ.
    # === FIX: порядок запуска "nginx → сокет" вместо "сокет → nginx" ===
    # АРХИТЕКТУРА REALITY+Unix-сокет (см. nginx_setup.py:573-579):
    #   Nginx слушает на `listen unix:PARAM_SOCKET_PATH ssl proxy_protocol` —
    #   именно NGINX создаёт unix-сокет при своём bind(). Xray НЕ создаёт
    #   сокет — он только делает connect к нему при fallback (dest в
    #   realitySettings). Это документировано в create_xray_service()
    #   (xray_install.py:1276-1283) и в _nginx_restart_if_reality()
    #   (xray_install.py:1871-1874).
    #
    # СТАРЫЙ БАГ: код ждал сокет ДО запуска nginx — deadlock, потому что
    # сокет физически не может появиться пока nginx не запущен. Цикл
    # range(1, 31) всегда завершался else → гарантированный warning
    # "Сокет не появился" после 30 сек ожидания. Увеличение timeout не
    # помогало (пользователь пробовал) — проблема не в длительности, а в
    # порядке операций.
    #
    # ИСПРАВЛЕНИЕ: сначала запускаем nginx (он создаёт сокет), потом
    # проверяем что сокет появился. Это та же логика что уже работает в
    # _nginx_restart_if_reality() (xray_install.py:1897-1905) и в
    # emergency_repair.py (строки 773-777).
    info("Шаг 3/3: запуск Nginx...")
    _run(["systemctl", "stop",  "nginx"], check=False, quiet=True)
    time.sleep(1)
    _run(["systemctl", "start", "nginx"], check=False, quiet=True)
    nginx_ok = _wait_service_active("nginx", 15)

    # Проверка сокета — только в классическом REALITY (не AWG, не xHTTP).
    # В AWG-режиме Xray слушает напрямую TCP-порт, unix-сокета нет.
    # В xHTTP-режиме Xray слушает loopback backend, unix-сокета нет.
    if PROTOCOL_MODE == "reality" and nginx_ok and PARAM_SOCKET_PATH and not AWG_EXIT_ENABLED:
        # Nginx уже запущен выше — он создаёт сокет при bind (listen unix:).
        # Ждём подтверждения (обычно <1 сек, но даём 20 сек как в
        # _nginx_restart_if_reality для надёжности на медленных VPS).
        for _i in range(20):
            if Path(PARAM_SOCKET_PATH).is_socket():
                success(f"  Сокет готов: {PARAM_SOCKET_PATH}")
                break
            time.sleep(1)
        else:
            warn(f"  Сокет {PARAM_SOCKET_PATH} не появился после запуска nginx — "
                 f"проверьте: journalctl -u nginx -n 20")
    elif AWG_EXIT_ENABLED:
        info("  AWG-режим: unix socket не используется, Xray слушает TCP напрямую")

    if nginx_ok:
        success("  Nginx активен")
    else:
        warn("  Nginx не запустился — journalctl -u nginx -n 20")
    # === END FIX ===

    # ── Сохранение state.json ДО health check ─────────────────────────────────
    # ВАЖНО: state.json должен быть сохранён ДО run_full_health_check(), потому
    # что health.py читает из него domain и server_port (через _get_state_value,
    # без импорта _core — чтобы избежать циклической зависимости). Раньше state
    # сохранялся ПОСЛЕ health check → health_check_ssl() получала пустой domain
    # → ложный warning "SSL проверка пропущена: домен не задан" даже когда домен
    # был указан и сертификат получен. Аналогично health_check_ports() получала
    # server_port=443 (fallback) вместо реального порта при первой установке.
    # Фикс: сохраняем state сразу после запуска сервисов, до любых проверок.
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
        # CDN masking profile flag (опциональный, дефолт False — простой XHTTP).
        "xhttp_cdn_masking":             globals().get("XHTTP_CDN_MASKING", False),
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
        # Сохраняем email/имя начального юзера — это нужно для user portal /
        # admin panel / подписки. Также позволяет при повторной установке
        # восстановить начального юзера с тем же именем.
        "user_email":     PARAM_USER_EMAIL,
        "user_name":      PARAM_USER_NAME,
        "ipv6":           IPV6_PREFLIGHT,
        "use_dnscrypt":   PARAM_USE_DNSCRYPT,
        "use_aghome":     PARAM_USE_AGHOME,
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
            # Параметры обфускации — все 16 (Jc/Jmin/Jmax/S1-S4/
            # H1-H4/I1-I5) + источник. Раньше persist'ились только connection
            # параметры (exit_host, port, keys), а obfuscation всегда
            # сбрасывалась в дефолты при рестарте Chimera — скрытый баг.
            "awg_jc":              AWG_JC,
            "awg_jmin":            AWG_JMIN,
            "awg_jmax":            AWG_JMAX,
            "awg_s1":              AWG_S1,
            "awg_s2":              AWG_S2,
            "awg_s3":              AWG_S3,
            "awg_s4":              AWG_S4,
            "awg_h1":              AWG_H1,
            "awg_h2":              AWG_H2,
            "awg_h3":              AWG_H3,
            "awg_h4":              AWG_H4,
            "awg_i1":              AWG_I1,
            "awg_i2":              AWG_I2,
            "awg_i3":              AWG_I3,
            "awg_i4":              AWG_I4,
            "awg_i5":              AWG_I5,
            "awg_obfuscation_source": AWG_OBFUSCATION_SOURCE,
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

    PROGRESS.update(5, "Проверки")

    time.sleep(3)
    run_full_health_check()
    _box_top("Проверка сетевой доступности")
    verify_connectivity()
    _box_bottom()

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
    # Имена шаблонов берутся из единого источника, чтобы финальный статус,
    # меню install_prompts и состояние emergency_repair всегда совпадали.
    from chimera.modules.nginx_setup_templates import get_template_names as _get_tmpl_names
    tmpl_names   = _get_tmpl_names()

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
    _agh_dns = False
    try:
        from chimera.modules.aghome_setup import aghome_dns_ready as _aghr
        _agh_dns = _aghr()
    except Exception:
        pass
    if _agh_dns:
        _box_row(f"  DNS:          {CYAN}AdGuard Home :53 (кеш+фильтры) → DNSCrypt :{DNSCRYPT_LISTEN_PORT} → fallback 9.9.9.9/1.1.1.1{NC}")
    elif DNSCRYPT_INSTALLED:
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
    _box_row(f"  Шаблон:       {CYAN}{tmpl_names[int(PARAM_SITE_TEMPLATE or '0')]}{NC}")
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

    # Синхронизируем начального пользователя в единый users.json.
    # Берём email/имя из PARAM_USER_EMAIL/PARAM_USER_NAME (заполняются в
    # install_prompts.py [1/12]/[2/12]). Если их нет (старая инсталляция
    # без этого патча) — fallback на PARAM_EMAIL (LE email) или дефолт.
    _init_email = (PARAM_USER_EMAIL or PARAM_EMAIL or "default@chimera.local").strip()
    _init_name = (PARAM_USER_NAME or _init_email.split("@")[0] or "admin").strip()
    try:
        existing = _unified_load_users()
        if not any(u.get("uuid") == PARAM_UUID for u in existing):
            existing.append({
                "uuid":    PARAM_UUID,
                "email":   _init_email,
                "name":    _init_name,
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
    if PARAM_DOMAIN:
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
#  _MTU_STATE_FILE — вынесены в chimera.modules.mtu_tuning;
#  импорт — в верхней секции этого файла.)


# (Diagnostics engine — _diag_ok/err/head/warn/make_counters/chk/run/fmt_bytes/
#  resolve_config/stats_api_available/get_stats_via_api/hint_stats_api/
#  render_traffic_table/print_traffic_from_ss/print_traffic_volume/
#  check_xray_service/geo_files/config_structure/outbounds/routing_live/
#  access_log/error_log/top_hosts/state/geo_autoupdate/print_summary,
#  run_split_tunnel_diagnostics, _DIAG_BLOCKED_DOMAINS/_DIAG_RUSSIAN_DOMAINS/
#  _DIAG_STATS_API_ADDR — вынесены в chimera.modules.diagnostics;
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
# warp — перенесено в chimera/modules/warp.py
# (do_live_traffic_dashboard вынесен в chimera.modules.diagnostics;
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
            # v57 (start-limit-fix): reset-failed перед start/restart — сбрасывает
            # счётчик StartLimitBurst юнита (fp-ротация может совпасть с другими
            # рестартами xray за то же окно).
            systemctl reset-failed xray >> "$LOG" 2>&1 || true
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
                # v57 (start-limit-fix): безопасный рестарт (reset-failed)
                if _xray_safe_restart(wait_active=15, attempts=2):
                    success(f"Fingerprint изменён на: {new_fp}, Xray перезапущен")
                else:
                    warn("Fingerprint изменён, но Xray не поднялся — journalctl -u xray -n 30")
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


# (check_exit_geo вынесен в chimera.modules.standalone_screens;
#  импорт — в верхней секции этого файла.)


# ---------------------------------------------------------------------------
#  4. МЕНЕДЖЕР МНОЖЕСТВЕННЫХ ПОЛЬЗОВАТЕЛЕЙ
# ---------------------------------------------------------------------------
USERS_FILE = CONFIG_DIR / "users.json"


# (_users_load, _users_save, _users_patch_config_no_restart,
#  _users_apply_to_config — вынесены в chimera.modules.users_manager;
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
        _box_item("6", f"IP whitelist (per-user, для ingress_geoip)")
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
                    # v58: pbk/sid с fallback на живой config.json —
                    # частично битый state.json не должен выдавать битые ссылки
                    try:
                        pub_key, short_id, _spx_fb = _reality_transport_params_from_state(st)
                        spiderx = st.get("spiderx", "") or _spx_fb or "/"
                    except Exception:
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
                    from chimera.modules.box_renderer import _print_link_warning
                    _print_link_warning(is_vless=True)
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

        elif ch == "6":
            #  per-user IP whitelist для ingress_geoip.
            # Делегирует в user_ip_whitelist.do_manage_user_ip_whitelist().
            try:
                from chimera.modules.user_ip_whitelist import do_manage_user_ip_whitelist
                do_manage_user_ip_whitelist()
            except Exception as e:
                warn(f"Не удалось открыть менеджер IP whitelist: {e}")
                time.sleep(1)

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


# ---------------------------------------------------------------------------
#  ЕДИНЫЙ МЕНЕДЖЕР ПОЛЬЗОВАТЕЛЕЙ (объединяет режимы A и B)
# ---------------------------------------------------------------------------

# (_unified_load_users, _unified_save_users — вынесены в
#  chimera.modules.users_manager; импорт — в верхней секции этого файла.)


def _unified_gen_link(u: dict) -> str:
    """Оставлен для совместимости. Используй _unified_show_links."""
    links = _unified_show_links(u, print_output=False)
    return links[0] if links else ""


# (_unified_show_links — вынесена в chimera.modules.users_manager;
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


# (_do_user_stats_screen — вынесена в chimera.modules.users_manager;
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
                        xhttp_mode= _state.get("xhttp_mode", "stream-up"),
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


def _show_device_limit_info_core() -> None:
    """Информация: ограничение доступа по устройствам в VLESS/REALITY."""
    print()
    _box_top("Ограничение доступа по устройствам")
    _box_row()
    _box_row(f"  {BOLD}Как работает VLESS/REALITY:{NC}")
    _box_row(f"  {DIM}UUID в ссылке — это идентификатор пользователя, не устройства.{NC}")
    _box_row(f"  {DIM}Xray-core не ограничивает количество одновременных подключений{NC}")
    _box_row(f"  {DIM}с одним UUID. Ссылку можно скопировать на сколько угодно устройств.{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {YELLOW}Рекомендуемый способ — отдельный UUID на каждое устройство:{NC}")
    _box_row()
    _box_row(f"  {DIM}Пример: создаёте 2 пользователя:{NC}")
    _box_row(f"    {CYAN}alice-iphone{NC}  {DIM}→ ссылка для iPhone{NC}")
    _box_row(f"    {CYAN}alice-macbook{NC}  {DIM}→ ссылка для MacBook{NC}")
    _box_row(f"  {DIM}Каждое устройство получает свою ссылку со своим UUID.{NC}")
    _box_row(f"  {DIM}Если одна ссылка утечёт — не затронет вторую.{NC}")
    _box_row(f"  {DIM}При удалении пользователя — отключается только его устройство.{NC}")
    _box_row()
    _box_row(f"  {GREEN}Это единственный надёжный способ в VLESS/REALITY.{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {YELLOW}Что насчёт HWID (Hardware ID)?{NC}")
    _box_row()
    _box_row(f"  {DIM}Коммерческие панели (Marzban, Hiddify Next, 3X-UI) используют{NC}")
    _box_row(f"  {DIM}кастомные форки Xray со своим proxy-слоем, который добавляет{NC}")
    _box_row(f"  {DIM}HWID-поле в handshake. Стандартный Xray-core HWID не поддерживает —{NC}")
    _box_row(f"  {DIM}VLESS-протокол просто не имеет такого поля.{NC}")
    _box_row()
    _box_row(f"  {DIM}Альтернативы, которые НЕ работают надёжно:{NC}")
    _box_row(f"  {DIM}• connlimit по IP — ломает NAT (2 устройства за роутером){NC}")
    _box_row(f"  {DIM}• Мониторинг access.log — race condition, хрупко{NC}")
    _box_row(f"  {DIM}• Блокировка по source IP — меняется при перезде/Wi-Fi смене{NC}")
    _box_row()
    _box_row(f"  {BOLD}Итог: создавайте отдельного пользователя на каждое устройство.{NC}")
    _box_bottom()
    input(f"  {CYAN}Нажмите Enter для возврата...{NC}")


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
                    # iOS-shadow помечаем явно — это служебная запись без flow,
                    # созданная через _users_get_or_create_ios_shadow для
                    # REALITY-юзера. Не реальный пользователь.
                    if u.get("is_ios_shadow"):
                        src_tag = f"{DIM}ios-shadow{NC}"
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
            _box_item("K", f"📱 iOS/Karing-ссылка для пользователя  {DIM}(без Vision flow){NC}")
            _box_item("E", f"Экспорт всех пользователей (ZIP с QR-кодами)")
            _box_item("I", f"Информация: ограничение доступа по устройствам")
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
                # v4.25: синхронизируем нового юзера во все активные спутниковые
                # протоколы (NaiveProxy, Mieru, TrustTunnel, sing-box, Telemt).
                # Если протокол не установлен — is_active() вернёт False, skip.
                _new_user_dict = {
                    "uuid": new_uuid, "email": email, "name": name,
                    "device_label": device_label,
                }
                _sync_result = _sync_user_to_protocols("add", _new_user_dict)
                _active_protos = [k for k, v in _sync_result.items() if v is not None]
                if _active_protos:
                    info(f"Синхронизирован со спутниковыми протоколами: {', '.join(_active_protos)}")
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
                    # v4.25: удаляем юзера из всех спутниковых протоколов.
                    _sync_result = _sync_user_to_protocols("remove", removed)
                    _active_protos = [k for k, v in _sync_result.items() if v is not None]
                    if _active_protos:
                        info(f"Удалён из спутниковых протоколов: {', '.join(_active_protos)}")
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
                    # v57 (start-limit-fix): безопасный рестарт (reset-failed) —
                    # применение юзеров может идти в цепочке с другими рестартами
                    if _xray_safe_restart(wait_active=15, attempts=2):
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
                    # v4.25: блокируем во всех спутниковых протоколах.
                    _sync_result = _sync_user_to_protocols("toggle_off", u)
                    _active_protos = [k for k, v in _sync_result.items() if v is not None]
                    if _active_protos:
                        info(f"Отключён в спутниковых протоколах: {', '.join(_active_protos)}")
                else:
                    success(f"Пользователь '{label}' ВОССТАНОВЛЕН")
                    # v4.25: восстанавливаем во всех спутниковых протоколах.
                    _sync_result = _sync_user_to_protocols("toggle_on", u)
                    _active_protos = [k for k, v in _sync_result.items() if v is not None]
                    if _active_protos:
                        info(f"Восстановлен в спутниковых протоколах: {', '.join(_active_protos)}")
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
                old_name  = u.get("name", "")
                # Сохраняем old_user dict для rename sync.
                _old_user_dict = dict(u)
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
                # v4.25: переименовываем во всех спутниковых протоколах.
                # rename sync передаёт old_user + new_user — каждый протокол
                # сам решает как обработать (sing-box: update name field in
                # place, TrustTunnel/NaiveProxy/Mieru: remove+add с тем же UUID).
                _new_user_dict = dict(users[idx])
                _sync_result = _sync_user_to_protocols(
                    "rename", _new_user_dict, old_user=_old_user_dict,
                )
                _active_protos = [k for k, v in _sync_result.items() if v is not None]
                if _active_protos:
                    info(f"Переименован в спутниковых протоколах: {', '.join(_active_protos)}")
                warn("Не забудьте применить список [5] чтобы Xray подхватил изменение email")
                input(f"{BLUE}Нажмите Enter...{NC}")

            elif ch == "e":
                if not users:
                    warn("Нет пользователей для экспорта")
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue
                _do_export_users_zip(users, install_mode)
                input(f"{BLUE}Нажмите Enter...{NC}")

            elif ch == "k":
                # iOS/Karing-ссылка для пользователя.
                # Логика выбора — ДОСЛОВНАЯ копия пункта "3" (Показать ссылку):
                # тот же паттерн `if not users`, `raw = input(...)`,
                # `raw.isdigit() and 1 <= int(raw) <= len(users)`,
                # `u = users[int(raw) - 1]`. Любая другая схема матчинга
                # (email/uuid) создала бы второй источник правды в одном меню.
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
                # do_user_show_link_ios_by_uuid берёт email НАПРЯМУЮ из
                # clients[] config.json по UUID (а не из этого объекта u),
                # чтобы избежать рассинхрона между users.json и clients[].
                do_user_show_link_ios_by_uuid(u["uuid"])
                input(f"{BLUE}Нажмите Enter...{NC}")

            elif ch == "i":
                _show_device_limit_info_core()

            elif ch in ("q", ""):
                break
            else:
                warn("Неверный выбор")
                time.sleep(1)
    finally:
        _BOX_W = _saved_BOX_W


# (do_manage_geo_update вынесен в chimera.modules.geo_files;
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

    # Базовый список (VLESS/Reality/state/users/geo/AS-direct) — остаётся
    # статическим, это ядро проекта, гарантированно стабильные пути.
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

    # ── АВТООБНАРУЖЕНИЕ протоколов через backup_registry ──────────────────────
    # Все спутниковые протоколы (Telemt, Mieru, NaiveProxy, FPTN, TrustTunnel,
    # sing-box семейство, AWG Standalone, Hysteria2, и любые будущие)
    # добавляют свой get_backup_paths() — здесь НИКАКИХ изменений не нужно
    # при появлении нового протокола. Это и есть APPEND-FREE дизайн.
    _discovered: list = []
    try:
        from chimera.modules.backup_registry import discover_backup_paths
        _discovered = discover_backup_paths()
        if _discovered:
            _export_list.extend(_discovered)
            dim(f"  + автообнаружено протоколов: {len(_discovered)} путей")
    except Exception as _e:
        warn(f"  Автообнаружение протоколов не удалось: {_e}")
        warn(f"  (статический список EXPORT_INCLUDE остаётся в силе)")

    # ── ПРЕДУПРЕЖДЕНИЕ О СЕРВЕРНЫХ СЕКРЕТАХ В НЕЗАШИФРОВАННОМ АРХИВЕ ───────────
    # Если архив НЕ шифруется (encrypt=False) И автообнаружение реально что-то
    # нашло — предупреждаем пользователя, что теперь в архиве лежат не только
    # VLESS/Reality/geo/AWG-Cascade, но и серверные секреты спутниковых
    # протоколов (MTProto-secret, NaiveProxy probe-secret, Hysteria2 TLS-key
    # и т.д. — задокументировано в get_backup_paths() каждого модуля).
    # При encrypt=True архив закрыт AES-256-CBC — предупреждать не о чем.
    # При пустом _discovered ничего сверх старого списка нет — предупреждать
    # тоже не о чем (архив как раньше, до ввода автообнаружения).
    if not encrypt and _discovered:
        warn(f"  ⚠ Архив НЕ зашифрован, но содержит серверные секреты "
             f"{len(_discovered)} доп. протоколов (MTProto/NaiveProxy/"
             f"Hysteria2 и др., если установлены) — TLS-ключи и "
             f"pre-shared секреты, без которых протокол не поднять "
             f"заново. Храните архив как приватный ключ. Для передачи "
             f"куда-либо — используйте шифрованный экспорт (пункт "
             f"«Экспорт с шифрованием»).")

    with tempfile.TemporaryDirectory(prefix="xray_export_") as tmpdir:
        tmp = Path(tmpdir)
        copied = []

        for src, dest_name in _export_list:
            if src.exists():
                dest_path = tmp / dest_name
                # dest_name теперь может быть вложенным ("telemt/telemt.toml",
                # "etc/systemd/system/mita.service", и т.д. — arcname из
                # discover_backup_paths). Создаём parent-директорию,
                # иначе shutil.copy2 упадёт с FileNotFoundError.
                # (migration.py::do_full_migration_export делает так же.)
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest_path)
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
            Chimera Project — архив конфигурации
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
        # v57 (start-limit-fix): безопасный рестарт (reset-failed)
        if _xray_safe_restart(wait_active=15, attempts=2):
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
#  do_manage_scheduled_backup — вынесены в chimera.modules.backup_manager;
#  импорт — в верхней секции этого файла.)


# ---------------------------------------------------------------------------
#  7. ТЕСТ СКОРОСТИ ЧЕРЕЗ EXIT-НОДЫ (все ноды по очереди)
# ---------------------------------------------------------------------------
# (Chain/Nodes — _speed_test_node_latency, _speed_test_node_geo — вынесены в
#  chimera.modules.chain_nodes; импорт — в верхней секции этого файла.)


def _speed_test_download(resolve_host: str, resolve_ip: str, port: int, size_mb_target: int = 10) -> str:
    """
    Измеряет скорость загрузки с Cloudflare.
    size_mb_target — размер файла в МБ (10 / 100 / 500 / 1000).
    Возвращает строку с результатом.

    DoH-резолв speed.cloudflare.com через _resolve_host_fresh (Cloudflare/Google
    JSON API), минуя серверный DNS. Это КРИТИЧНО после фикса DNS-leak —
    серверный DNS направлен на 127.0.0.1 (DNSCrypt-proxy), и если DNSCrypt
    не может резолвить speed.cloudflare.com (или работает медленно) — curl
    падает с "Cloudflare недоступен с сервера". DoH обходит это: IP
    передаётся в curl через --resolve, системный резолвер не используется.

    Fallback: если DoH не сработал — обычный curl (через системный DNS).
    """
    bytes_count = size_mb_target * 1024 * 1024
    timeout = max(60, size_mb_target * 8)
    url = f"https://speed.cloudflare.com/__down?bytes={bytes_count}"

    cf_ip = _cf_resolve_ip()

    try:
        curl_cmd = [
            "curl", "-s", "-o", "/dev/null", "--max-time", str(timeout),
            "-w", "%{size_download} %{time_total} %{speed_download}",
        ]
        # Если DoH отдал IP — передаём в curl через --resolve, чтобы обойти
        # системный DNS. Иначе curl будет резолвить через /etc/resolv.conf.
        if cf_ip:
            curl_cmd += ["--resolve", f"speed.cloudflare.com:443:{cf_ip}"]
        curl_cmd.append(url)

        r = _run(curl_cmd, capture=True, check=False)
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


def _cf_resolve_ip() -> Optional[str]:
    """Резолвит speed.cloudflare.com через DoH (Cloudflare/Google JSON API),
    минуя серверный DNS.

    Возвращает IP-строку или None при ошибке. None означает, что caller
    должен использовать fallback (обычный curl через системный DNS).

    Зачем: после фикса DNS-leak серверный DNS направлен на 127.0.0.1
    (DNSCrypt-proxy). Если DNSCrypt не может резолвить speed.cloudflare.com
    (или работает медленно) — curl падает. DoH обходит это.
    """
    try:
        from chimera.modules.chain_nodes import _resolve_host_fresh
        return _resolve_host_fresh("speed.cloudflare.com")
    except Exception:
        return None


def _cf_probe_available(probe_bytes: int = 1048576, timeout: int = 15) -> bool:
    """Проверяет доступность Cloudflare SpeedTest endpoint.

    Использует DoH-резолв + --resolve в curl, минуя серверный DNS —
    см. _cf_resolve_ip(). Возвращает True если Cloudflare доступен.
    """
    cf_ip = _cf_resolve_ip()
    curl_cmd = [
        "curl", "-s", "-o", "/dev/null", "--max-time", str(timeout),
        "-w", "%{size_download}",
    ]
    if cf_ip:
        curl_cmd += ["--resolve", f"speed.cloudflare.com:443:{cf_ip}"]
    curl_cmd.append(f"https://speed.cloudflare.com/__down?bytes={probe_bytes}")
    r = _run(curl_cmd, capture=True, check=False)
    return r.returncode == 0 and int(r.stdout.strip() or 0) > 500_000


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
    _probe_ok = _cf_probe_available()

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

# (Chain/Nodes — _access_log_bytes_per_node, do_node_health_matrix — вынесены в
#  chimera.modules.chain_nodes; импорт — в верхней секции этого файла.)


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
            # Возможные форматы ответа check-host.net:
            #   Старый формат (до 2026):
            #     [[1, "ip", latency_s]]       — успех (порт открыт)
            #     [[0, "ip", null]]            — отклонено (порт закрыт/заблокирован)
            #     [null]                       — таймаут
            #   Новый формат (с 2026):
            #     [{"address": "ip", "time": 0.047}]   — успех
            #     [{"error": "Connection timed out"}]  — ошибка ноды/таймаут
            #     []                                    — пустой список
            first = res_list[0] if isinstance(res_list, list) and res_list else None
            if first and isinstance(first, list) and len(first) >= 1:
                # Старый формат: [[1, "ip", latency_s]] или [[0, "ip", null]]
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
            elif first and isinstance(first, dict):
                # Новый формат: dict вместо list.
                # Если есть "address" и "time" — успех.
                # Если есть "error" — ошибка ноды.
                if "address" in first and "time" in first:
                    # Успешное подключение.
                    ok = True
                    lat_s = first.get("time")
                    stat_str = f"{GREEN}открыт{NC}"
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
                elif "error" in first:
                    # Нода вернула ошибку — показываем её текст.
                    err_text = str(first.get("error", "unknown"))[:30]
                    stat_str = f"{YELLOW}ошибка: {err_text}{NC}"
                    lat_str  = f"{DIM}—{NC}"
                    # НЕ засчитываем в ru_total/eu_total — это сбой ноды.
                else:
                    # Неизвестный формат dict — показываем как есть.
                    stat_str = f"{YELLOW}?{NC}"
                    lat_str  = f"{DIM}—{NC}"
            else:
                # таймаут [null] или пустой список — недоступен.
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

    # Резолв домена через DoH + fallback (минуя локальный DNS-кэш),
    # чтобы TCP-пробы шли на АКТУАЛЬНЫЙ IP сервера.
    try:
        from chimera.modules.chain_nodes import _resolve_host_fresh
        ip = _resolve_host_fresh(domain)
    except Exception:
        ip = None
    if not ip:
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


# (do_speed_test — вынесен в chimera.modules.speed_test;
#  импорт — в верхней секции этого файла.)


# (do_reconfigure — вынесен в chimera.modules.reconfigure;
#  импорт — в верхней секции этого файла.)


# (SSH Hardening — _ssh_2fa_install, do_ssh_hardening, _SSHD_CONFIG, _SSHD_BACKUP —
#  вынесен в chimera.modules.ssh_hardening; импорт — в верхней секции
#  этого файла.)


# (UUID rotation — _uuid_rotate_now, _uuid_install_cron, do_manage_uuid_rotation,
#  _UUID_CRON_TAG, _UUID_CRON_SCRIPT — вынесены в
#  chimera.modules.credential_rotation; импорт — в верхней секции
#  этого файла.)


# (REALITY keys rotation — _rotate_reality_keys, do_manage_reality_keys —
#  вынесены в chimera.modules.credential_rotation; импорт — в
#  верхней секции этого файла.)


# (watchdog — _watchdog_install, _watchdog_remove, do_manage_watchdog —
#  вынесен в chimera.modules.fail2ban_setup; импорт — в верхней
#  секции этого файла.)


# (do_view_logs вынесен в chimera.modules.standalone_screens;
#  импорт — в верхней секции этого файла.)


# (do_check_domain_external вынесен в chimera.modules.standalone_screens;
#  импорт — в верхней секции этого файла.)


# (Failover — _failover_load/save/install, do_failover_status, _FAILOVER_*
#  — вынесены в chimera.modules.failover; импорт — в верхней секции
#  этого файла.)


# =============================================================================
#  ГЕНЕРАЦИЯ CLASH META / SING-BOX КОНФИГА
# =============================================================================
# (do_generate_client_config, do_export_client_config вынесены в
#  chimera.modules.client_config_export; импорт — в верхней
#  секции этого файла.)


# =============================================================================
#  ДАШБОРД СИСТЕМНЫХ РЕСУРСОВ
# =============================================================================
# (do_generate_client_config, do_export_client_config вынесены в
#  chimera.modules.client_config_export; импорт — в верхней
#  секции этого файла.)


# (do_system_dashboard вынесен в chimera.modules.standalone_screens;
#  импорт — в верхней секции этого файла.)


# (do_full_diagnostic — мастер полной диагностики, ~800 строк, wizard — вынесен
#  в chimera.modules.diagnostics; импорт — в верхней секции этого файла.)

# =============================================================================

# (Traffic limits — TRAFFIC_LIMITS_FILE, _limits_load/save,
#  _query_user_traffic_bytes, _stats_api_is_configured,
#  _check_traffic_limits_once, do_manage_traffic_limits — вынесены в
#  chimera.modules.traffic_tracking; импорт — в верхней секции
#  этого файла.)


# (TTL users + blocked — TTL_FILE/CRON_SCRIPT/CRON_FILE/LOG, BLOCKED_FILE,
#  _ttl_load/save/expires_str/is_expired/expires_within_hours/set/remove,
#  _blocked_load/save, _ttl_block_user/unblock_user/is_blocked,
#  _ttl_check_and_expire, _ttl_install_cron/remove_cron/cron_active,
#  do_manage_ttl_users — вынесены в chimera.modules.ttl_users;
#  импорт — в верхней секции этого файла.)


# (do_share_config_server вынесен в chimera.modules.client_config_export;
#  импорт — в верхней секции этого файла.)


# (Health report — do_health_report, _health_report_install_cron,
#  do_manage_health_report — вынесены в chimera.modules.health_report;
#  импорт — в верхней секции этого файла.)


# (Full migration — TG_CONFIG_FILE, do_full_migration_export,
#  do_full_migration_import — вынесены в chimera.modules.migration;
#  импорт — в верхней секции этого файла.)


# (Traffic history — TRAFFIC_HISTORY_FILE, _traffic_snapshot_save,
#  _install_traffic_snapshot_cron, do_traffic_history — вынесены в
#  chimera.modules.traffic_history; импорт — в верхней секции этого файла.)


# (GeoIP-блокировка — do_manage_geoip_block, _geoip_block_get_rules,
#  _geoip_apply_routing, _geoip_set_allowlist, _geoip_add_country_block,
#  _geoip_add_scanner_block — вынесены в chimera.modules.geoip_block;
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
#  RIPE_STAT_PREFIXES_URL — вынесены в chimera.modules.ru_subnets
#  и chimera.modules.as_direct; импорт — в верхней секции этого файла.)


# (_geoip_remove_all вынесен в chimera.modules.geoip_block;
#  импорт — в верхней секции этого файла.)


# (Аудит подключений — do_connection_audit, _parse_access_log,
#  _audit_user_summary, _audit_recent_connections, _audit_suspicious,
#  _audit_active_now — вынесены в chimera.modules.connection_audit;
#  импорт — в верхней секции этого файла.)

# (AutoBan — _ban_report_rotate/append/show_in_box, _autoban_load/save/
#  get_chain_ips/run_once/install_cron, do_manage_autoban,
#  _XRAY_BAN_STATE/CRON/SCRIPT/LOG/REPORT, _BAN_THRESHOLD_DEFAULT,
#  _BAN_WINDOW_MINUTES, _BAN_WHITELIST_DEFAULT, _BAN_REPORT_TTL_DAYS —
#  вынесены в chimera.modules.autoban; импорт — в верхней секции
#  этого файла.)


# (Certbot monitor — _certbot_renew_and_notify, _certbot_install_monitor_cron,
#  do_manage_certbot_monitor, _CERTBOT_MONITOR_CRON, _CERTBOT_MONITOR_SCRIPT —
#  вынесены в chimera.modules.ssl_certbot; импорт — в верхней секции
#  этого файла.)


# (Quick status — do_quick_status — вынесен в chimera.modules.quick_status;
#  импорт — в верхней секции этого файла.)


# =============================================================================
#  ФИЧА 4: СОРТИРОВКА В СТАТИСТИКЕ ПОЛЬЗОВАТЕЛЕЙ
# =============================================================================
# (интегрируется в _do_user_stats_screen через аргумент sort_key)
# Реализована как отдельная обёртка, которая вызывается из меню U→4

# (_STATS_SORT_KEYS — вынесен в chimera.modules.quick_status;
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


# (_do_user_stats_screen_v2 — вынесена в chimera.modules.users_manager;
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
#  вынесены в chimera.modules.quick_status; импорт — в верхней секции
#  этого файла.)


# =============================================================================
#  ФИЧА 8: ЛОГ ИЗМЕНЕНИЙ КОНФИГА
# =============================================================================
CHANGES_LOG_FILE = Path("/var/log/xray-changes.log")
CHANGES_DB_FILE  = Path("/var/lib/xray-installer/changes.json")


def _sync_user_to_protocols(action: str, user: dict,
                            old_user: dict = None) -> dict:
    """Синхронизирует действие над VLESS-пользователем со всеми спутниковыми
    протоколами (NaiveProxy, Mieru, TrustTunnel, sing-box, MTProto/Telemt).

    v4.25: раньше TUI do_unified_user_manager только писал в users.json + xray
    config.json. Satellite-протоколы НЕ обновлялись → юзер получал VLESS-ссылку,
    но не получал naive+https://, mierus://, tt://, trojan://, tg://proxy.

    Теперь: после _unified_save_users(users) вызываем эту функцию. Она через
    rest_api._SYNCABLE_PROTOCOLS реестр диспатчит action на все активные
    протоколы. Каждый протокол сам решает как обработать action (см. контракты
    в chimera/modules/<proto>.py: is_active / ensure_user_full / remove_user_full
    / rename_user_full).

    Args:
      action: "add" | "remove" | "rename" | "toggle_off" | "toggle_on"
      user: full user dict (uuid, email, name, device_label)
      old_user: для rename — старый dict (с old email)

    Returns:
      {proto_name: bool|None} — результат на каждом протоколе.
      None = протокол не активен (is_active=False), пропущен.
    """
    try:
        from chimera.modules.rest_api import (
            _sync_ensure_user, _sync_remove_user, _sync_rename_user,
        )
        if action == "add":
            return _sync_ensure_user(user.get("name", ""), user=user)
        elif action == "remove":
            return _sync_remove_user(user.get("name", ""), user=user)
        elif action == "rename" and old_user:
            return _sync_rename_user(
                old_user.get("name", ""), user.get("name", ""),
                old_user=old_user, new_user=user,
            )
        elif action in ("toggle_off", "toggle_on"):
            # Toggle: на off — remove (аккаунт инвалидируется), на on — add.
            # VLESS-блокировка идёт через _user_toggle_disabled + apply [5],
            # satellite-протоколы блокируем здесь.
            if action == "toggle_off":
                return _sync_remove_user(user.get("name", ""), user=user)
            else:
                return _sync_ensure_user(user.get("name", ""), user=user)
        return {}
    except Exception as e:
        try:
            warn(f"Синхронизация спутниковых протоколов не удалась: {e}")
        except Exception:
            print(f"Синхронизация не удалась: {e}")
        return {}


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

    # v57 (start-limit-fix): безопасный рестарт (reset-failed) вместо
    # голого restart + sleep(3)
    _ok = _xray_safe_restart(wait_active=15, attempts=2)
    _r2 = _run(["pgrep", "-x", "xray"], capture=True, check=False)
    if _ok and _r2.returncode == 0:
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
# box_renderer — перенесено в chimera/modules/box_renderer.py
# (do_emergency_repair — вынесена в chimera.modules.emergency_repair;
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
        _box_item("5b", f"♻️  Перегенерировать конфиг Xray  {DIM}(из state.json, с minClientVer для 26.7.11+){NC}")
        _box_item("6", f"🛠️  Аварийное восстановление  {DIM}(из state.json, без переустановки){NC}")
        _box_item("7", "🗑️  Удалить установку")
        _box_item("8", "🧪 Запустить unit-тесты")
        _box_item("9", f"🔀 Mieru Hybrid Addon  {DIM}(Mieru поверх Xray на Entry-ноде, SOCKS-петля){NC}")
        _box_sep()
        _box_item("W", f"🌐 Веб-панель управления  {DIM}(Admin Panel + User Portal + REST API){NC}")
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
        elif ch == "5b":
            do_rebuild_xray_config()
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
        elif ch.lower() == "w":
            do_manage_web_panel()
        elif ch.lower() == "q" or ch == "":
            break
        else:
            warn("Неверный выбор.")
            time.sleep(1)


def _menu_migration() -> None:
    """Подменю миграции (экспорт/импорт).

    Решение по dual-system (см. CHANGELOG.md / git history commit 7acdbfb):
    migration.py был извлечён из _core.py как рефакторинг-перенос (Tier-3
    group 5), НЕ как замена. Оба инструмента остаются:
      • [1]/[2] do_full_migration_export/import — полная миграция на другой
        сервер: config + state + users + traffic_limits + telegram +
        SSL-сертификаты + systemd unit, обязательно зашифровано AES-256-CBC.
      • [3] do_export_config — стандартный нешифрованный бэкап ядра проекта
        (VLESS/Reality/state/users/geo/AS-direct).
      • [4] _import_users_only — ИМПОРТ ТОЛЬКО ПОЛЬЗОВАТЕЛЕЙ из любого
        tar.gz-архива. Безопасно после переустановки сервера: не трогает
        config.json/state.json, не требует совпадения socket-пути.
        РАНЬШЕ был мёртвым кодом (do_manage_backup() с пунктом 4 нигде не
        вызывался) — теперь вернули в живое меню.
    Оба инструмента [1]/[3] теперь ТАКЖЕ получают пути через автообнаружение
    chimera.modules.backup_registry — то есть Telemt/Mieru/NaiveProxy/FPTN/
    TrustTunnel/sing-box/AWG-Standalone/Hysteria2 едут в архивы автоматически,
    без правок этих функций при добавлении новых протоколов.
    """
    while True:
        os.system("clear")
        print()
        _box_top("📦  МИГРАЦИЯ КОНФИГУРАЦИИ")
        _box_row()
        _box_item("1", f"📤 Экспорт  {DIM}(зашифрованный архив, для миграции){NC}")
        _box_item("2", f"📥 Импорт  {DIM}(восстановить из .tar.gz или .tar.gz.enc){NC}")
        _box_item("3", f"📄 Стандартный экспорт  {DIM}(без шифрования){NC}")
        _box_item("4", f"👥 Импорт только пользователей  {DIM}(безопасно после переустановки){NC}")
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
        elif ch == "4":
            print()
            archive_raw = input(f"  Путь к архиву (.tar.gz): ").strip()
            ap = Path(archive_raw)
            if not ap.exists():
                warn(f"Файл не найден: {ap}")
            else:
                info("Импорт только пользователей из архива...")
                _import_users_only(ap)
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
        _box_item("K", f"📱 iOS/Karing-ссылки  {DIM}(сводный экран, без Vision flow){NC}")
        _box_item("R", f"🌐 Sing-box rulesets  {DIM}(Podkop/OpenWrt: РФ → direct, заблок. → proxy){NC}")
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
                from chimera.modules.subscription import do_subscription_menu
                do_subscription_menu()
            except ImportError as _e:
                warn(f"Модуль Единой подписки не найден: {_e}")
                time.sleep(2)
        elif ch.lower() == "m":
            try:
                from chimera.modules.entry_mirrors import do_entry_mirrors_menu
                do_entry_mirrors_menu()
            except ImportError as _e:
                warn(f"Модуль Entry Mirrors не найден: {_e}")
                time.sleep(2)
        elif ch.lower() == "k":
            _load_state_into_globals()
            if not PARAM_DOMAIN:
                warn("Параметры не найдены. Сначала установите (раздел 1).")
                time.sleep(2)
                continue
            generate_client_links_ios()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch.lower() == "r":
            try:
                from chimera.modules.singbox_client_rulesets import (
                    do_manage_singbox_rulesets,
                )
                do_manage_singbox_rulesets()
            except ImportError as _e:
                warn(f"Модуль singbox_client_rulesets не найден: {_e}")
                time.sleep(2)
            except Exception as _e:
                warn(f"Ошибка в singbox_client_rulesets: {_e}")
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

    # v57 (start-limit-fix): безопасный рестарт (reset-failed)
    if _xray_safe_restart(wait_active=15, attempts=2):
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
        _box_item("RA", f"🛡️ DNSCrypt: расширенная настройка  {DIM}(198 серверов, ODoH, DNSSEC, анонимизация){NC}")
        _box_item("A", f"🛡️ AdGuard Home  {DIM}(DNS :53 + фильтры + DoH/DoT — поверх DNSCrypt){NC}")
        _box_item("4", f"☁️  Cloudflare WARP  {DIM}(управление туннелем){NC}")
        _box_item("5", f"🔄 Сменить домен / порт  {DIM}(без переустановки){NC}")
        _box_item("6", f"🌍 Стратегия исходящих  {DIM}(domainStrategy){NC}")
        _box_item("7", f"📡 Exit-ноды каскада  {DIM}(Режим B, до 10 нод){NC}")
        _box_item("8", f"🔗 Сводка каскадного прокси  {DIM}(Режим B){NC}")
        _box_item("9", "🌐 Внешняя проверка домена / порта")
        _box_item("0", "🌐 Геопроверка выходного IP")
        _box_sep()
        _box_item("D", f"🌐 Кастомные DNS правила  {DIM}(hosts / routing override){NC}")
        _box_item("DR", f"🔒 Принудительный DNS REDIRECT  {DIM}(NAT на dnscrypt-proxy, anti-leak){NC}")
        _box_item("M", f"📏 MTU/MSS автотюнинг  {DIM}(оптимизация для exit-нод){NC}")
        _box_item("X", f"⚡ XTLS-flow режим  {DIM}(Vision / Splice / none — только REALITY){NC}")
        _box_item("P", f"🧪 Постквантовый VLESS  {DIM}(экспериментально, отдельный порт){NC}")
        _box_sep()
        _box_item("Y", f"📺 YouTube через RU  {DIM}(geosite:youtube → direct/exit toggle){NC}")
        _box_item("B", f"🛡 DPI Bypass (b4)  {DIM}(централизованный, для любых заблокированных ресурсов){NC}")
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
        elif ch.lower() == "ra":
            do_dnscrypt_advanced_menu()
        elif ch.lower() == "a":
            # AdGuard Home — DNS-сервер :53 (кеш+фильтры) поверх DNSCrypt :5300.
            try:
                from chimera.modules.aghome_setup import do_aghome_menu
                do_aghome_menu()
            except ImportError as e:
                warn(f"Модуль aghome_setup не найден: {e}")
                time.sleep(2)
        elif ch.lower() == "dr":
            do_manage_dns_redirect()
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
                    from chimera.modules.pq_vless import do_manage_pq_vless
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
        elif ch.lower() == "y":
            # YouTube routing toggle: geosite:youtube → direct (RU entry) or
            # default (exit nodes via catch-all). Independent of split tunnel.
            _load_state_into_globals()
            try:
                from chimera.modules.youtube_route import do_manage_youtube_via_ru
                do_manage_youtube_via_ru()
            except ImportError as e:
                warn(f"Модуль youtube_route не найден: {e}")
                time.sleep(2)
        elif ch.lower() == "b":
            # DPI Bypass (b4) — централизованный, для любых заблокированных ресурсов.
            try:
                from chimera.modules.dpi_bypass import do_dpi_bypass_menu
                do_dpi_bypass_menu()
            except ImportError as e:
                warn(f"Модуль dpi_bypass не найден: {e}")
                time.sleep(2)
        elif ch.lower() == "q" or ch == "":
            break
        else:
            warn("Неверный выбор.")
            time.sleep(1)


# =============================================================================
#  DNS LEAK TEST
# =============================================================================
def _render_dns_reconciliation_box(configured_resolvers: list) -> None:
    """Рендерит блок «Сверка конфигурации» в конце DNS Leak Test.

    Выделен в отдельную функцию для тестопригодности —
    do_dns_leak_test() делает реальные сетевые запросы (dig, API),
    что делает её неподъёмной для unit-тестов. Эта функция работает
    только с переданным списком configured_resolvers и health_check,
    поэтому покрывает все 5 кейсов из tests/test_core_dns_redirect_integration.py.

    Логика (исправлен false negative из коммита 038540f):
      - loopback → зелёное "проксируется локально"
      - non-loopback + redirect_active (enabled AND rules_applied) →
        зелёное "редирект активен — трафик заворачивается на dnscrypt-proxy"
      - non-loopback + redirect НЕ активен (включая dnscrypt active но
        rules_applied=False) → жёлтое "DNS уходит напрямую, минуя Xray"
    """
    if not configured_resolvers:
        return
    print()
    _box_top("Сверка конфигурации")
    is_loopback = any(ip.startswith("127.") or ip == "::1"
                      for ip in configured_resolvers)
    # FIX: правильное условие для зелёного цвета.
    #
    # Коммит 038540f исправил визуальный баг — жёлтое
    # "DNS уходит напрямую" рисовалось даже при активном DNSCrypt.
    # НО он сделал это проверкой dnscrypt_active (процесс запущен),
    # что является false negative: dnscrypt-proxy может быть active
    # без того, чтобы системный DNS-трафик реально шёл через него —
    # для этого нужны применённые iptables-правила редиректа 53 порта.
    # Это прямо описано в dns_redirect.py:291-292: "редирект включён
    # в state, но правила в iptables отсутствуют".
    #
    # Вместо dnscrypt_active проверяем redirect_active =
    # health_check_dns_redirect()["enabled"] AND ["rules_applied"].
    # Это значит, что зелёный цвет показывается ТОЛЬКО когда трафик
    # реально перехватывается, не просто когда сервис запущен.
    dnscrypt_active = _run(
        ["systemctl", "is-active", "dnscrypt-proxy"],
        capture=True, check=False
    ).stdout.strip() == "active"
    try:
        _hc = health_check_dns_redirect()
        redirect_active = bool(_hc.get("enabled")) and bool(_hc.get("rules_applied"))
    except Exception:
        # fallback: если health_check_dns_redirect() упал (например,
        # state.json повреждён), не маскируем потенциальную утечку
        # зелёным — показываем жёлтое как реальный риск.
        redirect_active = False
    ns_str = ", ".join(configured_resolvers)
    if is_loopback:
        line1 = f"  {GREEN}✓ /etc/resolv.conf → localhost — DNS проксируется локально{NC}"
        line2 = f"    {DIM}({ns_str}){NC}"
        _box_row(line1)
        _box_row(line2)
    elif redirect_active:
        # DNS-редирект реально активен: правила в iptables применены,
        # трафик 53 порта принудительно заворачивается на dnscrypt-proxy.
        # Зелёное обоснованно — даже при внешних DNS в resolv.conf.
        _box_row(f"  {GREEN}✓ /etc/resolv.conf → внешний DNS ({ns_str}){NC}")
        _box_row(f"  {GREEN}  DNS-редирект активен — трафик принудительно "
                 f"заворачивается на dnscrypt-proxy{NC}")
    else:
        # Жёлтое: либо dnscrypt не запущен, либо запущен но правила
        # не применены (enabled=True, rules_applied=False) — оба случая
        # реально означают, что DNS уходит напрямую на 8.8.8.8/1.1.1.1.
        _box_row(f"  {YELLOW}⚠ /etc/resolv.conf → внешний DNS "
                 f"({ns_str}){NC}")
        _box_row(f"  {YELLOW}  DNS-запросы уходят напрямую, минуя Xray tunnel{NC}")
    dc_str = f"{GREEN}активен{NC}" if dnscrypt_active else f"{DIM}не запущен{NC}"
    _box_row(f"  DNSCrypt-proxy: {dc_str}")
    _box_row()
    _box_bottom()


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
        _box_row()
        _box_row(f"  {GREEN}  🔄  Авто-фикс: направить /etc/resolv.conf → 127.0.0.1{NC}")
        _box_row(f"  {DIM}     (через resolv_conf_fix.py — systemd-resolved drop-in или{NC}")
        _box_row(f"  {DIM}      static rewrite, с бэкапом и возможностью отката){NC}")
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
    # Блок выделен в _render_dns_reconciliation_box() для
    # тестопригодности. Логика описана в docstring функции.
    _render_dns_reconciliation_box(configured_resolvers)

    print()
    # ── Авто-фикс при обнаружении leak ──────────────────────────────────────
    # Если найдены RU-резолверы — предлагаем сразу открыть экран авто-фикса
    # /etc/resolv.conf (resolv_conf_fix.py). Не заставляем пользователя лезть
    # в файл руками — особенно на Ubuntu 24.04, где resolv.conf — симлинк на
    # systemd-resolved stub и прямая правка бесполезна.
    if leak_detected:
        try:
            _fix_input = input(
                f"{BLUE}Открыть экран авто-фикса /etc/resolv.conf? [Y/n]: {NC}"
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            _fix_input = "n"
        if _fix_input in ("", "y", "yes", "д", "да"):
            print()
            try:
                do_fix_resolv_conf_interactive()
            except Exception as _e:
                print(f"  {RED}Ошибка экрана авто-фикса: {_e}{NC}")
                input(f"{BLUE}Нажмите Enter...{NC}")
    else:
        input(f"{BLUE}Нажмите Enter...{NC}")


# =============================================================================
#  ПОДМЕНЮ: 4 — ДИАГНОСТИКА И МОНИТОРИНГ
# =============================================================================
def _do_dns_redirect_health_screen() -> None:
    """Экран health-check для принудительного DNS REDIRECT (диагностика)."""
    print()
    _box_top("🔒  DNS Redirect Health Check")
    hc = health_check_dns_redirect()
    # hc["port"] — реальный порт из state (target_port), добавлен в
    # health_check_dns_redirect() начиная с commit фиксинга 4 багов.
    # Ранее использовался hc.get('port', 5300) — но ключа 'port' не было,
    # поэтому всегда рисовался дефолт 5300 даже если state.target_port=6000.
    _port = hc.get("port", 5300)
    _box_row(f"  Включён в state:     {GREEN if hc['enabled'] else DIM}"
             f"{'да' if hc['enabled'] else 'нет'}{NC}")
    _box_row(f"  dnscrypt-proxy:      {GREEN if hc['dnscrypt_active'] else RED}"
             f"{'активен' if hc['dnscrypt_active'] else 'НЕ активен'}{NC}")
    _box_row(f"  Порт {_port}/udp:     "
             f"{GREEN if hc['port_listening_udp'] else RED}"
             f"{'слушается' if hc['port_listening_udp'] else 'НЕ слушается'}{NC}")
    _box_row(f"  Порт {_port}/tcp:     "
             f"{GREEN if hc['port_listening_tcp'] else RED}"
             f"{'слушается' if hc['port_listening_tcp'] else 'НЕ слушается'}{NC}")
    _box_row(f"  Правила iptables:    {GREEN if hc['rules_applied'] else DIM}"
             f"{'применены' if hc['rules_applied'] else 'отсутствуют'}{NC}")
    _box_row(f"  IPv6 support:        {GREEN if hc['ipv6_supported'] else YELLOW}"
             f"{'да' if hc['ipv6_supported'] else 'нет (только IPv4)'}{NC}")
    _box_sep()
    if hc["issues"]:
        _box_warn("  Обнаружены проблемы:")
        for issue in hc["issues"]:
            _box_warn(f"    • {issue}")
    else:
        _box_row(f"  {GREEN}OK — проблем не обнаружено{NC}")
    _box_sep()
    _box_row(f"  {DIM}Рекомендация: {hc['recommendation']}{NC}")
    _box_bottom()
    input(f"{BLUE}Нажмите Enter...{NC}")


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
        _box_item("DN", f"🔒 DNS Redirect health-check  {DIM}(проверка iptables NAT REDIRECT){NC}")
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
        _box_sep()
        _box_item("SF", f"🖥️  Server-side Fragment  {DIM}(Fragment на INBOUND — ServerHello/Cert, симметрия с клиентом){NC}")
        _box_sep()
        _box_item("DT", f"🧪 Диагностические тесты  {DIM}(unit-тесты по группам){NC}")
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
        elif ch.lower() == "dn":
            _do_dns_redirect_health_screen()
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
        elif ch.lower() == "sf":
            try:
                do_server_fragment_menu()
            except Exception as _e:
                warn(f"Модуль server_fragment недоступен: {_e}")
                time.sleep(2)
        elif ch.lower() == "dt":
            try:
                from chimera.modules.test_runner import do_test_runner_menu
                do_test_runner_menu()
            except ImportError as _e:
                warn(f"Модуль тестов не найден: {_e}")
                time.sleep(2)
        elif ch.lower() == "q" or ch == "":
            break
        else:
            warn("Неверный выбор.")
            time.sleep(1)


# =============================================================================
#  ПОДМЕНЮ: 5 — БЕЗОПАСНОСТЬ И АВТОМАТИЗАЦИЯ
# logrotate — перенесено в chimera/modules/logrotate.py
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
        _box_item("TC", f"🤖 Telegram Client Bot  {DIM}(self-service: /config /qr /status){NC}")
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
        elif ch.lower() == "tc":
            do_tg_client_bot_menu()
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


# (_menu_rotation вынесен в chimera.modules.credential_rotation;
#  импорт — в верхней секции этого файла.)


# =============================================================================
#  v58: ANTI-EMPTY IDENTITY GUARD
#  Гарантия непустых идентификационных параметров (UUID, ShortID, REALITY-
#  ключи, домен, сокет, spiderX) перед ЛЮБОЙ генерацией/регенерацией конфига.
#  Пустой privateKey/shortIds/uuid в config.json = REALITY-handshake рвётся
#  у ВСЕХ клиентов со ссылками, выданными до регенерации.
# =============================================================================
def _identity_read_live_config() -> dict:
    """
    Читает ЖИВОЙ xray config.json (первый найденный из двух путей) и
    достаёт идентификационные параметры. Возвращает dict (пустой, если
    конфига нет/битый):
      uuid, short_id, private_key, public_key, domain(sni), spiderx
    """
    for cfg_path in (CONFIG_DIR / "config.json",
                     Path("/usr/local/etc/xray/config.json")):
        try:
            if not cfg_path.exists():
                continue
            cfg = json.loads(cfg_path.read_text())
            out: dict = {}
            for inb in cfg.get("inbounds", []):
                rs = inb.get("streamSettings", {}).get("realitySettings", {})
                if not rs:
                    continue
                if not out.get("private_key"):
                    out["private_key"] = rs.get("privateKey", "") or ""
                if not out.get("public_key"):
                    out["public_key"] = rs.get("publicKey", "") or ""
                sids = rs.get("shortIds", [])
                if not out.get("short_id") and sids:
                    out["short_id"] = str(sids[0]) if sids[0] else ""
                if not out.get("spiderx"):
                    out["spiderx"] = rs.get("spiderX", "") or ""
                sn = rs.get("serverNames", [])
                if not out.get("domain") and sn:
                    out["domain"] = sn[0] or ""
                if not out.get("uuid"):
                    clients = inb.get("settings", {}).get("clients", [])
                    if clients:
                        out["uuid"] = clients[0].get("id", "") or ""
                break
            if out:
                return out
        except Exception:
            continue
    return {}


def _identity_pubkey_from_privkey(priv: str) -> str:
    """Выводит публичный x25519-ключ из приватного (xray x25519 -i)."""
    try:
        r = _run([str(XRAY_BIN), "x25519", "-i", priv],
                 capture=True, check=False)
        if r.returncode == 0 and r.stdout:
            # Парсер из xray_install — работает со всеми версиями xray
            # (включая v26+, где PublicKey печатается как Password).
            _priv, pub = _parse_x25519_keys(r.stdout)
            if pub:
                return pub
    except Exception:
        pass
    return ""


def _identity_params_recover() -> list:
    """
    v58: Anti-Empty Identity Guard — ЕДИНАЯ точка гарантии того, что при
    генерации/регенерации конфига Xray идентификационные параметры не
    останутся пустыми. Вызывается из всех генераторов конфига
    (xray_install.generate_xray_config / generate_xray_config_xhttp,
    chain_nodes.generate_xray_config_chain_entry / _entry_multi).

    Порядок восстановления каждого пустого параметра:
      1. state.json  (uuid / short_id / public_key / private_key /
                      domain / socket / spiderx)
      2. ЖИВОЙ /etc/xray/config.json (realitySettings + clients[0].id) —
         источник истины: именно из него были построены ссылки юзеров
      3. users.json  (первый непустой uuid)
      4. public_key из private_key (xray x25519 -i)
      5. Ничего не нашлось (fresh install — ни state, ни конфига):
         генерация НОВОГО значения. Конфиг с пустыми полями хуже:
         xray не стартует/рвёт handshake. Новое значение = ссылок всё
         равно нет (их ещё никому не выдавали).

    Побочный эффект (self-heal): восстановленные значения записываются
    обратно в state.json, если они там пустые/отсутствуют — генераторы
    ссылок (subscription / fragment_link / client_config_export /
    users_manager) читают state.json напрямую и должны видеть те же
    параметры, из которых собран конфиг.

    :return: список имён восстановленных полей (для лога); [] если всё
             уже было заполнено.
    """
    global PARAM_DOMAIN, PARAM_UUID, PARAM_PUBLIC_KEY, PARAM_PRIVATE_KEY
    global PARAM_SHORTID, PARAM_SOCKET_PATH, PARAM_SPIDERX

    recovered: list = []

    # ── Шаг 0: читаем источники восстановления ──────────────────────────
    state: dict = {}
    try:
        if STATE_FILE.exists():
            state = json.loads(STATE_FILE.read_text())
    except Exception:
        state = {}
    live = _identity_read_live_config()

    def _first_nonempty(*vals):
        for v in vals:
            if v:
                return v
        return ""

    # ── Шаг 1: PARAM_UUID ────────────────────────────────────────────────
    if not PARAM_UUID:
        new_val = _first_nonempty(
            state.get("uuid", ""),
            live.get("uuid", ""),
        )
        if not new_val:
            # users.json — первый непустой uuid
            try:
                if USERS_FILE.exists():
                    for u in json.loads(USERS_FILE.read_text()):
                        if u.get("uuid"):
                            new_val = u["uuid"]
                            break
            except Exception:
                pass
        if not new_val:
            new_val = str(uuid.uuid4())
        PARAM_UUID = new_val
        recovered.append("uuid")

    # ── Шаг 2: REALITY-ключи и ShortID ──────────────────────────────────
    if not PARAM_PRIVATE_KEY:
        new_val = _first_nonempty(
            state.get("private_key", ""),
            live.get("private_key", ""),
        )
        if not new_val:
            # Fresh install: генерируем новую пару (guard не должен
            # оставить конфиг без ключей)
            try:
                r = _run([str(XRAY_BIN), "x25519"], capture=True, check=False)
                if r.returncode == 0 and r.stdout:
                    _priv, _pub = _parse_x25519_keys(r.stdout)
                    if _priv:
                        new_val = _priv
                        if not PARAM_PUBLIC_KEY and _pub:
                            PARAM_PUBLIC_KEY = _pub
                            if "public_key" not in recovered:
                                recovered.append("public_key")
            except Exception:
                pass
        if new_val:
            PARAM_PRIVATE_KEY = new_val
            recovered.append("private_key")
        else:
            warn("identity-guard: не удалось восстановить REALITY private "
                 "key — конфиг будет невалиден (нет xray?)")

    if not PARAM_PUBLIC_KEY:
        new_val = _first_nonempty(
            state.get("public_key", ""),
            live.get("public_key", ""),
        )
        if not new_val and PARAM_PRIVATE_KEY:
            new_val = _identity_pubkey_from_privkey(PARAM_PRIVATE_KEY)
        if not new_val:
            warn("identity-guard: public_key пуст — ссылки pbk= будут "
                 "битыми; проверьте state.json")
        else:
            PARAM_PUBLIC_KEY = new_val
            recovered.append("public_key")

    if not PARAM_SHORTID:
        new_val = _first_nonempty(
            state.get("short_id", ""),
            live.get("short_id", ""),
        )
        if not new_val:
            # Fresh install fallback: случайный hex (валидный ShortID)
            new_val = uuid.uuid4().hex[:8]
        PARAM_SHORTID = new_val
        recovered.append("short_id")

    # ── Шаг 3: домен / сокет / spiderX ──────────────────────────────────
    if not PARAM_DOMAIN:
        new_val = _first_nonempty(
            (state.get("domain", "") or "").lower(),
            live.get("domain", ""),
        )
        if new_val:
            PARAM_DOMAIN = new_val
            recovered.append("domain")

    if not PARAM_SOCKET_PATH and PROTOCOL_MODE == "reality" \
            and not AWG_EXIT_ENABLED:
        new_val = _first_nonempty(
            state.get("socket", ""),
        )
        if new_val:
            PARAM_SOCKET_PATH = new_val
            recovered.append("socket")

    if not PARAM_SPIDERX:
        new_val = _first_nonempty(
            state.get("spiderx", ""),
            live.get("spiderx", ""),
        )
        if not new_val:
            new_val = "/" + uuid.uuid4().hex[:6]
        PARAM_SPIDERX = new_val
        recovered.append("spiderx")

    # ── Шаг 4: self-heal state.json ─────────────────────────────────────
    # Восстановленные (или найденные в live-конфиге) значения записываем
    # в state.json, если они там пустые/отсутствуют — генераторы ссылок
    # (subscription и др.) читают state напрямую.
    try:
        if STATE_FILE.exists() and state:
            _heal_fields = {
                "uuid":         PARAM_UUID,
                "public_key":   PARAM_PUBLIC_KEY,
                "private_key":  PARAM_PRIVATE_KEY,
                "short_id":     PARAM_SHORTID,
                "spiderx":      PARAM_SPIDERX,
            }
            if PARAM_DOMAIN:
                _heal_fields["domain"] = PARAM_DOMAIN
            _changed = False
            for k, v in _heal_fields.items():
                if v and not state.get(k):
                    state[k] = v
                    _changed = True
            if _changed:
                STATE_FILE.write_text(
                    json.dumps(state, indent=2, ensure_ascii=False))
                info("identity-guard: state.json дополнен недостающими "
                     f"полями ({', '.join(k for k, v in _heal_fields.items() if v and not state.get(k, 'x'))})")
    except Exception:
        pass  # self-heal не критичен

    if recovered:
        warn("identity-guard: восстановлены параметры, отсутствовавшие "
             f"в памяти: {', '.join(recovered)} (источники: state.json / "
             "текущий config.json / users.json)")
    return recovered


def _reality_transport_params_from_state(state: dict) -> tuple:
    """
    v58: (public_key, short_id, spiderx) для генераторов КЛИЕНТСКИХ ссылок
    с fallback на живой config.json. Генераторы ссылок (subscription,
    fragment_link, client_config_export, users_manager) читают state.json
    напрямую — при частично повреждённом state (domain/uuid на месте,
    public_key/short_id потеряны) они молча выдавали ссылки вида
    ``vless://...?pbk=&sid=`` — рабочие ссылки превращались в битые.
    Здесь: пустое значение добирается из текущего config.json
    (realitySettings), который и есть источник истины для выданных ссылок.
    """
    pub  = (state or {}).get("public_key", "") or ""
    sid  = (state or {}).get("short_id", "") or ""
    spx  = (state or {}).get("spiderx", "") or ""
    if not (pub and sid):
        live = _identity_read_live_config()
        if not pub:
            pub = live.get("public_key", "")
        if not sid:
            sid = live.get("short_id", "")
        if not spx:
            spx = live.get("spiderx", "")
    return pub, sid, spx


# =============================================================================
#  ВСПОМОГАТЕЛЬНАЯ: загрузка state.json в глобальные переменные
# =============================================================================
def _load_state_into_globals() -> None:
    global PARAM_DOMAIN, PARAM_UUID, PARAM_PUBLIC_KEY, PARAM_PRIVATE_KEY, PARAM_SHORTID
    # FIX: добавлен IPV6_ROUTE_OK — нужен для отметки что IPv6-адрес есть, но
    # связность отсутствует (см. логику ниже в теле функции).
    global IS_IPV6_AVAILABLE, IPV6_PREFLIGHT, IPV6_ROUTE_OK, PARAM_USE_DNSCRYPT
    global PARAM_USE_AGHOME, AGHOME_INSTALLED
    global INSTALL_MODE, PROTOCOL_MODE, XHTTP_MODE, XHTTP_PATH, XHTTP_PERF_PRESET
    global AWG_EXIT_ENABLED, AWG_INSTALLED, AWG_EXIT_HOST, AWG_EXIT_PORT, PARAM_REALITY_DEST
    # FIX: AWG_CLIENT_LISTEN_PORT присваивается ниже (state.get("awg_client_listen_port",
    # AWG_CLIENT_LISTEN_PORT)) но НЕ был объявлен как global. Python считал его
    # local переменной, и при чтении как default для state.get выбрасывал
    # UnboundLocalError. try/except: pass внизу функции проглатывал ошибку,
    # и ВСЕ строки после AWG_CLIENT_LISTEN_PORT (PARAM_REALITY_DEST, PARAM_SOCKET_PATH,
    # PARAM_SPIDERX) НЕ выполнялись. Это был давний баг проекта — проявился только
    # при вызове _load_state_into_globals() через новый пункт меню 5b, потому что
    # при do_full_install() эти поля устанавливались в процессе установки.
    global AWG_CLIENT_LISTEN_PORT
    global H2_EXIT_ENABLED
    global XTLS_FLOW
    global PARAM_FINGERPRINT
    # YouTube routing toggle (youtube_route.py).
    global YOUTUBE_VIA_RU
    # FIX: PARAM_SOCKET_PATH и PARAM_SPIDERX раньше не загружались из state,
    # хотя сохраняются туда (см. _save_state: "socket" / "spiderx"). Это
    # приводило к пустому dest/spiderX в generate_xray_config() при вызове
    # rebuild через меню (пункт 5b) — Xray падал с 'please fill in a valid
    # value for "target"'. При do_full_install() эти поля устанавливались в
    # процессе установки, поэтому баг не проявлялся.
    global PARAM_SOCKET_PATH, PARAM_SPIDERX
    # === FIX 1: объявление глобалей для multi-node полей ===
    global AWG_NODES, AWG_ACTIVE_NODE_INDEX, _AWG_SSH_CLIENT_IP
    # === END FIX 1 ===
    # Объявление глобалей для параметров обфускации AWG 2.0.
    # Раньше они не объявлялись как global — Python считал их local, и
    # try/except: pass проглатывал UnboundLocalError. Это значило что
    # obfuscation параметры всегда оставались дефолтами 4/40/70/0/0/1/2/3/4
    # после рестарта Chimera, даже если в state.json сохранены другие.
    global AWG_JC, AWG_JMIN, AWG_JMAX
    global AWG_S1, AWG_S2, AWG_S3, AWG_S4
    global AWG_H1, AWG_H2, AWG_H3, AWG_H4
    global AWG_I1, AWG_I2, AWG_I3, AWG_I4, AWG_I5
    global AWG_OBFUSCATION_SOURCE
    global XHTTP_PADDING_BYTES, XHTTP_NO_SSE_HEADER, XHTTP_NO_GRPC_HEADER, XHTTP_HOST
    global XHTTP_SC_STREAM_UP_SERVER_SECS, XHTTP_SC_MAX_EACH_POST_BYTES
    global XHTTP_SC_MIN_POSTS_INTERVAL_MS, XHTTP_SC_MAX_BUFFERED_POSTS
    global XHTTP_XMUX_ENABLED, XHTTP_XMUX_MAX_CONCURRENCY, XHTTP_XMUX_MAX_CONNECTIONS
    global XHTTP_XMUX_C_MAX_REUSE_TIMES, XHTTP_XMUX_H_MAX_REQUEST_TIMES
    global XHTTP_XMUX_H_MAX_REUSABLE_SECS, XHTTP_XMUX_H_KEEP_ALIVE_PERIOD
    global XHTTP_TCP_NO_DELAY, XHTTP_ENABLE_SESSION_RESUMPTION
    # CDN masking profile flag (опциональный, дефолт False — простой XHTTP).
    global XHTTP_CDN_MASKING
    global SERVER_PORT, XHTTP_PORT, CHAIN_BALANCER_STRATEGY
    global CHAIN_EXIT_HOST, CHAIN_EXIT_PORT, CHAIN_EXIT_UUID
    global CHAIN_EXIT_PUBKEY, CHAIN_EXIT_SHORTID, CHAIN_EXIT_SNI, CHAIN_EXIT_FP
    global CHAIN_NODES
    if not STATE_FILE.exists():
        return
    try:
        state = json.loads(STATE_FILE.read_text())
        PARAM_DOMAIN     = (state.get("domain",      PARAM_DOMAIN) or "").lower()  # DNS case-insensitive
        PARAM_UUID       = state.get("uuid",        PARAM_UUID)
        PARAM_PUBLIC_KEY = state.get("public_key",  PARAM_PUBLIC_KEY)
        PARAM_PRIVATE_KEY = state.get("private_key", PARAM_PRIVATE_KEY)
        PARAM_SHORTID    = state.get("short_id",    PARAM_SHORTID)
        PARAM_FINGERPRINT = state.get("fingerprint", PARAM_FINGERPRINT) or "chrome"
        IPV6_PREFLIGHT   = state.get("ipv6",        IPV6_PREFLIGHT)
        INSTALL_MODE     = state.get("install_mode", "A")
        # FIX: Раньше IS_IPV6_AVAILABLE = True ставилось безусловно, если в state
        # было поле 'ipv6'. Но IPv6 мог сломаться ПОСЛЕ сохранения state (пропал
        # маршрут, ISP-проблема, reboot без ipv6-маршрута). Xray тогда генерился
        # с query_strategy=UseIPv6v4 и все outbound к доменам таймаутились по IPv6.
        # Теперь — быстрая проверка связности (ping6 к Google DNS, fallback curl -6).
        if IPV6_PREFLIGHT:
            if _verify_ipv6_connectivity_quick():
                IS_IPV6_AVAILABLE = True
            else:
                # IPv6-адрес в state есть, но связности НЕТ. Не включаем
                # query_strategy=UseIPv6v4 — это ломает Xray на доменных outbound.
                IS_IPV6_AVAILABLE = False
                # Сохраняем IPV6_PREFLIGHT для отображения в меню,
                # но помечаем что маршрут не работает.
                IPV6_ROUTE_OK = False
                warn(f"IPv6-адрес в state ({IPV6_PREFLIGHT}), но связность "
                     f"отсутствует — IPv6 отключён, Xray будет использовать "
                     f"только IPv4 (query_strategy=UseIPv4).")
        else:
            IS_IPV6_AVAILABLE = False
        PARAM_USE_DNSCRYPT = state.get("use_dnscrypt", False)
        # AdGuard Home (v37): AGH-слой поверх DNSCrypt. AGHOME_INSTALLED
        # определяется по факту (бинарник + служба), а не только из state.
        PARAM_USE_AGHOME = state.get("use_aghome", False)
        try:
            from chimera.modules.aghome_setup import is_aghome_installed as _aghi
            AGHOME_INSTALLED = _aghi()
        except Exception:
            AGHOME_INSTALLED = AGHOME_BIN.exists()
        if PARAM_USE_AGHOME and not PARAM_USE_DNSCRYPT:
            PARAM_USE_AGHOME = False  # AGH без dnscrypt не имеет смысла
        PROTOCOL_MODE = state.get("protocol_mode", "reality")
        XTLS_FLOW     = state.get("xtls_flow",      "xtls-rprx-vision")
        # YouTube routing toggle (youtube_route.py). Default False — YouTube
        # идёт через exit-ноды (как было до этого фикса).
        YOUTUBE_VIA_RU = state.get("youtube_via_ru", False)
        XHTTP_MODE    = state.get("xhttp_mode",    "stream-up")
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
        # CDN masking profile flag — опциональный, по умолч. False (простой XHTTP).
        XHTTP_CDN_MASKING               = state.get("xhttp_cdn_masking",              False)
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
        # Загружаем параметры обфускации из state — раньше они
        # всегда сбрасывались в дефолты 4/40/70/0/0/1/2/3/4 при рестарте
        # Chimera, что приводило к рассинхрону сервера (со старыми значениями)
        # и конфигов, генерируемых Chimera (с дефолтами).
        AWG_JC = state.get("awg_jc",  AWG_JC)
        AWG_JMIN = state.get("awg_jmin",  AWG_JMIN)
        AWG_JMAX = state.get("awg_jmax",  AWG_JMAX)
        AWG_S1 = state.get("awg_s1",  AWG_S1)
        AWG_S2 = state.get("awg_s2",  AWG_S2)
        AWG_S3 = state.get("awg_s3",  AWG_S3)
        AWG_S4 = state.get("awg_s4",  AWG_S4)
        AWG_H1 = state.get("awg_h1",  AWG_H1)
        AWG_H2 = state.get("awg_h2",  AWG_H2)
        AWG_H3 = state.get("awg_h3",  AWG_H3)
        AWG_H4 = state.get("awg_h4",  AWG_H4)
        AWG_I1 = state.get("awg_i1",  AWG_I1)
        AWG_I2 = state.get("awg_i2",  AWG_I2)
        AWG_I3 = state.get("awg_i3",  AWG_I3)
        AWG_I4 = state.get("awg_i4",  AWG_I4)
        AWG_I5 = state.get("awg_i5",  AWG_I5)
        AWG_OBFUSCATION_SOURCE = state.get("awg_obfuscation_source", AWG_OBFUSCATION_SOURCE)
        PARAM_REALITY_DEST = state.get("reality_dest",   PARAM_REALITY_DEST)
        # FIX: загружаем socket_path и spiderx из state — раньше не делалось,
        # что ломало generate_xray_config() при rebuild через пункт меню 5b
        # (получали dest="", spiderX="" → Xray валидация падала).
        PARAM_SOCKET_PATH = state.get("socket",  PARAM_SOCKET_PATH)
        PARAM_SPIDERX     = state.get("spiderx", PARAM_SPIDERX)
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
    # CDN masking profile flag — для скрытого меню (unlock через код доступа).
    global XHTTP_CDN_MASKING
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
                from chimera.modules.status_panel import render as _render_status_panel
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
            _box_row(f"  {BOLD}{TITLE}Chimera Project v{_get_version()}{NC}  {DIM}│{NC}  {mode_str}")
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
            _box_row(f"  {CYAN}8{NC}  📲 {TITLE}VK Whitelist Bypass (4 модуля){NC}")
            _box_row(f"     {DIM}FreeTurn · WireTurn · qWDTT · CSQTT — обход через звонки ВКонтакте{NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}9{NC}  🌐 {TITLE}SlipGate / SlipNet{NC}")
            _box_row(f"     {DIM}DNS-туннели (DNSTT, NoizDNS, Slipstream) — обход полных блокировок{NC}")
            _box_row()
            _box_sep()
            _box_row(f"  {CYAN}10{NC} 🔐 {TITLE}NaiveProxy{NC}")
            _box_row(f"     {DIM}HTTPS/HTTP2 + Chromium fingerprint + probe resistance{NC}")
            _box_row()
            _box_sep()
            _box_row(f"  {CYAN}11{NC} 🔒 {TITLE}Mieru{NC}")
            _box_row(f"     {DIM}mTLS + random padding — маскировка без домена{NC}")
            _box_row()
            _box_sep()
            # olcRTC скрыт из меню — доступ через ввод "olcrtc" (как "cdn")
            _box_row(f"  {CYAN}12{NC} ☁️  {TITLE}WebDAV Tunnel{NC}")
            _box_row(f"     {DIM}TCP/SOCKS5 поверх WebDAV-файлов — маскировка под облако{NC}")
            _box_row()
            _box_sep()
            _box_row(f"  {CYAN}13{NC} 🐙 {TITLE}FPTN{NC}  {DIM}(Beta){NC}")
            _box_row(f"     {DIM}Свой L3 VPN (Protobuf/TLS) — honeypot-прокси вместо отказа зондам{NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}14{NC} 🔒 {TITLE}AmneziaWG 2.0 (standalone VPN){NC}")
            _box_row(f"     {DIM}Standalone AWG-сервер + carrier-пресеты + каскад RU→зарубеж{NC}")
            _box_row()
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}15{NC} 📦 {TITLE}Sing-box (ShadowTLS/AnyTLS/TUIC){NC}  {DIM}(NEW){NC}")
            _box_row(f"     {DIM}Параллельный backend: TLS-camouflage + QUIC-резерв к Hysteria2{NC}")
            _box_row()
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}16{NC} 🔐 {TITLE}TrustTunnel{NC}  {DIM}(NEW){NC}")
            _box_row(f"     {DIM}AdGuard VPN protocol (HTTP/2+HTTP/3 over TLS) — tt:// deep-link{NC}")
            _box_row()
            _box_sep()
            _box_row(f"  {DIM}[{NC}{TITLE}{BOLD}0{NC}{DIM}]{NC}  🚪 Выход")
            _box_bottom()
            _BOX_W = _BOX_W_saved
            print()
            choice = input(f"{CYAN}Выбор (1–16 / 0):{NC} ").strip()
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
                from chimera.modules.mtproto import mtproto_menu
                mtproto_menu()
            except ImportError as _e:
                warn(f"Модуль MTProxy не найден: {_e}")
                time.sleep(2)

        elif choice == "7":
            do_hysteria2_menu()

        elif choice == "8":
            try:
                do_vk_bypass_menu()
            except ImportError as _e:
                warn(f"Модуль VK Whitelist Bypass не найден: {_e}")
                time.sleep(2)

        elif choice == "9":
            try:
                do_slipgate_menu()
            except ImportError as _e:
                warn(f"Модуль SlipGate не найден: {_e}")
                time.sleep(2)

        elif choice == "10":
            try:
                do_naiveproxy_menu()
            except ImportError as _e:
                warn(f"Модуль NaiveProxy не найден: {_e}")
                time.sleep(2)

        elif choice == "11":
            try:
                do_mieru_menu()
            except ImportError as _e:
                warn(f"Модуль Mieru не найден: {_e}")
                time.sleep(2)

        elif choice == "12":
            try:
                do_webdav_tunnel_menu()
            except ImportError as _e:
                warn(f"Модуль WebDAV Tunnel не найден: {_e}")
                time.sleep(2)

        elif choice == "13":
            try:
                from chimera.modules.fptn import do_fptn_menu
                do_fptn_menu()
            except ImportError as _e:
                warn(f"Модуль FPTN не найден: {_e}")
                time.sleep(2)

        elif choice == "14":
            try:
                from chimera.modules.awg_standalone import do_manage_awg_standalone
                do_manage_awg_standalone()
            except ImportError as _e:
                warn(f"Модуль AmneziaWG standalone не найден: {_e}")
                time.sleep(2)

        elif choice == "15":
            try:
                from chimera.modules.singbox_menu import do_singbox_menu
                do_singbox_menu()
            except ImportError as _e:
                warn(f"Модуль sing-box не найден: {_e}")
                time.sleep(2)

        elif choice == "16":
            try:
                from chimera.modules.trusttunnel import do_trusttunnel_menu
                do_trusttunnel_menu()
            except ImportError as _e:
                warn(f"Модуль TrustTunnel не найден: {_e}")
                time.sleep(2)

        # ── Скрытое меню: olcRTC (туннель под видеозвонок) ────────────────
        # Активируется вводом строки "olcrtc" (без кавычек) в главном меню.
        # Не отображается в списке пунктов — пользователь должен знать
        # о существовании этого раздела.
        elif choice.lower() == "olcrtc":
            try:
                from chimera.modules.olcrtc import unlock_and_open_menu
                unlock_and_open_menu()
            except ImportError:
                # Тихая ошибка — не выдаём существование скрытого меню.
                warn(f"Неверный выбор: {choice}")
                time.sleep(1)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as _e:
                warn(f"Ошибка в скрытом разделе: {_e}")
                warn(f"Тип: {type(_e).__name__}")
                time.sleep(2)

        # ── Скрытое меню: CDN masking (обход белых списков через Beeline CDN) ─
        # Активируется вводом строки "cdn" (без кавычек) в главном меню.
        # Не отображается в списке пунктов — пользователь должен знать
        # о существовании этого раздела. После ввода "cdn" запрашивается
        # код доступа (getpass, без эха), проверяется через SHA-256 hash
        # (plaintext НЕ хранится в коде). Только после успешной авторизации
        # открывается интерфейс профиля CDN masking.
        elif choice.lower() == "cdn":
            try:
                from chimera.modules.xhttp_cdn_masking import run_cdn_masking_install
                run_cdn_masking_install()
            except ImportError as _e:
                # Тихая ошибка — не выдаём существование скрытого меню.
                warn(f"Неверный выбор: {choice}")
                time.sleep(1)
            except (KeyboardInterrupt, SystemExit):
                # Эти исключения НЕ маскируем — пользователь нажал Ctrl+C
                # или sys.exit() вызван намеренно. Пробрасываем дальше.
                raise
            except Exception as _e:
                # Любая другая ошибка из run_cdn_masking_install() — печатаем
                # её ЧЕСТНО (не "Неверный выбор"), чтобы пользователь видел
                # что произошло. Раньше тут было warn("Неверный выбор: {choice}")
                # что маскировало реальные ошибки (например, NameError _box_info).
                warn(f"Ошибка в скрытом разделе: {_e}")
                warn(f"Тип: {type(_e).__name__}")
                time.sleep(2)

        elif choice == "0":
            print(f"{GREEN}До свидания! 👋{NC}")
            log_to_file("INFO", "Скрипт завершён пользователем")
            sys.exit(0)

        else:
            warn(f"Неверный выбор: {choice}")
            time.sleep(1)


# (apply_sysctl_and_limits вынесен в chimera.modules.network_setup;
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

# (switch_mode_ab — вынесен в chimera.modules.switch_mode;
#  импорт — в верхней секции этого файла.)



# (AWG transport — awg_watchdog_install, awg_watchdog_remove, _awg_watchdog_set_flag, do_manage_awg_watchdog, _awg_node_subnets — вынесены в
#  chimera.modules.awg_transport; импорт — в верхней секции этого файла.)


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


# (AWG transport — _awg_persist_ssh_exclusion, _awg_node_from_globals, _awg_load_nodes_from_state, _awg_save_nodes_to_state, _awg_client_conf_for_node, _awg_server_conf_for_node, _awg_systemd_unit_for_node, awg_setup_all_nodes, _awg_bring_up_all_tunnels, _awg_apply_policy_routing_all_nodes, _awg_verify_all_tunnels — вынесены в
#  chimera.modules.awg_transport; импорт — в верхней секции этого файла.)


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
        # v57 (start-limit-fix): безопасный рестарт (reset-failed) + ожидание
        xray_ok = _xray_safe_restart(wait_active=max(timeout, 15), attempts=2)
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


# (AWG transport — awg_multinode_watchdog_install, do_manage_awg_nodes, _awg_manual_switch, _awg_ping_all_nodes, _awg_show_failover_log, _awg_show_ssh_protection_status, _awg_diagnostic_all_nodes, _prompt_awg_additional_nodes, _awg_emergency_restore_all_nodes — вынесены в
#  chimera.modules.awg_transport; импорт — в верхней секции этого файла.)


# === END PATCH v2: AWG MULTI-NODE ===


# (Auto-fallback — _auto_fallback_install, _auto_fallback_set_flag,
#  do_manage_auto_fallback — вынесены в chimera.modules.failover;
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
# — перенесено в chimera/modules/tui.py
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
# ingress_geoip — перенесено в chimera/modules/ingress_geoip.py
# INGRESS_* константы импортируются из модуля
# =============================================================================

# (do_mtu_tracepath_diag, _mtu_tracepath_one вынесены в
#  chimera.modules.mtu_tuning; импорт — в верхней секции этого файла.)


# =============================================================================
#  МОДУЛЬ: DPI-ДЕТЕКТОР  (v3.99)
#  Анализирует xray/error.log на паттерны активного зондирования:
#  - TLS Client Hello без SNI
#  - нестандартные TLS client_random
#  - повторные хендшейки с разными параметрами (fingerprint sweep)
#  - HTTP-запросы к Xray (не-TLS трафик на TLS-порт)
#  Забаненные IP интегрируются в существующий AutoBan (autoban.json)
# dpi_detector — перенесено в chimera/modules/dpi_detector.py
