"""
chimera/modules/emergency_repair.py
───────────────────────────────────────────────────────────────────────────────
Аварийное восстановление после сбоя хостера / краша системы.

Содержит одну большую функцию ``do_emergency_repair()``, вынесенную из
_core.py (~858 строк). Это оркестратор, который:

  1.  Читает state.json — восстанавливает все глобальные переменные.
  2.  Диагностирует, что именно сломано (юнит-файл, права сокета, сертификат...).
  3.  Пересоздаёт systemd-юнит Xray + nginx.service.d override.
  4.  Восстанавливает права на директорию сокета и TLS-сертификаты.
  5.  Поднимает AdGuardHome (если установлен — до пересборки конфига) и
      перезапускает: DNSCrypt → Xray (с ожиданием сокета) → Nginx.
  6.  Перезапускает fail2ban, irqbalance, WARP — если установлены.
  7.  Восстанавливает все systemd-таймеры (watchdog, autoupdate, geo, ru-subnets).
  8.  Проверяет все cron.d-задачи (certbot, geo, fp, uuid, tg, ttl, limits...).
  9.  Восстанавливает ingress GeoIP-правила (ipset/iptables).
  10. Восстанавливает honeypot-сервис (если был включён).
  11. Итоговый health-report по всем компонентам.

Точка входа из _core.py:
    from chimera.modules.emergency_repair import do_emergency_repair

Глобалы ядра мутируются через dual-form паттерн:
    X = value
    setattr(core, "X", X)
Это сохраняет и локальную переменную (для последующих чтений в той же
функции), и атрибут модуля ``_core`` (для других модулей).

Мутируются 44 глобала: ``INSTALL_MODE``, ``PROTOCOL_MODE``, ``SERVER_PORT``,
``XHTTP_PORT``, ``XHTTP_MODE``, ``XHTTP_PATH``, ``XHTTP_PERF_PRESET``,
``PARAM_DOMAIN``, ``PARAM_UUID``, ``PARAM_PUBLIC_KEY``, ``PARAM_PRIVATE_KEY``,
``PARAM_SHORTID``, ``PARAM_SPIDERX``, ``PARAM_SOCKET_PATH``,
``PARAM_DOMAIN_STRATEGY``, ``PARAM_EMAIL``, ``PARAM_SITE_TEMPLATE``,
``PARAM_USE_DNSCRYPT``, ``IPV6_PREFLIGHT``, ``SPLIT_TUNNEL_ENABLED``,
``SPLIT_TUNNEL_EXTRA_DOMAINS``, ``SPLIT_TUNNEL_EXTRA_IPS``,
``XHTTP_PADDING_BYTES``, ``XHTTP_NO_SSE_HEADER``, ``XHTTP_NO_GRPC_HEADER``,
``XHTTP_HOST``, ``XHTTP_SC_STREAM_UP_SERVER_SECS``,
``XHTTP_SC_MAX_EACH_POST_BYTES``, ``XHTTP_SC_MIN_POSTS_INTERVAL_MS``,
``XHTTP_SC_MAX_BUFFERED_POSTS``, ``XHTTP_XMUX_ENABLED``,
``XHTTP_XMUX_MAX_CONCURRENCY``, ``XHTTP_XMUX_MAX_CONNECTIONS``,
``XHTTP_XMUX_C_MAX_REUSE_TIMES``, ``XHTTP_XMUX_H_MAX_REQUEST_TIMES``,
``XHTTP_XMUX_H_MAX_REUSABLE_SECS``, ``XHTTP_XMUX_H_KEEP_ALIVE_PERIOD``,
``XHTTP_TCP_NO_DELAY``, ``XHTTP_ENABLE_SESSION_RESUMPTION``, ``CHAIN_NODES``,
``CHAIN_BALANCER_STRATEGY``, ``CHAIN_PINNED_NODE_INDEX``, ``AWG_EXIT_ENABLED``,
``PARAM_REALITY_DEST``.

Доступ к helpers ядра (``_box_*``, ``_run``, ``warn``/``info``/``success``,
``_set_config_owner``, ``_nodes_from_state``, ``_load_split_tunnel_custom``,
``_detect_xhttp_mode_support``, ``create_xray_service``,
``setup_nginx_systemd_override``, ``fix_letsencrypt_permissions``,
``ensure_cert_fix_script``, ``setup_nginx_final``,
``generate_xray_config_chain_entry_multi``, ``generate_xray_config_xhttp``,
``generate_xray_config``, ``_users_patch_config_no_restart``,
``_ru_subnets_restore_if_needed``, ``_as_direct_restore_if_needed``,
``_as_direct_list_load``, ``_wait_service_active``, ``_ingress_state_load``,
``_ingress_enable``, ``_awg_emergency_restore_all_nodes``, ``log_to_file``,
ANSI-цвета, ``STATE_FILE``, ``XRAY_SERVICE``, ``AWG_INTERFACE``,
``AWG_FWMARK``, ``AWG_ROUTE_TABLE``) — через importlib.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import time
from pathlib import Path


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль chimera._core, импортируя его лениво."""
    import importlib
    return importlib.import_module("chimera._core")


# =============================================================================
#  АВАРИЙНОЕ ВОССТАНОВЛЕНИЕ
# =============================================================================
def do_emergency_repair() -> None:
    """
    Аварийное восстановление после сбоя хостера / краша системы.

    Алгоритм:
      1.  Читает state.json — восстанавливает все глобальные переменные.
      2.  Диагностирует, что именно сломано (юнит-файл, права сокета, сертификат...).
      3.  Пересоздаёт systemd-юнит Xray + nginx.service.d override.
      4.  Восстанавливает права на директорию сокета и TLS-сертификаты.
      5.  Поднимает AdGuardHome (если установлен — до пересборки конфига) и
          перезапускает: DNSCrypt → Xray (с ожиданием сокета) → Nginx.
      6.  Перезапускает fail2ban, irqbalance, WARP — если установлены.
      7.  Восстанавливает все systemd-таймеры (watchdog, autoupdate, geo, ru-subnets).
      8.  Проверяет все cron.d-задачи (certbot, geo, fp, uuid, tg, ttl, limits...).
      9.  Восстанавливает ingress GeoIP-правила (ipset/iptables).
      10. Восстанавливает honeypot-сервис (если был включён).
      11. Итоговый health-report по всем компонентам.
    """
    core = _core_module()
    # ── Bind helpers ──────────────────────────────────────────────────────────
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_bottom = core._box_bottom
    _box_warn   = core._box_warn
    _box_ok     = core._box_ok
    _box_wrap_msg = core._box_wrap_msg
    _run        = core._run
    log_to_file = core.log_to_file
    _set_config_owner = core._set_config_owner
    _nodes_from_state = core._nodes_from_state
    _load_split_tunnel_custom = core._load_split_tunnel_custom
    _detect_xhttp_mode_support = core._detect_xhttp_mode_support
    create_xray_service = core.create_xray_service
    setup_nginx_systemd_override = core.setup_nginx_systemd_override
    fix_letsencrypt_permissions = core.fix_letsencrypt_permissions
    ensure_cert_fix_script = core.ensure_cert_fix_script
    setup_nginx_final = core.setup_nginx_final
    generate_xray_config_chain_entry_multi = core.generate_xray_config_chain_entry_multi
    generate_xray_config_xhttp = core.generate_xray_config_xhttp
    generate_xray_config = core.generate_xray_config
    _users_patch_config_no_restart = core._users_patch_config_no_restart
    _ru_subnets_restore_if_needed = core._ru_subnets_restore_if_needed
    _as_direct_restore_if_needed = core._as_direct_restore_if_needed
    _as_direct_list_load = core._as_direct_list_load
    _wait_service_active = core._wait_service_active
    _ingress_state_load = core._ingress_state_load
    _ingress_enable = core._ingress_enable
    _awg_emergency_restore_all_nodes = core._awg_emergency_restore_all_nodes
    # ── Bind globals (for reads as defaults in state.get) ─────────────────────
    STATE_FILE       = core.STATE_FILE
    XRAY_SERVICE     = core.XRAY_SERVICE
    AWG_INTERFACE    = core.AWG_INTERFACE
    AWG_FWMARK       = core.AWG_FWMARK
    AWG_ROUTE_TABLE  = core.AWG_ROUTE_TABLE
    XHTTP_MODE       = core.XHTTP_MODE
    XHTTP_PATH       = core.XHTTP_PATH
    XHTTP_PERF_PRESET = core.XHTTP_PERF_PRESET
    PARAM_DOMAIN     = core.PARAM_DOMAIN
    PARAM_UUID       = core.PARAM_UUID
    PARAM_PUBLIC_KEY = core.PARAM_PUBLIC_KEY
    PARAM_PRIVATE_KEY = core.PARAM_PRIVATE_KEY
    PARAM_SHORTID    = core.PARAM_SHORTID
    PARAM_SPIDERX    = core.PARAM_SPIDERX
    PARAM_SOCKET_PATH = core.PARAM_SOCKET_PATH
    PARAM_DOMAIN_STRATEGY = core.PARAM_DOMAIN_STRATEGY
    PARAM_EMAIL      = core.PARAM_EMAIL
    PARAM_SITE_TEMPLATE = core.PARAM_SITE_TEMPLATE
    IPV6_PREFLIGHT   = core.IPV6_PREFLIGHT
    XHTTP_PADDING_BYTES = core.XHTTP_PADDING_BYTES
    XHTTP_NO_SSE_HEADER = core.XHTTP_NO_SSE_HEADER
    XHTTP_NO_GRPC_HEADER = core.XHTTP_NO_GRPC_HEADER
    XHTTP_HOST       = core.XHTTP_HOST
    XHTTP_SC_STREAM_UP_SERVER_SECS = core.XHTTP_SC_STREAM_UP_SERVER_SECS
    XHTTP_SC_MAX_EACH_POST_BYTES   = core.XHTTP_SC_MAX_EACH_POST_BYTES
    XHTTP_SC_MIN_POSTS_INTERVAL_MS = core.XHTTP_SC_MIN_POSTS_INTERVAL_MS
    XHTTP_SC_MAX_BUFFERED_POSTS    = core.XHTTP_SC_MAX_BUFFERED_POSTS
    XHTTP_XMUX_ENABLED             = core.XHTTP_XMUX_ENABLED
    XHTTP_XMUX_MAX_CONCURRENCY     = core.XHTTP_XMUX_MAX_CONCURRENCY
    XHTTP_XMUX_MAX_CONNECTIONS     = core.XHTTP_XMUX_MAX_CONNECTIONS
    XHTTP_XMUX_C_MAX_REUSE_TIMES   = core.XHTTP_XMUX_C_MAX_REUSE_TIMES
    XHTTP_XMUX_H_MAX_REQUEST_TIMES = core.XHTTP_XMUX_H_MAX_REQUEST_TIMES
    XHTTP_XMUX_H_MAX_REUSABLE_SECS = core.XHTTP_XMUX_H_MAX_REUSABLE_SECS
    XHTTP_XMUX_H_KEEP_ALIVE_PERIOD = core.XHTTP_XMUX_H_KEEP_ALIVE_PERIOD
    XHTTP_TCP_NO_DELAY             = core.XHTTP_TCP_NO_DELAY
    XHTTP_ENABLE_SESSION_RESUMPTION = core.XHTTP_ENABLE_SESSION_RESUMPTION
    PARAM_REALITY_DEST = core.PARAM_REALITY_DEST
    # ── Bind colors ────────────────────────────────────────────────────────────
    CYAN   = core.CYAN
    GREEN  = core.GREEN
    YELLOW = core.YELLOW
    BLUE   = core.BLUE
    DIM    = core.DIM
    NC     = core.NC

    os_system_clear = __import__("os").system

    os_system_clear("clear")
    print()
    _box_top("🛠️  АВАРИЙНОЕ ВОССТАНОВЛЕНИЕ")
    _box_row()
    _box_wrap_msg(f"  {YELLOW}", 2,
        f"Этот режим считывает сохранённую конфигурацию и полностью "
        f"восстанавливает все сервисы, планировщики и правила без "
        f"повторного ввода параметров.{NC}")
    _box_row()
    _box_wrap_msg(f"  {CYAN}", 2,
        f"Продолжить? Все сервисы будут остановлены и перезапущены. [y/N]{NC}")
    _box_bottom()
    try:
        ans = input(f"{CYAN}Выбор:{NC} ").strip().lower()
    except KeyboardInterrupt:
        print()
        return
    if ans not in ('y', 'yes'):
        return

    # ── ШАГ 0: проверяем наличие state.json ───────────────────────────────────
    print()
    _box_top("🛠️  АВАРИЙНОЕ ВОССТАНОВЛЕНИЕ — в процессе")
    _box_row()

    if not STATE_FILE.exists():
        _box_warn("state.json не найден — установка не выполнялась или файл удалён.")
        _box_warn("Используйте пункт [1] для новой установки.")
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    # ── ШАГ 1: читаем state.json, восстанавливаем все переменные ──────────────
    _box_row(f"  {CYAN}[1/11]{NC} Чтение конфигурации из state.json...")
    try:
        state = json.loads(STATE_FILE.read_text())
    except Exception as e:
        _box_wrap_msg(f"  {YELLOW}[WARN]{NC} ", 9, f"Ошибка чтения state.json: {e}")
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    INSTALL_MODE             = state.get("install_mode",      "A")
    setattr(core, "INSTALL_MODE", INSTALL_MODE)
    PROTOCOL_MODE            = state.get("protocol_mode",     "reality")
    setattr(core, "PROTOCOL_MODE", PROTOCOL_MODE)
    SERVER_PORT              = state.get("server_port",        443)
    setattr(core, "SERVER_PORT", SERVER_PORT)
    XHTTP_PORT               = SERVER_PORT
    setattr(core, "XHTTP_PORT", XHTTP_PORT)
    XHTTP_MODE               = state.get("xhttp_mode",        XHTTP_MODE)
    setattr(core, "XHTTP_MODE", XHTTP_MODE)
    XHTTP_PATH               = state.get("xhttp_path",        XHTTP_PATH)
    setattr(core, "XHTTP_PATH", XHTTP_PATH)
    XHTTP_PERF_PRESET        = state.get("xhttp_perf_preset", XHTTP_PERF_PRESET)
    setattr(core, "XHTTP_PERF_PRESET", XHTTP_PERF_PRESET)
    PARAM_DOMAIN             = state.get("domain",             PARAM_DOMAIN)
    setattr(core, "PARAM_DOMAIN", PARAM_DOMAIN)
    PARAM_UUID               = state.get("uuid",               PARAM_UUID)
    setattr(core, "PARAM_UUID", PARAM_UUID)
    PARAM_PUBLIC_KEY         = state.get("public_key",         PARAM_PUBLIC_KEY)
    setattr(core, "PARAM_PUBLIC_KEY", PARAM_PUBLIC_KEY)
    PARAM_PRIVATE_KEY        = state.get("private_key",        PARAM_PRIVATE_KEY)
    setattr(core, "PARAM_PRIVATE_KEY", PARAM_PRIVATE_KEY)
    PARAM_SHORTID            = state.get("short_id",           PARAM_SHORTID)
    setattr(core, "PARAM_SHORTID", PARAM_SHORTID)
    PARAM_SPIDERX            = state.get("spiderx",            PARAM_SPIDERX)
    setattr(core, "PARAM_SPIDERX", PARAM_SPIDERX)
    PARAM_SOCKET_PATH        = state.get("socket",             PARAM_SOCKET_PATH)
    setattr(core, "PARAM_SOCKET_PATH", PARAM_SOCKET_PATH)
    PARAM_DOMAIN_STRATEGY    = state.get("strategy",           PARAM_DOMAIN_STRATEGY)
    setattr(core, "PARAM_DOMAIN_STRATEGY", PARAM_DOMAIN_STRATEGY)
    PARAM_EMAIL              = state.get("email",              PARAM_EMAIL)
    setattr(core, "PARAM_EMAIL", PARAM_EMAIL)
    PARAM_SITE_TEMPLATE      = state.get("template",           PARAM_SITE_TEMPLATE)
    setattr(core, "PARAM_SITE_TEMPLATE", PARAM_SITE_TEMPLATE)
    PARAM_USE_DNSCRYPT       = state.get("use_dnscrypt",       False)
    setattr(core, "PARAM_USE_DNSCRYPT", PARAM_USE_DNSCRYPT)
    IPV6_PREFLIGHT           = state.get("ipv6",               IPV6_PREFLIGHT)
    setattr(core, "IPV6_PREFLIGHT", IPV6_PREFLIGHT)
    SPLIT_TUNNEL_ENABLED     = state.get("split_tunnel",       False)
    setattr(core, "SPLIT_TUNNEL_ENABLED", SPLIT_TUNNEL_ENABLED)
    SPLIT_TUNNEL_EXTRA_DOMAINS = state.get("split_extra_domains", [])
    setattr(core, "SPLIT_TUNNEL_EXTRA_DOMAINS", SPLIT_TUNNEL_EXTRA_DOMAINS)
    SPLIT_TUNNEL_EXTRA_IPS   = state.get("split_extra_ips",    [])
    setattr(core, "SPLIT_TUNNEL_EXTRA_IPS", SPLIT_TUNNEL_EXTRA_IPS)
    XHTTP_PADDING_BYTES      = state.get("xhttp_padding_bytes",           XHTTP_PADDING_BYTES)
    setattr(core, "XHTTP_PADDING_BYTES", XHTTP_PADDING_BYTES)
    XHTTP_NO_SSE_HEADER      = state.get("xhttp_no_sse_header",           XHTTP_NO_SSE_HEADER)
    setattr(core, "XHTTP_NO_SSE_HEADER", XHTTP_NO_SSE_HEADER)
    XHTTP_NO_GRPC_HEADER     = state.get("xhttp_no_grpc_header",          XHTTP_NO_GRPC_HEADER)
    setattr(core, "XHTTP_NO_GRPC_HEADER", XHTTP_NO_GRPC_HEADER)
    XHTTP_HOST               = state.get("xhttp_host",                    XHTTP_HOST)
    setattr(core, "XHTTP_HOST", XHTTP_HOST)
    XHTTP_SC_STREAM_UP_SERVER_SECS  = state.get("xhttp_sc_stream_up_server_secs",  XHTTP_SC_STREAM_UP_SERVER_SECS)
    setattr(core, "XHTTP_SC_STREAM_UP_SERVER_SECS", XHTTP_SC_STREAM_UP_SERVER_SECS)
    XHTTP_SC_MAX_EACH_POST_BYTES    = state.get("xhttp_sc_max_each_post_bytes",    XHTTP_SC_MAX_EACH_POST_BYTES)
    setattr(core, "XHTTP_SC_MAX_EACH_POST_BYTES", XHTTP_SC_MAX_EACH_POST_BYTES)
    XHTTP_SC_MIN_POSTS_INTERVAL_MS  = state.get("xhttp_sc_min_posts_interval_ms",  XHTTP_SC_MIN_POSTS_INTERVAL_MS)
    setattr(core, "XHTTP_SC_MIN_POSTS_INTERVAL_MS", XHTTP_SC_MIN_POSTS_INTERVAL_MS)
    XHTTP_SC_MAX_BUFFERED_POSTS     = state.get("xhttp_sc_max_buffered_posts",     XHTTP_SC_MAX_BUFFERED_POSTS)
    setattr(core, "XHTTP_SC_MAX_BUFFERED_POSTS", XHTTP_SC_MAX_BUFFERED_POSTS)
    XHTTP_XMUX_ENABLED              = state.get("xhttp_xmux_enabled",             XHTTP_XMUX_ENABLED)
    setattr(core, "XHTTP_XMUX_ENABLED", XHTTP_XMUX_ENABLED)
    XHTTP_XMUX_MAX_CONCURRENCY      = state.get("xhttp_xmux_max_concurrency",     XHTTP_XMUX_MAX_CONCURRENCY)
    setattr(core, "XHTTP_XMUX_MAX_CONCURRENCY", XHTTP_XMUX_MAX_CONCURRENCY)
    XHTTP_XMUX_MAX_CONNECTIONS      = state.get("xhttp_xmux_max_connections",     XHTTP_XMUX_MAX_CONNECTIONS)
    setattr(core, "XHTTP_XMUX_MAX_CONNECTIONS", XHTTP_XMUX_MAX_CONNECTIONS)
    XHTTP_XMUX_C_MAX_REUSE_TIMES    = state.get("xhttp_xmux_c_max_reuse_times",   XHTTP_XMUX_C_MAX_REUSE_TIMES)
    setattr(core, "XHTTP_XMUX_C_MAX_REUSE_TIMES", XHTTP_XMUX_C_MAX_REUSE_TIMES)
    XHTTP_XMUX_H_MAX_REQUEST_TIMES  = state.get("xhttp_xmux_h_max_request_times", XHTTP_XMUX_H_MAX_REQUEST_TIMES)
    setattr(core, "XHTTP_XMUX_H_MAX_REQUEST_TIMES", XHTTP_XMUX_H_MAX_REQUEST_TIMES)
    XHTTP_XMUX_H_MAX_REUSABLE_SECS  = state.get("xhttp_xmux_h_max_reusable_secs", XHTTP_XMUX_H_MAX_REUSABLE_SECS)
    setattr(core, "XHTTP_XMUX_H_MAX_REUSABLE_SECS", XHTTP_XMUX_H_MAX_REUSABLE_SECS)
    XHTTP_XMUX_H_KEEP_ALIVE_PERIOD  = state.get("xhttp_xmux_h_keep_alive_period", XHTTP_XMUX_H_KEEP_ALIVE_PERIOD)
    setattr(core, "XHTTP_XMUX_H_KEEP_ALIVE_PERIOD", XHTTP_XMUX_H_KEEP_ALIVE_PERIOD)
    XHTTP_TCP_NO_DELAY               = state.get("xhttp_tcp_no_delay",             XHTTP_TCP_NO_DELAY)
    setattr(core, "XHTTP_TCP_NO_DELAY", XHTTP_TCP_NO_DELAY)
    XHTTP_ENABLE_SESSION_RESUMPTION  = state.get("xhttp_enable_session_resumption",XHTTP_ENABLE_SESSION_RESUMPTION)
    setattr(core, "XHTTP_ENABLE_SESSION_RESUMPTION", XHTTP_ENABLE_SESSION_RESUMPTION)
    CHAIN_NODES              = _nodes_from_state(state)
    setattr(core, "CHAIN_NODES", CHAIN_NODES)
    CHAIN_BALANCER_STRATEGY  = state.get("chain_balancer_strategy", "roundRobin")
    setattr(core, "CHAIN_BALANCER_STRATEGY", CHAIN_BALANCER_STRATEGY)
    CHAIN_PINNED_NODE_INDEX  = state.get("chain_pinned_node_index", -1)
    setattr(core, "CHAIN_PINNED_NODE_INDEX", CHAIN_PINNED_NODE_INDEX)
    AWG_EXIT_ENABLED         = state.get("awg_exit_enabled",  False)
    setattr(core, "AWG_EXIT_ENABLED", AWG_EXIT_ENABLED)
    PARAM_REALITY_DEST       = state.get("reality_dest",      PARAM_REALITY_DEST)
    setattr(core, "PARAM_REALITY_DEST", PARAM_REALITY_DEST)

    # Загружаем split tunnel кастомные правила.
    # redirect_stdout чтобы возможный warn() не ломал рамку бокса.
    import io as _io_pre, contextlib as _cl_pre
    with _cl_pre.redirect_stdout(_io_pre.StringIO()):
        _load_split_tunnel_custom()
    # Определяем поддержку xhttp mode (нужно до пересборки конфига).
    # Захватываем stdout чтобы глобальные warn()/info() не ломали рамку бокса;
    # затем показываем предупреждения через _box_warn внутри рамки.
    import io as _io_xhttp, contextlib as _cl_xhttp
    _xhttp_capture = _io_xhttp.StringIO()
    with _cl_xhttp.redirect_stdout(_xhttp_capture):
        _detect_xhttp_mode_support()
    _xhttp_out = _xhttp_capture.getvalue()
    if _xhttp_out.strip():
        import re as _re_xhttp
        for _xhttp_line in _xhttp_out.splitlines():
            _xhttp_plain = _re_xhttp.sub(r'\033\[[0-9;]*m', '', _xhttp_line).strip()
            if _xhttp_plain:
                if "[WARN]" in _xhttp_line or "WARN" in _xhttp_plain[:10]:
                    _box_warn(_xhttp_plain.replace("[WARN]", "").replace("[INFO]", "").strip())
                elif "[INFO]" in _xhttp_line:
                    _box_wrap_msg(f"  {CYAN}[INFO]{NC}  ", 9, _xhttp_plain.replace("[INFO]", "").strip())

    _box_wrap_msg(f"  {GREEN}[OK]{NC}    ", 11, f"Конфиг загружен: режим={INSTALL_MODE}, протокол={PROTOCOL_MODE}, домен={PARAM_DOMAIN}, порт={SERVER_PORT}")

    # ── ШАГ 2: диагностика — что сломано ──────────────────────────────────────
    _box_row()
    _box_row(f"  {CYAN}[2/11]{NC} Диагностика...")
    issues: list[str] = []

    # Проверяем юнит xray
    r_unit = _run(["systemctl", "cat", "xray"], capture=True, check=False)
    unit_text = r_unit.stdout if r_unit.returncode == 0 else ""
    # Проверяем юнит xray на проблемный ExecStartPre chown /dev/shm.
    # FIX: анализируем только раскомментированные строки — чтобы не ловить
    # строки вида "# ExecStartPre=/bin/chown /dev/shm" как проблему.
    unit_active_lines = "\n".join(
        line for line in unit_text.splitlines()
        if not line.lstrip().startswith("#")
    )
    if "chown" in unit_active_lines and "/dev/shm" in unit_active_lines:
        issues.append("unit_chown_shm")
        _box_wrap_msg(f"  {YELLOW}[WARN]{NC} ", 9, "Юнит xray содержит проблемный ExecStartPre chown /dev/shm — будет пересоздан")
    if not XRAY_SERVICE.exists():
        issues.append("unit_missing")
        _box_ok("Юнит xray.service отсутствует — будет создан")

    # Проверяем бинарник xray
    xray_ok = Path("/usr/local/bin/xray").exists()
    if not xray_ok:
        issues.append("xray_binary_missing")
        _box_wrap_msg(f"  {YELLOW}[WARN]{NC} ", 9, "Бинарник xray не найден — потребуется переустановка через пункт [5]")
    else:
        rv = _run(["/usr/local/bin/xray", "version"], capture=True, check=False)
        if rv.returncode != 0:
            issues.append("xray_binary_broken")
            _box_wrap_msg(f"  {YELLOW}[WARN]{NC} ", 9, "Бинарник xray повреждён — потребуется обновление через пункт [5]")

    # Проверяем конфиг xray
    cfg_path = Path("/etc/xray/config.json")
    if not cfg_path.exists():
        issues.append("config_missing")
        _box_ok("config.json не найден — будет пересоздан из state.json")
    else:
        rv2 = _run(["/usr/local/bin/xray", "-test", "-c", str(cfg_path)],
                   capture=True, check=False)
        if rv2.returncode != 0:
            issues.append("config_invalid")
            _box_wrap_msg(f"  {YELLOW}[WARN]{NC} ", 9, f"config.json не валиден — будет пересоздан")

    # Проверяем права на директорию сокета (только для REALITY)
    if PROTOCOL_MODE == "reality" and PARAM_SOCKET_PATH:
        sock_parent = Path(PARAM_SOCKET_PATH).parent
        if str(sock_parent) not in ("/", "/dev/shm"):
            # Нестандартная директория сокета — проверяем права
            if not sock_parent.exists():
                issues.append("socket_dir_missing")
                _box_ok(f"Директория сокета {sock_parent} отсутствует — будет создана")

    # Проверяем права на TLS-сертификаты (xhttp)
    if PROTOCOL_MODE == "xhttp" and PARAM_DOMAIN:
        privkey = Path(f"/etc/letsencrypt/live/{PARAM_DOMAIN}/privkey.pem")
        if privkey.exists():
            import stat as _stat
            mode = privkey.stat().st_mode & 0o777
            if mode not in (0o640, 0o600):
                issues.append("cert_perms")
                _box_ok(f"Права на privkey.pem некорректны — будут исправлены")
        else:
            _box_wrap_msg(f"  {YELLOW}[WARN]{NC} ", 9, f"TLS-сертификат не найден: {privkey}")

    # Проверяем nginx конфиг
    rn = _run(["nginx", "-t"], capture=True, check=False)
    if rn.returncode != 0:
        issues.append("nginx_config_broken")
        _box_ok("Конфиг nginx не прошёл проверку — попробуем пересоздать")

    if not issues:
        _box_ok("Явных проблем не обнаружено — выполним мягкий перезапуск")
    else:
        _box_warn(f"Обнаружено проблем: {len(issues)}")

    # ── ШАГ 3: пересоздаём systemd-юниты ──────────────────────────────────────
    _box_row()
    _box_row(f"  {CYAN}[3/11]{NC} Пересоздание systemd-юнитов...")
    import io as _io, contextlib as _cl
    _sink = _io.StringIO()
    try:
        with _cl.redirect_stdout(_sink):
            create_xray_service()
        _box_ok("Юнит xray.service пересоздан")
    except Exception as e:
        _box_warn(f"create_xray_service: {e}")
    try:
        with _cl.redirect_stdout(_sink):
            setup_nginx_systemd_override()
        _box_ok("nginx.service.d override восстановлен")
    except Exception as e:
        _box_warn(f"nginx override: {e}")
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)

    # ── ШАГ 4: пользователь, директории, права, nginx symlink, sysctl ──────────
    _box_row()
    _box_row(f"  {CYAN}[4/11]{NC} Восстановление прав доступа и системных настроек...")

    # Пользователь xray — мог исчезнуть при восстановлении хостером из снапшота
    r_id = _run(["id", "xray"], check=False, quiet=True)
    if r_id.returncode != 0:
        _run(["useradd", "-r", "-s", "/usr/sbin/nologin", "-d", "/var/lib/xray", "xray"],
             check=False, quiet=True)
        _box_ok("Пользователь xray воссоздан")
    else:
        _box_ok("Пользователь xray: существует")

    # Критичные директории xray
    for _xdir, _xmode in [
        (Path("/var/lib/xray"),                    0o750),
        (Path("/var/log/xray"),                    0o750),
        (Path("/etc/xray"),                        0o750),
        (Path("/var/lib/xray-installer"),          0o750),
    ]:
        _xdir.mkdir(parents=True, exist_ok=True)
        _run(["chown", "-R", "xray:xray", str(_xdir)], check=False, quiet=True)
        try:
            _xdir.chmod(_xmode)
        except Exception:
            pass
    _box_ok("Директории xray: права восстановлены")

    # www-data в группе xray (нужно для nginx→xray через Unix-сокет)
    _run(["usermod", "-aG", "xray", "www-data"], check=False, quiet=True)

    # Сокет (только REALITY)
    if PROTOCOL_MODE == "reality" and PARAM_SOCKET_PATH:
        sock_parent = Path(PARAM_SOCKET_PATH).parent
        if str(sock_parent) not in ("/", "/dev/shm"):
            sock_parent.mkdir(parents=True, exist_ok=True)
            _run(["chown", "xray:xray", str(sock_parent)], check=False, quiet=True)
            sock_parent.chmod(0o755)
            _box_ok(f"Директория сокета восстановлена: {sock_parent}")
        else:
            _box_ok(f"Сокет в {sock_parent} — права не меняем (системная директория)")
        old_sock = Path(PARAM_SOCKET_PATH)
        if old_sock.exists() or old_sock.is_socket():
            try:
                old_sock.unlink()
                _box_ok(f"Старый сокет-файл удалён: {PARAM_SOCKET_PATH}")
            except Exception:
                pass

    # TLS-сертификаты (только xHTTP)
    if PROTOCOL_MODE == "xhttp" and PARAM_DOMAIN:
        try:
            fix_letsencrypt_permissions(PARAM_DOMAIN)
            # Убеждаемся что fix-xray-certs.sh существует (встраивается в ExecStartPre)
            ensure_cert_fix_script(PARAM_DOMAIN)
            _box_ok("Права на TLS-сертификаты восстановлены")
        except Exception as e:
            _box_warn(f"fix_letsencrypt_permissions: {e}")

    # Права на конфиг xray
    try:
        _set_config_owner(Path("/etc/xray/config.json"))
    except Exception:
        pass

    # Nginx конфиг — при AWG всегда пересоздаём (старый конфиг может ссылаться на unix-сокет,
    # которого при AWG нет; Xray при AWG слушает на PORT напрямую).
    # В остальных случаях — восстанавливаем symlink если он исчез.
    if PARAM_DOMAIN:
        if AWG_EXIT_ENABLED:
            try:
                with _cl.redirect_stdout(_sink):
                    setup_nginx_final()
                _box_ok("Nginx конфиг пересоздан для AWG-режима (HTTP→HTTPS редирект)")
            except Exception as e:
                _box_warn(f"setup_nginx_final (AWG): {e}")
        else:
            _nginx_conf = Path(f"/etc/nginx/sites-available/{PARAM_DOMAIN}")
            _nginx_link = Path(f"/etc/nginx/sites-enabled/{PARAM_DOMAIN}")
            if _nginx_conf.exists() and not _nginx_link.exists():
                try:
                    _nginx_link.symlink_to(_nginx_conf)
                    _box_ok(f"Nginx symlink восстановлен: sites-enabled/{PARAM_DOMAIN}")
                except Exception as e:
                    _box_warn(f"Nginx symlink: {e}")
            elif _nginx_link.exists():
                _box_ok(f"Nginx symlink: существует")
            else:
                _box_row(f"  {DIM}Nginx конфиг {PARAM_DOMAIN} не найден в sites-available — пропуск{NC}")

    # sysctl — применяем принудительно (файл выживает ребут, но при
    # do_emergency_repair без перезагрузки ядро может не иметь актуальных значений;
    # для Режима B критично ip_forward=1)
    _sysctl_conf = Path("/etc/sysctl.d/99-vless-performance.conf")
    if _sysctl_conf.exists():
        r_sctl = _run(["sysctl", "--system"], check=False, quiet=True)
        if r_sctl.returncode == 0:
            _box_ok("sysctl --system применён (BBR, буферы, ip_forward)")
        else:
            _box_warn("sysctl --system завершился с ошибкой")
    else:
        _box_row(f"  {DIM}sysctl-конфиг не найден — пропуск{NC}")

    # unattended-upgrades (только apt-системы)
    import shutil as _shutil
    if _shutil.which("apt-get"):
        r_uu = _run(["systemctl", "is-active", "unattended-upgrades"],
                    capture=True, check=False)
        if r_uu.stdout.strip() != "active":
            _run(["systemctl", "enable", "--now", "unattended-upgrades"],
                 check=False, quiet=True)
            _box_ok("unattended-upgrades перезапущен")
        else:
            _box_ok("unattended-upgrades активен")

    # ── ШАГ 5: пересборка конфига и перезапуск сервисов ───────────────────────
    _box_row()
    _box_row(f"  {CYAN}[5/11]{NC} Пересборка конфига и перезапуск сервисов...")

    # При AWG — сначала восстанавливаем туннель, ПОТОМ запускаем Xray.
    # Xray маршрутизирует через awg0 — если awg0 не поднят в момент старта,
    # все соединения падают с "operation was canceled".
    if AWG_EXIT_ENABLED and INSTALL_MODE == "B":
        _box_row()
        _box_row(f"  {CYAN}[5a]{NC} Восстановление AWG-туннеля (до запуска Xray)...")
        _awg_svc = "amneziawg-awg0"
        r_awg_svc = _run(["systemctl", "is-active", _awg_svc], capture=True, check=False)
        if r_awg_svc.stdout.strip() != "active":
            _run(["systemctl", "enable", "--now", _awg_svc], check=False, quiet=True)
            # ИСПРАВЛЕНИЕ: sleep(2) было недостаточно — интерфейс awg0 может подниматься
            # дольше, и Xray стартовал до появления маршрута, из-за чего DNS-пакеты
            # уходили без AWG fwmark и отклонялись провайдером.
            # Теперь ждём реального появления интерфейса (до 15 сек).
            _awg_ready = False
            for _awg_i in range(15):
                _r_link = _run(["ip", "link", "show", AWG_INTERFACE],
                               capture=True, check=False)
                if _r_link.returncode == 0 and AWG_INTERFACE in (_r_link.stdout or ""):
                    _awg_ready = True
                    break
                time.sleep(1)
            if not _awg_ready:
                time.sleep(2)  # последний шанс
            r_awg_svc2 = _run(["systemctl", "is-active", _awg_svc], capture=True, check=False)
            if r_awg_svc2.stdout.strip() == "active":
                _box_ok("amneziawg-awg0 запущен")
            else:
                _box_warn(f"amneziawg-awg0 не запустился — проверьте: journalctl -u {_awg_svc} -n 20")
        else:
            _box_ok("amneziawg-awg0 активен")
        # Восстанавливаем ip rule + ip route + iptables
        try:
            _xray_uid_r = _run(["id", "-u", "xray"], capture=True, check=False)
            _xray_uid   = int(_xray_uid_r.stdout.strip()) if _xray_uid_r.returncode == 0 else 999
            _r_rule = _run(["ip", "rule", "show"], capture=True, check=False)
            if str(AWG_FWMARK) not in (_r_rule.stdout or ""):
                _run(["ip", "rule", "add", "fwmark", str(AWG_FWMARK),
                      "table", str(AWG_ROUTE_TABLE), "priority", "100"],
                     check=False, quiet=True)
                _box_ok(f"ip rule fwmark {AWG_FWMARK} восстановлен")
            else:
                _box_ok(f"ip rule fwmark {AWG_FWMARK}: присутствует")
            _r_rt = _run(["ip", "route", "show", "table", str(AWG_ROUTE_TABLE)],
                         capture=True, check=False)
            if "default" not in (_r_rt.stdout or ""):
                _run(["ip", "route", "add", "default", "dev", AWG_INTERFACE,
                      "table", str(AWG_ROUTE_TABLE)], check=False, quiet=True)
                _box_ok(f"ip route default dev {AWG_INTERFACE} восстановлен")
            else:
                _box_ok(f"ip route table {AWG_ROUTE_TABLE}: присутствует")
            _r_nat = _run(["iptables", "-t", "nat", "-L", "POSTROUTING", "-n"],
                          capture=True, check=False)
            if "MASQUERADE" not in (_r_nat.stdout or ""):
                _run(["bash", "-c",
                      "IFACE=$(ip route | awk '/default/ {print $5; exit}'); "
                      "[ -n \"$IFACE\" ] && iptables -t nat -A POSTROUTING "
                      "-o \"$IFACE\" -j MASQUERADE || true"],
                     check=False, quiet=True)
                _box_ok("iptables MASQUERADE восстановлен")
            else:
                _box_ok("iptables MASQUERADE: присутствует")
            _r_mangle = _run(["iptables", "-t", "mangle", "-L", "OUTPUT", "-n"],
                             capture=True, check=False)
            if f"0x{AWG_FWMARK:x}" not in (_r_mangle.stdout or "").lower():
                _run(["iptables", "-t", "mangle", "-A", "OUTPUT",
                      "-m", "owner", "--uid-owner", str(_xray_uid),
                      "-j", "MARK", "--set-mark", str(AWG_FWMARK)],
                     check=False, quiet=True)
                _box_ok(f"iptables mangle fwmark {AWG_FWMARK} восстановлен")
            else:
                _box_ok(f"iptables mangle OUTPUT fwmark: присутствует")
            # ИСПРАВЛЕНИЕ: dnscrypt-proxy работает от uid dnscrypt, не от xray.
            # Его DNS-трафик к upstream (138.124.98.4:443 и т.п.) тоже должен
            # идти через AWG — иначе провайдер блокирует DoT/DNSCrypt.
            try:
                _dc_uid_r = _run(["id", "-u", "dnscrypt"], capture=True, check=False)
                _dc_uid = int(_dc_uid_r.stdout.strip()) if _dc_uid_r.returncode == 0 else None
                if _dc_uid is not None:
                    _r_dc_mangle = _run(
                        ["iptables", "-t", "mangle", "-L", "OUTPUT", "-n"],
                        capture=True, check=False)
                    if f"0x{AWG_FWMARK:x}" not in (_r_dc_mangle.stdout or "").lower() \
                            or str(_dc_uid) not in (_r_dc_mangle.stdout or ""):
                        _run(["iptables", "-t", "mangle", "-A", "OUTPUT",
                              "-m", "owner", "--uid-owner", str(_dc_uid),
                              "-j", "MARK", "--set-mark", str(AWG_FWMARK)],
                             check=False, quiet=True)
                        _box_ok(f"iptables mangle dnscrypt uid {_dc_uid} fwmark восстановлен")
                    else:
                        _box_ok(f"iptables mangle dnscrypt uid fwmark: присутствует")
            except Exception:
                pass  # dnscrypt не установлен
        except Exception as _awg_e:
            _box_warn(f"Восстановление AWG policy routing: {_awg_e}")
        _box_row()
        # === PATCH v2: мульти-нодовое аварийное восстановление ===
        if state.get("awg_nodes") and len(state.get("awg_nodes", [])) > 1:
            _box_row(f"  {CYAN}[5b]{NC} Восстановление AWG Multi-Node ({len(state['awg_nodes'])} нод)...")
            try:
                _awg_emergency_restore_all_nodes()
            except Exception as _mne:
                _box_warn(f"AWG Multi-Node: {_mne}")
        # === END PATCH v2 ===

    # ── AdGuardHome: поднять ДО пересборки конфига ────────────────────────────
    # В стеке «Xray → AGH(127.0.0.1:53) → DNSCrypt(5300)» генераторы конфига
    # делают health-check AGH (agh_probe.py) и переключают DNS Xray на :53
    # только у живого и резолвящего AGH. Остановленный после краха AGH без
    # этого шага молча «выпадал» из цепочки — конфиг откатывался на 5300.
    try:
        from chimera.modules.agh_probe import agh_ensure_running
        _agh_ok, _agh_note = agh_ensure_running(_run)
        if _agh_ok:
            _box_ok(f"AdGuardHome: {_agh_note}")
        # не установлен / не поднялся → генераторы сами откатятся на
        # DNSCrypt:5300 — это безопасный путь, не ошибка восстановления
    except Exception as _agh_e:
        _box_warn(f"AdGuardHome: {_agh_e}")

    # Пересборка конфига:
    # - всегда при AWG_EXIT_ENABLED (даже валидный старый конфиг может не иметь AWG sockopt mark)
    # - при отсутствии или невалидности конфига в остальных режимах
    _need_regen = (
        "config_missing" in issues
        or "config_invalid" in issues
        or AWG_EXIT_ENABLED  # при AWG всегда пересобираем — гарантируем наличие mark
    )
    if _need_regen:
        try:
            with _cl.redirect_stdout(_sink):
                if INSTALL_MODE == "B":
                    generate_xray_config_chain_entry_multi()
                elif PROTOCOL_MODE == "xhttp":
                    generate_xray_config_xhttp()
                else:
                    generate_xray_config()
            _box_ok("Конфиг Xray пересоздан из state.json")
        except Exception as e:
            _box_wrap_msg(f"  {YELLOW}[WARN]{NC} ", 9, f"Ошибка пересборки конфига: {e}")

    # Восстанавливаем пользователей
    users_file = Path("/etc/xray/users.json")
    if users_file.exists():
        try:
            uu = json.loads(users_file.read_text())
            if uu:
                with _cl.redirect_stdout(_sink):
                    _users_patch_config_no_restart(uu)
                _box_ok(f"Восстановлено пользователей: {len(uu)}")
        except Exception as e:
            _box_warn(f"Восстановление пользователей: {e}")

    # Восстанавливаем RIPE/РФ-подсети в routing
    try:
        with _cl.redirect_stdout(_sink):
            _ru_subnets_restore_if_needed(silent=True)
        _box_ok("РФ-подсети в routing восстановлены")
    except Exception as e:
        _box_warn(f"РФ-подсети: {e}")

    # Восстанавливаем AS-direct правила в routing
    try:
        with _cl.redirect_stdout(_sink):
            _as_direct_restore_if_needed(silent=True)
        if _as_direct_list_load():
            _box_ok("AS-direct правила в routing восстановлены")
    except Exception as e:
        _box_warn(f"AS-direct: {e}")

    # ── Восстановление Telemt tproxy-интеграции ───────────────────────────────
    # После пересборки config.json dokodemo-door inbound теряется — нужно
    # переинжектировать до запуска Xray. Детект — по факту (бинарник/сервис),
    # без флагов в state.json (их для tproxy нет).
    try:
        from chimera.modules.mtproto import telemt_tproxy_emergency_restore
        import io as _io_tp, contextlib as _cl_tp
        _tp_sink = _io_tp.StringIO()
        with _cl_tp.redirect_stdout(_tp_sink):
            _tp_result, _tp_msg = telemt_tproxy_emergency_restore()
        if _tp_result is None:
            _box_row(f"  {DIM}Telemt tproxy: {_tp_msg} — пропуск{NC}")
        elif _tp_result:
            _box_ok(f"Telemt tproxy: {_tp_msg}")
        else:
            _box_warn(f"Telemt tproxy: {_tp_msg}")
    except ImportError:
        _box_row(f"  {DIM}Модуль mtproto не найден — Telemt tproxy пропуск{NC}")
    except Exception as _tp_e:
        _box_warn(f"Telemt tproxy: {_tp_e}")

    # DNSCrypt
    # ИСПРАВЛЕНИЕ: раньше проверялся только флаг PARAM_USE_DNSCRYPT из state.json.
    # Но DNSCrypt мог быть запущен (и использоваться Xray как DNS upstream) даже
    # при PARAM_USE_DNSCRYPT=False — например, в Режиме B + AWG, где DNSCrypt
    # не всегда записывается в state.json. В таком случае после аварийного
    # восстановления Xray пытался слать DNS через DNSCrypt, тот не был перезапущен
    # и не имел корректного AWG-маршрута, что давало "actively refused" на DNS upstream.
    _r_dc_active = _run(["systemctl", "is-active", "dnscrypt-proxy"],
                        capture=True, check=False)
    _dc_is_running = (_r_dc_active.stdout.strip() == "active")
    if PARAM_USE_DNSCRYPT or _dc_is_running:
        r_dc = _run(["systemctl", "is-enabled", "dnscrypt-proxy"],
                    capture=True, check=False)
        if r_dc.returncode == 0 or _dc_is_running:
            _run(["systemctl", "stop",    "dnscrypt-proxy"], check=False, quiet=True)
            _run(["systemctl", "start",   "dnscrypt-proxy"], check=False, quiet=True)
            if _wait_service_active("dnscrypt-proxy", 10, silent=True):
                _box_ok("dnscrypt-proxy запущен")
            else:
                _box_warn("dnscrypt-proxy не запустился")
            time.sleep(2)

    # Запуск Xray
    # v56 (start-limit-fix): reset-failed обязателен перед каждым start —
    # если восстановление запущено вскоре после неудачной пересборки
    # (3+ рестарта подряд), счётчик start-rate-limit юнита xray
    # (StartLimitBurst=3/60s) ещё не остыл и первый же start был бы
    # отклонён («Start request repeated too quickly» → start-limit-hit).
    _run(["systemctl", "reset-failed", "xray"], check=False, quiet=True)
    _run(["systemctl", "stop",  "xray"], check=False, quiet=True)
    time.sleep(1)
    _run(["systemctl", "start", "xray"], check=False, quiet=True)
    xray_ok_started = _wait_service_active("xray", 25, silent=True)
    if not xray_ok_started:
        _box_warn("Повторная попытка запуска Xray...")
        _run(["systemctl", "reset-failed", "xray"], check=False, quiet=True)
        _run(["systemctl", "stop",  "xray"], check=False, quiet=True)
        time.sleep(4)
        _run(["systemctl", "start", "xray"], check=False, quiet=True)
        xray_ok_started = _wait_service_active("xray", 20, silent=True)

    if xray_ok_started:
        _box_ok("Xray запущен")
    else:
        _box_warn("Xray не запустился — проверьте: journalctl -u xray -n 20")

    # Ждём сокет (только REALITY без AWG — при AWG Xray слушает на PORT, сокета нет)
    if PROTOCOL_MODE == "reality" and xray_ok_started and PARAM_SOCKET_PATH and not AWG_EXIT_ENABLED:
        _box_row(f"  {DIM}Ожидание Unix-сокета...{NC}")
        for _ in range(20):
            if Path(PARAM_SOCKET_PATH).is_socket():
                _box_ok(f"Сокет готов")
                break
            time.sleep(1)
        else:
            _box_warn("Сокет не появился — проверьте: journalctl -u xray -n 20")

    # Nginx
    _run(["systemctl", "stop",  "nginx"], check=False, quiet=True)
    time.sleep(1)
    _run(["systemctl", "start", "nginx"], check=False, quiet=True)
    nginx_ok = _wait_service_active("nginx", 15, silent=True)
    if nginx_ok:
        _box_ok("Nginx запущен")
    else:
        _box_warn("Nginx не запустился — journalctl -u nginx -n 20")

    # ── ШАГ 6: опциональные сервисы (fail2ban, irqbalance, WARP) ─────────────
    _box_row()
    _box_row(f"  {CYAN}[6/11]{NC} Опциональные сервисы...")

    # fail2ban — всегда устанавливается вместе с xray
    r_f2b = _run(["systemctl", "is-active", "fail2ban"], capture=True, check=False)
    if r_f2b.returncode != 127:   # 127 = not found
        if r_f2b.stdout.strip() != "active":
            _run(["systemctl", "stop",    "fail2ban"], check=False, quiet=True)
            time.sleep(1)
            _run(["systemctl", "start",   "fail2ban"], check=False, quiet=True)
            time.sleep(2)
            _run(["systemctl", "restart", "fail2ban"], check=False, quiet=True)
            r_f2b2 = _run(["systemctl", "is-active", "fail2ban"], capture=True, check=False)
            if r_f2b2.stdout.strip() == "active":
                _box_ok("fail2ban перезапущен")
            else:
                _box_warn("fail2ban не запустился")
        else:
            _box_ok("fail2ban активен")
    else:
        _box_row(f"  {DIM}fail2ban не установлен — пропуск{NC}")

    # irqbalance — ставится при оптимизации системы
    r_irq = _run(["systemctl", "is-active", "irqbalance"], capture=True, check=False)
    if r_irq.returncode != 127:
        if r_irq.stdout.strip() != "active":
            _run(["systemctl", "enable", "--now", "irqbalance"], check=False, quiet=True)
            _box_ok("irqbalance перезапущен")
        else:
            _box_ok("irqbalance активен")
    else:
        _box_row(f"  {DIM}irqbalance не установлен — пропуск{NC}")

    # WARP — опциональный компонент, читаем из state.json
    warp_installed = state.get("warp_installed", False)
    if warp_installed:
        warp_mode = state.get("warp_mode", "full")
        # Определяем какой warp-юнит активен по режиму
        warp_units = {
            "full":       "warp-svc",
            "ssh":        "warp-ssh-ns",
            "selective":  "warp-selective",
            "runet":      "warp-runet",
        }
        warp_unit = warp_units.get(warp_mode, "warp-svc")
        r_warp = _run(["systemctl", "is-active", warp_unit], capture=True, check=False)
        if r_warp.stdout.strip() != "active":
            _run(["systemctl", "enable", warp_unit], check=False, quiet=True)
            _run(["systemctl", "start",  warp_unit], check=False, quiet=True)
            time.sleep(3)
            r_warp2 = _run(["systemctl", "is-active", warp_unit], capture=True, check=False)
            if r_warp2.stdout.strip() == "active":
                _box_ok(f"WARP ({warp_unit}) перезапущен")
            else:
                _box_warn(f"WARP ({warp_unit}) не запустился — проверьте: warp-cli status")
        else:
            _box_ok(f"WARP ({warp_unit}) активен")
    else:
        _box_row(f"  {DIM}WARP не установлен — пропуск{NC}")

    # ── ШАГ 7: systemd-таймеры ────────────────────────────────────────────────
    _box_row()
    _box_row(f"  {CYAN}[7/11]{NC} Восстановление systemd-таймеров...")

    def _repair_timer(timer_name: str, label: str) -> None:
        """Включает и запускает systemd-таймер если не активен."""
        timer_path = Path(f"/etc/systemd/system/{timer_name}")
        if not timer_path.exists():
            _box_row(f"  {DIM}{label}: не установлен — пропуск{NC}")
            return
        r = _run(["systemctl", "is-active", timer_name], capture=True, check=False)
        if r.stdout.strip() != "active":
            _run(["systemctl", "enable", "--now", timer_name], check=False, quiet=True)
            r2 = _run(["systemctl", "is-active", timer_name], capture=True, check=False)
            if r2.stdout.strip() == "active":
                _box_ok(f"{label}: перезапущен")
            else:
                _box_warn(f"{label}: не запустился")
        else:
            _box_ok(f"{label}: активен")

    _repair_timer("xray-watchdog.timer",    "Watchdog")
    _repair_timer("nginx-watchdog.timer",   "nginx Watchdog")
    _repair_timer("xray-autoupdate.timer",  "Autoupdate Xray-core")
    _repair_timer("xray-geo-update.timer",  "Geo-update (systemd)")
    _repair_timer("xray-ru-subnets.timer",  "РФ-подсети")

    # Финальный daemon-reload
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)

    # ── ШАГ 8: cron.d-задачи ──────────────────────────────────────────────────
    _box_row()
    _box_row(f"  {CYAN}[8/11]{NC} Проверка cron.d-задач...")

    # certbot — в crontab root, не в cron.d
    r_cron = _run(["crontab", "-l"], capture=True, check=False)
    cron_text = r_cron.stdout if r_cron.returncode == 0 else ""
    if "certbot" in cron_text:
        _box_ok("certbot renew: активен (crontab)")
    else:
        _box_row(f"  {DIM}certbot cron не найден — пропуск{NC}")

    # Все остальные cron.d задачи — просто проверяем наличие файла,
    # т.к. если файл есть — cron его подхватывает автоматически после reboot.
    # Сам crond/cron обычно переживает перезагрузку без проблем.
    _cron_jobs = [
        ("/etc/cron.d/xray-geo-update",       "Geo-update (cron.d)"),
        ("/etc/cron.d/xray-fp-rotate",        "FP-rotate"),
        ("/etc/cron.d/xray-uuid-rotate",      "UUID-rotate"),
        ("/etc/cron.d/xray-tg-monitor",       "Telegram-monitor"),
        ("/etc/cron.d/xray-ttl-check",        "TTL-check пользователей"),
        ("/etc/cron.d/xray-traffic-limits",   "Traffic-limits"),
        ("/etc/cron.d/xray-traffic-snapshot", "Traffic-snapshot"),
        ("/etc/cron.d/xray-health-report",    "Health-report"),
        ("/etc/cron.d/xray-autoban",          "AutoBan"),
        ("/etc/cron.d/xray-certbot-monitor",  "Certbot-monitor"),
        ("/etc/cron.d/xray-dpi-detector",     "DPI-detector"),
        ("/etc/cron.d/xray-failover-watch",   "Failover-watch"),
        ("/etc/cron.d/xray-auto-fallback",    "Auto-fallback"),
        ("/etc/cron.d/xray-ingress-geoip",    "Ingress GeoIP update"),
    ]
    _cron_restarted = False
    for cron_path, label in _cron_jobs:
        if Path(cron_path).exists():
            # Проверяем что cron-демон активен (на случай если он тоже упал)
            if not _cron_restarted:
                r_crond = _run(["systemctl", "is-active", "cron"],
                               capture=True, check=False)
                if r_crond.stdout.strip() != "active":
                    _run(["systemctl", "restart", "cron"], check=False, quiet=True)
                    _box_ok("cron-демон перезапущен")
                    _cron_restarted = True
            _box_ok(f"{label}: активен")

    # ── ШАГ 9: восстановление ingress GeoIP (iptables/ipset) ──────────────────
    _box_row()
    _box_row(f"  {CYAN}[9/11]{NC} Ingress GeoIP-блокировка...")
    try:
        ing = _ingress_state_load()
        if ing.get("enabled"):
            ing_port = ing.get("port", SERVER_PORT)
            _box_row(f"  {DIM}Восстановление ipset/iptables для порта {ing_port}...{NC}")
            try:
                import io as _io_ing, contextlib as _cl_ing
                _ing_cap = _io_ing.StringIO()
                with _cl_ing.redirect_stdout(_ing_cap):
                    _ingress_enable(ing_port)
                _ingress_out = _ing_cap.getvalue()
                if _ingress_out.strip():
                    import re as _re_ing
                    for _il in _ingress_out.splitlines():
                        _ip = _re_ing.sub(r'\033\[[0-9;]*m', '', _il).strip()
                        if _ip:
                            if "[WARN]" in _il or "WARN" in _ip[:10]:
                                _box_warn(_ip.replace("[WARN]", "").strip())
                            else:
                                _box_row(f"  {DIM}{_ip}{NC}")
                _box_ok(f"Ingress GeoIP восстановлена (порт {ing_port})")
            except Exception as e:
                _box_warn(f"Ingress GeoIP: {e}")
        else:
            _box_row(f"  {DIM}Ingress GeoIP не активирована — пропуск{NC}")
    except Exception as e:
        _box_warn(f"Ingress GeoIP state: {e}")

    # ── ШАГ 10: honeypot-сервис ────────────────────────────────────────────────
    _box_row()
    _box_row(f"  {CYAN}[10/11]{NC} Honeypot-сервис...")
    try:
        _HONEYPOT_STATE  = Path("/var/lib/xray-installer/honeypot.json")
        _HONEYPOT_SVC    = Path("/etc/systemd/system/xray-honeypot.service")
        if _HONEYPOT_STATE.exists() and _HONEYPOT_SVC.exists():
            hp_state = json.loads(_HONEYPOT_STATE.read_text())
            if hp_state.get("enabled"):
                r_hp = _run(["systemctl", "is-active", "xray-honeypot"],
                            capture=True, check=False)
                if r_hp.stdout.strip() != "active":
                    _run(["systemctl", "enable", "--now", "xray-honeypot"],
                         check=False, quiet=True)
                    r_hp2 = _run(["systemctl", "is-active", "xray-honeypot"],
                                 capture=True, check=False)
                    if r_hp2.stdout.strip() == "active":
                        _box_ok("Honeypot перезапущен")
                    else:
                        _box_warn("Honeypot не запустился")
                else:
                    _box_ok("Honeypot активен")
            else:
                _box_row(f"  {DIM}Honeypot отключён в настройках — пропуск{NC}")
        else:
            _box_row(f"  {DIM}Honeypot не установлен — пропуск{NC}")
    except Exception as e:
        _box_warn(f"Honeypot: {e}")

    # ── ШАГ 11: итоговый health-report ────────────────────────────────────────
    _box_row()
    _box_row(f"  {CYAN}[11/11]{NC} Итоговая проверка состояния...")
    time.sleep(2)

    # Основные сервисы
    svcs_check = [("xray", "Xray"), ("nginx", "Nginx")]
    if PARAM_USE_DNSCRYPT:
        r_dc2 = _run(["systemctl", "is-enabled", "dnscrypt-proxy"],
                     capture=True, check=False)
        if r_dc2.returncode == 0:
            svcs_check.insert(0, ("dnscrypt-proxy", "DNSCrypt-proxy"))

    # v56: AdGuardHome — если установлен, это звено DNS-цепочки
    # «Xray → AGH(127.0.0.1:53) → DNSCrypt(5300)»: шагом выше восстановление
    # уже поднимает его (agh_ensure_running), здесь — финальный контроль.
    # Не установлен → строка не выводится (как у DNSCrypt при is-enabled != 0).
    _agh_installed = False
    try:
        from chimera.modules.aghome_setup import is_aghome_installed
        _agh_installed = is_aghome_installed()
    except Exception:
        _agh_installed = Path("/etc/systemd/system/AdGuardHome.service").exists()
    if _agh_installed:
        # После DNSCrypt, перед Xray — порядок DNS-цепочки снизу вверх.
        _dc_count = sum(1 for s, _l in svcs_check if s == "dnscrypt-proxy")
        svcs_check.insert(_dc_count, ("AdGuardHome", "AdGuardHome"))

    all_ok = True
    for svc_name, svc_label in svcs_check:
        rs = _run(["systemctl", "is-active", svc_name], capture=True, check=False)
        if rs.stdout.strip() == "active":
            _box_ok(f"{svc_label}: ● активен")
        else:
            _box_warn(f"{svc_label}: ○ неактивен")
            all_ok = False

    # Опциональные сервисы — только если установлены
    _opt_svcs = [
        ("fail2ban",         "Fail2ban"),
        ("irqbalance",       "IRQbalance"),
    ]
    if warp_installed:
        _opt_svcs.append((warp_units.get(state.get("warp_mode", "full"), "warp-svc"), "WARP"))
    if Path("/etc/systemd/system/xray-honeypot.service").exists():
        _opt_svcs.append(("xray-honeypot", "Honeypot"))

    for svc_name, svc_label in _opt_svcs:
        rs = _run(["systemctl", "is-active", svc_name], capture=True, check=False)
        status = rs.stdout.strip()
        if status == "active":
            _box_ok(f"{svc_label}: ● активен")
        elif status in ("inactive", "unknown"):
            _box_row(f"  {DIM}{svc_label}: ○ неактивен (не запущен или не установлен){NC}")
        else:
            _box_warn(f"{svc_label}: ○ {status}")

    _box_row()
    if all_ok:
        _box_ok("✅  Аварийное восстановление завершено успешно")
        _box_row(f"  {DIM}Все ключевые сервисы активны, планировщики восстановлены{NC}")
    else:
        _box_warn("⚠️  Восстановление завершено с предупреждениями")
        _box_wrap_msg(f"  {YELLOW}", 2,
            f"Один или несколько сервисов не запустились. "
            f"Проверьте журналы ниже.{NC}")
        _box_row()
        _box_row(f"  {DIM}Быстрая диагностика:{NC}")
        _box_wrap_msg(f"  {DIM}", 2, f"xray -test -c /etc/xray/config.json{NC}")
        _box_wrap_msg(f"  {DIM}", 2, f"journalctl -u xray -n 30 --no-pager{NC}")
        _box_wrap_msg(f"  {DIM}", 2, f"journalctl -u nginx -n 20 --no-pager{NC}")
        _box_wrap_msg(f"  {DIM}", 2, f"journalctl -u fail2ban -n 10 --no-pager{NC}")
        if _agh_installed:
            _box_wrap_msg(f"  {DIM}", 2,
                f"journalctl -u AdGuardHome -n 20 --no-pager{NC}")

    log_to_file("INFO", f"do_emergency_repair: завершено, all_ok={all_ok}, "
                        f"issues={issues}")
    _box_bottom()
    input(f"{BLUE}Нажмите Enter...{NC}")
