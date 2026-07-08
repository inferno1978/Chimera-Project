"""
vless_installer/modules/switch_mode.py
───────────────────────────────────────────────────────────────────────────────
Переключение сервера между Режимом A (прямой выход) и Режимом B (entry node →
каскад exit-нод или AWG-туннель) без полной переустановки Xray.

Содержит:
  • ``switch_mode_ab()`` — CLI entry point для ``--switch-mode-a/B``:
      1. Читает state.json, определяет текущий режим.
      2. Если переключаемся в B (без AWG) — проверяет наличие chain_nodes.
      3. Останавливает Xray.
      4. Загружает все переменные из state.json и мутирует глобалы ядра
         (``PROTOCOL_MODE``, ``XHTTP_*``, ``PARAM_*``, ``SERVER_PORT``,
         ``CHAIN_EXIT_*``, ``AWG_EXIT_ENABLED``, ``H2_EXIT_ENABLED``,
         ``PARAM_REALITY_DEST`` и т.д.) через ``setattr(core, ...)``.
      5. Обновляет install_mode в state.json.
      6. Регенерирует конфиг через ``_rebuild_and_restart_xray()``.

Точки входа из _core.py:
    from vless_installer.modules.switch_mode import switch_mode_ab

В оригинале ``switch_mode_ab`` использовала ``global X`` для ~30 глобалов;
в этом модуле все ``global X`` удалены, а записи заменены на
``setattr(core, "X", value)`` — что эквивалентно ``_core.X = value`` и
сохраняет прежнюю семантику (``_rebuild_and_restart_xray`` и другие функции
``_core`` читают эти имена из своего глобального namespace).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import time


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль vless_installer._core, импортируя его лениво."""
    import importlib
    return importlib.import_module("vless_installer._core")


# =============================================================================
#  ПЕРЕКЛЮЧЕНИЕ РЕЖИМА A ↔ B БЕЗ ПЕРЕУСТАНОВКИ
# =============================================================================
def switch_mode_ab() -> None:
    """
    Переключает сервер между Режимом A (прямой выход) и Режимом B (entry node → каскад)
    без полной переустановки.

    Алгоритм:
      1. Читает state.json, определяет текущий режим.
      2. Если переключаемся в B — проверяет наличие chain_nodes в state.json.
      3. Останавливает Xray.
      4. Обновляет install_mode в state.json.
      5. Регенерирует xray config (вызывает нужную функцию генерации).
      6. Перезапускает Xray.
    """
    core = _core_module()
    STATE_FILE = core.STATE_FILE
    warn    = core.warn
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_warn   = core._box_warn
    _box_info   = core._box_info
    _box_ok     = core._box_ok
    _box_bottom = core._box_bottom
    _run = core._run
    _nodes_from_state = core._nodes_from_state
    _rebuild_and_restart_xray = core._rebuild_and_restart_xray
    log_to_file = core.log_to_file
    CYAN = core.CYAN
    NC   = core.NC
    DIM  = core.DIM
    BLUE = core.BLUE

    if not STATE_FILE.exists():
        warn("state.json не найден — сначала выполните установку.")
        return

    try:
        state = json.loads(STATE_FILE.read_text())
    except Exception as e:
        warn(f"Ошибка чтения state.json: {e}")
        return

    current_mode = state.get("install_mode", "A")
    target_mode  = "B" if current_mode == "A" else "A"
    _awg_active  = state.get("awg_exit_enabled", False)

    print()
    print()
    _box_top(f"Переключение режима A ↔ B")
    _box_row()
    _box_row(f"  Текущий режим: {CYAN}{current_mode}{NC}")
    _box_row(f"  Целевой режим: {CYAN}{target_mode}{NC}")
    if _awg_active:
        _box_row(f"  Транспорт:     {CYAN}AWG 2.0 активен{NC}")
    _box_row()

    # При AWG + target=B: ноды VLESS не нужны (выход через awg0), но предупреждаем
    if _awg_active and target_mode == "B":
        _box_warn("Транспорт AWG 2.0 активен — VLESS exit-ноды не используются.")
        _box_row(f"  {DIM}Переключение в Режим B сохранит AWG как транспорт.{NC}")
        _box_row(f"  {DIM}Ноды VLESS можно не задавать.{NC}")
        _box_row()

    # При AWG + target=A: предупреждаем что AWG-туннель останется, но трафик пойдёт напрямую
    if _awg_active and target_mode == "A":
        _box_warn("ВНИМАНИЕ: переключение в Режим A отключает каскад.")
        _box_row(f"  {DIM}AWG-туннель (amneziawg-awg0) останется запущен, но Xray{NC}")
        _box_row(f"  {DIM}перестанет маршрутизировать через него — трафик пойдёт напрямую.{NC}")
        _box_row()

    # При переключении в B без AWG — нужны ноды
    if target_mode == "B" and not _awg_active:
        nodes = _nodes_from_state(state)
        if not nodes:
            _box_warn("В state.json не найдены exit-ноды (chain_nodes).")
            _box_warn("Добавьте ноды через меню [E] и повторите переключение.")
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")
            return
        _box_info(f"Найдено exit-нод: {len(nodes)}")
        for i, nd in enumerate(nodes):
            _box_row(f"    #{i+1}: {nd.get('host','?')}:{nd.get('port', 443)}")
        _box_row()

    _box_bottom()
    confirm = input(f"Переключить в Режим {target_mode}? [y/N]: ").strip().lower()
    if confirm != "y":
        _box_info("Отменено.")
        return

    # --- Загружаем все переменные из state и пишем их в globals ядра (_core) ---
    setattr(core, "PROTOCOL_MODE",   state.get("protocol_mode",  "reality"))
    setattr(core, "XHTTP_MODE",      state.get("xhttp_mode",     "auto"))
    setattr(core, "XHTTP_PATH",      state.get("xhttp_path",     "/xhttp"))
    setattr(core, "XHTTP_PERF_PRESET", state.get("xhttp_perf_preset", "balanced"))
    setattr(core, "XHTTP_PADDING_BYTES",           state.get("xhttp_padding_bytes",           0))
    setattr(core, "XHTTP_NO_SSE_HEADER",           state.get("xhttp_no_sse_header",           False))
    setattr(core, "XHTTP_NO_GRPC_HEADER",          state.get("xhttp_no_grpc_header",          False))
    setattr(core, "XHTTP_HOST",                    state.get("xhttp_host",                    ""))
    setattr(core, "XHTTP_SC_STREAM_UP_SERVER_SECS",state.get("xhttp_sc_stream_up_server_secs",0))
    setattr(core, "XHTTP_SC_MAX_EACH_POST_BYTES",  state.get("xhttp_sc_max_each_post_bytes",  0))
    setattr(core, "XHTTP_SC_MIN_POSTS_INTERVAL_MS",state.get("xhttp_sc_min_posts_interval_ms",0))
    setattr(core, "XHTTP_SC_MAX_BUFFERED_POSTS",   state.get("xhttp_sc_max_buffered_posts",   0))
    setattr(core, "XHTTP_XMUX_ENABLED",            state.get("xhttp_xmux_enabled",            False))
    setattr(core, "XHTTP_XMUX_MAX_CONCURRENCY",    state.get("xhttp_xmux_max_concurrency",    "16-32"))
    setattr(core, "XHTTP_XMUX_MAX_CONNECTIONS",    state.get("xhttp_xmux_max_connections",    0))
    setattr(core, "XHTTP_XMUX_C_MAX_REUSE_TIMES",  state.get("xhttp_xmux_c_max_reuse_times",  "0"))
    setattr(core, "XHTTP_XMUX_H_MAX_REQUEST_TIMES",state.get("xhttp_xmux_h_max_request_times","600-900"))
    setattr(core, "XHTTP_XMUX_H_MAX_REUSABLE_SECS",state.get("xhttp_xmux_h_max_reusable_secs","1800-3000"))
    setattr(core, "XHTTP_XMUX_H_KEEP_ALIVE_PERIOD",state.get("xhttp_xmux_h_keep_alive_period",0))
    setattr(core, "XHTTP_TCP_NO_DELAY",            state.get("xhttp_tcp_no_delay",            False))
    setattr(core, "XHTTP_ENABLE_SESSION_RESUMPTION",state.get("xhttp_enable_session_resumption",False))
    setattr(core, "SERVER_PORT",     state.get("server_port",   443))
    setattr(core, "PARAM_DOMAIN",    state.get("domain",        ""))
    setattr(core, "PARAM_UUID",      state.get("uuid",          ""))
    setattr(core, "PARAM_PUBLIC_KEY",  state.get("public_key",  ""))
    setattr(core, "PARAM_PRIVATE_KEY", state.get("private_key", ""))
    setattr(core, "PARAM_SHORTID",   state.get("short_id",      ""))
    setattr(core, "PARAM_SPIDERX",   state.get("spiderx",       ""))
    setattr(core, "PARAM_SOCKET_PATH", state.get("socket",      "/run/xray/xray.sock"))
    setattr(core, "PARAM_DOMAIN_STRATEGY", state.get("strategy","UseIPv4v6"))
    setattr(core, "PARAM_SITE_TEMPLATE",   state.get("template", 1))
    setattr(core, "PARAM_EMAIL",     state.get("email",         ""))
    setattr(core, "IPV6_PREFLIGHT",  state.get("ipv6",          False))
    CHAIN_NODES = _nodes_from_state(state)
    setattr(core, "CHAIN_NODES",     CHAIN_NODES)
    setattr(core, "CHAIN_BALANCER_STRATEGY", state.get("chain_balancer_strategy", "roundRobin"))
    # BUGFIX: раньше эти три поля не читались из state.json в этой функции —
    # generate_xray_config()/generate_xray_config_chain_entry_multi() ниже
    # использовали протухшие значения из памяти процесса.
    setattr(core, "AWG_EXIT_ENABLED",   state.get("awg_exit_enabled", False))
    setattr(core, "H2_EXIT_ENABLED",    state.get("h2_exit_enabled", False))
    setattr(core, "PARAM_REALITY_DEST", state.get("reality_dest", ""))
    if CHAIN_NODES:
        n = CHAIN_NODES[0]
        setattr(core, "CHAIN_EXIT_HOST",    n.get("host",    ""))
        setattr(core, "CHAIN_EXIT_PORT",    n.get("port",    443))
        setattr(core, "CHAIN_EXIT_UUID",    n.get("uuid",    ""))
        setattr(core, "CHAIN_EXIT_PUBKEY",  n.get("pubkey",  ""))
        setattr(core, "CHAIN_EXIT_SHORTID", n.get("short_id",""))
        setattr(core, "CHAIN_EXIT_SNI",     n.get("sni",     ""))
        setattr(core, "CHAIN_EXIT_FP",      n.get("fp",      "chrome"))

    # Обновляем install_mode в state
    setattr(core, "INSTALL_MODE", target_mode)
    state["install_mode"] = target_mode

    # --- Шаг 1: Остановка Xray ---
    _box_info("Шаг 1/4: останавливаем Xray...")
    _run(["systemctl", "stop", "xray"], check=False, quiet=True)
    time.sleep(1)

    # --- Шаг 2: Сохраняем state ---
    _box_info("Шаг 2/4: обновляем state.json...")
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    _box_ok(f"install_mode → {target_mode}")

    # --- Шаг 3+4: Регенерируем конфиг + восстанавливаем пользователей/RIPE + рестарт ---
    _box_info("Шаги 3-4/4: регенерируем конфиг, восстанавливаем пользователей и RIPE-правила...")
    try:
        _rebuild_and_restart_xray(f"✅ Xray запущен в Режиме {target_mode}.")
        _box_ok("Конфиг Xray применён.")
        log_to_file("INFO", f"switch_mode_ab: переключено A↔B → {target_mode}")
    except Exception as e:
        _box_warn(f"Ошибка генерации конфига: {e}")
        _box_warn("Xray не запущен — исправьте конфиг вручную.")
        return

    _box_row()
    _box_bottom()
    input(f"{BLUE}Нажмите Enter...{NC}")
