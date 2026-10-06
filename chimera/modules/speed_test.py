"""
chimera/modules/speed_test.py
───────────────────────────────────────────────────────────────────────────────
Тест скорости через exit-ноды (и AWG-туннель) + латентность.

Содержит:
  • ``do_speed_test(auto_mode=False)`` — измерение скорости и латентности в
    зависимости от режима установки:
      - Режим A (Exit-нода): тест напрямую в интернет до Cloudflare
        (делегируется ``_speed_test_mode_a`` в _core.py).
      - Режим B + AWG: тест выходного IP/латентности/скачивания через awg0.
      - Режим B + VLESS chain: тест до каждой exit-ноды по очереди
        (GeoIP → TCP-latency → Download через Cloudflare).

Точки входа из _core.py:
    from chimera.modules.speed_test import do_speed_test

Доступ к helpers ядра (``_box_*``, ``_run``, ``warn``/``info``/``success``,
ANSI-цвета, ``STATE_FILE``, ``country_flag_emoji``, ``_nodes_from_state``,
``_speed_test_mode_a``, ``_speed_test_node_*``, ``log_to_file``) — через
importlib (см. _core_module()).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import time


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль chimera._core, импортируя его лениво."""
    import importlib
    return importlib.import_module("chimera._core")


# =============================================================================
#  7. ТЕСТ СКОРОСТИ ЧЕРЕЗ EXIT-НОДЫ (все ноды по очереди)
# =============================================================================
def do_speed_test(auto_mode: bool = False) -> None:
    """
    Измеряет скорость и латентность.
    Режим A (Exit-нода): тест напрямую в интернет до Cloudflare.
    Режим B (Entry/Bridge): тест до каждой exit-ноды + Download через Cloudflare.
    auto_mode=True — пропускает интерактивный ввод (для do_full_diagnostic).
    Не требует внешних утилит кроме curl и socket.
    """
    core = _core_module()
    STATE_FILE = core.STATE_FILE
    warn    = core.warn
    info    = core.info
    success = core.success
    log_to_file = core.log_to_file
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_info   = core._box_info
    _box_warn   = core._box_warn
    _box_bottom = core._box_bottom
    _run = core._run
    _nodes_from_state = core._nodes_from_state
    _speed_test_mode_a       = core._speed_test_mode_a
    _speed_test_node_geo     = core._speed_test_node_geo
    _speed_test_node_latency = core._speed_test_node_latency
    _speed_test_download     = core._speed_test_download
    country_flag_emoji = core.country_flag_emoji
    CYAN   = core.CYAN
    NC     = core.NC
    RED    = core.RED
    GREEN  = core.GREEN
    YELLOW = core.YELLOW
    DIM    = core.DIM
    BOLD   = core.BOLD

    if not STATE_FILE.exists():
        warn("state.json не найден — сначала выполните установку")
        return

    # --- Определяем режим установки ---
    try:
        state = json.loads(STATE_FILE.read_text())
        current_mode = state.get("install_mode", "A")
    except Exception as e:
        warn(f"Не удалось прочитать state.json: {e}")
        return

    # Режим A — Exit-нода: отдельная подфункция
    if current_mode == "A":
        _speed_test_mode_a(auto_mode=auto_mode)
        return

    # --- Режим B (Entry/Bridge) — AWG транспорт: тест через туннель ---
    if current_mode == "B" and state.get("awg_exit_enabled", False):
        _box_top("Тест скорости через AWG-туннель (awg0)")
        _box_row()
        _box_info("  Режим AWG: тест выходного IP через туннель awg0...")
        _box_row()
        # GeoIP выходного IP (трафик идёт через awg0 → exit-VPS)
        try:
            r_geo = _run(
                ["curl", "-s", "--max-time", "10",
                 "--interface", "awg0",
                 "http://ip-api.com/json/?fields=status,country,countryCode,city,isp,query"],
                capture=True, check=False
            )
            if r_geo.returncode == 0 and r_geo.stdout.strip():
                geo = json.loads(r_geo.stdout.strip())
                if geo.get("status") == "success":
                    cc      = geo.get("countryCode", "??")
                    country = geo.get("country", "неизвестно")
                    ip_out  = geo.get("query", "?")
                    isp     = geo.get("isp", "?")
                    cc_col  = RED if cc == "RU" else GREEN
                    _box_row(f"    Выходной IP (AWG): {CYAN}{ip_out}{NC}")
                    _box_row(f"    Страна: {cc_col}{country} ({cc}){NC}")
                    _box_row(f"    ISP:    {CYAN}{isp}{NC}")
                    if cc == "RU":
                        _box_warn("Выходной IP в России — трафик не обходит блокировки!")
                    else:
                        _box_row(f"    {GREEN}✓ Выходной IP за пределами России{NC}")
                else:
                    _box_warn("GeoIP недоступен через awg0")
            else:
                _box_warn(f"Не удалось получить GeoIP через awg0 (curl rc={r_geo.returncode})")
                _box_info("  Подсказка: убедитесь что awg0 поднят (ip link show awg0)")
        except Exception as _ge:
            _box_warn(f"GeoIP через awg0: {_ge}")

        # TCP latency до Cloudflare через awg0
        _box_row()
        _box_info("  Измерение латентности до Cloudflare через туннель...")
        try:
            import socket as _sock_awg
            _t0 = time.time()
            _s = _sock_awg.create_connection(("1.1.1.1", 443), timeout=8)
            _s.close()
            _lat_ms = int((time.time() - _t0) * 1000)
            _lc = GREEN if _lat_ms < 200 else YELLOW if _lat_ms < 500 else RED
            _box_row(f"    TCP latency → 1.1.1.1:443: {_lc}{_lat_ms} мс{NC}")
        except Exception as _le:
            _box_row(f"    TCP latency → 1.1.1.1:443: {RED}ошибка ({_le}){NC}")

        # Download через awg0
        _box_row()
        _box_info("  Тест загрузки 10 МБ через туннель...")
        # DoH-резолв speed.cloudflare.com — обходит серверный DNS (после
        # фикса DNS-leak серверный DNS идёт через DNSCrypt на 127.0.0.1:5300).
        _cf_ip = core._cf_resolve_ip()
        _dl_cmd = [
            "curl", "-s", "-o", "/dev/null", "--max-time", "30",
            "-w", "%{speed_download} %{time_total}",
            "--interface", "awg0",
        ]
        if _cf_ip:
            _dl_cmd += ["--resolve", f"speed.cloudflare.com:443:{_cf_ip}"]
        _dl_cmd.append("https://speed.cloudflare.com/__down?bytes=10485760")
        _r_dl = _run(_dl_cmd, capture=True, check=False)
        if _r_dl.returncode == 0 and _r_dl.stdout.strip():
            try:
                _parts = _r_dl.stdout.strip().split()
                _bps   = float(_parts[0])
                _secs  = float(_parts[1])
                _mbps  = _bps * 8 / 1_000_000
                _dc    = GREEN if _mbps > 50 else YELLOW if _mbps > 10 else RED
                _box_row(f"    Download (AWG): {_dc}{_mbps:.1f} Мбит/с{NC}  ({_secs:.1f} с)")
            except Exception:
                _box_row(f"    Download: {DIM}ошибка парсинга{NC}")
        else:
            _box_warn("Download через awg0 не удался — проверьте туннель")

        _box_row()
        _box_bottom()
        success("Тест AWG-туннеля завершён")
        return

    # --- Режим B (Entry/Bridge) — тест до exit-нод (VLESS chain) ---
    _box_top(f"Тест скорости по всем exit-нодам")
    _box_row()

    # --- Проверка доступности Cloudflare и выбор размера ---
    _box_info("  Проверка доступности Cloudflare...")
    # DoH-резолв + --resolve в curl — обходит серверный DNS (после фикса
    # DNS-leak серверный DNS идёт через DNSCrypt на 127.0.0.1:5300).
    _cf_probe_available = core._cf_probe_available
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
            sz_choice = input(f"  {CYAN}Выбор [1-4, Enter = 1]:{NC} ").strip()
            dl_size_mb = SIZE_OPTIONS.get(sz_choice, 10)
            _box_top(f"Тест скорости по всем exit-нодам")
    else:
        _box_warn("  Cloudflare недоступен для больших файлов — используется 10 МБ")
        _box_warn("  Для точного теста скорости используйте fast.com или speedtest.net на клиенте")
        dl_size_mb = 10
    _box_row()

    # Загружаем ноды из уже прочитанного state
    nodes = _nodes_from_state(state)

    if not nodes:
        _box_warn("Ноды не найдены в state.json — сначала выполните установку в Режиме B")
        return

    strategy = state.get("chain_balancer_strategy", "roundRobin")
    _box_row(f"  Нод: {CYAN}{len(nodes)}{NC}  |  Балансировка: {CYAN}{strategy}{NC}")
    _box_row()

    # --- Тест каждой ноды ---
    for i, nd in enumerate(nodes):
        host = nd.get("host", "?")
        port = nd.get("port", 443)
        tag  = f"chain-exit-{i+1}"
        via_tag = (nd.get("via") or "").strip()

        _box_bottom()
        _box_top(f"Нода {i+1}: {host}:{port} ({tag})"
                 + (f"  ·  relay: {via_tag}" if via_tag else ""))

        # GeoIP
        _box_info(f"  Определение GeoIP...")
        ip, cc, country, city, isp = _speed_test_node_geo(host)
        cc_colour  = RED if cc == "RU" else GREEN
        _node_flag = country_flag_emoji(cc)
        _ncty_tr   = country[:24]
        _isp_tr    = isp[:34]
        # IP + ISP внутри рамки, затем рамка закрывается
        _box_row(f"    IP:      {CYAN}{ip}{NC}")
        _box_row(f"    ISP:     {CYAN}{_isp_tr}{NC}")
        _box_bottom()
        # Флаг + страна — вне рамки
        print(f"  {_node_flag}  {cc_colour}{_ncty_tr} ({cc}){NC}")
        print()
        # Статус в отдельном боксе
        _box_top()
        if cc == "RU":
            _box_row(f"  {RED}⚠  Нода в России — трафик может не обходить блокировки!{NC}")
        else:
            _box_row(f"  {GREEN}✓  Нода за пределами России{NC}")
        _box_bottom()

        # Новый бокс для латентности и скорости
        _box_top()
        _chain_r = None      # результат full-path (для via-нод)
        if via_tag:
            # Chain Relay: прямой TCP к via-ноде может быть перерезан ТСПУ —
            # «TCP latency: таймаут» здесь ЛОЖНЫЙ негатив. Меряем полный путь:
            # временный xray-клиент (entry → хопы → нода) + HTTP-проба +
            # реальный download ЧЕРЕЗ цепочку.
            _box_info(f"  Нода с релейным хопом «{via_tag}» — измеряем полный путь")
            _box_info(f"  (entry → {via_tag} → нода; прямой путь может быть резан ТСПУ)...")
            try:
                from chimera.modules.chain_relay import (
                    check_via_node_full_path, load_relay_hops)
                _chain_r = check_via_node_full_path(
                    nd, load_relay_hops(), want_ip=True,
                    want_speed_mb=min(dl_size_mb, 100))
            except ImportError:
                _chain_r = None
            if _chain_r is not None and _chain_r.get("ok"):
                _ms = _chain_r.get("ms", 0)
                _lc = GREEN if _ms < 400 else YELLOW
                _lat_line = (f"    Полный путь: {_lc}{_ms:.0f} мс{NC}")
                if _chain_r.get("exit_ip"):
                    _lat_line += f"  {DIM}(exit IP {_chain_r['exit_ip']}){NC}"
                _box_row(_lat_line)
            elif _chain_r is not None:
                _box_row(f"    Цепочка: {RED}недоступна "
                         f"({_chain_r.get('detail', '')[:60]}){NC}")
            else:
                # chain_relay недоступен — старый прямой замер (может таймаутить)
                _box_info(f"  Измерение TCP-латентности до {host}:{port}...")
                lat = _speed_test_node_latency(host, port)
                _box_row(f"    TCP latency: {lat}")
        else:
            _box_info(f"  Измерение TCP-латентности до {host}:{port}...")
            lat = _speed_test_node_latency(host, port)
            _box_row(f"    TCP latency: {lat}")

        # Скорость загрузки
        if _chain_r is not None and _chain_r.get("ok"):
            # via-нода: скорость уже измерена ЧЕРЕЗ цепочку (реальный путь
            # клиентского трафика), отдельный прямой замер не нужен.
            _mbps = _chain_r.get("speed_mbps", 0.0)
            if _mbps > 0:
                _dc = GREEN if _mbps > 100 else YELLOW if _mbps > 20 else RED
                _box_row(f"    Download (через цепочку {via_tag}): "
                         f"{_dc}{_mbps:.1f} Мбит/с{NC}")
            else:
                _box_row(f"    Download (через цепочку): "
                         f"{YELLOW}не измерен{NC}")
        else:
            _box_info(f"  Тест загрузки {dl_size_mb} МБ (Cloudflare)...")
            dl = _speed_test_download(host, ip, port, dl_size_mb)
            _box_row(f"    Download: {dl}")

        log_to_file("INFO", f"SpeedTest нода {i+1} ({host}"
                             + (f" via {via_tag}" if via_tag else "")
                             + f"): IP={ip}, CC={cc}, latency, DL")
        _box_bottom()

    success("Тест скорости завершён")
