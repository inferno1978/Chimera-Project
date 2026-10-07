"""
chimera/modules/chain_nodes.py
───────────────────────────────────────────────────────────────────────────────
Chain/Nodes (Режим B / каскад) — управление exit-нодами, генерация конфигов
Entry/Exit, prompt-функции, мульти-нодовая балансировка, health-матрица.

Содержит 22 функции, вынесенных из chimera._core.py:
  • prompt_chain_params, _prompt_balancer_strategy, prompt_chain_params_multi
  • generate_xray_config_chain_entry, _make_exit_node_config,
    generate_xray_config_chain_exit, do_generate_chain_exit_additional_client
  • _nodes_from_state, _load_chain_nodes_from_state, _save_chain_nodes_to_state
  • _prompt_one_node, _prompt_one_node_from_link, _fix_node_fields,
    _prompt_one_node_manual, _h2_reapply_transport_if_active
  • generate_xray_config_chain_entry_multi, do_manage_nodes, generate_chain_summary
  • _speed_test_node_latency, _speed_test_node_geo,
    _access_log_bytes_per_node, do_node_health_matrix

Точки входа из _core.py:
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

Все CHAIN_* / CHAIN_EXIT_* / PARAM_* / XHTTP_* / AWG_* / SPLIT_TUNNEL_* / etc.
глобали ОСТАЮТСЯ в _core.py — модуль читает их через
`getattr(core, "...", <default>)` и пишет через
`setattr(core, "...", value)` (dual-form), что сохраняет семантику `global X`
деклараций оригинала.

Доступ к helpers ядра (info/warn/success/_run/_box_*/_fm_prompt_fingerprint/
gen_hex/parse_vless_link/_show_qr/country_flag_emoji/get_server_country_cached/
_rebuild_and_restart_xray/_load_split_tunnel_custom/_detect_xhttp_mode_support/
_assert_reality_dest_sane/_build_xhttp_settings/_build_tls_settings_xhttp/
_build_sockopt/_build_exit_xhttp_settings/_build_exit_xhttp_outbound_settings/
_xray_log_block/_apply_stats_to_config/_set_config_owner/
build_split_tunnel_routing_rules/_wcslen/_get_box_width/_fp_from_state/
uuid/Path/...) — через importlib (см. _core_module()), как и в других
извлечённых модулях (asn_cache.py, warp.py, awg_transport.py и т.д.).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from chimera.modules.agh_probe import agh_dns_available

# TFO (TCP Fast Open): централизованная настройка, дефолт ВЫКЛЮЧЕН
# (инцидент 28.08.2026 — DPI резал data-in-SYN, см. tfo_settings.py)
from chimera.modules.tfo_settings import tfo_sockopt


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль chimera._core, импортируя его лениво.

    При запуске через cron (python -c 'from ... import ...') модуль ещё не
    загружен — importlib полноценно его импортирует. При вызове из
    интерактивного инсталлятора модуль уже в sys.modules (был импортирован
    одним из поздних lazy-вызовов внутри других модулей) — это просто lookup.
    """
    import importlib
    return importlib.import_module("chimera._core")


# =============================================================================
#  Helpers: routing rules + sniffing для VLESS REALITY TCP каскада
# =============================================================================
#  ВАЖНАЯ ИСТОРИЯ ФИКСА (commit fd1ede6 predecessors):
#  Раньше catch-all правило в routing было:
#      {"type": "field", "network": "tcp,udp", "outboundTag": "chain-exit"}
#  Это матчило И TCP, И UDP. Но VLESS over REALITY работает ТОЛЬКО по TCP —
#  UDP-трафик физически не может быть туннелирован. Симптомы на клиенте:
#    • DNS-запросы (UDP:53 к 1.1.1.1) → обрыв → «dns: exchange failed»
#    • QUIC (UDP:443 от браузеров) → обрыв → EOF
#    • Весь остальной UDP → обрыв → «EOF» при попытке подключения
#  Тестовый Xray-клиент на самом entry работал (curl --socks5 только TCP),
#  но полноценный VPN-клиент (Nyamebox/Hiddify/v2rayN) сразу падал.
#
#  Кроме того, в sniffing.destOverride не было «quic» и «dns», поэтому Xray
#  не перехватывал DNS-запросы на уровне приложения и не отправлял их на
#  свой встроенный DNS-резолвер — они шли «как есть» к 1.1.1.1:53 и попадали
#  в catch-all → обрыв.
#
#  ФИКС: единый helper строит правильный набор правил для VLESS REALITY TCP
#  каскада. Используется в 3 местах: single-node, multi-node pinned,
#  multi-node balancer — что гарантирует единое поведение. AWG и xHTTP
#  режимы эти хелперы НЕ затрагивают (у них другой routing: fwmark/loopback).
# =============================================================================

def _build_chain_routing_rules(outbound_target: str,
                               balancer: bool = False) -> list:
    """Строит список routing rules для VLESS REALITY TCP каскада.

    Параметры:
      outbound_target — тег outbound'а цепочки ('chain-exit', 'chain-exit-1')
                        или 'chain-balancer' если balancer=True.
      balancer         — True если outbound_target это balancerTag, не outboundTag.

    Возвращает список routing rules (порядок важен — первый матч выигрывает):
      1. loopback → direct (DNSCrypt на 127.0.0.1:5300 и т.п.)
      2. bittorrent → BLOCK (всегда)
      3. UDP DNS (порт 53 tcp+udp) → direct (резолвится через DNSCrypt на entry)
      4. QUIC (UDP порт 443) → BLOCK (браузер откатится на TCP/HTTP2)
      5. Весь остальной UDP → BLOCK (VLESS REALITY TCP-only не туннелирует UDP)
      6. TCP → outbound_target (chain-exit-1 / chain-balancer)

    Совместимость: для AWG-режима эта функция НЕ вызывается — там используется
    fwmark-based routing через awg0. См. generate_xray_config() для AWG.
    """
    # Catch-all правило для TCP: через exit-ноду или balancer.
    # При balancer=True используем balancerTag, иначе outboundTag.
    if balancer:
        _tcp_rule = {"type": "field", "network": "tcp",
                     "balancerTag": outbound_target}
    else:
        _tcp_rule = {"type": "field", "network": "tcp",
                     "outboundTag": outbound_target}
    return [
        # loopback → direct (DNSCrypt, внутренние сервисы Xray)
        {"type": "field", "ip": ["127.0.0.1/8", "::1/128"], "outboundTag": "direct"},
        # Блокируем торренты (всегда — независимо от transport)
        {"type": "field", "protocol": ["bittorrent"], "outboundTag": "BLOCK"},
        # UDP DNS (tcp+udp на порт 53) → direct
        # Xray сам резолвит через DNSCrypt на entry (127.0.0.1:5300).
        # Клиентские DNS-запросы (через туннель к 1.1.1.1:53) уходят напрямую
        # с entry, не через chain-exit (который не умеет UDP).
        {"type": "field", "port": "53", "network": "tcp,udp",
         "outboundTag": "direct"},
        # QUIC (UDP:443) → BLOCK
        # Браузер при BLOCK'd QUIC автоматически откатится на TCP (HTTP/2).
        # Это стандартное поведение для всех VPN-туннелей без UDP-поддержки.
        {"type": "field", "port": "443", "network": "udp",
         "outboundTag": "BLOCK"},
        # Весь остальной UDP → BLOCK
        # VLESS over REALITY — TCP-only transport, UDP туннелировать не может.
        # Без этого правила UDP-трафик попадал в catch-all → обрыв → EOF.
        {"type": "field", "network": "udp", "outboundTag": "BLOCK"},
        # Только TCP → через exit-ноду (chain-exit-1 / chain-balancer)
        _tcp_rule,
    ]


def _build_chain_sniffing(awg: bool = False) -> dict:
    """Строит sniffing-блок для VLESS REALITY inbound.

    Параметры:
      awg — True если AWG-режим (metadataOnly=True, т.к. routing через ядро).

    Возвращает dict с enabled/destOverride/metadataOnly/routeOnly.
    destOverride включает 'http', 'tls', 'quic' (последнее — для перехвата
    QUIC-трафика и его маршрутизации через BLOCK правило вместо падения
    в catch-all с последующим обрывом).
    """
    return {
        "enabled":      True,
        "destOverride": ["http", "tls", "quic"],
        # AWG использует маршрутизацию ядра — sniffing доменов не нужен.
        # Базовый VLESS/REALITY: metadataOnly=False обязателен — xray должен
        # читать SNI/Host, чтобы freedom мог резолвить домены.
        "metadataOnly": True if awg else False,
        "routeOnly":    False,
    }


# =============================================================================
#  Prompt-функции: параметры Exit Node (Режим B)
# =============================================================================
def prompt_chain_params() -> None:
    """Ввод параметров зарубежного (exit) VPS для Режима B.
    Устарела — используется только для совместимости. Новый код вызывает prompt_chain_params_multi()."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    _fm_prompt_fingerprint = core._fm_prompt_fingerprint
    info = core.info
    warn = core.warn
    success = core.success
    YELLOW = core.YELLOW
    BLUE = core.BLUE
    BOLD = core.BOLD
    NC = core.NC
    CHAIN_EXIT_HOST = getattr(core, "CHAIN_EXIT_HOST", "")
    CHAIN_EXIT_PORT = getattr(core, "CHAIN_EXIT_PORT", 443)
    CHAIN_EXIT_UUID = getattr(core, "CHAIN_EXIT_UUID", "")
    CHAIN_EXIT_PUBKEY = getattr(core, "CHAIN_EXIT_PUBKEY", "")
    CHAIN_EXIT_SHORTID = getattr(core, "CHAIN_EXIT_SHORTID", "")
    CHAIN_EXIT_SNI = getattr(core, "CHAIN_EXIT_SNI", "")
    CHAIN_EXIT_FP = getattr(core, "CHAIN_EXIT_FP", "chrome")

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
            setattr(core, "CHAIN_EXIT_HOST", CHAIN_EXIT_HOST)
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
            setattr(core, "CHAIN_EXIT_PORT", CHAIN_EXIT_PORT)
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
            setattr(core, "CHAIN_EXIT_UUID", CHAIN_EXIT_UUID)
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
            setattr(core, "CHAIN_EXIT_PUBKEY", CHAIN_EXIT_PUBKEY)
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
            setattr(core, "CHAIN_EXIT_SHORTID", CHAIN_EXIT_SHORTID)
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
            setattr(core, "CHAIN_EXIT_SNI", CHAIN_EXIT_SNI)
            success(f"   SNI: {CHAIN_EXIT_SNI}")
            break
        warn("   Некорректный домен")

    # Fingerprint
    _box_row(f"{BLUE}[E7] Fingerprint браузера:{NC}")
    _box_bottom()
    CHAIN_EXIT_FP = _fm_prompt_fingerprint(label="Exit Node", current=CHAIN_EXIT_FP or "chrome")
    setattr(core, "CHAIN_EXIT_FP", CHAIN_EXIT_FP)

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
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    _box_desc = core._box_desc
    warn = core.warn
    success = core.success
    GREEN = core.GREEN
    CYAN = core.CYAN
    NC = core.NC
    BOLD = core.BOLD
    CHAIN_NODES = getattr(core, "CHAIN_NODES", [])
    PROBE_INTERVAL_MIN = getattr(core, "PROBE_INTERVAL_MIN", 5)
    CHAIN_BALANCER_STRATEGY = getattr(core, "CHAIN_BALANCER_STRATEGY", "roundRobin")

    if len(CHAIN_NODES) < 2:
        # При одной ноде balancer не задействован — оставляем roundRobin как дефолт,
        # конфиг будет генерироваться без секции balancers.
        CHAIN_BALANCER_STRATEGY = "roundRobin"
        setattr(core, "CHAIN_BALANCER_STRATEGY", CHAIN_BALANCER_STRATEGY)
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
            setattr(core, "CHAIN_BALANCER_STRATEGY", CHAIN_BALANCER_STRATEGY)
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
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    _box_wrap_msg = core._box_wrap_msg
    _box_warn = core._box_warn
    _box_info = core._box_info
    _box_ok = core._box_ok
    # _sb_install_cron() вынесен в модуль smart_balancer при рефакторинге —
    # берём оттуда, не из core (который этот атрибут больше не содержит).
    from chimera.modules.smart_balancer import _sb_install_cron
    warn = core.warn
    success = core.success
    YELLOW = core.YELLOW
    CYAN = core.CYAN
    BOLD = core.BOLD
    NC = core.NC
    MAX_CHAIN_NODES = getattr(core, "MAX_CHAIN_NODES", 10)
    PROBE_INTERVAL_MIN = getattr(core, "PROBE_INTERVAL_MIN", 5)
    CHAIN_NODES = getattr(core, "CHAIN_NODES", [])
    CHAIN_EXIT_HOST = getattr(core, "CHAIN_EXIT_HOST", "")
    CHAIN_EXIT_PORT = getattr(core, "CHAIN_EXIT_PORT", 443)
    CHAIN_EXIT_UUID = getattr(core, "CHAIN_EXIT_UUID", "")
    CHAIN_EXIT_PUBKEY = getattr(core, "CHAIN_EXIT_PUBKEY", "")
    CHAIN_EXIT_SHORTID = getattr(core, "CHAIN_EXIT_SHORTID", "")
    CHAIN_EXIT_SNI = getattr(core, "CHAIN_EXIT_SNI", "")
    CHAIN_EXIT_FP = getattr(core, "CHAIN_EXIT_FP", "chrome")
    CHAIN_BALANCER_STRATEGY = getattr(core, "CHAIN_BALANCER_STRATEGY", "roundRobin")

    CHAIN_NODES = []
    setattr(core, "CHAIN_NODES", CHAIN_NODES)

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
    # _prompt_balancer_strategy() writes to core.CHAIN_BALANCER_STRATEGY via setattr;
    # re-bind local to see the updated value below.
    CHAIN_BALANCER_STRATEGY = getattr(core, "CHAIN_BALANCER_STRATEGY", "roundRobin")

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
        setattr(core, "CHAIN_BALANCER_STRATEGY", CHAIN_BALANCER_STRATEGY)

    _box_row()
    _box_bottom()
    # Синхронизируем legacy-переменные с первой нодой
    if CHAIN_NODES:
        n = CHAIN_NODES[0]
        CHAIN_EXIT_HOST    = n["host"]
        setattr(core, "CHAIN_EXIT_HOST", CHAIN_EXIT_HOST)
        CHAIN_EXIT_PORT    = n["port"]
        setattr(core, "CHAIN_EXIT_PORT", CHAIN_EXIT_PORT)
        CHAIN_EXIT_UUID    = n["uuid"]
        setattr(core, "CHAIN_EXIT_UUID", CHAIN_EXIT_UUID)
        CHAIN_EXIT_PUBKEY  = n["pubkey"]
        setattr(core, "CHAIN_EXIT_PUBKEY", CHAIN_EXIT_PUBKEY)
        CHAIN_EXIT_SHORTID = n["shortid"]
        setattr(core, "CHAIN_EXIT_SHORTID", CHAIN_EXIT_SHORTID)
        CHAIN_EXIT_SNI     = n["sni"]
        setattr(core, "CHAIN_EXIT_SNI", CHAIN_EXIT_SNI)
        CHAIN_EXIT_FP      = n["fp"]
        setattr(core, "CHAIN_EXIT_FP", CHAIN_EXIT_FP)


# =============================================================================
#  ГЕНЕРАЦИЯ КОНФИГА XRAY ДЛЯ РЕЖИМА B — российский (entry) VPS
# =============================================================================
# Гейт версий клиента REALITY (minClientVer) читается лениво из state.json
# (ставится меню 5b; "" = выкл — норма для Xray 26.9.8+; "1.8.0" — даунгрейд-
# рецепт для 26.7.11–26.7.28; VLESS_FAQ.md §18). Ридер безопасен к мок-ядрам
# в тестах: не-строка/исключение → "" (иначе MagicMock попадал в конфиг и
# ломал json.dumps).
def _min_client_ver_reader(core):
    fn = getattr(core, "_min_client_ver_from_state", None)

    def _read() -> str:
        try:
            val = fn() if callable(fn) else ""
            return val if isinstance(val, str) else ""
        except Exception:
            return ""
    return _read


def generate_xray_config_chain_entry() -> None:
    """
    Режим B, Entry node (российский VPS):
    • Принимает VLESS+REALITY от клиента на порту 443
    • Исходящий — VLESS+REALITY → зарубежный VPS (exit node)
    """
    core = _core_module()
    # Гейт версий клиента REALITY — лениво из state.json (меню 5b):
    # "" = выкл (норма для Xray 26.9.8+), "1.8.0" — даунгрейд-рецепт
    # для 26.7.11–26.7.28 (VLESS_FAQ §18).
    _min_client_ver = _min_client_ver_reader(core)
    # Anti-Empty Identity Guard — UUID/ShortID/REALITY-ключи entry-ноды
    # не должны быть пустыми при регенерации (восстановление из живого
    # config.json/users.json — иначе ссылки юзеров ломаются).
    try:
        core._identity_params_recover()
    except Exception:
        pass  # guard не должен блокировать генерацию
    _assert_reality_dest_sane = core._assert_reality_dest_sane
    _run = core._run
    _build_xhttp_settings = core._build_xhttp_settings
    _build_tls_settings_xhttp = core._build_tls_settings_xhttp
    _build_sockopt = core._build_sockopt
    _xray_log_block = core._xray_log_block
    _apply_stats_to_config = core._apply_stats_to_config
    _set_config_owner = core._set_config_owner
    build_split_tunnel_routing_rules = core.build_split_tunnel_routing_rules
    info = core.info
    warn = core.warn
    success = core.success
    log_to_file = core.log_to_file
    DNSCRYPT_LISTEN_PORT = getattr(core, "DNSCRYPT_LISTEN_PORT", 5300)
    DNSCRYPT_LISTEN_ADDR = getattr(core, "DNSCRYPT_LISTEN_ADDR", "127.0.0.1")
    DNSCRYPT_INSTALLED = getattr(core, "DNSCRYPT_INSTALLED", False)
    IS_IPV6_AVAILABLE = getattr(core, "IS_IPV6_AVAILABLE", False)
    PROTOCOL_MODE = getattr(core, "PROTOCOL_MODE", "reality")
    PARAM_DOMAIN = getattr(core, "PARAM_DOMAIN", "")
    PARAM_UUID = getattr(core, "PARAM_UUID", "")
    XTLS_FLOW = getattr(core, "XTLS_FLOW", "")
    XHTTP_MODE = getattr(core, "XHTTP_MODE", "stream-up")
    XHTTP_PATH = getattr(core, "XHTTP_PATH", "/")
    AWG_EXIT_ENABLED = getattr(core, "AWG_EXIT_ENABLED", False)
    PARAM_REALITY_DEST = getattr(core, "PARAM_REALITY_DEST", "")
    PARAM_SOCKET_PATH = getattr(core, "PARAM_SOCKET_PATH", "")
    PARAM_SPIDERX = getattr(core, "PARAM_SPIDERX", "/")
    PARAM_PRIVATE_KEY = getattr(core, "PARAM_PRIVATE_KEY", "")
    PARAM_PUBLIC_KEY = getattr(core, "PARAM_PUBLIC_KEY", "")
    PARAM_SHORTID = getattr(core, "PARAM_SHORTID", "")
    CHAIN_EXIT_HOST = getattr(core, "CHAIN_EXIT_HOST", "")
    CHAIN_EXIT_PORT = getattr(core, "CHAIN_EXIT_PORT", 443)
    CHAIN_EXIT_UUID = getattr(core, "CHAIN_EXIT_UUID", "")
    CHAIN_EXIT_FP = getattr(core, "CHAIN_EXIT_FP", "chrome")
    CHAIN_EXIT_SNI = getattr(core, "CHAIN_EXIT_SNI", "")
    CHAIN_EXIT_PUBKEY = getattr(core, "CHAIN_EXIT_PUBKEY", "")
    CHAIN_EXIT_SHORTID = getattr(core, "CHAIN_EXIT_SHORTID", "")
    AWG_FWMARK = getattr(core, "AWG_FWMARK", 1000)
    SERVER_PORT = getattr(core, "SERVER_PORT", 443)
    SPLIT_TUNNEL_ENABLED = getattr(core, "SPLIT_TUNNEL_ENABLED", False)
    CONFIG_DIR = getattr(core, "CONFIG_DIR", Path("/etc/xray"))
    XRAY_BIN = getattr(core, "XRAY_BIN", "/usr/local/bin/xray")
    Any = getattr(core, "Any", None)

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

    # AdGuardHome health-check (см. agh_probe.py): AGH жив и держит
    # 127.0.0.1:53 → Xray → AGH → DNSCrypt; сбой проверки → DNSCrypt:5300.
    # (agh-autostart): установлен, но остановлен → поднимаем перед пробой.
    agh_ok, agh_note = agh_dns_available(run=_run, log_info=info,
                                         log_warn=warn, autostart=True)

    if agh_ok:
        dns_servers = [
            {"address": "127.0.0.1", "port": 53,
             "network": "udp", "skipFallback": False},
        ]
        if dnscrypt_running:
            # Живой fallback на случай падения AGH после генерации
            dns_servers.append(
                {"address": DNSCRYPT_LISTEN_ADDR, "port": DNSCRYPT_LISTEN_PORT,
                 "network": "udp", "skipFallback": False})
        # последний живой fallback — Quad9 напрямую (UDP:53 anycast).
        # Достижим и с зарубежных, и с РФ-хостингов (1.1.1.1/8.8.8.8 в РФ
        # душатся/заблокированы РКН). Срабатывает ТОЛЬКО при падении AGH+DNSCrypt —
        # лучше открытый DNS, чем DNS black-hole для IPIfNonMatch-резолва
        # (иначе доменные соединения зависают на таймаутах DNS).
        dns_servers.append(
            {"address": "9.9.9.9", "port": 53, "network": "udp", "skipFallback": False})
        dns_servers += [
            {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": True},
            {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": True},
        ]
        info(f"DNS: AdGuardHome здоров ({agh_note}) — Xray → AGH:53 → DNSCrypt")
    elif dnscrypt_running:
        dns_servers = [
            {"address": DNSCRYPT_LISTEN_ADDR, "port": DNSCRYPT_LISTEN_PORT,
             "network": "udp", "skipFallback": False},
            # живой Quad9-fallback — достижим из РФ (в отличие от 1.1.1.1/8.8.8.8)
            {"address": "9.9.9.9", "port": 53, "network": "udp", "skipFallback": False},
            {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": True},
            {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": True},
        ]
    else:
        dns_servers = [
            {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": False},
            {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": False},
        ]

    query_strategy = "UseIPv6v4" if IS_IPV6_AVAILABLE else "UseIPv4"

    # ── BUGFIX: clients — из ЕДИНОГО источника юзеров ──────────
    #    Раньше сюда жёстко подставлялся PARAM_UUID из state.json. При
    #    регенерации конфига (AGH-финализация / «Пересоздать конфиг
    #    Xray» / emergency repair) все остальные юзеры выпадали из
    #    clients → xray рвал соединения «invalid request user id» →
    #    EOF у клиентов со ссылками, выданными до регенерации.
    #    Теперь: _unified_load_users() (users.json + текущий конфиг) +
    #    PARAM_UUID как fallback/дополнение. Fresh install поведение
    #    не меняется (юзеров нет → clients=[PARAM_UUID]).
    try:
        from chimera.modules.users_manager import (
            _users_collect_for_config, _clients_from_users)
        _cfg_users = _users_collect_for_config(
            PARAM_UUID, f"user@{PARAM_DOMAIN}")
    except Exception:
        _cfg_users = [{"uuid": PARAM_UUID,
                       "email": f"user@{PARAM_DOMAIN}"}]

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
                "clients": _clients_from_users(_cfg_users),
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
                "clients": _clients_from_users(_cfg_users, XTLS_FLOW),
                "decryption": "none",
            },
            # FIX: sniffing с 'quic' в destOverride — Xray перехватывает QUIC
            # и маршрутизирует через BLOCK правило вместо падения в catch-all.
            # Без этого браузерные QUIC-запросы рвут соединение → EOF на клиенте.
            "sniffing": _build_chain_sniffing(awg=AWG_EXIT_ENABLED),
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
                    # Гейт версий клиента (minClientVer) — механика по факту
                    # стенда 2026-09-10 (docs/faq/VLESS_FAQ.md §18):
                    # ClientVer в хендшейке отчитывают ВСЕ — sing-box →
                    # [1,8,1], mihomo → [1,8,2] (проходит непустые пороги
                    # ≤ "1.8.2"; прежний комментарий «не отчитывают вовсе»
                    # был неверен — те тесты валил MLKEM-чек ClientHello
                    # ядра 26.9.8+, не гейт), Xray-клиент → версию ядра.
                    # Xray 26.7.11–26.7.28: unset/"" = ДЕФОЛТ-гейт 26.3.27,
                    # валит mihomo/sing-box, лечится явным minClientVer=
                    # "1.8.0" (рецепт podkop). Xray 26.9.8+ (наш флот):
                    # дефолт-гейт УБРАН — unset/"" = гейт выключен,
                    # непустые пороги живут ("2.0.0" валит mihomo [1,8,2],
                    # "1.8.0"/"1.0.0" пропускает; sing-box против 26.9.8+
                    # не пройдёт ни при каком гейте — барьер MLKEM, не
                    # версия). Значение лениво из state.json ("min_client_ver",
                    # ставится меню 5b; дефолт "" — норма для 26.9.8+);
                    # поля пишем ЯВНО, чтобы поведение не зависело от дефолтов
                    # ядра. Источники: XTLS/Xray-core #6477 (RPRX) +
                    # PR #6507, MetaCubeX/mihomo#3042, MHSanaei/3x-ui#5922.
                    "minClientVer": _min_client_ver(),
                    "maxClientVer": "",
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
            "rules": _build_chain_routing_rules("chain-exit"),
        },
    }

    # === MERGE FROM install_split.py: split tunnel block (generate_xray_config_chain_entry) ===
    # Классический VLESS-каскад (без AWG): split tunnel через "direct" outbound.
    # AWG-режим: эта функция не вызывается (см. generate_xray_config_chain_entry_multi —
    # ветка elif AWG_EXIT_ENABLED уходит в generate_xray_config()). Но если всё же
    # вызвана с AWG_EXIT_ENABLED — нужен direct-local (без fwmark), иначе РФ-трафик
    # уйдёт через awg0 (exit-VPS), и split tunnel бесполезен.
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
    elif SPLIT_TUNNEL_ENABLED and AWG_EXIT_ENABLED:
        _dl_strategy = "UseIPv6v4" if IS_IPV6_AVAILABLE else "UseIPv4"
        config["outbounds"].insert(0, {
            "protocol": "freedom",
            "tag":      "direct-local",
            "settings": {"domainStrategy": _dl_strategy},
        })
        # IP-проверочные домены → direct-local (всегда в AWG-режиме)
        # build_awg_ip_check_rule возвращает list (domain + ip правило).
        from chimera.modules.split_tunnel import build_awg_ip_check_rule
        config["routing"]["rules"][:0] = build_awg_ip_check_rule("direct-local")
        st_rules = build_split_tunnel_routing_rules(
            proxy_tag="direct", direct_tag="direct-local")
        if st_rules:
            config["routing"]["rules"] = st_rules + config["routing"]["rules"]
            config["routing"]["geoDataBasePath"] = str(CONFIG_DIR)
            info(f"Split tunneling: добавлено {len(st_rules)} правил "
                 f"(Режим B + AWG, одиночная нода, direct-local)")
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
        # (geo-self-heal): см. generate_xray_config_chain_entry_multi
        _healed = False
        try:
            _cfg_h = json.loads(cfg_file.read_text())
            from chimera.modules.split_tunnel import strip_geo_rules
            if strip_geo_rules(_cfg_h):
                cfg_file.write_text(json.dumps(_cfg_h, indent=2, ensure_ascii=False))
                _set_config_owner(cfg_file)
                r2 = _run([str(XRAY_BIN), "run", "-test", "-config", str(cfg_file)],
                          capture=True, check=False)
                if r2.returncode == 0:
                    _healed = True
                    warn("GEO-SELF-HEAL: geo-файлы не загрузились — geosite/geoip-"
                         "правила УДАЛЕНЫ, Xray жив. Обновите geo-файлы "
                         "(Сеть → 3 → GeoIP/GeoSite).")
        except Exception:
            pass
        if not _healed:
            warn("Конфигурация создана с предупреждением")
            log_to_file("WARN", r.stderr[-1000:] if r.stderr else "")


# =============================================================================
#  ГЕНЕРАЦИЯ КОНФИГА XRAY ДЛЯ РЕЖИМА B — зарубежный (exit) VPS
# =============================================================================
def _make_exit_node_config(nd: dict) -> dict:
    """Строит словарь конфига Xray для одной exit-ноды."""
    core = _core_module()
    _build_exit_xhttp_settings = core._build_exit_xhttp_settings
    _build_sockopt = core._build_sockopt
    # Гейт версий клиента REALITY — лениво из state.json (меню 5b):
    # "" = выкл (норма для Xray 26.9.8+), "1.8.0" — даунгрейд-рецепт
    # для 26.7.11–26.7.28 (VLESS_FAQ §18).
    _min_client_ver = _min_client_ver_reader(core)
    XHTTP_TCP_NO_DELAY = getattr(core, "XHTTP_TCP_NO_DELAY", False)
    XHTTP_ENABLE_SESSION_RESUMPTION = getattr(core, "XHTTP_ENABLE_SESSION_RESUMPTION", False)
    XTLS_FLOW = getattr(core, "XTLS_FLOW", "")
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
                    **tfo_sockopt(),
                    "tcpKeepAliveInterval": 15,
                    "tcpKeepAliveIdle":   60,
                    "tcpUserTimeout":     30000,
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
    elif nd_proto == "xhttp_reality":
        # xHTTP + REALITY exit-нода (третий протокол): транспорт xHTTP,
        # TLS терминирует REALITY. Отличия от двух веток выше:
        #   • от xhttp-ветки: НЕТ tlsSettings/LE-сертификата — REALITY сама
        #     делает TLS-хендшейк (в этом весь смысл связки xhttp+reality);
        #   • от reality-ветки: НЕТ flow — xHTTP-транспорт несовместим с
        #     xtls-rprx-vision, клиенты принимаются без flow.
        inbound = {
            "tag":      "inbound-xhttp-reality",
            "port":     nd["port"],
            "listen":   "::",
            "protocol": "vless",
            "settings": {
                "clients": [{
                    "id":    nd["uuid"],
                    "email": "entry@chain",
                    # БЕЗ flow: xHTTP-транспорт не использует xtls-rprx-vision
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
                "security": "reality",
                # sockopt — стиль xhttp-ветки: xHTTP-транспорт требует
                # bbr/keepalive-оптимизации (у reality-ветки свой _build_sockopt)
                "sockopt":  {
                    **tfo_sockopt(),
                    "tcpKeepAliveInterval": 15,
                    "tcpKeepAliveIdle":   60,
                    "tcpUserTimeout":     30000,
                    "tcpCongestion":      "bbr",
                    **({"tcpNoDelay": True} if XHTTP_TCP_NO_DELAY else {}),
                },
                # tlsSettings НЕТ — TLS делает REALITY, LE-сертификат не нужен
                "xhttpSettings": _build_exit_xhttp_settings(nd),
                # realitySettings — как в reality-ветке (else) ПОЛНОСТЬЮ:
                # для xhttp_reality приватный ключ REALITY тоже обязателен
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
                    # Гейт версий клиента (minClientVer) — механика по факту
                    # стенда 2026-09-10 (docs/faq/VLESS_FAQ.md §18):
                    # ClientVer в хендшейке отчитывают ВСЕ — sing-box →
                    # [1,8,1], mihomo → [1,8,2] (проходит непустые пороги
                    # ≤ "1.8.2"; прежний комментарий «не отчитывают вовсе»
                    # был неверен — те тесты валил MLKEM-чек ClientHello
                    # ядра 26.9.8+, не гейт), Xray-клиент → версию ядра.
                    # Xray 26.7.11–26.7.28: unset/"" = ДЕФОЛТ-гейт 26.3.27,
                    # валит mihomo/sing-box, лечится явным minClientVer=
                    # "1.8.0" (рецепт podkop). Xray 26.9.8+ (наш флот):
                    # дефолт-гейт УБРАН — unset/"" = гейт выключен,
                    # непустые пороги живут ("2.0.0" валит mihomo [1,8,2],
                    # "1.8.0"/"1.0.0" пропускает; sing-box против 26.9.8+
                    # не пройдёт ни при каком гейте — барьер MLKEM, не
                    # версия). Значение лениво из state.json ("min_client_ver",
                    # ставится меню 5b; дефолт "" — норма для 26.9.8+);
                    # поля пишем ЯВНО, чтобы поведение не зависело от дефолтов
                    # ядра. Источники: XTLS/Xray-core #6477 (RPRX) +
                    # PR #6507, MetaCubeX/mihomo#3042, MHSanaei/3x-ui#5922.
                    "minClientVer": _min_client_ver(),
                    "maxClientVer": "",
                },
            },
        }
        comment = (
            "Этот конфиг предназначен для ЗАРУБЕЖНОГО VPS (exit node, xHTTP + REALITY). "
            "Скопируйте его в /etc/xray/config.json на зарубежном сервере. "
            "Приватный ключ REALITY: xray x25519 на exit-VPS, вставьте в privateKey."
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
                    # Гейт версий клиента (minClientVer) — механика по факту
                    # стенда 2026-09-10 (docs/faq/VLESS_FAQ.md §18):
                    # ClientVer в хендшейке отчитывают ВСЕ — sing-box →
                    # [1,8,1], mihomo → [1,8,2] (проходит непустые пороги
                    # ≤ "1.8.2"; прежний комментарий «не отчитывают вовсе»
                    # был неверен — те тесты валил MLKEM-чек ClientHello
                    # ядра 26.9.8+, не гейт), Xray-клиент → версию ядра.
                    # Xray 26.7.11–26.7.28: unset/"" = ДЕФОЛТ-гейт 26.3.27,
                    # валит mihomo/sing-box, лечится явным minClientVer=
                    # "1.8.0" (рецепт podkop). Xray 26.9.8+ (наш флот):
                    # дефолт-гейт УБРАН — unset/"" = гейт выключен,
                    # непустые пороги живут ("2.0.0" валит mihomo [1,8,2],
                    # "1.8.0"/"1.0.0" пропускает; sing-box против 26.9.8+
                    # не пройдёт ни при каком гейте — барьер MLKEM, не
                    # версия). Значение лениво из state.json ("min_client_ver",
                    # ставится меню 5b; дефолт "" — норма для 26.9.8+);
                    # поля пишем ЯВНО, чтобы поведение не зависело от дефолтов
                    # ядра. Источники: XTLS/Xray-core #6477 (RPRX) +
                    # PR #6507, MetaCubeX/mihomo#3042, MHSanaei/3x-ui#5922.
                    "minClientVer": _min_client_ver(),
                    "maxClientVer": "",
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
    core = _core_module()
    info = core.info
    warn = core.warn
    success = core.success
    CHAIN_NODES = getattr(core, "CHAIN_NODES", [])
    CHAIN_EXIT_HOST = getattr(core, "CHAIN_EXIT_HOST", "")
    CHAIN_EXIT_PORT = getattr(core, "CHAIN_EXIT_PORT", 443)
    CHAIN_EXIT_UUID = getattr(core, "CHAIN_EXIT_UUID", "")
    CHAIN_EXIT_PUBKEY = getattr(core, "CHAIN_EXIT_PUBKEY", "")
    CHAIN_EXIT_SHORTID = getattr(core, "CHAIN_EXIT_SHORTID", "")
    CHAIN_EXIT_SNI = getattr(core, "CHAIN_EXIT_SNI", "")
    CHAIN_EXIT_FP = getattr(core, "CHAIN_EXIT_FP", "chrome")

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
    has_xhttp_reality_nodes = any(nd.get("proto") == "xhttp_reality" for nd in nodes)
    if has_reality_nodes:
        info("REALITY exit nodes: сгенерируйте ключи: xray x25519")
        info("И прописать приватный ключ вместо <ВСТАВЬТЕ_PRIVATE_KEY_EXIT_NODE>")
    if has_xhttp_nodes:
        info("xHTTP exit nodes: получите сертификат Let's Encrypt на exit VPS")
        info("certbot certonly --standalone -d <ваш_домен> --non-interactive --agree-tos -m admin@<домен>")
    if has_xhttp_reality_nodes:
        # xhttp_reality: ключи x25519 нужны (REALITY TLS), LE-сертификат — НЕТ
        info("xHTTP+REALITY exit nodes: сгенерируйте ключи xray x25519 на exit VPS и вставьте privateKey (LE-сертификат НЕ нужен)")


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
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    warn = core.warn
    success = core.success
    uuid = core.uuid
    YELLOW = core.YELLOW
    CYAN = core.CYAN
    BLUE = core.BLUE
    BOLD = core.BOLD
    DIM = core.DIM
    NC = core.NC
    XTLS_FLOW = getattr(core, "XTLS_FLOW", "")
    CHAIN_NODES = getattr(core, "CHAIN_NODES", [])

    _load_chain_nodes_from_state()
    # _load_chain_nodes_from_state() writes to core.CHAIN_NODES via setattr;
    # re-bind local to see the updated value below.
    CHAIN_NODES = getattr(core, "CHAIN_NODES", [])

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
            proto = (input("  Протокол [reality/xhttp/xhttp_reality, по умолчанию reality]: ").strip().lower() or "reality")
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
    # flow только для классического tcp+reality: xhttp и xhttp_reality —
    # БЕЗ flow (xHTTP-транспорт несовместим с xtls-rprx-vision)
    if nd.get("proto", "reality") not in ("xhttp", "xhttp_reality") and XTLS_FLOW:
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
    core = _core_module()
    STATE_FILE = getattr(core, "STATE_FILE", None)
    CHAIN_NODES = getattr(core, "CHAIN_NODES", [])
    CHAIN_BALANCER_STRATEGY = getattr(core, "CHAIN_BALANCER_STRATEGY", "roundRobin")
    CHAIN_EXIT_HOST = getattr(core, "CHAIN_EXIT_HOST", "")
    CHAIN_EXIT_PORT = getattr(core, "CHAIN_EXIT_PORT", 443)
    CHAIN_EXIT_UUID = getattr(core, "CHAIN_EXIT_UUID", "")
    CHAIN_EXIT_PUBKEY = getattr(core, "CHAIN_EXIT_PUBKEY", "")
    CHAIN_EXIT_SHORTID = getattr(core, "CHAIN_EXIT_SHORTID", "")
    CHAIN_EXIT_SNI = getattr(core, "CHAIN_EXIT_SNI", "")
    CHAIN_EXIT_FP = getattr(core, "CHAIN_EXIT_FP", "chrome")
    if not STATE_FILE.exists():
        return
    try:
        state = json.loads(STATE_FILE.read_text())
        CHAIN_NODES = _nodes_from_state(state)
        setattr(core, "CHAIN_NODES", CHAIN_NODES)
        CHAIN_BALANCER_STRATEGY = state.get("chain_balancer_strategy", "roundRobin")
        setattr(core, "CHAIN_BALANCER_STRATEGY", CHAIN_BALANCER_STRATEGY)
        if CHAIN_NODES:
            n = CHAIN_NODES[0]
            CHAIN_EXIT_HOST    = n.get("host",    CHAIN_EXIT_HOST)
            setattr(core, "CHAIN_EXIT_HOST", CHAIN_EXIT_HOST)
            CHAIN_EXIT_PORT    = n.get("port",    CHAIN_EXIT_PORT)
            setattr(core, "CHAIN_EXIT_PORT", CHAIN_EXIT_PORT)
            CHAIN_EXIT_UUID    = n.get("uuid",    CHAIN_EXIT_UUID)
            setattr(core, "CHAIN_EXIT_UUID", CHAIN_EXIT_UUID)
            CHAIN_EXIT_PUBKEY  = n.get("pubkey",  CHAIN_EXIT_PUBKEY)
            setattr(core, "CHAIN_EXIT_PUBKEY", CHAIN_EXIT_PUBKEY)
            CHAIN_EXIT_SHORTID = n.get("shortid", CHAIN_EXIT_SHORTID)
            setattr(core, "CHAIN_EXIT_SHORTID", CHAIN_EXIT_SHORTID)
            CHAIN_EXIT_SNI     = n.get("sni",     CHAIN_EXIT_SNI)
            setattr(core, "CHAIN_EXIT_SNI", CHAIN_EXIT_SNI)
            CHAIN_EXIT_FP      = n.get("fp",      CHAIN_EXIT_FP)
            setattr(core, "CHAIN_EXIT_FP", CHAIN_EXIT_FP)
    except Exception:
        pass


def _save_chain_nodes_to_state() -> None:
    """Записывает CHAIN_NODES обратно в STATE_FILE, не затрагивая остальные поля."""
    core = _core_module()
    warn = core.warn
    STATE_FILE = getattr(core, "STATE_FILE", None)
    CHAIN_NODES = getattr(core, "CHAIN_NODES", [])
    CHAIN_BALANCER_STRATEGY = getattr(core, "CHAIN_BALANCER_STRATEGY", "roundRobin")
    CHAIN_PINNED_NODE_INDEX = getattr(core, "CHAIN_PINNED_NODE_INDEX", -1)
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
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    _box_back = core._box_back
    warn = core.warn
    YELLOW = core.YELLOW
    CYAN = core.CYAN
    GREEN = core.GREEN
    NC = core.NC

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
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    _box_sep = core._box_sep
    _box_item = core._box_item
    _box_item_exit = core._box_item_exit
    _box_wrap_msg = core._box_wrap_msg
    warn = core.warn
    parse_vless_link = core.parse_vless_link
    YELLOW = core.YELLOW
    BOLD = core.BOLD
    DIM = core.DIM
    NC = core.NC

    _box_top(f"Ввод Exit Node #{index} через VLESS-ссылку")
    _box_row()
    _box_wrap_msg(f"  {DIM}Пример: {NC}", 10, f"vless://UUID@host:443?type=tcp&security=reality&pbk=...&sid=...&sni=domain.com&flow=xtls-rprx-vision")
    _box_wrap_msg(f"  {DIM}Или:    {NC}", 10, f"vless://UUID@host:443?type=xhttp&security=tls&sni=domain.com&path=/abc")
    _box_wrap_msg(f"  {DIM}Или:    {NC}", 10, f"vless://UUID@host:443?type=xhttp&security=reality&sni=domain.com&fp=chrome&pbk=PUBKEY&sid=SID&path=/abc&mode=stream-up")
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
        elif parsed['proto'] == 'xhttp_reality':
            # xHTTP+REALITY: показываем И REALITY-ключи, И параметры транспорта
            pubkey_info = f"PubKey: {parsed['pubkey'][:20]}..." if parsed['pubkey'] else "PubKey: не найден!"
            _box_row(f"  Proto:    XHTTP_REALITY ({pubkey_info})")
            _box_row(f"  ShortID:  {parsed['shortid']}")
            _box_row(f"  xHTTP:    mode: {parsed['xhttp_mode']}, path: {parsed['path']}")
        else:
            _box_row(f"  Proto:    {parsed['proto'].upper()} (xhttp mode: {parsed['xhttp_mode']}, path: {parsed['path']})")
        _box_row(f"  SNI:      {parsed['sni']}")
        _box_row(f"  FP:       {parsed['fp']}")

        # Валидация host — проверка на self-reference и reverse-DNS.
        is_valid_host, host_msg, resolved_ip = _validate_chain_node_host(parsed["host"])
        if not is_valid_host:
            warn(f"  ⚠ {host_msg}")
            _box_sep()
            _box_item("F", f"Изменить host вручную")
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
                    parsed["host"] = ""  # заставим _fix_node_fields спросить host
                    return _fix_node_fields(index, parsed)
                warn("Введите F, R или 0")
            continue  # повтор ввода ссылки
        else:
            # Показываем куда резолвится host.
            if resolved_ip and resolved_ip != parsed["host"]:
                _box_row(f"  {DIM}Резолвится в: {resolved_ip}{NC}")

        # Проверка обязательных полей
        warnings = []
        # REALITY-ключи обязательны и для tcp+reality, и для xhttp+reality —
        # REALITY TLS требует пару ключей x25519 в любом транспорте
        if parsed['proto'] in ('reality', 'xhttp_reality'):
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
        # flow: только tcp+reality использует xtls-rprx-vision в каскадном
        # outbound'е. xhttp_reality — БЕЗ flow (xHTTP-транспорт); для xhttp
        # поведение не меняем (дефолт xtls-rprx-vision, поле не потребляется
        # xhttp-ветками) — контракт совпадает с collect_nodes() в
        # subscription_multinode.py.
        if parsed.get("proto") == "xhttp_reality":
            _node_flow = ""
        else:
            _node_flow = parsed.get("flow", "xtls-rprx-vision") or "xtls-rprx-vision"
        node = {
            "host":       parsed["host"],
            "port":       parsed["port"],
            "uuid":       parsed["uuid"],
            "pubkey":     parsed["pubkey"],
            "shortid":    parsed["shortid"],
            "sni":        parsed["sni"],
            "fp":         parsed["fp"],
            "flow":       _node_flow,
            "proto":      parsed["proto"],
            "path":       parsed.get("path", "/"),
            "xhttp_mode": parsed.get("xhttp_mode", "stream-up"),
        }
        return node


def _fix_node_fields(index: int, parsed: dict) -> dict | None:
    """Дозаполнение отсутствующих полей exit-ноды."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    warn = core.warn

    _box_top(f"Дозаполнение полей Exit Node #{index}")
    _box_row()

    if parsed['proto'] in ('reality', 'xhttp_reality'):
        # REALITY-ключи нужны обоим REALITY-протоколам: и tcp+reality, и
        # xhttp+reality (REALITY TLS требует пару ключей x25519 в любом транспорте)
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
    # flow: только tcp+reality (xtls-rprx-vision); xhttp_reality — БЕЗ flow
    # (xHTTP-транспорт). Для xhttp поведение не меняем — контракт как в
    # _prompt_one_node_from_link() и collect_nodes() (subscription_multinode).
    if parsed.get("proto") == "xhttp_reality":
        _node_flow = ""
    else:
        _node_flow = parsed.get("flow", "xtls-rprx-vision") or "xtls-rprx-vision"
    return {
        "host":       parsed["host"],
        "port":       parsed["port"],
        "uuid":       parsed["uuid"],
        "pubkey":     parsed["pubkey"],
        "shortid":    parsed["shortid"],
        "sni":        parsed["sni"],
        "fp":         parsed.get("fp", "chrome"),
        "flow":       _node_flow,
        "proto":      parsed["proto"],
        "path":       parsed.get("path", "/"),
        "xhttp_mode": parsed.get("xhttp_mode", "stream-up"),
    }


def _prompt_one_node_manual(index: int) -> dict | None:
    """Ввод параметров exit-ноды вручную по полям."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    warn = core.warn
    info = core.info
    _fm_prompt_fingerprint = core._fm_prompt_fingerprint
    gen_hex = core.gen_hex
    YELLOW = core.YELLOW
    CYAN = core.CYAN
    BLUE = core.BLUE
    GREEN = core.GREEN
    BOLD = core.BOLD
    NC = core.NC
    XTLS_FLOW = getattr(core, "XTLS_FLOW", "")

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
            # Валидация host перед сохранением.
            is_valid, msg, resolved_ip = _validate_chain_node_host(v)
            if not is_valid:
                warn(f"   {msg}")
                # Не выходим из цикла — даём пользователю шанс ввести заново.
                continue
            # Если валидация прошла — показываем что резолвится.
            if resolved_ip and resolved_ip != v:
                info(f"   {msg}")
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
    _box_row(f"   {CYAN}[3]{NC} VLESS + xHTTP + REALITY {YELLOW}(только xray-клиенты){NC}")
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
        elif v == "3":
            exit_proto = "xhttp_reality"
            break
        warn("   Введите 1, 2 или 3")

    pubkey = ""
    shortid = ""
    xhttp_mode_val = "stream-up"
    path_val = "/"
    flow_val = XTLS_FLOW

    # Нумерация полей ниже зависит от протокола: у xhttp_reality ДВА блока
    # промптов (REALITY-ключи + xHTTP-параметры) → последующие SNI/FP
    # сдвигаются на E9/E10, а xHTTP-поля получают E7/E8.
    _is_xhr = exit_proto == "xhttp_reality"

    if exit_proto in ("reality", "xhttp_reality"):
        # REALITY-ключи: нужны и tcp+reality, и xhttp+reality — REALITY TLS
        # требует пару ключей x25519 независимо от транспорта (xray x25519 на exit-VPS)
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

    if exit_proto in ("xhttp", "xhttp_reality"):
        # xHTTP-параметры: транспорту xHTTP безразлично, кто терминирует TLS —
        # LE-сертификат (xhttp) или REALITY (xhttp_reality)
        _mode_e = "E7" if _is_xhr else "E5"
        _path_e = "E8" if _is_xhr else "E6"
        _box_row(f"{BLUE}[{_mode_e}] xHTTP режим:{NC}")
        _box_row(f"   {CYAN}[1]{NC} stream-up {GREEN}(рек.){NC}  {CYAN}[2]{NC} stream-one  {CYAN}[3]{NC} packet-up {YELLOW}(⚠ проверьте версию Xray){NC}")
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
                xhttp_mode_val = "stream-up"
                break
            elif v == "2":
                xhttp_mode_val = "stream-one"
                break
            elif v == "3":
                xhttp_mode_val = "packet-up"
                warn("packet-up выбран — убедитесь что ваша версия Xray-core его поддерживает")
                break
            warn("   Введите 1, 2 или 3")

        auto_path = "/" + gen_hex(4)
        _box_row(f"{BLUE}[{_path_e}] xHTTP path [{auto_path}]:{NC}")
        try:
            v = input(f"   Path [{auto_path}]: ").strip()
        except KeyboardInterrupt:
            print()
            raise
        if v == "0":
            return None
        path_val = v if v.startswith("/") else auto_path
        # xHTTP не использует flow — ни с TLS, ни с REALITY (xHTTP-транспорт
        # несовместим с xtls-rprx-vision)
        flow_val = ""

    # SNI
    _sni_e = "E9" if _is_xhr else "E7"
    _box_row(f"{BLUE}[{_sni_e}] SNI / домен зарубежного VPS:{NC}")
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
    _fp_e = "E10" if _is_xhr else "E8"
    _box_row(f"{BLUE}[{_fp_e}] Fingerprint браузера:{NC}")
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
    elif exit_proto == "xhttp_reality":
        # xHTTP+REALITY: показываем И REALITY-ключи, И параметры транспорта —
        # для этой связки нужны обе группы полей
        _box_row(f"  PubKey:   {pubkey[:20]}...")
        _box_row(f"  ShortID:  {shortid}")
        _box_row(f"  xHTTP:    {xhttp_mode_val}, path={path_val}")
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
    core = _core_module()
    info = core.info
    warn = core.warn
    try:
        from chimera.modules.hysteria2_common import _load_h2_state
        h2 = _load_h2_state()
        if h2.get("active_transport") != "hysteria2":
            return
        nodes = [n for n in h2.get("exit_nodes", []) if n.get("status") == "active"]
        if not nodes:
            return
        from chimera.modules.hysteria2_transport import h2_transport_apply
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
    core = _core_module()
    # Гейт версий клиента REALITY — лениво из state.json (меню 5b):
    # "" = выкл (норма для Xray 26.9.8+), "1.8.0" — даунгрейд-рецепт
    # для 26.7.11–26.7.28 (VLESS_FAQ §18).
    _min_client_ver = _min_client_ver_reader(core)
    # Anti-Empty Identity Guard — UUID/ShortID/REALITY-ключи entry-ноды
    # не должны быть пустыми при регенерации (восстановление из живого
    # config.json/users.json — иначе ссылки юзеров ломаются).
    try:
        core._identity_params_recover()
    except Exception:
        pass  # guard не должен блокировать генерацию
    _assert_reality_dest_sane = core._assert_reality_dest_sane
    _run = core._run
    _build_xhttp_settings = core._build_xhttp_settings
    _build_tls_settings_xhttp = core._build_tls_settings_xhttp
    _build_sockopt = core._build_sockopt
    _build_exit_xhttp_outbound_settings = core._build_exit_xhttp_outbound_settings
    _xray_log_block = core._xray_log_block
    _apply_stats_to_config = core._apply_stats_to_config
    _set_config_owner = core._set_config_owner
    build_split_tunnel_routing_rules = core.build_split_tunnel_routing_rules
    generate_xray_config_xhttp = core.generate_xray_config_xhttp
    generate_xray_config = core.generate_xray_config
    info = core.info
    warn = core.warn
    success = core.success
    log_to_file = core.log_to_file
    DNSCRYPT_LISTEN_PORT = getattr(core, "DNSCRYPT_LISTEN_PORT", 5300)
    DNSCRYPT_LISTEN_ADDR = getattr(core, "DNSCRYPT_LISTEN_ADDR", "127.0.0.1")
    DNSCRYPT_INSTALLED = getattr(core, "DNSCRYPT_INSTALLED", False)
    IS_IPV6_AVAILABLE = getattr(core, "IS_IPV6_AVAILABLE", False)
    PROTOCOL_MODE = getattr(core, "PROTOCOL_MODE", "reality")
    PARAM_DOMAIN = getattr(core, "PARAM_DOMAIN", "")
    PARAM_UUID = getattr(core, "PARAM_UUID", "")
    XTLS_FLOW = getattr(core, "XTLS_FLOW", "")
    XHTTP_MODE = getattr(core, "XHTTP_MODE", "stream-up")
    XHTTP_PATH = getattr(core, "XHTTP_PATH", "/")
    XHTTP_BACKEND_PORT = getattr(core, "XHTTP_BACKEND_PORT", 8443)
    XHTTP_TCP_NO_DELAY = getattr(core, "XHTTP_TCP_NO_DELAY", False)
    XHTTP_ENABLE_SESSION_RESUMPTION = getattr(core, "XHTTP_ENABLE_SESSION_RESUMPTION", False)
    AWG_EXIT_ENABLED = getattr(core, "AWG_EXIT_ENABLED", False)
    H2_EXIT_ENABLED = getattr(core, "H2_EXIT_ENABLED", False)
    PARAM_REALITY_DEST = getattr(core, "PARAM_REALITY_DEST", "")
    PARAM_SOCKET_PATH = getattr(core, "PARAM_SOCKET_PATH", "")
    PARAM_SPIDERX = getattr(core, "PARAM_SPIDERX", "/")
    PARAM_PRIVATE_KEY = getattr(core, "PARAM_PRIVATE_KEY", "")
    PARAM_PUBLIC_KEY = getattr(core, "PARAM_PUBLIC_KEY", "")
    PARAM_SHORTID = getattr(core, "PARAM_SHORTID", "")
    CHAIN_NODES = getattr(core, "CHAIN_NODES", [])
    CHAIN_EXIT_HOST = getattr(core, "CHAIN_EXIT_HOST", "")
    CHAIN_EXIT_PORT = getattr(core, "CHAIN_EXIT_PORT", 443)
    CHAIN_EXIT_UUID = getattr(core, "CHAIN_EXIT_UUID", "")
    CHAIN_EXIT_PUBKEY = getattr(core, "CHAIN_EXIT_PUBKEY", "")
    CHAIN_EXIT_SHORTID = getattr(core, "CHAIN_EXIT_SHORTID", "")
    CHAIN_EXIT_SNI = getattr(core, "CHAIN_EXIT_SNI", "")
    CHAIN_EXIT_FP = getattr(core, "CHAIN_EXIT_FP", "chrome")
    CHAIN_BALANCER_STRATEGY = getattr(core, "CHAIN_BALANCER_STRATEGY", "roundRobin")
    CHAIN_PINNED_NODE_INDEX = getattr(core, "CHAIN_PINNED_NODE_INDEX", -1)
    AWG_FWMARK = getattr(core, "AWG_FWMARK", 1000)
    SERVER_PORT = getattr(core, "SERVER_PORT", 443)
    SPLIT_TUNNEL_ENABLED = getattr(core, "SPLIT_TUNNEL_ENABLED", False)
    CONFIG_DIR = getattr(core, "CONFIG_DIR", Path("/etc/xray"))
    XRAY_BIN = getattr(core, "XRAY_BIN", "/usr/local/bin/xray")
    Any = getattr(core, "Any", None)

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

    # AGH-AWARE (v37): при живом AdGuard Home на :53 — DNS entry-ноды
    # через AGH (кеш+фильтры). Exit-шаблоны выше НЕ трогаем — они
    # разворачиваются на чужих VPS без AGH.
    # (agh_probe): health-check углублён — живая проба резолва
    # (end-to-end AGH → DNSCrypt → интернет) + нейтрализация iptables
    # redirect 53→5300. Сбой любого шага → прежний путь DNSCrypt:5300.
    # (agh-autostart): AGH установлен, но остановлен → ПОДНИМАЕМ его
    # перед пробой («AGH должен запускаться и слушать порты, если он
    # установлен»). Не установлен — autostart безвреден (no-op, rc≠0
    # у systemctl start несуществующего юнита).
    agh_ok, agh_note = agh_dns_available(run=_run, log_info=info,
                                         log_warn=warn, autostart=True)

    if agh_ok:
        dns_servers = [
            {"address": "127.0.0.1", "port": 53,
             "network": "udp", "skipFallback": False},
        ]
        if dnscrypt_running:
            # Живой fallback на случай падения AGH после генерации
            dns_servers.append(
                {"address": DNSCRYPT_LISTEN_ADDR, "port": DNSCRYPT_LISTEN_PORT,
                 "network": "udp", "skipFallback": False})
        # последний живой fallback — Quad9 напрямую (UDP:53 anycast).
        # Достижим и с зарубежных, и с РФ-хостингов (1.1.1.1/8.8.8.8 в РФ
        # душатся/заблокированы РКН). Срабатывает ТОЛЬКО при падении AGH+DNSCrypt —
        # лучше открытый DNS, чем DNS black-hole для IPIfNonMatch-резолва
        # (иначе доменные соединения зависают на таймаутах DNS).
        dns_servers.append(
            {"address": "9.9.9.9", "port": 53, "network": "udp", "skipFallback": False})
        dns_servers += [
            {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": True},
            {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": True},
        ]
        info(f"DNS: AdGuardHome здоров ({agh_note}) — Xray → AGH:53 → DNSCrypt")
    elif dnscrypt_running:
        dns_servers = [
            {"address": DNSCRYPT_LISTEN_ADDR, "port": DNSCRYPT_LISTEN_PORT,
             "network": "udp", "skipFallback": False},
            # живой Quad9-fallback — достижим из РФ (в отличие от 1.1.1.1/8.8.8.8)
            {"address": "9.9.9.9", "port": 53, "network": "udp", "skipFallback": False},
            {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": True},
            {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": True},
        ]
    else:
        dns_servers = [
            {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": False},
            {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": False},
        ]

    query_strategy = "UseIPv6v4" if IS_IPV6_AVAILABLE else "UseIPv4"

    # ── Chain Relay (релейные хопы): exit-нода с via = «chain_nodes[i].via»
    #    соединяется к хопу через другой outbound (sockopt.dialerProxy).
    #    Без хопов / без via — конфиг байт-в-байт как раньше (совместимость).
    relay_hops: list[dict] = []
    try:
        from chimera.modules.chain_relay import (
            load_relay_hops as _cr_load_hops,
            hop_via_tag_for as _cr_via_tag,
            collect_hop_outbounds as _cr_collect,
        )
        relay_hops = _cr_load_hops()
    except Exception:
        relay_hops = []

    # Строим список outbound-ов для exit-нод
    outbounds_exit = []
    outbound_tags  = []
    via_count = 0
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
                        **tfo_sockopt(),
                        "tcpKeepAliveInterval": 15,
                        "tcpKeepAliveIdle":   60,
                        "tcpUserTimeout":     30000,
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
        elif nd_proto == "xhttp_reality":
            # xHTTP + REALITY исходящий к exit-ноде: транспорт xHTTP +
            # REALITY TLS (без LE-сертификата). users БЕЗ flow — как в
            # xhttp-ветке; realitySettings — как в reality-ветке ниже.
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
                            # REALITY: тоже без flow (xHTTP-транспорт)
                        }],
                    }],
                },
                "streamSettings": {
                    "network":  "xhttp",
                    "security": "reality",
                    # sockopt — xhttp-ветка (bbr/keepalive для xHTTP) ПЛЮС
                    # AWG-марк: при включённом AWG exit-трафик должен уходить
                    # в таблицу маршрутизации awg0 (как в reality-ветке)
                    "sockopt":  {
                        **tfo_sockopt(),
                        "tcpKeepAliveInterval": 15,
                        "tcpKeepAliveIdle":   60,
                        "tcpUserTimeout":     30000,
                        "tcpCongestion":      "bbr",
                        **({"tcpNoDelay": True} if XHTTP_TCP_NO_DELAY else {}),
                        **({"mark": AWG_FWMARK} if AWG_EXIT_ENABLED else {}),  # ПАТЧ: AWG mark
                    },
                    "xhttpSettings": _build_exit_xhttp_outbound_settings(nd),
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
        # Chain Relay: exit-нода с via ходит через хоп (sockopt.dialerProxy)
        _via_tag = None
        if relay_hops:
            try:
                _via_tag = _cr_via_tag(nd, relay_hops)
            except Exception:
                _via_tag = None
        if _via_tag:
            out["streamSettings"].setdefault("sockopt", {})["dialerProxy"] = _via_tag
            via_count += 1
        outbounds_exit.append(out)

    # Hop-outbound-и (только если хотя бы один exit использует via)
    hop_outbounds: list[dict] = []
    if relay_hops and via_count:
        try:
            hop_outbounds = _cr_collect(nodes, relay_hops)
        except Exception:
            hop_outbounds = []
        if hop_outbounds:
            info(f"Chain Relay: {via_count} exit-нод(ы) через хопи "
                 f"({', '.join(ob['tag'] for ob in hop_outbounds)}) — dialerProxy")

    # Inbound от клиента — зависит от PROTOCOL_MODE
    # ── BUGFIX: clients — из ЕДИНОГО источника юзеров ──────────
    #    Раньше сюда жёстко подставлялся PARAM_UUID из state.json. При
    #    регенерации конфига (AGH-финализация / «Пересоздать конфиг
    #    Xray» / emergency repair) все остальные юзеры выпадали из
    #    clients → xray рвал соединения «invalid request user id» →
    #    EOF у клиентов со ссылками, выданными до регенерации
    #    (регрессия на vds без IPv6: state.uuid ≠ uuid в /root/vless_link.txt).
    #    Теперь: _unified_load_users() (users.json + текущий конфиг) +
    #    PARAM_UUID как fallback/дополнение. Fresh install поведение
    #    не меняется (юзеров нет → clients=[PARAM_UUID]).
    try:
        from chimera.modules.users_manager import (
            _users_collect_for_config, _clients_from_users)
        _cfg_users = _users_collect_for_config(
            PARAM_UUID, f"user@{PARAM_DOMAIN}")
    except Exception:
        _cfg_users = [{"uuid": PARAM_UUID,
                       "email": f"user@{PARAM_DOMAIN}"}]

    if PROTOCOL_MODE == "xhttp_reality":
        # xHTTP + REALITY entry (Mode B): гибрид, зеркалящий Mode A
        # (generate_xray_config_xhttp_reality) — Xray владеет SERVER_PORT
        # напрямую (REALITY терминирует TLS), транспорт xHTTP (mode/path,
        # xmux/padding). Nginx — только unix-сокет с сайтом-заглушкой
        # (fallback dest). clients БЕЗ flow (xhttp не поддерживает vision).
        # Живой тест Mode A: DE 203.0.113.106:8443 — работает (2026-09-29).
        _xhttp_s_x, _sockopt_x = _build_xhttp_settings(XHTTP_MODE, XHTTP_PATH)
        info(f"chain B + xHTTP+REALITY: inbound на :{SERVER_PORT} напрямую "
             f"(network=xhttp, security=reality, mode={XHTTP_MODE}, "
             f"path={XHTTP_PATH})")
        client_inbound = {
            "tag":      "inbound-xhttp-reality",
            "port":     SERVER_PORT,          # публичный порт — REALITY TLS
            "listen":   "::",
            "protocol": "vless",
            "settings": {
                "clients": _clients_from_users(_cfg_users),  # БЕЗ flow
                "decryption": "none",
            },
            "sniffing": _build_chain_sniffing(awg=AWG_EXIT_ENABLED),
            "streamSettings": {
                "network":       "xhttp",
                "sockopt":       _sockopt_x,
                "security":      "reality",
                # Транспортный слой xHTTP (mode/path/extra: padding, xmux)
                "xhttpSettings": _xhttp_s_x,
                # TLS-маскировка REALITY — dest=unix-сокет nginx
                # (сайт-заглушка), serverNames=свой домен.
                "realitySettings": {
                    "show":        False,
                    "dest":        (PARAM_REALITY_DEST + ":443") if AWG_EXIT_ENABLED else PARAM_SOCKET_PATH,
                    "xver":        0 if AWG_EXIT_ENABLED else 1,
                    "spiderX":     PARAM_SPIDERX,
                    "serverNames": [PARAM_REALITY_DEST if AWG_EXIT_ENABLED else PARAM_DOMAIN],
                    "privateKey":  PARAM_PRIVATE_KEY,
                    "publicKey":   PARAM_PUBLIC_KEY,
                    "shortIds":    [PARAM_SHORTID],
                    # Гейт версий клиента — лениво из state.json (меню 5b);
                    # подробный комментарий — в reality-ветке ниже.
                    "minClientVer": _min_client_ver(),
                    "maxClientVer": "",
                },
            },
        }
    elif PROTOCOL_MODE == "xhttp":
        # Схема Nginx → Xray (loopback backend):
        # Xray-core не поддерживает fallbacks для xHTTP (задокументированное
        # ограничение — https://github.com/XTLS/Xray-core/discussions/4113).
        # Nginx терминирует TLS на :SERVER_PORT, отдаёт заглушку для "/" и
        # проксирует xhttp path сюда — на 127.0.0.1:XHTTP_BACKEND_PORT.
        # Сертификат тут не нужен — трафик уже расшифрован Nginx.
        _xhttp_s2, _sockopt_s2 = _build_xhttp_settings(XHTTP_MODE, XHTTP_PATH)
        info(f"chain B + xHTTP: inbound на 127.0.0.1:{XHTTP_BACKEND_PORT} (security: none, "
             f"TLS терминирует Nginx на :{SERVER_PORT})")
        client_inbound = {
            "tag":      "inbound-xhttp",
            "port":     XHTTP_BACKEND_PORT,   # loopback-only, Nginx проксирует сюда
            "listen":   "127.0.0.1",          # только loopback — извне не доступно
            "protocol": "vless",
            "settings": {
                "clients": _clients_from_users(_cfg_users),
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
                "security":      "none",      # TLS терминирован Nginx
                "sockopt":       _sockopt_s2,
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
                "clients": _clients_from_users(_cfg_users, XTLS_FLOW),
                "decryption": "none",
            },
            # FIX: sniffing с 'quic' в destOverride — Xray перехватывает QUIC
            # и маршрутизирует через BLOCK правило вместо падения в catch-all.
            "sniffing": _build_chain_sniffing(awg=AWG_EXIT_ENABLED),
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
                    # Гейт версий клиента (minClientVer) — механика по факту
                    # стенда 2026-09-10 (docs/faq/VLESS_FAQ.md §18):
                    # ClientVer в хендшейке отчитывают ВСЕ — sing-box →
                    # [1,8,1], mihomo → [1,8,2] (проходит непустые пороги
                    # ≤ "1.8.2"; прежний комментарий «не отчитывают вовсе»
                    # был неверен — те тесты валил MLKEM-чек ClientHello
                    # ядра 26.9.8+, не гейт), Xray-клиент → версию ядра.
                    # Xray 26.7.11–26.7.28: unset/"" = ДЕФОЛТ-гейт 26.3.27,
                    # валит mihomo/sing-box, лечится явным minClientVer=
                    # "1.8.0" (рецепт podkop). Xray 26.9.8+ (наш флот):
                    # дефолт-гейт УБРАН — unset/"" = гейт выключен,
                    # непустые пороги живут ("2.0.0" валит mihomo [1,8,2],
                    # "1.8.0"/"1.0.0" пропускает; sing-box против 26.9.8+
                    # не пройдёт ни при каком гейте — барьер MLKEM, не
                    # версия). Значение лениво из state.json ("min_client_ver",
                    # ставится меню 5b; дефолт "" — норма для 26.9.8+);
                    # поля пишем ЯВНО, чтобы поведение не зависело от дефолтов
                    # ядра. Источники: XTLS/Xray-core #6477 (RPRX) +
                    # PR #6507, MetaCubeX/mihomo#3042, MHSanaei/3x-ui#5922.
                    "minClientVer": _min_client_ver(),
                    "maxClientVer": "",
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
        # FIX: используем единый helper — он правильно обрабатывает UDP
        # (DNS→direct, QUIC→BLOCK, UDP→BLOCK, только TCP→exit-нода).
        # Раньше catch-all {"network": "tcp,udp"} рвал UDP-трафик, что
        # приводило к EOF и «dns: exchange failed» у VPN-клиентов.
        routing_rules = _build_chain_routing_rules(effective_tag)
    else:
        # Несколько нод — балансировщик с выбранной стратегией.
        # LB-состав (chain_lb_nodes): selector только по выбранным нодам
        # (зеркало lb_exits AWG/Mieru); outbounds остаются superset'ом —
        # невыбранные не участвуют в ротации, но не рвут конфиг.
        strategy = CHAIN_BALANCER_STRATEGY  # "roundRobin" | "leastPing" | "random"
        _lb_sel = _lb_selection_from_state(core)
        _sel_tags = _lb_selector_tags(outbound_tags, nodes, _lb_sel)
        if len(_sel_tags) < len(outbound_tags):
            info(f"LB-состав: {_lb_nodes_summary(nodes, _lb_sel)} "
                 f"— selector: {', '.join(_sel_tags)}")
        balancers = [{
            "tag":      "chain-balancer",
            "selector": _sel_tags,
            "strategy": {"type": strategy},
        }]
        # FIX: тот же helper, но с balancer=True (использует balancerTag).
        routing_rules = _build_chain_routing_rules("chain-balancer", balancer=True)
        # leastPing / leastLoad требуют observatory — без него деградирует до random
        if strategy in ("leastPing", "leastLoad"):
            observatory = {
                "subjectSelector":       list(_sel_tags),
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
        "outbounds": hop_outbounds + outbounds_exit + [
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
    # В AWG-режиме "direct" имеет fwmark=AWG_FWMARK → весь трафик через awg0.
    # Для split tunnel нужен "direct-local" (без fwmark) → РФ-трафик через default route ОС (физический интерфейс).
    if SPLIT_TUNNEL_ENABLED:
        # В Режиме B "direct" = прямой выход с Entry Node (российский VPS),
        # proxy_tag = первая exit-нода (или балансировщик).
        # В AWG-режиме proxy_tag = "direct" (с fwmark → awg0 → exit-VPS),
        # direct_tag = "direct-local" (без fwmark → default route ОС → IP entry-сервера).
        if AWG_EXIT_ENABLED:
            _dl_strategy = "UseIPv6v4" if IS_IPV6_AVAILABLE else "UseIPv4"
            if not any(ob.get("tag") == "direct-local" for ob in config.get("outbounds", [])):
                config["outbounds"].insert(0, {
                    "protocol": "freedom",
                    "tag":      "direct-local",
                    "settings": {"domainStrategy": _dl_strategy},
                })
            proxy_t = "direct"
            direct_t = "direct-local"
        else:
            if not any(ob.get("tag") == "direct" for ob in config.get("outbounds", [])):
                config["outbounds"].insert(0, {
                    "protocol": "freedom",
                    "tag":      "direct",
                    "settings": {"domainStrategy": "UseIP"},
                })
            proxy_t = "chain-balancer" if balancers else (outbound_tags[0] if outbound_tags else "direct")
            direct_t = "direct"
        st_rules = build_split_tunnel_routing_rules(proxy_tag=proxy_t, direct_tag=direct_t)
        if st_rules:
            config["routing"]["rules"] = st_rules + config["routing"]["rules"]
            config["routing"]["geoDataBasePath"] = str(CONFIG_DIR)
            info(f"Split tunneling: добавлено {len(st_rules)} правил "
                 f"(Режим B, Entry Node, AWG={AWG_EXIT_ENABLED}, direct_tag={direct_t})")

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
        # (geo-self-heal): негрузимые geo-правила = МЁРТВЫЙ Xray (exit 23
        # + RestartPreventExitStatus=23) = i/o timeout для ВСЕХ клиентов.
        # Убираем geosite:/geoip: правила, ретестим, пишем живой конфиг.
        _healed = False
        try:
            _cfg_h = json.loads(cfg_file.read_text())
            from chimera.modules.split_tunnel import strip_geo_rules
            if strip_geo_rules(_cfg_h):
                cfg_file.write_text(json.dumps(_cfg_h, indent=2, ensure_ascii=False))
                _set_config_owner(cfg_file)
                r2 = _run([str(XRAY_BIN), "run", "-test", "-config", str(cfg_file)],
                          capture=True, check=False)
                if r2.returncode == 0:
                    _healed = True
                    warn("GEO-SELF-HEAL: geo-файлы не загрузились (нет в пути "
                         "поиска Xray / категория отсутствует) — geosite/geoip-"
                         "правила УДАЛЕНЫ, Xray жив. Раздельное туннелирование "
                         "деградировало: весь трафик через exit-ноду. "
                         "Лечение: обновите geo-файлы (Сеть → 3 → GeoIP/GeoSite).")
        except Exception:
            pass
        if not _healed:
            warn("Конфигурация создана с предупреждением")
            log_to_file("WARN", r.stderr[-1000:] if r.stderr else "")
    _h2_reapply_transport_if_active()


def do_manage_nodes() -> None:
    """
    Пункт [E] главного меню: управление exit-нодами каскада (Режим B).
    Позволяет добавить, удалить ноду и пересобрать конфиг Xray.
    """
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    _box_item_exit = core._box_item_exit
    _box_sep = core._box_sep
    _box_info = core._box_info
    _box_warn = core._box_warn
    _box_back = core._box_back
    _run = core._run
    info = core.info
    warn = core.warn
    success = core.success
    country_flag_emoji = core.country_flag_emoji
    _load_split_tunnel_custom = core._load_split_tunnel_custom
    _detect_xhttp_mode_support = core._detect_xhttp_mode_support
    _rebuild_and_restart_xray = core._rebuild_and_restart_xray
    BOLD = core.BOLD
    CYAN = core.CYAN
    YELLOW = core.YELLOW
    GREEN = core.GREEN
    BLUE = core.BLUE
    DIM = core.DIM
    NC = core.NC
    STATE_FILE = getattr(core, "STATE_FILE", None)
    CONFIG_DIR = getattr(core, "CONFIG_DIR", Path("/etc/xray"))
    MAX_CHAIN_NODES = getattr(core, "MAX_CHAIN_NODES", 10)
    INSTALL_MODE = getattr(core, "INSTALL_MODE", "A")
    PROTOCOL_MODE = getattr(core, "PROTOCOL_MODE", "reality")
    SERVER_PORT = getattr(core, "SERVER_PORT", 443)
    XHTTP_PORT = getattr(core, "XHTTP_PORT", 443)
    XHTTP_MODE = getattr(core, "XHTTP_MODE", "stream-up")
    XHTTP_PATH = getattr(core, "XHTTP_PATH", "/")
    XHTTP_PERF_PRESET = getattr(core, "XHTTP_PERF_PRESET", "")
    PARAM_DOMAIN = getattr(core, "PARAM_DOMAIN", "")
    PARAM_UUID = getattr(core, "PARAM_UUID", "")
    PARAM_PUBLIC_KEY = getattr(core, "PARAM_PUBLIC_KEY", "")
    PARAM_SHORTID = getattr(core, "PARAM_SHORTID", "")
    PARAM_PRIVATE_KEY = getattr(core, "PARAM_PRIVATE_KEY", "")
    PARAM_SOCKET_PATH = getattr(core, "PARAM_SOCKET_PATH", "")
    PARAM_SPIDERX = getattr(core, "PARAM_SPIDERX", "/")
    PARAM_DOMAIN_STRATEGY = getattr(core, "PARAM_DOMAIN_STRATEGY", "")
    PARAM_REALITY_DEST = getattr(core, "PARAM_REALITY_DEST", "")
    SPLIT_TUNNEL_ENABLED = getattr(core, "SPLIT_TUNNEL_ENABLED", False)
    SPLIT_TUNNEL_EXTRA_DOMAINS = getattr(core, "SPLIT_TUNNEL_EXTRA_DOMAINS", [])
    SPLIT_TUNNEL_EXTRA_IPS = getattr(core, "SPLIT_TUNNEL_EXTRA_IPS", [])
    AWG_EXIT_ENABLED = getattr(core, "AWG_EXIT_ENABLED", False)
    AWG_EXIT_HOST = getattr(core, "AWG_EXIT_HOST", "")
    H2_EXIT_ENABLED = getattr(core, "H2_EXIT_ENABLED", False)
    CHAIN_NODES = getattr(core, "CHAIN_NODES", [])
    CHAIN_BALANCER_STRATEGY = getattr(core, "CHAIN_BALANCER_STRATEGY", "roundRobin")
    CHAIN_PINNED_NODE_INDEX = getattr(core, "CHAIN_PINNED_NODE_INDEX", -1)

    # Загружаем state
    if not STATE_FILE.exists():
        warn("state.json не найден. Сначала выполните установку (пункт 1).")
        return

    try:
        state = json.loads(STATE_FILE.read_text())
        INSTALL_MODE      = state.get("install_mode",  "A")
        setattr(core, "INSTALL_MODE", INSTALL_MODE)
        PARAM_DOMAIN      = (state.get("domain",        PARAM_DOMAIN) or "").lower()  # DNS case-insensitive
        setattr(core, "PARAM_DOMAIN", PARAM_DOMAIN)
        PARAM_UUID        = state.get("uuid",          PARAM_UUID)
        setattr(core, "PARAM_UUID", PARAM_UUID)
        PARAM_PUBLIC_KEY  = state.get("public_key",    PARAM_PUBLIC_KEY)
        setattr(core, "PARAM_PUBLIC_KEY", PARAM_PUBLIC_KEY)
        PARAM_SHORTID     = state.get("short_id",      PARAM_SHORTID)
        setattr(core, "PARAM_SHORTID", PARAM_SHORTID)
        PARAM_PRIVATE_KEY = state.get("private_key",   PARAM_PRIVATE_KEY)
        setattr(core, "PARAM_PRIVATE_KEY", PARAM_PRIVATE_KEY)
        PARAM_SOCKET_PATH = state.get("socket",        PARAM_SOCKET_PATH)
        setattr(core, "PARAM_SOCKET_PATH", PARAM_SOCKET_PATH)
        PARAM_SPIDERX     = state.get("spiderx",       PARAM_SPIDERX)
        setattr(core, "PARAM_SPIDERX", PARAM_SPIDERX)
        # Критично для пересборки конфига: без этих переменных generate_xray_config_chain_entry_multi()
        # использует глобальные дефолты ("reality", 443, "") и собирает неверный конфиг.
        PROTOCOL_MODE     = state.get("protocol_mode", PROTOCOL_MODE)
        setattr(core, "PROTOCOL_MODE", PROTOCOL_MODE)
        SERVER_PORT       = state.get("server_port",   SERVER_PORT)
        setattr(core, "SERVER_PORT", SERVER_PORT)
        XHTTP_PORT        = SERVER_PORT
        setattr(core, "XHTTP_PORT", XHTTP_PORT)
        XHTTP_MODE        = state.get("xhttp_mode",   XHTTP_MODE)
        setattr(core, "XHTTP_MODE", XHTTP_MODE)
        XHTTP_PATH        = state.get("xhttp_path",   XHTTP_PATH)
        setattr(core, "XHTTP_PATH", XHTTP_PATH)
        XHTTP_PERF_PRESET = state.get("xhttp_perf_preset", XHTTP_PERF_PRESET)
        setattr(core, "XHTTP_PERF_PRESET", XHTTP_PERF_PRESET)
        CHAIN_NODES = _nodes_from_state(state)
        setattr(core, "CHAIN_NODES", CHAIN_NODES)
        CHAIN_LB_NODES = state.get("chain_lb_nodes") or []
        setattr(core, "CHAIN_LB_NODES", CHAIN_LB_NODES)
        CHAIN_BALANCER_STRATEGY = state.get("chain_balancer_strategy", CHAIN_BALANCER_STRATEGY)
        setattr(core, "CHAIN_BALANCER_STRATEGY", CHAIN_BALANCER_STRATEGY)
        CHAIN_PINNED_NODE_INDEX = state.get("chain_pinned_node_index", -1)
        setattr(core, "CHAIN_PINNED_NODE_INDEX", CHAIN_PINNED_NODE_INDEX)
        AWG_EXIT_ENABLED  = state.get("awg_exit_enabled", False)
        setattr(core, "AWG_EXIT_ENABLED", AWG_EXIT_ENABLED)
        H2_EXIT_ENABLED   = state.get("h2_exit_enabled",  False)
        # NB: H2_EXIT_ENABLED was NOT in the original `global` declaration —
        # preserving original (local-only) behaviour: no setattr to core.
        PARAM_REALITY_DEST = state.get("reality_dest",    PARAM_REALITY_DEST)
        setattr(core, "PARAM_REALITY_DEST", PARAM_REALITY_DEST)
    except Exception as e:
        warn(f"Не удалось прочитать state.json: {e}")
        return

    # Загружаем настройки split tunnel — они должны сохраняться при любых
    # операциях с нодами (добавление, удаление, пересборка конфига).
    _load_split_tunnel_custom()

    # BUGFIX: определяем поддержку "mode" для установленной версии Xray.
    # Без этого вызова XHTTP_MODE_SUPPORTED остаётся False (дефолт),
    # и "mode": "stream-up" не пишется в конфиг — или пишется неверно.
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
        # Состав балансировки (lb-выбор, как в AWG/Mieru каскадах)
        _lb_sel_local = getattr(core, "CHAIN_LB_NODES", None)
        if _lb_sel_local is None:
            _lb_sel_local = state.get("chain_lb_nodes") or []
        _lb_label = _lb_nodes_summary(CHAIN_NODES, _lb_sel_local)

        print(f"  {DIM}Стратегия исходящих (domainStrategy):{NC} {CYAN}{_ds_label}{NC}")
        if len(CHAIN_NODES) >= 2:
            print(f"  {DIM}Стратегия балансировки:{NC}                {CYAN}{_bal_label}{NC}")
            print(f"  {DIM}Состав балансировки:{NC}                   {CYAN}{_lb_label}{NC}")
        print()
        # ────────────────────────────────────────────────────────────────────────

        if not CHAIN_NODES:
            print(f"  {YELLOW}Нод пока нет.{NC}")
        else:
            print(f"  Текущие exit-ноды ({len(CHAIN_NODES)}/{MAX_CHAIN_NODES}):")
            for i, nd in enumerate(CHAIN_NODES):
                _via = nd.get("via", "") or ""
                _via_s = f"  {DIM}via:{_via}{NC}" if _via else ""
                print(f"    {CYAN}[{i+1}]{NC} {nd['host']}:{nd['port']}  "
                      f"SNI={nd['sni']}  FP={nd['fp']}{_via_s}")
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
                _box_item("E", f"Состав нод балансировки  [{_lb_label}]")
        _box_item("O", f"Изменить стратегию исходящих соединений  [{_ds_label}]")
        _box_item("N", f"Доп. клиент для резервной Entry-ноды  {DIM}(на уже развёрнутый exit){NC}")
        try:
            from chimera.modules.chain_relay import load_relay_hops as _cr_lh
            _cr_n = len(_cr_lh())
        except Exception:
            _cr_n = 0
        _cr_lbl = f"  [{_cr_n} хоп(ов)]" if _cr_n else ""
        _box_item("H", f"⛓ Релейные хопы (многохоповый каскад){_cr_lbl}")
        _box_item_exit("0", f"Назад в главное меню")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            print()
            break

        if ch == "0" or ch == "":
            break

        elif ch == "h":
            # Chain Relay: релейные хопы (многохоповый каскад, dialerProxy)
            try:
                from chimera.modules.chain_relay import do_chain_relay_menu
                do_chain_relay_menu()
            except Exception as _cr_ex:
                warn(f"Chain Relay: {_cr_ex}")
            # relay-меню могло изменить chain_nodes/via в state.json —
            # перечитываем, чтобы список нод выше был актуальным
            try:
                _st = json.loads(STATE_FILE.read_text())
                CHAIN_NODES = _nodes_from_state(_st)
                setattr(core, "CHAIN_NODES", CHAIN_NODES)
            except Exception:
                pass
            continue

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
            # Гигиена LB-состава: удалённый хост выбывает из выбора;
            # если валидных осталось <2 — состав сбрасывается на «все»
            _lb_after = [
                h for h in (state.get("chain_lb_nodes") or [])
                if h.strip().lower() != (removed.get("host") or "").strip().lower()
            ]
            if len(_lb_after) < 2:
                _lb_after = []
            state["chain_lb_nodes"] = _lb_after
            setattr(core, "CHAIN_LB_NODES", _lb_after)
            try:
                _st_hd = json.loads(STATE_FILE.read_text())
                _st_hd["chain_lb_nodes"] = _lb_after
                STATE_FILE.write_text(json.dumps(_st_hd, indent=2, ensure_ascii=False))
            except Exception:
                pass
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
                    # Используем _resolve_host_fresh (DoH + fallback) вместо
                    # socket.gethostbyname — чтобы флаг страны определялся по
                    # АКТУАЛЬНОМУ IP ноды, а не по устаревшей кэш-записи.
                    ip = _resolve_host_fresh(host)
                    if ip:
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
                setattr(core, "CHAIN_PINNED_NODE_INDEX", CHAIN_PINNED_NODE_INDEX)
                info("Pinned-режим отключён. Активен балансировщик.")
            elif v.isdigit() and 1 <= int(v) <= len(CHAIN_NODES):
                CHAIN_PINNED_NODE_INDEX = int(v) - 1
                setattr(core, "CHAIN_PINNED_NODE_INDEX", CHAIN_PINNED_NODE_INDEX)
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
                setattr(core, "CHAIN_BALANCER_STRATEGY", CHAIN_BALANCER_STRATEGY)
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

        elif ch == "e" and len(CHAIN_NODES) >= 2:
            # ── Состав нод балансировки (lb-выбор, как AWG/Mieru) ───────────
            print()
            print()
            _box_top(f"Состав нод балансировки")
            _box_row(f"  {DIM}Выберите ноды, между которыми балансируется трафик.{NC}")
            _box_row(f"  {DIM}Ноды вне состава не выбрасываются из каскада — просто{NC}")
            _box_row(f"  {DIM}выпадают из ротации (проблемный хостер/steal/гео).{NC}")
            _box_sep()
            _cur_sel = set(_lb_sel_local)
            for i, nd in enumerate(CHAIN_NODES):
                marker = f"  {GREEN}◀ в составе{NC}" \
                    if (nd.get("host") or "").lower() in _cur_sel else ""
                _box_item(f"{i+1}", f"{nd['host']}:{nd['port']}  SNI={nd['sni']}{marker}")
            _box_sep()
            _box_row(f"  {DIM}Текущий состав: {CYAN}{_lb_label}{NC}")
            _box_row(f"  {DIM}Закрепление [P] имеет приоритет и работает вне состава.{NC}")
            _box_bottom()
            v = input(f"  {CYAN}Номера через запятую/пробел [Enter = все]:{NC} ").strip()
            if not v:
                _new_sel: list = []
            else:
                _idxs = []
                for tok in re.split(r"[,\s]+", v):
                    if tok.isdigit() and 1 <= int(tok) <= len(CHAIN_NODES):
                        _idxs.append(int(tok) - 1)
                _new_sel = [CHAIN_NODES[i]["host"] for i in sorted(set(_idxs))]
            _norm = _normalize_lb_nodes(_new_sel, CHAIN_NODES)
            if _new_sel and len(_norm) < 2:
                warn("В выборе меньше 2 известных нод — отклонено "
                     "(молчаливая одиночная нода запрещена).")
                time.sleep(2)
                continue
            # Пишем state (и dual-form глобаль)
            try:
                _st_lb = json.loads(STATE_FILE.read_text())
                _st_lb["chain_lb_nodes"] = _norm
                STATE_FILE.write_text(json.dumps(_st_lb, indent=2, ensure_ascii=False))
                setattr(core, "CHAIN_LB_NODES", _norm)
                _lb_sel_local = _norm
            except Exception as _lb_ex:
                warn(f"Не удалось сохранить состав: {_lb_ex}")
                time.sleep(2)
                continue
            success(f"Состав балансировки: {_lb_nodes_summary(CHAIN_NODES, _norm)}")
            if len(CHAIN_NODES) >= 2:
                ans = input(f"{YELLOW}Пересобрать конфиг Xray и перезапустить сейчас? [y/N]:{NC} ").strip().lower()
                if ans == 'y':
                    _rebuild_and_restart_xray("Xray активен — состав балансировки применён")
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
                setattr(core, "PARAM_DOMAIN_STRATEGY", PARAM_DOMAIN_STRATEGY)
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
                    # (start-limit-fix): безопасный рестарт — см.
                    # _core._xray_safe_restart (StartLimitBurst=3/60s)
                    _safe_restart = getattr(core, "_xray_safe_restart", None)
                    if callable(_safe_restart) and _safe_restart():
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
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    _box_sep = core._box_sep
    _box_link = core._box_link
    _run = core._run
    _get_box_width = core._get_box_width
    _show_qr = core._show_qr
    get_server_country_cached = core.get_server_country_cached
    _fp_from_state = core._fp_from_state
    success = core.success
    GREEN = core.GREEN
    RED = core.RED
    CYAN = core.CYAN
    YELLOW = core.YELLOW
    BOLD = core.BOLD
    DIM = core.DIM
    MAGENTA = core.MAGENTA
    NC = core.NC
    _BOX_W = getattr(core, "_BOX_W", 78)
    AWG_EXIT_ENABLED = getattr(core, "AWG_EXIT_ENABLED", False)
    INSTALL_MODE = getattr(core, "INSTALL_MODE", "A")
    PARAM_DOMAIN = getattr(core, "PARAM_DOMAIN", "")
    SERVER_IP = getattr(core, "SERVER_IP", "")
    SERVER_PORT = getattr(core, "SERVER_PORT", 443)
    AWG_EXIT_HOST = getattr(core, "AWG_EXIT_HOST", "")
    AWG_EXIT_PORT = getattr(core, "AWG_EXIT_PORT", 51820)
    AWG_INTERFACE = getattr(core, "AWG_INTERFACE", "awg0")
    AWG_SUBNET = getattr(core, "AWG_SUBNET", "10.66.66.0/24")
    AWG_SUBNET_V6 = getattr(core, "AWG_SUBNET_V6", "fd66:66:66::/64")
    AWG_FWMARK = getattr(core, "AWG_FWMARK", 1000)
    AWG_ROUTE_TABLE = getattr(core, "AWG_ROUTE_TABLE", 1000)
    CHAIN_NODES = getattr(core, "CHAIN_NODES", [])
    CHAIN_EXIT_HOST = getattr(core, "CHAIN_EXIT_HOST", "")
    CHAIN_EXIT_PORT = getattr(core, "CHAIN_EXIT_PORT", 443)
    CHAIN_EXIT_UUID = getattr(core, "CHAIN_EXIT_UUID", "")
    CHAIN_EXIT_PUBKEY = getattr(core, "CHAIN_EXIT_PUBKEY", "")
    CHAIN_EXIT_SHORTID = getattr(core, "CHAIN_EXIT_SHORTID", "")
    CHAIN_EXIT_SNI = getattr(core, "CHAIN_EXIT_SNI", "")
    CHAIN_EXIT_FP = getattr(core, "CHAIN_EXIT_FP", "chrome")
    CHAIN_BALANCER_STRATEGY = getattr(core, "CHAIN_BALANCER_STRATEGY", "roundRobin")
    PROTOCOL_MODE = getattr(core, "PROTOCOL_MODE", "reality")
    XHTTP_MODE = getattr(core, "XHTTP_MODE", "stream-up")
    XHTTP_PATH = getattr(core, "XHTTP_PATH", "/")
    PARAM_UUID = getattr(core, "PARAM_UUID", "")
    PARAM_PUBLIC_KEY = getattr(core, "PARAM_PUBLIC_KEY", "")
    PARAM_SHORTID = getattr(core, "PARAM_SHORTID", "")
    PARAM_REALITY_DEST = getattr(core, "PARAM_REALITY_DEST", "")
    PARAM_FINGERPRINT = getattr(core, "PARAM_FINGERPRINT", "chrome")
    _BOX_W = _get_box_width()
    setattr(core, "_BOX_W", _BOX_W)

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

    # ── BUGFIX (v5): загружаем АКТУАЛЬНЫЙ список юзеров через
    #    _unified_load_users(), а не глобальный PARAM_UUID. Раньше
    #    использовался PARAM_UUID — это UUID НАЧАЛЬНОГО юзера, который
    #    оставался устаревшим после удаления этого юзера через TUI
    #    2 → 1 → D. В результате "Клиентская ссылка (Entry Node)" в
    #    Mode B показывала UUID, которого больше нет в clients[] →
    #    "invalid request user id" в клиентах.
    #
    #    Теперь: показываем ссылки для ВСЕХ активных юзеров. Если юзеров
    #    нет — fallback на PARAM_UUID (для emergency_repair/fresh install).
    try:
        from chimera.modules.users_manager import _unified_load_users
        all_users = _unified_load_users()
        active_users = [u for u in all_users
                        if u.get("uuid") and not u.get("disabled")
                        and not u.get("is_ios_shadow")]
    except Exception:
        active_users = []
    if not active_users and PARAM_UUID:
        # Fallback — PARAM_UUID (старое поведение).
        active_users = [{"uuid": PARAM_UUID,
                         "email": getattr(core, "PARAM_USER_EMAIL", "") or "default",
                         "name": getattr(core, "PARAM_USER_NAME", "") or "default"}]

    # Клиентская ссылка — подключаться к entry (российскому) VPS
    import urllib.parse as _uparse
    _, _, _chain_flag = get_server_country_cached()
    _chain_flag_prefix = f"{_chain_flag} " if _chain_flag and _chain_flag != "🌐" else ""
    proto = PROTOCOL_MODE

    # ── Строим ссылки для каждого активного юзера ───────────────────
    # Раньше была ОДНА ссылка на PARAM_UUID. Теперь — список ссылок,
    # по одной на каждого активного юзера. Берём первую для записи в
    # /root/vless_link.txt (для обратной совместимости с инструкцией),
    # но показываем все в боксе.
    def _build_entry_link(user_uuid: str, label: str = "") -> str:
        _chain_label = _chain_flag_prefix + _uparse.quote(
            label or f"{PARAM_DOMAIN}-chain"
        )
        if proto == "xhttp":
            _path_enc = _uparse.quote(XHTTP_PATH, safe="/")
            _cs_fp = PARAM_FINGERPRINT or _fp_from_state()
            return (
                f"vless://{user_uuid}@{entry_host}:{SERVER_PORT}"
                f"?type=xhttp&security=tls&sni={PARAM_DOMAIN}"
                f"&path={_path_enc}&mode={XHTTP_MODE}"
                f"&fp={_cs_fp}#{_chain_label}"
            )
        else:
            _reality_sni = PARAM_REALITY_DEST if AWG_EXIT_ENABLED else PARAM_DOMAIN
            _cs_fp = PARAM_FINGERPRINT or _fp_from_state()
            return (
                f"vless://{user_uuid}@{entry_host}:{SERVER_PORT}"
                f"?type=tcp&security=reality&pbk={PARAM_PUBLIC_KEY}"
                f"&fp={_cs_fp}&sni={_reality_sni}&sid={PARAM_SHORTID}"
                f"&flow=xtls-rprx-vision#{_chain_label}"
            )

    # Первая ссылка — для записи в файлы (обратная совместимость).
    first_user = active_users[0] if active_users else {"uuid": PARAM_UUID, "email": "default"}
    link = _build_entry_link(first_user.get("uuid", PARAM_UUID), f"{PARAM_DOMAIN}-chain")

    # Определяем метку стратегии ДО цикла — она нужна внутри него
    strategy_labels = {
        "roundRobin": "Round Robin",
        "leastPing":  "Least Ping",
        "leastLoad":  "Least Load",
        "random":     "Random",
    }
    strategy_label = strategy_labels.get(CHAIN_BALANCER_STRATEGY, CHAIN_BALANCER_STRATEGY)

    # Состав балансировки (lb-выбор): подпись в сводке при мульти-ноде
    _lb_sel_sum = _lb_selection_from_state(core)
    if len(nodes) > 1:
        _lb_sum_txt = _lb_nodes_summary(nodes, _lb_sel_sum)
        strategy_label = f"{strategy_label} · состав: {_lb_sum_txt}"

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
xHTTP mode: {nd.get('xhttp_mode', 'stream-up')}
xHTTP path: {nd.get('path', '/')}
SNI:        {nd.get('sni', '')}
FP:         {nd.get('fp', 'chrome')}
"""
        elif nd_proto == "xhttp_reality":
            # xHTTP+REALITY: и REALITY-ключи, и параметры транспорта;
            # Flow НЕТ — xHTTP-транспорт без xtls-rprx-vision
            nodes_text += f"""
## ─── Exit Node #{i+1} ({lbl}, xHTTP + REALITY) ──
Адрес:      {nd['host']}
Порт:       {nd['port']}
UUID:       {nd['uuid']}
PublicKey:  {nd.get('pubkey', '')}
ShortID:    {nd.get('shortid', '')}
xHTTP mode: {nd.get('xhttp_mode', 'stream-up')}
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
PublicKey:  {PARAM_PUBLIC_KEY if proto in ('reality', 'xhttp_reality') else 'n/a (xHTTP TLS)'}
ShortID:    {PARAM_SHORTID if proto in ('reality', 'xhttp_reality') else 'n/a (xHTTP TLS)'}
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
    if len(active_users) > 1:
        print(f"  {MAGENTA}Клиентские ссылки (Entry Node) — {len(active_users)} юзеров:{NC}")
    else:
        print(f"  {MAGENTA}Клиентская ссылка (Entry Node):{NC}")
    _box_link(link)
    # Если юзеров больше одного — показываем остальные ссылки тоже.
    if len(active_users) > 1:
        for u in active_users[1:]:
            _u_label = u.get("email", u.get("name", u.get("uuid", "?")[:8]))
            _u_link = _build_entry_link(u.get("uuid", ""), f"{PARAM_DOMAIN}-chain · {_u_label}")
            print(f"  {DIM}─── {_u_label} ───{NC}")
            _box_link(_u_link)
    print()
    from chimera.modules.box_renderer import _print_link_warning
    _print_link_warning(is_vless=True)
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
#  СКОРОСТНЫЕ ТЕСТЫ — latency/geo для exit-нод
# =============================================================================
def _validate_chain_node_host(host: str) -> "tuple[bool, str, Optional[str]]":
    """Валидирует host exit-ноды перед сохранением в CHAIN_NODES.

    Проверки:
      1. Не пустой.
      2. Если это домен (не IP) — проверяет что он резолвится.
      3. Если домен резолвится в IP текущего сервера (self-reference) — ошибка.
      4. Если домен выглядит как reverse-DNS hostname текущего сервера
         (содержит часть IP-адреса сервера в имени) — предупреждение.

    Returns:
      (is_valid, message, resolved_ip)
      - is_valid=True если host прошёл валидацию (или это IP-литерал)
      - message: описание результата для пользователя
      - resolved_ip: IP-адрес в который резолвится host (или сам host если это IP)
    """
    import socket
    import ipaddress

    if not host:
        return False, "Host не указан", None

    # 1. Проверяем — это уже IP-адрес?
    try:
        ipaddress.ip_address(host)
        # Это валидный IP-литерал — пропускаем дальнейшие проверки.
        return True, f"IP-адрес: {host}", host
    except ValueError:
        pass

    # 2. Это домен — проверяем что резолвится.
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        return False, f"Домен '{host}' не резолвится: {e}", None

    if not infos:
        return False, f"Домен '{host}' не отдал IP-адресов", None

    # Берём первый IPv4.
    resolved_ip = None
    for family, _, _, _, sockaddr in infos:
        if family == socket.AF_INET:
            resolved_ip = sockaddr[0]
            break

    if not resolved_ip:
        return False, f"Домен '{host}' не имеет IPv4-адреса", None

    # 3. Проверка на self-reference — не резолвится ли в IP текущего сервера.
    try:
        core = _core_module()
        # Публичный IP текущего сервера (через ip addr или state).
        local_ip = None
        try:
            r = core._run(["ip", "-4", "addr", "show", "scope", "global"],
                          capture=True, check=False)
            import re as _re
            addrs = _re.findall(r'inet\s+(\d+\.\d+\.\d+\.\d+)', r.stdout)
            # Берём первый публичный IP.
            for a in addrs:
                try:
                    ip_obj = ipaddress.ip_address(a)
                    if not ip_obj.is_private and not ip_obj.is_loopback:
                        local_ip = a
                        break
                except ValueError:
                    continue
        except Exception:
            pass

        # Внешний IP через echo-сервис (для NAT-серверов).
        external_ip = None
        try:
            r = core._run(["curl", "-s", "--max-time", "3", "https://api.ipify.org"],
                          capture=True, check=False, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                external_ip = r.stdout.strip()
        except Exception:
            pass

        # Если домен резолвится в IP текущего сервера — это явно ошибка.
        # Пользователь прописал домен текущего сервера как exit-ноду.
        if local_ip and resolved_ip == local_ip:
            return False, (
                f"Домен '{host}' резолвится в {resolved_ip} — это IP текущего сервера! "
                f"Exit-нода не может быть самим собой. Укажите IP зарубежного VPS."
            ), resolved_ip

        if external_ip and resolved_ip == external_ip:
            return False, (
                f"Домен '{host}' резолвится в {resolved_ip} — это публичный IP текущего сервера (NAT)! "
                f"Exit-нода не может быть самим собой. Укажите IP зарубежного VPS."
            ), resolved_ip

        # 4. Проверка на reverse-DNS — если домен содержит IP-сегменты
        # текущего сервера (например '203.0.113.110.provider.example' или
        # '203.0.113.111.provider.example' где RU-сервер имеет hostname
        # '203-0-113-110.provider.example') — это подозрительно.
        server_hostname = ""
        try:
            r = core._run(["hostname", "-f"], capture=True, check=False)
            server_hostname = r.stdout.strip()
        except Exception:
            pass

        if server_hostname and external_ip:
            # Извлекаем доменную часть из hostname (например 'provider.example').
            hostname_parts = server_hostname.split(".", 1)
            if len(hostname_parts) == 2:
                hostname_domain = hostname_parts[1]
                # Если домен exit-ноды заканчивается на ту же доменную часть
                # что и hostname текущего сервера — это reverse-DNS от
                # текущего сервера или его провайдера.
                if host.endswith("." + hostname_domain):
                    # Дополнительная проверка: содержит ли домен IP-сегменты?
                    # Например '203.0.113.111.provider.example' — reverse-DNS.
                    import re as _re
                    if _re.search(r'\d+\.\d+\.\d+\.\d+', host):
                        return False, (
                            f"Домен '{host}' похож на reverse-DNS hostname (домен "
                            f"'{hostname_domain}' совпадает с hostname сервера). "
                            f"Резолвится в {resolved_ip} — это не похоже на exit-ноду. "
                            f"Укажите IP зарубежного VPS напрямую (например 203.0.113.20)."
                        ), resolved_ip

    except Exception:
        # Ошибка валидации не должна блокировать сохранение — возвращаем success.
        pass

    return True, f"Домен '{host}' резолвится в {resolved_ip}", resolved_ip


def _resolve_host_fresh(host: str, timeout: int = 3) -> Optional[str]:
    """
    Резолв hostname → IPv4 через публичные DoH-резолверы (Cloudflare 1.1.1.1
    и Google 8.8.8.8), минуя локальный DNS-кэш сервера
    (systemd-resolved / dnsmasq / nscd / /etc/hosts).

    Зачем это нужно:
      При диагностике exit-нод (SpeedTest, «полная диагностика одной кнопкой»)
      системный резолвер socket.gethostbyname() может отдать УСТАРЕВШИЙ IP-адрес
      домена — например, если:
        • на сервере ранее был прописан /etc/hosts или dnsmasq entry со старым IP;
        • systemd-resolved/nscd кэшировал A-record с большим TTL и не успел
          его сбросить после смены A-записи в DNS-провайдере;
        • используется локальный forwarder, который отдаёт устаревший кэш.

      В результате диагностика стучится на СТАРЫЙ IP-адрес ноды, хотя реальный
      клиент (xray/sing-box) может использовать свой resolver и идти на НОВЫЙ IP.
      DoH-запрос идёт напрямую к авторитетному рекурсиву (Cloudflare/Google),
      минуя любой локальный кэш.

    Порядок:
      1. Если host — уже валидный IPv4, вернуть как есть.
      2. DoH через Cloudflare (1.1.1.1) — JSON API /dns-query.
      3. DoH через Google (8.8.8.8) — JSON API /resolve.
      4. Fallback: socket.gethostbyname() (системный резолвер).
      5. Если всё упало — None.
    """
    # 1) Уже IPv4-адрес — отдаём как есть.
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass

    core = _core_module()
    _run = core._run

    # 2)–3) DoH-провайдеры (Cloudflare + Google JSON API).
    #    Cloudflare/Quad9: /dns-query + заголовок Accept: application/dns-json
    #    Google: /resolve без Accept-заголовка
    doh_endpoints = [
        (f"https://1.1.1.1/dns-query?name={host}&type=A",
         "Accept: application/dns-json"),
        (f"https://8.8.8.8/resolve?name={host}&type=A",
         None),
    ]

    for url, header in doh_endpoints:
        try:
            cmd = ["curl", "-s", "--max-time", str(timeout)]
            if header:
                cmd += ["-H", header]
            cmd.append(url)
            r = _run(cmd, capture=True, check=False)
            if r.returncode != 0 or not r.stdout.strip():
                continue
            data = json.loads(r.stdout.strip())
            # Status==0 → NOERROR (и у Cloudflare, и у Google).
            if data.get("Status", 0) != 0:
                continue
            for ans in data.get("Answer", []):
                if ans.get("type") == 1:  # A record
                    ip = ans.get("data", "")
                    try:
                        socket.inet_aton(ip)
                        return ip
                    except OSError:
                        continue
        except Exception:
            continue

    # 4) Fallback: системный резолвер (лучше старый IP, чем никакой).
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def _speed_test_node_latency(host: str, port: int) -> str:
    """
    Измеряет TCP-латентность до хоста через прямое подключение (socket).
    Резолв домена выполняется через _resolve_host_fresh (DoH + fallback),
    чтобы не ловить устаревший IP из локального DNS-кэша.
    Возвращает строку с результатом.
    """
    core = _core_module()
    GREEN = core.GREEN
    RED = core.RED
    NC = core.NC
    try:
        start = time.time()
        ip = _resolve_host_fresh(host)
        if not ip:
            return f"{RED}ошибка (DNS: не удалось резолвить {host}){NC}"
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
    Резолв домена выполняется через _resolve_host_fresh (DoH + fallback),
    чтобы GeoIP определялся по АКТУАЛЬНОМУ IP, а не по устаревшей кэш-записи.
    """
    core = _core_module()
    _run = core._run
    try:
        ip = _resolve_host_fresh(host)
        if not ip:
            return host, "??", "неизвестно", "?", "?"
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
    core = _core_module()
    DIAG_ACCESS_LOG = getattr(core, "DIAG_ACCESS_LOG", Path("/var/log/xray/access.log"))
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
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    _box_sep = core._box_sep
    _box_info = core._box_info
    _box_warn = core._box_warn
    _run = core._run
    _wcslen = core._wcslen
    BOLD = core.BOLD
    CYAN = core.CYAN
    YELLOW = core.YELLOW
    GREEN = core.GREEN
    RED = core.RED
    DIM = core.DIM
    BLUE = core.BLUE
    NC = core.NC
    STATE_FILE = getattr(core, "STATE_FILE", None)
    AWG_FWMARK = getattr(core, "AWG_FWMARK", 1000)
    _BOX_W = getattr(core, "_BOX_W", 78)

    os.system("clear")
    print()
    _box_top("🗺️   МАТРИЦА СОСТОЯНИЯ EXIT-НОД")
    _box_row(f"  {DIM}Проверяет все ноды каскада параллельно и выводит сводную таблицу.{NC}")
    _box_row()

    # ── Загрузка нод из state ────────────────────────────────────────────────
    nodes: list[dict] = []
    pinned_idx  = -1
    install_mode = "A"
    lb_selection: list = []
    try:
        if STATE_FILE.exists():
            st = json.loads(STATE_FILE.read_text())
            nodes        = st.get("chain_nodes", [])
            pinned_idx   = st.get("chain_pinned_node_index", -1)
            install_mode = st.get("install_mode", "A")
            lb_selection = st.get("chain_lb_nodes") or []
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
    if len(nodes) >= 2:
        _box_row(f"  Состав балансировки: {CYAN}"
                 f"{_lb_nodes_summary(nodes, lb_selection)}{NC}")
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
            # DoH + fallback — чтобы пинговать АКТУАЛЬНЫЙ IP ноды, а не старый
            # кэшированный адрес. См. _resolve_host_fresh().
            ip = _resolve_host_fresh(host)
            if not ip:
                return -1, f"{RED}▼ DNS fail{NC}"
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
        # LB-состав: нода вне состава (и не pinned) — вне ротации
        _lb_sel_m = set(lb_selection or [])
        _in_lb = (not _lb_sel_m or
                  (nd.get("host") or "").strip().lower() in _lb_sel_m or
                  is_pinned)
        if is_dead:
            dead_count += 1
            role_str = f"{RED}dead{NC}"
        elif is_pinned:
            role_str = f"{CYAN}pinned{NC}"
        elif not _in_lb:
            role_str = f"{YELLOW}вне состава{NC}"
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
#  LB-СОСТАВ (выбор нод для балансировки — зеркало lb_exits AWG/Mieru)
# =============================================================================
# Режим B, мульти-нода: нативный balancer Xray-coreSelector по умолчанию
# включает ВСЕ exit-ноды. Как и в AWG/Mieru-каскадах, это вредит, когда
# проблемная нода (steal/деградация) остаётся в ротации «просто потому,
# что добавлена». state['chain_lb_nodes'] — список хостов выбранных нод;
# пусто/None = все (обратная совместимость), <2 валидных = фолбэк на все
# (молчаливая одиночная нода запрещена). Пиннинг (P) ортогонален составу:
# закреплённая нода работает даже вне состава (явный override юзера).

_CHAIN_STATE_FILE = Path("/var/lib/xray-installer/state.json")
_CHAIN_CONFIG_FILE = Path("/etc/xray/config.json")


def _lb_node_host(nd: dict) -> str:
    """Ключ ноды для выбора состава: host (нормализованный, lower)."""
    return (nd.get("host") or "").strip().lower()


def _normalize_lb_nodes(selection: Optional[list],
                        chain_nodes_list: list) -> list:
    """Хосты выбранных нод: уникальные, известные, в порядке
    chain_nodes_list (индексы не «прыгают» при другом порядке ввода).
    None/пусто → [] (= все). Чистая функция (тестируется без сервера)."""
    if not selection:
        return []
    known = {_lb_node_host(nd) for nd in chain_nodes_list
             if (nd.get("host") or "").strip()}
    wanted: list = []
    for x in selection:
        h = (x or "").strip().lower()
        if h and h in known and h not in wanted:
            wanted.append(h)
    return [_lb_node_host(nd) for nd in chain_nodes_list
            if _lb_node_host(nd) in set(wanted)]


def _lb_effective_nodes(chain_nodes_list: list,
                        selection: Optional[list]) -> list:
    """Ноды, участвующие в балансировке (выбор пары/подмножества).

    Пустой выбор = все; неизвестные хосты отбрасываются; валидных <2 —
    фолбэк на ВСЕ ноды. Чистая функция."""
    if not selection:
        return list(chain_nodes_list)
    sel = set(_normalize_lb_nodes(selection, chain_nodes_list))
    if not sel:
        return list(chain_nodes_list)
    eff = [nd for nd in chain_nodes_list if _lb_node_host(nd) in sel]
    if len(eff) < 2:
        return list(chain_nodes_list)
    return eff


def _lb_selector_tags(outbound_tags: list, chain_nodes_list: list,
                      selection: Optional[list]) -> list:
    """Теги outbound'ов для balancer.selector / observatory.subjectSelector —
    только выбранные ноды (порядок outbound_tags сохраняется).
    Чистая функция."""
    eff = _lb_effective_nodes(chain_nodes_list, selection)
    if len(eff) == len(chain_nodes_list):
        return list(outbound_tags)
    eff_hosts = {_lb_node_host(nd) for nd in eff}
    return [tag for tag, nd in zip(outbound_tags, chain_nodes_list)
            if _lb_node_host(nd) in eff_hosts]


def _lb_nodes_summary(chain_nodes_list: list,
                      selection: Optional[list]) -> str:
    """Человекочитаемый состав: 'host1, host2 (2 из 4)' / 'все (4)'.
    Чистая функция."""
    total = len(chain_nodes_list)
    if not selection:
        return f"все ({total})" if total else "—"
    eff = _lb_effective_nodes(chain_nodes_list, selection)
    if len(eff) == total:
        return f"все ({total})"
    return ", ".join((nd.get("host") or "?") for nd in eff) + \
           f" ({len(eff)} из {total})"


def _lb_selection_from_state(core=None) -> list:
    """Читает выбор состава: core-глобаль CHAIN_LB_NODES (dual form),
    затем state.json ['chain_lb_nodes']. Пусто = все."""
    sel = []
    if core is not None:
        sel = getattr(core, "CHAIN_LB_NODES", None) or []
    if not sel:
        try:
            stf = getattr(core, "STATE_FILE", None) if core is not None \
                else None
            if stf is None:
                stf = _CHAIN_STATE_FILE
            stf = Path(stf)
            if stf.exists():
                sel = json.loads(stf.read_text()).get(
                    "chain_lb_nodes") or []
        except Exception:
            sel = []
    return sel if isinstance(sel, list) else []


def set_lb_nodes(hosts: Optional[list], restart: bool = True) -> bool:
    """API: задать состав нод балансировки VLESS-каскада (Режим B).

    hosts — список хостов (или метки-хосты в любом регистре);
    None/[] = все ноды. Пишет state.json ['chain_lb_nodes'], хирургически
    патчит selector цепочного balancer'а (+ observatory.subjectSelector)
    в живом /etc/xray/config.json и перезапускает xray (graceful-путь
    smart_balancer'а: reset-failed → restart → nginx restart).
    Работает headless (SSH/скрипты) — ядро chimera._core не требуется.
    False — отклонено (в выборе <2 известных хостов) или сбой патча.
    """
    try:
        state = json.loads(_CHAIN_STATE_FILE.read_text())
    except Exception:
        state = {}
    nodes = state.get("chain_nodes") or []
    if len(nodes) < 2:
        print("set_lb_nodes: нод в каскаде <2 — состав не нужен")
        return False
    sel = _normalize_lb_nodes(hosts, nodes)
    if hosts and len(sel) < 2:
        print("set_lb_nodes: в выборе <2 известных хостов — отклонено")
        return False
    state["chain_lb_nodes"] = sel
    try:
        _CHAIN_STATE_FILE.write_text(
            json.dumps(state, indent=2, ensure_ascii=False))
    except Exception as ex:
        print(f"set_lb_nodes: не удалось записать state.json: {ex}")
        return False
    print("состав LB: " + _lb_nodes_summary(nodes, sel))

    # ── Хирургический патч живого конфига (без полной пересборки) ─────────
    try:
        cfg = json.loads(_CHAIN_CONFIG_FILE.read_text())
        balancers = (cfg.get("routing") or {}).get("balancers") or []
        patched = False
        sel_set = set(sel)
        # Селектор строим ЗАНОВО из state (источник истины): теги по
        # ПОЗИЦИЯМ выбранных хостов в chain_nodes. Фильтровать ТЕКУЩИЙ
        # selector по живым адресам нельзя: он уже сужен прошлым
        # составом, а адреса могли быть пропатчены smart_balancer'ом
        # (кейс прод-деплоя: selector схлопнулся в один тег).
        _new_selector = [f"chain-exit-{i+1}"
                         for i, nd in enumerate(nodes)
                         if not sel or _lb_node_host(nd) in sel_set]
        if sel and len(_new_selector) < 2:
            print("set_lb_nodes: пересобранный selector <2 тегов — "
                  "отклонено")
            return False
        for b in balancers:
            if b.get("tag") == "chain-balancer":
                b["selector"] = list(_new_selector)
                patched = True
        # observatory пробирует только выбранные (subjectSelector = selector)
        obs = cfg.get("observatory")
        if obs and obs.get("subjectSelector") and _new_selector:
            obs["subjectSelector"] = list(_new_selector)
        # Ре-синх адресов ВСЕХ chain-exit outbound'ов: chain-exit-N →
        # nodes[N-1] из state (суперсет, не только выбранные — инвариант
        # «адреса конфига == state»). Снимает устаревший патч
        # smart_balancer'а (иначе «лучшая» нода остаётся в чужом слоте
        # и ротация состава схлопывается в одну ноду).
        _resynced: list = []
        for ob in cfg.get("outbounds", []):
            t = str(ob.get("tag", ""))
            m = re.fullmatch(r"chain-exit-(\d+)", t)
            if not m:
                continue
            idx = int(m.group(1)) - 1
            if not (0 <= idx < len(nodes)):
                continue
            vn = (ob.get("settings") or {}).get("vnext") or []
            if not vn:
                continue
            want_h = nodes[idx].get("host")
            want_p = int(nodes[idx].get("port", 443))
            if vn[0].get("address") != want_h or vn[0].get("port") != want_p:
                vn[0]["address"] = want_h
                vn[0]["port"] = want_p
                _resynced.append(t)
        if _resynced:
            print("ре-синх адресов (снят патч smart_balancer): "
                  + ", ".join(_resynced))
        if patched:
            _CHAIN_CONFIG_FILE.write_text(
                json.dumps(cfg, indent=2, ensure_ascii=False))
            _CHAIN_CONFIG_FILE.chmod(0o640)
            print("selector балансировщика: " + ", ".join(_new_selector))
        else:
            print("set_lb_nodes: chain-balancer в конфиге не найден "
                  "(одна нода / pinned) — сохранён только state")
    except Exception as ex:
        print(f"set_lb_nodes: патч конфига не удался: {ex}")
        return False

    if not restart:
        return True
    # graceful-рестарт как у smart_balancer (reset-failed → xray → nginx)
    import subprocess as _sp
    _sp.run(["systemctl", "reset-failed", "xray"],
            capture_output=True, check=False)
    _sp.run(["systemctl", "restart", "xray"],
            capture_output=True, timeout=30)
    _ok = False
    for _ in range(5):
        time.sleep(3)
        r = _sp.run(["systemctl", "is-active", "xray"],
                    capture_output=True, text=True, timeout=5)
        if r.stdout.strip() == "active":
            _ok = True
            break
    if not _ok:
        print("set_lb_nodes: xray не поднялся после рестарта!")
        return False
    rn = _sp.run(["systemctl", "is-active", "nginx"],
                 capture_output=True, text=True, timeout=5)
    if rn.stdout.strip() == "active":
        _sp.run(["systemctl", "restart", "nginx"],
                capture_output=True, timeout=15)
    # TG-уведомление (best effort, как set_lb_exits Mieru)
    try:
        from chimera.modules.smart_balancer import _tg_notify_event
        _tg_notify_event(
            "cascade_lb_change",
            "⚖️ VLESS-каскад: состав балансировки → <b>" +
            (_lb_nodes_summary(nodes, sel) or "все") + "</b>")
    except Exception:
        pass
    return True
