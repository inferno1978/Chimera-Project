"""
chimera/modules/awg_cascade.py
───────────────────────────────────────────────────────────────────────────────
Каскад из 2 серверов AmneziaWG: RU (вход) → зарубеж (выход).

Схема (как в bivlked CASCADE.md):
  Клиент ──AWG──► AWG0 (RU, вход) ──┬──► российские сети напрямую (через host)
                                    └──► остальной трафик ──► AWG1 (зарубеж, выход)

Реализация (мигрировано с iptables/ipset на nftables, этап 1.6):
  • AWG1 (выход): стандартная установка standalone AWG + спец-пир 'cascade_entry'
    для подключения AWG0
  • AWG0 (вход): стандартная установка standalone AWG + клиентский туннель awg1
    к AWG1 + nft set с RU-сетями (awg_cascade_nodes) + nftables-маршрутизация +
    systemd-юнит + cron обновления ru.zone

Весь трафик к российским сетям (из ru.zone) идёт напрямую через host,
остальной трафик маркируется fwmark=0x2000 и уходит через awg1 (туннель к AWG1).
"""
from __future__ import annotations

import re
import time
from pathlib import Path

from .awg_constants import (
    AWGS_CASCADE_DIR, AWGS_RU_ZONE_FILE, AWGS_ROUTING_SCRIPT,
    AWGS_IPSET_NAME, AWGS_CASCADE_FWMARK,
    AWGS_CRON_RU_UPDATE, AWGS_CRON_RU_UPDATE_SCRIPT, AWGS_SYSTEMD_CASCADE,
    AWGS_RU_ZONE_URL, AWGS_RU_ZONE_FALLBACK_GH,
    AWGS_CASCADE_ENTRY_PEER, AWGS_DEFAULT_SUBNET,
)
from .awg_state import (
    awgs_state_load, awgs_state_save, awgs_state_set_cascade_role,
    awgs_state_is_installed,
)
from .awg_standalone import (
    awgs_install, awgs_generate_keys, awgs_build_server_conf,
    awgs_write_server_conf, awgs_check_conflicts,
)
from .awg_peers import awg_peer_add, awg_peer_rebuild_conf
from .awg_apply import awgs_apply, awgs_service_status

# ЭТАП 1.6 МИГРАЦИИ: импорты nft_common + nft_constants.
# awgs_ipset (legacy) → nft set awg_cascade_nodes (table inet chimera).
# iptables mangle MARK → nft rule in mangle_forward chain.
# ipset restore / swap / destroy → nft_set_atomic_swap / nft_set_destroy.
from .nft_common import (
    nft_set_create, nft_set_atomic_swap, nft_set_destroy, nft_set_count,
    nft_rule_add, nft_rule_delete_by_comment, nft_persist,
)
from .nft_constants import (
    NFT_TABLE_NAME, NFT_TABLE_FAMILY,
    NFT_CHAIN_POSTROUTING, NFT_CHAIN_FORWARD,
    NFT_CHAIN_MANGLE_FORWARD, NFT_CHAIN_MANGLE_OUTPUT,
    NFT_SET_AWG_CASCADE,
    COMMENT_AWG_MASQ, COMMENT_AWG_CASCADE_MARK,
)


def _core_module():
    import importlib
    return importlib.import_module("chimera._core")


# ============================================================================
#  RU.ZONE — загрузка списка российских сетей
# ============================================================================

def awgs_cascade_download_ru_zone() -> bool:
    """
    Скачивает актуальный ru.zone через download_manager.fetch_package().

    МИГРАЦИЯ: раньше использовался subprocess curl с inline списком из 2
    URL (ipdeny.com + GitHub raw bivlked), БЕЗ проверки ручного размещения.
    Аналогично старому geo_files.py, который уже мигрирован.

    Теперь используется fetch_package(RU_ZONE_SPEC) из download_manager.py.
    fetch_package сам:
      1. Проверяет /root/ru.zone (manual_incoming_dir из spec) — если
         найден и размер >= 1 KB, использует без сети (WinSCP-friendly).
      2. Иначе — перебирает 9 зеркал (ipdeny + GitHub raw + 7 gh-proxy)
         по очереди через urllib.
      3. При успехе — post_install копирует в /etc/amneziawg/cascade/ru.zone
         + sanity check (lines_count > 100).
      4. При провале — print_manual_hint() с инструкцией.

    Fallback поведение сохранено: если все зеркала упали, создаётся пустой
    файл (будет обновлён cron'ом).
    """
    core = _core_module()
    info = core.info
    warn = core.warn

    AWGS_CASCADE_DIR.mkdir(parents=True, exist_ok=True)

    from chimera.modules.download_manager import fetch_package
    from chimera.modules.awg_cascade_packages import RU_ZONE_SPEC

    ok = fetch_package(RU_ZONE_SPEC, print_hint_on_failure=False)
    if ok:
        try:
            lines_count = sum(1 for _ in AWGS_RU_ZONE_FILE.open())
            info(f"ru.zone загружен: {lines_count} сетей")
        except Exception:
            info("ru.zone загружен")
        return True

    # Если ничего не вышло — создаём пустой файл (будет обновлён cron'ом)
    warn("Все источники недоступны — создан пустой ru.zone (обновится cron'ом)")
    AWGS_RU_ZONE_FILE.write_text("")
    return False


def awgs_cascade_load_ipset() -> bool:
    """Загружает ru.zone в nft set (атомарно через nft_set_atomic_swap).

    ЭТАП 1.6 МИГРАЦИИ:
      • Раньше: `ipset restore -exist -file <tmp>` (создавался временный файл
        restore с командами `create ... hash:net` + `add ...`).
      • Теперь: `nft_set_atomic_swap("awg_cascade_nodes", elements)` — атомарно
        flush + add в одной транзакции `nft -f -`. Set создаётся если его нет
        (nft_set_create с flags=["interval"] для CIDR-подсетей).
    """
    core = _core_module()
    if not AWGS_RU_ZONE_FILE.exists() or AWGS_RU_ZONE_FILE.stat().st_size == 0:
        core.log_to_file("WARN", "awgs_cascade_load_ipset: ru.zone пуст")
        return False

    # Создаём nft set если ещё нет (аналог ipset create -exist)
    # set_type=ipv4_addr (RU-сети — только IPv4 CIDR), flags=["interval"]
    # для поддержки CIDR-нотации (10.0.0.0/8).
    nft_set_create(
        NFT_SET_AWG_CASCADE, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY,
        set_type="ipv4_addr", flags=["interval"], maxelem=65536,
    )

    # Собираем список CIDR из ru.zone
    elements = []
    for line in AWGS_RU_ZONE_FILE.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            elements.append(line)

    try:
        if not nft_set_atomic_swap(
            NFT_SET_AWG_CASCADE, elements,
            table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY,
        ):
            core.log_to_file(
                "WARN",
                f"awgs_cascade_load_ipset: nft_set_atomic_swap failed "
                f"({len(elements)} elements)",
            )
            return False
        core.log_to_file(
            "INFO",
            f"nft set {NFT_SET_AWG_CASCADE} загружен ({len(elements)} сетей)",
        )
        return True
    except Exception as e:
        core.log_to_file("ERROR", f"awgs_cascade_load_ipset: {e}")
        return False


# ============================================================================
#  AWG0 (вход) — клиентский туннель к AWG1 + маршрутизация
# ============================================================================

def awgs_cascade_setup_awg0(
    exit_host: str,
    exit_port: int,
    exit_pubkey: str,
    exit_subnet: str = "172.16.61.0/24",
    exit_peer_privkey: str = "",
    exit_peer_psk: str = "",
) -> bool:
    """
    Настраивает AWG0 (вход каскада):
      • Создаёт туннель awg1 к AWG1 (через awg-quick@awg1)
      • Загружает ru.zone в ipset
      • Применяет iptables-маршрутизацию
      • Создаёт awg-routing.sh + systemd-юнит
      • Cron для обновления ru.zone
    """
    core = _core_module()
    info = core.info
    success = core.success
    warn = core.warn

    if not exit_peer_privkey:
        # Генерируем клиентский ключ для подключения к AWG1
        info("Генерация клиентского ключа для туннеля к AWG1...")
        exit_peer_privkey, exit_peer_pubkey = awgs_generate_keys()
        if not exit_peer_privkey:
            warn("Не удалось сгенерировать ключ туннеля")
            return False
    else:
        # Считаем pubkey из переданного privkey (fallback awg → wg)
        awg_path = core._run(["which", "awg"], capture=True, check=False).stdout.strip()
        wg_path = core._run(["which", "wg"], capture=True, check=False).stdout.strip()
        bin_for_pubkey = awg_path or wg_path
        if not bin_for_pubkey:
            warn("Ни awg, ни wg не найдены — не могу вычислить pubkey")
            return False
        r = core._run(["bash", "-c", f"echo '{exit_peer_privkey}' | {bin_for_pubkey} pubkey"],
                      capture=True, check=False)
        exit_peer_pubkey = r.stdout.strip() if r.returncode == 0 else ""

    # Сохраняем в state
    awgs_state_set_cascade_role(
        "entry",
        cascade_peer_host=exit_host,
        cascade_peer_port=exit_port,
        cascade_peer_pubkey=exit_pubkey,
        cascade_peer_privkey=exit_peer_privkey,
        cascade_subnet=exit_subnet,
    )

    # 1. Создаём конфиг awg1 (туннель к AWG1)
    info("Создание конфига awg1 (туннель к AWG1)...")
    awg1_conf = _awgs_cascade_build_awg1_conf(
        exit_host, exit_port, exit_pubkey,
        exit_peer_privkey, exit_peer_psk, exit_subnet,
    )
    awg1_path = Path("/etc/amnezia/amneziawg/awg1.conf")
    awg1_path.write_text(awg1_conf)
    awg1_path.chmod(0o600)

    # 2. Запускаем awg1 (отдельный сервис awg-quick@awg1)
    info("Запуск awg-quick@awg1...")
    core._run(["systemctl", "enable", "awg-quick@awg1"], check=False, quiet=True)
    r = core._run(["systemctl", "start", "awg-quick@awg1"],
                  capture=True, check=False)
    if r.returncode != 0:
        warn(f"awg1 не запустился: {r.stderr}")
        return False

    # 3. Загружаем ru.zone в ipset
    info("Загрузка ru.zone в ipset...")
    awgs_cascade_download_ru_zone()
    awgs_cascade_load_ipset()

    # 4. Применяем iptables-маршрутизацию
    info("Применение iptables-маршрутизации...")
    _awgs_cascade_apply_iptables(exit_subnet)

    # 5. Создаём awg-routing.sh (для пересоздания правил при ребуте)
    info("Создание awg-routing.sh + systemd-юнита...")
    _awgs_cascade_create_routing_script(exit_subnet)
    _awgs_cascade_create_systemd_unit()

    # 6. Cron для обновления ru.zone
    info("Создание cron для обновления ru.zone...")
    _awgs_cascade_setup_cron()

    # 7. Запуск routing-юнита
    core._run(["systemctl", "daemon-reload"], check=False, quiet=True)
    core._run(["systemctl", "enable", "awg-cascade-routing"],
              check=False, quiet=True)
    r = core._run(["systemctl", "start", "awg-cascade-routing"],
                  capture=True, check=False)
    if r.returncode != 0:
        warn(f"awg-cascade-routing не запустился: {r.stderr}")

    success("Каскад AWG0 (вход) настроен")
    return True


def _awgs_cascade_build_awg1_conf(
    exit_host: str,
    exit_port: int,
    exit_pubkey: str,
    client_privkey: str,
    psk: str,
    exit_subnet: str,
) -> str:
    """Генерирует awg1.conf — клиентский туннель к AWG1."""
    # IP клиента в подсети exit (обычно .2)
    base = exit_subnet.split("/")[0].rsplit(".", 1)[0]
    client_ip = f"{base}.2/32"

    # Параметры AWG 2.0 — берём из state (должны совпадать с AWG1)
    state = awgs_state_load()
    params = state.get("params", {})

    lines = [
        "[Interface]",
        f"PrivateKey = {client_privkey}",
        f"Address = {client_ip}",
        f"MTU = {state.get('mtu', 1280)}",
        # Table = off — КРИТИЧЕСКИ важно для каскада: awg-quick НЕ должен
        # автоматически создавать маршрут 0.0.0.0/0 dev awg1, иначе весь
        # трафик сервера (включая SSH-ответы) уходит через туннель и
        # сессия обрывается. Маршрутизация управляется через iptables +
        # policy routing (table 2000, fwmark) в _awgs_cascade_apply_iptables.
        "Table = off",
        # Параметры обфускации (должны совпадать с сервером AWG1)
        f"Jc = {params.get('jc', 4)}",
        f"Jmin = {params.get('jmin', 40)}",
        f"Jmax = {params.get('jmax', 70)}",
        f"S1 = {params.get('s1', 0)}",
        f"S2 = {params.get('s2', 0)}",
        f"S3 = {params.get('s3', 0)}",
        f"S4 = {params.get('s4', 0)}",
        f"H1 = {params.get('h1', 1)}",
        f"H2 = {params.get('h2', 2)}",
        f"H3 = {params.get('h3', 3)}",
        f"H4 = {params.get('h4', 4)}",
        "",
        "[Peer]",
        f"PublicKey = {exit_pubkey}",
        f"Endpoint = {exit_host}:{exit_port}",
        "AllowedIPs = 0.0.0.0/0",   # весь трафик (маршрутизация через iptables)
        "PersistentKeepalive = 25",
    ]
    if psk:
        lines.append(f"PresharedKey = {psk}")
    return "\n".join(lines) + "\n"


def _awgs_cascade_apply_iptables(exit_subnet: str) -> bool:
    """Применяет nftables-правила для каскада.

    ЭТАП 1.6 МИГРАЦИИ:
      • Раньше: 5 iptables правил (mangle MARK, nat MASQUERADE, FORWARD in/out,
        FORWARD ipset match) + ip rule fwmark 0x2000.
      • Теперь: 5 nft правил в таблице inet chimera (mangle_forward, postrouting,
        forward x3) + nft set lookup @awg_cascade_nodes.

    Основная идея:
      1. Трафик к RU-сетям → напрямую через host (без mark, match через @awg_cascade_nodes)
      2. Весь остальной трафик → mark 0x2000 → route через awg1 (table 2000)

    Используем nft set @awg_cascade_nodes для матчинга RU-сетей.

    Имя функции сохранено для совместимости со старыми тестами (test_awg_cascade.py
    TestAwgsCascadeApplyIptablesRules патчит именно это имя).
    """
    core = _core_module()

    # Гарантируем что nft set awg_cascade_nodes существует (для @awg_cascade_nodes lookup)
    nft_set_create(
        NFT_SET_AWG_CASCADE, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY,
        set_type="ipv4_addr", flags=["interval"], maxelem=65536,
    )

    # Применяем правила через nft_rule_add (idempotent через comment-tag)
    # Правила используют comment-tag из nft_constants (COMMENT_AWG_CASCADE_MARK,
    # COMMENT_AWG_MASQ, etc.) для безопасного cleanup при удалении каскада.

    # 1. mark трафик от клиентов awg0 (НЕ весь OUTPUT сервера!), кроме RU
    #    Используем FORWARD (не OUTPUT), чтобы не маркировать собственный
    #    трафик сервера (SSH-ответы и т.п.) — regression fix для SSH lockout.
    #    iptables -t mangle -A FORWARD -i awg0 -m set ! --match-set awgs_ipset dst -j MARK --set-mark 0x2000
    #    → nft: iifname "awg0" ip daddr != @awg_cascade_nodes meta mark set 0x2000
    nft_rule_add(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_MANGLE_FORWARD,
        rule_spec=f'iifname "awg0" ip daddr != @{NFT_SET_AWG_CASCADE} '
                  f'meta mark set {AWGS_CASCADE_FWMARK}',
        family=NFT_TABLE_FAMILY,
        comment=COMMENT_AWG_CASCADE_MARK,  # "awg-cascade-fwmark"
        idempotent=True,
    )

    # 2. NAT для выхода через awg1
    #    iptables -t nat -A POSTROUTING -o awg1 -j MASQUERADE
    #    → nft: oifname "awg1" masquerade
    nft_rule_add(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_POSTROUTING,
        rule_spec='oifname "awg1" masquerade',
        family=NFT_TABLE_FAMILY,
        comment=COMMENT_AWG_MASQ,  # "awg-masquerade"
        idempotent=True,
    )

    # 3. Разрешаем forward awg0 → awg1 (новые соединения от клиентов)
    nft_rule_add(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_FORWARD,
        rule_spec='iifname "awg0" oifname "awg1" accept',
        family=NFT_TABLE_FAMILY,
        comment="awg-cascade-fwd-in",
        idempotent=True,
    )

    # 4. Разрешаем forward awg1 → awg0 (ESTABLISHED,RELATED — обратный трафик)
    nft_rule_add(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_FORWARD,
        rule_spec='iifname "awg1" oifname "awg0" '
                  'ct state { established, related } accept',
        family=NFT_TABLE_FAMILY,
        comment="awg-cascade-fwd-out",
        idempotent=True,
    )

    # 5. Для RU-сетей — forward напрямую через host-интерфейс (match через @awg_cascade_nodes)
    nft_rule_add(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_FORWARD,
        rule_spec=f'iifname "awg0" ip daddr @{NFT_SET_AWG_CASCADE} accept',
        family=NFT_TABLE_FAMILY,
        comment="awg-cascade-fwd-ru",
        idempotent=True,
    )

    # Policy routing: marked-трафик → через awg1
    # Добавляем таблицу 2000 (если ещё нет) — ЭТО ip route, не nft (НЕ ТРОГАТЬ).
    r = core._run(["ip", "route", "show", "table", "2000"],
                  capture=True, check=False)
    if not r.stdout.strip():
        # Определяем шлюз по умолчанию через awg1
        exit_base = exit_subnet.split("/")[0].rsplit(".", 1)[0]
        exit_gw = f"{exit_base}.1"
        core._run(["ip", "route", "add", "default", "via", exit_gw, "dev", "awg1", "table", "2000"],
                  check=False, quiet=True)

    # Правило policy routing по fwmark — ЭТО ip rule, не nft (НЕ ТРОГАТЬ).
    core._run(["ip", "rule", "add", "fwmark", str(AWGS_CASCADE_FWMARK), "lookup", "2000"],
              check=False, quiet=True)

    return True


def _awgs_cascade_create_routing_script(exit_subnet: str) -> None:
    """Создаёт awg-routing.sh для пересоздания правил при ребуте.

    ЭТАП 1.6 МИГРАЦИИ:
      • Раньше: bash-скрипт с ipset create/restore + iptables -A правила.
      • Теперь: bash-скрипт с прямыми вызовами `nft add rule inet chimera ...`
        (idempotent через comment-tag) + `nft add element ...` для заполнения
        set awg_cascade_nodes (через batch-транзакцию).
    """
    AWGS_CASCADE_DIR.mkdir(parents=True, exist_ok=True)
    exit_base = exit_subnet.split("/")[0].rsplit(".", 1)[0]
    exit_gw = f"{exit_base}.1"

    # ЭТАП 1.6: bash-скрипт с nft binary напрямую.
    # Идемпотентность через comment-tag (nft не добавляет дубликаты правил
    # с одним comment-tag при втором вызове — nft_rule_add проверяет через
    # `nft -j list chain` JSON). Set awg_cascade_nodes создаётся через
    # nft add set если ещё нет.
    script = f"""#!/bin/bash
# AWG Cascade routing — пересоздаёт правила при старте системы
# Автоматически сгенерировано chimera/modules/awg_cascade.py
# ЭТАП 1.6 МИГРАЦИИ: переписано с iptables/ipset на nftables (inet chimera).

set -e

# 1. Создать nft set awg_cascade_nodes (если ещё нет) и заполнить из ru.zone
if [ -f "{AWGS_RU_ZONE_FILE}" ]; then
    # Создаём set если не существует (idempotent: -exist эквивалент в nft —
    # `add set` с тем же именем не падает если set уже есть, но мы делаем
    # явную проверку через `list set` чтобы избежать ошибки).
    nft list set inet chimera {NFT_SET_AWG_CASCADE} >/dev/null 2>&1 || \\
        nft add set inet chimera {NFT_SET_AWG_CASCADE} \\
            {{ type ipv4_addr; flags interval; size 65536; }}

    # Собираем элементы в batch-транзакцию (аналог ipset restore)
    TMP=$(/bin/mktemp)
    echo "flush set inet chimera {NFT_SET_AWG_CASCADE}" > "$TMP"
    FIRST=1
    echo -n "add element inet chimera {NFT_SET_AWG_CASCADE} {{ " >> "$TMP"
    while IFS= read -r line; do
        line=$(echo "$line" | tr -d '[:space:]')
        [ -z "$line" ] && continue
        [ "${{line:0:1}}" = "#" ] && continue
        if [ $FIRST -eq 1 ]; then
            echo -n "$line" >> "$TMP"
            FIRST=0
        else
            echo -n ", $line" >> "$TMP"
        fi
    done < "{AWGS_RU_ZONE_FILE}"
    echo " }}" >> "$TMP"
    nft -f "$TMP" 2>/dev/null || true
    rm -f "$TMP"
fi

# 2. nft правила (idempotent через comment-tag — nft_rule_add на python
#    проверяет существование правила по comment перед добавлением, но в bash
#    мы используем упрощённую схему: добавляем с `2>/dev/null || true`, nft
#    сам по себе не падает при повторном добавлении правила с тем же comment
#    в нашем случае — он создаёт ДУБЛЬ правила. Для строго идемпотентного
#    поведения используем del-before-add: удаляем все правила с этим comment,
#    затем добавляем одно. Эквивалент nft_rule_delete_by_comment из nft_common.
for chain_comment in \\
    "mangle_forward:awg-cascade-fwmark" \\
    "postrouting:awg-masquerade" \\
    "forward:awg-cascade-fwd-in" \\
    "forward:awg-cascade-fwd-out" \\
    "forward:awg-cascade-fwd-ru"; do
    chain="${{chain_comment%%:*}}"
    comment="${{chain_comment#*:}}"
    # Delete existing rules with this comment (cleanup dublicates)
    python3 -c "
import json, subprocess
r = subprocess.run(['nft','-a','-j','list','chain','inet','chimera','$chain'], capture_output=True, text=True)
if r.returncode != 0: exit()
try:
    data = json.loads(r.stdout)
    for item in data.get('nftables', []):
        if 'chain' not in item: continue
        for rule in item['chain'].get('expr', []):
            if rule.get('comment') != '$comment': continue
            h = rule.get('handle')
            if h is None: continue
            subprocess.run(['nft','delete','rule','inet','chimera','$chain','handle',str(h)], capture_output=True)
except Exception: pass
" 2>/dev/null || true
done

# Добавляем правила (idempotent после cleanup выше — ровно по одному правилу)
nft add rule inet chimera mangle_forward \\
    iifname "awg0" ip daddr != @{NFT_SET_AWG_CASCADE} \\
    meta mark set {AWGS_CASCADE_FWMARK} \\
    comment "awg-cascade-fwmark" 2>/dev/null || true
nft add rule inet chimera postrouting \\
    oifname "awg1" masquerade \\
    comment "awg-masquerade" 2>/dev/null || true
nft add rule inet chimera forward \\
    iifname "awg0" oifname "awg1" accept \\
    comment "awg-cascade-fwd-in" 2>/dev/null || true
nft add rule inet chimera forward \\
    iifname "awg1" oifname "awg0" \\
    ct state {{ established, related }} accept \\
    comment "awg-cascade-fwd-out" 2>/dev/null || true
nft add rule inet chimera forward \\
    iifname "awg0" ip daddr @{NFT_SET_AWG_CASCADE} accept \\
    comment "awg-cascade-fwd-ru" 2>/dev/null || true

# 3. Policy routing (НЕ ТРОГАТЬ — это ip rule/route, не nft)
ip route add default via {exit_gw} dev awg1 table 2000 2>/dev/null || true
ip rule add fwmark {AWGS_CASCADE_FWMARK} lookup 2000 2>/dev/null || true

echo "AWG Cascade routing started (nftables)"
"""
    AWGS_ROUTING_SCRIPT.write_text(script)
    AWGS_ROUTING_SCRIPT.chmod(0o755)


def _awgs_cascade_create_systemd_unit() -> None:
    """Создаёт systemd-юнит awg-cascade-routing.service."""
    unit = f"""[Unit]
Description=AWG Cascade Routing (RU split-tunnel)
After=awg-quick@awg0.service awg-quick@awg1.service network.target
Wants=awg-quick@awg0.service awg-quick@awg1.service

[Service]
Type=oneshot
ExecStart={AWGS_ROUTING_SCRIPT}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
    AWGS_SYSTEMD_CASCADE.write_text(unit)


def _awgs_cascade_setup_cron() -> None:
    """Создаёт cron для еженедельного обновления ru.zone.

    v5.1: bare ``python3 -c "from chimera.modules.awg_cascade import
    awgs_cascade_update_ru_zone; ..."`` в cron НЕ работает — cron
    запускается с произвольной cwd и без PYTHONPATH, поэтому
    ``from chimera...`` падает с ``ModuleNotFoundError: No module named
    'chimera'``. Тот же класс бага, что и в awgs_setup_expires_cron()
    и mtproto_stats.setup_iptables_accounting().

    Паттерн исправления — wrapper bash-скрипт (как в
    ``node_health_monitor.py::install_health_monitor`` и
    ``geo_files.py::setup_geo_autoupdate``): находим путь установки
    chimera, экспорим PYTHONPATH, вызываем python -c с
    ``sys.path.insert(0, ...)``. Cron-файл просто вызывает wrapper.
    """
    # Находим путь установки chimera (тот же способ, что в
    # node_health_monitor.py::install_health_monitor).
    try:
        import importlib.util
        spec = importlib.util.find_spec("chimera")
        if spec and spec.submodule_search_locations:
            installer_path = str(
                Path(list(spec.submodule_search_locations)[0]).parent
            )
        else:
            installer_path = "/opt/chimera"
    except Exception:
        installer_path = "/opt/chimera"

    # Wrapper bash-скрипт: export PYTHONPATH + sys.path.insert + python -c
    script_content = (
        "#!/bin/bash\n"
        "# AWG cascade: еженедельное обновление ru.zone "
        "(wrapper для cron; v5.1: PYTHONPATH-safe).\n"
        f"export PYTHONPATH=\"{installer_path}:$PYTHONPATH\"\n"
        f"/usr/bin/python3 -c \"\n"
        f"import sys\n"
        f"sys.path.insert(0, '{installer_path}')\n"
        f"from chimera.modules.awg_cascade import awgs_cascade_update_ru_zone\n"
        f"awgs_cascade_update_ru_zone()\n"
        f"\" >> /root/awg/awg_standalone.log 2>&1\n"
    )
    AWGS_CRON_RU_UPDATE_SCRIPT.write_text(script_content)
    AWGS_CRON_RU_UPDATE_SCRIPT.chmod(0o755)

    # Cron-файл — вызывает wrapper-скрипт.
    cron = (
        "# AWG cascade: еженедельное обновление ru.zone\n"
        f"0 3 * * 0 root {AWGS_CRON_RU_UPDATE_SCRIPT}\n"
    )
    AWGS_CRON_RU_UPDATE.write_text(cron)
    AWGS_CRON_RU_UPDATE.chmod(0o644)


def awgs_cascade_update_ru_zone() -> bool:
    """Cron-задача: обновляет ru.zone и перезагружает nft set.

    ЭТАП 1.6 МИГРАЦИИ:
      • Раньше: `ipset destroy awgs_ipset` + `ipset restore -! -f <file>`.
      • Теперь: `nft_set_destroy` + `awgs_cascade_load_ipset` (которая внутри
        вызывает `nft_set_atomic_swap` для атомарной замены).
    """
    core = _core_module()
    core.log_to_file("INFO", "awgs_cascade_update_ru_zone: started")
    if not awgs_cascade_download_ru_zone():
        return False
    # Пересоздаём nft set (destroy + create + atomic_swap)
    # На самом деле awgs_cascade_load_ipset сам делает nft_set_create (if not exists)
    # + nft_set_atomic_swap — поэтому destroy здесь опционален (для cleanup
    # от старых элементов, которые могли остаться после rename set'а).
    nft_set_destroy(NFT_SET_AWG_CASCADE, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY)
    return awgs_cascade_load_ipset()


# ============================================================================
#  AWG1 (выход) — спец-пир для AWG0
# ============================================================================

def awgs_cascade_setup_awg1() -> bool:
    """
    Настраивает AWG1 (выход каскада):
      • Стандартная установка standalone AWG (если ещё не установлен)
      • Создаёт спец-пир 'cascade_entry' для подключения AWG0
      • Возвращает данные для настройки AWG0 (host/port/pubkey)
    """
    core = _core_module()
    info = core.info
    success = core.success
    warn = core.warn

    # Если standalone AWG не установлен — устанавливаем
    if not awgs_state_is_installed():
        info("Установка standalone AWG на этом сервере (AWG1, выход)...")
        if not awgs_install():
            warn("Установка standalone AWG не удалась")
            return False

    # Создаём спец-пир cascade_entry
    info("Создание пира 'cascade_entry' для подключения AWG0...")
    # Удаляем если уже есть
    from .awg_state import awgs_state_peer_find, awgs_state_peer_remove
    if awgs_state_peer_find(AWGS_CASCADE_ENTRY_PEER):
        awgs_state_peer_remove(AWGS_CASCADE_ENTRY_PEER)

    # Добавляем нового пира
    if not awg_peer_add(AWGS_CASCADE_ENTRY_PEER, apply=True, show_qr=False):
        warn("Не удалось создать cascade_entry peer")
        return False

    # Помечаем роль
    awgs_state_set_cascade_role("exit")

    # Получаем данные для AWG0
    state = awgs_state_load()
    peer = awgs_state_peer_find(AWGS_CASCADE_ENTRY_PEER)

    print()
    success("AWG1 (выход каскада) настроен!")
    print()
    core._box_top(f"Данные для настройки AWG0 (вход каскада)")
    core._box_row(f"  {core.GREEN}Endpoint host:{core.NC}  {state.get('endpoint', '?')}")
    core._box_row(f"  {core.GREEN}Port:{core.NC}           {state.get('port', 51820)}")
    core._box_row(f"  {core.GREEN}Server pubkey:{core.NC}  {state.get('server_pubkey', '?')[:32]}...")
    core._box_row(f"  {core.GREEN}Cascade peer IP:{core.NC} {peer.get('client_ip', '?')}")
    core._box_row(f"  {core.GREEN}Cascade subnet:{core.NC}  {state.get('subnet', '?')}")
    core._box_bottom()
    print()
    info("Передайте эти данные на AWG0 (вход каскада) при настройке.")

    return True


# ============================================================================
#  TUI-МЕНЮ
# ============================================================================

def do_manage_awg_cascade() -> None:
    """TUI-меню настройки каскада."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    _box_desc = core._box_desc
    info = core.info
    warn = core.warn
    CYAN, NC, GREEN, YELLOW, DIM = core.CYAN, core.NC, core.GREEN, core.YELLOW, core.DIM

    while True:
        import os
        os.system("clear")
        print()
        _box_top(f"Каскад из 2 серверов (RU → зарубеж)")
        _box_row()
        _box_desc("Клиент ──► AWG0 (вход, РФ) ──┬──► RU-сети напрямую")
        _box_desc("                              └──► AWG1 (выход, зарубеж) ──► мир")
        _box_row()
        state = awgs_state_load()
        role = state.get("cascade_role", "")
        if role:
            _box_row(f"  {GREEN}● Текущая роль:{NC} {role}")
        else:
            _box_row(f"  {DIM}○ Каскад не настроен{NC}")
        _box_row()
        _box_item("1", f"Настроить как AWG0 (вход, РФ)")
        _box_desc("Этот сервер принимает клиентов и делит трафик: RU напрямую, остальное через AWG1.")
        _box_item("2", f"Настроить как AWG1 (выход, зарубеж)")
        _box_desc("Этот сервер — зарубежный exit. Создаст спец-пир для AWG0.")
        _box_item("3", f"Обновить ru.zone вручную")
        _box_desc("Принудительное обновление списка российских сетей с ipdeny.com.")
        _box_item("4", f"Проверить состояние каскада")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            _awgs_cascade_menu_awg0()
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            awgs_cascade_setup_awg1()
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            info("Обновление ru.zone...")
            if awgs_cascade_update_ru_zone():
                core.success("ru.zone обновлён")
            else:
                warn("Не удалось обновить ru.zone")
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            _awgs_cascade_status()
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch in ("q", ""):
            break


def _awgs_cascade_menu_awg0() -> None:
    """Подменю настройки AWG0 (вход каскада)."""
    core = _core_module()
    info = core.info
    warn = core.warn
    CYAN, NC = core.CYAN, core.NC

    print()
    info("Настройка AWG0 (вход каскада).")
    info("Сначала настройте AWG1 (выход) на зарубежном сервере — получите endpoint/pubkey.")
    print()

    # Если standalone AWG не установлен — нужно сначала установить
    if not awgs_state_is_installed():
        info("Standalone AWG не установлен. Сначала установим...")
        if not awgs_install():
            return

    # Запрашиваем данные от AWG1
    exit_host = input(f"{CYAN}Endpoint host AWG1 (зарубежный IP/домен): {NC}").strip()
    if not exit_host:
        warn("Endpoint обязателен")
        return

    exit_port_str = input(f"{CYAN}UDP-порт AWG1 [51820]: {NC}").strip()
    exit_port = int(exit_port_str) if exit_port_str.isdigit() else 51820

    exit_pubkey = input(f"{CYAN}Server pubkey AWG1: {NC}").strip()
    if not exit_pubkey:
        warn("Server pubkey обязателен")
        return

    exit_subnet = input(f"{CYAN}Подсеть AWG1 [172.16.61.0/24]: {NC}").strip() or "172.16.61.0/24"

    print()
    confirm = input(f"{core.YELLOW}Настроить каскад с {exit_host}:{exit_port}? [y/N]: {NC}").strip().lower()
    if confirm not in ("y", "yes", "д", "да"):
        return

    awgs_cascade_setup_awg0(
        exit_host=exit_host,
        exit_port=exit_port,
        exit_pubkey=exit_pubkey,
        exit_subnet=exit_subnet,
    )


def _awgs_cascade_status() -> None:
    """Показывает статус каскада."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_sep = core._box_sep
    _box_bottom = core._box_bottom
    GREEN, NC, RED, DIM, CYAN = core.GREEN, core.NC, core.RED, core.DIM, core.CYAN

    state = awgs_state_load()
    role = state.get("cascade_role", "")

    print()
    _box_top(f"Статус каскада")
    _box_row()
    if not role:
        _box_row(f"  {DIM}Каскад не настроен{NC}")
        _box_bottom()
        return

    _box_row(f"  Роль: {CYAN}{role}{NC}")
    _box_sep()

    if role == "entry":
        # Проверяем awg1 (туннель к AWG1)
        r = core._run(["systemctl", "is-active", "awg-quick@awg1"],
                      capture=True, check=False)
        awg1_active = r.stdout.strip() == "active"
        status_str = f"{GREEN}active{NC}" if awg1_active else f"{RED}inactive{NC}"
        _box_row(f"  awg-quick@awg1:      {status_str}")

        # Проверяем routing-юнит
        r = core._run(["systemctl", "is-active", "awg-cascade-routing"],
                      capture=True, check=False)
        rt_active = r.stdout.strip() == "active"
        status_str = f"{GREEN}active{NC}" if rt_active else f"{RED}inactive{NC}"
        _box_row(f"  awg-cascade-routing: {status_str}")

        # Проверяем nft set awg_cascade_nodes (мигрировано с ipset, этап 1.6)
        # Раньше: `ipset list awgs_ipset` → parse "Number of entries: N"
        # Теперь: `nft_set_count("awg_cascade_nodes")` → JSON parse `nft -j list set`
        n = nft_set_count(NFT_SET_AWG_CASCADE, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY)
        if n > 0:
            _box_row(f"  nft set {NFT_SET_AWG_CASCADE}: {GREEN}{n} сетей{NC}")
        else:
            _box_row(f"  nft set {NFT_SET_AWG_CASCADE}: {RED}не загружен{NC}")

        # Выход к AWG1
        _box_row(f"  Exit host: {state.get('cascade_peer_host', '?')}")
        _box_row(f"  Exit port: {state.get('cascade_peer_port', '?')}")
        _box_row(f"  Exit subnet: {state.get('cascade_subnet', '?')}")

    elif role == "exit":
        # Просто проверяем, что standalone AWG активен
        from .awg_apply import awgs_service_status
        status = awgs_service_status()
        status_str = f"{GREEN}active{NC}" if status["active"] else f"{RED}inactive{NC}"
        _box_row(f"  awg-quick@awg0: {status_str}")

        # Показываем cascade_entry пира
        from .awg_state import awgs_state_peer_find
        peer = awgs_state_peer_find(AWGS_CASCADE_ENTRY_PEER)
        if peer:
            _box_row(f"  Cascade entry peer: {GREEN}создан{NC} ({peer.get('client_ip', '?')})")
        else:
            _box_row(f"  Cascade entry peer: {RED}не найден{NC}")

    _box_bottom()
