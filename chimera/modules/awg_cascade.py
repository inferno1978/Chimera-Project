"""
chimera/modules/awg_cascade.py
───────────────────────────────────────────────────────────────────────────────
Каскад из 2 серверов AmneziaWG: RU (вход) → зарубеж (выход).

Схема (как в bivlked CASCADE.md):
  Клиент ──AWG──► AWG0 (RU, вход) ──┬──► российские сети напрямую (через host)
                                    └──► остальной трафик ──► AWG1 (зарубеж, выход)

Реализация:
  • AWG1 (выход): стандартная установка standalone AWG + спец-пир 'cascade_entry'
    для подключения AWG0
  • AWG0 (вход): стандартная установка standalone AWG + клиентский туннель awg1
    к AWG1 + ipset с RU-сетями + iptables-маршрутизация + systemd-юнит + cron
    обновления ru.zone

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
      2. Иначе — перебирает 5 зеркал (ipdeny + GitHub raw + 3 gh-proxy)
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
    """Загружает ru.zone в ipset (атомарно через restore)."""
    core = _core_module()
    if not AWGS_RU_ZONE_FILE.exists() or AWGS_RU_ZONE_FILE.stat().st_size == 0:
        core.log_to_file("WARN", "awgs_cascade_load_ipset: ru.zone пуст")
        return False

    # Создаём временный restore-файл
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".ipset", delete=False) as tmp:
        tmp.write(f"create {AWGS_IPSET_NAME} hash:net family inet hashsize 4096 maxelem 65536 -exist\n")
        for line in AWGS_RU_ZONE_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                tmp.write(f"add {AWGS_IPSET_NAME} {line} -exist\n")
        tmp_path = tmp.name

    try:
        r = core._run(["ipset", "restore", "-exist", "-file", tmp_path],
                      capture=True, check=False)
        if r.returncode != 0:
            core.log_to_file("WARN", f"awgs_cascade_load_ipset: {r.stderr}")
            return False
        core.log_to_file("INFO", f"ipset {AWGS_IPSET_NAME} загружен")
        return True
    except Exception as e:
        core.log_to_file("ERROR", f"awgs_cascade_load_ipset: {e}")
        return False
    finally:
        Path(tmp_path).unlink(missing_ok=True)


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
    exit_peer_ip: str = "",
    exit_params: dict = None,
) -> bool:
    """
    Настраивает AWG0 (вход каскада):
      • Создаёт туннель awg1 к AWG1 (через awg-quick@awg1)
      • Загружает ru.zone в ipset
      • Применяет iptables-маршрутизацию
      • Создаёт awg-routing.sh + systemd-юнит
      • Cron для обновления ru.zone

    v5.4.5:
      • exit_peer_ip — IP пира cascade_entry на стороне AWG1 (из бокса
        «Cascade peer IP»). Раньше хардкодился base.2 — если у exit уже
        были пиры (например VLESS-юзеры), cascade_entry получал .3+ →
        address mismatch → handshake никогда не сходился.
      • exit_params — параметры обфускации AWG1 (Jc/Jmin/Jmax/S1-S4/
        H1-H4/I1-I5 из бокса «Obfuscation»). КРИТИЧНО: обфускация
        должна совпадать на обеих сторонах — раньше awg1.conf брал
        параметры из СОБСТВЕННОГО state entry (случайные значения
        пресета) → handshake никогда не сходился (E2E 2026-10-03:
        transfer 0 B received при живом туннеле с обеих сторон).
      • Валидация: exit_subnet не должен совпадать с подсетью awg0 entry
        и exit_host не должен быть собственным IP (self-loop).
    """
    core = _core_module()
    info = core.info
    success = core.success
    warn = core.warn

    # v5.4.5: валидация подсети и self-loop (E2E: у юзера exit_subnet
    # мог совпасть с 10.66.66.0/24 entry — маршрутная каша)
    _own_state = awgs_state_load()
    _own_subnet = _own_state.get("subnet", "")
    if _own_subnet and _own_subnet == exit_subnet:
        warn(f"Подсеть AWG1 ({exit_subnet}) совпадает с подсетью awg0 на "
             f"этом сервере ({_own_subnet}) — маршруты конфликтуют!")
        warn("Установите standalone AWG на AWG1 с ДРУГОЙ подсетью "
             "(например 172.16.61.0/24) и повторите.")
        return False
    try:
        _own_ip = core.get_server_ip("4")
    except Exception:
        _own_ip = ""
    if _own_ip and _own_ip == exit_host:
        warn("exit_host указывает на этот же сервер (self-loop) — каскад "
             "не имеет смысла")
        return False

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
    if exit_params:
        info("Обфускация: используются параметры AWG1 (синхронизация)")
    else:
        warn("Параметры обфускации AWG1 не переданы — используются "
             "параметры ЭТОГО сервера. Если пресет AWG1 отличается, "
             "handshake не сойдётся!")
    awg1_conf = _awgs_cascade_build_awg1_conf(
        exit_host, exit_port, exit_pubkey,
        exit_peer_privkey, exit_peer_psk, exit_subnet,
        exit_peer_ip=exit_peer_ip,
        exit_params=exit_params,
    )
    awg1_path = Path("/etc/amnezia/amneziawg/awg1.conf")
    awg1_path.write_text(awg1_conf)
    awg1_path.chmod(0o600)

    # 2. Запускаем awg1 (отдельный сервис awg-quick@awg1)
    # v5.4.5: RESTART, а не start — при повторной настройке каскада юнит
    # уже активен и start = no-op: интерфейс продолжал жить со СТАРЫМ
    # конфигом (E2E: перезаписали awg1.conf с правильной обфускацией, но
    # handshake так и не появился — параметры не перечитались).
    info("Запуск awg-quick@awg1 (restart для перечитывания конфига)...")
    core._run(["systemctl", "enable", "awg-quick@awg1"], check=False, quiet=True)
    r = core._run(["systemctl", "restart", "awg-quick@awg1"],
                  capture=True, check=False)
    if r.returncode != 0:
        warn(f"awg1 не запустился: {r.stderr}")
        return False

    # 3. Загружаем ru.zone в ipset
    info("Загрузка ru.zone в ipset...")
    awgs_cascade_download_ru_zone()
    awgs_cascade_load_ipset()
    # v5.4.5: пустой ipset = весь клиентский трафик уйдёт НАПРЯМУЮ
    # с entry-сервера (mangle MARK не сработает — правило ссылается на
    # несуществующий set и не добавится) — каскад молча не каскадирует.
    # Проверяем и предупреждаем ЯВНО (E2E: у юзера именно так и было).
    r = core._run(["ipset", "list", AWGS_IPSET_NAME], capture=True, check=False)
    if r.returncode != 0 or "Number of entries: 0" in (r.stdout or ""):
        warn(f"ipset {AWGS_IPSET_NAME} пуст/отсутствует — ru.zone не загружен!")
        warn("Без ru.zone НЕ-RU трафик клиентов пойдёт напрямую с этого "
             "сервера, а не через AWG1. Проверьте /etc/awg-cascade/ru.zone.")

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

    # 7. Запуск routing-юнита (v5.4.5: restart — при повторной настройке
    # юнит уже активен, start = no-op, скрипт не перезапускался)
    core._run(["systemctl", "daemon-reload"], check=False, quiet=True)
    core._run(["systemctl", "enable", "awg-cascade-routing"],
              check=False, quiet=True)
    r = core._run(["systemctl", "restart", "awg-cascade-routing"],
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
    exit_peer_ip: str = "",
    exit_params: dict = None,
) -> str:
    """Генерирует awg1.conf — клиентский туннель к AWG1.

    v5.4.5:
      • exit_peer_ip — фактический IP пира cascade_entry на AWG1
        (раньше хардкод base.2 — при занятых IP на exit получали mismatch).
      • exit_params — параметры обфускации AWG1 (dict с ключами
        jc/jmin/jmax/s1-s4/h1-h4/i1-i5). Обфускация ОБЯЗАНА совпадать
        на обеих сторонах туннеля: раньше брались из state entry →
        случайные значения пресета не совпадали с exit → handshake
        никогда не сходился (E2E: 0 B received).
      • I1-I5 добавлены (правило v5.4.5: непустые как есть, пустые
        комментируются) — раньше отсутствовали полностью, что ломало
        handshake с exit-серверами, использующими I1 (default preset).
    """
    base = exit_subnet.split("/")[0].rsplit(".", 1)[0]
    # v5.4.5: приоритет — явно переданный peer IP, fallback — base.2
    peer_addr = exit_peer_ip if exit_peer_ip else f"{base}.2"
    client_ip = f"{peer_addr}/32"

    # Параметры AWG 2.0: приоритет — exit_params (синхронизация с AWG1),
    # fallback — собственный state (legacy, НЕ гарантирует handshake)
    state = awgs_state_load()
    params = exit_params if exit_params else state.get("params", {})

    def _p(key, default):
        return params.get(key, default)

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
        # Параметры обфускации — ДОЛЖНЫ совпадать с сервером AWG1
        # (v5.4.5: берём из exit_params)
        f"Jc = {_p('jc', 4)}",
        f"Jmin = {_p('jmin', 40)}",
        f"Jmax = {_p('jmax', 70)}",
        f"S1 = {_p('s1', 0)}",
        f"S2 = {_p('s2', 0)}",
        f"S3 = {_p('s3', 0)}",
        f"S4 = {_p('s4', 0)}",
        f"H1 = {_p('h1', 1)}",
        f"H2 = {_p('h2', 2)}",
        f"H3 = {_p('h3', 3)}",
        f"H4 = {_p('h4', 4)}",
    ]
    # v5.4.5: I1-I5 — по единому правилу (непустые как есть, пустые #)
    for key in ("i1", "i2", "i3", "i4", "i5"):
        val = _p(key, "")
        if val:
            lines.append(f"{key.upper()} = {val}")
        else:
            lines.append(f"# {key.upper()} = ")
    lines += [
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
    """Применяет iptables-правила для каскада.

    v5.4.5 ГЛАВНЫЙ ФИКС: MARK переносится из mangle FORWARD в mangle
    PREROUTING. Раньше (-A FORWARD ... -j MARK) метка ставилась ПОСЛЕ
    route decision: транзитный пакет клиента уже был маршрутизирован по
    main-таблице (oif=ens3), не попадал под FORWARD -i awg0 -o awg1 и
    дропался policy DROP — Е2Е 2026-10-03: счётчик MARK 236 пакетов при
    FORWARD awg0→awg1 = 0. fwmark-policy-routing работает для транзита
    ТОЛЬКО из PREROUTING (метка должна стоять ДО route decision).
    Метка в OUTPUT (первоначальный вариант) маркировала серверный
    трафик вместо клиентского (SSH-lockout, см. фикс 33970c2).

    Основная идея:
    1. Трафик клиентов awg0 к RU-сетям → напрямую через host (без mark)
    2. Весь остальной клиентский → mark 0x2000 (PREROUTING!) → table 2000 → awg1
    """
    core = _core_module()

    rules = [
        # v5.4.5: PREROUTING — ДО route decision (иначе транзит не
        # попадает в table 2000; см. докстринг). -i awg0 — только
        # клиентский трафик, серверный (ens3 in) не трогаем.
        f"iptables -t mangle -A PREROUTING -i awg0 -m set ! --match-set {AWGS_IPSET_NAME} dst -j MARK --set-mark {AWGS_CASCADE_FWMARK}",

        # NAT для выхода через awg1
        f"iptables -t nat -A POSTROUTING -o awg1 -j MASQUERADE",

        # Разрешаем forward
        "iptables -A FORWARD -i awg0 -o awg1 -j ACCEPT",
        "iptables -A FORWARD -i awg1 -o awg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",

        # Для RU-сетей — forward напрямую через host-интерфейс
        f"iptables -A FORWARD -i awg0 -m set --match-set {AWGS_IPSET_NAME} dst -j ACCEPT",

        # v5.4.5: TCPMSS clamp — двойное туннелирование (awg0 MTU 1280 внутри
        # awg1 MTU 1280 + оверхед обфускации) даёт effective MTU ~1200:
        # без клампа TCP-сессии с MSS 1240 зависают на больших пакетах
        # (TLS-certs) — классический MTU blackhole. Transport Mode B делает
        # TCPMSS 1240, cascade теперь тоже (E2E 2026-10-03).
        "iptables -t mangle -A FORWARD -i awg0 -o awg1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1140",
        "iptables -t mangle -A FORWARD -i awg1 -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1140",
    ]

    # v5.4.5: подчистить дубли от старых прогонов (голые -A до идемпотентного
    # фикса + MARK из FORWARD от бажных версий) перед применением
    core._run(["bash", "-c",
               f"while iptables -t mangle -D FORWARD -i awg0 -m set ! --match-set {AWGS_IPSET_NAME} dst -j MARK --set-mark {AWGS_CASCADE_FWMARK} 2>/dev/null; do :; done; "
               f"while iptables -t mangle -D PREROUTING -i awg0 -m set ! --match-set {AWGS_IPSET_NAME} dst -j MARK --set-mark {AWGS_CASCADE_FWMARK} 2>/dev/null; do :; done; "
               f"while iptables -t nat -D POSTROUTING -o awg1 -j MASQUERADE 2>/dev/null; do :; done; "
               f"while iptables -D FORWARD -i awg0 -o awg1 -j ACCEPT 2>/dev/null; do :; done; "
               f"while iptables -D FORWARD -i awg1 -o awg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do :; done; "
               f"while iptables -D FORWARD -i awg0 -m set --match-set {AWGS_IPSET_NAME} dst -j ACCEPT 2>/dev/null; do :; done"],
              check=False, quiet=True)

    # Применяем правила — ИДЕМПОТЕНТНО (v5.4.5: -C || -A)
    for rule in rules:
        check = rule.replace(" -A ", " -C ", 1)
        r = core._run(["bash", "-c", f"{check} 2>/dev/null || {rule}"],
                      capture=True, check=False, quiet=True)
        if r.returncode != 0:
            core.log_to_file("WARN", f"iptables rule failed: {rule}: {r.stderr}")

    # Policy routing: marked-трафик → через awg1
    # v5.4.5: КРИТИЧЕСКИЙ фикс — `ip route add default via {gw} dev awg1
    # table 2000` молча падал с "Nexthop has invalid gateway" при
    # Address=base.2/32 + Table=off (gateway НЕ on-link). Таблица 2000
    # оставалась ПУСТОЙ → fwmark-трафик падал в main → весь не-RU
    # клиентский трафик выходил НАПРЯМУЮ с entry-сервера, каскад молча
    # не каскадировал (подтверждено E2E 2026-10-03 на живой установке
    # юзера: table 2000 пустая при активном fwmark-правиле).
    # Фикс: сначала on-link маршрут подсети exit, затем default.
    # `replace` вместо `add` — идемпотентность при повторном запуске.
    exit_base = exit_subnet.split("/")[0].rsplit(".", 1)[0]
    exit_gw = f"{exit_base}.1"
    core._run(["ip", "route", "replace", f"{exit_base}.0/24", "dev", "awg1",
               "table", "2000"], check=False, quiet=True)
    core._run(["ip", "route", "replace", "default", "via", exit_gw, "dev", "awg1",
               "table", "2000"], check=False, quiet=True)
    # Проверяем что default-маршрут реально встал (иначе — громкий warn)
    r = core._run(["ip", "route", "show", "table", "2000"], capture=True, check=False)
    if "default" not in (r.stdout or ""):
        core.log_to_file("ERROR", "cascade: table 2000 has no default route!")
        core.warn("Маршрут default в table 2000 НЕ установлен — не-RU "
                  "трафик будет уходить напрямую! Проверьте awg1.")

    # Правило policy routing по fwmark — ИДЕМПОТЕНТНО (v5.4.5: ядро НЕ
    # отклоняет дубли «fwmark→table» — оно добавляет их с разными
    # автоприоритетами; E2E: после setup+boot-скрипта висело 2 правила).
    # Сначала удаляем все существующие fwmark-правила, затем добавляем одно.
    core._run(["bash", "-c",
               f"while ip rule del fwmark {AWGS_CASCADE_FWMARK} lookup 2000 2>/dev/null; do :; done; "
               f"ip rule add fwmark {AWGS_CASCADE_FWMARK} lookup 2000"],
              check=False, quiet=True)

    return True


def _awgs_cascade_create_routing_script(exit_subnet: str) -> None:
    """Создаёт awg-routing.sh для пересоздания правил при ребуте.

    v5.4.5: Скрипт приводит правила В ТОЧНОСТИ к live-набору из
    _awgs_cascade_apply_iptables. Раньше скрипт маркировал OUTPUT
    (серверный трафик!) вместо FORWARD -i awg0 (клиентский) и ставил
    conntrack-ACCEPT в OUTPUT — после ребута разметка молча меняла
    область действия (подтверждено E2E 2026-10-03: на живой установке
    юзера в mangle висело OUTPUT-правило от бут-скрипта вместо
    FORWARD-правила инсталлера). Также добавлены идемпотентность
    (-C || -A) и on-link маршрут для table 2000 (см. apply_iptables).
    """
    AWGS_CASCADE_DIR.mkdir(parents=True, exist_ok=True)
    exit_base = exit_subnet.split("/")[0].rsplit(".", 1)[0]
    exit_gw = f"{exit_base}.1"

    script = f"""#!/bin/bash
# AWG Cascade routing — пересоздаёт правила при старте системы
# Автоматически сгенерировано chimera/modules/awg_cascade.py (v5.4.5)
# Идемпотентно: безопасен при многократном запуске (-C || -A, replace).

# 1. Загрузить ipset из ru.zone
# v5.4.5: через `ipset restore` (один pipe) — построчный `ipset add`
# грузил 12k+ сетей МИНУТЫ; юнит теперь рестартует по PartOf и не
# должен подвешивать systemd надолго.
ipset create {AWGS_IPSET_NAME} hash:net family inet hashsize 4096 maxelem 65536 -exist
if [ -f "{AWGS_RU_ZONE_FILE}" ]; then
    grep -vE '^#|^$|;' "{AWGS_RU_ZONE_FILE}" | sed "s/^/add {AWGS_IPSET_NAME} /" | ipset restore -exist 2>/dev/null || true
fi

# 2. iptables правила (идентичны live-набору _awgs_cascade_apply_iptables)
# 2.1 v5.4.5 ГЛАВНЫЙ ФИКС: маркируем КЛИЕНТСКИЙ трафик в PREROUTING
#     (ДО route decision — метка в FORWARD ставилась ПОСЛЕ маршрутизации,
#     транзит уходил в main → DROP; метка в OUTPUT маркировала серверный
#     трафик — SSH-lockout). -i awg0 — только клиентский трафик.
iptables -t mangle -C PREROUTING -i awg0 -m set ! --match-set {AWGS_IPSET_NAME} dst -j MARK --set-mark {AWGS_CASCADE_FWMARK} 2>/dev/null || \
    iptables -t mangle -A PREROUTING -i awg0 -m set ! --match-set {AWGS_IPSET_NAME} dst -j MARK --set-mark {AWGS_CASCADE_FWMARK}
# подчистка старых FORWARD-MARK правил от предыдущих версий chimera
while iptables -t mangle -D FORWARD -i awg0 -m set ! --match-set {AWGS_IPSET_NAME} dst -j MARK --set-mark {AWGS_CASCADE_FWMARK} 2>/dev/null; do :; done
# 2.2 NAT для выхода через awg1
iptables -t nat -C POSTROUTING -o awg1 -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o awg1 -j MASQUERADE
# 2.3 FORWARD: клиенты → awg1 и обратно
iptables -C FORWARD -i awg0 -o awg1 -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i awg0 -o awg1 -j ACCEPT
iptables -C FORWARD -i awg1 -o awg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i awg1 -o awg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# 2.4 RU-сети — напрямую через host
iptables -C FORWARD -i awg0 -m set --match-set {AWGS_IPSET_NAME} dst -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i awg0 -m set --match-set {AWGS_IPSET_NAME} dst -j ACCEPT
# 2.5 v5.4.5: TCPMSS clamp (двойное туннелирование → effective MTU ~1200;
# без клампа TCP зависает на TLS-certs — MTU blackhole; E2E 2026-10-03)
iptables -t mangle -C FORWARD -i awg0 -o awg1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1140 2>/dev/null || \
    iptables -t mangle -A FORWARD -i awg0 -o awg1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1140
iptables -t mangle -C FORWARD -i awg1 -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1140 2>/dev/null || \
    iptables -t mangle -A FORWARD -i awg1 -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1140

# 3. Policy routing (v5.4.5: on-link подсеть перед default — иначе
#    "Nexthop has invalid gateway" при Address=base.N/32 + Table=off)
ip route replace {exit_base}.0/24 dev awg1 table 2000
ip route replace default via {exit_gw} dev awg1 table 2000
# v5.4.5: дедуп fwmark-правил (ядро не отклоняет дубли — они висят
# с разными автоприоритетами; E2E: после setup+reboot — 2 правила)
while ip rule del fwmark {AWGS_CASCADE_FWMARK} lookup 2000 2>/dev/null; do :; done
ip rule add fwmark {AWGS_CASCADE_FWMARK} lookup 2000

echo "AWG Cascade routing started"
"""
    AWGS_ROUTING_SCRIPT.write_text(script)
    AWGS_ROUTING_SCRIPT.chmod(0o755)


def _awgs_cascade_create_systemd_unit() -> None:
    """Создаёт systemd-юнит awg-cascade-routing.service.

    v5.4.5: PartOf=awg-quick@awg0/@awg1 — при рестарте/стопе этих юнитов
    routing-юнит рестартует вместе с ними и восстанавливает правила и
    table 2000. Иначе после `systemctl restart awg-quick@awg1` ядро
    удаляло маршруты удалённого dev awg1 из table 2000 (default via
    ... dev awg1 исчезал!) — каскад молча умирал: fwmark-трафик падал
    в main и уходил напрямую (E2E 2026-10-03 — корневая причина
    «неработающего» каскада у юзера после любого рестарта).
    """
    unit = f"""[Unit]
Description=AWG Cascade Routing (RU split-tunnel)
After=awg-quick@awg0.service awg-quick@awg1.service network.target
Wants=awg-quick@awg0.service awg-quick@awg1.service
PartOf=awg-quick@awg0.service awg-quick@awg1.service

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
    """Cron-задача: обновляет ru.zone и перезагружает ipset."""
    core = _core_module()
    core.log_to_file("INFO", "awgs_cascade_update_ru_zone: started")
    if not awgs_cascade_download_ru_zone():
        return False
    # Пересоздаём ipset
    core._run(["ipset", "destroy", AWGS_IPSET_NAME],
              check=False, quiet=True)
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
    core._box_row(f"  {core.GREEN}Server pubkey:{core.NC}  {state.get('server_pubkey', '?')}")
    core._box_row(f"  {core.GREEN}Cascade peer IP:{core.NC} {peer.get('client_ip', '?')}")
    core._box_row(f"  {core.GREEN}Cascade subnet:{core.NC}  {state.get('subnet', '?')}")
    # v5.4.5: параметры обфускации — КРИТИЧНО для handshake awg1
    # (должны совпадать на обеих сторонах; раньше не передавались)
    import json as _json
    _params_json = _json.dumps(state.get("params", {}), ensure_ascii=False)
    core._box_row(f"  {core.GREEN}Obfuscation (JSON):{core.NC}")
    core._box_row(f"  {_params_json}")
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

    # v5.4.5: IP пира cascade_entry на AWG1 (из бокса "Cascade peer IP").
    # Enter = base.2 (для чистого exit без других пиров).
    _base = exit_subnet.split("/")[0].rsplit(".", 1)[0]
    exit_peer_ip = input(f"{CYAN}Cascade peer IP на AWG1 [{_base}.2]: {NC}").strip() or f"{_base}.2"

    # v5.4.5: параметры обфускации AWG1 (строка Obfuscation из бокса AWG1).
    # Обфускация обязана совпадать на обеих сторонах — иначе handshake
    # никогда не сойдётся. Enter = параметры этого сервера (только если
    # вы УВЕРЕНЫ, что пресеты совпадают).
    exit_params = None
    _params_raw = input(f"{CYAN}Obfuscation JSON с AWG1 (Enter = как на этом сервере): {NC}").strip()
    if _params_raw:
        import json as _json
        try:
            exit_params = _json.loads(_params_raw)
        except Exception as e:
            warn(f"Некорректный JSON обфускации ({e}) — будут использованы "
                 "параметры этого сервера (handshake может не сойлись!)")
            exit_params = None

    print()
    confirm = input(f"{core.YELLOW}Настроить каскад с {exit_host}:{exit_port}? [y/N]: {NC}").strip().lower()
    if confirm not in ("y", "yes", "д", "да"):
        return

    awgs_cascade_setup_awg0(
        exit_host=exit_host,
        exit_port=exit_port,
        exit_pubkey=exit_pubkey,
        exit_subnet=exit_subnet,
        exit_peer_ip=exit_peer_ip,
        exit_params=exit_params,
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

        # Проверяем ipset
        r = core._run(["ipset", "list", AWGS_IPSET_NAME],
                      capture=True, check=False)
        if r.returncode == 0:
            import re
            m = re.search(r"Number of entries:\s+(\d+)", r.stdout)
            n = m.group(1) if m else "?"
            _box_row(f"  ipset {AWGS_IPSET_NAME}: {GREEN}{n} сетей{NC}")
        else:
            _box_row(f"  ipset {AWGS_IPSET_NAME}: {RED}не загружен{NC}")

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
