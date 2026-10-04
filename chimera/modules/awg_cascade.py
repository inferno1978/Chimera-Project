"""
chimera/modules/awg_cascade.py
───────────────────────────────────────────────────────────────────────────────
Каскад AmneziaWG: RU (вход) → зарубеж (выход). С v5.5.3 — МУЛЬТИ-EXIT:
несколько зарубежных выходов в одном каскаде, активен один awg1-туннель,
авто-failover переключает на следующий выход при смерти активного.

Схема (как в bivlked CASCADE.md):
  Клиент ──AWG──► AWG0 (RU, вход) ──┬──► российские сети напрямую (через host)
                                    └──► остальной трафик ──► awg1 ──► exit
                                             (exit = активный из cascade_exits:
                                              fi1 → de → nl1 → pl1 → ...)

Реализация:
  • Exit-нода: standalone AWG + спец-пир 'cascade_entry' (setup_awg1)
  • Entry-нода (RU): standalone AWG + клиентский туннель awg1 к АКТИВНОМУ
    exit + ipset RU-сетей + iptables/fwmark-маршрутизация + systemd-юнит
    + cron обновления ru.zone
  • Мульти-exit (v5.5.3): список cascade_exits в state (порядок = приоритет
    failover), awgs_cascade_activate_exit — переключение, таймер
    awg-cascade-failover.timer (health-тик каждую минуту) — авто-failover
    с двухступенчатой проверкой (handshake → ping → перебор кандидатов)

Весь трафик к российским сетям (из ru.zone) идёт напрямую через host,
остальной трафик маркируется fwmark=0x2000 и уходит через awg1 (туннель к
активному exit).
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
    AWGS_CASCADE_EXITS_KEY, AWGS_CASCADE_ACTIVE_KEY,
    AWGS_FAILOVER_SCRIPT, AWGS_SYSTEMD_FAILOVER_SVC,
    AWGS_SYSTEMD_FAILOVER_TIMER, AWGS_FAILOVER_STALE_SEC,
    AWGS_FAILOVER_PROBE_SEC, AWGS_FAILOVER_MAX_EXITS,
    AWGS_AWG1_CONF,
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
    exit_protocol_version: str = "",
    exit_name: str = "",
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

    v5.5 (AWG 3.1):
      • exit_protocol_version — версия протокола exit-ноды ("2.0"/"3.1"
        из бокса AWG1). Версии ОБЯЗАНЫ совпадать на обеих сторонах
        туннеля awg1 — при расхождении handshake не сойдётся (3.1-
        директивы обязаны быть на обоих концах или ни на одном).
        Пусто/отсутствие = "2.0" (совместимость со старыми боксами).
      • При 3.1 обфускация awg1.conf включает 9 транспортных директив
        из exit_params (HeaderProtectionKey и т.д. — полный JSON из
        бокса AWG1 уже содержит расширенный набор).
    """
    from .awg_protocol import (
        awg_is_31, awg_normalize_version, awg_protocol_label,
    )
    core = _core_module()
    info = core.info
    success = core.success
    warn = core.warn

    exit_protocol_version = awg_normalize_version(exit_protocol_version)

    # v5.5: версионная валидация — версии протокола entry и exit обязаны
    # совпадать (3.1-директивы синхронны на обоих концах или отсутствуют
    # на обоих). Расхождение = гарантированно мёртвый handshake.
    _own_protocol = awgs_state_load().get("protocol_version", "2.0")
    if awg_normalize_version(_own_protocol) != exit_protocol_version:
        warn(f"Версии протокола не совпадают: этот сервер — "
             f"{awg_protocol_label(_own_protocol)}, AWG1 — "
             f"{awg_protocol_label(exit_protocol_version)}.")
        warn("Обфускация awg1 обязана совпадать с exit — переустановите "
             "standalone AWG на этом сервере с той же версией протокола "
             "(меню установки → выбор версии).")
        return False

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

    # v5.5.8: IPv6-зеркало каскада — если v6 включён в standalone state
    # ЭТОЙ entry (allow_ipv6_tunnel), awg1 получает v6-адрес + ::/0,
    # весь клиентский v6 уходит через awg1 на exit (NAT66 на exit → GUA).
    from .awg_net_common import awg_v6_ula_from_subnet
    _own_v6 = bool(awgs_state_load().get("allow_ipv6_tunnel"))
    _cascade_v6 = awg_v6_ula_from_subnet(exit_subnet) if _own_v6 else ""

    # 1. Создаём конфиг awg1 (туннель к AWG1)
    info("Создание конфига awg1 (туннель к AWG1)...")
    if exit_params:
        info(f"Обфускация: используются параметры AWG1 (синхронизация, "
             f"{awg_protocol_label(exit_protocol_version)})")
    else:
        warn("Параметры обфускации AWG1 не переданы — используются "
             "параметры ЭТОГО сервера. Если пресет AWG1 отличается, "
             "handshake не сойдётся!")
    awg1_conf = _awgs_cascade_build_awg1_conf(
        exit_host, exit_port, exit_pubkey,
        exit_peer_privkey, exit_peer_psk, exit_subnet,
        exit_peer_ip=exit_peer_ip,
        exit_params=exit_params,
        exit_protocol_version=exit_protocol_version,
        allow_ipv6=bool(_cascade_v6),
    )
    awg1_path = AWGS_AWG1_CONF
    awg1_path.parent.mkdir(parents=True, exist_ok=True)
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
    _awgs_cascade_apply_iptables(exit_subnet, subnet_v6=_cascade_v6)

    # 5. Создаём awg-routing.sh (для пересоздания правил при ребуте)
    info("Создание awg-routing.sh + systemd-юнита...")
    _awgs_cascade_create_routing_script(exit_subnet, subnet_v6=_cascade_v6)
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

    # 8. v5.5.3: регистрируем exit в мульти-exit списке каскада
    #    (переключение/авто-failover). Дедуп — по имени и endpoint:port.
    _name = _awgs_cascade_slug_name(exit_name or exit_host)
    _exits = [e for e in awgs_state_load().get(AWGS_CASCADE_EXITS_KEY) or []
              if e.get("name") != _name
              and not (str(e.get("endpoint")) == exit_host
                       and int(e.get("port") or 0) == exit_port)]
    _exits.append({
        "name": _name,
        "endpoint": exit_host,
        "port": exit_port,
        "server_pubkey": exit_pubkey,
        "peer_privkey": exit_peer_privkey,
        "peer_psk": exit_peer_psk or "",
        "peer_ip": exit_peer_ip or "",
        "subnet": exit_subnet,
        "protocol_version": exit_protocol_version,
        "params": exit_params or {},
        "mtu": awgs_state_load().get("mtu", 1280),
        "added_at": _now_iso(),
    })
    _st = awgs_state_load()
    _st[AWGS_CASCADE_EXITS_KEY] = _exits
    _st[AWGS_CASCADE_ACTIVE_KEY] = _name
    awgs_state_save(_st)

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
    exit_protocol_version: str = "",
    allow_ipv6: bool = False,
    exit_peer_ipv6: str = "",
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

    v5.5 (AWG 3.1): exit_protocol_version="3.1" → после I1-I5 добавляются
    9 транспортных директив (HeaderProtectionKey/ContentPaddingAddition/
    Rekey*/... — из exit_params, тот же расширенный JSON из бокса AWG1).
    Пусто/"2.0" — конфиг байт-в-байт как в v5.4.5.
    """
    from .awg_protocol import awg_is_31, awg_render_31_lines
    base = exit_subnet.split("/")[0].rsplit(".", 1)[0]
    # v5.4.5: приоритет — явно переданный peer IP, fallback — base.2
    peer_addr = exit_peer_ip if exit_peer_ip else f"{base}.2"
    client_ip = f"{peer_addr}/32"

    # v5.5.8 (IPv6): v6-зеркало адреса awg1 в каскадной ULA-подсети
    # (fd66:66:<okt3>::/64 от exit_subnet). Тот же host-id, что у v4 —
    # гарантия совпадения с AllowedIPs пира cascade_entry_* на exit.
    client_ipv6 = ""
    if allow_ipv6:
        from .awg_net_common import awg_v6_ula_from_subnet, awg_v6_host_from_v4
        cascade_v6 = awg_v6_ula_from_subnet(exit_subnet)
        client_ipv6 = exit_peer_ipv6 or awg_v6_host_from_v4(peer_addr, cascade_v6)

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
    ]
    if allow_ipv6 and client_ipv6:
        # v5.5.8: v6-адрес awg1 (зеркало host-id) — нужен как source для
        # MASQUERADE v6 -o awg1 (NAT66 подставляет адрес интерфейса).
        lines.append(f"Address = {client_ipv6}/128")
    lines += [
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
    # v5.5 — AWG 3.1: 9 транспортных директив из exit_params (тот же
    # расширенный JSON обфускации из бокса AWG1). Правило v5.4.5 —
    # непустые «Key = value», пустые «# Key = ».
    if awg_is_31(exit_protocol_version):
        lines.append(awg_render_31_lines(params))
    # v5.5.8: при включённом v6 — ::/0 в AllowedIPs (cryptokey routing
    # пускает v6-пакеты в туннель; сами маршруты — через ip -6 rule)
    allowed_ips = "0.0.0.0/0, ::/0" if (allow_ipv6 and client_ipv6) else "0.0.0.0/0"
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {exit_pubkey}",
        f"Endpoint = {exit_host}:{exit_port}",
        f"AllowedIPs = {allowed_ips}",   # весь трафик (маршрутизация через iptables)
        "PersistentKeepalive = 25",
    ]
    if psk:
        lines.append(f"PresharedKey = {psk}")
    return "\n".join(lines) + "\n"


def _awgs_cascade_apply_iptables(exit_subnet: str, subnet_v6: str = "") -> bool:
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

    v5.5.8 (IPv6): при непустом subnet_v6 — v6-зеркало каскада:
    ВЕСЬ клиентский v6 (без RU-ipset — v6-ру-сетей в ru.zone нет, а
    весь v6 из РФ под TSPU-риском) → mark 0x2000 → ip -6 rule → table 2000
    → awg1 → exit, где NAT66 (MASQUERADE v6) выпускает в GUA exit-ноды.
    На entry MASQUERADE v6 -o awg1 переписывает src на v6-адрес awg1
    (fd66:66:<okt3>::X) — зеркало v4-дизайна каскада.
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

    # v5.5.8: IPv6-зеркало каскада — весь клиентский v6 через exit
    if subnet_v6:
        from .awg_net_common import apply_ipv6_forward
        apply_ipv6_forward(core)
        rules6 = [
            # Весь v6 из awg0 → mark 0x2000 (PREROUTING, до route decision —
            # тот же фикс v5.4.5, но для v6; RU-ipset для v6 не применяется:
            # в ru.zone v6-сетей нет, весь v6 из РФ под TSPU-риском → через exit)
            f"ip6tables -t mangle -A PREROUTING -i awg0 -j MARK --set-mark {AWGS_CASCADE_FWMARK}",
            # NAT66 на выходе в awg1: src → v6-адрес awg1 (зеркало v4-MASQUERADE)
            "ip6tables -t nat -A POSTROUTING -o awg1 -j MASQUERADE",
            # FORWARD: клиенты → awg1 и обратно
            "ip6tables -A FORWARD -i awg0 -o awg1 -j ACCEPT",
            "ip6tables -A FORWARD -i awg1 -o awg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            # TCPMSS clamp (двойное туннелирование — тот же 1140 что в v4)
            "ip6tables -t mangle -A FORWARD -i awg0 -o awg1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1140",
            "ip6tables -t mangle -A FORWARD -i awg1 -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1140",
        ]
        for rule in rules6:
            check = rule.replace(" -A ", " -C ", 1)
            r = core._run(["bash", "-c", f"{check} 2>/dev/null || {rule}"],
                          capture=True, check=False, quiet=True)
            if r.returncode != 0:
                core.log_to_file("WARN", f"ip6tables rule failed: {rule}: {r.stderr}")
        # v6 policy routing: fwmark → table 2000 → awg1 (default без via —
        # WG p2p onlink; v6-адрес подсети exit на awg1 не нужен для транзита)
        core._run(["ip", "-6", "route", "replace", "default", "dev", "awg1",
                   "table", "2000"], check=False, quiet=True)
        core._run(["bash", "-c",
                   f"while ip -6 rule del fwmark {AWGS_CASCADE_FWMARK} lookup 2000 2>/dev/null; do :; done; "
                   f"ip -6 rule add fwmark {AWGS_CASCADE_FWMARK} lookup 2000"],
                  check=False, quiet=True)
        # Контроль: default v6-маршрут в table 2000 реально встал
        r = core._run(["ip", "-6", "route", "show", "table", "2000"],
                      capture=True, check=False)
        if "default" not in (r.stdout or ""):
            core.log_to_file("ERROR", "cascade: table 2000 has no IPv6 default route!")
            core.warn("IPv6 default в table 2000 НЕ установлен — клиентский v6 "
                      "не уйдёт через awg1! Проверьте awg1 (Address v6).")

    return True


def _awgs_cascade_create_routing_script(exit_subnet: str,
                                        subnet_v6: str = "") -> None:
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
"""
    if subnet_v6:
        script += f"""
# 4. v5.5.8: IPv6-зеркало каскада — весь клиентский v6 → awg1 → exit
# (idempotent, идентично live-набору _awgs_cascade_apply_iptables)
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
ip6tables -t mangle -C PREROUTING -i awg0 -j MARK --set-mark {AWGS_CASCADE_FWMARK} 2>/dev/null || \
    ip6tables -t mangle -A PREROUTING -i awg0 -j MARK --set-mark {AWGS_CASCADE_FWMARK}
ip6tables -t nat -C POSTROUTING -o awg1 -j MASQUERADE 2>/dev/null || \
    ip6tables -t nat -A POSTROUTING -o awg1 -j MASQUERADE
ip6tables -C FORWARD -i awg0 -o awg1 -j ACCEPT 2>/dev/null || \
    ip6tables -A FORWARD -i awg0 -o awg1 -j ACCEPT
ip6tables -C FORWARD -i awg1 -o awg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    ip6tables -A FORWARD -i awg1 -o awg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -t mangle -C FORWARD -i awg0 -o awg1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1140 2>/dev/null || \
    ip6tables -t mangle -A FORWARD -i awg0 -o awg1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1140
ip6tables -t mangle -C FORWARD -i awg1 -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1140 2>/dev/null || \
    ip6tables -t mangle -A FORWARD -i awg1 -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1140
ip -6 route replace default dev awg1 table 2000
while ip -6 rule del fwmark {AWGS_CASCADE_FWMARK} lookup 2000 2>/dev/null; do :; done
ip -6 rule add fwmark {AWGS_CASCADE_FWMARK} lookup 2000
"""
    script += """
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
#  МУЛЬТИ-EXIT КАСКАД (v5.5.3)
#  RU (вход) → НЕСКОЛЬКО зарубежных выходов. Активен один awg1-туннель;
#  порядок cascade_exits = приоритет failover. Таймер раз в минуту
#  проверяет handshake активного exit и при его смерти переключает awg1
#  на следующий живой выход (awgs_cascade_failover_check).
# ============================================================================

def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _awgs_cascade_slug_name(name: str) -> str:
    """Имя exit-ноды → slug [A-Za-z0-9._-] (для state/меню/логов)."""
    slug = re.sub(r"[^A-Za-z0-9._-]", "-", (name or "").strip()).strip("-.")
    return slug or "exit-1"


def _awgs_cascade_exits_load() -> list:
    """Список exit-боксов из state + ленивая миграция legacy-каскада.

    Legacy (v5.4.x/v5.5.2): единственный exit хранился в плоских полях
    cascade_peer_*. При первом обращении синтезируем из них бокс и
    сохраняем в cascade_exits. Плоские поля остаются зеркалом активного
    exit (обратная совместимость чтения).
    """
    state = awgs_state_load()
    exits = state.get(AWGS_CASCADE_EXITS_KEY) or []
    if exits:
        return exits
    if state.get("cascade_role") == "entry" and state.get("cascade_peer_host"):
        box = {
            "name": _awgs_cascade_slug_name(state.get("cascade_peer_host")),
            "endpoint": state.get("cascade_peer_host", ""),
            "port": int(state.get("cascade_peer_port") or 51820),
            "server_pubkey": state.get("cascade_peer_pubkey", ""),
            "peer_privkey": state.get("cascade_peer_privkey", ""),
            "peer_psk": "",
            "peer_ip": "",
            "subnet": state.get("cascade_subnet", AWGS_DEFAULT_SUBNET),
            "protocol_version": state.get("protocol_version", "2.0"),
            "params": state.get("params", {}),
            "mtu": state.get("mtu", 1280),
            "added_at": _now_iso(),
        }
        exits = [box]
        state[AWGS_CASCADE_EXITS_KEY] = exits
        state[AWGS_CASCADE_ACTIVE_KEY] = box["name"]
        awgs_state_save(state)
    return exits


def _awgs_cascade_active_name(exits: list, state: dict) -> str:
    """Имя активного exit (с фолбэком на первый в списке)."""
    name = state.get(AWGS_CASCADE_ACTIVE_KEY, "")
    if name and any(e.get("name") == name for e in exits):
        return name
    return exits[0].get("name", "") if exits else ""


def awgs_cascade_register_exit(
    name: str = "",
    endpoint: str = "",
    port: int = 51820,
    server_pubkey: str = "",
    peer_privkey: str = "",
    peer_psk: str = "",
    peer_ip: str = "",
    subnet: str = "",
    protocol_version: str = "2.0",
    params: dict = None,
    mtu: int = 1280,
    activate: bool = False,
) -> bool:
    """Регистрирует exit-ноду в мульти-exit каскаде (v5.5.3).

    Бокс данных берётся с exit-ноды (awgs_cascade_setup_awg1 / меню
    «Настроить как AWG1»). Валидации те же, что в awgs_cascade_setup_awg0
    (версия протокола/подсеть/self-loop) — до записи в state. Дубликат
    по имени ИЛИ endpoint:port заменяется (обновление), а не плодится.
    Первый зарегистрированный exit становится активным автоматически.
    """
    from .awg_protocol import awg_normalize_version, awg_protocol_label
    core = _core_module()
    info = core.info
    warn = core.warn

    endpoint = (endpoint or "").strip()
    if not endpoint:
        warn("Endpoint host обязателен")
        return False
    name = _awgs_cascade_slug_name(name or endpoint)
    try:
        port = int(port)
    except (TypeError, ValueError):
        warn(f"Некорректный порт: {port!r}")
        return False
    if not (1 <= port <= 65535):
        warn(f"Порт вне диапазона 1-65535: {port}")
        return False
    if not (server_pubkey or "").strip():
        warn("Server pubkey exit-ноды обязателен")
        return False
    if not (peer_privkey or "").strip():
        warn("Cascade peer privkey обязателен (без него handshake "
             "невозможен: exit ждёт pubkey этого ключа)")
        return False

    protocol_version = awg_normalize_version(protocol_version)
    state = awgs_state_load()

    # Версии протокола entry и exit обязаны совпадать (3.1-директивы
    # синхронны на обоих концах или отсутствуют на обоих).
    _own_pv = awg_normalize_version(state.get("protocol_version", "2.0"))
    if _own_pv != protocol_version:
        warn(f"Версии протокола не совпадают: этот сервер — "
             f"{awg_protocol_label(_own_pv)}, exit '{name}' — "
             f"{awg_protocol_label(protocol_version)}.")
        return False

    # Self-loop
    try:
        _own_ip = core.get_server_ip("4")
    except Exception:
        _own_ip = ""
    if _own_ip and _own_ip == endpoint:
        warn(f"exit '{name}' указывает на этот же сервер (self-loop)")
        return False

    # Подсеть exit не должна совпадать с подсетью awg0 entry
    subnet = (subnet or "").strip() or AWGS_DEFAULT_SUBNET
    _own_subnet = state.get("subnet", "")
    if _own_subnet and _own_subnet == subnet:
        warn(f"Подсеть exit ({subnet}) совпадает с подсетью awg0 ({_own_subnet})")
        return False

    if not params:
        warn("Параметры обфускации exit не переданы — awg1 возьмёт "
             "параметры ЭТОГО сервера (handshake может не сойтись!)")

    exits = _awgs_cascade_exits_load()
    # Дедуп по имени И по endpoint:port — обновление бокса, а не клон
    exits = [e for e in exits
             if e.get("name") != name
             and not (str(e.get("endpoint")) == endpoint
                      and int(e.get("port") or 0) == port)]
    if len(exits) + 1 > AWGS_FAILOVER_MAX_EXITS:
        warn(f"Слишком много exit-нод (максимум {AWGS_FAILOVER_MAX_EXITS})")
        return False

    box = {
        "name": name,
        "endpoint": endpoint,
        "port": port,
        "server_pubkey": server_pubkey.strip(),
        "peer_privkey": peer_privkey.strip(),
        "peer_psk": (peer_psk or "").strip(),
        "peer_ip": (peer_ip or "").strip(),
        "subnet": subnet,
        "protocol_version": protocol_version,
        "params": params or {},
        "mtu": int(mtu or 1280),
        "added_at": _now_iso(),
    }
    exits.append(box)
    state = awgs_state_load()
    state[AWGS_CASCADE_EXITS_KEY] = exits
    if not state.get(AWGS_CASCADE_ACTIVE_KEY):
        state[AWGS_CASCADE_ACTIVE_KEY] = name
    awgs_state_save(state)
    info(f"Exit-нода '{name}' ({endpoint}:{port}, "
         f"{awg_protocol_label(protocol_version)}) добавлена в каскад "
         f"(всего exit: {len(exits)})")

    if activate or len(exits) == 1:
        return awgs_cascade_activate_exit(name)
    return True


def awgs_cascade_activate_exit(name: str, probe_timeout: int = 0) -> bool:
    """Переключает awg1-туннель на exit-ноду `name` из cascade_exits.

    Меняется только [Interface]-ключ + [Peer]-секция awg1.conf (Endpoint/
    PublicKey/обфускация) — маршрутизация (fwmark 0x2000 → table 2000 →
    awg1) не меняется. routing-скрипт перегенерируется под подсеть exit
    (все exit обычно в одной подсети 172.16.91.0/24 — тогда no-op).

    probe_timeout > 0 — ждать handshake/ping после переключения (используется
    failover-пробой кандидатов).
    """
    core = _core_module()
    info = core.info
    warn = core.warn

    exits = _awgs_cascade_exits_load()
    box = next((e for e in exits if e.get("name") == name), None)
    if box is None:
        warn(f"Exit-нода '{name}' не найдена в списке каскада")
        return False

    subnet = box.get("subnet", AWGS_DEFAULT_SUBNET)

    # v5.5.8: v6-зеркало каскада — пробросляем флаг из standalone state
    # (переключение exit не должно молча выключать IPv6-туннель)
    from .awg_net_common import awg_v6_ula_from_subnet
    _v6_on = bool(awgs_state_load().get("allow_ipv6_tunnel"))
    _cascade_v6 = awg_v6_ula_from_subnet(subnet) if _v6_on else ""

    # 1. awg1.conf из бокса exit (обфускация/версия — синхронно с exit)
    conf = _awgs_cascade_build_awg1_conf(
        exit_host=box.get("endpoint", ""),
        exit_port=int(box.get("port", 51820)),
        exit_pubkey=box.get("server_pubkey", ""),
        client_privkey=box.get("peer_privkey", ""),
        psk=box.get("peer_psk", "") or "",
        exit_subnet=subnet,
        exit_peer_ip=box.get("peer_ip", ""),
        exit_params=box.get("params") or None,
        exit_protocol_version=box.get("protocol_version", "2.0"),
        allow_ipv6=bool(_cascade_v6),
    )
    awg1_path = AWGS_AWG1_CONF
    awg1_path.parent.mkdir(parents=True, exist_ok=True)
    awg1_path.write_text(conf)
    awg1_path.chmod(0o600)

    # 2. Routing-скрипт под подсеть exit + рестарт туннеля
    #    (PartOf=awg-quick@awg1 перезапустит routing-юнит и пересоздаст
    #    table 2000; явный restart — страховка для старых юнит-файлов)
    _awgs_cascade_create_routing_script(subnet, subnet_v6=_cascade_v6)
    core._run(["systemctl", "enable", "awg-quick@awg1"], check=False, quiet=True)
    r = core._run(["systemctl", "restart", "awg-quick@awg1"],
                  capture=True, check=False)
    if r.returncode != 0:
        warn(f"awg1 не перезапустился: {r.stderr}")
        return False
    core._run(["systemctl", "restart", "awg-cascade-routing"],
              check=False, quiet=True)

    # 3. state: активный exit + зеркало legacy-полей (обратная совместимость)
    state = awgs_state_load()
    state[AWGS_CASCADE_EXITS_KEY] = exits
    state[AWGS_CASCADE_ACTIVE_KEY] = name
    state["cascade_peer_host"] = box.get("endpoint", "")
    state["cascade_peer_port"] = int(box.get("port", 51820))
    state["cascade_peer_pubkey"] = box.get("server_pubkey", "")
    state["cascade_peer_privkey"] = box.get("peer_privkey", "")
    state["cascade_subnet"] = subnet
    awgs_state_save(state)
    info(f"Активный exit каскада: {name} ({box.get('endpoint')}:{box.get('port')})")

    # 4. Проба живости (failover-кандидаты): ждём свежий handshake или ping
    if probe_timeout and probe_timeout > 0:
        deadline = time.time() + probe_timeout
        while time.time() < deadline:
            time.sleep(3)
            age = awgs_cascade_handshake_age()
            if age is not None and age <= 30:
                return True
            if _awgs_cascade_probe_alive(subnet):
                return True
        return False
    return True


def awgs_cascade_remove_exit(name: str) -> bool:
    """Удаляет exit-ноду из списка каскада.

    Если удаляли активную — активируется первая оставшаяся (awg1
    переключается немедленно, чтобы каскад не смотрел в пустоту).
    """
    core = _core_module()
    warn = core.warn
    exits = _awgs_cascade_exits_load()
    if not any(e.get("name") == name for e in exits):
        warn(f"Exit-нода '{name}' не найдена")
        return False
    was_active = _awgs_cascade_active_name(exits, awgs_state_load()) == name
    exits = [e for e in exits if e.get("name") != name]
    state = awgs_state_load()
    state[AWGS_CASCADE_EXITS_KEY] = exits
    if state.get(AWGS_CASCADE_ACTIVE_KEY) == name:
        state[AWGS_CASCADE_ACTIVE_KEY] = exits[0].get("name", "") if exits else ""
    awgs_state_save(state)
    if was_active and exits:
        return awgs_cascade_activate_exit(exits[0].get("name", ""))
    return True


def _awgs_cascade_parse_handshake_age(text: str):
    """Парсит вывод `awg show` → возраст handshake в секундах.

    "latest handshake: 1 minute, 25 seconds ago" → 85
    Нет строки handshake (туннель свежий/мёртвый) → None.
    Чистая функция (тестируется без сервера).
    """
    m = re.search(r"latest handshake:\s*(.+?)\s+ago", text or "")
    if not m:
        return None
    total, found = 0, False
    for part in m.group(1).split(","):
        pm = re.match(r"(\d+)\s+(second|minute|hour|day|week)s?",
                      part.strip())
        if pm:
            found = True
            mult = {"second": 1, "minute": 60, "hour": 3600,
                    "day": 86400, "week": 604800}[pm.group(2)]
            total += int(pm.group(1)) * mult
    return total if found else None


def awgs_cascade_handshake_age():
    """Возраст последнего handshake awg1 (сек) или None (не было/нет awg1)."""
    core = _core_module()
    r = core._run(["awg", "show", "awg1"], capture=True, check=False)
    if r.returncode != 0:
        return None
    return _awgs_cascade_parse_handshake_age(r.stdout or "")


def _awgs_cascade_probe_alive(subnet: str) -> bool:
    """Пинг-проба шлюза exit через awg1 (ICMP отвечает ядро exit-ноды)."""
    core = _core_module()
    base = (subnet or AWGS_DEFAULT_SUBNET).split("/")[0].rsplit(".", 1)[0]
    gw = f"{base}.1"
    r = core._run(["ping", "-n", "-I", "awg1", "-c", "2", "-W", "2", gw],
                  capture=True, check=False)
    return r.returncode == 0


def _awgs_cascade_failover_notify(detail: str) -> None:
    """Best-effort TG-уведомление о failover-событии (не бросает исключений)."""
    try:
        from .tg_bot import tg_notify_event
        tg_notify_event("awg_failover", detail)
    except Exception:
        pass


def awgs_cascade_failover_check() -> str:
    """Health-тик мульти-exit каскада (таймер раз в минуту).

    Логика (двухступенчатая защита от ложных срабатываний):
      1. handshake свежий (<= AWGS_FAILOVER_STALE_SEC) → "ok"
      2. handshake несвежий, но ping шлюза через awg1 жив → "ok-probe"
      3. туннель мёртв → перебор exit-кандидатов ПО ПОРЯДКУ СПИСКА
         (после активного); первый давший handshake → "failover:<name>"
      4. никто не ответил → восстановить исходный → "all-dead"

    Возвращает строку-действие (для логов/тестов): not-entry |
    single-exit | ok | ok-probe | failover:<name> | all-dead.
    """
    core = _core_module()
    state = awgs_state_load()
    if state.get("cascade_role") != "entry":
        return "not-entry"
    exits = _awgs_cascade_exits_load()
    if len(exits) < 2:
        return "single-exit"

    active = _awgs_cascade_active_name(exits, state)

    age = awgs_cascade_handshake_age()
    if age is not None and age <= AWGS_FAILOVER_STALE_SEC:
        return "ok"

    active_box = next((e for e in exits if e.get("name") == active), exits[0])
    if _awgs_cascade_probe_alive(active_box.get("subnet", AWGS_DEFAULT_SUBNET)):
        return "ok-probe"

    core.log_to_file(
        "WARN",
        f"awg-cascade-failover: активный exit '{active}' не отвечает "
        f"(handshake age={age}s, ping fail) — перебор кандидатов")
    for cand in [e for e in exits if e.get("name") != active]:
        _name = cand.get("name", "?")
        if awgs_cascade_activate_exit(_name, probe_timeout=AWGS_FAILOVER_PROBE_SEC):
            core.log_to_file(
                "INFO",
                f"awg-cascade-failover: переключение на '{_name}' успешно")
            _awgs_cascade_failover_notify(
                f"AWG-каскад: авто-failover → <b>{_name}</b> "
                f"({cand.get('endpoint')}:{cand.get('port')})")
            return f"failover:{_name}"

    # Все кандидаты молчат — возвращаем исходный (стабильность приоритетов)
    awgs_cascade_activate_exit(active, probe_timeout=0)
    core.log_to_file(
        "ERROR",
        "awg-cascade-failover: все exit-ноды недоступны — восстановлен "
        "исходный exit, ждём восстановления сети")
    _awgs_cascade_failover_notify(
        "AWG-каскад: failover не удался — все exit-ноды недоступны, "
        "восстановлен исходный")
    return "all-dead"


def awgs_cascade_failover_setup() -> bool:
    """Создаёт и запускает failover-таймер (ежеминутный health-тик).

    Wrapper-скрипт PYTHONPATH-safe (тот же паттерн, что
    _awgs_cascade_setup_cron — bare python3 -c из-под systemd падает с
    ModuleNotFoundError). Лог — в /root/awg/awg_standalone.log.
    """
    core = _core_module()
    try:
        import importlib.util
        spec = importlib.util.find_spec("chimera")
        if spec and spec.submodule_search_locations:
            installer_path = str(
                Path(list(spec.submodule_search_locations)[0]).parent)
        else:
            installer_path = "/opt/chimera"
    except Exception:
        installer_path = "/opt/chimera"

    wrapper = (
        "#!/bin/bash\n"
        "# AWG cascade multi-exit failover — health-тик (v5.5.3).\n"
        "mkdir -p /root/awg\n"
        f"export PYTHONPATH=\"{installer_path}:$PYTHONPATH\"\n"
        f"/usr/bin/python3 -c \"\n"
        f"import sys\n"
        f"sys.path.insert(0, '{installer_path}')\n"
        f"from chimera.modules.awg_cascade import awgs_cascade_failover_check\n"
        f"awgs_cascade_failover_check()\n"
        f"\" >> /root/awg/awg_standalone.log 2>&1\n"
    )
    AWGS_FAILOVER_SCRIPT.write_text(wrapper)
    AWGS_FAILOVER_SCRIPT.chmod(0o755)

    AWGS_SYSTEMD_FAILOVER_SVC.write_text(
        "[Unit]\n"
        "Description=AWG Cascade failover check (multi-exit health)\n"
        "After=awg-quick@awg1.service\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={AWGS_FAILOVER_SCRIPT}\n"
    )
    AWGS_SYSTEMD_FAILOVER_TIMER.write_text(
        "[Unit]\n"
        "Description=AWG Cascade multi-exit failover (health-тик каждую минуту)\n"
        "\n"
        "[Timer]\n"
        "OnCalendar=*:0/1\n"
        "AccuracySec=10s\n"
        "Persistent=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )

    core._run(["systemctl", "daemon-reload"], check=False, quiet=True)
    core._run(["systemctl", "enable", "--now", "awg-cascade-failover.timer"],
              capture=True, check=False)
    r = core._run(["systemctl", "is-active", "awg-cascade-failover.timer"],
                  capture=True, check=False)
    return (r.stdout or "").strip() == "active"


def awgs_cascade_failover_teardown() -> bool:
    """Останавливает и удаляет failover-таймер/сервис/wrapper."""
    core = _core_module()
    for unit in ("awg-cascade-failover.timer", "awg-cascade-failover.service"):
        core._run(["systemctl", "stop", unit], check=False, quiet=True)
        core._run(["systemctl", "disable", unit], check=False, quiet=True)
    AWGS_SYSTEMD_FAILOVER_TIMER.unlink(missing_ok=True)
    AWGS_SYSTEMD_FAILOVER_SVC.unlink(missing_ok=True)
    AWGS_FAILOVER_SCRIPT.unlink(missing_ok=True)
    core._run(["systemctl", "daemon-reload"], check=False, quiet=True)
    return True


# ============================================================================
#  AWG1 (выход) — спец-пир для AWG0
# ============================================================================

def awgs_cascade_enable_ipv6() -> bool:
    """
    v5.5.8: включает v6-зеркало каскада на УЖЕ настроенной entry-ноде —
    без переустановки каскада (upgrade-путь для живых установок).

    Что делает:
      1. Патчит awg1.conf: добавляет Address v6/128 (зеркало host-id
         из текущего v4-адреса awg1 в каскадной ULA fd66:66:<okt3>::/64)
         и ::/0 в AllowedIPs пира.
      2. Рестарт awg-quick@awg1 — интерфейс получает v6-адрес (source
         для MASQUERADE v6 -o awg1).
      3. Применяет ip6tables-зеркало (MARK 0x2000 в PREROUTING для всего
         клиентского v6 + FORWARD + TCPMSS + NAT66 -o awg1) и
         ip -6 rule fwmark → table 2000 → default dev awg1.
      4. Перегенерирует awg-routing.sh с v6-частью (переживает ребут).

    Вызывается из awg_standalone.awgs_enable_ipv6() при cascade_role == "entry".
    """
    core = _core_module()
    info = core.info
    warn = core.warn
    success = core.success

    from .awg_net_common import awg_v6_ula_from_subnet, awg_v6_host_from_v4

    if not AWGS_AWG1_CONF.exists():
        warn("awg1.conf не найден — каскад не настроен на этой ноде")
        return False

    state = awgs_state_load()
    exit_subnet = state.get("cascade_subnet", "")
    if not exit_subnet:
        warn("cascade_subnet не найден в state — перенастройте каскад")
        return False

    cascade_v6 = awg_v6_ula_from_subnet(exit_subnet)

    # 1. Патчим awg1.conf: Address v6 + AllowedIPs ::/0 (idempotent)
    conf_lines = AWGS_AWG1_CONF.read_text().splitlines()
    v4_addr = next((l.split("=", 1)[1].strip().split("/")[0]
                    for l in conf_lines if l.startswith("Address = ")), "")
    v6_addr = awg_v6_host_from_v4(v4_addr, cascade_v6)
    if not v6_addr:
        warn(f"Не удалось вычислить v6-адрес awg1 (v4={v4_addr!r}, "
             f"подсеть={cascade_v6})")
        return False

    out, v6_added = [], False
    for line in conf_lines:
        if line.startswith(f"Address = {v6_addr}/128"):
            v6_added = True  # уже есть (повторный запуск)
            out.append(line)
            continue
        if line.startswith("Address = ") and not v6_added:
            out.append(line)
            out.append(f"Address = {v6_addr}/128")
            v6_added = True
            continue
        if line.strip() == "AllowedIPs = 0.0.0.0/0":
            out.append("AllowedIPs = 0.0.0.0/0, ::/0")
            continue
        out.append(line)
    if not v6_added:
        warn("Не найден Address в awg1.conf — каскад повреждён")
        return False
    AWGS_AWG1_CONF.write_text("\n".join(out) + "\n")
    AWGS_AWG1_CONF.chmod(0o600)
    info(f"awg1.conf: Address {v6_addr}/128 + AllowedIPs ::/0")

    # 2. Рестарт awg1 — перечитывает Address (краткий блэкаут каскада ~1с)
    r = core._run(["systemctl", "restart", "awg-quick@awg1"],
                  capture=True, check=False)
    if r.returncode != 0:
        warn(f"awg1 не перезапустился: {r.stderr}")
        return False

    # 3. ip6tables-зеркало + policy routing v6
    _awgs_cascade_apply_iptables(exit_subnet, subnet_v6=cascade_v6)

    # 4. Перманентность: routing-скрипт с v6-частью
    _awgs_cascade_create_routing_script(exit_subnet, subnet_v6=cascade_v6)
    core._run(["systemctl", "restart", "awg-cascade-routing"],
              check=False, quiet=True)

    success(f"Каскадный IPv6 включён: awg1 = {v6_addr}/128, "
            f"весь клиентский v6 → exit ({exit_subnet} → {cascade_v6})")
    return True


def awgs_cascade_setup_awg1(protocol_version: str = "2.0") -> bool:
    """
    Настраивает AWG1 (выход каскада):
      • Стандартная установка standalone AWG (если ещё не установлен)
      • Создаёт спец-пир 'cascade_entry' для подключения AWG0
      • Возвращает данные для настройки AWG0 (host/port/pubkey)

    v5.5: protocol_version="3.1" — установка exit на AWG 3.1 (полный
    3.1-набор обфускации + директивы в awg0.conf). Бокс данных для AWG0
    теперь содержит строку Protocol version + расширенный JSON обфускации
    (включая HeaderProtectionKey и таймеры для 3.1).
    """
    from .awg_protocol import awg_normalize_version, awg_protocol_label
    core = _core_module()
    info = core.info
    success = core.success
    warn = core.warn

    protocol_version = awg_normalize_version(protocol_version)

    # Если standalone AWG не установлен — устанавливаем (с выбранной версией)
    if not awgs_state_is_installed():
        info(f"Установка standalone {awg_protocol_label(protocol_version)} "
             f"на этом сервере (AWG1, выход)...")
        if not awgs_install(protocol_version=protocol_version):
            warn("Установка standalone AWG не удалась")
            return False
    else:
        # v5.5: если уже установлен — проверяем совпадение версий
        _installed_v = awgs_state_load().get("protocol_version", "2.0")
        if awg_normalize_version(_installed_v) != protocol_version:
            warn(f"Standalone AWG на этом сервере — {awg_protocol_label(_installed_v)}, "
                 f"а запрошено {awg_protocol_label(protocol_version)} для каскада.")
            warn("Каскад требует одинаковой версии на обоих концах. "
                 "Переустановите standalone AWG с нужной версией или "
                 "используйте текущую.")
            # Продолжаем с ФАКТИЧЕСКОЙ версией установки — бокс данных
            # должен отражать реальность (иначе AWG0 получит неверные
            # параметры для синхронизации).
            protocol_version = awg_normalize_version(_installed_v)
            info(f"Бокс данных будет сформирован для "
                 f"{awg_protocol_label(protocol_version)} (фактическая версия)")

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
    # v5.5.8: v6-зеркало пира (если v6 включён на ЭТОМ exit) — передаётся
    # на AWG0 для сверки с Address v6 в awg1.conf (host-id совпадает с v4)
    if peer.get("client_ipv6"):
        core._box_row(f"  {core.GREEN}Cascade peer IPv6:{core.NC} {peer['client_ipv6']}")
    core._box_row(f"  {core.GREEN}Cascade subnet:{core.NC}  {state.get('subnet', '?')}")
    # v5.5.3 FIX-E: privkey пира cascade_entry — ОБЯЗАТЕЛЬНАЯ часть бокса.
    # AWG0 подставляет его в [Interface] awg1.conf; без него exit ждёт
    # чужой pubkey и handshake никогда не сойдётся (TUI-флоу был сломан —
    # ключ генерировался заново на entry, см. _awgs_cascade_menu_awg0).
    core._box_row(f"  {core.GREEN}Cascade peer privkey:{core.NC}")
    core._box_row(f"  {peer.get('client_privkey', '?')}")
    # v5.5: версия протокола — ОБЯЗАТЕЛЬНА для передачи на AWG0 (при
    # расхождении версий handshake не сойдётся)
    core._box_row(f"  {core.GREEN}Protocol version:{core.NC} {protocol_version}")
    # v5.4.5: параметры обфускации — КРИТИЧНО для handshake awg1
    # (должны совпадать на обеих сторонах; раньше не передавались).
    # Для 3.1 JSON содержит и 9 транспортных параметров.
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
            from .awg_protocol import awg_protocol_label
            _pv = state.get("protocol_version", "2.0")
            _box_row(f"  {GREEN}● Текущая роль:{NC} {role} "
                     f"({awg_protocol_label(_pv)})")
        else:
            _box_row(f"  {DIM}○ Каскад не настроен{NC}")
        _box_row()
        _box_item("1", f"Настроить как AWG0 (вход, РФ)")
        _box_desc("Этот сервер принимает клиентов и делит трафик: RU напрямую, остальное через AWG1.")
        _box_item("2", f"Настроить как AWG1 (выход, зарубеж) — 2.0 / 3.1")
        _box_desc("Этот сервер — зарубежный exit. Создаст спец-пир для AWG0. "
                  "Версия протокола выбирается перед настройкой.")
        _box_item("3", f"Обновить ru.zone вручную")
        _box_desc("Принудительное обновление списка российских сетей с ipdeny.com.")
        _box_item("4", f"Проверить состояние каскада")
        _box_item("5", f"Мульти-exit: все выходы + авто-failover")
        _box_desc("Несколько зарубежных exit в одном каскаде: активен один, "
                  "при смерти активного таймер переключает на следующий. "
                  "Порядок списка = приоритет.")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            _awgs_cascade_menu_awg0()
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            # v5.5: выбор версии протокола перед настройкой exit
            _pv = _awgs_cascade_prompt_exit_version()
            awgs_cascade_setup_awg1(protocol_version=_pv)
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
        elif ch == "5":
            _awgs_cascade_menu_multiexit()
        elif ch in ("q", ""):
            break


def _awgs_cascade_prompt_exit_version() -> str:
    """v5.5: выбор версии протокола exit-ноды (AWG1) перед настройкой.

    Возвращает "2.0" или "3.1".
    """
    from .awg_protocol import AWG_VERSION_20, AWG_VERSION_31
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_item = core._box_item
    _box_desc = core._box_desc
    _box_bottom = core._box_bottom
    CYAN, NC, GREEN, YELLOW, DIM = core.CYAN, core.NC, core.GREEN, core.YELLOW, core.DIM

    print()
    _box_top(f"Версия протокола AWG1 (выход каскада)")
    _box_row()
    _box_item("1", f"AmneziaWG 2.0 {GREEN}(Enter — по умолчанию){NC}")
    _box_desc("Каскад на 2.0 — максимальная совместимость инструментов.")
    _box_item("2", f"AmneziaWG 3.1 {YELLOW}(transport protection){NC}")
    _box_desc("Каскад на 3.1 — шифрование заголовков + паддинг + "
              "рандомизация таймеров на транзитном канале. "
              "AWG0 (вход) должен быть переустановлен с той же версией!")
    _box_row()
    _box_bottom()
    while True:
        ch = input(f"{CYAN}Версия протокола AWG1 [1/2, Enter=1]:{NC} ").strip()
        if ch in ("", "1"):
            return AWG_VERSION_20
        if ch == "2":
            return AWG_VERSION_31
        core.warn("Введите 1 или 2")


def _awgs_cascade_menu_awg0() -> None:
    """Подменю настройки AWG0 (вход каскада)."""
    from .awg_protocol import awg_normalize_version
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

    # v5.5.3 FIX-E: privkey пира cascade_entry (строка «Cascade peer
    # privkey» из бокса AWG1). КРИТИЧНО: exit ждёт pubkey именно этого
    # ключа в своём [Peer]. Раньше промпта не было и setup_awg0 молча
    # генерировал НОВЫЙ ключ — handshake никогда не сходился в TUI-флоу.
    exit_peer_privkey = input(
        f"{CYAN}Cascade peer privkey с AWG1 (строка из бокса): {NC}").strip()
    if not exit_peer_privkey:
        warn("Без peer privkey с AWG1 handshake НЕ сойдётся (exit ждёт "
             "pubkey этого ключа). Будет сгенерирован новый ключ — "
             "потребуется пересоздать cascade_entry на AWG1 с ним.")

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

    # v5.5: версия протокола AWG1 (строка Protocol version из бокса AWG1).
    # Обязательна для 3.1-каскада — версии должны совпадать на обоих концах.
    _pv_raw = input(f"{CYAN}Версия протокола AWG1 [1=2.0, 2=3.1, Enter=2.0]: {NC}").strip()
    exit_protocol_version = "3.1" if _pv_raw == "2" else "2.0"

    print()
    confirm = input(f"{core.YELLOW}Настроить каскад с {exit_host}:{exit_port}? [y/N]: {NC}").strip().lower()
    if confirm not in ("y", "yes", "д", "да"):
        return

    awgs_cascade_setup_awg0(
        exit_host=exit_host,
        exit_port=exit_port,
        exit_pubkey=exit_pubkey,
        exit_subnet=exit_subnet,
        exit_peer_privkey=exit_peer_privkey,
        exit_peer_ip=exit_peer_ip,
        exit_params=exit_params,
        exit_protocol_version=exit_protocol_version,
    )


def _awgs_cascade_menu_multiexit() -> None:
    """v5.5.3: управление мульти-exit каскадом (список выходов + failover)."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_sep = core._box_sep
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    _box_desc = core._box_desc
    info = core.info
    warn = core.warn
    success = core.success
    CYAN, NC, GREEN, YELLOW, DIM = core.CYAN, core.NC, core.GREEN, core.YELLOW, core.DIM

    while True:
        import os
        os.system("clear")
        print()
        exits = _awgs_cascade_exits_load()
        state = awgs_state_load()
        active = _awgs_cascade_active_name(exits, state)

        _box_top(f"Мульти-exit каскад — все выходы + авто-failover")
        _box_row()
        _box_desc("RU (вход) ──awg1──► активный exit; при его смерти таймер")
        _box_desc("переключает туннель на следующий по списку (1 раз/мин).")
        _box_row()
        if exits:
            _box_row(f"  Exit-ноды ({len(exits)}), активный: "
                     f"{GREEN}{active or '—'}{NC}")
            for e in exits:
                mark = f"{GREEN}●{NC}" if e.get("name") == active else f"{DIM}○{NC}"
                _box_row(f"    {mark} {e.get('name')} — {e.get('endpoint')}:"
                         f"{e.get('port')} ({e.get('protocol_version', '2.0')})")
        else:
            _box_row(f"  {DIM}Exit-ноды не заданы — добавьте первый{NC}")
        r = core._run(["systemctl", "is-active", "awg-cascade-failover.timer"],
                      capture=True, check=False)
        timer_on = (r.stdout or "").strip() == "active"
        _box_row(f"  Авто-failover: "
                 f"{GREEN}включён{NC}" if timer_on else f"  Авто-failover: {DIM}выключен{NC}")
        _box_row()
        _box_item("1", "Добавить/обновить exit (бокс данных с AWG1)")
        _box_item("2", "Переключить активный exit")
        _box_item("3", "Удалить exit")
        _box_item("4", "Авто-failover: включить (health-тик каждую минуту)")
        _box_item("5", "Авто-failover: выключить")
        _box_item("Q", "Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            _awgs_cascade_menu_exit_add(active)
        elif ch == "2":
            if not exits:
                warn("Список exit пуст")
                input(f"{core.BLUE}Нажмите Enter...{NC}")
                continue
            print()
            for i, e in enumerate(exits, 1):
                mark = "●" if e.get("name") == active else " "
                print(f"  [{i}] {mark} {e.get('name')} — {e.get('endpoint')}:"
                      f"{e.get('port')}")
            pick = input(f"{CYAN}Номер exit для активации:{NC} ").strip()
            if pick.isdigit() and 1 <= int(pick) <= len(exits):
                name = exits[int(pick) - 1].get("name", "")
                if awgs_cascade_activate_exit(name):
                    success(f"Активный exit: {name}")
                else:
                    warn(f"Не удалось переключиться на {name} (см. лог)")
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            if not exits:
                warn("Список exit пуст")
                input(f"{core.BLUE}Нажмите Enter...{NC}")
                continue
            name = input(f"{CYAN}Имя exit для удаления:{NC} ").strip()
            if name:
                if awgs_cascade_remove_exit(name):
                    success(f"Exit '{name}' удалён")
                else:
                    warn(f"Не удалось удалить '{name}'")
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            if awgs_cascade_failover_setup():
                success("Авто-failover включён (таймер каждую минуту)")
            else:
                warn("Не удалось включить failover-таймер (см. лог)")
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            awgs_cascade_failover_teardown()
            info("Авто-failover выключен, юниты удалены")
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch in ("q", ""):
            break


def _awgs_cascade_menu_exit_add(active: str) -> None:
    """Промпты добавления/обновления exit-ноды в мульти-exit каскад."""
    core = _core_module()
    info = core.info
    warn = core.warn
    CYAN, NC, YELLOW = core.CYAN, core.NC, core.YELLOW

    print()
    info("Добавление exit-ноды. Все данные — из бокса «Данные для")
    info("настройки AWG0» на exit-ноде (меню каскада → «Настроить как AWG1»).")
    print()
    name = input(f"{CYAN}Имя exit (например de/nl1/pl1/fi1): {NC}").strip()
    endpoint = input(f"{CYAN}Endpoint host: {NC}").strip()
    if not endpoint:
        warn("Endpoint обязателен")
        return
    port_str = input(f"{CYAN}UDP-порт [52831]: {NC}").strip()
    port = int(port_str) if port_str.isdigit() else 52831
    server_pubkey = input(f"{CYAN}Server pubkey: {NC}").strip()
    peer_privkey = input(f"{CYAN}Cascade peer privkey: {NC}").strip()
    peer_ip = input(f"{CYAN}Cascade peer IP [172.16.91.2]: {NC}").strip() or "172.16.91.2"
    subnet = input(f"{CYAN}Cascade subnet [172.16.91.0/24]: {NC}").strip() or "172.16.91.0/24"

    import json as _json
    params = None
    _params_raw = input(f"{CYAN}Obfuscation JSON с exit (обязателен): {NC}").strip()
    if _params_raw:
        try:
            params = _json.loads(_params_raw)
        except Exception as e:
            warn(f"Некорректный JSON ({e})")
            return
    else:
        warn("Obfuscation JSON обязателен — параметры обязаны совпадать с exit")

    _pv_raw = input(f"{CYAN}Версия протокола exit [1=2.0, 2=3.1, Enter=3.1]: {NC}").strip()
    protocol_version = "2.0" if _pv_raw == "1" else "3.1"

    first = not _awgs_cascade_exits_load()
    activate_default = "n" if (not first and active) else "y"
    act = input(f"{CYAN}Активировать сразу? [Y/n]: {NC}").strip().lower()
    activate = (act not in ("n", "no", "н", "нет")) if act else (activate_default == "y")

    print()
    if awgs_cascade_register_exit(
        name=name, endpoint=endpoint, port=port,
        server_pubkey=server_pubkey, peer_privkey=peer_privkey,
        peer_ip=peer_ip, subnet=subnet, protocol_version=protocol_version,
        params=params, activate=activate,
    ):
        core.success(f"Exit '{name or endpoint}' добавлен")


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
        from .awg_protocol import awg_protocol_label
        _pv = state.get("protocol_version", "2.0")
        _box_row(f"  Протокол: {CYAN}{awg_protocol_label(_pv)}{NC}")

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

        # v5.5.3: мульти-exit каскад
        exits = _awgs_cascade_exits_load()
        if len(exits) > 1 or state.get(AWGS_CASCADE_ACTIVE_KEY):
            _active = _awgs_cascade_active_name(exits, state)
            _box_sep()
            _box_row(f"  Exit-ноды ({len(exits)}), активный: "
                     f"{CYAN}{_active or '—'}{NC}")
            for e in exits:
                mark = f"{GREEN}●{NC}" if e.get("name") == _active else f"{DIM}○{NC}"
                _box_row(f"    {mark} {e.get('name')} — {e.get('endpoint')}:"
                         f"{e.get('port')} ({e.get('protocol_version', '2.0')})")
            age = awgs_cascade_handshake_age()
            if age is not None:
                _box_row(f"    handshake awg1: {age} сек назад")
            r = core._run(["systemctl", "is-active",
                           "awg-cascade-failover.timer"],
                          capture=True, check=False)
            timer_on = (r.stdout or "").strip() == "active"
            _box_row(f"    failover-таймер: "
                     f"{GREEN}active{NC}" if timer_on
                     else f"{DIM}off{NC}")

    elif role == "exit":
        from .awg_protocol import awg_protocol_label
        _pv = state.get("protocol_version", "2.0")
        _box_row(f"  Протокол: {CYAN}{awg_protocol_label(_pv)}{NC}")

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
