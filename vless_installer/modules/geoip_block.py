"""
vless_installer/modules/geoip_block.py
───────────────────────────────────────────────────────────────────────────────
Блокировка по GeoIP и интернет-сканерам (routing rules в Xray).

Содержит интерактивный экран «Блокировка по GeoIP» и набор helpers для
манипуляции routing-правилами Xray (outboundTag=block + blackhole outbound):

  • do_manage_geoip_block()        — главное меню (allowlist / blocklist /
                                      сканеры / удаление / РФ-подсети /
                                      AS-маршрутизация)
  • _geoip_block_get_rules()       — читает текущие block-правила из config.json
  • _geoip_apply_routing(extra)    — применяет новые правила, добавляет blackhole,
                                      перезапускает Xray и откатывает при сбое
  • _geoip_set_allowlist(codes)    — принимать только указанные страны
  • _geoip_add_country_block(codes)— заблокировать конкретные страны
  • _geoip_add_scanner_block()     — заблокировать подсети Shodan/Censys/...
  • _geoip_remove_all()            — удалить все block-правила и blackhole outbound

Точки входа из _core.py:
    from vless_installer.modules.geoip_block import (
        do_manage_geoip_block,
        _geoip_block_get_rules,
        _geoip_apply_routing,
        _geoip_set_allowlist,
        _geoip_add_country_block,
        _geoip_add_scanner_block,
        _geoip_remove_all,
    )

Доступ к helpers ядра (_box_*, _run, цвета, AS-routing helpers, ...) — через
importlib (lazy binding), как и в других извлечённых модулях
(standalone_screens.py, asn_cache.py, warp.py и т.д.).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль vless_installer._core (импорт лениво, как в warp.py)."""
    import importlib
    return importlib.import_module("vless_installer._core")


# ============================================================================
#  ГЛАВНОЕ МЕНЮ: БЛОКИРОВКА ПО GEOIP
# ============================================================================
def do_manage_geoip_block() -> None:
    """Добавляет routing-правила в Xray для GeoIP-блокировки."""
    core = _core_module()
    _box_top               = core._box_top
    _box_row               = core._box_row
    _box_item              = core._box_item
    _box_bottom            = core._box_bottom
    _xray_count_ru_subnet_rules = core._xray_count_ru_subnet_rules
    _as_suggest_server_asn = core._as_suggest_server_asn
    _as_direct_list_load   = core._as_direct_list_load
    _as_action_label       = core._as_action_label
    _resolve_asn_from_input = core._resolve_asn_from_input
    _as_normalize          = core._as_normalize
    _as_validate           = core._as_validate
    _as_ask_action         = core._as_ask_action
    _fetch_prefixes_for_asn = core._fetch_prefixes_for_asn
    _as_direct_save        = core._as_direct_save
    _as_direct_apply_to_xray = core._as_direct_apply_to_xray
    _as_direct_list_save   = core._as_direct_list_save
    _log_change            = core._log_change
    do_manage_ru_subnet_direct = core.do_manage_ru_subnet_direct
    do_manage_as_direct    = core.do_manage_as_direct
    info                   = core.info
    warn                   = core.warn
    success                = core.success
    BLUE = core.BLUE
    BOLD = core.BOLD
    CYAN = core.CYAN
    DIM = core.DIM
    GREEN = core.GREEN
    NC = core.NC
    RED = core.RED
    YELLOW = core.YELLOW
    BOLD, NC, RED, GREEN, YELLOW, DIM, CYAN, BLUE = (
        core.BOLD, core.NC, core.RED, core.GREEN, core.YELLOW, core.DIM, core.CYAN, core.BLUE
    )

    # Авто-определение ASN хостинга при первом открытии (патч: задача #3)
    _as_suggest_server_asn()
    while True:
        os.system("clear")
        print()
        _box_top(f"Блокировка по GeoIP")

        current_rules = _geoip_block_get_rules()
        if current_rules:
            _box_row(f"  {BOLD}Текущие правила блокировки:{NC}")
            for r in current_rules:
                ip_str  = ", ".join(r.get("ip",    [])[:3])
                geo_str = ", ".join(r.get("geoip", [])[:3])
                targets = " | ".join(filter(None, [ip_str, geo_str]))
                _box_row(f"    {RED}✗{NC} [{r.get('outboundTag','block')}] {targets or '(прочие)'}")
        else:
            _box_row(f"  {DIM}Нет правил блокировки{NC}")

        # Статус РФ подсетей в шапке меню
        _ru_active_geo = _xray_count_ru_subnet_rules()
        _ru_file_geo   = Path("/etc/xray/ru_subnets_ripe.txt")
        if _ru_active_geo:
            _ru_geo_str = f"{GREEN}✓ {_ru_active_geo} правил в Xray{NC}"
        elif _ru_file_geo.exists():
            _ru_geo_str = f"{YELLOW}файл есть, не применены{NC}"
        else:
            _ru_geo_str = f"{DIM}не настроены{NC}"
        _box_row(f"  {DIM}РФ подсети RIPE: {_ru_geo_str}{NC}")
        _box_item("1", f"Allowlist — принимать только из выбранных стран")
        _box_item("2", f"Blocklist — заблокировать конкретные страны")
        _box_item("3", f"Заблокировать диапазоны сканеров (Shodan, Censys и др.)")
        _box_item("4", f"{RED}Удалить все правила GeoIP-блокировки{NC}")
        _box_item("5", f"{GREEN}РФ подсети (RIPE NCC) → direct{NC}  [защита от цензора]")
        # Показываем активные AS прямо в шапке пункта [6]
        _geo_as_entries = _as_direct_list_load()
        if _geo_as_entries:
            _geo_as_parts = []
            for _e in _geo_as_entries:
                _geo_as_parts.append(f"{BOLD}{_e['asn']}{NC}[{_as_action_label(_e['action'])}]")
            _geo_as_hint = "  активны: " + "  ".join(_geo_as_parts)
            _box_item("6", f"{GREEN}AS-маршрутизация{NC}  [по ASN хостера/провайдера]")
            _box_row(f"       {DIM}{_geo_as_hint}{NC}")
        else:
            _box_item("6", f"{GREEN}AS-маршрутизация{NC}  [по ASN хостера/провайдера]")
        _box_item("7", f"Управление AS-маршрутами  [изменить/удалить/обновить]")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            print()
            raw = input("  Коды стран через запятую (напр.: RU,BY,KZ): ").strip().upper()
            if not raw:
                warn("Пусто — отмена")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            codes = [c.strip() for c in raw.split(",") if c.strip()]
            _geoip_set_allowlist(codes)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            print()
            raw = input("  Коды стран для блокировки (напр.: CN,US): ").strip().upper()
            if not raw:
                warn("Пусто — отмена")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            codes = [c.strip() for c in raw.split(",") if c.strip()]
            _geoip_add_country_block(codes)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            _geoip_add_scanner_block()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "4":
            ans = input(f"  {YELLOW}Удалить все GeoIP-правила? [y/N]:{NC} ").strip().lower()
            if ans == "y":
                _geoip_remove_all()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            do_manage_ru_subnet_direct()

        elif ch == "6":
            # ── Добавление AS прямо в меню GeoIP (батч + поиск по IP/домену) ─
            print()
            info(f"Введите ASN(ы) через пробел/запятую — или IP/домен для авто-определения")
            info(f"Примеры: {BOLD}AS8359{NC}  {BOLD}8359 1234{NC}  {BOLD}google.com{NC}  {BOLD}8.8.8.8{NC}")
            raw = input(f"  Введите: ").strip()
            if not raw:
                continue

            # Авто-определение ASN по IP/домену
            import re as _re_geo
            tokens = [t for t in _re_geo.split(r'[\s,;]+', raw) if t]
            resolved_tokens = []
            for tok in tokens:
                # Если это явно не ASN-формат — пробуем определить через API
                if not _re_geo.match(r'^(?:AS)?\d+$', tok, _re_geo.IGNORECASE):
                    info(f"  Определяю ASN для {tok}...")
                    r_asn, r_org = _resolve_asn_from_input(tok)
                    if r_asn:
                        success(f"  {tok} → {r_asn}  ({r_org})")
                        resolved_tokens.append(r_asn)
                    else:
                        warn(f"  Не удалось определить ASN для {tok!r} — пропуск")
                else:
                    resolved_tokens.append(tok)

            if not resolved_tokens:
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            # Нормализуем и валидируем все токены
            valid_asns = []
            for tok in resolved_tokens:
                asn = _as_normalize(tok)
                _asn_ok, _asn_err = _as_validate(asn)
                if not _asn_ok:
                    warn(f"Неверный ASN {tok!r}: {_asn_err}")
                else:
                    valid_asns.append(asn)

            if not valid_asns:
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            # Для батча из нескольких — спрашиваем действие один раз
            _cur_entries = _as_direct_list_load()
            _cur_map     = {e["asn"]: e for e in _cur_entries}

            # Фильтруем уже добавленные
            new_asns = []
            for asn in valid_asns:
                if asn in _cur_map:
                    info(f"{asn} уже добавлен [{_as_action_label(_cur_map[asn]['action'])}] — пропуск")
                else:
                    new_asns.append(asn)

            if not new_asns:
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            # Показываем имена организаций для новых ASN (задача #10)
            if len(new_asns) == 1:
                action = _as_ask_action(new_asns[0])
            else:
                print()
                info(f"Будет добавлено {len(new_asns)} AS: {', '.join(new_asns)}")
                action = _as_ask_action()
            if not action:
                info("Отмена")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            # Добавляем каждый ASN
            for asn in new_asns:
                print()
                info(f"Загрузка префиксов для {asn} из RIPE Stat API...")
                cidrs = _fetch_prefixes_for_asn(asn)
                if not cidrs:
                    warn(f"Не удалось получить префиксы для {asn} — пропуск")
                    continue
                success(f"Получено {len(cidrs)} префиксов для {asn}")
                _as_direct_save(asn, cidrs)
                ok = _as_direct_apply_to_xray(asn, cidrs, action)
                if ok:
                    _cur_entries.append({"asn": asn, "action": action})
                    _as_direct_list_save(_cur_entries)
                    _cur_map[asn] = {"asn": asn, "action": action}
                    _log_change("as_routing", f"{asn} добавлен → {action}")
                    success(f"{asn} добавлен → {_as_action_label(action)}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "7":
            do_manage_as_direct()

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


def _geoip_block_get_rules() -> list:
    core = _core_module()
    CONFIG_DIR = core.CONFIG_DIR

    for cfg_path in (CONFIG_DIR / "config.json",
                     Path("/usr/local/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            cfg   = json.loads(cfg_path.read_text())
            rules = cfg.get("routing", {}).get("rules", [])
            return [r for r in rules if r.get("outboundTag") == "block"]
        except Exception:
            pass
    return []


def _geoip_apply_routing(extra_rules: list) -> None:
    """Применяет routing-правила к Xray конфигу. Добавляет blackhole outbound.

    В AWG-режиме также гарантирует наличие outbound "direct-local" (freedom без
    fwmark) — он нужен, если в extra_rules есть правила с outboundTag="direct-local"
    (например, allowlist). Без этого outbound Xray упадёт при старте с
    "no such outbound".
    """
    core = _core_module()
    CONFIG_DIR               = core.CONFIG_DIR
    _set_config_owner        = core._set_config_owner
    _run                     = core._run
    _nginx_restart_if_reality = core._nginx_restart_if_reality
    warn                     = core.warn
    success                  = core.success
    AWG_EXIT_ENABLED         = getattr(core, "AWG_EXIT_ENABLED", False)

    written: set = set()
    for cfg_path in (CONFIG_DIR / "config.json",
                     Path("/usr/local/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            real = str(cfg_path.resolve())
        except Exception:
            real = str(cfg_path)
        if real in written:
            continue
        written.add(real)
        try:
            cfg = json.loads(cfg_path.read_text())
            routing = cfg.setdefault("routing", {})
            rules   = [r for r in routing.setdefault("rules", [])
                       if r.get("outboundTag") != "block"]
            routing["rules"] = extra_rules + rules
            outbounds = cfg.setdefault("outbounds", [])
            if not any(ob.get("tag") == "block" for ob in outbounds):
                outbounds.append({
                    "protocol": "blackhole",
                    "tag": "block",
                    "settings": {"response": {"type": "none"}},
                })
            # AWG-режим: если в extra_rules есть ссылка на "direct-local" —
            # убеждаемся что этот outbound существует. Без fwmark → default route ОС.
            # См. аналогичный паттерн в ru_subnets.py:_ru_subnets_apply_to_xray.
            if AWG_EXIT_ENABLED and any(r.get("outboundTag") == "direct-local"
                                        for r in extra_rules):
                if not any(ob.get("tag") == "direct-local" for ob in outbounds):
                    outbounds.append({
                        "protocol": "freedom",
                        "tag":      "direct-local",
                        "settings": {"domainStrategy": "UseIPv4"},
                    })
                    warn("AWG: добавлен outbound direct-local для GeoIP-allowlist")
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(cfg_path)
        except Exception as e:
            warn(f"Ошибка патча {cfg_path}: {e}")

    _run(["systemctl", "restart", "xray"], check=False, quiet=True)
    _nginx_restart_if_reality()
    time.sleep(1)
    r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
    if r.stdout.strip() == "active":
        success("Правила применены, Xray перезагружен")
    else:
        warn("Xray не запустился — откатываем GeoIP-правила")
        _geoip_remove_all()


def _geoip_set_allowlist(codes: list) -> None:
    """Принимаем только из указанных стран, остальное — block.

    В AWG-режиме outbound "direct" имеет sockopt.mark=AWG_FWMARK → трафик
    уходит через awg0 (exit-VPS). Для allowlist нужна семантика "напрямую,
    без туннеля" — используем "direct-local" (freedom без fwmark → default
    route ОС). См. аналогичный фикс в ru_subnets.py / as_direct.py /
    chain_nodes.py / xray_install.py.
    """
    core = _core_module()
    info    = core.info
    success = core.success
    warn    = core.warn
    AWG_EXIT_ENABLED = getattr(core, "AWG_EXIT_ENABLED", False)

    # AWG-режим: allowlist-трафик должен идти напрямую (eth0/default route),
    # а не через awg0 (exit-VPS). Используем "direct-local" без fwmark.
    _allow_outbound = "direct-local" if AWG_EXIT_ENABLED else "direct"
    info(f"Настройка allowlist: {', '.join(codes)} (outbound={_allow_outbound})")
    # Разрешить из allowlist → direct(-local), всё остальное → block
    rules = [
        {"type": "field", "geoip": [c.lower() for c in codes], "outboundTag": _allow_outbound},
        {"type": "field", "ip":    ["0.0.0.0/0", "::/0"],      "outboundTag": "block"},
    ]
    _geoip_apply_routing(rules)
    success(f"Allowlist: {', '.join(codes)} (outbound={_allow_outbound})")
    warn("Убедитесь что ваш IP входит в разрешённые страны — иначе потеряете SSH!")


def _geoip_add_country_block(codes: list) -> None:
    core = _core_module()
    info    = core.info
    success = core.success

    info(f"Блокировка стран: {', '.join(codes)}")
    rule = {"type": "field", "geoip": [c.lower() for c in codes], "outboundTag": "block"}
    _geoip_apply_routing([rule])
    success(f"Заблокированы: {', '.join(codes)}")


def _geoip_add_scanner_block() -> None:
    """Блокирует известные диапазоны IP крупнейших интернет-сканеров."""
    core = _core_module()
    info    = core.info
    success = core.success

    scanner_ips = [
        # Shodan
        "198.20.69.74/31", "198.20.69.96/27", "198.20.99.130/31",
        "198.20.99.132/30", "104.131.0.69",
        # Censys
        "162.142.125.0/24", "167.248.133.0/24",
        # GreyNoise
        "45.83.66.0/24", "45.83.67.0/24",
        # Rapid7 / Sonar
        "71.6.135.131", "71.6.167.142", "71.6.199.23",
        # BinaryEdge
        "45.129.14.0/24", "45.129.15.0/24",
        # LeakIX
        "176.119.7.0/24",
        # Internet Archive scanners
        "207.241.224.0/20",
    ]
    info("Блокировка диапазонов интернет-сканеров...")
    rule = {"type": "field", "ip": scanner_ips, "outboundTag": "block"}
    _geoip_apply_routing([rule])
    success(f"Заблокированы {len(scanner_ips)} диапазонов сканеров")


def _geoip_remove_all() -> None:
    core = _core_module()
    CONFIG_DIR               = core.CONFIG_DIR
    _set_config_owner        = core._set_config_owner
    _run                     = core._run
    _nginx_restart_if_reality = core._nginx_restart_if_reality
    warn                     = core.warn
    success                  = core.success

    written: set = set()
    for cfg_path in (CONFIG_DIR / "config.json",
                     Path("/usr/local/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            real = str(cfg_path.resolve())
        except Exception:
            real = str(cfg_path)
        if real in written:
            continue
        written.add(real)
        try:
            cfg = json.loads(cfg_path.read_text())
            routing = cfg.get("routing", {})
            routing["rules"] = [r for r in routing.get("rules", [])
                                 if r.get("outboundTag") != "block"]
            cfg["outbounds"] = [ob for ob in cfg.get("outbounds", [])
                                 if ob.get("tag") != "block"]
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(cfg_path)
        except Exception as e:
            warn(f"Ошибка {cfg_path}: {e}")
    _run(["systemctl", "restart", "xray"], check=False, quiet=True)
    _nginx_restart_if_reality()
    success("Все GeoIP-правила удалены")
