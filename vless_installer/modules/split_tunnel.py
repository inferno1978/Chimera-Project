"""
vless_installer/modules/split_tunnel.py
───────────────────────────────────────────────────────────────────────────────
Раздельное туннелирование (split tunneling) — заблокированные в РФ ресурсы
идут через VPN (exit-нода), остальной трафик (банки, маркетплейсы,
госсервисы) — напрямую.

Содержит 8 функций, вынесенных из _core.py:

  • ``prompt_split_tunnel()``                       — интерактивный опрос
    при первичной установке (включить split tunnel, добавить домены/IP).
  • ``_save_split_tunnel_custom()`` / ``_load_split_tunnel_custom()``` —
    persistence-слой: JSON-файл ``/etc/xray/split_tunnel_custom.json``.
  • ``build_split_tunnel_routing_rules(...)``       — формирует routing
    rules для Xray (пользовательские домены/IP + geosite:category-ru /
    geoip:ru через ``direct``, остальное → exit-нода).
  • ``_xray_count_ru_subnet_rules()``               — счётчик правил
    ru_subnets_ripe в config.json (для статуса меню).
  • ``_show_xray_routing_rules()``                  — просмотр всех
    routing-правил Xray в рамке.
  • ``do_manage_split_tunnel()``                    — меню управления из
    главного меню (включить/выключить, добавить/очистить, обновить
    geo-файлы, применить, просмотреть правила).
  • ``_apply_split_tunnel_config_from_state()``     — пересоздаёт config.json
    с актуальными настройками split tunneling (загружает state.json +
    custom.json, мутирует глобали ядра, вызывает _rebuild_and_restart_xray).

Точки входа из _core.py:
    from vless_installer.modules.split_tunnel import (
        prompt_split_tunnel, _save_split_tunnel_custom, _load_split_tunnel_custom,
        build_split_tunnel_routing_rules, _xray_count_ru_subnet_rules,
        _show_xray_routing_rules, do_manage_split_tunnel,
        _apply_split_tunnel_config_from_state,
    )

Глобалы ядра (SPLIT_TUNNEL_ENABLED / SPLIT_TUNNEL_EXTRA_DOMAINS /
SPLIT_TUNNEL_EXTRA_IPS, а также INSTALL_MODE / PROTOCOL_MODE / PARAM_* /
CHAIN_* / AWG_EXIT_ENABLED в _apply_split_tunnel_config_from_state)
мутируются через ``setattr(core, "X", value)`` — это сохраняет ту же
семантику, что и ``global X; X = value``, поскольку ``_core`` и есть сам
модуль ядра. Каноническое хранилище этих глобалей остаётся в _core.py.

Доступ к helpers ядра (``_box_*``, цвета, ``warn``/``info``/``success``,
``_rebuild_and_restart_xray``, ``download_geo_files``, ``STATE_FILE``,
``GEOSITE_DAT``/``GEOIP_DAT``, ``SPLIT_TUNNEL_CUSTOM_FILE``) — через
importlib (lazy binding), как и в других извлечённых модулях
(warp.py, reconfigure.py, standalone_screens.py и т.д.).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль vless_installer._core, импортируя его лениво.

    При запуске через cron (python -c 'from ... import ...') модуль ещё не
    загружен — importlib полноценно его импортирует. При вызове из
    интерактивного инсталлятора модуль уже в sys.modules — это просто lookup.
    """
    import importlib
    return importlib.import_module("vless_installer._core")


# =============================================================================
#  ИНТЕРАКТИВНЫЙ ОПРОС ПРИ УСТАНОВКЕ
# =============================================================================
def prompt_split_tunnel() -> None:
    """Интерактивный опрос о раздельном туннелировании."""
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_bottom = core._box_bottom
    _box_item   = core._box_item
    CYAN   = core.CYAN
    NC     = core.NC
    DIM    = core.DIM
    info    = core.info
    warn    = core.warn
    success = core.success

    _box_top("РАЗДЕЛЬНОЕ ТУННЕЛИРОВАНИЕ (SPLIT TUNNELING)")
    _box_row(f"  Заблокированные в РФ ресурсы → через VPN (Exit Node)")
    _box_row(f"  Остальной трафик (банки, маркетплейсы, госсервисы) → прямо")
    _box_row(f"  Списки geosite/geoip: runetfreedom (github)")
    _box_bottom()
    print()
    _box_top(f"Включить раздельное туннелирование?")
    _box_item("Y", f"Да — заблокированное через VPN, остальное напрямую")
    _box_item("N", f"Нет — весь трафик через VPN (текущее поведение)")
    _box_bottom()

    while True:
        try:
            choice = input(f"{CYAN}Выбор [Y/N]: {NC}").strip().lower()
        except KeyboardInterrupt:
            print()
            raise
        if choice in ('y', 'д'):
            setattr(core, "SPLIT_TUNNEL_ENABLED", True)
            break
        elif choice in ('n', 'н', ''):
            setattr(core, "SPLIT_TUNNEL_ENABLED", False)
            info("Раздельное туннелирование отключено — весь трафик через VPN")
            return
        warn("Введите Y или N")

    success("Раздельное туннелирование включено")
    print()

    # Предложение добавить домены вручную
    print(f"{CYAN}Добавить домены/IP вручную для туннелирования (через VPN)?{NC}")
    print(f"  {DIM}Например: blocked-site.com, 203.0.113.0/24{NC}")
    print(f"  {DIM}Введите домены/IP через запятую, или нажмите Enter для пропуска:{NC}")
    print()

    try:
        extra_raw = input(f"{CYAN}Дополнительные домены/IP:{NC} ").strip()
    except KeyboardInterrupt:
        print()
        raise
    if extra_raw:
        # Списки хранятся в ядре; мутируем их по ссылке (in-place append).
        SPLIT_TUNNEL_EXTRA_DOMAINS = getattr(core, "SPLIT_TUNNEL_EXTRA_DOMAINS", [])
        SPLIT_TUNNEL_EXTRA_IPS     = getattr(core, "SPLIT_TUNNEL_EXTRA_IPS",     [])
        for entry in extra_raw.split(','):
            entry = entry.strip()
            if not entry:
                continue
            # Определяем: это IP/CIDR или домен
            if re.match(r'^\d+\.\d+\.\d+\.\d+', entry) or re.match(r'^[0-9a-fA-F:]+/', entry):
                SPLIT_TUNNEL_EXTRA_IPS.append(entry)
            else:
                SPLIT_TUNNEL_EXTRA_DOMAINS.append(entry)

        if SPLIT_TUNNEL_EXTRA_DOMAINS:
            success(f"Добавлено доменов: {len(SPLIT_TUNNEL_EXTRA_DOMAINS)}: "
                    f"{', '.join(SPLIT_TUNNEL_EXTRA_DOMAINS[:5])}"
                    f"{'...' if len(SPLIT_TUNNEL_EXTRA_DOMAINS) > 5 else ''}")
        if SPLIT_TUNNEL_EXTRA_IPS:
            success(f"Добавлено IP/CIDR: {len(SPLIT_TUNNEL_EXTRA_IPS)}: "
                    f"{', '.join(SPLIT_TUNNEL_EXTRA_IPS[:5])}"
                    f"{'...' if len(SPLIT_TUNNEL_EXTRA_IPS) > 5 else ''}")

    _save_split_tunnel_custom()


# =============================================================================
#  PERSISTENCE: СОХРАНЕНИЕ / ЗАГРУЗКА ПОЛЬЗОВАТЕЛЬСКИХ ДОБАВОК
# =============================================================================
def _save_split_tunnel_custom() -> None:
    """Сохраняет пользовательские дополнения в JSON-файл."""
    core = _core_module()
    SPLIT_TUNNEL_CUSTOM_FILE   = core.SPLIT_TUNNEL_CUSTOM_FILE
    warn = core.warn
    try:
        SPLIT_TUNNEL_CUSTOM_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "enabled":        getattr(core, "SPLIT_TUNNEL_ENABLED",       False),
            "extra_domains":  getattr(core, "SPLIT_TUNNEL_EXTRA_DOMAINS", []),
            "extra_ips":      getattr(core, "SPLIT_TUNNEL_EXTRA_IPS",     []),
            "updated_at":     datetime.now(timezone.utc).isoformat(),
        }
        SPLIT_TUNNEL_CUSTOM_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        SPLIT_TUNNEL_CUSTOM_FILE.chmod(0o640)
    except Exception as e:
        warn(f"Не удалось сохранить пользовательские настройки split tunnel: {e}")


def _load_split_tunnel_custom() -> None:
    """Загружает пользовательские дополнения из JSON-файла."""
    core = _core_module()
    SPLIT_TUNNEL_CUSTOM_FILE = core.SPLIT_TUNNEL_CUSTOM_FILE
    warn = core.warn
    if not SPLIT_TUNNEL_CUSTOM_FILE.exists():
        return
    try:
        data = json.loads(SPLIT_TUNNEL_CUSTOM_FILE.read_text())
        setattr(core, "SPLIT_TUNNEL_ENABLED",       data.get("enabled", False))
        setattr(core, "SPLIT_TUNNEL_EXTRA_DOMAINS", data.get("extra_domains", []))
        setattr(core, "SPLIT_TUNNEL_EXTRA_IPS",     data.get("extra_ips", []))
    except Exception as e:
        warn(f"Не удалось загрузить настройки split tunnel: {e}")


# =============================================================================
#  ФОРМИРОВАНИЕ ROUTING-ПРАВИЛ XRAY
# =============================================================================
def build_split_tunnel_routing_rules(
    proxy_tag: str = "direct",
    direct_tag: str = "direct",
) -> list[dict]:
    """
    Формирует routing rules для split tunneling.
    proxy_tag  — тег outbound, через который идёт заблокированный трафик
    direct_tag — тег outbound для незаблокированного трафика (прямой)

    В Режиме A (одиночный сервер): весь трафик уже пришёл через VPN-туннель,
    поэтому для выхода используется "direct" — сервер сам маршрутизирует.
    В Режиме B (каскад): proxy_tag указывает на exit-ноду за рубежом.
    """
    core = _core_module()
    GEOSITE_DAT = core.GEOSITE_DAT
    GEOIP_DAT   = core.GEOIP_DAT
    warn        = core.warn

    SPLIT_TUNNEL_ENABLED       = getattr(core, "SPLIT_TUNNEL_ENABLED",       False)
    SPLIT_TUNNEL_EXTRA_DOMAINS = getattr(core, "SPLIT_TUNNEL_EXTRA_DOMAINS", [])
    SPLIT_TUNNEL_EXTRA_IPS     = getattr(core, "SPLIT_TUNNEL_EXTRA_IPS",     [])

    if not SPLIT_TUNNEL_ENABLED:
        return []

    geo_files_ok = GEOSITE_DAT.exists() and GEOIP_DAT.exists()
    rules: list[dict] = []

    # --- Пользовательские домены (наивысший приоритет) ---
    if SPLIT_TUNNEL_EXTRA_DOMAINS:
        rules.append({
            "type":        "field",
            "domain":      SPLIT_TUNNEL_EXTRA_DOMAINS,
            "outboundTag": proxy_tag,
            "comment":     "split_tunnel: пользовательские домены",
        })

    # --- Пользовательские IP/CIDR ---
    if SPLIT_TUNNEL_EXTRA_IPS:
        rules.append({
            "type":        "field",
            "ip":          SPLIT_TUNNEL_EXTRA_IPS,
            "outboundTag": proxy_tag,
            "comment":     "split_tunnel: пользовательские IP",
        })

    if geo_files_ok:
        # --- Явные домены IP-проверок и РФ — ВСЕГДА через direct (наивысший приоритет) ---
        # ВАЖНО: российские домены/IP идут первыми — первое совпадение побеждает.
        # Xray применяет правила в порядке списка.
        rules.append({
            "type":        "field",
            "domain":      [
                "domain:2ip.ru",
                "domain:2ip.io",
                "domain:myip.ru",
                "domain:whoer.net",
                "geosite:category-ru",
                "geosite:ru-available-only-inside",
            ],
            "outboundTag": direct_tag,
            "comment":     "split_tunnel: российские домены напрямую",
        })
        rules.append({
            "type":        "field",
            "ip":          ["geoip:ru"],
            "outboundTag": direct_tag,
            "comment":     "split_tunnel: российские IP напрямую",
        })

        # Правила ru-blocked убраны как избыточные:
        # всё что не попало в direct (geoip:ru / geosite:category-ru)
        # уходит через дефолтное правило tcp,udp → chain-balancer.
    else:
        warn("Geo-файлы не найдены — split tunneling будет работать только с пользовательскими правилами")

    return rules


# =============================================================================
#  ПРОСМОТР / ПОДСЧЁТ ROUTING-ПРАВИЛ XRAY
# =============================================================================
def _xray_count_ru_subnet_rules() -> int:
    """Считает количество routing-правил модуля ru_subnets_ripe в конфиге Xray."""
    for cfg_path in (Path("/etc/xray/config.json"),
                     Path("/usr/local/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            cfg   = json.loads(cfg_path.read_text())
            rules = cfg.get("routing", {}).get("rules", [])
            return sum(1 for r in rules if r.get("comment") == "ru_subnets_ripe")
        except Exception:
            pass
    return 0


def _show_xray_routing_rules() -> None:
    """
    Читает config.json и выводит все routing-правила в читаемом виде.
    Правила модуля ru_subnets_ripe подсвечиваются и суммируются (не листаются).
    """
    core = _core_module()
    _box_top   = core._box_top
    _box_row   = core._box_row
    _box_sep   = core._box_sep
    _box_bottom = core._box_bottom
    _wcslen    = core._wcslen
    _plain     = core._plain
    _BOX_W     = core._BOX_W
    warn       = core.warn
    DIM        = core.DIM
    NC         = core.NC
    CYAN       = core.CYAN
    BOLD       = core.BOLD
    GREEN      = core.GREEN
    YELLOW     = core.YELLOW
    RED        = core.RED
    MAGENTA    = core.MAGENTA
    _re = re  # в исходном _core.py здесь был недокументированный _re.split(...)

    cfg_path = None
    for p in (Path("/etc/xray/config.json"),
              Path("/usr/local/etc/xray/config.json")):
        if p.exists():
            cfg_path = p
            break

    print()
    if cfg_path is None:
        warn("Конфиг Xray не найден (/etc/xray/config.json)")
        return

    try:
        cfg = json.loads(cfg_path.read_text())
    except Exception as e:
        warn(f"Ошибка чтения конфига: {e}")
        return

    rules = cfg.get("routing", {}).get("rules", [])
    domain_strategy = cfg.get("routing", {}).get("domainStrategy", "AsIs")

    # ── Вспомогательная функция: перенос длинной строки внутри рамки ──
    def _box_row_wrap(text: str, indent: str = "     ") -> None:
        """
        Выводит строку внутри рамки. Если видимая ширина превышает _BOX_W,
        разбивает по пробелам/разделителям и печатает продолжение с отступом.
        """
        if _wcslen(text) <= _BOX_W:
            _box_row(text)
            return
        # Делим plain-текст по ' | ' чтобы перенести matchers на новые строки
        plain_text = _plain(text)
        # Находим все позиции ' | ' во вхождении в plain и делим
        # Простая стратегия: ищем последний ' | ' или ' ' в пределах BOX_W
        # Работаем посимвольно по оригинальному (с ANSI) тексту через chunks
        # Разбиваем по видимым пробелам, сохраняя ANSI-коды
        chunks = _re.split(r'( \| )', text)
        line   = ""
        first  = True
        pfx    = indent  # отступ для строк-продолжений
        for chunk in chunks:
            candidate = line + chunk if line else chunk
            if _wcslen(candidate) <= _BOX_W:
                line = candidate
            else:
                if line:
                    _box_row(line)
                    line = pfx + chunk.lstrip(" |")
                    first = False
                else:
                    # Один chunk длиннее BOX_W — обрезаем жёстко
                    _box_row(chunk[:_BOX_W])
                    line = ""
        if line:
            _box_row(line)

    _box_top("ROUTING ПРАВИЛА XRAY")
    # Файл и стратегия — на отдельных строках чтобы не переполнять
    _box_row(f"  Файл: {DIM}{cfg_path}{NC}")
    _box_row(f"  domainStrategy: {CYAN}{domain_strategy}{NC}   "
             f"Всего правил: {BOLD}{len(rules)}{NC}")
    _box_sep()

    ru_rules   = [r for r in rules if r.get("comment") == "ru_subnets_ripe"]
    other_rules = [r for r in rules if r.get("comment") != "ru_subnets_ripe"]

    # ── РФ подсети (суммарно) ────────────────────────────────────────
    if ru_rules:
        total_cidrs = sum(len(r.get("ip", [])) for r in ru_rules)
        _box_row(f"  {GREEN}[РФ подсети RIPE]{NC}  "
                 f"{GREEN}{len(ru_rules)} правил{NC} → "
                 f"{total_cidrs} CIDR → outbound: {GREEN}direct{NC}")
        _ru_file = Path("/etc/xray/ru_subnets_ripe.txt")
        if _ru_file.exists():
            _mtime = datetime.fromtimestamp(_ru_file.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            _box_row(f"  {DIM}Файл подсетей обновлён: {_mtime}{NC}")
    else:
        _box_row(f"  {YELLOW}РФ подсети RIPE: правила не найдены в конфиге{NC}")

    _box_sep()
    # ── Остальные правила ────────────────────────────────────────────
    if not other_rules:
        _box_row(f"  {DIM}Других routing-правил нет{NC}")
    else:
        _box_row(f"  {BOLD}Прочие правила ({len(other_rules)}):{NC}")
        _box_sep()
        for idx, r in enumerate(other_rules, 1):
            # outboundTag или balancerTag (правила с балансировщиком)
            balancer_tag = r.get("balancerTag", "")
            tag          = r.get("outboundTag", "")
            comment      = r.get("comment", "")

            if balancer_tag:
                balancers = cfg.get("routing", {}).get("balancers", [])
                bal       = next((b for b in balancers if b.get("tag") == balancer_tag), {})
                selector  = bal.get("selector", [])
                strategy  = bal.get("strategy", {}).get("type", "roundRobin")
                sel_str   = ", ".join(selector) if selector else "?"
                tag_col   = f"{MAGENTA}balancer:{balancer_tag}{NC} [{strategy}]"
                # Показываем ноды балансировщика на отдельной строке если длинные
                sel_col   = f"{CYAN}{sel_str}{NC}"
            elif tag.lower() in ("block", "blackhole"):
                tag_col = f"{RED}{tag}{NC}"
                sel_col = ""
            elif tag == "direct":
                tag_col = f"{GREEN}{tag}{NC}"
                sel_col = ""
            elif tag in ("proxy", "vless-out", "chain-proxy", "xray-stats-api"):
                tag_col = f"{CYAN}{tag}{NC}"
                sel_col = ""
            elif tag:
                tag_col = f"{YELLOW}{tag}{NC}"
                sel_col = ""
            else:
                tag_col = f"{DIM}(нет тега){NC}"
                sel_col = ""

            # Что матчит
            matchers = []
            if r.get("inboundTag"):
                matchers.append(f"inbound:{','.join(r['inboundTag'])}")
            if r.get("domain"):
                d = r["domain"]
                matchers.append(f"domain[{len(d)}]: {', '.join(d[:3])}{'...' if len(d)>3 else ''}")
            if r.get("geoip"):
                matchers.append(f"geoip:{','.join(r['geoip'])}")
            if r.get("ip"):
                ips = r["ip"]
                matchers.append(f"ip[{len(ips)}]: {', '.join(ips[:2])}{'...' if len(ips)>2 else ''}")
            if r.get("protocol"):
                matchers.append(f"proto:{','.join(r['protocol'])}")
            if r.get("network"):
                matchers.append(f"network:{r['network']}")
            if r.get("port"):
                matchers.append(f"port:{r['port']}")
            if not matchers:
                matchers = ["(все)"]

            # Строка номер + тег
            prefix  = f"  {DIM}{idx:>3}.{NC} → {tag_col}"
            matcher_str = " | ".join(matchers)

            # Строка с комментарием — отдельно снизу если есть
            _box_row_wrap(f"{prefix}  {matcher_str}", indent="        ")

            # Ноды балансировщика — отдельная строка с отступом
            if balancer_tag and sel_col:
                _box_row_wrap(f"       {DIM}↳ nodes:{NC} {sel_col}", indent="              ")

            # Комментарий — отдельная строка
            if comment:
                _box_row(f"       {DIM}# {comment}{NC}")

    _box_bottom()


# =============================================================================
#  МЕНЮ УПРАВЛЕНИЯ ИЗ ГЛАВНОГО МЕНЮ
# =============================================================================
def do_manage_split_tunnel() -> None:
    """Меню управления раздельным туннелированием из главного меню."""
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_back   = core._box_back
    _box_bottom = core._box_bottom
    info    = core.info
    warn    = core.warn
    success = core.success
    GEOSITE_DAT = core.GEOSITE_DAT
    GEOIP_DAT   = core.GEOIP_DAT
    CYAN   = core.CYAN
    NC     = core.NC
    DIM    = core.DIM
    BOLD   = core.BOLD
    BLUE   = core.BLUE
    GREEN  = core.GREEN
    YELLOW = core.YELLOW
    RED    = core.RED
    download_geo_files = core.download_geo_files

    _load_split_tunnel_custom()

    while True:
        print()
        # Списки мутируются in-place (.append/.clear), поэтому bind по ссылке
        # один раз — актуальны до тех пор, пока никто не перепривяжет имя в
        # core. _load_split_tunnel_custom() выше мог перепривязать; читаем
        # актуальные ссылки на каждой итерации для надёжности.
        SPLIT_TUNNEL_ENABLED       = getattr(core, "SPLIT_TUNNEL_ENABLED",       False)
        SPLIT_TUNNEL_EXTRA_DOMAINS = getattr(core, "SPLIT_TUNNEL_EXTRA_DOMAINS", [])
        SPLIT_TUNNEL_EXTRA_IPS     = getattr(core, "SPLIT_TUNNEL_EXTRA_IPS",     [])
        st_status = f"{GREEN}ВКЛЮЧЕНО{NC}" if SPLIT_TUNNEL_ENABLED else f"{YELLOW}ОТКЛЮЧЕНО{NC}"
        geo_ok = GEOSITE_DAT.exists() and GEOIP_DAT.exists()
        geo_str = f"{GREEN}OK{NC}" if geo_ok else f"{RED}НЕТ{NC}"
        dom_count = len(SPLIT_TUNNEL_EXTRA_DOMAINS)
        ip_count  = len(SPLIT_TUNNEL_EXTRA_IPS)
        # --- РФ подсети RIPE ---
        _ru_file = Path("/etc/xray/ru_subnets_ripe.txt")
        _ru_active = _xray_count_ru_subnet_rules()
        if _ru_file.exists():
            _ru_lines = [l for l in _ru_file.read_text().splitlines() if l and not l.startswith("#")]
            _ru_mtime = datetime.fromtimestamp(_ru_file.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            _ru_str   = f"{GREEN}{len(_ru_lines)} подсетей{NC} (файл {_ru_mtime})"
        else:
            _ru_str   = f"{YELLOW}не загружены{NC}"
        _ru_xray_str = f"{GREEN}{_ru_active} правил в Xray{NC}" if _ru_active else f"{RED}не применены{NC}"

        _box_top("УПРАВЛЕНИЕ РАЗДЕЛЬНЫМ ТУННЕЛИРОВАНИЕМ")
        _box_row()
        _box_row(f"  Статус:            {st_status}")
        _box_row(f"  Geo-файлы:         {geo_str}")
        _box_row(f"  Доп. доменов: {dom_count} | Доп. IP: {ip_count}")
        _box_row(f"  РФ подсети RIPE:   {_ru_str}")
        _box_row(f"  Правил в Xray:     {_ru_xray_str}")
        _box_row()
        _box_sep()
        _box_row(f"  {CYAN}[1]{NC} {'Отключить' if SPLIT_TUNNEL_ENABLED else 'Включить'} раздельное туннелирование")
        _box_row(f"  {CYAN}[2]{NC} Добавить домен(ы) для туннелирования")
        _box_row(f"  {CYAN}[3]{NC} Добавить IP/CIDR для туннелирования")
        _box_row(f"  {CYAN}[4]{NC} Показать текущие пользовательские правила")
        _box_row(f"  {CYAN}[5]{NC} Очистить пользовательские правила")
        _box_row(f"  {CYAN}[6]{NC} Обновить geo-файлы (runetfreedom)")
        _box_row(f"  {CYAN}[7]{NC} Применить настройки (пересоздать конфиг Xray)")
        _box_row(f"  {CYAN}[8]{NC} Просмотр активных routing-правил Xray")
        _box_row()
        _box_back()
        _box_bottom()
        choice = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if choice == '1':
            new_val = not SPLIT_TUNNEL_ENABLED
            setattr(core, "SPLIT_TUNNEL_ENABLED", new_val)
            SPLIT_TUNNEL_ENABLED = new_val
            _save_split_tunnel_custom()
            status = "включено" if SPLIT_TUNNEL_ENABLED else "отключено"
            success(f"Раздельное туннелирование {status}")
            if SPLIT_TUNNEL_ENABLED and not (GEOSITE_DAT.exists() and GEOIP_DAT.exists()):
                warn("Geo-файлы не скачаны!")
                warn("Без них geosite:category-ru / geoip:ru не будут работать и Xray упадёт.")
                warn("Выберите [6] для загрузки geo-файлов перед применением [7].")

        elif choice == '2':
            raw = input(f"{CYAN}Домены (через запятую):{NC} ").strip()
            added = 0
            for d in raw.split(','):
                d = d.strip()
                if d and d not in SPLIT_TUNNEL_EXTRA_DOMAINS:
                    SPLIT_TUNNEL_EXTRA_DOMAINS.append(d)
                    added += 1
            _save_split_tunnel_custom()
            success(f"Добавлено {added} домен(ов). Итого: {len(SPLIT_TUNNEL_EXTRA_DOMAINS)}")

        elif choice == '3':
            raw = input(f"{CYAN}IP/CIDR (через запятую):{NC} ").strip()
            added = 0
            for ip in raw.split(','):
                ip = ip.strip()
                if ip and ip not in SPLIT_TUNNEL_EXTRA_IPS:
                    SPLIT_TUNNEL_EXTRA_IPS.append(ip)
                    added += 1
            _save_split_tunnel_custom()
            success(f"Добавлено {added} IP/CIDR. Итого: {len(SPLIT_TUNNEL_EXTRA_IPS)}")

        elif choice == '4':
            print()
            if SPLIT_TUNNEL_EXTRA_DOMAINS:
                print(f"{BOLD}Домены ({len(SPLIT_TUNNEL_EXTRA_DOMAINS)}):{NC}")
                for d in SPLIT_TUNNEL_EXTRA_DOMAINS:
                    print(f"  • {d}")
            else:
                print(f"{DIM}Пользовательских доменов нет{NC}")
            print()
            if SPLIT_TUNNEL_EXTRA_IPS:
                print(f"{BOLD}IP/CIDR ({len(SPLIT_TUNNEL_EXTRA_IPS)}):{NC}")
                for ip in SPLIT_TUNNEL_EXTRA_IPS:
                    print(f"  • {ip}")
            else:
                print(f"{DIM}Пользовательских IP нет{NC}")

        elif choice == '5':
            conf = input(f"{RED}Очистить всё? [y/N]:{NC} ").strip().lower()
            if conf == 'y':
                SPLIT_TUNNEL_EXTRA_DOMAINS.clear()
                SPLIT_TUNNEL_EXTRA_IPS.clear()
                _save_split_tunnel_custom()
                success("Пользовательские правила очищены")

        elif choice == '6':
            if download_geo_files():
                success("Geo-файлы обновлены")
                # BUGFIX: после скачивания geo-файлов Xray нужно перезапустить,
                # чтобы подхватить новые файлы. Используем _apply_split_tunnel_config_from_state,
                # которая пересобирает конфиг (с учётом режима B) и вызывает _rebuild_and_restart_xray
                # — он дожидается нового Unix-сокета и перезапускает nginx, иначе клиенты
                # получают EOF из-за устаревшего upstream.
                info("Применяю конфиг и перезапускаю Xray (подхватить новые geo-файлы)...")
                _apply_split_tunnel_config_from_state()
            else:
                warn("Не удалось обновить geo-файлы")

        elif choice == '7':
            # Загружаем state и пересоздаём конфиг
            _apply_split_tunnel_config_from_state()
            # Показываем актуальный счётчик сразу после применения
            _ru_after = _xray_count_ru_subnet_rules()
            _st_after = f"{GREEN}ВКЛЮЧЕНО{NC}" if getattr(core, "SPLIT_TUNNEL_ENABLED", False) else f"{YELLOW}ОТКЛЮЧЕНО{NC}"
            print()
            print(f"  Итог после применения:")
            print(f"    Split tunnel:    {_st_after}")
            if _ru_after:
                print(f"    RIPE-правил:     {GREEN}{_ru_after} правил в Xray{NC}")
            else:
                _ru_file_chk = Path("/etc/xray/ru_subnets_ripe.txt")
                if _ru_file_chk.exists():
                    print(f"    RIPE-правил:     {YELLOW}файл есть, но правила не вписались{NC}")
                    print(f"    {DIM}→ проверьте: python3 {sys.argv[0]} (раздел РФ подсети → Применить){NC}")
                else:
                    print(f"    RIPE-правил:     {DIM}файл не скачан (нормально если не используется){NC}")
            print()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif choice == '8':
            _show_xray_routing_rules()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif choice in ('q', ''):
            return

        else:
            warn("Неверный выбор")


# =============================================================================
#  ПРИМЕНЕНИЕ КОНФИГА ИЗ STATE (state.json + custom.json)
# =============================================================================
def _apply_split_tunnel_config_from_state() -> None:
    """Пересоздаёт конфиг Xray с актуальными настройками split tunneling."""
    core = _core_module()
    STATE_FILE              = core.STATE_FILE
    SPLIT_TUNNEL_CUSTOM_FILE = core.SPLIT_TUNNEL_CUSTOM_FILE
    GEOSITE_DAT             = core.GEOSITE_DAT
    GEOIP_DAT               = core.GEOIP_DAT
    CYAN   = core.CYAN
    NC     = core.NC
    YELLOW = core.YELLOW
    warn    = core.warn
    info    = core.info
    download_geo_files            = core.download_geo_files
    _rebuild_and_restart_xray     = core._rebuild_and_restart_xray

    if not STATE_FILE.exists():
        warn("state.json не найден — сначала выполните установку (пункт 1)")
        return

    try:
        state = json.loads(STATE_FILE.read_text())
        setattr(core, "INSTALL_MODE",          state.get("install_mode",   "A"))
        setattr(core, "PROTOCOL_MODE",         state.get("protocol_mode",  "reality"))
        setattr(core, "PARAM_DOMAIN",          state.get("domain",         ""))
        setattr(core, "PARAM_UUID",            state.get("uuid",           ""))
        setattr(core, "PARAM_PUBLIC_KEY",      state.get("public_key",     ""))
        setattr(core, "PARAM_PRIVATE_KEY",     state.get("private_key",    ""))
        setattr(core, "PARAM_SHORTID",         state.get("short_id",       ""))
        setattr(core, "PARAM_SPIDERX",         state.get("spiderx",        ""))
        setattr(core, "PARAM_SOCKET_PATH",     state.get("socket",         ""))
        setattr(core, "PARAM_DOMAIN_STRATEGY", state.get("strategy",       ""))
        setattr(core, "PARAM_USE_DNSCRYPT",    state.get("use_dnscrypt",   False))
        setattr(core, "IS_IPV6_AVAILABLE",     bool(state.get("ipv6",      "")))
        setattr(core, "IPV6_PREFLIGHT",        state.get("ipv6",           ""))
        setattr(core, "SERVER_PORT",           state.get("server_port",    443))
        setattr(core, "XHTTP_PORT",            state.get("server_port",    443))
        setattr(core, "XHTTP_MODE",            state.get("xhttp_mode",     "streamup"))
        setattr(core, "XHTTP_PATH",            state.get("xhttp_path",     "/"))
        setattr(core, "CHAIN_BALANCER_STRATEGY", state.get("chain_balancer_strategy", "roundRobin"))
        setattr(core, "CHAIN_NODES",           state.get("chain_nodes",    []))
        setattr(core, "CHAIN_EXIT_HOST",       state.get("chain_exit_host",   ""))
        setattr(core, "CHAIN_EXIT_PORT",       state.get("chain_exit_port",   443))
        setattr(core, "CHAIN_EXIT_UUID",       state.get("chain_exit_uuid",   ""))
        setattr(core, "CHAIN_EXIT_PUBKEY",     state.get("chain_exit_pubkey", ""))
        setattr(core, "CHAIN_EXIT_SHORTID",    state.get("chain_exit_shortid",""))
        setattr(core, "CHAIN_EXIT_SNI",        state.get("chain_exit_sni",    ""))
        setattr(core, "CHAIN_EXIT_FP",         state.get("chain_exit_fp",     "chrome"))
        setattr(core, "AWG_EXIT_ENABLED",      state.get("awg_exit_enabled",  False))
        setattr(core, "PARAM_REALITY_DEST",    state.get("reality_dest",      ""))
        # Split tunneling — всегда читаем из custom.json (актуальное состояние),
        # state.json обновляется только при полной установке и может быть устаревшим.
        # .clear() мутирует существующие списки в ядре (in-place), не разрывая
        # ссылки, которые могут держать другие модули.
        getattr(core, "SPLIT_TUNNEL_EXTRA_DOMAINS", []).clear()
        getattr(core, "SPLIT_TUNNEL_EXTRA_IPS",     []).clear()
        setattr(core, "SPLIT_TUNNEL_ENABLED", False)
        if SPLIT_TUNNEL_CUSTOM_FILE.exists():
            try:
                _custom = json.loads(SPLIT_TUNNEL_CUSTOM_FILE.read_text())
                setattr(core, "SPLIT_TUNNEL_ENABLED",       _custom.get("enabled", False))
                setattr(core, "SPLIT_TUNNEL_EXTRA_DOMAINS", list(_custom.get("extra_domains", [])))
                setattr(core, "SPLIT_TUNNEL_EXTRA_IPS",     list(_custom.get("extra_ips", [])))
            except Exception:
                pass
        # Фолбэк: если custom-файла нет — берём из state.json
        if not SPLIT_TUNNEL_CUSTOM_FILE.exists():
            setattr(core, "SPLIT_TUNNEL_ENABLED",       state.get("split_tunnel", False))
            setattr(core, "SPLIT_TUNNEL_EXTRA_DOMAINS", list(state.get("split_extra_domains", [])))
            setattr(core, "SPLIT_TUNNEL_EXTRA_IPS",     list(state.get("split_extra_ips", [])))
    except Exception as e:
        warn(f"Ошибка чтения state.json: {e}")
        return

    PARAM_DOMAIN = getattr(core, "PARAM_DOMAIN", "")
    if not PARAM_DOMAIN:
        warn("Параметры установки не найдены в state.json")
        return

    SPLIT_TUNNEL_ENABLED = getattr(core, "SPLIT_TUNNEL_ENABLED", False)
    # --- BUGFIX: проверяем наличие geo-файлов ДО генерации конфига ---
    # Если split tunneling включён, но geo-файлы отсутствуют/повреждены,
    # конфиг будет содержать geosite:category-ru — и Xray упадёт при старте.
    if SPLIT_TUNNEL_ENABLED:
        geo_missing = not (GEOSITE_DAT.exists() and GEOIP_DAT.exists())
        geo_too_small = False
        if not geo_missing:
            # Стандартный geosite.dat от v2fly/xray ~1-2 МБ — не содержит
            # категорию BLOCKED. Нужный файл от runetfreedom весит ~4-6 МБ.
            # Порог 3 МБ отсекает неправильные файлы.
            geo_too_small = (
                GEOSITE_DAT.stat().st_size < 3_000_000
                or GEOIP_DAT.stat().st_size < 10_000
            )
        if geo_missing or geo_too_small:
            reason = "отсутствуют" if geo_missing else "повреждены (слишком малый размер)"
            warn(f"Geo-файлы {reason} — geosite:category-ru/geoip:ru вызовут падение Xray!")
            ans = input(f"{CYAN}Скачать geo-файлы сейчас? [Y/n]:{NC} ").strip().lower()
            if ans in ("", "y"):
                ok = download_geo_files()
                if not ok:
                    warn("Geo-файлы не удалось скачать.")
                    ans2 = input(
                        f"{YELLOW}Применить конфиг БЕЗ geosite/geoip правил (только польз. правила)? [y/N]:{NC} "
                    ).strip().lower()
                    if ans2 != "y":
                        warn("Применение отменено. Xray не перезапускался.")
                        return
                    # Временно форсируем отсутствие geo-файлов — build_split_tunnel_routing_rules
                    # сам пропустит geosite/geoip блок, если файлов нет.
                    # Просто продолжаем — файлов нет, логика уже учтена.
            else:
                ans2 = input(
                    f"{YELLOW}Применить конфиг БЕЗ geosite/geoip правил (только польз. правила)? [y/N]:{NC} "
                ).strip().lower()
                if ans2 != "y":
                    warn("Применение отменено. Xray не перезапускался.")
                    return

    info("Пересоздание конфига Xray с учётом split tunneling...")
    try:
        st_label = "ВКЛЮЧЁН" if getattr(core, "SPLIT_TUNNEL_ENABLED", False) else "ОТКЛЮЧЁН"
        _rebuild_and_restart_xray(f"Xray перезапущен. Split tunnel: {st_label}")
    except Exception as e:
        warn(f"Ошибка применения конфига: {e}")
