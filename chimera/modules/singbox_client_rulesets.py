"""
chimera/modules/singbox_client_rulesets.py
───────────────────────────────────────────────────────────────────────────────
Готовые .srs ruleset'ы для sing-box клиентских конфигов (Podkop / OpenWrt).

ПРОБЛЕМА, КОТОРУЮ РЕШАЕТ МОДУЛЬ
────────────────────────────────
Пользователь на Podkop/OpenWrt импортирует sing-box клиентский конфиг через
URL подписки (?format=singbox). Стандартный конфиг, который генерирует chimera,
содержит только outbounds + route.final="vless-out" — ВЕСЬ трафик клиента
(включая Госуслуги, Wildberries, Ozon, Детский Мир, Тинькофф, Сбер, и т.д.)
уходит в VPN-туннель. Российские антифрод-системы видят «иностранный» IP и:
  - Госуслуги: требуют подтверждение по СНИЛС / блокируют вход
  - WB / Ozon: показывают капчу / запрещают оплату картой РФ
  - Детский Мир: показывают «войдите с российского IP»

РЕШЕНИЕ
───────
Включаем в клиентский sing-box конфиг секцию route.rule_set + route.rules с
готовыми .srs-списками от hydraponique/roscomvpn-geosite (217⭐ на GitHub,
форк roscomvpn-проекта, специально собранный для sing-box RuleSet v3):

  - category-ru.srs           → direct  (РФ-домены мимо VPN)
  - category-geoblock-ru.srs  → proxy   (заблокированные в РФ через VPN)
  - whitelist.srs             → direct  (приватные/локальные домены)
  - telegram.srs              → proxy   (Telegram через VPN, если заблокирован)
  - youtube.srs               → proxy   (YouTube через VPN)
  - apple.srs / steam.srs / epicgames.srs → direct (магазины приложений)

По умолчанию ВЫКЛЮЧЕНО — обратная совместимость 100%. Существующие клиентские
конфиги (Clash/sing-box/Hiddify/vless-link) не меняются, пока администратор
явно не включит фичу через TUI: меню → Клиенты → [R] Sing-box rulesets.

ИСТОЧНИК RULESET'ОВ
───────────────────
GitHub: https://github.com/hydraponique/roscomvpn-geosite
Файлы:  release/sing-box/<name>.srs  (binary format, sing-box RuleSet v3)
CDN:    cdn.jsdelivr.net (Cloudflare-backed, хорошо доступен из РФ)

ВАЖНО: имя репозитория именно «hydraponique/roscomvpn-geosite» — это
правильное имя. Распространённая опечатка: «hydraronique/roscomprn-geosite»
(такого репозитория не существует, все URL возвращают HTTP 404).

ТОЧКИ ИНТЕГРАЦИИ
────────────────
Вызывается из трёх мест (один и тот же inject_route_rulesets):
  1. subscription.build_subscription_singbox_config(user)
     — генерация полного sing-box JSON для подписки ?format=singbox
  2. rest_api._generate_singbox_config(user)
     — sing-box JSON для эндпоинта /api/portal/singbox
  3. client_config_export.do_generate_client_config()
     — файл /root/xray-client-configs/sing-box.json

Каждая точка вызывает inject_route_rulesets(config, proxy_outbound_tag)
— если фича выключена, функция возвращает config без изменений (no-op).

СОСТОЯНИЕ В state.json
──────────────────────
Поле «singbox_client_rulesets»:
  {
    "enabled": true|false,           # по умолчанию false
    "selected": ["ru-direct", ...]   # список выбранных тегов из RULESET_CATALOG
  }

При отсутствии поля — фича считается выключенной, конфиги не меняются.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional


# =============================================================================
#  ЛЕНИВАЯ ПРИВЯЗКА К ЯДРУ (как в warp.py / warp_curated_lists.py)
# =============================================================================
def _core_module():
    import importlib
    return importlib.import_module("chimera._core")


def _log_to_file(level: str, msg: str) -> None:
    try:
        _core_module().log_to_file(level, msg)
    except Exception:
        pass


# =============================================================================
#  КАТАЛОГ RULESET'ОВ
# =============================================================================
# Источник: github.com/hydraponique/roscomvpn-geosite (НЕ hydraronique/roscomprn!)
# Каждый .srs — это бинарный sing-box RuleSet v3 с domain_suffix списком.
# Format=binary → клиент не парсит, а кэширует как есть (cache.db).
_RULESET_BASE = (
    "https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geosite"
    "@HEAD/release/sing-box/"
)

# action="direct"  → трафик мимо VPN (для РФ-сервисов, чтобы не детектили VPN)
# action="proxy"   → трафик через VLESS outbound (для заблокированных в РФ)
#
# Тег должен быть уникальным в пределах одного sing-box конфига и не
# пересекаться со встроенными тегами sing-box (типа "direct", "block").
# Поэтому используется суффикс -direct/-proxy.
RULESET_CATALOG: dict[str, dict] = {
    "ru-direct": {
        "url": _RULESET_BASE + "category-ru.srs",
        "action": "direct",
        "label": "Российские домены → direct",
        "hint": "Госуслуги, Wildberries, Ozon, Детский Мир, банки — мимо VPN",
    },
    "geoblock-ru-proxy": {
        "url": _RULESET_BASE + "category-geoblock-ru.srs",
        "action": "proxy",
        "label": "Заблокированные в РФ → proxy",
        "hint": "Instagram, Twitter, Facebook и др. — через VPN",
    },
    "private-direct": {
        "url": _RULESET_BASE + "whitelist.srs",
        "action": "direct",
        "label": "Приватные домены → direct",
        "hint": "Локальные/корпоративные домены — напрямую",
    },
    "telegram-proxy": {
        "url": _RULESET_BASE + "telegram.srs",
        "action": "proxy",
        "label": "Telegram → proxy",
        "hint": "Все домены Telegram — через VPN (если регион блокирует)",
    },
    "youtube-proxy": {
        "url": _RULESET_BASE + "youtube.srs",
        "action": "proxy",
        "label": "YouTube → proxy",
        "hint": "Google Video / YouTube CDN — через VPN",
    },
    "apple-direct": {
        "url": _RULESET_BASE + "apple.srs",
        "action": "direct",
        "label": "Apple → direct",
        "hint": "App Store / iCloud / Apple Music — напрямую (доступно в РФ)",
    },
    "steam-direct": {
        "url": _RULESET_BASE + "steam.srs",
        "action": "direct",
        "label": "Steam → direct",
        "hint": "Steam Store / CDN — напрямую (доступно в РФ)",
    },
    "epicgames-direct": {
        "url": _RULESET_BASE + "epicgames.srs",
        "action": "direct",
        "label": "Epic Games → direct",
        "hint": "Epic Games Store / CDN — напрямую",
    },
}

# Минимальный набор по умолчанию — решает основную боль (РФ-сервисы + приватные
# домены мимо VPN, заблокированные через VPN). Пользователь может расширить в TUI.
DEFAULT_SELECTED: tuple[str, ...] = (
    "ru-direct",
    "geoblock-ru-proxy",
    "private-direct",
)

STATE_FIELD = "singbox_client_rulesets"


# =============================================================================
#  ЧТЕНИЕ/ЗАПИСЬ СОСТОЯНИЯ
# =============================================================================
def _state_file() -> Path:
    return _core_module().STATE_FILE


def _load_state() -> dict:
    """Читает state.json. Возвращает {} если файла нет или он битый."""
    try:
        sf = _state_file()
        if not sf.exists():
            return {}
        return json.loads(sf.read_text())
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    """Атомарно сохраняет state.json."""
    import os
    import tempfile
    sf = _state_file()
    sf.parent.mkdir(parents=True, exist_ok=True)
    # Атомарная запись через временный файл + rename — стандартный приём,
    # чтобы избежать partial writes при одновременном доступе (cron + TUI).
    fd, tmp_path = tempfile.mkstemp(dir=str(sf.parent), prefix=".state.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, str(sf))
    finally:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass


def get_rulesets_config() -> dict:
    """Возвращает конфиг ruleset'ов из state.json.

    Гарантированно возвращает {"enabled": bool, "selected": list[str]}.
    Если поля нет — возвращает defaults (enabled=False, selected=DEFAULT).
    """
    state = _load_state()
    cfg = state.get(STATE_FIELD, {}) or {}
    if not isinstance(cfg, dict):
        return {"enabled": False, "selected": list(DEFAULT_SELECTED)}
    enabled = bool(cfg.get("enabled", False))
    selected = cfg.get("selected", list(DEFAULT_SELECTED))
    if not isinstance(selected, list):
        selected = list(DEFAULT_SELECTED)
    # Фильтруем теги, которых больше нет в каталоге (на случай удаления).
    selected = [t for t in selected if t in RULESET_CATALOG]
    if not selected:
        selected = list(DEFAULT_SELECTED)
    return {"enabled": enabled, "selected": selected}


def set_rulesets_config(enabled: bool, selected: list[str]) -> None:
    """Сохраняет конфиг ruleset'ов в state.json (merge с существующим state)."""
    # Только валидные теги из каталога.
    valid = [t for t in selected if t in RULESET_CATALOG]
    if not valid:
        valid = list(DEFAULT_SELECTED)
    state = _load_state()
    state[STATE_FIELD] = {
        "enabled": bool(enabled),
        "selected": valid,
    }
    _save_state(state)
    _log_to_file("INFO",
                 f"singbox_client_rulesets: enabled={enabled}, "
                 f"selected={valid}")


# =============================================================================
#  ИНЪЕКЦИЯ В SING-BOX КОНФИГ
# =============================================================================
def _load_enabled_rulesets() -> list[tuple[str, str, str]]:
    """Возвращает список (tag, url, action) для ВКЛЮЧЁННЫХ ruleset'ов.

    Если фича выключена — возвращает пустой список (no-op).
    """
    cfg = get_rulesets_config()
    if not cfg["enabled"]:
        return []
    out: list[tuple[str, str, str]] = []
    for tag in cfg["selected"]:
        meta = RULESET_CATALOG.get(tag)
        if meta:
            out.append((tag, meta["url"], meta["action"]))
    return out


def inject_route_rulesets(
    config: dict,
    proxy_outbound_tag: str = "vless-out",
) -> dict:
    """Добавляет route.rule_set + route.rules в sing-box клиентский конфиг.

    Если фича выключена в state.json — возвращает config без изменений.
    Идемпотентно: повторный вызов не дублирует rule_set/rules (по тегу).

    Parameters:
      config: dict sing-box конфига (с ключом "outbounds").
      proxy_outbound_tag: tag основного proxy outbound (для route.final,
                          download_detour и action="proxy" rules).

    Returns:
      Тот же dict (mutated in-place для эффективности), с добавленными
      ключами route.rule_set и route.rules при необходимости.
    """
    rulesets = _load_enabled_rulesets()
    if not rulesets:
        return config

    # Группируем по action — sing-box предпочитает одно правило на action.
    direct_tags: list[str] = []
    proxy_tags: list[str] = []
    rule_set_defs: list[dict] = []
    seen_tags: set[str] = set()

    for tag, url, action in rulesets:
        if tag in seen_tags:
            continue
        seen_tags.add(tag)
        rule_set_defs.append({
            "type": "remote",
            "tag": tag,
            "format": "binary",
            "url": url,
            "download_detour": proxy_outbound_tag,
        })
        if action == "direct":
            direct_tags.append(tag)
        else:
            proxy_tags.append(tag)

    route = config.setdefault("route", {})

    # Гарантируем route.final — sing-box требует, чтобы был final outbound.
    if "final" not in route:
        route["final"] = proxy_outbound_tag

    # Merge rule_set (не дублируем существующие теги).
    existing_rule_set = route.get("rule_set", [])
    if not isinstance(existing_rule_set, list):
        existing_rule_set = []
    existing_rs_tags = {rs.get("tag") for rs in existing_rule_set if isinstance(rs, dict)}
    for rs_def in rule_set_defs:
        if rs_def["tag"] not in existing_rs_tags:
            existing_rule_set.append(rs_def)
            existing_rs_tags.add(rs_def["tag"])
    if existing_rule_set:
        route["rule_set"] = existing_rule_set

    # Prepend наши rules перед существующими (по приоритету: direct сначала,
    # потом proxy, потом всё что было).
    existing_rules = route.get("rules", [])
    if not isinstance(existing_rules, list):
        existing_rules = []
    new_rules: list[dict] = []
    if direct_tags:
        new_rules.append({
            "rule_set": direct_tags,
            "outbound": "direct",
        })
    if proxy_tags:
        new_rules.append({
            "rule_set": proxy_tags,
            "outbound": proxy_outbound_tag,
        })
    if new_rules:
        # Идемпотентность: не добавляем дублирующее правило с тем же набором
        # rule_set тегов. Сравниваем по отсортированному кортежу тегов.
        existing_signatures = set()
        for r in existing_rules:
            if isinstance(r, dict) and isinstance(r.get("rule_set"), list):
                existing_signatures.add(
                    (tuple(sorted(r["rule_set"])), r.get("outbound"))
                )
        for nr in new_rules:
            sig = (tuple(sorted(nr["rule_set"])), nr["outbound"])
            if sig not in existing_signatures:
                existing_rules.insert(0, nr)
                existing_signatures.add(sig)
        route["rules"] = existing_rules

    return config


# =============================================================================
#  TUI: меню управления
# =============================================================================
def do_manage_singbox_rulesets() -> None:
    """TUI меню: вкл/выкл фичу + выбор ruleset'ов из каталога.

    Вызывается из _core.py main_menu() → пункт «R» в подменю управления
    клиентскими конфигами (рядом с пунктом 5 «Генерация Clash/Sing-box»).
    """
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_bottom = core._box_bottom
    _box_item   = core._box_item
    _box_info   = getattr(core, "_box_info", None) or core._box_row
    _box_ok     = core._box_ok
    _box_warn   = core._box_warn
    GREEN = core.GREEN
    RED   = core.RED
    YELLOW = core.YELLOW
    CYAN  = core.CYAN
    DIM   = core.DIM
    NC    = core.NC

    while True:
        cfg = get_rulesets_config()
        enabled = cfg["enabled"]
        selected = set(cfg["selected"])

        print()
        _box_top("Sing-box rulesets для Podkop / OpenWrt")
        _box_row()
        status = (f"{GREEN}ВКЛЮЧЕНО{NC}" if enabled else f"{RED}ВЫКЛЮЧЕНО{NC}")
        _box_row(f"Статус: {status}")
        _box_row()
        _box_row(f"{DIM}Добавляет в клиентский sing-box конфиг route.rule_set +{NC}")
        _box_row(f"{DIM}route.rules с готовыми .srs списками от{NC}")
        _box_row(f"{DIM}hydraponique/roscomvpn-geosite (217★ на GitHub).{NC}")
        _box_row()
        _box_row(f"{CYAN}Зачем:{NC} российские сервисы (Госуслуги, WB, Ozon,")
        _box_row(f"Детский Мир) идут НАПРЯМУЮ — антифрод не детектит VPN.")
        _box_row()
        _box_sep()

        idx_map: dict[str, str] = {}
        for i, (tag, meta) in enumerate(RULESET_CATALOG.items(), start=1):
            mark = f"{GREEN}[x]{NC}" if tag in selected else f"{RED}[ ]{NC}"
            action_color = GREEN if meta["action"] == "direct" else CYAN
            _box_row(
                f"  {i}  {mark}  {meta['label']}  "
                f"{DIM}({action_color}{meta['action']}{NC}{DIM}){NC}"
            )
            _box_row(f"      {meta['hint']}")
            idx_map[str(i)] = tag

        _box_row()
        _box_item("T", f"Переключить вкл/выкл  {DIM}(сейчас: {('ON' if enabled else 'OFF')}){NC}")
        _box_item("R", f"{YELLOW}Сбросить к набору по умолчанию{NC}")
        _box_item("0", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            print()
            break

        if ch in ("0", "", "q"):
            break

        elif ch == "t":
            new_enabled = not enabled
            set_rulesets_config(new_enabled, list(selected))
            if new_enabled:
                _box_ok("Фича включена — новые sing-box конфиги будут включать ruleset'ы.")
                _box_info("Существующие клиентские конфиги обновятся при следующем запросе подписки.")
            else:
                _box_warn("Фича выключена — sing-box конфиги вернулись к виду только с outbounds.")
            input(f"{CYAN}Нажмите Enter...{NC}")

        elif ch == "r":
            set_rulesets_config(enabled, list(DEFAULT_SELECTED))
            _box_ok("Сброшено к набору по умолчанию (ru-direct + geoblock-ru-proxy + private-direct).")
            input(f"{CYAN}Нажмите Enter...{NC}")

        elif ch in idx_map:
            tag = idx_map[ch]
            if tag in selected:
                selected.discard(tag)
            else:
                selected.add(tag)
            # Не сохраняем enabled — только список выбранных.
            set_rulesets_config(enabled, sorted(selected))
            # Без input() — пользователь видит обновлённое меню сразу.

        else:
            _box_warn("Неверный выбор.")
            import time
            time.sleep(1)


# =============================================================================
#  ТОЧКА ВХОДА ДЛЯ ТЕСТОВ / ОТЛАДКИ
# =============================================================================
if __name__ == "__main__":
    # python3 singbox_client_rulesets.py — показывает текущий статус.
    cfg = get_rulesets_config()
    print(json.dumps(cfg, indent=2, ensure_ascii=False))
