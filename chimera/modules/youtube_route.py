"""
chimera/modules/youtube_route.py
───────────────────────────────────────────────────────────────────────────────
Переключатель маршрутизации YouTube между RU (entry-нода, direct) и
каскадом exit-нод (chain-exit / chain-balancer).

ПОЧЕМУ ЭТО ОТДЕЛЬНЫЙ МОДУЛЬ (а не опция в split_tunnel):
  Split tunneling — глобальный режим: «РФ-трафик через direct,
  заблокированное — через exit». Если он выключен, весь трафик
  (включая YouTube) идёт через exit-ноды.

  Этот модуль решает обратную задачу: при ВЫключенном split tunneling
  (весь трафик через exit) — точечно направить YouTube через RU entry.
  Или при ВКЛЮченном split tunneling (весь РФ через direct) — точечно
  пустить YouTube через exit (когда RU-сервер не справляется с 4K).

  Правило добавляется в routing.rules ПЕРЕД catch-all (tcp,udp → exit)
  и ПОСЛЕ RIPE ru_subnets правил. Удаляется по comment="youtube_via_ru".

АРХИТЕКТУРА (mirror ru_subnets.py Pattern C):
  1. _youtube_apply_to_xray() — добавляет правило
     {type: "field", domain: ["geosite:youtube", "geosite:youtube-googletag",
     "domain:googlevideo.com", "domain:ytimg.com", ...],
     outboundTag: <direct|direct-local>, comment: "youtube_via_ru"}
     в routing.rules, убирая старое правило с тем же comment (идемпотентность).
  2. _youtube_remove_from_xray() — фильтрует rules по comment.
  3. do_manage_youtube_via_ru() — TUI-меню, переключатель On/Off.
  4. Состояние хранится в state.json как youtube_via_ru: bool.
     Загружается в _core.YOUTUBE_VIA_RU через _load_state_into_globals().

AWG-AWARE:
  Если AWG_EXIT_ENABLED=True — используем outboundTag="direct-local"
  (freedom без fwmark), чтобы YouTube выходил через дефолтный маршрут
  RU-сервера, а не через AWG-туннель к exit-ноде. Логика та же что
  в ru_subnets._ru_subnets_apply_to_xray (lines 267, 290-296).

GEO-FILES:
  Требует geosite.dat с категорией 'youtube' (runetfreedom/russia-v2ray-rules-dat
  включает её). Если geosite.dat отсутствует — пользователь видит предупреждение
  и приглашение установить geo-файлы (через Split Tunneling → 1).

ВЫЗОВ:
  TUI: Настройки сети → Y → YouTube через RU
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

# ── Делегирование в _core.py (без circular import) ──────────────────────────
def _core_module():
    """Возвращает модуль chimera._core (lazy import)."""
    import importlib
    return importlib.import_module("chimera._core")


# ── Константы ───────────────────────────────────────────────────────────────
_YOUTUBE_RULE_COMMENT = "youtube_via_ru"

# Список доменов YouTube и связанных сервисов.
#
# v5.0.0 FIX: Раньше использовались geosite:youtube и geosite:google, но
# geosite.dat от runetfreedom (который ставит Chimera) НЕ содержит этих
# категорий — только российские (category-ru, ru-available-only-inside).
# Xray падал при старте с "code not found in geosite.dat: YOUTUBE".
#
# Теперь используем ТОЛЬКО domain: записи — они работают с любым geosite.dat
# (или даже без него). Список расширен чтобы покрыть то, что обычно входит
# в geosite:youtube:
#   - Основные домены: youtube.com, youtu.be, *.youtube-nocookie.com и т.д.
#   - CDN видео-стримов: googlevideo.com, manifest.googlevideo.com
#   - Thumbnails/images: ytimg.com, ggpht.com
#   - Внутренний API: youtubei.googleapis.com
#   - Ad-tracking: youtube-googletag (через domain: записи)
#
# Xray matching: domain:example.com матчит поддомены тоже (foo.example.com).
# Полный список — чтобы не было ситуации когда видео-стрим через RU,
# а thumbnails через exit (или наоборот) — асимметричная маршрутизация
# ломает сессию YouTube.
_YOUTUBE_DOMAINS = [
    # Основные домены YouTube
    "domain:youtube.com",
    "domain:youtu.be",
    "domain:youtube-nocookie.com",
    "domain:youtubeeducation.com",
    "domain:youtubei.googleapis.com",
    "domain:ytimg.com",
    # CDN видео-стримов (DASH/HLS манифесты + сегменты)
    "domain:googlevideo.com",
    "domain:manifest.googlevideo.com",
    # Avatars / user images
    "domain:ggpht.com",
    # Ad-tracking (YouTube-specific)
    "domain:youtube-googletag.com",
    # Google services used by YouTube internally
    "domain:accounts.google.com",
    "domain:apis.google.com",
]


# =============================================================================
#  ПРИМЕНЕНИЕ / УДАЛЕНИЕ ПРАВИЛА В XRAY CONFIG
# =============================================================================

def _youtube_apply_to_xray(target_tag: str | None = None) -> bool:
    """Добавляет YouTube→{target} правило в Xray config.

    Идемпотентно: сначала убирает старое правило с comment="youtube_via_ru",
    затем добавляет новое.

    Args:
      target_tag: None — RU entry-нода (direct/direct-local, AWG-aware,
                  автосоздание outbound если отсутствует).
                  "chain-exit-N" — конкретная exit-нода N (1-indexed).
                  Outbound должен уже существовать в cfg["outbounds"] —
                  если нет (нода удалена после реконфигурации), возвращаем
                  False с warn, НЕ пишем правило с несуществующим тегом
                  (Xray падает с "unknown outbound tag").

    Возвращает True если хотя бы один config.json пропатчен успешно.
    """
    core = _core_module()
    AWG_EXIT_ENABLED         = core.AWG_EXIT_ENABLED
    CONFIG_DIR               = core.CONFIG_DIR
    _nginx_restart_if_reality = core._nginx_restart_if_reality
    _run                     = core._run
    _set_config_owner        = core._set_config_owner
    info                     = core.info
    success                  = core.success
    warn                     = core.warn

    # Определяем outboundTag для правила.
    if target_tag is not None:
        # Конкретная exit-нода — outbound уже должен существовать.
        _outbound_tag = target_tag
        _is_exit_node = True
    else:
        # RU entry-нода — direct/direct-local, AWG-aware.
        _outbound_tag = "direct-local" if AWG_EXIT_ENABLED else "direct"
        _is_exit_node = False

    written: set = set()
    ok = False
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
            cfg      = json.loads(cfg_path.read_text())
            routing  = cfg.setdefault("routing", {})
            # Убираем старое правило (идемпотентность).
            rules    = [r for r in routing.setdefault("rules", [])
                        if r.get("comment") != _YOUTUBE_RULE_COMMENT]
            outbounds = cfg.setdefault("outbounds", [])

            if _is_exit_node:
                # Проверяем что outbound с этим тегом существует.
                # Если нет — нода была удалена после реконфигурации.
                # НЕ пишем правило с несуществующим тегом (Xray падает).
                if not any(ob.get("tag") == _outbound_tag for ob in outbounds):
                    # Извлекаем номер ноды из тега для понятного сообщения.
                    _node_num = "?"
                    _m = re.match(r'chain-exit-(\d+)', _outbound_tag)
                    if _m:
                        _node_num = _m.group(1)
                    warn(f"Exit-нода #{_node_num} ({_outbound_tag}) "
                         f"была удалена из конфигурации — выберите другую")
                    # НЕ пишем конфиг, НЕ считаем успехом.
                    continue
            else:
                # RU-путь: автосоздание outbound если отсутствует.
                if AWG_EXIT_ENABLED:
                    if not any(ob.get("tag") == "direct-local" for ob in outbounds):
                        outbounds.append({
                            "protocol": "freedom",
                            "tag":      "direct-local",
                            "settings": {"domainStrategy": "UseIPv4"},
                        })
                        info("AWG: добавлен outbound direct-local для YouTube→RU")
                else:
                    if not any(ob.get("tag") == "direct" for ob in outbounds):
                        outbounds.append({"protocol": "freedom", "tag": "direct"})

            # Новое правило. Prepended ПЕРЕД существующими — Xray eval
            # top-to-bottom, первое совпадение выигрывает. catch-all
            # (network=tcp,udp без domain) остаётся в конце.
            new_rule = {
                "type":        "field",
                "domain":      list(_YOUTUBE_DOMAINS),
                "outboundTag": _outbound_tag,
                "comment":     _YOUTUBE_RULE_COMMENT,
            }
            routing["rules"] = [new_rule] + rules
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(cfg_path)
            info(f"Конфиг: {cfg_path} (YouTube→{_outbound_tag})")
            ok = True
        except Exception as e:
            warn(f"Ошибка патча {cfg_path}: {e}")

    if not ok:
        if _is_exit_node:
            # warn уже вызван выше с конкретным сообщением про ноду.
            return False
        warn("Конфиг Xray не найден — не удалось применить YouTube→RU")
        return False

    # Restart xray, wait for it to come up (mirror ru_subnets).
    _run(["systemctl", "restart", "xray"], check=False, quiet=True)
    r = None
    for _ in range(30):
        r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
        if r.stdout.strip() == "active":
            break
        time.sleep(1)
    if not r or r.stdout.strip() != "active":
        warn("Xray не запустился — проверьте: journalctl -u xray -n 30")
        _nginx_restart_if_reality()
        return False
    if _is_exit_node:
        success(f"YouTube → {_outbound_tag} (exit-нода)")
    else:
        success(f"YouTube → {_outbound_tag} (RU entry-нода)")
    _nginx_restart_if_reality()
    return True


def _youtube_remove_from_xray() -> bool:
    """Удаляет YouTube→direct правило из Xray config.

    Возвращает True если хотя бы один config.json пропатчен.
    """
    core = _core_module()
    CONFIG_DIR               = core.CONFIG_DIR
    _nginx_restart_if_reality = core._nginx_restart_if_reality
    _run                     = core._run
    _set_config_owner        = core._set_config_owner
    success                  = core.success
    warn                     = core.warn

    written: set = set()
    ok = False
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
            old_count = len(routing.get("rules", []))
            routing["rules"] = [r for r in routing.get("rules", [])
                                if r.get("comment") != _YOUTUBE_RULE_COMMENT]
            new_count = len(routing["rules"])
            if new_count == old_count:
                # Правила не было — пропускаем.
                continue
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(cfg_path)
            info_msg = f"Конфиг: {cfg_path} (удалено правило YouTube→RU)"
            try:
                core.info(info_msg)
            except Exception:
                print(info_msg)
            ok = True
        except Exception as e:
            warn(f"Ошибка {cfg_path}: {e}")

    if not ok:
        # Если ни в одном конфиге правила не было — это не ошибка.
        # Но всё равно перезапускаем xray чтобы конфиг был consistent.
        success("Правило YouTube→RU не найдено в конфиге — уже выключено.")
    else:
        _run(["systemctl", "restart", "xray"], check=False, quiet=True)
        r = None
        for _ in range(30):
            r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
            if r.stdout.strip() == "active":
                break
            time.sleep(1)
        if not r or r.stdout.strip() != "active":
            warn("Xray не запустился — проверьте: journalctl -u xray -n 30")
            _nginx_restart_if_reality()
            return False
        success("YouTube → exit-ноды (правило убрано)")
        _nginx_restart_if_reality()
    return True


# =============================================================================
#  ПРОВЕРКА НАЛИЧИЯ GEOSITE.DAT
# =============================================================================

def _geosite_available() -> bool:
    """Проверяет что geosite.dat доступен Xray (переиспользует
    split_tunnel._geo_files_available с auto_copy=True)."""
    try:
        from chimera.modules.split_tunnel import _geo_files_available
        return _geo_files_available(auto_copy=True)
    except Exception:
        return False


# =============================================================================
#  TUI-МЕНЮ
# =============================================================================

def do_manage_youtube_via_ru() -> None:
    """TUI-меню переключателя YouTube→RU / конкретная exit-нода.

    v5.0.0: расширено для multi-node режима — если CHAIN_NODES содержит
    >1 ноду, показывает по пункту на каждую ноду + RU + default.

    В single-node режиме (0-1 нода) — старое двухпунктовое меню без
    изменений (обратная совместимость).
    """
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_bottom = core._box_bottom
    _box_item   = core._box_item
    _box_info   = core._box_info
    _box_warn   = core._box_warn
    CYAN   = core.CYAN
    NC     = core.NC
    GREEN  = core.GREEN
    YELLOW = core.YELLOW
    RED    = core.RED
    BOLD   = core.BOLD
    DIM    = core.DIM
    BLUE   = core.BLUE
    info    = core.info
    warn    = core.warn
    success = core.success

    # Текущее состояние из state.json — с миграцией со старого bool-ключа.
    try:
        state = json.loads(core.STATE_FILE.read_text()) if core.STATE_FILE.exists() else {}
    except Exception:
        state = {}
    current_target = state.get("youtube_route_target")
    if current_target is None:
        # Миграция со старого формата.
        current_target = "ru" if state.get("youtube_via_ru", False) else "off"

    # Дополнительная проверка: что в конфиге реально есть правило.
    rule_in_config = _youtube_rule_in_xray_config()

    # Multi-node: проверяем количество exit-нод.
    nodes = getattr(core, "CHAIN_NODES", [])
    multi_node = len(nodes) > 1

    # Определяем отображаемое имя текущего маршрута.
    if current_target == "off":
        current_display = f"{CYAN}YouTube → exit-ноды (default){NC}"
        current_detail = f"{DIM}Весь YouTube-трафик идёт через каскад exit-нод.{NC}"
    elif current_target == "ru":
        if rule_in_config:
            current_display = f"{GREEN}YouTube → RU entry{NC}"
            current_detail = f"{DIM}outbound:{'direct-local' if core.AWG_EXIT_ENABLED else 'direct'}{NC}"
        else:
            current_display = f"{YELLOW}несогласованно{NC}"
            current_detail = f"{DIM}state: youtube_route_target=ru, но правило в config.json отсутствует.{NC}"
    elif current_target.startswith("chain-exit-"):
        if rule_in_config:
            # Извлекаем номер ноды и ищем её хост.
            _m = re.match(r'chain-exit-(\d+)', current_target)
            _node_idx = int(_m.group(1)) - 1 if _m else -1
            _host = nodes[_node_idx].get("host", "?") if 0 <= _node_idx < len(nodes) else "?"
            current_display = f"{GREEN}YouTube → Exit-нода #{_m.group(1) if _m else '?'} ({_host}){NC}"
            current_detail = f"{DIM}outbound:{current_target}{NC}"
        else:
            # Правила нет — нода удалена или после regenerate xray-config.
            _m = re.match(r'chain-exit-(\d+)', current_target)
            _node_num = _m.group(1) if _m else "?"
            _node_idx = int(_node_num) - 1 if _node_num != "?" else -1
            if 0 <= _node_idx < len(nodes):
                current_display = f"{YELLOW}несогласованно{NC}"
                current_detail = f"{DIM}state: youtube_route_target={current_target}, но правило отсутствует (regenerate?).{NC}"
            else:
                current_display = f"{YELLOW}несогласованно{NC}"
                current_detail = f"{DIM}Exit-нода #{_node_num} была удалена из конфигурации — выберите другую.{NC}"
    else:
        current_display = f"{CYAN}YouTube → exit-ноды (default){NC}"
        current_detail = f"{DIM}Весь YouTube-трафик идёт через каскад exit-нод.{NC}"

    print()
    _box_top("📺  YouTube маршрутизация")
    _box_row()
    _box_row(f"  Текущий маршрут: {current_display}")
    _box_row(f"  {current_detail}")
    _box_row()
    _box_row(f"  {DIM}Переключатель добавляет/убирает правило routing в config.json:{NC}")
    _box_row(f"  {DIM}  domain:[youtube.com, googlevideo.com, ytimg.com, ...] → {current_target}{NC}")
    _box_sep()

    if multi_node:
        # Multi-node меню: RU + N нод + default.
        _is_current = (current_target == "ru" and rule_in_config)
        _box_item("1", f"{'● ' if _is_current else '  '}YouTube через RU entry")
        for i, nd in enumerate(nodes):
            _tag = f"chain-exit-{i+1}"
            _is_cur = (current_target == _tag and rule_in_config)
            _host = nd.get("host", "?")
            _box_item(str(i+2), f"{'● ' if _is_cur else '  '}YouTube через Exit-нода #{i+1} ({_host})")
        _default_idx = len(nodes) + 2
        _is_cur = (current_target == "off")
        _box_item(str(_default_idx), f"{'● ' if _is_cur else '  '}YouTube через exit-ноды (default, балансировщик)")
        _box_row()
        _box_item("Q", f"{DIM}Назад{NC}")
        _box_bottom()

        try:
            ch = input(f"{CYAN}  Выбор [1-{_default_idx}/Q]:{NC} ").strip().lower()
        except KeyboardInterrupt:
            print()
            return

        if ch == "q" or ch == "":
            return
        try:
            _choice = int(ch)
        except ValueError:
            return

        if _choice == 1:
            # RU entry
            if not _geosite_available():
                warn("geosite.dat не найден — правило geosite:youtube не сработает.")
                input(f"\n{BLUE}  Нажмите Enter...{NC}")
                return
            info("Применяем YouTube→RU...")
            if _youtube_apply_to_xray():
                _save_youtube_state("ru")
                _box_info("YouTube теперь выходит через RU entry-ноду.")
            else:
                _box_warn("  Не удалось применить правило — смотрите вывод выше.")
        elif 2 <= _choice <= len(nodes) + 1:
            # Конкретная exit-нода
            _node_idx = _choice - 2  # 0-indexed
            _tag = f"chain-exit-{_node_idx+1}"
            _host = nodes[_node_idx].get("host", "?")
            info(f"Применяем YouTube→{_tag} ({_host})...")
            if _youtube_apply_to_xray(target_tag=_tag):
                _save_youtube_state(_tag)
                _box_info(f"YouTube теперь через Exit-ноду #{_node_idx+1} ({_host}).")
            else:
                _box_warn(f"  Не удалось — нода {_tag} возможно удалена. Смотрите вывод выше.")
        elif _choice == _default_idx:
            # Default (балансировщик)
            info("Убираем YouTube→RU правило...")
            if _youtube_remove_from_xray():
                _save_youtube_state("off")
                _box_info("YouTube теперь через exit-ноды (default).")
            else:
                _box_warn("  Не удалось убрать правило — смотрите вывод выше.")
        else:
            return
    else:
        # Single-node / no-chain: старое двухпунктовое меню (обратная совместимость).
        _is_cur = (current_target == "ru" and rule_in_config)
        _box_item("1", f"{'● ' if _is_cur else '  '}YouTube через RU entry")
        _is_cur_off = (current_target == "off")
        _box_item("2", f"{'● ' if _is_cur_off else '  '}YouTube через exit-ноды (default)")
        _box_row()
        _box_item("Q", f"{DIM}Назад{NC}")
        _box_bottom()

        try:
            ch = input(f"{CYAN}  Выбор [1/2/Q]:{NC} ").strip().lower()
        except KeyboardInterrupt:
            print()
            return

        if ch == "1":
            if not _geosite_available():
                warn("geosite.dat не найден — правило geosite:youtube не сработает.")
                input(f"\n{BLUE}  Нажмите Enter...{NC}")
                return
            info("Применяем YouTube→RU...")
            if _youtube_apply_to_xray():
                _save_youtube_state("ru")
                _box_info("YouTube теперь выходит через RU entry-ноду.")
            else:
                _box_warn("  Не удалось применить правило — смотрите вывод выше.")
        elif ch == "2":
            info("Убираем YouTube→RU правило...")
            if _youtube_remove_from_xray():
                _save_youtube_state("off")
                _box_info("YouTube теперь через exit-ноды (default).")
            else:
                _box_warn("  Не удалось убрать правило — смотрите вывод выше.")
        else:
            return

    input(f"\n{BLUE}  Нажмите Enter...{NC}")


# =============================================================================
#  ВСПОМОГАТЕЛЬНЫЕ
# =============================================================================

def _youtube_rule_in_xray_config() -> bool:
    """Проверяет, есть ли правило с comment=youtube_via_ru в любом
    из config.json. Используется TUI для отображения актуального
    состояния (state.json может рассинхронизироваться после regenerate)."""
    core = _core_module()
    CONFIG_DIR = core.CONFIG_DIR
    for cfg_path in (CONFIG_DIR / "config.json",
                     Path("/usr/local/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            cfg = json.loads(cfg_path.read_text())
            for rule in cfg.get("routing", {}).get("rules", []):
                if rule.get("comment") == _YOUTUBE_RULE_COMMENT:
                    return True
        except Exception:
            continue
    return False


def _save_youtube_state(target: str) -> None:
    """Сохраняет youtube_route_target в state.json.

    Args:
      target: "ru" | "off" | "chain-exit-{N}"

    Также пишет legacy "youtube_via_ru": (target == "ru") для обратной
    совместимости с _core.YOUTUBE_VIA_RU и любыми внешними скриптами/
    бэкапами, которые могут читать этот ключ.
    """
    core = _core_module()
    try:
        if core.STATE_FILE.exists():
            state = json.loads(core.STATE_FILE.read_text())
        else:
            state = {}
        state["youtube_route_target"] = target
        # Legacy: youtube_via_ru = True только когда target == "ru".
        state["youtube_via_ru"] = (target == "ru")
        core.STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    except Exception as e:
        try:
            core.warn(f"Не удалось обновить state.json: {e}")
        except Exception:
            print(f"Не удалось обновить state.json: {e}")


def restore_youtube_rule_if_needed(silent: bool = False) -> bool:
    """Пере-применяет YouTube правило если state.json говорит что оно
    должно быть включено, но в config.json его нет.

    ВЫЗЫВАЕТСЯ ИЗ:
      - ru_subnets._ru_subnets_restore_if_needed (после regenerate xray-config)
      - Любого места которое перезаписывает routing полностью.

    v5.0.0: поддерживает не только RU (direct/direct-local), но и
    конкретную exit-ноду (chain-exit-N). Читает новый ключ
    "youtube_route_target" (с миграцией со старого "youtube_via_ru").

    Возвращает True если правило было пере-применено.
    """
    try:
        core = _core_module()
    except Exception:
        return False
    try:
        if not core.STATE_FILE.exists():
            return False
        state = json.loads(core.STATE_FILE.read_text())
    except Exception:
        return False

    # Миграция: новый ключ youtube_route_target, fallback на старый bool.
    target = state.get("youtube_route_target")
    if target is None:
        # Миграция со старого формата.
        target = "ru" if state.get("youtube_via_ru", False) else "off"

    if target == "off":
        return False

    if _youtube_rule_in_xray_config():
        return False  # Уже на месте

    # Определяем outboundTag для пере-применения.
    if target == "ru":
        tag = None  # direct/direct-local, AWG-aware
    else:
        tag = target  # chain-exit-N

    if not silent:
        try:
            core.info(f"Пере-применяем YouTube→{target} правило "
                      f"после regenerate xray-config...")
        except Exception:
            pass
    return _youtube_apply_to_xray(target_tag=tag)
