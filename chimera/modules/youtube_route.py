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
# v4.25.1 FIX: Раньше использовались geosite:youtube и geosite:google, но
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

def _youtube_apply_to_xray() -> bool:
    """Добавляет YouTube→direct правило в Xray config.

    Идемпотентно: сначала убирает старое правило с comment="youtube_via_ru",
    затем добавляет новое. AWG-aware: outboundTag="direct-local" если
    AWG_EXIT_ENABLED, иначе "direct".

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

    # Если outbound direct-local ещё не существует (AWG mode), добавляем.
    # В обычном режиме "direct" уже есть во всех конфигах.
    _outbound_tag = "direct-local" if AWG_EXIT_ENABLED else "direct"

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
            # В AWG-режиме нужен "direct-local" (без fwmark) — чтобы YouTube
            # вышел через RU-сервер, а не через AWG-туннель к exit.
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
    """TUI-меню переключателя YouTube→RU.

    Показывает текущее состояние (state["youtube_via_ru"]) и предлагает:
      [1] YouTube через RU (entry-нода)  — добавляет правило
      [2] YouTube через exit-ноды        — убирает правило (default)
      [Q] Назад
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

    # Текущее состояние из state.json (свежее, не из глобали —
    # на случай если пользователь редактировал state.json вручную).
    try:
        state = json.loads(core.STATE_FILE.read_text()) if core.STATE_FILE.exists() else {}
    except Exception:
        state = {}
    current = state.get("youtube_via_ru", False)

    # Дополнительная проверка: что в конфиге реально есть правило.
    # Если state говорит True, но правила нет (например, после regenerate
    # xray-config через пункт 5b — он перезаписывает routing полностью)
    # — показываем что правило отсутствует.
    rule_in_config = _youtube_rule_in_xray_config()

    print()
    _box_top("📺  YouTube через RU  (entry-нода)")
    _box_row()
    if current and rule_in_config:
        _box_row(f"  Текущий маршрут: {GREEN}YouTube → RU entry{NC}")
        _box_row(f"  {DIM}geosite:youtube → outbound:{'direct-local' if core.AWG_EXIT_ENABLED else 'direct'}{NC}")
    elif current and not rule_in_config:
        _box_row(f"  Текущий маршрут: {YELLOW}несогласованно{NC}")
        _box_row(f"  {DIM}state.json: youtube_via_ru=True, но правило в config.json отсутствует.{NC}")
        _box_row(f"  {DIM}Это бывает после regenerate xray-config (пункт 5b).{NC}")
        _box_row(f"  {DIM}Нажмите [1] чтобы пере-применить.{NC}")
    else:
        _box_row(f"  Текущий маршрут: {CYAN}YouTube → exit-ноды (default){NC}")
        _box_row(f"  {DIM}Весь YouTube-трафик идёт через каскад exit-нод.{NC}")
    _box_row()
    _box_row(f"  {DIM}Переключатель добавляет/убирает правило routing в config.json:{NC}")
    _box_row(f"  {DIM}  domain:[geosite:youtube, googlevideo.com, ytimg.com, ...] → direct{NC}")
    _box_row(f"  {DIM}AWG-aware: outbound=direct-local когда AWG exit активен.{NC}")
    _box_sep()
    _box_item("1", f"{'● ' if current and rule_in_config else '  '}YouTube через RU entry")
    _box_item("2", f"{'● ' if not current else '  '}YouTube через exit-ноды (default)")
    _box_row()
    _box_item("Q", f"{DIM}Назад{NC}")
    _box_bottom()

    try:
        ch = input(f"{CYAN}  Выбор [1/2/Q]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        print()
        return

    if ch == "1":
        # Проверка geosite.dat
        if not _geosite_available():
            warn("geosite.dat не найден — правило geosite:youtube не сработает.")
            warn("Установите geo-файлы: Настройки сети → 1 (Split Tunneling) → 1 (Включить).")
            _box_warn("  Geo-файлы необходимы для geosite:youtube категории.")
            input(f"\n{BLUE}  Нажмите Enter...{NC}")
            return

        info("Применяем YouTube→RU...")
        if _youtube_apply_to_xray():
            _save_youtube_state(True)
            _box_info("YouTube теперь выходит через RU entry-ноду.")
            try:
                core._log_change("youtube_route", "exit -> RU entry (direct)")
            except Exception:
                pass
        else:
            _box_warn("  Не удалось применить правило — смотрите вывод выше.")
    elif ch == "2":
        info("Убираем YouTube→RU правило...")
        if _youtube_remove_from_xray():
            _save_youtube_state(False)
            _box_info("YouTube теперь через exit-ноды (default).")
            try:
                core._log_change("youtube_route", "RU entry -> exit (default)")
            except Exception:
                pass
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


def _save_youtube_state(enabled: bool) -> None:
    """Сохраняет youtube_via_ru в state.json.

    НЕ использует _core.YOUTUBE_VIA_RU глобаль (она обновится при
    следующем _load_state_into_globals()) — пишем прямо в state.json.
    """
    core = _core_module()
    try:
        if core.STATE_FILE.exists():
            state = json.loads(core.STATE_FILE.read_text())
        else:
            state = {}
        state["youtube_via_ru"] = bool(enabled)
        core.STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    except Exception as e:
        try:
            core.warn(f"Не удалось обновить state.json: {e}")
        except Exception:
            print(f"Не удалось обновить state.json: {e}")


def restore_youtube_rule_if_needed(silent: bool = False) -> bool:
    """Пере-применяет YouTube→RU правило если state.json говорит что оно
    должно быть включено, но в config.json его нет.

    ВЫЗЫВАЕТСЯ ИЗ:
      - ru_subnets._ru_subnets_restore_if_needed (после regenerate xray-config)
      - Любого места которое перезаписывает routing полностью.

    Это нужно потому что generate_xray_config* полностью перезаписывает
    config.json, стирая все runtime-правила (youtube_via_ru, ru_subnets_ripe,
    geoip_block). После regenerate — restore_*_if_needed пере-добавляет
    их из state.

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
        if not state.get("youtube_via_ru", False):
            return False
    except Exception:
        return False

    if _youtube_rule_in_xray_config():
        return False  # Уже на месте

    if not silent:
        try:
            core.info("Пере-применяем YouTube→RU правило после regenerate xray-config...")
        except Exception:
            pass
    return _youtube_apply_to_xray()
