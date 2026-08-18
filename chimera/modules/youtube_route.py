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
_YOUTUBE_FRAG_RULE_COMMENT = "youtube_via_ru_fragment"
_YOUTUBE_QUIC_BLOCK_COMMENT = "youtube_block_quic"

#  маркер в state.json для сохранённых оригинальных значений sniffing.
# Используется _youtube_patch_inbounds_for_fragment() / _youtube_restore_inbounds_after_fragment()
# чтобы корректно откатывать routeOnly/destOverride после отключения fragment.
#
#  ВРЕМЕННО выключал вызовы patch_inbounds (routeOnly=True ломал UseIPv4
# на серверах без IPv6 — фикс v4.12.6).
#  ВЕРНУТЫ вызовы. Причина: на серверах с IPv6 routeOnly=True работает
# корректно и чинит асимметричную маршрутизацию QUIC-видео. Пользователь должен
# сам выбрать — если сервер без IPv6, можно не включать RU+fragment (или
# отключить QUIC block). Если с IPv6 — всё работает как задумано.
_YOUTUBE_SNIFFING_BACKUP_KEY = "_youtube_sniffing_backup"

#  безопасный sockopt для freedom outbound.
#
# В  мы добавили sockopt с tcpCongestion='bbr' и это сломало YouTube
# полностью (  откатили). Причина — tcpCongestion='bbr' требует
# загруженного модуля tcp_bbr в ядре, иначе setsockopt(TCP_CONGESTION,"bbr")
# возвращает ENOTSUP и Xray прерывает КАЖДЫЙ dial через freedom outbound.
#
#  временно убран из freedom outbound (у пользователя на сервере без
# IPv6 это вызывало 'Нет подключения' — но причина была в routeOnly, не sockopt).
#  ВОЗВРАЩЁН. tcpFastOpen/tcpKeepAlive*/tcpUserTimeout безопасны
# на любом современном ядре (в отличие от tcpCongestion='bbr').
#
# Подтверждено документацией Xray (v26.x): sockopt на freedom outbound
# поддерживается официально. Источник: xtls.github.io/en/config/transports/sockopt.html
_YOUTUBE_SAFE_SOCKOPT = {
    "tcpKeepAliveIdle":     60,
    "tcpKeepAliveInterval": 15,
    "tcpUserTimeout":       10000,
    "tcpFastOpen":          True,
}

# Список доменов YouTube и связанных сервисов.
#
#  FIX: Раньше использовались geosite:youtube и geosite:google, но
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
    #  расширенный набор CDN-доменов YouTube.
    # Без них видеострим (DASH) может асимметрично уйти через default outbound,
    # пока thumbnails/api идут через fragment — это и есть причина "Shorts
    # долго грузятся" и "видео buffering". Все эти домена на одной AS Google.
    "domain:wide-youtube.l.google.com",
    "domain:youtube-ui.l.google.com",
    "domain:youtubeembedded-pa.googleapis.com",
    "domain:youtube.googleapis.com",
    "domain:yt-video-googleusercontent.com",
    # Avatars / user images
    "domain:ggpht.com",
    "domain:lh3.googleusercontent.com",
    # Ad-tracking (YouTube-specific)
    "domain:youtube-googletag.com",
    # Google services used by YouTube internally
    "domain:accounts.google.com",
    "domain:apis.google.com",
]


# =============================================================================
#  ХЕЛПЕР: IP + ФЛАГ СТРАНЫ для exit-ноды
# =============================================================================
#  отображение флага страны рядом с IP exit-ноды в TUI-меню.
# Используется в do_manage_youtube_via_ru() для multi-node режима.
#
# Алгоритм:
#   1. Резолвим hostname → IPv4 через _resolve_host_fresh (DoH + fallback).
#   2. Запрашиваем страну через http://ip-api.com/json/{ip}?fields=countryCode
#      (тот же endpoint что в chain_nodes.py:2421, 4 сек таймаут).
#   3. Преобразуем countryCode в emoji-флаг через country_flag_emoji().
#
# Возвращает (ip_str, flag_emoji):
#   ip_str     — IP-адрес или "(IP недоступен)" если резолв упал.
#   flag_emoji — emoji-флаг (🇩🇪, 🇷🇺, ...) или пустая строка если страна
#                неизвестна или запрос упал. НЕ возвращаем 🌐 для fallback
#                (это зарезервировано для балансировщика) — лучше пусто.
#
#  FIX: U+FE0F (VARIATION SELECTOR-16) после regional indicator pair.
#   Без VS16 некоторые терминалы (особенно с нестандартными шрифтами) рендерят
#   regional indicator pair как ОДНУ букву вместо emoji-флага. Был зафиксирован
#   случай: 🇳🇱 рендерилась как "N" (одна буква), 🇩🇪 как "D", 🇮🇹 как "I",
#   но при этом 🇧🇾 (Беларусь) рендерилась корректно как флаг. Добавление
#   U+FE0F принудительно заставляет терминал рендерить пару как emoji.
#   _wcslen в box_renderer корректно считает VS16 как 0 колонок — выравнивание
#   бокса не ломается (проверено тестом test_box_right_border_aligned_with_emoji).
#
# Кеширование: модуль-level dict _NODE_IP_FLAG_CACHE[host] = (ip_str, flag).
# Это критично — меню может перерисовываться, и без кеша каждый раз был бы
# новый сетевой запрос (4 секунды на ноду × N нод = неприемлемо).
_NODE_IP_FLAG_CACHE: dict[str, tuple[str, str]] = {}


def _with_emoji_vs16(flag: str) -> str:
    """Добавляет U+FE0F (VARIATION SELECTOR-16) к emoji-флагу.

    VS16 — это Unicode variation selector, который говорит терминалу
    "рендери предшествующий символ как emoji, не как текст". Для regional
    indicator pair (🇷🇺 = U+1F1F7 + U+1F1FA) без VS16 некоторые терминалы
    рендерят только первую букву вместо флага.

    Также добавляет VS16 к 🌍 (U+1F30D) — на всякий случай, для терминалов
    которые рендерят 🌍 как 🌐 (Globe with meridians) без VS16.

    _wcslen корректно считает VS16 как 0 колонок — выравнивание бокса
    не ломается.
    """
    if not flag:
        return flag
    # Если уже есть VS16 в конце — не дублируем
    if flag.endswith("\ufe0f"):
        return flag
    return flag + "\ufe0f"


def _resolve_node_ip_and_flag(host: str) -> tuple[str, str]:
    """Резолвит host → (IP, flag_emoji) с кешированием.

    Возвращает (ip_str, flag_emoji):
      ip_str:     "132.243.221.181" или "(IP недоступен)".
      flag_emoji: "🇩🇪️" (с VS16) или "" (пусто если не удалось определить страну).

    Кеширует результат в _NODE_IP_FLAG_CACHE чтобы при перерисовке меню
    не делать повторных сетевых запросов (4с на каждый ip-api.com запрос).
    """
    # Кеш: host → (ip_str, flag_emoji)
    if host in _NODE_IP_FLAG_CACHE:
        return _NODE_IP_FLAG_CACHE[host]

    # Резолв IP через DoH (минуя локальный DNS-кэш) + fallback на системный
    # резолвер. См. chimera.modules.chain_nodes._resolve_host_fresh —
    # это нужно, чтобы флаг страны определялся по АКТУАЛЬНОМУ IP ноды,
    # а не по устаревшей кэш-записи (баг с blackshadows.ru и т.п.).
    ip = ""
    try:
        from chimera.modules.chain_nodes import _resolve_host_fresh
        ip = _resolve_host_fresh(host) or ""
    except Exception:
        try:
            import socket as _sock
            ip = _sock.gethostbyname(host)
        except Exception:
            ip = ""

    if not ip:
        result = ("(IP недоступен)", "")
        _NODE_IP_FLAG_CACHE[host] = result
        return result

    # Получаем страну через ip-api.com (best-effort, не блокируем надолго)
    flag = ""
    try:
        core = _core_module()
        _run = core._run
        r = _run(
            ["curl", "-s", "--max-time", "4",
             f"http://ip-api.com/json/{ip}?fields=countryCode"],
            capture=True, check=False,
        )
        if r.returncode == 0 and r.stdout.strip():
            data = json.loads(r.stdout.strip())
            if data.get("status") == "success" or "countryCode" in data:
                cc = data.get("countryCode", "")
                if cc and len(cc) == 2:
                    # country_flag_emoji из resources.py
                    try:
                        from chimera.modules.resources import country_flag_emoji
                        flag = country_flag_emoji(cc)
                        #  добавляем U+FE0F чтобы терминал рендерил
                        # regional indicator pair как emoji-флаг, не как буквы.
                        flag = _with_emoji_vs16(flag)
                    except Exception:
                        flag = ""
    except Exception:
        flag = ""

    result = (ip, flag)
    _NODE_IP_FLAG_CACHE[host] = result
    return result


# =============================================================================
#  ПРИМЕНЕНИЕ / УДАЛЕНИЕ ПРАВИЛА В XRAY CONFIG
# =============================================================================

# =============================================================================
#   ПАТЧ INBOUND SNIFFING ДЛЯ FRAGMENT-РЕЖИМА
# =============================================================================
# Проблема: по умолчанию (с v4.12.6) все VLESS/REALITY inbound имеют
#   routeOnly: False + destOverride: ["http", "tls"]
# Это значит:
#   1. QUIC-пакеты YouTube (UDP/443) НЕ имеют sniffed-домена в routing
#      → правило fragment (domain:[youtube...]) НЕ матчит QUIC
#      → QUIC видео идёт через catch-all к exit-нодам (медленно / блокируется ТСПУ)
#   2. routeOnly: False переписывает destination на sniffed domain
#      → freedom outbound получает домен и делает DNS-resolve через систему
#      → при медленном DNS это добавляет задержку на каждый новый TCP-коннект
#      → "видео buffering несколько секунд"
#   3. При смене параметров (Xray restart) — активные TCP-коннекты рвутся,
#      browser retries, но в момент restart routing не работает →
#      "Нет подключения к интернету" (проходит после перезагрузки сервера).
#
# Решение: ТОЛЬКО когда включён RU+fragment — патчим inbound на:
#   • routeOnly: True  (routing по SNI без переписывания destination)
#   • destOverride: ["http", "tls", "quic"]  (QUIC SNI используется для роутинга)
#
# После отключения fragment — откатываем обратно (routeOnly: False, без quic).
# Аналогично для AWG-режима: НЕ трогаем metadataOnly=True (там sniffing доменов
# отключён намеренно, AWG использует kernel-роутинг).
#
# ВАЖНО про фикс v4.12.6 и совместимость с IPv4-only серверами:
#   • routeOnly=True передаёт freedom outbound IP-адрес (а не домен) от клиента.
#   • Если клиент резолвит YouTube в IPv6 (мобильный оператор, некоторые ISP),
#     а RU-сервер БЕЗ IPv6 — freedom пытается звонить на IPv6 и dial падает
#     → 'Нет подключения к интернету'.
#   • На сервере С IPv6 — всё работает корректно.
#   • На сервере БЕЗ IPv6 — либо не включайте RU+fragment, либо используйте
#     QUIC block (чтобы QUIC-видео не пыталось звонить на IPv6), либо включите
#     WARP routing (он работает через Cloudflare IPv4 даже если у RU-сервера
#     нет IPv6).
#
# Источник: https://xtls.github.io/en/config/inbound.html#routeonly-true-false
#   "routeOnly: true — Use the sniffed domain only for routing; the proxy
#    destination address remains the IP. This item requires destOverride
#    to be enabled to work."

def _youtube_patch_inbounds_for_fragment(cfg: dict) -> bool:
    """Включает routeOnly=True + destOverride['quic'] во всех VLESS/REALITY
    inbound с metadataOnly=False (не-AWG).

    Возвращает True если хотя бы один inbound был изменён.
    """
    changed = False
    for ib in cfg.get("inbounds", []):
        proto = ib.get("protocol", "")
        if proto not in ("vless", "trojan", "vmess", "dokodemo-door"):
            continue
        sniffing = ib.get("sniffing")
        # Нет sniffing или disabled — пропускаем.
        if not sniffing or not sniffing.get("enabled"):
            continue
        # AWG-режим: metadataOnly=True означает что sniffers TLS/HTTP/QUIC
        # отключены, routeOnly не имеет эффекта. НЕ трогаем — оставляем как есть.
        if sniffing.get("metadataOnly") is True:
            continue
        # routeOnly: True — routing по SNI без переписывания destination.
        if sniffing.get("routeOnly") is not True:
            sniffing["routeOnly"] = True
            changed = True
        # Добавляем 'quic' в destOverride (если его нет).
        do = sniffing.setdefault("destOverride", ["http", "tls"])
        if not isinstance(do, list):
            do = ["http", "tls"]
            sniffing["destOverride"] = do
        if "quic" not in do:
            # Вставляем 'quic' в конец — порядок не важен для Xray.
            do.append("quic")
            changed = True
    return changed


def _youtube_restore_inbounds_after_fragment(cfg: dict) -> bool:
    """Восстанавливает дефолтные routeOnly=False + destOverride без 'quic'.

    Вызывается из _youtube_remove_from_xray() чтобы вернуть конфиг в исходное
    состояние (после того как fragment-правило удалено).

    Возвращает True если хотя бы один inbound был изменён.
    """
    changed = False
    for ib in cfg.get("inbounds", []):
        proto = ib.get("protocol", "")
        if proto not in ("vless", "trojan", "vmess", "dokodemo-door"):
            continue
        sniffing = ib.get("sniffing")
        if not sniffing or not sniffing.get("enabled"):
            continue
        # НЕ трогаем metadataOnly=True (AWG-режим).
        if sniffing.get("metadataOnly") is True:
            continue
        # routeOnly: False (дефолт проекта с v4.12.6).
        if sniffing.get("routeOnly") is not False:
            sniffing["routeOnly"] = False
            changed = True
        # Убираем 'quic' из destOverride.
        do = sniffing.get("destOverride", [])
        if isinstance(do, list) and "quic" in do:
            sniffing["destOverride"] = [x for x in do if x != "quic"]
            changed = True
    return changed


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


def _youtube_apply_fragment_to_xray(
    packets: str = "1",
    length: str = "10-30",
    interval: str = "3-8",
    block_quic: bool = False,
    max_split: str | None = None,
) -> bool:
    """Добавляет YouTube→RU правило с TCP-фрагментацией ClientHello.

    Создаёт отдельный outbound 'direct-fragment' (freedom protocol) с
    settings.fragment — Xray разбивает первые N байт TLS ClientHello
    на мелкие куски, что мешает ТСПУ DPI-анализу SNI.

     ТСПУ начал фильтровать YouTube SNI на прямых соединениях
    из РФ. Раньше YouTube→RU (direct) работал. Теперь нужен fragment
    чтобы обойти DPI.

     дефолтные параметры изменены на более сбалансированные
    (packets="1", length="10-30", interval="3-8") — меньше задержка,
    достаточно для обхода ТСПУ. Пресеты доступны в меню.

     добавлена опциональная блокировка QUIC (block_quic=True).
    По умолчанию ВЫКЛЮЧЕНА — на некоторых конфигурациях Xray QUIC block
    ломает YouTube полностью. Включается в подменю пресета.

     block_quic по умолчанию False (был True в   вызывал
    'Нет подключения к интернету' у некоторых пользователей).

     убран sockopt из freedom outbound — он ломал YouTube
    (tcpFastOpen/tcpCongestion/tcpUserTimeout могут не поддерживаться
    freedom outbound или вызывать проблемы). Возвращаем к чистому
    fragment, как было в рабочей  

     ПОЛНАЯ переработка стабильности YouTube через fragment:
      • Возврат безопасного sockopt (БЕЗ tcpCongestion='bbr' — он был
        причиной поломки  . Проверено по доке Xray v26.x:
        sockopt на freedom outbound поддерживается официально.
      • Патч inbound sniffing: routeOnly=True + destOverride["quic"]
        только при активном fragment. Это чинит:
          - QUIC видео теперь матчится по SNI (раньше шло через catch-all)
          - destination не переписывается (DNS-resolve не задерживает)
          - "Нет подключения" при смене preset — сокращается до минимума
      • maxSplit — новое поле fragment (недокументированное, но
        поддерживаемое в Xray v26.x). Ограничивает количество фрагментов
        на один TCP-сегмент — стабильность при больших ClientHello.
      • Грейсфул-рестарт: 500мс задержка перед `systemctl restart xray`,
        чтобы активные соединения успели корректно завершиться.
      • Расширенный список YouTube-доменов (CDN variants).

     HOTFIX — откат опасных изменений  (на сервере без IPv6
      у пользователя  ломал YouTube полностью):
      • УБРАН sockopt из freedom outbound.
      • УБРАНЫ вызовы _youtube_patch_inbounds_for_fragment() /
        _youtube_restore_inbounds_after_fragment().
      • ОСТАВЛЕНЫ: maxSplit, расширенный список доменов, грейсфул-рестарт.

     ВОЗВРАТ  — пользователь переезжает на сервер с IPv6.
      На сервере с IPv6 routeOnly=True безопасен и чинит асимметричную
      маршрутизацию QUIC-видео. Возвращаем:
      • ВОЗВРАЩЁН sockopt в freedom outbound (tcpKeepAlive + TFO + tcpUserTimeout).
      • ВОЗВРАЩЕНЫ вызовы _youtube_patch_inbounds_for_fragment() /
        _youtube_restore_inbounds_after_fragment().
      • ВАЖНО про IPv4-only серверы: на сервере БЕЗ IPv6 не включайте
        RU+fragment (или включайте QUIC block). См. подробнее в комментарии
        к _youtube_patch_inbounds_for_fragment().

    Требует Xray 26.x+ (XTLS форк поддерживает fragment в freedom.settings).
    Vanilla Xray-core не поддерживает — будет ошибка при старте.

    Args:
      packets:    "1" — только первый TCP-сегмент (ClientHello)
      length:     "10-30" — размер каждого фрагмента в байтах
      interval:   "3-8" — задержка между фрагментами в мс
      block_quic: если True — блокировать QUIC (UDP/443) для YouTube.
                  По умолчанию False — может ломать YouTube.
      max_split:  диапазон max количества фрагментов на пакет ("3-6")
                  или None — не добавлять поле (поведение по умолчанию).

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

    # В AWG-режиме используем direct-local-fragment (без fwmark → default route),
    # иначе — direct-fragment (с fwmark → awg0).
    _outbound_tag = "direct-local-fragment" if AWG_EXIT_ENABLED else "direct-fragment"

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
            # Убираем старые YouTube правила (и обычное, и fragment).
            rules    = [r for r in routing.setdefault("rules", [])
                        if r.get("comment") not in (_YOUTUBE_RULE_COMMENT,
                                                     _YOUTUBE_FRAG_RULE_COMMENT)]
            outbounds = cfg.setdefault("outbounds", [])

            # Создаём outbound direct-fragment если его нет.
            # Перезаписываем если есть — чтобы обновить параметры fragment.
            outbounds = [ob for ob in outbounds if ob.get("tag") != _outbound_tag]
            #  безопасный sockopt для freedom outbound.
            #  был sockopt с tcpCongestion='bbr' → ломал YouTube полностью
            # (bbr требует modprobe tcp_bbr; иначе setsockopt возвращает ENOTSUP,
            #  Xray прерывает dial).
            #  sockopt убран целиком.  возвращён БЕЗ bbr.
            #  временно убран.  ВОЗВРАЩЁН.
            # Подтверждено докой: https://xtls.github.io/en/config/transports/sockopt.html
            # «For direct outbounds such as Freedom, the peer is usually any
            # ordinary public network target... only sockopt is available.»
            _fragment_settings = {
                "domainStrategy": "UseIPv4",
                "fragment": {
                    "packets":  packets,
                    "length":   length,
                    "interval": interval,
                },
            }
            #  maxSplit — недокументированное, но поддерживаемое поле
            # в fragment. Ограничивает количество фрагментов на один TCP-сегмент.
            # Полезно для больших ClientHello (TLS 1.3 + ECH + ALPN).
            if max_split is not None and max_split != "":
                _fragment_settings["fragment"]["maxSplit"] = max_split
            outbounds.append({
                "protocol": "freedom",
                "tag":      _outbound_tag,
                "settings": _fragment_settings,
                "sockopt":  dict(_YOUTUBE_SAFE_SOCKOPT),
            })
            cfg["outbounds"] = outbounds

            #  ПАТЧ INBOUND SNIFFING — критично для стабильности fragment.
            # Без этого QUIC-трафик YouTube (UDP/443) не матчится по domain в
            # routing → идёт через catch-all к exit-нодам. Также routeOnly=True
            # убирает лишний DNS-resolve в freedom outbound.
            #  временно выключался (ломал UseIPv4 на серверах без IPv6).
            #  ВОЗВРАЩЁН. На сервере БЕЗ IPv6 — либо не включайте
            # RU+fragment, либо включайте QUIC block.
            _inbounds_changed = _youtube_patch_inbounds_for_fragment(cfg)

            #  опциональная блокировка QUIC (UDP/443) для YouTube.
            # По умолчанию ВЫКЛЮЧЕНА (block_quic=False) — на некоторых конфигурациях
            # Xray QUIC block ломает YouTube полностью ('Нет подключения').
            # Включается в подменю пресета если пользователь хочет попробовать.
            if block_quic:
                if not any(ob.get("tag") == "youtube-quic-block" for ob in cfg["outbounds"]):
                    cfg["outbounds"].append({
                        "protocol": "blackhole",
                        "tag":      "youtube-quic-block",
                    })
                # Убираем старое правило блокировки QUIC (идемпотентность).
                rules = [r for r in rules
                         if r.get("comment") != _YOUTUBE_QUIC_BLOCK_COMMENT]
                quic_block_rule = {
                    "type":        "field",
                    "port":        "443",
                    "network":     "udp",
                    "domain":      list(_YOUTUBE_DOMAINS),
                    "outboundTag": "youtube-quic-block",
                    "comment":     _YOUTUBE_QUIC_BLOCK_COMMENT,
                }
                info("QUIC block: ВКЛЮЧЁН (UDP/443 для YouTube → blackhole)")
            else:
                # Убираем QUIC block если он был ранее включён.
                rules = [r for r in rules
                         if r.get("comment") != _YOUTUBE_QUIC_BLOCK_COMMENT]
                cfg["outbounds"] = [ob for ob in cfg["outbounds"]
                                    if ob.get("tag") != "youtube-quic-block"]

            info(f"Outbound '{_outbound_tag}' (fragment: packets={packets}, "
                 f"length={length}, interval={interval}"
                 + (f", maxSplit={max_split}" if max_split else "")
                 + ", sockopt: keepalive+TFO)")

            # Новое правило fragment.
            new_rule = {
                "type":        "field",
                "domain":      list(_YOUTUBE_DOMAINS),
                "outboundTag": _outbound_tag,
                "comment":     _YOUTUBE_FRAG_RULE_COMMENT,
            }
            # Если QUIC block включён — ставим его первым, затем fragment.
            if block_quic:
                routing["rules"] = [quic_block_rule, new_rule] + rules
            else:
                routing["rules"] = [new_rule] + rules
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(cfg_path)
            _quic_status = "+ QUIC block" if block_quic else "(без QUIC block)"
            _sniff_status = ", sniffing patched" if _inbounds_changed else ""
            info(f"Конфиг: {cfg_path} (YouTube→{_outbound_tag} {_quic_status}{_sniff_status})")
            ok = True
        except Exception as e:
            warn(f"Ошибка патча {cfg_path}: {e}")

    if not ok:
        warn("Конфиг Xray не найден — не удалось применить YouTube→RU+fragment")
        return False

    #  грейсфул-рестарт — даём 500мс активным соединениям завершиться
    # перед restart xray. Уменьшает "Нет подключения к интернету" при смене
    # preset (активные TCP-коннекты к YouTube CDN рвутся, browser retries,
    # но Xray в момент restart недоступен).
    time.sleep(0.5)

    # Restart xray, wait for it to come up.
    _run(["systemctl", "restart", "xray"], check=False, quiet=True)
    r = None
    for _ in range(30):
        r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
        if r.stdout.strip() == "active":
            break
        time.sleep(1)
    if not r or r.stdout.strip() != "active":
        warn("Xray не запустился — возможно ваш Xray не поддерживает fragment в freedom.settings")
        warn("Проверьте: journalctl -u xray -n 30")
        warn("Откатите: меню YouTube → [6] (exit-ноды default)")
        _nginx_restart_if_reality()
        return False
    success(f"YouTube → {_outbound_tag} (RU+fragment, обход ТСПУ DPI)")
    _nginx_restart_if_reality()
    return True


def _youtube_remove_from_xray() -> bool:
    """Удаляет все YouTube правила (direct, direct-fragment, warp) из Xray config.

    Возвращает True если хотя бы один config.json пропатчен.
    """
    core = _core_module()
    CONFIG_DIR               = core.CONFIG_DIR
    _nginx_restart_if_reality = core._nginx_restart_if_reality
    _run                     = core._run
    _set_config_owner        = core._set_config_owner
    success                  = core.success
    warn                     = core.warn

    # Все возможные comment для YouTube правил
    _youtube_comments = {
        _YOUTUBE_RULE_COMMENT,           # youtube_via_ru
        _YOUTUBE_FRAG_RULE_COMMENT,      # youtube_via_ru_fragment
        _YOUTUBE_QUIC_BLOCK_COMMENT,     # youtube_block_quic
        "youtube_via_warp",              # из youtube_warp_route.py
    }
    # Все возможные outbound tags для YouTube
    _youtube_outbound_tags = {
        "direct-fragment", "direct-local-fragment", "warp", "youtube-quic-block"
    }

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
            # Удаляем все YouTube правила
            routing["rules"] = [r for r in routing.get("rules", [])
                                if r.get("comment") not in _youtube_comments]
            new_count = len(routing["rules"])
            # Удаляем YouTube-специфичные outbounds (direct-fragment, warp)
            # Оставляем direct/direct-local — они могут использоваться ru_subnets
            outbounds = cfg.get("outbounds", [])
            new_outbounds = [ob for ob in outbounds
                             if ob.get("tag") not in _youtube_outbound_tags]
            if len(new_outbounds) != len(outbounds):
                cfg["outbounds"] = new_outbounds
            #  восстанавливаем дефолтные значения sniffing в inbound
            # (routeOnly=False, destOverride без 'quic') — откат патча fragment.
            #  временно выключалось.  ВОЗВРАЩЕНО.
            _sniff_changed = _youtube_restore_inbounds_after_fragment(cfg)
            if new_count == old_count and len(new_outbounds) == len(outbounds) and not _sniff_changed:
                # Ничего не изменилось — пропускаем.
                continue
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(cfg_path)
            info_msg = f"Конфиг: {cfg_path} (удалены все YouTube правила"
            if _sniff_changed:
                info_msg += ", sniffing откачен"
            info_msg += ")"
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

#  Пресеты fragment для ТСПУ-обхода.
#  пресеты расширены — добавлен max_split (недокументированное, но
# поддерживаемое поле Xray fragment). Ограничивает количество фрагментов на
# один TCP-сегмент. Полезно для больших ClientHello (TLS 1.3 + ECH + ALPN).
# None — не добавлять поле (поведение по умолчанию).
# Дефолтный пресет — "medium" (баланс между обходом ТСПУ и скоростью).
_FRAGMENT_PRESETS = [
    # (key, label, packets, length, interval, max_split, description)
    ("light",  "Light",  "1",    "50-100", "1-3",   None,
     "Минимальная задержка. Только 1 сегмент, крупные фрагменты 50-100 байт. "
     "Может не обойти ТСПУ если DPI умный. Подходит для быстрого интернета."),
    ("medium", "Medium", "1",    "10-30",  "3-8",   "3-6",
     "Баланс. 1 сегмент, фрагменты 10-30 байт, задержка 3-8мс, maxSplit=3-6. "
     "Рекомендуется для большинства случаев."),
    ("heavy",  "Heavy",  "1-2",  "5-15",   "5-12",  "5-10",
     "Больше покрытия. 2 сегмента, фрагменты 5-15 байт. "
     "Лучше обход, но медленнее."),
    ("max",    "Max",    "1-3",  "3-7",    "10-20", "8-15",
     "Максимум обхода. 3 сегмента, мелкие фрагменты 3-7 байт. "
     "Самый медленный, но пробивает строгий DPI."),
]


def _fragment_preset_menu(core) -> tuple | None:
    """Подменю выбора пресета fragment для YouTube→RU+fragment.

    Возвращает (packets, length, interval, block_quic, max_split) или None если пользователь отменил.
    """
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_bottom = core._box_bottom
    _box_item   = core._box_item
    CYAN = core.CYAN
    NC   = core.NC
    DIM  = core.DIM
    GREEN = core.GREEN
    YELLOW = core.YELLOW

    print()
    _box_top("📦  Пресеты fragment (обход ТСПУ DPI)")
    _box_row()
    _box_row(f"  {DIM}TCP-фрагментация ClientHello для обхода ТСПУ SNI-фильтрации.{NC}")
    _box_row(f"  {DIM}Меньше фрагменты = лучше обход, но медленнее загрузка.{NC}")
    _box_sep()

    # Показываем пресеты
    for i, (key, label, packets, length, interval, max_split, desc) in enumerate(_FRAGMENT_PRESETS, 1):
        _box_row(f"  {GREEN}[{i}]{NC} {label}")
        _ms_str = f", maxSplit={max_split}" if max_split else ""
        _box_row(f"      {DIM}packets={packets}, length={length}, interval={interval} мс{_ms_str}{NC}")
        _box_row(f"      {DIM}{desc}{NC}")
        _box_row()

    _box_row(f"  {GREEN}[C]{NC} Custom — ввести параметры вручную")
    _box_row(f"  {DIM}  (для опытных пользователей, знающих формат Xray fragment){NC}")
    _box_row()
    _box_item("Q", f"{DIM}Отмена (использовать пресет Medium по умолчанию){NC}")
    _box_bottom()

    try:
        ch = input(f"{CYAN}  Выбор [1-4/C/Q]:{NC} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return None

    if ch in ("q", ""):
        # Дефолт — medium, без QUIC block
        result = ("1", "10-30", "3-8", "3-6")
    elif ch == "c":
        # Custom input
        print()
        print(f"{DIM}  Формат: range 'N-M' или single 'N' (без кавычек){NC}")
        print(f"{DIM}  packets:   какие TCP-сегменты фрагментировать (1 = первый ClientHello){NC}")
        print(f"{DIM}  length:    размер фрагмента в байтах (1-1000){NC}")
        print(f"{DIM}  interval:  задержка между фрагментами в мс (1-1000){NC}")
        print(f"{DIM}  max_split: макс. кол-во фрагментов на сегмент (Enter = не ограничивать){NC}")
        print()
        try:
            packets   = input(f"{CYAN}  packets [1]:{NC} ").strip() or "1"
            length    = input(f"{CYAN}  length [10-30]:{NC} ").strip() or "10-30"
            interval  = input(f"{CYAN}  interval [3-8]:{NC} ").strip() or "3-8"
            max_split = input(f"{CYAN}  max_split []:{NC} ").strip() or None
        except (EOFError, KeyboardInterrupt):
            return None
        # Базовая валидация
        if not re.match(r'^\d+(-\d+)?$', packets):
            print(f"{YELLOW}  Некорректный формат packets{NC}")
            return None
        if not re.match(r'^\d+(-\d+)?$', length):
            print(f"{YELLOW}  Некорректный формат length{NC}")
            return None
        if not re.match(r'^\d+(-\d+)?$', interval):
            print(f"{YELLOW}  Некорректный формат interval{NC}")
            return None
        if max_split and not re.match(r'^\d+(-\d+)?$', max_split):
            print(f"{YELLOW}  Некорректный формат max_split (Enter = пропустить){NC}")
            return None
        result = (packets, length, interval, max_split or None)
    else:
        # Пресет 1-4
        try:
            idx = int(ch) - 1
            if 0 <= idx < len(_FRAGMENT_PRESETS):
                _, _, packets, length, interval, max_split, _ = _FRAGMENT_PRESETS[idx]
                result = (packets, length, interval, max_split)
            else:
                return None
        except ValueError:
            return None

    #  вопрос про QUIC block (опционально, по умолчанию ВЫКЛ)
    #  с патчем sniffing (routeOnly=True + destOverride[quic])
    # QUIC block теперь действительно работает — но всё ещё может вызывать
    # browser retry delay.
    #  патч sniffing был выключен.  ВОЗВРАЩЁН.
    print()
    print(f"{DIM}  QUIC (UDP/443) — YouTube использует его для видео.{NC}")
    print(f"{DIM}  TCP fragment работает только с TCP. С  QUIC-трафик{NC}")
    print(f"{DIM}  теперь корректно маршрутизируется по SNI (routeOnly+quic),{NC}")
    print(f"{DIM}  но фрагментация на QUIC не действует. Блокировка QUIC{NC}")
    print(f"{DIM}  заставляет YouTube fallback на TCP — добавляет 1-3с задержки.{NC}")
    print(f"{DIM}  Рекомендуется ВЫКЛЮЧАТЬ на сервере с IPv6 (QUIC работает быстрее TCP).{NC}")
    print(f"{DIM}  Рекомендуется ВКЛЮЧАТЬ на сервере БЕЗ IPv6 (иначе QUIC-видео может{NC}")
    print(f"{DIM}  пытаться звонить на IPv6 и падать — 'Нет подключения').{NC}")
    print()
    try:
        quic_ans = input(f"{CYAN}  Блокировать QUIC для YouTube? [y/N]:{NC} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        quic_ans = "n"
    block_quic = quic_ans in ("y", "yes", "д", "да")

    return (result[0], result[1], result[2], block_quic, result[3])


def do_manage_youtube_via_ru() -> None:
    """TUI-меню переключателя YouTube→RU / конкретная exit-нода.

     расширено для multi-node режима — если CHAIN_NODES содержит
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
    if current_target == "warp":
        if rule_in_config:
            current_display = f"{GREEN}YouTube → WARP (Cloudflare){NC}"
            current_detail = f"{DIM}outbound:warp (sendThrough + table 301){NC}"
        else:
            current_display = f"{YELLOW}несогласованно{NC}"
            current_detail = f"{DIM}state: youtube_route_target=warp, но правило отсутствует (regenerate?).{NC}"
    elif current_target == "ru-fragment":
        if rule_in_config:
            _frag_tag = "direct-local-fragment" if core.AWG_EXIT_ENABLED else "direct-fragment"
            current_display = f"{GREEN}YouTube → RU+fragment{NC}"
            current_detail = f"{DIM}outbound:{_frag_tag} (TCP-фрагментация, обход ТСПУ){NC}"
        else:
            current_display = f"{YELLOW}несогласованно{NC}"
            current_detail = f"{DIM}state: youtube_route_target=ru-fragment, но правило отсутствует (regenerate?).{NC}"
    elif current_target == "off":
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
        #
        #  рядом с IP каждой exit-ноды показываем emoji-флаг страны
        # (🇩🇪, 🇳🇱, 🇷🇺, ...). Для пункта "балансировщик" — 🌍 в начале.
        #
        # ВАЖНО про выравнивание и границы бокса:
        #   • _box_row (через _wcslen) корректно считает emoji-флаги как
        #     2 колонки — правая граница бокса не съедет.
        #   • _name_width выравнивает только имя ноды ("Exit-нода #1"),
        #     emoji-флаг ставится ПОСЛЕ IP, не участвует в выравнивании.
        #   • 🌍 для балансировщика ставится в начале названия (до текста),
        #     это не влияет на выравнивание других строк.

        # Вычисляем ширину колонки имени ноды для выравнивания IP.
        _name_width = max(len(f"Exit-нода #{i+1}") for i in range(len(nodes)))
        _name_width = max(_name_width, len("RU entry"))

        _is_current = (current_target == "ru" and rule_in_config)
        _marker = "● " if _is_current else "  "
        # RU entry — флаг 🇷🇺 в начале (статичный, без сетевого запроса).
        _box_item("1", f"{_marker}YouTube через 🇷🇺\ufe0f {'RU entry':<{_name_width}}")

        for i, nd in enumerate(nodes):
            _tag = f"chain-exit-{i+1}"
            _is_cur = (current_target == _tag and rule_in_config)
            _marker = "● " if _is_cur else "  "
            _host = nd.get("host", "?")
            #  резолвим IP + страну через кешированный хелпер.
            # Хелпер делает _resolve_host_fresh (DoH) + curl ip-api.com (4с таймаут)
            # с кешированием по host — повторные перерисовки меню не делают
            # повторных сетевых запросов.
            _ip, _flag = _resolve_node_ip_and_flag(_host)
            # Флаг ставим после IP, через пробел. Если флаг пустой — не
            # добавляем лишний пробел (не "132.x.x.x  ", а "132.x.x.x").
            if _flag:
                _ip_str = f"  {DIM}{_ip}{NC}  {_flag}"
            else:
                _ip_str = f"  {DIM}{_ip}{NC}"
            _node_name = f"Exit-нода #{i+1}"
            _box_item(str(i+2), f"{_marker}YouTube через {_node_name:<{_name_width}}{_ip_str}")

        _default_idx = len(nodes) + 2
        _is_cur = (current_target == "off")
        _marker = "● " if _is_cur else "  "
        #  🌍 в начале — символизирует балансировщик по всем exit-нодам
        # (без привязки к конкретной стране). Emoji занимает 2 колонки,
        # _wcslen в box_renderer корректно его посчитает — правая граница
        # бокса останется ровной.
        _box_item(str(_default_idx), f"{_marker}YouTube через 🌍\ufe0f exit-ноды (default, балансировщик)")
        _box_row()
        #  RU+fragment — обход ТСПУ DPI через TCP-фрагментацию ClientHello.
        #  перенесён вниз, рядом с WARP — буквы отдельно от цифр.
        _is_current_frag = (current_target == "ru-fragment" and rule_in_config)
        _marker = "● " if _is_current_frag else "  "
        _box_item("F", f"{_marker}YouTube через 🇷🇺\ufe0f RU+fragment {DIM}(обход ТСПУ DPI){NC}")
        _is_cur_warp = (current_target == "warp")
        _marker = "● " if _is_cur_warp else "  "
        _box_item("W", f"{_marker}YouTube через ☁️ WARP (Cloudflare)")
        _box_row
        _box_item("B", "📺 b4 (DPI bypass на entry) {DIM}(fake SNI + фрагментация){NC}")
        _box_row()
        _box_item("Q", f"{DIM}Назад{NC}")
        _box_bottom()

        try:
            ch = input(f"{CYAN}  Выбор [1-{_default_idx}/F/W/Q]:{NC} ").strip().lower()
        except KeyboardInterrupt:
            print()
            return

        if ch == "q" or ch == "":
            return
        #  FIX: проверяем 'w' и 'f' ДО int(ch), иначе int('w') бросает
        # ValueError и handler ниже недостижим — кнопка [W] молча
        # возвращала пользователя в основное меню.
        if ch == "w":
            from chimera.modules.youtube_warp_route import do_youtube_warp_interactive
            _ok, _msg = do_youtube_warp_interactive(core)
            if _ok:
                _save_youtube_state("warp")
                current_target = "warp"
                rule_in_config = True
                _box_info(f"  {_msg}")
            else:
                _box_warn(f"  {_msg}")
            # Переходим к IP-pin submenu (ниже), не выходим из функции.
        elif ch == "f":
            #  YouTube → RU с TCP-фрагментацией ClientHello (обход ТСПУ DPI)
            #  подменю выбора пресета fragment
            print()
            print(f"{DIM}  RU+fragment: TCP-фрагментация ClientHello для обхода ТСПУ DPI.{NC}")
            print(f"{DIM}  Требуется Xray 26.x+ (XTLS форк с поддержкой fragment в freedom).{NC}")
            # Подменю выбора пресета
            _frag_params = _fragment_preset_menu(core)
            if _frag_params is None:
                _box_warn("  Отменено пользователем.")
            else:
                _packets, _length, _interval, _block_quic, _max_split = _frag_params
                _quic_str = "+ QUIC block" if _block_quic else "(без QUIC block)"
                _ms_str = f", maxSplit={_max_split}" if _max_split else ""
                info(f"Применяем YouTube→RU+fragment (packets={_packets}, length={_length}, interval={_interval}{_ms_str}, {_quic_str})...")
                if _youtube_apply_fragment_to_xray(_packets, _length, _interval,
                                                   block_quic=_block_quic, max_split=_max_split):
                    _save_youtube_state("ru-fragment")
                    current_target = "ru-fragment"
                    rule_in_config = True
                    _box_info(f"YouTube через RU+fragment ({_quic_str}).")
                    _box_info(f"{DIM}  packets={_packets}, length={_length}, interval={_interval}{_ms_str}{NC}")
                    _box_info(f"{DIM}   применён patch sniffing (routeOnly+quic) + sockopt (keepalive+TFO).{NC}")
                    _box_info(f"{DIM}  Требуется IPv6 connectivity на RU-сервере. Если 'Нет подключения'{NC}")
                    _box_info(f"{DIM}  — выключите QUIC block или используйте WARP routing.{NC}")
                    _box_info(f"{DIM}  Если не работает — проверьте: journalctl -u xray -n 30{NC}")
                else:
                    _box_warn("  Не удалось применить — смотрите вывод выше.")
        else:
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
                    current_target = "ru"  #  FIX: обновляем локальную переменную
                    rule_in_config = True
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
                    current_target = _tag  #  FIX: обновляем локальную переменную
                    rule_in_config = True
                    _box_info(f"YouTube теперь через Exit-ноду #{_node_idx+1} ({_host}).")
                else:
                    _box_warn(f"  Не удалось — нода {_tag} возможно удалена. Смотрите вывод выше.")
            elif _choice == _default_idx:
                # Default (балансировщик)
                info("Убираем YouTube→RU правило...")
                if _youtube_remove_from_xray():
                    _save_youtube_state("off")
                    current_target = "off"  #  FIX: обновляем локальную переменную
                    _box_info("YouTube теперь через exit-ноды (default).")
                else:
                    _box_warn("  Не удалось убрать правило — смотрите вывод выше.")
            else:
                return
    else:
        # Single-node / no-chain: старое двухпунктовое меню (обратная совместимость).
        #  добавлены emoji для консистентности с multi-node меню —
        # 🇷🇺 для RU entry, 🌍 для default (балансировщик).
        #  F (RU+fragment) перенесён вниз, рядом с WARP.
        _is_cur = (current_target == "ru" and rule_in_config)
        _box_item("1", f"{'● ' if _is_cur else '  '}YouTube через 🇷🇺\ufe0f RU entry")
        _is_cur_off = (current_target == "off")
        _box_item("2", f"{'● ' if _is_cur_off else '  '}YouTube через 🌍\ufe0f exit-ноды (default)")
        _box_row()
        _is_cur_frag = (current_target == "ru-fragment" and rule_in_config)
        _box_item("F", f"{'● ' if _is_cur_frag else '  '}YouTube через 🇷🇺\ufe0f RU+fragment {DIM}(обход ТСПУ DPI){NC}")
        _is_cur_warp = (current_target == "warp")
        _box_item("W", f"{'● ' if _is_cur_warp else '  '}YouTube через ☁\ufe0f WARP (Cloudflare)")
        _box_row()
        _box_item("Q", f"{DIM}Назад{NC}")
        _box_bottom()

        try:
            ch = input(f"{CYAN}  Выбор [1/2/F/W/B/Q]:{NC} ").strip().lower()
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
                current_target = "ru"  #  FIX: обновляем локальную переменную
                rule_in_config = True
                _box_info("YouTube теперь выходит через RU entry-ноду.")
            else:
                _box_warn("  Не удалось применить правило — смотрите вывод выше.")
        elif ch == "2":
            info("Убираем YouTube→RU правило...")
            if _youtube_remove_from_xray():
                _save_youtube_state("off")
                current_target = "off"  #  FIX: обновляем локальную переменную
                _box_info("YouTube теперь через exit-ноды (default).")
            else:
                _box_warn("  Не удалось убрать правило — смотрите вывод выше.")
        elif ch == "f":
            #  YouTube → RU с TCP-фрагментацией ClientHello (обход ТСПУ DPI)
            #  подменю выбора пресета fragment
            print()
            print(f"{DIM}  RU+fragment: TCP-фрагментация ClientHello для обхода ТСПУ DPI.{NC}")
            print(f"{DIM}  Требуется Xray 26.x+ (XTLS форк с поддержкой fragment в freedom).{NC}")
            _frag_params = _fragment_preset_menu(core)
            if _frag_params is None:
                _box_warn("  Отменено пользователем.")
            else:
                _packets, _length, _interval, _block_quic, _max_split = _frag_params
                _quic_str = "+ QUIC block" if _block_quic else "(без QUIC block)"
                _ms_str = f", maxSplit={_max_split}" if _max_split else ""
                info(f"Применяем YouTube→RU+fragment (packets={_packets}, length={_length}, interval={_interval}{_ms_str}, {_quic_str})...")
                if _youtube_apply_fragment_to_xray(_packets, _length, _interval,
                                                   block_quic=_block_quic, max_split=_max_split):
                    _save_youtube_state("ru-fragment")
                    current_target = "ru-fragment"
                    rule_in_config = True
                    _box_info(f"YouTube через RU+fragment ({_quic_str}).")
                    _box_info(f"{DIM}  packets={_packets}, length={_length}, interval={_interval}{_ms_str}{NC}")
                    _box_info(f"{DIM}   применён patch sniffing (routeOnly+quic) + sockopt (keepalive+TFO).{NC}")
                    _box_info(f"{DIM}  Требуется IPv6 connectivity на RU-сервере. Если 'Нет подключения'{NC}")
                    _box_info(f"{DIM}  — выключите QUIC block или используйте WARP routing.{NC}")
                    _box_info(f"{DIM}  Если не работает — проверьте: journalctl -u xray -n 30{NC}")
                else:
                    _box_warn("  Не удалось применить — смотрите вывод выше.")
        elif ch == "w":
            #  используем интерактивный flow с авто-установкой WARP.
            from chimera.modules.youtube_warp_route import do_youtube_warp_interactive
            _ok, _msg = do_youtube_warp_interactive(core)
            if _ok:
                _save_youtube_state("warp")
                current_target = "warp"
                rule_in_config = True
                _box_info(f"  {_msg}")
            else:
                _box_warn(f"  {_msg}")
        elif ch == "b":
            # b4 (DPI bypass для YouTube на entry VPS)
            try:
                from chimera.modules.youtube_b4 import do_youtube_b4_menu
                do_youtube_b4_menu()
            except ImportError as _e:
                _box_warn(f"  Модуль youtube_b4 не найден: {_e}")
            except Exception as _e:
                _box_warn(f"  Ошибка: {_e}")
            return
        else:
            return

    # ── IP-pin submenu (только когда current_target != "off") ─────────────
    if current_target != "off":
        _handle_ip_pin_submenu(core, current_target, rule_in_config,
                                _box_top, _box_row, _box_sep, _box_bottom,
                                _box_item, _box_info, _box_warn,
                                CYAN, NC, GREEN, YELLOW, RED, DIM, BLUE,
                                info, warn, success)

    input(f"\n{BLUE}  Нажмите Enter...{NC}")


def _handle_ip_pin_submenu(core, current_target, rule_in_config,
                            _box_top, _box_row, _box_sep, _box_bottom,
                            _box_item, _box_info, _box_warn,
                            CYAN, NC, GREEN, YELLOW, RED, DIM, BLUE,
                            info, warn, success):
    """Подменю IP-pin — показывается только когда выбрана нода (не 'off')."""
    from chimera.modules.youtube_ip_pin import (
        get_ip_pin_status, apply_youtube_ip_pin, remove_youtube_ip_pin,
        download_youtube_iplist, save_ip_pin_state,
        setup_youtube_iplist_autoupdate, remove_youtube_iplist_autoupdate,
    )

    ip_status = get_ip_pin_status()

    print()
    _box_top("📌  YouTube IP-pin (ЭКСПЕРИМЕНТАЛЬНО)")
    _box_row()
    if ip_status["enabled"] and ip_status["rule_in_config"]:
        _box_row(f"  Статус: {GREEN}включён{NC}")
    elif ip_status["enabled"] and not ip_status["rule_in_config"]:
        _box_row(f"  Статус: {YELLOW}несогласованно{NC}")
        _box_row(f"  {DIM}state: enabled, но правило отсутствует (regenerate?).{NC}")
    else:
        _box_row(f"  Статус: {DIM}выключен{NC}")
    _box_row(f"  CIDR записей: {ip_status['cidr_count']}")
    if ip_status["updated_at"]:
        _box_row(f"  Обновлён: {DIM}{ip_status['updated_at'][:19]}{NC}")
    else:
        _box_row(f"  Обновлён: {DIM}— (скачайте список){NC}")
    _box_row()
    _box_row(f"  {YELLOW}⚠ ЭКСПЕРИМЕНТ:{NC} YouTube отдаёт видео с подписанных URL")
    _box_row(f"  {DIM}конкретного cache-узла, выбирhttp://мого сервером YouTube{NC}")
    _box_row(f"  {DIM}в момент запроса manifest'а. Пиннинг по IP из внешнего{NC}")
    _box_row(f"  {DIM}списка НЕ гарантирует доступность видео — может давать{NC}")
    _box_row(f"  {DIM}403/таймауты. Это best-effort, не основной механизм.{NC}")
    _box_sep()

    _menu_items = []
    _idx = 1
    if not ip_status["enabled"]:
        _box_item(str(_idx), "Включить IP-pin (с дисклеймером)")
        _menu_items.append(("enable", _idx))
        _idx += 1
    else:
        _box_item(str(_idx), "Выключить IP-pin")
        _menu_items.append(("disable", _idx))
        _idx += 1

    _box_item(str(_idx), "Обновить IP-списки (скачать с GitHub)")
    _menu_items.append(("download", _idx))
    _idx += 1

    _box_item(str(_idx), "Включить автообновление IP-списков (cron, ежедневно)")
    _menu_items.append(("cron_on", _idx))
    _idx += 1

    _box_item(str(_idx), "Выключить автообновление")
    _menu_items.append(("cron_off", _idx))
    _idx += 1

    _box_row()
    _box_item("Q", f"{DIM}Назад{NC}")
    _box_bottom()

    try:
        ch = input(f"{CYAN}  Выбор [1-{_idx-1}/Q]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        print()
        return

    if ch == "q" or ch == "":
        return

    try:
        _choice = int(ch)
    except ValueError:
        return

    _action = None
    for act, idx in _menu_items:
        if idx == _choice:
            _action = act
            break

    if _action is None:
        return

    if _action == "enable":
        # Показываем дисклеймер перед подтверждением.
        print()
        warn("⚠ ВНИМАНИЕ: Это экспериментальная опция.")
        warn("  YouTube отдаёт видео с подписанных URL конкретного cache-узла,")
        warn("  который сервер YouTube выбирает в момент запроса manifest'а.")
        warn("  Пиннинг по IP из внешнего списка НЕ гарантирует, что видео")
        warn("  будет доступно — это best-effort, может давать 403/таймауты.")
        warn("  Не использовать как основной механизм выбора региона.")
        print()
        try:
            _confirm = input(f"{CYAN}  Продолжить? [y/N]:{NC} ").strip().lower()
        except KeyboardInterrupt:
            return
        if _confirm != "y":
            return

        # Определяем outboundTag для IP-pin.
        if current_target == "ru":
            _tag = "direct-local" if core.AWG_EXIT_ENABLED else "direct"
        else:
            _tag = current_target  # chain-exit-N

        # Если IP-списков нет — сначала скачиваем.
        if ip_status["cidr_count"] == 0:
            info("IP-списки не найдены — скачиваем...")
            if not download_youtube_iplist():
                _box_warn("  Не удалось скачать IP-списки — IP-pin не включён.")
                return

        if apply_youtube_ip_pin(_tag):
            save_ip_pin_state(True)
            _box_info("YouTube IP-pin включён (экспериментально).")
        else:
            _box_warn("  Не удалось применить IP-pin — смотрите вывод выше.")

    elif _action == "disable":
        info("Убираем IP-pin правило...")
        if remove_youtube_ip_pin():
            save_ip_pin_state(False)
            _box_info("YouTube IP-pin выключен.")
        else:
            _box_warn("  Не удалось убрать IP-pin — смотрите вывод выше.")

    elif _action == "download":
        info("Скачиваем YouTube IP-списки...")
        if download_youtube_iplist():
            _box_info("IP-списки обновлены.")
        else:
            _box_warn("  Не удалось скачать IP-списки.")

    elif _action == "cron_on":
        setup_youtube_iplist_autoupdate()
        _box_info("Автообновление IP-списков включено (ежедневно в 04:00).")

    elif _action == "cron_off":
        remove_youtube_iplist_autoupdate()
        _box_info("Автообновление IP-списков выключено.")


# =============================================================================
#  ВСПОМОГАТЕЛЬНЫЕ
# =============================================================================

def _youtube_rule_in_xray_config() -> bool:
    """Проверяет, есть ли любое YouTube правило в config.json.

    Используется TUI для отображения актуального состояния
    (state.json может рассинхронизироваться после regenerate)."""
    core = _core_module()
    CONFIG_DIR = core.CONFIG_DIR
    _youtube_comments = {_YOUTUBE_RULE_COMMENT, _YOUTUBE_FRAG_RULE_COMMENT,
                         _YOUTUBE_QUIC_BLOCK_COMMENT, "youtube_via_warp"}
    for cfg_path in (CONFIG_DIR / "config.json",
                     Path("/usr/local/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            cfg = json.loads(cfg_path.read_text())
            for rule in cfg.get("routing", {}).get("rules", []):
                if rule.get("comment") in _youtube_comments:
                    return True
        except Exception:
            continue
    return False


def _save_youtube_state(target: str) -> None:
    """Сохраняет youtube_route_target в state.json.

    Args:
      target: "ru" | "off" | "chain-exit-{N}" | "warp"

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
        # Для warp: также устанавливаем youtube_via_warp = True
        state["youtube_via_warp"] = (target == "warp")
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

     поддерживает не только RU (direct/direct-local), но и
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
    if target == "warp":
        # YouTube -> WARP (через sendThrough + kernel table 301)
        try:
            from chimera.modules.youtube_warp_route import restore_if_needed as _warp_restore
            _warp_restore(silent=silent)
        except Exception as _e:
            if not silent:
                try:
                    core.warn(f"YouTube->WARP restore не удалось: {_e}")
                except Exception:
                    pass
        return True

    if target == "ru-fragment":
        # YouTube -> RU+fragment (TCP-фрагментация для обхода ТСПУ)
        if not silent:
            try:
                core.info("Пере-применяем YouTube→RU+fragment правило "
                          "после regenerate xray-config...")
            except Exception:
                pass
        _result = _youtube_apply_fragment_to_xray()
        return _result

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
    _result = _youtube_apply_to_xray(target_tag=tag)

    # Также пере-применяем IP-pin если он включён в state.
    #  FIX: раньше это вызывало ВТОРОЙ restart Xray внутри
    # apply_youtube_ip_pin — два рестарта подряд могли приводить к race
    # condition. Теперь _youtube_apply_to_xray уже перезапустил Xray с
    # доменным правилом, а restore_ip_pin_if_needed добавит IP-pin правило
    # и перезапустит ещё раз. Это НЕ идеально (два рестарта), но альтернатива
    # — объединить оба правила в одну функцию — требует рефакторинга,
    # который рискованно делать в хотфиксе. Два последовательных рестарта
    # работают корректно (проверено на проде), проблема была не в этом,
    # а в stale current_target (БАГ 1 выше).
    try:
        from chimera.modules.youtube_ip_pin import restore_ip_pin_if_needed
        restore_ip_pin_if_needed(silent=silent)
    except Exception:
        pass  # модуль недоступен — не критично

    return _result
