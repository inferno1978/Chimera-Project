"""
chimera/modules/routing_rules.py
───────────────────────────────────────────────────────────────────────────────
Кастомные routing-правила Xray — полный контроль над routing.rules.

Правило = {
  имя, матч (домены / IP+CIDR / порты), действие (outboundTag),
  вкл/выкл, приоритет, расположение в конфиге }.

Возможности:
  • Матч: домен-паттерны (plain / domain: / full: / regexp: / geosite:),
    IP/CIDR (в т.ч. geoip:), порты/диапазоны. Несколько полей в одном
    правиле = AND (семантика Xray), значения внутри списка = OR.
  • Действие: любой outboundTag из живого конфига (chain-exit-N, direct,
    direct-local, block, ...) или произвольный тег вручную.
  • Приоритет: int, меньше = выше в списке (раньше матчится).
  • Расположение: top (в начало, выше dns_custom/ru_subnets/youtube —
    перебивает встроенные пресеты) | before_catchall (перед catch-all
    в конце — после встроенных).
  • Большие IP-списки автоматически режутся по chunk=500 на правило
    (канон ru_subnets_ripe).
  • Имппорт РФ-подсетей RIPE NCC как правила с любым outbound
    (запрос Vasily: «правила из Split Tunneling, но вместо direct —
    другой outbound»).
  • Готовые пресеты (пункт 9): двухуровневый каталог — 12 групп
    (игры / видео / соцсети / музыка / AI / медиа / РФ-банки-магазины /
    dev+наука / торренты / блокировки / звонки / диагностика), у каждого
    пресета рекомендуемый outbound (chain/direct/block — Enter в пикере
    подставляет его сразу), предпросмотр доменов категории
    (geosite_samples) и честная пометка «куцых» категорий (<10 дом.);
    сборщик «свой набор» — multi-select по группам → одно правило из
    объединения доменов; geosite-категории runetfreedom; наличие
    сверяется с живым geosite.dat (модуль geosite_codes), чтобы не
    положить Xray ссылкой на несуществующий код.
  • Re-apply после regenerate (restore_routing_rules_if_needed) —
    вызывается из _core._rebuild_and_restart_xray, ПОСЛЕДНИМ из
    «в начало»-вставляющих: кастомные правила всегда выше встроенных.

State:      /var/lib/xray-installer/routing_rules.json (0600)
Применение: патч routing.rules в /etc/xray/config.json (+ альтернативный
            /usr/local/etc/xray/config.json), comment="custom:<name>".

ОГРАНИЧЕНИЕ (честно): правила действуют на ВСЕХ клиентов сервера сразу —
Xray routing не разделяет трафик по пользователям.

Точки входа из _core.py:
    from chimera.modules.routing_rules import (
        do_manage_routing_rules, restore_routing_rules_if_needed,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from chimera.modules.tui import (tui_form, tui_select, tui_multi_select,
                                 tui_confirm, TuiField)
from chimera.modules.box_renderer import (
    _box_top, _box_bottom, _box_sep, _box_row, _box_item, _box_back,
    _box_desc, _box_kv, _box_info, _box_warn, _box_ok, _box_ask,
)
from chimera.modules.geosite_codes import geosite_codes, geosite_samples

# ── Цвета (канон dns_rules) ───────────────────────────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
            DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BLUE',
                            'BOLD', 'DIM', 'WHITE', 'NC')}

_C   = _detect_colors()
RED, GREEN, YELLOW = _C['RED'], _C['GREEN'], _C['YELLOW']
CYAN, BLUE, BOLD   = _C['CYAN'], _C['BLUE'], _C['BOLD']
DIM, WHITE, NC     = _C['DIM'], _C['WHITE'], _C['NC']

# ── Логирование (канон dns_rules: /var/log/chimera.log) ───────────────────────
_LOG_FILE = Path("/var/log/chimera.log")

def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\033\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [{level}] [routing_rules] {clean}\n")
    except Exception:
        pass

def _success(msg: str) -> None:
    print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)

def _warn(msg: str) -> None:
    print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)

def _info(msg: str) -> None:
    print(f"{CYAN}[..]{NC}    {msg}"); _log("INFO", msg)

# ── Вспомогательные ───────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def _set_config_owner(path) -> None:
    """
    FIX (04.11.2026, репорт клиента): владелец конфига = канон _core —
    640 root:xray. Раньше здесь жёстко ставили root:root: на серверах с
    User=xray (весь флот) конфиг после патча терял group-read и xray
    падал с permission denied (клиент чинил вручную chgrp xray).
    Числовой GID — не зависит от chown в PATH (канон _core).
    """
    try:
        import grp
        xray_gid = grp.getgrnam("xray").gr_gid
        os.chown(str(path), 0, xray_gid)
        os.chmod(str(path), 0o640)
    except KeyError:
        # группы xray нет — 644, чтобы xray-сервис читал как other (канон _core)
        try:
            os.chmod(str(path), 0o644)
        except Exception:
            pass
    except Exception:
        pass

# ── Константы ─────────────────────────────────────────────────────────────────
RR_STATE_FILE     = Path("/var/lib/xray-installer/routing_rules.json")
RR_COMMENT_PREFIX = "custom:"
RR_DEFAULT_CHUNK  = 500       # канон ru_subnets_ripe: ≤500 CIDR на правило
RR_PLACEMENTS     = ("top", "before_catchall")
RR_NAME_RE        = re.compile(r'^[a-z0-9][a-z0-9._-]{1,63}$')
RR_DOMAIN_PREFIXES = ("domain:", "full:", "regexp:", "geosite:")
RR_TINY_CATEGORY  = 10        # «куцая» geosite-категория: <N доменов — честная пометка
RR_SAMPLE_DOMAINS = 4         # доменов категории в предпросмотре (geosite_samples)

# ── Готовые пресеты (пункт 9): двухуровневый каталог ─────────────────────────
# Группа (RR_PRESET_GROUPS) → пресеты группы (RR_PRESETS). Поля пресета:
#   key    — имя правила (source=preset:<key>), при занятости суффиксы -2/-3;
#   group  — ключ группы верхнего уровня;
#   suggest— рекомендуемый outbound: "chain" (первый chain-exit-* — через
#            прокси), "direct", "block"; Enter в пикере подставляет сразу,
#            тега нет в живом конфиге — рекомендация тихо игнорируется.
# Категории сверены с актуальным release-geosite runetfreedom
# (russia-v2ray-rules-dat = все категории v2fly domain-list-community +
# ru-*). Наличие в ЖИВОМ dat-файле проверяется при выборе пресета
# (geosite_codes): ссылка на отсутствующий код = мёртвый Xray (exit 23,
# «code not found in geosite.dat» — прецедент youtube_route FIX и
# зеркало-инцидент legacy-v3-v5).
# domain:-дополнения YouTube: googlevideo/ggpht/youtubei живут в
# категории google, а НЕ youtube — без них видео-стрим (тяжёлый трафик
# *.googlevideo.com) уходит мимо правила, асимметричная маршрутизация
# ломает сессию (канон youtube_route._YOUTUBE_DOMAINS).
# Яндекс Музыка: geosite-категории yandex-music в dat-файле НЕТ —
# music-пресеты добирают её domain:-паттернами вручную (music.yandex.ru/
# .com), честно отражено в desc. Куцые категории (rutube 4, zoom 3,
# kick 1...) не прячем: счётчики честные, при показе — пометка «куцая».
# В подсчёт доменов агрегаты !cn входят как есть — пересечения с
# точечными категориями (vk внутри category-social-media-!cn) для
# Xray безвредны: матчинг по объединению, дубль в списке = OR.
RR_PRESET_GROUPS: tuple = (
    {"key": "games",  "title": "🎮 Игры"},
    {"key": "video",  "title": "📺 Видеосервисы"},
    {"key": "social", "title": "💬 Соцсети и мессенджеры"},
    {"key": "music",  "title": "🎵 Музыка"},
    {"key": "ai",     "title": "🤖 AI-сервисы"},
    {"key": "media",  "title": "📰 Медиа"},
    {"key": "ru",     "title": "🇷🇺 РФ: банки и магазины"},
    {"key": "dev",    "title": "🛠 Разработка и наука"},
    {"key": "p2p",    "title": "📡 Торренты и P2P"},
    {"key": "block",  "title": "🚫 Блокировки"},
    {"key": "voip",   "title": "📞 Звонки и конференции"},
    {"key": "svc",    "title": "🌐 Диагностика"},
)

RR_PRESETS: tuple = (
    # 🎮 Игры
    {"key": "games-all", "group": "games", "suggest": "chain",
     "title": "🎮 Игры — все сервисы",
     "desc": "Агрегат v2fly: Steam, Epic, Blizzard, Riot, EA, Ubisoft, Nintendo,"
             " PlayStation, Xbox, Wargaming, GOG, Roblox и др.",
     "domains": ("geosite:category-games-!cn",)},
    {"key": "games-steam", "group": "games", "suggest": "chain",
     "title": "🎮 Steam",
     "desc": "Steam, Steam Community, CDN",
     "domains": ("geosite:steam",)},
    {"key": "games-epic", "group": "games", "suggest": "chain",
     "title": "🎮 Epic Games",
     "desc": "Epic Games Store, Unreal, Fortnite-домены",
     "domains": ("geosite:epicgames",)},
    {"key": "games-blizzard", "group": "games", "suggest": "chain",
     "title": "🎮 Blizzard Battle.net",
     "desc": "Battle.net, Blizzard-сервисы",
     "domains": ("geosite:blizzard",)},
    {"key": "games-riot", "group": "games", "suggest": "chain",
     "title": "🎮 Riot Games",
     "desc": "LoL, Valorant, Riot-CDN",
     "domains": ("geosite:riot",)},
    {"key": "games-ea", "group": "games", "suggest": "chain",
     "title": "🎮 EA (+Origin)",
     "desc": "EA-сервисы и Origin",
     "domains": ("geosite:ea", "geosite:origin",)},
    {"key": "games-ubisoft", "group": "games", "suggest": "chain",
     "title": "🎮 Ubisoft",
     "desc": "Ubisoft Connect, CDN",
     "domains": ("geosite:ubisoft",)},
    {"key": "games-nintendo", "group": "games", "suggest": "chain",
     "title": "🎮 Nintendo",
     "desc": "Nintendo eShop, аккаунты",
     "domains": ("geosite:nintendo",)},
    {"key": "games-playstation", "group": "games", "suggest": "chain",
     "title": "🎮 PlayStation Network",
     "desc": "PSN, PS Store",
     "domains": ("geosite:playstation",)},
    {"key": "games-xbox", "group": "games", "suggest": "chain",
     "title": "🎮 Xbox Live",
     "desc": "Xbox-сервисы, Game Pass",
     "domains": ("geosite:xbox",)},
    {"key": "games-wargaming", "group": "games", "suggest": "chain",
     "title": "🎮 Wargaming",
     "desc": "World of Tanks и др.",
     "domains": ("geosite:wargaming",)},
    {"key": "games-gog", "group": "games", "suggest": "chain",
     "title": "🎮 GOG",
     "desc": "GOG Galaxy, магазин",
     "domains": ("geosite:gog",)},
    {"key": "games-roblox", "group": "games", "suggest": "chain",
     "title": "🎮 Roblox",
     "desc": "Roblox-домены",
     "domains": ("geosite:roblox",)},
    {"key": "games-faceit", "group": "games", "suggest": "chain",
     "title": "🎮 FACEIT",
     "desc": "FACEIT-платформа",
     "domains": ("geosite:faceit",)},
    {"key": "games-eft", "group": "games", "suggest": "chain",
     "title": "🎮 Escape from Tarkov",
     "desc": "EFT, Battlestate",
     "domains": ("geosite:escapefromtarkov",)},
    {"key": "games-downloads", "group": "games", "suggest": "direct",
     "title": "🎮 Загрузки игр (CDN платформ)",
     "desc": "Загрузки игр/обновлений Steam, PS, Xbox и др. (492 дом.):"
             " геймплей — через прокси (пинг), загрузки — direct (трафик)",
     "domains": ("geosite:category-game-platforms-download",)},
    # 📺 Видеосервисы
    {"key": "video-all", "group": "video", "suggest": "chain",
     "title": "📺 Видеосервисы — все",
     "desc": "YouTube(+CDN), Rutube, Twitch, Netflix, Prime Video, Hulu, Disney+,"
             " HBO, Kinopoisk, OKKO, Vimeo, Dailymotion, Kick",
     "domains": ("geosite:youtube", "domain:googlevideo.com",
                 "domain:ggpht.com", "domain:youtubei.googleapis.com",
                 "geosite:rutube", "geosite:twitch", "geosite:netflix",
                 "geosite:primevideo", "geosite:hulu", "geosite:disney",
                 "geosite:hbo", "geosite:kinopoisk", "geosite:okko",
                 "geosite:vimeo", "geosite:dailymotion", "geosite:kick")},
    {"key": "video-youtube", "group": "video", "suggest": "chain",
     "title": "📺 YouTube (+CDN)",
     "desc": "YouTube + CDN видео/картинок/API (googlevideo, ggpht, youtubei)",
     "domains": ("geosite:youtube", "domain:googlevideo.com",
                 "domain:ggpht.com", "domain:youtubei.googleapis.com")},
    {"key": "video-twitch", "group": "video", "suggest": "chain",
     "title": "📺 Twitch",
     "desc": "Twitch-стриминг",
     "domains": ("geosite:twitch",)},
    {"key": "video-streaming", "group": "video", "suggest": "chain",
     "title": "📺 Зарубежные стриминги",
     "desc": "Netflix, Prime Video, Hulu, Disney+, HBO",
     "domains": ("geosite:netflix", "geosite:primevideo", "geosite:hulu",
                 "geosite:disney", "geosite:hbo")},
    {"key": "video-ru", "group": "video", "suggest": "direct",
     "title": "📺 Российское видео",
     "desc": "Rutube, Kinopoisk, OKKO (+VK-видео в пресете соцсетей) —"
             " direct, не гнать RU-видео через зарубежный exit",
     "domains": ("geosite:rutube", "geosite:kinopoisk", "geosite:okko")},
    # 💬 Соцсети и мессенджеры
    {"key": "social-all", "group": "social", "suggest": "chain",
     "title": "💬 Соцсети — все",
     "desc": "Зарубежные (агрегат v2fly) + российские VK/OK явными категориями",
     "domains": ("geosite:category-social-media-!cn", "geosite:vk",
                 "geosite:ok")},
    {"key": "social-ru", "group": "social", "suggest": "direct",
     "title": "💬 Российские соцсети",
     "desc": "VK (вкл. видео-CDN userapi/vkuservideo) и OK",
     "domains": ("geosite:vk", "geosite:ok")},
    {"key": "social-foreign", "group": "social", "suggest": "chain",
     "title": "💬 Зарубежные соцсети",
     "desc": "Facebook, Instagram, Threads, Twitter/X, TikTok, Reddit, LinkedIn,"
             " Pinterest — без российских",
     "domains": ("geosite:facebook", "geosite:instagram", "geosite:threads",
                 "geosite:twitter", "geosite:x", "geosite:tiktok",
                 "geosite:reddit", "geosite:linkedin", "geosite:pinterest")},
    {"key": "msg-all", "group": "social", "suggest": "chain",
     "title": "💬 Мессенджеры",
     "desc": "Telegram, WhatsApp, Viber, Discord (по доменам; звонки Telegram"
             " по IP — при желании добавьте geoip:telegram в IP-поле вручную)",
     "domains": ("geosite:telegram", "geosite:whatsapp", "geosite:viber",
                 "geosite:discord")},
    # 🎵 Музыка
    {"key": "music-all", "group": "music", "suggest": "chain",
     "title": "🎵 Музыка — все сервисы",
     "desc": "Spotify, Apple Music, SoundCloud, Deezer, Tidal + Яндекс Музыка"
             " (её нет в geosite — добавлена domain: вручную)",
     "domains": ("geosite:spotify", "geosite:apple-music",
                 "geosite:soundcloud", "geosite:deezer", "geosite:tidal",
                 "domain:music.yandex.ru", "domain:music.yandex.com")},
    {"key": "music-spotify", "group": "music", "suggest": "chain",
     "title": "🎵 Spotify",
     "desc": "Spotify + audio-CDN (akamaized)",
     "domains": ("geosite:spotify",)},
    {"key": "music-yandex", "group": "music", "suggest": "direct",
     "title": "🎵 Яндекс Музыка",
     "desc": "Geosite-категории нет — домены добавлены вручную; direct —"
             " не гонять RU-музыку через зарубежный exit",
     "domains": ("domain:music.yandex.ru", "domain:music.yandex.com")},
    # 🤖 AI-сервисы
    {"key": "ai-all", "group": "ai", "suggest": "chain",
     "title": "🤖 AI — все сервисы",
     "desc": "ChatGPT, Claude, Gemini, Perplexity и др. (агрегат v2fly"
             " category-ai-chat-!cn) + GitHub Copilot",
     "domains": ("geosite:category-ai-chat-!cn", "geosite:github-copilot")},
    {"key": "ai-openai", "group": "ai", "suggest": "chain",
     "title": "🤖 OpenAI (ChatGPT)",
     "desc": "ChatGPT и OpenAI API",
     "domains": ("geosite:openai",)},
    {"key": "ai-anthropic", "group": "ai", "suggest": "chain",
     "title": "🤖 Anthropic (Claude)",
     "desc": "Claude (anthropic.com)",
     "domains": ("geosite:anthropic",)},
    {"key": "ai-gemini", "group": "ai", "suggest": "chain",
     "title": "🤖 Google Gemini",
     "desc": "Gemini и AI-домены Google",
     "domains": ("geosite:google-gemini",)},
    # 📰 Медиа
    {"key": "media-ru-blocked", "group": "media", "suggest": "chain",
     "title": "📰 Заблокированные в РФ медиа",
     "desc": "Независимые медиа одним правилом: BBC, Радио Свобода, VOA,"
             " Meduza, agents.media и др. (агрегат category-media-ru-blocked)",
     "domains": ("geosite:category-media-ru-blocked", "geosite:bbc",
                 "geosite:rferl", "geosite:voanews", "geosite:meduza")},
    # 🇷🇺 РФ: банки и магазины
    {"key": "ru-banks", "group": "ru", "suggest": "direct",
     "title": "🇷🇺 Российские банки",
     "desc": "Сбер, Т-Банк, Альфа, ВТБ и др. (356 дом.) — direct: банк видит"
             " домашний IP, а не зарубежный exit (антифрод/СБ)",
     "domains": ("geosite:category-bank-ru",)},
    {"key": "ru-shop", "group": "ru", "suggest": "direct",
     "title": "🇷🇺 Российские магазины",
     "desc": "Ozon, Wildberries + агрегат ecommerce-ru — direct, чтобы не"
             " гнать RU-заказы через зарубежный exit",
     "domains": ("geosite:category-ecommerce-ru", "geosite:ozon",
                 "geosite:wildberries")},
    # 🛠 Разработка и наука
    {"key": "dev-all", "group": "dev", "suggest": "chain",
     "title": "🛠 Dev — все сервисы",
     "desc": "GitHub, GitLab, Docker Hub, npm + агрегат dev-сервисов v2fly (692)",
     "domains": ("geosite:category-dev", "geosite:github", "geosite:gitlab",
                 "geosite:docker", "geosite:npmjs")},
    {"key": "dev-github", "group": "dev", "suggest": "chain",
     "title": "🛠 Хостинги кода (GitHub, GitLab)",
     "desc": "GitHub + GitLab — из РФ капризничают",
     "domains": ("geosite:github", "geosite:gitlab")},
    {"key": "dev-science", "group": "dev", "suggest": "chain",
     "title": "🛠 Наука и университеты",
     "desc": "Журналы, университеты, Google Scholar (агрегат v2fly scholar)",
     "domains": ("geosite:category-scholar-!cn",)},
    # 📡 Торренты и P2P
    {"key": "p2p-all", "group": "p2p", "suggest": "direct",
     "title": "📡 Торренты — все трекеры",
     "desc": "Публичные + приватные трекеры (RuTracker и др.): direct — не"
             " жечь трафик прокси; block — запретить P2P клиентам",
     "domains": ("geosite:category-public-tracker", "geosite:category-pt")},
    {"key": "p2p-public", "group": "p2p", "suggest": "direct",
     "title": "📡 Публичные трекеры",
     "desc": "TPB, 1337x и др. (437 дом.)",
     "domains": ("geosite:category-public-tracker",)},
    {"key": "p2p-private", "group": "p2p", "suggest": "direct",
     "title": "📡 Приватные трекеры",
     "desc": "RuTracker и др. приватные (126 дом.)",
     "domains": ("geosite:category-pt",)},
    # 🚫 Блокировки
    {"key": "block-ads", "group": "block", "suggest": "block",
     "title": "🚫 Вся реклама",
     "desc": "category-ads-all (184 тыс. дом.) — серверная блокировка рекламы"
             " всем клиентам на уровне routing; жёстко — возможны ложные",
     "domains": ("geosite:category-ads-all",)},
    {"key": "block-ads-telemetry", "group": "block", "suggest": "block",
     "title": "🚫 Реклама + телеметрия",
     "desc": "Курируемый список v2fly (мягче ads-all) — реклама и слежка",
     "domains": ("geosite:category-ads-and-telemetry",)},
    {"key": "block-telemetry", "group": "block", "suggest": "block",
     "title": "🚫 Телеметрия",
     "desc": "Телеметрия приложений/сайтов без рекламы (298 дом.)",
     "domains": ("geosite:category-telemetry",)},
    # 📞 Звонки и конференции
    {"key": "voip-all", "group": "voip", "suggest": "direct",
     "title": "📞 Конференции (Zoom, Webex)",
     "desc": "Zoom, Webex, TeamSpeak + VoIP-агрегат — direct: звонки"
             " чувствительны к задержкам прокси",
     "domains": ("geosite:zoom", "geosite:webex", "geosite:teamspeak",
                 "geosite:category-voip")},
    {"key": "voip-stun", "group": "voip", "suggest": "direct",
     "title": "📞 STUN/WebRTC",
     "desc": "STUN-серверы (359 дом.) — определение реального IP для"
             " звонков/игр; direct, иначе ломается NAT-обход",
     "domains": ("geosite:category-stun",)},
    # 🌐 Диагностика
    {"key": "svc-ip-detect", "group": "svc", "suggest": "chain",
     "title": "🌐 Сервисы «ваш IP»",
     "desc": "2ip.ru и др. (1682 дом.): через прокси — увидите IP выхода,"
             " direct — домашний IP; удобно для проверки правила",
     "domains": ("geosite:category-ip-geo-detect",)},
    {"key": "svc-speedtest", "group": "svc", "suggest": "chain",
     "title": "🌐 Speedtest",
     "desc": "Speedtest и аналоги (329 дом.) — через прокси: замер"
             " прокси-канала, а не домашнего",
     "domains": ("geosite:category-speedtest",)},
)

_CONFIG_DIR      = Path("/etc/xray")
_ALT_CONFIG      = Path("/usr/local/etc/xray/config.json")


# ══════════════════════════════════════════════════════════════════════════════
#  STATE I/O
# ══════════════════════════════════════════════════════════════════════════════

def _rr_load() -> dict:
    try:
        if RR_STATE_FILE.exists():
            data = json.loads(RR_STATE_FILE.read_text())
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {"version": 1, "rules": []}


def _rr_save(data: dict) -> None:
    RR_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    data.setdefault("version", 1)
    RR_STATE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    RR_STATE_FILE.chmod(0o600)


def _rr_now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _rr_enabled_rules(state: "dict | None" = None) -> list:
    """Включённые правила, отсортированные по (priority, name) —
    меньше priority = выше в конфиге = раньше матчится."""
    if state is None:
        state = _rr_load()
    rules = [r for r in state.get("rules", [])
             if isinstance(r, dict) and r.get("enabled", True)]
    return sorted(rules, key=lambda r: (r.get("priority", 100), r.get("name", "")))


# ══════════════════════════════════════════════════════════════════════════════
#  ВАЛИДАТОРЫ (для TuiField)
# ══════════════════════════════════════════════════════════════════════════════

def _rr_validate_name(text: str) -> "str | None":
    t = text.strip().lower()
    if not t:
        return "Введите имя правила"
    if not RR_NAME_RE.match(t):
        return "Имя: 2-64 символа, a-z0-9._-, начинается с буквы/цифры"
    return None


def _rr_validate_domain_item(item: str) -> "str | None":
    """Один домен-паттерн: plain / domain: / full: / regexp: / geosite:"""
    p = item.strip()
    if not p:
        return None
    low = p.lower()
    if low.startswith("geosite:"):
        # geosite-имена не содержат точку: category-ads-all, ru, youtube.
        # '!' — суффиксы v2fly-агрегатов (category-games-!cn,
        # category-social-media-!cn): Xray верхнерегистрит искомый код
        # и находит тег в geosite.dat как есть.
        rest = p.split(":", 1)[1]
        if not rest or not re.match(r'^[a-z0-9_!-]+$', rest, re.I):
            return f"После geosite: нет имени: '{p}'"
        return None
    if low.startswith(("domain:", "full:")):
        rest = p.split(":", 1)[1]
        if not rest or "." not in rest:
            return f"После префикса нет домена (с точкой): '{p}'"
        return None
    if low.startswith("regexp:"):
        rest = p.split(":", 1)[1]
        if not rest:
            return f"После regexp: нет выражения: '{p}'"
        return None
    if " " in p:
        return f"Пробелы не допускаются: '{p}'"
    if "." not in p:
        return f"'{p}' — нужен домен с точкой или префикс domain:/full:/regexp:/geosite:"
    if not re.match(r'^[a-z0-9*._-]+$', low, re.I):
        return f"Недопустимые символы в домене: '{p}'"
    return None


def _rr_validate_ip_item(item: str) -> "str | None":
    """Один элемент ip-списка: IP / CIDR / geoip:xxx."""
    p = item.strip()
    if not p:
        return None
    low = p.lower()
    if low.startswith("geoip:"):
        rest = p.split(":", 1)[1]
        if not rest or not re.match(r'^[a-z0-9_-]+$', rest, re.I):
            return f"После geoip: нет имени: '{p}'"
        return None
    try:
        ipaddress.ip_network(p, strict=False)
        return None
    except ValueError:
        return f"'{p}' — не IP/CIDR (напр. 1.2.3.0/24) и не geoip:ru"


def _rr_validate_port_item(item: str) -> "str | None":
    """Один порт или диапазон: 443 / 1000-2000."""
    p = item.strip()
    if not p:
        return None
    m = re.match(r'^(\d+)-(\d+)$', p)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        if not (1 <= a < b <= 65535):
            return f"Диапазон неверен: '{p}' (нужно 1 ≤ a < b ≤ 65535)"
        return None
    if p.isdigit():
        if not (1 <= int(p) <= 65535):
            return f"Порт вне диапазона: '{p}'"
        return None
    return f"'{p}' — не порт и не диапазон (напр. 443 или 1000-2000)"


def _rr_make_list_validator(item_validator):
    """Обёртка: список через запятую; пустая строка допустима (поле опц.)."""
    def _validate(text: str) -> "str | None":
        if not text.strip():
            return None
        for part in text.split(","):
            p = part.strip()
            if not p:
                continue
            err = item_validator(p)
            if err:
                return err
        return None
    return _validate

_rr_validate_domains = _rr_make_list_validator(_rr_validate_domain_item)
_rr_validate_ips     = _rr_make_list_validator(_rr_validate_ip_item)
_rr_validate_ports   = _rr_make_list_validator(_rr_validate_port_item)


def _rr_validate_priority(text: str) -> "str | None":
    t = text.strip()
    if not t:
        return "Введите приоритет (целое, 0-9999; меньше = выше)"
    if not t.isdigit() or not (0 <= int(t) <= 9999):
        return "Приоритет: целое 0-9999"
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  КОНФИГ XRAY
# ══════════════════════════════════════════════════════════════════════════════

def _rr_iter_configs() -> list:
    """Все живые конфиги Xray (path, cfg), dedup по realpath.
    Канон ru_subnets: патчим и /etc/xray/config.json, и альтернативный."""
    out, seen = [], set()
    for p in (_CONFIG_DIR / "config.json", _ALT_CONFIG):
        if not p.exists():
            continue
        try:
            real = str(p.resolve())
        except Exception:
            real = str(p)
        if real in seen:
            continue
        seen.add(real)
        try:
            out.append((p, json.loads(p.read_text())))
        except Exception:
            _warn(f"Не читается конфиг: {p}")
    return out


def _rr_live_outbounds() -> "tuple[list, dict]":
    """Теги outbounds из живого конфига (первый найденный)."""
    configs = _rr_iter_configs()
    if not configs:
        return [], {}
    _, cfg = configs[0]
    tags = []
    for ob in cfg.get("outbounds", []):
        t = ob.get("tag", "")
        if t:
            tags.append(t)
    return tags, cfg


# ── Пикер outbound (общий для импорта РФ-подсетей и правил) ──────────────────
# Запрос клиента (04.11, скриншот меню «Куда направить трафик РФ-подсетей?»):
# «в режиме А можно как-то добавить outbound?» — служебные теги скрываем,
# кастомные помечаем 🔗, даём создать новый на ходу (custom_outbounds).

_RR_SERVICE_TAGS = {"xray-stats-api", "api", "dns-out", "antiblock"}


def _rr_picker_options(tags: list, cfg: dict) -> "tuple[list, list]":
    """(labels, tags) для пикера: служебные (api/stats) скрыты, кастомные
    (из custom_outbounds state) помечены 🔗."""
    protos = {o.get("tag", ""): o.get("protocol", "")
              for o in cfg.get("outbounds", [])}
    custom = set()
    try:
        from chimera.modules.custom_outbounds import co_state_tags
        custom = co_state_tags()
    except Exception:
        custom = set()
    labels, pick = [], []
    for t in tags:
        if t in _RR_SERVICE_TAGS or protos.get(t) in ("api", "dns"):
            continue                      # служебные — не для трафика
        p = protos.get(t, "")
        if t in custom:
            d = f"🔗 custom · {p or 'outbound'}"
        elif p == "freedom" or t in ("direct", "direct-local"):
            d = "freedom (напрямую)"
        elif p == "blackhole" or t in ("block", "BLOCK"):
            d = "blackhole (блок)"
        elif t.startswith("chain-exit"):
            d = "внешняя нода (каскад)"
        else:
            d = p or "outbound"
        labels.append(f"{t}  ({d})")
        pick.append(t)
    return labels, pick


def _rr_suggest_outbound(suggest: "str | None", pick: list) -> "int | None":
    """Индекс рекомендуемого outbound в списке пикера.

    suggest: "chain" — первый chain-exit-* (прокси-каскад); "direct" /
    "block" — точный тег. Не задан или нет в живом конфиге → None
    (предвыбора нет, обычный порядок пикера).
    """
    if not suggest or not pick:
        return None
    if suggest == "chain":
        for i, t in enumerate(pick):
            if t.startswith("chain-exit"):
                return i
        return None
    if suggest in ("direct", "block"):
        try:
            return pick.index(suggest)
        except ValueError:
            return None
    return None


def _rr_pick_outbound(cur_out: "str | None" = None,
                      title: str = "Outbound (куда направить трафик)",
                      suggest: "str | None" = None,
                      ) -> "str | None":
    """Выбор outbound: живые теги + создать новый (custom_outbounds) +
    тег вручную. Возвращает тег или None (отмена).

    suggest (пресеты): предвыбор рекомендуемого тега + пометка в
    заголовке («рекомендуется: ...»); cur_out задан (редактирование
    правила) — предвыбор текущего тега, рекомендация игнорируется.
    """
    tags, cfg = _rr_live_outbounds()
    if not tags:
        manual = tui_form("Outbound (нет живого конфига)", [
            TuiField(key="tag", label="Тег", default=cur_out or "",
                     required=True),
        ])
        if manual is None:
            return None
        return manual["tag"].strip()
    labels, pick = _rr_picker_options(tags, cfg)
    options = labels + ["— Создать новый outbound —  🔗",
                        "— Ввести тег вручную —"]
    pre = pick.index(cur_out) if cur_out in pick else 0
    sug = _rr_suggest_outbound(suggest, pick)
    if sug is not None and not cur_out:
        pre = sug
        what = {"chain": "через прокси (каскад)",
                "direct": "direct (напрямую)",
                "block": "block (заблокировать)"}.get(suggest, suggest)
        title = f"{title}  — рекомендуется: {what}"
    idx = tui_select(title, options, default=pre)
    if idx is None:
        return None
    if idx == len(options) - 2:
        # Создать новый на ходу: мастер custom_outbounds вернёт тег
        try:
            from chimera.modules.custom_outbounds import co_create_outbound_inline
        except ImportError as e:
            _warn(f"Модуль custom_outbounds недоступен: {e}")
            return None
        return co_create_outbound_inline()   # None = отмена
    if idx == len(options) - 1:
        manual = tui_form("Outbound вручную", [
            TuiField(key="tag", label="Тег", default=cur_out or "chain-exit-1",
                     required=True, hint="Напр. chain-exit-4"),
        ])
        if manual is None:
            return None
        return manual["tag"].strip()
    return pick[idx]


def _rr_awg_exit_enabled() -> bool:
    try:
        import importlib
        core = importlib.import_module("chimera._core")
        return bool(getattr(core, "AWG_EXIT_ENABLED", False))
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
#  СБОРКА XRAY-ПРАВИЛ ИЗ STATE
# ══════════════════════════════════════════════════════════════════════════════

def _rr_split_ips(ips: list, chunk: int) -> list:
    """Режет ip-список на чанки (канон ru_subnets: ≤500 на правило)."""
    chunk = max(1, int(chunk or RR_DEFAULT_CHUNK))
    return [ips[i:i + chunk] for i in range(0, len(ips), chunk)] or [[]]


def _rr_build_xray_rules(rule: dict) -> "tuple[list, str]":
    """State-правило → список Xray routing rules (comment=custom:<name>).

    Возвращает ([xr_rule, ...], "") или ([], "причина отказа").
    Несколько полей в одном правиле = AND; значения в списке = OR.
    ips > chunk требует пустых domains/ports (иначе AND-семантика
    размножится на каждый чанк — молча изменив смысл правила).
    """
    name     = rule.get("name", "?")
    domains  = [d for d in rule.get("domains", []) or [] if d]
    ips      = [i for i in rule.get("ips", []) or [] if i]
    ports    = [p for p in rule.get("ports", []) or [] if p]
    outbound = rule.get("outbound", "direct")
    chunk    = int(rule.get("chunk", RR_DEFAULT_CHUNK) or RR_DEFAULT_CHUNK)
    chunk    = max(1, chunk)

    if not domains and not ips and not ports:
        return [], f"правило '{name}': нет ни одного матча"

    ip_chunks = _rr_split_ips(ips, chunk)
    multi_chunk = len(ip_chunks) > 1
    if multi_chunk and (domains or ports):
        return [], (f"правило '{name}': {len(ips)} IP разбивается на "
                    f"{len(ip_chunks)} правил по {chunk} — домены/порты при "
                    f"разбивке не поддерживаются (AND внутри правила). "
                    f"Вынесите домены/порты в отдельное правило.")

    base = {"type": "field", "outboundTag": outbound,
            "comment": f"{RR_COMMENT_PREFIX}{name}"}
    out = []
    if multi_chunk:
        for ch in ip_chunks:
            r = dict(base)
            r["ip"] = ch
            out.append(r)
        return out, ""

    r = dict(base)
    if domains:
        r["domain"] = list(domains)
    if ips:
        r["ip"] = list(ips)
    if ports:
        r["port"] = list(ports)
    out.append(r)
    return out, ""


# ══════════════════════════════════════════════════════════════════════════════
#  ПРИМЕНЕНИЕ К КОНФИГУ
# ══════════════════════════════════════════════════════════════════════════════

def _rr_is_catchall(rule: dict) -> bool:
    """Catch-all: network без доменов/IP/портов/протоколов (канон ru_subnets)."""
    if rule.get("network") not in ("tcp,udp", "tcp", "udp"):
        return False
    return not (rule.get("ip") or rule.get("domain")
                or rule.get("protocol") or rule.get("port"))


def _rr_custom_names_in_config() -> set:
    """Имена (после custom:) во всех живых конфигах."""
    names = set()
    for _path, cfg in _rr_iter_configs():
        for r in cfg.get("routing", {}).get("rules", []):
            c = r.get("comment", "")
            if c.startswith(RR_COMMENT_PREFIX):
                names.add(c[len(RR_COMMENT_PREFIX):])
    return names


def _rr_apply_to_xray(restart: bool = False, validate: bool = False,
                      silent: bool = False) -> bool:
    """Пере-применяет ВСЕ включённые правила из state в живые конфиги.

    Атомарно: сначала удаляет из routing.rules все custom:*, потом
    вставляет новые (top → в начало, before_catchall → перед catch-all).
    Если validate=True — после записи гоняет `xray run -test`; при ошибке
    откатывает конфиги к исходному тексту и возвращает False.
    restart=True — безопасный рестарт Xray (reset-failed, канон dns_rules).
    """
    configs = _rr_iter_configs()
    if not configs:
        if not silent:
            _warn("Xray конфиг не найден")
        return False

    state   = _rr_load()
    enabled = _rr_enabled_rules(state)

    # Сборка + валидация (до записи в конфиги).
    built, skipped = [], 0
    for rule in enabled:
        xr_list, err = _rr_build_xray_rules(rule)
        if err:
            if not silent:
                _warn(f"Пропуск: {err}")
            skipped += 1
            continue
        built.append((rule, xr_list))

    top_rules = []
    bc_rules  = []
    for rule, xr_list in built:
        if rule.get("placement", "top") == "before_catchall":
            bc_rules.extend(xr_list)
        else:
            top_rules.extend(xr_list)

    # Снапшоты для отката при невалидном конфиге.
    snapshots = {str(p): p.read_text() for p, _ in configs}

    for path, cfg in configs:
        try:
            routing = cfg.setdefault("routing", {})
            rules = [r for r in routing.setdefault("rules", [])
                     if not str(r.get("comment", "")).startswith(RR_COMMENT_PREFIX)]
            if bc_rules:
                idx = len(rules)
                for i, r in enumerate(rules):
                    if _rr_is_catchall(r):
                        idx = i
                        break
                rules = rules[:idx] + bc_rules + rules[idx:]
            if top_rules:
                rules = top_rules + rules
            routing["rules"] = rules
            path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(path)
        except Exception as e:
            if not silent:
                _warn(f"Ошибка патча {path}: {e}")
            return False

    # Валидация конфига живым бинарником + откат при ошибке.
    if validate:
        xray_bin = "/usr/local/bin/xray"
        for path, _ in configs:
            val = _run([xray_bin, "run", "-test", "-config", str(path)],
                       capture=True, check=False, quiet=True)
            if val.returncode != 0:
                for p2, _ in configs:
                    try:
                        p2.write_text(snapshots[str(p2)])
                        _set_config_owner(p2)
                    except Exception:
                        pass
                tail = (val.stdout + val.stderr)[-400:]
                if not silent:
                    _warn(f"Xray отклонил конфиг — откат. {tail}")
                _log("ERROR", f"apply: xray run -test failed: {tail}")
                return False

    if restart:
        _rr_reload_xray(silent=silent)

    if not silent and enabled:
        n_xray = len(top_rules) + len(bc_rules)
        _info(f"Применено правил Xray: {n_xray} из {len(enabled)} state-правил"
              + (f" (пропущено {skipped})" if skipped else ""))
    return True


def _rr_reload_xray(silent: bool = False) -> bool:
    """Безопасный рестарт (start-limit-fix, канон dns_rules/_dns_reload_xray)."""
    _run(["systemctl", "reset-failed", "xray"], check=False, quiet=True)
    _run(["systemctl", "restart", "xray"], check=False, quiet=True)
    ok = None
    for _ in range(15):
        time.sleep(1)
        ok = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
        if ok.stdout.strip() == "active":
            break
    if ok is not None and ok.stdout.strip() == "active":
        if not silent:
            _success("Xray перезапущен с новыми routing-правилами")
        return True
    _run(["systemctl", "reset-failed", "xray"], check=False, quiet=True)
    _run(["systemctl", "restart", "xray"], check=False, quiet=True)
    time.sleep(2)
    ok = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
    if ok.stdout.strip() == "active":
        if not silent:
            _success("Xray перезапущен с новыми routing-правилами")
        return True
    if not silent:
        _warn("Xray не запустился — проверьте конфиг! journalctl -u xray -n 30")
    return False


# ══════════════════════════════════════════════════════════════════════════════
#  RESTORE (после regenerate — канон restore_youtube_rule_if_needed)
# ══════════════════════════════════════════════════════════════════════════════

def restore_routing_rules_if_needed(silent: bool = False) -> bool:
    """Пере-применяет кастомные routing-правила, если state говорит что
    они должны быть включены, но в config.json их нет (generate_*
    перезаписывает routing целиком — без restore правила молча терялись
    при каждой пересборке: смена домена/порта, regenerate 5b и т.д.).

    Отличие от youtube-канона: правил много, поэтому «уже применено» =
    ВСЕ включённые имена присутствуют в конфиге; при частичной потере —
    полный re-apply (идемпотентно: сначала удаляются все custom:*,
    потом вставляются все включённые).

    Вызывается из _core._rebuild_and_restart_xray ПОСЛЕДНИМ из
    «в начало»-вставляющих restore — итоговый порядок в конфиге:
    [custom:*] → [dns_custom:*] → [youtube] → [ru_subnets_ripe] → ...

    Перезапуск Xray делает вызывающий код. Возвращает True если
    правила были пере-применены.
    """
    state = _rr_load()
    enabled = _rr_enabled_rules(state)
    if not enabled:
        return False

    have = _rr_custom_names_in_config()
    need = {r["name"] for r in enabled}
    if need <= have:
        return False  # всё уже на месте

    missing = need - have
    if not silent:
        _info(f"Восстанавливаем кастомные routing-правила после "
              f"regenerate (потеряно: {len(missing)} из {len(need)})...")
    ok = _rr_apply_to_xray(restart=False, validate=False, silent=silent)
    if ok and not silent:
        _success(f"Кастомные routing-правила восстановлены "
                 f"({len(enabled)} правил из state)")
    return ok


# ══════════════════════════════════════════════════════════════════════════════
#  ИМПОРТ РФ-ПОДСЕТЕЙ (RIPE NCC) — запрос Vasily:
#  «правила из Split Tunneling, но вместо direct — другой outbound»
# ══════════════════════════════════════════════════════════════════════════════

_RU_SUBNETS_SOURCE = "ru_subnets_import"


def _rr_import_ru_subnets() -> "dict | None":
    """Интерактивный импорт РФ-подсетей как кастомного правила.

    Читает /etc/xray/ru_subnets_ripe.txt (split tunneling); при отсутствии
    предлагает скачать свежий delegated-ripencc-latest. Создаёт правило
    { ips: все CIDR, chunk: 500, placement: top } с выбранным outbound —
    вставляется ВЫШЕ ru_subnets_ripe, т.е. перебивает direct из Split
    Tunneling. Возвращает созданное правило-словарь или None.
    """
    print()
    _box_top("Импорт РФ подсетей (RIPE NCC) → кастомный outbound")
    _box_row()
    _box_desc("Правила Split Tunneling (ru_subnets_ripe) направляют РФ-подсети")
    _box_desc("в direct. Это правило делает то же самое, но в выбранный outbound")
    _box_desc("(напр. chain-exit-N) — вставляется ВЫШЕ ru_subnets_ripe и BLOCK,")
    _box_desc("поэтому перебивает direct. Домены/порты не задаются.")
    _box_row()
    _box_bottom()

    # 1. Список CIDR
    cidrs = []
    try:
        from chimera.modules.ru_subnets import _ru_subnets_load_from_file
        cidrs = _ru_subnets_load_from_file()
    except Exception:
        try:
            f = Path("/etc/xray/ru_subnets_ripe.txt")
            if f.exists():
                cidrs = [l.strip() for l in f.read_text().splitlines()
                         if l.strip() and not l.startswith("#")]
        except Exception:
            cidrs = []

    if not cidrs:
        ans = _box_ask("Файл РФ-подсетей пуст/нет. Скачать из RIPE NCC сейчас? [y/N]")
        if ans.strip().lower() != "y":
            _warn("Импорт отменён: нет списка подсетей.")
            return None
        try:
            from chimera.modules import ru_subnets as rs
            fetched = rs._fetch_ru_subnets_from_ripe()
            if not fetched:
                _warn("RIPE NCC недоступен — импорт отменён.")
                return None
            rs._ru_subnets_save(fetched)
            cidrs = fetched
        except Exception as e:
            _warn(f"Не удалось скачать: {e}")
            return None

    _info(f"Подсетей РФ: {len(cidrs)} (→ {(len(cidrs) + 499) // 500} правил Xray по 500)")

    # 2. Outbound
    outbound = _rr_pick_outbound(title="Куда направить трафик РФ-подсетей?")
    if not outbound:
        return None

    # 3. Имя правила
    default_name = f"ru-subnets-via-{outbound}".lower()[:64]
    existing = {r.get("name") for r in _rr_load().get("rules", [])}
    if default_name in existing:
        default_name = f"{default_name}-{len(existing) + 1}"
    res = tui_form("Имя правила", [
        TuiField(key="name", label="Имя", default=default_name,
                 required=True, validator=_rr_validate_name,
                 hint="Идентификатор в comment=custom:<имя>"),
        TuiField(key="priority", label="Приоритет", default="10",
                 required=True, validator=_rr_validate_priority,
                 hint="Меньше = выше в конфиге"),
    ])
    if not res:
        return None
    name = res["name"].strip().lower()

    rule = {
        "name": name,
        "enabled": True,
        "domains": [],
        "ips": sorted(cidrs),
        "ports": [],
        "outbound": outbound,
        "priority": int(res["priority"]),
        "placement": "top",
        "chunk": RR_DEFAULT_CHUNK,
        "source": _RU_SUBNETS_SOURCE,
        "created_at": _rr_now(),
        "updated_at": _rr_now(),
    }

    # Сводка + подтверждение
    print()
    _box_top(f"Правило: {name}")
    _box_kv("Матч", f"РФ подсети RIPE ({len(cidrs)} CIDR)")
    _box_kv("Outbound", outbound)
    _box_kv("Приоритет", str(rule["priority"]))
    _box_kv("Расположение", "top (выше ru_subnets_ripe)")
    _box_kv("Правил Xray", f"{(len(cidrs) + 499) // 500} (по 500 CIDR)")
    _box_row()
    _box_warn("  Правило действует на всех клиентов сервера сразу (routing Xray")
    _box_warn("  не разделяет трафик по пользователям).")
    _box_bottom()
    if not tui_confirm("Создать правило и применить?", default=False):
        return None

    state = _rr_load()
    state.setdefault("rules", []).append(rule)
    _rr_save(state)
    _log_change(f"rule_add:{name}", f"РФ подсети ({len(cidrs)}) → {outbound}")
    _rr_apply_to_xray(restart=True, validate=True)
    return rule


def _log_change(key: str, detail: str) -> None:
    """Пишет в /var/lib/xray-installer/changes.json (канон _core._log_change)."""
    try:
        ch_file = Path("/var/lib/xray-installer/changes.json")
        entries = []
        if ch_file.exists():
            try:
                entries = json.loads(ch_file.read_text())
                if not isinstance(entries, list):
                    entries = []
            except Exception:
                entries = []
        entries.append({"ts": _rr_now(), "key": key, "detail": detail})
        ch_file.parent.mkdir(parents=True, exist_ok=True)
        ch_file.write_text(json.dumps(entries, indent=2, ensure_ascii=False))
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  ОТОБРАЖЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════

def _rr_match_summary(rule: dict, max_len: int = 34) -> str:
    """Компактная строка матча для списка: 'd:2 ip:500 p:1'."""
    d = len(rule.get("domains") or [])
    i = len(rule.get("ips") or [])
    p = len(rule.get("ports") or [])
    parts = []
    if d:
        parts.append(f"d:{d}")
    if i:
        tag = "geoip" if any(str(x).startswith("geoip:") for x in rule["ips"]) else "cidr"
        parts.append(f"{tag}:{i}")
    if p:
        parts.append(f"p:{p}")
    return " ".join(parts) if parts else "—"


def _rr_show_live_rules() -> None:
    os.system("clear")
    print()
    _box_top("Живые кастомные правила в конфиге (custom:*)")
    configs = _rr_iter_configs()
    if not configs:
        _box_row(f"  {DIM}Конфиг не найден{NC}")
        _box_bottom()
        return
    for path, cfg in configs:
        _box_row(f"  {BOLD}{path}{NC}")
        rules = [r for r in cfg.get("routing", {}).get("rules", [])
                 if str(r.get("comment", "")).startswith(RR_COMMENT_PREFIX)]
        if not rules:
            _box_row(f"    {DIM}— нет custom:* правил —{NC}")
            continue
        for pos, r in enumerate(rules, 1):
            name = str(r.get("comment", ""))[len(RR_COMMENT_PREFIX):]
            ob   = r.get("outboundTag", "?")
            nd   = len(r.get("domain") or [])
            ni   = len(r.get("ip") or [])
            np_  = len(r.get("port") or [])
            mat = " ".join(x for x in (f"d:{nd}" if nd else "",
                                       f"ip:{ni}" if ni else "",
                                       f"p:{np_}" if np_ else "") if x) or "—"
            col = GREEN if r.get("enabled", True) is not False else DIM
            _box_row(f"    #{pos:<3} {CYAN}{name:<32}{NC} → {GREEN}{ob}{NC}  {DIM}{mat}{NC}")
        _box_sep()
    _box_row(f"  {DIM}dns_custom:* / ru_subnets_ripe / youtube — встроенные, тут не показаны{NC}")
    _box_bottom()
    input(f"{BLUE}Нажмите Enter...{NC}")


# ══════════════════════════════════════════════════════════════════════════════
#  ГОТОВЫЕ ПРЕСЕТЫ (пункт 9) — двухуровневый каталог + свой набор
# ══════════════════════════════════════════════════════════════════════════════

def _rr_preset_geocodes(preset: dict) -> list:
    """geosite-коды пресета (без префикса, нижний регистр)."""
    out = []
    for d in preset.get("domains", []) or []:
        low = str(d).lower()
        if low.startswith("geosite:"):
            out.append(low.split(":", 1)[1])
    return out


def _rr_preset_missing(preset: dict, codes: "dict | None") -> "list | None":
    """Коды, которых нет в geosite.dat. None = проверка невозможна
    (dat не распарсился) — не блокируем: финальный гвард xray run -test
    с откатом живёт в _rr_apply_to_xray(validate=True)."""
    if codes is None:
        return None
    return [c for c in _rr_preset_geocodes(preset) if c not in codes]


def _rr_preset_total(preset: dict, codes: "dict | None") -> "int | None":
    """Оценка числа доменов пресета (подпись в списке). None — не знаем."""
    if codes is None:
        return None
    total = 0
    for d in preset.get("domains", []) or []:
        low = str(d).lower()
        if low.startswith("geosite:"):
            total += codes.get(low.split(":", 1)[1], 0)
        else:
            total += 1          # domain:/full: дополнение — 1 паттерн
    return total


def _rr_preset_tiny(preset: dict, codes: "dict | None") -> list:
    """Куцые geosite-категории пресета (< RR_TINY_CATEGORY доменов):
    [(код, N), ...] — честная пометка «покрытие может быть неполным»."""
    if codes is None:
        return []
    out = []
    for c in _rr_preset_geocodes(preset):
        n = codes.get(c)
        if n is not None and n < RR_TINY_CATEGORY:
            out.append((c, n))
    return out


def _rr_unique_preset_name(key: str) -> str:
    """Свободное имя правила для пресета (key, key-2, key-3...)."""
    existing = {r.get("name") for r in _rr_load().get("rules", [])}
    if key not in existing:
        return key
    i = 2
    while f"{key}-{i}" in existing:
        i += 1
    return f"{key}-{i}"


def _rr_plural(n: int, forms: tuple) -> str:
    """1 пресет / 2 пресета / 5 пресетов — русская плюрализация."""
    n100, n10 = n % 100, n % 10
    if 11 <= n100 <= 14:
        return forms[2]
    if n10 == 1:
        return forms[0]
    if 2 <= n10 <= 4:
        return forms[1]
    return forms[2]


def _rr_presets_in_group(group_key: str) -> list:
    """Пресеты группы в порядке каталога."""
    return [p for p in RR_PRESETS if p.get("group") == group_key]


def _rr_preset_label(preset: dict, codes: "dict | None") -> str:
    """Строка списка: «🎮 Steam  (61 дом.)» (+ «⚠ нет в geosite.dat»)."""
    label = preset["title"]
    total = _rr_preset_total(preset, codes)
    if total is not None:
        label += f"  ({total} дом.)"
    if _rr_preset_missing(preset, codes):
        label += "  ⚠ нет в geosite.dat"
    return label


def _rr_menu_presets() -> None:
    """Меню готовых пресетов (двухуровневое): группа → пресет →
    outbound (с рекомендацией) → правило → apply. Плюс сборщик
    «свой набор» — multi-select по группам → одно правило.

    Пресет = обычное state-правило (source=preset:<key>): после создания
    редактируется/включается/удаляется как любое другое (пункты 2/3/4).
    """
    print()
    _info("Читаю категории geosite.dat (первый раз ~2 с, дальше кэш)...")
    codes = geosite_codes()
    if codes is None:
        _warn("geosite.dat не найден/не распарсился — наличие категорий проверить "
              "не смогу; правило прогонит xray run -test при применении")
    else:
        _info(f"geosite.dat: {len(codes)} категорий — пресеты сверены с живым файлом")

    while True:
        groups = [g for g in RR_PRESET_GROUPS if _rr_presets_in_group(g["key"])]
        g_options = []
        for g in groups:
            presets = _rr_presets_in_group(g["key"])
            miss = sum(1 for p in presets if _rr_preset_missing(p, codes))
            label = (f"{g['title']}  ({len(presets)} "
                     f"{_rr_plural(len(presets), ('пресет', 'пресета', 'пресетов'))})")
            if miss:
                label += f"  ⚠ {miss} с пропусками"
            g_options.append(label)
        g_options.append("🔧 Свой набор — отметить несколько категорий")
        g_options.append("— Отмена —")

        gidx = tui_select("Готовые пресеты — выберите группу", g_options)
        if gidx is None or gidx == len(g_options) - 1:
            return
        if gidx == len(g_options) - 2:
            _rr_menu_mix(codes)
            continue
        _rr_menu_group_presets(groups[gidx], codes)


def _rr_menu_group_presets(group: dict, codes: "dict | None") -> None:
    """Второй уровень каталога: пресеты внутри группы."""
    presets = _rr_presets_in_group(group["key"])
    while True:
        options = [_rr_preset_label(p, codes) for p in presets]
        options.append("— Назад —")
        idx = tui_select(f"{group['title']} — выберите пресет", options)
        if idx is None or idx == len(options) - 1:
            return
        _rr_apply_preset_flow(presets[idx], codes)


def _rr_apply_preset_flow(preset: dict, codes: "dict | None") -> None:
    """Карточка пресета (счётчики + предпросмотр доменов + куцые) →
    outbound с рекомендацией → правило → apply."""
    # Наличие категорий: ссылка на отсутствующий код = мёртвый Xray.
    missing = _rr_preset_missing(preset, codes)
    if missing:
        print()
        _box_top(f"Пресет: {preset['title']}")
        _box_row()
        _box_warn(f"  В geosite.dat НЕТ категорий: {', '.join(missing)}")
        _box_row()
        _box_desc("Правило с geosite-кодом, которого нет в dat-файле, валит Xray")
        _box_desc("при старте («code not found in geosite.dat» → exit 23).")
        _box_desc("Обновите geo-файлы: Настройки сети → GeoIP/GeoSite — и повторите.")
        _box_bottom()
        _log("WARN", f"preset {preset['key']}: нет категорий {missing}")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    # Предпросмотр: первые домены каждой категории (~2 с один раз,
    # дальше mtime-кэш) — видно, ЧТО именно матчится, до создания правила.
    samples = geosite_samples(RR_SAMPLE_DOMAINS) if codes is not None else None

    print()
    _box_top(f"Пресет: {preset['title']}")
    _box_row()
    _box_desc(preset["desc"])
    _box_row()
    for d in preset["domains"]:
        low = str(d).lower()
        cnt = ""
        if codes is not None and low.startswith("geosite:"):
            c = low.split(":", 1)[1]
            cnt = f"  — {codes.get(c, 0)} дом."
            if samples:
                smp = ", ".join(samples.get(c, [])[:2])
                if smp:
                    cnt += f"  · {smp}"
        _box_row(f"  {CYAN}{d}{NC}{DIM}{cnt}{NC}")
    _box_row()
    tiny = _rr_preset_tiny(preset, codes)
    if tiny:
        tlist = ", ".join(f"{c} ({n} дом.)" for c, n in tiny)
        _box_warn(f"  Куцые категории: {tlist} — покрытие может быть неполным;")
        _box_warn("  при желании добавьте domain:-паттерны редактором (пункт 2).")
        _box_row()
    _box_desc("Правило создастся с priority=10, placement=top (перебивает")
    _box_desc("встроенные ru_subnets/youtube). Пересекающиеся пресеты: точечному")
    _box_desc("ставьте меньший приоритет (меню 2). Дальше — обычное правило (2/3/4).")
    _box_bottom()

    outbound = _rr_pick_outbound(title=f"Куда направить: {preset['title']}?",
                                 suggest=preset.get("suggest"))
    if not outbound:
        return

    name = _rr_unique_preset_name(preset["key"])
    rule = {
        "name": name,
        "enabled": True,
        "domains": list(preset["domains"]),
        "ips": [],
        "ports": [],
        "outbound": outbound,
        "priority": 10,
        "placement": "top",
        "chunk": RR_DEFAULT_CHUNK,
        "source": f"preset:{preset['key']}",
        "created_at": _rr_now(),
        "updated_at": _rr_now(),
    }

    print()
    _box_top(f"Новое правило (пресет): {name}")
    _box_kv("Матч", _rr_match_summary(rule))
    _box_kv("  домены", ", ".join(rule["domains"][:5])
            + (" ..." if len(rule["domains"]) > 5 else ""))
    _box_kv("Outbound", outbound)
    _box_kv("Приоритет", "10")
    _box_kv("Расположение", "top (выше встроенных)")
    _box_kv("Источник", rule["source"])
    _box_row()
    _box_warn("  Правило действует на всех клиентов сервера сразу (routing Xray")
    _box_warn("  не разделяет трафик по пользователям).")
    _box_bottom()
    if not tui_confirm("Создать правило из пресета и применить?", default=False):
        return

    state = _rr_load()
    state.setdefault("rules", []).append(rule)
    _rr_save(state)
    _log_change(f"rule_add:{name}", f"preset {preset['key']} → {outbound}")
    _rr_apply_to_xray(restart=True, validate=True)
    input(f"{BLUE}Нажмите Enter...{NC}")


def _rr_menu_mix(codes: "dict | None") -> None:
    """Сборщик «свой набор»: multi-select пресетов по группам → ОДНО
    правило из объединения доменов (OR-семантика Xray).

    Категории, отсутствующие в geosite.dat, в набор не попадают —
    WARN и пропуск (защита от мёртвого Xray, канон пресетов).
    """
    picked: list = []
    picked_keys: set = set()

    while True:
        groups = [g for g in RR_PRESET_GROUPS if _rr_presets_in_group(g["key"])]
        g_options = [g["title"] for g in groups]
        g_options.append("✔ Завершить набор" if picked else "— Отмена —")
        gidx = tui_select("Свой набор — добавить категории из группы", g_options)
        if gidx is None or gidx == len(g_options) - 1:
            if not picked:
                return
            break
        group = groups[gidx]
        presets = _rr_presets_in_group(group["key"])
        options = [_rr_preset_label(p, codes) for p in presets]
        sel = tui_multi_select(
            f"{group['title']} — отметьте Space, Enter — готово", options)
        if not sel:
            continue
        for i in sel:
            p = presets[i]
            if p["key"] in picked_keys:
                continue
            missing = _rr_preset_missing(p, codes)
            if missing:
                _warn(f"«{p['title']}» пропущен — нет категорий: "
                      f"{', '.join(missing)}")
                continue
            picked.append(p)
            picked_keys.add(p["key"])
        if picked:
            _info(f"В наборе {len(picked)} "
                  f"{_rr_plural(len(picked), ('категория', 'категории', 'категорий'))}"
                  " — можно добавить ещё из другой группы")

    # Объединение доменов с дедупом (порядок выбора сохраняется).
    domains: list = []
    seen: set = set()
    for p in picked:
        for d in p["domains"]:
            low = str(d).lower()
            if low not in seen:
                seen.add(low)
                domains.append(d)

    # Рекомендация outbound: единая для всех отмеченных — иначе без
    # предвыбора (смешали direct и block — решает человек).
    suggests = {p.get("suggest") for p in picked}
    suggest = suggests.pop() if len(suggests) == 1 else None

    total = None
    if codes is not None:
        total = 0
        for d in domains:
            low = str(d).lower()
            if low.startswith("geosite:"):
                total += codes.get(low.split(":", 1)[1], 0)
            else:
                total += 1

    print()
    _box_top("🔧 Свой набор — одно правило из отмеченных категорий")
    _box_row()
    _box_desc("Домены всех отмеченных пресетов объединяются в ОДНО правило (OR).")
    _box_row()
    for p in picked:
        _box_row(f"  {CYAN}{p['title']}{NC}")
    _box_row()
    _box_kv("Матч", f"{len(domains)} паттернов"
            + (f" (~{total} дом.)" if total is not None else ""))
    _box_kv("  домены", ", ".join(domains[:6])
            + (" ..." if len(domains) > 6 else ""))
    tiny_pairs: list = []
    for p in picked:
        tiny_pairs.extend(_rr_preset_tiny(p, codes))
    if tiny_pairs:
        tlist = ", ".join(f"{c} ({n})" for c, n in tiny_pairs)
        _box_warn(f"  Куцые категории: {tlist} — покрытие может быть неполным.")
    _box_row()
    _box_desc("Правило создастся с priority=10, placement=top — как пресет;")
    _box_desc("пересечения с другими правилами решайте приоритетами (меню 2).")
    _box_bottom()

    outbound = _rr_pick_outbound(title="Куда направить: свой набор?",
                                 suggest=suggest)
    if not outbound:
        return

    name = _rr_unique_preset_name("mix")
    rule = {
        "name": name,
        "enabled": True,
        "domains": domains,
        "ips": [],
        "ports": [],
        "outbound": outbound,
        "priority": 10,
        "placement": "top",
        "chunk": RR_DEFAULT_CHUNK,
        "source": "mix:" + "+".join(p["key"] for p in picked),
        "created_at": _rr_now(),
        "updated_at": _rr_now(),
    }

    print()
    _box_top(f"Новое правило (свой набор): {name}")
    _box_kv("Матч", _rr_match_summary(rule))
    _box_kv("  домены", ", ".join(rule["domains"][:5])
            + (" ..." if len(rule["domains"]) > 5 else ""))
    _box_kv("Outbound", outbound)
    _box_kv("Приоритет", "10")
    _box_kv("Расположение", "top (выше встроенных)")
    _box_kv("Источник", rule["source"])
    _box_row()
    _box_warn("  Правило действует на всех клиентов сервера сразу (routing Xray")
    _box_warn("  не разделяет трафик по пользователям).")
    _box_bottom()
    if not tui_confirm("Создать правило из набора и применить?", default=False):
        return

    state = _rr_load()
    state.setdefault("rules", []).append(rule)
    _rr_save(state)
    _log_change(f"rule_add:{name}", f"{rule['source']} → {outbound}")
    _rr_apply_to_xray(restart=True, validate=True)
    input(f"{BLUE}Нажмите Enter...{NC}")


# ══════════════════════════════════════════════════════════════════════════════
#  МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════

def do_manage_routing_rules() -> None:
    """Меню управления кастомными routing-правилами."""
    while True:
        os.system("clear")
        state   = _rr_load()
        rules   = state.get("rules", [])
        enabled = [r for r in rules if r.get("enabled", True)]
        in_cfg  = _rr_custom_names_in_config()
        need    = {r["name"] for r in enabled}
        lost    = need - in_cfg
        extra   = in_cfg - need

        print()
        _box_top("🧭  КАСТОМНЫЕ ROUTING-ПРАВИЛА")
        _box_row()
        _box_row(f"  {BOLD}Правил: {len(rules)}{NC}  {DIM}(включено {len(enabled)}, "
                 f"в конфиге {len(in_cfg)}){NC}")
        if rules:
            _box_sep()
            shown = 0
            for r in sorted(rules, key=lambda x: (x.get("priority", 100), x.get("name", ""))):
                if shown >= 8:
                    _box_row(f"  {DIM}... ещё {len(rules) - 8} правил{NC}")
                    break
                shown += 1
                on    = r.get("enabled", True)
                dot   = f"{GREEN}●{NC}" if on else f"{DIM}○{NC}"
                name  = r.get("name", "?")
                ob    = r.get("outbound", "?")
                prio  = r.get("priority", 100)
                mat   = _rr_match_summary(r)
                plac  = "↑top" if r.get("placement", "top") != "before_catchall" else "↓pre-catchall"
                obcol = GREEN if ob in ("direct", "direct-local") else (
                    RED if ob in ("block", "BLOCK") else CYAN)
                _box_row(f"  {dot} {CYAN}{name:<28}{NC} {DIM}p{prio:<3}{NC} "
                         f"{mat:<16} → {obcol}{ob}{NC}  {DIM}{plac}{NC}")
        if lost:
            _box_sep()
            _box_row(f"  {RED}⚠  Потеряно в конфиге: {len(lost)}{NC}  "
                     f"{DIM}(regenerate стёр — пункт 7 восстановит){NC}")
        _box_row()
        _box_desc("Матч: домены / IP+CIDR / порты. Поля в одном правиле = AND,")
        _box_desc("значения в списке = OR. Большие IP-списки режутся по 500.")
        _box_desc(f"{YELLOW}⚠  Правила действуют на всех клиентов сервера сразу.{NC}")
        _box_row()
        _box_item("1", "Добавить правило")
        _box_item("2", "Изменить правило")
        _box_item("3", "Вкл / выкл правило")
        _box_item("4", "Удалить правило")
        _box_item("5", f"Импорт РФ-подсетей (RIPE)  {DIM}→ любой outbound вместо direct{NC}")
        _box_item("6", "Показать живые правила из конфига (custom:*)")
        _box_item("7", "Пере-применить все правила из state (после regenerate)")
        _box_item("8", f"Кастомные outbound'ы 🔗  {DIM}свои ноды / друзья — vless:// ссылка, мастер, JSON{NC}")
        _box_item("9", f"Готовые пресеты  {DIM}12 групп: игры / видео / соцсети / музыка / AI / РФ / торренты / блокировки — + свой набор{NC}")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch == "1":
            _rr_menu_add_rule()
        elif ch == "2":
            _rr_menu_edit_rule()
        elif ch == "3":
            _rr_menu_toggle_rule()
        elif ch == "4":
            _rr_menu_delete_rule()
        elif ch == "5":
            _rr_import_ru_subnets()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "6":
            _rr_show_live_rules()
        elif ch == "7":
            print()
            ok = _rr_apply_to_xray(restart=True, validate=True)
            if ok:
                _success("Все правила из state пере-применены")
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "8":
            # Кастомные outbound'ы (запрос клиента 04.11: «в режиме А можно
            # как-то добавить outbound?») — свои ноды/друзья: vless:// и др.
            try:
                from chimera.modules.custom_outbounds import do_manage_custom_outbounds
                do_manage_custom_outbounds()
            except ImportError as e:
                _warn(f"Модуль custom_outbounds не найден: {e}")
                time.sleep(2)
        elif ch == "9":
            _rr_menu_presets()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch in ("q", ""):
            break
        else:
            _warn("Неверный выбор")
            time.sleep(1)


# ── Подменю: добавление / изменение ──────────────────────────────────────────

_AWG_HINT_SHOWN = False


def _rr_menu_add_or_edit(existing: "dict | None" = None) -> "dict | None":
    """Общий flow добавления (existing=None) / изменения (existing=rule).

    Возвращает готовое правило-словарь или None (отмена). НЕ сохраняет.
    """
    global _AWG_HINT_SHOWN
    is_edit = existing is not None
    state   = _rr_load()
    others  = {r.get("name") for r in state.get("rules", [])
               if not is_edit or r.get("name") != existing.get("name")}

    awg = _rr_awg_exit_enabled()
    if awg and not _AWG_HINT_SHOWN and not is_edit:
        _AWG_HINT_SHOWN = True
        print()
        _box_top("Подсказка (AWG-режим)")
        _box_row()
        _box_row(f"  Транспорт AWG активен: {CYAN}direct{NC} идёт через туннель awg0 → exit-VPS,")
        _box_row(f"  {CYAN}direct-local{NC} — через default route ОС (как ru_subnets в AWG).")
        _box_bottom()

    # ── Шаг 1: форма (имя, матчи, приоритет) ──
    f_default = (existing or {}).get
    while True:
        form = tui_form(
            "Изменить правило" if is_edit else "Новое правило — матч и приоритет",
            [
                TuiField(key="name", label="Имя", default=f_default("name", ""),
                         required=True, validator=_rr_validate_name,
                         hint="a-z0-9._- ; идентификатор в comment=custom:<имя>"),
                TuiField(key="domains", label="Домены", default=", ".join(f_default("domains", []) or []),
                         validator=_rr_validate_domains,
                         hint="example.com, domain:google.com, geosite:category-ads-all"),
                TuiField(key="ips", label="IP / CIDR", default=", ".join(f_default("ips", []) or []),
                         validator=_rr_validate_ips,
                         hint="1.2.3.0/24, 5.6.7.8, geoip:ru — пусто = нет"),
                TuiField(key="ports", label="Порты", default=", ".join(f_default("ports", []) or []),
                         validator=_rr_validate_ports,
                         hint="443, 1000-2000 — пусто = нет"),
                TuiField(key="priority", label="Приоритет", default=str(f_default("priority", 10)),
                         required=True, validator=_rr_validate_priority,
                         hint="Меньше = выше в конфиге (раньше матчится)"),
            ],
        )
        if form is None:
            return None

        name = form["name"].strip().lower()
        if name in others:
            _warn(f"Имя '{name}' уже занято другим правилом")
            continue

        domains = _split_list(form.get("domains", ""))
        ips     = _split_list(form.get("ips", ""))
        ports   = _split_list(form.get("ports", ""))
        if not domains and not ips and not ports:
            _warn("Хотя бы один матч: домены, IP/CIDR или порты")
            continue

        n_ip_chunks = (len(ips) + RR_DEFAULT_CHUNK - 1) // RR_DEFAULT_CHUNK or 1
        if n_ip_chunks > 1 and (domains or ports):
            _warn(f"{len(ips)} IP режется на {n_ip_chunks} правил по "
                  f"{RR_DEFAULT_CHUNK} — домены/порты при разбивке не "
                  f"поддерживаются. Вынесите их в отдельное правило.")
            continue
        break

    # ── Шаг 2: outbound ──
    outbound = _rr_pick_outbound(cur_out=f_default("outbound", "direct"))
    if not outbound:
        return None

    # ── Шаг 3: расположение ──
    cur_plac = f_default("placement", "top") or "top"
    plac_idx = tui_select(
        "Расположение правила в routing.rules",
        [
            "top — в начало: ВЫШЕ dns_custom/ru_subnets/youtube (перебивает встроенные)",
            "before_catchall — перед catch-all в конце: ПОСЛЕ встроенных",
        ],
        default=0 if cur_plac != "before_catchall" else 1,
    )
    if plac_idx is None:
        return None
    placement = "top" if plac_idx == 0 else "before_catchall"

    # ── Сборка ──
    rule = {
        "name": name,
        "enabled": f_default("enabled", True),
        "domains": domains,
        "ips": ips,
        "ports": ports,
        "outbound": outbound,
        "priority": int(form["priority"]),
        "placement": placement,
        "chunk": int(f_default("chunk", RR_DEFAULT_CHUNK) or RR_DEFAULT_CHUNK),
        "source": f_default("source", "manual"),
        "created_at": f_default("created_at", _rr_now()),
        "updated_at": _rr_now(),
    }
    if is_edit:
        rule["enabled"] = existing.get("enabled", True)

    # ── Сводка ──
    xr_list, err = _rr_build_xray_rules(rule)
    print()
    _box_top(f"{'Изменение' if is_edit else 'Новое'} правило: {name}")
    _box_kv("Матч (AND между полями)", _rr_match_summary(rule))
    if domains:
        _box_kv("  домены", ", ".join(domains[:4]) + (" ..." if len(domains) > 4 else ""))
    if ips:
        _box_kv("  ip/cidr", f"{len(ips)} шт" + (f" (→ {len(xr_list)} правил по {rule['chunk']})" if len(xr_list) > 1 else ""))
    if ports:
        _box_kv("  порты", ", ".join(ports[:4]) + (" ..." if len(ports) > 4 else ""))
    _box_kv("Outbound", outbound)
    _box_kv("Приоритет", str(rule["priority"]))
    _box_kv("Расположение", placement + (" (выше встроенных)" if placement == "top" else " (перед catch-all)"))
    if err:
        _box_row()
        _box_warn(f"  {err}")
    _box_bottom()
    return rule


def _split_list(text: str) -> list:
    return [p.strip() for p in (text or "").split(",") if p.strip()]


def _rr_menu_add_rule() -> None:
    rule = _rr_menu_add_or_edit(existing=None)
    if not rule:
        return
    if not tui_confirm("Добавить и применить сейчас?", default=True):
        # Сохранить без применения — предупредить о состоянии
        state = _rr_load()
        state.setdefault("rules", []).append(rule)
        _rr_save(state)
        _warn("Сохранено БЕЗ применения — в конфиге появится по пункту 7")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    state = _rr_load()
    state.setdefault("rules", []).append(rule)
    _rr_save(state)
    _log_change(f"rule_add:{rule['name']}",
                f"{rule.get('source','manual')} → {rule['outbound']}")
    _rr_apply_to_xray(restart=True, validate=True)
    input(f"{BLUE}Нажмите Enter...{NC}")


def _rr_pick_rule(prompt: str, only_enabled: bool = False) -> "dict | None":
    state = _rr_load()
    rules = state.get("rules", [])
    pool = [r for r in rules if (r.get("enabled", True) or not only_enabled)] \
        if only_enabled else list(rules)
    if not pool:
        _warn("Нет правил в state")
        return None
    options = []
    for r in sorted(pool, key=lambda x: (x.get("priority", 100), x.get("name", ""))):
        on = "●" if r.get("enabled", True) else "○"
        options.append(f"[{on}] {r.get('name','?'):<28} → {r.get('outbound','?')}"
                       f"  {_rr_match_summary(r)}")
    idx = tui_select(prompt, options)
    if idx is None:
        return None
    return pool[idx]


def _rr_menu_edit_rule() -> None:
    target = _rr_pick_rule("Какое правило изменить?")
    if not target:
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    old_name = target.get("name")
    updated = _rr_menu_add_or_edit(existing=target)
    if not updated:
        return
    state = _rr_load()
    for i, r in enumerate(state.get("rules", [])):
        if r.get("name") == old_name:
            state["rules"][i] = updated
            break
    _rr_save(state)
    _log_change(f"rule_edit:{updated['name']}", f"было {old_name}")
    if not tui_confirm("Применить изменения (патч конфига + рестарт)?", default=True):
        _warn("Сохранено в state; в конфиге — по пункту 7")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    _rr_apply_to_xray(restart=True, validate=True)
    input(f"{BLUE}Нажмите Enter...{NC}")


def _rr_menu_toggle_rule() -> None:
    target = _rr_pick_rule("Какое правило включить/выключить?")
    if not target:
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    name = target.get("name")
    state = _rr_load()
    for r in state.get("rules", []):
        if r.get("name") == name:
            r["enabled"] = not r.get("enabled", True)
            r["updated_at"] = _rr_now()
            new_val = r["enabled"]
            break
    else:
        return
    _rr_save(state)
    _log_change(f"rule_toggle:{name}", f"enabled={new_val}")
    _rr_apply_to_xray(restart=True, validate=True)
    input(f"{BLUE}Нажмите Enter...{NC}")


def _rr_menu_delete_rule() -> None:
    target = _rr_pick_rule("Какое правило удалить?")
    if not target:
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    name = target.get("name")
    if not tui_confirm(f"Удалить правило '{name}'?", default=False):
        return
    state = _rr_load()
    state["rules"] = [r for r in state.get("rules", []) if r.get("name") != name]
    _rr_save(state)
    _log_change(f"rule_del:{name}", "удалено")
    # apply удалит его из конфига (custom:* удаляются все, вставляются включённые)
    _rr_apply_to_xray(restart=True, validate=True)
    _success(f"Правило '{name}' удалено")
    input(f"{BLUE}Нажмите Enter...{NC}")
