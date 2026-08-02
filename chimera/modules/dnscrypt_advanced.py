"""
chimera/modules/dnscrypt_advanced.py
───────────────────────────────────────────────────────────────────────────────
Расширенная настройка DNSCrypt-proxy: 154 сервера в 36 странах, ODoH, DNSSEC,
131 анонимизированный маршрут, RTT-замер, ручная настройка параметров.

БЕЗОПАСНОСТЬ:
  • НЕ вызывает networkctl / ifconfig / ip link / dhclient.
  • НЕ трогает /etc/resolv.conf, /etc/nsswitch.conf, сетевые интерфейсы.
  • Только перезаписывает /etc/dnscrypt-proxy/dnscrypt-proxy.toml + restart сервиса.
  • Бэкап конфига перед изменением.

Точка входа:
    from chimera.modules.dnscrypt_advanced import do_dnscrypt_advanced_menu
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os, re, shutil, subprocess, sys, time
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

# ── Цвета ──────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                        CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                        DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m')
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                    DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m')
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED=_C['RED']; GREEN=_C['GREEN']; YELLOW=_C['YELLOW']; CYAN=_C['CYAN']
BLUE=_C['BLUE']; BOLD=_C['BOLD']; DIM=_C['DIM']; WHITE=_C['WHITE']; NC=_C['NC']

from chimera.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item,
    _box_back, _box_info, _box_warn, _box_desc,
)

_DNSCRYPT_CONF = Path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml")
_DNSCRYPT_BIN  = Path("/usr/local/bin/dnscrypt-proxy")

def _run(cmd, capture=False, quiet=False):
    kw = {}
    if capture: kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet: kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def _info(msg):  print(f"{CYAN}[INFO]{NC}  {msg}")
def _ok(msg):    print(f"{GREEN}[OK]{NC}    {msg}")
def _warn(msg):  print(f"{YELLOW}[WARN]{NC}  {msg}")
def _err(msg):   print(f"{RED}[ERR]{NC}   {msg}")

# =============================================================================
#  ПОЛНЫЙ СПИСОК СЕРВЕРОВ — 154 шт., 36 стран
#  Yandex ИСКЛЮЧЁН (утечка DNS). RU-серверы — через EU relay.
# =============================================================================
_SERVER_NAMES: List[str] = [
    # ── RU (2) — dnscry.pt-moscow через EU relay ──────────────────────────
    "dnscry.pt-moscow-ipv4", "dnscry.pt-moscow-ipv6",
    # ── UA (2) ────────────────────────────────────────────────────────────
    "dnscry.pt-kyiv-ipv4", "dnscry.pt-kyiv-ipv6",
    # ── EE (2) ────────────────────────────────────────────────────────────
    "dnscry.pt-tallinn-ipv4", "dnscry.pt-tallinn-ipv6",
    # ── LV (2) ────────────────────────────────────────────────────────────
    "dnscry.pt-riga-ipv4", "dnscry.pt-riga-ipv6",
    # ── LT (2) ────────────────────────────────────────────────────────────
    "dnscry.pt-vilnius-ipv4", "dnscry.pt-vilnius-ipv6",
    # ── FI (7) ────────────────────────────────────────────────────────────
    "cs-finland", "cs-finland6",
    "dnscry.pt-helsinki-ipv4", "dnscry.pt-helsinki-ipv6",
    "dnscry.pt-tuusula-ipv4", "dnscry.pt-tuusula-ipv6",
    "nwps.fi",
    # ── PL (6) ────────────────────────────────────────────────────────────
    "cs-poland", "cs-poland6",
    "dnscry.pt-gdansk-ipv4", "dnscry.pt-gdansk-ipv6",
    "dnscry.pt-warsaw-ipv4", "dnscry.pt-warsaw-ipv6",
    # ── DE (32) ───────────────────────────────────────────────────────────
    "cs-de", "cs-de6", "cs-berlin", "cs-berlin6", "cs-dus", "cs-dus6",
    "dns.digitalsize.net", "dns.digitalsize.net-ipv6",
    "dnscry.pt-dusseldorf-ipv4", "dnscry.pt-dusseldorf-ipv6",
    "dnscry.pt-dusseldorf02-ipv6", "dnscry.pt-dusseldorf03-ipv6",
    "dnscry.pt-frankfurt-ipv4", "dnscry.pt-frankfurt-ipv6",
    "dnscry.pt-frankfurt02-ipv4", "dnscry.pt-frankfurt02-ipv6",
    "dnscry.pt-jena-ipv4", "dnscry.pt-jena-ipv6",
    "dnscry.pt-munich-ipv4", "dnscry.pt-munich-ipv6",
    "dnscry.pt-nuremberg-ipv4", "dnscry.pt-nuremberg-ipv6",
    "dnsforge.de-nofilter", "dnsforge.de-nofilter-ipv6",
    "doh.ffmuc.net", "doh.ffmuc.net-2", "doh.ffmuc.net-v6", "doh.ffmuc.net-v6-2",
    "quad9-dnscrypt-ip4-nofilter-pri", "quad9-dnscrypt-ip6-nofilter-pri",
    "quad9-doh-ip4-port443-nofilter-pri", "quad9-doh-ip6-port443-nofilter-pri",
    # ── SE (10) ───────────────────────────────────────────────────────────
    "cs-swe", "cs-swe6",
    "dnscry.pt-hudiksvall-ipv4", "dnscry.pt-hudiksvall-ipv6",
    "dnscry.pt-stockholm-ipv4", "dnscry.pt-stockholm-ipv6",
    "dnscry.pt-stockholm02-ipv4", "dnscry.pt-stockholm02-ipv6",
    "searx-se-ipv4", "searx-se-ipv6",
    # ── CH (19) ───────────────────────────────────────────────────────────
    "cs-ch", "cs-ch6",
    "dns.digitale-gesellschaft.ch", "dns.digitale-gesellschaft.ch-ipv6",
    "dns.sb", "dns.sb-ipv6",
    "dnscry.pt-geneva-ipv4", "dnscry.pt-geneva-ipv6",
    "dnscry.pt-molln-ipv4", "dnscry.pt-molln-ipv6",
    "dnscry.pt-zurich-ipv4", "dnscry.pt-zurich-ipv6",
    "doh.ibksturm", "ibksturm",
    "switch", "switch-ipv6",
    "dnscrypt-ch-blahdns-ipv4", "dnscrypt-ch-blahdns-ipv6",
    "mullvad-doh",
    # ── NL (10) ───────────────────────────────────────────────────────────
    "cs-nl", "cs-nl6",
    "dnscry.pt-amsterdam-ipv4", "dnscry.pt-amsterdam-ipv6",
    "dnscry.pt-amsterdam02-ipv4", "dnscry.pt-amsterdam02-ipv6",
    "dnscry.pt-amsterdam03-ipv4", "dnscry.pt-amsterdam03-ipv6",
    "dnscry.pt-eygelshoven-ipv4", "dnscry.pt-eygelshoven-ipv6",
    # ── CZ (6) ────────────────────────────────────────────────────────────
    "cs-czech", "cs-czech6",
    "dnscry.pt-prague-ipv4", "dnscry.pt-prague-ipv6",
    "nic.cz", "nic.cz-ipv6",
    # ── RS (3) ────────────────────────────────────────────────────────────
    "cs-serbia", "cs-serbia6", "serbica",
    # ── AT (4) ────────────────────────────────────────────────────────────
    "cs-austria", "cs-austria6",
    "dnscry.pt-vienna-ipv4", "dnscry.pt-vienna-ipv6",
    # ── NO (2) ────────────────────────────────────────────────────────────
    "dnscry.pt-sandefjord-ipv4", "dnscry.pt-sandefjord-ipv6",
    # ── IS (2) ────────────────────────────────────────────────────────────
    "dnscry.pt-hafnarfjordur-ipv4", "dnscry.pt-hafnarfjordur-ipv6",
    # ── BG (2) ────────────────────────────────────────────────────────────
    "dnscry.pt-sofia-ipv4", "dnscry.pt-sofia-ipv6",
    # ── DK (2) ────────────────────────────────────────────────────────────
    "dnscry.pt-copenhagen-ipv4", "dnscry.pt-copenhagen-ipv6",
    # ── RO (2) ────────────────────────────────────────────────────────────
    "dnscry.pt-bucharest-ipv4", "dnscry.pt-bucharest-ipv6",
    # ── HU (2) ────────────────────────────────────────────────────────────
    "dnscry.pt-budapest-ipv4", "dnscry.pt-budapest-ipv6",
    # ── BE (4) ────────────────────────────────────────────────────────────
    "cs-belgium", "cs-belgium6",
    "dnscry.pt-brussels-ipv4", "dnscry.pt-brussels-ipv6",
    # ── LU (2) ────────────────────────────────────────────────────────────
    "dnscry.pt-luxembourg-ipv4", "dnscry.pt-luxembourg-ipv6",
    # ══ НОВЫЕ СТРАНЫ (Tier 1-3) ══════════════════════════════════════════
    # ── TR (2) — Стамбул ──────────────────────────────────────────────────
    "dnscry.pt-istanbul-ipv4", "dnscry.pt-istanbul-ipv6",
    # ── SK (2) — Братислава ───────────────────────────────────────────────
    "dnscry.pt-bratislava-ipv4", "dnscry.pt-bratislava-ipv6",
    # ── MD (2) — Кишинёв ──────────────────────────────────────────────────
    "dnscry.pt-chisinau-ipv4", "dnscry.pt-chisinau-ipv6",
    # ── FR (4) — Париж ────────────────────────────────────────────────────
    "cs-france", "cs-france6",
    "dnscry.pt-paris-ipv4", "dnscry.pt-paris-ipv6",
    # ── IT (2) — Милан ────────────────────────────────────────────────────
    "dnscry.pt-milan-ipv4", "dnscry.pt-milan-ipv6",
    # ── ES (2) — Мадрид ───────────────────────────────────────────────────
    "dnscry.pt-madrid-ipv4", "dnscry.pt-madrid-ipv6",
    # ── GR (2) — Афины ────────────────────────────────────────────────────
    "dnscry.pt-athens-ipv4", "dnscry.pt-athens-ipv6",
    # ── SI (2) — Любляна ──────────────────────────────────────────────────
    "dnscry.pt-ljubljana-ipv4", "dnscry.pt-ljubljana-ipv6",
    # ── HR (2) — Загреб ───────────────────────────────────────────────────
    "dnscry.pt-zagreb-ipv4", "dnscry.pt-zagreb-ipv6",
    # ── PT (2) — Лиссабон ─────────────────────────────────────────────────
    "dnscry.pt-lisbon-ipv4", "dnscry.pt-lisbon-ipv6",
    # ── UK (3) — Лондон ───────────────────────────────────────────────────
    "dnsforge.uk",
    "dnscry.pt-london-ipv4", "dnscry.pt-london-ipv6",
    # ── JP (2) — Токио ────────────────────────────────────────────────────
    "dnscry.pt-tokyo-ipv4", "dnscry.pt-tokyo-ipv6",
    # ── SG (2) — Сингапур ─────────────────────────────────────────────────
    "dnscry.pt-singapore-ipv4", "dnscry.pt-singapore-ipv6",
    # ── GE (2) — Тбилиси ──────────────────────────────────────────────────
    "dnscry.pt-tbilisi-ipv4", "dnscry.pt-tbilisi-ipv6",
    # ══ TIER 4 — ГЛОБАЛЬНОЕ ПОКРЫТИЕ (отказоустойчивость, диверсификация) ══
    # ── US (8) — Нью-Йорк, Чикаго, Лос-Анджелес, Даллас ───────────────────
    "dnscry.pt-newyork-ipv4", "dnscry.pt-newyork-ipv6",
    "dnscry.pt-chicago-ipv4", "dnscry.pt-chicago-ipv6",
    "dnscry.pt-losangeles-ipv4", "dnscry.pt-losangeles-ipv6",
    "dnscry.pt-dallas-ipv4", "dnscry.pt-dallas-ipv6",
    # ── CA (4) — Торонто, Монреаль ────────────────────────────────────────
    "dnscry.pt-toronto-ipv4", "dnscry.pt-toronto-ipv6",
    "dnscry.pt-montreal-ipv4", "dnscry.pt-montreal-ipv6",
    # ── AU (4) — Сидней, Мельбурн ─────────────────────────────────────────
    "dnscry.pt-sydney-ipv4", "dnscry.pt-sydney-ipv6",
    "dnscry.pt-melbourne-ipv4", "dnscry.pt-melbourne-ipv6",
    # ── AE (2) — Дубай ────────────────────────────────────────────────────
    "dnscry.pt-dubai-ipv4", "dnscry.pt-dubai-ipv6",
    # ── IL (2) — Тель-Авив ────────────────────────────────────────────────
    "dnscry.pt-telaviv-ipv4", "dnscry.pt-telaviv-ipv6",
    # ── IN (2) — Мумбаи ───────────────────────────────────────────────────
    "dnscry.pt-mumbai-ipv4", "dnscry.pt-mumbai-ipv6",
    # ── BR (2) — Сан-Паулу ────────────────────────────────────────────────
    "dnscry.pt-saopaulo-ipv4", "dnscry.pt-saopaulo-ipv6",
    # ── ZA (2) — Йоханнесбург ─────────────────────────────────────────────
    "dnscry.pt-johannesburg-ipv4", "dnscry.pt-johannesburg-ipv6",
    # ── IE (2) — Дублин ───────────────────────────────────────────────────
    "dnscry.pt-dublin-ipv4", "dnscry.pt-dublin-ipv6",
    # ── AR (2) — Буэнос-Айрес ─────────────────────────────────────────────
    "dnscry.pt-buenosaires-ipv4", "dnscry.pt-buenosaires-ipv6",
    # ── CL (2) — Сантьяго ─────────────────────────────────────────────────
    "dnscry.pt-santiago-ipv4", "dnscry.pt-santiago-ipv6",
    # ── KR (2) — Сеул ─────────────────────────────────────────────────────
    "dnscry.pt-seoul-ipv4", "dnscry.pt-seoul-ipv6",
    # ── TH (2) — Бангкок ──────────────────────────────────────────────────
    "dnscry.pt-bangkok-ipv4", "dnscry.pt-bangkok-ipv6",
    # ── ID (2) — Джакарта ─────────────────────────────────────────────────
    "dnscry.pt-jakarta-ipv4", "dnscry.pt-jakarta-ipv6",
    # ── Глобальные DoH (cloudflare + google как fallback) ─────────────────
    "cloudflare", "cloudflare-ipv6",
    "google", "google-ipv6",
]

# =============================================================================
#  АНОНИМИЗИРОВАННЫЕ МАРШРУТЫ — 130 + wildcard
#  Принцип: server в стране X → relay в стране Y (≠ X, не сосед)
#  Relay видит IP клиента, не видит запрос.
#  Server видит запрос, не знает IP клиента (видит relay).
# =============================================================================
_ANON_ROUTES: List[str] = [
    # ── RU → FI/PL/DE/SE ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-moscow-ipv4', via=['anon-cs-finland','anon-cs-poland','anon-cs-de','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-moscow-ipv6', via=['anon-cs-finland6','anon-cs-poland6','anon-cs-de6','anon-cs-swe6'] }",
    # ── UA → FI/PL/DE/SE (не RU, не сосед) ─────────────────────────────────
    "{ server_name='dnscry.pt-kyiv-ipv4', via=['anon-cs-finland','anon-cs-poland','anon-cs-de','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-kyiv-ipv6', via=['anon-cs-finland6','anon-cs-poland6','anon-cs-de6','anon-cs-swe6'] }",
    # ── EE → FI/PL/DE/SE ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-tallinn-ipv4', via=['anon-cs-finland','anon-cs-poland','anon-cs-de','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-tallinn-ipv6', via=['anon-cs-finland6','anon-cs-poland6','anon-cs-de6','anon-cs-swe6'] }",
    # ── LV → FI/PL/DE/SE ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-riga-ipv4', via=['anon-cs-finland','anon-cs-poland','anon-cs-de','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-riga-ipv6', via=['anon-cs-finland6','anon-cs-poland6','anon-cs-de6','anon-cs-swe6'] }",
    # ── LT → PL/FI/DE/SE ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-vilnius-ipv4', via=['anon-cs-poland','anon-cs-finland','anon-cs-de','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-vilnius-ipv6', via=['anon-cs-poland6','anon-cs-finland6','anon-cs-de6','anon-cs-swe6'] }",
    # ── FI → DE/PL/SE/NL ──────────────────────────────────────────────────
    "{ server_name='cs-finland',              via=['anon-cs-de','anon-cs-poland','anon-cs-swe','anon-cs-nl'] }",
    "{ server_name='cs-finland6',             via=['anon-cs-de6','anon-cs-poland6','anon-cs-swe6','anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-helsinki-ipv4', via=['anon-cs-de','anon-cs-poland','anon-cs-swe','anon-cs-nl'] }",
    "{ server_name='dnscry.pt-helsinki-ipv6', via=['anon-cs-de6','anon-cs-poland6','anon-cs-swe6','anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-tuusula-ipv4',  via=['anon-cs-de','anon-cs-poland','anon-cs-berlin','anon-cs-nl'] }",
    "{ server_name='dnscry.pt-tuusula-ipv6',  via=['anon-cs-de6','anon-cs-poland6','anon-cs-berlin6','anon-cs-nl6'] }",
    # ── PL → FI/DE/SE/NL ──────────────────────────────────────────────────
    "{ server_name='cs-poland',             via=['anon-cs-finland','anon-cs-de','anon-cs-swe','anon-cs-nl'] }",
    "{ server_name='cs-poland6',            via=['anon-cs-finland6','anon-cs-de6','anon-cs-swe6','anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-gdansk-ipv4', via=['anon-cs-finland','anon-cs-de','anon-cs-berlin','anon-cs-nl'] }",
    "{ server_name='dnscry.pt-gdansk-ipv6', via=['anon-cs-finland6','anon-cs-de6','anon-cs-berlin6','anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-warsaw-ipv4', via=['anon-cs-finland','anon-cs-de','anon-cs-swe','anon-cs-nl'] }",
    "{ server_name='dnscry.pt-warsaw-ipv6', via=['anon-cs-finland6','anon-cs-de6','anon-cs-swe6','anon-cs-nl6'] }",
    # ── DE → FI/PL/SE/NL/CH (не тот же провайдер!) ────────────────────────
    "{ server_name='cs-de',                       via=['anon-cs-finland','anon-cs-poland','anon-cs-swe','anon-cs-nl'] }",
    "{ server_name='cs-de6',                      via=['anon-cs-finland6','anon-cs-poland6','anon-cs-swe6','anon-cs-nl6'] }",
    "{ server_name='cs-berlin',                   via=['anon-cs-finland','anon-cs-poland','anon-cs-nl','anon-cs-ch'] }",
    "{ server_name='cs-berlin6',                  via=['anon-cs-finland6','anon-cs-poland6','anon-cs-nl6','anon-cs-ch6'] }",
    "{ server_name='cs-dus',                      via=['anon-cs-finland','anon-cs-poland','anon-cs-swe','anon-cs-nl'] }",
    "{ server_name='cs-dus6',                     via=['anon-cs-finland6','anon-cs-poland6','anon-cs-swe6','anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-frankfurt-ipv4',    via=['anon-cs-finland','anon-cs-poland','anon-cs-swe','anon-cs-nl'] }",
    "{ server_name='dnscry.pt-frankfurt-ipv6',    via=['anon-cs-finland6','anon-cs-poland6','anon-cs-swe6','anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-frankfurt02-ipv4',  via=['anon-cs-finland','anon-cs-poland','anon-cs-nl','anon-cs-ch'] }",
    "{ server_name='dnscry.pt-frankfurt02-ipv6',  via=['anon-cs-finland6','anon-cs-poland6','anon-cs-nl6','anon-cs-ch6'] }",
    "{ server_name='dnscry.pt-dusseldorf-ipv4',   via=['anon-cs-finland','anon-cs-poland','anon-cs-swe','anon-cs-ch'] }",
    "{ server_name='dnscry.pt-dusseldorf-ipv6',   via=['anon-cs-finland6','anon-cs-poland6','anon-cs-swe6','anon-cs-ch6'] }",
    "{ server_name='dnscry.pt-dusseldorf02-ipv6', via=['anon-cs-finland6','anon-cs-poland6','anon-cs-nl6','anon-cs-swe6'] }",
    "{ server_name='dnscry.pt-dusseldorf03-ipv6', via=['anon-cs-finland6','anon-cs-poland6','anon-cs-ch6','anon-cs-swe6'] }",
    "{ server_name='dnscry.pt-nuremberg-ipv4',    via=['anon-cs-finland','anon-cs-poland','anon-cs-swe','anon-cs-nl'] }",
    "{ server_name='dnscry.pt-nuremberg-ipv6',    via=['anon-cs-finland6','anon-cs-poland6','anon-cs-swe6','anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-jena-ipv4',         via=['anon-cs-finland','anon-cs-poland','anon-cs-nl','anon-cs-ch'] }",
    "{ server_name='dnscry.pt-jena-ipv6',         via=['anon-cs-finland6','anon-cs-poland6','anon-cs-nl6','anon-cs-ch6'] }",
    "{ server_name='dnscry.pt-munich-ipv4',       via=['anon-cs-finland','anon-cs-poland','anon-cs-swe','anon-cs-ch'] }",
    "{ server_name='dnscry.pt-munich-ipv6',       via=['anon-cs-finland6','anon-cs-poland6','anon-cs-swe6','anon-cs-ch6'] }",
    "{ server_name='quad9-dnscrypt-ip4-nofilter-pri', via=['anon-cs-finland','anon-cs-poland','anon-cs-swe','anon-cs-nl'] }",
    "{ server_name='quad9-dnscrypt-ip6-nofilter-pri', via=['anon-cs-finland6','anon-cs-poland6','anon-cs-swe6','anon-cs-nl6'] }",
    # ── SE → FI/PL/DE/NL ──────────────────────────────────────────────────
    "{ server_name='cs-swe',                     via=['anon-cs-finland','anon-cs-poland','anon-cs-de','anon-cs-nl'] }",
    "{ server_name='cs-swe6',                    via=['anon-cs-finland6','anon-cs-poland6','anon-cs-de6','anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-hudiksvall-ipv4',  via=['anon-cs-finland','anon-cs-de','anon-cs-nl','anon-cs-ch'] }",
    "{ server_name='dnscry.pt-hudiksvall-ipv6',  via=['anon-cs-finland6','anon-cs-de6','anon-cs-nl6','anon-cs-ch6'] }",
    "{ server_name='dnscry.pt-stockholm-ipv4',   via=['anon-cs-finland','anon-cs-poland','anon-cs-de','anon-cs-nl'] }",
    "{ server_name='dnscry.pt-stockholm-ipv6',   via=['anon-cs-finland6','anon-cs-poland6','anon-cs-de6','anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-stockholm02-ipv4', via=['anon-cs-finland','anon-cs-poland','anon-cs-nl','anon-cs-ch'] }",
    "{ server_name='dnscry.pt-stockholm02-ipv6', via=['anon-cs-finland6','anon-cs-poland6','anon-cs-nl6','anon-cs-ch6'] }",
    # ── CH → DE/FI/PL/NL ──────────────────────────────────────────────────
    "{ server_name='cs-ch',                    via=['anon-cs-de','anon-cs-finland','anon-cs-poland','anon-cs-nl'] }",
    "{ server_name='cs-ch6',                   via=['anon-cs-de6','anon-cs-finland6','anon-cs-poland6','anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-geneva-ipv4',    via=['anon-cs-de','anon-cs-finland','anon-cs-poland','anon-cs-nl'] }",
    "{ server_name='dnscry.pt-geneva-ipv6',    via=['anon-cs-de6','anon-cs-finland6','anon-cs-poland6','anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-molln-ipv4',     via=['anon-cs-de','anon-cs-finland','anon-cs-swe','anon-cs-nl'] }",
    "{ server_name='dnscry.pt-molln-ipv6',     via=['anon-cs-de6','anon-cs-finland6','anon-cs-swe6','anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-zurich-ipv4',    via=['anon-cs-de','anon-cs-finland','anon-cs-poland','anon-cs-nl'] }",
    "{ server_name='dnscry.pt-zurich-ipv6',    via=['anon-cs-de6','anon-cs-finland6','anon-cs-poland6','anon-cs-nl6'] }",
    "{ server_name='ibksturm',                 via=['anon-cs-de','anon-cs-finland','anon-cs-poland','anon-cs-nl'] }",
    "{ server_name='dnscrypt-ch-blahdns-ipv4', via=['anon-cs-de','anon-cs-finland','anon-cs-swe','anon-cs-nl'] }",
    "{ server_name='dnscrypt-ch-blahdns-ipv6', via=['anon-cs-de6','anon-cs-finland6','anon-cs-swe6','anon-cs-nl6'] }",
    # ── NL → DE/FI/PL/SE ──────────────────────────────────────────────────
    "{ server_name='cs-nl',                      via=['anon-cs-de','anon-cs-finland','anon-cs-poland','anon-cs-swe'] }",
    "{ server_name='cs-nl6',                     via=['anon-cs-de6','anon-cs-finland6','anon-cs-poland6','anon-cs-swe6'] }",
    "{ server_name='dnscry.pt-amsterdam-ipv4',   via=['anon-cs-de','anon-cs-finland','anon-cs-poland','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-amsterdam-ipv6',   via=['anon-cs-de6','anon-cs-finland6','anon-cs-poland6','anon-cs-swe6'] }",
    "{ server_name='dnscry.pt-amsterdam02-ipv4', via=['anon-cs-de','anon-cs-finland','anon-cs-swe','anon-cs-ch'] }",
    "{ server_name='dnscry.pt-amsterdam02-ipv6', via=['anon-cs-de6','anon-cs-finland6','anon-cs-swe6','anon-cs-ch6'] }",
    "{ server_name='dnscry.pt-amsterdam03-ipv4', via=['anon-cs-de','anon-cs-poland','anon-cs-swe','anon-cs-ch'] }",
    "{ server_name='dnscry.pt-amsterdam03-ipv6', via=['anon-cs-de6','anon-cs-poland6','anon-cs-swe6','anon-cs-ch6'] }",
    "{ server_name='dnscry.pt-eygelshoven-ipv4', via=['anon-cs-de','anon-cs-finland','anon-cs-poland','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-eygelshoven-ipv6', via=['anon-cs-de6','anon-cs-finland6','anon-cs-poland6','anon-cs-swe6'] }",
    # ── CZ → DE/PL/FI/SE ──────────────────────────────────────────────────
    "{ server_name='cs-czech',              via=['anon-cs-de','anon-cs-poland','anon-cs-finland','anon-cs-swe'] }",
    "{ server_name='cs-czech6',             via=['anon-cs-de6','anon-cs-poland6','anon-cs-finland6','anon-cs-swe6'] }",
    "{ server_name='dnscry.pt-prague-ipv4', via=['anon-cs-de','anon-cs-poland','anon-cs-finland','anon-cs-nl'] }",
    "{ server_name='dnscry.pt-prague-ipv6', via=['anon-cs-de6','anon-cs-poland6','anon-cs-finland6','anon-cs-nl6'] }",
    # ── RS → DE/PL/NL/CH ──────────────────────────────────────────────────
    "{ server_name='cs-serbia',  via=['anon-cs-de','anon-cs-poland','anon-cs-nl','anon-cs-ch'] }",
    "{ server_name='cs-serbia6', via=['anon-cs-de6','anon-cs-poland6','anon-cs-nl6','anon-cs-ch6'] }",
    # ── AT → DE/CH/CZ/NL ──────────────────────────────────────────────────
    "{ server_name='cs-austria',            via=['anon-cs-de','anon-cs-ch','anon-cs-czech','anon-cs-nl'] }",
    "{ server_name='cs-austria6',           via=['anon-cs-de6','anon-cs-ch6','anon-cs-czech6','anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-vienna-ipv4', via=['anon-cs-de','anon-cs-ch','anon-cs-czech','anon-cs-nl'] }",
    "{ server_name='dnscry.pt-vienna-ipv6', via=['anon-cs-de6','anon-cs-ch6','anon-cs-czech6','anon-cs-nl6'] }",
    # ── NO → SE/FI/DE/NL ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-sandefjord-ipv4', via=['anon-cs-swe','anon-cs-finland','anon-cs-de','anon-cs-nl'] }",
    "{ server_name='dnscry.pt-sandefjord-ipv6', via=['anon-cs-swe6','anon-cs-finland6','anon-cs-de6','anon-cs-nl6'] }",
    # ── IS → SE/FI/NL/CH ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-hafnarfjordur-ipv4', via=['anon-cs-swe','anon-cs-finland','anon-cs-nl','anon-cs-ch'] }",
    "{ server_name='dnscry.pt-hafnarfjordur-ipv6', via=['anon-cs-swe6','anon-cs-finland6','anon-cs-nl6','anon-cs-ch6'] }",
    # ── BG → DE/CH/NL/SE ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-sofia-ipv4', via=['anon-cs-de','anon-cs-ch','anon-cs-nl','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-sofia-ipv6', via=['anon-cs-de6','anon-cs-ch6','anon-cs-nl6','anon-cs-swe6'] }",
    # ── DK → SE/FI/DE/NL ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-copenhagen-ipv4', via=['anon-cs-swe','anon-cs-finland','anon-cs-de','anon-cs-nl'] }",
    "{ server_name='dnscry.pt-copenhagen-ipv6', via=['anon-cs-swe6','anon-cs-finland6','anon-cs-de6','anon-cs-nl6'] }",
    # ── RO → DE/PL/CH/NL ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-bucharest-ipv4', via=['anon-cs-de','anon-cs-poland','anon-cs-ch','anon-cs-nl'] }",
    "{ server_name='dnscry.pt-bucharest-ipv6', via=['anon-cs-de6','anon-cs-poland6','anon-cs-ch6','anon-cs-nl6'] }",
    # ── HU → DE/AT/PL/CH ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-budapest-ipv4', via=['anon-cs-de','anon-cs-austria','anon-cs-poland','anon-cs-ch'] }",
    "{ server_name='dnscry.pt-budapest-ipv6', via=['anon-cs-de6','anon-cs-austria6','anon-cs-poland6','anon-cs-ch6'] }",
    # ── BE → NL/DE/FI/CH ──────────────────────────────────────────────────
    "{ server_name='cs-belgium',              via=['anon-cs-nl','anon-cs-de','anon-cs-finland','anon-cs-ch'] }",
    "{ server_name='cs-belgium6',             via=['anon-cs-nl6','anon-cs-de6','anon-cs-finland6','anon-cs-ch6'] }",
    "{ server_name='dnscry.pt-brussels-ipv4', via=['anon-cs-nl','anon-cs-de','anon-cs-finland','anon-cs-ch'] }",
    "{ server_name='dnscry.pt-brussels-ipv6', via=['anon-cs-nl6','anon-cs-de6','anon-cs-finland6','anon-cs-ch6'] }",
    # ── LU → DE/NL/CH/BE ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-luxembourg-ipv4', via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-belgium'] }",
    "{ server_name='dnscry.pt-luxembourg-ipv6', via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-belgium6'] }",
    # ══ НОВЫЕ МАРШРУТЫ (Tier 1-3) ════════════════════════════════════════
    # ── TR → DE/NL/CH/SE (не сосед TR) ────────────────────────────────────
    "{ server_name='dnscry.pt-istanbul-ipv4', via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-istanbul-ipv6', via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── SK → DE/CH/NL/SE (не сосед SK) ────────────────────────────────────
    "{ server_name='dnscry.pt-bratislava-ipv4', via=['anon-cs-de','anon-cs-ch','anon-cs-nl','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-bratislava-ipv6', via=['anon-cs-de6','anon-cs-ch6','anon-cs-nl6','anon-cs-swe6'] }",
    # ── MD → DE/PL/NL/SE (не сосед MD) ────────────────────────────────────
    "{ server_name='dnscry.pt-chisinau-ipv4', via=['anon-cs-de','anon-cs-poland','anon-cs-nl','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-chisinau-ipv6', via=['anon-cs-de6','anon-cs-poland6','anon-cs-nl6','anon-cs-swe6'] }",
    # ── FR → DE/CH/NL/SE (не сосед FR) ────────────────────────────────────
    "{ server_name='cs-france',             via=['anon-cs-de','anon-cs-ch','anon-cs-nl','anon-cs-swe'] }",
    "{ server_name='cs-france6',            via=['anon-cs-de6','anon-cs-ch6','anon-cs-nl6','anon-cs-swe6'] }",
    "{ server_name='dnscry.pt-paris-ipv4',  via=['anon-cs-de','anon-cs-ch','anon-cs-nl','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-paris-ipv6',  via=['anon-cs-de6','anon-cs-ch6','anon-cs-nl6','anon-cs-swe6'] }",
    # ── IT → DE/CH/NL/SE (не сосед IT) ────────────────────────────────────
    "{ server_name='dnscry.pt-milan-ipv4',  via=['anon-cs-de','anon-cs-ch','anon-cs-nl','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-milan-ipv6',  via=['anon-cs-de6','anon-cs-ch6','anon-cs-nl6','anon-cs-swe6'] }",
    # ── ES → DE/CH/NL/SE (не сосед ES) ────────────────────────────────────
    "{ server_name='dnscry.pt-madrid-ipv4', via=['anon-cs-de','anon-cs-ch','anon-cs-nl','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-madrid-ipv6', via=['anon-cs-de6','anon-cs-ch6','anon-cs-nl6','anon-cs-swe6'] }",
    # ── GR → DE/NL/CH/SE (не сосед GR) ────────────────────────────────────
    "{ server_name='dnscry.pt-athens-ipv4', via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-athens-ipv6', via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── SI → DE/CH/NL/SE (не сосед SI) ────────────────────────────────────
    "{ server_name='dnscry.pt-ljubljana-ipv4', via=['anon-cs-de','anon-cs-ch','anon-cs-nl','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-ljubljana-ipv6', via=['anon-cs-de6','anon-cs-ch6','anon-cs-nl6','anon-cs-swe6'] }",
    # ── HR → DE/CH/NL/SE (не сосед HR) ────────────────────────────────────
    "{ server_name='dnscry.pt-zagreb-ipv4', via=['anon-cs-de','anon-cs-ch','anon-cs-nl','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-zagreb-ipv6', via=['anon-cs-de6','anon-cs-ch6','anon-cs-nl6','anon-cs-swe6'] }",
    # ── PT → DE/CH/NL/SE (не сосед PT) ────────────────────────────────────
    "{ server_name='dnscry.pt-lisbon-ipv4', via=['anon-cs-de','anon-cs-ch','anon-cs-nl','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-lisbon-ipv6', via=['anon-cs-de6','anon-cs-ch6','anon-cs-nl6','anon-cs-swe6'] }",
    # ── UK → DE/NL/CH/SE (не сосед UK) ────────────────────────────────────
    "{ server_name='dnscry.pt-london-ipv4', via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-london-ipv6', via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── JP → DE/NL/CH/SE (далеко) ─────────────────────────────────────────
    "{ server_name='dnscry.pt-tokyo-ipv4', via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-tokyo-ipv6', via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── SG → DE/NL/CH/SE (далеко) ─────────────────────────────────────────
    "{ server_name='dnscry.pt-singapore-ipv4', via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-singapore-ipv6', via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── GE → DE/NL/CH/SE (не сосед GE, не RU) ─────────────────────────────
    "{ server_name='dnscry.pt-tbilisi-ipv4', via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-tbilisi-ipv6', via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── DE: доп. серверы без явного маршрута ──────────────────────────────
    "{ server_name='dns.digitalsize.net', via=['anon-cs-finland','anon-cs-poland','anon-cs-swe','anon-cs-nl'] }",
    "{ server_name='dns.digitalsize.net-ipv6', via=['anon-cs-finland6','anon-cs-poland6','anon-cs-swe6','anon-cs-nl6'] }",
    "{ server_name='dnsforge.de-nofilter', via=['anon-cs-finland','anon-cs-poland','anon-cs-swe','anon-cs-nl'] }",
    "{ server_name='dnsforge.de-nofilter-ipv6', via=['anon-cs-finland6','anon-cs-poland6','anon-cs-swe6','anon-cs-nl6'] }",
    "{ server_name='doh.ffmuc.net', via=['anon-cs-finland','anon-cs-poland','anon-cs-swe','anon-cs-nl'] }",
    "{ server_name='doh.ffmuc.net-2', via=['anon-cs-finland','anon-cs-poland','anon-cs-swe','anon-cs-nl'] }",
    "{ server_name='doh.ffmuc.net-v6', via=['anon-cs-finland6','anon-cs-poland6','anon-cs-swe6','anon-cs-nl6'] }",
    "{ server_name='doh.ffmuc.net-v6-2', via=['anon-cs-finland6','anon-cs-poland6','anon-cs-swe6','anon-cs-nl6'] }",
    "{ server_name='quad9-doh-ip4-port443-nofilter-pri', via=['anon-cs-finland','anon-cs-poland','anon-cs-swe','anon-cs-nl'] }",
    "{ server_name='quad9-doh-ip6-port443-nofilter-pri', via=['anon-cs-finland6','anon-cs-poland6','anon-cs-swe6','anon-cs-nl6'] }",
    # ── CH: доп. серверы ──────────────────────────────────────────────────
    "{ server_name='dns.digitale-gesellschaft.ch', via=['anon-cs-de','anon-cs-finland','anon-cs-poland','anon-cs-nl'] }",
    "{ server_name='dns.digitale-gesellschaft.ch-ipv6', via=['anon-cs-de6','anon-cs-finland6','anon-cs-poland6','anon-cs-nl6'] }",
    "{ server_name='dns.sb', via=['anon-cs-de','anon-cs-finland','anon-cs-poland','anon-cs-nl'] }",
    "{ server_name='dns.sb-ipv6', via=['anon-cs-de6','anon-cs-finland6','anon-cs-poland6','anon-cs-nl6'] }",
    "{ server_name='doh.ibksturm', via=['anon-cs-de','anon-cs-finland','anon-cs-poland','anon-cs-nl'] }",
    "{ server_name='ibksturm', via=['anon-cs-de','anon-cs-finland','anon-cs-poland','anon-cs-nl'] }",
    "{ server_name='switch', via=['anon-cs-de','anon-cs-finland','anon-cs-poland','anon-cs-nl'] }",
    "{ server_name='switch-ipv6', via=['anon-cs-de6','anon-cs-finland6','anon-cs-poland6','anon-cs-nl6'] }",
    "{ server_name='mullvad-doh', via=['anon-cs-de','anon-cs-finland','anon-cs-poland','anon-cs-nl'] }",
    # ── CZ: доп. серверы ──────────────────────────────────────────────────
    "{ server_name='nic.cz', via=['anon-cs-de','anon-cs-poland','anon-cs-finland','anon-cs-swe'] }",
    "{ server_name='nic.cz-ipv6', via=['anon-cs-de6','anon-cs-poland6','anon-cs-finland6','anon-cs-swe6'] }",
    # ── RS: доп. серверы ──────────────────────────────────────────────────
    "{ server_name='serbica', via=['anon-cs-de','anon-cs-poland','anon-cs-nl','anon-cs-ch'] }",
    # ── SE: доп. серверы ──────────────────────────────────────────────────
    "{ server_name='searx-se-ipv4', via=['anon-cs-finland','anon-cs-poland','anon-cs-de','anon-cs-nl'] }",
    "{ server_name='searx-se-ipv6', via=['anon-cs-finland6','anon-cs-poland6','anon-cs-de6','anon-cs-nl6'] }",
    # ── FI: доп. серверы ──────────────────────────────────────────────────
    "{ server_name='nwps.fi', via=['anon-cs-de','anon-cs-poland','anon-cs-swe','anon-cs-nl'] }",
    # ── UK: доп. серверы ──────────────────────────────────────────────────
    "{ server_name='dnsforge.uk', via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    # ══ TIER 4: НОВЫЕ ГЛОБАЛЬНЫЕ МАРШРУТЫ ═════════════════════════════════
    # ── US → DE/NL/CH/SE (трансатлантический) ─────────────────────────────
    "{ server_name='dnscry.pt-newyork-ipv4',      via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-newyork-ipv6',      via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    "{ server_name='dnscry.pt-chicago-ipv4',      via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-chicago-ipv6',      via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    "{ server_name='dnscry.pt-losangeles-ipv4',   via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-losangeles-ipv6',   via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    "{ server_name='dnscry.pt-dallas-ipv4',       via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-dallas-ipv6',       via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── CA → DE/NL/CH/SE ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-toronto-ipv4',      via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-toronto-ipv6',      via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    "{ server_name='dnscry.pt-montreal-ipv4',     via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-montreal-ipv6',     via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── AU → DE/NL/CH/SE (транстихоокеанский) ─────────────────────────────
    "{ server_name='dnscry.pt-sydney-ipv4',       via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-sydney-ipv6',       via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    "{ server_name='dnscry.pt-melbourne-ipv4',    via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-melbourne-ipv6',    via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── AE → DE/NL/CH/SE ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-dubai-ipv4',        via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-dubai-ipv6',        via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── IL → DE/NL/CH/SE ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-telaviv-ipv4',      via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-telaviv-ipv6',      via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── IN → DE/NL/CH/SE ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-mumbai-ipv4',       via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-mumbai-ipv6',       via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── BR → DE/NL/CH/SE ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-saopaulo-ipv4',     via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-saopaulo-ipv6',     via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── ZA → DE/NL/CH/SE ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-johannesburg-ipv4', via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-johannesburg-ipv6', via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── IE → DE/NL/CH/SE (не UK!) ─────────────────────────────────────────
    "{ server_name='dnscry.pt-dublin-ipv4',       via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-dublin-ipv6',       via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── AR → DE/NL/CH/SE ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-buenosaires-ipv4',  via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-buenosaires-ipv6',  via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── CL → DE/NL/CH/SE ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-santiago-ipv4',     via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-santiago-ipv6',     via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── KR → DE/NL/CH/SE ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-seoul-ipv4',        via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-seoul-ipv6',        via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── TH → DE/NL/CH/SE ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-bangkok-ipv4',      via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-bangkok-ipv6',      via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── ID → DE/NL/CH/SE ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-jakarta-ipv4',      via=['anon-cs-de','anon-cs-nl','anon-cs-ch','anon-cs-swe'] }",
    "{ server_name='dnscry.pt-jakarta-ipv6',      via=['anon-cs-de6','anon-cs-nl6','anon-cs-ch6','anon-cs-swe6'] }",
    # ── Глобальные DoH → EU relay ─────────────────────────────────────────
    "{ server_name='cloudflare',      via=['anon-cs-de','anon-cs-finland','anon-cs-poland','anon-cs-nl'] }",
    "{ server_name='cloudflare-ipv6', via=['anon-cs-de6','anon-cs-finland6','anon-cs-poland6','anon-cs-nl6'] }",
    "{ server_name='google',          via=['anon-cs-de','anon-cs-finland','anon-cs-poland','anon-cs-nl'] }",
    "{ server_name='google-ipv6',     via=['anon-cs-de6','anon-cs-finland6','anon-cs-poland6','anon-cs-nl6'] }",
    # ── WILDCARD — все серверы без явного маршрута ────────────────────────
    "{ server_name='*', via=["
    "'anon-cs-finland','anon-cs-finland6','anon-cs-poland','anon-cs-poland6',"
    "'anon-cs-de','anon-cs-de6','anon-cs-berlin','anon-cs-berlin6',"
    "'anon-cs-dus','anon-cs-dus6','anon-cs-swe','anon-cs-swe6',"
    "'anon-cs-nl','anon-cs-nl6','anon-cs-ch','anon-cs-ch6',"
    "'anon-cs-czech','anon-cs-czech6','anon-cs-serbia','anon-cs-serbia6',"
    "'anon-cs-austria','anon-cs-austria6','anon-cs-belgium','anon-cs-belgium6',"
    "'dnscry.pt-anon-helsinki-ipv4','dnscry.pt-anon-helsinki-ipv6',"
    "'dnscry.pt-anon-frankfurt-ipv4','dnscry.pt-anon-frankfurt-ipv6',"
    "'dnscry.pt-anon-gdansk-ipv4','dnscry.pt-anon-gdansk-ipv6'"
    "] }",
]

# =============================================================================
#  ПАРАМЕТРЫ БЕЗОПАСНОСТИ
# =============================================================================
_SECURITY_PARAMS: Dict[str, str] = {
    "ipv4_servers":          "true",
    "ipv6_servers":          "true",
    "dnscrypt_servers":      "true",
    "doh_servers":           "true",
    "odoh_servers":          "true",
    "require_dnssec":        "true",
    "require_nolog":         "true",
    "require_nofilter":      "true",
    "force_tcp":             "false",
    "http3":                 "true",
    "http3_probe":           "false",
    "timeout":               "3000",
    "keepalive":             "30",
    "lb_strategy":           "'p2'",
    "lb_estimator":          "true",
    "dnscrypt_ephemeral_keys":     "true",
    "tls_disable_session_tickets": "true",
    "block_ipv6":            "false",
    "block_unqualified":     "true",
    "block_undelegated":     "true",
    "reject_ttl":            "10",
    "cache":                 "true",
    "cache_size":            "16384",
    "cache_min_ttl":         "60",
    "cache_max_ttl":         "86400",
    "cache_neg_min_ttl":     "60",
    "cache_neg_max_ttl":     "600",
    "bootstrap_resolvers":   "['9.9.9.9:53', '8.8.8.8:53', '1.1.1.1:53']",
    "ignore_system_dns":     "true",
    "netprobe_timeout":      "60",
    "netprobe_address":      "'9.9.9.9:53'",
    "cert_refresh_delay":    "240",
    "cert_ignore_timestamp": "false",
    "skip_incompatible":     "true",
    "direct_cert_fallback":  "true",
    "max_clients":           "250",
}

_EXTRA_SOURCES: str = """
[sources.odoh-servers]
urls = [
  'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-servers.md',
  'https://download.dnscrypt.info/resolvers-list/v3/odoh-servers.md',
]
cache_file    = 'odoh-servers.md'
minisign_key  = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
refresh_delay = 73

[sources.odoh-relays]
urls = [
  'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-relays.md',
  'https://download.dnscrypt.info/resolvers-list/v3/odoh-relays.md',
]
cache_file    = 'odoh-relays.md'
minisign_key  = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
refresh_delay = 73

[sources.dnscry-pt-resolvers]
urls          = ['https://www.dnscry.pt/resolvers.md']
minisign_key  = 'RWQM31Nwkqh01x88SvrBL8djp1NH56Rb4mKLHz16K7qsXgEomnDv6ziQ'
cache_file    = 'dnscry.pt-resolvers.md'
refresh_delay = 73

[sources.dnscry-pt-relays]
urls          = ['https://www.dnscry.pt/anon-relays.md']
minisign_key  = 'RWQM31Nwkqh01x88SvrBL8djp1NH56Rb4mKLHz16K7qsXgEomnDv6ziQ'
cache_file    = 'dnscry.pt-relays.md'
refresh_delay = 73
"""


# =============================================================================
#  КОНФИГУРАЦИЯ
# =============================================================================
def _backup_config() -> Optional[Path]:
    if not _DNSCRYPT_CONF.exists():
        return None
    bak = _DNSCRYPT_CONF.parent / (
        _DNSCRYPT_CONF.name + "." +
        datetime.now().strftime("%Y%m%d%H%M%S") + ".bak"
    )
    shutil.copy2(_DNSCRYPT_CONF, bak)
    return bak

def _read_config() -> str:
    if not _DNSCRYPT_CONF.exists():
        return ""
    return _DNSCRYPT_CONF.read_text(errors="replace")

def _get_listen_addresses(content: str) -> str:
    m = re.search(r"^listen_addresses\s*=\s*\[.*?\]", content, re.MULTILINE)
    return m.group(0) if m else "listen_addresses = ['127.0.0.1:5300']"

def _get_current_server_names() -> List[str]:
    content = _read_config()
    m = re.search(r"^server_names\s*=\s*\[([^\]]+)\]", content, re.MULTILINE)
    if not m:
        return []
    return [s.strip().strip("'\"") for s in m.group(1).split(",") if s.strip()]

def _apply_preset(server_names: List[str],
                  security_params: Dict[str, str],
                  anon_routes: List[str],
                  extra_sources: bool = True) -> bool:
    content = _read_config()
    listen = _get_listen_addresses(content)
    names_str = ", ".join(f"'{n}'" for n in server_names)
    routes_str = ",\n  ".join(anon_routes)
    params_lines = "\n".join(f"{k} = {v}" for k, v in security_params.items())
    sources = _EXTRA_SOURCES if extra_sources else ""

    config = f"""## dnscrypt-proxy.toml — Chimera Project (advanced preset)
## Сгенерирован: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
## {len(server_names)} серверов · {len(anon_routes)} маршрутов · ODoH · DNSSEC
## 36 стран: RU, UA, EE, LV, LT, FI, PL, DE, SE, CH, NL, CZ, RS, AT, NO, IS,
## BG, DK, RO, HU, BE, LU, TR, SK, MD, FR, IT, ES, GR, SI, HR, PT, UK, JP, SG, GE

{listen}

server_names = [{names_str}]

{params_lines}

[sources]
  [sources.public-resolvers]
  urls = [
    'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md',
    'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md',
  ]
  cache_file    = 'public-resolvers.md'
  minisign_key  = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 73

  [sources.relays]
  urls = [
    'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md',
    'https://download.dnscrypt.info/resolvers-list/v3/relays.md',
  ]
  cache_file    = 'relays.md'
  minisign_key  = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 73
{sources}

[anonymized_dns]
  routes = [
  {routes_str}
  ]

[broken_implementations]
  fragments_blocked = [
  'cisco','cisco-ipv6','cisco-familyshield','cisco-familyshield-ipv6',
  'cisco-sandbox','cleanbrowsing-adult','cleanbrowsing-adult-ipv6',
  'cleanbrowsing-family','cleanbrowsing-family-ipv6',
  'cleanbrowsing-security','cleanbrowsing-security-ipv6',
  ]

[blocked_names]
[blocked_ips]
[allowed_names]
[allowed_ips]
[schedules]
[captive_portals]
[local_doh]
"""
    try:
        _DNSCRYPT_CONF.write_text(config)
        return True
    except Exception as e:
        _err(f"Не удалось записать конфиг: {e}")
        return False

def _restart_dnscrypt() -> bool:
    _info("Перезапускаю dnscrypt-proxy...")
    _run(["systemctl", "restart", "dnscrypt-proxy"], quiet=True)
    time.sleep(3)
    r = _run(["systemctl", "is-active", "dnscrypt-proxy"], capture=True, check=False)
    if r.returncode == 0 and r.stdout.strip() == "active":
        return True
    _warn("dnscrypt-proxy не запустился — проверьте journalctl -u dnscrypt-proxy")
    return False


# =============================================================================
#  RTT-замер
# =============================================================================
def _measure_rtt(server_names: List[str]) -> Dict[str, float]:
    import socket
    from concurrent.futures import ThreadPoolExecutor, as_completed
    try:
        from chimera.modules.dnscrypt_selector import _parse_resolver_ips_from_md
        stamp_ips = _parse_resolver_ips_from_md()
    except Exception:
        stamp_ips = {}

    def _ping(name: str) -> Tuple[str, float]:
        entry = stamp_ips.get(name)
        if not entry:
            return name, 9999.0
        ip, ports = entry
        try:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            for p in ports:
                try:
                    start = time.monotonic()
                    with socket.socket(family, socket.SOCK_STREAM) as s:
                        s.settimeout(2.0)
                        s.connect((ip, p))
                    return name, round((time.monotonic() - start) * 1000, 1)
                except Exception:
                    continue
        except Exception:
            pass
        return name, 9999.0

    results: Dict[str, float] = {}
    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(_ping, n): n for n in server_names}
        for future in as_completed(futures):
            name, ms = future.result()
            results[name] = ms
    return results


# =============================================================================
#  TUI
# =============================================================================
def _screen_preset() -> None:
    os.system("clear")
    print()
    _box_top("🛡️  ПРЕСЕТ: 154 СЕРВЕРА, 36 СТРАН, АНОНИМИЗАЦИЯ")
    _box_row()
    _box_row(f"  {BOLD}Серверы:{NC} {len(_SERVER_NAMES)} шт. (36 стран, EU+RU+Asia)")
    _box_row(f"  {BOLD}Маршруты:{NC} {len(_ANON_ROUTES)} анонимизированных")
    _box_row(f"  {BOLD}Протоколы:{NC} DNSCrypt + DoH + ODoH")
    _box_row(f"  {BOLD}Безопасность:{NC} DNSSEC + nolog + nofilter")
    _box_row(f"  {BOLD}Эфемерные ключи:{NC} да")
    _box_row(f"  {BOLD}HTTP/3:{NC} да")
    _box_row(f"  {BOLD}Анонимизация:{NC} server → relay в другой стране")
    _box_row()
    _box_row(f"  {DIM}Yandex DNS ИСКЛЮЧЁН (утечка).{NC}")
    _box_row(f"  {DIM}RU-серверы (dnscry.pt-moscow) — через EU relay.{NC}")
    _box_row(f"  {DIM}Новые: UA, TR, SK, MD, FR, IT, ES, GR, SI, HR, PT, UK, JP, SG, GE{NC}")
    _box_row()
    _box_warn("Бэкап конфига будет создан перед изменением.")
    _box_row(f"  {GREEN}НЕ трогает: resolv.conf, nsswitch, интерфейсы, SSH.{NC}")
    _box_bottom()
    print()
    try:
        confirm = input(f"{CYAN}Применить пресет? [Y/n]: {NC}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        confirm = "n"
    if confirm not in ("", "y", "yes", "д", "да"):
        return
    bak = _backup_config()
    if bak:
        _ok(f"Бэкап: {bak}")
    _info(f"Записываю конфиг ({len(_SERVER_NAMES)} серверов, {len(_ANON_ROUTES)} маршрутов)...")
    if _apply_preset(_SERVER_NAMES, _SECURITY_PARAMS, _ANON_ROUTES, extra_sources=True):
        _ok("Конфиг записан")
        if _restart_dnscrypt():
            _ok("DNSCrypt-proxy перезапущен с расширенным конфигом")
            _info("Новые источники (dnscry.pt, odoh) будут скачаны при первом запуске (~30 сек)")
        else:
            _warn("Сервис не поднялся — проверьте journalctl -u dnscrypt-proxy")
    else:
        _err("Не удалось записать конфиг")
    print()
    input(f"{BLUE}Нажмите Enter...{NC}")


def _screen_rtt_select() -> None:
    if not _DNSCRYPT_BIN.exists():
        _warn("DNSCrypt-proxy не установлен")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return
    os.system("clear")
    print()
    _box_top("⚡  RTT-ЗАМЕР СЕРВЕРОВ")
    _box_desc(
        "Замеряет реальную TCP latency до каждого сервера из пресетного "
        "списка. Выберите 2-5 ближайших — они будут прописаны в server_names."
    )
    _box_bottom()
    print()
    current = _get_current_server_names()
    if current:
        _info(f"Текущие server_names: {len(current)} шт.")
    print()
    _info(f"Замеряю RTT для {len(_SERVER_NAMES)} серверов (параллельно, ~15-30 сек)...")
    print()
    rtt_map = _measure_rtt(_SERVER_NAMES)
    reachable = sorted(
        [(n, rtt_map[n]) for n in _SERVER_NAMES if rtt_map.get(n, 9999) < 9999],
        key=lambda x: x[1]
    )
    unreachable = [(n, 9999.0) for n in _SERVER_NAMES if rtt_map.get(n, 9999) >= 9999]
    all_sorted = reachable + unreachable
    _box_top("РЕЗУЛЬТАТ RTT-ЗАМЕРА")
    _box_row(f"  {GREEN}Доступны:{NC} {len(reachable)} серверов")
    _box_row(f"  {RED}Недоступны:{NC} {len(unreachable)} серверов")
    _box_sep()
    show = min(40, len(all_sorted))
    for i in range(show):
        name, ms = all_sorted[i]
        is_current = name in current
        marker = f" {GREEN}← текущий{NC}" if is_current else ""
        if ms < 9999:
            col = GREEN if ms < 50 else YELLOW if ms < 150 else RED
            _box_row(f"  {WHITE}{i+1:>3}.{NC}  {CYAN}{name:<40}{NC}  {col}{ms:.0f} мс{NC}{marker}")
        else:
            _box_row(f"  {DIM}{i+1:>3}.  {name:<40}  недоступен{NC}{marker}")
    if len(all_sorted) > show:
        _box_row(f"  {DIM}... и ещё {len(all_sorted) - show} серверов{NC}")
    _box_bottom()
    print()
    try:
        raw = input(f"{CYAN}Введите номера через запятую (например: 1,3,7) или Q:{NC} ").strip()
    except KeyboardInterrupt:
        return
    if not raw or raw.lower() == "q":
        return
    chosen: List[str] = []
    errors: List[str] = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit():
            idx = int(part)
            if 1 <= idx <= len(all_sorted):
                name = all_sorted[idx - 1][0]
                if name not in chosen:
                    chosen.append(name)
            else:
                errors.append(f"{part} (нет такого номера)")
        elif part in _SERVER_NAMES and part not in chosen:
            chosen.append(part)
        else:
            errors.append(f"'{part}'")
    if errors:
        _warn(f"Пропущены: {', '.join(errors)}")
    if not chosen:
        _warn("Ни одного сервера не выбрано")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return
    print()
    _info(f"Выбрано {len(chosen)} серверов:")
    for n in chosen:
        print(f"  {GREEN}•{NC} {n}")
    print()
    try:
        confirm = input(f"{CYAN}Применить? [Y/n]: {NC}").strip().lower()
    except KeyboardInterrupt:
        return
    if confirm not in ("", "y", "yes", "д", "да"):
        return
    bak = _backup_config()
    if bak:
        _ok(f"Бэкап: {bak}")
    if _apply_preset(chosen, _SECURITY_PARAMS, _ANON_ROUTES, extra_sources=True):
        _ok("Конфиг записан")
        if _restart_dnscrypt():
            _ok(f"DNSCrypt-proxy перезапущен ({len(chosen)} серверов)")
    print()
    input(f"{BLUE}Нажмите Enter...{NC}")


def _screen_manual_params() -> None:
    os.system("clear")
    print()
    _box_top("⚙️  РУЧНАЯ НАСТРОЙКА ПАРАМЕТРОВ")
    _box_desc(
        "Текущие значения параметров DNSCrypt-proxy. "
        "Введите 'preset' для применения всех параметров из пресета, "
        "или key=value для изменения одного параметра."
    )
    _box_sep()
    content = _read_config()
    params_to_edit = [
        ("require_dnssec",        "DNSSEC (проверка подлинности)"),
        ("require_nolog",         "No-log (без логирования запросов)"),
        ("require_nofilter",      "No-filter (без блокировок)"),
        ("dnscrypt_servers",      "DNSCrypt-протокол"),
        ("doh_servers",           "DoH (DNS-over-HTTPS)"),
        ("odoh_servers",          "ODoH (Oblivious DoH)"),
        ("dnscrypt_ephemeral_keys", "Эфемерные ключи DNSCrypt"),
        ("tls_disable_session_tickets", "Отключить TLS session tickets"),
        ("block_unqualified",    "Блокировать unqualified запросы"),
        ("block_undelegated",    "Блокировать undelegated зоны"),
        ("http3",                "HTTP/3 (QUIC)"),
        ("force_tcp",            "Принудительный TCP (false=UDP)"),
        ("cache",                "Кеширование DNS"),
        ("cache_size",           "Размер кеша (записей)"),
        ("cache_min_ttl",        "Минимальный TTL (сек)"),
        ("cache_max_ttl",        "Максимальный TTL (сек)"),
        ("timeout",              "Таймаут запроса (мс)"),
        ("lb_strategy",          "Стратегия балансировки"),
        ("max_clients",          "Макс. клиентов"),
    ]
    for key, label in params_to_edit:
        m = re.search(rf'^{key}\s*=\s*(.+)$', content, re.MULTILINE)
        current_val = m.group(1).strip() if m else "?"
        _box_row(f"  {BOLD}{label}{NC}")
        _box_row(f"    {DIM}{key} = {current_val}{NC}")
    _box_bottom()
    print()
    _info("Введите 'preset' для всех параметров пресета, или key=value, или Enter для выхода")
    print()
    try:
        raw = input(f"{CYAN}Ввод:{NC} ").strip()
    except KeyboardInterrupt:
        return
    if not raw:
        return
    if raw.lower() == "preset":
        bak = _backup_config()
        if bak:
            _ok(f"Бэкап: {bak}")
        if _apply_preset(_SERVER_NAMES, _SECURITY_PARAMS, _ANON_ROUTES, extra_sources=True):
            _ok("Параметры пресета применены")
            _restart_dnscrypt()
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return
    m = re.match(r'^(\w+)\s*=\s*(.+)$', raw)
    if not m:
        _warn("Формат: key=value (например: require_dnssec=true)")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return
    key, value = m.group(1), m.group(2).strip()
    if key not in _SECURITY_PARAMS and key not in ("server_names", "listen_addresses"):
        _warn(f"Неизвестный параметр: {key}")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return
    bak = _backup_config()
    if bak:
        _ok(f"Бэкап: {bak}")
    content = _read_config()
    if re.search(rf'^{key}\s*=', content, re.MULTILINE):
        content = re.sub(rf'^{key}\s*=\s*.+', f'{key} = {value}', content, flags=re.MULTILINE)
    else:
        content += f"\n{key} = {value}\n"
    try:
        _DNSCRYPT_CONF.write_text(content)
        _ok(f"{key} = {value}")
        _restart_dnscrypt()
    except Exception as e:
        _err(f"Ошибка: {e}")
    print()
    input(f"{BLUE}Нажмите Enter...{NC}")


def _screen_status() -> None:
    os.system("clear")
    print()
    _box_top("📊  СТАТУС DNSCRYPT-PROXY")
    r = _run(["systemctl", "is-active", "dnscrypt-proxy"], capture=True, check=False)
    svc = f"{GREEN}active{NC}" if r.returncode == 0 else f"{RED}не активен{NC}"
    _box_row(f"  Сервис:          {svc}")
    content = _read_config()
    if not content:
        _box_row(f"  Конфиг:          {RED}не найден{NC}")
        _box_bottom()
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return
    listen = _get_listen_addresses(content)
    _box_row(f"  Listen:          {CYAN}{listen}{NC}")
    names = _get_current_server_names()
    _box_row(f"  Серверов:        {CYAN}{len(names)}{NC}")
    if names:
        _box_row(f"  Текущие:         {DIM}{', '.join(names[:5])}{'...' if len(names)>5 else ''}{NC}")
    _box_sep()
    params = [
        ("require_dnssec",        "DNSSEC"),
        ("require_nolog",         "No-log"),
        ("require_nofilter",      "No-filter"),
        ("doh_servers",           "DoH"),
        ("odoh_servers",          "ODoH"),
        ("dnscrypt_ephemeral_keys", "Эфемерные ключи"),
        ("tls_disable_session_tickets", "No session tickets"),
        ("block_unqualified",    "Block unqualified"),
        ("block_undelegated",    "Block undelegated"),
        ("http3",                "HTTP/3"),
        ("cache",                "Cache"),
    ]
    for key, label in params:
        m = re.search(rf'^{key}\s*=\s*(.+)$', content, re.MULTILINE)
        val = m.group(1).strip().lower() if m else "?"
        col = GREEN if val in ("true", "1") else RED if val in ("false", "0") else DIM
        _box_row(f"  {label:<25} {col}{val}{NC}")
    _box_sep()
    has_anon = "[anonymized_dns]" in content
    route_count = content.count("server_name=")
    if has_anon:
        _box_row(f"  Анонимизация:    {GREEN}активна{NC} ({route_count} маршрутов)")
    else:
        _box_row(f"  Анонимизация:    {DIM}не настроена{NC}")
    sources = []
    if "dnscry-pt-resolvers" in content:
        sources.append("dnscry.pt")
    if "odoh-servers" in content:
        sources.append("ODoH")
    if sources:
        _box_row(f"  Источники:       {CYAN}{', '.join(sources)}{NC}")
    else:
        _box_row(f"  Источники:       {DIM}только public-resolvers{NC}")
    _box_bottom()
    input(f"\n{BLUE}Нажмите Enter...{NC}")


# =============================================================================
#  Главное меню
# =============================================================================
def do_dnscrypt_advanced_menu() -> None:
    """Интерактивное меню расширенной настройки DNSCrypt-proxy.

    БЕЗОПАСНО: не трогает resolv.conf, nsswitch, интерфейсы, SSH.
    """
    while True:
        os.system("clear")
        print()
        _box_top("🛡️  РАСШИРЕННАЯ НАСТРОЙКА DNSCRYPT-PROXY")
        _box_desc(
            "154 сервера в 36 странах. ODoH, DNSSEC, анонимизация. "
            "RTT-замер реальной latency. Ручная настройка параметров. "
            "НЕ трогает resolv.conf / nsswitch / интерфейсы."
        )
        _box_sep()
        names = _get_current_server_names()
        content = _read_config()
        has_odoh = "odoh_servers = true" in content
        has_dnssec = "require_dnssec = true" in content
        has_anon = "[anonymized_dns]" in content
        _box_row(f"  Серверов: {CYAN}{len(names)}{NC}  "
                 f"ODoH: {'✓' if has_odoh else '✗'}  "
                 f"DNSSEC: {'✓' if has_dnssec else '✗'}  "
                 f"Анонимизация: {'✓' if has_anon else '✗'}")
        _box_sep()
        _box_item("1", f"{GREEN}Применить пресет (154 сервера, 36 стран){NC}")
        _box_item("2", f"{CYAN}RTT-замер и выбор серверов{NC}  (реальная latency)")
        _box_item("3", f"{YELLOW}Ручная настройка параметров{NC}  (DNSSEC, ODoH, cache...)")
        _box_item("4", "📊  Статус конфигурации")
        _box_item("Q", f"{DIM}← Назад{NC}")
        _box_bottom()
        print()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        if ch == "1":
            _screen_preset()
        elif ch == "2":
            _screen_rtt_select()
        elif ch == "3":
            _screen_manual_params()
        elif ch == "4":
            _screen_status()
        elif ch in ("q", "0", ""):
            return
        else:
            _warn("Неверный выбор")
            time.sleep(1)


__all__ = [
    "do_dnscrypt_advanced_menu",
    "_SERVER_NAMES",
    "_ANON_ROUTES",
    "_SECURITY_PARAMS",
]
