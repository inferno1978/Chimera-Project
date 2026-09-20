"""
chimera/modules/dnscrypt_advanced.py
───────────────────────────────────────────────────────────────────────────────
Расширенная настройка DNSCrypt-proxy: 245 серверов в 51 стране, ODoH, DNSSEC,
180 анонимизированных маршрутов, RTT-замер, ручная настройка параметров.

 (динамический пул + версионная гигиена):
  • Пул синхронизирован с живым v3/public-resolvers.md: −37 мёртвых имён
    (кладбище _POOL_GRAVEYARD — воскрешаются pool-sync'ом автоматически),
    +90 живых серверов (замены выродившихся стран + UK/IE + глобальный блок).
    Итог: 245 серверов, 51 страна, 129 IPv4 / 116 IPv6, 221 через релеи,
    24 DoH-напрямую (протокол не анонимизируется).
  • ИСТОЧНИКИ dnscry.pt УДАЛЕНЫ: единственный URL за антиботом без failover
    ронял старт FATAL'ом «Invalid encoded signature» при пустом кеше;
    контент на 100% избыточен (все dnscry.pt-серверы и релеи — в официальных
    public-resolvers.md/relays.md). Официальные источники усилены третьим
    зеркалом cdn.jsdelivr.net (RF-резистентность).
  • http3_probe УДАЛЁН из параметров: в dnscrypt-proxy 2.1.5 ключа нет —
    [FATAL] Unsupported key, конфиг не стартовал вовсе; в 2.1.18 ключ
    существует, но default false — запись избыточна.
  • refresh_delay 73→25 ч (2.1.18 кламп [25..169], фоновая перекачка чаще).
  • Проверка цепочки xray → AGH(:53) → dnscrypt(:5300) ПОСЛЕ применения
    (chimera/modules/dnscrypt_update.py::check_dns_chain) + запись state
    /var/lib/chimera/dnscrypt-state.json (шапки меню — из него).
  • Аварийный фолбэк: если откат тоже не поднял резолвинг — экстренный конфиг
    quad9-dnscrypt (известно-живые имена официального источника), сервер
    без DNS не остаётся (AGH fallback_dns 9.9.9.9/149.112.112.112 страхует
    и поверх).
  • Авто-синк пула каждые 6 ч + авто-обновление бинарника — меню «DU»
    (do_dnscrypt_update_menu, единое для всех DNS-меню — синхронизировано
    через state-файл).

 Гео-резистентность (синхрон с dnscrypt_setup):
  • dnscry.pt-moscow ИСКЛЮЧЁН: RU-юрисдикция/хостер — риск отравления
    рекурсии (голова списка = де-факто основной резолвер в lb_strategy p2);
    список теперь начинается с kyiv.
  • Хвост cloudflare/google удалён: DoH CF/GG из РФ душится ТСПУ
    (мёртвый груз); за рубежом пул и так богат DoH-серверами.
  • bootstrap/fallback → 9.9.9.9 + 77.88.8.8 (канон).
  • Фаза-1 пресета — quad9-dnscrypt (DNSCrypt-протокол, порт 8443,
    без SNI — жив и из РФ, и из-за рубежа).
  • resolv.conf на время применения временно указывает на 9.9.9.9/77.88.8.8
    и ВОССТАНАВЛИВАЕТСЯ гарантированно (try/finally — раньше Ctrl+C посреди
    фазы оставлял систему на временном DNS).

БЕЗОПАСНОСТЬ:
  • НЕ вызывает networkctl / ifconfig / ip link / dhclient.
  • НЕ трогает /etc/nsswitch.conf, сетевые интерфейсы. resolv.conf — только
    временная подмена на живые 9.9.9.9/77.88.8.8 с гарантированным
     восстановлением (try/finally).
  • Только перезаписывает /etc/dnscrypt-proxy/dnscrypt-proxy.toml + restart сервиса.
  • Бэкап конфига перед изменением + откат при провале + экстренный конфиг
    quad9-dnscrypt — сервер без DNS не остаётся.
  • Проверка цепочки xray→AGH→dnscrypt после применения.

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

def _run(cmd, capture=False, quiet=False, check=False):
    kw = {}
    if capture: kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet: kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def _info(msg):  print(f"{CYAN}[INFO]{NC}  {msg}")
def _ok(msg):    print(f"{GREEN}[OK]{NC}    {msg}")
def _warn(msg):  print(f"{YELLOW}[WARN]{NC}  {msg}")
def _err(msg):   print(f"{RED}[ERR]{NC}   {msg}")

# =============================================================================
# ПОЛНЫЙ СПИСОК СЕРВЕРОВ — 245 шт., 51 страна
# синхронизирован с живым public-resolvers.md (drift-резистентность):
# − 37 мёртвых имён (budapest/brussels/athens/Tier-4-хвост) → кладбище
#    + 90 живых: замены выродившихся стран (AL/GR/HU/FR/LU/IT/ES/NO/RO/MD/DK/AT/
#      SE/DE/UA/PT), UK-восстановление, IE, вторые города (kyiv02/lisbon02/
#      dusseldorf02-03/stockholm02-уже-были), глобальный блок (HK×3, JP, KR,
#      SG, TW, IN, AU, NZ, CA, BD, NG, PK, LA, CL) — все DNSCrypt, живые.
# Yandex ИСКЛЮЧЁН (утечка DNS). dnscry.pt-moscow ИСКЛЮЧЁН (RU-юрисдикция,
#  риск hoster-level отравления рекурсии; голова списка — kyiv). Хвост
# cloudflare/google удалён (из РФ DoH CF/GG душатся ТСПУ).
#  Динамический синк: cron каждые 6 ч (chimera/modules/dnscrypt_update.py,
#  /usr/local/bin/chimera-dnscrypt-pool-sync.py) — пул ∩ живой список,
#  воскрешения из кладбища, ребилд маршрутов по живым релеям.
# =============================================================================
_SERVER_NAMES: List[str] = [
    # ── UA (4) — Украина ────────────────────────────────────────
    "dnscry.pt-kyiv-ipv4", "dnscry.pt-kyiv-ipv6",
    "dnscry.pt-kyiv02-ipv4", "dnscry.pt-kyiv02-ipv6",
    # ── EE (2) — Эстония ────────────────────────────────────────
    "dnscry.pt-tallinn-ipv4", "dnscry.pt-tallinn-ipv6",
    # ── LV (2) — Латвия ────────────────────────────────────────
    "dnscry.pt-riga-ipv4", "dnscry.pt-riga-ipv6",
    # ── LT (2) — Литва ────────────────────────────────────────
    "dnscry.pt-vilnius-ipv4", "dnscry.pt-vilnius-ipv6",
    # ── FI (7) — Финляндия ────────────────────────────────────────
    "cs-finland", "cs-finland6",
    "dnscry.pt-helsinki-ipv4", "dnscry.pt-helsinki-ipv6",
    "dnscry.pt-tuusula-ipv4", "dnscry.pt-tuusula-ipv6",
    "nwps.fi",
    # ── PL (6) — Польша ────────────────────────────────────────
    "cs-poland", "cs-poland6",
    "dnscry.pt-gdansk-ipv4", "dnscry.pt-gdansk-ipv6",
    "dnscry.pt-warsaw-ipv4", "dnscry.pt-warsaw-ipv6",
    # ── DE (34) — Германия ────────────────────────────────────────
    "cs-de", "cs-de6",
    "cs-berlin", "cs-berlin6",
    "cs-dus", "cs-dus6",
    "dns.digitalsize.net", "dns.digitalsize.net-ipv6",
    "dnscry.pt-dusseldorf-ipv4", "dnscry.pt-dusseldorf-ipv6",
    "dnscry.pt-dusseldorf02-ipv6", "dnscry.pt-dusseldorf03-ipv6",
    "dnscry.pt-frankfurt-ipv4", "dnscry.pt-frankfurt-ipv6",
    "dnscry.pt-frankfurt02-ipv4", "dnscry.pt-frankfurt02-ipv6",
    "dnscry.pt-jena-ipv4", "dnscry.pt-jena-ipv6",
    "dnscry.pt-munich-ipv4", "dnscry.pt-munich-ipv6",
    "dnscry.pt-nuremberg-ipv4", "dnscry.pt-nuremberg-ipv6",
    "dnsforge.de-nofilter", "dnsforge.de-nofilter-ipv6",
    "doh.ffmuc.net", "doh.ffmuc.net-v6",
    "quad9-dnscrypt-ip4-nofilter-pri", "quad9-dnscrypt-ip6-nofilter-pri",
    "quad9-doh-ip4-port443-nofilter-pri", "quad9-doh-ip6-port443-nofilter-pri",
    "dnscry.pt-dusseldorf02-ipv4", "dnscry.pt-dusseldorf03-ipv4",
    "dnscry.pt-bremen-ipv4", "dnscry.pt-bremen-ipv6",
    # ── SE (11) — Швеция ────────────────────────────────────────
    "cs-swe", "cs-swe6",
    "dnscry.pt-hudiksvall-ipv4", "dnscry.pt-hudiksvall-ipv6",
    "dnscry.pt-stockholm-ipv4", "dnscry.pt-stockholm-ipv6",
    "dnscry.pt-stockholm02-ipv4", "dnscry.pt-stockholm02-ipv6",
    "searx-se-ipv4", "searx-se-ipv6",
    "njalla-doh",
    # ── CH (16) — Швейцария ────────────────────────────────────────
    "cs-ch", "cs-ch6",
    "dns.digitale-gesellschaft.ch", "dns.digitale-gesellschaft.ch-ipv6",
    "dns.sb", "dnscry.pt-geneva-ipv4",
    "dnscry.pt-geneva-ipv6", "dnscry.pt-molln-ipv4",
    "dnscry.pt-molln-ipv6", "dnscry.pt-zurich-ipv4",
    "dnscry.pt-zurich-ipv6", "doh.ibksturm",
    "ibksturm", "switch",
    "switch-ipv6", "mullvad-doh",
    # ── NL (13) — Нидерланды ────────────────────────────────────────
    "cs-nl", "cs-nl6",
    "dnscry.pt-amsterdam-ipv4", "dnscry.pt-amsterdam-ipv6",
    "dnscry.pt-amsterdam02-ipv4", "dnscry.pt-amsterdam02-ipv6",
    "dnscry.pt-amsterdam03-ipv4", "dnscry.pt-amsterdam03-ipv6",
    "dnscry.pt-eygelshoven-ipv4", "dnscry.pt-eygelshoven-ipv6",
    "dnscry.pt-ebenecity02-ipv4", "dnscry.pt-ebenecity02-ipv6",
    "dnscry.pt-naaldwijk-ipv4",
    # ── CZ (6) — Чехия ────────────────────────────────────────
    "cs-czech", "cs-czech6",
    "dnscry.pt-prague-ipv4", "dnscry.pt-prague-ipv6",
    "nic.cz", "nic.cz-ipv6",
    # ── RS (3) — Сербия ────────────────────────────────────────
    "cs-serbia", "cs-serbia6",
    "serbica",
    # ── AT (5) — Австрия ────────────────────────────────────────
    "cs-austria", "cs-austria6",
    "dnscry.pt-vienna-ipv4", "dnscry.pt-vienna-ipv6",
    "doh.appliedprivacy.net",
    # ── NO (4) — Норвегия ────────────────────────────────────────
    "dnscry.pt-sandefjord-ipv4", "dnscry.pt-sandefjord-ipv6",
    "cs-norway", "cs-norway6",
    # ── IS (2) — Исландия ────────────────────────────────────────
    "dnscry.pt-hafnarfjordur-ipv4", "dnscry.pt-hafnarfjordur-ipv6",
    # ── BG (2) — Болгария ────────────────────────────────────────
    "dnscry.pt-sofia-ipv4", "dnscry.pt-sofia-ipv6",
    # ── DK (3) — Дания ────────────────────────────────────────
    "dnscry.pt-copenhagen-ipv4", "dnscry.pt-copenhagen-ipv6",
    "uncensoreddns-dk-ipv6",
    # ── RO (7) — Румыния ────────────────────────────────────────
    "dnscry.pt-bucharest-ipv4", "dnscry.pt-bucharest-ipv6",
    "dnscry.pt-oradea-ipv4", "dnscry.pt-oradea-ipv6",
    "dnscry.pt-timisoara-ipv4", "dnscry.pt-timisoara-ipv6",
    "cs-ro",
    # ── HU (1) — Венгрия ────────────────────────────────────────
    "cs-hungary",
    # ── BE (2) — Бельгия ────────────────────────────────────────
    "cs-belgium", "cs-belgium6",
    # ── LU (2) — Люксембург ────────────────────────────────────────
    "circl-doh", "circl-doh-ipv6",
    # ── TR (2) — Турция ────────────────────────────────────────
    "dnscry.pt-istanbul-ipv4", "dnscry.pt-istanbul-ipv6",
    # ── SK (2) — Словакия ────────────────────────────────────────
    "dnscry.pt-bratislava-ipv4", "dnscry.pt-bratislava-ipv6",
    # ── MD (4) — Молдова ────────────────────────────────────────
    "dnscry.pt-chisinau-ipv4", "dnscry.pt-chisinau-ipv6",
    "cs-md", "cs-md6",
    # ── FR (6) — Франция ────────────────────────────────────────
    "dnscry.pt-paris-ipv4", "dnscry.pt-paris-ipv6",
    "cs-fr", "cs-fr6",
    "dnscry.pt-marseille-ipv4", "dnscry.pt-marseille-ipv6",
    # ── IT (3) — Италия ────────────────────────────────────────
    "dnscry.pt-milan-ipv4", "cs-milan",
    "cs-milan6",
    # ── ES (4) — Испания ────────────────────────────────────────
    "dnscry.pt-madrid-ipv4", "dnscry.pt-madrid-ipv6",
    "cs-barcelona", "cs-barcelona6",
    # ── GR (2) — Греция ────────────────────────────────────────
    "dnscry.pt-thessaloniki-ipv4", "dnscry.pt-thessaloniki-ipv6",
    # ── PT (4) — Португалия ────────────────────────────────────────
    "dnscry.pt-lisbon-ipv4", "dnscry.pt-lisbon-ipv6",
    "dnscry.pt-lisbon02-ipv4", "dnscry.pt-lisbon02-ipv6",
    # ── UK (10) — Британия ────────────────────────────────────────
    "dnscry.pt-london-ipv4", "dnscry.pt-london-ipv6",
    "cs-london", "cs-manchester",
    "dnscry.pt-coventry-ipv4", "dnscry.pt-coventry-ipv6",
    "dnscry.pt-newcastle-ipv4", "dnscry.pt-newcastle-ipv6",
    "dnscry.pt-redditch-ipv4", "dnscry.pt-redditch-ipv6",
    # ── JP (4) — Япония ────────────────────────────────────────
    "dnscry.pt-tokyo-ipv4", "dnscry.pt-tokyo-ipv6",
    "dnscry.pt-tokyo02-ipv4", "dnscry.pt-tokyo02-ipv6",
    # ── SG (4) — Сингапур ────────────────────────────────────────
    "dnscry.pt-singapore-ipv4", "dnscry.pt-singapore-ipv6",
    "dnscry.pt-singapore02-ipv4", "dnscry.pt-singapore02-ipv6",
    # ── GE (2) — Грузия ────────────────────────────────────────
    "dnscry.pt-tbilisi-ipv4", "dnscry.pt-tbilisi-ipv6",
    # ── US (8) — США ────────────────────────────────────────
    "dnscry.pt-newyork-ipv4", "dnscry.pt-newyork-ipv6",
    "dnscry.pt-chicago-ipv4", "dnscry.pt-chicago-ipv6",
    "dnscry.pt-losangeles-ipv4", "dnscry.pt-losangeles-ipv6",
    "dnscry.pt-dallas-ipv4", "dnscry.pt-dallas-ipv6",
    # ── CA (10) — Канада ────────────────────────────────────────
    "dnscry.pt-toronto-ipv4", "dnscry.pt-toronto-ipv6",
    "dnscry.pt-montreal-ipv4", "dnscry.pt-montreal-ipv6",
    "dnscry.pt-toronto02-ipv4", "dnscry.pt-toronto02-ipv6",
    "dnscry.pt-vancouver-ipv4", "dnscry.pt-vancouver-ipv6",
    "dnscry.pt-calgary-ipv4", "dnscry.pt-calgary-ipv6",
    # ── AU (8) — Австралия ────────────────────────────────────────
    "dnscry.pt-melbourne-ipv4", "dnscry.pt-melbourne-ipv6",
    "dnscry.pt-sydney02-ipv4", "dnscry.pt-sydney02-ipv6",
    "dnscry.pt-brisbane-ipv4", "dnscry.pt-brisbane-ipv6",
    "dnscry.pt-perth-ipv4", "dnscry.pt-perth-ipv6",
    # ── IN (4) — Индия ────────────────────────────────────────
    "dnscry.pt-mumbai02-ipv4", "dnscry.pt-mumbai02-ipv6",
    "dnscry.pt-bengaluru-ipv4", "dnscry.pt-bengaluru-ipv6",
    # ── ZA (2) — ЮАР ────────────────────────────────────────
    "dnscry.pt-johannesburg-ipv4", "dnscry.pt-johannesburg-ipv6",
    # ── IE (4) — Ирландия ────────────────────────────────────────
    "dnscry.pt-dublin-ipv4", "dnscry.pt-dublin-ipv6",
    "dnscry.pt-doh-dublin-ipv4", "dnscry.pt-doh-dublin-ipv6",
    # ── CL (2) — Чили ────────────────────────────────────────
    "dnscry.pt-valdivia-ipv4", "dnscry.pt-valdivia-ipv6",
    # ── KR (2) — Корея ────────────────────────────────────────
    "dnscry.pt-seoul02-ipv4", "dnscry.pt-seoul02-ipv6",
    # ── TH (2) — Тайланд ────────────────────────────────────────
    "dnscry.pt-bangkok-ipv4", "dnscry.pt-bangkok-ipv6",
    # ── ID (2) — Индонезия ────────────────────────────────────────
    "dnscry.pt-jakarta-ipv4", "dnscry.pt-jakarta-ipv6",
    # ── AL (2) — Албания ────────────────────────────────────────
    "dnscry.pt-tirana-ipv4", "dnscry.pt-tirana-ipv6",
    # ── HK (6) — Гонконг ────────────────────────────────────────
    "dnscry.pt-hongkong-ipv4", "dnscry.pt-hongkong-ipv6",
    "dnscry.pt-hongkong02-ipv4", "dnscry.pt-hongkong02-ipv6",
    "dnscry.pt-hongkong03-ipv4", "dnscry.pt-hongkong03-ipv6",
    # ── NZ (2) — Новая Зеландия ────────────────────────────────────────
    "dnscry.pt-auckland-ipv4", "dnscry.pt-auckland-ipv6",
    # ── TW (2) — Тайвань ────────────────────────────────────────
    "dnscry.pt-taipeh-ipv4", "dnscry.pt-taipeh-ipv6",
    # ── BD (2) — Бангладеш ────────────────────────────────────────
    "dnscry.pt-dhaka-ipv4", "dnscry.pt-dhaka-ipv6",
    # ── NG (2) — Нигерия ────────────────────────────────────────
    "dnscry.pt-ikeja-ipv4", "dnscry.pt-ikeja-ipv6",
    # ── PK (2) — Пакистан ────────────────────────────────────────
    "dnscry.pt-islamabad-ipv4", "dnscry.pt-islamabad-ipv6",
    # ── LA (2) — Лаос ────────────────────────────────────────
    "dnscry.pt-vientiane-ipv4", "dnscry.pt-vientiane-ipv6",
]

# =============================================================================
# АНОНИМИЗИРОВАННЫЕ МАРШРУТЫ — 193 + wildcard (194 всего)
#  Принцип: server в стране X → relay в стране Y (≠ X, не сосед)
#  Relay видит IP клиента, не видит запрос.
#  Server видит запрос, не знает IP клиента (видит relay).
# =============================================================================
_ANON_ROUTES: List[str] = [
    # 37 мёртвых имён удалено (кладбище — _POOL_GRAVEYARD),
    # 61 живой добавлен; мёртвые релеи заменены (anon-cs-ch6→belgium6,
    # anon-cs-swe6→austria6); DoH-серверы из маршрутов исключены
    # (не анонимизируются — ERROR «cannot be anonymized» в логах).
    # ── UA ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-kyiv-ipv4', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-de', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-kyiv-ipv6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-de6', 'anon-cs-austria6'] }",
    "{ server_name='dnscry.pt-kyiv02-ipv4', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-de', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-kyiv02-ipv6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-de6', 'anon-cs-austria6'] }",
    # ── EE ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-tallinn-ipv4', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-de', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-tallinn-ipv6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-de6', 'anon-cs-austria6'] }",
    # ── LV ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-riga-ipv4', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-de', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-riga-ipv6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-de6', 'anon-cs-austria6'] }",
    # ── LT ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-vilnius-ipv4', via=['anon-cs-poland', 'anon-cs-finland', 'anon-cs-de', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-vilnius-ipv6', via=['anon-cs-poland6', 'anon-cs-finland6', 'anon-cs-de6', 'anon-cs-austria6'] }",
    # ── FI ── ──────────────────────────────────────────────────
    "{ server_name='cs-finland', via=['anon-cs-de', 'anon-cs-poland', 'anon-cs-swe', 'anon-cs-nl'] }",
    "{ server_name='cs-finland6', via=['anon-cs-de6', 'anon-cs-poland6', 'anon-cs-austria6', 'anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-helsinki-ipv4', via=['anon-cs-de', 'anon-cs-poland', 'anon-cs-swe', 'anon-cs-nl'] }",
    "{ server_name='dnscry.pt-helsinki-ipv6', via=['anon-cs-de6', 'anon-cs-poland6', 'anon-cs-austria6', 'anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-tuusula-ipv4', via=['anon-cs-de', 'anon-cs-poland', 'anon-cs-berlin', 'anon-cs-nl'] }",
    "{ server_name='dnscry.pt-tuusula-ipv6', via=['anon-cs-de6', 'anon-cs-poland6', 'anon-cs-berlin6', 'anon-cs-nl6'] }",
    "{ server_name='nwps.fi', via=['anon-cs-de', 'anon-cs-poland', 'anon-cs-swe', 'anon-cs-nl'] }",
    # ── PL ── ──────────────────────────────────────────────────
    "{ server_name='cs-poland', via=['anon-cs-finland', 'anon-cs-de', 'anon-cs-swe', 'anon-cs-nl'] }",
    "{ server_name='cs-poland6', via=['anon-cs-finland6', 'anon-cs-de6', 'anon-cs-austria6', 'anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-gdansk-ipv4', via=['anon-cs-finland', 'anon-cs-de', 'anon-cs-berlin', 'anon-cs-nl'] }",
    "{ server_name='dnscry.pt-gdansk-ipv6', via=['anon-cs-finland6', 'anon-cs-de6', 'anon-cs-berlin6', 'anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-warsaw-ipv4', via=['anon-cs-finland', 'anon-cs-de', 'anon-cs-swe', 'anon-cs-nl'] }",
    "{ server_name='dnscry.pt-warsaw-ipv6', via=['anon-cs-finland6', 'anon-cs-de6', 'anon-cs-austria6', 'anon-cs-nl6'] }",
    # ── DE ── ──────────────────────────────────────────────────
    "{ server_name='cs-de', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-swe', 'anon-cs-nl'] }",
    "{ server_name='cs-de6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-austria6', 'anon-cs-nl6'] }",
    "{ server_name='cs-berlin', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-nl', 'anon-cs-ch'] }",
    "{ server_name='cs-berlin6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-nl6', 'anon-cs-belgium6'] }",
    "{ server_name='cs-dus', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-swe', 'anon-cs-nl'] }",
    "{ server_name='cs-dus6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-austria6', 'anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-dusseldorf-ipv4', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-swe', 'anon-cs-ch'] }",
    "{ server_name='dnscry.pt-dusseldorf-ipv6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-austria6', 'anon-cs-belgium6'] }",
    "{ server_name='dnscry.pt-dusseldorf02-ipv6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-nl6', 'anon-cs-austria6'] }",
    "{ server_name='dnscry.pt-dusseldorf03-ipv6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    "{ server_name='dnscry.pt-frankfurt-ipv4', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-swe', 'anon-cs-nl'] }",
    "{ server_name='dnscry.pt-frankfurt-ipv6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-austria6', 'anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-frankfurt02-ipv4', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-nl', 'anon-cs-ch'] }",
    "{ server_name='dnscry.pt-frankfurt02-ipv6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-nl6', 'anon-cs-belgium6'] }",
    "{ server_name='dnscry.pt-jena-ipv4', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-nl', 'anon-cs-ch'] }",
    "{ server_name='dnscry.pt-jena-ipv6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-nl6', 'anon-cs-belgium6'] }",
    "{ server_name='dnscry.pt-munich-ipv4', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-swe', 'anon-cs-ch'] }",
    "{ server_name='dnscry.pt-munich-ipv6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-austria6', 'anon-cs-belgium6'] }",
    "{ server_name='dnscry.pt-nuremberg-ipv4', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-swe', 'anon-cs-nl'] }",
    "{ server_name='dnscry.pt-nuremberg-ipv6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-austria6', 'anon-cs-nl6'] }",
    "{ server_name='quad9-dnscrypt-ip4-nofilter-pri', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-swe', 'anon-cs-nl'] }",
    "{ server_name='quad9-dnscrypt-ip6-nofilter-pri', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-austria6', 'anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-dusseldorf02-ipv4', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-swe', 'anon-cs-ch'] }",
    "{ server_name='dnscry.pt-dusseldorf03-ipv4', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-ch', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-bremen-ipv4', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-swe', 'anon-cs-ch'] }",
    "{ server_name='dnscry.pt-bremen-ipv6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-austria6', 'anon-cs-nl6'] }",
    # ── SE ── ──────────────────────────────────────────────────
    "{ server_name='cs-swe', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-de', 'anon-cs-nl'] }",
    "{ server_name='cs-swe6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-de6', 'anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-hudiksvall-ipv4', via=['anon-cs-finland', 'anon-cs-de', 'anon-cs-nl', 'anon-cs-ch'] }",
    "{ server_name='dnscry.pt-hudiksvall-ipv6', via=['anon-cs-finland6', 'anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6'] }",
    "{ server_name='dnscry.pt-stockholm-ipv4', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-de', 'anon-cs-nl'] }",
    "{ server_name='dnscry.pt-stockholm-ipv6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-de6', 'anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-stockholm02-ipv4', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-nl', 'anon-cs-ch'] }",
    "{ server_name='dnscry.pt-stockholm02-ipv6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-nl6', 'anon-cs-belgium6'] }",
    "{ server_name='searx-se-ipv4', via=['anon-cs-finland', 'anon-cs-poland', 'anon-cs-de', 'anon-cs-nl'] }",
    "{ server_name='searx-se-ipv6', via=['anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-de6', 'anon-cs-nl6'] }",
    # ── CH ── ──────────────────────────────────────────────────
    "{ server_name='cs-ch', via=['anon-cs-de', 'anon-cs-finland', 'anon-cs-poland', 'anon-cs-nl'] }",
    "{ server_name='cs-ch6', via=['anon-cs-de6', 'anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-geneva-ipv4', via=['anon-cs-de', 'anon-cs-finland', 'anon-cs-poland', 'anon-cs-nl'] }",
    "{ server_name='dnscry.pt-geneva-ipv6', via=['anon-cs-de6', 'anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-molln-ipv4', via=['anon-cs-de', 'anon-cs-finland', 'anon-cs-swe', 'anon-cs-nl'] }",
    "{ server_name='dnscry.pt-molln-ipv6', via=['anon-cs-de6', 'anon-cs-finland6', 'anon-cs-austria6', 'anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-zurich-ipv4', via=['anon-cs-de', 'anon-cs-finland', 'anon-cs-poland', 'anon-cs-nl'] }",
    "{ server_name='dnscry.pt-zurich-ipv6', via=['anon-cs-de6', 'anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-nl6'] }",
    "{ server_name='ibksturm', via=['anon-cs-de', 'anon-cs-finland', 'anon-cs-poland', 'anon-cs-nl'] }",
    # ── NL ── ──────────────────────────────────────────────────
    "{ server_name='cs-nl', via=['anon-cs-de', 'anon-cs-finland', 'anon-cs-poland', 'anon-cs-swe'] }",
    "{ server_name='cs-nl6', via=['anon-cs-de6', 'anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-austria6'] }",
    "{ server_name='dnscry.pt-amsterdam-ipv4', via=['anon-cs-de', 'anon-cs-finland', 'anon-cs-poland', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-amsterdam-ipv6', via=['anon-cs-de6', 'anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-austria6'] }",
    "{ server_name='dnscry.pt-amsterdam02-ipv4', via=['anon-cs-de', 'anon-cs-finland', 'anon-cs-swe', 'anon-cs-ch'] }",
    "{ server_name='dnscry.pt-amsterdam02-ipv6', via=['anon-cs-de6', 'anon-cs-finland6', 'anon-cs-austria6', 'anon-cs-belgium6'] }",
    "{ server_name='dnscry.pt-amsterdam03-ipv4', via=['anon-cs-de', 'anon-cs-poland', 'anon-cs-swe', 'anon-cs-ch'] }",
    "{ server_name='dnscry.pt-amsterdam03-ipv6', via=['anon-cs-de6', 'anon-cs-poland6', 'anon-cs-austria6', 'anon-cs-belgium6'] }",
    "{ server_name='dnscry.pt-eygelshoven-ipv4', via=['anon-cs-de', 'anon-cs-finland', 'anon-cs-poland', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-eygelshoven-ipv6', via=['anon-cs-de6', 'anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-austria6'] }",
    "{ server_name='dnscry.pt-ebenecity02-ipv4', via=['anon-cs-de', 'anon-cs-finland', 'anon-cs-poland', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-ebenecity02-ipv6', via=['anon-cs-de6', 'anon-cs-finland6', 'anon-cs-poland6', 'anon-cs-austria6'] }",
    "{ server_name='dnscry.pt-naaldwijk-ipv4', via=['anon-cs-de', 'anon-cs-finland', 'anon-cs-poland', 'anon-cs-swe'] }",
    # ── CZ ── ──────────────────────────────────────────────────
    "{ server_name='cs-czech', via=['anon-cs-de', 'anon-cs-poland', 'anon-cs-finland', 'anon-cs-swe'] }",
    "{ server_name='cs-czech6', via=['anon-cs-de6', 'anon-cs-poland6', 'anon-cs-finland6', 'anon-cs-austria6'] }",
    "{ server_name='dnscry.pt-prague-ipv4', via=['anon-cs-de', 'anon-cs-poland', 'anon-cs-finland', 'anon-cs-nl'] }",
    "{ server_name='dnscry.pt-prague-ipv6', via=['anon-cs-de6', 'anon-cs-poland6', 'anon-cs-finland6', 'anon-cs-nl6'] }",
    # ── RS ── ──────────────────────────────────────────────────
    "{ server_name='cs-serbia', via=['anon-cs-de', 'anon-cs-poland', 'anon-cs-nl', 'anon-cs-ch'] }",
    "{ server_name='cs-serbia6', via=['anon-cs-de6', 'anon-cs-poland6', 'anon-cs-nl6', 'anon-cs-belgium6'] }",
    "{ server_name='serbica', via=['anon-cs-de', 'anon-cs-poland', 'anon-cs-nl', 'anon-cs-ch'] }",
    # ── AT ── ──────────────────────────────────────────────────
    "{ server_name='cs-austria', via=['anon-cs-de', 'anon-cs-ch', 'anon-cs-czech', 'anon-cs-nl'] }",
    "{ server_name='cs-austria6', via=['anon-cs-de6', 'anon-cs-belgium6', 'anon-cs-czech6', 'anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-vienna-ipv4', via=['anon-cs-de', 'anon-cs-ch', 'anon-cs-czech', 'anon-cs-nl'] }",
    "{ server_name='dnscry.pt-vienna-ipv6', via=['anon-cs-de6', 'anon-cs-belgium6', 'anon-cs-czech6', 'anon-cs-nl6'] }",
    # ── NO ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-sandefjord-ipv4', via=['anon-cs-swe', 'anon-cs-finland', 'anon-cs-de', 'anon-cs-nl'] }",
    "{ server_name='dnscry.pt-sandefjord-ipv6', via=['anon-cs-austria6', 'anon-cs-finland6', 'anon-cs-de6', 'anon-cs-nl6'] }",
    "{ server_name='cs-norway', via=['anon-cs-swe', 'anon-cs-finland', 'anon-cs-de', 'anon-cs-nl'] }",
    "{ server_name='cs-norway6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-finland6', 'anon-cs-poland6'] }",
    # ── IS ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-hafnarfjordur-ipv4', via=['anon-cs-swe', 'anon-cs-finland', 'anon-cs-nl', 'anon-cs-ch'] }",
    "{ server_name='dnscry.pt-hafnarfjordur-ipv6', via=['anon-cs-austria6', 'anon-cs-finland6', 'anon-cs-nl6', 'anon-cs-belgium6'] }",
    # ── BG ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-sofia-ipv4', via=['anon-cs-de', 'anon-cs-ch', 'anon-cs-nl', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-sofia-ipv6', via=['anon-cs-de6', 'anon-cs-belgium6', 'anon-cs-nl6', 'anon-cs-austria6'] }",
    # ── DK ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-copenhagen-ipv4', via=['anon-cs-swe', 'anon-cs-finland', 'anon-cs-de', 'anon-cs-nl'] }",
    "{ server_name='dnscry.pt-copenhagen-ipv6', via=['anon-cs-austria6', 'anon-cs-finland6', 'anon-cs-de6', 'anon-cs-nl6'] }",
    # ── RO ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-bucharest-ipv4', via=['anon-cs-de', 'anon-cs-poland', 'anon-cs-ch', 'anon-cs-nl'] }",
    "{ server_name='dnscry.pt-bucharest-ipv6', via=['anon-cs-de6', 'anon-cs-poland6', 'anon-cs-belgium6', 'anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-oradea-ipv4', via=['anon-cs-de', 'anon-cs-poland', 'anon-cs-ch', 'anon-cs-nl'] }",
    "{ server_name='dnscry.pt-oradea-ipv6', via=['anon-cs-de6', 'anon-cs-poland6', 'anon-cs-belgium6', 'anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-timisoara-ipv4', via=['anon-cs-de', 'anon-cs-poland', 'anon-cs-ch', 'anon-cs-nl'] }",
    "{ server_name='dnscry.pt-timisoara-ipv6', via=['anon-cs-de6', 'anon-cs-poland6', 'anon-cs-belgium6', 'anon-cs-nl6'] }",
    "{ server_name='cs-ro', via=['anon-cs-de', 'anon-cs-poland', 'anon-cs-ch', 'anon-cs-nl'] }",
    # ── HU ── ──────────────────────────────────────────────────
    "{ server_name='cs-hungary', via=['anon-cs-de', 'anon-cs-austria', 'anon-cs-poland', 'anon-cs-ch'] }",
    # ── BE ── ──────────────────────────────────────────────────
    "{ server_name='cs-belgium', via=['anon-cs-nl', 'anon-cs-de', 'anon-cs-finland', 'anon-cs-ch'] }",
    "{ server_name='cs-belgium6', via=['anon-cs-nl6', 'anon-cs-de6', 'anon-cs-finland6', 'anon-cs-belgium6'] }",
    # ── TR ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-istanbul-ipv4', via=['anon-cs-de', 'anon-cs-nl', 'anon-cs-ch', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-istanbul-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    # ── SK ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-bratislava-ipv4', via=['anon-cs-de', 'anon-cs-ch', 'anon-cs-nl', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-bratislava-ipv6', via=['anon-cs-de6', 'anon-cs-belgium6', 'anon-cs-nl6', 'anon-cs-austria6'] }",
    # ── MD ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-chisinau-ipv4', via=['anon-cs-de', 'anon-cs-poland', 'anon-cs-nl', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-chisinau-ipv6', via=['anon-cs-de6', 'anon-cs-poland6', 'anon-cs-nl6', 'anon-cs-austria6'] }",
    "{ server_name='cs-md', via=['anon-cs-de', 'anon-cs-poland', 'anon-cs-nl', 'anon-cs-swe'] }",
    "{ server_name='cs-md6', via=['anon-cs-de6', 'anon-cs-poland6', 'anon-cs-nl6', 'anon-cs-austria6'] }",
    # ── FR ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-paris-ipv4', via=['anon-cs-de', 'anon-cs-ch', 'anon-cs-nl', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-paris-ipv6', via=['anon-cs-de6', 'anon-cs-belgium6', 'anon-cs-nl6', 'anon-cs-austria6'] }",
    "{ server_name='cs-fr', via=['anon-cs-de', 'anon-cs-ch', 'anon-cs-nl', 'anon-cs-swe'] }",
    "{ server_name='cs-fr6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    "{ server_name='dnscry.pt-marseille-ipv4', via=['anon-cs-de', 'anon-cs-ch', 'anon-cs-nl', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-marseille-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    # ── IT ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-milan-ipv4', via=['anon-cs-de', 'anon-cs-ch', 'anon-cs-nl', 'anon-cs-swe'] }",
    "{ server_name='cs-milan', via=['anon-cs-de', 'anon-cs-ch', 'anon-cs-nl', 'anon-cs-swe'] }",
    "{ server_name='cs-milan6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    # ── ES ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-madrid-ipv4', via=['anon-cs-de', 'anon-cs-ch', 'anon-cs-nl', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-madrid-ipv6', via=['anon-cs-de6', 'anon-cs-belgium6', 'anon-cs-nl6', 'anon-cs-austria6'] }",
    "{ server_name='cs-barcelona', via=['anon-cs-de', 'anon-cs-ch', 'anon-cs-nl', 'anon-cs-swe'] }",
    "{ server_name='cs-barcelona6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    # ── GR ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-thessaloniki-ipv4', via=['anon-cs-de', 'anon-cs-nl', 'anon-cs-ch', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-thessaloniki-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    # ── PT ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-lisbon-ipv4', via=['anon-cs-de', 'anon-cs-ch', 'anon-cs-nl', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-lisbon-ipv6', via=['anon-cs-de6', 'anon-cs-belgium6', 'anon-cs-nl6', 'anon-cs-austria6'] }",
    "{ server_name='dnscry.pt-lisbon02-ipv4', via=['anon-cs-de', 'anon-cs-ch', 'anon-cs-nl', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-lisbon02-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    # ── UK ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-london-ipv4', via=['anon-cs-de', 'anon-cs-nl', 'anon-cs-ch', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-london-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    "{ server_name='cs-london', via=['anon-cs-nl', 'anon-cs-de', 'anon-cs-finland', 'anon-cs-ch'] }",
    "{ server_name='cs-manchester', via=['anon-cs-nl', 'anon-cs-de', 'anon-cs-finland', 'anon-cs-ch'] }",
    "{ server_name='dnscry.pt-coventry-ipv4', via=['anon-cs-nl', 'anon-cs-de', 'anon-cs-finland', 'anon-cs-ch'] }",
    "{ server_name='dnscry.pt-coventry-ipv6', via=['anon-cs-nl6', 'anon-cs-de6', 'anon-cs-finland6', 'anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-newcastle-ipv4', via=['anon-cs-nl', 'anon-cs-de', 'anon-cs-finland', 'anon-cs-ch'] }",
    "{ server_name='dnscry.pt-newcastle-ipv6', via=['anon-cs-nl6', 'anon-cs-de6', 'anon-cs-finland6', 'anon-cs-nl6'] }",
    "{ server_name='dnscry.pt-redditch-ipv4', via=['anon-cs-nl', 'anon-cs-de', 'anon-cs-finland', 'anon-cs-ch'] }",
    "{ server_name='dnscry.pt-redditch-ipv6', via=['anon-cs-nl6', 'anon-cs-de6', 'anon-cs-finland6', 'anon-cs-nl6'] }",
    # ── JP ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-tokyo-ipv4', via=['anon-cs-de', 'anon-cs-nl', 'anon-cs-ch', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-tokyo-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    # ── SG ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-singapore-ipv4', via=['anon-cs-de', 'anon-cs-nl', 'anon-cs-ch', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-singapore-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    # ── GE ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-tbilisi-ipv4', via=['anon-cs-de', 'anon-cs-nl', 'anon-cs-ch', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-tbilisi-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    # ── US ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-newyork-ipv4', via=['anon-cs-de', 'anon-cs-nl', 'anon-cs-ch', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-newyork-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    "{ server_name='dnscry.pt-chicago-ipv4', via=['anon-cs-de', 'anon-cs-nl', 'anon-cs-ch', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-chicago-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    "{ server_name='dnscry.pt-losangeles-ipv4', via=['anon-cs-de', 'anon-cs-nl', 'anon-cs-ch', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-losangeles-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    "{ server_name='dnscry.pt-dallas-ipv4', via=['anon-cs-de', 'anon-cs-nl', 'anon-cs-ch', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-dallas-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    # ── CA ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-toronto-ipv4', via=['anon-cs-de', 'anon-cs-nl', 'anon-cs-ch', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-toronto-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    "{ server_name='dnscry.pt-montreal-ipv4', via=['anon-cs-de', 'anon-cs-nl', 'anon-cs-ch', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-montreal-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    # ── AU ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-melbourne-ipv4', via=['anon-cs-de', 'anon-cs-nl', 'anon-cs-ch', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-melbourne-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    # ── ZA ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-johannesburg-ipv4', via=['anon-cs-de', 'anon-cs-nl', 'anon-cs-ch', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-johannesburg-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    # ── IE ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-dublin-ipv4', via=['anon-cs-de', 'anon-cs-nl', 'anon-cs-ch', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-dublin-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    # ── TH ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-bangkok-ipv4', via=['anon-cs-de', 'anon-cs-nl', 'anon-cs-ch', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-bangkok-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    # ── ID ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-jakarta-ipv4', via=['anon-cs-de', 'anon-cs-nl', 'anon-cs-ch', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-jakarta-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    # ── AL ── ──────────────────────────────────────────────────
    "{ server_name='dnscry.pt-tirana-ipv4', via=['anon-cs-de', 'anon-cs-nl', 'anon-cs-ch', 'anon-cs-swe'] }",
    "{ server_name='dnscry.pt-tirana-ipv6', via=['anon-cs-de6', 'anon-cs-nl6', 'anon-cs-belgium6', 'anon-cs-austria6'] }",
    # ── WILDCARD: серверы без персонального маршрута (только живые) ──
    "{ server_name='*', via=[\n"
    "        'anon-cs-finland','anon-cs-finland6','anon-cs-poland','anon-cs-poland6','anon-cs-de','anon-cs-de6',\n"
    "        'anon-cs-berlin','anon-cs-berlin6','anon-cs-dus','anon-cs-dus6','anon-cs-swe','anon-cs-nl',\n"
    "        'anon-cs-nl6','anon-cs-ch','anon-cs-czech','anon-cs-czech6','anon-cs-serbia','anon-cs-serbia6',\n"
    "        'anon-cs-austria','anon-cs-austria6','anon-cs-belgium','anon-cs-belgium6','dnscry.pt-anon-helsinki-ipv4','dnscry.pt-anon-helsinki-ipv6',\n"
    "        'dnscry.pt-anon-warsaw-ipv4','dnscry.pt-anon-warsaw-ipv6','dnscry.pt-anon-kyiv-ipv4','dnscry.pt-anon-kyiv-ipv6','dnscry.pt-anon-gdansk-ipv4','dnscry.pt-anon-gdansk-ipv6',\n"
    "] }",
]
# кладбище — выселенные из пула имена (проверка воскрешений
# в pool-sync: если имя снова появится в живом списке, оно
# возвращается в пул автоматически). Мёртвое имя в server_names
# игнорируется dnscrypt-proxy молча — безопасно всегда.
_POOL_GRAVEYARD: List[str] = [
    "cs-france", "cs-france6", "dns.sb-ipv6",
    "dnscry.pt-athens-ipv4", "dnscry.pt-athens-ipv6", "dnscry.pt-brussels-ipv4",
    "dnscry.pt-brussels-ipv6", "dnscry.pt-budapest-ipv4", "dnscry.pt-budapest-ipv6",
    "dnscry.pt-buenosaires-ipv4", "dnscry.pt-buenosaires-ipv6", "dnscry.pt-dubai-ipv4",
    "dnscry.pt-dubai-ipv6", "dnscry.pt-ljubljana-ipv4", "dnscry.pt-ljubljana-ipv6",
    "dnscry.pt-luxembourg-ipv4", "dnscry.pt-luxembourg-ipv6", "dnscry.pt-milan-ipv6",
    "dnscry.pt-mumbai-ipv4", "dnscry.pt-mumbai-ipv6", "dnscry.pt-santiago-ipv4",
    "dnscry.pt-santiago-ipv6", "dnscry.pt-saopaulo-ipv4", "dnscry.pt-saopaulo-ipv6",
    "dnscry.pt-seoul-ipv4", "dnscry.pt-seoul-ipv6", "dnscry.pt-sydney-ipv4",
    "dnscry.pt-sydney-ipv6", "dnscry.pt-telaviv-ipv4", "dnscry.pt-telaviv-ipv6",
    "dnscry.pt-zagreb-ipv4", "dnscry.pt-zagreb-ipv6", "dnscrypt-ch-blahdns-ipv4",
    "dnscrypt-ch-blahdns-ipv6", "dnsforge.uk", "doh.ffmuc.net-2",
    "doh.ffmuc.net-v6-2",
]
# живой wildcard-набор релеев для серверов без персонального
# маршрута (страховка; pool-sync перефильтровывает по живому списку).
_WILDCARD_RELAYS: List[str] = [
    "anon-cs-finland", "anon-cs-finland6", "anon-cs-poland", "anon-cs-poland6",
    "anon-cs-de", "anon-cs-de6", "anon-cs-berlin", "anon-cs-berlin6",
    "anon-cs-dus", "anon-cs-dus6", "anon-cs-swe", "anon-cs-nl",
    "anon-cs-nl6", "anon-cs-ch", "anon-cs-czech", "anon-cs-czech6",
    "anon-cs-serbia", "anon-cs-serbia6", "anon-cs-austria", "anon-cs-austria6",
    "anon-cs-belgium", "anon-cs-belgium6", "dnscry.pt-anon-helsinki-ipv4", "dnscry.pt-anon-helsinki-ipv6",
    "dnscry.pt-anon-warsaw-ipv4", "dnscry.pt-anon-warsaw-ipv6", "dnscry.pt-anon-kyiv-ipv4", "dnscry.pt-anon-kyiv-ipv6",
    "dnscry.pt-anon-gdansk-ipv4", "dnscry.pt-anon-gdansk-ipv6",
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
    # http3_probe УДАЛЁН — в 2.1.5 ключа нет ([FATAL] Unsupported key,
    # конфиг не стартует вовсе), в 2.1.18 default false — запись избыточна.
    "timeout":               "3000",
    "keepalive":             "60",
    "lb_strategy":           "'p2'",
    "lb_estimator":          "true",
    "dnscrypt_ephemeral_keys":     "true",
    "tls_disable_session_tickets": "true",
    "block_ipv6":            "false",
    "block_unqualified":     "true",
    "block_undelegated":     "true",
    "reject_ttl":            "10",
    "cache":                 "true",
    "cache_size":            "32768",
    "cache_min_ttl":         "300",
    "cache_max_ttl":         "3600",
    "cache_neg_min_ttl":     "300",
    "cache_neg_max_ttl":     "900",
    # = канон (dnscrypt_setup): 8.8.8.8/1.1.1.1 в РФ отравлены
    # (DNAT→НСДИ, NXDomain-spoof), 9.9.9.9 + 77.88.8.8 работают отовсюду.
    # Используются ТОЛЬКО для резолва имён DoH-upstream'ов.
    "bootstrap_resolvers":   "['9.9.9.9:53', '77.88.8.8:53']",
    "fallback_resolvers":    "['9.9.9.9:53', '77.88.8.8:53']",
    "ignore_system_dns":     "true",
    "netprobe_timeout":      "10",
    "netprobe_address":      "'9.9.9.9:53'",
    "cert_refresh_delay":    "240",
    "cert_ignore_timestamp": "false",
    "max_clients":           "250",
    # (кейс vds14808, 2026-09-20): use_syslog отсутствовал в наборе →
    # pool-sync/advanced конфиги не имели его в top-level, а
    # apply_dnscrypt_tuning [T] дописывал недостающий ключ В КОНЕЦ файла
    # — после хвостовой секции [local_doh] → local_doh.use_syslog →
    # [FATAL] dnscrypt-proxy (дубль при повторе: Key has already been
    # defined). Ключ в каноническом top-level наборе генераторов.
    "use_syslog":            "true",
}

# источники dnscry.pt УДАЛЕНЫ — антибот-URL без failover ронял старт
# FATAL'ом при пустом кеше; весь их контент уже в официальных списках
# (public-resolvers.md / relays.md). Официальные источники продублированы
# третьим зеркалом cdn.jsdelivr.net — см. шаблон конфига в _apply_preset.
_EXTRA_SOURCES: str = """
[sources.odoh-servers]
urls = [
  'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-servers.md',
  'https://download.dnscrypt.info/resolvers-list/v3/odoh-servers.md',
  'https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/odoh-servers.md',
]
cache_file    = 'odoh-servers.md'
minisign_key  = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
refresh_delay = 25

[sources.odoh-relays]
urls = [
  'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-relays.md',
  'https://download.dnscrypt.info/resolvers-list/v3/odoh-relays.md',
  'https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/odoh-relays.md',
]
cache_file    = 'odoh-relays.md'
minisign_key  = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
refresh_delay = 25
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
    # жадный [^\n]* до ПОСЛЕДНЕЙ ']' в строке — IPv6-элементы
    # '[::1]:5300' содержат ']' внутри списка; ленивый .*? обрезал
    # строку на внутренней скобке и портил перегенерированный TOML.
    m = re.search(r"^listen_addresses\s*=\s*\[[^\n]*\]", content, re.MULTILINE)
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
## 51 страна: UA, EE, LV, LT, FI, PL, DE, SE, CH, NL, CZ, RS, AT, NO, IS,
## BG, DK, RO, HU, BE, LU, TR, SK, MD, FR, IT, ES, GR, PT, UK, IE, JP, SG,
## GE, AL, HK, TW, BD, NG, PK, LA, NZ, AU, IN, KR, CA, CL, US, ZA, TH, ID

{listen}

server_names = [{names_str}]

{params_lines}

[sources]
  [sources.public-resolvers]
  urls = [
    'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md',
    'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md',
    'https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/public-resolvers.md',
  ]
  cache_file    = 'public-resolvers.md'
  minisign_key  = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 25

  [sources.relays]
  urls = [
    'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md',
    'https://download.dnscrypt.info/resolvers-list/v3/relays.md',
    'https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/relays.md',
  ]
  cache_file    = 'relays.md'
  minisign_key  = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 25
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
    r = _run(["systemctl", "is-active", "dnscrypt-proxy"], capture=True)
    if r.returncode == 0 and r.stdout.strip() == "active":
        return True
    _warn("dnscrypt-proxy не запустился — проверьте journalctl -u dnscrypt-proxy")
    return False


def _dnscrypt_resolves() -> bool:
    """Проверяет что dnscrypt-proxy реально резолвит DNS (не просто активен)."""
    r = _run(["dig", "+short", "+time=3", "+tries=1",
              "@127.0.0.1", "-p", "5300", "google.com"], capture=True)
    if r.returncode == 0 and r.stdout.strip():
        return True
    return False


def _verify_resolves_with_retry(attempts: int = 4, pause: float = 3.0) -> bool:
    """Ждёт резолвинг с ретраями (окно netprobe/latency-ranking на старте)."""
    for attempt in range(attempts):
        if _dnscrypt_resolves():
            return True
        time.sleep(pause)
        _info(f"Ожидание ({attempt+1}/{attempts}) — dnscrypt-proxy стартует...")
    return False


def _apply_emergency_config() -> bool:
    """ЭКСТРЕННЫЙ конфиг — последнее средство «сервер без DNS».

    Известно-живые имена официального public-resolvers.md (quad9-dnscrypt,
    DNSCrypt-протокол, порт 8443, без SNI — жив и из РФ, и из-за рубежа),
    без маршрутов, без odoh-источников. Вызывается ТОЛЬКО когда и откат
    бэкапа не поднял резолвинг: битый бэкап хуже минимализма.
    """
    _warn("ЭКСТРЕННЫЙ фолбэк: минимальный конфиг quad9-dnscrypt...")
    ok = _apply_preset(
        ["quad9-dnscrypt-ip4-nofilter-pri", "quad9-dnscrypt-ip6-nofilter-pri"],
        _SECURITY_PARAMS, [], extra_sources=False)
    if not ok or not _restart_dnscrypt():
        return False
    if not _verify_resolves_with_retry(attempts=5):
        return False
    _ok("Экстренный конфиг применён: dnscrypt-proxy резолвит (quad9-dnscrypt). "
        "AGH fallback_dns (9.9.9.9/149.112.112.112) страхует поверх.")
    return True


def _rollback_or_emergency(bak: Optional[Path], phase: str) -> bool:
    """откат бэкапа; если откат не резолвит — экстренный конфиг.

    Возвращает True если сервер остался с рабочим DNS (откат или экстренный).
    """
    restored = False
    if bak and Path(bak).exists():
        try:
            shutil.copy2(str(bak), str(_DNSCRYPT_CONF))
            _run(["systemctl", "restart", "dnscrypt-proxy"], quiet=True)
            time.sleep(3)
            if _dnscrypt_resolves():
                _ok(f"Откат ({phase}): исходный конфиг восстановлен и резолвит.")
                restored = True
            else:
                _warn(f"Откат ({phase}): конфиг восстановлен, но не резолвит.")
        except Exception as e:
            _warn(f"Откат ({phase}) не удался: {e}")
    if not restored:
        # Последнее средство — сервер НЕ должен остаться без DNS.
        if _apply_emergency_config():
            restored = True
        else:
            _err("КРИТИЧНО: dnscrypt-proxy не резолвит даже в экстренном режиме. "
                 "Системный DNS живёт через AGH fallback (9.9.9.9/149.112.112.112) "
                 "или redirect 53→5300. Проверьте: journalctl -u dnscrypt-proxy -n 30")
    return restored


def _check_chain_after_apply() -> None:
    """проверка всей цепочки xray → AGH(:53) → dnscrypt(:5300).

    Ленивый импорт: модуль dnscrypt_update тянет state-файл, общий для всех
    DNS-меню (синхронизация версий/синка между меню). Провал импорта —
    не фатален: цепочка проверена не будет, но пресет уже применён.
    """
    try:
        from chimera.modules.dnscrypt_update import check_dns_chain
        chain = check_dns_chain(verbose=True)
        if chain.get("ok"):
            _ok("Цепочка DNS: xray → AGH → dnscrypt — цела.")
        else:
            _warn("Цепочка DNS требует внимания (см. вывод выше) — "
                  "dnscrypt применён, разрыв в другом звене (AGH/xray).")
    except Exception as e:
        _info(f"Проверка цепочки пропущена (dnscrypt_update недоступен: {e})")


def _write_state_after_apply(server_names: List[str]) -> None:
    """фиксирует применённый пул в общий state-файл (шапки меню)."""
    try:
        from chimera.modules.dnscrypt_update import update_state
        update_state(pool={
            "total": len(server_names),
            "template_total": len(_SERVER_NAMES),
            "alive": len(server_names),
            "countries": 51,
            "routes": len(_ANON_ROUTES),
            "last_sync": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "changed": True,
            "source": "ra-preset",
        })
    except Exception:
        pass


def _safe_apply_preset(server_names: List[str],
                       security_params: Dict[str, str],
                       anon_routes: List[str],
                       extra_sources: bool = True) -> bool:
    """Безопасное применение пресета с откатом при неудаче.

    Двухфазное применение:
      Фаза 1: Записать конфиг с базовыми серверами (/: quad9-dnscrypt
               DNSCrypt-протокол жив и из РФ, и из-за рубежа) + официальными
               источниками (public-resolvers/relays/odoh, 3 зеркала).
               Перезапустить dnscrypt — скачает официальные списки.
      Фаза 2: Записать полный конфиг (весь список серверов + маршруты).
               ждать скачивания dnscry.pt больше не нужно (источник
               удалён), стартует из кеша фазы 1 мгновенно.

    Если dnscrypt падает на любой фазе — откат с возвратом resolv.conf;
    если откат не резолвит — ЭКСТРЕННЫЙ конфиг quad9-dnscrypt:
    сервер без DNS не остаётся (плюс AGH fallback_dns поверх).

    resolv.conf восстанавливается через try/finally при ЛЮБОМ исходе
    (включая Ctrl+C и обрыв SSH посреди фазы) — раньше прерывание оставляло
    систему на временном DNS. Временные nameserver-ы — живые из РФ
    9.9.9.9/77.88.8.8 (раньше 8.8.8.8/1.1.1.1 — отравлены ТСПУ).

    после успешного применения — проверка цепочки
    xray → AGH → dnscrypt + запись state-файла.

    Возвращает True при успехе, False при неудаче (с откатом).
    """
    resolv_path = Path("/etc/resolv.conf")
    resolv_backup = None

    # 1. Бэкап конфига.
    bak = _backup_config()
    if bak:
        _ok(f"Бэкап конфига: {bak}")

    # 2. Временный bootstrap-DNS в resolv.conf на время применения.
    # = канон: 9.9.9.9 + 77.88.8.8 достижимы и из РФ, и из-за
    #    рубежа; 8.8.8.8/1.1.1.1 в РФ DNAT-ятся ТСПУ на НСДИ (NXDomain-spoof).
    try:
        if resolv_path.exists():
            resolv_backup = resolv_path.read_text(errors="replace")
            resolv_path.write_text("nameserver 9.9.9.9\nnameserver 77.88.8.8\n")
            _info("Временный fallback DNS: 9.9.9.9 + 77.88.8.8 (на время применения)")
    except Exception:
        pass

    def _restore_resolv() -> None:
        if resolv_backup is not None:
            try:
                resolv_path.write_text(resolv_backup)
            except Exception:
                pass

    # всё тело применения — под try/finally: восстановление resolv.conf
    # гарантировано при любом исходе, включая KeyboardInterrupt (Ctrl+C)
    # и потерю SSH-сессии (обрыв = SIGHUP/смерть процесса без finally —
    # тогда остаётся временный DNS, но живой, а не отравленный).
    try:
        # ── ФАЗА 1: базовые серверы + официальные источники ────────────
        _info("Фаза 1/2: запись базовых серверов + официальных источников (3 зеркала)...")
        # quad9-dnscrypt вместо cloudflare/google — фаза-1 обязана
        # резолвить ИЗ РФ (см. в dnscrypt_setup); имена живут в
        # стандартном public-resolvers (dnscry.pt-источников больше нет).
        phase1_names = ["quad9-dnscrypt-ip4-nofilter-pri",
                        "quad9-dnscrypt-ip6-nofilter-pri"]
        if not _apply_preset(phase1_names, security_params, [], extra_sources=extra_sources):
            return False

        if not _restart_dnscrypt():
            _warn("dnscrypt-proxy не запустился (фаза 1) — откат...")
            _rollback_or_emergency(bak, "фаза 1, старт")
            _err("Пресет не применён. Проверьте journalctl -u dnscrypt-proxy")
            return False

        # Проверить что фаза 1 резолвит. с ретраями — на старте
        # netprobe/latency-ranking держит ~15-20с окно, когда :5300 ещё
        # не отвечает (живой кейс: не путать с блокировкой).
        _info("Проверяю что dnscrypt-proxy резолвит (фаза 1)...")
        if not _verify_resolves_with_retry():
            _warn("dnscrypt-proxy не резолвит (фаза 1) — откат...")
            _rollback_or_emergency(bak, "фаза 1, резолвинг")
            _err("Пресет не применён.")
            return False

        _ok("Фаза 1: dnscrypt-proxy резолвит (quad9-dnscrypt)")

        # ── ФАЗА 2: полный список серверов + маршруты ──────────────────
        _info(f"Фаза 2/2: запись полного списка ({len(server_names)} серверов, {len(anon_routes)} маршрутов)...")
        # пауза 15с для скачивания dnscry.pt больше не нужна
        # официальные списки скачаны/закешированы фазой 1.

        if not _apply_preset(server_names, security_params, anon_routes, extra_sources=extra_sources):
            # Если не удалось записать — фаза 1 конфиг остаётся (рабочий).
            _warn("Не удалось записать полный конфиг — остаётся базовый (quad9-dnscrypt)")
            return False

        if not _restart_dnscrypt():
            _warn("dnscrypt-proxy не запустился (фаза 2) — возвращаю базовый конфиг...")
            # Возвращаем фаза-1 конфиг.
            _apply_preset(phase1_names, security_params, [], extra_sources=extra_sources)
            _run(["systemctl", "restart", "dnscrypt-proxy"], quiet=True)
            time.sleep(2)
            if not _dnscrypt_resolves():
                _rollback_or_emergency(bak, "фаза 2, старт")
            _err("Полный пресет не применён — оставлен базовый (quad9-dnscrypt).")
            return False

        # Проверить что фаза 2 резолвит.
        _info("Проверяю что dnscrypt-proxy резолвит (фаза 2)...")
        if not _verify_resolves_with_retry():
            _warn("dnscrypt не резолвит (фаза 2) — возвращаю базовый конфиг...")
            _apply_preset(phase1_names, security_params, [], extra_sources=extra_sources)
            _run(["systemctl", "restart", "dnscrypt-proxy"], quiet=True)
            time.sleep(2)
            if not _dnscrypt_resolves():
                _rollback_or_emergency(bak, "фаза 2, резолвинг")
            _err("Полный пресет не применён — оставлен базовый (quad9-dnscrypt).")
            return False

        # Успех!
        _ok(f"DNSCrypt-proxy резолвит DNS — пресет применён ({len(server_names)} серверов)!")
        # проверка цепочки xray → AGH → dnscrypt + state для шапок меню.
        _check_chain_after_apply()
        _write_state_after_apply(server_names)
        return True
    finally:
        # восстановление resolv.conf при ЛЮБОМ исходе — включая
        # Ctrl+C (KeyboardInterrupt) и нештатные исключения посреди фаз.
        _restore_resolv()


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
def _pool_header_line() -> str:
    """строка шапки из state-файла последнего синка (fallback — статика)."""
    try:
        from chimera.modules.dnscrypt_update import get_pool_status_line
        return get_pool_status_line(len(_SERVER_NAMES))
    except Exception:
        return f"{len(_SERVER_NAMES)} шт. (51 страна, EU+Asia+Global)"


def _version_header_line() -> str:
    """строка версии из state (синхронизирована между всеми DNS-меню)."""
    try:
        from chimera.modules.dnscrypt_update import get_version_status_line
        return get_version_status_line()
    except Exception:
        return "?"


def _screen_preset() -> None:
    os.system("clear")
    print()
    _box_top("🛡️  ПРЕСЕТ: 245 СЕРВЕРОВ, 51 СТРАНА, АНОНИМИЗАЦИЯ")
    _box_row()
    _box_row(f"  {BOLD}Серверы:{NC} {_pool_header_line()}")
    _box_row(f"  {BOLD}Маршруты:{NC} {len(_ANON_ROUTES)} анонимизированных (персональные + wildcard)")
    _box_row(f"  {BOLD}Протоколы:{NC} DNSCrypt + DoH + ODoH")
    _box_row(f"  {BOLD}Безопасность:{NC} DNSSEC + nolog + nofilter")
    _box_row(f"  {BOLD}Эфемерные ключи:{NC} да")
    _box_row(f"  {BOLD}HTTP/3:{NC} да")
    _box_row(f"  {BOLD}Анонимизация:{NC} server → relay в другой стране (221 из 245; 24 DoH — напрямую)")
    _box_row(f"  {BOLD}Версия:{NC} {_version_header_line()}")
    _box_row()
    _box_row(f"  {DIM}Yandex DNS ИСКЛЮЧЁН (утечка).{NC}")
    _box_row(f" {DIM}: moscow/CF/GG исключены — гео-резистентность.{NC}")
    _box_row(f" {DIM}: синк с живым списком — 37 мёртвых вон (кладбище), +90 живых; dnscry.pt-источники удалены.{NC}")
    _box_row(f"  {DIM}После применения — тест цепочки xray → AGH → dnscrypt + откат/экстренный фолбэк при провале.{NC}")
    _box_row()
    _box_warn("Бэкап конфига будет создан перед изменением.")
    _box_row(f"  {GREEN}resolv.conf: временно 9.9.9.9/77.88.8.8, восстановление гарантировано.{NC}")
    _box_bottom()
    print()
    try:
        confirm = input(f"{CYAN}Применить пресет? [Y/n]: {NC}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        confirm = "n"
    if confirm not in ("", "y", "yes", "д", "да"):
        return
    _info(f"Записываю конфиг ({len(_SERVER_NAMES)} серверов, {len(_ANON_ROUTES)} маршрутов)...")
    _safe_apply_preset(_SERVER_NAMES, _SECURITY_PARAMS, _ANON_ROUTES, extra_sources=True)
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
    _info(f"Замеряю RTT для {len(_SERVER_NAMES)} серверов (параллельно, ~40-60 сек)...")
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
    _safe_apply_preset(chosen, _SECURITY_PARAMS, _ANON_ROUTES, extra_sources=True)
    print()
    input(f"{BLUE}Нажмите Enter...{NC}")


# Параметры для ручной настройки: (key, label, type, description)
# type: "bool" — toggle true/false
#       "int"  — ввод числа
#       "str"  — ввод строки
_PARAMS_TO_EDIT = [
    ("require_dnssec",              "DNSSEC (проверка подлинности)",          "bool", "Проверка подлинности DNS-ответов через DNSSEC"),
    ("require_nolog",               "No-log (без логирования запросов)",      "bool", "Серверы не логируют DNS-запросы"),
    ("require_nofilter",            "No-filter (без блокировок)",             "bool", "Серверы не фильтруют контент"),
    ("dnscrypt_servers",            "DNSCrypt-протокол",                      "bool", "Использовать DNSCrypt-протокол"),
    ("doh_servers",                 "DoH (DNS-over-HTTPS)",                   "bool", "Использовать DNS-over-HTTPS"),
    ("odoh_servers",                "ODoH (Oblivious DoH)",                  "bool", "Oblivious DoH — сервер не видит IP клиента"),
    ("dnscrypt_ephemeral_keys",     "Эфемерные ключи DNSCrypt",              "bool", "Одноразовые ключи для каждого соединения"),
    ("tls_disable_session_tickets", "Отключить TLS session tickets",          "bool", "Усиление приватности TLS"),
    ("block_unqualified",           "Блокировать unqualified запросы",        "bool", "Блокировать запросы к односоставным именам"),
    ("block_undelegated",           "Блокировать undelegated зоны",           "bool", "Блокировать запросы к неделегированным зонам"),
    ("http3",                       "HTTP/3 (QUIC)",                          "bool", "Использовать HTTP/3 поверх QUIC"),
    ("force_tcp",                   "Принудительный TCP (false=UDP)",         "bool", "false = UDP предпочтителен, true = только TCP"),
    ("cache",                       "Кеширование DNS",                        "bool", "Кешировать DNS-ответы"),
    ("cache_size",                  "Размер кеша (записей)",                  "int",  "Количество записей в кеше (32768 = ~1MB)"),
    ("cache_min_ttl",               "Минимальный TTL (сек)",                  "int",  "Минимальное время жизни записи (300 = 5 мин)"),
    ("cache_max_ttl",               "Максимальный TTL (сек)",                 "int",  "Максимальное время жизни записи (3600 = 1 час)"),
    ("cache_neg_min_ttl",           "Мин. TTL негативных (NXDOMAIN, сек)",    "int",  "Кешировать отсутствие домена (300 = 5 мин)"),
    ("cache_neg_max_ttl",           "Макс. TTL негативных (NXDOMAIN, сек)",   "int",  "Макс. время кеширования NXDOMAIN (900 = 15 мин)"),
    ("timeout",                     "Таймаут запроса (мс)",                   "int",  "Таймаут ожидания ответа от сервера"),
    ("keepalive",                   "Keepalive соединений (сек)",             "int",  "Время удержания соединения (60 = 1 мин)"),
    ("netprobe_timeout",            "Таймаут сетевого пробника (сек)",        "int",  "Время ожидания сети при старте (10 сек)"),
    ("lb_strategy",                 "Стратегия балансировки",                 "str",  "p2 / ph / random / fastest_addr"),
    ("max_clients",                 "Макс. клиентов",                         "int",  "Максимальное количество одновременных клиентов"),
]


def _get_param_value(content: str, key: str) -> str:
    """Читает текущее значение параметра из конфига."""
    m = re.search(rf'^{key}\s*=\s*(.+)$', content, re.MULTILINE)
    return m.group(1).strip() if m else "?"


def _toggle_bool(val: str) -> str:
    """Переключает true ↔ false."""
    v = val.strip().lower()
    if v in ("true", "1", "yes"):
        return "false"
    return "true"


def _apply_single_param(key: str, value: str) -> bool:
    """Применяет один параметр в конфиг и перезапускает dnscrypt."""
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
        return _restart_dnscrypt()
    except Exception as e:
        _err(f"Ошибка: {e}")
        return False


def _screen_manual_params() -> None:
    """Зацикленный TUI-экран ручной настройки параметров.

    Каждый параметр — пункт меню с номером. Bool — переключается по номеру.
    Int/str — ввод нового значения. P — применить весь пресет. Q — выход.
    """
    while True:
        os.system("clear")
        print()
        _box_top("⚙️  РУЧНАЯ НАСТРОЙКА ПАРАМЕТРОВ")
        _box_desc(
            "Переключите bool-параметры по номеру, или введите новое "
            "значение для int/str. [P] — применить весь пресет."
        )
        _box_sep()

        content = _read_config()

        for i, (key, label, ptype, desc) in enumerate(_PARAMS_TO_EDIT, 1):
            current_val = _get_param_value(content, key)

            # Цвет для bool: зелёный = true, красный = false.
            if ptype == "bool":
                v_lower = current_val.lower()
                if v_lower in ("true", "1", "yes"):
                    val_col = f"{GREEN}{current_val}{NC}"
                    toggle_hint = f"{DIM}→ false{NC}"
                else:
                    val_col = f"{RED}{current_val}{NC}"
                    toggle_hint = f"{DIM}→ true{NC}"
            else:
                val_col = f"{CYAN}{current_val}{NC}"
                toggle_hint = ""

            _box_row(f"  {BOLD}[{i}]{NC}  {label}")
            _box_row(f"       {DIM}{key} = {NC}{val_col}  {toggle_hint}")
            _box_row(f"       {DIM}{desc}{NC}")
            _box_sep()

        _box_sep()
        _box_item("P", f"{GREEN}Применить весь пресет{NC}  (245 серверов + все параметры)")
        _box_item("R", f"{YELLOW}Перезапустить dnscrypt-proxy{NC}  (без изменения конфига)")
        _box_item("Q", f"{DIM}← Назад{NC}")
        _box_bottom()

        print()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except (EOFError, KeyboardInterrupt):
            return

        if not ch:
            continue

        rl = ch.lower()

        # Q — выход.
        if rl in ("q", "0"):
            return

        # P — применить пресет.
        if rl == "p":
            _safe_apply_preset(_SERVER_NAMES, _SECURITY_PARAMS, _ANON_ROUTES, extra_sources=True)
            input(f"\n{BLUE}Нажмите Enter...{NC}")
            continue

        # R — перезапуск без изменений.
        if rl == "r":
            _restart_dnscrypt()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
            continue

        # Число — выбор параметра по номеру.
        if ch.isdigit():
            idx = int(ch)
            if 1 <= idx <= len(_PARAMS_TO_EDIT):
                key, label, ptype, desc = _PARAMS_TO_EDIT[idx - 1]
                current_val = _get_param_value(content, key)

                if ptype == "bool":
                    # Переключаем true ↔ false.
                    new_val = _toggle_bool(current_val)
                    _info(f"Переключаю: {key} = {current_val} → {new_val}")
                    _apply_single_param(key, new_val)
                    input(f"\n{BLUE}Нажмите Enter...{NC}")
                    continue

                elif ptype == "int":
                    _info(f"Текущее: {key} = {current_val}")
                    try:
                        new_val = input(f"{CYAN}Новое значение (число):{NC} ").strip()
                    except KeyboardInterrupt:
                        continue
                    if not new_val:
                        continue
                    try:
                        int(new_val)
                    except ValueError:
                        _warn("Нужно целое число")
                        input(f"\n{BLUE}Нажмите Enter...{NC}")
                        continue
                    _apply_single_param(key, new_val)
                    input(f"\n{BLUE}Нажмите Enter...{NC}")
                    continue

                elif ptype == "str":
                    _info(f"Текущее: {key} = {current_val}")
                    try:
                        new_val = input(f"{CYAN}Новое значение:{NC} ").strip()
                    except KeyboardInterrupt:
                        continue
                    if not new_val:
                        continue
                    _apply_single_param(key, new_val)
                    input(f"\n{BLUE}Нажмите Enter...{NC}")
                    continue

            else:
                _warn(f"Нет такого номера (1-{len(_PARAMS_TO_EDIT)})")
                time.sleep(1)
                continue

        # key=value — прямой ввод.
        m = re.match(r'^(\w+)\s*=\s*(.+)$', ch)
        if m:
            key, value = m.group(1), m.group(2).strip()
            known_keys = {p[0] for p in _PARAMS_TO_EDIT} | {"server_names", "listen_addresses"}
            if key not in known_keys:
                _warn(f"Неизвестный параметр: {key}")
                input(f"\n{BLUE}Нажмите Enter...{NC}")
                continue
            _apply_single_param(key, value)
            input(f"\n{BLUE}Нажмите Enter...{NC}")
            continue

        _warn("Неверный ввод. Введите номер, P, R, Q или key=value")
        time.sleep(1)


def _screen_status() -> None:
    os.system("clear")
    print()
    _box_top("📊  СТАТУС DNSCRYPT-PROXY")
    r = _run(["systemctl", "is-active", "dnscrypt-proxy"], capture=True)
    svc = f"{GREEN}active{NC}" if r.returncode == 0 else f"{RED}не активен{NC}"
    _box_row(f"  Сервис:          {svc}")
    _box_row(f"  Версия:          {CYAN}{_version_header_line()}{NC}")
    _box_row(f"  Пул:             {CYAN}{_pool_header_line()}{NC}")
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
    if "cdn.jsdelivr.net" in content:
        sources.append("jsdelivr-зеркало")
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
            "245 серверов в 51 стране. ODoH, DNSSEC, анонимизация. "
            "Авто-синк пула каждые 6 ч (cron) — счётчики из последнего синка. "
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
        _box_row(f"  Пул: {_pool_header_line()}")
        _box_row(f"  Версия: {_version_header_line()}")
        _box_sep()
        _box_item("1", f"{GREEN}Применить пресет (245 серверов, 51 страна){NC}")
        _box_item("2", f"{CYAN}RTT-замер и выбор серверов{NC}  (реальная latency)")
        _box_item("3", f"{YELLOW}Ручная настройка параметров{NC}  (DNSSEC, ODoH, cache...)")
        _box_item("4", "📊  Статус конфигурации")
        _box_item("5", f"{CYAN}🔄 Синхронизировать пул с живым списком{NC}  (запуск pool-sync сейчас)")
        _box_item("6", f"{CYAN}⬆️  Обновление dnscrypt-proxy{NC}  (версия/автообновление/цепочка)")
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
        elif ch == "5":
            try:
                from chimera.modules.dnscrypt_update import run_pool_sync_now
                run_pool_sync_now(interactive=True)
            except Exception as e:
                _warn(f"pool-sync недоступен: {e}")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "6":
            try:
                from chimera.modules.dnscrypt_update import do_dnscrypt_update_menu
                do_dnscrypt_update_menu()
            except Exception as e:
                _warn(f"dnscrypt_update недоступен: {e}")
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
    "_POOL_GRAVEYARD",
    "_WILDCARD_RELAYS",
    "_safe_apply_preset",
    "_apply_emergency_config",
]
