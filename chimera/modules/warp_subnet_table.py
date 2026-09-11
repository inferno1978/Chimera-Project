#!/usr/bin/env python3
"""
chimera/modules/warp_subnet_table.py
───────────────────────────────────────────────────────────────────────────────
Таблица подсетей WARP в стиле vernette/warpscout: «лучший эндпоинт на каждую
/24» с РЕАЛЬНОЙ пробой ноды выхода (colo/loc) и MTProto-проверкой Telegram —
до применения эндпоинта.

Идея портирована из warpscout (MIT). У vernette каждый эндпоинт проверяется
полным WireGuard-хендшейком из юзерспейс-туннеля (wireguard-go + gVisor
netstack) и trace внутри туннеля отдаёт ноду выхода (colo IATA / loc).
У Химеры kernel-WireGuard, поэтому вместо юзерспейс-стека поднимается
ВРЕМЕННЫЙ интерфейс wg-scout на ТЕХ ЖЕ ключах wgcf, что и прод wg-warp —
данные честные именно для этого сервера и аккаунта (egress-география у
чужого wgcf-аккаунта была бы другой):

    ip link add wg-scout → wg set (peer=кандидат) → trace → teardown.

Зачем это нужно: массовый TCP-скан Химеры слеп к ноде выхода — быстрый по
RTT эндпоинт может выходить в DME (DPI-фильтрация с 04.2026) или терять
2 из 5 ДЦ Telegram (живой пример warpscout-tg: Франкфурт отвечал только на
DC1/3/5). Таблица показывает это ДО применения, а чёрный список colo
подсвечивается прямо в строках.

Маршрутизация пробы — не трогает ни прод wg-warp, ни telemt_warp_route:
  • ЕДИНЫЙ путь trace и MTProto — bind по АДРЕСУ: сокеты/кёрл биндятся
    к IPv4 wg-scout, ip rule from <addr> lookup 303 priority 140 +
    default dev wg-scout table 303 уводит их через КАНДИДАТА мимо
    telemt-fwmark (150) и прода; чужой трафик не затрагивается —
    правило матчит только наш src. Bind по ИМЕНИ интерфейса
    (curl --interface wg-scout) заменён на bind по IP-литералу из-за
    живых багов curl-пути: 1) proxy-переменные окружения
    (http(s)_proxy/all_proxy) заставляют curl идти к ПРОКСИ, полностью
    игнорируя --interface для назначения (подтверждено экспериментом
    curl 8.x: «Uses proxy env variable … Trying <proxy>») — лечится
    --noproxy '*', теперь ставится всегда; 2) DNS, резолвящий ЛЮБОЕ имя
    (wildcard на части хостингов), превращает --interface wg-scout в
    bind по чужому АДРЕСУ — curl трактует резолвящееся значение как
    хост, не как устройство (тоже подтверждено: unresolvable → errno 19
    «No such device», resolvable → source-bind). IP-литерал исключает
    резолв целиком;
  • 1.1.1.1/32 dev wg-scout в main (replace; прежний /32, если был,
    восстанавливается после) — резервный маршрут trace (если from-правило
    не встало, source-bound пакет уйдёт в main по /32 — тоже в scout);
  • host-маршрут до САМОГО кандидата через исходный шлюз — UDP-хендшейк
    не заворачивается в прод-туннель при активном FULL (0.0.0.0/1).

ВНИМАНИЕ (аккаунт один → CF видит «роуминг»): после пробы основного
туннеля ре-хендшейк не происходит до REKEY_AFTER_TIME (~120 с). Поэтому
по завершении пробы модуль сам делает restart wg-quick@wg-warp (~2 сек,
маршруты не страдают — Table=off, их тут же переприменяет _apply_mode).

Точка входа: run_subnet_table_flow() — из warp._menu_endpoint_manager (п.8).
warp.py импортирует этот модуль ЛЕНИВО (внутри пункта меню): модуль сам
импортирует warp на верхнем уровне → top-level импорт из warp создал бы
цикл. Паттерн тот же, что у warp_telegram_probe.py.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

# warp.py лежит рядом — относительный импорт пакета при любом запуске.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules.box_renderer import (
    RED, GREEN, BLUE, CYAN, YELLOW, DIM, NC,
    _box_top, _box_row, _box_sep, _box_bottom,
)
from chimera.modules import warp as _warp

# ── Константы ─────────────────────────────────────────────────────────────
SCOUT_IFACE = "wg-scout"
# Таблица/приоритет проб ДЦ и trace: 300 = telemt, 301 = youtube,
# 302 = probe у warp_telegram_probe. 303 — наша. Приоритет 140 — ВЫШЕ
# telemt-fwmark (150), но ниже всего остального: правило матчит только
# src-адрес wg-scout (bind по адресу — trace и MTProto, см. докстринг
# модуля: это эмпирически рабочий путь даже там, где curl --interface
# <имя> ломается на proxy-env/wildcard-DNS).
SCOUT_TABLE = 303
SCOUT_RULE_PRIORITY = 140

TRACE_URL = "https://1.1.1.1/cdn-cgi/trace"
TRACE_TIMEOUT = 7       # сек на попытку curl (хендшейк ленивый — 1-я попытка его ждёт)
TRACE_RETRIES = 3
TRACE_RETRY_PAUSE = 1.5 # сек

TG_PROBE_TIMEOUT_S = 6.0  # сек, общий дедлайн 5 ДЦ (параллельно)

# ── IATA-код colo → «Город, CC» (RU) ─────────────────────────────────────
# Не полный список CF (~300 нод) — только те, что реально встречаются на
# пути из RU/EU-хостингов; незнакомый код показывается как есть, без города.
IATA_CITY_MAP: dict[str, str] = {
    "DME": "Москва, RU", "SVO": "Москва, RU", "LED": "Санкт-Петербург, RU",
    "KUF": "Самара, RU", "SVX": "Екатеринбург, RU", "KIV": "Кишинёв, MD",
    "MSQ": "Минск, BY", "KBP": "Киев, UA",
    "FRA": "Франкфурт, DE", "BER": "Берлин, DE", "MUC": "Мюнхен, DE",
    "HAM": "Гамбург, DE", "DUS": "Дюссельдорф, DE", "STR": "Штутгарт, DE",
    "AMS": "Амстердам, NL", "LHR": "Лондон, GB", "MAN": "Манчестер, GB",
    "CDG": "Париж, FR", "MRS": "Марсель, FR", "LIL": "Лилль, FR",
    "MXP": "Милан, IT", "FCO": "Рим, IT", "ZRH": "Цюрих, CH",
    "GVA": "Женева, CH", "VIE": "Вена, AT", "PRG": "Прага, CZ",
    "BRQ": "Брно, CZ", "WAW": "Варшава, PL", "KRK": "Краков, PL",
    "ARN": "Стокгольм, SE", "GOT": "Гётеборг, SE", "CPH": "Копенгаген, DK",
    "HEL": "Хельсинки, FI", "OSL": "Осло, NO", "KEF": "Рейкьявик, IS",
    "DUB": "Дублин, IE", "BRU": "Брюссель, BE", "LUX": "Люксембург, LU",
    "MAD": "Мадрид, ES", "BCN": "Барселона, ES", "LIS": "Лиссабон, PT",
    "OPO": "Порту, PT", "BUD": "Будапешт, HU", "OTP": "Бухарест, RO",
    "SOF": "София, BG", "ATH": "Афины, GR", "SKG": "Салоники, GR",
    "IST": "Стамбул, TR", "ZAG": "Загреб, HR", "BEG": "Белград, RS",
    "RIX": "Рига, LV", "TLL": "Таллин, EE", "VNO": "Вильнюс, LT",
    "TLV": "Тель-Авив, IL", "CAI": "Каир, EG",
    "DXB": "Дубай, AE", "DOH": "Доха, QA", "BAH": "Манама, BH",
    "KWI": "Кувейт, KW", "RUH": "Эр-Рияд, SA", "JED": "Джидда, SA",
    "BOM": "Мумбаи, IN", "DEL": "Дели, IN", "MAA": "Ченнай, IN",
    "BLR": "Бангалор, IN", "SIN": "Сингапур, SG", "HKG": "Гонконг, HK",
    "NRT": "Токио, JP", "KIX": "Осака, JP", "ICN": "Сеул, KR",
    "SJC": "Сан-Хосе, US", "LAX": "Лос-Анджелес, US", "SEA": "Сиэтл, US",
    "SFO": "Сан-Франциско, US", "ORD": "Чикаго, US", "DFW": "Даллас, US",
    "IAH": "Хьюстон, US", "ATL": "Атланта, US", "BOS": "Бостон, US",
    "IAD": "Вашингтон, US", "EWR": "Ньюарк, US", "JFK": "Нью-Йорк, US",
    "MIA": "Майами, US", "DEN": "Денвер, US", "PHX": "Финикс, US",
    "LAS": "Лас-Вегас, US", "YYZ": "Торонто, CA", "YVR": "Ванкувер, CA",
    "GRU": "Сан-Паулу, BR", "EZE": "Буэнос-Айрес, AR", "SCL": "Сантьяго, CL",
    "BOG": "Богота, CO", "LIM": "Лима, PE", "MEX": "Мехико, MX",
    "JNB": "Йоханнесбург, ZA", "CPT": "Кейптаун, ZA", "LOS": "Лагос, NG",
    "NBO": "Найроби, KE", "MRB": "Марракеш, MA",
}


def colo_city(colo: Optional[str]) -> str:
    """«Хельсинки, FI» по IATA-коду; незнакомый код — как есть."""
    if not colo:
        return ""
    return IATA_CITY_MAP.get(colo.upper(), colo)


# ── Вспомогательный раннер (ip/wg/curl без исключений) ───────────────────
def _ip(args: list, timeout: int = 8) -> subprocess.CompletedProcess:
    """ip(8)/wg(8) без исключений: в тестах патчится, в бою молчит в stdout."""
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(args, 1, stdout="", stderr=str(e))


_ANSI_RE = re.compile(chr(27) + r"\[[0-9;]*m")


def _plain(s: str) -> str:
    return _ANSI_RE.sub("", s)


# ── Агрегация «лучший на подсеть» ────────────────────────────────────────
def aggregate_best_per_subnet(results: list[dict]) -> list[dict]:
    """Группирует результаты скана по /24 (host → ip_network(host/24));
    в каждой подсети остаётся эндпоинт с минимальным RTT, сортировка итога —
    по RTT по возрастанию («Best endpoint per subnet» у warpscout).
    Исходные dict не мутируются — каждая строка копия с ключом subnet."""
    import ipaddress

    best: dict[str, dict] = {}
    for r in results or []:
        host = r.get("host") or (r.get("endpoint", ":").rsplit(":", 1)[0] if r.get("endpoint") else None)
        if not host:
            continue
        try:
            key = str(ipaddress.ip_network(f"{host}/24", strict=False))
        except ValueError:
            continue
        cur = best.get(key)
        rtt, cur_rtt = r.get("rtt_ms"), (cur or {}).get("rtt_ms")
        better = (
            cur is None
            or (rtt is not None and (cur_rtt is None or rtt < cur_rtt))
        )
        if better:
            best[key] = dict(r, subnet=key)
    rows = list(best.values())
    rows.sort(key=lambda r: (r.get("rtt_ms") is None, r.get("rtt_ms") or 0.0))
    return rows


# ── trace через wg-scout / прод-интерфейс ────────────────────────────────
def _trace_via(iface: str,
               src: Optional[str] = None) -> tuple[Optional[str], Optional[str],
                                                   bool, Optional[str]]:
    """curl cdn-cgi/trace через туннель (первый пакет лениво инициирует
    WireGuard-хендшейк — поэтому ретраи). Возвращает (colo, loc, warp_on,
    err), где err — компактная причина последней неудачной попытки
    (последняя строка stderr curl / «curl timeout» / «no colo= in trace»)
    для честного «нет trace (…)» в прогрессе пробы; None при успехе.

    src — bind по IP-ЛИТЕРАЛУ (адрес wg-scout), а не по имени интерфейса.
    Почему: curl трактует РЕЗОЛВЯЩЕЕСЯ значение --interface как хост и
    биндится по чужому адресу (wildcard-DNS хостингов резолвит и
    «wg-scout»), а при http(s)_proxy/all_proxy в окружении вообще идёт
    к прокси мимо назначения — оба случая дают «? » во всех колонках
    ВЫХОД/НОДА при живом туннеле (живой кейс: TG 5/5 через этот же scout,
    trace — нет). Поэтому: 1) всегда --noproxy '*' — trace диагностический,
    прокси исказил бы вердикт; 2) IP-литерал в --interface исключает
    DNS-резолв; пакет уходит by from-правилу 140 → таблица 303 → тот же
    путь, что у MTProto-проб (эмпирически рабочий). Без src — bind по
    имени интерфейса (прод wg-warp в rehandshake_prod: имя не резолвится
    на нормальном DNS, --noproxy страхует от proxy-env)."""
    bind = src or iface
    last_err: Optional[str] = None
    for attempt in range(TRACE_RETRIES):
        try:
            r = subprocess.run(
                ["curl", "-sS", "--noproxy", "*",
                 "--interface", bind,
                 "--max-time", str(TRACE_TIMEOUT), TRACE_URL],
                capture_output=True, text=True,
                timeout=TRACE_TIMEOUT + 4, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            r = None
        body = (r.stdout if r else "") or ""
        if r is not None and r.returncode == 0 and "colo=" in body:
            m_colo = re.search(r"^colo=(\w+)", body, flags=re.MULTILINE)
            m_loc = re.search(r"^loc=(\w+)", body, flags=re.MULTILINE)
            return (
                m_colo.group(1) if m_colo else None,
                m_loc.group(1) if m_loc else None,
                "warp=on" in body,
                None,
            )
        if r is None:
            last_err = "curl timeout"
        elif r.returncode == 0:
            last_err = "no colo= in trace"
        else:
            lines = (r.stderr or "").strip().splitlines()
            last_err = lines[-1] if lines else f"curl rc={r.returncode}"
        if attempt < TRACE_RETRIES - 1:
            time.sleep(TRACE_RETRY_PAUSE)
    return None, None, False, last_err


# ── MTProto-проба 5 ДЦ через wg-scout ────────────────────────────────────
def _tg_probe_via(scout_ip: str) -> dict:
    """Все 5 ДЦ Telegram параллельно, сокеты биндятся к адресу wg-scout
    (см. докстринг модуля: from-правило приоритетом 140 уводит их через
    КАНДИДАТА мимо telemt-fwmark). Формат ответа — как у
    warp_telegram_probe.probe_all_dcs()."""
    from chimera.modules.warp_telegram_probe import (
        TELEGRAM_DCS, TG_DC_PORT, probe_dc,
    )
    result: dict = {
        "ok": False, "reached_mask": 0, "reached_names": [],
        "missing_names": [n for n, _ in TELEGRAM_DCS], "worst_rtt_ms": None,
    }
    with ThreadPoolExecutor(max_workers=len(TELEGRAM_DCS)) as pool:
        futures = {
            pool.submit(probe_dc, ip, TG_DC_PORT, TG_PROBE_TIMEOUT_S, scout_ip):
                (i, name)
            for i, (name, ip) in enumerate(TELEGRAM_DCS)
        }
        for future, (i, name) in futures.items():
            try:
                answered, rtt = future.result()
            except Exception:
                answered, rtt = False, None
            if answered:
                result["reached_mask"] |= 1 << i
                if rtt is not None and (
                    result["worst_rtt_ms"] is None or rtt > result["worst_rtt_ms"]
                ):
                    result["worst_rtt_ms"] = rtt
    # имена пересчитываем по маске — надёжнее, чем вести список параллельно
    result["reached_names"] = [
        n for i, (n, _ip) in enumerate(TELEGRAM_DCS)
        if result["reached_mask"] >> i & 1
    ]
    result["missing_names"] = [
        n for i, (n, _ip) in enumerate(TELEGRAM_DCS)
        if not (result["reached_mask"] >> i & 1)
    ]
    result["ok"] = result["reached_mask"] == (1 << len(TELEGRAM_DCS)) - 1
    if result["worst_rtt_ms"] is not None:
        result["worst_rtt_ms"] = round(result["worst_rtt_ms"], 1)
    return result


def _tg_cell(tg: Optional[dict]) -> str:
    """Клетка таблицы: «5/5» / «3/5» / «—» (не пробовали)."""
    if not tg:
        return "—"
    total = 5
    reached = bin(tg.get("reached_mask", 0)).count("1")
    return f"{reached}/{total}"


# ── Полная проба кандидата через временный wg-scout ──────────────────────
def _default_route() -> Optional[list[str]]:
    """Аргументы исходного шлюза из `ip route show default`:
    ['via', gw, 'dev', if] / ['dev', if] / None. Нужен, чтобы UDP-хендшейк
    до КАНДИДАТА не заворачивался в прод wg-warp при активном FULL."""
    r = _ip(["ip", "route", "show", "default"])
    for line in (r.stdout or "").splitlines():
        if line.startswith("default"):
            parts = line.split()
            out: list[str] = []
            if "via" in parts:
                out += ["via", parts[parts.index("via") + 1]]
            if "dev" in parts:
                out += ["dev", parts[parts.index("dev") + 1]]
            if out:
                return out
    return None


def _live_tunnel_v4() -> Optional[str]:
    """IPv4 с живого интерфейса wg-warp — на случай, когда адрес есть на
    интерфейсе, но в конфиге его нет (добавлен руками/скриптом)."""
    r = _ip(["ip", "-4", "addr", "show", "dev", _warp.WG_INTERFACE])
    m = re.search(r"inet (\d+(?:\.\d+){3})", r.stdout or "")
    return m.group(1) if m else None


def _probe_v4_source(fields: dict) -> tuple[Optional[str], str]:
    """IPv4-адрес для wg-scout и готовое пояснение, откуда он взялся:
    1) Address из конфига wg-warp;
    2) адрес живого интерфейса (конфиг addressless, адрес добавлен руками);
    3) стандартный туннельный IPv4 WARP 172.16.0.2 — wgcf-регистрации
       получают его практически всегда; тот же fallback уже использует
       экспорт mihomo (warp._export_warp_mihomo_proxy).
    Живой кейс (3): нода БЕЗ родного IPv6 поднимает WARP ради v6 —
    конфиг IPv6-only, IPv4-строки в нём нет вовсе, но ключи wgcf те же,
    и хендшейк с КАНДИДАТОМ честно проверяет именно этот аккаунт.
    Если CF не примет адрес — trace промолчит и строка уйдёт в серые
    («проба не прошла»), что и будет правдой."""
    v4, _v6 = _warp._warp_addr_v4_v6(fields)
    if v4:
        return v4, ""
    v4 = _live_tunnel_v4()
    if v4:
        return v4, (f"В конфиге wg-warp нет IPv4-адреса туннеля — проба с "
                    f"адреса живого интерфейса {_warp.WG_INTERFACE}: {v4}.")
    return "172.16.0.2", (
        "В конфиге wg-warp нет IPv4-адреса туннеля (IPv6-only — WARP "
        "поднят ради v6?) и на интерфейсе его тоже нет. Проба со "
        "стандартным IPv4 WARP 172.16.0.2 (тот же fallback, что в экспорте "
        "mihomo); если CF его не примет — строки уйдут в серые «проба не "
        "прошла».")


def probe_endpoint_egress(row: dict, fields: dict, with_tg: bool = True) -> dict:
    """Проба ОДНОГО кандидата через временный интерфейс wg-scout:
    handshake + trace (colo/loc/warp) [+ MTProto 5 ДЦ].

    row — строка из aggregate_best_per_subnet; результат — её копия,
    дополненная ключами colo / loc / warp_on / trace_err (причина
    «нет trace», см. _trace_via) / probe_ok / tg (dict пробы)
    / tg_cell. IPv4 туннеля берётся из конфига, а при его отсутствии —
    с живого wg-warp или стандартный 172.16.0.2 (см. _probe_v4_source):
    IPv6-only-конфиг больше не отменяет пробу. Trace идёт bind'ом по
    этому АДРЕСУ (from-правило 140 → таблица 303 → wg-scout — тот же
    путь, что у MTProto-проб; путь поднимается всегда, не только при
    with_tg). Все временные маршруты/правила/интерфейс снимаются в
    finally, поэтому функция безопасна при Ctrl+C и исключениях."""
    out = dict(row)
    out.update({
        "colo": None, "loc": None, "warp_on": False, "probe_ok": False,
        "trace_err": None, "tg": None, "tg_cell": "—",
    })
    endpoint = row.get("endpoint")
    if not endpoint or ":" not in endpoint:
        return out
    host, _port = endpoint.rsplit(":", 1)
    v4, _src = _probe_v4_source(fields)

    keyfile: Optional[str] = None
    del_rules: list[list] = []        # ip rule del (снимаются первыми)
    del_routes: list[list] = []       # наши host-маршруты
    restore_routes: list[list] = []   # прежние маршруты, которые затёрли replace
    try:
        # 1. временный файл ключа (wg set принимает только путь)
        fd, keyfile = tempfile.mkstemp(prefix="wgscout-", suffix=".key")
        with os.fdopen(fd, "w") as f:
            f.write(fields["private_key"] or "")
        os.chmod(keyfile, 0o600)

        # 2. интерфейс + peer (allowed-ips 0.0.0.0/0 — маршрутизацию делаем сами)
        r_link = _ip(["ip", "link", "add", SCOUT_IFACE, "type", "wireguard"])
        if r_link.returncode != 0:
            _warp.warn(f"Не удалось создать {SCOUT_IFACE}: {r_link.stderr}")
            return out
        _ip(["wg", "set", SCOUT_IFACE, "listen-port", "0",
             "private-key", keyfile, "peer", fields["public_key"],
             "endpoint", endpoint, "allowed-ips", "0.0.0.0/0"])
        _ip(["ip", "addr", "add", f"{v4}/32", "dev", SCOUT_IFACE])
        # MTU как у прода: путь до кандидата уже проверен прод-туннелем с
        # этим MTU (wgcf обычно 1280) — большие пакеты по «узкому» пути
        # душат trace TLS-хендшейком.
        mtu = str(fields.get("mtu") or "").strip()
        if mtu.isdigit():
            _ip(["ip", "link", "set", SCOUT_IFACE, "mtu", mtu])
        _ip(["ip", "link", "set", SCOUT_IFACE, "up"])

        # 3. host-маршрут до кандидата через исходный шлюз (только если FULL
        #    сейчас заворачивает его /1-маршрутом в прод-туннель)
        r_get = _ip(["ip", "route", "get", host])
        if _warp.WG_INTERFACE in (r_get.stdout or ""):
            gw = _default_route()
            if gw:
                _ip(["ip", "route", "add", f"{host}/32"] + gw)
                del_routes.append(["ip", "route", "del", f"{host}/32"])
            else:
                _warp.info("Исходный шлюз не определён — хендшейк может пойти "
                           "через прод-туннель (FULL).")

        # 4. trace-маршрут 1.1.1.1/32 через wg-scout (replace; прежний /32 —
        #    восстановить). SELECTIVE с 1.1.1.1 в списках — тот самый случай.
        r_prev = _ip(["ip", "route", "show", "1.1.1.1/32"])
        prev = (r_prev.stdout or "").strip().splitlines()
        prev_line = prev[0].strip() if prev else ""
        _ip(["ip", "route", "replace", "1.1.1.1/32", "dev", SCOUT_IFACE])
        del_routes.append(["ip", "route", "del", "1.1.1.1/32", "dev", SCOUT_IFACE])
        if prev_line and SCOUT_IFACE not in prev_line:
            restore_routes.append(["ip", "route", "add"] + prev_line.split())

        # 5. from-правило 140 + default в 303 — ОБЩИЙ путь ОБЕИХ проб:
        #    trace (curl --interface <v4>: bind по адресу — см. _trace_via,
        #    резолв/прокси-окружение больше не ломают его) и MTProto
        #    (probe_dc(bind_to=v4)). Ставится ВСЕГДА, не только с with_tg.
        _ip(["ip", "route", "replace", "default", "dev", SCOUT_IFACE,
             "table", str(SCOUT_TABLE)])
        _ip(["ip", "rule", "add", "from", v4, "lookup", str(SCOUT_TABLE),
             "priority", str(SCOUT_RULE_PRIORITY)])
        del_rules.append(["ip", "rule", "del", "from", v4,
                          "lookup", str(SCOUT_TABLE),
                          "priority", str(SCOUT_RULE_PRIORITY)])

        # 6. trace (первая попытка ждёт хендшейк; bind по АДРЕСУ wg-scout)
        #    + MTProto по тому же from-правилу
        colo, loc, warp_on, trace_err = _trace_via(SCOUT_IFACE, src=v4)
        out.update({"colo": colo, "loc": loc, "warp_on": warp_on,
                    "trace_err": trace_err})
        out["probe_ok"] = colo is not None and warp_on
        if with_tg:
            tg = _tg_probe_via(v4)
            out["tg"] = tg
            out["tg_cell"] = _tg_cell(tg)
        return out
    finally:
        # Правила снимаются первыми (матчат src, независимы от интерфейса).
        for args in del_rules:
            _ip(args)
        for args in del_routes:
            _ip(args)
        for args in restore_routes:
            _ip(args)
        # Удаление интерфейса снимает и остатки маршрутов на нём (в т.ч.
        # default в таблице 303) — но 303-таблицу чистим и явно, на всякий.
        _ip(["ip", "link", "del", SCOUT_IFACE])
        _ip(["ip", "route", "del", "default", "dev", SCOUT_IFACE,
             "table", str(SCOUT_TABLE)])
        if keyfile:
            try:
                os.unlink(keyfile)
            except OSError:
                pass


# ── Ре-хендшейк прод-туннеля после пробы ─────────────────────────────────
def rehandshake_prod() -> None:
    """CF-сервер после хендшейков wg-scout считает источником наш ephemeral
    порт (роуминг), прод-сессия мертва до REKEY_AFTER_TIME (~120 с).
    Лечится рестартом wg-quick@wg-warp (~2 сек): конфиг не менялся,
    Table=off → wg-quick не трогает main-таблицу, маршруты переприменяет
    _apply_mode (тот же порядок, что в _change_warp_endpoint)."""
    if not _warp._warp_service_active():
        return
    _warp.info("Возвращаю основной туннель wg-warp (CF видел «роуминг» с "
               f"{SCOUT_IFACE})...")
    _warp._run(["systemctl", "restart", _warp.WG_SERVICE],
               capture=True, check=False)
    time.sleep(2)
    colo, _loc, warp_on, err = _trace_via(_warp.WG_INTERFACE)
    mode = _warp._state_get("WARP_MODE", _warp.MODE_FULL) or _warp.MODE_FULL
    _warp._apply_mode(
        mode,
        _warp._state_get("WARP_SSH_CLIENT_IP", ""),
        _warp._state_get("WARP_CUSTOM_IPS", []),
        _warp._state_get("WARP_CUSTOM_DOMAINS", []),
    )
    if warp_on:
        _warp.success(f"Туннель wg-warp восстановлен (warp=on" +
                      (f", нода {colo})" if colo else ")") + ".")
    else:
        extra = f" ({err})" if err else ""
        _warp.warn(f"После рестарта trace не подтвердил warp=on{extra} — "
                   "проверьте диагностику (меню WARP → пункт 4).")


# ── Рендер таблицы ───────────────────────────────────────────────────────
def render_subnet_table(rows: list[dict], blacklist: list[str],
                        probed: bool) -> list[str]:
    """Строки таблицы «лучший эндпоинт на подсеть» (выравнивание по len(),
    строки с нодой из чёрного списка — красные, TG 5/5 — зелёные клетки).
    Вызыватель печатает их ВНЕ рамки (широкий контент — паттерн «ссылки
    вне рамок» из mieru v87)."""
    if not rows:
        return ["  (нет отвечающих подсетей)"]

    headers = ["#", "ПОДСЕТЬ", "ENDPOINT", "RTT", "ВЫХОД", "НОДА",
               "ЛОКАЦИЯ НОДЫ", "TG"]
    table: list[list[str]] = []
    for i, r in enumerate(rows, start=1):
        rtt = r.get("rtt_ms")
        rtt_s = f"{rtt:.0f} мс" if isinstance(rtt, (int, float)) else "—"
        colo = r.get("colo")
        loc = r.get("loc")
        city = colo_city(colo)
        tg = r.get("tg_cell", "—")
        table.append([
            str(i), r.get("subnet", "?"), r.get("endpoint", "?"), rtt_s,
            (loc or "?") if probed else "·",
            (colo or "?") if probed else "·",
            city if probed else "·",
            tg if probed else "·",
        ])
    widths = []
    for j in range(len(headers)):
        w = len(_plain(headers[j]))
        for row in table:
            w = max(w, len(_plain(row[j])))
        widths.append(w)

    def fmt(cells: list[str]) -> str:
        return "  ".join(_plain(c).ljust(widths[j]) for j, c in enumerate(cells))

    lines = [f"  {fmt(headers)}", "  " + "  ".join("─" * w for w in widths)]
    for i, row in enumerate(table):
        line = fmt(row)
        bl = probed and rows[i].get("colo") in (blacklist or [])
        tg_ok = probed and rows[i].get("tg_cell") == "5/5"
        if bl:
            line = f"{RED}{line}  ⚠ ЧС{NC}"
        elif tg_ok:
            # зелёным только хвост «TG 5/5» — строка остаётся читаемой
            head = line[: len(line) - len(_plain(row[-1]))]
            line = f"{head}{GREEN}{row[-1]}{NC}"
        elif probed and not rows[i].get("probe_ok", False):
            line = f"{DIM}{line}{NC}"
        lines.append(f"  {line}")
    lines.append("")
    if probed:
        lines.append(f"  {DIM}ЧС — нода в чёрном списке colo (применение "
                     f"закончится автооткатом); серые строки — проба не "
                     f"прошла; TG — ответившие ДЦ Telegram из 5.{NC}")
    else:
        # быстрый режим: без этой подсказки колонки «·» выглядят ошибкой
        lines.append(f"  {DIM}«·» — не пробовалось. Клавиша P в промпте ниже: "
                     f"хендшейк wg-scout + trace (нода/локация) + Telegram "
                     f"для каждой строки, без пересканирования.{NC}")
    return lines


# ── Сводка статуса над таблицей ──────────────────────────────────────────
def _status_line(rows: list[dict], probed: bool) -> str:
    if not probed:
        return f"Подсетей: {len(rows)} (быстрый режим — без проб нод)"
    colos = sorted({r["colo"] for r in rows if r.get("colo")})
    locs = sorted({r["loc"] for r in rows if r.get("loc")})
    working = sum(1 for r in rows if r.get("probe_ok"))
    tg_ok = sum(1 for r in rows if r.get("tg_cell") == "5/5")
    parts = [
        f"Рабочие: {working}/{len(rows)}",
        f"Ноды: {', '.join(colos) or '—'}",
        f"Выход: {', '.join(locs) or '—'}",
        f"Telegram 5/5: {tg_ok}",
    ]
    return "   ·   ".join(parts)


# ── Полная проба всех строк (общий код Y-режима и клавиши P) ────────────
def _probe_all_rows(rows: list[dict], fields: dict) -> None:
    """Пробит каждую строку через wg-scout in-place (хендшейк + trace +
    Telegram), с прогрессом по строкам. Ctrl+C — частичные результаты
    (успевшие строки уже дописаны в rows). В finally — ре-хендшейк
    прод-туннеля, если он был активен: CF после проб видит «роуминг»."""
    was_active = _warp._warp_service_active()
    _v4, v4_note = _probe_v4_source(fields)
    if v4_note:
        # один раз на весь проход, а не «нет IPv4» на каждой строке
        _warp.info(v4_note)
    _warp.info(f"Поднимаю {SCOUT_IFACE} на ключах wgcf по очереди для "
               f"каждой подсети (Ctrl+C — прервать и показать что есть)...")
    try:
        for i, row in enumerate(rows, start=1):
            end = row["endpoint"]
            print(f"  [{i}/{len(rows)}] {end} ...", end="", flush=True)
            res = probe_endpoint_egress(row, fields, with_tg=True)
            rows[i - 1] = res
            tail = []
            if res.get("colo"):
                tail.append(f"{res['colo']} {res['loc'] or ''}".strip())
            else:
                err = (res.get("trace_err") or "").strip()
                # причина видна сразу — больше не «?» без объяснений
                tail.append(f"нет trace ({err[:80]})" if err else "нет trace")
            if res.get("tg") is not None:
                tail.append(f"TG {res['tg_cell']}")
            print("  →  " + ", ".join(t for t in tail if t))
    except KeyboardInterrupt:
        _warp.warn("\nПроба прервана — показываю то, что успело пробиться.")
    finally:
        if was_active:
            try:
                rehandshake_prod()
            except Exception as e:
                _warp.warn(f"Ре-хендшейк wg-warp не удался: {e} — "
                           f"проверьте диагностику (меню WARP → 4).")


# ── Экран таблицы (clear + шапка + рендер) ────────────────────────────────
def _render_table_screen(rows: list[dict], probed: bool) -> None:
    """clear + рамка-шапка + таблица. Текст шапки ЗАВИСИТ от режима:
    быстрый честно говорит, что хендшейков не было и колонки пусты
    (иначе «trace отдаёт ноду» в шапке выглядит ошибкой — живой кейс
    юзера: «данных нет никаких кроме задержки»)."""
    os.system("clear")
    _box_top("ТАБЛИЦА ПОДСЕТЕЙ WARP — лучший эндпоинт на /24")
    _box_row()
    if probed:
        _box_row("  Порт идеи warpscout: каждый /24 проверен хендшейком wg-scout")
        _box_row("  (те же ключи wgcf), trace отдаёт ноду выхода и локацию.")
    else:
        _box_row("  Быстрый режим: только RTT массового TCP-скана, "
                 f"хендшейков wg-scout не было.")
        _box_row("  Колонки ВЫХОД/НОДА/ЛОКАЦИЯ/TG заполняются полной "
                 "пробой —")
        _box_row("  клавиша P в промпте ниже (прод wg-warp мигнёт ~2 с), "
                 "или Y на")
        _box_row("  вопросе о пробе при следующем запуске.")
    _box_row()
    _box_row(f"  {_status_line(rows, probed)}")
    _box_bottom()
    print()
    title = ("Лучший эндпоинт на подсеть (наименьший RTT" +
             (", проба нод + Telegram)" if probed else ", без проб нод):"))
    print(f"  {CYAN}{title}{NC}")
    for line in render_subnet_table(rows, _warp._colo_blacklist(), probed):
        print(line)
    print()


# ── Интерактивный флоу (пункт 8 Endpoint Manager) ────────────────────────
def run_subnet_table_flow() -> None:
    """Скан → (по желанию) полная проба каждой /24 → таблица → выбор и
    применение эндпоинта через штатный _change_warp_endpoint (со всей
    пост-примен верификацией: colo-чёрный список + MTProto + watchdog).
    Быстрый режим (n) допробивается прямо у таблицы клавишей P —
    без пересканирования, по уже найденным строкам."""
    os.system("clear")
    fields = _warp._parse_wg_config_fields()
    if not fields:
        _box_top("ТАБЛИЦА ПОДСЕТЕЙ WARP (ноды выхода + Telegram)")
        _box_row()
        _box_row(f"  {RED}WARP не установлен{NC} — сначала установите "
                 f"(меню WARP → пункт 1).")
        _box_row()
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    # Пулы скана: восстановить cron автообновления / подтянуть протухший
    # кэш warpscout (тихо; сбой сети не отменяет скан — статика остаётся).
    _warp.ensure_pools_ready()

    _warp.info("Сканирую диапазоны WARP (массовый TCP-зонд, ~15–30 с)...")
    try:
        results = _warp._scan_warp_endpoints(top=None)
    except KeyboardInterrupt:
        results = []
    if not results:
        _warp.warn("Скан не нашёл отвечающих узлов.")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    # топ-5 — в кэш Endpoint Manager (пункт «выбрать из кэша» остаётся живым)
    _warp._endpoint_cache_save(results[:5], valid=True)

    rows = aggregate_best_per_subnet(results)
    _warp.info(f"Подсетей с отвечающими узлами: {len(rows)}.")

    probed = False
    answer = input(
        f"{YELLOW}Пробить ноду выхода и Telegram для каждой подсети? "
        f"(~{max(4, len(rows) * 4)} с, прод wg-warp мигнёт ~2 с; «n» — только "
        f"RTT, колонки нод будут пусты) [Y/n]:{NC} "
    ).strip().lower()
    if answer in ("", "y", "д", "yes", "да"):
        probed = True
        _probe_all_rows(rows, fields)

    # Экран можно перерисовывать: P допробит строки и вернётся к выбору.
    while True:
        _render_table_screen(rows, probed)
        if not rows:
            input(f"{BLUE}Нажмите Enter...{NC}")
            return
        p_hint = "" if probed else "P — допробить ноды, "
        choice = input(
            f"{CYAN}Номер для применения ({p_hint}Enter — выйти):{NC} "
        ).strip()
        if not choice:
            return
        # «p» латиницей; «з» — та же клавиша на RU-раскладке; «п» — «проба»
        if not probed and choice.lower() in ("p", "з", "п"):
            probed = True
            _probe_all_rows(rows, fields)
            continue
        if not choice.isdigit() or not (1 <= int(choice) <= len(rows)):
            _warp.warn("Неверный номер.")
            return
        idx = int(choice) - 1
        chosen = rows[idx]["endpoint"]
        if probed and rows[idx].get("colo") in _warp._colo_blacklist():
            _warp.warn(f"Нода {rows[idx]['colo']} в чёрном списке — "
                       f"применение завершится автооткатом.")
        if input(f"{YELLOW}Применить Endpoint {chosen}? [y/N]:{NC} ").strip().lower() == "y":
            _warp._change_warp_endpoint(chosen)
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

