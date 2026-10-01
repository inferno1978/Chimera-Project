"""
chimera/modules/mieru_dpi.py
───────────────────────────────────────────────────────────────────────────────
Mieru + B4 — DPI bypass через Mieru-транспорт (паритет Xray-связки).

КОНЦЕПЦИЯ
─────────
b4 процессо-агностичен: перехват идёт по адресам назначения через
NFQUEUE в OUTPUT — демону безразлично, кто открыл соединение
(freedom-outbound Xray, curl или mita). Серверная часть ОБЩАЯ с
Xray-связкой (dpi_bypass.py): те же сеты, та же панель, тот же
Discovery. Отличие — в маршрутизации:

  Xray-связка (dpi_bypass)            Mieru-связка (этот модуль)
  ──────────────────────────────      ──────────────────────────────
  домены сетов b4 → Xray routing      домены сетов b4 → клиентские
  (outbound:direct на сервере)        конфиги: domain_suffix →
                                       mieru-outbound (выход через mita)

Схема работы:

  Клиент (Karing/sing-box/Nekobox)
      │ mTLS + random padding (ТСПУ нечем дышать: нет SNI/JA3)
      ▼
  mita (RU-нода, /usr/local/bin/mita, systemd mita)
      │ dial цели напрямую с ноды
      │ iptables mangle OUTPUT → NFQUEUE
      ▼
  b4 (fake SNI + фрагментация ClientHello + fake RST)
      ▼
  ТСПУ не сопоставляет SNI → пропускает → цель видит RU-IP

ПАРИТЕТ ФУНКЦИЙ С dpi_bypass (Xray-связкой)
───────────────────────────────────────────
  • Импорт кастомного сета (JSON) — переиспользуется dpi_bypass.
    import_custom_set: REST hot-reload (TUI → панель), экспорт из
    Web UI (панель → TUI) — синхронизация «во все стороны» работает
    по построению: TUI и панель управляют ОДНИМ демоном b4.
  • Discovery — dpi_bypass.run_discovery.
  • «Синхронизировать домены b4 → …» ([S] в dpi_bypass) — здесь
    sync_b4_to_mieru(): домены всех enabled-сетов → state →
    клиентские конфиги (подписка обеих веток + split-конфиг меню).
  • Health check — health_check_mieru(): mita + время (±30 c) +
    b4 + YouTube-проба + E2E `mieru test` реальным клиентом.
  • Кастомные ресурсы «не только YouTube» — любые домены в сетах b4;
    после синка они попадают в клиентскую маршрутку автоматически.

ИНТЕГРАЦИЯ
──────────
  • Меню: раздел сети → [MB] «Mieru + B4» (рядом с [B] DPI Bypass,
    [Y] YouTube через RU — похожие фичи в одном месте).
  • Подписка format=singbox, мульти-нодовая ветка
    (subscription_multinode.build_singbox_config): mieru-outbound'ы в
    главном selector и Streaming-группе; route-правило b4-доменов →
    mieru стоит ВЫШЕ geosite-правил (кастомные ресурсы приоритетнее
    категорий); домен mita защищён protect-правилом.
  • Подписка, одиночная ветка (subscription.build_subscription_
    singbox_config): route.rules с теми же доменами → mieru-outbound.
  • Обратная совместимость: режим ВЫКЛ по умолчанию — без
    mieru_dpi.json/is_mieru_dpi_active()=False конфиги подписки
    байт-в-байт прежние (is_mieru_dpi_active проверяет и enabled,
    и установленность mita — удаление mieru автоматически выключает
    маршрутизацию в подписке без orphan-правил).

STATE
─────
/var/lib/xray-installer/mieru_dpi.json:
  {
    "enabled": true,
    "route_domains": ["youtube.com", ...],   # домены → mieru-outbound
    "synced_sets":   ["custom-abc", ...],    # id сетов на момент синка
    "last_sync":     "2026-09-21T12:00:00"
  }
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Цвета (как в dpi_bypass.py / mieru.py) ────────────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(
            RED='\033[31m', GREEN='\033[32m', YELLOW='\033[33m',
            CYAN='\033[36m', BOLD='\033[1m', DIM='\033[2m',
            WHITE='\033[37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN',
                            'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, WHITE, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'],
    _C['BOLD'], _C['DIM'], _C['WHITE'], _C['NC'],
)

# ── Логирование (единый формат проекта) ───────────────────────────────────
_LOG_FILE = Path("/var/log/chimera.log")

def _log(level: str, msg: str) -> None:
    try:
        clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] "
                    f"[mieru_dpi] [{level}] {clean}\n")
    except Exception:
        pass

def _info(msg): print(f"{CYAN}[INFO]{NC}  {msg}"); _log("INFO", msg)
def _ok(msg):   print(f"{GREEN}[OK]{NC}    {msg}");   _log("OK", msg)
def _warn(msg): print(f"{YELLOW}[WARN]{NC}  {msg}");  _log("WARN", msg)
def _err(msg):  print(f"{RED}[ERR]{NC}   {msg}");    _log("ERR", msg)

# ── box_renderer (общий UI) ───────────────────────────────────────────────
from chimera.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_item_exit,
    _box_back, _box_info, _box_warn, _box_ok, _box_link, _box_desc,
)

# ── proto_common (state-хелперы, как в mieru.py) ──────────────────────────
from chimera.modules.proto_common import (
    ProtoCancelled, proto_load_state, proto_save_state, proto_ask,
)

# ══════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════
_STATE_FILE      = Path("/var/lib/xray-installer/mieru_dpi.json")
_MIERU_STATE     = Path("/var/lib/xray-installer/mieru.json")
_MITA_SERVICE    = "mita"
_MIERU_BIN       = Path("/usr/local/bin/mieru")
_E2E_START_TIMEOUT = 15   # c: ожидание подъёма демона зонда (socks5-порт)
# split-JSON экрана [6]: сохраняется файлом (scp/sftp целиком, без
# копирования из терминала); отдельная константа — для патчей в тестах
_SPLIT_CFG_PATH  = Path("/tmp/mieru-split-karing.json")
# NyameBox-вариант split-конфига (ядро 1.13.x): тот же сплит, другой
# формат DNS/полей — отдельный файл, чтобы Karing/NyameBox не
# перезатирали друг друга при scp
_NYAME_CFG_PATH  = Path("/tmp/mieru-split-nyamebox.json")
# Конвенция приложения NyameBox/Iblis (qr243vbi/nekobox): при старте
# Custom-профиля ВСЕ не-fakeip DNS-серверы заменяются на remote_dns
# приложения с жёстко зашитым detour="proxy" — главный outbound
# ОБЯЗАН носить этот тег (ConfigBuilder.cpp:118, разбор 01.10.2026)
_NYAMEBOX_PROXY_TAG = "proxy"

# ── Ленивые импорты тяжёлых соседей (без циклов на уровне модуля) ─────────
def _dpi():
    """dpi_bypass — серверная часть b4 (общая с Xray-связкой)."""
    from chimera.modules import dpi_bypass
    return dpi_bypass

def _mieru():
    """mieru — генераторы клиентских конфигов/ссылок, пресеты."""
    from chimera.modules import mieru
    return mieru

# ══════════════════════════════════════════════════════════════════════════
#  STATE
# ══════════════════════════════════════════════════════════════════════════
def _load_state() -> dict:
    return proto_load_state(_STATE_FILE, defaults={
        "enabled": False,
        "route_domains": [],
        "synced_sets": [],
        "last_sync": "",
    })

def _save_state(state: dict) -> None:
    proto_save_state(_STATE_FILE, state)

def _load_mieru_state() -> dict:
    """Стейт standalone-Mieru (mieru.json): installed/порты/юзеры/preset."""
    try:
        return proto_load_state(_MIERU_STATE)
    except Exception:
        return {}

# ══════════════════════════════════════════════════════════════════════════
#  СТАТУСЫ
# ══════════════════════════════════════════════════════════════════════════
def _mita_service_active() -> bool:
    r = subprocess.run(["systemctl", "is-active", "--quiet", _MITA_SERVICE],
                       capture_output=True, check=False, timeout=10)
    return r.returncode == 0

def _mita_port_listening(port: int, protocol: str = "tcp") -> bool:
    """mita слушает порт (ss, без root-полей: -tln/-uln)."""
    flag = "-tln" if protocol.lower() == "tcp" else "-uln"
    try:
        r = subprocess.run(["ss", flag], capture_output=True, text=True,
                           check=False, timeout=10)
        return f":{port} " in (r.stdout or "")
    except Exception:
        return False

def _mita_status() -> dict:
    """Сводка mita: installed/service/ports/users/preset."""
    st = _load_mieru_state()
    installed = bool(st.get("installed")) and Path("/usr/local/bin/mita").exists()
    protocol = (st.get("protocol") or "TCP").upper()
    return {
        "installed": installed,
        "service_active": _mita_service_active() if installed else False,
        "port_start": st.get("port_start") or 0,
        "port_end": st.get("port_end") or 0,
        "protocol": protocol,
        "users": len(st.get("users") or []),
        "traffic_preset": st.get("traffic_preset") or "basic",
        "client_server_addr": (st.get("client_server_addr") or "").strip(),
    }

def is_mieru_dpi_active() -> bool:
    """Режим включён И standalone-Mieru установлен.

    Единая точка правды для подписки (обе ветки) и генераторов:
    False → конфиги не меняются вовсе (обратная совместимость).
    Удаление/снос Mieru автоматически гасит маршрутизацию —
    orphan-правил на mieru-outbound в подписке не остаётся."""
    try:
        if not _load_state().get("enabled"):
            return False
    except Exception:
        return False
    st = _load_mieru_state()
    return bool(st.get("installed"))

def get_route_domains() -> list:
    """Домены для клиентской маршрутки (из state, без обращения к b4)."""
    try:
        return sorted(set(_load_state().get("route_domains") or []))
    except Exception:
        return []

# ══════════════════════════════════════════════════════════════════════════
#  СБОР ДОМЕНОВ ИЗ b4-СЕТОВ
# ══════════════════════════════════════════════════════════════════════════
def _normalize_domain(raw) -> Optional[str]:
    """'*.example.com' → 'example.com'; catch-all/мусор → None.

    sing-box domain_suffix матчит поддомены суффиксом — apex даёт
    тот же эффект, что wildcard в b4."""
    d = str(raw or "").strip().lower().lstrip(".")
    if not d or "*" in d or "/" in d or " " in d:
        # "*.x" → берём хвост после звезды
        if d.startswith("*."):
            d = d[2:]
            if d and "*" not in d and "/" not in d:
                return d
        return None
    if not re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", d):
        return None
    return d

def collect_b4_domains() -> tuple:
    """Домены всех enabled b4-сетов → (domains, set_ids).

    Источник — dpi_bypass._detect_sets() (тот же, что читает меню
    [S] «синк b4 → Xray routing»): сеты из config.json b4."""
    out, set_ids = [], []
    try:
        sets = _dpi()._detect_sets()
    except Exception as e:
        _log("WARN", f"collect_b4_domains: {e}")
        return [], []
    for s in sets:
        if not s.get("enabled", False):
            continue
        sid = s.get("id") or ""
        if sid:
            set_ids.append(sid)
        for raw in (s.get("domains") or []):
            d = _normalize_domain(raw)
            if d:
                out.append(d)
    return sorted(set(out)), sorted(set(set_ids))

def sync_b4_to_mieru() -> dict:
    """[S]-эквивалент для Mieru: домены enabled-сетов b4 → state.

    После синка домены попадают:
      • в подписку format=singbox (обе ветки: мульти-нодовая и одиночная)
        — route-правила domain_suffix → mieru-outbound;
      • в split-конфиг меню [6] (домены → mieru, остальное → direct).
    Returns: {"domains": int, "sets": int, "changed": bool}"""
    domains, set_ids = collect_b4_domains()
    state = _load_state()
    changed = (sorted(state.get("route_domains") or []) != domains)
    state["route_domains"] = domains
    state["synced_sets"] = set_ids
    state["last_sync"] = datetime.now().isoformat(timespec="seconds")
    _save_state(state)
    _log("OK", f"sync_b4_to_mieru: {len(domains)} доменов из {len(set_ids)} сетов")
    return {"domains": len(domains), "sets": len(set_ids), "changed": changed}

def enable() -> dict:
    """Включить режим: флаг + синк доменов b4 → клиентские конфиги."""
    state = _load_state()
    state["enabled"] = True
    _save_state(state)
    return sync_b4_to_mieru()

def disable() -> bool:
    """Выключить режим (b4 и mita не трогаются)."""
    state = _load_state()
    state["enabled"] = False
    _save_state(state)
    _log("INFO", "mieru_dpi disabled")
    return True

# ══════════════════════════════════════════════════════════════════════════
#  КЛИЕНТСКИЕ КОНФИГИ
# ══════════════════════════════════════════════════════════════════════════
def build_mieru_route_rules(mieru_tag: str, domains: list) -> list:
    """sing-box route.rules: domain_suffix → mieru-outbound.

    Чистая функция — используется подпиской (обе ветки) и split-
    конфигом. Пустые домены/тег → [] (вызывающий не добавляет ничего)."""
    if not mieru_tag or not domains:
        return []
    return [{
        "domain_suffix": list(domains),
        "action": "route",
        "outbound": mieru_tag,
    }]

def build_karing_split_config() -> Optional[dict]:
    """Split-конфиг Karing/sing-box: домены b4 → mieru, остальное → direct.

    Собирается из state standalone-Mieru (порт/юзер/preset/адрес) теми
    же генераторами, что и обычная выдача mieru.py. None — Mieru не
    установлен или юзеров нет."""
    m = _mieru()
    st = _load_mieru_state()
    if not st.get("installed") or not (st.get("users") or []):
        return None
    u = st["users"][0]
    addr = (st.get("client_server_addr") or "").strip() or m._get_server_ip()
    port = int(st.get("port_start") or 2012)
    protocol = (st.get("protocol") or "TCP").upper()
    protocol = "TCP" if protocol == "BOTH" else protocol
    ob = m._gen_singbox_outbound(addr, port, port, protocol,
                                 u.get("username", "user"),
                                 u.get("password", ""))
    # traffic_pattern — синхронизация обфускации с сервером
    preset = st.get("traffic_preset")
    if preset and preset not in ("disabled",):
        try:
            from chimera.modules.mieru_traffic_presets import get_preset_base64
            b64 = get_preset_base64(preset)
            if b64:
                ob["traffic_pattern"] = b64
        except Exception:
            pass
    server_domain = addr if m._dns_host_is_domain(addr) else ""
    if server_domain:
        ob["domain_resolver"] = "local"
    domains = get_route_domains()
    rules = build_mieru_route_rules(ob["tag"], domains)
    cfg = {
        "log": {"level": "info"},
        "dns": m._build_karing_dns_block(
            (st.get("client_dns") or "").strip(), ob["tag"], server_domain),
        "outbounds": [ob, {"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    }
    if rules:
        cfg["route"]["rules"] = rules
    return cfg

def _nyamebox_dns_block(legacy_dns: dict, mieru_tag: str) -> dict:
    """Karing-DNS (legacy address-формат) → DNS sing-box 1.12+ для
    NyameBox-ядра (qr243vbi/nekobox, форк sing-box 1.13.19).

    Семантика та же: кастомный DNS через mieru-туннель, local —
    bootstrap напрямую. Отличия формата (пойманы живым nekobox_core
    5.11.28.3 / sing-box 1.13.19, check+run+E2E 01.10.2026):
      • type-серверы (https/udp) вместо address-строк — legacy
        deprecated с 1.12, вырезан в 1.14;
      • local БЕЗ detour: новый формат сам ходит direct, а явный
        detour на пустой direct-outbound ядро отвергает ПРИ СТАРТЕ
        (FATAL «detour to an empty direct outbound makes no sense»)
        — sing-box check это НЕ ловит, только run;
      • кастомный DNS: detour наследуется; при отсутствии (гугл-
        дефолт старого формата = дефолтный outbound = mieru)
        подставляем mieru_tag — в новом формате «без detour» =
        direct, что утекло бы мимо туннеля.
    """
    from urllib.parse import urlparse
    m = _mieru()
    servers = []
    for i, srv in enumerate(legacy_dns.get("servers") or []):
        addr = (srv.get("address") or "").strip()
        tag = srv.get("tag") or (f"custom-dns-{i + 1}" if i else "custom-dns")
        if not addr:
            continue
        u = urlparse(addr if "://" in addr else "//" + addr)
        is_local = srv.get("detour") == "direct" or tag == "local"
        if is_local:
            # bootstrap: direct по умолчанию, detour НЕ ставим (см. докстринг)
            servers.append({"type": "udp", "tag": tag,
                            "server": u.hostname or "1.1.1.1"})
            continue
        dtype = {"https": "https", "http": "http",
                 "quic": "quic", "h3": "h3"}.get((u.scheme or "").lower(), "udp")
        new = {"type": dtype, "tag": tag,
               "detour": srv.get("detour") or mieru_tag}
        if dtype == "udp":
            new["server"] = u.hostname or addr
        else:
            new["server"] = u.hostname
            if u.port:
                new["server_port"] = u.port
            if u.path and u.path != "/":
                new["path"] = u.path
            if m._dns_host_is_domain(u.hostname or ""):
                new["domain_resolver"] = "local"
        servers.append(new)
    block = {"servers": servers}
    if servers:
        block["final"] = servers[0]["tag"]
    if legacy_dns.get("rules"):
        block["rules"] = legacy_dns["rules"]  # формат dns.rules 1.12+ совместим
    return block

def build_nyamebox_split_config() -> Optional[dict]:
    """NyameBox-вариант split-конфига меню [6] (ядро sing-box 1.13.x).

    Отличия от Karing-варианта — формат И тег mieru-outbound.
    Формат: валидация nekobox_core 5.11.28.3 — sing-box check PASS
    без ворнингов; E2E socks-харнесс — маршрутка → mieru, финал →
    direct (HTTP 200). mieru-outbound БЕЗ mtu — релизное ядро поля
    не знает (strict-decode «unknown field»), дефолт mieru = 1400;
    поле есть только в master-ветке форка.

    Тег «proxy» — конвенция ПРИЛОЖЕНИЯ, не ядра (разбор активации
    01.10.2026, скриншот юзера «LoadConfig return error … transport
    must be TCP or UDP»):
      • при старте Custom-профиля приложение заменяет ВСЕ не-fakeip
        DNS-серверы на свой remote_dns с жёстко зашитым detour="proxy"
        (NormalizeFullConfigDnsForRuntime, ConfigBuilder.cpp:118) —
        тег из пасты («mieru-admin» и т.п.) оставил бы DNS в никуда;
      • импорт полного JSON через БУФЕР/ПОДПИСКУ дополнительно гонит
        конфиг через sanitizeSingBoxConfig (GroupUpdater.cpp:588),
        который ВЫРЕЗАЕТ у mieru поле transport (строка → toObject()
        → пусто → remove) — потому в инструкции только Add Profile →
        Custom Config, хранящий JSON без санитайза.
    """
    karing = build_karing_split_config()
    if karing is None:
        return None
    mieru_tag = next(o["tag"] for o in karing["outbounds"]
                     if o.get("type") == "mieru")
    # переименовываем тег + перевешиваем все ссылки на него
    outbounds = []
    for o in karing["outbounds"]:
        if o.get("type") == "mieru":
            o = {**o, "tag": _NYAMEBOX_PROXY_TAG}
        outbounds.append(o)
    rules = []
    for r in karing["route"].get("rules") or []:
        if r.get("outbound") == mieru_tag:
            r = {**r, "outbound": _NYAMEBOX_PROXY_TAG}
        rules.append(r)
    legacy_dns = karing.get("dns") or {}
    for srv in legacy_dns.get("servers") or []:
        if srv.get("detour") == mieru_tag:
            srv["detour"] = _NYAMEBOX_PROXY_TAG
    dns = _nyamebox_dns_block(legacy_dns, _NYAMEBOX_PROXY_TAG)
    first_tag = (dns.get("servers") or [{}])[0].get("tag", "")
    cfg = {
        "log": {"level": "info"},
        "dns": dns,
        "outbounds": outbounds,
        "route": {"final": "direct", "auto_detect_interface": True},
    }
    if first_tag:
        # явная фиксация неявного дефолта (первый DNS-сервер): без поля
        # ядро 1.12+ сыплет deprecation-WARN; семантику не меняет
        cfg["route"]["default_domain_resolver"] = first_tag
    if rules:
        cfg["route"]["rules"] = rules
    return cfg

def _mierus_links_for_state() -> list:
    """mierus://-выдача из state standalone-Mieru — по юзерам, с метками.

    Раньше возвращала плоский список ссылок без подписей: Karing- и
    Nekobox-форматы шли вперемешку, и на экране [6] было не понять,
    какую ссылку в какое приложение вставлять («какую сунуть в
    Nekobox?»). Теперь — запись на юзера×транспорт с обоими форматами
    под явными ключами:

    [{"user": "admin", "proto": "TCP",
      "karing":  "mierus://…?port=…&protocol=…",   # query-параметры
      "nekobox": "mierus://…:2012?transport=…"}, …]  # порт в host:порт

    Форматы ссылок не менялись — генераторы mieru.py как были."""
    m = _mieru()
    st = _load_mieru_state()
    if not st.get("installed") or not (st.get("users") or []):
        return []
    out = []
    addr = (st.get("client_server_addr") or "").strip() or m._get_server_ip()
    port = int(st.get("port_start") or 2012)
    protos = ("TCP", "UDP") if (st.get("protocol") or "TCP").upper() == "BOTH" \
        else ((st.get("protocol") or "TCP").upper(),)
    for u in st.get("users", []):
        uname = u.get("username", "")
        passwd = u.get("password", "")
        for proto in protos:
            link_addr = addr
            # UDP-транспорт в Karing — только IP (баг резолвера Karing,
            # см. mieru._karing_link_addr)
            if proto == "UDP" and m._dns_host_is_domain(addr):
                ip = m._karing_udp_server_ip()
                if ip:
                    link_addr = ip
            out.append({
                "user": uname,
                "proto": proto,
                "karing": m._gen_client_share_link(
                    link_addr, port, port, proto, uname, passwd,
                    traffic_preset=(st.get("traffic_preset") or "")),
                "nekobox": m._gen_client_share_link_nekobox(
                    link_addr, port, proto, uname, passwd),
            })
    return out

# ══════════════════════════════════════════════════════════════════════════
#  HEALTH CHECK (+ E2E через реальный mieru-клиент)
# ══════════════════════════════════════════════════════════════════════════
def _e2e_probe(url: str = "https://www.youtube.com") -> dict:
    """E2E-проба цепочки реальным mieru-клиентом.

    Поднимает ИЗОЛИРОВАННЫЙ клиент (HOME/XDG_CONFIG_HOME → temp,
    боевой конфиг ~/.config/mieru не трогается), применяет профиль с
    кредом первого юзера mita (trafficPattern — той же JSON-формой,
    что в server.json mita), затем `mieru start` (демон в фоне) и
    `mieru test <url>` — upstream-команду проверки связки
    (docs/client-install.md: «Connected to …» = клиент успешно
    соединился с сервером). test работает ТОЛЬКО через запущенного
    клиента — без start бинарник отвечает «mieru client is not
    running» (живой фейл на B 01.10). У mieru start есть известный
    форк-баг: родительский процесс не выходит после форка демона —
    поэтому start запускается Popen'ом, а в finally зонд гасится
    `mieru stop` (RPC) + явный reap родителя. Тест проходит через
    клиент → mita → dial цели → NFQUEUE → b4 — проверяется ВСЯ
    цепочка.

    Returns: {"available": bool, "ok": Optional[bool], "detail": str}
      available=False — клиентский бинарник не установлен / нет юзеров
      (E2E пропущен, остальные проверки остаются значимыми)."""
    res = {"available": False, "ok": None, "detail": ""}
    if not _MIERU_BIN.exists():
        res["detail"] = "клиент mieru не установлен (E2E пропущен)"
        return res
    st = _load_mieru_state()
    if not st.get("users"):
        res["detail"] = "в mieru нет пользователей (E2E пропущен)"
        return res
    u = st["users"][0]
    port = int(st.get("port_start") or 2012)
    protocol = (st.get("protocol") or "TCP").upper()
    protocol = "TCP" if protocol == "BOTH" else protocol

    # trafficPattern — JSON-объект (та же форма, что mita понимает в
    # server.json); базис — пресет из state standalone-установки.
    pattern_cfg = None
    preset = st.get("traffic_preset")
    if preset and preset != "disabled":
        try:
            pattern_cfg = _mieru()._MIERU_TRAFFIC_PRESETS[preset]["config"]
        except Exception:
            pattern_cfg = None

    profile = {
        "profileName": "chimera-e2e-probe",
        "user": {"name": u.get("username", ""), "password": u.get("password", "")},
        "servers": [{
            "ipAddress": "127.0.0.1",
            "portBindings": [{"port": port, "protocol": protocol}],
        }],
        "mtu": 1400,
        "multiplexing": {"level": "MULTIPLEXING_HIGH"},
    }
    if pattern_cfg:
        profile["trafficPattern"] = pattern_cfg
    client_cfg = {
        "profiles": [profile],
        "activeProfile": "chimera-e2e-probe",
        "rpcPort": 39864,          # RPC: status/stop/test ходят через него
        "socks5Port": 39865,       # слушает демон: по нему ждём готовность
        "httpProxyPort": 39866,    # порты mieru идут тройкой, все — свободные
        "loggingLevel": "WARN",
    }
    with tempfile.TemporaryDirectory(prefix="mieru-e2e-") as td:
        cfg_path = Path(td) / "client.json"
        cfg_path.write_text(json.dumps(client_cfg, indent=2))
        env = dict(os.environ)
        env["HOME"] = td
        env["XDG_CONFIG_HOME"] = str(Path(td) / ".config")
        start_proc = None
        try:
            # 1. apply config — валидация профиля клиентом
            r = subprocess.run([str(_MIERU_BIN), "apply", "config", str(cfg_path)],
                               capture_output=True, text=True, check=False,
                               timeout=30, env=env)
            if r.returncode != 0:
                res["detail"] = (f"apply config отклонён: "
                                 f"{(r.stderr or r.stdout or '').strip()[:200]}")
                return res
            # 2. гигиена: погасить зависший зонд прошлых прогонов (конфиг
            #    уже применён → stop бьёт по RPC-порту зонда 39864 и не
            #    задевает чужие инстансы mieru — хопы каскада на своих)
            try:
                subprocess.run([str(_MIERU_BIN), "stop"], env=env,
                               capture_output=True, timeout=15, check=False)
            except Exception:
                pass
            # 3. mieru start — демон в фоне (родитель не выходит —
            #    форк-баг mieru start, см. докстринг) → Popen + reap
            start_proc = subprocess.Popen([str(_MIERU_BIN), "start"], env=env,
                                          stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL)
            # 4. готовность: socks5-порт зонда слушается (≤15 c)
            socks_port = int(client_cfg["socks5Port"])
            ready = False
            deadline = time.monotonic() + _E2E_START_TIMEOUT
            while time.monotonic() < deadline:
                if _mita_port_listening(socks_port):
                    ready = True
                    break
                time.sleep(0.5)
            if not ready:
                res["available"] = True
                res["ok"] = False
                st_out = ""
                try:
                    sr = subprocess.run([str(_MIERU_BIN), "status"], env=env,
                                        capture_output=True, text=True,
                                        check=False, timeout=10)
                    st_out = ((sr.stdout or "") + (sr.stderr or "")).strip()
                except Exception:
                    pass
                res["detail"] = ("mieru start: клиент не поднялся за 15 c"
                                 + (f" ({st_out[:120]})" if st_out else ""))
                return res
            # 5. mieru test — upstream E2E-команда (через ЗАПУЩЕННОГО
            #    клиента; без start отвечает «client is not running»)
            r = subprocess.run([str(_MIERU_BIN), "test", url],
                               capture_output=True, text=True, check=False,
                               timeout=40, env=env)
            out = ((r.stdout or "") + (r.stderr or "")).strip()
            res["available"] = True
            if r.returncode == 0 and "Connected to" in out:
                res["ok"] = True
                res["detail"] = "клиент → mita → цель: OK"
            else:
                res["ok"] = False
                res["detail"] = (out[:300] or
                                 f"exit={r.returncode} (таймаут/отказ)")
        except subprocess.TimeoutExpired:
            res["available"] = True
            res["ok"] = False
            res["detail"] = "mieru test: таймаут 40 c"
        except Exception as e:
            res["detail"] = f"запуск mieru: {e}"
        finally:
            # 6. уборка: stop по RPC гасит демона и застрявшего
            #    родителя; kill — страховка от неисправимых
            try:
                subprocess.run([str(_MIERU_BIN), "stop"], env=env,
                               capture_output=True, timeout=20, check=False)
            except Exception:
                pass
            if start_proc is not None:
                try:
                    start_proc.wait(timeout=5)
                except Exception:
                    try:
                        start_proc.kill()
                    except Exception:
                        pass
    return res

def health_check_mieru() -> dict:
    """Полный health check связки Mieru + b4.

    Чеки:
      1. mita: сервис active, порт слушается, юзеры есть
      2. время: ±30 c (mTLS-хендшейк mita требует синхронизации)
      3. b4: сервис active (DPI-обработка исходящих)
      4. YouTube: HTTP-проба с ноды через b4 (dpi_bypass.health_check_youtube)
      5. E2E: `mieru test` реальным клиентом (вся цепочка разом)
    Returns: dict с по-чековыми результатами и all_ok."""
    result = {"all_ok": True, "checks": []}

    def _add(name: str, ok: bool, detail: str, fatal: bool = True):
        result["checks"].append({"name": name, "ok": ok, "detail": detail})
        if not ok and fatal:
            result["all_ok"] = False

    # 1. mita
    ms = _mita_status()
    if not ms["installed"]:
        _add("mita", False, "standalone-Mieru не установлен (транспортный "
             "протоколы → 11 «Mieru»)")
    else:
        _add("mita: сервис", ms["service_active"],
             "active" if ms["service_active"] else "systemctl is-active mita ≠ active")
        proto = ms["protocol"]
        listening = (proto in ("TCP", "BOTH") and _mita_port_listening(ms["port_start"], "tcp")) \
            or (proto == "UDP" and _mita_port_listening(ms["port_start"], "udp"))
        if proto == "BOTH":
            listening = _mita_port_listening(ms["port_start"], "tcp") or \
                _mita_port_listening(ms["port_start"], "udp")
        _add("mita: порт", listening,
             f"{'слушается' if listening else 'НЕ слушается'} :{ms['port_start']} ({proto})")
        _add("mita: юзеры", ms["users"] > 0,
             f"{ms['users']} польз." if ms["users"] else "нет пользователей")

    # 2. время
    try:
        ts_ok, ts_detail = _mieru()._check_time_sync()
    except Exception:
        ts_ok, ts_detail = True, "проверка недоступна"
    _add("время (±30 c)", ts_ok, ts_detail, fatal=ts_ok is False)

    # 3. b4
    try:
        b4s = _dpi().status()
        b4_installed = bool(b4s.get("installed"))
        b4_active = bool(b4s.get("service_active"))
        n_sets = len(b4s.get("active_sets") or [])
        if not b4_installed:
            _add("b4", False, "не установлен (меню [B] DPI Bypass → [1])")
        else:
            _add("b4: сервис", b4_active,
                 f"v{b4s.get('version', '?')}, "
                 f"{'active' if b4_active else 'stopped'}, сетов: {n_sets}")
    except Exception as e:
        _add("b4", False, f"статус недоступен: {e}")

    # 4. YouTube через b4 (прямая проба с ноды — плечо нода → цель)
    try:
        yt = _dpi().health_check_youtube()
        bad = [t["target"] for t in yt.get("targets", []) if not t.get("ok")]
        _add("цели через b4", yt.get("all_ok", False),
             "все цели отвечают" if yt.get("all_ok") else
             f"не отвечают: {', '.join(bad)}")
    except Exception as e:
        _add("цели через b4", False, f"проба недоступна: {e}")

    # 5. E2E
    e2e = _e2e_probe()
    if e2e.get("available"):
        _add("E2E mieru test", bool(e2e.get("ok")), e2e.get("detail", ""))
    else:
        result["e2e_skipped"] = e2e.get("detail", "")

    return result

# ══════════════════════════════════════════════════════════════════════════
#  INFO ДЛЯ ПАНЕЛЕЙ (REST API / Admin Panel)
# ══════════════════════════════════════════════════════════════════════════
def get_mieru_dpi_info() -> dict:
    """Краткий статус для порталов (паритет get_portal_info у dpi_bypass)."""
    state = _load_state()
    ms = _mita_status()
    return {
        "enabled": bool(state.get("enabled")),
        "active": is_mieru_dpi_active(),
        "mita_installed": ms["installed"],
        "mita_service_active": ms["service_active"],
        "route_domains": len(state.get("route_domains") or []),
        "synced_sets": len(state.get("synced_sets") or []),
        "last_sync": state.get("last_sync", ""),
    }

# ══════════════════════════════════════════════════════════════════════════
#  TUI-МЕНЮ
# ══════════════════════════════════════════════════════════════════════════
def do_mieru_dpi_menu() -> None:
    """TUI-меню «Mieru + B4» — паритет функциям dpi_bypass для Mieru."""
    while True:
        os.system("clear")
        state = _load_state()
        ms = _mita_status()
        try:
            b4s = _dpi().status()
        except Exception:
            b4s = {}
        b4_installed = bool(b4s.get("installed"))
        b4_active = bool(b4s.get("service_active"))
        n_sets = len(b4s.get("active_sets") or [])

        _box_top("🧅  MIERU + B4 — DPI BYPASS ЧЕРЕЗ MIERU")
        _box_row()

        # ── Статусы ──
        if ms["installed"]:
            m_col = GREEN if ms["service_active"] else RED
            proto_label = ms["protocol"]
            _box_row(f"  Mieru (mita):   {m_col}{'active' if ms['service_active'] else 'stopped'}{NC}"
                     f"  {CYAN}{proto_label} :{ms['port_start']}{NC}"
                     f"  юзеров: {ms['users']}  preset: {ms['traffic_preset']}")
        else:
            _box_warn("Mieru (standalone) не установлен.")
            _box_row(f"  {DIM}Транспортные протоколы → 11 «Mieru» — поставить mita.{NC}")
            _box_row()
        if b4_installed:
            b_col = GREEN if b4_active else RED
            _box_row(f"  b4:             {b_col}{'active' if b4_active else 'stopped'}{NC}"
                     f"  v{CYAN}{b4s.get('version', '?')}{NC}  сетов: {n_sets}")
        else:
            _box_warn("b4 не установлен.")
            _box_row(f"  {DIM}Поставить: [B] DPI Bypass → [1] (серверная часть общая).{NC}")
            _box_row()

        # ── Режим ──
        active = is_mieru_dpi_active()
        n_dom = len(state.get("route_domains") or [])
        last = (state.get("last_sync") or "—")[:19].replace("T", " ")
        mode_col = GREEN if active else YELLOW
        _box_row(f"  Режим:          {mode_col}{'ВКЛ' if active else 'ВЫКЛ'}{NC}"
                 f" — доменов в маршрутке: {n_dom}  (синк: {last})")
        if active and not ms["service_active"]:
            _box_warn("Режим включён, но mita остановлен — маршрутка мертва.")
            _box_row()
        if active and b4_installed and not b4_active:
            _box_warn("Режим включён, но b4 остановлен — ТСПУ не дурится.")
            _box_row()

        _box_row()
        _box_row(f"  {DIM}Как это работает:{NC}")
        _box_row(f"  {DIM}1. Клиент ──mTLS──► mita (RU-нода) — ТСПУ нечем дышать{NC}")
        _box_row(f"  {DIM}2. mita dial'ит цель напрямую с ноды{NC}")
        _box_row(f"  {DIM}3. b4 (NFQUEUE): fake SNI + фрагментация + fake RST{NC}")
        _box_row(f"  {DIM}4. Домены сетов b4 → mieru-outbound в клиентских конфигах{NC}")
        _box_row(f"  {DIM}   (подписка singbox + split-конфиг [6] — вместо Xray-routing){NC}")
        _box_row()

        # ── Требования ──
        if not ms["installed"] or not b4_installed:
            _box_warn("Для включения режима нужны: standalone-Mieru (меню "
                      "транспортных протоколов) + b4 ([B] → [1]).")
            _box_row()

        _box_sep()
        if active:
            _box_item("1", "⏸  Выключить режим (b4 и mita не трогаются)")
        else:
            _box_item("1", "🚀 Включить режим (синк доменов b4 → клиентские конфиги)")
        if b4_installed:
            _box_item("2", "📥 Импортировать кастомный сет (JSON) — b4 + автосинк в Mieru")
            _box_item("3", "🔍 Discovery (автоподбор сета под провайдера)")
        _box_item("4", "🏥 Health check: mita + время + b4 + цели + E2E mieru test")
        _box_item("5", "🔁 Синхронизировать домены b4 → Mieru (все активные сеты)")
        _box_item("6", "📱 Клиентские конфиги (split: домены → mieru, остальное → direct)")
        if b4_installed:
            _box_item("7", "📋 Логи b4 (последние 30 строк)")
        _box_row()
        _box_item("8", "ℹ️  Управление b4 (пресеты/обновление/Web UI — меню DPI Bypass)")
        _box_item("9", "🧹 Сброс маршрутки (очистить домены в state)")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return
        if ch in ("q", "0", ""):
            return

        if ch == "1":
            _menu_toggle_mode(ms, b4_installed)
        elif ch == "2" and b4_installed:
            _menu_import_set()
        elif ch == "3" and b4_installed:
            _menu_discovery()
        elif ch == "4":
            _menu_health()
        elif ch == "5":
            _menu_sync()
        elif ch == "6":
            _menu_client_configs()
        elif ch == "7" and b4_installed:
            _menu_b4_logs()
        elif ch == "8":
            _info("Открываю меню DPI Bypass (b4)…")
            try:
                _dpi().do_dpi_bypass_menu()
            except Exception as e:
                _err(f"Не удалось открыть меню dpi_bypass: {e}")
        elif ch == "9":
            _menu_reset_domains()
        else:
            _warn("Неверный выбор.")
            time.sleep(1)

# ── Обработчики меню ──────────────────────────────────────────────────────
def _menu_toggle_mode(ms: dict, b4_installed: bool) -> None:
    state = _load_state()
    if state.get("enabled"):
        disable()
        _ok("Режим выключен. Домены в state сохранены (маршрутка погашена "
            "в конфигах подписки при следующей выдаче).")
    else:
        if not ms["installed"]:
            _warn("Сначала установите standalone-Mieru: транспортные "
                  "протоколы → 11 «Mieru».")
        elif not b4_installed:
            _warn("Сначала установите b4: [B] DPI Bypass → [1].")
        else:
            r = enable()
            _ok(f"Режим включён: {r['domains']} доменов из {r['sets']} "
                f"активных сетов b4 → клиентские конфиги.")
            _info("Домены попадают в подписку format=singbox (обе ветки) и "
                  "split-конфиг [6] при следующей выдаче.")
    input(f"\n{BOLD}Enter…{NC}")

def _menu_import_set() -> None:
    """Импорт кастомного сета — тот же движок, что в dpi_bypass ([3]).

    После импорта — автосинк доменов сета в клиентскую маршрутку
    (эквивалент авто-синка b4 → Xray routing в dpi_bypass)."""
    print()
    _box_top("📥  ИМПОРТ КАСТОМНОГО СЕТА (b4 + MIERU)")
    _box_row()
    _box_row(f"  {DIM}Вставьте JSON сета (из b4 Web UI → Import/Export →{NC}")
    _box_row(f"  {DIM}Copy JSON, из файла или написанный вручную):{NC}")
    _box_row(f"  {DIM}{{\"name\":\"...\",\"targets\":{{\"sni_domains\":[...]}},...}}{NC}")
    _box_row()
    try:
        json_str = input(f"{CYAN}JSON (пустая строка — отмена): {NC}").strip()
    except (KeyboardInterrupt, EOFError):
        return
    if not json_str:
        return
    ok = _dpi().import_custom_set(json_str)
    if ok:
        r = sync_b4_to_mieru()
        _ok(f"Сет импортирован в b4 (панель обновится по F5).")
        _ok(f"Синк в Mieru: {r['domains']} доменов из {r['sets']} сетов "
            f"→ клиентские конфиги.")
    else:
        _err("Импорт не удался (причина выше — валидация b4).")
    input(f"\n{BOLD}Enter…{NC}")

def _menu_discovery() -> None:
    """Discovery — переиспользуется из dpi_bypass."""
    print()
    _info("Discovery подбирает сет под текущего провайдера (60 c).")
    try:
        r = _dpi().run_discovery(timeout_sec=60)
        if r.get("ok"):
            _ok("Discovery завершён; сет применён.")
            rr = sync_b4_to_mieru()
            _ok(f"Синк в Mieru: {rr['domains']} доменов из {rr['sets']} сетов.")
        else:
            _warn(f"Discovery не дал результата: {r.get('error', 'см. лог b4')}")
    except Exception as e:
        _err(f"Discovery: {e}")
    input(f"\n{BOLD}Enter…{NC}")

def _menu_health() -> None:
    print()
    _box_top("🏥  HEALTH CHECK — MIERU + B4")
    _box_row()
    r = health_check_mieru()
    for c in r.get("checks", []):
        mark = f"{GREEN}✓{NC}" if c["ok"] else f"{RED}✗{NC}"
        _box_row(f"  {mark} {c['name']}: {DIM}{c['detail']}{NC}")
    if r.get("e2e_skipped"):
        _box_row(f"  {YELLOW}–{NC} E2E mieru test: {DIM}{r['e2e_skipped']}{NC}")
    _box_row()
    verdict = GREEN + "ВСЯ ЦЕПОЧКА РАБОТАЕТ" + NC if r.get("all_ok") \
        else RED + "ЕСТЬ ПРОБЛЕМЫ (см. выше)" + NC
    _box_row(f"  Итог: {verdict}")
    _box_row()
    _log("INFO", f"health_check_mieru: all_ok={r.get('all_ok')}")
    input(f"\n{BOLD}Enter…{NC}")

def _menu_sync() -> None:
    print()
    _info("Собираю домены всех enabled-сетов b4…")
    r = sync_b4_to_mieru()
    if r["domains"]:
        _ok(f"Синхронизировано: {r['domains']} доменов из {r['sets']} сетов → "
            f"клиентские конфиги Mieru.")
        if r["changed"]:
            _info("Состав доменов ИЗМЕНИЛСЯ — перевыгрузите подписку на "
                  "клиенте (или подождите auto-update).")
        else:
            _info("Состав не изменился (идемпотентно).")
    else:
        _warn("Активных сетов b4 с доменами нет — маршрутка пустая. "
              "Импортируйте сет [2] или запустите Discovery [3].")
    input(f"\n{BOLD}Enter…{NC}")

def _menu_client_configs() -> None:
    """Split-конфиг + mierus://-ссылки из state standalone-Mieru.

    Редизайн (фидбек владельца, 01.10): раньше экран печатал JSON
    прямо посреди ОТКРЫТОЙ рамки — правая граница ║ ломалась на
    каждой строке конфига, а mierus://-ссылки обоих форматов шли
    без подписей, и было не понять, какую ссылку в какое приложение
    вставлять. Теперь:
      • внутри рамки — статус маршрутки + шпаргалка «что куда
        вставлять» (главный вопрос «какую ссылку в Nekobox» снят
        подписью «NekoBox», а не гаданием по виду ссылки);
      • ссылки и JSON — ВНЕ рамок (паттерн hybrid_addon: ссылка
        ОДНОЙ строкой под закрытой рамкой — мягкий перенос
        терминала не вставляет \n при копировании);
      • мини-меню [1]/[2]: ссылки и JSON на разных экранах, чтобы
        длинный JSON не отталкивал ссылки за первый экран."""
    while True:
        os.system("clear")
        cfg = build_karing_split_config()
        if cfg is None:
            _box_top("📱  КЛИЕНТСКИЕ КОНФИГИ (SPLIT)")
            _box_row()
            _box_warn("Mieru не установлен / нет юзеров — конфиг не собрать.")
            _box_row()
            _box_back()
            _box_bottom()
            input(f"\n{BOLD}Enter…{NC}")
            return
        entries = _mierus_links_for_state()
        domains = get_route_domains()
        last = (_load_state().get("last_sync") or "—")[:19].replace("T", " ")

        _box_top("📱  КЛИЕНТСКИЕ КОНФИГИ (SPLIT)")
        _box_row()
        if domains:
            _box_row(f"  Маршрутка: {CYAN}{len(domains)} доменов{NC} → mieru, "
                     f"остальное → direct  (синк: {last})")
        else:
            _box_warn("Маршрутка пуста — весь трафик пойдёт direct (синк [5]).")
        _box_row()

        _box_row(f"  {BOLD}Что куда вставлять:{NC}")
        _box_row(f"   {WHITE}Karing{NC} (Android/iOS/ПК) → [1] ссылка «Karing»")
        _box_row(f"   {WHITE}NekoBox / Nyamebox{NC}      → [1] ссылка «NekoBox»")
        _box_row(f"   {WHITE}NyameBox{NC} (ПК, ядро 1.13) → [3] JSON «Custom Config»")
        _box_row(f"   {WHITE}sing-box CLI{NC}            → [2] JSON-конфиг")
        _box_row()
        _box_row(f"  {DIM}Ссылка даёт только прокси; маршрутку (домены → mieru){NC}")
        _box_row(f"  {DIM}несёт подписка format=singbox (правила уже вшиты) или{NC}")
        _box_row(f"  {DIM}JSON [2]; в NekoBox для сплита — «Custom Config» из [2].{NC}")
        _box_row()

        _box_sep()
        _box_item("1", "🔗 mierus://-ссылки (по юзерам) — вне рамок")
        _box_item("2", "📄 JSON split-конфиг (в файл + на экран) — вне рамок")
        _box_item("3", "📄 NyameBox JSON (ядро 1.13.x) — в файл + на экран")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return
        if ch in ("q", "0", ""):
            return
        if ch == "1":
            if entries:
                _show_client_links(entries)
            else:
                _warn("Нет юзеров в standalone-Mieru — ссылки не собрать.")
                time.sleep(1)
        elif ch == "2":
            first_user = ((_load_mieru_state().get("users") or [{}])[0] or {})\
                .get("username", "")
            _show_client_json(cfg, first_user)
        elif ch == "3":
            nyame = build_nyamebox_split_config()
            if nyame is None:
                _warn("Конфиг NyameBox не собрался — Mieru/юзеры недоступны.")
                time.sleep(1)
            else:
                first_user = ((_load_mieru_state().get("users") or [{}])[0] or {})\
                    .get("username", "")
                _show_client_json(nyame, first_user, nyamebox=True)
        else:
            _warn("Неверный выбор.")
            time.sleep(1)

def _show_client_links(entries: list) -> None:
    """Экран [1] мини-меню [6]: mierus://-ссылки — ВНЕ рамок, по юзерам.

    Каждая ссылка печатается ОДНОЙ строкой ПОД закрытой рамкой: мягкий
    перенос терминала не вставляет перевод строки при копировании
    (паттерн hybrid_addon._show_mieru_client_links). Форматы подписаны
    явно: Karing (query-параметры port=/protocol=) и NekoBox/Nyamebox
    (порт через двоеточие + transport=) — два РАЗНЫХ формата под
    разные приложения, вперемешку их не показываем."""
    print()
    _box_top("🔗  MIERUS://-ССЫЛКИ (ПО ЮЗЕРАМ)")
    _box_row()
    _box_row(f"  {DIM}Ссылки — ПОД рамкой, каждая ОДНОЙ строкой:{NC}")
    _box_row(f"  {DIM}копируйте целиком, без склейки переносов.{NC}")
    if any(e.get("proto") == "UDP" for e in entries):
        _box_row(f"  {DIM}UDP-ссылка для Karing идёт с IP (баг ядра Karing —{NC}")
        _box_row(f"  {DIM}с доменом UDP молчит, «0 байт/с»); NekoBox — домен.{NC}")
    _box_row()
    _box_bottom()
    for e in entries:
        print()
        print(f"  {BOLD}Юзер «{e['user']}» — {e['proto']}:{NC}")
        print()
        print(f"  {BOLD}Karing (sing-box core):{NC}")
        print(f"  {YELLOW}{e['karing']}{NC}")
        print()
        print(f"  {BOLD}NekoBox / Nyamebox:{NC}")
        print(f"  {YELLOW}{e['nekobox']}{NC}")
    print()
    input(f"{BOLD}Enter…{NC}")

def _show_client_json(cfg: dict, username: str = "",
                      nyamebox: bool = False) -> None:
    """Экран [2]/[3] мини-меню [6]: split-JSON — ВНЕ рамок + файл для scp.

    JSON маршрутки длинный (все домены в route.rules) — внутри
    открытой рамки он ломал границы ║ и был нечитаем. Теперь рамка
    короткая (юзер, путь файла, куда вставлять), а конфиг печатается
    целиком ПОД ней; дополнительно сохраняется в файл — забрать на
    устройство scp/sftp целиком, без копирования из терминала.
    Конфиг несёт креды ПЕРВОГО юзера standalone-Mieru
    (build_karing_split_config) — имя юзера показываем в рамке.
    nyamebox=True — вариант для NyameBox (ядро sing-box 1.13.x):
    файл _NYAME_CFG_PATH, инструкция импорта «Custom Config»."""
    path = _NYAME_CFG_PATH if nyamebox else _SPLIT_CFG_PATH
    title = "📄  NYAMEBOX SPLIT-КОНФИГ (SING-BOX 1.13)" if nyamebox \
        else "📄  JSON SPLIT-КОНФИГ (SING-BOX)"
    print()
    _box_top(title)
    _box_row()
    if username:
        _box_row(f"  Юзер: {CYAN}{username}{NC} {DIM}(креды вшиты в конфиг){NC}")
    try:
        path.write_text(
            json.dumps(cfg, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
        _box_row(f"  Файл:  {CYAN}{path}{NC}")
        _box_row(f"  {DIM}Забрать целиком: scp <юзер>@<нода>:{path}{NC}")
    except OSError as e:
        _box_warn(f"Файл не записан: {e} — копируйте JSON из терминала.")
    _box_row()
    if nyamebox:
        _box_row(f"  {DIM}Куда: NyameBox → Профили → Add Profile → Custom Config{NC}")
        _box_row(f"  {DIM}→ вставить файл/текст. Конфиг — ПОД рамкой.{NC}")
        _box_row()
        _box_row(f"  {YELLOW}⚠  НЕ через буфер/подписку: санитайз приложения{NC}")
        _box_row(f"  {YELLOW}вырезает mieru transport → FATAL «transport must{NC}")
        _box_row(f"  {YELLOW}be TCP or UDP». Только Manual/Custom Config.{NC}")
    else:
        _box_row(f"  {DIM}Куда: Karing → импорт конфига · sing-box → config.json ·{NC}")
        _box_row(f"  {DIM}NekoBox → профиль «Custom Config». Конфиг — ПОД рамкой.{NC}")
    _box_row()
    _box_bottom()
    print()
    print(json.dumps(cfg, indent=2, ensure_ascii=False))
    print()
    input(f"{BOLD}Enter…{NC}")

def _menu_b4_logs() -> None:
    print()
    _box_top("📋  ЛОГИ b4 (последние 30 строк)")
    _box_row()
    try:
        r = subprocess.run(
            ["journalctl", "-u", "b4", "-n", "30", "--no-pager", "-o", "cat"],
            capture_output=True, text=True, check=False, timeout=10)
        for line in (r.stdout or "").splitlines()[-30:]:
            print(f"  {DIM}{line}{NC}")
    except Exception as e:
        _err(f"journalctl: {e}")
    print()
    input(f"{BOLD}Enter…{NC}")

def _menu_reset_domains() -> None:
    state = _load_state()
    state["route_domains"] = []
    state["synced_sets"] = []
    _save_state(state)
    _ok("Маршрутка очищена (route_domains=[]). Режим и b4 не тронуты.")
    input(f"\n{BOLD}Enter…{NC}")
